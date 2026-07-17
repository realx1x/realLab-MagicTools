use std::collections::HashSet;

use domain::{
    AppError, ClassificationCategory, ClassificationReason, ClassificationResult, ErrorCode,
    FieldValue, PortProtocol, PortState, ProcessOwnership, ProcessRecord, ProjectId,
    UserClassificationOverride,
};

pub const ALGORITHM_VERSION: u32 = 1;
pub const DEFAULT_DEVELOPMENT_THRESHOLD: i32 = 40;
pub const MAX_CLASSIFICATION_RULES: usize = 4_096;
pub const MAX_KNOWN_PROJECTS: usize = 4_096;
pub const COMMON_DEVELOPMENT_PORTS: &[u16] = &[
    3_000, 3_001, 4_000, 4_200, 5_000, 5_173, 5_174, 8_000, 8_001, 8_080, 8_081, 8_888,
];

const MAX_RULE_ID_BYTES: usize = 256;
const MAX_RULE_PATTERN_BYTES: usize = 4_096;
const MAX_PROJECT_ID_BYTES: usize = 256;
const MAX_PROJECT_FEATURE_ID_BYTES: usize = 256;
const MAX_DEVELOPMENT_THRESHOLD: i32 = 1_000;

const MANAGED_SCORE: i32 = 100;
const REGISTERED_PROJECT_SCORE: i32 = 50;
const KNOWN_FRAMEWORK_SCORE: i32 = 30;
const PROJECT_FEATURE_SCORE: i32 = 25;
const COMMON_DEVELOPMENT_PORT_SCORE: i32 = 10;
const KNOWN_RUNTIME_SCORE: i32 = 10;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClassificationRuleMatcher {
    ExecutableNameExact(String),
    ExecutablePathExact(String),
    CommandLineContains(String),
    WorkingDirectoryPrefix(String),
}

impl ClassificationRuleMatcher {
    fn pattern(&self) -> &str {
        match self {
            Self::ExecutableNameExact(pattern)
            | Self::ExecutablePathExact(pattern)
            | Self::CommandLineContains(pattern)
            | Self::WorkingDirectoryPrefix(pattern) => pattern,
        }
    }

    fn matches(&self, process: &ProcessRecord) -> bool {
        match self {
            Self::ExecutableNameExact(pattern) => {
                known_string(&process.executable_name).is_some_and(|value| value == pattern)
            }
            Self::ExecutablePathExact(pattern) => {
                known_string(&process.executable_path).is_some_and(|value| value == pattern)
            }
            Self::CommandLineContains(pattern) => {
                known_string(&process.command_line).is_some_and(|value| value.contains(pattern))
            }
            Self::WorkingDirectoryPrefix(pattern) => known_string(&process.working_directory)
                .is_some_and(|value| path_has_prefix(value, pattern)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClassificationRuleAction {
    Include,
    Exclude,
    AssignProject(ProjectId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassificationRule {
    pub id: String,
    pub matcher: ClassificationRuleMatcher,
    pub action: ClassificationRuleAction,
    pub priority: i64,
    pub enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassificationRulesSnapshot {
    pub development_threshold: i32,
    pub known_project_ids: Vec<ProjectId>,
    pub rules: Vec<ClassificationRule>,
}

impl Default for ClassificationRulesSnapshot {
    fn default() -> Self {
        Self {
            development_threshold: DEFAULT_DEVELOPMENT_THRESHOLD,
            known_project_ids: Vec::new(),
            rules: Vec::new(),
        }
    }
}

/// Facts owned by project discovery rather than classification output.
///
/// Keeping these separate prevents a prior `AssignProject` decision from
/// becoming evidence for a later classification pass after the rule changes.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProcessClassificationFacts {
    pub working_directory_project_id: Option<ProjectId>,
    pub project_feature_id: Option<String>,
}

impl ProcessClassificationFacts {
    pub fn validate(&self) -> Result<(), AppError> {
        if let Some(project_id) = &self.working_directory_project_id {
            validate_non_empty_bounded(
                "workingDirectoryProjectId",
                project_id,
                MAX_PROJECT_ID_BYTES,
            )?;
        }
        if let Some(feature_id) = &self.project_feature_id {
            validate_non_empty_bounded(
                "projectFeatureId",
                feature_id,
                MAX_PROJECT_FEATURE_ID_BYTES,
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassificationDecision {
    pub result: ClassificationResult,
    pub project_id: Option<ProjectId>,
}

#[derive(Clone, Debug)]
pub struct ClassificationEngine {
    development_threshold: i32,
    known_project_ids: HashSet<ProjectId>,
    rules: Vec<ClassificationRule>,
}

impl ClassificationEngine {
    pub fn new(mut snapshot: ClassificationRulesSnapshot) -> Result<Self, AppError> {
        if !(0..=MAX_DEVELOPMENT_THRESHOLD).contains(&snapshot.development_threshold) {
            return Err(invalid_classification_input(
                "developmentThreshold",
                "must be between 0 and 1000",
            ));
        }
        if snapshot.known_project_ids.len() > MAX_KNOWN_PROJECTS {
            return Err(invalid_classification_input(
                "knownProjectIds",
                "exceeds the supported capacity",
            ));
        }
        if snapshot.rules.len() > MAX_CLASSIFICATION_RULES {
            return Err(invalid_classification_input(
                "rules",
                "exceeds the supported capacity",
            ));
        }

        let mut known_project_ids = HashSet::with_capacity(snapshot.known_project_ids.len());
        for project_id in snapshot.known_project_ids {
            validate_non_empty_bounded("knownProjectId", &project_id, MAX_PROJECT_ID_BYTES)?;
            if !known_project_ids.insert(project_id) {
                return Err(invalid_classification_input(
                    "knownProjectIds",
                    "contains a duplicate project ID",
                ));
            }
        }

        let mut rule_ids = HashSet::with_capacity(snapshot.rules.len());
        for rule in &snapshot.rules {
            validate_non_empty_bounded("ruleId", &rule.id, MAX_RULE_ID_BYTES)?;
            if !rule_ids.insert(rule.id.as_str()) {
                return Err(invalid_classification_input(
                    "rules",
                    "contains a duplicate rule ID",
                ));
            }
            validate_non_empty_bounded(
                "rulePattern",
                rule.matcher.pattern(),
                MAX_RULE_PATTERN_BYTES,
            )?;
            if let ClassificationRuleAction::AssignProject(project_id) = &rule.action {
                validate_non_empty_bounded("ruleProjectId", project_id, MAX_PROJECT_ID_BYTES)?;
                if !known_project_ids.contains(project_id) {
                    return Err(invalid_classification_input(
                        "ruleProjectId",
                        "AssignProject references an unknown project ID",
                    ));
                }
            }
        }

        snapshot.rules.retain(|rule| rule.enabled);
        snapshot.rules.sort_by(|left, right| {
            right
                .priority
                .cmp(&left.priority)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(Self {
            development_threshold: snapshot.development_threshold,
            known_project_ids,
            rules: snapshot.rules,
        })
    }

    pub fn validate_facts(&self, facts: &ProcessClassificationFacts) -> Result<(), AppError> {
        facts.validate()?;
        if let Some(project_id) = &facts.working_directory_project_id
            && !self.known_project_ids.contains(project_id)
        {
            return Err(invalid_classification_input(
                "workingDirectoryProjectId",
                "references an unknown project ID",
            ));
        }
        Ok(())
    }

    pub(crate) fn enabled_rule_count(&self) -> usize {
        self.rules.len()
    }

    pub(crate) fn pattern_bytes_per_classification(&self) -> usize {
        self.rules
            .iter()
            .map(|rule| rule.matcher.pattern().len().max(8))
            .sum()
    }

    pub fn classify(
        &self,
        process: &ProcessRecord,
        facts: &ProcessClassificationFacts,
    ) -> ClassificationDecision {
        let mut score = 0;
        let mut reasons = Vec::with_capacity(7);

        let managed = process.ownership == ProcessOwnership::Managed;
        if managed {
            push_reason(
                &mut reasons,
                &mut score,
                "managed",
                MANAGED_SCORE,
                "Process is managed by MagicTools",
            );
        }

        let registered_project_id =
            facts
                .working_directory_project_id
                .as_ref()
                .filter(|project_id| {
                    self.known_project_ids.contains(*project_id)
                        && matches!(process.working_directory, FieldValue::Known(_))
                });
        if registered_project_id.is_some() {
            push_reason(
                &mut reasons,
                &mut score,
                "registeredProject",
                REGISTERED_PROJECT_SCORE,
                "Working directory is associated with a registered project",
            );
        }

        let known_framework =
            known_string(&process.command_line).is_some_and(command_matches_known_framework);
        if known_framework {
            push_reason(
                &mut reasons,
                &mut score,
                "knownFramework",
                KNOWN_FRAMEWORK_SCORE,
                "Command matches a known development framework",
            );
        }

        let project_feature = facts.project_feature_id.as_deref().is_some_and(|value| {
            !value.trim().is_empty() && value.len() <= MAX_PROJECT_FEATURE_ID_BYTES
        });
        if project_feature {
            push_reason(
                &mut reasons,
                &mut score,
                "projectFeature",
                PROJECT_FEATURE_SCORE,
                "A known project feature was detected",
            );
        }

        let common_development_port = listens_on_common_development_port(process);
        if common_development_port {
            push_reason(
                &mut reasons,
                &mut score,
                "commonDevelopmentPort",
                COMMON_DEVELOPMENT_PORT_SCORE,
                "Process listens on a common development port",
            );
        }

        let known_runtime = process_is_known_runtime(process);
        if known_runtime {
            push_reason(
                &mut reasons,
                &mut score,
                "knownRuntime",
                KNOWN_RUNTIME_SCORE,
                "Executable is a known development runtime",
            );
        }

        let mut winning_rule = None;
        let mut excluding_rule = None;
        for rule in &self.rules {
            if !rule.matcher.matches(process) {
                continue;
            }
            match &rule.action {
                ClassificationRuleAction::Exclude => {
                    excluding_rule = Some(rule);
                    break;
                }
                ClassificationRuleAction::Include | ClassificationRuleAction::AssignProject(_) => {
                    if winning_rule.is_none() {
                        winning_rule = Some(rule);
                    }
                }
            }
        }
        if let Some(excluding_rule) = excluding_rule {
            reasons.push(ClassificationReason {
                code: "rule.exclude".into(),
                score: 0,
                summary: format!(
                    "Rule '{}' explicitly excludes the process",
                    excluding_rule.id
                ),
            });
            return ClassificationDecision {
                result: ClassificationResult {
                    score,
                    version: ALGORITHM_VERSION,
                    category: ClassificationCategory::Excluded,
                    reasons,
                    user_override: Some(UserClassificationOverride::Exclude),
                    is_development: false,
                },
                project_id: registered_project_id.cloned(),
            };
        }

        let mut project_id = registered_project_id.cloned();
        let user_override = winning_rule.map(|rule| match &rule.action {
            ClassificationRuleAction::Include => UserClassificationOverride::Include,
            ClassificationRuleAction::AssignProject(assigned_project_id) => {
                project_id = Some(assigned_project_id.clone());
                UserClassificationOverride::AssignProject(assigned_project_id.clone())
            }
            ClassificationRuleAction::Exclude => unreachable!("exclude rules were handled first"),
        });
        if let (Some(winning_rule), Some(user_override)) = (winning_rule, &user_override) {
            let (code, summary) = match user_override {
                UserClassificationOverride::Include => (
                    "rule.include",
                    format!("Rule '{}' explicitly includes the process", winning_rule.id),
                ),
                UserClassificationOverride::AssignProject(_) => (
                    "rule.assignProject",
                    format!(
                        "Rule '{}' assigns the process to a project",
                        winning_rule.id
                    ),
                ),
                UserClassificationOverride::Exclude => unreachable!("exclude handled above"),
            };
            reasons.push(ClassificationReason {
                code: code.into(),
                score: 0,
                summary,
            });
        }

        let has_non_runtime_signal = managed
            || registered_project_id.is_some()
            || known_framework
            || project_feature
            || common_development_port;
        let direct_include = user_override.is_some();
        let runtime_only = known_runtime && !has_non_runtime_signal;
        let is_development = direct_include
            || (!runtime_only && has_non_runtime_signal && score >= self.development_threshold);
        let category = if is_development {
            ClassificationCategory::Development
        } else if known_runtime {
            ClassificationCategory::Runtime
        } else {
            ClassificationCategory::Unknown
        };
        ClassificationDecision {
            result: ClassificationResult {
                score,
                version: ALGORITHM_VERSION,
                category,
                reasons,
                user_override,
                is_development,
            },
            project_id,
        }
    }
}

impl Default for ClassificationEngine {
    fn default() -> Self {
        Self::new(ClassificationRulesSnapshot::default())
            .expect("the built-in classification snapshot must be valid")
    }
}

fn known_string(value: &FieldValue<String>) -> Option<&str> {
    match value {
        FieldValue::Known(value) => Some(value),
        FieldValue::Unknown | FieldValue::AccessLimited { .. } | FieldValue::NotSupported => None,
    }
}

fn push_reason(
    reasons: &mut Vec<ClassificationReason>,
    score: &mut i32,
    code: &str,
    reason_score: i32,
    summary: &str,
) {
    *score += reason_score;
    reasons.push(ClassificationReason {
        code: code.into(),
        score: reason_score,
        summary: summary.into(),
    });
}

fn command_matches_known_framework(command_line: &str) -> bool {
    const FRAMEWORK_TERMS: &[&str] = &[
        "vite",
        "webpack",
        "next dev",
        "nuxt",
        "react-scripts",
        "ng serve",
        "manage.py runserver",
        "flask run",
        "uvicorn",
        "fastapi",
        "spring-boot",
        "quarkus",
        "bootrun",
        "cargo run",
        "go run",
        "dotnet watch",
        "rails server",
        "artisan serve",
    ];
    let command_line = command_line.to_ascii_lowercase();
    FRAMEWORK_TERMS
        .iter()
        .any(|term| contains_command_term(&command_line, term))
}

fn contains_command_term(command_line: &str, term: &str) -> bool {
    command_line.match_indices(term).any(|(start, value)| {
        let before = command_line[..start].chars().next_back();
        let after = command_line[start + value.len()..].chars().next();
        before.is_none_or(|character| !is_command_word_character(character))
            && after.is_none_or(|character| !is_command_word_character(character))
    })
}

fn is_command_word_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_'
}

fn listens_on_common_development_port(process: &ProcessRecord) -> bool {
    let FieldValue::Known(bindings) = &process.port_bindings else {
        return false;
    };
    bindings.iter().any(|binding| {
        binding.protocol == PortProtocol::Tcp
            && binding.state == FieldValue::Known(PortState::TcpListen)
            && COMMON_DEVELOPMENT_PORTS
                .binary_search(&binding.local_port)
                .is_ok()
    })
}

fn process_is_known_runtime(process: &ProcessRecord) -> bool {
    known_string(&process.executable_name).is_some_and(is_known_runtime_name)
        || known_string(&process.executable_path)
            .and_then(path_file_name)
            .is_some_and(is_known_runtime_name)
}

fn path_has_prefix(path: &str, prefix: &str) -> bool {
    if is_path_root(prefix) {
        return path.starts_with(prefix);
    }
    let prefix = prefix.trim_end_matches(['/', '\\']);
    if path == prefix {
        return true;
    }
    path.strip_prefix(prefix)
        .and_then(|suffix| suffix.chars().next())
        .is_some_and(|separator| separator == '/' || separator == '\\')
}

fn is_path_root(path: &str) -> bool {
    if path == "/" || path == "\\" {
        return true;
    }
    let bytes = path.as_bytes();
    bytes.len() == 3
        && bytes[1] == b':'
        && (bytes[2] == b'/' || bytes[2] == b'\\')
        && bytes[0].is_ascii_alphabetic()
}

fn path_file_name(path: &str) -> Option<&str> {
    path.rsplit(['/', '\\'])
        .find(|component| !component.is_empty())
}

fn is_known_runtime_name(executable_name: &str) -> bool {
    let executable_name = executable_name.to_ascii_lowercase();
    let executable_name = executable_name
        .strip_suffix(".exe")
        .unwrap_or(&executable_name);
    matches!(
        executable_name,
        "node"
            | "nodejs"
            | "deno"
            | "bun"
            | "java"
            | "javaw"
            | "go"
            | "dotnet"
            | "ruby"
            | "php"
            | "python"
            | "pythonw"
    ) || executable_name
        .strip_prefix("python")
        .is_some_and(|version| {
            !version.is_empty()
                && version.chars().any(|character| character.is_ascii_digit())
                && version
                    .chars()
                    .all(|character| character.is_ascii_digit() || character == '.')
        })
}

fn validate_non_empty_bounded(field: &str, value: &str, max_bytes: usize) -> Result<(), AppError> {
    if value.trim().is_empty() {
        return Err(invalid_classification_input(field, "must not be empty"));
    }
    if value.len() > max_bytes {
        return Err(invalid_classification_input(
            field,
            "exceeds the supported length",
        ));
    }
    Ok(())
}

fn invalid_classification_input(field: &str, reason: &str) -> AppError {
    let mut error = AppError::new(ErrorCode::InvalidArgument, "invalid classification input");
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}
