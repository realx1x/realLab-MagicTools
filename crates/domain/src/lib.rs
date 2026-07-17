//! Shared, serializable domain contracts used by the Supervisor, bridge, and UI.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{Ordering, compiler_fence};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use ts_rs::TS;

pub type Revision = u64;
pub type Timestamp = String;
pub type ProjectId = String;

/// Largest revision that can be represented exactly by a JavaScript number.
pub const MAX_SAFE_REVISION: Revision = 9_007_199_254_740_991;
pub const MAX_SNAPSHOT_PROCESSES: usize = 16_384;
pub const MAX_SNAPSHOT_PORT_BINDINGS: usize = 65_536;
pub const MAX_SNAPSHOT_ENTITY_BYTES: usize = 512 * 1_024;
pub const MAX_SNAPSHOT_TOTAL_ENTITY_BYTES: usize = 128 * 1_024 * 1_024;

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub struct ProcessInstanceKey {
    pub boot_id: String,
    pub pid: u32,
    /// Decimal native creation-time representation. A string preserves the
    /// full platform precision across JSON and JavaScript.
    pub native_start_time: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum FieldValue<T> {
    Known(T),
    Unknown,
    AccessLimited { reason: Option<String> },
    NotSupported,
}

/// Evidence produced by bounded project discovery.
///
/// `Missing` means the relevant lookup completed and found no association,
/// while `Unknown` and the access variants mean no negative conclusion can be
/// drawn from the current observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum ProjectEvidence<T> {
    Known(T),
    Missing,
    Unknown,
    AccessLimited { reason: Option<String> },
    NotSupported,
}

impl<T> Default for ProjectEvidence<T> {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ProjectAssociationEvidence {
    pub project_id: ProjectId,
    pub registered_root: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ProjectFeatureEvidence {
    pub marker_id: String,
    pub marker_path: String,
    pub detected_root: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ProjectInput {
    pub name: String,
    pub root_directory: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ProjectSummary {
    pub id: ProjectId,
    pub input: ProjectInput,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct CreateProjectRequest {
    pub input: ProjectInput,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct UpdateProjectRequest {
    pub project_id: ProjectId,
    pub expected_updated_at: Timestamp,
    pub input: ProjectInput,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(tag = "operation", rename_all = "camelCase")]
#[ts(tag = "operation", rename_all = "camelCase")]
pub enum SaveProjectRequest {
    Create(CreateProjectRequest),
    Update(UpdateProjectRequest),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ListProjectsRequest {
    pub cursor: Option<String>,
    pub limit: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ListProjectsResponse {
    pub projects: Vec<ProjectSummary>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct DeleteProjectRequest {
    pub project_id: ProjectId,
    pub expected_updated_at: Timestamp,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct DeleteProjectResponse {
    pub project_id: ProjectId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum ClassificationRuleMatcherKind {
    ExecutableNameExact,
    ExecutablePathExact,
    CommandLineContains,
    WorkingDirectoryPrefix,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
#[ts(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum ClassificationRuleAction {
    Include,
    Exclude,
    AssignProject { project_id: ProjectId },
}

#[derive(Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum ClassificationRuleActionWire {
    Include,
    Exclude,
    AssignProject { project_id: ProjectId },
}

impl<'de> Deserialize<'de> for ClassificationRuleAction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(
            match ClassificationRuleActionWire::deserialize(deserializer)? {
                ClassificationRuleActionWire::Include => Self::Include,
                ClassificationRuleActionWire::Exclude => Self::Exclude,
                ClassificationRuleActionWire::AssignProject { project_id } => {
                    Self::AssignProject { project_id }
                }
            },
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ClassificationRuleInput {
    pub matcher_kind: ClassificationRuleMatcherKind,
    pub pattern: String,
    pub action: ClassificationRuleAction,
    pub priority: i32,
    pub enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ClassificationRuleSummary {
    pub id: String,
    pub input: ClassificationRuleInput,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct CreateClassificationRuleRequest {
    pub input: ClassificationRuleInput,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct UpdateClassificationRuleRequest {
    pub rule_id: String,
    pub expected_updated_at: Timestamp,
    pub input: ClassificationRuleInput,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(tag = "operation", rename_all = "camelCase")]
#[ts(tag = "operation", rename_all = "camelCase")]
pub enum SaveClassificationRuleRequest {
    Create(CreateClassificationRuleRequest),
    Update(UpdateClassificationRuleRequest),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ListClassificationRulesRequest {
    pub cursor: Option<String>,
    pub limit: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ListClassificationRulesResponse {
    pub rules: Vec<ClassificationRuleSummary>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct DeleteClassificationRuleRequest {
    pub rule_id: String,
    pub expected_updated_at: Timestamp,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct DeleteClassificationRuleResponse {
    pub rule_id: String,
}

/// A shell is never inferred from command text. Selecting this enum is the
/// explicit opt-in required for shell execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum ShellKind {
    PowerShell,
    Cmd,
    Zsh,
}

/// Persistable execution modes. Detected scripts are suggestions and must be
/// accepted into one of these concrete modes before a profile can be saved.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct DirectLaunch {
    pub executable: String,
    pub argv: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ShellLaunch {
    pub shell: ShellKind,
    pub command: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(tag = "mode", rename_all = "camelCase")]
#[ts(tag = "mode", rename_all = "camelCase")]
pub enum LaunchExecution {
    Direct(DirectLaunch),
    Shell(ShellLaunch),
}

/// Environment values are mutually exclusive by construction. Empty plain
/// values are valid; credential references never contain the secret itself.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct PlainLaunchEnvironmentValue {
    pub value: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct CredentialReferenceLaunchEnvironmentValue {
    pub credential_reference: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, TS)]
#[serde(tag = "kind", rename_all = "camelCase")]
#[ts(tag = "kind", rename_all = "camelCase")]
pub enum LaunchEnvironmentValue {
    Plain(PlainLaunchEnvironmentValue),
    CredentialReference(CredentialReferenceLaunchEnvironmentValue),
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
enum LaunchEnvironmentValueWire {
    Plain(PlainLaunchEnvironmentValue),
    CredentialReference(CredentialReferenceLaunchEnvironmentValue),
}

impl<'de> Deserialize<'de> for LaunchEnvironmentValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(
            match LaunchEnvironmentValueWire::deserialize(deserializer)? {
                LaunchEnvironmentValueWire::Plain(value) => Self::Plain(value),
                LaunchEnvironmentValueWire::CredentialReference(value) => {
                    Self::CredentialReference(value)
                }
            },
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct LaunchEnvironmentEntry {
    pub name: String,
    pub value: LaunchEnvironmentValue,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct LaunchProfileInput {
    pub project_id: Option<ProjectId>,
    pub name: String,
    pub execution: LaunchExecution,
    pub working_directory: String,
    pub environment: Vec<LaunchEnvironmentEntry>,
    pub interactive: bool,
    pub stop_timeout_ms: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct LaunchProfile {
    pub id: String,
    pub input: LaunchProfileInput,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct CreateLaunchProfileRequest {
    pub input: LaunchProfileInput,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct UpdateLaunchProfileRequest {
    pub profile_id: String,
    pub expected_updated_at: Timestamp,
    pub input: LaunchProfileInput,
}

/// Identity and timestamps on create remain Supervisor-owned. Updates name a
/// target separately and require its last observed timestamp for optimistic
/// concurrency.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(tag = "operation", rename_all = "camelCase")]
#[ts(tag = "operation", rename_all = "camelCase")]
pub enum SaveLaunchProfileRequest {
    Create(CreateLaunchProfileRequest),
    Update(UpdateLaunchProfileRequest),
}

/// A write-only secret value supplied for one profile environment slot. It is
/// never persisted or returned by the Supervisor.
#[derive(Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct SecretLaunchEnvironmentEntry {
    pub name: String,
    pub secret: String,
}

impl fmt::Debug for SecretLaunchEnvironmentEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretLaunchEnvironmentEntry")
            .field("name", &self.name)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl Drop for SecretLaunchEnvironmentEntry {
    fn drop(&mut self) {
        // The wire stack may hold independent JSON copies; this clears the
        // typed request's owned buffer once domain decoding has completed.
        for byte in unsafe { self.secret.as_mut_vec() } {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// Authenticated write request used to create or rotate system-backed
/// environment secrets. The nested profile request contains no new secret
/// values; entries here replace the matching environment slots before save.
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct SaveLaunchProfileWithSecretsRequest {
    pub request: SaveLaunchProfileRequest,
    pub secret_environment: Vec<SecretLaunchEnvironmentEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ListLaunchProfilesRequest {
    pub cursor: Option<String>,
    pub limit: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ListLaunchProfilesResponse {
    pub profiles: Vec<LaunchProfile>,
    pub next_cursor: Option<String>,
}

/// A detector may propose execution, but this DTO is not a persistable launch
/// mode. The lifecycle boundary must validate and explicitly accept it first.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct DetectedScriptSuggestion {
    pub detector_id: String,
    pub source_path: String,
    pub suggested_execution: LaunchExecution,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct DeleteLaunchProfileRequest {
    pub profile_id: String,
    pub expected_updated_at: Timestamp,
}

/// Confirms the exact profile identity removed by the Supervisor. Credential
/// references and write-only secret values are intentionally absent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct DeleteLaunchProfileResponse {
    pub profile_id: String,
}

/// Starts exactly the persisted profile revision named by the client. The
/// Supervisor owns executable resolution, the final environment, and all run
/// identity fields; none of those values are accepted on this request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct StartManagedRunRequest {
    pub profile_id: String,
    pub expected_profile_updated_at: Timestamp,
}

/// A bounded public projection of a Supervisor-owned managed run. The profile
/// timestamp identifies the immutable configuration revision used at launch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ManagedRunSummary {
    pub run_id: String,
    pub profile_id: String,
    pub profile_updated_at: Timestamp,
    pub state: RunState,
    pub process_instance_key: Option<ProcessInstanceKey>,
    /// Controlled POSIX process group. Windows Job-managed runs leave this
    /// empty because a console process-group identifier is not the Job owner.
    pub process_group_id: Option<u32>,
    pub started_at: Timestamp,
    pub updated_at: Timestamp,
    pub ended_at: Option<Timestamp>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct StartManagedRunResult {
    pub run: ManagedRunSummary,
}

/// Empty read request for the authoritative consequences of exiting the UI.
/// The Supervisor derives every affected run from durable state and its live
/// control table; the client cannot nominate or omit runs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct GetExitImpactRequest {}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum ExitRetainedReason {
    Quarantined,
    CleanupPending,
    DurableOnly,
    ControlMismatch,
}

/// One bounded, content-free exit consequence. Commands, environment values,
/// paths, process identities, and profile snapshots never cross this boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
#[ts(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum ExitRunImpact {
    Launching {
        run_id: String,
    },
    Running {
        run_id: String,
    },
    GracefulStopping {
        run_id: String,
        operation_id: String,
    },
    GracefulTimedOut {
        run_id: String,
        operation_id: String,
    },
    ForceStopping {
        run_id: String,
        operation_id: String,
    },
    Retained {
        run_id: String,
        reason: ExitRetainedReason,
    },
}

/// `assessment_id` binds the exact sorted union of live controls and durable
/// unfinished runs to one Supervisor incarnation, preventing stale exit
/// confirmation after state changes or an ABA-shaped restart.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ExitImpactSummary {
    pub assessment_id: String,
    pub runs: Vec<ExitRunImpact>,
}

/// Requests graceful stops for exactly the members in one prior assessment.
/// The idempotency key remains exclusively in the authenticated envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct StopAllForExitRequest {
    pub expected_assessment_id: String,
}

/// Fixed action reserved for one batch member. A graceful reservation for a
/// launching run remains blocked until replay observes it as Running. `None`
/// is reserved for retained controls that cannot safely receive a new signal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
#[ts(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum StopAllForExitMemberAction {
    None,
    GracefulRequested { operation_id: String },
    StopAdopted { operation_id: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct StopAllForExitMemberResult {
    pub run_id: String,
    pub action: StopAllForExitMemberAction,
    /// Absent only after this fixed member no longer has any exit impact.
    pub current_impact: Option<ExitRunImpact>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum StopAllForExitStatus {
    Draining,
    Blocked,
    Completed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct StopAllForExitResult {
    pub operation_id: String,
    pub status: StopAllForExitStatus,
    pub members: Vec<StopAllForExitMemberResult>,
}

/// A deliberately content-free projection of one durable managed run. Profile
/// snapshots, commands, environment values, paths, exit summaries, and log
/// directories never cross this history boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct RunHistoryItem {
    pub run_id: String,
    pub profile_id: String,
    pub profile_name: String,
    pub state: RunState,
    pub process_instance_key: Option<ProcessInstanceKey>,
    pub stop_kind: Option<ManagedStopKind>,
    pub recovery_state: Option<RunState>,
    pub started_at: Timestamp,
    pub updated_at: Timestamp,
    pub ended_at: Option<Timestamp>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ListRunHistoryRequest {
    pub cursor: Option<String>,
    pub limit: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ListRunHistoryResponse {
    pub runs: Vec<RunHistoryItem>,
    pub next_cursor: Option<String>,
}

/// Closed diagnostic content categories. Managed-process stdout/stderr,
/// commands, environment values, credential references, paths, and session
/// tokens have no representable category in this contract.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum DiagnosticContentKind {
    SystemSummary,
    ApplicationLogs,
    DatabaseSummary,
}

/// The content-level privacy boundary applied before an item can be exported.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum DiagnosticContentPrivacy {
    MetadataOnly,
    StructuredRedacted,
    AggregateOnly,
}

/// One bounded entry in the diagnostic content checklist. `included` is the
/// default selection in a manifest preview and the actual selection in an
/// export result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct DiagnosticManifestItem {
    pub kind: DiagnosticContentKind,
    pub included: bool,
    pub available: bool,
    pub estimated_bytes: u64,
    pub maximum_bytes: u64,
    pub privacy: DiagnosticContentPrivacy,
    pub truncated: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct GetDiagnosticsManifestRequest {}

/// Bounded checklist shown before export and embedded in the final result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct GetDiagnosticsManifestResponse {
    pub format_version: u16,
    pub items: Vec<DiagnosticManifestItem>,
    pub selected_estimated_bytes: u64,
    pub selected_maximum_bytes: u64,
    pub byte_budget: u64,
}

/// The system summary is mandatory. Application logs are the structured,
/// bounded application ring only; managed-process output is never eligible.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ExportDiagnosticsRequest {
    pub include_application_logs: bool,
    pub include_database_summary: bool,
}

/// Result of atomically publishing one diagnostic JSON document under the
/// Supervisor-owned export root. Only a generated file name crosses the wire;
/// an absolute filesystem path never does.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ExportDiagnosticsResult {
    pub file_name: String,
    pub total_bytes: u64,
    pub sha256: String,
    pub manifest: GetDiagnosticsManifestResponse,
}

/// Independent output streams for an ordinary non-interactive managed run.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum ManagedLogStream {
    Stdout,
    Stderr,
}

/// Sanitized IO categories for managed log collection and delivery. These
/// values never contain a path, OS error message, or log body.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum ManagedLogIoErrorKind {
    InvalidConfiguration,
    InvalidPath,
    NotFound,
    PermissionDenied,
    AlreadyExists,
    ResourceBusy,
    StorageFull,
    Interrupted,
    UnexpectedEof,
    InvalidData,
    LimitExceeded,
    WriteZero,
    Unavailable,
    OtherIo,
}

/// Resolved source encoding for one managed log stream. The stored/event text
/// is always normalized UTF-8 regardless of this source encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
#[ts(rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum ManagedLogEncoding {
    Utf8,
    Utf16Le,
    Utf16Be,
    WindowsCodePage { code_page: u16 },
}

/// Encoding and sanitization evidence for one stream snapshot. Historical
/// readers return `Unknown` when no trusted status record is available.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase")]
#[ts(rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum ManagedLogTextStatus {
    Known {
        encoding: ManagedLogEncoding,
        replacement_used: bool,
        controls_filtered: bool,
        fallback_unavailable: bool,
    },
    Unknown,
}

/// One bounded, ordered plain-text update for a managed-run stream. Offsets
/// count bytes in the filtered UTF-8 representation and remain within
/// JavaScript's exact integer range. Log text must never be emitted through
/// `Debug` or interpreted as HTML.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ManagedLogChunk {
    pub run_id: String,
    pub stream: ManagedLogStream,
    pub sequence: u64,
    pub first_available_byte_offset: u64,
    pub first_byte_offset: u64,
    pub next_byte_offset: u64,
    pub stream_end_byte_offset: u64,
    pub text: String,
    pub has_more: bool,
    pub caught_up: bool,
    pub end_of_file: bool,
    pub io_status_known: bool,
    pub disk_error: Option<ManagedLogIoErrorKind>,
    pub read_error: Option<ManagedLogIoErrorKind>,
    pub delivery_error: Option<ManagedLogIoErrorKind>,
    pub text_status: ManagedLogTextStatus,
}

impl fmt::Debug for ManagedLogChunk {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedLogChunk")
            .field("run_id", &self.run_id)
            .field("stream", &self.stream)
            .field("sequence", &self.sequence)
            .field(
                "first_available_byte_offset",
                &self.first_available_byte_offset,
            )
            .field("first_byte_offset", &self.first_byte_offset)
            .field("next_byte_offset", &self.next_byte_offset)
            .field("stream_end_byte_offset", &self.stream_end_byte_offset)
            .field("text", &"<redacted>")
            .field("has_more", &self.has_more)
            .field("caught_up", &self.caught_up)
            .field("end_of_file", &self.end_of_file)
            .field("io_status_known", &self.io_status_known)
            .field("disk_error", &self.disk_error)
            .field("read_error", &self.read_error)
            .field("delivery_error", &self.delivery_error)
            .field("text_status", &self.text_status)
            .finish()
    }
}

/// One throttled UI event containing at most one chunk per output stream.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ManagedLogBatch {
    pub chunks: Vec<ManagedLogChunk>,
}

impl fmt::Debug for ManagedLogBatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedLogBatch")
            .field("chunks", &"<redacted>")
            .finish()
    }
}

/// Requests a bounded filtered UTF-8 byte range from one managed-run stream.
/// An omitted offset asks for the first currently retained scalar boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct GetManagedLogRangeRequest {
    pub run_id: String,
    pub stream: ManagedLogStream,
    pub starting_byte_offset: Option<u64>,
    pub maximum_bytes: u32,
}

/// Bounded plain-text range plus the stream position observed atomically with
/// the read. Log text must never be emitted through `Debug` or interpreted as
/// HTML.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct GetManagedLogRangeResponse {
    pub run_id: String,
    pub stream: ManagedLogStream,
    pub observed_sequence: u64,
    pub first_available_byte_offset: u64,
    pub first_byte_offset: u64,
    pub next_byte_offset: u64,
    pub stream_end_byte_offset: u64,
    pub text: String,
    pub has_more: bool,
    pub complete: bool,
    pub end_of_file: bool,
    pub io_status_known: bool,
    pub disk_error: Option<ManagedLogIoErrorKind>,
    pub read_error: Option<ManagedLogIoErrorKind>,
    pub text_status: ManagedLogTextStatus,
}

impl fmt::Debug for GetManagedLogRangeResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GetManagedLogRangeResponse")
            .field("run_id", &self.run_id)
            .field("stream", &self.stream)
            .field("observed_sequence", &self.observed_sequence)
            .field(
                "first_available_byte_offset",
                &self.first_available_byte_offset,
            )
            .field("first_byte_offset", &self.first_byte_offset)
            .field("next_byte_offset", &self.next_byte_offset)
            .field("stream_end_byte_offset", &self.stream_end_byte_offset)
            .field("text", &"<redacted>")
            .field("has_more", &self.has_more)
            .field("complete", &self.complete)
            .field("end_of_file", &self.end_of_file)
            .field("io_status_known", &self.io_status_known)
            .field("disk_error", &self.disk_error)
            .field("read_error", &self.read_error)
            .field("text_status", &self.text_status)
            .finish()
    }
}

/// Requests a graceful stop for a Supervisor-owned managed run. The
/// idempotency key is carried only by the authenticated request envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct StopManagedRunRequest {
    pub run_id: String,
}

/// Requests a force stop through the control boundary established at launch.
/// An active graceful operation may be replaced only when its exact ID is
/// named, preventing a stale confirmation from superseding newer work.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ForceStopManagedRunRequest {
    pub run_id: String,
    pub supersede_operation_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum ManagedStopKind {
    Graceful,
    Force,
}

/// Durable progress of one idempotent stop operation. `Superseded` is a
/// terminal state used only when an explicitly linked force request replaces
/// a graceful operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum ManagedStopStatus {
    Requested,
    SignalPending,
    InProgress,
    TimedOut,
    Completed,
    Superseded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum ManagedStopSignalDisposition {
    Delivered,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum ManagedStopOutcome {
    Exited,
    AlreadyExited,
    IdentityMismatch,
    Orphaned,
    SignalUnavailable,
    Failed,
}

/// Public projection of a durable operation and its current run state. Signal
/// and outcome values are closed enums; platform diagnostics never cross this
/// boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ManagedStopOperationResult {
    pub operation_id: String,
    pub run: ManagedRunSummary,
    pub kind: ManagedStopKind,
    pub status: ManagedStopStatus,
    pub signal_disposition: Option<ManagedStopSignalDisposition>,
    pub outcome: Option<ManagedStopOutcome>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub completed_at: Option<Timestamp>,
}

/// Resolves lifecycle control for one exact process instance. The complete
/// identity is required so a stale selection cannot resolve a reused PID.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct GetProcessDetailsRequest {
    pub process_instance_key: ProcessInstanceKey,
}

/// Control evidence is mutually exclusive by construction. Managed details
/// carry the current durable run and, when present, its one active stop.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
#[ts(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum ProcessControl {
    External,
    Managed {
        run: ManagedRunSummary,
        active_stop: Option<ManagedStopOperationResult>,
    },
}

#[derive(Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum ProcessControlWire {
    External,
    Managed {
        run: ManagedRunSummary,
        active_stop: Option<ManagedStopOperationResult>,
    },
}

impl<'de> Deserialize<'de> for ProcessControl {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(match ProcessControlWire::deserialize(deserializer)? {
            ProcessControlWire::External => Self::External,
            ProcessControlWire::Managed { run, active_stop } => Self::Managed { run, active_stop },
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct GetProcessDetailsResponse {
    pub process_instance_key: ProcessInstanceKey,
    pub control: ProcessControl,
}

/// The only supported scope for stopping a process that was discovered but
/// was not launched through a Supervisor-owned control boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum ExternalProcessStopScope {
    SingleProcess,
}

/// Explicit user confirmation for one exact external process instance. The
/// identity is captured again here so a confirmation cannot be reused for a
/// different PID instance or widened to a process tree.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct StopExternalProcessConfirmation {
    pub process_instance_key: ProcessInstanceKey,
    pub scope: ExternalProcessStopScope,
}

/// Requests a conservative stop of one external process. Managed runs use
/// their separate run.stop and run.force_stop contracts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct StopExternalProcessRequest {
    pub confirmation: StopExternalProcessConfirmation,
}

/// A delivered stop signal does not prove that an external process exited.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum ExternalProcessStopOutcome {
    SignalDelivered,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct StopExternalProcessResult {
    pub process_instance_key: ProcessInstanceKey,
    pub scope: ExternalProcessStopScope,
    pub outcome: ExternalProcessStopOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum ExecutionPlatform {
    Windows,
    MacOs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum EnvironmentLayer {
    SupervisorBase,
    User,
    Project,
    Profile,
}

/// The client supplies only the profile being previewed. Platform and lower
/// environment layers come from a non-serializable Supervisor context.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ExecutionPreviewRequest {
    pub profile: LaunchProfileInput,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum EnvironmentPreviewValue {
    Plain(String),
    InheritedRedacted,
    CredentialReferenceRedacted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct EnvironmentPreviewEntry {
    pub name: String,
    pub value: EnvironmentPreviewValue,
    pub source: EnvironmentLayer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum PathUnknownReason {
    Missing,
    CredentialReference,
    InvalidValue,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct KnownPathResolution {
    pub value: String,
    pub source: EnvironmentLayer,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct UnknownPathResolution {
    pub reason: PathUnknownReason,
    pub source: Option<EnvironmentLayer>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(tag = "status", rename_all = "camelCase")]
#[ts(tag = "status", rename_all = "camelCase")]
pub enum PathResolution {
    Known(KnownPathResolution),
    Unknown(UnknownPathResolution),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct KnownPathExtensionResolution {
    pub value: String,
    pub extensions: Vec<String>,
    pub source: EnvironmentLayer,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct UnknownPathExtensionResolution {
    pub reason: PathUnknownReason,
    pub source: Option<EnvironmentLayer>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(tag = "status", rename_all = "camelCase")]
#[ts(tag = "status", rename_all = "camelCase")]
pub enum PathExtensionResolution {
    Known(KnownPathExtensionResolution),
    Unknown(UnknownPathExtensionResolution),
    NotApplicable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum PathEntryKind {
    Absolute,
    WorkingDirectoryEmpty,
    WorkingDirectoryRelative,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct PathExecutableCandidateSource {
    pub path_source: EnvironmentLayer,
    pub path_index: u16,
    pub entry_kind: PathEntryKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum ExecutableCandidateSource {
    Explicit,
    WorkingDirectory,
    Path(PathExecutableCandidateSource),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ExecutableCandidate {
    pub path: String,
    pub source: ExecutableCandidateSource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum ExecutableUnknownReason {
    FilesystemNotInspected,
    PathMissing,
    PathInvalidValue,
    PathCredentialReference,
    PathExtensionMissing,
    PathExtensionCredentialReference,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum ExecutableNotFoundReason {
    EmptySearchPath,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum ExecutableNotSupportedReason {
    ShellUnavailableOnPlatform,
    InvalidExecutablePath,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct UnknownExecutableResolution {
    pub reason: ExecutableUnknownReason,
    pub candidates: Vec<ExecutableCandidate>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct NotFoundExecutableResolution {
    pub reason: ExecutableNotFoundReason,
    pub candidates: Vec<ExecutableCandidate>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct NotSupportedExecutableResolution {
    pub reason: ExecutableNotSupportedReason,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(tag = "status", rename_all = "camelCase")]
#[ts(tag = "status", rename_all = "camelCase")]
pub enum ExecutableResolution {
    Unknown(UnknownExecutableResolution),
    NotFound(NotFoundExecutableResolution),
    NotSupported(NotSupportedExecutableResolution),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct DirectExecutionPreview {
    pub executable: String,
    pub argv: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ShellExecutionPreview {
    pub shell: ShellKind,
    pub executable: Option<String>,
    pub argv: Vec<String>,
    pub command: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(tag = "mode", rename_all = "camelCase")]
#[ts(tag = "mode", rename_all = "camelCase")]
pub enum ExecutionInvocationPreview {
    Direct(DirectExecutionPreview),
    Shell(ShellExecutionPreview),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct FinalExecutionPreview {
    pub platform: ExecutionPlatform,
    pub working_directory: String,
    pub interactive: bool,
    pub requires_credential_resolution: bool,
    pub invocation: ExecutionInvocationPreview,
    pub environment: Vec<EnvironmentPreviewEntry>,
    pub path: PathResolution,
    pub path_extensions: PathExtensionResolution,
    pub executable_resolution: ExecutableResolution,
}

impl<T> FieldValue<T> {
    pub fn known(value: T) -> Self {
        Self::Known(value)
    }

    pub fn as_ref(&self) -> FieldValue<&T> {
        match self {
            Self::Known(value) => FieldValue::Known(value),
            Self::Unknown => FieldValue::Unknown,
            Self::AccessLimited { reason } => FieldValue::AccessLimited {
                reason: reason.clone(),
            },
            Self::NotSupported => FieldValue::NotSupported,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum ProcessStatus {
    Running,
    Sleeping,
    Stopped,
    Zombie,
    Exited,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum AccessLevel {
    Full,
    Limited,
    Denied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum ProcessOwnership {
    Managed,
    External,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum PortProtocol {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum PortState {
    TcpListen,
    TcpEstablished,
    TcpOther,
    UdpBound,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum PortOwnershipConfidence {
    Exact,
    Shared,
    Inferred,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub struct PortBinding {
    pub protocol: PortProtocol,
    pub address_family: AddressFamily,
    pub local_address: String,
    pub local_port: u16,
    pub state: FieldValue<PortState>,
    pub process_instance_key: Option<ProcessInstanceKey>,
    pub confidence: PortOwnershipConfidence,
    pub observed_at: Timestamp,
}

/// Stable identity for a port binding. Observation metadata is deliberately
/// excluded so a binding can be removed after its mutable fields change.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct PortBindingKey {
    pub protocol: PortProtocol,
    pub address_family: AddressFamily,
    pub local_address: String,
    pub local_port: u16,
    pub process_instance_key: Option<ProcessInstanceKey>,
}

impl From<&PortBinding> for PortBindingKey {
    fn from(binding: &PortBinding) -> Self {
        Self {
            protocol: binding.protocol,
            address_family: binding.address_family,
            local_address: binding.local_address.clone(),
            local_port: binding.local_port,
            process_instance_key: binding.process_instance_key.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum ClassificationCategory {
    Development,
    Runtime,
    Infrastructure,
    Database,
    Excluded,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum UserClassificationOverride {
    Include,
    Exclude,
    AssignProject(ProjectId),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub struct ClassificationReason {
    pub code: String,
    pub score: i32,
    pub summary: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub struct ClassificationResult {
    pub score: i32,
    pub version: u32,
    pub category: ClassificationCategory,
    pub reasons: Vec<ClassificationReason>,
    pub user_override: Option<UserClassificationOverride>,
    pub is_development: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub struct ProcessRecord {
    pub instance_key: ProcessInstanceKey,
    pub parent_instance_key: FieldValue<Option<ProcessInstanceKey>>,
    pub owner_user: FieldValue<String>,
    pub executable_name: FieldValue<String>,
    pub executable_path: FieldValue<String>,
    pub command_line: FieldValue<String>,
    pub working_directory: FieldValue<String>,
    pub cpu_percent: FieldValue<f32>,
    pub memory_bytes: FieldValue<u64>,
    pub started_at: FieldValue<Timestamp>,
    pub status: FieldValue<ProcessStatus>,
    pub access_level: AccessLevel,
    pub ownership: ProcessOwnership,
    /// Present exactly when `ownership` is `Managed`. Native discovery never
    /// sets this Supervisor-owned association.
    pub managed_run_id: Option<String>,
    pub project_association: ProjectEvidence<ProjectAssociationEvidence>,
    pub project_features: ProjectEvidence<Vec<ProjectFeatureEvidence>>,
    /// Compatibility field derived from project evidence or an explicit
    /// AssignProject classification rule.
    pub project_id: Option<ProjectId>,
    pub classification: ClassificationResult,
    /// `Known(vec![])` means scanned with no bindings; other variants preserve
    /// not-scanned, permission-limited, and unsupported states.
    pub port_bindings: FieldValue<Vec<PortBinding>>,
    pub last_seen_revision: Revision,
}

/// Ephemeral UI demand for bounded process enrichment. The visible set is
/// validated by the Supervisor before any work is queued; a selected process
/// may also appear there and is then requested only at selected priority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct RequestProcessEnrichmentRequest {
    pub visible_process_instance_keys: Vec<ProcessInstanceKey>,
    pub selected_process_instance_key: Option<ProcessInstanceKey>,
}

/// Counts only process identities that the discovery scheduler accepted.
/// Missing identities are deliberately reported as not accepted rather than
/// failing the whole retryable, non-persistent request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct RequestProcessEnrichmentResponse {
    pub visible_accepted: u32,
    pub selected_accepted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct GetSnapshotRequest {
    pub starting_revision: Revision,
    /// Opaque continuation returned by the preceding chunk. `None` always
    /// starts a new, frozen snapshot session.
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct SystemSnapshot {
    /// Identifies the frozen server-side view shared by every chunk.
    pub snapshot_id: String,
    pub chunk_index: u32,
    pub revision: Revision,
    pub process_count: u32,
    pub port_binding_count: u32,
    pub total_entity_bytes: u64,
    pub processes: Vec<ProcessRecord>,
    pub port_bindings: Vec<PortBinding>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct ProcessDelta {
    pub upserted: Vec<ProcessRecord>,
    pub removed: Vec<ProcessInstanceKey>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct PortDelta {
    pub upserted: Vec<PortBinding>,
    pub removed: Vec<PortBindingKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename_all = "camelCase")]
pub enum RunState {
    Starting,
    Running,
    StopRequested,
    GracefulStopping,
    ForceStopping,
    Exited,
    Failed,
    Recovered,
    ExitedWhileOffline,
    IdentityMismatch,
    Orphaned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, TS)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[ts(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    InvalidArgument,
    NotFound,
    AlreadyExited,
    AccessDenied,
    IdentityMismatch,
    NotSupported,
    SupervisorUnavailable,
    Timeout,
    Conflict,
    StorageError,
    PlatformError,
    Internal,
}

#[derive(Clone, Debug, Error, PartialEq, Serialize, Deserialize, TS)]
#[error("{message}")]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[ts(rename_all = "camelCase")]
pub struct AppError {
    pub code: ErrorCode,
    pub message: String,
    pub details: BTreeMap<String, String>,
    pub retryable: bool,
    pub operation_id: Option<String>,
}

impl AppError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: BTreeMap::new(),
            retryable: false,
            operation_id: None,
        }
    }
}

/// Export root used by the deterministic `export-types` build tool.
#[derive(TS)]
pub struct DomainBindings {
    pub process_record: ProcessRecord,
    pub request_process_enrichment_request: RequestProcessEnrichmentRequest,
    pub request_process_enrichment_response: RequestProcessEnrichmentResponse,
    pub get_snapshot_request: GetSnapshotRequest,
    pub system_snapshot: SystemSnapshot,
    pub process_delta: ProcessDelta,
    pub port_binding_key: PortBindingKey,
    pub port_delta: PortDelta,
    pub project_association_evidence: ProjectAssociationEvidence,
    pub project_feature_evidence: ProjectFeatureEvidence,
    pub project_evidence: ProjectEvidence<ProjectFeatureEvidence>,
    pub project_input: ProjectInput,
    pub project_summary: ProjectSummary,
    pub create_project_request: CreateProjectRequest,
    pub update_project_request: UpdateProjectRequest,
    pub save_project_request: SaveProjectRequest,
    pub list_projects_request: ListProjectsRequest,
    pub list_projects_response: ListProjectsResponse,
    pub delete_project_request: DeleteProjectRequest,
    pub delete_project_response: DeleteProjectResponse,
    pub classification_rule_matcher_kind: ClassificationRuleMatcherKind,
    pub classification_rule_action: ClassificationRuleAction,
    pub classification_rule_input: ClassificationRuleInput,
    pub classification_rule_summary: ClassificationRuleSummary,
    pub create_classification_rule_request: CreateClassificationRuleRequest,
    pub update_classification_rule_request: UpdateClassificationRuleRequest,
    pub save_classification_rule_request: SaveClassificationRuleRequest,
    pub list_classification_rules_request: ListClassificationRulesRequest,
    pub list_classification_rules_response: ListClassificationRulesResponse,
    pub delete_classification_rule_request: DeleteClassificationRuleRequest,
    pub delete_classification_rule_response: DeleteClassificationRuleResponse,
    pub launch_profile: LaunchProfile,
    pub launch_profile_input: LaunchProfileInput,
    pub save_launch_profile_request: SaveLaunchProfileRequest,
    pub list_launch_profiles_request: ListLaunchProfilesRequest,
    pub list_launch_profiles_response: ListLaunchProfilesResponse,
    pub save_launch_profile_with_secrets_request: SaveLaunchProfileWithSecretsRequest,
    pub detected_script_suggestion: DetectedScriptSuggestion,
    pub delete_launch_profile_request: DeleteLaunchProfileRequest,
    pub delete_launch_profile_response: DeleteLaunchProfileResponse,
    pub execution_preview_request: ExecutionPreviewRequest,
    pub final_execution_preview: FinalExecutionPreview,
    pub start_managed_run_request: StartManagedRunRequest,
    pub managed_run_summary: ManagedRunSummary,
    pub start_managed_run_result: StartManagedRunResult,
    pub get_exit_impact_request: GetExitImpactRequest,
    pub exit_retained_reason: ExitRetainedReason,
    pub exit_run_impact: ExitRunImpact,
    pub exit_impact_summary: ExitImpactSummary,
    pub stop_all_for_exit_request: StopAllForExitRequest,
    pub stop_all_for_exit_member_action: StopAllForExitMemberAction,
    pub stop_all_for_exit_member_result: StopAllForExitMemberResult,
    pub stop_all_for_exit_status: StopAllForExitStatus,
    pub stop_all_for_exit_result: StopAllForExitResult,
    pub run_history_item: RunHistoryItem,
    pub list_run_history_request: ListRunHistoryRequest,
    pub list_run_history_response: ListRunHistoryResponse,
    pub diagnostic_content_kind: DiagnosticContentKind,
    pub diagnostic_content_privacy: DiagnosticContentPrivacy,
    pub diagnostic_manifest_item: DiagnosticManifestItem,
    pub get_diagnostics_manifest_request: GetDiagnosticsManifestRequest,
    pub get_diagnostics_manifest_response: GetDiagnosticsManifestResponse,
    pub export_diagnostics_request: ExportDiagnosticsRequest,
    pub export_diagnostics_result: ExportDiagnosticsResult,
    pub managed_log_stream: ManagedLogStream,
    pub managed_log_io_error_kind: ManagedLogIoErrorKind,
    pub managed_log_encoding: ManagedLogEncoding,
    pub managed_log_text_status: ManagedLogTextStatus,
    pub managed_log_chunk: ManagedLogChunk,
    pub managed_log_batch: ManagedLogBatch,
    pub get_managed_log_range_request: GetManagedLogRangeRequest,
    pub get_managed_log_range_response: GetManagedLogRangeResponse,
    pub stop_managed_run_request: StopManagedRunRequest,
    pub force_stop_managed_run_request: ForceStopManagedRunRequest,
    pub managed_stop_kind: ManagedStopKind,
    pub managed_stop_status: ManagedStopStatus,
    pub managed_stop_signal_disposition: ManagedStopSignalDisposition,
    pub managed_stop_outcome: ManagedStopOutcome,
    pub managed_stop_operation_result: ManagedStopOperationResult,
    pub get_process_details_request: GetProcessDetailsRequest,
    pub process_control: ProcessControl,
    pub get_process_details_response: GetProcessDetailsResponse,
    pub external_process_stop_scope: ExternalProcessStopScope,
    pub stop_external_process_confirmation: StopExternalProcessConfirmation,
    pub stop_external_process_request: StopExternalProcessRequest,
    pub external_process_stop_outcome: ExternalProcessStopOutcome,
    pub stop_external_process_result: StopExternalProcessResult,
    pub run_state: RunState,
    pub app_error: AppError,
}
