use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::path::Path;
use std::sync::Arc;

use domain::{
    AppError, ErrorCode, ProcessInstanceKey, ProjectAssociationEvidence, ProjectEvidence,
    ProjectFeatureEvidence, ProjectId,
};

use crate::backend::CancellationToken;
use crate::classification::{ClassificationRulesSnapshot, ProcessClassificationFacts};

pub const MAX_PROJECT_CATALOG_ENTRIES: usize = 4_096;
pub const MAX_PROJECT_PATH_BYTES: usize = 32 * 1_024;
pub const MAX_PROJECT_ANCESTOR_DEPTH: usize = 64;
pub const MAX_PROJECT_FEATURES: usize = 32;

const MAX_PROJECT_ID_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum NormalizedPathRoot {
    Posix,
    WindowsDrive(char),
    WindowsUnc { server: String, share: String },
}

/// An opaque, component-aware comparison key produced from a platform's
/// losslessly canonicalized path.
///
/// Platform adapters must resolve aliases and apply their comparison casing
/// before calling [`NormalizedPathKey::from_canonical_components`].
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct NormalizedPathKey {
    root: NormalizedPathRoot,
    components: Vec<String>,
}

impl NormalizedPathKey {
    pub fn from_canonical_components(
        root: NormalizedPathRoot,
        components: Vec<String>,
    ) -> Result<Self, AppError> {
        if components.len() > MAX_PROJECT_ANCESTOR_DEPTH {
            return Err(invalid_project_input(
                "normalizedPath",
                "exceeds the supported component depth",
            ));
        }
        let root = match root {
            NormalizedPathRoot::WindowsDrive(drive) => {
                NormalizedPathRoot::WindowsDrive(drive.to_ascii_uppercase())
            }
            root => root,
        };
        validate_root(&root)?;
        for component in &components {
            validate_component(&root, component)?;
        }
        let key = Self { root, components };
        if key.encoded_len() > MAX_PROJECT_PATH_BYTES {
            return Err(invalid_project_input(
                "normalizedPath",
                "exceeds the supported path length",
            ));
        }
        Ok(key)
    }

    pub fn to_storage_string(&self) -> String {
        let (kind, root) = match &self.root {
            NormalizedPathRoot::Posix => ("p", String::new()),
            NormalizedPathRoot::WindowsDrive(drive) => ("d", drive.to_string()),
            NormalizedPathRoot::WindowsUnc { server, share } => {
                ("u", format!("{}:{}", hex_encode(server), hex_encode(share)))
            }
        };
        let components = self
            .components
            .iter()
            .map(|component| hex_encode(component))
            .collect::<Vec<_>>()
            .join("/");
        format!("mtpk1|{kind}|{root}|{components}")
    }

    pub fn from_storage_string(value: &str) -> Result<Self, AppError> {
        if value.len() > MAX_PROJECT_PATH_BYTES.saturating_mul(2).saturating_add(128) {
            return Err(invalid_project_input(
                "normalizedPath",
                "encoded key exceeds the supported length",
            ));
        }
        let fields = value.split('|').collect::<Vec<_>>();
        if fields.len() != 4 || fields[0] != "mtpk1" {
            return Err(invalid_project_input(
                "normalizedPath",
                "is not a supported versioned path key",
            ));
        }
        let root = match fields[1] {
            "p" if fields[2].is_empty() => NormalizedPathRoot::Posix,
            "d" => {
                let mut characters = fields[2].chars();
                let drive = characters
                    .next()
                    .filter(|_| characters.next().is_none())
                    .ok_or_else(|| {
                        invalid_project_input(
                            "normalizedPath",
                            "contains an invalid encoded drive root",
                        )
                    })?;
                NormalizedPathRoot::WindowsDrive(drive)
            }
            "u" => {
                let (server, share) = fields[2].split_once(':').ok_or_else(|| {
                    invalid_project_input("normalizedPath", "contains an invalid encoded UNC root")
                })?;
                NormalizedPathRoot::WindowsUnc {
                    server: hex_decode(server)?,
                    share: hex_decode(share)?,
                }
            }
            _ => {
                return Err(invalid_project_input(
                    "normalizedPath",
                    "contains an unknown encoded root kind",
                ));
            }
        };
        let components = if fields[3].is_empty() {
            Vec::new()
        } else {
            fields[3]
                .split('/')
                .map(hex_decode)
                .collect::<Result<Vec<_>, _>>()?
        };
        let key = Self::from_canonical_components(root, components)?;
        if key.to_storage_string() != value {
            return Err(invalid_project_input(
                "normalizedPath",
                "is not in canonical encoded form",
            ));
        }
        Ok(key)
    }

    pub fn root(&self) -> &NormalizedPathRoot {
        &self.root
    }

    pub fn components(&self) -> &[String] {
        &self.components
    }

    pub fn component_count(&self) -> usize {
        self.components.len()
    }

    pub fn parent(&self) -> Option<Self> {
        if self.components.is_empty() {
            return None;
        }
        let mut components = self.components.clone();
        components.pop();
        Some(Self {
            root: self.root.clone(),
            components,
        })
    }

    fn encoded_len(&self) -> usize {
        let root_len = match &self.root {
            NormalizedPathRoot::Posix => 1,
            NormalizedPathRoot::WindowsDrive(_) => 3,
            NormalizedPathRoot::WindowsUnc { server, share } => 2_usize
                .saturating_add(server.len())
                .saturating_add(1)
                .saturating_add(share.len()),
        };
        self.components.iter().fold(root_len, |length, component| {
            length.saturating_add(1).saturating_add(component.len())
        })
    }
}

/// A canonical project root and its comparison key produced together by a
/// platform backend. This type is deliberately not serializable so an IPC
/// client cannot submit a normalized key as trusted input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedProjectRoot {
    canonical_root_directory: String,
    normalized_path: NormalizedPathKey,
}

impl NormalizedProjectRoot {
    pub fn from_platform_observation(
        canonical_root_directory: String,
        normalized_path: NormalizedPathKey,
    ) -> Result<Self, AppError> {
        validate_non_empty_bounded(
            "canonicalRootDirectory",
            &canonical_root_directory,
            MAX_PROJECT_PATH_BYTES,
        )?;
        if canonical_root_directory.contains('\0')
            || !canonical_root_matches_key(&canonical_root_directory, &normalized_path)
        {
            return Err(invalid_project_input(
                "canonicalRootDirectory",
                "is not an absolute canonical path matching the normalized root flavor",
            ));
        }
        Ok(Self {
            canonical_root_directory,
            normalized_path,
        })
    }

    pub fn canonical_root_directory(&self) -> &str {
        &self.canonical_root_directory
    }

    pub fn normalized_path(&self) -> &NormalizedPathKey {
        &self.normalized_path
    }
}

fn canonical_root_matches_key(path: &str, key: &NormalizedPathKey) -> bool {
    match key.root() {
        NormalizedPathRoot::Posix => path.starts_with('/'),
        NormalizedPathRoot::WindowsDrive(drive) => {
            let bytes = path.as_bytes();
            bytes.len() >= 3
                && drive.eq_ignore_ascii_case(&(bytes[0] as char))
                && bytes[1] == b':'
                && bytes[2] == b'\\'
        }
        NormalizedPathRoot::WindowsUnc { .. } => {
            path.starts_with("\\\\") && !path.starts_with("\\\\?\\") && !path.starts_with("\\\\.\\")
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredProject {
    pub id: ProjectId,
    pub root_directory: String,
    pub normalized_path: NormalizedPathKey,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProjectCatalogSnapshot {
    pub projects: Vec<RegisteredProject>,
}

#[derive(Clone, Debug)]
pub struct ProjectCatalog {
    projects_by_root: HashMap<NormalizedPathKey, RegisteredProject>,
    project_ids: HashSet<ProjectId>,
}

impl ProjectCatalog {
    pub fn new(snapshot: ProjectCatalogSnapshot) -> Result<Self, AppError> {
        if snapshot.projects.len() > MAX_PROJECT_CATALOG_ENTRIES {
            return Err(invalid_project_input(
                "projects",
                "exceeds the supported catalog capacity",
            ));
        }

        let mut projects_by_root = HashMap::with_capacity(snapshot.projects.len());
        let mut project_ids = HashSet::with_capacity(snapshot.projects.len());
        for project in snapshot.projects {
            validate_non_empty_bounded("projectId", &project.id, MAX_PROJECT_ID_BYTES)?;
            validate_non_empty_bounded(
                "rootDirectory",
                &project.root_directory,
                MAX_PROJECT_PATH_BYTES,
            )?;
            if !Path::new(&project.root_directory).is_absolute() {
                return Err(invalid_project_input(
                    "rootDirectory",
                    "must be an absolute path",
                ));
            }
            if !project_ids.insert(project.id.clone()) {
                return Err(invalid_project_input(
                    "projects",
                    "contains a duplicate project ID",
                ));
            }
            if projects_by_root
                .insert(project.normalized_path.clone(), project)
                .is_some()
            {
                return Err(invalid_project_input(
                    "projects",
                    "contains a duplicate normalized project root",
                ));
            }
        }
        Ok(Self {
            projects_by_root,
            project_ids,
        })
    }

    pub fn empty() -> Arc<Self> {
        Arc::new(Self {
            projects_by_root: HashMap::new(),
            project_ids: HashSet::new(),
        })
    }

    pub fn len(&self) -> usize {
        self.projects_by_root.len()
    }

    pub fn is_empty(&self) -> bool {
        self.projects_by_root.is_empty()
    }

    pub fn contains_project_id(&self, project_id: &str) -> bool {
        self.project_ids.contains(project_id)
    }

    pub fn project_ids(&self) -> Vec<ProjectId> {
        let mut project_ids = self.project_ids.iter().cloned().collect::<Vec<_>>();
        project_ids.sort();
        project_ids
    }

    pub fn nearest_project(
        &self,
        working_directory: &NormalizedPathKey,
    ) -> Option<&RegisteredProject> {
        let mut candidate = working_directory.clone();
        loop {
            if let Some(project) = self.projects_by_root.get(&candidate) {
                return Some(project);
            }
            if candidate.components.pop().is_none() {
                break;
            }
        }
        None
    }

    pub fn association_for(
        &self,
        working_directory: &NormalizedPathKey,
    ) -> ProjectEvidence<ProjectAssociationEvidence> {
        self.nearest_project(working_directory)
            .map(|project| {
                ProjectEvidence::Known(ProjectAssociationEvidence {
                    project_id: project.id.clone(),
                    registered_root: project.root_directory.clone(),
                })
            })
            .unwrap_or(ProjectEvidence::Missing)
    }
}

impl Default for ProjectCatalog {
    fn default() -> Self {
        Self {
            projects_by_root: HashMap::new(),
            project_ids: HashSet::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectMarker {
    pub id: &'static str,
    pub file_name: &'static str,
}

pub const PROJECT_MARKERS: &[ProjectMarker] = &[
    ProjectMarker {
        id: "node.packageJson",
        file_name: "package.json",
    },
    ProjectMarker {
        id: "rust.cargoToml",
        file_name: "Cargo.toml",
    },
    ProjectMarker {
        id: "go.module",
        file_name: "go.mod",
    },
    ProjectMarker {
        id: "java.mavenPom",
        file_name: "pom.xml",
    },
    ProjectMarker {
        id: "java.gradleSettingsKts",
        file_name: "settings.gradle.kts",
    },
    ProjectMarker {
        id: "java.gradleSettings",
        file_name: "settings.gradle",
    },
    ProjectMarker {
        id: "java.gradleBuildKts",
        file_name: "build.gradle.kts",
    },
    ProjectMarker {
        id: "java.gradleBuild",
        file_name: "build.gradle",
    },
    ProjectMarker {
        id: "python.pyproject",
        file_name: "pyproject.toml",
    },
    ProjectMarker {
        id: "python.requirements",
        file_name: "requirements.txt",
    },
    ProjectMarker {
        id: "python.pipfile",
        file_name: "Pipfile",
    },
    ProjectMarker {
        id: "ruby.gemfile",
        file_name: "Gemfile",
    },
    ProjectMarker {
        id: "php.composerJson",
        file_name: "composer.json",
    },
    ProjectMarker {
        id: "dotnet.globalJson",
        file_name: "global.json",
    },
    ProjectMarker {
        id: "native.cmakeLists",
        file_name: "CMakeLists.txt",
    },
    ProjectMarker {
        id: "native.makefile",
        file_name: "Makefile",
    },
];

#[derive(Clone, Debug)]
pub struct ProjectScanRequest {
    pub instance_key: ProcessInstanceKey,
    pub expected_working_directory: String,
    pub catalog: Arc<ProjectCatalog>,
    pub catalog_generation: u64,
    pub cancellation: CancellationToken,
}

impl ProjectScanRequest {
    pub fn new(
        instance_key: ProcessInstanceKey,
        expected_working_directory: String,
        catalog: Arc<ProjectCatalog>,
        catalog_generation: u64,
        cancellation: CancellationToken,
    ) -> Result<Self, AppError> {
        validate_non_empty_bounded(
            "workingDirectory",
            &expected_working_directory,
            MAX_PROJECT_PATH_BYTES,
        )?;
        Ok(Self {
            instance_key,
            expected_working_directory,
            catalog,
            catalog_generation,
            cancellation,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectScanResult {
    pub instance_key: ProcessInstanceKey,
    pub expected_working_directory: String,
    pub catalog_generation: u64,
    pub normalized_working_directory: ProjectEvidence<NormalizedPathKey>,
    pub association: ProjectEvidence<ProjectAssociationEvidence>,
    pub features: ProjectEvidence<Vec<ProjectFeatureEvidence>>,
}

impl ProjectScanResult {
    pub fn from_platform_observation(
        request: &ProjectScanRequest,
        normalized_working_directory: ProjectEvidence<NormalizedPathKey>,
        features: ProjectEvidence<Vec<ProjectFeatureEvidence>>,
    ) -> Result<Self, AppError> {
        validate_project_evidence(&normalized_working_directory, &features)?;
        let association =
            association_from_normalized(request.catalog.as_ref(), &normalized_working_directory);
        Ok(Self {
            instance_key: request.instance_key.clone(),
            expected_working_directory: request.expected_working_directory.clone(),
            catalog_generation: request.catalog_generation,
            normalized_working_directory,
            association,
            features,
        })
    }

    pub fn not_supported(request: &ProjectScanRequest) -> Self {
        Self {
            instance_key: request.instance_key.clone(),
            expected_working_directory: request.expected_working_directory.clone(),
            catalog_generation: request.catalog_generation,
            normalized_working_directory: ProjectEvidence::NotSupported,
            association: ProjectEvidence::NotSupported,
            features: ProjectEvidence::NotSupported,
        }
    }

    pub fn validate_for(&self, request: &ProjectScanRequest) -> Result<(), AppError> {
        if self.instance_key != request.instance_key
            || self.expected_working_directory != request.expected_working_directory
            || self.catalog_generation != request.catalog_generation
        {
            return Err(invalid_project_result(
                "project scan result does not match its request",
            ));
        }
        validate_project_evidence(&self.normalized_working_directory, &self.features)?;
        let expected_association = association_from_normalized(
            request.catalog.as_ref(),
            &self.normalized_working_directory,
        );
        if self.association != expected_association {
            return Err(invalid_project_result(
                "project association is inconsistent with the normalized path",
            ));
        }
        Ok(())
    }

    pub fn classification_facts(&self) -> ProcessClassificationFacts {
        let working_directory_project_id = match &self.association {
            ProjectEvidence::Known(association) => Some(association.project_id.clone()),
            ProjectEvidence::Missing
            | ProjectEvidence::Unknown
            | ProjectEvidence::AccessLimited { .. }
            | ProjectEvidence::NotSupported => None,
        };
        let project_feature_id = match &self.features {
            ProjectEvidence::Known(features) => {
                features.first().map(|feature| feature.marker_id.clone())
            }
            ProjectEvidence::Missing
            | ProjectEvidence::Unknown
            | ProjectEvidence::AccessLimited { .. }
            | ProjectEvidence::NotSupported => None,
        };
        ProcessClassificationFacts {
            working_directory_project_id,
            project_feature_id,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProjectContextSnapshot {
    pub catalog: ProjectCatalogSnapshot,
    pub classification_rules: ClassificationRulesSnapshot,
}

fn association_from_normalized(
    catalog: &ProjectCatalog,
    normalized: &ProjectEvidence<NormalizedPathKey>,
) -> ProjectEvidence<ProjectAssociationEvidence> {
    match normalized {
        ProjectEvidence::Known(path) => catalog.association_for(path),
        ProjectEvidence::Missing => ProjectEvidence::Missing,
        ProjectEvidence::Unknown => ProjectEvidence::Unknown,
        ProjectEvidence::AccessLimited { reason } => ProjectEvidence::AccessLimited {
            reason: reason.clone(),
        },
        ProjectEvidence::NotSupported => ProjectEvidence::NotSupported,
    }
}

fn validate_feature_evidence(
    features: &ProjectEvidence<Vec<ProjectFeatureEvidence>>,
) -> Result<(), AppError> {
    let ProjectEvidence::Known(features) = features else {
        return Ok(());
    };
    if features.len() > MAX_PROJECT_FEATURES {
        return Err(invalid_project_result(
            "project feature evidence exceeds the supported capacity",
        ));
    }
    let mut marker_ids = HashSet::with_capacity(features.len());
    let mut last_marker_index = None;
    let detected_root = features
        .first()
        .map(|feature| feature.detected_root.as_str());
    for feature in features {
        let (marker_index, marker) = PROJECT_MARKERS
            .iter()
            .enumerate()
            .find(|(_, marker)| marker.id == feature.marker_id)
            .ok_or_else(|| {
                invalid_project_result("project feature evidence contains an unknown marker ID")
            })?;
        if last_marker_index.is_some_and(|previous| marker_index <= previous) {
            return Err(invalid_project_result(
                "project feature evidence is not in fixed marker order",
            ));
        }
        last_marker_index = Some(marker_index);
        if !marker_ids.insert(feature.marker_id.as_str()) {
            return Err(invalid_project_result(
                "project feature evidence contains a duplicate marker ID",
            ));
        }
        validate_non_empty_bounded("markerPath", &feature.marker_path, MAX_PROJECT_PATH_BYTES)?;
        validate_non_empty_bounded(
            "detectedRoot",
            &feature.detected_root,
            MAX_PROJECT_PATH_BYTES,
        )?;
        if !Path::new(&feature.marker_path).is_absolute()
            || !Path::new(&feature.detected_root).is_absolute()
        {
            return Err(invalid_project_result(
                "project feature evidence paths must be absolute",
            ));
        }
        if detected_root != Some(feature.detected_root.as_str()) {
            return Err(invalid_project_result(
                "project features must come from one nearest detected root",
            ));
        }
        if Path::new(&feature.marker_path).parent() != Some(Path::new(&feature.detected_root)) {
            return Err(invalid_project_result(
                "project marker must be a direct child of its detected root",
            ));
        }
        if Path::new(&feature.marker_path).file_name() != Some(OsStr::new(marker.file_name)) {
            return Err(invalid_project_result(
                "project marker path does not match its marker ID",
            ));
        }
    }
    Ok(())
}

fn validate_project_evidence(
    normalized: &ProjectEvidence<NormalizedPathKey>,
    features: &ProjectEvidence<Vec<ProjectFeatureEvidence>>,
) -> Result<(), AppError> {
    let states_are_consistent = matches!(
        (normalized, features),
        (
            ProjectEvidence::Known(_),
            ProjectEvidence::Known(_)
                | ProjectEvidence::AccessLimited { .. }
                | ProjectEvidence::NotSupported
        ) | (ProjectEvidence::Missing, ProjectEvidence::Missing)
            | (ProjectEvidence::Unknown, ProjectEvidence::Unknown)
            | (
                ProjectEvidence::AccessLimited { .. },
                ProjectEvidence::AccessLimited { .. }
            )
            | (ProjectEvidence::NotSupported, ProjectEvidence::NotSupported)
    );
    if !states_are_consistent {
        return Err(invalid_project_result(
            "normalized path and project feature evidence states are inconsistent",
        ));
    }
    validate_feature_evidence(features)
}

fn validate_root(root: &NormalizedPathRoot) -> Result<(), AppError> {
    match root {
        NormalizedPathRoot::Posix => Ok(()),
        NormalizedPathRoot::WindowsDrive(drive) if drive.is_ascii_alphabetic() => Ok(()),
        NormalizedPathRoot::WindowsDrive(_) => Err(invalid_project_input(
            "normalizedPath",
            "contains an invalid Windows drive root",
        )),
        NormalizedPathRoot::WindowsUnc { server, share } => {
            validate_windows_component("UNC server", server)?;
            validate_windows_component("UNC share", share)
        }
    }
}

fn validate_component(root: &NormalizedPathRoot, component: &str) -> Result<(), AppError> {
    if component.is_empty() || component == "." || component == ".." || component.contains('\0') {
        return Err(invalid_project_input(
            "normalizedPath",
            "contains an empty or relative component",
        ));
    }
    if component.contains('/')
        || (!matches!(root, NormalizedPathRoot::Posix) && component.contains('\u{5c}'))
    {
        return Err(invalid_project_input(
            "normalizedPath",
            "contains a path separator inside a component",
        ));
    }
    Ok(())
}

fn validate_windows_component(field: &str, component: &str) -> Result<(), AppError> {
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.contains('\0')
        || component.contains(['/', '\u{5c}'])
    {
        return Err(invalid_project_input(
            "normalizedPath",
            &format!("contains an invalid {field}"),
        ));
    }
    Ok(())
}

fn validate_non_empty_bounded(
    field: &str,
    value: &str,
    maximum_bytes: usize,
) -> Result<(), AppError> {
    if value.trim().is_empty() {
        return Err(invalid_project_input(field, "must not be empty"));
    }
    if value.len() > maximum_bytes {
        return Err(invalid_project_input(field, "exceeds the supported length"));
    }
    Ok(())
}

fn hex_encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(value.len().saturating_mul(2));
    for byte in value.bytes() {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn hex_decode(value: &str) -> Result<String, AppError> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return Err(invalid_project_input(
            "normalizedPath",
            "contains an invalid hexadecimal component",
        ));
    }
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = hex_nibble(pair[0]).ok_or_else(|| {
            invalid_project_input(
                "normalizedPath",
                "contains an invalid hexadecimal component",
            )
        })?;
        let low = hex_nibble(pair[1]).ok_or_else(|| {
            invalid_project_input(
                "normalizedPath",
                "contains an invalid hexadecimal component",
            )
        })?;
        decoded.push((high << 4) | low);
    }
    String::from_utf8(decoded).map_err(|_| {
        invalid_project_input("normalizedPath", "contains a non-UTF-8 encoded component")
    })
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn invalid_project_input(field: &str, reason: &str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "invalid project discovery input",
    );
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn invalid_project_result(reason: &str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "project discovery backend returned invalid evidence",
    );
    error.details.insert("reason".into(), reason.into());
    error
}
