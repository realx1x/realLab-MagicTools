use std::collections::HashMap;

use domain::{
    AppError, DirectExecutionPreview, EnvironmentLayer, EnvironmentPreviewEntry,
    EnvironmentPreviewValue, ExecutableCandidate, ExecutableCandidateSource,
    ExecutableNotSupportedReason, ExecutableResolution, ExecutableUnknownReason,
    ExecutionInvocationPreview, ExecutionPlatform, ExecutionPreviewRequest, FinalExecutionPreview,
    KnownPathExtensionResolution, KnownPathResolution, LaunchEnvironmentEntry,
    LaunchEnvironmentValue, LaunchExecution, NotSupportedExecutableResolution, PathEntryKind,
    PathExecutableCandidateSource, PathExtensionResolution, PathResolution, PathUnknownReason,
    ShellExecutionPreview, ShellKind, UnknownExecutableResolution, UnknownPathExtensionResolution,
    UnknownPathResolution,
};
use platform_common::credentials::{CredentialReference, CredentialSlot, SecretBytes, SecretStore};

use crate::{
    MAX_LAUNCH_ENVIRONMENT_ENTRIES, MAX_LAUNCH_PROFILE_INPUT_WIRE_BYTES,
    MAX_LAUNCH_WORKING_DIRECTORY_BYTES, invalid_launch_input, validate_environment_for_platform,
    validate_launch_profile_input,
};

pub const MAX_EXECUTION_PREVIEW_WIRE_BYTES: usize = 896 * 1_024;
pub const MAX_EXECUTABLE_CANDIDATES: usize = 256;
pub const MAX_EXECUTABLE_CANDIDATE_TOTAL_BYTES: usize = 256 * 1_024;
pub const MAX_PATH_ENTRIES: usize = 256;
pub const MAX_PATH_EXTENSIONS: usize = 64;
pub const MAX_PATH_EXTENSION_BYTES: usize = 16;
pub const MAX_MERGED_ENVIRONMENT_TOTAL_BYTES: usize = 256 * 1_024;
pub const MAX_WINDOWS_COMMAND_LINE_UTF16_UNITS: usize = 32_767;
pub const MAX_WINDOWS_ENVIRONMENT_UTF16_UNITS: usize = 32_767;
pub const MAX_MACOS_EXEC_ARGUMENT_ENV_BYTES: usize = 256 * 1_024;

/// Trusted, process-local context assembled by the Supervisor. It cannot be
/// deserialized from IPC and intentionally has no `Debug` implementation.
#[derive(Clone)]
pub struct ExecutionPreviewContext {
    platform: ExecutionPlatform,
    supervisor_base_environment: Vec<LaunchEnvironmentEntry>,
    user_environment: Vec<LaunchEnvironmentEntry>,
    project_environment: Vec<LaunchEnvironmentEntry>,
}

impl ExecutionPreviewContext {
    pub fn from_supervisor_layers(
        supervisor_base_environment: Vec<LaunchEnvironmentEntry>,
        user_environment: Vec<LaunchEnvironmentEntry>,
        project_environment: Vec<LaunchEnvironmentEntry>,
    ) -> Result<Self, AppError> {
        let platform = current_platform()?;
        let windows = platform == ExecutionPlatform::Windows;
        validate_environment_for_platform(&supervisor_base_environment, windows)?;
        validate_environment_for_platform(&user_environment, windows)?;
        validate_environment_for_platform(&project_environment, windows)?;
        Ok(Self {
            platform,
            supervisor_base_environment,
            user_environment,
            project_environment,
        })
    }

    pub fn platform(&self) -> ExecutionPlatform {
        self.platform
    }
}

/// Opaque merged values retained for the later credential-resolution stage.
/// This type is neither serializable nor debug-printable.
pub struct MergedEnvironment {
    platform: ExecutionPlatform,
    entries: Vec<MergedEnvironmentEntry>,
}

struct MergedEnvironmentEntry {
    name: String,
    value: LaunchEnvironmentValue,
    source: EnvironmentLayer,
}

/// Final process-local environment after system credentials are read. This
/// value is intentionally neither serializable, cloneable, nor debug-printable.
pub struct ResolvedEnvironment {
    platform: ExecutionPlatform,
    entries: Vec<ResolvedEnvironmentEntry>,
}

impl ResolvedEnvironment {
    pub fn platform(&self) -> ExecutionPlatform {
        self.platform
    }

    pub fn entries(&self) -> &[ResolvedEnvironmentEntry] {
        &self.entries
    }
}

pub struct ResolvedEnvironmentEntry {
    name: String,
    value: ResolvedEnvironmentValue,
    source: EnvironmentLayer,
}

impl ResolvedEnvironmentEntry {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn value(&self) -> &ResolvedEnvironmentValue {
        &self.value
    }

    pub fn source(&self) -> EnvironmentLayer {
        self.source
    }
}

pub enum ResolvedEnvironmentValue {
    Plain(String),
    Secret(SecretBytes),
}

impl ResolvedEnvironmentValue {
    pub fn expose(&self) -> &str {
        match self {
            Self::Plain(value) => value,
            Self::Secret(value) => value.expose_utf8(),
        }
    }
}

pub fn merge_environment(
    context: &ExecutionPreviewContext,
    profile_environment: &[LaunchEnvironmentEntry],
) -> Result<MergedEnvironment, AppError> {
    let windows = context.platform == ExecutionPlatform::Windows;
    validate_environment_for_platform(profile_environment, windows)?;

    let mut entries = Vec::new();
    let mut indices = HashMap::<String, usize>::new();
    merge_layer(
        &mut entries,
        &mut indices,
        &context.supervisor_base_environment,
        EnvironmentLayer::SupervisorBase,
        windows,
    )?;
    merge_layer(
        &mut entries,
        &mut indices,
        &context.user_environment,
        EnvironmentLayer::User,
        windows,
    )?;
    merge_layer(
        &mut entries,
        &mut indices,
        &context.project_environment,
        EnvironmentLayer::Project,
        windows,
    )?;
    merge_layer(
        &mut entries,
        &mut indices,
        profile_environment,
        EnvironmentLayer::Profile,
        windows,
    )?;
    entries.sort_by(|left, right| {
        environment_key(&left.name, windows).cmp(&environment_key(&right.name, windows))
    });
    let merged_bytes = entries.iter().fold(0_usize, |total, entry| {
        let value_bytes = match &entry.value {
            LaunchEnvironmentValue::Plain(value) => value.value.len(),
            LaunchEnvironmentValue::CredentialReference(reference) => {
                reference.credential_reference.len()
            }
        };
        total
            .saturating_add(entry.name.len())
            .saturating_add(value_bytes)
    });
    if merged_bytes > MAX_MERGED_ENVIRONMENT_TOTAL_BYTES {
        return Err(invalid_launch_input(
            "environment",
            "merged environment exceeds the supported total length",
        ));
    }
    Ok(MergedEnvironment {
        platform: context.platform,
        entries,
    })
}

pub fn resolve_environment_credentials(
    profile_id: &str,
    merged: MergedEnvironment,
    store: &dyn SecretStore,
) -> Result<ResolvedEnvironment, AppError> {
    let mut entries = Vec::with_capacity(merged.entries.len());
    for entry in merged.entries {
        let value = match entry.value {
            LaunchEnvironmentValue::Plain(value) => ResolvedEnvironmentValue::Plain(value.value),
            LaunchEnvironmentValue::CredentialReference(reference) => {
                let reference = CredentialReference::parse(&reference.credential_reference)?;
                if entry.source == EnvironmentLayer::Profile {
                    let slot = CredentialSlot::new(profile_id.to_owned(), entry.name.clone())?;
                    if !reference.belongs_to(&slot) {
                        return Err(invalid_launch_input(
                            "environment.credentialReference",
                            "is not bound to this profile environment slot",
                        ));
                    }
                }
                ResolvedEnvironmentValue::Secret(store.get(&reference)?)
            }
        };
        entries.push(ResolvedEnvironmentEntry {
            name: entry.name,
            value,
            source: entry.source,
        });
    }
    validate_resolved_environment_budget(merged.platform, &entries)?;
    Ok(ResolvedEnvironment {
        platform: merged.platform,
        entries,
    })
}

pub fn build_execution_preview(
    context: &ExecutionPreviewContext,
    request: &ExecutionPreviewRequest,
) -> Result<FinalExecutionPreview, AppError> {
    validate_launch_profile_input(&request.profile)?;
    let request_wire = serde_json::to_vec(request).map_err(preview_serialization_error)?;
    if request_wire.len() > MAX_LAUNCH_PROFILE_INPUT_WIRE_BYTES {
        return Err(invalid_launch_input(
            "request",
            "encoded execution preview request exceeds the supported wire size",
        ));
    }

    let merged = merge_environment(context, &request.profile.environment)?;
    let path = resolve_path(&merged);
    let path_extensions = resolve_path_extensions(&merged)?;
    let (invocation, executable, direct) = build_invocation(
        context,
        &request.profile.execution,
        request.profile.interactive,
    );
    let executable_resolution = if let Some(executable) = executable.as_deref() {
        resolve_executable(
            context.platform,
            executable,
            &request.profile.working_directory,
            &path,
            &path_extensions,
            direct,
        )?
    } else {
        ExecutableResolution::NotSupported(NotSupportedExecutableResolution {
            reason: ExecutableNotSupportedReason::ShellUnavailableOnPlatform,
        })
    };

    validate_platform_execution_budget(context.platform, &invocation, &merged)?;
    let preview = FinalExecutionPreview {
        platform: context.platform,
        working_directory: request.profile.working_directory.clone(),
        interactive: request.profile.interactive,
        requires_credential_resolution: merged
            .entries
            .iter()
            .any(|entry| matches!(entry.value, LaunchEnvironmentValue::CredentialReference(_))),
        invocation,
        environment: preview_environment(&merged),
        path,
        path_extensions,
        executable_resolution,
    };
    let output_wire = serde_json::to_vec(&preview).map_err(preview_serialization_error)?;
    if output_wire.len() > MAX_EXECUTION_PREVIEW_WIRE_BYTES {
        return Err(invalid_launch_input(
            "preview",
            "encoded execution preview exceeds the supported wire size",
        ));
    }
    Ok(preview)
}

fn merge_layer(
    merged: &mut Vec<MergedEnvironmentEntry>,
    indices: &mut HashMap<String, usize>,
    layer: &[LaunchEnvironmentEntry],
    source: EnvironmentLayer,
    windows: bool,
) -> Result<(), AppError> {
    for entry in layer {
        let key = environment_key(&entry.name, windows);
        let replacement = MergedEnvironmentEntry {
            name: entry.name.clone(),
            value: entry.value.clone(),
            source,
        };
        if let Some(index) = indices.get(&key).copied() {
            merged[index] = replacement;
        } else {
            if merged.len() >= MAX_LAUNCH_ENVIRONMENT_ENTRIES {
                return Err(invalid_launch_input(
                    "environment",
                    "merged environment exceeds the supported entry count",
                ));
            }
            indices.insert(key, merged.len());
            merged.push(replacement);
        }
    }
    Ok(())
}

fn preview_environment(merged: &MergedEnvironment) -> Vec<EnvironmentPreviewEntry> {
    merged
        .entries
        .iter()
        .map(|entry| EnvironmentPreviewEntry {
            name: entry.name.clone(),
            value: match &entry.value {
                LaunchEnvironmentValue::CredentialReference(_) => {
                    EnvironmentPreviewValue::CredentialReferenceRedacted
                }
                LaunchEnvironmentValue::Plain(_)
                    if entry.source == EnvironmentLayer::SupervisorBase =>
                {
                    EnvironmentPreviewValue::InheritedRedacted
                }
                LaunchEnvironmentValue::Plain(value) => {
                    EnvironmentPreviewValue::Plain(value.value.clone())
                }
            },
            source: entry.source,
        })
        .collect()
}

fn resolve_path(merged: &MergedEnvironment) -> PathResolution {
    match environment_variable(merged, "PATH") {
        Some(entry) => match &entry.value {
            LaunchEnvironmentValue::Plain(value) => {
                if valid_search_path(merged.platform, &value.value) {
                    PathResolution::Known(KnownPathResolution {
                        value: value.value.clone(),
                        source: entry.source,
                    })
                } else {
                    PathResolution::Unknown(UnknownPathResolution {
                        reason: PathUnknownReason::InvalidValue,
                        source: Some(entry.source),
                    })
                }
            }
            LaunchEnvironmentValue::CredentialReference(_) => {
                PathResolution::Unknown(UnknownPathResolution {
                    reason: PathUnknownReason::CredentialReference,
                    source: Some(entry.source),
                })
            }
        },
        None => PathResolution::Unknown(UnknownPathResolution {
            reason: PathUnknownReason::Missing,
            source: None,
        }),
    }
}

fn resolve_path_extensions(
    merged: &MergedEnvironment,
) -> Result<PathExtensionResolution, AppError> {
    if merged.platform == ExecutionPlatform::MacOs {
        return Ok(PathExtensionResolution::NotApplicable);
    }
    let Some(entry) = environment_variable(merged, "PATHEXT") else {
        return Ok(PathExtensionResolution::Unknown(
            UnknownPathExtensionResolution {
                reason: PathUnknownReason::Missing,
                source: None,
            },
        ));
    };
    let LaunchEnvironmentValue::Plain(value) = &entry.value else {
        return Ok(PathExtensionResolution::Unknown(
            UnknownPathExtensionResolution {
                reason: PathUnknownReason::CredentialReference,
                source: Some(entry.source),
            },
        ));
    };

    let mut extensions = Vec::new();
    for raw_extension in value.value.split(';') {
        let extension =
            raw_extension.trim_matches(|character: char| character.is_ascii_whitespace());
        if extension.is_empty() {
            continue;
        }
        if extensions.len() >= MAX_PATH_EXTENSIONS {
            return Err(invalid_launch_input(
                "PATHEXT",
                "exceeds the supported extension count",
            ));
        }
        let extension = extension.to_ascii_uppercase();
        if extension.len() > MAX_PATH_EXTENSION_BYTES
            || !extension.starts_with('.')
            || extension.len() == 1
            || !extension[1..]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric())
        {
            return Ok(PathExtensionResolution::Unknown(
                UnknownPathExtensionResolution {
                    reason: PathUnknownReason::InvalidValue,
                    source: Some(entry.source),
                },
            ));
        }
        if !extensions.contains(&extension) {
            extensions.push(extension);
        }
    }
    Ok(PathExtensionResolution::Known(
        KnownPathExtensionResolution {
            value: value.value.clone(),
            extensions,
            source: entry.source,
        },
    ))
}

fn build_invocation(
    context: &ExecutionPreviewContext,
    execution: &LaunchExecution,
    interactive: bool,
) -> (ExecutionInvocationPreview, Option<String>, bool) {
    match execution {
        LaunchExecution::Direct(configuration) => (
            ExecutionInvocationPreview::Direct(DirectExecutionPreview {
                executable: configuration.executable.clone(),
                argv: configuration.argv.clone(),
            }),
            Some(configuration.executable.clone()),
            true,
        ),
        LaunchExecution::Shell(configuration) => {
            let (executable, argv) = match (context.platform, configuration.shell) {
                (ExecutionPlatform::Windows, ShellKind::PowerShell) => {
                    let mut argv = vec!["-NoLogo".into(), "-NoProfile".into()];
                    if !interactive {
                        argv.push("-NonInteractive".into());
                    }
                    argv.push("-Command".into());
                    argv.push(configuration.command.clone());
                    (
                        windows_system_shell_path(
                            context,
                            "System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        ),
                        argv,
                    )
                }
                (ExecutionPlatform::Windows, ShellKind::Cmd) => (
                    windows_system_shell_path(context, "System32\\cmd.exe"),
                    vec![
                        "/D".into(),
                        "/S".into(),
                        "/C".into(),
                        configuration.command.clone(),
                    ],
                ),
                (ExecutionPlatform::MacOs, ShellKind::Zsh) => (
                    Some("/bin/zsh".to_owned()),
                    vec!["-f".into(), "-c".into(), configuration.command.clone()],
                ),
                (ExecutionPlatform::MacOs, ShellKind::PowerShell) => {
                    let mut argv = vec!["-NoLogo".into(), "-NoProfile".into()];
                    if !interactive {
                        argv.push("-NonInteractive".into());
                    }
                    argv.push("-Command".into());
                    argv.push(configuration.command.clone());
                    (Some("pwsh".to_owned()), argv)
                }
                (ExecutionPlatform::Windows, ShellKind::Zsh) => (None, Vec::new()),
                (ExecutionPlatform::MacOs, ShellKind::Cmd) => (None, Vec::new()),
            };
            (
                ExecutionInvocationPreview::Shell(ShellExecutionPreview {
                    shell: configuration.shell,
                    executable: executable.clone(),
                    argv,
                    command: configuration.command.clone(),
                }),
                executable,
                false,
            )
        }
    }
}

fn resolve_executable(
    platform: ExecutionPlatform,
    executable: &str,
    working_directory: &str,
    path: &PathResolution,
    path_extensions: &PathExtensionResolution,
    direct: bool,
) -> Result<ExecutableResolution, AppError> {
    if direct
        && (!valid_direct_executable(platform, executable)
            || (platform == ExecutionPlatform::Windows && unsafe_windows_direct_script(executable)))
    {
        return Ok(ExecutableResolution::NotSupported(
            NotSupportedExecutableResolution {
                reason: ExecutableNotSupportedReason::InvalidExecutablePath,
            },
        ));
    }

    let has_separator = match platform {
        ExecutionPlatform::Windows => executable.contains(['\\', '/']),
        ExecutionPlatform::MacOs => executable.contains('/'),
    };
    if is_absolute(platform, executable) {
        return unknown_with_candidates(vec![ExecutableCandidate {
            path: executable.to_owned(),
            source: ExecutableCandidateSource::Explicit,
        }]);
    }
    if has_separator && direct {
        return Ok(ExecutableResolution::NotSupported(
            NotSupportedExecutableResolution {
                reason: ExecutableNotSupportedReason::InvalidExecutablePath,
            },
        ));
    }
    if has_separator {
        return unknown_with_candidates(vec![ExecutableCandidate {
            path: join_path(platform, working_directory, executable)?,
            source: ExecutableCandidateSource::WorkingDirectory,
        }]);
    }

    let PathResolution::Known(path) = path else {
        let PathResolution::Unknown(path) = path else {
            unreachable!()
        };
        let reason = match path.reason {
            PathUnknownReason::CredentialReference => {
                ExecutableUnknownReason::PathCredentialReference
            }
            PathUnknownReason::Missing => ExecutableUnknownReason::PathMissing,
            PathUnknownReason::InvalidValue => ExecutableUnknownReason::PathInvalidValue,
        };
        return Ok(ExecutableResolution::Unknown(UnknownExecutableResolution {
            reason,
            candidates: Vec::new(),
        }));
    };
    let Some(path_entries) = parse_search_path_entries(platform, &path.value) else {
        return Ok(ExecutableResolution::Unknown(UnknownExecutableResolution {
            reason: ExecutableUnknownReason::PathInvalidValue,
            candidates: Vec::new(),
        }));
    };
    if path_entries.len() > MAX_PATH_ENTRIES {
        return Err(invalid_launch_input(
            "PATH",
            "exceeds the supported entry count",
        ));
    }

    let safe_extensions =
        safe_direct_path_extensions(platform, direct, executable, path_extensions);
    let mut candidates = Vec::new();
    let mut keys = HashMap::<String, ()>::new();
    let mut candidate_bytes = 0_usize;
    for (index, entry) in path_entries.iter().enumerate() {
        let (directory, entry_kind) = if entry.is_empty() {
            (
                working_directory.to_owned(),
                PathEntryKind::WorkingDirectoryEmpty,
            )
        } else if is_absolute(platform, entry) {
            (entry.clone(), PathEntryKind::Absolute)
        } else {
            (
                join_path(platform, working_directory, entry)?,
                PathEntryKind::WorkingDirectoryRelative,
            )
        };
        let source = ExecutableCandidateSource::Path(PathExecutableCandidateSource {
            path_source: path.source,
            path_index: u16::try_from(index)
                .map_err(|_| invalid_launch_input("PATH", "contains an unsupported entry index"))?,
            entry_kind,
        });
        push_candidate(
            platform,
            &mut candidates,
            &mut keys,
            &mut candidate_bytes,
            join_path(platform, &directory, executable)?,
            source.clone(),
        )?;
        for extension in &safe_extensions {
            let executable_with_extension = format!("{executable}{extension}");
            push_candidate(
                platform,
                &mut candidates,
                &mut keys,
                &mut candidate_bytes,
                join_path(platform, &directory, &executable_with_extension)?,
                source.clone(),
            )?;
        }
    }

    let reason = if platform == ExecutionPlatform::Windows
        && direct
        && executable_extension(executable).is_none()
    {
        match path_extensions {
            PathExtensionResolution::Unknown(unknown) => match unknown.reason {
                PathUnknownReason::CredentialReference => {
                    ExecutableUnknownReason::PathExtensionCredentialReference
                }
                PathUnknownReason::Missing | PathUnknownReason::InvalidValue => {
                    ExecutableUnknownReason::PathExtensionMissing
                }
            },
            PathExtensionResolution::Known(_) | PathExtensionResolution::NotApplicable => {
                ExecutableUnknownReason::FilesystemNotInspected
            }
        }
    } else {
        ExecutableUnknownReason::FilesystemNotInspected
    };
    Ok(ExecutableResolution::Unknown(UnknownExecutableResolution {
        reason,
        candidates,
    }))
}

fn safe_direct_path_extensions(
    platform: ExecutionPlatform,
    direct: bool,
    executable: &str,
    path_extensions: &PathExtensionResolution,
) -> Vec<String> {
    if platform != ExecutionPlatform::Windows
        || !direct
        || executable_extension(executable).is_some()
    {
        return Vec::new();
    }
    match path_extensions {
        PathExtensionResolution::Known(known) => known
            .extensions
            .iter()
            .filter(|extension| matches!(extension.as_str(), ".EXE" | ".COM"))
            .cloned()
            .collect(),
        PathExtensionResolution::Unknown(_) | PathExtensionResolution::NotApplicable => Vec::new(),
    }
}

fn push_candidate(
    platform: ExecutionPlatform,
    candidates: &mut Vec<ExecutableCandidate>,
    keys: &mut HashMap<String, ()>,
    total_bytes: &mut usize,
    path: String,
    source: ExecutableCandidateSource,
) -> Result<(), AppError> {
    if path.len() > MAX_LAUNCH_WORKING_DIRECTORY_BYTES {
        return Err(invalid_launch_input(
            "executableCandidates",
            "contains a path that exceeds the supported length",
        ));
    }
    let key = environment_key(&path, platform == ExecutionPlatform::Windows);
    if keys.contains_key(&key) {
        return Ok(());
    }
    if candidates.len() >= MAX_EXECUTABLE_CANDIDATES {
        return Err(invalid_launch_input(
            "executableCandidates",
            "exceeds the supported candidate count",
        ));
    }
    *total_bytes = total_bytes.saturating_add(path.len());
    if *total_bytes > MAX_EXECUTABLE_CANDIDATE_TOTAL_BYTES {
        return Err(invalid_launch_input(
            "executableCandidates",
            "exceeds the supported total length",
        ));
    }
    keys.insert(key, ());
    candidates.push(ExecutableCandidate { path, source });
    Ok(())
}

fn unknown_with_candidates(
    candidates: Vec<ExecutableCandidate>,
) -> Result<ExecutableResolution, AppError> {
    let total_bytes = candidates.iter().fold(0_usize, |total, candidate| {
        total.saturating_add(candidate.path.len())
    });
    if candidates.len() > MAX_EXECUTABLE_CANDIDATES
        || total_bytes > MAX_EXECUTABLE_CANDIDATE_TOTAL_BYTES
        || candidates
            .iter()
            .any(|candidate| candidate.path.len() > MAX_LAUNCH_WORKING_DIRECTORY_BYTES)
    {
        return Err(invalid_launch_input(
            "executableCandidates",
            "exceeds the supported candidate budget",
        ));
    }
    Ok(ExecutableResolution::Unknown(UnknownExecutableResolution {
        reason: ExecutableUnknownReason::FilesystemNotInspected,
        candidates,
    }))
}

fn validate_platform_execution_budget(
    platform: ExecutionPlatform,
    invocation: &ExecutionInvocationPreview,
    environment: &MergedEnvironment,
) -> Result<(), AppError> {
    let (executable, argv) = invocation_parts(invocation);
    match platform {
        ExecutionPlatform::Windows => {
            let command_units = executable
                .into_iter()
                .chain(argv.iter().map(String::as_str))
                .fold(1_usize, |total, value| {
                    total
                        .saturating_add(value.encode_utf16().count().saturating_mul(2))
                        .saturating_add(3)
                });
            if command_units > MAX_WINDOWS_COMMAND_LINE_UTF16_UNITS {
                return Err(invalid_launch_input(
                    "invocation",
                    "exceeds the conservative Windows command-line UTF-16 budget",
                ));
            }
            let environment_units = environment.entries.iter().fold(1_usize, |total, entry| {
                let value_units = match &entry.value {
                    LaunchEnvironmentValue::Plain(value) => value.value.encode_utf16().count(),
                    LaunchEnvironmentValue::CredentialReference(_) => 0,
                };
                total
                    .saturating_add(entry.name.encode_utf16().count())
                    .saturating_add(value_units)
                    .saturating_add(2)
            });
            if environment_units > MAX_WINDOWS_ENVIRONMENT_UTF16_UNITS {
                return Err(invalid_launch_input(
                    "environment",
                    "exceeds the Windows environment UTF-16 budget before credential resolution",
                ));
            }
        }
        ExecutionPlatform::MacOs => {
            let argument_bytes = executable
                .into_iter()
                .chain(argv.iter().map(String::as_str))
                .fold(0_usize, |total, value| {
                    total.saturating_add(value.len()).saturating_add(1)
                });
            let environment_bytes = environment.entries.iter().fold(0_usize, |total, entry| {
                let value_bytes = match &entry.value {
                    LaunchEnvironmentValue::Plain(value) => value.value.len(),
                    LaunchEnvironmentValue::CredentialReference(_) => 0,
                };
                total
                    .saturating_add(entry.name.len())
                    .saturating_add(value_bytes)
                    .saturating_add(2)
            });
            if argument_bytes.saturating_add(environment_bytes) > MAX_MACOS_EXEC_ARGUMENT_ENV_BYTES
            {
                return Err(invalid_launch_input(
                    "invocation",
                    "exceeds the conservative macOS argument and environment byte budget",
                ));
            }
        }
    }
    Ok(())
}

fn validate_resolved_environment_budget(
    platform: ExecutionPlatform,
    entries: &[ResolvedEnvironmentEntry],
) -> Result<(), AppError> {
    match platform {
        ExecutionPlatform::Windows => {
            let units = entries.iter().fold(1_usize, |total, entry| {
                total
                    .saturating_add(entry.name.encode_utf16().count())
                    .saturating_add(entry.value.expose().encode_utf16().count())
                    .saturating_add(2)
            });
            if units > MAX_WINDOWS_ENVIRONMENT_UTF16_UNITS {
                return Err(invalid_launch_input(
                    "environment",
                    "exceeds the Windows environment UTF-16 budget after credential resolution",
                ));
            }
        }
        ExecutionPlatform::MacOs => {
            let bytes = entries.iter().fold(0_usize, |total, entry| {
                total
                    .saturating_add(entry.name.len())
                    .saturating_add(entry.value.expose().len())
                    .saturating_add(2)
            });
            if bytes > MAX_MACOS_EXEC_ARGUMENT_ENV_BYTES {
                return Err(invalid_launch_input(
                    "environment",
                    "exceeds the macOS environment byte budget after credential resolution",
                ));
            }
        }
    }
    Ok(())
}

fn invocation_parts(invocation: &ExecutionInvocationPreview) -> (Option<&str>, &[String]) {
    match invocation {
        ExecutionInvocationPreview::Direct(preview) => (Some(&preview.executable), &preview.argv),
        ExecutionInvocationPreview::Shell(preview) => {
            (preview.executable.as_deref(), &preview.argv)
        }
    }
}

fn environment_variable<'a>(
    merged: &'a MergedEnvironment,
    name: &str,
) -> Option<&'a MergedEnvironmentEntry> {
    let windows = merged.platform == ExecutionPlatform::Windows;
    let key = environment_key(name, windows);
    merged
        .entries
        .iter()
        .find(|entry| environment_key(&entry.name, windows) == key)
}

fn environment_key(value: &str, windows: bool) -> String {
    if windows {
        value.to_ascii_uppercase()
    } else {
        value.to_owned()
    }
}

fn valid_search_path(platform: ExecutionPlatform, value: &str) -> bool {
    parse_search_path_entries(platform, value).is_some()
}

fn parse_search_path_entries(platform: ExecutionPlatform, value: &str) -> Option<Vec<String>> {
    let separator = match platform {
        ExecutionPlatform::Windows => ';',
        ExecutionPlatform::MacOs => ':',
    };
    let mut entries = Vec::new();
    for raw_entry in value.split(separator) {
        let entry = if platform == ExecutionPlatform::Windows {
            normalize_quoted_windows_path_entry(raw_entry)?
        } else {
            raw_entry
        };
        if !valid_search_path_entry(platform, entry) {
            return None;
        }
        entries.push(entry.to_owned());
    }
    (entries.len() <= MAX_PATH_ENTRIES).then_some(entries)
}

fn normalize_quoted_windows_path_entry(value: &str) -> Option<&str> {
    if !value.contains('"') {
        return Some(value);
    }
    if value.len() <= 2 || !value.starts_with('"') || !value.ends_with('"') {
        return None;
    }
    let inner = &value[1..value.len() - 1];
    (!inner.is_empty() && !inner.contains('"')).then_some(inner)
}

fn valid_search_path_entry(platform: ExecutionPlatform, entry: &str) -> bool {
    if entry.is_empty() {
        return true;
    }
    match platform {
        ExecutionPlatform::MacOs => {
            let tail = entry.strip_prefix('/').unwrap_or(entry);
            tail.is_empty() || valid_normal_components(tail.split('/'))
        }
        ExecutionPlatform::Windows => {
            let entry = entry.replace('/', "\\");
            if invalid_windows_namespace(&entry) {
                return false;
            }
            let bytes = entry.as_bytes();
            if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
                return bytes.len() >= 3
                    && bytes[2] == b'\\'
                    && (bytes.len() == 3 || valid_windows_components(entry[3..].split('\\')));
            }
            if entry.starts_with("\\\\") {
                let mut components = entry[2..].split('\\');
                let server = components.next().unwrap_or_default();
                let share = components.next().unwrap_or_default();
                return !server.is_empty()
                    && !share.is_empty()
                    && !matches!(
                        server.to_ascii_uppercase().as_str(),
                        "." | "?" | "GLOBALROOT"
                    )
                    && valid_windows_component(server)
                    && valid_windows_component(share)
                    && valid_windows_components(components);
            }
            !entry.starts_with('\\')
                && !entry.contains(':')
                && valid_windows_components(entry.split('\\'))
        }
    }
}

fn valid_normal_components<'a>(components: impl IntoIterator<Item = &'a str>) -> bool {
    components
        .into_iter()
        .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
}

fn valid_windows_components<'a>(components: impl IntoIterator<Item = &'a str>) -> bool {
    components.into_iter().all(valid_windows_component)
}

fn valid_windows_component(component: &str) -> bool {
    !component.is_empty()
        && !matches!(component, "." | "..")
        && !component.ends_with(' ')
        && !component.ends_with('.')
        && !component
            .chars()
            .any(|character| character.is_control() || "<>:\"/\\|?*".contains(character))
}

fn join_path(platform: ExecutionPlatform, base: &str, child: &str) -> Result<String, AppError> {
    let separator = match platform {
        ExecutionPlatform::Windows => '\\',
        ExecutionPlatform::MacOs => '/',
    };
    let mut result = match platform {
        ExecutionPlatform::Windows => base.replace('/', "\\"),
        ExecutionPlatform::MacOs => base.to_owned(),
    };
    let child = match platform {
        ExecutionPlatform::Windows => child.replace('/', "\\"),
        ExecutionPlatform::MacOs => child.to_owned(),
    };
    if !result.ends_with(separator) {
        result.push(separator);
    }
    result.push_str(child.trim_start_matches(separator));
    if result.len() > MAX_LAUNCH_WORKING_DIRECTORY_BYTES || result.contains('\0') {
        return Err(invalid_launch_input(
            "executableCandidates",
            "contains an invalid or overlong path",
        ));
    }
    Ok(result)
}

fn is_absolute(platform: ExecutionPlatform, value: &str) -> bool {
    match platform {
        ExecutionPlatform::Windows => valid_absolute_windows_path(value),
        ExecutionPlatform::MacOs => {
            value == "/"
                || value
                    .strip_prefix('/')
                    .is_some_and(|tail| valid_normal_components(tail.split('/')))
        }
    }
}

fn valid_absolute_windows_path(value: &str) -> bool {
    let value = value.replace('/', "\\");
    if invalid_windows_namespace(&value) {
        return false;
    }
    let bytes = value.as_bytes();
    if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\' {
        return bytes.len() == 3 || valid_windows_components(value[3..].split('\\'));
    }
    if !value.starts_with("\\\\") {
        return false;
    }
    let mut components = value[2..].split('\\');
    let server = components.next().unwrap_or_default();
    let share = components.next().unwrap_or_default();
    valid_windows_component(server)
        && valid_windows_component(share)
        && !matches!(
            server.to_ascii_uppercase().as_str(),
            "." | "?" | "GLOBALROOT"
        )
        && valid_windows_components(components)
}

fn valid_direct_executable(platform: ExecutionPlatform, executable: &str) -> bool {
    match platform {
        ExecutionPlatform::Windows => {
            if valid_absolute_windows_path(executable) {
                return true;
            }
            !executable.contains(['\\', '/', ':']) && valid_windows_component(executable)
        }
        ExecutionPlatform::MacOs => {
            if executable.contains('/') {
                is_absolute(platform, executable)
            } else {
                !executable.is_empty()
                    && !executable.contains('\0')
                    && !executable.chars().any(char::is_control)
            }
        }
    }
}

fn windows_system_shell_path(
    context: &ExecutionPreviewContext,
    relative_executable: &str,
) -> Option<String> {
    if context.platform != ExecutionPlatform::Windows {
        return None;
    }
    let system_root = context
        .supervisor_base_environment
        .iter()
        .find(|entry| entry.name.eq_ignore_ascii_case("SystemRoot"))?;
    let LaunchEnvironmentValue::Plain(system_root) = &system_root.value else {
        return None;
    };
    if !valid_absolute_windows_path(&system_root.value) {
        return None;
    }
    let executable = join_path(
        ExecutionPlatform::Windows,
        &system_root.value,
        relative_executable,
    )
    .ok()?;
    valid_absolute_windows_path(&executable).then_some(executable)
}

fn invalid_windows_namespace(value: &str) -> bool {
    let value = value.replace('/', "\\");
    ["\\\\?\\", "\\\\.\\", "\\??\\", "\\Device\\"]
        .iter()
        .any(|prefix| {
            value
                .get(..prefix.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
        })
}

fn unsafe_windows_direct_script(executable: &str) -> bool {
    executable_extension(executable).is_some_and(|extension| {
        matches!(
            extension.as_str(),
            ".BAT" | ".CMD" | ".PS1" | ".VBS" | ".JS" | ".JSE" | ".WSF" | ".WSH" | ".MSC"
        )
    })
}

fn executable_extension(executable: &str) -> Option<String> {
    let name = executable.rsplit(['\\', '/']).next()?;
    let dot = name.rfind('.')?;
    (dot > 0).then(|| name[dot..].to_ascii_uppercase())
}

fn preview_serialization_error(error: serde_json::Error) -> AppError {
    let mut result = AppError::new(
        domain::ErrorCode::Internal,
        "failed to encode execution preview",
    );
    result.details.insert("reason".into(), error.to_string());
    result
}

#[cfg(windows)]
fn current_platform() -> Result<ExecutionPlatform, AppError> {
    Ok(ExecutionPlatform::Windows)
}

#[cfg(target_os = "macos")]
fn current_platform() -> Result<ExecutionPlatform, AppError> {
    Ok(ExecutionPlatform::MacOs)
}

#[cfg(not(any(windows, target_os = "macos")))]
fn current_platform() -> Result<ExecutionPlatform, AppError> {
    Err(AppError::new(
        domain::ErrorCode::NotSupported,
        "execution previews are not supported on this platform",
    ))
}
