use std::collections::HashMap;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use discovery::{
    BackendFuture, CancellationToken, DiscoveryBackend, EnrichmentDemand, FastProcessScan,
    MAX_PROJECT_ANCESTOR_DEPTH, MAX_PROJECT_FEATURES, MAX_PROJECT_PATH_BYTES, NormalizedPathKey,
    NormalizedPathRoot, NormalizedProjectRoot, PROJECT_MARKERS, PortScan, ProcessEnrichment,
    ProjectScanRequest, ProjectScanResult,
};
use domain::{
    AccessLevel, AppError, ClassificationCategory, ClassificationResult, ErrorCode, FieldValue,
    PortBinding, PortOwnershipConfidence, ProcessInstanceKey, ProcessOwnership, ProcessRecord,
    ProcessStatus, ProjectEvidence, ProjectFeatureEvidence,
};
use tokio::sync::Semaphore;

use crate::native::{
    NativePathObservation, NativeProcessSample, query_boot_identifier, query_enrichment,
    query_process_ports, query_process_snapshot, query_verified_working_directory,
};

const CANCELLATION_CHECK_INTERVAL: usize = 64;
const MAX_TARGETED_PORT_SCANS: usize = 4;

#[derive(Clone, Default)]
pub struct MacosDiscoveryBackend {
    state: Arc<BackendState>,
}

#[derive(Default)]
struct BackendState {
    boot_id: OnceLock<String>,
    cpu_baseline: Mutex<Option<CpuBaseline>>,
    targeted_port_scans: OnceLock<Arc<Semaphore>>,
}

impl BackendState {
    fn targeted_port_scan_semaphore(&self) -> Arc<Semaphore> {
        Arc::clone(
            self.targeted_port_scans
                .get_or_init(|| Arc::new(Semaphore::new(MAX_TARGETED_PORT_SCANS))),
        )
    }
}

struct CpuBaseline {
    monotonic_ns: u64,
    logical_cpus: u32,
    process_totals: HashMap<ProcessInstanceKey, u64>,
}

impl DiscoveryBackend for MacosDiscoveryBackend {
    fn scan_processes(
        &self,
        cancellation: CancellationToken,
    ) -> BackendFuture<'_, FastProcessScan> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || scan_processes_blocking(&state, &cancellation))
                .await
                .map_err(blocking_join_error)?
        })
    }

    fn scan_ports(&self, cancellation: CancellationToken) -> BackendFuture<'_, PortScan> {
        // P3-T05 owns libproc FD/socket discovery. The platform supports it,
        // but it has not been observed yet, so this must remain Unknown.
        Box::pin(async move {
            check_cancelled(&cancellation)?;
            Ok(PortScan {
                bindings: FieldValue::Unknown,
            })
        })
    }

    fn enrich_process(
        &self,
        instance_key: ProcessInstanceKey,
        demand: EnrichmentDemand,
        cancellation: CancellationToken,
    ) -> BackendFuture<'_, ProcessEnrichment> {
        let targeted_port_scans = (demand == EnrichmentDemand::MetadataAndPorts)
            .then(|| self.state.targeted_port_scan_semaphore());
        Box::pin(async move {
            let port_scan_permit = match targeted_port_scans {
                Some(semaphore) => Some(tokio::select! {
                    permit = semaphore.acquire_owned() => permit.map_err(|_| {
                        AppError::new(
                            ErrorCode::Internal,
                            "macOS targeted port scan limiter was closed",
                        )
                    })?,
                    _ = cancellation.cancelled() => return Err(cancellation_error()),
                }),
                None => None,
            };
            tokio::task::spawn_blocking(move || {
                let _port_scan_permit = port_scan_permit;
                enrich_process_blocking(instance_key, demand, &cancellation)
            })
            .await
            .map_err(blocking_join_error)?
        })
    }

    fn scan_project_evidence(
        &self,
        request: ProjectScanRequest,
    ) -> BackendFuture<'_, ProjectScanResult> {
        Box::pin(async move {
            tokio::task::spawn_blocking(move || scan_project_evidence_blocking(request))
                .await
                .map_err(blocking_join_error)?
        })
    }

    fn normalize_project_root(
        &self,
        root_directory: String,
        cancellation: CancellationToken,
    ) -> BackendFuture<'_, NormalizedProjectRoot> {
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                normalize_project_root_blocking(root_directory, &cancellation)
            })
            .await
            .map_err(blocking_join_error)?
        })
    }
}

fn scan_processes_blocking(
    state: &BackendState,
    cancellation: &CancellationToken,
) -> Result<FastProcessScan, AppError> {
    check_cancelled(cancellation)?;
    let boot_id = get_boot_id(state, cancellation)?;
    let snapshot = query_process_snapshot(cancellation)?;
    let cpu_values = calculate_cpu_values(
        state,
        snapshot.monotonic_ns,
        snapshot.logical_cpus,
        &snapshot.processes,
        &boot_id,
        cancellation,
    )?;

    let mut live_keys = HashMap::with_capacity(snapshot.processes.len());
    for (index, sample) in snapshot.processes.iter().enumerate() {
        if index % CANCELLATION_CHECK_INTERVAL == 0 {
            check_cancelled(cancellation)?;
        }
        live_keys.insert(
            sample.pid,
            (
                sample.start_micros,
                process_key(&boot_id, sample.pid, sample.start_micros),
            ),
        );
    }

    let mut processes = Vec::with_capacity(snapshot.processes.len());
    for (index, sample) in snapshot.processes.into_iter().enumerate() {
        if index % CANCELLATION_CHECK_INTERVAL == 0 {
            check_cancelled(cancellation)?;
        }
        let key = process_key(&boot_id, sample.pid, sample.start_micros);
        let parent = sample.parent_pid.and_then(|parent_pid| {
            live_keys
                .get(&parent_pid)
                .filter(|(parent_start, _)| *parent_start <= sample.start_micros)
                .map(|(_, key)| key.clone())
        });
        let access_reason = sample
            .access_limited
            .then(|| "proc_pidinfo(PROC_PIDTASKINFO):accessLimited".to_owned());
        processes.push(ProcessRecord {
            instance_key: key.clone(),
            parent_instance_key: FieldValue::Known(parent),
            owner_user: FieldValue::Known(format!("uid:{}", sample.uid)),
            executable_name: sample.name,
            executable_path: FieldValue::Unknown,
            command_line: FieldValue::Unknown,
            working_directory: FieldValue::Unknown,
            cpu_percent: cpu_values
                .get(&key)
                .cloned()
                .unwrap_or_else(|| match &access_reason {
                    Some(reason) => FieldValue::AccessLimited {
                        reason: Some(reason.clone()),
                    },
                    None => FieldValue::Unknown,
                }),
            memory_bytes: sample.resident_bytes,
            started_at: unix_micros_timestamp(sample.start_micros)
                .map(FieldValue::Known)
                .unwrap_or(FieldValue::Unknown),
            status: if sample.status == ProcessStatus::Unknown {
                FieldValue::Unknown
            } else {
                FieldValue::Known(sample.status)
            },
            access_level: if sample.access_limited {
                AccessLevel::Limited
            } else {
                AccessLevel::Full
            },
            // Supervisor ownership is overlaid after discovery; visibility
            // through libproc never establishes lifecycle control.
            ownership: ProcessOwnership::External,
            managed_run_id: None,
            project_association: ProjectEvidence::Unknown,
            project_features: ProjectEvidence::Unknown,
            project_id: None,
            classification: unknown_classification(),
            port_bindings: FieldValue::Unknown,
            last_seen_revision: 0,
        });
    }
    Ok(FastProcessScan { processes })
}

fn enrich_process_blocking(
    instance_key: ProcessInstanceKey,
    demand: EnrichmentDemand,
    cancellation: &CancellationToken,
) -> Result<ProcessEnrichment, AppError> {
    check_cancelled(cancellation)?;
    let Some(enrichment) = query_enrichment(&instance_key, cancellation)? else {
        let mut error = AppError::new(
            ErrorCode::NotFound,
            "macOS process disappeared or its identity changed",
        );
        error
            .details
            .insert("pid".into(), instance_key.pid.to_string());
        return Err(error);
    };
    let port_bindings = if demand == EnrichmentDemand::MetadataAndPorts {
        let Some(bindings) = query_process_ports(&instance_key, cancellation)? else {
            let mut error = AppError::new(
                ErrorCode::NotFound,
                "macOS process disappeared or its identity changed during port discovery",
            );
            error
                .details
                .insert("pid".into(), instance_key.pid.to_string());
            return Err(error);
        };
        Some(match bindings {
            FieldValue::Known(samples) => {
                let observed_at = current_timestamp()?;
                let mut bindings = Vec::with_capacity(samples.len());
                for (index, sample) in samples.into_iter().enumerate() {
                    if index % CANCELLATION_CHECK_INTERVAL == 0 {
                        check_cancelled(cancellation)?;
                    }
                    bindings.push(PortBinding {
                        protocol: sample.protocol,
                        address_family: sample.address_family,
                        local_address: sample.local_address,
                        local_port: sample.local_port,
                        state: sample.state.map_or(FieldValue::Unknown, FieldValue::Known),
                        process_instance_key: Some(instance_key.clone()),
                        confidence: PortOwnershipConfidence::Exact,
                        observed_at: observed_at.clone(),
                    });
                }
                FieldValue::Known(bindings)
            }
            FieldValue::Unknown => FieldValue::Unknown,
            FieldValue::AccessLimited { reason } => FieldValue::AccessLimited { reason },
            FieldValue::NotSupported => FieldValue::NotSupported,
        })
    } else {
        None
    };
    let access_limited = enrichment.access_limited
        || !matches!(&enrichment.executable_path, FieldValue::Known(_))
        || !matches!(&enrichment.command_line, FieldValue::Known(_))
        || !matches!(&enrichment.working_directory, FieldValue::Known(_))
        || matches!(&port_bindings, Some(FieldValue::AccessLimited { .. }));
    Ok(ProcessEnrichment {
        instance_key,
        executable_path: enrichment.executable_path,
        command_line: enrichment.command_line,
        working_directory: enrichment.working_directory,
        port_bindings,
        access_level: Some(if access_limited {
            AccessLevel::Limited
        } else {
            AccessLevel::Full
        }),
    })
}

struct CanonicalProjectPath {
    path: PathBuf,
    normalized: NormalizedPathKey,
    directory_identity: DirectoryIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

fn normalize_project_root_blocking(
    root_directory: String,
    cancellation: &CancellationToken,
) -> Result<NormalizedProjectRoot, AppError> {
    if root_directory.is_empty()
        || root_directory.len() > MAX_PROJECT_PATH_BYTES
        || root_directory.contains('\0')
        || !Path::new(&root_directory).is_absolute()
    {
        let mut error = AppError::new(
            ErrorCode::InvalidArgument,
            "macOS project root must be a bounded absolute path",
        );
        error.details.insert("field".into(), "rootDirectory".into());
        return Err(error);
    }

    match canonicalize_project_path(&root_directory, cancellation, "canonicalize(project root)")? {
        ProjectEvidence::Known(path) => {
            let canonical_root_directory = bounded_utf8_path(&path.path).ok_or_else(|| {
                project_root_availability_error(
                    ErrorCode::NotSupported,
                    "macOS canonical project root is not losslessly representable",
                )
            })?;
            NormalizedProjectRoot::from_platform_observation(
                canonical_root_directory,
                path.normalized,
            )
        }
        ProjectEvidence::Missing => Err(project_root_availability_error(
            ErrorCode::NotFound,
            "macOS project root does not exist",
        )),
        ProjectEvidence::AccessLimited { reason } => {
            let mut error = project_root_availability_error(
                ErrorCode::AccessDenied,
                "macOS project root cannot be accessed",
            );
            if let Some(reason) = reason {
                error.details.insert("reason".into(), reason);
            }
            Err(error)
        }
        ProjectEvidence::NotSupported => Err(project_root_availability_error(
            ErrorCode::NotSupported,
            "macOS project root is not losslessly representable",
        )),
        ProjectEvidence::Unknown => Err(project_root_availability_error(
            ErrorCode::PlatformError,
            "macOS project root normalization is inconclusive",
        )),
    }
}

fn scan_project_evidence_blocking(
    request: ProjectScanRequest,
) -> Result<ProjectScanResult, AppError> {
    let cancellation = &request.cancellation;
    check_cancelled(cancellation)?;
    let first_path = match query_verified_working_directory(&request.instance_key, cancellation)? {
        NativePathObservation::Known(path) => path,
        NativePathObservation::Missing => {
            return ProjectScanResult::from_platform_observation(
                &request,
                ProjectEvidence::Missing,
                ProjectEvidence::Missing,
            );
        }
        NativePathObservation::AccessLimited(reason) => {
            return ProjectScanResult::from_platform_observation(
                &request,
                ProjectEvidence::AccessLimited {
                    reason: Some(reason.clone()),
                },
                ProjectEvidence::AccessLimited {
                    reason: Some(reason),
                },
            );
        }
        NativePathObservation::NotSupported => {
            return ProjectScanResult::from_platform_observation(
                &request,
                ProjectEvidence::NotSupported,
                ProjectEvidence::NotSupported,
            );
        }
    };
    if first_path != request.expected_working_directory {
        return Err(stale_project_scan_error(
            &request.instance_key,
            "working directory no longer matches the scheduled value",
        ));
    }

    let first_canonical = match canonicalize_project_path(
        &first_path,
        cancellation,
        "canonicalize(project working directory)",
    )? {
        ProjectEvidence::Known(path) => path,
        ProjectEvidence::Missing => {
            return ProjectScanResult::from_platform_observation(
                &request,
                ProjectEvidence::Missing,
                ProjectEvidence::Missing,
            );
        }
        ProjectEvidence::Unknown => {
            return ProjectScanResult::from_platform_observation(
                &request,
                ProjectEvidence::Unknown,
                ProjectEvidence::Unknown,
            );
        }
        ProjectEvidence::AccessLimited { reason } => {
            return ProjectScanResult::from_platform_observation(
                &request,
                ProjectEvidence::AccessLimited {
                    reason: reason.clone(),
                },
                ProjectEvidence::AccessLimited { reason },
            );
        }
        ProjectEvidence::NotSupported => {
            return ProjectScanResult::from_platform_observation(
                &request,
                ProjectEvidence::NotSupported,
                ProjectEvidence::NotSupported,
            );
        }
    };

    let features = scan_project_markers(&request, &first_canonical, cancellation)?;

    check_cancelled(cancellation)?;
    let second_path = match query_verified_working_directory(&request.instance_key, cancellation)? {
        NativePathObservation::Known(path) => path,
        NativePathObservation::Missing
        | NativePathObservation::AccessLimited(_)
        | NativePathObservation::NotSupported => {
            return Err(stale_project_scan_error(
                &request.instance_key,
                "working directory became unavailable during project discovery",
            ));
        }
    };
    if second_path != first_path || second_path != request.expected_working_directory {
        return Err(stale_project_scan_error(
            &request.instance_key,
            "working directory changed during project discovery",
        ));
    }
    let second_canonical = match canonicalize_project_path(
        &second_path,
        cancellation,
        "canonicalize(project working directory)",
    )? {
        ProjectEvidence::Known(path) => path,
        ProjectEvidence::Missing
        | ProjectEvidence::Unknown
        | ProjectEvidence::AccessLimited { .. }
        | ProjectEvidence::NotSupported => {
            return Err(stale_project_scan_error(
                &request.instance_key,
                "canonical working directory changed availability during project discovery",
            ));
        }
    };
    if second_canonical.path != first_canonical.path
        || second_canonical.normalized != first_canonical.normalized
        || second_canonical.directory_identity != first_canonical.directory_identity
    {
        return Err(stale_project_scan_error(
            &request.instance_key,
            "canonical working directory changed during project discovery",
        ));
    }

    ProjectScanResult::from_platform_observation(
        &request,
        ProjectEvidence::Known(first_canonical.normalized),
        features,
    )
}

fn canonicalize_project_path(
    path: &str,
    cancellation: &CancellationToken,
    operation: &'static str,
) -> Result<ProjectEvidence<CanonicalProjectPath>, AppError> {
    check_cancelled(cancellation)?;
    let canonical = match fs::canonicalize(Path::new(path)) {
        Ok(path) => path,
        Err(error) => {
            return match error.raw_os_error() {
                Some(libc::ENOENT) => Ok(ProjectEvidence::Missing),
                Some(libc::EACCES | libc::EPERM) => Ok(ProjectEvidence::AccessLimited {
                    reason: Some(format!("{operation}:accessLimited")),
                }),
                _ => Err(project_path_error(operation, &error)),
            };
        }
    };
    check_cancelled(cancellation)?;
    let nofollow_metadata = match project_directory_metadata(
        &canonical,
        false,
        "symlink_metadata(canonical project directory)",
    )? {
        ProjectEvidence::Known(metadata) => metadata,
        ProjectEvidence::Missing => return Ok(ProjectEvidence::Missing),
        ProjectEvidence::AccessLimited { reason } => {
            return Ok(ProjectEvidence::AccessLimited { reason });
        }
        ProjectEvidence::NotSupported | ProjectEvidence::Unknown => {
            return Ok(ProjectEvidence::NotSupported);
        }
    };
    if nofollow_metadata.file_type().is_symlink() || !nofollow_metadata.file_type().is_dir() {
        return Ok(ProjectEvidence::NotSupported);
    }
    check_cancelled(cancellation)?;
    let followed_metadata = match project_directory_metadata(
        &canonical,
        true,
        "metadata(canonical project directory)",
    )? {
        ProjectEvidence::Known(metadata) => metadata,
        ProjectEvidence::Missing => return Ok(ProjectEvidence::Missing),
        ProjectEvidence::AccessLimited { reason } => {
            return Ok(ProjectEvidence::AccessLimited { reason });
        }
        ProjectEvidence::NotSupported | ProjectEvidence::Unknown => {
            return Ok(ProjectEvidence::NotSupported);
        }
    };
    if !followed_metadata.file_type().is_dir() {
        return Ok(ProjectEvidence::NotSupported);
    }
    let nofollow_identity = DirectoryIdentity {
        device: nofollow_metadata.dev(),
        inode: nofollow_metadata.ino(),
    };
    let followed_identity = DirectoryIdentity {
        device: followed_metadata.dev(),
        inode: followed_metadata.ino(),
    };
    if nofollow_identity != followed_identity {
        return Err(changed_canonical_project_directory_error());
    }
    check_cancelled(cancellation)?;
    let Some(canonical_text) = canonical.to_str() else {
        return Ok(ProjectEvidence::NotSupported);
    };
    if canonical_text.is_empty() || canonical_text.len() > MAX_PROJECT_PATH_BYTES {
        return Ok(ProjectEvidence::NotSupported);
    }

    let mut saw_root = false;
    let mut components = Vec::new();
    for component in canonical.components() {
        check_cancelled(cancellation)?;
        match component {
            Component::RootDir if !saw_root => saw_root = true,
            Component::Normal(component) => {
                let Some(component) = component.to_str() else {
                    return Ok(ProjectEvidence::NotSupported);
                };
                components.push(component.to_owned());
                if components.len() > MAX_PROJECT_ANCESTOR_DEPTH {
                    return Ok(ProjectEvidence::NotSupported);
                }
            }
            Component::RootDir
            | Component::CurDir
            | Component::ParentDir
            | Component::Prefix(_) => {
                return Err(invalid_canonical_project_path(
                    "canonical path contains a non-normal component",
                ));
            }
        }
    }
    if !saw_root {
        return Err(invalid_canonical_project_path(
            "canonical path is not absolute",
        ));
    }
    let normalized =
        NormalizedPathKey::from_canonical_components(NormalizedPathRoot::Posix, components)
            .map_err(|error| normalized_project_path_error(&error))?;
    Ok(ProjectEvidence::Known(CanonicalProjectPath {
        path: canonical,
        normalized,
        directory_identity: followed_identity,
    }))
}

fn project_directory_metadata(
    path: &Path,
    follow: bool,
    operation: &'static str,
) -> Result<ProjectEvidence<fs::Metadata>, AppError> {
    let result = if follow {
        fs::metadata(path)
    } else {
        fs::symlink_metadata(path)
    };
    match result {
        Ok(metadata) => Ok(ProjectEvidence::Known(metadata)),
        Err(error) => match error.raw_os_error() {
            Some(libc::ENOENT) => Ok(ProjectEvidence::Missing),
            Some(libc::EACCES | libc::EPERM) => Ok(ProjectEvidence::AccessLimited {
                reason: Some(format!("{operation}:accessLimited")),
            }),
            _ => Err(project_path_error(operation, &error)),
        },
    }
}

fn scan_project_markers(
    request: &ProjectScanRequest,
    working_directory: &CanonicalProjectPath,
    cancellation: &CancellationToken,
) -> Result<ProjectEvidence<Vec<ProjectFeatureEvidence>>, AppError> {
    let boundary = request
        .catalog
        .nearest_project(&working_directory.normalized)
        .map(|project| project.normalized_path.clone());
    let mut current_path = working_directory.path.clone();
    let mut current_key = working_directory.normalized.clone();
    let mut features = Vec::new();

    for parent_steps in 0..=MAX_PROJECT_ANCESTOR_DEPTH {
        check_cancelled(cancellation)?;
        let Some(detected_root) = bounded_utf8_path(&current_path) else {
            return Ok(ProjectEvidence::NotSupported);
        };

        for marker in PROJECT_MARKERS {
            check_cancelled(cancellation)?;
            let marker_path = current_path.join(marker.file_name);
            let Some(marker_path_text) = bounded_utf8_path(&marker_path) else {
                return Ok(ProjectEvidence::NotSupported);
            };
            let metadata = match fs::symlink_metadata(&marker_path) {
                Ok(metadata) => metadata,
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => continue,
                Err(error) if matches!(error.raw_os_error(), Some(libc::EACCES | libc::EPERM)) => {
                    return Ok(ProjectEvidence::AccessLimited {
                        reason: Some("symlink_metadata(project marker):accessLimited".into()),
                    });
                }
                Err(error) => {
                    return Err(project_path_error(
                        "symlink_metadata(project marker)",
                        &error,
                    ));
                }
            };
            if !metadata.file_type().is_file() {
                continue;
            }
            if features.len() >= MAX_PROJECT_FEATURES {
                return Ok(ProjectEvidence::NotSupported);
            }
            features.push(ProjectFeatureEvidence {
                marker_id: marker.id.into(),
                marker_path: marker_path_text,
                detected_root: detected_root.clone(),
            });
        }

        if !features.is_empty()
            || boundary.as_ref().is_some_and(|root| root == &current_key)
            || parent_steps == MAX_PROJECT_ANCESTOR_DEPTH
        {
            break;
        }
        let Some(parent_key) = current_key.parent() else {
            break;
        };
        if !current_path.pop() {
            return Err(invalid_canonical_project_path(
                "canonical path and normalized parent depth disagree",
            ));
        }
        current_key = parent_key;
    }

    Ok(ProjectEvidence::Known(features))
}

fn bounded_utf8_path(path: &Path) -> Option<String> {
    path.to_str()
        .filter(|path| !path.is_empty() && path.len() <= MAX_PROJECT_PATH_BYTES)
        .map(str::to_owned)
}

fn stale_project_scan_error(instance_key: &ProcessInstanceKey, reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::IdentityMismatch,
        "macOS project scan no longer matches the process instance",
    );
    error.retryable = true;
    error
        .details
        .insert("pid".into(), instance_key.pid.to_string());
    error.details.insert("reason".into(), reason.into());
    error
}

fn project_path_error(operation: &'static str, source: &io::Error) -> AppError {
    let mut error = AppError::new(ErrorCode::PlatformError, "macOS project path query failed");
    error.retryable = true;
    error.details.insert("operation".into(), operation.into());
    if let Some(errno) = source.raw_os_error() {
        error.details.insert("errno".into(), errno.to_string());
    }
    error
}

fn project_root_availability_error(code: ErrorCode, message: &'static str) -> AppError {
    let mut error = AppError::new(code, message);
    error.details.insert("field".into(), "rootDirectory".into());
    error
}

fn invalid_canonical_project_path(reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "macOS canonical project path is invalid",
    );
    error.details.insert("reason".into(), reason.into());
    error
}

fn changed_canonical_project_directory_error() -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "macOS canonical project directory changed during inspection",
    );
    error.retryable = true;
    error
}

fn normalized_project_path_error(source: &AppError) -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "macOS canonical project path could not be normalized",
    );
    error
        .details
        .insert("reason".into(), source.message.clone());
    error
}

fn get_boot_id(state: &BackendState, cancellation: &CancellationToken) -> Result<String, AppError> {
    if let Some(boot_id) = state.boot_id.get() {
        return Ok(boot_id.clone());
    }
    check_cancelled(cancellation)?;
    let queried = query_boot_identifier()?;
    let _ = state.boot_id.set(queried);
    state.boot_id.get().cloned().ok_or_else(|| {
        AppError::new(
            ErrorCode::Internal,
            "macOS boot identifier cache was not initialized",
        )
    })
}

fn calculate_cpu_values(
    state: &BackendState,
    monotonic_ns: Option<u64>,
    logical_cpus: Option<u32>,
    samples: &[NativeProcessSample],
    boot_id: &str,
    cancellation: &CancellationToken,
) -> Result<HashMap<ProcessInstanceKey, FieldValue<f32>>, AppError> {
    let mut values = HashMap::with_capacity(samples.len());
    let (Some(monotonic_ns), Some(logical_cpus)) = (monotonic_ns, logical_cpus) else {
        return Ok(values);
    };
    let mut process_totals = HashMap::with_capacity(samples.len());
    for (index, sample) in samples.iter().enumerate() {
        if index % CANCELLATION_CHECK_INTERVAL == 0 {
            check_cancelled(cancellation)?;
        }
        if let Some(total) = sample.cpu_total_ns {
            process_totals.insert(process_key(boot_id, sample.pid, sample.start_micros), total);
        }
    }

    let mut baseline = state
        .cpu_baseline
        .lock()
        .map_err(|_| AppError::new(ErrorCode::Internal, "macOS CPU sample cache is poisoned"))?;
    if let Some(previous) = baseline.as_ref()
        && previous.logical_cpus == logical_cpus
        && let Some(elapsed_ns) = monotonic_ns.checked_sub(previous.monotonic_ns)
        && let Some(capacity_ns) = elapsed_ns.checked_mul(u64::from(logical_cpus))
        && capacity_ns != 0
    {
        for (index, (key, current_total)) in process_totals.iter().enumerate() {
            if index % CANCELLATION_CHECK_INTERVAL == 0 {
                check_cancelled(cancellation)?;
            }
            let value = previous
                .process_totals
                .get(key)
                .and_then(|previous| current_total.checked_sub(*previous))
                .map(|process_delta| process_delta as f64 / capacity_ns as f64 * 100.0)
                .filter(|percent| percent.is_finite())
                .map(|percent| FieldValue::Known(percent.clamp(0.0, 100.0) as f32))
                .unwrap_or(FieldValue::Unknown);
            values.insert(key.clone(), value);
        }
    }
    *baseline = Some(CpuBaseline {
        monotonic_ns,
        logical_cpus,
        process_totals,
    });
    Ok(values)
}

fn process_key(boot_id: &str, pid: u32, start_micros: u64) -> ProcessInstanceKey {
    ProcessInstanceKey {
        boot_id: boot_id.to_owned(),
        pid,
        native_start_time: start_micros.to_string(),
    }
}

fn unknown_classification() -> ClassificationResult {
    ClassificationResult {
        score: 0,
        version: 0,
        category: ClassificationCategory::Unknown,
        reasons: Vec::new(),
        user_override: None,
        is_development: false,
    }
}

fn current_timestamp() -> Result<String, AppError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            let mut app_error = AppError::new(
                ErrorCode::PlatformError,
                "macOS system clock is before the Unix epoch",
            );
            app_error.details.insert("reason".into(), error.to_string());
            app_error
        })?;
    let seconds = duration.as_secs();
    let days = i64::try_from(seconds / 86_400).map_err(|_| {
        AppError::new(
            ErrorCode::PlatformError,
            "macOS system clock exceeds the supported timestamp range",
        )
    })?;
    let seconds_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days).ok_or_else(|| {
        AppError::new(
            ErrorCode::PlatformError,
            "macOS system clock exceeds the supported timestamp range",
        )
    })?;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:09}Z",
        seconds_of_day / 3_600,
        seconds_of_day % 3_600 / 60,
        seconds_of_day % 60,
        duration.subsec_nanos(),
    ))
}

fn unix_micros_timestamp(micros: u64) -> Option<String> {
    let seconds = micros / 1_000_000;
    let fraction = micros % 1_000_000;
    let days = i64::try_from(seconds / 86_400).ok()?;
    let seconds_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days)?;
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{fraction:06}Z",
        seconds_of_day / 3_600,
        seconds_of_day % 3_600 / 60,
        seconds_of_day % 60,
    ))
}

fn civil_from_days(days_since_unix_epoch: i64) -> Option<(i64, u64, u64)> {
    let shifted = days_since_unix_epoch.checked_add(719_468)?;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era.checked_add(era.checked_mul(400)?)?;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    Some((year, u64::try_from(month).ok()?, u64::try_from(day).ok()?))
}

fn check_cancelled(cancellation: &CancellationToken) -> Result<(), AppError> {
    if cancellation.is_cancelled() {
        Err(cancellation_error())
    } else {
        Ok(())
    }
}

fn cancellation_error() -> AppError {
    let mut error = AppError::new(
        ErrorCode::Timeout,
        "macOS discovery operation was cancelled",
    );
    error.retryable = true;
    error
}

fn blocking_join_error(error: tokio::task::JoinError) -> AppError {
    let mut app_error = AppError::new(ErrorCode::Internal, "macOS discovery worker failed");
    app_error.details.insert("reason".into(), error.to_string());
    app_error
}
