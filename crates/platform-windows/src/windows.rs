use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use discovery::{
    BackendFuture, CancellationToken, DiscoveryBackend, EnrichmentDemand, FastProcessScan,
    MAX_PROJECT_ANCESTOR_DEPTH, MAX_PROJECT_FEATURES, MAX_PROJECT_PATH_BYTES, NormalizedPathKey,
    NormalizedPathRoot, NormalizedProjectRoot, PROJECT_MARKERS, PortScan, ProcessEnrichment,
    ProjectScanRequest, ProjectScanResult,
};
use domain::{
    AccessLevel, AddressFamily, AppError, ClassificationCategory, ClassificationResult, ErrorCode,
    FieldValue, PortBinding, PortOwnershipConfidence, PortProtocol, PortState, ProcessInstanceKey,
    ProcessOwnership, ProcessRecord, ProjectEvidence, ProjectFeatureEvidence,
};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, GetLastError,
    HANDLE, LPARAM, WIN32_ERROR,
};
use windows::Win32::Globalization::{LCMAP_UPPERCASE, LCMapStringEx, LOCALE_NAME_INVARIANT};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CreateFileW, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_TYPE_DISK, GetFileInformationByHandle, GetFileType,
    GetFinalPathNameByHandleW, OPEN_EXISTING,
};
use windows::core::{Error as WindowsError, PCWSTR};

use crate::native::{
    NativePathObservation, NativeProcessSample, ProcessInspection, inspect_process,
    query_boot_identifier, query_enrichment, query_process_snapshot,
    query_verified_working_directory,
};
use crate::ports::{NativePortRow, query_port_rows};

#[derive(Clone, Default)]
pub struct WindowsDiscoveryBackend {
    state: Arc<BackendState>,
}

#[derive(Default)]
struct BackendState {
    boot_id: OnceLock<String>,
    cpu_baseline: Mutex<Option<CpuBaseline>>,
}

#[derive(Default)]
struct CpuBaseline {
    system_total: u64,
    process_totals: HashMap<ProcessInstanceKey, u64>,
}

const MAX_WINDOWS_PROJECT_PATH_UNITS: usize = 32 * 1024;
const MAX_WINDOWS_EXTENDED_PROJECT_PATH_UNITS: usize = MAX_WINDOWS_PROJECT_PATH_UNITS + 8;

impl DiscoveryBackend for WindowsDiscoveryBackend {
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
        Box::pin(async move {
            tokio::task::spawn_blocking(move || scan_ports_blocking(&cancellation))
                .await
                .map_err(blocking_join_error)?
        })
    }

    fn enrich_process(
        &self,
        instance_key: ProcessInstanceKey,
        _demand: EnrichmentDemand,
        cancellation: CancellationToken,
    ) -> BackendFuture<'_, ProcessEnrichment> {
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                enrich_process_blocking(instance_key, &cancellation)
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
    check_cancelled(cancellation)?;
    let snapshot = query_process_snapshot(cancellation)?;

    let cpu_values = calculate_cpu_values(
        state,
        snapshot.system_total,
        &snapshot.processes,
        &boot_id,
        cancellation,
    )?;
    let mut inspected = Vec::with_capacity(snapshot.processes.len());
    for (index, sample) in snapshot.processes.into_iter().enumerate() {
        if index % 64 == 0 {
            check_cancelled(cancellation)?;
        }
        match inspect_process(&sample, cancellation) {
            ProcessInspection::Verified {
                owner_user,
                executable_path,
                access_level,
            } => inspected.push((
                sample,
                InspectionFields {
                    owner_user,
                    executable_path,
                    access_level,
                },
            )),
            ProcessInspection::Denied { reason } => {
                let limited = FieldValue::AccessLimited {
                    reason: Some(reason),
                };
                inspected.push((
                    sample,
                    InspectionFields {
                        owner_user: limited.clone(),
                        executable_path: limited,
                        access_level: AccessLevel::Denied,
                    },
                ));
            }
            ProcessInspection::Gone => {}
            ProcessInspection::Cancelled => return Err(cancelled_error()),
        }
    }

    let mut live_keys = HashMap::with_capacity(inspected.len());
    for (index, (sample, _)) in inspected.iter().enumerate() {
        if index % 64 == 0 {
            check_cancelled(cancellation)?;
        }
        live_keys.insert(
            sample.pid,
            (
                sample.create_time,
                process_key(&boot_id, sample.pid, sample.create_time),
            ),
        );
    }

    let mut processes = Vec::with_capacity(inspected.len());
    for (index, (sample, fields)) in inspected.into_iter().enumerate() {
        if index % 64 == 0 {
            check_cancelled(cancellation)?;
        }
        let key = process_key(&boot_id, sample.pid, sample.create_time);
        let parent = sample.parent_pid.and_then(|parent_pid| {
            live_keys
                .get(&parent_pid)
                .filter(|(parent_create_time, _)| *parent_create_time <= sample.create_time)
                .map(|(_, key)| key.clone())
        });
        let cpu_percent = cpu_values.get(&key).cloned().unwrap_or(FieldValue::Unknown);
        processes.push(ProcessRecord {
            instance_key: key,
            parent_instance_key: FieldValue::Known(parent),
            owner_user: fields.owner_user,
            executable_name: sample.image_name,
            executable_path: fields.executable_path,
            command_line: FieldValue::Unknown,
            working_directory: FieldValue::Unknown,
            cpu_percent,
            memory_bytes: FieldValue::Known(sample.working_set),
            started_at: filetime_timestamp(sample.create_time)
                .map(FieldValue::Known)
                .unwrap_or(FieldValue::Unknown),
            status: if sample.status == domain::ProcessStatus::Unknown {
                FieldValue::Unknown
            } else {
                FieldValue::Known(sample.status)
            },
            access_level: fields.access_level,
            // Supervisor ownership is overlaid after discovery; native rows
            // never imply lifecycle control.
            ownership: ProcessOwnership::External,
            managed_run_id: None,
            project_id: None,
            project_association: ProjectEvidence::Unknown,
            project_features: ProjectEvidence::Unknown,
            classification: unknown_classification(),
            port_bindings: FieldValue::Unknown,
            last_seen_revision: 0,
        });
    }
    Ok(FastProcessScan { processes })
}

fn scan_ports_blocking(cancellation: &CancellationToken) -> Result<PortScan, AppError> {
    check_cancelled(cancellation)?;
    let boot_before = optional_boot_identifier(cancellation)?;
    let identities_before = optional_identity_snapshot(cancellation)?;
    let native_rows = match query_port_rows(cancellation)? {
        FieldValue::Known(rows) => rows,
        FieldValue::Unknown => {
            return Ok(PortScan {
                bindings: FieldValue::Unknown,
            });
        }
        FieldValue::AccessLimited { reason } => {
            return Ok(PortScan {
                bindings: FieldValue::AccessLimited { reason },
            });
        }
        FieldValue::NotSupported => {
            return Ok(PortScan {
                bindings: FieldValue::NotSupported,
            });
        }
    };

    let identities_after = optional_identity_snapshot(cancellation)?;
    let boot_after = optional_boot_identifier(cancellation)?;
    let stable_identities = stable_identity_keys(
        boot_before,
        boot_after,
        identities_before,
        identities_after,
        cancellation,
    )?;
    let observed_at = current_timestamp()?;
    let bindings = aggregate_port_rows(native_rows, &stable_identities, observed_at, cancellation)?;
    Ok(PortScan {
        bindings: FieldValue::Known(bindings),
    })
}

fn optional_boot_identifier(cancellation: &CancellationToken) -> Result<Option<String>, AppError> {
    check_cancelled(cancellation)?;
    let boot_id = query_boot_identifier().ok();
    check_cancelled(cancellation)?;
    Ok(boot_id)
}

fn optional_identity_snapshot(
    cancellation: &CancellationToken,
) -> Result<Option<HashMap<u32, u64>>, AppError> {
    check_cancelled(cancellation)?;
    let snapshot = match query_process_snapshot(cancellation) {
        Ok(snapshot) => snapshot,
        Err(_) if cancellation.is_cancelled() => return Err(cancelled_error()),
        Err(_) => return Ok(None),
    };
    let mut identities = HashMap::with_capacity(snapshot.processes.len());
    for (index, process) in snapshot.processes.into_iter().enumerate() {
        if index % 64 == 0 {
            check_cancelled(cancellation)?;
        }
        identities.insert(process.pid, process.create_time);
    }
    Ok(Some(identities))
}

fn stable_identity_keys(
    boot_before: Option<String>,
    boot_after: Option<String>,
    identities_before: Option<HashMap<u32, u64>>,
    identities_after: Option<HashMap<u32, u64>>,
    cancellation: &CancellationToken,
) -> Result<HashMap<u32, ProcessInstanceKey>, AppError> {
    let (Some(boot_before), Some(boot_after)) = (boot_before, boot_after) else {
        return Ok(HashMap::new());
    };
    if boot_before != boot_after {
        return Ok(HashMap::new());
    }
    let (Some(identities_before), Some(identities_after)) = (identities_before, identities_after)
    else {
        return Ok(HashMap::new());
    };

    let mut stable = HashMap::with_capacity(identities_before.len().min(identities_after.len()));
    for (index, (pid, create_time_after)) in identities_after.into_iter().enumerate() {
        if index % 64 == 0 {
            check_cancelled(cancellation)?;
        }
        if identities_before.get(&pid) == Some(&create_time_after) {
            stable.insert(pid, process_key(&boot_before, pid, create_time_after));
        }
    }
    Ok(stable)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PortEndpointKey {
    protocol: PortProtocol,
    address_family: AddressFamily,
    local_address: String,
    local_port: u16,
}

impl Ord for PortEndpointKey {
    fn cmp(&self, other: &Self) -> Ordering {
        protocol_rank(self.protocol)
            .cmp(&protocol_rank(other.protocol))
            .then_with(|| family_rank(self.address_family).cmp(&family_rank(other.address_family)))
            .then_with(|| self.local_address.cmp(&other.local_address))
            .then_with(|| self.local_port.cmp(&other.local_port))
    }
}

impl PartialOrd for PortEndpointKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Default)]
struct PortEndpointAggregate {
    owner_states: BTreeMap<u32, FieldValue<PortState>>,
}

fn aggregate_port_rows(
    native_rows: Vec<NativePortRow>,
    stable_identities: &HashMap<u32, ProcessInstanceKey>,
    observed_at: String,
    cancellation: &CancellationToken,
) -> Result<Vec<PortBinding>, AppError> {
    let mut endpoints = BTreeMap::<PortEndpointKey, PortEndpointAggregate>::new();
    for (index, row) in native_rows.into_iter().enumerate() {
        if index % 64 == 0 {
            check_cancelled(cancellation)?;
        }
        let endpoint = PortEndpointKey {
            protocol: row.protocol,
            address_family: row.address_family,
            local_address: row.local_address,
            local_port: row.local_port,
        };
        endpoints
            .entry(endpoint)
            .or_default()
            .owner_states
            .entry(row.pid)
            .and_modify(|state| {
                *state = preferred_port_state(state.clone(), row.state.clone());
            })
            .or_insert(row.state);
    }

    let mut bindings = Vec::new();
    for (endpoint_index, (endpoint, aggregate)) in endpoints.into_iter().enumerate() {
        if endpoint_index % 64 == 0 {
            check_cancelled(cancellation)?;
        }
        let owner_count = aggregate.owner_states.len();
        let mut unknown_state = None;
        for (owner_index, (pid, state)) in aggregate.owner_states.into_iter().enumerate() {
            if owner_index % 64 == 0 {
                check_cancelled(cancellation)?;
            }
            if let Some(instance_key) = stable_identities.get(&pid) {
                bindings.push(PortBinding {
                    protocol: endpoint.protocol,
                    address_family: endpoint.address_family,
                    local_address: endpoint.local_address.clone(),
                    local_port: endpoint.local_port,
                    state,
                    process_instance_key: Some(instance_key.clone()),
                    confidence: if owner_count > 1 {
                        PortOwnershipConfidence::Shared
                    } else {
                        PortOwnershipConfidence::Exact
                    },
                    observed_at: observed_at.clone(),
                });
            } else {
                unknown_state = Some(match unknown_state {
                    Some(current) => preferred_port_state(current, state),
                    None => state,
                });
            }
        }
        if let Some(state) = unknown_state {
            bindings.push(PortBinding {
                protocol: endpoint.protocol,
                address_family: endpoint.address_family,
                local_address: endpoint.local_address,
                local_port: endpoint.local_port,
                state,
                process_instance_key: None,
                confidence: PortOwnershipConfidence::Unknown,
                observed_at: observed_at.clone(),
            });
        }
    }
    Ok(bindings)
}

fn preferred_port_state(
    left: FieldValue<PortState>,
    right: FieldValue<PortState>,
) -> FieldValue<PortState> {
    if port_state_priority(&right) > port_state_priority(&left) {
        right
    } else {
        left
    }
}

fn port_state_priority(state: &FieldValue<PortState>) -> u8 {
    match state {
        FieldValue::Known(PortState::TcpListen) => 5,
        FieldValue::Known(PortState::TcpEstablished) => 4,
        FieldValue::Known(PortState::UdpBound) => 3,
        FieldValue::Known(PortState::TcpOther) => 2,
        FieldValue::Known(PortState::Unknown) | FieldValue::Unknown => 1,
        FieldValue::AccessLimited { .. } | FieldValue::NotSupported => 0,
    }
}

fn protocol_rank(protocol: PortProtocol) -> u8 {
    match protocol {
        PortProtocol::Tcp => 0,
        PortProtocol::Udp => 1,
    }
}

fn family_rank(family: AddressFamily) -> u8 {
    match family {
        AddressFamily::Ipv4 => 0,
        AddressFamily::Ipv6 => 1,
    }
}

fn current_timestamp() -> Result<String, AppError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            let mut app_error = AppError::new(
                ErrorCode::PlatformError,
                "Windows system clock is before the Unix epoch",
            );
            app_error.details.insert("reason".into(), error.to_string());
            app_error
        })?;
    let seconds = duration.as_secs();
    let days = i64::try_from(seconds / 86_400).map_err(|_| {
        AppError::new(
            ErrorCode::PlatformError,
            "Windows system clock exceeds the supported timestamp range",
        )
    })?;
    let seconds_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days).ok_or_else(|| {
        AppError::new(
            ErrorCode::PlatformError,
            "Windows system clock exceeds the supported timestamp range",
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

fn enrich_process_blocking(
    instance_key: ProcessInstanceKey,
    cancellation: &CancellationToken,
) -> Result<ProcessEnrichment, AppError> {
    check_cancelled(cancellation)?;
    let Some(enrichment) = query_enrichment(&instance_key, cancellation)? else {
        let mut error = AppError::new(
            ErrorCode::NotFound,
            "Windows process disappeared or its identity changed",
        );
        error
            .details
            .insert("pid".into(), instance_key.pid.to_string());
        return Err(error);
    };
    Ok(ProcessEnrichment {
        instance_key,
        executable_path: enrichment.executable_path,
        command_line: enrichment.command_line,
        working_directory: enrichment.working_directory,
        port_bindings: None,
        access_level: Some(enrichment.access_level),
    })
}

struct CanonicalProjectPath {
    path: PathBuf,
    normalized: NormalizedPathKey,
    identity: ProjectDirectoryIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProjectDirectoryIdentity {
    volume_serial_number: u32,
    file_index: u64,
}

fn normalize_project_root_blocking(
    root_directory: String,
    cancellation: &CancellationToken,
) -> Result<NormalizedProjectRoot, AppError> {
    if supported_absolute_windows_path(&root_directory).is_none() {
        let mut error = AppError::new(
            ErrorCode::InvalidArgument,
            "Windows project root must be a bounded absolute drive or UNC path",
        );
        error.details.insert("field".into(), "rootDirectory".into());
        return Err(error);
    }

    match canonicalize_project_path(&root_directory, cancellation)? {
        ProjectEvidence::Known(path) => {
            let canonical_root_directory = bounded_utf8_path(&path.path).ok_or_else(|| {
                project_root_availability_error(
                    ErrorCode::NotSupported,
                    "Windows canonical project root is not losslessly representable",
                )
            })?;
            NormalizedProjectRoot::from_platform_observation(
                canonical_root_directory,
                path.normalized,
            )
        }
        ProjectEvidence::Missing => Err(project_root_availability_error(
            ErrorCode::NotFound,
            "Windows project root does not exist",
        )),
        ProjectEvidence::AccessLimited { reason } => {
            let mut error = project_root_availability_error(
                ErrorCode::AccessDenied,
                "Windows project root cannot be accessed",
            );
            if let Some(reason) = reason {
                error.details.insert("reason".into(), reason);
            }
            Err(error)
        }
        ProjectEvidence::NotSupported => Err(project_root_availability_error(
            ErrorCode::NotSupported,
            "Windows project root is not losslessly representable",
        )),
        ProjectEvidence::Unknown => Err(project_root_availability_error(
            ErrorCode::PlatformError,
            "Windows project root normalization is inconclusive",
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
        NativePathObservation::Unknown => {
            return ProjectScanResult::from_platform_observation(
                &request,
                ProjectEvidence::Unknown,
                ProjectEvidence::Unknown,
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

    let first_canonical = match canonicalize_project_path(&first_path, cancellation)? {
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
        NativePathObservation::Unknown
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
    let second_canonical = match canonicalize_project_path(&second_path, cancellation)? {
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
        || second_canonical.identity != first_canonical.identity
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
) -> Result<ProjectEvidence<CanonicalProjectPath>, AppError> {
    check_cancelled(cancellation)?;
    let Some(wide_path) = supported_absolute_windows_path(path) else {
        return Ok(ProjectEvidence::NotSupported);
    };
    let handle = match open_project_directory(&wide_path) {
        Ok(handle) => handle,
        Err(ProjectFileFailure::Missing) => return Ok(ProjectEvidence::Missing),
        Err(ProjectFileFailure::AccessLimited(reason)) => {
            return Ok(ProjectEvidence::AccessLimited {
                reason: Some(reason),
            });
        }
        Err(ProjectFileFailure::Platform(error)) => return Err(error),
    };

    check_cancelled(cancellation)?;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // Safety: the directory handle remains owned and the output is writable.
    if let Err(error) = unsafe { GetFileInformationByHandle(handle.raw(), &mut information) } {
        return match classify_project_windows_error("inspect(project directory)", &error) {
            ProjectFileFailure::Missing => Ok(ProjectEvidence::Missing),
            ProjectFileFailure::AccessLimited(reason) => Ok(ProjectEvidence::AccessLimited {
                reason: Some(reason),
            }),
            ProjectFileFailure::Platform(error) => Err(error),
        };
    }
    if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0 {
        return Ok(ProjectEvidence::NotSupported);
    }
    let identity = ProjectDirectoryIdentity {
        volume_serial_number: information.dwVolumeSerialNumber,
        file_index: ((information.nFileIndexHigh as u64) << 32) | information.nFileIndexLow as u64,
    };

    check_cancelled(cancellation)?;
    // Safety: the owned handle remains live for this type query.
    if unsafe { GetFileType(handle.raw()) } != FILE_TYPE_DISK {
        return Ok(ProjectEvidence::NotSupported);
    }

    check_cancelled(cancellation)?;
    let final_path = match query_final_project_path(handle.raw()) {
        Ok(Some(path)) => path,
        Ok(None) => return Ok(ProjectEvidence::NotSupported),
        Err(ProjectFileFailure::Missing) => return Ok(ProjectEvidence::Missing),
        Err(ProjectFileFailure::AccessLimited(reason)) => {
            return Ok(ProjectEvidence::AccessLimited {
                reason: Some(reason),
            });
        }
        Err(ProjectFileFailure::Platform(error)) => return Err(error),
    };
    check_cancelled(cancellation)?;
    let Some(canonical) = parse_final_project_path(&final_path, identity, cancellation)? else {
        return Ok(ProjectEvidence::NotSupported);
    };
    Ok(ProjectEvidence::Known(canonical))
}

fn supported_absolute_windows_path(path: &str) -> Option<Vec<u16>> {
    if path.is_empty() || path.len() > MAX_PROJECT_PATH_BYTES || path.contains('\0') {
        return None;
    }
    let units = path.encode_utf16().collect::<Vec<_>>();
    if units.is_empty() || units.len() >= MAX_WINDOWS_PROJECT_PATH_UNITS {
        return None;
    }
    let tail = if starts_with_ascii_units(&units, b"\\\\?\\") {
        let tail = &units[4..];
        if starts_with_ascii_units(tail, b"UNC\\") {
            if !valid_unc_root(&tail[4..]) {
                return None;
            }
        } else if !valid_drive_root(tail) {
            return None;
        }
        tail
    } else if starts_with_ascii_units(&units, b"\\\\.\\") {
        return None;
    } else {
        if !valid_drive_root(&units) && !valid_unc_root(&units) {
            return None;
        }
        &units
    };
    if starts_with_ascii_units(tail, b"GLOBALROOT\\") {
        return None;
    }

    let mut nul_terminated = units;
    nul_terminated.push(0);
    Some(nul_terminated)
}

fn valid_drive_root(units: &[u16]) -> bool {
    units.len() >= 3
        && units[0] <= u8::MAX as u16
        && (units[0] as u8).is_ascii_alphabetic()
        && units[1] == b':' as u16
        && is_windows_separator(units[2])
}

fn valid_unc_root(units: &[u16]) -> bool {
    let tail = if units.starts_with(&[b'\\' as u16, b'\\' as u16]) {
        &units[2..]
    } else {
        units
    };
    let Some(server_end) = tail.iter().position(|unit| is_windows_separator(*unit)) else {
        return false;
    };
    if server_end == 0 {
        return false;
    }
    let server = &tail[..server_end];
    if ascii_units_equal(server, b".")
        || ascii_units_equal(server, b"?")
        || ascii_units_equal(server, b"GLOBALROOT")
    {
        return false;
    }
    let share_and_tail = &tail[server_end + 1..];
    let share_end = share_and_tail
        .iter()
        .position(|unit| is_windows_separator(*unit))
        .unwrap_or(share_and_tail.len());
    share_end > 0
}

fn is_windows_separator(unit: u16) -> bool {
    unit == b'\\' as u16 || unit == b'/' as u16
}

fn starts_with_ascii_units(units: &[u16], expected: &[u8]) -> bool {
    units.len() >= expected.len()
        && units
            .iter()
            .zip(expected)
            .take(expected.len())
            .all(|(left, right)| {
                *left <= u8::MAX as u16 && (*left as u8).eq_ignore_ascii_case(right)
            })
}

fn ascii_units_equal(units: &[u16], expected: &[u8]) -> bool {
    units.len() == expected.len() && starts_with_ascii_units(units, expected)
}

fn open_project_directory(wide_path: &[u16]) -> Result<OwnedProjectHandle, ProjectFileFailure> {
    // Safety: the path is NUL-terminated, and the returned handle is owned.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide_path.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    }
    .map_err(|error| classify_project_windows_error("open(project directory)", &error))?;
    Ok(OwnedProjectHandle(handle))
}

fn query_final_project_path(handle: HANDLE) -> Result<Option<String>, ProjectFileFailure> {
    let mut buffer = vec![0_u16; MAX_WINDOWS_PROJECT_PATH_UNITS];
    // Safety: the handle remains owned and the slice is fully writable. The
    // zero-valued flag requests a normalized name with a DOS volume.
    let returned =
        unsafe { GetFinalPathNameByHandleW(handle, &mut buffer, FILE_NAME_NORMALIZED) } as usize;
    if returned == 0 {
        // Safety: this immediately follows the failed Win32 call.
        return Err(classify_project_win32_code(
            "canonicalize(project directory)",
            unsafe { GetLastError() },
        ));
    }
    if returned >= buffer.len() {
        return Ok(None);
    }
    buffer.truncate(returned);
    Ok(String::from_utf16(&buffer)
        .ok()
        .filter(|path| !path.is_empty() && !path.contains('\0')))
}

fn parse_final_project_path(
    final_path: &str,
    identity: ProjectDirectoryIdentity,
    cancellation: &CancellationToken,
) -> Result<Option<CanonicalProjectPath>, AppError> {
    if final_path.is_empty()
        || final_path.len() > MAX_PROJECT_PATH_BYTES
        || final_path.contains(['/', '\0'])
    {
        return Ok(None);
    }

    let dos_path = if let Some(tail) = strip_ascii_case_prefix(final_path, "\\\\?\\UNC\\") {
        format!("\\\\{tail}")
    } else if let Some(tail) = strip_ascii_case_prefix(final_path, "\\\\?\\") {
        if strip_ascii_case_prefix(tail, "GLOBALROOT\\").is_some() || !is_absolute_drive_text(tail)
        {
            return Ok(None);
        }
        tail.to_owned()
    } else if strip_ascii_case_prefix(final_path, "\\\\.\\").is_some() {
        return Ok(None);
    } else {
        final_path.to_owned()
    };

    if is_absolute_drive_text(&dos_path) {
        parse_final_drive_path(&dos_path, identity, cancellation)
    } else if dos_path.starts_with("\\\\") {
        parse_final_unc_path(&dos_path, identity, cancellation)
    } else {
        Ok(None)
    }
}

fn is_absolute_drive_text(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\'
}

fn parse_final_drive_path(
    path: &str,
    identity: ProjectDirectoryIdentity,
    cancellation: &CancellationToken,
) -> Result<Option<CanonicalProjectPath>, AppError> {
    let drive = (path.as_bytes()[0] as char).to_ascii_uppercase();
    let Some(components) = parse_canonical_components(&path[3..]) else {
        return Err(invalid_canonical_project_path(
            "canonical drive path contains an invalid component",
        ));
    };
    build_canonical_project_path(
        NormalizedPathRoot::WindowsDrive(drive),
        format!("{drive}:\\"),
        components,
        identity,
        cancellation,
    )
}

fn parse_final_unc_path(
    path: &str,
    identity: ProjectDirectoryIdentity,
    cancellation: &CancellationToken,
) -> Result<Option<CanonicalProjectPath>, AppError> {
    let mut parts = path[2..].split('\\').collect::<Vec<_>>();
    if parts.last() == Some(&"") {
        parts.pop();
    }
    if parts.len() < 2
        || parts.iter().any(|part| !valid_canonical_component(part))
        || parts[0].eq_ignore_ascii_case("GLOBALROOT")
    {
        return Err(invalid_canonical_project_path(
            "canonical UNC path contains an invalid root or component",
        ));
    }
    let server = parts.remove(0);
    let share = parts.remove(0);
    if parts.len() > MAX_PROJECT_ANCESTOR_DEPTH {
        return Ok(None);
    }
    let Some(server_key) = windows_component_key(server, cancellation)? else {
        return Ok(None);
    };
    let Some(share_key) = windows_component_key(share, cancellation)? else {
        return Ok(None);
    };
    build_canonical_project_path(
        NormalizedPathRoot::WindowsUnc {
            server: server_key,
            share: share_key,
        },
        format!("\\\\{server}\\{share}"),
        parts,
        identity,
        cancellation,
    )
}

fn parse_canonical_components(path: &str) -> Option<Vec<&str>> {
    if path.is_empty() {
        return Some(Vec::new());
    }
    let path = path.strip_suffix('\\').unwrap_or(path);
    if path.is_empty() {
        return Some(Vec::new());
    }
    let components = path.split('\\').collect::<Vec<_>>();
    components
        .iter()
        .all(|component| valid_canonical_component(component))
        .then_some(components)
}

fn valid_canonical_component(component: &str) -> bool {
    !component.is_empty()
        && component != "."
        && component != ".."
        && !component.contains(['\\', '/', '\0'])
}

fn build_canonical_project_path(
    root: NormalizedPathRoot,
    mut display_path: String,
    components: Vec<&str>,
    identity: ProjectDirectoryIdentity,
    cancellation: &CancellationToken,
) -> Result<Option<CanonicalProjectPath>, AppError> {
    if components.len() > MAX_PROJECT_ANCESTOR_DEPTH {
        return Ok(None);
    }
    let mut normalized_components = Vec::with_capacity(components.len());
    for component in components {
        check_cancelled(cancellation)?;
        let Some(key) = windows_component_key(component, cancellation)? else {
            return Ok(None);
        };
        normalized_components.push(key);
        if !display_path.ends_with('\\') {
            display_path.push('\\');
        }
        display_path.push_str(component);
        if display_path.len() > MAX_PROJECT_PATH_BYTES {
            return Ok(None);
        }
    }
    let normalized = NormalizedPathKey::from_canonical_components(root, normalized_components)
        .map_err(|error| normalized_project_path_error(&error))?;
    Ok(Some(CanonicalProjectPath {
        path: PathBuf::from(display_path),
        normalized,
        identity,
    }))
}

fn windows_component_key(
    component: &str,
    cancellation: &CancellationToken,
) -> Result<Option<String>, AppError> {
    if !valid_canonical_component(component) {
        return Ok(None);
    }
    let source = component.encode_utf16().collect::<Vec<_>>();
    check_cancelled(cancellation)?;
    // Invariant uppercase provides a locale-independent Windows comparison
    // key without applying Unicode normalization that NTFS does not perform.
    let required = unsafe {
        LCMapStringEx(
            LOCALE_NAME_INVARIANT,
            LCMAP_UPPERCASE,
            &source,
            None,
            None,
            None,
            LPARAM(0),
        )
    };
    if required <= 0 {
        return Err(project_win32_code_error(
            "map(project path component case)",
            unsafe { GetLastError() },
        ));
    }
    let required = required as usize;
    if required > MAX_PROJECT_PATH_BYTES {
        return Ok(None);
    }
    check_cancelled(cancellation)?;
    let mut mapped = vec![0_u16; required];
    let actual = unsafe {
        LCMapStringEx(
            LOCALE_NAME_INVARIANT,
            LCMAP_UPPERCASE,
            &source,
            Some(&mut mapped),
            None,
            None,
            LPARAM(0),
        )
    };
    if actual <= 0 {
        return Err(project_win32_code_error(
            "map(project path component case)",
            unsafe { GetLastError() },
        ));
    }
    if actual as usize != mapped.len() {
        return Err(invalid_canonical_project_path(
            "Windows case mapping returned an inconsistent length",
        ));
    }
    check_cancelled(cancellation)?;
    Ok(String::from_utf16(&mapped)
        .ok()
        .filter(|mapped| valid_canonical_component(mapped)))
}

fn strip_ascii_case_prefix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    let head = value.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &value[prefix.len()..])
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
            match inspect_project_marker(&marker_path_text, cancellation)? {
                ProjectMarkerObservation::MissingOrUnsafe => continue,
                ProjectMarkerObservation::NotSupported => {
                    return Ok(ProjectEvidence::NotSupported);
                }
                ProjectMarkerObservation::AccessLimited(reason) => {
                    return Ok(ProjectEvidence::AccessLimited {
                        reason: Some(reason),
                    });
                }
                ProjectMarkerObservation::RegularFile => {}
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

enum ProjectMarkerObservation {
    RegularFile,
    MissingOrUnsafe,
    NotSupported,
    AccessLimited(String),
}

fn inspect_project_marker(
    marker_path: &str,
    cancellation: &CancellationToken,
) -> Result<ProjectMarkerObservation, AppError> {
    let Some(wide_path) = extended_project_path(marker_path) else {
        return Ok(ProjectMarkerObservation::NotSupported);
    };
    check_cancelled(cancellation)?;
    // OPEN_REPARSE_POINT makes the final marker itself no-follow. Backup
    // semantics allows opening a directory so it can be rejected explicitly.
    let handle = match unsafe {
        CreateFileW(
            PCWSTR(wide_path.as_ptr()),
            FILE_READ_ATTRIBUTES.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
    } {
        Ok(handle) => OwnedProjectHandle(handle),
        Err(error) => {
            return match classify_project_windows_error("open(project marker)", &error) {
                ProjectFileFailure::Missing => Ok(ProjectMarkerObservation::MissingOrUnsafe),
                ProjectFileFailure::AccessLimited(reason) => {
                    Ok(ProjectMarkerObservation::AccessLimited(reason))
                }
                ProjectFileFailure::Platform(error) => Err(error),
            };
        }
    };

    check_cancelled(cancellation)?;
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    if let Err(error) = unsafe { GetFileInformationByHandle(handle.raw(), &mut information) } {
        return match classify_project_windows_error("inspect(project marker)", &error) {
            ProjectFileFailure::Missing => Ok(ProjectMarkerObservation::MissingOrUnsafe),
            ProjectFileFailure::AccessLimited(reason) => {
                Ok(ProjectMarkerObservation::AccessLimited(reason))
            }
            ProjectFileFailure::Platform(error) => Err(error),
        };
    }
    let attributes = information.dwFileAttributes;
    if attributes & (FILE_ATTRIBUTE_DIRECTORY.0 | FILE_ATTRIBUTE_REPARSE_POINT.0) != 0 {
        Ok(ProjectMarkerObservation::MissingOrUnsafe)
    } else {
        Ok(ProjectMarkerObservation::RegularFile)
    }
}

fn extended_project_path(path: &str) -> Option<Vec<u16>> {
    if path.is_empty() || path.len() > MAX_PROJECT_PATH_BYTES || path.contains('\0') {
        return None;
    }
    let extended = if is_absolute_drive_text(path) {
        format!("\\\\?\\{path}")
    } else if let Some(tail) = path.strip_prefix("\\\\") {
        format!("\\\\?\\UNC\\{tail}")
    } else {
        return None;
    };
    let mut units = extended.encode_utf16().collect::<Vec<_>>();
    if units.len() > MAX_WINDOWS_EXTENDED_PROJECT_PATH_UNITS {
        return None;
    }
    units.push(0);
    Some(units)
}

fn bounded_utf8_path(path: &Path) -> Option<String> {
    path.to_str()
        .filter(|path| !path.is_empty() && path.len() <= MAX_PROJECT_PATH_BYTES)
        .map(str::to_owned)
}

struct OwnedProjectHandle(HANDLE);

impl OwnedProjectHandle {
    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedProjectHandle {
    fn drop(&mut self) {
        // Safety: this wrapper owns one successful file handle.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

enum ProjectFileFailure {
    Missing,
    AccessLimited(String),
    Platform(AppError),
}

fn classify_project_windows_error(
    operation: &'static str,
    error: &WindowsError,
) -> ProjectFileFailure {
    match WIN32_ERROR::from_error(error) {
        Some(code) => classify_project_win32_code(operation, code),
        None => ProjectFileFailure::Platform(project_windows_error(operation, error)),
    }
}

fn classify_project_win32_code(operation: &'static str, code: WIN32_ERROR) -> ProjectFileFailure {
    match code {
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => ProjectFileFailure::Missing,
        ERROR_ACCESS_DENIED => {
            ProjectFileFailure::AccessLimited(format!("{operation}:accessLimited"))
        }
        _ => ProjectFileFailure::Platform(project_win32_code_error(operation, code)),
    }
}

fn stale_project_scan_error(instance_key: &ProcessInstanceKey, reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::IdentityMismatch,
        "Windows project scan no longer matches the process instance",
    );
    error.retryable = true;
    error
        .details
        .insert("pid".into(), instance_key.pid.to_string());
    error.details.insert("reason".into(), reason.into());
    error
}

fn project_windows_error(operation: &'static str, source: &WindowsError) -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "Windows project path query failed",
    );
    error.retryable = true;
    error.details.insert("operation".into(), operation.into());
    error.details.insert(
        "hresult".into(),
        format!("0x{:08X}", source.code().0 as u32),
    );
    error
}

fn project_win32_code_error(operation: &'static str, code: WIN32_ERROR) -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "Windows project path query failed",
    );
    error.retryable = true;
    error.details.insert("operation".into(), operation.into());
    error.details.insert("win32Code".into(), code.0.to_string());
    error
}

fn invalid_canonical_project_path(reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "Windows canonical project path is invalid",
    );
    error.details.insert("reason".into(), reason.into());
    error
}

fn normalized_project_path_error(source: &AppError) -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "Windows canonical project path could not be normalized",
    );
    error
        .details
        .insert("reason".into(), source.message.clone());
    error
}

fn project_root_availability_error(code: ErrorCode, message: &'static str) -> AppError {
    let mut error = AppError::new(code, message);
    error.retryable = true;
    error.details.insert("field".into(), "rootDirectory".into());
    error
}

struct InspectionFields {
    owner_user: FieldValue<String>,
    executable_path: FieldValue<String>,
    access_level: AccessLevel,
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
            "Windows boot identifier cache was not initialized",
        )
    })
}

fn calculate_cpu_values(
    state: &BackendState,
    system_total: Option<u64>,
    samples: &[NativeProcessSample],
    boot_id: &str,
    cancellation: &CancellationToken,
) -> Result<HashMap<ProcessInstanceKey, FieldValue<f32>>, AppError> {
    let mut values = HashMap::with_capacity(samples.len());
    let Some(system_total) = system_total else {
        return Ok(values);
    };
    let mut process_totals = HashMap::with_capacity(samples.len());
    for (index, sample) in samples.iter().enumerate() {
        if index % 64 == 0 {
            check_cancelled(cancellation)?;
        }
        if let Some(total) = sample.kernel_time.checked_add(sample.user_time) {
            process_totals.insert(process_key(boot_id, sample.pid, sample.create_time), total);
        }
    }

    let mut baseline = state
        .cpu_baseline
        .lock()
        .map_err(|_| AppError::new(ErrorCode::Internal, "Windows CPU sample cache is poisoned"))?;
    if let Some(previous) = baseline.as_ref()
        && let Some(system_delta) = system_total.checked_sub(previous.system_total)
        && system_delta != 0
    {
        for (index, (key, current_total)) in process_totals.iter().enumerate() {
            if index % 64 == 0 {
                check_cancelled(cancellation)?;
            }
            let value = previous
                .process_totals
                .get(key)
                .and_then(|previous| current_total.checked_sub(*previous))
                .map(|process_delta| process_delta as f64 / system_delta as f64 * 100.0)
                .filter(|percent| percent.is_finite() && *percent <= f32::MAX as f64)
                .map(|percent| FieldValue::Known(percent.clamp(0.0, 100.0) as f32))
                .unwrap_or(FieldValue::Unknown);
            values.insert(key.clone(), value);
        }
    }
    *baseline = Some(CpuBaseline {
        system_total,
        process_totals,
    });
    Ok(values)
}

fn process_key(boot_id: &str, pid: u32, create_time: u64) -> ProcessInstanceKey {
    ProcessInstanceKey {
        boot_id: boot_id.to_owned(),
        pid,
        native_start_time: create_time.to_string(),
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

fn filetime_timestamp(filetime: u64) -> Option<String> {
    const WINDOWS_TO_UNIX_100NS: u64 = 116_444_736_000_000_000;
    const TICKS_PER_SECOND: u64 = 10_000_000;
    let unix_ticks = filetime.checked_sub(WINDOWS_TO_UNIX_100NS)?;
    let seconds = unix_ticks / TICKS_PER_SECOND;
    let fraction = unix_ticks % TICKS_PER_SECOND;
    let days = i64::try_from(seconds / 86_400).ok()?;
    let seconds_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days)?;
    let hour = seconds_of_day / 3_600;
    let minute = seconds_of_day % 3_600 / 60;
    let second = seconds_of_day % 60;
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{fraction:07}Z"
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
        Err(cancelled_error())
    } else {
        Ok(())
    }
}

fn cancelled_error() -> AppError {
    let mut error = AppError::new(
        ErrorCode::Timeout,
        "Windows discovery operation was cancelled",
    );
    error.retryable = true;
    error
}

fn blocking_join_error(error: tokio::task::JoinError) -> AppError {
    let mut app_error = AppError::new(ErrorCode::Internal, "Windows discovery worker failed");
    app_error.details.insert("reason".into(), error.to_string());
    app_error
}
