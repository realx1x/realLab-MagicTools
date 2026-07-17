use std::collections::hash_map::Entry;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::io::{self, PipeReader, PipeWriter, Read, pipe};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use discovery::{
    CancellationToken, ClassificationEngine, ClassificationRule as DiscoveryClassificationRule,
    ClassificationRuleAction as DiscoveryClassificationRuleAction,
    ClassificationRuleMatcher as DiscoveryClassificationRuleMatcher, DiscoveryBackend,
    DiscoverySchedulerHandle, NormalizedProjectRoot, ProjectCatalog, ProjectContextSnapshot,
    RegisteredProject,
};
#[cfg(windows)]
use domain::ShellKind;
use domain::{
    AppError, ClassificationRuleAction, ClassificationRuleMatcherKind, ClassificationRuleSummary,
    CreateClassificationRuleRequest, CreateLaunchProfileRequest, CreateProjectRequest,
    DeleteClassificationRuleRequest, DeleteClassificationRuleResponse, DeleteLaunchProfileRequest,
    DeleteLaunchProfileResponse, DeleteProjectRequest, DeleteProjectResponse, ErrorCode,
    ExecutableResolution, ExecutableUnknownReason, ExecutionInvocationPreview, ExecutionPlatform,
    ExecutionPreviewRequest, ExitImpactSummary, ExitRetainedReason, ExitRunImpact,
    FinalExecutionPreview, ForceStopManagedRunRequest, GetExitImpactRequest,
    GetManagedLogRangeRequest, GetManagedLogRangeResponse, GetProcessDetailsRequest,
    GetProcessDetailsResponse, LaunchExecution, LaunchProfile, ListClassificationRulesRequest,
    ListClassificationRulesResponse, ListLaunchProfilesRequest, ListLaunchProfilesResponse,
    ListProjectsRequest, ListProjectsResponse, ListRunHistoryRequest, ListRunHistoryResponse,
    ManagedLogBatch, ManagedLogChunk, ManagedLogEncoding, ManagedLogIoErrorKind, ManagedLogStream,
    ManagedLogTextStatus, ManagedRunSummary, ManagedStopKind, ManagedStopOperationResult,
    ManagedStopOutcome, ManagedStopSignalDisposition, ManagedStopStatus, ProcessControl,
    ProcessInstanceKey, ProjectSummary, RunState, SaveClassificationRuleRequest,
    SaveLaunchProfileRequest, SaveLaunchProfileWithSecretsRequest, SaveProjectRequest,
    StartManagedRunRequest, StartManagedRunResult, StopAllForExitMemberAction,
    StopAllForExitMemberResult, StopAllForExitRequest, StopAllForExitResult, StopAllForExitStatus,
    StopManagedRunRequest, UpdateClassificationRuleRequest, UpdateLaunchProfileRequest,
    UpdateProjectRequest,
};
use lifecycle::{ExecutionPreviewContext, ResolvedEnvironment, ResolvedEnvironmentValue};
use logging::{
    DEFAULT_DISK_BYTES_PER_RUN, LogCaptureSummary, LogEncodingPolicy, LogError, LogErrorKind,
    LogLimits, LogRedactionError, LogRedactionRules, LogStream, LogTextError, LogTextPipeline,
    LogTextStatus, MAX_LOG_FILE_BYTES, MAX_LOG_FILES_PER_STREAM, ManagedLogRetentionInspection,
    ManagedLogRetentionRemoval, ManagedLogRetentionStore, ManagedRunLogCollector,
    ManagedRunLogEventSource, ManagedRunLogRangeReader, ManagedRunLogStreams, ResolvedLogEncoding,
};
use platform_common::credentials::SecretStore;
use platform_common::is_sensitive_field_name;
#[cfg(target_os = "macos")]
use platform_macos::{
    MacosManagedExitPoll as ManagedExitPoll, MacosManagedLaunchError as ManagedLaunchError,
    MacosManagedLaunchRequest, MacosManagedProcess as ManagedProcess, MacosManagedRecoveryProbe,
    MacosManagedStdio as ManagedStdio, MacosManagedStopSignalResult as ManagedStopSignalResult,
    RecoveredMacosProcessGroup, SuspendedMacosManagedProcess as SuspendedManagedProcess,
    prepare_suspended_process_group, probe_recovered_process_group,
};
#[cfg(windows)]
use platform_windows::{
    SuspendedWindowsManagedProcess as SuspendedManagedProcess,
    WindowsManagedExitPoll as ManagedExitPoll, WindowsManagedLaunchError as ManagedLaunchError,
    WindowsManagedLaunchRequest, WindowsManagedProcess as ManagedProcess,
    WindowsManagedRecoveryProbe, WindowsManagedStdio as ManagedStdio,
    WindowsManagedStopSignalResult as ManagedStopSignalResult, prepare_suspended_into_job,
    probe_managed_process_recovery,
};
use protocol::names::method::{
    PROFILE_DELETE, PROFILE_SAVE, PROJECT_DELETE, PROJECT_SAVE, RULE_DELETE, RULE_SAVE,
};
use sha2::{Digest, Sha256};
use storage::{
    CURRENT_MANAGED_LOG_REDACTION_VERSION, DiagnosticDatabaseSummary, LaunchFailureStage,
    MAX_AUDIT_RETENTION_DELETE_BATCH_SIZE, MAX_MANAGED_EXIT_ACTIVE_RUNS,
    MAX_MANAGED_RUN_LOG_RETENTION_PAGE_SIZE, ManagedExitActiveRun, ManagedExitMemberAction,
    ManagedExitOperation, ManagedExitOperationMember, ManagedRunControlGroup,
    ManagedRunLogRetentionCandidate, ManagedRunLogRetentionCursor, ManagedRunRecord,
    ManagedRunRecoveryCandidate, ManagedRunRecoveryOutcome, ManagedStopCompletion,
    ManagedStopRequest, PreparedCatalogMutation, SupervisorRepository,
};
use tokio::sync::{Mutex, Semaphore};
#[cfg(windows)]
use windows::Win32::Globalization::{GetACP, GetOEMCP};

use crate::{CredentialCleanupStatus, ManagedLogPublisher, ProfileService};

const RUN_ID_RANDOM_BYTES: usize = 16;
const RUN_ID_ALLOCATION_ATTEMPTS: usize = 4;
const PROFILE_ID_RANDOM_BYTES: usize = 16;
const PROFILE_ID_ALLOCATION_ATTEMPTS: usize = 4;
const PROJECT_ID_RANDOM_BYTES: usize = 16;
const PROJECT_ID_ALLOCATION_ATTEMPTS: usize = 4;
const RULE_ID_RANDOM_BYTES: usize = 16;
const RULE_ID_ALLOCATION_ATTEMPTS: usize = 4;
const CLEANUP_RETRY_ATTEMPTS: usize = 4;
const CLEANUP_RETRY_DELAY: Duration = Duration::from_millis(250);
const STOP_POLL_INTERVAL: Duration = Duration::from_millis(100);
const TIMED_OUT_STOP_POLL_INTERVAL: Duration = Duration::from_secs(1);
const FORCE_STOP_CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(5);
const TERMINAL_EXIT_POLL_INTERVAL: Duration = Duration::from_millis(100);
const DEFAULT_TERMINAL_ROWS: u16 = 24;
const DEFAULT_TERMINAL_COLUMNS: u16 = 80;
const MANAGED_LOG_RANGE_CONCURRENCY: usize = 4;
const MANAGED_LOG_READER_CAPACITY: usize = 256;
const MANAGED_LOG_RETENTION_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
const MANAGED_LOG_RETENTION_MAX_AGE: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const MANAGED_LOG_RETENTION_MAX_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;
const HARD_MAX_MANAGED_LOG_DISK_BYTES_PER_RUN: u64 =
    MAX_LOG_FILE_BYTES * MAX_LOG_FILES_PER_STREAM as u64 * 2;
const MANAGED_LOG_RETENTION_PAGE_SIZE: u16 = 64;
const MANAGED_LOG_RETENTION_MAX_PAGES: usize = 4;
const MAX_RETAINED_MANAGED_LOG_RUNS: u64 = 256;
const AUDIT_RETENTION_MAX_BATCHES_PER_PASS: usize = 4;
const MAX_ACTIVE_MANAGED_LOG_RUNS: usize =
    (MANAGED_LOG_RETENTION_MAX_TOTAL_BYTES / DEFAULT_DISK_BYTES_PER_RUN) as usize;

type ManagedLogReaders = Arc<StdMutex<ManagedLogReaderRegistry>>;

/// Owns every platform process control from suspended creation through durable
/// Running state. It intentionally has no `Debug` implementation.
pub struct ManagedRunService {
    inner: Arc<Mutex<ManagedRunInner>>,
    log_publisher: ManagedLogPublisher,
    log_range_permits: Arc<Semaphore>,
    log_readers: ManagedLogReaders,
    log_retention_store: ManagedLogRetentionStore,
    log_retention_gate: Arc<Mutex<()>>,
    log_start_gate: Mutex<()>,
}

struct ManagedRunInner {
    profiles: ProfileService,
    discovery_backend: Arc<dyn DiscoveryBackend>,
    discovery_scheduler: DiscoverySchedulerHandle,
    log_root: PathBuf,
    controls: HashMap<String, PlatformRunControl>,
    service_incarnation: [u8; 32],
}

enum PlatformRunControl {
    StartingIntent,
    Suspended(SuspendedManagedProcess),
    RunningUncommitted(ManagedProcess),
    Running(PlatformManagedProcess),
    Stopping(StoppingManagedProcess),
    Quarantined(PlatformManagedProcess),
    CleanupPending(ManagedLaunchError),
}

struct StoppingManagedProcess {
    process: PlatformManagedProcess,
    operation_id: String,
    kind: ManagedStopKind,
    phase: ManagedStopControlPhase,
    signal_disposition: Option<ManagedStopSignalDisposition>,
    confirmation_window: Duration,
    deadline: Instant,
    worker_running: bool,
}

struct RecoveredStopWorker {
    run_id: String,
    operation_id: String,
}

struct ManagedLogCapture {
    _stdout: JoinHandle<Result<LogCaptureSummary, LogError>>,
    _stderr: JoinHandle<Result<LogCaptureSummary, LogError>>,
    _events: JoinHandle<()>,
    range_reader: ManagedRunLogRangeReader,
}

struct ManagedLogReaderEntry {
    reader: ManagedRunLogRangeReader,
    active: bool,
    historical: bool,
}

#[derive(Default)]
struct ManagedLogReaderRegistry {
    entries: HashMap<String, ManagedLogReaderEntry>,
    completed: VecDeque<String>,
}

struct ManagedLogReaderReservation {
    run_id: String,
    readers: ManagedLogReaders,
    committed: bool,
}

impl ManagedLogReaderReservation {
    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for ManagedLogReaderReservation {
    fn drop(&mut self) {
        if !self.committed {
            if let Ok(mut readers) = self.readers.lock() {
                readers.remove(&self.run_id);
            }
        }
    }
}

struct ManagedLogEventCompletion {
    run_id: String,
    readers: ManagedLogReaders,
}

impl Drop for ManagedLogEventCompletion {
    fn drop(&mut self) {
        if let Ok(mut readers) = self.readers.lock() {
            readers.mark_completed(&self.run_id);
        }
    }
}

impl ManagedLogReaderRegistry {
    fn get(&mut self, run_id: &str) -> Option<(ManagedRunLogRangeReader, bool)> {
        let entry = self.entries.get(run_id)?;
        let result = (entry.reader.clone(), entry.historical);
        if !entry.active {
            self.completed.retain(|completed| completed != run_id);
            self.completed.push_back(run_id.to_owned());
        }
        Some(result)
    }

    fn reserve_active(
        readers: &ManagedLogReaders,
        run_id: &str,
        reader: ManagedRunLogRangeReader,
    ) -> Result<ManagedLogReaderReservation, AppError> {
        let mut registry = readers.lock().map_err(|_| managed_log_registry_error())?;
        if registry.entries.contains_key(run_id) {
            return Err(AppError::new(
                ErrorCode::Conflict,
                "managed run log reader is already registered",
            ));
        }
        registry.make_room()?;
        registry.entries.insert(
            run_id.to_owned(),
            ManagedLogReaderEntry {
                reader,
                active: true,
                historical: false,
            },
        );
        drop(registry);
        Ok(ManagedLogReaderReservation {
            run_id: run_id.to_owned(),
            readers: Arc::clone(readers),
            committed: false,
        })
    }

    fn insert_historical(
        &mut self,
        run_id: &str,
        reader: ManagedRunLogRangeReader,
    ) -> Result<(ManagedRunLogRangeReader, bool), AppError> {
        if let Some(entry) = self.entries.get(run_id) {
            return Ok((entry.reader.clone(), entry.historical));
        }
        self.make_room()?;
        self.entries.insert(
            run_id.to_owned(),
            ManagedLogReaderEntry {
                reader: reader.clone(),
                active: false,
                historical: true,
            },
        );
        self.completed.push_back(run_id.to_owned());
        Ok((reader, true))
    }

    fn mark_completed(&mut self, run_id: &str) {
        let Some(entry) = self.entries.get_mut(run_id) else {
            return;
        };
        if entry.active {
            entry.active = false;
            self.completed.push_back(run_id.to_owned());
        }
    }

    fn remove(&mut self, run_id: &str) {
        self.entries.remove(run_id);
        self.completed.retain(|completed| completed != run_id);
    }

    /// Removes a completed or historical reader before retention deletes its
    /// files. Active capture readers remain protected even when the database
    /// has already reached a terminal state.
    fn evict_for_retention(&mut self, run_id: &str) -> bool {
        if self.entries.get(run_id).is_some_and(|entry| entry.active) {
            return false;
        }
        self.remove(run_id);
        true
    }

    fn make_room(&mut self) -> Result<(), AppError> {
        while self.entries.len() >= MANAGED_LOG_READER_CAPACITY {
            let Some(run_id) = self.completed.pop_front() else {
                let mut error = AppError::new(
                    ErrorCode::Conflict,
                    "managed run log reader capacity is exhausted",
                );
                error.retryable = true;
                error
                    .details
                    .insert("stage".into(), "ReserveManagedLogReader".into());
                return Err(error);
            };
            if self.entries.get(&run_id).is_some_and(|entry| !entry.active) {
                self.entries.remove(&run_id);
            }
        }
        Ok(())
    }
}

enum RecoveredControlPlan {
    Running,
    Stopping {
        operation_id: String,
        kind: ManagedStopKind,
        phase: ManagedStopControlPhase,
        signal_disposition: Option<ManagedStopSignalDisposition>,
        confirmation_window: Duration,
    },
}

enum PlatformManagedProcess {
    Launched {
        process: ManagedProcess,
        _logs: ManagedLogCapture,
    },
    #[cfg(target_os = "macos")]
    Recovered(RecoveredMacosProcessGroup),
}

impl PlatformManagedProcess {
    fn instance_key(&self) -> &ProcessInstanceKey {
        match self {
            Self::Launched { process, .. } => process.instance_key(),
            #[cfg(target_os = "macos")]
            Self::Recovered(process) => process.instance_key(),
        }
    }

    fn log_range_reader(&self) -> Option<ManagedRunLogRangeReader> {
        match self {
            Self::Launched { _logs, .. } => Some(_logs.range_reader.clone()),
            #[cfg(target_os = "macos")]
            Self::Recovered(_) => None,
        }
    }

    fn is_terminal(&self) -> bool {
        match self {
            Self::Launched { process, .. } => process.is_terminal(),
            #[cfg(target_os = "macos")]
            Self::Recovered(_) => false,
        }
    }

    #[cfg(target_os = "macos")]
    fn process_group_id(&self) -> u32 {
        match self {
            Self::Launched { process, .. } => process.process_group_id(),
            Self::Recovered(process) => process.process_group_id(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ManagedStopControlPhase {
    Requested,
    SignalPending,
    SignalAttempted,
    Monitoring,
    TimedOut,
    CompletionPending(domain::ManagedStopOutcome),
}

enum ManagedStopCommand {
    Graceful(StopManagedRunRequest),
    Force(ForceStopManagedRunRequest),
}

impl ManagedStopCommand {
    fn run_id(&self) -> &str {
        match self {
            Self::Graceful(request) => &request.run_id,
            Self::Force(request) => &request.run_id,
        }
    }

    fn kind(&self) -> ManagedStopKind {
        match self {
            Self::Graceful(_) => ManagedStopKind::Graceful,
            Self::Force(_) => ManagedStopKind::Force,
        }
    }

    fn as_storage_request(&self) -> ManagedStopRequest<'_> {
        match self {
            Self::Graceful(request) => ManagedStopRequest::Graceful(request),
            Self::Force(request) => ManagedStopRequest::Force(request),
        }
    }
}

impl ManagedRunService {
    pub async fn open(
        database_path: storage::PrivateDatabasePath,
        log_root: impl AsRef<Path>,
        log_publisher: ManagedLogPublisher,
        discovery_backend: Arc<dyn DiscoveryBackend>,
        discovery_scheduler: DiscoverySchedulerHandle,
    ) -> Result<Self, AppError> {
        let profiles = ProfileService::open(database_path).await?;
        Self::new(
            profiles,
            log_root,
            log_publisher,
            discovery_backend,
            discovery_scheduler,
        )
        .await
    }

    /// Builds a service only after every unfinished durable run has been
    /// reconciled. The async boundary prevents injected profile services from
    /// bypassing startup recovery.
    pub async fn new(
        mut profiles: ProfileService,
        log_root: impl AsRef<Path>,
        log_publisher: ManagedLogPublisher,
        discovery_backend: Arc<dyn DiscoveryBackend>,
        discovery_scheduler: DiscoverySchedulerHandle,
    ) -> Result<Self, AppError> {
        let log_root = log_root.as_ref();
        if !log_root.is_absolute() || log_root.as_os_str().is_empty() || log_root.to_str().is_none()
        {
            let mut error = AppError::new(
                ErrorCode::InvalidArgument,
                "managed run log root is invalid",
            );
            error.details.insert("field".into(), "logRoot".into());
            error.details.insert(
                "reason".into(),
                "must be an absolute Unicode path owned by the Supervisor".into(),
            );
            return Err(error);
        }
        let log_retention_store =
            ManagedLogRetentionStore::open(log_root).map_err(managed_log_retention_error)?;
        let service_incarnation = generate_service_incarnation()?;
        let mut controls = HashMap::new();
        let workers =
            reconcile_startup_managed_runs(profiles.repository_mut(), &mut controls).await?;
        let project_context = profiles.repository_mut().project_context_snapshot().await?;
        discovery_scheduler
            .replace_project_context(project_context)
            .await?;
        let inner = Arc::new(Mutex::new(ManagedRunInner {
            profiles,
            discovery_backend,
            discovery_scheduler,
            log_root: log_root.to_owned(),
            controls,
            service_incarnation,
        }));
        for worker in workers {
            schedule_stop_worker(Arc::clone(&inner), worker.run_id, worker.operation_id);
        }
        let service = Self {
            inner,
            log_publisher,
            log_range_permits: Arc::new(Semaphore::new(MANAGED_LOG_RANGE_CONCURRENCY)),
            log_readers: Arc::new(StdMutex::new(ManagedLogReaderRegistry::default())),
            log_retention_store,
            log_retention_gate: Arc::new(Mutex::new(())),
            log_start_gate: Mutex::new(()),
        };
        // Retention is best-effort at startup: recovered process ownership is
        // never abandoned because an archived log cannot yet be removed.
        let _ = service.run_log_retention_cleanup(0).await;
        schedule_periodic_log_retention(&service);
        Ok(service)
    }

    pub async fn running_count(&self) -> usize {
        self.inner
            .lock()
            .await
            .controls
            .values()
            .filter(|control| match control {
                PlatformRunControl::Running(process) | PlatformRunControl::Quarantined(process) => {
                    let _ = process.instance_key();
                    true
                }
                PlatformRunControl::Stopping(stop) => {
                    let _ = stop.process.instance_key();
                    true
                }
                _ => false,
            })
            .count()
    }

    pub async fn managed_instance_key(&self, run_id: &str) -> Option<ProcessInstanceKey> {
        match self.inner.lock().await.controls.get(run_id) {
            Some(PlatformRunControl::Running(process))
            | Some(PlatformRunControl::Quarantined(process)) => {
                Some(process.instance_key().clone())
            }
            Some(PlatformRunControl::Stopping(stop)) => Some(stop.process.instance_key().clone()),
            _ => None,
        }
    }

    /// Resolves the durable control association for one complete process
    /// identity. Live control evidence and SQLite identity must never disagree;
    /// a mismatch fails closed instead of presenting the process as external.
    pub async fn get_process_details(
        &self,
        request: &GetProcessDetailsRequest,
    ) -> Result<GetProcessDetailsResponse, AppError> {
        lifecycle::validate_get_process_details_request(request)?;
        let request = request.clone();
        let inner = Arc::clone(&self.inner);
        join_supervisor_task(tokio::spawn(async move {
            let mut inner = inner.lock().await;
            resolve_process_details(&mut inner, &request).await
        }))
        .await
    }

    pub async fn managed_run_id_for_instance_key(
        &self,
        instance_key: &ProcessInstanceKey,
    ) -> Result<Option<String>, AppError> {
        let response = self
            .get_process_details(&GetProcessDetailsRequest {
                process_instance_key: instance_key.clone(),
            })
            .await?;
        Ok(match response.control {
            ProcessControl::External => None,
            ProcessControl::Managed { run, .. } => Some(run.run_id),
        })
    }

    pub async fn get_log_range(
        &self,
        request: &GetManagedLogRangeRequest,
    ) -> Result<GetManagedLogRangeResponse, AppError> {
        lifecycle::validate_get_managed_log_range_request(request)?;
        let permit = Arc::clone(&self.log_range_permits)
            .acquire_owned()
            .await
            .map_err(|_| AppError::new(ErrorCode::Internal, "managed log reader is unavailable"))?;
        let registered_reader = self
            .log_readers
            .lock()
            .map_err(|_| managed_log_registry_error())?
            .get(&request.run_id);
        let (control_reader, log_directory) = {
            let mut inner = self.inner.lock().await;
            let control_reader = inner
                .controls
                .get(&request.run_id)
                .and_then(control_log_range_reader);
            let record = inner
                .profiles
                .repository_mut()
                .managed_run(&request.run_id)
                .await?;
            if record.logs_deletion_started_at.is_some() || record.logs_deleted_at.is_some() {
                return Err(managed_log_retention_expired_error());
            }
            if record.log_redaction_version != CURRENT_MANAGED_LOG_REDACTION_VERSION {
                return Err(managed_log_redaction_provenance_error());
            }
            let expected_log_directory = inner.log_root.join(&request.run_id);
            if Path::new(&record.log_directory) != expected_log_directory {
                let mut error = AppError::new(
                    ErrorCode::StorageError,
                    "managed run log directory does not match its Supervisor-owned identity",
                );
                error
                    .details
                    .insert("stage".into(), "ValidateManagedLogDirectory".into());
                return Err(error);
            }
            (control_reader, expected_log_directory)
        };
        let available_reader =
            registered_reader.or_else(|| control_reader.map(|reader| (reader, false)));
        if available_reader.is_none() && request.starting_byte_offset.is_some() {
            return Err(stale_managed_log_offset_error());
        }
        let run_id = request.run_id.clone();
        let stream = request.stream;
        let offset = request.starting_byte_offset;
        let maximum_bytes = request.maximum_bytes as usize;
        let log_readers = Arc::clone(&self.log_readers);
        let range_run_id = run_id.clone();
        let (read, historical) = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let (reader, historical) = match available_reader {
                Some(reader) => reader,
                None => {
                    let reader = ManagedRunLogRangeReader::open_existing(
                        log_directory,
                        LogLimits::default(),
                    )
                    .map_err(managed_log_read_error)?;
                    log_readers
                        .lock()
                        .map_err(|_| managed_log_registry_error())?
                        .insert_historical(&range_run_id, reader)?
                }
            };
            let read = reader
                .read_range(logging_stream(stream), offset, maximum_bytes)
                .map_err(managed_log_read_error)?;
            Ok::<_, AppError>((read, historical))
        })
        .await
        .map_err(|_| AppError::new(ErrorCode::Internal, "managed log range worker failed"))??;
        let response = GetManagedLogRangeResponse {
            run_id,
            stream,
            observed_sequence: read.observed_sequence,
            first_available_byte_offset: read.first_available,
            first_byte_offset: read.first,
            next_byte_offset: read.next,
            stream_end_byte_offset: read.end,
            text: read.text,
            has_more: read.has_more,
            complete: read.complete,
            end_of_file: read.end_of_file || historical,
            io_status_known: read.io_status_known,
            disk_error: read.disk_error.map(managed_log_io_error_kind),
            read_error: read.read_error.map(managed_log_io_error_kind),
            text_status: managed_log_text_status(read.text_status),
        };
        lifecycle::validate_get_managed_log_range_response(&response)?;
        Ok(response)
    }

    pub async fn cleanup_pending_count(&self) -> usize {
        self.inner
            .lock()
            .await
            .controls
            .values()
            .filter(|control| match control {
                PlatformRunControl::CleanupPending(error) => error.cleanup_pending(),
                _ => false,
            })
            .count()
    }

    pub async fn retry_pending_cleanup(&self) -> usize {
        let inner = Arc::clone(&self.inner);
        let task = tokio::spawn(async move {
            let mut inner = inner.lock().await;
            retry_pending_controls(&mut inner.controls)
        });
        task.await.unwrap_or_default()
    }

    pub async fn list_projects(
        &self,
        request: &ListProjectsRequest,
    ) -> Result<ListProjectsResponse, AppError> {
        lifecycle::validate_list_projects_request(request)?;
        let request = request.clone();
        let inner = Arc::clone(&self.inner);
        join_supervisor_task(tokio::spawn(async move {
            inner
                .lock()
                .await
                .profiles
                .repository_mut()
                .list_projects(&request)
                .await
        }))
        .await
    }

    pub async fn save_project(
        &self,
        operation_id: String,
        request: SaveProjectRequest,
    ) -> Result<ProjectSummary, AppError> {
        lifecycle::validate_save_project_request(&request)?;
        let inner = Arc::clone(&self.inner);
        join_supervisor_task(tokio::spawn(async move {
            let backend = {
                let mut inner = inner.lock().await;
                if let Some(project) = inner
                    .profiles
                    .repository_mut()
                    .replay_catalog_mutation(
                        &operation_id,
                        PROJECT_SAVE,
                        &request,
                        lifecycle::validate_project_summary,
                    )
                    .await?
                {
                    return Ok(project);
                }
                Arc::clone(&inner.discovery_backend)
            };
            let requested_root = match &request {
                SaveProjectRequest::Create(CreateProjectRequest { input }) => {
                    input.root_directory.clone()
                }
                SaveProjectRequest::Update(UpdateProjectRequest { input, .. }) => {
                    input.root_directory.clone()
                }
            };
            let trusted_root = backend
                .normalize_project_root(requested_root, CancellationToken::new())
                .await?;
            let mut inner = inner.lock().await;
            if let Some(project) = inner
                .profiles
                .repository_mut()
                .replay_catalog_mutation(
                    &operation_id,
                    PROJECT_SAVE,
                    &request,
                    lifecycle::validate_project_summary,
                )
                .await?
            {
                return Ok(project);
            }
            let discovery_scheduler = inner.discovery_scheduler.clone();
            let old_context = inner
                .profiles
                .repository_mut()
                .project_context_snapshot()
                .await?;
            let server_project = match &request {
                SaveProjectRequest::Create(CreateProjectRequest { input }) => {
                    let project_id = allocate_project_id(inner.profiles.repository_mut()).await?;
                    let timestamp = next_canonical_timestamp(None)?;
                    ProjectSummary {
                        id: project_id,
                        input: domain::ProjectInput {
                            name: input.name.clone(),
                            root_directory: trusted_root.canonical_root_directory().to_owned(),
                        },
                        created_at: timestamp.clone(),
                        updated_at: timestamp,
                    }
                }
                SaveProjectRequest::Update(UpdateProjectRequest {
                    project_id,
                    expected_updated_at,
                    input,
                }) => {
                    let current = inner
                        .profiles
                        .repository_mut()
                        .project_summary(project_id)
                        .await?;
                    require_catalog_version(
                        "project",
                        "projectId",
                        project_id,
                        expected_updated_at,
                        &current.updated_at,
                    )?;
                    ProjectSummary {
                        id: current.id,
                        input: domain::ProjectInput {
                            name: input.name.clone(),
                            root_directory: trusted_root.canonical_root_directory().to_owned(),
                        },
                        created_at: current.created_at,
                        updated_at: next_canonical_timestamp(Some(&current.updated_at))?,
                    }
                }
            };
            lifecycle::validate_project_summary(&server_project)?;
            let mut prospective = old_context.clone();
            replace_project_in_context(&mut prospective, &server_project, &trusted_root)?;
            validate_project_context(&prospective)?;
            let repository = inner.profiles.repository_mut();
            let prepared = repository
                .prepare_save_project(
                    &operation_id,
                    PROJECT_SAVE,
                    &request,
                    &server_project,
                    &trusted_root,
                )
                .await?;
            publish_and_commit_catalog_mutation(
                repository,
                &discovery_scheduler,
                prospective,
                prepared,
            )
            .await
        }))
        .await
    }

    pub async fn delete_project(
        &self,
        operation_id: String,
        request: DeleteProjectRequest,
    ) -> Result<DeleteProjectResponse, AppError> {
        lifecycle::validate_delete_project_request(&request)?;
        let inner = Arc::clone(&self.inner);
        join_supervisor_task(tokio::spawn(async move {
            let mut inner = inner.lock().await;
            if let Some(response) = inner
                .profiles
                .repository_mut()
                .replay_catalog_mutation(
                    &operation_id,
                    PROJECT_DELETE,
                    &request,
                    lifecycle::validate_delete_project_response,
                )
                .await?
            {
                return Ok(response);
            }
            let discovery_scheduler = inner.discovery_scheduler.clone();
            let current = inner
                .profiles
                .repository_mut()
                .project_summary(&request.project_id)
                .await?;
            require_catalog_version(
                "project",
                "projectId",
                &request.project_id,
                &request.expected_updated_at,
                &current.updated_at,
            )?;
            let old_context = inner
                .profiles
                .repository_mut()
                .project_context_snapshot()
                .await?;
            let recorded_at = current_timestamp()?;
            let repository = inner.profiles.repository_mut();
            let prepared = repository
                .prepare_delete_project_if_version(
                    &operation_id,
                    PROJECT_DELETE,
                    &request,
                    &recorded_at,
                )
                .await?;
            let mut prospective = old_context.clone();
            let prospective_result =
                remove_project_from_context(&mut prospective, &request.project_id)
                    .and_then(|()| validate_project_context(&prospective));
            if let Err(error) = prospective_result {
                return Err(rollback_unpublished_catalog_mutation(
                    repository,
                    &discovery_scheduler,
                    prepared,
                    error,
                )
                .await);
            }
            publish_and_commit_catalog_mutation(
                repository,
                &discovery_scheduler,
                prospective,
                prepared,
            )
            .await
        }))
        .await
    }

    pub async fn list_classification_rules(
        &self,
        request: &ListClassificationRulesRequest,
    ) -> Result<ListClassificationRulesResponse, AppError> {
        lifecycle::validate_list_classification_rules_request(request)?;
        let request = request.clone();
        let inner = Arc::clone(&self.inner);
        join_supervisor_task(tokio::spawn(async move {
            inner
                .lock()
                .await
                .profiles
                .repository_mut()
                .list_classification_rules(&request)
                .await
        }))
        .await
    }

    pub async fn save_classification_rule(
        &self,
        operation_id: String,
        request: SaveClassificationRuleRequest,
    ) -> Result<ClassificationRuleSummary, AppError> {
        lifecycle::validate_save_classification_rule_request(&request)?;
        let inner = Arc::clone(&self.inner);
        join_supervisor_task(tokio::spawn(async move {
            let mut inner = inner.lock().await;
            if let Some(rule) = inner
                .profiles
                .repository_mut()
                .replay_catalog_mutation(
                    &operation_id,
                    RULE_SAVE,
                    &request,
                    lifecycle::validate_classification_rule_summary,
                )
                .await?
            {
                return Ok(rule);
            }
            let discovery_scheduler = inner.discovery_scheduler.clone();
            let old_context = inner
                .profiles
                .repository_mut()
                .project_context_snapshot()
                .await?;
            let server_rule = match &request {
                SaveClassificationRuleRequest::Create(CreateClassificationRuleRequest {
                    input,
                }) => {
                    let rule_id =
                        allocate_classification_rule_id(inner.profiles.repository_mut()).await?;
                    let timestamp = next_canonical_timestamp(None)?;
                    ClassificationRuleSummary {
                        id: rule_id,
                        input: input.clone(),
                        created_at: timestamp.clone(),
                        updated_at: timestamp,
                    }
                }
                SaveClassificationRuleRequest::Update(UpdateClassificationRuleRequest {
                    rule_id,
                    expected_updated_at,
                    input,
                }) => {
                    let current = inner
                        .profiles
                        .repository_mut()
                        .classification_rule_summary(rule_id)
                        .await?;
                    require_catalog_version(
                        "classificationRule",
                        "ruleId",
                        rule_id,
                        expected_updated_at,
                        &current.updated_at,
                    )?;
                    ClassificationRuleSummary {
                        id: current.id,
                        input: input.clone(),
                        created_at: current.created_at,
                        updated_at: next_canonical_timestamp(Some(&current.updated_at))?,
                    }
                }
            };
            lifecycle::validate_classification_rule_summary(&server_rule)?;
            let mut prospective = old_context.clone();
            replace_rule_in_context(&mut prospective, &server_rule)?;
            validate_project_context(&prospective)?;
            let repository = inner.profiles.repository_mut();
            let prepared = repository
                .prepare_save_classification_rule(&operation_id, RULE_SAVE, &request, &server_rule)
                .await?;
            publish_and_commit_catalog_mutation(
                repository,
                &discovery_scheduler,
                prospective,
                prepared,
            )
            .await
        }))
        .await
    }

    pub async fn delete_classification_rule(
        &self,
        operation_id: String,
        request: DeleteClassificationRuleRequest,
    ) -> Result<DeleteClassificationRuleResponse, AppError> {
        lifecycle::validate_delete_classification_rule_request(&request)?;
        let inner = Arc::clone(&self.inner);
        join_supervisor_task(tokio::spawn(async move {
            let mut inner = inner.lock().await;
            if let Some(response) = inner
                .profiles
                .repository_mut()
                .replay_catalog_mutation(
                    &operation_id,
                    RULE_DELETE,
                    &request,
                    lifecycle::validate_delete_classification_rule_response,
                )
                .await?
            {
                return Ok(response);
            }
            let discovery_scheduler = inner.discovery_scheduler.clone();
            let current = inner
                .profiles
                .repository_mut()
                .classification_rule_summary(&request.rule_id)
                .await?;
            require_catalog_version(
                "classificationRule",
                "ruleId",
                &request.rule_id,
                &request.expected_updated_at,
                &current.updated_at,
            )?;
            let old_context = inner
                .profiles
                .repository_mut()
                .project_context_snapshot()
                .await?;
            let mut prospective = old_context.clone();
            remove_rule_from_context(&mut prospective, &request.rule_id)?;
            validate_project_context(&prospective)?;
            let recorded_at = current_timestamp()?;
            let repository = inner.profiles.repository_mut();
            let prepared = repository
                .prepare_delete_classification_rule_if_version(
                    &operation_id,
                    RULE_DELETE,
                    &request,
                    &recorded_at,
                )
                .await?;
            publish_and_commit_catalog_mutation(
                repository,
                &discovery_scheduler,
                prospective,
                prepared,
            )
            .await
        }))
        .await
    }

    pub async fn list_run_history(
        &self,
        request: &ListRunHistoryRequest,
    ) -> Result<ListRunHistoryResponse, AppError> {
        lifecycle::validate_list_run_history_request(request)?;
        let request = request.clone();
        let inner = Arc::clone(&self.inner);
        join_supervisor_task(tokio::spawn(async move {
            inner
                .lock()
                .await
                .profiles
                .repository_mut()
                .run_history(&request)
                .await
        }))
        .await
    }

    /// Returns only fixed aggregate counts. The storage contract cannot
    /// represent commands, environment values, credentials, paths, log text,
    /// row identities, or user-authored database content.
    pub async fn diagnostic_database_summary(&self) -> Result<DiagnosticDatabaseSummary, AppError> {
        let inner = Arc::clone(&self.inner);
        join_supervisor_task(tokio::spawn(async move {
            inner
                .lock()
                .await
                .profiles
                .repository_mut()
                .diagnostic_database_summary()
                .await
        }))
        .await
    }

    pub async fn list_profiles(
        &self,
        request: &ListLaunchProfilesRequest,
    ) -> Result<ListLaunchProfilesResponse, AppError> {
        lifecycle::validate_list_launch_profiles_request(request)?;
        let request = request.clone();
        let inner = Arc::clone(&self.inner);
        join_supervisor_task(tokio::spawn(async move {
            inner.lock().await.profiles.list(&request).await
        }))
        .await
    }

    /// Saves one authenticated wire request while keeping identity and version
    /// timestamps entirely Supervisor-owned. Write-only secret values are
    /// consumed by `ProfileService` and cannot appear in the returned profile.
    pub async fn save_profile_from_wire(
        &self,
        operation_id: String,
        request: SaveLaunchProfileWithSecretsRequest,
    ) -> Result<LaunchProfile, AppError> {
        lifecycle::validate_save_launch_profile_with_secrets_request(&request)?;
        let inner = Arc::clone(&self.inner);
        join_supervisor_task(tokio::spawn(async move {
            let mut inner = inner.lock().await;
            if let Some(profile) = inner
                .profiles
                .replay_save(&operation_id, PROFILE_SAVE, &request)
                .await?
            {
                return Ok(profile);
            }
            let server_profile = match &request.request {
                SaveLaunchProfileRequest::Create(CreateLaunchProfileRequest { input }) => {
                    let profile_id = allocate_launch_profile_id(&inner.profiles).await?;
                    let timestamp = next_canonical_timestamp(None)?;
                    LaunchProfile {
                        id: profile_id,
                        input: input.clone(),
                        created_at: timestamp.clone(),
                        updated_at: timestamp,
                    }
                }
                SaveLaunchProfileRequest::Update(UpdateLaunchProfileRequest {
                    profile_id,
                    input,
                    ..
                }) => {
                    let current = inner.profiles.profile(profile_id).await?;
                    LaunchProfile {
                        id: current.id,
                        input: input.clone(),
                        created_at: current.created_at,
                        updated_at: next_canonical_timestamp(Some(&current.updated_at))?,
                    }
                }
            };
            let mutation = inner
                .profiles
                .save(&operation_id, PROFILE_SAVE, request, server_profile)
                .await?;
            let (profile, _credential_cleanup) = mutation.into_parts();
            Ok(profile)
        }))
        .await
    }

    pub async fn delete_profile(
        &self,
        operation_id: String,
        request: DeleteLaunchProfileRequest,
    ) -> Result<DeleteLaunchProfileResponse, AppError> {
        lifecycle::validate_delete_launch_profile_request(&request)?;
        let inner = Arc::clone(&self.inner);
        join_supervisor_task(tokio::spawn(async move {
            let mut inner = inner.lock().await;
            if let Some(response) = inner
                .profiles
                .replay_delete(&operation_id, PROFILE_DELETE, &request)
                .await?
            {
                return Ok(response);
            }
            let recorded_at = current_timestamp()?;
            let mutation = inner
                .profiles
                .delete(&operation_id, PROFILE_DELETE, &request, &recorded_at)
                .await?;
            let (response, _credential_cleanup) = mutation.into_parts();
            lifecycle::validate_delete_launch_profile_response(&response)?;
            Ok(response)
        }))
        .await
    }

    /// Builds a read-only preview from a process-local trusted context. The
    /// context is borrowed and can never be supplied or reconstructed by IPC.
    pub fn preview_profile(
        &self,
        context: &ExecutionPreviewContext,
        request: &ExecutionPreviewRequest,
    ) -> Result<FinalExecutionPreview, AppError> {
        if context.platform() != active_platform() {
            return Err(AppError::new(
                ErrorCode::NotSupported,
                "launch profile preview context is not available for this platform",
            ));
        }
        lifecycle::build_execution_preview(context, request)
    }

    pub async fn drain_credential_cleanup(&self) -> CredentialCleanupStatus {
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move { inner.lock().await.profiles.drain_credential_cleanup().await })
            .await
            .unwrap_or(CredentialCleanupStatus::Pending { acknowledged: 0 })
    }

    async fn run_log_retention_cleanup(
        &self,
        additional_active_reservations: usize,
    ) -> Result<(), AppError> {
        run_managed_log_retention_cleanup(
            Arc::clone(&self.inner),
            Arc::clone(&self.log_readers),
            Arc::clone(&self.log_range_permits),
            self.log_retention_store.clone(),
            Arc::clone(&self.log_retention_gate),
            additional_active_reservations,
        )
        .await
    }

    pub async fn start(
        &self,
        request: &StartManagedRunRequest,
        context: &ExecutionPreviewContext,
    ) -> Result<StartManagedRunResult, AppError> {
        lifecycle::validate_start_managed_run_request(request)?;
        if context.platform() != active_platform() {
            return Err(AppError::new(
                ErrorCode::NotSupported,
                "managed run context is not available for this platform",
            ));
        }
        let _start_gate = self.log_start_gate.lock().await;
        if self.inner.lock().await.controls.len() >= MAX_ACTIVE_MANAGED_LOG_RUNS {
            return Err(managed_log_active_capacity_error());
        }
        self.run_log_retention_cleanup(1).await?;
        let request = request.clone();
        let context = context.clone();
        let inner = Arc::clone(&self.inner);
        let retry_inner = Arc::clone(&self.inner);
        let monitor_inner = Arc::clone(&self.inner);
        let log_publisher = self.log_publisher.clone();
        let log_readers = Arc::clone(&self.log_readers);
        join_supervisor_task(tokio::spawn(async move {
            let (result, terminal_run_id) = {
                let mut inner = inner.lock().await;
                if inner.controls.len() >= MAX_ACTIVE_MANAGED_LOG_RUNS {
                    return Err(managed_log_active_capacity_error());
                }
                let log_root = inner.log_root.clone();
                let ManagedRunInner {
                    profiles, controls, ..
                } = &mut *inner;
                let (repository, credential_store) = profiles.launch_resources();
                let result = start_platform_run(
                    repository,
                    credential_store,
                    controls,
                    &log_root,
                    &log_publisher,
                    &log_readers,
                    &request,
                    &context,
                )
                .await;
                let terminal_run_id = result.as_ref().ok().and_then(|result| {
                    controls
                        .get(&result.run.run_id)
                        .and_then(|control| match control {
                            PlatformRunControl::Running(process) if process.is_terminal() => {
                                Some(result.run.run_id.clone())
                            }
                            _ => None,
                        })
                });
                (result, terminal_run_id)
            };
            if let Some(run_id) = terminal_run_id {
                schedule_terminal_exit_monitor(monitor_inner, run_id);
            }
            if result.as_ref().err().is_some_and(|error| {
                error
                    .details
                    .get("cleanupPending")
                    .is_some_and(|value| value == "true")
            }) {
                schedule_cleanup_retries(retry_inner);
            }
            result
        }))
        .await
    }

    pub async fn stop(
        &self,
        operation_id: &str,
        request: &StopManagedRunRequest,
    ) -> Result<ManagedStopOperationResult, AppError> {
        lifecycle::validate_managed_stop_operation_id(operation_id)?;
        lifecycle::validate_stop_managed_run_request(request)?;
        self.request_stop(
            operation_id.to_owned(),
            ManagedStopCommand::Graceful(request.clone()),
        )
        .await
    }

    pub async fn get_exit_impact(
        &self,
        request: &GetExitImpactRequest,
    ) -> Result<ExitImpactSummary, AppError> {
        lifecycle::validate_get_exit_impact_request(request)?;
        let inner = Arc::clone(&self.inner);
        join_supervisor_task(tokio::spawn(async move {
            let mut inner = inner.lock().await;
            authoritative_exit_impact(&mut inner).await
        }))
        .await
    }

    pub async fn stop_all_for_exit(
        &self,
        operation_id: &str,
        request: &StopAllForExitRequest,
    ) -> Result<StopAllForExitResult, AppError> {
        lifecycle::validate_managed_stop_operation_id(operation_id)?;
        lifecycle::validate_stop_all_for_exit_request(request)?;
        let request_sha256 = managed_exit_request_sha256(request)?;
        let operation_id = operation_id.to_owned();
        let request = request.clone();
        let inner = Arc::clone(&self.inner);
        let operation = join_supervisor_task(tokio::spawn(async move {
            let mut inner = inner.lock().await;
            load_or_prepare_managed_exit_operation(
                &mut inner,
                operation_id,
                request,
                request_sha256,
            )
            .await
        }))
        .await?;

        let before_convergence = self.get_exit_impact(&GetExitImpactRequest {}).await?;
        for member in &operation.members {
            if member.action != ManagedExitMemberAction::GracefulRequested {
                continue;
            }
            let stop_operation_id = member
                .stop_operation_id
                .as_deref()
                .expect("validated graceful exit member operation ID");
            if !exit_impact_needs_child_stop(
                &before_convergence.runs,
                &member.run_id,
                stop_operation_id,
            ) {
                continue;
            }
            let command = ManagedStopCommand::Graceful(StopManagedRunRequest {
                run_id: member.run_id.clone(),
            });
            if let Err(error) = self
                .request_stop(stop_operation_id.to_owned(), command)
                .await
            {
                if error.code == ErrorCode::AlreadyExited {
                    continue;
                }
                if error.code == ErrorCode::Conflict {
                    let latest = self.get_exit_impact(&GetExitImpactRequest {}).await?;
                    if !exit_impact_needs_child_stop(
                        &latest.runs,
                        &member.run_id,
                        stop_operation_id,
                    ) {
                        continue;
                    }
                }
                return Err(error);
            }
        }

        let current = self.get_exit_impact(&GetExitImpactRequest {}).await?;
        project_stop_all_for_exit_result(&operation, &current)
    }

    pub async fn force_stop(
        &self,
        operation_id: &str,
        request: &ForceStopManagedRunRequest,
    ) -> Result<ManagedStopOperationResult, AppError> {
        lifecycle::validate_managed_stop_operation_id(operation_id)?;
        lifecycle::validate_force_stop_managed_run_request(request)?;
        self.request_stop(
            operation_id.to_owned(),
            ManagedStopCommand::Force(request.clone()),
        )
        .await
    }

    async fn request_stop(
        &self,
        operation_id: String,
        command: ManagedStopCommand,
    ) -> Result<ManagedStopOperationResult, AppError> {
        let inner = Arc::clone(&self.inner);
        join_supervisor_task(tokio::spawn(async move {
            begin_supervisor_stop(inner, operation_id, command).await
        }))
        .await
    }
}

async fn authoritative_exit_impact(
    inner: &mut ManagedRunInner,
) -> Result<ExitImpactSummary, AppError> {
    let ManagedRunInner {
        profiles,
        controls,
        service_incarnation,
        ..
    } = inner;
    let durable_runs = profiles.repository_mut().managed_exit_active_runs().await?;
    build_authoritative_exit_impact(controls, &durable_runs, service_incarnation)
}

fn build_authoritative_exit_impact(
    controls: &HashMap<String, PlatformRunControl>,
    durable_runs: &[ManagedExitActiveRun],
    service_incarnation: &[u8; 32],
) -> Result<ExitImpactSummary, AppError> {
    let durable_by_run_id = durable_runs
        .iter()
        .map(|active| (active.run.id.as_str(), active))
        .collect::<HashMap<_, _>>();
    let mut run_ids = BTreeSet::new();
    run_ids.extend(controls.keys().map(String::as_str));
    run_ids.extend(durable_runs.iter().map(|active| active.run.id.as_str()));
    if run_ids.len() > MAX_MANAGED_EXIT_ACTIVE_RUNS {
        return Err(managed_exit_active_capacity_error(run_ids.len()));
    }

    let runs = run_ids
        .into_iter()
        .map(|run_id| {
            project_authoritative_exit_impact(
                run_id,
                controls.get(run_id),
                durable_by_run_id.get(run_id).copied(),
            )
        })
        .collect::<Vec<_>>();
    let assessment_id = managed_exit_assessment_id(service_incarnation, &runs)?;
    let summary = ExitImpactSummary {
        assessment_id,
        runs,
    };
    lifecycle::validate_exit_impact_summary(&summary)?;
    Ok(summary)
}

fn project_authoritative_exit_impact(
    run_id: &str,
    control: Option<&PlatformRunControl>,
    durable: Option<&ManagedExitActiveRun>,
) -> ExitRunImpact {
    match control {
        Some(PlatformRunControl::Quarantined(_)) => ExitRunImpact::Retained {
            run_id: run_id.to_owned(),
            reason: ExitRetainedReason::Quarantined,
        },
        Some(PlatformRunControl::CleanupPending(_)) => ExitRunImpact::Retained {
            run_id: run_id.to_owned(),
            reason: ExitRetainedReason::CleanupPending,
        },
        None => ExitRunImpact::Retained {
            run_id: run_id.to_owned(),
            reason: ExitRetainedReason::DurableOnly,
        },
        Some(control)
            if durable.is_some_and(|durable| exit_control_matches_durable(control, durable)) =>
        {
            project_coherent_exit_control(run_id, control, durable.expect("matched durable run"))
        }
        Some(_) => ExitRunImpact::Retained {
            run_id: run_id.to_owned(),
            reason: ExitRetainedReason::ControlMismatch,
        },
    }
}

fn project_coherent_exit_control(
    run_id: &str,
    control: &PlatformRunControl,
    durable: &ManagedExitActiveRun,
) -> ExitRunImpact {
    match control {
        PlatformRunControl::StartingIntent
        | PlatformRunControl::Suspended(_)
        | PlatformRunControl::RunningUncommitted(_) => ExitRunImpact::Launching {
            run_id: run_id.to_owned(),
        },
        PlatformRunControl::Running(_) => ExitRunImpact::Running {
            run_id: run_id.to_owned(),
        },
        PlatformRunControl::Stopping(stop) => match stop.kind {
            ManagedStopKind::Graceful
                if durable
                    .active_stop
                    .as_ref()
                    .is_some_and(|active| active.status == ManagedStopStatus::TimedOut) =>
            {
                ExitRunImpact::GracefulTimedOut {
                    run_id: run_id.to_owned(),
                    operation_id: stop.operation_id.clone(),
                }
            }
            ManagedStopKind::Graceful => ExitRunImpact::GracefulStopping {
                run_id: run_id.to_owned(),
                operation_id: stop.operation_id.clone(),
            },
            ManagedStopKind::Force => ExitRunImpact::ForceStopping {
                run_id: run_id.to_owned(),
                operation_id: stop.operation_id.clone(),
            },
        },
        PlatformRunControl::Quarantined(_) | PlatformRunControl::CleanupPending(_) => {
            unreachable!("retained controls are projected before coherence checks")
        }
    }
}

fn exit_control_matches_durable(
    control: &PlatformRunControl,
    durable: &ManagedExitActiveRun,
) -> bool {
    match control {
        PlatformRunControl::StartingIntent => {
            durable.run.state == RunState::Starting
                && durable.run.process_instance_key.is_none()
                && durable.run.process_group_id.is_none()
                && durable.active_stop.is_none()
        }
        PlatformRunControl::Suspended(process) => {
            durable.run.state == RunState::Starting
                && durable.active_stop.is_none()
                && durable.run.process_instance_key.as_ref() == Some(process.instance_key())
        }
        PlatformRunControl::RunningUncommitted(process) => {
            matches!(durable.run.state, RunState::Starting | RunState::Running)
                && durable.active_stop.is_none()
                && durable.run.process_instance_key.as_ref() == Some(process.instance_key())
        }
        PlatformRunControl::Running(process) => {
            matches!(durable.run.state, RunState::Running | RunState::Recovered)
                && durable.active_stop.is_none()
                && platform_control_matches_record(process, &durable.run)
        }
        PlatformRunControl::Stopping(stop) => durable.active_stop.as_ref().is_some_and(|active| {
            active.operation_id == stop.operation_id
                && active.kind == stop.kind
                && managed_stop_phase_matches_result(stop.phase, active.status)
                && platform_control_matches_record(&stop.process, &durable.run)
        }),
        PlatformRunControl::Quarantined(_) | PlatformRunControl::CleanupPending(_) => false,
    }
}

fn managed_stop_phase_matches_result(
    phase: ManagedStopControlPhase,
    status: ManagedStopStatus,
) -> bool {
    match phase {
        ManagedStopControlPhase::Requested => status == ManagedStopStatus::Requested,
        ManagedStopControlPhase::SignalPending | ManagedStopControlPhase::SignalAttempted => {
            status == ManagedStopStatus::SignalPending
        }
        ManagedStopControlPhase::Monitoring => status == ManagedStopStatus::InProgress,
        ManagedStopControlPhase::TimedOut => status == ManagedStopStatus::TimedOut,
        ManagedStopControlPhase::CompletionPending(_) => matches!(
            status,
            ManagedStopStatus::Requested
                | ManagedStopStatus::SignalPending
                | ManagedStopStatus::InProgress
                | ManagedStopStatus::TimedOut
        ),
    }
}

#[cfg(windows)]
fn platform_control_matches_record(
    process: &PlatformManagedProcess,
    record: &ManagedRunRecord,
) -> bool {
    record.process_instance_key.as_ref() == Some(process.instance_key())
        && record.process_group_id.is_none()
}

#[cfg(target_os = "macos")]
fn platform_control_matches_record(
    process: &PlatformManagedProcess,
    record: &ManagedRunRecord,
) -> bool {
    record.process_instance_key.as_ref() == Some(process.instance_key())
        && record.process_group_id == Some(process.process_group_id())
}

async fn load_or_prepare_managed_exit_operation(
    inner: &mut ManagedRunInner,
    operation_id: String,
    request: StopAllForExitRequest,
    request_sha256: [u8; 32],
) -> Result<ManagedExitOperation, AppError> {
    if let Some(replay) = inner
        .profiles
        .repository_mut()
        .managed_exit_operation_replay(&operation_id, &request_sha256)
        .await?
    {
        return Ok(replay);
    }

    let impact = authoritative_exit_impact(inner).await?;
    if impact.assessment_id != request.expected_assessment_id {
        return Err(stale_exit_assessment(
            &operation_id,
            &request.expected_assessment_id,
            &impact.assessment_id,
        ));
    }
    let members = impact
        .runs
        .iter()
        .map(|impact| managed_exit_operation_member(&operation_id, impact))
        .collect();
    let operation = ManagedExitOperation {
        operation_id,
        request_sha256,
        assessment_id: impact.assessment_id,
        created_at: current_timestamp()?,
        members,
    };
    inner
        .profiles
        .repository_mut()
        .prepare_managed_exit_operation(&operation)
        .await
}

fn managed_exit_operation_member(
    exit_operation_id: &str,
    impact: &ExitRunImpact,
) -> ManagedExitOperationMember {
    let run_id = exit_run_impact_id(impact).to_owned();
    match impact {
        ExitRunImpact::Launching { .. } | ExitRunImpact::Running { .. } => {
            ManagedExitOperationMember {
                stop_operation_id: Some(managed_exit_child_operation_id(
                    exit_operation_id,
                    &run_id,
                )),
                run_id,
                action: ManagedExitMemberAction::GracefulRequested,
            }
        }
        ExitRunImpact::GracefulStopping { operation_id, .. }
        | ExitRunImpact::GracefulTimedOut { operation_id, .. }
        | ExitRunImpact::ForceStopping { operation_id, .. } => ManagedExitOperationMember {
            run_id,
            action: ManagedExitMemberAction::StopAdopted,
            stop_operation_id: Some(operation_id.clone()),
        },
        ExitRunImpact::Retained { .. } => ManagedExitOperationMember {
            run_id,
            action: ManagedExitMemberAction::None,
            stop_operation_id: None,
        },
    }
}

fn project_stop_all_for_exit_result(
    operation: &ManagedExitOperation,
    current: &ExitImpactSummary,
) -> Result<StopAllForExitResult, AppError> {
    let fixed_run_ids = operation
        .members
        .iter()
        .map(|member| member.run_id.as_str())
        .collect::<HashSet<_>>();
    if current
        .runs
        .iter()
        .any(|impact| !fixed_run_ids.contains(exit_run_impact_id(impact)))
    {
        return Err(managed_exit_membership_changed(operation, current));
    }
    let current_by_run_id = current
        .runs
        .iter()
        .map(|impact| (exit_run_impact_id(impact), impact))
        .collect::<HashMap<_, _>>();
    let members = operation
        .members
        .iter()
        .map(|member| {
            let action = match member.action {
                ManagedExitMemberAction::None => StopAllForExitMemberAction::None,
                ManagedExitMemberAction::GracefulRequested => {
                    StopAllForExitMemberAction::GracefulRequested {
                        operation_id: member
                            .stop_operation_id
                            .clone()
                            .expect("validated graceful exit member operation ID"),
                    }
                }
                ManagedExitMemberAction::StopAdopted => StopAllForExitMemberAction::StopAdopted {
                    operation_id: member
                        .stop_operation_id
                        .clone()
                        .expect("validated adopted exit member operation ID"),
                },
            };
            StopAllForExitMemberResult {
                run_id: member.run_id.clone(),
                action,
                current_impact: current_by_run_id
                    .get(member.run_id.as_str())
                    .map(|impact| (*impact).clone()),
            }
        })
        .collect::<Vec<_>>();
    let status = if members.iter().all(|member| member.current_impact.is_none()) {
        StopAllForExitStatus::Completed
    } else if members.iter().any(|member| {
        member.current_impact.as_ref().is_some_and(|impact| {
            matches!(
                impact,
                ExitRunImpact::Launching { .. }
                    | ExitRunImpact::Running { .. }
                    | ExitRunImpact::GracefulTimedOut { .. }
                    | ExitRunImpact::Retained { .. }
            )
        })
    }) {
        StopAllForExitStatus::Blocked
    } else {
        StopAllForExitStatus::Draining
    };
    let result = StopAllForExitResult {
        operation_id: operation.operation_id.clone(),
        status,
        members,
    };
    lifecycle::validate_stop_all_for_exit_result(&result)?;
    Ok(result)
}

fn exit_impact_needs_child_stop(
    impacts: &[ExitRunImpact],
    run_id: &str,
    child_operation_id: &str,
) -> bool {
    impacts
        .iter()
        .find(|impact| exit_run_impact_id(impact) == run_id)
        .is_some_and(|impact| match impact {
            ExitRunImpact::Running { .. } => true,
            ExitRunImpact::GracefulStopping { operation_id, .. }
            | ExitRunImpact::GracefulTimedOut { operation_id, .. } => {
                operation_id == child_operation_id
            }
            ExitRunImpact::Launching { .. }
            | ExitRunImpact::ForceStopping { .. }
            | ExitRunImpact::Retained { .. } => false,
        })
}

fn exit_run_impact_id(impact: &ExitRunImpact) -> &str {
    match impact {
        ExitRunImpact::Launching { run_id }
        | ExitRunImpact::Running { run_id }
        | ExitRunImpact::GracefulStopping { run_id, .. }
        | ExitRunImpact::GracefulTimedOut { run_id, .. }
        | ExitRunImpact::ForceStopping { run_id, .. }
        | ExitRunImpact::Retained { run_id, .. } => run_id,
    }
}

fn managed_exit_request_sha256(request: &StopAllForExitRequest) -> Result<[u8; 32], AppError> {
    let canonical = serde_json::to_vec(request).map_err(|error| {
        let mut result = AppError::new(
            ErrorCode::Internal,
            "failed to serialize the managed exit request",
        );
        result.details.insert("reason".into(), error.to_string());
        result
    })?;
    Ok(Sha256::digest(canonical).into())
}

fn managed_exit_assessment_id(
    service_incarnation: &[u8; 32],
    runs: &[ExitRunImpact],
) -> Result<String, AppError> {
    let canonical = serde_json::to_vec(runs).map_err(|error| {
        let mut result = AppError::new(
            ErrorCode::Internal,
            "failed to serialize the managed exit assessment",
        );
        result.details.insert("reason".into(), error.to_string());
        result
    })?;
    let mut digest = Sha256::new();
    digest.update(b"magictools.managed-exit-assessment.v1\0");
    digest.update(service_incarnation);
    digest.update(canonical);
    Ok(lowercase_hex(&digest.finalize()))
}

fn managed_exit_child_operation_id(exit_operation_id: &str, run_id: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"magictools.managed-exit-child-stop.v1\0");
    digest.update((exit_operation_id.len() as u64).to_be_bytes());
    digest.update(exit_operation_id.as_bytes());
    digest.update((run_id.len() as u64).to_be_bytes());
    digest.update(run_id.as_bytes());
    format!("exit-stop:{}", lowercase_hex(&digest.finalize()))
}

fn lowercase_hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut result, "{byte:02x}").expect("writing to String cannot fail");
    }
    result
}

fn generate_service_incarnation() -> Result<[u8; 32], AppError> {
    let mut incarnation = [0_u8; 32];
    getrandom::fill(&mut incarnation).map_err(|error| {
        let mut result = AppError::new(
            ErrorCode::PlatformError,
            "failed to generate the Supervisor service incarnation",
        );
        result
            .details
            .insert("stage".into(), "GenerateServiceIncarnation".into());
        result.details.insert("source".into(), error.to_string());
        result
    })?;
    Ok(incarnation)
}

fn stale_exit_assessment(
    operation_id: &str,
    expected_assessment_id: &str,
    current_assessment_id: &str,
) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Conflict,
        "managed exit impact changed before stop confirmation",
    );
    error.retryable = true;
    error.operation_id = Some(operation_id.to_owned());
    error.details.insert(
        "expectedAssessmentId".into(),
        expected_assessment_id.to_owned(),
    );
    error.details.insert(
        "currentAssessmentId".into(),
        current_assessment_id.to_owned(),
    );
    error
}

fn managed_exit_membership_changed(
    operation: &ManagedExitOperation,
    current: &ExitImpactSummary,
) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Conflict,
        "managed exit impact gained a run outside the fixed stop membership",
    );
    error.retryable = true;
    error.operation_id = Some(operation.operation_id.clone());
    error.details.insert(
        "reason".into(),
        "request a fresh exit assessment and use a new operation ID".into(),
    );
    error
        .details
        .insert("currentAssessmentId".into(), current.assessment_id.clone());
    error
}

fn managed_exit_active_capacity_error(observed: usize) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Conflict,
        "managed exit active-run capacity is exhausted",
    );
    error.retryable = true;
    error.details.insert(
        "maximumActiveRuns".into(),
        MAX_MANAGED_EXIT_ACTIVE_RUNS.to_string(),
    );
    error
        .details
        .insert("observedActiveRuns".into(), observed.to_string());
    error
}

async fn resolve_process_details(
    inner: &mut ManagedRunInner,
    request: &GetProcessDetailsRequest,
) -> Result<GetProcessDetailsResponse, AppError> {
    let instance_key = &request.process_instance_key;
    let mut live_run_id: Option<String> = None;
    for (run_id, control) in &inner.controls {
        if control_instance_key(control) != Some(instance_key) {
            continue;
        }
        if let Some(existing) = &live_run_id {
            return Err(process_control_conflict(
                instance_key,
                Some(existing),
                Some(run_id),
                "multiple live controls claim the same process identity",
            ));
        }
        live_run_id = Some(run_id.clone());
    }

    let repository = inner.profiles.repository_mut();
    let durable = repository
        .managed_run_by_process_instance_key(instance_key)
        .await?;
    let control = match (live_run_id.as_deref(), durable) {
        (None, None) => ProcessControl::External,
        (Some(live_run_id), None) => {
            return Err(process_control_conflict(
                instance_key,
                Some(live_run_id),
                None,
                "live control has no durable run identity",
            ));
        }
        (Some(live_run_id), Some(record)) if live_run_id != record.id => {
            return Err(process_control_conflict(
                instance_key,
                Some(live_run_id),
                Some(&record.id),
                "live and durable run identities disagree",
            ));
        }
        (_, Some(record)) => {
            let run = projected_managed_run_summary(&record)?;
            let active_stop = repository.active_managed_stop_for_run(&record.id).await?;
            ProcessControl::Managed { run, active_stop }
        }
    };
    let response = GetProcessDetailsResponse {
        process_instance_key: instance_key.clone(),
        control,
    };
    lifecycle::validate_get_process_details_response(&response)?;
    Ok(response)
}

fn control_instance_key(control: &PlatformRunControl) -> Option<&ProcessInstanceKey> {
    match control {
        PlatformRunControl::Suspended(process) => Some(process.instance_key()),
        PlatformRunControl::RunningUncommitted(process) => Some(process.instance_key()),
        PlatformRunControl::Running(process) | PlatformRunControl::Quarantined(process) => {
            Some(process.instance_key())
        }
        PlatformRunControl::Stopping(stop) => Some(stop.process.instance_key()),
        PlatformRunControl::CleanupPending(error) => error.process_instance_key(),
        PlatformRunControl::StartingIntent => None,
    }
}

fn projected_managed_run_summary(record: &ManagedRunRecord) -> Result<ManagedRunSummary, AppError> {
    let summary = ManagedRunSummary {
        run_id: record.id.clone(),
        profile_id: record.profile_snapshot.id.clone(),
        profile_updated_at: record.profile_snapshot.updated_at.clone(),
        state: record.state,
        process_instance_key: record.process_instance_key.clone(),
        process_group_id: summary_process_group_id(record)?,
        started_at: record.started_at.clone(),
        updated_at: record.updated_at.clone(),
        ended_at: record.ended_at.clone(),
    };
    lifecycle::validate_managed_run_summary(&summary)?;
    Ok(summary)
}

fn process_control_conflict(
    instance_key: &ProcessInstanceKey,
    live_run_id: Option<&str>,
    durable_run_id: Option<&str>,
    reason: &'static str,
) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Conflict,
        "managed process control evidence is inconsistent",
    );
    error
        .details
        .insert("pid".into(), instance_key.pid.to_string());
    if let Some(run_id) = live_run_id {
        error.details.insert("liveRunId".into(), run_id.into());
    }
    if let Some(run_id) = durable_run_id {
        error.details.insert("durableRunId".into(), run_id.into());
    }
    error.details.insert("reason".into(), reason.into());
    error
}

struct InspectedRetentionCandidate {
    candidate: ManagedRunLogRetentionCandidate,
    reserved_bytes: u64,
    missing: bool,
}

enum RetentionDeleteOutcome {
    Deleted,
    Protected,
    StateChanged,
}

struct RetentionCandidateProtection {
    controlled: bool,
    active_reader: bool,
}

fn schedule_periodic_log_retention(service: &ManagedRunService) {
    let inner = Arc::downgrade(&service.inner);
    let readers = Arc::downgrade(&service.log_readers);
    let permits = Arc::downgrade(&service.log_range_permits);
    let gate = Arc::downgrade(&service.log_retention_gate);
    let store = service.log_retention_store.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(MANAGED_LOG_RETENTION_INTERVAL).await;
            let (Some(inner), Some(readers), Some(permits), Some(gate)) = (
                inner.upgrade(),
                readers.upgrade(),
                permits.upgrade(),
                gate.upgrade(),
            ) else {
                return;
            };
            let _ =
                run_managed_log_retention_cleanup(inner, readers, permits, store.clone(), gate, 0)
                    .await;
        }
    });
}

async fn run_managed_log_retention_cleanup(
    inner: Arc<Mutex<ManagedRunInner>>,
    readers: ManagedLogReaders,
    range_permits: Arc<Semaphore>,
    store: ManagedLogRetentionStore,
    gate: Arc<Mutex<()>>,
    additional_active_reservations: usize,
) -> Result<(), AppError> {
    let _gate = gate.lock().await;
    let (candidates, candidate_count, active_runs) =
        load_managed_log_retention_candidates(&inner).await?;
    let truncated = candidate_count > candidates.len() as u64;
    let mut remaining_candidate_count = candidate_count;
    let now = current_timestamp()?;
    let cutoff_time = SystemTime::now()
        .checked_sub(MANAGED_LOG_RETENTION_MAX_AGE)
        .ok_or_else(managed_log_retention_clock_error)?;
    let cutoff = timestamp_for_system_time(cutoff_time)?;
    let mut inspected = Vec::with_capacity(candidates.len());
    let mut retained_bytes = 0_u64;
    let mut active_reader_only_runs = 0_usize;
    for candidate in candidates {
        let protection =
            retention_candidate_protection(&inner, &readers, &candidate.run_id).await?;
        if protection.controlled || protection.active_reader {
            if !protection.controlled && protection.active_reader {
                active_reader_only_runs = active_reader_only_runs
                    .checked_add(1)
                    .ok_or_else(managed_log_retention_capacity_error)?;
            }
            continue;
        }
        let inspection_store = store.clone();
        let run_id = candidate.run_id.clone();
        let inspection = tokio::task::spawn_blocking(move || inspection_store.inspect(&run_id))
            .await
            .map_err(|_| managed_log_retention_worker_error())?;
        let (reserved_bytes, missing) = match inspection {
            Ok(ManagedLogRetentionInspection::NotFound) => (0, true),
            Ok(ManagedLogRetentionInspection::Present { retained_bytes, .. }) => {
                (retained_bytes, false)
            }
            Err(_) => (HARD_MAX_MANAGED_LOG_DISK_BYTES_PER_RUN, false),
        };
        retained_bytes = retained_bytes
            .checked_add(reserved_bytes)
            .ok_or_else(managed_log_retention_capacity_error)?;
        inspected.push(InspectedRetentionCandidate {
            candidate,
            reserved_bytes,
            missing,
        });
    }
    let active_reservations = active_runs
        .checked_add(additional_active_reservations)
        .and_then(|count| count.checked_add(active_reader_only_runs))
        .ok_or_else(managed_log_retention_capacity_error)?;
    let active_reserved_bytes = u64::try_from(active_reservations)
        .ok()
        .and_then(|count| count.checked_mul(DEFAULT_DISK_BYTES_PER_RUN))
        .ok_or_else(managed_log_retention_capacity_error)?;
    if active_reserved_bytes > MANAGED_LOG_RETENTION_MAX_TOTAL_BYTES {
        return Err(managed_log_retention_capacity_error());
    }
    let retained_budget = MANAGED_LOG_RETENTION_MAX_TOTAL_BYTES - active_reserved_bytes;

    for inspected_candidate in inspected {
        let deletion_pending = inspected_candidate.candidate.deletion_started_at.is_some();
        let expired = inspected_candidate.candidate.retention_timestamp.as_str() <= cutoff.as_str();
        let count_pressure = remaining_candidate_count > MAX_RETAINED_MANAGED_LOG_RUNS;
        let quota_pressure = !truncated && retained_bytes > retained_budget;
        if !deletion_pending
            && !inspected_candidate.missing
            && !expired
            && !count_pressure
            && !quota_pressure
        {
            continue;
        }
        match remove_managed_log_retention_candidate(
            &inner,
            &readers,
            &range_permits,
            &store,
            &inspected_candidate.candidate,
        )
        .await
        {
            Ok(RetentionDeleteOutcome::Deleted) => {
                retained_bytes = retained_bytes.saturating_sub(inspected_candidate.reserved_bytes);
                remaining_candidate_count = remaining_candidate_count.saturating_sub(1);
            }
            Ok(RetentionDeleteOutcome::Protected | RetentionDeleteOutcome::StateChanged) => {}
            Err(_) => {}
        }
    }

    {
        let mut inner = inner.lock().await;
        for _ in 0..AUDIT_RETENTION_MAX_BATCHES_PER_PASS {
            let deleted = inner
                .profiles
                .repository_mut()
                .delete_expired_audit_events(&now, MAX_AUDIT_RETENTION_DELETE_BATCH_SIZE)
                .await
                .unwrap_or_default();
            if deleted < u64::from(MAX_AUDIT_RETENTION_DELETE_BATCH_SIZE) {
                break;
            }
        }
    }
    if truncated
        || remaining_candidate_count > MAX_RETAINED_MANAGED_LOG_RUNS
        || retained_bytes > retained_budget
    {
        return Err(managed_log_retention_capacity_error());
    }
    Ok(())
}

async fn load_managed_log_retention_candidates(
    inner: &Arc<Mutex<ManagedRunInner>>,
) -> Result<(Vec<ManagedRunLogRetentionCandidate>, u64, usize), AppError> {
    debug_assert!(MANAGED_LOG_RETENTION_PAGE_SIZE <= MAX_MANAGED_RUN_LOG_RETENTION_PAGE_SIZE);
    let mut inner = inner.lock().await;
    let active_runs = inner.controls.len();
    let repository = inner.profiles.repository_mut();
    let candidate_count = repository
        .managed_run_log_retention_candidate_count()
        .await?;
    let mut candidates = Vec::with_capacity(
        usize::from(MANAGED_LOG_RETENTION_PAGE_SIZE) * MANAGED_LOG_RETENTION_MAX_PAGES,
    );
    let mut cursor = None;
    for _ in 0..MANAGED_LOG_RETENTION_MAX_PAGES {
        let page = repository
            .managed_run_log_retention_candidates(cursor.as_ref(), MANAGED_LOG_RETENTION_PAGE_SIZE)
            .await?;
        let complete = page.len() < usize::from(MANAGED_LOG_RETENTION_PAGE_SIZE);
        cursor = page.last().map(ManagedRunLogRetentionCursor::from);
        candidates.extend(page);
        if complete {
            return Ok((candidates, candidate_count, active_runs));
        }
    }
    Ok((candidates, candidate_count, active_runs))
}

async fn retention_candidate_protection(
    inner: &Arc<Mutex<ManagedRunInner>>,
    readers: &ManagedLogReaders,
    run_id: &str,
) -> Result<RetentionCandidateProtection, AppError> {
    let controlled = inner.lock().await.controls.contains_key(run_id);
    let readers = readers.lock().map_err(|_| managed_log_registry_error())?;
    let active_reader = readers
        .entries
        .get(run_id)
        .is_some_and(|entry| entry.active);
    Ok(RetentionCandidateProtection {
        controlled,
        active_reader,
    })
}

async fn remove_managed_log_retention_candidate(
    inner: &Arc<Mutex<ManagedRunInner>>,
    readers: &ManagedLogReaders,
    range_permits: &Arc<Semaphore>,
    store: &ManagedLogRetentionStore,
    candidate: &ManagedRunLogRetentionCandidate,
) -> Result<RetentionDeleteOutcome, AppError> {
    let permits = Arc::clone(range_permits)
        .acquire_many_owned(MANAGED_LOG_RANGE_CONCURRENCY as u32)
        .await
        .map_err(|_| managed_log_retention_worker_error())?;
    let deletion_started_at = {
        let mut inner = inner.lock().await;
        if inner.controls.contains_key(&candidate.run_id) {
            return Ok(RetentionDeleteOutcome::Protected);
        }
        let current = inner
            .profiles
            .repository_mut()
            .managed_run_log_retention_candidate(&candidate.run_id)
            .await?;
        let Some(current) = current else {
            return Ok(RetentionDeleteOutcome::StateChanged);
        };
        let expected_directory = inner.log_root.join(&candidate.run_id);
        if Path::new(&candidate.log_directory) != expected_directory
            || current.log_directory.as_str() != candidate.log_directory.as_str()
        {
            return Err(managed_log_retention_identity_error());
        }
        if !readers
            .lock()
            .map_err(|_| managed_log_registry_error())?
            .evict_for_retention(&candidate.run_id)
        {
            return Ok(RetentionDeleteOutcome::Protected);
        }
        let deletion_started_at = match current.deletion_started_at.as_deref() {
            Some(existing) => existing.to_owned(),
            None => next_canonical_timestamp(Some(&current.retention_timestamp))?,
        };
        let started = inner
            .profiles
            .repository_mut()
            .begin_managed_run_log_deletion(
                &candidate.run_id,
                &candidate.log_directory,
                &deletion_started_at,
            )
            .await?;
        if !started {
            return Ok(RetentionDeleteOutcome::StateChanged);
        }
        deletion_started_at
    };

    let removal_store = store.clone();
    let run_id = candidate.run_id.clone();
    let (removal, _permits) = tokio::task::spawn_blocking(move || {
        let removal = removal_store.remove(&run_id);
        (removal, permits)
    })
    .await
    .map_err(|_| managed_log_retention_worker_error())?;
    let removal = removal.map_err(managed_log_retention_error)?;
    match removal {
        ManagedLogRetentionRemoval::NotFound | ManagedLogRetentionRemoval::Removed { .. } => {}
    }

    let deleted_at = next_canonical_timestamp(Some(&deletion_started_at))?;
    let mut inner = inner.lock().await;
    let marked = inner
        .profiles
        .repository_mut()
        .mark_managed_run_logs_deleted(&candidate.run_id, &candidate.log_directory, &deleted_at)
        .await?;
    if marked {
        Ok(RetentionDeleteOutcome::Deleted)
    } else {
        Ok(RetentionDeleteOutcome::StateChanged)
    }
}

fn control_log_range_reader(control: &PlatformRunControl) -> Option<ManagedRunLogRangeReader> {
    match control {
        PlatformRunControl::Running(process) | PlatformRunControl::Quarantined(process) => {
            process.log_range_reader()
        }
        PlatformRunControl::Stopping(stop) => stop.process.log_range_reader(),
        _ => None,
    }
}

async fn reconcile_startup_managed_runs(
    repository: &mut SupervisorRepository,
    controls: &mut HashMap<String, PlatformRunControl>,
) -> Result<Vec<RecoveredStopWorker>, AppError> {
    let mut cursor = None;
    let mut workers = Vec::new();
    loop {
        let candidates = repository
            .managed_run_recovery_candidates(cursor.as_deref())
            .await?;
        let Some(next_cursor) = candidates
            .last()
            .map(|candidate| candidate.run().id.clone())
        else {
            break;
        };

        for candidate in candidates {
            let plan = recovered_control_plan(&candidate);
            let (mut outcome, mut process) = if recovery_evidence_is_probeable(candidate.run()) {
                probe_platform_recovery(candidate.run())
            } else {
                (ManagedRunRecoveryOutcome::Orphaned, None)
            };
            if outcome == ManagedRunRecoveryOutcome::Recovered
                && (plan.is_none() || process.is_none())
            {
                outcome = ManagedRunRecoveryOutcome::Orphaned;
                process = None;
            }
            let previous_timestamp = candidate
                .active_stop()
                .map(|operation| operation.updated_at.as_str())
                .filter(|updated_at| *updated_at > candidate.run().updated_at.as_str())
                .unwrap_or(&candidate.run().updated_at);
            let observed_at = next_canonical_timestamp(Some(previous_timestamp))?;
            repository
                .reconcile_managed_run(&candidate, outcome, &observed_at)
                .await?;

            if let (Some(plan), Some(process)) = (plan, process) {
                let run_id = candidate.run().id.clone();
                let (control, worker) = materialize_recovered_control(&run_id, plan, process);
                controls.insert(run_id, control);
                if let Some(worker) = worker {
                    workers.push(worker);
                }
            }
        }
        cursor = Some(next_cursor);
    }
    Ok(workers)
}

fn recovered_control_plan(candidate: &ManagedRunRecoveryCandidate) -> Option<RecoveredControlPlan> {
    let run = candidate.run();
    if run.state == RunState::Starting || !recovery_evidence_is_probeable(run) {
        return None;
    }

    let Some(operation) = candidate.active_stop() else {
        return (run.stop_method.is_none()
            && matches!(run.state, RunState::Running | RunState::Recovered))
        .then_some(RecoveredControlPlan::Running);
    };
    if !stop_summary_matches_record(&operation.run, run)
        || run.stop_method.as_deref() != Some(stop_method_label(operation.kind))
        || operation.outcome.is_some()
        || operation.completed_at.is_some()
    {
        return None;
    }

    let phase = match (operation.kind, operation.status, run.state) {
        (ManagedStopKind::Graceful, ManagedStopStatus::Requested, RunState::StopRequested)
        | (
            ManagedStopKind::Force,
            ManagedStopStatus::Requested,
            RunState::StopRequested | RunState::GracefulStopping,
        ) if operation.signal_disposition.is_none() => ManagedStopControlPhase::Requested,
        (ManagedStopKind::Graceful, ManagedStopStatus::InProgress, RunState::GracefulStopping)
        | (ManagedStopKind::Force, ManagedStopStatus::InProgress, RunState::ForceStopping)
            if operation.signal_disposition.is_some() =>
        {
            ManagedStopControlPhase::Monitoring
        }
        (ManagedStopKind::Graceful, ManagedStopStatus::TimedOut, RunState::GracefulStopping)
            if operation.signal_disposition.is_some() =>
        {
            ManagedStopControlPhase::TimedOut
        }
        // SIGNAL_PENDING is an ambiguous crash window: recovery must never
        // deliver a signal whose prior delivery cannot be disproved.
        _ => return None,
    };
    let confirmation_window = match operation.kind {
        ManagedStopKind::Graceful => {
            Duration::from_millis(u64::from(run.profile_snapshot.input.stop_timeout_ms))
        }
        ManagedStopKind::Force => FORCE_STOP_CONFIRMATION_TIMEOUT,
    };
    Some(RecoveredControlPlan::Stopping {
        operation_id: operation.operation_id.clone(),
        kind: operation.kind,
        phase,
        signal_disposition: operation.signal_disposition,
        confirmation_window,
    })
}

fn recovery_evidence_is_probeable(run: &ManagedRunRecord) -> bool {
    run.process_instance_key
        .as_ref()
        .is_some_and(|instance_key| {
            run.ended_at.is_none()
                && run.exit_code.is_none()
                && run.exit_signal.is_none()
                && persisted_platform_control_is_valid(instance_key, run.process_group_id)
        })
}

fn stop_method_label(kind: ManagedStopKind) -> &'static str {
    match kind {
        ManagedStopKind::Graceful => "GRACEFUL",
        ManagedStopKind::Force => "FORCE",
    }
}

fn stop_summary_matches_record(summary: &ManagedRunSummary, record: &ManagedRunRecord) -> bool {
    summary.run_id == record.id
        && summary.profile_id == record.profile_snapshot.id
        && summary.profile_updated_at == record.profile_snapshot.updated_at
        && summary.state == record.state
        && summary.process_instance_key == record.process_instance_key
        && summary.process_group_id == record.process_group_id
        && summary.started_at == record.started_at
        && summary.updated_at == record.updated_at
        && summary.ended_at == record.ended_at
}

#[cfg(windows)]
fn persisted_platform_control_is_valid(
    _instance_key: &ProcessInstanceKey,
    process_group_id: Option<u32>,
) -> bool {
    process_group_id.is_none()
}

#[cfg(target_os = "macos")]
fn persisted_platform_control_is_valid(
    instance_key: &ProcessInstanceKey,
    process_group_id: Option<u32>,
) -> bool {
    process_group_id == Some(instance_key.pid)
}

#[cfg(windows)]
fn probe_platform_recovery(
    record: &ManagedRunRecord,
) -> (ManagedRunRecoveryOutcome, Option<PlatformManagedProcess>) {
    let outcome = match probe_managed_process_recovery(
        record
            .process_instance_key
            .as_ref()
            .expect("validated recovery identity"),
    ) {
        WindowsManagedRecoveryProbe::ExitedWhileOffline => {
            ManagedRunRecoveryOutcome::ExitedWhileOffline
        }
        WindowsManagedRecoveryProbe::IdentityMismatch => {
            ManagedRunRecoveryOutcome::IdentityMismatch
        }
        WindowsManagedRecoveryProbe::Orphaned => ManagedRunRecoveryOutcome::Orphaned,
    };
    (outcome, None)
}

#[cfg(target_os = "macos")]
fn probe_platform_recovery(
    record: &ManagedRunRecord,
) -> (ManagedRunRecoveryOutcome, Option<PlatformManagedProcess>) {
    let probe = probe_recovered_process_group(
        record
            .process_instance_key
            .as_ref()
            .expect("validated recovery identity"),
        record
            .process_group_id
            .expect("validated recovery process group"),
    );
    match probe {
        MacosManagedRecoveryProbe::Recovered(process) => (
            ManagedRunRecoveryOutcome::Recovered,
            Some(PlatformManagedProcess::Recovered(process)),
        ),
        MacosManagedRecoveryProbe::ExitedWhileOffline => {
            (ManagedRunRecoveryOutcome::ExitedWhileOffline, None)
        }
        MacosManagedRecoveryProbe::IdentityMismatch => {
            (ManagedRunRecoveryOutcome::IdentityMismatch, None)
        }
        MacosManagedRecoveryProbe::Orphaned => (ManagedRunRecoveryOutcome::Orphaned, None),
    }
}

fn materialize_recovered_control(
    run_id: &str,
    plan: RecoveredControlPlan,
    process: PlatformManagedProcess,
) -> (PlatformRunControl, Option<RecoveredStopWorker>) {
    match plan {
        RecoveredControlPlan::Running => (PlatformRunControl::Running(process), None),
        RecoveredControlPlan::Stopping {
            operation_id,
            kind,
            phase,
            signal_disposition,
            confirmation_window,
        } => {
            let worker = RecoveredStopWorker {
                run_id: run_id.to_owned(),
                operation_id: operation_id.clone(),
            };
            let deadline = match phase {
                ManagedStopControlPhase::Requested => Instant::now() + confirmation_window,
                ManagedStopControlPhase::Monitoring | ManagedStopControlPhase::TimedOut => {
                    Instant::now()
                }
                _ => unreachable!("validated recovered stop phase"),
            };
            (
                PlatformRunControl::Stopping(StoppingManagedProcess {
                    process,
                    operation_id,
                    kind,
                    phase,
                    signal_disposition,
                    confirmation_window,
                    deadline,
                    worker_running: true,
                }),
                Some(worker),
            )
        }
    }
}

async fn begin_supervisor_stop(
    inner: Arc<Mutex<ManagedRunInner>>,
    operation_id: String,
    command: ManagedStopCommand,
) -> Result<ManagedStopOperationResult, AppError> {
    let run_id = command.run_id().to_owned();
    let kind = command.kind();
    let mut inner_guard = inner.lock().await;
    let ManagedRunInner {
        profiles, controls, ..
    } = &mut *inner_guard;
    reject_unsafe_force_supersession(controls, &operation_id, &command)?;
    let (repository, _) = profiles.launch_resources();
    let now = next_managed_stop_timestamp(repository, &operation_id, &run_id).await?;
    let decision = repository
        .begin_managed_stop(&operation_id, command.as_storage_request(), &now)
        .await?;

    if matches!(
        decision.result.status,
        ManagedStopStatus::Completed | ManagedStopStatus::Superseded
    ) {
        return Ok(decision.result);
    }

    if let Some(PlatformRunControl::Stopping(stop)) = controls.get_mut(&run_id)
        && stop.operation_id == operation_id
    {
        let schedule = !stop.worker_running;
        stop.worker_running = true;
        let result = decision.result;
        drop(inner_guard);
        if schedule {
            schedule_stop_worker(inner, run_id, operation_id);
        }
        return Ok(result);
    }

    let record = repository.managed_run(&run_id).await?;
    let Some(process) = take_process_for_stop(
        controls,
        &run_id,
        decision.superseded_operation_id.as_deref(),
    ) else {
        let completion_at =
            next_canonical_timestamp(Some(latest_stop_result_timestamp(&decision.result)))?;
        return repository
            .complete_stop(
                &operation_id,
                &ManagedStopCompletion {
                    outcome: ManagedStopOutcome::Orphaned,
                    exit_code: None,
                    exit_signal: None,
                },
                &completion_at,
            )
            .await;
    };

    let (mut phase, signal_disposition) = control_phase_from_result(&decision.result)?;
    if !platform_control_matches_summary(&process, &decision.result.run)
        || record.process_instance_key.as_ref() != Some(process.instance_key())
    {
        phase = ManagedStopControlPhase::CompletionPending(ManagedStopOutcome::IdentityMismatch);
    }
    let wait = match kind {
        ManagedStopKind::Graceful => {
            Duration::from_millis(u64::from(record.profile_snapshot.input.stop_timeout_ms))
        }
        ManagedStopKind::Force => FORCE_STOP_CONFIRMATION_TIMEOUT,
    };
    controls.insert(
        run_id.clone(),
        PlatformRunControl::Stopping(StoppingManagedProcess {
            process,
            operation_id: operation_id.clone(),
            kind,
            phase,
            signal_disposition,
            confirmation_window: wait,
            deadline: Instant::now() + wait,
            worker_running: true,
        }),
    );
    let result = decision.result;
    drop(inner_guard);
    schedule_stop_worker(inner, run_id, operation_id);
    Ok(result)
}

async fn next_managed_stop_timestamp(
    repository: &SupervisorRepository,
    operation_id: &str,
    run_id: &str,
) -> Result<String, AppError> {
    match repository.managed_stop_operation(operation_id).await {
        Ok(result) => next_canonical_timestamp(Some(latest_stop_result_timestamp(&result))),
        Err(error) if error.code == ErrorCode::NotFound => {
            let run = repository.managed_run(run_id).await?;
            let active = repository.active_managed_stop_for_run(run_id).await?;
            let previous = active
                .as_ref()
                .map(latest_stop_result_timestamp)
                .filter(|updated_at| *updated_at > run.updated_at.as_str())
                .unwrap_or(run.updated_at.as_str());
            next_canonical_timestamp(Some(previous))
        }
        Err(error) => Err(error),
    }
}

fn latest_stop_result_timestamp(result: &ManagedStopOperationResult) -> &str {
    if result.updated_at > result.run.updated_at {
        &result.updated_at
    } else {
        &result.run.updated_at
    }
}

fn reject_unsafe_force_supersession(
    controls: &HashMap<String, PlatformRunControl>,
    operation_id: &str,
    command: &ManagedStopCommand,
) -> Result<(), AppError> {
    let ManagedStopCommand::Force(request) = command else {
        return Ok(());
    };
    let Some(PlatformRunControl::Stopping(stop)) = controls.get(&request.run_id) else {
        return Ok(());
    };
    if stop.operation_id == operation_id
        || request.supersede_operation_id.as_deref() != Some(stop.operation_id.as_str())
        || !matches!(
            stop.phase,
            ManagedStopControlPhase::SignalAttempted
                | ManagedStopControlPhase::CompletionPending(_)
        )
    {
        return Ok(());
    }

    let mut error = AppError::new(
        ErrorCode::Conflict,
        "managed stop operation is committing an irreversible result",
    );
    error.retryable = true;
    error
        .details
        .insert("activeOperationId".into(), stop.operation_id.clone());
    error.details.insert(
        "reason".into(),
        "retry after the active signal or completion evidence is durable".into(),
    );
    Err(error)
}

fn control_phase_from_result(
    result: &ManagedStopOperationResult,
) -> Result<
    (
        ManagedStopControlPhase,
        Option<ManagedStopSignalDisposition>,
    ),
    AppError,
> {
    let phase = match result.status {
        ManagedStopStatus::Requested => ManagedStopControlPhase::Requested,
        ManagedStopStatus::SignalPending => ManagedStopControlPhase::SignalPending,
        ManagedStopStatus::InProgress => ManagedStopControlPhase::Monitoring,
        ManagedStopStatus::TimedOut => ManagedStopControlPhase::TimedOut,
        ManagedStopStatus::Completed | ManagedStopStatus::Superseded => {
            return Err(AppError::new(
                ErrorCode::Conflict,
                "terminal managed stop operation cannot own a live control",
            ));
        }
    };
    Ok((phase, result.signal_disposition))
}

fn take_process_for_stop(
    controls: &mut HashMap<String, PlatformRunControl>,
    run_id: &str,
    superseded_operation_id: Option<&str>,
) -> Option<PlatformManagedProcess> {
    let control = controls.remove(run_id)?;
    match control {
        PlatformRunControl::Running(process) if superseded_operation_id.is_none() => Some(process),
        PlatformRunControl::Stopping(stop)
            if superseded_operation_id == Some(stop.operation_id.as_str()) =>
        {
            Some(stop.process)
        }
        control => {
            controls.insert(run_id.to_owned(), control);
            None
        }
    }
}

fn schedule_stop_worker(inner: Arc<Mutex<ManagedRunInner>>, run_id: String, operation_id: String) {
    tokio::spawn(run_stop_worker(inner, run_id, operation_id));
}

async fn run_stop_worker(inner: Arc<Mutex<ManagedRunInner>>, run_id: String, operation_id: String) {
    loop {
        let step = {
            let mut inner = inner.lock().await;
            advance_stop_worker(&mut inner, &run_id, &operation_id).await
        };
        match step {
            StopWorkerStep::Continue(delay) if delay.is_zero() => tokio::task::yield_now().await,
            StopWorkerStep::Continue(delay) => tokio::time::sleep(delay).await,
            StopWorkerStep::Finished => return,
        }
    }
}

enum StopWorkerStep {
    Continue(Duration),
    Finished,
}

async fn advance_stop_worker(
    inner: &mut ManagedRunInner,
    run_id: &str,
    operation_id: &str,
) -> StopWorkerStep {
    let ManagedRunInner {
        profiles, controls, ..
    } = inner;
    let (repository, _) = profiles.launch_resources();
    let Some(PlatformRunControl::Stopping(stop)) = controls.get_mut(run_id) else {
        return StopWorkerStep::Finished;
    };
    if stop.operation_id != operation_id {
        return StopWorkerStep::Finished;
    }

    match stop.phase {
        ManagedStopControlPhase::Requested => {
            let Some(now) = stop_worker_timestamp(repository, operation_id).await else {
                return StopWorkerStep::Continue(CLEANUP_RETRY_DELAY);
            };
            match repository
                .mark_stop_signal_pending(operation_id, &now)
                .await
            {
                Ok(_) => {
                    stop.phase = ManagedStopControlPhase::SignalPending;
                    StopWorkerStep::Continue(Duration::ZERO)
                }
                Err(_) => match repository.managed_stop_operation(operation_id).await {
                    Ok(result) if result.status == ManagedStopStatus::SignalPending => {
                        stop.phase = ManagedStopControlPhase::SignalPending;
                        StopWorkerStep::Continue(Duration::ZERO)
                    }
                    _ => StopWorkerStep::Continue(CLEANUP_RETRY_DELAY),
                },
            }
        }
        ManagedStopControlPhase::SignalPending => {
            match send_platform_stop_signal(&mut stop.process, stop.kind) {
                Ok((disposition, _diagnostic)) => {
                    stop.signal_disposition = Some(disposition);
                    stop.phase = ManagedStopControlPhase::SignalAttempted;
                }
                Err(error) => {
                    let outcome = if error.code == ErrorCode::IdentityMismatch {
                        identity_validation_outcome(&error)
                    } else {
                        ManagedStopOutcome::Orphaned
                    };
                    stop.phase = ManagedStopControlPhase::CompletionPending(outcome);
                }
            }
            StopWorkerStep::Continue(Duration::ZERO)
        }
        ManagedStopControlPhase::SignalAttempted => {
            let Some(disposition) = stop.signal_disposition else {
                stop.phase =
                    ManagedStopControlPhase::CompletionPending(ManagedStopOutcome::Orphaned);
                return StopWorkerStep::Continue(Duration::ZERO);
            };
            let Some(now) = stop_worker_timestamp(repository, operation_id).await else {
                return StopWorkerStep::Continue(CLEANUP_RETRY_DELAY);
            };
            match repository
                .mark_stop_signal_attempted(operation_id, disposition, &now)
                .await
            {
                Ok(_) => {
                    stop.deadline = Instant::now() + stop.confirmation_window;
                    stop.phase = ManagedStopControlPhase::Monitoring;
                    StopWorkerStep::Continue(Duration::ZERO)
                }
                Err(_) => match repository.managed_stop_operation(operation_id).await {
                    Ok(result)
                        if result.status == ManagedStopStatus::InProgress
                            && result.signal_disposition == Some(disposition) =>
                    {
                        stop.deadline = Instant::now() + stop.confirmation_window;
                        stop.phase = ManagedStopControlPhase::Monitoring;
                        StopWorkerStep::Continue(Duration::ZERO)
                    }
                    _ => StopWorkerStep::Continue(CLEANUP_RETRY_DELAY),
                },
            }
        }
        ManagedStopControlPhase::Monitoring => match poll_platform_exit(&mut stop.process) {
            Ok(true) => {
                stop.phase = ManagedStopControlPhase::CompletionPending(ManagedStopOutcome::Exited);
                StopWorkerStep::Continue(Duration::ZERO)
            }
            Ok(false) if Instant::now() < stop.deadline => {
                StopWorkerStep::Continue(STOP_POLL_INTERVAL)
            }
            Err(error) if error.code == ErrorCode::IdentityMismatch => {
                stop.phase =
                    ManagedStopControlPhase::CompletionPending(identity_validation_outcome(&error));
                StopWorkerStep::Continue(Duration::ZERO)
            }
            Ok(false) | Err(_)
                if stop.kind == ManagedStopKind::Graceful && Instant::now() >= stop.deadline =>
            {
                let Some(now) = stop_worker_timestamp(repository, operation_id).await else {
                    return StopWorkerStep::Continue(CLEANUP_RETRY_DELAY);
                };
                match repository.mark_graceful_timed_out(operation_id, &now).await {
                    Ok(_) => {
                        stop.phase = ManagedStopControlPhase::TimedOut;
                        StopWorkerStep::Continue(TIMED_OUT_STOP_POLL_INTERVAL)
                    }
                    Err(_) => match repository.managed_stop_operation(operation_id).await {
                        Ok(result) if result.status == ManagedStopStatus::TimedOut => {
                            stop.phase = ManagedStopControlPhase::TimedOut;
                            StopWorkerStep::Continue(TIMED_OUT_STOP_POLL_INTERVAL)
                        }
                        _ => StopWorkerStep::Continue(CLEANUP_RETRY_DELAY),
                    },
                }
            }
            Ok(false) => {
                let outcome =
                    if stop.signal_disposition == Some(ManagedStopSignalDisposition::Unavailable) {
                        ManagedStopOutcome::SignalUnavailable
                    } else {
                        ManagedStopOutcome::Orphaned
                    };
                stop.phase = ManagedStopControlPhase::CompletionPending(outcome);
                StopWorkerStep::Continue(Duration::ZERO)
            }
            Err(_) if stop.kind == ManagedStopKind::Force && Instant::now() >= stop.deadline => {
                stop.phase =
                    ManagedStopControlPhase::CompletionPending(ManagedStopOutcome::Orphaned);
                StopWorkerStep::Continue(Duration::ZERO)
            }
            Err(_) => StopWorkerStep::Continue(STOP_POLL_INTERVAL),
        },
        ManagedStopControlPhase::TimedOut => match poll_platform_exit(&mut stop.process) {
            Ok(true) => {
                stop.phase = ManagedStopControlPhase::CompletionPending(ManagedStopOutcome::Exited);
                StopWorkerStep::Continue(Duration::ZERO)
            }
            Err(error) if error.code == ErrorCode::IdentityMismatch => {
                stop.phase =
                    ManagedStopControlPhase::CompletionPending(identity_validation_outcome(&error));
                StopWorkerStep::Continue(Duration::ZERO)
            }
            Ok(false) | Err(_) => StopWorkerStep::Continue(TIMED_OUT_STOP_POLL_INTERVAL),
        },
        ManagedStopControlPhase::CompletionPending(outcome) => {
            let Some(now) = stop_worker_timestamp(repository, operation_id).await else {
                return StopWorkerStep::Continue(CLEANUP_RETRY_DELAY);
            };
            let completion = ManagedStopCompletion {
                outcome,
                exit_code: None,
                exit_signal: None,
            };
            let persisted = match repository
                .complete_stop(operation_id, &completion, &now)
                .await
            {
                Ok(_) => true,
                Err(_) => repository
                    .managed_stop_operation(operation_id)
                    .await
                    .is_ok_and(|result| {
                        result.status == ManagedStopStatus::Completed
                            && result.outcome == Some(outcome)
                    }),
            };
            if !persisted {
                return StopWorkerStep::Continue(CLEANUP_RETRY_DELAY);
            }
            finalize_stop_control(controls, run_id, operation_id, outcome);
            StopWorkerStep::Finished
        }
    }
}

fn identity_validation_outcome(error: &AppError) -> ManagedStopOutcome {
    if matches!(
        error.details.get("stage").map(String::as_str),
        Some("RevalidateProcessGroup" | "getpgid" | "PollManagedProcessGroup")
    ) {
        ManagedStopOutcome::Orphaned
    } else {
        ManagedStopOutcome::IdentityMismatch
    }
}

async fn stop_worker_timestamp(
    repository: &SupervisorRepository,
    operation_id: &str,
) -> Option<String> {
    let result = repository.managed_stop_operation(operation_id).await.ok()?;
    next_canonical_timestamp(Some(latest_stop_result_timestamp(&result))).ok()
}

fn finalize_stop_control(
    controls: &mut HashMap<String, PlatformRunControl>,
    run_id: &str,
    operation_id: &str,
    outcome: ManagedStopOutcome,
) {
    let Some(control) = controls.remove(run_id) else {
        return;
    };
    match control {
        PlatformRunControl::Stopping(stop) if stop.operation_id == operation_id => {
            if outcome != ManagedStopOutcome::Exited {
                controls.insert(
                    run_id.to_owned(),
                    PlatformRunControl::Quarantined(stop.process),
                );
            }
        }
        control => {
            controls.insert(run_id.to_owned(), control);
        }
    }
}

async fn join_supervisor_task<T>(
    task: tokio::task::JoinHandle<Result<T, AppError>>,
) -> Result<T, AppError>
where
    T: Send + 'static,
{
    task.await.map_err(|_| {
        let mut error = AppError::new(
            ErrorCode::Internal,
            "Supervisor operation task did not complete",
        );
        error.retryable = true;
        error
    })?
}

fn schedule_cleanup_retries(inner: Arc<Mutex<ManagedRunInner>>) {
    tokio::spawn(async move {
        for _ in 0..CLEANUP_RETRY_ATTEMPTS {
            tokio::time::sleep(CLEANUP_RETRY_DELAY).await;
            let remaining = {
                let mut inner = inner.lock().await;
                retry_pending_controls(&mut inner.controls)
            };
            if remaining == 0 {
                break;
            }
        }
    });
}

fn schedule_terminal_exit_monitor(inner: Arc<Mutex<ManagedRunInner>>, run_id: String) {
    tokio::spawn(async move {
        let mut confirmed_at = None;
        loop {
            tokio::time::sleep(TERMINAL_EXIT_POLL_INTERVAL).await;
            let mut inner = inner.lock().await;
            let ManagedRunInner {
                profiles, controls, ..
            } = &mut *inner;
            let (repository, _) = profiles.launch_resources();

            let process = match controls.get_mut(&run_id) {
                Some(PlatformRunControl::Running(process)) if process.is_terminal() => process,
                // A stop worker becomes the sole exit/persistence owner as
                // soon as it moves the control out of Running.
                _ => return,
            };
            if confirmed_at.is_none() {
                let exited = match poll_terminal_natural_exit(process) {
                    Ok(exited) => exited,
                    Err(_) => continue,
                };
                if !exited {
                    continue;
                }
                let Ok(record) = repository.managed_run(&run_id).await else {
                    continue;
                };
                let Ok(timestamp) = next_canonical_timestamp(Some(&record.updated_at)) else {
                    continue;
                };
                confirmed_at = Some(timestamp);
            }

            let ended_at = confirmed_at
                .as_deref()
                .expect("confirmed terminal exit timestamp");
            if repository
                .mark_running_run_exited(&run_id, ended_at)
                .await
                .is_ok()
            {
                controls.remove(&run_id);
                return;
            }
        }
    });
}

fn retry_pending_controls(controls: &mut HashMap<String, PlatformRunControl>) -> usize {
    let completed = controls
        .iter_mut()
        .filter_map(|(run_id, control)| match control {
            PlatformRunControl::CleanupPending(error) => {
                error.retry_cleanup().is_ok().then(|| run_id.clone())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    for run_id in completed {
        controls.remove(&run_id);
    }
    controls
        .values()
        .filter(|control| matches!(control, PlatformRunControl::CleanupPending(_)))
        .count()
}

#[cfg(windows)]
fn active_platform() -> ExecutionPlatform {
    ExecutionPlatform::Windows
}

#[cfg(target_os = "macos")]
fn active_platform() -> ExecutionPlatform {
    ExecutionPlatform::MacOs
}

#[cfg(windows)]
fn prepare_platform_suspended(
    executable: &str,
    argv: &[String],
    working_directory: &str,
    environment: &ResolvedEnvironment,
    stdio: ManagedStdio<'_>,
) -> Result<SuspendedManagedProcess, ManagedLaunchError> {
    prepare_suspended_into_job(&WindowsManagedLaunchRequest {
        executable,
        argv,
        working_directory,
        environment,
        stdio,
    })
}

#[cfg(target_os = "macos")]
fn prepare_platform_suspended(
    executable: &str,
    argv: &[String],
    working_directory: &str,
    environment: &ResolvedEnvironment,
    stdio: ManagedStdio<'_>,
) -> Result<SuspendedManagedProcess, ManagedLaunchError> {
    prepare_suspended_process_group(&MacosManagedLaunchRequest {
        executable,
        argv,
        working_directory,
        environment,
        stdio,
    })
}

#[cfg(windows)]
fn ordinary_managed_stdio<'a>(stdout: &'a PipeWriter, stderr: &'a PipeWriter) -> ManagedStdio<'a> {
    ManagedStdio::Pipes {
        stdout,
        stderr,
        create_new_process_group: true,
    }
}

#[cfg(target_os = "macos")]
fn ordinary_managed_stdio<'a>(stdout: &'a PipeWriter, stderr: &'a PipeWriter) -> ManagedStdio<'a> {
    ManagedStdio::Pipes { stdout, stderr }
}

#[cfg(windows)]
fn terminal_managed_stdio() -> ManagedStdio<'static> {
    ManagedStdio::PseudoConsole {
        columns: DEFAULT_TERMINAL_COLUMNS,
        rows: DEFAULT_TERMINAL_ROWS,
    }
}

#[cfg(target_os = "macos")]
fn terminal_managed_stdio() -> ManagedStdio<'static> {
    ManagedStdio::Terminal {
        rows: DEFAULT_TERMINAL_ROWS,
        columns: DEFAULT_TERMINAL_COLUMNS,
    }
}

#[cfg(windows)]
fn platform_control_group(
    _process: &SuspendedManagedProcess,
) -> Result<ManagedRunControlGroup, AppError> {
    Ok(ManagedRunControlGroup::windows_job())
}

#[cfg(target_os = "macos")]
fn platform_control_group(
    process: &SuspendedManagedProcess,
) -> Result<ManagedRunControlGroup, AppError> {
    ManagedRunControlGroup::macos_process_group(process.process_group_id())
}

fn send_platform_stop_signal(
    process: &mut PlatformManagedProcess,
    kind: ManagedStopKind,
) -> Result<(ManagedStopSignalDisposition, Option<AppError>), AppError> {
    let result = match process {
        PlatformManagedProcess::Launched { process, .. } => match kind {
            ManagedStopKind::Graceful => process.send_graceful()?,
            ManagedStopKind::Force => process.send_force()?,
        },
        #[cfg(target_os = "macos")]
        PlatformManagedProcess::Recovered(process) => match kind {
            ManagedStopKind::Graceful => process.send_graceful()?,
            ManagedStopKind::Force => process.send_force()?,
        },
    };
    match result {
        ManagedStopSignalResult::Delivered => Ok((ManagedStopSignalDisposition::Delivered, None)),
        ManagedStopSignalResult::SignalUnavailable(error) => {
            Ok((ManagedStopSignalDisposition::Unavailable, Some(error)))
        }
    }
}

fn poll_platform_exit(process: &mut PlatformManagedProcess) -> Result<bool, AppError> {
    let poll = match process {
        PlatformManagedProcess::Launched { process, .. } => process.poll_exit()?,
        #[cfg(target_os = "macos")]
        PlatformManagedProcess::Recovered(process) => process.poll_exit()?,
    };
    match poll {
        ManagedExitPoll::Running => Ok(false),
        ManagedExitPoll::Exited => Ok(true),
    }
}

#[cfg(windows)]
fn poll_terminal_natural_exit(process: &mut PlatformManagedProcess) -> Result<bool, AppError> {
    let PlatformManagedProcess::Launched { process, .. } = process;
    Ok(matches!(process.poll_exit()?, ManagedExitPoll::Exited))
}

#[cfg(target_os = "macos")]
fn poll_terminal_natural_exit(process: &mut PlatformManagedProcess) -> Result<bool, AppError> {
    match process {
        PlatformManagedProcess::Launched { process, .. } => Ok(matches!(
            process.poll_natural_exit()?,
            ManagedExitPoll::Exited
        )),
        PlatformManagedProcess::Recovered(_) => Err(AppError::new(
            ErrorCode::NotSupported,
            "recovered macOS runs do not own a terminal session",
        )),
    }
}

#[cfg(windows)]
fn platform_control_matches_summary(
    process: &PlatformManagedProcess,
    summary: &ManagedRunSummary,
) -> bool {
    summary.process_instance_key.as_ref() == Some(process.instance_key())
        && summary.process_group_id.is_none()
}

#[cfg(target_os = "macos")]
fn platform_control_matches_summary(
    process: &PlatformManagedProcess,
    summary: &ManagedRunSummary,
) -> bool {
    summary.process_instance_key.as_ref() == Some(process.instance_key())
        && summary.process_group_id == Some(process.process_group_id())
}

struct OrdinaryManagedLogPipes {
    stdout_reader: PipeReader,
    stdout_writer: PipeWriter,
    stderr_reader: PipeReader,
    stderr_writer: PipeWriter,
}

async fn start_platform_run(
    repository: &mut SupervisorRepository,
    credential_store: &dyn SecretStore,
    controls: &mut HashMap<String, PlatformRunControl>,
    log_root: &Path,
    log_publisher: &ManagedLogPublisher,
    log_readers: &ManagedLogReaders,
    request: &StartManagedRunRequest,
    context: &ExecutionPreviewContext,
) -> Result<StartManagedRunResult, AppError> {
    let profile = repository.launch_profile(&request.profile_id).await?;
    if profile.updated_at != request.expected_profile_updated_at {
        return Err(profile_revision_conflict(request, &profile.updated_at));
    }

    let starting = create_starting_intent(repository, controls, log_root, &profile).await?;
    let run_id = starting.id.clone();
    let fallback_timestamp = starting.started_at.clone();

    let preview = match lifecycle::build_execution_preview(
        context,
        &ExecutionPreviewRequest {
            profile: profile.input.clone(),
        },
    ) {
        Ok(preview) => preview,
        Err(error) => {
            return Err(record_failed_launch(
                repository,
                controls,
                &run_id,
                LaunchFailureStage::ExecutableResolution,
                &fallback_timestamp,
                error,
            )
            .await);
        }
    };
    let (argv, executable_candidates) = match platform_launch_plan(preview) {
        Ok(plan) => plan,
        Err(error) => {
            return Err(record_failed_launch(
                repository,
                controls,
                &run_id,
                LaunchFailureStage::ExecutableResolution,
                &fallback_timestamp,
                error,
            )
            .await);
        }
    };
    if let Err(error) = validate_working_directory(&profile.input.working_directory) {
        return Err(record_failed_launch(
            repository,
            controls,
            &run_id,
            LaunchFailureStage::ProcessCreation,
            &fallback_timestamp,
            error,
        )
        .await);
    }

    let merged = match lifecycle::merge_environment(context, &profile.input.environment) {
        Ok(environment) => environment,
        Err(error) => {
            return Err(record_failed_launch(
                repository,
                controls,
                &run_id,
                LaunchFailureStage::CredentialResolution,
                &fallback_timestamp,
                error,
            )
            .await);
        }
    };
    let environment =
        match lifecycle::resolve_environment_credentials(&profile.id, merged, credential_store) {
            Ok(environment) => environment,
            Err(error) => {
                return Err(record_failed_launch(
                    repository,
                    controls,
                    &run_id,
                    LaunchFailureStage::CredentialResolution,
                    &fallback_timestamp,
                    redact_credential_error(error),
                )
                .await);
            }
        };

    let redaction_rules = match managed_log_redaction_rules(&environment) {
        Ok(rules) => rules,
        Err(error) => {
            drop(environment);
            return Err(record_failed_launch(
                repository,
                controls,
                &run_id,
                LaunchFailureStage::LogPreparation,
                &fallback_timestamp,
                error,
            )
            .await);
        }
    };
    let (stdout_text_pipeline, stderr_text_pipeline) = match prepare_managed_log_text_pipelines(
        &profile.input.execution,
        profile.input.interactive,
        &redaction_rules,
    ) {
        Ok(pipelines) => pipelines,
        Err(error) => {
            drop(environment);
            return Err(record_failed_launch(
                repository,
                controls,
                &run_id,
                LaunchFailureStage::LogPreparation,
                &fallback_timestamp,
                error,
            )
            .await);
        }
    };

    let log_collector = match ManagedRunLogCollector::open(
        Path::new(&starting.log_directory),
        LogLimits::default(),
    ) {
        Ok(collector) => collector,
        Err(error) => {
            drop(environment);
            return Err(record_failed_launch(
                repository,
                controls,
                &run_id,
                LaunchFailureStage::LogPreparation,
                &fallback_timestamp,
                managed_log_error(error),
            )
            .await);
        }
    };
    let ordinary_pipes = if profile.input.interactive {
        None
    } else {
        let (stdout_reader, stdout_writer) = match create_managed_log_pipe(LogStream::Stdout) {
            Ok(pipe) => pipe,
            Err(error) => {
                drop(environment);
                return Err(record_failed_launch(
                    repository,
                    controls,
                    &run_id,
                    LaunchFailureStage::LogPreparation,
                    &fallback_timestamp,
                    error,
                )
                .await);
            }
        };
        let (stderr_reader, stderr_writer) = match create_managed_log_pipe(LogStream::Stderr) {
            Ok(pipe) => pipe,
            Err(error) => {
                drop(environment);
                return Err(record_failed_launch(
                    repository,
                    controls,
                    &run_id,
                    LaunchFailureStage::LogPreparation,
                    &fallback_timestamp,
                    error,
                )
                .await);
            }
        };
        Some(OrdinaryManagedLogPipes {
            stdout_reader,
            stdout_writer,
            stderr_reader,
            stderr_writer,
        })
    };

    let mut suspended = None;
    for executable in executable_candidates {
        let stdio = match ordinary_pipes.as_ref() {
            Some(pipes) => ordinary_managed_stdio(&pipes.stdout_writer, &pipes.stderr_writer),
            None => terminal_managed_stdio(),
        };
        match prepare_platform_suspended(
            &executable,
            &argv,
            &profile.input.working_directory,
            &environment,
            stdio,
        ) {
            Ok(process) => {
                suspended = Some(process);
                break;
            }
            Err(error) if executable_candidate_was_not_found(&error) => {}
            Err(error) => {
                let stage = native_failure_stage(&error);
                drop(environment);
                return Err(record_native_failure(
                    repository,
                    controls,
                    &run_id,
                    stage,
                    &fallback_timestamp,
                    error,
                    None,
                )
                .await);
            }
        }
    }
    drop(environment);

    let Some(suspended) = suspended else {
        let error = AppError::new(ErrorCode::NotFound, "managed run executable was not found");
        return Err(record_failed_launch(
            repository,
            controls,
            &run_id,
            LaunchFailureStage::ExecutableResolution,
            &fallback_timestamp,
            error,
        )
        .await);
    };

    let instance_key = suspended.instance_key().clone();
    let control_group = match platform_control_group(&suspended) {
        Ok(control_group) => control_group,
        Err(error) => {
            return Err(abort_suspended_after_failure(
                repository,
                controls,
                &run_id,
                &fallback_timestamp,
                suspended,
                LaunchFailureStage::IdentityRead,
                error,
            )
            .await);
        }
    };
    replace_control(controls, &run_id, PlatformRunControl::Suspended(suspended));
    let identity_updated_at = next_canonical_timestamp(Some(&fallback_timestamp))?;
    let bound = match repository
        .bind_starting_run_identity_and_control(
            &run_id,
            &instance_key,
            control_group,
            &identity_updated_at,
        )
        .await
    {
        Ok(record) => record,
        Err(error) => {
            let suspended = take_suspended(controls, &run_id);
            return Err(abort_suspended_after_failure(
                repository,
                controls,
                &run_id,
                &fallback_timestamp,
                suspended,
                LaunchFailureStage::IdentityPersistence,
                error,
            )
            .await);
        }
    };

    let running_updated_at = next_canonical_timestamp(Some(&identity_updated_at))?;
    let result = match projected_running_result(&bound, &running_updated_at) {
        Ok(result) => result,
        Err(error) => {
            let suspended = take_suspended(controls, &run_id);
            return Err(abort_suspended_after_failure(
                repository,
                controls,
                &run_id,
                &fallback_timestamp,
                suspended,
                LaunchFailureStage::RunningPersistence,
                error,
            )
            .await);
        }
    };

    let mut suspended = take_suspended(controls, &run_id);
    let (stdout_reader, stderr_reader): (Box<dyn Read + Send>, Box<dyn Read + Send>) =
        match ordinary_pipes {
            Some(OrdinaryManagedLogPipes {
                stdout_reader,
                stdout_writer,
                stderr_reader,
                stderr_writer,
            }) => {
                drop(stdout_writer);
                drop(stderr_writer);
                (Box::new(stdout_reader), Box::new(stderr_reader))
            }
            None => {
                let Some(terminal_output) = suspended.take_terminal_output() else {
                    let error = AppError::new(
                        ErrorCode::Internal,
                        "interactive managed run did not return terminal output",
                    );
                    return Err(abort_suspended_after_failure(
                        repository,
                        controls,
                        &run_id,
                        &fallback_timestamp,
                        suspended,
                        LaunchFailureStage::LogPreparation,
                        error,
                    )
                    .await);
                };
                // PTY/ConPTY combine stdout and stderr. The merged, filtered
                // transcript is exposed as stdout; stderr reaches EOF immediately.
                (Box::new(terminal_output), Box::new(io::empty()))
            }
        };
    let logs = match start_managed_log_capture(
        &run_id,
        log_publisher,
        log_readers,
        log_collector,
        stdout_reader,
        stderr_reader,
        stdout_text_pipeline,
        stderr_text_pipeline,
    ) {
        Ok(logs) => logs,
        Err(error) => {
            return Err(abort_suspended_after_failure(
                repository,
                controls,
                &run_id,
                &fallback_timestamp,
                suspended,
                LaunchFailureStage::LogPreparation,
                error,
            )
            .await);
        }
    };
    let process = match suspended.resume() {
        Ok(process) => process,
        Err(error) => {
            return Err(record_native_failure(
                repository,
                controls,
                &run_id,
                LaunchFailureStage::ProcessResume,
                &fallback_timestamp,
                error,
                None,
            )
            .await);
        }
    };
    replace_control(
        controls,
        &run_id,
        PlatformRunControl::RunningUncommitted(process),
    );

    let running_persistence_error = match repository
        .mark_starting_run_running(&run_id, &running_updated_at)
        .await
    {
        Ok(_) => None,
        Err(error) => match repository.managed_run(&run_id).await {
            Ok(record)
                if record.state == RunState::Running
                    && record.process_instance_key.as_ref() == Some(&instance_key) =>
            {
                None
            }
            _ => Some(error),
        },
    };
    if let Some(error) = running_persistence_error {
        let process = take_running_uncommitted(controls, &run_id);
        return Err(terminate_running_after_failure(
            repository,
            controls,
            &run_id,
            &fallback_timestamp,
            process,
            error,
        )
        .await);
    }

    let process = take_running_uncommitted(controls, &run_id);
    replace_control(
        controls,
        &run_id,
        PlatformRunControl::Running(PlatformManagedProcess::Launched {
            process,
            _logs: logs,
        }),
    );
    Ok(result)
}

fn create_managed_log_pipe(stream: LogStream) -> Result<(PipeReader, PipeWriter), AppError> {
    pipe().map_err(|error| managed_log_io_error(stream, "CreatePipe", &error))
}

fn start_managed_log_capture(
    run_id: &str,
    log_publisher: &ManagedLogPublisher,
    log_readers: &ManagedLogReaders,
    collector: ManagedRunLogCollector,
    mut stdout_reader: Box<dyn Read + Send>,
    mut stderr_reader: Box<dyn Read + Send>,
    stdout_text_pipeline: LogTextPipeline,
    stderr_text_pipeline: LogTextPipeline,
) -> Result<ManagedLogCapture, AppError> {
    let ManagedRunLogStreams {
        mut stdout,
        mut stderr,
        event_source,
        range_reader,
    } = collector.into_streams();
    let mut reservation =
        ManagedLogReaderRegistry::reserve_active(log_readers, run_id, range_reader.clone())?;
    let completion = Arc::new(ManagedLogEventCompletion {
        run_id: run_id.to_owned(),
        readers: Arc::clone(log_readers),
    });
    let stdout_completion = Arc::clone(&completion);
    let stdout_worker = thread::Builder::new()
        .name("magictools-log-stdout".into())
        .spawn(move || {
            let _completion = stdout_completion;
            let result = stdout.capture_with_pipeline(&mut stdout_reader, stdout_text_pipeline);
            drop(stdout);
            result
        })
        .map_err(|error| managed_log_io_error(LogStream::Stdout, "SpawnCaptureWorker", &error))?;
    let stderr_completion = Arc::clone(&completion);
    let stderr_worker = thread::Builder::new()
        .name("magictools-log-stderr".into())
        .spawn(move || {
            let _completion = stderr_completion;
            let result = stderr.capture_with_pipeline(&mut stderr_reader, stderr_text_pipeline);
            drop(stderr);
            result
        })
        .map_err(|error| managed_log_io_error(LogStream::Stderr, "SpawnCaptureWorker", &error))?;
    let event_worker = spawn_managed_log_event_worker(
        run_id,
        log_publisher,
        Arc::clone(&completion),
        event_source,
    )?;
    reservation.commit();
    drop(completion);
    Ok(ManagedLogCapture {
        _stdout: stdout_worker,
        _stderr: stderr_worker,
        _events: event_worker,
        range_reader,
    })
}

fn spawn_managed_log_event_worker(
    run_id: &str,
    log_publisher: &ManagedLogPublisher,
    completion: Arc<ManagedLogEventCompletion>,
    mut event_source: ManagedRunLogEventSource,
) -> Result<JoinHandle<()>, AppError> {
    let run_id = run_id.to_owned();
    let log_publisher = log_publisher.clone();
    thread::Builder::new()
        .name("magictools-log-events".into())
        .spawn(move || {
            let _completion = completion;
            while let Ok(Some(events)) = event_source.recv_batch() {
                let chunks = events
                    .into_iter()
                    .map(|event| ManagedLogChunk {
                        run_id: run_id.clone(),
                        stream: managed_log_stream(event.stream),
                        sequence: event.sequence,
                        first_available_byte_offset: event.first_available,
                        first_byte_offset: event.first,
                        next_byte_offset: event.next,
                        stream_end_byte_offset: event.end,
                        text: event.text,
                        has_more: event.has_more,
                        caught_up: event.complete,
                        end_of_file: event.end_of_file,
                        io_status_known: event.io_status_known,
                        disk_error: event.disk_error.map(managed_log_io_error_kind),
                        read_error: event.read_error.map(managed_log_io_error_kind),
                        delivery_error: event.delivery_error.map(managed_log_io_error_kind),
                        text_status: managed_log_text_status(event.text_status),
                    })
                    .collect();
                if log_publisher
                    .publish(Arc::new(ManagedLogBatch { chunks }))
                    .is_err()
                {
                    return;
                }
            }
        })
        .map_err(|error| managed_log_background_error("SpawnEventWorker", &error))
}

fn managed_log_stream(stream: LogStream) -> ManagedLogStream {
    match stream {
        LogStream::Stdout => ManagedLogStream::Stdout,
        LogStream::Stderr => ManagedLogStream::Stderr,
    }
}

fn logging_stream(stream: ManagedLogStream) -> LogStream {
    match stream {
        ManagedLogStream::Stdout => LogStream::Stdout,
        ManagedLogStream::Stderr => LogStream::Stderr,
    }
}

fn managed_log_redaction_rules(
    environment: &ResolvedEnvironment,
) -> Result<LogRedactionRules, AppError> {
    LogRedactionRules::from_secrets(environment.entries().iter().filter_map(|entry| {
        match entry.value() {
            ResolvedEnvironmentValue::Secret(secret) => Some(secret.expose_utf8()),
            ResolvedEnvironmentValue::Plain(value) if is_sensitive_field_name(entry.name()) => {
                Some(value.as_str())
            }
            ResolvedEnvironmentValue::Plain(_) => None,
        }
    }))
    .map_err(managed_log_redaction_error)
}

fn prepare_managed_log_text_pipelines(
    execution: &LaunchExecution,
    interactive: bool,
    redaction_rules: &LogRedactionRules,
) -> Result<(LogTextPipeline, LogTextPipeline), AppError> {
    let policy = if interactive {
        // ConPTY and the macOS terminal path expose a UTF-8 byte stream. The
        // platform code-page fallback is only valid for ordinary Windows pipes.
        LogEncodingPolicy::Utf8
    } else {
        managed_log_encoding_policy(execution)?
    };
    let stdout = LogTextPipeline::with_redactor(policy, redaction_rules.stream())
        .map_err(managed_log_text_error)?;
    let stderr = LogTextPipeline::with_redactor(policy, redaction_rules.stream())
        .map_err(managed_log_text_error)?;
    Ok((stdout, stderr))
}

#[cfg(windows)]
fn managed_log_encoding_policy(execution: &LaunchExecution) -> Result<LogEncodingPolicy, AppError> {
    let code_page = match execution {
        LaunchExecution::Direct(_) => unsafe { GetACP() },
        LaunchExecution::Shell(shell) => match shell.shell {
            ShellKind::PowerShell | ShellKind::Cmd => unsafe { GetOEMCP() },
            ShellKind::Zsh => {
                return Err(AppError::new(
                    ErrorCode::NotSupported,
                    "the selected shell has no Windows log encoding policy",
                ));
            }
        },
    };
    let fallback_code_page = u16::try_from(code_page).map_err(|_| {
        AppError::new(
            ErrorCode::PlatformError,
            "the Windows log encoding code page is invalid",
        )
    })?;
    Ok(LogEncodingPolicy::WindowsAuto { fallback_code_page })
}

#[cfg(target_os = "macos")]
fn managed_log_encoding_policy(
    _execution: &LaunchExecution,
) -> Result<LogEncodingPolicy, AppError> {
    Ok(LogEncodingPolicy::Utf8)
}

fn managed_log_text_status(status: Option<LogTextStatus>) -> ManagedLogTextStatus {
    let Some(status) = status else {
        return ManagedLogTextStatus::Unknown;
    };
    let Some(resolved_encoding) = status.resolved_encoding else {
        return ManagedLogTextStatus::Unknown;
    };
    ManagedLogTextStatus::Known {
        encoding: managed_log_encoding(resolved_encoding),
        replacement_used: status.replacement_used,
        controls_filtered: status.controls_filtered,
        fallback_unavailable: status.fallback_unavailable,
    }
}

fn managed_log_encoding(encoding: ResolvedLogEncoding) -> ManagedLogEncoding {
    match encoding {
        ResolvedLogEncoding::Utf8 => ManagedLogEncoding::Utf8,
        ResolvedLogEncoding::Utf16LittleEndian => ManagedLogEncoding::Utf16Le,
        ResolvedLogEncoding::Utf16BigEndian => ManagedLogEncoding::Utf16Be,
        ResolvedLogEncoding::WindowsCodePage(code_page) => {
            ManagedLogEncoding::WindowsCodePage { code_page }
        }
    }
}

fn managed_log_text_error(source: LogTextError) -> AppError {
    let mut error = AppError::new(
        ErrorCode::NotSupported,
        "managed run log encoding is not supported",
    );
    error
        .details
        .insert("stage".into(), "PrepareManagedLogText".into());
    match source {
        LogTextError::UnsupportedWindowsCodePage { code_page } => {
            error
                .details
                .insert("codePage".into(), code_page.to_string());
        }
    }
    error
}

fn managed_log_redaction_error(source: LogRedactionError) -> AppError {
    let reason = match source {
        LogRedactionError::PatternTooLong => "patternTooLong",
        LogRedactionError::TooManyPatterns => "tooManyPatterns",
        LogRedactionError::TotalPatternBytesExceeded => "totalPatternBytesExceeded",
    };
    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "managed run log redaction rules are invalid",
    );
    error
        .details
        .insert("stage".into(), "PrepareManagedLogRedaction".into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn managed_log_io_error_kind(kind: LogErrorKind) -> ManagedLogIoErrorKind {
    match kind {
        LogErrorKind::InvalidConfiguration => ManagedLogIoErrorKind::InvalidConfiguration,
        LogErrorKind::InvalidPath => ManagedLogIoErrorKind::InvalidPath,
        LogErrorKind::NotFound => ManagedLogIoErrorKind::NotFound,
        LogErrorKind::PermissionDenied => ManagedLogIoErrorKind::PermissionDenied,
        LogErrorKind::AlreadyExists => ManagedLogIoErrorKind::AlreadyExists,
        LogErrorKind::ResourceBusy => ManagedLogIoErrorKind::ResourceBusy,
        LogErrorKind::StorageFull => ManagedLogIoErrorKind::StorageFull,
        LogErrorKind::Interrupted => ManagedLogIoErrorKind::Interrupted,
        LogErrorKind::UnexpectedEof => ManagedLogIoErrorKind::UnexpectedEof,
        LogErrorKind::InvalidData => ManagedLogIoErrorKind::InvalidData,
        LogErrorKind::LimitExceeded => ManagedLogIoErrorKind::LimitExceeded,
        LogErrorKind::WriteZero => ManagedLogIoErrorKind::WriteZero,
        LogErrorKind::Unavailable => ManagedLogIoErrorKind::Unavailable,
        LogErrorKind::OtherIo => ManagedLogIoErrorKind::OtherIo,
    }
}

fn managed_log_registry_error() -> AppError {
    AppError::new(ErrorCode::Internal, "managed log registry is unavailable")
}

fn managed_log_retention_error(source: LogError) -> AppError {
    let code = match source.kind() {
        LogErrorKind::PermissionDenied => ErrorCode::AccessDenied,
        LogErrorKind::InvalidConfiguration | LogErrorKind::InvalidPath => {
            ErrorCode::InvalidArgument
        }
        _ => ErrorCode::StorageError,
    };
    let mut error = AppError::new(code, "managed run log retention operation failed");
    error.retryable = matches!(
        source.kind(),
        LogErrorKind::Interrupted | LogErrorKind::ResourceBusy
    );
    error
        .details
        .insert("stage".into(), "RetainManagedRunLogs".into());
    error
        .details
        .insert("logOperation".into(), format!("{:?}", source.operation()));
    error
        .details
        .insert("logErrorKind".into(), format!("{:?}", source.kind()));
    error
}

fn managed_log_retention_worker_error() -> AppError {
    let mut error = AppError::new(
        ErrorCode::Internal,
        "managed run log retention worker failed",
    );
    error.retryable = true;
    error
}

fn managed_log_retention_clock_error() -> AppError {
    AppError::new(
        ErrorCode::PlatformError,
        "managed run log retention cutoff could not be calculated",
    )
}

fn managed_log_retention_capacity_error() -> AppError {
    let mut error = AppError::new(
        ErrorCode::StorageError,
        "managed run log retention capacity is not yet available",
    );
    error.retryable = true;
    error.details.insert(
        "maximumRetainedBytes".into(),
        MANAGED_LOG_RETENTION_MAX_TOTAL_BYTES.to_string(),
    );
    error
}

fn managed_log_retention_identity_error() -> AppError {
    let mut error = AppError::new(
        ErrorCode::StorageError,
        "managed run log retention identity is inconsistent",
    );
    error
        .details
        .insert("stage".into(), "ValidateManagedLogRetentionIdentity".into());
    error
}

fn managed_log_retention_expired_error() -> AppError {
    let mut error = AppError::new(
        ErrorCode::NotFound,
        "managed run logs are no longer retained",
    );
    error
        .details
        .insert("reason".into(), "retentionExpired".into());
    error
}

fn managed_log_redaction_provenance_error() -> AppError {
    let mut error = AppError::new(
        ErrorCode::NotSupported,
        "managed run log redaction provenance is unavailable",
    );
    error
        .details
        .insert("reason".into(), "untrustedLogRedactionVersion".into());
    error
}

fn managed_log_active_capacity_error() -> AppError {
    let mut error = AppError::new(
        ErrorCode::Conflict,
        "managed log active-run capacity is exhausted",
    );
    error.retryable = true;
    error.details.insert(
        "maximumActiveRuns".into(),
        MAX_ACTIVE_MANAGED_LOG_RUNS.to_string(),
    );
    error
}

fn stale_managed_log_offset_error() -> AppError {
    let mut error = AppError::new(
        ErrorCode::Conflict,
        "managed log offset generation is no longer available",
    );
    error.retryable = true;
    error
        .details
        .insert("reason".into(), "staleLogOffsetGeneration".into());
    error
        .details
        .insert("recovery".into(), "omitStartingByteOffset".into());
    error
}

fn managed_log_error(source: LogError) -> AppError {
    let code = match source.kind() {
        LogErrorKind::PermissionDenied => ErrorCode::AccessDenied,
        LogErrorKind::InvalidConfiguration | LogErrorKind::InvalidPath => ErrorCode::Internal,
        _ => ErrorCode::StorageError,
    };
    let mut error = AppError::new(code, "managed run log preparation failed");
    error.retryable = matches!(
        source.kind(),
        LogErrorKind::Interrupted | LogErrorKind::ResourceBusy
    );
    error
        .details
        .insert("stage".into(), "PrepareManagedRunLogs".into());
    error
        .details
        .insert("logOperation".into(), format!("{:?}", source.operation()));
    error
        .details
        .insert("logErrorKind".into(), format!("{:?}", source.kind()));
    if let Some(stream) = source.stream() {
        error.details.insert("logStream".into(), stream.to_string());
    }
    if source.accepted_input_bytes() != 0 {
        error.details.insert(
            "acceptedInputBytes".into(),
            source.accepted_input_bytes().to_string(),
        );
    }
    error
}

fn managed_log_read_error(source: LogError) -> AppError {
    let code = match source.kind() {
        LogErrorKind::PermissionDenied => ErrorCode::AccessDenied,
        LogErrorKind::InvalidConfiguration | LogErrorKind::InvalidPath => {
            ErrorCode::InvalidArgument
        }
        LogErrorKind::NotFound => ErrorCode::NotFound,
        _ => ErrorCode::StorageError,
    };
    let mut error = AppError::new(code, "managed run log range could not be read");
    error.retryable = matches!(
        source.kind(),
        LogErrorKind::Interrupted | LogErrorKind::ResourceBusy
    );
    error
        .details
        .insert("stage".into(), "ReadManagedRunLogs".into());
    error
        .details
        .insert("logOperation".into(), format!("{:?}", source.operation()));
    error
        .details
        .insert("logErrorKind".into(), format!("{:?}", source.kind()));
    if let Some(stream) = source.stream() {
        error.details.insert("logStream".into(), stream.to_string());
    }
    error
}

fn managed_log_io_error(
    stream: LogStream,
    stage: &'static str,
    source: &std::io::Error,
) -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "managed run log pipe setup failed",
    );
    error.retryable = matches!(
        source.kind(),
        std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::ResourceBusy
    );
    error.details.insert("stage".into(), stage.into());
    error.details.insert("logStream".into(), stream.to_string());
    error
        .details
        .insert("ioKind".into(), format!("{:?}", source.kind()));
    error
}

fn managed_log_background_error(stage: &'static str, source: &std::io::Error) -> AppError {
    let mut error = AppError::new(
        ErrorCode::PlatformError,
        "managed run log worker could not be started",
    );
    error.retryable = matches!(
        source.kind(),
        std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::ResourceBusy
    );
    error.details.insert("stage".into(), stage.into());
    error
        .details
        .insert("ioKind".into(), format!("{:?}", source.kind()));
    error
}

async fn create_starting_intent(
    repository: &mut SupervisorRepository,
    controls: &mut HashMap<String, PlatformRunControl>,
    log_root: &Path,
    profile: &domain::LaunchProfile,
) -> Result<ManagedRunRecord, AppError> {
    for _ in 0..RUN_ID_ALLOCATION_ATTEMPTS {
        let run_id = generate_run_id()?;
        if controls.contains_key(&run_id) {
            continue;
        }
        let started_at = current_timestamp()?;
        let log_directory = log_root.join(&run_id);
        let log_directory = log_directory.to_str().ok_or_else(|| {
            AppError::new(
                ErrorCode::Internal,
                "managed run log directory could not be represented as Unicode",
            )
        })?;
        match repository
            .create_starting_run(&run_id, profile, log_directory, &started_at)
            .await
        {
            Ok(record) => {
                match controls.entry(run_id) {
                    Entry::Vacant(entry) => {
                        entry.insert(PlatformRunControl::StartingIntent);
                    }
                    Entry::Occupied(_) => {
                        return Err(AppError::new(
                            ErrorCode::Internal,
                            "managed run control ID collided after persistence",
                        ));
                    }
                }
                return Ok(record);
            }
            Err(error) if run_id_collision(&error, &run_id) => continue,
            Err(error) => return Err(error),
        }
    }
    Err(AppError::new(
        ErrorCode::Internal,
        "failed to allocate a unique managed run ID",
    ))
}

fn platform_launch_plan(
    preview: FinalExecutionPreview,
) -> Result<(Vec<String>, Vec<String>), AppError> {
    if preview.platform != active_platform() {
        return Err(AppError::new(
            ErrorCode::NotSupported,
            "execution preview is not supported by this managed launcher",
        ));
    }
    let argv = match preview.invocation {
        ExecutionInvocationPreview::Direct(invocation) => invocation.argv,
        ExecutionInvocationPreview::Shell(invocation) => invocation.argv,
    };
    match preview.executable_resolution {
        ExecutableResolution::Unknown(resolution)
            if matches!(
                resolution.reason,
                ExecutableUnknownReason::PathCredentialReference
                    | ExecutableUnknownReason::PathExtensionCredentialReference
            ) =>
        {
            Err(AppError::new(
                ErrorCode::NotSupported,
                "credential-backed executable search paths require an explicit executable",
            ))
        }
        ExecutableResolution::Unknown(resolution) if !resolution.candidates.is_empty() => Ok((
            argv,
            resolution
                .candidates
                .into_iter()
                .map(|candidate| candidate.path)
                .collect(),
        )),
        ExecutableResolution::NotSupported(_) => Err(AppError::new(
            ErrorCode::NotSupported,
            "managed run executable is not supported on this platform",
        )),
        ExecutableResolution::Unknown(_) | ExecutableResolution::NotFound(_) => Err(AppError::new(
            ErrorCode::NotFound,
            "managed run executable could not be resolved",
        )),
    }
}

fn validate_working_directory(path: &str) -> Result<(), AppError> {
    match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(invalid_working_directory(
            ErrorCode::InvalidArgument,
            "must identify a directory",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(
            invalid_working_directory(ErrorCode::NotFound, "does not exist"),
        ),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => Err(
            invalid_working_directory(ErrorCode::AccessDenied, "is not accessible"),
        ),
        Err(_) => Err(invalid_working_directory(
            ErrorCode::PlatformError,
            "could not be inspected",
        )),
    }
}

fn invalid_working_directory(code: ErrorCode, reason: &'static str) -> AppError {
    let mut error = AppError::new(code, "managed run working directory is unavailable");
    error
        .details
        .insert("field".into(), "workingDirectory".into());
    error.details.insert("reason".into(), reason.into());
    error
}

async fn abort_suspended_after_failure(
    repository: &mut SupervisorRepository,
    controls: &mut HashMap<String, PlatformRunControl>,
    run_id: &str,
    fallback_timestamp: &str,
    suspended: SuspendedManagedProcess,
    stage: LaunchFailureStage,
    error: AppError,
) -> AppError {
    match suspended.abort() {
        Ok(()) => {
            record_failed_launch(
                repository,
                controls,
                run_id,
                stage,
                fallback_timestamp,
                error,
            )
            .await
        }
        Err(cleanup) => {
            record_native_failure(
                repository,
                controls,
                run_id,
                stage,
                fallback_timestamp,
                cleanup,
                Some(error),
            )
            .await
        }
    }
}

async fn terminate_running_after_failure(
    repository: &mut SupervisorRepository,
    controls: &mut HashMap<String, PlatformRunControl>,
    run_id: &str,
    fallback_timestamp: &str,
    process: ManagedProcess,
    error: AppError,
) -> AppError {
    match process.terminate_and_wait() {
        Ok(()) => {
            record_failed_launch(
                repository,
                controls,
                run_id,
                LaunchFailureStage::RunningPersistence,
                fallback_timestamp,
                error,
            )
            .await
        }
        Err(cleanup) => {
            record_native_failure(
                repository,
                controls,
                run_id,
                LaunchFailureStage::RunningPersistence,
                fallback_timestamp,
                cleanup,
                Some(error),
            )
            .await
        }
    }
}

async fn record_native_failure(
    repository: &mut SupervisorRepository,
    controls: &mut HashMap<String, PlatformRunControl>,
    run_id: &str,
    stage: LaunchFailureStage,
    _fallback_timestamp: &str,
    native: ManagedLaunchError,
    preferred_error: Option<AppError>,
) -> AppError {
    let mut public = preferred_error.unwrap_or_else(|| native.public_error().clone());
    if native.cleanup_pending() {
        public
            .details
            .insert("cleanupPending".into(), "true".into());
        replace_control(controls, run_id, PlatformRunControl::CleanupPending(native));
        let updated_at = match next_managed_run_timestamp(repository, run_id).await {
            Ok(updated_at) => updated_at,
            Err(_) => {
                public
                    .details
                    .insert("runStatePersistence".into(), "failed".into());
                public.details.insert("runId".into(), run_id.into());
                return public;
            }
        };
        match repository
            .mark_starting_run_orphaned(run_id, LaunchFailureStage::Cleanup, &updated_at)
            .await
        {
            Ok(_) => {
                public.details.insert("runState".into(), "orphaned".into());
            }
            Err(_) => {
                public
                    .details
                    .insert("runStatePersistence".into(), "failed".into());
            }
        }
        public.details.insert("runId".into(), run_id.into());
        public
    } else {
        drop(native);
        record_failed_launch(
            repository,
            controls,
            run_id,
            stage,
            _fallback_timestamp,
            public,
        )
        .await
    }
}

async fn record_failed_launch(
    repository: &mut SupervisorRepository,
    controls: &mut HashMap<String, PlatformRunControl>,
    run_id: &str,
    stage: LaunchFailureStage,
    _fallback_timestamp: &str,
    mut error: AppError,
) -> AppError {
    let updated_at = match next_managed_run_timestamp(repository, run_id).await {
        Ok(updated_at) => updated_at,
        Err(_) => {
            error
                .details
                .insert("runStatePersistence".into(), "failed".into());
            controls.remove(run_id);
            error.details.insert("runId".into(), run_id.into());
            return error;
        }
    };
    match repository
        .mark_starting_run_failed(run_id, stage, &updated_at)
        .await
    {
        Ok(_) => {
            error.details.insert("runState".into(), "failed".into());
        }
        Err(_) => {
            error
                .details
                .insert("runStatePersistence".into(), "failed".into());
        }
    }
    controls.remove(run_id);
    error.details.insert("runId".into(), run_id.into());
    error
}

async fn next_managed_run_timestamp(
    repository: &SupervisorRepository,
    run_id: &str,
) -> Result<String, AppError> {
    let current = repository.managed_run(run_id).await?;
    next_canonical_timestamp(Some(&current.updated_at))
}

fn projected_running_result(
    record: &ManagedRunRecord,
    updated_at: &str,
) -> Result<StartManagedRunResult, AppError> {
    let profile_id = record.profile_id.clone().ok_or_else(|| {
        AppError::new(
            ErrorCode::Internal,
            "managed run lost its launch profile identity",
        )
    })?;
    let process_group_id = summary_process_group_id(record)?;
    let result = StartManagedRunResult {
        run: ManagedRunSummary {
            run_id: record.id.clone(),
            profile_id,
            profile_updated_at: record.profile_snapshot.updated_at.clone(),
            state: RunState::Running,
            process_instance_key: record.process_instance_key.clone(),
            process_group_id,
            started_at: record.started_at.clone(),
            updated_at: updated_at.to_owned(),
            ended_at: None,
        },
    };
    lifecycle::validate_start_managed_run_result(&result)?;
    Ok(result)
}

#[cfg(windows)]
fn summary_process_group_id(record: &ManagedRunRecord) -> Result<Option<u32>, AppError> {
    if record.process_group_id.is_some() {
        return Err(AppError::new(
            ErrorCode::Internal,
            "Windows Job-managed run unexpectedly stored a process group",
        ));
    }
    Ok(None)
}

#[cfg(target_os = "macos")]
fn summary_process_group_id(record: &ManagedRunRecord) -> Result<Option<u32>, AppError> {
    record.process_group_id.map(Some).ok_or_else(|| {
        AppError::new(
            ErrorCode::Internal,
            "macOS managed run lost its controlled process group",
        )
    })
}

fn executable_candidate_was_not_found(error: &ManagedLaunchError) -> bool {
    !error.cleanup_pending()
        && error.public_error().code == ErrorCode::NotFound
        && error
            .public_error()
            .details
            .get("stage")
            .is_some_and(|stage| {
                matches!(
                    stage.as_str(),
                    "OpenRequestedExecutable" | "CreateProcessW" | "posix_spawn"
                )
            })
}

fn native_failure_stage(error: &ManagedLaunchError) -> LaunchFailureStage {
    let details = &error.public_error().details;
    match details
        .get("stage")
        .or_else(|| details.get("cleanupStage"))
        .map(String::as_str)
    {
        Some("CreateJobObjectW") => LaunchFailureStage::JobCreation,
        Some("SetInformationJobObject") => LaunchFailureStage::JobConfiguration,
        Some("OpenRequestedExecutable") | Some("GetRequestedExecutableFileId") => {
            LaunchFailureStage::ExecutableResolution
        }
        Some("OpenStandardInputNull")
        | Some("DuplicateStandardInput")
        | Some("DuplicateStandardOutput")
        | Some("DuplicateStandardError")
        | Some("InitializeProcThreadAttributeList(size)")
        | Some("InitializeProcThreadAttributeList")
        | Some("UpdateProcThreadAttribute(handleList)")
        | Some("CreatePseudoConsoleInputPipe")
        | Some("CreatePseudoConsoleOutputPipe")
        | Some("CreatePseudoConsole")
        | Some("UpdateProcThreadAttribute(pseudoConsole)")
        | Some("fcntl(F_DUPFD_CLOEXEC, stdout)")
        | Some("fcntl(F_DUPFD_CLOEXEC, stderr)")
        | Some("openpty")
        | Some("fcntl(F_DUPFD_CLOEXEC, pty-master)")
        | Some("fcntl(F_DUPFD_CLOEXEC, pty-slave)")
        | Some("fcntl(F_DUPFD_CLOEXEC, pty-output)")
        | Some("posix_spawn_file_actions_adddup2(stdout)")
        | Some("posix_spawn_file_actions_addclose(stdout-source)")
        | Some("posix_spawn_file_actions_adddup2(stderr)")
        | Some("posix_spawn_file_actions_addclose(stderr-source)")
        | Some("posix_spawn_file_actions_adddup2(pty-stdin)")
        | Some("posix_spawn_file_actions_adddup2(pty-stdout)")
        | Some("posix_spawn_file_actions_adddup2(pty-stderr)")
        | Some("posix_spawn_file_actions_addclose(pty-slave)") => {
            LaunchFailureStage::LogPreparation
        }
        Some("CreateProcessW") => LaunchFailureStage::ProcessCreation,
        Some("posix_spawn")
        | Some("ValidateLaunchRequest")
        | Some("posix_spawnattr_init")
        | Some("posix_spawnattr_setpgroup")
        | Some("sigemptyset(mask)")
        | Some("posix_spawnattr_setsigmask")
        | Some("sigemptyset(defaults)")
        | Some("sigaddset(defaults)")
        | Some("posix_spawnattr_setsigdefault")
        | Some("posix_spawnattr_setflags")
        | Some("posix_spawn_file_actions_init")
        | Some("posix_spawn_file_actions_addchdir_np")
        | Some("posix_spawn_file_actions_addopen(stdin)")
        | Some("posix_spawn_file_actions_addopen(stdout)")
        | Some("posix_spawn_file_actions_addopen(stderr)") => LaunchFailureStage::ProcessCreation,
        Some("AssignProcessToJobObject") => LaunchFailureStage::JobAssignment,
        Some("GetProcessTimes")
        | Some("QueryFullProcessImageNameW")
        | Some("OpenCreatedProcessImage")
        | Some("GetCreatedProcessImageFileId")
        | Some("QueryBootIdentifier")
        | Some("proc_pidinfo(PROC_PIDTBSDINFO)")
        | Some("getpgid")
        | Some("RevalidateProcessIdentity")
        | Some("RevalidateProcessGroup") => LaunchFailureStage::IdentityRead,
        Some("ResumeThread") | Some("SIGCONT") => LaunchFailureStage::ProcessResume,
        Some("TerminateJobObject")
        | Some("TerminateProcess")
        | Some("WaitForSingleObject")
        | Some("kill(SIGKILL)")
        | Some("killpg(SIGKILL)")
        | Some("killpg(0)")
        | Some("waitpid") => LaunchFailureStage::Cleanup,
        _ => LaunchFailureStage::IdentityRead,
    }
}

fn redact_credential_error(source: AppError) -> AppError {
    let mut error = AppError::new(source.code, "managed run credentials could not be resolved");
    error.retryable = source.retryable;
    error
}

fn profile_revision_conflict(request: &StartManagedRunRequest, actual: &str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Conflict,
        "launch profile changed before the managed run started",
    );
    error
        .details
        .insert("profileId".into(), request.profile_id.clone());
    error.details.insert(
        "expectedUpdatedAt".into(),
        request.expected_profile_updated_at.clone(),
    );
    error
        .details
        .insert("actualUpdatedAt".into(), actual.into());
    error
}

fn replace_project_in_context(
    context: &mut ProjectContextSnapshot,
    project: &ProjectSummary,
    trusted_root: &NormalizedProjectRoot,
) -> Result<(), AppError> {
    let registered = RegisteredProject {
        id: project.id.clone(),
        root_directory: trusted_root.canonical_root_directory().to_owned(),
        normalized_path: trusted_root.normalized_path().clone(),
    };
    match context
        .catalog
        .projects
        .iter_mut()
        .find(|current| current.id == project.id)
    {
        Some(current) => *current = registered,
        None => context.catalog.projects.push(registered),
    }
    synchronize_known_project_ids(context);
    Ok(())
}

fn remove_project_from_context(
    context: &mut ProjectContextSnapshot,
    project_id: &str,
) -> Result<(), AppError> {
    let previous_len = context.catalog.projects.len();
    context
        .catalog
        .projects
        .retain(|project| project.id != project_id);
    if context.catalog.projects.len() == previous_len {
        return Err(missing_catalog_context_entity("project", project_id));
    }
    synchronize_known_project_ids(context);
    Ok(())
}

fn synchronize_known_project_ids(context: &mut ProjectContextSnapshot) {
    let mut project_ids = context
        .catalog
        .projects
        .iter()
        .map(|project| project.id.clone())
        .collect::<Vec<_>>();
    project_ids.sort();
    context.classification_rules.known_project_ids = project_ids;
}

fn replace_rule_in_context(
    context: &mut ProjectContextSnapshot,
    rule: &ClassificationRuleSummary,
) -> Result<(), AppError> {
    let rule = classification_rule_for_discovery(rule);
    match context
        .classification_rules
        .rules
        .iter_mut()
        .find(|current| current.id == rule.id)
    {
        Some(current) => *current = rule,
        None => context.classification_rules.rules.push(rule),
    }
    Ok(())
}

fn remove_rule_from_context(
    context: &mut ProjectContextSnapshot,
    rule_id: &str,
) -> Result<(), AppError> {
    let previous_len = context.classification_rules.rules.len();
    context
        .classification_rules
        .rules
        .retain(|rule| rule.id != rule_id);
    if context.classification_rules.rules.len() == previous_len {
        return Err(missing_catalog_context_entity(
            "classificationRule",
            rule_id,
        ));
    }
    Ok(())
}

fn classification_rule_for_discovery(
    summary: &ClassificationRuleSummary,
) -> DiscoveryClassificationRule {
    let matcher = match summary.input.matcher_kind {
        ClassificationRuleMatcherKind::ExecutableNameExact => {
            DiscoveryClassificationRuleMatcher::ExecutableNameExact(summary.input.pattern.clone())
        }
        ClassificationRuleMatcherKind::ExecutablePathExact => {
            DiscoveryClassificationRuleMatcher::ExecutablePathExact(summary.input.pattern.clone())
        }
        ClassificationRuleMatcherKind::CommandLineContains => {
            DiscoveryClassificationRuleMatcher::CommandLineContains(summary.input.pattern.clone())
        }
        ClassificationRuleMatcherKind::WorkingDirectoryPrefix => {
            DiscoveryClassificationRuleMatcher::WorkingDirectoryPrefix(
                summary.input.pattern.clone(),
            )
        }
    };
    let action = match &summary.input.action {
        ClassificationRuleAction::Include => DiscoveryClassificationRuleAction::Include,
        ClassificationRuleAction::Exclude => DiscoveryClassificationRuleAction::Exclude,
        ClassificationRuleAction::AssignProject { project_id } => {
            DiscoveryClassificationRuleAction::AssignProject(project_id.clone())
        }
    };
    DiscoveryClassificationRule {
        id: summary.id.clone(),
        matcher,
        action,
        priority: i64::from(summary.input.priority),
        enabled: summary.input.enabled,
    }
}

fn validate_project_context(context: &ProjectContextSnapshot) -> Result<(), AppError> {
    let catalog = ProjectCatalog::new(context.catalog.clone())?;
    let catalog_ids = catalog.project_ids();
    let mut classification_ids = context.classification_rules.known_project_ids.clone();
    classification_ids.sort();
    if catalog_ids != classification_ids {
        let mut error = AppError::new(
            ErrorCode::Internal,
            "prospective project context contains mismatched project identities",
        );
        error
            .details
            .insert("catalogProjects".into(), catalog_ids.len().to_string());
        error.details.insert(
            "classificationProjects".into(),
            classification_ids.len().to_string(),
        );
        return Err(error);
    }
    ClassificationEngine::new(context.classification_rules.clone())?;
    Ok(())
}

async fn publish_and_commit_catalog_mutation<T>(
    repository: &mut SupervisorRepository,
    discovery_scheduler: &DiscoverySchedulerHandle,
    prospective: ProjectContextSnapshot,
    prepared: PreparedCatalogMutation<T>,
) -> Result<T, AppError> {
    if let Err(mut publish_error) = discovery_scheduler
        .replace_project_context(prospective)
        .await
    {
        publish_error.details.insert(
            "catalogMutationFailurePhase".into(),
            "schedulerPublish".into(),
        );
        match prepared.rollback().await {
            Ok(()) => {
                publish_error
                    .details
                    .insert("catalogTransactionRollback".into(), "succeeded".into());
            }
            Err(rollback_error) => {
                publish_error
                    .details
                    .insert("catalogTransactionRollback".into(), "failed".into());
                publish_error.details.insert(
                    "catalogTransactionRollbackErrorCode".into(),
                    format!("{:?}", rollback_error.code),
                );
                publish_error.retryable = true;
            }
        }
        return Err(reconcile_catalog_context_from_storage(
            repository,
            discovery_scheduler,
            publish_error,
        )
        .await);
    }

    match prepared.commit().await {
        Ok(result) => Ok(result),
        Err(mut commit_error) => {
            commit_error
                .details
                .insert("catalogMutationFailurePhase".into(), "commit".into());
            commit_error.retryable = true;
            Err(reconcile_catalog_context_from_storage(
                repository,
                discovery_scheduler,
                commit_error,
            )
            .await)
        }
    }
}

async fn rollback_unpublished_catalog_mutation<T>(
    repository: &mut SupervisorRepository,
    discovery_scheduler: &DiscoverySchedulerHandle,
    prepared: PreparedCatalogMutation<T>,
    mut error: AppError,
) -> AppError {
    error.details.insert(
        "catalogMutationFailurePhase".into(),
        "prospectiveValidation".into(),
    );
    match prepared.rollback().await {
        Ok(()) => {
            error
                .details
                .insert("catalogTransactionRollback".into(), "succeeded".into());
        }
        Err(rollback_error) => {
            error
                .details
                .insert("catalogTransactionRollback".into(), "failed".into());
            error.details.insert(
                "catalogTransactionRollbackErrorCode".into(),
                format!("{:?}", rollback_error.code),
            );
            error.retryable = true;
        }
    }
    reconcile_catalog_context_from_storage(repository, discovery_scheduler, error).await
}

async fn reconcile_catalog_context_from_storage(
    repository: &mut SupervisorRepository,
    discovery_scheduler: &DiscoverySchedulerHandle,
    mut error: AppError,
) -> AppError {
    let durable_context = match repository.project_context_snapshot().await {
        Ok(context) => context,
        Err(read_error) => {
            error.details.insert(
                "catalogContextReconcileStatus".into(),
                "durableReadFailed".into(),
            );
            error.details.insert(
                "catalogContextReconcileErrorCode".into(),
                format!("{:?}", read_error.code),
            );
            error.retryable = true;
            return error;
        }
    };
    match discovery_scheduler
        .replace_project_context(durable_context)
        .await
    {
        Ok(()) => {
            error
                .details
                .insert("catalogContextReconcileStatus".into(), "succeeded".into());
        }
        Err(reconcile_error) => {
            error.details.insert(
                "catalogContextReconcileStatus".into(),
                "schedulerPublishFailed".into(),
            );
            error.details.insert(
                "catalogContextReconcileErrorCode".into(),
                format!("{:?}", reconcile_error.code),
            );
            error.retryable = true;
        }
    }
    error
}

fn missing_catalog_context_entity(entity: &'static str, id: &str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Internal,
        "stored catalog entity is missing from the project context",
    );
    error.details.insert("entity".into(), entity.into());
    error.details.insert("id".into(), id.into());
    error
}

fn require_catalog_version(
    entity: &'static str,
    id_field: &'static str,
    id: &str,
    expected_updated_at: &str,
    actual_updated_at: &str,
) -> Result<(), AppError> {
    if expected_updated_at == actual_updated_at {
        return Ok(());
    }
    let mut error = AppError::new(
        ErrorCode::Conflict,
        format!("{entity} was modified by another operation"),
    );
    error.details.insert(id_field.into(), id.into());
    error
        .details
        .insert("expectedUpdatedAt".into(), expected_updated_at.into());
    error
        .details
        .insert("actualUpdatedAt".into(), actual_updated_at.into());
    Err(error)
}

fn run_id_collision(error: &AppError, run_id: &str) -> bool {
    error.code == ErrorCode::Conflict
        && error
            .details
            .get("runId")
            .is_some_and(|stored| stored == run_id)
}

async fn allocate_project_id(repository: &SupervisorRepository) -> Result<String, AppError> {
    for _ in 0..PROJECT_ID_ALLOCATION_ATTEMPTS {
        let project_id = generate_catalog_id("project-", PROJECT_ID_RANDOM_BYTES)?;
        match repository.project_summary(&project_id).await {
            Ok(_) => continue,
            Err(error) if error.code == ErrorCode::NotFound => return Ok(project_id),
            Err(error) => return Err(error),
        }
    }
    let mut error = AppError::new(
        ErrorCode::Internal,
        "failed to allocate a unique project ID",
    );
    error.retryable = true;
    Err(error)
}

async fn allocate_classification_rule_id(
    repository: &SupervisorRepository,
) -> Result<String, AppError> {
    for _ in 0..RULE_ID_ALLOCATION_ATTEMPTS {
        let rule_id = generate_catalog_id("rule-", RULE_ID_RANDOM_BYTES)?;
        match repository.classification_rule_summary(&rule_id).await {
            Ok(_) => continue,
            Err(error) if error.code == ErrorCode::NotFound => return Ok(rule_id),
            Err(error) => return Err(error),
        }
    }
    let mut error = AppError::new(
        ErrorCode::Internal,
        "failed to allocate a unique classification rule ID",
    );
    error.retryable = true;
    Err(error)
}

fn generate_catalog_id(prefix: &'static str, random_bytes: usize) -> Result<String, AppError> {
    let mut random = vec![0_u8; random_bytes];
    getrandom::fill(&mut random).map_err(|_| {
        AppError::new(
            ErrorCode::PlatformError,
            "failed to generate a catalog entity ID",
        )
    })?;
    let mut result = String::with_capacity(prefix.len() + random_bytes * 2);
    result.push_str(prefix);
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut result, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(result)
}

async fn allocate_launch_profile_id(profiles: &ProfileService) -> Result<String, AppError> {
    for _ in 0..PROFILE_ID_ALLOCATION_ATTEMPTS {
        let profile_id = generate_profile_id()?;
        match profiles.profile(&profile_id).await {
            Ok(_) => continue,
            Err(error) if error.code == ErrorCode::NotFound => return Ok(profile_id),
            Err(error) => return Err(error),
        }
    }
    let mut error = AppError::new(
        ErrorCode::Internal,
        "failed to allocate a unique launch profile ID",
    );
    error.retryable = true;
    Err(error)
}

fn generate_profile_id() -> Result<String, AppError> {
    let mut random = [0_u8; PROFILE_ID_RANDOM_BYTES];
    getrandom::fill(&mut random).map_err(|_| {
        AppError::new(
            ErrorCode::PlatformError,
            "failed to generate a launch profile ID",
        )
    })?;
    let mut result = String::with_capacity(8 + PROFILE_ID_RANDOM_BYTES * 2);
    result.push_str("profile-");
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut result, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(result)
}

fn next_canonical_timestamp(previous: Option<&str>) -> Result<String, AppError> {
    let Some(previous) = previous else {
        return current_timestamp();
    };
    lifecycle::validate_canonical_utc_timestamp("previousUpdatedAt", previous)?;
    if let Ok(timestamp) = current_timestamp()
        && timestamp.as_str() > previous
    {
        return Ok(timestamp);
    }
    advance_canonical_timestamp_one_nanosecond(previous)
}

fn advance_canonical_timestamp_one_nanosecond(value: &str) -> Result<String, AppError> {
    let mut year = value[0..4]
        .parse::<u32>()
        .expect("validated timestamp year");
    let mut month = value[5..7]
        .parse::<u32>()
        .expect("validated timestamp month");
    let mut day = value[8..10]
        .parse::<u32>()
        .expect("validated timestamp day");
    let mut hour = value[11..13]
        .parse::<u32>()
        .expect("validated timestamp hour");
    let mut minute = value[14..16]
        .parse::<u32>()
        .expect("validated timestamp minute");
    let mut second = value[17..19]
        .parse::<u32>()
        .expect("validated timestamp second");
    let mut nanosecond = value[20..29]
        .parse::<u32>()
        .expect("validated timestamp nanosecond");

    nanosecond += 1;
    if nanosecond == 1_000_000_000 {
        nanosecond = 0;
        second += 1;
        if second == 60 {
            second = 0;
            minute += 1;
            if minute == 60 {
                minute = 0;
                hour += 1;
                if hour == 24 {
                    hour = 0;
                    day += 1;
                    if day > catalog_days_in_month(year, month) {
                        day = 1;
                        month += 1;
                        if month == 13 {
                            month = 1;
                            year = year
                                .checked_add(1)
                                .filter(|year| *year <= 9999)
                                .ok_or_else(|| {
                                    AppError::new(
                                        ErrorCode::PlatformError,
                                        "catalog timestamp exceeds the supported range",
                                    )
                                })?;
                        }
                    }
                }
            }
        }
    }
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{nanosecond:09}Z"
    ))
}

fn catalog_days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(400) || (year.is_multiple_of(4) && !year.is_multiple_of(100)) => {
            29
        }
        2 => 28,
        _ => 0,
    }
}

fn generate_run_id() -> Result<String, AppError> {
    let mut random = [0_u8; RUN_ID_RANDOM_BYTES];
    getrandom::fill(&mut random).map_err(|_| {
        AppError::new(
            ErrorCode::PlatformError,
            "failed to generate a managed run ID",
        )
    })?;
    let mut result = String::with_capacity(4 + RUN_ID_RANDOM_BYTES * 2);
    result.push_str("run-");
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut result, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(result)
}

fn current_timestamp() -> Result<String, AppError> {
    timestamp_for_system_time(SystemTime::now())
}

fn timestamp_for_system_time(time: SystemTime) -> Result<String, AppError> {
    let duration = time.duration_since(UNIX_EPOCH).map_err(|_| {
        AppError::new(
            ErrorCode::PlatformError,
            "system clock is before Unix epoch",
        )
    })?;
    let seconds = duration.as_secs();
    let days = i64::try_from(seconds / 86_400).map_err(|_| {
        AppError::new(
            ErrorCode::PlatformError,
            "system clock exceeds the supported timestamp range",
        )
    })?;
    let seconds_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days).ok_or_else(|| {
        AppError::new(
            ErrorCode::PlatformError,
            "system clock exceeds the supported timestamp range",
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

fn replace_control(
    controls: &mut HashMap<String, PlatformRunControl>,
    run_id: &str,
    next: PlatformRunControl,
) {
    let control = controls
        .get_mut(run_id)
        .expect("durable managed run has a control slot");
    *control = next;
}

fn take_suspended(
    controls: &mut HashMap<String, PlatformRunControl>,
    run_id: &str,
) -> SuspendedManagedProcess {
    let control = controls
        .get_mut(run_id)
        .expect("durable managed run has a control slot");
    let previous = std::mem::replace(control, PlatformRunControl::StartingIntent);
    match previous {
        PlatformRunControl::Suspended(process) => process,
        _ => panic!("managed run control was not suspended"),
    }
}

fn take_running_uncommitted(
    controls: &mut HashMap<String, PlatformRunControl>,
    run_id: &str,
) -> ManagedProcess {
    let control = controls
        .get_mut(run_id)
        .expect("durable managed run has a control slot");
    let previous = std::mem::replace(control, PlatformRunControl::StartingIntent);
    match previous {
        PlatformRunControl::RunningUncommitted(process) => process,
        _ => panic!("managed run control was not awaiting Running persistence"),
    }
}
