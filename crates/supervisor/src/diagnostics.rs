use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{SystemTime, UNIX_EPOCH};

use domain::{
    AppError, DiagnosticContentKind, DiagnosticContentPrivacy, DiagnosticManifestItem, ErrorCode,
    ExportDiagnosticsRequest, ExportDiagnosticsResult, GetDiagnosticsManifestResponse,
};
use logging::{
    ApplicationLogBuffer, ApplicationLogError, ApplicationLogRead, DiagnosticContentInput,
    DiagnosticContentManifest, DiagnosticContentProtection, DiagnosticExportStore,
    DiagnosticManifestLimits, LogError, LogErrorKind, LogOperation, MAX_APPLICATION_LOG_READ_BYTES,
};
use protocol::{CancelDisposition, PROTOCOL_MAX_VERSION, PROTOCOL_MIN_VERSION};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use storage::DiagnosticDatabaseSummary;

use crate::ManagedRunService;

const SYSTEM_SUMMARY_CONTENT_ID: &str = "system.summary";
const DATABASE_SUMMARY_CONTENT_ID: &str = "database.summary";
const MAX_SYSTEM_SUMMARY_BYTES: u64 = lifecycle::MAX_DIAGNOSTIC_SYSTEM_SUMMARY_BYTES;
const MAX_DATABASE_SUMMARY_BYTES: u64 = lifecycle::MAX_DIAGNOSTIC_DATABASE_SUMMARY_BYTES;
const MAX_COMPLETED_EXPORT_OPERATIONS: usize = 128;
const MAX_COMPLETED_EXPORT_REQUESTS: usize = 256;

pub type SharedApplicationLogBuffer = Arc<StdMutex<ApplicationLogBuffer>>;

/// Owns the fixed private export capability, the bounded structured
/// application-log ring, cancellation state, and a small in-memory replay
/// ledger. Long-running Supervisor host assembly remains outside this type.
pub struct DiagnosticsService {
    application_logs: SharedApplicationLogBuffer,
    export_store: Arc<DiagnosticExportStore>,
    exports: Arc<StdMutex<ExportRegistry>>,
    next_export_slot: AtomicU8,
}

impl DiagnosticsService {
    pub fn open(
        export_root: impl AsRef<Path>,
        application_logs: SharedApplicationLogBuffer,
    ) -> Result<Self, AppError> {
        let export_store =
            DiagnosticExportStore::open(export_root).map_err(diagnostic_export_error)?;
        Ok(Self {
            application_logs,
            export_store: Arc::new(export_store),
            exports: Arc::new(StdMutex::new(ExportRegistry::default())),
            next_export_slot: AtomicU8::new(0),
        })
    }

    pub fn application_logs(&self) -> SharedApplicationLogBuffer {
        Arc::clone(&self.application_logs)
    }

    /// Returns the default preflight checklist. The final export rebuilds the
    /// same contract with `included` matching the user's exact request.
    pub fn get_manifest(&self) -> Result<GetDiagnosticsManifestResponse, AppError> {
        let result = (|| {
            let log_content = self
                .application_logs
                .lock()
                .map_err(|_| diagnostic_log_registry_error())?
                .diagnostic_content(false);
            build_manifest(false, log_content, None).map(|manifest| manifest.wire)
        })();
        best_effort_diagnostic_event(
            &self.application_logs,
            if result.is_ok() {
                logging::ApplicationLogLevel::Info
            } else {
                logging::ApplicationLogLevel::Error
            },
            "diagnostics.manifest_read",
            &[logging::ApplicationLogField::new(
                logging::ApplicationLogFieldName::Success,
                logging::ApplicationLogValue::Boolean(result.is_ok()),
            )],
        );
        result
    }

    pub async fn export(
        &self,
        managed_runs: &ManagedRunService,
        request_id: &str,
        operation_id: &str,
        request: ExportDiagnosticsRequest,
    ) -> Result<ExportDiagnosticsResult, AppError> {
        lifecycle::validate_export_diagnostics_request(&request)?;
        let reservation = self.reserve_export(request_id, operation_id, &request)?;
        let lease = match reservation {
            ExportReservation::Replay(result) => return Ok(result),
            ExportReservation::Active(lease) => lease,
        };
        let cancellation = Arc::clone(&lease.cancellation);
        best_effort_diagnostic_event(
            &self.application_logs,
            logging::ApplicationLogLevel::Info,
            "diagnostics.export_started",
            &[
                logging::ApplicationLogField::new(
                    logging::ApplicationLogFieldName::Status,
                    logging::ApplicationLogValue::Code("started"),
                ),
                logging::ApplicationLogField::new(
                    logging::ApplicationLogFieldName::Count,
                    logging::ApplicationLogValue::Unsigned(
                        u64::from(request.include_application_logs)
                            + u64::from(request.include_database_summary),
                    ),
                ),
            ],
        );

        let database_summary = if cancellation.load(Ordering::Acquire) {
            Err(cancelled_export_error())
        } else if request.include_database_summary {
            managed_runs.diagnostic_database_summary().await.map(Some)
        } else {
            Ok(None)
        };
        let database_summary = match database_summary {
            Ok(summary) if !cancellation.load(Ordering::Acquire) => summary,
            Ok(_) => {
                let result = Err(cancelled_export_error());
                lease.finish(&result);
                return attach_export_operation_id(result, operation_id);
            }
            Err(error) => {
                let result = Err(error);
                lease.finish(&result);
                return attach_export_operation_id(result, operation_id);
            }
        };

        let application_logs = Arc::clone(&self.application_logs);
        let export_store = Arc::clone(&self.export_store);
        let worker_request = request.clone();
        let worker_cancellation = Arc::clone(&cancellation);
        let export_slot = self.next_export_slot.fetch_add(1, Ordering::Relaxed)
            % logging::DIAGNOSTIC_EXPORT_SLOT_COUNT;
        let file_name = match logging::diagnostic_export_slot_file_name(export_slot)
            .map_err(diagnostic_export_error)
        {
            Ok(file_name) => file_name,
            Err(error) => {
                let result = Err(error);
                lease.finish(&result);
                return attach_export_operation_id(result, operation_id);
            }
        };
        if let Err(error) = invalidate_completed_slot(&self.exports, &file_name) {
            let result = Err(error);
            lease.finish(&result);
            return attach_export_operation_id(result, operation_id);
        }
        let (caller_guard, worker_lease) = lease.into_worker();
        let result = match tokio::task::spawn_blocking(move || {
            let result = build_and_export_bundle(
                &application_logs,
                &export_store,
                &worker_cancellation,
                &worker_request,
                database_summary,
                file_name,
            );
            worker_lease.finish(&result);
            result
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Err(diagnostic_worker_error()),
        };
        let result = attach_export_operation_id(result, operation_id);
        drop(caller_guard);
        result
    }

    /// Hook for the eventual authenticated host's CancelEnvelope router.
    /// Cancellation is request-ID scoped and never guesses by operation ID.
    pub async fn cancel_export(&self, target_request_id: &str) -> CancelDisposition {
        let Ok(exports) = self.exports.lock() else {
            return CancelDisposition::NotFound;
        };
        if let Some(active) = &exports.active
            && active.request_id == target_request_id
        {
            active.cancellation.store(true, Ordering::Release);
            return CancelDisposition::Accepted;
        }
        if exports
            .completed_requests
            .iter()
            .any(|request_id| request_id == target_request_id)
        {
            CancelDisposition::AlreadyCompleted
        } else {
            CancelDisposition::NotFound
        }
    }

    fn reserve_export(
        &self,
        request_id: &str,
        operation_id: &str,
        request: &ExportDiagnosticsRequest,
    ) -> Result<ExportReservation, AppError> {
        let mut exports = self
            .exports
            .lock()
            .map_err(|_| diagnostic_export_registry_error())?;
        if let Some(active) = &exports.active {
            if active.operation_id == operation_id && active.request != *request {
                return Err(export_operation_conflict(operation_id));
            }
            return Err(export_busy_error(operation_id));
        }
        if let Some(completed) = exports.completed_operations.get(operation_id) {
            if completed.request != *request {
                return Err(export_operation_conflict(operation_id));
            }
            let result = completed.result.clone();
            remember_completed_request(&mut exports.completed_requests, request_id);
            return Ok(ExportReservation::Replay(result));
        }
        let cancellation = Arc::new(AtomicBool::new(false));
        exports.active = Some(ActiveExport {
            request_id: request_id.to_owned(),
            operation_id: operation_id.to_owned(),
            request: request.clone(),
            cancellation: Arc::clone(&cancellation),
        });
        drop(exports);
        Ok(ExportReservation::Active(PendingExportLease {
            registry: Arc::clone(&self.exports),
            application_logs: Arc::clone(&self.application_logs),
            request_id: request_id.to_owned(),
            operation_id: operation_id.to_owned(),
            request: request.clone(),
            cancellation,
            completed: Arc::new(AtomicBool::new(false)),
            finished: false,
        }))
    }
}

impl std::fmt::Debug for DiagnosticsService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DiagnosticsService")
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct ExportRegistry {
    active: Option<ActiveExport>,
    completed_operations: HashMap<String, CompletedExport>,
    completed_operation_order: VecDeque<String>,
    completed_requests: VecDeque<String>,
}

struct ActiveExport {
    request_id: String,
    operation_id: String,
    request: ExportDiagnosticsRequest,
    cancellation: Arc<AtomicBool>,
}

struct CompletedExport {
    request: ExportDiagnosticsRequest,
    result: ExportDiagnosticsResult,
}

enum ExportReservation {
    Replay(ExportDiagnosticsResult),
    Active(PendingExportLease),
}

struct PendingExportLease {
    registry: Arc<StdMutex<ExportRegistry>>,
    application_logs: SharedApplicationLogBuffer,
    request_id: String,
    operation_id: String,
    request: ExportDiagnosticsRequest,
    cancellation: Arc<AtomicBool>,
    completed: Arc<AtomicBool>,
    finished: bool,
}

impl PendingExportLease {
    fn finish(mut self, result: &Result<ExportDiagnosticsResult, AppError>) {
        finish_export_registry(
            &self.registry,
            &self.request_id,
            &self.operation_id,
            &self.request,
            result,
        );
        log_export_result(&self.application_logs, result);
        self.completed.store(true, Ordering::Release);
        self.finished = true;
    }

    fn into_worker(mut self) -> (CallerExportGuard, WorkerExportLease) {
        let caller = CallerExportGuard {
            cancellation: Arc::clone(&self.cancellation),
            completed: Arc::clone(&self.completed),
        };
        let worker = WorkerExportLease {
            registry: Arc::clone(&self.registry),
            application_logs: Arc::clone(&self.application_logs),
            request_id: self.request_id.clone(),
            operation_id: self.operation_id.clone(),
            request: self.request.clone(),
            cancellation: Arc::clone(&self.cancellation),
            completed: Arc::clone(&self.completed),
            finished: false,
        };
        self.finished = true;
        (caller, worker)
    }
}

impl Drop for PendingExportLease {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.cancellation.store(true, Ordering::Release);
        abandon_export_registry(&self.registry, &self.request_id);
        best_effort_diagnostic_event(
            &self.application_logs,
            logging::ApplicationLogLevel::Warn,
            "diagnostics.export_cancelled",
            &[logging::ApplicationLogField::new(
                logging::ApplicationLogFieldName::Success,
                logging::ApplicationLogValue::Boolean(false),
            )],
        );
        self.completed.store(true, Ordering::Release);
    }
}

struct CallerExportGuard {
    cancellation: Arc<AtomicBool>,
    completed: Arc<AtomicBool>,
}

impl Drop for CallerExportGuard {
    fn drop(&mut self) {
        if !self.completed.load(Ordering::Acquire) {
            self.cancellation.store(true, Ordering::Release);
        }
    }
}

struct WorkerExportLease {
    registry: Arc<StdMutex<ExportRegistry>>,
    application_logs: SharedApplicationLogBuffer,
    request_id: String,
    operation_id: String,
    request: ExportDiagnosticsRequest,
    cancellation: Arc<AtomicBool>,
    completed: Arc<AtomicBool>,
    finished: bool,
}

impl WorkerExportLease {
    fn finish(mut self, result: &Result<ExportDiagnosticsResult, AppError>) {
        finish_export_registry(
            &self.registry,
            &self.request_id,
            &self.operation_id,
            &self.request,
            result,
        );
        log_export_result(&self.application_logs, result);
        self.completed.store(true, Ordering::Release);
        self.finished = true;
    }
}

impl Drop for WorkerExportLease {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.cancellation.store(true, Ordering::Release);
        abandon_export_registry(&self.registry, &self.request_id);
        best_effort_diagnostic_event(
            &self.application_logs,
            logging::ApplicationLogLevel::Error,
            "diagnostics.export_failed",
            &[logging::ApplicationLogField::new(
                logging::ApplicationLogFieldName::Success,
                logging::ApplicationLogValue::Boolean(false),
            )],
        );
        self.completed.store(true, Ordering::Release);
    }
}

fn finish_export_registry(
    registry: &StdMutex<ExportRegistry>,
    request_id: &str,
    operation_id: &str,
    request: &ExportDiagnosticsRequest,
    result: &Result<ExportDiagnosticsResult, AppError>,
) {
    if let Ok(mut exports) = registry.lock() {
        clear_active_export(&mut exports, request_id);
        remember_completed_request(&mut exports.completed_requests, request_id);
        if let Ok(result) = result {
            remember_completed_operation(&mut exports, operation_id, request, result);
        }
    }
}

fn abandon_export_registry(registry: &StdMutex<ExportRegistry>, request_id: &str) {
    if let Ok(mut exports) = registry.lock() {
        clear_active_export(&mut exports, request_id);
        remember_completed_request(&mut exports.completed_requests, request_id);
    }
}

fn clear_active_export(exports: &mut ExportRegistry, request_id: &str) {
    if exports
        .active
        .as_ref()
        .is_some_and(|active| active.request_id == request_id)
    {
        exports.active = None;
    }
}

fn remember_completed_operation(
    exports: &mut ExportRegistry,
    operation_id: &str,
    request: &ExportDiagnosticsRequest,
    result: &ExportDiagnosticsResult,
) {
    remove_completed_slot(exports, &result.file_name);
    if !exports.completed_operations.contains_key(operation_id) {
        while exports.completed_operation_order.len() >= MAX_COMPLETED_EXPORT_OPERATIONS {
            if let Some(expired) = exports.completed_operation_order.pop_front() {
                exports.completed_operations.remove(&expired);
            }
        }
        exports
            .completed_operation_order
            .push_back(operation_id.to_owned());
    }
    exports.completed_operations.insert(
        operation_id.to_owned(),
        CompletedExport {
            request: request.clone(),
            result: result.clone(),
        },
    );
}

fn invalidate_completed_slot(
    registry: &StdMutex<ExportRegistry>,
    file_name: &str,
) -> Result<(), AppError> {
    let mut exports = registry
        .lock()
        .map_err(|_| diagnostic_export_registry_error())?;
    remove_completed_slot(&mut exports, file_name);
    Ok(())
}

fn remove_completed_slot(exports: &mut ExportRegistry, file_name: &str) {
    let stale_operations = exports
        .completed_operations
        .iter()
        .filter_map(|(operation_id, completed)| {
            (completed.result.file_name == file_name).then(|| operation_id.clone())
        })
        .collect::<Vec<_>>();
    for stale in stale_operations {
        exports.completed_operations.remove(&stale);
        exports
            .completed_operation_order
            .retain(|operation| operation != &stale);
    }
}

fn remember_completed_request(requests: &mut VecDeque<String>, request_id: &str) {
    requests.retain(|completed| completed != request_id);
    while requests.len() >= MAX_COMPLETED_EXPORT_REQUESTS {
        requests.pop_front();
    }
    requests.push_back(request_id.to_owned());
}

fn log_export_result(
    application_logs: &SharedApplicationLogBuffer,
    result: &Result<ExportDiagnosticsResult, AppError>,
) {
    match result {
        Ok(result) => best_effort_diagnostic_event(
            application_logs,
            logging::ApplicationLogLevel::Info,
            "diagnostics.export_completed",
            &[
                logging::ApplicationLogField::new(
                    logging::ApplicationLogFieldName::Success,
                    logging::ApplicationLogValue::Boolean(true),
                ),
                logging::ApplicationLogField::new(
                    logging::ApplicationLogFieldName::ByteCount,
                    logging::ApplicationLogValue::Unsigned(result.total_bytes),
                ),
            ],
        ),
        Err(error) if is_cancelled_export_error(error) => best_effort_diagnostic_event(
            application_logs,
            logging::ApplicationLogLevel::Warn,
            "diagnostics.export_cancelled",
            &[
                logging::ApplicationLogField::new(
                    logging::ApplicationLogFieldName::Success,
                    logging::ApplicationLogValue::Boolean(false),
                ),
                logging::ApplicationLogField::new(
                    logging::ApplicationLogFieldName::Outcome,
                    logging::ApplicationLogValue::Code("cancelled"),
                ),
            ],
        ),
        Err(error) => best_effort_diagnostic_event(
            application_logs,
            logging::ApplicationLogLevel::Error,
            "diagnostics.export_failed",
            &[
                logging::ApplicationLogField::new(
                    logging::ApplicationLogFieldName::Success,
                    logging::ApplicationLogValue::Boolean(false),
                ),
                logging::ApplicationLogField::new(
                    logging::ApplicationLogFieldName::ErrorCode,
                    logging::ApplicationLogValue::Code(error_code_identifier(error.code)),
                ),
            ],
        ),
    }
}

fn best_effort_diagnostic_event(
    application_logs: &SharedApplicationLogBuffer,
    level: logging::ApplicationLogLevel,
    event_code: &'static str,
    fields: &[logging::ApplicationLogField],
) {
    if let Ok(mut logs) = application_logs.lock() {
        let _ = logs.append_now(level, "supervisor", event_code, fields);
    }
}

fn error_code_identifier(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::InvalidArgument => "invalid_argument",
        ErrorCode::NotFound => "not_found",
        ErrorCode::AlreadyExited => "already_exited",
        ErrorCode::AccessDenied => "access_denied",
        ErrorCode::IdentityMismatch => "identity_mismatch",
        ErrorCode::NotSupported => "not_supported",
        ErrorCode::SupervisorUnavailable => "supervisor_unavailable",
        ErrorCode::Timeout => "timeout",
        ErrorCode::Conflict => "conflict",
        ErrorCode::StorageError => "storage_error",
        ErrorCode::PlatformError => "platform_error",
        ErrorCode::Internal => "internal",
    }
}

fn is_cancelled_export_error(error: &AppError) -> bool {
    error.code == ErrorCode::Conflict
        && error
            .details
            .get("reason")
            .is_some_and(|reason| reason == "cancelled")
}

fn attach_export_operation_id(
    result: Result<ExportDiagnosticsResult, AppError>,
    operation_id: &str,
) -> Result<ExportDiagnosticsResult, AppError> {
    result.map_err(|mut error| {
        if error.operation_id.is_none() {
            error.operation_id = Some(operation_id.to_owned());
        }
        error
    })
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticSystemSummary {
    application_version: &'static str,
    target_os: &'static str,
    target_arch: &'static str,
    protocol_min_version: u16,
    protocol_max_version: u16,
    diagnostic_format_version: u16,
}

impl DiagnosticSystemSummary {
    fn current() -> Self {
        Self {
            application_version: env!("CARGO_PKG_VERSION"),
            target_os: std::env::consts::OS,
            target_arch: std::env::consts::ARCH,
            protocol_min_version: PROTOCOL_MIN_VERSION,
            protocol_max_version: PROTOCOL_MAX_VERSION,
            diagnostic_format_version: lifecycle::DIAGNOSTIC_FORMAT_VERSION,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticBundle {
    format_version: u16,
    generated_at_unix_millis: u64,
    manifest: GetDiagnosticsManifestResponse,
    system_summary: DiagnosticSystemSummary,
    application_logs: Option<DiagnosticApplicationLogs>,
    database_summary: Option<DiagnosticDatabaseSummary>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DiagnosticApplicationLogs {
    first_available_sequence: Option<u64>,
    first_sequence: Option<u64>,
    next_sequence: u64,
    end_sequence: u64,
    complete: bool,
    dropped_records: u64,
    records: Vec<Value>,
}

struct CapturedApplicationLogs {
    content: DiagnosticContentInput<'static>,
    bundle: DiagnosticApplicationLogs,
}

struct BuiltManifest {
    wire: GetDiagnosticsManifestResponse,
    bounded: DiagnosticContentManifest,
}

fn build_and_export_bundle(
    application_logs: &SharedApplicationLogBuffer,
    export_store: &DiagnosticExportStore,
    cancellation: &AtomicBool,
    request: &ExportDiagnosticsRequest,
    database_summary: Option<DiagnosticDatabaseSummary>,
    file_name: String,
) -> Result<ExportDiagnosticsResult, AppError> {
    check_export_cancelled(cancellation)?;
    let system_summary = DiagnosticSystemSummary::current();
    let system_bytes = serialized_len(&system_summary, "system summary")?;
    if system_bytes > MAX_SYSTEM_SUMMARY_BYTES {
        return Err(diagnostic_content_limit_error("systemSummary"));
    }

    let (log_content, captured_logs) = if request.include_application_logs {
        let captured = capture_application_logs(application_logs)?;
        (captured.content, Some(captured.bundle))
    } else {
        let content = application_logs
            .lock()
            .map_err(|_| diagnostic_log_registry_error())?
            .diagnostic_content(false);
        (content, None)
    };
    check_export_cancelled(cancellation)?;

    let database_bytes = database_summary
        .as_ref()
        .map(|summary| serialized_len(summary, "database summary"))
        .transpose()?
        .unwrap_or(MAX_DATABASE_SUMMARY_BYTES);
    if database_bytes > MAX_DATABASE_SUMMARY_BYTES {
        return Err(diagnostic_content_limit_error("databaseSummary"));
    }
    let manifest = build_manifest(
        request.include_database_summary,
        log_content,
        Some((system_bytes, database_bytes)),
    )?;
    let generated_at_unix_millis = current_unix_millis()?;
    let bundle = DiagnosticBundle {
        format_version: lifecycle::DIAGNOSTIC_FORMAT_VERSION,
        generated_at_unix_millis,
        manifest: manifest.wire.clone(),
        system_summary,
        application_logs: captured_logs,
        database_summary,
    };
    let contents = serde_json::to_vec(&bundle).map_err(|_| diagnostic_serialization_error())?;
    let mut budget = manifest
        .bounded
        .exact_budget()
        .map_err(diagnostic_application_log_error)?;
    budget
        .consume(contents.len() as u64)
        .map_err(diagnostic_application_log_error)?;
    check_export_cancelled(cancellation)?;

    let sha256 = sha256_hex(&contents);
    let receipt = export_store
        .write_atomic_cancellable(&file_name, &contents, || {
            cancellation.load(Ordering::Acquire)
        })
        .map_err(diagnostic_export_error)?;
    let result = ExportDiagnosticsResult {
        file_name,
        total_bytes: receipt.bytes_written,
        sha256,
        manifest: manifest.wire,
    };
    lifecycle::validate_export_diagnostics_result(&result)?;
    Ok(result)
}

fn build_manifest(
    include_database_summary: bool,
    log_content: DiagnosticContentInput<'static>,
    exact_summary_bytes: Option<(u64, u64)>,
) -> Result<BuiltManifest, AppError> {
    let (system_bytes, database_bytes) =
        exact_summary_bytes.unwrap_or((1_024, MAX_DATABASE_SUMMARY_BYTES));
    let limits = DiagnosticManifestLimits::new(
        lifecycle::MAX_DIAGNOSTIC_CONTENT_ITEMS,
        lifecycle::MAX_DIAGNOSTIC_BUNDLE_BYTES,
    )
    .map_err(diagnostic_application_log_error)?;
    let bounded = DiagnosticContentManifest::build(
        limits,
        [
            DiagnosticContentInput::new(
                SYSTEM_SUMMARY_CONTENT_ID,
                true,
                system_bytes,
                MAX_SYSTEM_SUMMARY_BYTES,
                DiagnosticContentProtection::MetadataOnly,
                false,
            ),
            log_content,
            DiagnosticContentInput::new(
                DATABASE_SUMMARY_CONTENT_ID,
                include_database_summary,
                database_bytes,
                MAX_DATABASE_SUMMARY_BYTES,
                DiagnosticContentProtection::MetadataOnly,
                false,
            ),
        ],
    )
    .map_err(diagnostic_application_log_error)?;
    let items = bounded
        .items()
        .iter()
        .map(|item| {
            let (kind, privacy) = match item.content_id() {
                SYSTEM_SUMMARY_CONTENT_ID => (
                    DiagnosticContentKind::SystemSummary,
                    DiagnosticContentPrivacy::MetadataOnly,
                ),
                logging::APPLICATION_LOG_DIAGNOSTIC_CONTENT_ID => (
                    DiagnosticContentKind::ApplicationLogs,
                    DiagnosticContentPrivacy::StructuredRedacted,
                ),
                DATABASE_SUMMARY_CONTENT_ID => (
                    DiagnosticContentKind::DatabaseSummary,
                    DiagnosticContentPrivacy::AggregateOnly,
                ),
                _ => return Err(diagnostic_manifest_error()),
            };
            Ok(DiagnosticManifestItem {
                kind,
                included: item.selected(),
                available: true,
                estimated_bytes: item.estimated_bytes(),
                maximum_bytes: item.maximum_bytes(),
                privacy,
                truncated: item.truncated(),
            })
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    let wire = GetDiagnosticsManifestResponse {
        format_version: lifecycle::DIAGNOSTIC_FORMAT_VERSION,
        items,
        selected_estimated_bytes: bounded.selected_estimated_bytes(),
        selected_maximum_bytes: bounded.selected_maximum_bytes(),
        byte_budget: bounded.byte_budget(),
    };
    lifecycle::validate_get_diagnostics_manifest_response(&wire)?;
    Ok(BuiltManifest { wire, bounded })
}

fn capture_application_logs(
    application_logs: &SharedApplicationLogBuffer,
) -> Result<CapturedApplicationLogs, AppError> {
    let logs = application_logs
        .lock()
        .map_err(|_| diagnostic_log_registry_error())?;
    let content = logs.diagnostic_content(true);
    let mut cursor = None;
    let mut first_read = None;
    let mut json_lines = String::with_capacity(logs.retained_bytes());
    let last = loop {
        let read = logs
            .read_json_lines(cursor, MAX_APPLICATION_LOG_READ_BYTES)
            .map_err(diagnostic_application_log_error)?;
        if first_read.is_none() {
            first_read = Some(read_metadata(&read));
        }
        json_lines.push_str(&read.json_lines);
        let has_more = read.has_more;
        let next_sequence = read.next_sequence;
        if !has_more {
            break read_metadata(&read);
        }
        if cursor == Some(next_sequence) {
            return Err(diagnostic_manifest_error());
        }
        cursor = Some(next_sequence);
    };
    drop(logs);

    let first = first_read.ok_or_else(diagnostic_manifest_error)?;
    let records = json_lines
        .lines()
        .map(|line| {
            serde_json::from_str::<Value>(line).map_err(|_| diagnostic_serialization_error())
        })
        .collect::<Result<Vec<_>, AppError>>()?;
    Ok(CapturedApplicationLogs {
        content,
        bundle: DiagnosticApplicationLogs {
            first_available_sequence: first.first_available_sequence,
            first_sequence: first.first_sequence,
            next_sequence: last.next_sequence,
            end_sequence: last.end_sequence,
            complete: last.complete,
            dropped_records: last.dropped_records,
            records,
        },
    })
}

#[derive(Clone, Copy)]
struct ApplicationLogReadMetadata {
    first_available_sequence: Option<u64>,
    first_sequence: Option<u64>,
    next_sequence: u64,
    end_sequence: u64,
    complete: bool,
    dropped_records: u64,
}

fn read_metadata(read: &ApplicationLogRead) -> ApplicationLogReadMetadata {
    ApplicationLogReadMetadata {
        first_available_sequence: read.first_available_sequence,
        first_sequence: read.first_sequence,
        next_sequence: read.next_sequence,
        end_sequence: read.end_sequence,
        complete: read.complete,
        dropped_records: read.dropped_records,
    }
}

fn serialized_len(value: &impl Serialize, content: &'static str) -> Result<u64, AppError> {
    let length = serde_json::to_vec(value)
        .map_err(|_| diagnostic_serialization_error())?
        .len();
    u64::try_from(length).map_err(|_| diagnostic_content_limit_error(content))
}

fn current_unix_millis() -> Result<u64, AppError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| diagnostic_clock_error())?
        .as_millis();
    u64::try_from(millis).map_err(|_| diagnostic_clock_error())
}

fn sha256_hex(contents: &[u8]) -> String {
    let digest = Sha256::digest(contents);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn check_export_cancelled(cancellation: &AtomicBool) -> Result<(), AppError> {
    if cancellation.load(Ordering::Acquire) {
        Err(cancelled_export_error())
    } else {
        Ok(())
    }
}

fn diagnostic_application_log_error(error: ApplicationLogError) -> AppError {
    let mut result = AppError::new(ErrorCode::Internal, "diagnostic content is unavailable");
    result.details.insert(
        "diagnosticOperation".into(),
        format!("{:?}", error.operation()),
    );
    result
        .details
        .insert("diagnosticErrorKind".into(), format!("{:?}", error.kind()));
    result
}

fn diagnostic_export_error(error: LogError) -> AppError {
    if error.operation() == LogOperation::CancelDiagnosticExport {
        return cancelled_export_error();
    }
    let code = match error.kind() {
        LogErrorKind::PermissionDenied => ErrorCode::AccessDenied,
        LogErrorKind::AlreadyExists | LogErrorKind::ResourceBusy => ErrorCode::Conflict,
        LogErrorKind::StorageFull
        | LogErrorKind::WriteZero
        | LogErrorKind::UnexpectedEof
        | LogErrorKind::OtherIo => ErrorCode::StorageError,
        LogErrorKind::InvalidConfiguration
        | LogErrorKind::InvalidPath
        | LogErrorKind::NotFound
        | LogErrorKind::Interrupted
        | LogErrorKind::InvalidData
        | LogErrorKind::LimitExceeded
        | LogErrorKind::Unavailable => ErrorCode::Internal,
    };
    let mut result = AppError::new(code, "diagnostic export could not be published");
    result.retryable = matches!(
        error.kind(),
        LogErrorKind::Interrupted | LogErrorKind::ResourceBusy
    );
    result.details.insert(
        "diagnosticOperation".into(),
        format!("{:?}", error.operation()),
    );
    result
        .details
        .insert("diagnosticErrorKind".into(), format!("{:?}", error.kind()));
    result
}

fn cancelled_export_error() -> AppError {
    let mut error = AppError::new(ErrorCode::Conflict, "diagnostic export was cancelled");
    error.retryable = true;
    error.details.insert("reason".into(), "cancelled".into());
    error
}

fn export_operation_conflict(operation_id: &str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Conflict,
        "diagnostic export operation ID is bound to different options",
    );
    error.operation_id = Some(operation_id.to_owned());
    error
}

fn export_busy_error(operation_id: &str) -> AppError {
    let mut error = AppError::new(ErrorCode::Conflict, "a diagnostic export is already active");
    error.operation_id = Some(operation_id.to_owned());
    error.retryable = true;
    error
}

fn diagnostic_log_registry_error() -> AppError {
    AppError::new(
        ErrorCode::Internal,
        "structured application logs are unavailable",
    )
}

fn diagnostic_export_registry_error() -> AppError {
    AppError::new(
        ErrorCode::Internal,
        "diagnostic export registry is unavailable",
    )
}

fn diagnostic_manifest_error() -> AppError {
    AppError::new(
        ErrorCode::Internal,
        "diagnostic content manifest is invalid",
    )
}

fn diagnostic_serialization_error() -> AppError {
    AppError::new(
        ErrorCode::Internal,
        "diagnostic bundle serialization failed",
    )
}

fn diagnostic_content_limit_error(content: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Internal,
        "diagnostic content exceeds its resource limit",
    );
    error.details.insert("content".into(), content.into());
    error
}

fn diagnostic_worker_error() -> AppError {
    AppError::new(ErrorCode::Internal, "diagnostic export worker failed")
}

fn diagnostic_clock_error() -> AppError {
    AppError::new(
        ErrorCode::PlatformError,
        "diagnostic export timestamp is unavailable",
    )
}
