use std::collections::HashMap;
use std::sync::Arc;

use domain::{
    AppError, ErrorCode, ExternalProcessStopOutcome, StopExternalProcessRequest,
    StopExternalProcessResult,
};
#[cfg(target_os = "macos")]
use platform_macos::{
    MacosExternalStopResult as PlatformExternalStopResult, stop_external_process,
};
#[cfg(windows)]
use platform_windows::{
    WindowsExternalStopResult as PlatformExternalStopResult, stop_external_process,
};
use tokio::sync::Mutex;

use crate::{AuthenticatedPeerRequest, ManagedRunService};

const MAX_EXTERNAL_STOP_OPERATIONS: usize = 4_096;

/// Owns the bounded idempotency boundary for external single-process stops.
/// Managed runs deliberately use [`crate::ManagedRunService`] instead.
///
/// Results are shared by every authenticated reconnect to this Supervisor
/// process. External observations remain transient, so the ledger is reset
/// only when a new Supervisor process establishes a new authenticated session.
pub struct ExternalProcessStopService {
    inner: Arc<Mutex<ExternalProcessStopInner>>,
}

struct ExternalProcessStopInner {
    operations: HashMap<String, ExternalProcessStopOperation>,
}

#[derive(Clone)]
struct ExternalProcessStopOperation {
    request: StopExternalProcessRequest,
    result: Result<StopExternalProcessResult, AppError>,
}

impl ExternalProcessStopService {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ExternalProcessStopInner {
                operations: HashMap::new(),
            })),
        }
    }

    pub async fn stop(
        &self,
        managed_runs: &ManagedRunService,
        request: &AuthenticatedPeerRequest<'_>,
    ) -> Result<StopExternalProcessResult, AppError> {
        let envelope = request.envelope();
        if envelope.method() != protocol::names::method::PROCESS_STOP_EXTERNAL {
            return Err(invalid_bound_request_error(
                envelope.operation_id(),
                "method",
                "must be process.stop_external",
            ));
        }
        let operation_id = envelope.operation_id().ok_or_else(|| {
            invalid_bound_request_error(None, "operationId", "is required for external stop")
        })?;
        let stop_request = envelope
            .decode_params::<StopExternalProcessRequest>()
            .map_err(|_| {
                invalid_bound_request_error(
                    Some(operation_id),
                    "params",
                    "must contain a valid external stop request",
                )
            })?;

        lifecycle::validate_external_stop_operation_id(operation_id)?;
        lifecycle::validate_stop_external_process_request(&stop_request)?;
        let application_process_id = request.peer_process_id.get();

        let mut inner = self.inner.lock().await;
        if let Some(existing) = inner.operations.get(operation_id) {
            if existing.request != stop_request {
                return Err(operation_input_conflict(
                    operation_id,
                    &existing.request,
                    &stop_request,
                ));
            }
            return existing.result.clone();
        }
        if inner.operations.len() >= MAX_EXTERNAL_STOP_OPERATIONS {
            return Err(operation_capacity_error(operation_id));
        }
        let target = &stop_request.confirmation.process_instance_key;
        // Keep the operation ledger locked across the authoritative lookup and
        // synchronous platform call. This preserves one signal attempt for a
        // concurrent replay without introducing a second pending-operation
        // state machine. ManagedRunService never acquires this ledger.
        let managed_run_id = managed_runs
            .managed_run_id_for_instance_key(target)
            .await
            .map_err(|mut error| {
                error.operation_id = Some(operation_id.to_owned());
                error
                    .details
                    .insert("managedControlLookup".into(), "failedClosed".into());
                error
            });
        let result = match managed_run_id {
            Ok(Some(run_id)) => Err(managed_process_error(operation_id, target.pid, &run_id)),
            Err(error) => Err(error),
            Ok(None) => {
                let platform_result = stop_external_process(target, &[application_process_id]);
                match platform_result {
                    Ok(PlatformExternalStopResult::SignalDelivered) => {
                        let result = StopExternalProcessResult {
                            process_instance_key: target.clone(),
                            scope: stop_request.confirmation.scope,
                            outcome: ExternalProcessStopOutcome::SignalDelivered,
                        };
                        lifecycle::validate_stop_external_process_result(&result).map(|_| result)
                    }
                    Ok(PlatformExternalStopResult::AlreadyExited) => {
                        Err(already_exited_error(target.pid))
                    }
                    Err(error) => Err(error),
                }
                .map_err(|mut error| {
                    error.operation_id = Some(operation_id.to_owned());
                    error
                })
            }
        };

        inner.operations.insert(
            operation_id.to_owned(),
            ExternalProcessStopOperation {
                request: stop_request,
                result: result.clone(),
            },
        );
        result
    }
}

fn invalid_bound_request_error(
    operation_id: Option<&str>,
    field: &'static str,
    reason: &'static str,
) -> AppError {
    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "invalid authenticated external stop request",
    );
    error.operation_id = operation_id.map(str::to_owned);
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

impl Default for ExternalProcessStopService {
    fn default() -> Self {
        Self::new()
    }
}

fn operation_input_conflict(
    operation_id: &str,
    existing: &StopExternalProcessRequest,
    requested: &StopExternalProcessRequest,
) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Conflict,
        "external stop operation ID is already bound to a different process",
    );
    error.operation_id = Some(operation_id.to_owned());
    error
        .details
        .insert("operationId".into(), operation_id.into());
    error.details.insert(
        "existingPid".into(),
        existing.confirmation.process_instance_key.pid.to_string(),
    );
    error.details.insert(
        "requestedPid".into(),
        requested.confirmation.process_instance_key.pid.to_string(),
    );
    error
}

fn operation_capacity_error(operation_id: &str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Conflict,
        "external stop operation capacity is exhausted",
    );
    error.operation_id = Some(operation_id.to_owned());
    error
        .details
        .insert("operationId".into(), operation_id.into());
    error
        .details
        .insert("capacity".into(), MAX_EXTERNAL_STOP_OPERATIONS.to_string());
    error
}

fn managed_process_error(operation_id: &str, pid: u32, run_id: &str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Conflict,
        "managed process cannot be stopped through the external process boundary",
    );
    error.operation_id = Some(operation_id.to_owned());
    error.details.insert("runId".into(), run_id.into());
    error.details.insert("pid".into(), pid.to_string());
    error.details.insert(
        "reason".into(),
        "use run.stop or run.force_stop for the associated managed run".into(),
    );
    error
}

fn already_exited_error(pid: u32) -> AppError {
    let mut error = AppError::new(
        ErrorCode::AlreadyExited,
        "external process already exited before the stop signal was delivered",
    );
    error.details.insert("pid".into(), pid.to_string());
    error
}
