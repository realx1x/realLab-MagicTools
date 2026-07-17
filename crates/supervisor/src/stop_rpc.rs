use domain::{
    AppError, ErrorCode, ForceStopManagedRunRequest, GetProcessDetailsRequest,
    GetProcessDetailsResponse, ManagedStopOperationResult, StopExternalProcessResult,
    StopManagedRunRequest,
};
use protocol::RequestEnvelope;
use protocol::names::method::{
    PROCESS_GET_DETAILS, PROCESS_STOP_EXTERNAL, RUN_FORCE_STOP, RUN_STOP,
};
use serde::{Serialize, Serializer, de::DeserializeOwned};

use crate::{AuthenticatedPeerRequest, ExternalProcessStopService, ManagedRunService};

/// Closed response set for process control RPCs. Each variant serializes as
/// its inner domain DTO without a dispatcher-specific wrapper.
pub enum StopRpcResponse {
    Details(GetProcessDetailsResponse),
    Managed(ManagedStopOperationResult),
    External(StopExternalProcessResult),
}

impl Serialize for StopRpcResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Details(response) => response.serialize(serializer),
            Self::Managed(response) => response.serialize(serializer),
            Self::External(response) => response.serialize(serializer),
        }
    }
}

pub enum StopRpcDispatch {
    Handled(StopRpcResponse),
    NotHandled,
}

/// Compile-only typed routing for process details and the three distinct stop
/// boundaries. Transport listener ownership remains outside this dispatcher.
pub struct StopRpcDispatcher<'service> {
    managed_runs: &'service ManagedRunService,
    external_stops: &'service ExternalProcessStopService,
}

impl<'service> StopRpcDispatcher<'service> {
    pub fn new(
        managed_runs: &'service ManagedRunService,
        external_stops: &'service ExternalProcessStopService,
    ) -> Self {
        Self {
            managed_runs,
            external_stops,
        }
    }

    pub async fn dispatch(
        &self,
        request: &AuthenticatedPeerRequest<'_>,
    ) -> Result<StopRpcDispatch, AppError> {
        let envelope = request.envelope();
        let response = match envelope.method() {
            PROCESS_GET_DETAILS => {
                require_read_operation(envelope)?;
                let details = decode_params::<GetProcessDetailsRequest>(envelope)?;
                StopRpcResponse::Details(self.managed_runs.get_process_details(&details).await?)
            }
            RUN_STOP => {
                let operation_id = require_mutation_operation(envelope)?;
                let stop = decode_params::<StopManagedRunRequest>(envelope)?;
                StopRpcResponse::Managed(
                    self.managed_runs
                        .stop(operation_id, &stop)
                        .await
                        .map_err(|error| attach_operation_id(error, operation_id))?,
                )
            }
            RUN_FORCE_STOP => {
                let operation_id = require_mutation_operation(envelope)?;
                let stop = decode_params::<ForceStopManagedRunRequest>(envelope)?;
                StopRpcResponse::Managed(
                    self.managed_runs
                        .force_stop(operation_id, &stop)
                        .await
                        .map_err(|error| attach_operation_id(error, operation_id))?,
                )
            }
            PROCESS_STOP_EXTERNAL => {
                let operation_id = require_mutation_operation(envelope)?;
                StopRpcResponse::External(
                    self.external_stops
                        .stop(self.managed_runs, request)
                        .await
                        .map_err(|error| attach_operation_id(error, operation_id))?,
                )
            }
            _ => return Ok(StopRpcDispatch::NotHandled),
        };
        Ok(StopRpcDispatch::Handled(response))
    }
}

fn require_read_operation(envelope: &RequestEnvelope) -> Result<(), AppError> {
    if envelope.operation_id().is_none() {
        return Ok(());
    }
    Err(invalid_request(
        envelope,
        "operationId",
        "must be absent for process.get_details",
    ))
}

fn require_mutation_operation(envelope: &RequestEnvelope) -> Result<&str, AppError> {
    envelope.operation_id().ok_or_else(|| {
        invalid_request(
            envelope,
            "operationId",
            "is required for process control mutations",
        )
    })
}

fn decode_params<T: DeserializeOwned>(envelope: &RequestEnvelope) -> Result<T, AppError> {
    envelope.decode_params::<T>().map_err(|_| {
        invalid_request(
            envelope,
            "params",
            "must contain exactly the fields required by the registered method",
        )
    })
}

fn invalid_request(
    envelope: &RequestEnvelope,
    field: &'static str,
    reason: &'static str,
) -> AppError {
    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "process control request does not match the registered method contract",
    );
    error.operation_id = envelope.operation_id().map(str::to_owned);
    error.details.insert("field".into(), field.into());
    error
        .details
        .insert("method".into(), envelope.method().to_owned());
    error.details.insert("reason".into(), reason.into());
    error
}

fn attach_operation_id(mut error: AppError, operation_id: &str) -> AppError {
    if error.operation_id.is_none() {
        error.operation_id = Some(operation_id.to_owned());
    }
    error
}
