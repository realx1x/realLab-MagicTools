use domain::{
    AppError, ErrorCode, ExitImpactSummary, GetExitImpactRequest, StopAllForExitRequest,
    StopAllForExitResult,
};
use protocol::RequestEnvelope;
use protocol::names::method::{RUN_STOP_ALL_FOR_EXIT, SYSTEM_GET_EXIT_IMPACT};
use serde::{Serialize, Serializer, de::DeserializeOwned};

use crate::{AuthenticatedPeerRequest, ManagedRunService};

/// Closed response set for the authoritative explicit-exit boundary. Each
/// variant serializes directly as its domain DTO without a dispatcher tag.
pub enum ExitRpcResponse {
    Impact(ExitImpactSummary),
    StopAll(StopAllForExitResult),
}

impl Serialize for ExitRpcResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Impact(response) => response.serialize(serializer),
            Self::StopAll(response) => response.serialize(serializer),
        }
    }
}

pub enum ExitRpcDispatch {
    Handled(ExitRpcResponse),
    NotHandled,
}

/// Compile-only typed routing for explicit UI-exit assessment and stop-all.
/// Transport listener and desktop lifecycle ownership remain outside it.
pub struct ExitRpcDispatcher<'service> {
    managed_runs: &'service ManagedRunService,
}

impl<'service> ExitRpcDispatcher<'service> {
    pub fn new(managed_runs: &'service ManagedRunService) -> Self {
        Self { managed_runs }
    }

    pub async fn dispatch(
        &self,
        request: &AuthenticatedPeerRequest<'_>,
    ) -> Result<ExitRpcDispatch, AppError> {
        let envelope = request.envelope();
        let response = match envelope.method() {
            SYSTEM_GET_EXIT_IMPACT => {
                require_read_operation(envelope)?;
                let request = decode_params::<GetExitImpactRequest>(envelope)?;
                ExitRpcResponse::Impact(self.managed_runs.get_exit_impact(&request).await?)
            }
            RUN_STOP_ALL_FOR_EXIT => {
                let operation_id = require_mutation_operation(envelope)?;
                let request = decode_params::<StopAllForExitRequest>(envelope)?;
                ExitRpcResponse::StopAll(
                    self.managed_runs
                        .stop_all_for_exit(operation_id, &request)
                        .await
                        .map_err(|error| attach_operation_id(error, operation_id))?,
                )
            }
            _ => return Ok(ExitRpcDispatch::NotHandled),
        };
        Ok(ExitRpcDispatch::Handled(response))
    }
}

fn require_read_operation(envelope: &RequestEnvelope) -> Result<(), AppError> {
    if envelope.operation_id().is_none() {
        return Ok(());
    }
    Err(invalid_request(
        envelope,
        "operationId",
        "must be absent for system.get_exit_impact",
    ))
}

fn require_mutation_operation(envelope: &RequestEnvelope) -> Result<&str, AppError> {
    envelope.operation_id().ok_or_else(|| {
        invalid_request(
            envelope,
            "operationId",
            "is required for run.stop_all_for_exit",
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
        "managed exit request does not match the registered method contract",
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
