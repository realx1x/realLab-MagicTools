use domain::{AppError, ErrorCode, GetManagedLogRangeRequest, GetManagedLogRangeResponse};
use protocol::RequestEnvelope;
use protocol::names::method::RUN_GET_LOG_RANGE;
use serde::{Serialize, Serializer, de::DeserializeOwned};

use crate::{AuthenticatedPeerRequest, ManagedRunService};

/// Closed response set for managed-run log reads. The inner domain DTO is
/// serialized directly without a dispatcher-specific wire wrapper.
pub enum LogRpcResponse {
    Range(GetManagedLogRangeResponse),
}

impl Serialize for LogRpcResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Range(response) => response.serialize(serializer),
        }
    }
}

pub enum LogRpcDispatch {
    Handled(LogRpcResponse),
    NotHandled,
}

/// Compile-only typed routing for bounded managed-run log range reads.
/// Transport listener ownership remains outside this dispatcher.
pub struct LogRpcDispatcher<'service> {
    managed_runs: &'service ManagedRunService,
}

impl<'service> LogRpcDispatcher<'service> {
    pub fn new(managed_runs: &'service ManagedRunService) -> Self {
        Self { managed_runs }
    }

    pub async fn dispatch(
        &self,
        request: &AuthenticatedPeerRequest<'_>,
    ) -> Result<LogRpcDispatch, AppError> {
        let envelope = request.envelope();
        if envelope.method() != RUN_GET_LOG_RANGE {
            return Ok(LogRpcDispatch::NotHandled);
        }
        require_read_operation(envelope)?;
        let request = decode_params::<GetManagedLogRangeRequest>(envelope)?;
        let response = self.managed_runs.get_log_range(&request).await?;
        lifecycle::validate_get_managed_log_range_response(&response)?;
        Ok(LogRpcDispatch::Handled(LogRpcResponse::Range(response)))
    }
}

fn require_read_operation(envelope: &RequestEnvelope) -> Result<(), AppError> {
    if envelope.operation_id().is_none() {
        return Ok(());
    }
    Err(invalid_request(
        envelope,
        "operationId",
        "must be null for run.get_log_range",
    ))
}

fn decode_params<T: DeserializeOwned>(envelope: &RequestEnvelope) -> Result<T, AppError> {
    envelope.decode_params::<T>().map_err(|_| {
        invalid_request(
            envelope,
            "params",
            "must contain exactly the fields required by run.get_log_range",
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
        "managed log request does not match the registered method contract",
    );
    error.operation_id = envelope.operation_id().map(str::to_owned);
    error.details.insert("field".into(), field.into());
    error
        .details
        .insert("method".into(), envelope.method().to_owned());
    error.details.insert("reason".into(), reason.into());
    error
}
