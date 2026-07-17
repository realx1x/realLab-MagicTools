use domain::{AppError, ErrorCode, ListRunHistoryRequest, ListRunHistoryResponse};
use protocol::RequestEnvelope;
use protocol::names::method::RUN_GET_HISTORY;
use serde::{Serialize, Serializer, de::DeserializeOwned};

use crate::{AuthenticatedPeerRequest, ManagedRunService};

/// Closed response set for read-only durable managed-run history.
pub enum HistoryRpcResponse {
    List(ListRunHistoryResponse),
}

impl Serialize for HistoryRpcResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::List(response) => response.serialize(serializer),
        }
    }
}

pub enum HistoryRpcDispatch {
    Handled(HistoryRpcResponse),
    NotHandled,
}

/// Typed read routing for the redacted durable run-history projection.
pub struct HistoryRpcDispatcher<'service> {
    managed_runs: &'service ManagedRunService,
}

impl<'service> HistoryRpcDispatcher<'service> {
    pub fn new(managed_runs: &'service ManagedRunService) -> Self {
        Self { managed_runs }
    }

    pub async fn dispatch(
        &self,
        request: &AuthenticatedPeerRequest<'_>,
    ) -> Result<HistoryRpcDispatch, AppError> {
        let envelope = request.envelope();
        if envelope.method() != RUN_GET_HISTORY {
            return Ok(HistoryRpcDispatch::NotHandled);
        }
        require_read_operation(envelope)?;
        let request = decode_params::<ListRunHistoryRequest>(envelope)?;
        let response = self.managed_runs.list_run_history(&request).await?;
        Ok(HistoryRpcDispatch::Handled(HistoryRpcResponse::List(
            response,
        )))
    }
}

fn require_read_operation(envelope: &RequestEnvelope) -> Result<(), AppError> {
    if envelope.operation_id().is_none() {
        return Ok(());
    }
    Err(invalid_request(
        envelope,
        "operationId",
        "must be null for run.get_history",
    ))
}

fn decode_params<T: DeserializeOwned>(envelope: &RequestEnvelope) -> Result<T, AppError> {
    envelope.decode_params::<T>().map_err(|_| {
        invalid_request(
            envelope,
            "params",
            "must contain exactly the fields required by run.get_history",
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
        "run history request does not match the registered method contract",
    );
    error.operation_id = envelope.operation_id().map(str::to_owned);
    error.details.insert("field".into(), field.into());
    error
        .details
        .insert("method".into(), envelope.method().to_owned());
    error.details.insert("reason".into(), reason.into());
    error
}
