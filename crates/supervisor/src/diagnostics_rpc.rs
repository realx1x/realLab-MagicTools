use domain::{
    AppError, ErrorCode, ExportDiagnosticsRequest, ExportDiagnosticsResult,
    GetDiagnosticsManifestRequest, GetDiagnosticsManifestResponse,
};
use protocol::CancelDisposition;
use protocol::RequestEnvelope;
use protocol::names::method::{DIAGNOSTICS_EXPORT, DIAGNOSTICS_GET_MANIFEST};
use serde::{Serialize, Serializer, de::DeserializeOwned};

use crate::{AuthenticatedPeerRequest, DiagnosticsService, ManagedRunService};

/// Closed response set for diagnostic manifest reads and atomic exports. Each
/// variant serializes its inner domain DTO without another wire tag.
pub enum DiagnosticsRpcResponse {
    Manifest(GetDiagnosticsManifestResponse),
    Export(ExportDiagnosticsResult),
}

impl Serialize for DiagnosticsRpcResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Manifest(response) => response.serialize(serializer),
            Self::Export(response) => response.serialize(serializer),
        }
    }
}

pub enum DiagnosticsRpcDispatch {
    Handled(DiagnosticsRpcResponse),
    NotHandled,
}

/// Compile-time typed routing only. The repository still has no assembled
/// long-running host; its eventual CancelEnvelope route must call
/// [`Self::cancel`] with the target request ID.
pub struct DiagnosticsRpcDispatcher<'service> {
    diagnostics: &'service DiagnosticsService,
    managed_runs: &'service ManagedRunService,
}

impl<'service> DiagnosticsRpcDispatcher<'service> {
    pub fn new(
        diagnostics: &'service DiagnosticsService,
        managed_runs: &'service ManagedRunService,
    ) -> Self {
        Self {
            diagnostics,
            managed_runs,
        }
    }

    pub async fn dispatch(
        &self,
        request: &AuthenticatedPeerRequest<'_>,
    ) -> Result<DiagnosticsRpcDispatch, AppError> {
        let envelope = request.envelope();
        let response = match envelope.method() {
            DIAGNOSTICS_GET_MANIFEST => {
                require_read_operation(envelope)?;
                let request = decode_params::<GetDiagnosticsManifestRequest>(envelope)?;
                lifecycle::validate_get_diagnostics_manifest_request(&request)?;
                let response = self.diagnostics.get_manifest()?;
                lifecycle::validate_get_diagnostics_manifest_response(&response)?;
                DiagnosticsRpcResponse::Manifest(response)
            }
            DIAGNOSTICS_EXPORT => {
                let operation_id = require_mutation_operation(envelope)?;
                let request = decode_params::<ExportDiagnosticsRequest>(envelope)?;
                lifecycle::validate_export_diagnostics_request(&request)?;
                let response = self
                    .diagnostics
                    .export(
                        self.managed_runs,
                        envelope.request_id(),
                        operation_id,
                        request,
                    )
                    .await
                    .map_err(|error| attach_operation_id(error, operation_id))?;
                lifecycle::validate_export_diagnostics_result(&response)?;
                DiagnosticsRpcResponse::Export(response)
            }
            _ => return Ok(DiagnosticsRpcDispatch::NotHandled),
        };
        Ok(DiagnosticsRpcDispatch::Handled(response))
    }

    pub async fn cancel(&self, target_request_id: &str) -> CancelDisposition {
        self.diagnostics.cancel_export(target_request_id).await
    }
}

fn require_read_operation(envelope: &RequestEnvelope) -> Result<(), AppError> {
    if envelope.operation_id().is_none() {
        return Ok(());
    }
    Err(invalid_request(
        envelope,
        "operationId",
        "must be null for diagnostics.get_manifest",
    ))
}

fn require_mutation_operation(envelope: &RequestEnvelope) -> Result<&str, AppError> {
    envelope.operation_id().ok_or_else(|| {
        invalid_request(
            envelope,
            "operationId",
            "is required for diagnostics.export",
        )
    })
}

fn decode_params<T: DeserializeOwned>(envelope: &RequestEnvelope) -> Result<T, AppError> {
    envelope.decode_params::<T>().map_err(|_| {
        invalid_request(
            envelope,
            "params",
            "must contain exactly the fields required by the diagnostics method",
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
        "diagnostics request does not match the registered method contract",
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
