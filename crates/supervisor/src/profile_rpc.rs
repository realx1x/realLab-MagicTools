use domain::{
    AppError, DeleteLaunchProfileRequest, DeleteLaunchProfileResponse, ExecutionPreviewRequest,
    FinalExecutionPreview, LaunchProfile, ListLaunchProfilesRequest, ListLaunchProfilesResponse,
    SaveLaunchProfileWithSecretsRequest,
};
use lifecycle::ExecutionPreviewContext;
use protocol::RequestEnvelope;
use protocol::names::method::{PROFILE_DELETE, PROFILE_LIST, PROFILE_PREVIEW, PROFILE_SAVE};
use serde::{Serialize, Serializer, de::DeserializeOwned};

use crate::{AuthenticatedPeerRequest, ManagedRunService};

/// The closed set of profile responses that can be written directly as an RPC
/// success result. Serialization delegates to the inner wire DTO and adds no
/// dispatcher-specific tag or wrapper.
pub enum ProfileRpcResponse {
    List(ListLaunchProfilesResponse),
    Save(LaunchProfile),
    Delete(DeleteLaunchProfileResponse),
    Preview(FinalExecutionPreview),
}

impl Serialize for ProfileRpcResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::List(response) => response.serialize(serializer),
            Self::Save(response) => response.serialize(serializer),
            Self::Delete(response) => response.serialize(serializer),
            Self::Preview(response) => response.serialize(serializer),
        }
    }
}

/// A non-profile request remains available to the next closed dispatcher.
pub enum ProfileRpcDispatch {
    Handled(ProfileRpcResponse),
    NotHandled,
}

/// Dispatches authenticated profile RPC requests without owning a transport
/// or starting a Supervisor listener. The preview context is process-local and
/// cannot be supplied by the wire request.
pub struct ProfileRpcDispatcher<'service> {
    managed_runs: &'service ManagedRunService,
    preview_context: &'service ExecutionPreviewContext,
}

impl<'service> ProfileRpcDispatcher<'service> {
    pub fn new(
        managed_runs: &'service ManagedRunService,
        preview_context: &'service ExecutionPreviewContext,
    ) -> Self {
        Self {
            managed_runs,
            preview_context,
        }
    }

    pub async fn dispatch(
        &self,
        request: &AuthenticatedPeerRequest<'_>,
    ) -> Result<ProfileRpcDispatch, AppError> {
        let envelope = request.envelope();
        let operation_id = envelope.operation_id().map(str::to_owned);
        let response = match envelope.method() {
            PROFILE_LIST => {
                let request = decode_params::<ListLaunchProfilesRequest>(envelope)?;
                ProfileRpcResponse::List(
                    self.managed_runs
                        .list_profiles(&request)
                        .await
                        .map_err(|error| attach_operation_id(error, operation_id.as_deref()))?,
                )
            }
            PROFILE_SAVE => {
                let operation_id = require_mutation_operation(envelope)?;
                let request = decode_params::<SaveLaunchProfileWithSecretsRequest>(envelope)?;
                ProfileRpcResponse::Save(
                    self.managed_runs
                        .save_profile_from_wire(operation_id.to_owned(), request)
                        .await
                        .map_err(|error| attach_operation_id(error, Some(operation_id)))?,
                )
            }
            PROFILE_DELETE => {
                let operation_id = require_mutation_operation(envelope)?;
                let request = decode_params::<DeleteLaunchProfileRequest>(envelope)?;
                ProfileRpcResponse::Delete(
                    self.managed_runs
                        .delete_profile(operation_id.to_owned(), request)
                        .await
                        .map_err(|error| attach_operation_id(error, Some(operation_id)))?,
                )
            }
            PROFILE_PREVIEW => {
                let request = decode_params::<ExecutionPreviewRequest>(envelope)?;
                ProfileRpcResponse::Preview(
                    self.managed_runs
                        .preview_profile(self.preview_context, &request)
                        .map_err(|error| attach_operation_id(error, operation_id.as_deref()))?,
                )
            }
            _ => return Ok(ProfileRpcDispatch::NotHandled),
        };
        Ok(ProfileRpcDispatch::Handled(response))
    }
}

fn require_mutation_operation(envelope: &RequestEnvelope) -> Result<&str, AppError> {
    envelope.operation_id().ok_or_else(|| {
        let mut error = AppError::new(
            domain::ErrorCode::InvalidArgument,
            "profile mutation requires an operation ID",
        );
        error.details.insert("field".into(), "operationId".into());
        error
            .details
            .insert("method".into(), envelope.method().to_owned());
        error.details.insert("reason".into(), "is required".into());
        error
    })
}

fn decode_params<T: DeserializeOwned>(envelope: &RequestEnvelope) -> Result<T, AppError> {
    envelope.decode_params::<T>().map_err(|_| {
        let mut error = AppError::new(
            domain::ErrorCode::InvalidArgument,
            "profile request parameters do not match the registered method contract",
        );
        error.operation_id = envelope.operation_id().map(str::to_owned);
        error.details.insert("field".into(), "params".into());
        error
            .details
            .insert("method".into(), envelope.method().to_owned());
        error.details.insert(
            "reason".into(),
            "must contain exactly the fields required by this method".into(),
        );
        error
    })
}

fn attach_operation_id(mut error: AppError, operation_id: Option<&str>) -> AppError {
    if error.operation_id.is_none() {
        error.operation_id = operation_id.map(str::to_owned);
    }
    error
}
