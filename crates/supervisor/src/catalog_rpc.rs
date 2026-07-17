use domain::{
    AppError, ClassificationRuleSummary, DeleteClassificationRuleRequest,
    DeleteClassificationRuleResponse, DeleteProjectRequest, DeleteProjectResponse, ErrorCode,
    ListClassificationRulesRequest, ListClassificationRulesResponse, ListProjectsRequest,
    ListProjectsResponse, ProjectSummary, SaveClassificationRuleRequest, SaveProjectRequest,
};
use protocol::RequestEnvelope;
use protocol::names::method::{
    PROJECT_DELETE, PROJECT_LIST, PROJECT_SAVE, RULE_DELETE, RULE_LIST, RULE_SAVE,
};
use serde::{Serialize, Serializer, de::DeserializeOwned};

use crate::{AuthenticatedPeerRequest, ManagedRunService};

/// Closed response set for project and classification-rule catalog RPCs. Each
/// variant delegates directly to its domain DTO without another wire tag.
pub enum CatalogRpcResponse {
    ProjectList(ListProjectsResponse),
    ProjectSave(ProjectSummary),
    ProjectDelete(DeleteProjectResponse),
    RuleList(ListClassificationRulesResponse),
    RuleSave(ClassificationRuleSummary),
    RuleDelete(DeleteClassificationRuleResponse),
}

impl Serialize for CatalogRpcResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::ProjectList(response) => response.serialize(serializer),
            Self::ProjectSave(response) => response.serialize(serializer),
            Self::ProjectDelete(response) => response.serialize(serializer),
            Self::RuleList(response) => response.serialize(serializer),
            Self::RuleSave(response) => response.serialize(serializer),
            Self::RuleDelete(response) => response.serialize(serializer),
        }
    }
}

pub enum CatalogRpcDispatch {
    Handled(CatalogRpcResponse),
    NotHandled,
}

/// Typed catalog routing only; transport and listener ownership remain outside
/// this dispatcher.
pub struct CatalogRpcDispatcher<'service> {
    managed_runs: &'service ManagedRunService,
}

impl<'service> CatalogRpcDispatcher<'service> {
    pub fn new(managed_runs: &'service ManagedRunService) -> Self {
        Self { managed_runs }
    }

    pub async fn dispatch(
        &self,
        request: &AuthenticatedPeerRequest<'_>,
    ) -> Result<CatalogRpcDispatch, AppError> {
        let envelope = request.envelope();
        let response = match envelope.method() {
            PROJECT_LIST => {
                require_read_operation(envelope)?;
                let request = decode_params::<ListProjectsRequest>(envelope)?;
                CatalogRpcResponse::ProjectList(self.managed_runs.list_projects(&request).await?)
            }
            PROJECT_SAVE => {
                let operation_id = require_mutation_operation(envelope)?;
                let request = decode_params::<SaveProjectRequest>(envelope)?;
                CatalogRpcResponse::ProjectSave(
                    self.managed_runs
                        .save_project(operation_id.to_owned(), request)
                        .await
                        .map_err(|error| attach_operation_id(error, operation_id))?,
                )
            }
            PROJECT_DELETE => {
                let operation_id = require_mutation_operation(envelope)?;
                let request = decode_params::<DeleteProjectRequest>(envelope)?;
                CatalogRpcResponse::ProjectDelete(
                    self.managed_runs
                        .delete_project(operation_id.to_owned(), request)
                        .await
                        .map_err(|error| attach_operation_id(error, operation_id))?,
                )
            }
            RULE_LIST => {
                require_read_operation(envelope)?;
                let request = decode_params::<ListClassificationRulesRequest>(envelope)?;
                CatalogRpcResponse::RuleList(
                    self.managed_runs
                        .list_classification_rules(&request)
                        .await?,
                )
            }
            RULE_SAVE => {
                let operation_id = require_mutation_operation(envelope)?;
                let request = decode_params::<SaveClassificationRuleRequest>(envelope)?;
                CatalogRpcResponse::RuleSave(
                    self.managed_runs
                        .save_classification_rule(operation_id.to_owned(), request)
                        .await
                        .map_err(|error| attach_operation_id(error, operation_id))?,
                )
            }
            RULE_DELETE => {
                let operation_id = require_mutation_operation(envelope)?;
                let request = decode_params::<DeleteClassificationRuleRequest>(envelope)?;
                CatalogRpcResponse::RuleDelete(
                    self.managed_runs
                        .delete_classification_rule(operation_id.to_owned(), request)
                        .await
                        .map_err(|error| attach_operation_id(error, operation_id))?,
                )
            }
            _ => return Ok(CatalogRpcDispatch::NotHandled),
        };
        Ok(CatalogRpcDispatch::Handled(response))
    }
}

fn require_read_operation(envelope: &RequestEnvelope) -> Result<(), AppError> {
    if envelope.operation_id().is_none() {
        return Ok(());
    }
    Err(invalid_request(
        envelope,
        "operationId",
        "must be null for catalog reads",
    ))
}

fn require_mutation_operation(envelope: &RequestEnvelope) -> Result<&str, AppError> {
    envelope.operation_id().ok_or_else(|| {
        invalid_request(envelope, "operationId", "is required for catalog mutations")
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
        "catalog request does not match the registered method contract",
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
