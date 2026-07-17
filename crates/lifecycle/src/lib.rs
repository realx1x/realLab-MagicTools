//! Managed process lifecycle contracts and validation.

mod preview;

pub use preview::{
    ExecutionPreviewContext, MergedEnvironment, ResolvedEnvironment, ResolvedEnvironmentEntry,
    ResolvedEnvironmentValue, build_execution_preview, merge_environment,
    resolve_environment_credentials,
};

use std::collections::HashSet;
use std::path::Path;

use platform_common::is_sensitive_field_name;

use domain::{
    AppError, ClassificationRuleAction, ClassificationRuleInput, ClassificationRuleSummary,
    CreateClassificationRuleRequest, CreateProjectRequest, DeleteClassificationRuleRequest,
    DeleteClassificationRuleResponse, DeleteLaunchProfileRequest, DeleteLaunchProfileResponse,
    DeleteProjectRequest, DeleteProjectResponse, DetectedScriptSuggestion, DiagnosticContentKind,
    DiagnosticContentPrivacy, DiagnosticManifestItem, ErrorCode, ExitImpactSummary, ExitRunImpact,
    ExportDiagnosticsRequest, ExportDiagnosticsResult, ExternalProcessStopScope,
    ForceStopManagedRunRequest, GetDiagnosticsManifestRequest, GetDiagnosticsManifestResponse,
    GetExitImpactRequest, GetManagedLogRangeRequest, GetManagedLogRangeResponse,
    GetProcessDetailsRequest, GetProcessDetailsResponse, LaunchEnvironmentEntry,
    LaunchEnvironmentValue, LaunchExecution, LaunchProfile, LaunchProfileInput,
    ListClassificationRulesRequest, ListClassificationRulesResponse, ListLaunchProfilesRequest,
    ListLaunchProfilesResponse, ListProjectsRequest, ListProjectsResponse, ListRunHistoryRequest,
    ListRunHistoryResponse, MAX_SAFE_REVISION, ManagedLogBatch, ManagedLogChunk,
    ManagedLogEncoding, ManagedLogStream, ManagedLogTextStatus, ManagedRunSummary, ManagedStopKind,
    ManagedStopOperationResult, ManagedStopOutcome, ManagedStopSignalDisposition,
    ManagedStopStatus, ProcessControl, ProcessInstanceKey, ProcessOwnership, ProcessRecord,
    ProjectInput, ProjectSummary, RunHistoryItem, RunState, SaveClassificationRuleRequest,
    SaveLaunchProfileRequest, SaveLaunchProfileWithSecretsRequest, SaveProjectRequest,
    StartManagedRunRequest, StartManagedRunResult, StopAllForExitMemberAction,
    StopAllForExitRequest, StopAllForExitResult, StopAllForExitStatus,
    StopExternalProcessConfirmation, StopExternalProcessRequest, StopExternalProcessResult,
    StopManagedRunRequest, UpdateClassificationRuleRequest, UpdateProjectRequest,
};
use platform_common::credentials::MAX_CREDENTIAL_SECRET_BYTES;
use unicode_general_category::{GeneralCategory, get_general_category};

pub const MAX_LAUNCH_PROFILE_ID_BYTES: usize = 256;
pub const MAX_LAUNCH_PROFILE_NAME_BYTES: usize = 256;
pub const MAX_LAUNCH_PROJECT_ID_BYTES: usize = 256;
pub const MAX_LAUNCH_EXECUTABLE_BYTES: usize = 32 * 1_024;
pub const MAX_LAUNCH_ARGUMENTS: usize = 256;
pub const MAX_LAUNCH_ARGUMENT_BYTES: usize = 32 * 1_024;
pub const MAX_LAUNCH_ARGUMENT_TOTAL_BYTES: usize = 64 * 1_024;
pub const MAX_SHELL_COMMAND_BYTES: usize = 64 * 1_024;
pub const MAX_LAUNCH_WORKING_DIRECTORY_BYTES: usize = 32 * 1_024;
pub const MAX_LAUNCH_ENVIRONMENT_ENTRIES: usize = 256;
pub const MAX_LAUNCH_ENVIRONMENT_NAME_BYTES: usize = 256;
pub const MAX_LAUNCH_ENVIRONMENT_VALUE_BYTES: usize = 32 * 1_024;
pub const MAX_LAUNCH_ENVIRONMENT_TOTAL_BYTES: usize = 64 * 1_024;
pub const MAX_CREDENTIAL_REFERENCE_BYTES: usize = 4 * 1_024;
pub const MAX_DETECTED_SCRIPT_ID_BYTES: usize = 256;
pub const MAX_DETECTED_SCRIPT_PATH_BYTES: usize = 32 * 1_024;
pub const MAX_LAUNCH_TIMESTAMP_BYTES: usize = 128;
pub const MAX_LAUNCH_PROFILE_CURSOR_BYTES: usize = 1_024;
pub const MAX_LAUNCH_PROFILE_PAGE_SIZE: u16 = 4;
pub const MAX_LAUNCH_PROFILE_INPUT_WIRE_BYTES: usize = 192 * 1_024;
pub const MAX_LAUNCH_PROFILE_SECRET_REQUEST_WIRE_BYTES: usize = 256 * 1_024;
pub const MAX_LAUNCH_PROFILE_LIST_WIRE_BYTES: usize = 896 * 1_024;
pub const MAX_MANAGED_RUN_ID_BYTES: usize = 256;
pub const MAX_PROCESS_BOOT_ID_BYTES: usize = 256;
pub const MAX_PROCESS_NATIVE_START_TIME_BYTES: usize = 128;
pub const MAX_MANAGED_RUN_REQUEST_WIRE_BYTES: usize = 1_024;
pub const MAX_MANAGED_RUN_RESULT_WIRE_BYTES: usize = 4 * 1_024;
pub const MAX_MANAGED_LOG_CHUNK_BYTES: usize = 65_536;
pub const MAX_MANAGED_LOG_BATCH_CHUNKS: usize = 2;
pub const MAX_MANAGED_LOG_BATCH_BYTES: usize = 131_072;
pub const MAX_MANAGED_LOG_RANGE_BYTES: u32 = 65_536;
pub const MAX_MANAGED_STOP_OPERATION_ID_BYTES: usize = 128;
pub const MAX_MANAGED_STOP_REQUEST_WIRE_BYTES: usize = 1_024;
pub const MAX_MANAGED_STOP_RESULT_WIRE_BYTES: usize = 8 * 1_024;
pub const MAX_EXIT_IMPACT_RUNS: usize = 16;
pub const EXIT_ASSESSMENT_ID_BYTES: usize = 64;
pub const MAX_EXIT_IMPACT_REQUEST_WIRE_BYTES: usize = 1_024;
pub const MAX_EXIT_IMPACT_SUMMARY_WIRE_BYTES: usize = 16 * 1_024;
pub const MAX_STOP_ALL_FOR_EXIT_RESULT_WIRE_BYTES: usize = 24 * 1_024;
pub const MAX_EXTERNAL_PROCESS_STOP_REQUEST_WIRE_BYTES: usize = 2 * 1_024;
pub const MAX_EXTERNAL_PROCESS_STOP_RESULT_WIRE_BYTES: usize = 2 * 1_024;
pub const MAX_PROCESS_DETAILS_REQUEST_WIRE_BYTES: usize = 2 * 1_024;
pub const MAX_PROCESS_DETAILS_RESPONSE_WIRE_BYTES: usize = 16 * 1_024;
pub const MAX_MACOS_PROCESS_GROUP_ID: u32 = i32::MAX as u32;
pub const MAX_STOP_TIMEOUT_MS: u32 = 300_000;
pub const MAX_PROJECT_ID_BYTES: usize = 256;
pub const MAX_PROJECT_NAME_BYTES: usize = 256;
pub const MAX_PROJECT_ROOT_DIRECTORY_BYTES: usize = 32 * 1_024;
pub const MAX_PROJECT_TIMESTAMP_BYTES: usize = 128;
pub const MAX_CLASSIFICATION_RULE_ID_BYTES: usize = 256;
pub const MAX_CLASSIFICATION_RULE_PATTERN_BYTES: usize = 4 * 1_024;
pub const MAX_CLASSIFICATION_RULE_PRIORITY_ABS: i32 = 1_000_000;
pub const MAX_CATALOG_CURSOR_BYTES: usize = 4 * 1_024;
pub const MAX_CATALOG_PAGE_SIZE: u16 = 100;
pub const MAX_PROJECT_REQUEST_WIRE_BYTES: usize = 64 * 1_024;
pub const MAX_PROJECT_LIST_WIRE_BYTES: usize = 4 * 1_024 * 1_024;
pub const MAX_CLASSIFICATION_RULE_REQUEST_WIRE_BYTES: usize = 16 * 1_024;
pub const MAX_CLASSIFICATION_RULE_LIST_WIRE_BYTES: usize = 1_024 * 1_024;
pub const MAX_RUN_HISTORY_ITEM_WIRE_BYTES: usize = 8 * 1_024;
pub const MAX_RUN_HISTORY_LIST_WIRE_BYTES: usize = 1_024 * 1_024;
pub const DIAGNOSTIC_FORMAT_VERSION: u16 = 1;
pub const MAX_DIAGNOSTIC_CONTENT_ITEMS: usize = 3;
pub const MAX_DIAGNOSTIC_SYSTEM_SUMMARY_BYTES: u64 = 64 * 1_024;
pub const MAX_DIAGNOSTIC_APPLICATION_LOG_BYTES: u64 = 32 * 1_024 * 1_024;
pub const MAX_DIAGNOSTIC_DATABASE_SUMMARY_BYTES: u64 = 64 * 1_024;
pub const MAX_DIAGNOSTIC_BUNDLE_BYTES: u64 = 64 * 1_024 * 1_024;
pub const MAX_DIAGNOSTIC_FILE_NAME_BYTES: usize = 128;
pub const MAX_DIAGNOSTIC_MANIFEST_WIRE_BYTES: usize = 16 * 1_024;
pub const MAX_DIAGNOSTIC_EXPORT_RESULT_WIRE_BYTES: usize = 24 * 1_024;

pub fn validate_project_input(input: &ProjectInput) -> Result<(), AppError> {
    validate_catalog_text("name", &input.name, MAX_PROJECT_NAME_BYTES, "project")?;
    validate_catalog_text(
        "rootDirectory",
        &input.root_directory,
        MAX_PROJECT_ROOT_DIRECTORY_BYTES,
        "project",
    )?;
    if !Path::new(&input.root_directory).is_absolute() {
        return Err(invalid_catalog_input(
            "rootDirectory",
            "must be an absolute path",
        ));
    }
    validate_catalog_wire_size(
        input,
        MAX_PROJECT_REQUEST_WIRE_BYTES,
        "input",
        "encoded project input exceeds the supported wire size",
    )
}

pub fn validate_project_summary(summary: &ProjectSummary) -> Result<(), AppError> {
    validate_catalog_text("id", &summary.id, MAX_PROJECT_ID_BYTES, "project")?;
    validate_project_input(&summary.input)?;
    validate_canonical_utc_timestamp("createdAt", &summary.created_at)?;
    validate_canonical_utc_timestamp("updatedAt", &summary.updated_at)?;
    if summary.updated_at < summary.created_at {
        return Err(invalid_catalog_input(
            "updatedAt",
            "must not precede the project creation timestamp",
        ));
    }
    validate_catalog_wire_size(
        summary,
        MAX_PROJECT_REQUEST_WIRE_BYTES,
        "project",
        "encoded project summary exceeds the supported wire size",
    )
}

pub fn validate_create_project_request(request: &CreateProjectRequest) -> Result<(), AppError> {
    validate_project_input(&request.input)?;
    validate_catalog_wire_size(
        request,
        MAX_PROJECT_REQUEST_WIRE_BYTES,
        "request",
        "encoded project create request exceeds the supported wire size",
    )
}

pub fn validate_update_project_request(request: &UpdateProjectRequest) -> Result<(), AppError> {
    validate_catalog_text(
        "projectId",
        &request.project_id,
        MAX_PROJECT_ID_BYTES,
        "project update",
    )?;
    validate_canonical_utc_timestamp("expectedUpdatedAt", &request.expected_updated_at)?;
    validate_project_input(&request.input)?;
    validate_catalog_wire_size(
        request,
        MAX_PROJECT_REQUEST_WIRE_BYTES,
        "request",
        "encoded project update request exceeds the supported wire size",
    )
}

pub fn validate_save_project_request(request: &SaveProjectRequest) -> Result<(), AppError> {
    match request {
        SaveProjectRequest::Create(request) => validate_create_project_request(request)?,
        SaveProjectRequest::Update(request) => validate_update_project_request(request)?,
    }
    validate_catalog_wire_size(
        request,
        MAX_PROJECT_REQUEST_WIRE_BYTES,
        "request",
        "encoded project save request exceeds the supported wire size",
    )
}

pub fn validate_list_projects_request(request: &ListProjectsRequest) -> Result<(), AppError> {
    validate_catalog_page_request(request.cursor.as_deref(), request.limit)?;
    validate_catalog_wire_size(
        request,
        MAX_PROJECT_REQUEST_WIRE_BYTES,
        "request",
        "encoded project list request exceeds the supported wire size",
    )
}

pub fn validate_list_projects_response(response: &ListProjectsResponse) -> Result<(), AppError> {
    if response.projects.len() > usize::from(MAX_CATALOG_PAGE_SIZE) {
        return Err(invalid_catalog_input(
            "projects",
            "exceeds the supported page size",
        ));
    }
    for project in &response.projects {
        validate_project_summary(project)?;
    }
    if let Some(cursor) = response.next_cursor.as_deref() {
        validate_catalog_cursor("nextCursor", cursor)?;
    }
    validate_catalog_wire_size(
        response,
        MAX_PROJECT_LIST_WIRE_BYTES,
        "projects",
        "encoded project page exceeds the supported wire size",
    )
}

pub fn validate_delete_project_request(request: &DeleteProjectRequest) -> Result<(), AppError> {
    validate_catalog_text(
        "projectId",
        &request.project_id,
        MAX_PROJECT_ID_BYTES,
        "project delete request",
    )?;
    validate_canonical_utc_timestamp("expectedUpdatedAt", &request.expected_updated_at)?;
    validate_catalog_wire_size(
        request,
        MAX_PROJECT_REQUEST_WIRE_BYTES,
        "request",
        "encoded project delete request exceeds the supported wire size",
    )
}

pub fn validate_delete_project_response(response: &DeleteProjectResponse) -> Result<(), AppError> {
    validate_catalog_text(
        "projectId",
        &response.project_id,
        MAX_PROJECT_ID_BYTES,
        "project delete response",
    )?;
    validate_catalog_wire_size(
        response,
        MAX_PROJECT_REQUEST_WIRE_BYTES,
        "response",
        "encoded project delete response exceeds the supported wire size",
    )
}

pub fn validate_classification_rule_input(input: &ClassificationRuleInput) -> Result<(), AppError> {
    validate_catalog_text(
        "pattern",
        &input.pattern,
        MAX_CLASSIFICATION_RULE_PATTERN_BYTES,
        "classification rule",
    )?;
    if let ClassificationRuleAction::AssignProject { project_id } = &input.action {
        validate_catalog_text(
            "action.projectId",
            project_id,
            MAX_PROJECT_ID_BYTES,
            "classification rule",
        )?;
    }
    if !(-MAX_CLASSIFICATION_RULE_PRIORITY_ABS..=MAX_CLASSIFICATION_RULE_PRIORITY_ABS)
        .contains(&input.priority)
    {
        return Err(invalid_catalog_input(
            "priority",
            "must be within the supported range",
        ));
    }
    validate_catalog_wire_size(
        input,
        MAX_CLASSIFICATION_RULE_REQUEST_WIRE_BYTES,
        "input",
        "encoded classification rule input exceeds the supported wire size",
    )
}

pub fn validate_classification_rule_summary(
    summary: &ClassificationRuleSummary,
) -> Result<(), AppError> {
    validate_catalog_text(
        "id",
        &summary.id,
        MAX_CLASSIFICATION_RULE_ID_BYTES,
        "classification rule",
    )?;
    validate_classification_rule_input(&summary.input)?;
    validate_canonical_utc_timestamp("createdAt", &summary.created_at)?;
    validate_canonical_utc_timestamp("updatedAt", &summary.updated_at)?;
    if summary.updated_at < summary.created_at {
        return Err(invalid_catalog_input(
            "updatedAt",
            "must not precede the classification rule creation timestamp",
        ));
    }
    validate_catalog_wire_size(
        summary,
        MAX_CLASSIFICATION_RULE_REQUEST_WIRE_BYTES,
        "rule",
        "encoded classification rule summary exceeds the supported wire size",
    )
}

pub fn validate_create_classification_rule_request(
    request: &CreateClassificationRuleRequest,
) -> Result<(), AppError> {
    validate_classification_rule_input(&request.input)?;
    validate_catalog_wire_size(
        request,
        MAX_CLASSIFICATION_RULE_REQUEST_WIRE_BYTES,
        "request",
        "encoded classification rule create request exceeds the supported wire size",
    )
}

pub fn validate_update_classification_rule_request(
    request: &UpdateClassificationRuleRequest,
) -> Result<(), AppError> {
    validate_catalog_text(
        "ruleId",
        &request.rule_id,
        MAX_CLASSIFICATION_RULE_ID_BYTES,
        "classification rule update",
    )?;
    validate_canonical_utc_timestamp("expectedUpdatedAt", &request.expected_updated_at)?;
    validate_classification_rule_input(&request.input)?;
    validate_catalog_wire_size(
        request,
        MAX_CLASSIFICATION_RULE_REQUEST_WIRE_BYTES,
        "request",
        "encoded classification rule update request exceeds the supported wire size",
    )
}

pub fn validate_save_classification_rule_request(
    request: &SaveClassificationRuleRequest,
) -> Result<(), AppError> {
    match request {
        SaveClassificationRuleRequest::Create(request) => {
            validate_create_classification_rule_request(request)?
        }
        SaveClassificationRuleRequest::Update(request) => {
            validate_update_classification_rule_request(request)?
        }
    }
    validate_catalog_wire_size(
        request,
        MAX_CLASSIFICATION_RULE_REQUEST_WIRE_BYTES,
        "request",
        "encoded classification rule save request exceeds the supported wire size",
    )
}

pub fn validate_list_classification_rules_request(
    request: &ListClassificationRulesRequest,
) -> Result<(), AppError> {
    validate_catalog_page_request(request.cursor.as_deref(), request.limit)?;
    validate_catalog_wire_size(
        request,
        MAX_CLASSIFICATION_RULE_REQUEST_WIRE_BYTES,
        "request",
        "encoded classification rule list request exceeds the supported wire size",
    )
}

pub fn validate_list_classification_rules_response(
    response: &ListClassificationRulesResponse,
) -> Result<(), AppError> {
    if response.rules.len() > usize::from(MAX_CATALOG_PAGE_SIZE) {
        return Err(invalid_catalog_input(
            "rules",
            "exceeds the supported page size",
        ));
    }
    for rule in &response.rules {
        validate_classification_rule_summary(rule)?;
    }
    if let Some(cursor) = response.next_cursor.as_deref() {
        validate_catalog_cursor("nextCursor", cursor)?;
    }
    validate_catalog_wire_size(
        response,
        MAX_CLASSIFICATION_RULE_LIST_WIRE_BYTES,
        "rules",
        "encoded classification rule page exceeds the supported wire size",
    )
}

pub fn validate_delete_classification_rule_request(
    request: &DeleteClassificationRuleRequest,
) -> Result<(), AppError> {
    validate_catalog_text(
        "ruleId",
        &request.rule_id,
        MAX_CLASSIFICATION_RULE_ID_BYTES,
        "classification rule delete request",
    )?;
    validate_canonical_utc_timestamp("expectedUpdatedAt", &request.expected_updated_at)?;
    validate_catalog_wire_size(
        request,
        MAX_CLASSIFICATION_RULE_REQUEST_WIRE_BYTES,
        "request",
        "encoded classification rule delete request exceeds the supported wire size",
    )
}

pub fn validate_delete_classification_rule_response(
    response: &DeleteClassificationRuleResponse,
) -> Result<(), AppError> {
    validate_catalog_text(
        "ruleId",
        &response.rule_id,
        MAX_CLASSIFICATION_RULE_ID_BYTES,
        "classification rule delete response",
    )?;
    validate_catalog_wire_size(
        response,
        MAX_CLASSIFICATION_RULE_REQUEST_WIRE_BYTES,
        "response",
        "encoded classification rule delete response exceeds the supported wire size",
    )
}

pub fn validate_run_history_item(item: &RunHistoryItem) -> Result<(), AppError> {
    validate_catalog_text(
        "runId",
        &item.run_id,
        MAX_MANAGED_RUN_ID_BYTES,
        "run history item",
    )?;
    validate_catalog_text(
        "profileId",
        &item.profile_id,
        MAX_LAUNCH_PROFILE_ID_BYTES,
        "run history item",
    )?;
    validate_catalog_text(
        "profileName",
        &item.profile_name,
        MAX_LAUNCH_PROFILE_NAME_BYTES,
        "run history item",
    )?;
    if let Some(key) = &item.process_instance_key {
        validate_catalog_process_instance_key(key)?;
    }
    if let Some(recovery_state) = item.recovery_state {
        if !matches!(
            recovery_state,
            RunState::Recovered
                | RunState::ExitedWhileOffline
                | RunState::IdentityMismatch
                | RunState::Orphaned
        ) {
            return Err(invalid_catalog_input(
                "recoveryState",
                "must be a supported recovery outcome",
            ));
        }
    }
    validate_canonical_utc_timestamp("startedAt", &item.started_at)?;
    validate_canonical_utc_timestamp("updatedAt", &item.updated_at)?;
    if item.updated_at < item.started_at {
        return Err(invalid_catalog_input(
            "updatedAt",
            "must not precede the run start timestamp",
        ));
    }
    if let Some(ended_at) = &item.ended_at {
        validate_canonical_utc_timestamp("endedAt", ended_at)?;
        if ended_at < &item.started_at || ended_at > &item.updated_at {
            return Err(invalid_catalog_input(
                "endedAt",
                "must fall between the run start and update timestamps",
            ));
        }
    }
    let requires_ended_at = matches!(
        item.state,
        RunState::Exited | RunState::Failed | RunState::ExitedWhileOffline
    );
    if requires_ended_at != item.ended_at.is_some() {
        return Err(invalid_catalog_input(
            "endedAt",
            "does not match the managed run state",
        ));
    }
    if item.state == RunState::Recovered && item.recovery_state != Some(RunState::Recovered) {
        return Err(invalid_catalog_input(
            "recoveryState",
            "a recovered run must carry its recovery marker",
        ));
    }
    if item.state == RunState::ExitedWhileOffline
        && item.recovery_state != Some(RunState::ExitedWhileOffline)
    {
        return Err(invalid_catalog_input(
            "recoveryState",
            "an offline exit must carry its recovery marker",
        ));
    }
    if let Some(recovery_state) = item.recovery_state {
        let compatible = match recovery_state {
            RunState::Recovered => matches!(
                item.state,
                RunState::Recovered
                    | RunState::StopRequested
                    | RunState::GracefulStopping
                    | RunState::ForceStopping
                    | RunState::Exited
                    | RunState::Failed
                    | RunState::IdentityMismatch
                    | RunState::Orphaned
            ),
            RunState::ExitedWhileOffline => item.state == RunState::ExitedWhileOffline,
            RunState::IdentityMismatch => item.state == RunState::IdentityMismatch,
            RunState::Orphaned => item.state == RunState::Orphaned,
            RunState::Starting
            | RunState::Running
            | RunState::StopRequested
            | RunState::GracefulStopping
            | RunState::ForceStopping
            | RunState::Exited
            | RunState::Failed => false,
        };
        if !compatible {
            return Err(invalid_catalog_input(
                "recoveryState",
                "does not match the managed run state",
            ));
        }
    }
    validate_catalog_wire_size(
        item,
        MAX_RUN_HISTORY_ITEM_WIRE_BYTES,
        "run",
        "encoded run history item exceeds the supported wire size",
    )
}

pub fn validate_list_run_history_request(request: &ListRunHistoryRequest) -> Result<(), AppError> {
    validate_catalog_page_request(request.cursor.as_deref(), request.limit)?;
    validate_catalog_wire_size(
        request,
        MAX_RUN_HISTORY_ITEM_WIRE_BYTES,
        "request",
        "encoded run history request exceeds the supported wire size",
    )
}

pub fn validate_list_run_history_response(
    response: &ListRunHistoryResponse,
) -> Result<(), AppError> {
    if response.runs.len() > usize::from(MAX_CATALOG_PAGE_SIZE) {
        return Err(invalid_catalog_input(
            "runs",
            "exceeds the supported page size",
        ));
    }
    for run in &response.runs {
        validate_run_history_item(run)?;
    }
    if let Some(cursor) = response.next_cursor.as_deref() {
        validate_catalog_cursor("nextCursor", cursor)?;
    }
    validate_catalog_wire_size(
        response,
        MAX_RUN_HISTORY_LIST_WIRE_BYTES,
        "runs",
        "encoded run history page exceeds the supported wire size",
    )
}

pub fn validate_get_diagnostics_manifest_request(
    request: &GetDiagnosticsManifestRequest,
) -> Result<(), AppError> {
    validate_diagnostic_wire_size(
        request,
        64,
        "request",
        "encoded diagnostics manifest request exceeds the supported wire size",
    )
}

pub fn validate_get_diagnostics_manifest_response(
    response: &GetDiagnosticsManifestResponse,
) -> Result<(), AppError> {
    if response.format_version != DIAGNOSTIC_FORMAT_VERSION {
        return Err(invalid_diagnostic_input(
            "formatVersion",
            "uses an unsupported diagnostic bundle format",
        ));
    }
    if response.items.len() != MAX_DIAGNOSTIC_CONTENT_ITEMS {
        return Err(invalid_diagnostic_input(
            "items",
            "must contain exactly the three supported diagnostic content items",
        ));
    }

    let mut kinds = HashSet::with_capacity(MAX_DIAGNOSTIC_CONTENT_ITEMS);
    let mut selected_estimated_bytes = 0_u64;
    let mut selected_maximum_bytes = 0_u64;
    for item in &response.items {
        validate_diagnostic_manifest_item(item)?;
        if !kinds.insert(item.kind) {
            return Err(invalid_diagnostic_input(
                "items.kind",
                "must not contain duplicate diagnostic content kinds",
            ));
        }
        if item.included {
            selected_estimated_bytes = selected_estimated_bytes
                .checked_add(item.estimated_bytes)
                .ok_or_else(|| {
                invalid_diagnostic_input("selectedEstimatedBytes", "overflows its bound")
            })?;
            selected_maximum_bytes = selected_maximum_bytes
                .checked_add(item.maximum_bytes)
                .ok_or_else(|| {
                    invalid_diagnostic_input("selectedMaximumBytes", "overflows its bound")
                })?;
        }
    }
    for required in [
        DiagnosticContentKind::SystemSummary,
        DiagnosticContentKind::ApplicationLogs,
        DiagnosticContentKind::DatabaseSummary,
    ] {
        if !kinds.contains(&required) {
            return Err(invalid_diagnostic_input(
                "items.kind",
                "is missing a required diagnostic content kind",
            ));
        }
    }
    if response.selected_estimated_bytes != selected_estimated_bytes {
        return Err(invalid_diagnostic_input(
            "selectedEstimatedBytes",
            "does not equal the included item estimates",
        ));
    }
    if response.selected_maximum_bytes != selected_maximum_bytes {
        return Err(invalid_diagnostic_input(
            "selectedMaximumBytes",
            "does not equal the included item maxima",
        ));
    }
    if response.byte_budget != MAX_DIAGNOSTIC_BUNDLE_BYTES
        || selected_estimated_bytes > response.byte_budget
        || selected_maximum_bytes > response.byte_budget
    {
        return Err(invalid_diagnostic_input(
            "byteBudget",
            "must be the fixed bundle budget and contain all included items",
        ));
    }
    validate_diagnostic_wire_size(
        response,
        MAX_DIAGNOSTIC_MANIFEST_WIRE_BYTES,
        "manifest",
        "encoded diagnostics manifest exceeds the supported wire size",
    )
}

pub fn validate_export_diagnostics_request(
    request: &ExportDiagnosticsRequest,
) -> Result<(), AppError> {
    validate_diagnostic_wire_size(
        request,
        128,
        "request",
        "encoded diagnostics export request exceeds the supported wire size",
    )
}

pub fn validate_export_diagnostics_result(
    result: &ExportDiagnosticsResult,
) -> Result<(), AppError> {
    validate_get_diagnostics_manifest_response(&result.manifest)?;
    let system_included = result
        .manifest
        .items
        .iter()
        .any(|item| item.kind == DiagnosticContentKind::SystemSummary && item.included);
    if !system_included {
        return Err(invalid_diagnostic_input(
            "manifest.items",
            "must include the mandatory system summary",
        ));
    }
    if result.file_name.len() > MAX_DIAGNOSTIC_FILE_NAME_BYTES
        || !result.file_name.starts_with("magictools-diagnostics-")
        || !result.file_name.ends_with(".json")
        || !result.file_name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-' | b'_')
        })
    {
        return Err(invalid_diagnostic_input(
            "fileName",
            "must be a generated portable diagnostic JSON file name",
        ));
    }
    if result.total_bytes == 0 || result.total_bytes > result.manifest.byte_budget {
        return Err(invalid_diagnostic_input(
            "totalBytes",
            "must be within the diagnostic bundle byte budget",
        ));
    }
    if result.sha256.len() != 64
        || !result
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(invalid_diagnostic_input(
            "sha256",
            "must contain a lowercase SHA-256 digest",
        ));
    }
    validate_diagnostic_wire_size(
        result,
        MAX_DIAGNOSTIC_EXPORT_RESULT_WIRE_BYTES,
        "result",
        "encoded diagnostics export result exceeds the supported wire size",
    )
}

fn validate_diagnostic_manifest_item(item: &DiagnosticManifestItem) -> Result<(), AppError> {
    let (privacy, maximum_bytes) = match item.kind {
        DiagnosticContentKind::SystemSummary => (
            DiagnosticContentPrivacy::MetadataOnly,
            MAX_DIAGNOSTIC_SYSTEM_SUMMARY_BYTES,
        ),
        DiagnosticContentKind::ApplicationLogs => (
            DiagnosticContentPrivacy::StructuredRedacted,
            MAX_DIAGNOSTIC_APPLICATION_LOG_BYTES,
        ),
        DiagnosticContentKind::DatabaseSummary => (
            DiagnosticContentPrivacy::AggregateOnly,
            MAX_DIAGNOSTIC_DATABASE_SUMMARY_BYTES,
        ),
    };
    if item.privacy != privacy {
        return Err(invalid_diagnostic_input(
            "items.privacy",
            "does not match the diagnostic content kind",
        ));
    }
    if item.estimated_bytes > item.maximum_bytes || item.maximum_bytes > maximum_bytes {
        return Err(invalid_diagnostic_input(
            "items.maximumBytes",
            "exceeds the content-specific diagnostic bound",
        ));
    }
    if item.available && item.maximum_bytes == 0 {
        return Err(invalid_diagnostic_input(
            "items.maximumBytes",
            "an available item must declare a nonzero resource bound",
        ));
    }
    if !item.available && (item.included || item.estimated_bytes != 0 || item.truncated) {
        return Err(invalid_diagnostic_input(
            "items.available",
            "an unavailable item cannot be included or contain retained content",
        ));
    }
    if item.truncated && item.kind != DiagnosticContentKind::ApplicationLogs {
        return Err(invalid_diagnostic_input(
            "items.truncated",
            "is supported only for bounded application logs",
        ));
    }
    if item.kind == DiagnosticContentKind::SystemSummary
        && (!item.available || !item.included || item.truncated)
    {
        return Err(invalid_diagnostic_input(
            "items.systemSummary",
            "the metadata-only system summary must always be available and included",
        ));
    }
    Ok(())
}

fn validate_diagnostic_wire_size<T: serde::Serialize>(
    value: &T,
    maximum_bytes: usize,
    field: &'static str,
    reason: &'static str,
) -> Result<(), AppError> {
    let wire_bytes = serde_json::to_vec(value).map_err(|_| {
        AppError::new(
            ErrorCode::Internal,
            "failed to measure diagnostic contract payload",
        )
    })?;
    if wire_bytes.len() > maximum_bytes {
        return Err(invalid_diagnostic_input(field, reason));
    }
    Ok(())
}

fn invalid_diagnostic_input(field: &'static str, reason: &'static str) -> AppError {
    let mut error = AppError::new(ErrorCode::InvalidArgument, "invalid diagnostics payload");
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn validate_catalog_page_request(cursor: Option<&str>, limit: u16) -> Result<(), AppError> {
    if let Some(cursor) = cursor {
        validate_catalog_cursor("cursor", cursor)?;
    }
    if limit == 0 || limit > MAX_CATALOG_PAGE_SIZE {
        return Err(invalid_catalog_input(
            "limit",
            "must be within the supported page size",
        ));
    }
    Ok(())
}

pub fn validate_canonical_utc_timestamp(field: &'static str, value: &str) -> Result<(), AppError> {
    const LENGTH: usize = 30;
    let bytes = value.as_bytes();
    if bytes.len() != LENGTH
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'.'
        || bytes[29] != b'Z'
        || bytes.iter().enumerate().any(|(index, byte)| {
            !matches!(index, 4 | 7 | 10 | 13 | 16 | 19 | 29) && !byte.is_ascii_digit()
        })
    {
        return Err(invalid_catalog_input(
            field,
            "must be a canonical UTC timestamp with nanosecond precision",
        ));
    }
    let year = parse_timestamp_number(bytes, 0, 4);
    let month = parse_timestamp_number(bytes, 5, 7);
    let day = parse_timestamp_number(bytes, 8, 10);
    let hour = parse_timestamp_number(bytes, 11, 13);
    let minute = parse_timestamp_number(bytes, 14, 16);
    let second = parse_timestamp_number(bytes, 17, 19);
    let maximum_day = days_in_month(year, month);
    if year == 0
        || maximum_day == 0
        || day == 0
        || day > maximum_day
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(invalid_catalog_input(
            field,
            "contains an invalid UTC calendar value",
        ));
    }
    Ok(())
}

fn parse_timestamp_number(bytes: &[u8], start: usize, end: usize) -> u32 {
    bytes[start..end]
        .iter()
        .fold(0_u32, |value, byte| value * 10 + u32::from(*byte - b'0'))
}

fn days_in_month(year: u32, month: u32) -> u32 {
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

fn validate_catalog_cursor(field: &'static str, cursor: &str) -> Result<(), AppError> {
    validate_catalog_text(field, cursor, MAX_CATALOG_CURSOR_BYTES, "catalog cursor")
}

fn validate_catalog_process_instance_key(key: &ProcessInstanceKey) -> Result<(), AppError> {
    validate_catalog_text(
        "processInstanceKey.bootId",
        &key.boot_id,
        MAX_PROCESS_BOOT_ID_BYTES,
        "run history item",
    )?;
    validate_catalog_text(
        "processInstanceKey.nativeStartTime",
        &key.native_start_time,
        MAX_PROCESS_NATIVE_START_TIME_BYTES,
        "run history item",
    )?;
    validate_process_instance_key(key).map_err(as_catalog_input)
}

fn validate_catalog_text(
    field: &'static str,
    value: &str,
    maximum_bytes: usize,
    entity: &'static str,
) -> Result<(), AppError> {
    if value.len() > maximum_bytes {
        return Err(invalid_catalog_input(field, "exceeds the supported length"));
    }
    if value.trim().is_empty() {
        return Err(invalid_catalog_input(
            field,
            &format!("{entity} value must not be empty"),
        ));
    }
    if value.chars().any(|character| {
        matches!(
            get_general_category(character),
            GeneralCategory::Control
                | GeneralCategory::Format
                | GeneralCategory::LineSeparator
                | GeneralCategory::ParagraphSeparator
                | GeneralCategory::Surrogate
                | GeneralCategory::Unassigned
        )
    }) {
        return Err(invalid_catalog_input(
            field,
            "must not contain control or non-text Unicode characters",
        ));
    }
    Ok(())
}

fn validate_catalog_wire_size<T: serde::Serialize>(
    value: &T,
    maximum_bytes: usize,
    field: &'static str,
    reason: &'static str,
) -> Result<(), AppError> {
    let wire_bytes = serde_json::to_vec(value).map_err(|error| {
        let mut result = AppError::new(ErrorCode::Internal, "failed to measure catalog payload");
        result.details.insert("reason".into(), error.to_string());
        result
    })?;
    if wire_bytes.len() > maximum_bytes {
        return Err(invalid_catalog_input(field, reason));
    }
    Ok(())
}

fn as_catalog_input(mut error: AppError) -> AppError {
    error.message = "invalid catalog or run history payload".into();
    error
}

fn invalid_catalog_input(field: &'static str, reason: &str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "invalid catalog or run history payload",
    );
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

/// A launch profile that is valid for persistence. P4-T02 must still resolve
/// platform executables, shell availability, and the final environment before
/// this data can be used to start a process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedLaunchProfile {
    profile: LaunchProfile,
}

impl ValidatedLaunchProfile {
    pub fn as_profile(&self) -> &LaunchProfile {
        &self.profile
    }

    pub fn into_profile(self) -> LaunchProfile {
        self.profile
    }
}

impl TryFrom<LaunchProfile> for ValidatedLaunchProfile {
    type Error = AppError;

    fn try_from(profile: LaunchProfile) -> Result<Self, Self::Error> {
        validate_launch_profile(&profile)?;
        Ok(Self { profile })
    }
}

pub fn validate_launch_profile(profile: &LaunchProfile) -> Result<(), AppError> {
    validate_required_text(
        "id",
        &profile.id,
        MAX_LAUNCH_PROFILE_ID_BYTES,
        "launch profile",
    )?;
    validate_launch_profile_input(&profile.input)?;
    validate_required_text(
        "createdAt",
        &profile.created_at,
        MAX_LAUNCH_TIMESTAMP_BYTES,
        "launch profile",
    )?;
    validate_required_text(
        "updatedAt",
        &profile.updated_at,
        MAX_LAUNCH_TIMESTAMP_BYTES,
        "launch profile",
    )?;
    Ok(())
}

pub fn validate_launch_profile_input(input: &LaunchProfileInput) -> Result<(), AppError> {
    if let Some(project_id) = &input.project_id {
        validate_required_text(
            "projectId",
            project_id,
            MAX_LAUNCH_PROJECT_ID_BYTES,
            "launch profile",
        )?;
    }
    validate_required_text(
        "name",
        &input.name,
        MAX_LAUNCH_PROFILE_NAME_BYTES,
        "launch profile",
    )?;
    validate_launch_execution(&input.execution)?;
    validate_working_directory(
        "workingDirectory",
        &input.working_directory,
        MAX_LAUNCH_WORKING_DIRECTORY_BYTES,
        "launch profile",
    )?;
    validate_environment(&input.environment)?;
    if input.stop_timeout_ms > MAX_STOP_TIMEOUT_MS {
        return Err(invalid_launch_input(
            "stopTimeoutMs",
            "exceeds the supported maximum",
        ));
    }
    let wire_bytes = serde_json::to_vec(input).map_err(|error| {
        let mut error_result = AppError::new(
            ErrorCode::Internal,
            "failed to measure launch configuration payload",
        );
        error_result
            .details
            .insert("reason".into(), error.to_string());
        error_result
    })?;
    if wire_bytes.len() > MAX_LAUNCH_PROFILE_INPUT_WIRE_BYTES {
        return Err(invalid_launch_input(
            "input",
            "encoded launch configuration exceeds the supported wire size",
        ));
    }
    Ok(())
}

pub fn validate_save_launch_profile_request(
    request: &SaveLaunchProfileRequest,
) -> Result<(), AppError> {
    match request {
        SaveLaunchProfileRequest::Create(request) => validate_launch_profile_input(&request.input),
        SaveLaunchProfileRequest::Update(request) => {
            validate_required_text(
                "profileId",
                &request.profile_id,
                MAX_LAUNCH_PROFILE_ID_BYTES,
                "launch profile update",
            )?;
            validate_required_text(
                "expectedUpdatedAt",
                &request.expected_updated_at,
                MAX_LAUNCH_TIMESTAMP_BYTES,
                "launch profile update",
            )?;
            validate_launch_profile_input(&request.input)
        }
    }
}

pub fn validate_save_launch_profile_with_secrets_request(
    request: &SaveLaunchProfileWithSecretsRequest,
) -> Result<(), AppError> {
    validate_save_launch_profile_request(&request.request)?;
    let input =
        match &request.request {
            SaveLaunchProfileRequest::Create(request) => {
                if request.input.environment.iter().any(|entry| {
                    matches!(&entry.value, LaunchEnvironmentValue::CredentialReference(_))
                }) {
                    return Err(invalid_launch_input(
                        "environment",
                        "create requests cannot supply credential references",
                    ));
                }
                &request.input
            }
            SaveLaunchProfileRequest::Update(request) => &request.input,
        };

    if request.secret_environment.len() > MAX_LAUNCH_ENVIRONMENT_ENTRIES {
        return Err(invalid_launch_input(
            "secretEnvironment",
            "exceeds the supported entry count",
        ));
    }
    let windows = cfg!(windows);
    let mut names = HashSet::with_capacity(request.secret_environment.len());
    let mut materialized_names = input
        .environment
        .iter()
        .map(|entry| environment_name_key(&entry.name, windows))
        .collect::<HashSet<_>>();
    let mut total_bytes = 0_usize;
    for entry in &request.secret_environment {
        validate_required_text(
            "secretEnvironment.name",
            &entry.name,
            MAX_LAUNCH_ENVIRONMENT_NAME_BYTES,
            "secret environment entry",
        )?;
        if !is_portable_environment_name(&entry.name) {
            return Err(invalid_launch_input(
                "secretEnvironment.name",
                "must match [A-Za-z_][A-Za-z0-9_]*",
            ));
        }
        let key = environment_name_key(&entry.name, windows);
        if !names.insert(key.clone()) {
            return Err(invalid_launch_input(
                "secretEnvironment",
                "contains duplicate names",
            ));
        }
        if let Some(existing) = input
            .environment
            .iter()
            .find(|candidate| environment_name_key(&candidate.name, windows) == key)
        {
            if matches!(&existing.value, LaunchEnvironmentValue::Plain(_)) {
                return Err(invalid_launch_input(
                    "secretEnvironment",
                    "must not replace a plain environment value",
                ));
            }
        } else {
            materialized_names.insert(key);
        }
        validate_optional_text(
            "secretEnvironment.secret",
            &entry.secret,
            MAX_CREDENTIAL_SECRET_BYTES,
        )?;
        total_bytes = total_bytes
            .saturating_add(entry.name.len())
            .saturating_add(entry.secret.len());
    }
    if materialized_names.len() > MAX_LAUNCH_ENVIRONMENT_ENTRIES
        || total_bytes > MAX_LAUNCH_ENVIRONMENT_TOTAL_BYTES
    {
        return Err(invalid_launch_input(
            "secretEnvironment",
            "exceeds the supported materialized environment budget",
        ));
    }
    let wire_bytes = serde_json::to_vec(request).map_err(|error| {
        let mut result = AppError::new(
            ErrorCode::Internal,
            "failed to measure secret launch configuration payload",
        );
        result.details.insert("reason".into(), error.to_string());
        result
    })?;
    if wire_bytes.len() > MAX_LAUNCH_PROFILE_SECRET_REQUEST_WIRE_BYTES {
        return Err(invalid_launch_input(
            "request",
            "encoded secret launch configuration exceeds the supported wire size",
        ));
    }
    Ok(())
}

pub fn validate_list_launch_profiles_request(
    request: &ListLaunchProfilesRequest,
) -> Result<(), AppError> {
    if let Some(cursor) = &request.cursor {
        validate_required_text(
            "cursor",
            cursor,
            MAX_LAUNCH_PROFILE_CURSOR_BYTES,
            "launch profile list request",
        )?;
    }
    if request.limit == 0 || request.limit > MAX_LAUNCH_PROFILE_PAGE_SIZE {
        return Err(invalid_launch_input(
            "limit",
            "must be within the supported page size",
        ));
    }
    Ok(())
}

pub fn validate_list_launch_profiles_response(
    response: &ListLaunchProfilesResponse,
) -> Result<(), AppError> {
    if response.profiles.len() > usize::from(MAX_LAUNCH_PROFILE_PAGE_SIZE) {
        return Err(invalid_launch_input(
            "profiles",
            "exceeds the supported page size",
        ));
    }
    for profile in &response.profiles {
        validate_launch_profile(profile)?;
    }
    if let Some(cursor) = &response.next_cursor {
        validate_required_text(
            "nextCursor",
            cursor,
            MAX_LAUNCH_PROFILE_CURSOR_BYTES,
            "launch profile list response",
        )?;
    }
    let wire_bytes = serde_json::to_vec(response).map_err(|error| {
        let mut error_result = AppError::new(
            ErrorCode::Internal,
            "failed to measure launch profile list payload",
        );
        error_result
            .details
            .insert("reason".into(), error.to_string());
        error_result
    })?;
    if wire_bytes.len() > MAX_LAUNCH_PROFILE_LIST_WIRE_BYTES {
        return Err(invalid_launch_input(
            "profiles",
            "encoded launch profile page exceeds the supported wire size",
        ));
    }
    Ok(())
}

pub fn validate_launch_execution(execution: &LaunchExecution) -> Result<(), AppError> {
    match execution {
        LaunchExecution::Direct(configuration) => {
            validate_required_text(
                "executable",
                &configuration.executable,
                MAX_LAUNCH_EXECUTABLE_BYTES,
                "direct launch",
            )?;
            if configuration.argv.len() > MAX_LAUNCH_ARGUMENTS {
                return Err(invalid_launch_input(
                    "argv",
                    "exceeds the supported argument count",
                ));
            }
            let mut total_bytes = 0_usize;
            for argument in &configuration.argv {
                validate_optional_text("argv", argument, MAX_LAUNCH_ARGUMENT_BYTES)?;
                total_bytes = total_bytes.saturating_add(argument.len());
            }
            if total_bytes > MAX_LAUNCH_ARGUMENT_TOTAL_BYTES {
                return Err(invalid_launch_input(
                    "argv",
                    "exceeds the supported total length",
                ));
            }
        }
        LaunchExecution::Shell(configuration) => {
            // Platform shell availability and executable resolution belong to
            // P4-T02; P4-T01 only requires the selection to be explicit.
            validate_required_text(
                "command",
                &configuration.command,
                MAX_SHELL_COMMAND_BYTES,
                "shell launch",
            )?;
        }
    }
    Ok(())
}

pub fn validate_detected_script_suggestion(
    suggestion: &DetectedScriptSuggestion,
) -> Result<(), AppError> {
    validate_required_text(
        "detectorId",
        &suggestion.detector_id,
        MAX_DETECTED_SCRIPT_ID_BYTES,
        "detected script suggestion",
    )?;
    validate_absolute_path(
        "sourcePath",
        &suggestion.source_path,
        MAX_DETECTED_SCRIPT_PATH_BYTES,
        "detected script suggestion",
    )?;
    validate_launch_execution(&suggestion.suggested_execution)
}

/// Explicitly accepts a detected suggestion into a persistable Direct or
/// Shell execution. Detected Script itself never becomes a stored mode.
pub fn accept_detected_script_suggestion(
    suggestion: DetectedScriptSuggestion,
) -> Result<LaunchExecution, AppError> {
    validate_detected_script_suggestion(&suggestion)?;
    Ok(suggestion.suggested_execution)
}

pub fn validate_delete_launch_profile_request(
    request: &DeleteLaunchProfileRequest,
) -> Result<(), AppError> {
    validate_required_text(
        "profileId",
        &request.profile_id,
        MAX_LAUNCH_PROFILE_ID_BYTES,
        "launch profile delete request",
    )?;
    validate_required_text(
        "expectedUpdatedAt",
        &request.expected_updated_at,
        MAX_LAUNCH_TIMESTAMP_BYTES,
        "launch profile delete request",
    )
}

pub fn validate_delete_launch_profile_response(
    response: &DeleteLaunchProfileResponse,
) -> Result<(), AppError> {
    validate_required_text(
        "profileId",
        &response.profile_id,
        MAX_LAUNCH_PROFILE_ID_BYTES,
        "launch profile delete response",
    )
}

pub fn validate_start_managed_run_request(
    request: &StartManagedRunRequest,
) -> Result<(), AppError> {
    validate_required_text(
        "profileId",
        &request.profile_id,
        MAX_LAUNCH_PROFILE_ID_BYTES,
        "managed run start request",
    )?;
    validate_required_text(
        "expectedProfileUpdatedAt",
        &request.expected_profile_updated_at,
        MAX_LAUNCH_TIMESTAMP_BYTES,
        "managed run start request",
    )?;
    let wire_bytes = serde_json::to_vec(request).map_err(|error| {
        managed_run_serialization_error("failed to measure managed run start request", error)
    })?;
    if wire_bytes.len() > MAX_MANAGED_RUN_REQUEST_WIRE_BYTES {
        return Err(invalid_launch_input(
            "request",
            "encoded managed run start request exceeds the supported wire size",
        ));
    }
    Ok(())
}

pub fn validate_managed_run_summary(summary: &ManagedRunSummary) -> Result<(), AppError> {
    validate_required_text(
        "runId",
        &summary.run_id,
        MAX_MANAGED_RUN_ID_BYTES,
        "managed run",
    )?;
    validate_required_text(
        "profileId",
        &summary.profile_id,
        MAX_LAUNCH_PROFILE_ID_BYTES,
        "managed run",
    )?;
    validate_canonical_utc_timestamp("profileUpdatedAt", &summary.profile_updated_at)?;
    if let Some(instance_key) = &summary.process_instance_key {
        validate_process_instance_key(instance_key)?;
    }
    if let Some(process_group_id) = summary.process_group_id {
        if process_group_id == 0 || process_group_id > MAX_MACOS_PROCESS_GROUP_ID {
            return Err(invalid_launch_input(
                "processGroupId",
                "must be a positive macOS pid_t value",
            ));
        }
        let instance_key = summary.process_instance_key.as_ref().ok_or_else(|| {
            invalid_launch_input("processGroupId", "requires a process instance identity")
        })?;
        if process_group_id != instance_key.pid {
            return Err(invalid_launch_input(
                "processGroupId",
                "must equal the dedicated process-group leader PID",
            ));
        }
    }
    validate_canonical_utc_timestamp("startedAt", &summary.started_at)?;
    validate_canonical_utc_timestamp("updatedAt", &summary.updated_at)?;
    if summary.updated_at < summary.started_at {
        return Err(invalid_launch_input(
            "updatedAt",
            "must not precede the managed run start timestamp",
        ));
    }
    if let Some(ended_at) = &summary.ended_at {
        validate_canonical_utc_timestamp("endedAt", ended_at)?;
        if ended_at < &summary.started_at || ended_at > &summary.updated_at {
            return Err(invalid_launch_input(
                "endedAt",
                "must fall between the managed run start and update timestamps",
            ));
        }
    }
    let requires_ended_at = matches!(
        summary.state,
        RunState::Exited | RunState::Failed | RunState::ExitedWhileOffline
    );
    if requires_ended_at != summary.ended_at.is_some() {
        return Err(invalid_launch_input(
            "endedAt",
            "does not match the managed run state",
        ));
    }
    let wire_bytes = serde_json::to_vec(summary).map_err(|error| {
        managed_run_serialization_error("failed to measure managed run summary", error)
    })?;
    if wire_bytes.len() > MAX_MANAGED_RUN_RESULT_WIRE_BYTES {
        return Err(invalid_launch_input(
            "run",
            "encoded managed run summary exceeds the supported wire size",
        ));
    }
    Ok(())
}

pub fn validate_start_managed_run_result(result: &StartManagedRunResult) -> Result<(), AppError> {
    validate_managed_run_summary(&result.run)?;
    if result.run.state != RunState::Running {
        return Err(invalid_launch_input(
            "run.state",
            "successful managed run start must be running",
        ));
    }
    if result.run.process_instance_key.is_none() {
        return Err(invalid_launch_input(
            "run.processInstanceKey",
            "successful managed run start requires a process identity",
        ));
    }
    if result.run.ended_at.is_some() {
        return Err(invalid_launch_input(
            "run.endedAt",
            "successful managed run start must not be ended",
        ));
    }
    let wire_bytes = serde_json::to_vec(result).map_err(|error| {
        managed_run_serialization_error("failed to measure managed run start result", error)
    })?;
    if wire_bytes.len() > MAX_MANAGED_RUN_RESULT_WIRE_BYTES {
        return Err(invalid_launch_input(
            "result",
            "encoded managed run start result exceeds the supported wire size",
        ));
    }
    Ok(())
}

pub fn validate_managed_log_chunk(chunk: &ManagedLogChunk) -> Result<(), AppError> {
    validate_managed_log_run_id(&chunk.run_id)?;
    validate_managed_log_safe_integer("sequence", chunk.sequence)?;
    if chunk.sequence == 0 {
        return Err(invalid_managed_log_input(
            "sequence",
            "must be greater than zero",
        ));
    }
    for (field, value) in [
        (
            "firstAvailableByteOffset",
            chunk.first_available_byte_offset,
        ),
        ("firstByteOffset", chunk.first_byte_offset),
        ("nextByteOffset", chunk.next_byte_offset),
        ("streamEndByteOffset", chunk.stream_end_byte_offset),
    ] {
        validate_managed_log_safe_integer(field, value)?;
    }
    if chunk.first_available_byte_offset > chunk.first_byte_offset
        || chunk.first_byte_offset > chunk.next_byte_offset
        || chunk.next_byte_offset > chunk.stream_end_byte_offset
    {
        return Err(invalid_managed_log_input(
            "byteOffsets",
            "must be monotonic from first available through stream end",
        ));
    }
    if chunk.text.len() > MAX_MANAGED_LOG_CHUNK_BYTES {
        return Err(invalid_managed_log_input(
            "text",
            "exceeds the 65536-byte chunk limit",
        ));
    }
    validate_managed_log_text(&chunk.text)?;
    validate_managed_log_text_status(&chunk.text_status)?;
    let byte_count = chunk.next_byte_offset - chunk.first_byte_offset;
    if byte_count != chunk.text.len() as u64 {
        return Err(invalid_managed_log_input(
            "text",
            "UTF-8 byte length must match the byte-offset interval",
        ));
    }
    if chunk.has_more != (chunk.next_byte_offset < chunk.stream_end_byte_offset) {
        return Err(invalid_managed_log_input(
            "hasMore",
            "must indicate whether the chunk ends before the observed stream end",
        ));
    }
    if chunk.caught_up && chunk.has_more {
        return Err(invalid_managed_log_input(
            "caughtUp",
            "cannot be true while more observed stream bytes remain",
        ));
    }
    if chunk.delivery_error.is_some() && chunk.caught_up {
        return Err(invalid_managed_log_input(
            "deliveryError",
            "cannot report delivery failure for a caught-up chunk",
        ));
    }
    if !chunk.io_status_known && (chunk.disk_error.is_some() || chunk.read_error.is_some()) {
        return Err(invalid_managed_log_input(
            "ioStatusKnown",
            "must be true when an IO error category is present",
        ));
    }
    Ok(())
}

pub fn validate_managed_log_batch(batch: &ManagedLogBatch) -> Result<(), AppError> {
    if batch.chunks.is_empty() || batch.chunks.len() > MAX_MANAGED_LOG_BATCH_CHUNKS {
        return Err(invalid_managed_log_input(
            "chunks",
            "must contain between one and two chunks",
        ));
    }

    let mut stdout_seen = false;
    let mut stderr_seen = false;
    let mut total_bytes = 0_usize;
    let mut run_id = None;
    for chunk in &batch.chunks {
        validate_managed_log_chunk(chunk)?;
        if run_id.is_some_and(|run_id| run_id != chunk.run_id) {
            return Err(invalid_managed_log_input(
                "chunks.runId",
                "must be identical for every chunk in one batch",
            ));
        }
        run_id = Some(chunk.run_id.as_str());
        let already_seen = match chunk.stream {
            ManagedLogStream::Stdout => std::mem::replace(&mut stdout_seen, true),
            ManagedLogStream::Stderr => std::mem::replace(&mut stderr_seen, true),
        };
        if already_seen {
            return Err(invalid_managed_log_input(
                "chunks.stream",
                "must not repeat stdout or stderr within one batch",
            ));
        }
        total_bytes = total_bytes.saturating_add(chunk.text.len());
    }
    if total_bytes > MAX_MANAGED_LOG_BATCH_BYTES {
        return Err(invalid_managed_log_input(
            "chunks",
            "exceeds the 131072-byte batch limit",
        ));
    }
    Ok(())
}

pub fn validate_get_managed_log_range_request(
    request: &GetManagedLogRangeRequest,
) -> Result<(), AppError> {
    validate_managed_log_run_id(&request.run_id)?;
    if let Some(starting_byte_offset) = request.starting_byte_offset {
        validate_managed_log_safe_integer("startingByteOffset", starting_byte_offset)?;
    }
    if request.maximum_bytes < 4 || request.maximum_bytes > MAX_MANAGED_LOG_RANGE_BYTES {
        return Err(invalid_managed_log_input(
            "maximumBytes",
            "must be between 4 and 65536 bytes",
        ));
    }
    Ok(())
}

pub fn validate_get_managed_log_range_response(
    response: &GetManagedLogRangeResponse,
) -> Result<(), AppError> {
    validate_managed_log_run_id(&response.run_id)?;
    for (field, value) in [
        ("observedSequence", response.observed_sequence),
        (
            "firstAvailableByteOffset",
            response.first_available_byte_offset,
        ),
        ("firstByteOffset", response.first_byte_offset),
        ("nextByteOffset", response.next_byte_offset),
        ("streamEndByteOffset", response.stream_end_byte_offset),
    ] {
        validate_managed_log_safe_integer(field, value)?;
    }
    if response.first_available_byte_offset > response.first_byte_offset
        || response.first_byte_offset > response.next_byte_offset
        || response.next_byte_offset > response.stream_end_byte_offset
    {
        return Err(invalid_managed_log_input(
            "byteOffsets",
            "must be monotonic from first available through stream end",
        ));
    }
    if response.text.len() > MAX_MANAGED_LOG_RANGE_BYTES as usize {
        return Err(invalid_managed_log_input(
            "text",
            "exceeds the 65536-byte range limit",
        ));
    }
    validate_managed_log_text(&response.text)?;
    validate_managed_log_text_status(&response.text_status)?;
    let byte_count = response.next_byte_offset - response.first_byte_offset;
    if byte_count != response.text.len() as u64 {
        return Err(invalid_managed_log_input(
            "text",
            "UTF-8 byte length must match the byte-offset interval",
        ));
    }
    if response.has_more != (response.next_byte_offset < response.stream_end_byte_offset) {
        return Err(invalid_managed_log_input(
            "hasMore",
            "must indicate whether the response ends before the observed stream end",
        ));
    }
    if response.complete && response.has_more {
        return Err(invalid_managed_log_input(
            "complete",
            "cannot be true while more observed stream bytes remain",
        ));
    }
    if !response.io_status_known && (response.disk_error.is_some() || response.read_error.is_some())
    {
        return Err(invalid_managed_log_input(
            "ioStatusKnown",
            "must be true when an IO error category is present",
        ));
    }
    Ok(())
}

fn validate_managed_log_run_id(run_id: &str) -> Result<(), AppError> {
    if run_id.is_empty() {
        return Err(invalid_managed_log_input("runId", "must not be empty"));
    }
    if run_id.len() > MAX_MANAGED_RUN_ID_BYTES {
        return Err(invalid_managed_log_input(
            "runId",
            "exceeds the 256-byte limit",
        ));
    }
    if run_id.chars().any(char::is_control) {
        return Err(invalid_managed_log_input(
            "runId",
            "must not contain control characters",
        ));
    }
    Ok(())
}

fn validate_managed_log_text(text: &str) -> Result<(), AppError> {
    if text.chars().any(|character| {
        !matches!(character, '\n' | '\t')
            && matches!(
                get_general_category(character),
                GeneralCategory::Control
                    | GeneralCategory::Format
                    | GeneralCategory::LineSeparator
                    | GeneralCategory::ParagraphSeparator
                    | GeneralCategory::Surrogate
                    | GeneralCategory::Unassigned
            )
    }) {
        return Err(invalid_managed_log_input(
            "text",
            "must contain only printable Unicode, line feed, and tab",
        ));
    }
    Ok(())
}

fn validate_managed_log_text_status(status: &ManagedLogTextStatus) -> Result<(), AppError> {
    let ManagedLogTextStatus::Known {
        encoding,
        replacement_used,
        fallback_unavailable,
        ..
    } = status
    else {
        return Ok(());
    };
    if matches!(
        encoding,
        ManagedLogEncoding::WindowsCodePage { code_page: 0 }
    ) {
        return Err(invalid_managed_log_input(
            "textStatus",
            "resolved Windows code page must be greater than zero",
        ));
    }
    if *fallback_unavailable && (*encoding != ManagedLogEncoding::Utf8 || !*replacement_used) {
        return Err(invalid_managed_log_input(
            "textStatus",
            "unavailable fallback must use replacement UTF-8",
        ));
    }
    Ok(())
}

fn validate_managed_log_safe_integer(field: &'static str, value: u64) -> Result<(), AppError> {
    if value > MAX_SAFE_REVISION {
        return Err(invalid_managed_log_input(
            field,
            "exceeds JavaScript's exact integer range",
        ));
    }
    Ok(())
}

fn invalid_managed_log_input(field: &'static str, reason: &str) -> AppError {
    let mut error = AppError::new(ErrorCode::InvalidArgument, "invalid managed log contract");
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

/// Validates the idempotency key supplied by the authenticated request
/// envelope. Stop request DTOs deliberately do not contain this value.
pub fn validate_managed_stop_operation_id(operation_id: &str) -> Result<(), AppError> {
    validate_managed_stop_id("operationId", operation_id)
}

pub fn validate_stop_managed_run_request(request: &StopManagedRunRequest) -> Result<(), AppError> {
    validate_managed_stop_run_id(&request.run_id, "managed graceful stop request")?;
    validate_managed_stop_wire_size(request, "request")
}

pub fn validate_force_stop_managed_run_request(
    request: &ForceStopManagedRunRequest,
) -> Result<(), AppError> {
    validate_managed_stop_run_id(&request.run_id, "managed force stop request")?;
    if let Some(operation_id) = &request.supersede_operation_id {
        validate_managed_stop_id("supersedeOperationId", operation_id)?;
    }
    validate_managed_stop_wire_size(request, "request")
}

pub fn validate_managed_stop_operation_result(
    result: &ManagedStopOperationResult,
) -> Result<(), AppError> {
    validate_managed_stop_operation_id(&result.operation_id)?;
    validate_managed_run_summary(&result.run).map_err(as_managed_stop_input)?;
    validate_canonical_utc_timestamp("createdAt", &result.created_at)
        .map_err(as_managed_stop_input)?;
    validate_canonical_utc_timestamp("updatedAt", &result.updated_at)
        .map_err(as_managed_stop_input)?;
    if result.updated_at < result.created_at {
        return Err(invalid_managed_stop_input(
            "updatedAt",
            "must not precede the managed stop creation timestamp",
        ));
    }
    if let Some(completed_at) = &result.completed_at {
        validate_canonical_utc_timestamp("completedAt", completed_at)
            .map_err(as_managed_stop_input)?;
        if completed_at < &result.created_at || completed_at > &result.updated_at {
            return Err(invalid_managed_stop_input(
                "completedAt",
                "must fall between the managed stop creation and update timestamps",
            ));
        }
    }

    let terminal = matches!(
        result.status,
        ManagedStopStatus::Completed | ManagedStopStatus::Superseded
    );
    if terminal != result.completed_at.is_some() {
        return Err(invalid_managed_stop_input(
            "completedAt",
            "must be present exactly when the operation status is terminal",
        ));
    }
    if !terminal && result.run.ended_at.is_some() {
        return Err(invalid_managed_stop_input(
            "run.endedAt",
            "active managed stop operation requires a live run record",
        ));
    }

    match result.status {
        ManagedStopStatus::Requested | ManagedStopStatus::SignalPending => {
            if result.signal_disposition.is_some() || result.outcome.is_some() {
                return Err(invalid_managed_stop_input(
                    "status",
                    "pre-signal operation status cannot have a signal disposition or outcome",
                ));
            }
            let valid_run_state = match result.kind {
                ManagedStopKind::Graceful => result.run.state == RunState::StopRequested,
                ManagedStopKind::Force => matches!(
                    result.run.state,
                    RunState::StopRequested | RunState::GracefulStopping
                ),
            };
            if !valid_run_state {
                return Err(invalid_managed_stop_input(
                    "run.state",
                    "does not match the pre-signal stop kind",
                ));
            }
        }
        ManagedStopStatus::InProgress => {
            if result.signal_disposition.is_none() || result.outcome.is_some() {
                return Err(invalid_managed_stop_input(
                    "status",
                    "in-progress operation requires a signal disposition and no outcome",
                ));
            }
            let expected_run_state = match result.kind {
                ManagedStopKind::Graceful => RunState::GracefulStopping,
                ManagedStopKind::Force => RunState::ForceStopping,
            };
            if result.run.state != expected_run_state {
                return Err(invalid_managed_stop_input(
                    "run.state",
                    "does not match the in-progress stop kind",
                ));
            }
        }
        ManagedStopStatus::TimedOut => {
            if result.kind != ManagedStopKind::Graceful
                || result.signal_disposition.is_none()
                || result.outcome.is_some()
                || result.run.state != RunState::GracefulStopping
            {
                return Err(invalid_managed_stop_input(
                    "status",
                    "timed-out status requires an active graceful stop",
                ));
            }
        }
        ManagedStopStatus::Completed => {
            let outcome = result.outcome.ok_or_else(|| {
                invalid_managed_stop_input("outcome", "completed operation requires an outcome")
            })?;
            if outcome == ManagedStopOutcome::SignalUnavailable
                && result.signal_disposition != Some(ManagedStopSignalDisposition::Unavailable)
            {
                return Err(invalid_managed_stop_input(
                    "signalDisposition",
                    "signal-unavailable outcome requires an unavailable signal attempt",
                ));
            }
            let valid_run_state = match outcome {
                ManagedStopOutcome::Exited => result.run.state == RunState::Exited,
                ManagedStopOutcome::AlreadyExited => matches!(
                    result.run.state,
                    RunState::Exited | RunState::ExitedWhileOffline
                ),
                ManagedStopOutcome::IdentityMismatch => {
                    result.run.state == RunState::IdentityMismatch
                }
                ManagedStopOutcome::Orphaned => result.run.state == RunState::Orphaned,
                ManagedStopOutcome::Failed => result.run.state == RunState::Failed,
                ManagedStopOutcome::SignalUnavailable => result.run.state == RunState::Orphaned,
            };
            if !valid_run_state {
                return Err(invalid_managed_stop_input(
                    "run.state",
                    "does not match the completed stop outcome",
                ));
            }
            if matches!(
                outcome,
                ManagedStopOutcome::IdentityMismatch
                    | ManagedStopOutcome::Orphaned
                    | ManagedStopOutcome::SignalUnavailable
            ) && result.run.ended_at.is_some()
            {
                return Err(invalid_managed_stop_input(
                    "run.endedAt",
                    "must remain empty when process exit was not confirmed",
                ));
            }
        }
        ManagedStopStatus::Superseded => {
            if result.kind != ManagedStopKind::Graceful || result.outcome.is_some() {
                return Err(invalid_managed_stop_input(
                    "status",
                    "only a graceful operation without an outcome may be superseded",
                ));
            }
        }
    }

    let wire_bytes = serde_json::to_vec(result).map_err(|error| {
        managed_run_serialization_error("failed to measure managed stop result", error)
    })?;
    if wire_bytes.len() > MAX_MANAGED_STOP_RESULT_WIRE_BYTES {
        return Err(invalid_managed_stop_input(
            "result",
            "encoded managed stop result exceeds the supported wire size",
        ));
    }
    Ok(())
}

/// Validates the canonical cross-platform process identity shared by
/// discovery, lifecycle lookup, and every stop boundary.
pub fn validate_process_instance_key(key: &ProcessInstanceKey) -> Result<(), AppError> {
    validate_required_text(
        "processInstanceKey.bootId",
        &key.boot_id,
        MAX_PROCESS_BOOT_ID_BYTES,
        "process identity",
    )?;
    if key.pid == 0 {
        return Err(invalid_launch_input(
            "processInstanceKey.pid",
            "must be greater than zero",
        ));
    }
    validate_required_text(
        "processInstanceKey.nativeStartTime",
        &key.native_start_time,
        MAX_PROCESS_NATIVE_START_TIME_BYTES,
        "process identity",
    )?;
    let native_start_time = key.native_start_time.parse::<u64>().map_err(|_| {
        invalid_launch_input(
            "processInstanceKey.nativeStartTime",
            "must be an unsigned decimal native start time",
        )
    })?;
    if native_start_time == 0 {
        return Err(invalid_launch_input(
            "processInstanceKey.nativeStartTime",
            "must be greater than zero",
        ));
    }
    if native_start_time.to_string() != key.native_start_time {
        return Err(invalid_launch_input(
            "processInstanceKey.nativeStartTime",
            "must use canonical unsigned decimal form",
        ));
    }
    Ok(())
}

/// Native discovery can only emit External/None. A trusted Supervisor overlay
/// must set both fields together before a process record is published.
pub fn validate_process_record_control(record: &ProcessRecord) -> Result<(), AppError> {
    match (&record.ownership, &record.managed_run_id) {
        (ProcessOwnership::External, None) => Ok(()),
        (ProcessOwnership::Managed, Some(run_id)) => validate_required_text(
            "managedRunId",
            run_id,
            MAX_MANAGED_RUN_ID_BYTES,
            "managed process association",
        )
        .map_err(as_process_details_input),
        (ProcessOwnership::Managed, None) => Err(invalid_process_details_input(
            "managedRunId",
            "must be present when ownership is managed",
        )),
        (ProcessOwnership::External, Some(_)) => Err(invalid_process_details_input(
            "managedRunId",
            "must be absent when ownership is external",
        )),
    }
}

pub fn validate_get_process_details_request(
    request: &GetProcessDetailsRequest,
) -> Result<(), AppError> {
    validate_process_instance_key(&request.process_instance_key)
        .map_err(as_process_details_input)?;
    validate_process_details_wire_size(request, MAX_PROCESS_DETAILS_REQUEST_WIRE_BYTES, "request")
}

pub fn validate_get_process_details_response(
    response: &GetProcessDetailsResponse,
) -> Result<(), AppError> {
    validate_process_instance_key(&response.process_instance_key)
        .map_err(as_process_details_input)?;
    if let ProcessControl::Managed { run, active_stop } = &response.control {
        validate_managed_run_summary(run).map_err(as_process_details_input)?;
        if run.process_instance_key.as_ref() != Some(&response.process_instance_key) {
            return Err(invalid_process_details_input(
                "control.run.processInstanceKey",
                "must match the requested process instance",
            ));
        }
        let run_requires_active_stop = matches!(
            run.state,
            RunState::StopRequested | RunState::GracefulStopping | RunState::ForceStopping
        );
        if run_requires_active_stop != active_stop.is_some() {
            return Err(invalid_process_details_input(
                "control.activeStop",
                "must be present exactly while the run is in an active stop state",
            ));
        }
        if let Some(active_stop) = active_stop {
            validate_managed_stop_operation_result(active_stop)
                .map_err(as_process_details_input)?;
            if matches!(
                active_stop.status,
                ManagedStopStatus::Completed | ManagedStopStatus::Superseded
            ) {
                return Err(invalid_process_details_input(
                    "control.activeStop.status",
                    "must describe an active stop operation",
                ));
            }
            if active_stop.run != *run {
                return Err(invalid_process_details_input(
                    "control.activeStop.run",
                    "must exactly match the managed run projection",
                ));
            }
        }
    }
    validate_process_details_wire_size(
        response,
        MAX_PROCESS_DETAILS_RESPONSE_WIRE_BYTES,
        "response",
    )
}

fn validate_process_details_wire_size<T: serde::Serialize>(
    value: &T,
    maximum_bytes: usize,
    field: &'static str,
) -> Result<(), AppError> {
    let wire_bytes = serde_json::to_vec(value).map_err(|error| {
        managed_run_serialization_error("failed to measure process details payload", error)
    })?;
    if wire_bytes.len() > maximum_bytes {
        return Err(invalid_process_details_input(
            field,
            "encoded process details payload exceeds the supported wire size",
        ));
    }
    Ok(())
}

fn as_process_details_input(mut error: AppError) -> AppError {
    error.message = "invalid process details payload".into();
    error
}

fn invalid_process_details_input(field: &'static str, reason: &str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "invalid process details payload",
    );
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn validate_managed_stop_run_id(run_id: &str, entity: &'static str) -> Result<(), AppError> {
    validate_required_text("runId", run_id, MAX_MANAGED_RUN_ID_BYTES, entity)
        .map_err(as_managed_stop_input)
}

fn validate_managed_stop_id(field: &'static str, value: &str) -> Result<(), AppError> {
    if value.is_empty() {
        return Err(invalid_managed_stop_input(field, "must not be empty"));
    }
    if value.len() > MAX_MANAGED_STOP_OPERATION_ID_BYTES {
        return Err(invalid_managed_stop_input(
            field,
            "exceeds the 128-byte limit",
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(invalid_managed_stop_input(
            field,
            "must contain only ASCII letters, digits, '-', '_', '.', or ':'",
        ));
    }
    Ok(())
}

fn validate_managed_stop_wire_size<T: serde::Serialize>(
    request: &T,
    field: &'static str,
) -> Result<(), AppError> {
    let wire_bytes = serde_json::to_vec(request).map_err(|error| {
        managed_run_serialization_error("failed to measure managed stop request", error)
    })?;
    if wire_bytes.len() > MAX_MANAGED_STOP_REQUEST_WIRE_BYTES {
        return Err(invalid_managed_stop_input(
            field,
            "encoded managed stop request exceeds the supported wire size",
        ));
    }
    Ok(())
}

fn as_managed_stop_input(mut error: AppError) -> AppError {
    error.message = "invalid managed stop operation".into();
    error
}

fn invalid_managed_stop_input(field: &'static str, reason: &str) -> AppError {
    let mut error = AppError::new(ErrorCode::InvalidArgument, "invalid managed stop operation");
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

pub fn validate_get_exit_impact_request(request: &GetExitImpactRequest) -> Result<(), AppError> {
    validate_exit_wire_size(
        request,
        MAX_EXIT_IMPACT_REQUEST_WIRE_BYTES,
        "request",
        "encoded exit-impact request exceeds the supported wire size",
    )
}

pub fn validate_exit_assessment_id(assessment_id: &str) -> Result<(), AppError> {
    if assessment_id.len() != EXIT_ASSESSMENT_ID_BYTES
        || !assessment_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(invalid_exit_input(
            "assessmentId",
            "must be exactly 64 lowercase hexadecimal characters",
        ));
    }
    Ok(())
}

pub fn validate_exit_impact_summary(summary: &ExitImpactSummary) -> Result<(), AppError> {
    validate_exit_assessment_id(&summary.assessment_id)?;
    validate_exit_impacts(&summary.runs, "runs")?;
    validate_exit_wire_size(
        summary,
        MAX_EXIT_IMPACT_SUMMARY_WIRE_BYTES,
        "summary",
        "encoded exit-impact summary exceeds the supported wire size",
    )
}

pub fn validate_stop_all_for_exit_request(request: &StopAllForExitRequest) -> Result<(), AppError> {
    validate_exit_assessment_id(&request.expected_assessment_id)?;
    validate_exit_wire_size(
        request,
        MAX_EXIT_IMPACT_REQUEST_WIRE_BYTES,
        "request",
        "encoded stop-all-for-exit request exceeds the supported wire size",
    )
}

pub fn validate_stop_all_for_exit_result(result: &StopAllForExitResult) -> Result<(), AppError> {
    validate_managed_stop_operation_id(&result.operation_id).map_err(as_exit_input)?;
    if result.members.len() > MAX_EXIT_IMPACT_RUNS {
        return Err(invalid_exit_input(
            "members",
            "exceeds the 16-run exit-impact limit",
        ));
    }

    let mut previous_run_id: Option<&str> = None;
    let mut stop_operation_ids = HashSet::with_capacity(result.members.len());
    let mut has_current_impact = false;
    let mut has_blocking_impact = false;
    for member in &result.members {
        validate_exit_run_id(&member.run_id)?;
        validate_strict_exit_run_order(previous_run_id, &member.run_id, "members")?;
        previous_run_id = Some(&member.run_id);

        let action_operation_id = match &member.action {
            StopAllForExitMemberAction::None => None,
            StopAllForExitMemberAction::GracefulRequested { operation_id }
            | StopAllForExitMemberAction::StopAdopted { operation_id } => {
                validate_managed_stop_operation_id(operation_id).map_err(as_exit_input)?;
                Some(operation_id.as_str())
            }
        };
        if let Some(operation_id) = action_operation_id
            && !stop_operation_ids.insert(operation_id)
        {
            return Err(invalid_exit_input(
                "members.action.operationId",
                "contains a duplicate stop operation ID",
            ));
        }

        if let Some(current_impact) = &member.current_impact {
            validate_exit_run_impact(current_impact)?;
            if exit_run_impact_run_id(current_impact) != member.run_id {
                return Err(invalid_exit_input(
                    "members.currentImpact.runId",
                    "must match its fixed member run ID",
                ));
            }
            has_current_impact = true;
            has_blocking_impact |= matches!(
                current_impact,
                ExitRunImpact::Launching { .. }
                    | ExitRunImpact::Running { .. }
                    | ExitRunImpact::GracefulTimedOut { .. }
                    | ExitRunImpact::Retained { .. }
            );
        }
    }

    let expected_status = if !has_current_impact {
        StopAllForExitStatus::Completed
    } else if has_blocking_impact {
        StopAllForExitStatus::Blocked
    } else {
        StopAllForExitStatus::Draining
    };
    if result.status != expected_status {
        return Err(invalid_exit_input(
            "status",
            "must be derived from the fixed members' current impacts",
        ));
    }

    validate_exit_wire_size(
        result,
        MAX_STOP_ALL_FOR_EXIT_RESULT_WIRE_BYTES,
        "result",
        "encoded stop-all-for-exit result exceeds the supported wire size",
    )
}

fn validate_exit_impacts(impacts: &[ExitRunImpact], field: &'static str) -> Result<(), AppError> {
    if impacts.len() > MAX_EXIT_IMPACT_RUNS {
        return Err(invalid_exit_input(
            field,
            "exceeds the 16-run exit-impact limit",
        ));
    }
    let mut previous_run_id: Option<&str> = None;
    for impact in impacts {
        validate_exit_run_impact(impact)?;
        let run_id = exit_run_impact_run_id(impact);
        validate_strict_exit_run_order(previous_run_id, run_id, field)?;
        previous_run_id = Some(run_id);
    }
    Ok(())
}

fn validate_exit_run_impact(impact: &ExitRunImpact) -> Result<(), AppError> {
    validate_exit_run_id(exit_run_impact_run_id(impact))?;
    match impact {
        ExitRunImpact::GracefulStopping { operation_id, .. }
        | ExitRunImpact::GracefulTimedOut { operation_id, .. }
        | ExitRunImpact::ForceStopping { operation_id, .. } => {
            validate_managed_stop_operation_id(operation_id).map_err(as_exit_input)
        }
        ExitRunImpact::Launching { .. }
        | ExitRunImpact::Running { .. }
        | ExitRunImpact::Retained { .. } => Ok(()),
    }
}

fn exit_run_impact_run_id(impact: &ExitRunImpact) -> &str {
    match impact {
        ExitRunImpact::Launching { run_id }
        | ExitRunImpact::Running { run_id }
        | ExitRunImpact::GracefulStopping { run_id, .. }
        | ExitRunImpact::GracefulTimedOut { run_id, .. }
        | ExitRunImpact::ForceStopping { run_id, .. }
        | ExitRunImpact::Retained { run_id, .. } => run_id,
    }
}

fn validate_exit_run_id(run_id: &str) -> Result<(), AppError> {
    validate_managed_stop_run_id(run_id, "exit-impact run").map_err(as_exit_input)
}

fn validate_strict_exit_run_order(
    previous_run_id: Option<&str>,
    run_id: &str,
    field: &'static str,
) -> Result<(), AppError> {
    if previous_run_id.is_some_and(|previous| previous >= run_id) {
        return Err(invalid_exit_input(
            field,
            "must contain unique runs in strictly increasing runId order",
        ));
    }
    Ok(())
}

fn validate_exit_wire_size<T: serde::Serialize>(
    value: &T,
    maximum_bytes: usize,
    field: &'static str,
    reason: &'static str,
) -> Result<(), AppError> {
    let wire_bytes = serde_json::to_vec(value).map_err(|error| {
        managed_run_serialization_error("failed to measure managed exit payload", error)
    })?;
    if wire_bytes.len() > maximum_bytes {
        return Err(invalid_exit_input(field, reason));
    }
    Ok(())
}

fn as_exit_input(mut error: AppError) -> AppError {
    error.message = "invalid managed exit payload".into();
    error
}

fn invalid_exit_input(field: &'static str, reason: &str) -> AppError {
    let mut error = AppError::new(ErrorCode::InvalidArgument, "invalid managed exit payload");
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

/// Validates the idempotency key supplied by the authenticated external-stop
/// request envelope. It is intentionally absent from the request and result
/// DTOs because the protocol envelope owns operation correlation.
pub fn validate_external_stop_operation_id(operation_id: &str) -> Result<(), AppError> {
    validate_managed_stop_id("operationId", operation_id).map_err(as_external_process_stop_input)
}

pub fn validate_stop_external_process_confirmation(
    confirmation: &StopExternalProcessConfirmation,
) -> Result<(), AppError> {
    validate_external_process_instance_key(&confirmation.process_instance_key)?;
    match confirmation.scope {
        ExternalProcessStopScope::SingleProcess => Ok(()),
    }
}

pub fn validate_stop_external_process_request(
    request: &StopExternalProcessRequest,
) -> Result<(), AppError> {
    validate_stop_external_process_confirmation(&request.confirmation)?;
    validate_external_process_stop_wire_size(
        request,
        MAX_EXTERNAL_PROCESS_STOP_REQUEST_WIRE_BYTES,
        "request",
    )
}

pub fn validate_stop_external_process_result(
    result: &StopExternalProcessResult,
) -> Result<(), AppError> {
    validate_external_process_instance_key(&result.process_instance_key)?;
    match result.scope {
        ExternalProcessStopScope::SingleProcess => {}
    }
    validate_external_process_stop_wire_size(
        result,
        MAX_EXTERNAL_PROCESS_STOP_RESULT_WIRE_BYTES,
        "result",
    )
}

fn validate_external_process_instance_key(key: &ProcessInstanceKey) -> Result<(), AppError> {
    validate_process_instance_key(key).map_err(as_external_process_stop_input)
}

fn validate_external_process_stop_wire_size<T: serde::Serialize>(
    value: &T,
    maximum_bytes: usize,
    field: &'static str,
) -> Result<(), AppError> {
    let wire_bytes = serde_json::to_vec(value).map_err(|error| {
        managed_run_serialization_error("failed to measure external process stop payload", error)
    })?;
    if wire_bytes.len() > maximum_bytes {
        return Err(invalid_external_process_stop_input(
            field,
            "encoded external process stop payload exceeds the supported wire size",
        ));
    }
    Ok(())
}

fn as_external_process_stop_input(mut error: AppError) -> AppError {
    error.message = "invalid external process stop payload".into();
    error
}

fn invalid_external_process_stop_input(field: &'static str, reason: &str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "invalid external process stop payload",
    );
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn validate_environment(environment: &[LaunchEnvironmentEntry]) -> Result<(), AppError> {
    validate_environment_for_platform(environment, cfg!(windows))
}

pub(crate) fn validate_environment_for_platform(
    environment: &[LaunchEnvironmentEntry],
    windows_case_insensitive: bool,
) -> Result<(), AppError> {
    if environment.len() > MAX_LAUNCH_ENVIRONMENT_ENTRIES {
        return Err(invalid_launch_input(
            "environment",
            "exceeds the supported entry count",
        ));
    }
    let mut names = HashSet::with_capacity(environment.len());
    let mut total_bytes = 0_usize;
    for entry in environment {
        validate_required_text(
            "environment.name",
            &entry.name,
            MAX_LAUNCH_ENVIRONMENT_NAME_BYTES,
            "environment entry",
        )?;
        if !is_portable_environment_name(&entry.name) {
            return Err(invalid_launch_input(
                "environment.name",
                "must match [A-Za-z_][A-Za-z0-9_]*",
            ));
        }
        let comparison_name = environment_name_key(&entry.name, windows_case_insensitive);
        if !names.insert(comparison_name) {
            return Err(invalid_launch_input(
                "environment",
                "contains duplicate names",
            ));
        }
        total_bytes = total_bytes.saturating_add(entry.name.len());
        match &entry.value {
            LaunchEnvironmentValue::Plain(value) => {
                if is_sensitive_field_name(&entry.name) {
                    return Err(invalid_launch_input(
                        "environment.value",
                        "sensitive environment names require a credential reference",
                    ));
                }
                validate_optional_text(
                    "environment.value",
                    &value.value,
                    MAX_LAUNCH_ENVIRONMENT_VALUE_BYTES,
                )?;
                total_bytes = total_bytes.saturating_add(value.value.len());
            }
            LaunchEnvironmentValue::CredentialReference(reference) => {
                validate_required_text(
                    "environment.credentialReference",
                    &reference.credential_reference,
                    MAX_CREDENTIAL_REFERENCE_BYTES,
                    "environment entry",
                )?;
                total_bytes = total_bytes.saturating_add(reference.credential_reference.len());
            }
        }
    }
    if total_bytes > MAX_LAUNCH_ENVIRONMENT_TOTAL_BYTES {
        return Err(invalid_launch_input(
            "environment",
            "exceeds the supported total length",
        ));
    }
    Ok(())
}

fn is_portable_environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn environment_name_key(value: &str, windows_case_insensitive: bool) -> String {
    if windows_case_insensitive {
        value.to_ascii_uppercase()
    } else {
        value.to_owned()
    }
}

fn validate_absolute_path(
    field: &'static str,
    value: &str,
    maximum_bytes: usize,
    entity: &'static str,
) -> Result<(), AppError> {
    validate_required_text(field, value, maximum_bytes, entity)?;
    if !Path::new(value).is_absolute() {
        return Err(invalid_launch_input(field, "must be an absolute path"));
    }
    Ok(())
}

fn validate_working_directory(
    field: &'static str,
    value: &str,
    maximum_bytes: usize,
    entity: &'static str,
) -> Result<(), AppError> {
    validate_absolute_path(field, value, maximum_bytes, entity)?;
    validate_platform_working_directory(value)
}

#[cfg(windows)]
fn validate_platform_working_directory(value: &str) -> Result<(), AppError> {
    let path = value.replace('/', "\\");
    if starts_with_ascii_case(&path, "\\\\?\\")
        || starts_with_ascii_case(&path, "\\\\.\\")
        || starts_with_ascii_case(&path, "\\??\\")
        || starts_with_ascii_case(&path, "\\Device\\")
    {
        return Err(invalid_launch_input(
            "workingDirectory",
            "must not use a verbatim, device, or GLOBALROOT namespace",
        ));
    }

    let component_tail = if path.starts_with("\\\\") {
        let mut parts = path[2..].split('\\');
        let server = parts.next().unwrap_or_default();
        let share = parts.next().unwrap_or_default();
        if server.is_empty()
            || share.is_empty()
            || matches!(
                server.to_ascii_uppercase().as_str(),
                "." | "?" | "GLOBALROOT"
            )
        {
            return Err(invalid_launch_input(
                "workingDirectory",
                "contains an invalid UNC authority",
            ));
        }
        parts.collect::<Vec<_>>()
    } else {
        let bytes = path.as_bytes();
        if bytes.len() < 3
            || !bytes[0].is_ascii_alphabetic()
            || bytes[1] != b':'
            || bytes[2] != b'\\'
        {
            return Err(invalid_launch_input(
                "workingDirectory",
                "must use an absolute drive or UNC path",
            ));
        }
        if path.len() == 3 {
            Vec::new()
        } else {
            path[3..].split('\\').collect::<Vec<_>>()
        }
    };

    validate_lexical_path_components(&component_tail)
}

#[cfg(target_os = "macos")]
fn validate_platform_working_directory(value: &str) -> Result<(), AppError> {
    if value == "/" {
        return Ok(());
    }
    validate_lexical_path_components(&value[1..].split('/').collect::<Vec<_>>())
}

#[cfg(not(any(windows, target_os = "macos")))]
fn validate_platform_working_directory(value: &str) -> Result<(), AppError> {
    let separators = ['/', '\\'];
    validate_lexical_path_components(
        &value
            .split(separators)
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>(),
    )
}

fn validate_lexical_path_components(components: &[&str]) -> Result<(), AppError> {
    if components
        .iter()
        .any(|component| component.is_empty() || matches!(*component, "." | ".."))
    {
        return Err(invalid_launch_input(
            "workingDirectory",
            "must contain only non-empty normal path components",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn starts_with_ascii_case(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

fn validate_required_text(
    field: &'static str,
    value: &str,
    maximum_bytes: usize,
    entity: &'static str,
) -> Result<(), AppError> {
    validate_optional_text(field, value, maximum_bytes)?;
    if value.trim().is_empty() {
        return Err(invalid_launch_input(
            field,
            &format!("{entity} value must not be empty"),
        ));
    }
    Ok(())
}

fn validate_optional_text(
    field: &'static str,
    value: &str,
    maximum_bytes: usize,
) -> Result<(), AppError> {
    if value.len() > maximum_bytes {
        return Err(invalid_launch_input(field, "exceeds the supported length"));
    }
    if value.contains('\0') {
        return Err(invalid_launch_input(field, "must not contain NUL"));
    }
    Ok(())
}

fn managed_run_serialization_error(message: &'static str, error: serde_json::Error) -> AppError {
    let mut result = AppError::new(ErrorCode::Internal, message);
    result.details.insert("reason".into(), error.to_string());
    result
}

pub(crate) fn invalid_launch_input(field: &'static str, reason: &str) -> AppError {
    let mut error = AppError::new(ErrorCode::InvalidArgument, "invalid launch configuration");
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}
