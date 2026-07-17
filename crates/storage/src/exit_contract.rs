use std::collections::HashSet;

use domain::{AppError, ErrorCode, ManagedStopOperationResult, RunState};
use sqlx::SqliteConnection;

use crate::error::storage_error;
use crate::models::{ManagedStopOperationRow, Run};
use crate::run_contract::stored_run_to_managed;
use crate::stop_contract::project_stop_result;
use crate::{ManagedRunRecord, StorageResult, SupervisorRepository};

pub const MANAGED_EXIT_METHOD: &str = "run.stop_all_for_exit";
pub const MAX_MANAGED_EXIT_ACTIVE_RUNS: usize = lifecycle::MAX_EXIT_IMPACT_RUNS;

const MAX_MANAGED_EXIT_LEDGER_ENTRIES: i64 = 4_096;
const MAX_MANAGED_EXIT_OPERATION_ID_BYTES: usize = 128;
const MAX_MANAGED_EXIT_RUN_ID_BYTES: usize = 256;
const ACTIVE_RUN_QUERY_LIMIT: i64 = MAX_MANAGED_EXIT_ACTIVE_RUNS as i64 + 1;

const ACTIVE_RUN_SELECT: &str = "SELECT id, profile_id, profile_snapshot_json, process_boot_id, \
     process_pid, process_native_start_time, process_group_id, state, exit_code, exit_signal, \
     exit_summary, stop_method, log_directory, log_redaction_version, recovery_state, started_at, \
     updated_at, ended_at, logs_deletion_started_at, logs_deleted_at FROM runs \
     WHERE state IN ('STARTING', 'RUNNING', 'STOP_REQUESTED', 'GRACEFUL_STOPPING', \
     'FORCE_STOPPING', 'RECOVERED') ORDER BY id COLLATE BINARY LIMIT ?";

const ACTIVE_STOP_SELECT_BY_RUN: &str = "SELECT operation_id, run_id, kind, status, \
     signal_disposition, outcome, supersedes_operation_id, created_at, updated_at, completed_at \
     FROM managed_stop_operations WHERE run_id = ? \
     AND status IN ('REQUESTED', 'SIGNAL_PENDING', 'IN_PROGRESS', 'TIMED_OUT')";

const EXIT_OPERATION_SELECT_BY_ID: &str = "SELECT operation_id, method, request_sha256, \
     assessment_id, created_at FROM managed_exit_operations WHERE operation_id = ?";

const EXIT_MEMBER_SELECT_BY_OPERATION: &str = "SELECT ordinal, run_id, action, stop_operation_id \
     FROM managed_exit_operation_members WHERE exit_operation_id = ? ORDER BY ordinal";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedExitActiveRun {
    pub run: ManagedRunRecord,
    pub active_stop: Option<ManagedStopOperationResult>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedExitMemberAction {
    None,
    GracefulRequested,
    StopAdopted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedExitOperationMember {
    pub run_id: String,
    pub action: ManagedExitMemberAction,
    pub stop_operation_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedExitOperation {
    pub operation_id: String,
    pub request_sha256: [u8; 32],
    pub assessment_id: String,
    pub created_at: String,
    pub members: Vec<ManagedExitOperationMember>,
}

struct StoredManagedExitOperation {
    operation_id: String,
    method: String,
    request_sha256: Vec<u8>,
    assessment_id: String,
    created_at: String,
    members: Vec<StoredManagedExitOperationMember>,
}

struct StoredManagedExitOperationMember {
    ordinal: i64,
    run_id: String,
    action: String,
    stop_operation_id: Option<String>,
}

impl SupervisorRepository {
    /// Reads the complete bounded durable active-run set from one SQLite
    /// snapshot. The seventeenth row is never returned; it proves that a safe
    /// managed-exit assessment cannot be represented and fails closed.
    pub async fn managed_exit_active_runs(&self) -> StorageResult<Vec<ManagedExitActiveRun>> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| storage_error("begin managed exit active-run read", error))?;
        let rows = sqlx::query_as::<_, Run>(ACTIVE_RUN_SELECT)
            .bind(ACTIVE_RUN_QUERY_LIMIT)
            .fetch_all(&mut *transaction)
            .await
            .map_err(|error| storage_error("read managed exit active runs", error))?;
        if rows.len() > MAX_MANAGED_EXIT_ACTIVE_RUNS {
            return Err(managed_exit_active_capacity_error());
        }

        let mut active_runs = Vec::with_capacity(rows.len());
        for row in rows {
            let run = stored_run_to_managed(row.clone())?;
            let active_stop_row =
                sqlx::query_as::<_, ManagedStopOperationRow>(ACTIVE_STOP_SELECT_BY_RUN)
                    .bind(&run.id)
                    .fetch_optional(&mut *transaction)
                    .await
                    .map_err(|error| storage_error("read managed exit active stop", error))?;
            validate_active_stop_presence(&run, active_stop_row.is_some())?;
            let active_stop = active_stop_row
                .map(|operation| project_stop_result(operation, row))
                .transpose()?;
            active_runs.push(ManagedExitActiveRun { run, active_stop });
        }
        transaction
            .commit()
            .await
            .map_err(|error| storage_error("complete managed exit active-run read", error))?;
        Ok(active_runs)
    }

    /// Returns the immutable committed ledger record for this idempotency key.
    /// A valid key already associated with another request hash fails with a
    /// conflict instead of exposing or replacing the original record.
    pub async fn managed_exit_operation_replay(
        &self,
        operation_id: &str,
        request_sha256: &[u8; 32],
    ) -> StorageResult<Option<ManagedExitOperation>> {
        validate_portable_input(
            "operationId",
            operation_id,
            MAX_MANAGED_EXIT_OPERATION_ID_BYTES,
        )?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|error| storage_error("acquire managed exit replay connection", error))?;
        let Some(stored) = read_stored_exit_operation(&mut connection, operation_id).await? else {
            return Ok(None);
        };
        require_exit_operation_match(operation_id, request_sha256, &stored)?;
        project_stored_exit_operation(stored).map(Some)
    }

    /// Atomically records a fixed, bounded stop-all membership plan. Replay is
    /// checked again inside the write transaction; a matching committed row is
    /// returned unchanged, while a mismatched request is rejected.
    pub async fn prepare_managed_exit_operation(
        &mut self,
        operation: &ManagedExitOperation,
    ) -> StorageResult<ManagedExitOperation> {
        validate_portable_input(
            "operationId",
            &operation.operation_id,
            MAX_MANAGED_EXIT_OPERATION_ID_BYTES,
        )?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| storage_error("begin managed exit operation", error))?;

        if let Some(stored) =
            read_stored_exit_operation(&mut transaction, &operation.operation_id).await?
        {
            require_exit_operation_match(
                &operation.operation_id,
                &operation.request_sha256,
                &stored,
            )?;
            let replay = project_stored_exit_operation(stored)?;
            transaction
                .commit()
                .await
                .map_err(|error| storage_error("complete managed exit replay", error))?;
            return Ok(replay);
        }

        validate_managed_exit_operation(operation)?;
        let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM managed_exit_operations")
            .fetch_one(&mut *transaction)
            .await
            .map_err(|error| storage_error("count managed exit operation ledger", error))?;
        if count >= MAX_MANAGED_EXIT_LEDGER_ENTRIES {
            return Err(managed_exit_ledger_capacity_error(&operation.operation_id));
        }

        sqlx::query(
            "INSERT INTO managed_exit_operations \
             (operation_id, method, request_sha256, assessment_id, created_at) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&operation.operation_id)
        .bind(MANAGED_EXIT_METHOD)
        .bind(operation.request_sha256.as_slice())
        .bind(&operation.assessment_id)
        .bind(&operation.created_at)
        .execute(&mut *transaction)
        .await
        .map_err(|error| storage_error("insert managed exit operation", error))?;

        for (ordinal, member) in operation.members.iter().enumerate() {
            let ordinal = i64::try_from(ordinal).map_err(|_| {
                invalid_exit_field("members", "contains an unsupported member ordinal")
            })?;
            sqlx::query(
                "INSERT INTO managed_exit_operation_members \
                 (exit_operation_id, ordinal, run_id, action, stop_operation_id) \
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind(&operation.operation_id)
            .bind(ordinal)
            .bind(&member.run_id)
            .bind(member_action_to_storage(member.action))
            .bind(&member.stop_operation_id)
            .execute(&mut *transaction)
            .await
            .map_err(|error| storage_error("insert managed exit operation member", error))?;
        }

        let stored = read_stored_exit_operation(&mut transaction, &operation.operation_id)
            .await?
            .ok_or_else(|| corrupt_exit("operationId", "inserted operation could not be read"))?;
        require_exit_operation_match(&operation.operation_id, &operation.request_sha256, &stored)?;
        let persisted = project_stored_exit_operation(stored)?;
        if persisted != *operation {
            return Err(corrupt_exit(
                "operation",
                "inserted operation does not match its validated input",
            ));
        }
        transaction
            .commit()
            .await
            .map_err(|error| storage_error("commit managed exit operation", error))?;
        Ok(persisted)
    }
}

async fn read_stored_exit_operation(
    connection: &mut SqliteConnection,
    operation_id: &str,
) -> StorageResult<Option<StoredManagedExitOperation>> {
    let header =
        sqlx::query_as::<_, (String, String, Vec<u8>, String, String)>(EXIT_OPERATION_SELECT_BY_ID)
            .bind(operation_id)
            .fetch_optional(&mut *connection)
            .await
            .map_err(|error| storage_error("read managed exit operation", error))?;
    let Some((operation_id, method, request_sha256, assessment_id, created_at)) = header else {
        return Ok(None);
    };
    let members =
        sqlx::query_as::<_, (i64, String, String, Option<String>)>(EXIT_MEMBER_SELECT_BY_OPERATION)
            .bind(&operation_id)
            .fetch_all(connection)
            .await
            .map_err(|error| storage_error("read managed exit operation members", error))?
            .into_iter()
            .map(
                |(ordinal, run_id, action, stop_operation_id)| StoredManagedExitOperationMember {
                    ordinal,
                    run_id,
                    action,
                    stop_operation_id,
                },
            )
            .collect();
    Ok(Some(StoredManagedExitOperation {
        operation_id,
        method,
        request_sha256,
        assessment_id,
        created_at,
        members,
    }))
}

fn project_stored_exit_operation(
    stored: StoredManagedExitOperation,
) -> StorageResult<ManagedExitOperation> {
    validate_portable_stored(
        "operationId",
        &stored.operation_id,
        MAX_MANAGED_EXIT_OPERATION_ID_BYTES,
    )?;
    if stored.method != MANAGED_EXIT_METHOD {
        return Err(corrupt_exit("method", "uses an unsupported RPC method"));
    }
    let request_sha256 = stored
        .request_sha256
        .try_into()
        .map_err(|_| corrupt_exit("requestSha256", "is not a 32-byte SHA-256 digest"))?;
    lifecycle::validate_exit_assessment_id(&stored.assessment_id)
        .map_err(|_| corrupt_exit("assessmentId", "is not a lowercase SHA-256 digest"))?;
    lifecycle::validate_canonical_utc_timestamp("createdAt", &stored.created_at)
        .map_err(|_| corrupt_exit("createdAt", "is not a canonical UTC timestamp"))?;
    if stored.members.len() > MAX_MANAGED_EXIT_ACTIVE_RUNS {
        return Err(corrupt_exit(
            "members",
            "exceeds the managed exit member limit",
        ));
    }

    let mut members = Vec::with_capacity(stored.members.len());
    let mut run_ids = HashSet::with_capacity(stored.members.len());
    let mut stop_operation_ids = HashSet::with_capacity(stored.members.len());
    let mut previous_run_id: Option<String> = None;
    for (expected_ordinal, member) in stored.members.into_iter().enumerate() {
        if usize::try_from(member.ordinal).ok() != Some(expected_ordinal) {
            return Err(corrupt_exit(
                "members.ordinal",
                "does not form a contiguous zero-based sequence",
            ));
        }
        validate_required_stored(
            "members.runId",
            &member.run_id,
            MAX_MANAGED_EXIT_RUN_ID_BYTES,
        )?;
        if !run_ids.insert(member.run_id.clone()) {
            return Err(corrupt_exit("members.runId", "contains a duplicate run ID"));
        }
        if previous_run_id
            .as_deref()
            .is_some_and(|previous| previous >= member.run_id.as_str())
        {
            return Err(corrupt_exit(
                "members.runId",
                "is not in strictly increasing run ID order",
            ));
        }
        previous_run_id = Some(member.run_id.clone());
        let action = member_action_from_storage(&member.action)?;
        validate_member_stop_operation(action, member.stop_operation_id.as_deref(), true)?;
        if let Some(stop_operation_id) = &member.stop_operation_id {
            if !stop_operation_ids.insert(stop_operation_id.clone()) {
                return Err(corrupt_exit(
                    "members.stopOperationId",
                    "contains a duplicate stop operation ID",
                ));
            }
        }
        members.push(ManagedExitOperationMember {
            run_id: member.run_id,
            action,
            stop_operation_id: member.stop_operation_id,
        });
    }
    Ok(ManagedExitOperation {
        operation_id: stored.operation_id,
        request_sha256,
        assessment_id: stored.assessment_id,
        created_at: stored.created_at,
        members,
    })
}

fn validate_managed_exit_operation(operation: &ManagedExitOperation) -> StorageResult<()> {
    validate_portable_input(
        "operationId",
        &operation.operation_id,
        MAX_MANAGED_EXIT_OPERATION_ID_BYTES,
    )?;
    lifecycle::validate_exit_assessment_id(&operation.assessment_id)
        .map_err(|_| invalid_exit_field("assessmentId", "must be a lowercase SHA-256 digest"))?;
    lifecycle::validate_canonical_utc_timestamp("createdAt", &operation.created_at)
        .map_err(|error| invalid_exit_field("createdAt", &error.message))?;
    if operation.members.len() > MAX_MANAGED_EXIT_ACTIVE_RUNS {
        return Err(invalid_exit_field(
            "members",
            "exceeds the managed exit member limit",
        ));
    }

    let mut run_ids = HashSet::with_capacity(operation.members.len());
    let mut stop_operation_ids = HashSet::with_capacity(operation.members.len());
    let mut previous_run_id: Option<&str> = None;
    for member in &operation.members {
        validate_required_input(
            "members.runId",
            &member.run_id,
            MAX_MANAGED_EXIT_RUN_ID_BYTES,
        )?;
        if !run_ids.insert(member.run_id.as_str()) {
            return Err(invalid_exit_field(
                "members.runId",
                "contains a duplicate run ID",
            ));
        }
        if previous_run_id.is_some_and(|previous| previous >= member.run_id.as_str()) {
            return Err(invalid_exit_field(
                "members.runId",
                "must be in strictly increasing run ID order",
            ));
        }
        previous_run_id = Some(&member.run_id);
        validate_member_stop_operation(member.action, member.stop_operation_id.as_deref(), false)?;
        if let Some(stop_operation_id) = member.stop_operation_id.as_deref() {
            if !stop_operation_ids.insert(stop_operation_id) {
                return Err(invalid_exit_field(
                    "members.stopOperationId",
                    "contains a duplicate stop operation ID",
                ));
            }
        }
    }
    Ok(())
}

fn validate_member_stop_operation(
    action: ManagedExitMemberAction,
    stop_operation_id: Option<&str>,
    stored: bool,
) -> StorageResult<()> {
    let valid_presence = match action {
        ManagedExitMemberAction::None => stop_operation_id.is_none(),
        ManagedExitMemberAction::GracefulRequested | ManagedExitMemberAction::StopAdopted => {
            stop_operation_id.is_some()
        }
    };
    if !valid_presence {
        return Err(exit_validation_error(
            stored,
            "members.stopOperationId",
            "does not match the member action",
        ));
    }
    if let Some(stop_operation_id) = stop_operation_id {
        if stored {
            validate_portable_stored(
                "members.stopOperationId",
                stop_operation_id,
                MAX_MANAGED_EXIT_OPERATION_ID_BYTES,
            )?;
        } else {
            validate_portable_input(
                "members.stopOperationId",
                stop_operation_id,
                MAX_MANAGED_EXIT_OPERATION_ID_BYTES,
            )?;
        }
    }
    Ok(())
}

fn validate_active_stop_presence(
    run: &ManagedRunRecord,
    has_active_stop: bool,
) -> StorageResult<()> {
    let requires_active_stop = matches!(
        run.state,
        RunState::StopRequested | RunState::GracefulStopping | RunState::ForceStopping
    );
    if requires_active_stop == has_active_stop {
        return Ok(());
    }
    let reason = if requires_active_stop {
        "stopping run is missing its active stop operation"
    } else {
        "non-stopping run has an active stop operation"
    };
    let mut error = corrupt_exit("activeStop", reason);
    error.details.insert("runId".into(), run.id.clone());
    Err(error)
}

fn require_exit_operation_match(
    requested_operation_id: &str,
    requested_sha256: &[u8; 32],
    stored: &StoredManagedExitOperation,
) -> StorageResult<()> {
    validate_portable_stored(
        "operationId",
        &stored.operation_id,
        MAX_MANAGED_EXIT_OPERATION_ID_BYTES,
    )?;
    if stored.operation_id != requested_operation_id {
        return Err(corrupt_exit(
            "operationId",
            "does not match the requested ledger key",
        ));
    }
    if stored.request_sha256.len() != 32 {
        return Err(corrupt_exit(
            "requestSha256",
            "is not a 32-byte SHA-256 digest",
        ));
    }
    if stored.method == MANAGED_EXIT_METHOD
        && stored.request_sha256.as_slice() == requested_sha256.as_slice()
    {
        return Ok(());
    }
    let mut error = AppError::new(
        ErrorCode::Conflict,
        "managed exit operation ID was already used for a different request",
    );
    error.operation_id = Some(requested_operation_id.to_owned());
    error
        .details
        .insert("requestedMethod".into(), MANAGED_EXIT_METHOD.into());
    error
        .details
        .insert("recordedMethod".into(), stored.method.clone());
    error.details.insert(
        "requestHashMatches".into(),
        (stored.request_sha256.as_slice() == requested_sha256.as_slice()).to_string(),
    );
    Err(error)
}

fn member_action_to_storage(action: ManagedExitMemberAction) -> &'static str {
    match action {
        ManagedExitMemberAction::None => "NONE",
        ManagedExitMemberAction::GracefulRequested => "GRACEFUL_REQUESTED",
        ManagedExitMemberAction::StopAdopted => "STOP_ADOPTED",
    }
}

fn member_action_from_storage(value: &str) -> StorageResult<ManagedExitMemberAction> {
    match value {
        "NONE" => Ok(ManagedExitMemberAction::None),
        "GRACEFUL_REQUESTED" => Ok(ManagedExitMemberAction::GracefulRequested),
        "STOP_ADOPTED" => Ok(ManagedExitMemberAction::StopAdopted),
        _ => Err(corrupt_exit(
            "members.action",
            "uses an unsupported member action",
        )),
    }
}

fn validate_portable_input(field: &'static str, value: &str, maximum: usize) -> StorageResult<()> {
    if is_portable_identifier(value, maximum) {
        Ok(())
    } else {
        Err(invalid_exit_field(
            field,
            "must be a bounded portable ASCII identifier",
        ))
    }
}

fn validate_portable_stored(field: &'static str, value: &str, maximum: usize) -> StorageResult<()> {
    if is_portable_identifier(value, maximum) {
        Ok(())
    } else {
        Err(corrupt_exit(field, "is not a bounded portable identifier"))
    }
}

fn is_portable_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn validate_required_input(field: &'static str, value: &str, maximum: usize) -> StorageResult<()> {
    if is_valid_required_text(value, maximum) {
        Ok(())
    } else {
        Err(invalid_exit_field(
            field,
            "must be nonblank, bounded text without NUL",
        ))
    }
}

fn validate_required_stored(field: &'static str, value: &str, maximum: usize) -> StorageResult<()> {
    if is_valid_required_text(value, maximum) {
        Ok(())
    } else {
        Err(corrupt_exit(
            field,
            "is not nonblank bounded text without NUL",
        ))
    }
}

fn is_valid_required_text(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty() && value.len() <= maximum && !value.contains('\0')
}

fn exit_validation_error(stored: bool, field: &'static str, reason: &'static str) -> AppError {
    if stored {
        corrupt_exit(field, reason)
    } else {
        invalid_exit_field(field, reason)
    }
}

fn invalid_exit_field(field: &'static str, reason: &str) -> AppError {
    let mut error = AppError::new(ErrorCode::InvalidArgument, "invalid managed exit operation");
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn corrupt_exit(field: &'static str, reason: &str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::StorageError,
        "stored managed exit operation is invalid",
    );
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn managed_exit_active_capacity_error() -> AppError {
    let mut error = AppError::new(
        ErrorCode::Conflict,
        "managed exit active-run capacity is exhausted",
    );
    error.retryable = true;
    error.details.insert(
        "maximumActiveRuns".into(),
        MAX_MANAGED_EXIT_ACTIVE_RUNS.to_string(),
    );
    error
        .details
        .insert("observedAtLeast".into(), ACTIVE_RUN_QUERY_LIMIT.to_string());
    error
}

fn managed_exit_ledger_capacity_error(operation_id: &str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::StorageError,
        "managed exit operation ledger capacity is exhausted",
    );
    error.operation_id = Some(operation_id.to_owned());
    error
        .details
        .insert("limit".into(), MAX_MANAGED_EXIT_LEDGER_ENTRIES.to_string());
    error
}
