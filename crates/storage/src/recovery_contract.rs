use domain::{AppError, ErrorCode, ManagedStopOperationResult, ManagedStopOutcome, RunState};

use crate::error::{not_found, storage_error};
use crate::models::{ManagedStopOperationRow, Run};
use crate::repository::RUN_SELECT_BY_ID;
use crate::run_contract::stored_run_to_managed;
use crate::stop_contract::project_stop_result;
use crate::{ManagedRunRecord, StorageResult, SupervisorRepository};

pub const MANAGED_RUN_RECOVERY_BATCH_SIZE: u16 = 64;
const MAX_RECOVERY_CURSOR_BYTES: usize = 256;

const RECOVERY_RUN_SELECT_FIRST: &str = "SELECT id, profile_id, profile_snapshot_json, process_boot_id, process_pid, \
     process_native_start_time, process_group_id, state, exit_code, exit_signal, exit_summary, \
     stop_method, log_directory, log_redaction_version, recovery_state, started_at, updated_at, ended_at, \
     logs_deletion_started_at, logs_deleted_at FROM runs \
     WHERE state IN ('STARTING', 'RUNNING', 'STOP_REQUESTED', \
     'GRACEFUL_STOPPING', 'FORCE_STOPPING', 'RECOVERED') \
     ORDER BY id COLLATE BINARY ASC LIMIT ?";
const RECOVERY_RUN_SELECT_AFTER: &str = "SELECT id, profile_id, profile_snapshot_json, process_boot_id, process_pid, \
     process_native_start_time, process_group_id, state, exit_code, exit_signal, exit_summary, \
     stop_method, log_directory, log_redaction_version, recovery_state, started_at, updated_at, ended_at, \
     logs_deletion_started_at, logs_deleted_at FROM runs \
     WHERE state IN ('STARTING', 'RUNNING', 'STOP_REQUESTED', \
     'GRACEFUL_STOPPING', 'FORCE_STOPPING', 'RECOVERED') \
     AND id COLLATE BINARY > ? COLLATE BINARY \
     ORDER BY id COLLATE BINARY ASC LIMIT ?";
const ACTIVE_STOP_SELECT_BY_RUN: &str = "SELECT operation_id, run_id, kind, status, signal_disposition, outcome, \
     supersedes_operation_id, created_at, updated_at, completed_at \
     FROM managed_stop_operations WHERE run_id = ? \
     AND status IN ('REQUESTED', 'SIGNAL_PENDING', 'IN_PROGRESS', 'TIMED_OUT')";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedRunRecoveryOutcome {
    Recovered,
    ExitedWhileOffline,
    IdentityMismatch,
    Orphaned,
}

impl ManagedRunRecoveryOutcome {
    fn run_state(self) -> RunState {
        match self {
            Self::Recovered => RunState::Recovered,
            Self::ExitedWhileOffline => RunState::ExitedWhileOffline,
            Self::IdentityMismatch => RunState::IdentityMismatch,
            Self::Orphaned => RunState::Orphaned,
        }
    }

    fn storage_value(self) -> &'static str {
        match self {
            Self::Recovered => "RECOVERED",
            Self::ExitedWhileOffline => "EXITED_WHILE_OFFLINE",
            Self::IdentityMismatch => "IDENTITY_MISMATCH",
            Self::Orphaned => "ORPHANED",
        }
    }

    fn summary(self) -> &'static str {
        match self {
            Self::Recovered => "recovery:recovered",
            Self::ExitedWhileOffline => "recovery:exitedWhileOffline",
            Self::IdentityMismatch => "recovery:identityMismatch",
            Self::Orphaned => "recovery:orphaned",
        }
    }

    fn stop_outcome(self) -> Option<ManagedStopOutcome> {
        match self {
            Self::Recovered => None,
            Self::ExitedWhileOffline => Some(ManagedStopOutcome::AlreadyExited),
            Self::IdentityMismatch => Some(ManagedStopOutcome::IdentityMismatch),
            Self::Orphaned => Some(ManagedStopOutcome::Orphaned),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedRunRecoveryCandidate {
    run: ManagedRunRecord,
    active_stop: Option<ManagedStopOperationResult>,
}

impl ManagedRunRecoveryCandidate {
    pub fn run(&self) -> &ManagedRunRecord {
        &self.run
    }

    pub fn active_stop(&self) -> Option<&ManagedStopOperationResult> {
        self.active_stop.as_ref()
    }
}

impl SupervisorRepository {
    /// Returns one deterministic page of unfinished runs. A caller must finish
    /// startup reconciliation before exposing any mutation entry point.
    pub async fn managed_run_recovery_candidates(
        &self,
        after_run_id: Option<&str>,
    ) -> StorageResult<Vec<ManagedRunRecoveryCandidate>> {
        if let Some(after_run_id) = after_run_id {
            validate_text("afterRunId", after_run_id, MAX_RECOVERY_CURSOR_BYTES)?;
        }

        let rows = if let Some(after_run_id) = after_run_id {
            sqlx::query_as::<_, Run>(RECOVERY_RUN_SELECT_AFTER)
                .bind(after_run_id)
                .bind(i64::from(MANAGED_RUN_RECOVERY_BATCH_SIZE))
                .fetch_all(&self.pool)
                .await
        } else {
            sqlx::query_as::<_, Run>(RECOVERY_RUN_SELECT_FIRST)
                .bind(i64::from(MANAGED_RUN_RECOVERY_BATCH_SIZE))
                .fetch_all(&self.pool)
                .await
        }
        .map_err(|error| storage_error("list managed run recovery candidates", error))?;

        let mut candidates = Vec::with_capacity(rows.len());
        for row in rows {
            let run = stored_run_to_managed(row)?;
            validate_recovery_candidate_run(&run)?;
            let active_operation_id = sqlx::query_scalar::<_, String>(
                "SELECT operation_id FROM managed_stop_operations WHERE run_id = ? \
                 AND status IN ('REQUESTED', 'SIGNAL_PENDING', 'IN_PROGRESS', 'TIMED_OUT')",
            )
            .bind(&run.id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| storage_error("read active recovery stop operation", error))?;
            let active_stop = match active_operation_id {
                Some(operation_id) => {
                    let operation = self.managed_stop_operation(&operation_id).await?;
                    if operation.run.run_id != run.id || operation.run.state != run.state {
                        return Err(corrupt_recovery(
                            "activeStop.run",
                            "does not match its recovery candidate",
                        ));
                    }
                    Some(operation)
                }
                None => None,
            };
            candidates.push(ManagedRunRecoveryCandidate { run, active_stop });
        }
        Ok(candidates)
    }

    /// Atomically closes the persisted run and any active stop operation using
    /// the exact snapshots returned by [`Self::managed_run_recovery_candidates`].
    pub async fn reconcile_managed_run(
        &mut self,
        candidate: &ManagedRunRecoveryCandidate,
        outcome: ManagedRunRecoveryOutcome,
        observed_at: &str,
    ) -> StorageResult<ManagedRunRecord> {
        lifecycle::validate_canonical_utc_timestamp("observedAt", observed_at)?;
        if candidate.run.process_instance_key.is_none()
            && outcome != ManagedRunRecoveryOutcome::Orphaned
        {
            return Err(invalid_recovery(
                "run.processInstanceKey",
                "a run without complete identity can only be orphaned",
            ));
        }
        if outcome == ManagedRunRecoveryOutcome::Recovered {
            if candidate.run.process_instance_key.is_none()
                || candidate.run.process_group_id.is_none()
            {
                return Err(invalid_recovery(
                    "run.control",
                    "recovery requires a complete process identity and persisted process group",
                ));
            }
            match candidate
                .active_stop
                .as_ref()
                .map(|operation| operation.status)
            {
                None if !matches!(candidate.run.state, RunState::Running | RunState::Recovered) => {
                    return Err(invalid_recovery(
                        "run.state",
                        "only a running run can recover without an active stop operation",
                    ));
                }
                Some(domain::ManagedStopStatus::SignalPending) => {
                    return Err(invalid_recovery(
                        "activeStop.status",
                        "a signal-pending crash window must not regain control",
                    ));
                }
                Some(
                    domain::ManagedStopStatus::Requested
                    | domain::ManagedStopStatus::InProgress
                    | domain::ManagedStopStatus::TimedOut,
                )
                | None => {}
                Some(
                    domain::ManagedStopStatus::Completed | domain::ManagedStopStatus::Superseded,
                ) => {
                    return Err(corrupt_recovery(
                        "activeStop.status",
                        "uses a terminal status in the active-operation slot",
                    ));
                }
            }
        }

        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| storage_error("begin managed run reconciliation", error))?;
        let current_row = sqlx::query_as::<_, Run>(RUN_SELECT_BY_ID)
            .bind(&candidate.run.id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|error| storage_error("read reconciliation run", error))?
            .ok_or_else(|| not_found("run", &candidate.run.id))?;
        let current = stored_run_to_managed(current_row.clone())?;
        if current != candidate.run {
            return Err(recovery_conflict(&candidate.run.id, "runChanged"));
        }

        let active_rows = sqlx::query_as::<_, ManagedStopOperationRow>(ACTIVE_STOP_SELECT_BY_RUN)
            .bind(&candidate.run.id)
            .fetch_all(&mut *transaction)
            .await
            .map_err(|error| storage_error("read reconciliation stop operation", error))?;
        if active_rows.len() > 1 {
            return Err(corrupt_recovery(
                "activeStop",
                "contains more than one active operation",
            ));
        }
        let active_row = active_rows.into_iter().next();
        let active_result = active_row
            .as_ref()
            .map(|active| project_stop_result(active.clone(), current_row.clone()))
            .transpose()?;
        if active_result.as_ref() != candidate.active_stop.as_ref() {
            return Err(recovery_conflict(&candidate.run.id, "activeStopChanged"));
        }

        if observed_at <= current.updated_at.as_str()
            || active_row
                .as_ref()
                .is_some_and(|active| observed_at <= active.updated_at.as_str())
        {
            return Err(invalid_recovery(
                "observedAt",
                "must be later than the current run and active stop timestamps",
            ));
        }

        let next_state =
            if outcome == ManagedRunRecoveryOutcome::Recovered && candidate.active_stop.is_some() {
                candidate.run.state
            } else {
                outcome.run_state()
            };
        let ended_at =
            (outcome == ManagedRunRecoveryOutcome::ExitedWhileOffline).then_some(observed_at);
        let mut prospective_run = current_row.clone();
        prospective_run.state = run_state_to_storage(next_state).to_owned();
        prospective_run.recovery_state = Some(outcome.storage_value().to_owned());
        prospective_run.exit_summary = Some(outcome.summary().to_owned());
        prospective_run.updated_at = observed_at.to_owned();
        prospective_run.ended_at = ended_at.map(str::to_owned);
        stored_run_to_managed(prospective_run.clone())?;

        if let Some(active) = &active_row {
            let mut prospective_active = active.clone();
            if let Some(stop_outcome) = outcome.stop_outcome() {
                prospective_active.status = "COMPLETED".to_owned();
                prospective_active.outcome = Some(stop_outcome_to_storage(stop_outcome).to_owned());
                prospective_active.updated_at = observed_at.to_owned();
                prospective_active.completed_at = Some(observed_at.to_owned());
            }
            project_stop_result(prospective_active, prospective_run.clone())?;
        }

        if let (Some(active), Some(stop_outcome)) = (&candidate.active_stop, outcome.stop_outcome())
        {
            let stop_result = sqlx::query(
                "UPDATE managed_stop_operations SET status = 'COMPLETED', outcome = ?, \
                 updated_at = ?, completed_at = ? WHERE operation_id = ? AND run_id = ? \
                 AND status = ? AND updated_at = ?",
            )
            .bind(stop_outcome_to_storage(stop_outcome))
            .bind(observed_at)
            .bind(observed_at)
            .bind(&active.operation_id)
            .bind(&candidate.run.id)
            .bind(stop_status_to_storage(active.status))
            .bind(&active.updated_at)
            .execute(&mut *transaction)
            .await
            .map_err(|error| storage_error("complete recovery stop operation", error))?;
            if stop_result.rows_affected() != 1 {
                return Err(recovery_conflict(
                    &candidate.run.id,
                    "activeStopCasRejected",
                ));
            }
        }

        let run_result = sqlx::query(
            "UPDATE runs SET state = ?, recovery_state = ?, exit_summary = ?, \
             updated_at = ?, ended_at = ? WHERE id = ? AND state = ? AND updated_at = ? \
             AND ended_at IS NULL AND (recovery_state IS NULL OR recovery_state = 'RECOVERED')",
        )
        .bind(run_state_to_storage(next_state))
        .bind(outcome.storage_value())
        .bind(outcome.summary())
        .bind(observed_at)
        .bind(ended_at)
        .bind(&candidate.run.id)
        .bind(run_state_to_storage(candidate.run.state))
        .bind(&candidate.run.updated_at)
        .execute(&mut *transaction)
        .await
        .map_err(|error| storage_error("update reconciled managed run", error))?;
        if run_result.rows_affected() != 1 {
            return Err(recovery_conflict(&candidate.run.id, "runCasRejected"));
        }

        let reconciled = sqlx::query_as::<_, Run>(RUN_SELECT_BY_ID)
            .bind(&candidate.run.id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|error| storage_error("read reconciled managed run", error))?
            .ok_or_else(|| not_found("run", &candidate.run.id))?;
        let reconciled = stored_run_to_managed(reconciled)?;
        transaction
            .commit()
            .await
            .map_err(|error| storage_error("commit managed run reconciliation", error))?;
        Ok(reconciled)
    }
}

fn validate_recovery_candidate_run(run: &ManagedRunRecord) -> StorageResult<()> {
    if run.ended_at.is_some() {
        return Err(corrupt_recovery(
            "run.endedAt",
            "is present on an unfinished recovery candidate",
        ));
    }
    if run.exit_code.is_some() || run.exit_signal.is_some() {
        return Err(corrupt_recovery(
            "run.exit",
            "is present on an unfinished recovery candidate",
        ));
    }
    match run.recovery_state {
        None if run.state != RunState::Recovered => Ok(()),
        None => Err(corrupt_recovery(
            "run.recoveryState",
            "a Recovered run is missing its recovery marker",
        )),
        Some(RunState::Recovered)
            if matches!(
                run.state,
                RunState::Recovered
                    | RunState::StopRequested
                    | RunState::GracefulStopping
                    | RunState::ForceStopping
            ) =>
        {
            Ok(())
        }
        Some(RunState::Recovered) => Err(corrupt_recovery(
            "run.recoveryState",
            "does not match the unfinished run state",
        )),
        Some(_) => Err(corrupt_recovery(
            "run.recoveryState",
            "an unfinished run carries a terminal recovery result",
        )),
    }
}

fn validate_text(field: &'static str, value: &str, maximum: usize) -> StorageResult<()> {
    if value.trim().is_empty() || value.len() > maximum || value.contains('\0') {
        return Err(invalid_recovery(
            field,
            "must be non-empty bounded text without NUL",
        ));
    }
    Ok(())
}

fn run_state_to_storage(state: RunState) -> &'static str {
    match state {
        RunState::Starting => "STARTING",
        RunState::Running => "RUNNING",
        RunState::StopRequested => "STOP_REQUESTED",
        RunState::GracefulStopping => "GRACEFUL_STOPPING",
        RunState::ForceStopping => "FORCE_STOPPING",
        RunState::Exited => "EXITED",
        RunState::Failed => "FAILED",
        RunState::Recovered => "RECOVERED",
        RunState::ExitedWhileOffline => "EXITED_WHILE_OFFLINE",
        RunState::IdentityMismatch => "IDENTITY_MISMATCH",
        RunState::Orphaned => "ORPHANED",
    }
}

fn stop_status_to_storage(status: domain::ManagedStopStatus) -> &'static str {
    match status {
        domain::ManagedStopStatus::Requested => "REQUESTED",
        domain::ManagedStopStatus::SignalPending => "SIGNAL_PENDING",
        domain::ManagedStopStatus::InProgress => "IN_PROGRESS",
        domain::ManagedStopStatus::TimedOut => "TIMED_OUT",
        domain::ManagedStopStatus::Completed => "COMPLETED",
        domain::ManagedStopStatus::Superseded => "SUPERSEDED",
    }
}

fn stop_outcome_to_storage(outcome: ManagedStopOutcome) -> &'static str {
    match outcome {
        ManagedStopOutcome::Exited => "EXITED",
        ManagedStopOutcome::AlreadyExited => "ALREADY_EXITED",
        ManagedStopOutcome::IdentityMismatch => "IDENTITY_MISMATCH",
        ManagedStopOutcome::Orphaned => "ORPHANED",
        ManagedStopOutcome::SignalUnavailable => "SIGNAL_UNAVAILABLE",
        ManagedStopOutcome::Failed => "FAILED",
    }
}

fn invalid_recovery(field: &'static str, reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "invalid managed run reconciliation",
    );
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn corrupt_recovery(field: &'static str, reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::StorageError,
        "stored managed run recovery state is invalid",
    );
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn recovery_conflict(run_id: &str, reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Conflict,
        "managed run changed during startup reconciliation",
    );
    error.details.insert("runId".into(), run_id.into());
    error.details.insert("reason".into(), reason.into());
    error
}
