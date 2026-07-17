use domain::{
    AppError, ErrorCode, ForceStopManagedRunRequest, ManagedRunSummary, ManagedStopKind,
    ManagedStopOperationResult, ManagedStopOutcome, ManagedStopSignalDisposition,
    ManagedStopStatus, RunState, StopManagedRunRequest,
};
use sqlx::SqliteConnection;

use crate::error::{not_found, storage_error};
use crate::models::{ManagedStopOperationRow, Run};
use crate::repository::RUN_SELECT_BY_ID;
use crate::run_contract::stored_run_to_managed;
use crate::{StorageResult, SupervisorRepository};

const MAX_STOP_OPERATION_ID_BYTES: usize = 128;
const MAX_STOP_RUN_ID_BYTES: usize = 256;
const MAX_EXIT_SIGNAL_BYTES: usize = 128;

const STOP_OPERATION_SELECT_BY_ID: &str = "SELECT operation_id, run_id, kind, status, \
     signal_disposition, outcome, supersedes_operation_id, created_at, updated_at, completed_at \
     FROM managed_stop_operations WHERE operation_id = ?";

const ACTIVE_STOP_OPERATION_SELECT_BY_RUN: &str = "SELECT operation_id, run_id, kind, status, \
     signal_disposition, outcome, supersedes_operation_id, created_at, updated_at, completed_at \
     FROM managed_stop_operations WHERE run_id = ? \
     AND status IN ('REQUESTED', 'SIGNAL_PENDING', 'IN_PROGRESS', 'TIMED_OUT')";

/// Keeps the graceful and force request DTOs distinct while allowing their
/// durable transaction to share one implementation.
#[derive(Clone, Copy, Debug)]
pub enum ManagedStopRequest<'a> {
    Graceful(&'a StopManagedRunRequest),
    Force(&'a ForceStopManagedRunRequest),
}

impl<'a> ManagedStopRequest<'a> {
    fn validate(self) -> StorageResult<()> {
        match self {
            Self::Graceful(request) => lifecycle::validate_stop_managed_run_request(request),
            Self::Force(request) => lifecycle::validate_force_stop_managed_run_request(request),
        }
    }

    fn run_id(self) -> &'a str {
        match self {
            Self::Graceful(request) => &request.run_id,
            Self::Force(request) => &request.run_id,
        }
    }

    fn kind(self) -> ManagedStopKind {
        match self {
            Self::Graceful(_) => ManagedStopKind::Graceful,
            Self::Force(_) => ManagedStopKind::Force,
        }
    }

    fn supersede_operation_id(self) -> Option<&'a str> {
        match self {
            Self::Graceful(_) => None,
            Self::Force(request) => request.supersede_operation_id.as_deref(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedStopBeginDecision {
    pub result: ManagedStopOperationResult,
    pub created: bool,
    pub superseded_operation_id: Option<String>,
}

/// Exit information is accepted only for an `Exited` outcome. Other stop
/// failures persist closed summaries instead of raw platform diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedStopCompletion {
    pub outcome: ManagedStopOutcome,
    pub exit_code: Option<i64>,
    pub exit_signal: Option<String>,
}

impl SupervisorRepository {
    /// Begins a globally idempotent managed stop. A new live-run operation and
    /// `RUNNING -> STOP_REQUESTED` are committed atomically. Reusing the same
    /// operation ID returns its durable state; changing its run, kind, or
    /// supersession target is rejected.
    pub async fn begin_managed_stop(
        &mut self,
        operation_id: &str,
        request: ManagedStopRequest<'_>,
        now: &str,
    ) -> StorageResult<ManagedStopBeginDecision> {
        lifecycle::validate_managed_stop_operation_id(operation_id)?;
        request.validate()?;
        validate_timestamp("now", now)?;
        if request.supersede_operation_id() == Some(operation_id) {
            return Err(invalid_stop_field(
                "supersedeOperationId",
                "must identify a different graceful stop operation",
            ));
        }

        let run_id = request.run_id();
        let kind = request.kind();
        let supersede_operation_id = request.supersede_operation_id();
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| storage_error("begin managed stop transaction", error))?;

        if let Some(existing) = stop_operation_optional(&mut transaction, operation_id).await? {
            let existing_kind = stop_kind_from_storage(&existing.kind)?;
            if existing.run_id != run_id
                || existing_kind != kind
                || existing.supersedes_operation_id.as_deref() != supersede_operation_id
            {
                return Err(operation_id_conflict(operation_id, run_id, kind, &existing));
            }
            let result = read_stop_result(&mut transaction, operation_id).await?;
            transaction
                .commit()
                .await
                .map_err(|error| storage_error("commit managed stop replay", error))?;
            return Ok(ManagedStopBeginDecision {
                superseded_operation_id: existing.supersedes_operation_id,
                result,
                created: false,
            });
        }

        let active = active_stop_operation(&mut transaction, run_id).await?;
        let run_row = run_row(&mut transaction, run_id).await?;
        let run = stored_run_to_managed(run_row.clone())?;

        if let Some(active) = active {
            let active_kind = stop_kind_from_storage(&active.kind)?;
            let active_status = stop_status_from_storage(&active.status)?;
            project_stop_result(active.clone(), run_row.clone())?;
            let may_supersede = kind == ManagedStopKind::Force
                && active_kind == ManagedStopKind::Graceful
                && supersede_operation_id == Some(active.operation_id.as_str());
            if !may_supersede {
                return Err(active_stop_conflict(
                    run_id,
                    kind,
                    supersede_operation_id,
                    &active,
                ));
            }
            if !matches!(
                run.state,
                RunState::StopRequested | RunState::GracefulStopping
            ) {
                return Err(run_state_conflict(
                    run_id,
                    "STOP_REQUESTED or GRACEFUL_STOPPING",
                    run.state,
                ));
            }
            validate_stop_transition_timestamp(now, &active.updated_at, &run.updated_at)?;

            let mut prospective_run = run_row.clone();
            prospective_run.stop_method = Some(stop_kind_to_storage(kind).to_owned());
            prospective_run.updated_at = now.to_owned();
            let mut prospective_superseded = active.clone();
            prospective_superseded.status =
                stop_status_to_storage(ManagedStopStatus::Superseded).to_owned();
            prospective_superseded.updated_at = now.to_owned();
            prospective_superseded.completed_at = Some(now.to_owned());
            project_stop_result(prospective_superseded, prospective_run.clone())?;
            project_stop_result(
                prospective_stop_operation(
                    operation_id,
                    run_id,
                    kind,
                    ManagedStopStatus::Requested,
                    None,
                    None,
                    Some(&active.operation_id),
                    now,
                    None,
                ),
                prospective_run,
            )?;

            let superseded = sqlx::query(
                "UPDATE managed_stop_operations SET status = 'SUPERSEDED', updated_at = ?, \
                 completed_at = ? WHERE operation_id = ? AND kind = 'GRACEFUL' AND status = ? \
                 AND updated_at = ?",
            )
            .bind(now)
            .bind(now)
            .bind(&active.operation_id)
            .bind(stop_status_to_storage(active_status))
            .bind(&active.updated_at)
            .execute(&mut *transaction)
            .await
            .map_err(|error| storage_error("supersede graceful stop operation", error))?;
            require_stop_cas(
                superseded.rows_affected(),
                &active.operation_id,
                &active.status,
            )?;

            let touched_run = sqlx::query(
                "UPDATE runs SET stop_method = 'FORCE', updated_at = ? WHERE id = ? \
                 AND state IN ('STOP_REQUESTED', 'GRACEFUL_STOPPING') AND ended_at IS NULL \
                 AND updated_at = ?",
            )
            .bind(now)
            .bind(run_id)
            .bind(&run_row.updated_at)
            .execute(&mut *transaction)
            .await
            .map_err(|error| storage_error("record force stop supersession", error))?;
            if touched_run.rows_affected() != 1 {
                return Err(run_state_conflict(
                    run_id,
                    "STOP_REQUESTED or GRACEFUL_STOPPING",
                    run.state,
                ));
            }

            insert_stop_operation(
                &mut transaction,
                operation_id,
                run_id,
                kind,
                ManagedStopStatus::Requested,
                None,
                None,
                Some(&active.operation_id),
                now,
                None,
            )
            .await?;
            let result = read_stop_result(&mut transaction, operation_id).await?;
            transaction
                .commit()
                .await
                .map_err(|error| storage_error("commit force stop supersession", error))?;
            return Ok(ManagedStopBeginDecision {
                result,
                created: true,
                superseded_operation_id: Some(active.operation_id),
            });
        }

        if supersede_operation_id.is_some() {
            return Err(missing_superseded_operation(
                run_id,
                supersede_operation_id.unwrap_or_default(),
            ));
        }

        if let Some(outcome) = completed_outcome_for_run(run.state) {
            validate_stop_transition_timestamp(now, &run.updated_at, &run.updated_at)?;
            project_stop_result(
                prospective_stop_operation(
                    operation_id,
                    run_id,
                    kind,
                    ManagedStopStatus::Completed,
                    None,
                    Some(outcome),
                    None,
                    now,
                    Some(now),
                ),
                run_row.clone(),
            )?;
            insert_stop_operation(
                &mut transaction,
                operation_id,
                run_id,
                kind,
                ManagedStopStatus::Completed,
                None,
                Some(outcome),
                None,
                now,
                Some(now),
            )
            .await?;
            let result = read_stop_result(&mut transaction, operation_id).await?;
            transaction
                .commit()
                .await
                .map_err(|error| storage_error("commit completed managed stop replay", error))?;
            return Ok(ManagedStopBeginDecision {
                result,
                created: true,
                superseded_operation_id: None,
            });
        }

        if !matches!(run.state, RunState::Running | RunState::Recovered) {
            return Err(run_state_conflict(
                run_id,
                "RUNNING or RECOVERED",
                run.state,
            ));
        }
        if run.process_instance_key.is_none() {
            return Err(corrupt_stop(
                "run.processInstanceKey",
                "live managed run does not have a complete process identity",
            ));
        }

        validate_stop_transition_timestamp(now, &run.updated_at, &run.updated_at)?;
        let mut prospective_run = run_row.clone();
        prospective_run.state = run_state_to_storage(RunState::StopRequested).to_owned();
        prospective_run.stop_method = Some(stop_kind_to_storage(kind).to_owned());
        prospective_run.updated_at = now.to_owned();
        project_stop_result(
            prospective_stop_operation(
                operation_id,
                run_id,
                kind,
                ManagedStopStatus::Requested,
                None,
                None,
                None,
                now,
                None,
            ),
            prospective_run,
        )?;

        insert_stop_operation(
            &mut transaction,
            operation_id,
            run_id,
            kind,
            ManagedStopStatus::Requested,
            None,
            None,
            None,
            now,
            None,
        )
        .await?;
        let transitioned = sqlx::query(
            "UPDATE runs SET state = 'STOP_REQUESTED', stop_method = ?, updated_at = ? \
             WHERE id = ? AND state = ? AND ended_at IS NULL \
              AND process_boot_id IS NOT NULL AND process_pid IS NOT NULL \
              AND process_native_start_time IS NOT NULL AND updated_at = ?",
        )
        .bind(stop_kind_to_storage(kind))
        .bind(now)
        .bind(run_id)
        .bind(run_state_to_storage(run.state))
        .bind(&run_row.updated_at)
        .execute(&mut *transaction)
        .await
        .map_err(|error| storage_error("request managed run stop", error))?;
        if transitioned.rows_affected() != 1 {
            return Err(run_state_conflict(
                run_id,
                "RUNNING or RECOVERED",
                run.state,
            ));
        }

        let result = read_stop_result(&mut transaction, operation_id).await?;
        transaction
            .commit()
            .await
            .map_err(|error| storage_error("commit managed stop transaction", error))?;
        Ok(ManagedStopBeginDecision {
            result,
            created: true,
            superseded_operation_id: None,
        })
    }

    pub async fn managed_stop_operation(
        &self,
        operation_id: &str,
    ) -> StorageResult<ManagedStopOperationResult> {
        lifecycle::validate_managed_stop_operation_id(operation_id)?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|error| storage_error("acquire managed stop read connection", error))?;
        read_stop_result(&mut connection, operation_id).await
    }

    /// Returns the one nonterminal stop operation selected by the partial
    /// unique index for this run. Terminal operations are history, not active
    /// control state.
    pub async fn active_managed_stop_for_run(
        &self,
        run_id: &str,
    ) -> StorageResult<Option<ManagedStopOperationResult>> {
        validate_stored_text("runId", run_id, MAX_STOP_RUN_ID_BYTES)?;
        let mut connection = self
            .pool
            .acquire()
            .await
            .map_err(|error| storage_error("acquire active managed stop connection", error))?;
        let Some(operation) = active_stop_operation(&mut connection, run_id).await? else {
            return Ok(None);
        };
        let run = run_row(&mut connection, run_id).await?;
        project_stop_result(operation, run).map(Some)
    }

    /// Reserves the only signal attempt. A failed CAS is returned as a
    /// conflict, so a caller must not send a signal after replaying this stage.
    pub async fn mark_stop_signal_pending(
        &mut self,
        operation_id: &str,
        now: &str,
    ) -> StorageResult<ManagedStopOperationResult> {
        validate_stop_stage_input(operation_id, now)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| storage_error("begin stop signal pending transaction", error))?;
        let operation = stop_operation(&mut transaction, operation_id).await?;
        let status = stop_status_from_storage(&operation.status)?;
        if status != ManagedStopStatus::Requested {
            return Err(stop_stage_conflict(
                operation_id,
                ManagedStopStatus::Requested,
                status,
            ));
        }
        let run = run_row(&mut transaction, &operation.run_id).await?;
        project_stop_result(operation.clone(), run.clone())?;
        validate_stop_transition_timestamp(now, &operation.updated_at, &run.updated_at)?;
        let mut prospective_operation = operation.clone();
        prospective_operation.status =
            stop_status_to_storage(ManagedStopStatus::SignalPending).to_owned();
        prospective_operation.updated_at = now.to_owned();
        project_stop_result(prospective_operation, run)?;

        let transitioned_operation = sqlx::query(
            "UPDATE managed_stop_operations SET status = 'SIGNAL_PENDING', updated_at = ? \
             WHERE operation_id = ? AND status = 'REQUESTED' AND updated_at = ?",
        )
        .bind(now)
        .bind(operation_id)
        .bind(&operation.updated_at)
        .execute(&mut *transaction)
        .await
        .map_err(|error| storage_error("mark managed stop signal pending", error))?;
        require_stop_cas(
            transitioned_operation.rows_affected(),
            operation_id,
            "REQUESTED",
        )?;

        let result = read_stop_result(&mut transaction, operation_id).await?;
        transaction
            .commit()
            .await
            .map_err(|error| storage_error("commit stop signal pending", error))?;
        Ok(result)
    }

    /// Persists both delivered and unavailable attempts before the caller may
    /// wait, time out, or complete the operation. The run transition and
    /// operation transition are one transaction.
    pub async fn mark_stop_signal_attempted(
        &mut self,
        operation_id: &str,
        disposition: ManagedStopSignalDisposition,
        now: &str,
    ) -> StorageResult<ManagedStopOperationResult> {
        validate_stop_stage_input(operation_id, now)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| storage_error("begin stop signal attempt transaction", error))?;
        let operation = stop_operation(&mut transaction, operation_id).await?;
        let kind = stop_kind_from_storage(&operation.kind)?;
        let status = stop_status_from_storage(&operation.status)?;
        if status != ManagedStopStatus::SignalPending {
            return Err(stop_stage_conflict(
                operation_id,
                ManagedStopStatus::SignalPending,
                status,
            ));
        }
        let current_run = run_row(&mut transaction, &operation.run_id).await?;
        project_stop_result(operation.clone(), current_run.clone())?;
        validate_stop_transition_timestamp(now, &operation.updated_at, &current_run.updated_at)?;

        let next_run_state = match kind {
            ManagedStopKind::Graceful => RunState::GracefulStopping,
            ManagedStopKind::Force => RunState::ForceStopping,
        };
        let mut prospective_run = current_run.clone();
        prospective_run.state = run_state_to_storage(next_run_state).to_owned();
        prospective_run.stop_method = Some(stop_kind_to_storage(kind).to_owned());
        prospective_run.updated_at = now.to_owned();
        let mut prospective_operation = operation.clone();
        prospective_operation.status =
            stop_status_to_storage(ManagedStopStatus::InProgress).to_owned();
        prospective_operation.signal_disposition =
            Some(signal_disposition_to_storage(disposition).to_owned());
        prospective_operation.updated_at = now.to_owned();
        project_stop_result(prospective_operation, prospective_run)?;
        let (transitioned_run, expected_run_states) = match kind {
            ManagedStopKind::Graceful => (
                sqlx::query(
                    "UPDATE runs SET state = ?, stop_method = ?, updated_at = ? WHERE id = ? \
                     AND state = 'STOP_REQUESTED' AND ended_at IS NULL AND updated_at = ?",
                )
                .bind(run_state_to_storage(next_run_state))
                .bind(stop_kind_to_storage(kind))
                .bind(now)
                .bind(&operation.run_id)
                .bind(&current_run.updated_at)
                .execute(&mut *transaction)
                .await,
                "STOP_REQUESTED",
            ),
            ManagedStopKind::Force => (
                sqlx::query(
                    "UPDATE runs SET state = ?, stop_method = ?, updated_at = ? WHERE id = ? \
                     AND state IN ('STOP_REQUESTED', 'GRACEFUL_STOPPING') AND ended_at IS NULL \
                     AND updated_at = ?",
                )
                .bind(run_state_to_storage(next_run_state))
                .bind(stop_kind_to_storage(kind))
                .bind(now)
                .bind(&operation.run_id)
                .bind(&current_run.updated_at)
                .execute(&mut *transaction)
                .await,
                "STOP_REQUESTED or GRACEFUL_STOPPING",
            ),
        };
        let transitioned_run = transitioned_run
            .map_err(|error| storage_error("mark managed run stop in progress", error))?;
        if transitioned_run.rows_affected() != 1 {
            let current = run_row(&mut transaction, &operation.run_id).await?;
            return Err(run_state_conflict(
                &operation.run_id,
                expected_run_states,
                run_state_from_storage(&current.state)?,
            ));
        }

        let transitioned_operation = sqlx::query(
            "UPDATE managed_stop_operations SET status = 'IN_PROGRESS', \
             signal_disposition = ?, updated_at = ? \
             WHERE operation_id = ? AND status = 'SIGNAL_PENDING' AND updated_at = ?",
        )
        .bind(signal_disposition_to_storage(disposition))
        .bind(now)
        .bind(operation_id)
        .bind(&operation.updated_at)
        .execute(&mut *transaction)
        .await
        .map_err(|error| storage_error("record managed stop signal attempt", error))?;
        require_stop_cas(
            transitioned_operation.rows_affected(),
            operation_id,
            "SIGNAL_PENDING",
        )?;

        let result = read_stop_result(&mut transaction, operation_id).await?;
        transaction
            .commit()
            .await
            .map_err(|error| storage_error("commit stop signal attempt", error))?;
        Ok(result)
    }

    /// Records expiration of the graceful wait without changing the run out
    /// of `GRACEFUL_STOPPING`. A later natural exit may still complete it.
    pub async fn mark_graceful_timed_out(
        &mut self,
        operation_id: &str,
        now: &str,
    ) -> StorageResult<ManagedStopOperationResult> {
        validate_stop_stage_input(operation_id, now)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| storage_error("begin graceful stop timeout transaction", error))?;
        let operation = stop_operation(&mut transaction, operation_id).await?;
        let kind = stop_kind_from_storage(&operation.kind)?;
        let status = stop_status_from_storage(&operation.status)?;
        if kind != ManagedStopKind::Graceful || status != ManagedStopStatus::InProgress {
            return Err(stop_stage_conflict(
                operation_id,
                ManagedStopStatus::InProgress,
                status,
            ));
        }
        let current_run = run_row(&mut transaction, &operation.run_id).await?;
        project_stop_result(operation.clone(), current_run.clone())?;
        validate_stop_transition_timestamp(now, &operation.updated_at, &current_run.updated_at)?;
        let mut prospective_run = current_run.clone();
        prospective_run.updated_at = now.to_owned();
        let mut prospective_operation = operation.clone();
        prospective_operation.status =
            stop_status_to_storage(ManagedStopStatus::TimedOut).to_owned();
        prospective_operation.updated_at = now.to_owned();
        project_stop_result(prospective_operation, prospective_run)?;

        let transitioned = sqlx::query(
            "UPDATE managed_stop_operations SET status = 'TIMED_OUT', updated_at = ? \
             WHERE operation_id = ? AND kind = 'GRACEFUL' AND status = 'IN_PROGRESS' \
             AND updated_at = ?",
        )
        .bind(now)
        .bind(operation_id)
        .bind(&operation.updated_at)
        .execute(&mut *transaction)
        .await
        .map_err(|error| storage_error("record graceful stop timeout", error))?;
        require_stop_cas(transitioned.rows_affected(), operation_id, "IN_PROGRESS")?;

        let touched_run = sqlx::query(
            "UPDATE runs SET updated_at = ? WHERE id = ? AND state = 'GRACEFUL_STOPPING' \
             AND ended_at IS NULL AND updated_at = ?",
        )
        .bind(now)
        .bind(&operation.run_id)
        .bind(&current_run.updated_at)
        .execute(&mut *transaction)
        .await
        .map_err(|error| storage_error("retain graceful stopping run", error))?;
        if touched_run.rows_affected() != 1 {
            let current = run_row(&mut transaction, &operation.run_id).await?;
            return Err(run_state_conflict(
                &operation.run_id,
                "GRACEFUL_STOPPING",
                run_state_from_storage(&current.state)?,
            ));
        }

        let result = read_stop_result(&mut transaction, operation_id).await?;
        transaction
            .commit()
            .await
            .map_err(|error| storage_error("commit graceful stop timeout", error))?;
        Ok(result)
    }

    /// Completes an active operation and updates the run outcome atomically.
    /// A timed-out graceful operation may still converge to `Exited` unless a
    /// force operation has already superseded it.
    pub async fn complete_stop(
        &mut self,
        operation_id: &str,
        completion: &ManagedStopCompletion,
        now: &str,
    ) -> StorageResult<ManagedStopOperationResult> {
        validate_stop_stage_input(operation_id, now)?;
        validate_completion(completion)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| storage_error("begin stop completion transaction", error))?;
        let operation = stop_operation(&mut transaction, operation_id).await?;
        let kind = stop_kind_from_storage(&operation.kind)?;
        let status = stop_status_from_storage(&operation.status)?;
        if !is_active_status(status) {
            return Err(active_stop_stage_conflict(operation_id, status));
        }
        if completion.outcome == ManagedStopOutcome::SignalUnavailable
            && signal_disposition_from_storage(operation.signal_disposition.as_deref())?
                != Some(ManagedStopSignalDisposition::Unavailable)
        {
            return Err(invalid_stop_field(
                "outcome",
                "signal-unavailable completion requires a persisted unavailable signal attempt",
            ));
        }

        let current_run_row = run_row(&mut transaction, &operation.run_id).await?;
        let current_run = stored_run_to_managed(current_run_row.clone())?;
        project_stop_result(operation.clone(), current_run_row.clone())?;
        if !completion_run_state_is_eligible(kind, status, current_run.state) {
            return Err(run_state_conflict(
                &operation.run_id,
                completion_expected_run_states(kind, status),
                current_run.state,
            ));
        }
        validate_stop_transition_timestamp(now, &operation.updated_at, &current_run.updated_at)?;

        let (next_run_state, ended_at, exit_summary) =
            completion_run_update(completion.outcome, now);
        let mut prospective_run = current_run_row.clone();
        prospective_run.state = run_state_to_storage(next_run_state).to_owned();
        prospective_run.exit_code = completion.exit_code;
        prospective_run.exit_signal = completion.exit_signal.clone();
        prospective_run.exit_summary = exit_summary.map(str::to_owned);
        prospective_run.stop_method = Some(stop_kind_to_storage(kind).to_owned());
        prospective_run.updated_at = now.to_owned();
        prospective_run.ended_at = ended_at.map(str::to_owned);
        let mut prospective_operation = operation.clone();
        prospective_operation.status =
            stop_status_to_storage(ManagedStopStatus::Completed).to_owned();
        prospective_operation.outcome =
            Some(stop_outcome_to_storage(completion.outcome).to_owned());
        prospective_operation.updated_at = now.to_owned();
        prospective_operation.completed_at = Some(now.to_owned());
        project_stop_result(prospective_operation, prospective_run)?;
        let transitioned_run = sqlx::query(
            "UPDATE runs SET state = ?, exit_code = ?, exit_signal = ?, exit_summary = ?, \
             stop_method = ?, updated_at = ?, ended_at = ? WHERE id = ? \
             AND state = ? AND ended_at IS NULL AND updated_at = ?",
        )
        .bind(run_state_to_storage(next_run_state))
        .bind(completion.exit_code)
        .bind(&completion.exit_signal)
        .bind(exit_summary)
        .bind(stop_kind_to_storage(kind))
        .bind(now)
        .bind(ended_at)
        .bind(&operation.run_id)
        .bind(&current_run_row.state)
        .bind(&current_run_row.updated_at)
        .execute(&mut *transaction)
        .await
        .map_err(|error| storage_error("complete managed run stop", error))?;
        if transitioned_run.rows_affected() != 1 {
            let current = run_row(&mut transaction, &operation.run_id).await?;
            return Err(run_state_conflict(
                &operation.run_id,
                completion_expected_run_states(kind, status),
                run_state_from_storage(&current.state)?,
            ));
        }

        let completed_operation = sqlx::query(
            "UPDATE managed_stop_operations SET status = 'COMPLETED', outcome = ?, \
             updated_at = ?, completed_at = ? WHERE operation_id = ? AND status = ? \
             AND updated_at = ?",
        )
        .bind(stop_outcome_to_storage(completion.outcome))
        .bind(now)
        .bind(now)
        .bind(operation_id)
        .bind(stop_status_to_storage(status))
        .bind(&operation.updated_at)
        .execute(&mut *transaction)
        .await
        .map_err(|error| storage_error("complete managed stop operation", error))?;
        require_stop_cas(
            completed_operation.rows_affected(),
            operation_id,
            stop_status_to_storage(status),
        )?;

        let result = read_stop_result(&mut transaction, operation_id).await?;
        transaction
            .commit()
            .await
            .map_err(|error| storage_error("commit stop completion", error))?;
        Ok(result)
    }
}

#[allow(clippy::too_many_arguments)]
fn prospective_stop_operation(
    operation_id: &str,
    run_id: &str,
    kind: ManagedStopKind,
    status: ManagedStopStatus,
    signal_disposition: Option<ManagedStopSignalDisposition>,
    outcome: Option<ManagedStopOutcome>,
    supersedes_operation_id: Option<&str>,
    now: &str,
    completed_at: Option<&str>,
) -> ManagedStopOperationRow {
    ManagedStopOperationRow {
        operation_id: operation_id.to_owned(),
        run_id: run_id.to_owned(),
        kind: stop_kind_to_storage(kind).to_owned(),
        status: stop_status_to_storage(status).to_owned(),
        signal_disposition: signal_disposition
            .map(signal_disposition_to_storage)
            .map(str::to_owned),
        outcome: outcome.map(stop_outcome_to_storage).map(str::to_owned),
        supersedes_operation_id: supersedes_operation_id.map(str::to_owned),
        created_at: now.to_owned(),
        updated_at: now.to_owned(),
        completed_at: completed_at.map(str::to_owned),
    }
}

#[allow(clippy::too_many_arguments)]
async fn insert_stop_operation(
    connection: &mut SqliteConnection,
    operation_id: &str,
    run_id: &str,
    kind: ManagedStopKind,
    status: ManagedStopStatus,
    signal_disposition: Option<ManagedStopSignalDisposition>,
    outcome: Option<ManagedStopOutcome>,
    supersedes_operation_id: Option<&str>,
    now: &str,
    completed_at: Option<&str>,
) -> StorageResult<()> {
    sqlx::query(
        "INSERT INTO managed_stop_operations \
         (operation_id, run_id, kind, status, signal_disposition, outcome, \
          supersedes_operation_id, created_at, updated_at, completed_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(operation_id)
    .bind(run_id)
    .bind(stop_kind_to_storage(kind))
    .bind(stop_status_to_storage(status))
    .bind(signal_disposition.map(signal_disposition_to_storage))
    .bind(outcome.map(stop_outcome_to_storage))
    .bind(supersedes_operation_id)
    .bind(now)
    .bind(now)
    .bind(completed_at)
    .execute(connection)
    .await
    .map_err(|error| storage_error("insert managed stop operation", error))?;
    Ok(())
}

async fn read_stop_result(
    connection: &mut SqliteConnection,
    operation_id: &str,
) -> StorageResult<ManagedStopOperationResult> {
    let operation = stop_operation(connection, operation_id).await?;
    let run = run_row(connection, &operation.run_id).await?;
    project_stop_result(operation, run)
}

async fn stop_operation(
    connection: &mut SqliteConnection,
    operation_id: &str,
) -> StorageResult<ManagedStopOperationRow> {
    stop_operation_optional(connection, operation_id)
        .await?
        .ok_or_else(|| not_found("managedStopOperation", operation_id))
}

async fn stop_operation_optional(
    connection: &mut SqliteConnection,
    operation_id: &str,
) -> StorageResult<Option<ManagedStopOperationRow>> {
    sqlx::query_as::<_, ManagedStopOperationRow>(STOP_OPERATION_SELECT_BY_ID)
        .bind(operation_id)
        .fetch_optional(connection)
        .await
        .map_err(|error| storage_error("read managed stop operation", error))
}

async fn active_stop_operation(
    connection: &mut SqliteConnection,
    run_id: &str,
) -> StorageResult<Option<ManagedStopOperationRow>> {
    sqlx::query_as::<_, ManagedStopOperationRow>(ACTIVE_STOP_OPERATION_SELECT_BY_RUN)
        .bind(run_id)
        .fetch_optional(connection)
        .await
        .map_err(|error| storage_error("read active managed stop operation", error))
}

async fn run_row(connection: &mut SqliteConnection, run_id: &str) -> StorageResult<Run> {
    sqlx::query_as::<_, Run>(RUN_SELECT_BY_ID)
        .bind(run_id)
        .fetch_optional(connection)
        .await
        .map_err(|error| storage_error("read managed stop run", error))?
        .ok_or_else(|| not_found("run", run_id))
}

pub(crate) fn project_stop_result(
    operation: ManagedStopOperationRow,
    run: Run,
) -> StorageResult<ManagedStopOperationResult> {
    validate_stored_text(
        "operationId",
        &operation.operation_id,
        MAX_STOP_OPERATION_ID_BYTES,
    )?;
    validate_stored_text("runId", &operation.run_id, MAX_STOP_RUN_ID_BYTES)?;
    validate_stored_timestamp("createdAt", &operation.created_at)?;
    validate_stored_timestamp("updatedAt", &operation.updated_at)?;
    if let Some(completed_at) = &operation.completed_at {
        validate_stored_timestamp("completedAt", completed_at)?;
    }
    if let Some(supersedes_operation_id) = &operation.supersedes_operation_id {
        validate_stored_text(
            "supersedesOperationId",
            supersedes_operation_id,
            MAX_STOP_OPERATION_ID_BYTES,
        )?;
        if supersedes_operation_id == &operation.operation_id {
            return Err(corrupt_stop(
                "supersedesOperationId",
                "references the same operation",
            ));
        }
    }
    if operation.run_id != run.id {
        return Err(corrupt_stop(
            "runId",
            "does not match the joined managed run",
        ));
    }

    let run = stored_run_to_managed(run)?;
    let result = ManagedStopOperationResult {
        operation_id: operation.operation_id,
        run: ManagedRunSummary {
            run_id: run.id,
            profile_id: run.profile_snapshot.id.clone(),
            profile_updated_at: run.profile_snapshot.updated_at.clone(),
            state: run.state,
            process_instance_key: run.process_instance_key,
            process_group_id: run.process_group_id,
            started_at: run.started_at,
            updated_at: run.updated_at,
            ended_at: run.ended_at,
        },
        kind: stop_kind_from_storage(&operation.kind)?,
        status: stop_status_from_storage(&operation.status)?,
        signal_disposition: signal_disposition_from_storage(
            operation.signal_disposition.as_deref(),
        )?,
        outcome: stop_outcome_from_storage(operation.outcome.as_deref())?,
        created_at: operation.created_at,
        updated_at: operation.updated_at,
        completed_at: operation.completed_at,
    };
    if is_active_status(result.status)
        && (!completion_run_state_is_eligible(result.kind, result.status, result.run.state)
            || result.run.ended_at.is_some())
    {
        return Err(corrupt_stop(
            "run.state",
            "does not match the active managed stop operation",
        ));
    }
    lifecycle::validate_managed_stop_operation_result(&result)
        .map_err(|error| corrupt_stop("operation", &error.message))?;
    Ok(result)
}

fn validate_stop_stage_input(operation_id: &str, now: &str) -> StorageResult<()> {
    lifecycle::validate_managed_stop_operation_id(operation_id)?;
    validate_timestamp("now", now)
}

fn validate_timestamp(field: &'static str, value: &str) -> StorageResult<()> {
    lifecycle::validate_canonical_utc_timestamp(field, value)
}

fn validate_stop_transition_timestamp(
    now: &str,
    operation_updated_at: &str,
    run_updated_at: &str,
) -> StorageResult<()> {
    if now <= operation_updated_at || now <= run_updated_at {
        return Err(invalid_stop_field(
            "now",
            "must be later than the current stop operation and managed run timestamps",
        ));
    }
    Ok(())
}

fn validate_stored_timestamp(field: &'static str, value: &str) -> StorageResult<()> {
    lifecycle::validate_canonical_utc_timestamp(field, value)
        .map_err(|_| corrupt_stop(field, "is not a canonical UTC timestamp"))
}

fn validate_completion(completion: &ManagedStopCompletion) -> StorageResult<()> {
    if let Some(exit_signal) = &completion.exit_signal {
        validate_input_text("exitSignal", exit_signal, MAX_EXIT_SIGNAL_BYTES)?;
    }
    if completion.outcome != ManagedStopOutcome::Exited
        && (completion.exit_code.is_some() || completion.exit_signal.is_some())
    {
        return Err(invalid_stop_field(
            "exit",
            "exit code and signal are supported only for an exited outcome",
        ));
    }
    Ok(())
}

fn completion_run_update(
    outcome: ManagedStopOutcome,
    now: &str,
) -> (RunState, Option<&str>, Option<&'static str>) {
    match outcome {
        ManagedStopOutcome::Exited => (RunState::Exited, Some(now), None),
        ManagedStopOutcome::AlreadyExited => {
            (RunState::Exited, Some(now), Some("stop:alreadyExited"))
        }
        ManagedStopOutcome::IdentityMismatch => (
            RunState::IdentityMismatch,
            None,
            Some("stop:identityMismatch"),
        ),
        ManagedStopOutcome::Orphaned => (RunState::Orphaned, None, Some("stop:orphaned")),
        ManagedStopOutcome::SignalUnavailable => {
            (RunState::Orphaned, None, Some("stop:signalUnavailable"))
        }
        ManagedStopOutcome::Failed => (RunState::Failed, Some(now), Some("stop:failed")),
    }
}

fn completion_run_state_is_eligible(
    kind: ManagedStopKind,
    status: ManagedStopStatus,
    run_state: RunState,
) -> bool {
    match (kind, status) {
        (
            ManagedStopKind::Graceful,
            ManagedStopStatus::Requested | ManagedStopStatus::SignalPending,
        ) => run_state == RunState::StopRequested,
        (
            ManagedStopKind::Force,
            ManagedStopStatus::Requested | ManagedStopStatus::SignalPending,
        ) => matches!(
            run_state,
            RunState::StopRequested | RunState::GracefulStopping
        ),
        (ManagedStopKind::Graceful, ManagedStopStatus::InProgress)
        | (ManagedStopKind::Graceful, ManagedStopStatus::TimedOut) => {
            run_state == RunState::GracefulStopping
        }
        (ManagedStopKind::Force, ManagedStopStatus::InProgress) => {
            run_state == RunState::ForceStopping
        }
        _ => false,
    }
}

fn completion_expected_run_states(
    kind: ManagedStopKind,
    status: ManagedStopStatus,
) -> &'static str {
    match (kind, status) {
        (
            ManagedStopKind::Graceful,
            ManagedStopStatus::Requested | ManagedStopStatus::SignalPending,
        ) => "STOP_REQUESTED",
        (
            ManagedStopKind::Force,
            ManagedStopStatus::Requested | ManagedStopStatus::SignalPending,
        ) => "STOP_REQUESTED or GRACEFUL_STOPPING",
        (ManagedStopKind::Graceful, ManagedStopStatus::InProgress)
        | (ManagedStopKind::Graceful, ManagedStopStatus::TimedOut) => "GRACEFUL_STOPPING",
        (ManagedStopKind::Force, ManagedStopStatus::InProgress) => "FORCE_STOPPING",
        _ => "an active stop state",
    }
}

fn completed_outcome_for_run(state: RunState) -> Option<ManagedStopOutcome> {
    match state {
        RunState::Exited | RunState::ExitedWhileOffline => Some(ManagedStopOutcome::AlreadyExited),
        RunState::IdentityMismatch => Some(ManagedStopOutcome::IdentityMismatch),
        RunState::Orphaned => Some(ManagedStopOutcome::Orphaned),
        RunState::Failed => Some(ManagedStopOutcome::Failed),
        _ => None,
    }
}

fn is_active_status(status: ManagedStopStatus) -> bool {
    matches!(
        status,
        ManagedStopStatus::Requested
            | ManagedStopStatus::SignalPending
            | ManagedStopStatus::InProgress
            | ManagedStopStatus::TimedOut
    )
}

fn stop_kind_to_storage(kind: ManagedStopKind) -> &'static str {
    match kind {
        ManagedStopKind::Graceful => "GRACEFUL",
        ManagedStopKind::Force => "FORCE",
    }
}

fn stop_kind_from_storage(value: &str) -> StorageResult<ManagedStopKind> {
    match value {
        "GRACEFUL" => Ok(ManagedStopKind::Graceful),
        "FORCE" => Ok(ManagedStopKind::Force),
        _ => Err(corrupt_stop("kind", "uses an unsupported stop kind")),
    }
}

fn stop_status_to_storage(status: ManagedStopStatus) -> &'static str {
    match status {
        ManagedStopStatus::Requested => "REQUESTED",
        ManagedStopStatus::SignalPending => "SIGNAL_PENDING",
        ManagedStopStatus::InProgress => "IN_PROGRESS",
        ManagedStopStatus::TimedOut => "TIMED_OUT",
        ManagedStopStatus::Completed => "COMPLETED",
        ManagedStopStatus::Superseded => "SUPERSEDED",
    }
}

fn stop_status_from_storage(value: &str) -> StorageResult<ManagedStopStatus> {
    match value {
        "REQUESTED" => Ok(ManagedStopStatus::Requested),
        "SIGNAL_PENDING" => Ok(ManagedStopStatus::SignalPending),
        "IN_PROGRESS" => Ok(ManagedStopStatus::InProgress),
        "TIMED_OUT" => Ok(ManagedStopStatus::TimedOut),
        "COMPLETED" => Ok(ManagedStopStatus::Completed),
        "SUPERSEDED" => Ok(ManagedStopStatus::Superseded),
        _ => Err(corrupt_stop("status", "uses an unsupported stop status")),
    }
}

fn signal_disposition_to_storage(disposition: ManagedStopSignalDisposition) -> &'static str {
    match disposition {
        ManagedStopSignalDisposition::Delivered => "DELIVERED",
        ManagedStopSignalDisposition::Unavailable => "UNAVAILABLE",
    }
}

fn signal_disposition_from_storage(
    value: Option<&str>,
) -> StorageResult<Option<ManagedStopSignalDisposition>> {
    value
        .map(|value| match value {
            "DELIVERED" => Ok(ManagedStopSignalDisposition::Delivered),
            "UNAVAILABLE" => Ok(ManagedStopSignalDisposition::Unavailable),
            _ => Err(corrupt_stop(
                "signalDisposition",
                "uses an unsupported signal disposition",
            )),
        })
        .transpose()
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

fn stop_outcome_from_storage(value: Option<&str>) -> StorageResult<Option<ManagedStopOutcome>> {
    value
        .map(|value| match value {
            "EXITED" => Ok(ManagedStopOutcome::Exited),
            "ALREADY_EXITED" => Ok(ManagedStopOutcome::AlreadyExited),
            "IDENTITY_MISMATCH" => Ok(ManagedStopOutcome::IdentityMismatch),
            "ORPHANED" => Ok(ManagedStopOutcome::Orphaned),
            "SIGNAL_UNAVAILABLE" => Ok(ManagedStopOutcome::SignalUnavailable),
            "FAILED" => Ok(ManagedStopOutcome::Failed),
            _ => Err(corrupt_stop("outcome", "uses an unsupported stop outcome")),
        })
        .transpose()
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

fn run_state_from_storage(value: &str) -> StorageResult<RunState> {
    match value {
        "STARTING" => Ok(RunState::Starting),
        "RUNNING" => Ok(RunState::Running),
        "STOP_REQUESTED" => Ok(RunState::StopRequested),
        "GRACEFUL_STOPPING" => Ok(RunState::GracefulStopping),
        "FORCE_STOPPING" => Ok(RunState::ForceStopping),
        "EXITED" => Ok(RunState::Exited),
        "FAILED" => Ok(RunState::Failed),
        "RECOVERED" => Ok(RunState::Recovered),
        "EXITED_WHILE_OFFLINE" => Ok(RunState::ExitedWhileOffline),
        "IDENTITY_MISMATCH" => Ok(RunState::IdentityMismatch),
        "ORPHANED" => Ok(RunState::Orphaned),
        _ => Err(corrupt_stop("run.state", "uses an unsupported run state")),
    }
}

fn validate_input_text(field: &'static str, value: &str, maximum: usize) -> StorageResult<()> {
    if value.trim().is_empty() {
        return Err(invalid_stop_field(field, "must not be empty or whitespace"));
    }
    if value.len() > maximum {
        return Err(invalid_stop_field(field, "exceeds the supported length"));
    }
    if value.contains('\0') {
        return Err(invalid_stop_field(field, "must not contain NUL"));
    }
    Ok(())
}

fn validate_stored_text(field: &'static str, value: &str, maximum: usize) -> StorageResult<()> {
    if value.trim().is_empty() || value.len() > maximum || value.contains('\0') {
        Err(corrupt_stop(field, "contains an invalid stored value"))
    } else {
        Ok(())
    }
}

fn require_stop_cas(rows: u64, operation_id: &str, expected: &str) -> StorageResult<()> {
    if rows == 1 {
        Ok(())
    } else {
        let mut error = AppError::new(
            ErrorCode::Conflict,
            "managed stop operation state transition was rejected",
        );
        error
            .details
            .insert("operationId".into(), operation_id.into());
        error
            .details
            .insert("expectedStatus".into(), expected.into());
        Err(error)
    }
}

fn invalid_stop_field(field: &'static str, reason: &'static str) -> AppError {
    let mut error = AppError::new(ErrorCode::InvalidArgument, "invalid managed stop operation");
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn corrupt_stop(field: &'static str, reason: &str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::StorageError,
        "stored managed stop operation is invalid",
    );
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn operation_id_conflict(
    operation_id: &str,
    requested_run_id: &str,
    requested_kind: ManagedStopKind,
    existing: &ManagedStopOperationRow,
) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Conflict,
        "managed stop operation ID is already bound to different input",
    );
    error
        .details
        .insert("operationId".into(), operation_id.into());
    error
        .details
        .insert("requestedRunId".into(), requested_run_id.into());
    error
        .details
        .insert("actualRunId".into(), existing.run_id.clone());
    error.details.insert(
        "requestedKind".into(),
        stop_kind_to_storage(requested_kind).into(),
    );
    error
        .details
        .insert("actualKind".into(), existing.kind.clone());
    error
}

fn active_stop_conflict(
    run_id: &str,
    requested_kind: ManagedStopKind,
    requested_supersession: Option<&str>,
    active: &ManagedStopOperationRow,
) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Conflict,
        "managed run already has an active stop operation",
    );
    error.details.insert("runId".into(), run_id.into());
    error
        .details
        .insert("activeOperationId".into(), active.operation_id.clone());
    error
        .details
        .insert("activeKind".into(), active.kind.clone());
    error.details.insert(
        "requestedKind".into(),
        stop_kind_to_storage(requested_kind).into(),
    );
    if let Some(requested_supersession) = requested_supersession {
        error.details.insert(
            "requestedSupersedeOperationId".into(),
            requested_supersession.into(),
        );
    }
    error
}

fn missing_superseded_operation(run_id: &str, operation_id: &str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Conflict,
        "force stop supersession target is not the active graceful operation",
    );
    error.details.insert("runId".into(), run_id.into());
    error
        .details
        .insert("supersedeOperationId".into(), operation_id.into());
    error
}

fn run_state_conflict(run_id: &str, expected: &str, actual: RunState) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Conflict,
        "managed run state transition was rejected",
    );
    error.details.insert("runId".into(), run_id.into());
    error
        .details
        .insert("expectedState".into(), expected.into());
    error
        .details
        .insert("actualState".into(), run_state_to_storage(actual).into());
    error
}

fn stop_stage_conflict(
    operation_id: &str,
    expected: ManagedStopStatus,
    actual: ManagedStopStatus,
) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Conflict,
        "managed stop operation state transition was rejected",
    );
    error
        .details
        .insert("operationId".into(), operation_id.into());
    error.details.insert(
        "expectedStatus".into(),
        stop_status_to_storage(expected).into(),
    );
    error
        .details
        .insert("actualStatus".into(), stop_status_to_storage(actual).into());
    error
}

fn active_stop_stage_conflict(operation_id: &str, actual: ManagedStopStatus) -> AppError {
    let mut error = stop_stage_conflict(operation_id, ManagedStopStatus::InProgress, actual);
    error.details.insert(
        "expectedStatus".into(),
        "REQUESTED, SIGNAL_PENDING, IN_PROGRESS, or TIMED_OUT".into(),
    );
    error
}
