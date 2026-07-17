use std::fmt::{self, Formatter};
use std::path::Path;

use domain::{AppError, ErrorCode, RunState};
use sqlx::FromRow;

use crate::models::Run;
use crate::repository::RUN_SELECT_BY_ID;
use crate::run_contract::stored_run_to_managed;
use crate::{StorageResult, SupervisorRepository};

const MAX_RETENTION_RUN_ID_BYTES: usize = 256;
const MAX_RETENTION_LOG_DIRECTORY_BYTES: usize = 32 * 1_024;

pub const MAX_MANAGED_RUN_LOG_RETENTION_PAGE_SIZE: u16 = 256;

const RETENTION_CANDIDATE_SELECT_FIRST: &str = "SELECT id AS run_id, log_directory, COALESCE(ended_at, updated_at) AS retention_timestamp, \
     logs_deletion_started_at AS deletion_started_at \
     FROM runs WHERE logs_deleted_at IS NULL \
     AND state IN ('EXITED', 'FAILED', 'EXITED_WHILE_OFFLINE', 'IDENTITY_MISMATCH', 'ORPHANED') \
     ORDER BY COALESCE(ended_at, updated_at) COLLATE BINARY, id COLLATE BINARY LIMIT ?";

const RETENTION_CANDIDATE_SELECT_AFTER: &str = "SELECT id AS run_id, log_directory, COALESCE(ended_at, updated_at) AS retention_timestamp, \
     logs_deletion_started_at AS deletion_started_at \
     FROM runs WHERE logs_deleted_at IS NULL \
     AND state IN ('EXITED', 'FAILED', 'EXITED_WHILE_OFFLINE', 'IDENTITY_MISMATCH', 'ORPHANED') \
     AND (COALESCE(ended_at, updated_at) > ? COLLATE BINARY \
          OR (COALESCE(ended_at, updated_at) = ? COLLATE BINARY AND id > ? COLLATE BINARY)) \
     ORDER BY COALESCE(ended_at, updated_at) COLLATE BINARY, id COLLATE BINARY LIMIT ?";

const RETENTION_CANDIDATE_SELECT_BY_ID: &str = "SELECT id AS run_id, log_directory, COALESCE(ended_at, updated_at) AS retention_timestamp, \
     logs_deletion_started_at AS deletion_started_at \
     FROM runs WHERE id = ? AND logs_deleted_at IS NULL \
     AND state IN ('EXITED', 'FAILED', 'EXITED_WHILE_OFFLINE', 'IDENTITY_MISMATCH', 'ORPHANED')";

/// Minimal storage projection needed to safely remove one terminal run's logs.
#[derive(Clone, Eq, FromRow, PartialEq)]
pub struct ManagedRunLogRetentionCandidate {
    pub run_id: String,
    pub log_directory: String,
    pub retention_timestamp: String,
    pub deletion_started_at: Option<String>,
}

impl fmt::Debug for ManagedRunLogRetentionCandidate {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedRunLogRetentionCandidate")
            .field("run_id", &self.run_id)
            .field("log_directory", &"<redacted>")
            .field("retention_timestamp", &self.retention_timestamp)
            .field("deletion_started_at", &self.deletion_started_at)
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedRunLogRetentionCursor {
    pub retention_timestamp: String,
    pub run_id: String,
}

impl From<&ManagedRunLogRetentionCandidate> for ManagedRunLogRetentionCursor {
    fn from(candidate: &ManagedRunLogRetentionCandidate) -> Self {
        Self {
            retention_timestamp: candidate.retention_timestamp.clone(),
            run_id: candidate.run_id.clone(),
        }
    }
}

impl SupervisorRepository {
    /// Counts every terminal run whose log directory has not yet been durably
    /// marked as deleted.
    pub async fn managed_run_log_retention_candidate_count(&self) -> StorageResult<u64> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM runs WHERE logs_deleted_at IS NULL \
             AND state IN ('EXITED', 'FAILED', 'EXITED_WHILE_OFFLINE', \
                           'IDENTITY_MISMATCH', 'ORPHANED')",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|error| {
            retention_storage_error("count managed run log retention candidates", error)
        })?;
        u64::try_from(count).map_err(|error| {
            retention_storage_error("count managed run log retention candidates", error)
        })
    }

    /// Lists a bounded, stable oldest-first page of terminal runs whose log
    /// directories have not yet been durably marked as deleted.
    pub async fn managed_run_log_retention_candidates(
        &self,
        after: Option<&ManagedRunLogRetentionCursor>,
        limit: u16,
    ) -> StorageResult<Vec<ManagedRunLogRetentionCandidate>> {
        validate_page_limit(limit)?;
        let rows = match after {
            Some(cursor) => {
                validate_cursor(cursor)?;
                sqlx::query_as::<_, ManagedRunLogRetentionCandidate>(
                    RETENTION_CANDIDATE_SELECT_AFTER,
                )
                .bind(&cursor.retention_timestamp)
                .bind(&cursor.retention_timestamp)
                .bind(&cursor.run_id)
                .bind(i64::from(limit))
                .fetch_all(&self.pool)
                .await
            }
            None => {
                sqlx::query_as::<_, ManagedRunLogRetentionCandidate>(
                    RETENTION_CANDIDATE_SELECT_FIRST,
                )
                .bind(i64::from(limit))
                .fetch_all(&self.pool)
                .await
            }
        }
        .map_err(|error| {
            retention_storage_error("list managed run log retention candidates", error)
        })?;

        rows.into_iter().map(validate_stored_candidate).collect()
    }

    /// Rechecks whether one exact run is still an undeleted terminal log
    /// candidate immediately before filesystem work begins.
    pub async fn managed_run_log_retention_candidate(
        &self,
        run_id: &str,
    ) -> StorageResult<Option<ManagedRunLogRetentionCandidate>> {
        validate_required_text("runId", run_id, MAX_RETENTION_RUN_ID_BYTES)?;
        sqlx::query_as::<_, ManagedRunLogRetentionCandidate>(RETENTION_CANDIDATE_SELECT_BY_ID)
            .bind(run_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| {
                retention_storage_error("recheck managed run log retention candidate", error)
            })?
            .map(validate_stored_candidate)
            .transpose()
    }

    /// Durably records filesystem deletion intent while the exact terminal
    /// run and Supervisor-selected directory still match. Reusing the same
    /// marker is an idempotent retry; a different marker is rejected.
    pub async fn begin_managed_run_log_deletion(
        &mut self,
        run_id: &str,
        expected_log_directory: &str,
        started_at: &str,
    ) -> StorageResult<bool> {
        validate_required_text("runId", run_id, MAX_RETENTION_RUN_ID_BYTES)?;
        validate_log_directory(expected_log_directory)?;
        validate_timestamp("deletionStartedAt", started_at)?;

        let mut transaction =
            self.pool.begin().await.map_err(|error| {
                retention_storage_error("begin managed run log deletion", error)
            })?;
        let current_row = sqlx::query_as::<_, Run>(RUN_SELECT_BY_ID)
            .bind(run_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|error| retention_storage_error("read managed run log deletion", error))?;
        let Some(current_row) = current_row else {
            transaction.rollback().await.map_err(|error| {
                retention_storage_error("rollback missing managed run log deletion", error)
            })?;
            return Ok(false);
        };
        let current = stored_run_to_managed(current_row.clone())?;
        if !is_terminal_retention_state(current.state)
            || current.logs_deleted_at.is_some()
            || current.log_directory != expected_log_directory
        {
            transaction.rollback().await.map_err(|error| {
                retention_storage_error("rollback ineligible managed run log deletion", error)
            })?;
            return Ok(false);
        }
        if let Some(existing) = current.logs_deletion_started_at.as_deref() {
            transaction.rollback().await.map_err(|error| {
                retention_storage_error("rollback replayed managed run log deletion", error)
            })?;
            return Ok(existing == started_at);
        }
        let retention_timestamp = current.ended_at.as_deref().unwrap_or(&current.updated_at);
        if started_at <= retention_timestamp {
            return Err(invalid_retention_input(
                "deletionStartedAt",
                "must be later than the terminal run retention timestamp",
            ));
        }
        let mut prospective = current_row.clone();
        prospective.logs_deletion_started_at = Some(started_at.to_owned());
        stored_run_to_managed(prospective)?;

        let result = sqlx::query(
            "UPDATE runs SET logs_deletion_started_at = ? \
             WHERE id = ? AND log_directory = ? AND state = ? AND updated_at = ? \
             AND ended_at IS ? AND logs_deletion_started_at IS NULL AND logs_deleted_at IS NULL",
        )
        .bind(started_at)
        .bind(run_id)
        .bind(expected_log_directory)
        .bind(&current_row.state)
        .bind(&current_row.updated_at)
        .bind(&current_row.ended_at)
        .execute(&mut *transaction)
        .await
        .map_err(|error| retention_storage_error("begin managed run log deletion", error))?;
        if result.rows_affected() != 1 {
            transaction.rollback().await.map_err(|error| {
                retention_storage_error("rollback rejected managed run log deletion", error)
            })?;
            return Ok(false);
        }
        let stored = sqlx::query_as::<_, Run>(RUN_SELECT_BY_ID)
            .bind(run_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|error| retention_storage_error("read begun managed run log deletion", error))?
            .ok_or_else(corrupt_retention_candidate)?;
        let stored = stored_run_to_managed(stored)?;
        if stored.logs_deletion_started_at.as_deref() != Some(started_at)
            || stored.logs_deleted_at.is_some()
        {
            return Err(corrupt_retention_candidate());
        }
        transaction
            .commit()
            .await
            .map_err(|error| retention_storage_error("commit managed run log deletion", error))?;
        Ok(true)
    }

    /// Marks deletion only if the run is still terminal, still unmarked, and
    /// still owns the exact Supervisor-selected log directory that was purged.
    pub async fn mark_managed_run_logs_deleted(
        &mut self,
        run_id: &str,
        expected_log_directory: &str,
        deleted_at: &str,
    ) -> StorageResult<bool> {
        validate_required_text("runId", run_id, MAX_RETENTION_RUN_ID_BYTES)?;
        validate_log_directory(expected_log_directory)?;
        validate_timestamp("deletedAt", deleted_at)?;

        let mut transaction = self.pool.begin().await.map_err(|error| {
            retention_storage_error("begin marking managed run logs deleted", error)
        })?;
        let current_row = sqlx::query_as::<_, Run>(RUN_SELECT_BY_ID)
            .bind(run_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|error| retention_storage_error("read managed run logs deleted", error))?;
        let Some(current_row) = current_row else {
            transaction.rollback().await.map_err(|error| {
                retention_storage_error("rollback missing managed run logs deleted", error)
            })?;
            return Ok(false);
        };
        let current = stored_run_to_managed(current_row.clone())?;
        if !is_terminal_retention_state(current.state)
            || current.logs_deleted_at.is_some()
            || current.log_directory != expected_log_directory
        {
            transaction.rollback().await.map_err(|error| {
                retention_storage_error("rollback ineligible managed run logs deleted", error)
            })?;
            return Ok(false);
        }
        let Some(deletion_started_at) = current.logs_deletion_started_at.as_deref() else {
            transaction.rollback().await.map_err(|error| {
                retention_storage_error("rollback unstarted managed run logs deleted", error)
            })?;
            return Ok(false);
        };
        if deleted_at <= deletion_started_at {
            return Err(invalid_retention_input(
                "deletedAt",
                "must be later than the log deletion start timestamp",
            ));
        }
        let mut prospective = current_row.clone();
        prospective.logs_deleted_at = Some(deleted_at.to_owned());
        stored_run_to_managed(prospective)?;

        let result = sqlx::query(
            "UPDATE runs SET logs_deleted_at = ? WHERE id = ? AND log_directory = ? \
             AND state = ? AND updated_at = ? AND ended_at IS ? \
             AND logs_deletion_started_at = ? AND logs_deleted_at IS NULL",
        )
        .bind(deleted_at)
        .bind(run_id)
        .bind(expected_log_directory)
        .bind(&current_row.state)
        .bind(&current_row.updated_at)
        .bind(&current_row.ended_at)
        .bind(deletion_started_at)
        .execute(&mut *transaction)
        .await
        .map_err(|error| retention_storage_error("mark managed run logs deleted", error))?;
        if result.rows_affected() != 1 {
            transaction.rollback().await.map_err(|error| {
                retention_storage_error("rollback rejected managed run logs deleted", error)
            })?;
            return Ok(false);
        }
        let stored = sqlx::query_as::<_, Run>(RUN_SELECT_BY_ID)
            .bind(run_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|error| {
                retention_storage_error("read marked managed run logs deleted", error)
            })?
            .ok_or_else(corrupt_retention_candidate)?;
        let stored = stored_run_to_managed(stored)?;
        if stored.logs_deletion_started_at.as_deref() != Some(deletion_started_at)
            || stored.logs_deleted_at.as_deref() != Some(deleted_at)
        {
            return Err(corrupt_retention_candidate());
        }
        transaction
            .commit()
            .await
            .map_err(|error| retention_storage_error("commit managed run logs deleted", error))?;
        Ok(true)
    }
}

fn validate_page_limit(limit: u16) -> StorageResult<()> {
    if (1..=MAX_MANAGED_RUN_LOG_RETENTION_PAGE_SIZE).contains(&limit) {
        Ok(())
    } else {
        Err(invalid_retention_input(
            "limit",
            "must be between 1 and 256 entries",
        ))
    }
}

fn validate_cursor(cursor: &ManagedRunLogRetentionCursor) -> StorageResult<()> {
    validate_timestamp("cursor.retentionTimestamp", &cursor.retention_timestamp)?;
    validate_required_text("cursor.runId", &cursor.run_id, MAX_RETENTION_RUN_ID_BYTES)
}

fn validate_stored_candidate(
    candidate: ManagedRunLogRetentionCandidate,
) -> StorageResult<ManagedRunLogRetentionCandidate> {
    if validate_required_text("runId", &candidate.run_id, MAX_RETENTION_RUN_ID_BYTES).is_err()
        || validate_log_directory(&candidate.log_directory).is_err()
        || validate_timestamp("retentionTimestamp", &candidate.retention_timestamp).is_err()
    {
        return Err(corrupt_retention_candidate());
    }
    if candidate
        .deletion_started_at
        .as_ref()
        .is_some_and(|value| validate_timestamp("deletionStartedAt", value).is_err())
    {
        return Err(corrupt_retention_candidate());
    }
    if candidate
        .deletion_started_at
        .as_deref()
        .is_some_and(|value| value < candidate.retention_timestamp.as_str())
    {
        return Err(corrupt_retention_candidate());
    }
    Ok(candidate)
}

fn is_terminal_retention_state(state: RunState) -> bool {
    matches!(
        state,
        RunState::Exited
            | RunState::Failed
            | RunState::ExitedWhileOffline
            | RunState::IdentityMismatch
            | RunState::Orphaned
    )
}

fn validate_log_directory(value: &str) -> StorageResult<()> {
    validate_required_text(
        "expectedLogDirectory",
        value,
        MAX_RETENTION_LOG_DIRECTORY_BYTES,
    )?;
    if !Path::new(value).is_absolute() {
        return Err(invalid_retention_input(
            "expectedLogDirectory",
            "must be an absolute path",
        ));
    }
    Ok(())
}

fn validate_required_text(field: &'static str, value: &str, maximum: usize) -> StorageResult<()> {
    if value.trim().is_empty() || value.len() > maximum || value.contains('\0') {
        Err(invalid_retention_input(
            field,
            "must be non-empty bounded text without NUL",
        ))
    } else {
        Ok(())
    }
}

fn validate_timestamp(field: &'static str, value: &str) -> StorageResult<()> {
    lifecycle::validate_canonical_utc_timestamp(field, value)
}

fn invalid_retention_input(field: &'static str, reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "invalid managed run log retention input",
    );
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn corrupt_retention_candidate() -> AppError {
    AppError::new(
        ErrorCode::StorageError,
        "stored managed run log retention candidate is invalid",
    )
}

fn retention_storage_error(operation: &'static str, _source: impl fmt::Display) -> AppError {
    let mut error = AppError::new(ErrorCode::StorageError, "SQLite storage operation failed");
    error.details.insert("operation".into(), operation.into());
    error
}
