use domain::{AppError, ErrorCode};
use serde::Serialize;
use sqlx::FromRow;

use crate::error::storage_error;
use crate::{StorageResult, SupervisorRepository};

/// Fixed aggregate-only database projection for a diagnostic bundle. No row
/// identity, user-authored text, path, command, environment value, credential
/// reference, log body, or audit detail is representable here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticDatabaseSummary {
    pub schema_version: u32,
    pub projects: u64,
    pub launch_profiles: u64,
    pub launch_environment_entries: u64,
    pub classification_rules: u64,
    pub runs: DiagnosticRunStateCounts,
    pub audit_events: u64,
    pub application_settings: u64,
    pub pending_credential_cleanup: u64,
    pub active_stop_operations: u64,
    pub catalog_mutation_operations: u64,
    pub managed_exit_operations: u64,
    pub pending_log_retention: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticRunStateCounts {
    pub total: u64,
    pub starting: u64,
    pub running: u64,
    pub stop_requested: u64,
    pub graceful_stopping: u64,
    pub force_stopping: u64,
    pub exited: u64,
    pub failed: u64,
    pub recovered: u64,
    pub exited_while_offline: u64,
    pub identity_mismatch: u64,
    pub orphaned: u64,
}

#[derive(FromRow)]
struct RawDiagnosticDatabaseSummary {
    schema_version: i64,
    projects: i64,
    launch_profiles: i64,
    launch_environment_entries: i64,
    classification_rules: i64,
    run_total: i64,
    run_starting: i64,
    run_running: i64,
    run_stop_requested: i64,
    run_graceful_stopping: i64,
    run_force_stopping: i64,
    run_exited: i64,
    run_failed: i64,
    run_recovered: i64,
    run_exited_while_offline: i64,
    run_identity_mismatch: i64,
    run_orphaned: i64,
    audit_events: i64,
    application_settings: i64,
    pending_credential_cleanup: i64,
    active_stop_operations: i64,
    catalog_mutation_operations: i64,
    managed_exit_operations: i64,
    pending_log_retention: i64,
}

impl SupervisorRepository {
    /// Reads every aggregate from one SQLite statement, so the projection is
    /// internally consistent without holding a long-running read transaction.
    pub async fn diagnostic_database_summary(&self) -> StorageResult<DiagnosticDatabaseSummary> {
        let raw = sqlx::query_as::<_, RawDiagnosticDatabaseSummary>(
            "SELECT \
                (SELECT COALESCE(MAX(version), 0) FROM _sqlx_migrations WHERE success = 1) AS schema_version, \
                (SELECT COUNT(*) FROM projects) AS projects, \
                (SELECT COUNT(*) FROM launch_profiles) AS launch_profiles, \
                (SELECT COUNT(*) FROM profile_environment) AS launch_environment_entries, \
                (SELECT COUNT(*) FROM classification_rules) AS classification_rules, \
                (SELECT COUNT(*) FROM runs) AS run_total, \
                (SELECT COUNT(*) FROM runs WHERE state = 'STARTING') AS run_starting, \
                (SELECT COUNT(*) FROM runs WHERE state = 'RUNNING') AS run_running, \
                (SELECT COUNT(*) FROM runs WHERE state = 'STOP_REQUESTED') AS run_stop_requested, \
                (SELECT COUNT(*) FROM runs WHERE state = 'GRACEFUL_STOPPING') AS run_graceful_stopping, \
                (SELECT COUNT(*) FROM runs WHERE state = 'FORCE_STOPPING') AS run_force_stopping, \
                (SELECT COUNT(*) FROM runs WHERE state = 'EXITED') AS run_exited, \
                (SELECT COUNT(*) FROM runs WHERE state = 'FAILED') AS run_failed, \
                (SELECT COUNT(*) FROM runs WHERE state = 'RECOVERED') AS run_recovered, \
                (SELECT COUNT(*) FROM runs WHERE state = 'EXITED_WHILE_OFFLINE') AS run_exited_while_offline, \
                (SELECT COUNT(*) FROM runs WHERE state = 'IDENTITY_MISMATCH') AS run_identity_mismatch, \
                (SELECT COUNT(*) FROM runs WHERE state = 'ORPHANED') AS run_orphaned, \
                (SELECT COUNT(*) FROM audit_events) AS audit_events, \
                (SELECT COUNT(*) FROM app_settings) AS application_settings, \
                (SELECT COUNT(*) FROM credential_cleanup_queue) AS pending_credential_cleanup, \
                (SELECT COUNT(*) FROM managed_stop_operations \
                    WHERE status IN ('REQUESTED', 'SIGNAL_PENDING', 'IN_PROGRESS', 'TIMED_OUT')) \
                    AS active_stop_operations, \
                (SELECT COUNT(*) FROM catalog_mutation_ledger) AS catalog_mutation_operations, \
                (SELECT COUNT(*) FROM managed_exit_operations) AS managed_exit_operations, \
                (SELECT COUNT(*) FROM runs WHERE logs_deleted_at IS NULL \
                    AND state IN ('EXITED', 'FAILED', 'EXITED_WHILE_OFFLINE', \
                                  'IDENTITY_MISMATCH', 'ORPHANED')) AS pending_log_retention",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|error| storage_error("read aggregate diagnostic database summary", error))?;
        raw.try_into()
    }
}

impl TryFrom<RawDiagnosticDatabaseSummary> for DiagnosticDatabaseSummary {
    type Error = AppError;

    fn try_from(raw: RawDiagnosticDatabaseSummary) -> Result<Self, Self::Error> {
        Ok(Self {
            schema_version: u32::try_from(raw.schema_version)
                .map_err(|_| invalid_diagnostic_count("schemaVersion"))?,
            projects: count("projects", raw.projects)?,
            launch_profiles: count("launchProfiles", raw.launch_profiles)?,
            launch_environment_entries: count(
                "launchEnvironmentEntries",
                raw.launch_environment_entries,
            )?,
            classification_rules: count("classificationRules", raw.classification_rules)?,
            runs: DiagnosticRunStateCounts {
                total: count("runs.total", raw.run_total)?,
                starting: count("runs.starting", raw.run_starting)?,
                running: count("runs.running", raw.run_running)?,
                stop_requested: count("runs.stopRequested", raw.run_stop_requested)?,
                graceful_stopping: count("runs.gracefulStopping", raw.run_graceful_stopping)?,
                force_stopping: count("runs.forceStopping", raw.run_force_stopping)?,
                exited: count("runs.exited", raw.run_exited)?,
                failed: count("runs.failed", raw.run_failed)?,
                recovered: count("runs.recovered", raw.run_recovered)?,
                exited_while_offline: count(
                    "runs.exitedWhileOffline",
                    raw.run_exited_while_offline,
                )?,
                identity_mismatch: count("runs.identityMismatch", raw.run_identity_mismatch)?,
                orphaned: count("runs.orphaned", raw.run_orphaned)?,
            },
            audit_events: count("auditEvents", raw.audit_events)?,
            application_settings: count("applicationSettings", raw.application_settings)?,
            pending_credential_cleanup: count(
                "pendingCredentialCleanup",
                raw.pending_credential_cleanup,
            )?,
            active_stop_operations: count("activeStopOperations", raw.active_stop_operations)?,
            catalog_mutation_operations: count(
                "catalogMutationOperations",
                raw.catalog_mutation_operations,
            )?,
            managed_exit_operations: count("managedExitOperations", raw.managed_exit_operations)?,
            pending_log_retention: count("pendingLogRetention", raw.pending_log_retention)?,
        })
    }
}

fn count(field: &'static str, value: i64) -> StorageResult<u64> {
    u64::try_from(value).map_err(|_| invalid_diagnostic_count(field))
}

fn invalid_diagnostic_count(field: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::StorageError,
        "aggregate diagnostic database summary is invalid",
    );
    error.details.insert("field".into(), field.into());
    error
}
