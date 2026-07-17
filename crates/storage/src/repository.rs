use std::collections::HashSet;
use std::fs::File;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use discovery::{
    MAX_PROJECT_ANCESTOR_DEPTH, MAX_PROJECT_PATH_BYTES, NormalizedPathKey, NormalizedPathRoot,
    NormalizedProjectRoot,
};
use domain::{AppError, ErrorCode};
use platform_common::credentials::{CredentialDeleteOutcome, CredentialReference, SecretStore};
use sqlx::migrate::Migrator;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteConnection, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous,
};
use sqlx::{Sqlite, SqlitePool, Transaction};
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::LPARAM;
#[cfg(target_os = "windows")]
use windows::Win32::Globalization::{LCMAP_UPPERCASE, LCMapStringEx, LOCALE_NAME_INVARIANT};

use crate::error::{migration_recovery_error, not_found, storage_error};
use crate::migration_recovery::prepare_database;
use crate::models::AuditEvent;
use crate::models::{
    LaunchProfile, LaunchProfileCursor, LaunchProfileEnvironment, LaunchProfilePage,
    LaunchProfileWithEnvironment, Run,
};
use crate::{AppSetting, ClassificationRule, PrivateDatabasePath, Project, StorageResult};

static MIGRATOR: Migrator = sqlx::migrate!("../../migrations");
static REPOSITORY_OPEN: AtomicBool = AtomicBool::new(false);

const MAX_PROJECT_ID_BYTES: usize = 256;
const MAX_PROJECT_NAME_BYTES: usize = 256;
const MAX_PROJECT_TIMESTAMP_BYTES: usize = 128;
const MAX_NORMALIZED_PROJECT_PATH_BYTES: usize = MAX_PROJECT_PATH_BYTES * 2 + 128;
const MAX_LAUNCH_PROFILE_ID_BYTES: usize = 256;
const MAX_LAUNCH_PROJECT_ID_BYTES: usize = 256;
const MAX_LAUNCH_PROFILE_NAME_BYTES: usize = 256;
const MAX_LAUNCH_PROFILE_PAGE_SIZE: u16 = 4;
const MAX_LAUNCH_EXECUTABLE_BYTES: usize = 32 * 1_024;
const MAX_SHELL_COMMAND_BYTES: usize = 64 * 1_024;
const MAX_LAUNCH_ARGUMENTS: usize = 256;
const MAX_LAUNCH_ARGUMENT_BYTES: usize = 32 * 1_024;
const MAX_LAUNCH_ARGUMENT_TOTAL_BYTES: usize = 64 * 1_024;
const MAX_LAUNCH_ARGUMENT_JSON_BYTES: usize = 192 * 1_024;
const MAX_LAUNCH_WORKING_DIRECTORY_BYTES: usize = 32 * 1_024;
const MAX_LAUNCH_SHELL_BYTES: usize = 32;
const MAX_LAUNCH_TIMESTAMP_BYTES: usize = 128;
const MAX_LAUNCH_ENVIRONMENT_ENTRIES: usize = 256;
const MAX_LAUNCH_ENVIRONMENT_NAME_BYTES: usize = 256;
const MAX_LAUNCH_ENVIRONMENT_VALUE_BYTES: usize = 32 * 1_024;
const MAX_LAUNCH_ENVIRONMENT_TOTAL_BYTES: usize = 64 * 1_024;
const MAX_CREDENTIAL_REFERENCE_BYTES: usize = 4 * 1_024;
const MAX_CREDENTIAL_CLEANUP_BATCH_SIZE: u16 = 64;
const MAX_CREDENTIAL_CLEANUP_QUEUE_ENTRIES: i64 = 256;
const MAX_STOP_TIMEOUT_MS: i64 = 300_000;
const MAX_AUDIT_ID_BYTES: usize = 256;
const MAX_AUDIT_RUN_ID_BYTES: usize = 256;
const MAX_AUDIT_EVENT_TYPE_BYTES: usize = 128;
const MAX_AUDIT_SUMMARY_BYTES: usize = 256;
const MAX_AUDIT_DETAILS_BYTES: usize = 64 * 1_024;
const MAX_AUDIT_DETAILS_KEY_BYTES: usize = 128;
const MAX_AUDIT_DETAILS_STRING_BYTES: usize = 256;
const MAX_AUDIT_DETAILS_DEPTH: usize = 8;
const MAX_AUDIT_DETAILS_NODES: usize = 256;
const MAX_AUDIT_TIMESTAMP_BYTES: usize = 128;

pub const MAX_AUDIT_RETENTION_DELETE_BATCH_SIZE: u16 = 256;

/// The Supervisor-owned, single-connection SQLite write boundary.
///
/// This type deliberately does not implement [`Clone`]. Mutating operations
/// require `&mut self`, so the Supervisor actor remains the only write entry.
pub struct SupervisorRepository {
    pub(crate) pool: SqlitePool,
    pub(crate) _private_database_path: PrivateDatabasePath,
    _repository_lock: File,
    _open_guard: RepositoryOpenGuard,
}

struct RepositoryOpenGuard;

impl RepositoryOpenGuard {
    fn acquire() -> StorageResult<Self> {
        REPOSITORY_OPEN
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Self)
            .map_err(|_| migration_recovery_error("repository_already_open"))
    }
}

impl Drop for RepositoryOpenGuard {
    fn drop(&mut self) {
        REPOSITORY_OPEN.store(false, Ordering::Release);
    }
}

impl SupervisorRepository {
    /// Opens the fixed current-user database and runs all embedded migrations
    /// before exposing the repository to its caller.
    pub async fn open(private_database_path: PrivateDatabasePath) -> StorageResult<Self> {
        let open_guard = RepositoryOpenGuard::acquire()?;
        let repository_lock = private_database_path.acquire_repository_lock()?;
        prepare_database(&private_database_path, &MIGRATOR).await?;
        let database_path = private_database_path.database();

        let options = SqliteConnectOptions::new()
            .filename(database_path)
            .create_if_missing(false)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .busy_timeout(Duration::from_secs(5));

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(options)
            .await
            .map_err(|_| migration_recovery_error("open_final_database"))?;

        if private_database_path
            .validate_root()
            .and_then(|()| private_database_path.harden_existing_files())
            .is_err()
        {
            pool.close().await;
            return Err(migration_recovery_error("validate_final_database"));
        }

        Ok(Self {
            pool,
            _private_database_path: private_database_path,
            _repository_lock: repository_lock,
            _open_guard: open_guard,
        })
    }

    pub async fn close(self) {
        self.pool.close().await;
    }

    /// Durably marks a newly generated reference before its secret is written
    /// to the operating-system store. A successful profile save adopts it in
    /// the same transaction as the profile environment write.
    pub async fn stage_credential_cleanup(
        &mut self,
        reference: &CredentialReference,
    ) -> StorageResult<()> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| storage_error("begin credential cleanup transaction", error))?;
        enqueue_unreferenced_credential_references(
            &mut transaction,
            &[reference.as_str().to_owned()],
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|error| storage_error("commit credential cleanup transaction", error))
    }

    /// Deletes a bounded batch from the operating-system store. Queue rows are
    /// acknowledged only after deletion succeeds or the secret is already
    /// absent, so failures remain retryable without affecting profile writes.
    pub async fn drain_credential_cleanup(
        &mut self,
        credential_store: &dyn SecretStore,
        limit: u16,
    ) -> StorageResult<u16> {
        validate_credential_cleanup_limit(limit)?;
        let queued = sqlx::query_scalar::<_, String>(
            "SELECT queue.credential_ref \
             FROM credential_cleanup_queue AS queue \
             WHERE NOT EXISTS (\
                 SELECT 1 FROM profile_environment AS environment \
                 WHERE environment.credential_ref = queue.credential_ref\
             ) \
             ORDER BY queue.credential_ref COLLATE BINARY LIMIT ?",
        )
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(|error| storage_error("read credential cleanup queue", error))?;

        let mut acknowledged = 0_u16;
        for queued_reference in queued {
            let reference = CredentialReference::parse(&queued_reference)
                .map_err(|_| corrupt_credential_cleanup_queue())?;
            match credential_store
                .delete(&reference)
                .map_err(credential_cleanup_store_error)?
            {
                CredentialDeleteOutcome::Deleted | CredentialDeleteOutcome::NotFound => {}
            }
            let result = sqlx::query(
                "DELETE FROM credential_cleanup_queue \
                 WHERE credential_ref = ? AND NOT EXISTS (\
                     SELECT 1 FROM profile_environment WHERE credential_ref = ?\
                 )",
            )
            .bind(reference.as_str())
            .bind(reference.as_str())
            .execute(&self.pool)
            .await
            .map_err(|error| storage_error("acknowledge credential cleanup", error))?;
            if result.rows_affected() != 0 {
                acknowledged = acknowledged.saturating_add(1);
            }
        }
        Ok(acknowledged)
    }

    #[allow(dead_code)]
    pub(crate) async fn update_project(
        &mut self,
        project: &Project,
        trusted_root: &NormalizedProjectRoot,
    ) -> StorageResult<()> {
        validate_project(project, trusted_root)?;
        let result = sqlx::query(
            "UPDATE projects SET name = ?, root_directory = ?, normalized_path = ?, updated_at = ? \
             WHERE id = ?",
        )
        .bind(&project.name)
        .bind(&project.root_directory)
        .bind(&project.normalized_path)
        .bind(&project.updated_at)
        .bind(&project.id)
        .execute(&self.pool)
        .await
        .map_err(|error| storage_error("update project", error))?;
        require_affected(result.rows_affected(), "project", &project.id)
    }

    #[allow(dead_code)]
    pub(crate) async fn project(&self, id: &str) -> StorageResult<Project> {
        sqlx::query_as::<_, Project>(
            "SELECT id, name, root_directory, normalized_path, created_at, updated_at \
             FROM projects WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| storage_error("read project", error))?
        .ok_or_else(|| not_found("project", id))
    }

    pub(crate) async fn projects(&self) -> StorageResult<Vec<Project>> {
        sqlx::query_as::<_, Project>(
            "SELECT id, name, root_directory, normalized_path, created_at, updated_at \
             FROM projects ORDER BY name, id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|error| storage_error("list projects", error))
    }

    #[allow(dead_code)]
    pub(crate) async fn delete_project(&mut self, id: &str) -> StorageResult<()> {
        let result = sqlx::query("DELETE FROM projects WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|error| storage_error("delete project", error))?;
        require_affected(result.rows_affected(), "project", id)
    }

    pub(crate) async fn insert_stored_launch_profile(
        &mut self,
        transaction: &mut Transaction<'_, Sqlite>,
        profile: &LaunchProfile,
        environment: &[LaunchProfileEnvironment],
        credential_references: &[CredentialReference],
    ) -> StorageResult<()> {
        let arguments_json = validate_launch_profile(profile, environment)?;
        validate_launch_profile_relations(transaction, profile, true).await?;
        insert_launch_profile_row(transaction, profile, &arguments_json).await?;
        replace_profile_environment(transaction, &profile.id, environment).await?;
        adopt_credential_references(transaction, credential_references).await
    }

    pub(crate) async fn update_stored_launch_profile(
        &mut self,
        transaction: &mut Transaction<'_, Sqlite>,
        profile: &LaunchProfile,
        environment: &[LaunchProfileEnvironment],
        expected_updated_at: &str,
        credential_references: &[CredentialReference],
    ) -> StorageResult<()> {
        let arguments_json = validate_launch_profile(profile, environment)?;
        validate_required_launch_text(
            "expectedUpdatedAt",
            expected_updated_at,
            MAX_LAUNCH_TIMESTAMP_BYTES,
        )?;
        if profile.updated_at == expected_updated_at {
            return Err(invalid_launch_profile(
                "updatedAt",
                "must differ from expectedUpdatedAt so the version advances",
            ));
        }
        let actual_updated_at = launch_profile_updated_at(transaction, &profile.id).await?;
        require_launch_profile_version(&profile.id, expected_updated_at, &actual_updated_at)?;
        validate_launch_profile_relations(transaction, profile, false).await?;
        let old_credential_references =
            profile_credential_references(transaction, &profile.id).await?;

        let result = sqlx::query(
            "UPDATE launch_profiles SET project_id = ?, name = ?, execution_mode = ?, \
             executable = ?, arguments_json = ?, working_directory = ?, shell = ?, \
             interactive = ?, stop_timeout_ms = ?, updated_at = ? \
             WHERE id = ? AND updated_at = ?",
        )
        .bind(&profile.project_id)
        .bind(&profile.name)
        .bind(&profile.execution_mode)
        .bind(&profile.executable)
        .bind(&arguments_json)
        .bind(&profile.working_directory)
        .bind(&profile.shell)
        .bind(profile.interactive)
        .bind(profile.stop_timeout_ms)
        .bind(&profile.updated_at)
        .bind(&profile.id)
        .bind(expected_updated_at)
        .execute(&mut **transaction)
        .await
        .map_err(|error| storage_error("update launch profile", error))?;
        if result.rows_affected() == 0 {
            return Err(launch_profile_version_conflict(
                &profile.id,
                expected_updated_at,
                &actual_updated_at,
            ));
        }

        replace_profile_environment(transaction, &profile.id, environment).await?;
        adopt_credential_references(transaction, credential_references).await?;
        enqueue_unreferenced_credential_references(transaction, &old_credential_references).await?;
        Ok(())
    }

    pub(crate) async fn stored_launch_profile(
        &self,
        id: &str,
    ) -> StorageResult<LaunchProfileWithEnvironment> {
        let profile = sqlx::query_as::<_, LaunchProfile>(LAUNCH_PROFILE_SELECT_BY_ID)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| storage_error("read launch profile", error))?
            .ok_or_else(|| not_found("launchProfile", id))?;
        let environment = profile_environment(&self.pool, id).await?;
        Ok(LaunchProfileWithEnvironment {
            profile,
            environment,
        })
    }

    pub(crate) async fn stored_launch_profiles(
        &self,
        cursor_name: Option<&str>,
        cursor_id: Option<&str>,
        limit: u16,
    ) -> StorageResult<LaunchProfilePage> {
        let cursor = validate_launch_profile_page(cursor_name, cursor_id, limit)?;
        let query_limit = i64::from(limit) + 1;
        let mut profiles = match cursor {
            Some((name, id)) => {
                sqlx::query_as::<_, LaunchProfile>(
                    "SELECT id, project_id, name, execution_mode, executable, arguments_json, \
                 working_directory, shell, interactive, stop_timeout_ms, created_at, updated_at \
                 FROM launch_profiles \
                 WHERE name COLLATE BINARY > ? \
                    OR (name COLLATE BINARY = ? AND id COLLATE BINARY > ?) \
                 ORDER BY name COLLATE BINARY, id COLLATE BINARY LIMIT ?",
                )
                .bind(name)
                .bind(name)
                .bind(id)
                .bind(query_limit)
                .fetch_all(&self.pool)
                .await
            }
            None => {
                sqlx::query_as::<_, LaunchProfile>(
                    "SELECT id, project_id, name, execution_mode, executable, arguments_json, \
                 working_directory, shell, interactive, stop_timeout_ms, created_at, updated_at \
                 FROM launch_profiles \
                 ORDER BY name COLLATE BINARY, id COLLATE BINARY LIMIT ?",
                )
                .bind(query_limit)
                .fetch_all(&self.pool)
                .await
            }
        }
        .map_err(|error| storage_error("list launch profiles", error))?;

        let has_more = profiles.len() > usize::from(limit);
        profiles.truncate(usize::from(limit));
        let next_cursor = if has_more {
            profiles.last().map(|profile| LaunchProfileCursor {
                name: profile.name.clone(),
                id: profile.id.clone(),
            })
        } else {
            None
        };
        let mut records = Vec::with_capacity(profiles.len());
        for profile in profiles {
            let environment = profile_environment(&self.pool, &profile.id).await?;
            records.push(LaunchProfileWithEnvironment {
                profile,
                environment,
            });
        }
        Ok(LaunchProfilePage {
            items: records,
            next_cursor,
        })
    }

    pub(crate) async fn delete_stored_launch_profile(
        &mut self,
        transaction: &mut Transaction<'_, Sqlite>,
        id: &str,
        expected_updated_at: &str,
    ) -> StorageResult<()> {
        validate_required_launch_text("id", id, MAX_LAUNCH_PROFILE_ID_BYTES)?;
        validate_required_launch_text(
            "expectedUpdatedAt",
            expected_updated_at,
            MAX_LAUNCH_TIMESTAMP_BYTES,
        )?;
        let actual_updated_at = launch_profile_updated_at(transaction, id).await?;
        require_launch_profile_version(id, expected_updated_at, &actual_updated_at)?;
        let old_credential_references = profile_credential_references(transaction, id).await?;
        let result = sqlx::query("DELETE FROM launch_profiles WHERE id = ? AND updated_at = ?")
            .bind(id)
            .bind(expected_updated_at)
            .execute(&mut **transaction)
            .await
            .map_err(|error| storage_error("delete launch profile", error))?;
        if result.rows_affected() == 0 {
            return Err(launch_profile_version_conflict(
                id,
                expected_updated_at,
                &actual_updated_at,
            ));
        }
        enqueue_unreferenced_credential_references(transaction, &old_credential_references).await?;
        Ok(())
    }

    pub(crate) async fn insert_run(&mut self, run: &Run) -> StorageResult<()> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| storage_error("begin run transaction", error))?;
        insert_run_row(&mut transaction, run).await?;
        transaction
            .commit()
            .await
            .map_err(|error| storage_error("commit run transaction", error))
    }

    #[allow(dead_code)]
    pub(crate) async fn update_run(&mut self, run: &Run) -> StorageResult<()> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| storage_error("begin run transaction", error))?;
        update_run_row(&mut transaction, run).await?;
        transaction
            .commit()
            .await
            .map_err(|error| storage_error("commit run transaction", error))
    }

    /// Binds an immutable process instance identity and its optional POSIX
    /// process group to a run exactly once.
    pub(crate) async fn bind_run_process_identity_and_control(
        &mut self,
        run_id: &str,
        instance_key: &domain::ProcessInstanceKey,
        process_group_id: Option<u32>,
        expected_updated_at: &str,
        updated_at: &str,
    ) -> StorageResult<()> {
        let result = sqlx::query(
            "UPDATE runs SET process_boot_id = ?, process_pid = ?, \
             process_native_start_time = ?, process_group_id = ?, updated_at = ? \
              WHERE id = ? AND state = 'STARTING' AND process_boot_id IS NULL \
              AND process_pid IS NULL AND process_native_start_time IS NULL \
              AND process_group_id IS NULL AND updated_at = ?",
        )
        .bind(&instance_key.boot_id)
        .bind(i64::from(instance_key.pid))
        .bind(&instance_key.native_start_time)
        .bind(process_group_id.map(i64::from))
        .bind(updated_at)
        .bind(run_id)
        .bind(expected_updated_at)
        .execute(&self.pool)
        .await
        .map_err(|error| storage_error("bind run process identity and control", error))?;

        if result.rows_affected() != 0 {
            return Ok(());
        }
        if run_exists(&self.pool, run_id).await? {
            Err(run_identity_already_bound(run_id))
        } else {
            Err(not_found("run", run_id))
        }
    }

    /// Persists a run state transition and its immutable audit event atomically.
    #[allow(dead_code)]
    pub(crate) async fn update_run_with_audit(
        &mut self,
        run: &Run,
        audit_event: &AuditEvent,
    ) -> StorageResult<()> {
        if audit_event.run_id.as_deref() != Some(run.id.as_str()) {
            return Err(audit_run_mismatch(&run.id, audit_event.run_id.as_deref()));
        }
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| storage_error("begin run audit transaction", error))?;
        update_run_row(&mut transaction, run).await?;
        insert_audit_event_row(&mut transaction, audit_event).await?;
        transaction
            .commit()
            .await
            .map_err(|error| storage_error("commit run audit transaction", error))
    }

    pub(crate) async fn run(&self, id: &str) -> StorageResult<Run> {
        sqlx::query_as::<_, Run>(RUN_SELECT_BY_ID)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| storage_error("read run", error))?
            .ok_or_else(|| not_found("run", id))
    }

    pub(crate) async fn transition_starting_run(
        &mut self,
        run_id: &str,
        next_state: &str,
        exit_summary: Option<&str>,
        updated_at: &str,
        ended_at: Option<&str>,
        require_identity: bool,
        expected_updated_at: &str,
    ) -> StorageResult<Option<Run>> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| storage_error("begin starting run transition", error))?;
        let result = if require_identity {
            sqlx::query(
                "UPDATE runs SET state = ?, exit_summary = ?, updated_at = ?, ended_at = ? \
                 WHERE id = ? AND state = 'STARTING' AND ended_at IS NULL \
                  AND process_boot_id IS NOT NULL AND process_pid IS NOT NULL \
                  AND process_native_start_time IS NOT NULL AND updated_at = ?",
            )
            .bind(next_state)
            .bind(exit_summary)
            .bind(updated_at)
            .bind(ended_at)
            .bind(run_id)
            .bind(expected_updated_at)
            .execute(&mut *transaction)
            .await
        } else {
            sqlx::query(
                "UPDATE runs SET state = ?, exit_summary = ?, updated_at = ?, ended_at = ? \
                  WHERE id = ? AND state = 'STARTING' AND ended_at IS NULL AND updated_at = ?",
            )
            .bind(next_state)
            .bind(exit_summary)
            .bind(updated_at)
            .bind(ended_at)
            .bind(run_id)
            .bind(expected_updated_at)
            .execute(&mut *transaction)
            .await
        }
        .map_err(|error| storage_error("transition starting run", error))?;
        if result.rows_affected() != 1 {
            transaction.rollback().await.map_err(|error| {
                storage_error("rollback rejected starting run transition", error)
            })?;
            return Ok(None);
        }
        let row = sqlx::query_as::<_, Run>(RUN_SELECT_BY_ID)
            .bind(run_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|error| storage_error("read transitioned starting run", error))?
            .ok_or_else(|| not_found("run", run_id))?;
        transaction
            .commit()
            .await
            .map_err(|error| storage_error("commit starting run transition", error))?;
        Ok(Some(row))
    }

    /// Atomically closes a live run whose complete process identity is still
    /// bound. The returned flag distinguishes a successful compare-and-swap
    /// from the current row observed after a rejected transition.
    pub(crate) async fn transition_running_run_to_exited(
        &mut self,
        run_id: &str,
        expected_updated_at: &str,
        ended_at: &str,
    ) -> StorageResult<(Run, bool)> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| storage_error("begin running run exit transition", error))?;
        let result = sqlx::query(
            "UPDATE runs SET state = 'EXITED', exit_code = NULL, exit_signal = NULL, \
             updated_at = ?, ended_at = ? WHERE id = ? AND state = 'RUNNING' \
              AND ended_at IS NULL AND exit_code IS NULL AND exit_signal IS NULL \
              AND process_boot_id IS NOT NULL AND process_pid IS NOT NULL \
              AND process_native_start_time IS NOT NULL AND updated_at = ?",
        )
        .bind(ended_at)
        .bind(ended_at)
        .bind(run_id)
        .bind(expected_updated_at)
        .execute(&mut *transaction)
        .await
        .map_err(|error| storage_error("transition running run to exited", error))?;
        let transitioned = result.rows_affected() == 1;
        let row = sqlx::query_as::<_, Run>(RUN_SELECT_BY_ID)
            .bind(run_id)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(|error| storage_error("read running run exit transition", error))?;

        if transitioned {
            let row = row.ok_or_else(|| not_found("run", run_id))?;
            transaction
                .commit()
                .await
                .map_err(|error| storage_error("commit running run exit transition", error))?;
            return Ok((row, true));
        }

        transaction.rollback().await.map_err(|error| {
            storage_error("rollback rejected running run exit transition", error)
        })?;
        row.map(|row| (row, false))
            .ok_or_else(|| not_found("run", run_id))
    }

    #[allow(dead_code)]
    pub(crate) async fn runs(&self, limit: u32) -> StorageResult<Vec<Run>> {
        sqlx::query_as::<_, Run>(
            "SELECT id, profile_id, profile_snapshot_json, process_boot_id, process_pid, \
             process_native_start_time, process_group_id, state, exit_code, exit_signal, exit_summary, \
             stop_method, log_directory, log_redaction_version, recovery_state, started_at, updated_at, ended_at, \
             logs_deletion_started_at, logs_deleted_at \
             FROM runs ORDER BY started_at DESC, id DESC LIMIT ?",
        )
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(|error| storage_error("list runs", error))
    }

    #[allow(dead_code)]
    pub(crate) async fn delete_run(&mut self, id: &str) -> StorageResult<()> {
        let result = sqlx::query("DELETE FROM runs WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|error| storage_error("delete run", error))?;
        require_affected(result.rows_affected(), "run", id)
    }

    #[allow(dead_code)]
    pub(crate) async fn update_classification_rule(
        &mut self,
        rule: &ClassificationRule,
    ) -> StorageResult<()> {
        validate_classification_rule(rule)?;
        let result = sqlx::query(
            "UPDATE classification_rules SET rule_type = ?, pattern = ?, action = ?, \
             project_id = ?, priority = ?, enabled = ?, updated_at = ? WHERE id = ?",
        )
        .bind(&rule.rule_type)
        .bind(&rule.pattern)
        .bind(&rule.action)
        .bind(&rule.project_id)
        .bind(rule.priority)
        .bind(rule.enabled)
        .bind(&rule.updated_at)
        .bind(&rule.id)
        .execute(&self.pool)
        .await
        .map_err(|error| storage_error("update classification rule", error))?;
        require_affected(result.rows_affected(), "classificationRule", &rule.id)
    }

    #[allow(dead_code)]
    pub(crate) async fn classification_rule(&self, id: &str) -> StorageResult<ClassificationRule> {
        sqlx::query_as::<_, ClassificationRule>(
            "SELECT id, rule_type, pattern, action, project_id, priority, enabled, created_at, updated_at \
             FROM classification_rules WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| storage_error("read classification rule", error))?
        .ok_or_else(|| not_found("classificationRule", id))
    }

    pub(crate) async fn classification_rules(&self) -> StorageResult<Vec<ClassificationRule>> {
        sqlx::query_as::<_, ClassificationRule>(
            "SELECT id, rule_type, pattern, action, project_id, priority, enabled, created_at, updated_at \
             FROM classification_rules ORDER BY priority DESC, id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|error| storage_error("list classification rules", error))
    }

    #[allow(dead_code)]
    pub(crate) async fn delete_classification_rule(&mut self, id: &str) -> StorageResult<()> {
        let result = sqlx::query("DELETE FROM classification_rules WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|error| storage_error("delete classification rule", error))?;
        require_affected(result.rows_affected(), "classificationRule", id)
    }

    /// Audit events are append-only; retention and explicit deletion are the
    /// supported delete operations.
    #[allow(dead_code)]
    pub(crate) async fn insert_audit_event(&mut self, event: &AuditEvent) -> StorageResult<()> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| storage_error("begin audit transaction", error))?;
        insert_audit_event_row(&mut transaction, event).await?;
        transaction
            .commit()
            .await
            .map_err(|error| storage_error("commit audit transaction", error))
    }

    #[allow(dead_code)]
    pub(crate) async fn audit_events(&self, limit: u16) -> StorageResult<Vec<AuditEvent>> {
        validate_audit_limit(limit)?;
        let events = sqlx::query_as::<_, AuditEvent>(
            "SELECT id, run_id, event_type, summary, details_json, occurred_at, retention_until \
             FROM audit_events ORDER BY occurred_at DESC, id DESC LIMIT ?",
        )
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await
        .map_err(|error| storage_error("list audit events", error))?;
        for event in &events {
            validate_audit_event(event).map_err(|_| corrupt_audit_event())?;
        }
        Ok(events)
    }

    #[allow(dead_code)]
    pub(crate) async fn delete_audit_event(&mut self, id: &str) -> StorageResult<()> {
        validate_audit_code("id", id, MAX_AUDIT_ID_BYTES)?;
        let result = sqlx::query("DELETE FROM audit_events WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|error| storage_error("delete audit event", error))?;
        require_affected(result.rows_affected(), "auditEvent", id)
    }

    pub async fn delete_expired_audit_events(
        &mut self,
        retention_cutoff: &str,
        limit: u16,
    ) -> StorageResult<u64> {
        validate_audit_timestamp("retentionCutoff", retention_cutoff)?;
        validate_audit_limit(limit)?;
        let result = sqlx::query(
            "DELETE FROM audit_events WHERE id IN (\
                 SELECT id FROM audit_events WHERE retention_until <= ? \
                 ORDER BY retention_until COLLATE BINARY, occurred_at COLLATE BINARY, \
                          id COLLATE BINARY LIMIT ?\
             )",
        )
        .bind(retention_cutoff)
        .bind(i64::from(limit))
        .execute(&self.pool)
        .await
        .map_err(|error| storage_error("delete expired audit events", error))?;
        Ok(result.rows_affected())
    }

    pub async fn insert_setting(&mut self, setting: &AppSetting) -> StorageResult<()> {
        sqlx::query("INSERT INTO app_settings (key, value_json, updated_at) VALUES (?, ?, ?)")
            .bind(&setting.key)
            .bind(&setting.value_json)
            .bind(&setting.updated_at)
            .execute(&self.pool)
            .await
            .map_err(|error| storage_error("insert application setting", error))?;
        Ok(())
    }

    pub async fn update_setting(&mut self, setting: &AppSetting) -> StorageResult<()> {
        let result =
            sqlx::query("UPDATE app_settings SET value_json = ?, updated_at = ? WHERE key = ?")
                .bind(&setting.value_json)
                .bind(&setting.updated_at)
                .bind(&setting.key)
                .execute(&self.pool)
                .await
                .map_err(|error| storage_error("update application setting", error))?;
        require_affected(result.rows_affected(), "appSetting", &setting.key)
    }

    pub async fn setting(&self, key: &str) -> StorageResult<AppSetting> {
        sqlx::query_as::<_, AppSetting>(
            "SELECT key, value_json, updated_at FROM app_settings WHERE key = ?",
        )
        .bind(key)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| storage_error("read application setting", error))?
        .ok_or_else(|| not_found("appSetting", key))
    }

    pub async fn settings(&self) -> StorageResult<Vec<AppSetting>> {
        sqlx::query_as::<_, AppSetting>(
            "SELECT key, value_json, updated_at FROM app_settings ORDER BY key",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|error| storage_error("list application settings", error))
    }

    pub async fn delete_setting(&mut self, key: &str) -> StorageResult<()> {
        let result = sqlx::query("DELETE FROM app_settings WHERE key = ?")
            .bind(key)
            .execute(&self.pool)
            .await
            .map_err(|error| storage_error("delete application setting", error))?;
        require_affected(result.rows_affected(), "appSetting", key)
    }
}

const LAUNCH_PROFILE_SELECT_BY_ID: &str = "SELECT id, project_id, name, execution_mode, executable, arguments_json, \
     working_directory, shell, interactive, stop_timeout_ms, created_at, updated_at \
     FROM launch_profiles WHERE id = ?";

pub(crate) const RUN_SELECT_BY_ID: &str = "SELECT id, profile_id, profile_snapshot_json, process_boot_id, process_pid, \
     process_native_start_time, process_group_id, state, exit_code, exit_signal, exit_summary, stop_method, \
     log_directory, log_redaction_version, recovery_state, started_at, updated_at, ended_at, logs_deletion_started_at, \
     logs_deleted_at FROM runs WHERE id = ?";

async fn launch_profile_updated_at(
    connection: &mut SqliteConnection,
    id: &str,
) -> StorageResult<String> {
    sqlx::query_scalar::<_, String>("SELECT updated_at FROM launch_profiles WHERE id = ?")
        .bind(id)
        .fetch_optional(connection)
        .await
        .map_err(|error| storage_error("read launch profile version", error))?
        .ok_or_else(|| not_found("launchProfile", id))
}

async fn insert_launch_profile_row(
    connection: &mut SqliteConnection,
    profile: &LaunchProfile,
    arguments_json: &str,
) -> StorageResult<()> {
    sqlx::query(
        "INSERT INTO launch_profiles \
         (id, project_id, name, execution_mode, executable, arguments_json, working_directory, \
         shell, interactive, stop_timeout_ms, created_at, updated_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&profile.id)
    .bind(&profile.project_id)
    .bind(&profile.name)
    .bind(&profile.execution_mode)
    .bind(&profile.executable)
    .bind(arguments_json)
    .bind(&profile.working_directory)
    .bind(&profile.shell)
    .bind(profile.interactive)
    .bind(profile.stop_timeout_ms)
    .bind(&profile.created_at)
    .bind(&profile.updated_at)
    .execute(connection)
    .await
    .map_err(|error| storage_error("insert launch profile", error))?;
    Ok(())
}

async fn replace_profile_environment(
    connection: &mut SqliteConnection,
    profile_id: &str,
    environment: &[LaunchProfileEnvironment],
) -> StorageResult<()> {
    sqlx::query("DELETE FROM profile_environment WHERE profile_id = ?")
        .bind(profile_id)
        .execute(&mut *connection)
        .await
        .map_err(|error| storage_error("replace launch profile environment", error))?;

    for variable in environment {
        if variable.profile_id != profile_id {
            return Err(invalid_profile_environment(
                profile_id,
                &variable.profile_id,
            ));
        }
        sqlx::query(
            "INSERT INTO profile_environment (profile_id, name, value, credential_ref) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(&variable.profile_id)
        .bind(&variable.name)
        .bind(&variable.value)
        .bind(&variable.credential_ref)
        .execute(&mut *connection)
        .await
        .map_err(|error| storage_error("insert launch profile environment", error))?;
    }
    Ok(())
}

async fn profile_credential_references(
    connection: &mut SqliteConnection,
    profile_id: &str,
) -> StorageResult<Vec<String>> {
    sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT credential_ref FROM profile_environment \
         WHERE profile_id = ? AND credential_ref IS NOT NULL \
         ORDER BY credential_ref COLLATE BINARY",
    )
    .bind(profile_id)
    .fetch_all(connection)
    .await
    .map_err(|error| storage_error("read profile credential references", error))
}

async fn adopt_credential_references(
    connection: &mut SqliteConnection,
    references: &[CredentialReference],
) -> StorageResult<()> {
    for reference in references {
        sqlx::query("DELETE FROM credential_cleanup_queue WHERE credential_ref = ?")
            .bind(reference.as_str())
            .execute(&mut *connection)
            .await
            .map_err(|error| storage_error("adopt profile credential reference", error))?;
    }
    Ok(())
}

async fn enqueue_unreferenced_credential_references(
    connection: &mut SqliteConnection,
    references: &[String],
) -> StorageResult<()> {
    for reference in references {
        let result = sqlx::query(
            "INSERT INTO credential_cleanup_queue (credential_ref) \
             SELECT ? WHERE NOT EXISTS (\
                 SELECT 1 FROM profile_environment WHERE credential_ref = ?\
             ) AND NOT EXISTS (\
                 SELECT 1 FROM credential_cleanup_queue WHERE credential_ref = ?\
             ) AND (SELECT COUNT(*) FROM credential_cleanup_queue) < ?",
        )
        .bind(reference)
        .bind(reference)
        .bind(reference)
        .bind(MAX_CREDENTIAL_CLEANUP_QUEUE_ENTRIES)
        .execute(&mut *connection)
        .await
        .map_err(|error| storage_error("enqueue credential cleanup", error))?;
        if result.rows_affected() == 0 {
            let already_safe = sqlx::query_scalar::<_, i64>(
                "SELECT EXISTS(\
                     SELECT 1 FROM profile_environment WHERE credential_ref = ?\
                 ) OR EXISTS(\
                     SELECT 1 FROM credential_cleanup_queue WHERE credential_ref = ?\
                 )",
            )
            .bind(reference)
            .bind(reference)
            .fetch_one(&mut *connection)
            .await
            .map_err(|error| storage_error("check credential cleanup capacity", error))?;
            if already_safe == 0 {
                return Err(credential_cleanup_queue_full());
            }
        }
    }
    Ok(())
}

async fn profile_environment(
    pool: &SqlitePool,
    profile_id: &str,
) -> StorageResult<Vec<LaunchProfileEnvironment>> {
    sqlx::query_as::<_, LaunchProfileEnvironment>(
        "SELECT profile_id, name, value, credential_ref FROM profile_environment \
         WHERE profile_id = ? ORDER BY name COLLATE BINARY",
    )
    .bind(profile_id)
    .fetch_all(pool)
    .await
    .map_err(|error| storage_error("read launch profile environment", error))
}

async fn insert_run_row(connection: &mut SqliteConnection, run: &Run) -> StorageResult<()> {
    sqlx::query(
        "INSERT INTO runs \
         (id, profile_id, profile_snapshot_json, process_boot_id, process_pid, \
         process_native_start_time, process_group_id, state, exit_code, exit_signal, exit_summary, stop_method, \
         log_directory, log_redaction_version, recovery_state, started_at, updated_at, ended_at, logs_deletion_started_at, \
         logs_deleted_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&run.id)
    .bind(&run.profile_id)
    .bind(&run.profile_snapshot_json)
    .bind(&run.process_boot_id)
    .bind(run.process_pid)
    .bind(&run.process_native_start_time)
    .bind(run.process_group_id)
    .bind(&run.state)
    .bind(run.exit_code)
    .bind(&run.exit_signal)
    .bind(&run.exit_summary)
    .bind(&run.stop_method)
    .bind(&run.log_directory)
    .bind(run.log_redaction_version)
    .bind(&run.recovery_state)
    .bind(&run.started_at)
    .bind(&run.updated_at)
    .bind(&run.ended_at)
    .bind(&run.logs_deletion_started_at)
    .bind(&run.logs_deleted_at)
    .execute(connection)
    .await
    .map_err(|error| storage_error("insert run", error))?;
    Ok(())
}

async fn update_run_row(connection: &mut SqliteConnection, run: &Run) -> StorageResult<()> {
    let result = sqlx::query(
        "UPDATE runs SET state = ?, exit_code = ?, exit_signal = ?, exit_summary = ?, \
         stop_method = ?, recovery_state = ?, updated_at = ?, ended_at = ?, \
         logs_deletion_started_at = ?, logs_deleted_at = ? \
         WHERE id = ?",
    )
    .bind(&run.state)
    .bind(run.exit_code)
    .bind(&run.exit_signal)
    .bind(&run.exit_summary)
    .bind(&run.stop_method)
    .bind(&run.recovery_state)
    .bind(&run.updated_at)
    .bind(&run.ended_at)
    .bind(&run.logs_deletion_started_at)
    .bind(&run.logs_deleted_at)
    .bind(&run.id)
    .execute(connection)
    .await
    .map_err(|error| storage_error("update run", error))?;
    require_affected(result.rows_affected(), "run", &run.id)
}

async fn run_exists(pool: &SqlitePool, run_id: &str) -> StorageResult<bool> {
    sqlx::query_scalar::<_, i64>("SELECT 1 FROM runs WHERE id = ?")
        .bind(run_id)
        .fetch_optional(pool)
        .await
        .map(|row| row.is_some())
        .map_err(|error| storage_error("check run existence", error))
}

async fn insert_audit_event_row(
    connection: &mut SqliteConnection,
    event: &AuditEvent,
) -> StorageResult<()> {
    validate_audit_event(event)?;
    sqlx::query(
        "INSERT INTO audit_events \
         (id, run_id, event_type, summary, details_json, occurred_at, retention_until) \
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&event.id)
    .bind(&event.run_id)
    .bind(&event.event_type)
    .bind(&event.summary)
    .bind(&event.details_json)
    .bind(&event.occurred_at)
    .bind(&event.retention_until)
    .execute(connection)
    .await
    .map_err(|error| storage_error("insert audit event", error))?;
    Ok(())
}

fn require_affected(rows_affected: u64, entity: &'static str, id: &str) -> StorageResult<()> {
    if rows_affected == 0 {
        Err(not_found(entity, id))
    } else {
        Ok(())
    }
}

fn validate_audit_event(event: &AuditEvent) -> StorageResult<()> {
    validate_audit_code("id", &event.id, MAX_AUDIT_ID_BYTES)?;
    if let Some(run_id) = &event.run_id {
        validate_audit_code("runId", run_id, MAX_AUDIT_RUN_ID_BYTES)?;
    }
    validate_audit_code("eventType", &event.event_type, MAX_AUDIT_EVENT_TYPE_BYTES)?;
    validate_audit_code("summary", &event.summary, MAX_AUDIT_SUMMARY_BYTES)?;
    validate_audit_timestamp("occurredAt", &event.occurred_at)?;
    validate_audit_timestamp("retentionUntil", &event.retention_until)?;

    if let Some(details_json) = &event.details_json {
        if details_json.len() > MAX_AUDIT_DETAILS_BYTES || details_json.contains('\0') {
            return Err(invalid_audit_event(
                "detailsJson",
                "must be bounded UTF-8 JSON without NUL",
            ));
        }
        let details = serde_json::from_str::<serde_json::Value>(details_json)
            .map_err(|_| invalid_audit_event("detailsJson", "must contain a valid JSON object"))?;
        if !details.is_object() {
            return Err(invalid_audit_event(
                "detailsJson",
                "must contain a JSON object",
            ));
        }
        let mut nodes = 0_usize;
        validate_audit_details_value(&details, 0, &mut nodes)?;
    }
    Ok(())
}

fn validate_audit_details_value(
    value: &serde_json::Value,
    depth: usize,
    nodes: &mut usize,
) -> StorageResult<()> {
    *nodes = nodes.saturating_add(1);
    if *nodes > MAX_AUDIT_DETAILS_NODES || depth > MAX_AUDIT_DETAILS_DEPTH {
        return Err(invalid_audit_event(
            "detailsJson",
            "exceeds the supported structure bounds",
        ));
    }
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object {
                validate_audit_detail_key(key)?;
                validate_audit_details_value(value, depth + 1, nodes)?;
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                validate_audit_details_value(value, depth + 1, nodes)?;
            }
        }
        serde_json::Value::String(value) => {
            validate_audit_code("detailsJson.value", value, MAX_AUDIT_DETAILS_STRING_BYTES)?
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
    Ok(())
}

fn validate_audit_detail_key(key: &str) -> StorageResult<()> {
    validate_audit_code("detailsJson.key", key, MAX_AUDIT_DETAILS_KEY_BYTES)?;
    let canonical = key
        .bytes()
        .filter(|byte| byte.is_ascii_alphanumeric())
        .map(|byte| byte.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let canonical =
        std::str::from_utf8(&canonical).expect("filtered ASCII audit detail key is valid UTF-8");
    let contains_content_fragment = ["command", "environment"]
        .iter()
        .any(|fragment| canonical.contains(fragment));
    let is_sensitive_field = platform_common::is_sensitive_field_name(key)
        || contains_content_fragment
        || matches!(
            canonical,
            "cookie"
                | "setcookie"
                | "env"
                | "argv"
                | "arguments"
                | "log"
                | "logs"
                | "logtext"
                | "stdout"
                | "stderr"
        );
    if is_sensitive_field {
        Err(invalid_audit_event(
            "detailsJson.key",
            "uses a field reserved for sensitive data",
        ))
    } else {
        Ok(())
    }
}

fn validate_audit_limit(limit: u16) -> StorageResult<()> {
    if (1..=MAX_AUDIT_RETENTION_DELETE_BATCH_SIZE).contains(&limit) {
        Ok(())
    } else {
        Err(invalid_audit_event(
            "limit",
            "must be between 1 and 256 entries",
        ))
    }
}

fn validate_audit_code(field: &'static str, value: &str, maximum: usize) -> StorageResult<()> {
    validate_audit_text(field, value, maximum)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-'))
    {
        return Err(invalid_audit_event(
            field,
            "must contain only portable code characters",
        ));
    }
    Ok(())
}

fn validate_audit_text(field: &'static str, value: &str, maximum: usize) -> StorageResult<()> {
    if value.trim().is_empty() || value.len() > maximum || value.contains('\0') {
        Err(invalid_audit_event(
            field,
            "must be non-empty bounded text without NUL",
        ))
    } else {
        Ok(())
    }
}

fn validate_audit_timestamp(field: &'static str, value: &str) -> StorageResult<()> {
    validate_audit_text(field, value, MAX_AUDIT_TIMESTAMP_BYTES)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'-' | b':' | b'.' | b'T' | b'Z'))
        || !value.contains('T')
        || !value.ends_with('Z')
    {
        return Err(invalid_audit_event(
            field,
            "must be a bounded UTC timestamp",
        ));
    }
    Ok(())
}

fn invalid_audit_event(field: &'static str, reason: &'static str) -> AppError {
    let mut error = AppError::new(ErrorCode::InvalidArgument, "invalid audit event");
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn corrupt_audit_event() -> AppError {
    AppError::new(ErrorCode::StorageError, "stored audit event is invalid")
}

fn validate_credential_cleanup_limit(limit: u16) -> StorageResult<()> {
    if (1..=MAX_CREDENTIAL_CLEANUP_BATCH_SIZE).contains(&limit) {
        Ok(())
    } else {
        let mut error = AppError::new(
            ErrorCode::InvalidArgument,
            "credential cleanup batch limit is invalid",
        );
        error.details.insert("field".into(), "limit".into());
        error
            .details
            .insert("reason".into(), "must be between 1 and 64 entries".into());
        Err(error)
    }
}

fn corrupt_credential_cleanup_queue() -> AppError {
    AppError::new(
        ErrorCode::StorageError,
        "credential cleanup queue contains an invalid reference",
    )
}

fn credential_cleanup_store_error(source: AppError) -> AppError {
    let mut error = AppError::new(source.code, "system credential cleanup failed");
    error.retryable = source.retryable;
    error
}

fn credential_cleanup_queue_full() -> AppError {
    let mut error = AppError::new(
        ErrorCode::StorageError,
        "system credential cleanup backlog is full",
    );
    error.retryable = true;
    error.details.insert(
        "limit".into(),
        MAX_CREDENTIAL_CLEANUP_QUEUE_ENTRIES.to_string(),
    );
    error
}

fn validate_launch_profile_page<'a>(
    cursor_name: Option<&'a str>,
    cursor_id: Option<&'a str>,
    limit: u16,
) -> StorageResult<Option<(&'a str, &'a str)>> {
    if !(1..=MAX_LAUNCH_PROFILE_PAGE_SIZE).contains(&limit) {
        return Err(invalid_launch_profile_page(
            "limit",
            "must be between 1 and 4",
        ));
    }
    match (cursor_name, cursor_id) {
        (Some(name), Some(id)) => {
            validate_required_launch_text("cursor.name", name, MAX_LAUNCH_PROFILE_NAME_BYTES)?;
            validate_required_launch_text("cursor.id", id, MAX_LAUNCH_PROFILE_ID_BYTES)?;
            Ok(Some((name, id)))
        }
        (None, None) => Ok(None),
        _ => Err(invalid_launch_profile_page(
            "cursor",
            "name and id must either both be present or both be absent",
        )),
    }
}

fn validate_launch_profile(
    profile: &LaunchProfile,
    environment: &[LaunchProfileEnvironment],
) -> StorageResult<String> {
    validate_required_launch_text("id", &profile.id, MAX_LAUNCH_PROFILE_ID_BYTES)?;
    if let Some(project_id) = &profile.project_id {
        validate_required_launch_text("projectId", project_id, MAX_LAUNCH_PROJECT_ID_BYTES)?;
    }
    validate_required_launch_text("name", &profile.name, MAX_LAUNCH_PROFILE_NAME_BYTES)?;
    validate_optional_launch_text(
        "executionMode",
        &profile.execution_mode,
        MAX_LAUNCH_SHELL_BYTES,
    )?;

    let arguments = validate_launch_arguments(&profile.arguments_json)?;
    match profile.execution_mode.as_str() {
        "DIRECT" => {
            validate_required_launch_text(
                "executable",
                &profile.executable,
                MAX_LAUNCH_EXECUTABLE_BYTES,
            )?;
            if profile.shell.is_some() {
                return Err(invalid_launch_profile(
                    "shell",
                    "must be absent for DIRECT execution",
                ));
            }
        }
        "SHELL" => {
            validate_required_launch_text(
                "executable",
                &profile.executable,
                MAX_SHELL_COMMAND_BYTES,
            )?;
            if !arguments.is_empty() {
                return Err(invalid_launch_profile(
                    "argumentsJson",
                    "must be an empty array for SHELL execution",
                ));
            }
            let shell = profile.shell.as_deref().ok_or_else(|| {
                invalid_launch_profile("shell", "must be present for SHELL execution")
            })?;
            validate_required_launch_text("shell", shell, MAX_LAUNCH_SHELL_BYTES)?;
            if !matches!(shell, "POWERSHELL" | "CMD" | "ZSH") {
                return Err(invalid_launch_profile(
                    "shell",
                    "must be POWERSHELL, CMD, or ZSH",
                ));
            }
        }
        "DETECTED_SCRIPT" => {
            return Err(invalid_launch_profile(
                "executionMode",
                "DETECTED_SCRIPT suggestions must be converted before persistence",
            ));
        }
        _ => {
            return Err(invalid_launch_profile(
                "executionMode",
                "must be DIRECT or SHELL",
            ));
        }
    }

    validate_required_launch_text(
        "workingDirectory",
        &profile.working_directory,
        MAX_LAUNCH_WORKING_DIRECTORY_BYTES,
    )?;
    if !Path::new(&profile.working_directory).is_absolute() {
        return Err(invalid_launch_profile(
            "workingDirectory",
            "must be an absolute path",
        ));
    }
    if !(0..=MAX_STOP_TIMEOUT_MS).contains(&profile.stop_timeout_ms) {
        return Err(invalid_launch_profile(
            "stopTimeoutMs",
            "must be between 0 and 300000 milliseconds",
        ));
    }
    validate_required_launch_text("createdAt", &profile.created_at, MAX_LAUNCH_TIMESTAMP_BYTES)?;
    validate_required_launch_text("updatedAt", &profile.updated_at, MAX_LAUNCH_TIMESTAMP_BYTES)?;
    validate_launch_environment(&profile.id, environment)?;

    let canonical_arguments = serde_json::to_string(&arguments).map_err(|_| {
        invalid_launch_profile("argumentsJson", "could not be serialized canonically")
    })?;
    if canonical_arguments.len() > MAX_LAUNCH_ARGUMENT_JSON_BYTES {
        return Err(invalid_launch_profile(
            "argumentsJson",
            "canonical representation exceeds the supported length",
        ));
    }
    Ok(canonical_arguments)
}

fn validate_launch_arguments(arguments_json: &str) -> StorageResult<Vec<String>> {
    validate_optional_launch_text(
        "argumentsJson",
        arguments_json,
        MAX_LAUNCH_ARGUMENT_JSON_BYTES,
    )?;
    let arguments = serde_json::from_str::<Vec<String>>(arguments_json).map_err(|_| {
        invalid_launch_profile(
            "argumentsJson",
            "must be a JSON array containing only strings",
        )
    })?;
    if arguments.len() > MAX_LAUNCH_ARGUMENTS {
        return Err(invalid_launch_profile(
            "argumentsJson",
            "exceeds the supported argument count",
        ));
    }
    let mut total_bytes = 0_usize;
    for argument in &arguments {
        validate_optional_launch_text("argumentsJson", argument, MAX_LAUNCH_ARGUMENT_BYTES)?;
        total_bytes = total_bytes.saturating_add(argument.len());
    }
    if total_bytes > MAX_LAUNCH_ARGUMENT_TOTAL_BYTES {
        return Err(invalid_launch_profile(
            "argumentsJson",
            "exceeds the supported total argument length",
        ));
    }
    Ok(arguments)
}

fn validate_launch_environment(
    profile_id: &str,
    environment: &[LaunchProfileEnvironment],
) -> StorageResult<()> {
    if environment.len() > MAX_LAUNCH_ENVIRONMENT_ENTRIES {
        return Err(invalid_launch_profile(
            "environment",
            "exceeds the supported entry count",
        ));
    }

    let mut names = HashSet::with_capacity(environment.len());
    let mut total_bytes = 0_usize;
    for variable in environment {
        if variable.profile_id != profile_id {
            return Err(invalid_profile_environment(
                profile_id,
                &variable.profile_id,
            ));
        }
        validate_required_launch_text(
            "environment.name",
            &variable.name,
            MAX_LAUNCH_ENVIRONMENT_NAME_BYTES,
        )?;
        if !is_portable_environment_name(&variable.name) {
            return Err(invalid_launch_profile(
                "environment.name",
                "must match [A-Za-z_][A-Za-z0-9_]*",
            ));
        }
        if !names.insert(environment_name_key(&variable.name)?) {
            return Err(invalid_launch_profile(
                "environment",
                "contains duplicate names",
            ));
        }

        total_bytes = total_bytes.saturating_add(variable.name.len());
        match (&variable.value, &variable.credential_ref) {
            (Some(value), None) => {
                validate_optional_launch_text(
                    "environment.value",
                    value,
                    MAX_LAUNCH_ENVIRONMENT_VALUE_BYTES,
                )?;
                total_bytes = total_bytes.saturating_add(value.len());
            }
            (None, Some(credential_ref)) => {
                validate_required_launch_text(
                    "environment.credentialRef",
                    credential_ref,
                    MAX_CREDENTIAL_REFERENCE_BYTES,
                )?;
                total_bytes = total_bytes.saturating_add(credential_ref.len());
            }
            _ => {
                return Err(invalid_launch_profile(
                    "environment",
                    "value and credentialRef must be strictly mutually exclusive",
                ));
            }
        }
    }
    if total_bytes > MAX_LAUNCH_ENVIRONMENT_TOTAL_BYTES {
        return Err(invalid_launch_profile(
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

#[cfg(target_os = "windows")]
fn environment_name_key(name: &str) -> StorageResult<String> {
    windows_comparison_key(name).map_err(|_| {
        invalid_launch_profile(
            "environment.name",
            "could not be mapped with Windows invariant casing",
        )
    })
}

#[cfg(not(target_os = "windows"))]
fn environment_name_key(name: &str) -> StorageResult<String> {
    Ok(name.to_owned())
}

fn validate_required_launch_text(
    field: &'static str,
    value: &str,
    maximum_bytes: usize,
) -> StorageResult<()> {
    validate_optional_launch_text(field, value, maximum_bytes)?;
    if value.trim().is_empty() {
        return Err(invalid_launch_profile(field, "must not be empty"));
    }
    Ok(())
}

fn validate_optional_launch_text(
    field: &'static str,
    value: &str,
    maximum_bytes: usize,
) -> StorageResult<()> {
    if value.len() > maximum_bytes {
        return Err(invalid_launch_profile(
            field,
            "exceeds the supported length",
        ));
    }
    if value.contains('\0') {
        return Err(invalid_launch_profile(field, "must not contain NUL"));
    }
    Ok(())
}

fn invalid_launch_profile(field: &'static str, reason: &'static str) -> domain::AppError {
    let mut error = domain::AppError::new(
        domain::ErrorCode::InvalidArgument,
        "Launch profile is invalid",
    );
    error.details.insert("field".to_owned(), field.to_owned());
    error.details.insert("reason".to_owned(), reason.to_owned());
    error
}

fn invalid_launch_profile_page(field: &'static str, reason: &'static str) -> domain::AppError {
    let mut error = domain::AppError::new(
        domain::ErrorCode::InvalidArgument,
        "Launch profile page request is invalid",
    );
    error.details.insert("field".to_owned(), field.to_owned());
    error.details.insert("reason".to_owned(), reason.to_owned());
    error
}

fn require_launch_profile_version(
    id: &str,
    expected_updated_at: &str,
    actual_updated_at: &str,
) -> StorageResult<()> {
    if expected_updated_at == actual_updated_at {
        Ok(())
    } else {
        Err(launch_profile_version_conflict(
            id,
            expected_updated_at,
            actual_updated_at,
        ))
    }
}

async fn validate_launch_profile_relations(
    connection: &mut SqliteConnection,
    profile: &LaunchProfile,
    inserting: bool,
) -> StorageResult<()> {
    if let Some(project_id) = &profile.project_id {
        let project_exists =
            sqlx::query_scalar::<_, i64>("SELECT EXISTS(SELECT 1 FROM projects WHERE id = ?)")
                .bind(project_id)
                .fetch_one(&mut *connection)
                .await
                .map_err(|error| storage_error("validate launch profile project", error))?
                != 0;
        if !project_exists {
            return Err(not_found("project", project_id));
        }
    }

    if inserting {
        let id_exists = sqlx::query_scalar::<_, i64>(
            "SELECT EXISTS(SELECT 1 FROM launch_profiles WHERE id = ?)",
        )
        .bind(&profile.id)
        .fetch_one(&mut *connection)
        .await
        .map_err(|error| storage_error("validate launch profile identity", error))?
            != 0;
        if id_exists {
            return Err(launch_profile_conflict(
                &profile.id,
                "id",
                "a launch profile with this ID already exists",
            ));
        }
    }

    if let Some(project_id) = &profile.project_id {
        let name_exists = sqlx::query_scalar::<_, i64>(
            "SELECT EXISTS(SELECT 1 FROM launch_profiles \
             WHERE project_id = ? AND name = ? AND id <> ?)",
        )
        .bind(project_id)
        .bind(&profile.name)
        .bind(&profile.id)
        .fetch_one(connection)
        .await
        .map_err(|error| storage_error("validate launch profile name", error))?
            != 0;
        if name_exists {
            return Err(launch_profile_conflict(
                &profile.id,
                "name",
                "a launch profile with this name already exists in the project",
            ));
        }
    }
    Ok(())
}

fn launch_profile_conflict(id: &str, field: &'static str, reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Conflict,
        "Launch profile conflicts with an existing profile",
    );
    error.details.insert("profileId".into(), id.into());
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn launch_profile_version_conflict(
    id: &str,
    expected_updated_at: &str,
    actual_updated_at: &str,
) -> domain::AppError {
    let mut error = domain::AppError::new(
        domain::ErrorCode::Conflict,
        "Launch profile was modified by another operation",
    );
    error.details.insert("profileId".to_owned(), id.to_owned());
    error.details.insert(
        "expectedUpdatedAt".to_owned(),
        expected_updated_at.to_owned(),
    );
    error
        .details
        .insert("actualUpdatedAt".to_owned(), actual_updated_at.to_owned());
    error
}

fn validate_project(project: &Project, trusted_root: &NormalizedProjectRoot) -> StorageResult<()> {
    validate_project_text("id", &project.id, MAX_PROJECT_ID_BYTES, true)?;
    validate_project_text("name", &project.name, MAX_PROJECT_NAME_BYTES, true)?;
    validate_project_text(
        "rootDirectory",
        &project.root_directory,
        MAX_PROJECT_PATH_BYTES,
        false,
    )?;
    validate_project_text(
        "normalizedPath",
        &project.normalized_path,
        MAX_NORMALIZED_PROJECT_PATH_BYTES,
        false,
    )?;
    validate_project_text(
        "createdAt",
        &project.created_at,
        MAX_PROJECT_TIMESTAMP_BYTES,
        true,
    )?;
    validate_project_text(
        "updatedAt",
        &project.updated_at,
        MAX_PROJECT_TIMESTAMP_BYTES,
        true,
    )?;

    if project.root_directory != trusted_root.canonical_root_directory() {
        return Err(invalid_project(
            "rootDirectory",
            "must exactly match the platform-normalized project root",
        ));
    }
    if project.normalized_path != trusted_root.normalized_path().to_storage_string() {
        return Err(invalid_project(
            "normalizedPath",
            "must exactly match the platform-normalized path key",
        ));
    }

    let normalized =
        NormalizedPathKey::from_storage_string(&project.normalized_path).map_err(|_| {
            invalid_project(
                "normalizedPath",
                "must be a canonical versioned mtpk1 path key",
            )
        })?;
    if normalized
        .components()
        .iter()
        .any(|component| component.contains('\0'))
    {
        return Err(invalid_project(
            "normalizedPath",
            "must not contain NUL path components",
        ));
    }
    if &normalized != trusted_root.normalized_path() {
        return Err(invalid_project(
            "normalizedPath",
            "does not match the trusted platform-normalized path key",
        ));
    }
    validate_project_platform_path(&project.root_directory, &normalized)
}

fn validate_project_text(
    field: &'static str,
    value: &str,
    maximum_bytes: usize,
    reject_whitespace_only: bool,
) -> StorageResult<()> {
    if value.is_empty() || (reject_whitespace_only && value.trim().is_empty()) {
        return Err(invalid_project(field, "must not be empty"));
    }
    if value.len() > maximum_bytes {
        return Err(invalid_project(field, "exceeds the supported length"));
    }
    if value.contains('\0') {
        return Err(invalid_project(field, "must not contain NUL"));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
enum RawProjectRoot {
    Drive(char),
    Unc { server: String, share: String },
}

#[cfg(target_os = "windows")]
struct RawWindowsProjectPath {
    root: RawProjectRoot,
    components: Vec<String>,
}

#[cfg(target_os = "windows")]
fn parse_raw_project_path(value: &str) -> Option<RawWindowsProjectPath> {
    if value.is_empty() || value.len() > MAX_PROJECT_PATH_BYTES || value.contains('\0') {
        return None;
    }
    if starts_with_ascii_case(value, "\\\\.\\") {
        return None;
    }
    if let Some(tail) = strip_ascii_case_prefix(value, "\\\\?\\") {
        if starts_with_ascii_case(tail, "GLOBALROOT\\") {
            return None;
        }
        if let Some(unc_tail) = strip_ascii_case_prefix(tail, "UNC\\") {
            let (root, component_tail) = parse_unc_path_text(unc_tail)?;
            return Some(RawWindowsProjectPath {
                root,
                components: parse_windows_components(component_tail)?,
            });
        }
        let (root, component_tail) = parse_drive_path_text(tail)?;
        return Some(RawWindowsProjectPath {
            root,
            components: parse_windows_components(component_tail)?,
        });
    }
    if let Some((root, component_tail)) = parse_drive_path_text(value) {
        return Some(RawWindowsProjectPath {
            root,
            components: parse_windows_components(component_tail)?,
        });
    }
    let (root, component_tail) = value.strip_prefix("\\\\").and_then(parse_unc_path_text)?;
    Some(RawWindowsProjectPath {
        root,
        components: parse_windows_components(component_tail)?,
    })
}

#[cfg(target_os = "windows")]
fn parse_drive_path_text(value: &str) -> Option<(RawProjectRoot, &str)> {
    let bytes = value.as_bytes();
    (bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/'))
    .then(|| {
        (
            RawProjectRoot::Drive((bytes[0] as char).to_ascii_uppercase()),
            &value[3..],
        )
    })
}

#[cfg(target_os = "windows")]
fn parse_unc_path_text(value: &str) -> Option<(RawProjectRoot, &str)> {
    let server_end = value.find(['\\', '/'])?;
    let server = &value[..server_end];
    let share_and_tail = &value[server_end + 1..];
    let share_end = share_and_tail
        .find(['\\', '/'])
        .unwrap_or(share_and_tail.len());
    let share = &share_and_tail[..share_end];
    if server.is_empty()
        || share.is_empty()
        || server.contains('\0')
        || share.contains('\0')
        || matches!(
            server.to_ascii_uppercase().as_str(),
            "." | "?" | "GLOBALROOT"
        )
    {
        return None;
    }
    let component_tail = if share_end == share_and_tail.len() {
        ""
    } else {
        &share_and_tail[share_end + 1..]
    };
    Some((
        RawProjectRoot::Unc {
            server: server.to_owned(),
            share: share.to_owned(),
        },
        component_tail,
    ))
}

#[cfg(target_os = "windows")]
fn parse_windows_components(value: &str) -> Option<Vec<String>> {
    if value.is_empty() {
        return Some(Vec::new());
    }
    let value = value
        .strip_suffix('\\')
        .or_else(|| value.strip_suffix('/'))
        .unwrap_or(value);
    if value.is_empty() {
        return Some(Vec::new());
    }
    let components = value.split(['\\', '/']).collect::<Vec<_>>();
    (components.len() <= MAX_PROJECT_ANCESTOR_DEPTH
        && components.iter().all(|component| {
            !component.is_empty()
                && *component != "."
                && *component != ".."
                && !component.contains('\0')
        }))
    .then(|| {
        components
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    })
}

#[cfg(target_os = "windows")]
fn starts_with_ascii_case(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

#[cfg(target_os = "windows")]
fn strip_ascii_case_prefix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    starts_with_ascii_case(value, prefix).then(|| &value[prefix.len()..])
}

#[cfg(target_os = "windows")]
fn validate_project_platform_path(
    root_directory: &str,
    normalized: &NormalizedPathKey,
) -> StorageResult<()> {
    let Some(raw_path) = parse_raw_project_path(root_directory) else {
        return Err(invalid_project(
            "rootDirectory",
            "must be an absolute drive or UNC path without a device namespace",
        ));
    };
    validate_windows_normalized_key(normalized)?;
    let root_matches = match (&raw_path.root, normalized.root()) {
        (RawProjectRoot::Drive(raw), NormalizedPathRoot::WindowsDrive(key)) => raw == key,
        (
            RawProjectRoot::Unc {
                server: raw_server,
                share: raw_share,
            },
            NormalizedPathRoot::WindowsUnc {
                server: key_server,
                share: key_share,
            },
        ) => {
            windows_comparison_key(raw_server)? == *key_server
                && windows_comparison_key(raw_share)? == *key_share
        }
        _ => false,
    };
    let raw_components = raw_path
        .components
        .iter()
        .map(|component| windows_comparison_key(component))
        .collect::<StorageResult<Vec<_>>>()?;
    if !root_matches || raw_components.as_slice() != normalized.components() {
        return Err(invalid_project(
            "normalizedPath",
            "must match the canonical Windows root and every comparison component",
        ));
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn validate_windows_normalized_key(normalized: &NormalizedPathKey) -> StorageResult<()> {
    match normalized.root() {
        NormalizedPathRoot::WindowsDrive(drive) if drive.is_ascii_uppercase() => {}
        NormalizedPathRoot::WindowsDrive(_) => {
            return Err(invalid_project(
                "normalizedPath",
                "drive comparison key must use canonical ASCII casing",
            ));
        }
        NormalizedPathRoot::WindowsUnc { server, share } => {
            validate_invariant_windows_key(server)?;
            validate_invariant_windows_key(share)?;
        }
        NormalizedPathRoot::Posix => {
            return Err(invalid_project(
                "normalizedPath",
                "must contain a Windows drive or UNC root on Windows",
            ));
        }
    }
    for component in normalized.components() {
        validate_invariant_windows_key(component)?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn validate_invariant_windows_key(value: &str) -> StorageResult<()> {
    if windows_comparison_key(value)? == value {
        Ok(())
    } else {
        Err(invalid_project(
            "normalizedPath",
            "Windows path comparison keys must use invariant uppercase casing",
        ))
    }
}

#[cfg(target_os = "windows")]
fn windows_comparison_key(value: &str) -> StorageResult<String> {
    if value.is_empty() || value.len() > MAX_PROJECT_PATH_BYTES || value.contains('\0') {
        return Err(invalid_project(
            "normalizedPath",
            "path component exceeds the Windows comparison boundary",
        ));
    }
    let source = value.encode_utf16().collect::<Vec<_>>();
    if source.is_empty() || source.len() > MAX_PROJECT_PATH_BYTES {
        return Err(invalid_project(
            "normalizedPath",
            "path component exceeds the Windows UTF-16 boundary",
        ));
    }
    // Match the locale-independent comparison key used by platform-windows.
    // Unicode normalization is intentionally not applied.
    let required = unsafe {
        LCMapStringEx(
            LOCALE_NAME_INVARIANT,
            LCMAP_UPPERCASE,
            &source,
            None,
            None,
            None,
            LPARAM(0),
        )
    };
    let required = usize::try_from(required)
        .ok()
        .filter(|required| *required > 0 && *required <= MAX_PROJECT_PATH_BYTES)
        .ok_or_else(|| {
            invalid_project(
                "normalizedPath",
                "path component could not be mapped with Windows invariant casing",
            )
        })?;
    let mut mapped = vec![0_u16; required];
    let actual = unsafe {
        LCMapStringEx(
            LOCALE_NAME_INVARIANT,
            LCMAP_UPPERCASE,
            &source,
            Some(&mut mapped),
            None,
            None,
            LPARAM(0),
        )
    };
    if usize::try_from(actual).ok() != Some(required) {
        return Err(invalid_project(
            "normalizedPath",
            "Windows invariant case mapping returned an inconsistent length",
        ));
    }
    String::from_utf16(&mapped)
        .ok()
        .filter(|mapped| !mapped.contains('\0'))
        .ok_or_else(|| {
            invalid_project(
                "normalizedPath",
                "Windows invariant case mapping was not losslessly representable",
            )
        })
}

#[cfg(target_os = "macos")]
fn validate_project_platform_path(
    root_directory: &str,
    normalized: &NormalizedPathKey,
) -> StorageResult<()> {
    let Some(components) = canonical_posix_components(root_directory) else {
        return Err(invalid_project(
            "rootDirectory",
            "must be a canonical absolute POSIX display path without NUL",
        ));
    };
    match normalized.root() {
        NormalizedPathRoot::Posix if components.as_slice() == normalized.components() => Ok(()),
        NormalizedPathRoot::Posix => Err(invalid_project(
            "normalizedPath",
            "must match every canonical POSIX path component",
        )),
        NormalizedPathRoot::WindowsDrive(_) | NormalizedPathRoot::WindowsUnc { .. } => Err(
            invalid_project("normalizedPath", "must contain a POSIX root on macOS"),
        ),
    }
}

#[cfg(target_os = "macos")]
fn canonical_posix_components(value: &str) -> Option<Vec<String>> {
    if value.is_empty()
        || value.len() > MAX_PROJECT_PATH_BYTES
        || value.contains('\0')
        || !Path::new(value).is_absolute()
    {
        return None;
    }
    let mut saw_root = false;
    let mut components = Vec::new();
    for component in Path::new(value).components() {
        match component {
            std::path::Component::RootDir if !saw_root => saw_root = true,
            std::path::Component::Normal(component) => {
                let Some(component) = component.to_str() else {
                    return None;
                };
                components.push(component.to_owned());
            }
            _ => return None,
        }
    }
    if !saw_root || components.len() > MAX_PROJECT_ANCESTOR_DEPTH {
        return None;
    }
    let canonical = if components.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", components.join("/"))
    };
    (canonical == value).then_some(components)
}

#[cfg(not(any(target_os = "windows", target_os = "macos")))]
fn validate_project_platform_path(
    _root_directory: &str,
    _normalized: &NormalizedPathKey,
) -> StorageResult<()> {
    Err(invalid_project(
        "normalizedPath",
        "project paths are not supported on this platform",
    ))
}

fn invalid_project(field: &'static str, reason: &'static str) -> domain::AppError {
    let mut error = domain::AppError::new(domain::ErrorCode::InvalidArgument, "Project is invalid");
    error.details.insert("field".to_owned(), field.to_owned());
    error.details.insert("reason".to_owned(), reason.to_owned());
    error
}

fn validate_classification_rule(rule: &ClassificationRule) -> StorageResult<()> {
    if rule.id.trim().is_empty() {
        return Err(invalid_classification_rule(
            "id",
            "must not be empty or whitespace",
        ));
    }
    if !matches!(
        rule.rule_type.as_str(),
        "EXECUTABLE_NAME_EXACT"
            | "EXECUTABLE_PATH_EXACT"
            | "COMMAND_LINE_CONTAINS"
            | "WORKING_DIRECTORY_PREFIX"
    ) {
        return Err(invalid_classification_rule(
            "ruleType",
            "must be a supported classification rule type",
        ));
    }
    if rule.pattern.trim().is_empty() {
        return Err(invalid_classification_rule(
            "pattern",
            "must not be empty or whitespace",
        ));
    }
    if rule.created_at.is_empty() {
        return Err(invalid_classification_rule(
            "createdAt",
            "must not be empty",
        ));
    }
    if rule.updated_at.is_empty() {
        return Err(invalid_classification_rule(
            "updatedAt",
            "must not be empty",
        ));
    }
    match rule.action.as_str() {
        "INCLUDE" | "EXCLUDE" if rule.project_id.is_some() => Err(invalid_classification_rule(
            "projectId",
            "must be absent for INCLUDE and EXCLUDE actions",
        )),
        "INCLUDE" | "EXCLUDE" => Ok(()),
        "ASSIGN_PROJECT" => match rule.project_id.as_deref() {
            Some(project_id) if !project_id.trim().is_empty() => Ok(()),
            _ => Err(invalid_classification_rule(
                "projectId",
                "must identify a project for ASSIGN_PROJECT actions",
            )),
        },
        _ => Err(invalid_classification_rule(
            "action",
            "must be INCLUDE, EXCLUDE, or ASSIGN_PROJECT",
        )),
    }
}

fn invalid_classification_rule(field: &'static str, reason: &'static str) -> domain::AppError {
    let mut error = domain::AppError::new(
        domain::ErrorCode::InvalidArgument,
        "Classification rule is invalid",
    );
    error.details.insert("field".to_owned(), field.to_owned());
    error.details.insert("reason".to_owned(), reason.to_owned());
    error
}

fn invalid_profile_environment(expected: &str, actual: &str) -> domain::AppError {
    let mut error = domain::AppError::new(
        domain::ErrorCode::InvalidArgument,
        "Environment entry belongs to another launch profile",
    );
    error
        .details
        .insert("expectedProfileId".to_owned(), expected.to_owned());
    error
        .details
        .insert("actualProfileId".to_owned(), actual.to_owned());
    error
}

fn run_identity_already_bound(run_id: &str) -> domain::AppError {
    let mut error = domain::AppError::new(
        domain::ErrorCode::Conflict,
        "Run process identity is already bound",
    );
    error.details.insert("runId".to_owned(), run_id.to_owned());
    error
}

fn audit_run_mismatch(run_id: &str, audit_run_id: Option<&str>) -> domain::AppError {
    let mut error = domain::AppError::new(
        domain::ErrorCode::InvalidArgument,
        "Audit event does not belong to the updated run",
    );
    error.details.insert("runId".to_owned(), run_id.to_owned());
    error.details.insert(
        "auditRunIdPresent".to_owned(),
        audit_run_id.is_some().to_string(),
    );
    error
}
