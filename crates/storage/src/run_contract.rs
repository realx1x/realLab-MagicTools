use std::path::Path;

use domain::{
    AppError, ErrorCode, LaunchEnvironmentValue, LaunchProfile, ProcessInstanceKey, RunState,
};
use platform_common::credentials::{CredentialReference, CredentialSlot};

use crate::error::storage_error;
use crate::models::Run;
use crate::{StorageResult, SupervisorRepository};

pub const CURRENT_MANAGED_LOG_REDACTION_VERSION: i64 = 1;

const MAX_RUN_ID_BYTES: usize = 256;
const MAX_RUN_LOG_DIRECTORY_BYTES: usize = 32 * 1_024;
const MAX_RUN_BOOT_ID_BYTES: usize = 256;
const MAX_RUN_NATIVE_START_TIME_BYTES: usize = 128;
const MAX_RUN_PROFILE_SNAPSHOT_BYTES: usize = 256 * 1_024;

const RUN_SELECT_BY_PROCESS_INSTANCE_KEY: &str = "SELECT id, profile_id, profile_snapshot_json, process_boot_id, process_pid, \
     process_native_start_time, process_group_id, state, exit_code, exit_signal, exit_summary, \
     stop_method, log_directory, log_redaction_version, recovery_state, started_at, updated_at, \
     ended_at, logs_deletion_started_at, logs_deleted_at FROM runs \
     WHERE process_boot_id = ? AND process_pid = ? AND process_native_start_time = ?";

/// Closed launch stages safe to persist without including commands,
/// environment values, credential references, paths, or platform messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LaunchFailureStage {
    CredentialResolution,
    ExecutableResolution,
    JobCreation,
    JobConfiguration,
    ProcessCreation,
    JobAssignment,
    IdentityRead,
    IdentityPersistence,
    ProcessResume,
    RunningPersistence,
    LogPreparation,
    Cleanup,
}

impl LaunchFailureStage {
    fn storage_summary(self) -> &'static str {
        match self {
            Self::CredentialResolution => "launch:credentialResolution",
            Self::ExecutableResolution => "launch:executableResolution",
            Self::JobCreation => "launch:jobCreation",
            Self::JobConfiguration => "launch:jobConfiguration",
            Self::ProcessCreation => "launch:processCreation",
            Self::JobAssignment => "launch:jobAssignment",
            Self::IdentityRead => "launch:identityRead",
            Self::IdentityPersistence => "launch:identityPersistence",
            Self::ProcessResume => "launch:processResume",
            Self::RunningPersistence => "launch:runningPersistence",
            Self::LogPreparation => "launch:logPreparation",
            Self::Cleanup => "launch:cleanup",
        }
    }
}

/// Platform lifecycle boundary associated with a managed process identity.
/// Windows ownership remains in a Job handle and therefore has no persisted
/// numeric process-group identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedRunControlGroup {
    WindowsJob,
    #[non_exhaustive]
    MacOsProcessGroup {
        process_group_id: u32,
    },
}

impl ManagedRunControlGroup {
    pub const fn windows_job() -> Self {
        Self::WindowsJob
    }

    pub fn macos_process_group(process_group_id: u32) -> Result<Self, AppError> {
        validate_process_group_id(process_group_id)?;
        Ok(Self::MacOsProcessGroup { process_group_id })
    }

    fn persisted_process_group_id(self) -> StorageResult<Option<u32>> {
        match self {
            Self::WindowsJob => Ok(None),
            Self::MacOsProcessGroup { process_group_id } => {
                validate_process_group_id(process_group_id)?;
                Ok(Some(process_group_id))
            }
        }
    }
}

/// Typed representation of a durable run. The profile snapshot contains only
/// ordinary environment values and opaque credential references.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedRunRecord {
    pub id: String,
    pub profile_id: Option<String>,
    pub profile_snapshot: LaunchProfile,
    pub process_instance_key: Option<ProcessInstanceKey>,
    pub process_group_id: Option<u32>,
    pub state: RunState,
    pub exit_code: Option<i64>,
    pub exit_signal: Option<String>,
    pub exit_summary: Option<String>,
    pub stop_method: Option<String>,
    pub log_directory: String,
    pub log_redaction_version: i64,
    pub recovery_state: Option<RunState>,
    pub started_at: String,
    pub updated_at: String,
    pub ended_at: Option<String>,
    pub logs_deletion_started_at: Option<String>,
    pub logs_deleted_at: Option<String>,
}

impl SupervisorRepository {
    /// Creates the durable launch intent before any credential is read or
    /// process is created. Identity, state, timestamps, and paths are supplied
    /// only by the Supervisor boundary, never by an IPC launch payload.
    pub async fn create_starting_run(
        &mut self,
        run_id: &str,
        profile: &LaunchProfile,
        log_directory: &str,
        started_at: &str,
    ) -> StorageResult<ManagedRunRecord> {
        validate_required_text("runId", run_id, MAX_RUN_ID_BYTES)?;
        validate_input_timestamp("startedAt", started_at)?;
        validate_log_directory(log_directory)?;
        lifecycle::validate_launch_profile(profile)?;
        validate_snapshot_credential_references(profile, false)?;

        let current_profile = self.launch_profile(&profile.id).await?;
        if current_profile != *profile {
            return Err(profile_snapshot_conflict(profile, &current_profile));
        }
        match self.run(run_id).await {
            Ok(_) => return Err(run_id_conflict(run_id)),
            Err(error) if error.code == ErrorCode::NotFound => {}
            Err(error) => return Err(error),
        }

        let profile_snapshot_json = canonical_profile_snapshot(profile)?;
        let row = Run {
            id: run_id.to_owned(),
            profile_id: Some(profile.id.clone()),
            profile_snapshot_json,
            process_boot_id: None,
            process_pid: None,
            process_native_start_time: None,
            process_group_id: None,
            state: run_state_to_storage(RunState::Starting).to_owned(),
            exit_code: None,
            exit_signal: None,
            exit_summary: None,
            stop_method: None,
            log_directory: log_directory.to_owned(),
            log_redaction_version: CURRENT_MANAGED_LOG_REDACTION_VERSION,
            recovery_state: None,
            started_at: started_at.to_owned(),
            updated_at: started_at.to_owned(),
            ended_at: None,
            logs_deletion_started_at: None,
            logs_deleted_at: None,
        };
        stored_run_to_managed(row.clone())?;
        self.insert_run(&row).await?;
        self.managed_run(run_id).await
    }

    /// Binds the identity and platform control group obtained from the live
    /// suspended process. The underlying SQL requires an unbound `STARTING`
    /// row and changes both values in the same compare-and-swap.
    pub async fn bind_starting_run_identity_and_control(
        &mut self,
        run_id: &str,
        instance_key: &ProcessInstanceKey,
        control_group: ManagedRunControlGroup,
        updated_at: &str,
    ) -> StorageResult<ManagedRunRecord> {
        validate_required_text("runId", run_id, MAX_RUN_ID_BYTES)?;
        validate_input_timestamp("updatedAt", updated_at)?;
        validate_process_instance_key(instance_key)?;
        let process_group_id = control_group.persisted_process_group_id()?;
        if process_group_id.is_some_and(|process_group_id| process_group_id != instance_key.pid) {
            return Err(invalid_run_field(
                "processGroupId",
                "must equal the dedicated process-group leader PID",
            ));
        }

        let current = self.run(run_id).await?;
        let current_record = stored_run_to_managed(current.clone())?;
        if current.state != run_state_to_storage(RunState::Starting)
            || current.process_boot_id.is_some()
            || current.process_pid.is_some()
            || current.process_native_start_time.is_some()
            || current.process_group_id.is_some()
        {
            return Err(starting_run_conflict(
                run_id,
                &current.state,
                "identity or control group is already bound, or the run is no longer Starting",
            ));
        }
        validate_strictly_later_timestamp("updatedAt", updated_at, &current_record.updated_at)?;
        let mut prospective = current.clone();
        prospective.process_boot_id = Some(instance_key.boot_id.clone());
        prospective.process_pid = Some(i64::from(instance_key.pid));
        prospective.process_native_start_time = Some(instance_key.native_start_time.clone());
        prospective.process_group_id = process_group_id.map(i64::from);
        prospective.updated_at = updated_at.to_owned();
        stored_run_to_managed(prospective)?;
        self.bind_run_process_identity_and_control(
            run_id,
            instance_key,
            process_group_id,
            &current.updated_at,
            updated_at,
        )
        .await?;
        self.managed_run(run_id).await
    }

    /// Marks a suspended, identity-bound launch as running. The SQL compare
    /// and swap refuses unbound or non-Starting rows.
    pub async fn mark_starting_run_running(
        &mut self,
        run_id: &str,
        updated_at: &str,
    ) -> StorageResult<ManagedRunRecord> {
        self.transition_starting_launch(run_id, RunState::Running, None, updated_at, None, true)
            .await
    }

    /// Records a launch failure only after the platform layer has confirmed
    /// that no launched process remains alive.
    pub async fn mark_starting_run_failed(
        &mut self,
        run_id: &str,
        stage: LaunchFailureStage,
        updated_at: &str,
    ) -> StorageResult<ManagedRunRecord> {
        self.transition_starting_launch(
            run_id,
            RunState::Failed,
            Some(stage),
            updated_at,
            Some(updated_at),
            false,
        )
        .await
    }

    /// Records loss of a provable cleanup boundary without claiming that the
    /// process ended. Any identity already bound to the run remains immutable.
    pub async fn mark_starting_run_orphaned(
        &mut self,
        run_id: &str,
        stage: LaunchFailureStage,
        updated_at: &str,
    ) -> StorageResult<ManagedRunRecord> {
        self.transition_starting_launch(
            run_id,
            RunState::Orphaned,
            Some(stage),
            updated_at,
            None,
            false,
        )
        .await
    }

    /// Records a natural exit observed for a fully identity-bound running
    /// process. Stop-requested, stopping, and terminal states cannot be
    /// overwritten. Replaying the exact same unknown-status exit is idempotent.
    pub async fn mark_running_run_exited(
        &mut self,
        run_id: &str,
        ended_at: &str,
    ) -> StorageResult<ManagedRunRecord> {
        validate_required_text("runId", run_id, MAX_RUN_ID_BYTES)?;
        validate_input_timestamp("endedAt", ended_at)?;

        let current = self.run(run_id).await?;
        let current_record = stored_run_to_managed(current.clone())?;
        if is_identical_natural_exit(&current, ended_at) {
            return Ok(current_record);
        }
        if current_record.state != RunState::Running {
            return Err(running_run_exit_conflict(
                run_id,
                &current.state,
                "the run is no longer Running",
            ));
        }
        validate_strictly_later_timestamp("endedAt", ended_at, &current_record.updated_at)?;
        let mut prospective = current.clone();
        prospective.state = run_state_to_storage(RunState::Exited).to_owned();
        prospective.exit_code = None;
        prospective.exit_signal = None;
        prospective.updated_at = ended_at.to_owned();
        prospective.ended_at = Some(ended_at.to_owned());
        stored_run_to_managed(prospective)?;

        let (row, transitioned) = self
            .transition_running_run_to_exited(run_id, &current.updated_at, ended_at)
            .await?;
        if transitioned || is_identical_natural_exit(&row, ended_at) {
            return stored_run_to_managed(row);
        }

        let reason = if row.state == run_state_to_storage(RunState::Running) {
            if row.process_boot_id.is_none()
                || row.process_pid.is_none()
                || row.process_native_start_time.is_none()
            {
                "the Running run does not have a complete process identity"
            } else if row.ended_at.is_some() {
                "the Running run already has an end timestamp"
            } else if row.exit_code.is_some() || row.exit_signal.is_some() {
                "the Running run already has exit information"
            } else {
                "the Running run no longer matches the required exit transition"
            }
        } else if row.state == run_state_to_storage(RunState::Exited) {
            "the existing Exited result differs from the requested natural exit"
        } else {
            "the run is no longer Running"
        };
        Err(running_run_exit_conflict(run_id, &row.state, reason))
    }

    pub async fn managed_run(&self, run_id: &str) -> StorageResult<ManagedRunRecord> {
        validate_required_text("runId", run_id, MAX_RUN_ID_BYTES)?;
        stored_run_to_managed(self.run(run_id).await?)
    }

    /// Looks up the immutable run association for one complete process
    /// identity. The partial unique index on these three columns guarantees at
    /// most one result; no PID-only fallback is permitted.
    pub async fn managed_run_by_process_instance_key(
        &self,
        instance_key: &ProcessInstanceKey,
    ) -> StorageResult<Option<ManagedRunRecord>> {
        lifecycle::validate_process_instance_key(instance_key)?;
        let row = sqlx::query_as::<_, Run>(RUN_SELECT_BY_PROCESS_INSTANCE_KEY)
            .bind(&instance_key.boot_id)
            .bind(i64::from(instance_key.pid))
            .bind(&instance_key.native_start_time)
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| storage_error("read run by process instance identity", error))?;
        row.map(stored_run_to_managed).transpose()
    }

    async fn transition_starting_launch(
        &mut self,
        run_id: &str,
        next_state: RunState,
        failure_stage: Option<LaunchFailureStage>,
        updated_at: &str,
        ended_at: Option<&str>,
        require_identity: bool,
    ) -> StorageResult<ManagedRunRecord> {
        validate_required_text("runId", run_id, MAX_RUN_ID_BYTES)?;
        validate_input_timestamp("updatedAt", updated_at)?;
        let exit_summary = failure_stage.map(LaunchFailureStage::storage_summary);
        let current = self.run(run_id).await?;
        let current_record = stored_run_to_managed(current.clone())?;
        if current_record.state != RunState::Starting {
            return Err(starting_run_conflict(
                run_id,
                &current.state,
                "the run is no longer an eligible Starting launch",
            ));
        }
        if require_identity && current_record.process_instance_key.is_none() {
            return Err(starting_run_conflict(
                run_id,
                &current.state,
                "the Starting run does not have a complete process identity",
            ));
        }
        validate_strictly_later_timestamp("updatedAt", updated_at, &current_record.updated_at)?;
        let mut prospective = current.clone();
        prospective.state = run_state_to_storage(next_state).to_owned();
        prospective.exit_summary = exit_summary.map(str::to_owned);
        prospective.updated_at = updated_at.to_owned();
        prospective.ended_at = ended_at.map(str::to_owned);
        stored_run_to_managed(prospective)?;
        let transitioned = self
            .transition_starting_run(
                run_id,
                run_state_to_storage(next_state),
                exit_summary,
                updated_at,
                ended_at,
                require_identity,
                &current.updated_at,
            )
            .await?;
        if let Some(row) = transitioned {
            return stored_run_to_managed(row);
        }
        let current = self.run(run_id).await?;
        let reason = if require_identity
            && current.state == run_state_to_storage(RunState::Starting)
            && (current.process_boot_id.is_none()
                || current.process_pid.is_none()
                || current.process_native_start_time.is_none())
        {
            "the Starting run does not have a complete process identity"
        } else {
            "the run is no longer an eligible Starting launch"
        };
        Err(starting_run_conflict(run_id, &current.state, reason))
    }
}

fn is_identical_natural_exit(row: &Run, ended_at: &str) -> bool {
    row.state == run_state_to_storage(RunState::Exited)
        && row.process_boot_id.is_some()
        && row.process_pid.is_some()
        && row.process_native_start_time.is_some()
        && row.exit_code.is_none()
        && row.exit_signal.is_none()
        && row.updated_at == ended_at
        && row.ended_at.as_deref() == Some(ended_at)
}

fn canonical_profile_snapshot(profile: &LaunchProfile) -> StorageResult<String> {
    let encoded = serde_json::to_string(profile).map_err(|error| {
        let mut result = AppError::new(
            ErrorCode::Internal,
            "server-owned launch profile snapshot could not be serialized",
        );
        result.details.insert("reason".into(), error.to_string());
        result
    })?;
    if encoded.len() > MAX_RUN_PROFILE_SNAPSHOT_BYTES {
        return Err(invalid_run_field(
            "profileSnapshot",
            "exceeds the supported encoded size",
        ));
    }
    Ok(encoded)
}

pub(crate) fn stored_run_to_managed(row: Run) -> StorageResult<ManagedRunRecord> {
    validate_stored_text("id", &row.id, MAX_RUN_ID_BYTES)?;
    validate_stored_text(
        "logDirectory",
        &row.log_directory,
        MAX_RUN_LOG_DIRECTORY_BYTES,
    )?;
    if !Path::new(&row.log_directory).is_absolute() {
        return Err(corrupt_run("logDirectory", "is not an absolute path"));
    }
    if !(0..=CURRENT_MANAGED_LOG_REDACTION_VERSION).contains(&row.log_redaction_version) {
        return Err(corrupt_run(
            "logRedactionVersion",
            "is outside the supported version range",
        ));
    }
    validate_stored_timestamp("startedAt", &row.started_at)?;
    validate_stored_timestamp("updatedAt", &row.updated_at)?;
    if let Some(ended_at) = &row.ended_at {
        validate_stored_timestamp("endedAt", ended_at)?;
    }
    if let Some(logs_deletion_started_at) = &row.logs_deletion_started_at {
        validate_stored_timestamp("logsDeletionStartedAt", logs_deletion_started_at)?;
    }
    if let Some(logs_deleted_at) = &row.logs_deleted_at {
        validate_stored_timestamp("logsDeletedAt", logs_deleted_at)?;
    }

    let profile_snapshot = serde_json::from_str::<LaunchProfile>(&row.profile_snapshot_json)
        .map_err(|error| corrupt_run("profileSnapshot", &error.to_string()))?;
    lifecycle::validate_launch_profile(&profile_snapshot)
        .map_err(|error| corrupt_run("profileSnapshot", &error.message))?;
    validate_snapshot_credential_references(&profile_snapshot, true)?;
    let canonical = canonical_profile_snapshot(&profile_snapshot)
        .map_err(|error| corrupt_run("profileSnapshot", &error.message))?;
    if canonical != row.profile_snapshot_json {
        return Err(corrupt_run(
            "profileSnapshot",
            "is not encoded in canonical form",
        ));
    }
    if row
        .profile_id
        .as_ref()
        .is_some_and(|profile_id| profile_id != &profile_snapshot.id)
    {
        return Err(corrupt_run(
            "profileId",
            "does not match the immutable profile snapshot",
        ));
    }

    let process_instance_key = match (
        row.process_boot_id,
        row.process_pid,
        row.process_native_start_time,
    ) {
        (None, None, None) => None,
        (Some(boot_id), Some(pid), Some(native_start_time)) => {
            let pid = u32::try_from(pid)
                .ok()
                .filter(|pid| *pid != 0)
                .ok_or_else(|| corrupt_run("processPid", "is outside the supported PID range"))?;
            let key = ProcessInstanceKey {
                boot_id,
                pid,
                native_start_time,
            };
            validate_process_instance_key(&key)
                .map_err(|error| corrupt_run("processInstanceKey", &error.message))?;
            Some(key)
        }
        _ => {
            return Err(corrupt_run(
                "processInstanceKey",
                "contains a partial process identity",
            ));
        }
    };
    let process_group_id = row
        .process_group_id
        .map(|process_group_id| {
            let process_group_id = u32::try_from(process_group_id).map_err(|_| {
                corrupt_run(
                    "processGroupId",
                    "is outside the supported process group range",
                )
            })?;
            validate_process_group_id(process_group_id)
                .map_err(|error| corrupt_run("processGroupId", &error.message))?;
            Ok(process_group_id)
        })
        .transpose()?;
    if let Some(process_group_id) = process_group_id {
        let instance_key = process_instance_key.as_ref().ok_or_else(|| {
            corrupt_run(
                "processGroupId",
                "is present without a complete process identity",
            )
        })?;
        if process_group_id != instance_key.pid {
            return Err(corrupt_run(
                "processGroupId",
                "does not equal the dedicated process-group leader PID",
            ));
        }
    }
    let state = run_state_from_storage(&row.state)?;
    let is_terminal = matches!(
        state,
        RunState::Exited
            | RunState::Failed
            | RunState::ExitedWhileOffline
            | RunState::IdentityMismatch
            | RunState::Orphaned
    );
    if row.logs_deletion_started_at.is_some() && !is_terminal {
        return Err(corrupt_run(
            "logsDeletionStartedAt",
            "is present on a non-terminal run",
        ));
    }
    if row.logs_deleted_at.is_some() && row.logs_deletion_started_at.is_none() {
        return Err(corrupt_run(
            "logsDeletedAt",
            "is present without a deletion-started marker",
        ));
    }
    if row.logs_deleted_at.is_some() && !is_terminal {
        return Err(corrupt_run(
            "logsDeletedAt",
            "is present on a non-terminal run",
        ));
    }
    let recovery_state = row
        .recovery_state
        .as_deref()
        .map(recovery_state_from_storage)
        .transpose()?;
    validate_stored_run_timeline(
        state,
        recovery_state,
        &row.started_at,
        &row.updated_at,
        row.ended_at.as_deref(),
    )?;
    validate_stored_log_retention_timeline(
        &row.updated_at,
        row.ended_at.as_deref(),
        row.logs_deletion_started_at.as_deref(),
        row.logs_deleted_at.as_deref(),
    )?;

    Ok(ManagedRunRecord {
        id: row.id,
        profile_id: row.profile_id,
        profile_snapshot,
        process_instance_key,
        process_group_id,
        state,
        exit_code: row.exit_code,
        exit_signal: row.exit_signal,
        exit_summary: row.exit_summary,
        stop_method: row.stop_method,
        log_directory: row.log_directory,
        log_redaction_version: row.log_redaction_version,
        recovery_state,
        started_at: row.started_at,
        updated_at: row.updated_at,
        ended_at: row.ended_at,
        logs_deletion_started_at: row.logs_deletion_started_at,
        logs_deleted_at: row.logs_deleted_at,
    })
}

fn validate_stored_timestamp(field: &'static str, value: &str) -> StorageResult<()> {
    lifecycle::validate_canonical_utc_timestamp(field, value)
        .map_err(|_| corrupt_run(field, "is not a canonical UTC timestamp"))
}

fn validate_input_timestamp(field: &'static str, value: &str) -> StorageResult<()> {
    lifecycle::validate_canonical_utc_timestamp(field, value)
}

fn validate_strictly_later_timestamp(
    field: &'static str,
    value: &str,
    previous: &str,
) -> StorageResult<()> {
    if value <= previous {
        return Err(invalid_run_field(
            field,
            "must be later than the current managed run update timestamp",
        ));
    }
    Ok(())
}

fn validate_stored_run_timeline(
    state: RunState,
    recovery_state: Option<RunState>,
    started_at: &str,
    updated_at: &str,
    ended_at: Option<&str>,
) -> StorageResult<()> {
    if updated_at < started_at {
        return Err(corrupt_run("updatedAt", "precedes the run start timestamp"));
    }
    if ended_at.is_some_and(|ended_at| ended_at < started_at || ended_at > updated_at) {
        return Err(corrupt_run(
            "endedAt",
            "does not fall between the run start and update timestamps",
        ));
    }
    let requires_ended_at = matches!(
        state,
        RunState::Exited | RunState::Failed | RunState::ExitedWhileOffline
    );
    if requires_ended_at != ended_at.is_some() {
        return Err(corrupt_run("endedAt", "does not match the run state"));
    }
    if state == RunState::Recovered && recovery_state != Some(RunState::Recovered) {
        return Err(corrupt_run(
            "recoveryState",
            "a recovered run is missing its recovery marker",
        ));
    }
    if state == RunState::ExitedWhileOffline && recovery_state != Some(RunState::ExitedWhileOffline)
    {
        return Err(corrupt_run(
            "recoveryState",
            "an offline exit is missing its recovery marker",
        ));
    }
    if let Some(recovery_state) = recovery_state {
        let compatible = match recovery_state {
            RunState::Recovered => matches!(
                state,
                RunState::Recovered
                    | RunState::StopRequested
                    | RunState::GracefulStopping
                    | RunState::ForceStopping
                    | RunState::Exited
                    | RunState::Failed
                    | RunState::IdentityMismatch
                    | RunState::Orphaned
            ),
            RunState::ExitedWhileOffline => state == RunState::ExitedWhileOffline,
            RunState::IdentityMismatch => state == RunState::IdentityMismatch,
            RunState::Orphaned => state == RunState::Orphaned,
            RunState::Starting
            | RunState::Running
            | RunState::StopRequested
            | RunState::GracefulStopping
            | RunState::ForceStopping
            | RunState::Exited
            | RunState::Failed => false,
        };
        if !compatible {
            return Err(corrupt_run("recoveryState", "does not match the run state"));
        }
    }
    Ok(())
}

fn validate_stored_log_retention_timeline(
    updated_at: &str,
    ended_at: Option<&str>,
    deletion_started_at: Option<&str>,
    deleted_at: Option<&str>,
) -> StorageResult<()> {
    let retention_timestamp = ended_at.unwrap_or(updated_at);
    if deletion_started_at.is_some_and(|value| value < retention_timestamp) {
        return Err(corrupt_run(
            "logsDeletionStartedAt",
            "precedes the terminal run retention timestamp",
        ));
    }
    if let (Some(deletion_started_at), Some(deleted_at)) = (deletion_started_at, deleted_at) {
        if deleted_at < deletion_started_at {
            return Err(corrupt_run(
                "logsDeletedAt",
                "precedes the log deletion start timestamp",
            ));
        }
    }
    Ok(())
}

fn validate_snapshot_credential_references(
    profile: &LaunchProfile,
    stored: bool,
) -> StorageResult<()> {
    for entry in &profile.input.environment {
        let LaunchEnvironmentValue::CredentialReference(value) = &entry.value else {
            continue;
        };
        let slot = CredentialSlot::new(profile.id.clone(), entry.name.clone())
            .map_err(|error| snapshot_reference_error(stored, &error.message))?;
        let reference = CredentialReference::parse(&value.credential_reference)
            .map_err(|error| snapshot_reference_error(stored, &error.message))?;
        if !reference.belongs_to(&slot) {
            return Err(snapshot_reference_error(
                stored,
                "credential reference is not bound to its profile environment slot",
            ));
        }
    }
    Ok(())
}

fn validate_process_instance_key(instance_key: &ProcessInstanceKey) -> StorageResult<()> {
    validate_required_text(
        "processInstanceKey.bootId",
        &instance_key.boot_id,
        MAX_RUN_BOOT_ID_BYTES,
    )?;
    if instance_key.pid == 0 {
        return Err(invalid_run_field(
            "processInstanceKey.pid",
            "must be a nonzero process identifier",
        ));
    }
    validate_required_text(
        "processInstanceKey.nativeStartTime",
        &instance_key.native_start_time,
        MAX_RUN_NATIVE_START_TIME_BYTES,
    )
}

fn validate_process_group_id(process_group_id: u32) -> StorageResult<()> {
    if process_group_id == 0 || process_group_id > i32::MAX as u32 {
        return Err(invalid_run_field(
            "processGroupId",
            "must be a positive process group identifier within the pid_t range",
        ));
    }
    Ok(())
}

fn validate_log_directory(value: &str) -> StorageResult<()> {
    validate_required_text("logDirectory", value, MAX_RUN_LOG_DIRECTORY_BYTES)?;
    if !Path::new(value).is_absolute() {
        return Err(invalid_run_field(
            "logDirectory",
            "must be an absolute path",
        ));
    }
    Ok(())
}

fn validate_required_text(field: &'static str, value: &str, maximum: usize) -> StorageResult<()> {
    if value.is_empty() || value.trim().is_empty() {
        return Err(invalid_run_field(field, "must not be empty or whitespace"));
    }
    if value.len() > maximum {
        return Err(invalid_run_field(field, "exceeds the supported length"));
    }
    if value.contains('\0') {
        return Err(invalid_run_field(field, "must not contain NUL"));
    }
    Ok(())
}

fn validate_stored_text(field: &'static str, value: &str, maximum: usize) -> StorageResult<()> {
    if value.is_empty() || value.trim().is_empty() || value.len() > maximum || value.contains('\0')
    {
        Err(corrupt_run(field, "contains an invalid stored value"))
    } else {
        Ok(())
    }
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
        _ => Err(corrupt_run("state", "uses an unsupported run state")),
    }
}

fn recovery_state_from_storage(value: &str) -> StorageResult<RunState> {
    let state = run_state_from_storage(value)?;
    if matches!(
        state,
        RunState::Recovered
            | RunState::ExitedWhileOffline
            | RunState::IdentityMismatch
            | RunState::Orphaned
    ) {
        Ok(state)
    } else {
        Err(corrupt_run(
            "recoveryState",
            "uses a non-recovery run state",
        ))
    }
}

fn invalid_run_field(field: &'static str, reason: &'static str) -> AppError {
    let mut error = AppError::new(ErrorCode::InvalidArgument, "managed run input is invalid");
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn corrupt_run(field: &'static str, reason: &str) -> AppError {
    let mut error = AppError::new(ErrorCode::StorageError, "stored managed run is invalid");
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn snapshot_reference_error(stored: bool, reason: &str) -> AppError {
    if stored {
        corrupt_run("profileSnapshot.environment", reason)
    } else {
        let mut error = AppError::new(
            ErrorCode::Internal,
            "server-owned launch profile contains an invalid credential reference",
        );
        error
            .details
            .insert("field".into(), "profileSnapshot.environment".into());
        error.details.insert("reason".into(), reason.into());
        error
    }
}

fn profile_snapshot_conflict(expected: &LaunchProfile, actual: &LaunchProfile) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Conflict,
        "launch profile changed before the run intent was persisted",
    );
    error
        .details
        .insert("profileId".into(), expected.id.clone());
    error
        .details
        .insert("expectedUpdatedAt".into(), expected.updated_at.clone());
    error
        .details
        .insert("actualUpdatedAt".into(), actual.updated_at.clone());
    error
}

fn run_id_conflict(run_id: &str) -> AppError {
    let mut error = AppError::new(ErrorCode::Conflict, "managed run ID already exists");
    error.details.insert("runId".into(), run_id.into());
    error
}

fn starting_run_conflict(run_id: &str, actual_state: &str, reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Conflict,
        "managed run launch state transition was rejected",
    );
    error.details.insert("runId".into(), run_id.into());
    error
        .details
        .insert("expectedState".into(), "STARTING".into());
    error
        .details
        .insert("actualState".into(), actual_state.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn running_run_exit_conflict(run_id: &str, actual_state: &str, reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::Conflict,
        "managed run natural exit transition was rejected",
    );
    error.details.insert("runId".into(), run_id.into());
    error
        .details
        .insert("expectedState".into(), "RUNNING".into());
    error
        .details
        .insert("actualState".into(), actual_state.into());
    error.details.insert("reason".into(), reason.into());
    error
}
