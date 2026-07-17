use sqlx::FromRow;

#[derive(Clone, Debug, Eq, FromRow, PartialEq)]
pub struct Project {
    pub id: String,
    pub name: String,
    pub root_directory: String,
    pub normalized_path: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Eq, FromRow, PartialEq)]
pub struct LaunchProfile {
    pub id: String,
    pub project_id: Option<String>,
    pub name: String,
    pub execution_mode: String,
    pub executable: String,
    /// A JSON array encoded as UTF-8 text.
    pub arguments_json: String,
    pub working_directory: String,
    pub shell: Option<String>,
    pub interactive: bool,
    pub stop_timeout_ms: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Eq, FromRow, PartialEq)]
pub struct LaunchProfileEnvironment {
    pub profile_id: String,
    pub name: String,
    /// An ordinary, non-secret environment value, including an empty value.
    /// This is mutually exclusive with `credential_ref` at the database
    /// boundary.
    pub value: Option<String>,
    /// An opaque system credential reference, never the secret itself.
    pub credential_ref: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchProfileWithEnvironment {
    pub profile: LaunchProfile,
    pub environment: Vec<LaunchProfileEnvironment>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchProfileCursor {
    pub name: String,
    pub id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaunchProfilePage {
    pub items: Vec<LaunchProfileWithEnvironment>,
    pub next_cursor: Option<LaunchProfileCursor>,
}

#[derive(Clone, Debug, Eq, FromRow, PartialEq)]
pub(crate) struct Run {
    pub(crate) id: String,
    pub(crate) profile_id: Option<String>,
    /// The launch configuration snapshot encoded as UTF-8 JSON text.
    pub(crate) profile_snapshot_json: String,
    pub(crate) process_boot_id: Option<String>,
    pub(crate) process_pid: Option<i64>,
    pub(crate) process_native_start_time: Option<String>,
    pub(crate) process_group_id: Option<i64>,
    pub(crate) state: String,
    pub(crate) exit_code: Option<i64>,
    pub(crate) exit_signal: Option<String>,
    pub(crate) exit_summary: Option<String>,
    pub(crate) stop_method: Option<String>,
    pub(crate) log_directory: String,
    pub(crate) log_redaction_version: i64,
    pub(crate) recovery_state: Option<String>,
    pub(crate) started_at: String,
    pub(crate) updated_at: String,
    pub(crate) ended_at: Option<String>,
    pub(crate) logs_deletion_started_at: Option<String>,
    pub(crate) logs_deleted_at: Option<String>,
}

#[derive(Clone, Debug, Eq, FromRow, PartialEq)]
pub(crate) struct ManagedStopOperationRow {
    pub(crate) operation_id: String,
    pub(crate) run_id: String,
    pub(crate) kind: String,
    pub(crate) status: String,
    pub(crate) signal_disposition: Option<String>,
    pub(crate) outcome: Option<String>,
    pub(crate) supersedes_operation_id: Option<String>,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
    pub(crate) completed_at: Option<String>,
}

#[derive(Clone, Debug, Eq, FromRow, PartialEq)]
pub struct ClassificationRule {
    pub id: String,
    pub rule_type: String,
    pub pattern: String,
    pub action: String,
    pub project_id: Option<String>,
    pub priority: i64,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Eq, FromRow, PartialEq)]
pub(crate) struct AuditEvent {
    pub id: String,
    pub run_id: Option<String>,
    pub event_type: String,
    pub summary: String,
    /// Optional structured event details encoded as UTF-8 JSON text.
    pub details_json: Option<String>,
    pub occurred_at: String,
    pub retention_until: String,
}

#[derive(Clone, Debug, Eq, FromRow, PartialEq)]
pub struct AppSetting {
    pub key: String,
    /// The setting value encoded as UTF-8 JSON text.
    pub value_json: String,
    pub updated_at: String,
}
