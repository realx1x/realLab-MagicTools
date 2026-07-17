//! SQLite persistence owned exclusively by the Supervisor process.
//!
//! [`SupervisorRepository`] is intentionally not cloneable and every write
//! requires exclusive access. The Tauri bridge must not depend on this crate.
//! Callers must provide a [`PrivateDatabasePath`] capability resolved by this
//! crate. Arbitrary filesystem paths cannot cross the repository boundary.

mod database_path;
mod diagnostics_contract;
mod error;
mod exit_contract;
mod history_contract;
mod migration_recovery;
mod models;
mod platform;
mod profile_contract;
mod project_rule_contract;
mod recovery_contract;
mod repository;
mod retention_contract;
mod run_contract;
mod stop_contract;

pub use database_path::PrivateDatabasePath;
pub use diagnostics_contract::{DiagnosticDatabaseSummary, DiagnosticRunStateCounts};
pub use exit_contract::{
    MANAGED_EXIT_METHOD, MAX_MANAGED_EXIT_ACTIVE_RUNS, ManagedExitActiveRun,
    ManagedExitMemberAction, ManagedExitOperation, ManagedExitOperationMember,
};
pub use models::AppSetting;
pub(crate) use models::{ClassificationRule, Project};
pub use profile_contract::{ProfileSecretCredential, launch_profile_save_request_hmac_sha256};
pub use project_rule_contract::PreparedCatalogMutation;
pub use recovery_contract::{
    MANAGED_RUN_RECOVERY_BATCH_SIZE, ManagedRunRecoveryCandidate, ManagedRunRecoveryOutcome,
};
pub use repository::{MAX_AUDIT_RETENTION_DELETE_BATCH_SIZE, SupervisorRepository};
pub use retention_contract::{
    MAX_MANAGED_RUN_LOG_RETENTION_PAGE_SIZE, ManagedRunLogRetentionCandidate,
    ManagedRunLogRetentionCursor,
};
pub use run_contract::{
    CURRENT_MANAGED_LOG_REDACTION_VERSION, LaunchFailureStage, ManagedRunControlGroup,
    ManagedRunRecord,
};
pub use stop_contract::{ManagedStopBeginDecision, ManagedStopCompletion, ManagedStopRequest};

pub type StorageResult<T> = Result<T, domain::AppError>;
