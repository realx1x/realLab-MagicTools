use std::fmt::{self, Debug, Formatter};
use std::fs::File;
use std::path::{Path, PathBuf};

use crate::StorageResult;

const DATABASE_FILE_NAME: &str = "supervisor.sqlite3";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DatabaseArtifact {
    Main,
    Wal,
    SharedMemory,
    Journal,
    BackupPrimary,
    BackupPrevious,
    BackupPartial,
    BackupPartialJournal,
    RestorePartial,
    MigrationState,
    MigrationStatePartial,
    MigrationLock,
}

impl DatabaseArtifact {
    pub(crate) const RECOVERY_FILES: [Self; 11] = [
        Self::Main,
        Self::Wal,
        Self::SharedMemory,
        Self::Journal,
        Self::BackupPrimary,
        Self::BackupPrevious,
        Self::BackupPartial,
        Self::BackupPartialJournal,
        Self::RestorePartial,
        Self::MigrationState,
        Self::MigrationStatePartial,
    ];

    pub(crate) const fn file_name(self) -> &'static str {
        match self {
            Self::Main => DATABASE_FILE_NAME,
            Self::Wal => "supervisor.sqlite3-wal",
            Self::SharedMemory => "supervisor.sqlite3-shm",
            Self::Journal => "supervisor.sqlite3-journal",
            Self::BackupPrimary => "migration-backup-0.sqlite3",
            Self::BackupPrevious => "migration-backup-1.sqlite3",
            Self::BackupPartial => "migration-backup.partial",
            Self::BackupPartialJournal => "migration-backup.partial-journal",
            Self::RestorePartial => "migration-restore.partial",
            Self::MigrationState => "migration-state.json",
            Self::MigrationStatePartial => "migration-state.partial",
            Self::MigrationLock => "migration.lock",
        }
    }
}

/// An unforgeable capability for the fixed current-user SQLite location.
///
/// The path cannot be supplied through RPC or deserialized from untrusted
/// input. Construction prepares and validates the platform-owned private data
/// directory before the repository is allowed to open SQLite.
pub struct PrivateDatabasePath {
    root: PathBuf,
    database: PathBuf,
}

impl PrivateDatabasePath {
    pub fn for_current_user() -> StorageResult<Self> {
        let root = crate::platform::prepare_private_database_root()?;
        crate::platform::validate_private_database_root(&root)?;
        let database = root.join(DATABASE_FILE_NAME);
        Ok(Self { root, database })
    }

    pub(crate) fn database(&self) -> &Path {
        &self.database
    }

    pub(crate) fn artifact_path(&self, artifact: DatabaseArtifact) -> PathBuf {
        self.root.join(artifact.file_name())
    }

    pub(crate) fn inspect_artifact(
        &self,
        artifact: DatabaseArtifact,
    ) -> StorageResult<Option<u64>> {
        crate::platform::inspect_database_artifact(&self.root, artifact)
    }

    pub(crate) fn open_artifact(&self, artifact: DatabaseArtifact) -> StorageResult<Option<File>> {
        crate::platform::open_database_artifact(&self.root, artifact)
    }

    pub(crate) fn create_artifact(&self, artifact: DatabaseArtifact) -> StorageResult<File> {
        crate::platform::create_database_artifact(&self.root, artifact)
    }

    pub(crate) fn validate_artifact_identity(
        &self,
        artifact: DatabaseArtifact,
        expected: &File,
    ) -> StorageResult<()> {
        crate::platform::validate_database_artifact_identity(&self.root, artifact, expected)
    }

    pub(crate) fn remove_artifact(&self, artifact: DatabaseArtifact) -> StorageResult<()> {
        crate::platform::remove_database_artifact(&self.root, artifact)
    }

    pub(crate) fn discard_sqlite_artifact(&self, artifact: DatabaseArtifact) -> StorageResult<()> {
        crate::platform::discard_sqlite_database_artifact(&self.root, artifact)
    }

    pub(crate) fn replace_artifact_if_exists(
        &self,
        source: DatabaseArtifact,
        destination: DatabaseArtifact,
    ) -> StorageResult<()> {
        crate::platform::replace_database_artifact_if_exists(&self.root, source, destination)
    }

    pub(crate) fn replace_artifact_required(
        &self,
        source: DatabaseArtifact,
        destination: DatabaseArtifact,
        expected: &File,
    ) -> StorageResult<()> {
        crate::platform::replace_database_artifact_required(
            &self.root,
            source,
            destination,
            expected,
        )
    }

    pub(crate) fn sync_root(&self) -> StorageResult<()> {
        crate::platform::sync_database_root(&self.root)
    }

    pub(crate) fn acquire_repository_lock(&self) -> StorageResult<File> {
        crate::platform::acquire_database_repository_lock(&self.root)
    }

    pub(crate) fn validate_root(&self) -> StorageResult<()> {
        crate::platform::validate_private_database_root(&self.root)
    }

    pub(crate) fn harden_existing_files(&self) -> StorageResult<()> {
        crate::platform::harden_existing_database_files(&self.root, &self.database)
    }
}

impl Debug for PrivateDatabasePath {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("PrivateDatabasePath([REDACTED])")
    }
}
