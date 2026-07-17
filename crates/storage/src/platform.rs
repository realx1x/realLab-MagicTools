use std::fs::File;
use std::path::{Path, PathBuf};

use crate::StorageResult;
use crate::database_path::DatabaseArtifact;
use crate::error::{migration_recovery_error, storage_error};

#[cfg(target_os = "macos")]
#[path = "platform/macos.rs"]
mod implementation;
#[cfg(windows)]
#[path = "platform/windows.rs"]
mod implementation;

#[cfg(not(any(target_os = "macos", windows)))]
mod implementation {
    use std::fs::File;
    use std::io;
    use std::path::{Path, PathBuf};

    use crate::database_path::DatabaseArtifact;

    pub(super) fn prepare_private_database_root() -> io::Result<PathBuf> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the private database root is unsupported on this platform",
        ))
    }

    pub(super) fn validate_private_database_root(_root: &Path) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the private database root is unsupported on this platform",
        ))
    }

    pub(super) fn harden_existing_database_files(_root: &Path, _database: &Path) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private database files are unsupported on this platform",
        ))
    }

    pub(super) fn inspect_database_artifact(
        _root: &Path,
        _artifact: DatabaseArtifact,
    ) -> io::Result<Option<u64>> {
        unsupported_artifact()
    }

    pub(super) fn open_database_artifact(
        _root: &Path,
        _artifact: DatabaseArtifact,
    ) -> io::Result<Option<File>> {
        unsupported_artifact()
    }

    pub(super) fn create_database_artifact(
        _root: &Path,
        _artifact: DatabaseArtifact,
    ) -> io::Result<File> {
        unsupported_artifact()
    }

    pub(super) fn validate_database_artifact_identity(
        _root: &Path,
        _artifact: DatabaseArtifact,
        _expected: &File,
    ) -> io::Result<()> {
        unsupported_artifact()
    }

    pub(super) fn remove_database_artifact(
        _root: &Path,
        _artifact: DatabaseArtifact,
    ) -> io::Result<()> {
        unsupported_artifact()
    }

    pub(super) fn discard_sqlite_database_artifact(
        _root: &Path,
        _artifact: DatabaseArtifact,
    ) -> io::Result<()> {
        unsupported_artifact()
    }

    pub(super) fn replace_database_artifact_if_exists(
        _root: &Path,
        _source: DatabaseArtifact,
        _destination: DatabaseArtifact,
    ) -> io::Result<()> {
        unsupported_artifact()
    }

    pub(super) fn replace_database_artifact_required(
        _root: &Path,
        _source: DatabaseArtifact,
        _destination: DatabaseArtifact,
        _expected: &File,
    ) -> io::Result<()> {
        unsupported_artifact()
    }

    pub(super) fn sync_database_root(_root: &Path) -> io::Result<()> {
        unsupported_artifact()
    }

    pub(super) fn acquire_database_repository_lock(_root: &Path) -> io::Result<File> {
        unsupported_artifact()
    }

    fn unsupported_artifact<T>() -> io::Result<T> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "private database recovery files are unsupported on this platform",
        ))
    }
}

pub(crate) fn prepare_private_database_root() -> StorageResult<PathBuf> {
    implementation::prepare_private_database_root()
        .map_err(|error| storage_error("prepare private database directory", error))
}

pub(crate) fn validate_private_database_root(root: &Path) -> StorageResult<()> {
    implementation::validate_private_database_root(root)
        .map_err(|error| storage_error("validate private database directory", error))
}

pub(crate) fn harden_existing_database_files(root: &Path, database: &Path) -> StorageResult<()> {
    implementation::harden_existing_database_files(root, database)
        .map_err(|error| storage_error("secure private SQLite files", error))
}

pub(crate) fn inspect_database_artifact(
    root: &Path,
    artifact: DatabaseArtifact,
) -> StorageResult<Option<u64>> {
    implementation::inspect_database_artifact(root, artifact)
        .map_err(|_| migration_recovery_error("inspect_artifact"))
}

pub(crate) fn open_database_artifact(
    root: &Path,
    artifact: DatabaseArtifact,
) -> StorageResult<Option<File>> {
    implementation::open_database_artifact(root, artifact)
        .map_err(|_| migration_recovery_error("open_artifact"))
}

pub(crate) fn create_database_artifact(
    root: &Path,
    artifact: DatabaseArtifact,
) -> StorageResult<File> {
    implementation::create_database_artifact(root, artifact)
        .map_err(|_| migration_recovery_error("create_artifact"))
}

pub(crate) fn validate_database_artifact_identity(
    root: &Path,
    artifact: DatabaseArtifact,
    expected: &File,
) -> StorageResult<()> {
    implementation::validate_database_artifact_identity(root, artifact, expected)
        .map_err(|_| migration_recovery_error("validate_artifact_identity"))
}

pub(crate) fn remove_database_artifact(
    root: &Path,
    artifact: DatabaseArtifact,
) -> StorageResult<()> {
    implementation::remove_database_artifact(root, artifact)
        .map_err(|_| migration_recovery_error("remove_artifact"))
}

pub(crate) fn discard_sqlite_database_artifact(
    root: &Path,
    artifact: DatabaseArtifact,
) -> StorageResult<()> {
    implementation::discard_sqlite_database_artifact(root, artifact)
        .map_err(|_| migration_recovery_error("discard_sqlite_artifact"))
}

pub(crate) fn replace_database_artifact_if_exists(
    root: &Path,
    source: DatabaseArtifact,
    destination: DatabaseArtifact,
) -> StorageResult<()> {
    implementation::replace_database_artifact_if_exists(root, source, destination)
        .map_err(|_| migration_recovery_error("rotate_backup"))
}

pub(crate) fn replace_database_artifact_required(
    root: &Path,
    source: DatabaseArtifact,
    destination: DatabaseArtifact,
    expected: &File,
) -> StorageResult<()> {
    implementation::replace_database_artifact_required(root, source, destination, expected)
        .map_err(|_| migration_recovery_error("publish_artifact"))
}

pub(crate) fn sync_database_root(root: &Path) -> StorageResult<()> {
    implementation::sync_database_root(root)
        .map_err(|_| migration_recovery_error("sync_database_root"))
}

pub(crate) fn acquire_database_repository_lock(root: &Path) -> StorageResult<File> {
    implementation::acquire_database_repository_lock(root)
        .map_err(|_| migration_recovery_error("acquire_database_lock"))
}
