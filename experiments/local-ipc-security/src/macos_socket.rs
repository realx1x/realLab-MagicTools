use std::ffi::OsStr;
use std::fs::{self, DirBuilder, Permissions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Component, Path, PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SocketSecurityError {
    #[error("the runtime directory cannot be a symbolic link")]
    SymlinkRuntimeDirectory,
    #[error("the socket name must be one normal path component")]
    InvalidSocketName,
    #[error("refusing to remove a stale path that is not a Unix socket")]
    UnsafeStalePath,
    #[error("{operation} for {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
}

pub struct PrivateUnixSocket {
    pub listener: UnixListener,
    pub path: PathBuf,
}

pub fn bind_private_socket(
    runtime_directory: &Path,
    socket_name: &OsStr,
) -> Result<PrivateUnixSocket, SocketSecurityError> {
    if matches!(
        fs::symlink_metadata(runtime_directory),
        Ok(metadata) if metadata.file_type().is_symlink()
    ) {
        return Err(SocketSecurityError::SymlinkRuntimeDirectory);
    }
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(runtime_directory)
        .map_err(|source| io_error("create runtime directory", runtime_directory, source))?;
    fs::set_permissions(runtime_directory, Permissions::from_mode(0o700))
        .map_err(|source| io_error("restrict runtime directory", runtime_directory, source))?;

    let component_path = Path::new(socket_name);
    if component_path.components().count() != 1
        || !matches!(
            component_path.components().next(),
            Some(Component::Normal(_))
        )
    {
        return Err(SocketSecurityError::InvalidSocketName);
    }
    let path = runtime_directory.join(component_path);

    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_socket() => fs::remove_file(&path)
            .map_err(|source| io_error("remove stale socket", &path, source))?,
        Ok(_) => return Err(SocketSecurityError::UnsafeStalePath),
        Err(source) if source.kind() == io::ErrorKind::NotFound => {}
        Err(source) => return Err(io_error("inspect stale socket", &path, source)),
    }

    let listener =
        UnixListener::bind(&path).map_err(|source| io_error("bind Unix socket", &path, source))?;
    if let Err(source) = fs::set_permissions(&path, Permissions::from_mode(0o600)) {
        let _ = fs::remove_file(&path);
        return Err(io_error("restrict Unix socket", &path, source));
    }
    Ok(PrivateUnixSocket { listener, path })
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> SocketSecurityError {
    SocketSecurityError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}
