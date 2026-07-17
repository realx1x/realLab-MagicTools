use std::path::{Component, Path};

use crate::{LogError, LogErrorKind, LogOperation, LogStream};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "macos")]
use macos as implementation;
#[cfg(windows)]
use windows as implementation;

#[cfg(not(any(windows, target_os = "macos")))]
compile_error!("managed log collection supports only Windows and macOS");

pub(crate) use implementation::{SecureLogRoot, SecureRunDirectory};

pub(crate) fn validate_retention_run_id(
    run_id: &str,
    maximum_bytes: usize,
) -> Result<(), LogError> {
    crate::retention::validate_run_id_component(run_id, maximum_bytes)
}

pub(super) fn validate_run_directory_path(path: &Path) -> Result<(), LogError> {
    validate_absolute_directory_path(path, LogOperation::ValidateRunDirectory)
}

pub(super) fn validate_log_root_path(path: &Path) -> Result<(), LogError> {
    validate_absolute_directory_path(path, LogOperation::ValidateRetentionLogRoot)
}

fn validate_absolute_directory_path(path: &Path, operation: LogOperation) -> Result<(), LogError> {
    if path.as_os_str().is_empty() || !path.is_absolute() || path.file_name().is_none() {
        return Err(LogError::configuration(
            operation,
            LogErrorKind::InvalidPath,
        ));
    }

    let mut saw_root = false;
    let mut normal_components = 0_usize;
    for component in path.components() {
        match component {
            Component::Prefix(_) if !saw_root && normal_components == 0 => {}
            Component::RootDir if !saw_root => saw_root = true,
            Component::Normal(_) if saw_root => normal_components += 1,
            Component::CurDir
            | Component::ParentDir
            | Component::Prefix(_)
            | Component::RootDir
            | Component::Normal(_) => {
                return Err(LogError::configuration(
                    operation,
                    LogErrorKind::InvalidPath,
                ));
            }
        }
    }
    if !saw_root || normal_components == 0 {
        return Err(LogError::configuration(
            operation,
            LogErrorKind::InvalidPath,
        ));
    }
    Ok(())
}

pub(super) fn validate_file_name(file_name: &str) -> Result<(), LogError> {
    let mut components = Path::new(file_name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(LogError::configuration(
            LogOperation::ValidateRunDirectory,
            LogErrorKind::InvalidPath,
        ));
    }
    Ok(())
}

pub(super) fn map_io(
    stream: Option<LogStream>,
    operation: LogOperation,
    error: &std::io::Error,
) -> LogError {
    LogError::io(stream, operation, error)
}
