use std::fmt::{self, Formatter};
use std::path::{Component, Path};
use std::sync::Arc;

use crate::control_filter::is_printable_log_character;
use crate::secure_directory::{SecureLogRoot, SecureRunDirectory, validate_retention_run_id};
use crate::{LogError, LogErrorKind, LogOperation, LogStream, MAX_LOG_FILES_PER_STREAM};

/// Largest UTF-8 run identifier accepted by the retention boundary.
pub const MAX_MANAGED_LOG_RUN_ID_BYTES: usize = 256;

/// A bounded inspection of the fixed rolling files owned by one managed run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedLogRetentionInspection {
    /// The expected run directory does not exist.
    NotFound,
    /// The run directory exists and every present fixed log file was verified.
    Present { retained_bytes: u64, file_count: u8 },
}

/// Result of removing one verified managed-run log directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedLogRetentionRemoval {
    /// The expected run directory was already absent. This is a successful,
    /// idempotent outcome.
    NotFound,
    /// Every present fixed log file and the now-empty run directory were
    /// removed. Unknown directory entries prevent this outcome.
    Removed { retained_bytes: u64, file_count: u8 },
}

/// A capability scoped to one validated, private Supervisor log root.
///
/// Operations accept only a single safe run-ID component. They never accept a
/// database-provided path, recursively walk a directory, or remove an unknown
/// file name. Callers must exclude active runs and coordinate concurrent range
/// readers before invoking [`Self::remove`].
#[derive(Clone)]
pub struct ManagedLogRetentionStore {
    log_root: Arc<SecureLogRoot>,
}

impl ManagedLogRetentionStore {
    /// Opens an absolute, private current-user log root and retains its
    /// platform directory capability for every subsequent run operation.
    pub fn open(log_root: impl AsRef<Path>) -> Result<Self, LogError> {
        Ok(Self {
            log_root: Arc::new(SecureLogRoot::open(log_root.as_ref())?),
        })
    }

    /// Inspects only `stdout.log`, `stderr.log`, and their supported numbered
    /// archives. Sizes are summed with checked arithmetic.
    pub fn inspect(&self, run_id: &str) -> Result<ManagedLogRetentionInspection, LogError> {
        self.validate_run_id(run_id)?;
        let directory = match self.log_root.open_run_existing(run_id) {
            Ok(directory) => directory,
            Err(error) if error.kind() == LogErrorKind::NotFound => {
                return Ok(ManagedLogRetentionInspection::NotFound);
            }
            Err(error) => return Err(error),
        };
        let (retained_bytes, file_count) = inspect_fixed_files(&directory)?;
        Ok(ManagedLogRetentionInspection::Present {
            retained_bytes,
            file_count,
        })
    }

    /// Removes only verified fixed rolling files and then removes the verified
    /// run directory if it is empty. A missing directory is an idempotent
    /// success; symlinks, reparse points, unknown entries, and ownership or ACL
    /// mismatches fail closed.
    pub fn remove(&self, run_id: &str) -> Result<ManagedLogRetentionRemoval, LogError> {
        self.validate_run_id(run_id)?;
        let directory = match self.log_root.open_run_for_retention(run_id) {
            Ok(directory) => directory,
            Err(error) if error.kind() == LogErrorKind::NotFound => {
                return Ok(ManagedLogRetentionRemoval::NotFound);
            }
            Err(error) => return Err(error),
        };

        let mut retained_bytes = 0_u64;
        let mut file_count = 0_u8;
        for_each_fixed_file(|stream, file_name| {
            let Some(length) = directory.remove_file_for_retention(
                &file_name,
                Some(stream),
                LogOperation::RemoveRetainedLogFile,
            )?
            else {
                return Ok(());
            };
            retained_bytes = retained_bytes.checked_add(length).ok_or_else(|| {
                LogError::for_stream(
                    stream,
                    LogOperation::AccountRetainedLogBytes,
                    LogErrorKind::LimitExceeded,
                )
            })?;
            file_count = file_count.checked_add(1).ok_or_else(|| {
                LogError::for_stream(
                    stream,
                    LogOperation::AccountRetainedLogBytes,
                    LogErrorKind::LimitExceeded,
                )
            })?;
            Ok(())
        })?;

        directory.remove_run_directory(LogOperation::RemoveRetainedRunDirectory)?;
        Ok(ManagedLogRetentionRemoval::Removed {
            retained_bytes,
            file_count,
        })
    }

    fn validate_run_id(&self, run_id: &str) -> Result<(), LogError> {
        validate_retention_run_id(run_id, MAX_MANAGED_LOG_RUN_ID_BYTES)
    }
}

impl fmt::Debug for ManagedLogRetentionStore {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedLogRetentionStore")
            .finish_non_exhaustive()
    }
}

fn inspect_fixed_files(directory: &SecureRunDirectory) -> Result<(u64, u8), LogError> {
    let mut retained_bytes = 0_u64;
    let mut file_count = 0_u8;
    for_each_fixed_file(|stream, file_name| {
        let Some(file) = directory.open_existing_file(
            &file_name,
            Some(stream),
            LogOperation::InspectRetainedLogFile,
        )?
        else {
            return Ok(());
        };
        let length = file
            .metadata()
            .map_err(|error| {
                LogError::io(Some(stream), LogOperation::InspectRetainedLogFile, &error)
            })?
            .len();
        retained_bytes = retained_bytes.checked_add(length).ok_or_else(|| {
            LogError::for_stream(
                stream,
                LogOperation::AccountRetainedLogBytes,
                LogErrorKind::LimitExceeded,
            )
        })?;
        file_count = file_count.checked_add(1).ok_or_else(|| {
            LogError::for_stream(
                stream,
                LogOperation::AccountRetainedLogBytes,
                LogErrorKind::LimitExceeded,
            )
        })?;
        Ok(())
    })?;
    Ok((retained_bytes, file_count))
}

fn for_each_fixed_file(
    mut visit: impl FnMut(LogStream, String) -> Result<(), LogError>,
) -> Result<(), LogError> {
    for stream in [LogStream::Stdout, LogStream::Stderr] {
        visit(stream, stream.active_file_name().to_owned())?;
        for index in 1..MAX_LOG_FILES_PER_STREAM {
            visit(stream, stream.archive_file_name(index))?;
        }
    }
    Ok(())
}

pub(crate) fn validate_run_id_component(
    run_id: &str,
    maximum_bytes: usize,
) -> Result<(), LogError> {
    let invalid = run_id.is_empty()
        || run_id.len() > maximum_bytes
        || run_id.trim() != run_id
        || run_id.ends_with(['.', ' '])
        || run_id.chars().any(|character| {
            character.is_control()
                || !is_printable_log_character(character)
                || matches!(
                    character,
                    '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
                )
        })
        || reserved_windows_device_name(run_id);
    let mut components = Path::new(run_id).components();
    let single_normal = matches!(components.next(), Some(Component::Normal(component)) if component == run_id)
        && components.next().is_none();
    if invalid || !single_normal {
        return Err(LogError::configuration(
            LogOperation::ValidateRetentionRunId,
            LogErrorKind::InvalidPath,
        ));
    }
    Ok(())
}

fn reserved_windows_device_name(run_id: &str) -> bool {
    let stem = run_id.split('.').next().unwrap_or(run_id);
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || upper
            .strip_prefix("COM")
            .or_else(|| upper.strip_prefix("LPT"))
            .is_some_and(|suffix| suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9'))
}
