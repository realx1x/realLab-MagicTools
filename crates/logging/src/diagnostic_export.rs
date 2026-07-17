use std::fs::File;
use std::io::Write;
use std::path::Path;

use crate::retention::validate_run_id_component;
use crate::secure_directory::SecureRunDirectory;
use crate::{LogError, LogErrorKind, LogOperation, MAX_DIAGNOSTIC_BYTE_BUDGET};

/// Hard UTF-8 length of a diagnostic export file name.
pub const MAX_DIAGNOSTIC_EXPORT_FILE_NAME_BYTES: usize = 128;
/// Fixed rotating slots keep the private export root bounded without walking
/// caller-controlled directory entries.
pub const DIAGNOSTIC_EXPORT_SLOT_COUNT: u8 = 8;

const DIAGNOSTIC_WRITE_CHUNK_BYTES: usize = 64 * 1_024;
const DIAGNOSTIC_PARTIAL_FILE_NAME: &str = ".magictools-diagnostic.partial";

/// Successful atomic diagnostic publication. Paths and content are never
/// retained in this receipt or its `Debug` representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiagnosticExportReceipt {
    pub bytes_written: u64,
}

/// A capability scoped to one private diagnostic-export directory.
///
/// The root is selected once when this value is opened. Writes accept only a
/// validated single-component file name, create one fixed sibling partial with
/// create-new semantics, sync its bytes, atomically replace one of eight fixed
/// final slots, and sync the directory. This type does not choose an archive
/// format and does not accept a destination path per write. The Supervisor's
/// single-instance/single-export boundary is required; opening the store
/// removes a crash-left partial before accepting work.
pub struct DiagnosticExportStore {
    directory: SecureRunDirectory,
}

impl DiagnosticExportStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, LogError> {
        let directory = SecureRunDirectory::prepare(root.as_ref()).map_err(|error| LogError {
            operation: LogOperation::ValidateDiagnosticExportRoot,
            ..error
        })?;
        let store = Self { directory };
        store.remove_partial_and_sync()?;
        store.validate_slots()?;
        Ok(store)
    }

    pub fn write_atomic(
        &self,
        final_name: &str,
        contents: &[u8],
    ) -> Result<DiagnosticExportReceipt, LogError> {
        self.write_atomic_cancellable(final_name, contents, || false)
    }

    /// Checks cancellation before creation, before every bounded write, and
    /// immediately before publication. Cancellation after publication remains
    /// a caller concern because a completed final file must not be reported as
    /// an unpublished partial.
    pub fn write_atomic_cancellable(
        &self,
        final_name: &str,
        contents: &[u8],
        mut is_cancelled: impl FnMut() -> bool,
    ) -> Result<DiagnosticExportReceipt, LogError> {
        validate_export_file_name(final_name)?;
        let bytes_written = u64::try_from(contents.len()).map_err(|_| {
            LogError::configuration(
                LogOperation::WriteDiagnosticPartialFile,
                LogErrorKind::LimitExceeded,
            )
        })?;
        if bytes_written > MAX_DIAGNOSTIC_BYTE_BUDGET {
            return Err(LogError::configuration(
                LogOperation::WriteDiagnosticPartialFile,
                LogErrorKind::LimitExceeded,
            ));
        }
        check_cancelled(&mut is_cancelled)?;

        // A prior failed cleanup must not permanently block this store. The
        // Supervisor owns one store and admits only one export at a time.
        self.remove_partial_and_sync()?;
        check_cancelled(&mut is_cancelled)?;

        let mut partial = self.create_partial()?;
        let write_result = write_partial(&mut partial, contents, &mut is_cancelled);
        drop(partial);
        if let Err(error) = write_result {
            return Err(self.cleanup_partial(error));
        }
        if let Err(error) = check_cancelled(&mut is_cancelled) {
            return Err(self.cleanup_partial(error));
        }

        if let Err(error) = self.directory.replace_file_required(
            DIAGNOSTIC_PARTIAL_FILE_NAME,
            final_name,
            None,
            LogOperation::PublishDiagnosticFile,
        ) {
            return Err(self.cleanup_partial(error));
        }
        if let Err(error) = self
            .directory
            .sync(None, LogOperation::SyncDiagnosticExportDirectory)
        {
            return Err(self.cleanup_published(final_name, error));
        }

        Ok(DiagnosticExportReceipt { bytes_written })
    }

    fn create_partial(&self) -> Result<File, LogError> {
        match self.directory.create_new_file(
            DIAGNOSTIC_PARTIAL_FILE_NAME,
            None,
            LogOperation::CreateDiagnosticPartialFile,
        ) {
            Ok(file) => Ok(file),
            Err(error) if error.kind() == LogErrorKind::AlreadyExists => {
                Err(LogError::configuration(
                    LogOperation::CreateDiagnosticPartialFile,
                    LogErrorKind::ResourceBusy,
                ))
            }
            Err(error) => Err(self.cleanup_partial(error)),
        }
    }

    fn remove_partial_and_sync(&self) -> Result<(), LogError> {
        self.directory
            .remove_file_if_exists(
                DIAGNOSTIC_PARTIAL_FILE_NAME,
                None,
                LogOperation::RemoveDiagnosticPartialFile,
            )
            .and_then(|()| {
                self.directory
                    .sync(None, LogOperation::SyncDiagnosticExportDirectory)
            })
    }

    fn validate_slots(&self) -> Result<(), LogError> {
        for slot in 0..DIAGNOSTIC_EXPORT_SLOT_COUNT {
            let file_name = diagnostic_export_slot_file_name(slot)?;
            if self
                .directory
                .inspect_file(&file_name, None, LogOperation::InspectDiagnosticExportFile)?
                .is_some_and(|bytes| bytes > MAX_DIAGNOSTIC_BYTE_BUDGET)
            {
                return Err(LogError::configuration(
                    LogOperation::InspectDiagnosticExportFile,
                    LogErrorKind::LimitExceeded,
                ));
            }
        }
        Ok(())
    }

    fn cleanup_partial(&self, primary: LogError) -> LogError {
        self.remove_partial_and_sync().err().unwrap_or(primary)
    }

    fn cleanup_published(&self, final_name: &str, primary: LogError) -> LogError {
        let cleanup = self
            .directory
            .remove_file_if_exists(final_name, None, LogOperation::RemoveDiagnosticExportFile)
            .and_then(|()| {
                self.directory
                    .sync(None, LogOperation::SyncDiagnosticExportDirectory)
            });
        cleanup.err().unwrap_or(primary)
    }
}

impl std::fmt::Debug for DiagnosticExportStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DiagnosticExportStore")
            .finish_non_exhaustive()
    }
}

fn write_partial(
    partial: &mut File,
    contents: &[u8],
    is_cancelled: &mut impl FnMut() -> bool,
) -> Result<(), LogError> {
    for chunk in contents.chunks(DIAGNOSTIC_WRITE_CHUNK_BYTES) {
        check_cancelled(is_cancelled)?;
        partial.write_all(chunk).map_err(|error| {
            LogError::io(None, LogOperation::WriteDiagnosticPartialFile, &error)
        })?;
    }
    check_cancelled(is_cancelled)?;
    partial
        .sync_all()
        .map_err(|error| LogError::io(None, LogOperation::FlushDiagnosticPartialFile, &error))
}

fn check_cancelled(is_cancelled: &mut impl FnMut() -> bool) -> Result<(), LogError> {
    if is_cancelled() {
        Err(LogError::configuration(
            LogOperation::CancelDiagnosticExport,
            LogErrorKind::Interrupted,
        ))
    } else {
        Ok(())
    }
}

fn validate_export_file_name(final_name: &str) -> Result<(), LogError> {
    validate_run_id_component(final_name, MAX_DIAGNOSTIC_EXPORT_FILE_NAME_BYTES).map_err(
        |error| LogError {
            operation: LogOperation::ValidateDiagnosticExportFileName,
            ..error
        },
    )?;
    let bytes = final_name.as_bytes();
    let restricted_ascii = bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        });
    let is_slot = (0..DIAGNOSTIC_EXPORT_SLOT_COUNT).any(|slot| {
        diagnostic_export_slot_file_name(slot).is_ok_and(|candidate| candidate == final_name)
    });
    if !restricted_ascii || !is_slot {
        return Err(LogError::configuration(
            LogOperation::ValidateDiagnosticExportFileName,
            LogErrorKind::InvalidPath,
        ));
    }
    Ok(())
}

pub fn diagnostic_export_slot_file_name(slot: u8) -> Result<String, LogError> {
    if slot >= DIAGNOSTIC_EXPORT_SLOT_COUNT {
        return Err(LogError::configuration(
            LogOperation::ValidateDiagnosticExportFileName,
            LogErrorKind::InvalidConfiguration,
        ));
    }
    Ok(format!("magictools-diagnostics-slot-{slot}.json"))
}
