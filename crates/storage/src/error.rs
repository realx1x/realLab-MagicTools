use std::fmt::Display;

use domain::{AppError, ErrorCode};

pub(crate) fn storage_error(operation: &'static str, source: impl Display) -> AppError {
    let mut error = AppError::new(ErrorCode::StorageError, "SQLite storage operation failed");
    error
        .details
        .insert("operation".to_owned(), operation.to_owned());
    error.details.insert("cause".to_owned(), source.to_string());
    error
}

pub(crate) fn migration_recovery_error(phase: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::StorageError,
        "SQLite migration recovery operation failed",
    );
    error.details.insert("phase".to_owned(), phase.to_owned());
    error
}

pub(crate) fn not_found(entity: &'static str, id: &str) -> AppError {
    let mut error = AppError::new(ErrorCode::NotFound, format!("{entity} was not found"));
    error.details.insert("entity".to_owned(), entity.to_owned());
    error.details.insert("id".to_owned(), id.to_owned());
    error
}
