use domain::{
    AppError, ErrorCode, ListRunHistoryRequest, ListRunHistoryResponse, ManagedStopKind,
    RunHistoryItem,
};
use sqlx::FromRow;

use crate::error::storage_error;
use crate::{StorageResult, SupervisorRepository};

const CURSOR_PREFIX: &str = "rhc1|";
const MAX_RUN_ID_BYTES: usize = 256;
const MAX_RUN_TIMESTAMP_BYTES: usize = 128;

#[derive(Debug, FromRow)]
struct RunHistoryKey {
    id: String,
    started_at: String,
}

impl SupervisorRepository {
    pub async fn run_history(
        &self,
        request: &ListRunHistoryRequest,
    ) -> StorageResult<ListRunHistoryResponse> {
        lifecycle::validate_list_run_history_request(request)?;
        let cursor = request.cursor.as_deref().map(decode_cursor).transpose()?;
        let fetch_limit = i64::from(request.limit) + 1;
        let mut keys = match cursor.as_ref() {
            Some(cursor) => sqlx::query_as::<_, RunHistoryKey>(
                "SELECT id, started_at FROM runs \
                     WHERE started_at COLLATE BINARY < ? \
                        OR (started_at COLLATE BINARY = ? AND id COLLATE BINARY < ?) \
                     ORDER BY started_at COLLATE BINARY DESC, id COLLATE BINARY DESC LIMIT ?",
            )
            .bind(&cursor.started_at)
            .bind(&cursor.started_at)
            .bind(&cursor.id)
            .bind(fetch_limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|error| storage_error("list managed run history", error))?,
            None => sqlx::query_as::<_, RunHistoryKey>(
                "SELECT id, started_at FROM runs \
                     ORDER BY started_at COLLATE BINARY DESC, id COLLATE BINARY DESC LIMIT ?",
            )
            .bind(fetch_limit)
            .fetch_all(&self.pool)
            .await
            .map_err(|error| storage_error("list managed run history", error))?,
        };

        let has_more = keys.len() > usize::from(request.limit);
        if has_more {
            keys.truncate(usize::from(request.limit));
        }

        let mut runs = Vec::with_capacity(keys.len());
        for key in &keys {
            let record = self
                .managed_run(&key.id)
                .await
                .map_err(invalid_stored_history)?;
            if record.started_at != key.started_at {
                return Err(corrupt_history(
                    "startedAt",
                    "changed between history key selection and durable run projection",
                ));
            }
            let stop_kind = record
                .stop_method
                .as_deref()
                .map(stop_kind_from_storage)
                .transpose()?;
            runs.push(RunHistoryItem {
                run_id: record.id,
                profile_id: record.profile_snapshot.id,
                profile_name: record.profile_snapshot.input.name,
                state: record.state,
                process_instance_key: record.process_instance_key,
                stop_kind,
                recovery_state: record.recovery_state,
                started_at: record.started_at,
                updated_at: record.updated_at,
                ended_at: record.ended_at,
            });
        }

        let next_cursor = if has_more {
            keys.last().map(encode_cursor)
        } else {
            None
        };
        let response = ListRunHistoryResponse { runs, next_cursor };
        lifecycle::validate_list_run_history_response(&response).map_err(invalid_stored_history)?;
        Ok(response)
    }
}

fn stop_kind_from_storage(value: &str) -> StorageResult<ManagedStopKind> {
    match value {
        "GRACEFUL" => Ok(ManagedStopKind::Graceful),
        "FORCE" => Ok(ManagedStopKind::Force),
        _ => Err(corrupt_history(
            "stopKind",
            "uses an unsupported managed stop kind",
        )),
    }
}

fn encode_cursor(cursor: &RunHistoryKey) -> String {
    format!(
        "{CURSOR_PREFIX}{}|{}{}",
        cursor.started_at.len(),
        cursor.started_at,
        cursor.id
    )
}

fn decode_cursor(value: &str) -> StorageResult<RunHistoryKey> {
    let body = value
        .strip_prefix(CURSOR_PREFIX)
        .ok_or_else(|| invalid_cursor("uses an unsupported cursor version"))?;
    let (timestamp_length, payload) = body
        .split_once('|')
        .ok_or_else(|| invalid_cursor("is malformed"))?;
    let timestamp_length = timestamp_length
        .parse::<usize>()
        .ok()
        .filter(|length| *length <= MAX_RUN_TIMESTAMP_BYTES && *length <= payload.len())
        .ok_or_else(|| invalid_cursor("contains an invalid timestamp length"))?;
    let started_at = payload
        .get(..timestamp_length)
        .filter(|value| valid_cursor_component(value, MAX_RUN_TIMESTAMP_BYTES))
        .ok_or_else(|| invalid_cursor("contains an invalid started-at value"))?;
    let id = payload
        .get(timestamp_length..)
        .filter(|value| valid_cursor_component(value, MAX_RUN_ID_BYTES))
        .ok_or_else(|| invalid_cursor("does not contain a valid run ID"))?;
    let cursor = RunHistoryKey {
        id: id.to_owned(),
        started_at: started_at.to_owned(),
    };
    if encode_cursor(&cursor) != value {
        return Err(invalid_cursor("is not canonical"));
    }
    Ok(cursor)
}

fn valid_cursor_component(value: &str, maximum_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum_bytes
        && !value.trim().is_empty()
        && !value.chars().any(char::is_control)
}

fn invalid_cursor(reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::InvalidArgument,
        "managed run history cursor is invalid",
    );
    error.details.insert("field".into(), "cursor".into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn corrupt_history(field: &'static str, reason: &'static str) -> AppError {
    let mut error = AppError::new(
        ErrorCode::StorageError,
        "stored managed run history is invalid",
    );
    error.details.insert("field".into(), field.into());
    error.details.insert("reason".into(), reason.into());
    error
}

fn invalid_stored_history(source: AppError) -> AppError {
    let mut error = AppError::new(
        ErrorCode::StorageError,
        "stored managed run history is invalid",
    );
    error.details.insert("reason".into(), source.message);
    if let Some(field) = source.details.get("field") {
        error.details.insert("field".into(), field.clone());
    }
    error
}
