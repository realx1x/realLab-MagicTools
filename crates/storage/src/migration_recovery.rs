use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::migrate::Migrator;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqliteSynchronous};
use sqlx::{ConnectOptions, Connection, Row, SqliteConnection};

use crate::StorageResult;
use crate::database_path::{DatabaseArtifact, PrivateDatabasePath};
use crate::error::migration_recovery_error;

const MARKER_FORMAT_VERSION: u32 = 1;
const MAX_MIGRATIONS: usize = 256;
const MAX_MARKER_BYTES: u64 = 128 * 1024;
const MAX_DATABASE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_DATABASE_AND_WAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SHARED_MEMORY_BYTES: u64 = 8 * 1024 * 1024;
const COPY_BUFFER_BYTES: usize = 64 * 1024;
const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const SQLX_MIGRATION_TABLE: &str = "_sqlx_migrations";
const SHA384_HEX_BYTES: usize = 96;
const SHA256_HEX_BYTES: usize = 64;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MigrationFingerprint {
    version: i64,
    checksum: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum MarkerKind {
    Fresh,
    Backup,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum BackupSlot {
    Primary,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct BackupMetadata {
    slot: BackupSlot,
    byte_length: u64,
    sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct MigrationMarker {
    format_version: u32,
    kind: MarkerKind,
    backup: Option<BackupMetadata>,
    source: Vec<MigrationFingerprint>,
    target: Vec<MigrationFingerprint>,
}

pub(crate) async fn prepare_database(
    path: &PrivateDatabasePath,
    migrator: &Migrator,
) -> StorageResult<()> {
    if path.validate_root().is_err() {
        return Err(failure("validate_database_root"));
    }
    if path.harden_existing_files().is_err() {
        return Err(failure("harden_database_artifacts"));
    }
    let embedded = embedded_manifest(migrator)?;
    validate_retained_limits(path)?;

    if let Some(marker) = read_marker(path)? {
        handle_active_marker(path, &marker).await?;
    }

    let main_exists = path.inspect_artifact(DatabaseArtifact::Main)?.is_some();
    if !main_exists {
        if sqlite_sidecar_exists(path)? {
            return Err(failure("orphan_sqlite_sidecar"));
        }
        if data_bearing_recovery_artifact_exists(path)? {
            return Err(failure("orphaned_retained_backup"));
        }
    }

    cleanup_unreferenced_partials(path)?;
    validate_retained_limits(path)?;

    if main_exists {
        prepare_existing_database(path, migrator, &embedded).await
    } else {
        prepare_fresh_database(path, migrator, &embedded).await
    }
}

async fn prepare_existing_database(
    path: &PrivateDatabasePath,
    migrator: &Migrator,
    embedded: &[MigrationFingerprint],
) -> StorageResult<()> {
    validate_live_file_limits(path)?;
    let mut connection = connect_main(path, false).await?;
    let applied = match read_database_manifest(&mut connection).await {
        Ok(applied) => applied,
        Err(error) => {
            close_quietly(connection).await;
            return Err(error);
        }
    };
    if let Err(error) = validate_applied_prefix(&applied, embedded) {
        close_quietly(connection).await;
        return Err(error);
    }
    if applied.len() == embedded.len() {
        if let Err(error) = validate_database_health(&mut connection).await {
            close_quietly(connection).await;
            return Err(error);
        }
        if let Err(error) = checkpoint_and_validate(path, &mut connection).await {
            close_quietly(connection).await;
            return Err(error);
        }
        close_connection(connection, "close_preflight_database").await?;
        if path.harden_existing_files().is_err() {
            return Err(failure("harden_preflight_database"));
        }
        return Ok(());
    }

    if let Err(error) = checkpoint_and_validate(path, &mut connection).await {
        close_quietly(connection).await;
        return Err(error);
    }
    if let Err(error) = validate_database_health(&mut connection).await {
        close_quietly(connection).await;
        return Err(error);
    }

    let marker = match create_and_publish_backup(path, &mut connection, &applied, embedded).await {
        Ok(marker) => marker,
        Err(error) => {
            close_quietly(connection).await;
            return Err(error);
        }
    };

    if migrator.run(&mut connection).await.is_err() {
        close_quietly(connection).await;
        return recover_after_failed_migration(path, &marker, "migration_failed").await;
    }
    if validate_exact_database(&mut connection, embedded)
        .await
        .is_err()
        || checkpoint_and_validate(path, &mut connection)
            .await
            .is_err()
    {
        close_quietly(connection).await;
        return recover_after_failed_migration(path, &marker, "post_migration_check_failed").await;
    }
    if close_connection(connection, "close_migrated_database")
        .await
        .is_err()
    {
        return recover_after_failed_migration(path, &marker, "close_migrated_database").await;
    }
    if path.harden_existing_files().is_err() {
        return recover_after_failed_migration(path, &marker, "harden_migrated_database").await;
    }
    clear_marker(path)?;
    Ok(())
}

async fn prepare_fresh_database(
    path: &PrivateDatabasePath,
    migrator: &Migrator,
    embedded: &[MigrationFingerprint],
) -> StorageResult<()> {
    let marker = MigrationMarker {
        format_version: MARKER_FORMAT_VERSION,
        kind: MarkerKind::Fresh,
        backup: None,
        source: Vec::new(),
        target: embedded.to_vec(),
    };
    publish_marker(path, &marker)?;

    let mut connection = match connect_main(path, true).await {
        Ok(connection) => connection,
        Err(_) => return recover_after_failed_migration(path, &marker, "fresh_open_failed").await,
    };
    if path.harden_existing_files().is_err() || migrator.run(&mut connection).await.is_err() {
        close_quietly(connection).await;
        return recover_after_failed_migration(path, &marker, "fresh_migration_failed").await;
    }
    if validate_exact_database(&mut connection, embedded)
        .await
        .is_err()
        || checkpoint_and_validate(path, &mut connection)
            .await
            .is_err()
    {
        close_quietly(connection).await;
        return recover_after_failed_migration(path, &marker, "fresh_postcheck_failed").await;
    }
    if close_connection(connection, "close_fresh_database")
        .await
        .is_err()
    {
        return recover_after_failed_migration(path, &marker, "close_fresh_database").await;
    }
    if path.harden_existing_files().is_err() {
        return recover_after_failed_migration(path, &marker, "harden_fresh_database").await;
    }
    clear_marker(path)?;
    Ok(())
}

async fn handle_active_marker(
    path: &PrivateDatabasePath,
    marker: &MigrationMarker,
) -> StorageResult<()> {
    validate_marker(marker)?;
    cleanup_unreferenced_partials(path)?;
    validate_marker_backup(path, marker).await?;

    if active_database_is_target(path, &marker.target).await && path.harden_existing_files().is_ok()
    {
        clear_marker(path)?;
        return Ok(());
    }

    match marker.kind {
        MarkerKind::Fresh => restore_fresh_state(path)?,
        MarkerKind::Backup => restore_backup_state(path, marker).await?,
    }
    Err(failure("previous_migration_recovered"))
}

async fn validate_marker_backup(
    path: &PrivateDatabasePath,
    marker: &MigrationMarker,
) -> StorageResult<()> {
    if marker.kind == MarkerKind::Fresh {
        return Ok(());
    }
    let backup = marker
        .backup
        .as_ref()
        .ok_or_else(|| failure("missing_backup_metadata"))?;
    let artifact = match backup.slot {
        BackupSlot::Primary => DatabaseArtifact::BackupPrimary,
    };
    let mut file = path
        .open_artifact(artifact)?
        .ok_or_else(|| failure("missing_migration_backup"))?;
    let (byte_length, sha256) = hash_open_file(path, artifact, &mut file, MAX_DATABASE_BYTES)?;
    if byte_length != backup.byte_length || sha256 != backup.sha256 {
        return Err(failure("invalid_migration_backup_digest"));
    }
    validate_snapshot_artifact(path, artifact, &file, &marker.source).await
}

async fn active_database_is_target(
    path: &PrivateDatabasePath,
    target: &[MigrationFingerprint],
) -> bool {
    if path
        .inspect_artifact(DatabaseArtifact::Main)
        .ok()
        .flatten()
        .is_none()
        || validate_live_file_limits(path).is_err()
    {
        return false;
    }
    let mut connection = match connect_main(path, false).await {
        Ok(connection) => connection,
        Err(_) => return false,
    };
    let matches = validate_exact_database(&mut connection, target)
        .await
        .is_ok()
        && checkpoint_and_validate(path, &mut connection).await.is_ok();
    let closed = connection.close().await.is_ok();
    matches && closed
}

async fn create_and_publish_backup(
    path: &PrivateDatabasePath,
    source_connection: &mut SqliteConnection,
    source: &[MigrationFingerprint],
    target: &[MigrationFingerprint],
) -> StorageResult<MigrationMarker> {
    path.discard_sqlite_artifact(DatabaseArtifact::BackupPartialJournal)?;
    path.discard_sqlite_artifact(DatabaseArtifact::BackupPartial)?;
    let mut partial = path.create_artifact(DatabaseArtifact::BackupPartial)?;
    let partial_path = utf8_artifact_path(path, DatabaseArtifact::BackupPartial)?;
    if sqlx::query("VACUUM main INTO ?1")
        .bind(partial_path)
        .persistent(false)
        .execute(&mut *source_connection)
        .await
        .is_err()
    {
        drop(partial);
        let _ = path.discard_sqlite_artifact(DatabaseArtifact::BackupPartialJournal);
        let _ = path.discard_sqlite_artifact(DatabaseArtifact::BackupPartial);
        return Err(failure("create_migration_backup"));
    }
    if path
        .inspect_artifact(DatabaseArtifact::BackupPartialJournal)?
        .is_some()
    {
        drop(partial);
        let _ = path.discard_sqlite_artifact(DatabaseArtifact::BackupPartialJournal);
        let _ = path.discard_sqlite_artifact(DatabaseArtifact::BackupPartial);
        return Err(failure("migration_backup_journal_remained"));
    }
    partial
        .sync_all()
        .map_err(|_| failure("sync_migration_backup"))?;
    path.validate_artifact_identity(DatabaseArtifact::BackupPartial, &partial)?;
    let (byte_length, sha256) = hash_open_file(
        path,
        DatabaseArtifact::BackupPartial,
        &mut partial,
        MAX_DATABASE_BYTES,
    )?;
    if byte_length == 0 {
        return Err(failure("empty_migration_backup"));
    }
    validate_snapshot_artifact(path, DatabaseArtifact::BackupPartial, &partial, source).await?;

    path.replace_artifact_if_exists(
        DatabaseArtifact::BackupPrimary,
        DatabaseArtifact::BackupPrevious,
    )?;
    path.replace_artifact_required(
        DatabaseArtifact::BackupPartial,
        DatabaseArtifact::BackupPrimary,
        &partial,
    )?;
    path.sync_root()?;

    let marker = MigrationMarker {
        format_version: MARKER_FORMAT_VERSION,
        kind: MarkerKind::Backup,
        backup: Some(BackupMetadata {
            slot: BackupSlot::Primary,
            byte_length,
            sha256,
        }),
        source: source.to_vec(),
        target: target.to_vec(),
    };
    publish_marker(path, &marker)?;
    Ok(marker)
}

async fn recover_after_failed_migration(
    path: &PrivateDatabasePath,
    expected_marker: &MigrationMarker,
    completed_phase: &'static str,
) -> StorageResult<()> {
    let marker = read_marker(path)?
        .filter(|marker| marker == expected_marker)
        .ok_or_else(|| failure("published_marker_changed"))?;
    let restored = match marker.kind {
        MarkerKind::Fresh => restore_fresh_state(path),
        MarkerKind::Backup => restore_backup_state(path, &marker).await,
    };
    match restored {
        Ok(()) => Err(failure(completed_phase)),
        Err(_) => Err(failure("migration_recovery_failed")),
    }
}

fn restore_fresh_state(path: &PrivateDatabasePath) -> StorageResult<()> {
    remove_sqlite_database_files(path)?;
    path.sync_root()?;
    clear_marker(path)
}

async fn restore_backup_state(
    path: &PrivateDatabasePath,
    marker: &MigrationMarker,
) -> StorageResult<()> {
    let backup = marker
        .backup
        .as_ref()
        .ok_or_else(|| failure("missing_backup_metadata"))?;
    let backup_artifact = match backup.slot {
        BackupSlot::Primary => DatabaseArtifact::BackupPrimary,
    };
    let mut source_file = path
        .open_artifact(backup_artifact)?
        .ok_or_else(|| failure("missing_migration_backup"))?;
    let (source_length, source_sha256) =
        hash_open_file(path, backup_artifact, &mut source_file, MAX_DATABASE_BYTES)?;
    if source_length != backup.byte_length || source_sha256 != backup.sha256 {
        return Err(failure("invalid_migration_backup_digest"));
    }
    validate_snapshot_artifact(path, backup_artifact, &source_file, &marker.source).await?;

    path.discard_sqlite_artifact(DatabaseArtifact::RestorePartial)?;
    let mut restore = path.create_artifact(DatabaseArtifact::RestorePartial)?;
    let (copied_length, copied_sha256) =
        copy_open_file(&mut source_file, &mut restore, MAX_DATABASE_BYTES)?;
    if copied_length != backup.byte_length || copied_sha256 != backup.sha256 {
        return Err(failure("restore_copy_digest_mismatch"));
    }
    restore
        .sync_all()
        .map_err(|_| failure("sync_restore_copy"))?;
    path.validate_artifact_identity(DatabaseArtifact::RestorePartial, &restore)?;
    path.validate_artifact_identity(backup_artifact, &source_file)?;

    remove_sqlite_database_files(path)?;
    path.sync_root()?;
    path.replace_artifact_required(
        DatabaseArtifact::RestorePartial,
        DatabaseArtifact::Main,
        &restore,
    )?;
    path.sync_root()?;
    if path.harden_existing_files().is_err() {
        return Err(failure("harden_restored_database"));
    }

    let (restored_length, restored_sha256) = hash_open_file(
        path,
        DatabaseArtifact::Main,
        &mut restore,
        MAX_DATABASE_BYTES,
    )?;
    if restored_length != backup.byte_length || restored_sha256 != backup.sha256 {
        return Err(failure("restored_database_digest_mismatch"));
    }
    validate_snapshot_artifact(path, DatabaseArtifact::Main, &restore, &marker.source).await?;
    clear_marker(path)
}

async fn validate_snapshot_artifact(
    path: &PrivateDatabasePath,
    artifact: DatabaseArtifact,
    expected_file: &File,
    expected_manifest: &[MigrationFingerprint],
) -> StorageResult<()> {
    path.validate_artifact_identity(artifact, expected_file)?;
    let artifact_path = path.artifact_path(artifact);
    ensure_utf8_path(&artifact_path)?;
    let options = SqliteConnectOptions::new()
        .filename(&artifact_path)
        .read_only(true)
        .immutable(true)
        .foreign_keys(true)
        .busy_timeout(SQLITE_BUSY_TIMEOUT);
    let mut connection = options
        .connect()
        .await
        .map_err(|_| failure("open_backup_snapshot"))?;
    let result = validate_exact_database(&mut connection, expected_manifest).await;
    let close_result = connection.close().await;
    if result.is_err() || close_result.is_err() {
        return Err(failure("validate_backup_snapshot"));
    }
    path.validate_artifact_identity(artifact, expected_file)
}

async fn connect_main(
    path: &PrivateDatabasePath,
    create_if_missing: bool,
) -> StorageResult<SqliteConnection> {
    ensure_utf8_path(path.database())?;
    SqliteConnectOptions::new()
        .filename(path.database())
        .create_if_missing(create_if_missing)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Full)
        .busy_timeout(SQLITE_BUSY_TIMEOUT)
        .connect()
        .await
        .map_err(|_| failure("open_migration_database"))
}

async fn read_database_manifest(
    connection: &mut SqliteConnection,
) -> StorageResult<Vec<MigrationFingerprint>> {
    let table_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name = '_sqlx_migrations'",
    )
    .fetch_one(&mut *connection)
    .await
    .map_err(|_| failure("inspect_migration_table"))?;
    if table_count == 0 {
        let user_object_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'")
                .fetch_one(&mut *connection)
                .await
                .map_err(|_| failure("inspect_legacy_empty_database"))?;
        if user_object_count == 0 {
            return Ok(Vec::new());
        }
        return Err(failure("missing_migration_table"));
    }
    if table_count != 1 {
        return Err(failure("invalid_migration_table"));
    }

    let rows = sqlx::query(
        "SELECT version, success, checksum FROM _sqlx_migrations ORDER BY version LIMIT 257",
    )
    .fetch_all(&mut *connection)
    .await
    .map_err(|_| failure("read_migration_manifest"))?;
    if rows.len() > MAX_MIGRATIONS {
        return Err(failure("migration_manifest_too_large"));
    }

    let mut result = Vec::with_capacity(rows.len());
    let mut previous_version = None;
    for row in rows {
        let version = row
            .try_get::<i64, _>("version")
            .map_err(|_| failure("decode_migration_manifest"))?;
        let success = row
            .try_get::<i64, _>("success")
            .map_err(|_| failure("decode_migration_manifest"))?;
        let checksum = row
            .try_get::<Vec<u8>, _>("checksum")
            .map_err(|_| failure("decode_migration_manifest"))?;
        if success != 1
            || version <= 0
            || previous_version.is_some_and(|previous| version <= previous)
            || checksum.len() * 2 != SHA384_HEX_BYTES
        {
            return Err(failure("dirty_or_invalid_migration_manifest"));
        }
        result.push(MigrationFingerprint {
            version,
            checksum: encode_hex(&checksum),
        });
        previous_version = Some(version);
    }
    Ok(result)
}

async fn validate_exact_database(
    connection: &mut SqliteConnection,
    expected: &[MigrationFingerprint],
) -> StorageResult<()> {
    let actual = read_database_manifest(connection).await?;
    if actual != expected {
        return Err(failure("migration_manifest_mismatch"));
    }
    validate_database_health(connection).await
}

async fn validate_database_health(connection: &mut SqliteConnection) -> StorageResult<()> {
    let page_count: i64 = sqlx::query_scalar("PRAGMA page_count")
        .fetch_one(&mut *connection)
        .await
        .map_err(|_| failure("read_database_page_count"))?;
    let page_size: i64 = sqlx::query_scalar("PRAGMA page_size")
        .fetch_one(&mut *connection)
        .await
        .map_err(|_| failure("read_database_page_size"))?;
    let logical_bytes = page_count
        .checked_mul(page_size)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(|| failure("invalid_database_page_size"))?;
    if page_count < 0 || page_size <= 0 || logical_bytes > MAX_DATABASE_BYTES {
        return Err(failure("database_size_limit"));
    }

    let quick_check: String = sqlx::query_scalar("PRAGMA quick_check(1)")
        .fetch_one(&mut *connection)
        .await
        .map_err(|_| failure("database_quick_check"))?;
    if quick_check != "ok" {
        return Err(failure("database_quick_check"));
    }
    if sqlx::query("PRAGMA foreign_key_check")
        .fetch_optional(&mut *connection)
        .await
        .map_err(|_| failure("database_foreign_key_check"))?
        .is_some()
    {
        return Err(failure("database_foreign_key_check"));
    }
    Ok(())
}

async fn checkpoint_and_validate(
    path: &PrivateDatabasePath,
    connection: &mut SqliteConnection,
) -> StorageResult<()> {
    let (busy, log_frames, checkpointed_frames): (i64, i64, i64) =
        sqlx::query_as("PRAGMA wal_checkpoint(TRUNCATE)")
            .fetch_one(&mut *connection)
            .await
            .map_err(|_| failure("checkpoint_database"))?;
    if busy != 0 || log_frames != checkpointed_frames {
        return Err(failure("checkpoint_database_busy"));
    }
    if path
        .inspect_artifact(DatabaseArtifact::Wal)?
        .is_some_and(|bytes| bytes != 0)
    {
        return Err(failure("checkpoint_wal_not_truncated"));
    }
    Ok(())
}

fn embedded_manifest(migrator: &Migrator) -> StorageResult<Vec<MigrationFingerprint>> {
    if migrator.table_name.as_ref() != SQLX_MIGRATION_TABLE {
        return Err(failure("unexpected_migration_table"));
    }
    let upward = migrator
        .iter()
        .filter(|migration| migration.migration_type.is_up_migration())
        .collect::<Vec<_>>();
    if upward.len() > MAX_MIGRATIONS {
        return Err(failure("embedded_migration_limit"));
    }
    let mut result = Vec::with_capacity(upward.len());
    let mut previous_version = None;
    for migration in upward {
        if migration.no_tx
            || migration.version <= 0
            || previous_version.is_some_and(|previous| migration.version <= previous)
            || migration.checksum.len() * 2 != SHA384_HEX_BYTES
        {
            return Err(failure("invalid_embedded_migration"));
        }
        result.push(MigrationFingerprint {
            version: migration.version,
            checksum: encode_hex(migration.checksum.as_ref()),
        });
        previous_version = Some(migration.version);
    }
    Ok(result)
}

fn validate_applied_prefix(
    applied: &[MigrationFingerprint],
    embedded: &[MigrationFingerprint],
) -> StorageResult<()> {
    if applied.len() > embedded.len() || applied != &embedded[..applied.len()] {
        return Err(failure("applied_migration_not_prefix"));
    }
    Ok(())
}

fn validate_marker(marker: &MigrationMarker) -> StorageResult<()> {
    if marker.format_version != MARKER_FORMAT_VERSION {
        return Err(failure("unsupported_marker_version"));
    }
    validate_manifest(&marker.source)?;
    validate_manifest(&marker.target)?;
    validate_applied_prefix(&marker.source, &marker.target)?;
    match (marker.kind, marker.backup.as_ref()) {
        (MarkerKind::Fresh, None) if marker.source.is_empty() => Ok(()),
        (MarkerKind::Backup, Some(backup))
            if backup.slot == BackupSlot::Primary
                && marker.source.len() < marker.target.len()
                && backup.byte_length > 0
                && backup.byte_length <= MAX_DATABASE_BYTES
                && is_lower_hex(&backup.sha256, SHA256_HEX_BYTES) =>
        {
            Ok(())
        }
        _ => Err(failure("invalid_migration_marker")),
    }
}

fn validate_manifest(manifest: &[MigrationFingerprint]) -> StorageResult<()> {
    if manifest.len() > MAX_MIGRATIONS {
        return Err(failure("migration_manifest_too_large"));
    }
    let mut previous_version = None;
    for migration in manifest {
        if migration.version <= 0
            || previous_version.is_some_and(|previous| migration.version <= previous)
            || !is_lower_hex(&migration.checksum, SHA384_HEX_BYTES)
        {
            return Err(failure("invalid_migration_manifest"));
        }
        previous_version = Some(migration.version);
    }
    Ok(())
}

fn read_marker(path: &PrivateDatabasePath) -> StorageResult<Option<MigrationMarker>> {
    let Some(length) = path.inspect_artifact(DatabaseArtifact::MigrationState)? else {
        return Ok(None);
    };
    if length == 0 || length > MAX_MARKER_BYTES {
        return Err(failure("invalid_marker_size"));
    }
    let mut file = path
        .open_artifact(DatabaseArtifact::MigrationState)?
        .ok_or_else(|| failure("marker_disappeared"))?;
    let mut bytes = Vec::with_capacity(length as usize);
    Read::take(&mut file, MAX_MARKER_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| failure("read_migration_marker"))?;
    if bytes.len() as u64 != length || bytes.len() as u64 > MAX_MARKER_BYTES {
        return Err(failure("invalid_marker_size"));
    }
    path.validate_artifact_identity(DatabaseArtifact::MigrationState, &file)?;
    let marker = serde_json::from_slice::<MigrationMarker>(&bytes)
        .map_err(|_| failure("parse_migration_marker"))?;
    validate_marker(&marker)?;
    Ok(Some(marker))
}

fn publish_marker(path: &PrivateDatabasePath, marker: &MigrationMarker) -> StorageResult<()> {
    validate_marker(marker)?;
    if path
        .inspect_artifact(DatabaseArtifact::MigrationState)?
        .is_some()
    {
        return Err(failure("migration_marker_already_exists"));
    }
    path.remove_artifact(DatabaseArtifact::MigrationStatePartial)?;
    let bytes = serde_json::to_vec(marker).map_err(|_| failure("serialize_migration_marker"))?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_MARKER_BYTES {
        return Err(failure("invalid_marker_size"));
    }
    let mut file = path.create_artifact(DatabaseArtifact::MigrationStatePartial)?;
    file.write_all(&bytes)
        .map_err(|_| failure("write_migration_marker"))?;
    file.sync_all()
        .map_err(|_| failure("sync_migration_marker"))?;
    path.validate_artifact_identity(DatabaseArtifact::MigrationStatePartial, &file)?;
    path.replace_artifact_required(
        DatabaseArtifact::MigrationStatePartial,
        DatabaseArtifact::MigrationState,
        &file,
    )?;
    path.sync_root()
}

fn clear_marker(path: &PrivateDatabasePath) -> StorageResult<()> {
    path.remove_artifact(DatabaseArtifact::MigrationStatePartial)?;
    path.remove_artifact(DatabaseArtifact::MigrationState)?;
    path.sync_root()
}

fn cleanup_unreferenced_partials(path: &PrivateDatabasePath) -> StorageResult<()> {
    path.discard_sqlite_artifact(DatabaseArtifact::BackupPartialJournal)?;
    path.discard_sqlite_artifact(DatabaseArtifact::BackupPartial)?;
    path.discard_sqlite_artifact(DatabaseArtifact::RestorePartial)?;
    path.remove_artifact(DatabaseArtifact::MigrationStatePartial)?;
    path.sync_root()
}

fn sqlite_sidecar_exists(path: &PrivateDatabasePath) -> StorageResult<bool> {
    for artifact in [
        DatabaseArtifact::Wal,
        DatabaseArtifact::SharedMemory,
        DatabaseArtifact::Journal,
    ] {
        if path.inspect_artifact(artifact)?.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn data_bearing_recovery_artifact_exists(path: &PrivateDatabasePath) -> StorageResult<bool> {
    for artifact in [
        DatabaseArtifact::BackupPrimary,
        DatabaseArtifact::BackupPrevious,
        DatabaseArtifact::BackupPartial,
        DatabaseArtifact::BackupPartialJournal,
        DatabaseArtifact::RestorePartial,
    ] {
        if path.inspect_artifact(artifact)?.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn validate_live_file_limits(path: &PrivateDatabasePath) -> StorageResult<()> {
    let main = path
        .inspect_artifact(DatabaseArtifact::Main)?
        .ok_or_else(|| failure("missing_database"))?;
    let wal = path
        .inspect_artifact(DatabaseArtifact::Wal)?
        .unwrap_or_default();
    let shared_memory = path
        .inspect_artifact(DatabaseArtifact::SharedMemory)?
        .unwrap_or_default();
    let journal = path
        .inspect_artifact(DatabaseArtifact::Journal)?
        .unwrap_or_default();
    if main > MAX_DATABASE_BYTES
        || main
            .checked_add(wal)
            .is_none_or(|bytes| bytes > MAX_DATABASE_AND_WAL_BYTES)
        || shared_memory > MAX_SHARED_MEMORY_BYTES
        || journal > MAX_DATABASE_BYTES
    {
        return Err(failure("database_file_size_limit"));
    }
    Ok(())
}

fn validate_retained_limits(path: &PrivateDatabasePath) -> StorageResult<()> {
    for artifact in [
        DatabaseArtifact::BackupPrimary,
        DatabaseArtifact::BackupPrevious,
    ] {
        if path
            .inspect_artifact(artifact)?
            .is_some_and(|bytes| bytes > MAX_DATABASE_BYTES)
        {
            return Err(failure("backup_retention_size_limit"));
        }
    }
    Ok(())
}

fn remove_sqlite_sidecars(path: &PrivateDatabasePath) -> StorageResult<()> {
    path.discard_sqlite_artifact(DatabaseArtifact::Wal)?;
    path.discard_sqlite_artifact(DatabaseArtifact::SharedMemory)?;
    path.discard_sqlite_artifact(DatabaseArtifact::Journal)
}

fn remove_sqlite_database_files(path: &PrivateDatabasePath) -> StorageResult<()> {
    remove_sqlite_sidecars(path)?;
    path.discard_sqlite_artifact(DatabaseArtifact::Main)
}

fn hash_open_file(
    path: &PrivateDatabasePath,
    artifact: DatabaseArtifact,
    file: &mut File,
    max_bytes: u64,
) -> StorageResult<(u64, String)> {
    path.validate_artifact_identity(artifact, file)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| failure("seek_database_artifact"))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    let mut total = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| failure("read_database_artifact"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| failure("database_artifact_size_overflow"))?;
        if total > max_bytes {
            return Err(failure("database_artifact_size_limit"));
        }
        digest.update(&buffer[..read]);
    }
    path.validate_artifact_identity(artifact, file)?;
    if file
        .metadata()
        .map_err(|_| failure("inspect_database_artifact"))?
        .len()
        != total
    {
        return Err(failure("database_artifact_changed"));
    }
    Ok((total, encode_hex(&digest.finalize())))
}

fn copy_open_file(
    source: &mut File,
    destination: &mut File,
    max_bytes: u64,
) -> StorageResult<(u64, String)> {
    source
        .seek(SeekFrom::Start(0))
        .map_err(|_| failure("seek_migration_backup"))?;
    destination
        .seek(SeekFrom::Start(0))
        .map_err(|_| failure("seek_restore_copy"))?;
    destination
        .set_len(0)
        .map_err(|_| failure("truncate_restore_copy"))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; COPY_BUFFER_BYTES];
    let mut total = 0_u64;
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(|_| failure("read_migration_backup"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| failure("restore_copy_size_overflow"))?;
        if total > max_bytes {
            return Err(failure("restore_copy_size_limit"));
        }
        destination
            .write_all(&buffer[..read])
            .map_err(|_| failure("write_restore_copy"))?;
        digest.update(&buffer[..read]);
    }
    Ok((total, encode_hex(&digest.finalize())))
}

fn utf8_artifact_path(
    path: &PrivateDatabasePath,
    artifact: DatabaseArtifact,
) -> StorageResult<String> {
    let artifact_path = path.artifact_path(artifact);
    ensure_utf8_path(&artifact_path)?;
    Ok(artifact_path
        .to_str()
        .expect("validated UTF-8 database artifact path")
        .to_owned())
}

fn ensure_utf8_path(path: &Path) -> StorageResult<()> {
    if path.to_str().is_none() {
        Err(failure("database_path_not_utf8"))
    } else {
        Ok(())
    }
}

async fn close_connection(connection: SqliteConnection, phase: &'static str) -> StorageResult<()> {
    connection.close().await.map_err(|_| failure(phase))
}

async fn close_quietly(connection: SqliteConnection) {
    let _ = connection.close().await;
}

fn is_lower_hex(value: &str, expected_bytes: usize) -> bool {
    value.len() == expected_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn failure(phase: &'static str) -> domain::AppError {
    migration_recovery_error(phase)
}
