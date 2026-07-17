ALTER TABLE runs ADD COLUMN log_redaction_version INTEGER NOT NULL DEFAULT 0 CHECK (
    log_redaction_version BETWEEN 0 AND 1
);

ALTER TABLE runs ADD COLUMN logs_deletion_started_at TEXT CHECK (
    logs_deletion_started_at IS NULL
    OR (
        length(trim(logs_deletion_started_at)) BETWEEN 1 AND 128
        AND state IN (
            'EXITED',
            'FAILED',
            'EXITED_WHILE_OFFLINE',
            'IDENTITY_MISMATCH',
            'ORPHANED'
        )
    )
);

ALTER TABLE runs ADD COLUMN logs_deleted_at TEXT CHECK (
    logs_deleted_at IS NULL
    OR (
        length(trim(logs_deleted_at)) BETWEEN 1 AND 128
        AND logs_deletion_started_at IS NOT NULL
        AND state IN (
            'EXITED',
            'FAILED',
            'EXITED_WHILE_OFFLINE',
            'IDENTITY_MISMATCH',
            'ORPHANED'
        )
    )
);

CREATE INDEX idx_runs_pending_log_retention
    ON runs(COALESCE(ended_at, updated_at), id)
    WHERE logs_deleted_at IS NULL
      AND state IN (
          'EXITED',
          'FAILED',
          'EXITED_WHILE_OFFLINE',
          'IDENTITY_MISMATCH',
          'ORPHANED'
      );
