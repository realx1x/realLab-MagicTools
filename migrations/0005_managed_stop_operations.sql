CREATE TABLE managed_stop_operations (
    operation_id TEXT PRIMARY KEY NOT NULL CHECK (
        length(operation_id) BETWEEN 1 AND 128
        AND operation_id NOT GLOB '*[^A-Za-z0-9_.:-]*'
    ),
    run_id TEXT NOT NULL CHECK (length(trim(run_id)) BETWEEN 1 AND 256)
        REFERENCES runs(id) ON UPDATE CASCADE ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('GRACEFUL', 'FORCE')),
    status TEXT NOT NULL CHECK (
        status IN (
            'REQUESTED',
            'SIGNAL_PENDING',
            'IN_PROGRESS',
            'TIMED_OUT',
            'COMPLETED',
            'SUPERSEDED'
        )
    ),
    signal_disposition TEXT CHECK (
        signal_disposition IS NULL OR signal_disposition IN ('DELIVERED', 'UNAVAILABLE')
    ),
    outcome TEXT CHECK (
        outcome IS NULL OR outcome IN (
            'EXITED',
            'ALREADY_EXITED',
            'IDENTITY_MISMATCH',
            'ORPHANED',
            'SIGNAL_UNAVAILABLE',
            'FAILED'
        )
    ),
    supersedes_operation_id TEXT UNIQUE CHECK (
        supersedes_operation_id IS NULL OR (
            length(supersedes_operation_id) BETWEEN 1 AND 128
            AND supersedes_operation_id NOT GLOB '*[^A-Za-z0-9_.:-]*'
        )
    ) REFERENCES managed_stop_operations(operation_id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    created_at TEXT NOT NULL CHECK (length(created_at) BETWEEN 1 AND 128),
    updated_at TEXT NOT NULL CHECK (length(updated_at) BETWEEN 1 AND 128),
    completed_at TEXT CHECK (completed_at IS NULL OR length(completed_at) BETWEEN 1 AND 128),
    CHECK (
        (status IN ('COMPLETED', 'SUPERSEDED') AND completed_at IS NOT NULL)
        OR
        (status NOT IN ('COMPLETED', 'SUPERSEDED') AND completed_at IS NULL)
    ),
    CHECK (
        (status = 'COMPLETED' AND outcome IS NOT NULL)
        OR
        (status <> 'COMPLETED' AND outcome IS NULL)
    ),
    CHECK (status <> 'TIMED_OUT' OR kind = 'GRACEFUL'),
    CHECK (status <> 'SUPERSEDED' OR kind = 'GRACEFUL'),
    CHECK (
        status NOT IN ('REQUESTED', 'SIGNAL_PENDING') OR signal_disposition IS NULL
    ),
    CHECK (
        status NOT IN ('IN_PROGRESS', 'TIMED_OUT') OR signal_disposition IS NOT NULL
    ),
    CHECK (
        supersedes_operation_id IS NULL
        OR (kind = 'FORCE' AND supersedes_operation_id <> operation_id)
    ),
    CHECK (
        outcome IS NOT 'SIGNAL_UNAVAILABLE' OR signal_disposition IS 'UNAVAILABLE'
    )
);

CREATE UNIQUE INDEX idx_managed_stop_operations_active_run
    ON managed_stop_operations(run_id)
    WHERE status IN ('REQUESTED', 'SIGNAL_PENDING', 'IN_PROGRESS', 'TIMED_OUT');

CREATE INDEX idx_managed_stop_operations_run_created
    ON managed_stop_operations(run_id, created_at DESC, operation_id DESC);
