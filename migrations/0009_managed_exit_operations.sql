CREATE TABLE managed_exit_operations (
    operation_id TEXT PRIMARY KEY NOT NULL CHECK (
        length(CAST(operation_id AS BLOB)) BETWEEN 1 AND 128
        AND operation_id NOT GLOB '*[^A-Za-z0-9_.:-]*'
    ),
    method TEXT NOT NULL CHECK (method = 'run.stop_all_for_exit'),
    request_sha256 BLOB NOT NULL CHECK (
        typeof(request_sha256) = 'blob'
        AND length(request_sha256) = 32
    ),
    assessment_id TEXT NOT NULL CHECK (
        length(CAST(assessment_id AS BLOB)) = 64
        AND assessment_id NOT GLOB '*[^0-9a-f]*'
    ),
    created_at TEXT NOT NULL CHECK (
        length(CAST(created_at AS BLOB)) = 30
        AND created_at GLOB
            '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]Z'
    )
);

CREATE TABLE managed_exit_operation_members (
    exit_operation_id TEXT NOT NULL
        REFERENCES managed_exit_operations(operation_id)
        ON UPDATE CASCADE ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 15),
    run_id TEXT NOT NULL CHECK (
        length(trim(run_id)) BETWEEN 1 AND 256
        AND length(CAST(run_id AS BLOB)) <= 256
        AND instr(run_id, char(0)) = 0
    ),
    action TEXT NOT NULL CHECK (
        action IN ('NONE', 'GRACEFUL_REQUESTED', 'STOP_ADOPTED')
    ),
    stop_operation_id TEXT CHECK (
        stop_operation_id IS NULL OR (
            length(CAST(stop_operation_id AS BLOB)) BETWEEN 1 AND 128
            AND stop_operation_id NOT GLOB '*[^A-Za-z0-9_.:-]*'
        )
    ),
    PRIMARY KEY (exit_operation_id, ordinal),
    UNIQUE (exit_operation_id, run_id),
    UNIQUE (exit_operation_id, stop_operation_id),
    CHECK (
        (action = 'NONE' AND stop_operation_id IS NULL)
        OR
        (action <> 'NONE' AND stop_operation_id IS NOT NULL)
    )
);

CREATE TRIGGER managed_exit_operations_capacity_guard
BEFORE INSERT ON managed_exit_operations
WHEN (SELECT COUNT(*) FROM managed_exit_operations) >= 4096
BEGIN
    SELECT RAISE(ABORT, 'managed exit operation ledger capacity exhausted');
END;
