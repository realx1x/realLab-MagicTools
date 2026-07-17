DROP TRIGGER catalog_mutation_ledger_capacity_guard;

ALTER TABLE catalog_mutation_ledger RENAME TO catalog_mutation_ledger_v1;

CREATE TABLE catalog_mutation_ledger (
    operation_id TEXT PRIMARY KEY NOT NULL CHECK (
        length(trim(operation_id)) > 0
        AND length(CAST(operation_id AS BLOB)) <= 128
        AND operation_id NOT GLOB '*[^A-Za-z0-9_.:-]*'
    ),
    method TEXT NOT NULL CHECK (
        method IN (
            'project.save',
            'project.delete',
            'rule.save',
            'rule.delete',
            'profile.save',
            'profile.delete'
        )
    ),
    request_sha256 BLOB NOT NULL CHECK (
        typeof(request_sha256) = 'blob'
        AND length(request_sha256) = 32
    ),
    result_json TEXT NOT NULL CHECK (
        json_valid(result_json)
        AND json_type(result_json) = 'object'
        AND length(CAST(result_json AS BLOB)) <= 262144
    ),
    recorded_at TEXT NOT NULL CHECK (length(recorded_at) = 30)
);

INSERT INTO catalog_mutation_ledger (
    operation_id,
    method,
    request_sha256,
    result_json,
    recorded_at
)
SELECT
    operation_id,
    method,
    request_sha256,
    result_json,
    recorded_at
FROM catalog_mutation_ledger_v1;

DROP TABLE catalog_mutation_ledger_v1;

CREATE TRIGGER catalog_mutation_ledger_capacity_guard
BEFORE INSERT ON catalog_mutation_ledger
WHEN (SELECT COUNT(*) FROM catalog_mutation_ledger) >= 16384
BEGIN
    SELECT RAISE(ABORT, 'catalog mutation ledger capacity exhausted');
END;
