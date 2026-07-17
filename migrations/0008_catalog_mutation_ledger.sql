CREATE TABLE catalog_mutation_ledger (
    operation_id TEXT PRIMARY KEY NOT NULL CHECK (
        length(trim(operation_id)) > 0
        AND length(CAST(operation_id AS BLOB)) <= 128
        AND operation_id NOT GLOB '*[^A-Za-z0-9_.:-]*'
    ),
    method TEXT NOT NULL CHECK (
        method IN ('project.save', 'project.delete', 'rule.save', 'rule.delete')
    ),
    request_sha256 BLOB NOT NULL CHECK (
        typeof(request_sha256) = 'blob'
        AND length(request_sha256) = 32
    ),
    result_json TEXT NOT NULL CHECK (
        json_valid(result_json)
        AND json_type(result_json) = 'object'
    ),
    recorded_at TEXT NOT NULL CHECK (length(recorded_at) = 30)
);

CREATE TRIGGER catalog_mutation_ledger_capacity_guard
BEFORE INSERT ON catalog_mutation_ledger
WHEN (SELECT COUNT(*) FROM catalog_mutation_ledger) >= 16384
BEGIN
    SELECT RAISE(ABORT, 'catalog mutation ledger capacity exhausted');
END;
