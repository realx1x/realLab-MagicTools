ALTER TABLE runs ADD COLUMN process_group_id INTEGER CHECK (
    process_group_id IS NULL
    OR (
        process_group_id BETWEEN 1 AND 2147483647
        AND process_pid IS NOT NULL
        AND process_group_id = process_pid
    )
);
