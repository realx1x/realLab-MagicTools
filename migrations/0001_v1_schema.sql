CREATE TABLE projects (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(trim(id)) > 0),
    name TEXT NOT NULL CHECK (length(trim(name)) > 0),
    root_directory TEXT NOT NULL CHECK (length(root_directory) > 0),
    normalized_path TEXT NOT NULL UNIQUE CHECK (length(normalized_path) > 0),
    created_at TEXT NOT NULL CHECK (length(created_at) > 0),
    updated_at TEXT NOT NULL CHECK (length(updated_at) > 0)
);

CREATE TABLE launch_profiles (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(trim(id)) > 0),
    project_id TEXT REFERENCES projects(id) ON UPDATE CASCADE ON DELETE SET NULL,
    name TEXT NOT NULL CHECK (length(trim(name)) > 0),
    execution_mode TEXT NOT NULL CHECK (
        execution_mode IN ('DIRECT', 'SHELL', 'DETECTED_SCRIPT')
    ),
    executable TEXT NOT NULL CHECK (length(executable) > 0),
    arguments_json TEXT NOT NULL CHECK (
        json_valid(arguments_json) AND json_type(arguments_json) = 'array'
    ),
    working_directory TEXT NOT NULL CHECK (length(working_directory) > 0),
    shell TEXT,
    interactive INTEGER NOT NULL CHECK (interactive IN (0, 1)),
    stop_timeout_ms INTEGER NOT NULL CHECK (stop_timeout_ms >= 0),
    created_at TEXT NOT NULL CHECK (length(created_at) > 0),
    updated_at TEXT NOT NULL CHECK (length(updated_at) > 0),
    UNIQUE (project_id, name)
);

CREATE INDEX idx_launch_profiles_project_id
    ON launch_profiles(project_id);

CREATE TABLE profile_environment (
    profile_id TEXT NOT NULL REFERENCES launch_profiles(id) ON UPDATE CASCADE ON DELETE CASCADE,
    name TEXT NOT NULL CHECK (length(name) > 0),
    value TEXT,
    credential_ref TEXT,
    CHECK (
        (value IS NOT NULL AND credential_ref IS NULL)
        OR
        (value IS NULL AND credential_ref IS NOT NULL AND length(credential_ref) > 0)
    ),
    PRIMARY KEY (profile_id, name)
);

CREATE TABLE runs (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(trim(id)) > 0),
    profile_id TEXT REFERENCES launch_profiles(id) ON UPDATE CASCADE ON DELETE SET NULL,
    profile_snapshot_json TEXT NOT NULL CHECK (
        json_valid(profile_snapshot_json) AND json_type(profile_snapshot_json) = 'object'
    ),
    process_boot_id TEXT CHECK (process_boot_id IS NULL OR length(process_boot_id) > 0),
    process_pid INTEGER CHECK (process_pid BETWEEN 1 AND 4294967295),
    process_native_start_time TEXT CHECK (
        process_native_start_time IS NULL OR length(process_native_start_time) > 0
    ),
    state TEXT NOT NULL CHECK (
        state IN (
            'STARTING',
            'RUNNING',
            'STOP_REQUESTED',
            'GRACEFUL_STOPPING',
            'FORCE_STOPPING',
            'EXITED',
            'FAILED',
            'RECOVERED',
            'EXITED_WHILE_OFFLINE',
            'IDENTITY_MISMATCH',
            'ORPHANED'
        )
    ),
    exit_code INTEGER,
    exit_signal TEXT,
    exit_summary TEXT,
    stop_method TEXT,
    log_directory TEXT NOT NULL CHECK (length(log_directory) > 0),
    recovery_state TEXT CHECK (
        recovery_state IS NULL OR recovery_state IN (
            'RECOVERED',
            'EXITED_WHILE_OFFLINE',
            'IDENTITY_MISMATCH',
            'ORPHANED'
        )
    ),
    started_at TEXT NOT NULL CHECK (length(started_at) > 0),
    updated_at TEXT NOT NULL CHECK (length(updated_at) > 0),
    ended_at TEXT,
    CHECK (
        (process_boot_id IS NULL AND process_pid IS NULL AND process_native_start_time IS NULL)
        OR
        (process_boot_id IS NOT NULL AND process_pid IS NOT NULL AND process_native_start_time IS NOT NULL)
    )
);

CREATE INDEX idx_runs_profile_started_at
    ON runs(profile_id, started_at DESC);
CREATE INDEX idx_runs_state_updated_at
    ON runs(state, updated_at DESC);
CREATE UNIQUE INDEX idx_runs_process_instance_key
    ON runs(process_boot_id, process_pid, process_native_start_time)
    WHERE process_boot_id IS NOT NULL
      AND process_pid IS NOT NULL
      AND process_native_start_time IS NOT NULL;

CREATE TABLE classification_rules (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(trim(id)) > 0),
    rule_type TEXT NOT NULL CHECK (length(trim(rule_type)) > 0),
    pattern TEXT NOT NULL CHECK (length(pattern) > 0),
    action TEXT NOT NULL CHECK (length(trim(action)) > 0),
    priority INTEGER NOT NULL,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    created_at TEXT NOT NULL CHECK (length(created_at) > 0),
    updated_at TEXT NOT NULL CHECK (length(updated_at) > 0),
    UNIQUE (rule_type, pattern, action)
);

CREATE INDEX idx_classification_rules_enabled_priority
    ON classification_rules(enabled, priority DESC, id);

CREATE TABLE audit_events (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(trim(id)) > 0),
    run_id TEXT REFERENCES runs(id) ON UPDATE CASCADE ON DELETE SET NULL,
    event_type TEXT NOT NULL CHECK (length(trim(event_type)) > 0),
    summary TEXT NOT NULL CHECK (length(summary) > 0),
    details_json TEXT CHECK (details_json IS NULL OR json_valid(details_json)),
    occurred_at TEXT NOT NULL CHECK (length(occurred_at) > 0),
    retention_until TEXT NOT NULL CHECK (length(retention_until) > 0)
);

CREATE INDEX idx_audit_events_run_occurred_at
    ON audit_events(run_id, occurred_at DESC);
CREATE INDEX idx_audit_events_retention_until
    ON audit_events(retention_until);

CREATE TABLE app_settings (
    key TEXT PRIMARY KEY NOT NULL CHECK (length(trim(key)) > 0),
    value_json TEXT NOT NULL CHECK (json_valid(value_json)),
    updated_at TEXT NOT NULL CHECK (length(updated_at) > 0)
);
