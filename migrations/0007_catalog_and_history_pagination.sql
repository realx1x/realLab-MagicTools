CREATE INDEX idx_projects_name_id
    ON projects(name COLLATE BINARY, id COLLATE BINARY);

CREATE INDEX idx_classification_rules_priority_id
    ON classification_rules(priority DESC, id COLLATE BINARY);

CREATE INDEX idx_runs_started_at_id
    ON runs(started_at DESC, id DESC);
