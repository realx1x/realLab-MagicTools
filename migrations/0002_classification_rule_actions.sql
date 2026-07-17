CREATE TABLE classification_rules_v2 (
    id TEXT PRIMARY KEY NOT NULL CHECK (length(trim(id)) > 0),
    rule_type TEXT NOT NULL CHECK (
        rule_type IN (
            'EXECUTABLE_NAME_EXACT',
            'EXECUTABLE_PATH_EXACT',
            'COMMAND_LINE_CONTAINS',
            'WORKING_DIRECTORY_PREFIX'
        )
    ),
    pattern TEXT NOT NULL CHECK (length(trim(pattern)) > 0),
    action TEXT NOT NULL CHECK (
        action IN ('INCLUDE', 'EXCLUDE', 'ASSIGN_PROJECT')
    ),
    project_id TEXT REFERENCES projects(id) ON UPDATE CASCADE ON DELETE CASCADE,
    priority INTEGER NOT NULL,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    created_at TEXT NOT NULL CHECK (length(created_at) > 0),
    updated_at TEXT NOT NULL CHECK (length(updated_at) > 0),
    CHECK (
        (action = 'ASSIGN_PROJECT' AND project_id IS NOT NULL)
        OR
        (action IN ('INCLUDE', 'EXCLUDE') AND project_id IS NULL)
    )
);

INSERT INTO classification_rules_v2 (
    id,
    rule_type,
    pattern,
    action,
    project_id,
    priority,
    enabled,
    created_at,
    updated_at
)
SELECT
    id,
    rule_type,
    pattern,
    action,
    NULL,
    priority,
    enabled,
    created_at,
    updated_at
FROM classification_rules;

DROP TABLE classification_rules;
ALTER TABLE classification_rules_v2 RENAME TO classification_rules;

CREATE INDEX idx_classification_rules_enabled_priority
    ON classification_rules(enabled, priority DESC, id);
CREATE INDEX idx_classification_rules_project_id
    ON classification_rules(project_id)
    WHERE project_id IS NOT NULL;
CREATE UNIQUE INDEX idx_classification_rules_ordinary_action
    ON classification_rules(rule_type, pattern, action)
    WHERE action IN ('INCLUDE', 'EXCLUDE');
CREATE UNIQUE INDEX idx_classification_rules_assign_project
    ON classification_rules(rule_type, pattern, project_id)
    WHERE action = 'ASSIGN_PROJECT';
