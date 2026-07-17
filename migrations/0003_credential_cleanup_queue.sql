CREATE TABLE credential_cleanup_queue (
    credential_ref TEXT PRIMARY KEY NOT NULL CHECK (length(credential_ref) > 0)
);

CREATE INDEX idx_profile_environment_credential_ref
    ON profile_environment(credential_ref)
    WHERE credential_ref IS NOT NULL;
