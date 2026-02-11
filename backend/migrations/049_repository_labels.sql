-- Repository labels: key:value tags for sync policy matching
CREATE TABLE IF NOT EXISTS repository_labels (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    label_key VARCHAR(128) NOT NULL,
    label_value VARCHAR(256) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(repository_id, label_key)
);

CREATE INDEX IF NOT EXISTS idx_repository_labels_repo ON repository_labels(repository_id);
CREATE INDEX IF NOT EXISTS idx_repository_labels_key_value ON repository_labels(label_key, label_value);

COMMENT ON TABLE repository_labels IS 'Key:value labels on repositories for sync policy matching and organization';
COMMENT ON COLUMN repository_labels.label_key IS 'Label key (e.g. env, tier, team)';
COMMENT ON COLUMN repository_labels.label_value IS 'Label value (e.g. production, critical, platform). Empty string for bare tags.';
