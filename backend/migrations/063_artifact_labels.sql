-- Artifact labels: key:value tags for sync policy artifact filtering.
-- Follows the same pattern as repository_labels (049) and peer_instance_labels (052).

CREATE TABLE IF NOT EXISTS artifact_labels (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_id UUID NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    label_key VARCHAR(128) NOT NULL,
    label_value VARCHAR(256) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(artifact_id, label_key)
);

CREATE INDEX IF NOT EXISTS idx_artifact_labels_artifact ON artifact_labels(artifact_id);
CREATE INDEX IF NOT EXISTS idx_artifact_labels_key_value ON artifact_labels(label_key, label_value);
