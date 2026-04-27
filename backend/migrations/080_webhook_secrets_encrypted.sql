-- Webhooks v2: encrypted-at-rest secrets, write-once display, rotation support.
--
-- Replaces the legacy bcrypt secret_hash with reversible AES-256-GCM ciphertext
-- so the backend can sign delivery payloads (HMAC signing arrives in a later
-- ticket; this migration only lays the storage foundation).
--
-- secret_hash is intentionally retained during the transition. Existing rows
-- have only a bcrypt hash, which is unrecoverable. Operators must call
-- POST /api/v1/webhooks/{id}/rotate-secret to obtain a new signable secret.
-- Until then, deliveries for those rows remain unsigned (matches existing
-- behavior in the retry path, which previously emitted a placeholder header).
-- A follow-up migration drops secret_hash once all rows are rotated.

ALTER TABLE webhooks ADD COLUMN secret_encrypted bytea;
ALTER TABLE webhooks ADD COLUMN secret_digest text;
ALTER TABLE webhooks ADD COLUMN secret_rotation_started_at timestamptz;
ALTER TABLE webhooks ADD COLUMN secret_previous_encrypted bytea;
ALTER TABLE webhooks ADD COLUMN secret_previous_expires_at timestamptz;

-- Partial index used by the previous-secret cleanup tick (see scheduler_service).
CREATE INDEX idx_webhooks_secret_previous_expires_at
    ON webhooks (secret_previous_expires_at)
    WHERE secret_previous_encrypted IS NOT NULL;
