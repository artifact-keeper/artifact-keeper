-- Create the dedicated email_subscriptions table and seed it from the
-- existing notification_subscriptions rows where channel='email'
-- (artifact-keeper#919, #927).
--
-- Schema mirrors notification_subscriptions but trims the channel column
-- (always email) and lifts the recipients array out of the jsonb config
-- column for cheaper indexing and validation. The notification_dispatcher
-- continues to read from notification_subscriptions in v1.1.9, so this
-- table is populated but not yet authoritative. The dedicated email
-- producer that consumes this table will land alongside the v1.2.0
-- System B removal (artifact-keeper#920).
--
-- Idempotency: the seed step uses the existing subscription id as the
-- email_subscriptions id, so re-running this migration is a no-op via
-- the NOT EXISTS guard.

CREATE TABLE email_subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE,
    recipients TEXT[] NOT NULL,
    event_types TEXT[] NOT NULL DEFAULT '{}',
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_email_subscriptions_repo
    ON email_subscriptions(repository_id)
    WHERE repository_id IS NOT NULL;

CREATE INDEX idx_email_subscriptions_enabled
    ON email_subscriptions(enabled)
    WHERE enabled = true;

-- Seed from notification_subscriptions where channel='email'.
INSERT INTO email_subscriptions (
    id,
    repository_id,
    recipients,
    event_types,
    enabled,
    created_at,
    updated_at
)
SELECT
    ns.id,
    ns.repository_id,
    ARRAY(SELECT jsonb_array_elements_text(ns.config->'recipients')) AS recipients,
    ns.event_types,
    ns.enabled,
    ns.created_at,
    ns.updated_at
FROM notification_subscriptions ns
WHERE ns.channel = 'email'
  AND ns.config ? 'recipients'
  AND jsonb_typeof(ns.config->'recipients') = 'array'
  AND NOT EXISTS (
      SELECT 1 FROM email_subscriptions es WHERE es.id = ns.id
  );
