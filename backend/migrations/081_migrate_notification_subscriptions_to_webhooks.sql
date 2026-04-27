-- Migrate notification_subscriptions (System B) rows where channel='webhook'
-- into the webhooks table (System A) as part of the v1.1.9 webhooks v2 work
-- (artifact-keeper#919, #927).
--
-- Idempotency: enforced by a unique partial index on (url, repository_id)
-- created BEFORE the INSERT below. The INSERT uses ON CONFLICT DO NOTHING
-- so re-running this migration is a no-op even under concurrent runs. The
-- prior NOT EXISTS guard was probabilistic; this is a hard constraint.
-- A subscription is treated as already-migrated if a webhooks row exists
-- with the same URL and the same repository_id (or both NULL for
-- global-scoped subscriptions).
--
-- Retention: existing notification_subscriptions rows are NOT deleted by
-- this migration. System B continues to deliver notifications during the
-- v1.1.9 deprecation window so customers do not lose deliveries while
-- they migrate. The actual System B removal lands in v1.2.0
-- (artifact-keeper#920) once the deprecation window closes.
--
-- Secrets: secret_hash is intentionally left NULL. Migrated rows have
-- NEITHER a bcrypt secret_hash NOR a secret_encrypted value. The
-- notification subscription's plaintext config.secret cannot safely be
-- transcribed into either column, so customers must call
-- /api/v1/webhooks/{id}/rotate-secret to mint a fresh signing secret on
-- the migrated row. Webhooks where both forms are NULL still deliver, but
-- the retry path emits NO X-Webhook-Signature header so receivers can
-- distinguish "configured but legacy/unsigned" from "actively signed".
--
-- Event-type mapping: notifications use dot-separated names
-- (artifact.uploaded), webhooks use underscore-separated names
-- (artifact_uploaded). The CASE expression below mirrors
-- backend/src/services/notification_dispatcher.rs::
-- NOTIFICATION_TO_WEBHOOK_EVENT_MAP. Keep both in sync; the unit test
-- `notification_dispatcher::tests::test_migration_081_case_matches_rust_map`
-- regex-extracts the WHEN/THEN pairs from this file and asserts they equal
-- the Rust constant.

-- Idempotency guard: hard uniqueness on (url, repository_id) treating NULL
-- repository_id as a synthetic zero-UUID so the constraint covers both
-- repo-scoped and global-scoped webhooks.
CREATE UNIQUE INDEX IF NOT EXISTS idx_webhooks_url_repo_unique
    ON webhooks (url, COALESCE(repository_id, '00000000-0000-0000-0000-000000000000'::uuid));

INSERT INTO webhooks (
    id,
    name,
    url,
    secret_hash,
    events,
    is_enabled,
    repository_id,
    headers,
    payload_template,
    created_at,
    updated_at
)
SELECT
    gen_random_uuid(),
    'Migrated from notification ' || ns.id::text AS name,
    (ns.config->>'url')::text AS url,
    NULL AS secret_hash,
    ARRAY(
        SELECT
            CASE
                WHEN e = 'artifact.uploaded' THEN 'artifact_uploaded'
                WHEN e = 'artifact.deleted' THEN 'artifact_deleted'
                WHEN e = 'scan.completed' THEN 'scan_completed'
                WHEN e = 'scan.vulnerability_found' THEN 'scan_vulnerability_found'
                WHEN e = 'repository.updated' THEN 'repository_updated'
                WHEN e = 'repository.deleted' THEN 'repository_deleted'
                WHEN e = 'build.completed' THEN 'build_completed'
                WHEN e = 'build.failed' THEN 'build_failed'
                ELSE e
            END
        FROM unnest(ns.event_types) AS e
    ) AS events,
    ns.enabled AS is_enabled,
    ns.repository_id,
    '{}'::jsonb AS headers,
    'generic' AS payload_template,
    ns.created_at,
    NOW() AS updated_at
FROM notification_subscriptions ns
WHERE ns.channel = 'webhook'
  AND (ns.config->>'url') IS NOT NULL
ON CONFLICT DO NOTHING;
