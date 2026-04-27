-- Migrate notification_subscriptions (System B) rows where channel='webhook'
-- into the webhooks table (System A) as part of the v1.1.9 webhooks v2 work
-- (artifact-keeper#919, #927).
--
-- Idempotency: re-running this migration produces no duplicate webhooks.
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
-- Secrets: secret_hash is intentionally left empty. The notification
-- subscription's plaintext config.secret cannot safely be transcribed
-- into the webhooks.secret_hash column (which expects a hash, not a
-- plaintext secret), so customers must re-rotate the secret via the
-- webhooks rotate-secret endpoint to enable HMAC signing on the
-- migrated row. Webhooks with an empty secret still deliver, just
-- without a signature header.
--
-- Event-type mapping: notifications use dot-separated names
-- (artifact.uploaded), webhooks use underscore-separated names
-- (artifact_uploaded). The CASE expression below mirrors
-- backend/src/services/notification_dispatcher.rs::
-- NOTIFICATION_TO_WEBHOOK_EVENT_MAP. Keep both in sync.

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
    '' AS secret_hash,
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
  AND NOT EXISTS (
      SELECT 1
      FROM webhooks w
      WHERE w.url = (ns.config->>'url')::text
        AND COALESCE(w.repository_id, '00000000-0000-0000-0000-000000000000'::uuid)
            = COALESCE(ns.repository_id, '00000000-0000-0000-0000-000000000000'::uuid)
  );
