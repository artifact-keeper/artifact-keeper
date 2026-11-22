-- #5195: per-endpoint delivery backoff for webhooks.
--
-- A failed send already reschedules its own delivery row, but the endpoint's
-- other due rows stayed due, so a receiver that is down or black-holed was
-- sent one delivery on every worker pass and held a delivery lane for up to
-- the 30 s send timeout each time. The worker now records consecutive failed
-- sends per webhook and skips the webhook until `delivery_backoff_until`. A
-- successful send, or re-enabling the webhook, clears both.
--
-- Additive: an integer with a constant default (catalog-only since
-- PostgreSQL 11) and a nullable timestamp, no backfill and no index. A replica
-- on the previous release neither reads nor writes them. The short lock
-- timeout keeps the brief ACCESS EXCLUSIVE lock from queueing behind a long
-- `webhooks` reader; a busy table fails the migration fast and it is retried
-- on the next start.
SET LOCAL lock_timeout = '5s';

ALTER TABLE webhooks
    ADD COLUMN IF NOT EXISTS delivery_failures INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS delivery_backoff_until TIMESTAMPTZ;

COMMENT ON COLUMN webhooks.delivery_failures IS
    'Consecutive failed delivery sends to this endpoint; reset by a successful send or re-enable';
COMMENT ON COLUMN webhooks.delivery_backoff_until IS
    'The delivery worker does not send to this endpoint before this time (per-endpoint backoff); NULL = no backoff';
