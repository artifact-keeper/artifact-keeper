-- Webhooks v2 wire contract finalization (E4 + E5).
--
-- 1. Pin event_schema_version per webhook so receivers can opt in to
--    payload-shape changes without a forced cutover. Existing rows take
--    the inaugural version "2026-04-01" (the shape that landed in #953).
-- 2. Default new webhook_deliveries rows to a 12-attempt budget so the
--    retry loop's new schedule (E5) has room to run all the way to ~24h.
--    Existing in-flight rows keep their per-row max_attempts; only fresh
--    inserts pick up the new default.
-- 3. Carry a freeform reason on auto-disable so the UI/notifier can
--    explain WHY a webhook was disabled (e.g. dead-letter vs operator
--    toggle). Empty string by default; NULL means never auto-disabled.

ALTER TABLE webhooks
    ADD COLUMN event_schema_version text NOT NULL DEFAULT '2026-04-01';

ALTER TABLE webhooks
    ADD COLUMN disabled_reason text;

ALTER TABLE webhook_deliveries
    ALTER COLUMN max_attempts SET DEFAULT 12;
