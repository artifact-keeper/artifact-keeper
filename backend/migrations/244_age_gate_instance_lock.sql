-- Migration 244: an instance administrator's age-gate decisions can only be
-- relaxed by an instance administrator (#4238).
--
-- Since #4238 a repository's own admins can operate its gate, not only an
-- instance admin. Without a record of which decisions an instance admin made,
-- a repository admin could overturn one -- re-approve or reopen a package an
-- instance admin rejected -- or disable a gate an instance admin turned on,
-- which also stops the rejections being honoured. The age gate is a
-- supply-chain control, so both are locked:
--
--   age_gate_reviews.instance_locked       -- an instance admin has decided
--       this review. A repository admin may still REJECT it (that only
--       tightens), but not approve or reopen it.
--   repositories.age_gate_instance_locked  -- an instance admin has set this
--       repository's gate policy. A repository admin may still tighten it
--       (enable it, raise the minimum age), but not disable it, lower the
--       minimum age, or change the age-source mode.
--
-- Only an instance admin's action sets a lock, and nothing a repository admin
-- does clears one. A "last decided by" marker would not hold: a repository
-- admin could tighten first to become the last decider and then relax.
-- NOT NULL with a constant default is catalog-only on PostgreSQL 11+.

ALTER TABLE age_gate_reviews
    ADD COLUMN IF NOT EXISTS instance_locked BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE repositories
    ADD COLUMN IF NOT EXISTS age_gate_instance_locked BOOLEAN NOT NULL DEFAULT false;

-- Before #4238 every review decision and every policy change went through an
-- instance-admin-only endpoint, so every existing decision IS an instance
-- decision. Neither table is in the migration-safety HOT_TABLES set: reviews
-- hold one row per gated (package, version), repositories one per repository.
UPDATE age_gate_reviews
SET instance_locked = true
WHERE reviewed_by IS NOT NULL;

-- A policy only counts as "set" once it differs from the migration-146/191
-- defaults (disabled, 7 days, upstream_publish_time). A repository nobody has
-- configured stays unlocked, so its own admins may configure it freely.
UPDATE repositories
SET age_gate_instance_locked = true
WHERE age_gate_enabled
   OR age_gate_min_age_days <> 7
   OR age_gate_mode <> 'upstream_publish_time';
