-- #2072: artifacts.deleted_at -- when a row entered the trash.
--
-- Storage GC hard-deletes a soft-deleted artifact row (and its object) on the
-- next tick once nothing live references its storage key. To let operators
-- keep soft-deleted artifacts restorable for a while (GC_TRASH_RETENTION_DAYS,
-- default 0 = today's behaviour), GC has to know WHEN a row was soft-deleted.
-- `updated_at` cannot answer that: several paths touch it without deleting.
--
-- Why a trigger stamps it: there are a dozen soft-delete call sites
-- (artifact delete, lifecycle policies, repository cleanup, format handlers,
-- the migration worker) and every upsert that revives a soft-deleted row sets
-- `is_deleted = false`. A row trigger covers all of them, including code
-- written after this migration, with one enforcement point.
--
-- The trigger fires ONLY when `is_deleted` actually changes value (the WHEN
-- clause), so unrelated updates -- download counters, metadata edits, the
-- quarantine sweep, re-asserting `is_deleted = false` in an upsert -- never
-- touch `deleted_at`. A caller that sets `deleted_at` explicitly in the same
-- statement that flips the flag keeps its value.
--
-- Rows that were already soft-deleted before this migration keep
-- `deleted_at = NULL`; GC treats NULL as "deleted long ago" so enabling a
-- retention window never strands them. No backfill is needed.
--
-- Statement cost on a million-row artifacts table: ADD COLUMN with no default
-- is catalogue-only on PG 11+, and CREATE TRIGGER is a catalogue update; both
-- take their lock for microseconds. lock_timeout makes the migration fail fast
-- (and retry on the next boot) rather than queue uploads behind a long
-- transaction while waiting for the lock (precedent: 232, 237, 242, 243).
SET LOCAL lock_timeout = '5s';

ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

COMMENT ON COLUMN artifacts.deleted_at IS
    'When is_deleted last flipped to true (set by trigger artifacts_deleted_at_stamp; NULL for live rows and for rows soft-deleted before migration 261).';

CREATE OR REPLACE FUNCTION ak_artifacts_deleted_at_stamp()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.is_deleted THEN
        -- Entering the trash. An explicit value supplied by the statement
        -- itself wins; otherwise stamp the transaction time.
        IF TG_OP = 'INSERT' THEN
            NEW.deleted_at := COALESCE(NEW.deleted_at, NOW());
        ELSIF NEW.deleted_at IS NOT DISTINCT FROM OLD.deleted_at THEN
            NEW.deleted_at := NOW();
        END IF;
    ELSE
        -- Leaving the trash (restore, or an upsert reviving the path).
        NEW.deleted_at := NULL;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS artifacts_deleted_at_stamp ON artifacts;
CREATE TRIGGER artifacts_deleted_at_stamp
    BEFORE UPDATE OF is_deleted ON artifacts
    FOR EACH ROW
    WHEN (OLD.is_deleted IS DISTINCT FROM NEW.is_deleted)
    EXECUTE FUNCTION ak_artifacts_deleted_at_stamp();

DROP TRIGGER IF EXISTS artifacts_deleted_at_stamp_insert ON artifacts;
CREATE TRIGGER artifacts_deleted_at_stamp_insert
    BEFORE INSERT ON artifacts
    FOR EACH ROW
    WHEN (NEW.is_deleted)
    EXECUTE FUNCTION ak_artifacts_deleted_at_stamp();
