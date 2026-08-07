-- #2992: make `repository_usage_ledger` authoritative via row-level triggers.
--
-- Migration 171 introduced the ledger with an explicit sequencing contract:
-- "Repointing the quota read itself at these O(1) columns ... is the follow-up
-- once every mutation site applies an in-transaction delta." That precondition
-- was never met in application code: ~90 `INSERT INTO artifacts` sites, the
-- proxy-cache catalog writers and ~21 `oci_blobs` writers (plus ~30 scattered
-- soft/hard delete sites) mutate the source tables without touching the
-- ledger, so the stored counters drift until the background reconciler runs.
--
-- There is no application-code chokepoint for those writes -- but every one of
-- them, present and future, mutates exactly three tables. So the delta is
-- applied at the storage layer: row-level AFTER triggers on `artifacts`,
-- `proxy_cache_artifacts` and `oci_blobs` charge/decrement the matching ledger
-- component inside the mutating statement's own transaction. A rolled-back
-- write therefore rolls back its charge; no path can insert bytes without
-- charging them or charge without inserting. Triggers-over-app-publishes is
-- the same reasoning as 142_cache_invalidation_notify_triggers.sql.
--
-- Per-table contribution rules mirror `reconcile_usage_ledger`
-- (backend/src/services/repository_service.rs) and 171's backfill exactly:
--   artifacts             -> hosted_bytes, counted iff is_deleted = false AND
--                            storage_key NOT LIKE 'proxy-cache/%'
--                            (soft-delete = UPDATE flipping is_deleted;
--                            overwrite upserts change size_bytes in place;
--                            several admin paths hard-DELETE rows)
--   proxy_cache_artifacts -> proxy_bytes, every row counts
--                            (hard DELETE on invalidate; refresh upserts
--                            change size_bytes in place)
--   oci_blobs             -> oci_bytes, every row counts
--                            (hard DELETE by GC/purge; the mark-and-sweep
--                            `pending_delete_at` marker does NOT change the
--                            count, matching the reconciler, so marker
--                            transitions are a zero-delta no-op)
--
-- The reconciler stays as the drift safety net (absolute set, unchanged) and
-- should now find near-zero drift. Quota admission behaviour is unchanged by
-- this migration: `check_quota_locked` still reads the authoritative live sum;
-- this only keeps the O(1) counters exact so a later change can trust them.

-- ---------------------------------------------------------------------------
-- Shared delta applier.
--
-- Growth self-seeds the ledger row (repositories created before 171, or rows
-- lost to manual surgery) via the same ON CONFLICT upsert shape the app uses.
-- Shrink is deliberately a plain keyed UPDATE, NOT an upsert: during a
-- cascaded repository delete the parent `repositories` row is already gone,
-- so an INSERT here would violate the ledger's FK and abort the delete; a
-- missing row also simply has nothing to decrement. GREATEST(..., 0) floors
-- the counters against pre-existing under-count drift (a decrement of bytes
-- charged before this migration's true-up cannot push a component negative).
-- Zero deltas return without touching the row, so unrelated column updates
-- take no ledger row lock.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION ak_usage_ledger_apply(
    p_repository_id UUID,
    p_hosted_delta  BIGINT,
    p_proxy_delta   BIGINT,
    p_oci_delta     BIGINT
) RETURNS void AS $$
BEGIN
    IF p_repository_id IS NULL
       OR (p_hosted_delta = 0 AND p_proxy_delta = 0 AND p_oci_delta = 0) THEN
        RETURN;
    END IF;
    IF p_hosted_delta >= 0 AND p_proxy_delta >= 0 AND p_oci_delta >= 0 THEN
        INSERT INTO repository_usage_ledger
            (repository_id, hosted_bytes, proxy_bytes, oci_bytes, updated_at)
        VALUES (p_repository_id, p_hosted_delta, p_proxy_delta, p_oci_delta, now())
        ON CONFLICT (repository_id) DO UPDATE SET
            hosted_bytes = GREATEST(repository_usage_ledger.hosted_bytes + p_hosted_delta, 0),
            proxy_bytes  = GREATEST(repository_usage_ledger.proxy_bytes  + p_proxy_delta, 0),
            oci_bytes    = GREATEST(repository_usage_ledger.oci_bytes    + p_oci_delta, 0),
            updated_at   = now();
    ELSE
        UPDATE repository_usage_ledger SET
            hosted_bytes = GREATEST(hosted_bytes + p_hosted_delta, 0),
            proxy_bytes  = GREATEST(proxy_bytes  + p_proxy_delta, 0),
            oci_bytes    = GREATEST(oci_bytes    + p_oci_delta, 0),
            updated_at   = now()
        WHERE repository_id = p_repository_id;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- artifacts -> hosted_bytes.
--
-- delta = new contribution - old contribution, which uniformly covers INSERT,
-- soft-delete (is_deleted false -> true), restore, in-place overwrite size
-- change, proxy-cache storage_key reclassification, and hard DELETE. A row
-- moved between repositories (repository_id change) un-charges the source and
-- charges the destination.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION ak_usage_ledger_artifacts() RETURNS trigger AS $$
DECLARE
    old_contrib BIGINT := 0;
    new_contrib BIGINT := 0;
BEGIN
    IF TG_OP = 'UPDATE' OR TG_OP = 'DELETE' THEN
        old_contrib := CASE
            WHEN OLD.is_deleted = false AND OLD.storage_key NOT LIKE 'proxy-cache/%'
                THEN COALESCE(OLD.size_bytes, 0)
            ELSE 0
        END;
    END IF;
    IF TG_OP = 'INSERT' OR TG_OP = 'UPDATE' THEN
        new_contrib := CASE
            WHEN NEW.is_deleted = false AND NEW.storage_key NOT LIKE 'proxy-cache/%'
                THEN COALESCE(NEW.size_bytes, 0)
            ELSE 0
        END;
    END IF;

    IF TG_OP = 'DELETE' THEN
        PERFORM ak_usage_ledger_apply(OLD.repository_id, -old_contrib, 0, 0);
        RETURN OLD;
    ELSIF TG_OP = 'UPDATE' AND NEW.repository_id IS DISTINCT FROM OLD.repository_id THEN
        PERFORM ak_usage_ledger_apply(OLD.repository_id, -old_contrib, 0, 0);
        PERFORM ak_usage_ledger_apply(NEW.repository_id, new_contrib, 0, 0);
    ELSE
        PERFORM ak_usage_ledger_apply(NEW.repository_id, new_contrib - old_contrib, 0, 0);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS ak_usage_ledger_artifacts_t ON artifacts;
CREATE TRIGGER ak_usage_ledger_artifacts_t
    AFTER INSERT OR DELETE
        OR UPDATE OF repository_id, size_bytes, is_deleted, storage_key
    ON artifacts
    FOR EACH ROW
    EXECUTE FUNCTION ak_usage_ledger_artifacts();

-- ---------------------------------------------------------------------------
-- proxy_cache_artifacts -> proxy_bytes. Whole table counts (per 171); refresh
-- upserts that change size_bytes produce the net delta, identical-size
-- refreshes are a zero-delta no-op.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION ak_usage_ledger_proxy_cache() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        PERFORM ak_usage_ledger_apply(OLD.repository_id, 0, -COALESCE(OLD.size_bytes, 0), 0);
        RETURN OLD;
    ELSIF TG_OP = 'UPDATE' AND NEW.repository_id IS DISTINCT FROM OLD.repository_id THEN
        PERFORM ak_usage_ledger_apply(OLD.repository_id, 0, -COALESCE(OLD.size_bytes, 0), 0);
        PERFORM ak_usage_ledger_apply(NEW.repository_id, 0, COALESCE(NEW.size_bytes, 0), 0);
    ELSIF TG_OP = 'UPDATE' THEN
        PERFORM ak_usage_ledger_apply(
            NEW.repository_id, 0,
            COALESCE(NEW.size_bytes, 0) - COALESCE(OLD.size_bytes, 0), 0);
    ELSE
        PERFORM ak_usage_ledger_apply(NEW.repository_id, 0, COALESCE(NEW.size_bytes, 0), 0);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS ak_usage_ledger_proxy_cache_t ON proxy_cache_artifacts;
CREATE TRIGGER ak_usage_ledger_proxy_cache_t
    AFTER INSERT OR DELETE OR UPDATE OF repository_id, size_bytes
    ON proxy_cache_artifacts
    FOR EACH ROW
    EXECUTE FUNCTION ak_usage_ledger_proxy_cache();

-- ---------------------------------------------------------------------------
-- oci_blobs -> oci_bytes. Whole table counts (per 171/reconciler); the
-- dedup re-push upsert (`ON CONFLICT ... DO UPDATE SET pending_delete_at =
-- NULL`) does not list size_bytes-affecting columns, so it does not fire this
-- trigger -- the already-counted blob stays counted once.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION ak_usage_ledger_oci_blobs() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        PERFORM ak_usage_ledger_apply(OLD.repository_id, 0, 0, -COALESCE(OLD.size_bytes, 0));
        RETURN OLD;
    ELSIF TG_OP = 'UPDATE' AND NEW.repository_id IS DISTINCT FROM OLD.repository_id THEN
        PERFORM ak_usage_ledger_apply(OLD.repository_id, 0, 0, -COALESCE(OLD.size_bytes, 0));
        PERFORM ak_usage_ledger_apply(NEW.repository_id, 0, 0, COALESCE(NEW.size_bytes, 0));
    ELSIF TG_OP = 'UPDATE' THEN
        PERFORM ak_usage_ledger_apply(
            NEW.repository_id, 0, 0,
            COALESCE(NEW.size_bytes, 0) - COALESCE(OLD.size_bytes, 0));
    ELSE
        PERFORM ak_usage_ledger_apply(NEW.repository_id, 0, 0, COALESCE(NEW.size_bytes, 0));
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS ak_usage_ledger_oci_blobs_t ON oci_blobs;
CREATE TRIGGER ak_usage_ledger_oci_blobs_t
    AFTER INSERT OR DELETE OR UPDATE OF repository_id, size_bytes
    ON oci_blobs
    FOR EACH ROW
    EXECUTE FUNCTION ak_usage_ledger_oci_blobs();

-- ---------------------------------------------------------------------------
-- One-time true-up: erase all pre-trigger drift by setting every ledger row to
-- the authoritative live sums (the same three components as 171's backfill,
-- but DO UPDATE so existing drifted rows are corrected, and self-seeding rows
-- for repositories that never got one). An absolute SET inside this
-- migration's transaction, so ordering relative to the trigger DDL above is
-- immaterial. Writes that commit while this migration is in flight are
-- neither in the snapshot nor triggered; the background reconciler repairs
-- that (empty in practice: migrations run before the API serves).
-- ---------------------------------------------------------------------------

INSERT INTO repository_usage_ledger (repository_id, hosted_bytes, proxy_bytes, oci_bytes, updated_at)
SELECT
    r.id,
    COALESCE((SELECT SUM(a.size_bytes) FROM artifacts a
               WHERE a.repository_id = r.id
                 AND a.is_deleted = false
                 AND a.storage_key NOT LIKE 'proxy-cache/%'), 0),
    COALESCE((SELECT SUM(p.size_bytes) FROM proxy_cache_artifacts p
               WHERE p.repository_id = r.id), 0),
    COALESCE((SELECT SUM(o.size_bytes) FROM oci_blobs o
               WHERE o.repository_id = r.id), 0),
    now()
FROM repositories r
ON CONFLICT (repository_id) DO UPDATE SET
    hosted_bytes = EXCLUDED.hosted_bytes,
    proxy_bytes  = EXCLUDED.proxy_bytes,
    oci_bytes    = EXCLUDED.oci_bytes,
    updated_at   = now();
