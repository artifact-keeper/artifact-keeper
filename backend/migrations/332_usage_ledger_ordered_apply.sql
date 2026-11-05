-- #5084: apply usage-ledger deltas once, ordered by repository id, at commit.
--
-- Migration 182 charges `repository_usage_ledger` from row-level AFTER
-- triggers, so the ledger row lock was taken by the artifact INSERT itself.
-- A transaction writing two repositories therefore locked the two ledger rows
-- in the order its statements happened to write them, and two transactions
-- touching the same pair in opposite order could deadlock (SQLSTATE 40P01).
--
-- This file keeps the same triggers and the same delta rules, but changes
-- where the lock is taken:
--
--   1. `ak_usage_ledger_enqueue` aggregates the deltas of the current
--      transaction per repository in `repository_usage_ledger_pending`, keyed
--      by `pg_backend_pid()`. A rollback discards the rows with the rest of
--      the transaction, so a failed write never leaks a charge.
--   2. The first enqueue also inserts a marker in
--      `repository_usage_ledger_flush`. A DEFERRABLE INITIALLY DEFERRED
--      constraint trigger on that marker runs `ak_usage_ledger_flush` at
--      COMMIT: it walks the pending rows in `repository_id` order and calls
--      the unchanged `ak_usage_ledger_apply` once per repository.
--
-- Every transaction therefore takes its ledger row locks in the same global
-- order, regardless of the order it wrote artifacts, proxy-cache rows or OCI
-- blobs. Competing transactions may block on the first shared ledger row, but
-- cannot form a ledger-row cycle. Single-repository writes still take exactly
-- one row lock, and zero-net deltas still return without touching the ledger.
--
-- Quota admission keeps taking the ledger row `FOR UPDATE` before the INSERT
-- (that is what serializes same-repo admissions, #2523); the apply now happens
-- at commit, while that lock is still held, so the committed bytes are visible
-- to the next admission.
--
-- `reconcile_usage_ledger_in_tx` continues to write an absolute recompute. It
-- now also discards that transaction's pending delta for the repository (see
-- the application change in this PR), so a reconcile inside a transaction that
-- already wrote rows does not get the same bytes applied twice at commit.
--
-- The reconciler remains the drift safety net, unchanged. Its absolute SET is
-- not affected by deferral: it is deliberately the final word for its row.
SET LOCAL lock_timeout = '5s';

-- Aggregated per-transaction deltas. No FK to `repositories`: during a
-- cascaded repository DELETE the parent (and its ledger row) is already gone
-- when the negative deltas are enqueued, exactly why the original shrink path
-- uses a plain UPDATE rather than an upsert. Rows are private to one backend;
-- the PK also serves the `WHERE backend_pid = $1 ORDER BY repository_id`
-- flush walk.
CREATE TABLE repository_usage_ledger_pending (
    backend_pid   INTEGER NOT NULL,
    repository_id UUID    NOT NULL,
    hosted_delta  BIGINT  NOT NULL DEFAULT 0,
    proxy_delta   BIGINT  NOT NULL DEFAULT 0,
    oci_delta     BIGINT  NOT NULL DEFAULT 0,
    PRIMARY KEY (backend_pid, repository_id)
);

-- One row per transaction that has queued anything. The deferred trigger below
-- fires once, at COMMIT, instead of once per source row: bulk writes (a
-- restore, a GC sweep) enqueue thousands of deltas but still take the ledger
-- rows in one ordered pass.
CREATE TABLE repository_usage_ledger_flush (
    backend_pid INTEGER PRIMARY KEY
);

-- ---------------------------------------------------------------------------
-- Enqueue one delta for the current transaction. Consecutive changes to the
-- same repository collapse into one signed row, so the flush takes one lock
-- per repository, not one per artifact.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION ak_usage_ledger_enqueue(
    p_repository_id UUID,
    p_hosted_delta  BIGINT,
    p_proxy_delta   BIGINT,
    p_oci_delta     BIGINT
) RETURNS void AS $$
DECLARE
    v_pid INTEGER := pg_backend_pid();
BEGIN
    IF p_repository_id IS NULL
       OR (p_hosted_delta = 0 AND p_proxy_delta = 0 AND p_oci_delta = 0) THEN
        RETURN;
    END IF;

    INSERT INTO repository_usage_ledger_pending
        (backend_pid, repository_id, hosted_delta, proxy_delta, oci_delta)
    VALUES (v_pid, p_repository_id, p_hosted_delta, p_proxy_delta, p_oci_delta)
    ON CONFLICT (backend_pid, repository_id) DO UPDATE SET
        hosted_delta = repository_usage_ledger_pending.hosted_delta + EXCLUDED.hosted_delta,
        proxy_delta  = repository_usage_ledger_pending.proxy_delta  + EXCLUDED.proxy_delta,
        oci_delta    = repository_usage_ledger_pending.oci_delta    + EXCLUDED.oci_delta;

    INSERT INTO repository_usage_ledger_flush (backend_pid)
    VALUES (v_pid)
    ON CONFLICT (backend_pid) DO NOTHING;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- Apply every queued delta of this transaction in repository-id order, then
-- clear both transaction-local tables. `ak_usage_ledger_apply` is deliberately
-- unchanged: it still self-seeds on growth, shrinks with a plain UPDATE (the
-- repository can already be gone) and floors at zero.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION ak_usage_ledger_flush() RETURNS trigger AS $$
DECLARE
    v_pid INTEGER := NEW.backend_pid;
    r RECORD;
BEGIN
    FOR r IN
        SELECT repository_id, hosted_delta, proxy_delta, oci_delta
          FROM repository_usage_ledger_pending
         WHERE backend_pid = v_pid
         ORDER BY repository_id
    LOOP
        PERFORM ak_usage_ledger_apply(
            r.repository_id, r.hosted_delta, r.proxy_delta, r.oci_delta);
    END LOOP;

    DELETE FROM repository_usage_ledger_pending WHERE backend_pid = v_pid;
    DELETE FROM repository_usage_ledger_flush   WHERE backend_pid = v_pid;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE CONSTRAINT TRIGGER ak_usage_ledger_flush_t
    AFTER INSERT ON repository_usage_ledger_flush
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW
    EXECUTE FUNCTION ak_usage_ledger_flush();

-- ---------------------------------------------------------------------------
-- artifacts -> hosted_bytes.
--
-- Same contribution rules as migration 182, amended by 288 (OCI manifest rows
-- are not charged; their bytes are already in `oci_bytes`). The trigger
-- definition on `artifacts` is unchanged and still calls this function by
-- name, so no lock is taken on a hot table here.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION ak_usage_ledger_artifacts() RETURNS trigger AS $$
DECLARE
    old_contrib BIGINT := 0;
    new_contrib BIGINT := 0;
BEGIN
    IF TG_OP = 'UPDATE' OR TG_OP = 'DELETE' THEN
        old_contrib := CASE
            WHEN OLD.is_deleted = false
             AND OLD.storage_key NOT LIKE 'proxy-cache/%'
             AND OLD.storage_key NOT LIKE 'oci-manifests/%'
                THEN COALESCE(OLD.size_bytes, 0)
            ELSE 0
        END;
    END IF;
    IF TG_OP = 'INSERT' OR TG_OP = 'UPDATE' THEN
        new_contrib := CASE
            WHEN NEW.is_deleted = false
             AND NEW.storage_key NOT LIKE 'proxy-cache/%'
             AND NEW.storage_key NOT LIKE 'oci-manifests/%'
                THEN COALESCE(NEW.size_bytes, 0)
            ELSE 0
        END;
    END IF;

    IF TG_OP = 'DELETE' THEN
        PERFORM ak_usage_ledger_enqueue(OLD.repository_id, -old_contrib, 0, 0);
        RETURN OLD;
    ELSIF TG_OP = 'UPDATE' AND NEW.repository_id IS DISTINCT FROM OLD.repository_id THEN
        PERFORM ak_usage_ledger_enqueue(OLD.repository_id, -old_contrib, 0, 0);
        PERFORM ak_usage_ledger_enqueue(NEW.repository_id, new_contrib, 0, 0);
    ELSE
        PERFORM ak_usage_ledger_enqueue(NEW.repository_id, new_contrib - old_contrib, 0, 0);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- proxy_cache_artifacts -> proxy_bytes. Whole table counts (per 171); refresh
-- upserts that change size_bytes produce the net delta, identical-size
-- refreshes are a zero-delta no-op.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION ak_usage_ledger_proxy_cache() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        PERFORM ak_usage_ledger_enqueue(OLD.repository_id, 0, -COALESCE(OLD.size_bytes, 0), 0);
        RETURN OLD;
    ELSIF TG_OP = 'UPDATE' AND NEW.repository_id IS DISTINCT FROM OLD.repository_id THEN
        PERFORM ak_usage_ledger_enqueue(OLD.repository_id, 0, -COALESCE(OLD.size_bytes, 0), 0);
        PERFORM ak_usage_ledger_enqueue(NEW.repository_id, 0, COALESCE(NEW.size_bytes, 0), 0);
    ELSIF TG_OP = 'UPDATE' THEN
        PERFORM ak_usage_ledger_enqueue(
            NEW.repository_id, 0,
            COALESCE(NEW.size_bytes, 0) - COALESCE(OLD.size_bytes, 0), 0);
    ELSE
        PERFORM ak_usage_ledger_enqueue(NEW.repository_id, 0, COALESCE(NEW.size_bytes, 0), 0);
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- oci_blobs -> oci_bytes. Whole table counts (per 171/reconciler); the dedup
-- re-push upsert (`ON CONFLICT ... DO UPDATE SET pending_delete_at = NULL`)
-- does not list size_bytes-affecting columns, so it does not fire this
-- trigger -- the already-counted blob stays counted once.
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION ak_usage_ledger_oci_blobs() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        PERFORM ak_usage_ledger_enqueue(OLD.repository_id, 0, 0, -COALESCE(OLD.size_bytes, 0));
        RETURN OLD;
    ELSIF TG_OP = 'UPDATE' AND NEW.repository_id IS DISTINCT FROM OLD.repository_id THEN
        PERFORM ak_usage_ledger_enqueue(OLD.repository_id, 0, 0, -COALESCE(OLD.size_bytes, 0));
        PERFORM ak_usage_ledger_enqueue(NEW.repository_id, 0, 0, COALESCE(NEW.size_bytes, 0));
    ELSIF TG_OP = 'UPDATE' THEN
        PERFORM ak_usage_ledger_enqueue(
            NEW.repository_id, 0, 0,
            COALESCE(NEW.size_bytes, 0) - COALESCE(OLD.size_bytes, 0));
    ELSE
        PERFORM ak_usage_ledger_enqueue(NEW.repository_id, 0, 0, COALESCE(NEW.size_bytes, 0));
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
