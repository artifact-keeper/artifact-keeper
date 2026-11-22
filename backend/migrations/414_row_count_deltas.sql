-- #3094: exact row counts for `GET /admin/stats` without a full-table COUNT(*).
--
-- The dashboard reported four counts by aggregating whole tables on every
-- call: live `artifacts`, `proxy_cache_artifacts`, `download_statistics` and
-- `proxy_download_statistics`. Their cost grows with the catalogue and the
-- download history (the 1M-artifact / 10-100M-event workload of epic #2516),
-- so the page got slower exactly where it is most used.
--
-- The counts stay exact. Statement-level triggers append the net change of
-- every write to `row_count_deltas`, inside the writing transaction, so a
-- rollback drops its delta with the rows. They only ever INSERT: no shared
-- counter row is updated, so concurrent writers never wait on each other
-- (a single hot counter row would serialise every download and cache fill
-- behind one row lock, the #5635 shape). A table's count is SUM(delta) over
-- its rows; the background compaction folds them into one row per table with
-- a single DELETE ... RETURNING statement, which leaves every SUM unchanged.
--
-- Rows that existed before these triggers have no delta. The application
-- seeds each table once at startup (`services::row_counts::true_up`): in one
-- REPEATABLE READ snapshot it inserts `COUNT(*) - SUM(delta)` as a correction
-- row, which is exact whatever commits around it, and records the table in
-- `row_count_seeds`. Until a table is seeded the endpoint keeps its live
-- COUNT(*), so the figures never differ from the old ones. The same true-up
-- runs daily as a drift safety net (a session with
-- `session_replication_role = replica` bypasses triggers).
--
-- Contribution rules, matching the old queries:
--   artifacts                 -> rows with is_deleted = false (insert and
--                                delete by transition table; a soft delete or
--                                restore by a row trigger that fires only when
--                                is_deleted actually changes)
--   proxy_cache_artifacts     -> every row
--   download_statistics       -> every row
--   proxy_download_statistics -> every row
-- An INSERT ... ON CONFLICT DO UPDATE lists only the rows it inserted in the
-- INSERT transition table, so a cache refresh counts nothing. TRUNCATE clears
-- the table's deltas (the count is then 0) and keeps its seed.
--
-- Rolling back to a release without this migration (docs/operations/
-- rollback.md, SKIP_MIGRATIONS=true): the triggers stay and keep appending,
-- but nothing compacts row_count_deltas any more, so it grows by about one
-- row per write statement on the four tables. Fold it periodically while on
-- the older release with
--   WITH gone AS (DELETE FROM row_count_deltas RETURNING table_name, delta)
--   INSERT INTO row_count_deltas (table_name, delta)
--   SELECT table_name, SUM(delta) FROM gone GROUP BY table_name;
-- which keeps every count exact. Do not drop the triggers: rolling forward
-- does not re-run this file, and the counts would then rely on the daily
-- true-up alone.
--
-- Cost: two new tables and catalogue-only DDL. CREATE TRIGGER takes SHARE ROW
-- EXCLUSIVE on each table for the instant of the DDL; no row is read or
-- written here, the seeding COUNT(*) runs later, online, in the application.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS row_count_deltas (
    table_name TEXT   NOT NULL,
    delta      BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_row_count_deltas_table ON row_count_deltas (table_name);

CREATE TABLE IF NOT EXISTS row_count_seeds (
    table_name   TEXT PRIMARY KEY,
    trued_up_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Insert/delete of a table where every row counts.
CREATE OR REPLACE FUNCTION ak_row_count_all_rows() RETURNS trigger AS $$
DECLARE
    n BIGINT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        SELECT count(*) INTO n FROM ak_new_rows;
    ELSE
        SELECT -count(*) INTO n FROM ak_old_rows;
    END IF;
    IF n <> 0 THEN
        INSERT INTO row_count_deltas (table_name, delta) VALUES (TG_TABLE_NAME, n);
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Insert/delete of `artifacts`: only live rows count.
CREATE OR REPLACE FUNCTION ak_row_count_live_artifacts() RETURNS trigger AS $$
DECLARE
    n BIGINT;
BEGIN
    IF TG_OP = 'INSERT' THEN
        SELECT count(*) INTO n FROM ak_new_rows WHERE is_deleted = false;
    ELSE
        SELECT -count(*) INTO n FROM ak_old_rows WHERE is_deleted = false;
    END IF;
    IF n <> 0 THEN
        INSERT INTO row_count_deltas (table_name, delta) VALUES (TG_TABLE_NAME, n);
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Soft delete (+ restore) of one `artifacts` row. The trigger's WHEN clause
-- runs it only when is_deleted changed, so ordinary updates cost nothing.
CREATE OR REPLACE FUNCTION ak_row_count_artifact_soft_delete() RETURNS trigger AS $$
BEGIN
    INSERT INTO row_count_deltas (table_name, delta)
    VALUES (TG_TABLE_NAME, CASE WHEN NEW.is_deleted THEN -1 ELSE 1 END);
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION ak_row_count_truncate() RETURNS trigger AS $$
BEGIN
    DELETE FROM row_count_deltas WHERE table_name = TG_TABLE_NAME;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER ak_row_count_ins_t
    AFTER INSERT ON artifacts REFERENCING NEW TABLE AS ak_new_rows
    FOR EACH STATEMENT EXECUTE FUNCTION ak_row_count_live_artifacts();
CREATE OR REPLACE TRIGGER ak_row_count_del_t
    AFTER DELETE ON artifacts REFERENCING OLD TABLE AS ak_old_rows
    FOR EACH STATEMENT EXECUTE FUNCTION ak_row_count_live_artifacts();
CREATE OR REPLACE TRIGGER ak_row_count_soft_delete_t
    AFTER UPDATE OF is_deleted ON artifacts
    FOR EACH ROW WHEN (OLD.is_deleted IS DISTINCT FROM NEW.is_deleted)
    EXECUTE FUNCTION ak_row_count_artifact_soft_delete();
CREATE OR REPLACE TRIGGER ak_row_count_truncate_t
    AFTER TRUNCATE ON artifacts
    FOR EACH STATEMENT EXECUTE FUNCTION ak_row_count_truncate();

CREATE OR REPLACE TRIGGER ak_row_count_ins_t
    AFTER INSERT ON proxy_cache_artifacts REFERENCING NEW TABLE AS ak_new_rows
    FOR EACH STATEMENT EXECUTE FUNCTION ak_row_count_all_rows();
CREATE OR REPLACE TRIGGER ak_row_count_del_t
    AFTER DELETE ON proxy_cache_artifacts REFERENCING OLD TABLE AS ak_old_rows
    FOR EACH STATEMENT EXECUTE FUNCTION ak_row_count_all_rows();
CREATE OR REPLACE TRIGGER ak_row_count_truncate_t
    AFTER TRUNCATE ON proxy_cache_artifacts
    FOR EACH STATEMENT EXECUTE FUNCTION ak_row_count_truncate();

CREATE OR REPLACE TRIGGER ak_row_count_ins_t
    AFTER INSERT ON download_statistics REFERENCING NEW TABLE AS ak_new_rows
    FOR EACH STATEMENT EXECUTE FUNCTION ak_row_count_all_rows();
CREATE OR REPLACE TRIGGER ak_row_count_del_t
    AFTER DELETE ON download_statistics REFERENCING OLD TABLE AS ak_old_rows
    FOR EACH STATEMENT EXECUTE FUNCTION ak_row_count_all_rows();
CREATE OR REPLACE TRIGGER ak_row_count_truncate_t
    AFTER TRUNCATE ON download_statistics
    FOR EACH STATEMENT EXECUTE FUNCTION ak_row_count_truncate();

CREATE OR REPLACE TRIGGER ak_row_count_ins_t
    AFTER INSERT ON proxy_download_statistics REFERENCING NEW TABLE AS ak_new_rows
    FOR EACH STATEMENT EXECUTE FUNCTION ak_row_count_all_rows();
CREATE OR REPLACE TRIGGER ak_row_count_del_t
    AFTER DELETE ON proxy_download_statistics REFERENCING OLD TABLE AS ak_old_rows
    FOR EACH STATEMENT EXECUTE FUNCTION ak_row_count_all_rows();
CREATE OR REPLACE TRIGGER ak_row_count_truncate_t
    AFTER TRUNCATE ON proxy_download_statistics
    FOR EACH STATEMENT EXECUTE FUNCTION ak_row_count_truncate();
