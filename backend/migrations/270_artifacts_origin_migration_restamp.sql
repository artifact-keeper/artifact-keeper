-- no-transaction
-- #4153: record migrated content as `migration`, not `hosted`.
--
-- Migration 228 backfilled every pre-227 artifact from its owning repository
-- row, so content imported by the Artifactory / Nexus migration worker before
-- the worker started stamping its own origin (#4050) was recorded as a hosted
-- upload, and the immutability trigger then froze that. This migration
-- re-stamps those rows as
--
--   {"v":1,"kind":"migration","repository_key":<unchanged>,
--    "upstream_url":ak_normalize_upstream_url(source_connections.url)}
--
-- which is exactly what the worker writes today
-- (`ArtifactOrigin::migration`, migration_worker.rs).
--
-- Matching. An ITEM is a `migration_items` row with item_type 'artifact',
-- status 'completed', a non-empty `checksum_target` and a `completed_at`, in a
-- job that was not a dry run, whose target repository is resolved from the
-- job, not guessed: `target_path` is `<target_key>/<path>`, `source_path` is
-- `<source_key>/<path>` (`build_source_path`), `<target_key>` must be the
-- job's `repo_mappings[<source_key>]` (or `<source_key>` when the job does not
-- rename it), and `<path>` must be the same on both sides.
--
-- An item's CANDIDATES are the artifact rows of ANY origin kind in that
-- repository whose `checksum_sha256` equals `checksum_target` and that existed
-- when the item completed (`created_at <= completed_at`, so a later upload of
-- identical bytes is never considered). A candidate MATCHES the item when its
-- path is one the worker writes for it: the legacy `<target_key>/<path>`, the
-- verbatim `<path>`, or the OCI manifest path `v2/<image>/manifests/<ref>`
-- derived from either source layout (`classify_oci_source_artifact`,
-- including `sha256__<hex>` -> `sha256:<hex>`). Only when the item has no such
-- exact candidate (of any kind) does the parser-composed shape count: the one
-- candidate whose last path segment is the item's file name. Two or more such
-- candidates make the item ambiguous and it matches nothing.
--
-- Kinds are deliberately ignored while matching: when the importer's own row
-- is already `migration` (the worker stamped it, or an earlier run of this
-- file did), the item is satisfied by it and must not fall through to a
-- same-bytes, same-name hosted upload. A matched row is re-stamped only if it
-- is still `hosted` and every item matching it names the same normalized
-- source URL; a row claimed by two source systems stays `hosted`.
--
-- Immutability: for the duration of this file only,
-- `ak_artifacts_origin_immutable` is replaced by a version that admits ONE
-- rewrite, and only on a transaction that set `ak.origin_rewrite = 'on'`:
-- `hosted` (no upstream_url) -> a document with exactly the keys
-- {v, kind, repository_key, upstream_url}, kind `migration`, the same `v` and
-- `repository_key`. The last statement of the file restores the strict
-- function from migration 227. The GUC is set with `SET LOCAL` per batch, so
-- it ends with each batch's COMMIT. Only the function is replaced; no
-- `ALTER TABLE artifacts ... TRIGGER` runs, so no table lock is taken.
--
-- Online safety (docs/operations/online-migrations.md): one statement, a DO
-- block that COMMITs between steps. The plan is computed once into a temp
-- table (one pass over completed migration_items joined on the
-- idx_artifacts_checksum index), then applied in 5000-row primary-key
-- batches. Every transaction runs under SET LOCAL lock_timeout '5s', and a
-- batch that times out on a lock (or meets the RPM-depth guard of migration
-- 247 mid-change, AK_RPM_DEPTH_BUSY) is retried up to five times. A
-- statement_timeout set inside a DO block does not apply to the statements in
-- it, so statement time is bounded only by the migration session's
-- statement_timeout (30 minutes, main.rs) over the whole file. Cost on a
-- million-row catalogue: one index-driven join, then row-lock updates of the
-- matched rows only (in RPM repositories with a repodata depth the 247
-- trigger also bumps `updated_at` on them). An install that never ran the
-- migration worker plans zero rows.
--
-- Idempotent: only rows still `hosted` are planned, and matching is
-- independent of kind, so a re-run after an interruption plans only what is
-- left and a completed run plans nothing. The counts are reported with
-- RAISE NOTICE (logged by the backend under `sqlx::postgres::notice` at INFO).
DO $migration$
DECLARE
    planned integer;
    ambiguous_sources integer;
    ambiguous_names integer;
    touched integer;
    total integer := 0;
    attempt integer;
BEGIN
    SET LOCAL lock_timeout = '5s';
    CREATE OR REPLACE FUNCTION ak_artifacts_origin_immutable()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $fn$
    BEGIN
        IF OLD.origin IS NOT NULL AND NEW.origin IS DISTINCT FROM OLD.origin THEN
            -- Migration 270 only (#4153): hosted -> migration re-stamp.
            IF current_setting('ak.origin_rewrite', true) = 'on'
               AND OLD.origin->>'kind' = 'hosted'
               AND NOT OLD.origin ? 'upstream_url'
               AND NEW.origin->>'kind' = 'migration'
               AND NEW.origin->'v' = OLD.origin->'v'
               AND NEW.origin->'repository_key' = OLD.origin->'repository_key'
               AND jsonb_typeof(NEW.origin->'upstream_url') = 'string'
               AND (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(NEW.origin) k)
                   = ARRAY['kind', 'repository_key', 'upstream_url', 'v']
            THEN
                RETURN NEW;
            END IF;
            RAISE EXCEPTION 'artifacts.origin is immutable once recorded (artifact id %)', OLD.id;
        END IF;
        RETURN NEW;
    END;
    $fn$;
    COMMIT;

    SET LOCAL lock_timeout = '5s';
    IF to_regclass('pg_temp.ak_origin_restamp_270') IS NOT NULL THEN
        DROP TABLE pg_temp.ak_origin_restamp_270;
    END IF;
    CREATE TEMP TABLE ak_origin_restamp_270 (
        id uuid PRIMARY KEY,
        upstream_url text NOT NULL
    );
    WITH items AS (
        SELECT mi.id AS item_id,
               r.id AS repository_id,
               mi.target_path,
               mi.checksum_target,
               mi.completed_at,
               substr(mi.target_path, length(r.key) + 2) AS rel,
               ak_normalize_upstream_url(sc.url) AS upstream_url
          FROM migration_items mi
          JOIN migration_jobs j ON j.id = mi.job_id
          JOIN source_connections sc ON sc.id = j.source_connection_id
          JOIN repositories r ON r.key = split_part(mi.target_path, '/', 1)
         WHERE mi.item_type = 'artifact'
           AND mi.status = 'completed'
           AND mi.completed_at IS NOT NULL
           AND COALESCE(mi.checksum_target, '') <> ''
           AND COALESCE(j.config->>'dry_run', 'false') <> 'true'
           AND r.key = COALESCE(j.config->'repo_mappings'->>split_part(mi.source_path, '/', 1),
                                split_part(mi.source_path, '/', 1))
           AND substr(mi.source_path, length(split_part(mi.source_path, '/', 1)) + 2)
               = substr(mi.target_path, length(r.key) + 2)
    ),
    shaped AS (
        SELECT i.*,
               regexp_replace(i.rel, '^.*/', '') AS leaf,
               CASE
                   WHEN i.rel ~ '^.+/[^/]+/(list\.)?manifest\.json$'
                   THEN 'v2/' || regexp_replace(i.rel, '^(.+)/([^/]+)/(list\.)?manifest\.json$', '\1')
                        || '/manifests/'
                        || regexp_replace(regexp_replace(i.rel, '^(.+)/([^/]+)/(list\.)?manifest\.json$', '\2'),
                                          '^sha256__', 'sha256:')
                   WHEN i.rel ~ '^v2/-/'
                   THEN regexp_replace(i.rel, '^v2/-/', 'v2/')
                   ELSE ''
               END AS oci_path
          FROM items i
    ),
    candidates AS (
        SELECT s.item_id, s.upstream_url, a.id AS artifact_id,
               a.origin->>'kind' AS kind,
               (a.path IN (s.rel, s.target_path, s.oci_path)) AS exact,
               right(a.path, length(s.leaf) + 1) = '/' || s.leaf AS by_leaf
          FROM shaped s
          JOIN artifacts a
            ON a.checksum_sha256 = s.checksum_target
           AND a.repository_id = s.repository_id
           AND a.created_at <= s.completed_at
    ),
    per_item AS (
        SELECT c.*,
               bool_or(c.exact) OVER (PARTITION BY c.item_id) AS item_has_exact,
               count(*) FILTER (WHERE c.by_leaf) OVER (PARTITION BY c.item_id) AS item_leaf_rows
          FROM candidates c
    ),
    matched AS (
        SELECT artifact_id, kind, upstream_url
          FROM per_item
         WHERE exact OR (NOT item_has_exact AND by_leaf AND item_leaf_rows = 1)
    ),
    per_artifact AS (
        SELECT artifact_id, min(kind) AS kind, min(upstream_url) AS upstream_url,
               count(DISTINCT upstream_url) AS sources
          FROM matched
         GROUP BY artifact_id
    ),
    kept AS (
        INSERT INTO ak_origin_restamp_270 (id, upstream_url)
        SELECT artifact_id, upstream_url FROM per_artifact
         WHERE sources = 1 AND kind = 'hosted'
        RETURNING 1
    )
    SELECT (SELECT count(*) FROM kept),
           (SELECT count(*) FROM per_artifact WHERE sources > 1 AND kind = 'hosted'),
           (SELECT count(DISTINCT item_id) FROM per_item
             WHERE NOT item_has_exact AND item_leaf_rows > 1)
      INTO planned, ambiguous_sources, ambiguous_names;
    RAISE NOTICE 'migration 270 (#4153): % hosted artifact row(s) planned for re-stamp as migration; left hosted: % row(s) claimed by more than one source system, % migration item(s) whose file name matches more than one row',
        planned, ambiguous_sources, ambiguous_names;
    COMMIT;

    LOOP
        attempt := 0;
        LOOP
            BEGIN
                SET LOCAL lock_timeout = '5s';
                SET LOCAL ak.origin_rewrite = 'on';
                WITH batch AS (
                    DELETE FROM ak_origin_restamp_270
                     WHERE id IN (SELECT id FROM ak_origin_restamp_270 ORDER BY id LIMIT 5000)
                    RETURNING id, upstream_url
                )
                UPDATE artifacts a
                   SET origin = jsonb_build_object(
                           'v', a.origin->'v',
                           'kind', 'migration',
                           'repository_key', a.origin->'repository_key',
                           'upstream_url', b.upstream_url)
                  FROM batch b
                 WHERE a.id = b.id
                   AND a.origin->>'kind' = 'hosted'
                   AND NOT a.origin ? 'upstream_url';
                GET DIAGNOSTICS touched = ROW_COUNT;
                EXIT;
            EXCEPTION WHEN lock_not_available OR raise_exception THEN
                IF SQLSTATE = 'P0001' AND SQLERRM <> 'AK_RPM_DEPTH_BUSY' THEN
                    RAISE;
                END IF;
                attempt := attempt + 1;
                IF attempt >= 5 THEN
                    RAISE;
                END IF;
                PERFORM pg_sleep(attempt);
            END;
        END LOOP;
        total := total + touched;
        COMMIT;
        EXIT WHEN NOT EXISTS (SELECT 1 FROM ak_origin_restamp_270);
        PERFORM pg_sleep(0.05);
    END LOOP;
    DROP TABLE ak_origin_restamp_270;
    RAISE NOTICE 'migration 270 (#4153): re-stamped % artifact row(s) as migration', total;

    -- Close the window: restore the strict function from migration 227.
    SET LOCAL lock_timeout = '5s';
    CREATE OR REPLACE FUNCTION ak_artifacts_origin_immutable()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $fn$
    BEGIN
        IF OLD.origin IS NOT NULL AND NEW.origin IS DISTINCT FROM OLD.origin THEN
            RAISE EXCEPTION 'artifacts.origin is immutable once recorded (artifact id %)', OLD.id;
        END IF;
        RETURN NEW;
    END;
    $fn$;
END $migration$;
