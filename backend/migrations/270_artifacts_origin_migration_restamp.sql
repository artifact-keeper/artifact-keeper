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
-- What counts as a match (anything else stays `hosted`):
--   * a `migration_items` row with item_type 'artifact', status 'completed',
--     a non-empty `checksum_target` and a `completed_at`, in a job that was
--     not a dry run;
--   * its target repository is resolved from the job, not guessed:
--     `target_path` is `<target_key>/<path>` and `source_path` is
--     `<source_key>/<path>` (`build_source_path`), and `<target_key>` must be
--     the job's `repo_mappings[<source_key>]` (or `<source_key>` when the job
--     does not rename it) with the same `<path>` on both sides;
--   * the artifact row lives in that repository, its `checksum_sha256` equals
--     `checksum_target`, it existed when the item completed
--     (`created_at <= completed_at`, so a later upload of identical bytes is
--     never relabelled), and it is still stamped `hosted`;
--   * its path is one the worker writes for that item: the legacy
--     `<target_key>/<path>`, the verbatim `<path>`, the OCI manifest path
--     `v2/<image>/manifests/<reference>` derived from either source layout
--     (`classify_oci_source_artifact`), or -- only when none of those exist
--     for the item -- the single row whose last path segment is the item's
--     file name (the parser-composed `<name>/<version>/<file>` shape). An item
--     with two or more such rows is ambiguous and matches nothing;
--   * every matching item names the same normalized source URL. An artifact
--     matched by items from two different source systems stays `hosted`.
--
-- Immutability: `ak_artifacts_origin_immutable` is replaced by a version that
-- honours a transaction-local GUC, `ak.origin_rewrite = 'on'`, and even then
-- only for the two rewrites the 1.11.0 migrations need: hosted -> migration
-- with the same repository_key (this file), and a change of `upstream_url`
-- alone (271). The GUC is set with `SET LOCAL` per batch, so it
-- ends with each batch's COMMIT and is never visible to another session. This
-- replaces the function only; no `ALTER TABLE artifacts ... TRIGGER` runs, so
-- no table lock is taken on `artifacts`.
--
-- Online safety (docs/operations/online-migrations.md): one statement, a DO
-- block that COMMITs between steps. The plan is computed once into a temp
-- table (one pass over completed migration_items joined on the
-- idx_artifacts_checksum index), then applied in 5000-row primary-key batches,
-- each under SET LOCAL lock_timeout '5s' / statement_timeout '5min' with up
-- to five retries on a lock timeout. Cost on a million-row catalogue: one
-- index-driven join, then row-lock updates of the matched rows only. An
-- install that never ran the migration worker plans zero rows.
--
-- Idempotent: the predicate is the fix (`kind = 'hosted'`), so a re-run after
-- an interruption plans only what is left; a second run plans nothing. The
-- row counts are reported with RAISE NOTICE.
DO $migration$
DECLARE
    planned integer;
    ambiguous integer;
    touched integer;
    total integer := 0;
    attempt integer;
BEGIN
    SET LOCAL lock_timeout = '5s';
    SET LOCAL statement_timeout = '1min';
    CREATE OR REPLACE FUNCTION ak_artifacts_origin_immutable()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $fn$
    BEGIN
        IF OLD.origin IS NOT NULL AND NEW.origin IS DISTINCT FROM OLD.origin THEN
            -- Sanctioned one-way rewrites (#4153, #4463), only on a
            -- connection that set the transaction-local GUC.
            IF current_setting('ak.origin_rewrite', true) = 'on'
               AND NEW.origin IS NOT NULL
               AND (
                   -- hosted -> migration, same recording repository
                   (OLD.origin->>'kind' = 'hosted'
                    AND NEW.origin->>'kind' = 'migration'
                    AND NEW.origin->>'repository_key' IS NOT DISTINCT FROM OLD.origin->>'repository_key')
                   -- the upstream_url facet alone
                   OR (NEW.origin - 'upstream_url') = (OLD.origin - 'upstream_url')
               )
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
    SET LOCAL statement_timeout = '15min';
    DROP TABLE IF EXISTS pg_temp.ak_origin_restamp_270;
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
               END AS oci_path
          FROM items i
    ),
    candidates AS (
        SELECT s.item_id, s.upstream_url, a.id AS artifact_id,
               (a.path IN (s.rel, s.target_path) OR a.path = COALESCE(s.oci_path, '')) AS exact,
               right(a.path, length(s.leaf) + 1) = '/' || s.leaf AS by_leaf
          FROM shaped s
          JOIN artifacts a
            ON a.checksum_sha256 = s.checksum_target
           AND a.repository_id = s.repository_id
           AND a.created_at <= s.completed_at
           AND a.origin->>'kind' = 'hosted'
    ),
    per_item AS (
        SELECT c.*,
               bool_or(c.exact) OVER (PARTITION BY c.item_id) AS item_has_exact,
               count(*) FILTER (WHERE c.by_leaf) OVER (PARTITION BY c.item_id) AS item_leaf_rows
          FROM candidates c
    ),
    matched AS (
        SELECT artifact_id, upstream_url
          FROM per_item
         WHERE exact OR (NOT item_has_exact AND by_leaf AND item_leaf_rows = 1)
    ),
    per_artifact AS (
        SELECT artifact_id, min(upstream_url) AS upstream_url,
               count(DISTINCT upstream_url) AS sources
          FROM matched
         GROUP BY artifact_id
    ),
    kept AS (
        INSERT INTO ak_origin_restamp_270 (id, upstream_url)
        SELECT artifact_id, upstream_url FROM per_artifact WHERE sources = 1
        RETURNING 1
    )
    SELECT (SELECT count(*) FROM kept),
           (SELECT count(*) FROM per_artifact WHERE sources > 1)
      INTO planned, ambiguous;
    RAISE NOTICE 'migration 270 (#4153): % artifact row(s) planned for re-stamp as migration, % left hosted (matched by more than one source system)',
        planned, ambiguous;
    COMMIT;

    LOOP
        attempt := 0;
        LOOP
            BEGIN
                SET LOCAL lock_timeout = '5s';
                SET LOCAL statement_timeout = '5min';
                SET LOCAL ak.origin_rewrite = 'on';
                WITH batch AS (
                    DELETE FROM ak_origin_restamp_270
                     WHERE id IN (SELECT id FROM ak_origin_restamp_270 ORDER BY id LIMIT 5000)
                    RETURNING id, upstream_url
                )
                UPDATE artifacts a
                   SET origin = jsonb_build_object(
                           'v', 1,
                           'kind', 'migration',
                           'repository_key', a.origin->'repository_key',
                           'upstream_url', b.upstream_url)
                  FROM batch b
                 WHERE a.id = b.id
                   AND a.origin->>'kind' = 'hosted';
                GET DIAGNOSTICS touched = ROW_COUNT;
                EXIT;
            EXCEPTION WHEN lock_not_available THEN
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
END $migration$;
