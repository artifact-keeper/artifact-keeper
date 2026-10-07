-- no-transaction
-- Record an upload into a STAGING repository as `hosted`, not `virtual`.
--
-- `ak_artifact_origin_for_repo` (migration 227) mapped `local` to `hosted`,
-- `remote` to `proxy` and EVERYTHING ELSE to `virtual`, so a package uploaded
-- to a staging repository (a hosted repository with a release target) was
-- stamped `virtual`, and promotion, which carries the source origin over to
-- the copy (#4152), then showed the promoted package in the release
-- repository as "stored in a virtual repository". A staging upload is a
-- direct upload: it is `hosted`.
--
-- This file (1) replaces the derivation so staging maps to `hosted`, and
-- (2) re-stamps the rows already recorded wrongly: an origin whose kind is
-- `virtual` and whose `repository_key` names a repository that is NOT virtual
-- (in practice: a staging repository, or a promoted copy carrying a staging
-- origin) becomes `hosted` with every other key unchanged. An origin naming a
-- repository that no longer exists is left alone.
--
-- Immutability: as in migrations 270/271, `ak_artifacts_origin_immutable` is
-- replaced for the duration of this file by a version that admits exactly
-- this one rewrite (kind `virtual` -> `hosted`, all other keys equal) on a
-- transaction that set `ak.origin_rewrite = 'on'`, and the strict function is
-- restored by the last statement. Batches of 5000 rows by primary key, each
-- under SET LOCAL lock_timeout '5s' with up to five retries. Idempotent: a
-- re-run finds no `virtual` origins naming non-virtual repositories.
DO $migration$
DECLARE
    cursor_id uuid := '00000000-0000-0000-0000-000000000000';
    batch_end uuid;
    touched integer;
    total integer := 0;
    attempt integer;
BEGIN
    SET LOCAL lock_timeout = '5s';

    CREATE OR REPLACE FUNCTION ak_artifact_origin_for_repo(repo_id uuid)
    RETURNS jsonb
    LANGUAGE sql
    STABLE
    AS $fn$
        SELECT jsonb_build_object(
                   'v', 1,
                   'kind', CASE r.repo_type
                             WHEN 'local' THEN 'hosted'
                             WHEN 'staging' THEN 'hosted'
                             WHEN 'remote' THEN 'proxy'
                             ELSE 'virtual'
                           END,
                   'repository_key', r.key
               ) || CASE
                      WHEN r.upstream_url IS NOT NULL
                      THEN jsonb_build_object('upstream_url', ak_normalize_upstream_url(r.upstream_url))
                      ELSE '{}'::jsonb
                    END
          FROM repositories r
         WHERE r.id = repo_id;
    $fn$;

    CREATE OR REPLACE FUNCTION ak_artifacts_origin_immutable()
    RETURNS trigger
    LANGUAGE plpgsql
    AS $fn$
    BEGIN
        IF OLD.origin IS NOT NULL AND NEW.origin IS DISTINCT FROM OLD.origin THEN
            IF current_setting('ak.origin_rewrite', true) = 'on'
               AND OLD.origin->>'kind' = 'virtual'
               AND NEW.origin->>'kind' = 'hosted'
               AND (NEW.origin - 'kind') = (OLD.origin - 'kind')
            THEN
                RETURN NEW;
            END IF;
            RAISE EXCEPTION 'artifacts.origin is immutable once recorded (artifact id %)', OLD.id;
        END IF;
        RETURN NEW;
    END;
    $fn$;
    COMMIT;

    LOOP
        attempt := 0;
        LOOP
            BEGIN
                SET LOCAL lock_timeout = '5s';
                SET LOCAL ak.origin_rewrite = 'on';
                WITH batch AS (
                    SELECT id FROM artifacts
                     WHERE id > cursor_id
                     ORDER BY id
                     LIMIT 5000
                ), fixed AS (
                    UPDATE artifacts a
                       SET origin = jsonb_set(a.origin, '{kind}', '"hosted"')
                      FROM batch b, repositories r
                     WHERE a.id = b.id
                       AND a.origin->>'kind' = 'virtual'
                       AND r.key = a.origin->>'repository_key'
                       AND r.repo_type <> 'virtual'
                    RETURNING 1
                )
                SELECT (SELECT id FROM batch ORDER BY id DESC LIMIT 1), (SELECT count(*) FROM fixed)
                  INTO batch_end, touched;
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
        EXIT WHEN batch_end IS NULL;
        total := total + touched;
        cursor_id := batch_end;
        COMMIT;
        PERFORM pg_sleep(0.01);
    END LOOP;
    RAISE NOTICE 'migration 284: re-stamped % staging-origin artifact row(s) as hosted', total;

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
