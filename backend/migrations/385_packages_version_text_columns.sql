-- #5641: a client-supplied version string is stored as `TEXT`.
--
-- `packages.version` and `package_versions.version` (019) were `VARCHAR(100)`,
-- widened to `VARCHAR(128)` by 211 for the OCI tag grammar. PyPI accepts PEP
-- 440 local versions far past 128 characters: a `twine upload` of a wheel with
-- a 150-character version answered 200 and the wheel was served and
-- installable, but the catalog upsert failed with `value too long for type
-- character varying(128)`. That write is best-effort
-- (`try_create_or_update_from_artifact` swallows the error into a `warn`), so
-- the version was silently missing from `GET /api/v1/packages/{id}/versions`
-- and the catalog/UI never showed it -- a half-success with no error to the
-- client.
--
-- Cost: `VARCHAR(n)` -> `TEXT` is binary coercible, so on PostgreSQL 16/18 the
-- ALTER is a catalogue update. The heaps, their TOAST tables and the indexes
-- keep their relfilenodes (no rewrite, no index rebuild); verified against
-- postgres:16. `packages` has no index on `version` at all (its UNIQUE
-- constraint is `(repository_id, name)`, 113), and `package_versions`'s UNIQUE
-- index is `(package_id, version)`, so neither widening rebuilds an index. The
-- lock is still ACCESS EXCLUSIVE for that moment, so each attempt waits at
-- most 5s for it and backs off, rather than queueing every reader behind it
-- for the session's 5-minute lock_timeout.
--
-- Re-runnable: once neither column is `character varying` it does nothing.
DO $$
DECLARE
    attempt INT := 0;
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND (
                (table_name = 'packages' AND column_name = 'version')
             OR (table_name = 'package_versions' AND column_name = 'version')
          )
          AND data_type = 'character varying'
    ) THEN
        RETURN;
    END IF;

    LOOP
        BEGIN
            SET LOCAL lock_timeout = '5s';
            LOCK TABLE packages IN ACCESS EXCLUSIVE MODE;
            LOCK TABLE package_versions IN ACCESS EXCLUSIVE MODE;

            ALTER TABLE packages
                ALTER COLUMN version TYPE TEXT;
            ALTER TABLE package_versions
                ALTER COLUMN version TYPE TEXT;
            EXIT;
        EXCEPTION WHEN lock_not_available THEN
            attempt := attempt + 1;
            IF attempt >= 5 THEN
                RAISE;
            END IF;
            PERFORM pg_sleep(attempt);
        END;
    END LOOP;
END $$;
