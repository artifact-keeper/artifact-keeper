-- CEP 47 `indexed_timestamp`: when an artifact became visible in its
-- repository's index (#6525), kept across peers (#6527).
--
-- 1. `artifacts.indexed_at`: the instant the row was first listed. NULL on
--    every row written before this release; those keep being served with
--    `created_at`, the value they were served with until now, which CEP 47
--    allows for artifacts that predate the field.
-- 2. `artifacts.index_pending`: the row has not been listed yet. A hosted
--    conda write (upload, chunked or generic commit, promotion) that is held
--    or under a scan policy, and a trash restore of a row never listed, set
--    it in the writer's transaction (a write visible at once is indexed then;
--    restored or revived identical bytes keep their time); the first index
--    build that finds the row visible (no active hold, no scan policy
--    refusal) stamps `indexed_at = clock_timestamp()` and clears it. Kept apart
--    from `indexed_at IS NULL` so a pre-release row is never mistaken for one
--    that is still waiting, which would re-date every existing package.
-- 3. `upload_sessions.indexed_at`: the source's time a trusted peer sends
--    with a chunked replication, written onto the row at completion.
--
-- The columns live on `artifacts` rather than a conda side table: the
-- listing queries already read the row, so serving the value costs no join
-- and no extra statement, and the same column can carry the publish time of
-- other formats whose clients use one for cooldowns.
--
-- Expand-only and catalogue-only: two nullable columns and one boolean with
-- a constant default (no table rewrite since PostgreSQL 11, see
-- docs/operations/online-migrations.md), and no backfill. The previous
-- release neither reads nor writes them. Each ALTER waits at most 5 s for
-- its ACCESS EXCLUSIVE lock and is retried (5 attempts, backing off), as in
-- migration 399, so a long reader cannot queue every other query behind it.
--
-- Rollback: the previous binary ignores the columns; drop them in a quiet
-- window if wanted.
DO $$
DECLARE
    attempt INT := 0;
BEGIN
    LOOP
        BEGIN
            SET LOCAL lock_timeout = '5s';
            -- upload_sessions first: a chunked completion locks its session
            -- row before it writes `artifacts`, so this order cannot invert it.
            ALTER TABLE upload_sessions
                ADD COLUMN IF NOT EXISTS indexed_at TIMESTAMPTZ;
            ALTER TABLE artifacts
                ADD COLUMN IF NOT EXISTS indexed_at TIMESTAMPTZ,
                ADD COLUMN IF NOT EXISTS index_pending BOOLEAN NOT NULL DEFAULT false;
            EXIT;
        EXCEPTION WHEN lock_not_available THEN
            attempt := attempt + 1;
            IF attempt >= 5 THEN
                RAISE;
            END IF;
            PERFORM pg_sleep(attempt);
        END;
    END LOOP;
END
$$;
