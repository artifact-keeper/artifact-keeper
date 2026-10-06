-- no-transaction
-- #4463: stop keeping a Remote's URL-embedded credentials in origin records.
--
-- `ak_normalize_upstream_url` (migration 227) lowercased only the
-- scheme://authority of a Remote's `upstream_url`, so for a Remote configured
-- as `https://user:password@host/...` the `artifacts_origin_fill` trigger
-- copied `user:password@` into `artifacts.origin->>'upstream_url'` of every
-- artifact proxied through it, and migration 230 indexes that expression.
-- #4462 redacted it from every response; this removes it at rest:
--
--   1. `ak_strip_url_userinfo(text)` drops the `userinfo@` part of the
--      authority and nothing else. It is the SQL twin of
--      `proxy_service::strip_url_userinfo_textual`: the scheme is recognised
--      only at the start of the string, followed by any run of `/` or `\`
--      (WHATWG's `https:user:pass@host` and `https:\\user:pass@host`
--      spellings), a special-scheme authority also ends at `\`, and the
--      userinfo is everything up to the LAST `@` of the authority.
--   2. `ak_normalize_upstream_url(text)` now trims ASCII whitespace, strips
--      the userinfo, then does what it did before (lowercase the
--      scheme://authority, ASCII only, and strip trailing slashes). The Rust
--      mirror, `artifact_origin::normalize_upstream_url`, is pinned to it by a
--      DB-backed agreement test. For a URL without `@` or surrounding
--      whitespace the result is unchanged, so no stored origin of a
--      credential-free Remote is rewritten.
--   3. Every `artifacts` row whose `origin->>'upstream_url'` is not already in
--      normal form is rewritten to it (the upstream_url facet only; kind,
--      repository_key and v stay). The 230 expression index is maintained by
--      the UPDATE itself; no rebuild is needed.
--   4. `proxy_cache_artifacts.upstream_url` (write-only, no reader) is
--      stripped the same way; the application strips it on write from now on.
--
-- Not changed here: `repositories.upstream_url` keeps the credentials, because
-- the fetch paths authenticate from it (moving them is deferred, see #4463),
-- and the `policy_result` documents written before #4462 (origin predicates
-- shipped in the same unreleased release, so only pre-release databases hold
-- such rows).
--
-- Immutability: the rewrite runs with the transaction-local
-- `ak.origin_rewrite = 'on'` GUC that migration 270's trigger function
-- honours for an `upstream_url`-only change. No `ALTER TABLE ... TRIGGER`.
--
-- Online safety (docs/operations/online-migrations.md): one statement, a DO
-- block that walks each table by primary key in 5000-row keyset batches with
-- a COMMIT after each, under SET LOCAL lock_timeout '5s' / statement_timeout
-- '5min' and up to five retries on a lock timeout. Cost on a million-row
-- catalogue: one PK-ordered pass over each table, row-lock updates of the
-- credentialed rows only (none on an install without a credentialed Remote).
-- Idempotent: a re-run rewrites nothing that is already in normal form.
-- Row counts are reported with RAISE NOTICE.
DO $migration$
DECLARE
    cursor_id uuid;
    batch_end uuid;
    touched integer;
    total integer;
    attempt integer;
    tbl text;
BEGIN
    SET LOCAL lock_timeout = '5s';
    SET LOCAL statement_timeout = '1min';

    CREATE OR REPLACE FUNCTION ak_strip_url_userinfo(url text)
    RETURNS text
    LANGUAGE plpgsql
    IMMUTABLE
    AS $fn$
    DECLARE
        scheme text := substring(url from '^([A-Za-z][A-Za-z0-9+.-]*):');
        special boolean := false;
        prefix_len integer := 0;
        rest text;
        authority text;
    BEGIN
        IF url IS NULL THEN
            RETURN NULL;
        END IF;
        IF scheme IS NOT NULL THEN
            special := lower(scheme) IN ('http', 'https', 'ws', 'wss', 'ftp');
            -- A non-special scheme only counts with a `//` authority marker,
            -- otherwise `user:pass@host/x` would keep `user` as a scheme.
            IF special OR substr(url, length(scheme) + 2, 2) = '//' THEN
                prefix_len := length(scheme) + 1
                    + length(substring(substr(url, length(scheme) + 2) from '^[/\\]*'));
            END IF;
        ELSIF left(url, 2) = '//' THEN
            prefix_len := 2;
        END IF;
        rest := substr(url, prefix_len + 1);
        authority := CASE WHEN special THEN substring(rest from '^[^/?#\\]*')
                          ELSE substring(rest from '^[^/?#]*') END;
        IF strpos(authority, '@') = 0 THEN
            RETURN url;
        END IF;
        RETURN left(url, prefix_len)
            || substr(rest, length(authority) - strpos(reverse(authority), '@') + 2);
    END;
    $fn$;

    CREATE OR REPLACE FUNCTION ak_normalize_upstream_url(url text)
    RETURNS text
    LANGUAGE plpgsql
    IMMUTABLE
    AS $fn$
    DECLARE
        s text := ak_strip_url_userinfo(btrim(url, E' \t\n\r\f'));
        prefix text := substring(s from '^[a-zA-Z][a-zA-Z0-9+.-]*://[^/]*');
    BEGIN
        IF prefix IS NOT NULL THEN
            s := translate(prefix, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')
                 || substr(s, length(prefix) + 1);
        END IF;
        RETURN rtrim(s, '/');
    END;
    $fn$;
    COMMIT;

    FOREACH tbl IN ARRAY ARRAY['artifacts', 'proxy_cache_artifacts'] LOOP
        cursor_id := '00000000-0000-0000-0000-000000000000';
        total := 0;
        LOOP
            attempt := 0;
            LOOP
                BEGIN
                    SET LOCAL lock_timeout = '5s';
                    SET LOCAL statement_timeout = '5min';
                    SET LOCAL ak.origin_rewrite = 'on';
                    IF tbl = 'artifacts' THEN
                        WITH batch AS (
                            SELECT id FROM artifacts
                             WHERE id > cursor_id
                             ORDER BY id
                             LIMIT 5000
                        ), fixed AS (
                            UPDATE artifacts a
                               SET origin = jsonb_set(a.origin, '{upstream_url}',
                                       to_jsonb(ak_normalize_upstream_url(a.origin->>'upstream_url')))
                              FROM batch b
                             WHERE a.id = b.id
                               AND a.origin ? 'upstream_url'
                               AND a.origin->>'upstream_url'
                                   IS DISTINCT FROM ak_normalize_upstream_url(a.origin->>'upstream_url')
                            RETURNING 1
                        )
                        SELECT (SELECT id FROM batch ORDER BY id DESC LIMIT 1), (SELECT count(*) FROM fixed)
                          INTO batch_end, touched;
                    ELSE
                        WITH batch AS (
                            SELECT id FROM proxy_cache_artifacts
                             WHERE id > cursor_id
                             ORDER BY id
                             LIMIT 5000
                        ), fixed AS (
                            UPDATE proxy_cache_artifacts p
                               SET upstream_url = ak_strip_url_userinfo(p.upstream_url)
                              FROM batch b
                             WHERE p.id = b.id
                               AND strpos(p.upstream_url, '@') > 0
                               AND p.upstream_url IS DISTINCT FROM ak_strip_url_userinfo(p.upstream_url)
                            RETURNING 1
                        )
                        SELECT (SELECT id FROM batch ORDER BY id DESC LIMIT 1), (SELECT count(*) FROM fixed)
                          INTO batch_end, touched;
                    END IF;
                    EXIT;
                EXCEPTION WHEN lock_not_available THEN
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
        RAISE NOTICE 'migration 271 (#4463): stripped upstream userinfo / normalized % % row(s)',
            total, tbl;
    END LOOP;
END $migration$;
