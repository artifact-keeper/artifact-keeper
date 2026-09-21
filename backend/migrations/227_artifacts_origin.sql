-- #4050: artifacts.origin — a first-class, IMMUTABLE record of where an
-- artifact's bytes came from, stamped at ingest and never rewritten.
--
-- Why a JSONB document and not a text column: origin has two independent
-- facets — the repository the artifact was ingested into (or fetched
-- through) and, for proxied / mirrored / migrated content, the upstream
-- system that actually supplied the bytes. A single text value would force
-- one facet to be encoded inside the other; a structured document keeps
-- both queryable (origin->>'upstream_url' is indexed in migration 230) and
-- leaves room for new facets without a schema change ('v' versions it).
--
-- Why a trigger fills it: the catalogue has dozens of INSERT paths (every
-- format handler, the proxy cache, the migration worker, OCI manifest
-- upserts, promotion copies). Deriving the origin in a BEFORE INSERT
-- trigger from the owning repository row covers ALL of them — including
-- code written after this migration — with one enforcement point, and the
-- derivation is a snapshot: a later edit of repositories.upstream_url does
-- not rewrite history. Callers that know better than the repository row
-- (the migration worker, which knows the source system the bytes came
-- from) supply origin explicitly and the trigger keeps their value.
--
-- Statement cost on a million-row artifacts table: ADD COLUMN with no
-- default is catalogue-only on PG 11+; CREATE TRIGGER and the NOT VALID
-- CHECK are catalogue updates that take their lock for microseconds.
-- Existing rows are backfilled by migration 228.

ALTER TABLE artifacts ADD COLUMN origin JSONB;

-- Normalize an upstream URL for origin comparison: lowercase the
-- scheme://authority (both case-insensitive per RFC 3986) and strip
-- trailing slashes, so `HTTPS://Repo1.Example.ORG/maven2/` and
-- `https://repo1.example.org/maven2` record the same origin. The path is
-- left case-intact — it can be case-sensitive.
CREATE OR REPLACE FUNCTION ak_normalize_upstream_url(url text)
RETURNS text
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT CASE
             WHEN p.prefix IS NOT NULL
               THEN rtrim(lower(p.prefix) || substr(url, length(p.prefix) + 1), '/')
             ELSE rtrim(url, '/')
           END
      FROM (SELECT substring(url from '^[a-zA-Z][a-zA-Z0-9+.-]*://[^/]*') AS prefix) p;
$$;

-- Derive the origin document for an artifact owned by `repo_id`:
--   local repo   -> {"kind":"hosted"}          (an upload)
--   remote repo  -> {"kind":"proxy", upstream} (a proxied/mirrored fetch)
--   virtual repo -> {"kind":"virtual"}
-- A missing repository yields NULL, which the NOT VALID CHECK below
-- rejects — the same statement would fail the repository_id FK anyway.
CREATE OR REPLACE FUNCTION ak_artifact_origin_for_repo(repo_id uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
AS $$
    SELECT jsonb_build_object(
               'v', 1,
               'kind', CASE r.repo_type
                         WHEN 'local' THEN 'hosted'
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
$$;

CREATE OR REPLACE FUNCTION ak_artifacts_origin_fill()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- An explicit origin (migration worker) always wins; the repository
    -- row is the fallback for every other ingest path.
    IF NEW.origin IS NULL THEN
        NEW.origin := ak_artifact_origin_for_repo(NEW.repository_id);
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER artifacts_origin_fill
    BEFORE INSERT ON artifacts
    FOR EACH ROW EXECUTE FUNCTION ak_artifacts_origin_fill();

-- Immutability: once a row carries an origin it can never be changed or
-- cleared — a caching proxy re-serving content, a re-migration, or any
-- other upsert may refresh every other column, but the recorded origin
-- stands. The NULL exception exists for exactly one purpose: the batched
-- backfill (migration 228) writing the derivation onto rows that predate
-- this column. That is a one-way ratchet, not a mutation channel: the
-- fill trigger means no insert path can produce a NULL-origin row.
CREATE OR REPLACE FUNCTION ak_artifacts_origin_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.origin IS NOT NULL AND NEW.origin IS DISTINCT FROM OLD.origin THEN
        RAISE EXCEPTION 'artifacts.origin is immutable once recorded (artifact id %)', OLD.id;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER artifacts_origin_immutable
    BEFORE UPDATE ON artifacts
    FOR EACH ROW EXECUTE FUNCTION ak_artifacts_origin_immutable();

-- NOT VALID so existing (pre-backfill) rows are not scanned here; new rows
-- are checked immediately. Migration 228 validates it after the backfill.
ALTER TABLE artifacts
    ADD CONSTRAINT artifacts_origin_recorded CHECK (origin IS NOT NULL) NOT VALID;
