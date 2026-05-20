-- Denormalize a `filename` column on `artifacts` so format handlers can
-- look up artifacts by trailing filename in O(log n) instead of a
-- leading-wildcard LIKE seq-scan.
--
-- Hot path is `proxy_helpers::find_local_by_filename_suffix` and
-- `local_fetch_by_path_suffix`, used by every format that resolves an
-- artifact by filename without knowing the full path (cran, rpm,
-- helm, puppet, hex, ansible, rubygems, pypi). Before this change
-- those helpers run `path LIKE '%/' || $2 ESCAPE '\\'`, which the
-- leading wildcard makes un-indexable — Postgres seq-scans every
-- live row in the repo to find the match. On a populated
-- `artifacts` table (10⁶+ rows) each call costs 3-6 s, and under
-- concurrent resolver load the per-request tail latency tips past
-- pip's 15 s timeout. See #1266 for the prod logs.
--
-- The new column is `GENERATED ALWAYS AS (regexp_replace(path, '^.*/', '')) STORED`
-- so it self-maintains on every INSERT/UPDATE and there's no
-- application-side population work. The partial index
-- `(repository_id, filename) WHERE is_deleted = false` matches the
-- exact WHERE clause every helper uses, so the planner can do an
-- index-only scan when the data is hot.
--
-- Migration cost on a deployment with 10⁶ artifacts: the STORED
-- column ADD requires a table rewrite (~1-2 min on ~1 GB of table
-- bytes, depending on storage). Operators whose RDS parameter group
-- enforces a low `statement_timeout` (10-30 s is common) need to
-- either:
--   1. Bump `statement_timeout` for the migration session — #1269
--      raises it to 30 min session-locally; once that PR ships, no
--      operator action is needed.
--   2. Apply this migration out-of-band per the runbook playbook
--      (build the column / index separately with `SET
--      statement_timeout = 0`, then insert the row into
--      `_sqlx_migrations` with the canonical sha384 checksum).

ALTER TABLE artifacts
  ADD COLUMN filename TEXT
  GENERATED ALWAYS AS (regexp_replace(path, '^.*/', '')) STORED;

CREATE INDEX IF NOT EXISTS idx_artifacts_repo_filename
  ON artifacts (repository_id, filename)
  WHERE is_deleted = false;
