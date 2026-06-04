-- npm dist-tags persistence (issue #1543).
--
-- The npm packument previously carried a single synthesized `latest` dist-tag
-- chosen by row recency; custom dist-tags (`next`, `beta`, `canary`, ...) sent
-- on `npm publish --tag <tag>` were discarded, so `npm install pkg@next` 404'd
-- (ETARGET) and there was no way to list/manage them.
--
-- dist-tags are a per-PACKAGE concept — one tag->version map per
-- (repository_id, name). They live in their own table, NOT on `packages`:
-- `packages` is one row per (repository_id, name, version) (019,
-- UNIQUE(repository_id, name, version)), so a `dist_tags` column there would be
-- per-version, fan writes across every version row, and a (repo, name) read
-- would match multiple rows (PR #1557 review). A dedicated table keyed by
-- (repository_id, name) is correct regardless of the `packages` row shape.
CREATE TABLE IF NOT EXISTS npm_dist_tags (
    repository_id UUID        NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    name          TEXT        NOT NULL,
    tags          JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (repository_id, name)
);
