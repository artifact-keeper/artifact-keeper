-- npm dist-tags persistence (issue #1543).
--
-- Until now the npm packument was built with a single, synthesized `latest`
-- dist-tag chosen by row recency. Custom dist-tags (`next`, `beta`, `canary`,
-- ...) sent on `npm publish --tag <tag>` were discarded, so they could neither
-- be installed (`npm install pkg@next` -> ETARGET) nor listed/managed.
--
-- Store the tag -> version map per package. `packages` is already one row per
-- (repository_id, name) (migration 113), so the map lives there as JSONB.
ALTER TABLE packages
    ADD COLUMN IF NOT EXISTS dist_tags JSONB NOT NULL DEFAULT '{}'::jsonb;
