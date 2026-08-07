-- 180_curation_rule_types.sql
-- #2947: shared foundation for typed curation rules. Existing rows are the
-- glob/version/arch engine, now explicitly `rule_type = 'pattern'`; sibling
-- rule types (`publisher_trust` #2948, `popularity` #2949) carry their
-- type-specific parameters in `config`.
--
-- CONCURRENTLY N/A: ADD COLUMN with a constant default is a fast,
-- catalog-only change on modern Postgres (no table rewrite, no long lock).
ALTER TABLE curation_rules
    ADD COLUMN IF NOT EXISTS rule_type TEXT NOT NULL DEFAULT 'pattern';
ALTER TABLE curation_rules
    ADD COLUMN IF NOT EXISTS config JSONB NOT NULL DEFAULT '{}';

-- Scope dimension: 'repository' (attached to one staging repo, as today) vs
-- 'global' (instance-wide baseline policy, no repo). `staging_repo_id` was
-- created nullable in 071; DROP NOT NULL is a no-op belt-and-braces so the
-- invariant (scope = 'global' <=> staging_repo_id IS NULL) is expressible on
-- any upgrade path.
ALTER TABLE curation_rules ALTER COLUMN staging_repo_id DROP NOT NULL;
ALTER TABLE curation_rules
    ADD COLUMN IF NOT EXISTS scope TEXT NOT NULL DEFAULT 'repository';

-- Backfill: every pre-existing rule is the pattern engine. The column default
-- already stamps 'pattern' on old rows; this is an explicit belt-and-braces
-- pass for any row that predates the default on unusual upgrade paths.
UPDATE curation_rules SET rule_type = 'pattern' WHERE rule_type IS NULL OR rule_type = '';

-- Backfill scope: rules without a staging repo were already evaluated
-- instance-wide (the applicable-rules union has always included
-- `staging_repo_id IS NULL`); name that behavior explicitly.
UPDATE curation_rules SET scope = 'global' WHERE staging_repo_id IS NULL AND scope <> 'global';
UPDATE curation_rules SET scope = 'repository' WHERE staging_repo_id IS NOT NULL AND scope <> 'repository';

-- Global-baseline lookup: the enforcement seam reads all global rules ordered
-- by priority for every evaluation, independent of repo.
CREATE INDEX IF NOT EXISTS idx_curation_rules_scope_global
    ON curation_rules (priority) WHERE scope = 'global';
