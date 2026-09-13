-- Lifecycle policy exclusion ("keep") lists (#2024).
--
-- No column is added and no row is rewritten: the exclusion list lives inside
-- the existing `config` JSONB under the optional `exclude` key. Every policy
-- that exists today has no `exclude` key, which parses to two empty arrays,
-- which makes the new SQL predicate a no-op -- so every existing policy keeps
-- selecting and deleting exactly the artifacts it selected and deleted before
-- this migration.
--
-- The CHECK is defence-in-depth for rows written by direct SQL rather than
-- through the API (which validates the whole block, including rejecting
-- unknown keys). It is added NOT VALID deliberately: `exclude` cannot be
-- present on any pre-existing row, so there is nothing to validate, and
-- skipping the scan avoids an ACCESS EXCLUSIVE table scan during upgrade.
-- New and updated rows are still checked.

ALTER TABLE lifecycle_policies
    DROP CONSTRAINT IF EXISTS lifecycle_policies_config_exclude_is_object;

ALTER TABLE lifecycle_policies
    ADD CONSTRAINT lifecycle_policies_config_exclude_is_object
    CHECK (
        config->'exclude' IS NULL
        OR jsonb_typeof(config->'exclude') = 'object'
    ) NOT VALID;

COMMENT ON COLUMN lifecycle_policies.config IS
    'Policy parameters. Type-specific key (days/keep/quota_bytes/pattern) plus '
    'an optional "exclude" object: {"versions": [...], "version_patterns": [...]}. '
    'Entries in "exclude" protect matching artifacts.version from deletion by '
    'this policy. Unknown keys are rejected by the API (#2024).';
