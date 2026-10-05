-- Composite lifecycle policies (#2024): allow policy_type = 'composite'.
--
-- A composite policy keeps its conditions in the existing `config` JSONB
-- (`{"conditions": [{"type": "max_age_days", "value": 90}, ...]}`), so no
-- column is added and no row is rewritten. Only the CHECK on `policy_type`
-- from 035_storage_metrics.sql has to admit the new wire string.
--
-- The replacement CHECK is a strict superset of the old one, so every
-- existing row satisfies it by construction. It is added NOT VALID to skip
-- the scan (a catalogue-only change under the brief ACCESS EXCLUSIVE lock),
-- and no VALIDATE follows (docs/operations/online-migrations.md, section 2).
-- New and updated rows are still checked.

ALTER TABLE lifecycle_policies
    DROP CONSTRAINT IF EXISTS lifecycle_policies_policy_type_check;

ALTER TABLE lifecycle_policies
    ADD CONSTRAINT lifecycle_policies_policy_type_check
    CHECK (policy_type IN (
        'max_age_days',
        'max_versions',
        'no_downloads_days',
        'tag_pattern_keep',
        'tag_pattern_delete',
        'size_quota_bytes',
        'composite'
    )) NOT VALID;
