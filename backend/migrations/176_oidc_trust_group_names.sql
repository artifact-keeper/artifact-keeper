-- Fix C (#2823): per-provider opt-in restoring pre-1.6.1 name-matching for an
-- operator-TRUSTED OIDC IdP only. #2759 (1.6.1) added an ownership guard to the
-- group-sync upsert so an IdP-supplied group name can no longer attach a
-- federated user to a same-named operator-managed group (external_source IS
-- NULL); that regressed GitLab-OIDC deployments that pre-create operator groups
-- and expect the OIDC `groups` claim to attach users by name (Jon Craig, #2823).
--
-- This column re-enables name-matching against operator-managed groups for a
-- SINGLE provider the operator explicitly trusts. DEFAULT false: every existing
-- and every other provider stays fully guarded exactly as 1.6.1/1.6.2 -- no
-- grandfathering, no global relaxation. When true, the sync attaches the user to
-- the existing operator group by resolving its id; the group's external_source /
-- external_provider_id stay NULL (the group is NOT adopted into the OIDC
-- namespace), and another provider's oidc-owned groups are never attached
-- regardless of this flag.
ALTER TABLE oidc_configs
    ADD COLUMN IF NOT EXISTS trust_group_names BOOLEAN NOT NULL DEFAULT false;
