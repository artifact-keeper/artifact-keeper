-- Per-provider opt-in: reflect SAML assertion group values as Artifact Keeper
-- group memberships, mirroring the OIDC map_groups_to_groups flag from #1094
-- (migration 100 added the same column to oidc_configs plus the
-- groups.external_source / groups.external_provider_id columns that this
-- feature reuses).
--
-- When true, the ACS handler passes the assertion's `groups` attribute values
-- (resolved via attribute_mapping.groups, default "groups") through the shared
-- external-group reconciler: groups are auto-created tagged
-- external_source = 'saml' / external_provider_id = <provider id>, membership
-- rows are upserted, and stale memberships are pruned scoped to
-- (external_source = 'saml', provider id) so SAML-managed, OIDC-managed and
-- operator-managed (NULL external_source) memberships never strip each other.
--
-- Defaults to false so existing SAML providers keep their exact pre-157
-- behavior (groups only feed the admin_group role mapping) on upgrade. (#2333)
ALTER TABLE saml_configs
    ADD COLUMN IF NOT EXISTS map_groups_to_groups BOOLEAN NOT NULL DEFAULT false;
