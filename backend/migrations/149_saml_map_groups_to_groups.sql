-- SAML group-to-group mapping (parity with OIDC #1094).
--
-- Add map_groups_to_groups column to saml_configs. When true, the group
-- values carried in the SAML assertion (via the `groups` attribute mapping)
-- are reflected as Artifact Keeper group memberships, with groups auto-created
-- on first sight and tagged external_source = 'saml'. When false, only the
-- existing admin_group -> is_admin behavior applies.
--
-- Reuses the groups.external_source / external_provider_id columns and the
-- idx_groups_external index already added in migration 100.

ALTER TABLE saml_configs
    ADD COLUMN map_groups_to_groups BOOLEAN NOT NULL DEFAULT false;
