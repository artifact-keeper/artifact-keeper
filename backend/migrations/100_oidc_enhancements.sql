-- OIDC enhancements bundle: PKCE S256, group-to-group mapping, attribute_mapping
-- merge semantics support.
--
-- Issues: #1091 (S256 PKCE), #1094 (map OIDC groups to groups),
--         #1191 (PUT preserves attribute_mapping by deep merge).
--
-- Changes:
-- 1. Add pkce_code_verifier to sso_sessions so the OIDC callback can send the
--    verifier back to the token endpoint per RFC 7636.
-- 2. Add pkce_enabled column to oidc_configs so operators can opt out for IdPs
--    that misbehave with PKCE. Default ON since PKCE is the modern default.
-- 3. Add map_groups_to_groups column to oidc_configs. When true, the OIDC
--    `groups` claim values are reflected as Artifact Keeper group memberships,
--    with groups auto-created on first sight. When false, legacy role mapping
--    behavior is preserved.
-- 4. Add a (NULL-preserving) external_source column to groups so we can track
--    which groups were auto-created from an OIDC provider. This lets us avoid
--    stomping on operator-managed groups.

ALTER TABLE sso_sessions
    ADD COLUMN pkce_code_verifier VARCHAR(128);

ALTER TABLE oidc_configs
    ADD COLUMN pkce_enabled BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN map_groups_to_groups BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE groups
    ADD COLUMN external_source VARCHAR(64),
    ADD COLUMN external_provider_id UUID;

CREATE INDEX IF NOT EXISTS idx_groups_external
    ON groups(external_source, external_provider_id, name);
