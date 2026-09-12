-- Issue #2583: a stable, operator-chosen identifier for a SAML configuration.
--
-- The ACS URL the IdP is configured with embeds `saml_configs.id`, a
-- server-generated UUID, so rebuilding a deployment from scratch mints a new
-- one and the URL registered at the IdP has to be re-pasted. `slug` is an
-- additive, URL-safe alias that the public SAML login and ACS routes accept in
-- place of the UUID.
--
-- Deliberately NULLable with no backfill. Existing rows keep addressing
-- themselves by UUID and every ACS URL that works today keeps working
-- byte-for-byte; adopting a slug is an explicit operator action. Because the
-- column is new and starts NULL on every existing row, the UNIQUE constraint
-- cannot be violated by pre-existing data, so this migration has no failure
-- mode on a populated table (Postgres treats NULLs as distinct, so any number
-- of configurations may stay un-slugged). Duplicates can only be introduced
-- afterwards, through the admin API, where they surface as a 409.
--
-- The CHECK pins the character class the route resolver relies on: a slug is
-- lowercase, starts alphanumeric, and contains only [a-z0-9_-]. That makes it
-- safe verbatim as a path segment (no percent-encoding, no `/`) and gives it
-- exactly ONE spelling, so the uniqueness the database enforces and the
-- equality the ACS lookup performs are the same comparison. A case-insensitive
-- lookup over a case-sensitive constraint would let two rows the database
-- considers distinct both answer to one login URL.
ALTER TABLE saml_configs
    ADD COLUMN slug VARCHAR(64) UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9_-]*$');

COMMENT ON COLUMN saml_configs.slug IS
    'Optional operator-chosen URL-safe alias accepted in place of the UUID by /api/v1/auth/sso/saml/{id}/login and /acs (#2583).';
