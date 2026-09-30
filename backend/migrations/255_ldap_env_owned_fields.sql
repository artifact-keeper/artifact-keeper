-- #3904: persisted env-ownership record for the LDAP_* bootstrap.
--
-- `bootstrap_ldap_from_env` reconciles the env-managed LDAP provider on every
-- boot. Before this it overwrote every column the request carried and forced
-- `is_enabled`/`priority`/`use_starttls` back to hard-coded values, so an
-- admin-API change to the provider was undone silently on the next restart.
--
-- The reconcile now applies a complete desired configuration with explicit
-- ownership (the #3507 OIDC pattern): a field the environment sets this boot
-- is written, a field the environment set on the previous boot and no longer
-- sets is reset to its default, and every other field keeps whatever the
-- admin API stored. This column records which fields the environment wrote on
-- the previous reconcile. NULL means the row has never been reconciled under
-- this rule (admin-created rows, or env rows from before the upgrade).
ALTER TABLE ldap_configs ADD COLUMN IF NOT EXISTS env_owned_fields TEXT[];

-- #3830: the LDAP provider each federated user last authenticated through.
-- The periodic directory reconcile re-reads a user only against this
-- provider (its base, filter and service account). Without it, two providers
-- sharing a user base but differing in user_filter would re-read every user
-- of one with the other's filter and deactivate them. NULL for users who have
-- not logged in since the upgrade; the reconcile then treats a user as gone
-- only when every enabled provider covering their DN says so.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS ldap_provider_id UUID
        REFERENCES ldap_configs(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_users_ldap_provider_id
    ON users (ldap_provider_id) WHERE ldap_provider_id IS NOT NULL;
