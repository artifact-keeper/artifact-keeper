-- 350_users_auth_provider_id.sql
-- #5483: bind each federated account to the provider configuration that
-- created it.
--
-- A federated sign-in used to find its account by `(auth_provider,
-- external_id)` alone, so with two providers of one type configured, a user
-- of provider B whose subject (OIDC `sub`, SAML NameID, LDAP DN) equals one of
-- provider A's users was signed in as A's user. `auth_provider_id` names the
-- `oidc_configs` / `saml_configs` / `ldap_configs` row (which table follows
-- from `auth_provider`) and becomes part of the match. No foreign key: the
-- column refers to one of three tables. A deleted provider leaves the id
-- behind, so no other provider can claim its accounts.
--
-- CI service accounts stay NULL: their `external_id` already names the CI
-- provider and identity mapping (`ci:<provider>:<mapping>`, migration 232).
--
-- Backfill, only where the provider is certain:
--   * LDAP: the provider each user last signed in through (`ldap_provider_id`,
--     #3830).
--   * Any type with exactly one configured provider (enabled or not): that
--     provider, since no other configuration can have created the account.
-- Every other federated account stays NULL. Sign-in refuses a NULL account
-- of OIDC, SAML or LDAP (403, audited as LOGIN_FAILED with reason
-- `federated_account_unlinked`) until an administrator binds it with
--   UPDATE users SET auth_provider_id = '<provider id>' WHERE id = '<user id>';
--
-- Cost: adding a nullable column without a default changes only the catalog
-- (a brief ACCESS EXCLUSIVE lock on `users`, which first waits for open
-- transactions on the table). The backfill rewrites the matched federated
-- rows once. Re-running is a no-op: every statement skips rows that already
-- have a provider. Down path: `ALTER TABLE users DROP COLUMN auth_provider_id`.

ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_provider_id UUID;

UPDATE users
SET auth_provider_id = ldap_provider_id
WHERE auth_provider = 'ldap'
  AND auth_provider_id IS NULL
  AND ldap_provider_id IS NOT NULL;

UPDATE users
SET auth_provider_id = (SELECT id FROM ldap_configs)
WHERE auth_provider = 'ldap'
  AND auth_provider_id IS NULL
  AND external_id IS NOT NULL
  AND (SELECT COUNT(*) FROM ldap_configs) = 1;

UPDATE users
SET auth_provider_id = (SELECT id FROM oidc_configs)
WHERE auth_provider = 'oidc'
  AND auth_provider_id IS NULL
  AND external_id IS NOT NULL
  AND (SELECT COUNT(*) FROM oidc_configs) = 1;

UPDATE users
SET auth_provider_id = (SELECT id FROM saml_configs)
WHERE auth_provider = 'saml'
  AND auth_provider_id IS NULL
  AND external_id IS NOT NULL
  AND (SELECT COUNT(*) FROM saml_configs) = 1;
