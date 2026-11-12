# SSO accounts are bound to their identity provider

Since 1.12.0 (#5483) every account created by an OIDC, SAML or LDAP sign-in
records the provider configuration it came through, in `users.auth_provider_id`
(the id of the `oidc_configs`, `saml_configs` or `ldap_configs` row; which table
follows from `users.auth_provider`). A sign-in finds its account by the provider
type, **that provider**, and the subject (OIDC `sub`, SAML NameID, LDAP DN).

The same subject at a second provider of the same type is a second account.
Before 1.12.0 it was the same account, so a user of one provider could be signed
in as another provider's user whose subject happened to match.

If the second provider's user has the same username or email as the first
provider's account, its first sign-in is refused with `409 Conflict` (both
columns are unique). No account is merged.

CI service accounts are not affected: their `external_id` already names the CI
provider and identity mapping.

## Accounts that existed before the upgrade

Migration 350 binds an existing account when its provider is certain:

| account | bound to |
|---|---|
| LDAP with a recorded provider (`users.ldap_provider_id`, written at each sign-in since migration 255) | that LDAP provider |
| any type with exactly one configured provider of that type (enabled or not) | that provider |
| anything else | nothing (`auth_provider_id` stays NULL) |

A sign-in that resolves to an unbound account is refused:

- `403` with code `FORBIDDEN` and the message "This account was created before
  sign-ins were bound to a single identity provider ...";
- a `LOGIN_FAILED` audit event on the account (`resource_id`) with
  `details.reason = "federated_account_unlinked"`, `details.provider` (`oidc`,
  `saml` or `ldap`) and `details.provider_id` (the provider the sign-in came
  through);
- no second account is created beside it.

On the LDAP Basic-auth passthrough the refusal is a plain `401`, like any other
refused credential.

## Binding an account

Find the unbound accounts:

```sql
SELECT id, username, auth_provider, external_id, last_login_at
FROM users
WHERE auth_provider IN ('oidc', 'saml', 'ldap') AND auth_provider_id IS NULL;
```

The audit events above name the provider each one tried to sign in through.
Once you have confirmed which provider an account belongs to, bind it:

```sql
UPDATE users SET auth_provider_id = '<provider id>' WHERE id = '<user id>';
```

Provider ids are listed by `GET /api/v1/admin/sso/oidc`, `/saml` and `/ldap`.
The user's next sign-in through that provider succeeds. Sign-ins through any
other provider keep getting their own account.

Deleting a provider leaves its accounts bound to the deleted id, so no other
provider can claim them. To move users to a replacement provider, rebind them
with the `UPDATE` above.
