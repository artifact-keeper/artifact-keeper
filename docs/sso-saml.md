# SAML SSO: finding and formulating the ACS URL

Configuring a SAML identity provider against Artifact Keeper requires giving
the IdP an **Assertion Consumer Service (ACS)** URL. That URL embeds an
identifier for the SAML configuration: either its database id — a
server-generated UUID — or, since #2583, an operator-chosen `slug`. This page
documents how to obtain and construct it, and what to expect when you rebuild
an environment from scratch.

**If you are configuring a new provider, set a `slug` and use the slug form.**
It is the only form that survives a database wipe. See
[Pinning the URL with a slug](#pinning-the-url-with-a-slug).

## The URL shape

```text
https://<artifact-keeper-host>/api/v1/auth/sso/saml/<saml-config-uuid>/acs
https://<artifact-keeper-host>/api/v1/auth/sso/saml/<slug>/acs
```

The matching login-initiation URL, which is what the web UI links to, is:

```text
https://<artifact-keeper-host>/api/v1/auth/sso/saml/<saml-config-uuid>/login
https://<artifact-keeper-host>/api/v1/auth/sso/saml/<slug>/login
```

Both take the **same** identifier: either the primary key of the row in
`saml_configs`, or that row's `slug`. The two forms are interchangeable, and the
UUID form is unchanged — every URL that worked before #2583 still works.

## Finding the UUID

### Via the API (preferred)

The enabled providers are listed unauthenticated, because the login page needs
them:

```bash
curl -s https://artifact-keeper.example.com/api/v1/auth/sso/providers | jq .
```

Each SAML entry carries the id and the ready-made login URL. To list all SAML
configurations including disabled ones, use the admin endpoint with an admin
credential:

```bash
curl -s -H "Authorization: Bearer $AK_ADMIN_TOKEN" \
  https://artifact-keeper.example.com/api/v1/admin/sso/saml | jq -r '.[] | "\(.name)\t\(.id)"'
```

Names are unique, so this is a reliable name → UUID lookup:

```bash
SAML_ID=$(curl -s -H "Authorization: Bearer $AK_ADMIN_TOKEN" \
  https://artifact-keeper.example.com/api/v1/admin/sso/saml \
  | jq -r '.[] | select(.name == "okta") | .id')

echo "https://artifact-keeper.example.com/api/v1/auth/sso/saml/${SAML_ID}/acs"
```

### Via Postgres

```sql
SELECT id, name, is_enabled FROM saml_configs ORDER BY name;
```

### At creation time

`POST /api/v1/admin/sso/saml` returns the created row, including its `id`.
Capture it there and you never need to look it up:

```bash
SAML_ID=$(curl -s -X POST \
  -H "Authorization: Bearer $AK_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d @saml-config.json \
  https://artifact-keeper.example.com/api/v1/admin/sso/saml | jq -r .id)
```

## Pinning the URL with a slug

`saml_configs.slug` is an optional, URL-safe alias you choose. Set it and the
ACS URL stops depending on anything the server generates:

```bash
curl -s -X POST \
  -H "Authorization: Bearer $AK_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"name":"Okta","slug":"okta","entity_id":"...","sso_url":"...","certificate":"..."}' \
  https://artifact-keeper.example.com/api/v1/admin/sso/saml
```

The ACS URL you register at the IdP is then simply:

```text
https://artifact-keeper.example.com/api/v1/auth/sso/saml/okta/acs
```

An existing configuration can be given one with `PUT /api/v1/admin/sso/saml/{id}`
(still addressed by UUID — the admin CRUD endpoints are unchanged):

```bash
curl -s -X PUT -H "Authorization: Bearer $AK_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d '{"slug":"okta"}' \
  https://artifact-keeper.example.com/api/v1/admin/sso/saml/$SAML_ID
```

Rules, all enforced by both the API and a database constraint:

- `^[a-z0-9][a-z0-9_-]*$`, at most 64 characters. Lowercase only, no dots, no
  spaces, nothing that needs percent-encoding.
- **Unique** across SAML configurations. A duplicate is a `409 Conflict` naming
  the slug, not a partially-applied write.
- **Matched exactly.** `/saml/Okta/acs` does *not* resolve `okta` — it is a 404.
  A configuration has exactly one spelling of its ACS URL, so the uniqueness the
  database enforces and the lookup the ACS performs cannot disagree.
- **Not a UUID.** The routes parse the segment as a UUID first, so a UUID-shaped
  slug would be unreachable; it is refused at write time.

The slug is an address, not a key: `saml_configs.id` is still the primary key
and is still what `sso_sessions.provider_id`, `groups.external_provider_id`, the
admin CRUD endpoints and the audit log record. Omitting a slug keeps the
configuration UUID-addressed, exactly as before.

Because the `Destination`/`Recipient` binding is derived from the path segment
the request actually arrived on, the IdP may be configured with either form —
and a mixed setup (login by UUID, ACS by slug, or vice versa) also works. What
you may *not* do is register the slug ACS at the IdP and expect an assertion
bound to it to be accepted at the UUID URL; each address validates against
itself.

## Absolute vs relative ACS in the AuthnRequest

The `use_absolute_acs_url` flag on the SAML configuration controls what
Artifact Keeper puts in the `AssertionConsumerServiceURL` of the AuthnRequest
it sends, and what it expects back in the assertion's `Destination` /
`Recipient` bindings:

| `use_absolute_acs_url` | AuthnRequest carries | Use when |
| --- | --- | --- |
| `false` (default) | a root-relative path, `/api/v1/auth/sso/saml/<id>/acs` | the IdP is fine deriving the host itself |
| `true` | the full URL built from the configured trusted public base URL | the IdP requires an absolute ACS, or you are behind a proxy that rewrites the host |

The value the IdP is configured with and the value Artifact Keeper computes
must agree, because the assertion's `Destination`/`Recipient` are validated
against it. If assertions start failing validation after a proxy or hostname
change, this flag and the configured public base URL are the first things to
check.

## Rebuilt environments get a new UUID

`saml_configs.id` defaults to `gen_random_uuid()`, so a redeploy that wipes the
database produces a new UUID and a UUID-form ACS URL registered at the IdP must
be updated.

In rough order of preference:

1. **Set a `slug` and register the slug URL at the IdP.** The slug is part of
   the configuration you post, so recreating the configuration recreates the
   same ACS URL and the IdP needs no change. This is the fix for the
   "re-paste the ACS URL after every rebuild" problem.
2. **Do not wipe the database.** Treat `saml_configs` as persistent state.
   Restoring it — or just the one row — preserves the id too.
3. **Look the id up after bootstrap and feed it forward.** Useful for a
   configuration that already exists and cannot be re-registered at the IdP
   right now. Because `name` is `UNIQUE NOT NULL`, a fixed name is a stable
   handle even when the id is not; the `jq` snippet above is the whole lookup.
   In Terraform this is the `null_resource` + `external` data source pattern
   several operators use, keyed on the provider name — and adding a slug is
   what lets you delete it.
4. **Seed the row with a fixed id.** `POST /api/v1/admin/sso/saml` does not
   accept an `id` — the server always generates one — so this only works at the
   SQL level: have a bootstrap/seed script `INSERT INTO saml_configs (id, ...)`
   with a UUID you chose and keep in configuration management. Prefer a slug;
   this remains available for a deployment that must keep an ACS URL already
   registered in its UUID form.

## Why not change the primary key

The routes parse the path segment as a UUID first and only then look for a
slug, so the UUID remains the primary address and nothing that works today
changes. Changing the key outright would rewrite the ACS URL of every
deployment that is currently working — inflicting the exact breakage this issue
is about on everyone who is not affected by it today — and
`sso_sessions.provider_id` and `groups.external_provider_id` both store the
provider id as a UUID shared across the OIDC, LDAP and SAML provider types.

Migration 218 therefore *adds* a nullable `slug` rather than replacing `id`.
Existing rows are not backfilled: they have no slug until an operator sets one,
which is also why the new `UNIQUE` constraint cannot be violated by data that
predates it.
