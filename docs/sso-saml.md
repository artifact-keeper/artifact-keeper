# SAML SSO: finding and formulating the ACS URL

Configuring a SAML identity provider against Artifact Keeper requires giving
the IdP an **Assertion Consumer Service (ACS)** URL. That URL currently embeds
the SAML configuration's database id, which is a server-generated UUID. This
page documents how to obtain and construct it, and what to expect when you
rebuild an environment from scratch.

This is the documentation half of issue #2583. The identifier itself is not yet
configurable — see [Why the UUID, and what changes](#why-the-uuid-and-what-changes-later)
below.

## The URL shape

```text
https://<artifact-keeper-host>/api/v1/auth/sso/saml/<saml-config-uuid>/acs
```

The matching login-initiation URL, which is what the web UI links to, is:

```text
https://<artifact-keeper-host>/api/v1/auth/sso/saml/<saml-config-uuid>/login
```

Both take the **same** UUID: the primary key of the row in `saml_configs`.

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

There is no way to pin the id today. `saml_configs.id` defaults to
`gen_random_uuid()`, so a redeploy that wipes the database produces a new UUID
and the ACS URL registered at the IdP must be updated.

Practical workarounds, in rough order of preference:

1. **Do not wipe the database.** Treat `saml_configs` as persistent state.
   Restoring it — or just the one row — preserves the id and the IdP needs no
   change.
2. **Look the id up after bootstrap and feed it forward.** Because `name` is
   `UNIQUE NOT NULL`, a fixed name is a stable handle even when the id is not.
   The `jq` snippet above is the whole lookup; in Terraform this is the
   `null_resource` + `external` data source pattern several operators already
   use, keyed on the provider name.
3. **Seed the row with a fixed id.** `POST /api/v1/admin/sso/saml` does not
   accept an `id` — the server always generates one — so this only works at the
   SQL level: have a bootstrap/seed script `INSERT INTO saml_configs (id, ...)`
   with a UUID you chose and keep in configuration management. This is the only
   way to get a byte-stable ACS URL across a full database wipe today. Generate
   the UUID once, properly at random; do not invent a memorable one.

## Why the UUID, and what changes later

The route parses its path segment as a UUID and looks the configuration up by
primary key. `saml_configs` already has a `UNIQUE NOT NULL` `name`, so the
uniqueness half of "identify a provider by a name I choose" is satisfied at the
schema level — what is missing is a URL-safe, normalized form of it and route
acceptance for it.

The planned direction (tracked in #2583) is to add a separate, validated,
URL-safe `slug` and have the SAML routes accept either a UUID or a slug, rather
than to change the primary key. Changing the key would rewrite the ACS URL of
every deployment that is currently working — inflicting the exact breakage the
issue is about on everyone who is not affected by it today — and
`sso_sessions.provider_id` and `groups.external_provider_id` both store the
provider id as a UUID shared across the OIDC, LDAP and SAML provider types.

Until then, the name-based lookup in workaround 2 is the supported way to keep
a DRY configuration.
