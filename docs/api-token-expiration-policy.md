# API token expiration policy

Administrators can require that newly-minted API tokens expire, bound the
acceptable expiration range, and apply a default when a client does not ask
for one. This limits the abuse window of a leaked credential and supports
compliance postures (SOC 2, ISO 27001) that forbid non-expiring secrets.

This is issue #3460. The policy ships **disabled**: until an administrator
turns it on, token creation behaves exactly as before (`expires_in_days`
optional, omitted = never expires).

## What the policy governs — and what it never touches

The policy is enforced at **mint time only**, inside the single choke-point
every token-creating endpoint funnels through (personal tokens, profile
access tokens, repository-scoped tokens, service-account tokens, and
admin-minted user tokens). Two consequences:

* **Tokens that already exist are never retroactively expired.** Enabling the
  policy on an existing deployment cannot invalidate a credential a pipeline
  is already running on. Instead, the policy endpoint reports how many live
  never-expiring tokens exist (split into user-held and service-account-held)
  so you can rotate them deliberately, on your own schedule, using the
  existing revocation endpoints.
* **A token minted under the policy cannot escape it.** Expiry is stamped on
  the token row and checked by the single token validator used by every
  authentication surface (API Bearer, package-client Basic auth,
  `docker login`, the OCI `/v2/token` exchange). Additionally, a `/v2/token`
  exchange caps the bearer JWT it issues at the presenting credential's own
  expiry, so repeatedly re-exchanging bearers cannot extend access past the
  underlying token's lifetime.

## Behaviour while enforcing

With `require_expiration: true`:

| Client request | Result |
| --- | --- |
| Omits `expires_in_days` | The configured `default_days` is applied (the response's `expires_at`/`policy_applied` fields say so). If no default is configured, the request is rejected with a message naming the permitted range. |
| `expires_in_days` within `[min_days, max_days]` | Accepted as requested. |
| `expires_in_days` outside the range | Rejected (HTTP 400) with a message naming the permitted range. |
| Service-account token mint | **Exempt by default** — see below. |

Because omitted expirations are *defaulted* rather than rejected, older
clients and scripts that never send `expires_in_days` keep working the moment
the policy is switched on; only explicit out-of-range requests fail.

### Service accounts

Service-account tokens are the credentials CI pipelines run on; a mandatory
expiry there is an outage on a schedule. They are therefore exempt unless you
explicitly set `apply_to_service_accounts: true`. If you opt them in, make
sure your pipelines have a rotation story (the `expires_at` field in each
token-creation response and token listing tells you when each credential
dies).

## Managing the policy

### Runtime (admin API)

```text
GET /api/v1/admin/settings/token-policy   -> current policy + never-expiring-token inventory
PUT /api/v1/admin/settings/token-policy   -> update the policy (admin only)
```

Read the current policy and the inventory of live never-expiring tokens:

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  https://ak.example.com/api/v1/admin/settings/token-policy
```

```json
{
  "policy": {
    "require_expiration": false,
    "min_days": 1,
    "max_days": 90,
    "default_days": 90,
    "apply_to_service_accounts": false
  },
  "source": "database",
  "editable": true,
  "non_expiring_user_tokens": 4,
  "non_expiring_service_account_tokens": 2
}
```

Enable a 90-day policy:

```bash
curl -X PUT -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"policy": {"require_expiration": true, "min_days": 1, "max_days": 90,
       "default_days": 90, "apply_to_service_accounts": false}}' \
  https://ak.example.com/api/v1/admin/settings/token-policy
```

A relaxed 365-day posture: same body with `"max_days": 365, "default_days": 365`.
Disable enforcement: `"require_expiration": false` (the other fields are kept
but inert). An internally inconsistent policy (`min_days > max_days`, or a
`default_days` outside the range — which would make every defaulted mint
fail) is refused with HTTP 400 before anything is stored.

Policy changes take effect immediately for new mints — no restart — and are
recorded in the audit log as `API_TOKEN_POLICY_CHANGED`. Token creations
carry their stamped `expires_at` and a `policy_applied` marker in the
`API_TOKEN_CREATED` audit event for compliance review.

### Deployment-time (environment pin)

Setting `API_TOKEN_EXPIRATION_REQUIRED` pins the policy and makes the API
read-only (`PUT` returns 409; `GET` reports `"source": "environment"`):

| Variable | Meaning | Default when pinned |
| --- | --- | --- |
| `API_TOKEN_EXPIRATION_REQUIRED` | `true`/`false` — activates the pin | (unset = no pin) |
| `API_TOKEN_EXPIRATION_DAYS_MIN` | Minimum accepted `expires_in_days` | `1` |
| `API_TOKEN_EXPIRATION_DAYS_MAX` | Maximum accepted `expires_in_days` (hard ceiling 3650) | `90` |
| `API_TOKEN_EXPIRATION_DAYS_DEFAULT` | Applied when the request omits an expiry; `none` = reject instead | `90` |
| `API_TOKEN_EXPIRATION_INCLUDE_SERVICE_ACCOUNTS` | `true` subjects service-account mints to the policy | `false` |

`API_TOKEN_EXPIRATION_REQUIRED=false` plus a restart is the offline
break-glass: it turns enforcement off regardless of what is stored in the
database, without needing a working login. An unparseable or internally
inconsistent pin is ignored with a warning (the stored setting then governs),
so a typo can neither reject every mint nor silently disable stored
enforcement.

## Upgrade note

Upgrading to a version with this feature changes **nothing** by itself:

* The seeded policy is `require_expiration: false` — the historical
  behaviour.
* Existing tokens, including never-expiring ones, continue to work before and
  after you enable the policy. Use the `non_expiring_*` counts on
  `GET /api/v1/admin/settings/token-policy` to find and rotate them.
* Token-creation responses now additionally return `expires_at` and
  `policy_applied`; existing fields are unchanged.
* `/v2/token` (Docker/OCI) exchanges now cap the issued bearer's `expires_in`
  at the presenting credential's remaining lifetime. Clients that honour
  `expires_in` (Docker does) are unaffected; a credential within 30 minutes
  of expiry now yields a correspondingly shorter bearer instead of one that
  outlives it.
