# LDAP/AD Basic-auth passthrough for package managers

Artifact Keeper's native package endpoints (npm, Composer, NuGet, PyPI, Cargo,
Maven, and the rest of the format handlers) accept a `username:password` HTTP
Basic credential. Historically that password had to be a local account's
password or an API token. Directory users had to mint a personal API token
before a `.npmrc`, `auth.json`, or `nuget.config` would work.

The LDAP Basic-auth passthrough lets those clients use the same LDAP/AD
username and password they use for the web UI. It is **off by default**.

## Enable it

```bash
LDAP_BASIC_AUTH_PASSTHROUGH=true
```

The instance must already have an enabled LDAP provider (configured through
the admin API or the `LDAP_*` environment bootstrap). No other change is
needed.

Restart is not required for the switch itself: the setting is read per auth
attempt. A restart only clears the in-process credential cache.

## What clients can use

Any format handler that accepts Basic auth works, for example:

```bash
# npm
npm login --registry https://registry.example.com/npm/my-repo

# Composer
composer config --global http-basic.registry.example.com alice 'AD-password'

# NuGet
dotnet nuget add source https://registry.example.com/nuget/my-repo/index.json \
  --name company --username alice --password 'AD-password' --store-password-in-clear-text

# PyPI / twine
twine upload --repository-url https://registry.example.com/pypi/my-repo \
  -u alice -p 'AD-password' dist/*
```

The generic `GET /api/v1/repositories/{key}/download/{path}` route uses the
same passthrough. The OCI Distribution API (`/v2/...` and `/v2/token`)
authenticates separately and is not changed by this switch.

When guest access is disabled (`AK_GUEST_ACCESS_ENABLED=false`), the global
guest-access guard checks only local credentials and never binds against the
directory. A Basic credential on a package route is handed to that route,
which performs at most one bind; a Basic credential on the management API or
`/v2` is refused by the guard, so those surfaces cause no directory traffic.
That also means one rejected package request writes exactly one
`LOGIN_FAILED` audit row.

## Order of credential checks

A Basic password is tried in this order, and the directory is contacted only
after all of the following fail:

1. the local bcrypt password hash;
2. a short-lived Artifact Keeper JWT (supported by CI keyless flows);
3. an Artifact Keeper API token (only on the format/registry surfaces, not on
   the management API);
4. the LDAP/AD bind — the passthrough.

This preserves existing local-account and token-based client setups. A user
who has both a local password hash and an LDAP account keeps using the local
password; the directory is not consulted.

## Security properties

- **Opt-in.** With the variable unset or `false`, nothing changes.
- **Shared login budget.** Passthrough binds draw from the same
  per-`(username, IP)` limiter as `/v2/token`, plus its global backstop. A
  cache hit does not consume the budget; only a real bind does.
- **Bounded AD lockout exposure.** After three distinct failed passwords for
  the same username (configurable), further passwords fail fast without
  binding until the failure window expires. A password the directory rejected
  is not bound again for that username inside the window, parallel requests
  with the same credential share one bind, and parallel distinct passwords
  count toward the cap while they are in flight. The default therefore binds
  at most three failed passwords per username per 30 minutes, below typical
  AD lockout thresholds. A password that becomes valid inside the window
  (for example after an AD password reset to a value just tried) is accepted
  once the window expires, or immediately after a successful login with any
  other accepted password clears the username's failures.
- **Tokens are never sent to the directory.** A Basic password shaped like an
  Artifact Keeper API token or JWT that failed the token checks (expired,
  revoked) is refused without a bind.
- **Directory outages are 503.** An unreachable directory, a timeout, or a
  rejected service-account bind answers a retryable `503`, not `401`, and is
  not counted as a failed password.
- **No plaintext credential cache.** Success and failure entries are hashed
  with a per-process random HMAC key over a domain-separated,
  length-prefixed `username || password` input. Only the tags and user IDs are
  kept; the password is never stored. The caches are bounded.
- **Five-minute success window.** A successful credential is reused for five
  minutes so a CI job doing many downloads does not bind on every request. A
  changed AD password works immediately (the new password is a new cache key);
  the old password stops working within five minutes.
- **Deactivation wins immediately.** Every cache hit re-reads
  `users.is_active` from the database. Admin deactivation and the periodic
  LDAP reconcile clear both the success and failure entries for the user. Web
  LDAP login now matches the passthrough: a successful directory bind does not
  reactivate an account an administrator disabled. An administrator must
  explicitly reactivate it.
- **Audited.** A successful passthrough login writes `LOGIN`; a rejected
  request writes exactly one `LOGIN_FAILED` event, whether the directory
  rejected the password or the failure was served from the failure window.
  Passwords are never included.
- **Locally managed accounts are never bound.** If a username exists with
  `auth_provider` other than `ldap`, the passthrough refuses without contacting
  the directory: a mistyped local password must not spend an AD account's
  failure budget.

## Tuning

| Variable | Default | Meaning |
| --- | --- | --- |
| `LDAP_BASIC_AUTH_PASSTHROUGH` | `false` | Master switch. |
| `LDAP_BASIC_AUTH_CACHE_TTL_SECS` | `300` | Success cache lifetime. `0` disables the success cache. |
| `LDAP_BASIC_AUTH_FAILURE_TTL_SECS` | `60` | How long a rejected credential is remembered. `0` disables the failure cache. |
| `LDAP_BASIC_AUTH_MAX_FAILED_PASSWORDS` | `3` | Distinct failed passwords per username before failing fast. `0` disables the cap. |
| `LDAP_BASIC_AUTH_FAILED_WINDOW_SECS` | `1800` | Window in which distinct failures are counted and a rejected password is not bound again. Keep it at least as long as the directory's lockout observation window. |
| `LDAP_BASIC_AUTH_CACHE_MAX_ENTRIES` | `4096` | Bound for the success and exact-credential failure caches. The per-username failure ledger holds 16 times this many usernames and evicts the oldest instead of clearing. |

The per-username failure cap is a client-side guard against Artifact Keeper
walking an account into lockout. It does not make the directory's own lockout
policy irrelevant: use the two together, and keep
`LDAP_BASIC_AUTH_MAX_FAILED_PASSWORDS` comfortably below the AD threshold.
