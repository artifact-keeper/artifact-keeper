# Device authorization (RFC 8628)

A client that cannot open a browser, such as a CLI on a remote host, a CI
runner, or a device with no keyboard, can sign a user in with the OAuth 2.0
Device Authorization Grant ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)).
The client shows the user a short code; the user enters it at `/device` in a
browser where they are already signed in to Artifact Keeper and approves it; the
client receives an Artifact Keeper access token and refresh token.

This is a plain Artifact Keeper grant. The approving user signs in however the
instance already allows (local password, LDAP, OIDC or SAML SSO), and the client
receives AK-native tokens. It is **not** an OpenID Connect device flow: AK
publishes no OIDC discovery document and issues no `id_token`, and the scopes
`openid`, `profile` and `email` are rejected.

The grant is **off by default**. It is an unauthenticated way to start a
sign-in, and device-code phishing (an attacker starts a flow and persuades a
victim to approve the code) is a known attack, so turn it on only if you need
it.

## Settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `DEVICE_AUTH_ENABLED` | `false` | `true` or `1` enables the grant. While it is off, every route below answers 404. |
| `DEVICE_AUTH_CODE_TTL_SECS` | `600` | Lifetime of a code (60 to 1800). |
| `DEVICE_AUTH_POLL_INTERVAL_SECS` | `5` | Minimum seconds between token polls (1 to 60). |
| `DEVICE_AUTH_CODE_REQUESTS_PER_WINDOW` | `10` | Device-code requests per client IP per `RATE_LIMIT_WINDOW_SECS` (1 to 1000). |
| `DEVICE_AUTH_MAX_FAILED_ATTEMPTS_PER_USER` | `5` | Wrong user codes one user may enter per window (1 to 100). |
| `DEVICE_AUTH_MAX_FAILED_ATTEMPTS_PER_IP` | `20` | Wrong user codes one client IP may enter per window (1 to 1000). |
| `DEVICE_AUTH_FAILED_ATTEMPT_WINDOW_SECS` | `900` | Window for both failed-attempt budgets (60 to 86400). |

Values outside the ranges are clamped. Behind a reverse proxy, set
`RATE_LIMIT_TRUSTED_PROXY_CIDRS` so the per-IP limits see the real client
address rather than the proxy's. `GET /api/v1/system/config` reports
`auth.device_authorization_enabled`.

## Endpoints

| Endpoint | Caller | Purpose |
| --- | --- | --- |
| `POST /api/v1/auth/device/code` | client, no auth | Start a flow (RFC 8628 §3.1). |
| `POST /api/v1/auth/device/token` | client, no auth | Poll, then redeem (§3.4). |
| `GET /device` | user's browser | The approval page (`verification_uri`). |
| `POST /api/v1/auth/device/verify` | signed-in user | Show what a code asks for. |
| `POST /api/v1/auth/device/approve` | signed-in user | Approve a code. |
| `POST /api/v1/auth/device/deny` | signed-in user | Deny a code. |

The two client endpoints take `application/x-www-form-urlencoded` bodies, as
RFC 8628 specifies, and answer errors as `{"error", "error_description"}`
(RFC 6749 §5.2). `/device/code` also accepts JSON.

### Starting a flow

```
POST /api/v1/auth/device/code
Content-Type: application/x-www-form-urlencoded

client_id=my-cli&scope=read:artifacts+write:artifacts
```

```json
{
  "device_code": "…64 hex characters…",
  "user_code": "BCDF-GHJK",
  "verification_uri": "https://registry.example.com/device",
  "expires_in": 600,
  "interval": 5
}
```

`client_id` is any label of 1 to 128 printable ASCII characters; there is no
client registration, and no client secret. `scope` is a space-separated list of
AK token scopes. It defaults to `read:artifacts`. `*` and `admin` are never
available through this grant. The response has no `verification_uri_complete`:
the page never accepts a code from its URL, so a link cannot carry an
approvable code.

### Polling

```
POST /api/v1/auth/device/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=…&client_id=my-cli
```

Until the user decides, the answer is HTTP 400 with one of:

| `error` | Meaning |
| --- | --- |
| `authorization_pending` | Not decided yet. Wait `interval` seconds and poll again. |
| `slow_down` | Polled too early. The interval for this code is now 5 seconds longer (up to 60). |
| `access_denied` | The user denied the request. |
| `expired_token` | The code expired. Start again. |
| `invalid_grant` | Unknown code, a `client_id` that does not match the one that started the flow, or a code that was already redeemed. |

After approval, the next poll returns the tokens once:

```json
{
  "access_token": "…",
  "token_type": "Bearer",
  "expires_in": 1800,
  "refresh_token": "…",
  "scope": "read:artifacts write:artifacts"
}
```

Refresh through `POST /api/v1/auth/refresh` as for any session. Refresh tokens
rotate, reuse revokes the family, logout revokes it, and a refresh keeps the
granted scopes.

## What the user sees and who can approve

The user opens `/device`, types the code, and sees the scopes the device will
receive, including any requested scope their own account cannot grant (those
are dropped). The page never shows the client-chosen `client_id`, because it is
unverified text.

Only an interactive session can verify, approve or deny: a session JWT from a
normal sign-in. The following are refused with 403 and audited:

- API tokens, and JWTs exchanged from one (they carry a scope ceiling);
- service accounts;
- download tickets;
- Basic username and password;
- any JWT that carries a scope list or a repository restriction.

Without this, a narrow or expiring credential could approve its own request and
receive a broader, refreshable session.

The tokens are capped at the requested scopes the approver may grant. A
non-admin cannot grant the admin-only scopes (`delete:artifacts`,
`delete:repositories`, `promote:artifacts`, `trigger:sync`, `write:users`,
`write:findings`). If none of the requested scopes can be granted, approval is
refused. At redemption the approver is checked again: an account disabled,
deleted or turned into a service account since approving receives nothing, and
one that lost admin loses the admin-only scopes.

An approval is also void if, after it was given, anything invalidated the
approver's sessions. Changing or resetting the password, a forced password
change, enabling or disabling TOTP, and a role or admin change all make the
device's next poll answer `invalid_grant` with a `DEVICE_TOKEN_REJECTED` audit
row. So does revoking any of the approver's refresh families, which includes
signing out of a single session. Changing your password therefore also stops a
device you approved but that has not yet collected its tokens. Tokens a device
has already collected are revoked like any other session.

Wrong, malformed, expired or already-decided codes count against the per-user
and per-IP failed-attempt budgets. Once either budget is spent, verify, approve
and deny answer 429 until the window passes. These budgets ignore
`RATE_LIMIT_ENABLED` and the rate-limit exemptions, because they guard a secret
rather than shed load. They are kept per process, so each replica keeps its own.

User codes are 8 characters from `BCDFGHJKLMNPQRSTVWXZ` (no vowels, no digits;
about 2^34.6 possibilities) and are case- and hyphen-insensitive.

At most 10,000 unexpired flows exist instance-wide; past that,
`/device/code` answers 503 `temporarily_unavailable` until the sweep removes
expired ones. With the per-IP limit (10 per window) and the 10-minute lifetime,
roughly 100 client IPs acting together can fill that pool and deny new device
sign-ins for a while. Nothing else in Artifact Keeper is affected. A per-IP
cap on live flows would narrow this and is a possible follow-up.

## Headless deployments

`/device` is served by the backend, so it works when the web frontend is not
deployed, and it loads with guest access disabled. The user still needs a
browser session: with SSO, completing the provider sign-in sets it, after which
the user returns to `/device`. With the web frontend disabled and only local
accounts, there is currently no sign-in page to create that session.

## Audit events

| Action | When |
| --- | --- |
| `DEVICE_CODE_ISSUED` | A client started a flow (anonymous actor; client IP, `client_id`, scopes). |
| `DEVICE_AUTHORIZATION_APPROVED` | A user approved (granted and withheld scopes). |
| `DEVICE_AUTHORIZATION_DENIED` | A user denied. |
| `DEVICE_AUTHORIZATION_FAILED` | A refused verify/approve/deny, with `reason`: `invalid_or_expired_code`, `throttled`, `no_grantable_scope`, `account_not_eligible`, or the credential kind that was refused. |
| `LOGIN` (`auth_method: device_flow`) | Tokens were issued. |
| `DEVICE_TOKEN_REJECTED` | A redeemed code was presented again (`replay`), or the approver can no longer receive tokens (`approver_not_eligible`, `approver_inactive`, `approver_credential_changed`, `approver_must_change_password`, `approver_sessions_revoked`, `no_grantable_scope`). |
| `DEVICE_AUTHORIZATION_EXPIRED` | An approved code expired without being redeemed. |

Neither code appears in the audit trail, the logs or the database: both are
stored as SHA-256 digests. Expired flows are deleted within a minute.

## Example with oauth2c

The command below uses the standard device-grant options; check the flag names
against the oauth2c release you use.

```bash
oauth2c https://registry.example.com \
  --client-id my-cli \
  --grant-type urn:ietf:params:oauth:grant-type:device_code \
  --auth-method none \
  --device-authorization-endpoint https://registry.example.com/api/v1/auth/device/code \
  --token-endpoint https://registry.example.com/api/v1/auth/device/token \
  --scopes read:artifacts
```
