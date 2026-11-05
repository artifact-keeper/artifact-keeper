# Detection metrics

The backend exports these on `/metrics` (Prometheus text format) so an
operator can alert on abuse that otherwise shows only as a log line, or not at
all: connections held open, rate-limit refusals, SSRF refusals, rejected
credentials and proxy-scan decisions (#4676). Every label value comes from a
fixed set. No series carries a username, token, address, URL, repository name,
tag or digest.

The `LOGIN_RATE_LIMITED` audit row, the
`ak_permission_condition_evaluations_total` counter and joining gateway and
backend logs (#4677) are described in
[detection-signals.md](detection-signals.md).

## Counters reset on restart

Every `_total` series below is a Prometheus counter. It starts at zero when a
backend process starts, so it drops to zero on every rollout, restart or
crash, and each replica counts only its own traffic. Chart and alert on
`increase()` or `rate()`, summed across replicas, never on the raw value: a
dashboard of raw values reads a rollout as "the attack stopped".

```promql
# Rejected credentials per surface over the last 15 minutes, all replicas
sum by (surface, reason) (increase(ak_auth_failures_total[15m]))
```

## Connections

| Metric | Type | Labels | Moves when |
|---|---|---|---|
| `ak_http_connections_open` | gauge | none | a TCP connection is accepted (+1) and when hyper finishes with it (-1), however it ends |
| `ak_http_header_read_timeouts_total` | counter | none | a connection is closed because the client did not send a complete request head within `HTTP_HEADER_READ_TIMEOUT_SECS` (#4665); idle keep-alive closes are not counted |

`ak_http_connections_open` includes idle keep-alive connections and
connections still sending a request head. A slow-connection hold shows as this
gauge climbing while `ak_http_requests_total` does not; compare it with the
listener backlog (`HTTP_LISTEN_BACKLOG`) and the process file-descriptor
limit. It covers the main API listener, not the separate `METRICS_PORT`
listener.

## Rate limiting

| Metric | Type | Labels | Moves when |
|---|---|---|---|
| `ak_rate_limit_rejections_total` | counter | `limiter` | a request is refused with 429 |

`limiter` is one of:

| Value | Limits |
|---|---|
| `login` | `POST /api/v1/auth/login`, per (username, source IP) |
| `token` | `/v2/token` password exchanges, per (username, source IP) |
| `login_global` | the global backstop shared by login and `/v2/token` |
| `auth` | the public `/api/v1/auth` routes (refresh, logout, ...) and TOTP verification |
| `api` | authenticated `/api/v1` routes |
| `search` | search routes |
| `presign` | routes that mint presigned download URLs, per source IP |
| `password_change` | self-service password change, per user |
| `device_code` | `POST /api/v1/auth/device/code`, per source IP |
| `device_token` | `POST /api/v1/auth/device/token` polling, per source IP |
| `device_approval` | device code verify, approve and deny, per user |
| `upload` | a principal already at its concurrent-upload limit (`UPLOAD_MAX_IN_FLIGHT_PER_PRINCIPAL`) |
| `proxy_rescan` | a proxy rescan asked for inside the per-repository cooldown |

The limiters are per replica; their budgets are in the rate-limiting section
of `.env.example`.

## SSRF guard

| Metric | Type | Labels | Moves when |
|---|---|---|---|
| `ak_ssrf_blocks_total` | counter | `surface` | an outbound URL, redirect hop or resolved address is refused by the SSRF guard |
| `ak_outbound_url_blocked_total` | counter | `reason`, `label` | the same refusals at URL validation and redirect time, by `reason` (`hostname` or `ip`) and the caller's field name (`label`, for example `Webhook URL`) |

`surface` is one of `upstream` (remote and proxy repositories, migration and
remote-instance sources, format upstream downloads), `webhook`, `sso` (OIDC
discovery, token, JWKS and userinfo fetches), `ldap`, `plugin` (plugin git and
callback URLs), `peer` (replication peer endpoints) and `internal`
(operator-configured internal services such as the scanner adapter and the
egress proxy). A connect-time refusal, where every address a hostname
resolved to is blocked, is counted in `ak_ssrf_blocks_total` only.

## Rejected credentials

| Metric | Type | Labels | Moves when |
|---|---|---|---|
| `ak_auth_failures_total` | counter | `surface`, `reason` | a presented credential is rejected |

`surface`:

| Value | Credential |
|---|---|
| `api` | `POST /api/v1/auth/login`; a Bearer JWT, API token or `X-API-Key` on any route; a malformed `Authorization` header; a download ticket |
| `basic` | HTTP Basic `username:password` on any route (package clients) |
| `v2_token` | the OCI credential exchange, `/v2/token` (Basic, password form, Bearer swap, refresh grant) |
| `ci_oidc` | the CI OIDC token exchange, `POST /api/v1/auth/ci/token` |
| `sso` | OIDC callbacks and code exchange, SAML assertions, LDAP sign-in |

`reason`:

| Value | Meaning |
|---|---|
| `bad_password` | wrong password for an account that can sign in with one, or a rejected LDAP bind |
| `unknown_user` | no account that can sign in with a password: unknown or inactive username, a federated account, or one with no stored password |
| `lockout` | wrong password for an account whose lockout is in force |
| `expired` | a token or assertion past its expiry |
| `invalid_token` | a token, assertion, SSO state or header that did not validate |
| `scope` | a valid assertion that no policy admits: no CI OIDC mapping matches, or the identity provider's user is refused (automatic account creation off) |

Only a credential that was presented and rejected counts. A request with no
credential, and a check that could not finish (a 503 for a database outage or
a saturated bcrypt cap), are not counted. A request is counted once, by the
check that answered it. The OCI content routes (`/v2/<name>/manifests/...`,
`/blobs/...`) check the token a client obtained from `/v2/token` themselves
and are not counted; the `/v2/token` exchange that hands out those tokens is.

```promql
# A password sweep: many unknown usernames from the login form or package clients
sum by (surface) (increase(ak_auth_failures_total{reason="unknown_user"}[10m])) > 50
```

## Proxy scans

| Metric | Type | Labels | Moves when |
|---|---|---|---|
| `ak_proxy_scan_verdicts_total` | counter | `verdict`, `action` | a pull from a repository with scan-on-proxy enabled passes the scan gate |
| `ak_proxy_scan_queue_refused_total` | counter | `limit` | a proxied file gets no scan for now because the in-flight table has no room: `423` under `fail_closed`, served `pending` otherwise. `limit` is `scans`, `bytes`, `repository_scans`, `repository_bytes`, `scan_waiters` or `repository_waiters` |
| `ak_proxy_scan_abandoned_total` | counter | | a queued `fail_closed` scan leaves the queue because no request has wanted it for 30 seconds |

`verdict` is what the pull was judged as: `clean`, `vulnerable`, `pending` (a
first pull served before its scan, fail-open or record-only) or `inconclusive`
(an object over the scan size cap, or a scan that could not finish). A
vulnerable verdict below the repository's opted-in severity threshold is
served and counted as `clean`.

`action` is what was done with the pull: `served`, `blocked` (403),
`locked` (423 under fail-closed) or `recorded` (a record-only repository
serving a vulnerable verdict).

## Not included

`ak_storage_used_bytes` has no `repository` label. The backend keeps no
per-repository storage gauge to attach one to, and a per-repository series
would grow with the number of repositories; per-repository usage is available
from the repository API.
