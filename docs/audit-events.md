# Structured audit event stream

Artifact Keeper can emit every recorded audit action as a self-contained,
machine-readable log record so operators can ship the audit trail to a SIEM by
collecting stdout — without polling the admin API (`GET /api/v1/admin/audit`) or
reading Postgres directly. This is issue #2413.

The emitted record is an instance of the committed JSON Schema at
[`backend/schemas/audit-event.v1.schema.json`](../backend/schemas/audit-event.v1.schema.json).
The line you collect *is* the schema instance — there is no message-text parsing
and no nested JSON-string to unwrap.

## Enabling

Two independent knobs, both read from the environment before configuration
loads (like the `OTEL_*` variables):

| Variable | Values | Default | Effect |
| --- | --- | --- | --- |
| `AUDIT_STREAM` | `off`, `stdout` | `off` | Emit audit records as NDJSON on stdout. |
| `LOG_FORMAT` | `text` (alias `pretty`), `json` | `text` | Format of the *diagnostics* log lines; see [operations/logging.md](operations/logging.md). |

The audit stream is **opt-in**. When `AUDIT_STREAM=off` (the default) nothing is
emitted and the code path short-circuits before the export record is even
constructed — one sink check per audit event — so there is no overhead and no
behavior change for existing deployments.

For a fully structured stdout, pair `AUDIT_STREAM=stdout` with `LOG_FORMAT=json`.
The two streams interleave on stdout. Audit records enter a bounded queue and a
dedicated writer writes each complete line under the stdout lock, so stdout
backpressure cannot stall request workers. Audit lines are
distinguished from diagnostics by the top-level `"category": "audit"` marker —
never by parsing message text. Operators who want full separation can route
diagnostics to stderr at the container/runtime level; that is out of scope here.

## Envelope

Every record has this stable, versioned shape:

| Field | Type | Notes |
| --- | --- | --- |
| `schema_version` | integer | `1`. Bumped only on a breaking change. |
| `category` | string | Always `"audit"`. The machine marker. |
| `event_id` | uuid | Equals the `audit_log` row id — the SIEM ↔ admin-API join key. |
| `timestamp` | date-time | Emit time (UTC, RFC 3339). Approximates the row's `created_at`; join on `event_id`. |
| `action` | string | SCREAMING_SNAKE action name (`LOGIN`, `REPOSITORY_CREATED`, …). |
| `outcome` | enum | `success` \| `failure` \| `denied`, derived from the action name. |
| `actor` | object | `{ id, name, type }` — see below. |
| `source_ip` | string \| null | The request's verified client IP, for every action recorded while handling a request (see below); `null` for background jobs and when the address is not verified. Same value as the row's `ip_address`. |
| `resource` | object | `{ type, id, name }` — the targeted resource. |
| `correlation_id` | string | Joins to request logs and traces (#2414). Behind a gateway listed in `RATE_LIMIT_TRUSTED_PROXY_CIDRS` it is the gateway's `X-Request-ID` (#4677). |
| `details` | object \| null | Typed for representative events (below); permissive otherwise. |

`source_ip` (the `audit_log.ip_address` column) is populated for every action
written while handling an HTTP request, not only authentication events
(#4762). It is the address the client-IP resolution grades as verified
(#3888, #4681): the TCP peer, or the `X-Forwarded-For`-derived address only
when the peer is a trusted proxy and `XFF_TRUSTED_FOR_AUTHZ=true`. Behind a
trusted proxy without that assertion, and for rows written by background
jobs (janitors, schedulers, replication), it is `null`, never a guessed or
client-supplied address.

`actor.type` is one of `system`, `user`, `anonymous`, or the reserved
`service_account` (not yet emitted). `actor.name` is best-effort — it is
populated only where the emitter already had the name in hand (there is no
query-time join at emit time) and is `null` otherwise. Treat `actor.name` as
informational: on failed-authentication events (`anonymous` actors) it can carry
the *attempted* username — unauthenticated caller- or identity-provider-supplied
input — so detection and access decisions should key on `actor.type` and
`actor.id`, never on the name alone.

For the password/session lifecycle events (`PASSWORD_CHANGED`,
`SESSIONS_INVALIDATED`), the envelope's `actor` is the initiating principal
(the acting admin on an admin reset), while the `audit_log` row's `user_id`
column keeps its established subject-keyed semantics — the stream does not
change what the admin API returns.

## Examples

Human login (request-scoped, `LOG_FORMAT=json` diagnostics elided):

```json
{"schema_version":1,"category":"audit","event_id":"7b6e...","timestamp":"2026-07-11T18:30:02.145Z","action":"LOGIN","outcome":"success","actor":{"id":"1f2c...","name":"alice","type":"user"},"source_ip":null,"resource":{"type":"user","id":"1f2c...","name":null},"correlation_id":"3d0f...","details":{"username":"alice"}}
```

Failed login for an unknown principal (anonymous actor, `failure` outcome):

```json
{"schema_version":1,"category":"audit","event_id":"...","timestamp":"...","action":"LOGIN_FAILED","outcome":"failure","actor":{"id":null,"name":null,"type":"anonymous"},"source_ip":null,"resource":{"type":"user","id":null,"name":null},"correlation_id":"...","details":{"username":"root"}}
```

Authorization denial (`denied` outcome):

```json
{"schema_version":1,"category":"audit","event_id":"...","timestamp":"...","action":"PERMISSION_DENIED","outcome":"denied","actor":{"id":"...","name":null,"type":"user"},"source_ip":null,"resource":{"type":"user","id":"...","name":null},"correlation_id":"...","details":{"path":"/api/v1/admin/users","method":"GET","reason":"admin_privileges_required"}}
```

API token created (typed `TokenDetails`; the secret is never present):

```json
{"schema_version":1,"category":"audit","event_id":"...","timestamp":"...","action":"API_TOKEN_CREATED","outcome":"success","actor":{"id":"...","name":null,"type":"user"},"source_ip":null,"resource":{"type":"api_token","id":"...","name":null},"correlation_id":"...","details":{"token_id":"...","token_name":"ci","surface":"profile"}}
```

System-initiated reaping of a stuck scan (`system` actor, one record per reaped
row, all sharing the sweep's `correlation_id`):

```json
{"schema_version":1,"category":"audit","event_id":"...","timestamp":"...","action":"SCAN_REAPED","outcome":"success","actor":{"id":null,"name":"system:stuck_scan_janitor","type":"system"},"source_ip":null,"resource":{"type":"scan_result","id":"...","name":null},"correlation_id":"sweep-...","details":{"actor":"system:stuck_scan_janitor","scan_id":"...","reason":"stuck_running_janitor"}}
```

## Typed detail payloads

The `details` object is typed for the representative security-lifecycle events;
each shape is a `$def` in the schema. Actions not yet typed carry an ad-hoc
object and remain schema-valid under the permissive `details` fallback — typing
the remaining actions is an incremental follow-up.

| Actions | `details` shape |
| --- | --- |
| `REPOSITORY_CREATED` / `_UPDATED` / `_DELETED` | `RepositoryDetails` (`actor_id`, `key`, `is_public`, structured format/policy fields; `upstream_change` / `upstream_auth_change` on credential changes, secrets never carried; on `_UPDATED`, `project_change` `{previous_project_id, project_id}` when the project assignment changed, `project_id: null` for a cleared assignment, #4026; an age-gate policy change adds `age_gate_change`: the replaced policy, `actor_tier`, and `relaxed`) |
| `AGE_GATE_LOCK_SET` / `AGE_GATE_LOCK_RELEASED` | `lock` (`policy` / `review`), `actor_tier`, `repository_key`, and the policy (`age_gate_*`) or review (`review_id`, `package`, `version`, `status`) at that moment. A release is always a relaxation. |
| `ROLE_ASSIGNED` / `_REVOKED`, `REPOSITORY_PERMISSION_CHANGED` | `PermissionDetails` (`actor_id`, `role_id`, `grantee_id`, `repository_id?`) |
| `API_TOKEN_CREATED` / `_REVOKED` | `TokenDetails` (`token_id`, `token_name?`, `surface`, `expires_at?`, `policy_applied?`) |
| `LOGIN_FAILED`, `PERMISSION_DENIED`, `LOGIN_RATE_LIMITED` | `AuthDetails` (`username?`, `path?`, `method?`, `reason?`, federated labels?) |
| `ARTIFACT_UPLOADED` / `_DOWNLOADED` / `_DELETED` | `ArtifactDetails` (`repository_id`, `path`, `name`, `version?`, `size_bytes?`, `digest?`, `uploaded_by?`) |
| `SETTING_CHANGED` | `SettingDetails` (`key`, `old_value?`, `new_value?`) |

## Privileged administrative actions

These actions record who changed a security-relevant configuration or
released, approved or promoted content (#4710). Each row's `user_id` (and the
envelope's `actor`) is the authenticated principal; `resource` is the target
named below. `details` never carries a secret: no client secret, bind
password, key material, token, or webhook secret or secret digest, only flags
such as `credential_replaced` or `secret_rotated`.

| Action | Resource | `details` |
| --- | --- | --- |
| `QUARANTINE_RELEASED` | `artifact` (or `repository` for a held proxy-cache entry) | `artifact_id`, `previous_status`; for a proxy-cache entry `repository`, `path`, `proxy_cache: true` |
| `QUARANTINE_REJECTED` | `artifact` | `artifact_id`, `previous_status`, `reason` |
| `PROMOTION_APPROVAL_GRANTED` | `promotion_approval` | `approval_id`, `artifact_id`, `artifact_path`, `source_repository`, `target_repository`, `requested_by`, `promoted_artifact_id`, `promotion_id`, `skip_policy_check`, `notes` |
| `PROMOTION_APPROVAL_DENIED` | `promotion_approval` | `approval_id`, `artifact_id`, `source_repository`, `target_repository`, `requested_by`, `notes` |
| `ARTIFACT_PROMOTED` | `artifact` (the source artifact) | `artifact_id`, `artifact_path`, `source_repository`, `target_repository`, `promotion_id`, `skip_policy_check`, `bulk`, `gate_results` (`evaluated`, `failed`, `failed_rules`), `policy_violations` (count) |
| `PROMOTION_REFUSED` | `artifact` | as `ARTIFACT_PROMOTED`, with `promotion_id: null` and the refusal `message`. Written when the quality gate, the promotion policy or a promotion rule refuses the promotion (single or bulk item) |
| `PROMOTION_REJECTED` | `artifact` | `artifact_id`, `source_repository`, `rejection_id`, `reason`, `notes` |
| `PERMISSION_RULE_CREATED` / `_DELETED` | `permission_rule` | `principal_type`, `principal_id`, `principal_name`, `target_type`, `target_id`, `target_name`, `actions`, `conditions` |
| `PERMISSION_RULE_UPDATED` | `permission_rule` | `changed_fields`, `before`, `after` (each the shape above) |
| `SSO_PROVIDER_CREATED` | `sso_provider` | `provider_type` (`oidc`, `ldap`, `saml`), `name`, `is_enabled` |
| `SSO_PROVIDER_UPDATED` | `sso_provider` | `provider_type`, `name`, `changed_fields`, `credential_replaced` |
| `SSO_PROVIDER_DELETED` | `sso_provider` | `provider_type`, `name` |
| `SSO_PROVIDER_ENABLED` / `_DISABLED` | `sso_provider` | `provider_type`, `name`, `is_enabled` |
| `SIGNING_KEY_ROTATED` | `signing_key` (the old key) | `key_id`, `name`, `key_type`, `algorithm`, `fingerprint`, `repository_id`, `new_key_id`, `new_fingerprint` |
| `SIGNING_KEY_REVOKED` | `signing_key` | `key_id`, `name`, `key_type`, `algorithm`, `fingerprint`, `repository_id` |
| `SIGNING_KEY_TRUST_ATTESTED` | `signing_key` | `key_id`, `name`, `key_type`, `algorithm`, `fingerprint`, `repository_id`, `issuer_fingerprint`, `issuer_name`, `verification_status` |
| `WEBHOOK_CREATED` | `webhook` | `name`, `url`, `events`, `repository_id`, `signing_mode`, `signed` |
| `WEBHOOK_UPDATED` | `webhook` | `name`, `url`, `events`, `repository_id`, `is_enabled` (written by enable and disable) |
| `WEBHOOK_DELETED` | `webhook` | `name`, `url`, `events`, `repository_id` |
| `WEBHOOK_SECRET_ROTATED` | `webhook` | `name`, `url`, `events`, `repository_id`, `secret_rotated: true`, `previous_secret_expires_at` |
| `SYNC_POLICY_CREATED` / `_DELETED` | `sync_policy` | `name`, `policy` (the policy without timestamps) |
| `SYNC_POLICY_UPDATED` | `sync_policy` | `name`, `changed_fields`, `before`, `after` (written by update and by enable / disable) |

A webhook `url` is recorded as scheme, host, port and path: userinfo, query
string and fragment are dropped because receivers often carry a token there.
`PROMOTION_REFUSED` and `PROMOTION_APPROVAL_DENIED` export with outcome
`denied`; the others export as `success`.

## Conda channel and environment actions

Conda publishes, withdrawals and CEP-27 attestation outcomes, and stored
environment registrations and deletions, each write one row (#4709). Every
row's `user_id` / `actor.id` is the authenticated caller, and `details` carries
the repository (`repository` key, `repository_id`) plus the fields below. The
conda rows also carry `repository_type` and the package coordinates under
`package`: `{ name, version, build, subdir, filename }` (name, version and build
come from the CEP-26 filename and are `null` when it does not parse).

| Action | Resource | Fires when | `details` beyond the common fields |
| --- | --- | --- | --- |
| `ARTIFACT_UPLOADED` | `artifact` | A package is published natively (`PUT /conda/{key}/{subdir}/{file}` or `POST /conda/{key}/upload`, including the `/t/{token}/` forms) to a hosted or staging channel and its artifact row is committed. | The `ArtifactDetails` fields (`path`, `name`, `version`, `size_bytes`, `digest`, `uploaded_by`). The `artifact.uploaded` webhook fires as before. |
| `CONDA_PACKAGE_WITHDRAWN` | `artifact` | An administrator withdraws a hosted package (`DELETE /conda/{key}/{subdir}/{file}`). | `artifact_id`; `reason` (the supplied reason, or the default text) and `reason_supplied`; `hold` (`quarantine_status`, `permanent: true`); `notice` (the CEP-6 notice `id` and `message`). |
| `ATTESTATION_VERIFIED` | `artifact` | A CEP-27 attestation (`PUT .../{file}/attestation`) verifies and is stored. | `artifact_id`, `stored: true`, `method` (`sigstore-keyless` or `sigstore-key`), `identity`, `issuer`, `key_fingerprint` (key-based only), `statement_type`, `checks_passed`. |
| `ATTESTATION_REJECTED` | `artifact` | An attestation for an existing package does not verify, or its body is not JSON. Outcome `denied` when refused (the default, `CONDA_ATTESTATION_REQUIRE_VERIFIED=true`); outcome `failure` with `stored: true` when the operator opt-out stored it anyway. | The same fields as `ATTESTATION_VERIFIED`, with `reason`: the failure reason the API returned (the text after `CEP-27 attestation verification failed: `, or `Invalid JSON body`). |
| `ENVIRONMENT_REGISTERED` | `environment` | A lockfile is ingested as a stored environment (`POST /api/v1/repositories/{key}/environments`), new or replacing one of the same name. | `environment_id`, `name`, `lockfile_format`, `lockfile_filename`, `content_sha256`, `replaced`, `package_count` (distinct packages), `memberships`, `scope` (`count`, `environments`, `platforms`). |
| `ENVIRONMENT_DELETED` | `environment` | A stored environment is deleted (`DELETE /api/v1/repositories/{key}/environments/{id}`). | `environment_id`, `name`, `lockfile_format`, `content_sha256`, and the stored `summary`. |

## Detection events

Two actions close detection gaps found by the 1.11.0 red team (#4677).

| Action | Resource | Fires when | `details` |
| --- | --- | --- | --- |
| `LOGIN_RATE_LIMITED` | `user` (no id) | A login limiter refuses `POST /api/v1/auth/login` or an OCI credential exchange on `/v2/token` with 429. At most one row per source IP per limiter window; see below. Outcome `denied`. | `AuthDetails`: `username` (the attempted name, as `LOGIN_FAILED` records it; never the password), `path`, `method`, and `reason`, the limiter: `login_per_account` (the per-username-and-IP bucket) or `login_global_backstop`. |
| `EXTERNAL_FINDINGS_INGESTED` | `artifact` | An admin (or a token with `write:findings`) ingests an external scanner's findings (`POST /api/v1/security/findings/external`). This is the write that classes a `MAL-*` advisory `malicious`/Critical. Outcome `success`. | `artifact_id`, `repository_id`, `scan_id`, `scanner`, `scanner_version`, `findings_ingested`, `severity_counts` (`critical` .. `info`), `class_counts` (`vulnerability`, `malicious`, `policy`), `malicious_ids` (the `MAL-*` ids, at most 50) and `malicious_ids_truncated`, and the repository `score` and `grade` after the ingest. |

`LOGIN_RATE_LIMITED` rows carry the verified client IP in `source_ip` /
`ip_address` under the same rules as `LOGIN_FAILED` (`XFF_TRUSTED_FOR_AUTHZ`).
A refused flood would otherwise become a flood of audit inserts, so the first
refusal per source IP in each per-account limiter window writes a row and the
rest of that window does not; the global backstop is not per-client, so it
writes one row per backstop window whatever address the refusals come from.
Each written row also logs a `WARN` line on the `security` target; refusals
that are not audited log at `DEBUG`. `/api/v1/auth/login` and `/v2/token`
keep separate once-per-window memories.

Each ingest also logs an `INFO` line on the `security` target
(`external findings ingested`) with the artifact, scan, scanner, acting user,
finding and malicious counts and the new score.

### Proxy scan refusals

| Action | Resource | Fires when | `details` |
| --- | --- | --- | --- |
| `PROXY_SCAN_BLOCKED` | `repository` (the repository the pull was made through) | The scan-on-proxy gate refuses a proxied download with `403 scan_blocked` (#4777). Outcome `denied`. | `repository`, `repository_id`, `path` (the file the 403 names), `checksum_sha256`, `verdict`, `max_severity`, `findings_count`, `scanned_at` (of the verdict), `principal` (the username, `null` for an anonymous pull), `anonymous`, `attempts`, `aggregated`, `window_seconds`. |

The row's `user_id` is the authenticated principal (`null` for an anonymous
pull) and `ip_address` the verified client IP, as for `LOGIN_FAILED`. A client
retrying a blocked pull would otherwise write one row per retry, so refusals
are aggregated per (digest, principal, repository) over a 60 second window on
each replica: the first refusal writes a row at once with `attempts: 1`, and
the repeats inside the window write one summary row when it closes, with
`attempts` set to their count and `aggregated: true`. A retry loop therefore
writes at most two rows a minute per replica. An anonymous principal is keyed
by its client IP. The row does not carry the API token id; the principal is
the token's user.

To answer "who asked for this blocked package", filter the audit log on
`PROXY_SCAN_BLOCKED` and the repository, and match `checksum_sha256` against
`GET /api/v1/security/proxy-blocked`.

## Compatibility policy

Within `schema_version: 1`:

- **Additive fields are non-breaking.** New envelope or `details` fields may be
  added. Consumers must ignore unknown fields.
- **Enum values may be added.** New `action` and `actor.type` values may appear.
  Consumers must tolerate unknown values (do not hard-fail on them).
- **Breaking changes bump `schema_version`.** A rename or removal of an existing
  field, or a type change, ships under a new integer version.

A committed `--lib` test validates live emitted records against the committed
schema, so a change to the Rust types that would break this contract fails CI.

## Redaction guarantees

Representative typed payloads contain no credential fields; `TokenDetails`, in
particular, cannot carry the token secret. The compatibility path for legacy
free-form details recursively replaces known secret-bearing keys (passwords,
authorization/cookie fields, access/refresh tokens, API/private keys, SAML and
TOTP material) with `[REDACTED]` before storage or export. Payloads over 64 KiB
are replaced with a bounded truncation marker **in the exported record only** —
the database row always keeps the full (redacted) payload, so the bound can
never lose data from the authoritative trail; it exists to keep the export
queue's worst-case memory finite. Free-text business fields can still
contain operator-supplied sensitive text, so callers must not place secrets in
names, reasons, or other descriptive values. The `details.actor` key is
reserved for system emitters and is set only via a static label.

## Retention

The audit stream and the database audit trail are independent: the SIEM owns
long-term retention of the streamed copy, and the stream is not a replacement
for the DB audit trail but a delivery mechanism alongside it.

`audit_log` retention is applied by a scheduled job (#4718):

- **What runs.** Once an hour, one replica (a scheduler lease keeps replicas
  from running it at the same time) deletes the `audit_log` rows whose
  `created_at` is older than the `audit_retention_days` system setting, oldest
  first, in batches of 5,000 rows. Each run logs one `Audit retention pass`
  line with the period, rows deleted and batch count; the period in force is
  logged once at startup.
- **How to set it.** `POST /api/v1/admin/settings` with
  `audit_retention_days` set to a positive number of days. The job reads the
  setting on every run, so a change applies within the hour without a restart.
- **Off until saved.** A period must be saved explicitly before the job
  deletes anything. Until then `GET /api/v1/admin/settings` reports
  `audit_retention_days: 0` (it used to show `90`, a default that was never
  applied), and nothing is deleted.
- **How to turn it off.** Set `audit_retention_days` to `0`.

`POST /api/v1/admin/cleanup` with `"cleanup_audit_logs": true` still deletes
the same rows on demand, and deletes none while the period is `0` or was
never saved.

## Delivery semantics

- **At-most-once per process lifetime.** Records enter a bounded 4,096-record
  in-process queue whose writer drains on a best-effort basis during graceful
  shutdown, with no disk replay; durability and retry are the collector's job.
  Queue saturation or writer failure increments
  `ak_audit_stream_failures_total{reason=...}` rather than blocking the
  originating request.
- **Emitted even on DB-write failure.** The record is emitted *before* the row
  INSERT and regardless of its outcome, so a database outage (or the
  fire-and-forget swallow path) does not also lose the SIEM copy. In that case
  the `event_id` will have no matching `audit_log` row until the DB recovers.
- **Ordering.** The writer preserves queue order, but concurrent request tasks
  may enqueue in either order. There is no cross-instance ordering guarantee;
  join on `timestamp`, `event_id`, and `correlation_id`.

### Collector examples

OpenTelemetry Collector (filelog receiver over container stdout), keeping only
audit lines:

```yaml
receivers:
  filelog:
    include: [/var/log/pods/*/artifact-keeper/*.log]
    operators:
      - type: json_parser
      - type: filter
        expr: 'body.category != "audit"'
```

Fluent Bit (parse JSON, keep `category == "audit"`):

```ini
[FILTER]
    Name    grep
    Match   kube.*artifact-keeper*
    Regex   log \"category\":\"audit\"
```
