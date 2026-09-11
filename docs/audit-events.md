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
| `LOG_FORMAT` | `pretty`, `json` | `pretty` | Format of the *diagnostics* log lines. |

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
| `source_ip` | string \| null | Source IP when the emitter already captures one; otherwise `null`. |
| `resource` | object | `{ type, id, name }` — the targeted resource. |
| `correlation_id` | string | Joins to request logs and traces (#2414). |
| `details` | object \| null | Typed for representative events (below); permissive otherwise. |

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

`source_ip` is deliberately nullable. Most authentication, permission, and
token emitters do not currently capture the request address, so those events
generally emit `null`; existing emitters such as artifact operations populate
it when that context is already available. Client attribution across the wider
request surface needs a considered trust model and is separate from this export
contract.

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
| `REPOSITORY_CREATED` / `_UPDATED` / `_DELETED` | `RepositoryDetails` (`actor_id`, `key`, `is_public`, structured format/policy fields) |
| `ROLE_ASSIGNED` / `_REVOKED`, `REPOSITORY_PERMISSION_CHANGED` | `PermissionDetails` (`actor_id`, `role_id`, `grantee_id`, `repository_id?`) |
| `API_TOKEN_CREATED` / `_REVOKED` | `TokenDetails` (`token_id`, `token_name?`, `surface`, `expires_at?`, `policy_applied?`) |
| `LOGIN_FAILED`, `PERMISSION_DENIED` | `AuthDetails` (`username?`, `path?`, `method?`, `reason?`, federated labels?) |
| `ARTIFACT_UPLOADED` / `_DOWNLOADED` / `_DELETED` | `ArtifactDetails` (`repository_id`, `path`, `name`, `version?`, `size_bytes?`, `digest?`, `uploaded_by?`) |
| `SETTING_CHANGED` | `SettingDetails` (`key`, `old_value?`, `new_value?`) |

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

The audit stream and the database audit trail are independent. `audit_log`
retention is governed by the existing cleanup job; the SIEM owns long-term
retention of the streamed copy. The stream is not a replacement for the DB audit
trail — it is a delivery mechanism alongside it.

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
