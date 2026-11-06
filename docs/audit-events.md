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
| `REPOSITORY_CREATED` / `_UPDATED` / `_DELETED` | `RepositoryDetails` (`actor_id`, `key`, `is_public`, structured format/policy fields; `upstream_change` / `upstream_auth_change` on credential changes, secrets never carried; on `_UPDATED`, `project_change` `{previous_project_id, project_id}` when the project assignment changed, `project_id: null` for a cleared assignment, #4026; an age-gate policy change adds `age_gate_change`: the replaced policy, `actor_tier`, and `relaxed`; a `PUT .../upstream-mode` adds `upstream_mode_change` `{previous_upstream_mode, upstream_mode}`, #5282) |
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
| `QUARANTINE_RELEASED` | `artifact` (or `repository` for a held proxy-cache entry) | `artifact_id`, `previous_status`; `released_by: finding_acknowledgement` when an acknowledgement cleared a scan-policy hold; for a proxy-cache entry `repository`, `path`, `proxy_cache: true` |
| `QUARANTINE_REJECTED` | `artifact` | `artifact_id`, `previous_status`, `reason` |
| `FINDING_ACKNOWLEDGED` | `scan_result` (the decision's id); the actor is the user, on REST and gRPC alike | `acknowledgement_id`, `lineage_id`, `repository_id` (null: every repository), `checksum_sha256`, `finding_class`, `advisory`, `component`, `component_version`, `max_severity`, `reason`, `expires_at`, `created_via`, `revoked_reason` |
| `FINDING_ACKNOWLEDGEMENT_REVOKED` | `scan_result` (the decision's id); one row per decision the revoke reached, or for the decision a new one superseded (`revoked_reason: superseded`) | as `FINDING_ACKNOWLEDGED`, plus `left_effective` |
| `FINDING_ACKNOWLEDGEMENT_CARRIED` | `scan_result` (the copy's id); the actor is the promoter | `acknowledgement` (as `FINDING_ACKNOWLEDGED`), `promotion` (`source_repository_id`, `source_artifact_id`, `artifact_id`, `target_repository_id`) |
| `FINDING_ACKNOWLEDGEMENT_NOT_CARRIED` | `scan_result` (the source decision's id); the actor is the promoter, who could not acknowledge in the target | as `FINDING_ACKNOWLEDGEMENT_CARRIED` |
| `FINDING_ACKNOWLEDGEMENT_EXPIRED` | `scan_result` (the decision's id); system actor. Written at least once: a crash can repeat a row | as `FINDING_ACKNOWLEDGED` |
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
| `CONFIG_IMPORTED` | `setting` (`resource_name: config_document`); one summary row per `POST /api/v1/admin/config/import?mode=apply` (#5292), on top of the per-repository rows each write records | `schema_version`, `completed`, `error` (null on success), `planned_create`, `planned_update` (keys), `unchanged` and `not_in_document` (counts), `created`, `updated`, `members_updated` (keys actually written), `prune` |

A webhook `url` is recorded as scheme, host, port and path: userinfo, query
string and fragment are dropped because receivers often carry a token there.
`PROMOTION_REFUSED` and `PROMOTION_APPROVAL_DENIED` export with outcome
`denied`; a `CONFIG_IMPORTED` row for an apply that failed part way exports
with outcome `failure`; the others export as `success`. `CONFIG_IMPORTED`
never carries a value from the import's `secrets` map.

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

### MCP registry

| Action | Resource | Fires when | `details` |
| --- | --- | --- | --- |
| `MCP_PACKAGE_PINNED` | `artifact` (the server.json version) | A publish to an MCP registry resolved one `packages[]` entry to an artifact or image digest in a backing repository (#5253). One row per entry. Outcome `success`. | `repository`, `server`, `version`, `index`, `registry_type`, `submitted` (`identifier`, `version`), `resolved_repository`, `digest` (OCI) or `sha256`, `warnings` (e.g. `oci_tag_digest_mismatch`). |
| `MCP_PIN_DRIFT_DETECTED` | `artifact` (the server.json version that pinned the tag) | An OCI tag that a published server version pinned moved to another digest, by a push or an upstream refresh (#5253). The version keeps serving the pinned digest; nothing is unpublished. Outcome `success`. | `backing_repository_id`, `name`, `tag`, `previous_digest`, `pinned_digest`, `observed_digest`, `mcp_server`, `mcp_version`. |
| `MCP_SERVER_DOWNLOAD_REFUSED` | `artifact` (the server.json version) | The `/mcp/{repo}/v0.1` surface refused to hand a held server version to a client (#5253). Sampled: at most one row per (version, caller) per minute per replica. Outcome `denied`. | `repository`, `repository_id`, `server`, `version`, `hold_class` (`quarantine`, `scan_policy`, `backing`, `age_gate`, `unresolvable`, `resolving`, `curation`, `content_drift`, `unavailable`), `reason_disclosed` (whether the caller got the reason body), `anonymous`. |
| `MCP_SERVER_PUBLISHED` | `artifact` or `repository` | A server version was published to a hosted MCP registry, or ingested from upstream into a Remote one. (#5253). Outcome `success`. | `repository`, `server`, `version`, `repository_id`, `packages`, `remotes`, `pinned` (count), `resolving` (indexes of packages still being filled; the version answers `202`). |
| `MCP_SERVER_STATUS_CHANGED` | `artifact` or `repository` | A server version's registry status (active, deprecated, deleted) changed. (#5253). Outcome `success`. | `repository`, `server`, `version`, `from`, `to`, `status_message`. One row per version a status `PATCH` changed. |
| `MCP_SERVER_APPROVED` | `repository` (the Remote MCP registry) | A Remote MCP registry approved a server name (or a name@version pin) for serving. (#5253). Outcome `success`. | `repository`, `repository_id`, `server`, `version` (a `name@version` pin; `null` for a name), `review_id` (the curation row), `reason` (`auto_approve_namespace` for an approval made by the sync), `pattern` (a bulk approval). Actor: the approving user; none for an automatic approval. |
| `MCP_SERVER_REJECTED` | `repository` (the Remote MCP registry) | A Remote MCP registry blocked a server name (or a name@version pin). (#5253). Outcome `denied`. | `repository`, `repository_id`, `server`, `version` (`null` for a name), `review_id`, `reason`. Actor: the blocking user. |
| `MCP_SERVER_REOPENED` | `repository` (the Remote MCP registry) | An MCP approval was revoked back to review (an admin reopened it, or content drift re-queued it). (#5253). Outcome `success`. | `repository`, `repository_id`, `server`, `version` (`null` for a name), `review_id`, `reason` (`content_drift` when the sync re-queued a served version; otherwise the administrator's). |
| `MCP_SERVER_CONTENT_DRIFT` | `repository` (the Remote MCP registry) | An upstream entry changed content under an already ingested name@version. (#5253). Outcome `success`. | `repository`, `repository_id`, `server`, `version`, `review_id` (the version's curation row, now `review`), `stored_sha256`, `upstream_sha256`, `was_approved` (whether the version was being served). No actor (the sync). |
| `MCP_GATE_UNAVAILABLE` | `repository` (the MCP registry read) | An MCP serve gate could not be evaluated and the surface answered 503 (fail closed). (#5253). Outcome `failure`. | `repository_id`, `surface` (`detail` or `listing`), and for a detail read `repository`, `server`, `version`. Sampled: at most one row per version (or listing repository) per minute per replica. |
| `MCP_CAPABILITIES_INGESTED` | `artifact` | A capability snapshot (tools/resources/prompts) was recorded for a server version: declared at publish, reported by CI or a gateway, or observed by the introspection worker. Actor: the reporter (none for declarations and worker results). (#5253). Outcome `success`. | `repository`, `server`, `version`, `snapshot_id`, `source`, `provenance`, `origin`, `outcome`, `auth_state`, `content_hash`, `tools`, `resources`, `prompts` (counts). |
| `MCP_TOOLS_DRIFT` | `artifact` | A new successful capability snapshot differs from the previous successful one of the same source for the same server version; a `tool_drift` finding was recorded. (#5253). Outcome `success`. | The `MCP_CAPABILITIES_INGESTED` fields plus `previous_snapshot_id`, `previous_hash`, `scan_id`, `severity`, `summary`, `destructive_added`. |
| `MCP_NAMESPACE_GRANTED` | `repository` (the rule's target id) | A permission rule write added `conditions.mcp_namespaces` patterns (create, or an update that added patterns). One row per write, listing the added patterns. The condition is accepted only on an MCP repository target. (#5253). Outcome `success`. | `rule_id`, `principal_type`, `principal_id`, `target_type`, `target_id`, `actions`, `patterns` (added). |
| `MCP_NAMESPACE_REVOKED` | `repository` (the rule's target id) | A permission rule write removed `conditions.mcp_namespaces` patterns (delete, or an update that removed patterns). (#5253). Outcome `success`. | `rule_id`, `principal_type`, `principal_id`, `target_type`, `target_id`, `actions`, `patterns` (removed). |
| `MCP_NAMESPACE_PROOF_VERIFIED` | `setting` (the proof id; `resource_name` the namespace) | An administrator-initiated DNS/HTTP namespace proof check found the challenge value. (#5253). Outcome `success`. | `proof_id`, `namespace`, `domain`, `method` (`dns`, `http`), `error` (null). |
| `MCP_NAMESPACE_PROOF_FAILED` | `setting` (the proof id; `resource_name` the namespace) | An administrator-initiated DNS/HTTP namespace proof check did not find the challenge value, or the fetch was refused or failed. (#5253). Outcome `failure`. | `proof_id`, `namespace`, `domain`, `method`, `error` (why). |
| `MCP_SERVER_EDITED` | `artifact` or `repository` | An administrator replaced a server version's document (PUT admin edit). (#5253). Outcome `success`. | `repository`, `server`, `version`, `previous_sha256`, `sha256`, `packages_changed`, `resolving`. |
| `MCP_SERVER_DELETED` | `artifact` or `repository` | A server version was soft-deleted (DELETE), leaving a tombstone. (#5253). Outcome `success`. | `repository`, `server`, `version`, `from` (previous status), `status_message`. |
| `MCP_SERVER_PURGED` | `artifact` (the server.json) | An instance administrator purged a soft-deleted server version (`POST .../versions/{version}/purge`): its server.json and bundles went to the trash, releasing what it pinned; the tombstone stays. (#5368). Outcome `success`. | `repository`, `repository_id`, `server`, `version`, `released_digests` (each `repository_id`, `image`, `digest`, `still_pinned` when another live version pins it too), `pins`, `trashed` (artifact paths). |
| `MCP_MIRROR_SYNCED` | `repository` (the Remote MCP registry) | A Remote MCP registry finished an upstream sync run. (#5253). Outcome `success`. | `repository`, `repository_id`, `mode` (`allowlist` or `mirror`), `upstream` (the Remote's upstream URL with any userinfo credentials stripped), `updated_since` (the watermark the run started from), `summary` (`pages`, `entries`, `namesNew`, `autoApproved`, `flagged`, `ingested`, `unchanged`, `statusChanged`, `drifted`, `invalid`, `unresolved`, `reResolved`, `backfilledNames`, `complete`, `errors`). No actor. |
| `MCP_BUNDLE_SIGNATURE_REJECTED` | `artifact` or `repository` | An MCPB bundle upload was refused for its signature: it did not verify, or `mcp_require_bundle_signature` is on and the bundle is unsigned or signed by a signer not on `MCP_TRUSTED_BUNDLE_SIGNERS`. (#5253). Outcome `denied`. | `repository`, `server`, `version`, `file`, `file_sha256`, `signature` (`state`: `valid`, `self_signed`, `unsigned` or `invalid`; `reason`, `signer`, `fingerprint`, ...), `require_signature`, `error` (`mcp_bundle_signature_invalid`, `mcp_bundle_unsigned` or `mcp_bundle_signer_untrusted`). Resource type `repository` (no artifact is stored). |

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

### Proxy cache seeds

| Action | Resource | Fires when | `details` |
| --- | --- | --- | --- |
| `CACHE_SEEDED` | `repository` (the Remote that was seeded) | A proxy-cache seed job (`POST /api/v1/repositories/{key}/cache/seed`, #5284) completed. One row per job. Outcome `success`. | `repository`, `repository_id`, `job_id`, `kind`, `cached`, `already_cached`, `refused`, `failed`, `cached_bytes`. |

The row's `user_id` is the user who started the seed. The per-path inventory
stays on the job (`GET .../cache/seed/{job_id}`), not in the audit row.

### Upstream contact

| Action | Resource | Fires when | `details` |
| --- | --- | --- | --- |
| `UPSTREAM_FETCHED` | `repository` (the Remote the request was made for) | The proxy sends a request to an upstream (#5286): a cache-miss fetch, a revalidation, an OCI bearer-token exchange or its retry. One row per request actually sent; a cache hit sends nothing and writes nothing, neither does a miss a cache-only Remote (#5282) or the upstream filter refuses, and a single-flight fill writes one row however many clients wait on it. Off by default; see below. Outcome `failure` for `not_found`, `error` and `timeout`, else `success`. | `repository`, `repository_id`, `caller` (`proxy`, `revalidate`, `oci_token`), `method`, `host`, `port`, `path` (the URL path only: never userinfo, query string or fragment), `redirected_to_host` (the host the request ended on when a redirect left the requested one, else `null`), `conditional` (sent with `If-None-Match` / `If-Modified-Since`), `status` (`null` when no response arrived), `result` (`ok`, `not_modified`, `not_found`, `auth_challenge`, `error`, `timeout`), `error_type` (the transport error class: `timeout`, `connect`, `redirect`, `body`, `request`, `_OTHER`), `bytes` (the body length the upstream announced in `Content-Length`; `0` for a `HEAD` or `304`, `null` for a chunked body), `duration_ms` (to response headers), `principal` (the username of the client request that caused it, `null` when anonymous or outside a request). |

`AUDIT_UPSTREAM_FETCHES` selects what is written: `off` (the default, no rows
and no bookkeeping), `errors` (only `not_found`, `error` and `timeout`) or
`all` (every request; what an air-gapped deployment sets, so the seed
window's upstream traffic can be listed and the absence of any after the cut
shown from the audit log). `auth_challenge` is the `401` an OCI registry
answers an anonymous first request with; the token exchange and retry that
follow are rows of their own.

The row is written off the request path by a bounded background task, so it
adds no latency and a failed insert never fails the request (it is logged at
`WARN`). When the writer pool is saturated the insert runs inline instead of
being dropped. The row's `user_id`, `ip_address` and correlation id are those
of the client request that caused the upstream request, when there was one.

Not yet recorded: upstream requests made outside the proxy service (the
`test-upstream` probe, curation sync, the popularity source, the npm change
feed and the npm `/-/` and audit passthroughs, the Go sumdb pass-through of
a Hosted repository, the AWS token exchange). A Go Remote's checksum database
fetches go through the proxy service and are recorded (#5344).

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
