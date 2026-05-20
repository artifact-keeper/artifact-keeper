# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Pre-upgrade check

- **Stuck-scan janitor will reap accumulated `running` rows on first tick** (#1015, #1062) -- this release introduces a background janitor that transitions `scan_results` rows wedged in `status='running'` past the configured `STUCK_SCAN_THRESHOLD_SECS` (default 1800s / 30 min) to `status='failed'`. On long-running installs predating this release, previously-stuck rows from crashed scan workers (OOM, pod evicted, deploy mid-scan) will flip to `failed` in batches of up to 1000 rows per janitor tick (the per-tick cap bounds memory and audit-log write volume). With the default `STUCK_SCAN_CHECK_INTERVAL_SECS=600`, a backlog of N stuck rows therefore takes roughly `ceil(N / 1000) * (STUCK_SCAN_CHECK_INTERVAL_SECS / 60)` minutes per replica to fully drain. Multiple janitor-running replicas drain proportionally faster (the cap is per-replica, per-tick). Operators with a large backlog who want to accelerate the drain can lower `STUCK_SCAN_CHECK_INTERVAL_SECS` for one or two ticks after deploy and revert. Alerting on `status='failed'` deltas should expect this drain (one or many ticks depending on backlog size) at upgrade and tune accordingly.

  Count the rows that will be reaped before upgrading:

  ```sql
  SELECT count(*) FROM scan_results
  WHERE status = 'running'
    AND started_at < now() - interval '30 min';
  ```

  The same count also approximates migration `105_partial_index_running_scans.sql`'s ACCESS EXCLUSIVE lock duration on `scan_results`. The partial index is built non-concurrently (forced by sqlx's per-migration transaction wrapper), and the build scan touches every `running` row that exists at migration time. New `scan_results` inserts block on that lock for the build's duration. On installs with a small backlog the build is sub-second; on installs with hundreds of thousands of historical stuck rows the build can take seconds-to-tens-of-seconds. Plan the upgrade window using the count above. On fresh installs (no historical `running`-state rows) the build is sub-millisecond and the warning above does not apply.

  Rollback: the migration is reversible without operator state changes by running `DROP INDEX IF EXISTS idx_scan_results_running_started;` against the registry database. The janitor sweep continues to function without the index (it falls back to scanning `scan_results` filtered by `status='running'`); the index is purely a query-plan accelerator. If the migration window is too short to complete the index build, abort the deploy, drop the partial index if it was created, then add it out-of-band against a quiescent table with `CREATE INDEX CONCURRENTLY idx_scan_results_running_started ON scan_results (started_at) INCLUDE (id) WHERE status = 'running';` (run as the DB owner outside any transaction).

  Each reap also writes one `SCAN_REAPED` entry to `audit_log` (#1063) carrying `scan_id`, `artifact_id`, `repository_id`, `started_at`, `reaped_at`, `threshold_secs`, `reason='stuck_running_janitor'`, and `actor='system:stuck_scan_janitor'` so the burst is auditable and SIEM rules can filter system-initiated reaps via `details->>'actor'`. Note that `audit_log` entries are subject to the `audit_retention_days` retention sweep (default 90 days), and the `scan_results` row itself is `ON DELETE CASCADE` from `artifacts`/`repositories`; for long-term compliance retention, export `SCAN_REAPED` entries to durable SIEM storage rather than relying on either table as the long-term source of truth. Artifacts whose vulnerability scan was reaped this way are now visible to operators investigating an incident; rescan with `POST /api/v1/security/artifacts/{id}/rescan` if the scan never reported findings.

  Misconfiguration guard: `STUCK_SCAN_THRESHOLD_SECS` below 60 s is clamped to 60 s with a startup warning (a 0-second threshold would reap every in-flight scan on every tick), and `STUCK_SCAN_CHECK_INTERVAL_SECS` below 30 s is clamped to 30 s (a 0-second interval would panic the spawned scheduler task). The defaults of 1800 s and 600 s remain unchanged; the clamps only apply to operator-supplied overrides.

- **Migration 106 takes ACCESS EXCLUSIVE on `artifacts`** (#1217 audit follow-up). Migration `106_artifacts_lower_name_index.sql` builds the functional partial index `idx_artifacts_repo_lower_name ON artifacts (repository_id, LOWER(name)) WHERE is_deleted = false` non-concurrently (forced by sqlx's per-migration transaction wrapper). On installs with millions of artifact rows, plan the upgrade window using a row count: `SELECT count(*) FROM artifacts WHERE is_deleted = false;`. Inserts to `artifacts` (new uploads and proxy-cache writes) block on the index build for its duration; on small installs the build is sub-second, on installs with tens of millions of rows it can take seconds-to-tens-of-seconds. Operators who cannot accept the lock window can skip the migration and build the index out of band against a quiescent table with `CREATE INDEX CONCURRENTLY idx_artifacts_repo_lower_name ON artifacts (repository_id, LOWER(name)) WHERE is_deleted = false;` (run as the DB owner outside any transaction); the migration is idempotent (`CREATE INDEX IF NOT EXISTS`) so re-running it afterwards is a no-op. Functionality is correct without the index; it is purely a query-plan accelerator for the cross-format shadowing guard and the existing `find_artifact_by_name_lowercase` helper.

### Added

- **Stuck-scan janitor** (#1015) -- new `ScanResultService::cleanup_stuck_scans` background job registered in `scheduler_service::spawn_all` (90s startup delay, 600s default cadence) transitions `scan_results` rows wedged in `status='running'` past `STUCK_SCAN_THRESHOLD_SECS` (default 1800) to `status='failed'`. Configurable via `STUCK_SCAN_THRESHOLD_SECS` and `STUCK_SCAN_CHECK_INTERVAL_SECS` env vars. Emits the existing `ak_cleanup_items_removed_total{type="stuck_scans"}` counter. Forward-ported from `release/1.1.x` PR #1064.
- **Stuck-scan janitor partial index** (#1061) -- migration `105_partial_index_running_scans.sql` adds `idx_scan_results_running_started ON scan_results (started_at) WHERE status = 'running'`. The janitor sweep added in #1015 filters on `status='running'` without a `repository_id` predicate, which would degrade on installs with very large `scan_results` tables. The partial index only contains in-flight rows so the planner goes straight to the candidates. `CREATE INDEX CONCURRENTLY` is intentionally not used because `sqlx::migrate` runs each migration in a transaction; in-flight rows are bounded by the janitor itself so the synchronous build is short.
- **Audit-event emission on stuck-scan reap** (#1063) -- `ScanResultService::cleanup_stuck_scans` now writes one `SCAN_REAPED` entry to `audit_log` per reaped row, capturing `scan_id`, `artifact_id`, `repository_id`, `started_at`, `reaped_at`, `threshold_secs`, and `reason='stuck_running_janitor'` in the `details` JSON column. Previously the janitor emitted only the `ak_cleanup_items_removed_total{type="stuck_scans"}` counter, so operators investigating an incident could not tell which vulnerability scans never completed. Audit writes are best-effort: a failure to record the event is logged at warn level but does not roll back the reap, since leaving the row wedged in `running` is the worse outcome. Adds `AuditAction::ScanReaped` and `ResourceType::ScanResult`.
- **Auth: download-ticket consumer middleware** (#930) -- the `?ticket=<v>` query parameter minted by `POST /api/v1/auth/ticket` is now accepted as a fallback authenticator on read routes (`auth_middleware`, `optional_auth_middleware`, and `repo_visibility_middleware`). Tickets are single-use, expire after 30 seconds, are restricted to GET/HEAD methods, and only authenticate the request whose URL path matches the ticket's bound `resource_path`. Useful for browser anchor-tag downloads and `EventSource` SSE streams where `Authorization` headers cannot be set.

### Fixed

- **Replica-safe credential check no longer rejects the second admin request from a fresh non-admin user** (#1248 follow-up). `is_token_invalidated_replica_safe` consulted the in-memory `is_token_invalidated` fast-path before the DB-watermark check. The same `invalidation_map` is also used by `fetch_credential_change_watermark` to cache DB lookups for `CREDENTIAL_DB_CACHE_TTL_SECS` (5s), so the first admin request from a fresh non-admin populated the cache with the user's `password_changed_at`, and every subsequent request within the cache window hit the sync fast-path's `<=` comparator against that same wall-clock second and was rejected with 401. Release-gate `tests/rbac/test-admin-protection.sh` against `v1.2.0-rc.1` saw exactly this: the first endpoint (`/api/v1/admin/settings`) returned 403 as expected, every subsequent endpoint in the loop returned 401. The fix removes the sync fast-path call from `is_token_invalidated_replica_safe`; the cache hit inside `fetch_credential_change_watermark` already provides the in-replica acceleration without the `<=` conflation, and the strict `<` comparator from #1248 is now the sole gate. The sync `is_token_invalidated` helper is retained for `validate_access_token` (the non-replica-safe sync entry point that does not touch the DB cache). Adds `two_sequential_admin_requests_with_fresh_jwt_both_return_403` integration test that fails on rc.1 and passes on this branch.
- **Proxy cache HTTP 500 on filesystem backend, every cached read after the first** (closes #1278). `ProxyService::cache_artifact` previously wrote proxy-cached bodies through the global `self.storage` AND inserted a row in `artifacts` with `storage_key = "proxy-cache/<repo_key>/<path>/__content__"`. Every format handler's subsequent read resolved storage via `state.storage_for_repo(repo.storage_location()).get(&artifact.storage_key)` -- which on filesystem deployments creates a per-repo `FilesystemStorage` rooted at `repo.storage_path` and resolves to a doubled-prefix path (`<repo.storage_path>/proxy-cache/<repo_key>/...`) that does not exist on disk, returning HTTP 500 with `Storage error: Storage key not found`. S3 / object-store backends were unaffected because `StorageRegistry::backend_for` returns the shared instance regardless of `location.path`. The fix is surgical: `cache_artifact` no longer inserts proxy-cached items into the `artifacts` table. The cached body and metadata sidecar still live on disk under `self.storage`, and the format-handler hot path already checks the proxy cache via `proxy_check_cache` -> `get_cached_artifact_by_path` -> `self.storage.get` BEFORE falling through to upstream, so cache hits are served through that path with no `artifacts` row needed (read backend matches write backend). Tradeoff: proxy-cached items no longer surface in the repository artifact-listing endpoint or `storage_used_bytes` accounting -- that UX gap is tracked separately and is a graceful degradation, not a correctness regression. Existing rows from prior versions stay in `artifacts` and continue to surface in listings until invalidated. Adds a source-level meta-test (`test_cache_artifact_does_not_insert_into_artifacts_table`) that pins the no-INSERT invariant so a future refactor can't silently restore the bug.
- **Virtual repository creation now rejects requests with no members at create time, not at first fetch** (closes #1279). `POST /api/v1/repositories` with `repo_type=virtual` previously accepted both `member_repos` omitted entirely (e.g. when operators typed `members: [...]` -- the more natural field name -- which serde silently dropped because the struct field is `member_repos` and does not enable `deny_unknown_fields`) and `member_repos: []` (empty array). Both shapes returned HTTP 200 with a successfully-created repo whose `virtual_repo_members` row count was zero, and every subsequent fetch returned `404 Resource not found: Virtual repository has no members` -- so operators only discovered the misconfiguration minutes later when they actually tried to use the repo. The handler now validates up front via `validate_virtual_repo_member_count` and returns a `400 Bad Request` that names the expected `member_repos: [{repo_key, priority}, ...]` shape, echoes the offending repo key, and points at `PUT /api/v1/repositories/{key}/members` for post-creation updates. Five unit tests pin the validator (accept non-virtual types, reject None / empty for virtual, accept non-empty) plus a regression test pinning the `members:`-instead-of-`member_repos:` silent-drop behaviour so any future `deny_unknown_fields` hardening can simplify the validator.
- **First-time admin login surfaces the generated password in startup logs and points at the web UI forced-change flow** (#1009). The bootstrap path previously wrote the random admin password only to `${STORAGE_PATH}/admin.password` and printed the file path. Operators had to `docker exec` into the container to read it, then run two `curl` commands to change it. The startup banner now echoes the plaintext password (and the file path) once at INFO level when the password was generated by Artifact Keeper itself, and the banner now explicitly walks operators through the web UI flow: log in with the printed password, the UI redirects to the forced-change-password screen, and the API unlocks automatically. The new `ARTIFACT_KEEPER_HIDE_ADMIN_PASSWORD=true` env var suppresses the plaintext echo for installs where the backend log stream is shared with other tenants; the file is still written so the credential is recoverable. The plaintext is never echoed when the operator supplied `ADMIN_PASSWORD` from the environment (they already have it). The default password is single-use anyway: `must_change_password=true` is still set, the `setup` middleware blocks every mutating API call until the change runs, and tokens issued during the locked window are invalidated by the existing `change_password` flow.
- **Swift manifest endpoint serves Package.swift from the uploaded source archive** (#1100). `GET /swift/{repo}/{scope}/{name}/{version}/Package.swift` previously returned `404 {"detail":"Manifest not found for this release"}` for any release published via raw `PUT ... application/zip`, because the publish handler populated `artifact_metadata.metadata["manifest"]` only from the optional `X-Swift-Package-Manifest` header. SwiftPM manifests are multi-line and cannot reliably be sent as an HTTP header value, so this gate effectively required clients to know about a custom header to ship a working release, and broke `swift package resolve` against the registry. The publish path now extracts `Package.swift` from the uploaded zip when the header is absent (top-level `Package.swift` wins, `<single-prefix>/Package.swift` for GitHub-archive-style layouts is the fallback, and the shallowest path wins when multiple candidates exist). The fetch path also gained a fallback: when the cached `manifest` field is `NULL` (legacy uploads from before this fix), the handler reads the stored zip on demand. The explicit header still takes precedence so clients with their own preferred manifest text can override the archive contents.
- **`upload_chunks.status` check constraint now accepts `'uploading'` (closes #1168, part 2)**. Migration 072 created the table with `CHECK (status IN ('pending','completed','failed'))`, but the chunked-upload service in `services/upload_service.rs` atomically claims chunks via `UPDATE ... SET status = 'uploading' WHERE status = 'pending'` before writing data, then sets `'completed'` or `'failed'` after the write. The first PATCH against any chunk therefore aborted with `new row for relation "upload_chunks" violates check constraint`, surfacing in the browser as "upload big file failed because of database table error". Migration 089 drops and re-adds the constraint with the full status set (`'pending','uploading','completed','failed'`); the constraint is looked up via `pg_constraint` rather than by hard-coded name so prior fix migrations under non-default names are still handled.
- **Chunked upload finalize writes to the repo-scoped, content-addressable storage key (closes #1168, parts 1 and 3)**. Two bugs interacted: the create-session handler queried `SELECT id FROM repositories WHERE key = $1 AND is_deleted = false`, but `repositories` has no `is_deleted` column (the soft-delete pattern lives on `artifacts`, not `repositories`), so the lookup failed with a SQL error before any chunks could be uploaded. The `AND is_deleted = false` clause is removed. Second, the `complete` handler called `state.storage.put_file("uploads/<repo_id>/<path>", ...)` against the global default backend (no repo path prefix), while `download_artifact` resolves via `state.storage_for_repo(&repo.storage_location())` which prepends the repo's `storage_path`. The two paths never agreed, so a 201-CREATED chunked upload could not be downloaded. Finalize now resolves the repo-scoped backend and writes using `ArtifactService::storage_key_from_checksum` (`<sha[:2]>/<sha[2:4]>/<sha>`), matching how non-chunked uploads land on disk.
- **Migration runner recovers from the legacy duplicate-073 state without operator intervention (closes #1129)**. Between PRs #975 and #1138 the migrations directory contained two files numbered 073 (`073_account_lockout.sql` and `073_download_tickets_cascade.sql`). `sqlx migrate run` only inserts one row per version, and which checksum landed in `_sqlx_migrations` depended on filesystem-walk order, so installs that bootstrapped in that window now refuse to start with `Migration(VersionMismatch(73))` even though the `account_lockout` columns are physically present on `users`. The backend now runs a pre-migration repair step at startup: if `_sqlx_migrations` already has a version-73 row whose checksum doesn't match the current `073_account_lockout.sql`, and the `users.failed_login_attempts` column is present (proof account_lockout was applied at least once), the checksum is rewritten to the current value and the migrator continues. The check is conservative; unrelated checksum drift still aborts startup so accidental tampering surfaces loudly.

- **`POST /v2/token` now accepts OAuth2 password-grant credentials in the form body** (#894). Docker's distribution token endpoint flow uses `Content-Type: application/x-www-form-urlencoded` with `grant_type=password&username=...&password=...&service=...&scope=...` in the request body, but the handler previously read credentials only from the HTTP Basic Auth header and returned the anonymous token when the body carried the credentials. Result: `docker push` to a private repository failed with `unauthorized` because the OCI client received an anonymous token despite valid credentials. The handler now extracts username and password from the form body when no Basic Auth header is present, accepts `application/x-www-form-urlencoded` (with optional charset suffix), validates `grant_type=password` when supplied, and falls through to the existing Bearer / anonymous flow on any malformed input. No protocol regression: existing Basic Auth and Bearer-refresh paths are unchanged.

### Changed

- **`/readyz` no longer returns 503 when only the default admin password is unchanged** (#889). Previously, `setup_required = true` drove the readiness gate to "not ready", which made Kubernetes mark the pod NotReady and eventually restart it. The restart killed any `kubectl exec` session the operator was using to change the password, so they could never complete setup and the pod stayed in a restart loop. Now `/readyz` returns 200 OK once the database is reachable and migrations have run, even if setup is still required. The `setup_complete` field remains in the JSON body as informational; its `status` value changed from `healthy`/`unhealthy` to `complete`/`incomplete` so the value no longer implies the field is gating the response code. A `tracing::warn!` is emitted once at process startup when `setup_required` is true so log-based alerting (which previously relied on the 503 signal) can still page on the condition. The `setup` middleware that gates mutating API endpoints until setup completes is unchanged.
- **Webhooks v2 wire contract finalized** (#919). The webhook delivery wire format is now `X-ArtifactKeeper-Signature: t=<unix_secs>,v1=<hex_hmac_sha256>` over `<unix_secs>.<raw_body>`, replacing the placeholder `X-Webhook-Signature: hmac-signature` literal that shipped in v1.1.9. New headers on every delivery (test endpoint, retry path, manual redeliver): `X-ArtifactKeeper-Delivery` (UUID, idempotency key), `X-ArtifactKeeper-Event` (event type), `X-ArtifactKeeper-Event-Version` (pinned schema version, currently `2026-04-01`), and `X-ArtifactKeeper-Retry-Attempt` on retries. During the 24h secret-rotation overlap window the signature header carries two `v1=` tokens, current first, so receivers using either secret validate. The retry schedule moves from 5 attempts capped at 4h to 12 jittered attempts capped near 24h (30s, 1m, 2m, 5m, 10m, 30m, 1h, 2h, 4h, 8h, 16h, 24h, +/- 20% jitter). Webhooks that exhaust the retry budget are auto-disabled with a `disabled_reason` set, and `ak_webhook_dead_letter_total{event}` is incremented. Per-webhook event payload pinning is exposed via the new `event_schema_version` field on POST/GET/LIST `/api/v1/webhooks` (existing webhooks default to `2026-04-01`; unsupported versions return HTTP 400). Legacy `X-Webhook-*` headers continue to be emitted alongside the new headers for one release so existing receivers keep working; they will be removed in v1.3.0. See https://artifactkeeper.com/docs/advanced/webhooks for the wire contract reference and Python/Node/Go receiver samples.

### Security

- **API-token cache invalidation on user deactivation** (#931) -- when an admin deactivates or deletes a user (`PATCH /api/v1/users/{id}`, `DELETE /api/v1/users/{id}`), updates a service account (`PATCH/DELETE /api/v1/service-accounts/{id}`), or runs a federated SSO offboarding sync (`AuthService::deactivate_missing_users`), every cached API-token validation belonging to that user or service account is now rejected immediately rather than continuing to authenticate for up to 5 minutes (the previous `API_TOKEN_CACHE_TTL_SECS` window). Caveat: the invalidation map is per-process. In multi-replica deployments (Helm `replicas > 1`) only the replica that handled the admin action evicts immediately; other replicas still reject the cached entry within the same 5-minute window via the existing `WHERE is_active = true` SQL filter, but cache hits on those replicas can still authenticate during that window. A v1.2.0 follow-up will move the signal into the database or a Redis pub-sub channel so it is observed by every replica.
- **Hex virtual repo tarball shadowing guard** (#973). `GET /hex/{repo}/tarballs/{name}-{version}.tar` now blocks a Remote upstream from serving a tarball whose package name is already owned by a non-Remote member of the same virtual repo. Previously, a virtual hex repo configured with `[hex-remote (priority 1), hex-local (priority 2)]` could serve a malicious upstream `phoenix-1.0.0.tar` when the operator had published their own `phoenix` locally, because `resolve_virtual_download` iterates members in configured priority order. The metadata side of this guard (`GET /packages/{name}`) shipped in #1209 via `order_members_local_first`; this completes the pair on the tarball download path by checking non-Remote members for ownership via a single `SELECT 1 FROM artifacts WHERE repository_id = ANY($1) AND LOWER(name) = LOWER($2) LIMIT 1` query and calling `resolve_virtual_download` with `proxy_service: None` when ownership is established. The filename parser (`package_name_from_tarball_filename`) is fail-closed: filenames not matching `[a-z][a-z0-9_-]*-<version>.tar` (case-insensitive on the extension) return `None` and the guard does not activate. On guard-query DB failure the request fails closed to 500 with `event=shadowing_guard_db_error` in structured logs rather than falling through to upstream. Forward-ports the remaining piece of the abandoned PR #974 (todpunk). Other format handlers (cargo, npm, pypi, maven, rubygems) have the same shadowing attack surface and will receive analogous guards in follow-up PRs.
- **`require_scope` enforcement on admin and format push paths** (GHSA-vvc3-h39c-mrq5). A service-account token minted with `scopes: ["read"]` was accepted by `POST/PUT/DELETE /api/v1/permissions`, `POST/PUT/DELETE /api/v1/groups` and member-management endpoints, and the upload paths of most format handlers (npm, PyPI, NuGet, Maven, OCI v2, Cargo, Helm, Debian, RPM, Alpine, Conan, Conda, Cran, Git LFS, Hex, Hugging Face, Incus, Protobuf, Pub, Rubygems, SBT, Swift, Terraform, Composer, Go, ML model, Goproxy). The auth middleware was authenticating the token but the handlers were not checking the token's declared scopes. A read-scoped token could chain into full admin via `POST /api/v1/permissions` (grant self `admin` on the `system` sentinel). New `require_auth_basic_scope` and `require_scope_response` helpers in `api/middleware/auth.rs` enforce `read`/`write`/`delete`/`admin` (with `*`/`admin` wildcards). JWT user sessions pass through unchanged because scopes apply only to SA/PAT tokens. OCI v2 push and delete (`handle_start_upload`, `handle_patch_upload`, `handle_complete_upload`, `handle_put_manifest`, `handle_delete_manifest`) are gated; pull paths intentionally remain ungated. Six low-volume format handlers (Ansible, Chef, CocoaPods, JetBrains, pub_registry, Puppet, SBT, VSCode) are tracked for a follow-up PR alongside a shared raw-upload helper refactor to keep the duplication-gate metric clean; until then those handlers retain the pre-existing `require_auth_basic` and remain affected by the advisory.
- **Cross-format virtual-repo shadowing guard for cargo, npm, pypi, maven, rubygems** (#1217 audit follow-up). The supply-chain name-shadowing guard introduced for hex in #1217 now also protects the virtual-repo download paths for these five formats. A new primitive `proxy_helpers::virtual_non_remote_owns_name` runs the same `SELECT 1 FROM artifacts WHERE repository_id = ANY($1) AND LOWER(name) = LOWER($2) LIMIT 1` existence check across every non-Remote member of a virtual repo, and a new `DownloadResponseOpts::suppress_upstream_proxy` flag threads the result into the existing `try_remote_or_virtual_download` helper so Remote members are `Skip`'d when a local member owns the name. Per-format filename / path parsers and validators (`package_name_from_crate_filename`, `package_name_from_tarball_path` for npm, `package_name_from_gem_filename`, plus PEP 503 normalization for pypi and `MavenHandler::parse_coordinates` for maven's artifactId) live in `formats/*.rs` and reject path-traversal, unicode-homoglyph, and uppercase-only inputs so the guard refuses to interpret malformed names as legitimate identifiers. Maven uses `coords.artifact_id` (matching how `artifacts.name` is populated on publish); this is strictly a safety net since different groupIds may share an artifactId, but the trade-off is preferable to leaving the shadowing attack open. PyPI normalizes the requested project name via `PypiHandler::normalize_name` (PEP 503) before the guard query so name-variant attacks (`MyCompany-Utils` vs `mycompany-utils`) cannot bypass it. The `None`-to-`resolve_virtual_download` pattern that makes the guard load-bearing in hex.rs is preserved in every wire-up site.
- **Apply hex package-name validator at publish time** (#1217 audit follow-up, ak-xf8w). `POST /hex/{repo}/publish` previously checked only that the `metadata.config` `name` field was non-empty, so a publisher could craft a tarball whose name was `../evil` or `Phoenix` (uppercase) and have the malformed name persist into `storage_key`, `artifact_path`, and `artifacts.name`. The download-side guard already refused to interpret such names, but the upload side did not. Publishing now rejects any name that fails `is_valid_hex_package_name` (the same `[a-z][a-z0-9_-]*` shape the download parser enforces) with `400 Bad Request: Invalid hex package name`. Together with the move of `is_valid_hex_package_name` and `package_name_from_tarball_filename` from `api/handlers/hex.rs` to `formats/hex.rs` (ak-niid), uploads and downloads now share one source of truth for what counts as a valid hex package name.
- **Functional `LOWER(name)` index on `artifacts`** (#1217 audit follow-up, ak-wgzr). New migration `106_artifacts_lower_name_index.sql` adds `idx_artifacts_repo_lower_name ON artifacts (repository_id, LOWER(name)) WHERE is_deleted = false`. The shadowing-guard SQL compares case-insensitively (`LOWER(name) = LOWER($2)`), which is not sargable against the existing `idx_artifacts_repo_name_version`; the new functional index makes the per-download guard query a single-row index lookup instead of a sequential scan, and also accelerates the existing `find_artifact_by_name_lowercase` helper used by every metadata endpoint that resolves a package by name. See the Pre-upgrade check section for lock-window planning notes.

### Removed

- **System B notification subscriptions (BREAKING)** (#920). The deprecated `/api/v1/repositories/{key}/notifications` GET/POST/DELETE endpoints, the `notification_subscriptions` table, and the `notification_dispatcher` service are removed in v1.2.0. The endpoints carried RFC 8594 `Deprecation` / `Sunset` headers since v1.1.9 (sunset 2026-08-01) and a one-release migration window has elapsed. Replacement surfaces:
  - **Webhooks** (System A): the dedicated `/api/v1/webhooks` API shipped in v1.1.9 with the v2 wire contract (signed timestamps, replay window, secret rotation). Existing webhook-channel subscriptions were migrated by migration 081 in v1.1.9.
  - **Email**: new `/api/v1/repositories/{key}/email-subscriptions` GET/POST/DELETE endpoints (this release) backed by the `email_subscriptions` table (migration 082, also shipped in v1.1.9). Email-channel rows from `notification_subscriptions` were seeded by migration 082 in v1.1.9; no operator action is required for already-migrated rows.
  - Migration 086 drops `notification_subscriptions` after a pre-DROP `UPDATE config = '{}'` that overwrites the table's last plaintext webhook secrets. Operators with PCI-DSS / HIPAA requirements should additionally run `VACUUM FULL notification_subscriptions` in the same maintenance window (cannot be folded into the migration because VACUUM FULL cannot run inside a transaction) and rotate every webhook secret that ever transited the table, since pre-migration base backups and WAL archives may still contain plaintext bytes.
  - The 5 generated SDKs (TypeScript, Kotlin, Swift, Rust, Python) will lose the `notifications` tag, the `NotificationsApiDoc` schemas, and the three notification request/response types on the next API sync; downstream consumers should pin to a pre-v1.2.0 API tag or migrate before bumping.
  - Operator-visible log message changed: `Notification dispatcher started` is now `Email dispatcher started`; update any log-based alerting that keyed on the prior string.

## [1.1.10] - 2026-05-11

### Security

- **`dtrack-init` no longer silently revokes operator-attached `Automation` team keys** (#978, #1039, #1041) -- prior to this release, [`docker/init-dtrack.sh`](docker/init-dtrack.sh) deleted *every* `publicId` attached to the Dependency-Track `Automation` team on each cold start (empty `/shared/dtrack-api-key`). Any third-party integration (CI scanner, dashboard, webhook receiver) with a key on that team would have its credential revoked with no audit trail. The init container now records the `publicId` it minted in `/shared/.dtrack-publicid` (mode `0600`, atomically rewritten via `.tmp` + `rename`) and **refuses to rotate (exit 2)** when any foreign `publicId` is present on the team, naming each foreign key in stderr. Operators who want the previous unconditional-rotation behavior can set `DTRACK_INIT_FORCE_ROTATE=true`; the script then logs a `WARNING` listing every revoked `publicId` so the rotation is auditable.

  **Discoverability:** a refusal exits the init container non-zero with the diagnostic on stderr, which surfaces as `Init:CrashLoopBackOff` on the pod and as a non-zero `restartCount` in standard Kubernetes alerting (Prometheus `kube_pod_container_status_restarts_total`). Operators who page on init-container failures will see this signal without reading the CHANGELOG.

  **To audit your `Automation` team for foreign keys before upgrading**, run (substituting your DT URL and admin token):

  ```sh
  curl -sf -H "X-Api-Key: $DT_ADMIN_KEY" "$DT_URL/api/v1/team" \
    | jq '.[] | select(.name=="Automation") | .apiKeys[] | {publicId, maskedKey}'
  ```

  Every `publicId` in that list other than the one recorded in your running pod's `/shared/.dtrack-publicid` (or, on first install of v1.1.10, every entry) is foreign and must be either removed via the DT UI (`Administration` -> `Teams` -> `Automation` -> `API Keys`) before upgrade or explicitly accepted via `DTRACK_INIT_FORCE_ROTATE=true`.

  **Recommended long-term posture:** do not attach third-party integrations to the `Automation` team. Provision a separate DT team for external integrations; only the bundled artifact-keeper backend should consume keys from the `Automation` team.

### Added

- **CI: shell-tests are now a Tier 1 required check** (#1040) -- new `shell-tests` job in [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs `docker/test-init-dtrack.sh` on `ubuntu-latest` (capped at `timeout-minutes: 5`) and is aggregated into `ci-complete`. Self-contained — uses only `bash`, `python3`, `jq`, `curl` from the runner image; kept off the Rust critical path so cargo jobs are not blocked.

### Changed

- **`dtrack-init`: post-upgrade orphaned-key hygiene check** (#1039) -- during Kubernetes rollouts two init containers can race against the same `Automation` team and create two keys, leaving one orphaned (still a valid bearer credential against the DT API until the next cold-start rotation deletes it). The orphan window can be days or weeks in a stable cluster, and an orphan that leaks via a backup, screenshot, or log scrape remains a fully-valid key for that entire period. After every `helm upgrade`, review `Administration` -> `Teams` -> `Automation` -> `API Keys` in the DT UI and delete any entry whose `publicId` does not match the value recorded in the running pod's `/shared/.dtrack-publicid` (`kubectl exec <pod> -c <init-container> -- cat /shared/.dtrack-publicid`). A leader-election fix that closes the race in code is tracked as a follow-up and will land in a future release.

- **Mock fidelity and assertion coverage in `docker/test-init-dtrack.sh`** (#1041) -- the regression-test mock now returns HTTP 200 on `POST /api/v1/team/{uuid}/key` to match the DT 4.11 swagger contract, and the assertion suite was expanded to cover (a) warm-start short-circuit log content (not just `POST` count), (b) foreign-key refusal and `DTRACK_INIT_FORCE_ROTATE` override paths, (c) an injected 5xx from `POST /key` to exercise the script's negative branch, and (d) absence of half-written `dtrack-api-key` / `.tmp` files after a failed run. The mock-fidelity change alone is **not** drift detection — the init script uses `curl -sf` which accepts any 2xx — but the new explicit response-code assertions in the negative-path test do detect drift in the failure direction.

## [1.2.0] - 2026-04-24

## [1.1.6] - 2026-04-20

### Sponsors

Thank you to our backers for supporting ongoing development:

- **Ash A.** ([@dragonpaw](https://github.com/dragonpaw))
- **Gabriel Rodriguez** ([@injectedfusion](https://github.com/injectedfusion))

[Become a sponsor](https://github.com/sponsors/artifact-keeper)

### Fixed

- **PyPI: simple index now normalizes package names per PEP 503** (#798) -- packages with underscores, dots, or mixed case are now normalized to lowercase hyphens in the simple index, and lookups are case-insensitive.
- **npm: version-specific metadata endpoint** (#799) -- `GET /npm/{repo}/{package}/{version}` now returns the specific version object extracted from the packument, supporting both regular and scoped packages.
- **Go, Terraform, Swift: return 404 for nonexistent resources** (#800) -- version listings and release lookups for modules/packages that don't exist now return 404 instead of an empty 200. Empty repositories still work correctly.
- **Conda native: .conda package format key corrected** (#801) -- `derive_format_key()` was producing `"condanative"` instead of `"conda_native"` for multi-word format variants, breaking format handler registration. Also affects `wasm_oci` and `helm_oci`.
- **HuggingFace: long model name validation** (#802) -- model names over 255 characters, revisions over 255 characters, or paths over 2036 characters now return 400 with a descriptive error instead of a 500 database constraint violation.
- **Conan: revision count no longer inflated** (#803) -- uploading multiple files to the same recipe revision (conanfile.py, conanmanifest.txt, conan_export.tgz) now correctly counts as one revision, not three. The revisions query uses GROUP BY on the revision hash.

## [1.1.5] - 2026-04-19

### Sponsors

Thank you to our backers for supporting ongoing development:

- **Ash A.** ([@dragonpaw](https://github.com/dragonpaw))
- **Gabriel Rodriguez** ([@injectedfusion](https://github.com/injectedfusion))

[Become a sponsor](https://github.com/sponsors/artifact-keeper)

### Thank You

- @thimomulder for the OpenSearch backend request that drove the search engine migration (#462), and for an extensive backlog of enhancement requests around password policy, notifications, SMTP, and rate limiting that shaped the v1.2.0 roadmap
- @Firjens for three high-quality bug reports with clean reproductions: OTLP gRPC `FRAME_SIZE_ERROR` behind Envoy Gateway (#729), Dependency-Track HTTP rejection on private networks (#764), and the matchit route conflict that blocked startup after the Debian fix (#832). Also for the OpenTelemetry http/protobuf prototype PR (#733) that became #812.
- @ReneBeszon for reporting that virtual Maven repos could not serve SNAPSHOT artifacts (#839)
- @ddevz for two Debian remote proxy bugs: missing `.xz` index support (#810) and `admin.password` not appearing on first boot in some volume configurations (#787)
- @junsung-cho for catching the OCI 401 loop where blob `HEAD` requests dropped the bearer token because `WWW-Authenticate` omitted `scope` (#811)
- @Dreamacro for the S3 HTTP connection pool tuning PR (#772), which fixes TIME_WAIT exhaustion under sustained load

### Breaking Changes

- **Search backend replaced**: Meilisearch has been removed in favor of OpenSearch 2.x as the indexing backend (#462, #830). This enables HA search clustering without Meilisearch's Enterprise license.
  - Removed environment variables: `MEILISEARCH_URL`, `MEILISEARCH_API_KEY`
  - Added environment variables: `OPENSEARCH_URL`, `OPENSEARCH_USERNAME`, `OPENSEARCH_PASSWORD`, `OPENSEARCH_ALLOW_INVALID_CERTS`
  - Default port changed from 7700 to 9200
  - Health response field renamed from `meilisearch` to `opensearch`
  - No data migration required. The backend auto-reindexes from PostgreSQL on startup.
  - Operators using the bundled Docker Compose stack should pull the updated `docker-compose.yml` and `install.sh` (#858) before upgrading.

### Added

- **OpenSearch search backend** (#462, #830) - new `opensearch_service.rs` using the `opensearch` crate v2.x, with path_hierarchy tokenizer, edge_ngram analyzer, text+keyword multi-fields, bulk indexing via `_bulk` NDJSON, and refresh disabled during full reindex. `ArtifactDocument` gains an `is_public` field used for visibility filtering. 64 unit tests added.
- **OTLP http/protobuf transport** (#729, #812) - selectable via the standard `OTEL_EXPORTER_OTLP_PROTOCOL` environment variable. Works around the h2/tonic `FRAME_SIZE_ERROR` that occurred when running behind Envoy Gateway. Based on the prototype contributed by @Firjens in #733.
- **PermissionService for fine-grained access control** (#816, #824) - resolves user-direct and group-based permissions via a single SQL query against the `permissions` and `user_group_members` tables (migration 018). Provides `check_permission`, `list_user_permissions`, and helpers for evaluating effective access.
- **Repository-level permission enforcement in visibility middleware** (#817, #826) - `repo_visibility_middleware` now consults PermissionService after existing visibility and token-scope checks. Admin users bypass; rules are silently ignored when no rules exist on a repository, preserving existing behavior for installations that have not configured permissions.
- **Fine-grained permission checks on admin-level endpoints** (#818, #827) - `create_repository`, `update_repository`, and `delete_repository` now accept non-admin users that hold the relevant permission action on the system sentinel or target repository.
- **`enforcement_enabled` exposed in system config** (#819, #828) - the `/api/v1/system/config` endpoint reports `enforcement_enabled: true` so frontends can surface permission UI affordances.
- **Configurable S3 HTTP connection pool** (#772) - new `S3_POOL_MAX_IDLE_PER_HOST` (default 256) and `S3_POOL_IDLE_TIMEOUT_SECS` (default 90) environment variables let operators tune connection reuse and prevent TIME_WAIT exhaustion under sustained load. Contributed by @Dreamacro.
- **Group detail endpoint returns members** (#813) - `GET /api/v1/groups/{id}` now returns a `GroupDetailResponse` including the actual member list, fixing a frontend rendering bug where every group appeared empty.

### Changed

- **Search authorization model** (#829) - all six search endpoints now resolve the caller's accessible repository IDs from `role_assignments` and filter results accordingly, replacing the previous binary `public_only` flag. Closes five High-severity authorization findings discovered during OpenSearch migration review.
- **Coverage gate scope** (#822) - the new-code coverage gate now parses unified diffs and measures only added or modified lines, rather than the entire file. This unblocks small fixes to large handler files (e.g., `debian.rs`, `oci_v2.rs`) that previously could not meet the 70% threshold for unrelated existing code.
- **Coverage workflow skipped on non-Rust changes** (#855) - dependabot bumps and other non-`.rs` changes no longer trigger the 3-5 minute instrumented coverage build.
- **Bundled Trivy bumped from 0.69.3 to 0.70.0** (#807, #823) - resolves 1 CRITICAL and ~16 HIGH container scan findings in the bundled scanner binary.
- **Permission gap warnings** (#794, #820) - the backend now emits `warn!` log entries on startup when permission rules exist in the database but enforcement middleware is not active, making the previously silent gap visible to operators upgrading from earlier 1.1.x versions.
- Dependency bumps: rust 1.94-bookworm to 1.95-bookworm (#846), anchore/grype v0.111.0 to v0.111.1 (#845), openssl 0.10.76 to 0.10.78 (#849), aquasecurity/trivy-action 0.35.0 to 0.36.0 (#842), actions/setup-node 4 to 6 (#843), docker/build-push-action 7.0.0 to 7.1.0 (#841).

### Fixed

- **Maven virtual repos serve SNAPSHOT artifacts** (#839, #859) - both the version-level `maven-metadata.xml` and the SNAPSHOT JAR/POM download paths now traverse member repositories and resolve correctly. Reported by @ReneBeszon.
- **Debian backend panics on startup** (#832, #854) - axum's matchit router rejected the wildcard and parameter routes introduced in #814 because they shared a prefix segment. The catch-all dists proxy has been restructured so the router accepts both routes. This was causing a panic loop on every backend start since the Debian remote proxy fix landed.
- **Debian remote proxy `.xz` indices** (#810, #814) - remote Debian repos now serve `.xz`-compressed `Packages` files (using the `xz2` crate already in the dep tree) and proxy unrecognized files under `dists/` through to the upstream, fixing 404s on i18n Translation files. Reported by @ddevz.
- **OCI bearer token loop on blob HEAD** (#811, #821) - the `WWW-Authenticate` challenge now includes the OCI Distribution Spec `scope` parameter, so Docker clients correctly key their token cache and attach the token to subsequent blob and manifest requests. All OCI endpoints now accept Basic auth in addition to Bearer. Reported by @junsung-cho.
- **Dependency-Track HTTP rejection on private networks** (#764, #825) - the reqwest client previously enforced `https_only(true)`, causing opaque "builder error for url" failures when `DEPENDENCY_TRACK_URL` pointed at localhost, RFC 1918 private networks, or in-cluster Kubernetes services. The client now allows HTTP for private network targets. Also fixes the missing SBOM submission path so SBOMs are uploaded after artifact ingest. Reported by @Firjens.
- **`admin.password` missing on first boot** (#787, #815) - the storage directory is now created explicitly before the password file is written, fixing first-boot under bind mounts, Podman rootless, Kubernetes `emptyDir`, and custom `STORAGE_PATH` values. Reported by @ddevz.
- **OTLP http/protobuf NoHttpClient panic** (#812, #835) - added `opentelemetry-http` with the `reqwest` feature as a direct dependency to ensure the HTTP client registers when two `reqwest` versions coexist in the dep tree.
- **jsonwebtoken CryptoProvider test failures** (#835) - enabled the `aws_lc_rs` feature on `jsonwebtoken 10.3` so unit tests that bypass `main()` no longer panic on missing CryptoProvider. Fixes 11 pre-existing test failures in `auth_service` and `grpc::auth_interceptor`.
- **Search results leaked private repos to authenticated users** (#829) - any authenticated user previously saw all repository search results regardless of role assignments. Now filtered per-caller using `role_assignments`.
- **Conan `recipe_latest` and `recipe_revisions` now scope by user/channel** - the two endpoints previously ignored the `{user}` and `{channel}` path segments, so a recipe uploaded as `mylib/1.0.0@myuser/stable` could appear in the latest/revisions response for `mylib/1.0.0@_/_` (and vice versa), breaking dependency resolution for Conan clients that share a recipe name across namespaces. Both queries now filter on `am.metadata->>'user'` and `am.metadata->>'channel'`, matching the existing pattern in `recipe_files_list` and the package download handler. Discovered during the v1.2.0-rc.1 release-gate run (24934467423).

### Security

- **rustls-webpki CRL parsing panic** (#835) - bumped `rustls-webpki` from 0.103.12 to 0.103.13 (RUSTSEC-2026-0104, reachable panic in CRL parsing).
- **Permission enforcement gap closed** (#794, #816, #817, #818, #819, #820, #824, #826, #827, #828) - the `permissions` table introduced in migration 018 was previously CRUD-only with no enforcement, so administrators could create rules that the backend silently ignored. Phases 1 through 4 of the enforcement plan are now merged: PermissionService, repo_visibility_middleware enforcement, handler-level checks on admin endpoints, and the `enforcement_enabled` system-config flag. Operators upgrading from 1.1.x with existing permission rules should review the rules before deploying 1.2.0, since they will now be enforced.
- **Search authorization tightened** (#829) - five High-severity authorization findings resolved by replacing the binary `public_only` model with per-caller repo ID resolution.

## [1.1.2] - 2026-04-09

### Sponsors

Thank you to our backers for supporting ongoing development:

- **Ash A.** ([@dragonpaw](https://github.com/dragonpaw))
- **Gabriel Rodriguez** ([@injectedfusion](https://github.com/injectedfusion))

[Become a sponsor](https://github.com/sponsors/artifact-keeper)

### Thank You

- @feicipet for reporting the Maven checksum validation failure on virtual repos (#660)
- @ReneBeszon for reporting the Nexus migration stall (#654) and npm virtual repo metadata issue (#652)
- @m1m1x for reporting the APK remote repo multi-version failure (#653)
- @thonby for reporting the OIDC redirect_uri issue behind reverse proxies (#655)
- @jamie-kemp for reporting the Go proxy `go get` failure (#651)

### Fixed
- **Maven checksum 404 on virtual repos** (#660) - checksum requests (.sha1, .md5, .sha256) through virtual Maven repositories now traverse member repos and proxy from upstream, matching the behavior of artifact downloads.
- **Migration assessment stalls forever** (#654) - the assessment handler now spawns a background worker to run the assessment. Previously it set the job status to "assessing" but never executed the work. Assessment results are stored and retrievable via the GET endpoint.
- **APK remote proxy 500 across Alpine versions** (#653) - when a proxy-cached artifact's storage key is inaccessible, the handler now falls through to re-fetch from upstream instead of returning HTTP 500.
- **OIDC redirect_uri behind reverse proxy** (#655, #657) - the redirect URI is now constructed as an absolute URL using the request's Host header, fixing Keycloak/OIDC callbacks that failed when running behind a reverse proxy.
- **npm virtual repo metadata for local members** (#652, #659) - virtual npm repositories now include metadata from local and staging member repos, not just remote members.
- **Go proxy sumdb verification paths** (#651, #658) - `go get` through proxy repos no longer fails with "Bad Request" when the Go toolchain requests sumdb verification paths.

### Dependencies
- quick-xml 0.39.0 -> 0.39.2
- zip 2.4.2 -> 8.5.1
- docker/login-action 4.0.0 -> 4.1.0
- aws-actions/configure-aws-credentials 6.0.0 -> 6.1.0

Note: bergshamra was held at 0.3.x in this release. See #691 for upgrade blocker tracking.

## [1.1.0] - 2026-04-01

This is the first stable release of Artifact Keeper.

### Sponsors

Thank you to our backers for supporting ongoing development of Artifact Keeper:

- **Ash A.** ([@dragonpaw](https://github.com/dragonpaw))
- **Gabriel Rodriguez** ([@injectedfusion](https://github.com/injectedfusion))

[Become a sponsor](https://github.com/sponsors/artifact-keeper) to support the project.

### Thank You

This release includes fixes reported by the community. A special thanks to everyone who took the time to file detailed issues with reproduction steps:

- @Kimahriman for five high-quality bug reports: PyPI relative URL handling for Nexus/devpi remotes (#610), NPM scoped package encoding for private registries (#616), PyPI remote vs virtual divergence (#625), PyPI proxy cache misses (#603), and PyPI virtual download delegation (#602)
- @andrlange for four OCI/Docker bugs: manifest push error handling (#594, #595, #596) and API token auth on /v2/token (#593)
- @mtatheonly for reporting that remote repos don't list cached packages (#624)
- @gaetanmetzger for the Docker Hub remote proxy support request that led to the token exchange feature (#612)
- @ivolnistov for the SSO admin permissions fix PR (#609) and the SSO bug report (#608)
- @todpunk for the metrics endpoint feature (#571) and clippy docs fix (#572)
- @arnaudmut for reporting the Trivy image tag issue (#585)
- @myannou for the Docker remote pull failure (#584)
- @TechEnchante for the chunked upload feature request (#563)
- @Tartanpion27 for the AWS ECS/Fargate credential chain issue (#613)
- @injectedfusion for the Cargo remote 404 report (#611)
- @pipelineRat for reporting virtual repo member display issues (#461) and the SSO lockout problem (#443)
- @Lerentis for continued testing on the Maven S3 upload issue (#361)
- @msegura501 for the Caddy proxy env var fix (#445)

### Added
- **OCI bearer token exchange** (#612, #626) - remote Docker/OCI repos now handle the 401/token handshake required by Docker Hub, GHCR, and private registries. Tokens are cached in memory with TTL-based eviction. Includes SSRF validation on token endpoint URLs.
- **Chunked/resumable upload API** (#563, #564) - new `/api/v1/uploads` endpoints for multi-GB file uploads. Supports configurable chunk sizes (1 MB to 256 MB), SHA-256 verification, session expiry cleanup, and resume after interruption.
- **Upstream authentication for remote repositories** (#451) - remote (proxy) repos can now authenticate against private upstream registries using Basic or Bearer credentials. Credentials are encrypted at rest with AES-256-GCM.
- **ALLOW_LOCAL_ADMIN_LOGIN env var** (#443) - break-glass recovery mechanism that allows the built-in admin account to log in with local credentials even when SSO is configured.
- **Optional unauthenticated metrics endpoint** (#571) - contributed by @todpunk. Configurable via `METRICS_PORT` for Prometheus scraping without auth.
- **Proxy-cached artifacts in repo listings** (#624, #626) - artifacts fetched through remote proxy repos are now recorded in the database, making them visible in repository listings and storage size calculations.
- **Docker compose guide comments** (#448) - inline guidance explaining each service, what is optional, and what to change for production.

### Fixed
- **PyPI relative URL resolution** (#610, #622) - registries like Sonatype Nexus, devpi, and Artifactory that use relative hrefs in their simple index HTML now work correctly. URLs are resolved using the `url` crate's RFC 3986-compliant Url::join method.
- **PyPI virtual/direct remote parity** (#625, #627) - virtual repos now use the exact same remote proxy logic as direct remote access, including content-type preservation, conditional URL rewriting, and proxy cache checks.
- **NPM scoped package encoding for remotes** (#616, #622) - scoped packages (`@scope/pkg`) are now URL-encoded (`@scope%2Fpkg`) in upstream requests per the npm registry wire protocol. Private registries (Nexus, Verdaccio, GitHub Packages) that require the encoded form now work.
- **Chunked upload security hardening** (#621) - six P0 bugs fixed: memory-safe file streaming on complete (C1), bounded chunk body buffering (C2), session ownership verification (C3), strengthened path traversal validation (C4), total_size validation (C5), atomic chunk claim to prevent race conditions (C6).
- **SSRF protection hardening** (#622) - SSRF blocklist now rejects single-label hostnames and `.svc.cluster.local` Kubernetes addresses. Resolved URLs from upstream index pages are validated before fetch. Non-HTTP schemes rejected after relative URL resolution.
- **SSO admin permissions preserved on login** (#608, #609) - when an SSO user with admin permissions logs in and no admin group pattern matches, their existing admin flag is no longer reset. Contributed by @ivolnistov.
- **S3 ECS/EKS credential chain** (#613, #617) - switched to `AmazonS3Builder::from_env()` so ECS task roles, EKS IRSA, and instance profiles are automatically detected.
- **OCI manifest push bugs** (#594, #595, #596, #600) - three fixes: re-push after delete clears `is_deleted`, INSERT errors are no longer silently swallowed, and duplicate image name in log lines is resolved.
- **Docker /v2/token accepts API tokens** (#593, #599) - service account API tokens can now be used as Basic Auth passwords for Docker login.
- **Revoked tokens excluded from listings** (#592, #598) - service account token listing no longer includes revoked tokens.
- **Trivy image pinned** (#585, #597) - Docker image uses `ghcr.io/aquasecurity/trivy:0.69.3` instead of the removed `latest` tag.
- **S3 PUT errors surface response body** (#361) - S3 rejection details (e.g. 403 AccessDenied) now appear in error messages and structured logs.
- **Virtual repo members displayed in UI** (#455, #461) - fixed member panel rendering and OpenAPI spec field mismatch.
- **Caddy proxy env var interference** (#445) - cleared inherited Docker daemon proxy env vars on the Caddy service.
- **OCI Basic Auth on /v2 endpoint** (#457) - the `/v2/` version check endpoint now accepts Basic Auth in addition to Bearer tokens.
- **SSO login redirect URLs** (#454) - corrected OIDC/SAML callback URLs and added LDAP custom CA certificate support.

### Security
- **OIDC ID token signature verification** (#590) - validates ID token signatures via JWKS, plus nonce/iss/aud/exp claims.
- **SSRF protection on repository upstream URLs** (#590) - `validate_outbound_url` blocks private IPs, cloud metadata endpoints, and internal hostnames.
- **NPM package name validation** (#622) - decoded package names are validated for null bytes, path traversal, slash count, and length.
- **Chunked upload path traversal hardening** (#621) - rejects null bytes, backslashes, percent-encoded traversal, bare dot components, and double slashes.

### Performance
- **CI pipeline 60% faster** (#591) - sccache, dependency caching, and parallel jobs cut PR check time significantly.
- **Regex compilation moved to statics** (#622) - three per-request `Regex::new()` calls in PyPI handler replaced with `once_cell::sync::Lazy` statics.
- **N+1 download stats query eliminated** (#590) - batch query replaces per-artifact loop in artifact listing.

## [1.1.0-rc.8] - 2026-03-17

### Thank You
- @inspired-geek (Alexey Ivanov) for three quality contributions: paginated Dependency-Track list endpoints preventing truncated security data (#434), paginated Meilisearch reindex preventing OOM on large registries (#435/#440), advisory cache eviction with error visibility (#433/#439), S3 status code handling (#410), and Cargo sparse index field name fix (#419)
- @pipelineRat for reporting Maven pull-through cache failures (#427)
- @dispalt for continued feedback on storage backend behavior (#428)

### Added
- **Per-repository storage backend selection** (#431) - repositories can now be configured to use different storage backends (filesystem, S3, Azure, GCS) independently of the global default.
- **Correlation ID middleware** (#432) - every HTTP response now includes an `X-Correlation-ID` header for distributed tracing. The middleware was previously defined with 13 unit tests but never wired into the router.
- **Configurable rate limits** (#436) - auth and API rate limits are now configurable via `RATE_LIMIT_AUTH_PER_MIN` (default 120), `RATE_LIMIT_API_PER_MIN` (default 5000), and `RATE_LIMIT_WINDOW_SECS` (default 60) environment variables.

### Fixed
- **bcrypt blocking the async runtime** (#436) - moved all `bcrypt::verify` and `bcrypt::hash` calls to `tokio::task::spawn_blocking()`. Previously, bcrypt at cost-12 (~250ms per call) ran synchronously on the tokio event loop, serializing all concurrent requests. At 5 concurrent logins, max latency was 2.7s. Now runs on the blocking thread pool.
- **Rate limiter shared bucket in Kubernetes** (#436) - without `ConnectInfo`, all clients shared a single `ip:unknown` rate limit bucket. Now falls back to `X-Forwarded-For` from trusted ingress controllers. Auth rate limit raised from 30 to 120 req/min (bcrypt cost-12 already provides brute-force protection).
- **Sync policy create doesn't auto-evaluate** (#438) - creating, updating, deleting, or toggling a sync policy now automatically calls `evaluate_policies()` to populate `peer_repo_subscriptions`. Previously, uploads after policy creation wouldn't trigger sync tasks until a manual `/evaluate` call.
- **Maven SNAPSHOT timestamp treated as classifier** (#432) - `strip_snapshot_timestamp()` now correctly strips timestamp-build suffixes (e.g., `-20260314.155654-1`) from SNAPSHOT filenames so they aren't misidentified as classifiers.
- **Maven SNAPSHOT re-upload not updating primary** (#432) - when a new SNAPSHOT build replaces an existing primary artifact, the artifact record now correctly updates path, checksum, and storage key.
- **Dependency-Track truncated results** (#434) - list endpoints now paginate through all results instead of returning only the first page. Contributed by @inspired-geek.
- **Meilisearch OOM on large reindex** (#440) - full reindex now uses cursor-based pagination (1000 rows per batch) instead of loading all artifacts into memory. Download count subquery scoped to batch. `MeiliService::new` returns `Result` instead of panicking. Based on contribution by @inspired-geek.
- **Advisory cache silent error swallowing** (#439) - replaced `if let Ok` patterns with `match` + `warn!` logging for OSV and GitHub advisory API deserialization failures. Added bounded cache eviction. Based on contribution by @inspired-geek.
- **S3 backend error propagation** (#410) - improved status code handling and fallback error messages. Contributed by @inspired-geek.
- **Cargo sparse index field name** (#419) - renamed `version_req` to `req` in dependency entries to match the sparse registry protocol spec. Contributed by @inspired-geek.
- **Maven secondary GAV file serving** (#430) - resolve SNAPSHOT downloads and serve secondary files (POM, javadoc, sources) from the correct GAV path.
- **Maven SNAPSHOT checksum resolution** (#417) - resolve checksum requests for timestamped SNAPSHOT versions.
- **Maven GAV coordinate grouping** (#418) - group deploy artifacts by GAV coordinates to prevent incorrect artifact association.

### Changed
- Auth rate limit default raised from 30 to 120 req/min
- API rate limit default raised from 1,000 to 5,000 req/min
- Dependency bumps: docker/metadata-action 5 to 6, docker/build-push-action 6 to 7, docker/login-action 3 to 4, actions/github-script 7 to 8, anchore/grype v0.109.0 to v0.109.1, aquasecurity/trivy-action 0.34.2 to 0.35.0, rust 1.93-bookworm to 1.94-bookworm, quinn-proto security patch

## [1.1.0-rc.7] - 2026-03-08

### Thank You
- @todpunk for the security advisory heads-up and a Cargo token performance fix (#378, #377)
- @arp-mbender for reporting the broken quickstart commands (#368)
- @dispalt for catching the staging repo filter issue and SNAPSHOT soft-delete collision (#363, #321)
- @Lerentis for reporting the Maven path upload bug and the S3 IRSA panic (#361, #343)
- @lpreiner for flagging private repository visibility leaking to unauthenticated users (#333)
- @CJLove for continued follow-up on Docker login behind reverse proxies (#322)

### Added
- **Package curation engine** (#405) - intercept packages from upstream mirrors through staging repos, evaluate against configurable rules (glob patterns, version constraints, architecture filters), and approve or block before exposing to consumers. Includes rules CRUD, bulk operations, re-evaluation, and stats API endpoints.
- **Curation upstream sync** (#405) - background scheduler fetches and parses RPM primary.xml and DEB Packages indexes from remote repos, populating the curation catalog automatically.
- **Artifact content viewing endpoint** (#407) - `GET /api/v1/tree/content` returns inline file content for browsing artifacts in the web UI.
- **Automatic stale peer detection** (#402) - scheduler marks peers as stale when heartbeats stop, preventing sync attempts to unreachable nodes.
- **Failed sync retry on peer recovery** (#401) - automatically retries previously failed sync tasks when a peer comes back online.
- **Shared virtual metadata resolution** (#399) - extracted reusable helpers for resolving metadata across virtual repository members, reducing duplication in format handlers.
- **Build traceability** (#367) - `/health` endpoint now includes the git commit SHA for identifying deployed versions.

### Fixed
- **Path traversal in FilesystemStorage** (#387, #380) - sanitize storage keys to prevent directory traversal attacks via crafted artifact paths.
- **Peer identity endpoint exposed to non-admins** (#388, #381, #382) - restrict peer announce, heartbeat, and identity endpoints to admin users only.
- **gRPC missing admin authorization** (#390, #383) - add admin privilege checks to the gRPC auth interceptor.
- **Admin password file permissions** (#391, #384) - create password file with mode 0600 instead of world-readable.
- **Timing side-channel in token validation** (#392, #385) - use constant-time comparison for API token prefix lookup.
- **Authentication audit logging** (#393, #386) - wire up audit log entries for login, logout, and token operations.
- **Quickstart commands in README** (#394, #368) - fix incorrect docker compose commands in the getting started guide.
- **Air-gapped deployment issues** (#379) - fix offline installation and configuration for disconnected environments.
- **Cargo sparse index proxy path** (#342, #341) - strip `index/` prefix when proxying to upstream Cargo registries.
- **Soft-deleted artifact collision on re-upload** (#339, #321) - clean up soft-deleted records before INSERT to prevent unique constraint violations.
- **Maven version-level metadata** (#362, #361) - serve maven-metadata.xml from storage at the version path level.
- **Staging repo filter** (#364, #363) - accept `repo_type` query alias for filtering staging repositories.
- **Repository format enum casting** (#376) - cast `repository_format` enum to text in quality check queries to prevent type mismatch errors.
- **S3 IRSA TLS panic** (#348, #343) - install rustls CryptoProvider before S3 client initialization to prevent panics with IAM Roles for Service Accounts.
- **Fork PR SonarCloud gate** (#396) - detect fork PRs correctly in the quality gate workflow.
- **E2E PKI container cleanup** (#400) - kill lingering gpg-agent processes before cleanup to prevent non-zero exit codes.
- **Cargo token auth performance** (#377) - contributed by @todpunk.

### Tests
- Curation E2E test suite (#406) - 33 assertions across 13 phases covering sync, rules, manual/bulk status, stats, CRUD, global rules, and DEB format. Uses mock upstream repos (nginx serving RPM/DEB fixture files).

### Changed
- Trivy CI scanner bumped from 0.69.1 to 0.69.3 (#404)
- ALLOW_HTTP_INTEGRATIONS added to compose backend environment (#397)
- CI mirror namespace switched to GHCR for fork PR E2E parity (#366)
- Dependency bumps: actions/checkout 4 to 6, actions/upload-artifact 6 to 7, actions/download-artifact 4 to 8, github/codeql-action 3 to 4, alpine 3.21 to 3.23, trivy-action 0.34.1 to 0.34.2

## [1.1.0-rc.6] - 2026-02-28

### Thank You
- @CJLove for reporting the OCI v2 auth challenge issue behind reverse proxies (#315)
- @dispalt for identifying the Maven SNAPSHOT re-upload bug and scanner storage backend resolution (#297, #296)
- @msegura501 for reporting private repository visibility enforcement (#280)

### Added
- **Azure RBAC authentication for Blob Storage** (#312) - support managed identity and service principal authentication for Azure Blob Storage, removing the need for connection strings
- **Alpine-based Docker image variant** (#306) - lighter alternative image based on Alpine Linux alongside the existing UBI image
- **Release gate integration** (#317) - backend releases now run the full artifact-keeper-test suite (38 formats, stress, resilience, mesh) before proceeding
- **Quality of life improvements** (#298) - 9 features: configurable GC/lifecycle cron scheduling, stale proxy cache fallback, deletion replication to peers, webhook delivery retry with exponential backoff, soft token revocation with `last_used_at` tracking, per-repo cache TTL endpoint, search reindex API, quota warning events, and replication filters with regex include/exclude patterns

### Fixed
- **OCI v2 auth challenge uses wrong scheme/host behind reverse proxy** (#315, #316) - `Www-Authenticate` header now respects `X-Forwarded-Proto` and `X-Forwarded-Host`, fixing `docker login` failures when running behind Caddy, Nginx, or other reverse proxies
- **Maven SNAPSHOT re-upload and hard-delete** (#297, #301) - SNAPSHOT artifacts can now be re-uploaded (overwritten) as expected, and hard-delete properly removes files from storage
- **Scanner storage backend resolution** (#296, #301) - security scanners now use the configured storage backend (S3, Azure, GCS) instead of defaulting to filesystem
- **Format route key extraction** (#302) - fix repo key parsing for format handler routes when the key contains path separators
- **Private repository visibility enforcement** (#300) - anonymous users can no longer access private repository metadata
- **Storage probe path traversal** (#293, #308) - validate that health check storage probe paths stay within the base directory
- **Code scanning alerts** (#307) - address CodeQL alerts #16 and #39 for taint flow and input validation
- **Wasmtime CVE bump** (#292) - upgrade to wasmtime 24.0.6 for CVE-2026-27572 and CVE-2026-27204

### Tests
- Unit tests for ArtifactFilter matching logic (#309)
- E2E tests for Maven SNAPSHOT re-upload and S3 scanner (#304)
- Flaky cron policy test fix and Postgres added to coverage job (#311)
- Custom CodeQL workflow replacing default setup (#305)

### Changed
- Docker Hub documented as alternative registry (#289)
- Dependency bumps: actions/attest-build-provenance 3 to 4, SonarSource/sonarqube-scan-action 6 to 7

## [1.1.0-rc.4] - 2026-02-25

### Added
- **Service accounts and token scoping** (#205, #208, #209) - service account entities with API tokens, scope enforcement across all repository handlers, and RepoSelector-based token restrictions
- **Incus/LXC container image support** (#206) - new `incus` repository format implementing the SimpleStreams protocol for container and VM images
- **SSE event stream for live data refresh** (#269) - server-sent events endpoint allowing the web UI to receive real-time cache invalidation signals
- **Physical storage garbage collection** (#233) - background task to reclaim disk space from soft-deleted artifacts
- **Tag-filtered peer replication** (#243) - filter replication to only sync artifacts matching specified tag patterns
- **WASM plugin v2: handle-request** (#256) - plugins can now serve native package format wire protocols directly
- **`SKIP_ADMIN_PROVISIONING` env var** (#224) - skip admin user creation on first boot for SSO-only deployments
- **Artifact filter enforcement with retroactive sync** (#204) - evaluate filters against existing artifacts when policies change

### Fixed
- **Storage backend hardcoded to filesystem** (#237, #244, #245, #246) - use the configured storage backend (S3, Azure, GCS) instead of always defaulting to local filesystem
- **OIDC env var config ignored** (#249) - environment variable configuration for OIDC providers was not being read
- **Local login not blocked with SSO** (#223) - block local password login when SSO providers are configured
- **LRU eviction for size quotas** (#226) - change storage quota eviction from FIFO to least-recently-used ordering
- **Lifecycle policy execution** (#225) - implement `tag_pattern_keep` lifecycle policy type
- **Streaming uploads for Incus** (#217, #242) - fix chunked upload handling for large container images
- **96 code scanning alerts resolved** (#267, #268) - taint-flow fixes, safe string handling, and input validation improvements
- **DNS rebinding protection** - bound allocations, upgrade KDF from static HMAC to HKDF with domain separation
- **HTTPS enforced in Dockerfile healthchecks** (#251)

### Security
- **Privilege escalation fix** (#273) - enforce admin checks on user creation and all admin routes
- **Archive extraction hardening** (#274) - path traversal protection, safe file handling, parameterized SQL
- **Encryption and rate limiter hardening** (#275) - improved encryption key derivation, LDAP injection prevention, CSP headers, XSS/SSRF mitigations
- **SSRF and path traversal fixes** (#277) - close server-side request forgery vectors and path traversal in file operations
- **KDF upgrade** - migrate from static HMAC key to HKDF with domain separation, fix CodeQL hard-coded crypto alerts

### Changed
- SonarCloud scanner added to CI (#247)
- Code coverage reporting with cargo-llvm-cov (#229)
- All environment variables documented in .env.example (#227)
- Mergify auto-merge configuration (#215)
- Dependency bumps: actions/upload-artifact 4 to 6, actions/checkout 4 to 6, actions/attest-build-provenance 2 to 3

### Tests
- Unit test coverage increased toward 80% quality gate (#253, #254)

## [1.1.0-rc.3] - 2026-02-17

### Fixed
- **Token creation broken** (#195, #197) — `POST /api/v1/auth/tokens` and `DELETE /api/v1/auth/tokens/{token_id}` were documented in the OpenAPI spec but never registered in the router, causing silent 404s from the frontend
- **Non-admin users could request admin scope** (#197) — backend now returns 403 when a non-admin user attempts to create a token with the `admin` scope
- **Podman / standalone Docker Compose compatibility** (#194, #196) — SELinux `:z` bind-mount labels, replaced `service_completed_successfully` dependency with polling entrypoint, changed healthcheck from `/readyz` to `/livez`, downgraded web/caddy depends_on to `service_started`
- **Caddyfile missing `/livez` and `/readyz` routes** (#196) — reverse proxy now forwards liveness and readiness probes to the backend

### Added
- **OpenAPI route audit test** (#197) — `test_all_openapi_paths_have_handlers` cross-checks every documented endpoint against handler source files, catching annotated-but-unregistered routes at compile time

### Changed
- Renamed `UserResponse` to `AdminUserResponse` in users handler to avoid DTO collision (#187)
- CI skips Docker publish for docs-only changes (#185)

## [1.1.0-rc.2] - 2026-02-15

### Added
- **Promotion Workflow** (#151) — approval chains, age gates, signature verification, and rejection with audit trail
- **Auto-Promotion Rules Engine** (#152) — configurable rules for automatic artifact promotion based on quality gates, age, and scan results
- **K8s Health Probes & OpenTelemetry Tracing** (#147) — structured health endpoints for liveness/readiness and distributed tracing with span propagation
- **SECURITY.md** — vulnerability reporting policy

### Changed
- **UBI 9 Micro Runtime** (#160) — all containers migrated from Alpine to Red Hat UBI 9 Micro for STIG compliance
- **Container Hardening** (#163, #164) — Cosign image signing, Trivy vulnerability scanning in CI, and STIG hardening
- **UBI 9.5 → 9.7** (#170, #172, #173) and **Alpine 3.19 → 3.23** (#171)
- **SonarCloud Integration** (#158, #159, #162) — static analysis and Dockerfile scanning in CI
- **Dockerfiles Consolidated** (#157) — all Dockerfiles and Caddyfile moved to `docker/` directory
- **Deploy Folder Relocated** (#154, #155) — moved to `artifact-keeper-iac` repository
- **Self-Hosted ARC Runner** (#148) — smoke E2E tests run on self-hosted Actions Runner Controller
- **Dependabot Bumps** — codeql-action 3→4, upload-artifact 4→6, download-artifact 4→7, aws-actions/configure-aws-credentials 4→6, stale 9→10

### Fixed
- **Duplicate OpenAPI operationIds** (#182) — explicit operation IDs for sync_policies and repository_labels handlers to fix SDK generation
- **Release Build Pipeline** (#181) — add protoc installation and vendored OpenSSL for cross-platform binary builds
- **CI Pipeline Repairs** (#174, #175, #178) — Docker publish, security scan, and Trivy scan fixes
- **Native Test Scripts** (#177) — PyPI sed portability, NPM auth config, Cargo registry config fixes
- **E2E Test Failures** (#146, #180) — Go, Docker, Helm, Protobuf test fixes; switched release gate to smoke profile
- **arm64 Docker Builds** — use arch-appropriate protoc binary
- **Artifact Download Filter** — release workflow only downloads binary archives, not E2E artifacts

### Tests
- Backend unit test coverage pushed toward 80% (#153)

## [1.1.0-rc.1] - 2026-02-13

### Added
- **Artifact Health Scoring & Quality Gates** (#129)
  - Pluggable quality check system with composite health scores (A-F grade) and configurable quality gates for promotion gating
  - MetadataCompletenessChecker (all formats) and HelmLintChecker (in-process chart.tgz validation)
  - QualityCheckService orchestrator with weighted scoring (security=40, quality=25, license=20, metadata=15)
  - 15 new API endpoints under `/api/v1/quality`; async checks triggered on artifact upload
- **Sync Policy Engine & Background Sync Worker** (#109, #122)
  - Declarative label-based replication policies with JSONB selectors for repos and peers
  - 8 new API endpoints (`/api/v1/sync-policies`) for CRUD, evaluation, and preview
  - Peer instance labels API (`GET/PUT/POST/DELETE /api/v1/peers/:id/labels`) for `match_labels` resolution (#122)
  - Auto-evaluate triggers on repo label, peer label, and new peer registration changes (#122)
  - 5-minute periodic re-evaluation scheduler to catch drift (#122)
  - Background sync worker with per-peer sync windows, exponential backoff, and concurrent transfer limits
- **Remote Proxy Repositories** (#112)
  - Remote repos now proxy artifacts from upstream registries (npmjs.org, PyPI, Maven Central, etc.) on cache miss
  - Automatic local caching with 24-hour TTL and ETag-based revalidation
  - ProxyService wired into all 28 format handlers for download endpoints
  - Write guards return 405 Method Not Allowed on remote repos
- **Virtual Repository Resolution** (#112)
  - Virtual repos aggregate multiple member repos (local + remote) with priority-based resolution
  - Metadata merging for npm (`get_package_metadata`) and PyPI (`simple_project`) so native clients (`npm install`, `pip install`) work through virtual repos
  - Write guards return 400 Bad Request on virtual repos
  - Tarball URL rewriting to route downloads through the virtual repo key
- **Protobuf/BSR Format Support** (#119)
  - New `protobuf` repository format implementing BSR-compatible Connect RPC endpoints
  - 10 endpoints: GetModules, CreateModules, GetCommits, ListCommits, Upload, Download, GetLabels, CreateOrUpdateLabels, GetGraph, GetResources
  - Full proxy/virtual repository resolution support
- **Repository Key Renames** (#120) — `PATCH /api/v1/repositories/{key}` now accepts a `key` field to rename the URL slug
- **Repository Labels API** (#108)
- **Artifact Upload Sync Trigger** (#108)
- **Full-stack Kubernetes Manifest** (#104)
- **Proxy/Virtual E2E Test Suite** (#112)
  - 21-test script covering proxy downloads, write rejection, virtual resolution, and native client integration
  - Docker Compose `proxy` profile for CI
  - Bootstrap script creates remote, local, and virtual repos with member wiring
- **Mesh Replication E2E Workflow** (#127) — GitHub Actions workflow for automated mesh replication testing via ArgoCD
- **Stale Bot** (#121) — auto-labels inactive issues

### Fixed
- **Proxy cache key collision**: Metadata cached as file blocked tarball paths that needed same prefix as directory; fixed with `__content__` leaf file scheme (#112)
- Fix `replication_mode` enum type cast in sync policy evaluate (#126)
- Fix `format` column type mismatch in sync policy evaluate (#125)
- Fix peer instance labels auth middleware mismatch (#124)
- Use AWS default credential chain instead of env vars only (#106)
- Ensure admin login works on fresh installs and fix Dependency-Track startup race (#102)
- Add setup instructions to `admin.password` file so users know to login first (#100)
- Auto-enable NVD API 2.0 and add proxy passthrough for Dependency-Track (#98)
- Set global 512 MB body limit to prevent silent upload truncation (#97)

### Changed
- Moved `site/` to separate `artifact-keeper-site` repository (#101)

## [1.0.0-rc.3] - 2026-02-08

Bug fix release resolving 9 issues found by automated stress testing, plus build hygiene improvements.

### Fixed
- **Promotion handler**: Fix storage_key bind using `artifact.path` instead of `artifact.storage_key`, causing promoted artifacts to be undownloadable (#65, #72)
- **Promotion handler**: Replace direct `tokio::fs::copy` with `FilesystemStorage` abstraction to respect content-addressable sharding (#65, #72)
- **Repository key validation**: Add strict allowlist rejecting path traversal, XSS, SQL injection chars, null bytes, and keys over 128 characters (#69, #70)
- **Upload size limit**: Add `DefaultBodyLimit::max(512MB)` to repository router; Axum default 2MB was blocking legitimate uploads (#67)
- **Rate limiting**: Increase API rate limit from 100 to 1000 req/min, auth from 10 to 30 req/min (#66, #68, #71, #73)
- **Download panic**: Lowercase `X_ARTIFACT_STORAGE` header constant for `HeaderName::from_static()` compatibility
- Correct `AuthExtension` type in promotion handlers (#62)
- Remove extra blank lines in promotion handlers (#63)
- Fix pre-release banner overlapping content on mobile (#64)
- Use dev tag for main builds, latest only on release tags (#60)

### Added
- DevOps stress test agent script (12-phase, 71-test suite)

### Changed
- Documentation gaps filled for v1.0.0-a2 features (#61)

## [1.0.0-a2] - 2026-02-08

Second alpha release with staging promotion workflow, Dependency-Track monitoring, red team security hardening, and landing page refresh.

### Added
- **Staging Promotion Workflow**
  - New staging repository type for promotion-based artifact lifecycle
  - Promotion API endpoints for staging → release workflow
  - Policy gate integration for automated promotion decisions
  - Simplified promotion policy and handler code (#49)
- **Dependency-Track Monitoring** (#57)
  - Backend API for Dependency-Track integration
  - OpenSCAP and Dependency-Track added to health monitoring dashboard
- **Red Team Security Testing Suite** (#52)
- **STS Credential Rotation E2E Tests** (#56)
- **Pre-release banner** on landing page and README

### Changed
- Updated landing page to LCARS color scheme with new brand colors
- Pre-release banner changed from warning to release announcement

### Fixed
- Refresh credentials before presigned URL generation (#55)
- Calculate storage_used_bytes for repository list view (#58)
- Position banner above navbar without overlap
- CI fixes: fmt, clippy, and broken migration (#48)
- CI fixes: PKI file handling in E2E tests (tar archive, explicit patterns)

### Security
- Hardened 7 vulnerabilities identified by red team scan (#53)

## [1.0.0-a1] - 2026-02-06

First public alpha release, announced on Hacker News.

### Added
- **OWASP Dependency-Track Integration** (#46)
  - Docker service configuration for Dependency-Track API server
  - Rust API client for SBOM upload, vulnerability findings, policy violations
  - Comprehensive SBOM & Dependency-Track documentation
  - E2E test script for Dependency-Track integration
- **Multi-cloud Storage Backends** (#45)
  - Azure Blob Storage backend
  - Google Cloud Storage backend
  - Artifactory migration mode with fallback path support
- **S3 Direct Downloads** (#38)
  - 302 redirect to presigned S3 URLs
  - CloudFront signed URL generation
  - Configurable via `STORAGE_S3_REDIRECT_DOWNLOADS`
- **SBOM Generation & gRPC API** (#31)
  - CycloneDX and SPDX format support
  - CVE history tracking
  - gRPC service for SBOM operations
- **WASM Plugin E2E Tests** (#37)
- **SSO E2E Test Suite** - LDAP/OIDC/SAML authentication tests
- **TOTP Two-Factor Authentication**
- **Privacy Policy Page** for app store submissions
- **Migration Pipeline** - Artifactory and Nexus OSS support
- **OpenSCAP Multi-arch Image** with scanning enabled by default

### Changed
- Simplified and deduplicated code across backend and scripts (#27)
- Updated docs to use peer replication model instead of edge nodes
- Docker build cache optimization with cargo-chef and native arm64 runners
- Streamlined CI pipeline with CI/CD diagram in README

### Fixed
- E2E test infrastructure improvements (bootstrap, setup containers)
- CI workflow fixes (clippy warnings, YAML indentation)
- SSO e2e test infrastructure fixes
- Logo resized to exact 512x512 for app stores
- Metrics endpoint proxied through Caddy
- Various Caddy and port configuration fixes

### Security
- Secure first-boot admin password with API lock
- GitGuardian integration for secret scanning

## [1.0.0-rc.1] - 2026-02-03

### Added
- First-boot admin provisioning and Caddy reverse proxy
- OpenSCAP compliance scanner service
- Package auto-population and build tracking API
- httpOnly cookies, download tickets, and remote instance proxy
- SSO single-use exchange codes for secure token passing
- Complete SSO auth flows with real LDAP bind, SAML endpoints, and encryption key handling
- Admin-configurable SSO providers (OIDC, LDAP, SAML)
- Web frontend service in all docker-compose files
- Native apps section on landing page with macOS, iOS, Android demos

### Changed
- Use pre-built images from ghcr.io instead of local builds
- Rename frontend to web in Docker deployment docs
- Use standard port 3000 and correct BACKEND_URL env var for web service
- Clean up operations services and handlers
- Simplify SSO backend code for clarity and consistency

### Fixed
- NPM tarball URL and integrity hash in package metadata
- Hardcoded localhost:9080 fallback URLs removed from frontend
- Logo transparency using flood-fill to preserve silver highlights
- Duplicate heading on docs welcome page
- GitHub links updated to point to org instead of repo
- CORS credentials support for dev mode
