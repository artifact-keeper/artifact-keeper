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

- **Scanner dedup TTL no longer silently masks re-scans when a prior completed scan had zero findings** (closes #1469). `find_reusable_scan` and `find_existing_scan_for_artifact` previously applied a uniform 30-day TTL to every `status='completed'` row that matched `(checksum_sha256, scan_type)`. The uniform window has a hole: a scan that finished successfully but produced zero findings is indistinguishable, at the `scan_results` table level, from (1) a genuinely clean artifact and (2) a silent extraction failure where the staging tree was empty so the scanner walked nothing (the incus backup-format bug in #1427 / #1428 is the canonical instance). Case (2) gets cached for 30 days, so the operator-visible "rescan after fixing the extraction bug" silently returns the cached false-clean result. Two changes resolve this: (a) both dedup queries now take a second `zero_findings_ttl_days` argument and apply it via `CASE WHEN findings_count = 0 THEN ... ELSE ... END`, with the production callers passing the new `ZERO_FINDINGS_DEDUP_TTL_DAYS = 1` constant; zero-finding rows older than one day are no longer returned as reusable, while non-zero-finding rows still dedup for the standard 30 days, so legitimate vulnerability data continues to be reused; (b) `TriggerScanRequest` gains an optional `bypass_dedup: bool` (default `false`) that threads down through `prepare_artifact_scan`, `scan_artifact_with_options`, `scan_artifact_with_prepared`, `scan_repository_with_options`, and `scan_artifact_inner` to short-circuit both the same-artifact and cross-artifact dedup paths entirely, giving operators an explicit "rescan now, ignore the cache" knob for the impatient case. The inventory-backfill admin path (`POST /api/v1/admin/scan-inventory-backfill`) now passes `bypass_dedup = true` because its whole purpose is to populate SBOM rows that the cached false-clean had left empty. The `bypass_dedup` knob is gated to admin callers (the handler returns `403` for non-admin callers that set it `true`) so unprivileged users cannot use it to force-rescan expensive workloads. Four DB-backed regression tests in `tests/scan_dedup_zero_findings_ttl_tests.rs` cover the stale-zero-finding skip, the within-window keep, the unchanged non-zero-finding path, and the operationally-important "newer stale zero must not displace an older real-finding row" ordering case. Two `TriggerScanRequest` serde tests pin the new field's default-omitted and explicit-true/false shapes.
- **Dependency-Track SBOM submission now surfaces 401/403 with the required permissions named in the log** (closes #1472). `submit_sbom_to_dependency_track` (in `backend/src/services/scanner_service.rs`) previously swallowed every DT API failure as a `warn!`-level line, including the canonical "API key team is missing `BOM_UPLOAD` / `PROJECT_CREATION_UPLOAD`" 403 that every fresh DT install hits because the default `Automation` team has none of those permissions. The result was that a working DT integration and a totally broken DT integration looked identical from the outside: scans returned green, the SBOM payload was well-formed in the response, and DT stayed empty. The scanner caller is now `error!`-level, the AppError message returned from the DT service carries the upstream HTTP status, the endpoint URL, the upstream response body, and -- on 401/403 -- a permissions hint naming all four required DT team permissions (`BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD`, `VIEW_PORTFOLIO`, `VIEW_VULNERABILITY`). The bundled `docker/init-dtrack.sh` bootstrap script now grants those permissions to the team it provisions, so out-of-the-box deployments no longer ship with a broken DT integration. Operators who bring their own DT instance or set `dependencyTrack.existingApiKeySecret` should grant the four permissions to the team that owns the API key via the DT UI (Administration -> Teams -> Permissions) or `POST /api/v1/permission/{permission}/team/{uuid}`. Three new wiremock tests pin the behaviour: `test_dt_bom_upload_403_surfaces_permissions_hint`, `test_dt_create_project_401_surfaces_permissions_hint`, and `test_dt_500_does_not_include_permissions_hint` (the last asserts the hint is gated on 401/403 so it does not mislead the operator into rotating a key that is actually fine when DT itself is the one failing).
- **OpenSCAP scanner accepts the default scan workspace path out of the box** (closes #1466). The wrapper sidecar (`scripts/openscap-wrapper.py`) validates incoming scan paths against `OPENSCAP_ALLOWED_SCAN_DIRS`, which defaulted to `/tmp/:/var/tmp/`. The backend, however, writes per-artifact scan workspaces under `SCAN_WORKSPACE_PATH` (defaults to `/scan-workspace`) and sends that path to the wrapper, so every fresh docker-compose and Helm install hit `HTTP 400 {"error": "scan path not found or not allowed"}` on first Docker/OCI scan unless the operator knew to set the env var. The wrapper's default allowlist now includes `/scan-workspace/` alongside the previous `/tmp/` and `/var/tmp/` entries, so the default deployment topology works without per-deployment tweaks. Operators who customise `SCAN_WORKSPACE_PATH` or want a stricter allowlist can still override via `OPENSCAP_ALLOWED_SCAN_DIRS`. The backend's HTTP-400 surface in `services::openscap_scanner::call_openscap` also now includes the rejected path in the error chain so future allowlist mismatches are debuggable from backend logs alone, without enabling wrapper-side debug logging. Three new unit tests in `openscap_scanner::tests` cover the prepare-and-scan happy path (asserting the request body carries the configured workspace path), the workspace-under-base invariant, and the error-message-includes-rejected-path invariant.
- **Incus image scanner can scan real multi-GiB OS images again** (closes #1492, follow-up to #1428). The extraction hardening added in #1428 made the `incus-image` scanner reject every legitimate `incus export` OS rootfs: the compressed-size cap was 2 GiB (a real image is several GiB compressed), the post-extraction guard walked the tree as the non-root scanner UID and hit `EACCES` on a real rootfs's restrictive modes (combined with `--no-same-owner` extraction and tar's implicitly-created parent dirs that miss the archive `--mode`), and the symlink-traversal guard resolved absolute targets against the host root, so the ubiquitous `/var/run -> /run` present in essentially every OS rootfs was flagged as escaping the workspace. Three changes, with the decompression-bomb guards kept in force: (1) the compressed and extracted byte caps are now env-tunable (`MAX_INCUS_SCAN_COMPRESSED_BYTES` / `MAX_INCUS_SCAN_EXTRACTED_BYTES`) with OS-image-sized defaults (16 GiB compressed / 64 GiB extracted); (2) the extracted tree is made owner-traversable (`u+rwX`) before the guard walk and the trivy scan, done in-process via `symlink_metadata` so the chmod never follows a symlink target out of the workspace (which a `chmod -R` would); (3) absolute symlink targets are re-rooted under the workspace (chroot semantics) so `/run` resolves in-tree and is accepted, while `../`-style targets that normalise outside the workspace are still rejected. Adds unit tests for the env-cap resolver, the owner-traversable walk over a `0o000` tree, the guard passing a restrictively-permissioned tree, acceptance of absolute intra-rootfs links, and rejection of both relative and absolute climbing-out escapes. The silent-completion gap the reporter also noted (a failed format-native scanner still rolling up to an overall `completed` status) is tracked separately as #1497.
- **Scan dedup short-circuits on identical-bytes uploads instead of writing duplicate rows** (closes #1373). `ScannerService::prepare_artifact_scan` previously inserted a fresh `running` placeholder row on every call, even when the target artifact already had a completed scan for the same checksum + scan_type within the dedup TTL window. The placeholder was returned to the trigger-scan caller and then fell through `scan_artifact_inner`'s `should_skip_reuse_for_same_artifact` branch, which (pre-fix) skipped the reuse-copy path and ran a fresh scan, leaving the artifact with two completed `scan_results` rows for one logical scan. The release-gate `scan-dedup-checksum` suite (run 26344757642) caught this with `Per-artifact scan list for B contains exactly one completed scan; got 2` and `Second scan on identical bytes returns same scan_id`. The fix adds `ScanResultService::find_existing_scan_for_artifact`, scoped to `(artifact_id, checksum_sha256, scan_type, status='completed')` within `DEDUP_TTL_DAYS`. `prepare_artifact_scan` consults it before inserting a placeholder and returns the existing scan id when one is found, and `scan_artifact_inner` now `continue`s without inserting a new row when the matched reusable scan belongs to the same artifact (the auto-scan-on-upload path). If a placeholder was already committed in a race window between prepare and execute, the inner loop converts it to a reused row pointing at the existing source rather than leaving it stuck in `running`. The cross-artifact dedup path that copies a source scan's results into a new row for a different `artifact_id` (`find_reusable_scan` + `copy_scan_results` / `convert_to_reused`) is unchanged. Seven integration tests in `tests/scan_dedup_short_circuit_tests.rs` cover the new method's happy path, all four negative cases (different artifact, different checksum, different scan_type, `running` instead of completed), the TTL-window cutoff, and the most-recent-wins ordering.
- **Deactivated user's API token now rejected with 401 within seconds, not silently downgraded to anonymous, on optional-auth routes** (closes #1371). `optional_auth_middleware` previously treated an explicitly-presented but invalid Bearer credential the same as no credential: it set `Extension(Option<AuthExtension>::None)` and let the handler decide what to do. For `GET /api/v1/repositories` and other optional-auth routes the handler returns a public-only list with HTTP 200 in the anonymous case, which meant a deactivated user's API token continued to receive 200 responses for up to `API_TOKEN_CACHE_TTL_SECS` (5 min) after `is_active=false`, masking the off-boarding signal. The cache invalidation from #931 worked correctly (the cache hit IS rejected, and on cache miss the SQL `WHERE is_active = true` filter rejects too), but the middleware swallowed the resulting error. `try_resolve_auth_outcome` now returns a tri-state `AuthOutcome { Resolved, NoCredential, InvalidCredential }`, and both `optional_auth_middleware` and `repo_visibility_middleware` short-circuit with 401 when an explicitly-presented credential failed to validate (and no `?ticket=` fallback resolves). The legacy `try_resolve_auth` helper continues to flatten Invalid into None for back-compat with the guest_access guard and other call sites that need the Option-shape. The guest_access guard's long-lived `AuthService` is also now registered for global cache flush so its cache participates in the #931 invalidation registry (defense-in-depth). Adds three integration tests in `optional_auth_deactivation_tests.rs` that fail on `main` and pass on this branch, and three new unit tests pinning the tri-state outcome. Release-gate `auth-user-deactivation-revokes-tokens / Deactivated user's API token is rejected` (run 26344757642) now passes deterministically.
- **Incus/LXC URL builders now emit prefix-correct download paths and Location headers** (closes #1320). Follow-up to #1272/#1318. `build_download_url` and `build_upload_location` in `backend/src/api/handlers/incus.rs` hardcoded `/incus/` even when the request arrived under `/lxc/`, so the SimpleStreams catalog served by `GET /lxc/<key>/streams/v1/images.json` referenced `/incus/<key>/...` download paths and `POST /lxc/<key>/.../uploads` returned a `Location: /incus/...` header. Clients that follow absolute URLs blindly were unaffected, but clients doing prefix-scoped auth or relative-resumption against `/lxc/` saw cross-prefix redirects. The fix threads the mount prefix through both builders. Handlers (`streams_images`, `start_chunked_upload`, `upload_chunk`) extract the prefix from the request's `OriginalUri` via a new `mount_prefix_from_uri` helper that returns `/lxc` for `/lxc/...` requests and falls back to `/incus` for everything else (preserving the historical default for reverse-proxy rewrites). Eight unit tests pin the behaviour: both prefixes round-trip through both builders, the helper rejects substring matches (e.g. a repo key named `lxc-images` under `/incus/`), and a combined assertion fails loudly if either builder ever leaks `/incus/` under an `/lxc/` request.
- **`lxc`-format repositories now respond on `/lxc/*` instead of returning 404** (closes #1272). Repository creation accepted `format: lxc` and the rest of the stack already aliased `lxc` to the Incus handler (the `RepositoryFormat::Lxc` enum variant, the `formats::get_handler_for_format` dispatch, the `resolve_incus_repo` resolver that explicitly accepts both `incus` and `lxc`, and the on-disk `incus/<repo-id>/...` storage key prefix are all shared), but `create_router` only mounted `handlers::incus::router()` under `/incus`. Result: a repo created with `format: lxc` 404'd on every `/lxc/<key>/streams/v1/index.json`, `PUT /lxc/<key>/images/...`, and chunked-upload request, while the identical request against an `incus`-format repo at `/incus/<key>/...` returned 200. The fix nests the same `IncusHandler` router under `/lxc` as well, matching the dispatch table's existing two-label intent. Note: the SimpleStreams index served via `/lxc/` currently emits absolute `/incus/...` download URLs because `build_download_url` and `build_upload_location` hardcode the `/incus/` prefix; clients that follow absolute URLs blindly are unaffected, clients doing prefix-based auth or relative resolution against `/lxc/` get redirected to `/incus/`. Two source-level meta-tests pin the alias so a future refactor cannot silently drop the `/lxc` nest. Making the URL builders prefix-aware (or collapsing the `Lxc` enum variant into `Incus` outright, since they share every implementation detail) is tracked as a follow-up.
- **CocoaPods podspec JSON now preserves every field uploaded by the publisher** (closes #1286). `GET /cocoapods/{repo}/Specs/{name}/{version}/{name}.podspec.json` previously returned a stripped podspec because `PodSpec` was deserialized into a struct with only `name`, `version`, `summary`, `homepage`, `license`, `authors`, `source`, `platforms`, and `dependencies` named; every other field in the uploaded JSON (`vendored_frameworks`, `xcconfig`, `preserve_paths`, `requires_arc`, `documentation_url`, `screenshots`, `description`, `source_files`, `frameworks`, `swift_version`, `resource_bundles`, `subspecs`, ...) was silently dropped by serde during the publish-then-serve round-trip. The CocoaPods client could not link binary frameworks against a pod served by Artifact Keeper because `vendored_frameworks` and `xcconfig` never reached `pod install`. `PodSpec` now carries a `#[serde(flatten)] extra: HashMap<String, serde_json::Value>` catch-all so the served JSON is a faithful round-trip of what was uploaded. Two regression tests pin the behaviour: `test_podspec_preserves_unknown_fields_round_trip` at the format layer and `test_extract_podspec_from_archive_preserves_linker_fields` at the handler layer, both built around the exact payload from the issue report.
- **Scanner archive extraction no longer depends on host `tar`/`unzip` binaries** (closes #1243, follow-up to #722). `ScanWorkspace::extract_archive` previously shelled out to `tar xzf` and `unzip` to extract scan inputs. The Alpine variant of the backend container image (`docker/Dockerfile.backend.alpine`) does not install `tar` or `unzip`, so npm `.tgz` and other archive scans silently failed at the `Command::new("tar")` call, the workspace fell through to scanning the raw archive bytes, and Trivy returned zero findings. Extraction is now in-process via the `tar`, `flate2`, and `zip` crates (already direct deps), runs on `spawn_blocking` to avoid stalling the tokio runtime on large archives, and benefits every deployment variant (slim Debian, Alpine, distroless) without per-image package list changes. The supported extension set is unchanged (`.tar.gz`, `.tgz`, `.crate`, `.gem`, `.zip`, `.whl`, `.jar`, `.war`, `.ear`, `.nupkg`, `.egg`). Five unit tests cover the npm tgz happy path, the `.crate` aliasing, jar/zip extraction, the unknown-extension no-op, and corrupt-archive error reporting.
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

- **Dependency-Track is now opt-in in `docker-compose.yml`** (#1432). The bundled `dependency-track-apiserver` and `dtrack-init` services moved behind a new `dtrack` Compose profile, and `DEPENDENCY_TRACK_ENABLED` on the backend now defaults to `false`. With a fresh `docker compose up` the stack no longer pulls in the Dependency-Track Java apiserver, which was the dominant source of idle CPU and memory in the default deployment (DT held ~4 GiB of RAM, ran a continuous NVD mirror, and drove the shared Postgres to 60%+ CPU even with no inbound traffic). Operators who want SBOM analysis opt in with `docker compose --profile dtrack up` and set `DEPENDENCY_TRACK_ENABLED=true` in their `.env`. To also run the upstream DT UI add `--profile dtrack-ui`. Existing deployments that explicitly set `DEPENDENCY_TRACK_ENABLED=true` continue to work; only the default changes.
- **`/readyz` no longer returns 503 when only the default admin password is unchanged** (#889). Previously, `setup_required = true` drove the readiness gate to "not ready", which made Kubernetes mark the pod NotReady and eventually restart it. The restart killed any `kubectl exec` session the operator was using to change the password, so they could never complete setup and the pod stayed in a restart loop. Now `/readyz` returns 200 OK once the database is reachable and migrations have run, even if setup is still required. The `setup_complete` field remains in the JSON body as informational; its `status` value changed from `healthy`/`unhealthy` to `complete`/`incomplete` so the value no longer implies the field is gating the response code. A `tracing::warn!` is emitted once at process startup when `setup_required` is true so log-based alerting (which previously relied on the 503 signal) can still page on the condition. The `setup` middleware that gates mutating API endpoints until setup completes is unchanged.
- **Webhooks v2 wire contract finalized** (#919). The webhook delivery wire format is now `X-ArtifactKeeper-Signature: t=<unix_secs>,v1=<hex_hmac_sha256>` over `<unix_secs>.<raw_body>`, replacing the placeholder `X-Webhook-Signature: hmac-signature` literal that shipped in v1.1.9. New headers on every delivery (test endpoint, retry path, manual redeliver): `X-ArtifactKeeper-Delivery` (UUID, idempotency key), `X-ArtifactKeeper-Event` (event type), `X-ArtifactKeeper-Event-Version` (pinned schema version, currently `2026-04-01`), and `X-ArtifactKeeper-Retry-Attempt` on retries. During the 24h secret-rotation overlap window the signature header carries two `v1=` tokens, current first, so receivers using either secret validate. The retry schedule moves from 5 attempts capped at 4h to 12 jittered attempts capped near 24h (30s, 1m, 2m, 5m, 10m, 30m, 1h, 2h, 4h, 8h, 16h, 24h, +/- 20% jitter). Webhooks that exhaust the retry budget are auto-disabled with a `disabled_reason` set, and `ak_webhook_dead_letter_total{event}` is incremented. Per-webhook event payload pinning is exposed via the new `event_schema_version` field on POST/GET/LIST `/api/v1/webhooks` (existing webhooks default to `2026-04-01`; unsupported versions return HTTP 400). Legacy `X-Webhook-*` headers continue to be emitted alongside the new headers for one release so existing receivers keep working; they will be removed in v1.3.0. See https://artifactkeeper.com/docs/advanced/webhooks for the wire contract reference and Python/Node/Go receiver samples.
- **`scan_findings.affected_component` is now the bare package name** (#903, PR #1150, closes #1159). The field previously carried the parenthetical target alongside the name (`'body-parser (package-lock.json)'`); the target now lives on its own column at `scan_packages.source_target`, and `affected_component` is the package name alone (`'body-parser'`). The split makes `affected_component` usable as a join key against `scan_packages` and the SBOM CycloneDX/SPDX output, and removes the format ambiguity that prevented per-component dedupe across scan sources. The official Web, iOS, and Android SDKs render `affected_component` as a bare string with no parenthetical parsing, so no client-side migration is required; downstream integrations that built custom string matchers on the old format should switch to reading `source_target` from the joined `scan_packages` row instead of splitting `affected_component` on `' ('`.

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

## [1.2.0-rc.2] - 2026-05-23

Second release candidate for v1.2.0. Folds in ~40 PRs merged since rc.1, covering smoke-E2E CI breakage, the v1.1.9 -> v1.2.0 migration repair path, scanner archive extraction, format-handler bugs across Maven, PyPI, OCI, NuGet, Debian, Hex, Incus/LXC, CocoaPods, and several auth scope-enforcement fixes uncovered during the release-gate audit.

### Sponsors

Thank you to our sponsors for keeping Artifact Keeper development moving.

- [@dragonpaw](https://github.com/dragonpaw) (Ash A.)
- [@injectedfusion](https://github.com/injectedfusion) (Gabriel Rodriguez)

[Become a sponsor](https://github.com/sponsors/artifact-keeper) to support the project and get your name listed here.

### Thank You

Community contributors who shipped fixes in this release candidate:

- [@ThaSami](https://github.com/ThaSami) for the reverse-path functional index that makes suffix LIKE queries indexable (#1285), the migration session timeout fix (#1269), the MigrationService column-name corrections (#1268), PyPI virtual member union on `simple/<project>/` (#1267), the non-admin admin-scope escalation block (#1261), and the `/users` router split so non-admins can self-manage tokens (#1258)
- [@dragonpaw](https://github.com/dragonpaw) for the Incus server-wide `STORAGE_PATH` staging fix (#1297) and runtime-agnostic admin-password retrieval docs (#1271)
- [@danatri](https://github.com/danatri) for the JFrog 7.38.10 cache-artifact migration reliability fixes (#1295)
- [@lesaux](https://github.com/lesaux) for the generic-proxy streaming fix (#1294)
- [@joonhwan](https://github.com/joonhwan) for trailing-slash acceptance on NuGet push plus the packages index population (#1289)
- [@axellpadilla](https://github.com/axellpadilla) for refetching stale PyPI proxy-cache hits instead of returning 500 (#1283)
- [@junsung-cho](https://github.com/junsung-cho) for switching Dependency-Track API-key creation to PUT (#1270)
- [@D13410N3](https://github.com/D13410N3) for real OpenPGP signatures on Debian repository metadata (#1236)
- [@JojoMee](https://github.com/JojoMee) for the docker-compose file updates (#1231)

### Security

- **Non-admins can no longer grant admin-class scopes on token issuance** (#1261). The token-issuance path accepted any scope string the caller asked for without checking that the caller themselves held the scope they were granting, so a non-admin with a valid session could mint a personal access token carrying `admin` or `*` and chain into full admin. Token issuance now refuses any scope the caller does not already hold, with admin-class scopes (`admin`, `*`, write-on-system) gated explicitly. Existing tokens are not invalidated by this change; rotation is recommended on any token whose origin cannot be audited.
- **`/users` router split so non-admin self-service paths no longer share admin middleware** (closes #1257, #1258). The router previously mounted both admin user-management endpoints and self-service endpoints (`/users/me/tokens`, `/users/me/password`) under the same admin-only middleware tree, which forced every self-service request through the admin gate and returned 403 for legitimate users. The router is now split into an `/admin/users` subtree for admin-managed operations and a `/users` subtree for self-service, each with the correct middleware. No protocol change; the previously-broken self-service paths now work as documented.

### Fixed

- **Smoke E2E virtual repo creation now supplies `member_repos`** (closes #1353, #1354). The smoke E2E suite created virtual repos without `member_repos`, which #1281 then started rejecting at create time with HTTP 400. The smoke suite now passes the required `member_repos` array, restoring green CI on the release gate.
- **v1.1.9 -> v1.2.0 upgrade no longer aborts with `VersionMismatch(73)`** (closes #1277, #1335). Customers upgrading from v1.1.9 to v1.2.0-rc.1 hit a hard startup failure because the migration runner detected checksum drift between the on-disk `073_account_lockout.sql` and the version-73 row recorded in `_sqlx_migrations` from the legacy duplicate-073 window. The pre-migration repair step introduced in #1138 now also covers the v1.1.9-shipped checksum, so affected installs upgrade cleanly without operator intervention. See `backend/src/migration_repair.rs` for the exhaustive list of accepted prior checksums.
- **Remaining buffered proxy fetches now stream** (closes #1215, #1334). A subset of proxy-fetch paths still buffered upstream responses fully before relaying to the client, defeating the streaming refactor that landed earlier in the v1.2.0 cycle. Those paths now stream end-to-end, capping per-request memory at the configured buffer size regardless of upstream artifact size.
- **Grype-matched components included in `scan_packages` inventory** (closes #1273, #1333). Grype's component matches were recorded against `scan_findings` but never written to `scan_packages`, so the SBOM inventory view and `affected_component` -> `scan_packages` join surface showed empty package lists for Grype-only scans. Grype-matched components are now upserted into `scan_packages` alongside Trivy's, keyed by `(package_name, package_version, package_type)` with `source_target` populated from the scan input path.
- **Scanner archive extraction uses the `tar` crate, not host `tar`** (closes #1243, #1330). Builds on the #722 refactor: the npm `.tgz` extraction path still shelled out to `Command::new("tar")`, so Alpine-based images (which do not install `tar`) silently fell through to scanning raw archive bytes. Extraction is now fully in-process via the `tar` crate on `spawn_blocking`, matching the path other archive formats already took.
- **Generic proxy streaming** (#1294). Generic-format proxy fetches now stream upstream responses through to the client instead of buffering. Aligns the generic handler with the streaming guarantees other format handlers already provide.
- **Dependency-Track project name uses the artifact name** (closes #1276, #1324). The DT project record was created with the repository key as its name, which collapsed every artifact in a repo onto one DT project and made findings ambiguous. The DT project name is now the artifact name; existing one-per-repo projects continue to work, new uploads create one project per artifact.
- **Dependency-Track API-key creation uses PUT** (#1270). DT 4.13 changed the API-key creation endpoint from POST to PUT, so AK was returning 405 from the DT integration setup flow. The handler now issues PUT, matching the current DT API.
- **Maven virtual local-member match honors `groupId`** (closes #1287, #1323). The virtual-repo download-side shadowing guard for Maven matched only on `artifactId`, so a local member's `com.example:utils` blocked an upstream `org.other:utils` even though the coordinates differ. The match now uses the full coordinates (`groupId:artifactId`), restoring the upstream fetch for non-shadowing requests.
- **Multipart upload honors the custom artifact path** (closes #1237, #1322). Multipart `POST /repositories/{key}/artifacts` ignored the optional `path` field and always wrote to `<repo>/<filename>`, so operators using path-prefixed layouts (Maven-style `com/example/...`, generic `releases/2026/...`) had to PUT a second time to move the file. Multipart now respects `path` end-to-end, matching the single-PUT upload behavior.
- **CocoaPods served podspec preserves every uploaded field** (closes #1286, #1321). The serve path round-tripped podspec JSON through a struct with only a fixed set of named fields, dropping `vendored_frameworks`, `xcconfig`, `requires_arc`, `swift_version`, `resource_bundles`, `subspecs`, and ~30 other linker-affecting fields. `PodSpec` now carries a `#[serde(flatten)] extra` catch-all so the served JSON is a faithful round-trip of the upload.
- **`lxc`-format repositories respond on `/lxc/*`** (closes #1272, #1318). Repositories created with `format: lxc` 404'd on every request because `create_router` only mounted the Incus handler under `/incus`. The same `IncusHandler` router is now nested under `/lxc` as well, matching the `Lxc -> Incus` aliasing the rest of the stack already used.
- **Image scanner emits bare package name** (closes #1311, #1312). The image-scanner code path emitted `affected_component` carrying the parenthetical target alongside the package name, contradicting #903 / #1150 which already established the bare-name convention everywhere else. The image scanner now matches, completing the rollout of #1159.
- **Incus uses server-wide `STORAGE_PATH` for staging** (#1297). The Incus handler resolved its staging directory from `repo.storage_path`, which on filesystem deployments with per-repo storage paths pointed at a directory the handler did not own. Staging now uses the server-wide `STORAGE_PATH` like every other handler, fixing publish on filesystem backends with custom per-repo storage.
- **JFrog 7.38.10 cache-artifact migration reliability** (#1295). The Artifactory 7.38.10 migrator's cache-artifact phase mis-handled responses that lacked an explicit `Content-Length`, causing intermittent migration failures. The phase now reads the response body to completion before recording the migrated artifact.
- **NuGet push accepts trailing slash and populates packages index** (#1289). `PUT /nuget/{repo}/v3/registration5-semver1/` (with the trailing slash) returned 404 because the route was registered without the slash, and successful uploads did not refresh the `/v3/index.json` packages list. Both are fixed.
- **PyPI refetches stale proxy-cache hits instead of returning 500** (#1283). When the proxy-cache had a stale entry for a PyPI project, the handler returned 500 instead of refetching upstream. The handler now treats stale entries as cache misses, refetches, and stores the fresh response.
- **PyPI virtual members union on `simple/<project>/`** (#1267, #1230). Virtual PyPI repos previously returned only the first member's simple index for a given project; the handler now unions entries across all non-Remote members (Remote members fall back to the existing remote-fetch path).
- **Functional `reverse(path)` index on `artifacts`** (closes #1266, #1285). Suffix-match queries (`WHERE path LIKE '%/Cargo.toml'`) were not sargable against the existing `path` btree, so they fell back to a sequential scan on installs with many artifacts. A new `idx_artifacts_reverse_path ON artifacts (reverse(path))` lets the planner answer suffix LIKEs as a prefix-match against the reversed text. Build cost is a single index pass at migration time; runtime cost is the existing planner choice.
- **Migration session timeouts** (#1269). `sqlx migrate run` ran with the cluster's default `statement_timeout` and `lock_timeout`, which on installs with tuned-low defaults (5s) aborted long-running schema migrations partway through. The migration session now sets `statement_timeout=0` and `lock_timeout=0` for the duration of the migration run, restoring the previous "migrations are not subject to OLTP timeouts" behavior.
- **MigrationService column names and NOT NULL columns** (#1268). Two recently-added migrations referenced columns that did not match the live schema (a leftover from a rename mid-PR) and omitted NOT NULL columns that the migration runner inserts into. Both are corrected; affected migrations were never executed against any production install because the runner rejected them at parse time.
- **Repair sync fast-path on replica-safe credential check** (#1248 follow-up, #1265). The sync `is_token_invalidated` fast-path inside `is_token_invalidated_replica_safe` collided with the `fetch_credential_change_watermark` DB cache TTL on fresh non-admin users, returning 401 on every request after the first within the 5-second cache window. The sync fast-path is removed from the replica-safe entry point; the existing DB cache provides the same acceleration without the conflation. Adds the `two_sequential_admin_requests_with_fresh_jwt_both_return_403` regression test.
- **Forward client `Accept` header to upstream on OCI manifest pulls** (#1256). The OCI manifest-pull proxy stripped the client's `Accept` header before relaying upstream, so upstreams that content-negotiate on manifest media type (OCI vs Docker v2 vs Docker v2.1) returned the wrong manifest, breaking `docker pull` against some Docker Hub images.
- **Persist `sha1`/`md5` on upload and index for checksum lookup** (#1254). Per-upload `sha1` and `md5` were computed but only written to OpenSearch as metadata; the database row only carried `sha256`. Search-by-checksum on `sha1` or `md5` returned no results even when the artifact was indexed. Both checksums are now persisted on `artifacts` and indexed for lookup parity with `sha256`.
- **Pin Grype DB auto-update and drop `-q`** (#1252). The Grype invocation passed `-q` and let Grype auto-update its vulnerability DB at scan time, which on offline / network-restricted installs aborted every scan with a DB-download error and on online installs masked the error behind the `-q` quiet flag. Auto-update is now pinned (`db.auto-update: false`) so the operator-curated DB is the source of truth, and `-q` is removed so errors surface in scan output.
- **Self-service password change mounted under `/auth`, not `/admin`** (#1250). `POST /api/v1/users/me/password` was mounted under the admin router, so a non-admin user could not change their own password through the documented self-service path. The endpoint now lives under `/auth` where the rest of the self-service auth surface is mounted.
- **Debian repository metadata uses real OpenPGP signatures** (#1236). The Debian handler emitted `Release.gpg` and `InRelease` carrying placeholder ASCII-armored blocks instead of real detached OpenPGP signatures over the `Release` file, so `apt update` aborted with `BADSIG` against any repository with `Signed-By` configured (the documented setup). The handler now signs `Release` with the repository's configured signing key, producing valid `Release.gpg` and inline-signed `InRelease`.
- **Apply rustfmt to unblock v1.2.0-rc.2** (closes #1337, #1339). Mechanical `cargo fmt` pass over the tree to satisfy the rustfmt check gate after a batch of merges that landed slightly mis-formatted.
- **Test-email endpoint accepts `recipient` alias** (closes #1332, #1338). `POST /api/v1/admin/smtp/test` rejected requests carrying `recipient` (the field name the web UI and docs advertised) because the handler only accepted `to`. The handler now accepts both, with `recipient` as the canonical name going forward.
- **Reject virtual repo create with no members at 400** (closes #1279, #1281). `POST /api/v1/repositories` accepted virtual repos with no members at create time, then 404'd every subsequent fetch. The handler now returns `400 Bad Request` at create time, naming the expected `member_repos: [{repo_key, priority}, ...]` shape.
- **Stop inserting proxy-cached items into `artifacts`** (closes #1278, #1280). `ProxyService::cache_artifact` previously wrote a row to `artifacts` for every proxy-cached item, which on filesystem backends produced a doubled-prefix storage key that 500'd on every subsequent read. The proxy hot path already serves cache hits via the storage layer directly, so the `artifacts` insert is removed.

### Changed

- **Server-side Docker tag aggregation** (closes #1193, #1336). The Docker tag listing page in the web UI previously fetched every manifest individually and aggregated tags client-side, which on repos with thousands of tags ran into request fan-out limits. Tag aggregation now happens on the backend via a single `GET /repositories/{key}/docker/tags?aggregate=true` endpoint that returns tag lists pre-grouped by digest. The legacy per-manifest path remains for clients that still need it.
- **`AK_SSRF_ALLOW_PRIVATE_CIDRS` env var** (closes #1224, #1325). The SSRF guard rejected outbound requests to RFC1918 / loopback / link-local addresses unconditionally, which broke proxy-fetch against on-prem upstreams (a local Nexus / JFrog inside the same VPC). The new `AK_SSRF_ALLOW_PRIVATE_CIDRS` env var accepts a comma-separated allowlist of CIDR ranges that bypass the private-address check. The default is the empty list, preserving the previous behavior; operators must opt in explicitly.
- **Enforce PR-issue link via GitHub Actions** (#1310). New repo workflow requires every PR to link a tracking issue via the `Closes #<n>` / `Fixes #<n>` footer. Aligns with the linked-issue rule already documented for releases.
- **Docs note `affected_component` format change** (closes #1159, #1223). Adds an upgrade-notes entry making the v1.2.0 `affected_component` -> bare-name change explicit in the CHANGELOG and pointing integrations at `scan_packages.source_target`.
- **Update docker-compose files** (#1231). Refreshes the bundled `docker-compose.local-dev.yml` and `docker-compose.demo.yml` to match the v1.2.0 image set, service names, and required env vars; clears two stale env keys that no longer have any effect.
- **Runtime-agnostic admin password retrieval docs** (#1271). The first-time-setup docs previously assumed Docker as the runtime when telling operators how to retrieve the generated admin password; the new copy works for Docker, Podman, and Kubernetes deployments without rewording.

### Dependencies

- **Bump `wasmtime-wasi` to 36.0.10** (closes #1351, #1352). Picks up the upstream RUSTSEC-2026-0149 fix.
- **Bump `ubi9/ubi` from 9.7 to 9.8** (#1293).
- **Bump `ubi9/ubi-micro` from 9.7 to 9.8** (#1291).
- **Bump `github/codeql-action` from 4.35.4 to 4.35.5** (#1292).
- **Bump `actions/stale` from 10.2.0 to 10.3.0** (#1290).
- **Bump `totp-rs` from 5.7.0 to 5.7.1** (#1227).
- **Bump `mimalloc` from 0.1.48 to 0.1.51** (#1226).
- **Bump `anchore/grype` from v0.111.1 to v0.112.0** (#1082).

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
