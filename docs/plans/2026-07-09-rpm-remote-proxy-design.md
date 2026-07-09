# Design: RPM/YUM Remote Mirroring & Promotion

**Date:** 2026-07-09
**Status:** Approved (design) — Phase 1 ready for implementation planning
**Author:** Brandon Geraci (with Claude Code)
**Scope:** Add Pulp-grade RPM/YUM mirroring and promotion to Artifact Keeper, delivered as a
sequenced set of independently-shippable phases. This document specifies the **target
architecture**, the **6-phase roadmap**, and **Phase 1** in implementation-ready detail.
Phases 2–6 are specified at roadmap altitude and will each get their own design doc.

---

## 1. Motivation

Artifact Keeper today serves RPMs only as a **hosted** (`Local`) repository: upload, download,
on-demand `repodata` generation (repomd.xml / primary.xml / filelists.xml), and detached GPG
signing. It cannot mirror an upstream OS/vendor repository (Rocky, Alma, EPEL, Fedora, RHEL),
which is the capability Pulp and Artifactory/Nexus provide.

The goal is to let a `Remote` RPM repository **pull-through and/or fully sync** an upstream, make
the mirrored content **searchable and versioned**, support **point-in-time snapshots**, run
**scheduled syncs**, and **promote** mirrored content through staging→release stages.

### Non-goals (this effort)
- Mirroring non-RPM formats via this machinery (RPM-only tables in v1; generalize later if a
  second synced format demands it).
- Being a drop-in Pulp replacement. We deliberately diverge from Pulp where the cost is not
  justified (see §5).

---

## 2. Existing building blocks (reuse inventory)

Verified against the codebase; these are the assets Phase 1+ build on.

| Asset | Location | Role in this design |
|---|---|---|
| `ProxyService` | `backend/src/services/proxy_service.rs` | Generic pull-through: TTL, ETag revalidation, SHA-256 verification, storage-backed cache (`proxy-cache/{repo_key}/{path}` + `.__metadata__.json`), conditional HEAD. **Currently has zero callers.** Reuse + extend. |
| `RepositoryType` enum | `backend/src/models/repository.rs` | `Local`, `Remote` (scaffolded/unwired), `Virtual`, `Staging`. `Remote` + `upstream_url` are the entry point. |
| `Repository` fields | same | Already has `upstream_url`, `promotion_target_id`, `promotion_policy_id`, `quota_bytes`, `storage_backend`, `storage_path`. |
| RPM handlers | `backend/src/api/handlers/rpm.rs` | Routes at `/rpm/{repo_key}/...`. **`download_package` reads the local `artifacts` table + `FilesystemStorage::new(...)` directly (lines ~536, ~678) — a storage-abstraction bypass that Phase 1 must fix.** |
| RPM metadata structs | `backend/src/formats/rpm.rs` | repomd.xml / primary.xml generation structs. Reused by publish (P3). |
| `SigningService` | `backend/src/services/signing_service.rs` | Detached `.asc` signing already shipped for hosted repos. Reused for publish (P3). |
| `StorageService` | `backend/src/services/storage_service.rs` | fs/S3/GCS/Azure abstraction; `ProxyService` writes here. Content-addressed keys give free dedup. |
| Promotion | `backend/src/api/handlers/promotion.rs`, `PromotionPolicyService` | `Staging`→`Local` copy-based promotion with policy gates + history. Extended (not rebuilt) in P5. |
| Scheduler / job worker | `scheduler_service`, `migration_worker.rs` | In-process tick + job-table+worker pattern reused for sync (P2/P4). |

---

## 3. Target architecture (end state)

### 3.1 Modes

A `Remote` RPM repository operates in one of three escalating modes (stored in `remote_configs`,
introduced P2):

| Mode | Metadata | Packages | Introduced |
|---|---|---|---|
| **passthrough** | not stored in DB; byte-exact cache | cached on GET | P1 |
| **on_demand** | synced into DB (searchable) | fetched lazily on first GET, then persisted | P2 |
| **immediate** | synced into DB | all downloaded at sync time | P4 |

Versioning, snapshots, and promotion sit **above** the on_demand/immediate tier. All mirrored
blobs are **content-addressed** in storage (`content/rpm/{sha256[0..2]}/{sha256}.rpm`), so
snapshots and promotion are metadata-only operations (no blob copies).

### 3.2 New data model (target)

Introduced across phases; listed here for the whole picture. Migrations start at `049`.

| Table | Purpose | Phase |
|---|---|---|
| `remote_configs` | 1:1 typed remote config: `mode`, `metadata_ttl_secs`, `negative_ttl_secs`, `sync_schedule`, encrypted `client_cert`/`client_key`/`ca_cert`, `proxy_url`, `last_synced_at`. Not the k/v `repository_config` — certs need encryption. | P2 (cert cols P6) |
| `rpm_packages` | Global, deduped content units: NEVRA, `checksum_sha256` (UNIQUE), `size_bytes`, `location_href`, `summary`, raw `<package>` primary.xml snippet, `storage_key` (NULL = not yet fetched). | P2 |
| `repository_versions` | Monotonic point-in-time membership set per repo. | P3 |
| `repository_version_packages` | `(version_id, package_id)` membership rows. | P3 |
| `repo_metadata_files` | Opaque carry-through of non-primary repomd `<data>` entries (filelists/other/updateinfo/modules/comps): `data_type`, `checksum`, `open_checksum`, `storage_key`, `repomd_attrs` jsonb. | P3 |
| `publications` | Self-consistent locally generated + signed metadata for one version: `repomd_xml`, `repomd_asc`. | P3 |
| `sync_tasks` | Sync job rows (follows `migration_worker` pattern): `state`, timings, `error`, `stats` jsonb. | P2 |
| `repositories.active_publication_id` (ALTER) | The "distribution pointer". Repointing it = atomic promote/rollback. | P3 |

### 3.3 New/changed services (target)

| Service | Status | Role |
|---|---|---|
| `ProxyService` | Extend | Streaming tee (upstream→client + cache), HTTP Range passthrough, negative cache, per-path TTL classes, single-flight dedup. |
| `RpmSyncService` | New (P2) | Fetch repomd → stream-parse primary.xml → upsert `rpm_packages` → create `repository_version`; retry if repomd checksum changes mid-sync. |
| `RpmPublishService` | New (P3) | Generate primary.xml from stored snippets, carry opaque metadata refs, build + sign repomd.xml. |
| `PromotionService` / `PromotionPolicyService` | Extend (P5) | Promote a `repository_version` by reference into a target repo; reuse policy gates + history. |
| `scheduler_service` | Extend (P4) | Sync tick: scan `sync_schedule`, enqueue `sync_tasks` under per-repo advisory lock. |
| RPM handlers | Fix + extend (P1+) | Route through `StorageService`; dispatch on `repo_type`. |

### 3.4 Request-path decision tree (Remote RPM repo, end state)
1. `active_publication_id` set → serve locally generated repomd/primary + our `.asc`; `.rpm` from
   `storage_key`, lazy-fetch via ProxyService if NULL.
2. No publication (passthrough) → ProxyService byte-exact passthrough, incl. upstream
   `repomd.xml.asc` and gpgkey (never rewrite bodies).
3. Snapshot URL `/rpm/{repo_key}/@{version}/repodata/...` → serve the pinned publication forever.

---

## 4. Reuse-vs-rebuild decisions

| Decision | Call | Rationale |
|---|---|---|
| Lazy-fetch path | Reuse + extend `ProxyService` | TTL/ETag/SHA-256/cache logic already correct; only lacks streaming/Range/negative-cache. |
| Remote config storage | New `remote_configs` (1:1) | Certs/schedules/TTLs are remote-specific and need encryption; keep `Repository` lean. Pulp's shared many-to-many Remote is YAGNI. |
| Content units | New `rpm_packages` | `artifacts` is per-repo, path-centric, soft-delete — wrong shape for global deduped version-member units. |
| Blob storage | Reuse `StorageService`, content-addressed keys | Already abstracts fs/S3/GCS/Azure; content addressing = free dedup + immutability. |
| Metadata generation | Reuse `formats/rpm.rs` structs + raw-snippet republish | Storing raw `<package>` XML avoids lossless re-serialization bugs. |
| Signing | Reuse `SigningService` | Detached repomd `.asc` already shipped. |
| Promotion | Extend existing | Policy gates, history, endpoints, `promotion_target_id` exist; add a version-by-reference path. |
| Scheduling/jobs | Reuse `scheduler_service` + `migration_worker` pattern | Proven in-process pattern; a Pulp-style task+resource-lock system is overkill. |
| Distribution entity | Rebuild simpler: `active_publication_id` on Repository | Repo key already IS the serving URL in AK; a separate Distribution row adds indirection with no user value. |

---

## 5. Deliberate divergences from Pulp (YAGNI v1)

| Pulp feature | Decision | Why |
|---|---|---|
| `streamed` policy | Skip | `on_demand` covers the use case. |
| `mirror_complete` bit-for-bit | Skip (passthrough approximates) | Byte-exact republish needs upstream signatures we can't re-sign; passthrough already gives byte-exact. |
| Parse filelists/other/updateinfo/modules/comps | Opaque carry-through only | Parsing primary.xml suffices for search/versioning; opaque blobs keep modularity/comps/errata working with zero parsing. **Consequence: no package filtering / sub-repos in v1** (filtered repos desync opaque filelists). |
| sqlite `_db`, drpm/delta, zchunk generation | Skip | createrepo_c 1.0 dropped sqlite by default; dnf works without deltas; upstream `.zck` passes through (Range-aware). |
| Mirrorlist/metalink serving or transparent resolution | Skip | Admin configures one concrete baseurl; validate at config time. |
| Shared Remotes across repos; generic content-plugin framework | Skip | 1:1 config; RPM-only tables. Generalize when a 2nd synced format demands it. |
| Versioning for hosted (`Local`) repos | Skip | Mirror versions solve the stated problem; hosted versioning is a separate feature. |

---

## 6. Phased roadmap

Each phase is independently shippable and demoable.

### P1 — Pull-through (thin vertical slice) — *specified in §7*
Wire `ProxyService` into the Remote RPM path; fix the `StorageService` seam; add streaming tee,
Range passthrough, negative cache, TTL classes.
**Done =** `dnf install` works against AK proxying Rocky 9; 2nd install from cache; upstream
`.asc` byte-exact so `repo_gpgcheck=1` works; hosted RPM repos provably unaffected.

### P2 — Remote config + metadata sync + search (on_demand)
`remote_configs` (cert cols present, unused), `rpm_packages`, `sync_tasks`, `RpmSyncService`
(manual `POST /sync`), package search API; lazy downloads record `storage_key`.
**Done =** sync EPEL → ~20k packages searchable via API in minutes; dnf unaffected.
Risks: stream-parse ~200MB primary.xml; bulk-upsert throughput; repomd changing mid-sync.

### P3 — Versions, publications, snapshots
`repository_versions` + membership, `repo_metadata_files` (opaque carry-through), `publications`,
`RpmPublishService` + GPG signing, `active_publication_id`, snapshot serving at `/@{version}/`.
**Done =** create version N, publish, point dnf at `/rpm/epel/@N/`, identical resolvable content
a month later.
Risks: repomd generation fidelity (dnf is unforgiving about checksum/open-checksum mismatch);
snapshot URL routing vs hosted routes.

### P4 — Scheduled sync, immediate policy, GC
Scheduler tick reading `sync_schedule` under per-repo advisory lock; `immediate` bulk-download
with concurrency + resume; version retention; orphan-blob GC; quota accounting; **offline mode
toggle** (Nexus-style cache-only serving).
**Done =** nightly EPEL full mirror; old versions pruned; GC reclaims orphans without racing
in-flight lazy fetches.
Risks: GC-vs-lazy-fetch race; disk growth; long syncs vs deploy restarts (resumable tasks).

### P5 — Promotion of mirrored versions
Extend promote endpoint/policy: source Staging-or-Remote repo version → target gets new version
with membership copied by reference + auto-publish + re-sign; history records version ids;
rollback = repoint `active_publication_id`.
**Done =** `promote {version: 12}` from `rocky-staging` to `rocky-prod`; clients on the prod URL
atomically see new signed metadata; one-call rollback.
Risks: current policy gates assume source=Staging/target=Local — needs a mirrored-content variant;
per-stage GPG key expectations.

### P6 — RHEL CDN & authenticated upstreams
Wire encrypted `client_cert`/`client_key`/`ca_cert` into ProxyService + sync HTTP client (reqwest
identity); entitlement-cert upload UX; validation ping.
**Done =** sync RHEL 9 BaseOS via entitlement certs; certs stored encrypted, never logged.
Risks: cert/entitlement lifecycle (expiry alerting); Red Hat T&C compliance is the maintainer's
call, not a technical one.

### The three hardest problems in the whole effort
1. **Streaming tee through ProxyService** — feed client + cache simultaneously, honor Range,
   dedupe concurrent misses, without buffering multi-GB rpms. Changes the current `Bytes` return
   type, touching every caller. (Starts in P1.)
2. **Sync consistency at scale** — a `repository_version` must be coherent even when upstream
   republishes `repomd.xml` mid-sync (recheck/retry loop) with transactional bulk membership
   writes that don't lock the serving path. (P2/P3.)
3. **GC of shared content-addressed blobs** — refcounts span repos, versions, snapshots, and
   in-flight lazy fetches; a wrong delete breaks a "permanent" snapshot. (P4.)

---

## 7. Phase 1 — implementation-ready specification

### 7.1 Objective
A `Remote` RPM repository transparently pull-through caches a **public** upstream over HTTPS.
Byte-exact passthrough (including GPG artifacts). No DB metadata, no versioning, no auth.

### 7.2 Components & changes

**A. Request-path dispatch — `backend/src/api/handlers/rpm.rs`**
- In `download_package` (and the `repodata/*` GET handlers), branch on `repo.repo_type`:
  - `Local` → existing DB + storage path, **unchanged** (must be behaviorally invisible).
  - `Remote` → `ProxyService`, proxying the same relative path to
    `{upstream_url}/{path}`.
- For a `Remote` repo, a single catch-all proxy covers **both** packages and `repodata/*`
  uniformly (dnf just issues GETs), including `repomd.xml`, `repomd.xml.asc`, and the
  checksum-named metadata files.

**B. Storage-seam fix**
- The `Remote` path uses `StorageService` (where `ProxyService` writes its cache), not the direct
  `FilesystemStorage::new(&repo.storage_path)` bypass at `rpm.rs:~536/~678`. The `Local` path may
  remain as-is in P1 (scoped change), but the Remote path must not use the bypass.

**C. `ProxyService` extensions — `backend/src/services/proxy_service.rs`**
1. **Streaming tee** — replace the buffer-whole-body `fetch_artifact -> (Bytes, ...)` with a
   streaming response that writes to the cache and streams to the client concurrently. Multi-GB
   rpms must not be fully buffered in memory. (Keep a buffered path only for small metadata if
   simpler, but packages must stream.)
2. **HTTP Range passthrough** — forward `Range` and relay `206 Partial Content` (+ `Content-Range`,
   `Accept-Ranges`). Required for zchunk and interrupted-download resume. Ranged responses are
   **not** cached in P1 (only full 200s populate the cache).
3. **Negative cache** — persist upstream `404`s with `negative_ttl_secs` (default 1800s) to avoid
   hammering upstream on repeated misses.
4. **Single-flight** — coalesce concurrent cache-miss fetches for the same path (in-process lock
   keyed by cache key) to prevent thundering-herd on cold cache.

**D. TTL classes** (classify by request path; P1 stores config in `repository_config` k/v):

| Path pattern | Behavior |
|---|---|
| `repodata/repomd.xml`, `repodata/repomd.xml.asc` | TTL `metadata_ttl_secs` (default **600s**); always revalidate via existing ETag conditional GET. |
| `repodata/<anything-else>` (checksum-named `*.xml.gz`/`.zck`) | Immutable — cache indefinitely. |
| `*.rpm`, `*.drpm` | Immutable — cache indefinitely. |
| upstream 404 | Negative cache, `negative_ttl_secs` (default **1800s**). |

**E. Repo-creation validation — `repository_service`**
- `Remote` + RPM already requires `upstream_url`. Add: reject a `upstream_url` that looks like a
  mirrorlist/metalink endpoint (heuristic: path contains `mirrorlist`/`metalink`, or query has
  `release=`/`repo=` typical of metalink) with a clear error directing the admin to a concrete
  baseurl. Resolving mirrorlist/metalink is explicitly out of scope.

### 7.3 Behavior decisions (Phase 1 defaults)
- **Byte-exact:** never rewrite response bodies. `repomd.xml.asc` and `gpgkey` pass through
  untouched so `repo_gpgcheck=1` / `gpgcheck=1` work against the **upstream's** key.
- **Offline mode:** no dedicated toggle in P1. Cached content is served whenever present; on a
  cache miss with upstream unreachable, return the upstream error. (Toggle arrives P4.)
- **E2E target:** Rocky Linux 9 BaseOS (public, plain HTTPS, no certs).
- **Config location:** TTLs in the existing `repository_config` k/v table; typed `remote_configs`
  arrives in P2.

### 7.4 Error handling
- Upstream `404` → `404` to client (+ negative cache).
- Upstream `5xx`/timeout on cache miss → `502 Bad Gateway` with upstream status in the message; do
  **not** poison the cache.
- Cache write failure → still stream to client (serving the client takes priority over caching);
  log a warning.
- Checksum mismatch on a cached content-addressed file → treat as cache miss, re-fetch.

### 7.5 Testing
- **Unit:** path→TTL-class classification; mirrorlist/metalink rejection heuristic; negative-cache
  expiry; single-flight coalescing.
- **Integration:** `Remote` RPM repo → mock upstream; assert byte-exact passthrough of
  `repomd.xml.asc`; assert immutable files cached and served from cache on 2nd request; assert
  Range request relays `206`; assert `Local` RPM repos are unchanged (regression).
- **E2E** (`scripts/native-tests/`): create a `Remote` repo pointing at Rocky 9 BaseOS; run
  `dnf --disablerepo=* --enablerepo=<ak> install <small pkg>` with `repo_gpgcheck=1`; assert
  success; second install served from cache (assert no upstream hit via proxy logs/metrics).
- Must pass Tier-1 CI: `cargo fmt --check`, `cargo clippy --workspace`, `cargo test --workspace --lib`.

### 7.6 Out of scope for Phase 1 (explicit)
DB metadata sync, `rpm_packages`, search, versioning, publications, snapshots, scheduled sync,
`immediate`/`on_demand` modes, promotion, upstream auth / entitlement certs, offline-mode toggle,
mirrorlist/metalink resolution, non-RPM formats.

### 7.7 Phase 1 risks
- Streaming refactor changes the `ProxyService` return type — audit for future callers and keep the
  change self-contained.
- Memory blowups if streaming is fudged for large rpms (explicit test with a large artifact).
- Route-precedence between the Remote catch-all and existing hosted RPM routes — verify hosted
  repos are untouched.

---

## 8. Rollout & workflow notes
- All work via feature branches + PRs (never push to main); squash-merge after CI.
- No Docker builds on cloud instances; E2E runs locally or in GitHub Actions.
- Each phase ships behind its own PR with the "Done =" criterion demonstrably met.
- **CI merge gates (mandatory, per CLAUDE.md):** `cargo clippy --workspace --all-targets -- -D warnings`,
  unit tests, **≥70% coverage on new/changed lines**, **≤3% duplication (jscpd) on changed files**,
  security audit, CodeQL — all green; no `--admin` bypass. Implication for design: extract testable
  logic (TTL classification, mirrorlist/metalink rejection, negative-cache expiry, single-flight)
  into **pure helper functions** so handler code is coverable, and factor the cache read/write
  patterns into shared helpers to stay under the duplication gate.
- Check migration numbering before adding migrations (`ls backend/migrations/ | tail -5`); target is
  `049+` (current tip is `048`).
