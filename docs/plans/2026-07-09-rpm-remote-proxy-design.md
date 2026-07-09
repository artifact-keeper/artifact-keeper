# Design: RPM/YUM Remote Mirroring & Promotion (re-baselined)

**Date:** 2026-07-09
**Status:** Approved (design, re-baselined against verified code) — Phase 1 ready for planning
**Author:** Brandon Geraci (with Claude Code)

> **Re-baseline note.** An earlier revision of this doc described a codebase that did not
> match reality (it claimed `ProxyService` had zero callers, that `rpm.rs` bypassed the storage
> abstraction via `FilesystemStorage`, that the migration tip was 048, and that a `sync_tasks`
> table did not exist). A parallel accuracy + security + compliance review caught this. Every
> "current state" claim below has now been **verified by direct file reads** (citations inline).
> The headline correction: **Remote RPM pull-through already works** — the substrate this feature
> was going to "build" is shipped. The real work is (a) a handful of RPM-specific proxy gaps and
> (b) the genuinely net-new Pulp-grade sync/versioning/promotion layer, built on existing infra.

---

## 1. Motivation

Artifact Keeper can already **serve** hosted RPMs and **proxy** Remote RPM repos (pull-through).
It cannot **mirror at Pulp grade**: sync upstream metadata into the DB for search, version the
mirror, take point-in-time snapshots, schedule syncs, or promote mirrored content through
staging→release with the existing scan gates. This effort adds those, reusing what exists.

Non-goals: mirroring non-RPM formats via this machinery (RPM-only tables in v1); being a Pulp
drop-in. Deliberate divergences in §5.

---

## 2. Verified current state (what already works)

All citations verified by direct read on branch `feat/rpm-remote-proxy` (migration tip **148**).

| Capability | Status | Evidence |
|---|---|---|
| Remote RPM **repodata** pull-through | **Shipped** | `rpm.rs:118` `try_proxy_repodata` → `proxy_helpers::proxy_fetch_capped` (buffered, capped) for Remote repos. |
| Remote RPM **package** pull-through | **Shipped** | `rpm.rs:747` `download_package` falls back to `proxy_helpers::try_remote_or_virtual_download` on local miss. |
| **Streaming** (no full-body buffering) | **Shipped** | `proxy_helpers::proxy_fetch_streaming*` (`:538`) → `ProxyService::fetch_artifact_streaming`; `rpm.rs` `build_rpm_package_response` streams via `Body::from_stream(get_stream(...))` (#1608 "Core Invariant ①"). Storage via `state.storage_for_repo(...).get_stream(...)` — **no `FilesystemStorage` bypass exists.** |
| Central **cache freshness** classifier | **Shipped** | `cache_classifier.rs` (Core Invariant ④, #1611): `classify(format, path) -> Mutability{Immutable\|Mutable{ttl}}`, pure `evaluate()`, `Freshness{Fresh,Stale,NegativeHit}`. Constants: `MUTABLE_DEFAULT_TTL_SECS=300`, `NEGATIVE_CACHE_TTL_SECS=45`, `STALE_IF_ERROR_GRACE_SECS=3600` (RFC 5861 stale-if-error already implemented). |
| Cache **integrity on read** | **Shipped** | `ProxyService` stores + compares `checksum_sha256` on cache reads (`proxy_service.rs:835-852`) — detects on-disk corruption. |
| **SSRF** URL validation | **Shipped (partial)** | `validation.rs:147` `validate_outbound_url` / `:319` `is_blocked_url` block loopback/link-local/private/metadata (169.254.169.254); wired into repo create/update (`repository_service.rs:92-109`). `http_client.rs:59` `base_client_builder` + `:129` `ssrf_redirect_policy` re-validate every redirect hop. **Gap: no connect-time resolved-IP check (DNS rebinding) — see §6.** |
| Secrets **encryption at rest** | **Shipped** | `encryption.rs` (AES-256-GCM `CredentialEncryption`); precedent in `signing_service.rs`, `webhook_secret_crypto.rs`. Reuse for entitlement certs (P6). |
| **Promotion** (Staging→release) + scan gates | **Shipped** | Release target = `repository_config` key `release_repository_id` (`promotion.rs:337-358`). Authz: `ensure_promotion_authorized` + admin-mintable `promote:artifacts` scope + `require_promotion_tenant_access` (`promotion.rs:432-564`). Scan gates: Grype/Dependency-Track (`grype_scanner.rs`, `dependency_track_service.rs`; migs 054–056 promotion_approvals/gates/rules, 121 block-unscanned, 143 repo_scan_failed). |
| Cross-replica **singleton job lease** | **Shipped** | `cluster_work.rs:249` `try_acquire_scheduler_lease` + `scheduler_leases` table (mig 147). Reuse for scheduled sync (P4) and cross-replica single-flight. |
| Background **sync worker** pattern | **Shipped (different domain)** | `sync_worker.rs` + `sync_tasks` table (mig 008) — **peer-mesh/edge replication** (`edge_node_id`/`artifact_id`), 10 callers. Pattern is reusable; **the table name is taken (§6).** |
| Audit + telemetry infra | **Shipped** | `audit_log` (mig 005: user_id/action/resource_type/ip); `download_statistics` (mig 004: user_id/ip/user_agent). |

**Bottom line:** Remote RPM pull-through, streaming, cache classification, stale-if-error,
SSRF URL-string validation, secrets encryption, promotion, and cross-replica leasing all exist.

---

## 3. The real gaps

### RPM-proxy gaps (small, mostly Phase 1)
1. **No `Rpm` arm in `cache_classifier::classify`** — RPM paths hit the conservative 300s mutable
   default, so content-addressed `repodata/<sha256>-*.xml.gz`, `.rpm`, `.drpm`, `.zck` are
   revalidated every 5 min instead of cached immutably. Add an arm: content-addressed/package
   paths → `Immutable`; `repodata/repomd.xml`(+`.asc`) → `Mutable` (300s default is safe).
2. **No HTTP `Range`/`206` passthrough** — verified absent in `proxy_service.rs` (only a
   `validate_upstream_status` test references 206). Needed for zchunk chunk-deltas + `.rpm` resume.
3. **No mirrorlist/metalink rejection** at repo creation — a mirrorlist/metalink `upstream_url`
   must be rejected (proxy one concrete baseurl only).
4. **No cache quota enforcement** — `Repository.quota_bytes` exists but is not enforced against
   proxy-cache writes (unbounded growth risk — §6, security High).
5. **DNS-rebinding connect-time gap** — see §6 (security High); affects the already-shipped proxy.

### Pulp-grade gaps (net-new; build on existing infra)
6. **Metadata sync into DB** for search/versioning (`RpmSyncService`, parse primary.xml).
7. **Versions / snapshots / publications** (locally generated + AK-signed metadata).
8. **Promotion of mirrored content** through the existing `release_repository_id` + scan-gate path.
9. **GPG-verify-before-ingest/re-sign** — precondition for P2/P3 (§6, security High).

---

## 4. Target architecture

A `Remote` RPM repository gains three escalating modes (config in a new `remote_configs` row):
**passthrough** (today's behavior, hardened), **on_demand** (metadata in DB, packages lazy),
**immediate** (full mirror). Versioning/snapshots/promotion sit above on_demand/immediate.
Mirrored blobs stay content-addressed in `StorageService`, so snapshots/promotion are
metadata-only.

### New data model (migrations start at **149**; verify with `ls backend/migrations | sort -V | tail`)

| Table | Purpose | Phase |
|---|---|---|
| `remote_configs` | 1:1 typed remote config: `mode`, TTL overrides, `sync_schedule`, **encrypted** `client_cert`/`client_key`/`ca_cert` (via `encryption.rs`), `proxy_url`, `trusted_gpg_key`, `last_synced_at`. | P2 (cert cols P6) |
| `rpm_packages` | Global deduped content units: NEVRA, `checksum_sha256` UNIQUE, `location_href`, raw `<package>` snippet, `storage_key` (NULL=not fetched). | P2 |
| `repository_versions` (+ `_packages`) | Monotonic point-in-time membership. | P3 |
| `repo_metadata_files` | Opaque carry-through of non-primary repomd `<data>` (filelists/other/updateinfo/modules/comps). | P3 |
| `publications` | Locally generated + AK-signed repomd/metadata for one version. | P3 |
| **`rpm_remote_sync_tasks`** | Mirror sync jobs. **Renamed** to avoid colliding with the existing peer-mesh `sync_tasks` (mig 008). | P2 |
| `repositories.active_publication_id` (ALTER) | Distribution pointer; repoint = atomic promote/rollback. | P3 |

### Services (all extend existing, except two new)
- `cache_classifier::classify` — **add `Rpm` arm** (P1).
- `ProxyService` / `proxy_helpers` — **add Range/206 passthrough** and quota-aware cache writes (P1); reuse existing streaming + classifier + stale-if-error unchanged.
- `http_client` — **add connect-time resolved-IP validation** (DNS-rebinding fix) to `base_client_builder` (P1).
- `RpmSyncService` (**new**, P2) — fetch repomd, **verify `.asc` against `trusted_gpg_key`**, stream-parse primary.xml (with decompression cap), upsert `rpm_packages`, create a version.
- `RpmPublishService` (**new**, P3) — generate + sign metadata via `SigningService`.
- Scheduled sync (P4) — reuse `cluster_work::try_acquire_scheduler_lease` (not a new lock).
- Promotion (P5) — extend `promotion.rs` to promote a **version by reference** into
  `release_repository_id`, reusing `ensure_promotion_authorized`/tenant checks **and the existing
  scan gates** (mirrored content must not bypass Grype/Dependency-Track).

### 4a. Confirmed target workflow — Rocky 10, curate + AK-sign

Operator confirmed (2026-07-09): mirror **BaseOS / AppStream / CRB / Extras / EPEL** — all
**public** EL10 rebuild repos, so **no entitlement certs and P6 is not required for this
deployment**. Workflow: **mirror → scan/approve (may hold back individual packages) → promote →
serve internally, DNF-valid.**

Decisions this locks in:

- **Curate + AK-sign metadata.** Because approval can hold back individual packages, a promoted repo
  may differ from upstream, so AK **regenerates** repomd/primary/filelists/other from the approved
  set and signs with **AK's** key (served at the existing `/rpm/{repo}/repodata/repomd.xml.key`).
  `repo_gpgcheck` then trusts AK's key; **package-level `gpgcheck` still validates each RPM against
  Rocky's key** (unchanged). Clients import AK's repo key once.
- **This overrides §5's "opaque carry-through" YAGNI for package-enumerating metadata.** Curation
  *is* package filtering, which is incompatible with carrying `filelists`/`other` opaquely (dnf
  cross-checks filelists against primary by pkgid). P2/P3 must **regenerate primary + filelists +
  other** from the package set. `comps` (groups) and `updateinfo` (advisories) may still be carried
  opaquely — an advisory referencing a held-back package simply won't resolve, which is acceptable.
- **`immediate` (full) mirror is this track's default mode.** "Serve internally" must not depend on
  reaching upstream at request time, and a full local mirror lets AK regenerate filelists/other
  **from the stored RPM headers by reusing the existing hosted-repo metadata generation**
  (`formats/rpm.rs` + the `filelists_xml_gz`/`primary_xml_gz` handlers) instead of writing a
  from-scratch filelists parser. This **pulls P4's `immediate` mode forward** in this track and
  makes P3 publish reuse hosted generation rather than opaque carry-through.
- **Scale note.** A full EL10 BaseOS+AppStream+CRB+Extras+EPEL mirror is large (many GB, tens of
  thousands of packages); the scan/approve step is a correspondingly large Grype/Dependency-Track
  workload. Budget disk + scan time; prefer scanning at sync time so promotion gates read cached
  results.

Net effect on phases: this workflow completes at **P3 + P5**, with **P4 `immediate` mode brought in
early**; **P1 remains the substrate**; **P6 is dropped** for this deployment.

---

## 5. Reuse-vs-rebuild & deliberate divergences

**Reuse:** `cache_classifier` (add arm, don't parallel it), `proxy_helpers` streaming, `http_client`
SSRF-aware client (no bespoke client permitted), `encryption.rs` for certs, promotion's
`release_repository_id`/authz/scan-gates, `cluster_work` leases. **Rebuild:** none of the proxy
stack. **Rename:** mirror sync table → `rpm_remote_sync_tasks`.

**YAGNI v1 (skip):** `streamed` policy; bit-for-bit republish; sqlite `_db`, drpm, zchunk
*generation*; mirrorlist/metalink serving; shared Remotes; hosted-repo versioning; Distribution as a
separate entity (use `active_publication_id`). `comps`/`updateinfo`/`modules` carried opaquely.

**Overridden by §4a (curate track):** primary/filelists/other are **regenerated** (not opaque),
because curation requires package filtering; reuse the existing hosted-repo generation from local
RPM headers under `immediate` mode.

---

## 6. Security & compliance requirements (from parallel review — binding)

These are design requirements, not optional hardening. Phase assignment noted.

| # | Requirement | Severity | Phase |
|---|---|---|---|
| S1 | **DNS-rebinding:** validate the *resolved IP* at connect time (custom `reqwest` resolver/connector re-applying `is_blocked_url` logic), for initial request + every redirect. The Range/streaming change must route **only** through `base_client_builder()` — no new client. Add a test asserting connect-time IP checks. | High | **P1** |
| S2 | **Cache quota:** enforce `Repository.quota_bytes` on proxy-cache writes (at minimum: stop caching + alert past quota, keep serving). Don't defer disk-exhaustion control to P4 GC. | High | **P1** |
| S3 | **Content-addressed integrity:** when a fetched path embeds a hex checksum (createrepo unique-filename convention), verify SHA-256 of the body before caching it "immutable". | Medium | **P1** |
| S4 | **GPG-verify-before-ingest:** `RpmSyncService` must verify `repomd.xml.asc` against a configured `trusted_gpg_key` before ingesting/parsing; without it, refuse publishable/re-signed mode or label the publication "unverified upstream". Prevents P3 AK-re-signing from laundering unverified content. | High | P2/P3 |
| S5 | **Authz:** new `POST /sync`, `remote_configs` writes, and P6 cert upload need a global capability gate (admin or admin-mintable scope, e.g. `manage:remote-config`/`trigger:sync`) **plus** a non-admin-bypassing per-repo tenant check — mirroring `ensure_promotion_authorized` + `require_promotion_tenant_access`. | Medium | P2/P6 |
| S6 | **Scan gates for mirrored promotion:** mirrored content promoted to a release repo must pass the same Grype/Dependency-Track gates as uploaded artifacts (decide sync-time vs promotion-time scanning; do not silently bypass). | High | P5 |
| S7 | **Audit logging:** remote create/edit, sync trigger, cert upload, and mirrored-content promotion write `audit_log` entries (actor/action/resource). | Medium | P2/P5/P6 |
| S8 | **Cert handling:** reuse `encryption.rs` AES-256-GCM (no new scheme); redacting newtype so `{:?}` can't leak key material; test that logs never contain raw cert bytes. | Medium | P6 |
| S9 | **Negative-cache tuning:** reuse the existing 45s `NEGATIVE_CACHE_TTL_SECS` convention (the earlier draft's 1800s was wrong); exempt `repomd.xml`(+`.asc`) from negative caching (already revalidated). | Medium | P1 |
| S10 | **Decompression cap:** P2 primary.xml.gz parsing must cap decompressed size / use a bounded decompressor. | Medium | P2 |
| S11 | **Single-flight across replicas:** in-process coalescing only dedupes per process; for multi-replica, consider the `scheduler_leases`/advisory-lock pattern, or document the bounded N-fetch tradeoff. | Medium | P1 (doc) / P4 |
| S12 | **Secrets hygiene:** forbid credentials embedded in `upstream_url`/`proxy_url`; size-cap + redact any upstream response data persisted to `rpm_remote_sync_tasks.error`/`stats`. | Medium | P2/P6 |
| C1 | **RHEL redistribution (P6):** explicit operator-vs-software responsibility statement + on-screen notice at entitlement-cert config; gate P6 on legal-counsel review, not engineering. | Medium | P6 |
| C2 | **Trust-model doc (P3):** document that once a publication exists, `repo_gpgcheck` validates AK's key (operators must distribute it); package-level signatures remain the vendor's; package integrity enforced via checksum vs upstream primary.xml. | Medium | P3 |

**P1 verdict from review:** safe to proceed **provided S1, S2, S3, S9 (and S11 as a documented
note) are in the Phase-1 spec.** S4/S6/C1/C2 are the load-bearing items for later phases.

---

## 7. Revised phased roadmap

- **P1 — RPM proxy hardening (thin slice).** `Rpm` arm in `cache_classifier`; Range/206 passthrough
  through `base_client_builder`; mirrorlist/metalink rejection at repo create; **S1 DNS-rebind
  connect-time check, S2 quota enforcement, S3 content-addressed checksum verify, S9 negative-cache
  reuse**. No new tables.
  **Done =** `dnf install` against a Remote repo mirroring Rocky 9 works with `repo_gpgcheck=1`;
  content-addressed files served immutably from cache (no needless revalidation); a rebinding test
  and a quota test pass; existing hosted + other-format proxy behavior unchanged.
- **P2 — Sync + search (on_demand).** `remote_configs`, `rpm_packages`, `rpm_remote_sync_tasks`,
  `RpmSyncService` (manual `POST /sync`), package search; **S4 GPG-verify, S5 authz, S7 audit, S10
  decompression cap, S12 hygiene.** Done = sync EPEL → ~20k searchable packages; dnf unaffected.
- **P3 — Versions, publications, snapshots.** `repository_versions`(+members), `repo_metadata_files`,
  `publications`, `RpmPublishService` + signing, `active_publication_id`, `/@{version}/` serving;
  **C2 trust-model doc.** Done = pin `/rpm/epel/@N/`, identical resolvable content later.
- **P4 — Scheduled sync, immediate policy, GC.** Reuse `try_acquire_scheduler_lease`; `immediate`
  bulk download; version retention; orphan-blob GC; offline mode. Done = nightly mirror; GC safe.
- **P5 — Promote mirrored versions.** Extend promotion to promote a version by reference into
  `release_repository_id`; **S6 scan gates apply**; rollback = repoint `active_publication_id`.
- **P6 — RHEL / authed upstreams.** Encrypted certs via `encryption.rs`; **S8 handling, C1 legal
  gate.** Done = sync RHEL 9 via entitlement certs, encrypted, never logged.

**Three hardest problems (revised):** (1) DNS-rebind-safe streaming client without regressing the
shipped SSRF controls; (2) sync consistency when upstream republishes repomd mid-sync + GPG-verify;
(3) GC of shared content-addressed blobs vs in-flight lazy fetches and pinned snapshots.

---

## 8. Phase 1 — implementation-ready specification

### 8.1 Objective
Harden the **existing** Remote RPM passthrough: correct cache classification, add Range support,
reject non-baseurl upstreams, and close the S1/S2/S3/S9 review findings. Public HTTPS upstreams
only; no auth, no DB metadata, no versioning.

### 8.2 Work items
1. **`cache_classifier::classify` — add `Rpm` arm** (pure fn; table-tested for jscpd/coverage):
   - `repodata/repomd.xml`, `repodata/repomd.xml.asc` → `Mutable{300}` (safe default; revalidated).
   - `repodata/<hex>-*` (content-addressed) and `*.rpm`/`*.drpm`/`*.zck` → `Immutable`.
   - Everything else under the repo → conservative `Mutable` default.
2. **Range/206 passthrough** in the proxy fetch path: forward `Range`, relay `206`/`Content-Range`/
   `Accept-Ranges`; do **not** cache partial responses (only full 200s populate cache). Must use
   `base_client_builder()` (S1).
3. **DNS-rebinding connect-time check (S1):** add a custom resolver/connector to
   `base_client_builder` that re-applies `is_blocked_url`-equivalent logic to the **resolved IP**,
   for initial + redirect hops. Test: hostname resolving to 169.254.169.254 is refused at connect.
4. **Quota enforcement (S2):** before a proxy-cache write, check `Repository.quota_bytes`; past
   quota, skip the cache write (still stream to client) and emit a warning/metric.
5. **Content-addressed integrity (S3):** when the path embeds a hex checksum, verify body SHA-256
   before caching immutable; mismatch → serve but refuse to cache (treat as miss).
6. **Mirrorlist/metalink rejection:** in `repository_service` repo create/update validation for
   Remote+RPM, reject an `upstream_url` whose path/query indicates mirrorlist/metalink, with a
   clear error pointing to a concrete baseurl.
7. **Negative-cache (S9):** confirm RPM uses the shared 45s `NEGATIVE_CACHE_TTL_SECS`; exempt
   `repomd.xml`(+`.asc`) from negative caching.

### 8.3 Error handling
Upstream 404 → 404 (+ short negative cache, except repomd). Upstream 5xx/timeout on miss → 502;
existing `STALE_IF_ERROR_GRACE_SECS` stale-if-error path continues to serve a still-held mutable
body. Cache-write failure → still stream to client (existing self-healing). Checksum mismatch → S3.

### 8.4 Testing
- **Unit (pure fns):** `Rpm` classify arm (table test: repomd vs content-addressed vs pkg);
  mirrorlist/metalink rejection; S3 checksum-in-path verification; S2 quota decision.
- **Integration:** Remote RPM repo vs mock upstream — immutable file served from cache without
  revalidation; repomd revalidated; Range → 206 relayed; **S1 rebinding refused at connect**;
  hosted + other-format proxy paths unchanged (regression).
- **E2E** (`scripts/native-tests/`): Remote repo → Rocky 9 BaseOS; `dnf install` with
  `repo_gpgcheck=1`; 2nd install from cache (assert no upstream hit).
- **CI gates (must pass):** `cargo fmt --check`; `cargo clippy --workspace --all-targets -- -D
  warnings`; `cargo test --workspace --lib`; ≥70% coverage on changed lines; ≤3% jscpd duplication.

### 8.5 Out of scope for P1
DB metadata sync, `rpm_packages`, search, versions, publications, snapshots, scheduled sync,
on_demand/immediate modes, promotion, upstream auth/certs, offline-mode toggle, mirrorlist
resolution, non-RPM formats.

### 8.6 Phase 1 risks
Touching `base_client_builder`/the shared fetch path affects **all** formats — regression tests for
maven/pypi/etc. proxy paths are mandatory. The DNS-rebind resolver must not break normal resolution
or add latency. Keep the classifier arm a pure function to satisfy coverage/duplication gates.

---

## 9. Rollout & workflow
- Feature branches + PRs (never push to main); squash-merge after CI; each phase = its own PR with
  its "Done =" met. No Docker builds on cloud. Verify migration numbering before adding (tip 148).
- Before P2/P5/P6 sub-design-docs are written, resolve their binding review items (S4/S6/C1/C2).
