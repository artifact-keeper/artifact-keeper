# Artifact Keeper — Backend Design Retrospective

**Date:** 2026-06-04
**Author:** Engineering (retro facilitated via issue-corpus analysis + clean-room comparison)
**Scope:** `artifact-keeper` backend service
**Question asked:** *We designed this backend in January, then accumulated hundreds of issues. Did we get the design wrong, or is it still good? How does it compare to a clean-room design done with no knowledge of our implementation?*

---

## TL;DR

**We did not get the design wrong.** An independent expert, given only the product requirements and no knowledge of our codebase, reconstructs ~85% of Artifact Keeper's architecture (Rust/axum, single PostgreSQL + content-addressed object storage, one format-handler trait, virtual = ordered-first-hit + index-merge, WASM plugins, edge-node = remote-repo-pointed-at-primary). That convergence is the strongest available evidence the original design was sound. **No rewrite is warranted.**

The bug volume concentrated in two places:

1. **Irreducible domain complexity** — per-format native-client compatibility and the virtual × remote/proxy matrix. Every registry vendor struggles here.
2. **Three cross-cutting *disciplines* that were under-specified in January and retrofitted later** — streaming I/O, cross-replica coordination, and blob lifecycle / cache-correctness. These produced recurring, hard-to-reproduce bugs precisely because they were treated as one-off fixes instead of structural invariants.

The recommendation is a focused **Core Invariants Hardening** epic that converts those three disciplines into enforced invariants — not a redesign.

---

## 1. What we set out to build (January 15, 2026)

From the original speckit spec (`specs/001-artifact-registry/{spec,plan,data-model}.md`):

- **Stack:** Rust/Axum + PostgreSQL (metadata) + S3-compatible object storage using a **content-addressed storage (CAS)** pattern; React frontend (later split to `artifact-keeper-web`); a separate edge binary sharing crates.
- **Scope:** 13+ package formats; LDAP/SAML/OIDC SSO; RBAC with repo-level permissions; local/remote/virtual repository kinds; edge nodes (P3); backup/DR (P3); plugin system (P4).
- **Targets:** 99.9% read availability, horizontal scaling for 100–1,000 users, 5 s up/download for 100 MB files.

The original data model already had the right bones: `Repository{local|remote|virtual}`, `VirtualRepoMember.priority`, `Artifact.storage_key` (CAS), soft-delete, and `UNIQUE(repository_id, path)` enforcing immutable versions.

## 2. The bug record — where the pain actually landed

636 issues total (567 closed, 69 open at time of writing; 274 bug-labeled). Categorized by subsystem (categories overlap — one issue can match several):

| Subsystem | Total | Open | Bug-labeled |
|---|---|---|---|
| **Package formats** | 150 | 20 | **75** |
| **Virtual / remote / proxy repos** | 108 | 16 | **55** |
| API / HTTP / routing | 93 | 9 | 50 |
| Auth / SSO / RBAC | 93 | 8 | 31 |
| Security scanning / SBOM | 61 | 4 | 30 |
| Storage / CAS / S3 | 48 | 12 | 18 |
| Database / migrations | 36 | 1 | 20 |
| Search / metadata / indexing | 26 | 4 | 8 |
| UI / Web | 20 | 2 | 9 |
| Webhooks / events | 12 | 0 | 2 |
| Migration (Artifactory/Nexus) | 8 | 0 | 5 |
| Edge / replication / mesh | 7 | 0 | 3 |
| Backup / DR | 1 | 1 | 0 |

Cross-cutting **failure modes** (the more diagnostic lens):

| Failure mode | Total | Bug-labeled |
|---|---|---|
| Data integrity / corruption / truncation | 40 | 20 |
| Caching correctness (stale / shadow / TTL) | 34 | 14 |
| Path normalization | 20 | 7 |
| **Streaming / memory / OOM** | 16 | 3 |
| Error handling / 5xx / panic | 14 | 12 |
| Pagination / N+1 / perf | 8 | 4 |
| Concurrency / races / locking | 6 | 3 |
| Horizontal-scale / multi-replica | 3 | — |

**Reading.** Bugs concentrated in (1) per-format native-client compatibility and (2) the virtual × remote/proxy matrix. The P3/P4 features (edge, backup) generated almost no bugs — partly because they were correctly deprioritized (good YAGNI). Bug creation peaked in May (265 new issues) and is falling (44 in June); 89% of all issues are closed. This is a maturing system, not one thrashing against a bad foundation.

## 3. The clean-room test

A fresh expert agent was given **only the product requirements** (universal registry, 40+ formats with native clients, local/remote/virtual repos, multi-GB artifacts, pluggable storage, SSO/RBAC, SBOM/scanning, horizontal scaling + edge, plugins, Artifactory/Nexus migration) and **no access to our code or design**. It was asked to produce an opinionated architecture.

Independently, it chose:

| Decision | Clean-room | Artifact Keeper | Match |
|---|---|---|---|
| Language/runtime | Rust + axum + tokio | Rust + axum + tokio | ✅ |
| Source of truth | Single PostgreSQL | Single PostgreSQL | ✅ |
| Byte storage | Content-addressed object storage (SHA-256) | CAS object storage | ✅ |
| Format abstraction | One `FormatHandler` trait; quirks in index/merge | Format handlers | ✅ |
| Virtual repos | Ordered first-hit for content + fan-out `merge_indexes` for listings | Same model | ✅ |
| Remote/proxy | Cache-aside, content-addressed | Same | ✅ |
| Plugins | WASM (sandboxed, language-agnostic, hot-load) | WASM plugins | ✅ |
| Edge nodes | A remote repo pointed at the primary | Same idea | ✅ |

**The architecture is independently reproducible.** That answers the headline question: the design was not wrong.

## 4. Where the clean-room design *diverged* — and it maps 1:1 to our bug hotspots

The independent design made three things **first-class invariants up front** that we retrofitted. Each retrofit is a bug cluster.

### ① Streaming as an enforced rule: "no handler ever buffers a whole artifact"

The clean-room design flagged this as a top risk and made it structural ("no handler ever calls `.bytes().await` on an artifact body"; uploads stream → hashing wrapper → multipart; downloads map HTTP Range to storage Range). We did not enforce it, and it shows:

- Scanner buffers the entire artifact in heap → multi-GiB scans OOM the backend.
- `GcsBackend` buffers whole artifacts (no streaming get/put) → multi-GiB uploads/scans OOM the pod.
- OCI streaming upload hits a ~50 GiB S3 object ceiling (#1523).
- Large uploads (incus, OCI) stage to `/tmp` by default → multi-GiB pushes evict the pod on Kubernetes (#1573).
- `ProxyService::list_cached_artifacts` loads every sidecar before paginating — O(N) per listing (#1571).

**16 memory/OOM issues** that would largely not exist if streaming were a structural invariant from day one.

### ② One cluster-wide coordination primitive

The clean-room design insisted all coordination live in PostgreSQL: **advisory-lock single-flight** (auto-released on replica crash), a `SELECT … FOR UPDATE SKIP LOCKED` job queue, and the rule "object-storage write → metadata commit, with the metadata commit as the linearization point." Our single-flight is **per-process**, so across replicas it races and serves partial/truncated files:

- `fetch: cold-cache singleflight (#1355) is per-process — cross-replica races serve partial files / truncated .sha1` (#1606).

We claimed horizontal scaling in the spec but built per-process assumptions into the hot path.

### ③ Blob lifecycle / GC + explicit immutable-vs-mutable cache classification

The clean-room design made GC a named risk (grace-period mark-and-sweep, single-leader via advisory lock, "leak storage before losing data") and made cache TTL a **per-path-pattern property of each format handler**. We have:

- Blob layer garbage collection missing — `oci_blobs` rows and blob objects never reclaimed (#1408).
- OCI upload leaves the final `oci-blobs/<digest>` object orphaned on failure (#1527).
- Deleting a repository with the S3 backend doesn't delete files in S3 (#1551).
- Ghost artifacts (S3 objects with no DB row) require a manual reindex/recover tool (#1570).
- A family of virtual/proxy **cache-correctness** bugs that are exactly "immutable-vs-mutable misclassification": Maven virtual 404s an artifact its remote member serves directly (#1562), PyPI virtual shadows the download for local packages (#1600), Maven virtual doesn't proxy group-level plugin-prefix `maven-metadata.xml` (#1595), Maven remote/virtual checksum requests do a failing DB lookup before proxying upstream (#1599), Maven remote proxy creates empty directories (#1547).

### The risks were predictable

The clean-room design's top predicted risks were **native-client compatibility drift** (our #1 bug category — formats, 75 bugs) and **auth/SSO sprawl** (our 93 auth issues). We hit every predicted hard part.

## 5. Where we are

- **Architecturally healthy.** Core design validated by independent reconstruction. A rewrite would discard a correct foundation.
- **Maturing, not firefighting.** 89% of issues closed; bug creation past its peak. The open backlog is dominated by refinement (hardening, refactors, feature requests, edge-case format/proxy bugs).
- **The remaining open bugs cluster in the same three retrofitted invariants.**

## 6. Recommendations

1. **Promote streaming to an enforced invariant.** Add a review/lint rule and an architectural test: no artifact-path handler may read a full body (`.bytes()` / `get()`). Convert remaining offenders (GCS backend, scanner, `/tmp` staging) to streaming + bounded multipart. *(Closes the OOM class structurally: #1523, #1571, #1573 + scanner/GCS.)*
2. **Replace per-process single-flight with a PostgreSQL advisory-lock single-flight** keyed on `hash(repo_id‖path)`; losers poll object storage with bounded backoff and a proxy-without-cache fallback for large artifacts. Auto-releases on crash; correct across replicas. *(Closes #1606; hardens the whole proxy path.)*
3. **Build a real blob-lifecycle subsystem:** ref-counted mark-and-sweep GC with a grace window, single-leader via advisory lock, dry-run + audit log, and "delete object store only after metadata commit." *(Closes #1408, #1527, #1551, #1570.)*
4. **Formalize immutable-vs-mutable as a per-path-pattern property of each format handler**, with conditional revalidation (ETag/If-None-Match, Last-Modified) on mutable index/metadata docs and short negative-cache TTLs. Root cause behind most virtual/proxy correctness bugs. *(Maven/PyPI virtual family: #1547, #1562, #1595, #1599, #1600.)*
5. **Keep investing in native-client conformance E2E.** It is *why* 567 issues closed — running real `mvn` / `pip` / `docker` / `cargo` against the server is the correct strategy. Extend to object-storage backends (#1529) and the long-tail formats.
6. **Do not rewrite. Do not re-architect.** Treat the three invariants as a focused hardening epic, not a redesign.

## Appendix A — Method

- Issue corpus: `gh issue list --state all --limit 1000` (636 issues), categorized by keyword over titles + labels (subsystem and failure-mode passes). Overlap is expected and noted.
- Original design: extracted from git history at the initial implementation commit (`specs/001-artifact-registry/`).
- Clean-room design: a fresh agent with zero codebase context, given only product requirements, asked for an opinionated architecture and a top-risks prediction.

## Appendix B — Companion design

A detailed, implementation-ready design for invariants ② and ④ (cross-replica single-flight + cache-correctness classification) is in `docs/audits/design-clean-room-singleflight-cache-2026-06-04.md`.
