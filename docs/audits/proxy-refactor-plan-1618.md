# Refactor Plan — Abstractions for `ProxyService` + `proxy_helpers.rs` (issue #1618)

**Date:** 2026-06-04 · **Status:** Proposed · **Scope:** `backend/src/services/proxy_service.rs` (6,430 lines), `backend/src/api/handlers/proxy_helpers.rs` (5,094 lines) · **Constraint:** behavior-preserving, incremental, each step independently mergeable · **Foundation for:** #1607 epic (#1608 streaming, #1609 single-flight, #1611 cache correctness) · **Origin:** community discussion #1614 (@Dreamacro)

## 1. Current call graph (the duplication, made explicit)

### 1a. `fetch_artifact*` wrapper chain (proxy_service.rs)

```
fetch_artifact ─────────────► fetch_artifact_with_cache_path(repo, path, path)
fetch_artifact_with_accept ─► fetch_artifact_with_cache_path_and_accept(repo, path, path, accept)
fetch_artifact_with_cache_path ─► fetch_artifact_with_cache_path_and_accept(.., None)
                                              │  (REAL IMPL, lines 759–862)
                                              ▼
   guard: repo_type==Remote                 ── duplicated 5× ──┐
   guard: upstream_url present              ── duplicated 5× ──┤
   cache_key  = cache_storage_key(key,path) ── duplicated 6× ──┤
   metadata_key = cache_metadata_key(...)   ── duplicated 6× ──┤
   get_cached_artifact → coordinate_proxy_hydration{ fetch_from_upstream_with_accept,
                                                      cache_artifact,
                                                      get_stale_cached_artifact }
fetch_artifact_streaming (885–958) ─► SAME guards + SAME key derivation,
   then load_cache_metadata → storage.get_stream | fetch_from_upstream_streaming → tee_upstream_to_cache
fetch_upstream_direct (1007) ──────► SAME guards, build_upstream_url, fetch_from_upstream (no cache)
fetch_upstream_direct_with_link ───► SAME guards, build_upstream_url, fetch_from_upstream (no cache)
check_upstream (962) ──────────────► SAME guards, cache_metadata_key, check_etag_changed
```

The guard block (`repo_type != Remote → Validation`, `upstream_url.ok_or → Config`) and the `(cache_key, metadata_key)` pair derivation are copy-pasted across **six** public methods.

### 1b. `proxy_fetch*` thin wrappers (proxy_helpers.rs) — 8 variants

Every one is `build_remote_repo(repo_id, repo_key, upstream_url)` → call a `ProxyService` method → `.map_err(|e| map_proxy_error(repo_key, path, e))`:

| Wrapper | Delegates to |
|---|---|
| `proxy_fetch` | `fetch_artifact` |
| `proxy_fetch_with_accept` | `fetch_artifact_with_accept` |
| `proxy_fetch_streaming` | `proxy_fetch_streaming_with_disposition` |
| `proxy_fetch_streaming_with_disposition` | `fetch_artifact_streaming` + `build_streaming_response_with_disposition` |
| `proxy_fetch_or_redirect` | `is_cache_fresh` + `try_proxy_cache_redirect` + `proxy_fetch` |
| `proxy_fetch_with_cache_key` | `fetch_artifact_with_cache_path` |
| `proxy_fetch_uncached` | `fetch_upstream_direct` |
| `proxy_fetch_uncached_with_link` | `fetch_upstream_direct_with_link` |

### 1c. Cache key / cache get / invalidate twins

- `cache_storage_key` (`__content__`) and `cache_metadata_key` (`__cache_meta__.json`) differ only by suffix; both call `validate_cache_path` + `check_cache_key_length`, and are **always derived together** at 6+ sites.
- `get_cached_artifact` (1510) vs `get_stale_cached_artifact` (2096): identical load-metadata + storage.get + checksum-verify; they differ **only** by the `Utc::now() > expires_at` early-return.
- `invalidate_cache` (1053) vs `invalidate_cache_by_key` (1070): byte-identical two-`delete` bodies; one takes `&Repository`, the other `&str`.

### 1d. `local_fetch_by_*` family (proxy_helpers.rs)

`local_fetch_by_path`, `local_fetch_by_name_version`, `local_fetch_or_redirect` share one skeleton: `SELECT ... FROM artifacts WHERE <clause> → check_quarantine_row → storage_for_repo_or_500 → storage.get → coordinated_retry_get on NotFound`. They differ only in the WHERE clause and (for `_or_redirect`) a presigned short-circuit before the read. `local_fetch_by_path_suffix` already delegates into `local_fetch_by_path` after resolving the path — the correct pattern to generalize.

## 2. Target abstraction — the five seams

Create a new module tree `backend/src/services/proxy/` and split the monolith:

```
services/proxy/
  mod.rs            // re-exports; ProxyService facade kept as the public type
  cache_key.rs      // seam (d-keys): CacheKeys + derivation/validation
  cache_store.rs    // seam (d): CacheStore trait — read/write/validate/invalidate sidecar+body
  upstream.rs       // seam (a): UpstreamClient — fetch (buffered+stream), auth, OCI token exchange
  persist.rs        // seam (b): post-proxy persistence (cache_artifact, tee_upstream_to_cache)
  local_serve.rs    // seam (c): LocalArtifactFetcher (artifacts table → storage.get) [in proxy_helpers' module]
  response.rs       // seam (e): body→HTTP (buffered/stream/redirect/disposition)
```

### (d-keys) Cache-key seam — `CacheKeys`

```rust
pub(crate) struct CacheKeys { pub content: String, pub metadata: String }

impl CacheKeys {
    pub(crate) fn derive(repo_key: &str, path: &str) -> Result<Self> {
        let trimmed = validate_cache_path(path)?;
        check_cache_key_length(repo_key, trimmed)?;        // worst-suffix bound, unchanged
        Ok(Self {
            content:  format!("proxy-cache/{repo_key}/{trimmed}/__content__"),
            metadata: format!("proxy-cache/{repo_key}/{trimmed}/__cache_meta__.json"),
        })
    }
}
```

Keep `cache_storage_key` as a `pub(crate)` shim (`derive(...).map(|k| k.content)`) so `proxy_fetch_or_redirect` and existing tests stay green. Collapses the 6× pair derivation into one call.

### (d) Cache-store seam — `CacheStore`

Wraps `Arc<StorageService>` and owns the `__cache_meta__.json` lifecycle. Methods: `load_metadata(&CacheKeys)`, `get(&CacheKeys, allow_stale: bool)` — the **one** function replacing `get_cached_artifact` + `get_stale_cached_artifact` (the `allow_stale: bool` from the issue: skip the `expires_at` check, and on stale path skip the ETag fast-path); `write(&CacheKeys, body, CacheMetadataTemplate)` (current `cache_artifact` body, minus the dead `repository_id`/`artifact_path` args, lines 2080–2082); `invalidate(&CacheKeys)` — the single two-`delete` body behind both `invalidate_cache*`; `is_fresh(&CacheKeys)` (current `is_cache_fresh` ETag-revalidation logic). **Preserve exactly** the B6 "transient read error → treat as miss, not 502" branches and the zero-byte guard (#1365) — these are load-bearing.

### (a) Upstream seam — `UpstreamClient`

Owns `http_client` + `token_cache`. Methods: `fetch_buffered(url, repo_id, accept) -> UpstreamResponse` (= `fetch_from_upstream_with_accept`); `fetch_stream(url, repo_id) -> UpstreamStream`; `head_etag_changed(...)`. The 401/Bearer-challenge + `validate_outbound_url` + `obtain_bearer_token` + retry block is duplicated verbatim between the buffered (1645–1692) and streaming (1784–1816) paths — extract a private `exchange_bearer_then<F>(challenge, url, repo_id, build_request)` so both reuse one auth state machine.

### (b) Persistence seam — `CachePersister`

The write-back after a successful upstream fetch. Buffered = `cache_artifact`; streaming = `tee_upstream_to_cache`. Both already share `CacheMetadataTemplate`, `pin_storage_etag`, and the zero-byte guard. Group them so #1608/#1609 add new fetch modes without re-implementing persistence.

### (c) Local-serve seam — `LocalArtifactFetcher` (in `proxy_helpers`/`local_serve.rs`)

```rust
enum LocalLookup<'a> { Path(&'a str), NameVersion(&'a str,&'a str), PathSuffix(&'a str) }

async fn local_fetch(db, state, repo_id, location, lookup: LocalLookup<'_>)
    -> Result<(Bytes, Option<String>), Response>;          // SELECT→quarantine→storage.get→retry
async fn local_fetch_or_redirect(...);                      // same, presigned short-circuit first
```

`local_fetch_by_path/_by_name_version/_by_path_suffix` become one-line shims dispatching on `LocalLookup`. The SQL row→quarantine→storage.get→`coordinated_retry_get` skeleton lives once.

### (e) Response seam — `ProxyResponse`

Centralize body→HTTP. `build_streaming_response_with_disposition` already exists; add a buffered sibling so the hand-rolled `Response::builder()...body(Body::from(content)).unwrap()` blocks (in `proxy_fetch_or_redirect`, `local_fetch_or_redirect`) route through one builder that owns content-type fallback, content-length, content-disposition, and presigned-redirect selection. `map_proxy_error` and `try_presigned_redirect` move here.

## 3. Sequenced steps (each compiles, tests pass, reviewable alone)

Order is lowest-risk-first; later behavioral epics land on the seams the earlier steps create.

| # | Step | Risk | Why first |
|---|---|---|---|
| **S1** | Introduce `CacheKeys::derive`; make `cache_storage_key`/`cache_metadata_key` shims over it. No call-site changes. | trivial | Pure refactor; the 100+ existing `test_cache_*_key*` tests prove equivalence. |
| **S2** | Collapse `get_cached_artifact`/`get_stale_cached_artifact` into one `fn get_cached(.., allow_stale: bool)`; keep both names as `allow_stale=false/true` shims. | low | Self-contained; checksum + B6 branches covered by unit tests. |
| **S3** | Collapse `invalidate_cache`/`invalidate_cache_by_key` onto `invalidate(&CacheKeys)`; `invalidate_cache` builds a `CacheKeys` from `repo.key`. | trivial | Byte-identical bodies. |
| **S4** | Extract the guard block into `fn remote_target(repo) -> Result<(&str /*upstream_url*/)>`; apply to all six methods. | low | Mechanical; covered by existing `Validation`/`Config` error tests. |
| **S5** | `proxy_helpers`: collapse 8 `proxy_fetch*` onto `build_remote_repo` + a `with_proxy_repo(repo_id, key, url, |repo| ...)` closure carrying the `map_proxy_error` mapping. | low | Wrappers are trivial; `map_proxy_error` tests already exist. |
| **S6** | `local_fetch_by_*` → `LocalLookup` dispatch; old names become shims. | low–med | Needs DB; covered by integration tests + `test-npm`/`test-helm` E2E (suffix path). |
| **S7** | Extract `CacheStore` struct wrapping the body/metadata ops from S1–S3; `ProxyService` holds one. | med | Now a real seam, not just shims. |
| **S8** | Extract `UpstreamClient` (incl. shared `exchange_bearer_then`); de-dup the two 401 blocks. | med | OCI token-exchange is the subtle part — gate on `test-docker-proxy`. |
| **S9** | Extract `CachePersister` (`cache_artifact` + `tee_upstream_to_cache`). | med | Sets the seam #1608/#1609 plug into. |
| **S10** | Extract `ProxyResponse`; route buffered builders through it; move `map_proxy_error`/`try_presigned_redirect`. | low–med | Pure output-shaping; redirect tests exist. |
| **S11** | Physically split into `services/proxy/*.rs` modules; `mod.rs` re-exports `ProxyService` so external paths are unchanged. | low | Move-only; no logic change. |

After S1–S11 the two files are an orchestration facade over five named seams. Land S1–S6 first (all "shim" steps, zero behavior risk) to relieve the merge pressure @Dreamacro reported, before the structural S7–S11.

## 4. Where @Dreamacro's fork plugs in

The fork adds **singleflight fan-out stream** and **singleflight buffered get** (buffered for "upstream response needs modification"). On the new seams:

- The repo already has `coordinate_proxy_hydration` (`proxy_hydration.rs`) — a cancellation-safe in-process leader/follower coordinator. The fork's fan-out is the **stream** generalization of this. It belongs in **seam (a/b)**: when the streaming path (`fetch_artifact_streaming`, S9) is a cache miss, wrap the `fetch_from_upstream_streaming → tee_upstream_to_cache` in the singleflight leader; followers subscribe to a `broadcast`-style fan-out of the leader's chunks instead of each opening their own upstream connection. The tee's bounded-mpsc design is compatible.
- The fork's **buffered get** maps to **seam (d)** `CacheStore::get` + **seam (b)** persistence already wrapped in `coordinate_proxy_hydration` (the buffered path does this today at lines 787–861). The fork's value is collapsing the per-waiter re-fetch into one leader fetch + shared buffer — which is exactly #1609.
- **Action:** keep `coordinate_proxy_hydration`'s leader-election + `LeaderLease` Drop semantics as the single coordination primitive; have the fork's fan-out implement a `SingleFlight` trait that both the buffered (`Bytes`) and streaming (`BoxStream`) modes implement, injected into `CachePersister`/`UpstreamClient`. Do **not** reinvent the coordinator — extend it. *(Note: this is the in-process layer; the cross-replica advisory-lock single-flight in #1609 / `design-clean-room-singleflight-cache-2026-06-04.md` layers on top.)*

## 5. Test strategy (behavior preservation)

**Existing coverage to lean on:** 174 unit tests in proxy_service.rs (cache-key derivation incl. length/traversal/collision, TTL/expiry math, ETag staleness, bearer-challenge parse, token-cache hit/expiry/eviction) and 138 in proxy_helpers.rs (`map_proxy_error` status mapping, `build_remote_repo`, `reverse_suffix_for_like`, presigned redirect, streaming-response headers). These are the equivalence oracle for S1–S5 and S10.

**Integration tests** (require Postgres): `oci_virtual_resolution_tests.rs`, `maven_virtual_groupid_shadowing_test.rs`, `virtual_members_atomicity_test.rs`, `oci_chunked_upload_cross_repo_tests.rs` — gate S6 (local fetch) and S8 (OCI auth).

**Native E2E that MUST stay green** (`scripts/native-tests/`): `test-docker-proxy.sh` (OCI token exchange + manifest Accept negotiation — S8), `test-proxy-virtual.sh` (virtual member resolution + TTL — S6/S7), `test-npm.sh`/`test-helm.sh`/`test-maven.sh` (suffix-LIKE local fetch — S6), `test-pypi.sh` (uncached simple-index fetch + cache-path divergence — S5), and the redirect suite (presigned `proxy_fetch_or_redirect`/`is_cache_fresh` fast-path — S2/S7/S10).

**Gaps to fill before merging:**
1. A unit test asserting `get_cached(allow_stale=true)` skips the `expires_at` gate AND the ETag fast-path but still verifies checksum (locks S2).
2. A `CacheStore::write` zero-byte test (buffered #1365 parity with the streaming tee test).
3. A table-driven `LocalLookup` test proving the three WHERE-clause variants produce identical post-lookup behavior (S6).
4. A B6 regression test: transient `storage.get` error on the cached body returns a cache miss (no 502 leak) — pin this before touching `CacheStore`.

Per CLAUDE.md: each step must clear ≥70% changed-line coverage and ≤3% jscpd on changed files — the refactor *helps* the latter since it removes duplication.

## 6. Risks & rollback-friendly ordering

- **OCI token exchange (S8)** is the highest-risk seam: two near-identical 401 blocks with subtle differences (buffered re-adds `Accept` on retry; streaming does not forward `Accept` at all). Preserve that asymmetry exactly — do not "helpfully" unify the Accept handling. Mitigate with `test-docker-proxy` before merge.
- **B6 / 502-leak invariants** (`get_cached_artifact`, `cache_artifact` write-best-effort) and **#1365 zero-byte guard** are correctness-critical and must move verbatim — annotate with the originating issue numbers as they are today.
- **Module split (S11) last:** keeping it last means every prior step is a small in-file diff, trivially revertable.
- **Shim retention:** keep old public/`pub(crate)` fn names as thin shims through at least S1–S10 so no handler call site (28 across `backend/src/api/handlers/`) changes in the same PR as a logic move. Remove shims in a final cleanup PR only after the epic work (#1608/#1609/#1611) has landed on the seams.
- **Rollback unit:** each step is one PR; reverting any single PR restores the prior shim layer.

## Relevant files
- `backend/src/services/proxy_service.rs`
- `backend/src/api/handlers/proxy_helpers.rs`
- `backend/src/services/proxy_hydration.rs` (existing single-flight coordinator — **extend, do not replace**)
- Target new tree: `backend/src/services/proxy/{mod,cache_key,cache_store,upstream,persist,response}.rs`
