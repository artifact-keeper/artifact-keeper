# Implementation Plan — #1609 Cross-Replica Single-Flight (Layer 3)

**Issue:** #1609 (Core Invariant ②) · **Epic:** #1607 · **Seam:** #1631 · **Also closes:** #1606
**Design source:** `docs/audits/design-clean-room-singleflight-cache-2026-06-04.md` (Subsystem 1)
**Status:** ready to execute in a Postgres-equipped dev loop. Cannot be behaviourally verified without PG + the multi-process harness, so it is intentionally **not** built blind.

---

## 0. Where we are (ground truth, verified against source)

The single-flight seam is ~65% built. **Layers 1 and 2 are merged and wired; only Layer 3 is missing.**

| Layer | What | State | Evidence |
|---|---|---|---|
| 1 | Buffered in-process single-flight behind `Coordinator` trait | **DONE** | `proxy_hydration.rs:122` (trait), `:227` (`BufferedCoordinator`), wired at `proxy_service.rs:1789` (field) + call site `proxy_service.rs:1999` |
| 2 | Streaming broadcast fan-out | **DONE** | `Coordinator::coordinate_stream` `proxy_hydration.rs:201`; impl `:301-635`; call site `proxy_service.rs:2173` |
| 3 | **Cross-replica advisory-lock coordination** | **MISSING** | only `// #1631 layer 3 seam` comments at `proxy_hydration.rs:107-116, 197-199, 224-225`; `proxy_service.rs:1787` |

The advisory-lock idiom is already proven in-repo: `pg_try_advisory_xact_lock` at `scan_result_service.rs:379`, blocking `pg_advisory_xact_lock` at `repository_service.rs:856` and `main.rs:1402`.

The multi-process acceptance harness already exists and is **intentionally red on `main`** (it reproduces #1606): `scripts/concurrency/run-singleflight-race.sh` (#1627). It flips **green** when this work lands — that is the gate.

---

## 1. The one critical design correction

**Do NOT make `ProxyService` generic over the coordinator.** The triage suggestion (`ProxyService<C: Coordinator>`) has an enormous blast radius: `ProxyService` is named concretely in `SharedState` (`api/mod.rs:113 — Option<Arc<ProxyService>>`) and in **~40 handler signatures** (helm, conda, pypi, conan, terraform, and ~15 sites in `proxy_helpers.rs`). Going generic forces `SharedState` — the axum app state — generic too, cascading through every handler and extractor. Unacceptable.

**Use an enum instead.** The `Coordinator` trait is not object-safe (generic-closure methods), but a concrete enum that `impl`s it dispatches fine and is monomorphised at the two existing call sites:

```rust
// proxy_hydration.rs
pub enum CoordinatorImpl {
    Buffered(BufferedCoordinator),
    Advisory(AdvisoryCoordinator),
}

impl Coordinator for CoordinatorImpl {
    async fn coordinate<...>(&self, lease_key, check, produce, timeout_error) -> Result<T, E> {
        match self {
            Self::Buffered(c) => c.coordinate(lease_key, check, produce, timeout_error).await,
            Self::Advisory(c) => c.coordinate(lease_key, check, produce, timeout_error).await,
        }
    }
    async fn coordinate_stream<...>(&self, lease_key, open_leader) -> Result<Option<StreamHandle>> {
        match self { Self::Buffered(c) => c.coordinate_stream(..).await, Self::Advisory(c) => c.coordinate_stream(..).await }
    }
}
```

`ProxyService.coordinator` changes type `BufferedCoordinator → CoordinatorImpl`. The two call sites (`self.coordinator.coordinate(...)`, `.coordinate_stream(...)`) are unchanged. **Blast radius: `proxy_hydration.rs`, `proxy_service.rs`, `main.rs` only.** Tests keep using `CoordinatorImpl::Buffered(..)`; production wires `CoordinatorImpl::Advisory(..)`.

---

## 2. Why "just hold an advisory lock during the download" is wrong

A `pg_try_advisory_xact_lock` is transaction-scoped. Holding it across `produce` (the full upstream download — minutes for a multi-GB layer) pins a Postgres connection per in-flight cold miss and risks idle-in-transaction timeouts → **connection-pool exhaustion under concurrent cold misses.** The design doc's **two-transaction + `cache_fill` lease** pattern (§1.2–1.5) exists precisely to avoid this. We implement that, not the naive version.

---

## 3. Data model — `cache_fill` migration

New migration `backend/migrations/NNN_cache_fill.sql` (check `ls backend/migrations/ | tail` for the next number):

```sql
CREATE TABLE cache_fill (
    repo_id        UUID NOT NULL,          -- AK uses UUID repo ids, not BIGINT
    path           TEXT NOT NULL,
    lock_key       BIGINT NOT NULL,        -- fill_lock_key(repo_id, path)
    owner_replica  TEXT NOT NULL,          -- hostname/pod, for debugging
    state          TEXT NOT NULL,          -- 'fetching' | 'failed'
    heartbeat_at   TIMESTAMPTZ NOT NULL,
    lease_expires  TIMESTAMPTZ NOT NULL,   -- heartbeat_at + lease_ttl
    started_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (repo_id, path)
);
CREATE INDEX cache_fill_lease ON cache_fill (lease_expires);
```

> **AK delta vs the design doc:** AK already content-addresses proxy bodies under `proxy-cache/<key>/__content__` with a `__cache_meta__.json` sidecar (`proxy_service.rs`), and the filesystem/S3/GCS backends already do their own multipart/atomic writes. So the design doc's separate `blob`/`remote_cache_entry` tables and explicit `object_store.create_multipart()`/`upload_id` are **already handled by the existing cache layer** — `cache_fill` only needs the lease/heartbeat columns (drop `upload_id` from the design's schema; the staging key is the existing proxy-cache temp path). The finalize step (Tx B) is the existing sidecar+content write.

---

## 4. `fill_lock_key`

Add to `proxy_hydration.rs` (or a small `fill_lock.rs`). Stable across replicas/restarts; **no `Math.random`/time** — pure hash:

```rust
fn fill_lock_key(repo_id: Uuid, path: &str) -> i64 {
    use std::hash::{Hash, Hasher};
    let mut h = siphasher::sip::SipHasher13::new_with_keys(LOCK_K0, LOCK_K1);
    repo_id.as_bytes().hash(&mut h);
    path.hash(&mut h);
    h.finish() as i64
}
```

`siphasher` (fixed seeds) — confirm it is already in `Cargo.lock` (sqlx pulls it transitively) before adding; otherwise add the crate. The key is computed at the `ProxyService` call site (which has `repo_id` + `path`) and threaded to the coordinator alongside the existing string `lease_key`, rather than re-parsed out of the string key.

---

## 5. `AdvisoryCoordinator` — the Layer-3 impl

A struct holding `db: PgPool` + an inner `BufferedCoordinator`. It overrides `coordinate` and `coordinate_stream`, gating the **leader-election step** with the two-tx + lease protocol (design §1.3–1.5):

**`coordinate` (buffered path):**
1. Fast path is already the caller's `check()` — run it first; on `Some`, return (no lock).
2. **Tx A (short):** `pg_try_advisory_xact_lock(lock_key)`.
   - **Acquired → winner:** upsert `cache_fill(state='fetching', owner=me, heartbeat=now, lease=now+30s)`; `COMMIT` (lock auto-releases, lease live). Spawn a **heartbeat task** (bump `heartbeat_at`/`lease_expires` every ~10s). Run the inner `BufferedCoordinator::coordinate` (in-process single-flight + `produce`, which performs the existing cache write). **Tx B (short):** re-acquire lock, `DELETE FROM cache_fill`, `COMMIT` (= linearisation point). Stop heartbeat.
   - **Not acquired → loser:** enter the bounded **loser poll** (design §1.4): loop `check()` cache → if `cache_fill` row gone, re-enter (may become winner) → if `lease_expires < now`, `try_reclaim` (CAS the row, become winner) → on deadline, **passthrough** (caller's existing uncoordinated fetch path, `proxy_service.rs:2138 fetch_artifact_streaming_uncoordinated`), no caching. Backoff 50ms→500ms with jitter.

**`coordinate_stream`:** same election gate; the inner streaming fan-out is unchanged. The winner is the streaming leader (existing tee). Losers poll for the warm cache, else subscribe to the in-process broadcast if same-replica, else passthrough.

**Crash safety (I3):** the advisory lock is released at end of Tx A, so it can never wedge. A dead winner's `cache_fill` lease expires → a loser reclaims. Belt-and-suspenders: a **fill-janitor** scheduler task sweeps `cache_fill WHERE lease_expires < now - grace` (wire into `scheduler_service.rs::spawn_all`, same pattern as the #1654 sweep).

**Negative cache (404):** already implemented — `write_negative_cache` at `proxy_service.rs:2063`. Keep using it; the winner writes it and `DELETE`s `cache_fill`.

---

## 6. Wiring

`main.rs:611` — change
`ProxyService::new(db_pool.clone(), Arc::new(storage_svc))`
→ a `new_with_coordinator(.., CoordinatorImpl::Advisory(AdvisoryCoordinator::new(db_pool.clone())))`.
Keep `ProxyService::new` defaulting to `CoordinatorImpl::Buffered(BufferedCoordinator::new())` so every existing test (`proxy_service.rs:5279`, `:7873`, `test_db_helpers.rs:432`) is unchanged.

Add the janitor spawn in `scheduler_service.rs::spawn_all` (hourly or 5-min tick).

---

## 7. Test matrix

| Tier | Test | Needs |
|---|---|---|
| **Unit** | `fill_lock_key` stable + collision-free for sample tuples; loser-poll state machine (drive `check`/`cache_fill`/`lease` mocks → assert winner/loser/reclaim/passthrough transitions); `CoordinatorImpl::Buffered` behaves identically to today (regression) | none |
| **Integration (Tier 2, real PG)** | two `AdvisoryCoordinator`s on one pool contend `pg_try_advisory_xact_lock(same key)` → exactly one winner; `cache_fill` lease-expiry → reclaim; janitor orphan sweep; pattern mirrors `scan_result_service.rs:379` | PG @ `localhost:30432` |
| **Multi-replica (the gate)** | `scripts/concurrency/run-singleflight-race.sh` (#1627): ≥3 replicas + slow mock upstream, 200 concurrent GETs of one uncached object → **exactly one** `upstream_fetch_total`, all clients get bytes whose SHA-256 == published digest, one cached blob. Kill winner mid-stream → a loser reclaims, fill completes. 404 → one upstream miss, rest `negative_hit`. **Must flip from red→green.** | docker compose + PG |
| **Stress** | adapt `scripts/stress/` for concurrent pulls; amplification ratio ≈ 1 | compose |

---

## 8. PR breakdown (shippable increments, each green before the next)

1. **PR 1 — enum seam (zero behaviour change).** Introduce `CoordinatorImpl`, switch `ProxyService.coordinator` to it (still only the `Buffered` variant), add `new_with_coordinator`. Pure refactor; existing tests prove no behaviour change. *Small, low-risk, unblocks the rest.*
2. **PR 2 — `cache_fill` migration + `fill_lock_key` + lease helpers.** Migration, pure hash, pure lease/reclaim SQL helpers with Tier-2 PG tests. No behaviour change to the live path yet.
3. **PR 3 — `AdvisoryCoordinator` (buffered path) + winner/loser/reclaim + heartbeat + janitor.** Wire `CoordinatorImpl::Advisory` in `main.rs`. Unit + Tier-2 tests. *This is the core.*
4. **PR 4 — `coordinate_stream` advisory gating.** Extend to the streaming path.
5. **PR 5 — flip the gate.** Make `run-singleflight-race.sh` a required CI check (it now passes); wire the observability counters (§2.6: `single_flight_total{role}`, amplification ratio).

Closes #1609 and #1606; advances #1607 and #1631. PRs 1–2 are landable immediately in a PG dev loop; PR 3 is the keystone.

---

## 9. Open decisions for the maintainer

- **Lease/heartbeat constants:** 30s lease / 10s heartbeat / grace (design suggests these; confirm against pod scheduling).
- **Passthrough budget:** fixed (e.g. 5s) vs `Content-Length`-scaled (design §1.4 prefers size-hinted). Recommend size-hinted, capped.
- **`siphasher` dependency:** confirm transitive availability vs. adding it explicitly.
- **Failure ceiling:** per-path `consecutive_failures` to avoid thundering a persistently-down upstream (design §1.5) — include in PR 3 or defer.
