# Clean-Room Design — Cross-Replica Single-Flight & Cache Correctness

**Date:** 2026-06-04
**Status:** Clean-room proposal (companion to `design-retro-2026-06-04.md`)
**Produced by:** An independent architect agent with **no access to the Artifact Keeper codebase** — given only the problem constraints (Rust/axum/tokio, PostgreSQL as source of truth, content-addressed object storage, stateless replicas). It is a *target* design for invariants ② and ④ of the Core Invariants Hardening epic (#1607 → #1609, #1611), not a description of current code.

> Implementation note: our enum/table names will differ from the sketches below; treat the column sets, state machine, and test plan as the contract, not the identifiers.

---

This document specifies two coupled subsystems for the pull-through (remote/proxy) and virtual repository paths of a stateless, horizontally-scaled artifact registry. Postgres is the single source of truth for metadata; object storage holds content-addressed (SHA-256) bytes. All app replicas are interchangeable and share nothing but Postgres and object storage.

---

## Subsystem 1: Cross-Replica Single-Flight for Cache Fills

### 1.1 Goal & invariants

When `GET <remote-repo>/<path>` arrives for an artifact not yet cached, exactly **one** upstream fetch should occur across the entire cluster, while every concurrent caller still receives a correct, complete response with bounded latency. Invariants:

- **I1 — No torn reads.** A client never receives a truncated or in-progress blob.
- **I2 — Bounded upstream amplification.** N concurrent requests → ~1 upstream fetch (not N), with a deliberate, bounded exception for very large objects.
- **I3 — Crash safety.** A replica dying mid-fill must not wedge the path forever.
- **I4 — Linearizability of "is it cached?".** The metadata commit is the single point at which the artifact becomes visible as cached.

### 1.2 Coordination primitive: Postgres advisory locks

We key a lock on a stable 64-bit hash of `(repo_id, path)`:

```rust
fn fill_lock_key(repo_id: i64, path: &str) -> i64 {
    // SipHash/xxhash of the canonical tuple, reinterpreted as i64.
    // Stable across replicas and process restarts.
    let mut h = SipHasher13::new_with_keys(LOCK_K0, LOCK_K1);
    repo_id.hash(&mut h);
    path.hash(&mut h);
    h.finish() as i64
}
```

**Transaction-level lock (`pg_try_advisory_xact_lock`) is the default.** Justification:

- It auto-releases on `COMMIT`/`ROLLBACK` — no `pg_advisory_unlock` to leak. Combined with a `BEGIN`/`COMMIT` around the fill's metadata write, the lock's lifetime is exactly the critical section.
- **Crash safety (I3) is free:** if the replica's process or TCP connection dies, Postgres rolls back the transaction and releases the lock automatically. No TTL, no janitor needed for the lock itself.

A naive xact lock would force us to hold one DB transaction open for the *entire* upstream download (potentially minutes for a multi-GB layer), pinning a connection and risking idle-in-transaction timeouts. We avoid that with a two-transaction design:

- **Tx A (short, lock-acquire + claim):** `pg_try_advisory_xact_lock(key)`. If acquired, insert/update a `cache_fill` row marking the fill in-progress, then `COMMIT`. The advisory lock releases on commit — but the `cache_fill` row now records ownership with a lease.
- **Long-running download:** happens *outside* any transaction. Liveness is tracked by the `cache_fill` row's heartbeat, not by holding the DB lock.
- **Tx B (short, finalize):** re-acquire the xact lock, write blob + artifact metadata, delete/complete the `cache_fill` row, `COMMIT`.

The advisory lock is held only across the two short transactions, never across the network download. This combines auto-release crash-safety with not pinning connections.

```sql
CREATE TABLE cache_fill (
    repo_id        BIGINT NOT NULL,
    path           TEXT   NOT NULL,
    lock_key       BIGINT NOT NULL,
    owner_replica  TEXT   NOT NULL,      -- hostname/pod for debugging
    upload_id      TEXT,                 -- object-store multipart id (for cleanup)
    state          TEXT   NOT NULL,      -- 'fetching' | 'failed'
    heartbeat_at   TIMESTAMPTZ NOT NULL,
    lease_expires  TIMESTAMPTZ NOT NULL, -- heartbeat_at + lease_ttl
    started_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (repo_id, path)
);
CREATE INDEX cache_fill_lease ON cache_fill (lease_expires);
```

The advisory lock prevents two replicas from racing on Tx A. The `cache_fill` lease (heartbeat + `lease_expires`, e.g. 30s lease, 10s heartbeat) provides liveness signaling for losers and a reclaim path if the winner dies between Tx A and Tx B.

### 1.3 Winner path

```text
fn serve_remote(repo, path) -> Response:
    if let Some(blob) = lookup_cached(repo, path):        # fast path, no lock
        return stream_from_object_store(blob)
    if let Some(neg) = lookup_negative_cache(repo, path): # 404 cached
        return 404

    # Try to become the winner
    tx = begin()
    if not pg_try_advisory_xact_lock(tx, key):
        tx.rollback()
        return loser_path(repo, path)                     # someone else owns it
    upsert cache_fill(state='fetching', owner=me, heartbeat=now, lease=now+30s)
    upload_id = object_store.create_multipart()
    update cache_fill set upload_id = upload_id
    tx.commit()                                           # lock released; lease live

    spawn heartbeat_task(repo, path)                      # bumps heartbeat_at/lease

    resp = upstream.get(path)
    if resp.status == 404: return finalize_negative(repo, path)   # see 1.5
    if resp.status >= 500 or timeout: return abort_fill(...)      # see 1.5

    hasher = Sha256::new()
    for chunk in resp.body_stream():
        hasher.update(chunk)
        object_store.upload_part(upload_id, chunk)        # to staging
        client_sink.write(chunk)                          # TEE to requester
    digest = hasher.finalize()

    object_store.complete_multipart(upload_id)            # now at content-addr key
    tx2 = begin()
    pg_advisory_xact_lock(tx2, key)                       # blocking re-acquire
    insert blob(digest, size, ...) on conflict do nothing # dedupe by digest
    insert artifact(repo, path, digest, fetched_at=now, etag, last_modified, ...)
    delete cache_fill where repo,path
    tx2.commit()                                          # *** LINEARIZATION POINT ***
    client_sink.finish()
```

**Tee semantics.** The winner streams upstream bytes simultaneously to (a) its own HTTP client and (b) the object-store multipart upload, hashing inline. The multipart upload writes to a staging key; only on `complete_multipart` followed by the metadata `COMMIT` does the object become referenceable. **The metadata commit in Tx B is the linearization point (I4):** before it, no replica sees the artifact as cached and any reader takes the loser path; after it, the fast path returns it. Because the staging upload and the digest are computed together, we never publish metadata for bytes that aren't fully present (I1).

If the winner's own client disconnects mid-stream, the fill continues to completion (detached) so the cache still warms — the work is not wasted.

### 1.4 Loser path

Losers must not hammer upstream and must stay latency-bounded.

```text
fn loser_path(repo, path):
    deadline = now + LOSER_WAIT_BUDGET            # e.g. 5s for small, scaled by hint
    backoff = 50ms
    loop:
        if let Some(blob) = lookup_cached(repo, path):    # winner committed
            return stream_from_object_store(blob)
        if let Some(neg) = lookup_negative_cache(...):
            return 404
        fill = lookup_cache_fill(repo, path)
        if fill is None:                          # winner finished or aborted
            return serve_remote(repo, path)       # re-enter; we may become winner
        if fill.lease_expires < now:              # winner died → steal
            return try_reclaim(repo, path)        # CAS the cache_fill, become winner
        if now > deadline:
            return proxy_passthrough(repo, path)  # FALLBACK: stream w/o caching
        sleep(jitter(backoff)); backoff = min(backoff*2, 500ms)
```

**Bounded poll with backoff** keeps losers off upstream while the winner works. The **passthrough fallback** is the key latency guarantee: for a very large artifact (e.g. a 4 GB container layer) where the winner is still streaming past the loser's budget, the loser fetches directly from upstream *without caching*, so its latency tracks upstream bandwidth rather than queueing behind the winner.

**Why a duplicate fetch is safe:** content-addressing makes fills idempotent. If a loser passes through (or a reclaim races), the worst case is two upstream GETs producing identical bytes → identical SHA-256 → the same content-addressed key. The `blob` insert is `ON CONFLICT DO NOTHING`; the `artifact` row points at a digest that's correct regardless of who wrote it. There is no corruption risk from N fetches — only wasted bandwidth, which the single-flight minimizes but does not need to guarantee for correctness.

The passthrough budget should be tuned by a size hint: if upstream advertises `Content-Length` (captured by the winner and stamped onto `cache_fill`, or probed via a cheap `HEAD`), losers extend their wait budget for large objects (caching is more valuable) but cap absolute latency.

### 1.5 Failure handling

- **Winner crashes mid-fetch.** The advisory lock was already released at end of Tx A, so it can't wedge. The `cache_fill` lease expires (no heartbeat). The next loser observing `lease_expires < now` calls `try_reclaim`: in one transaction it re-takes the advisory lock, verifies the lease is still stale, rewrites `cache_fill` with itself as owner (and aborts the dead winner's `upload_id`), and becomes the new winner. A background **fill-janitor** also sweeps `cache_fill WHERE lease_expires < now - grace`, aborting orphaned multipart uploads.
- **Upstream 5xx / timeout.** Winner runs `abort_fill`: abort the multipart upload, delete the `cache_fill` row (Tx), return `502/504` to its client. It does *not* write negative cache (transient). Losers see the row vanish and re-enter; one becomes the new winner and retries upstream (with a small retry ceiling per path to avoid thundering on a persistently-down upstream — track `consecutive_failures` on a small `remote_failure` table or in `cache_fill`).
- **Partial multipart cleanup.** Every `upload_id` lives in `cache_fill`. Cleanup happens in three places: explicit `abort_fill`, `try_reclaim` (aborts the predecessor's upload), and the janitor. Object stores' lifecycle rules on incomplete multipart uploads (S3 `AbortIncompleteMultipartUpload`) are configured as a backstop.
- **Negative caching of 404.** On upstream `404`, winner writes `negative_cached_until = now + NEG_TTL` (short, e.g. 30–60s) on the artifact/index row and deletes `cache_fill`. Losers return 404 immediately. Short TTL bounds the publish-visibility delay (Subsystem 2).

### 1.6 Why not Redis / a dedicated lock service in v1

- **Zero new infrastructure.** Postgres is already the source of truth and is on the critical path anyway; advisory locks add no new failure domain, no new thing to operate, secure, back up, or page on.
- **Correctness doesn't require it.** Content-addressing means the lock is an *optimization* (reduce upstream amplification), not a correctness primitive. The system is safe even if the lock layer hiccups.
- **Auto-release semantics** of xact locks give crash-safety that a naive Redis `SETNX` lock lacks (Redis needs TTLs + fencing tokens to avoid the split-brain that Redlock is famous for).

**When to add one:** if fill rate grows to where advisory-lock acquisition contention or `cache_fill` row churn measurably loads Postgres (watch `pg_locks`, WAL volume from `cache_fill` upserts), or if we need sub-millisecond coordination or cross-region fills, introduce Redis (with fencing tokens) or a lease service. The `cache_fill` table abstracts the lease so the primitive can be swapped behind a `FillCoordinator` trait.

---

## Subsystem 2: Cache Correctness — Immutable vs Mutable Classification

### 2.1 Per-format path classifier

Each format handler exposes:

```rust
enum Mutability {
    Immutable,                       // cache forever, never revalidate
    Mutable { default_ttl: Duration }, // short TTL + conditional revalidation
}

trait FormatHandler {
    fn classify(&self, path: &str) -> Mutability;
}
```

Classification is **path-structural**, derived from each ecosystem's contract:

| Format | Immutable | Mutable (`default_ttl`) |
|---|---|---|
| **Maven** | versioned coordinates: `…/foo/1.2.3/foo-1.2.3.jar`, `.pom`, classifier jars | `maven-metadata.xml`, any `*-SNAPSHOT/` listing, directory indexes (~5 min) |
| **PyPI** | wheel/sdist files `…/packages/<hash>/foo-1.2-py3-none-any.whl` | simple index `…/simple/foo/`, JSON API `/pypi/foo/json` (~1–5 min) |
| **npm** | tarballs `…/foo/-/foo-1.2.3.tgz` | packument `…/foo` (the package document with dist-tags) (~1–5 min) |
| **OCI** | blobs/manifests **by digest** `…/blobs/sha256:…`, `…/manifests/sha256:…` | tags `…/manifests/<tag>` (~1 min) |
| **Cargo** | crate files `…/api/v1/crates/foo/1.2.3/download`, sparse index *content* is immutable-per-revision | sparse index file `…/index/fo/o/foo` (config says short TTL) (~1–5 min) |

The classifier must default to **`Mutable` with a conservative TTL** for unrecognized paths — misclassifying a mutable path as immutable is the dangerous direction (serves stale forever), so the safe default is revalidation.

### 2.2 TTL and conditional revalidation

- **Immutable:** on cache hit, serve from object store with no upstream contact, ever. (A versioned jar that "changed" upstream is a republish anomaly handled by explicit cache-invalidation tooling, not normal reads.)
- **Mutable:** on cache hit where `now > expires_at`, perform **conditional revalidation** against upstream:

```text
fn revalidate(entry):
    headers = {}
    if entry.etag:          headers["If-None-Match"]     = entry.etag
    if entry.last_modified: headers["If-Modified-Since"]  = entry.last_modified
    resp = upstream.get(entry.path, headers)
    if resp.status == 304:                          # still fresh
        entry.expires_at = now + ttl; entry.fetched_at = now; save()
        return serve_cached(entry)                  # cheap: no body transfer
    if resp.status == 200:                          # changed → single-flight refill
        return single_flight_fill(entry)            # reuses Subsystem 1
    if resp.status == 404:                          # gone
        set_negative_cache(entry, NEG_TTL); return 404
    # 5xx/timeout → serve stale within a grace window (stale-if-error)
    if now < entry.expires_at + STALE_IF_ERROR_GRACE:
        return serve_cached(entry)
    return 502
```

`304` responses make revalidation cheap (headers only, no body). Refills (`200`) route through Subsystem 1's single-flight so a popular index that just changed doesn't trigger N upstream pulls.

### 2.3 Negative caching & publish-visibility tradeoff

A `404` from upstream is cached with a **short** `negative_cached_until` (30–60s). This shields upstream from repeated misses (e.g. a build polling for a not-yet-published version) but bounds **publish visibility latency**: after a package is published upstream, clients see it within at most the negative TTL. Longer negative TTL → less upstream load but staler "not found"; we choose short (30–60s) because false-negatives are user-visible and confusing. Mutable index entries get the same short positive TTL for the same reason: a newly published version must appear in the simple index / packument promptly.

### 2.4 Virtual repos: index merging vs member caching

A virtual repo fans a request out to its member repos and merges results. Members may be local or remote; remote members use the caching above.

- **Immutable file requests** (e.g. a specific jar): query members in priority order, return the first hit. Each remote member's fetch is its own single-flight fill. Stop at first success.
- **Mutable index requests** (e.g. `simple/foo/`, a packument, `maven-metadata.xml`): fan out to **all** members in parallel, each with a **per-member timeout** (e.g. 2s), then merge (union of versions, dedup, ecosystem-specific precedence — e.g. first-member-wins on version collision).

```text
fn virtual_index(repo, path):
    results = parallel_map(repo.members, m =>
        with_timeout(PER_MEMBER_TIMEOUT, fetch_index(m, path)))
    merged = merge_format_index(results.successes())
    if results.has_failures():
        mark_response_partial(metric, repo, path)   # graceful partial results
    return merged   # served even if some members timed out
```

**Graceful partial results:** a slow/down member must not fail the whole virtual index — return the merge of what succeeded and emit a `partial` metric. Merged virtual indexes are **not** persisted as a cache entry (they're a function of member states that change independently); instead each *member's* index is cached per Subsystem 2, and the merge is recomputed (cheaply) per request from cached member indexes. This keeps freshness correct: invalidating one member naturally re-merges.

### 2.5 Data model

```sql
-- One row per cached path per remote repo (the index/metadata side).
CREATE TABLE remote_cache_entry (
    repo_id              BIGINT NOT NULL,
    path                 TEXT   NOT NULL,
    digest               BYTEA,                 -- NULL for pure-metadata/neg entries
    mutability           TEXT   NOT NULL,       -- 'immutable' | 'mutable'
    etag                 TEXT,                  -- upstream validator
    last_modified        TEXT,                  -- upstream Last-Modified (verbatim)
    fetched_at           TIMESTAMPTZ NOT NULL,
    expires_at           TIMESTAMPTZ,           -- NULL ⇒ immutable (never expires)
    negative_cached_until TIMESTAMPTZ,          -- non-NULL ⇒ cached 404
    upstream_status      SMALLINT,              -- last upstream status
    size_bytes           BIGINT,
    PRIMARY KEY (repo_id, path)
);
CREATE INDEX rce_expiry ON remote_cache_entry (expires_at)
    WHERE expires_at IS NOT NULL;
CREATE INDEX rce_neg ON remote_cache_entry (negative_cached_until)
    WHERE negative_cached_until IS NOT NULL;

-- Content-addressed blobs (shared, dedup by digest).
CREATE TABLE blob (
    digest     BYTEA PRIMARY KEY,   -- sha256
    size_bytes BIGINT NOT NULL,
    storage_key TEXT  NOT NULL,     -- object-store key (== digest-derived)
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Freshness logic is a pure function of the row, making it unit-testable:

```rust
enum Freshness { Fresh, Stale, NegativeHit, Miss }
fn evaluate(entry: Option<&RemoteCacheEntry>, now: Instant) -> Freshness {
    match entry {
        None => Freshness::Miss,
        Some(e) if e.negative_cached_until.map_or(false, |t| now < t) => Freshness::NegativeHit,
        Some(e) if e.expires_at.is_none() => Freshness::Fresh,        // immutable
        Some(e) if now < e.expires_at.unwrap() => Freshness::Fresh,
        Some(_) => Freshness::Stale,
    }
}
```

### 2.6 Observability

Per `(repo_id, format, mutability)` counters and histograms:

- `cache_request_total{result=hit|miss|revalidate_304|revalidate_200|negative_hit|stale_served|passthrough}`
- `single_flight_total{role=winner|loser|reclaim|passthrough_fallback}`
- `upstream_fetch_total{status}` and `upstream_fetch_duration_seconds` (the amplification check: ratio of `upstream_fetch_total` to `cache_request_total{result=miss}` should approach 1).
- `virtual_index_partial_total{repo}` and `virtual_member_timeout_total{member}`
- `cache_fill_active` gauge, `cache_fill_reclaimed_total`, `cache_fill_orphaned_total` (janitor).
- `multipart_abort_total{reason=upstream_error|reclaim|janitor}`.

The single most important dashboard panel is **upstream amplification ratio** — it directly validates I2.

---

## Implementation Order & Test Plan

**Build order:**

1. **Blob + content-addressed storage + `evaluate()` freshness function.** Pure logic first; unit-test `evaluate` and each format's `classify` exhaustively (table-driven tests with the examples in §2.1). No concurrency yet.
2. **Mutable-path caching with TTL + conditional revalidation** (single replica). Validates the 304/200/404/5xx matrix in §2.2 against a mock upstream.
3. **Single-flight winner/loser with advisory locks + `cache_fill`** (§1). Add heartbeat, reclaim, janitor.
4. **Negative caching** and **passthrough fallback**.
5. **Virtual-repo fan-out, merge, per-member timeout, partial results.**
6. **Observability** wired throughout.

**Test plan:**

- **Unit (Tier 1):** `classify` truth tables per format; `evaluate` freshness for every (expires_at, negative, immutable) combination; SHA-256 streaming hasher correctness; merge functions with version-collision precedence.
- **Integration (Tier 2, real Postgres):** advisory-lock acquire/release; `cache_fill` lease expiry + reclaim; janitor orphan sweep; revalidation against a mock upstream returning scripted 304/200/404/503.
- **Multi-replica concurrency (the core proof):** spin up ≥3 app replicas + one Postgres + a deliberately-slow mock upstream (configurable per-byte delay). Fire 200 concurrent `GET`s for the same uncached large object across replicas. **Assert:** exactly one `upstream_fetch_total` increment (winner) plus any deliberate passthrough fallbacks; every client receives bytes whose SHA-256 equals the published digest (I1); exactly one `blob` row, one `artifact` row. Kill the winner replica mid-stream and assert a loser reclaims and the fill completes. Repeat for a 404 → assert one upstream miss, all others `negative_hit`.
- **Stress:** reuse `scripts/stress/run-concurrent-uploads.sh` adapted for concurrent *pulls*; validate amplification ratio ≈1.
- **Native-client E2E (Tier 3):** real clients through a remote repo pointed at a real upstream — `pip install` (PyPI simple index mutable + wheel immutable), `npm install` (packument + tarball), `docker pull` (tag→manifest mutable, blob-by-digest immutable), `mvn` (maven-metadata.xml + versioned jar), `cargo` (sparse index + crate). For each: first pull MISS warms cache, second pull HIT with zero upstream contact (assert via upstream mock request count); publish-then-pull within negative TTL proves visibility bound. These slot into `./scripts/native-tests/run-all.sh`.

The clean-room ordering guarantees each layer is provably correct before the next depends on it, and the multi-replica concurrency test is the gate that proves the single-flight invariants under real contention.
