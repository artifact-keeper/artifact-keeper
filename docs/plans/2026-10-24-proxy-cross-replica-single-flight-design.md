# Proxy single-flight across replicas: decouple the fill and publish an in-flight row (design note)

**Date**: 2026-10-24
**Status**: Proposed, for maintainer review. Nothing here is decided; no code
ships with this note (implementation is 1.13.0 material). The open questions
at the end need an answer first.
**Issues**: #4533 (this design), #4013 and #4532 (what 1.11.0 shipped), #4331 (HA
latency report), #2928 (per-object cache ceiling), #4660 (per-Remote cache cap)

## What ships today

A cold proxied GET elects a leader in two layers:

1. **In process** (`BufferedCoordinator`, `proxy_hydration.rs`): concurrent
   requests for the same cache key on one replica share one upstream fetch; the
   leader's `StreamHandle` is fanned out to followers.
2. **Across replicas**, opt-in with `PROXY_SINGLEFLIGHT_ADVISORY_LOCKS_ENABLED`
   (`AdvisoryLockCoordinator`, #4532): the in-process leader takes a Postgres
   advisory lock keyed by `cluster_lock::lease_object_id(lease_key)`, a 32-bit
   FNV hash. A losing replica polls the lock (`PROXY_SINGLEFLIGHT_LOCK_POLL_INTERVAL_MS`,
   200 ms) for up to `PROXY_SINGLEFLIGHT_LOCK_WAIT_TIMEOUT_SECS` (65 s), at most
   `PROXY_SINGLEFLIGHT_MAX_LOCK_WAITERS` (32) waits at once, and then re-checks
   the cache. The leader releases after its cache publish.

The leader's body is teed (`CachePersister::tee_stream`): upstream chunks go to
the client and, through a bounded channel (`TEE_CHANNEL_DEPTH` = 64 chunks of at
most 64 KiB), to a storage writer that stages the object, copies it onto the
live key and writes the sidecar.

## What that leaves on the table

- **One client paces the fill.** The tee only reads upstream as fast as the
  leader's client reads it (the channel is bounded and the client stream is the
  driver). A slow leader client slows the fill, and every remote waiter waits
  for it. Past the wait timeout each replica fetches for itself, so the floor is
  N upstream fetches for N replicas, not 1.
- **A follower on another replica cannot serve from an in-progress object.** It
  only ever sees the finished cache entry.
- **The lock is a 32-bit hash.** Unrelated keys can share a lock: extra
  waiting, harmless today, but it rules the lock out as a precise signal.

## Proposed direction

1. **Decouple the fill from the client.** The leader reads upstream at upstream
   speed into a spool (the staging object it already writes), and its own client
   reads from the spool instead of driving the tee. A slow client then delays
   only itself.
2. **Publish an in-flight row** keyed by the full cache key, not a hash:

   ```sql
   CREATE TABLE proxy_cache_inflight (
       cache_key        TEXT PRIMARY KEY,
       leader           TEXT NOT NULL,        -- replica identity
       spool_key        TEXT NOT NULL,        -- staging object being written
       content_length   BIGINT,               -- upstream Content-Length, when known
       bytes_committed  BIGINT NOT NULL DEFAULT 0,
       state            TEXT NOT NULL,        -- filling | published | failed
       heartbeat_at     TIMESTAMPTZ NOT NULL DEFAULT now()
   );
   ```

   The row replaces the advisory lock as the election (an `INSERT ... ON
   CONFLICT DO NOTHING` wins; a stale `heartbeat_at` lets a successor take over).
3. **Followers by backend class.**
   - Filesystem (one shared `STORAGE_PATH`): followers tail the spool with
     ranged reads up to `bytes_committed`, so a second replica starts streaming
     before the fill ends.
   - S3, GCS, Azure: a multipart or block upload is not readable until it is
     committed, so followers wait on the row (`state = published`) and serve
     from the cache entry, as today but without the hash collisions and with a
     fill that runs at upstream speed.
4. **Do not build "follower proxies the leader's stream across processes".** It
   moves the fan-out hop onto the network, still needs the row to find the
   leader, and couples two replicas' lifetimes.

## What it interacts with

- **Digest-gated commit** (GHSA-qxv7-p3mq-88fv, #2274): only the leader's writer
  task commits the object (staging key → copy onto the live key → sidecar);
  followers never finalize cache commits. The gate stays on the leader for
  every algorithm (SHA-256 via the storage layer's observed checksum,
  SHA-1/SHA-512 via `TeeDigestHasher`). A tailing follower must either buffer
  until `state = published` or accept the same semantics the leader's client
  has today (the client verifies the digest itself for an uncached stream),
  because a leader that refuses the spool at the digest gate leaves a
  partially-tailed follower's client with bytes whose cache entry was never
  published.
- **Per-object ceiling** (#2928) and **per-Remote cap** (#4660): the spool is
  bounded by the same ceiling; the cap's admission check runs at election, and
  eviction after the publish, as now. The `max_cache_bytes` check must run on
  the leader as it streams from upstream (independent of client pacing), not
  driven by the client's read rate. Today, when the ceiling trips mid-stream,
  `tee_stream` abandons only the cache half and keeps yielding bytes to the
  client; a body that will never be cached (`cache_published.is_none()`)
  releases the lock at once. Once the client reads from the spool instead of
  the tee, an abandoned spool leaves the leader's client and any tailing
  follower with nothing to read: a known `Content-Length` over the ceiling
  must skip the spool and pass through as today, and an unknown length that
  trips the ceiling mid-stream must switch the leader's client to direct
  pass-through and mark the row `failed` so followers stop tailing.
- **Scan-on-proxy and commit-after-gate** (#4514, #5070): the scanned path
  buffers the body and does not tee, so decoupling the fill does not change how
  it reads upstream, and the gate still decides on the full object. Since #5070
  the fill is not committed before the gate: it is held until
  `gate_proxy_scan_serve` decides, then a served or `403` blocked body is
  committed (a blocked body stays cached, and every reader of the scanning
  Remote refuses it from its stored verdict), while a `fail_closed` `423`
  (inconclusive) body is dropped and never cached. Today a request on another replica that lost the advisory
  lock polls for the cache entry, so after a dropped fill it waits out the
  65-second hydration wait before fetching the file itself. The row removes
  that wait: a held fill stays `filling` while the gate decides, a committed
  body (served or blocked) moves it to `published`, and a dropped body moves it
  to `failed`, so followers fetch and gate the file themselves at once.
  Followers never tail a scanned fill's spool; they wait for `published` and
  read the committed entry through the gate, as today.

## Open questions

1. **Spool lifecycle on leader death.** Who deletes an orphaned spool, and when
   may a successor reuse the bytes already committed rather than refetch?
   (Proposal: a successor refetches from byte 0; the janitor deletes spools of
   rows whose heartbeat is older than the lease TTL. Orphan cleanup must be
   driven by a background sweep keyed off `heartbeat_at` and `state !=
   'published'`. A retention rule is also needed for `published` and `failed`
   rows (not only orphaned spools), or the `proxy_cache_inflight` table will
   grow by one row per cold object; stale spool objects must be removed
   without blocking new elections.)
2. **Heartbeat write rate.** Updating `bytes_committed` per chunk is too much
   write traffic; per N MiB or per second? (Proposal: every 1 s or 8 MiB,
   whichever comes first; tailing followers read the spool's size, not the row,
   for progress. The transitions to `published` and `failed` also write the
   row. A successor detects a dead leader only by a stale `heartbeat_at`.)
3. **Does the in-process `BufferedCoordinator` stay** as a first layer (no DB
   round trip for the common single-replica case), with the row only for
   cross-replica election? (Proposal: yes.) The in-process fan-out and local
   leader election must remain as the fast path for single-replica and for
   coalescing within a pod.
4. **Opt-in or default and configuration compatibility.** The advisory-lock
   coordinator is opt-in today. Should the row-based coordinator be the default
   for multi-replica Helm installs? The row-based approach must remain
   compatible with existing `PROXY_SINGLEFLIGHT_*` configuration and degrade
   gracefully when Postgres is unavailable (fall back to per-replica fetches,
   as today). Of those variables, `PROXY_SINGLEFLIGHT_LOCK_POLL_INTERVAL_MS`
   and `PROXY_SINGLEFLIGHT_MAX_LOCK_WAITERS` are lock-specific; under a
   row-based coordinator they become no-ops unless there is still a lock-based
   path. The other two need an explicit answer rather than an assumption that
   they carry over: does `PROXY_SINGLEFLIGHT_ADVISORY_LOCKS_ENABLED` also turn
   the row-based coordinator on, and does
   `PROXY_SINGLEFLIGHT_LOCK_WAIT_TIMEOUT_SECS` (65 s) become a follower's wait
   on a `filling` row?
5. **Keeping an inconclusive body.** Since #5070 a `fail_closed` inconclusive
   fill is dropped, so its next pull fetches it from the upstream again
   (bounded by `PROXY_SCAN_MAX_BYTES`), and
   `docs/security/proxy-cache-commit-after-gate.md` leaves keeping those bytes
   for a retry to this spool. Should a dropped scanned fill keep its spool,
   outside the live cache key, so the retry rescans it without a refetch?
   (Proposal: not in the first cut. A kept spool must never be served or
   committed without passing the gate again, and it needs the same retention
   rule as question 1.)
