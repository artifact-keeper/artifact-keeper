# Running remote repositories on more than one replica

This page answers the question in #4331: what is the supported shape for
high availability of remote (proxy) repositories, and what does each storage
choice cost in latency.

## The short answer

- **Object storage is supported for remote repositories.** With
  `STORAGE_BACKEND=s3` or `gcs` the proxy cache lives in the bucket and every
  replica shares it; no shared filesystem is needed. With `STORAGE_BACKEND=azure`
  it does too since 1.12.0 once `AZURE_PROXY_CACHE_ENABLED=true` is set
  (`docs/operations/proxy-cache-on-azure.md`); before that, or without the
  setting, an Azure deployment keeps the proxy cache under `STORAGE_PATH`.
  (The report on #4331 that object storage refuses to start with a remote
  repository describes Azure before 1.11.0, #3923.)
- **A shared filesystem (NFS, a ReadWriteMany volume) is also supported**, and
  is the only option for `STORAGE_BACKEND=filesystem` with more than one
  replica: every replica must see the same `STORAGE_PATH`, or purges,
  quarantine, scans and cache-cap eviction act on one replica's copy. Mount
  NFS with a short attribute cache, see [NFS mount options](#nfs-mount-options).
- **Turn on cross-replica single-flight** on any multi-replica deployment:
  `PROXY_SINGLEFLIGHT_ADVISORY_LOCKS_ENABLED=true`. Without it each replica
  fetches the same cold object from upstream once.

## What a cache hit costs on each backend

A proxied GET that hits the cache reads two objects: the metadata sidecar
(`__cache_meta__.json`) and the body (`__content__`).

- The sidecar is kept in an in-process cache for 30 seconds, so a repeat hit on
  the same replica does not read it again.
- Since 1.12.0 (#4331), on the filesystem backend the body is measured and
  opened at the same time as the sidecar is read, not after it. A first-touch
  hit on NFS costs one storage round trip of latency instead of three (sidecar
  read, size check, open). The buffered path (small metadata documents) reads
  the body alongside the sidecar the same way. The one-instead-of-three figure
  is reasoned from the sequence of storage calls (a test pins that the body is
  opened while the sidecar read is still in flight); it has not been measured
  on NFS. An entry published in the last few seconds is still read
  sequentially, so a replica with a skewed clock never trusts a body opened
  before the publish.
- On S3, GCS and Azure the two reads stay sequential: opening the body there is
  a GET that starts transferring it, which a miss or a stale entry would throw
  away. A presigned redirect (`*_REDIRECT_DOWNLOADS`) moves the body transfer
  off the backend entirely.

What remains is the storage's own per-operation latency. The measurements
reported on #4331 (by the reporter, before this change) put local disk at about
7 ms and NFS at about 40 to 66 ms for the same request; no change in the
backend removes NFS's own round trip. If
latency matters more than a shared cache, two other shapes work:

- object storage with presigned redirects, so replicas share one cache and
  clients fetch bodies from the bucket;
- one replica per site with local disk, each with its own cache, accepting that
  purges and quarantine apply per replica (not recommended where the
  quarantine and purge controls matter).

## Settings that matter with several replicas

| Setting | Why |
|---|---|
| `PROXY_SINGLEFLIGHT_ADVISORY_LOCKS_ENABLED=true` | one upstream fetch per cold object across replicas, not one per replica |
| `PROXY_SINGLEFLIGHT_LOCK_WAIT_TIMEOUT_SECS` | how long a replica waits for another's fill before fetching itself (default 65 s); raise it for very large objects on slow upstreams |
| a shared `STORAGE_PATH` | only for the filesystem backend (and Azure without `AZURE_PROXY_CACHE_ENABLED`) |

The single-flight limits that remain (a slow client paces the fill every other
replica waits for, and a waiting replica cannot serve from a fill in progress)
are described, with a proposed design, in
`docs/plans/2026-10-24-proxy-cross-replica-single-flight-design.md` (#4533).

## NFS mount options

A replica that loses the race for a cold object on the buffered path (small
files such as metadata documents and checksums) does not wait on the advisory
lock. It reads the entry's sidecar again every 200 ms
(`PROXY_SINGLEFLIGHT_LOCK_POLL_INTERVAL_MS`) until the entry is there, or until
`PROXY_SINGLEFLIGHT_LOCK_WAIT_TIMEOUT_SECS` (65 s by default) runs out and it
fetches the object itself. The Linux NFS client keeps a "file not found" until
the cached attributes of the parent directory expire, so the waiting replica
keeps missing an entry another replica has already written for that long.
With `actimeo=30` each cross-replica race for a cold object costs about 30 s
(#5768), with the defaults (`acdirmin=30`, `acdirmax=60`) 30 to 60 s, close to
the whole wait. Polling faster doesn't help: every read hits the same cached
miss.

Mount a shared `STORAGE_PATH` with one of:

- `actimeo=0`: nothing is cached and a waiting replica sees the entry on its
  next read. Every request then checks attributes with the server for each
  file and directory it touches: more round trips on every cache hit and more
  load on the NFS server
- a low value such as `actimeo=1`: a race costs at most about that long. The
  reporter of #5768 went from 30 to 1 and saw no more stalls and no measurable
  change in warm-read latency
- `lookupcache=positive`, keeping `actimeo` as it is: the client asks the
  server again for any name it last saw missing and keeps caching what
  exists, so only a miss pays the round trip. This follows from `nfs(5)` and
  has not been measured here

The streaming path doesn't stall: its waiting replica blocks on the lock,
which the filling replica releases only after the publish. With a long
attribute cache its next read can still miss, and it then fetches the object
a second time. Object storage (S3, GCS, Azure) has no client-side cache of
this kind.
