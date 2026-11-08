# Sizing memory for virtual conda channels

A virtual conda channel serves `repodata.json` (and `.zst`, `.bz2`),
`run_exports.json`, `channeldata.json` and the CEP-16 shard index by merging its
members, and derives `current_repodata.json` from its merged `repodata.json`
(#4708). For a
remote member that mirrors conda-forge this is the most memory-hungry thing the
backend does: the `linux-64` `repodata.json.zst` is about 60 MB on the wire and
decodes to about 455 MB of JSON, and the merge works on the decoded document.
This page explains how that memory is bounded, which settings size it, and what
to alert on (#4608).

## How a merge is bounded

**One merge per document, shared.** Requests for the same merged document
share one merge, and the result is kept for a short time. A burst of 40 solves
asking for `linux-64/repodata.json.zst` runs one merge, not 40, and every
request gets the same bytes and the same `ETag`, so a client that revalidates
gets a 304.

**One merge for every encoding (#4879).** `repodata.json`,
`repodata.json.zst` and `repodata.json.bz2` of one subdir are one merge. The
merged document is kept zstd-encoded (compact JSON); the plain `.json` and the
`.bz2` are derived from it the first time a client asks for them, on a
blocking thread, and kept with it, so each is built at most once per merge.
Each encoding has its own `ETag`. Deriving an encoding takes a merge slot and
reserves its output (plus about 16 MiB for the encoder) from the budget like a
merge does, and sheds with the same 503 when neither is free in time. The
gzip transfer coding of a plain JSON document is built and kept the same way,
except that when it cannot get a slot or budget in time the response goes out
uncoded instead of 503.
The served `.json` of a virtual is compact JSON; earlier releases
pretty-printed it.

The kept document is reused only while all of these are unchanged:

- the virtual and the document (not its encoding);
- the members the caller can read, in order (a token that sees fewer members
  gets its own merge);
- the hosted records the merge lists and the package names hosted members own
  (an upload, delete or withdrawal starts a new merge);
- the stored package allowlist of the virtual;
- each remote member's document: the merge records the checksum of the bytes it
  read out of the member's proxy cache, and the kept document is served only
  while that cache entry is still fresh and still holds those bytes.

**Stale while revalidate (#4879).** When a kept document stops being fresh
(a remote member's cache entry expired or changed, or the document is older
than `CONDA_VIRTUAL_MERGE_CACHE_TTL_SECS`), the request that notices is still
answered at once with the kept document, and exactly one background merge
starts to rebuild it. Every request until the rebuild lands gets the kept
document too, with a `Warning: 110 - "Response is Stale"` header, and counts as
`ak_conda_virtual_merge_cache_hits_total{via="stale"}`. The rebuilt document
replaces the kept one only once it is complete, including the encodings the
kept one had been asked for (so a client that wants `.bz2` never waits on the
bzip2 encoder after a rebuild); the next request gets it. A document is served
stale for at most `CONDA_VIRTUAL_MERGE_MAX_STALE_SECS` after it was first found
stale; after that a request waits on the rebuild as it did before. Set it to
`0` to turn stale serving off. A rebuild that fails (a member is down) leaves
the kept document in place, still bounded by the same setting, and the next
request starts another rebuild.

`current_repodata.json` follows the merged `repodata.json` it is derived from,
stale or not. The CEP-16 shard index is never served stale.

A merge in which a member failed is never kept, so it is never served stale.
The member-failure policy (strict 502, or a partial document marked
`no-store`) is applied to every response exactly as before.

**A cap on concurrent merges.** At most `CONDA_VIRTUAL_MAX_CONCURRENT_MERGES`
merges run at once across all virtual channels. A merge that cannot start within
`CONDA_VIRTUAL_MERGE_QUEUE_SECS` is refused with `503 Service Unavailable`, a
`Retry-After` header and a body naming the setting. Every request that was
waiting on that merge gets the same 503. pixi, rattler and conda retry 503s.

**Accounted against the buffered-metadata budget.** Before it fetches
anything, a merge reserves memory from the process-wide buffered-metadata
budget, `AK_PROXY_METADATA_BUDGET_BYTES` (default 1 GiB), which every format's
buffered metadata shares. The reservation is what the previous merge of the
same document held at most (the member fetch buffer until it is decoded, each
decoded member document, the parsed records and the output) plus 10 %. The
first merge of a document after a restart does not know its size yet and
reserves the whole budget, so it runs alone; that happens once per document.
The wait for the reservation is bounded by `CONDA_VIRTUAL_MERGE_QUEUE_SECS` and
ends in the same 503. A merge that outgrows its reservation (the upstream
document grew) tops up from whatever budget is free without waiting, and goes
on over its reservation by that growth if none is; it never waits for budget
while holding some, so two merges cannot wait on each other.

The merged document is written straight into the zstd compressor, so the
plain document is not held next to its compressed form during the merge. The
`.bz2` is derived by streaming the kept document through a zstd decoder into
the bzip2 encoder, so it does not hold the plain document either; only the
`.json` itself, when a client asks for it, is held plain.

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `CONDA_VIRTUAL_MAX_CONCURRENT_MERGES` | budget ÷ (member fetch ceiling + member decoded ceiling), at least 2 (2 with the defaults) | Merges that may run at once. |
| `CONDA_VIRTUAL_MERGE_QUEUE_SECS` | 60 | Longest a merge waits for a slot or for budget before the request gets 503. `Retry-After` is this value capped at 5 s. |
| `CONDA_VIRTUAL_MERGE_CACHE_TTL_SECS` | 300 (the proxy cache's default for mutable metadata) | How long a merged document is fresh. `0` turns the cache off; concurrent requests still share one merge. |
| `CONDA_VIRTUAL_MERGE_MAX_STALE_SECS` | the cache TTL | How long after it was first found stale a kept document may still be served while one background merge rebuilds it. `0` turns stale serving off: the request waits on the rebuild. |
| `CONDA_VIRTUAL_MERGE_CACHE_MAX_BYTES` | 1 GiB | Ceiling on kept merged documents, counting the kept body and every encoding derived from it so far. |
| `AK_PROXY_METADATA_BUDGET_BYTES` | 1 GiB | The shared buffered-metadata budget merges reserve from. Accounted in 4 KiB units; values above 4 GiB are honoured (before 1.11.5 they were clamped to 4 GiB, #4881). |
| `CONDA_VIRTUAL_MEMBER_MAX_BYTES` | 128 MiB | Ceiling on one member document as fetched (compressed). |
| `CONDA_VIRTUAL_MEMBER_MAX_DECODED_BYTES` | 1 GiB | Ceiling on one member document after decoding. |

## Sizing

Merge memory in flight is bounded by the budget, not by the number of clients.
Size the container from three parts:

1. **Baseline**: the backend's steady resident set without merges (a few
   hundred MB, more with a large proxy-cache sidecar LRU).
2. **Merges in flight**: at most `AK_PROXY_METADATA_BUDGET_BYTES`, plus, for a
   merge whose upstream document grew since its previous merge, that growth.
   With conda-forge as the remote member, a `linux-64` `repodata.json.zst`
   merge holds about 0.7 GB (455 MB decoded plus the parsed records and the
   output) and a `noarch` one about 0.3 GB, so the default 1 GiB budget lets a
   platform subdir and `noarch` merge side by side. Every encoding of a subdir
   is served from that one merge; deriving the plain `repodata.json` from it
   reserves the plain document's size again while it is built. Two virtual
   channels over conda-forge, or more platforms,
   want a larger budget: about 0.7 GB per compressed platform document you
   expect to be merged at the same time.
3. **Kept documents**: up to `CONDA_VIRTUAL_MERGE_CACHE_MAX_BYTES`. A merged
   conda-forge `linux-64` is kept as its `.zst`, about 60 MB; a client that
   asks for `.bz2` adds about as much again, and one that asks for plain
   `repodata.json` adds the plain document, about 455 MB, so clients that
   cannot read `.zst` or `.bz2` cost several times more cache. A kept
   document stays in the cache for its TTL plus
   `CONDA_VIRTUAL_MERGE_MAX_STALE_SECS`, and during a rebuild the kept and the
   rebuilt document are held side by side.

Then leave headroom for the allocator: freed merge memory is not always returned
to the operating system at once, so the resident set after a burst sits above
the steady baseline. How glibc arenas and jemalloc's decay affect that is in
[backend RSS and the memory allocator](backend-memory-allocator.md).

### How this adds up with the upload budget

The merge budget and cache are fixed byte counts; they are not derived from the
container's memory limit. The in-memory upload budget
(`UPLOAD_MEMORY_BUDGET_BYTES`, [Sizing local scratch disk for
uploads](upload-scratch-disk.md)) is: unset, it is half the cgroup memory
limit. The two are independent and can be in use at the same time, so the
worst case the defaults admit is

```
baseline
+ UPLOAD_MEMORY_BUDGET_BYTES            (default: half the container limit)
+ AK_PROXY_METADATA_BUDGET_BYTES        (default: 1 GiB, merges and all other buffered metadata)
+ CONDA_VIRTUAL_MERGE_CACHE_MAX_BYTES   (default: 1 GiB)
```

With the defaults that fits a container of 6 GiB or more (3 + 1 + 1 GiB plus
a baseline under 1 GiB). Below that, set `UPLOAD_MEMORY_BUDGET_BYTES`
explicitly, or lower `CONDA_VIRTUAL_MERGE_CACHE_MAX_BYTES`, so the sum stays
under the limit; on a 4 GiB container, for example, 1 GiB for uploads,
the 1 GiB metadata budget and a 512 MiB merge cache leave room for the
baseline. When you raise `AK_PROXY_METADATA_BUDGET_BYTES` for more concurrent
merges, the upload budget does not shrink to make room: raise the container
limit by the same amount, or set the upload budget explicitly.

When you raise the budget, raise `CONDA_VIRTUAL_MAX_CONCURRENT_MERGES` with it
if you want more merges to run at once; the default is derived from the budget
at startup (for example 28 merges for a 32 GiB budget at the default member
ceilings). Lowering the budget or the merge cap trades memory for 503s under a
burst of distinct documents; it does not affect a burst of identical requests,
which share one merge.

## Metrics

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `ak_conda_virtual_merge_inflight` | gauge | | Merges running now. At the merge cap for long, merges are queueing. |
| `ak_conda_virtual_merge_cache_hits_total` | counter | `kind`, `via` | Requests answered without a merge of their own: `via="cache"` from a fresh kept document, `via="stale"` from a stale kept document while it is rebuilt, `via="singleflight"` by waiting on a merge already running. |
| `ak_conda_virtual_merge_cache_misses_total` | counter | `kind` | Requests that started a merge (in the foreground, or the background rebuild of a stale document). |
| `ak_conda_virtual_merge_rejected_total` | counter | `kind`, `reason` | Merges and encodings shed with 503: `reason="queue"` (no slot in time) or `reason="budget"` (no budget in time). |
| `ak_conda_virtual_merge_bytes_reserved` | gauge | | Buffered-metadata budget bytes held by running merges. |

`kind` is `repodata`, `current_repodata`, `run_exports`, `channeldata` or
`shard_index`, and `rendering` on `rejected_total` for an encoding derived
from a kept merge. A healthy channel under load shows misses at roughly one
per document (not per encoding) per cache TTL and hits for the rest. A
rising `rejected_total` means the cap or the budget is too small for the
number of distinct documents being merged at once. A steady
`via="stale"` share is expected right after each member refresh; stale serves
that go on for long mean rebuilds are failing or being shed.

The counters for the conda security controls (attestation outcomes,
install-script findings, allowlist drops) are in
[conda-security-metrics.md](conda-security-metrics.md).

## Alert on restarts, not only on memory

A container that is OOM-killed and restarted by its restart policy can look
healthy from the outside: the 2026-10 conda stress campaign recorded nine OOM
kills with no client-visible failure, because each restart came back before
clients gave up. Alert on the restart itself:

- Kubernetes: `increase(kube_pod_container_status_restarts_total{container="backend"}[15m]) > 0`,
  and `kube_pod_container_status_last_terminated_reason{reason="OOMKilled"} == 1`.
- Docker / Podman: a change in the container's `RestartCount`
  (`docker inspect -f '{{.RestartCount}}'`, `podman inspect -f '{{.RestartCount}}'`).
  Podman's `.State.OOMKilled` stays `true` after a later normal restart, so
  alert on the count changing rather than on the flag.

Alert on memory before the kernel acts too: container memory above 80 % of its
limit for several minutes, together with `ak_conda_virtual_merge_bytes_reserved`
and `ak_conda_virtual_merge_inflight`, tells you whether merges are the cause.
