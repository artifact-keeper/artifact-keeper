# Hosted conda repodata: stored shards and revisions

From 1.12.0 a hosted (local or staging) conda channel no longer rebuilds its
index documents from the catalog on every request (#4172).

## What is stored

- **CEP-16 shards** (#4173). Each `(repository, subdir, package name)` has
  one stored shard, the `.msgpack.zst` document a CEP-16 client (pixi,
  rattler, mamba 2, conda with the sharded plugin) fetches as
  `shards/<sha256>.msgpack.zst`. It lives in the `conda_shard_index` table
  with its SHA-256. A shard request is one lookup by address; the bytes are
  checked against the address before they are served and carry
  `Cache-Control: public, max-age=31536000, immutable`. The shard index
  (`repodata_shards.msgpack.zst`) is serialised from the stored map.
- **A revision per subdir** (#4174). Every rebuild of a subdir bumps its
  revision. `repodata.json`, `.zst`, `.bz2`, `current_repodata.json`,
  `run_exports.json` and `repodata.json.jlap` are rendered
  together from one catalog walk the first time a revision is read, and kept
  in memory under it. `channeldata.json` is kept under the sum of the
  repository's subdir revisions. A request reads the revision (one statement
  against the conda state tables, no catalog rows) and serves the kept bytes
  when it matches; concurrent requests for a new revision share one render.
  `repodata.json` is unchanged from 1.11; since #4175 `.zst` and `.bz2`
  decompress to exactly those bytes (1.11 compressed a compact rendering).
  The pretty document is about 35 % larger uncompressed; compressed, `.zst`
  grows about 4 % and `.bz2` under 1 % (measured on 30,000 and 387,000
  conda-forge noarch records).
- **The last N `repodata.json` revisions and a JLAP** (#4175), see
  [JLAP](#jlap-incremental-repodata) below.

The kept documents are per process. Each replica renders a revision once.

## Rendering

A revision is rendered with one cursor over the repository's live rows
(only the columns that decide which row each document lists), then the
listed rows in filename order, 512 at a time, each record written straight
into the pretty `repodata.json` (and on into the zstd encoder, so `.zst`
holds the same bytes) and `current_repodata.json` (#4176). The render holds its output and one chunk of
rows, not the row set, so its memory is about the size of the documents it
produces.

A subdir no row has ever named (every write and the backfill give a named
subdir a revision, so its revision is still 0) is answered its empty
documents without a catalog walk, a permit or a cache entry, so requests for
made-up subdirs cost one state lookup and cannot evict real subdirs from the
cache.

`repodata.json.bz2` is not rendered with the revision: the first `.bz2`
request renders it from the kept `.zst` document and it is then kept with the
revision (#4882). It is single-stream bzip2 at level 9, the bytes 1.11
served. Measured with the backend's encoder (conda-forge documents, one core
of the reference host):

| Document | Level 9 | Level 1 | Multistream, 4 threads |
|---|---|---|---|
| `noarch/current_repodata.json`, 26 MB | 1.50 s, 4.68 MB | 1.21 s, 5.17 MB | 0.49 s, 4.69 MB |
| `linux-64/repodata.json`, 459 MB | 25.6 s, 61.7 MB | 21.1 s, 67.3 MB | 6.8 s, 61.7 MB |

A lower level saves under a fifth of the time for a tenth more bytes.
Multistream (independently compressed chunks, concatenated) scales with
threads but is a different file, and the one client measured to read `.bz2`
cannot read it: pixi 0.81 (rattler) fetches `.bz2` when a channel has no
`.zst` and, given a multistream file, parses only the first stream and fails
("EOF while parsing"). conda 26.9, mamba 2.9 and micromamba 2.0 never request
`.bz2` (they read `.zst` or `repodata.json`). So the file stays single-stream;
rendering it once per revision instead of once per request is the saving.

Renders take a permit from a process-wide gate,
`AK_CONDA_REGEN_CONCURRENCY` (default 2), and a request waits at most
`AK_CONDA_REGEN_WAIT_SECS` (default 30, `0` for no bound) before it is
answered `503` with `Retry-After: 5`. The render it was waiting for keeps
running and serves the requests that follow. See
[load-shedding.md](load-shedding.md).

## JLAP incremental repodata

`repodata.jlap` (also served as `repodata.json.jlap`, the name 1.11 used;
conda and rattler request `repodata.jlap`) lets a client that holds an
older `repodata.json`
update it with a patch instead of downloading the index again (conda with
`--experimental=jlap` (conda 23.9 and later, before 26.9, which dropped it), rattler and pixi when the channel has no
shard index or sharding is disabled). From 1.12.0 a hosted subdir serves a
real JLAP (#4175); before, it served a file with no patches and every
client downloaded the whole index anyway.

- Each render of a new revision records its `repodata.json` in
  `conda_repodata_revisions` (zstd-compressed, with its BLAKE2b-256) and,
  when the document changed, appends one RFC 6902 patch line from the
  previous document to the subdir's stored JLAP in `conda_repodata_jlap`.
  The new line replaces the old footer, so the bytes before it never move,
  and the BLAKE2b checksum chain continues from the stored bytes. A client's
  `Range: bytes=<pos>-` request (conda sends the offset of the footer it
  last saw) is answered `206` with only the new lines; a position past the
  end is `416` and the client fetches the whole file.
- `AK_CONDA_JLAP_REVISIONS` (default 8, 1 to 1024) revisions are kept per
  subdir and the JLAP keeps one patch line fewer. A client that last
  refreshed more than that many changes ago finds no patch from its hash
  and downloads `repodata.json`, as it would without JLAP. When the window
  moves the oldest line is dropped and the IV line takes its chain value:
  the kept lines' checksums do not change, but their offsets do, so a
  client's next range request does not verify and it fetches the whole
  (small) JLAP once, still without downloading the index. A value of 1
  keeps only the current document: the JLAP names its hash and carries no
  patches. Storage per subdir is about N compressed copies of its index.
- A patch is not written when it would have more than 8192 operations (a
  bulk import): clients holding the older document download the index once.
- Ordering: the JLAP is recorded inside the render of the revision, before
  that revision's documents are kept or served, under the JLAP row's lock.
  The JLAP a replica serves ends at the `repodata.json` it serves, so a
  withdrawal, which moves the revision, is absent from the JLAP tail as soon
  as it is absent from `repodata.json`. A render that finds a newer revision
  already recorded (another replica moved on) does not append, so the tail
  never moves back. Neither does a render of the recorded revision with other
  bytes (two renders that decided visibility at different instants): until
  the revision next moves, a client holding that render's document finds no
  patch and downloads `repodata.json`.
- Only hosted channels serve a JLAP; Remote and Virtual channels answer 404
  and clients fetch `repodata.json`.

## How changes reach them

Database triggers on `artifacts` and `artifact_metadata` record every
`(repository, subdir, name)` a write touches in `conda_shard_dirty`, in the
writer's own transaction, whatever made the write: a conda upload or
withdrawal, a generic delete, the quarantine console, a scanner verdict, an
attestation added to a package. Only the dirty names are rebuilt: their rows
are read, only shards whose bytes changed are rewritten, and the subdir's
revision moves. The conda upload and withdrawal routes rebuild right after
their write; any other writer leaves the rebuild to the next read, which
always rebuilds what is dirty before it serves. A read therefore never sees a
document older than the catalog.

An upload hold that lapses changes what a channel lists with no write at all.
The earliest pending `quarantine_until` of each channel is kept, and the
first read after it rebuilds the names whose hold lapsed.

Rebuilds announce themselves to the other replicas on their own
notification channel (`ak_conda_repodata_invalidation_v1`, event
`conda_repodata_invalidated`, the same listener connection as
`ak_cache_invalidation_v1`) so they free the superseded documents early.
Correctness does not depend on the event: every replica checks the revision
on every request. The channel is separate so that 1.11.x replicas, which do
not listen on it, are not affected during a rolling upgrade: on the shared
channel they would answer every unknown event with a conservative flush of
their authorization caches.

## Remote channels whose upstream has no shard index

A Remote conda repository proxies its upstream's CEP-16 shard index when the
upstream publishes one. From 1.12.0, when it does not (most private channels
and older mirrors publish only `repodata.json` and its `.zst`/`.bz2`), the
remote synthesises the shards itself (#4178), so CEP-16 clients of it fetch
shards instead of the whole index, and a virtual channel's shard index can
include that member instead of dropping to `repodata.json` for everyone.

- **Source.** The upstream document the plain `repodata.json` proxy already
  reads and caches: `repodata.json.zst`, else `.bz2`, else `repodata.json`.
  It is decoded as a stream and parsed record by record; records are spilled
  to 64 temporary files (in the process's temporary directory) by package
  name, and each file is then grouped into shards. The plain JSON of the index
  is never held. Measured on the reference host with conda-forge documents
  (debug build, single thread; peak resident set of the whole test process):

  | Document | Compressed | Records | Names | Shard bytes | Peak RSS |
  |---|---|---|---|---|---|
  | `noarch/repodata.json.zst` | 29 MB | 387,298 | 23,959 | 36 MB | 97 MiB |
  | `linux-64/repodata.json.zst` | 59 MB | 799,329 | 14,173 | 68 MB | 143 MiB |

  The compressed document itself (under the 128 MiB metadata ceiling) is held
  while it is read, as for any proxied metadata read. An upstream that
  publishes only the plain `repodata.json` is held as fetched, under the same
  ceiling.
- **Storage.** The shards go into `conda_shard_index` with
  `origin = 'synthesized'`, the served revision into
  `conda_subdir_revisions`, and `conda_synthesized_subdirs` records the
  upstream document (path and SHA-256) they were built from. A rebuild writes
  the changed shards, deletes the names the upstream dropped and bumps the
  revision in one transaction, so a reader sees the old set or the new one.
  Shards are checked against their address before they are served.
- **Refresh.** While the proxy cache entry of that document is fresh and
  still holds the recorded SHA-256, the stored shards are served with no read
  of the document. Past the entry's TTL (the remote's metadata TTL,
  `cache_ttl_secs`) the next shard index request fetches it through the
  proxy: the same bytes change nothing; different bytes mark the subdir stale
  and rebuild it. A stale index is not served: the request waits for the
  rebuild like any other render (`AK_CONDA_REGEN_CONCURRENCY`,
  `AK_CONDA_REGEN_WAIT_SECS`, then `503` with `Retry-After`).
- **Bounds.** The decoded document is refused past
  `CONDA_VIRTUAL_MEMBER_MAX_DECODED_BYTES` (1 GiB by default, the virtual
  merge's member ceiling), one record past 16 MiB, and one package name whose
  records pass 64 MiB (conda-forge's largest record is about 5 KB and its
  largest name, `awscli` on linux-64, about 7 MB). A refused or unparseable
  upstream document answers `502`; nothing is stored and the subdir stays
  stale, so no index is served from it.
- **Temporary space.** The spill files take about the decoded size of the
  document (about 460 MB for conda-forge linux-64) under `TMPDIR` while the
  rebuild runs, in a directory named `ak-conda-shard-synth-*` that is removed
  when the rebuild ends, fails or panics (a process killed outright leaves it
  behind). A full, read-only or missing `TMPDIR` fails the rebuild with `500`
  and an error log naming the spill files; nothing is stored.
- An upstream that does publish a shard index, but one past the 64 MiB
  shard-index ceiling (#4612), is not synthesised: its shard index keeps
  answering `404` and a virtual with that member serves none for the subdir,
  so clients use `repodata.json`.
- A subdir the upstream publishes no `repodata.json` for at all still answers
  `404` on the shard index, and keeps a virtual off CEP-16 for that subdir.

## Backfill of existing channels

The migration marks every hosted conda repository that exists at upgrade
time as not backfilled. At startup each 1.12 backend backfills them in
batches of 500 package names, one transaction per batch, saving a cursor with
each, so a restart resumes where it stopped and two replicas never work on
the same repository at once. Until a repository finishes, its shard index and
shards are built per request as in 1.11; its repodata documents use the
revision cache from the first request, as they do not depend on the backfill.
The log line `conda shard backfill finished` marks each repository.

## Metrics

The kept documents report through the shared metadata-cache metrics with
`format="conda"` and `scope` `subdir`, `shard_index` or `channel`; see
[repo-metadata-cache-metrics.md](repo-metadata-cache-metrics.md). A burst of
cold requests after one upload moves
`ak_repo_metadata_regenerations_total{format="conda",scope="subdir"}` by one.
