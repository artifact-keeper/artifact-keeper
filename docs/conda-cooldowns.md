# Conda cooldowns and `indexed_timestamp`

A *cooldown* keeps packages that were published very recently out of your
solves for a while, so that a malicious or broken release has time to be
noticed before it reaches you. Artifact Keeper supports two kinds for conda:

- **Client-side cooldowns.** `pixi` `exclude-newer`, `conda --exclude-newer`
  and mamba's `exclude_newer_timestamp` drop records newer than a cutoff. They
  rely on the per-record `indexed_timestamp` the channel serves (CEP 47).
- **The server-side age gate** on Remote channels and the Virtual channels
  over them. It filters young records out of what Artifact Keeper serves, so
  it also protects clients that set no cooldown at all.

## `indexed_timestamp` (CEP 47)

[CEP 47](https://github.com/conda/ceps/blob/main/cep-0047.md) adds an optional
`indexed_timestamp` to every record in `repodata.json`: the Unix time, in
milliseconds, at which the channel server added the file to its index. Unlike
the record's `timestamp`, which the package builder sets and can set to
anything, `indexed_timestamp` is set by the server.

What each channel type serves:

| Channel | `indexed_timestamp` |
|---|---|
| Hosted (local) | Set by Artifact Keeper when the package becomes visible in the channel, and never changed afterwards. It appears in `repodata.json` and its `.bz2`/`.zst` encodings, `current_repodata.json` and the CEP-16 shards. |
| Remote | The upstream's value, passed through unchanged. Artifact Keeper never stamps its own cache time on a proxied record: that would make a package that was cached early look old. As of November 2026 none of the major upstreams (conda-forge, repo.anaconda.com, prefix.dev) emit the field yet, so proxied records usually have none. |
| Virtual | A mix: records from hosted members carry the field, records from remote members carry whatever their upstream sent (usually nothing). |

A package migrated from Artifactory or Nexus keeps the source's creation time
as its `indexed_timestamp` (Artifactory `created`, else `modified`; Nexus
`lastModified`), not the time of the import. A re-import that brings back a
deleted package counts it from that moment, unless the age gate's ledger has
already seen the same bytes (sha256), which keep that first sighting.

## Client-side cooldowns

pixi (`pixi.toml`):

```toml
[workspace]
channels = ["https://ak.example.com/conda/conda-forge-virtual"]
exclude-newer = "7d"        # or an RFC 3339 date
```

conda (24.x with exclude-newer support):

```bash
conda create -n app --exclude-newer 7d -c https://ak.example.com/conda/my-channel numpy
```

mamba / micromamba: `--exclude-newer` (or `exclude_newer_timestamp` in the
config), same semantics.

Clients prefer `indexed_timestamp` and fall back to the builder `timestamp`
when a record has none. On a Remote whose upstream does not emit the field the
client is therefore trusting the builder's clock. Use the server-side age gate
when that matters.

## The server-side conda age gate

The age gate is the same Package Age Policy that npm, PyPI, Maven, Cargo, Go
and VS Code Remotes use, configured per Remote:

```bash
curl -X PUT -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  https://ak.example.com/api/v1/repositories/conda-forge-remote/age-gate \
  -d '{"enabled": true, "min_age_days": 7, "mode": "upstream_publish_time"}'
```

When it is on:

- **What is filtered.** Every record the gate holds is left out of the
  Remote's `repodata.json` (all encodings), `current_repodata.json` and CEP-16
  shard index and shards. A Virtual applies each gated Remote member's gate to
  what that member contributes, and a file a gated member withholds is served
  by no remote member. A Virtual with a gated member derives its shards from
  its own filtered `repodata.json`, so an ungated member's shards cannot list
  a withheld file. Hosted members are never gated. The gated documents carry
  an `x-ak-age-gate-withheld: <count>` header.
- **The baseline.** The first time the gate reads a subdir it records every
  file of one complete snapshot (a document fetched and parsed successfully;
  a missing `packages` or `packages.conda` map is an empty one) as the
  subdir's baseline. A replica that loses the race to record it records the
  files its own document adds as ordinary later sightings. A document that
  parses but has neither package map nor `info` (an empty `{}`) is refused
  with a warning and never becomes a baseline or prunes anything. Once the
  baseline exists, a file with no ledger row is always first seen now. Until the baseline exists the gate answers 503 with
  `Retry-After` rather than serve the subdir unfiltered. Baseline files count
  as old, so switching the gate on does not empty the channel, unless the
  record's builder `timestamp` or its `indexed_timestamp` falls inside the gate
  window (the builder's claim can only hold a record, never release one).
  Repointing the Remote at another upstream, or switching the gate off and on,
  never takes a new baseline; files the ledger has not seen are then new.
  Re-baselining is an explicit, audited action:
  `POST /api/v1/repositories/{key}/age-gate/conda/rebaseline`
  (`AGE_GATE_REBASELINED`). **The gate is not retroactive:** if the upstream
  was already compromised when the baseline was taken, the baseline accepts
  what it served.
- **How old a later file is.** Every file is recorded by filename and sha256
  the first time the gate sees it, at the database clock. New bytes under a
  published filename are a new file. A file first seen after the baseline is
  aged from `max(indexed_timestamp, the previous read of the subdir, first
  sighting - refresh cap)`: an upstream `indexed_timestamp` older than the read
  in which the file was not yet listed earns no credit. The refresh cap
  (`CONDA_AGE_GATE_REFRESH_CAP_SECS`, default the metadata cache TTL) bounds the
  credit when nobody read the subdir for a while. An `indexed_timestamp`
  older than the sighting by more than the cap is logged, counted, and
  reported as `backdated_indexed_timestamp`. In `first_seen` mode the upstream
  `indexed_timestamp` earns no credit at all.
- **Always held.** A record whose builder `timestamp` is in the future, or
  whose `indexed_timestamp` is earlier than its `timestamp` (CEP 47 asks
  channel servers to flag both), while `min_age_days` is above 0.
- **Downloads.** A withheld file answers `451 age_gate_blocked` with the
  package, version, `reason` (`too_young`, `rejected`, `timestamp_in_future`,
  `indexed_before_built`), `age_basis` (`indexed`, `first_seen`, `baseline` or
  `none`) and `available_at`, and records a pending review. A file the
  upstream index does not list answers `404 age_gate_unlisted`: the gate cannot
  date it, so it is not fetched. An approved review lets that version through
  early and a rejected one keeps it out whatever its age; decisions take
  effect on the next request.
- **Why is X withheld.**
  `GET /api/v1/repositories/{key}/age-gate/conda/withheld?subdir=noarch[&filename=...]`
  lists each withheld file with its reason, basis and date. The review queue
  is the existing `/api/v1/repositories/{key}/age-gate/reviews`.
- **When records are released.** The gated document is rebuilt whenever the
  Remote's cached upstream repodata is revalidated (the Remote's metadata
  TTL) and served from memory in between, so a record appears at most one
  revalidation after it crosses the threshold.
- **Not filtered.** `channeldata.json`, `run_exports.json` and
  `patch_instructions.json` stay the upstream's. A gated Remote's
  `repodata.json.sig` answers 404, because the upstream signature no longer
  covers the filtered document.

Operational notes: the ledger lives in `conda_first_seen_channels` and
`conda_record_first_seen` (migration 427). A rebuild writes only files not
seen before and reads back only the post-baseline sightings inside the gate
window. `CONDA_AGE_GATE_KNOWN_CACHE_MAX_BYTES` (default 256 MiB) bounds the
in-memory sets of recorded files the cache keeps across channels (least
recently used first); a set a running rebuild still uses stays alive until
that rebuild ends, so the peak is the bound plus the sets of the rebuilds in
flight. A repoint's prune bumps the channel's ledger generation, so every
replica reloads its set.
The gated document is kept by the same merge cache as Virtual merges
(`CONDA_VIRTUAL_MERGE_*`).
