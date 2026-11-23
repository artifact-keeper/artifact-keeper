# Warming a conda Remote from a lockfile (#4184)

A fleet of CI jobs that installs one locked environment from a Remote whose
cache is cold sends every package's first request upstream, from every job at
once. Warming fetches the environment's pinned packages into the Remote's
proxy cache beforehand, so the fleet is served from the cache.

## 1. Store the environment

Ingest the lockfile once (`pixi.lock` or `conda-lock.yml`):

```bash
curl -X POST "$AK/api/v1/repositories/conda-internal/environments?filename=pixi.lock&name=ci-env" \
  -H "Authorization: Bearer $TOKEN" --data-binary @pixi.lock
# -> {"id": "<environment id>", ...}
```

The stored environment records each package's URL and sha256. An environment
ingested before 1.13.0 has neither: ingest it again before warming from it.

## 2. Start the warm

```bash
curl -X POST "$AK/api/v1/conda/conda/warm" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"environmentId": "<environment id>", "platform": "linux-64"}'
```

`{repo}` is a conda **Remote**, or a **Virtual** whose Remote members are
warmed. `platform` is optional and defaults to every platform the lock
resolves. The answer is `202` with the job, or `200` with the job already
running for the same environment and platform.

Each pinned URL is mapped to the Remote that serves it:

- a URL on this server's conda route for `{repo}`
  (`https://<host>/conda/<repo>/<subdir>/<file>`, any host, token layouts
  included). On a Virtual, the Remote members are tried in priority order and
  the first that has the file fills its cache, as a download through the
  Virtual would. A name a hosted member owns is skipped (`not_remote`), and so
  is a file the Virtual's allowlist does not admit (`not_allowed`);
- a URL on the route of one Remote member: that member;
- a URL under a Remote's `upstream_url`, for a lock solved against the
  upstream channel itself: that Remote.

Anything else is `not_remote` and is never fetched. A warm never contacts the
host a lockfile URL names. It asks the Remote for `<subdir>/<file>`.

## 3. Follow it

`GET /api/v1/conda/{repo}/warm/{id}` returns the job's `status` (`pending`,
`running`, `completed`, `cancelled`, `budget_exceeded` when it fetched
`CONDA_WARM_MAX_JOB_BYTES`, or `failed` when its runner gave up after repeated
database errors), `total`, `done`, `remaining`,
`bytesFetched`, `skippedNoUrl`, the `counts` per item state, and up to 50
`problems` (items that did not warm):

| State | Meaning |
| --- | --- |
| `fetched` | Fetched through the Remote into its cache by this job. |
| `cached` | A fresh cache entry with the pinned sha256 was already there; not fetched. |
| `held` | Inside the Remote's Package Age Policy hold. Cached under the hold and refused (409) to clients until the hold elapses or an admin releases it. |
| `blocked` | Refused by the scan or origin policy (403). |
| `checksum_mismatch` | The bytes differ from the sha256 the lock pins. Bytes this job fetched are removed from the cache again, so nothing the lock does not pin stays cached and a rerun fetches the file again. An entry a client cached earlier is reported, not removed. |
| `failed` | The upstream does not have it (404 from every Remote), or a fault (including the item deadline) persisted after 3 attempts. |
| `not_remote` | No Remote of `{repo}` serves the URL. |
| `not_allowed` | The Virtual's allowlist does not admit the package. |

`GET /api/v1/conda/{repo}/warm` lists recent jobs. `DELETE
/api/v1/conda/{repo}/warm/{id}` cancels an active job; what is already warm
stays cached.

Metrics: `ak_conda_warm_items_total{outcome}`,
`ak_conda_warm_upstream_fetches_total`, `ak_conda_warm_bytes_total`,
`ak_conda_warm_jobs_running`.

## Warming does not bypass the gates

Each package is fetched through the same Remote fetch path a client's cold
download takes: the inline scan gate when the Remote scans on proxy, the
streaming fill otherwise. A warm of a Virtual uses the scan policy a download
through that Virtual uses: the stricter of the Virtual's and the member's. A
Virtual that scans on proxy therefore scans what it warms even when its Remote
member does not. The age hold, the origin policy and the scan policy
therefore decide what is cached, exactly as for a client. A warm fills the
cache and serves nothing. A warmed entry is an ordinary proxy-cache entry, and
every later serve passes the cache-hit gates (freshness, the hold, the origin
policy, the stored verdict).

## Bounds, idempotency and restarts

| Setting | Default | Meaning |
| --- | --- | --- |
| `CONDA_WARM_CONCURRENCY` | 8 (max 64) | Package fetches in flight per process, across all warm jobs. |
| `CONDA_WARM_UPSTREAM_RPS` | 20 (max 1000) | Upstream fetches started per second per process. Entries already cached cost nothing. |
| `CONDA_WARM_MAX_ITEMS` | 50,000 | Package files one job may warm (`400` beyond). |
| `CONDA_WARM_ITEM_LEASE_SECS` | 600 (30 to 86,400) | How long a claimed item waits before another runner takes it over. |
| `CONDA_WARM_ITEM_TIMEOUT_SECS` | 300 (10 to 3,600) | The most one package may take from its first upstream byte to its cache commit. A slow or trickling upstream gives up its fetch slot at this deadline and the item is retried. The commit wait holds no fetch slot. |
| `CONDA_WARM_MAX_JOB_BYTES` | 107374182400 (100 GiB, at least 1 MiB) | The most bytes one job fetches from upstream. Checked before each fetch, so fetches already in flight may overshoot it. The job then ends as `budget_exceeded`, and what it did not fetch stays unfetched. |

There is at most one active job per (repository, environment, platform).
Starting again after it completes creates a new job, whose items are `cached`
without an upstream request. Jobs and items are stored (migration 425). A
restarted process resumes active jobs a few seconds after startup, and items
claimed by a process that died are taken over once their lease lapses, by any
replica. A runner that stops on a database error retries 5 times with backoff
and then ends the job as `failed`. If the database is still unreachable then,
the job stays active, and the next start or a repeat `POST` runs it again.

## Who may warm

Every warm endpoint needs repository `write` (or the administrator role) on
`{repo}`; a caller who cannot read it gets the unknown-key 404. Warming a
Virtual also needs read access to each of its Remote members, the rule a
download through the Virtual applies. The environment must be one the caller
can read.

## See also

- [cache-seed.md](cache-seed.md): the generic `paths` cache seed (#5284).
  A conda warm goes through the conda format route, so it runs the scan gate
  and walks a Virtual's members, which a `paths` seed does not.
