# Seeding a Remote's proxy cache (#5284)

A Remote repository caches what clients ask for. To prepare an instance for
disconnected use you would otherwise have to replay every client install
against it and hope the replay touched every file. A **cache seed** fetches a
list of paths into the cache on the server and reports, per path, what
happened.

This release implements the generic `paths` manifest on a Remote repository.
The typed manifests (`pypi-requirements`, `npm-lockfile`, `oci-images`,
`hf-models`) and seeding a Virtual through its Remote members are planned
(#5284) and answer `400` for now.

## Start a seed

```bash
curl -X POST "$AK/api/v1/repositories/maven-remote/cache/seed" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{
        "kind": "paths",
        "content": [
          "org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar",
          "org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.pom"
        ],
        "options": {"concurrency": 4}
      }'
```

`content` is a JSON array of repository-relative paths, or the same list as
newline-separated text (`"content": "a/b.jar\nc/d.pom\n"`). Blank lines and
lines starting with `#` are skipped, a leading `/` is dropped, and a repeated
path is seeded once. A path is the same one a client downloads with
`GET /api/v1/repositories/{key}/download/{path}`; a routing rule on the
repository rewrites it exactly as it rewrites that download.

| Option | Default | Bounds |
| --- | --- | --- |
| `concurrency` | 4 | 1 to 16 items fetched at once |
| `max_total_bytes` | unbounded | once the job has fetched this many bytes, the remaining items are `refused` |

A request lists at most 10,000 paths (after duplicates are dropped), each at
most 4096 bytes long. The caller needs the `write:repositories` scope and
`admin` on the repository (or the administrator role), like
`cache/invalidate` and `cache-ttl`.

The answer is `202` with the job id:

```json
{"job_id": "…", "status": "pending", "total_items": 2, "duplicates_ignored": 0,
 "status_url": "/api/v1/repositories/maven-remote/cache/seed/…", "…": "…"}
```

## Read the inventory

`GET /api/v1/repositories/{key}/cache/seed/{job_id}` (scope
`read:repositories`, repository `admin`) returns the job's `status`
(`pending`, `running`, `completed`, `failed`), a `summary` of counts and one
`items` row per requested path, in request order:

| `state` | Meaning |
| --- | --- |
| `pending` | Not processed yet. |
| `cached` | Fetched from the upstream and committed to the cache. `size_bytes` and `checksum_sha256` are the cached entry's. |
| `already_cached` | A fresh cache entry existed, so the upstream was not contacted. `checksum_sha256` is the cached entry's. |
| `refused` | A gate refused the item and nothing was cached; `reason` names it. |
| `failed` | The upstream or the cache write failed; `status` is what a client would have been answered (404 for an upstream miss, 503 for an upstream 5xx, 502 otherwise) and `reason` says more. |

Because the rows keep request order and carry the checksum, the inventories
of two runs of the same manifest can be diffed. Running a seed again is a
no-op for what is cached: those items come back `already_cached` without an
upstream request.

## A seed is not a way around curation

Every item is fetched through the same proxy entry as a client's download
through the generic download route, on the same cache key, so:

- the repository's **upstream filter** (`/upstream-filter`, #840) refuses a
  path before any request (`refused`, "excluded by the repository's upstream
  filter");
- the repository's **origin policy** (#4506) refuses the whole job's items;
- a **Package Age Policy** hold is reported `refused`;
- an object over the repository **quota** or **proxy-cache cap**
  ([proxy-cache-cap.md](proxy-cache-cap.md)) is served without caching and
  reported `refused`;
- a repository that **scans on proxy** serves an enforced format's files only
  through its format route (#4442), so a `paths` seed refuses every item of
  it. Format-aware seed kinds, which will run the scan gate, are planned.

## Restarts and replicas

The job and its items are stored (`proxy_cache_seed_jobs`,
`proxy_cache_seed_items`, migration 329). A running job holds a claim that
it renews; every replica looks for pending jobs and lapsed claims once a
minute and resumes them from the items still `pending`. After a restart the
job therefore continues once its previous claim lapses (up to five minutes).
A job whose run itself failed (for example the database was unreachable) is
retried, and marked `failed` after five runs; items keep the results they
reached.

Each completed job writes one `CACHE_SEEDED` audit row with its counts (see
[audit-events.md](audit-events.md)).

## See also

- [proxy-cache-freshness.md](proxy-cache-freshness.md): how long cached entries
  stay fresh, and `cache/invalidate`.
- `backend/src/api/handlers/repositories/cache_seed.rs`: the job, the manifest
  parser and the item classification.
