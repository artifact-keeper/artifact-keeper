# Deleting a repository

`DELETE /api/v1/repositories/{key}` runs as a background job (#4311). A
repository with hundreds of thousands of artifacts can take minutes to delete;
the request no longer waits for that, so it is not cut off by a proxy or load
balancer timeout in front of the server.

## What the request does

The request checks the caller's permission (`delete:repositories` scope and
the repository `admin` action), records the job, and renames the repository to
`~deleting~<job id>` in the same transaction. From that moment the original key
no longer resolves (every format route and API call for it answers 404, except
a repeated `DELETE`, below), the repository disappears from
`GET /api/v1/repositories`, it leaves every virtual repository that included it,
and a new repository can be created under the same key. The `~deleting~` key
itself is unreachable through every by-key resolver, the auth visibility
middleware, repository listings and search, so a job that failed halfway cannot
expose a repository that is still being deleted (#5002). The answer is
`202 Accepted`:

```json
{
  "id": "6d0c...",
  "job_type": "repository_delete",
  "status": "pending",
  "phase": "queued",
  "repository_id": "1f3e...",
  "repository_key": "libs-release",
  "total_items": 0,
  "completed_items": 0,
  "failed_items": 0,
  "skipped_items": 0,
  "total_bytes": 0,
  "transferred_bytes": 0,
  "progress_percent": 0.0,
  "status_url": "/api/v1/repository-deletions/6d0c..."
}
```

`Location` carries the same status URL. A second `DELETE`, of the original key
or of the renamed repository, while its job runs returns the job in flight;
once the job has completed, the original key answers 404 (or names the new
repository created under it). The audit event is
written when the delete is requested; the `repository.deleted` webhook event
is emitted when the job completes.

## Polling

`GET /api/v1/repository-deletions/{id}` returns the job in the same shape (that
of a migration job). The requester and instance administrators can read it.

| Field | Meaning |
|---|---|
| `status` | `pending`, `running`, `completed` or `failed` |
| `phase` | `queued`, `collect`, `delete_rows`, `purge`, `cleanup`, `done` |
| `total_items` / `completed_items` | artifacts when the job started / artifact rows deleted |
| `total_bytes` / `transferred_bytes` | their bytes |
| `skipped_items` | stored objects kept because another repository still references them |
| `failed_items` | stored objects whose delete failed (left for storage GC) |
| `error_summary` | the last step failure, if any |

## How the job runs

Each replica runs a worker that claims jobs with a row claim
(`repository_delete_jobs.claim_token`, five-minute lease, renewed while the job
runs), so exactly one replica works on a job. The job that a request creates
starts on that replica at once; a job whose replica died is picked up by
another replica within a minute of its claim lapsing, from the phase it
reached. A step that fails is retried, up to five runs, then the job is marked
`failed`.

1. **collect**: records the keys only the repository's own rows can name: OCI
   manifests and blobs (left to storage GC's candidate sweep), Maven row-less
   objects (checksum sidecars, `maven-metadata.xml`) and the in-flight OCI
   upload temp objects.
2. **delete_rows**: deletes the repository's artifact rows and older revisions
   in batches of 500. Each batch records its storage keys in
   `oci_gc_candidates` in the same transaction, then the repository row itself
   is deleted (the remaining dependent rows cascade).
3. **purge**: for each recorded key, the job takes the key's
   `oci_gc_candidates` slot (the record every upload commit takes first,
   #4980), checks whether any other repository on the same storage references
   the key (a live or trashed artifact, an older revision, a Maven object it
   owns), and deletes the object only if none does. The check runs immediately
   before each delete, so an upload of identical content into another
   repository during the delete keeps its object.
4. **cleanup**: deletes the OCI upload temp objects and, again, the proxy-cache
   subtree of the original key.

The proxy-cache subtree of the original key is purged first, when the job
starts, so a repository created under the freed key does not find the deleted
repository's cached upstream content. Neither purge runs once a repository has
been created under that key: what is cached there is then its own.

A key the job keeps or cannot delete stays recorded in `oci_gc_candidates`;
the storage GC candidate sweep re-checks it after `BLOB_GC_MIN_AGE_SECS` and
deletes it once nothing references it.

## A failed job

A job marked `failed` leaves the repository renamed to `~deleting~<job id>`,
with whatever rows the job had not yet deleted (the rows already deleted have
their storage keys recorded in `oci_gc_candidates`). Fix the cause named in
`error_summary` and delete the repository again, under `~deleting~<job id>` or
under its original key (while no new repository has taken that key); the new
job keeps the original key and resumes the
work, including the purge of the keys already recorded.

## Rolling upgrades

A 1.11 replica does not run delete jobs. During a rolling upgrade, a job
created by an upgraded replica is run by an upgraded replica; until it
completes, a 1.11 replica lists the repository under its `~deleting~` key.
