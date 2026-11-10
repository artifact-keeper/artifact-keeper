# Health, readiness and liveness probes

Artifact Keeper serves three probe endpoints at the root of the backend, outside
`/api/v1`. They need no authentication, no rate limiter applies to them, and the
global concurrency limit (`GLOBAL_MAX_CONCURRENCY`) never refuses them, so a
replica that is busy with uploads still answers its probes (#4588).

| Endpoint | Meaning | Status codes |
|---|---|---|
| `/livez` | The process is up and can route HTTP. Touches no dependency. | always `200` |
| `/readyz` (alias `/ready`) | This replica can serve artifacts. | `200` ready, `503` not ready |
| `/health` (alias `/healthz`) | Dashboard view of every dependency. | `200` all healthy, `503` otherwise |

Use `/livez` for a Kubernetes liveness probe and `/readyz` for the readiness
probe. Do not use `/health` as a readiness probe: it turns `503` whenever
OpenSearch or storage is unhealthy, which takes every replica out of rotation
at once when a shared dependency fails.

## What `/readyz` checks

`/readyz` is ready when:

- the database answers, and
- at least one migration has applied successfully.

That is the definition of "can serve artifacts": downloads, uploads and
repository metadata need the database and nothing else from this list.

Initial setup (the default admin password not yet changed) is reported as
`checks.setup_complete` but never makes `/readyz` fail, so an operator can
finish setup through `kubectl exec` without the pod being restarted (#889).

## Dependencies

Every `/readyz` response carries a `dependencies` object with one entry for
each dependency `/health` probes (#4610):

```json
{
  "status": "ready",
  "checks": {
    "database": { "status": "healthy" },
    "migrations": { "status": "healthy" },
    "setup_complete": { "status": "complete" }
  },
  "dependencies": {
    "opensearch": { "status": "unhealthy", "required": false },
    "storage": { "status": "healthy", "required": false },
    "scanner": { "status": "not_configured", "required": false },
    "ldap": { "status": "not_configured", "required": false }
  }
}
```

- `status` is `healthy`, `unhealthy` or `not_configured` (the deployment does
  not use that dependency). An OpenSearch that `OPENSEARCH_URL` names but that
  was unreachable when the server started is `unhealthy`: the server then runs
  without search until it is restarted.
- `required` says whether the dependency gates readiness on this deployment.
- `message`, the probe's error text, is only included when
  `EXPOSE_DETAILED_HEALTH=true`, because it can name internal hosts.

The probes run at the same time, each with a 2 second deadline (the storage
probe itself is bounded to the same 2 seconds), and share the 5 second result cache
that `/health` uses, so polling `/readyz` does not add load on the
dependencies and a dead dependency cannot make the probe slow.

A dependency that is unhealthy but does not gate readiness is also named in a
top-level `degraded` list, omitted when nothing is degraded (#5649). That is
storage while the object store is unreachable or full, and likewise
`opensearch`, `scanner` or `ldap` when unhealthy and not required (an
OpenSearch that `READYZ_REQUIRE_SEARCH=true` makes required appears under
`failing` instead):

```json
{
  "status": "ready",
  "degraded": ["storage"],
  "dependencies": {
    "storage": { "status": "unhealthy", "required": false }
  }
}
```

## Storage outages and full storage

Storage never gates readiness: every replica shares the same object store, so
taking them all out of rotation would turn a storage outage into a total one.
Instead the requests that need storage answer promptly with a retryable or a
definite status, and the probes report storage as degraded:

| Condition | Requests answer | `/health` and `/readyz` |
|---|---|---|
| The object store cannot be reached or does not answer in time (stopped MinIO, refused connection, DNS failure, timeout, 502/503/504, throttling) | `503 STORAGE_UNAVAILABLE` with `Retry-After: 1` (OCI: `503 UNAVAILABLE`); with the defaults in about 15-20 s for a control-plane request and about 30 s for an upload or download | storage `unhealthy`: the probe (a HEAD for object stores, a small write for the filesystem) fails or exceeds its 2 s bound |
| The store refuses a write for lack of space (MinIO bucket quota `XMinioAdminBucketQuotaExceeded` / `XMinioStorageFull`, S3-compatible `QuotaExceeded`, HTTP 507, filesystem `ENOSPC` / `EDQUOT`) | `507 STORAGE_FULL` (OCI: `507 INSUFFICIENT_STORAGE`) | storage `unhealthy` for 60 s after the last refused write, then it clears on its own once space is freed |

Neither body carries the store's own error text: the bucket name, request ids
and XML error documents go to the server log only, on every route including
the OCI `/v2` error envelope. `507 STORAGE_FULL` is distinct from
`507 QUOTA_EXCEEDED`, which is Artifact Keeper's own per-repository quota. A
GCS `quotaExceeded` is treated as retryable (`503`), because GCS also answers
it for API-usage quotas. The class is taken from the response status and its
exact error code, never from the message text, so an object named after an
error code cannot change the answer.

The bounds are set in `.env.example`: `STORAGE_CONNECT_TIMEOUT_SECS`
(default 3) for one connection attempt; `STORAGE_OPERATION_TIMEOUT_SECS`
(default 15), the retry budget of an S3 control-plane request (head, exists,
list, delete); and `STORAGE_BULK_RETRY_TIMEOUT_SECS` (default 180), the retry
budget of an S3 upload, download or copy. The S3 client counts a retry budget
from the start of the request, so the payload budget stays long enough for a
long transfer to keep its retries; against a gone store a payload request is
bounded by its fixed 5 retries instead. The pause between retries is capped
at 2 s. Compare a database outage,
which answers `503 DATABASE_UNAVAILABLE` and does make `/readyz` fail.

## Making search part of readiness

By default an unhealthy OpenSearch is reported but does not gate readiness:
artifact serving works without search, and only search and some UI views
degrade. Where search is part of what a replica must provide before it takes
traffic, set:

```
READYZ_REQUIRE_SEARCH=true
```

`/readyz` then answers `503` while OpenSearch is unhealthy, and also when no
OpenSearch is configured, and names it under `failing`:

```json
{
  "status": "not_ready",
  "failing": ["opensearch"],
  "dependencies": {
    "opensearch": { "status": "unhealthy", "required": true }
  }
}
```

A database or migrations failure is a `503` whatever this setting says, and
appears under `failing` as `database` or `migrations`.

Keep in mind that every replica shares the same OpenSearch cluster: with
`READYZ_REQUIRE_SEARCH=true`, an OpenSearch outage takes every replica out of
rotation, including for artifact downloads that would have worked.
