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

## Probing from inside the container

The backend image's Docker `HEALTHCHECK` runs `artifact-keeper healthcheck`,
which sends `GET /health` to the address in `BIND_ADDRESS` (default
`0.0.0.0:8080`, probed on loopback). It exits `0` on a `2xx` answer and `1`
otherwise, with a 9 second budget for the whole probe. Pass a path
(`artifact-keeper healthcheck /livez`) or an `http://host:port/path` URL to
probe something else, for example in a compose `healthcheck.test`:

```yaml
healthcheck:
  test: ["CMD", "artifact-keeper", "healthcheck", "/livez"]
```

`artifact-keeper healthcheck` needs a 1.12.0 or later image. On an older image
the binary ignores the argument and starts a second server, so a compose file
pinned to an older tag must keep its curl-based healthcheck
(`["CMD", "curl", "-f", "http://localhost:8080/health"]`). The image still
ships `curl`, built without Kerberos, LDAP or SSH support (#5991), so such
healthchecks keep working on 1.12.0 too.

## What `/readyz` checks

`/readyz` is ready when:

- the database answers, and
- at least one migration has applied successfully.

That is the definition of "can serve artifacts": downloads, uploads and
repository metadata need the database and nothing else from this list.

Both are one query, bounded to 1 second and run alongside the dependency
probes below, so with the database down `/readyz` answers `503` in about a
second, inside a 5 second probe timeout (#5651).

From a stop signal on, `/readyz` answers `503` at once with `failing:
["shutting_down"]`, without probing anything, while `/livez` and `/health`
keep their usual answers (#5921). See
[graceful-shutdown.md](graceful-shutdown.md).

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

The generic, Maven and OCI routes, and the package routes that go through the
shared storage error mapping, answer this way. Since 1.12.0 so do the native
routes that used to answer both conditions with a hard-coded `500`, each in its
own error envelope: Alpine, Chef, CocoaPods, Composer, Conda (package download),
Debian, Git LFS, Go, Incus, JetBrains, NuGet, Protobuf (Connect code
`unavailable` / `resource_exhausted`), RPM, sbt, Swift (`problem+json`
`detail`), VS Code and the agent-plugin marketplace. An Incus image whose
background finalize fails on storage records the same fixed wording in the
upload session's `finalize_error`, and the Debian backfill reports a stored
package it cannot read with that wording too.

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

## Health monitor

Besides the probes, one replica (whichever holds the `health_monitor`
scheduler lease) checks the dependencies every 60 seconds and records each
result in the health log and the alert state that
`GET /api/v1/admin/monitoring/health-log` and `GET /api/v1/admin/monitoring/alerts`
return (`POST /api/v1/admin/monitoring/check` runs a check at once). It
records:

| Service name | Checked when | Probe |
|---|---|---|
| `database` | always | one query; also compares `pg_postmaster_start_time()` with the last database check, so a Postgres restart between two checks is recorded as an `unavailable` row stamped with the restart time, followed by the recovery |
| `storage` | always | the `/health` storage check (a HEAD for object stores, a small write for the filesystem), shared with its 5 s cache and 2 s bound |
| `scanner-adapter` | `TRIVY_ADAPTER_URL` is set | `GET /probe/healthy` |
| `scanner-adapter-worker` | `SCAN_WORKER_TRIVY_ADAPTER_URL` is set to a different adapter | `GET /probe/healthy` |
| `trivy` | `TRIVY_URL` is set | `GET /healthz` |
| `opensearch` | `OPENSEARCH_URL` is set | `GET /_cluster/health` |
| `openscap` | `OPENSCAP_URL` is set | `GET /health` |
| `dependency-track` | `DEPENDENCY_TRACK_ENABLED=true` and a URL is set | `GET /api/version` |

The probes run at the same time, each bounded (5 s for HTTP, 2 s for
storage), so a check costs the slowest probe, not the sum.

For alerting, every recorded check also sets the gauge
`ak_health_monitor_up{service}` (1 healthy, 0 not), and each detected
Postgres restart increments `ak_health_monitor_postgres_restarts_total`.
Both are per process, and only the replica that runs a check (the
`health_monitor` lease holder, or the one serving a manual check) updates
them. A replica that held the lease earlier keeps its last values and one
that never held it exports neither, so alert on the restart counter's
`sum(increase(...))` across replicas, and on the up gauge of the current
lease holder only. A
restart is usually over before the next check, so alert on the counter's
`increase()` rather than on the gauge. A restart is recorded once, even when
the scheduled check and `POST /api/v1/admin/monitoring/check` see it
together, and it stamps the database's `last_alert_sent_at` at once instead
of waiting for three consecutive failures. A failover to a standby that has
been up longer than the last check is not detected as a restart. The monitor cannot
write while the database is down, so an outage that ends without a Postgres
restart (a network partition, say) leaves no row in the health log.
