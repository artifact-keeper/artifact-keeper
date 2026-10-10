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

The probes run at the same time, each with a 2 second deadline, and share the
5 second result cache that `/health` uses, so polling `/readyz` does not add
load on the dependencies and a dead dependency cannot make the probe slow.

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
