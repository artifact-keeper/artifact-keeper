# Disconnected operation: pausing scheduled upstream jobs

Several background jobs contact an upstream on a timer, whether or not a
client asked for anything. On a disconnected (air-gapped) instance, or during
a planned upstream outage, each of them fails on every tick, fills the logs,
and shows up as outbound traffic in an egress proxy log. One switch pauses all
of them (#5288).

## The switch

| How | Value | Effect |
|---|---|---|
| Env `UPSTREAM_JOBS_PAUSED` | `true` / `1` (anything else, or unset, is off) | Pins the switch **on**. The runtime setting cannot resume the jobs while it is set. |
| Runtime setting `upstream_jobs_paused` | `PATCH /api/v1/admin/settings/system` with `{"upstream_jobs_paused": true}` | Pauses or resumes the jobs with no restart. Each write records a `SETTING_CHANGED` audit event. |

The default is off: nothing changes unless an operator turns it on.

`GET /api/v1/admin/settings/system` reports `upstream_jobs_paused`,
`upstream_jobs_paused_source` (`environment`, `database`, `default`, or
`unavailable`) and `upstream_jobs_paused_stored`. The npm feed status endpoint
(`GET /api/v1/admin/npm/upstream-feed/status`) also reports `upstream_jobs_paused`.

Each job checks the switch at the start of every tick, before it does any
network work. A paused tick is skipped and logged at `debug`. Each job logs
once at `info` when it sees the switch change. At startup, if the switch is
on, the backend logs one `warn` line (`event=upstream_jobs_paused`) that names
every paused job. When the switch is turned off, each job resumes on its next
tick and picks up where it stopped: due repositories sync, queued peer
transfers are dispatched, pending advisory deltas are processed, and the npm
feed resumes from its stored cursor.

If the setting cannot be read (for example, the database is unreachable), the
jobs are treated as paused until a read succeeds. A database error never
starts outbound work that an operator turned off.

## Jobs the switch pauses

| Job (`job` log field) | What it contacts | Code |
|---|---|---|
| `curation_sync` | Each Staging repository's upstream metadata, and the popularity lookups (`pypistats.org`, `api.npmjs.org`) made while evaluating it. Runs every 5 min for repositories past `curation_sync_interval_secs`. | `backend/src/services/scheduler_service.rs`, "Curation upstream metadata sync" |
| `environment_reeval` | OSV (`query_osv_detailed`), when advisory deltas are pending. Runs every 60 s. | `backend/src/services/scheduler_service.rs`, "Environment advisory re-evaluation" |
| `npm_upstream_feed` | npm's replication feed (`NPM_UPSTREAM_FEED_URL`), when `NPM_UPSTREAM_FEED_ENABLED=true`. While the switch is on, the consumer also releases its leadership. | `backend/src/services/upstream_feed.rs`, `FeedConsumer::run` |
| `peer_sync` | Peer instances: push and mirror replication transfers, and the scheduled `mirror` passes that queue them (#5342). Queued tasks stay queued; a schedule that comes due while paused runs once after resume. Runs every 10 s (schedules checked every 60 s). | `backend/src/services/sync_worker.rs`, `spawn_sync_worker` |
| `mcp_remote_sync` | The upstream MCP registry of each Remote MCP repository. The per-repository cursor survives a paused tick, so the sync resumes from it. | `backend/src/services/mcp_remote.rs`, `spawn` |

## Popularity lookups: an internal mirror, or off

The popularity lookups also run at request time, when a curation `popularity`
rule evaluates a package, so the switch above does not cover all of them. Two
env vars set where they go:

| Variable | Default | `off` |
|---|---|---|
| `CURATION_POPULARITY_PYPI_URL` | `https://pypistats.org` | No PyPI lookups |
| `CURATION_POPULARITY_NPM_URL` | `https://api.npmjs.org` | No npm lookups |

Any other value is used as the base URL, for example an internal mirror of
the same API. With `off`, every lookup for that ecosystem answers "unknown" at
once instead of waiting out a connect timeout. A `popularity` rule treats an
unknown count as its rule says (flag for review, by default), so on a
disconnected instance disable such rules or accept that new packages are
flagged.

## Scheduled jobs the switch does not pause

These jobs keep running. Either they are purely local or they contact
services the operator configured inside the deployment, not an upstream:

- Peer heartbeat probes and stale-peer detection (`sync_worker.rs`). These are
  liveness checks between peers. To stop the probes, set
  `PEER_HEARTBEAT_ENABLED=false`.
- Webhook delivery retries (`scheduler_service.rs`). They go to endpoints that
  an administrator registered.
- Health monitor (`scheduler_service.rs`). It probes the configured Trivy,
  OpenSearch, OpenSCAP and Dependency-Track sidecars.
- LDAP directory reconcile, password-expiry email (SMTP), scheduled backups,
  storage scrub, and OpenTelemetry export (`OTEL_*`). These go to services
  configured for the deployment.
- Garbage collection, lifecycle policies, retention passes, metrics and
  storage-stats snapshots, sync-policy re-evaluation, the age-gate sweep,
  upload cleanup, and the rest of the local maintenance jobs.

Request-time proxy fetches are out of scope. A Remote repository still asks
its upstream when a client requests something that is not cached. To stop
that, put the Remote in cache-only mode (`PUT
/api/v1/repositories/{key}/upstream-mode`, or `PROXY_UPSTREAM_MODE=cache_only`
for every Remote, #5282); see
[Proxy cache freshness](../proxy-cache-freshness.md#cache-only-offline-mode-upstream_mode-5282).

## Adding a scheduled upstream job

Add the job's name to `PAUSABLE_JOBS` in
`backend/src/services/upstream_pause.rs`. Build an
`UpstreamPauseGate::new(upstream_pause::<JOB>)` before the loop, and skip the
tick when `gate.skip_tick(&db).await` returns `true`. Then add a row to the
structural test `every_pausable_job_consults_the_gate`. That test fails when a
listed job's loop stops asking the gate before it does its upstream work.
