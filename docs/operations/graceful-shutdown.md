# Graceful shutdown and the drain

When the backend is asked to stop (SIGTERM, Ctrl+C, or a Windows service
stop), it first takes itself out of rotation. With `SHUTDOWN_DRAIN_SECS` set,
it then keeps serving for that many seconds before it closes its listeners, so
a load balancer that learns about the stop a moment late does not send
requests to a closed port, which its proxy would answer with 502 (#5921).

The default is `0`: the listeners close at once, as before 1.13.0. Behind a
Kubernetes Service, an ingress or any other load balancer, set 5-10 s (see
[Choosing a value](#choosing-a-value-and-the-grace-period)).

## Phases

| Phase | Starts | `/readyz` | `/livez`, `/health` | Requests | Background workers |
|---|---|---|---|---|---|
| Drain | the stop signal | `503`, `failing: ["shutting_down"]` | unchanged | served normally, new and in flight | claim no new work (see below) |
| Close | `SHUTDOWN_DRAIN_SECS` later | not reachable | not reachable | in-flight requests finish; no new connections | leases released |
| Exit | the last in-flight request finishes | | | | |

While draining, `/readyz` answers at once without probing anything: every
check and dependency reads `not_checked`.

The log shows each step:

```text
received SIGTERM, starting graceful shutdown
shutdown: draining for 10s; /readyz answers 503, requests are still served, background workers claim no new work (signal again to exit at once)
shutdown: drain over, closing the listeners
HTTP server shut down
shutdown complete released_scheduler_leases=2
```

`ak_shutdown_draining` is `1` from the stop signal on.

**A second SIGTERM or Ctrl+C**, during the drain or while in-flight requests
finish, exits the process at once (status 1) without waiting for them.

**From the stop signal on**, background work winds down without being cut
off, whatever the drain length:

- scheduler leases (lifecycle, storage GC, health monitor, curation sync and
  the other singleton jobs) are not acquired, so another replica runs the
  next tick. A job already running under one is told to stop through its
  lease-loss token and keeps the lease, renewed, while it winds down;
- the webhook delivery worker, the peer sync worker and scheduled backups
  claim nothing new; deliveries, transfers and backups already running
  finish;
- the scan-queue worker, the repository-delete and cache-seed resumers, the
  MCP resolver and registry sync, the RPM repodata builder, the conda shard
  backfill and the npm feed consumer stop as they do on shutdown today.

The work requests still feed (download statistics, the webhook producer,
cache invalidation from other replicas, score refresh) and running migrations
keep going until the listeners close, so a migration started through the API
during the drain is not stopped the moment it starts.

**At the end**, after the last request, the process pauses any migration it
was running (as before). It then waits for the scheduler jobs still running,
up to five seconds after the drain has ended (#6487), and releases the
scheduler leases it still holds, so the next replica claims those jobs on its
next tick instead of waiting out the lease TTL. The lease of a job still
running at that point is kept: it lapses at its TTL, so no other replica
starts the same job while this process may still be doing it, and the log
says how many were left (`running_scheduler_jobs`).

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SHUTDOWN_DRAIN_SECS` | `0` | Seconds to keep serving after the stop signal, with readiness failing. `0` closes the listeners at once, as before 1.13.0. 5-10 s is recommended behind a load balancer. Capped at 300. `SHUTDOWN_DRAIN_SECONDS` is accepted as an alias. |

With the Helm chart, set the drain through `backend.shutdown.drainSecs` or the
exact `backend.env.SHUTDOWN_DRAIN_SECS` key (#6487). The chart derives
`terminationGracePeriodSeconds` from those two values only: a drain supplied
through `environmentSecrets`, `extraEnvFrom` or the `SHUTDOWN_DRAIN_SECONDS`
alias is invisible to the chart. If you use one of those spellings, set
`backend.shutdown.terminationGracePeriodSeconds` explicitly from the formula
below.

## Choosing a value and the grace period

The drain only helps if the load balancer stops sending traffic within it,
and the whole shutdown has to finish before the platform kills the process:

```text
grace period  >  preStop hook (if any)  +  SHUTDOWN_DRAIN_SECS  +  longest request  +  telemetry flush (up to 5 s with OTLP)
```

- **Behind a Kubernetes Service or ingress**: endpoint removal reaches
  kube-proxy and ingress controllers asynchronously, usually within 1-2 s but
  slower on a busy cluster. Set `SHUTDOWN_DRAIN_SECS` to 5-10. The readiness
  probe failing is a second signal for anything that health-checks the pod
  directly.
- **`terminationGracePeriodSeconds`** (default 30) counts from the moment the
  pod is told to stop, including any preStop hook. The default fits a 10 s
  drain with requests of up to about 15 s. Raise it when long downloads or
  uploads must finish: for example a 10 s drain plus uploads of up to 2
  minutes needs at least 135 s, say 150. When the grace period runs out the
  kubelet sends SIGKILL, and the requests still in flight are cut.
- **A preStop hook** is no longer needed for this. If one is configured (a
  `sleep 5`, say), the drain starts after it, because SIGTERM is only sent
  when the hook returns; the two add up, so either keep the hook and lower
  the drain by the same amount, or drop the hook.
- **Docker and Docker Compose**: `docker stop` and `docker compose down` wait
  10 s by default before SIGKILL. With a drain, raise `stop_grace_period` on
  the backend service (or pass `docker stop -t`) above the formula's total.
- **A single replica**: the drain cannot send traffic elsewhere, but it stops
  the `connection refused` (proxy 502) burst on every restart; clients that
  retry on `503` keep working once the new replica is ready.

Example for the pod spec:

```yaml
spec:
  terminationGracePeriodSeconds: 45
  containers:
    - name: backend
      env:
        - name: SHUTDOWN_DRAIN_SECS
          value: "10"
      readinessProbe:
        httpGet:
          path: /readyz
          port: 8080
        periodSeconds: 5
        failureThreshold: 1
      livenessProbe:
        httpGet:
          path: /livez
          port: 8080
```

With `failureThreshold: 1` and `periodSeconds: 5` the kubelet marks the pod
not ready within about 5 s of the stop, which matters only for components that
read pod readiness rather than the endpoint removal that the stop itself
triggers.

See [health-probes.md](health-probes.md) for what the probes check outside a
shutdown.
