# Overload, load shedding and CPU sizing

How the backend behaves when it gets more work than its CPU can serve, and
how to size a replica so overload shows up as a status code a client retries
instead of a hung or failed connection (#4647).

## The three places a request can wait

1. **Kernel accept queue.** The kernel holds completed TCP handshakes until
   the process accepts them. Its length is `HTTP_LISTEN_BACKLOG`; unset (the
   default) asks for the OS maximum, which Linux caps at
   `net.core.somaxconn` (4096 on current kernels; 128 on kernels before
   5.4). The value the kernel grants is logged at startup ("HTTP listener
   accept backlog"); `ss -ltn` shows it in the `Send-Q` column. When this
   queue is full, Linux **drops** new SYNs (with the default
   `net.ipv4.tcp_abort_on_overflow=0`), so the client's connect stalls and
   retransmits. It does not get a fast refusal.
2. **Global concurrency limit.** `GLOBAL_MAX_CONCURRENCY` (default 512) is the
   number of requests served at once, excluding health and readiness probes.
   A request over the limit is answered **immediately** with `503` and
   `Retry-After`; it never queues. This is the outermost application layer,
   so a shed request does no authentication, database or storage work.
3. **In process.** Below the limit, every accepted request runs. When the CPU
   limit is the bottleneck, they all slow down together.

Some expensive work sheds on its own limits inside the process. Virtual conda
channel merges are capped by `CONDA_VIRTUAL_MAX_CONCURRENT_MERGES` and answer
`503` with `Retry-After` after `CONDA_VIRTUAL_MERGE_QUEUE_SECS`; a merged
document that is being rebuilt is served stale for up to
`CONDA_VIRTUAL_MERGE_MAX_STALE_SECS` instead of making clients wait on the
rebuild ([Sizing memory for virtual conda
channels](conda-virtual-merge-memory.md)).

## Measured behaviour

Debug build on one host, the API listener under a systemd `CPUQuota=20%`.
Each client opens a new connection per request (`Connection: close`) and
sends `GET /api/v1/repositories` for 20 s.

| Clients | `GLOBAL_MAX_CONCURRENCY` | `HTTP_LISTEN_BACKLOG` | Result |
|---|---|---|---|
| 200 | 512 | default (4096) | 100% answered, p50 0.98 s, p99 6.3 s; no connect failures |
| 200 | 16 | default (4096) | 96% `503` + `Retry-After` (p50 0.30 s), 4% served; no connect failures |
| 1000 | 16 | default (4096) | 96% `503` + `Retry-After` (p50 1.6 s), 4% served; no connect failures |
| 1000 | 512 | default (4096) | 78% `503` + `Retry-After` (p50 1.1 s), 22% served; no connect failures |
| 1000 | 512 | 8 | 23% connect timeouts (5 s), 26% response timeouts, 51% served |

The backend's own listener did not refuse a connection in any run. With the
default backlog, overload became `503` + `Retry-After` once concurrency
passed the limit. Below the limit it showed up as latency. A deliberately tiny
backlog shows what a full accept queue looks like: connect **timeouts**, not
refusals.

So a connection that is refused within milliseconds (the symptom in #4647) is
not the backend's accept queue overflowing. Look at what sits between the
client and the pod: an ingress or gateway with its own connection or
pending-request limits, a `kubectl port-forward`, or a load balancer whose
health check briefly removed the endpoint.

## Sizing guidance

- **CPU.** For mixed CI-fleet load (many formats publishing and fetching at
  once), give each backend replica at least 8 cores, or set a CPU *request*
  without a CPU *limit*. In the #4647 release-gate run, 42 concurrent
  mixed-format clients saturated a 4-core limit, and the same load on 8 cores
  peaked below 3 cores of use. CFS throttling at a hard limit stalls the whole
  process, including the accept loop, for the rest of each period.
- **`GLOBAL_MAX_CONCURRENCY`.** The default of 512 is sized so it never
  throttles legitimate parallel traffic on a well-provisioned replica. On a
  CPU-limited replica it is rarely reached, so overload shows up as latency
  and then as client or gateway timeouts. If you would rather clients see a
  fast `503` + `Retry-After`, lower it toward the concurrency the replica
  serves at acceptable latency, for example 32 to 64 per core. Every
  byte-transfer request also holds a permit, so leave room for your
  concurrent uploads and downloads.
- **`HTTP_LISTEN_BACKLOG`.** Leave it unset unless you have a reason. If
  `net.core.somaxconn` in the pod's network namespace is low (128 on older
  kernels), raise the sysctl (for example via the pod `securityContext.sysctls`
  where your cluster allows it) and then, if you want an explicit value, set
  `HTTP_LISTEN_BACKLOG` to at most that.
- **Gateway in front.** Make the gateway's upstream timeout longer than the
  backend's `GLOBAL_REQUEST_TIMEOUT_SECS` (120 s), and make sure it passes the
  backend's `503` and `Retry-After` through rather than turning upstream
  overload into a connection error.

## Database admission under a burst

Every request needs pooled database connections (credential check,
repository and artifact lookups), and a replica's pool has
`DATABASE_MAX_CONNECTIONS` of them. Each query is a separate acquire from a
FIFO queue, so once a burst puts far more requests in flight than there are
connections, every acquire of every request waits behind the whole crowd
(#4182). Latency becomes the queue wait times the query count, the same for
every request, so the whole burst slows down together: past the clients'
timeouts nothing completes, and a request whose acquire reaches
`DATABASE_ACQUIRE_TIMEOUT_SECS` (5 s) gets `503 POOL_EXHAUSTED` only then.
`/readyz`, which queried the same pool, waited out the same timeout and
reported the replica not ready.

Since 1.13 a router-wide admission gate runs before any authentication,
database or storage work. At most `DATABASE_REQUEST_CONCURRENCY` requests
(default four per pool connection, 200 with the default pool) run their
handler phase at once; a download's body streams after the handler phase,
without holding a slot. When every slot is held and the pool is busy, a
request waits up to `DATABASE_REQUEST_ACQUIRE_WAIT_MS` (default 500) for one
and is otherwise answered at once with the same `503 POOL_EXHAUSTED` body
and `Retry-After: 1`, counted in `ak_db_requests_shed_total`. An admitted
request queues behind at most the other slot holders, so it finishes in a
bounded time; the rest are told to back off instead of waiting. When every
slot is held but the pool has room (connections not yet opened, or a quarter
of them idle), a request runs without a slot, so slow uploads or upstream
fetches holding slots never shed anything on their own.

Package clients (pip, npm, Maven, Docker, rattler, conda, mamba) retry a
503. A shed request has done no work, so it is never let through:
authentication, authorization and scanning run unchanged for every admitted
request, and a credential check that cannot reach the database still answers
`503`, never `2xx`.

`/health` and `/readyz` are never gated, and they read the database through a
separate pool of `DATABASE_PROBE_CONNECTIONS` (default 1), so they report
whether the database answers rather than whether the request pool is busy.
A replica that is saturated but healthy stays in its Service.

To keep the behaviour before 1.13: `DATABASE_REQUEST_ACQUIRE_WAIT_MS=0` or
`DATABASE_REQUEST_CONCURRENCY=0` (no gate), `DATABASE_PROBE_CONNECTIONS=0`
(probes share the request pool).

Measured with `scripts/perf/db-pool-burst.sh` (24 installers x 50 fetches in
flight, anonymous downloads from a public generic repository, clients retry a
503 after its `Retry-After` up to 30 times, 30 s client timeout per attempt).
One backend container (4 CPUs, `GLOBAL_MAX_CONCURRENCY=4096` so the global
limit does not shed first, `DATABASE_MAX_CONNECTIONS=8`), Postgres with every
round trip delayed by netem to make the burst exhaust the pool. Before is
1.12.x (main `5d99629`), after is this change with its defaults.

| Run | Installs done | Wall | 2xx p50 / p99 | Other answers | `/readyz` during the burst |
|---|---|---|---|---|---|
| +2 ms, 200 files each, before | 24 / 24 | 37.1 s | 9.19 s / 9.31 s | none | 13 / 13 ok, slowest 3.5 s |
| +2 ms, 200 files each, after | 24 / 24 | 39.0 s | 0.75 s / 1.00 s | 23,759 `503` + `Retry-After`, p50 0.50 s | 76 / 76 ok, slowest 0.39 s |
| +8 ms, 50 files each, before | 24 / 24 | 92.6 s | 28.3 s / 29.9 s | 2,218 client timeouts at 30 s | 8 / 13 ok, 5 timed out at 10 s |
| +8 ms, 50 files each, after | 24 / 24 | 35.9 s | 1.44 s / 2.05 s | 13,289 `503` + `Retry-After`, p50 0.50 s | 65 / 65 ok, slowest 0.41 s |

Throughput is set by the database either way (about 125 to 130 files a second
in the first pair), so where the burst stays inside the clients' patience the
gate moves the waiting from the server to the clients' back-off: served
requests drop from 9 s to under 1 s, the fleet finishes in about the same
time, and readiness stays fast. Where it does not (the second pair), every
request on 1.12.x slowed to the client timeout, timed-out work was thrown
away, and readiness failed; with the gate the same fleet finished 2.6x
sooner with no timeouts. The trade-off: a client with a small retry budget
gives up sooner on 503s than on a slow answer (with 5 retries instead of 30,
the first pair's installs did not finish), so give a fleet a pool and server
sized for its burst (below) and treat the gate as the overload backstop, not
the steady state.

## Conda package downloads under an installer fleet

rattler-based installers (pixi, micromamba, conda with the libmamba solver)
fetch up to 50 packages at once each, so N installers put up to 50 x N
package requests in flight. A hosted package request reads the database once
(#4181) and then streams from storage without holding a connection, so the
pool only has to cover the lookups, not the transfers.

The lookup takes its connection through a fast-fail gate (#4182): when no
pooled connection frees up within `CONDA_PACKAGE_DB_WAIT_MS` (default 500),
the request is answered at once with `503` and `Retry-After: 1` instead of
queueing until `DATABASE_ACQUIRE_TIMEOUT_SECS` (5 s) runs out. rattler, conda
and mamba retry a 503, so a shed request costs the installer one short
back-off rather than a 5 s stall. Shed requests are counted in
`ak_conda_package_requests_shed_total`; `0` turns the gate off and the pool's
own acquire timeout applies. Remote and Virtual package requests make further
database calls after the lookup (cache catalog, member resolution, download
records) on the normal pool.

Sizing for a fleet. These figures are reasoned from the request path and
the defaults, not measured: unlike the table under Measured behaviour, no
fleet run has confirmed them yet. The fleet measurements are tracked in
#4188; treat the numbers below as a starting point and check them against
`ak_conda_package_requests_shed_total` and the pool metrics on your own
deployment.

- **Pool per replica.** A hosted lookup holds a connection for about one
  round trip (well under 5 ms on a local network), so a pool of 50 serves on
  the order of 10,000 lookups per second before requests start to queue.
  Shedding in steady state therefore means something else holds the
  connections: long transactions, slow storage reads in other handlers, or
  `DATABASE_MAX_CONNECTIONS` set far below the default.
- **Postgres `max_connections`.** Keep `DATABASE_MAX_CONNECTIONS` x replicas,
  plus one surge replica and the connections other clients hold, below the
  server's limit (see the database connection budget below). For 24
  installers against two replicas, the defaults (2 x 50 + 50 surge) need a
  server limit of at least 160; raise `max_connections` or lower
  `DATABASE_MAX_CONNECTIONS` rather than adding replicas.
- **Global concurrency.** Every package download holds a
  `GLOBAL_MAX_CONCURRENCY` permit for the whole transfer. 24 installers x 50
  fetches is 1,200 transfers, above the default 512 for one replica, so either
  run three or more replicas or raise the limit on a replica with the CPU and
  network to serve it.
- **What to watch.** A sustained non-zero
  `rate(ak_conda_package_requests_shed_total[5m])` with installs still
  completing is the gate doing its job under a burst; a rate that does not
  fall after the burst means the pool is undersized for the load.

## Hosted conda repodata regeneration

The first request for a hosted conda subdir's documents after a change
renders them once and keeps them (see
[conda-hosted-repodata.md](conda-hosted-repodata.md)); concurrent requests
for the same subdir wait for that one render. Across subdirs and
repositories, `AK_CONDA_REGEN_CONCURRENCY` (default 2) renders run at once
per process, so a fleet refreshing many subdirs after a bulk publish cannot
put every core on JSON encoding and compression. A request that has waited
`AK_CONDA_REGEN_WAIT_SECS` (default 30) for its render is answered `503` with
`Retry-After: 5`; the render keeps running and its result serves the next
requests. Those 503s count in `ak_conda_repodata_requests_shed_total`, and
`ak_conda_repodata_regenerations_in_flight` shows the renders running now.
`AK_CONDA_REGEN_WAIT_SECS=0` waits as long as the render takes.

## Buffered metadata memory budget

Proxied metadata that has to be held in memory before it is answered (npm
packuments, the PyPI simple index, Debian `dists`, Helm indexes, VS Code
gallery queries, conda virtual merges) reserves bytes from one process-wide
budget, `AK_PROXY_METADATA_BUDGET_BYTES` (default 1 GiB). When the budget is
held by in-flight requests, a new request waits for room; the callers that
bound their wait (conda virtual merges, VS Code gallery queries) answer `503`
with `Retry-After` instead.

The budget is accounted in 4 KiB units: a reservation is rounded up to a
whole unit, and a single request larger than the whole budget holds all of it
rather than waiting forever. Any value the platform can address is honoured.
Before 1.11.5, a value above 4 GiB was silently clamped to 4294967295 bytes
(#4881), which also capped the default `CONDA_VIRTUAL_MAX_CONCURRENT_MERGES`
at 3. A blank, non-numeric or zero value falls back to the default; that, or
a value too large to represent, logs a warning at startup naming the
configured and effective values. The effective value is in the
`conda virtual merge gate configured` log line (`budget_bytes`), printed when
the first virtual conda merge runs. Sizing against the container memory limit
is in [conda virtual merge memory](conda-virtual-merge-memory.md).

## Download verification memory budget

A download that checks stored bytes against their recorded SHA-256 (see
[download integrity](download-integrity.md)) reads an object of at most
4 MiB whole and checks it before the response status is sent, then holds it
until the client has read it. Those buffers draw on one process-wide budget,
`AK_SERVE_VERIFY_BUFFER_BUDGET_BYTES` (default 256 MiB), separate from the
metadata budget above (#4989). The global concurrency limit does not bound
them: a request's permit is released when its response starts, and the body
is sent after that, so before this budget the total was set only by how many
connections clients kept open.

When the budget has no room, a download does not wait. It is checked while it
streams, as an object over 4 MiB always is: a corrupt object is still never
delivered complete, but the transfer is aborted instead of answered `502`.
`ak_serve_verify_buffer_bytes_reserved` reports the budget in use and
`ak_serve_verify_buffer_fallback_total` counts the downloads that streamed for
lack of room; a steady rate means the budget is too small for the load. The
budget uses the same 4 KiB accounting, and the same blank, zero and overflow
handling, as `AK_PROXY_METADATA_BUDGET_BYTES`.

## Database connection budget

Every replica opens its own pools, so size the fleet against the server
(#4549, #4182). Per replica, in the worst case:

```
C_replica = DATABASE_MAX_CONNECTIONS            request pool (default 50)
          + DATABASE_PROBE_CONNECTIONS          health/readiness pool (default 1)
          + PROXY_SINGLEFLIGHT_LOCK_MAX_CONNECTIONS
                                                proxy single-flight lock and wait
                                                sessions held outside the pool
                                                (default 33; only while Remote
                                                repositories are fetching)
```

and for the server:

```
(replicas + surge) x C_replica
  + superuser_reserved_connections (Postgres default 3)
  + every other client (migration job, backups, monitoring, psql)
  <= max_connections
```

`surge` is the extra pods a rollout starts before old ones stop: `0` with the
chart's default `strategy.type: Recreate`, `maxSurge` (usually 1) with
`RollingUpdate`, and the HPA's `maxReplicas` replaces `replicas` when
autoscaling is on.

| Deployment | Per replica | Server needs | Stock `max_connections = 100`? |
|---|---|---|---|
| 1 replica, Recreate, no Remote repositories | 50 + 1 = 51 | 54 | fits |
| 1 replica, Recreate, Remote repositories | 50 + 1 + 33 = 84 | 87 | fits, barely |
| 2 replicas, RollingUpdate (`maxSurge` 1) | 84 | 3 x 84 + 3 = 255 | no: lower `DATABASE_MAX_CONNECTIONS` to 20 (3 x 54 + 3 = 165) and raise `max_connections` to 200 |
| 3 to 20 replicas (HPA), RollingUpdate | 84 | 21 x 84 + 3 = 1767 | no: an RDS `db.r6g.large` (about 1,800 by default) barely fits; lower `DATABASE_MAX_CONNECTIONS` or put a pooler such as PgBouncer in front |

How big the request pool needs to be is Little's law: the connections busy at
once are the request rate times the database time each request holds a
connection for. A hosted package download (#4181) holds one for a single
round trip, about 1 ms on a local network, so one replica at 2,000 requests a
second keeps about two connections busy, and a pool of 20 has ten times the
headroom. A request that makes several queries, or a database a few
milliseconds away, multiplies that. When the pool you can afford is smaller
than the burst needs, the admission gate above sheds the excess as
`503` + `Retry-After` instead of letting it queue; a sustained
`rate(ak_db_requests_shed_total[5m])` after the burst has passed is the signal
to raise the pool (and the server limit with it), not something to tune the
gate for.

Every pool connection arms
server-side TCP keepalives (15 s idle, 5 s interval, 3 probes) with a query
right after connect, so sessions left behind by a force-killed pod are
reaped in about 30 s. `DATABASE_TCP_KEEPALIVES=false` turns this off. Behind
a pooler in transaction mode (PgBouncer, RDS Proxy) the setting may not
reach the server session that serves later queries; configure keepalives
on the pooler or in `postgresql.conf` instead. A failure to set them is
logged once at warn and never fails the connection.

A database that stays down at startup fails the process after at most five
connect attempts (each bounded by `DATABASE_ACQUIRE_TIMEOUT_SECS`) and no new
attempt after about 60 s, roughly 40 s with the defaults.

`ak_db_pool_connection_failures_total{stage}` counts pool connection
failures:

| `stage` | Counted when |
|---|---|
| `startup` | An initial connect attempt failed at boot. Startup retries up to five times with a jittered 1 to 8 s backoff, so a refusal storm shows several increments before the process exits or recovers. |
| `request` | A pool acquire timed out while serving a request and the client was answered `503 POOL_EXHAUSTED`. Since 1.13 most saturation is shed at the admission gate first and counted in `ak_db_requests_shed_total` instead; alert on both. |

The `startup` series is exported once the replica has started serving, so it
shows how many connect attempts a replica that did come up needed; a replica
that gave up exits before it can be scraped, and its attempts are in its log.
Before 1.11.5 the `startup` series was never exported, because the attempts
were counted before the Prometheus recorder was installed (#4828).

A sustained non-zero `rate(ak_db_pool_connection_failures_total{stage="request"}[5m])`
means the pool is too small for the load, or the server is refusing new
sessions; the server's `FATAL: sorry, too many clients already` lines appear
only in the Postgres log.
