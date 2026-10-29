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

Every replica opens its own pool, so size the fleet against the server
(#4549): `DATABASE_MAX_CONNECTIONS` x replicas, plus the single-flight
lock/wait connections held outside the pool (capped per replica by
`PROXY_SINGLEFLIGHT_MAX_LOCK_WAITERS`), plus one rolling-update surge
replica, must stay below Postgres `max_connections`. The defaults
(3 x 50 = 150) do not fit a stock server's 100. Every pool connection arms
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
| `request` | A pool acquire timed out while serving a request and the client was answered `503 POOL_EXHAUSTED`. |

The `startup` series is exported once the replica has started serving, so it
shows how many connect attempts a replica that did come up needed; a replica
that gave up exits before it can be scraped, and its attempts are in its log.
Before 1.11.5 the `startup` series was never exported, because the attempts
were counted before the Prometheus recorder was installed (#4828).

A sustained non-zero `rate(ak_db_pool_connection_failures_total{stage="request"}[5m])`
means the pool is too small for the load, or the server is refusing new
sessions; the server's `FATAL: sorry, too many clients already` lines appear
only in the Postgres log.
