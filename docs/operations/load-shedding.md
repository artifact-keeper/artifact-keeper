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

**Read this first.**

- **Readiness comes from the probe pool, not from the gate.** `/health`
  and `/readyz` query the database through their own pool of
  `DATABASE_PROBE_CONNECTIONS` (default 1). They report whether the
  database answers, not whether the request pool is busy. A replica whose
  request pool is wedged (every connection held by a stuck query or a lock)
  therefore **stays Ready while it sheds every request**.
- **Alerting on the shed rate is required in production.** For example,
  alert when `sum(rate(ak_db_requests_shed_total[5m])) > 0` holds for 10
  minutes, together with `ak_db_pool_connection_failures_total{stage="request"}`.
  A burst sheds for seconds to a minute; a wedged pool sheds until someone
  steps in. The first shed, and then at most one every 5 minutes, also logs
  a WARN that names the knobs below.
- **The gate is for a slow database, not a dead one.** A database that is
  down, refusing connections or failing over still fails each request at
  `DATABASE_ACQUIRE_TIMEOUT_SECS` with `503`, exactly as before 1.13.

Every request needs pooled database connections for its credential check
and its repository and artifact lookups. A replica's pool has
`DATABASE_MAX_CONNECTIONS` of them. Each query is a separate acquire from a
FIFO queue. Once a burst puts far more requests in flight than there are
connections, every acquire of every request waits behind the whole crowd
(#4182). A request's latency becomes the queue wait times its query count,
the same for every request, so the whole burst slows down together. Past
the clients' timeouts nothing completes, and timed-out work is thrown away.

Since 1.13 a router-wide admission gate runs before any authentication,
database or storage work:

- **Slots.** At most `DATABASE_REQUEST_CONCURRENCY` requests (default four
  per pool connection, 200 with the default pool) run their handler phase
  at once. A download's body streams after the handler phase, without
  holding a slot.
- **Waiting.** When every slot is held and the pool is busy, a request may
  queue for a slot for up to `DATABASE_REQUEST_ACQUIRE_WAIT_MS`. Unset, that
  is the pool's own acquire timeout, `DATABASE_ACQUIRE_TIMEOUT_SECS x 1000`
  (5000 ms by default), so the gate only sheds what would have waited that
  long on the pool anyway.
- **Prediction.** Once someone is queued, the gate predicts a newcomer's
  wait: the requests queued ahead, times the moving average of how long a
  slot is held, divided by the slots. A hold longer than the budget counts
  as the budget, so one stuck request doesn't skew the average.
- **Shedding.** A backlog predicted to outlast the budget is answered at
  once with `503 POOL_EXHAUSTED` and a `Retry-After` of 1 to 30 s. The
  `Retry-After` is predicted from the queue plus every client already told
  to come back, so clients that honour it return spread out instead of
  colliding. A request that queues and still gets no slot in time is
  answered the same way. Sheds are counted in `ak_db_requests_shed_total`.
- **No shedding while the pool has room.** If every slot is held but the
  pool has room (connections not yet opened, or a quarter of them idle), a
  request runs without a slot. Slow uploads or upstream fetches holding
  slots never shed anything on their own.

**Fairness between clients (#6344).** Without it, whoever arrives first gets
every slot, so one anonymous flood (a single IP, or a misbehaving CI job)
could hold them all and get everyone else shed. Two rules apply, only while
the pool is busy:

- **Reserved share for credentialed requests.**
  `DATABASE_REQUEST_CREDENTIALED_RESERVE_PERCENT` (default 25) of the slots
  can only be taken by a request that presents a credential: an
  `Authorization` header, `X-API-Key`, `X-NuGet-ApiKey`, the `ak_access_token`
  session cookie, or a `/t/<token>/` path. Anonymous requests share the rest,
  so an anonymous flood is shed before it reaches the reserve. The gate can't
  verify a credential without a database round trip, so this is a hint. A
  request with a forged header takes a reserved slot and is answered `401` by
  authentication. While other clients wait, one address can hold at most its
  per-client share of the slots that way. A flood of forged headers from
  many addresses can still fill the reserve; credentialed clients then
  compete with it first come, first served, as everyone did without the
  reserve. Web-UI logins and other anonymous calls draw from the anonymous
  share.
- **Per-client share under contention.** Requests are keyed by the
  best-effort client IP, the rate limiter's key (`X-Forwarded-For` believed
  only from `RATE_LIMIT_TRUSTED_PROXY_CIDRS`; an IPv6 client by its /64), in
  a fixed table, so memory is
  bounded however many addresses a flood uses. A client that already holds or
  waits for `DATABASE_REQUEST_CLIENT_SHARE_PERCENT` (default 25, one slot per
  pool connection with the default slots) of the slots is shed at once while
  another client is waiting, so the slots it releases go to the others. A
  client alone on a busy pool is never limited by its share. Clients behind
  one NAT or proxy that isn't trusted count as one client.

Fairness sheds are the same `503 POOL_EXHAUSTED` + `Retry-After`, counted in
`ak_db_requests_shed_total` and, by `class` (`anonymous`, `credentialed`) and
`reason` (`backlog`, `client_share`), in `ak_db_admission_sheds_total`. Set
either variable to `0` to turn its rule off; with both at `0` the gate
hands out slots first come, first served.

A shed request has done no work, so it is never let through. Authentication,
authorization and scanning run unchanged for every admitted request, and a
credential check that can't reach the database still answers `503`, never
`2xx`. `/health`, `/healthz`, `/ready`, `/readyz`, `/livez` and the
main-port metrics scrape (`/api/v1/admin/metrics`) are never gated. The
`METRICS_PORT` listener has no gate at all.

A shed is answered before the request body is read. A client sending a body
(an upload or publish) that doesn't wait for `100 Continue` may see the
connection close mid-send, and report a broken pipe or connection reset
instead of the `503`.

**Opting out.**

- No gate: `DATABASE_REQUEST_ACQUIRE_WAIT_MS=0` or
  `DATABASE_REQUEST_CONCURRENCY=0`.
- No fairness: `DATABASE_REQUEST_CREDENTIALED_RESERVE_PERCENT=0` and
  `DATABASE_REQUEST_CLIENT_SHARE_PERCENT=0`.
- Probes on the request pool: `DATABASE_PROBE_CONNECTIONS=0`.

### How package clients retry a 503

The gate relies on clients retrying a `503`. This table gives each
client's defaults, from its upstream documentation or source as of
November 2026. Clients that aren't listed weren't confirmed.

| Client | Retries a 503 | Default retries | Back-off | Honours `Retry-After` | Source |
|---|---|---|---|---|---|
| npm | yes: 408, 420, 429 and any 5xx; not POST or a streaming body | `fetch-retries` 2 | `fetch-retry-factor` 10, `fetch-retry-mintimeout` 10 s, `fetch-retry-maxtimeout` 60 s | not read in make-fetch-happen's retry path | [npm config](https://docs.npmjs.com/cli/v10/using-npm/config), [make-fetch-happen `lib/remote.js`](https://github.com/npm/make-fetch-happen/blob/main/lib/remote.js) |
| conda | yes: 413, 429, 500, 502, 503, 504 | `remote_max_retries` 3 | `remote_backoff_factor` 1 | no (`respect_retry_after_header=False`) | [conda configuration](https://docs.conda.io/projects/conda/en/latest/configuration.html), [`conda/gateways/connection/session.py`](https://github.com/conda/conda/blob/main/conda/gateways/connection/session.py) |
| pixi | yes: any 5xx, plus 408 and 429 | 3 | exponential | no handling found in reqwest-retry | [`pixi_utils/src/reqwest.rs`](https://github.com/prefix-dev/pixi/blob/main/crates/pixi_utils/src/reqwest.rs), [reqwest-retry `retryable_strategy.rs`](https://github.com/TrueLayer/reqwest-middleware/blob/main/reqwest-retry/src/retryable_strategy.rs) |
| rattler | `default_retry_policy` is 3 retries, exponential | 3 | exponential | not confirmed | [`rattler_networking/src/retry_policies.rs`](https://github.com/conda/rattler/blob/main/crates/rattler_networking/src/retry_policies.rs) |
| pip | yes: 500, 502, 503, 520, 527 | `--retries` 5 | `backoff_factor` 0.25 | yes, through urllib3's default (`respect_retry_after_header=True` for 413, 429, 503) | [pip options](https://pip.pypa.io/en/stable/cli/pip/), [`pip/_internal/network/session.py`](https://github.com/pypa/pip/blob/main/src/pip/_internal/network/session.py), [urllib3 `Retry`](https://urllib3.readthedocs.io/en/stable/reference/urllib3.util.html) |
| Maven 3.8 (Wagon transport) | **no** by default: `maven.wagon.http.serviceUnavailableRetryStrategy.class` defaults to `none`; `retryHandler.count` 3 covers I/O errors only | 0 for a 503 | n/a | n/a | [Wagon `AbstractHttpClientWagon.java`](https://github.com/apache/maven-wagon/blob/master/wagon-providers/wagon-http-shared/src/main/java/org/apache/maven/wagon/shared/http/AbstractHttpClientWagon.java), [Wagon HTTP docs](https://maven.apache.org/wagon/wagon-providers/wagon-http/) |
| Maven 3.9.5+ (Resolver 1.9.16+) | yes: 429 and 503 (`aether.transport.http.retryHandler.serviceUnavailable`) | `retryHandler.count` 3 | `interval` 5 s, growing, capped at `intervalMax` 300 s | yes | [Resolver configuration](https://maven.apache.org/resolver/configuration.html), [Maven 3.9.5 release notes](https://maven.apache.org/docs/3.9.5/release-notes.html) |

Maven 3.8 fails a download on the first `503`. A Maven 3.8 fleet that
can't move to 3.9.5 or later should set
`maven.wagon.http.serviceUnavailableRetryStrategy.class=standard`, or run
with the gate off. conda and the reqwest-retry clients back off on their
own schedule rather than the `Retry-After`, so they retry sooner than the
gate suggests. That costs them retries in a long backlog.

### Measured

These runs used `scripts/perf/db-pool-burst.sh`:

- **Load:** 24 installers x 50 fetches in flight, anonymous downloads from
  a public generic repository.
- **Client:** retries a 503 after its `Retry-After` at most 5 times, with a
  30 s timeout per attempt.
- **Backend:** one container with 4 CPUs, `DATABASE_MAX_CONNECTIONS=8`, and
  `GLOBAL_MAX_CONCURRENCY=4096` so the global limit doesn't shed first.
- **Database:** Postgres with every round trip delayed by netem, so the
  burst exhausts the pool.

Before is 1.12.x (main `5d99629`). After is the gate with its defaults
(a 5000 ms budget).

| Run | Installs done | Wall | 2xx p50 / p99 | Other answers | `/readyz` during the burst |
|---|---|---|---|---|---|
| +2 ms, 200 files each, before | 24 / 24 | 37.4 s | 9.25 s / 9.42 s | none | 13 / 13 ok, slowest 3.5 s |
| +2 ms, 200 files each, after (5 runs) | 24 / 24 in 5 of 5 | 42.1 to 43.7 s | 4.69 to 4.79 s / 5.26 to 5.29 s | 1,618 to 1,708 `503` + `Retry-After` | all ok, slowest 0.44 s |
| +8 ms, 50 files each, before | 24 / 24 | 92.6 s | 28.3 s / 29.7 s | 2,240 client timeouts at 30 s | 8 / 13 ok, 5 timed out at 10 s |
| +8 ms, 50 files each, after (2 runs) | 24 / 24 in 2 of 2 | 38.8 / 39.4 s | 5.10 / 5.15 s, 6.01 / 6.04 s | 1,596 / 1,624 `503` + `Retry-After` | all ok, slowest 0.43 s |

**Where queueing would have cleared within the clients' patience** (the
+2 ms pair):

- Served requests take 5.3 s at p99 instead of 9.4 s.
- About a quarter of the attempts are told to retry.
- The fleet takes about 15 % longer (42 to 44 s against 37 s).

**Where it would not** (the +8 ms pair):

- On 1.12.x, every request slowed to the client timeout and that work was
  thrown away.
- With the gate, the same fleet finished in about 40 % of the time, with no
  timeouts and readiness green.

With a 2000 ms budget, clients with 5 retries sometimes ran out of retries
in the +2 ms run (0 to 2 of 4,800 files). That is why the default budget is
the pool's acquire timeout. The gate is the overload backstop, not the
steady state: size the pool and the server for the fleet's burst (below).


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
