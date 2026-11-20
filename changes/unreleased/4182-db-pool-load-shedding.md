---
section: Changed
issues: [#6349, #4182]
---
- **Under a burst on a slow database, operators may now see `503 POOL_EXHAUSTED` with a `Retry-After` from a new admission gate, where requests used to slow down together until clients timed out; set `DATABASE_REQUEST_ACQUIRE_WAIT_MS=0` to turn it off** (#6349, #4182). Each query takes its own connection from a first-come-first-served pool. With far more requests in flight than connections, every request waited behind the whole crowd, and `/readyz`, on the same pool, reported a busy replica not ready.

  The gate runs before any authentication or handler work.
  - **Slots.** While the pool is busy, at most `DATABASE_REQUEST_CONCURRENCY` requests (default four per pool connection) run their handler phase. A request queues for a slot for up to `DATABASE_REQUEST_ACQUIRE_WAIT_MS`. Unset, that is the pool's own acquire timeout (`DATABASE_ACQUIRE_TIMEOUT_SECS` x 1000, 5000 ms by default), so the gate only sheds what would have waited that long anyway.
  - **Shedding.** A request whose predicted wait is longer is answered at once with a `Retry-After` (1 to 30 s). The value is predicted from the queue plus the clients already told to come back, so returning clients spread out. Sheds are counted in the new `ak_db_requests_shed_total`.
  - **Exemptions.** The gate sheds nothing while the pool has room, and never touches health, readiness, liveness or `/api/v1/admin/metrics`.
  - **Safety.** A shed request has done no work, so it is never let through. Authentication and scanning run unchanged.

  A database that is down or failing over still fails at the acquire timeout, as before.

  `/health` and `/readyz` now read the database through their own one-connection pool, `DATABASE_PROBE_CONNECTIONS`. That connection counts toward the Postgres connection budget, one more per replica; `0` restores the old behaviour. A wedged request pool therefore no longer fails readiness, and alerting on `ak_db_requests_shed_total` is required in production. The first shed also logs a rate-limited WARN.

  Measured trade-off, 24 installers on a pool of 8, clients retrying a 503 up to 5 times:
  - **+2 ms per database round trip:** all installs finish in 5 of 5 runs. Served requests take 5.3 s at p99 instead of 9.4 s. The fleet takes about 15% longer (42 to 44 s against 37 s).
  - **+8 ms per round trip:** the fleet finishes in about 37 s instead of 93 s, with no client timeouts and readiness green.

  A shed upload may show up as a broken pipe on clients that send the body without waiting for `100 Continue`. Maven 3.8 does not retry a 503 by default. The client retry table, measurements and connection-budget formula are in `docs/operations/load-shedding.md`.
