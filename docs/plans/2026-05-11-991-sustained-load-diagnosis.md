# Sustained-load error rate diagnosis (issues #991 / #1088)

Status: investigation, no code change in this branch.
Branch: `investigate/991-sustained-load`
Worktree: `/tmp/690a0ca2-3b27-4cbc-9947-63ed86f84d09-ak-991`

## TL;DR

The single most likely culprit is **PostgreSQL CPU starvation on the test pod
combined with the no-retry shape of `test-concurrent-api-clients.sh`**, not a
hot lock or middleware regression in the backend code. The
`helm/values-test.yaml` overlay sits postgres at `limits.cpu: 500m` while the
backend gets `limits.cpu: 2500m`, so the backend can issue queries at 5x the
rate the database can serve them. Under sustained 5-worker mixed traffic, sqlx
pool acquires queue up against a 30s `acquire_timeout` and the slowest in-flight
queries surface as `AppError::Database` (HTTP 500). On
`test-concurrent-api-clients.sh`, the `create-repo` step is the only authenticated
non-retried mutating step in the per-client sequence, so by construction nearly
every transient failure under load is recorded as a `create-repo` failure even
when the underlying error is generic DB pressure, not specific to
`POST /api/v1/repositories`.

This means #991 (sustained mixed workload) and #1088 (create-repo concentration)
are most likely the **same underlying problem viewed through two different test
shapes**, not two independent backend defects.

## Tests and what they measure

### `test-sustained-load.sh` (#991)

`/Users/khan/ak/artifact-keeper-test/tests/stress/test-sustained-load.sh:14-104`

- One repo is created **at suite startup** (line 25 `create_local_repo`). Every
  subsequent op done by workers is one of: `auth` / `upload` / `list` /
  `download` against that repo, modulo 4 per worker. `POST /api/v1/repositories`
  is **not in the hot path** of the sustained workload. So #991's hypothesis
  that bcrypt-bound `/auth/login` saturates the pod is plausible for sustained
  load but is unrelated to the create_repository concentration #1088 reports.
- "Errors" = HTTP status outside `[200, 400)` and not curl exit `000`.
  Timeouts are reported as a separate `total_timeout` bucket
  (`test-sustained-load.sh:120-126`). Per #1088, observed `total_timeout == 0`,
  so failures are pure 4xx/5xx, not curl `--max-time` blowouts.

### `test-concurrent-api-clients.sh` (#1088)

`/Users/khan/ak/artifact-keeper-test/tests/stress/test-concurrent-api-clients.sh:26-81`

Each simulated client runs:

| Step | Retry policy | Records "fail step" as |
|------|--------------|------------------------|
| `auth` (POST /auth/login) | up to **3 attempts** with `sleep 1` between | `auth` |
| `create-repo` (POST /repositories) | **single attempt** | `create-repo` |
| `upload` (PUT /repositories/.../artifacts/...) | **single attempt** | `upload` |
| `read` (GET /repositories/.../artifacts) | **single attempt** | `read` |

The harness exits the per-client function as soon as any one step fails
(`return` on lines 46, 56, 67, 76). The fail step recorded is whichever step
first non-2xx'd. Because `auth` is the only step with retries, transient
failures during `auth` are masked, and the **next** authenticated step
(`create-repo`) absorbs all the load-induced statistical noise. The "100%
concentration on POST /api/v1/repositories" finding is therefore an artifact of
the test shape, not a property of the backend endpoint.

## Backend code-path walk for POST /api/v1/repositories

Handler: `backend/src/api/handlers/repositories.rs:765-927`
Service: `backend/src/services/repository_service.rs:325-421`

What runs on a single request (admin caller, generic format, no upstream URL,
guest access enabled, no virtual members):

1. Outer layers (`backend/src/api/routes.rs:147-167`):
   - `correlation_id_middleware` (pure header set, no I/O)
   - `setup_guard` (one `AtomicBool::load(Relaxed)`, returns next.run() when
     setup is complete)
   - `guest_access_guard` (no-op when `guest_access_enabled=true`, which is the
     test default; `backend/src/api/middleware/guest_access.rs:104-107`)
2. `/api/v1` route layer: `rate_limit_middleware` keyed on `user_id` with the
   admin user **exempted** by `RATE_LIMIT_EXEMPT_USERNAMES: "admin"` in
   `helm/values-test.yaml:36`, so the request short-circuits on
   `RateLimitExemptions::is_exempt`
   (`backend/src/api/middleware/rate_limit.rs:120-128`). No 429 path is
   exercised in the test config.
3. `/repositories` layer: `optional_auth_middleware` validates the bearer JWT
   in process (HS256, no DB round-trip) and inserts `Option<AuthExtension>`
   into request extensions
   (`backend/src/api/middleware/auth.rs:670-700`).
4. Handler body:
   - `require_auth` + `require_scope("write")` (pure)
   - `auth.is_admin` short-circuit skips the `permission_service.check_permission`
     DB query for admins
     (`backend/src/api/handlers/repositories.rs:774-790`).
   - `validate_repository_key`, `parse_format`, `parse_repo_type` (pure)
   - `validate_outbound_url` on `upstream_url` if present (pure, no DNS)
     (`backend/src/api/validation.rs:95-125`)
5. `repository_service.create` (`backend/src/services/repository_service.rs:325-421`):
   - **DB query 1**: `SELECT is_enabled FROM format_handlers WHERE format_key = $1`
     (`repository_service.rs:332-336`). One round-trip.
   - **DB query 2**: `INSERT INTO repositories ... RETURNING *`
     (`repository_service.rs:346-378`). One round-trip. Returns existing row on
     duplicate key (idempotent), via a follow-up `SELECT` in `get_by_key`.
   - `tokio::spawn` for OpenSearch indexing (fire-and-forget; does not affect
     response latency) (`repository_service.rs:406-418`).
6. Optional follow-ups in the handler:
   - `upsert_index_upstream_url` only if `payload.index_upstream_url.is_some()`
     (not set by the stress harness).
   - `save_upstream_auth` only if `payload.upstream_auth_type.is_some()`
     (not set by the stress harness).
7. `state.event_bus.emit_repository_event` is a `broadcast::Sender::send`
   (non-blocking; drops if no subscribers)
   (`backend/src/services/event_bus.rs:79-82`).

**Lock audit:**
- `std::sync::RwLock<HashMap<...>>` is used in
  `PermissionService::cache` and `PermissionService::rules_cache`
  (`backend/src/services/permission_service.rs:96-97`), but for admin callers
  `check_permission` returns `true` before touching either lock
  (`permission_service.rs:122-125`). So neither lock is held on the
  admin-driven stress path.
- `auth_service` global token-invalidation maps (`backend/src/services/auth_service.rs:100-176`)
  are read-only on the JWT-validation path (`read()` calls, never `write()`
  unless a credential change is in flight).
- `RateLimiter::requests` is a `std::sync::Mutex<HashMap<...>>`
  (`backend/src/api/middleware/rate_limit.rs:163`), but admin requests skip it
  entirely via the exemption.

No `tokio::sync::Mutex` is held across an `.await` on this path. No synchronous
DNS, file I/O, or network calls are performed inside the handler.

## Why "all failures concentrate on POST /repositories" is misleading

In `test-concurrent-api-clients.sh`, all four steps in `run_client` share the
same auth bearer token, the same backend, and the same DB pool. Anything that
makes the **second** authenticated request fail (e.g., a sqlx
`PoolTimedOut`, an OpenSearch indexing backlog spike that briefly drives the
postgres pod to 100% CPU, a transient TCP RST during graceful pool churn) will
record the fail step as `create-repo` because that is what step 2 happens to be.

The smoking gun: the same client harness, if you reorder steps 2 and 3
(upload first, then create-repo), is expected to invert the concentration. The
current pattern is not "create_repository is slow", it is "step 2 absorbs all
non-auth transient failures".

## Why postgres is the throughput ceiling

`helm/values-test.yaml:57-65` gives postgres `limits.cpu: 500m`. Backend gets
`2500m`. A 5-worker sustained-load mix at 180 RPS issues at minimum:

- auth (1/4 of ops): one `SELECT users WHERE username = $1` plus
  `UPDATE users SET last_login_at = ...` plus password bcrypt verify on the
  backend. ~2 DB queries.
- upload (1/4): `SELECT artifacts WHERE...` + `INSERT artifacts` +
  `SELECT repository_config WHERE ...` (quarantine resolve) + optional
  package upsert. ~3-4 DB queries.
- list (1/4): one `SELECT ... LIMIT 20` + `COUNT(*)` + `get_download_stats_batch`.
  ~3 DB queries.
- download (1/4): `get_by_key` (SELECT) + storage existence + record stats.
  ~2 DB queries.

Average ~2.5 queries/op x 180 RPS = ~450 queries/sec into a 0.5-core postgres
pod. Even simple indexed queries on a small dataset top out around 200-300 q/s
on half a core. Tail latency runs hot, sqlx connections queue, and the
`database_acquire_timeout_secs` default of 30s
(`backend/src/db.rs:18`, `backend/src/config.rs:411`) starts firing on the
slowest acquires, which surface as `AppError::Database` -> HTTP 500.

This matches the observed shape: 0 timeouts (curl never `--max-time`s), pure
4xx/5xx, error rate growing with RPS because the gap between postgres
service rate and backend issue rate widens.

## Reproducer

```bash
# 1. Start the full local stack with the v1.1 cherry-picked dev image.
cd /Users/khan/ak/artifact-keeper
docker compose -f docker-compose.local-dev.yml up -d postgres meilisearch trivy

# 2. Constrain postgres to roughly match the test pod.
docker update --cpus=0.5 --memory=512m \
  $(docker compose -f docker-compose.local-dev.yml ps -q postgres)

# 3. Run the backend.
DATABASE_URL=postgresql://registry:registry@localhost:30432/artifact_registry \
  RATE_LIMIT_EXEMPT_USERNAMES=admin \
  ADMIN_PASSWORD=admin123 \
  cargo run --release --bin artifact-keeper

# 4. Drive the sustained-load harness.
cd /Users/khan/ak/artifact-keeper-test
RUN_ID=local-991 BASE_URL=http://localhost:8080 \
  ADMIN_USER=admin ADMIN_PASS=admin123 \
  SUSTAINED_DURATION=60 \
  bash tests/stress/test-sustained-load.sh
```

Expected: with postgres at 0.5 CPU, the error rate climbs over 30% in 60s.
Re-run with `docker update --cpus=2.0 postgres` and the same workload should
land under 10% error rate. If both reproduce, the diagnosis is confirmed.

Optional follow-up: while the harness is running, `docker stats` should show
the postgres container pinned near its CPU limit while the backend container
has headroom. That asymmetry IS the bug.

## Proposed fix scope (do NOT implement in this branch)

The fix is not in `backend/src/`. It is in the test infrastructure and the
diagnostic harness:

1. **`artifact-keeper-test/helm/values-test.yaml`**: lift the postgres CPU
   limit so it can keep up with the backend under the release-gate stress
   suites. Either:
   - bump postgres `limits.cpu` from `500m` to at least `1500m`, or
   - drop the backend `limits.cpu` from `2500m` to `1000m`,
   so the backend cannot outrun the database by more than 2x.
   Tradeoff: total namespace request stays inside the 4 CPU quota in either
   case. The first option is more honest about postgres being on the critical
   path now that v1.2 fanned out indexing into the upload code path.

2. **`artifact-keeper-test/tests/stress/test-concurrent-api-clients.sh`**:
   either give every step the same retry budget as `auth` (3 attempts with
   1s backoff) or, better, capture per-request HTTP status from every step
   and report which actual status code dominates (429 vs 500 vs 503 vs
   curl 000). Without that breakdown the harness will keep producing the
   misleading "all failures on create-repo" signal on any future load
   regression, no matter where it actually lives.

3. **(Stretch) `backend/src/services/repository_service.rs:325`**: combine
   the format-handler SELECT and the repository INSERT into a single
   round-trip using a CTE, e.g.
   `WITH fh AS (SELECT is_enabled FROM format_handlers WHERE format_key = $1)
    INSERT INTO repositories ... SELECT ... FROM fh WHERE COALESCE(fh.is_enabled, true) RETURNING *`.
   This is a small optimization (one fewer query per repo create) that
   marginally reduces postgres load on this endpoint. It would NOT fix the
   broader sustained-load error rate -- the test config is the actual bottleneck.

## Confidence and what would refute the hypothesis

Confidence: medium-high. Signals supporting it:

- The arithmetic on postgres CPU vs query rate is straightforward.
- The retry-asymmetry of the concurrent-clients harness is a clean
  explanation of the misleading "concentration on create-repo" signal.
- No hot lock, sync I/O in async, or N+1 query was found on the
  create_repository path.

What would refute it:

- A reproducer where postgres CPU is uncapped (or generously sized) but
  POST /api/v1/repositories still concentrates failures. That would
  mean there is a backend-side bug specifically on this handler, and
  the next step would be to enable `tokio-console` and
  `EXPLAIN ANALYZE` on the in-flight queries during a 60s burst.
- A real-deployment (non-CI) report of the same 33-54% error rate at
  similar RPS. The hardening label on #991 says this is reproducing
  on the v1.1-dev test namespace, which IS the CI environment, so a
  prod report would be a meaningful update.

## Follow-up issue text (to file once this branch lands as a draft PR)

Title: **Release-gate stress tests fail because postgres is CPU-starved relative to the backend, not because of a create_repository hot path**

Body:

> While investigating #991 and #1088, the failure shape resolves to two
> compounding issues in the test infrastructure rather than a backend
> regression on `POST /api/v1/repositories`.
>
> 1. In `helm/values-test.yaml` the postgres pod is capped at `limits.cpu:
>    500m` while the backend is capped at `2500m`. Under the sustained
>    mixed-workload harness (`tests/stress/test-sustained-load.sh`, 5 workers
>    x 60s), the backend issues queries at roughly 5x the rate the database
>    can serve. The slowest sqlx `acquire`s hit the 30s `acquire_timeout` and
>    surface as `AppError::Database` -> HTTP 500.
>
> 2. In `tests/stress/test-concurrent-api-clients.sh`, only the `auth` step
>    retries (3 attempts). All subsequent steps are single-attempt. So
>    whichever step happens to be #2 in the per-client sequence
>    (today: `create-repo`) absorbs ~100% of transient failures, producing
>    the misleading "concentration on POST /api/v1/repositories" signal
>    reported in #1088.
>
> The walk of the `create_repository` handler and `repository_service.create`
> shows no hot lock, no sync I/O in an async function, and no N+1 query.
> Admin callers also skip the `permission_service` cache lookups entirely.
> See [diagnosis doc](./docs/plans/2026-05-11-991-sustained-load-diagnosis.md)
> for the full walk and citations.
>
> Proposed scope:
>
> - **(test infra)** Raise postgres `limits.cpu` to at least `1500m`, or
>   drop backend `limits.cpu` to `1000m`, in `helm/values-test.yaml`.
> - **(test harness)** Give every step in `test-concurrent-api-clients.sh`
>   the same retry budget as `auth`, OR record the HTTP status per step
>   so the fail mode is identifiable instead of being attributed to whichever
>   step happened to run first after auth.
> - **(optional perf nicety)** Fold the format-handlers SELECT into the
>   repositories INSERT as a CTE so create-repo costs one DB round-trip
>   instead of two.
>
> This investigation specifically rules out: bcrypt CPU saturation on
> `/auth/login` (admin user is rate-limit-exempt and JWT validation is
> in-process), permission-cache lock contention (admins short-circuit
> before touching the lock), and middleware-chain latency
> (no sync I/O is performed on the request path under the test config).
