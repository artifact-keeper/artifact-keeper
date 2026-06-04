# Multi-Replica Single-Flight Concurrency Harness (#1624)

A black-box concurrency harness that runs **≥3 backend replicas** sharing one
PostgreSQL and one S3-compatible object store (MinIO), behind a round-robin
load balancer, and fires a storm of concurrent GETs for a single **uncached**
large artifact through a proxy/remote repository.

It is the **acceptance gate for #1609** and **reproduces #1606** (per-process
single-flight races across replicas serving partial/truncated artifacts).

> **This harness is RED on `main` by design.** Today's coordinator
> (`backend/src/services/proxy_hydration.rs`) elects a single-flight *leader*
> using a process-local `static` map, so it only deduplicates **within one
> replica**. With the storm spread across replicas, each replica independently
> fetches the artifact — multiple upstream fetches and, under #1606, torn /
> truncated bodies. The harness is expected to FAIL here. It flips green once
> #1609 implements cross-process single-flight, and then becomes its
> regression gate.

## Components

| File | Purpose |
| --- | --- |
| `mock_upstream.py` | Stdlib-only HTTP server: serves ONE large artifact with a fixed SHA-256, injects per-response latency to widen the race window, and exposes a **fetch counter**. |
| `Dockerfile.mock-upstream` | Containerises the mock upstream on stock `python:3.12-slim` (no pip install). |
| `nginx-lb.conf` | Round-robin LB that re-resolves the `backend` service via Docker DNS so the storm spreads across all replicas. |
| `assert_lib.sh` | Pure, side-effect-free assertion helpers (digest match, counter==1, blob count). Unit-tested without Docker. |
| `run-singleflight-race.sh` | Driver: creates the proxy repo, fires N concurrent GETs, asserts A1/A2/A3, prints a PASS/FAIL summary. |
| `test_assert_lib.sh` | Unit tests for `assert_lib.sh` + a standalone smoke test of `mock_upstream.py` (no Docker). |
| `../../docker-compose.concurrency-e2e.yml` | Postgres + MinIO + mock upstream + ≥3 backend replicas + nginx LB. |
| `../../.github/workflows/concurrency-e2e.yml` | `workflow_dispatch` + weekly schedule. **Not** on `pull_request`. |

## The mock upstream

Serves the artifact at `GET /race/<ARTIFACT_NAME>` and exposes:

- `GET /__digest__` → `{"sha256": "...", "size": N, "name": "..."}` (the published digest)
- `GET /__count__` → `{"fetches": N}` (how many times the artifact was actually fetched)
- `POST /__reset__` → resets the counter to 0
- `GET /healthz` → `ok`

Artifact bytes are generated **deterministically from a fixed seed**, so the
SHA-256 is stable across restarts without shipping a 256 MiB blob in the image.
Each served response increments the counter exactly once (counted *before* the
body is streamed, so a client disconnect still counts as a real upstream hit).

Configurable via env: `ARTIFACT_SIZE_BYTES` (default 256 MiB), `LATENCY_MS`
(default 1500), `ARTIFACT_NAME`, `SEED`, `PORT`.

## Assertions

| ID | Assertion | The bug it catches |
| --- | --- | --- |
| **A1** | mock-upstream fetch counter `== 1` (strict; `FETCH_TOLERANCE` allows a documented passthrough margin) | Cross-process stampede: each replica fetches independently → counter ≫ 1. |
| **A2** | **every** response is HTTP 200 **and** its SHA-256 == the published digest | Torn / truncated bodies — the #1606 failure. |
| **A3** | exactly **one** cached blob (`__content__`) under `proxy-cache/<repo>/` in the object store | Duplicate / half-written cache entries from racing writers. |

## How to run

Requires Docker (with the Compose plugin) on a local machine. Building the
backend image locally is fine — this is a developer machine, **not** cloud
compute (per repo infra rules, never build on EC2).

```bash
# From the repo root.
docker compose -f docker-compose.concurrency-e2e.yml build
docker compose -f docker-compose.concurrency-e2e.yml up -d --scale backend=3

# Wait for health, then run the storm (default 200 concurrent GETs).
CONCURRENCY=200 ./scripts/concurrency/run-singleflight-race.sh

# Tear down.
docker compose -f docker-compose.concurrency-e2e.yml down -v
```

Tunables (env vars consumed by the driver):

```bash
CONCURRENCY=200            # number of concurrent GETs
LB_URL=http://localhost:18080
MOCK_UPSTREAM_URL=http://localhost:19999
FETCH_TOLERANCE=0          # allow upstream counter up to 1+tolerance
```

To widen or narrow the race window, set `LATENCY_MS` / `ARTIFACT_SIZE_BYTES` on
the `mock-upstream` service before `up` (or via the workflow inputs).

## Run the no-Docker checks

The assertion logic and the mock upstream counter can be validated without the
full stack:

```bash
shellcheck scripts/concurrency/*.sh
python3 -m py_compile scripts/concurrency/mock_upstream.py
bash scripts/concurrency/test_assert_lib.sh
docker compose -f docker-compose.concurrency-e2e.yml config >/dev/null
```

## Expected result on `main`

On current `main` the driver exits **non-zero**. An actual observed run against a
pre-#1609 backend (3 replicas, shared MinIO, 256 MiB artifact, 1.5 s upstream
latency, `CONCURRENCY=24`, cold cache) produced:

```
==> Wiping shared object store for a cold cache ...
  object store wiped (0 cached blobs)
...
==> Reading mock upstream fetch counter...
  Upstream fetch counter: 24
==> Counting cached blobs in object store...
  Cached blob count: 1
--- A1: exactly one upstream fetch ---
  FAIL upstream fetch counter is 24 (>1): cross-process single-flight failed (#1606)
--- A2: every response 200 + correct sha256 ---
  FAIL of 24 responses: 20 non-200, 0 digest-mismatch
--- A3: exactly one cached blob ---
  PASS exactly one cached blob in object store
RACE HARNESS FAILED (2 assertion(s))
```

- **A1** fails: the upstream counter is **24** — every cold-cache request fetched
  upstream independently (a correct cross-process coordinator would fetch once).
  The mock upstream's per-client access log confirms the fetches are spread
  across all replica IPs, proving the race is cross-process, not within a
  single replica.
- **A2** fails: most responses were **502** (the cold-cache stampede tears the
  buffered upstream reads — `Failed to read upstream response: error decoding
  response body` in the backend log). This is the #1606 client-visible failure.
- **A3** passes once the cache converges to a single blob.

> **Cold cache matters.** A warm shared cache makes every request a cache hit
> (upstream counter 0, all 200s) and masks the race entirely. The driver wipes
> the object store before each storm (`WIPE_CACHE=1`, the default). If you run
> the storm twice without a wipe, the second run will spuriously look "less bad".

That red result is the **correct** outcome for this task — it proves the harness
reproduces #1606. When #1609 lands, all three assertions pass and the workflow
turns green, at which point the `continue-on-error` in the workflow's `race`
job should be removed so it becomes a hard regression gate.
