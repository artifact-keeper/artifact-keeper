# Cache-correctness + virtual-resolution E2E suite (#1625)

Black-box E2E tests that pin **cache correctness** (immutable-vs-mutable
classification, TTL, conditional revalidation, negative cache) and
**virtual-repository resolution** correctness.

This suite is the **acceptance gate for #1611** and **reproduces three open
wrong-result bugs**: #1600, #1595, #1562.

> **These tests are RED on `main` BY DESIGN.**
> A failure proves the bug still exists. When #1611 lands they flip green and
> become its regression gate. They are wired to a `workflow_dispatch` +
> weekly-schedule workflow (`cache-correctness-e2e.yml`), **never** to the
> per-PR gate.

## Components

| File | Purpose |
| --- | --- |
| `mock_upstream.py` | ETag/counter/mutation-aware HTTP mock upstream (stdlib only). |
| `Dockerfile` | Minimal container image for the mock upstream. |
| `../test-virtual-resolution.sh` | Virtual-resolution regressions (#1600/#1595/#1562). |
| `../test-proxy-cache-correctness.sh` | Cache-correctness (immutable/mutable/negative). |

## The mock upstream

`mock_upstream.py` is a small stdlib HTTP server giving the artifact-keeper proxy
a *controllable* upstream. It is more capable than a static nginx fixture: it
counts requests, answers conditional requests, mutates resources, and supports
404-then-publish.

### Data plane (proxied through artifact-keeper)

| Path | Kind | Used by |
| --- | --- | --- |
| `/maven2/com/example/widget/1.0.0/widget-1.0.0.jar` | immutable | cache: counter==1 |
| `/maven2/com/example/widget/maven-metadata.xml` | mutable | cache: revalidate |
| `/maven2/org/example/plugins/maven-metadata.xml` | mutable (group-level) | #1595 |
| `/maven2/com/example/parent/1.0.0/parent-1.0.0.pom` | immutable (remote-only) | #1562 control |
| `/maven2/com/example/vonly-parent/1.0.0/vonly-parent-1.0.0.pom` | immutable (remote-only, never primed) | #1562 virtual-first-request |
| `/simple/lonelydep/` + `/packages/ld/lonelydep/lonelydep-2.3.0-py3-none-any.whl` | mutable index + immutable wheel | #1600, cache |
| `/maven2/com/example/late/1.0.0/late-1.0.0.jar` | starts 404, publishable | negative cache |

### Control plane (out-of-band, never proxied)

```
GET  /__mock__/health                      -> "ok"
GET  /__mock__/count?path=/p                -> {"path","count","revalidations"}
GET  /__mock__/count_all                    -> {"/p": {...}, ...}
POST /__mock__/reset                        -> zero all counters
POST /__mock__/mutate?path=/p               -> change body+ETag (mutable paths)
POST /__mock__/publish?path=/p   (body)     -> make a 404 path exist
POST /__mock__/unpublish?path=/p            -> make a path 404 again
POST /__mock__/latency?ms=N                 -> artificial per-response latency
```

Conditional requests (`If-None-Match` matching the current ETag, or
`If-Modified-Since` >= last-modified) get a `304` and bump `revalidations`
instead of `count`.

## What each script asserts

### `test-virtual-resolution.sh` (assert CORRECT behavior → red on `main`)

- **#1600 (PyPI virtual, remote-only download):** a package present only on the
  remote member (`lonelydep`) is listed in the virtual's `/simple/<name>/` index
  **and** its wheel downloads `200` through the virtual (not `404` bound to the
  local member). Optional `pip download` end-to-end through the virtual.
- **#1595 (Maven virtual, group-level plugin-prefix metadata):** the
  group-level `<groupPath>/maven-metadata.xml` (the `<plugins>` list, no
  artifactId) is proxied `200` from the remote member and exposes `<prefix>` —
  enabling `mvn <prefix>:<goal>`.
- **#1562 (Maven virtual, remote-only artifact):** a remote-only parent POM
  (`com.example:parent:1.0.0`) — which the remote member serves `200` directly —
  resolves `200` through the virtual on first request, instead of `404`.

### `test-proxy-cache-correctness.sh` (assert cache invariant ④ → red on `main`)

- **Immutable:** a versioned jar pulled N times within the TTL window hits the
  upstream **exactly once** (`/__mock__/count` stays `1`).
- **Mutable:** `maven-metadata.xml` and the PyPI simple index are served from
  cache within the TTL; after TTL they **revalidate conditionally** (mock
  answers `304`, `revalidations >= 1`); a **mutated** upstream (new ETag/body)
  is reflected promptly.
- **Negative cache:** a missing path returns `404`, then after upstream
  `publish` it becomes visible within the short negative-TTL window.

## Running

### Standalone mock upstream (no full stack — validates the harness itself)

```bash
python3 scripts/native-tests/mock-upstream/mock_upstream.py --port 9101 &
curl -s http://localhost:9101/__mock__/health           # -> ok
curl -s -X POST http://localhost:9101/__mock__/reset
curl -s "http://localhost:9101/__mock__/count?path=/maven2/com/example/widget/1.0.0/widget-1.0.0.jar"
```

### Full stack via docker compose

```bash
# Builds the backend + mock upstream, runs both suites under the dedicated profile.
docker compose -f docker-compose.test.yml --profile cache-correctness up --build --abort-on-container-exit
docker compose -f docker-compose.test.yml --profile cache-correctness down -v --remove-orphans
```

### Against an already-running backend + standalone mock

```bash
python3 scripts/native-tests/mock-upstream/mock_upstream.py --port 9101 &
REGISTRY_URL=http://localhost:8080 MOCK_UPSTREAM_URL=http://localhost:9101 \
  scripts/native-tests/test-virtual-resolution.sh

REGISTRY_URL=http://localhost:8080 MOCK_UPSTREAM_URL=http://localhost:9101 \
  CACHE_TTL_SECONDS=30 NEG_TTL_SECONDS=15 \
  scripts/native-tests/test-proxy-cache-correctness.sh
```

### CI

`.github/workflows/cache-correctness-e2e.yml` — `workflow_dispatch` (choose
`both` / `virtual-resolution` / `cache-correctness`) plus a weekly schedule.
The job uses `continue-on-error: true` so a red result (the expected outcome on
`main`) does not fail the run; remove that once #1611 lands.

## Interpreting results

| Branch | Expected | Meaning |
| --- | --- | --- |
| `main` (pre-#1611) | **FAIL** | Bugs reproduced — correct outcome. |
| post-#1611 | **PASS** | Cache classification + virtual resolution fixed. |

A *green* run on `main` would mean the repros stopped reproducing — investigate
the harness before trusting it.

### Observed on the `:dev` (main) backend image — 2026-06-04

A manual run against `ghcr.io/artifact-keeper/artifact-keeper-backend:dev`
(postgres + dev backend + this mock, on a shared docker network):

- **#1600 — reproduced RED.** The virtual `/simple/lonelydep/` index lists
  `lonelydep-2.3.0` but the wheel download through the virtual returns `404`
  (and `pip download` fails). Index/download inconsistency confirmed.
- **#1595 — reproduced RED.** The virtual returns `404` for the group-level
  plugin-prefix `maven-metadata.xml` while the remote member serves it `200`.
- **#1562 — PASSED (green) on this build.** A remote-only parent POM (even an
  uncached `vonly-parent`) resolved `200` through the virtual. The original
  #1562 is a subtle buffered-vs-streaming / cache-key discrepancy that a trivial
  flat-namespace static POM on this mock does not trigger; it may need a more
  faithful upstream (redirects / content-length quirks like Confluent's repo) or
  may already be partially addressed on this image. The assertion still guards
  against regression; it simply does not reproduce here. **Follow-up:** make the
  mock more faithful (redirect + chunked transfer) to try to reproduce #1562
  deterministically, or confirm via the live Confluent repro from the issue.
- **Cache — immutable-vs-mutable mis-caching reproduced RED.** After the upstream
  `maven-metadata.xml` changed (`1.0.0` → `1.1.0`), the proxy kept serving stale
  `1.0.0`; the mock counter stayed `count=1, revalidations=0` — i.e. the proxy
  never re-fetched **or** conditionally revalidated the mutable path. The PyPI
  simple index showed the same staleness. This is exactly invariant ④ (#1611).
- **Immutable counter==1 PASSED**, but a second cached read of the immutable jar
  returned `500 STORAGE_ERROR` (`Failed to read .../__content__: No such file`).
  This appeared in a standalone container without a persistent `/data` volume,
  so it may be an environment artifact rather than a confirmed product bug —
  re-run under the compose `cache-correctness` profile (persistent backend
  storage) to confirm before treating it as a real defect.

## Tuning the TTL waits

`CACHE_TTL_SECONDS` (default 30) and `NEG_TTL_SECONDS` (default 15) are the
sleeps before asserting revalidation / negative-cache expiry. Once #1611 makes
the backend's metadata and negative TTLs explicit/configurable, set these to
match so the suite stays fast and deterministic.

## Consolidation note (re #1624)

Issue #1624 builds a sibling **mock upstream** under `scripts/concurrency/` with
a request **counter + injectable latency** for the single-flight concurrency
harness. This mock already shares that shape (counter + a `/__mock__/latency`
control endpoint) and adds the knobs #1625 needs (ETag/Last-Modified conditional
handling, a mutating resource, 404-then-publish). The two were kept separate to
avoid a merge collision while both land. **Follow-up: consolidate into a single
mock-upstream image exposing both knob-sets** (counter+latency for #1624,
ETag+mutation+publish for #1625). This dir is intentionally self-contained to
make that merge mechanical.
