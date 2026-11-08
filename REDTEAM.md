# Red Team Security Testing

Automated security testing suite for artifact-keeper. Run on-demand during major changes to validate the security posture of the registry.

**Tracking:** [Discussion #50](https://github.com/orgs/artifact-keeper/discussions/50) | [Issue #51](https://github.com/artifact-keeper/artifact-keeper/issues/51)

## Quick Start

### Automated (full suite)

```bash
docker compose -f docker-compose.test.yml --profile redteam up --build --abort-on-container-exit
```

Results are written to the `redteam-results` Docker volume as `redteam-report.json`.

### Run a single test

```bash
docker compose -f docker-compose.test.yml --profile redteam up -d postgres backend setup pki
docker compose -f docker-compose.test.yml --profile redteam run --rm redteam bash /scripts/run-all.sh --test cors
```

### Interactive exploration

```bash
# Start infrastructure
docker compose -f docker-compose.test.yml --profile redteam up -d postgres backend setup pki

# Drop into the redteam container
docker compose -f docker-compose.test.yml --profile redteam run --rm --entrypoint bash redteam
```

Inside the container you have access to:

```bash
# Network scanning
nmap -sV backend

# Web scanning
nikto -host http://backend:8080
nuclei -target http://backend:8080 -severity critical,high

# gRPC probing
grpcurl -plaintext backend:9090 list
grpcurl -plaintext backend:9090 describe

# SQL injection testing
sqlmap -u "http://backend:8080/api/v1/search?q=test" --batch --level=1 \
  --auth-type=Basic --auth-cred="admin:admin123"

# Manual HTTP testing
curl -s http://backend:8080/health | jq .
curl -sI -H "Origin: https://evil.com" http://backend:8080/api/v1/repositories
```

### Cleanup

```bash
docker compose -f docker-compose.test.yml --profile redteam down -v --remove-orphans
```

## Test Suite

| # | Test | Severity | What it checks |
|---|------|----------|----------------|
| 01 | recon | MEDIUM | Port scanning, unexpected services |
| 02 | security-headers | MEDIUM | X-Frame-Options, CSP, HSTS, X-Content-Type-Options |
| 03 | cors | CRITICAL | CORS `AllowOrigin::Any` in non-dev mode |
| 04 | auth-bypass | HIGH | Protected endpoints accessible without auth |
| 05 | default-credentials | CRITICAL | admin:admin123, peer API key, Meilisearch key |
| 06 | grpc-unauth | CRITICAL | gRPC services callable without authentication |
| 07 | oci-dos | CRITICAL | OCI V2 unlimited body size (no `DefaultBodyLimit`) |
| 08 | path-traversal | HIGH | `../` in 30+ format handler paths |
| 09 | sql-injection | MEDIUM | SQLi in search, repo creation, backup endpoints |
| 10 | rate-limit | HIGH | Rate limiting middleware not wired to routes |
| 11 | wasm-plugin | HIGH | Plugin install from arbitrary URLs, no signing |
| 12 | information-disclosure | MEDIUM | /metrics exposed, error verbosity, version leak |

## Results

The JSON report at `/results/redteam-report.json` has this structure:

```json
{
  "timestamp": "2026-02-07T00:00:00Z",
  "target": "http://backend:8080",
  "findings": [
    {
      "severity": "CRITICAL",
      "test": "cors",
      "description": "CORS allows any origin",
      "evidence": "Access-Control-Allow-Origin: *"
    }
  ],
  "summary": {
    "pass": 15,
    "fail": 8,
    "warn": 3,
    "info": 2,
    "findings": 1
  }
}
```

The counts are totals for the whole run and the document is guaranteed to
parse: `run-all.sh` runs `jq` over the report before it exits and fails the run
if it does not. Both were broken until #3491 — each test script runs in its own
shell, so the counters reset per script (a run printed "Passed: 1 checks" after
dozens of PASS lines, and the exit-code gate never fired) and findings written
by different scripts were concatenated with no separating comma. The counters
now live in `${RESULTS_DIR}/.state`, which is also where the run's single
shared admin token is cached — the suite authenticates once rather than once
per script, so the login rate limiter that tests 04 and 10 exercise on purpose
no longer starves the later tests of a token.

`scripts/ci/test-redteam-report.sh` exercises all of that against a stub
registry, offline, in about a second; it runs in the Shell Tests CI job.

### gRPC checks and reflection

Server reflection is disabled, which is correct and is what test 06's first two
checks assert. That also means `grpcurl` cannot build a request for the
unauthenticated method probes on its own, so the container mounts
`backend/proto` at `/protos` (`PROTO_DIR`) and the probes invoke methods from
the descriptors. If the protos are not available the probes report themselves
as SKIPPED: an unmeasurable control is reported as unmeasured, never as a pass
and never as a finding.

## Container Tools

| Tool | Version | Purpose |
|------|---------|---------|
| nmap | 7.94 | Port scanning, service discovery |
| nikto | 2.5.0 | Web server misconfiguration scanning |
| nuclei | 3.7.0 | Template-based vulnerability scanning |
| grpcurl | 1.9.3 | gRPC service probing and enumeration |
| sqlmap | 1.10.2 | SQL injection detection |
| curl + jq | - | HTTP testing, JSON parsing |
| openssl | - | TLS certificate inspection |

## HTML application UI (RT-15)

The suite above and `docker-compose.test.yml` start the backend only. A
red-team rig built from them reaches the JSON API and the opt-in Swagger UI,
and **no HTML application**. The repository, catalog, capability, curation
and audit views are a separate component with its own releases (#2708):

| | |
| --- | --- |
| Source | [`artifact-keeper/artifact-keeper-web`](https://github.com/artifact-keeper/artifact-keeper-web) |
| Image | `ghcr.io/artifact-keeper/artifact-keeper-web` (`artifactkeeper/web` on Docker Hub) |
| Deployment | the `web` service of [`docker-compose.yml`](docker-compose.yml), pinned by `ARTIFACT_KEEPER_WEB_VERSION` (#4481), behind Caddy |
| Stored-content rendering tests | `e2e/suites/interactions/security/rt15-mcp-stored-content.spec.ts` in that repository |

A raw-JSON or Swagger check therefore cannot show that stored content stays
inert in the UI (#5472). #5472 named `artifact-keeper-test` as the primary
regression destination, but the rendering case lives in the web repository's
Playwright suite instead. The test repository's release gate
(`release-gate.yml`, which the web image publish calls) runs no browser
suite, and it does not run this one.

The suite stores hostile MCP content through a live backend: a publish, a CI
capability report, a status change, a Remote synced from a hostile upstream
registry, an unprivileged reader's approval request and an administrator's
approval reason. It then opens the following views in Chromium:

- the MCP repository views
- the catalog
- server detail, each tab and each capability panel
- curation
- the audit log

Each view is opened as an administrator and as an unprivileged reader, with
and without the web server's Content-Security-Policy. The suite fails on
script execution, active nodes, active-scheme URLs or requests to an attacker
origin. artifact-keeper/artifact-keeper-web#1106 lists the views it covers
and the stored fields the UI does not render at all.

The suite runs in the web repository's `E2E Interactions` CI job against the
backend `dev` image. That job is **advisory**: E2E is not a required check
there, so a red run does not block a merge and someone has to read it. To run
the suite by hand, see that repository's `docker-compose.e2e-mcp-upstream.yml`.

Two #5472 criteria are covered elsewhere, not by this suite:

- **Terminal controls in logs:** the red-team rig's DEBUG-log analysis, plus
  the backend test `telemetry::tests::test_json_request_line_has_siem_fields_top_level`
  (JSON logs never carry ANSI).
- **Authorization unaffected by display text:**
  `mcp_capabilities::db_tests::capability_reports_run_the_namespace_gate` and
  `mcp_namespaces::tests::namespace_rule_grants_nothing_outside_the_mcp_gate`.
  The suite adds its own checks that a reader is shown no lint findings,
  audit rows or approval queue.

When a release assessment covers the UI, record the web revision and image
digest next to the backend's, and deploy that exact image rather than a tag:

```bash
skopeo inspect --format '{{.Digest}} {{index .Labels "org.opencontainers.image.revision"}}' \
  docker://ghcr.io/artifact-keeper/artifact-keeper-web:<version>
# then ARTIFACT_KEEPER_WEB_VERSION=<version>@sha256:<digest> docker compose up -d web
```

Web `1.11.2` (`sha256:c17f1bff9a8bc1646efded313c107a003c383f7c03b213b389cdf789302267a5`,
revision `6a43afc`) predates the MCP UI: it serves no MCP views and does not
proxy `/mcp/`. The first web release with MCP views will be the next one,
1.12.0, which contains `b65f961` and artifact-keeper/artifact-keeper-web#1106.

The suite has passed against `b65f961` plus #1106, built from source, with
backend `dev` revision `ad20810`
(`sha256:a55b5d560c18e66efdac3107e13d4239cbae59c15fcbad4eccd88365ace27c5f`).
`b65f961` is the `artifact-keeper-web:dev` image
(`sha256:e05124d427420f81fbc2656bbad1cd50a5e3333a5cfae27859a61c6f1812e5ff`).
That build is not the release. RT-15 is marked PASS only after the suite is
rerun against the 1.12.0 web image, deployed by its digest, and that digest
is recorded here.

## When to Run

- Before any release
- After changes to authentication, middleware, or route configuration
- After adding new package format handlers
- After changes to gRPC services
- After changes to plugin system
- When onboarding new infrastructure services
