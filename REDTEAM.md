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

## When to Run

- Before any release
- After changes to authentication, middleware, or route configuration
- After adding new package format handlers
- After changes to gRPC services
- After changes to plugin system
- When onboarding new infrastructure services
