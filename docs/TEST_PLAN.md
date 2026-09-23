# Backend Test Plan

## Overview

The artifact-keeper backend uses a multi-tier testing strategy covering unit tests, integration tests, end-to-end tests with native package manager clients, stress tests, and security audits.

## Test Inventory

| Test Type | Framework | Count | CI Job | Status |
|-----------|-----------|-------|--------|--------|
| Unit | cargo nextest --lib --bins | ~17,500 tests | `test-backend-unit` | Active |
| Integration | cargo nextest --test | 63 test files (55 run in CI, 8 exempt) | `test-backend-unit` (Tier 2 steps) | Pushes + backend PRs |
| Native client E2E | Shell scripts | 28 scripts, 12 formats | `smoke-e2e` | Active |
| Stress | Shell scripts | 100 concurrent uploads | Manual/dispatch | Active |
| Failure injection | Shell scripts | 3 scenarios | Manual/dispatch | Active |
| Security audit | cargo-audit | Nightly | `security-audit` | Active |
| Mesh replication E2E | Docker Compose | Replication tests | Manual/dispatch | Active |

## How to Run

### Unit Tests (no database required)
```bash
SQLX_OFFLINE=true cargo nextest run --workspace --lib --test-threads 8
```

### Single Test
```bash
cargo nextest run --workspace --lib test_name_here
```

### Integration Tests (requires PostgreSQL)
```bash
docker compose -f docker-compose.local-dev.yml up -d postgres
DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
  cargo nextest run --workspace --run-ignored ignored-only --test <name>
```

### E2E Smoke Tests
```bash
./scripts/run-e2e-tests.sh                      # smoke profile (default)
./scripts/run-e2e-tests.sh --profile all         # all 12 formats
```

### Stress Tests
```bash
./scripts/stress/run-concurrent-uploads.sh       # 100 concurrent uploads
```

### Failure Injection
```bash
./scripts/failure/run-all.sh                     # all failure scenarios
```

## Native Client Test Coverage

| Format | Script | Profile |
|--------|--------|---------|
| PyPI | `scripts/native-tests/test-pypi.sh` | smoke |
| NPM | `scripts/native-tests/test-npm.sh` | smoke |
| Cargo | `scripts/native-tests/test-cargo.sh` | smoke |
| Maven | `scripts/native-tests/test-maven.sh` | all |
| Go | `scripts/native-tests/test-go.sh` | all |
| RPM | `scripts/native-tests/test-rpm.sh` | all |
| Debian | `scripts/native-tests/test-deb.sh` | all |
| Helm | `scripts/native-tests/test-helm.sh` | all |
| Conda | `scripts/native-tests/test-conda.sh` | all |
| Docker | `scripts/native-tests/test-docker.sh` | all |
| Protobuf | `scripts/native-tests/test-protobuf.sh` | all |
| gRPC SBOM | `scripts/native-tests/test-grpc-sbom.sh` | all |

## CI Pipeline

```
PR opened/pushed
  -> check-rust (cargo fmt + clippy)
  -> test-backend-unit (one instrumented build: unit tests + lcov.info,
     then the PostgreSQL integration suites on backend-touching changes)
     -> coverage-gates (PR only: floor, new-code and duplication gates)
  -> smoke-e2e (PyPI, NPM, Cargo via Docker)
  -> security-audit (cargo audit)
  -> build-backend-image (Docker build)

Merge to main
  -> All above (except coverage-gates) PLUS:
  -> Docker publish to ghcr.io
```

## Gaps and Roadmap

| Gap | Recommendation | Priority |
|-----|---------------|----------|
| No property-based testing | Add `proptest` for format parsers | P3 |
| No fuzz testing | Add `cargo-fuzz` for upload/parse paths | P3 |
| No contract testing | Validate OpenAPI spec against live API | P2 |

## Agent-Assisted QA

Invoke the security auditor agent for periodic security reviews:
```bash
claude --print ".claude/agents/security-auditor.md"
```

Invoke the dependency health monitor for cross-repo dependency audits:
```bash
claude --print ".claude/agents/dependency-health.md"
```
