# Quickstart: Staged Testing Strategy

**Branch**: `005-staged-testing-ci` | **Date**: 2026-01-18

## Overview

This guide explains how to use the tiered testing infrastructure for Artifact Keeper.

## Test Tiers

| Tier | Trigger | Duration | What's Tested |
|------|---------|----------|---------------|
| **Tier 1** | Every push/PR | < 5 min | Lint, unit tests |
| **Tier 2** | Main branch push | < 15 min | Integration tests, Docker build |
| **Tier 3** | Release or manual | < 30 min | E2E, native clients, stress, failure |

## Running Tests Locally

### Tier 1: Fast CI Tests

```bash
# Backend
cargo fmt --check
cargo clippy --workspace
cargo test --workspace --lib

# Frontend
cd frontend
npm run lint
npx tsc --noEmit
npm run test:run
```

### Tier 2: Integration Tests

```bash
# Start database
docker compose up -d postgres

# Run integration tests
DATABASE_URL=postgresql://registry:registry@localhost:5432/artifact_registry \
  cargo test --workspace --test '*'
```

### Tier 3: E2E Tests

```bash
# Smoke tests (default - fastest)
docker compose -f docker-compose.test.yml up --abort-on-container-exit

# Specific format
docker compose -f docker-compose.test.yml --profile rpm up --abort-on-container-exit

# All formats
docker compose -f docker-compose.test.yml --profile all up --abort-on-container-exit
```

## Docker Compose Profiles

### Available Profiles

| Profile | Formats Tested | Estimated Time |
|---------|----------------|----------------|
| (default) | PyPI, NPM, Cargo | ~10 min |
| `all` | All 9 formats | ~30 min |
| `pypi` | PyPI only | ~3 min |
| `npm` | NPM only | ~3 min |
| `cargo` | Cargo only | ~3 min |
| `maven` | Maven only | ~5 min |
| `go` | Go modules only | ~3 min |
| `rpm` | RPM/dnf only | ~5 min |
| `deb` | Debian/apt only | ~5 min |
| `helm` | Helm only | ~3 min |
| `conda` | Conda only | ~5 min |
| `docker` | Docker/OCI only | ~5 min |

### Usage Examples

```bash
# Run smoke tests (PyPI, NPM, Cargo)
docker compose -f docker-compose.test.yml up

# Run RPM tests only
docker compose -f docker-compose.test.yml --profile rpm up

# Run all native client tests
docker compose -f docker-compose.test.yml --profile all up

# Clean up
docker compose -f docker-compose.test.yml down -v
```

## Generating Test Packages

Test packages are generated from templates in `.assets/`:

```bash
# Generate small PyPI package
.assets/pypi/generate.sh small

# Generate medium NPM package (10MB)
.assets/npm/generate.sh medium

# Generate large Cargo crate (100MB)
.assets/cargo/generate.sh large

# Generated packages appear in .assets/generated/
ls .assets/generated/
```

## Running Stress Tests

```bash
# Run 100 concurrent uploads
./scripts/stress/run-concurrent-uploads.sh 100

# Custom concurrency level
./scripts/stress/run-concurrent-uploads.sh 50
```

## Running Failure Tests

```bash
# Test server crash mid-upload
./scripts/failure/test-server-crash.sh

# Test database disconnect
./scripts/failure/test-db-disconnect.sh

# Test storage failure
./scripts/failure/test-storage-failure.sh

# Run all failure scenarios
./scripts/failure/run-all.sh
```

## CI Workflows

### Triggering E2E Tests Manually

1. Go to **Actions** tab in GitHub
2. Select **E2E Tests** workflow
3. Click **Run workflow**
4. Choose profile and options:
   - Profile: `smoke`, `all`, or specific format
   - Include stress tests: ✓/✗
   - Include failure tests: ✓/✗
5. Click **Run workflow**

### Release Process

1. Create and push a version tag:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```
2. E2E tests run automatically with `--profile all`
3. Release publishes only if E2E tests pass

## Test Reports

Test reports are uploaded as GitHub Actions artifacts:

| Artifact | Contents | Retention |
|----------|----------|-----------|
| `playwright-report` | HTML test report | 14 days |
| `e2e-results` | Test result data | 14 days |
| `coverage-report` | Code coverage | 14 days |

## Troubleshooting

### Tests fail with "connection refused"

Ensure services are healthy before tests run:
```bash
docker compose -f docker-compose.test.yml ps
# All services should show "healthy"
```

### GPG signature verification fails

Regenerate GPG keys:
```bash
./scripts/pki/generate-gpg.sh
```

### SSL certificate errors

Regenerate TLS certificates:
```bash
./scripts/pki/generate-certs.sh
```

### Air-gapped test fails with network error

Check that no test is trying to reach external URLs. All packages should be generated locally from `.assets/` templates.

## Adding a New Package Format

1. Create template directory:
   ```bash
   mkdir -p .assets/newformat
   ```

2. Add manifest files for the format

3. Create `generate.sh`:
   ```bash
   #!/bin/bash
   SIZE_TIER=${1:-small}
   # ... build logic
   ```

4. Add Docker Compose service:
   ```yaml
   newformat-test:
     profiles: ["newformat", "all"]
     # ... service config
   ```

5. Update this quickstart and contracts

## Reference

- [Spec](./spec.md) - Full feature specification
- [Plan](./plan.md) - Implementation plan
- [Data Model](./data-model.md) - Entity definitions
- [CI Workflows Contract](./contracts/ci-workflows.yaml) - Workflow definitions
- [Test Assets Contract](./contracts/test-asset-templates.yaml) - Template specifications
