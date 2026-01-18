# Artifact Keeper Development Guidelines

Auto-generated from all feature plans. Last updated: 2026-01-14

## Active Technologies
- Rust 1.75+ (backend), TypeScript 5.x (frontend) + wasmtime 21.0+, wasmtime-wasi, wit-bindgen, git2, axum (002-wasm-plugin-system)
- PostgreSQL (existing), filesystem for WASM binaries (002-wasm-plugin-system)
- TypeScript 5.3, React 19.x + Ant Design 6.x, React Router 7.x, TanStack Query 5.x, Axios (003-frontend-ui-parity)
- N/A (frontend only, uses backend APIs) (003-frontend-ui-parity)
- Rust 1.75+ (backend), TypeScript 5.x (frontend) + axum, sqlx, tokio, reqwest (backend); React 19, Ant Design 6, TanStack Query 5 (frontend) (004-artifactory-migration)
- PostgreSQL (migration job state), existing Artifact Keeper storage (migrated artifacts) (004-artifactory-migration)
- Rust 1.75+ (backend), TypeScript 5.3 (frontend), Bash/YAML (CI workflows) + GitHub Actions, Docker Compose, Playwright, Vitest, Cargo test, axum-test (005-staged-testing-ci)
- PostgreSQL (test database), local filesystem (test artifacts) (005-staged-testing-ci)

- Rust 1.75+ (backend), TypeScript 5.x (frontend) (001-artifact-registry)

## Project Structure

```text
src/
tests/
```

## Commands

### Fast CI (Tier 1) - Every Push/PR
```bash
# Backend lint and unit tests
cargo fmt --check
cargo clippy --workspace
cargo test --workspace --lib

# Frontend lint and unit tests
cd frontend && npm run lint && npm run type-check
cd frontend && npm run test:run
```

### Integration Tests (Tier 2) - Main Branch Only
```bash
# Backend integration tests (requires PostgreSQL)
cargo test --workspace
```

### Full E2E Tests (Tier 3) - Release/Manual Only
```bash
# Run all E2E tests with default (smoke) profile
./scripts/run-e2e-tests.sh

# Run with specific profile
./scripts/run-e2e-tests.sh --profile all      # All native clients
./scripts/run-e2e-tests.sh --profile pypi     # PyPI only
./scripts/run-e2e-tests.sh --profile smoke    # Quick smoke tests (default)

# Include stress and failure tests
./scripts/run-e2e-tests.sh --stress --failure

# Run with test tag filter
./scripts/run-e2e-tests.sh --tag @smoke       # Only smoke-tagged tests
./scripts/run-e2e-tests.sh --tag @full        # Full test suite

# Cleanup after tests
./scripts/run-e2e-tests.sh --clean
```

### Native Client Tests
```bash
# Run individual native client tests
./scripts/native-tests/run-all.sh smoke   # PyPI, NPM, Cargo
./scripts/native-tests/run-all.sh all     # All 10 package formats
./scripts/native-tests/test-pypi.sh       # Individual test
```

### Stress and Failure Tests
```bash
# Stress tests (100 concurrent uploads)
./scripts/stress/run-concurrent-uploads.sh
./scripts/stress/validate-results.sh

# Failure injection tests
./scripts/failure/run-all.sh
./scripts/failure/test-server-crash.sh
./scripts/failure/test-db-disconnect.sh
./scripts/failure/test-storage-failure.sh
```

### GitHub Actions
```bash
# Manually trigger E2E workflow
gh workflow run e2e.yml -f profile=all -f include_stress=true
```

## Code Style

Rust 1.75+ (backend), TypeScript 5.x (frontend): Follow standard conventions

## Recent Changes
- 005-staged-testing-ci: Added Rust 1.75+ (backend), TypeScript 5.3 (frontend), Bash/YAML (CI workflows) + GitHub Actions, Docker Compose, Playwright, Vitest, Cargo test, axum-test
- 004-artifactory-migration: Added Rust 1.75+ (backend), TypeScript 5.x (frontend) + axum, sqlx, tokio, reqwest (backend); React 19, Ant Design 6, TanStack Query 5 (frontend)
- 003-frontend-ui-parity: Added TypeScript 5.3, React 19.x + Ant Design 6.x, React Router 7.x, TanStack Query 5.x, Axios


<!-- MANUAL ADDITIONS START -->
<!-- MANUAL ADDITIONS END -->
