# Artifact Keeper Development Guidelines

Auto-generated from all feature plans. Last updated: 2026-01-14

## Active Technologies
- Rust 1.75+ (backend) + wasmtime 21.0+, wasmtime-wasi, wit-bindgen, git2, axum
- PostgreSQL (existing), filesystem for WASM binaries
- Rust 1.75+ + axum, sqlx, tokio, reqwest
- Rust 1.75+ + axum, serde, serde_json

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

Rust 1.75+: Follow standard conventions

## Git & GitHub

- **Do NOT add Co-Authored-By lines** to commit messages
- **Always use `gh` CLI** for GitHub operations (PRs, issues, workflows, etc.)
  - Use `gh pr create` for pull requests
  - Use `gh issue` for issues
  - Use `gh workflow` for workflow operations
  - Do not use raw git commands for GitHub-specific features

## Recent Changes
- 007-shared-dto: Added Rust 1.75+ + axum, serde, serde_json
- Frontend removed: Moved to separate repository (artifact-keeper-web)


<!-- MANUAL ADDITIONS START -->

## Infrastructure & Cost Rules

- **NEVER build Docker images or compile code on EC2/cloud instances.** Cloud compute costs money. All builds must happen locally on the developer's MacBook or via GitHub Actions CI.
- **Demo EC2 instance** (`i-0caaf8acac6f85d4d`, Elastic IP `3.222.57.187`): Only pull pre-built images from `ghcr.io`, never `docker compose build`. Use `docker compose pull && docker compose up -d`.
- **SSH access**: `ssh ubuntu@3.222.57.187` (uses local SSH key)
- **Demo stack**: Managed via systemd service `artifact-keeper-demo` and Caddy reverse proxy for TLS.
- **Docker images** are published to `ghcr.io/artifact-keeper/artifact-keeper-backend` by the Docker Publish CI workflow on every push to main.
- **GitHub Pages site** (`/site/` directory): Combined landing page + Starlight docs, deployed to `artifactkeeper.com`.

<!-- MANUAL ADDITIONS END -->
