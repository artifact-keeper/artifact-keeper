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

### Integration Tests (Tier 2) - Main & Release Branches Only
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

### gRPC SBOM Tests
```bash
# Run SBOM JSON structure validation unit tests (no database required)
cargo test sbom_service::tests --lib

# Run gRPC integration tests (requires PostgreSQL at localhost:30432)
DATABASE_URL="postgresql://registry:registry@localhost:30432/artifact_registry" \
  cargo test --test grpc_sbom_tests -- --ignored

# Run gRPC E2E tests with grpcurl (requires backend running with gRPC on port 9090)
./scripts/native-tests/test-grpc-sbom.sh
```

### Dependency-Track Integration Tests
```bash
# Run Dependency-Track integration tests (requires docker compose up)
./scripts/native-tests/test-dependency-track.sh

# With API key for full tests
DEPENDENCY_TRACK_API_KEY=your-key ./scripts/native-tests/test-dependency-track.sh
```

### WASM Plugin E2E Tests
```bash
# Run all WASM plugin tests (requires backend running on port 8080)
./scripts/native-tests/test-wasm-plugins.sh

# Run individual test suites
./scripts/native-tests/test-wasm-plugins.sh git        # Git installation tests
./scripts/native-tests/test-wasm-plugins.sh lifecycle  # Enable/disable/uninstall
./scripts/native-tests/test-wasm-plugins.sh reload     # Hot-reload tests

# Run with custom API URL
API_URL=http://localhost:8080 ./scripts/native-tests/test-wasm-plugins.sh
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

### Branch Protection — NEVER push directly to main

All changes must go through pull requests:

1. **Create a feature branch** from main:
   ```bash
   git checkout main && git pull
   git checkout -b feat/short-description   # or fix/, chore/, docs/
   ```

2. **Make changes and commit** to the feature branch

3. **Push and create PR**:
   ```bash
   git push -u origin feat/short-description
   gh pr create --fill   # or with --title and --body
   ```

4. **Merge via GitHub** after CI passes (squash merge preferred)

Branch naming conventions:
- `feat/` — new features
- `fix/` — bug fixes
- `chore/` — maintenance, dependencies, CI
- `docs/` — documentation only

### Maintenance Branches

Long-lived `release/X.Y.x` branches exist for shipping bug fixes to older release series:

- **`release/1.0.x`** — maintenance branch for the 1.0 series (created from `v1.0.0-rc.5`)
- **`main`** — continues with 1.1.x (and beyond) development

**Bug fix workflow for maintenance branches:**
1. Create a fix branch from the maintenance branch:
   ```bash
   git checkout release/1.0.x && git pull
   git checkout -b fix/short-description
   ```
2. Push and create a PR **targeting `release/1.0.x`** (not main):
   ```bash
   git push -u origin fix/short-description
   gh pr create --base release/1.0.x --fill
   ```
3. Tag releases from the maintenance branch:
   ```bash
   git checkout release/1.0.x && git pull
   git tag v1.0.1 && git push origin v1.0.1
   ```
4. Cherry-pick to the maintenance branch when a fix on `main` also applies to 1.0.x.

**Docker image tags** (set by `docker/metadata-action` in `docker-publish.yml`):
- Version tags **strip the `v` prefix**: git tag `v1.1.0-rc.2` → Docker tag `:1.1.0-rc.2`
- `:latest` is only set for stable releases (no `-rc`, `-beta`, etc.)
- `:1.0`, `:1.1` series tags are set automatically via semver parsing
- `:dev` is only set for `main` branch pushes
- `:sha-<commit>` is set for every build

### Other Git Rules

- **Do NOT add AI Co-Authored-By lines** (e.g., Claude, GPT) to commit messages — real human co-authors are fine
- **Do NOT include "Generated with Claude" or similar AI attribution** in PR descriptions
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
- **Demo EC2 instance** (`i-0caaf8acac6f85d4d`, Elastic IP `3.222.57.187`): Only pull pre-built images from `ghcr.io`, never `docker compose build`.
- **SSH access**: `ssh ubuntu@3.222.57.187` (uses local SSH key)
- **Demo stack**: Managed via systemd service `artifact-keeper-demo` and Caddy reverse proxy for TLS. Compose file at `/opt/artifact-keeper/deploy/demo/docker-compose.demo.yml`.
- **Demo version pinning**: Set `ARTIFACT_KEEPER_VERSION` in `/opt/artifact-keeper/deploy/demo/.env` to pin a release (e.g., `ARTIFACT_KEEPER_VERSION=1.1.0-rc.2`). Omit the `v` prefix — Docker tags use semver without `v`. Default is `latest` if unset.
- **Demo update procedure**: `ssh ubuntu@3.222.57.187`, edit `.env` with the desired version, then `cd /opt/artifact-keeper/deploy/demo && docker compose -f docker-compose.demo.yml pull && docker compose -f docker-compose.demo.yml up -d`.
- **Docker images** are published to `ghcr.io/artifact-keeper/artifact-keeper-{backend,web,openscap}` by the Docker Publish CI workflow on every push to main and on release tags.
- **GitHub Pages site** (`/site/` directory): Combined landing page + Starlight docs, deployed to `artifactkeeper.com`.

<!-- MANUAL ADDITIONS END -->
