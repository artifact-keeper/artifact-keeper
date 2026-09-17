# Testing Guide

This document covers the testing infrastructure for Artifact Keeper, including unit tests, integration tests, and end-to-end (E2E) tests.

## Quick Start

### Run All Tests Locally

```bash
# Backend tests (requires PostgreSQL)
cargo test --workspace

# E2E tests with Docker (fully automated, no human in the loop)
./scripts/run-e2e-tests.sh
```

### Run Tests in CI/CD

Tests run automatically on push/PR via GitHub Actions. See `.github/workflows/ci.yml`.

## Test Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Test Pyramid                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│                      ┌───────────────┐                           │
│                      │  E2E Tests    │  Native client tests      │
│                      │  (Docker)     │  (PyPI, NPM, Cargo, etc)  │
│                     ┌┴───────────────┴┐                          │
│                    ┌┴─────────────────┴┐                         │
│                   ┌┴───────────────────┴┐                        │
│                   │  Integration Tests   │  Cargo test            │
│                   │  (PostgreSQL)        │  (API + DB)            │
│                  ┌┴─────────────────────┴┐                       │
│                 ┌┴───────────────────────┴┐                      │
│                ┌┴─────────────────────────┴┐                     │
│                │       Unit Tests          │  Cargo test          │
│                │    (Functions, logic)      │  (Isolated)         │
│                └───────────────────────────┘                     │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Backend Tests

### Running Backend Tests

```bash
# Run all backend tests
cargo test --workspace

# Run with verbose output
cargo test --workspace -- --nocapture

# Run specific test
cargo test test_create_repository

# Run integration tests only
cargo test --test integration_tests
```

### Test Location

- `backend/tests/integration_tests.rs` - API integration tests
- `backend/src/**/*.rs` - Unit tests (inline `#[cfg(test)]` modules)

## Automated E2E Testing with Docker

Run fully automated E2E tests without any manual setup:

```bash
# Run all E2E tests in containers
./scripts/run-e2e-tests.sh

# Force rebuild containers
./scripts/run-e2e-tests.sh --build

# Clean up after tests
./scripts/run-e2e-tests.sh --clean
```

### How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                    docker-compose.test.yml                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐        │
│  │  PostgreSQL │────▶│   Backend   │◀────│  Native     │        │
│  │   (tmpfs)   │     │   (Rust)    │     │  Clients    │        │
│  └─────────────┘     └─────────────┘     └─────────────┘        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Container Details

| Service | Image | Purpose |
|---------|-------|---------|
| `postgres` | postgres:18-alpine | Test database (tmpfs for speed) |
| `backend` | Custom (Rust) | API server |
| `pypi-test` | python:3.14-slim | PyPI native client test |
| `npm-test` | node:26-slim | NPM native client test |
| `cargo-test` | rust:1.98-slim | Cargo native client test |

### The e2e admin credential

The e2e stacks (`docker-compose.test.yml`, `docker-compose.concurrency-e2e.yml`,
`docker-compose.mesh-e2e.yml`, `scripts/*/docker-compose.yml`, `proof/compose.*.yml`)
and the scripts that log in to them all take the value from ONE file,
[`.env.test`](.env.test) at the repository root, so the stack and the scripts
cannot disagree and the password is written down in exactly one place:

* the compose files read it through each service's `env_file:`, which is
  relative to the compose file — no `--env-file` flag, no change to how you
  invoke `docker compose`;
* host-side scripts source it through `scripts/lib/test-env.sh`, which walks up
  to the same file. Scripts running inside an e2e container do not need that:
  compose has already injected the same variables from the same file.

`.env.test` is written in the syntax that is both a dotenv file and a POSIX
shell script, which is what lets one file serve both. Every assignment in it
uses `:-`, so an exported value always wins:

```bash
# Give the run a credential that exists nowhere in this repository.
export AK_TEST_ADMIN_PASSWORD="$(openssl rand -base64 24)"
docker compose -f docker-compose.test.yml --profile smoke up
```

`scripts/run-e2e-tests.sh` does that for you and prints the value so you can
drive the same stack from another shell. Unset, everything falls back to the
placeholder in `.env.test`, so an unconfigured local run still works.

These stacks are torn down with `down -v` at the end of a run and hold nothing
worth protecting — but they are also the files people copy when they start a
deployment, which is why the fallback is a placeholder that announces what it
is rather than a plausible-looking password (#3490), and why there is only one
of it (#3938: sixty copies of one password string is indistinguishable from a
leaked credential to a secret scanner). A real deployment must set
`ADMIN_PASSWORD` (or `INITIAL_ADMIN_PASSWORD_FILE`) from its own secret store;
see the root `docker-compose.yml`.

Individual scripts still honour `ADMIN_PASS` / `ADMIN_USER` if you want to
point one at a registry that is not one of these stacks.

## CI/CD Integration

### GitHub Actions

Tests run automatically via `.github/workflows/ci.yml`:

### Jobs

1. **lint-rust** - `cargo fmt` and `cargo clippy`
2. **test-backend-unit** - Rust unit tests
3. **test-backend-integration** - Integration tests (main branch only)
4. **build-backend** - Release build
5. **smoke-e2e** - Native client smoke tests
6. **security-audit** - Dependency audit

## Coverage Goals

| Test Type | Target Coverage |
|-----------|-----------------|
| Unit Tests | 80%+ |
| E2E Tests | Critical paths |

## Resources

- [Cargo Test Documentation](https://doc.rust-lang.org/cargo/commands/cargo-test.html)
