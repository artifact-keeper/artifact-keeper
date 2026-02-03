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
| `postgres` | postgres:16-alpine | Test database (tmpfs for speed) |
| `backend` | Custom (Rust) | API server |
| `pypi-test` | python:3.12-slim | PyPI native client test |
| `npm-test` | node:20-slim | NPM native client test |
| `cargo-test` | rust:1.75-slim | Cargo native client test |

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
