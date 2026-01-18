# Changelog

All notable changes to Artifact Keeper will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### Staged Testing Strategy (005-staged-testing-ci)
- **Tiered CI/CD Testing Infrastructure**
  - Tier 1 (Every Push/PR): Fast lint and unit tests completing in under 5 minutes
  - Tier 2 (Main Branch): Integration tests with PostgreSQL database
  - Tier 3 (Release/Manual): Full E2E suite with native client testing

- **GitHub Actions Workflows**
  - Restructured `ci.yml` for tiered testing with conditional job execution
  - New `e2e.yml` workflow with manual trigger and profile selection
  - Added E2E gate to `release.yml` blocking releases on test failure

- **Native Package Manager Client Testing**
  - Test scripts for 10 package formats: PyPI, NPM, Cargo, Maven, Go, RPM, Debian, Helm, Conda, Docker
  - Docker Compose profiles for selective test execution (smoke, all, individual formats)
  - Package templates in `.assets/` for generating test artifacts of various sizes

- **Stress and Failure Testing**
  - Stress testing infrastructure for 100 concurrent upload operations
  - Failure injection tests: server crash recovery, database disconnect handling, storage failure scenarios
  - Results validation with checksums and data consistency checks

- **PKI Infrastructure for Testing**
  - Self-signed CA and TLS certificate generation scripts
  - GPG key generation for RPM and Debian package signing

- **Test Improvements**
  - Playwright test tagging with `@smoke` and `@full` for selective execution
  - New frontend API tests: `artifacts.test.ts`, `admin.test.ts`
  - Backend handler unit tests using `axum-test` in `health.rs`
  - Backend test utilities module with fixtures and helpers

- **Script Enhancements**
  - Updated `run-e2e-tests.sh` with profile, stress, and failure test options
  - Master test runners for native clients (`scripts/native-tests/run-all.sh`)
  - Stress test runner (`scripts/stress/run-concurrent-uploads.sh`)
  - Failure test runner (`scripts/failure/run-all.sh`)

### Changed
- Updated `CLAUDE.md` with comprehensive testing commands documentation
- Extended `docker-compose.test.yml` with native client test services and profiles
- Added `axum-test` dev dependency to backend `Cargo.toml`

## [0.1.0] - 2026-01-14

### Added
- Initial release of Artifact Keeper
- Multi-format artifact registry supporting PyPI, NPM, Cargo, Maven, Go, RPM, Debian, Helm, Conda, and Docker
- React frontend with Ant Design UI components
- Rust backend with Axum web framework
- PostgreSQL database for metadata storage
- JWT-based authentication
- Repository management (create, update, delete)
- Artifact upload and download
- Search functionality across repositories
- User management and permissions
- Health check endpoints
- Prometheus metrics endpoint

### Infrastructure
- Docker Compose setup for local development
- GitHub Actions CI pipeline
- Playwright E2E test suite
- Vitest unit test suite for frontend
- Cargo test suite for backend

---

[Unreleased]: https://github.com/brandonrc/artifact-keeper/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/brandonrc/artifact-keeper/releases/tag/v0.1.0
