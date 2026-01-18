# Feature Specification: Staged Testing Strategy for CI/CD

**Feature Branch**: `005-staged-testing-ci`
**Created**: 2026-01-18
**Status**: Draft
**Input**: User description: "Implement staged testing strategy separating fast CI tests from heavy E2E tests"

## Clarifications

### Session 2026-01-18
- Q: When backend server crashes during active operation (e.g., artifact upload mid-push), what recovery behavior should tests validate? → A: Atomic rollback (partial operations fully reversed, no orphaned state)
- Q: What concurrent load level should stress tests validate? → A: 100 concurrent operations (moderate stress, catches most concurrency bugs)
- Q: How should tests simulate backend failures for recovery validation? → A: Controlled service termination via test harness (kill process/container at specific points)
- Q: Which failure scenarios are highest priority for production-style testing? → A: Comprehensive coverage (server crash + database disconnect + storage backend failure)
- Q: Which package managers should have native client integration tests? → A: All major formats (PyPI/pip, NPM/npm, Maven/mvn, Cargo, Go, RPM/dnf, Debian/apt, Conda, Helm)
- Q: How should Docker Compose profiles organize native client tests? → A: Per-format profiles (rpm, deb, pypi, npm, etc.) + "all" profile + default runs smoke subset
- Q: How should tests validate SSL/TLS connectivity with package manager clients? → A: Self-signed CA with generated test certificates (clients trust test CA)
- Q: How should tests validate GPG signing for RPM and Debian repositories? → A: Generate test GPG keys, sign packages/repos, validate with dnf/apt
- Q: Which base images for Linux distro package manager tests? → A: Rocky Linux UBI for RPM (dnf), Debian official for apt
- Q: Where should test packages/artifacts come from for native client testing? → A: Generate packages from templates in `.assets/` folder (pyproject.toml, Cargo.toml, package.json, etc.)
- Q: Should generated packages include size variations for stress testing? → A: Fixed size tiers: small (<1MB), medium (~10MB), large (~100MB)
- Q: How should Docker/OCI images be handled for push/pull validation? → A: Build minimal test images during test setup (docker build → docker push → docker pull)
- Q: Should tests have external network dependencies or be air-gapped? → A: Fully air-gapped - zero external network calls during tests

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Fast Feedback on Every Push (Priority: P1)

As a developer, I want to receive fast feedback when I push code or create a pull request, so that I can quickly identify and fix issues without waiting for heavy test suites to complete.

**Why this priority**: Fast feedback loops are critical for developer productivity. Every push/PR should validate code quality within minutes, not tens of minutes.

**Independent Test**: Can be fully tested by pushing a commit to any branch and verifying that lint and unit tests complete within the target time, delivering immediate feedback on code quality.

**Acceptance Scenarios**:

1. **Given** a developer pushes code to any branch, **When** the CI pipeline runs, **Then** lint checks and unit tests complete within 5 minutes
2. **Given** a developer creates a pull request, **When** the CI pipeline runs, **Then** only Tier 1 tests (lint + unit) execute automatically
3. **Given** a push to any branch, **When** CI completes, **Then** E2E tests do NOT run automatically

---

### User Story 2 - Integration Testing on Main Branch (Priority: P2)

As a team lead, I want integration tests to run when code is merged to the main branch, so that we catch integration issues early while keeping PR feedback fast.

**Why this priority**: Integration tests catch issues that unit tests miss, but running them on every PR slows feedback. Running on main branch merges balances thoroughness with speed.

**Independent Test**: Can be fully tested by merging a PR to main and verifying that integration tests run with database connectivity.

**Acceptance Scenarios**:

1. **Given** a PR is merged to the main branch, **When** the CI pipeline runs, **Then** integration tests execute with a database service
2. **Given** a push to a feature branch, **When** the CI pipeline runs, **Then** integration tests do NOT execute
3. **Given** integration tests are running, **When** they complete, **Then** Docker images are built successfully

---

### User Story 3 - Comprehensive E2E Testing for Releases (Priority: P2)

As a release manager, I want comprehensive E2E tests to run before releases, so that I have confidence the full system works correctly before deployment.

**Why this priority**: E2E tests are the final quality gate before release. They must pass before any release is published.

**Independent Test**: Can be fully tested by triggering a release workflow and verifying E2E tests run and block release if they fail.

**Acceptance Scenarios**:

1. **Given** a version tag is pushed (e.g., `v1.0.0`), **When** the release workflow starts, **Then** E2E tests run before release publication
2. **Given** E2E tests fail during release, **When** the workflow completes, **Then** the release is NOT published
3. **Given** E2E tests pass during release, **When** the workflow completes, **Then** the release is published with all artifacts

---

### User Story 4 - Manual E2E Test Triggering (Priority: P3)

As a developer, I want to manually trigger E2E tests when needed, so that I can validate complex changes before merging without waiting for a release.

**Why this priority**: Provides flexibility for developers to run comprehensive tests on-demand without requiring a release.

**Independent Test**: Can be fully tested by manually triggering the E2E workflow from the GitHub Actions interface.

**Acceptance Scenarios**:

1. **Given** I am on the GitHub Actions page, **When** I manually trigger the E2E workflow, **Then** the full E2E test suite runs
2. **Given** I manually trigger E2E tests on a feature branch, **When** the tests complete, **Then** I receive the test results and reports

---

### User Story 5 - Smoke vs Full E2E Test Selection (Priority: P3)

As a developer, I want to run a quick subset of E2E tests (smoke tests) for faster validation, so that I can get reasonable E2E coverage without running the full suite.

**Why this priority**: Provides a middle ground between no E2E tests and full E2E suite, useful for quick validation.

**Independent Test**: Can be fully tested by running E2E tests with smoke tag filter and verifying only tagged tests execute.

**Acceptance Scenarios**:

1. **Given** E2E tests are tagged with `@smoke` or `@full`, **When** I run with smoke filter, **Then** only `@smoke` tagged tests execute
2. **Given** I run the full E2E suite, **When** tests complete, **Then** both `@smoke` and `@full` tagged tests have executed

---

### User Story 6 - Native Package Manager Client Testing (Priority: P2)

As a platform engineer, I want E2E tests to validate that real package manager clients (pip, npm, cargo, dnf, apt, etc.) can successfully push and pull packages from our registry, so that I have confidence the registry works with official tools in production.

**Why this priority**: API-level tests can pass while native clients fail due to protocol nuances. Testing with real tools catches format/protocol issues before users encounter them.

**Independent Test**: Can be fully tested by running Docker Compose with specific profiles and verifying native client operations succeed.

**Acceptance Scenarios**:

1. **Given** a test repository is configured, **When** `pip install` runs against it, **Then** the package downloads and installs successfully
2. **Given** a signed RPM repository, **When** `dnf install` runs with gpgcheck enabled, **Then** the package installs with valid signature
3. **Given** Docker Compose runs with `--profile all`, **When** all native client tests complete, **Then** every package format has passed push and pull validation
4. **Given** Docker Compose runs without a profile, **When** tests complete, **Then** only smoke subset of formats are tested

---

### Edge Cases

- What happens when integration tests fail on main branch? (Build should still fail, blocking subsequent jobs)
- What happens when E2E workflow is triggered but services fail to start? (Timeout and fail with clear error)
- How does the system handle concurrent E2E test runs? (CI concurrency controls should manage this)
- What happens when a release tag is pushed but E2E tests timeout? (Release should be blocked)
- What happens when backend server crashes mid-artifact-upload? (Transaction rolls back atomically, no partial artifacts stored)
- What happens when database connection drops during write operation? (Operation fails cleanly, no corrupted state)
- What happens when storage backend fails during artifact write? (Operation fails with clear error, no partial files left on disk/S3)
- What happens when native client can't verify SSL certificate? (Client fails with clear TLS error, test catches misconfigured CA trust)
- What happens when GPG signature verification fails in dnf/apt? (Package install rejected, test validates signing is working)
- What happens when API key is invalid for authenticated push? (Client receives 401/403, test validates auth flow)

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: CI system MUST run lint checks (code formatting, static analysis) on every push and pull request
- **FR-002**: CI system MUST run backend unit tests on every push and pull request
- **FR-003**: CI system MUST run frontend unit tests on every push and pull request
- **FR-004**: CI system MUST complete Tier 1 tests (lint + unit) within 5 minutes for typical codebases
- **FR-005**: CI system MUST run backend integration tests only on pushes to the main branch
- **FR-006**: CI system MUST provide a separate E2E workflow that can be triggered manually
- **FR-007**: CI system MUST run E2E tests before publishing any release
- **FR-008**: CI system MUST block release publication if E2E tests fail
- **FR-009**: E2E test configuration MUST support filtering tests by tag (smoke vs full)
- **FR-010**: CI system MUST upload test reports and artifacts for debugging failed tests
- **FR-011**: CI system MUST NOT run E2E tests on regular push/PR events
- **FR-012**: Backend test utilities MUST be available for handler testing without requiring HTTP server
- **FR-013**: Integration tests MUST validate atomic rollback behavior when server fails mid-operation (no orphaned artifacts or partial state)
- **FR-014**: Stress tests MUST validate backend handles 100 concurrent operations without data corruption or deadlocks
- **FR-015**: Stress tests MUST be included in Tier 3 (E2E/release) testing, not in fast CI
- **FR-016**: Failure recovery tests MUST use controlled service termination (process/container kill) to simulate crashes at specific operation points
- **FR-017**: Test harness MUST support triggering failures at deterministic points (e.g., mid-upload, mid-transaction)
- **FR-018**: Failure tests MUST cover server crash mid-operation scenario (process termination during active request)
- **FR-019**: Failure tests MUST cover database disconnect scenario (connection drop during transaction)
- **FR-020**: Failure tests MUST cover storage backend failure scenario (I/O errors during artifact read/write)
- **FR-021**: E2E tests MUST validate native client operations for all major package formats: PyPI (pip), NPM (npm), Maven (mvn), Cargo, Go modules, RPM (dnf), Debian (apt), Conda, Helm
- **FR-022**: Native client tests MUST verify both push (publish/upload) and pull (install/download) operations using official tools
- **FR-023**: Native client tests MUST use real package manager binaries in containerized test environments
- **FR-024**: Docker Compose MUST provide per-format profiles (e.g., `--profile rpm`, `--profile pypi`, `--profile npm`) for selective testing
- **FR-025**: Docker Compose MUST provide an "all" profile that runs all native client tests
- **FR-026**: Docker Compose MUST run a smoke subset of tests when no profile is specified (default behavior)
- **FR-027**: Test infrastructure MUST generate a self-signed CA and TLS certificates for HTTPS testing
- **FR-028**: Native client test containers MUST trust the test CA to validate full TLS handshake
- **FR-029**: SSL/TLS tests MUST verify certificate chain validation works correctly with each package manager client
- **FR-030**: Test infrastructure MUST generate GPG keys for signing RPM and Debian repositories
- **FR-031**: RPM repository tests MUST validate GPG signature verification using dnf with gpgcheck enabled
- **FR-032**: Debian repository tests MUST validate Release file GPG signing and apt signature verification
- **FR-033**: RPM tests MUST use Rocky Linux UBI as the base container image for dnf operations
- **FR-034**: Debian tests MUST use official Debian image as the base container for apt operations
- **FR-035**: Native client tests MUST validate authentication using generated API keys/tokens where required
- **FR-036**: Test infrastructure MUST include an `.assets/` folder with package templates for each format (pyproject.toml, Cargo.toml, package.json, pom.xml, go.mod, .spec, debian/, Chart.yaml, meta.yaml)
- **FR-037**: Test setup MUST generate valid packages from templates on-the-fly during test execution
- **FR-038**: Generated test packages MUST be minimal but valid (installable by native clients)
- **FR-039**: Test package generator MUST support size tiers: small (<1MB), medium (~10MB), large (~100MB)
- **FR-040**: Stress tests MUST include large artifact uploads to validate chunked transfer and timeout handling
- **FR-041**: Docker registry tests MUST build minimal test images during test setup (not pull from external registries)
- **FR-042**: Docker tests MUST validate full workflow: `docker build` → `docker push` → `docker pull` → verify content
- **FR-043**: `.assets/` folder MUST include Dockerfile templates for generating test container images
- **FR-044**: All E2E and native client tests MUST be fully air-gapped with zero external network dependencies
- **FR-045**: Test infrastructure MUST NOT require connectivity to upstream mirrors (PyPI, npmjs, Docker Hub, Fedora, etc.)
- **FR-046**: Container base images for test runners MUST be pre-pulled or built locally (no runtime pulls from external registries)

### Key Entities

- **Test Tier**: Classification of test types (Tier 1: Fast CI, Tier 2: Integration, Tier 3: E2E) with associated triggers and time targets
- **Test Tag**: Labels applied to E2E tests (@smoke, @full) for selective execution
- **CI Workflow**: Automated process triggered by events (push, PR, tag, manual) that executes specific test tiers
- **Test Report**: Artifacts produced by test runs including results, coverage, and failure evidence
- **Failure Test Harness**: Test infrastructure that can terminate services at controlled points to validate recovery behavior
- **Native Client Test Suite**: Containerized test environments with real package manager tools (pip, npm, cargo, dnf, apt, etc.) for protocol validation
- **Test PKI Infrastructure**: Self-signed CA and certificates for TLS testing, plus GPG keys for RPM/Debian signing
- **Test Asset Templates**: Package manifest templates in `.assets/` folder for generating valid test packages across all formats (pyproject.toml, Cargo.toml, package.json, pom.xml, etc.)

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Tier 1 tests (lint + unit) complete within 5 minutes on every push/PR
- **SC-002**: Developers receive CI feedback on code quality before E2E tests would complete (under 5 min vs 30 min)
- **SC-003**: Integration tests run automatically on 100% of merges to main branch
- **SC-004**: E2E tests run as a gate for 100% of releases (no release without E2E pass)
- **SC-005**: Developers can manually trigger E2E tests within 3 clicks from CI interface
- **SC-006**: Smoke E2E tests complete within 10 minutes when filtered
- **SC-007**: Full E2E test suite completes within 30 minutes
- **SC-008**: Test reports are available for all failed test runs within 24 hours (artifact retention)
- **SC-009**: Backend sustains 100 concurrent operations with zero data corruption or deadlocks during stress tests
- **SC-010**: All three failure scenarios (server crash, DB disconnect, storage failure) result in clean rollback with no orphaned data
- **SC-011**: All 9 major package formats pass native client push/pull tests with `--profile all`
- **SC-012**: Native client tests validate SSL/TLS with certificate chain verification (no --insecure flags)
- **SC-013**: RPM and Debian tests pass with GPG signature validation enabled
- **SC-014**: All native client tests pass in air-gapped environment (no external network required)
- **SC-015**: Test package generation from `.assets/` templates completes in under 30 seconds per format

## Assumptions

- The project uses a CI/CD platform that supports workflow triggers, conditions, and manual dispatch
- The project has existing backend unit tests and frontend unit tests that can be run independently
- The project has an E2E test suite that can be executed via a test runner
- Database services can be provisioned for integration tests
- The team follows semantic versioning with version tags for releases
- Test reports and artifacts can be stored and retrieved for debugging
