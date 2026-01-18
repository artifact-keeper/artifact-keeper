# Tasks: Staged Testing Strategy for CI/CD

**Input**: Design documents from `/specs/005-staged-testing-ci/`
**Prerequisites**: plan.md (required), spec.md (required), research.md, data-model.md, contracts/

**Tests**: This feature IS about testing infrastructure, so implementation tasks are the tests themselves. No separate test tasks needed.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- **Web app**: `backend/`, `frontend/`, `.github/workflows/`, `.assets/`
- Paths are relative to repository root

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization and test infrastructure foundation

- [x] T001 Create `.assets/` directory structure for package templates per plan.md
- [x] T002 [P] Create PKI generation script in `scripts/pki/generate-certs.sh`
- [x] T003 [P] Create GPG key generation script in `scripts/pki/generate-gpg.sh`
- [x] T004 [P] Add axum-test dev-dependency to `backend/Cargo.toml`
- [x] T005 [P] Create backend test utilities module in `backend/tests/common/mod.rs`
- [x] T006 [P] Create backend test fixtures in `backend/tests/common/fixtures.rs`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core test infrastructure that MUST be complete before ANY user story can be implemented

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [x] T007 Create base Docker Compose test configuration in `docker-compose.test.yml` with profile support structure
- [x] T008 [P] Create PyPI package template in `.assets/pypi/pyproject.toml` and `.assets/pypi/generate.sh`
- [x] T009 [P] Create NPM package template in `.assets/npm/package.json` and `.assets/npm/generate.sh`
- [x] T010 [P] Create Cargo package template in `.assets/cargo/Cargo.toml` and `.assets/cargo/generate.sh`
- [x] T011 [P] Create Maven package template in `.assets/maven/pom.xml` and `.assets/maven/generate.sh`
- [x] T012 [P] Create Go module template in `.assets/go/go.mod` and `.assets/go/generate.sh`
- [x] T013 [P] Create RPM package template in `.assets/rpm/test-package.spec` and `.assets/rpm/generate.sh`
- [x] T014 [P] Create Debian package template in `.assets/debian/debian/` structure and `.assets/debian/generate.sh`
- [x] T015 [P] Create Helm chart template in `.assets/helm/Chart.yaml` and `.assets/helm/generate.sh`
- [x] T016 [P] Create Conda package template in `.assets/conda/meta.yaml` and `.assets/conda/generate.sh`
- [x] T017 [P] Create Docker image template in `.assets/docker/Dockerfile` and `.assets/docker/generate.sh`
- [x] T018 Create master package generation script in `scripts/assets/generate-all.sh` with size tier support (small/medium/large)

**Checkpoint**: Foundation ready - user story implementation can now begin in parallel

---

## Phase 3: User Story 1 - Fast Feedback on Every Push (Priority: P1) 🎯 MVP

**Goal**: Developers receive lint and unit test feedback within 5 minutes on every push/PR

**Independent Test**: Push a commit to any branch and verify lint + unit tests complete in under 5 minutes, and E2E tests do NOT run

### Implementation for User Story 1

- [x] T019 [US1] Modify `.github/workflows/ci.yml` to restructure for Tier 1 only on push/PR (remove E2E job from default flow)
- [x] T020 [P] [US1] Add conditional for integration tests to run only on main branch in `.github/workflows/ci.yml`
- [x] T021 [P] [US1] Update build-backend job dependencies in `.github/workflows/ci.yml` to not require skipped integration tests
- [x] T022 [P] [US1] Update ci-complete job to exclude E2E from required checks in `.github/workflows/ci.yml`
- [x] T023 [US1] Verify Tier 1 tests (lint + unit) complete within 5 minutes target

**Checkpoint**: At this point, User Story 1 should be fully functional - fast CI feedback on every push/PR

---

## Phase 4: User Story 2 - Integration Testing on Main Branch (Priority: P2)

**Goal**: Integration tests run automatically when code is merged to main branch

**Independent Test**: Merge a PR to main and verify integration tests run with database connectivity

### Implementation for User Story 2

- [x] T024 [US2] Ensure `.github/workflows/ci.yml` integration job has `if: github.ref == 'refs/heads/main' && github.event_name == 'push'` condition
- [x] T025 [P] [US2] Verify Postgres service configuration in integration test job
- [x] T026 [P] [US2] Add Docker build jobs that depend on integration test success (main branch only)
- [x] T027 [US2] Test that integration tests do NOT run on feature branch pushes

**Checkpoint**: At this point, User Stories 1 AND 2 should both work independently

---

## Phase 5: User Story 3 - Comprehensive E2E Testing for Releases (Priority: P2)

**Goal**: E2E tests run before any release publication and block release if they fail

**Independent Test**: Push a version tag and verify E2E tests run and block/allow release based on result

### Implementation for User Story 3

- [x] T028 [US3] Modify `.github/workflows/release.yml` to call E2E workflow before release publication
- [x] T029 [P] [US3] Add E2E job dependency to release publish step in `.github/workflows/release.yml`
- [x] T030 [P] [US3] Configure release workflow to abort if E2E tests fail
- [x] T031 [US3] Verify release is blocked when E2E tests fail (manual validation)

**Checkpoint**: At this point, releases require E2E tests to pass

---

## Phase 6: User Story 4 - Manual E2E Test Triggering (Priority: P3)

**Goal**: Developers can manually trigger E2E tests from GitHub Actions interface

**Independent Test**: Manually trigger the E2E workflow from GitHub Actions page and verify tests run

### Implementation for User Story 4

- [x] T032 [US4] Create dedicated E2E workflow in `.github/workflows/e2e.yml` with workflow_dispatch trigger
- [x] T033 [P] [US4] Add input parameters for profile selection (smoke, all, pypi, npm, etc.) in `.github/workflows/e2e.yml`
- [x] T034 [P] [US4] Add input parameters for stress tests and failure tests toggles in `.github/workflows/e2e.yml`
- [x] T035 [P] [US4] Configure artifact upload for test reports in `.github/workflows/e2e.yml`
- [x] T036 [US4] Add workflow_call trigger to allow release.yml to invoke e2e.yml

**Checkpoint**: At this point, E2E tests can be triggered manually with configurable options

---

## Phase 7: User Story 5 - Smoke vs Full E2E Test Selection (Priority: P3)

**Goal**: Developers can run quick smoke tests or full E2E suite based on needs

**Independent Test**: Run tests with smoke filter and verify only smoke-tagged tests execute

### Implementation for User Story 5

- [x] T037 [US5] Update `frontend/playwright.config.ts` to support grep patterns for @smoke and @full tags
- [x] T038 [P] [US5] Tag existing E2E tests with @smoke or @full in `frontend/e2e/*.spec.ts`
- [x] T039 [P] [US5] Add smoke profile to Docker Compose that runs default subset (PyPI, NPM, Cargo) in `docker-compose.test.yml`
- [x] T040 [US5] Update e2e.yml workflow to pass tag filter based on profile input

**Checkpoint**: At this point, smoke vs full test selection works

---

## Phase 8: User Story 6 - Native Package Manager Client Testing (Priority: P2)

**Goal**: E2E tests validate real package manager clients can push/pull from registry

**Independent Test**: Run `docker compose -f docker-compose.test.yml --profile all up` and verify all 9 formats pass

### Implementation for User Story 6

#### PKI and Security Infrastructure
- [x] T041 [US6] Implement certificate generation in `scripts/pki/generate-certs.sh` (self-signed CA + server certs)
- [x] T042 [P] [US6] Implement GPG key generation in `scripts/pki/generate-gpg.sh` for RPM/Debian signing

#### Docker Compose Native Client Services
- [x] T043 [P] [US6] Add pypi-test service with pip client to `docker-compose.test.yml` (profile: pypi, all, smoke)
- [x] T044 [P] [US6] Add npm-test service with npm client to `docker-compose.test.yml` (profile: npm, all, smoke)
- [x] T045 [P] [US6] Add cargo-test service with cargo client to `docker-compose.test.yml` (profile: cargo, all, smoke)
- [x] T046 [P] [US6] Add maven-test service with mvn client to `docker-compose.test.yml` (profile: maven, all)
- [x] T047 [P] [US6] Add go-test service with go client to `docker-compose.test.yml` (profile: go, all)
- [x] T048 [P] [US6] Add rpm-test service with Rocky Linux UBI and dnf to `docker-compose.test.yml` (profile: rpm, all)
- [x] T049 [P] [US6] Add deb-test service with Debian and apt to `docker-compose.test.yml` (profile: deb, all)
- [x] T050 [P] [US6] Add helm-test service with helm CLI to `docker-compose.test.yml` (profile: helm, all)
- [x] T051 [P] [US6] Add conda-test service with conda to `docker-compose.test.yml` (profile: conda, all)
- [x] T052 [P] [US6] Add docker-test service with docker CLI to `docker-compose.test.yml` (profile: docker, all)

#### Native Client Test Scripts
- [x] T053 [P] [US6] Create PyPI push/pull test script in `scripts/native-tests/test-pypi.sh`
- [x] T054 [P] [US6] Create NPM push/pull test script in `scripts/native-tests/test-npm.sh`
- [x] T055 [P] [US6] Create Cargo push/pull test script in `scripts/native-tests/test-cargo.sh`
- [x] T056 [P] [US6] Create Maven push/pull test script in `scripts/native-tests/test-maven.sh`
- [x] T057 [P] [US6] Create Go modules push/pull test script in `scripts/native-tests/test-go.sh`
- [x] T058 [P] [US6] Create RPM push/pull test script with GPG validation in `scripts/native-tests/test-rpm.sh`
- [x] T059 [P] [US6] Create Debian push/pull test script with GPG validation in `scripts/native-tests/test-deb.sh`
- [x] T060 [P] [US6] Create Helm push/pull test script in `scripts/native-tests/test-helm.sh`
- [x] T061 [P] [US6] Create Conda push/pull test script in `scripts/native-tests/test-conda.sh`
- [x] T062 [P] [US6] Create Docker push/pull test script in `scripts/native-tests/test-docker.sh`

#### Integration
- [x] T063 [US6] Create master native test runner script in `scripts/native-tests/run-all.sh`
- [x] T064 [US6] Integrate native client tests into e2e.yml workflow

**Checkpoint**: At this point, all 9 package formats pass native client push/pull tests

---

## Phase 9: Stress and Failure Testing

**Goal**: Validate backend handles 100 concurrent ops and recovers cleanly from failures

**Independent Test**: Run stress tests and failure injection tests, verify no data corruption or orphaned state

### Stress Testing
- [x] T065 Create stress test script for 100 concurrent uploads in `scripts/stress/run-concurrent-uploads.sh`
- [x] T066 [P] Add stress test validation (checksums, counts, no deadlocks) in `scripts/stress/validate-results.sh`

### Failure Testing
- [x] T067 [P] Create server crash test script in `scripts/failure/test-server-crash.sh`
- [x] T068 [P] Create database disconnect test script in `scripts/failure/test-db-disconnect.sh`
- [x] T069 [P] Create storage failure test script in `scripts/failure/test-storage-failure.sh`
- [x] T070 Create failure test runner in `scripts/failure/run-all.sh`
- [x] T071 Add stress and failure tests to e2e.yml workflow as optional inputs

**Checkpoint**: Stress and failure testing infrastructure complete

---

## Phase 10: Polish & Cross-Cutting Concerns

**Purpose**: Final improvements and documentation

- [x] T072 [P] Create missing frontend API tests in `frontend/src/api/artifacts.test.ts`
- [x] T073 [P] Create missing frontend API tests in `frontend/src/api/admin.test.ts`
- [x] T074 [P] Add sample backend handler unit tests using axum-test in `backend/src/api/handlers/health.rs`
- [x] T075 Update `scripts/run-e2e-tests.sh` to support profile argument
- [x] T076 Validate all scripts are executable and work in air-gapped environment
- [x] T077 Run full E2E suite with `--profile all` and verify all tests pass
- [x] T078 Update CLAUDE.md with new testing commands and infrastructure

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion - BLOCKS all user stories
- **User Stories (Phase 3-8)**: All depend on Foundational phase completion
  - User Story 1 (P1): Fast feedback - can start immediately after Phase 2
  - User Story 2 (P2): Integration - can run parallel to US1
  - User Story 3 (P2): Release E2E - depends on E2E workflow existing (US4)
  - User Story 4 (P3): Manual E2E - can run parallel to US1/US2
  - User Story 5 (P3): Smoke/Full - can run parallel to US4
  - User Story 6 (P2): Native clients - can run parallel after Phase 2
- **Stress/Failure (Phase 9)**: Depends on US6 infrastructure
- **Polish (Phase 10)**: Depends on all user stories being complete

### User Story Dependencies

```
Phase 2 (Foundational)
       │
       ▼
   ┌───┴───┬───────┬───────┬───────┐
   ▼       ▼       ▼       ▼       ▼
  US1     US2     US4     US5     US6
   │              │       │
   │              ▼       │
   │             US3 ◄────┘
   │              │
   ▼              ▼
Phase 9 (Stress/Failure)
       │
       ▼
Phase 10 (Polish)
```

### Within Each User Story

- Scripts and configs can be created in parallel [P]
- Integration tasks depend on individual components
- Validation depends on implementation

### Parallel Opportunities

- **Phase 1**: T002, T003, T004, T005, T006 can all run in parallel
- **Phase 2**: T008-T017 (all package templates) can run in parallel
- **Phase 3-7**: User story phases 3, 4, 5, 6, 7 can proceed in parallel after Phase 2
- **Phase 8**: T043-T052 (Docker services) and T053-T062 (test scripts) can run in parallel
- **Phase 9**: T067, T068, T069 can run in parallel
- **Phase 10**: T072, T073, T074 can run in parallel

---

## Parallel Example: Phase 2 (Foundational)

```bash
# Launch all package template tasks together:
Task: "Create PyPI package template in .assets/pypi/"
Task: "Create NPM package template in .assets/npm/"
Task: "Create Cargo package template in .assets/cargo/"
Task: "Create Maven package template in .assets/maven/"
Task: "Create Go module template in .assets/go/"
Task: "Create RPM package template in .assets/rpm/"
Task: "Create Debian package template in .assets/debian/"
Task: "Create Helm chart template in .assets/helm/"
Task: "Create Conda package template in .assets/conda/"
Task: "Create Docker image template in .assets/docker/"
```

## Parallel Example: User Story 6 (Native Clients)

```bash
# Launch all native client Docker services together:
Task: "Add pypi-test service to docker-compose.test.yml"
Task: "Add npm-test service to docker-compose.test.yml"
Task: "Add cargo-test service to docker-compose.test.yml"
# ... (all 10 services)

# Launch all native client test scripts together:
Task: "Create PyPI test script in scripts/native-tests/test-pypi.sh"
Task: "Create NPM test script in scripts/native-tests/test-npm.sh"
# ... (all 10 scripts)
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational
3. Complete Phase 3: User Story 1 (Fast Feedback)
4. **STOP and VALIDATE**: Push a commit, verify Tier 1 tests run < 5 min, E2E does NOT run
5. Merge if ready - developers get immediate benefit

### Incremental Delivery

1. Complete Setup + Foundational → Foundation ready
2. Add User Story 1 → Test: Fast CI feedback works → Deploy (MVP!)
3. Add User Story 2 → Test: Integration on main → Deploy
4. Add User Story 4 → Test: Manual E2E trigger works → Deploy
5. Add User Story 3 → Test: Release gating works → Deploy
6. Add User Story 5 → Test: Smoke/full selection works → Deploy
7. Add User Story 6 → Test: All 9 native clients work → Deploy
8. Add Stress/Failure testing → Test: Concurrent + failure scenarios pass → Deploy
9. Polish → Final validation → Complete!

### Parallel Team Strategy

With multiple developers:

1. Team completes Setup + Foundational together
2. Once Foundational is done:
   - Developer A: User Story 1 (CI restructure) + User Story 2 (integration)
   - Developer B: User Story 4 (E2E workflow) + User Story 5 (smoke/full)
   - Developer C: User Story 6 (native client infrastructure)
3. Integrate and validate each independently
4. Developer A: User Story 3 (release gating) after US4 complete
5. All: Phase 9 (stress/failure) and Phase 10 (polish)

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Each user story should be independently completable and testable
- This feature has no separate test tasks because the feature IS the testing infrastructure
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- All scripts must work in air-gapped environment (no external network)
- Avoid: vague tasks, same file conflicts, cross-story dependencies that break independence
