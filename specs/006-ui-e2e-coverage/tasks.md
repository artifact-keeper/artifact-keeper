# Tasks: UI E2E Test Coverage

**Input**: Design documents from `/specs/006-ui-e2e-coverage/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- **Frontend E2E**: `frontend/e2e/` at repository root
- Page Objects: `frontend/e2e/pages/`
- Test Fixtures: `frontend/e2e/fixtures/`
- Test Specs: `frontend/e2e/*.spec.ts`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Create test infrastructure shared by all user stories

- [X] T001 Create pages directory structure in frontend/e2e/pages/
- [X] T002 Create fixtures directory structure in frontend/e2e/fixtures/
- [X] T003 [P] Implement BasePage class with common utilities in frontend/e2e/pages/BasePage.ts
- [X] T004 [P] Implement test data factory with uniqueId() in frontend/e2e/fixtures/test-data.ts
- [X] T005 [P] Implement cleanup utility for test resource cleanup in frontend/e2e/fixtures/cleanup.ts
- [X] T006 [P] Implement auth fixture with login helpers in frontend/e2e/fixtures/auth.fixture.ts
- [X] T007 Enhance global-setup.ts with test data seeding in frontend/e2e/global-setup.ts

---

## Phase 2: Foundational Page Objects (Blocking Prerequisites)

**Purpose**: Core page objects that MUST be complete before ANY user story test can be implemented

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T008 [P] Implement LoginPage with login/logout methods in frontend/e2e/pages/LoginPage.ts
- [X] T009 [P] Implement DashboardPage with widget locators in frontend/e2e/pages/DashboardPage.ts
- [X] T010 [P] Implement RepositoriesPage with table/create button in frontend/e2e/pages/RepositoriesPage.ts

**Checkpoint**: Foundation ready - user story implementation can now begin in parallel

---

## Phase 3: User Story 1 - Repository Creation Wizard E2E Tests (Priority: P1) 🎯 MVP

**Goal**: Complete E2E test coverage for the multi-step repository creation wizard with form state persistence validation

**Independent Test**: Run `TEST_TAG=@smoke npx playwright test repositories.spec.ts` - all wizard tests pass

### Page Objects for User Story 1

- [X] T011 [US1] Implement RepoWizardPage with all step locators in frontend/e2e/pages/RepoWizardPage.ts
- [X] T012 [US1] Add step navigation methods (next, previous, cancel) to RepoWizardPage in frontend/e2e/pages/RepoWizardPage.ts
- [X] T013 [US1] Add form fill methods for each step to RepoWizardPage in frontend/e2e/pages/RepoWizardPage.ts

### E2E Tests for User Story 1

- [X] T014 [US1] Rewrite @smoke test for complete local repo wizard flow in frontend/e2e/repositories.spec.ts
- [X] T015 [P] [US1] Add @smoke test for form state persistence (navigate back) in frontend/e2e/repositories.spec.ts
- [X] T016 [P] [US1] Add @full test for remote repository wizard flow in frontend/e2e/repositories.spec.ts
- [X] T017 [P] [US1] Add @full test for virtual repository wizard flow in frontend/e2e/repositories.spec.ts
- [X] T018 [P] [US1] Add @full test for wizard validation errors in frontend/e2e/repositories.spec.ts
- [X] T019 [P] [US1] Add @full test for wizard cancel behavior in frontend/e2e/repositories.spec.ts
- [X] T020 [US1] Update test cleanup to delete created test repos in frontend/e2e/repositories.spec.ts

**Checkpoint**: At this point, User Story 1 should be fully functional and testable independently

---

## Phase 4: User Story 2 - Migration Wizard E2E Tests (Priority: P1)

**Goal**: Complete E2E test coverage for the Artifactory migration wizard with progress monitoring

**Independent Test**: Run `npx playwright test migration.spec.ts` - all migration tests pass

### Page Objects for User Story 2

- [X] T021 [P] [US2] Implement MigrationPage with jobs table in frontend/e2e/pages/MigrationPage.ts
- [X] T022 [US2] Implement MigrationWizardPage with all step locators in frontend/e2e/pages/MigrationWizardPage.ts
- [X] T023 [US2] Add source config methods to MigrationWizardPage in frontend/e2e/pages/MigrationWizardPage.ts
- [X] T024 [US2] Add progress monitoring methods to MigrationWizardPage in frontend/e2e/pages/MigrationWizardPage.ts

### E2E Tests for User Story 2

- [X] T025 [US2] Create migration.spec.ts with @smoke complete migration flow test in frontend/e2e/migration.spec.ts
- [X] T026 [P] [US2] Add @smoke test for source connection validation in frontend/e2e/migration.spec.ts
- [X] T027 [P] [US2] Add @full test for invalid credentials error handling in frontend/e2e/migration.spec.ts
- [X] T028 [P] [US2] Add @full test for progress monitoring display in frontend/e2e/migration.spec.ts
- [X] T029 [P] [US2] Add @full test for pause/resume migration in frontend/e2e/migration.spec.ts
- [X] T030 [P] [US2] Add @full test for migration completion summary in frontend/e2e/migration.spec.ts

**Checkpoint**: At this point, User Stories 1 AND 2 should both work independently

---

## Phase 5: User Story 3 - CI/CD Platform Setup Wizard E2E Tests (Priority: P2)

**Goal**: E2E tests for CI/CD platform configuration wizards (GitHub Actions, GitLab CI, Jenkins)

**Independent Test**: Run `npx playwright test setup-cicd.spec.ts` - all CI/CD setup tests pass

### Page Objects for User Story 3

- [X] T031 [US3] Implement SetupPage with platform tabs in frontend/e2e/pages/SetupPage.ts
- [X] T032 [US3] Add code block and copy button locators to SetupPage in frontend/e2e/pages/SetupPage.ts

### E2E Tests for User Story 3

- [X] T033 [US3] Create setup-cicd.spec.ts with @smoke GitHub Actions test in frontend/e2e/setup-cicd.spec.ts
- [X] T034 [P] [US3] Add @smoke test for copy-to-clipboard functionality in frontend/e2e/setup-cicd.spec.ts
- [X] T035 [P] [US3] Add @full test for GitLab CI setup display in frontend/e2e/setup-cicd.spec.ts
- [X] T036 [P] [US3] Add @full test for Jenkins setup instructions in frontend/e2e/setup-cicd.spec.ts
- [X] T037 [P] [US3] Add @full test for Azure DevOps setup display in frontend/e2e/setup-cicd.spec.ts
- [X] T038 [US3] Add @full test for repository-specific values in templates in frontend/e2e/setup-cicd.spec.ts

**Checkpoint**: User Story 3 complete and testable independently

---

## Phase 6: User Story 4 - Package Manager Setup Wizard E2E Tests (Priority: P2)

**Goal**: E2E tests for package manager configuration wizards (Maven, npm, Docker, PyPI)

**Independent Test**: Run `npx playwright test setup-package-manager.spec.ts` - all package manager tests pass

### E2E Tests for User Story 4 (reuses SetupPage from US3)

- [X] T039 [US4] Create setup-package-manager.spec.ts with @smoke npm setup test in frontend/e2e/setup-package-manager.spec.ts
- [X] T040 [P] [US4] Add @smoke test for Maven settings.xml display in frontend/e2e/setup-package-manager.spec.ts
- [X] T041 [P] [US4] Add @full test for Docker login commands in frontend/e2e/setup-package-manager.spec.ts
- [X] T042 [P] [US4] Add @full test for PyPI twine config in frontend/e2e/setup-package-manager.spec.ts
- [X] T043 [P] [US4] Add @full test for Go module config in frontend/e2e/setup-package-manager.spec.ts
- [X] T044 [US4] Add @full test for copy functionality with success toast in frontend/e2e/setup-package-manager.spec.ts

**Checkpoint**: User Story 4 complete and testable independently

---

## Phase 7: User Story 5 - Dashboard and Onboarding Wizard E2E Tests (Priority: P2)

**Goal**: E2E tests for dashboard widgets and first-time user onboarding experience

**Independent Test**: Run `npx playwright test dashboard.spec.ts` - all dashboard tests pass

### E2E Tests for User Story 5 (enhances existing dashboard.spec.ts)

- [X] T045 [US5] Enhance DashboardPage with onboarding wizard locators in frontend/e2e/pages/DashboardPage.ts
- [X] T046 [US5] Add @smoke test for onboarding wizard flow for new user in frontend/e2e/dashboard.spec.ts
- [X] T047 [P] [US5] Add @smoke test for dashboard widgets display in frontend/e2e/dashboard.spec.ts
- [X] T048 [P] [US5] Add @full test for empty state when no repos exist in frontend/e2e/dashboard.spec.ts
- [X] T049 [P] [US5] Add @full test for widget data refresh in frontend/e2e/dashboard.spec.ts
- [X] T050 [US5] Add @full test for onboarding wizard completion persistence in frontend/e2e/dashboard.spec.ts

**Checkpoint**: User Story 5 complete and testable independently

---

## Phase 8: User Story 6 - Authentication Flow E2E Tests (Priority: P2)

**Goal**: E2E tests for complete authentication flows including MFA

**Independent Test**: Run `npx playwright test auth.spec.ts` - all auth tests pass

### E2E Tests for User Story 6 (enhances existing auth.spec.ts)

- [X] T051 [US6] Add MFA enrollment page locators to LoginPage in frontend/e2e/pages/LoginPage.ts
- [X] T052 [US6] Add @smoke test for complete login/logout cycle in frontend/e2e/auth.spec.ts
- [X] T053 [P] [US6] Add @full test for invalid credentials error in frontend/e2e/auth.spec.ts
- [X] T054 [P] [US6] Add @full test for MFA enrollment flow in frontend/e2e/auth.spec.ts
- [X] T055 [P] [US6] Add @full test for MFA challenge on login in frontend/e2e/auth.spec.ts
- [X] T056 [US6] Add @full test for SSO provider buttons visibility in frontend/e2e/auth.spec.ts

**Checkpoint**: User Story 6 complete and testable independently

---

## Phase 9: User Story 7 - User Profile Management E2E Tests (Priority: P3)

**Goal**: E2E tests for profile management, API keys, and access tokens

**Independent Test**: Run `npx playwright test profile.spec.ts` - all profile tests pass

### Page Objects for User Story 7

- [X] T057 [US7] Implement ProfilePage with API key/token locators in frontend/e2e/pages/ProfilePage.ts
- [X] T058 [US7] Add API key generation/revoke methods to ProfilePage in frontend/e2e/pages/ProfilePage.ts

### E2E Tests for User Story 7

- [X] T059 [US7] Create profile.spec.ts with @smoke API key generation test in frontend/e2e/profile.spec.ts
- [X] T060 [P] [US7] Add @smoke test for API key copy functionality in frontend/e2e/profile.spec.ts
- [X] T061 [P] [US7] Add @full test for API key revocation in frontend/e2e/profile.spec.ts
- [X] T062 [P] [US7] Add @full test for access token creation in frontend/e2e/profile.spec.ts
- [X] T063 [US7] Add @full test for profile update in frontend/e2e/profile.spec.ts

**Checkpoint**: User Story 7 complete and testable independently

---

## Phase 10: User Story 8 - Admin User/Group Management E2E Tests (Priority: P3)

**Goal**: E2E tests for administrative user and group management

**Independent Test**: Run `npx playwright test admin.spec.ts` - all admin tests pass

### Page Objects for User Story 8

- [X] T064 [P] [US8] Implement AdminUsersPage with user CRUD locators in frontend/e2e/pages/AdminUsersPage.ts
- [X] T065 [P] [US8] Implement AdminGroupsPage with group management locators in frontend/e2e/pages/AdminGroupsPage.ts

### E2E Tests for User Story 8 (enhances existing admin.spec.ts)

- [X] T066 [US8] Refactor admin.spec.ts to use page objects in frontend/e2e/admin.spec.ts
- [X] T067 [US8] Add @smoke test for user creation flow in frontend/e2e/admin.spec.ts
- [X] T068 [P] [US8] Add @full test for group creation with members in frontend/e2e/admin.spec.ts
- [X] T069 [P] [US8] Add @full test for permission target creation in frontend/e2e/admin.spec.ts
- [X] T070 [US8] Add @full test for user permissions summary display in frontend/e2e/admin.spec.ts

**Checkpoint**: User Story 8 complete and testable independently

---

## Phase 11: User Story 9 - Search Functionality E2E Tests (Priority: P3)

**Goal**: E2E tests for quick search and advanced search functionality

**Independent Test**: Run `npx playwright test search.spec.ts` - all search tests pass

### Page Objects for User Story 9

- [X] T071 [US9] Implement SearchPage with search type locators in frontend/e2e/pages/SearchPage.ts
- [X] T072 [US9] Add quick search and advanced search methods to SearchPage in frontend/e2e/pages/SearchPage.ts

### E2E Tests for User Story 9 (enhances existing search.spec.ts)

- [X] T073 [US9] Refactor search.spec.ts to use page objects in frontend/e2e/search.spec.ts
- [X] T074 [US9] Add @smoke test for quick search dropdown in frontend/e2e/search.spec.ts
- [X] T075 [P] [US9] Add @full test for checksum search in frontend/e2e/search.spec.ts
- [X] T076 [P] [US9] Add @full test for GAVC (Maven coordinates) search in frontend/e2e/search.spec.ts
- [X] T077 [US9] Add @full test for empty search results state in frontend/e2e/search.spec.ts

**Checkpoint**: All user stories should now be independently functional

---

## Phase 12: Polish & Cross-Cutting Concerns

**Purpose**: Improvements that affect multiple user stories

- [X] T078 [P] Update quickstart.md with test run examples in specs/006-ui-e2e-coverage/quickstart.md
- [X] T079 [P] Add JSDoc comments to all page objects in frontend/e2e/pages/
- [X] T080 Run full E2E test suite and verify 90%+ pass rate
- [X] T081 Verify @smoke tests complete in under 15 minutes
- [X] T082 Verify test cleanup removes all created resources
- [X] T083 Run tests in CI and verify report generation

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion - BLOCKS all user stories
- **User Stories (Phase 3-11)**: All depend on Foundational phase completion
  - User stories can then proceed in parallel (if staffed)
  - Or sequentially in priority order (P1 → P2 → P3)
- **Polish (Phase 12)**: Depends on all desired user stories being complete

### User Story Dependencies

| Story | Priority | Depends On | Can Parallelize With |
|-------|----------|------------|---------------------|
| US1: Repo Wizard | P1 | Foundational | US2 (after T010) |
| US2: Migration | P1 | Foundational | US1 (after T010) |
| US3: CI/CD Setup | P2 | Foundational | US4, US5, US6 |
| US4: Package Setup | P2 | US3 (shares SetupPage) | US5, US6 |
| US5: Dashboard | P2 | Foundational | US3, US4, US6 |
| US6: Auth | P2 | Foundational | US3, US4, US5 |
| US7: Profile | P3 | Foundational | US8, US9 |
| US8: Admin | P3 | Foundational | US7, US9 |
| US9: Search | P3 | Foundational | US7, US8 |

### Within Each User Story

- Page objects before tests
- @smoke tests before @full tests
- Complete test cleanup before marking complete

### Parallel Opportunities

- All Setup tasks marked [P] can run in parallel
- All Foundational tasks marked [P] can run in parallel (within Phase 2)
- Once Foundational phase completes, US1 and US2 can start in parallel
- All P2 user stories (US3-US6) can run in parallel
- All P3 user stories (US7-US9) can run in parallel
- Tests within a story marked [P] can run in parallel

---

## Parallel Example: User Story 1

```bash
# Launch all page object tasks for US1 sequentially (same file):
Task: T011 "Implement RepoWizardPage with all step locators"
Task: T012 "Add step navigation methods to RepoWizardPage"
Task: T013 "Add form fill methods for each step to RepoWizardPage"

# After T014, launch all [P] test tasks together:
Task: T015 "@smoke test for form state persistence"
Task: T016 "@full test for remote repository wizard"
Task: T017 "@full test for virtual repository wizard"
Task: T018 "@full test for wizard validation errors"
Task: T019 "@full test for wizard cancel behavior"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational
3. Complete Phase 3: User Story 1 (Repo Wizard)
4. **STOP and VALIDATE**: Run `TEST_TAG=@smoke npx playwright test repositories.spec.ts`
5. This alone catches the form state bug we discovered

### Incremental Delivery

1. Complete Setup + Foundational → Foundation ready
2. Add US1 (Repo Wizard) → Test independently → This is the MVP
3. Add US2 (Migration) → Both P1 stories complete
4. Add US3-US6 → P2 stories complete
5. Add US7-US9 → Full E2E coverage
6. Each story adds coverage without breaking previous tests

### Parallel Team Strategy

With multiple developers:

1. Team completes Setup + Foundational together
2. Once Foundational is done:
   - Developer A: US1 (Repo Wizard) + US2 (Migration)
   - Developer B: US3 (CI/CD) + US4 (Package Manager)
   - Developer C: US5 (Dashboard) + US6 (Auth)
   - Developer D: US7 (Profile) + US8 (Admin) + US9 (Search)
3. Stories complete and integrate independently

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Each user story should be independently completable and testable
- @smoke tests are critical path tests for PR gate
- @full tests include edge cases for release gate
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- Test cleanup is critical for repeatable test runs
