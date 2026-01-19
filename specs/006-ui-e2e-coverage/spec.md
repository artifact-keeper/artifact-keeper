# Feature Specification: UI E2E Test Coverage

**Feature Branch**: `006-ui-e2e-coverage`
**Created**: 2026-01-18
**Status**: Draft
**Input**: User description: "Generate comprehensive E2E tests for all new UI components added in the 003-frontend-ui-parity feature. This includes the RepoWizard multi-step flow, migration wizards, CI/CD platform setup wizards, and any other new interactive components. Tests should cover the actual user flows through multi-step wizards, form submissions, error states, and success scenarios."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Repository Creation Wizard E2E Tests (Priority: P1)

QA engineers and developers need E2E tests that validate the complete repository creation wizard flow, ensuring form state persists across all wizard steps and the repository is successfully created with all configured options.

**Why this priority**: The repository wizard is the primary admin function and the existing E2E test is broken (doesn't match actual wizard flow). We discovered a real bug where form state was lost between steps.

**Independent Test**: Run the repository wizard E2E test suite, verify it navigates through all 5 steps, fills all required fields, and successfully creates a repository.

**Acceptance Scenarios**:

1. **Given** an admin user on the repositories page, **When** they click "Create Repository" and complete all wizard steps (type selection, package format, basic settings, advanced settings), **Then** a repository is created with all configured values.
2. **Given** the wizard at step 3 (basic settings), **When** the user fills key/name/description and clicks Next, **Then** those values are preserved when returning to step 3 via Previous.
3. **Given** an incomplete wizard at any step, **When** the user clicks Cancel, **Then** the wizard closes and no repository is created.
4. **Given** the wizard with validation errors, **When** the user tries to proceed to the next step, **Then** an error message displays and navigation is blocked.
5. **Given** a Remote repository type selected, **When** reaching the remote configuration step, **Then** the upstream URL field is visible and required.
6. **Given** a Virtual repository type selected, **When** reaching the virtual configuration step, **Then** the repository selection list is visible for aggregation.

---

### User Story 2 - Migration Wizard E2E Tests (Priority: P1)

QA engineers need E2E tests that validate the Artifactory migration wizard flow, including source configuration, repository mapping, and migration progress monitoring.

**Why this priority**: Migration is a critical feature for user onboarding from Artifactory. Multi-step wizards are prone to the same form state issues found in RepoWizard.

**Independent Test**: Run migration wizard E2E tests, verify source connection, repository selection, and migration job initiation.

**Acceptance Scenarios**:

1. **Given** an admin user on the migration page, **When** they complete the migration wizard (source config, repository selection, options), **Then** a migration job is created and appears in the jobs list.
2. **Given** the migration source step, **When** entering valid Artifactory credentials, **Then** the connection is tested and repositories are fetched.
3. **Given** invalid source credentials, **When** testing the connection, **Then** an error message displays with specific failure reason.
4. **Given** a running migration job, **When** viewing the progress page, **Then** real-time progress updates display (items completed, bytes transferred, errors).
5. **Given** a migration in progress, **When** clicking Pause, **Then** the migration pauses and can be resumed.
6. **Given** a completed migration, **When** viewing results, **Then** summary shows successful/failed/skipped items with details.

---

### User Story 3 - CI/CD Platform Setup Wizard E2E Tests (Priority: P2)

QA engineers need E2E tests for the CI/CD integration setup wizards (GitHub Actions, GitLab CI, Jenkins, Azure DevOps) ensuring configuration instructions are displayed correctly.

**Why this priority**: Setup wizards guide new users through integration - they must display correct, copyable configuration.

**Independent Test**: Navigate to Set Me Up, select a CI/CD platform, verify configuration code blocks display and can be copied.

**Acceptance Scenarios**:

1. **Given** the Set Me Up page, **When** selecting GitHub Actions, **Then** workflow YAML templates display with correct repository-specific values.
2. **Given** GitHub Actions setup selected, **When** a specific repository is selected, **Then** the workflow templates include the repository's key and URL.
3. **Given** any CI/CD platform selected, **When** clicking copy on a code block, **Then** the content is copied to clipboard and a success toast appears.
4. **Given** Jenkins selected, **When** viewing setup instructions, **Then** step-by-step plugin installation and configuration instructions display.
5. **Given** GitLab CI selected, **When** viewing setup, **Then** .gitlab-ci.yml templates with correct registry configuration display.

---

### User Story 4 - Package Manager Setup Wizard E2E Tests (Priority: P2)

QA engineers need E2E tests for package manager configuration wizards (Maven, npm, Docker, PyPI, Go, Cargo) ensuring correct setup instructions display.

**Why this priority**: Package manager setup is the primary onboarding path for developers to start using the registry.

**Independent Test**: Navigate to Set Me Up, select npm, verify .npmrc configuration and publish/install commands display correctly.

**Acceptance Scenarios**:

1. **Given** the Set Me Up page with a repository selected, **When** selecting Maven, **Then** settings.xml and pom.xml configuration display with repository URL.
2. **Given** npm selected, **When** viewing configuration, **Then** npm config commands and .npmrc content display with authentication.
3. **Given** Docker selected, **When** viewing setup, **Then** docker login and push/pull commands display with correct registry URL.
4. **Given** PyPI selected, **When** viewing setup, **Then** pip install and twine upload configuration display.
5. **Given** any package manager, **When** clicking copy on configuration, **Then** content copies to clipboard with success feedback.

---

### User Story 5 - Dashboard and Onboarding Wizard E2E Tests (Priority: P2)

QA engineers need E2E tests for the dashboard widgets and first-time user onboarding wizard flow.

**Why this priority**: Dashboard is the landing page - widgets must load correctly. Onboarding wizard guides new users through initial setup.

**Independent Test**: Log in as a new user, complete the onboarding wizard, then verify dashboard widgets display real data.

**Acceptance Scenarios**:

1. **Given** a first-time user login, **When** landing on the dashboard, **Then** the onboarding wizard modal appears with welcome message.
2. **Given** the onboarding wizard, **When** completing all steps (tour highlights), **Then** the wizard completes and dashboard displays.
3. **Given** an existing user with data, **When** viewing dashboard, **Then** widgets show artifact count, storage summary, and recent activity.
4. **Given** no repositories exist, **When** viewing dashboard, **Then** empty state with "Create your first repository" CTA displays.
5. **Given** dashboard widgets, **When** clicking refresh, **Then** data reloads and displays current values.

---

### User Story 6 - Authentication Flow E2E Tests (Priority: P2)

QA engineers need E2E tests for complete authentication flows including login, logout, MFA enrollment, and session management.

**Why this priority**: Authentication is foundational - all other features depend on it working correctly.

**Independent Test**: Complete login/logout cycle, enroll in MFA, verify MFA challenge on next login.

**Acceptance Scenarios**:

1. **Given** the login page, **When** entering valid credentials, **Then** user is authenticated and redirected to dashboard.
2. **Given** invalid credentials, **When** attempting login, **Then** error message displays without revealing which field is wrong.
3. **Given** a logged-in user, **When** clicking logout, **Then** session ends and user is redirected to login page.
4. **Given** MFA enrollment page, **When** scanning QR code and entering valid OTP, **Then** MFA is enabled on the account.
5. **Given** MFA-enabled account, **When** logging in, **Then** OTP prompt appears after password verification.
6. **Given** SSO configured, **When** on login page, **Then** SSO provider buttons are visible and clickable.

---

### User Story 7 - User Profile Management E2E Tests (Priority: P3)

QA engineers need E2E tests for profile management including API key generation, access token creation, and profile editing.

**Why this priority**: Profile features enable programmatic access - important but not blocking core workflows.

**Independent Test**: Navigate to profile, generate API key, copy it, then revoke it.

**Acceptance Scenarios**:

1. **Given** the profile page, **When** clicking "Generate API Key", **Then** a new key is created and displayed once for copying.
2. **Given** a generated API key, **When** clicking copy, **Then** the key copies to clipboard with success toast.
3. **Given** an existing API key, **When** clicking revoke, **Then** confirmation dialog appears and key is deleted on confirm.
4. **Given** access token creation, **When** filling scope and expiration, **Then** token is generated with selected permissions.
5. **Given** profile form, **When** updating display name and saving, **Then** profile is updated and success toast appears.

---

### User Story 8 - Admin User/Group Management E2E Tests (Priority: P3)

QA engineers need E2E tests for administrative user and group management workflows.

**Why this priority**: Admin functions are less frequently used but must work correctly for security management.

**Independent Test**: Create a user, add them to a group, create a permission target, verify access.

**Acceptance Scenarios**:

1. **Given** admin users page, **When** clicking "Create User", **Then** user creation form with all required fields displays.
2. **Given** user creation form, **When** filling fields and submitting, **Then** user is created and appears in the list.
3. **Given** groups page, **When** creating a group and adding members, **Then** group is created with selected users.
4. **Given** permission targets page, **When** creating a permission with repository pattern, **Then** permission target is created and active.
5. **Given** a user with permissions, **When** viewing user details, **Then** effective permissions summary displays correctly.

---

### User Story 9 - Search Functionality E2E Tests (Priority: P3)

QA engineers need E2E tests for quick search and advanced search functionality.

**Why this priority**: Search enables artifact discovery - important for large repositories.

**Independent Test**: Use quick search to find an artifact, then use advanced property search to filter results.

**Acceptance Scenarios**:

1. **Given** the search box in top bar, **When** typing a query, **Then** instant search results appear as dropdown.
2. **Given** search results dropdown, **When** clicking a result, **Then** navigation to that artifact occurs.
3. **Given** advanced search page, **When** selecting checksum search and entering SHA256, **Then** matching artifacts display.
4. **Given** advanced search with GAVC, **When** entering Maven coordinates, **Then** matching Maven artifacts display.
5. **Given** no search results, **When** viewing search, **Then** empty state with search suggestions appears.

---

### Edge Cases

- What happens when a wizard step validation fails but the user clicks browser back?
- How does the system handle network timeout during wizard submission?
- What happens when session expires mid-wizard?
- How does E2E testing handle dynamic content like UUIDs or timestamps?
- What happens when parallel tests try to create resources with the same name?
- How should tests handle flaky network conditions?

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: E2E test suite MUST cover all multi-step wizard flows (RepoWizard, Migration, CI/CD Setup, Package Manager Setup, Onboarding)
- **FR-002**: E2E tests MUST validate form state persistence across wizard steps (data entered in step N must persist when navigating away and back)
- **FR-003**: E2E tests MUST verify wizard validation prevents proceeding with invalid/incomplete data
- **FR-004**: E2E tests MUST cover both happy path (successful completion) and error scenarios (validation failures, API errors)
- **FR-005**: E2E tests MUST verify that wizard cancellation does not create partial resources
- **FR-006**: E2E tests MUST be tagged for selective execution (@smoke for critical paths, @full for comprehensive coverage)
- **FR-007**: E2E tests MUST use realistic test data and verify actual backend state changes
- **FR-008**: E2E tests MUST handle test data cleanup to enable repeated test runs
- **FR-009**: E2E tests MUST verify copy-to-clipboard functionality with success feedback
- **FR-010**: E2E tests MUST verify real-time updates (migration progress, dashboard widgets)
- **FR-011**: E2E tests MUST cover authentication flows including MFA enrollment and verification
- **FR-012**: E2E tests MUST verify administrative workflows (user/group/permission management)
- **FR-013**: E2E tests MUST verify search functionality (quick search, advanced search types)
- **FR-014**: E2E tests MUST use page object pattern for maintainability
- **FR-015**: E2E tests MUST generate test reports with screenshots on failure

### Key Entities

- **Test Suite**: Collection of related E2E tests for a feature area (wizard, auth, admin, etc.)
- **Test Case**: Individual test with setup, actions, and assertions
- **Page Object**: Abstraction of UI page with selectors and interaction methods
- **Test Fixture**: Reusable test data and setup utilities
- **Test Tag**: Marker for categorizing tests (@smoke, @full, @wizard, @admin)

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: All multi-step wizard flows have E2E test coverage (minimum 5 test cases per wizard)
- **SC-002**: E2E test suite completes in under 15 minutes for @smoke tests, under 45 minutes for @full suite
- **SC-003**: E2E tests achieve 90% pass rate on clean test environment (no flaky tests)
- **SC-004**: All critical user journeys identified in 003-frontend-ui-parity spec have corresponding E2E tests
- **SC-005**: Test failures produce actionable reports with screenshots and step traces
- **SC-006**: E2E tests can run in CI pipeline without manual intervention
- **SC-007**: Test data cleanup enables unlimited sequential test runs without conflicts
- **SC-008**: Form state persistence bug (like RepoWizard issue) would be caught by E2E tests

## Assumptions

- Playwright is the E2E testing framework (already configured in the project)
- Backend APIs are stable and return consistent responses for test scenarios
- Test environment can be seeded with predictable test data
- Tests will run against a Docker Compose environment matching production
- Authentication can use test credentials without MFA for most tests
- Some tests may need to mock external services (SSO providers, Artifactory for migration)
- Tests will use unique identifiers (timestamps, random strings) to avoid conflicts
