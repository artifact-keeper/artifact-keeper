# Implementation Plan: UI E2E Test Coverage

**Branch**: `006-ui-e2e-coverage` | **Date**: 2026-01-18 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/006-ui-e2e-coverage/spec.md`

## Summary

Implement comprehensive E2E test coverage for all UI components added in the 003-frontend-ui-parity feature. Focus on multi-step wizard flows (RepoWizard, Migration, CI/CD Setup, Package Manager Setup, Onboarding) with emphasis on form state persistence, validation, and error handling. Tests will use Playwright with @smoke/@full tagging for selective CI execution.

## Technical Context

**Language/Version**: TypeScript 5.3
**Primary Dependencies**: Playwright 1.41+, React 19.x, Ant Design 6.x
**Storage**: N/A (E2E tests interact with running backend via HTTP)
**Testing**: Playwright for E2E, Vitest for unit tests
**Target Platform**: Modern browsers (Chrome, Firefox, Safari)
**Project Type**: Web application (frontend E2E tests)
**Performance Goals**: @smoke tests < 15 minutes, @full suite < 45 minutes
**Constraints**: Tests must be non-flaky (90%+ pass rate on clean environment)
**Scale/Scope**: ~50+ new E2E test cases across 9 test suites

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|-----------|--------|-------|
| I. API-First Design | N/A | Tests validate existing APIs, no new contracts needed |
| II. Security by Default | PASS | Tests will use test credentials, no secrets in code |
| III. Simplicity & YAGNI | PASS | Page object pattern is standard, not over-engineering |
| IV. Documentation Standards | PASS | Test files serve as executable documentation |
| V. Accessibility Standards | PASS | E2E tests can verify keyboard navigation (FR-024) |
| VI. Test Coverage | PASS | This feature IS about test coverage |
| VII. Observability | N/A | Tests validate observable behavior |

**Gate Result**: PASS - Proceeding with Phase 0

## Project Structure

### Documentation (this feature)

```text
specs/006-ui-e2e-coverage/
├── plan.md              # This file
├── research.md          # Phase 0 output - best practices
├── data-model.md        # Phase 1 output - test entities
├── quickstart.md        # Phase 1 output - how to run tests
├── contracts/           # Phase 1 output - N/A (no new APIs)
└── tasks.md             # Phase 2 output
```

### Source Code (repository root)

```text
frontend/
├── e2e/
│   ├── pages/                    # NEW: Page Object classes
│   │   ├── BasePage.ts
│   │   ├── LoginPage.ts
│   │   ├── DashboardPage.ts
│   │   ├── RepositoriesPage.ts
│   │   ├── RepoWizardPage.ts
│   │   ├── MigrationPage.ts
│   │   ├── MigrationWizardPage.ts
│   │   ├── SetupPage.ts
│   │   ├── ProfilePage.ts
│   │   ├── AdminUsersPage.ts
│   │   ├── AdminGroupsPage.ts
│   │   └── SearchPage.ts
│   ├── fixtures/                 # NEW: Test fixtures and utilities
│   │   ├── auth.fixture.ts
│   │   ├── test-data.ts
│   │   └── cleanup.ts
│   ├── admin.spec.ts             # EXISTING - enhance
│   ├── artifacts.spec.ts         # EXISTING - keep
│   ├── auth.spec.ts              # EXISTING - enhance with MFA tests
│   ├── dashboard.spec.ts         # EXISTING - enhance with onboarding
│   ├── repositories.spec.ts      # EXISTING - REWRITE for wizard flow
│   ├── repository-browser.spec.ts # EXISTING - keep
│   ├── search.spec.ts            # EXISTING - enhance
│   ├── migration.spec.ts         # NEW: Migration wizard E2E
│   ├── setup-cicd.spec.ts        # NEW: CI/CD platform setup E2E
│   ├── setup-package-manager.spec.ts # NEW: Package manager setup E2E
│   └── global-setup.ts           # EXISTING - enhance cleanup
├── playwright.config.ts          # EXISTING - already has @smoke/@full support
└── package.json                  # EXISTING - no changes needed
```

**Structure Decision**: Enhance existing E2E directory with Page Object pattern for maintainability. All new files follow established patterns.

## Complexity Tracking

No violations to justify - design follows established patterns and tools.
