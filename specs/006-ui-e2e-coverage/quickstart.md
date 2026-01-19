# Quickstart: UI E2E Test Coverage

**Feature**: 006-ui-e2e-coverage
**Date**: 2026-01-18

## Prerequisites

- Node.js 18+ installed
- Docker/Podman for running the full stack
- Playwright browsers installed

## Installation

```bash
# Navigate to frontend directory
cd frontend

# Install dependencies (if not already done)
npm install

# Install Playwright browsers
npx playwright install
```

## Running E2E Tests

### Option 1: Against Running Dev Environment

Start the full stack first:

```bash
# From project root
podman-compose up -d

# Wait for services to be ready
# Backend: http://localhost:8080/health
# Frontend: http://localhost:5173
```

Run tests:

```bash
cd frontend

# Run all E2E tests
npm run test:e2e

# Run with UI (interactive mode)
npm run test:e2e:ui

# Run headed (see browser)
npm run test:e2e:headed
```

### Option 2: With Auto-Started Dev Server

```bash
cd frontend

# Playwright will start Vite dev server automatically
# Note: Backend must still be running separately
npm run test:e2e
```

## Test Tags

### Running Smoke Tests Only

Smoke tests are critical path tests that run on every PR:

```bash
cd frontend

# Run only @smoke tagged tests
TEST_TAG=@smoke npm run test:e2e
```

### Running Full Test Suite

Full suite includes all tests including edge cases:

```bash
cd frontend

# Run full suite (default)
npm run test:e2e

# Or explicitly
TEST_TAG=@full npm run test:e2e
```

## Running Specific Test Files

```bash
cd frontend

# Run repository wizard tests
npx playwright test repositories.spec.ts

# Run migration tests
npx playwright test migration.spec.ts

# Run setup wizard tests
npx playwright test setup-cicd.spec.ts setup-package-manager.spec.ts

# Run with filter pattern
npx playwright test -g "creates local repository"
```

## Browser Selection

```bash
cd frontend

# Run in specific browser
npx playwright test --project=chromium
npx playwright test --project=firefox
npx playwright test --project=webkit

# Run in all browsers (default in CI)
npx playwright test
```

## Debugging Tests

### Interactive UI Mode

```bash
cd frontend
npm run test:e2e:ui
```

This opens Playwright's interactive test runner where you can:
- See test execution in real-time
- Step through tests
- Inspect selectors
- View network requests

### Debug Mode with Inspector

```bash
cd frontend
PWDEBUG=1 npx playwright test -g "test name"
```

### View Test Reports

```bash
cd frontend

# Run tests (generates report)
npm run test:e2e

# Open HTML report
npx playwright show-report
```

## Test Data

### Test Credentials

Default test credentials (configured in global-setup.ts):

| Role | Username | Password |
|------|----------|----------|
| Admin | admin | admin123 |
| User | testuser | testpass |

### Test Data Cleanup

Tests create resources with unique identifiers. Cleanup happens:
- After each test (via afterEach hooks)
- In globalTeardown (for orphaned resources)

To manually clean test data:

```bash
# Via API (requires auth)
curl -X DELETE http://localhost:8080/api/v1/repositories/e2e-* \
  -H "Authorization: Bearer <token>"
```

## CI Integration

### GitHub Actions Example

```yaml
e2e-tests:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4

    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '20'

    - name: Install dependencies
      run: |
        cd frontend
        npm ci
        npx playwright install --with-deps

    - name: Start services
      run: docker-compose up -d

    - name: Wait for services
      run: |
        ./scripts/wait-for-it.sh localhost:8080 -t 60
        ./scripts/wait-for-it.sh localhost:5173 -t 60

    - name: Run smoke tests
      run: |
        cd frontend
        TEST_TAG=@smoke BASE_URL=http://localhost:5173 npm run test:e2e

    - name: Upload test results
      uses: actions/upload-artifact@v4
      if: always()
      with:
        name: playwright-report
        path: frontend/playwright-report/
```

## Common Issues

### Tests Failing with "Navigation Timeout"

Ensure the frontend is fully loaded:

```bash
# Check frontend is responding
curl http://localhost:5173

# Check backend is responding
curl http://localhost:8080/health
```

### Tests Failing with "Element Not Found"

1. Check if selectors match current UI
2. Run in headed mode to see what's happening:
   ```bash
   npm run test:e2e:headed
   ```
3. Use Playwright Inspector to find correct selectors:
   ```bash
   PWDEBUG=1 npx playwright test -g "failing test"
   ```

### Clipboard Tests Failing

Ensure test grants permissions:

```typescript
await context.grantPermissions(['clipboard-read', 'clipboard-write']);
```

### Parallel Test Conflicts

If tests conflict when run in parallel:
1. Ensure unique test data using `uniqueId()` factory
2. Add `test.describe.serial()` for tests that must run sequentially

## Writing New Tests

### Template for Wizard Tests

```typescript
import { test, expect } from '@playwright/test';
import { RepoWizardPage } from './pages/RepoWizardPage';
import { testRepo } from './fixtures/test-data';

test.describe('@smoke Repository Wizard', () => {
  test.beforeEach(async ({ page }) => {
    // Login and navigate
    await page.goto('/login');
    await page.getByPlaceholder('Username').fill('admin');
    await page.getByPlaceholder('Password').fill('admin123');
    await page.getByRole('button', { name: /log in/i }).click();
    await page.goto('/repositories');
  });

  test('creates local repository successfully', async ({ page }) => {
    const repo = testRepo();
    const wizard = new RepoWizardPage(page);

    // Open wizard
    await page.getByRole('button', { name: 'Create Repository' }).click();

    // Complete wizard
    await wizard.selectRepoType('local');
    await wizard.clickNext();
    await wizard.selectPackageFormat('npm');
    await wizard.clickNext();
    await wizard.fillBasicConfig(repo);
    await wizard.clickNext();
    await wizard.clickCreate();

    // Verify success
    await expect(page.getByText(/created successfully/i)).toBeVisible();
  });
});
```

### Template for Form State Tests

```typescript
test('@full preserves form data on navigation', async ({ page }) => {
  const wizard = new RepoWizardPage(page);
  const repo = testRepo();

  await wizard.open();
  await wizard.selectRepoType('local');
  await wizard.clickNext();
  await wizard.selectPackageFormat('npm');
  await wizard.clickNext();

  // Fill data
  await wizard.fillBasicConfig(repo);

  // Navigate forward and back
  await wizard.clickNext();
  await wizard.clickPrevious();

  // Verify data preserved
  await expect(wizard.keyInput).toHaveValue(repo.key);
  await expect(wizard.nameInput).toHaveValue(repo.name);
});
```
