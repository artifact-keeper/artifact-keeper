# Research: UI E2E Test Coverage

**Feature**: 006-ui-e2e-coverage
**Date**: 2026-01-18

## Research Topics

### 1. Page Object Pattern for Playwright

**Decision**: Use Page Object Model (POM) with composition over inheritance

**Rationale**:
- Page Objects encapsulate page-specific selectors and actions
- Reduces test maintenance when UI changes (update one place)
- Improves test readability by abstracting low-level interactions
- Playwright's official documentation recommends this pattern

**Alternatives Considered**:
- Raw Playwright API everywhere: Rejected - leads to selector duplication and brittle tests
- Component-level objects: Rejected - too granular for E2E tests, adds complexity
- Screenplay pattern: Rejected - over-engineering for our test scope

**Implementation Pattern**:
```typescript
// pages/BasePage.ts
export class BasePage {
  constructor(protected page: Page) {}

  async waitForPageLoad() {
    await this.page.waitForLoadState('networkidle');
  }
}

// pages/RepoWizardPage.ts
export class RepoWizardPage extends BasePage {
  // Locators
  readonly nextButton = this.page.getByRole('button', { name: 'Next' });
  readonly createButton = this.page.getByRole('button', { name: 'Create Repository' });

  // Step 1: Repository Type
  async selectRepoType(type: 'local' | 'remote' | 'virtual') {
    await this.page.getByTestId(`repo-type-${type}`).click();
  }

  // Step 2: Package Format
  async selectPackageFormat(format: string) {
    await this.page.getByTestId(`package-format-${format}`).click();
  }

  // ... etc
}
```

### 2. Multi-Step Wizard Testing Strategy

**Decision**: Test each step independently AND test complete flows

**Rationale**:
- Independent step tests catch specific regressions faster
- Complete flow tests catch integration issues (like the form state bug)
- Combination provides comprehensive coverage

**Key Test Scenarios for Wizards**:
1. **Happy path**: Complete all steps successfully
2. **Form state persistence**: Fill step N, go to step N+1, go back to step N, verify data retained
3. **Validation blocking**: Try to proceed with invalid/empty required fields
4. **Cancel behavior**: Cancel at any step, verify no side effects
5. **Back navigation**: Verify previous step data is preserved
6. **Conditional steps**: Verify step visibility based on earlier selections

**Form State Bug Pattern** (what we found in RepoWizard):
```typescript
// BAD: Only render current step
{steps[currentStep]?.component}

// GOOD: Render all steps, hide inactive ones
{steps.map((step, index) => (
  <div style={{ display: index === currentStep ? 'block' : 'none' }}>
    {step.component}
  </div>
))}
```

**Test Pattern for Form State**:
```typescript
test('preserves form data when navigating between steps', async ({ page }) => {
  const wizard = new RepoWizardPage(page);

  // Step 1
  await wizard.selectRepoType('local');
  await wizard.clickNext();

  // Step 2
  await wizard.selectPackageFormat('npm');
  await wizard.clickNext();

  // Step 3: Fill data
  await wizard.fillBasicConfig({
    key: 'test-repo',
    name: 'Test Repository',
    description: 'Test description'
  });
  await wizard.clickNext();

  // Step 4: Go back
  await wizard.clickPrevious();

  // Verify Step 3 data preserved
  await expect(wizard.keyInput).toHaveValue('test-repo');
  await expect(wizard.nameInput).toHaveValue('Test Repository');
});
```

### 3. Test Tagging Strategy (@smoke vs @full)

**Decision**: Use test.describe naming convention with grep filtering

**Rationale**:
- Playwright supports grep-based test filtering out of the box
- Existing config already has TEST_TAG support
- @smoke tests run on every PR, @full runs on release

**Tag Guidelines**:
| Tag | Scope | When to Use |
|-----|-------|-------------|
| @smoke | Critical happy paths | PR gate, fast feedback |
| @full | All scenarios including edge cases | Release gate, nightly |
| No tag | Default behavior | Runs in both modes |

**Example**:
```typescript
test.describe('@smoke Repository Wizard', () => {
  test('creates local repository successfully', async ({ page }) => {
    // Critical path - must pass on every PR
  });
});

test.describe('@full Repository Wizard - Edge Cases', () => {
  test('handles validation errors gracefully', async ({ page }) => {
    // Important but not critical - runs on release
  });

  test('preserves form state on back navigation', async ({ page }) => {
    // The bug we found - critical now, was edge case before
  });
});
```

### 4. Test Data Management

**Decision**: Use unique identifiers + cleanup hooks

**Rationale**:
- Tests must be repeatable without manual cleanup
- Parallel test execution requires unique resource names
- globalSetup/globalTeardown for heavy cleanup

**Pattern**:
```typescript
// fixtures/test-data.ts
export function uniqueId(prefix: string): string {
  return `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
}

export function testRepo() {
  return {
    key: uniqueId('e2e-repo'),
    name: `E2E Test Repository ${Date.now()}`,
  };
}

// In test
test('creates repository', async ({ page }) => {
  const repo = testRepo();
  // ... create repo

  // Cleanup in afterEach or use test fixtures
});
```

### 5. Ant Design Component Testing

**Decision**: Use Ant Design's data-testid and ARIA roles for selectors

**Rationale**:
- Ant Design components have stable role attributes
- CSS class selectors are brittle (change with library updates)
- data-testid should be added to custom components

**Common Selectors**:
```typescript
// Modal
await page.getByRole('dialog');
await page.getByRole('dialog').getByRole('button', { name: 'OK' });

// Form
await page.getByRole('textbox', { name: 'Username' });
await page.getByRole('button', { name: 'Submit' });

// Steps
await page.locator('.ant-steps-item-active');

// Select
await page.getByRole('combobox');
await page.getByTitle('Option Name');

// Table
await page.getByRole('table');
await page.getByRole('row').filter({ hasText: 'expected text' });
```

### 6. Real-time Progress Testing (SSE/WebSocket)

**Decision**: Use page.waitForResponse with polling for SSE endpoints

**Rationale**:
- Migration progress uses Server-Sent Events (SSE)
- Playwright doesn't have native SSE support
- Poll for DOM updates or intercept network

**Pattern**:
```typescript
test('shows migration progress updates', async ({ page }) => {
  // Start migration
  await page.getByRole('button', { name: 'Start Migration' }).click();

  // Wait for progress to update
  await expect(page.getByText(/\d+%/)).toBeVisible();

  // Wait for completion (with reasonable timeout)
  await expect(page.getByText('Migration Complete')).toBeVisible({
    timeout: 60000
  });
});
```

### 7. Copy-to-Clipboard Testing

**Decision**: Grant clipboard permissions and verify navigator.clipboard

**Rationale**:
- Setup wizards have copy buttons for configuration snippets
- Clipboard API requires permissions in browser context

**Pattern**:
```typescript
// In test
test('copies configuration to clipboard', async ({ page, context }) => {
  // Grant clipboard permissions
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);

  // Click copy button
  await page.getByRole('button', { name: 'Copy' }).click();

  // Verify clipboard content
  const clipboardText = await page.evaluate(() => navigator.clipboard.readText());
  expect(clipboardText).toContain('npm config set registry');

  // Verify success toast
  await expect(page.getByText('Copied to clipboard')).toBeVisible();
});
```

## Summary of Decisions

| Topic | Decision | Key Benefit |
|-------|----------|-------------|
| Page Objects | Composition-based POM | Maintainability |
| Wizard Testing | Independent + flow tests | Comprehensive coverage |
| Test Tags | @smoke/@full with grep | Tiered CI execution |
| Test Data | Unique IDs + cleanup | Repeatable tests |
| Selectors | ARIA roles + data-testid | Stable, accessible |
| SSE Testing | DOM polling | Pragmatic approach |
| Clipboard | Permission grants | Full E2E verification |
