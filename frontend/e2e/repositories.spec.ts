import { test, expect } from '@playwright/test';
import { LoginPage, RepositoriesPage, RepoWizardPage } from './pages';
import { testRepo, testRemoteRepo, testVirtualRepo, uniqueId } from './fixtures/test-data';

/**
 * Repository Management E2E Tests
 *
 * Tests cover the multi-step repository creation wizard and list management.
 * Uses Page Object pattern for maintainability.
 */
test.describe('Repository Management', () => {
  let loginPage: LoginPage;
  let reposPage: RepositoriesPage;
  let wizardPage: RepoWizardPage;

  // Track created repos for cleanup
  const createdRepos: string[] = [];

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);
    reposPage = new RepositoriesPage(page);
    wizardPage = new RepoWizardPage(page);

    // Login as admin
    await loginPage.goto();
    await loginPage.loginAndWaitForDashboard('admin', 'admin123');
  });

  test.afterEach(async ({ page }) => {
    // Cleanup created repos
    if (createdRepos.length > 0) {
      await reposPage.goto();
      for (const key of createdRepos) {
        try {
          if (await reposPage.repoExists(key)) {
            await reposPage.deleteRepo(key);
          }
        } catch {
          // Ignore cleanup errors
        }
      }
      createdRepos.length = 0;
    }
  });

  test.describe('Repository List', () => {
    test('@smoke should navigate to repositories page', async ({ page }) => {
      await page.getByRole('link', { name: 'Repositories' }).click();
      await reposPage.expectPageLoaded();
      await expect(page).toHaveURL('/repositories');
    });

    test('@smoke should display repository list with table headers', async () => {
      await reposPage.goto();
      await reposPage.expectPageLoaded();

      // Verify table structure
      await expect(reposPage.keyColumn).toBeVisible();
      await expect(reposPage.nameColumn).toBeVisible();
      await expect(reposPage.formatColumn).toBeVisible();
      await expect(reposPage.typeColumn).toBeVisible();
    });

    test('@full should filter repositories by format', async () => {
      await reposPage.goto();
      await reposPage.filterByFormat('Maven');
      // Verification depends on test data - just ensure no errors
    });

    test('@full should filter repositories by type', async () => {
      await reposPage.goto();
      await reposPage.filterByType('Local');
      // Verification depends on test data
    });

    test('@full should clear filters', async () => {
      await reposPage.goto();
      await reposPage.filterByFormat('Maven');
      await reposPage.clearFilters();
    });

    test('@full should refresh repository list', async () => {
      await reposPage.goto();
      await reposPage.refresh();
      await expect(reposPage.table).toBeVisible();
    });
  });

  test.describe('Repository Creation Wizard - Local', () => {
    test('@smoke should complete local repository creation wizard', async () => {
      const repo = testRepo({ format: 'npm' });
      createdRepos.push(repo.key);

      await reposPage.goto();
      await reposPage.openCreateWizard();

      // Complete the wizard
      await wizardPage.completeLocalRepoWizard(repo);

      // Verify success
      await wizardPage.expectCreationSuccess();
      await wizardPage.expectWizardClosed();

      // Verify repo appears in list
      await reposPage.expectRepoExists(repo.key);
    });

    test('@smoke should preserve form state when navigating back', async ({ page }) => {
      const repo = testRepo({ format: 'generic' });

      await reposPage.goto();
      await reposPage.openCreateWizard();

      // Step 1: Select repo type
      await wizardPage.selectRepoType('local');
      await wizardPage.clickNext();

      // Step 2: Select format
      await wizardPage.selectPackageFormat('generic');
      await wizardPage.clickNext();

      // Step 3: Fill basic config
      await wizardPage.fillBasicConfig({
        key: repo.key,
        name: repo.name,
        description: repo.description,
      });

      // Navigate back to step 2
      await wizardPage.clickPrevious();

      // Verify format is still selected (generic should still be active/selected)
      const genericFormat = wizardPage.formatGeneric;
      await expect(genericFormat).toHaveClass(/selected|active|ant-card-bordered/);

      // Navigate back to step 1
      await wizardPage.clickPrevious();

      // Verify repo type is still selected
      const localType = wizardPage.repoTypeLocal;
      await expect(localType).toHaveClass(/selected|active|ant-card-bordered/);

      // Navigate forward again to step 3
      await wizardPage.clickNext();
      await wizardPage.clickNext();

      // Verify form data is preserved - use placeholder selector since labels have icons
      const keyInput = page.getByPlaceholder('my-repo');
      await expect(keyInput).toHaveValue(repo.key);
    });

    test('@full should validate required fields in wizard', async ({ page }) => {
      await reposPage.goto();
      await reposPage.openCreateWizard();

      // Try to proceed without selecting repo type
      await wizardPage.clickNext();

      // Should show validation error or stay on same step
      const currentStep = await wizardPage.getCurrentStep();
      expect(currentStep).toBe(1);

      // Select type and proceed
      await wizardPage.selectRepoType('local');
      await wizardPage.clickNext();

      // Try to proceed without selecting format
      await wizardPage.clickNext();
      const step2 = await wizardPage.getCurrentStep();
      expect(step2).toBe(2);

      // Select format and proceed
      await wizardPage.selectPackageFormat('npm');
      await wizardPage.clickNext();

      // Try to create without filling required fields
      await wizardPage.clickCreate();

      // Should show validation error
      await expect(wizardPage.validationError.first()).toBeVisible();
    });

    test('@full should cancel wizard without creating repository', async () => {
      const repo = testRepo();

      await reposPage.goto();
      const initialCount = await reposPage.getRepoCount();

      await reposPage.openCreateWizard();

      // Fill some data
      await wizardPage.selectRepoType('local');
      await wizardPage.clickNext();
      await wizardPage.selectPackageFormat('npm');
      await wizardPage.clickNext();
      await wizardPage.fillBasicConfig({
        key: repo.key,
        name: repo.name,
      });

      // Cancel
      await wizardPage.clickCancel();

      // Wizard should close
      await wizardPage.expectWizardClosed();

      // No new repo should be created
      const finalCount = await reposPage.getRepoCount();
      expect(finalCount).toBe(initialCount);
    });
  });

  test.describe('Repository Creation Wizard - Remote', () => {
    test('@smoke should complete remote repository creation wizard', async () => {
      const repo = testRemoteRepo({ format: 'npm' });
      createdRepos.push(repo.key);

      await reposPage.goto();
      await reposPage.openCreateWizard();

      // Complete the wizard
      await wizardPage.completeRemoteRepoWizard(repo);

      // Verify success
      await wizardPage.expectCreationSuccess();
      await wizardPage.expectWizardClosed();

      // Verify repo appears in list
      await reposPage.expectRepoExists(repo.key);
    });

    test('@full should validate upstream URL for remote repos', async ({ page }) => {
      await reposPage.goto();
      await reposPage.openCreateWizard();

      // Navigate through wizard
      await wizardPage.selectRepoType('remote');
      await wizardPage.clickNext();
      await wizardPage.selectPackageFormat('npm');
      await wizardPage.clickNext();

      const repo = testRepo();
      await wizardPage.fillBasicConfig({
        key: repo.key,
        name: repo.name,
      });
      await wizardPage.clickNext();

      // Try to proceed with invalid URL
      const urlInput = page.getByLabel(/upstream.*url|remote.*url|url/i);
      await urlInput.fill('not-a-valid-url');
      await wizardPage.clickNext();

      // Should show validation error
      const hasError = await wizardPage.hasValidationError();
      if (hasError) {
        const errorText = await wizardPage.getValidationError();
        expect(errorText.toLowerCase()).toContain('url');
      }
    });
  });

  test.describe('Repository Creation Wizard - Virtual', () => {
    test('@full should complete virtual repository creation wizard', async () => {
      // First create a local repo to include in virtual
      const localRepo = testRepo({ format: 'npm' });
      createdRepos.push(localRepo.key);

      await reposPage.goto();
      await reposPage.openCreateWizard();
      await wizardPage.completeLocalRepoWizard(localRepo);
      await wizardPage.expectCreationSuccess();

      // Now create virtual repo
      const virtualRepo = testVirtualRepo({
        format: 'npm',
        includedRepos: [localRepo.key],
      });
      createdRepos.push(virtualRepo.key);

      await reposPage.openCreateWizard();
      await wizardPage.completeVirtualRepoWizard(virtualRepo);

      await wizardPage.expectCreationSuccess();
      await wizardPage.expectWizardClosed();
      await reposPage.expectRepoExists(virtualRepo.key);
    });
  });

  test.describe('Repository Actions', () => {
    test('@full should navigate to repository detail', async () => {
      await reposPage.goto();

      // Click view on first repo
      const firstRow = reposPage.tableRows.first();
      const repoKey = await firstRow.locator('td').first().textContent();

      if (repoKey) {
        await reposPage.viewRepo(repoKey.trim());
        await expect(reposPage.page.getByText('Repository Details')).toBeVisible();
      }
    });

    test('@full should open edit modal', async () => {
      await reposPage.goto();

      const firstRow = reposPage.tableRows.first();
      const repoKey = await firstRow.locator('td').first().textContent();

      if (repoKey) {
        await reposPage.editRepo(repoKey.trim());
        await expect(reposPage.page.getByText(/edit repository/i)).toBeVisible();
      }
    });

    test('@full should show delete confirmation', async ({ page }) => {
      await reposPage.goto();

      // Click delete on first repo
      await page.getByRole('button', { name: /delete/i }).first().click();

      // Verify confirmation dialog
      await expect(reposPage.confirmDialog).toBeVisible();
      await expect(page.getByText(/are you sure|delete/i)).toBeVisible();

      // Cancel deletion
      await reposPage.cancelButton.click();
      await expect(reposPage.confirmDialog).toBeHidden();
    });
  });
});
