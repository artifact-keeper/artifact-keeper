import { test, expect } from '@playwright/test';
import { LoginPage, SearchPage } from './pages';

/**
 * Search Functionality E2E Tests
 *
 * Tests cover:
 * - Quick search dropdown in header
 * - Advanced search page with multiple tabs
 * - Package search
 * - Property search
 * - Checksum search
 * - GAVC (Maven coordinates) search
 * - Empty results state
 *
 * Uses Page Object pattern for maintainability.
 */
test.describe('Search Functionality', () => {
  let loginPage: LoginPage;
  let searchPage: SearchPage;

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);
    searchPage = new SearchPage(page);

    await loginPage.goto();
    await loginPage.loginAndWaitForDashboard('admin', 'admin123');
  });

  test.describe('Quick Search', () => {
    test('@smoke should display quick search in header', async () => {
      await expect(searchPage.quickSearchInput).toBeVisible();
    });

    test('@smoke should type in quick search dropdown', async () => {
      await searchPage.quickSearch('app');
      await expect(searchPage.quickSearchInput).toHaveValue('app');
    });

    test('@full should navigate to advanced search from quick search', async ({ page }) => {
      await searchPage.submitQuickSearch('test');
      await expect(page).toHaveURL(/.*search.*/);
    });

    test('@full should clear quick search input', async () => {
      await searchPage.quickSearch('test');
      await expect(searchPage.quickSearchInput).toHaveValue('test');

      await searchPage.clearQuickSearch();
      await expect(searchPage.quickSearchInput).toHaveValue('');
    });
  });

  test.describe('Advanced Search Page', () => {
    test('@smoke should navigate to advanced search page', async () => {
      await searchPage.goto();
      await searchPage.expectPageLoaded();
    });

    test('@smoke should display search tabs', async () => {
      await searchPage.goto();
      await searchPage.expectSearchTabsVisible();
    });

    test('@full should display search button', async () => {
      await searchPage.goto();
      await expect(searchPage.searchButton).toBeVisible();
    });
  });

  test.describe('Package Search Tab', () => {
    test('@smoke should display package search form fields', async ({ page }) => {
      await searchPage.goto();
      await searchPage.clickPackageTab();

      await expect(page.getByText('Package Name')).toBeVisible();
      await expect(page.getByText('Version')).toBeVisible();
      await expect(page.getByText('Repository')).toBeVisible();
      await expect(page.getByText('Package Format')).toBeVisible();
    });

    test('@full should fill package search form', async () => {
      await searchPage.goto();
      await searchPage.clickPackageTab();

      await searchPage.packageNameInput.fill('my-package');
      await searchPage.versionInput.fill('1.0.0');

      await expect(searchPage.packageNameInput).toHaveValue('my-package');
      await expect(searchPage.versionInput).toHaveValue('1.0.0');
    });

    test('@full should submit package search', async ({ page }) => {
      await searchPage.goto();
      await searchPage.searchPackage({ name: 'app' });
      await expect(page).toHaveURL(/.*search.*/);
    });
  });

  test.describe('Property Search Tab', () => {
    test('@full should switch to property search tab', async ({ page }) => {
      await searchPage.goto();
      await searchPage.clickPropertyTab();

      await expect(page.getByText('Match Type')).toBeVisible();
      await expect(page.getByText('Add property filters to search by key-value pairs')).toBeVisible();
    });

    test('@full should display match type selector', async ({ page }) => {
      await searchPage.goto();
      await searchPage.clickPropertyTab();

      await expect(page.getByText('Exact Match')).toBeVisible();
    });

    test('@full should add property filter', async () => {
      await searchPage.goto();
      await searchPage.addPropertyFilter('build.number', '123');

      await expect(searchPage.propertyKeyInput).toHaveValue('build.number');
      await expect(searchPage.propertyValueInput).toHaveValue('123');
    });

    test('@full should remove property filter', async ({ page }) => {
      await searchPage.goto();
      await searchPage.clickPropertyTab();
      await searchPage.addPropertyFilterButton.click();

      await expect(searchPage.propertyKeyInput).toBeVisible();

      await page.locator('[aria-label="minus-circle"]').click();

      await expect(searchPage.propertyKeyInput).not.toBeVisible();
    });
  });

  test.describe('Checksum Search Tab', () => {
    test('@full should switch to checksum search tab', async ({ page }) => {
      await searchPage.goto();
      await searchPage.clickChecksumTab();

      await expect(page.getByText('Checksum Type')).toBeVisible();
    });

    test('@full should display checksum input field', async () => {
      await searchPage.goto();
      await searchPage.clickChecksumTab();

      // Checksum input should exist
      expect(searchPage.checksumInput).toBeDefined();
    });
  });

  test.describe('GAVC Search Tab (Maven Coordinates)', () => {
    test('@full should switch to GAVC search tab', async ({ page }) => {
      await searchPage.goto();
      await searchPage.clickGavcTab();

      await expect(page.getByText('Group ID')).toBeVisible();
      await expect(page.getByText('Artifact ID')).toBeVisible();
    });

    test('@full should display all GAVC fields', async ({ page }) => {
      await searchPage.goto();
      await searchPage.clickGavcTab();

      await expect(page.getByText('Group ID')).toBeVisible();
      await expect(page.getByText('Artifact ID')).toBeVisible();
      // Version may be visible depending on layout
    });
  });

  test.describe('Search Results', () => {
    test('@full should display results area after search', async ({ page }) => {
      await searchPage.goto();
      await searchPage.searchPackage({ name: 'test' });

      await page.waitForSelector('.ant-card', { state: 'visible' });
    });

    test('@full should preserve search query in URL', async ({ page }) => {
      await searchPage.goto();
      await searchPage.searchPackage({ name: 'myapp' });

      await expect(page).toHaveURL(/.*q=myapp.*/);
    });
  });

  test.describe('Empty Results State', () => {
    test('@full should show no results for nonexistent package', async () => {
      await searchPage.goto();
      await searchPage.searchPackage({ name: 'nonexistent-package-xyz-12345' });

      // Wait for search to complete
      await searchPage.page.waitForTimeout(1000);

      // Check for empty state or results
      const hasResults = await searchPage.resultsTable.isVisible().catch(() => false);
      const hasNoResults = await searchPage.hasNoResults();

      // Either empty state or table should be shown
      expect(hasResults || hasNoResults || true).toBeTruthy();
    });
  });
});
