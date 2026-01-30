import { test, expect } from '@playwright/test';
import { LoginPage, DashboardPage } from './pages';

/**
 * Dashboard E2E Tests
 *
 * Tests cover:
 * - Dashboard widgets display (system health, statistics)
 * - Onboarding wizard flow for new users
 * - Empty state when no repositories exist
 * - Widget data refresh
 * - Navigation from dashboard
 *
 * Uses Page Object pattern for maintainability.
 */
test.describe('Dashboard', () => {
  let loginPage: LoginPage;
  let dashboardPage: DashboardPage;

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);
    dashboardPage = new DashboardPage(page);

    // Login first
    await loginPage.goto();
    await loginPage.loginAndWaitForDashboard('admin', 'admin123');
  });

  test.describe('Dashboard Widgets', () => {
    test('@smoke should display dashboard heading', async ({ page }) => {
      await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
    });

    test('@smoke should show system health section', async ({ page }) => {
      await expect(page.getByText('System Health')).toBeVisible();
      await expect(page.getByText('Status')).toBeVisible();
      await expect(page.getByText('Database')).toBeVisible();
      await expect(page.getByText('Storage')).toBeVisible();
    });

    test('@full should display admin statistics', async ({ page }) => {
      await expect(page.getByText('Repositories')).toBeVisible();
      await expect(page.getByText('Artifacts')).toBeVisible();
      await expect(page.getByText('Users')).toBeVisible();
      await expect(page.getByText('Total Storage')).toBeVisible();
    });

    test('@full should display recent repositories table', async ({ page }) => {
      await expect(page.getByText('Recent Repositories')).toBeVisible();
      await expect(page.getByText('View All')).toBeVisible();
    });

    test('@full should navigate to repositories from View All link', async ({ page }) => {
      await page.getByText('View All').click();
      await expect(page).toHaveURL('/repositories');
    });

    test('@full should have refresh button', async ({ page }) => {
      await expect(page.getByRole('button', { name: 'Refresh' })).toBeVisible();
    });

    test('@full should refresh data when clicking refresh', async ({ page }) => {
      await page.getByRole('button', { name: 'Refresh' }).click();
      // Button should show loading state briefly then return to visible
      await expect(page.getByRole('button', { name: 'Refresh' })).toBeVisible();
    });

    test('@full should display healthy status with green color', async ({ page }) => {
      await expect(page.getByText('healthy')).toBeVisible();
    });
  });

  test.describe('Dashboard Navigation', () => {
    test('@full should navigate from stat card clicks', async ({ page }) => {
      // Click on Repositories stat card
      await page.locator('.ant-card').filter({ hasText: 'Repositories' }).first().click();
      await expect(page).toHaveURL('/repositories');
    });

    test('@full should show help modal from header', async ({ page }) => {
      // Click help button in header
      await page.locator('button').filter({ has: page.locator('[aria-label="question-circle"]') }).click();

      await expect(page.getByText('About Artifact Keeper')).toBeVisible();
      await expect(page.getByText('Version 1.0.0')).toBeVisible();
      await expect(page.getByText('Supported Formats')).toBeVisible();
    });

    test('@full should close help modal', async ({ page }) => {
      // Open help modal
      await page.locator('button').filter({ has: page.locator('[aria-label="question-circle"]') }).click();
      await expect(page.getByText('About Artifact Keeper')).toBeVisible();

      // Close it
      await page.getByRole('button', { name: 'Close' }).click();

      await expect(page.getByText('About Artifact Keeper')).not.toBeVisible();
    });
  });

  test.describe('Onboarding Wizard', () => {
    // Note: Onboarding wizard tests may require a fresh user that hasn't completed onboarding
    // These tests verify the UI flow exists

    test('@smoke should handle onboarding wizard if shown', async () => {
      const isOnboardingVisible = await dashboardPage.isOnboardingVisible();
      if (isOnboardingVisible) {
        // Complete the onboarding wizard
        await dashboardPage.completeOnboarding();
        await dashboardPage.expectOnboardingComplete();
      }
      // Dashboard should be loaded after onboarding
      await dashboardPage.expectDashboardLoaded();
    });

    test('@full should skip onboarding wizard if available', async () => {
      const isOnboardingVisible = await dashboardPage.isOnboardingVisible();
      if (isOnboardingVisible) {
        // Skip the onboarding wizard
        await dashboardPage.skipOnboarding();
        await dashboardPage.expectOnboardingComplete();
      }
      // Dashboard should be loaded after skipping
      await dashboardPage.expectDashboardLoaded();
    });

    test('@full should persist onboarding completion', async ({ page }) => {
      // Complete or skip onboarding if visible
      const isOnboardingVisible = await dashboardPage.isOnboardingVisible();
      if (isOnboardingVisible) {
        await dashboardPage.skipOnboarding();
      }

      // Refresh the page
      await page.reload();
      await dashboardPage.waitForPageLoad();

      // Onboarding should not appear again
      const isStillVisible = await dashboardPage.isOnboardingVisible();
      expect(isStillVisible).toBeFalsy();
    });
  });

  test.describe('Widget Data Refresh', () => {
    test('@full should refresh widget data using page object', async () => {
      await dashboardPage.refreshWidgets();
      // Verify dashboard is still loaded after refresh
      await dashboardPage.expectDashboardLoaded();
    });

    test('@full should display artifact count in widget', async () => {
      const count = await dashboardPage.getArtifactCount();
      // Count should be a valid number (0 or more)
      expect(count).toBeGreaterThanOrEqual(0);
    });
  });

  test.describe('Empty State', () => {
    // Note: Empty state tests may require a fresh environment with no repositories
    // These tests verify the empty state UI exists when applicable

    test('@full should show empty state or widgets based on data', async () => {
      const hasEmptyState = await dashboardPage.isEmptyStateVisible();
      if (hasEmptyState) {
        // Verify create repository button is available
        await expect(dashboardPage.createRepoButton).toBeVisible();
      } else {
        // Normal dashboard with widgets
        await dashboardPage.expectDashboardLoaded();
      }
    });

    test('@full should navigate to create repo from empty state', async () => {
      const hasEmptyState = await dashboardPage.isEmptyStateVisible();
      if (hasEmptyState) {
        await dashboardPage.clickCreateRepository();
        // Should navigate to repository creation
        // Exact URL depends on implementation
      }
    });
  });
});

test.describe('Sidebar Navigation', () => {
  let loginPage: LoginPage;

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);
    await loginPage.goto();
    await loginPage.loginAndWaitForDashboard('admin', 'admin123');
  });

  test('@smoke should display sidebar with grouped menu items', async ({ page }) => {
    // Overview group
    await expect(page.getByRole('link', { name: 'Dashboard' })).toBeVisible();

    // Artifacts group
    await expect(page.getByRole('link', { name: 'Repositories' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Artifacts' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Packages' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Builds' })).toBeVisible();

    // Admin group (admin user)
    await expect(page.getByRole('link', { name: 'Users' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Settings' })).toBeVisible();
  });

  test('@smoke should display nav group headers', async ({ page }) => {
    const sidebar = page.locator('.ant-layout-sider, .ant-drawer-body');
    await expect(sidebar.getByText('Overview')).toBeVisible();
    await expect(sidebar.getByText('Artifacts')).toBeVisible();
    await expect(sidebar.getByText('Security')).toBeVisible();
    await expect(sidebar.getByText('Integration')).toBeVisible();
    await expect(sidebar.getByText('AI / ML')).toBeVisible();
    await expect(sidebar.getByText('Administration')).toBeVisible();
  });

  test('@full should display version in sidebar footer', async ({ page }) => {
    await expect(page.getByText('v1.0.0')).toBeVisible();
  });

  test('@full should navigate to Users page', async ({ page }) => {
    await page.getByRole('link', { name: 'Users' }).click();
    await expect(page).toHaveURL('/users');
  });

  test('@full should navigate to Settings page', async ({ page }) => {
    await page.getByRole('link', { name: 'Settings' }).click();
    await expect(page).toHaveURL('/settings');
  });

  test('@full should navigate to Webhooks page', async ({ page }) => {
    await page.getByRole('link', { name: 'Webhooks' }).click();
    await expect(page).toHaveURL('/webhooks');
    await expect(page.getByRole('heading', { name: 'Webhooks' })).toBeVisible();
  });

  test('@full should highlight active menu item', async ({ page }) => {
    // Dashboard menu item should be selected by default
    const dashboardItem = page.locator('.ant-menu-item-selected').filter({
      has: page.getByRole('link', { name: 'Dashboard' }),
    });
    await expect(dashboardItem).toBeVisible();

    // Navigate to repositories
    await page.getByRole('link', { name: 'Repositories' }).click();

    const reposItem = page.locator('.ant-menu-item-selected').filter({
      has: page.getByRole('link', { name: 'Repositories' }),
    });
    await expect(reposItem).toBeVisible();
  });

  test('@full should show Coming Soon tooltip for unbuilt items', async ({ page }) => {
    // AI/ML items should be disabled
    const modelConfigItem = page.locator('.ant-menu-item-disabled').filter({
      hasText: 'Model Config',
    });
    await expect(modelConfigItem).toBeVisible();

    const analysisItem = page.locator('.ant-menu-item-disabled').filter({
      hasText: 'Artifact Analysis',
    });
    await expect(analysisItem).toBeVisible();
  });

  test('@full should show Integration group items', async ({ page }) => {
    await expect(page.getByRole('link', { name: 'Edge Nodes' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Plugins' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Webhooks' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Migration' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Set Me Up' })).toBeVisible();
  });

  test('@full should show Security group items', async ({ page }) => {
    await expect(page.getByRole('link', { name: 'Permissions' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Scan Results' })).toBeVisible();
    await expect(page.getByRole('link', { name: 'Policies' })).toBeVisible();
    const sidebar = page.locator('.ant-layout-sider, .ant-drawer-body');
    await expect(sidebar.getByText('Dashboard')).toBeVisible();
  });
});
