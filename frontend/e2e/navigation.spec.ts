import { test, expect } from '@playwright/test';
import { LoginPage, NavigationPage } from './pages';

/**
 * Navigation E2E Tests
 *
 * Tests cover:
 * - Grouped sidebar structure (6 groups for admin)
 * - Correct items in each group
 * - Admin-only group visibility
 * - Coming Soon disabled items
 * - Navigation to all working pages
 * - Webhooks page functionality
 *
 * Uses Page Object pattern for maintainability.
 */
test.describe('Grouped Navigation', () => {
  let loginPage: LoginPage;
  let navPage: NavigationPage;

  test.describe('Admin User', () => {
    test.beforeEach(async ({ page }) => {
      loginPage = new LoginPage(page);
      navPage = new NavigationPage(page);
      await loginPage.goto();
      await loginPage.loginAndWaitForDashboard('admin', 'admin123');
    });

    test('@smoke should display all 6 nav groups for admin', async () => {
      await navPage.expectGroupVisible('Overview');
      await navPage.expectGroupVisible('Artifacts');
      await navPage.expectGroupVisible('Security');
      await navPage.expectGroupVisible('Integration');
      await navPage.expectGroupVisible('AI / ML');
      await navPage.expectGroupVisible('Administration');
    });

    test('@smoke should display logo and version', async () => {
      await navPage.expectLogoText('Artifact Keeper');
      await navPage.expectVersion('1.0.0');
    });

    test.describe('Overview Group', () => {
      test('@full should contain Dashboard', async () => {
        await navPage.expectItemEnabled('Dashboard');
      });

      test('@full should navigate to Dashboard', async () => {
        await navPage.navigateTo('Dashboard');
        await navPage.expectUrl('/');
        await navPage.expectItemSelected('Dashboard');
      });
    });

    test.describe('Artifacts Group', () => {
      test('@full should contain all artifact items', async () => {
        await navPage.expectItemEnabled('Repositories');
        await navPage.expectItemEnabled('Artifacts');
        await navPage.expectItemEnabled('Packages');
        await navPage.expectItemEnabled('Builds');
      });

      test('@full should navigate to Repositories', async () => {
        await navPage.navigateTo('Repositories');
        await navPage.expectUrl('/repositories');
        await navPage.expectItemSelected('Repositories');
      });

      test('@full should navigate to Artifacts', async () => {
        await navPage.navigateTo('Artifacts');
        await navPage.expectUrl('/artifacts');
      });

      test('@full should navigate to Packages', async () => {
        await navPage.navigateTo('Packages');
        await navPage.expectUrl('/packages');
      });

      test('@full should navigate to Builds', async () => {
        await navPage.navigateTo('Builds');
        await navPage.expectUrl('/builds');
      });
    });

    test.describe('Security Group', () => {
      test('@full should contain all security items', async () => {
        await navPage.expectItemEnabled('Dashboard');
        await navPage.expectItemEnabled('Scan Results');
        await navPage.expectItemEnabled('Policies');
        await navPage.expectItemEnabled('Permissions');
      });

      test('@full should navigate to Security Dashboard', async ({ page }) => {
        await navPage.navigateTo('Dashboard');
        // Navigate to security dashboard via direct URL since "Dashboard" is ambiguous
        await page.goto('/security');
        await expect(page.getByText('Security Dashboard')).toBeVisible();
      });

      test('@full should navigate to Scan Results', async ({ page }) => {
        await navPage.navigateTo('Scan Results');
        await navPage.expectUrl('/security/scans');
        await expect(page.getByText('Security Scans')).toBeVisible();
      });

      test('@full should navigate to Policies', async ({ page }) => {
        await navPage.navigateTo('Policies');
        await navPage.expectUrl('/security/policies');
        await expect(page.getByText('Security Policies')).toBeVisible();
      });

      test('@full should navigate to Permissions', async () => {
        await navPage.navigateTo('Permissions');
        await navPage.expectUrl('/permissions');
      });
    });

    test.describe('Integration Group', () => {
      test('@full should contain all integration items', async () => {
        await navPage.expectItemEnabled('Edge Nodes');
        await navPage.expectItemEnabled('Plugins');
        await navPage.expectItemEnabled('Webhooks');
        await navPage.expectItemEnabled('Migration');
        await navPage.expectItemEnabled('Set Me Up');
      });

      test('@full should navigate to Edge Nodes', async () => {
        await navPage.navigateTo('Edge Nodes');
        await navPage.expectUrl('/edge-nodes');
      });

      test('@full should navigate to Plugins', async () => {
        await navPage.navigateTo('Plugins');
        await navPage.expectUrl('/plugins');
      });

      test('@full should navigate to Webhooks', async ({ page }) => {
        await navPage.navigateTo('Webhooks');
        await navPage.expectUrl('/webhooks');
        await expect(page.getByRole('heading', { name: 'Webhooks' })).toBeVisible();
      });

      test('@full should navigate to Migration', async () => {
        await navPage.navigateTo('Migration');
        await navPage.expectUrl('/migration');
      });

      test('@full should navigate to Set Me Up', async () => {
        await navPage.navigateTo('Set Me Up');
        await navPage.expectUrl('/setup');
      });
    });

    test.describe('AI / ML Group', () => {
      test('@full should show Model Config as Coming Soon', async () => {
        await navPage.expectItemDisabled('Model Config');
      });

      test('@full should show Artifact Analysis as Coming Soon', async () => {
        await navPage.expectItemDisabled('Artifact Analysis');
      });
    });

    test.describe('Administration Group', () => {
      test('@full should contain all admin items', async () => {
        await navPage.expectItemEnabled('Users');
        await navPage.expectItemEnabled('Groups');
        await navPage.expectItemEnabled('Backups');
        await navPage.expectItemEnabled('Settings');
      });

      test('@full should navigate to Users', async () => {
        await navPage.navigateTo('Users');
        await navPage.expectUrl('/users');
      });

      test('@full should navigate to Groups', async () => {
        await navPage.navigateTo('Groups');
        await navPage.expectUrl('/groups');
      });

      test('@full should navigate to Backups', async () => {
        await navPage.navigateTo('Backups');
        await navPage.expectUrl('/backups');
      });

      test('@full should navigate to Settings', async () => {
        await navPage.navigateTo('Settings');
        await navPage.expectUrl('/settings');
      });
    });
  });

  test.describe('Webhooks Page', () => {
    test.beforeEach(async ({ page }) => {
      loginPage = new LoginPage(page);
      navPage = new NavigationPage(page);
      await loginPage.goto();
      await loginPage.loginAndWaitForDashboard('admin', 'admin123');
      await navPage.navigateTo('Webhooks');
    });

    test('@smoke should display webhooks page with stats', async ({ page }) => {
      await expect(page.getByRole('heading', { name: 'Webhooks' })).toBeVisible();
      await expect(page.getByText('Total Webhooks')).toBeVisible();
      await expect(page.getByText('Active')).toBeVisible();
      await expect(page.getByText('Disabled')).toBeVisible();
    });

    test('@full should have Create Webhook button', async ({ page }) => {
      await expect(page.getByRole('button', { name: /Create Webhook/i })).toBeVisible();
    });

    test('@full should open create webhook modal', async ({ page }) => {
      await page.getByRole('button', { name: /Create Webhook/i }).click();
      await expect(page.getByText('Create Webhook')).toBeVisible();
      await expect(page.getByLabel('Name')).toBeVisible();
      await expect(page.getByLabel('Payload URL')).toBeVisible();
      await expect(page.getByText('Events')).toBeVisible();
    });

    test('@full should close create webhook modal on cancel', async ({ page }) => {
      await page.getByRole('button', { name: /Create Webhook/i }).click();
      await expect(page.getByLabel('Name')).toBeVisible();
      await page.getByRole('button', { name: 'Cancel' }).click();
      await expect(page.getByLabel('Name')).not.toBeVisible();
    });

    test('@full should have Refresh button', async ({ page }) => {
      await expect(page.getByRole('button', { name: 'Refresh' })).toBeVisible();
    });
  });
});
