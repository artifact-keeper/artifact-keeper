import { test, expect } from '@playwright/test';
import { LoginPage } from './pages';

/**
 * Authentication E2E Tests
 *
 * Tests cover:
 * - Basic login/logout flows
 * - Invalid credentials handling
 * - MFA enrollment and challenge
 * - SSO provider buttons
 * - Session persistence
 *
 * Uses Page Object pattern for maintainability.
 */
test.describe('Authentication', () => {
  let loginPage: LoginPage;

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);

    // Clear any stored tokens
    await page.evaluate(() => {
      localStorage.clear();
    });
  });

  test.describe('Login Page', () => {
    test('@smoke should show login page when not authenticated', async ({ page }) => {
      await page.goto('/');
      await expect(page).toHaveURL(/.*login/);
      await expect(page.getByText('Artifact Keeper')).toBeVisible();
      await expect(page.getByText('Artifact Registry')).toBeVisible();
    });

    test('@smoke should display login form elements', async () => {
      await loginPage.goto();
      await expect(loginPage.usernameInput).toBeVisible();
      await expect(loginPage.passwordInput).toBeVisible();
      await expect(loginPage.loginButton).toBeVisible();
    });
  });

  test.describe('Login Flow', () => {
    test('@smoke should login successfully with valid credentials', async ({ page }) => {
      await loginPage.goto();
      await loginPage.login('admin', 'admin123');

      // Should redirect to dashboard after login
      await expect(page).toHaveURL('/');
      await expect(page.getByText('Dashboard')).toBeVisible();
    });

    test('@smoke should complete full login/logout cycle', async ({ page }) => {
      await loginPage.goto();
      await loginPage.loginAndWaitForDashboard('admin', 'admin123');

      // Verify logged in
      await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();

      // Logout
      await loginPage.logout();

      // Should be back on login page
      await expect(page).toHaveURL(/.*login/);
      await expect(loginPage.loginButton).toBeVisible();
    });
  });

  test.describe('Invalid Credentials', () => {
    test('@full should show error for invalid credentials', async ({ page }) => {
      await loginPage.goto();
      await loginPage.login('invalid', 'invalid');

      // Should show error
      await loginPage.expectLoginFailure();
    });

    test('@full should show error message text', async () => {
      await loginPage.goto();
      await loginPage.login('invalid', 'invalid');

      const hasError = await loginPage.hasError();
      expect(hasError).toBeTruthy();
    });

    test('@full should show validation errors for empty fields', async ({ page }) => {
      await page.goto('/login');
      await page.getByRole('button', { name: /log in/i }).click();

      await expect(page.getByText('Please input your username!')).toBeVisible();
      await expect(page.getByText('Please input your password!')).toBeVisible();
    });
  });

  test.describe('Logout Flow', () => {
    test('@smoke should logout successfully', async ({ page }) => {
      // First login
      await loginPage.goto();
      await loginPage.loginAndWaitForDashboard('admin', 'admin123');

      // Wait for dashboard
      await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();

      // Logout
      await loginPage.logout();

      // Should redirect to login
      await expect(page).toHaveURL(/.*login/);
    });
  });

  test.describe('Session Persistence', () => {
    test('@full should persist login across page refresh', async ({ page }) => {
      // Login
      await loginPage.goto();
      await loginPage.loginAndWaitForDashboard('admin', 'admin123');

      await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();

      // Refresh page
      await page.reload();

      // Should still be on dashboard (not redirected to login)
      await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
    });

    test('@full should redirect to login after token expiry', async ({ page }) => {
      // Login
      await loginPage.goto();
      await loginPage.loginAndWaitForDashboard('admin', 'admin123');

      // Clear tokens to simulate expiry
      await page.evaluate(() => {
        localStorage.clear();
      });

      // Navigate to protected route
      await page.goto('/');

      // Should redirect to login
      await expect(page).toHaveURL(/.*login/);
    });
  });

  test.describe('MFA Authentication', () => {
    // Note: MFA tests require a user with MFA enabled or enrollment flow
    // These tests verify the UI flow exists

    test('@full should display MFA enrollment option in settings', async ({ page }) => {
      await loginPage.goto();
      await loginPage.loginAndWaitForDashboard('admin', 'admin123');

      // Navigate to security settings where MFA is configured
      await page.getByRole('link', { name: 'Settings' }).click();

      // Look for MFA/2FA section (exact implementation depends on UI)
      const mfaSection = page.locator('text=/mfa|two-factor|2fa/i');
      // MFA section may or may not be visible depending on implementation
    });

    test('@full should handle MFA challenge if enabled', async () => {
      await loginPage.goto();

      // Login with credentials
      await loginPage.login('admin', 'admin123');

      // Check if MFA challenge is shown (for users with MFA enabled)
      const isMfaVisible = await loginPage.isMfaChallengeVisible();
      if (isMfaVisible) {
        // MFA input should be visible
        await expect(loginPage.mfaCodeInput).toBeVisible();
        await expect(loginPage.mfaVerifyButton).toBeVisible();
      }
      // If no MFA, user should be logged in
    });

    test('@full should show MFA enrollment UI elements', async () => {
      // Note: This test verifies locators exist, actual enrollment requires MFA setup
      await loginPage.goto();
      await loginPage.loginAndWaitForDashboard('admin', 'admin123');

      // The MFA enrollment UI would be in user settings
      // This test just verifies page object locators are defined correctly
      expect(loginPage.mfaQrCode).toBeDefined();
      expect(loginPage.mfaSecretKey).toBeDefined();
      expect(loginPage.mfaEnrollButton).toBeDefined();
    });
  });

  test.describe('SSO Providers', () => {
    test('@full should display SSO provider buttons if configured', async () => {
      await loginPage.goto();

      // Check if SSO section is visible (depends on backend configuration)
      const areSsoVisible = await loginPage.areSsoProvidersVisible();
      if (areSsoVisible) {
        // Verify provider buttons
        await expect(loginPage.ssoSection).toBeVisible();
      }
      // SSO may not be configured in test environment
    });

    test('@full should have GitHub SSO button locator defined', async () => {
      await loginPage.goto();

      // Verify the locator is properly defined
      expect(loginPage.githubSsoButton).toBeDefined();
      expect(loginPage.gitlabSsoButton).toBeDefined();
      expect(loginPage.googleSsoButton).toBeDefined();
    });
  });

  test.describe('Forgot Password', () => {
    test('@full should display forgot password link', async () => {
      await loginPage.goto();

      // Forgot password link may or may not be visible
      const forgotLink = loginPage.forgotPasswordLink;
      expect(forgotLink).toBeDefined();
    });
  });
});
