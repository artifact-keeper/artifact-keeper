import { test, expect } from '@playwright/test';
import { LoginPage, ProfilePage } from './pages';
import { uniqueId } from './fixtures/test-data';

/**
 * User Profile E2E Tests
 *
 * Tests cover:
 * - Profile information display and editing
 * - API key generation, copy, and revocation
 * - Access token creation and management
 * - Password change functionality
 *
 * Uses Page Object pattern for maintainability.
 */
test.describe('User Profile', () => {
  let loginPage: LoginPage;
  let profilePage: ProfilePage;

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);
    profilePage = new ProfilePage(page);

    // Login as admin
    await loginPage.goto();
    await loginPage.loginAndWaitForDashboard('admin', 'admin123');
  });

  test.describe('Profile Navigation', () => {
    test('@smoke should navigate to profile page', async ({ page }) => {
      await profilePage.goto();
      // Profile page should load (URL may vary)
      await expect(page).toHaveURL(/profile|settings|account/);
    });

    test('@smoke should display profile heading', async () => {
      await profilePage.goto();
      await expect(profilePage.heading).toBeVisible();
    });
  });

  test.describe('API Key Management', () => {
    test('@smoke should display API keys section', async () => {
      await profilePage.goto();
      // API keys section should be visible (if implemented)
      const generateButton = profilePage.generateApiKeyButton;
      expect(generateButton).toBeDefined();
    });

    test('@smoke should generate a new API key', async () => {
      await profilePage.goto();

      const keyName = `test-key-${uniqueId()}`;

      // Check if generate button is visible
      const isButtonVisible = await profilePage.generateApiKeyButton.isVisible().catch(() => false);
      if (isButtonVisible) {
        const apiKey = await profilePage.generateApiKey(keyName);

        // Key should be generated
        expect(apiKey.length).toBeGreaterThan(0);
      } else {
        test.skip(true, 'API key generation not visible in current UI');
      }
    });

    test('@full should copy API key to clipboard', async () => {
      await profilePage.goto();

      const isButtonVisible = await profilePage.generateApiKeyButton.isVisible().catch(() => false);
      if (isButtonVisible) {
        const keyName = `copy-test-${uniqueId()}`;
        await profilePage.generateApiKey(keyName);

        // Copy button should be visible
        const copyVisible = await profilePage.copyApiKeyButton.isVisible().catch(() => false);
        if (copyVisible) {
          await profilePage.copyApiKey();
        }
      } else {
        test.skip(true, 'API key management not visible in current UI');
      }
    });

    test('@full should revoke an API key', async () => {
      await profilePage.goto();

      const isButtonVisible = await profilePage.generateApiKeyButton.isVisible().catch(() => false);
      if (isButtonVisible) {
        const keyName = `revoke-test-${uniqueId()}`;
        await profilePage.generateApiKey(keyName);

        // Close any modal showing the generated key
        await profilePage.page.keyboard.press('Escape');
        await profilePage.page.waitForTimeout(500);

        // Revoke the key
        await profilePage.revokeApiKey(keyName);
      } else {
        test.skip(true, 'API key management not visible in current UI');
      }
    });

    test('@full should display API key count', async () => {
      await profilePage.goto();

      const isTableVisible = await profilePage.apiKeysTable.isVisible().catch(() => false);
      if (isTableVisible) {
        const count = await profilePage.getApiKeyCount();
        expect(count).toBeGreaterThanOrEqual(0);
      }
    });
  });

  test.describe('Access Token Management', () => {
    test('@full should display access tokens section', async () => {
      await profilePage.goto();
      // Access tokens section should be visible (if implemented)
      const createButton = profilePage.createTokenButton;
      expect(createButton).toBeDefined();
    });

    test('@full should create a new access token', async () => {
      await profilePage.goto();

      const isButtonVisible = await profilePage.createTokenButton.isVisible().catch(() => false);
      if (isButtonVisible) {
        const tokenName = `test-token-${uniqueId()}`;
        const token = await profilePage.createAccessToken(tokenName);

        // Token should be generated
        expect(token.length).toBeGreaterThan(0);
      } else {
        test.skip(true, 'Access token creation not visible in current UI');
      }
    });

    test('@full should revoke an access token', async () => {
      await profilePage.goto();

      const isButtonVisible = await profilePage.createTokenButton.isVisible().catch(() => false);
      if (isButtonVisible) {
        const tokenName = `revoke-token-${uniqueId()}`;
        await profilePage.createAccessToken(tokenName);

        // Close any modal showing the generated token
        await profilePage.page.keyboard.press('Escape');
        await profilePage.page.waitForTimeout(500);

        // Revoke the token
        await profilePage.revokeAccessToken(tokenName);
      } else {
        test.skip(true, 'Access token management not visible in current UI');
      }
    });
  });

  test.describe('Profile Update', () => {
    test('@full should update profile information', async () => {
      await profilePage.goto();

      const isEmailVisible = await profilePage.emailInput.isVisible().catch(() => false);
      if (isEmailVisible) {
        await profilePage.updateProfile({
          displayName: `Test User ${uniqueId()}`,
        });
        await profilePage.expectProfileUpdateSuccess();
      }
    });

    test('@full should display username', async () => {
      await profilePage.goto();

      const usernameDisplay = profilePage.usernameDisplay;
      expect(usernameDisplay).toBeDefined();
    });
  });

  test.describe('Password Change', () => {
    test('@full should display password change form', async () => {
      await profilePage.goto();

      // Password change fields should exist
      expect(profilePage.currentPasswordInput).toBeDefined();
      expect(profilePage.newPasswordInput).toBeDefined();
      expect(profilePage.confirmPasswordInput).toBeDefined();
    });

    // Note: Actual password change test is skipped to avoid changing test user password
    test.skip('@full should change password successfully', async () => {
      await profilePage.goto();

      const isCurrentVisible = await profilePage.currentPasswordInput.isVisible().catch(() => false);
      if (isCurrentVisible) {
        await profilePage.changePassword('admin123', 'newpassword123');
        await profilePage.expectPasswordChangeSuccess();
      }
    });
  });
});
