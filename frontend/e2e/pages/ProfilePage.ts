import { type Page, type Locator, expect } from '@playwright/test';
import { BasePage } from './BasePage';

/**
 * Page Object for User Profile page
 * Path: /profile or /settings/profile
 *
 * Features:
 * - User profile information
 * - API key generation and management
 * - Access token creation
 * - Password change
 */
export class ProfilePage extends BasePage {
  // Page heading
  readonly heading: Locator;

  // Profile info
  readonly usernameDisplay: Locator;
  readonly emailInput: Locator;
  readonly displayNameInput: Locator;
  readonly saveProfileButton: Locator;

  // Password change
  readonly currentPasswordInput: Locator;
  readonly newPasswordInput: Locator;
  readonly confirmPasswordInput: Locator;
  readonly changePasswordButton: Locator;

  // API Keys section
  readonly apiKeysSection: Locator;
  readonly generateApiKeyButton: Locator;
  readonly apiKeyNameInput: Locator;
  readonly apiKeyExpirySelect: Locator;
  readonly apiKeysTable: Locator;
  readonly copyApiKeyButton: Locator;
  readonly revokeApiKeyButton: Locator;
  readonly generatedApiKeyDisplay: Locator;

  // Access Tokens section
  readonly accessTokensSection: Locator;
  readonly createTokenButton: Locator;
  readonly tokenNameInput: Locator;
  readonly tokenScopesSelect: Locator;
  readonly tokensTable: Locator;
  readonly revokeTokenButton: Locator;
  readonly generatedTokenDisplay: Locator;

  // Modals
  readonly confirmRevokeModal: Locator;
  readonly confirmRevokeButton: Locator;
  readonly cancelRevokeButton: Locator;

  constructor(page: Page) {
    super(page);

    // Page heading
    this.heading = page.getByRole('heading', { name: /profile|account|settings/i });

    // Profile info
    this.usernameDisplay = page.locator('[data-testid="username"], .username-display');
    this.emailInput = page.getByPlaceholder(/email/i);
    this.displayNameInput = page.getByPlaceholder(/display.*name|full.*name/i);
    this.saveProfileButton = page.getByRole('button', { name: /save|update.*profile/i });

    // Password change
    this.currentPasswordInput = page.getByPlaceholder(/current.*password/i);
    this.newPasswordInput = page.getByPlaceholder(/new.*password/i).first();
    this.confirmPasswordInput = page.getByPlaceholder(/confirm.*password|repeat.*password/i);
    this.changePasswordButton = page.getByRole('button', { name: /change.*password|update.*password/i });

    // API Keys
    this.apiKeysSection = page.locator('[data-testid="api-keys-section"], .api-keys-section').first();
    this.generateApiKeyButton = page.getByRole('button', { name: /generate.*key|create.*key|new.*key/i });
    this.apiKeyNameInput = page.getByPlaceholder(/key.*name|name.*key/i);
    this.apiKeyExpirySelect = page.locator('select').filter({ hasText: /expire|days|never/i });
    this.apiKeysTable = page.locator('.ant-table').filter({ hasText: /api.*key|key.*name/i });
    this.copyApiKeyButton = page.getByRole('button', { name: /copy/i });
    this.revokeApiKeyButton = page.getByRole('button', { name: /revoke|delete/i }).first();
    this.generatedApiKeyDisplay = page.locator('[data-testid="generated-key"], .generated-key, code').first();

    // Access Tokens
    this.accessTokensSection = page.locator('[data-testid="access-tokens-section"], .access-tokens-section');
    this.createTokenButton = page.getByRole('button', { name: /create.*token|generate.*token|new.*token/i });
    this.tokenNameInput = page.getByPlaceholder(/token.*name|name.*token/i);
    this.tokenScopesSelect = page.locator('.ant-select').filter({ hasText: /scope|permission/i });
    this.tokensTable = page.locator('.ant-table').filter({ hasText: /token|access/i });
    this.revokeTokenButton = page.getByRole('button', { name: /revoke.*token|delete.*token/i });
    this.generatedTokenDisplay = page.locator('[data-testid="generated-token"], .generated-token, code').first();

    // Modals
    this.confirmRevokeModal = page.locator('.ant-modal').filter({ hasText: /revoke|delete|confirm/i });
    this.confirmRevokeButton = this.confirmRevokeModal.getByRole('button', { name: /revoke|delete|confirm|yes/i });
    this.cancelRevokeButton = this.confirmRevokeModal.getByRole('button', { name: /cancel|no/i });
  }

  /**
   * Navigate to the Profile page
   */
  async goto(): Promise<void> {
    await this.page.goto('/profile');
    await this.waitForPageReady();
  }

  /**
   * Wait for page to be fully loaded
   */
  async waitForPageReady(): Promise<void> {
    await this.page.waitForLoadState('networkidle');
    await this.heading.waitFor({ state: 'visible', timeout: 10000 }).catch(() => {
      // Page might have different structure
    });
  }

  /**
   * Assert page is loaded
   */
  async expectPageLoaded(): Promise<void> {
    await expect(this.heading).toBeVisible();
  }

  // === Profile Management ===

  /**
   * Update profile information
   */
  async updateProfile(updates: {
    email?: string;
    displayName?: string;
  }): Promise<void> {
    if (updates.email) {
      await this.emailInput.clear();
      await this.emailInput.fill(updates.email);
    }
    if (updates.displayName) {
      await this.displayNameInput.clear();
      await this.displayNameInput.fill(updates.displayName);
    }
    await this.saveProfileButton.click();
  }

  /**
   * Change password
   */
  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    await this.currentPasswordInput.fill(currentPassword);
    await this.newPasswordInput.fill(newPassword);
    await this.confirmPasswordInput.fill(newPassword);
    await this.changePasswordButton.click();
  }

  // === API Key Management ===

  /**
   * Generate a new API key
   */
  async generateApiKey(name: string, expiry?: string): Promise<string> {
    await this.generateApiKeyButton.click();

    // Fill key details in modal
    await this.apiKeyNameInput.fill(name);
    if (expiry && await this.apiKeyExpirySelect.isVisible()) {
      await this.apiKeyExpirySelect.selectOption(expiry);
    }

    // Confirm generation (button text varies)
    const confirmButton = this.page.getByRole('button', { name: /generate|create|confirm/i }).last();
    await confirmButton.click();

    // Wait for key to be displayed
    await this.generatedApiKeyDisplay.waitFor({ state: 'visible', timeout: 10000 });

    // Return the generated key
    const apiKey = await this.generatedApiKeyDisplay.textContent();
    return apiKey || '';
  }

  /**
   * Copy API key to clipboard
   */
  async copyApiKey(): Promise<void> {
    await this.copyApiKeyButton.click();
    await this.expectSuccessToast(/copied/i);
  }

  /**
   * Revoke an API key by name
   */
  async revokeApiKey(keyName: string): Promise<void> {
    const keyRow = this.apiKeysTable.locator('tr').filter({ hasText: keyName });
    await keyRow.getByRole('button', { name: /revoke|delete/i }).click();

    // Confirm revocation
    await this.confirmRevokeButton.click();
    await this.expectSuccessToast(/revoked|deleted/i);
  }

  /**
   * Get count of API keys
   */
  async getApiKeyCount(): Promise<number> {
    const rows = await this.apiKeysTable.locator('tbody tr').all();
    return rows.length;
  }

  // === Access Token Management ===

  /**
   * Create a new access token
   */
  async createAccessToken(name: string, scopes?: string[]): Promise<string> {
    await this.createTokenButton.click();

    // Fill token details
    await this.tokenNameInput.fill(name);

    if (scopes && await this.tokenScopesSelect.isVisible()) {
      for (const scope of scopes) {
        await this.tokenScopesSelect.click();
        await this.page.getByText(scope, { exact: false }).click();
      }
    }

    // Confirm creation
    const confirmButton = this.page.getByRole('button', { name: /create|generate|confirm/i }).last();
    await confirmButton.click();

    // Wait for token to be displayed
    await this.generatedTokenDisplay.waitFor({ state: 'visible', timeout: 10000 });

    // Return the generated token
    const token = await this.generatedTokenDisplay.textContent();
    return token || '';
  }

  /**
   * Revoke an access token by name
   */
  async revokeAccessToken(tokenName: string): Promise<void> {
    const tokenRow = this.tokensTable.locator('tr').filter({ hasText: tokenName });
    await tokenRow.getByRole('button', { name: /revoke|delete/i }).click();

    // Confirm revocation
    await this.confirmRevokeButton.click();
    await this.expectSuccessToast(/revoked|deleted/i);
  }

  /**
   * Get count of access tokens
   */
  async getAccessTokenCount(): Promise<number> {
    const rows = await this.tokensTable.locator('tbody tr').all();
    return rows.length;
  }

  // === Assertions ===

  /**
   * Expect API key to be visible in table
   */
  async expectApiKeyVisible(keyName: string): Promise<void> {
    await expect(this.apiKeysTable.getByText(keyName)).toBeVisible();
  }

  /**
   * Expect access token to be visible in table
   */
  async expectAccessTokenVisible(tokenName: string): Promise<void> {
    await expect(this.tokensTable.getByText(tokenName)).toBeVisible();
  }

  /**
   * Expect profile update success
   */
  async expectProfileUpdateSuccess(): Promise<void> {
    await this.expectSuccessToast(/saved|updated|success/i);
  }

  /**
   * Expect password change success
   */
  async expectPasswordChangeSuccess(): Promise<void> {
    await this.expectSuccessToast(/password.*changed|updated|success/i);
  }
}
