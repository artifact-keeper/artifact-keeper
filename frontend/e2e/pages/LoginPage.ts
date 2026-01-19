import { Page, Locator, expect } from '@playwright/test';
import { BasePage } from './BasePage';

/**
 * Page object for the Login page.
 * Handles authentication flows including login, logout, and MFA.
 */
export class LoginPage extends BasePage {
  // Login form locators
  readonly usernameInput: Locator;
  readonly passwordInput: Locator;
  readonly loginButton: Locator;
  readonly errorMessage: Locator;
  readonly forgotPasswordLink: Locator;

  // SSO provider buttons
  readonly ssoSection: Locator;
  readonly githubSsoButton: Locator;
  readonly gitlabSsoButton: Locator;
  readonly googleSsoButton: Locator;

  // MFA locators
  readonly mfaCodeInput: Locator;
  readonly mfaVerifyButton: Locator;
  readonly mfaQrCode: Locator;
  readonly mfaSecretKey: Locator;
  readonly mfaEnrollButton: Locator;

  constructor(page: Page) {
    super(page);

    // Login form
    this.usernameInput = page.getByPlaceholder('Username');
    this.passwordInput = page.getByPlaceholder('Password');
    this.loginButton = page.getByRole('button', { name: /log in/i });
    this.errorMessage = page.locator('.ant-alert-error, .ant-form-item-explain-error');
    this.forgotPasswordLink = page.getByRole('link', { name: /forgot.*password/i });

    // SSO
    this.ssoSection = page.locator('[data-testid="sso-providers"], .sso-section');
    this.githubSsoButton = page.getByRole('button', { name: /github/i });
    this.gitlabSsoButton = page.getByRole('button', { name: /gitlab/i });
    this.googleSsoButton = page.getByRole('button', { name: /google/i });

    // MFA
    this.mfaCodeInput = page.getByPlaceholder(/code|otp|token/i);
    this.mfaVerifyButton = page.getByRole('button', { name: /verify|confirm/i });
    this.mfaQrCode = page.locator('[data-testid="mfa-qr-code"], .mfa-qr-code, canvas');
    this.mfaSecretKey = page.locator('[data-testid="mfa-secret"], .mfa-secret');
    this.mfaEnrollButton = page.getByRole('button', { name: /enable.*mfa|enroll.*mfa/i });
  }

  /**
   * Navigate to the login page
   */
  async goto(): Promise<void> {
    await this.page.goto('/login');
    await this.waitForPageLoad();
  }

  /**
   * Login with username and password
   */
  async login(username: string, password: string): Promise<void> {
    await this.usernameInput.fill(username);
    await this.passwordInput.fill(password);
    await this.loginButton.click();
  }

  /**
   * Login and wait for redirect to dashboard
   */
  async loginAndWaitForDashboard(username: string, password: string): Promise<void> {
    await this.login(username, password);
    await this.page.waitForURL(/\/(dashboard)?$/);
  }

  /**
   * Logout from the application
   */
  async logout(): Promise<void> {
    // Try different logout button locations
    const userMenu = this.page.locator(
      '[data-testid="user-menu"], .user-menu, .ant-dropdown-trigger'
    ).first();

    if (await userMenu.isVisible()) {
      await userMenu.click();
      await this.page.getByRole('menuitem', { name: /log ?out|sign ?out/i }).click();
    } else {
      // Direct logout button
      await this.page.getByRole('button', { name: /log ?out|sign ?out/i }).click();
    }

    await this.page.waitForURL(/\/login/);
  }

  /**
   * Check if login error is displayed
   */
  async hasError(): Promise<boolean> {
    return await this.isVisible(this.errorMessage);
  }

  /**
   * Get error message text
   */
  async getErrorMessage(): Promise<string> {
    return await this.getText(this.errorMessage);
  }

  /**
   * Verify MFA code
   */
  async verifyMfaCode(code: string): Promise<void> {
    await this.mfaCodeInput.fill(code);
    await this.mfaVerifyButton.click();
  }

  /**
   * Check if MFA challenge is displayed
   */
  async isMfaChallengeVisible(): Promise<boolean> {
    return await this.isVisible(this.mfaCodeInput);
  }

  /**
   * Check if SSO providers are visible
   */
  async areSsoProvidersVisible(): Promise<boolean> {
    return await this.isVisible(this.ssoSection);
  }

  /**
   * Get MFA secret key (for enrollment)
   */
  async getMfaSecretKey(): Promise<string> {
    return await this.getText(this.mfaSecretKey);
  }

  /**
   * Assert successful login (user is redirected)
   */
  async expectLoginSuccess(): Promise<void> {
    await expect(this.page).not.toHaveURL(/\/login/);
  }

  /**
   * Assert login failure (error is shown)
   */
  async expectLoginFailure(): Promise<void> {
    await expect(this.errorMessage).toBeVisible();
  }
}

export default LoginPage;
