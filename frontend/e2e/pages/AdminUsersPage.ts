import { type Page, type Locator, expect } from '@playwright/test';
import { BasePage } from './BasePage';

/**
 * Page Object for Admin Users page
 * Path: /users or /admin/users
 *
 * Features:
 * - User list table with CRUD operations
 * - Create user modal
 * - Edit user modal
 * - Reset password
 * - Enable/disable users
 */
export class AdminUsersPage extends BasePage {
  // Page heading
  readonly heading: Locator;

  // Users table
  readonly usersTable: Locator;
  readonly searchInput: Locator;
  readonly createUserButton: Locator;
  readonly refreshButton: Locator;

  // Create user modal
  readonly createUserModal: Locator;
  readonly usernameInput: Locator;
  readonly emailInput: Locator;
  readonly displayNameInput: Locator;
  readonly passwordGenerateCheckbox: Locator;
  readonly submitCreateButton: Locator;
  readonly cancelButton: Locator;

  // Edit user modal
  readonly editUserModal: Locator;
  readonly submitEditButton: Locator;

  // Generated password modal
  readonly passwordModal: Locator;
  readonly generatedPassword: Locator;
  readonly doneButton: Locator;

  // User row actions
  readonly editButton: Locator;
  readonly resetPasswordButton: Locator;
  readonly toggleStatusButton: Locator;
  readonly deleteButton: Locator;

  constructor(page: Page) {
    super(page);

    // Page heading
    this.heading = page.getByRole('heading', { name: 'Users' });

    // Users table
    this.usersTable = page.locator('.ant-table');
    this.searchInput = page.getByPlaceholder(/search/i);
    this.createUserButton = page.getByRole('button', { name: /create user/i });
    this.refreshButton = page.getByRole('button', { name: /refresh/i });

    // Create user modal
    this.createUserModal = page.locator('.ant-modal').filter({ hasText: 'Create User' });
    this.usernameInput = page.getByLabel('Username');
    this.emailInput = page.getByLabel('Email');
    this.displayNameInput = page.getByLabel('Display Name');
    this.passwordGenerateCheckbox = page.locator('label').filter({ hasText: /auto.*generate|generate.*password/i });
    this.submitCreateButton = page.getByRole('button', { name: /^create$/i });
    this.cancelButton = page.getByRole('button', { name: 'Cancel' });

    // Edit user modal
    this.editUserModal = page.locator('.ant-modal').filter({ hasText: /Edit User/i });
    this.submitEditButton = page.getByRole('button', { name: /save|update/i });

    // Generated password modal
    this.passwordModal = page.locator('.ant-modal').filter({ hasText: /Temporary Password|Generated Password/i });
    this.generatedPassword = page.locator('code, .password-display, [data-testid="generated-password"]').first();
    this.doneButton = page.getByRole('button', { name: 'Done' });

    // User row actions
    this.editButton = page.getByRole('button', { name: 'Edit' });
    this.resetPasswordButton = page.getByRole('button', { name: /reset password/i });
    this.toggleStatusButton = page.getByRole('button', { name: /(enable|disable)/i });
    this.deleteButton = page.getByRole('button', { name: /delete/i });
  }

  /**
   * Navigate to Users page
   */
  async goto(): Promise<void> {
    await this.page.goto('/users');
    await this.waitForPageReady();
  }

  /**
   * Wait for page to be fully loaded
   */
  async waitForPageReady(): Promise<void> {
    await this.heading.waitFor({ state: 'visible' });
    await this.usersTable.waitFor({ state: 'visible' });
  }

  /**
   * Assert page is loaded
   */
  async expectPageLoaded(): Promise<void> {
    await expect(this.heading).toBeVisible();
    await expect(this.usersTable).toBeVisible();
  }

  // === User CRUD Operations ===

  /**
   * Open create user modal
   */
  async openCreateUserModal(): Promise<void> {
    await this.createUserButton.click();
    await this.createUserModal.waitFor({ state: 'visible' });
  }

  /**
   * Create a new user
   */
  async createUser(user: {
    username: string;
    email: string;
    displayName?: string;
  }): Promise<string | null> {
    await this.openCreateUserModal();

    await this.usernameInput.fill(user.username);
    await this.emailInput.fill(user.email);
    if (user.displayName) {
      await this.displayNameInput.fill(user.displayName);
    }

    await this.submitCreateButton.click();

    // Wait for password modal or success
    await this.page.waitForTimeout(1000);

    // Check if password modal is shown
    let generatedPassword: string | null = null;
    if (await this.passwordModal.isVisible()) {
      generatedPassword = await this.generatedPassword.textContent();
      await this.doneButton.click();
    }

    return generatedPassword;
  }

  /**
   * Close create user modal
   */
  async closeCreateUserModal(): Promise<void> {
    await this.cancelButton.click();
    await this.createUserModal.waitFor({ state: 'hidden' });
  }

  /**
   * Edit a user
   */
  async editUser(username: string, updates: {
    email?: string;
    displayName?: string;
  }): Promise<void> {
    const userRow = this.usersTable.locator('tr').filter({ hasText: username });
    await userRow.getByRole('button', { name: 'Edit' }).click();

    await this.editUserModal.waitFor({ state: 'visible' });

    if (updates.email) {
      await this.emailInput.clear();
      await this.emailInput.fill(updates.email);
    }
    if (updates.displayName) {
      await this.displayNameInput.clear();
      await this.displayNameInput.fill(updates.displayName);
    }

    await this.submitEditButton.click();
    await this.editUserModal.waitFor({ state: 'hidden' });
  }

  /**
   * Reset a user's password
   */
  async resetUserPassword(username: string): Promise<string | null> {
    const userRow = this.usersTable.locator('tr').filter({ hasText: username });
    await userRow.getByRole('button', { name: /reset password/i }).click();

    // Confirm if needed
    const confirmButton = this.page.getByRole('button', { name: /confirm|yes|reset/i });
    if (await confirmButton.isVisible()) {
      await confirmButton.click();
    }

    // Wait for password modal
    await this.page.waitForTimeout(1000);

    let newPassword: string | null = null;
    if (await this.passwordModal.isVisible()) {
      newPassword = await this.generatedPassword.textContent();
      await this.doneButton.click();
    }

    return newPassword;
  }

  /**
   * Toggle user status (enable/disable)
   */
  async toggleUserStatus(username: string): Promise<void> {
    const userRow = this.usersTable.locator('tr').filter({ hasText: username });
    await userRow.getByRole('button', { name: /(enable|disable)/i }).click();

    // Confirm if needed
    const confirmButton = this.page.getByRole('button', { name: /confirm|yes/i });
    if (await confirmButton.isVisible()) {
      await confirmButton.click();
    }
  }

  /**
   * Search for users
   */
  async searchUsers(query: string): Promise<void> {
    await this.searchInput.fill(query);
    await this.page.waitForTimeout(500); // Debounce
  }

  /**
   * Get user count
   */
  async getUserCount(): Promise<number> {
    const rows = await this.usersTable.locator('tbody tr').all();
    return rows.length;
  }

  // === Assertions ===

  /**
   * Expect user to be visible in table
   */
  async expectUserVisible(username: string): Promise<void> {
    await expect(this.usersTable.getByText(username)).toBeVisible();
  }

  /**
   * Expect user creation success
   */
  async expectUserCreated(username: string): Promise<void> {
    await this.expectSuccessToast(/created|success/i);
    await this.expectUserVisible(username);
  }
}
