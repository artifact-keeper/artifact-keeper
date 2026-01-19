import { Page, Locator, expect } from '@playwright/test';

/**
 * Base page object class with common utilities for all page objects.
 * All page objects should extend this class.
 */
export class BasePage {
  constructor(protected page: Page) {}

  /**
   * Wait for page to finish loading (network idle)
   */
  async waitForPageLoad(): Promise<void> {
    await this.page.waitForLoadState('networkidle');
  }

  /**
   * Wait for page to be ready (DOM content loaded)
   */
  async waitForDOMReady(): Promise<void> {
    await this.page.waitForLoadState('domcontentloaded');
  }

  /**
   * Assert that a toast notification with the given message is visible
   * Ant Design v5 uses .ant-message-notice for toast messages
   */
  async expectToast(message: string | RegExp): Promise<void> {
    const toast = this.page.locator('.ant-message-notice, .ant-message-notice-content');
    await expect(toast.filter({ hasText: message })).toBeVisible({ timeout: 10000 });
  }

  /**
   * Assert that a success toast is visible with the given message
   * Ant Design v5 uses check-circle icon for success messages
   * Uses .first() to handle multiple matching toasts
   */
  async expectSuccessToast(message: string | RegExp): Promise<void> {
    // Use .first() to handle case where multiple success toasts appear
    const toast = this.page.locator('.ant-message-notice').filter({ hasText: message }).first();
    await expect(toast).toBeVisible({ timeout: 10000 });
  }

  /**
   * Assert that an error toast is visible with the given message
   */
  async expectErrorToast(message: string | RegExp): Promise<void> {
    const toast = this.page.locator('.ant-message-notice').filter({ hasText: message });
    await expect(toast).toBeVisible({ timeout: 10000 });
  }

  /**
   * Assert that the current URL matches the given pattern
   */
  async expectUrl(pattern: string | RegExp): Promise<void> {
    await expect(this.page).toHaveURL(pattern);
  }

  /**
   * Navigate to a specific path
   */
  async goto(path: string): Promise<void> {
    await this.page.goto(path);
    await this.waitForPageLoad();
  }

  /**
   * Click a button by its text content
   */
  async clickButton(name: string | RegExp): Promise<void> {
    await this.page.getByRole('button', { name }).click();
  }

  /**
   * Fill an input field by its label
   */
  async fillInput(label: string, value: string): Promise<void> {
    await this.page.getByLabel(label).fill(value);
  }

  /**
   * Select an option from a dropdown by label
   */
  async selectOption(label: string, value: string): Promise<void> {
    await this.page.getByLabel(label).click();
    await this.page.getByTitle(value).click();
  }

  /**
   * Wait for an element to be visible
   */
  async waitForVisible(locator: Locator, timeout = 30000): Promise<void> {
    await expect(locator).toBeVisible({ timeout });
  }

  /**
   * Wait for an element to be hidden
   */
  async waitForHidden(locator: Locator, timeout = 30000): Promise<void> {
    await expect(locator).toBeHidden({ timeout });
  }

  /**
   * Check if an element is visible (without throwing)
   */
  async isVisible(locator: Locator): Promise<boolean> {
    try {
      await expect(locator).toBeVisible({ timeout: 1000 });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get the text content of an element
   */
  async getText(locator: Locator): Promise<string> {
    return (await locator.textContent()) || '';
  }

  /**
   * Take a screenshot with a descriptive name
   */
  async screenshot(name: string): Promise<void> {
    await this.page.screenshot({ path: `test-results/${name}.png` });
  }
}

export default BasePage;
