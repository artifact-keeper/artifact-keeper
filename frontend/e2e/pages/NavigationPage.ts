import { Page, Locator, expect } from '@playwright/test';
import { BasePage } from './BasePage';

/**
 * Page object for sidebar navigation interactions.
 * Encapsulates grouped nav structure introduced in the nav refactor.
 */
export class NavigationPage extends BasePage {
  readonly sidebar: Locator;
  readonly siderMenu: Locator;

  constructor(page: Page) {
    super(page);
    this.sidebar = page.locator('.ant-layout-sider, .ant-drawer-body');
    this.siderMenu = this.sidebar.locator('.ant-menu');
  }

  /** Assert a nav group header is visible */
  async expectGroupVisible(groupName: string): Promise<void> {
    await expect(this.sidebar.getByText(groupName, { exact: true })).toBeVisible();
  }

  /** Assert a nav group header is NOT visible (e.g., non-admin user) */
  async expectGroupHidden(groupName: string): Promise<void> {
    await expect(this.sidebar.getByText(groupName, { exact: true })).not.toBeVisible();
  }

  /** Get all visible group header labels */
  async getVisibleGroups(): Promise<string[]> {
    const groupHeaders = this.sidebar.locator('.ant-menu-item-group-title');
    return groupHeaders.allTextContents();
  }

  /** Click a navigation link by its label */
  async navigateTo(linkName: string): Promise<void> {
    await this.page.getByRole('link', { name: linkName }).click();
    await this.waitForPageLoad();
  }

  /** Assert the given menu item is currently selected */
  async expectItemSelected(linkName: string): Promise<void> {
    const selectedItem = this.page.locator('.ant-menu-item-selected').filter({
      has: this.page.getByRole('link', { name: linkName }),
    });
    await expect(selectedItem).toBeVisible();
  }

  /** Assert a menu item is disabled (Coming Soon) */
  async expectItemDisabled(text: string): Promise<void> {
    const disabledItem = this.sidebar.locator('.ant-menu-item-disabled').filter({
      hasText: text,
    });
    await expect(disabledItem).toBeVisible();
  }

  /** Assert a menu item link is enabled and visible */
  async expectItemEnabled(linkName: string): Promise<void> {
    await expect(this.page.getByRole('link', { name: linkName })).toBeVisible();
  }

  /** Get count of items within a specific group */
  async getGroupItemCount(groupName: string): Promise<number> {
    const group = this.sidebar.locator('.ant-menu-item-group').filter({
      has: this.sidebar.locator('.ant-menu-item-group-title', { hasText: groupName }),
    });
    const items = group.locator('.ant-menu-item');
    return items.count();
  }

  /** Assert the sidebar logo text */
  async expectLogoText(text: string): Promise<void> {
    await expect(this.sidebar.getByText(text, { exact: true })).toBeVisible();
  }

  /** Assert version is displayed */
  async expectVersion(version: string): Promise<void> {
    await expect(this.sidebar.getByText(`v${version}`)).toBeVisible();
  }
}

export default NavigationPage;
