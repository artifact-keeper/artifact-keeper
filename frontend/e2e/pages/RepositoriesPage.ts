import { Page, Locator, expect } from '@playwright/test';
import { BasePage } from './BasePage';

/**
 * Page object for the Repositories list page.
 * Handles repository table and navigation to create wizard.
 */
export class RepositoriesPage extends BasePage {
  // Page elements
  readonly heading: Locator;
  readonly createButton: Locator;
  readonly refreshButton: Locator;
  readonly table: Locator;
  readonly tableRows: Locator;

  // Filters
  readonly searchInput: Locator;
  readonly formatFilter: Locator;
  readonly typeFilter: Locator;
  readonly clearFiltersButton: Locator;

  // Table columns
  readonly keyColumn: Locator;
  readonly nameColumn: Locator;
  readonly formatColumn: Locator;
  readonly typeColumn: Locator;
  readonly actionsColumn: Locator;

  // Empty state
  readonly emptyState: Locator;

  // Confirmation dialog
  readonly confirmDialog: Locator;
  readonly confirmInput: Locator;
  readonly confirmButton: Locator;
  readonly cancelButton: Locator;

  constructor(page: Page) {
    super(page);

    // Page elements
    this.heading = page.getByRole('heading', { name: /repositories/i });
    // Button text includes icon text "plus" + label "Create Repository"
    this.createButton = page.getByRole('button', { name: /create repository/i });
    // Refresh button has "reload" in its accessible name
    this.refreshButton = page.getByRole('button', { name: /reload/i });
    this.table = page.getByRole('table');
    this.tableRows = this.table.locator('tbody tr');

    // Filters - use combobox locators based on actual UI
    this.searchInput = page.getByRole('searchbox', { name: /search/i });
    this.formatFilter = page.locator('[class*="generic"]').filter({ hasText: 'Filter by format' }).locator('div').first();
    this.typeFilter = page.locator('[class*="generic"]').filter({ hasText: 'Filter by type' }).locator('div').first();
    this.clearFiltersButton = page.getByText(/clear filters/i);

    // Table columns (headers)
    this.keyColumn = page.getByRole('columnheader', { name: /key/i });
    this.nameColumn = page.getByRole('columnheader', { name: /name/i });
    this.formatColumn = page.getByRole('columnheader', { name: /format/i });
    this.typeColumn = page.getByRole('columnheader', { name: /type/i });
    this.actionsColumn = page.getByRole('columnheader', { name: /actions/i });

    // Empty state
    this.emptyState = page.locator('.ant-empty, [data-testid="empty-state"]');

    // Confirmation dialog
    this.confirmDialog = page.locator('.ant-modal-confirm, .ant-modal').filter({
      hasText: /delete|confirm/i,
    });
    this.confirmInput = this.confirmDialog.getByRole('textbox');
    this.confirmButton = this.confirmDialog.getByRole('button', {
      name: /delete|confirm|yes/i,
    });
    this.cancelButton = this.confirmDialog.getByRole('button', {
      name: /cancel|no/i,
    });
  }

  /**
   * Navigate to the repositories page
   */
  async goto(): Promise<void> {
    await this.page.goto('/repositories');
    await this.waitForPageLoad();
  }

  /**
   * Click the create repository button to open the wizard
   */
  async openCreateWizard(): Promise<void> {
    await this.createButton.click();
    // Wait for wizard modal to appear
    await this.page.waitForSelector('.ant-modal', { state: 'visible' });
  }

  /**
   * Find a repository row by its key
   */
  async findRepo(key: string): Promise<Locator> {
    return this.tableRows.filter({ hasText: key });
  }

  /**
   * Check if a repository exists in the table
   */
  async repoExists(key: string): Promise<boolean> {
    const row = await this.findRepo(key);
    return await this.isVisible(row);
  }

  /**
   * Click view button for a repository
   * Button text is "eye View" (icon name + text)
   */
  async viewRepo(key: string): Promise<void> {
    const row = await this.findRepo(key);
    await row.getByRole('button', { name: /eye view/i }).click();
  }

  /**
   * Click edit button for a repository
   * Button text is "edit Edit" (icon name + text)
   */
  async editRepo(key: string): Promise<void> {
    const row = await this.findRepo(key);
    await row.getByRole('button', { name: /edit edit/i }).click();
    // Wait for edit modal
    await this.page.waitForSelector('.ant-modal', { state: 'visible' });
  }

  /**
   * Delete a repository with confirmation
   * Button text is "delete Delete" (icon name + text)
   */
  async deleteRepo(key: string): Promise<void> {
    const row = await this.findRepo(key);
    await row.getByRole('button', { name: /delete delete/i }).click();

    // Wait for confirmation dialog
    await expect(this.confirmDialog).toBeVisible();

    // Type confirmation if required
    if (await this.isVisible(this.confirmInput)) {
      await this.confirmInput.fill(key);
    }

    // Click confirm
    await this.confirmButton.click();

    // Wait for dialog to close
    await this.waitForHidden(this.confirmDialog);
  }

  /**
   * Filter repositories by format
   */
  async filterByFormat(format: string): Promise<void> {
    await this.formatFilter.click();
    await this.page.getByText(format, { exact: true }).click();
  }

  /**
   * Filter repositories by type
   */
  async filterByType(type: string): Promise<void> {
    await this.typeFilter.click();
    await this.page.getByTitle(type).click();
  }

  /**
   * Clear all filters
   */
  async clearFilters(): Promise<void> {
    if (await this.isVisible(this.clearFiltersButton)) {
      await this.clearFiltersButton.click();
    }
  }

  /**
   * Refresh the repository list
   */
  async refresh(): Promise<void> {
    await this.refreshButton.click();
    await this.waitForPageLoad();
  }

  /**
   * Get the count of repositories in the table
   */
  async getRepoCount(): Promise<number> {
    const count = await this.tableRows.count();
    // Exclude empty row if present
    const emptyRow = this.tableRows.filter({ hasText: /no data/i });
    if (await this.isVisible(emptyRow)) {
      return 0;
    }
    return count;
  }

  /**
   * Assert repositories page is loaded
   */
  async expectPageLoaded(): Promise<void> {
    await expect(this.heading).toBeVisible();
    await expect(this.createButton).toBeVisible();
  }

  /**
   * Assert repository exists in table
   */
  async expectRepoExists(key: string): Promise<void> {
    const row = await this.findRepo(key);
    await expect(row).toBeVisible();
  }

  /**
   * Assert repository does not exist in table
   */
  async expectRepoNotExists(key: string): Promise<void> {
    const row = await this.findRepo(key);
    await expect(row).toBeHidden();
  }
}

export default RepositoriesPage;
