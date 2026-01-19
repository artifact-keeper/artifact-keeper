import { type Page, type Locator, expect } from '@playwright/test';
import { BasePage } from './BasePage';

/**
 * Page Object for the Migration page
 * Path: /migration
 *
 * Features:
 * - Jobs table with migration status and actions
 * - Connections table with source connections
 * - Tabs for Live Migration and Import from Export
 * - New Migration wizard trigger
 */
export class MigrationPage extends BasePage {
  // Page heading
  readonly heading: Locator;

  // Tabs
  readonly liveMigrationTab: Locator;
  readonly importFromExportTab: Locator;

  // Jobs table
  readonly jobsTable: Locator;
  readonly jobsTableRows: Locator;
  readonly newMigrationButton: Locator;
  readonly refreshButton: Locator;

  // Connections table
  readonly connectionsTable: Locator;
  readonly addConnectionButton: Locator;

  // Job actions
  readonly pauseButton: Locator;
  readonly resumeButton: Locator;
  readonly cancelButton: Locator;
  readonly deleteButton: Locator;

  constructor(page: Page) {
    super(page);

    // Page heading
    this.heading = page.getByRole('heading', { name: /migration from artifactory/i });

    // Tabs
    this.liveMigrationTab = page.getByRole('tab', { name: /live migration/i });
    this.importFromExportTab = page.getByRole('tab', { name: /import from export/i });

    // Jobs table section
    this.jobsTable = page.locator('.ant-card').filter({ hasText: 'Migration Jobs' }).locator('table');
    this.jobsTableRows = this.jobsTable.locator('tbody tr');
    this.newMigrationButton = page.getByRole('button', { name: /new migration/i });
    this.refreshButton = page.getByRole('button', { name: /refresh/i });

    // Connections table section
    this.connectionsTable = page.locator('.ant-card').filter({ hasText: 'Source Connections' }).locator('table');
    this.addConnectionButton = page.getByRole('button', { name: /add connection/i });

    // Job action buttons (context-dependent)
    this.pauseButton = page.getByRole('button', { name: /pause/i });
    this.resumeButton = page.getByRole('button', { name: /resume/i });
    this.cancelButton = page.getByRole('button', { name: /cancel/i });
    this.deleteButton = page.getByRole('button', { name: /delete/i });
  }

  /**
   * Navigate to the Migration page
   */
  async goto(): Promise<void> {
    await this.page.goto('/migration');
    await this.waitForPageReady();
  }

  /**
   * Wait for the page to be fully loaded
   */
  async waitForPageReady(): Promise<void> {
    await this.heading.waitFor({ state: 'visible' });
    await this.liveMigrationTab.waitFor({ state: 'visible' });
  }

  /**
   * Assert that the page is loaded
   */
  async expectPageLoaded(): Promise<void> {
    await expect(this.heading).toBeVisible();
    await expect(this.liveMigrationTab).toBeVisible();
  }

  // === Tab Navigation ===

  /**
   * Click on Live Migration tab
   */
  async clickLiveMigrationTab(): Promise<void> {
    await this.liveMigrationTab.click();
    await this.newMigrationButton.waitFor({ state: 'visible', timeout: 10000 }).catch(() => {
      // Button might not be visible if wizard is open
    });
  }

  /**
   * Click on Import from Export tab
   */
  async clickImportFromExportTab(): Promise<void> {
    await this.importFromExportTab.click();
  }

  // === Migration Jobs ===

  /**
   * Click New Migration button to open the wizard
   */
  async openMigrationWizard(): Promise<void> {
    await this.newMigrationButton.click();
    // Wait for wizard to appear
    await this.page.locator('.ant-steps').waitFor({ state: 'visible' });
  }

  /**
   * Refresh the migration jobs list
   */
  async refresh(): Promise<void> {
    await this.refreshButton.click();
  }

  /**
   * Get the number of migration jobs
   */
  async getJobsCount(): Promise<number> {
    const rows = await this.jobsTableRows.all();
    // Filter out empty state row
    return rows.filter(async (row) => {
      const text = await row.textContent();
      return text && !text.includes('No data');
    }).length;
  }

  /**
   * Find a job row by ID (partial match)
   */
  findJob(idPrefix: string): Locator {
    return this.jobsTableRows.filter({ hasText: idPrefix });
  }

  /**
   * Get the status of a job by ID prefix
   */
  async getJobStatus(idPrefix: string): Promise<string> {
    const row = this.findJob(idPrefix);
    const statusTag = row.locator('.ant-tag').first();
    return await statusTag.textContent() || '';
  }

  /**
   * Pause a running migration
   */
  async pauseJob(idPrefix: string): Promise<void> {
    const row = this.findJob(idPrefix);
    await row.getByRole('button', { name: /pause/i }).click();
    await this.expectSuccessToast(/paused/i);
  }

  /**
   * Resume a paused migration
   */
  async resumeJob(idPrefix: string): Promise<void> {
    const row = this.findJob(idPrefix);
    await row.getByRole('button', { name: /resume/i }).click();
    await this.expectSuccessToast(/resumed/i);
  }

  /**
   * Cancel a migration
   */
  async cancelJob(idPrefix: string): Promise<void> {
    const row = this.findJob(idPrefix);
    await row.getByRole('button', { name: /cancel/i }).click();
    await this.expectSuccessToast(/cancelled/i);
  }

  /**
   * Delete a completed/failed migration
   */
  async deleteJob(idPrefix: string): Promise<void> {
    const row = this.findJob(idPrefix);
    await row.getByRole('button', { name: /delete/i }).click();
    // Confirm deletion in modal
    await this.page.getByRole('button', { name: /delete/i }).last().click();
    await this.expectSuccessToast(/deleted/i);
  }

  // === Source Connections ===

  /**
   * Get the number of source connections
   */
  async getConnectionsCount(): Promise<number> {
    const rows = await this.connectionsTable.locator('tbody tr').all();
    return rows.filter(async (row) => {
      const text = await row.textContent();
      return text && !text.includes('No data');
    }).length;
  }

  /**
   * Find a connection by name
   */
  findConnection(name: string): Locator {
    return this.connectionsTable.locator('tbody tr').filter({ hasText: name });
  }

  /**
   * Delete a source connection
   */
  async deleteConnection(name: string): Promise<void> {
    const row = this.findConnection(name);
    await row.getByRole('button', { name: /delete/i }).click();
    await this.expectSuccessToast(/deleted/i);
  }
}
