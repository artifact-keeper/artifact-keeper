import { type Page, type Locator, expect } from '@playwright/test';
import { BasePage } from './BasePage';

/**
 * Page Object for the Migration Wizard
 *
 * Multi-step wizard with 5 steps:
 * 1. Connect - Source connection form (URL, credentials)
 * 2. Select Repos - Repository selection from source
 * 3. Configure - Migration options (artifacts, metadata, users, etc.)
 * 4. Review - Summary of migration configuration
 * 5. Complete - Success result
 */
export class MigrationWizardPage extends BasePage {
  // Steps navigation
  readonly steps: Locator;
  readonly activeStep: Locator;

  // Navigation buttons
  readonly backButton: Locator;
  readonly nextButton: Locator;
  readonly cancelButton: Locator;
  readonly startMigrationButton: Locator;

  // Step 1: Connection form
  readonly connectionNameInput: Locator;
  readonly sourceUrlInput: Locator;
  readonly usernameInput: Locator;
  readonly passwordInput: Locator;
  readonly apiKeyInput: Locator;
  readonly authTypeSelect: Locator;
  readonly testConnectionButton: Locator;

  // Step 2: Repository selection
  readonly repoSearchInput: Locator;
  readonly repoTable: Locator;
  readonly selectAllCheckbox: Locator;

  // Step 3: Configuration options
  readonly includeArtifactsCheckbox: Locator;
  readonly includeMetadataCheckbox: Locator;
  readonly includeUsersCheckbox: Locator;
  readonly includeGroupsCheckbox: Locator;
  readonly includePermissionsCheckbox: Locator;
  readonly conflictResolutionSelect: Locator;
  readonly verifyChecksumsCheckbox: Locator;

  // Step 4: Review summary
  readonly reviewSourceConnection: Locator;
  readonly reviewRepositories: Locator;
  readonly reviewConfiguration: Locator;

  // Step 5: Complete
  readonly successResult: Locator;
  readonly viewProgressButton: Locator;
  readonly newMigrationButton: Locator;

  constructor(page: Page) {
    super(page);

    // Steps navigation
    this.steps = page.locator('.ant-steps');
    this.activeStep = page.locator('.ant-steps-item-active');

    // Navigation buttons
    this.backButton = page.getByRole('button', { name: /back/i });
    this.nextButton = page.getByRole('button', { name: /next/i });
    this.cancelButton = page.getByRole('button', { name: /cancel/i });
    this.startMigrationButton = page.getByRole('button', { name: /start migration/i });

    // Step 1: Connection form fields
    this.connectionNameInput = page.getByPlaceholder(/connection name|name/i);
    this.sourceUrlInput = page.getByPlaceholder(/artifactory url|https:\/\//i);
    this.usernameInput = page.getByPlaceholder(/username/i);
    this.passwordInput = page.getByPlaceholder(/password/i);
    this.apiKeyInput = page.getByPlaceholder(/api key/i);
    this.authTypeSelect = page.locator('select').filter({ hasText: /basic|token|api key/i });
    this.testConnectionButton = page.getByRole('button', { name: /test connection|verify/i });

    // Step 2: Repository selection
    this.repoSearchInput = page.getByPlaceholder(/search|filter/i);
    this.repoTable = page.locator('.ant-table');
    this.selectAllCheckbox = page.locator('.ant-table-selection-column').locator('input[type="checkbox"]').first();

    // Step 3: Configuration checkboxes
    this.includeArtifactsCheckbox = page.locator('label').filter({ hasText: /include artifacts/i }).locator('input');
    this.includeMetadataCheckbox = page.locator('label').filter({ hasText: /include.*metadata/i }).locator('input');
    this.includeUsersCheckbox = page.locator('label').filter({ hasText: /migrate users/i }).locator('input');
    this.includeGroupsCheckbox = page.locator('label').filter({ hasText: /migrate groups/i }).locator('input');
    this.includePermissionsCheckbox = page.locator('label').filter({ hasText: /migrate permissions/i }).locator('input');
    this.conflictResolutionSelect = page.locator('select').filter({ hasText: /skip|overwrite|rename/i });
    this.verifyChecksumsCheckbox = page.locator('label').filter({ hasText: /verify checksums/i }).locator('input');

    // Step 4: Review sections
    this.reviewSourceConnection = page.locator('h5').filter({ hasText: /source connection/i }).locator('..').locator('..');
    this.reviewRepositories = page.locator('h5').filter({ hasText: /repositories/i }).locator('..').locator('..');
    this.reviewConfiguration = page.locator('h5').filter({ hasText: /configuration/i }).locator('..').locator('..');

    // Step 5: Success
    this.successResult = page.locator('.ant-result-success');
    this.viewProgressButton = page.getByRole('button', { name: /view progress/i });
    this.newMigrationButton = page.getByRole('button', { name: /start new migration/i });
  }

  // === Step Navigation ===

  /**
   * Get the current step number (1-indexed)
   */
  async getCurrentStep(): Promise<number> {
    const stepItems = await this.page.locator('.ant-steps-item').all();
    for (let i = 0; i < stepItems.length; i++) {
      const className = await stepItems[i].getAttribute('class');
      if (className?.includes('ant-steps-item-active')) {
        return i + 1;
      }
    }
    return 1;
  }

  /**
   * Click Next button
   */
  async clickNext(): Promise<void> {
    await this.nextButton.click();
    await this.page.waitForTimeout(500); // Wait for step transition
  }

  /**
   * Click Back button
   */
  async clickBack(): Promise<void> {
    await this.backButton.click();
    await this.page.waitForTimeout(500);
  }

  /**
   * Click Cancel button
   */
  async clickCancel(): Promise<void> {
    await this.cancelButton.click();
  }

  /**
   * Click Start Migration button (on review step)
   */
  async clickStartMigration(): Promise<void> {
    await this.startMigrationButton.click();
  }

  // === Step 1: Source Connection ===

  /**
   * Fill the source connection form
   */
  async fillConnectionForm(config: {
    name?: string;
    url: string;
    username: string;
    password: string;
  }): Promise<void> {
    if (config.name) {
      await this.connectionNameInput.fill(config.name);
    }
    await this.sourceUrlInput.fill(config.url);
    await this.usernameInput.fill(config.username);
    await this.passwordInput.fill(config.password);
  }

  /**
   * Test the connection
   */
  async testConnection(): Promise<void> {
    await this.testConnectionButton.click();
  }

  /**
   * Expect connection success message
   */
  async expectConnectionSuccess(): Promise<void> {
    await this.expectSuccessToast(/connected|success|verified/i);
  }

  /**
   * Expect connection failure message
   */
  async expectConnectionFailure(): Promise<void> {
    await this.expectErrorToast(/failed|error|invalid/i);
  }

  // === Step 2: Repository Selection ===

  /**
   * Select all repositories
   */
  async selectAllRepositories(): Promise<void> {
    await this.selectAllCheckbox.check();
  }

  /**
   * Select specific repositories by name
   */
  async selectRepositories(repoNames: string[]): Promise<void> {
    for (const name of repoNames) {
      const row = this.repoTable.locator('tr').filter({ hasText: name });
      await row.locator('input[type="checkbox"]').check();
    }
  }

  /**
   * Get the count of selected repositories
   */
  async getSelectedRepoCount(): Promise<number> {
    const checkedBoxes = await this.repoTable.locator('input[type="checkbox"]:checked').all();
    return checkedBoxes.length;
  }

  /**
   * Search for repositories
   */
  async searchRepositories(query: string): Promise<void> {
    await this.repoSearchInput.fill(query);
    await this.page.waitForTimeout(300); // Debounce
  }

  // === Step 3: Configuration ===

  /**
   * Configure migration options
   */
  async configureOptions(options: {
    includeArtifacts?: boolean;
    includeMetadata?: boolean;
    includeUsers?: boolean;
    includeGroups?: boolean;
    includePermissions?: boolean;
    conflictResolution?: 'skip' | 'overwrite' | 'rename';
    verifyChecksums?: boolean;
  }): Promise<void> {
    if (options.includeArtifacts !== undefined) {
      if (options.includeArtifacts) {
        await this.includeArtifactsCheckbox.check();
      } else {
        await this.includeArtifactsCheckbox.uncheck();
      }
    }

    if (options.includeMetadata !== undefined) {
      if (options.includeMetadata) {
        await this.includeMetadataCheckbox.check();
      } else {
        await this.includeMetadataCheckbox.uncheck();
      }
    }

    if (options.includeUsers !== undefined) {
      if (options.includeUsers) {
        await this.includeUsersCheckbox.check();
      } else {
        await this.includeUsersCheckbox.uncheck();
      }
    }

    if (options.includeGroups !== undefined) {
      if (options.includeGroups) {
        await this.includeGroupsCheckbox.check();
      } else {
        await this.includeGroupsCheckbox.uncheck();
      }
    }

    if (options.includePermissions !== undefined) {
      if (options.includePermissions) {
        await this.includePermissionsCheckbox.check();
      } else {
        await this.includePermissionsCheckbox.uncheck();
      }
    }

    if (options.conflictResolution) {
      await this.conflictResolutionSelect.selectOption(options.conflictResolution);
    }

    if (options.verifyChecksums !== undefined) {
      if (options.verifyChecksums) {
        await this.verifyChecksumsCheckbox.check();
      } else {
        await this.verifyChecksumsCheckbox.uncheck();
      }
    }
  }

  // === Step 4: Review ===

  /**
   * Verify the review summary contains expected values
   */
  async expectReviewSummary(expectations: {
    connectionName?: string;
    repoCount?: number;
  }): Promise<void> {
    if (expectations.connectionName) {
      await expect(this.reviewSourceConnection).toContainText(expectations.connectionName);
    }
    if (expectations.repoCount !== undefined) {
      await expect(this.reviewRepositories).toContainText(`${expectations.repoCount}`);
    }
  }

  // === Step 5: Complete ===

  /**
   * Expect migration started successfully
   */
  async expectMigrationStarted(): Promise<void> {
    await expect(this.successResult).toBeVisible({ timeout: 15000 });
    await expect(this.page.getByText(/migration started/i)).toBeVisible();
  }

  /**
   * Click View Progress to return to jobs list
   */
  async clickViewProgress(): Promise<void> {
    await this.viewProgressButton.click();
  }

  // === Complete Wizard Flows ===

  /**
   * Complete a full migration wizard flow
   */
  async completeMigrationWizard(config: {
    connection: {
      name?: string;
      url: string;
      username: string;
      password: string;
    };
    selectAllRepos?: boolean;
    selectedRepos?: string[];
    options?: {
      includeArtifacts?: boolean;
      includeMetadata?: boolean;
      includeUsers?: boolean;
      includeGroups?: boolean;
      includePermissions?: boolean;
      conflictResolution?: 'skip' | 'overwrite' | 'rename';
      verifyChecksums?: boolean;
    };
  }): Promise<void> {
    // Step 1: Fill connection form
    await this.fillConnectionForm(config.connection);
    // Connection form auto-advances on success

    // Step 2: Select repositories
    if (config.selectAllRepos) {
      await this.selectAllRepositories();
    } else if (config.selectedRepos) {
      await this.selectRepositories(config.selectedRepos);
    }
    await this.clickNext();

    // Step 3: Configure options
    if (config.options) {
      await this.configureOptions(config.options);
    }
    await this.clickNext();

    // Step 4: Review and start
    await this.clickStartMigration();

    // Step 5: Verify success
    await this.expectMigrationStarted();
  }

  /**
   * Verify the wizard is closed/hidden
   */
  async expectWizardClosed(): Promise<void> {
    await expect(this.steps).toBeHidden({ timeout: 5000 });
  }
}
