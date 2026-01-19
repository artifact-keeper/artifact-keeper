import { type Page, type Locator, expect } from '@playwright/test';
import { BasePage } from './BasePage';

/**
 * Page Object for Search page
 * Path: /search
 *
 * Features:
 * - Quick search in header
 * - Advanced search page with tabs:
 *   - Package search
 *   - Property search
 *   - Checksum search
 *   - GAVC (Maven coordinates) search
 */
export class SearchPage extends BasePage {
  // Quick search (header)
  readonly quickSearchInput: Locator;
  readonly quickSearchDropdown: Locator;
  readonly quickSearchClearButton: Locator;

  // Advanced search page heading
  readonly advancedSearchHeading: Locator;

  // Search tabs
  readonly packageTab: Locator;
  readonly propertyTab: Locator;
  readonly checksumTab: Locator;
  readonly gavcTab: Locator;

  // Package search form
  readonly packageNameInput: Locator;
  readonly versionInput: Locator;
  readonly repositorySelect: Locator;
  readonly formatSelect: Locator;

  // Property search form
  readonly matchTypeSelect: Locator;
  readonly addPropertyFilterButton: Locator;
  readonly propertyKeyInput: Locator;
  readonly propertyValueInput: Locator;
  readonly removePropertyButton: Locator;

  // Checksum search form
  readonly checksumTypeSelect: Locator;
  readonly checksumInput: Locator;

  // GAVC search form
  readonly groupIdInput: Locator;
  readonly artifactIdInput: Locator;
  readonly gavcVersionInput: Locator;
  readonly classifierInput: Locator;

  // Search action
  readonly searchButton: Locator;
  readonly clearButton: Locator;

  // Results
  readonly resultsSection: Locator;
  readonly resultsTable: Locator;
  readonly noResultsMessage: Locator;

  constructor(page: Page) {
    super(page);

    // Quick search
    this.quickSearchInput = page.getByPlaceholder('Search artifacts...');
    this.quickSearchDropdown = page.locator('.ant-dropdown, .ant-select-dropdown').filter({ hasText: /search|results/i });
    this.quickSearchClearButton = page.locator('.ant-input-clear-icon').first();

    // Advanced search heading
    this.advancedSearchHeading = page.getByRole('heading', { name: 'Advanced Search' });

    // Search tabs
    this.packageTab = page.getByRole('tab', { name: 'Package' });
    this.propertyTab = page.getByRole('tab', { name: 'Property' });
    this.checksumTab = page.getByRole('tab', { name: 'Checksum' });
    this.gavcTab = page.getByRole('tab', { name: 'GAVC' });

    // Package search
    this.packageNameInput = page.getByPlaceholder('Enter package name (supports wildcards)');
    this.versionInput = page.getByPlaceholder(/Enter version/);
    this.repositorySelect = page.locator('.ant-select').filter({ hasText: /repository/i });
    this.formatSelect = page.locator('.ant-select').filter({ hasText: /format/i });

    // Property search
    this.matchTypeSelect = page.locator('.ant-select').filter({ hasText: /exact|contains|wildcard/i });
    this.addPropertyFilterButton = page.getByRole('button', { name: 'Add Property Filter' });
    this.propertyKeyInput = page.getByPlaceholder('Property key');
    this.propertyValueInput = page.getByPlaceholder('Property value');
    this.removePropertyButton = page.locator('[aria-label="minus-circle"]');

    // Checksum search
    this.checksumTypeSelect = page.locator('.ant-select').filter({ hasText: /md5|sha/i });
    this.checksumInput = page.getByPlaceholder(/checksum|hash/i);

    // GAVC search
    this.groupIdInput = page.locator('input').filter({ has: page.locator('text=Group ID') });
    this.artifactIdInput = page.locator('input').filter({ has: page.locator('text=Artifact ID') });
    this.gavcVersionInput = page.locator('input').filter({ has: page.locator('text=Version') }).last();
    this.classifierInput = page.locator('input').filter({ has: page.locator('text=Classifier') });

    // Search actions
    this.searchButton = page.getByRole('button', { name: /search/i });
    this.clearButton = page.getByRole('button', { name: /clear|reset/i });

    // Results
    this.resultsSection = page.locator('.search-results, .ant-card').filter({ hasText: /results|found/i });
    this.resultsTable = page.locator('.ant-table');
    this.noResultsMessage = page.locator('.ant-empty, .no-results').filter({ hasText: /no.*results|nothing.*found/i });
  }

  /**
   * Navigate to the advanced search page
   */
  async goto(): Promise<void> {
    await this.page.goto('/search');
    await this.waitForPageReady();
  }

  /**
   * Wait for page to be fully loaded
   */
  async waitForPageReady(): Promise<void> {
    await this.advancedSearchHeading.waitFor({ state: 'visible' });
  }

  /**
   * Assert page is loaded
   */
  async expectPageLoaded(): Promise<void> {
    await expect(this.advancedSearchHeading).toBeVisible();
    await expect(this.searchButton).toBeVisible();
  }

  // === Quick Search ===

  /**
   * Perform quick search from header
   */
  async quickSearch(query: string): Promise<void> {
    await this.quickSearchInput.fill(query);
    await this.page.waitForTimeout(500); // Wait for dropdown
  }

  /**
   * Submit quick search (press Enter)
   */
  async submitQuickSearch(query: string): Promise<void> {
    await this.quickSearchInput.fill(query);
    await this.quickSearchInput.press('Enter');
  }

  /**
   * Clear quick search
   */
  async clearQuickSearch(): Promise<void> {
    await this.quickSearchClearButton.click();
  }

  // === Tab Navigation ===

  /**
   * Click Package search tab
   */
  async clickPackageTab(): Promise<void> {
    await this.packageTab.click();
  }

  /**
   * Click Property search tab
   */
  async clickPropertyTab(): Promise<void> {
    await this.propertyTab.click();
  }

  /**
   * Click Checksum search tab
   */
  async clickChecksumTab(): Promise<void> {
    await this.checksumTab.click();
  }

  /**
   * Click GAVC search tab
   */
  async clickGavcTab(): Promise<void> {
    await this.gavcTab.click();
  }

  // === Package Search ===

  /**
   * Perform package search
   */
  async searchPackage(options: {
    name?: string;
    version?: string;
    repository?: string;
    format?: string;
  }): Promise<void> {
    await this.clickPackageTab();

    if (options.name) {
      await this.packageNameInput.fill(options.name);
    }
    if (options.version) {
      await this.versionInput.fill(options.version);
    }
    if (options.repository) {
      await this.repositorySelect.click();
      await this.page.getByText(options.repository).click();
    }
    if (options.format) {
      await this.formatSelect.click();
      await this.page.getByText(options.format).click();
    }

    await this.searchButton.click();
  }

  // === Property Search ===

  /**
   * Add a property filter
   */
  async addPropertyFilter(key: string, value: string): Promise<void> {
    await this.clickPropertyTab();
    await this.addPropertyFilterButton.click();
    await this.propertyKeyInput.fill(key);
    await this.propertyValueInput.fill(value);
  }

  /**
   * Perform property search
   */
  async searchByProperty(properties: { key: string; value: string }[]): Promise<void> {
    await this.clickPropertyTab();

    for (const prop of properties) {
      await this.addPropertyFilterButton.click();
      await this.propertyKeyInput.last().fill(prop.key);
      await this.propertyValueInput.last().fill(prop.value);
    }

    await this.searchButton.click();
  }

  // === Checksum Search ===

  /**
   * Search by checksum
   */
  async searchByChecksum(checksum: string, type?: 'MD5' | 'SHA1' | 'SHA256'): Promise<void> {
    await this.clickChecksumTab();

    if (type) {
      await this.checksumTypeSelect.click();
      await this.page.getByText(type).click();
    }

    await this.checksumInput.fill(checksum);
    await this.searchButton.click();
  }

  // === GAVC Search ===

  /**
   * Search by Maven coordinates (GAVC)
   */
  async searchByGavc(options: {
    groupId?: string;
    artifactId?: string;
    version?: string;
    classifier?: string;
  }): Promise<void> {
    await this.clickGavcTab();

    // Fill GAVC fields using labels
    if (options.groupId) {
      await this.page.locator('label').filter({ hasText: 'Group ID' }).locator('..').locator('input').fill(options.groupId);
    }
    if (options.artifactId) {
      await this.page.locator('label').filter({ hasText: 'Artifact ID' }).locator('..').locator('input').fill(options.artifactId);
    }
    if (options.version) {
      await this.page.locator('label').filter({ hasText: 'Version' }).locator('..').locator('input').fill(options.version);
    }
    if (options.classifier) {
      await this.page.locator('label').filter({ hasText: 'Classifier' }).locator('..').locator('input').fill(options.classifier);
    }

    await this.searchButton.click();
  }

  // === Results ===

  /**
   * Get search result count
   */
  async getResultCount(): Promise<number> {
    const rows = await this.resultsTable.locator('tbody tr').all();
    return rows.length;
  }

  /**
   * Check if no results message is shown
   */
  async hasNoResults(): Promise<boolean> {
    return await this.noResultsMessage.isVisible().catch(() => false);
  }

  // === Assertions ===

  /**
   * Expect search tabs to be visible
   */
  async expectSearchTabsVisible(): Promise<void> {
    await expect(this.packageTab).toBeVisible();
    await expect(this.propertyTab).toBeVisible();
    await expect(this.checksumTab).toBeVisible();
    await expect(this.gavcTab).toBeVisible();
  }

  /**
   * Expect quick search dropdown visible
   */
  async expectQuickSearchDropdownVisible(): Promise<void> {
    await expect(this.quickSearchDropdown).toBeVisible();
  }

  /**
   * Expect empty results state
   */
  async expectEmptyResults(): Promise<void> {
    await expect(this.noResultsMessage).toBeVisible();
  }
}
