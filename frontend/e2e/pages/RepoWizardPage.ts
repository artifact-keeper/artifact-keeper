import { Page, Locator, expect } from '@playwright/test';
import { BasePage } from './BasePage';
import { RepoConfig } from '../fixtures/test-data';

/**
 * Page object for the Repository Creation Wizard.
 * Handles the multi-step wizard flow for creating repositories.
 */
export class RepoWizardPage extends BasePage {
  // Modal container
  readonly modal: Locator;
  readonly modalTitle: Locator;

  // Steps indicator
  readonly steps: Locator;
  readonly activeStep: Locator;

  // Navigation buttons
  readonly nextButton: Locator;
  readonly previousButton: Locator;
  readonly cancelButton: Locator;
  readonly createButton: Locator;

  // Step 1: Repository Type
  readonly repoTypeLocal: Locator;
  readonly repoTypeRemote: Locator;
  readonly repoTypeVirtual: Locator;

  // Step 2: Package Format
  readonly formatNpm: Locator;
  readonly formatMaven: Locator;
  readonly formatDocker: Locator;
  readonly formatPypi: Locator;
  readonly formatGeneric: Locator;
  readonly formatHelm: Locator;
  readonly formatGo: Locator;
  readonly formatCargo: Locator;

  // Step 3: Basic Config
  readonly keyInput: Locator;
  readonly nameInput: Locator;
  readonly descriptionInput: Locator;
  readonly isPublicCheckbox: Locator;

  // Step 4 (Remote): Remote Config
  readonly upstreamUrlInput: Locator;
  readonly proxySettingsSection: Locator;

  // Step 4 (Virtual): Virtual Config
  readonly repoSelector: Locator;
  readonly selectedReposList: Locator;

  // Step 5: Advanced Config
  readonly quotaInput: Locator;

  // Validation errors
  readonly validationError: Locator;

  constructor(page: Page) {
    super(page);

    // Modal - matches "Create New Repository" or "Edit Repository"
    this.modal = page.locator('.ant-modal').filter({
      has: page.locator('.ant-modal-title', { hasText: /repository/i }),
    });
    this.modalTitle = this.modal.locator('.ant-modal-title');

    // Steps
    this.steps = this.modal.locator('.ant-steps');
    this.activeStep = this.modal.locator('.ant-steps-item-active');

    // Navigation - Ant Design buttons with icons have accessible names including icon
    this.nextButton = this.modal.getByRole('button', { name: /next/i });
    this.previousButton = this.modal.getByRole('button', { name: /previous/i });
    this.cancelButton = this.modal.getByRole('button', { name: /cancel/i });
    // Create button: "Create Repository" or "Save Changes"
    this.createButton = this.modal.getByRole('button', {
      name: /create repository|save changes/i,
    });

    // Step 1: Repository Type selectors - Card components with titles
    this.repoTypeLocal = this.modal.locator('.ant-card').filter({
      hasText: /local repository/i,
    });
    this.repoTypeRemote = this.modal.locator('.ant-card').filter({
      hasText: /remote repository/i,
    });
    this.repoTypeVirtual = this.modal.locator('.ant-card').filter({
      hasText: /virtual repository/i,
    });

    // Step 2: Package Format selectors - Card components with format titles
    // Use locator that matches the card containing the format text (text is not exact, card may have other content)
    this.formatNpm = this.modal.locator('.ant-card').filter({ hasText: 'npm' }).first();
    this.formatMaven = this.modal.locator('.ant-card').filter({ hasText: 'Maven' }).first();
    this.formatDocker = this.modal.locator('.ant-card').filter({ hasText: 'Docker' }).first();
    this.formatPypi = this.modal.locator('.ant-card').filter({ hasText: 'PyPI' }).first();
    this.formatGeneric = this.modal.locator('.ant-card').filter({ hasText: 'Generic' }).first();
    this.formatHelm = this.modal.locator('.ant-card').filter({ hasText: 'Helm' }).first();
    this.formatGo = this.modal.locator('.ant-card').filter({ hasText: 'Go' }).first();
    this.formatCargo = this.modal.locator('.ant-card').filter({ hasText: 'Cargo' }).first();

    // Step 3: Basic Config
    this.keyInput = this.modal.locator('#key, [name="key"], input').filter({ hasText: '' }).first();
    this.nameInput = this.modal.locator('#name, [name="name"]');
    this.descriptionInput = this.modal.locator('#description, [name="description"], textarea');
    this.isPublicCheckbox = this.modal.getByLabel(/public/i);

    // Step 4 (Remote)
    this.upstreamUrlInput = this.modal.locator('#upstream_url, [name="upstream_url"]');
    this.proxySettingsSection = this.modal.locator('.proxy-settings');

    // Step 4 (Virtual)
    this.repoSelector = this.modal.locator('.ant-transfer, .repo-selector');
    this.selectedReposList = this.modal.locator('.selected-repos, .ant-transfer-list-content');

    // Step 5: Advanced
    this.quotaInput = this.modal.locator('#quota_bytes, [name="quota_bytes"]');

    // Validation
    this.validationError = this.modal.locator(
      '.ant-form-item-explain-error, .ant-message-error'
    );
  }

  /**
   * Check if wizard modal is open
   */
  async isOpen(): Promise<boolean> {
    return await this.isVisible(this.modal);
  }

  /**
   * Get current step number (1-based)
   */
  async getCurrentStep(): Promise<number> {
    const stepText = await this.activeStep.getAttribute('class');
    const match = stepText?.match(/ant-steps-item-(\d+)/);
    return match ? parseInt(match[1], 10) + 1 : 1;
  }

  // === Step Navigation ===

  /**
   * Click Next button to proceed to next step
   */
  async clickNext(): Promise<void> {
    await this.nextButton.click();
    await this.page.waitForTimeout(300); // Wait for step transition
  }

  /**
   * Click Previous button to go back to previous step
   */
  async clickPrevious(): Promise<void> {
    await this.previousButton.click();
    await this.page.waitForTimeout(300);
  }

  /**
   * Click Cancel button to close wizard
   */
  async clickCancel(): Promise<void> {
    await this.cancelButton.click();
  }

  /**
   * Click Create button to submit the wizard
   */
  async clickCreate(): Promise<void> {
    await this.createButton.click();
  }

  // === Step 1: Repository Type ===

  /**
   * Select repository type
   */
  async selectRepoType(type: 'local' | 'remote' | 'virtual'): Promise<void> {
    const typeLocators = {
      local: this.repoTypeLocal,
      remote: this.repoTypeRemote,
      virtual: this.repoTypeVirtual,
    };
    await typeLocators[type].click();
  }

  // === Step 2: Package Format ===

  /**
   * Select package format
   */
  async selectPackageFormat(
    format: 'npm' | 'maven' | 'docker' | 'pypi' | 'generic' | 'helm' | 'go' | 'cargo'
  ): Promise<void> {
    const formatLocators: Record<string, Locator> = {
      npm: this.formatNpm,
      maven: this.formatMaven,
      docker: this.formatDocker,
      pypi: this.formatPypi,
      generic: this.formatGeneric,
      helm: this.formatHelm,
      go: this.formatGo,
      cargo: this.formatCargo,
    };
    await formatLocators[format].click();
  }

  // === Step 3: Basic Config ===

  /**
   * Fill basic configuration fields
   * Labels from BasicConfigStep: "Repository Key", "Display Name", "Description", "Visibility"
   */
  async fillBasicConfig(config: {
    key: string;
    name: string;
    description?: string;
    isPublic?: boolean;
  }): Promise<void> {
    // Repository Key input - find by placeholder "my-repo" since label has icon
    const keyInput = this.modal.getByPlaceholder('my-repo');
    await keyInput.fill(config.key);

    // Display Name input - find by placeholder "My Repository"
    const nameInput = this.modal.getByPlaceholder('My Repository');
    await nameInput.fill(config.name);

    if (config.description) {
      // Description textarea - find by placeholder
      const descInput = this.modal.getByPlaceholder(/enter a description/i);
      await descInput.fill(config.description);
    }

    if (config.isPublic !== undefined) {
      // Visibility switch - locate by the switch role
      const switchLocator = this.modal.locator('.ant-switch');
      const isCurrentlyChecked = await switchLocator.getAttribute('aria-checked') === 'true';

      if (config.isPublic && !isCurrentlyChecked) {
        await switchLocator.click();
      } else if (!config.isPublic && isCurrentlyChecked) {
        await switchLocator.click();
      }
    }
  }

  // === Step 4 (Remote): Remote Config ===

  /**
   * Fill remote repository configuration
   * Form field has placeholder: "https://repo.maven.apache.org/maven2"
   */
  async fillRemoteConfig(config: { upstreamUrl: string }): Promise<void> {
    const urlInput = this.modal.getByPlaceholder('https://repo.maven.apache.org/maven2');
    await urlInput.fill(config.upstreamUrl);
  }

  // === Step 4 (Virtual): Virtual Config ===

  /**
   * Select repositories to include in virtual repo
   */
  async selectIncludedRepos(repoKeys: string[]): Promise<void> {
    for (const key of repoKeys) {
      const repoItem = this.modal.locator('.ant-transfer-list-content-item').filter({
        hasText: key,
      });
      await repoItem.click();
    }
    // Move selected to right
    const moveButton = this.modal.locator('.ant-transfer-operation button').first();
    await moveButton.click();
  }

  // === Step 5: Advanced Config ===

  /**
   * Fill advanced configuration
   */
  async fillAdvancedConfig(config: { quotaBytes?: number }): Promise<void> {
    if (config.quotaBytes !== undefined) {
      const quotaInput = this.modal.getByLabel(/quota/i);
      await quotaInput.fill(config.quotaBytes.toString());
    }
  }

  // === Complete Wizard Flows ===

  /**
   * Complete the entire wizard for a local repository
   */
  async completeLocalRepoWizard(config: RepoConfig): Promise<void> {
    // Step 1: Select local type
    await this.selectRepoType('local');
    await this.clickNext();

    // Step 2: Select format
    await this.selectPackageFormat(config.format);
    await this.clickNext();

    // Step 3: Basic config
    await this.fillBasicConfig({
      key: config.key,
      name: config.name,
      description: config.description,
      isPublic: config.isPublic,
    });
    await this.clickNext();

    // Step 4: Advanced (skip or fill)
    await this.clickCreate();
  }

  /**
   * Complete the entire wizard for a remote repository
   */
  async completeRemoteRepoWizard(
    config: RepoConfig & { upstreamUrl: string }
  ): Promise<void> {
    // Step 1: Select remote type
    await this.selectRepoType('remote');
    await this.clickNext();

    // Step 2: Select format
    await this.selectPackageFormat(config.format);
    await this.clickNext();

    // Step 3: Basic config
    await this.fillBasicConfig({
      key: config.key,
      name: config.name,
      description: config.description,
    });
    await this.clickNext();

    // Step 4: Remote config
    await this.fillRemoteConfig({ upstreamUrl: config.upstreamUrl });
    await this.clickNext();

    // Step 5: Advanced
    await this.clickCreate();
  }

  /**
   * Complete the entire wizard for a virtual repository
   */
  async completeVirtualRepoWizard(
    config: RepoConfig & { includedRepos: string[] }
  ): Promise<void> {
    // Step 1: Select virtual type
    await this.selectRepoType('virtual');
    await this.clickNext();

    // Step 2: Select format
    await this.selectPackageFormat(config.format);
    await this.clickNext();

    // Step 3: Basic config
    await this.fillBasicConfig({
      key: config.key,
      name: config.name,
      description: config.description,
    });
    await this.clickNext();

    // Step 4: Virtual config
    await this.selectIncludedRepos(config.includedRepos);
    await this.clickNext();

    // Step 5: Advanced
    await this.clickCreate();
  }

  // === Validation ===

  /**
   * Check if validation error is displayed
   */
  async hasValidationError(): Promise<boolean> {
    return await this.isVisible(this.validationError);
  }

  /**
   * Get validation error message
   */
  async getValidationError(): Promise<string> {
    return await this.getText(this.validationError);
  }

  /**
   * Assert wizard closed successfully
   */
  async expectWizardClosed(): Promise<void> {
    await expect(this.modal).toBeHidden();
  }

  /**
   * Assert success toast after creation
   */
  async expectCreationSuccess(): Promise<void> {
    await this.expectSuccessToast(/created successfully/i);
  }
}

export default RepoWizardPage;
