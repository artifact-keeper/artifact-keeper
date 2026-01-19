import { type Page, type Locator, expect } from '@playwright/test';
import { BasePage } from './BasePage';

/**
 * Page Object for the Set Me Up / Setup page
 * Path: /setup
 *
 * Features:
 * - Package Managers tab with format-specific configurations
 * - CI/CD Platforms tab with GitHub Actions, GitLab CI, Jenkins, Azure DevOps
 * - By Repository tab with repository-specific configurations
 * - Setup wizard triggers for both package managers and CI/CD
 */
export class SetupPage extends BasePage {
  // Page heading
  readonly heading: Locator;

  // Tabs
  readonly packageManagersTab: Locator;
  readonly cicdPlatformsTab: Locator;
  readonly byRepositoryTab: Locator;

  // Package Managers tab
  readonly openPackageManagerWizardButton: Locator;
  readonly mavenCard: Locator;
  readonly npmCard: Locator;
  readonly dockerCard: Locator;
  readonly pypiCard: Locator;
  readonly helmCard: Locator;
  readonly nugetCard: Locator;
  readonly cargoCard: Locator;
  readonly goCard: Locator;

  // CI/CD Platforms tab
  readonly openCICDWizardButton: Locator;
  readonly githubActionsCard: Locator;
  readonly gitlabCICard: Locator;
  readonly jenkinsCard: Locator;
  readonly azureDevOpsCard: Locator;

  // Wizard modals (shared between package manager and CI/CD wizards)
  readonly wizardModal: Locator;
  readonly codeBlock: Locator;
  readonly copyButton: Locator;

  constructor(page: Page) {
    super(page);

    // Page heading
    this.heading = page.getByRole('heading', { name: /set me up/i });

    // Tabs
    this.packageManagersTab = page.getByRole('tab', { name: /package managers/i });
    this.cicdPlatformsTab = page.getByRole('tab', { name: /ci\/cd platforms/i });
    this.byRepositoryTab = page.getByRole('tab', { name: /by repository/i });

    // Package Managers section
    this.openPackageManagerWizardButton = page.getByRole('button', { name: /open setup wizard/i });
    this.mavenCard = page.locator('.ant-card').filter({ hasText: 'Maven' });
    this.npmCard = page.locator('.ant-card').filter({ hasText: 'npm' });
    this.dockerCard = page.locator('.ant-card').filter({ hasText: 'Docker' });
    this.pypiCard = page.locator('.ant-card').filter({ hasText: 'PyPI' });
    this.helmCard = page.locator('.ant-card').filter({ hasText: 'Helm' });
    this.nugetCard = page.locator('.ant-card').filter({ hasText: 'NuGet' });
    this.cargoCard = page.locator('.ant-card').filter({ hasText: 'Cargo' });
    this.goCard = page.locator('.ant-card').filter({ hasText: /^Go$/ });

    // CI/CD Platforms section
    this.openCICDWizardButton = page.getByRole('button', { name: /open ci\/cd wizard/i });
    this.githubActionsCard = page.locator('.ant-card').filter({ hasText: 'GitHub Actions' });
    this.gitlabCICard = page.locator('.ant-card').filter({ hasText: 'GitLab CI' });
    this.jenkinsCard = page.locator('.ant-card').filter({ hasText: 'Jenkins' });
    this.azureDevOpsCard = page.locator('.ant-card').filter({ hasText: 'Azure DevOps' });

    // Wizard modals - code blocks and copy functionality
    this.wizardModal = page.locator('.ant-modal, .ant-drawer');
    this.codeBlock = page.locator('pre, code, .code-block');
    this.copyButton = page.getByRole('button', { name: /copy/i });
  }

  /**
   * Navigate to the Setup page
   */
  async goto(): Promise<void> {
    await this.page.goto('/setup');
    await this.waitForPageReady();
  }

  /**
   * Wait for the page to be fully loaded
   */
  async waitForPageReady(): Promise<void> {
    await this.heading.waitFor({ state: 'visible' });
    await this.packageManagersTab.waitFor({ state: 'visible' });
  }

  /**
   * Assert that the page is loaded
   */
  async expectPageLoaded(): Promise<void> {
    await expect(this.heading).toBeVisible();
    await expect(this.packageManagersTab).toBeVisible();
  }

  // === Tab Navigation ===

  /**
   * Click on Package Managers tab
   */
  async clickPackageManagersTab(): Promise<void> {
    await this.packageManagersTab.click();
    await this.openPackageManagerWizardButton.waitFor({ state: 'visible' });
  }

  /**
   * Click on CI/CD Platforms tab
   */
  async clickCICDPlatformsTab(): Promise<void> {
    await this.cicdPlatformsTab.click();
    await this.openCICDWizardButton.waitFor({ state: 'visible' });
  }

  /**
   * Click on By Repository tab
   */
  async clickByRepositoryTab(): Promise<void> {
    await this.byRepositoryTab.click();
  }

  // === Package Manager Wizards ===

  /**
   * Open the Package Manager setup wizard
   */
  async openPackageManagerWizard(): Promise<void> {
    await this.openPackageManagerWizardButton.click();
    await this.wizardModal.waitFor({ state: 'visible' });
  }

  /**
   * Click on a specific package format card
   */
  async clickPackageFormat(format: 'maven' | 'npm' | 'docker' | 'pypi' | 'helm' | 'nuget' | 'cargo' | 'go'): Promise<void> {
    const cardMap = {
      maven: this.mavenCard,
      npm: this.npmCard,
      docker: this.dockerCard,
      pypi: this.pypiCard,
      helm: this.helmCard,
      nuget: this.nugetCard,
      cargo: this.cargoCard,
      go: this.goCard,
    };
    await cardMap[format].click();
    await this.wizardModal.waitFor({ state: 'visible' });
  }

  // === CI/CD Platform Wizards ===

  /**
   * Open the CI/CD Platform setup wizard
   */
  async openCICDWizard(): Promise<void> {
    await this.openCICDWizardButton.click();
    await this.wizardModal.waitFor({ state: 'visible' });
  }

  /**
   * Click on a specific CI/CD platform card
   */
  async clickCICDPlatform(platform: 'github' | 'gitlab' | 'jenkins' | 'azure'): Promise<void> {
    const cardMap = {
      github: this.githubActionsCard,
      gitlab: this.gitlabCICard,
      jenkins: this.jenkinsCard,
      azure: this.azureDevOpsCard,
    };
    await cardMap[platform].click();
    await this.wizardModal.waitFor({ state: 'visible' });
  }

  // === Code Blocks and Copy ===

  /**
   * Get the content of the first visible code block
   */
  async getCodeBlockContent(): Promise<string> {
    const visibleCode = this.codeBlock.first();
    return await visibleCode.textContent() || '';
  }

  /**
   * Click the copy button and verify success toast
   */
  async copyCode(): Promise<void> {
    await this.copyButton.first().click();
    await this.expectSuccessToast(/copied/i);
  }

  /**
   * Verify that code contains expected content
   */
  async expectCodeContains(text: string): Promise<void> {
    const content = await this.getCodeBlockContent();
    expect(content.toLowerCase()).toContain(text.toLowerCase());
  }

  /**
   * Close the wizard modal
   */
  async closeWizard(): Promise<void> {
    // Try close button or click outside
    const closeButton = this.page.locator('.ant-modal-close, .ant-drawer-close').first();
    if (await closeButton.isVisible()) {
      await closeButton.click();
    }
    await this.wizardModal.waitFor({ state: 'hidden', timeout: 5000 });
  }

  // === Repository Selection ===

  /**
   * Click on a repository card in the "By Repository" tab
   */
  async clickRepository(repoName: string): Promise<void> {
    const repoCard = this.page.locator('.ant-card').filter({ hasText: repoName });
    await repoCard.click();
    await this.wizardModal.waitFor({ state: 'visible' });
  }
}
