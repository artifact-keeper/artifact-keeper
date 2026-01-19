import { Page, Locator, expect } from '@playwright/test';
import { BasePage } from './BasePage';

/**
 * Page object for the Dashboard page.
 * Handles dashboard widgets and onboarding wizard.
 */
export class DashboardPage extends BasePage {
  // Dashboard widgets
  readonly welcomeWidget: Locator;
  readonly artifactCountWidget: Locator;
  readonly storageWidget: Locator;
  readonly recentActivityWidget: Locator;
  readonly quickActionsWidget: Locator;

  // Onboarding wizard
  readonly onboardingModal: Locator;
  readonly onboardingTitle: Locator;
  readonly onboardingNextButton: Locator;
  readonly onboardingSkipButton: Locator;
  readonly onboardingFinishButton: Locator;
  readonly onboardingSteps: Locator;

  // Empty state
  readonly emptyState: Locator;
  readonly createRepoButton: Locator;

  // Quick actions
  readonly uploadArtifactButton: Locator;
  readonly browseReposButton: Locator;

  constructor(page: Page) {
    super(page);

    // Widgets
    this.welcomeWidget = page.locator(
      '[data-testid="welcome-widget"], .welcome-widget, .dashboard-welcome'
    );
    this.artifactCountWidget = page.locator(
      '[data-testid="artifact-count-widget"], .artifact-count, .ant-statistic'
    ).filter({ hasText: /artifact/i });
    this.storageWidget = page.locator(
      '[data-testid="storage-widget"], .storage-widget'
    );
    this.recentActivityWidget = page.locator(
      '[data-testid="recent-activity-widget"], .recent-activity'
    );
    this.quickActionsWidget = page.locator(
      '[data-testid="quick-actions"], .quick-actions'
    );

    // Onboarding
    this.onboardingModal = page.locator(
      '[data-testid="onboarding-modal"], .onboarding-wizard, .ant-modal'
    ).filter({ hasText: /welcome|getting started|onboarding/i });
    this.onboardingTitle = this.onboardingModal.locator('.ant-modal-title, h2, h3');
    this.onboardingNextButton = this.onboardingModal.getByRole('button', {
      name: /next|continue/i,
    });
    this.onboardingSkipButton = this.onboardingModal.getByRole('button', {
      name: /skip|later/i,
    });
    this.onboardingFinishButton = this.onboardingModal.getByRole('button', {
      name: /finish|done|get started/i,
    });
    this.onboardingSteps = this.onboardingModal.locator('.ant-steps-item');

    // Empty state
    this.emptyState = page.locator(
      '[data-testid="empty-state"], .empty-state, .ant-empty'
    );
    this.createRepoButton = page.getByRole('button', {
      name: /create.*repo|new.*repo|get started/i,
    });

    // Quick actions
    this.uploadArtifactButton = page.getByRole('button', { name: /upload/i });
    this.browseReposButton = page.getByRole('button', { name: /browse|repositories/i });
  }

  /**
   * Navigate to the dashboard
   */
  async goto(): Promise<void> {
    await this.page.goto('/');
    await this.waitForPageLoad();
  }

  /**
   * Check if onboarding wizard is visible
   */
  async isOnboardingVisible(): Promise<boolean> {
    return await this.isVisible(this.onboardingModal);
  }

  /**
   * Complete the onboarding wizard
   */
  async completeOnboarding(): Promise<void> {
    // Click through all steps
    while (await this.isVisible(this.onboardingNextButton)) {
      await this.onboardingNextButton.click();
      await this.page.waitForTimeout(500); // Wait for animation
    }

    // Click finish button if visible
    if (await this.isVisible(this.onboardingFinishButton)) {
      await this.onboardingFinishButton.click();
    }

    // Wait for modal to close
    await this.waitForHidden(this.onboardingModal);
  }

  /**
   * Skip the onboarding wizard
   */
  async skipOnboarding(): Promise<void> {
    if (await this.isVisible(this.onboardingSkipButton)) {
      await this.onboardingSkipButton.click();
      await this.waitForHidden(this.onboardingModal);
    }
  }

  /**
   * Check if empty state is displayed
   */
  async isEmptyStateVisible(): Promise<boolean> {
    return await this.isVisible(this.emptyState);
  }

  /**
   * Get artifact count from widget
   */
  async getArtifactCount(): Promise<number> {
    const text = await this.getText(this.artifactCountWidget);
    const match = text.match(/(\d+)/);
    return match ? parseInt(match[1], 10) : 0;
  }

  /**
   * Refresh dashboard widgets
   */
  async refreshWidgets(): Promise<void> {
    const refreshButton = this.page.getByRole('button', { name: /refresh|reload/i });
    if (await this.isVisible(refreshButton)) {
      await refreshButton.click();
      await this.waitForPageLoad();
    } else {
      // Reload the page if no refresh button
      await this.page.reload();
      await this.waitForPageLoad();
    }
  }

  /**
   * Click create repository from empty state or quick actions
   */
  async clickCreateRepository(): Promise<void> {
    await this.createRepoButton.click();
  }

  /**
   * Assert dashboard is loaded with widgets
   */
  async expectDashboardLoaded(): Promise<void> {
    // Wait for at least one widget or the empty state
    const hasWidgets = await this.isVisible(this.artifactCountWidget);
    const hasEmpty = await this.isVisible(this.emptyState);
    expect(hasWidgets || hasEmpty).toBeTruthy();
  }

  /**
   * Assert onboarding was completed (modal not visible)
   */
  async expectOnboardingComplete(): Promise<void> {
    await expect(this.onboardingModal).toBeHidden();
  }
}

export default DashboardPage;
