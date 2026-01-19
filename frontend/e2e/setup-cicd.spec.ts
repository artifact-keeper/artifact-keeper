import { test, expect } from '@playwright/test';
import { LoginPage, SetupPage } from './pages';

/**
 * CI/CD Platform Setup E2E Tests
 *
 * Tests cover the Setup page CI/CD Platforms tab functionality:
 * - GitHub Actions configuration wizard
 * - GitLab CI configuration wizard
 * - Jenkins configuration wizard
 * - Azure DevOps configuration wizard
 *
 * Uses Page Object pattern for maintainability.
 */
test.describe('CI/CD Platform Setup', () => {
  let loginPage: LoginPage;
  let setupPage: SetupPage;

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);
    setupPage = new SetupPage(page);

    // Login and navigate to setup page
    await loginPage.goto();
    await loginPage.loginAndWaitForDashboard('admin', 'admin123');
    await setupPage.goto();
  });

  test.describe('Setup Page Navigation', () => {
    test('@smoke should navigate to setup page', async ({ page }) => {
      await setupPage.expectPageLoaded();
      await expect(page).toHaveURL('/setup');
    });

    test('@smoke should display all tabs', async () => {
      await expect(setupPage.packageManagersTab).toBeVisible();
      await expect(setupPage.cicdPlatformsTab).toBeVisible();
      await expect(setupPage.byRepositoryTab).toBeVisible();
    });

    test('@smoke should switch to CI/CD Platforms tab', async () => {
      await setupPage.clickCICDPlatformsTab();
      await expect(setupPage.openCICDWizardButton).toBeVisible();
    });
  });

  test.describe('CI/CD Platform Cards', () => {
    test.beforeEach(async () => {
      await setupPage.clickCICDPlatformsTab();
    });

    test('@smoke should display all CI/CD platform cards', async () => {
      await expect(setupPage.githubActionsCard).toBeVisible();
      await expect(setupPage.gitlabCICard).toBeVisible();
      await expect(setupPage.jenkinsCard).toBeVisible();
      await expect(setupPage.azureDevOpsCard).toBeVisible();
    });

    test('@full should open GitHub Actions wizard', async () => {
      await setupPage.clickCICDPlatform('github');
      await expect(setupPage.wizardModal).toBeVisible();
    });

    test('@full should open GitLab CI wizard', async () => {
      await setupPage.clickCICDPlatform('gitlab');
      await expect(setupPage.wizardModal).toBeVisible();
    });

    test('@full should open Jenkins wizard', async () => {
      await setupPage.clickCICDPlatform('jenkins');
      await expect(setupPage.wizardModal).toBeVisible();
    });

    test('@full should open Azure DevOps wizard', async () => {
      await setupPage.clickCICDPlatform('azure');
      await expect(setupPage.wizardModal).toBeVisible();
    });
  });

  test.describe('GitHub Actions Wizard', () => {
    test.beforeEach(async () => {
      await setupPage.clickCICDPlatformsTab();
      await setupPage.clickCICDPlatform('github');
    });

    test('@full should display GitHub Actions code block', async () => {
      await expect(setupPage.codeBlock.first()).toBeVisible();
      // GitHub Actions workflow should contain typical YAML structure
      const content = await setupPage.getCodeBlockContent();
      expect(content.length).toBeGreaterThan(0);
    });

    test('@full should have copy functionality', async () => {
      // Verify copy button exists
      await expect(setupPage.copyButton.first()).toBeVisible();
    });

    test('@full should close wizard', async () => {
      await setupPage.closeWizard();
      await expect(setupPage.wizardModal).toBeHidden();
    });
  });

  test.describe('GitLab CI Wizard', () => {
    test.beforeEach(async () => {
      await setupPage.clickCICDPlatformsTab();
      await setupPage.clickCICDPlatform('gitlab');
    });

    test('@full should display GitLab CI code block', async () => {
      await expect(setupPage.codeBlock.first()).toBeVisible();
      const content = await setupPage.getCodeBlockContent();
      expect(content.length).toBeGreaterThan(0);
    });

    test('@full should close wizard', async () => {
      await setupPage.closeWizard();
      await expect(setupPage.wizardModal).toBeHidden();
    });
  });

  test.describe('Jenkins Wizard', () => {
    test.beforeEach(async () => {
      await setupPage.clickCICDPlatformsTab();
      await setupPage.clickCICDPlatform('jenkins');
    });

    test('@full should display Jenkins code block', async () => {
      await expect(setupPage.codeBlock.first()).toBeVisible();
      const content = await setupPage.getCodeBlockContent();
      expect(content.length).toBeGreaterThan(0);
    });

    test('@full should close wizard', async () => {
      await setupPage.closeWizard();
      await expect(setupPage.wizardModal).toBeHidden();
    });
  });

  test.describe('Azure DevOps Wizard', () => {
    test.beforeEach(async () => {
      await setupPage.clickCICDPlatformsTab();
      await setupPage.clickCICDPlatform('azure');
    });

    test('@full should display Azure DevOps code block', async () => {
      await expect(setupPage.codeBlock.first()).toBeVisible();
      const content = await setupPage.getCodeBlockContent();
      expect(content.length).toBeGreaterThan(0);
    });

    test('@full should close wizard', async () => {
      await setupPage.closeWizard();
      await expect(setupPage.wizardModal).toBeHidden();
    });
  });

  test.describe('Open CI/CD Wizard Button', () => {
    test('@full should open general CI/CD wizard', async () => {
      await setupPage.clickCICDPlatformsTab();
      await setupPage.openCICDWizard();
      await expect(setupPage.wizardModal).toBeVisible();
    });
  });
});
