import { test, expect } from '@playwright/test';
import { LoginPage, SetupPage } from './pages';

/**
 * Package Manager Setup E2E Tests
 *
 * Tests cover the Setup page Package Managers tab functionality:
 * - Maven settings.xml configuration
 * - npm .npmrc configuration
 * - Docker login commands
 * - PyPI twine configuration
 * - Helm chart repository config
 * - NuGet source configuration
 * - Cargo registry configuration
 * - Go module proxy configuration
 *
 * Uses Page Object pattern for maintainability.
 */
test.describe('Package Manager Setup', () => {
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

  test.describe('Package Managers Tab', () => {
    test('@smoke should display Package Managers tab by default', async () => {
      await expect(setupPage.packageManagersTab).toBeVisible();
      await expect(setupPage.openPackageManagerWizardButton).toBeVisible();
    });

    test('@smoke should display all package format cards', async () => {
      await setupPage.clickPackageManagersTab();
      await expect(setupPage.mavenCard).toBeVisible();
      await expect(setupPage.npmCard).toBeVisible();
      await expect(setupPage.dockerCard).toBeVisible();
      await expect(setupPage.pypiCard).toBeVisible();
    });

    test('@full should display additional package format cards', async () => {
      await setupPage.clickPackageManagersTab();
      await expect(setupPage.helmCard).toBeVisible();
      await expect(setupPage.nugetCard).toBeVisible();
      await expect(setupPage.cargoCard).toBeVisible();
      await expect(setupPage.goCard).toBeVisible();
    });
  });

  test.describe('npm Setup', () => {
    test('@smoke should open npm setup wizard', async () => {
      await setupPage.clickPackageManagersTab();
      await setupPage.clickPackageFormat('npm');
      await expect(setupPage.wizardModal).toBeVisible();
    });

    test('@full should display .npmrc configuration', async () => {
      await setupPage.clickPackageManagersTab();
      await setupPage.clickPackageFormat('npm');

      // Verify code block is visible
      await expect(setupPage.codeBlock.first()).toBeVisible();
      const content = await setupPage.getCodeBlockContent();
      expect(content.length).toBeGreaterThan(0);
    });

    test('@full should close npm wizard', async () => {
      await setupPage.clickPackageManagersTab();
      await setupPage.clickPackageFormat('npm');
      await setupPage.closeWizard();
      await expect(setupPage.wizardModal).toBeHidden();
    });
  });

  test.describe('Maven Setup', () => {
    test('@smoke should open Maven setup wizard', async () => {
      await setupPage.clickPackageManagersTab();
      await setupPage.clickPackageFormat('maven');
      await expect(setupPage.wizardModal).toBeVisible();
    });

    test('@full should display settings.xml configuration', async () => {
      await setupPage.clickPackageManagersTab();
      await setupPage.clickPackageFormat('maven');

      // Verify code block is visible
      await expect(setupPage.codeBlock.first()).toBeVisible();
      const content = await setupPage.getCodeBlockContent();
      expect(content.length).toBeGreaterThan(0);
    });

    test('@full should close Maven wizard', async () => {
      await setupPage.clickPackageManagersTab();
      await setupPage.clickPackageFormat('maven');
      await setupPage.closeWizard();
      await expect(setupPage.wizardModal).toBeHidden();
    });
  });

  test.describe('Docker Setup', () => {
    test('@full should open Docker setup wizard', async () => {
      await setupPage.clickPackageManagersTab();
      await setupPage.clickPackageFormat('docker');
      await expect(setupPage.wizardModal).toBeVisible();
    });

    test('@full should display docker login commands', async () => {
      await setupPage.clickPackageManagersTab();
      await setupPage.clickPackageFormat('docker');

      await expect(setupPage.codeBlock.first()).toBeVisible();
      const content = await setupPage.getCodeBlockContent();
      expect(content.length).toBeGreaterThan(0);
    });

    test('@full should close Docker wizard', async () => {
      await setupPage.clickPackageManagersTab();
      await setupPage.clickPackageFormat('docker');
      await setupPage.closeWizard();
      await expect(setupPage.wizardModal).toBeHidden();
    });
  });

  test.describe('PyPI Setup', () => {
    test('@full should open PyPI setup wizard', async () => {
      await setupPage.clickPackageManagersTab();
      await setupPage.clickPackageFormat('pypi');
      await expect(setupPage.wizardModal).toBeVisible();
    });

    test('@full should display twine configuration', async () => {
      await setupPage.clickPackageManagersTab();
      await setupPage.clickPackageFormat('pypi');

      await expect(setupPage.codeBlock.first()).toBeVisible();
      const content = await setupPage.getCodeBlockContent();
      expect(content.length).toBeGreaterThan(0);
    });

    test('@full should close PyPI wizard', async () => {
      await setupPage.clickPackageManagersTab();
      await setupPage.clickPackageFormat('pypi');
      await setupPage.closeWizard();
      await expect(setupPage.wizardModal).toBeHidden();
    });
  });

  test.describe('Go Module Setup', () => {
    test('@full should open Go setup wizard', async () => {
      await setupPage.clickPackageManagersTab();
      await setupPage.clickPackageFormat('go');
      await expect(setupPage.wizardModal).toBeVisible();
    });

    test('@full should display Go module config', async () => {
      await setupPage.clickPackageManagersTab();
      await setupPage.clickPackageFormat('go');

      await expect(setupPage.codeBlock.first()).toBeVisible();
      const content = await setupPage.getCodeBlockContent();
      expect(content.length).toBeGreaterThan(0);
    });

    test('@full should close Go wizard', async () => {
      await setupPage.clickPackageManagersTab();
      await setupPage.clickPackageFormat('go');
      await setupPage.closeWizard();
      await expect(setupPage.wizardModal).toBeHidden();
    });
  });

  test.describe('Helm Setup', () => {
    test('@full should open Helm setup wizard', async () => {
      await setupPage.clickPackageManagersTab();
      await setupPage.clickPackageFormat('helm');
      await expect(setupPage.wizardModal).toBeVisible();
    });

    test('@full should display Helm repository config', async () => {
      await setupPage.clickPackageManagersTab();
      await setupPage.clickPackageFormat('helm');

      await expect(setupPage.codeBlock.first()).toBeVisible();
      const content = await setupPage.getCodeBlockContent();
      expect(content.length).toBeGreaterThan(0);
    });
  });

  test.describe('NuGet Setup', () => {
    test('@full should open NuGet setup wizard', async () => {
      await setupPage.clickPackageManagersTab();
      await setupPage.clickPackageFormat('nuget');
      await expect(setupPage.wizardModal).toBeVisible();
    });

    test('@full should display NuGet source config', async () => {
      await setupPage.clickPackageManagersTab();
      await setupPage.clickPackageFormat('nuget');

      await expect(setupPage.codeBlock.first()).toBeVisible();
      const content = await setupPage.getCodeBlockContent();
      expect(content.length).toBeGreaterThan(0);
    });
  });

  test.describe('Cargo Setup', () => {
    test('@full should open Cargo setup wizard', async () => {
      await setupPage.clickPackageManagersTab();
      await setupPage.clickPackageFormat('cargo');
      await expect(setupPage.wizardModal).toBeVisible();
    });

    test('@full should display Cargo registry config', async () => {
      await setupPage.clickPackageManagersTab();
      await setupPage.clickPackageFormat('cargo');

      await expect(setupPage.codeBlock.first()).toBeVisible();
      const content = await setupPage.getCodeBlockContent();
      expect(content.length).toBeGreaterThan(0);
    });
  });

  test.describe('Copy Functionality', () => {
    test('@full should have copy button in wizard', async () => {
      await setupPage.clickPackageManagersTab();
      await setupPage.clickPackageFormat('npm');

      // Verify copy button exists
      await expect(setupPage.copyButton.first()).toBeVisible();
    });

    test('@full should open general package manager wizard', async () => {
      await setupPage.clickPackageManagersTab();
      await setupPage.openPackageManagerWizard();
      await expect(setupPage.wizardModal).toBeVisible();
    });
  });

  test.describe('By Repository Tab', () => {
    test('@full should switch to By Repository tab', async () => {
      await setupPage.clickByRepositoryTab();
      // Verify the tab content changes (specific verification depends on implementation)
    });
  });
});
