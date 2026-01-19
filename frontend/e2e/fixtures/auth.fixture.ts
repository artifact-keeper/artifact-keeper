import { test as base, Page, BrowserContext } from '@playwright/test';
import { TEST_CREDENTIALS } from './test-data';
import { CleanupUtility } from './cleanup';

/**
 * Auth fixture that provides pre-authenticated page contexts.
 */
export interface AuthFixture {
  /** Page logged in as admin user */
  adminPage: Page;
  /** Page logged in as regular user */
  userPage: Page;
  /** Login helper function */
  login: (page: Page, role: 'admin' | 'user') => Promise<void>;
  /** Logout helper function */
  logout: (page: Page) => Promise<void>;
  /** Cleanup utility for test resources */
  cleanup: CleanupUtility;
}

/**
 * Login to the application with the given credentials
 */
async function loginWithCredentials(
  page: Page,
  username: string,
  password: string
): Promise<void> {
  await page.goto('/login');
  await page.getByPlaceholder('Username').fill(username);
  await page.getByPlaceholder('Password').fill(password);
  await page.getByRole('button', { name: /log in/i }).click();

  // Wait for redirect to dashboard
  await page.waitForURL(/\/(dashboard)?$/);
}

/**
 * Logout from the application
 */
async function logoutFromApp(page: Page): Promise<void> {
  // Click user menu and logout
  await page.getByRole('button', { name: /user|profile|account/i }).click();
  await page.getByRole('menuitem', { name: /log ?out|sign ?out/i }).click();

  // Wait for redirect to login
  await page.waitForURL(/\/login/);
}

/**
 * Create authenticated page context
 */
async function createAuthenticatedPage(
  context: BrowserContext,
  role: 'admin' | 'user'
): Promise<Page> {
  const page = await context.newPage();
  const credentials = TEST_CREDENTIALS[role];
  await loginWithCredentials(page, credentials.username, credentials.password);
  return page;
}

/**
 * Extended test fixture with authentication helpers
 */
export const test = base.extend<AuthFixture>({
  adminPage: async ({ browser }, use) => {
    const context = await browser.newContext();
    const page = await context.newPage();
    await loginWithCredentials(
      page,
      TEST_CREDENTIALS.admin.username,
      TEST_CREDENTIALS.admin.password
    );
    await use(page);
    await context.close();
  },

  userPage: async ({ browser }, use) => {
    const context = await browser.newContext();
    const page = await context.newPage();
    await loginWithCredentials(
      page,
      TEST_CREDENTIALS.user.username,
      TEST_CREDENTIALS.user.password
    );
    await use(page);
    await context.close();
  },

  login: async ({}, use) => {
    const loginFn = async (page: Page, role: 'admin' | 'user') => {
      const credentials = TEST_CREDENTIALS[role];
      await loginWithCredentials(page, credentials.username, credentials.password);
    };
    await use(loginFn);
  },

  logout: async ({}, use) => {
    await use(logoutFromApp);
  },

  cleanup: async ({ request }, use) => {
    const cleanupUtil = new CleanupUtility(request);
    await use(cleanupUtil);
    // Clean up after test
    await cleanupUtil.cleanup();
  },
});

export { expect } from '@playwright/test';

/**
 * Helper to quickly login in beforeEach hooks
 */
export async function quickLogin(
  page: Page,
  role: 'admin' | 'user' = 'admin'
): Promise<void> {
  const credentials = TEST_CREDENTIALS[role];
  await page.goto('/login');
  await page.getByPlaceholder('Username').fill(credentials.username);
  await page.getByPlaceholder('Password').fill(credentials.password);
  await page.getByRole('button', { name: /log in/i }).click();
  await page.waitForURL(/\/(dashboard)?$/);
}

export default test;
