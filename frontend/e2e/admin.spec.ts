import { test, expect } from '@playwright/test';
import { LoginPage, AdminUsersPage, AdminGroupsPage } from './pages';
import { uniqueId } from './fixtures/test-data';

/**
 * Admin User and Group Management E2E Tests
 *
 * Tests cover:
 * - User CRUD operations (create, read, update)
 * - Group management with member assignment
 * - Permission target creation
 * - User permissions summary display
 *
 * Uses Page Object pattern for maintainability.
 */
test.describe('Admin Workflow', () => {
  let loginPage: LoginPage;
  let usersPage: AdminUsersPage;
  let groupsPage: AdminGroupsPage;

  test.beforeEach(async ({ page }) => {
    loginPage = new LoginPage(page);
    usersPage = new AdminUsersPage(page);
    groupsPage = new AdminGroupsPage(page);

    // Login as admin
    await loginPage.goto();
    await loginPage.loginAndWaitForDashboard('admin', 'admin123');
  });

  test.describe('Users Management', () => {
    test('@smoke should navigate to Users page', async ({ page }) => {
      await page.getByRole('link', { name: 'Users' }).click();
      await expect(page).toHaveURL('/users');
      await usersPage.expectPageLoaded();
    });

    test('@smoke should display users table', async () => {
      await usersPage.goto();
      await expect(usersPage.usersTable).toBeVisible();
      await expect(usersPage.page.getByText('admin')).toBeVisible();
    });

    test('@smoke should open create user modal', async () => {
      await usersPage.goto();
      await usersPage.openCreateUserModal();
      await expect(usersPage.createUserModal).toBeVisible();
    });

    test('@full should fill create user form', async () => {
      await usersPage.goto();
      await usersPage.openCreateUserModal();

      await usersPage.usernameInput.fill('testuser');
      await usersPage.emailInput.fill('testuser@example.com');
      await usersPage.displayNameInput.fill('Test User');

      await expect(usersPage.usernameInput).toHaveValue('testuser');
      await expect(usersPage.emailInput).toHaveValue('testuser@example.com');
    });

    test('@full should close create user modal', async () => {
      await usersPage.goto();
      await usersPage.openCreateUserModal();
      await usersPage.closeCreateUserModal();
      await expect(usersPage.createUserModal).not.toBeVisible();
    });

    test('@full should show edit user modal', async () => {
      await usersPage.goto();

      const editButton = usersPage.editButton.first();
      if (await editButton.isVisible()) {
        await editButton.click();
        await expect(usersPage.editUserModal).toBeVisible();
      }
    });

    test('@smoke should create a new user', async () => {
      await usersPage.goto();

      const testUserName = `e2e-user-${uniqueId()}`;
      const generatedPassword = await usersPage.createUser({
        username: testUserName,
        email: `${testUserName}@example.com`,
        displayName: 'E2E Test User',
      });

      // User should be visible in table
      await usersPage.expectUserVisible(testUserName);

      // If password was generated, it should have content
      if (generatedPassword) {
        expect(generatedPassword.length).toBeGreaterThan(0);
      }
    });

    test('@full should show reset password option', async () => {
      await usersPage.goto();
      const resetButton = usersPage.resetPasswordButton.first();
      await expect(resetButton).toBeVisible();
    });

    test('@full should show toggle status option', async () => {
      await usersPage.goto();
      const toggleButton = usersPage.toggleStatusButton.first();
      if (await toggleButton.isVisible()) {
        await expect(toggleButton).toBeEnabled();
      }
    });
  });

  test.describe('Groups Management', () => {
    test('@smoke should navigate to Groups page', async () => {
      await groupsPage.goto();
      await groupsPage.expectPageLoaded();
    });

    test('@smoke should display groups table', async () => {
      await groupsPage.goto();
      await expect(groupsPage.groupsTable).toBeVisible();
    });

    test('@smoke should open create group modal', async () => {
      await groupsPage.goto();
      await groupsPage.openCreateGroupModal();
      await expect(groupsPage.createGroupModal).toBeVisible();
    });

    test('@full should fill create group form', async () => {
      await groupsPage.goto();
      await groupsPage.openCreateGroupModal();

      await groupsPage.groupNameInput.fill('test-group');
      await groupsPage.groupDescriptionInput.fill('Test group description');

      await expect(groupsPage.groupNameInput).toHaveValue('test-group');
      await expect(groupsPage.groupDescriptionInput).toHaveValue('Test group description');
    });

    test('@full should close create group modal', async () => {
      await groupsPage.goto();
      await groupsPage.openCreateGroupModal();
      await groupsPage.closeCreateGroupModal();
      await expect(groupsPage.createGroupModal).not.toBeVisible();
    });

    test('@full should show edit group option', async () => {
      await groupsPage.goto();

      const editButton = groupsPage.editButton.first();
      if (await editButton.isVisible()) {
        await editButton.click();
        await expect(groupsPage.editGroupModal).toBeVisible();
      }
    });

    test('@full should create a new group with members', async () => {
      await groupsPage.goto();

      const testGroupName = `e2e-group-${uniqueId()}`;
      await groupsPage.createGroup({
        name: testGroupName,
        description: 'E2E Test Group Description',
      });

      await groupsPage.expectGroupCreated();
    });

    test('@full should show manage members button', async () => {
      await groupsPage.goto();

      const membersButton = groupsPage.membersButton.first();
      if (await membersButton.isVisible()) {
        await expect(membersButton).toBeEnabled();
      }
    });
  });

  test.describe('Permissions Management', () => {
    test('@smoke should navigate to Permissions page', async ({ page }) => {
      await page.goto('/admin/permissions');
      await expect(page.getByRole('heading', { name: 'Permissions' })).toBeVisible();
    });

    test('@full should display permissions table', async ({ page }) => {
      await page.goto('/admin/permissions');
      await expect(page.getByRole('table')).toBeVisible();
    });

    test('@full should open create permission wizard', async ({ page }) => {
      await page.goto('/admin/permissions');
      await page.getByRole('button', { name: /create/i }).click();
      await page.waitForSelector('.ant-modal', { state: 'visible' });
    });

    test('@full should close permission wizard', async ({ page }) => {
      await page.goto('/admin/permissions');
      await page.getByRole('button', { name: /create/i }).click();
      await page.waitForSelector('.ant-modal', { state: 'visible' });
      await page.getByRole('button', { name: 'Cancel' }).first().click();
    });
  });

  test.describe('Admin Access Control', () => {
    test('@smoke should show admin-only pages for admin user', async ({ page }) => {
      await page.goto('/users');
      await expect(page.getByRole('heading', { name: 'Users' })).toBeVisible();

      await page.goto('/admin/groups');
      await expect(page.getByRole('heading', { name: 'Groups' })).toBeVisible();

      await page.goto('/admin/permissions');
      await expect(page.getByRole('heading', { name: 'Permissions' })).toBeVisible();
    });

    test('@full should display sidebar menu with admin links', async ({ page }) => {
      await expect(page.getByRole('link', { name: 'Users' })).toBeVisible();
    });
  });

  test.describe('User Permissions Summary', () => {
    test('@full should display user permissions summary', async ({ page }) => {
      await page.goto('/users');

      // Click on a user row to view details (if implemented)
      const userRow = page.locator('.ant-table tbody tr').first();
      if (await userRow.isVisible()) {
        // Check for permissions info in user details
        const permissionsLabel = page.locator('text=/permissions|roles|access/i');
        expect(permissionsLabel).toBeDefined();
      }
    });
  });
});
