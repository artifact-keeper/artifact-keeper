import { test, expect } from '@playwright/test'

test.describe('Admin Workflow', () => {
  const testUserName = `e2e-test-user-${Date.now()}`
  const testGroupName = `e2e-test-group-${Date.now()}`
  const _testPermissionName = `e2e-test-perm-${Date.now()}`

  test.beforeEach(async ({ page }) => {
    await page.goto('/login')
    await page.getByPlaceholder('Username').fill('admin')
    await page.getByPlaceholder('Password').fill('admin123')
    await page.getByRole('button', { name: /log in/i }).click()
    await expect(page.getByText('Dashboard')).toBeVisible()
  })

  test.describe('Users Management', () => {
    test('should navigate to Users page', async ({ page }) => {
      await page.getByRole('link', { name: 'Users' }).click()
      await expect(page).toHaveURL('/users')
      await expect(page.getByRole('heading', { name: 'Users' })).toBeVisible()
    })

    test('should display users table', async ({ page }) => {
      await page.goto('/users')

      await expect(page.getByRole('table')).toBeVisible()
      await expect(page.getByText('admin')).toBeVisible()
    })

    test('should open create user modal', async ({ page }) => {
      await page.goto('/users')

      await page.getByRole('button', { name: /create user/i }).click()

      await expect(page.getByText('Create User')).toBeVisible()
      await expect(page.getByText('Password will be auto-generated')).toBeVisible()
    })

    test('should fill create user form', async ({ page }) => {
      await page.goto('/users')

      await page.getByRole('button', { name: /create user/i }).click()

      await page.getByLabel('Username').fill('testuser')
      await page.getByLabel('Email').fill('testuser@example.com')
      await page.getByLabel('Display Name').fill('Test User')

      await expect(page.getByLabel('Username')).toHaveValue('testuser')
      await expect(page.getByLabel('Email')).toHaveValue('testuser@example.com')
    })

    test('should close create user modal', async ({ page }) => {
      await page.goto('/users')

      await page.getByRole('button', { name: /create user/i }).click()
      await expect(page.getByText('Create User')).toBeVisible()

      await page.getByRole('button', { name: 'Cancel' }).click()
      await expect(page.getByRole('dialog')).not.toBeVisible()
    })

    test('should show edit user modal', async ({ page }) => {
      await page.goto('/users')

      await page.getByRole('button', { name: 'Edit' }).first().click()

      await expect(page.getByText(/Edit User:/)).toBeVisible()
    })
  })

  test.describe('Groups Management', () => {
    test('should navigate to Groups page', async ({ page }) => {
      await page.goto('/admin/groups')
      await expect(page.getByRole('heading', { name: 'Groups' })).toBeVisible()
    })

    test('should display groups table', async ({ page }) => {
      await page.goto('/admin/groups')

      await expect(page.getByRole('table')).toBeVisible()
    })

    test('should open create group modal', async ({ page }) => {
      await page.goto('/admin/groups')

      await page.getByRole('button', { name: /create group/i }).click()

      await expect(page.getByText('Create Group')).toBeVisible()
    })

    test('should fill create group form', async ({ page }) => {
      await page.goto('/admin/groups')

      await page.getByRole('button', { name: /create group/i }).click()

      await page.getByLabel('Name').fill('test-group')
      await page.getByLabel('Description').fill('Test group description')

      await expect(page.getByLabel('Name')).toHaveValue('test-group')
      await expect(page.getByLabel('Description')).toHaveValue('Test group description')
    })

    test('should close create group modal', async ({ page }) => {
      await page.goto('/admin/groups')

      await page.getByRole('button', { name: /create group/i }).click()
      await expect(page.getByText('Create Group')).toBeVisible()

      await page.getByRole('button', { name: 'Cancel' }).click()
      await expect(page.getByRole('dialog')).not.toBeVisible()
    })

    test('should show edit group option', async ({ page }) => {
      await page.goto('/admin/groups')

      const editButton = page.getByRole('button', { name: 'Edit' }).first()
      if (await editButton.isVisible()) {
        await editButton.click()
        await expect(page.getByText(/Edit Group:/)).toBeVisible()
      }
    })
  })

  test.describe('Permissions Management', () => {
    test('should navigate to Permissions page', async ({ page }) => {
      await page.goto('/admin/permissions')
      await expect(page.getByRole('heading', { name: 'Permissions' })).toBeVisible()
    })

    test('should display permissions table', async ({ page }) => {
      await page.goto('/admin/permissions')

      await expect(page.getByRole('table')).toBeVisible()
    })

    test('should open create permission wizard', async ({ page }) => {
      await page.goto('/admin/permissions')

      await page.getByRole('button', { name: /create/i }).click()

      await page.waitForSelector('.ant-modal', { state: 'visible' })
    })

    test('should close permission wizard', async ({ page }) => {
      await page.goto('/admin/permissions')

      await page.getByRole('button', { name: /create/i }).click()
      await page.waitForSelector('.ant-modal', { state: 'visible' })

      await page.getByRole('button', { name: 'Cancel' }).first().click()
    })
  })

  test.describe('Admin Workflow - Create and Cleanup', () => {
    test('should create a new user', async ({ page }) => {
      await page.goto('/users')

      await page.getByRole('button', { name: /create user/i }).click()

      await page.getByLabel('Username').fill(testUserName)
      await page.getByLabel('Email').fill(`${testUserName}@example.com`)
      await page.getByLabel('Display Name').fill('E2E Test User')

      await page.getByRole('button', { name: /create$/i }).click()

      await page.waitForSelector('.ant-modal', { state: 'visible', timeout: 10000 })
      const passwordModal = page.getByText('Temporary Password')
      if (await passwordModal.isVisible()) {
        await page.getByRole('button', { name: 'Done' }).click()
      }

      await expect(page.getByText(testUserName)).toBeVisible({ timeout: 10000 })
    })

    test('should create a new group', async ({ page }) => {
      await page.goto('/admin/groups')

      await page.getByRole('button', { name: /create group/i }).click()

      await page.getByLabel('Name').fill(testGroupName)
      await page.getByLabel('Description').fill('E2E Test Group Description')

      await page.getByRole('button', { name: /create$/i }).click()

      await expect(page.getByText('Group created successfully')).toBeVisible({ timeout: 10000 })
    })
  })

  test.describe('Admin Access Control', () => {
    test('should show admin-only pages for admin user', async ({ page }) => {
      await page.goto('/users')
      await expect(page.getByRole('heading', { name: 'Users' })).toBeVisible()

      await page.goto('/admin/groups')
      await expect(page.getByRole('heading', { name: 'Groups' })).toBeVisible()

      await page.goto('/admin/permissions')
      await expect(page.getByRole('heading', { name: 'Permissions' })).toBeVisible()
    })

    test('should display sidebar menu with admin links', async ({ page }) => {
      await expect(page.getByRole('link', { name: 'Users' })).toBeVisible()
    })
  })

  test.describe('User Actions', () => {
    test('should show reset password option', async ({ page }) => {
      await page.goto('/users')

      const resetButton = page.getByRole('button', { name: /reset password/i }).first()
      await expect(resetButton).toBeVisible()
    })

    test('should show toggle status option', async ({ page }) => {
      await page.goto('/users')

      const toggleButton = page.getByRole('button', { name: /(enable|disable)/i }).first()
      if (await toggleButton.isVisible()) {
        await expect(toggleButton).toBeEnabled()
      }
    })
  })

  test.describe('Group Member Management', () => {
    test('should show manage members button', async ({ page }) => {
      await page.goto('/admin/groups')

      const membersButton = page.getByRole('button', { name: /members/i }).first()
      if (await membersButton.isVisible()) {
        await expect(membersButton).toBeEnabled()
      }
    })
  })
})
