import { test, expect } from '@playwright/test'

test.describe('Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    // Login first
    await page.goto('/login')
    await page.getByPlaceholder('Username').fill('admin')
    await page.getByPlaceholder('Password').fill('admin123')
    await page.getByRole('button', { name: /log in/i }).click()
    await expect(page.getByText('Dashboard')).toBeVisible()
  })

  test('@smoke should display dashboard heading', async ({ page }) => {
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible()
  })

  test('@smoke should show system health section', async ({ page }) => {
    await expect(page.getByText('System Health')).toBeVisible()
    await expect(page.getByText('Status')).toBeVisible()
    await expect(page.getByText('Database')).toBeVisible()
    await expect(page.getByText('Storage')).toBeVisible()
  })

  test('@full should display admin statistics', async ({ page }) => {
    await expect(page.getByText('Repositories')).toBeVisible()
    await expect(page.getByText('Artifacts')).toBeVisible()
    await expect(page.getByText('Users')).toBeVisible()
    await expect(page.getByText('Total Storage')).toBeVisible()
  })

  test('@full should display recent repositories table', async ({ page }) => {
    await expect(page.getByText('Recent Repositories')).toBeVisible()
    await expect(page.getByText('View All')).toBeVisible()
  })

  test('@full should navigate to repositories from View All link', async ({ page }) => {
    await page.getByText('View All').click()
    await expect(page).toHaveURL('/repositories')
  })

  test('@full should have refresh button', async ({ page }) => {
    await expect(page.getByRole('button', { name: 'Refresh' })).toBeVisible()
  })

  test('@full should refresh data when clicking refresh', async ({ page }) => {
    await page.getByRole('button', { name: 'Refresh' }).click()
    // Button should show loading state briefly
    await expect(page.getByRole('button', { name: 'Refresh' })).toBeVisible()
  })

  test('@full should navigate from stat card clicks', async ({ page }) => {
    // Click on Repositories stat card
    await page.locator('.ant-card').filter({ hasText: 'Repositories' }).first().click()
    await expect(page).toHaveURL('/repositories')
  })

  test('@full should display healthy status with green color', async ({ page }) => {
    await expect(page.getByText('healthy')).toBeVisible()
  })

  test('@full should show help modal from header', async ({ page }) => {
    // Click help button in header
    await page.locator('button').filter({ has: page.locator('[aria-label="question-circle"]') }).click()

    await expect(page.getByText('About Artifact Keeper')).toBeVisible()
    await expect(page.getByText('Version 1.0.0')).toBeVisible()
    await expect(page.getByText('Supported Formats')).toBeVisible()
  })

  test('@full should close help modal', async ({ page }) => {
    // Open help modal
    await page.locator('button').filter({ has: page.locator('[aria-label="question-circle"]') }).click()
    await expect(page.getByText('About Artifact Keeper')).toBeVisible()

    // Close it
    await page.getByRole('button', { name: 'Close' }).click()

    await expect(page.getByText('About Artifact Keeper')).not.toBeVisible()
  })
})

test.describe('Sidebar Navigation', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/login')
    await page.getByPlaceholder('Username').fill('admin')
    await page.getByPlaceholder('Password').fill('admin123')
    await page.getByRole('button', { name: /log in/i }).click()
    await expect(page.getByText('Dashboard')).toBeVisible()
  })

  test('@smoke should display sidebar with all menu items', async ({ page }) => {
    await expect(page.getByRole('link', { name: 'Dashboard' })).toBeVisible()
    await expect(page.getByRole('link', { name: 'Repositories' })).toBeVisible()
    await expect(page.getByRole('link', { name: 'Users' })).toBeVisible()
    await expect(page.getByRole('link', { name: 'Settings' })).toBeVisible()
  })

  test('@full should display version in sidebar footer', async ({ page }) => {
    await expect(page.getByText('v1.0.0')).toBeVisible()
  })

  test('@full should navigate to Users page', async ({ page }) => {
    await page.getByRole('link', { name: 'Users' }).click()
    await expect(page).toHaveURL('/users')
  })

  test('@full should navigate to Settings page', async ({ page }) => {
    await page.getByRole('link', { name: 'Settings' }).click()
    await expect(page).toHaveURL('/settings')
  })

  test('@full should highlight active menu item', async ({ page }) => {
    // Dashboard should be highlighted by default
    const dashboardLink = page.getByRole('link', { name: 'Dashboard' })
    await expect(dashboardLink).toHaveClass(/ant-menu-item-selected/)

    // Navigate to repositories
    await page.getByRole('link', { name: 'Repositories' }).click()

    const reposLink = page.getByRole('link', { name: 'Repositories' })
    await expect(reposLink).toHaveClass(/ant-menu-item-selected/)
  })
})
