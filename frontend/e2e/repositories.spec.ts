import { test, expect } from '@playwright/test'

test.describe('Repository Management', () => {
  test.beforeEach(async ({ page }) => {
    // Login first
    await page.goto('/login')
    await page.getByPlaceholder('Username').fill('admin')
    await page.getByPlaceholder('Password').fill('admin123')
    await page.getByRole('button', { name: /log in/i }).click()
    await expect(page.getByText('Dashboard')).toBeVisible()
  })

  test('@smoke should navigate to repositories page', async ({ page }) => {
    await page.getByRole('link', { name: 'Repositories' }).click()
    await expect(page).toHaveURL('/repositories')
    await expect(page.getByRole('heading', { name: 'Repositories' })).toBeVisible()
  })

  test('@smoke should display repository list', async ({ page }) => {
    await page.goto('/repositories')

    // Should show table headers
    await expect(page.getByRole('columnheader', { name: 'Key' })).toBeVisible()
    await expect(page.getByRole('columnheader', { name: 'Name' })).toBeVisible()
    await expect(page.getByRole('columnheader', { name: 'Format' })).toBeVisible()
    await expect(page.getByRole('columnheader', { name: 'Type' })).toBeVisible()
  })

  test('@full should open create repository modal', async ({ page }) => {
    await page.goto('/repositories')

    await page.getByRole('button', { name: 'Create Repository' }).click()

    await expect(page.getByText('Create Repository')).toBeVisible()
    await expect(page.getByLabel('Repository Key')).toBeVisible()
    await expect(page.getByLabel('Name')).toBeVisible()
    await expect(page.getByLabel('Format')).toBeVisible()
  })

  test('@smoke should create new repository', async ({ page }) => {
    await page.goto('/repositories')

    await page.getByRole('button', { name: 'Create Repository' }).click()

    // Fill out the form
    await page.getByLabel('Repository Key').fill('test-repo')
    await page.getByLabel('Name').fill('Test Repository')
    await page.getByLabel('Description').fill('Test repository description')

    // Select format
    await page.getByLabel('Format').click()
    await page.getByText('Generic').click()

    // Select type
    await page.getByLabel('Type').click()
    await page.getByTitle('Local').click()

    // Submit
    await page.getByRole('button', { name: 'Create' }).click()

    // Should show success message
    await expect(page.getByText('Repository created successfully')).toBeVisible()
  })

  test('should filter repositories by format', async ({ page }) => {
    await page.goto('/repositories')

    // Click format filter
    await page.getByPlaceholder('Filter by format').click()
    await page.getByText('Maven').click()

    // Should filter the table (results will depend on test data)
    await expect(page.getByPlaceholder('Filter by format')).toHaveValue('maven')
  })

  test('should filter repositories by type', async ({ page }) => {
    await page.goto('/repositories')

    // Click type filter
    await page.getByPlaceholder('Filter by type').click()
    await page.getByTitle('Local').click()

    // Should filter the table
    await expect(page.getByPlaceholder('Filter by type')).toHaveValue('local')
  })

  test('should clear filters', async ({ page }) => {
    await page.goto('/repositories')

    // Add filters
    await page.getByPlaceholder('Filter by format').click()
    await page.getByText('Maven').click()

    // Clear filters
    await page.getByText('Clear filters').click()

    // Filters should be cleared
    await expect(page.getByText('Clear filters')).not.toBeVisible()
  })

  test('should navigate to repository detail', async ({ page }) => {
    await page.goto('/repositories')

    // Click on first repository link (View button)
    await page.getByRole('button', { name: 'View' }).first().click()

    // Should navigate to detail page
    await expect(page.getByText('Repository Details')).toBeVisible()
    await expect(page.getByText('Artifacts')).toBeVisible()
  })

  test('should open edit modal', async ({ page }) => {
    await page.goto('/repositories')

    await page.getByRole('button', { name: 'Edit' }).first().click()

    await expect(page.getByText('Edit Repository:')).toBeVisible()
    await expect(page.getByLabel('Name')).toBeVisible()
  })

  test('should show delete confirmation', async ({ page }) => {
    await page.goto('/repositories')

    await page.getByRole('button', { name: 'Delete' }).first().click()

    await expect(page.getByText('Delete repository')).toBeVisible()
    await expect(page.getByText('Are you sure you want to delete this repository?')).toBeVisible()
  })

  test('should refresh repository list', async ({ page }) => {
    await page.goto('/repositories')

    // Click refresh button (ReloadOutlined icon button)
    await page.locator('button').filter({ has: page.locator('[aria-label="reload"]') }).click()

    // Should show loading state briefly then data
    await expect(page.getByRole('table')).toBeVisible()
  })
})
