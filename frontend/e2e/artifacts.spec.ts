import { test, expect } from '@playwright/test'

test.describe('Artifact Management', () => {
  test.beforeEach(async ({ page }) => {
    // Login first
    await page.goto('/login')
    await page.getByPlaceholder('Username').fill('admin')
    await page.getByPlaceholder('Password').fill('admin123')
    await page.getByRole('button', { name: /log in/i }).click()
    await expect(page.getByText('Dashboard')).toBeVisible()
  })

  test('should display artifacts in repository detail', async ({ page }) => {
    // Navigate to a repository
    await page.goto('/repositories')
    await page.getByRole('button', { name: 'View' }).first().click()

    // Should show artifacts section
    await expect(page.getByText('Artifacts')).toBeVisible()

    // Should show artifact table headers
    await expect(page.getByRole('columnheader', { name: 'Name' })).toBeVisible()
    await expect(page.getByRole('columnheader', { name: 'Path' })).toBeVisible()
    await expect(page.getByRole('columnheader', { name: 'Size' })).toBeVisible()
  })

  test('should open upload artifact modal', async ({ page }) => {
    await page.goto('/repositories')
    await page.getByRole('button', { name: 'View' }).first().click()

    await page.getByRole('button', { name: 'Upload Artifact' }).click()

    await expect(page.getByText('Upload Artifact')).toBeVisible()
    await expect(page.getByText('Path (optional)')).toBeVisible()
    await expect(page.getByText('Click or drag file to this area to upload')).toBeVisible()
  })

  test('should search artifacts', async ({ page }) => {
    await page.goto('/repositories')
    await page.getByRole('button', { name: 'View' }).first().click()

    // Type in search box
    await page.getByPlaceholder('Search artifacts...').fill('test')
    await page.getByPlaceholder('Search artifacts...').press('Enter')

    // Search should be triggered (results depend on test data)
    await expect(page.getByPlaceholder('Search artifacts...')).toHaveValue('test')
  })

  test('should show artifact details modal', async ({ page }) => {
    await page.goto('/repositories')
    await page.getByRole('button', { name: 'View' }).first().click()

    // Wait for artifacts to load, then click Details
    await page.getByRole('button', { name: 'Details' }).first().click()

    // Should show detail modal with all info
    await expect(page.getByText('Artifact Details')).toBeVisible()
    await expect(page.getByText('SHA-256 Checksum')).toBeVisible()
    await expect(page.getByText('Download URL')).toBeVisible()
  })

  test('should copy artifact path', async ({ page }) => {
    await page.goto('/repositories')
    await page.getByRole('button', { name: 'View' }).first().click()

    // Open artifact detail modal
    await page.getByRole('button', { name: 'Details' }).first().click()

    // Should have copy button for path
    await expect(page.locator('[aria-label="copy"]').first()).toBeVisible()
  })

  test('should show download button in artifact detail', async ({ page }) => {
    await page.goto('/repositories')
    await page.getByRole('button', { name: 'View' }).first().click()

    // Open artifact detail modal
    await page.getByRole('button', { name: 'Details' }).first().click()

    // Should show download button
    await expect(page.getByRole('button', { name: /download/i })).toBeVisible()
  })

  test('should show delete confirmation for artifact', async ({ page }) => {
    await page.goto('/repositories')
    await page.getByRole('button', { name: 'View' }).first().click()

    // Click delete button for first artifact
    await page.getByRole('button', { name: /delete/i }).first().click()

    // Should show confirmation popover
    await expect(page.getByText('Delete artifact')).toBeVisible()
    await expect(page.getByText('Are you sure you want to delete this artifact?')).toBeVisible()
  })

  test('should display breadcrumb navigation', async ({ page }) => {
    await page.goto('/repositories')
    await page.getByRole('button', { name: 'View' }).first().click()

    // Should show breadcrumb
    await expect(page.getByText('Repositories', { exact: false })).toBeVisible()

    // Click breadcrumb to go back
    await page.locator('.ant-breadcrumb').getByText('Repositories').click()

    await expect(page).toHaveURL('/repositories')
  })

  test('should show back button', async ({ page }) => {
    await page.goto('/repositories')
    await page.getByRole('button', { name: 'View' }).first().click()

    // Click back button
    await page.getByRole('button', { name: 'Back to Repositories' }).click()

    await expect(page).toHaveURL('/repositories')
  })

  test('should display repository details card', async ({ page }) => {
    await page.goto('/repositories')
    await page.getByRole('button', { name: 'View' }).first().click()

    // Should show repository details
    await expect(page.getByText('Repository Details')).toBeVisible()
    await expect(page.getByText('Key')).toBeVisible()
    await expect(page.getByText('Format')).toBeVisible()
    await expect(page.getByText('Type')).toBeVisible()
    await expect(page.getByText('Storage Used')).toBeVisible()
  })
})
