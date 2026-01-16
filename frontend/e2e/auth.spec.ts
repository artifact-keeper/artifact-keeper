import { test, expect } from '@playwright/test'

test.describe('Authentication', () => {
  test.beforeEach(async ({ page }) => {
    // Clear any stored tokens
    await page.evaluate(() => {
      localStorage.clear()
    })
  })

  test('should show login page when not authenticated', async ({ page }) => {
    await page.goto('/')
    await expect(page).toHaveURL(/.*login/)
    await expect(page.getByText('Artifact Keeper')).toBeVisible()
    await expect(page.getByText('Artifact Registry')).toBeVisible()
  })

  test('should login successfully with valid credentials', async ({ page }) => {
    await page.goto('/login')

    await page.getByPlaceholder('Username').fill('admin')
    await page.getByPlaceholder('Password').fill('admin123')
    await page.getByRole('button', { name: /log in/i }).click()

    // Should redirect to dashboard after login
    await expect(page).toHaveURL('/')
    await expect(page.getByText('Dashboard')).toBeVisible()
  })

  test('should show error for invalid credentials', async ({ page }) => {
    await page.goto('/login')

    await page.getByPlaceholder('Username').fill('invalid')
    await page.getByPlaceholder('Password').fill('invalid')
    await page.getByRole('button', { name: /log in/i }).click()

    // Should show error alert
    await expect(page.getByRole('alert')).toBeVisible()
  })

  test('should show validation errors for empty fields', async ({ page }) => {
    await page.goto('/login')

    await page.getByRole('button', { name: /log in/i }).click()

    await expect(page.getByText('Please input your username!')).toBeVisible()
    await expect(page.getByText('Please input your password!')).toBeVisible()
  })

  test('should logout successfully', async ({ page }) => {
    // First login
    await page.goto('/login')
    await page.getByPlaceholder('Username').fill('admin')
    await page.getByPlaceholder('Password').fill('admin123')
    await page.getByRole('button', { name: /log in/i }).click()

    // Wait for dashboard
    await expect(page.getByText('Dashboard')).toBeVisible()

    // Click user dropdown and logout
    await page.getByText('Admin User').click()
    await page.getByText('Logout').click()

    // Should redirect to login
    await expect(page).toHaveURL(/.*login/)
  })

  test('should persist login across page refresh', async ({ page }) => {
    // Login
    await page.goto('/login')
    await page.getByPlaceholder('Username').fill('admin')
    await page.getByPlaceholder('Password').fill('admin123')
    await page.getByRole('button', { name: /log in/i }).click()

    await expect(page.getByText('Dashboard')).toBeVisible()

    // Refresh page
    await page.reload()

    // Should still be on dashboard (not redirected to login)
    await expect(page.getByText('Dashboard')).toBeVisible()
  })
})
