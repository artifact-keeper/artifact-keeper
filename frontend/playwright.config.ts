import { defineConfig, devices } from '@playwright/test'

// Use BASE_URL from environment (for Docker) or default to localhost
const baseURL = process.env.BASE_URL || 'http://localhost:5173'

// Support for @smoke and @full test tags via environment variable
// Usage: TEST_TAG=@smoke npx playwright test
// Usage: TEST_TAG=@full npx playwright test
const testTag = process.env.TEST_TAG

export default defineConfig({
  testDir: './e2e',
  globalSetup: './e2e/global-setup.ts',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI ? [['html', { open: 'never' }], ['list']] : 'html',
  outputDir: 'test-results',
  // Filter tests by tag if TEST_TAG environment variable is set
  grep: testTag ? new RegExp(testTag) : undefined,
  use: {
    baseURL,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: process.env.CI ? 'retain-on-failure' : 'off',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
    },
  ],
  // Only start dev server when running locally (not in Docker/CI)
  ...(process.env.BASE_URL ? {} : {
    webServer: {
      command: 'npm run dev',
      url: 'http://localhost:5173',
      reuseExistingServer: true,
      timeout: 120000,
    },
  }),
})
