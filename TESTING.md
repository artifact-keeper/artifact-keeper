# Testing Guide

This document covers the testing infrastructure for Artifact Keeper, including unit tests, component tests, and end-to-end (E2E) tests.

## Quick Start

### Run All Tests Locally

```bash
# Backend tests (requires PostgreSQL)
cargo test --workspace

# Frontend unit/component tests
cd frontend && npm run test:run

# E2E tests with Docker (fully automated, no human in the loop)
./scripts/run-e2e-tests.sh
```

### Run Tests in CI/CD

Tests run automatically on push/PR via GitHub Actions. See `.github/workflows/e2e-tests.yml`.

## Test Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Test Pyramid                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│                         ┌───────────┐                            │
│                         │   E2E     │  Playwright                │
│                         │   Tests   │  (Browser automation)      │
│                        ┌┴───────────┴┐                           │
│                       ┌┴─────────────┴┐                          │
│                      ┌┴───────────────┴┐                         │
│                      │   Component     │  Vitest + RTL           │
│                      │     Tests       │  (React components)     │
│                     ┌┴─────────────────┴┐                        │
│                    ┌┴───────────────────┴┐                       │
│                   ┌┴─────────────────────┴┐                      │
│                   │       Unit Tests       │  Vitest / Cargo      │
│                   │    (Functions, APIs)   │  (Isolated logic)    │
│                   └────────────────────────┘                      │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Backend Tests

### Running Backend Tests

```bash
# Run all backend tests
cargo test --workspace

# Run with verbose output
cargo test --workspace -- --nocapture

# Run specific test
cargo test test_create_repository

# Run integration tests only
cargo test --test integration_tests
```

### Test Location

- `backend/tests/integration_tests.rs` - API integration tests
- `backend/src/**/*.rs` - Unit tests (inline `#[cfg(test)]` modules)

## Frontend Tests

### Unit & Component Tests (Vitest)

```bash
cd frontend

# Watch mode (interactive)
npm run test

# Single run
npm run test:run

# With coverage report
npm run test:coverage

# With Vitest UI
npm run test:ui
```

#### Test Files

| File | Purpose |
|------|---------|
| `src/api/auth.test.ts` | Auth API functions |
| `src/api/repositories.test.ts` | Repository API functions |
| `src/pages/Login.test.tsx` | Login page component |
| `src/pages/Dashboard.test.tsx` | Dashboard page component |

#### Test Utilities

- `src/test/setup.ts` - Global test setup (jest-dom, MSW)
- `src/test/utils.tsx` - Custom render with providers
- `src/test/mocks/handlers.ts` - MSW API mock handlers
- `src/test/mocks/server.ts` - MSW server configuration

### E2E Tests (Playwright)

#### Run Locally (with local dev server)

```bash
cd frontend

# Headless
npm run test:e2e

# With browser UI
npm run test:e2e:headed

# Interactive mode
npm run test:e2e:ui
```

**Note:** Local E2E tests require:
- Backend running at `http://localhost:9080`
- Frontend dev server at `http://localhost:5173`

#### Test Files

| File | Coverage |
|------|----------|
| `e2e/auth.spec.ts` | Login, logout, session management |
| `e2e/dashboard.spec.ts` | Dashboard stats, health, navigation |
| `e2e/repositories.spec.ts` | CRUD, filtering, modals |
| `e2e/artifacts.spec.ts` | Upload, download, search, details |

## Automated E2E Testing with Docker

Run fully automated E2E tests without any manual setup:

```bash
# Run all E2E tests in containers
./scripts/run-e2e-tests.sh

# Force rebuild containers
./scripts/run-e2e-tests.sh --build

# Clean up after tests
./scripts/run-e2e-tests.sh --clean
```

### How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                    docker-compose.test.yml                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐        │
│  │  PostgreSQL │────▶│   Backend   │────▶│  Frontend   │        │
│  │   (tmpfs)   │     │   (Rust)    │     │   (Vite)    │        │
│  └─────────────┘     └─────────────┘     └──────┬──────┘        │
│                                                  │               │
│                                                  ▼               │
│                                          ┌─────────────┐        │
│                                          │  Playwright │        │
│                                          │   (Tests)   │        │
│                                          └─────────────┘        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Container Details

| Service | Image | Purpose |
|---------|-------|---------|
| `postgres` | postgres:16-alpine | Test database (tmpfs for speed) |
| `backend` | Custom (Rust) | API server |
| `frontend` | Custom (Node) | Vite dev server |
| `playwright` | mcr.microsoft.com/playwright | Test runner |

### Test Results

After running, test artifacts are available at:
- `./playwright-report/index.html` - HTML report
- `./test-results/` - Screenshots, videos, traces

## CI/CD Integration

### GitHub Actions

Tests run automatically via `.github/workflows/e2e-tests.yml`:

```yaml
# Triggers
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]
```

### Jobs

1. **e2e-tests** - Docker Compose E2E tests
2. **unit-tests** - Frontend Vitest tests
3. **backend-tests** - Rust cargo tests

### Artifacts

Test reports are uploaded as GitHub Actions artifacts:
- `playwright-report` - E2E test HTML report
- `test-results` - Screenshots, traces
- `coverage-report` - Code coverage

## Writing Tests

### Unit Test Example (Vitest)

```typescript
import { describe, it, expect } from 'vitest'
import { authApi } from './auth'

describe('authApi', () => {
  it('should login with valid credentials', async () => {
    const result = await authApi.login({
      username: 'admin',
      password: 'admin'
    })
    expect(result.access_token).toBeDefined()
  })
})
```

### Component Test Example (RTL)

```typescript
import { render, screen } from '../test/utils'
import userEvent from '@testing-library/user-event'
import Login from './Login'

it('should submit login form', async () => {
  const user = userEvent.setup()
  render(<Login />)

  await user.type(screen.getByPlaceholder('Username'), 'admin')
  await user.type(screen.getByPlaceholder('Password'), 'admin')
  await user.click(screen.getByRole('button', { name: /log in/i }))

  expect(localStorage.getItem('access_token')).toBeDefined()
})
```

### E2E Test Example (Playwright)

```typescript
import { test, expect } from '@playwright/test'

test('should login and see dashboard', async ({ page }) => {
  await page.goto('/login')
  await page.getByPlaceholder('Username').fill('admin')
  await page.getByPlaceholder('Password').fill('admin')
  await page.getByRole('button', { name: /log in/i }).click()

  await expect(page).toHaveURL('/')
  await expect(page.getByText('Dashboard')).toBeVisible()
})
```

## Troubleshooting

### E2E Tests Failing Locally

1. Ensure backend is running: `cargo run`
2. Ensure frontend is running: `cd frontend && npm run dev`
3. Check backend URL in `playwright.config.ts`

### Docker E2E Tests Failing

```bash
# View container logs
docker compose -f docker-compose.test.yml logs

# Rebuild from scratch
docker compose -f docker-compose.test.yml down -v
docker compose -f docker-compose.test.yml build --no-cache
./scripts/run-e2e-tests.sh
```

### MSW Not Intercepting Requests

1. Check `src/test/setup.ts` is in vitest config
2. Verify handler URL matches API calls
3. Check network requests in test output

## Coverage Goals

| Test Type | Target Coverage |
|-----------|-----------------|
| Unit Tests | 80%+ |
| Component Tests | 70%+ |
| E2E Tests | Critical paths |

## Resources

- [Vitest Documentation](https://vitest.dev/)
- [React Testing Library](https://testing-library.com/docs/react-testing-library/intro/)
- [Playwright Documentation](https://playwright.dev/)
- [MSW Documentation](https://mswjs.io/)
