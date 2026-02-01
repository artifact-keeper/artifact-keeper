import { describe, it, expect, beforeEach, afterEach } from 'vitest'
// Removed unused vi import
import { render, screen, waitFor } from '../test/utils'
import userEvent from '@testing-library/user-event'
import Login from './Login'
import { server } from '../test/mocks/server'
import { http, HttpResponse } from 'msw'

const API_URL = '/api/v1'

describe('Login Page', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  afterEach(() => {
    localStorage.clear()
  })

  it('should render login form', () => {
    render(<Login />)

    expect(screen.getByText('Artifact Keeper')).toBeInTheDocument()
    expect(screen.getByText('Artifact Registry')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Username')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Password')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /log in/i })).toBeInTheDocument()
  })

  it('should show validation errors for empty fields', async () => {
    const user = userEvent.setup()
    render(<Login />)

    await user.click(screen.getByRole('button', { name: /log in/i }))

    await waitFor(() => {
      expect(screen.getByText('Please input your username!')).toBeInTheDocument()
      expect(screen.getByText('Please input your password!')).toBeInTheDocument()
    })
  })

  it('should show validation error for empty username only', async () => {
    const user = userEvent.setup()
    render(<Login />)

    await user.type(screen.getByPlaceholderText('Password'), 'somepassword')
    await user.click(screen.getByRole('button', { name: /log in/i }))

    await waitFor(() => {
      expect(screen.getByText('Please input your username!')).toBeInTheDocument()
    })
  })

  it('should submit form with valid credentials', async () => {
    const user = userEvent.setup()
    render(<Login />)

    await user.type(screen.getByPlaceholderText('Username'), 'admin')
    await user.type(screen.getByPlaceholderText('Password'), 'admin')
    await user.click(screen.getByRole('button', { name: /log in/i }))

    // Wait for the form to be submitted
    await waitFor(() => {
      expect(localStorage.getItem('access_token')).toBe('mock-access-token')
    })
  })

  it('should show error alert for invalid credentials', async () => {
    const user = userEvent.setup()
    render(<Login />)

    await user.type(screen.getByPlaceholderText('Username'), 'wrong')
    await user.type(screen.getByPlaceholderText('Password'), 'wrong')
    await user.click(screen.getByRole('button', { name: /log in/i }))

    await waitFor(() => {
      // The error might be displayed in the Alert component
      expect(screen.getByRole('alert')).toBeInTheDocument()
    })
  })

  it('should disable form inputs while loading', async () => {
    // Add a delay to the login handler
    server.use(
      http.post(`${API_URL}/auth/login`, async () => {
        await new Promise(resolve => setTimeout(resolve, 100))
        return HttpResponse.json({
          access_token: 'mock-access-token',
          refresh_token: 'mock-refresh-token',
          expires_in: 3600,
          token_type: 'Bearer',
        })
      })
    )

    const user = userEvent.setup()
    render(<Login />)

    await user.type(screen.getByPlaceholderText('Username'), 'admin')
    await user.type(screen.getByPlaceholderText('Password'), 'admin')
    await user.click(screen.getByRole('button', { name: /log in/i }))

    // Check that button shows loading state (Ant Design 6 uses loading class, not disabled attr)
    await waitFor(() => {
      const button = screen.getByRole('button', { name: /log in/i })
      expect(
        button.classList.contains('ant-btn-loading') || button.hasAttribute('disabled')
      ).toBe(true)
    })
  })

  it('should handle network errors gracefully', async () => {
    server.use(
      http.post(`${API_URL}/auth/login`, () => {
        return HttpResponse.error()
      })
    )

    const user = userEvent.setup()
    render(<Login />)

    await user.type(screen.getByPlaceholderText('Username'), 'admin')
    await user.type(screen.getByPlaceholderText('Password'), 'admin')
    await user.click(screen.getByRole('button', { name: /log in/i }))

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
    })
  })

  it('should allow closing error alert', async () => {
    server.use(
      http.post(`${API_URL}/auth/login`, () => {
        return HttpResponse.json(
          { code: 'UNAUTHORIZED', message: 'Invalid credentials' },
          { status: 401 }
        )
      })
    )

    const user = userEvent.setup()
    render(<Login />)

    await user.type(screen.getByPlaceholderText('Username'), 'wrong')
    await user.type(screen.getByPlaceholderText('Password'), 'wrong')
    await user.click(screen.getByRole('button', { name: /log in/i }))

    await waitFor(() => {
      expect(screen.getByRole('alert')).toBeInTheDocument()
    })

    // Close button in Alert component
    const closeButton = screen.getByRole('button', { name: /close/i })
    await user.click(closeButton)

    await waitFor(() => {
      expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    })
  })

  it('should set document title to Login', () => {
    render(<Login />)
    expect(document.title).toContain('Login')
  })
})
