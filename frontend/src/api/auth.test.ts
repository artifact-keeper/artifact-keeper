import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { authApi } from './auth'
import { server } from '../test/mocks/server'
import { http, HttpResponse } from 'msw'

const API_URL = '/api/v1'

describe('authApi', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  afterEach(() => {
    localStorage.clear()
  })

  describe('login', () => {
    it('should successfully login with valid credentials', async () => {
      const result = await authApi.login({ username: 'admin', password: 'admin' })

      expect(result).toEqual({
        access_token: 'mock-access-token',
        refresh_token: 'mock-refresh-token',
        expires_in: 3600,
        token_type: 'Bearer',
      })
    })

    it('should throw error with invalid credentials', async () => {
      await expect(
        authApi.login({ username: 'invalid', password: 'invalid' })
      ).rejects.toThrow()
    })
  })

  describe('logout', () => {
    it('should successfully logout', async () => {
      localStorage.setItem('access_token', 'mock-access-token')
      await expect(authApi.logout()).resolves.not.toThrow()
    })
  })

  describe('getCurrentUser', () => {
    it('should return current user when authenticated', async () => {
      localStorage.setItem('access_token', 'mock-access-token')
      const user = await authApi.getCurrentUser()

      expect(user).toMatchObject({
        username: 'admin',
        email: 'admin@example.com',
        is_admin: true,
      })
    })

    it('should throw error when not authenticated', async () => {
      await expect(authApi.getCurrentUser()).rejects.toThrow()
    })
  })

  describe('refreshToken', () => {
    it('should refresh token with valid refresh token', async () => {
      const result = await authApi.refreshToken('mock-refresh-token')

      expect(result).toMatchObject({
        access_token: expect.any(String),
        refresh_token: expect.any(String),
        expires_in: 3600,
      })
    })

    it('should throw error with invalid refresh token', async () => {
      await expect(
        authApi.refreshToken('invalid-token')
      ).rejects.toThrow()
    })
  })
})

describe('authApi error handling', () => {
  it('should handle network errors', async () => {
    server.use(
      http.post(`${API_URL}/auth/login`, () => {
        return HttpResponse.error()
      })
    )

    await expect(
      authApi.login({ username: 'admin', password: 'admin' })
    ).rejects.toThrow()
  })

  it('should handle server errors', async () => {
    server.use(
      http.post(`${API_URL}/auth/login`, () => {
        return HttpResponse.json(
          { code: 'SERVER_ERROR', message: 'Internal server error' },
          { status: 500 }
        )
      })
    )

    await expect(
      authApi.login({ username: 'admin', password: 'admin' })
    ).rejects.toThrow()
  })
})
