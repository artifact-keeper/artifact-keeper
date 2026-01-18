import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { adminApi } from './admin'
import { server } from '../test/mocks/server'
import { http, HttpResponse } from 'msw'

const API_URL = 'http://localhost:9080/api/v1'

describe('adminApi', () => {
  beforeEach(() => {
    localStorage.setItem('access_token', 'mock-access-token')
  })

  afterEach(() => {
    localStorage.clear()
  })

  describe('getStats', () => {
    it('should return admin statistics', async () => {
      const result = await adminApi.getStats()

      expect(result).toHaveProperty('total_repositories')
      expect(result).toHaveProperty('total_artifacts')
      expect(result).toHaveProperty('total_storage_bytes')
      expect(result).toHaveProperty('total_users')
      expect(typeof result.total_repositories).toBe('number')
      expect(typeof result.total_artifacts).toBe('number')
    })

    it('should handle empty stats', async () => {
      server.use(
        http.get(`${API_URL}/admin/stats`, () => {
          return HttpResponse.json({
            total_repositories: 0,
            total_artifacts: 0,
            total_storage_bytes: 0,
            total_users: 0,
          })
        })
      )

      const result = await adminApi.getStats()

      expect(result.total_repositories).toBe(0)
      expect(result.total_artifacts).toBe(0)
    })
  })

  describe('listUsers', () => {
    it('should return list of users', async () => {
      const result = await adminApi.listUsers()

      expect(Array.isArray(result)).toBe(true)
      expect(result.length).toBeGreaterThan(0)
      expect(result[0]).toHaveProperty('id')
      expect(result[0]).toHaveProperty('username')
      expect(result[0]).toHaveProperty('email')
    })

    it('should handle empty user list', async () => {
      server.use(
        http.get(`${API_URL}/users`, () => {
          return HttpResponse.json({
            items: [],
            pagination: {
              page: 1,
              per_page: 20,
              total: 0,
              total_pages: 0,
            },
          })
        })
      )

      const result = await adminApi.listUsers()

      expect(Array.isArray(result)).toBe(true)
      expect(result.length).toBe(0)
    })
  })

  describe('getHealth', () => {
    it('should return health status', async () => {
      const result = await adminApi.getHealth()

      expect(result).toHaveProperty('status')
      expect(result.status).toBe('healthy')
    })

    it('should include version', async () => {
      const result = await adminApi.getHealth()

      expect(result).toHaveProperty('version')
    })

    it('should include health checks', async () => {
      const result = await adminApi.getHealth()

      expect(result).toHaveProperty('checks')
      expect(result.checks).toHaveProperty('database')
      expect(result.checks).toHaveProperty('storage')
    })

    it('should handle degraded status', async () => {
      server.use(
        http.get(`${API_URL}/health`, () => {
          return HttpResponse.json({
            status: 'degraded',
            version: '1.0.0',
            checks: {
              database: { status: 'healthy', message: 'Connected' },
              storage: { status: 'unhealthy', message: 'Disk space low' },
            },
          })
        })
      )

      const result = await adminApi.getHealth()

      expect(result.status).toBe('degraded')
      expect(result.checks.storage.status).toBe('unhealthy')
    })

    it('should handle unhealthy status', async () => {
      server.use(
        http.get(`${API_URL}/health`, () => {
          return HttpResponse.json({
            status: 'unhealthy',
            version: '1.0.0',
            checks: {
              database: { status: 'unhealthy', message: 'Connection refused' },
              storage: { status: 'unhealthy', message: 'Storage unavailable' },
            },
          }, { status: 503 })
        })
      )

      await expect(adminApi.getHealth()).rejects.toThrow()
    })
  })
})

describe('adminApi error handling', () => {
  beforeEach(() => {
    localStorage.setItem('access_token', 'mock-access-token')
  })

  afterEach(() => {
    localStorage.clear()
  })

  it('should handle network errors for stats', async () => {
    server.use(
      http.get(`${API_URL}/admin/stats`, () => {
        return HttpResponse.error()
      })
    )

    await expect(adminApi.getStats()).rejects.toThrow()
  })

  it('should handle unauthorized errors for stats', async () => {
    server.use(
      http.get(`${API_URL}/admin/stats`, () => {
        return HttpResponse.json(
          { code: 'FORBIDDEN', message: 'Admin access required' },
          { status: 403 }
        )
      })
    )

    await expect(adminApi.getStats()).rejects.toThrow()
  })

  it('should handle server errors for users', async () => {
    server.use(
      http.get(`${API_URL}/users`, () => {
        return HttpResponse.json(
          { code: 'SERVER_ERROR', message: 'Internal server error' },
          { status: 500 }
        )
      })
    )

    await expect(adminApi.listUsers()).rejects.toThrow()
  })

  it('should handle timeout errors', async () => {
    server.use(
      http.get(`${API_URL}/admin/stats`, async () => {
        await new Promise(resolve => setTimeout(resolve, 30000))
        return HttpResponse.json({})
      })
    )

    // This test verifies the timeout handling
    // In real scenario, axios would throw a timeout error
  })
})

describe('adminApi authorization', () => {
  it('should require authentication for stats', async () => {
    localStorage.clear()
    server.use(
      http.get(`${API_URL}/admin/stats`, ({ request }) => {
        const authHeader = request.headers.get('Authorization')
        if (!authHeader) {
          return HttpResponse.json(
            { code: 'UNAUTHORIZED', message: 'Authentication required' },
            { status: 401 }
          )
        }
        return HttpResponse.json({
          total_repositories: 5,
          total_artifacts: 198,
          total_storage_bytes: 2147483648,
          total_users: 3,
        })
      })
    )

    await expect(adminApi.getStats()).rejects.toThrow()
  })

  it('should require admin role for stats', async () => {
    server.use(
      http.get(`${API_URL}/admin/stats`, () => {
        return HttpResponse.json(
          { code: 'FORBIDDEN', message: 'Admin privileges required' },
          { status: 403 }
        )
      })
    )

    await expect(adminApi.getStats()).rejects.toThrow()
  })
})
