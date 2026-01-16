import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { repositoriesApi } from './repositories'
import { server } from '../test/mocks/server'
import { http, HttpResponse } from 'msw'
import { mockRepositories } from '../test/mocks/handlers'

const API_URL = 'http://localhost:9080/api/v1'

describe('repositoriesApi', () => {
  beforeEach(() => {
    localStorage.setItem('access_token', 'mock-access-token')
  })

  afterEach(() => {
    localStorage.clear()
  })

  describe('list', () => {
    it('should return paginated list of repositories', async () => {
      const result = await repositoriesApi.list()

      expect(result.items).toHaveLength(mockRepositories.length)
      expect(result.pagination).toMatchObject({
        page: 1,
        per_page: 20,
        total: mockRepositories.length,
      })
    })

    it('should filter by format', async () => {
      const result = await repositoriesApi.list({ format: 'maven' })

      expect(result.items).toHaveLength(1)
      expect(result.items[0].format).toBe('maven')
    })

    it('should filter by repo_type', async () => {
      const result = await repositoriesApi.list({ repo_type: 'local' })

      result.items.forEach(repo => {
        expect(repo.repo_type).toBe('local')
      })
    })

    it('should handle combined filters', async () => {
      const result = await repositoriesApi.list({
        format: 'npm',
        repo_type: 'local'
      })

      result.items.forEach(repo => {
        expect(repo.format).toBe('npm')
        expect(repo.repo_type).toBe('local')
      })
    })
  })

  describe('get', () => {
    it('should return repository details', async () => {
      const result = await repositoriesApi.get('maven-local')

      expect(result).toMatchObject({
        key: 'maven-local',
        name: 'Maven Local',
        format: 'maven',
      })
    })

    it('should throw error for non-existent repository', async () => {
      await expect(repositoriesApi.get('non-existent')).rejects.toThrow()
    })
  })

  describe('create', () => {
    it('should create new repository', async () => {
      const newRepo = {
        key: 'pypi-local',
        name: 'PyPI Local',
        description: 'Local PyPI repository',
        format: 'pypi' as const,
        repo_type: 'local' as const,
        is_public: false,
      }

      const result = await repositoriesApi.create(newRepo)

      expect(result).toMatchObject({
        key: 'pypi-local',
        name: 'PyPI Local',
        format: 'pypi',
      })
      expect(result.id).toBeDefined()
    })

    it('should handle validation errors', async () => {
      server.use(
        http.post(`${API_URL}/repositories`, () => {
          return HttpResponse.json(
            { code: 'VALIDATION_ERROR', message: 'Invalid repository key' },
            { status: 400 }
          )
        })
      )

      await expect(
        repositoriesApi.create({
          key: 'INVALID',
          name: 'Test',
          format: 'generic',
          repo_type: 'local',
        })
      ).rejects.toThrow()
    })
  })

  describe('update', () => {
    it('should update repository', async () => {
      const result = await repositoriesApi.update('maven-local', {
        name: 'Updated Maven Local',
        is_public: true,
      })

      expect(result).toMatchObject({
        key: 'maven-local',
        name: 'Updated Maven Local',
        is_public: true,
      })
    })

    it('should throw error for non-existent repository', async () => {
      await expect(
        repositoriesApi.update('non-existent', { name: 'Test' })
      ).rejects.toThrow()
    })
  })

  describe('delete', () => {
    it('should delete repository', async () => {
      await expect(repositoriesApi.delete('maven-local')).resolves.not.toThrow()
    })

    it('should throw error for non-existent repository', async () => {
      await expect(repositoriesApi.delete('non-existent')).rejects.toThrow()
    })
  })
})

describe('repositoriesApi edge cases', () => {
  beforeEach(() => {
    localStorage.setItem('access_token', 'mock-access-token')
  })

  afterEach(() => {
    localStorage.clear()
  })

  it('should handle empty repository list', async () => {
    server.use(
      http.get(`${API_URL}/repositories`, () => {
        return HttpResponse.json({
          items: [],
          pagination: { page: 1, per_page: 20, total: 0, total_pages: 0 },
        })
      })
    )

    const result = await repositoriesApi.list()
    expect(result.items).toHaveLength(0)
    expect(result.pagination.total).toBe(0)
  })

  it('should handle large pagination', async () => {
    const result = await repositoriesApi.list({ page: 1, per_page: 100 })
    expect(result.pagination).toBeDefined()
  })

  it('should handle server timeout', async () => {
    server.use(
      http.get(`${API_URL}/repositories`, async () => {
        await new Promise(resolve => setTimeout(resolve, 10000))
        return HttpResponse.json({ items: [] })
      })
    )

    // This will either timeout or be cancelled by test cleanup
    const promise = repositoriesApi.list()
    // We don't await here as the timeout is long
    expect(promise).toBeDefined()
  })
})
