import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { artifactsApi } from './artifacts'
import { server } from '../test/mocks/server'
import { http, HttpResponse } from 'msw'

const API_URL = '/api/v1'

describe('artifactsApi', () => {
  beforeEach(() => {
    localStorage.setItem('access_token', 'mock-access-token')
  })

  afterEach(() => {
    localStorage.clear()
  })

  describe('list', () => {
    it('should list artifacts for a repository', async () => {
      const result = await artifactsApi.list('maven-local')

      expect(result).toHaveProperty('items')
      expect(result).toHaveProperty('pagination')
      expect(Array.isArray(result.items)).toBe(true)
    })

    it('should pass pagination params', async () => {
      const result = await artifactsApi.list('maven-local', {
        page: 2,
        per_page: 10,
      })

      expect(result).toHaveProperty('items')
    })

    it('should filter by path', async () => {
      const result = await artifactsApi.list('maven-local', {
        path: 'com/example',
      })

      expect(result).toHaveProperty('items')
    })

    it('should search artifacts', async () => {
      const result = await artifactsApi.list('maven-local', {
        search: 'mylib',
      })

      expect(result).toHaveProperty('items')
    })
  })

  describe('get', () => {
    it('should get a single artifact', async () => {
      const result = await artifactsApi.get(
        'maven-local',
        'com/example/mylib/1.0.0/mylib-1.0.0.jar'
      )

      expect(result).toHaveProperty('id')
      expect(result).toHaveProperty('path')
      expect(result).toHaveProperty('name')
      expect(result.repository_key).toBe('maven-local')
    })

    it('should throw error for non-existent artifact', async () => {
      await expect(
        artifactsApi.get('maven-local', 'non/existent/path.jar')
      ).rejects.toThrow()
    })
  })

  describe('delete', () => {
    it('should delete an artifact', async () => {
      await expect(
        artifactsApi.delete('maven-local', 'com/example/mylib/1.0.0/mylib-1.0.0.jar')
      ).resolves.not.toThrow()
    })

    it('should throw error for non-existent artifact', async () => {
      server.use(
        http.delete(`${API_URL}/repositories/:key/artifacts/*`, () => {
          return HttpResponse.json(
            { code: 'NOT_FOUND', message: 'Artifact not found' },
            { status: 404 }
          )
        })
      )

      await expect(
        artifactsApi.delete('maven-local', 'non/existent/path.jar')
      ).rejects.toThrow()
    })
  })

  describe('getDownloadUrl', () => {
    it('should return a download URL', () => {
      const url = artifactsApi.getDownloadUrl(
        'maven-local',
        'com/example/mylib/1.0.0/mylib-1.0.0.jar'
      )

      expect(url).toContain('/api/v1/repositories/maven-local/artifacts/')
      expect(url).toContain('/download')
    })

    it('should encode special characters in path', () => {
      const url = artifactsApi.getDownloadUrl('maven-local', 'path with spaces/file.jar')

      expect(url).toContain(encodeURIComponent('path with spaces/file.jar'))
    })
  })

  // Upload tests are skipped because MSW's XMLHttpRequest interceptor in jsdom
  // cannot reliably handle multipart/form-data uploads from axios.
  // These are covered by E2E tests instead.
  describe.skip('upload', () => {
    it('should upload an artifact', async () => {
      server.use(
        http.post(`${API_URL}/repositories/:key/artifacts`, async () => {
          return HttpResponse.json({
            id: 'new-artifact-id',
            repository_key: 'maven-local',
            path: 'uploaded/file.jar',
            name: 'file.jar',
            size_bytes: 1024,
            checksum_sha256: 'abc123',
            content_type: 'application/java-archive',
            download_count: 0,
            created_at: new Date().toISOString(),
            metadata: {},
          }, { status: 201 })
        })
      )

      const file = new File(['test content'], 'file.jar', { type: 'application/java-archive' })
      const result = await artifactsApi.upload('maven-local', file)

      expect(result).toHaveProperty('id')
      expect(result.path).toBe('uploaded/file.jar')
    })

    it('should upload with custom path', async () => {
      server.use(
        http.post(`${API_URL}/repositories/:key/artifacts`, async () => {
          return HttpResponse.json({
            id: 'new-artifact-id',
            repository_key: 'maven-local',
            path: 'custom/path/file.jar',
            name: 'file.jar',
            size_bytes: 1024,
            checksum_sha256: 'abc123',
            content_type: 'application/java-archive',
            download_count: 0,
            created_at: new Date().toISOString(),
            metadata: {},
          }, { status: 201 })
        })
      )

      const file = new File(['test content'], 'file.jar', { type: 'application/java-archive' })
      const result = await artifactsApi.upload('maven-local', file, 'custom/path')

      expect(result.path).toBe('custom/path/file.jar')
    })

    it('should call progress callback', async () => {
      server.use(
        http.post(`${API_URL}/repositories/:key/artifacts`, async () => {
          return HttpResponse.json({
            id: 'new-artifact-id',
            repository_key: 'maven-local',
            path: 'uploaded/file.jar',
            name: 'file.jar',
            size_bytes: 1024,
            checksum_sha256: 'abc123',
            content_type: 'application/java-archive',
            download_count: 0,
            created_at: new Date().toISOString(),
            metadata: {},
          }, { status: 201 })
        })
      )

      const file = new File(['test content'], 'file.jar', { type: 'application/java-archive' })
      const progressCallback = vi.fn()

      await artifactsApi.upload('maven-local', file, undefined, progressCallback)
    })
  })
})

describe('artifactsApi error handling', () => {
  beforeEach(() => {
    localStorage.setItem('access_token', 'mock-access-token')
  })

  afterEach(() => {
    localStorage.clear()
  })

  it('should handle network errors', async () => {
    server.use(
      http.get(`${API_URL}/repositories/:key/artifacts`, () => {
        return HttpResponse.error()
      })
    )

    await expect(artifactsApi.list('maven-local')).rejects.toThrow()
  })

  it('should handle server errors', async () => {
    server.use(
      http.get(`${API_URL}/repositories/:key/artifacts`, () => {
        return HttpResponse.json(
          { code: 'SERVER_ERROR', message: 'Internal server error' },
          { status: 500 }
        )
      })
    )

    await expect(artifactsApi.list('maven-local')).rejects.toThrow()
  })

  it('should handle unauthorized errors', async () => {
    localStorage.removeItem('access_token')
    server.use(
      http.get(`${API_URL}/repositories/:key/artifacts`, () => {
        return HttpResponse.json(
          { code: 'UNAUTHORIZED', message: 'Authentication required' },
          { status: 401 }
        )
      })
    )

    await expect(artifactsApi.list('maven-local')).rejects.toThrow()
  })
})
