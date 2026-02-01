import { http, HttpResponse } from 'msw'

// In test environment, axios uses empty baseURL (non-PROD mode),
// so requests are relative paths that MSW intercepts as-is.
const API_URL = '/api/v1'

// Mock data
export const mockUser = {
  id: '550e8400-e29b-41d4-a716-446655440000',
  username: 'admin',
  email: 'admin@example.com',
  display_name: 'Admin User',
  is_admin: true,
  is_active: true,
  auth_provider: 'local',
  created_at: '2024-01-01T00:00:00Z',
  last_login_at: '2024-01-15T10:00:00Z',
}

export const mockRepositories = [
  {
    id: '550e8400-e29b-41d4-a716-446655440001',
    key: 'maven-local',
    name: 'Maven Local',
    description: 'Local Maven repository',
    format: 'maven',
    repo_type: 'local',
    is_public: false,
    artifact_count: 42,
    storage_used_bytes: 1073741824,
    created_at: '2024-01-01T00:00:00Z',
    updated_at: '2024-01-15T00:00:00Z',
  },
  {
    id: '550e8400-e29b-41d4-a716-446655440002',
    key: 'npm-local',
    name: 'NPM Local',
    description: 'Local NPM repository',
    format: 'npm',
    repo_type: 'local',
    is_public: true,
    artifact_count: 156,
    storage_used_bytes: 536870912,
    created_at: '2024-01-02T00:00:00Z',
    updated_at: '2024-01-14T00:00:00Z',
  },
]

export const mockArtifacts = [
  {
    id: '550e8400-e29b-41d4-a716-446655440010',
    repository_key: 'maven-local',
    path: 'com/example/mylib/1.0.0/mylib-1.0.0.jar',
    name: 'mylib-1.0.0.jar',
    version: '1.0.0',
    size_bytes: 1048576,
    checksum_sha256: 'a'.repeat(64),
    content_type: 'application/java-archive',
    download_count: 100,
    created_at: '2024-01-05T00:00:00Z',
    metadata: {},
  },
]

export const mockStats = {
  total_repositories: 5,
  total_artifacts: 198,
  total_storage_bytes: 2147483648,
  total_users: 3,
}

// API handlers
export const handlers = [
  // Auth endpoints
  http.post(`${API_URL}/auth/login`, async ({ request }) => {
    const body = await request.json() as { username: string; password: string }
    if (body.username === 'admin' && body.password === 'admin') {
      return HttpResponse.json({
        access_token: 'mock-access-token',
        refresh_token: 'mock-refresh-token',
        expires_in: 3600,
        token_type: 'Bearer',
      })
    }
    return HttpResponse.json(
      { code: 'UNAUTHORIZED', message: 'Invalid credentials' },
      { status: 401 }
    )
  }),

  http.post(`${API_URL}/auth/logout`, () => {
    return new HttpResponse(null, { status: 204 })
  }),

  http.get(`${API_URL}/auth/me`, ({ request }) => {
    const authHeader = request.headers.get('Authorization')
    if (!authHeader?.startsWith('Bearer ')) {
      return HttpResponse.json(
        { code: 'UNAUTHORIZED', message: 'Authentication required' },
        { status: 401 }
      )
    }
    return HttpResponse.json(mockUser)
  }),

  http.post(`${API_URL}/auth/refresh`, async ({ request }) => {
    const body = await request.json() as { refresh_token: string }
    if (body.refresh_token === 'mock-refresh-token') {
      return HttpResponse.json({
        access_token: 'mock-access-token-refreshed',
        refresh_token: 'mock-refresh-token-new',
        expires_in: 3600,
        token_type: 'Bearer',
      })
    }
    return HttpResponse.json(
      { code: 'UNAUTHORIZED', message: 'Invalid refresh token' },
      { status: 401 }
    )
  }),

  // Repositories endpoints
  http.get(`${API_URL}/repositories`, ({ request }) => {
    const url = new URL(request.url)
    const format = url.searchParams.get('format')
    const repoType = url.searchParams.get('repo_type')

    let filtered = [...mockRepositories]
    if (format) {
      filtered = filtered.filter(r => r.format === format)
    }
    if (repoType) {
      filtered = filtered.filter(r => r.repo_type === repoType)
    }

    return HttpResponse.json({
      items: filtered,
      pagination: {
        page: 1,
        per_page: 20,
        total: filtered.length,
        total_pages: 1,
      },
    })
  }),

  http.get(`${API_URL}/repositories/:key`, ({ params }) => {
    const repo = mockRepositories.find(r => r.key === params.key)
    if (!repo) {
      return HttpResponse.json(
        { code: 'NOT_FOUND', message: 'Repository not found' },
        { status: 404 }
      )
    }
    return HttpResponse.json(repo)
  }),

  http.post(`${API_URL}/repositories`, async ({ request }) => {
    const body = await request.json() as Record<string, unknown>
    const newRepo = {
      id: '550e8400-e29b-41d4-a716-446655440099',
      ...body,
      artifact_count: 0,
      storage_used_bytes: 0,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    }
    return HttpResponse.json(newRepo, { status: 201 })
  }),

  http.put(`${API_URL}/repositories/:key`, async ({ params, request }) => {
    const repo = mockRepositories.find(r => r.key === params.key)
    if (!repo) {
      return HttpResponse.json(
        { code: 'NOT_FOUND', message: 'Repository not found' },
        { status: 404 }
      )
    }
    const updates = await request.json() as Record<string, unknown>
    return HttpResponse.json({ ...repo, ...updates })
  }),

  http.delete(`${API_URL}/repositories/:key`, ({ params }) => {
    const repo = mockRepositories.find(r => r.key === params.key)
    if (!repo) {
      return HttpResponse.json(
        { code: 'NOT_FOUND', message: 'Repository not found' },
        { status: 404 }
      )
    }
    return new HttpResponse(null, { status: 204 })
  }),

  // Artifacts endpoints
  http.get(`${API_URL}/repositories/:key/artifacts`, ({ params }) => {
    const artifacts = mockArtifacts.filter(a => a.repository_key === params.key)
    return HttpResponse.json({
      items: artifacts,
      pagination: {
        page: 1,
        per_page: 20,
        total: artifacts.length,
        total_pages: 1,
      },
    })
  }),

  http.get(`${API_URL}/repositories/:key/artifacts/*`, ({ params }) => {
    const path = Array.isArray(params['0']) ? params['0'].join('/') : params['0']
    const artifact = mockArtifacts.find(
      a => a.repository_key === params.key && a.path === path
    )
    if (!artifact) {
      return HttpResponse.json(
        { code: 'NOT_FOUND', message: 'Artifact not found' },
        { status: 404 }
      )
    }
    return HttpResponse.json(artifact)
  }),

  http.delete(`${API_URL}/repositories/:key/artifacts/*`, () => {
    return new HttpResponse(null, { status: 204 })
  }),

  // Admin endpoints
  http.get(`${API_URL}/admin/stats`, () => {
    return HttpResponse.json(mockStats)
  }),

  http.get('/health', () => {
    return HttpResponse.json({
      status: 'healthy',
      version: '1.0.0',
      checks: {
        database: { status: 'healthy', message: 'Connected' },
        storage: { status: 'healthy', message: 'Available' },
      },
    })
  }),

  // Users endpoints
  http.get(`${API_URL}/users`, () => {
    return HttpResponse.json({
      items: [mockUser],
      pagination: {
        page: 1,
        per_page: 20,
        total: 1,
        total_pages: 1,
      },
    })
  }),
]
