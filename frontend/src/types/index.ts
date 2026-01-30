// API Response types

// Re-export all type modules
export * from './groups';
export * from './migration';
export * from './permissions';
export * from './packages';
export * from './builds';
export * from './search';
export * from './tree';
export * from './security';

export interface User {
  id: string;
  username: string;
  email: string;
  display_name?: string;
  is_admin: boolean;
  is_active?: boolean;
  must_change_password?: boolean;
}

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: string;
  must_change_password: boolean;
}

export interface CreateUserResponse {
  user: User;
  generated_password?: string;
}

export interface Repository {
  id: string;
  key: string;
  name: string;
  description?: string;
  format: RepositoryFormat;
  repo_type: RepositoryType;
  is_public: boolean;
  storage_used_bytes: number;
  quota_bytes?: number;
  created_at: string;
  updated_at: string;
}

export type RepositoryFormat =
  | 'maven'
  | 'pypi'
  | 'npm'
  | 'docker'
  | 'helm'
  | 'rpm'
  | 'debian'
  | 'go'
  | 'nuget'
  | 'cargo'
  | 'generic';

export type RepositoryType = 'local' | 'remote' | 'virtual';

export interface CreateRepositoryRequest {
  key: string;
  name: string;
  description?: string;
  format: RepositoryFormat;
  repo_type: RepositoryType;
  is_public?: boolean;
  quota_bytes?: number;
}

export interface Artifact {
  id: string;
  repository_key: string;
  path: string;
  name: string;
  version?: string;
  size_bytes: number;
  checksum_sha256: string;
  content_type: string;
  download_count: number;
  created_at: string;
  metadata?: Record<string, unknown>;
}

export interface PaginatedResponse<T> {
  items: T[];
  pagination: {
    page: number;
    per_page: number;
    total: number;
    total_pages: number;
  };
}

export interface HealthResponse {
  status: string;
  version: string;
  checks: {
    database: { status: string };
    storage: { status: string };
  };
}

export interface AdminStats {
  total_repositories: number;
  total_artifacts: number;
  total_storage_bytes: number;
  total_users: number;
}

export interface ApiError {
  code: string;
  message: string;
}
