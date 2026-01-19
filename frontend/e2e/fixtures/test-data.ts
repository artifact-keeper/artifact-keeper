/**
 * Test data factory for generating unique test data.
 * All test data should be created through these factories to ensure uniqueness.
 */

/**
 * Generate a unique ID with the given prefix
 */
export function uniqueId(prefix: string): string {
  const timestamp = Date.now();
  const random = Math.random().toString(36).slice(2, 7);
  return `${prefix}-${timestamp}-${random}`;
}

/**
 * Repository configuration for tests
 */
export interface RepoConfig {
  key: string;
  name: string;
  description?: string;
  format: 'npm' | 'maven' | 'docker' | 'pypi' | 'generic' | 'helm' | 'go' | 'cargo';
  repoType: 'local' | 'remote' | 'virtual';
  upstreamUrl?: string;
  includedRepos?: string[];
  isPublic?: boolean;
}

/**
 * Generate test repository configuration
 */
export function testRepo(overrides?: Partial<RepoConfig>): RepoConfig {
  const id = uniqueId('e2e-repo');
  return {
    key: id,
    name: `E2E Test Repository ${id}`,
    description: 'Created by E2E test suite',
    format: 'generic',
    repoType: 'local',
    isPublic: false,
    ...overrides,
  };
}

/**
 * Generate test remote repository configuration
 */
export function testRemoteRepo(
  overrides?: Partial<RepoConfig & { upstreamUrl: string }>
): RepoConfig & { upstreamUrl: string } {
  const id = uniqueId('e2e-remote');
  return {
    key: id,
    name: `E2E Remote Repository ${id}`,
    description: 'Remote repository created by E2E test suite',
    format: 'npm',
    repoType: 'remote',
    isPublic: false,
    upstreamUrl: 'https://registry.npmjs.org',
    ...overrides,
  };
}

/**
 * Generate test virtual repository configuration
 */
export function testVirtualRepo(
  overrides?: Partial<RepoConfig & { includedRepos: string[] }>
): RepoConfig & { includedRepos: string[] } {
  const id = uniqueId('e2e-virtual');
  return {
    key: id,
    name: `E2E Virtual Repository ${id}`,
    description: 'Virtual repository created by E2E test suite',
    format: 'npm',
    repoType: 'virtual',
    isPublic: false,
    includedRepos: [],
    ...overrides,
  };
}

/**
 * User configuration for tests
 */
export interface UserConfig {
  username: string;
  email: string;
  password: string;
  isAdmin?: boolean;
  groups?: string[];
}

/**
 * Generate test user configuration
 */
export function testUser(overrides?: Partial<UserConfig>): UserConfig {
  const id = uniqueId('e2e-user');
  return {
    username: id,
    email: `${id}@test.example.com`,
    password: 'TestPass123!',
    isAdmin: false,
    groups: [],
    ...overrides,
  };
}

/**
 * Group configuration for tests
 */
export interface GroupConfig {
  name: string;
  description?: string;
  members?: string[];
}

/**
 * Generate test group configuration
 */
export function testGroup(overrides?: Partial<GroupConfig>): GroupConfig {
  const id = uniqueId('e2e-group');
  return {
    name: id,
    description: 'Created by E2E test suite',
    members: [],
    ...overrides,
  };
}

/**
 * Migration configuration for tests
 */
export interface MigrationConfig {
  sourceUrl: string;
  username: string;
  password: string;
  repositories: string[];
  skipExisting?: boolean;
}

/**
 * Generate test migration configuration
 */
export function testMigration(overrides?: Partial<MigrationConfig>): MigrationConfig {
  return {
    sourceUrl: 'https://artifactory.example.com',
    username: 'admin',
    password: 'password',
    repositories: ['libs-release', 'libs-snapshot'],
    skipExisting: true,
    ...overrides,
  };
}

/**
 * Test credentials
 */
export const TEST_CREDENTIALS = {
  admin: {
    username: 'admin',
    password: 'admin123',
  },
  user: {
    username: 'testuser',
    password: 'testpass',
  },
} as const;

/**
 * Common test data patterns
 */
export const TEST_PATTERNS = {
  repoKeyPrefix: 'e2e-repo-',
  userPrefix: 'e2e-user-',
  groupPrefix: 'e2e-group-',
} as const;
