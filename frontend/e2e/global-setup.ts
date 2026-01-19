/**
 * Global setup for E2E tests
 * Seeds the database with test data via API calls
 * Cleans up stale E2E test data before seeding
 */

import { TEST_PATTERNS } from './fixtures/test-data';

const BASE_URL = process.env.BASE_URL || 'http://localhost:5173';
const API_URL = process.env.API_URL || 'http://localhost:8080';

/**
 * Clean up stale E2E test resources before running tests
 */
async function cleanupStaleTestData(authHeaders: Record<string, string>): Promise<void> {
  console.log('🧹 Cleaning up stale E2E test data...');

  // Clean up repositories with E2E prefix
  try {
    const reposResponse = await fetch(`${API_URL}/api/v1/repositories`, {
      headers: authHeaders,
    });

    if (reposResponse.ok) {
      const data = await reposResponse.json();
      const repos = data.items || data || [];

      for (const repo of repos) {
        if (repo.key?.startsWith(TEST_PATTERNS.repoKeyPrefix)) {
          const deleteResponse = await fetch(
            `${API_URL}/api/v1/repositories/${repo.key}`,
            { method: 'DELETE', headers: authHeaders }
          );
          if (deleteResponse.ok) {
            console.log(`  🗑️  Deleted stale repo: ${repo.key}`);
          }
        }
      }
    }
  } catch (error) {
    console.warn('  ⚠️  Failed to clean up repositories:', error);
  }

  // Clean up users with E2E prefix
  try {
    const usersResponse = await fetch(`${API_URL}/api/v1/users`, {
      headers: authHeaders,
    });

    if (usersResponse.ok) {
      const data = await usersResponse.json();
      const users = data.items || data || [];

      for (const user of users) {
        if (user.username?.startsWith(TEST_PATTERNS.userPrefix)) {
          const deleteResponse = await fetch(
            `${API_URL}/api/v1/users/${user.username}`,
            { method: 'DELETE', headers: authHeaders }
          );
          if (deleteResponse.ok) {
            console.log(`  🗑️  Deleted stale user: ${user.username}`);
          }
        }
      }
    }
  } catch (error) {
    console.warn('  ⚠️  Failed to clean up users:', error);
  }

  // Clean up groups with E2E prefix
  try {
    const groupsResponse = await fetch(`${API_URL}/api/v1/groups`, {
      headers: authHeaders,
    });

    if (groupsResponse.ok) {
      const data = await groupsResponse.json();
      const groups = data.items || data || [];

      for (const group of groups) {
        if (group.name?.startsWith(TEST_PATTERNS.groupPrefix)) {
          const deleteResponse = await fetch(
            `${API_URL}/api/v1/groups/${group.name}`,
            { method: 'DELETE', headers: authHeaders }
          );
          if (deleteResponse.ok) {
            console.log(`  🗑️  Deleted stale group: ${group.name}`);
          }
        }
      }
    }
  } catch (error) {
    console.warn('  ⚠️  Failed to clean up groups:', error);
  }

  console.log('🧹 Cleanup complete!');
}

async function globalSetup() {
  console.log('🌱 Starting E2E test setup...');

  // Login to get auth token (use API_URL for direct backend calls)
  const loginResponse = await fetch(`${API_URL}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: 'admin123' }),
  });

  if (!loginResponse.ok) {
    console.error('Failed to login for seeding:', await loginResponse.text());
    throw new Error('Failed to login for test data seeding');
  }

  const { access_token } = await loginResponse.json();
  const authHeaders = {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${access_token}`,
  };

  // Clean up stale test data first
  await cleanupStaleTestData(authHeaders);

  console.log('🌱 Seeding test data...');

  // Create test repositories
  const repositories = [
    { key: 'maven-releases', name: 'Maven Releases', description: 'Maven release artifacts', format: 'maven', repo_type: 'local', is_public: false },
    { key: 'npm-registry', name: 'NPM Registry', description: 'NPM packages', format: 'npm', repo_type: 'local', is_public: true },
    { key: 'docker-images', name: 'Docker Images', description: 'Docker container images', format: 'docker', repo_type: 'local', is_public: false },
    { key: 'pypi-packages', name: 'PyPI Packages', description: 'Python packages', format: 'pypi', repo_type: 'local', is_public: true },
    { key: 'generic-files', name: 'Generic Files', description: 'Generic file storage', format: 'generic', repo_type: 'local', is_public: false },
  ];

  for (const repo of repositories) {
    const response = await fetch(`${API_URL}/api/v1/repositories`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify(repo),
    });

    if (response.ok) {
      console.log(`  ✅ Created repository: ${repo.key}`);
    } else if (response.status === 409) {
      console.log(`  ⏭️  Repository already exists: ${repo.key}`);
    } else {
      console.warn(`  ⚠️  Failed to create ${repo.key}:`, await response.text());
    }
  }

  // Upload test artifacts to maven-releases
  const testArtifacts = [
    { repo: 'maven-releases', path: 'com/example/app/1.0.0/app-1.0.0.jar', content: 'test jar content' },
    { repo: 'maven-releases', path: 'com/example/app/1.0.0/app-1.0.0.pom', content: '<project><version>1.0.0</version></project>' },
    { repo: 'npm-registry', path: '@myorg/utils/1.2.3/package.json', content: '{"name":"@myorg/utils","version":"1.2.3"}' },
    { repo: 'generic-files', path: 'docs/readme.txt', content: 'This is a test readme file for E2E testing.' },
  ];

  for (const artifact of testArtifacts) {
    const response = await fetch(`${API_URL}/api/v1/repositories/${artifact.repo}/artifacts/${artifact.path}`, {
      method: 'PUT',
      headers: {
        ...authHeaders,
        'Content-Type': 'application/octet-stream',
      },
      body: artifact.content,
    });

    if (response.ok) {
      console.log(`  ✅ Uploaded artifact: ${artifact.repo}/${artifact.path}`);
    } else if (response.status === 409) {
      console.log(`  ⏭️  Artifact already exists: ${artifact.path}`);
    } else {
      console.warn(`  ⚠️  Failed to upload ${artifact.path}:`, await response.text());
    }
  }

  console.log('🌱 Test data seeding complete!');
}

export default globalSetup;
