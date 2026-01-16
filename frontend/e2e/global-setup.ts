/**
 * Global setup for E2E tests
 * Seeds the database with test data via API calls
 */

const BASE_URL = process.env.BASE_URL || 'http://localhost:5173';

async function globalSetup() {
  console.log('🌱 Seeding test data...');

  // Login to get auth token
  const loginResponse = await fetch(`${BASE_URL}/api/v1/auth/login`, {
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

  // Create test repositories
  const repositories = [
    { key: 'maven-releases', name: 'Maven Releases', description: 'Maven release artifacts', format: 'maven', repo_type: 'local', is_public: false },
    { key: 'npm-registry', name: 'NPM Registry', description: 'NPM packages', format: 'npm', repo_type: 'local', is_public: true },
    { key: 'docker-images', name: 'Docker Images', description: 'Docker container images', format: 'docker', repo_type: 'local', is_public: false },
    { key: 'pypi-packages', name: 'PyPI Packages', description: 'Python packages', format: 'pypi', repo_type: 'local', is_public: true },
    { key: 'generic-files', name: 'Generic Files', description: 'Generic file storage', format: 'generic', repo_type: 'local', is_public: false },
  ];

  for (const repo of repositories) {
    const response = await fetch(`${BASE_URL}/api/v1/repositories`, {
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
    const response = await fetch(`${BASE_URL}/api/v1/repositories/${artifact.repo}/artifacts/${artifact.path}`, {
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
