-- E2E Test Seed Data
-- This script creates test repositories and artifacts for E2E testing

-- Wait for migrations to complete (the backend runs migrations on startup)
-- This seed data will be inserted after the schema is created

-- Insert test repositories
INSERT INTO repositories (id, key, name, description, format, repo_type, storage_backend, storage_path, is_public, created_at, updated_at)
VALUES
    ('11111111-1111-1111-1111-111111111111', 'maven-releases', 'Maven Releases', 'Maven release artifacts', 'maven', 'local', 'filesystem', 'data/repositories/maven-releases', false, NOW(), NOW()),
    ('22222222-2222-2222-2222-222222222222', 'npm-registry', 'NPM Registry', 'NPM packages', 'npm', 'local', 'filesystem', 'data/repositories/npm-registry', true, NOW(), NOW()),
    ('33333333-3333-3333-3333-333333333333', 'docker-images', 'Docker Images', 'Docker container images', 'docker', 'local', 'filesystem', 'data/repositories/docker-images', false, NOW(), NOW()),
    ('44444444-4444-4444-4444-444444444444', 'pypi-packages', 'PyPI Packages', 'Python packages', 'pypi', 'local', 'filesystem', 'data/repositories/pypi-packages', true, NOW(), NOW()),
    ('55555555-5555-5555-5555-555555555555', 'generic-files', 'Generic Files', 'Generic file storage', 'generic', 'local', 'filesystem', 'data/repositories/generic-files', false, NOW(), NOW())
ON CONFLICT (key) DO NOTHING;

-- Insert test artifacts for maven-releases repository
INSERT INTO artifacts (id, repository_id, path, name, version, size_bytes, checksum_sha256, content_type, download_count, created_at)
VALUES
    ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', '11111111-1111-1111-1111-111111111111', 'com/example/app/1.0.0/app-1.0.0.jar', 'app-1.0.0.jar', '1.0.0', 1024000, 'abc123def456789', 'application/java-archive', 42, NOW()),
    ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', '11111111-1111-1111-1111-111111111111', 'com/example/app/1.0.0/app-1.0.0.pom', 'app-1.0.0.pom', '1.0.0', 2048, 'def456abc789123', 'application/xml', 15, NOW()),
    ('cccccccc-cccc-cccc-cccc-cccccccccccc', '11111111-1111-1111-1111-111111111111', 'com/example/lib/2.1.0/lib-2.1.0.jar', 'lib-2.1.0.jar', '2.1.0', 512000, 'ghi789jkl012345', 'application/java-archive', 28, NOW())
ON CONFLICT (repository_id, path) DO NOTHING;

-- Insert test artifacts for npm-registry repository
INSERT INTO artifacts (id, repository_id, path, name, version, size_bytes, checksum_sha256, content_type, download_count, created_at)
VALUES
    ('dddddddd-dddd-dddd-dddd-dddddddddddd', '22222222-2222-2222-2222-222222222222', '@myorg/utils/1.2.3/utils-1.2.3.tgz', 'utils-1.2.3.tgz', '1.2.3', 45000, 'npm123hash456', 'application/gzip', 156, NOW()),
    ('eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee', '22222222-2222-2222-2222-222222222222', 'lodash/4.17.21/lodash-4.17.21.tgz', 'lodash-4.17.21.tgz', '4.17.21', 528000, 'lodash789hash', 'application/gzip', 9999, NOW())
ON CONFLICT (repository_id, path) DO NOTHING;

-- Insert test artifacts for generic-files repository
INSERT INTO artifacts (id, repository_id, path, name, version, size_bytes, checksum_sha256, content_type, download_count, created_at)
VALUES
    ('ffffffff-ffff-ffff-ffff-ffffffffffff', '55555555-5555-5555-5555-555555555555', 'docs/readme.pdf', 'readme.pdf', NULL, 102400, 'pdf123hash456', 'application/pdf', 5, NOW())
ON CONFLICT (repository_id, path) DO NOTHING;
