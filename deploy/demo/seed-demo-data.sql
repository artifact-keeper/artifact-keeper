-- Demo seed data for demo.artifactkeeper.com
-- Idempotent: safe to run multiple times.
-- All write operations are blocked by DEMO_MODE in the backend.

-- Create demo users (password is "demo" for all accounts)
-- Use ON CONFLICT DO UPDATE for admin so we always set the demo password
INSERT INTO users (id, username, email, password_hash, display_name, is_admin, is_active, must_change_password, created_at)
VALUES
  ('00000000-0000-0000-0000-000000000002', 'developer', 'dev@demo.artifactkeeper.com',
   '$2b$12$hz/7VwvP.R7vwpyYKbzE0ud.7G058qWPdRNRUWakNU5dyipzllIde',
   'Jane Developer', false, true, false, NOW() - interval '150 days'),
  ('00000000-0000-0000-0000-000000000003', 'viewer', 'viewer@demo.artifactkeeper.com',
   '$2b$12$hz/7VwvP.R7vwpyYKbzE0ud.7G058qWPdRNRUWakNU5dyipzllIde',
   'Read-Only User', false, true, false, NOW() - interval '120 days'),
  ('00000000-0000-0000-0000-000000000004', 'ci-bot', 'ci@demo.artifactkeeper.com',
   '$2b$12$hz/7VwvP.R7vwpyYKbzE0ud.7G058qWPdRNRUWakNU5dyipzllIde',
   'CI Pipeline Bot', false, true, false, NOW() - interval '170 days')
ON CONFLICT (username) DO NOTHING;

-- Update admin password to "demo" regardless of existing hash
UPDATE users
SET password_hash = '$2b$12$hz/7VwvP.R7vwpyYKbzE0ud.7G058qWPdRNRUWakNU5dyipzllIde',
    must_change_password = false
WHERE username = 'admin';

-- Store admin ID for FK references
DO $$
DECLARE admin_id uuid;
BEGIN
  SELECT id INTO admin_id FROM users WHERE username = 'admin';

  -- ============================================================================
  -- Repositories — public and private across many formats
  -- ============================================================================

  INSERT INTO repositories (id, key, name, description, format, repo_type, storage_path, is_public, created_at)
  VALUES
    -- Public repositories
    ('10000000-0000-0000-0000-000000000001', 'maven-releases', 'Maven Releases',
     'Production-ready Java/Kotlin artifacts. All releases go through full CI/CD pipeline with Trivy scanning.',
     'maven', 'local', '/data/storage/maven-releases', true, NOW() - interval '180 days'),

    ('10000000-0000-0000-0000-000000000002', 'npm-public', 'NPM Public',
     'Open-source npm packages published by the team. Includes design system, CLI tools, and shared configs.',
     'npm', 'local', '/data/storage/npm-public', true, NOW() - interval '160 days'),

    ('10000000-0000-0000-0000-000000000003', 'docker-images', 'Docker Images',
     'Container images for all microservices. Multi-arch builds (amd64/arm64). Scanned on every push.',
     'docker', 'local', '/data/storage/docker-images', true, NOW() - interval '150 days'),

    ('10000000-0000-0000-0000-000000000004', 'pypi-packages', 'PyPI Packages',
     'Python packages for data engineering and ML pipelines. Compatible with pip and Poetry.',
     'pypi', 'local', '/data/storage/pypi-packages', true, NOW() - interval '140 days'),

    ('10000000-0000-0000-0000-000000000005', 'helm-charts', 'Helm Charts',
     'Kubernetes Helm charts for production deployments. Includes monitoring, ingress, and service mesh.',
     'helm', 'local', '/data/storage/helm-charts', true, NOW() - interval '130 days'),

    ('10000000-0000-0000-0000-000000000006', 'cargo-crates', 'Cargo Crates',
     'Internal Rust crates for high-performance services. Shared serialization, networking, and crypto libraries.',
     'cargo', 'local', '/data/storage/cargo-crates', true, NOW() - interval '120 days'),

    ('10000000-0000-0000-0000-000000000007', 'nuget-packages', 'NuGet Packages',
     '.NET packages for backend services and shared libraries. Targets .NET 8 LTS.',
     'nuget', 'local', '/data/storage/nuget-packages', true, NOW() - interval '110 days'),

    ('10000000-0000-0000-0000-000000000008', 'go-modules', 'Go Modules',
     'Go modules for CLI tools and infrastructure automation. Uses Go 1.22+ with generics.',
     'go', 'local', '/data/storage/go-modules', true, NOW() - interval '100 days'),

    ('10000000-0000-0000-0000-000000000009', 'debian-packages', 'Debian Packages',
     'APT repository for Ubuntu/Debian server packages. GPG-signed with automated builds.',
     'debian', 'local', '/data/storage/debian-packages', true, NOW() - interval '90 days'),

    ('10000000-0000-0000-0000-000000000010', 'rpm-packages', 'RPM Packages',
     'YUM/DNF repository for RHEL/Fedora/CentOS packages. RPM-signed releases.',
     'rpm', 'local', '/data/storage/rpm-packages', true, NOW() - interval '85 days'),

    -- Private repositories
    ('10000000-0000-0000-0000-000000000011', 'npm-internal', 'NPM Internal',
     'Private npm packages for internal microservices. Includes auth middleware, logging, and API clients.',
     'npm', 'local', '/data/storage/npm-internal', false, NOW() - interval '155 days'),

    ('10000000-0000-0000-0000-000000000012', 'docker-staging', 'Docker Staging',
     'Pre-release container images for staging environment. Auto-cleaned after 30 days.',
     'docker', 'local', '/data/storage/docker-staging', false, NOW() - interval '120 days'),

    ('10000000-0000-0000-0000-000000000013', 'maven-snapshots', 'Maven Snapshots',
     'Development snapshots from CI. Retained for 14 days. Not for production use.',
     'maven', 'local', '/data/storage/maven-snapshots', false, NOW() - interval '175 days'),

    ('10000000-0000-0000-0000-000000000014', 'terraform-modules', 'Terraform Modules',
     'Infrastructure-as-code modules for AWS, GCP, and Azure. Versioned with semantic versioning.',
     'terraform', 'local', '/data/storage/terraform-modules', false, NOW() - interval '70 days'),

    ('10000000-0000-0000-0000-000000000015', 'conda-packages', 'Conda Packages',
     'Data science packages for Conda environments. Includes GPU-optimized builds.',
     'conda', 'local', '/data/storage/conda-packages', false, NOW() - interval '60 days')
  ON CONFLICT (key) DO NOTHING;

  -- ============================================================================
  -- Artifacts (use admin_id for admin-uploaded, fixed IDs for other users)
  -- ============================================================================

  -- Maven Releases
  INSERT INTO artifacts (id, repository_id, name, version, path, size_bytes, checksum_sha256, content_type, storage_key, uploaded_by, created_at)
  VALUES
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000001', 'com.example:auth-service', '2.4.1',
     'com/example/auth-service/2.4.1/auth-service-2.4.1.jar', 4521984,
     'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2', 'application/java-archive',
     'maven-releases/com/example/auth-service/2.4.1/auth-service-2.4.1.jar',
     '00000000-0000-0000-0000-000000000002', NOW() - interval '30 days'),
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000001', 'com.example:payment-gateway', '1.8.0',
     'com/example/payment-gateway/1.8.0/payment-gateway-1.8.0.jar', 3145728,
     'b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3', 'application/java-archive',
     'maven-releases/com/example/payment-gateway/1.8.0/payment-gateway-1.8.0.jar',
     '00000000-0000-0000-0000-000000000002', NOW() - interval '25 days'),
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000001', 'com.example:user-api', '3.1.0',
     'com/example/user-api/3.1.0/user-api-3.1.0.jar', 2097152,
     'c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4', 'application/java-archive',
     'maven-releases/com/example/user-api/3.1.0/user-api-3.1.0.jar',
     '00000000-0000-0000-0000-000000000002', NOW() - interval '20 days'),
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000001', 'com.example:notification-service', '1.2.3',
     'com/example/notification-service/1.2.3/notification-service-1.2.3.jar', 1572864,
     'd4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5', 'application/java-archive',
     'maven-releases/com/example/notification-service/1.2.3/notification-service-1.2.3.jar',
     '00000000-0000-0000-0000-000000000004', NOW() - interval '15 days'),
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000001', 'com.example:commons-utils', '5.0.2',
     'com/example/commons-utils/5.0.2/commons-utils-5.0.2.jar', 524288,
     'e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6', 'application/java-archive',
     'maven-releases/com/example/commons-utils/5.0.2/commons-utils-5.0.2.jar',
     '00000000-0000-0000-0000-000000000004', NOW() - interval '10 days'),
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000001', 'com.example:event-bus', '2.0.0',
     'com/example/event-bus/2.0.0/event-bus-2.0.0.jar', 1835008,
     'f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1', 'application/java-archive',
     'maven-releases/com/example/event-bus/2.0.0/event-bus-2.0.0.jar',
     '00000000-0000-0000-0000-000000000004', NOW() - interval '5 days')
  ON CONFLICT DO NOTHING;

  -- NPM Public
  INSERT INTO artifacts (id, repository_id, name, version, path, size_bytes, checksum_sha256, content_type, storage_key, uploaded_by, created_at)
  VALUES
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000002', '@acme/design-system', '4.2.0',
     '@acme/design-system/-/design-system-4.2.0.tgz', 1048576,
     'a1a2a3a4a5a6a7a8a9a0b1b2b3b4b5b6b7b8b9b0c1c2c3c4c5c6c7c8c9c0d1d2', 'application/gzip',
     'npm-public/@acme/design-system/-/design-system-4.2.0.tgz',
     '00000000-0000-0000-0000-000000000002', NOW() - interval '28 days'),
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000002', '@acme/eslint-config', '2.1.0',
     '@acme/eslint-config/-/eslint-config-2.1.0.tgz', 32768,
     'b1b2b3b4b5b6b7b8b9b0c1c2c3c4c5c6c7c8c9c0d1d2d3d4d5d6d7d8d9d0e1e2', 'application/gzip',
     'npm-public/@acme/eslint-config/-/eslint-config-2.1.0.tgz',
     '00000000-0000-0000-0000-000000000002', NOW() - interval '22 days'),
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000002', '@acme/api-client', '3.5.1',
     '@acme/api-client/-/api-client-3.5.1.tgz', 262144,
     'c1c2c3c4c5c6c7c8c9c0d1d2d3d4d5d6d7d8d9d0e1e2e3e4e5e6e7e8e9e0f1f2', 'application/gzip',
     'npm-public/@acme/api-client/-/api-client-3.5.1.tgz',
     '00000000-0000-0000-0000-000000000002', NOW() - interval '18 days'),
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000002', '@acme/react-hooks', '1.8.0',
     '@acme/react-hooks/-/react-hooks-1.8.0.tgz', 98304,
     'd1d2d3d4d5d6d7d8d9d0e1e2e3e4e5e6e7e8e9e0f1f2f3f4f5f6f7f8f9f0a1a2', 'application/gzip',
     'npm-public/@acme/react-hooks/-/react-hooks-1.8.0.tgz',
     '00000000-0000-0000-0000-000000000004', NOW() - interval '12 days'),
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000002', '@acme/logger', '1.0.8',
     '@acme/logger/-/logger-1.0.8.tgz', 65536,
     'e1e2e3e4e5e6e7e8e9e0f1f2f3f4f5f6f7f8f9f0a1a2a3a4a5a6a7a8a9a0b1b2', 'application/gzip',
     'npm-public/@acme/logger/-/logger-1.0.8.tgz',
     '00000000-0000-0000-0000-000000000004', NOW() - interval '8 days')
  ON CONFLICT DO NOTHING;

  -- Docker Images
  INSERT INTO artifacts (id, repository_id, name, version, path, size_bytes, checksum_sha256, content_type, storage_key, uploaded_by, created_at)
  VALUES
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000003', 'api-gateway', 'v2.1.0',
     'api-gateway/v2.1.0/manifest.json', 157286400,
     'f1f2f3f4f5f6f7f8f9f0a1a2a3a4a5a6a7a8a9a0b1b2b3b4b5b6b7b8b9b0c1c2', 'application/vnd.docker.distribution.manifest.v2+json',
     'docker-images/api-gateway/v2.1.0/manifest.json',
     '00000000-0000-0000-0000-000000000004', NOW() - interval '14 days'),
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000003', 'web-frontend', 'v3.0.0',
     'web-frontend/v3.0.0/manifest.json', 209715200,
     'a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3', 'application/vnd.docker.distribution.manifest.v2+json',
     'docker-images/web-frontend/v3.0.0/manifest.json',
     '00000000-0000-0000-0000-000000000004', NOW() - interval '7 days'),
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000003', 'worker-service', 'v1.5.2',
     'worker-service/v1.5.2/manifest.json', 104857600,
     'b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4', 'application/vnd.docker.distribution.manifest.v2+json',
     'docker-images/worker-service/v1.5.2/manifest.json',
     '00000000-0000-0000-0000-000000000004', NOW() - interval '3 days'),
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000003', 'ml-inference', 'v0.9.1',
     'ml-inference/v0.9.1/manifest.json', 524288000,
     'c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5', 'application/vnd.docker.distribution.manifest.v2+json',
     'docker-images/ml-inference/v0.9.1/manifest.json',
     '00000000-0000-0000-0000-000000000002', NOW() - interval '1 day')
  ON CONFLICT DO NOTHING;

  -- PyPI Packages
  INSERT INTO artifacts (id, repository_id, name, version, path, size_bytes, checksum_sha256, content_type, storage_key, uploaded_by, created_at)
  VALUES
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000004', 'acme-ml-pipeline', '1.3.0',
     'acme-ml-pipeline/1.3.0/acme_ml_pipeline-1.3.0-py3-none-any.whl', 2097152,
     'd5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6', 'application/zip',
     'pypi-packages/acme-ml-pipeline/1.3.0/acme_ml_pipeline-1.3.0-py3-none-any.whl',
     '00000000-0000-0000-0000-000000000002', NOW() - interval '21 days'),
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000004', 'acme-data-utils', '2.0.1',
     'acme-data-utils/2.0.1/acme_data_utils-2.0.1-py3-none-any.whl', 524288,
     'e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7', 'application/zip',
     'pypi-packages/acme-data-utils/2.0.1/acme_data_utils-2.0.1-py3-none-any.whl',
     '00000000-0000-0000-0000-000000000002', NOW() - interval '16 days'),
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000004', 'acme-auth-sdk', '3.2.0',
     'acme-auth-sdk/3.2.0/acme_auth_sdk-3.2.0-py3-none-any.whl', 131072,
     'f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8', 'application/zip',
     'pypi-packages/acme-auth-sdk/3.2.0/acme_auth_sdk-3.2.0-py3-none-any.whl',
     '00000000-0000-0000-0000-000000000004', NOW() - interval '9 days')
  ON CONFLICT DO NOTHING;

  -- Helm Charts (use admin_id for admin-uploaded ones)
  INSERT INTO artifacts (id, repository_id, name, version, path, size_bytes, checksum_sha256, content_type, storage_key, uploaded_by, created_at)
  VALUES
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000005', 'api-gateway-chart', '1.5.0',
     'api-gateway-chart-1.5.0.tgz', 32768,
     'a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9', 'application/gzip',
     'helm-charts/api-gateway-chart-1.5.0.tgz',
     admin_id, NOW() - interval '19 days'),
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000005', 'monitoring-stack', '2.0.0',
     'monitoring-stack-2.0.0.tgz', 65536,
     'b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0', 'application/gzip',
     'helm-charts/monitoring-stack-2.0.0.tgz',
     admin_id, NOW() - interval '11 days'),
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000005', 'redis-ha', '3.1.2',
     'redis-ha-3.1.2.tgz', 16384,
     'c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1', 'application/gzip',
     'helm-charts/redis-ha-3.1.2.tgz',
     '00000000-0000-0000-0000-000000000004', NOW() - interval '6 days')
  ON CONFLICT DO NOTHING;

  -- Cargo Crates
  INSERT INTO artifacts (id, repository_id, name, version, path, size_bytes, checksum_sha256, content_type, storage_key, uploaded_by, created_at)
  VALUES
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000006', 'acme-proto', '0.12.0',
     'acme-proto/0.12.0/acme-proto-0.12.0.crate', 262144,
     'aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44', 'application/gzip',
     'cargo-crates/acme-proto/0.12.0/acme-proto-0.12.0.crate',
     '00000000-0000-0000-0000-000000000002', NOW() - interval '35 days'),
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000006', 'acme-crypto', '1.4.0',
     'acme-crypto/1.4.0/acme-crypto-1.4.0.crate', 196608,
     'bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55', 'application/gzip',
     'cargo-crates/acme-crypto/1.4.0/acme-crypto-1.4.0.crate',
     '00000000-0000-0000-0000-000000000002', NOW() - interval '20 days')
  ON CONFLICT DO NOTHING;

  -- NuGet Packages
  INSERT INTO artifacts (id, repository_id, name, version, path, size_bytes, checksum_sha256, content_type, storage_key, uploaded_by, created_at)
  VALUES
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000007', 'Acme.Core', '6.1.0',
     'acme.core/6.1.0/acme.core.6.1.0.nupkg', 524288,
     'dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11', 'application/octet-stream',
     'nuget-packages/acme.core/6.1.0/acme.core.6.1.0.nupkg',
     '00000000-0000-0000-0000-000000000002', NOW() - interval '40 days'),
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000007', 'Acme.EntityFramework', '3.0.2',
     'acme.entityframework/3.0.2/acme.entityframework.3.0.2.nupkg', 393216,
     'ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22', 'application/octet-stream',
     'nuget-packages/acme.entityframework/3.0.2/acme.entityframework.3.0.2.nupkg',
     '00000000-0000-0000-0000-000000000002', NOW() - interval '18 days')
  ON CONFLICT DO NOTHING;

  -- Go Modules
  INSERT INTO artifacts (id, repository_id, name, version, path, size_bytes, checksum_sha256, content_type, storage_key, uploaded_by, created_at)
  VALUES
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000008', 'github.com/acme/infra-cli', 'v1.7.0',
     'github.com/acme/infra-cli/@v/v1.7.0.zip', 3145728,
     '1122334455667788990011223344556677889900112233445566778899001122', 'application/zip',
     'go-modules/github.com/acme/infra-cli/@v/v1.7.0.zip',
     '00000000-0000-0000-0000-000000000002', NOW() - interval '15 days')
  ON CONFLICT DO NOTHING;

  -- Debian Packages
  INSERT INTO artifacts (id, repository_id, name, version, path, size_bytes, checksum_sha256, content_type, storage_key, uploaded_by, created_at)
  VALUES
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000009', 'acme-agent', '1.2.0-1',
     'pool/main/a/acme-agent/acme-agent_1.2.0-1_amd64.deb', 8388608,
     '3344556677889900112233445566778899001122334455667788990011223344', 'application/vnd.debian.binary-package',
     'debian-packages/pool/main/a/acme-agent/acme-agent_1.2.0-1_amd64.deb',
     '00000000-0000-0000-0000-000000000004', NOW() - interval '22 days'),
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000009', 'acme-collector', '0.9.5-1',
     'pool/main/a/acme-collector/acme-collector_0.9.5-1_amd64.deb', 4194304,
     '4455667788990011223344556677889900112233445566778899001122334455', 'application/vnd.debian.binary-package',
     'debian-packages/pool/main/a/acme-collector/acme-collector_0.9.5-1_amd64.deb',
     '00000000-0000-0000-0000-000000000004', NOW() - interval '10 days')
  ON CONFLICT DO NOTHING;

  -- RPM Packages
  INSERT INTO artifacts (id, repository_id, name, version, path, size_bytes, checksum_sha256, content_type, storage_key, uploaded_by, created_at)
  VALUES
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000010', 'acme-agent', '1.2.0-1.el9',
     'Packages/acme-agent-1.2.0-1.el9.x86_64.rpm', 9437184,
     '5566778899001122334455667788990011223344556677889900112233445566', 'application/x-rpm',
     'rpm-packages/Packages/acme-agent-1.2.0-1.el9.x86_64.rpm',
     '00000000-0000-0000-0000-000000000004', NOW() - interval '22 days')
  ON CONFLICT DO NOTHING;

  -- NPM Internal (private)
  INSERT INTO artifacts (id, repository_id, name, version, path, size_bytes, checksum_sha256, content_type, storage_key, uploaded_by, created_at)
  VALUES
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000011', '@acme-internal/auth-middleware', '2.0.3',
     '@acme-internal/auth-middleware/-/auth-middleware-2.0.3.tgz', 131072,
     '7788990011223344556677889900112233445566778899001122334455667788', 'application/gzip',
     'npm-internal/@acme-internal/auth-middleware/-/auth-middleware-2.0.3.tgz',
     '00000000-0000-0000-0000-000000000002', NOW() - interval '5 days'),
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000011', '@acme-internal/feature-flags', '0.4.1',
     '@acme-internal/feature-flags/-/feature-flags-0.4.1.tgz', 49152,
     '9900112233445566778899001122334455667788990011223344556677889900', 'application/gzip',
     'npm-internal/@acme-internal/feature-flags/-/feature-flags-0.4.1.tgz',
     '00000000-0000-0000-0000-000000000004', NOW() - interval '1 day')
  ON CONFLICT DO NOTHING;

  -- Docker Staging (private)
  INSERT INTO artifacts (id, repository_id, name, version, path, size_bytes, checksum_sha256, content_type, storage_key, uploaded_by, created_at)
  VALUES
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000012', 'api-gateway', 'v2.2.0-rc3',
     'api-gateway/v2.2.0-rc3/manifest.json', 162529280,
     'aabb11223344556677889900aabbccddeeff00112233445566778899aabbccdd', 'application/vnd.docker.distribution.manifest.v2+json',
     'docker-staging/api-gateway/v2.2.0-rc3/manifest.json',
     '00000000-0000-0000-0000-000000000004', NOW() - interval '1 day')
  ON CONFLICT DO NOTHING;

  -- Maven Snapshots (private)
  INSERT INTO artifacts (id, repository_id, name, version, path, size_bytes, checksum_sha256, content_type, storage_key, uploaded_by, created_at)
  VALUES
    (gen_random_uuid(), '10000000-0000-0000-0000-000000000013', 'com.example:auth-service', '2.5.0-SNAPSHOT',
     'com/example/auth-service/2.5.0-SNAPSHOT/auth-service-2.5.0-20260131.jar', 4653056,
     'ccdd11223344556677889900aabbccddeeff00112233445566778899aabbccdd', 'application/java-archive',
     'maven-snapshots/com/example/auth-service/2.5.0-SNAPSHOT/auth-service-2.5.0-20260131.jar',
     '00000000-0000-0000-0000-000000000004', NOW() - interval '3 hours')
  ON CONFLICT DO NOTHING;

  -- ============================================================================
  -- Audit log entries (correlation_id is required NOT NULL uuid)
  -- ============================================================================

  INSERT INTO audit_log (id, user_id, action, resource_type, resource_id, details, ip_address, correlation_id, created_at)
  VALUES
    (gen_random_uuid(), admin_id, 'create', 'repository', NULL,
     '{"key": "maven-releases", "format": "maven"}',
     '10.0.1.1', gen_random_uuid(), NOW() - interval '180 days'),
    (gen_random_uuid(), '00000000-0000-0000-0000-000000000002', 'upload', 'artifact', NULL,
     '{"name": "com.example:auth-service", "version": "2.4.1", "repo": "maven-releases"}',
     '10.0.1.50', gen_random_uuid(), NOW() - interval '30 days'),
    (gen_random_uuid(), '00000000-0000-0000-0000-000000000004', 'upload', 'artifact', NULL,
     '{"name": "api-gateway", "version": "v2.1.0", "repo": "docker-images"}',
     '10.0.1.100', gen_random_uuid(), NOW() - interval '14 days'),
    (gen_random_uuid(), '00000000-0000-0000-0000-000000000003', 'download', 'artifact', NULL,
     '{"name": "@acme/api-client", "version": "3.5.1", "repo": "npm-public"}',
     '10.0.2.101', gen_random_uuid(), NOW() - interval '5 days'),
    (gen_random_uuid(), admin_id, 'scan', 'repository', NULL,
     '{"repo": "docker-images", "scanner": "trivy", "vulnerabilities": {"critical": 0, "high": 2, "medium": 5}}',
     '10.0.1.1', gen_random_uuid(), NOW() - interval '2 days')
  ON CONFLICT DO NOTHING;

END $$;
