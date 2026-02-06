# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-a1] - 2026-02-06

First public alpha release, announced on Hacker News.

### Added
- **OWASP Dependency-Track Integration** (#46)
  - Docker service configuration for Dependency-Track API server
  - Rust API client for SBOM upload, vulnerability findings, policy violations
  - Comprehensive SBOM & Dependency-Track documentation
  - E2E test script for Dependency-Track integration
- **Multi-cloud Storage Backends** (#45)
  - Azure Blob Storage backend
  - Google Cloud Storage backend
  - Artifactory migration mode with fallback path support
- **S3 Direct Downloads** (#38)
  - 302 redirect to presigned S3 URLs
  - CloudFront signed URL generation
  - Configurable via `STORAGE_S3_REDIRECT_DOWNLOADS`
- **SBOM Generation & gRPC API** (#31)
  - CycloneDX and SPDX format support
  - CVE history tracking
  - gRPC service for SBOM operations
- **WASM Plugin E2E Tests** (#37)
- **SSO E2E Test Suite** - LDAP/OIDC/SAML authentication tests
- **TOTP Two-Factor Authentication**
- **Privacy Policy Page** for app store submissions
- **Migration Pipeline** - Artifactory and Nexus OSS support
- **OpenSCAP Multi-arch Image** with scanning enabled by default

### Changed
- Simplified and deduplicated code across backend and scripts (#27)
- Updated docs to use peer replication model instead of edge nodes
- Docker build cache optimization with cargo-chef and native arm64 runners
- Streamlined CI pipeline with CI/CD diagram in README

### Fixed
- E2E test infrastructure improvements (bootstrap, setup containers)
- CI workflow fixes (clippy warnings, YAML indentation)
- SSO e2e test infrastructure fixes
- Logo resized to exact 512x512 for app stores
- Metrics endpoint proxied through Caddy
- Various Caddy and port configuration fixes

### Security
- Secure first-boot admin password with API lock
- GitGuardian integration for secret scanning

## [1.0.0-rc.1] - 2026-02-03

### Added
- First-boot admin provisioning and Caddy reverse proxy
- OpenSCAP compliance scanner service
- Package auto-population and build tracking API
- httpOnly cookies, download tickets, and remote instance proxy
- SSO single-use exchange codes for secure token passing
- Complete SSO auth flows with real LDAP bind, SAML endpoints, and encryption key handling
- Admin-configurable SSO providers (OIDC, LDAP, SAML)
- Web frontend service in all docker-compose files
- Native apps section on landing page with macOS, iOS, Android demos

### Changed
- Use pre-built images from ghcr.io instead of local builds
- Rename frontend to web in Docker deployment docs
- Use standard port 3000 and correct BACKEND_URL env var for web service
- Clean up operations services and handlers
- Simplify SSO backend code for clarity and consistency

### Fixed
- NPM tarball URL and integrity hash in package metadata
- Hardcoded localhost:9080 fallback URLs removed from frontend
- Logo transparency using flood-fill to preserve silver highlights
- Duplicate heading on docs welcome page
- GitHub links updated to point to org instead of repo
- CORS credentials support for dev mode
