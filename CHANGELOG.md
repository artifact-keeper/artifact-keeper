# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
