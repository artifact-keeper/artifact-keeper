# Changelog

All notable changes to Artifact Keeper will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### 45+ Package Format Support
- Expanded from 11 to 45+ package format types with native protocol handlers
- **P1 formats**: npm, Maven, Cargo, NuGet, Go, RubyGems, RPM, Debian — full native registry APIs
- **P2 formats**: Helm, Conan, Composer, Alpine, Conda, Terraform — native protocol handlers
- **P3 formats**: Hex, CocoaPods, Swift, Pub/Dart, Git LFS, Chef, Puppet, Ansible, SBT, VS Code, JetBrains, HuggingFace, ML Model, CRAN, Vagrant, OPKG, P2/Eclipse, Bazel
- OCI aliases: Docker, Podman, Buildx, ORAS, WASM OCI, Helm OCI all route through unified OCI handler
- PyPI aliases: Poetry and Conda share PyPI handler
- NPM aliases: Yarn, Bower, pnpm share NPM handler
- NuGet aliases: Chocolatey and PowerShell share NuGet handler
- Terraform alias: OpenTofu shares Terraform handler
- VS Code aliases: Cursor, Windsurf, Kiro share VS Code handler
- `FormatHandler` trait shared between native Rust handlers and WASM plugins
- Simple Icons brand SVGs for all format types in frontend

#### OCI Distribution Spec
- Full Docker Registry V2 / OCI Distribution Spec implementation
- Blob upload (monolithic and chunked), manifest push/pull, tag listing
- Content-addressable storage with SHA-256 digest verification

#### Security Scanning Pipeline
- Trivy filesystem scanner for archive-based artifacts (wheels, JARs, tarballs, crates)
- Grype dependency scanner for SBOM-based vulnerability analysis
- Scan-on-upload with configurable per-repository scan policies
- SHA-256 hash-based scan deduplication (skip re-scanning identical content)
- Vulnerability scoring system with A through F grades
- Policy engine: block or quarantine artifacts exceeding severity thresholds
- Security dashboard, scan detail pages, and per-artifact security tab in frontend
- Trivy and Meilisearch health checks on admin dashboard
- Searchable scan dropdowns and severity filters in frontend

#### GPG/RSA Artifact Signing
- Signing key management system supporting GPG and RSA key types
- Integrated signing into Debian (Release/InRelease files)
- Integrated signing into RPM (repomd.xml)
- Integrated signing into Alpine (APKINDEX)
- Integrated signing into Conda (repodata.json)
- Key generation scripts in `.pki/` for development and testing

#### Meilisearch Full-Text Search
- Meilisearch integration for indexing artifacts and repositories
- Server-side search with filters, sorting, and faceting
- Automatic index creation and background reindex on startup
- Index hooks on artifact upload, update, and deletion
- Admin reindex endpoint for manual full reindex
- Search integrated into repository list and security scan modal

#### Borg Replication System
- Edge node registration, health monitoring, and status tracking
- Chunked transfer protocol for reliable artifact distribution
- Peer-to-peer replication between edge nodes (mesh topology)
- Network-aware scheduling with bandwidth and latency profiling
- Replication priority levels: Immediate, Scheduled, OnDemand, LocalOnly
- Transfer session management with failure recovery
- Replication dashboard in frontend with topology visualization
- Edge node service (`/edge/`) with cache, scheduler, and sync modules
- E2E tests for replication workflows

#### WASM Plugin System
- WIT-based format plugin interface (`FormatHandler` contract)
- Wasmtime runtime with fuel-based CPU limits and 64MB memory cap
- Plugin installation from Git repositories, ZIP uploads, or local paths
- Plugin manifest validation (semver, capabilities, resource limits)
- Plugin registry with enable/disable/reload lifecycle
- Plugin event audit log and configuration storage
- Plugin management UI in frontend
- Database tables: plugins, plugin_hooks, plugin_events, plugin_config, format_handlers

#### Authentication Expansion
- OpenID Connect (OIDC) service for federated authentication
- LDAP service for directory-based authentication
- SAML 2.0 service for enterprise SSO
- API token management with scopes and expiration
- Auth provider tracking per user (Local, LDAP, SAML, OIDC)
- Groups and permissions system with role-based access control

#### Artifactory Migration Tooling
- Artifactory REST API client for repository, artifact, user, and permission discovery
- Import service for bulk artifact migration with format mapping
- Migration worker for background job processing with conflict resolution
- Migration tracking API with job status, progress, and error reporting
- Migration wizard UI in frontend with step-by-step workflow
- CLI migration commands for headless operation

#### Frontend Enhancements
- React 19 + Ant Design 6 + TanStack Query 5 + React Router 7
- New pages: Artifacts, Edge Nodes, Backups, Plugins, Security Dashboard,
  Security Policies, Security Scans, Scan Detail, Replication Dashboard,
  Webhooks, Builds, Packages, Setup Wizards, Search, Profile, Settings
- Resizable artifact browser panel with server-side tree API
- Repository wizard with format-specific configuration
- Artifact detail view with metadata, security, and download tabs
- Help modal, version info display, refresh buttons, document titles
- Theme support with dark/light mode toggle
- Tiered access model: anonymous browsing, authenticated actions, admin controls

#### Demo Mode
- Backend middleware blocking all POST/PUT/DELETE/PATCH in demo mode
- Exempts authentication endpoints for login
- Frontend auto-login as admin when `DEMO_MODE=true`
- Seed data script with 15 repositories, 33 artifacts, 4 users, 5 audit entries
- Pre-built Docker images on ghcr.io for demo deployment
- Demo instance at demo.artifactkeeper.com

#### Documentation Site
- Astro + Starlight documentation site with 26 pages
- Sections: Getting Started, Guides (6 package formats), Deployment,
  Advanced (auth, storage, plugins, edge nodes, backup, webhooks),
  Reference (API, CLI, environment), Security (scanning, policies, signing),
  Migration (from Artifactory)
- Landing page with feature showcase, comparison, and deployment options
- Combined landing + docs deployed to GitHub Pages at artifactkeeper.com

#### Staged Testing Strategy
- **Tiered CI/CD testing infrastructure**
  - Tier 1 (every push/PR): Fast lint and unit tests under 5 minutes
  - Tier 2 (main branch): Integration tests with PostgreSQL
  - Tier 3 (release/manual): Full E2E with native client testing
- GitHub Actions workflows: restructured `ci.yml`, new `e2e.yml`, E2E gate on `release.yml`
- Native package manager client tests for 10 formats: PyPI, NPM, Cargo, Maven, Go, RPM, Debian, Helm, Conda, Docker
- Stress testing: 100 concurrent upload operations with consistency validation
- Failure injection: server crash recovery, database disconnect, storage failure scenarios
- PKI infrastructure for test signing (CA, TLS, GPG keys)
- Playwright test tagging with `@smoke` and `@full` profiles

#### UI E2E Test Coverage
- Comprehensive Playwright E2E test suite with Page Object Model
- Tests covering login, repositories, artifacts, security, admin workflows
- Docker Compose profiles for selective test execution

### Changed

- Consolidated duplicate `Pagination` structs into shared `backend/src/api/dto.rs` module
- Migrated ESLint to flat config format
- Upgraded Playwright to v1.57.0
- Simplified backend code across 15 files (-271 lines) via extracted helpers,
  `From` trait impls, idiomatic iterators, and reduced duplication
- Simplified frontend AuthContext and Repositories components
- Removed internal agent tooling (`.beads/`, `.specify/`, `AGENTS.md`) from repository
- Scrubbed internal tooling from full git history via `git filter-repo`
- Updated all repository URLs from `brandonrc` to `artifact-keeper` organization
- Docker image and healthcheck improvements for demo deployment

### Fixed

- Axum route conflicts in Swift and SBT handlers (ambiguous path segments)
- Tree children preservation across repository list re-renders
- Replaced Ant Layout with plain flex for artifact browser (layout conflicts)
- Resolved all Clippy warnings across backend and edge crates
- Fixed TypeScript errors breaking CI and Docker builds
- Fixed SQLx compile-time query check errors
- Corrected demo seed data: admin password hash, checksum lengths (64 chars),
  `correlation_id` for audit log, FK references with dynamic admin UUID
- Fixed Dependabot breaking dependency updates (reverted zip/lzma-rust2/crc)

## [0.1.0] - 2026-01-14

### Added

- Initial release of Artifact Keeper
- Multi-format artifact registry supporting PyPI, NPM, Cargo, Maven, Go, RPM, Debian, Helm, Conda, and Docker
- React frontend with Ant Design UI components
- Rust backend with Axum web framework
- PostgreSQL database for metadata storage
- JWT-based authentication
- Repository management (create, update, delete)
- Artifact upload and download
- Search functionality across repositories
- User management and permissions
- Health check endpoints
- Prometheus metrics endpoint

### Infrastructure

- Docker Compose setup for local development
- GitHub Actions CI pipeline
- Playwright E2E test suite
- Vitest unit test suite for frontend
- Cargo test suite for backend

---

[Unreleased]: https://github.com/artifact-keeper/artifact-keeper/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/artifact-keeper/artifact-keeper/releases/tag/v0.1.0
