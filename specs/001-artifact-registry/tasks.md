# Tasks: Artifact Registry Platform

**Feature**: 001-artifact-registry | **Generated**: 2026-01-16
**Input**: Design documents from `/specs/001-artifact-registry/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/openapi.yaml

**Tests**: Not explicitly requested in spec - test tasks omitted (add via `/speckit.tasks --with-tests` if needed)

**Organization**: Tasks grouped by user story to enable independent implementation and testing.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization and Cargo workspace setup

- [x] T001 Create Cargo workspace with backend, edge crates in Cargo.toml (workspace root)
- [x] T002 [P] Initialize backend crate with Axum dependencies in backend/Cargo.toml
- [x] T003 [P] Initialize edge crate skeleton in edge/Cargo.toml
- [x] T004 [P] Initialize frontend with Vite + React + TypeScript in frontend/package.json
- [x] T005 [P] Configure rustfmt.toml and .clippy.toml for Rust linting
- [x] T006 [P] Configure ESLint and Prettier for frontend in frontend/.eslintrc.js
- [x] T007 [P] Create docker-compose.yml with PostgreSQL and MinIO services in deploy/docker/docker-compose.yml
- [x] T008 Create .env.example with all configuration variables
- [x] T009 [P] Setup SQLx CLI and create initial migration structure in backend/migrations/

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before ANY user story can be implemented

**CRITICAL**: No user story work can begin until this phase is complete

### Database Schema & Core Models

- [x] T010 Create database migration for users table in backend/migrations/001_users.sql
- [x] T011 [P] Create database migration for roles and permissions in backend/migrations/002_roles.sql
- [x] T012 [P] Create database migration for repositories table in backend/migrations/003_repositories.sql
- [x] T013 [P] Create database migration for artifacts table in backend/migrations/004_artifacts.sql
- [x] T014 Create database migration for audit_log table in backend/migrations/005_audit_log.sql

### Backend Core Infrastructure

- [x] T015 Implement config loading from environment in backend/src/config.rs
- [x] T016 [P] Create database connection pool setup in backend/src/db.rs
- [x] T017 [P] Implement error types and API error responses in backend/src/error.rs
- [x] T018 Create Axum application setup with router in backend/src/main.rs
- [x] T019 Implement request tracing middleware in backend/src/api/middleware/tracing.rs
- [x] T020 [P] Implement Prometheus metrics middleware in backend/src/api/middleware/metrics.rs
- [x] T021 Implement health check endpoints (/health, /ready) in backend/src/api/handlers/health.rs
- [x] T022 Setup route registration framework in backend/src/api/routes.rs

### Storage Abstraction Layer

- [x] T023 Define storage trait for artifact backends in backend/src/storage/mod.rs
- [x] T024 [P] Implement filesystem storage backend in backend/src/storage/filesystem.rs
- [ ] T025 [P] Implement S3 storage backend with aws-sdk-s3 in backend/src/storage/s3.rs

### Core Models (SQLx)

- [x] T026 [P] Create User model with SQLx in backend/src/models/user.rs
- [x] T027 [P] Create Role model with SQLx in backend/src/models/role.rs
- [x] T028 [P] Create Repository model with SQLx in backend/src/models/repository.rs
- [x] T029 [P] Create Artifact model with SQLx in backend/src/models/artifact.rs
- [x] T030 Create AuditLog model with SQLx in backend/src/models/audit_log.rs

### Authentication Framework (Local Auth Only)

- [x] T031 Implement password hashing with bcrypt in backend/src/services/auth_service.rs
- [x] T032 Implement JWT token generation and validation in backend/src/services/auth_service.rs
- [x] T033 Implement auth middleware for JWT extraction in backend/src/api/middleware/auth.rs
- [x] T034 Implement login handler (POST /auth/login) in backend/src/api/handlers/auth.rs
- [x] T035 [P] Implement logout handler (POST /auth/logout) in backend/src/api/handlers/auth.rs
- [x] T036 [P] Implement current user handler (GET /auth/me) in backend/src/api/handlers/auth.rs

**Checkpoint**: Foundation ready - user story implementation can now begin

---

## Phase 3: User Story 1 - Artifact Upload and Download (Priority: P1) MVP

**Goal**: Enable developers to upload and download artifacts with integrity verification

**Independent Test**: Upload a file via PUT /repositories/{key}/artifacts/{path}, download via GET .../download, verify SHA-256 checksum matches

### Implementation for User Story 1

- [x] T037 [US1] Implement ArtifactService with upload logic in backend/src/services/artifact_service.rs
- [x] T038 [US1] Add checksum calculation (SHA-256, MD5, SHA-1) to artifact upload in backend/src/services/artifact_service.rs
- [x] T039 [US1] Implement artifact storage with CAS pattern in backend/src/services/storage_service.rs
- [x] T040 [US1] Implement upload artifact handler (PUT /repositories/{key}/artifacts/{path}) in backend/src/api/handlers/artifacts.rs
- [x] T041 [US1] Implement download artifact handler with streaming in backend/src/api/handlers/artifacts.rs
- [x] T042 [US1] Implement get artifact metadata handler in backend/src/api/handlers/artifacts.rs
- [x] T043 [US1] Implement list artifacts handler with pagination in backend/src/api/handlers/artifacts.rs
- [x] T044 [US1] Implement delete artifact handler (soft delete) in backend/src/api/handlers/artifacts.rs
- [x] T045 [US1] Implement artifact search endpoint (GET /search/artifacts) in backend/src/api/handlers/artifacts.rs
- [x] T046 [US1] Enforce immutable versions (409 Conflict on duplicate) in backend/src/services/artifact_service.rs
- [x] T047 [US1] Add download statistics tracking in backend/src/services/artifact_service.rs
- [x] T048 [US1] Implement checksum validation on download in backend/src/api/handlers/artifacts.rs
- [x] T049 [US1] Register artifact routes in backend/src/api/routes.rs

**Checkpoint**: User Story 1 complete - artifacts can be uploaded, downloaded, and searched

---

## Phase 4: User Story 2 - Enterprise Authentication (Priority: P2)

**Goal**: Integrate with enterprise identity providers (LDAP, SAML, OIDC)

**Independent Test**: Configure OIDC with test provider, login via SSO, verify user created with correct permissions

**Dependencies**: Requires Foundational auth framework (T031-T036)

### Implementation for User Story 2

- [x] T050 [P] [US2] Create database migration for api_tokens table in backend/migrations/006_api_tokens.sql
- [ ] T051 [P] [US2] Create ApiToken model with SQLx in backend/src/models/api_token.rs
- [ ] T052 [US2] Implement LDAP authentication with ldap3 crate in backend/src/services/ldap_service.rs
- [ ] T053 [US2] Implement OIDC authentication with openidconnect crate in backend/src/services/oidc_service.rs
- [ ] T054 [US2] Implement SAML authentication with samael crate in backend/src/services/saml_service.rs
- [ ] T055 [US2] Extend auth_service to route by auth_provider type in backend/src/services/auth_service.rs
- [ ] T056 [US2] Implement group-to-role mapping for federated auth in backend/src/services/auth_service.rs
- [ ] T057 [US2] Implement API token generation and validation in backend/src/services/token_service.rs
- [ ] T058 [US2] Implement API token CRUD handlers in backend/src/api/handlers/users.rs
- [ ] T059 [US2] Extend auth middleware to support API tokens in backend/src/api/middleware/auth.rs
- [ ] T060 [US2] Implement user sync/deactivation for federated providers in backend/src/services/auth_service.rs
- [x] T061 [US2] Add audit logging for authentication events in backend/src/services/auth_service.rs

**Checkpoint**: User Story 2 complete - enterprise SSO and API tokens functional

---

## Phase 5: User Story 3 - Repository Management (Priority: P2)

**Goal**: Create and manage repositories for all major artifact formats

**Independent Test**: Create Maven repository via API, publish JAR with mvn deploy, verify artifact stored correctly

**Dependencies**: Can run in parallel with US2 after Foundational phase

### Repository CRUD

- [x] T062 [P] [US3] Create database migration for virtual_repo_members in backend/migrations/007_virtual_repos.sql
- [x] T063 [P] [US3] Create VirtualRepoMember model in backend/src/models/repository.rs
- [x] T064 [US3] Implement RepositoryService with CRUD operations in backend/src/services/repository_service.rs
- [x] T065 [US3] Implement create repository handler (POST /repositories) in backend/src/api/handlers/repositories.rs
- [x] T066 [US3] Implement get repository handler (GET /repositories/{key}) in backend/src/api/handlers/repositories.rs
- [x] T067 [US3] Implement list repositories handler with filtering in backend/src/api/handlers/repositories.rs
- [x] T068 [US3] Implement update repository handler (PATCH) in backend/src/api/handlers/repositories.rs
- [x] T069 [US3] Implement delete repository handler in backend/src/api/handlers/repositories.rs
- [x] T070 [US3] Implement virtual repository member management in backend/src/services/repository_service.rs
- [x] T071 [US3] Register repository routes in backend/src/api/routes.rs

### Package Format Handlers (Tier 1 - Critical)

- [x] T072 [US3] Define format handler trait in backend/src/formats/mod.rs
- [x] T073 [P] [US3] Implement generic binary format handler in backend/src/formats/generic.rs
- [x] T074 [P] [US3] Implement Maven format handler (layout, pom parsing) in backend/src/formats/maven.rs
- [x] T075 [P] [US3] Implement npm format handler (packument, tarballs) in backend/src/formats/npm.rs
- [x] T076 [US3] Implement Docker/OCI format handler (Registry API v2) in backend/src/formats/oci.rs

### Package Format Handlers (Tier 2 - High Priority)

- [ ] T077 [P] [US3] Implement PyPI format handler (PEP 503 simple API) in backend/src/formats/pypi.rs
- [ ] T078 [P] [US3] Implement Helm format handler (index.yaml, charts) in backend/src/formats/helm.rs
- [ ] T079 [P] [US3] Implement NuGet format handler (v3 API) in backend/src/formats/nuget.rs

### Package Format Handlers (Tier 3 - Standard)

- [ ] T080 [P] [US3] Implement Go module proxy handler (GOPROXY) in backend/src/formats/go.rs
- [ ] T081 [P] [US3] Implement Cargo format handler (sparse index) in backend/src/formats/cargo.rs
- [ ] T082 [P] [US3] Implement RPM format handler (repodata, GPG) in backend/src/formats/rpm.rs
- [ ] T083 [P] [US3] Implement Debian format handler (Packages, Release) in backend/src/formats/debian.rs

### Package Format Handlers (Tier 4 - Specialized)

- [ ] T084 [P] [US3] Implement RubyGems format handler in backend/src/formats/rubygems.rs
- [ ] T085 [P] [US3] Implement Conan format handler (v2 API) in backend/src/formats/conan.rs

### Remote/Proxy Repositories

- [ ] T086 [US3] Implement upstream proxy service for remote repos in backend/src/services/proxy_service.rs
- [ ] T087 [US3] Add caching logic for proxied artifacts in backend/src/services/proxy_service.rs

**Checkpoint**: User Story 3 complete - all 13+ package formats supported

---

## Phase 6: User Story 4 - Edge Node Deployment (Priority: P3)

**Goal**: Deploy edge nodes for distributed caching with automatic sync

**Independent Test**: Deploy edge node, configure sync, verify artifact served from edge cache

**Dependencies**: Requires US1 (artifacts), US3 (repositories)

### Implementation for User Story 4

- [x] T088 [P] [US4] Create database migration for edge_nodes table in backend/migrations/008_edge_nodes.sql
- [x] T089 [P] [US4] Create database migration for sync_tasks table in backend/migrations/009_sync_tasks.sql
- [ ] T090 [P] [US4] Create EdgeNode model with SQLx in backend/src/models/edge_node.rs
- [ ] T091 [P] [US4] Create SyncTask model with SQLx in backend/src/models/sync_task.rs
- [x] T092 [US4] Implement EdgeNodeService with registration in backend/src/services/edge_service.rs
- [x] T093 [US4] Implement sync task configuration in backend/src/services/edge_service.rs
- [x] T094 [US4] Implement edge node handlers (CRUD) in backend/src/api/handlers/edge.rs
- [x] T095 [US4] Implement heartbeat endpoint for edge status in backend/src/api/handlers/edge.rs
- [x] T096 [US4] Implement sync trigger endpoint in backend/src/api/handlers/edge.rs
- [x] T097 [US4] Register edge routes in backend/src/api/routes.rs

### Edge Node Binary

- [x] T098 [US4] Implement edge node main entry point in edge/src/main.rs
- [x] T099 [US4] Implement LRU cache for artifacts in edge/src/cache.rs
- [x] T100 [US4] Implement sync protocol (pull from primary) in edge/src/sync.rs
- [x] T101 [US4] Implement heartbeat reporting to primary in edge/src/sync.rs
- [ ] T102 [US4] Implement offline mode (serve from cache) in edge/src/main.rs

**Checkpoint**: User Story 4 complete - edge nodes deployable with automatic sync

---

## Phase 7: User Story 5 - Backup and Disaster Recovery (Priority: P3)

**Goal**: Automated backups with point-in-time restore capability

**Independent Test**: Configure backup, trigger backup, delete test data, restore, verify integrity

**Dependencies**: Requires US1 (artifacts to backup)

### Implementation for User Story 5

- [x] T103 [P] [US5] Create database migration for backups table in backend/migrations/010_backups.sql
- [ ] T104 [US5] Create Backup model with SQLx in backend/src/models/backup.rs
- [x] T105 [US5] Implement BackupService with scheduling in backend/src/services/backup_service.rs
- [x] T106 [US5] Implement full backup logic (metadata + artifacts) in backend/src/services/backup_service.rs
- [x] T107 [US5] Implement incremental backup logic in backend/src/services/backup_service.rs
- [x] T108 [US5] Implement backup to S3/external storage in backend/src/services/backup_service.rs
- [x] T109 [US5] Implement backup integrity verification (checksums) in backend/src/services/backup_service.rs
- [x] T110 [US5] Implement restore from backup in backend/src/services/backup_service.rs
- [x] T111 [US5] Implement backup handlers (list, create, restore) in backend/src/api/handlers/admin.rs
- [x] T112 [US5] Register admin/backup routes in backend/src/api/routes.rs

**Checkpoint**: User Story 5 complete - automated backups with verified restore

---

## Phase 8: User Story 6 - Plugin Extensions (Priority: P4)

**Goal**: Install and manage plugins for webhooks, validators, integrations

**Independent Test**: Install webhook plugin, upload artifact, verify webhook called

**Dependencies**: Requires US1 (artifact events to trigger plugins)

### Implementation for User Story 6

- [x] T113 [P] [US6] Create database migration for plugins table in backend/migrations/011_plugins.sql
- [x] T114 [P] [US6] Create database migration for plugin_config table in backend/migrations/012_plugin_config.sql
- [ ] T115 [P] [US6] Create Plugin model with SQLx in backend/src/models/plugin.rs
- [ ] T116 [P] [US6] Create PluginConfig model with SQLx in backend/src/models/plugin.rs
- [ ] T117 [US6] Implement PluginService with lifecycle management in backend/src/services/plugin_service.rs
- [ ] T118 [US6] Implement plugin loading and isolation in backend/src/services/plugin_service.rs
- [ ] T119 [US6] Implement plugin event hooks (upload, download, delete) in backend/src/services/plugin_service.rs
- [ ] T120 [US6] Implement webhook plugin type in backend/src/services/plugin_service.rs
- [ ] T121 [US6] Implement validator plugin type in backend/src/services/plugin_service.rs
- [x] T122 [US6] Implement plugin handlers (install, enable, disable, uninstall) in backend/src/api/handlers/plugins.rs
- [x] T123 [US6] Register plugin routes in backend/src/api/routes.rs
- [ ] T124 [US6] Integrate plugin hooks into artifact service in backend/src/services/artifact_service.rs

**Checkpoint**: User Story 6 complete - plugin system operational

---

## Phase 9: Frontend Admin UI

**Goal**: Web-based administration interface for all features

**Dependencies**: Requires backend API endpoints from US1-US6

### Core Frontend Infrastructure

- [x] T125 [P] Setup React Router in frontend/src/App.tsx
- [x] T126 [P] Generate API client from OpenAPI spec in frontend/src/services/api.ts
- [x] T127 [P] Create layout components (Header, Sidebar, Footer) in frontend/src/components/layout/
- [ ] T128 [P] Create common components (Button, Table, Form, Modal) in frontend/src/components/common/
- [x] T129 Setup TanStack Query provider in frontend/src/main.tsx

### Pages

- [x] T130 [P] Implement Login page with auth flow in frontend/src/pages/Login.tsx
- [x] T131 [P] Implement Dashboard page with overview stats in frontend/src/pages/Dashboard.tsx
- [x] T132 [P] Implement Repositories list page in frontend/src/pages/Repositories.tsx
- [x] T133 [P] Implement Repository detail page with artifacts in frontend/src/pages/RepositoryDetail.tsx
- [x] T134 [P] Implement Artifacts browse/search page in frontend/src/pages/Artifacts.tsx
- [x] T135 [P] Implement Users management page in frontend/src/pages/Users.tsx
- [x] T136 [P] Implement Settings page in frontend/src/pages/Settings.tsx
- [x] T137 [P] Implement Edge Nodes management page in frontend/src/pages/EdgeNodes.tsx
- [x] T138 [P] Implement Backups management page in frontend/src/pages/Backups.tsx
- [x] T139 [P] Implement Plugins management page in frontend/src/pages/Plugins.tsx

### File Upload Component

- [ ] T140 Implement file upload with progress tracking in frontend/src/components/common/FileUpload.tsx
- [x] T141 Integrate file upload into repository detail page in frontend/src/pages/RepositoryDetail.tsx

**Checkpoint**: Frontend complete - full admin UI operational

---

## Phase 10: Polish & Cross-Cutting Concerns

**Purpose**: Improvements that affect multiple user stories

- [x] T142 [P] Create Dockerfile for backend in deploy/docker/Dockerfile.backend
- [ ] T143 [P] Create Dockerfile for frontend in deploy/docker/Dockerfile.frontend
- [ ] T144 [P] Create Dockerfile for edge node in deploy/docker/Dockerfile.edge
- [x] T145 Update docker-compose.yml with all services in deploy/docker/docker-compose.yml
- [ ] T146 [P] Create Kubernetes manifests in deploy/k8s/
- [ ] T147 Add rate limiting middleware in backend/src/api/middleware/rate_limit.rs
- [x] T148 Implement quota enforcement per repository in backend/src/services/artifact_service.rs
- [x] T149 Add CORS configuration in backend/src/main.rs
- [ ] T150 [P] Add request correlation IDs to all handlers in backend/src/api/middleware/tracing.rs
- [ ] T151 Run cargo clippy and fix all warnings
- [ ] T152 Run cargo test and ensure all pass
- [ ] T153 [P] Run ESLint and fix all warnings in frontend
- [ ] T154 Validate quickstart.md instructions work end-to-end

---

## Dependencies & Execution Order

### Phase Dependencies

```
Phase 1 (Setup) ─────────────────┐
                                 │
                                 ▼
Phase 2 (Foundational) ──────────┤ BLOCKS ALL USER STORIES
                                 │
           ┌─────────────────────┼─────────────────────┐
           │                     │                     │
           ▼                     ▼                     ▼
    Phase 3 (US1)         Phase 4 (US2)         Phase 5 (US3)
    Artifact CRUD         Enterprise Auth       Repo Mgmt
    [MVP]                 [Can parallel]        [Can parallel]
           │                     │                     │
           └─────────────────────┼─────────────────────┘
                                 │
           ┌─────────────────────┼─────────────────────┐
           │                     │                     │
           ▼                     ▼                     ▼
    Phase 6 (US4)         Phase 7 (US5)         Phase 8 (US6)
    Edge Nodes            Backup/DR             Plugins
    [Needs US1,US3]       [Needs US1]          [Needs US1]
           │                     │                     │
           └─────────────────────┼─────────────────────┘
                                 │
                                 ▼
                    Phase 9 (Frontend)
                    [Needs backend APIs]
                                 │
                                 ▼
                    Phase 10 (Polish)
```

### User Story Dependencies

| Story | Can Start After | Integrates With |
|-------|-----------------|-----------------|
| US1 (P1) | Phase 2 | None (MVP) |
| US2 (P2) | Phase 2 | Independent |
| US3 (P2) | Phase 2 | Independent |
| US4 (P3) | US1, US3 | US1 artifacts, US3 repos |
| US5 (P3) | US1 | US1 artifacts |
| US6 (P4) | US1 | US1 artifact events |

### Parallel Opportunities

**Within Setup (Phase 1)**: T002, T003, T004, T005, T006, T007

**Within Foundational (Phase 2)**:
- Models: T026, T027, T028, T029
- Storage: T024, T025
- Auth handlers: T035, T036

**Within US3 (Format Handlers)**:
- All format handlers (T073-T085) can run in parallel after T072

**Across User Stories (after Phase 2)**:
- US1, US2, US3 can all start simultaneously
- Different developers can work on different stories

---

## Parallel Example: Phase 2 Models

```bash
# Launch all model tasks in parallel:
Task: "Create User model with SQLx in backend/src/models/user.rs"
Task: "Create Role model with SQLx in backend/src/models/role.rs"
Task: "Create Repository model with SQLx in backend/src/models/repository.rs"
Task: "Create Artifact model with SQLx in backend/src/models/artifact.rs"
```

## Parallel Example: US3 Format Handlers

```bash
# After T072 (trait definition), launch all format handlers:
Task: "Implement generic binary format handler in backend/src/formats/generic.rs"
Task: "Implement Maven format handler in backend/src/formats/maven.rs"
Task: "Implement npm format handler in backend/src/formats/npm.rs"
Task: "Implement Docker/OCI format handler in backend/src/formats/oci.rs"
Task: "Implement PyPI format handler in backend/src/formats/pypi.rs"
# ... etc
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (CRITICAL - blocks all stories)
3. Complete Phase 3: User Story 1 (Artifact Upload/Download)
4. **STOP and VALIDATE**: Test artifact upload/download independently
5. Deploy/demo if ready - this is a functional artifact repository!

### Incremental Delivery

| Increment | Stories Included | Value Delivered |
|-----------|------------------|-----------------|
| MVP | US1 | Basic artifact storage and retrieval |
| Auth | US1 + US2 | Enterprise SSO, API tokens |
| Formats | US1 + US2 + US3 | All 13+ package formats |
| Distribution | + US4 | Edge caching for global teams |
| DR | + US5 | Automated backups, restore capability |
| Extensibility | + US6 | Plugin system for customization |

### Parallel Team Strategy

With multiple developers after Phase 2 completion:

| Developer | Assigned Stories | Files |
|-----------|------------------|-------|
| Dev A | US1 (MVP) | artifact_service, artifacts handler |
| Dev B | US2 (Auth) | ldap/oidc/saml services, auth handlers |
| Dev C | US3 (Formats) | format handlers, repository service |

---

## Summary

| Metric | Count |
|--------|-------|
| **Total Tasks** | 154 |
| **Setup Tasks** | 9 |
| **Foundational Tasks** | 27 |
| **US1 Tasks** | 13 |
| **US2 Tasks** | 12 |
| **US3 Tasks** | 26 |
| **US4 Tasks** | 15 |
| **US5 Tasks** | 10 |
| **US6 Tasks** | 12 |
| **Frontend Tasks** | 17 |
| **Polish Tasks** | 13 |
| **Parallel Opportunities** | 65 tasks marked [P] |
| **MVP Scope** | Phase 1-3 (49 tasks) |

---

## Notes

- [P] tasks = different files, no dependencies on incomplete tasks
- [Story] label maps task to specific user story for traceability
- Each user story is independently completable and testable
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- Format handlers (US3) can be implemented incrementally based on priority tiers
