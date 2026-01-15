# Implementation Plan: Artifact Registry Platform

**Branch**: `001-artifact-registry` | **Date**: 2026-01-14 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/001-artifact-registry/spec.md`

**Note**: This template is filled in by the `/speckit.plan` command. See `.specify/templates/commands/plan.md` for the execution workflow.

## Summary

Open-source Artifactory replacement providing comprehensive artifact management for enterprise software development. The platform supports 13+ package manager formats (Maven, npm, Docker, PyPI, RPM, Debian, Helm, etc.), enterprise authentication (LDAP/SAML/OIDC), distributed edge nodes for geographic caching, automated backup/recovery, and a plugin architecture for extensibility.

## Technical Context

**Language/Version**: Rust 1.75+ (backend), TypeScript 5.x (frontend)
**Primary Dependencies**:
  - Backend: Axum, Tower, SQLx, tokio, serde
  - Frontend: React 18+, Ant Design or MUI, TanStack Query
**Storage**:
  - Metadata: PostgreSQL 15+ with streaming replication
  - Artifacts: S3-compatible (MinIO self-hosted, AWS S3/GCS cloud) with CAS pattern
**Testing**: cargo test (Rust), vitest (TypeScript)
**Target Platform**: Linux server, Docker container, Kubernetes
**Project Type**: web (backend API + frontend SPA)
**Performance Goals**: 5s upload/download for 100MB files, 5+ concurrent uploads (per SC-001, SC-002)
**Constraints**: 99.9% availability for reads (SC-007), <200ms p95 for metadata operations
**Scale/Scope**: 100-1,000 users initially, horizontal scaling for larger deployments (per spec assumptions)

*See [research.md](./research.md) for detailed technology decisions and rationale.*

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Evidence/Action |
|-----------|--------|-----------------|
| **I. API-First Design** | ✅ PASS | Plan includes Phase 1 contract generation before implementation |
| **II. Security by Default** | ✅ PASS | FR-023-029 cover auth/authz; spec requires HTTPS, audit logging |
| **III. Simplicity & YAGNI** | ✅ PASS | Prioritized user stories (P1-P4); starting with core artifact CRUD |
| **IV. Documentation Standards** | ✅ PASS | Plan includes quickstart.md, API docs via OpenAPI contracts |
| **V. Accessibility Standards** | ⚠️ PENDING | Must address in UI design phase for admin interface |
| **VI. Test Coverage** | ✅ PASS | Testing strategy defined; contract tests required per constitution |
| **VII. Observability** | ✅ PASS | FR-046 requires health monitoring/metrics; structured logging planned |

**Pre-Gate Result**: PASS - All MUST requirements satisfied; accessibility will be addressed in UI design

## Project Structure

### Documentation (this feature)

```text
specs/[###-feature]/
├── plan.md              # This file (/speckit.plan command output)
├── research.md          # Phase 0 output (/speckit.plan command)
├── data-model.md        # Phase 1 output (/speckit.plan command)
├── quickstart.md        # Phase 1 output (/speckit.plan command)
├── contracts/           # Phase 1 output (/speckit.plan command)
└── tasks.md             # Phase 2 output (/speckit.tasks command - NOT created by /speckit.plan)
```

### Source Code (repository root)

```text
backend/
├── src/
│   ├── main.rs                  # Entry point
│   ├── config.rs                # Configuration loading
│   ├── lib.rs                   # Library root
│   ├── api/
│   │   ├── mod.rs
│   │   ├── routes.rs            # Route definitions
│   │   ├── handlers/            # HTTP handlers by domain
│   │   │   ├── artifacts.rs
│   │   │   ├── repositories.rs
│   │   │   ├── users.rs
│   │   │   └── auth.rs
│   │   └── middleware/          # Tower middleware
│   │       ├── auth.rs
│   │       ├── tracing.rs
│   │       └── metrics.rs
│   ├── models/                  # Database models (SQLx)
│   │   ├── artifact.rs
│   │   ├── repository.rs
│   │   ├── user.rs
│   │   └── role.rs
│   ├── services/                # Business logic
│   │   ├── artifact_service.rs
│   │   ├── auth_service.rs
│   │   └── storage_service.rs
│   ├── storage/                 # Storage abstraction
│   │   ├── mod.rs
│   │   ├── s3.rs
│   │   └── filesystem.rs
│   └── formats/                 # Package format handlers
│       ├── mod.rs
│       ├── oci.rs               # Docker/OCI/Helm
│       ├── maven.rs
│       ├── npm.rs
│       ├── pypi.rs
│       └── generic.rs
├── tests/
│   ├── contract/                # API contract tests
│   ├── integration/             # Integration tests
│   └── unit/                    # Unit tests
├── migrations/                  # SQLx migrations
└── Cargo.toml

frontend/
├── src/
│   ├── main.tsx                 # Entry point
│   ├── App.tsx                  # Root component
│   ├── components/              # Reusable UI components
│   │   ├── common/              # Buttons, forms, tables
│   │   └── layout/              # Header, sidebar, footer
│   ├── pages/                   # Route pages
│   │   ├── Dashboard.tsx
│   │   ├── Repositories.tsx
│   │   ├── Artifacts.tsx
│   │   ├── Users.tsx
│   │   └── Settings.tsx
│   ├── services/                # API client (generated from OpenAPI)
│   │   └── api.ts
│   ├── hooks/                   # Custom React hooks
│   └── types/                   # TypeScript type definitions
├── tests/
│   ├── component/               # Component tests
│   └── e2e/                     # End-to-end tests
├── package.json
├── vite.config.ts
└── tsconfig.json

edge/                            # Edge node binary (shares backend crates)
├── src/
│   ├── main.rs
│   ├── cache.rs                 # LRU cache implementation
│   └── sync.rs                  # Replication logic
├── tests/
└── Cargo.toml

deploy/                          # Deployment configurations
├── docker/
│   ├── Dockerfile.backend
│   ├── Dockerfile.frontend
│   └── docker-compose.yml
└── k8s/
    ├── backend.yaml
    ├── frontend.yaml
    └── postgres.yaml
```

**Structure Decision**: Web application structure with separate backend (Rust/Axum) and frontend (React/TypeScript) projects. Edge node is a separate binary sharing backend crates via Cargo workspace.

## Complexity Tracking

> No constitution violations identified. Architecture follows simplicity principle with justified complexity.

| Pattern | Justification |
|---------|---------------|
| Dual storage (PostgreSQL + S3) | Industry standard for artifact registries; each store optimized for its workload |
| Separate edge binary | Required for geographic distribution; shares code via Cargo workspace |
| Format handler abstraction | Required by spec for 13+ package formats; avoids code duplication |

---

## Constitution Check (Post-Design)

*Re-evaluated after Phase 1 design completion.*

| Principle | Status | Evidence |
|-----------|--------|----------|
| **I. API-First Design** | ✅ PASS | OpenAPI 3.1 contract generated in `contracts/openapi.yaml` before implementation |
| **II. Security by Default** | ✅ PASS | JWT auth, role-based access, audit logging defined in data model and API |
| **III. Simplicity & YAGNI** | ✅ PASS | Single storage abstraction, no premature optimization, format handlers share common interface |
| **IV. Documentation Standards** | ✅ PASS | quickstart.md, OpenAPI docs, data-model.md with examples generated |
| **V. Accessibility Standards** | ✅ PASS | React Aria / Chakra UI selected (WCAG 2.1 AA compliant); accessibility checklist for UI tasks |
| **VI. Test Coverage** | ✅ PASS | Test structure defined: contract/, integration/, unit/; API contract tests required |
| **VII. Observability** | ✅ PASS | /health, /ready, /metrics endpoints; tracing middleware; correlation IDs in audit log |

**Post-Design Result**: PASS - All constitution principles satisfied. Design artifacts aligned with requirements.

---

## Generated Artifacts

| Artifact | Path | Status |
|----------|------|--------|
| Research | `specs/001-artifact-registry/research.md` | ✅ Complete |
| Data Model | `specs/001-artifact-registry/data-model.md` | ✅ Complete |
| API Contract | `specs/001-artifact-registry/contracts/openapi.yaml` | ✅ Complete |
| Quickstart | `specs/001-artifact-registry/quickstart.md` | ✅ Complete |

## Next Steps

Run `/speckit.tasks` to generate the implementation task list from this plan.
