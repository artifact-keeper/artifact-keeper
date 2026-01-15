# Research: Artifact Registry Platform

**Feature**: 001-artifact-registry | **Date**: 2026-01-14 | **Status**: Complete

## Overview

This document consolidates research findings to resolve all "NEEDS CLARIFICATION" items from the Technical Context section and establish best practices for implementation.

---

## 1. Backend Web Framework

### Decision: Axum

### Rationale

Axum is the optimal choice for building the artifact registry backend:

1. **Large File Handling**: Native streaming support via `BodyStream` and `StreamBody` for efficient memory usage with 100MB+ files
2. **Memory Efficiency**: Achieves lowest memory footprint per connection - critical for concurrent large uploads
3. **Tokio Integration**: Seamless integration with Tokio ecosystem (Hyper, Tower) for async I/O
4. **Production Readiness**: 191M+ downloads, backed by Tokio team, used by Shopify, Discord, Cloudflare
5. **Auth Middleware**: Mature JWT/OIDC libraries (axum-jwt-auth, jwt-authorizer, axum-jwt-oidc)

### Alternatives Considered

| Framework | Why Not Selected |
|-----------|------------------|
| **Actix-Web** | Higher memory usage due to actor system; known issues with large multipart uploads; marginal performance advantage doesn't justify trade-offs for file-heavy workloads |
| **Rocket** | Performance trails both; less flexible async support |

**Note**: SAML requires manual integration regardless of framework choice (Rust ecosystem limitation - use `samael` crate).

---

## 2. Frontend Framework

### Decision: React

### Rationale

React is the recommended frontend framework for the admin UI:

1. **Enterprise Ecosystem**: Most mature library ecosystem (Ant Design Pro, MUI, CoreUI, KendoReact)
2. **Accessibility**: Best selection of WCAG-compliant libraries (React Aria, Reakit, Chakra UI, Shadcn UI)
3. **TypeScript Support**: Longest history with TypeScript - more examples, better IDE support
4. **File Uploads**: Multiple solutions with progress tracking (React Dropzone, dhtmlxVault)
5. **Talent Pool**: ~40% developer adoption, largest talent pool for hiring

### Alternatives Considered

| Framework | Why Not Selected |
|-----------|------------------|
| **Vue 3** | Smaller ecosystem of enterprise-focused UI libraries; fewer WCAG-compliant options |
| **Svelte 5** | Ecosystem maturity gap for enterprise admin dashboards; smaller talent pool; accessibility libraries are newer |

---

## 3. Storage Architecture

### Decision: Dual-Storage Model

- **Metadata**: PostgreSQL with read replicas
- **Artifacts**: S3-compatible object storage with Content-Addressable Storage (CAS) pattern

### Rationale

**PostgreSQL for Metadata**:
1. MVCC enables concurrent read/write without blocking (unlike SQLite's single-writer limit)
2. Native replication for 99.9%+ availability (streaming replication, PITR)
3. Read replicas for edge node metadata distribution
4. Industry standard: used by Artifactory and GitLab Container Registry

**S3-Compatible Object Storage for Artifacts**:
1. Designed for large binaries (1KB-10GB+) with unlimited capacity
2. Built-in durability (11 nines) and availability (99.99%)
3. CAS pattern provides natural deduplication via SHA-256 keys
4. Cross-region replication for edge node support
5. Cost-efficient tiered storage (hot/warm/cold)

**Why Separate Stores**:
1. Industry best practice (Artifactory, GitLab, MLflow use this pattern)
2. Independent scaling of metadata queries vs artifact streaming
3. Each store optimized for its workload
4. Simpler backup strategy with native tools

### Storage Architecture Diagram

```
                                ┌─────────────────────────────────────────────┐
                                │              CENTRAL REGION                  │
                                │                                              │
┌──────────────┐               │  ┌─────────────────────────────────────┐     │
│   Clients    │───────────────┼─▶│        Load Balancer               │     │
└──────────────┘               │  └─────────────────────────────────────┘     │
                                │               │                              │
                                │               ▼                              │
                                │  ┌─────────────────────────────────────┐     │
                                │  │     Registry API Nodes              │     │
                                │  │     (Axum, Stateless)               │     │
                                │  └─────────────────────────────────────┘     │
                                │          │                    │              │
                                │          ▼                    ▼              │
                                │  ┌──────────────┐   ┌─────────────────┐     │
                                │  │  PostgreSQL  │   │  S3-Compatible  │     │
                                │  │   Primary    │   │  Object Storage │     │
                                │  │  + Replicas  │   │  (CAS Pattern)  │     │
                                │  └──────────────┘   └─────────────────┘     │
                                └─────────────────────────────────────────────┘
                                             │                    │
            ┌────────────────────────────────┼────────────────────┼────────────┐
            │                                │                    │            │
            │                    EDGE NODES (Pull-based Replication)           │
            │  ┌─────────────────┐   ┌─────────────────┐   ┌────────────────┐ │
            │  │  Edge Node A    │   │  Edge Node B    │   │  Edge Node C   │ │
            │  │ ┌─────────────┐ │   │ ┌─────────────┐ │   │ ┌────────────┐ │ │
            │  │ │PG Read-Only │ │   │ │PG Read-Only │ │   │ │PG Read-Only│ │ │
            │  │ │  Replica    │ │   │ │  Replica    │ │   │ │  Replica   │ │ │
            │  │ └─────────────┘ │   │ └─────────────┘ │   │ └────────────┘ │ │
            │  │ ┌─────────────┐ │   │ ┌─────────────┐ │   │ ┌────────────┐ │ │
            │  │ │ LRU Cache   │ │   │ │ LRU Cache   │ │   │ │ LRU Cache  │ │ │
            │  │ │ (Artifacts) │ │   │ │ (Artifacts) │ │   │ │ (Artifacts)│ │ │
            │  │ └─────────────┘ │   │ └─────────────┘ │   │ └────────────┘ │ │
            │  └─────────────────┘   └─────────────────┘   └────────────────┘ │
            └─────────────────────────────────────────────────────────────────┘
```

### Alternatives Considered

| Architecture | Why Not Selected |
|--------------|------------------|
| **SQLite** | Single writer limit prevents concurrent access; no native HA |
| **Local Filesystem** | No built-in replication; difficult to scale; manual backup setup |
| **Single Database with BLOBs** | Performance issues with large files; doesn't scale |

---

## 4. Package Format Implementation Strategy

### Decision: Protocol-Based Groupings with Unified Storage Layer

### Format Groupings by Implementation Similarity

| Group | Formats | Shared Protocol |
|-------|---------|-----------------|
| **OCI Distribution** | Docker, Helm 3, OCI Artifacts | OCI Registry API v2 |
| **Simple Index** | npm, PyPI, NuGet, RubyGems | HTTP REST with JSON/HTML indexes |
| **Repository Metadata** | RPM, Debian | Static metadata files + GPG signing |
| **Module Proxy** | Go, Cargo | HTTP GET with version lists |
| **Maven Layout** | Maven, Gradle | HTTP with directory structure |
| **Build System** | Conan | Custom REST API |

### Abstraction Architecture

```
┌──────────────────────────────────────────────────────────┐
│                  Protocol Handlers                        │
│   OCI | Simple Index | Repo Metadata | Module Proxy | Maven
└──────────────────────────┬───────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────┐
│                 Unified Artifact API                      │
│   Upload/Download | Metadata | Versioning | Access Control
└──────────────────────────┬───────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────┐
│                   Storage Backend                         │
│   CAS Blob Store (S3) | Metadata DB (PostgreSQL) | Cache
└──────────────────────────────────────────────────────────┘
```

### Repository Types (Following Google Artifact Registry Pattern)

| Type | Purpose | Use Case |
|------|---------|----------|
| **Standard** | Primary storage | Internal/private packages |
| **Remote (Proxy)** | Cache upstream | Maven Central, npm registry |
| **Virtual** | Aggregate repositories | Single endpoint for resolution (mitigates dependency confusion) |

### Implementation Priority (Based on 2024 Enterprise Adoption)

**Tier 1 (Critical)**:
1. Docker/OCI - 92% container adoption, foundation for cloud-native
2. Maven - 1.5T requests/year, Java enterprise backbone
3. npm - 2.1M packages, web development standard

**Tier 2 (High Priority)**:
4. PyPI - Fastest growing (AI/ML)
5. NuGet - .NET enterprise
6. Helm - Kubernetes (shares OCI implementation)

**Tier 3 (Standard Enterprise)**:
7. Go modules
8. Cargo
9. RPM/Debian

**Tier 4 (Specialized)**:
10. Conan (C/C++)
11. RubyGems
12. Generic binary

### Protocol Implementation Complexity

| Format | Complexity | Notes |
|--------|------------|-------|
| **Generic** | Low | Simple file storage |
| **Maven/Gradle** | Low-Medium | Well-documented layout, XML metadata |
| **npm** | Medium | JSON API, tarball handling, scoped packages |
| **PyPI** | Medium | PEP 503 simple, PEP 691 JSON, wheel parsing |
| **Helm** | Low | index.yaml + tarballs |
| **Docker/OCI** | High | Chunked uploads, manifests, layers |
| **Cargo** | Medium | Sparse index, binary publish format |
| **Go** | Medium | GOPROXY protocol, module validation |
| **RPM** | High | repodata XML, GPG signing, complex metadata |
| **Debian** | High | Packages/Release files, GPG, component structure |
| **NuGet** | Medium | v3 API, .nuspec parsing |
| **Conan** | Medium | v2 API, recipe handling |
| **RubyGems** | Low-Medium | Gem index, simple API |

---

## 5. Key Rust Crates

| Category | Crate(s) | Purpose |
|----------|----------|---------|
| **Web Framework** | `axum`, `tower` | HTTP handling, middleware |
| **Database** | `sqlx` | Async PostgreSQL with compile-time checks |
| **Async Runtime** | `tokio` | Async runtime |
| **Serialization** | `serde`, `serde_json` | JSON/YAML handling |
| **OCI/Docker** | `oci-distribution`, `oci-spec` | Container registry protocol |
| **RPM** | `rpm-rs` | Parse/create RPM packages |
| **Debian** | `ar`, `deb-rs` | Parse .deb files |
| **Archive** | `flate2`, `tar`, `zip` | Compression/archive formats |
| **GPG signing** | `sequoia-openpgp` | RPM/Debian signing |
| **Checksums** | `sha2`, `md5`, `blake2` | Integrity verification |
| **S3 storage** | `aws-sdk-s3` | S3-compatible storage |
| **JWT/Auth** | `jsonwebtoken` | Token handling |
| **OIDC** | `openidconnect` | OpenID Connect client |
| **LDAP** | `ldap3` | LDAP/AD integration |
| **SAML** | `samael` | SAML 2.0 integration |
| **XML** | `quick-xml` | Maven POM, repodata |
| **Semver** | `semver` | Version parsing/comparison |
| **Tracing** | `tracing`, `tracing-subscriber` | Structured logging |
| **Metrics** | `metrics`, `metrics-exporter-prometheus` | Prometheus metrics |

---

## 6. Resolved Technical Context

Based on research, the final Technical Context:

```
Language/Version: Rust 1.75+ (backend), TypeScript 5.x (frontend)
Primary Dependencies:
  - Backend: Axum, Tower, SQLx, tokio, serde
  - Frontend: React 18+, Ant Design or MUI, TanStack Query
Storage:
  - Metadata: PostgreSQL 15+ with streaming replication
  - Artifacts: S3-compatible (MinIO for self-hosted, AWS S3/GCS for cloud)
  - Pattern: Content-Addressable Storage (CAS) with SHA-256 keys
Testing: cargo test, vitest
Target Platform: Linux server, Docker container, Kubernetes
Project Type: Web (backend API + frontend SPA)
Performance Goals: 5s upload/download for 100MB, 5+ concurrent uploads
Constraints: 99.9% read availability, <200ms p95 metadata ops
Scale/Scope: 100-1,000 users initially, horizontal scaling for larger
```

---

## Sources

- [Rust Web Frameworks 2025: Actix vs Axum](https://ritik-chopra28.medium.com/rust-web-frameworks-in-2025-actix-vs-axum-a-data-backed-verdict-b956eb1c094e)
- [Production-Ready JWT Validation in Axum](https://pipinghot.dev/production-ready-jwt-validation-in-axum-a-real-implementation/)
- [React Dashboard Libraries 2025](https://www.luzmo.com/blog/react-dashboard)
- [JFrog Artifactory Storage Architecture](https://jfrog.com/reference-architecture/self-managed/deployment/considerations/storage/)
- [GitLab Container Registry Metadata Database](https://docs.gitlab.com/administration/packages/container_registry_metadata_database/)
- [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec/blob/main/spec.md)
- [Sonatype 2024 Software Supply Chain Report](https://www.sonatype.com/state-of-the-software-supply-chain/2024/scale)
- [Google Cloud Artifact Registry Formats](https://cloud.google.com/artifact-registry/docs/supported-formats)
- [MLflow Backend Store Architecture](https://mlflow.org/docs/latest/self-hosting/architecture/backend-store/)
- [Efficient File Upload with Axum](https://aarambhdevhub.medium.com/efficient-file-upload-and-download-with-axum-in-rust-a-comprehensive-guide-f4ff9c9bbe70)
