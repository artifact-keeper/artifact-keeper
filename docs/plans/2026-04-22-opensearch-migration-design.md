# OpenSearch Migration Design

Fixes: [#462](https://github.com/artifact-keeper/artifact-keeper/issues/462)

Consolidated from 6 independent planning agents (2 SWE, 2 Security, 2 DevOps).

## Problem

Meilisearch HA requires an Enterprise license. Users deploying Artifact Keeper in production need HA search without vendor lock-in. OpenSearch provides native clustering, free HA, and a mature ecosystem.

## Decision: Full Migration (Not Dual Backend)

Replace Meilisearch entirely with OpenSearch. Keep the PostgreSQL full-text search fallback for deployments that don't need a dedicated search engine.

Rationale: supporting two search backends doubles the test surface for minimal gain. Users without HA needs already have PostgreSQL.

## Critical Pre-Migration: Search Authorization Bugs

All 6 agents identified authorization gaps in the current search system. These MUST be fixed during the migration:

1. **Authenticated users can search ALL private repos** without permission checks. The `public_only` flag in `search_service.rs` is binary (auth vs no auth), not per-repo.
2. **`/search/suggest`** has zero visibility filtering, leaks all artifact names.
3. **`/search/checksum`** has zero visibility filtering.
4. **Facet counts** leak private repository names and artifact counts.
5. **Search endpoints have no rate limiting** in `routes.rs`.

Fix: resolve the list of accessible repository IDs for the current user (public repos + repos with read permission via `PermissionService`), pass as a filter in every search query.

## Crate Selection

**`opensearch` v2.4** (unanimous across all 6 agents)

- Official OpenSearch Project client, maintained at opensearch-project/opensearch-rs
- Built on `reqwest` (already in the dependency tree)
- Supports basic auth, AWS SigV4, TLS via `rustls`
- Apache-2.0 license, no known vulnerabilities

Features to enable: `rustls-tls`. Disable `native-tls` and `aws-auth`.

## Architecture

### Files Changed (~20 files)

| File | Action |
|------|--------|
| `Cargo.toml` (workspace) | Replace `meilisearch-sdk` with `opensearch` |
| `backend/Cargo.toml` | Same |
| `backend/src/services/meili_service.rs` | Delete |
| `backend/src/services/opensearch_service.rs` | New (rewrite of meili_service) |
| `backend/src/services/mod.rs` | Rename module |
| `backend/src/config.rs` | Replace config fields + env vars |
| `backend/src/main.rs` | Update initialization |
| `backend/src/api/mod.rs` | Rename field in AppState |
| `backend/src/services/artifact_service.rs` | Rename field/methods (2 call sites) |
| `backend/src/services/repository_service.rs` | Rename field/methods (3 call sites) |
| `backend/src/api/handlers/search.rs` | Add repo visibility filter, rename service |
| `backend/src/api/handlers/admin.rs` | Rename service |
| `backend/src/api/handlers/health.rs` | New health check logic |
| `backend/src/services/health_monitor_service.rs` | Update endpoint |
| `backend/src/api/handlers/system_config.rs` | Rename |
| `backend/src/api/routes.rs` | Add rate limiting to search routes |
| `docker-compose.yml` | Replace meilisearch service |
| `docker-compose.local-dev.yml` | Replace meilisearch service |
| `.env.example` | Replace env var docs |
| Test config objects in ldap, oidc, conan handlers | Mechanical renames |

### Document Types (Unchanged)

`ArtifactDocument` and `RepositoryDocument` structs stay identical. Add `is_public: bool` to `ArtifactDocument` for visibility filtering.

### Index Mappings

**Artifacts:**
- `name`: text (edge_ngram analyzer for prefix search) + keyword subfield
- `path`: text (path_hierarchy tokenizer) + keyword subfield
- `version`, `format`, `repository_id`, `repository_key`, `content_type`: keyword
- `repository_name`: text
- `size_bytes`, `download_count`, `created_at`: long
- `is_public`: boolean (NEW, for visibility filtering)

**Repositories:**
- `name`, `key`: text + keyword subfield
- `description`: text
- `format`, `repo_type`: keyword
- `is_public`: boolean
- `created_at`: long

Settings: 1 shard, 0 replicas (dev). 2 shards, 1 replica (production HA).

### Search Query Translation

Meilisearch filter strings -> OpenSearch typed filter structs:

```rust
struct ArtifactFilter {
    format: Option<String>,
    repository_key: Option<String>,
    repository_id: Option<String>,
    content_type: Option<String>,
    min_size: Option<i64>,
    max_size: Option<i64>,
    created_after: Option<i64>,
    created_before: Option<i64>,
    accessible_repo_ids: Vec<Uuid>,  // visibility filter
}
```

Each filter field maps to an OpenSearch `term`, `range`, or `terms` clause in a `bool.filter` array. The `accessible_repo_ids` is mandatory for non-admin users.

### Bulk Indexing

Keep `BATCH_SIZE = 1000`. Use OpenSearch `_bulk` API (NDJSON format). Disable `refresh_interval` during reindex, force refresh at the end. Same cursor-based pagination from PostgreSQL.

### Health Check

`GET /_cluster/health?wait_for_status=yellow&timeout=5s`

Map `green`/`yellow` to healthy, `red` to unhealthy.

## Configuration

### Environment Variables

| Old | New | Required | Default |
|-----|-----|----------|---------|
| `MEILISEARCH_URL` | `OPENSEARCH_URL` | No | None (search optional) |
| `MEILISEARCH_API_KEY` | `OPENSEARCH_USERNAME` | No | None |
| (none) | `OPENSEARCH_PASSWORD` | No | None |
| (none) | `OPENSEARCH_ALLOW_INVALID_CERTS` | No | false |

### Docker Compose (Dev)

```yaml
opensearch:
  image: opensearchproject/opensearch:2.19.1
  environment:
    discovery.type: single-node
    OPENSEARCH_JAVA_OPTS: "-Xms256m -Xmx256m"
    DISABLE_SECURITY_PLUGIN: "true"
    DISABLE_INSTALL_DEMO_CONFIG: "true"
  healthcheck:
    test: ["CMD-SHELL", "curl -sf http://localhost:9200/_cluster/health || exit 1"]
    interval: 10s
    timeout: 10s
    retries: 12
    start_period: 30s
```

### Docker Desktop Extension

256MB heap in 512MB container. Disable security plugin, ML commons, performance analyzer. Start period 30s (vs Meilisearch 5s). Total memory budget stays ~3.5-3.75GB.

### Production HA (3-node K8s)

StatefulSet with 3 replicas, headless service for discovery, 2GB heap per node, encrypted PVs, NetworkPolicy restricting access to backend pods.

## Security Requirements (Must Have)

1. **Search visibility filtering**: Every search query must filter by accessible repos
2. **TLS in production**: Security plugin enabled, TLS for HTTP and transport
3. **Credential management**: Username/password via env vars, redacted in config dump
4. **Network isolation**: OpenSearch not exposed to host/public network
5. **No query injection**: Use opensearch-rs typed builders, never string interpolation
6. **Error message hiding**: Wrap all OpenSearch errors in AppError::Internal
7. **Rate limiting on search endpoints**: Add rate limit middleware to search routes

## Performance Expectations

| Metric | Meilisearch | OpenSearch |
|--------|-------------|------------|
| Cold start | 2-3s | 15-25s |
| Search P50 | 2-5ms | 5-15ms |
| Search P95 | 5-10ms | 15-25ms |
| Memory (dev) | 512MB | 512MB (256MB heap) |
| Memory (prod) | 512MB | 2-4GB per node |
| Disk (10K docs) | 50-100MB | 30-50MB |

## Migration Path

1. No data migration needed. Auto-reindex from PostgreSQL on startup (existing pattern).
2. Breaking change: env vars renamed, health response field renamed, port 7700 -> 9200.
3. Downtime: search unavailable during first startup reindex (<60s for most installs).

## Implementation Order

### Phase 1: Fix search authorization (prerequisite)
- Add `accessible_repo_ids` filter to SearchService
- Fix suggest, checksum, facets endpoints
- Add rate limiting to search routes
- Add `is_public` to ArtifactDocument

### Phase 2: Core OpenSearch service
- Create `opensearch_service.rs` (index management, CRUD, bulk, health)
- Update config.rs with new env vars
- Update main.rs initialization

### Phase 3: Integration updates
- Mechanical renames across artifact_service, repository_service, handlers
- Docker compose updates (all 3 compose files)
- Update health monitoring

### Phase 4: Testing and docs
- Unit tests for filter translation, sort, service construction
- Integration tests (requires OpenSearch in CI)
- Update .env.example, CLAUDE.md, site docs
- E2E test verification

### Phase 5: IaC and extension
- Helm chart: Deployment -> StatefulSet, new values
- Docker Desktop extension compose update
- Extension Go backend health check update
