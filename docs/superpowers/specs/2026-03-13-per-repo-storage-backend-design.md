# Per-Repository Storage Backend Selection

**Date:** 2026-03-13
**GitHub Issue:** [#428](https://github.com/artifact-keeper/artifact-keeper/issues/428)
**Status:** Approved

## Problem

Storage backend selection is currently global: a single `STORAGE_BACKEND` environment variable determines whether all repositories use filesystem, S3, Azure, or GCS. Users want different repos to use different backends. For example, a cache repo on local filesystem (ephemeral, cheap) vs. production artifacts on S3 (durable, replicated).

The database schema already stores `storage_backend` and `storage_path` per repository, but the routing logic ignores the per-repo field and always uses the global config.

## Design Decisions

- **Immutable after creation.** A repo's storage backend is set when the repo is created and cannot be changed. No artifact migration logic.
- **Shared credentials, shared content-addressed keys.** All S3 repos share the instance-level S3 bucket, credentials, and content-addressed key namespace. Same for Azure and GCS. Artifacts are keyed by SHA-256 hash (`ab/cd/abcdef...`), so identical content uploaded to different repos is stored once. This is by design for deduplication. The per-repo `storage_path` field is only meaningful for filesystem backends (where it determines the base directory). For cloud backends, `storage_path` is stored for metadata purposes but does not affect key routing. No per-repo credential management or bucket isolation.
- **Reject at creation time.** If a user requests a backend whose credentials are not configured on the instance, the API returns 400. No silent fallback, no deferred failure.
- **Fail hard at runtime.** If a backend becomes unavailable after repo creation (e.g., credentials removed from environment), `storage_for_repo()` returns an error that propagates as a 500. No silent fallback to the default backend.
- **Admin-only backend selection.** Only admin users can specify a non-default `storage_backend` when creating a repo. Non-admin users always get the instance default.
- **Backwards compatible.** New repos default to the global `STORAGE_BACKEND` env var unless the create request explicitly specifies a different backend. Existing repos are unaffected since their `storage_backend` DB field already matches the global setting.

## Architecture

### StorageLocation

A small struct to avoid passing two untyped `String` parameters through callbacks:

```rust
pub struct StorageLocation {
    pub backend: String,
    pub path: String,
}
```

Used by `storage_for_repo()`, the `resolve_virtual_download` callback, and the `local_fetch_*` helpers.

### StorageRegistry

A new struct that holds all initialized backend instances, keyed by type name:

```rust
pub struct StorageRegistry {
    backends: HashMap<String, Arc<dyn StorageBackend>>,
    default_backend: String,
}
```

**Initialization (in main.rs):** At startup, the registry attempts to initialize each backend whose credentials are present in the environment. Filesystem is always available (handled inline by `backend_for()`, not stored in the map). S3/Azure/GCS are added to the map only if their respective env vars (`S3_BUCKET`, `AZURE_CONTAINER_NAME`, `GCS_BUCKET`) are set. The registry logs which backends were initialized at startup for operator visibility.

**Key methods:**

- `backend_for(location: &StorageLocation) -> Result<Arc<dyn StorageBackend>>`: Returns the correct backend instance. For filesystem, creates a per-repo `FilesystemStorage` using the location's path. For cloud backends, returns the shared instance from the map. Returns an error if the requested backend is not available.
- `is_available(backend) -> bool`: Checks whether a backend type can be used. Filesystem is always available. Cloud backends are available only if initialized in the map. Used during repo creation validation.
- `default_backend() -> &str`: Returns the instance default backend name (from `STORAGE_BACKEND` env var).

**Location:** `backend/src/storage/registry.rs`, re-exported from `backend/src/storage/mod.rs`.

### AppState Changes

`AppState` gains a `storage_registry: Arc<StorageRegistry>` field. The existing `storage: Arc<dyn StorageBackend>` field is kept as the default backend instance.

`storage_for_repo()` changes signature from:

```rust
pub fn storage_for_repo(&self, repo_storage_path: &str) -> Arc<dyn StorageBackend>
```

to:

```rust
pub fn storage_for_repo(&self, location: &StorageLocation) -> Result<Arc<dyn StorageBackend>>
```

The implementation delegates to `storage_registry.backend_for()`. Errors propagate to the handler, which returns 500 to the client. No silent fallback.

### Handler Call Sites

Approximately 96 call sites across 39 handler files change from:

```rust
let storage = state.storage_for_repo(&repo.storage_path);
```

to:

```rust
let storage = state.storage_for_repo(&repo.storage_location())?;
```

Where `Repository` gains a helper method:

```rust
impl Repository {
    pub fn storage_location(&self) -> StorageLocation {
        StorageLocation { backend: self.storage_backend.clone(), path: self.storage_path.clone() }
    }
}
```

This is a mechanical change. Every call site already has the `repo` object in scope and is in an error-propagating context.

### Virtual Repository and Proxy Helper Changes

The `resolve_virtual_download` function in `proxy_helpers.rs` passes `(member_id, storage_path)` to a `local_fetch` callback. The callback signature changes to use `StorageLocation`:

```rust
// Before: Fn(Uuid, String) -> Fut
// After:  Fn(Uuid, StorageLocation) -> Fut
```

`fetch_virtual_members()` already queries the full `Repository` struct (including `storage_backend`), so the data is available. The callback signature change propagates to ~31 handler call sites that use `resolve_virtual_download`.

The `local_fetch_by_path`, `local_fetch_by_name_version`, and `local_fetch_by_path_suffix` helper functions in `proxy_helpers.rs` change to accept `&StorageLocation` instead of `storage_path: &str`.

### Cross-Backend Artifact Promotion

The promotion handler (`promotion.rs`) resolves source and target storage independently:

```rust
let source_storage = state.storage_for_repo(&source_repo.storage_location())?;
let target_storage = state.storage_for_repo(&target_repo.storage_location())?;
```

Content is read into memory as `Bytes` and written to the target, so cross-backend promotion (e.g., filesystem to S3) works naturally without special handling. The approval handler follows the same pattern.

Note: for large artifacts, this buffers the full content in memory. This is a pre-existing behavior, not introduced by this change. Streaming transfer is a potential follow-up optimization but is not in scope here.

### Service Changes

**ScannerService:** Replace `storage_backend_type: String` with `storage_registry: Arc<StorageRegistry>`. Update `resolve_repo_storage()` to query both `storage_backend` and `storage_path` from the DB (currently only queries `storage_path`) and delegate to the registry:

```sql
-- Before:
SELECT storage_path FROM repositories WHERE id = $1

-- After:
SELECT storage_backend, storage_path FROM repositories WHERE id = $1
```

**StorageGcService:** Replace `storage_backend_type: String` with `storage_registry: Arc<StorageRegistry>`. Update `run_gc()` SQL query to also select `r.storage_backend` alongside `r.storage_path` from the joined artifacts/repositories tables. Add `r.storage_backend` to the `GROUP BY` clause so orphans on different backends are resolved independently. Update `storage_for_path()` to accept `&StorageLocation` and delegate to the registry.

For cloud backends with shared content-addressed keys, the GC's `NOT EXISTS` subquery already correctly checks whether any live artifact references the same `storage_key` across all repos. For filesystem backends, the `NOT EXISTS` is overly conservative (it prevents GC of a local file even if the only live reference is on a different filesystem path), but this is safe (no data loss) and can be refined as a follow-up.

### Repository Creation

The `CreateRepositoryRequest` HTTP payload gains an optional field:

```rust
pub storage_backend: Option<String>,  // "filesystem", "s3", "azure", "gcs"
```

Validation logic in the create handler:

1. If `storage_backend` is `None`, use `config.storage_backend` (the instance default).
2. If provided and the requesting user is not an admin, return 403.
3. If provided, validate against `storage_registry.is_available(backend)`. Return 400 if unavailable.
4. Compute `storage_path`:
   - Filesystem: `{config.storage_path}/{repo_key}`
   - Cloud: `{repo_key}` (stored for metadata; not used in key routing)

The `UpdateRepositoryRequest` does not accept `storage_backend`. Immutable after creation.

### CachedRepo Changes

The `CachedRepo` struct (used by repo-visibility middleware) gains a `storage_backend: String` field so handlers can access it without a DB round-trip when using the cache.

The following locations that construct `CachedRepo` must be updated to populate the new field:

1. **Auth middleware** (`backend/src/api/middleware/auth.rs`): The DB query that populates `CachedRepo` must add `SELECT r.storage_backend`.
2. **Cargo handler** (`backend/src/api/handlers/cargo.rs`): Manual cache population must include `storage_backend`.

### OpenAPI/utoipa

- Add `storage_backend` field to the `CreateRepositoryRequest` schema with enum constraint (`filesystem`, `s3`, `azure`, `gcs`).
- Document it as optional, defaulting to the instance setting. Note that non-admin users cannot override the default.
- Add a new `GET /api/v1/admin/storage-backends` endpoint that returns the list of available backend type names (e.g., `["filesystem", "s3"]`). Admin-only. Does not expose bucket names, regions, endpoints, or credentials.

## Testing

**Unit tests (no database):**

- `StorageRegistry::backend_for()` returns correct backend type for each variant
- `StorageRegistry::is_available()` returns true for configured backends, false for unconfigured
- `StorageRegistry::backend_for()` returns error for unavailable backend
- `storage_for_repo()` returns `Result` and propagates errors (no fallback)
- `storage_for_repo()` routes correctly based on repo's `storage_backend` field

**Existing test compatibility:**

All existing tests use `storage_backend = "filesystem"` (the default). Filesystem routing is unchanged (still creates per-repo `FilesystemStorage` instances), so existing tests pass without modification.

**Integration tests:**

- Create a repo with explicit `storage_backend: "filesystem"`, verify artifacts are stored in the expected directory
- Attempt to create a repo with an unavailable backend, verify 400 response
- Attempt to create a repo with non-default backend as non-admin user, verify 403 response
- Verify default backend is applied when `storage_backend` is omitted
- Cross-backend promotion: promote an artifact between repos with different backends, verify content integrity

## Files Changed

| File | Change |
|------|--------|
| `backend/src/storage/registry.rs` | New: `StorageRegistry` and `StorageLocation` structs |
| `backend/src/storage/mod.rs` | Re-export `StorageRegistry`, `StorageLocation` |
| `backend/src/main.rs` | Build `StorageRegistry` at startup |
| `backend/src/api/mod.rs` | Add `storage_registry` to `AppState`, update `storage_for_repo()` to return `Result`, add `storage_backend` to `CachedRepo` |
| `backend/src/models/repository.rs` | Add `storage_location()` helper method |
| `backend/src/api/handlers/repositories.rs` | Validate `storage_backend` on create (admin-only for non-default), add system endpoint |
| `backend/src/api/handlers/proxy_helpers.rs` | Update `resolve_virtual_download` callback to use `StorageLocation`, update `local_fetch_*` helper signatures |
| `backend/src/api/handlers/*.rs` (~39 files, ~96 call sites) | Update `storage_for_repo()` call sites to use `storage_location()` and `?` |
| `backend/src/api/middleware/auth.rs` | Add `storage_backend` to `CachedRepo` DB query and construction |
| `backend/src/api/handlers/cargo.rs` | Add `storage_backend` to manual `CachedRepo` population |
| `backend/src/services/scanner_service.rs` | Use `StorageRegistry`, update `resolve_repo_storage()` SQL to select both columns |
| `backend/src/services/storage_gc_service.rs` | Use `StorageRegistry`, update `run_gc()` SQL to select and GROUP BY `storage_backend` |

## Operational Notes

- **Credential rotation:** Static credentials (access keys, storage account keys) require a process restart to take effect. Token-based auth (Azure RBAC, GCS Workload Identity) refreshes automatically within the backend implementations.
- **Backup:** With mixed backends, a complete backup must cover all active storage locations: the filesystem directory, S3 bucket, Azure container, and/or GCS bucket. The `GET /api/v1/admin/storage-backends` admin endpoint can be used to inventory which backends are in use.
- **Restore:** All backend credentials must be present in the environment before starting the server, or repos on unavailable backends will return 500 errors until credentials are restored.

## Non-Goals

- Per-repo credentials or bucket configuration. All repos sharing a backend type share the instance-level credentials and bucket.
- Per-repo key prefix isolation on cloud backends. Artifacts use shared content-addressed SHA-256 keys for deduplication.
- Changing a repo's backend after creation (artifact migration).
- UI changes. The frontend can use the new system endpoint to populate a dropdown, but UI work is out of scope for this spec.
- Streaming transfer for cross-backend promotion (follow-up optimization).
