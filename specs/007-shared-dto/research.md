# Research: Shared DTO Module

**Feature**: 007-shared-dto
**Date**: 2026-01-26

## Research Summary

### 1. Existing Pagination Struct Analysis

**Finding**: 6 identical `Pagination` structs exist across handler files:

| File | Line | Fields | Types |
|------|------|--------|-------|
| users.rs | 91-96 | page, per_page, total, total_pages | u32, u32, i64, u32 |
| repositories.rs | 99-104 | page, per_page, total, total_pages | u32, u32, i64, u32 |
| packages.rs | 81-86 | page, per_page, total, total_pages | u32, u32, i64, u32 |
| permissions.rs | 83-88 | page, per_page, total, total_pages | u32, u32, i64, u32 |
| groups.rs | 67-72 | page, per_page, total, total_pages | u32, u32, i64, u32 |
| builds.rs | 99-104 | page, per_page, total, total_pages | u32, u32, i64, u32 |

**Exception**: `migration.rs:217-222` has `PaginationInfo` with all `i64` types - different struct, not included in consolidation.

**Decision**: Consolidate the 6 identical structs; leave `PaginationInfo` as-is since it has different types and serves a different purpose.

### 2. Serialization Traits

**Finding**: All existing Pagination structs derive `Serialize` only (no `Deserialize` needed for response-only structs).

**Decision**: Shared `Pagination` will derive `Debug, Clone, Serialize` to match existing behavior.

### 3. Module Location

**Alternatives Considered**:
1. `backend/src/api/dto.rs` - Single file in api module
2. `backend/src/api/dto/mod.rs` + pagination.rs - Directory with sub-modules
3. `backend/src/api/handlers/common.rs` - Inside handlers directory

**Decision**: Use `backend/src/api/dto.rs` (Option 1)
- **Rationale**: Single struct doesn't warrant a directory; `dto` is a standard name for Data Transfer Objects; direct sibling to `handlers` keeps API-related code together.

### 4. Query Parameter Struct

**Finding**: Each handler defines its own list query struct with varying filters but common pagination fields:

| Handler | Query Struct | Pagination Fields | Custom Filters |
|---------|--------------|-------------------|----------------|
| users | ListUsersQuery | page, per_page | search, is_active, is_admin |
| repositories | ListRepositoriesQuery | page, per_page | format, repo_type |
| packages | ListPackagesQuery | page, per_page | (varies) |
| permissions | ListPermissionsQuery | page, per_page | (varies) |
| groups | ListGroupsQuery | page, per_page | (varies) |
| builds | ListBuildsQuery | page, per_page | (varies) |

**Decision**: Create a shared `PaginationQuery` struct for the common fields but do NOT try to consolidate the full query structs - each handler's custom filters are legitimately different.

### 5. Default Values

**Finding**: Handlers use varying defaults:
- Most use `page.unwrap_or(1)` and `per_page.unwrap_or(20)`
- Some use `per_page.unwrap_or(10)` or other values

**Decision**: `PaginationQuery` will provide accessor methods `page()` and `per_page()` that return defaults (page=1, per_page=20). Handlers can override defaults if needed by extracting raw `Option<u32>` values.

### 6. Import Path

**Decision**: Handlers will import as:
```rust
use crate::api::dto::{Pagination, PaginationQuery};
```

This is consistent with existing import patterns in the codebase.

## Best Practices Applied

1. **Rust DTO patterns**: Use `#[derive]` for common traits rather than manual implementations
2. **Serde serialization**: Keep `#[serde(rename_all = "snake_case")]` if needed (current structs use default snake_case)
3. **Module organization**: Place DTOs adjacent to their consumers (api module)
4. **Minimal public API**: Only expose what's needed; keep implementation details private
