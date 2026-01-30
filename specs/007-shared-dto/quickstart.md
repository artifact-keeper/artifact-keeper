# Quickstart: Shared DTO Module

**Feature**: 007-shared-dto
**Date**: 2026-01-26

## Overview

This feature creates a shared DTO module for common API response types, starting with the `Pagination` struct that was duplicated across 6 handler files.

## Usage

### Import the shared DTOs

```rust
use crate::api::dto::{Pagination, PaginationQuery};
```

### Using Pagination in responses

```rust
use crate::api::dto::Pagination;

#[derive(Serialize)]
pub struct ListUsersResponse {
    pub data: Vec<UserResponse>,
    pub pagination: Pagination,
}

async fn list_users(...) -> Result<Json<ListUsersResponse>> {
    // Query database...
    let total = count_users(&db).await?;
    let users = fetch_users(&db, page, per_page).await?;

    Ok(Json(ListUsersResponse {
        data: users,
        pagination: Pagination {
            page,
            per_page,
            total,
            total_pages: ((total as f64) / (per_page as f64)).ceil() as u32,
        },
    }))
}
```

### Using PaginationQuery for request parameters

```rust
use crate::api::dto::PaginationQuery;

#[derive(Deserialize)]
pub struct ListUsersQuery {
    #[serde(flatten)]
    pub pagination: PaginationQuery,
    pub search: Option<String>,
    pub is_active: Option<bool>,
}

async fn list_users(
    Query(query): Query<ListUsersQuery>,
    ...
) -> Result<Json<ListUsersResponse>> {
    let page = query.pagination.page();      // defaults to 1
    let per_page = query.pagination.per_page(); // defaults to 20
    // ...
}
```

## Verification

Run tests to ensure the refactor doesn't break anything:

```bash
# Run all backend tests
cargo test --workspace

# Run specific handler tests
cargo test --package artifact-keeper-backend handlers::users
cargo test --package artifact-keeper-backend handlers::repositories
```

## Files Changed

| File | Change |
|------|--------|
| `backend/src/api/dto.rs` | NEW - Shared Pagination and PaginationQuery |
| `backend/src/api/mod.rs` | ADD `pub mod dto;` |
| `backend/src/api/handlers/users.rs` | REMOVE local Pagination, ADD import |
| `backend/src/api/handlers/repositories.rs` | REMOVE local Pagination, ADD import |
| `backend/src/api/handlers/packages.rs` | REMOVE local Pagination, ADD import |
| `backend/src/api/handlers/permissions.rs` | REMOVE local Pagination, ADD import |
| `backend/src/api/handlers/groups.rs` | REMOVE local Pagination, ADD import |
| `backend/src/api/handlers/builds.rs` | REMOVE local Pagination, ADD import |
