# Data Model: Shared DTO Module

**Feature**: 007-shared-dto
**Date**: 2026-01-26

## Entities

### Pagination

Response metadata for paginated list endpoints.

| Field | Type | Description |
|-------|------|-------------|
| page | u32 | Current page number (1-indexed) |
| per_page | u32 | Number of items per page |
| total | i64 | Total number of items across all pages |
| total_pages | u32 | Total number of pages |

**Relationships**: None (embedded in list response payloads)

**Validation Rules**:
- `page` >= 1
- `per_page` >= 1
- `total` >= 0
- `total_pages` = ceil(total / per_page)

**State Transitions**: N/A (immutable response object)

### PaginationQuery

Query parameters for list endpoint requests.

| Field | Type | Description |
|-------|------|-------------|
| page | Option<u32> | Requested page number (default: 1) |
| per_page | Option<u32> | Requested items per page (default: 20) |

**Relationships**: Used to construct `Pagination` response

**Validation Rules**:
- `page` must be >= 1 if provided
- `per_page` must be >= 1 if provided
- `per_page` should be capped at a reasonable maximum (100) by handlers

**State Transitions**: N/A (immutable request parameters)

## Entity Diagram

```text
┌─────────────────────────────────────────┐
│           API Request                   │
│  ┌─────────────────────────────────┐    │
│  │     PaginationQuery             │    │
│  │  - page: Option<u32>            │    │
│  │  - per_page: Option<u32>        │    │
│  └─────────────────────────────────┘    │
└─────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│           Handler Logic                 │
│  - Apply defaults (page=1, per_page=20) │
│  - Query database with LIMIT/OFFSET     │
│  - Count total items                    │
│  - Calculate total_pages                │
└─────────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────┐
│           API Response                  │
│  ┌─────────────────────────────────┐    │
│  │     Pagination                  │    │
│  │  - page: u32                    │    │
│  │  - per_page: u32                │    │
│  │  - total: i64                   │    │
│  │  - total_pages: u32             │    │
│  └─────────────────────────────────┘    │
│  + data: Vec<T>                         │
└─────────────────────────────────────────┘
```
