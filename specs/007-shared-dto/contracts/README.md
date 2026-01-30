# API Contracts: Shared DTO Module

**Feature**: 007-shared-dto
**Date**: 2026-01-26

## No New Contracts

This feature is a pure refactor that consolidates existing code without changing API contracts.

### Existing Pagination Contract (unchanged)

All list endpoints already return pagination metadata in this format:

```json
{
  "data": [...],
  "pagination": {
    "page": 1,
    "per_page": 20,
    "total": 100,
    "total_pages": 5
  }
}
```

### Contract Stability

The following endpoints use this pagination format and will continue to do so after refactoring:

- `GET /api/users`
- `GET /api/repositories`
- `GET /api/packages`
- `GET /api/permissions`
- `GET /api/groups`
- `GET /api/builds`

**No OpenAPI changes required** - the external API contract remains identical.
