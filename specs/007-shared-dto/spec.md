# Feature Specification: Shared DTO Module for API Handlers

**Feature Branch**: `007-shared-dto`
**Created**: 2026-01-26
**Status**: Draft
**Input**: User description: "Extract shared Pagination and common DTOs into a centralized module. Multiple identical Pagination structs are duplicated across 6+ handler files. Create backend/src/api/dto/mod.rs to consolidate: 1) Pagination struct, 2) Common ListQuery parameters (page/per_page), 3) Response wrapper types. Update all handlers to import from shared module."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Developer Uses Shared Pagination (Priority: P1)

A backend developer working on any API handler needs to return paginated list responses. Instead of defining their own Pagination struct, they import the shared one from a central location, ensuring consistency across all endpoints.

**Why this priority**: This is the core value of the refactor - eliminating duplication and ensuring all API responses use identical pagination structure.

**Independent Test**: Can be tested by creating a new handler that imports and uses the shared Pagination struct, verifying it compiles and produces correct JSON responses.

**Acceptance Scenarios**:

1. **Given** a developer creates a new list endpoint, **When** they need pagination, **Then** they can import `Pagination` from the shared DTO module and use it directly
2. **Given** an existing handler with local Pagination definition, **When** refactored to use shared module, **Then** all existing tests pass without modification
3. **Given** a paginated API response, **When** serialized to JSON, **Then** it contains `page`, `per_page`, `total`, and `total_pages` fields with correct types

---

### User Story 2 - Developer Uses Shared List Query Parameters (Priority: P2)

A backend developer building a list endpoint needs standard query parameters for pagination (page, per_page). They import shared query parameter structs that provide consistent defaults and validation.

**Why this priority**: Reduces boilerplate and ensures all list endpoints accept the same query parameter names and defaults.

**Independent Test**: Can be tested by creating a handler that uses the shared ListQuery struct and verifying query parameter parsing works correctly.

**Acceptance Scenarios**:

1. **Given** a developer creates a list endpoint, **When** they need query parameters, **Then** they can import `PaginationQuery` from the shared module
2. **Given** an API request without pagination parameters, **When** parsed, **Then** defaults are applied consistently (page=1, per_page=20)
3. **Given** an API request with pagination parameters, **When** parsed, **Then** values are correctly extracted and validated

---

### User Story 3 - Consistent API Response Structure (Priority: P3)

API consumers (frontend, external integrations) receive consistent response structures across all list endpoints. The pagination metadata is always in the same format regardless of which resource they're listing.

**Why this priority**: Improves API usability and allows frontend to use generic pagination components.

**Independent Test**: Can be tested by calling multiple list endpoints and verifying pagination structure is identical across responses.

**Acceptance Scenarios**:

1. **Given** a consumer calls the users list endpoint, **When** response is returned, **Then** pagination structure matches other list endpoints exactly
2. **Given** a consumer calls the repositories list endpoint, **When** response is returned, **Then** pagination field names and types are identical to the users endpoint

---

### Edge Cases

- What happens when page number exceeds total pages? System returns empty data array with correct pagination metadata.
- What happens when per_page is 0 or negative? System applies minimum value of 1.
- What happens when per_page exceeds maximum allowed? System caps at configured maximum (default: 100).

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST provide a shared `Pagination` struct containing `page` (u32), `per_page` (u32), `total` (i64), and `total_pages` (u32) fields
- **FR-002**: System MUST provide a shared `PaginationQuery` struct for extracting page/per_page from query parameters with defaults (page=1, per_page=20)
- **FR-003**: All existing handler files (users, repositories, packages, permissions, groups, builds) MUST be updated to import from the shared module
- **FR-004**: System MUST maintain backward compatibility - existing API responses must not change structure
- **FR-005**: System MUST ensure all existing tests pass after refactoring
- **FR-006**: Shared module MUST be located at `backend/src/api/dto/mod.rs` or `backend/src/api/dto.rs`
- **FR-007**: System MUST provide derive macros for serialization (Serialize, Deserialize) on shared structs

### Key Entities

- **Pagination**: Metadata struct for paginated responses containing current page, items per page, total item count, and total page count
- **PaginationQuery**: Query parameter extraction struct with optional page and per_page fields that provide defaults when not specified

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Zero duplicate Pagination struct definitions remain in handler files after refactoring
- **SC-002**: All 6+ affected handler files successfully compile using the shared module
- **SC-003**: 100% of existing pagination-related tests pass without modification
- **SC-004**: API response structure remains identical (verified by comparing JSON output before/after)
- **SC-005**: New handlers can add pagination support with a single import statement

## Assumptions

- The existing Pagination structs across all handlers are semantically identical (same field names, types, and serialization behavior)
- The project uses serde for JSON serialization
- No handler requires custom pagination fields beyond the standard four (page, per_page, total, total_pages)
- The refactor is purely structural - no behavioral changes to pagination logic
