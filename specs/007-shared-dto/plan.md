# Implementation Plan: Shared DTO Module for API Handlers

**Branch**: `007-shared-dto` | **Date**: 2026-01-26 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/007-shared-dto/spec.md`

## Summary

Consolidate duplicate Pagination structs from 6 handler files into a shared DTO module at `backend/src/api/dto.rs`. This eliminates code duplication across users, repositories, packages, permissions, groups, and builds handlers while maintaining backward-compatible API responses.

## Technical Context

**Language/Version**: Rust 1.75+
**Primary Dependencies**: axum, serde, serde_json
**Storage**: N/A (no storage changes)
**Testing**: cargo test
**Target Platform**: Linux server
**Project Type**: web (backend + frontend)
**Performance Goals**: N/A (pure refactor, no performance impact)
**Constraints**: Must maintain backward compatibility - no API response changes
**Scale/Scope**: 6 handler files affected, ~30 lines of duplicate code removed

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|-----------|--------|-------|
| I. API-First Design | ✅ PASS | No API contract changes; maintaining existing response structure |
| II. Security by Default | ✅ PASS | No security impact; pure code organization change |
| III. Simplicity & YAGNI | ✅ PASS | Reducing duplication is simplification; shared module serves immediate need |
| IV. Documentation Standards | ✅ PASS | Shared module will have doc comments |
| V. Accessibility Standards | ✅ N/A | Backend-only change |
| VI. Test Coverage | ✅ PASS | Existing tests must pass; no new functionality to test |
| VII. Observability | ✅ N/A | No observability changes |

**Gate Result**: PASS - All applicable principles satisfied

## Project Structure

### Documentation (this feature)

```text
specs/007-shared-dto/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output (empty - no API changes)
└── tasks.md             # Phase 2 output
```

### Source Code (repository root)

```text
backend/
├── src/
│   ├── api/
│   │   ├── dto.rs           # NEW: Shared DTOs (Pagination, PaginationQuery)
│   │   ├── mod.rs           # MODIFY: Add `pub mod dto;`
│   │   └── handlers/
│   │       ├── users.rs     # MODIFY: Import from dto, remove local Pagination
│   │       ├── repositories.rs  # MODIFY: Import from dto, remove local Pagination
│   │       ├── packages.rs  # MODIFY: Import from dto, remove local Pagination
│   │       ├── permissions.rs   # MODIFY: Import from dto, remove local Pagination
│   │       ├── groups.rs    # MODIFY: Import from dto, remove local Pagination
│   │       └── builds.rs    # MODIFY: Import from dto, remove local Pagination
│   └── ...
└── tests/
```

**Structure Decision**: Adding a single new file `backend/src/api/dto.rs` to the existing web application structure. No structural changes to directories.

## Complexity Tracking

> No violations - this is a simplification refactor that aligns with Constitution Principle III (Simplicity & YAGNI).
