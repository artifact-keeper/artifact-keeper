# Tasks: Shared DTO Module for API Handlers

**Input**: Design documents from `/specs/007-shared-dto/`
**Prerequisites**: plan.md (required), spec.md (required), research.md, data-model.md, contracts/

**Tests**: No new tests required - this is a pure refactor. Existing tests validate success.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- **Web app**: `backend/src/`, `frontend/src/`

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Create the shared DTO module structure

- [x] T001 Create shared DTO module file at backend/src/api/dto.rs
- [x] T002 Register dto module in backend/src/api/mod.rs by adding `pub mod dto;`

---

## Phase 2: Foundational (DTO Implementation)

**Purpose**: Implement shared structs that all user stories depend on

**⚠️ CRITICAL**: Handler refactoring cannot begin until this phase is complete

- [x] T003 Implement Pagination struct with page, per_page, total, total_pages fields in backend/src/api/dto.rs
- [x] T004 Implement PaginationQuery struct with optional page/per_page fields and accessor methods in backend/src/api/dto.rs
- [x] T005 Add doc comments for Pagination and PaginationQuery in backend/src/api/dto.rs
- [x] T006 Verify compilation with `cargo check --package artifact-keeper-backend`

**Checkpoint**: Shared DTO module ready - handler refactoring can now begin in parallel

---

## Phase 3: User Story 1 - Developer Uses Shared Pagination (Priority: P1) 🎯 MVP

**Goal**: Replace duplicate Pagination structs in all handlers with shared import

**Independent Test**: `cargo test --package artifact-keeper-backend` passes with no changes to test code

### Implementation for User Story 1

- [x] T007 [P] [US1] Refactor backend/src/api/handlers/users.rs - remove local Pagination, add import from crate::api::dto
- [x] T008 [P] [US1] Refactor backend/src/api/handlers/repositories.rs - remove local Pagination, add import from crate::api::dto
- [x] T009 [P] [US1] Refactor backend/src/api/handlers/packages.rs - remove local Pagination, add import from crate::api::dto
- [x] T010 [P] [US1] Refactor backend/src/api/handlers/permissions.rs - remove local Pagination, add import from crate::api::dto
- [x] T011 [P] [US1] Refactor backend/src/api/handlers/groups.rs - remove local Pagination, add import from crate::api::dto
- [x] T012 [P] [US1] Refactor backend/src/api/handlers/builds.rs - remove local Pagination, add import from crate::api::dto
- [x] T013 [US1] Verify all handlers compile with `cargo check --package artifact-keeper-backend`
- [x] T014 [US1] Run existing tests with `cargo test --package artifact-keeper-backend` to validate backward compatibility

**Checkpoint**: All 6 handlers using shared Pagination - User Story 1 complete

---

## Phase 4: User Story 2 - Developer Uses Shared List Query Parameters (Priority: P2)

**Goal**: Provide PaginationQuery for handlers to optionally adopt

**Independent Test**: PaginationQuery can be imported and used; provides default values

### Implementation for User Story 2

- [x] T015 [US2] Add helper method `Pagination::from_query_and_total(query: &PaginationQuery, total: i64)` in backend/src/api/dto.rs
- [x] T016 [US2] Verify PaginationQuery defaults work correctly (page=1, per_page=20) with a compile check

**Checkpoint**: PaginationQuery available for future handler simplification - User Story 2 complete

---

## Phase 5: User Story 3 - Consistent API Response Structure (Priority: P3)

**Goal**: Verify all list endpoints return identical pagination structure

**Independent Test**: Manual or automated verification that pagination JSON is identical across endpoints

### Implementation for User Story 3

- [x] T017 [US3] Run integration tests to verify pagination response consistency
- [x] T018 [US3] Document usage in backend/src/api/dto.rs module-level doc comment

**Checkpoint**: API response consistency verified - User Story 3 complete

---

## Phase 6: Polish & Cross-Cutting Concerns

**Purpose**: Final validation and cleanup

- [x] T019 Run full test suite with `cargo test --workspace`
- [x] T020 Run clippy lints with `cargo clippy --workspace`
- [x] T021 Verify no duplicate Pagination structs remain with grep search

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion - BLOCKS all user stories
- **User Stories (Phase 3-5)**: All depend on Foundational phase completion
- **Polish (Phase 6)**: Depends on all user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational (Phase 2) - No dependencies on other stories
- **User Story 2 (P2)**: Can start after Foundational (Phase 2) - Independent of US1
- **User Story 3 (P3)**: Can start after US1 complete (needs handlers refactored to verify consistency)

### Parallel Opportunities

- T007-T012 can ALL run in parallel (6 different handler files, no dependencies between them)
- T003-T005 are sequential (same file: dto.rs)
- US1 and US2 can run in parallel after Foundational phase

---

## Parallel Example: User Story 1 Handler Refactoring

```bash
# All 6 handler refactors can run simultaneously:
Task: "Refactor users.rs - remove local Pagination, add import"
Task: "Refactor repositories.rs - remove local Pagination, add import"
Task: "Refactor packages.rs - remove local Pagination, add import"
Task: "Refactor permissions.rs - remove local Pagination, add import"
Task: "Refactor groups.rs - remove local Pagination, add import"
Task: "Refactor builds.rs - remove local Pagination, add import"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup (T001-T002)
2. Complete Phase 2: Foundational (T003-T006)
3. Complete Phase 3: User Story 1 (T007-T014)
4. **STOP and VALIDATE**: Run `cargo test` - all tests should pass
5. This delivers 100% of the duplicate code elimination value

### Incremental Delivery

1. Complete Setup + Foundational → Shared module ready
2. Add User Story 1 → Handlers refactored → Test (MVP complete!)
3. Add User Story 2 → PaginationQuery helper ready
4. Add User Story 3 → Consistency verified → Polish

### Parallel Execution

With the Task tool, launch T007-T012 in a single message for maximum parallelism:
- 6 independent file modifications
- No conflicts or dependencies between them
- Significant speed improvement over sequential execution

---

## Notes

- This is a pure refactor - no behavioral changes
- Existing tests are the validation mechanism
- [P] tasks in US1 = 6 different files, truly independent
- Migration.rs PaginationInfo is NOT affected (different struct with different types)
- Commit after each phase for safe rollback points
