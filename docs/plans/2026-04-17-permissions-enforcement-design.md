# Permissions Enforcement Design

Fixes: [#794](https://github.com/artifact-keeper/artifact-keeper/issues/794)

## Problem

The `permissions` table (migration 018) stores fine-grained access control rules
with a complete CRUD API at `/api/v1/permissions`. Administrators can create
rules that grant or restrict specific actions (read, write, delete, admin) for
specific principals (users, groups) on specific targets (repositories, groups,
artifacts). However, the backend never queries these rules when authorizing
requests. The auth middleware checks `is_admin` on the JWT claims and checks API
token scopes/repo restrictions, but it does not consult the permissions table.

This means permission rules are silently ignored. An administrator who creates a
rule granting "read" on repo X to group Y will see the rule in the API response,
but members of group Y gain no actual access from it. The security gap is that
the feature appears to work while providing no protection.

## Current Authorization Model

The existing authorization pipeline has three layers:

1. **Authentication middleware** (`auth_middleware`, `optional_auth_middleware`,
   `admin_middleware`) identifies the caller and populates `AuthExtension` with
   `user_id`, `is_admin`, `scopes`, and `allowed_repo_ids`.

2. **Repo visibility middleware** (`repo_visibility_middleware`) checks whether
   the target repository is public or private, requires auth for writes, and
   enforces API token repo-scope restrictions.

3. **Handler-level checks** call `auth.require_admin()` or `auth.require_scope()`
   for specific operations (e.g., peer management, user CRUD, telemetry).

None of these layers query the `permissions` table.

## Permissions Table Schema

From migration `018_groups_permissions.sql`:

```sql
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_type VARCHAR(50) NOT NULL,   -- 'user' or 'group'
    principal_id UUID NOT NULL,
    target_type VARCHAR(50) NOT NULL,      -- 'repository', 'group', 'artifact'
    target_id UUID NOT NULL,
    actions TEXT[] NOT NULL DEFAULT '{}',   -- 'read', 'write', 'delete', 'admin'
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(principal_type, principal_id, target_type, target_id)
);
```

Supporting tables:
- `groups` (id, name, description)
- `user_group_members` (user_id, group_id)

Key design points:
- A single row grants a set of actions from one principal to one target.
- Group membership is resolved through `user_group_members`.
- The schema supports repository, group, and artifact target types.
- There is no explicit "deny" column; the model is allow-only.

## Enforcement Plan

### Phase 1: Permission Resolution Service (#795)

Create `backend/src/services/permission_service.rs` with a `PermissionService`
that answers the question: "Does user U have action A on target T?"

Resolution logic:
1. Query all `permissions` rows where `principal_type = 'user'` AND
   `principal_id = user_id` AND `target_type = T` AND `target_id = target_id`.
2. Query all `permissions` rows where `principal_type = 'group'` AND
   `principal_id IN (SELECT group_id FROM user_group_members WHERE user_id = U)`
   AND `target_type = T` AND `target_id = target_id`.
3. Union the action sets from both queries.
4. Return true if the requested action is in the unioned set.

Admin users bypass permission checks entirely (preserving current behavior).

Performance considerations:
- Cache resolved permissions per (user_id, target_type, target_id) with a
  short TTL (30-60 seconds), similar to the API token cache pattern.
- Invalidate cache entries on permission CRUD events via the event bus
  ("permission.created", "permission.updated", "permission.deleted").
- Batch the user + group lookup into a single query using a UNION.

### Phase 2: Repository Access Enforcement (#796)

Integrate the permission service into `repo_visibility_middleware`. After the
existing public/private and API-token-scope checks pass, add:

1. If the user is admin, skip permission checks (backward compatible).
2. If no permission rules exist for this repository, allow access (backward
   compatible: existing repos without permission rules keep working).
3. If permission rules exist for this repository, check that the authenticated
   user has the required action:
   - GET/HEAD on package content: requires "read"
   - PUT/POST (upload, publish): requires "write"
   - DELETE: requires "delete"
   - Repository settings changes: requires "admin"

The "no rules means open access" default is critical for backward compatibility.
Locking down a repository requires an administrator to explicitly create at
least one permission rule for it. Once any rule exists for a repository, only
principals with matching rules gain access.

This mirrors the common pattern in Nexus, Artifactory, and Harbor.

### Phase 3: API Endpoint Authorization (#797)

Add permission checks to handler-level operations that currently only check
`is_admin`:

- **User management** (create, update, delete, list users): requires "admin"
  action on a system-level target or remains admin-only.
- **Repository management** (create, delete, update settings): requires "admin"
  action on the target repository.
- **Group management** (create groups, manage membership): requires "admin"
  action on the target group.
- **Audit log access**: remains admin-only (no per-resource scoping needed).

For system-level actions that have no specific target (like creating a new
repository), use a sentinel target_id (e.g., the zero UUID) with target_type
"system".

### Phase 4: UI Integration and Documentation (#798)

- Update the web frontend to show enforcement status from `/api/v1/system/config`.
- Add a warning banner in the permissions management UI when
  `enforcement_enabled` is false.
- Once enforcement is active, flip `enforcement_enabled` to true in the system
  config response.
- Document the permission model in the site docs under security/permissions.

## Interaction with Existing Role System

The current system has two authorization mechanisms:

1. **Role-based (is_admin)**: Binary admin/non-admin from the users table.
2. **API token scopes**: Coarse-grained scopes ("read:artifacts",
   "write:artifacts", "*") and optional repo ID restrictions on API tokens.

Permissions add a third, more granular layer. The intended precedence:

- Admin users bypass all permission checks (unchanged).
- API token scope restrictions are checked first (tokens with
  "read:artifacts" cannot write even if a permission rule allows "write").
- Permission rules are checked after token scope validation.
- Non-admin users without any applicable permission rules fall back to the
  current behavior (access determined by repo visibility and token scope).

This means permissions only restrict access further; they never grant access
that a token's scopes would deny. Token scopes are the ceiling, permission
rules are the floor.

## What This PR Does

This PR does NOT implement enforcement. It:

1. Adds a startup WARNING log when permission rules exist but are not enforced,
   so administrators see the gap in their server logs.
2. Adds `permissions.rules_exist` and `permissions.enforcement_enabled` fields
   to the `/api/v1/system/config` response, so frontends can display the
   enforcement status.
3. Documents the enforcement plan in this design document.
4. Creates sub-issues (#795-#798) to track the phased implementation.

## Migration Path

No database migrations are needed. The existing schema from migration 018 is
sufficient. The enforcement code reads from the existing `permissions`,
`groups`, and `user_group_members` tables without schema changes.

Operators upgrading from a version without enforcement to one with enforcement
will experience this transition:

1. Before: permission rules are stored but ignored.
2. After this PR: server logs warn about unenforced rules; system config
   exposes the status.
3. After Phase 2: repository-level rules take effect. Repositories with no
   rules continue to work as before. Repositories with rules restrict access
   to matching principals.

## Open Questions

- Should there be a global toggle (env var) to disable enforcement even after
  the code ships? This would provide an escape hatch if enforcement causes
  unexpected lockouts. A `PERMISSIONS_ENFORCEMENT=false` env var could be
  useful during rollout.
- Should "deny" rules be supported in addition to "allow"? The current schema
  has no deny column, and allow-only is simpler. Deny support could be added
  later with a migration that adds an `effect` column (`allow` / `deny`).
- How should wildcard permissions work? For example, granting "read" on all
  repositories to a group. The current schema requires a specific target_id.
  A sentinel UUID could represent "all repositories of this type".
