# Data Model: Artifact Registry Platform

**Feature**: 001-artifact-registry | **Date**: 2026-01-14

*Extracted from feature spec Key Entities and functional requirements.*

## Entity Relationship Diagram

```
┌─────────────┐       ┌─────────────┐       ┌─────────────┐
│    User     │───────│  RoleAssign │───────│    Role     │
└─────────────┘       └─────────────┘       └─────────────┘
      │                                            │
      │                                            │
      ▼                                            ▼
┌─────────────┐       ┌─────────────┐       ┌─────────────┐
│  ApiToken   │       │ Permission  │◄──────│PermGrant   │
└─────────────┘       └─────────────┘       └─────────────┘
                            │
                            ▼
┌─────────────┐       ┌─────────────┐       ┌─────────────┐
│  EdgeNode   │───────│ Repository  │───────│  Artifact   │
└─────────────┘       └─────────────┘       └─────────────┘
      │                     │                      │
      │                     │                      │
      ▼                     ▼                      ▼
┌─────────────┐       ┌─────────────┐       ┌─────────────┐
│  SyncTask   │       │ VirtualRepo │       │ArtifactMeta │
└─────────────┘       └─────────────┘       └─────────────┘
                                                   │
                                                   ▼
┌─────────────┐                             ┌─────────────┐
│   Backup    │                             │DownloadStat │
└─────────────┘                             └─────────────┘

┌─────────────┐       ┌─────────────┐
│   Plugin    │───────│PluginConfig│
└─────────────┘       └─────────────┘

┌─────────────┐
│  AuditLog   │
└─────────────┘
```

## Core Entities

### Repository

Container for artifacts of a specific format. Maps to spec entity: **Repository**.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PK | Unique identifier |
| key | VARCHAR(255) | UNIQUE, NOT NULL | URL-safe repository identifier |
| name | VARCHAR(255) | NOT NULL | Human-readable name |
| description | TEXT | NULLABLE | Repository description |
| format | ENUM | NOT NULL | Repository type (see Format enum) |
| repo_type | ENUM | NOT NULL | local, remote, virtual |
| storage_backend | VARCHAR(50) | NOT NULL | filesystem, s3 |
| storage_path | VARCHAR(1024) | NOT NULL | Storage location (path or bucket/prefix) |
| upstream_url | VARCHAR(2048) | NULLABLE | For remote repos: upstream URL |
| is_public | BOOLEAN | DEFAULT false | Anonymous read access |
| quota_bytes | BIGINT | NULLABLE | Storage quota (FR-045) |
| created_at | TIMESTAMP | NOT NULL | Creation timestamp |
| updated_at | TIMESTAMP | NOT NULL | Last modification |

**Format Enum** (FR-007 through FR-020):
```
maven, gradle, npm, pypi, nuget, go, rubygems,
docker, helm, rpm, debian, conan, cargo, generic
```

**Repo Type Enum** (FR-021, FR-022):
```
local    - Stores artifacts directly
remote   - Proxies/caches from upstream
virtual  - Aggregates multiple repos
```

### VirtualRepoMember

Links virtual repositories to their underlying repositories.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PK | Unique identifier |
| virtual_repo_id | UUID | FK(Repository), NOT NULL | Virtual repository |
| member_repo_id | UUID | FK(Repository), NOT NULL | Member repository |
| priority | INTEGER | NOT NULL | Resolution order (lower = higher priority) |
| created_at | TIMESTAMP | NOT NULL | Creation timestamp |

**Unique Constraint**: (virtual_repo_id, member_repo_id)

---

### Artifact

A versioned file stored in the registry. Maps to spec entity: **Artifact**.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PK | Unique identifier |
| repository_id | UUID | FK(Repository), NOT NULL | Parent repository |
| path | VARCHAR(2048) | NOT NULL | Artifact path within repository |
| name | VARCHAR(512) | NOT NULL | Artifact name (e.g., package name) |
| version | VARCHAR(255) | NULLABLE | Version string (format-specific) |
| size_bytes | BIGINT | NOT NULL | File size in bytes |
| checksum_sha256 | CHAR(64) | NOT NULL | SHA-256 checksum (FR-002) |
| checksum_md5 | CHAR(32) | NULLABLE | MD5 checksum (legacy support) |
| checksum_sha1 | CHAR(40) | NULLABLE | SHA-1 checksum (Maven) |
| content_type | VARCHAR(255) | NOT NULL | MIME type |
| storage_key | VARCHAR(2048) | NOT NULL | Key in storage backend (CAS) |
| is_deleted | BOOLEAN | DEFAULT false | Soft delete flag (FR-004) |
| uploaded_by | UUID | FK(User), NULLABLE | Uploader |
| created_at | TIMESTAMP | NOT NULL | Upload timestamp |
| updated_at | TIMESTAMP | NOT NULL | Last modification |

**Unique Constraint**: (repository_id, path) - Enforces immutable versions (FR-003)

---

### ArtifactMetadata

Format-specific metadata stored as JSONB.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PK | Unique identifier |
| artifact_id | UUID | FK(Artifact), UNIQUE | Parent artifact |
| format | ENUM | NOT NULL | Format type |
| metadata | JSONB | NOT NULL | Format-specific data |
| properties | JSONB | DEFAULT '{}' | Custom properties (FR-005) |

**Metadata Examples by Format**:

```json
// Maven (FR-007)
{
  "groupId": "com.example",
  "artifactId": "my-lib",
  "version": "1.0.0",
  "packaging": "jar",
  "classifier": null
}

// npm (FR-009)
{
  "name": "@scope/package",
  "version": "1.0.0",
  "dependencies": {...},
  "devDependencies": {...}
}

// Docker/OCI (FR-014)
{
  "digest": "sha256:abc...",
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "architecture": "amd64",
  "os": "linux",
  "layers": [...]
}

// PyPI (FR-010)
{
  "name": "my-package",
  "version": "1.0.0",
  "requires_python": ">=3.8",
  "requires_dist": [...]
}

// RPM (FR-016)
{
  "name": "my-package",
  "version": "1.0",
  "release": "1.el9",
  "arch": "x86_64",
  "requires": [...],
  "provides": [...]
}

// Debian (FR-017)
{
  "package": "my-package",
  "version": "1.0-1",
  "architecture": "amd64",
  "depends": [...],
  "section": "utils"
}

// Helm (FR-015)
{
  "name": "my-chart",
  "version": "1.0.0",
  "appVersion": "2.0.0",
  "dependencies": [...]
}
```

---

### User

An identity that can authenticate and access the system. Maps to spec entity: **User**.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PK | Unique identifier |
| username | VARCHAR(255) | UNIQUE, NOT NULL | Login name |
| email | VARCHAR(255) | UNIQUE, NOT NULL | Email address |
| password_hash | VARCHAR(255) | NULLABLE | bcrypt hash (FR-023) |
| auth_provider | ENUM | NOT NULL | local, ldap, saml, oidc |
| external_id | VARCHAR(512) | NULLABLE | External provider ID |
| display_name | VARCHAR(255) | NULLABLE | Display name |
| is_active | BOOLEAN | DEFAULT true | Account active |
| is_admin | BOOLEAN | DEFAULT false | System administrator |
| last_login_at | TIMESTAMP | NULLABLE | Last successful login |
| created_at | TIMESTAMP | NOT NULL | Account creation |
| updated_at | TIMESTAMP | NOT NULL | Last modification |

**Auth Provider Enum** (FR-023 through FR-026):
```
local  - Password authentication
ldap   - LDAP/Active Directory
saml   - SAML 2.0 SSO
oidc   - OpenID Connect
```

---

### ApiToken

Programmatic access tokens for users (FR-028).

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PK | Unique identifier |
| user_id | UUID | FK(User), NOT NULL | Token owner |
| name | VARCHAR(255) | NOT NULL | Token description |
| token_hash | VARCHAR(255) | NOT NULL | SHA-256 of token |
| token_prefix | CHAR(8) | NOT NULL | First 8 chars (for identification) |
| scopes | VARCHAR[] | NOT NULL | Permission scopes |
| expires_at | TIMESTAMP | NULLABLE | Expiration (null = never) |
| last_used_at | TIMESTAMP | NULLABLE | Last usage |
| created_at | TIMESTAMP | NOT NULL | Creation timestamp |

---

### Role

A named set of permissions. Maps to spec entity: **Role**.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PK | Unique identifier |
| name | VARCHAR(255) | UNIQUE, NOT NULL | Role name |
| description | TEXT | NULLABLE | Role description |
| is_system | BOOLEAN | DEFAULT false | Built-in role (not editable) |
| created_at | TIMESTAMP | NOT NULL | Creation timestamp |
| updated_at | TIMESTAMP | NOT NULL | Last modification |

**Built-in Roles**:
- `admin` - Full system access
- `developer` - Read/write to assigned repos
- `reader` - Read-only access to assigned repos
- `anonymous` - Unauthenticated access (public repos only)

---

### PermissionGrant

Links roles to repositories with specific permissions (FR-027).

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PK | Unique identifier |
| role_id | UUID | FK(Role), NOT NULL | Role |
| repository_id | UUID | FK(Repository), NULLABLE | Specific repo (null = all) |
| permission | ENUM | NOT NULL | Permission type |
| created_at | TIMESTAMP | NOT NULL | Creation timestamp |

**Permission Enum**:
```
read     - Download artifacts, view metadata
write    - Upload artifacts, update metadata
delete   - Delete artifacts
admin    - Manage repository settings
```

---

### RoleAssignment

Assigns roles to users.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PK | Unique identifier |
| user_id | UUID | FK(User), NOT NULL | User |
| role_id | UUID | FK(Role), NOT NULL | Role |
| repository_id | UUID | FK(Repository), NULLABLE | Scope (null = global) |
| created_at | TIMESTAMP | NOT NULL | Assignment timestamp |

**Unique Constraint**: (user_id, role_id, repository_id)

---

### EdgeNode

Distributed cache instance. Maps to spec entity: **Edge Node**.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PK | Unique identifier |
| name | VARCHAR(255) | UNIQUE, NOT NULL | Node name |
| url | VARCHAR(2048) | NOT NULL | Node base URL |
| api_key_hash | VARCHAR(255) | NOT NULL | Authentication key |
| status | ENUM | NOT NULL | online, offline, syncing |
| last_heartbeat | TIMESTAMP | NULLABLE | Last health check (FR-033) |
| storage_used_bytes | BIGINT | DEFAULT 0 | Storage usage |
| storage_limit_bytes | BIGINT | NULLABLE | Storage quota |
| created_at | TIMESTAMP | NOT NULL | Registration timestamp |
| updated_at | TIMESTAMP | NOT NULL | Last modification |

---

### SyncTask

Replication configuration for edge nodes (FR-030, FR-031).

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PK | Unique identifier |
| edge_node_id | UUID | FK(EdgeNode), NOT NULL | Target edge node |
| repository_id | UUID | FK(Repository), NOT NULL | Source repository |
| sync_mode | ENUM | NOT NULL | on_demand, scheduled, eager |
| include_pattern | VARCHAR(1024) | NULLABLE | Include glob pattern |
| exclude_pattern | VARCHAR(1024) | NULLABLE | Exclude glob pattern |
| last_sync_at | TIMESTAMP | NULLABLE | Last sync completion |
| next_sync_at | TIMESTAMP | NULLABLE | Next scheduled sync |
| status | ENUM | NOT NULL | active, paused, error |
| error_message | TEXT | NULLABLE | Last error |
| created_at | TIMESTAMP | NOT NULL | Creation timestamp |
| updated_at | TIMESTAMP | NOT NULL | Last modification |

---

### Backup

Point-in-time backup snapshot. Maps to spec entity: **Backup**.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PK | Unique identifier |
| name | VARCHAR(255) | NOT NULL | Backup name/label |
| type | ENUM | NOT NULL | full, incremental (FR-035) |
| status | ENUM | NOT NULL | pending, running, completed, failed |
| storage_location | VARCHAR(2048) | NOT NULL | Backup storage path (FR-036) |
| size_bytes | BIGINT | NULLABLE | Backup size |
| artifact_count | INTEGER | NULLABLE | Number of artifacts |
| checksum | VARCHAR(64) | NULLABLE | Backup integrity hash (FR-038) |
| started_at | TIMESTAMP | NULLABLE | Start time |
| completed_at | TIMESTAMP | NULLABLE | Completion time |
| error_message | TEXT | NULLABLE | Error details if failed |
| created_by | UUID | FK(User), NULLABLE | Initiator |
| created_at | TIMESTAMP | NOT NULL | Creation timestamp |

---

### Plugin

Installed extension module. Maps to spec entity: **Plugin**.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PK | Unique identifier |
| name | VARCHAR(255) | UNIQUE, NOT NULL | Plugin identifier |
| version | VARCHAR(50) | NOT NULL | Installed version |
| display_name | VARCHAR(255) | NOT NULL | Human-readable name |
| description | TEXT | NULLABLE | Plugin description |
| author | VARCHAR(255) | NULLABLE | Plugin author |
| status | ENUM | NOT NULL | installed, enabled, disabled, error |
| plugin_type | ENUM | NOT NULL | webhook, validator, integration (FR-040) |
| package_path | VARCHAR(2048) | NOT NULL | Plugin package location |
| entry_point | VARCHAR(255) | NOT NULL | Main entry function |
| error_message | TEXT | NULLABLE | Error if status=error |
| installed_at | TIMESTAMP | NOT NULL | Installation timestamp |
| updated_at | TIMESTAMP | NOT NULL | Last modification |

---

### PluginConfig

Configuration for installed plugins.

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PK | Unique identifier |
| plugin_id | UUID | FK(Plugin), NOT NULL | Parent plugin |
| key | VARCHAR(255) | NOT NULL | Config key |
| value | TEXT | NOT NULL | Config value (may be encrypted) |
| is_secret | BOOLEAN | DEFAULT false | Encrypted value |
| created_at | TIMESTAMP | NOT NULL | Creation timestamp |
| updated_at | TIMESTAMP | NOT NULL | Last modification |

**Unique Constraint**: (plugin_id, key)

---

### DownloadStatistic

Artifact download tracking (FR-006).

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PK | Unique identifier |
| artifact_id | UUID | FK(Artifact), NOT NULL | Downloaded artifact |
| user_id | UUID | FK(User), NULLABLE | Downloader (null = anonymous) |
| ip_address | INET | NOT NULL | Client IP |
| user_agent | VARCHAR(512) | NULLABLE | Client user agent |
| downloaded_at | TIMESTAMP | NOT NULL | Download timestamp |

---

### AuditLog

Security audit trail (FR-029).

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| id | UUID | PK | Unique identifier |
| user_id | UUID | FK(User), NULLABLE | Actor (null = system) |
| action | VARCHAR(100) | NOT NULL | Action type |
| resource_type | VARCHAR(100) | NOT NULL | Entity type |
| resource_id | UUID | NULLABLE | Entity ID |
| details | JSONB | NULLABLE | Additional context |
| ip_address | INET | NULLABLE | Client IP |
| correlation_id | UUID | NOT NULL | Request correlation ID |
| created_at | TIMESTAMP | NOT NULL | Event timestamp |

**Action Examples**: `user.login`, `user.logout`, `artifact.upload`, `artifact.download`, `artifact.delete`, `repository.create`, `repository.delete`, `permission.grant`, `permission.revoke`

---

## State Machines

### Backup Status

```
pending → running → completed
              ↓
            failed
```

**Transitions**:
- `pending → running`: Backup job starts
- `running → completed`: Backup finishes successfully
- `running → failed`: Backup encounters error

### Edge Node Status

```
      ┌─────────────┐
      ▼             │
offline ←→ online ←→ syncing
```

**Transitions**:
- `offline → online`: Heartbeat received
- `online → offline`: Heartbeat timeout
- `online ←→ syncing`: Replication in progress

### Plugin Status

```
installed → enabled ←→ disabled
    │          │
    └──────────┼────→ error
               │         │
               └─────────┘
```

**Transitions**:
- `installed → enabled`: Plugin activated
- `enabled ←→ disabled`: Admin toggle
- `* → error`: Plugin failure (FR-041 - isolated from core)
- `error → enabled/disabled`: Error resolved

---

## Indexes

### Performance-Critical Indexes

```sql
-- Artifact lookup (SC-001: 5s for 100MB)
CREATE INDEX idx_artifacts_repo_path ON artifacts(repository_id, path);
CREATE INDEX idx_artifacts_repo_name_version ON artifacts(repository_id, name, version);
CREATE INDEX idx_artifacts_checksum ON artifacts(checksum_sha256);

-- Search (FR-005)
CREATE INDEX idx_artifacts_name_gin ON artifacts USING gin(name gin_trgm_ops);
CREATE INDEX idx_artifact_metadata_gin ON artifact_metadata USING gin(metadata);

-- User lookup
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_external_id ON users(auth_provider, external_id);

-- API tokens
CREATE INDEX idx_api_tokens_prefix ON api_tokens(token_prefix);
CREATE INDEX idx_api_tokens_user ON api_tokens(user_id);

-- Statistics (FR-006)
CREATE INDEX idx_download_stats_artifact ON download_statistics(artifact_id, downloaded_at);
CREATE INDEX idx_download_stats_user ON download_statistics(user_id, downloaded_at);

-- Audit (FR-029)
CREATE INDEX idx_audit_log_user ON audit_log(user_id, created_at);
CREATE INDEX idx_audit_log_resource ON audit_log(resource_type, resource_id, created_at);
CREATE INDEX idx_audit_log_correlation ON audit_log(correlation_id);
```

---

## Validation Rules

### Repository

- `key`: alphanumeric with hyphens, 3-255 chars, cannot start with `_` or `-`
- `format` must match `repo_type` constraints (virtual repos aggregate same format only)
- `upstream_url` required for `remote` type, forbidden for `local` type

### Artifact

- `path`: cannot contain `..` or start with `/`
- `version`: format-specific validation (semver for npm, Maven coordinates, etc.)
- `checksum_sha256`: valid 64-character hex string

### User

- `username`: alphanumeric with underscores, 3-255 chars
- `email`: valid email format (RFC 5322)
- `password`: minimum 12 characters if local auth

### ApiToken

- Token scopes must be valid permission types
- Expiration must be in the future if set
- Token prefix must be unique per user

---

## Edge Cases (from spec)

| Edge Case | Handling |
|-----------|----------|
| Storage capacity exhausted during upload | Check quota before upload; reject with 507 Insufficient Storage |
| Concurrent uploads of same artifact version | Database unique constraint; second upload fails with 409 Conflict |
| Stale cached artifacts on edge nodes | Checksum validation on read; invalidation via sync protocol |
| Plugin failures during artifact operations | Plugin execution isolated; core operation completes; error logged |
| Backup storage unavailable | Backup status → failed; error_message populated; retry on next schedule |
| Authentication provider outage | Fallback to cached auth decisions; grace period for session extension |
| Checksum mismatch during download | Reject download with 409; mark artifact for integrity check |
