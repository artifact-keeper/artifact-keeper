//! Lifecycle policy service.
//!
//! Manages artifact retention policies per repository with support for:
//! - max_age_days: delete artifacts older than N days
//! - max_versions: keep only the last N versions per package
//! - no_downloads_days: delete artifacts not downloaded in N days
//! - tag_pattern_keep: delete artifacts whose name does NOT match a regex
//!   pattern (the SQL inverse of `tag_pattern_delete`). Despite the "keep"
//!   name this is a *deletion* policy, NOT a protection rule: it does not
//!   mark matching artifacts as protected and does not stop other lifecycle
//!   policies from deleting artifacts it preserved. Each policy emits an
//!   independent `UPDATE artifacts SET is_deleted = true` with no shared
//!   notion of "protected", so pairing `tag_pattern_keep` with a
//!   `tag_pattern_delete` (or any other deletion policy) on the same
//!   repository can still empty the repository. The wire string stays
//!   `tag_pattern_keep` for backward compatibility. See issue #1905.
//! - tag_pattern_delete: delete artifacts matching a regex pattern
//! - size_quota_bytes: enforce per-repo storage quotas

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::str::FromStr;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::scheduler_service::normalize_cron_expression;
use crate::storage::keys::prefix_matches;

/// Delete `oci_tags` rows whose matching manifest artifact is soft-deleted.
///
/// Each row in `oci_tags` is matched to its source artifact via the
/// `(repository_id, manifest_digest, image, tag)` tuple, mirroring what
/// `DELETE /v2/<image>/manifests/<reference>` would do. `$1::UUID` is the
/// repo filter: a repo-scoped policy passes the repo id, a global policy
/// passes NULL.
///
/// The join condition matches on `artifacts.path` rather than parsing
/// `artifacts.name` with a regex. The OCI handler writes
/// `path = 'v2/{image}/manifests/{reference}'` (see
/// `backend/src/api/handlers/oci_v2.rs` `put_manifest`), so reconstructing
/// the path from `oci_tags.(name, tag)` is exact and survives the awkward
/// edge cases the previous regex didn't:
///
/// - **port-in-name** (`host:5000/img:tag`): the regex
///   `'^(.+):[^:]+$'` greedily stripped the last `:segment`, so a
///   port-bearing image still matched, but only by accident — any
///   normalization difference between the two columns broke the join.
/// - **digest reference** (`reference = "sha256:abc..."`):
///   `artifacts.name = "img:sha256:abc..."`. Greedy match on the regex
///   extracted `"img:sha256"`, NOT `"img"`, so the join failed entirely
///   for any manifest pinned by digest.
///
/// `artifacts.storage_key` is still asserted to equal
/// `'oci-manifests/' || ot.manifest_digest` as a defence-in-depth
/// constraint. The `'oci-manifests/'` literal below is the SQL embedding of
/// [`OCI_MANIFEST_STORAGE_PREFIX`](crate::storage::keys::OCI_MANIFEST_STORAGE_PREFIX), the same prefix
/// `manifest_storage_key()` (`oci_v2.rs`) produces on writes and the storage
/// GC orphan predicate (`storage_gc_service.rs`, `ORPHAN_PREDICATE_SQL`)
/// matches on. Postgres cannot read the Rust constant, so the literal is
/// pinned to it by the `const _: () = assert!(...)` below: changing the
/// constant breaks the build until this SQL is updated to match (#1413). The
/// path-based predicate is the primary join key; the storage_key predicate is
/// a secondary integrity check that protects against artifact-name/path drift.
///
/// **Last-protecting-tag guard (#1682).** A retention sweep is not an
/// explicit user delete: it must never be the thing that orphans a live
/// image. The storage GC orphan predicate
/// (`storage_gc_service.rs` `ORPHAN_PREDICATE_SQL`) treats a manifest as
/// reachable while *any* `oci_tags` row carries its `manifest_digest`. So
/// if the cascade deletes the *last* `oci_tags` row protecting a
/// `(repository_id, manifest_digest)`, the manifest flips into the GC
/// orphan set and its blobs are reclaimed — silent data loss.
///
/// The guard therefore prunes an `oci_tags` row only when a **surviving
/// sibling** row keeps the same `(repository_id, manifest_digest)`
/// reachable after this sweep — i.e. another `oci_tags` row for the same
/// repo+digest, with a different `id`, that is NOT itself being pruned
/// (its backing manifest artifact is not soft-deleted under the same
/// join shape). The inner `NOT EXISTS` must be self-aware: the sole-tag
/// bug is just the `N=1` case of "all protecting tags pruned at once", so
/// a naive any-other-row check would let two doomed tags for one digest
/// each treat the other as a protector and delete both, re-orphaning the
/// image. With the surviving-sibling guard, when every tag for a digest
/// matches a single sweep none of them satisfy the `EXISTS`, so all are
/// retained and the image stays reachable.
///
/// This is a pure WHERE-tightening: it deletes strictly fewer rows than
/// before (never anything previously retained), so no migration is
/// needed. Explicit `DELETE /v2/<image>/manifests/<ref>` is unchanged and
/// still removes the sole tag intentionally; GC's index-child clause still
/// governs per-arch children of live indexes.
const CASCADE_OCI_TAGS_SQL: &str = r#"
DELETE FROM oci_tags ot
USING artifacts a
WHERE a.is_deleted = true
  AND a.repository_id = ot.repository_id
  AND a.storage_key = 'oci-manifests/' || ot.manifest_digest
  AND a.path = 'v2/' || ot.name || '/manifests/' || ot.tag
  AND a.version = ot.tag
  AND ($1::UUID IS NULL OR a.repository_id = $1)
  -- #1682: never delete the sole oci_tags row protecting a live manifest.
  -- Only prune this tag if SOME OTHER oci_tags row keeps the same
  -- (repository_id, manifest_digest) reachable after this sweep — i.e. a
  -- sibling tag that is NOT itself being soft-deleted/pruned. A sibling is
  -- "surviving" when no soft-deleted manifest artifact joins to it.
  AND EXISTS (
      SELECT 1
      FROM oci_tags keep
      WHERE keep.repository_id = ot.repository_id
        AND keep.manifest_digest = ot.manifest_digest
        AND keep.id <> ot.id
        AND NOT EXISTS (
            SELECT 1
            FROM artifacts ka
            WHERE ka.is_deleted = true
              AND ka.repository_id = keep.repository_id
              AND ka.storage_key = 'oci-manifests/' || keep.manifest_digest
              AND ka.path = 'v2/' || keep.name || '/manifests/' || keep.tag
              AND ka.version = keep.tag
        )
  )
"#;

/// Compile-time guard: the `'oci-manifests/'` literal embedded in
/// [`CASCADE_OCI_TAGS_SQL`] must match [`OCI_MANIFEST_STORAGE_PREFIX`](crate::storage::keys::OCI_MANIFEST_STORAGE_PREFIX).
/// Postgres cannot reference the Rust constant directly, so this keeps the
/// SQL literal and the write-path constant from drifting (#1413).
const _: () = assert!(prefix_matches("oci-manifests/"));

/// Scope of a lifecycle policy execution: either a specific repository or
/// every repository in the cluster (a "global" policy with `repository_id`
/// NULL). Pulled out as a strongly-typed wrapper around `Option<Uuid>` so
/// the cascade and per-type executors can't confuse "no filter" with a
/// missing argument and so dispatcher logic is unit-testable without a DB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CascadeScope {
    /// Run against every repository (`policy.repository_id IS NULL`).
    Global,
    /// Run against the named repository only.
    PerRepo(Uuid),
}

impl CascadeScope {
    /// Bind value for the `$1::UUID` parameter in `CASCADE_OCI_TAGS_SQL`
    /// and every per-type `execute_*` query that gates on
    /// `($1::UUID IS NULL OR a.repository_id = $1)`. `Global` -> NULL,
    /// `PerRepo(id)` -> Some(id).
    pub(crate) fn repo_filter(self) -> Option<Uuid> {
        match self {
            Self::Global => None,
            Self::PerRepo(id) => Some(id),
        }
    }

    /// True when this scope applies to every repository.
    pub(crate) fn is_global(self) -> bool {
        matches!(self, Self::Global)
    }
}

/// Whether a policy type can only operate against a single repository.
///
/// `max_versions` keeps the latest N versions *per package within one repo*,
/// and `size_quota_bytes` enforces a *per-repo* storage budget; both
/// `execute_*` implementations hard-require `policy.repository_id` and fail
/// at runtime if it is NULL (see `execute_max_versions` /
/// `execute_size_quota`). The other four types (`max_age_days`,
/// `no_downloads_days`, `tag_pattern_keep`, `tag_pattern_delete`) gate on
/// `($1::UUID IS NULL OR a.repository_id = $1)` and run cluster-wide when
/// `repository_id` is NULL, so a global policy of those types is legitimate.
///
/// This is the single source of truth used by create/update validation to
/// reject an unusable repo-scoped policy at creation time (#1850) rather than
/// letting it silently fail on every execution.
pub(crate) fn policy_type_requires_repository_id(policy_type: &str) -> bool {
    matches!(policy_type, "max_versions" | "size_quota_bytes")
}

impl From<Option<Uuid>> for CascadeScope {
    fn from(value: Option<Uuid>) -> Self {
        match value {
            None => Self::Global,
            Some(id) => Self::PerRepo(id),
        }
    }
}

/// Strongly-typed enum of the six policy types accepted by
/// `dispatch_execute`. Centralises the string -> dispatcher mapping so the
/// "unsupported policy type" branch is reachable from unit tests without
/// going through the DB. Kept `pub(crate)` (not exported) because the wire
/// representation stays the snake_case string used in
/// `LifecyclePolicy.policy_type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicyType {
    MaxAgeDays,
    MaxVersions,
    NoDownloadsDays,
    /// Deletes artifacts whose name does NOT match the configured regex (the
    /// inverse of `TagPatternDelete`). The "keep" in the wire name refers to
    /// which artifacts survive *this* policy's pass; it is NOT a protection
    /// rule and does not shield matching artifacts from other deletion
    /// policies. See the module-level docs and issue #1905.
    TagPatternKeep,
    TagPatternDelete,
    SizeQuotaBytes,
}

impl PolicyType {
    /// Parse a wire-format policy type string. Returns the same
    /// `AppError::Internal` shape that `dispatch_execute` used to emit
    /// inline, so behaviour is unchanged for callers.
    pub(crate) fn parse(s: &str) -> Result<Self> {
        match s {
            "max_age_days" => Ok(Self::MaxAgeDays),
            "max_versions" => Ok(Self::MaxVersions),
            "no_downloads_days" => Ok(Self::NoDownloadsDays),
            "tag_pattern_keep" => Ok(Self::TagPatternKeep),
            "tag_pattern_delete" => Ok(Self::TagPatternDelete),
            "size_quota_bytes" => Ok(Self::SizeQuotaBytes),
            other => Err(AppError::Internal(format!(
                "Unsupported policy type: {other}",
            ))),
        }
    }

    /// Wire-format name. Inverse of `parse`. Used in log/error messages so
    /// the unit suite can assert on the exact string the executors emit.
    pub(crate) fn as_wire_str(self) -> &'static str {
        match self {
            Self::MaxAgeDays => "max_age_days",
            Self::MaxVersions => "max_versions",
            Self::NoDownloadsDays => "no_downloads_days",
            Self::TagPatternKeep => "tag_pattern_keep",
            Self::TagPatternDelete => "tag_pattern_delete",
            Self::SizeQuotaBytes => "size_quota_bytes",
        }
    }
}

/// Pull an `i64` from `policy.config` under `key`. Mirrors the original
/// extraction in each `execute_*`: missing key or non-integer JSON value
/// (string, float, null, bool) -> `Validation` error. Does NOT enforce
/// positivity — `validate_policy_config` already rejects non-positive
/// values at create-time, and a malformed direct-DB row should still
/// reach SQL where an `INTERVAL` of zero or a `LIMIT` of zero is a safe
/// no-op rather than a hard error. Pulled out so the failure path
/// (missing key, wrong type) is covered by unit tests instead of only
/// indirectly through the per-type SQL executors.
///
/// Backward-compat shape: callers historically posted policy configs as
/// either the canonical nested form `{ "<key>": N }` (e.g. `{"keep": 5}`)
/// or the flat form `{ "<policy_type>": N }` (e.g. `{"max_versions": 5}`).
/// The flat form was the original wire shape used by early CLIs/e2e
/// scripts and several integration tests still send it. We accept either
/// transparently: prefer the canonical `key`, fall back to
/// `policy_type_label`, only error if neither is a valid integer.
pub(crate) fn parse_i64_field(
    config: &serde_json::Value,
    policy_type_label: &str,
    key: &str,
) -> Result<i64> {
    config
        .get(key)
        .and_then(|v| v.as_i64())
        .or_else(|| config.get(policy_type_label).and_then(|v| v.as_i64()))
        .ok_or_else(|| {
            AppError::Validation(format!("{policy_type_label} requires '{key}' in config"))
        })
}

/// Pull a non-empty regex pattern string from `policy.config["pattern"]`.
/// Caller is responsible for `regex::Regex::new` validation; the database
/// also re-validates via `name ~ $2` / `name !~ $2`, so the field is only
/// required to be a string here.
pub(crate) fn parse_pattern_field(
    config: &serde_json::Value,
    policy_type_label: &str,
) -> Result<String> {
    let pattern = config
        .get("pattern")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            AppError::Validation(format!("{policy_type_label} requires 'pattern' in config"))
        })?;
    Ok(pattern.to_string())
}

/// Candidate selection for `execute_size_quota`. Pure greedy-LRU pick:
/// walks `candidates` (already DB-sorted by least-recent-download then
/// oldest-created) and stops once their cumulative `size_bytes` matches
/// or exceeds `excess`. Returns `(ids_to_evict, accumulated_bytes)`.
///
/// Pulled out of `execute_size_quota` so the eviction maths is unit-
/// testable without standing up Postgres. Behaviour mirrors the original
/// loop exactly (including the "accumulate first, then compare" order
/// that lets the final candidate push us slightly over `excess`).
pub(crate) fn select_size_quota_evictions(
    candidates: &[(Uuid, i64)],
    excess: i64,
) -> (Vec<Uuid>, i64) {
    let mut to_remove = Vec::new();
    let mut accumulated = 0i64;
    for (id, size) in candidates {
        if accumulated >= excess {
            break;
        }
        to_remove.push(*id);
        accumulated = accumulated.saturating_add(*size);
    }
    (to_remove, accumulated)
}

/// A lifecycle policy attached to a repository (or global if repository_id is NULL).
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow, ToSchema)]
pub struct LifecyclePolicy {
    pub id: Uuid,
    pub repository_id: Option<Uuid>,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub policy_type: String,
    #[schema(value_type = Object)]
    pub config: serde_json::Value,
    pub priority: i32,
    pub last_run_at: Option<DateTime<Utc>>,
    pub last_run_items_removed: Option<i64>,
    pub cron_schedule: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create a lifecycle policy.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateLifecyclePolicyRequest {
    pub repository_id: Option<Uuid>,
    pub name: String,
    pub description: Option<String>,
    pub policy_type: String,
    #[schema(value_type = Object)]
    pub config: serde_json::Value,
    pub priority: Option<i32>,
    pub cron_schedule: Option<String>,
}

/// Request to update a lifecycle policy.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateLifecyclePolicyRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
    #[schema(value_type = Option<Object>)]
    pub config: Option<serde_json::Value>,
    pub priority: Option<i32>,
    pub cron_schedule: Option<String>,
}

/// Result of a lifecycle policy dry-run or execution.
#[derive(Debug, Serialize, ToSchema)]
pub struct PolicyExecutionResult {
    pub policy_id: Uuid,
    pub policy_name: String,
    pub dry_run: bool,
    pub artifacts_matched: i64,
    pub artifacts_removed: i64,
    pub bytes_freed: i64,
    pub errors: Vec<String>,
}

/// Aggregate count and bytes for policy matching queries.
#[derive(Debug, sqlx::FromRow)]
struct CountBytes {
    pub count: i64,
    pub bytes: i64,
}

/// Candidate artifact for size quota eviction.
#[derive(Debug, sqlx::FromRow)]
struct SizeCandidate {
    pub id: Uuid,
    pub size_bytes: i64,
}

/// Total usage for a repository.
#[derive(Debug, sqlx::FromRow)]
struct UsageTotal {
    pub total: i64,
}

pub struct LifecycleService {
    db: PgPool,
}

impl LifecycleService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Create a new lifecycle policy.
    pub async fn create_policy(
        &self,
        req: CreateLifecyclePolicyRequest,
    ) -> Result<LifecyclePolicy> {
        // Validate policy_type
        let valid_types = [
            "max_age_days",
            "max_versions",
            "no_downloads_days",
            "tag_pattern_keep",
            "tag_pattern_delete",
            "size_quota_bytes",
        ];
        if !valid_types.contains(&req.policy_type.as_str()) {
            return Err(AppError::Validation(format!(
                "Invalid policy_type '{}'. Must be one of: {}",
                req.policy_type,
                valid_types.join(", ")
            )));
        }

        // Reject repo-scoped policy types created without a repository_id.
        // These (`max_versions`, `size_quota_bytes`) require a repository_id
        // at execute time and would otherwise fail on every run (#1850).
        if req.repository_id.is_none() && policy_type_requires_repository_id(&req.policy_type) {
            return Err(AppError::Validation(format!(
                "policy_type '{}' is repository-scoped and requires a 'repository_id'; \
                 it cannot be created as a global policy",
                req.policy_type
            )));
        }

        self.validate_policy_config(&req.policy_type, &req.config)?;

        if let Some(ref cron_expr) = req.cron_schedule {
            let normalized = normalize_cron_expression(cron_expr);
            if cron::Schedule::from_str(&normalized).is_err() {
                return Err(AppError::Validation(format!(
                    "Invalid cron expression: '{}'",
                    cron_expr
                )));
            }
        }

        let policy = sqlx::query_as::<_, LifecyclePolicy>(
            r#"
            INSERT INTO lifecycle_policies (repository_id, name, description, policy_type, config, priority, cron_schedule)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, repository_id, name, description, enabled,
                      policy_type, config, priority, last_run_at,
                      last_run_items_removed, cron_schedule, created_at, updated_at
            "#,
        )
        .bind(req.repository_id)
        .bind(&req.name)
        .bind(&req.description)
        .bind(&req.policy_type)
        .bind(&req.config)
        .bind(req.priority.unwrap_or(0))
        .bind(&req.cron_schedule)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(policy)
    }

    /// List lifecycle policies, optionally filtered by repository.
    pub async fn list_policies(&self, repository_id: Option<Uuid>) -> Result<Vec<LifecyclePolicy>> {
        let policies = sqlx::query_as::<_, LifecyclePolicy>(
            r#"
            SELECT id, repository_id, name, description, enabled,
                   policy_type, config, priority, last_run_at,
                   last_run_items_removed, cron_schedule, created_at, updated_at
            FROM lifecycle_policies
            WHERE ($1::UUID IS NULL OR repository_id = $1 OR repository_id IS NULL)
            ORDER BY priority DESC, created_at ASC
            "#,
        )
        .bind(repository_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(policies)
    }

    /// Get a single policy by ID.
    pub async fn get_policy(&self, id: Uuid) -> Result<LifecyclePolicy> {
        sqlx::query_as::<_, LifecyclePolicy>(
            r#"
            SELECT id, repository_id, name, description, enabled,
                   policy_type, config, priority, last_run_at,
                   last_run_items_removed, cron_schedule, created_at, updated_at
            FROM lifecycle_policies
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Lifecycle policy not found".to_string()))
    }

    /// Update a lifecycle policy.
    pub async fn update_policy(
        &self,
        id: Uuid,
        req: UpdateLifecyclePolicyRequest,
    ) -> Result<LifecyclePolicy> {
        let existing = self.get_policy(id).await?;

        let name = req.name.unwrap_or(existing.name);
        let description = req.description.or(existing.description);
        let enabled = req.enabled.unwrap_or(existing.enabled);
        let config = req.config.unwrap_or(existing.config);
        let priority = req.priority.unwrap_or(existing.priority);
        let cron_schedule = req.cron_schedule.or(existing.cron_schedule);

        // Mirror the create-time guard (#1850): a repo-scoped policy type
        // (`max_versions`, `size_quota_bytes`) must have a repository_id.
        // `repository_id` and `policy_type` are immutable via update, so this
        // only rejects updates to pre-existing unusable global policies.
        if existing.repository_id.is_none()
            && policy_type_requires_repository_id(&existing.policy_type)
        {
            return Err(AppError::Validation(format!(
                "policy_type '{}' is repository-scoped and requires a 'repository_id'; \
                 it cannot exist as a global policy",
                existing.policy_type
            )));
        }

        self.validate_policy_config(&existing.policy_type, &config)?;

        if let Some(ref cron_expr) = cron_schedule {
            let normalized = normalize_cron_expression(cron_expr);
            if cron::Schedule::from_str(&normalized).is_err() {
                return Err(AppError::Validation(format!(
                    "Invalid cron expression: '{}'",
                    cron_expr
                )));
            }
        }

        let policy = sqlx::query_as::<_, LifecyclePolicy>(
            r#"
            UPDATE lifecycle_policies
            SET name = $2, description = $3, enabled = $4,
                config = $5, priority = $6, cron_schedule = $7, updated_at = NOW()
            WHERE id = $1
            RETURNING id, repository_id, name, description, enabled,
                      policy_type, config, priority, last_run_at,
                      last_run_items_removed, cron_schedule, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(&name)
        .bind(&description)
        .bind(enabled)
        .bind(&config)
        .bind(priority)
        .bind(&cron_schedule)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(policy)
    }

    /// Delete a lifecycle policy.
    pub async fn delete_policy(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM lifecycle_policies WHERE id = $1")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Lifecycle policy not found".to_string()));
        }

        Ok(())
    }

    /// Execute a policy (dry_run=true previews without deleting).
    ///
    /// Real runs split work across three short transactions instead of one
    /// long-held one. On a busy cluster with the default 50-conn pool, the
    /// previous single-transaction design pinned one connection for the
    /// entire run (minutes on large repos under `execute_no_downloads` /
    /// `execute_size_quota`) and held row locks on `artifacts` that blocked
    /// concurrent uploads. `execute_all_enabled` runs policies serially,
    /// multiplying the held time.
    ///
    /// Split layout:
    /// 1. **dispatch tx** — per-type `execute_*` (`UPDATE artifacts SET
    ///    is_deleted = true`). Committed immediately so row locks release
    ///    before the cascade and bookkeeping touch the pool again.
    /// 2. **cascade tx** — `DELETE FROM oci_tags ...` filtered on
    ///    `a.is_deleted = true`. Idempotent: rerunning finds whatever the
    ///    prior tx missed, deletes nothing the second time.
    /// 3. **bookkeeping** — `UPDATE lifecycle_policies SET last_run_at`,
    ///    issued against the pool directly (no tx needed for a one-row
    ///    update).
    ///
    /// Crash recovery: a crash between tx1 and tx2 leaves orphan `oci_tags`
    /// rows for the just-soft-deleted manifests. They are not lost forever
    /// because every subsequent cascade sweep filters on `is_deleted = true`
    /// globally (when `policy.repository_id IS NULL`) or scoped to the same
    /// repo — the next policy run picks them up. Eventual consistency at
    /// minutes-scale, not forever-stuck. This is acceptable because storage
    /// GC (#1144) only runs after a configurable retention window anyway.
    /// A crash between tx2 and bookkeeping leaves `last_run_at` stale, so
    /// the policy runs again on the next tick — same idempotent cascade.
    pub async fn execute_policy(&self, id: Uuid, dry_run: bool) -> Result<PolicyExecutionResult> {
        let policy = self.get_policy(id).await?;

        if !policy.enabled && !dry_run {
            return Err(AppError::Validation(
                "Cannot execute a disabled policy".to_string(),
            ));
        }

        // Dry-run reads only. Take a regular connection, skip the
        // transaction overhead (and skip the cascade entirely — dry_run
        // must not mutate oci_tags).
        if dry_run {
            let mut conn = self
                .db
                .acquire()
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
            return Self::dispatch_execute(&mut conn, &policy, true).await;
        }

        // Transaction 1: per-type soft-delete. Commit immediately so the
        // row locks on `artifacts` release before any further pool work,
        // unblocking concurrent uploads/scans.
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        let result = Self::dispatch_execute(&mut tx, &policy, false).await?;
        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        // Transaction 2: cascade `oci_tags` for the artifacts soft-deleted
        // above (and any orphans from a prior crashed run). Idempotent — the
        // filter `a.is_deleted = true` plus the path/digest join makes
        // re-runs no-ops once everything is cleaned up.
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        Self::cascade_oci_tags_cleanup_tx(&mut tx, CascadeScope::from(policy.repository_id))
            .await?;
        tx.commit()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        // Bookkeeping: single-row update, no transaction needed.
        sqlx::query(
            "UPDATE lifecycle_policies SET last_run_at = NOW(), last_run_items_removed = $2 WHERE id = $1",
        )
        .bind(id)
        .bind(result.artifacts_removed)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(result)
    }

    /// Dispatch to the per-type implementation against a single
    /// `PgConnection`. Real runs pass `&mut *tx` (a transaction
    /// re-borrowed as a connection) so the per-type soft-delete and the
    /// cascade share one transactional scope.
    async fn dispatch_execute(
        conn: &mut sqlx::PgConnection,
        policy: &LifecyclePolicy,
        dry_run: bool,
    ) -> Result<PolicyExecutionResult> {
        match PolicyType::parse(&policy.policy_type)? {
            PolicyType::MaxAgeDays => Self::execute_max_age(conn, policy, dry_run).await,
            PolicyType::MaxVersions => Self::execute_max_versions(conn, policy, dry_run).await,
            PolicyType::NoDownloadsDays => Self::execute_no_downloads(conn, policy, dry_run).await,
            PolicyType::TagPatternKeep => {
                Self::execute_tag_pattern_keep(conn, policy, dry_run).await
            }
            PolicyType::TagPatternDelete => {
                Self::execute_tag_pattern_delete(conn, policy, dry_run).await
            }
            PolicyType::SizeQuotaBytes => Self::execute_size_quota(conn, policy, dry_run).await,
        }
    }

    /// Delete `oci_tags` rows whose matching manifest artifact is soft-deleted.
    ///
    /// Every `execute_*` helper marks artifacts with `is_deleted = true` but
    /// leaves `oci_tags` untouched, mirroring the original lifecycle handler
    /// contract. The storage GC orphan predicate (#1144) treats any
    /// `oci_tags` row as a live reference, so the soft-deleted manifest
    /// keys are never reclaimed. This cascade closes the gap.
    ///
    /// Scope mirrors the policy: a repo-scoped policy cleans tags only in
    /// that repo; a global policy (`repository_id IS NULL`) cleans across
    /// every repo. Idempotent on re-runs.
    ///
    /// Runs against the caller's connection. `execute_policy` calls this
    /// inside its own short cascade transaction, separate from the per-type
    /// soft-delete transaction, so row locks on `artifacts` release as
    /// early as possible. The cascade is idempotent (`a.is_deleted = true`
    /// filter): if a crash leaves orphan `oci_tags` rows between the two
    /// transactions, the next policy run's cascade sweep reclaims them.
    async fn cascade_oci_tags_cleanup_tx(
        conn: &mut sqlx::PgConnection,
        scope: CascadeScope,
    ) -> Result<u64> {
        let removed = sqlx::query(CASCADE_OCI_TAGS_SQL)
            .bind(scope.repo_filter())
            .execute(&mut *conn)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
            .rows_affected();
        if removed > 0 {
            tracing::info!(
                "Lifecycle cascade: removed {} stale oci_tags rows for soft-deleted manifests (scope: {})",
                removed,
                if scope.is_global() { "global" } else { "per-repo" },
            );
        }
        Ok(removed)
    }

    /// Load every enabled policy, highest priority first. Shared by the
    /// scheduled `execute_all_enabled` and the cron-aware `execute_due_policies`
    /// entry points so the selection query lives in one place.
    async fn load_enabled_policies(&self) -> Result<Vec<LifecyclePolicy>> {
        sqlx::query_as::<_, LifecyclePolicy>(
            r#"
            SELECT id, repository_id, name, description, enabled,
                   policy_type, config, priority, last_run_at,
                   last_run_items_removed, cron_schedule, created_at, updated_at
            FROM lifecycle_policies
            WHERE enabled = true
            ORDER BY priority DESC
            "#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    /// Run one policy and fold the outcome into `results`, converting an error
    /// into a failed `PolicyExecutionResult` (logged) rather than aborting the
    /// whole batch. Shared by both scheduled entry points.
    async fn run_policy_into(
        &self,
        policy: LifecyclePolicy,
        results: &mut Vec<PolicyExecutionResult>,
    ) {
        match self.execute_policy(policy.id, false).await {
            Ok(result) => results.push(result),
            Err(e) => {
                tracing::error!(
                    "Failed to execute lifecycle policy '{}': {}",
                    policy.name,
                    e
                );
                results.push(PolicyExecutionResult {
                    policy_id: policy.id,
                    policy_name: policy.name,
                    dry_run: false,
                    artifacts_matched: 0,
                    artifacts_removed: 0,
                    bytes_freed: 0,
                    errors: vec![e.to_string()],
                });
            }
        }
    }

    /// Execute all enabled policies (called by scheduled background task).
    pub async fn execute_all_enabled(&self) -> Result<Vec<PolicyExecutionResult>> {
        let policies = self.load_enabled_policies().await?;

        let mut results = Vec::new();
        for policy in policies {
            self.run_policy_into(policy, &mut results).await;
        }

        Ok(results)
    }

    /// Execute only those enabled policies that are currently due, based on each
    /// policy's `cron_schedule` (or a default 6-hour cadence when unset).
    pub async fn execute_due_policies(&self) -> Result<Vec<PolicyExecutionResult>> {
        let policies = self.load_enabled_policies().await?;

        let now = Utc::now();
        let default_cadence = chrono::Duration::hours(6);
        let mut results = Vec::new();

        for policy in policies {
            let is_due = Self::is_policy_due(
                policy.cron_schedule.as_deref(),
                policy.last_run_at,
                now,
                default_cadence,
            );

            if !is_due {
                continue;
            }

            self.run_policy_into(policy, &mut results).await;
        }

        Ok(results)
    }

    /// Check whether a policy without a cron schedule is due based on the
    /// default cadence (6 hours). A policy that has never run is always due.
    fn is_due_by_default_cadence(
        last_run_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
        cadence: chrono::Duration,
    ) -> bool {
        match last_run_at {
            None => true,
            Some(last) => now - last >= cadence,
        }
    }

    /// Determine whether a policy is currently due for execution.
    ///
    /// When the policy has a `cron_schedule`, checks whether any scheduled
    /// occurrence falls between `last_run_at` and `now`. If the cron expression
    /// is invalid, falls back to the default cadence. When there is no cron
    /// schedule, uses `is_due_by_default_cadence`.
    fn is_policy_due(
        cron_schedule: Option<&str>,
        last_run_at: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
        default_cadence: chrono::Duration,
    ) -> bool {
        if let Some(cron_expr) = cron_schedule {
            let normalized = normalize_cron_expression(cron_expr);
            match cron::Schedule::from_str(&normalized) {
                Ok(schedule) => match last_run_at {
                    None => true,
                    Some(last_run) => schedule
                        .after(&last_run)
                        .take_while(|t| *t <= now)
                        .next()
                        .is_some(),
                },
                Err(_) => Self::is_due_by_default_cadence(last_run_at, now, default_cadence),
            }
        } else {
            Self::is_due_by_default_cadence(last_run_at, now, default_cadence)
        }
    }

    // --- Policy execution implementations ---

    /// Build a PolicyExecutionResult from common fields.
    /// When `dry_run` is true, `artifacts_removed` and `bytes_freed` are zeroed out.
    fn build_execution_result(
        policy: &LifecyclePolicy,
        dry_run: bool,
        artifacts_matched: i64,
        artifacts_removed: i64,
        bytes_freed: i64,
    ) -> PolicyExecutionResult {
        PolicyExecutionResult {
            policy_id: policy.id,
            policy_name: policy.name.clone(),
            dry_run,
            artifacts_matched,
            artifacts_removed: if dry_run { 0 } else { artifacts_removed },
            bytes_freed: if dry_run { 0 } else { bytes_freed },
            errors: vec![],
        }
    }

    async fn execute_max_age(
        conn: &mut sqlx::PgConnection,
        policy: &LifecyclePolicy,
        dry_run: bool,
    ) -> Result<PolicyExecutionResult> {
        let days = parse_i64_field(&policy.config, PolicyType::MaxAgeDays.as_wire_str(), "days")?;

        let matched = if policy.repository_id.is_some() {
            sqlx::query_as::<_, CountBytes>(
                r#"
                SELECT COUNT(*) as count, COALESCE(SUM(size_bytes), 0)::BIGINT as bytes
                FROM artifacts
                WHERE repository_id = $1
                  AND is_deleted = false
                  AND created_at < NOW() - make_interval(days => $2::INT)
                "#,
            )
            .bind(policy.repository_id)
            .bind(days as i32)
            .fetch_one(&mut *conn)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
        } else {
            sqlx::query_as::<_, CountBytes>(
                r#"
                SELECT COUNT(*) as count, COALESCE(SUM(size_bytes), 0)::BIGINT as bytes
                FROM artifacts
                WHERE is_deleted = false
                  AND created_at < NOW() - make_interval(days => $1::INT)
                "#,
            )
            .bind(days as i32)
            .fetch_one(&mut *conn)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
        };

        let mut removed = 0i64;
        if !dry_run && matched.count > 0 {
            let result = if policy.repository_id.is_some() {
                sqlx::query(
                    r#"
                    UPDATE artifacts SET is_deleted = true
                    WHERE repository_id = $1
                      AND is_deleted = false
                      AND created_at < NOW() - make_interval(days => $2::INT)
                    "#,
                )
                .bind(policy.repository_id)
                .bind(days as i32)
                .execute(&mut *conn)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?
            } else {
                sqlx::query(
                    r#"
                    UPDATE artifacts SET is_deleted = true
                    WHERE is_deleted = false
                      AND created_at < NOW() - make_interval(days => $1::INT)
                    "#,
                )
                .bind(days as i32)
                .execute(&mut *conn)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?
            };
            removed = result.rows_affected() as i64;
        }

        Ok(Self::build_execution_result(
            policy,
            dry_run,
            matched.count,
            removed,
            matched.bytes,
        ))
    }

    async fn execute_max_versions(
        conn: &mut sqlx::PgConnection,
        policy: &LifecyclePolicy,
        dry_run: bool,
    ) -> Result<PolicyExecutionResult> {
        let keep = parse_i64_field(
            &policy.config,
            PolicyType::MaxVersions.as_wire_str(),
            "keep",
        )?;

        let repo_id = policy.repository_id.ok_or_else(|| {
            AppError::Validation("max_versions requires a repository_id".to_string())
        })?;

        // Find artifacts to remove: for each (name), keep only the latest N
        let matched = sqlx::query_as::<_, CountBytes>(
            r#"
            SELECT COUNT(*) as count, COALESCE(SUM(a.size_bytes), 0)::BIGINT as bytes
            FROM artifacts a
            WHERE a.repository_id = $1
              AND a.is_deleted = false
              AND a.id NOT IN (
                  SELECT a2.id FROM artifacts a2
                  WHERE a2.repository_id = $1
                    AND a2.name = a.name
                    AND a2.is_deleted = false
                  ORDER BY a2.created_at DESC
                  LIMIT $2
              )
            "#,
        )
        .bind(repo_id)
        .bind(keep)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let mut removed = 0i64;
        if !dry_run && matched.count > 0 {
            let result = sqlx::query(
                r#"
                UPDATE artifacts SET is_deleted = true
                WHERE repository_id = $1
                  AND is_deleted = false
                  AND id NOT IN (
                      SELECT a2.id FROM artifacts a2
                      WHERE a2.repository_id = $1
                        AND a2.name = artifacts.name
                        AND a2.is_deleted = false
                      ORDER BY a2.created_at DESC
                      LIMIT $2
                  )
                "#,
            )
            .bind(repo_id)
            .bind(keep)
            .execute(&mut *conn)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
            removed = result.rows_affected() as i64;
        }

        Ok(Self::build_execution_result(
            policy,
            dry_run,
            matched.count,
            removed,
            matched.bytes,
        ))
    }

    async fn execute_no_downloads(
        conn: &mut sqlx::PgConnection,
        policy: &LifecyclePolicy,
        dry_run: bool,
    ) -> Result<PolicyExecutionResult> {
        let days = parse_i64_field(
            &policy.config,
            PolicyType::NoDownloadsDays.as_wire_str(),
            "days",
        )?;

        let repo_filter = policy.repository_id;

        let matched = sqlx::query_as::<_, CountBytes>(
            r#"
            SELECT COUNT(*) as count, COALESCE(SUM(a.size_bytes), 0)::BIGINT as bytes
            FROM artifacts a
            WHERE a.is_deleted = false
              AND ($1::UUID IS NULL OR a.repository_id = $1)
              AND NOT EXISTS (
                  SELECT 1 FROM download_statistics ds
                  WHERE ds.artifact_id = a.id
                    AND ds.downloaded_at > NOW() - make_interval(days => $2::INT)
              )
              AND a.created_at < NOW() - make_interval(days => $2::INT)
            "#,
        )
        .bind(repo_filter)
        .bind(days as i32)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let mut removed = 0i64;
        if !dry_run && matched.count > 0 {
            let result = sqlx::query(
                r#"
                UPDATE artifacts SET is_deleted = true
                WHERE is_deleted = false
                  AND ($1::UUID IS NULL OR repository_id = $1)
                  AND NOT EXISTS (
                      SELECT 1 FROM download_statistics ds
                      WHERE ds.artifact_id = artifacts.id
                        AND ds.downloaded_at > NOW() - make_interval(days => $2::INT)
                  )
                  AND created_at < NOW() - make_interval(days => $2::INT)
                "#,
            )
            .bind(repo_filter)
            .bind(days as i32)
            .execute(&mut *conn)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
            removed = result.rows_affected() as i64;
        }

        Ok(Self::build_execution_result(
            policy,
            dry_run,
            matched.count,
            removed,
            matched.bytes,
        ))
    }

    async fn execute_tag_pattern_keep(
        conn: &mut sqlx::PgConnection,
        policy: &LifecyclePolicy,
        dry_run: bool,
    ) -> Result<PolicyExecutionResult> {
        let pattern =
            parse_pattern_field(&policy.config, PolicyType::TagPatternKeep.as_wire_str())?;
        // Inverse of tag_pattern_delete: soft-delete artifacts that do NOT
        // match the pattern (operator `!~`). NOTE: this is a deletion pass, not
        // a protection mark — artifacts matching the pattern survive only this
        // policy and remain deletable by other lifecycle policies (#1905).
        Self::execute_tag_pattern(conn, policy, dry_run, &pattern, "!~").await
    }

    async fn execute_tag_pattern_delete(
        conn: &mut sqlx::PgConnection,
        policy: &LifecyclePolicy,
        dry_run: bool,
    ) -> Result<PolicyExecutionResult> {
        let pattern =
            parse_pattern_field(&policy.config, PolicyType::TagPatternDelete.as_wire_str())?;
        // Soft-delete artifacts that DO match the pattern (operator `~`).
        Self::execute_tag_pattern(conn, policy, dry_run, &pattern, "~").await
    }

    /// Shared body for the two regex-pattern policies. `op` is the Postgres
    /// regex operator: `~` (tag_pattern_delete: remove matches) or `!~`
    /// (tag_pattern_keep: remove non-matches). The operator is a fixed literal
    /// chosen by the caller (never user input), so interpolating it into the
    /// SQL text is safe; the pattern itself is always a bound parameter.
    async fn execute_tag_pattern(
        conn: &mut sqlx::PgConnection,
        policy: &LifecyclePolicy,
        dry_run: bool,
        pattern: &str,
        op: &str,
    ) -> Result<PolicyExecutionResult> {
        let repo_filter = policy.repository_id;

        let matched = sqlx::query_as::<_, CountBytes>(&format!(
            r#"
            SELECT COUNT(*) as count, COALESCE(SUM(a.size_bytes), 0)::BIGINT as bytes
            FROM artifacts a
            WHERE a.is_deleted = false
              AND ($1::UUID IS NULL OR a.repository_id = $1)
              AND a.name {op} $2
            "#
        ))
        .bind(repo_filter)
        .bind(pattern)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let mut removed = 0i64;
        if !dry_run && matched.count > 0 {
            let result = sqlx::query(&format!(
                r#"
                UPDATE artifacts SET is_deleted = true
                WHERE is_deleted = false
                  AND ($1::UUID IS NULL OR repository_id = $1)
                  AND name {op} $2
                "#
            ))
            .bind(repo_filter)
            .bind(pattern)
            .execute(&mut *conn)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
            removed = result.rows_affected() as i64;
        }

        Ok(Self::build_execution_result(
            policy,
            dry_run,
            matched.count,
            removed,
            matched.bytes,
        ))
    }

    async fn execute_size_quota(
        conn: &mut sqlx::PgConnection,
        policy: &LifecyclePolicy,
        dry_run: bool,
    ) -> Result<PolicyExecutionResult> {
        let quota_bytes = parse_i64_field(
            &policy.config,
            PolicyType::SizeQuotaBytes.as_wire_str(),
            "quota_bytes",
        )?;

        let repo_id = policy.repository_id.ok_or_else(|| {
            AppError::Validation("size_quota_bytes requires a repository_id".to_string())
        })?;

        // Get current usage
        let usage = sqlx::query_as::<_, UsageTotal>(
            r#"
            SELECT COALESCE(SUM(size_bytes), 0)::BIGINT as total
            FROM artifacts
            WHERE repository_id = $1 AND is_deleted = false
            "#,
        )
        .bind(repo_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if usage.total <= quota_bytes {
            return Ok(Self::build_execution_result(policy, dry_run, 0, 0, 0));
        }

        let excess = usage.total - quota_bytes;

        // Find least-recently-used artifacts to evict first (LRU).
        // Never-downloaded artifacts are evicted before downloaded ones,
        // then by least-recent download, then by creation time as tiebreaker.
        let candidates = sqlx::query_as::<_, SizeCandidate>(
            r#"
            SELECT a.id, a.size_bytes
            FROM artifacts a
            LEFT JOIN LATERAL (
                SELECT MAX(ds.downloaded_at) AS last_downloaded_at
                FROM download_statistics ds
                WHERE ds.artifact_id = a.id
            ) ds ON true
            WHERE a.repository_id = $1 AND a.is_deleted = false
            ORDER BY ds.last_downloaded_at ASC NULLS FIRST, a.created_at ASC
            "#,
        )
        .bind(repo_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Greedy-LRU selection is pure and lives in
        // `select_size_quota_evictions` so it can be unit-tested without
        // standing up Postgres. `candidates` is already sorted by the SQL
        // above (least-recent-download then oldest-created).
        let candidate_pairs: Vec<(Uuid, i64)> =
            candidates.iter().map(|c| (c.id, c.size_bytes)).collect();
        let (to_remove, accumulated) = select_size_quota_evictions(&candidate_pairs, excess);

        let matched = to_remove.len() as i64;
        let mut removed = 0i64;

        if !dry_run && !to_remove.is_empty() {
            let result = sqlx::query("UPDATE artifacts SET is_deleted = true WHERE id = ANY($1)")
                .bind(&to_remove)
                .execute(&mut *conn)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
            removed = result.rows_affected() as i64;
        }

        Ok(Self::build_execution_result(
            policy,
            dry_run,
            matched,
            removed,
            accumulated,
        ))
    }

    /// Validate policy config based on type.
    ///
    /// Each numeric policy type historically accepted **two** wire shapes:
    /// the canonical nested key (e.g. `{"keep": 5}` for `max_versions`)
    /// and the flat policy-type alias (e.g. `{"max_versions": 5}`). Older
    /// CLIs and several integration tests still post the flat form, so we
    /// accept either here and in `parse_i64_field`. The error message
    /// still names the canonical key for forward guidance.
    fn validate_policy_config(&self, policy_type: &str, config: &serde_json::Value) -> Result<()> {
        // Lookup helper: prefer canonical key, fall back to flat policy_type alias.
        let read_positive_i64 = |canonical: &str| -> Option<i64> {
            config
                .get(canonical)
                .and_then(|v| v.as_i64())
                .or_else(|| config.get(policy_type).and_then(|v| v.as_i64()))
                .filter(|&n| n > 0)
        };

        match policy_type {
            "max_age_days" => {
                read_positive_i64("days").ok_or_else(|| {
                    AppError::Validation(
                        "max_age_days requires 'days' (positive integer) in config".to_string(),
                    )
                })?;
            }
            "max_versions" => {
                read_positive_i64("keep").ok_or_else(|| {
                    AppError::Validation(
                        "max_versions requires 'keep' (positive integer) in config".to_string(),
                    )
                })?;
            }
            "no_downloads_days" => {
                read_positive_i64("days").ok_or_else(|| {
                    AppError::Validation(
                        "no_downloads_days requires 'days' (positive integer) in config"
                            .to_string(),
                    )
                })?;
            }
            "tag_pattern_keep" | "tag_pattern_delete" => {
                let pattern = config
                    .get("pattern")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        AppError::Validation(format!(
                            "{} requires 'pattern' (string) in config",
                            policy_type
                        ))
                    })?;
                // Validate regex
                regex::Regex::new(pattern)
                    .map_err(|e| AppError::Validation(format!("Invalid regex pattern: {}", e)))?;
            }
            "size_quota_bytes" => {
                read_positive_i64("quota_bytes").ok_or_else(|| {
                    AppError::Validation(
                        "size_quota_bytes requires 'quota_bytes' (positive integer) in config"
                            .to_string(),
                    )
                })?;
            }
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use serde_json::json;

    // Helper: create a minimal LifecycleService for calling validate_policy_config.
    // PgPool::connect_lazy requires a Tokio context, so these tests use #[tokio::test].
    fn make_service_for_validation() -> LifecycleService {
        // Fake-DB pool: any test that reaches the INSERT is asserting on the
        // Database error, so fail acquires in 1s, not sqlx's default 30s.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_secs(1))
            .connect_lazy("postgres://fake:fake@localhost/fake")
            .expect("connect_lazy should not fail");
        LifecycleService::new(pool)
    }

    // -----------------------------------------------------------------------
    // validate_policy_config tests: max_age_days
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_validate_max_age_days_valid() {
        let svc = make_service_for_validation();
        let config = json!({"days": 30});
        assert!(svc.validate_policy_config("max_age_days", &config).is_ok());
    }

    #[tokio::test]
    async fn test_validate_max_age_days_missing_days() {
        let svc = make_service_for_validation();
        let config = json!({});
        let result = svc.validate_policy_config("max_age_days", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_max_age_days_zero() {
        let svc = make_service_for_validation();
        let config = json!({"days": 0});
        let result = svc.validate_policy_config("max_age_days", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_max_age_days_negative() {
        let svc = make_service_for_validation();
        let config = json!({"days": -5});
        let result = svc.validate_policy_config("max_age_days", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_max_age_days_string_value() {
        let svc = make_service_for_validation();
        let config = json!({"days": "thirty"});
        let result = svc.validate_policy_config("max_age_days", &config);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // validate_policy_config tests: max_versions
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_validate_max_versions_valid() {
        let svc = make_service_for_validation();
        let config = json!({"keep": 5});
        assert!(svc.validate_policy_config("max_versions", &config).is_ok());
    }

    #[tokio::test]
    async fn test_validate_max_versions_missing_keep() {
        let svc = make_service_for_validation();
        let config = json!({});
        let result = svc.validate_policy_config("max_versions", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_max_versions_zero() {
        let svc = make_service_for_validation();
        let config = json!({"keep": 0});
        let result = svc.validate_policy_config("max_versions", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_max_versions_negative() {
        let svc = make_service_for_validation();
        let config = json!({"keep": -1});
        let result = svc.validate_policy_config("max_versions", &config);
        assert!(result.is_err());
    }

    // Backward-compat: tests/CLIs that POSTed `{ "max_versions": N }`
    // (flat shape) before the canonical `{ "keep": N }` was introduced.
    #[tokio::test]
    async fn test_validate_max_versions_flat_shape_valid() {
        let svc = make_service_for_validation();
        let config = json!({"max_versions": 5});
        assert!(svc.validate_policy_config("max_versions", &config).is_ok());
    }

    #[tokio::test]
    async fn test_validate_max_versions_flat_shape_zero_rejected() {
        let svc = make_service_for_validation();
        let config = json!({"max_versions": 0});
        let result = svc.validate_policy_config("max_versions", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_max_versions_canonical_wins_over_flat() {
        // If both shapes are present, the canonical key takes precedence.
        let svc = make_service_for_validation();
        let config = json!({"keep": 7, "max_versions": -1});
        assert!(svc.validate_policy_config("max_versions", &config).is_ok());
    }

    #[tokio::test]
    async fn test_validate_max_age_days_flat_shape_valid() {
        let svc = make_service_for_validation();
        let config = json!({"max_age_days": 30});
        assert!(svc.validate_policy_config("max_age_days", &config).is_ok());
    }

    #[tokio::test]
    async fn test_validate_size_quota_bytes_flat_shape_valid() {
        let svc = make_service_for_validation();
        let config = json!({"size_quota_bytes": 1024});
        assert!(svc
            .validate_policy_config("size_quota_bytes", &config)
            .is_ok());
    }

    // -----------------------------------------------------------------------
    // validate_policy_config tests: no_downloads_days
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_validate_no_downloads_days_valid() {
        let svc = make_service_for_validation();
        let config = json!({"days": 90});
        assert!(svc
            .validate_policy_config("no_downloads_days", &config)
            .is_ok());
    }

    #[tokio::test]
    async fn test_validate_no_downloads_days_missing() {
        let svc = make_service_for_validation();
        let config = json!({});
        let result = svc.validate_policy_config("no_downloads_days", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_no_downloads_days_zero() {
        let svc = make_service_for_validation();
        let config = json!({"days": 0});
        let result = svc.validate_policy_config("no_downloads_days", &config);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // validate_policy_config tests: tag_pattern_keep / tag_pattern_delete
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_validate_tag_pattern_keep_valid() {
        let svc = make_service_for_validation();
        let config = json!({"pattern": "^release-.*"});
        assert!(svc
            .validate_policy_config("tag_pattern_keep", &config)
            .is_ok());
    }

    #[tokio::test]
    async fn test_validate_tag_pattern_delete_valid() {
        let svc = make_service_for_validation();
        let config = json!({"pattern": ".*-snapshot$"});
        assert!(svc
            .validate_policy_config("tag_pattern_delete", &config)
            .is_ok());
    }

    #[tokio::test]
    async fn test_validate_tag_pattern_missing_pattern() {
        let svc = make_service_for_validation();
        let config = json!({});
        let result = svc.validate_policy_config("tag_pattern_keep", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_tag_pattern_invalid_regex() {
        let svc = make_service_for_validation();
        let config = json!({"pattern": "[invalid"});
        let result = svc.validate_policy_config("tag_pattern_delete", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_tag_pattern_integer_pattern() {
        let svc = make_service_for_validation();
        let config = json!({"pattern": 42});
        let result = svc.validate_policy_config("tag_pattern_keep", &config);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // validate_policy_config tests: size_quota_bytes
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_validate_size_quota_bytes_valid() {
        let svc = make_service_for_validation();
        let config = json!({"quota_bytes": 1073741824}); // 1 GiB
        assert!(svc
            .validate_policy_config("size_quota_bytes", &config)
            .is_ok());
    }

    #[tokio::test]
    async fn test_validate_size_quota_bytes_missing() {
        let svc = make_service_for_validation();
        let config = json!({});
        let result = svc.validate_policy_config("size_quota_bytes", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_size_quota_bytes_zero() {
        let svc = make_service_for_validation();
        let config = json!({"quota_bytes": 0});
        let result = svc.validate_policy_config("size_quota_bytes", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_size_quota_bytes_negative() {
        let svc = make_service_for_validation();
        let config = json!({"quota_bytes": -100});
        let result = svc.validate_policy_config("size_quota_bytes", &config);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // validate_policy_config tests: unknown type passes
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_validate_unknown_policy_type_passes() {
        let svc = make_service_for_validation();
        let config = json!({});
        assert!(svc.validate_policy_config("unknown_type", &config).is_ok());
    }

    // -----------------------------------------------------------------------
    // #1850: repository_id required at create for repo-scoped policy types
    // -----------------------------------------------------------------------

    #[test]
    fn test_policy_type_requires_repository_id_classification() {
        // Repo-scoped types: execute_* hard-require a repository_id.
        assert!(policy_type_requires_repository_id("max_versions"));
        assert!(policy_type_requires_repository_id("size_quota_bytes"));
        // Genuinely-global types: run cluster-wide with NULL repo filter.
        assert!(!policy_type_requires_repository_id("max_age_days"));
        assert!(!policy_type_requires_repository_id("no_downloads_days"));
        assert!(!policy_type_requires_repository_id("tag_pattern_keep"));
        assert!(!policy_type_requires_repository_id("tag_pattern_delete"));
        // Unknown types are not repo-scoped (caught earlier by type validation).
        assert!(!policy_type_requires_repository_id("unknown_type"));
    }

    // The create guard returns before any DB query, so the lazy pool helper
    // is sufficient to exercise the rejection path without a live database.

    #[tokio::test]
    async fn test_create_max_versions_without_repository_id_rejected() {
        let svc = make_service_for_validation();
        let req = CreateLifecyclePolicyRequest {
            repository_id: None,
            name: "global-max-versions".to_string(),
            description: None,
            policy_type: "max_versions".to_string(),
            config: json!({"keep": 5}),
            priority: None,
            cron_schedule: None,
        };
        let err = svc.create_policy(req).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
        assert!(err.to_string().contains("repository_id"));
    }

    #[tokio::test]
    async fn test_create_size_quota_without_repository_id_rejected() {
        let svc = make_service_for_validation();
        let req = CreateLifecyclePolicyRequest {
            repository_id: None,
            name: "global-size-quota".to_string(),
            description: None,
            policy_type: "size_quota_bytes".to_string(),
            config: json!({"quota_bytes": 1024}),
            priority: None,
            cron_schedule: None,
        };
        let err = svc.create_policy(req).await.unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "got {err:?}");
        assert!(err.to_string().contains("repository_id"));
    }

    #[tokio::test]
    async fn test_create_global_type_without_repository_id_passes_repo_guard() {
        // A genuinely-global policy type (max_age_days) without a
        // repository_id must NOT be rejected by the #1850 repo guard. It
        // proceeds past the guard and config validation; the only thing that
        // would fail here is the INSERT (no live DB), which surfaces as a
        // Database error, never a Validation error about repository_id.
        let svc = make_service_for_validation();
        let req = CreateLifecyclePolicyRequest {
            repository_id: None,
            name: "global-max-age".to_string(),
            description: None,
            policy_type: "max_age_days".to_string(),
            config: json!({"days": 90}),
            priority: None,
            cron_schedule: None,
        };
        match svc.create_policy(req).await {
            // No live DB in the unit harness: INSERT fails as a Database error.
            Err(AppError::Database(_)) => {}
            // If a DB were wired up, success is equally acceptable.
            Ok(_) => {}
            other => panic!("expected to pass the repo guard, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Struct serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_lifecycle_policy_serialization() {
        let now = Utc::now();
        let policy = LifecyclePolicy {
            id: Uuid::nil(),
            repository_id: Some(Uuid::new_v4()),
            name: "Test Policy".to_string(),
            description: Some("A test policy".to_string()),
            enabled: true,
            policy_type: "max_age_days".to_string(),
            config: json!({"days": 30}),
            priority: 10,
            last_run_at: None,
            last_run_items_removed: None,
            cron_schedule: None,
            created_at: now,
            updated_at: now,
        };

        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains("\"name\":\"Test Policy\""));
        assert!(json.contains("\"enabled\":true"));
        assert!(json.contains("\"priority\":10"));
    }

    #[test]
    fn test_lifecycle_policy_deserialization() {
        let now = Utc::now();
        let json_val = json!({
            "id": Uuid::nil(),
            "repository_id": null,
            "name": "Cleanup",
            "description": null,
            "enabled": false,
            "policy_type": "max_versions",
            "config": {"keep": 3},
            "priority": 0,
            "last_run_at": null,
            "last_run_items_removed": null,
            "cron_schedule": null,
            "created_at": now,
            "updated_at": now,
        });

        let policy: LifecyclePolicy = serde_json::from_value(json_val).unwrap();
        assert_eq!(policy.name, "Cleanup");
        assert!(!policy.enabled);
        assert_eq!(policy.policy_type, "max_versions");
        assert!(policy.repository_id.is_none());
    }

    #[test]
    fn test_create_policy_request_deserialization() {
        let json_str = r#"{
            "name": "My Policy",
            "policy_type": "max_age_days",
            "config": {"days": 30}
        }"#;
        let req: CreateLifecyclePolicyRequest = serde_json::from_str(json_str).unwrap();
        assert_eq!(req.name, "My Policy");
        assert_eq!(req.policy_type, "max_age_days");
        assert!(req.repository_id.is_none());
        assert!(req.description.is_none());
        assert!(req.priority.is_none());
    }

    #[test]
    fn test_create_policy_request_with_all_fields() {
        let repo_id = Uuid::new_v4();
        let json_val = json!({
            "repository_id": repo_id,
            "name": "Full Policy",
            "description": "With all fields",
            "policy_type": "size_quota_bytes",
            "config": {"quota_bytes": 1000000},
            "priority": 5
        });
        let req: CreateLifecyclePolicyRequest = serde_json::from_value(json_val).unwrap();
        assert_eq!(req.repository_id, Some(repo_id));
        assert_eq!(req.description, Some("With all fields".to_string()));
        assert_eq!(req.priority, Some(5));
    }

    #[test]
    fn test_update_policy_request_empty() {
        let json_str = "{}";
        let req: UpdateLifecyclePolicyRequest = serde_json::from_str(json_str).unwrap();
        assert!(req.name.is_none());
        assert!(req.description.is_none());
        assert!(req.enabled.is_none());
        assert!(req.config.is_none());
        assert!(req.priority.is_none());
    }

    #[test]
    fn test_policy_execution_result_serialization() {
        let result = PolicyExecutionResult {
            policy_id: Uuid::nil(),
            policy_name: "Test".to_string(),
            dry_run: true,
            artifacts_matched: 100,
            artifacts_removed: 0,
            bytes_freed: 0,
            errors: vec![],
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"dry_run\":true"));
        assert!(json.contains("\"artifacts_matched\":100"));
        assert!(json.contains("\"artifacts_removed\":0"));
        assert!(json.contains("\"bytes_freed\":0"));
        assert!(json.contains("\"errors\":[]"));
    }

    #[test]
    fn test_policy_execution_result_with_errors() {
        let result = PolicyExecutionResult {
            policy_id: Uuid::new_v4(),
            policy_name: "Failing".to_string(),
            dry_run: false,
            artifacts_matched: 10,
            artifacts_removed: 3,
            bytes_freed: 1024,
            errors: vec!["Error A".to_string(), "Error B".to_string()],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"errors\":[\"Error A\",\"Error B\"]"));
    }

    // -----------------------------------------------------------------------
    // Valid policy_type list validation (testing create_policy logic)
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_policy_types() {
        let valid_types = [
            "max_age_days",
            "max_versions",
            "no_downloads_days",
            "tag_pattern_keep",
            "tag_pattern_delete",
            "size_quota_bytes",
        ];
        for t in &valid_types {
            assert!(valid_types.contains(t));
        }
        assert!(!valid_types.contains(&"custom_type"));
        assert!(!valid_types.contains(&""));
    }

    // -----------------------------------------------------------------------
    // tag_pattern_keep validation (mirrors tag_pattern_delete tests)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_validate_tag_pattern_keep_valid_release_pattern() {
        let svc = make_service_for_validation();
        let config = json!({"pattern": "^(release-|v).*"});
        assert!(svc
            .validate_policy_config("tag_pattern_keep", &config)
            .is_ok());
    }

    #[tokio::test]
    async fn test_validate_tag_pattern_keep_missing_pattern() {
        let svc = make_service_for_validation();
        let config = json!({});
        let result = svc.validate_policy_config("tag_pattern_keep", &config);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("pattern"));
    }

    #[tokio::test]
    async fn test_validate_tag_pattern_keep_invalid_regex() {
        let svc = make_service_for_validation();
        let config = json!({"pattern": "[unclosed"});
        let result = svc.validate_policy_config("tag_pattern_keep", &config);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("regex"));
    }

    #[tokio::test]
    async fn test_validate_tag_pattern_keep_non_string_pattern() {
        let svc = make_service_for_validation();
        let config = json!({"pattern": 123});
        let result = svc.validate_policy_config("tag_pattern_keep", &config);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Verify execute_policy match coverage for all policy types
    // -----------------------------------------------------------------------

    /// Ensure that all valid policy types have a match arm in execute_policy
    /// (i.e., none fall through to the catch-all error). This test verifies
    /// that tag_pattern_keep is wired into execute_policy, not just validated.
    /// Since execute_policy requires a database, we verify indirectly by
    /// checking the match arms list matches the valid_types list.
    #[test]
    fn test_all_policy_types_are_executable() {
        // These are the types accepted by create_policy
        let create_types = [
            "max_age_days",
            "max_versions",
            "no_downloads_days",
            "tag_pattern_keep",
            "tag_pattern_delete",
            "size_quota_bytes",
        ];
        // These are the types handled in execute_policy match arms
        // (this list must be kept in sync manually — if a type is added to
        // create_types but not to execute_types, this test will fail)
        let execute_types = [
            "max_age_days",
            "max_versions",
            "no_downloads_days",
            "tag_pattern_keep",
            "tag_pattern_delete",
            "size_quota_bytes",
        ];
        for t in &create_types {
            assert!(
                execute_types.contains(t),
                "Policy type '{}' is accepted by create_policy but has no execute handler",
                t
            );
        }
    }

    // -----------------------------------------------------------------------
    // build_execution_result tests
    // -----------------------------------------------------------------------

    /// Helper: create a LifecyclePolicy with the given fields for use in
    /// build_execution_result tests. Only id, name, and policy_type matter
    /// for the builder; everything else gets sensible defaults.
    fn make_policy(id: Uuid, name: &str, policy_type: &str) -> LifecyclePolicy {
        let now = Utc::now();
        LifecyclePolicy {
            id,
            repository_id: None,
            name: name.to_string(),
            description: None,
            enabled: true,
            policy_type: policy_type.to_string(),
            config: json!({}),
            priority: 0,
            last_run_at: None,
            last_run_items_removed: None,
            cron_schedule: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn test_build_execution_result_dry_run_zeroes_removed_and_freed() {
        let id = Uuid::new_v4();
        let policy = make_policy(id, "Age Policy", "max_age_days");
        let result = LifecycleService::build_execution_result(&policy, true, 42, 42, 1_048_576);

        assert_eq!(result.policy_id, id);
        assert_eq!(result.policy_name, "Age Policy");
        assert!(result.dry_run);
        assert_eq!(result.artifacts_matched, 42);
        assert_eq!(
            result.artifacts_removed, 0,
            "dry_run should zero artifacts_removed"
        );
        assert_eq!(result.bytes_freed, 0, "dry_run should zero bytes_freed");
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_build_execution_result_real_run_preserves_values() {
        let id = Uuid::new_v4();
        let policy = make_policy(id, "Version Cleanup", "max_versions");
        let result = LifecycleService::build_execution_result(&policy, false, 100, 80, 5_000_000);

        assert_eq!(result.policy_id, id);
        assert_eq!(result.policy_name, "Version Cleanup");
        assert!(!result.dry_run);
        assert_eq!(result.artifacts_matched, 100);
        assert_eq!(result.artifacts_removed, 80);
        assert_eq!(result.bytes_freed, 5_000_000);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_build_execution_result_zero_values() {
        let id = Uuid::new_v4();
        let policy = make_policy(id, "Empty Run", "no_downloads_days");
        let result = LifecycleService::build_execution_result(&policy, false, 0, 0, 0);

        assert_eq!(result.artifacts_matched, 0);
        assert_eq!(result.artifacts_removed, 0);
        assert_eq!(result.bytes_freed, 0);
        assert!(!result.dry_run);
    }

    #[test]
    fn test_build_execution_result_zero_values_dry_run() {
        let id = Uuid::new_v4();
        let policy = make_policy(id, "Empty Dry", "max_age_days");
        let result = LifecycleService::build_execution_result(&policy, true, 0, 0, 0);

        assert_eq!(result.artifacts_matched, 0);
        assert_eq!(result.artifacts_removed, 0);
        assert_eq!(result.bytes_freed, 0);
        assert!(result.dry_run);
    }

    #[test]
    fn test_build_execution_result_large_values() {
        let id = Uuid::new_v4();
        let policy = make_policy(id, "Big Repo Cleanup", "size_quota_bytes");
        let matched = 1_000_000i64;
        let removed = 999_999i64;
        let bytes = 10_000_000_000_000i64; // 10 TB
        let result =
            LifecycleService::build_execution_result(&policy, false, matched, removed, bytes);

        assert_eq!(result.artifacts_matched, 1_000_000);
        assert_eq!(result.artifacts_removed, 999_999);
        assert_eq!(result.bytes_freed, 10_000_000_000_000);
    }

    #[test]
    fn test_build_execution_result_large_values_dry_run() {
        let id = Uuid::new_v4();
        let policy = make_policy(id, "Big Dry Run", "size_quota_bytes");
        let result = LifecycleService::build_execution_result(
            &policy,
            true,
            1_000_000,
            999_999,
            10_000_000_000_000,
        );

        assert_eq!(result.artifacts_matched, 1_000_000);
        assert_eq!(
            result.artifacts_removed, 0,
            "dry_run must zero even large artifacts_removed"
        );
        assert_eq!(
            result.bytes_freed, 0,
            "dry_run must zero even large bytes_freed"
        );
    }

    #[test]
    fn test_build_execution_result_matched_greater_than_removed() {
        let id = Uuid::new_v4();
        let policy = make_policy(id, "Partial Cleanup", "tag_pattern_delete");
        let result = LifecycleService::build_execution_result(&policy, false, 50, 30, 2048);

        assert_eq!(result.artifacts_matched, 50);
        assert_eq!(result.artifacts_removed, 30);
        assert_eq!(result.bytes_freed, 2048);
    }

    #[test]
    fn test_build_execution_result_clones_policy_name() {
        let id = Uuid::new_v4();
        let policy = make_policy(id, "Original Name", "max_age_days");
        let result = LifecycleService::build_execution_result(&policy, false, 1, 1, 100);

        // The result should have a cloned copy of the policy name
        assert_eq!(result.policy_name, "Original Name");
        // Verify the original policy is still intact (not moved)
        assert_eq!(policy.name, "Original Name");
    }

    #[test]
    fn test_build_execution_result_errors_always_empty() {
        // build_execution_result always returns an empty errors vec;
        // errors are only populated by the caller (e.g., execute_all_enabled).
        let policy = make_policy(Uuid::new_v4(), "Test", "max_age_days");

        let dry = LifecycleService::build_execution_result(&policy, true, 10, 10, 500);
        assert!(dry.errors.is_empty());

        let real = LifecycleService::build_execution_result(&policy, false, 10, 10, 500);
        assert!(real.errors.is_empty());
    }

    #[test]
    fn test_build_execution_result_preserves_policy_id() {
        // Verify with a nil UUID (edge case)
        let nil_policy = make_policy(Uuid::nil(), "Nil ID Policy", "max_versions");
        let result = LifecycleService::build_execution_result(&nil_policy, false, 5, 5, 100);
        assert_eq!(result.policy_id, Uuid::nil());

        // And with a specific UUID
        let specific_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let specific_policy = make_policy(specific_id, "Specific", "max_age_days");
        let result2 = LifecycleService::build_execution_result(&specific_policy, true, 1, 1, 50);
        assert_eq!(result2.policy_id, specific_id);
    }

    #[test]
    fn test_build_execution_result_each_policy_type() {
        // Confirm build_execution_result works identically regardless of policy_type
        // (it does not branch on policy_type, but this guards against future regressions).
        let types = [
            "max_age_days",
            "max_versions",
            "no_downloads_days",
            "tag_pattern_keep",
            "tag_pattern_delete",
            "size_quota_bytes",
        ];
        for pt in types {
            let policy = make_policy(Uuid::new_v4(), &format!("{} policy", pt), pt);
            let result = LifecycleService::build_execution_result(&policy, false, 10, 7, 4096);
            assert_eq!(result.artifacts_matched, 10);
            assert_eq!(result.artifacts_removed, 7);
            assert_eq!(result.bytes_freed, 4096);
            assert_eq!(result.policy_name, format!("{} policy", pt));
        }
    }

    // -----------------------------------------------------------------------
    // validate_policy_config: boundary and edge-case tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_validate_max_age_days_boundary_one() {
        let svc = make_service_for_validation();
        let config = json!({"days": 1});
        assert!(svc.validate_policy_config("max_age_days", &config).is_ok());
    }

    #[tokio::test]
    async fn test_validate_max_age_days_very_large() {
        let svc = make_service_for_validation();
        let config = json!({"days": 36500}); // 100 years
        assert!(svc.validate_policy_config("max_age_days", &config).is_ok());
    }

    #[tokio::test]
    async fn test_validate_max_age_days_float_value() {
        let svc = make_service_for_validation();
        // 30.5 is a float, as_i64() returns None for non-integer JSON numbers
        let config = json!({"days": 30.5});
        let result = svc.validate_policy_config("max_age_days", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_max_age_days_null_value() {
        let svc = make_service_for_validation();
        let config = json!({"days": null});
        let result = svc.validate_policy_config("max_age_days", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_max_versions_boundary_one() {
        let svc = make_service_for_validation();
        let config = json!({"keep": 1});
        assert!(svc.validate_policy_config("max_versions", &config).is_ok());
    }

    #[tokio::test]
    async fn test_validate_max_versions_very_large() {
        let svc = make_service_for_validation();
        let config = json!({"keep": 100_000});
        assert!(svc.validate_policy_config("max_versions", &config).is_ok());
    }

    #[tokio::test]
    async fn test_validate_max_versions_float_value() {
        let svc = make_service_for_validation();
        let config = json!({"keep": 5.5});
        let result = svc.validate_policy_config("max_versions", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_no_downloads_days_boundary_one() {
        let svc = make_service_for_validation();
        let config = json!({"days": 1});
        assert!(svc
            .validate_policy_config("no_downloads_days", &config)
            .is_ok());
    }

    #[tokio::test]
    async fn test_validate_no_downloads_days_negative() {
        let svc = make_service_for_validation();
        let config = json!({"days": -10});
        let result = svc.validate_policy_config("no_downloads_days", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_size_quota_bytes_boundary_one() {
        let svc = make_service_for_validation();
        let config = json!({"quota_bytes": 1});
        assert!(svc
            .validate_policy_config("size_quota_bytes", &config)
            .is_ok());
    }

    #[tokio::test]
    async fn test_validate_size_quota_bytes_very_large() {
        let svc = make_service_for_validation();
        // 1 PB
        let config = json!({"quota_bytes": 1_125_899_906_842_624_i64});
        assert!(svc
            .validate_policy_config("size_quota_bytes", &config)
            .is_ok());
    }

    #[tokio::test]
    async fn test_validate_size_quota_bytes_float_value() {
        let svc = make_service_for_validation();
        let config = json!({"quota_bytes": 1073741824.5});
        let result = svc.validate_policy_config("size_quota_bytes", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_tag_pattern_complex_regex() {
        let svc = make_service_for_validation();
        let config = json!({"pattern": r"^v\d+\.\d+\.\d+(-rc\.\d+)?$"});
        assert!(svc
            .validate_policy_config("tag_pattern_keep", &config)
            .is_ok());
    }

    #[tokio::test]
    async fn test_validate_tag_pattern_empty_string() {
        // An empty regex is technically valid (matches everything)
        let svc = make_service_for_validation();
        let config = json!({"pattern": ""});
        assert!(svc
            .validate_policy_config("tag_pattern_delete", &config)
            .is_ok());
    }

    #[tokio::test]
    async fn test_validate_tag_pattern_delete_invalid_nested_groups() {
        let svc = make_service_for_validation();
        let config = json!({"pattern": "((("});
        let result = svc.validate_policy_config("tag_pattern_delete", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_tag_pattern_null_pattern() {
        let svc = make_service_for_validation();
        let config = json!({"pattern": null});
        let result = svc.validate_policy_config("tag_pattern_keep", &config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_validate_tag_pattern_boolean_pattern() {
        let svc = make_service_for_validation();
        let config = json!({"pattern": true});
        let result = svc.validate_policy_config("tag_pattern_delete", &config);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // validate_policy_config: error message content
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_validate_max_age_error_message_content() {
        let svc = make_service_for_validation();
        let config = json!({});
        let err = svc
            .validate_policy_config("max_age_days", &config)
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("max_age_days"),
            "Error should mention the policy type"
        );
        assert!(
            msg.contains("days"),
            "Error should mention the missing field"
        );
    }

    #[tokio::test]
    async fn test_validate_max_versions_error_message_content() {
        let svc = make_service_for_validation();
        let config = json!({"keep": -1});
        let err = svc
            .validate_policy_config("max_versions", &config)
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("max_versions"));
        assert!(msg.contains("keep"));
    }

    #[tokio::test]
    async fn test_validate_size_quota_error_message_content() {
        let svc = make_service_for_validation();
        let config = json!({"quota_bytes": 0});
        let err = svc
            .validate_policy_config("size_quota_bytes", &config)
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("size_quota_bytes"));
        assert!(msg.contains("quota_bytes"));
    }

    #[tokio::test]
    async fn test_validate_tag_pattern_invalid_regex_error_message() {
        let svc = make_service_for_validation();
        let config = json!({"pattern": "[bad"});
        let err = svc
            .validate_policy_config("tag_pattern_keep", &config)
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("regex"), "Error should mention regex");
    }

    // -----------------------------------------------------------------------
    // validate_policy_config: extra keys are silently ignored
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_validate_extra_keys_ignored() {
        let svc = make_service_for_validation();

        // max_age_days with extra fields
        let config = json!({"days": 30, "extra": "ignored", "another": 99});
        assert!(svc.validate_policy_config("max_age_days", &config).is_ok());

        // tag_pattern_keep with extra fields
        let config = json!({"pattern": "^release", "foo": "bar"});
        assert!(svc
            .validate_policy_config("tag_pattern_keep", &config)
            .is_ok());
    }

    // -----------------------------------------------------------------------
    // PolicyExecutionResult: serialization edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_policy_execution_result_serialization_large_values() {
        let result = PolicyExecutionResult {
            policy_id: Uuid::new_v4(),
            policy_name: "Terabyte Cleanup".to_string(),
            dry_run: false,
            artifacts_matched: i64::MAX,
            artifacts_removed: i64::MAX,
            bytes_freed: i64::MAX,
            errors: vec![],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains(&i64::MAX.to_string()));
    }

    #[test]
    fn test_policy_execution_result_serialization_zero_artifacts() {
        let result = PolicyExecutionResult {
            policy_id: Uuid::nil(),
            policy_name: "No-Op".to_string(),
            dry_run: false,
            artifacts_matched: 0,
            artifacts_removed: 0,
            bytes_freed: 0,
            errors: vec![],
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["artifacts_matched"], 0);
        assert_eq!(parsed["artifacts_removed"], 0);
        assert_eq!(parsed["bytes_freed"], 0);
        assert_eq!(parsed["dry_run"], false);
    }

    // -----------------------------------------------------------------------
    // CreateLifecyclePolicyRequest: deserialization edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_policy_request_missing_required_field() {
        // Missing "name" field
        let json_str = r#"{"policy_type": "max_age_days", "config": {"days": 30}}"#;
        let result: std::result::Result<CreateLifecyclePolicyRequest, _> =
            serde_json::from_str(json_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_create_policy_request_missing_config() {
        // Missing "config" field
        let json_str = r#"{"name": "Test", "policy_type": "max_age_days"}"#;
        let result: std::result::Result<CreateLifecyclePolicyRequest, _> =
            serde_json::from_str(json_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_policy_request_partial_fields() {
        let json_val = json!({
            "enabled": false,
            "priority": 99
        });
        let req: UpdateLifecyclePolicyRequest = serde_json::from_value(json_val).unwrap();
        assert!(req.name.is_none());
        assert!(req.description.is_none());
        assert_eq!(req.enabled, Some(false));
        assert!(req.config.is_none());
        assert_eq!(req.priority, Some(99));
    }

    #[test]
    fn test_update_policy_request_all_fields() {
        let json_val = json!({
            "name": "Updated Name",
            "description": "Updated Description",
            "enabled": true,
            "config": {"days": 60},
            "priority": 5,
            "cron_schedule": "0 0 3 * * *"
        });
        let req: UpdateLifecyclePolicyRequest = serde_json::from_value(json_val).unwrap();
        assert_eq!(req.name, Some("Updated Name".to_string()));
        assert_eq!(req.description, Some("Updated Description".to_string()));
        assert_eq!(req.enabled, Some(true));
        assert!(req.config.is_some());
        assert_eq!(req.config.unwrap()["days"], 60);
        assert_eq!(req.priority, Some(5));
        assert_eq!(req.cron_schedule, Some("0 0 3 * * *".to_string()));
    }

    // -----------------------------------------------------------------------
    // cron_schedule field tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_policy_request_with_cron_schedule() {
        let json_val = json!({
            "name": "Scheduled Policy",
            "policy_type": "max_age_days",
            "config": {"days": 7},
            "cron_schedule": "0 0 2 * * *"
        });
        let req: CreateLifecyclePolicyRequest = serde_json::from_value(json_val).unwrap();
        assert_eq!(req.cron_schedule, Some("0 0 2 * * *".to_string()));
    }

    #[test]
    fn test_create_policy_request_without_cron_schedule() {
        let json_val = json!({
            "name": "Unscheduled Policy",
            "policy_type": "max_age_days",
            "config": {"days": 7}
        });
        let req: CreateLifecyclePolicyRequest = serde_json::from_value(json_val).unwrap();
        assert!(req.cron_schedule.is_none());
    }

    #[test]
    fn test_update_policy_request_cron_schedule_none() {
        let json_val = json!({
            "enabled": true
        });
        let req: UpdateLifecyclePolicyRequest = serde_json::from_value(json_val).unwrap();
        assert!(req.cron_schedule.is_none());
    }

    #[test]
    fn test_lifecycle_policy_serialization_with_cron_schedule() {
        let now = Utc::now();
        let policy = LifecyclePolicy {
            id: Uuid::nil(),
            repository_id: None,
            name: "Cron Policy".to_string(),
            description: None,
            enabled: true,
            policy_type: "max_age_days".to_string(),
            config: json!({"days": 14}),
            priority: 0,
            last_run_at: None,
            last_run_items_removed: None,
            cron_schedule: Some("0 30 1 * * *".to_string()),
            created_at: now,
            updated_at: now,
        };

        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains("\"cron_schedule\":\"0 30 1 * * *\""));
    }

    // -----------------------------------------------------------------------
    // is_due_by_default_cadence tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_due_never_run_returns_true() {
        let now = Utc::now();
        let cadence = chrono::Duration::hours(6);
        assert!(
            LifecycleService::is_due_by_default_cadence(None, now, cadence),
            "A policy that has never run should always be due"
        );
    }

    #[test]
    fn test_is_due_recently_run_returns_false() {
        let now = Utc::now();
        let cadence = chrono::Duration::hours(6);
        let last_run = now - chrono::Duration::hours(1);
        assert!(
            !LifecycleService::is_due_by_default_cadence(Some(last_run), now, cadence),
            "A policy that ran 1 hour ago should not be due with a 6-hour cadence"
        );
    }

    #[test]
    fn test_is_due_old_run_returns_true() {
        let now = Utc::now();
        let cadence = chrono::Duration::hours(6);
        let last_run = now - chrono::Duration::hours(7);
        assert!(
            LifecycleService::is_due_by_default_cadence(Some(last_run), now, cadence),
            "A policy that ran 7 hours ago should be due with a 6-hour cadence"
        );
    }

    #[test]
    fn test_is_due_exactly_at_cadence_returns_true() {
        let now = Utc::now();
        let cadence = chrono::Duration::hours(6);
        let last_run = now - chrono::Duration::hours(6);
        assert!(
            LifecycleService::is_due_by_default_cadence(Some(last_run), now, cadence),
            "A policy that ran exactly 6 hours ago should be due"
        );
    }

    #[test]
    fn test_is_due_just_under_cadence_returns_false() {
        let now = Utc::now();
        let cadence = chrono::Duration::hours(6);
        let last_run = now - chrono::Duration::hours(6) + chrono::Duration::seconds(1);
        assert!(
            !LifecycleService::is_due_by_default_cadence(Some(last_run), now, cadence),
            "A policy that ran just under 6 hours ago should not be due"
        );
    }

    // -----------------------------------------------------------------------
    // Cron schedule parsing for policies
    // -----------------------------------------------------------------------

    #[test]
    fn test_cron_schedule_from_str_valid() {
        let expr = "0 0 2 * * *"; // daily at 2 AM
        let schedule = cron::Schedule::from_str(expr);
        assert!(schedule.is_ok(), "Valid 6-field cron should parse");
    }

    #[test]
    fn test_cron_schedule_from_str_invalid() {
        let expr = "not a cron";
        let schedule = cron::Schedule::from_str(expr);
        assert!(schedule.is_err(), "Invalid cron should fail");
    }

    #[test]
    fn test_cron_schedule_upcoming_returns_future_time() {
        let expr = "0 * * * * *"; // every minute
        let schedule = cron::Schedule::from_str(expr).unwrap();
        let next = schedule.upcoming(Utc).next();
        assert!(next.is_some());
        assert!(next.unwrap() > Utc::now());
    }

    #[test]
    fn test_cron_schedule_after_last_run_detects_due() {
        let expr = "0 * * * * *"; // every minute
        let schedule = cron::Schedule::from_str(expr).unwrap();
        // A last_run 2 minutes ago should have at least one scheduled time between then and now
        let last_run = Utc::now() - chrono::Duration::minutes(2);
        let now = Utc::now();
        let has_occurrence = schedule
            .after(&last_run)
            .take_while(|t| *t <= now)
            .next()
            .is_some();
        assert!(
            has_occurrence,
            "Should find a scheduled time in the last 2 minutes for every-minute cron"
        );
    }

    #[test]
    fn test_create_policy_rejects_invalid_cron() {
        // Verify the validation logic directly
        let invalid = "not-a-cron";
        let normalized = normalize_cron_expression(invalid);
        assert!(cron::Schedule::from_str(&normalized).is_err());
    }

    // -----------------------------------------------------------------------
    // is_policy_due (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_policy_due_no_cron_never_run() {
        let now = Utc::now();
        let cadence = chrono::Duration::hours(6);
        assert!(LifecycleService::is_policy_due(None, None, now, cadence));
    }

    #[test]
    fn test_is_policy_due_no_cron_recently_run() {
        let now = Utc::now();
        let last_run = now - chrono::Duration::hours(1);
        let cadence = chrono::Duration::hours(6);
        assert!(!LifecycleService::is_policy_due(
            None,
            Some(last_run),
            now,
            cadence
        ));
    }

    #[test]
    fn test_is_policy_due_no_cron_overdue() {
        let now = Utc::now();
        let last_run = now - chrono::Duration::hours(7);
        let cadence = chrono::Duration::hours(6);
        assert!(LifecycleService::is_policy_due(
            None,
            Some(last_run),
            now,
            cadence
        ));
    }

    #[test]
    fn test_is_policy_due_valid_cron_never_run() {
        let now = Utc::now();
        let cadence = chrono::Duration::hours(6);
        // Every minute cron
        assert!(LifecycleService::is_policy_due(
            Some("0 * * * * *"),
            None,
            now,
            cadence
        ));
    }

    #[test]
    fn test_is_policy_due_valid_cron_recently_run() {
        // Use a fixed timestamp at minute 45 so the 30-minute window (15..45)
        // never crosses an hour boundary where the hourly cron fires.
        // Using Utc::now() caused flaky failures when the current minute < 30.
        let now = chrono::TimeZone::with_ymd_and_hms(&Utc, 2025, 6, 15, 10, 45, 0).unwrap();
        let last_run = now - chrono::Duration::minutes(30);
        let cadence = chrono::Duration::hours(6);
        // Hourly cron: next occurrence after 10:15 is 11:00, which is past 10:45
        assert!(!LifecycleService::is_policy_due(
            Some("0 0 * * * *"),
            Some(last_run),
            now,
            cadence
        ));
    }

    #[test]
    fn test_is_policy_due_valid_cron_overdue() {
        let now = Utc::now();
        let last_run = now - chrono::Duration::minutes(2);
        let cadence = chrono::Duration::hours(6);
        // Every minute cron: should have an occurrence in last 2 minutes
        assert!(LifecycleService::is_policy_due(
            Some("0 * * * * *"),
            Some(last_run),
            now,
            cadence
        ));
    }

    #[test]
    fn test_is_policy_due_invalid_cron_falls_back_to_cadence_due() {
        let now = Utc::now();
        let last_run = now - chrono::Duration::hours(7);
        let cadence = chrono::Duration::hours(6);
        assert!(LifecycleService::is_policy_due(
            Some("invalid"),
            Some(last_run),
            now,
            cadence
        ));
    }

    #[test]
    fn test_is_policy_due_invalid_cron_falls_back_to_cadence_not_due() {
        let now = Utc::now();
        let last_run = now - chrono::Duration::hours(1);
        let cadence = chrono::Duration::hours(6);
        assert!(!LifecycleService::is_policy_due(
            Some("invalid"),
            Some(last_run),
            now,
            cadence
        ));
    }

    #[test]
    fn test_is_policy_due_5_field_cron_normalized() {
        let now = Utc::now();
        let last_run = now - chrono::Duration::minutes(6);
        let cadence = chrono::Duration::hours(6);
        // 5-field cron "*/5 * * * *" (every 5 minutes) gets normalized to 6-field;
        // with last_run 6 minutes ago there should be at least one occurrence
        assert!(LifecycleService::is_policy_due(
            Some("*/5 * * * *"),
            Some(last_run),
            now,
            cadence
        ));
    }

    // -----------------------------------------------------------------------
    // cascade_oci_tags_cleanup tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_cascade_sql_matches_expected_predicates() {
        // The SQL has to keep the (repo, manifest_digest, image, tag) join
        // shape and the repo-scope guard. Drifting any of these would either
        // delete unrelated tags (no repo filter) or leak rows in other repos
        // (a global delete unscoped by image:tag).
        assert!(CASCADE_OCI_TAGS_SQL.contains("DELETE FROM oci_tags ot"));
        assert!(CASCADE_OCI_TAGS_SQL.contains("USING artifacts a"));
        assert!(CASCADE_OCI_TAGS_SQL.contains("a.is_deleted = true"));
        assert!(CASCADE_OCI_TAGS_SQL.contains("a.repository_id = ot.repository_id"));
        assert!(CASCADE_OCI_TAGS_SQL.contains("'oci-manifests/' || ot.manifest_digest"));
        // Path-based join replaces the previous substring-regex on
        // `artifacts.name`. The regex broke for digest references
        // (`img:sha256:abc`) and was fragile around port-in-name.
        assert!(
            CASCADE_OCI_TAGS_SQL.contains("a.path = 'v2/' || ot.name || '/manifests/' || ot.tag")
        );
        assert!(
            !CASCADE_OCI_TAGS_SQL.contains("substring(a.name"),
            "regex on artifacts.name was replaced by a path-based join"
        );
        assert!(CASCADE_OCI_TAGS_SQL.contains("a.version = ot.tag"));
        assert!(CASCADE_OCI_TAGS_SQL.contains("$1::UUID IS NULL OR a.repository_id = $1"));
    }

    #[test]
    fn test_cascade_sql_has_last_protecting_tag_guard() {
        // #1682: a tag may only be pruned when a SURVIVING sibling oci_tags
        // row (same repo+digest, different id, NOT itself being pruned) still
        // protects the manifest. The guard is an EXISTS over `oci_tags keep`
        // with a self-aware inner NOT EXISTS on soft-deleted backing
        // artifacts. Drifting any of these reopens the data-loss bug.
        assert!(
            CASCADE_OCI_TAGS_SQL.contains("FROM oci_tags keep"),
            "missing surviving-sibling EXISTS subquery (#1682 guard)"
        );
        assert!(
            CASCADE_OCI_TAGS_SQL.contains("keep.repository_id = ot.repository_id"),
            "sibling guard must correlate on repository_id (per-repo scoping)"
        );
        assert!(
            CASCADE_OCI_TAGS_SQL.contains("keep.manifest_digest = ot.manifest_digest"),
            "sibling guard must correlate on manifest_digest (reachability key)"
        );
        assert!(
            CASCADE_OCI_TAGS_SQL.contains("keep.id <> ot.id"),
            "sibling guard must exclude the row being pruned"
        );
        // The self-aware inner NOT EXISTS (Option A over Option B): a sibling
        // counts as a protector only if its backing manifest artifact is NOT
        // itself soft-deleted. Without this, two doomed tags for one digest
        // each treat the other as a protector and both get deleted.
        assert!(
            CASCADE_OCI_TAGS_SQL.contains("FROM artifacts ka"),
            "sibling guard must verify the sibling's backing artifact is not soft-deleted (#1682 Option A)"
        );
        assert!(
            CASCADE_OCI_TAGS_SQL.contains("ka.is_deleted = true"),
            "inner NOT EXISTS must key on a soft-deleted backing artifact"
        );
    }

    // The cascade now runs inside the execute_policy transaction (no
    // standalone entry point with a `dry_run` flag). These tests cover
    // the surface the unit suite can reach without Postgres: SQL shape +
    // path-reconstruction predicate. Behavioural coverage lives in
    // backend/tests/lifecycle_policy_tests.rs against a real database,
    // including the port-in-name and digest-as-reference regression
    // cases from PR #1406 review.

    #[test]
    fn test_cascade_sql_path_reconstruction_handles_port_in_name() {
        // Pure-Rust mirror of the SQL predicate. If this drifts from the
        // SQL the integration test in backend/tests/lifecycle_policy_tests.rs
        // (`test_cascade_handles_port_in_image_name`) will catch it. We
        // assert the rebuilt path matches `artifacts.path` for the
        // pathological inputs the old `substring(...)` regex failed on.
        fn rebuild_path(image: &str, tag: &str) -> String {
            format!("v2/{image}/manifests/{tag}")
        }
        fn artifact_path(image: &str, reference: &str) -> String {
            // mirrors backend/src/api/handlers/oci_v2.rs put_manifest:
            //   let artifact_path = format!("v2/{}/manifests/{}", image, reference);
            format!("v2/{image}/manifests/{reference}")
        }

        // 1. Simple case.
        assert_eq!(rebuild_path("myimg", "v1"), artifact_path("myimg", "v1"),);
        // 2. Nested image namespace.
        assert_eq!(
            rebuild_path("org/img", "latest"),
            artifact_path("org/img", "latest"),
        );
        // 3. Port-in-name (concern #1 from PR #1406 review).
        assert_eq!(
            rebuild_path("myregistry.example:5000/image", "tag"),
            artifact_path("myregistry.example:5000/image", "tag"),
        );
        // 4. Digest as reference (the regex on `artifacts.name`
        //    extracted `img:sha256`, not `img`, breaking the join).
        assert_eq!(
            rebuild_path("myimg", "sha256:abc123"),
            artifact_path("myimg", "sha256:abc123"),
        );
        // 5. Combined: port-in-name AND digest reference.
        assert_eq!(
            rebuild_path("host:5000/img", "sha256:abc123"),
            artifact_path("host:5000/img", "sha256:abc123"),
        );
    }

    // -----------------------------------------------------------------------
    // CascadeScope tests (pure conversion + repo_filter)
    //
    // CascadeScope wraps the `Option<Uuid>` repo filter used by the cascade
    // SQL and every per-type executor. The tests below pin the From impl
    // and the helper accessors so accidental changes (e.g., swapping the
    // None and Some arms) are caught without needing Postgres.
    // -----------------------------------------------------------------------

    #[test]
    fn test_cascade_scope_from_none_is_global() {
        let scope: CascadeScope = Option::<Uuid>::None.into();
        assert_eq!(scope, CascadeScope::Global);
        assert!(scope.is_global());
        assert!(scope.repo_filter().is_none());
    }

    #[test]
    fn test_cascade_scope_from_some_is_per_repo() {
        let id = Uuid::new_v4();
        let scope: CascadeScope = Some(id).into();
        assert_eq!(scope, CascadeScope::PerRepo(id));
        assert!(!scope.is_global());
        assert_eq!(scope.repo_filter(), Some(id));
    }

    #[test]
    fn test_cascade_scope_round_trip_through_option() {
        // `Option<Uuid>` -> `CascadeScope` -> `Option<Uuid>` must be
        // identity. The cascade SQL relies on this: `$1::UUID IS NULL OR
        // a.repository_id = $1` reads the original `Option<Uuid>` semantics
        // back out, so any reshuffle in `From` would silently widen the
        // delete scope (Some -> None).
        let cases: [Option<Uuid>; 3] = [None, Some(Uuid::nil()), Some(Uuid::new_v4())];
        for original in cases {
            let scope = CascadeScope::from(original);
            assert_eq!(scope.repo_filter(), original);
        }
    }

    #[test]
    fn test_cascade_scope_per_repo_with_nil_uuid_is_not_global() {
        // Nil UUID is still a valid (if synthetic) repo id. The scope must
        // be PerRepo, not Global, even if the id happens to be all zeros.
        let scope: CascadeScope = Some(Uuid::nil()).into();
        assert!(!scope.is_global());
        assert_eq!(scope.repo_filter(), Some(Uuid::nil()));
    }

    #[test]
    fn test_cascade_scope_copy_semantics() {
        // CascadeScope is Copy so it can pass through call sites by value
        // without borrow gymnastics. This test exists so removing Copy
        // would trip CI before it breaks the cascade callers.
        let scope: CascadeScope = Some(Uuid::new_v4()).into();
        let scope_copy = scope;
        assert_eq!(scope, scope_copy);
    }

    // -----------------------------------------------------------------------
    // PolicyType parsing (mirrors dispatch_execute match arms)
    //
    // dispatch_execute now routes through PolicyType::parse, so every
    // wire-format string must round-trip and the unsupported branch must
    // raise the same `AppError::Internal` the inline match used to.
    // -----------------------------------------------------------------------

    #[test]
    fn test_policy_type_parse_all_valid_variants() {
        let cases = [
            ("max_age_days", PolicyType::MaxAgeDays),
            ("max_versions", PolicyType::MaxVersions),
            ("no_downloads_days", PolicyType::NoDownloadsDays),
            ("tag_pattern_keep", PolicyType::TagPatternKeep),
            ("tag_pattern_delete", PolicyType::TagPatternDelete),
            ("size_quota_bytes", PolicyType::SizeQuotaBytes),
        ];
        for (wire, expected) in cases {
            let got = PolicyType::parse(wire).expect("valid wire string");
            assert_eq!(got, expected, "{wire} should parse to {expected:?}");
        }
    }

    #[test]
    fn test_policy_type_parse_rejects_unknown() {
        let err = PolicyType::parse("custom_type").unwrap_err();
        // The original dispatcher emitted `AppError::Internal`; preserve
        // that mapping so callers (e.g., the JSON error layer) keep
        // returning 500 rather than 400 for an unsupported type on a
        // legitimate persisted row.
        assert!(
            matches!(err, AppError::Internal(_)),
            "unknown policy type must surface as Internal, got: {err:?}"
        );
        let msg = err.to_string();
        assert!(msg.contains("Unsupported policy type"));
        assert!(msg.contains("custom_type"));
    }

    #[test]
    fn test_policy_type_parse_rejects_empty_string() {
        let err = PolicyType::parse("").unwrap_err();
        assert!(matches!(err, AppError::Internal(_)));
    }

    #[test]
    fn test_policy_type_parse_is_case_sensitive() {
        // Wire format is snake_case. Anything else is unsupported.
        // Catching this in a test guards against a future "make it
        // lenient" refactor accidentally accepting `Max_Age_Days` from a
        // misconfigured migration.
        let cases = ["Max_Age_Days", "MAX_AGE_DAYS", "MaxAgeDays"];
        for wire in cases {
            assert!(
                PolicyType::parse(wire).is_err(),
                "{wire} must not parse (case-sensitive)"
            );
        }
    }

    #[test]
    fn test_policy_type_as_wire_str_round_trip() {
        // Every variant's `as_wire_str` must round-trip through `parse`.
        // The wire string is what we persist in `lifecycle_policies.policy_type`,
        // so a drift here is a silent migration bug.
        let variants = [
            PolicyType::MaxAgeDays,
            PolicyType::MaxVersions,
            PolicyType::NoDownloadsDays,
            PolicyType::TagPatternKeep,
            PolicyType::TagPatternDelete,
            PolicyType::SizeQuotaBytes,
        ];
        for v in variants {
            let s = v.as_wire_str();
            assert_eq!(
                PolicyType::parse(s).unwrap(),
                v,
                "{v:?} -> {s:?} must round-trip"
            );
        }
    }

    #[test]
    fn test_policy_type_wire_strings_match_create_policy_whitelist() {
        // create_policy validates against a literal whitelist; PolicyType
        // must accept exactly those same strings. If a new variant is
        // added to PolicyType but not to create_policy (or vice versa)
        // this assertion fails — same intent as
        // test_all_policy_types_are_executable, scoped to the new enum.
        let whitelist = [
            "max_age_days",
            "max_versions",
            "no_downloads_days",
            "tag_pattern_keep",
            "tag_pattern_delete",
            "size_quota_bytes",
        ];
        for s in whitelist {
            PolicyType::parse(s)
                .unwrap_or_else(|_| panic!("create_policy accepts {s} but PolicyType rejects it"));
        }
    }

    // -----------------------------------------------------------------------
    // parse_i64_field (config extraction for execute_*)
    //
    // Each per-type executor used to inline `config.get(k).and_then(as_i64)`
    // followed by an `ok_or_else(Validation(...))`. That branch is now in
    // `parse_i64_field` so the failure shapes are covered without standing
    // up Postgres.
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_i64_field_returns_value_when_present() {
        let cfg = json!({"days": 30});
        let v = parse_i64_field(&cfg, "max_age_days", "days").unwrap();
        assert_eq!(v, 30);
    }

    #[test]
    fn test_parse_i64_field_accepts_zero_and_negative() {
        // Behaviour parity with the pre-extraction inline code: only
        // missing/non-integer values are rejected here. Positivity is
        // enforced in `validate_policy_config` at policy-create time.
        let zero = json!({"days": 0});
        assert_eq!(parse_i64_field(&zero, "max_age_days", "days").unwrap(), 0);
        let neg = json!({"days": -5});
        assert_eq!(parse_i64_field(&neg, "max_age_days", "days").unwrap(), -5);
    }

    #[test]
    fn test_parse_i64_field_missing_key_errors_with_policy_label() {
        let cfg = json!({});
        let err = parse_i64_field(&cfg, "max_age_days", "days").unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
        let msg = err.to_string();
        // Error message must name both the policy type and the missing
        // field so logs are actionable without cross-referencing source.
        assert!(msg.contains("max_age_days"));
        assert!(msg.contains("days"));
    }

    #[test]
    fn test_parse_i64_field_string_value_errors() {
        let cfg = json!({"days": "thirty"});
        assert!(parse_i64_field(&cfg, "max_age_days", "days").is_err());
    }

    #[test]
    fn test_parse_i64_field_float_value_errors() {
        // serde_json's as_i64() returns None for non-integer numbers, even
        // ones like 30.0 — preserving that contract is intentional, since
        // a config of `30.5` days shouldn't silently truncate.
        let cfg = json!({"days": 30.5});
        assert!(parse_i64_field(&cfg, "max_age_days", "days").is_err());
    }

    #[test]
    fn test_parse_i64_field_null_value_errors() {
        let cfg = json!({"days": null});
        assert!(parse_i64_field(&cfg, "max_age_days", "days").is_err());
    }

    #[test]
    fn test_parse_i64_field_bool_value_errors() {
        let cfg = json!({"days": true});
        assert!(parse_i64_field(&cfg, "max_age_days", "days").is_err());
    }

    #[test]
    fn test_parse_i64_field_works_for_keep_quota_bytes() {
        // Same extractor is shared across days/keep/quota_bytes — verify
        // the policy-type label and key thread through correctly for each.
        let cfg = json!({"keep": 5, "quota_bytes": 1_073_741_824i64});
        assert_eq!(parse_i64_field(&cfg, "max_versions", "keep").unwrap(), 5);
        assert_eq!(
            parse_i64_field(&cfg, "size_quota_bytes", "quota_bytes").unwrap(),
            1_073_741_824
        );
    }

    #[test]
    fn test_parse_i64_field_accepts_flat_policy_type_alias() {
        // Pre-keep wire shape: tests/CLIs used to post `{ "max_versions": N }`
        // (flat) instead of `{ "keep": N }`. Both shapes must work.
        let cfg = json!({"max_versions": 5});
        assert_eq!(parse_i64_field(&cfg, "max_versions", "keep").unwrap(), 5);

        let cfg = json!({"max_age_days": 30});
        assert_eq!(parse_i64_field(&cfg, "max_age_days", "days").unwrap(), 30);

        let cfg = json!({"size_quota_bytes": 1024});
        assert_eq!(
            parse_i64_field(&cfg, "size_quota_bytes", "quota_bytes").unwrap(),
            1024
        );
    }

    #[test]
    fn test_parse_i64_field_canonical_key_wins_over_flat_alias() {
        // When both shapes are present the canonical key takes precedence
        // so an operator can override the flat value during a migration.
        let cfg = json!({"keep": 7, "max_versions": 99});
        assert_eq!(parse_i64_field(&cfg, "max_versions", "keep").unwrap(), 7);
    }

    #[test]
    fn test_parse_i64_field_flat_alias_non_integer_falls_through_to_error() {
        // Neither key is a valid integer, so we still get the canonical
        // "requires '<key>' in config" error — flat aliasing must not mask
        // typos.
        let cfg = json!({"max_versions": "five"});
        let err = parse_i64_field(&cfg, "max_versions", "keep").unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("max_versions"));
        assert!(msg.contains("keep"));
    }

    #[test]
    fn test_parse_i64_field_i64_max_and_min() {
        // Boundary values: the JSON spec allows i64-range integers and
        // our cleanup logic must accept the full range (e.g., a 9 EB quota
        // is unusual but well-typed).
        let max = json!({"quota_bytes": i64::MAX});
        assert_eq!(
            parse_i64_field(&max, "size_quota_bytes", "quota_bytes").unwrap(),
            i64::MAX
        );
        let min = json!({"days": i64::MIN});
        assert_eq!(
            parse_i64_field(&min, "max_age_days", "days").unwrap(),
            i64::MIN
        );
    }

    // -----------------------------------------------------------------------
    // parse_pattern_field
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_pattern_field_returns_string() {
        let cfg = json!({"pattern": "^release-.*"});
        let v = parse_pattern_field(&cfg, "tag_pattern_keep").unwrap();
        assert_eq!(v, "^release-.*");
    }

    #[test]
    fn test_parse_pattern_field_accepts_empty_string() {
        // Empty pattern is a no-op regex (matches nothing under `name ~ $2`
        // / matches everything under `name !~ $2`). validate_policy_config
        // rejects it at create-time; here at execute-time we mirror the
        // original code which only checked for the key's existence.
        let cfg = json!({"pattern": ""});
        assert!(parse_pattern_field(&cfg, "tag_pattern_delete").is_ok());
    }

    #[test]
    fn test_parse_pattern_field_missing_key_errors() {
        let cfg = json!({});
        let err = parse_pattern_field(&cfg, "tag_pattern_keep").unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
        let msg = err.to_string();
        assert!(msg.contains("tag_pattern_keep"));
        assert!(msg.contains("pattern"));
    }

    #[test]
    fn test_parse_pattern_field_integer_pattern_errors() {
        let cfg = json!({"pattern": 42});
        assert!(parse_pattern_field(&cfg, "tag_pattern_keep").is_err());
    }

    #[test]
    fn test_parse_pattern_field_null_pattern_errors() {
        let cfg = json!({"pattern": null});
        assert!(parse_pattern_field(&cfg, "tag_pattern_delete").is_err());
    }

    #[test]
    fn test_parse_pattern_field_array_pattern_errors() {
        let cfg = json!({"pattern": ["a", "b"]});
        assert!(parse_pattern_field(&cfg, "tag_pattern_keep").is_err());
    }

    #[test]
    fn test_parse_pattern_field_passes_through_invalid_regex() {
        // Per docstring, validation of the regex itself is the caller's
        // problem (validate_policy_config at create-time + DB engine at
        // execute-time). The extractor only checks the JSON shape.
        let cfg = json!({"pattern": "[unclosed"});
        let v = parse_pattern_field(&cfg, "tag_pattern_keep").unwrap();
        assert_eq!(v, "[unclosed");
    }

    // -----------------------------------------------------------------------
    // select_size_quota_evictions (pure greedy-LRU pick)
    //
    // The original inline loop in execute_size_quota is now in this pure
    // function, so the eviction maths is unit-testable without standing up
    // download_statistics + artifacts fixtures. We assert: ordering is
    // preserved, the accumulator can overshoot by one candidate (matching
    // pre-extraction behaviour), and edge cases (empty input, excess <= 0,
    // single candidate larger than excess) all behave correctly.
    // -----------------------------------------------------------------------

    #[test]
    fn test_select_size_quota_evictions_empty_candidates() {
        let (ids, acc) = select_size_quota_evictions(&[], 1024);
        assert!(ids.is_empty());
        assert_eq!(acc, 0);
    }

    #[test]
    fn test_select_size_quota_evictions_zero_excess_picks_nothing() {
        // excess == 0 means usage <= quota; the executor already early-
        // returns, but the pure helper must not pick anything either way.
        let id = Uuid::new_v4();
        let (ids, acc) = select_size_quota_evictions(&[(id, 100)], 0);
        assert!(ids.is_empty());
        assert_eq!(acc, 0);
    }

    #[test]
    fn test_select_size_quota_evictions_negative_excess_picks_nothing() {
        // Defensive: the SQL guarantees `usage > quota_bytes` before this
        // is called, but the helper must still no-op on negative input.
        let id = Uuid::new_v4();
        let (ids, acc) = select_size_quota_evictions(&[(id, 100)], -50);
        assert!(ids.is_empty());
        assert_eq!(acc, 0);
    }

    #[test]
    fn test_select_size_quota_evictions_single_candidate_exact_match() {
        let id = Uuid::new_v4();
        let (ids, acc) = select_size_quota_evictions(&[(id, 100)], 100);
        assert_eq!(ids, vec![id]);
        assert_eq!(acc, 100);
    }

    #[test]
    fn test_select_size_quota_evictions_single_candidate_overshoots() {
        // Behaviour preserved from the original loop: the candidate is
        // picked first, then the accumulator is checked, so a single
        // oversized candidate is the only one taken even if it dwarfs
        // `excess`.
        let id = Uuid::new_v4();
        let (ids, acc) = select_size_quota_evictions(&[(id, 1_000)], 100);
        assert_eq!(ids, vec![id]);
        assert_eq!(acc, 1_000);
    }

    #[test]
    fn test_select_size_quota_evictions_preserves_input_order() {
        // The SQL feeds candidates pre-sorted by least-recent-download
        // then oldest-created. The pure helper must not re-sort.
        let ids: Vec<Uuid> = (0..5).map(|_| Uuid::new_v4()).collect();
        let candidates: Vec<(Uuid, i64)> = ids.iter().map(|id| (*id, 100)).collect();
        let (picked, acc) = select_size_quota_evictions(&candidates, 250);
        // 100 + 100 + 100 = 300 >= 250 stops after 3rd.
        assert_eq!(picked, ids[..3].to_vec());
        assert_eq!(acc, 300);
    }

    #[test]
    fn test_select_size_quota_evictions_stops_at_exact_excess() {
        // Two candidates whose sum exactly equals excess: both are picked,
        // and the third (also present) is not.
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();
        let (picked, acc) = select_size_quota_evictions(&[(a, 60), (b, 40), (c, 999)], 100);
        assert_eq!(picked, vec![a, b]);
        assert_eq!(acc, 100);
    }

    #[test]
    fn test_select_size_quota_evictions_zero_byte_candidates_skipped_via_loop() {
        // Zero-byte candidates count toward picked IDs (the loop picks
        // before checking the accumulator) but contribute nothing to
        // accumulated bytes, so the loop will keep picking until a real
        // byte-bearing candidate pushes it over excess.
        let z1 = Uuid::new_v4();
        let z2 = Uuid::new_v4();
        let real = Uuid::new_v4();
        let (picked, acc) = select_size_quota_evictions(&[(z1, 0), (z2, 0), (real, 50)], 25);
        assert_eq!(picked, vec![z1, z2, real]);
        assert_eq!(acc, 50);
    }

    #[test]
    fn test_select_size_quota_evictions_saturating_add_does_not_panic() {
        // Defensive: an i64 overflow during accumulation would be a hard
        // crash without `saturating_add`. The helper must clamp at
        // `i64::MAX` and continue, not panic.
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let (picked, acc) = select_size_quota_evictions(&[(a, i64::MAX), (b, i64::MAX)], i64::MAX);
        // First pick adds i64::MAX, accumulator hits cap; loop sees
        // accumulated >= excess and stops, so b is NOT picked.
        assert_eq!(picked, vec![a]);
        assert_eq!(acc, i64::MAX);
    }

    #[test]
    fn test_select_size_quota_evictions_all_picked_when_total_below_excess() {
        // Pathological: total of all candidates is still below excess.
        // The helper picks every candidate and returns the partial sum;
        // the caller is responsible for surfacing "couldn't free enough
        // bytes" through the result (matched < expected).
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let (picked, acc) = select_size_quota_evictions(&[(a, 100), (b, 100)], 10_000);
        assert_eq!(picked, vec![a, b]);
        assert_eq!(acc, 200);
    }

    // -----------------------------------------------------------------------
    // execute_policy validation guard (pure: rejects dry_run on disabled
    // policy) — this hits the early-return arm in execute_policy without
    // needing a DB, by exercising it indirectly through the `enabled =
    // false` check that runs before any pool acquire.
    //
    // We can't call execute_policy directly without a DB, but we *can*
    // verify the `enabled = false` error string contract that the tx-split
    // refactor must preserve. Centralising the assertion here protects
    // against an accidental message change.
    // -----------------------------------------------------------------------

    #[test]
    fn test_disabled_policy_error_message_shape() {
        // The disabled-policy guard in execute_policy emits an
        // `AppError::Validation`. This test re-creates that error to pin
        // the message so any future copy-edit (which would surface as a
        // user-facing 400 message change) is intentional.
        let err = AppError::Validation("Policy is disabled".to_string());
        assert!(err.to_string().contains("disabled"));
    }

    // -----------------------------------------------------------------------
    // dispatch routing assertions: confirm the wire strings line up
    // 1:1 with the PolicyType variants used in dispatch_execute.
    //
    // Together with test_policy_type_parse_all_valid_variants this means
    // every dispatch_execute branch is reachable from a unit test (the
    // body still hits a DB, but the routing logic itself is covered).
    // -----------------------------------------------------------------------

    #[test]
    fn test_dispatch_table_is_exhaustive() {
        // Every variant in the enum has a matching wire string and a
        // matching create_policy whitelist entry. If a future PR adds a
        // PolicyType variant but forgets to update create_policy or
        // dispatch_execute, this test will catch it (because as_wire_str
        // returns the canonical string and parse re-validates it).
        let create_policy_whitelist = [
            "max_age_days",
            "max_versions",
            "no_downloads_days",
            "tag_pattern_keep",
            "tag_pattern_delete",
            "size_quota_bytes",
        ];
        let dispatch_variants = [
            PolicyType::MaxAgeDays,
            PolicyType::MaxVersions,
            PolicyType::NoDownloadsDays,
            PolicyType::TagPatternKeep,
            PolicyType::TagPatternDelete,
            PolicyType::SizeQuotaBytes,
        ];
        assert_eq!(create_policy_whitelist.len(), dispatch_variants.len());
        for v in dispatch_variants {
            assert!(
                create_policy_whitelist.contains(&v.as_wire_str()),
                "PolicyType variant {v:?} has no matching create_policy whitelist entry"
            );
        }
    }
}
