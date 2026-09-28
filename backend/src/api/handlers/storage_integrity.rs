//! Admin storage-integrity endpoints: the storage scrub (#3910) and the
//! per-repository storage reindex that registers ghost objects (#1570).
//!
//! Mounted inside the `/api/v1/admin` block (routes.rs), so `admin_middleware`
//! gates every route; each handler re-checks `is_admin` as defense in depth,
//! like the storage-GC endpoints.

use axum::extract::{Extension, Path, Query, State};
use axum::{
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use utoipa::{IntoParams, OpenApi, ToSchema};

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::audit_export::Outcome;
use crate::services::audit_service::{
    audit_fire_and_forget, AuditAction, AuditEntry, ResourceType,
};
use crate::services::repository_service::RepositoryService;
use crate::services::storage_reindex_service::{StorageReindexResult, StorageReindexService};
use crate::services::storage_scrub_service::{
    ScrubFinding, ScrubObjectKind, ScrubOptions, ScrubResult, StorageScrubService,
};

#[derive(OpenApi)]
#[openapi(
    paths(
        run_storage_scrub,
        list_storage_scrub_findings,
        reindex_repository_storage
    ),
    components(schemas(
        StorageScrubRequest,
        ScrubResult,
        ScrubFinding,
        ScrubObjectKind,
        StorageReindexRequest,
        StorageReindexResult,
    ))
)]
pub struct StorageIntegrityApiDoc;

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/storage-scrub", post(run_storage_scrub))
        .route("/storage-scrub/findings", get(list_storage_scrub_findings))
        .route(
            "/repositories/:key/reindex-storage",
            post(reindex_repository_storage),
        )
}

/// Hard ceilings on one admin-triggered scrub, whatever the request asks for.
const MAX_SCRUB_OBJECTS: u64 = 100_000;
const MAX_SCRUB_BYTES: u64 = 1 << 40; // 1 TiB

/// Request body for a storage scrub.
///
/// `repair` is **required** and unknown fields are rejected, following the
/// storage-GC request contract (#3501): the caller states whether the run may
/// write to storage.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct StorageScrubRequest {
    /// Restore a corrupt or missing object when another stored copy of the
    /// same digest re-hashes correctly. Without a verified copy the object is
    /// only reported; bytes are never overwritten with unverified data.
    pub repair: bool,
    /// Stop after this many objects (default: `STORAGE_SCRUB_MAX_OBJECTS`).
    #[serde(default)]
    pub max_objects: Option<u64>,
    /// Stop after reading this many bytes (default: `STORAGE_SCRUB_MAX_BYTES`).
    #[serde(default)]
    pub max_bytes: Option<u64>,
    /// Only scrub this repository (by key). A scoped run starts from the
    /// beginning of the repository and leaves the instance-wide cursor alone.
    #[serde(default)]
    pub repository: Option<String>,
}

/// Resolve the per-run budget: request override, else config default, both
/// clamped to the hard ceilings (never zero).
fn scrub_budget(requested: Option<u64>, default: u64, ceiling: u64) -> u64 {
    requested.unwrap_or(default).clamp(1, ceiling)
}

/// POST /api/v1/admin/storage-scrub
#[utoipa::path(
    post,
    path = "/storage-scrub",
    context_path = "/api/v1/admin",
    tag = "admin",
    operation_id = "run_storage_scrub",
    request_body = StorageScrubRequest,
    responses(
        (status = 200, description = "Scrub result", body = ScrubResult),
        (status = 404, description = "Repository not found"),
        (status = 409, description = "Another scrub is already running"),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn run_storage_scrub(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(payload): Json<StorageScrubRequest>,
) -> Result<Json<ScrubResult>> {
    require_admin(auth.is_admin)?;

    let repository_id = match payload.repository.as_deref() {
        Some(key) => Some(
            RepositoryService::new(state.db.clone())
                .get_by_key(key)
                .await?
                .id,
        ),
        None => None,
    };
    let opts = ScrubOptions {
        max_objects: scrub_budget(
            payload.max_objects,
            state.config.storage_scrub_max_objects,
            MAX_SCRUB_OBJECTS,
        ),
        max_bytes: scrub_budget(
            payload.max_bytes,
            state.config.storage_scrub_max_bytes,
            MAX_SCRUB_BYTES,
        ),
        repair: payload.repair,
        repository_id,
    };
    // Audit BEFORE the work starts: the /admin request timeout (120 s) can
    // drop this future mid-run, after objects were already repaired. The
    // guard records the outcome at the end — or "cancelled" when dropped.
    let audit = ScrubRunAudit::start(
        state.db.clone(),
        &auth,
        repository_id,
        serde_json::json!({
            "repair": opts.repair,
            "repository": payload.repository,
            "max_objects": opts.max_objects,
            "max_bytes": opts.max_bytes,
        }),
    )
    .await;
    let outcome = StorageScrubService::new(state.db.clone(), state.storage_registry.clone())
        .run(&opts)
        .await;
    audit.finish(&outcome);

    outcome.map(Json)
}

/// Start/end audit trail of one scrub run (#3910 review).
///
/// [`ScrubRunAudit::start`] writes a `phase: "started"` row (awaited, so it is
/// durable before any object is touched) carrying a `run_id`;
/// [`ScrubRunAudit::finish`] writes `completed` / `failed` with the counts.
/// If the run is dropped before `finish` (request timeout, client
/// disconnect), `Drop` writes a `cancelled` row for the same `run_id`, so a
/// run that repaired objects never goes unaudited.
pub(crate) struct ScrubRunAudit {
    db: sqlx::PgPool,
    user_id: uuid::Uuid,
    username: String,
    repository_id: Option<uuid::Uuid>,
    run_id: uuid::Uuid,
    params: serde_json::Value,
    finished: bool,
}

impl ScrubRunAudit {
    pub(crate) async fn start(
        db: sqlx::PgPool,
        auth: &AuthExtension,
        repository_id: Option<uuid::Uuid>,
        params: serde_json::Value,
    ) -> Self {
        let audit = Self {
            db,
            user_id: auth.user_id,
            username: auth.username.clone(),
            repository_id,
            run_id: uuid::Uuid::new_v4(),
            params,
            finished: false,
        };
        let entry = audit.entry("started", serde_json::Value::Null);
        if let Err(e) = crate::services::audit_service::AuditService::new(audit.db.clone())
            .log(entry)
            .await
        {
            tracing::warn!(error = %e, "storage scrub start audit write failed");
        }
        audit
    }

    #[cfg(test)]
    pub(crate) fn run_id(&self) -> uuid::Uuid {
        self.run_id
    }

    fn entry(&self, phase: &str, extra: serde_json::Value) -> AuditEntry {
        let mut details = serde_json::json!({
            "run_id": self.run_id,
            "phase": phase,
            "params": self.params,
        });
        if !extra.is_null() {
            details["result"] = extra;
        }
        let mut entry = AuditEntry::new(AuditAction::StorageScrubRun, ResourceType::Setting)
            .user(self.user_id)
            .actor_name(&self.username)
            .details(details);
        if matches!(phase, "failed" | "cancelled") {
            entry = entry.outcome(Outcome::Failure);
        }
        if let Some(id) = self.repository_id {
            entry = entry.resource(id);
        }
        entry
    }

    fn spawn_log(&self, entry: AuditEntry) {
        let db = self.db.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                if let Err(e) = crate::services::audit_service::AuditService::new(db)
                    .log(entry)
                    .await
                {
                    tracing::warn!(error = %e, "storage scrub audit write failed");
                }
            });
        }
    }

    pub(crate) fn finish(mut self, outcome: &Result<ScrubResult>) {
        self.finished = true;
        let entry = match outcome {
            Ok(r) => self.entry(
                "completed",
                serde_json::json!({
                    "objects_checked": r.objects_checked,
                    "bytes_read": r.bytes_read,
                    "corrupt": r.corrupt,
                    "missing": r.missing,
                    "repaired": r.repaired,
                    "cycle_completed": r.cycle_completed,
                }),
            ),
            Err(e) => self.entry("failed", serde_json::json!({ "error": e.to_string() })),
        };
        self.spawn_log(entry);
    }
}

impl Drop for ScrubRunAudit {
    fn drop(&mut self) {
        if !self.finished {
            let entry = self.entry("cancelled", serde_json::Value::Null);
            self.spawn_log(entry);
        }
    }
}

/// Query for listing scrub findings.
#[derive(Debug, Deserialize, IntoParams)]
pub struct ScrubFindingsQuery {
    /// Filter by status: `corrupt`, `missing`, or `repaired`.
    pub status: Option<String>,
    /// Maximum rows (1-1000, default 100).
    pub limit: Option<i64>,
}

/// GET /api/v1/admin/storage-scrub/findings
#[utoipa::path(
    get,
    path = "/storage-scrub/findings",
    context_path = "/api/v1/admin",
    tag = "admin",
    operation_id = "list_storage_scrub_findings",
    params(ScrubFindingsQuery),
    responses(
        (status = 200, description = "Recorded scrub findings", body = Vec<ScrubFinding>),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn list_storage_scrub_findings(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Query(query): Query<ScrubFindingsQuery>,
) -> Result<Json<Vec<ScrubFinding>>> {
    require_admin(auth.is_admin)?;
    if let Some(s) = query.status.as_deref() {
        if !matches!(s, "corrupt" | "missing" | "repaired") {
            return Err(AppError::Validation(format!(
                "unknown status '{s}' (expected corrupt, missing, or repaired)"
            )));
        }
    }
    let findings = StorageScrubService::new(state.db.clone(), state.storage_registry.clone())
        .list_findings(query.status.as_deref(), query.limit.unwrap_or(100))
        .await?;
    Ok(Json(findings))
}

/// Default and ceiling for ghosts registered per reindex call.
const DEFAULT_REINDEX_LIMIT: u64 = 1_000;
const MAX_REINDEX_LIMIT: u64 = 10_000;

/// Request body for a storage reindex. `dry_run` is required and unknown
/// fields are rejected (the #3501 contract for write-capable admin calls).
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct StorageReindexRequest {
    /// Report what would be registered without writing any row.
    pub dry_run: bool,
    /// Register at most this many ghost objects in this call (default 1000,
    /// max 10000). `truncated` in the result says when more remain.
    #[serde(default)]
    pub limit: Option<u64>,
}

/// POST /api/v1/admin/repositories/{key}/reindex-storage
///
/// Registers artifact rows for objects stored in the repository's own key
/// namespace that have no row ("ghost artifacts", #1570), and reports live
/// rows whose object is missing. Maven and Gradle repositories only. Safe on
/// a live repository and idempotent: existing rows (live or soft-deleted) are
/// never touched.
#[utoipa::path(
    post,
    path = "/repositories/{key}/reindex-storage",
    context_path = "/api/v1/admin",
    tag = "admin",
    operation_id = "reindex_repository_storage",
    params(("key" = String, Path, description = "Repository key")),
    request_body = StorageReindexRequest,
    responses(
        (status = 200, description = "Reindex summary", body = StorageReindexResult),
        (status = 404, description = "Repository not found"),
        (status = 409, description = "A reindex of this repository is already running"),
        (status = 422, description = "Format or storage backend not supported"),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn reindex_repository_storage(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(key): Path<String>,
    Json(payload): Json<StorageReindexRequest>,
) -> Result<Json<StorageReindexResult>> {
    require_admin(auth.is_admin)?;
    let repo = RepositoryService::new(state.db.clone())
        .get_by_key(&key)
        .await?;
    let limit = scrub_budget(payload.limit, DEFAULT_REINDEX_LIMIT, MAX_REINDEX_LIMIT);
    let outcome = StorageReindexService::new(state.db.clone(), state.storage_registry.clone())
        .reindex(&repo, payload.dry_run, limit, Some(auth.user_id))
        .await;

    // Audited on success and on refusal/failure (409 lock held, 422 format or
    // backend unsupported, storage/DB errors).
    let details = match &outcome {
        Ok(result) => serde_json::json!({
            "repository": key,
            "dry_run": payload.dry_run,
            "scanned": result.scanned,
            "registered": result.registered,
            "skipped": result.skipped,
            "skipped_recent": result.skipped_recent,
            "skipped_unknown_age": result.skipped_unknown_age,
            "missing_objects": result.missing_objects,
            "errors": result.errors.len(),
        }),
        Err(e) => serde_json::json!({
            "repository": key,
            "dry_run": payload.dry_run,
            "error": e.to_string(),
        }),
    };
    let mut entry = AuditEntry::new(AuditAction::StorageReindexRun, ResourceType::Repository)
        .user(auth.user_id)
        .resource(repo.id)
        .actor_name(&auth.username)
        .details(details);
    if outcome.is_err() {
        entry = entry.outcome(Outcome::Failure);
    }
    audit_fire_and_forget(state.db.clone(), entry).await;

    outcome.map(Json)
}

fn require_admin(is_admin: bool) -> Result<()> {
    if is_admin {
        Ok(())
    } else {
        // 403: the caller is authenticated but not an admin (the /admin
        // block's admin_middleware answers the same).
        Err(AppError::Authorization(
            "Admin privileges required".to_string(),
        ))
    }
}

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_request_requires_repair_and_rejects_unknown_fields() {
        assert!(serde_json::from_str::<StorageScrubRequest>("{}").is_err());
        assert!(serde_json::from_str::<StorageScrubRequest>(r#"{"repair":false,"x":1}"#).is_err());
        let r: StorageScrubRequest =
            serde_json::from_str(r#"{"repair":true,"max_objects":5,"repository":"k"}"#).unwrap();
        assert!(r.repair);
        assert_eq!(r.max_objects, Some(5));
        assert_eq!(r.repository.as_deref(), Some("k"));
    }

    #[test]
    fn scrub_budget_clamps() {
        assert_eq!(scrub_budget(None, 500, 1000), 500);
        assert_eq!(scrub_budget(Some(0), 500, 1000), 1);
        assert_eq!(scrub_budget(Some(10_000), 500, 1000), 1000);
    }

    #[test]
    fn non_admin_is_refused() {
        assert!(matches!(
            require_admin(false),
            Err(AppError::Authorization(_))
        ));
        assert!(require_admin(true).is_ok());
    }

    #[test]
    fn openapi_doc_registers_scrub_paths() {
        let doc = StorageIntegrityApiDoc::openapi();
        assert!(doc.paths.paths.contains_key("/api/v1/admin/storage-scrub"));
        assert!(doc
            .paths
            .paths
            .contains_key("/api/v1/admin/storage-scrub/findings"));
    }

    /// Poll `audit_log` for the phases recorded under `run_id`.
    async fn scrub_audit_phases(
        pool: &sqlx::PgPool,
        run_id: uuid::Uuid,
        want: usize,
    ) -> Vec<String> {
        for _ in 0..50 {
            let phases: Vec<String> = sqlx::query_scalar(
                "SELECT details->>'phase' FROM audit_log \
                 WHERE action = 'STORAGE_SCRUB_RUN' AND details->>'run_id' = $1 \
                 ORDER BY created_at",
            )
            .bind(run_id.to_string())
            .fetch_all(pool)
            .await
            .expect("query audit_log");
            if phases.len() >= want {
                return phases;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        Vec::new()
    }

    async fn admin_auth(pool: &sqlx::PgPool) -> AuthExtension {
        let (user_id, username) = crate::api::handlers::test_db_helpers::create_user(pool).await;
        let mut auth = crate::api::handlers::test_db_helpers::make_auth(user_id, &username);
        auth.is_admin = true;
        auth
    }

    /// #3910 review (S-c): a scrub dropped mid-run (the 120 s /admin
    /// request timeout) must still leave an audit trail: the start row is
    /// written before any work, and the drop records `cancelled`.
    #[tokio::test]
    async fn scrub_audit_survives_a_dropped_run() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let auth = admin_auth(&pool).await;
        let audit = ScrubRunAudit::start(
            pool.clone(),
            &auth,
            None,
            serde_json::json!({"repair": true}),
        )
        .await;
        let run_id = audit.run_id();
        // The start row exists before the run does anything.
        let started = scrub_audit_phases(&pool, run_id, 1).await;
        drop(audit); // the handler future was dropped mid-run
        let phases = scrub_audit_phases(&pool, run_id, 2).await;
        assert_eq!(started, vec!["started".to_string()]);
        assert_eq!(phases, vec!["started".to_string(), "cancelled".to_string()]);
    }

    /// A run that finishes records `completed` (with its counts) and no
    /// `cancelled` row.
    #[tokio::test]
    async fn scrub_audit_records_completion_once() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let auth = admin_auth(&pool).await;
        let audit = ScrubRunAudit::start(pool.clone(), &auth, None, serde_json::json!({})).await;
        let run_id = audit.run_id();
        audit.finish(&Ok(ScrubResult {
            repaired: 2,
            ..Default::default()
        }));
        let phases = scrub_audit_phases(&pool, run_id, 2).await;
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let again = scrub_audit_phases(&pool, run_id, 2).await;
        let repaired: Option<String> = sqlx::query_scalar(
            "SELECT details->'result'->>'repaired' FROM audit_log \
             WHERE details->>'run_id' = $1 AND details->>'phase' = 'completed'",
        )
        .bind(run_id.to_string())
        .fetch_optional(&pool)
        .await
        .unwrap();
        assert_eq!(phases, vec!["started".to_string(), "completed".to_string()]);
        assert_eq!(again.len(), 2, "no extra cancelled row: {again:?}");
        assert_eq!(repaired.as_deref(), Some("2"));
    }

    /// A failed run (e.g. 409 lock held) is recorded as `failed`.
    #[tokio::test]
    async fn scrub_audit_records_failure() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let auth = admin_auth(&pool).await;
        let audit = ScrubRunAudit::start(pool.clone(), &auth, None, serde_json::json!({})).await;
        let run_id = audit.run_id();
        audit.finish(&Err(AppError::Conflict("busy".into())));
        let phases = scrub_audit_phases(&pool, run_id, 2).await;
        assert_eq!(phases, vec!["started".to_string(), "failed".to_string()]);
    }

    #[test]
    fn reindex_request_requires_dry_run() {
        assert!(serde_json::from_str::<StorageReindexRequest>("{}").is_err());
        assert!(serde_json::from_str::<StorageReindexRequest>(r#"{"dryRun":true}"#).is_err());
        let r: StorageReindexRequest =
            serde_json::from_str(r#"{"dry_run":false,"limit":3}"#).unwrap();
        assert!(!r.dry_run);
        assert_eq!(r.limit, Some(3));
    }

    #[test]
    fn openapi_doc_registers_reindex_path() {
        let doc = StorageIntegrityApiDoc::openapi();
        assert!(doc
            .paths
            .paths
            .contains_key("/api/v1/admin/repositories/{key}/reindex-storage"));
    }

    #[test]
    fn router_builds() {
        let _ = router();
    }
}
