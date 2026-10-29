//! Admin storage-integrity endpoints: the storage scrub (#3910), the
//! per-repository storage reindex that registers ghost objects (#1570), and
//! the source-free Debian package backfill (#4740).
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
use crate::services::audit_service::{AuditAction, AuditEntry, ResourceType};
use crate::services::debian_backfill_service::{DebianBackfillResult, DebianBackfillService};
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
        reindex_repository_storage,
        backfill_debian_packages
    ),
    components(schemas(
        StorageScrubRequest,
        ScrubResult,
        ScrubFinding,
        ScrubObjectKind,
        StorageReindexRequest,
        StorageReindexResult,
        DebianBackfillRequest,
        DebianBackfillResult,
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
        .route(
            "/repositories/:key/backfill-debian",
            post(backfill_debian_packages),
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
        Some(key) => match RepositoryService::new(state.db.clone())
            .get_by_key(key)
            .await
        {
            Ok(repo) => Some(repo.id),
            Err(e) => {
                // #4323: a refused run is audited like any other, so an
                // admin probing repository keys leaves a trail.
                let audit = ScrubRunAudit::start(
                    state.db.clone(),
                    &auth,
                    None,
                    serde_json::json!({ "repair": payload.repair, "repository": key }),
                )
                .await;
                // Audit the lookup's own error (a 404, or a database
                // failure), then answer it.
                let refused: Result<ScrubResult> = Err(e);
                audit.finish(&refused);
                return refused.map(Json);
            }
        },
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
    let limit = scrub_budget(payload.limit, DEFAULT_REINDEX_LIMIT, MAX_REINDEX_LIMIT);
    let params = serde_json::json!({
        "repository": key,
        "dry_run": payload.dry_run,
        "limit": limit,
    });
    let repo = match RepositoryService::new(state.db.clone())
        .get_by_key(&key)
        .await
    {
        Ok(repo) => repo,
        Err(e) => {
            // An unknown key (or a lookup failure) is audited like the
            // scrub's refusals, so probing repository keys leaves a trail.
            let audit = RepairRunAudit::start(
                state.db.clone(),
                &auth,
                AuditAction::StorageReindexRun,
                None,
                params,
            )
            .await;
            audit.finish(Err(&e));
            return Err(e);
        }
    };

    // Audit BEFORE the work starts: the /admin request timeout can drop this
    // future after rows were already registered. The guard records the
    // outcome at the end, or `cancelled` when dropped.
    let audit = RepairRunAudit::start(
        state.db.clone(),
        &auth,
        AuditAction::StorageReindexRun,
        Some(repo.id),
        params,
    )
    .await;
    let outcome = StorageReindexService::new(state.db.clone(), state.storage_registry.clone())
        .reindex(&repo, payload.dry_run, limit, Some(auth.user_id))
        .await;

    // Recorded on success and on refusal/failure (409 lock held, 422 format or
    // backend unsupported, storage/DB errors).
    match &outcome {
        Ok(result) => audit.finish(Ok(serde_json::json!({
            "scanned": result.scanned,
            "registered": result.registered,
            "skipped": result.skipped,
            "skipped_recent": result.skipped_recent,
            "skipped_unknown_age": result.skipped_unknown_age,
            "missing_objects": result.missing_objects,
            "errors": result.errors.len(),
        }))),
        Err(e) => audit.finish(Err(e)),
    }

    outcome.map(Json)
}

/// Default and ceiling for packages examined per Debian backfill call.
const DEFAULT_DEBIAN_BACKFILL_LIMIT: u64 = 1_000;
const MAX_DEBIAN_BACKFILL_LIMIT: u64 = 10_000;

/// Request body for the source-free Debian backfill. `dry_run` is required
/// and unknown fields are rejected (the #3501 contract for write-capable
/// admin calls).
#[derive(Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct DebianBackfillRequest {
    /// Report what would be registered and removed without writing anything.
    pub dry_run: bool,
    /// Examine at most this many candidate packages in this call (default
    /// 1000, max 10000). `truncated` says when more remain.
    #[serde(default)]
    pub limit: Option<u64>,
    /// Continue a truncated walk: the `next_after` of the previous call.
    #[serde(default)]
    #[schema(value_type = Option<String>, format = Uuid)]
    pub after: Option<uuid::Uuid>,
}

/// POST /api/v1/admin/repositories/{key}/backfill-debian
///
/// Repairs a hosted Debian repository migrated before #4657 without the
/// source system: walks live `.deb` rows that have no `debian` control
/// document, reads the `control.tar` member from the repository's own
/// storage, and records the same control document, catalog row, and
/// maintainer-script analysis a native upload writes. A package outside
/// `pool/<component>/` (`pool/<file>.deb`, a `pool/<letter>/<name>/` layout)
/// is moved under `pool/main/`, as the migration importer now files it.
/// Migration-origin `dists/` index copies are removed from the artifact list.
/// Idempotent and safe on a live repository.
#[utoipa::path(
    post,
    path = "/repositories/{key}/backfill-debian",
    context_path = "/api/v1/admin",
    tag = "admin",
    operation_id = "backfill_debian_packages",
    params(("key" = String, Path, description = "Repository key")),
    request_body = DebianBackfillRequest,
    responses(
        (status = 200, description = "Backfill summary", body = DebianBackfillResult),
        (status = 404, description = "Repository not found"),
        (status = 409, description = "A backfill of this repository is already running"),
        (status = 422, description = "Repository is not a hosted Debian repository"),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn backfill_debian_packages(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(key): Path<String>,
    Json(payload): Json<DebianBackfillRequest>,
) -> Result<Json<DebianBackfillResult>> {
    require_admin(auth.is_admin)?;
    let limit = scrub_budget(
        payload.limit,
        DEFAULT_DEBIAN_BACKFILL_LIMIT,
        MAX_DEBIAN_BACKFILL_LIMIT,
    );
    let params = serde_json::json!({
        "repository": key,
        "dry_run": payload.dry_run,
        "limit": limit,
        "after": payload.after,
    });
    let repo = match RepositoryService::new(state.db.clone())
        .get_by_key(&key)
        .await
    {
        Ok(repo) => repo,
        Err(e) => {
            let audit = RepairRunAudit::start(
                state.db.clone(),
                &auth,
                AuditAction::DebianBackfillRun,
                None,
                params,
            )
            .await;
            audit.finish(Err(&e));
            return Err(e);
        }
    };

    // Audit BEFORE the work starts (see reindex_repository_storage).
    let audit = RepairRunAudit::start(
        state.db.clone(),
        &auth,
        AuditAction::DebianBackfillRun,
        Some(repo.id),
        params,
    )
    .await;
    let outcome = DebianBackfillService::new(state.db.clone(), state.storage_registry.clone())
        .backfill(&repo, payload.dry_run, limit, payload.after)
        .await;

    // Recorded on success and on refusal/failure (409 lock held, 422 the
    // wrong repository kind, storage/DB errors).
    match &outcome {
        Ok(result) => audit.finish(Ok(serde_json::json!({
            "artifacts_scanned": result.artifacts_scanned,
            "packages_registered": result.packages_registered,
            "packages_relocated": result.packages_relocated,
            "artifacts_skipped": result.artifacts_skipped,
            "artifacts_failed": result.artifacts_failed,
            "dists_removed": result.dists_removed,
            "truncated": result.truncated,
            "next_after": result.next_after,
            "errors": result.errors.len(),
        }))),
        Err(e) => audit.finish(Err(e)),
    }

    outcome.map(Json)
}

/// Start/end audit trail of one admin repair run (reindex-storage,
/// backfill-debian), the same shape as [`ScrubRunAudit`].
///
/// [`RepairRunAudit::start`] writes a `phase: "started"` row (awaited, so it
/// is durable before any row or object is touched) carrying a `run_id` and
/// the request parameters; [`RepairRunAudit::finish`] writes `completed` with
/// the report counts or `failed` with the error. If the run is dropped before
/// `finish` (request timeout, client disconnect), `Drop` writes a `cancelled`
/// row for the same `run_id`.
///
/// Every row keeps the flat `details` layout these actions always had
/// (`repository`, `dry_run`, the counts or `error`), plus `run_id` and
/// `phase`.
pub(crate) struct RepairRunAudit {
    db: sqlx::PgPool,
    action: AuditAction,
    user_id: uuid::Uuid,
    username: String,
    repository_id: Option<uuid::Uuid>,
    run_id: uuid::Uuid,
    params: serde_json::Value,
    finished: bool,
}

impl RepairRunAudit {
    pub(crate) async fn start(
        db: sqlx::PgPool,
        auth: &AuthExtension,
        action: AuditAction,
        repository_id: Option<uuid::Uuid>,
        params: serde_json::Value,
    ) -> Self {
        let audit = Self {
            db,
            action,
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
            tracing::warn!(error = %e, "repair run start audit write failed");
        }
        audit
    }

    #[cfg(test)]
    pub(crate) fn run_id(&self) -> uuid::Uuid {
        self.run_id
    }

    fn entry(&self, phase: &str, extra: serde_json::Value) -> AuditEntry {
        let mut details = match &self.params {
            serde_json::Value::Object(map) => map.clone(),
            _ => serde_json::Map::new(),
        };
        if let serde_json::Value::Object(extra) = extra {
            details.extend(extra);
        }
        details.insert("run_id".into(), serde_json::json!(self.run_id));
        details.insert("phase".into(), serde_json::json!(phase));
        let mut entry = AuditEntry::new(self.action, ResourceType::Repository)
            .user(self.user_id)
            .actor_name(&self.username)
            .details(serde_json::Value::Object(details));
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
                    tracing::warn!(error = %e, "repair run audit write failed");
                }
            });
        }
    }

    /// Record the end of the run: `Ok(counts)` as `completed`, `Err` as
    /// `failed` with the error text.
    pub(crate) fn finish(mut self, outcome: std::result::Result<serde_json::Value, &AppError>) {
        self.finished = true;
        let entry = match outcome {
            Ok(counts) => self.entry("completed", counts),
            Err(e) => self.entry("failed", serde_json::json!({ "error": e.to_string() })),
        };
        self.spawn_log(entry);
    }
}

impl Drop for RepairRunAudit {
    fn drop(&mut self) {
        if !self.finished {
            let entry = self.entry("cancelled", serde_json::Value::Null);
            self.spawn_log(entry);
        }
    }
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
    use bytes::Bytes;

    use super::*;
    use crate::api::handlers::debian::minimal_deb;
    use crate::api::handlers::test_db_helpers as tdh;

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

    /// #4323: a scrub refused for an unknown repository key is audited too
    /// (started, then failed), not just answered 404.
    #[tokio::test]
    async fn scrub_of_an_unknown_repository_is_audited_4323() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let auth = admin_auth(&pool).await;
        let state = tdh::build_state(pool.clone(), "/tmp/ak-scrub-unknown-repo");
        let key = format!("no-such-repo-{}", uuid::Uuid::new_v4());
        let status = match run_storage_scrub(
            State(state),
            Extension(auth.clone()),
            Json(StorageScrubRequest {
                repair: false,
                repository: Some(key.clone()),
                max_objects: None,
                max_bytes: None,
            }),
        )
        .await
        {
            Ok(_) => axum::http::StatusCode::OK,
            Err(e) => axum::response::IntoResponse::into_response(e).status(),
        };
        let mut phases = Vec::new();
        for _ in 0..50 {
            phases = sqlx::query_scalar::<_, String>(
                "SELECT details->>'phase' FROM audit_log \
                 WHERE action = 'STORAGE_SCRUB_RUN' AND details->'params'->>'repository' = $1 \
                 ORDER BY created_at",
            )
            .bind(&key)
            .fetch_all(&pool)
            .await
            .expect("audit rows");
            if phases.len() >= 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(auth.user_id)
            .execute(&pool)
            .await;
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND);
        assert_eq!(phases, vec!["started".to_string(), "failed".to_string()]);
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
    fn debian_backfill_request_requires_dry_run() {
        assert!(serde_json::from_str::<DebianBackfillRequest>("{}").is_err());
        assert!(serde_json::from_str::<DebianBackfillRequest>(r#"{"dryRun":true}"#).is_err());
        let r: DebianBackfillRequest =
            serde_json::from_str(r#"{"dry_run":true,"limit":3}"#).unwrap();
        assert!(r.dry_run);
        assert_eq!(r.limit, Some(3));
    }

    #[test]
    fn openapi_doc_registers_debian_backfill_path() {
        let doc = StorageIntegrityApiDoc::openapi();
        assert!(doc
            .paths
            .paths
            .contains_key("/api/v1/admin/repositories/{key}/backfill-debian"));
    }

    /// Poll for the backfill's audit row: `audit_fire_and_forget` runs in a
    /// detached task, so the handler can return first.
    async fn debian_backfill_audit(
        pool: &sqlx::PgPool,
        repo_key: &str,
    ) -> Option<serde_json::Value> {
        for _ in 0..50 {
            let details: Option<serde_json::Value> = sqlx::query_scalar(
                "SELECT details FROM audit_log \
                 WHERE action = 'DEBIAN_BACKFILL_RUN' AND details->>'repository' = $1 \
                   AND details->>'phase' IN ('completed', 'failed') \
                 ORDER BY created_at DESC LIMIT 1",
            )
            .bind(repo_key)
            .fetch_optional(pool)
            .await
            .expect("query audit_log");
            if details.is_some() {
                return details;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        None
    }

    /// The admin route wires the service, clamps the limit, records the audit
    /// row, and still refuses non-admins.
    #[tokio::test]
    async fn debian_backfill_endpoint_registers_and_audits() {
        let Some(f) = tdh::Fixture::setup("local", "debian").await else {
            return;
        };
        let auth = admin_auth(&f.pool).await;
        let path = "pool/main/h/hello/hello_9.0_amd64.deb";
        let storage_key = format!("backfill-endpoint-{}", uuid::Uuid::new_v4());
        tdh::seed_artifact(
            &f.state,
            &f.pool,
            &f.repo_info("local", None),
            &storage_key,
            path,
            "hello",
            "9.0",
            "application/vnd.debian.binary-package",
            Bytes::from(minimal_deb("hello", "9.0", "amd64", "endpoint")),
            f.user_id,
        )
        .await;

        let result = backfill_debian_packages(
            State(f.state.clone()),
            Extension(auth.clone()),
            Path(f.repo_key.clone()),
            Json(DebianBackfillRequest {
                dry_run: false,
                limit: Some(10),
                after: None,
            }),
        )
        .await
        .expect("backfill handler succeeds");
        assert_eq!(result.0.packages_registered, 1);

        let details = debian_backfill_audit(&f.pool, &f.repo_key)
            .await
            .expect("backfill audit row");
        assert_eq!(details["repository"], f.repo_key);
        assert_eq!(details["packages_registered"], 1);
        assert_eq!(details["dry_run"], false);
        assert_eq!(details["phase"], "completed");
        // #5078: the start row was written under the same run_id.
        let run_id = details["run_id"].as_str().expect("run_id").to_string();
        let phases = repair_audit_phases(&f.pool, "DEBIAN_BACKFILL_RUN", &run_id, 2).await;
        assert_eq!(phases, vec!["started".to_string(), "completed".to_string()]);

        let mut non_admin = auth;
        non_admin.is_admin = false;
        let err = backfill_debian_packages(
            State(f.state.clone()),
            Extension(non_admin),
            Path(f.repo_key.clone()),
            Json(DebianBackfillRequest {
                dry_run: true,
                limit: Some(10),
                after: None,
            }),
        )
        .await
        .expect_err("a non-admin is refused");
        assert!(matches!(err, AppError::Authorization(_)));

        f.teardown().await;
    }

    /// A validation failure is audited with the error and reaches the caller.
    #[tokio::test]
    async fn debian_backfill_endpoint_audits_validation_failure() {
        let Some(f) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let auth = admin_auth(&f.pool).await;
        let err = backfill_debian_packages(
            State(f.state.clone()),
            Extension(auth),
            Path(f.repo_key.clone()),
            Json(DebianBackfillRequest {
                dry_run: true,
                limit: Some(10),
                after: None,
            }),
        )
        .await
        .expect_err("a generic repository is refused");
        assert!(matches!(err, AppError::UnprocessableEntity(_)));

        let details = debian_backfill_audit(&f.pool, &f.repo_key)
            .await
            .expect("failed backfill audit row");
        assert_eq!(details["repository"], f.repo_key);
        assert!(details["error"]
            .as_str()
            .expect("error detail")
            .contains("Debian repositories"));

        f.teardown().await;
    }

    /// Poll `audit_log` for the phases one repair run recorded.
    async fn repair_audit_phases(
        pool: &sqlx::PgPool,
        action: &str,
        run_id: &str,
        want: usize,
    ) -> Vec<String> {
        let mut phases = Vec::new();
        for _ in 0..50 {
            phases = sqlx::query_scalar(
                "SELECT details->>'phase' FROM audit_log \
                 WHERE action = $1 AND details->>'run_id' = $2 \
                 ORDER BY created_at",
            )
            .bind(action)
            .bind(run_id)
            .fetch_all(pool)
            .await
            .expect("query audit_log");
            if phases.len() >= want {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        phases
    }

    /// #5078: a repair run dropped mid-way (the /admin request timeout, a
    /// client disconnect) still leaves an audit trail: the start row exists
    /// before any work, and the drop records `cancelled`, both carrying the
    /// request parameters in the flat layout these actions use.
    #[tokio::test]
    async fn repair_audit_survives_a_dropped_run_5078() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let auth = admin_auth(&pool).await;
        for (action, name) in [
            (AuditAction::StorageReindexRun, "STORAGE_REINDEX_RUN"),
            (AuditAction::DebianBackfillRun, "DEBIAN_BACKFILL_RUN"),
        ] {
            let audit = RepairRunAudit::start(
                pool.clone(),
                &auth,
                action,
                None,
                serde_json::json!({"repository": "r", "dry_run": false, "limit": 5}),
            )
            .await;
            let run_id = audit.run_id().to_string();
            let started = repair_audit_phases(&pool, name, &run_id, 1).await;
            assert_eq!(started, vec!["started".to_string()], "{name}");
            drop(audit);
            let phases = repair_audit_phases(&pool, name, &run_id, 2).await;
            assert_eq!(
                phases,
                vec!["started".to_string(), "cancelled".to_string()],
                "{name}"
            );
            let details: serde_json::Value = sqlx::query_scalar(
                "SELECT details FROM audit_log \
                 WHERE details->>'run_id' = $1 AND details->>'phase' = 'cancelled'",
            )
            .bind(&run_id)
            .fetch_one(&pool)
            .await
            .expect("cancelled row");
            assert_eq!(details["repository"], "r");
            assert_eq!(details["dry_run"], false);
            assert_eq!(details["limit"], 5);
        }
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(auth.user_id)
            .execute(&pool)
            .await;
    }

    /// #5078: a finished repair run records `completed` with its counts
    /// merged into the flat details, and no `cancelled` row.
    #[tokio::test]
    async fn repair_audit_records_completion_once_5078() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let auth = admin_auth(&pool).await;
        let audit = RepairRunAudit::start(
            pool.clone(),
            &auth,
            AuditAction::StorageReindexRun,
            None,
            serde_json::json!({"repository": "r", "dry_run": true}),
        )
        .await;
        let run_id = audit.run_id().to_string();
        audit.finish(Ok(serde_json::json!({"registered": 3})));
        let phases = repair_audit_phases(&pool, "STORAGE_REINDEX_RUN", &run_id, 2).await;
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let again = repair_audit_phases(&pool, "STORAGE_REINDEX_RUN", &run_id, 2).await;
        let details: serde_json::Value = sqlx::query_scalar(
            "SELECT details FROM audit_log \
             WHERE details->>'run_id' = $1 AND details->>'phase' = 'completed'",
        )
        .bind(&run_id)
        .fetch_one(&pool)
        .await
        .expect("completed row");
        assert_eq!(phases, vec!["started".to_string(), "completed".to_string()]);
        assert_eq!(again.len(), 2, "no extra cancelled row: {again:?}");
        assert_eq!(details["registered"], 3);
        assert_eq!(details["repository"], "r");
        assert_eq!(details["dry_run"], true);
    }

    /// #5078: a repair call for an unknown repository key is audited
    /// (started, then failed) for both endpoints, not just answered 404.
    #[tokio::test]
    async fn repair_of_an_unknown_repository_is_audited_5078() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let auth = admin_auth(&pool).await;
        let state = tdh::build_state(pool.clone(), "/tmp/ak-repair-unknown-repo");
        let reindex_key = format!("no-such-repo-{}", uuid::Uuid::new_v4());
        let err = reindex_repository_storage(
            State(state.clone()),
            Extension(auth.clone()),
            Path(reindex_key.clone()),
            Json(StorageReindexRequest {
                dry_run: true,
                limit: None,
            }),
        )
        .await
        .expect_err("unknown key");
        assert!(matches!(err, AppError::NotFound(_)), "{err:?}");
        let backfill_key = format!("no-such-repo-{}", uuid::Uuid::new_v4());
        let err = backfill_debian_packages(
            State(state),
            Extension(auth.clone()),
            Path(backfill_key.clone()),
            Json(DebianBackfillRequest {
                dry_run: true,
                limit: None,
                after: None,
            }),
        )
        .await
        .expect_err("unknown key");
        assert!(matches!(err, AppError::NotFound(_)), "{err:?}");

        for (action, key) in [
            ("STORAGE_REINDEX_RUN", &reindex_key),
            ("DEBIAN_BACKFILL_RUN", &backfill_key),
        ] {
            let mut phases = Vec::new();
            for _ in 0..50 {
                phases = sqlx::query_scalar::<_, String>(
                    "SELECT details->>'phase' FROM audit_log \
                     WHERE action = $1 AND details->>'repository' = $2 \
                     ORDER BY created_at",
                )
                .bind(action)
                .bind(key)
                .fetch_all(&pool)
                .await
                .expect("audit rows");
                if phases.len() >= 2 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            assert_eq!(
                phases,
                vec!["started".to_string(), "failed".to_string()],
                "{action}"
            );
        }
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(auth.user_id)
            .execute(&pool)
            .await;
    }

    #[test]
    fn router_builds() {
        let _ = router();
    }
}
