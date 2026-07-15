//! Curation API handler: manage curation rules and package approvals.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::handlers::repositories::require_repo_id_visible;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::AppError;
use crate::services::audit_service::{AuditAction, AuditEntry, AuditService, ResourceType};
use crate::services::curation_service::CurationService;
use crate::services::repository_service::RepositoryService;

#[derive(OpenApi)]
#[openapi(
    paths(
        list_rules,
        create_rule,
        get_rule,
        update_rule,
        delete_rule,
        list_packages,
        get_package,
        approve_package,
        block_package,
        bulk_approve,
        bulk_block,
        re_evaluate,
        trigger_sync,
        search_packages,
        stats,
    ),
    components(schemas(
        CreateRuleRequest,
        UpdateRuleRequest,
        RuleResponse,
        CurationPackageResponse,
        BulkStatusRequest,
        PackageListQuery,
        PackageSearchQuery,
        SyncTriggerResponse,
        ReEvaluateRequest,
        StatsResponse,
        StatusCount,
        StatsQuery,
    ))
)]
pub struct CurationApiDoc;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Rules
        .route("/rules", get(list_rules).post(create_rule))
        .route(
            "/rules/:id",
            get(get_rule).put(update_rule).delete(delete_rule),
        )
        // Packages
        .route("/packages", get(list_packages))
        .route("/packages/:id", get(get_package))
        .route("/packages/:id/approve", post(approve_package))
        .route("/packages/:id/block", post(block_package))
        .route("/packages/bulk-approve", post(bulk_approve))
        .route("/packages/bulk-block", post(bulk_block))
        .route("/packages/re-evaluate", post(re_evaluate))
        // Per-repo manual sync trigger (#2357 WI-5) + package search (WI-6)
        .route("/repos/:repo_key/sync", post(trigger_sync))
        .route("/repos/:repo_key/packages/search", get(search_packages))
        // Stats
        .route("/stats", get(stats))
}

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
#[schema(as = CurationCreateRuleRequest)]
pub struct CreateRuleRequest {
    pub staging_repo_id: Option<Uuid>,
    pub package_pattern: String,
    #[serde(default = "default_wildcard")]
    pub version_constraint: String,
    #[serde(default = "default_wildcard")]
    pub architecture: String,
    pub action: String,
    #[serde(default = "default_priority")]
    pub priority: i32,
    pub reason: String,
}

fn default_wildcard() -> String {
    "*".to_string()
}

fn default_priority() -> i32 {
    100
}

#[derive(Debug, Deserialize, ToSchema)]
#[schema(as = CurationUpdateRuleRequest)]
pub struct UpdateRuleRequest {
    pub package_pattern: String,
    #[serde(default = "default_wildcard")]
    pub version_constraint: String,
    #[serde(default = "default_wildcard")]
    pub architecture: String,
    pub action: String,
    #[serde(default = "default_priority")]
    pub priority: i32,
    pub reason: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RuleResponse {
    pub id: Uuid,
    pub staging_repo_id: Option<Uuid>,
    pub package_pattern: String,
    pub version_constraint: String,
    pub architecture: String,
    pub action: String,
    pub priority: i32,
    pub reason: String,
    pub enabled: bool,
    pub created_by: Option<Uuid>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CurationPackageResponse {
    pub id: Uuid,
    pub staging_repo_id: Uuid,
    pub remote_repo_id: Uuid,
    pub format: String,
    pub package_name: String,
    pub version: String,
    pub release: Option<String>,
    pub architecture: Option<String>,
    pub checksum_sha256: Option<String>,
    pub upstream_path: String,
    pub status: String,
    pub evaluated_at: Option<String>,
    pub evaluated_by: Option<Uuid>,
    pub evaluation_reason: Option<String>,
    pub rule_id: Option<Uuid>,
    #[schema(value_type = Object)]
    pub metadata: serde_json::Value,
    pub first_seen_at: String,
}

#[derive(Debug, Deserialize, IntoParams, ToSchema)]
pub struct PackageListQuery {
    pub staging_repo_id: Uuid,
    pub status: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

fn default_limit() -> i64 {
    50
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BulkStatusRequest {
    pub ids: Vec<Uuid>,
    pub reason: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ReEvaluateRequest {
    pub staging_repo_id: Uuid,
    pub default_action: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct StatsResponse {
    pub staging_repo_id: Uuid,
    pub counts: Vec<StatusCount>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct StatusCount {
    pub status: String,
    pub count: i64,
}

#[derive(Debug, Deserialize, IntoParams, ToSchema)]
pub struct StatsQuery {
    pub staging_repo_id: Uuid,
}

#[derive(Debug, Deserialize, IntoParams, ToSchema)]
pub struct PackageSearchQuery {
    /// Case-insensitive substring match on the package name.
    pub q: Option<String>,
    /// Exact architecture filter (e.g. `x86_64`, `noarch`).
    pub arch: Option<String>,
    /// Curation status filter (e.g. `approved`, `pending`, `blocked`, `review`).
    pub status: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: i64,
    #[serde(default)]
    pub offset: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SyncTriggerResponse {
    /// The repository key the sync was triggered for.
    pub repository: String,
    /// Always true when the trigger was accepted and a sync pass ran.
    pub triggered: bool,
    /// Whether the sync pass completed without error. A false value with
    /// `triggered = true` means the pass ran but an upstream fetch/verify step
    /// failed for the repo (details are in the server logs, not this response).
    pub succeeded: bool,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/curation/rules",
    operation_id = "list_curation_rules",
    params(("staging_repo_id" = Option<Uuid>, Query, description = "Filter by staging repo")),
    responses((status = 200, body = Vec<RuleResponse>)),
    tag = "Curation"
)]
async fn list_rules(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<Json<Vec<RuleResponse>>, AppError> {
    let svc = CurationService::new(state.db.clone());
    let repo_id = params.get("staging_repo_id").and_then(|s| s.parse().ok());
    // Cross-repo authorization (#2443): curation rules expose the private
    // staging repo's package-gating policy. Filtered by staging repo → gate on
    // that repo's visibility; unfiltered spans every repo → admin-only.
    match repo_id {
        Some(id) => require_repo_id_visible(&state.db, &auth, id, "Repository not found").await?,
        None => auth.require_admin()?,
    }
    let rules = svc.list_rules(repo_id).await?;
    Ok(Json(rules.into_iter().map(rule_to_response).collect()))
}

#[utoipa::path(
    post,
    path = "/api/v1/curation/rules",
    operation_id = "create_curation_rule",
    request_body = CreateRuleRequest,
    responses((status = 201, body = RuleResponse)),
    tag = "Curation"
)]
async fn create_rule(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(req): Json<CreateRuleRequest>,
) -> Result<(StatusCode, Json<RuleResponse>), AppError> {
    auth.require_admin()?;
    let svc = CurationService::new(state.db.clone());
    let rule = svc
        .create_rule(
            req.staging_repo_id,
            &req.package_pattern,
            &req.version_constraint,
            &req.architecture,
            &req.action,
            req.priority,
            &req.reason,
            auth.user_id,
        )
        .await?;
    Ok((StatusCode::CREATED, Json(rule_to_response(rule))))
}

#[utoipa::path(
    get,
    path = "/api/v1/curation/rules/{id}",
    operation_id = "get_curation_rule",
    params(("id" = Uuid, Path, description = "Rule ID")),
    responses(
        (status = 200, body = RuleResponse),
        (status = 404, description = "Rule not found")
    ),
    tag = "Curation"
)]
async fn get_rule(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<RuleResponse>, AppError> {
    let svc = CurationService::new(state.db.clone());
    let rule = svc.get_rule(id).await?;
    // Cross-repo authorization (#2443): a curation rule discloses its staging
    // repo id plus the package/version/arch patterns, action, priority, reason
    // and author. Resolve the rule's staging repo and gate before returning it.
    // A caller who cannot see the staging repo gets the SAME 404 as a missing
    // rule so the id is not a cross-tenant existence oracle. A global rule
    // (NULL staging repo) is org-wide config, so it is admin-only — mirroring
    // the unfiltered `list_rules` aggregate.
    match rule.staging_repo_id {
        Some(repo_id) => {
            require_repo_id_visible(&state.db, &auth, repo_id, "Curation rule not found").await?
        }
        None => auth.require_admin()?,
    }
    Ok(Json(rule_to_response(rule)))
}

#[utoipa::path(
    put,
    path = "/api/v1/curation/rules/{id}",
    operation_id = "update_curation_rule",
    request_body = UpdateRuleRequest,
    params(("id" = Uuid, Path, description = "Rule ID")),
    responses((status = 200, body = RuleResponse)),
    tag = "Curation"
)]
async fn update_rule(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateRuleRequest>,
) -> Result<Json<RuleResponse>, AppError> {
    auth.require_admin()?;
    let svc = CurationService::new(state.db.clone());
    let rule = svc
        .update_rule(
            id,
            &req.package_pattern,
            &req.version_constraint,
            &req.architecture,
            &req.action,
            req.priority,
            &req.reason,
            req.enabled,
        )
        .await?;
    Ok(Json(rule_to_response(rule)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/curation/rules/{id}",
    operation_id = "delete_curation_rule",
    params(("id" = Uuid, Path, description = "Rule ID")),
    responses((status = 204)),
    tag = "Curation"
)]
async fn delete_rule(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    auth.require_admin()?;
    let svc = CurationService::new(state.db.clone());
    svc.delete_rule(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/api/v1/curation/packages",
    operation_id = "list_curation_packages",
    params(PackageListQuery),
    responses((status = 200, body = Vec<CurationPackageResponse>)),
    tag = "Curation"
)]
async fn list_packages(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Query(query): Query<PackageListQuery>,
) -> Result<Json<Vec<CurationPackageResponse>>, AppError> {
    // Cross-repo authorization (#2443): staged packages awaiting curation belong
    // to a private staging repo. Gate on that repo's visibility before listing.
    require_repo_id_visible(
        &state.db,
        &auth,
        query.staging_repo_id,
        "Repository not found",
    )
    .await?;
    let svc = CurationService::new(state.db.clone());
    let packages = svc
        .list_packages(
            query.staging_repo_id,
            query.status.as_deref(),
            query.limit,
            query.offset,
        )
        .await?;
    Ok(Json(packages.into_iter().map(pkg_to_response).collect()))
}

#[utoipa::path(
    get,
    path = "/api/v1/curation/packages/{id}",
    operation_id = "get_curation_package",
    params(("id" = Uuid, Path, description = "Package ID")),
    responses((status = 200, body = CurationPackageResponse)),
    tag = "Curation"
)]
async fn get_package(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<CurationPackageResponse>, AppError> {
    let svc = CurationService::new(state.db.clone());
    // Normalize the missing-package case to an existence-hiding 404 (the raw
    // `fetch_one` RowNotFound would otherwise surface as a 500) so it is
    // indistinguishable from the not-visible case gated below.
    let pkg = svc.get_package(id).await.map_err(|e| match e {
        sqlx::Error::RowNotFound => AppError::NotFound("Curation package not found".to_string()),
        other => AppError::from(other),
    })?;
    // Cross-repo authorization (#2443): resolve the package's staging repo and
    // gate before returning it. A caller who cannot see the staging repo gets
    // the SAME 404 as a missing package so the id is not an existence oracle.
    require_repo_id_visible(
        &state.db,
        &auth,
        pkg.staging_repo_id,
        "Curation package not found",
    )
    .await?;
    Ok(Json(pkg_to_response(pkg)))
}

#[utoipa::path(
    post,
    path = "/api/v1/curation/packages/{id}/approve",
    params(("id" = Uuid, Path, description = "Package ID")),
    responses((status = 200, body = CurationPackageResponse)),
    tag = "Curation"
)]
async fn approve_package(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<CurationPackageResponse>, AppError> {
    auth.require_admin()?;
    let svc = CurationService::new(state.db.clone());
    let pkg = svc
        .set_package_status(
            id,
            "approved",
            "Manually approved",
            Some(auth.user_id),
            None,
        )
        .await?;
    Ok(Json(pkg_to_response(pkg)))
}

#[utoipa::path(
    post,
    path = "/api/v1/curation/packages/{id}/block",
    params(("id" = Uuid, Path, description = "Package ID")),
    responses((status = 200, body = CurationPackageResponse)),
    tag = "Curation"
)]
async fn block_package(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<CurationPackageResponse>, AppError> {
    auth.require_admin()?;
    let svc = CurationService::new(state.db.clone());
    let pkg = svc
        .set_package_status(id, "blocked", "Manually blocked", Some(auth.user_id), None)
        .await?;
    Ok(Json(pkg_to_response(pkg)))
}

#[utoipa::path(
    post,
    path = "/api/v1/curation/packages/bulk-approve",
    request_body = BulkStatusRequest,
    responses((status = 200, body = u64)),
    tag = "Curation"
)]
async fn bulk_approve(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(req): Json<BulkStatusRequest>,
) -> Result<Json<u64>, AppError> {
    auth.require_admin()?;
    let svc = CurationService::new(state.db.clone());
    let count = svc
        .bulk_set_status(&req.ids, "approved", &req.reason, Some(auth.user_id))
        .await?;
    Ok(Json(count))
}

#[utoipa::path(
    post,
    path = "/api/v1/curation/packages/bulk-block",
    request_body = BulkStatusRequest,
    responses((status = 200, body = u64)),
    tag = "Curation"
)]
async fn bulk_block(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(req): Json<BulkStatusRequest>,
) -> Result<Json<u64>, AppError> {
    auth.require_admin()?;
    let svc = CurationService::new(state.db.clone());
    let count = svc
        .bulk_set_status(&req.ids, "blocked", &req.reason, Some(auth.user_id))
        .await?;
    Ok(Json(count))
}

#[utoipa::path(
    post,
    path = "/api/v1/curation/packages/re-evaluate",
    request_body = ReEvaluateRequest,
    responses((status = 200, body = u64)),
    tag = "Curation"
)]
async fn re_evaluate(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(req): Json<ReEvaluateRequest>,
) -> Result<Json<u64>, AppError> {
    auth.require_admin()?;
    let svc = CurationService::new(state.db.clone());
    let count = svc
        .re_evaluate_pending(req.staging_repo_id, &req.default_action)
        .await?;
    Ok(Json(count))
}

// ---------------------------------------------------------------------------
// Manual sync trigger + package search (#2357)
// ---------------------------------------------------------------------------

/// Pure global-capability gate for the manual sync trigger (#2357 WI-5),
/// mirroring promotion's `ensure_promotion_authorized`: authorized when the
/// caller is an admin OR presents an API token carrying the admin-mintable
/// `trigger:sync` scope. Split out as a pure boolean so the decision is
/// unit-testable without a DB, and so a JWT/session user cannot acquire the
/// capability through the scope (the call site guards on `is_api_token`).
fn ensure_sync_authorized(is_admin: bool, has_sync_scope: bool) -> Result<(), AppError> {
    if !is_admin && !has_sync_scope {
        return Err(AppError::Authorization(
            "Only admins or tokens with the 'trigger:sync' scope can trigger a sync".to_string(),
        ));
    }
    Ok(())
}

/// Pure tenant-ownership decision for the manual sync trigger, mirroring
/// promotion's `promotion_tenant_access_allowed`: the admin capability flag does
/// NOT blanket-bypass tenancy. A genuine super-admin passes via a NULL-scoped
/// grant; a tenant-scoped admin is rejected for a repository in a tenant they do
/// not own. Public repositories carry no tenant boundary, so they always pass.
fn sync_tenant_access_allowed(repo_is_public: bool, has_repo_grant: bool) -> bool {
    repo_is_public || has_repo_grant
}

#[utoipa::path(
    post,
    path = "/api/v1/curation/repos/{repo_key}/sync",
    operation_id = "trigger_curation_sync",
    params(("repo_key" = String, Path, description = "Staging repository key")),
    responses(
        (status = 200, body = SyncTriggerResponse),
        (status = 403, description = "Not authorized to trigger a sync for this repo"),
        (status = 404, description = "Repository not found"),
    ),
    tag = "Curation"
)]
async fn trigger_sync(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(repo_key): Path<String>,
) -> Result<Json<SyncTriggerResponse>, AppError> {
    // Global capability (#2357 S5): admin, or an API token carrying the
    // admin-mintable `trigger:sync` scope. `has_scope` is true for JWT sessions,
    // so the `is_api_token` guard keeps a session user from gaining the
    // capability they were never granted — mirroring the promotion gate.
    let has_sync_scope = auth.is_api_token && auth.has_scope("trigger:sync");
    ensure_sync_authorized(auth.is_admin, has_sync_scope)?;

    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service
        .get_by_key(&repo_key)
        .await
        .map_err(|e| match e {
            AppError::NotFound(_) => AppError::NotFound("Repository not found".to_string()),
            other => other,
        })?;

    // Tenant-ownership gate (campaign-#4 systemic authz), enforced independently
    // of the admin flag. A repo-scoped admin cannot trigger a sync for a repo in
    // another tenant; a genuine super-admin passes via their NULL-scoped grant.
    // Deliberately NOT `require_repo_access` (weaker, see systemic-artifact-authz-gap).
    let has_grant = repo_service
        .user_can_access_repo(repo.id, auth.user_id)
        .await?;
    if !sync_tenant_access_allowed(repo.is_public, has_grant) {
        return Err(AppError::Authorization(format!(
            "You are not authorized to trigger a sync for the '{}' repository's tenant",
            repo.key
        )));
    }

    // Run one sync pass for this repo. The pass applies the bounded-decompress
    // (#2556) and GPG-verify-before-ingest (#2357 S4) hardening. Upstream errors
    // are logged and surfaced as `succeeded = false`, not propagated, so the
    // trigger's own outcome (accepted + audited) is deterministic.
    let sync_result =
        crate::services::scheduler_service::run_curation_sync_cycle(&state.db, Some(repo.id)).await;
    let succeeded = sync_result.is_ok();
    if let Err(ref e) = sync_result {
        tracing::warn!("Manual curation sync for repo {} failed: {}", repo.key, e);
    }

    // Audit (#2357 S7). Details carry only the repo key + outcome — never
    // upstream credentials or response text (WI-7). Fire-and-forget: an audit
    // write failure must not mask a completed sync trigger.
    let _ = AuditService::new(state.db.clone())
        .log(
            AuditEntry::new(AuditAction::CurationSyncTriggered, ResourceType::Repository)
                .user(auth.user_id)
                .resource(repo.id)
                .actor_name(auth.username.clone())
                .resource_name(repo.key.clone())
                .details(serde_json::json!({
                    "repo_key": repo.key,
                    "succeeded": succeeded,
                })),
        )
        .await;

    Ok(Json(SyncTriggerResponse {
        repository: repo.key,
        triggered: true,
        succeeded,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/curation/repos/{repo_key}/packages/search",
    operation_id = "search_curation_packages",
    params(
        ("repo_key" = String, Path, description = "Staging repository key"),
        PackageSearchQuery,
    ),
    responses(
        (status = 200, body = Vec<CurationPackageResponse>),
        (status = 404, description = "Repository not found or not visible"),
    ),
    tag = "Curation"
)]
async fn search_packages(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(repo_key): Path<String>,
    Query(query): Query<PackageSearchQuery>,
) -> Result<Json<Vec<CurationPackageResponse>>, AppError> {
    let repo_service = RepositoryService::new(state.db.clone());
    let repo = repo_service
        .get_by_key(&repo_key)
        .await
        .map_err(|e| match e {
            AppError::NotFound(_) => AppError::NotFound("Repository not found".to_string()),
            other => other,
        })?;
    // Tenant-scoped read gate (mirrors `list_packages`): a caller who cannot see
    // the staging repo gets an existence-hiding 404 (#2443), so the repo key is
    // not an existence oracle and cross-tenant search is refused.
    require_repo_id_visible(&state.db, &auth, repo.id, "Repository not found").await?;

    let limit = query.limit.clamp(1, 500);
    let offset = query.offset.max(0);
    let svc = CurationService::new(state.db.clone());
    let packages = svc
        .search_packages(
            repo.id,
            query.q.as_deref(),
            query.arch.as_deref(),
            query.status.as_deref(),
            limit,
            offset,
        )
        .await?;
    Ok(Json(packages.into_iter().map(pkg_to_response).collect()))
}

#[utoipa::path(
    get,
    path = "/api/v1/curation/stats",
    params(StatsQuery),
    responses((status = 200, body = StatsResponse)),
    tag = "Curation"
)]
async fn stats(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Query(query): Query<StatsQuery>,
) -> Result<Json<StatsResponse>, AppError> {
    // Cross-repo authorization (#2443): curation stats aggregate a private
    // staging repo's package pipeline. Gate on that repo's visibility first.
    require_repo_id_visible(
        &state.db,
        &auth,
        query.staging_repo_id,
        "Repository not found",
    )
    .await?;
    let svc = CurationService::new(state.db.clone());
    let counts = svc.count_by_status(query.staging_repo_id).await?;
    Ok(Json(StatsResponse {
        staging_repo_id: query.staging_repo_id,
        counts: counts
            .into_iter()
            .map(|(status, count)| StatusCount { status, count })
            .collect(),
    }))
}

// ---------------------------------------------------------------------------
// Converters
// ---------------------------------------------------------------------------

fn rule_to_response(rule: crate::models::curation::CurationRule) -> RuleResponse {
    RuleResponse {
        id: rule.id,
        staging_repo_id: rule.staging_repo_id,
        package_pattern: rule.package_pattern,
        version_constraint: rule.version_constraint,
        architecture: rule.architecture,
        action: rule.action,
        priority: rule.priority,
        reason: rule.reason,
        enabled: rule.enabled,
        created_by: rule.created_by,
        created_at: rule.created_at.to_rfc3339(),
        updated_at: rule.updated_at.to_rfc3339(),
    }
}

fn pkg_to_response(pkg: crate::models::curation::CurationPackage) -> CurationPackageResponse {
    CurationPackageResponse {
        id: pkg.id,
        staging_repo_id: pkg.staging_repo_id,
        remote_repo_id: pkg.remote_repo_id,
        format: pkg.format,
        package_name: pkg.package_name,
        version: pkg.version,
        release: pkg.release,
        architecture: pkg.architecture,
        checksum_sha256: pkg.checksum_sha256,
        upstream_path: pkg.upstream_path,
        status: pkg.status,
        evaluated_at: pkg.evaluated_at.map(|t| t.to_rfc3339()),
        evaluated_by: pkg.evaluated_by,
        evaluation_reason: pkg.evaluation_reason,
        rule_id: pkg.rule_id,
        metadata: pkg.metadata,
        first_seen_at: pkg.first_seen_at.to_rfc3339(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admin_auth() -> AuthExtension {
        AuthExtension {
            user_id: Uuid::new_v4(),
            username: "admin".to_string(),
            email: "admin@example.com".to_string(),
            is_admin: true,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
        }
    }

    fn non_admin_auth() -> AuthExtension {
        AuthExtension {
            user_id: Uuid::new_v4(),
            username: "user".to_string(),
            email: "user@example.com".to_string(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
        }
    }

    // The curation write handlers (create/update/delete rule, approve/block,
    // bulk-approve/bulk-block, re-evaluate) gate on `auth.require_admin()` so a
    // non-admin cannot reach the allow/deny curation gate the security team
    // relies on. These tests pin that gate so the write path stays admin-only.

    #[test]
    fn test_curation_write_allows_admin() {
        assert!(admin_auth().require_admin().is_ok());
    }

    #[test]
    fn test_curation_write_rejects_non_admin() {
        let err = non_admin_auth().require_admin().unwrap_err();
        match err {
            AppError::Authorization(msg) => assert_eq!(msg, "Admin access required"),
            other => panic!("Expected Authorization error, got: {:?}", other),
        }
    }

    // -- OpenAPI contract (#2020) --------------------------------------------
    //
    // The curation create/update DTOs must export distinct component names so
    // they no longer collide with promotion_rules' bare `CreateRuleRequest`
    // (which the merged spec previously let win). Each curation endpoint must
    // document its own struct with the genuinely-required curation fields.

    fn curation_spec_json() -> serde_json::Value {
        serde_json::to_value(CurationApiDoc::openapi()).expect("serialize curation openapi")
    }

    #[test]
    fn test_openapi_curation_schema_has_distinct_component_names() {
        let spec = curation_spec_json();
        let schemas = &spec["components"]["schemas"];
        assert!(
            schemas.get("CurationCreateRuleRequest").is_some(),
            "expected CurationCreateRuleRequest component"
        );
        assert!(
            schemas.get("CurationUpdateRuleRequest").is_some(),
            "expected CurationUpdateRuleRequest component"
        );
        // The bare collision names must NOT be emitted by the curation doc.
        assert!(
            schemas.get("CreateRuleRequest").is_none(),
            "curation doc must not emit bare CreateRuleRequest"
        );
        assert!(
            schemas.get("UpdateRuleRequest").is_none(),
            "curation doc must not emit bare UpdateRuleRequest"
        );
    }

    #[test]
    fn test_openapi_curation_create_required_fields() {
        let spec = curation_spec_json();
        let required = spec["components"]["schemas"]["CurationCreateRuleRequest"]["required"]
            .as_array()
            .expect("CurationCreateRuleRequest.required array")
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>();
        for field in ["package_pattern", "action", "reason"] {
            assert!(
                required.contains(&field),
                "expected {field} in required, got {required:?}"
            );
        }
        // Defaulted/optional fields must not be required.
        for field in [
            "staging_repo_id",
            "version_constraint",
            "architecture",
            "priority",
        ] {
            assert!(
                !required.contains(&field),
                "{field} must not be required, got {required:?}"
            );
        }
        // `name` belongs to promotion rules, not curation.
        assert!(
            !required.contains(&"name"),
            "curation create must not require name"
        );
    }

    #[test]
    fn test_openapi_curation_create_request_body_refs_curation_schema() {
        let spec = curation_spec_json();
        let schema_ref = spec["paths"]["/api/v1/curation/rules"]["post"]["requestBody"]["content"]
            ["application/json"]["schema"]["$ref"]
            .as_str()
            .expect("curation create requestBody $ref");
        assert!(
            schema_ref.ends_with("CurationCreateRuleRequest"),
            "expected $ref to CurationCreateRuleRequest, got {schema_ref}"
        );
    }

    #[test]
    fn test_openapi_curation_get_by_id_route_present() {
        let spec = curation_spec_json();
        assert!(
            spec["paths"]["/api/v1/curation/rules/{id}"]
                .get("get")
                .is_some(),
            "expected GET /api/v1/curation/rules/{{id}} in spec"
        );
    }

    #[test]
    fn test_create_rule_request_serde_round_trip() {
        // The 3-field body the corrected contract documents must deserialize and
        // apply the documented defaults for the omitted optional fields.
        let body = serde_json::json!({
            "package_pattern": "evil-*",
            "action": "block",
            "reason": "qa"
        });
        let req: CreateRuleRequest =
            serde_json::from_value(body).expect("deserialize 3-field curation create body");
        assert_eq!(req.package_pattern, "evil-*");
        assert_eq!(req.action, "block");
        assert_eq!(req.reason, "qa");
        assert_eq!(req.version_constraint, "*");
        assert_eq!(req.architecture, "*");
        assert_eq!(req.priority, 100);
        assert!(req.staging_repo_id.is_none());
    }

    // ----------------------------------------------------------------------
    // #2443 cross-repo authorization for the curation read routes.
    // ----------------------------------------------------------------------

    #[cfg(test)]
    async fn seed_rule(pool: &sqlx::PgPool, staging: Uuid) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO curation_rules \
             (staging_repo_id, package_pattern, version_constraint, architecture, action, \
              priority, reason, enabled) \
             VALUES ($1, 'evil-*', '*', '*', 'block', 100, 'qa2443', true) RETURNING id",
        )
        .bind(staging)
        .fetch_one(pool)
        .await
        .expect("seed curation rule")
    }

    // get_rule: non-member -> existence-hiding 404; member -> 200; public -> 200.
    #[tokio::test]
    async fn test_get_rule_cross_tenant_authz_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (staging, _sk, _sd) = tdh::create_repo(&pool, "local", "rpm").await;
        let rule = seed_rule(&pool, staging).await;
        let (member, mname) = tdh::create_user(&pool).await;
        let (outsider, oname) = tdh::create_user(&pool).await;
        tdh::grant_repo_access(&pool, staging, member).await;
        let state = tdh::build_state(pool.clone(), "/tmp");

        let denied = super::get_rule(
            State(state.clone()),
            Extension(tdh::make_auth(outsider, &oname)),
            Path(rule),
        )
        .await;
        assert!(
            matches!(denied, Err(AppError::NotFound(_))),
            "non-member must 404: {denied:?}"
        );

        // hidden vs absent rule id -> same 404 body (no existence oracle).
        let absent = super::get_rule(
            State(state.clone()),
            Extension(tdh::make_auth(outsider, &oname)),
            Path(Uuid::new_v4()),
        )
        .await;
        match (&denied, &absent) {
            (Err(AppError::NotFound(a)), Err(AppError::NotFound(b))) => {
                assert_eq!(a, b, "hidden vs absent rule 404 bodies must match")
            }
            _ => panic!("both hidden and absent must be NotFound: {denied:?} {absent:?}"),
        }

        let seen = super::get_rule(
            State(state.clone()),
            Extension(tdh::make_auth(member, &mname)),
            Path(rule),
        )
        .await;
        assert!(
            seen.is_ok(),
            "member of staging repo must see rule: {seen:?}"
        );

        // admin sees it too.
        let admin = super::get_rule(
            State(state.clone()),
            Extension(tdh::admin_auth(outsider, &oname)),
            Path(rule),
        )
        .await;
        assert!(admin.is_ok(), "admin must see rule: {admin:?}");

        // public flip -> non-member passes.
        sqlx::query("UPDATE repositories SET is_public = true WHERE id = $1")
            .bind(staging)
            .execute(&pool)
            .await
            .unwrap();
        let public = super::get_rule(
            State(state),
            Extension(tdh::make_auth(outsider, &oname)),
            Path(rule),
        )
        .await;
        assert!(public.is_ok(), "public repo rule is visible: {public:?}");

        tdh::cleanup(&pool, staging, member).await;
        tdh::cleanup_user(&pool, outsider).await;
    }

    #[cfg(test)]
    async fn seed_package(pool: &sqlx::PgPool, staging: Uuid, remote: Uuid) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO curation_packages \
             (staging_repo_id, remote_repo_id, format, package_name, version, upstream_path) \
             VALUES ($1, $2, 'rpm', 'pkg2443', '1.0', '/pkg2443') RETURNING id",
        )
        .bind(staging)
        .bind(remote)
        .fetch_one(pool)
        .await
        .expect("seed curation package")
    }

    // get_package: non-member -> existence-hiding 404; member -> 200.
    #[tokio::test]
    async fn test_get_package_cross_tenant_authz_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (staging, _sk, _sd) = tdh::create_repo(&pool, "local", "rpm").await;
        let (remote, _rk, _rd) = tdh::create_repo(&pool, "remote", "rpm").await;
        let pkg = seed_package(&pool, staging, remote).await;
        let (member, mname) = tdh::create_user(&pool).await;
        let (outsider, oname) = tdh::create_user(&pool).await;
        tdh::grant_repo_access(&pool, staging, member).await;
        let state = tdh::build_state(pool.clone(), "/tmp");

        let denied = super::get_package(
            State(state.clone()),
            Extension(tdh::make_auth(outsider, &oname)),
            Path(pkg),
        )
        .await;
        assert!(
            matches!(denied, Err(AppError::NotFound(_))),
            "non-member must 404: {denied:?}"
        );

        let seen = super::get_package(
            State(state),
            Extension(tdh::make_auth(member, &mname)),
            Path(pkg),
        )
        .await;
        assert!(
            seen.is_ok(),
            "member of staging repo must see package: {seen:?}"
        );

        tdh::cleanup(&pool, staging, member).await;
        tdh::cleanup(&pool, remote, outsider).await;
    }

    // stats: non-member of the staging repo -> 404.
    #[tokio::test]
    async fn test_stats_non_member_404_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (staging, _sk, _sd) = tdh::create_repo(&pool, "local", "rpm").await;
        let (outsider, oname) = tdh::create_user(&pool).await;
        let state = tdh::build_state(pool.clone(), "/tmp");
        let denied = super::stats(
            State(state),
            Extension(tdh::make_auth(outsider, &oname)),
            Query(StatsQuery {
                staging_repo_id: staging,
            }),
        )
        .await;
        assert!(
            matches!(denied, Err(AppError::NotFound(_))),
            "non-member must 404 on stats: {denied:?}"
        );
        tdh::cleanup(&pool, staging, outsider).await;
    }

    // list_rules: unfiltered aggregate is admin-only.
    #[tokio::test]
    async fn test_list_rules_unfiltered_admin_only_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user, uname) = tdh::create_user(&pool).await;
        let state = tdh::build_state(pool.clone(), "/tmp");
        let denied = super::list_rules(
            State(state.clone()),
            Extension(tdh::make_auth(user, &uname)),
            Query(std::collections::HashMap::new()),
        )
        .await;
        assert!(
            matches!(denied, Err(AppError::Authorization(_))),
            "unfiltered curation rules list must be admin-only: {denied:?}"
        );
        let admin_ok = super::list_rules(
            State(state),
            Extension(tdh::admin_auth(user, &uname)),
            Query(std::collections::HashMap::new()),
        )
        .await;
        assert!(admin_ok.is_ok(), "admin sees the aggregate: {admin_ok:?}");
        tdh::cleanup_user(&pool, user).await;
    }

    // ----------------------------------------------------------------------
    // #2447 router-level (oneshot) coverage for the `/packages/:id` routes.
    //
    // The existing curation tests invoke the handler functions directly with a
    // synthetic `Path(uuid)`, so a broken route *registration* is invisible to
    // them. These tests drive the real `router()` through `tower::oneshot`, so
    // a route that does not match (e.g. an axum-0.8 `{id}` string on this
    // axum-0.7 router) surfaces as a router-layer 404 and fails the assertion.
    // ----------------------------------------------------------------------

    // GET /packages/:id must reach the handler and, for a real package viewed by
    // an admin, return 200 with the id echoed back — proving both that the route
    // matches and that the positional `Path<Uuid>` binds the right segment. On
    // the pre-fix `{id}` registration this is a router 404.
    #[tokio::test]
    async fn test_get_package_route_resolves_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::body::Body;
        use axum::http::Request;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (staging, _sk, _sd) = tdh::create_repo(&pool, "local", "rpm").await;
        let (remote, _rk, _rd) = tdh::create_repo(&pool, "remote", "rpm").await;
        let pkg = seed_package(&pool, staging, remote).await;
        let (admin, aname) = tdh::create_user(&pool).await;
        let state = tdh::build_state(pool.clone(), "/tmp");
        let router =
            tdh::router_with_auth_ext(super::router(), state, tdh::admin_auth(admin, &aname));

        let req = Request::builder()
            .method("GET")
            .uri(format!("/packages/{pkg}"))
            .body(Body::empty())
            .expect("build GET request");
        let (status, body) = tdh::send(router, req).await;

        assert_ne!(
            status.as_u16(),
            404,
            "GET /packages/:id must match a route, not a router 404; body: {}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(status.as_u16(), 200, "admin GET of a seeded package is 200");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("parse body json");
        assert_eq!(
            json["id"].as_str(),
            Some(pkg.to_string().as_str()),
            "response id must echo the path uuid"
        );

        tdh::cleanup(&pool, staging, admin).await;
        tdh::cleanup(&pool, remote, admin).await;
    }

    // POST /packages/:id/approve and /packages/:id/block must resolve to their
    // handlers. A non-admin caller hits `require_admin()` first and gets a 403 —
    // never a router 404 — which proves the routes match without depending on any
    // seeded package. On the pre-fix `{id}` registration both are router 404s.
    #[tokio::test]
    async fn test_approve_block_routes_resolve_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::body::Body;
        use axum::http::Request;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user, uname) = tdh::create_user(&pool).await;
        let state = tdh::build_state(pool.clone(), "/tmp");
        let id = Uuid::new_v4();

        for suffix in ["approve", "block"] {
            let router = tdh::router_with_auth_ext(
                super::router(),
                state.clone(),
                tdh::make_auth(user, &uname),
            );
            let req = Request::builder()
                .method("POST")
                .uri(format!("/packages/{id}/{suffix}"))
                .body(Body::empty())
                .expect("build POST request");
            let (status, body) = tdh::send(router, req).await;

            assert_ne!(
                status.as_u16(),
                404,
                "POST /packages/:id/{suffix} must match a route, not a router 404; body: {}",
                String::from_utf8_lossy(&body)
            );
            assert_eq!(
                status.as_u16(),
                403,
                "non-admin POST /packages/:id/{suffix} is rejected by require_admin (403)"
            );
        }

        tdh::cleanup_user(&pool, user).await;
    }

    // ----------------------------------------------------------------------
    // #2357 — manual sync trigger authz (pure) + search / trigger (DB).
    // ----------------------------------------------------------------------

    #[test]
    fn test_ensure_sync_authorized_pure() {
        // admin passes; scoped token passes; neither is rejected.
        assert!(super::ensure_sync_authorized(true, false).is_ok());
        assert!(super::ensure_sync_authorized(false, true).is_ok());
        let denied = super::ensure_sync_authorized(false, false);
        assert!(
            matches!(denied, Err(AppError::Authorization(_))),
            "no admin + no scope must be rejected: {denied:?}"
        );
    }

    #[test]
    fn test_sync_tenant_access_allowed_pure() {
        // Admin flag does NOT bypass: only a grant or a public repo allows.
        assert!(super::sync_tenant_access_allowed(false, true));
        assert!(super::sync_tenant_access_allowed(true, false)); // public repo
        assert!(!super::sync_tenant_access_allowed(false, false));
    }

    /// An API-token principal carrying the admin-mintable `trigger:sync` scope.
    fn sync_scope_token(user_id: Uuid, username: &str) -> AuthExtension {
        AuthExtension {
            user_id,
            username: username.to_string(),
            email: format!("{username}@test.local"),
            is_admin: false,
            is_api_token: true,
            is_service_account: false,
            scopes: Some(vec!["trigger:sync".to_string()]),
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
        }
    }

    // POST /repos/{key}/sync: anon-ish non-admin (no scope) -> 403;
    // authorized admin -> 200 and exactly one CURATION_SYNC_TRIGGERED audit row.
    #[tokio::test]
    async fn test_trigger_sync_authz_and_audit_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        // A curation staging repo whose remote points at an unreachable upstream,
        // so the sync pass runs and safely no-ops (no network) — the trigger's
        // authz + audit behavior is what we assert.
        let (staging, skey, _sd) = tdh::create_repo(&pool, "staging", "rpm").await;
        let (remote, _rk, _rd) = tdh::create_repo(&pool, "remote", "rpm").await;
        sqlx::query(
            "UPDATE repositories SET curation_enabled = true, curation_source_repo_id = $2 WHERE id = $1",
        )
        .bind(staging)
        .bind(remote)
        .execute(&pool)
        .await
        .unwrap();
        // Point the remote at an address that refuses instantly so the sync pass
        // fails fast (connection refused) instead of waiting on a DNS/HTTP
        // timeout — the trigger's authz + audit behavior is what this asserts.
        sqlx::query("UPDATE repositories SET upstream_url = 'http://127.0.0.1:1' WHERE id = $1")
            .bind(remote)
            .execute(&pool)
            .await
            .unwrap();

        let (user, uname) = tdh::create_user(&pool).await;
        let (admin, aname) = tdh::create_user(&pool).await;
        // The admin genuinely owns this tenant: grant a repo-scoped assignment so
        // the (admin-flag-independent) tenant gate passes. This models a real
        // super-admin/tenant owner, not a foreign-tenant admin (which the
        // cross-tenant test asserts is refused).
        tdh::grant_repo_access(&pool, staging, admin).await;
        let state = tdh::build_state(pool.clone(), "/tmp");

        // Non-admin, no scope -> 403 (no sync, no audit).
        let denied = super::trigger_sync(
            State(state.clone()),
            Extension(tdh::make_auth(user, &uname)),
            Path(skey.clone()),
        )
        .await;
        assert!(
            matches!(denied, Err(AppError::Authorization(_))),
            "non-admin without trigger:sync must be 403: {denied:?}"
        );

        // Authorized admin -> 200, triggered, and one audit row for the repo.
        let ok = super::trigger_sync(
            State(state.clone()),
            Extension(tdh::admin_auth(admin, &aname)),
            Path(skey.clone()),
        )
        .await;
        assert!(ok.is_ok(), "admin trigger must succeed: {ok:?}");
        assert!(ok.unwrap().triggered);

        let audits = tdh::audit_count(&pool, staging, "CURATION_SYNC_TRIGGERED").await;
        assert_eq!(
            audits, 1,
            "an authorized sync trigger must write exactly one audit_log row"
        );

        // A scoped API token also passes the global gate (tenant check applies).
        let scoped = super::trigger_sync(
            State(state),
            Extension(sync_scope_token(admin, &aname)),
            Path(skey),
        )
        .await;
        assert!(
            scoped.is_ok(),
            "trigger:sync-scoped token passes the global gate: {scoped:?}"
        );

        tdh::cleanup(&pool, staging, user).await;
        tdh::cleanup(&pool, remote, admin).await;
    }

    // Wrong-tenant admin-capable principal (repo-scoped admin, no grant on a
    // PRIVATE repo) must be refused by the tenant gate even though is_admin.
    #[tokio::test]
    async fn test_trigger_sync_cross_tenant_admin_rejected_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (staging, skey, _sd) = tdh::create_repo(&pool, "staging", "rpm").await;
        let (other_user, ouname) = tdh::create_user(&pool).await;
        let state = tdh::build_state(pool.clone(), "/tmp");

        // A tenant-scoped admin (is_admin=true) with NO grant on this private
        // repo. `admin_auth` uses AccessScope::Admin, but the tenant gate keys
        // off `user_can_access_repo`, which this user does not have.
        let denied = super::trigger_sync(
            State(state),
            Extension(tdh::admin_auth(other_user, &ouname)),
            Path(skey),
        )
        .await;
        assert!(
            matches!(denied, Err(AppError::Authorization(_))),
            "admin-capable principal without a tenant grant must be 403: {denied:?}"
        );

        tdh::cleanup(&pool, staging, other_user).await;
    }

    // GET /repos/{key}/packages/search: non-member -> existence-hiding 404;
    // member -> 200 with the NEVRA rows filtered by the name query.
    #[tokio::test]
    async fn test_search_packages_tenant_and_filter_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (staging, skey, _sd) = tdh::create_repo(&pool, "staging", "rpm").await;
        let (remote, _rk, _rd) = tdh::create_repo(&pool, "remote", "rpm").await;
        // Seed two RPM packages so the name filter is exercised.
        for (name, arch) in [("bash", "x86_64"), ("curl", "x86_64")] {
            sqlx::query(
                "INSERT INTO curation_packages \
                 (staging_repo_id, remote_repo_id, format, package_name, version, release, architecture, upstream_path, status) \
                 VALUES ($1, $2, 'rpm', $3, '5.1.8', '1.el9', $4, $5, 'approved')",
            )
            .bind(staging)
            .bind(remote)
            .bind(name)
            .bind(arch)
            .bind(format!("Packages/{name}.rpm"))
            .execute(&pool)
            .await
            .expect("seed curation package");
        }

        let (member, mname) = tdh::create_user(&pool).await;
        let (outsider, oname) = tdh::create_user(&pool).await;
        tdh::grant_repo_access(&pool, staging, member).await;
        let state = tdh::build_state(pool.clone(), "/tmp");

        // Non-member -> 404 (existence-hiding).
        let denied = super::search_packages(
            State(state.clone()),
            Extension(tdh::make_auth(outsider, &oname)),
            Path(skey.clone()),
            Query(PackageSearchQuery {
                q: Some("bash".to_string()),
                arch: None,
                status: None,
                limit: 50,
                offset: 0,
            }),
        )
        .await;
        assert!(
            matches!(denied, Err(AppError::NotFound(_))),
            "non-member search must 404: {denied:?}"
        );

        // Member -> 200, name filter returns only bash.
        let seen = super::search_packages(
            State(state),
            Extension(tdh::make_auth(member, &mname)),
            Path(skey),
            Query(PackageSearchQuery {
                q: Some("bash".to_string()),
                arch: Some("x86_64".to_string()),
                status: Some("approved".to_string()),
                limit: 50,
                offset: 0,
            }),
        )
        .await
        .expect("member search must succeed");
        let rows = seen.0;
        assert_eq!(
            rows.len(),
            1,
            "name filter must return only the bash package"
        );
        assert_eq!(rows[0].package_name, "bash");
        assert_eq!(rows[0].architecture.as_deref(), Some("x86_64"));

        tdh::cleanup(&pool, staging, member).await;
        tdh::cleanup(&pool, remote, outsider).await;
    }
}
