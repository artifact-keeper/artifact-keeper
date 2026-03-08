//! Curation API handler: manage curation rules and package approvals.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post, put},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::AppError;
use crate::services::curation_service::CurationService;

#[derive(OpenApi)]
#[openapi(
    paths(
        list_rules,
        create_rule,
        update_rule,
        delete_rule,
        list_packages,
        get_package,
        approve_package,
        block_package,
        bulk_approve,
        bulk_block,
        re_evaluate,
        stats,
    ),
    components(schemas(
        CreateRuleRequest,
        UpdateRuleRequest,
        RuleResponse,
        PackageResponse,
        BulkStatusRequest,
        PackageListQuery,
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
        .route("/rules/{id}", put(update_rule).delete(delete_rule))
        // Packages
        .route("/packages", get(list_packages))
        .route("/packages/{id}", get(get_package))
        .route("/packages/{id}/approve", post(approve_package))
        .route("/packages/{id}/block", post(block_package))
        .route("/packages/bulk-approve", post(bulk_approve))
        .route("/packages/bulk-block", post(bulk_block))
        .route("/packages/re-evaluate", post(re_evaluate))
        // Stats
        .route("/stats", get(stats))
}

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, ToSchema)]
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
pub struct PackageResponse {
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

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/curation/rules",
    params(("staging_repo_id" = Option<Uuid>, Query, description = "Filter by staging repo")),
    responses((status = 200, body = Vec<RuleResponse>)),
    tag = "Curation"
)]
async fn list_rules(
    State(state): State<SharedState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<Json<Vec<RuleResponse>>, AppError> {
    let svc = CurationService::new(state.db.clone());
    let repo_id = params.get("staging_repo_id").and_then(|s| s.parse().ok());
    let rules = svc.list_rules(repo_id).await?;
    Ok(Json(rules.into_iter().map(rule_to_response).collect()))
}

#[utoipa::path(
    post,
    path = "/api/v1/curation/rules",
    request_body = CreateRuleRequest,
    responses((status = 201, body = RuleResponse)),
    tag = "Curation"
)]
async fn create_rule(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(req): Json<CreateRuleRequest>,
) -> Result<(StatusCode, Json<RuleResponse>), AppError> {
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
    put,
    path = "/api/v1/curation/rules/{id}",
    request_body = UpdateRuleRequest,
    params(("id" = Uuid, Path, description = "Rule ID")),
    responses((status = 200, body = RuleResponse)),
    tag = "Curation"
)]
async fn update_rule(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateRuleRequest>,
) -> Result<Json<RuleResponse>, AppError> {
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
    params(("id" = Uuid, Path, description = "Rule ID")),
    responses((status = 204)),
    tag = "Curation"
)]
async fn delete_rule(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let svc = CurationService::new(state.db.clone());
    svc.delete_rule(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/api/v1/curation/packages",
    params(PackageListQuery),
    responses((status = 200, body = Vec<PackageResponse>)),
    tag = "Curation"
)]
async fn list_packages(
    State(state): State<SharedState>,
    Query(query): Query<PackageListQuery>,
) -> Result<Json<Vec<PackageResponse>>, AppError> {
    let svc = CurationService::new(state.db.clone());
    let packages = svc
        .list_packages(query.staging_repo_id, query.status.as_deref(), query.limit, query.offset)
        .await?;
    Ok(Json(packages.into_iter().map(pkg_to_response).collect()))
}

#[utoipa::path(
    get,
    path = "/api/v1/curation/packages/{id}",
    params(("id" = Uuid, Path, description = "Package ID")),
    responses((status = 200, body = PackageResponse)),
    tag = "Curation"
)]
async fn get_package(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<PackageResponse>, AppError> {
    let svc = CurationService::new(state.db.clone());
    let pkg = svc.get_package(id).await?;
    Ok(Json(pkg_to_response(pkg)))
}

#[utoipa::path(
    post,
    path = "/api/v1/curation/packages/{id}/approve",
    params(("id" = Uuid, Path, description = "Package ID")),
    responses((status = 200, body = PackageResponse)),
    tag = "Curation"
)]
async fn approve_package(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<PackageResponse>, AppError> {
    let svc = CurationService::new(state.db.clone());
    let pkg = svc
        .set_package_status(id, "approved", "Manually approved", Some(auth.user_id), None)
        .await?;
    Ok(Json(pkg_to_response(pkg)))
}

#[utoipa::path(
    post,
    path = "/api/v1/curation/packages/{id}/block",
    params(("id" = Uuid, Path, description = "Package ID")),
    responses((status = 200, body = PackageResponse)),
    tag = "Curation"
)]
async fn block_package(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<PackageResponse>, AppError> {
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
    Json(req): Json<ReEvaluateRequest>,
) -> Result<Json<u64>, AppError> {
    let svc = CurationService::new(state.db.clone());
    let count = svc
        .re_evaluate_pending(req.staging_repo_id, &req.default_action)
        .await?;
    Ok(Json(count))
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
    Query(query): Query<StatsQuery>,
) -> Result<Json<StatsResponse>, AppError> {
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

fn pkg_to_response(pkg: crate::models::curation::CurationPackage) -> PackageResponse {
    PackageResponse {
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
