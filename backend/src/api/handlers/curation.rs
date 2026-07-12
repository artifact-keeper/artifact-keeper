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
use crate::services::curation_service::CurationService;

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
        stats,
    ),
    components(schemas(
        CreateRuleRequest,
        UpdateRuleRequest,
        RuleResponse,
        CurationPackageResponse,
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
        .route(
            "/rules/:id",
            get(get_rule).put(update_rule).delete(delete_rule),
        )
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
}
