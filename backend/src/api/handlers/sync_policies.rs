//! Sync policy management handlers.

use axum::{
    extract::{Extension, Path, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::sync_policy_service::{
    ArtifactFilter, CreateSyncPolicyRequest, EvaluationResult, PeerSelector, PreviewResult,
    RepoSelector, SyncPolicy, SyncPolicyService, UpdateSyncPolicyRequest,
};

#[derive(OpenApi)]
#[openapi(
    paths(
        list_policies,
        create_policy,
        get_policy,
        update_policy,
        delete_policy,
        toggle_policy,
        evaluate_policies,
        preview_policy,
    ),
    components(schemas(
        SyncPolicyResponse,
        SyncPolicyListResponse,
        CreateSyncPolicyPayload,
        UpdateSyncPolicyPayload,
        TogglePolicyPayload,
        EvaluationResultResponse,
        PreviewPolicyPayload,
        PreviewResultResponse,
        RepoSelectorSchema,
        PeerSelectorSchema,
        ArtifactFilterSchema,
        MatchedRepoSchema,
        MatchedPeerSchema,
    )),
    tags((name = "peers", description = "Peer replication and sync"))
)]
pub struct SyncPoliciesApiDoc;

/// Create sync policy routes.
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_policies).post(create_policy))
        .route("/evaluate", post(evaluate_policies))
        .route("/preview", post(preview_policy))
        .route(
            "/:id",
            get(get_policy).put(update_policy).delete(delete_policy),
        )
        .route("/:id/toggle", post(toggle_policy))
}

// ---------------------------------------------------------------------------
// Request / Response types (with utoipa ToSchema for OpenAPI)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, ToSchema)]
pub struct SyncPolicyResponse {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    #[schema(value_type = Object)]
    pub repo_selector: serde_json::Value,
    #[schema(value_type = Object)]
    pub peer_selector: serde_json::Value,
    pub replication_mode: String,
    pub priority: i32,
    #[schema(value_type = Object)]
    pub artifact_filter: serde_json::Value,
    /// Convenience glob filter, mirrored from `artifact_filter.include_paths`.
    /// Round-trips the single-pattern shorthand accepted on create
    /// (e.g. `"*.tar.gz"`). Empty when no include pattern is set.
    pub filter: String,
    pub precedence: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SyncPolicyListResponse {
    pub items: Vec<SyncPolicyResponse>,
    pub total: usize,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateSyncPolicyPayload {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[schema(value_type = Object)]
    #[serde(default)]
    pub repo_selector: Option<serde_json::Value>,
    #[schema(value_type = Object)]
    #[serde(default)]
    pub peer_selector: Option<serde_json::Value>,
    #[serde(default = "default_replication_mode")]
    pub replication_mode: String,
    #[serde(default)]
    pub priority: i32,
    #[schema(value_type = Object)]
    #[serde(default)]
    pub artifact_filter: Option<serde_json::Value>,
    /// Convenience glob filter (e.g. `"*.tar.gz"`). When set, it is folded
    /// into `artifact_filter.include_paths` so only matching artifact paths
    /// are eligible for sync. Ignored if `artifact_filter.include_paths` is
    /// already provided.
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default = "default_precedence")]
    pub precedence: i32,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateSyncPolicyPayload {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[schema(value_type = Object)]
    #[serde(default)]
    pub repo_selector: Option<serde_json::Value>,
    #[schema(value_type = Object)]
    #[serde(default)]
    pub peer_selector: Option<serde_json::Value>,
    #[serde(default)]
    pub replication_mode: Option<String>,
    #[serde(default)]
    pub priority: Option<i32>,
    #[schema(value_type = Object)]
    #[serde(default)]
    pub artifact_filter: Option<serde_json::Value>,
    #[serde(default)]
    pub precedence: Option<i32>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct TogglePolicyPayload {
    pub enabled: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EvaluationResultResponse {
    pub created: usize,
    pub updated: usize,
    pub removed: usize,
    pub policies_evaluated: usize,
    pub retroactive_tasks_queued: usize,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct PreviewPolicyPayload {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[schema(value_type = Object)]
    #[serde(default)]
    pub repo_selector: Option<serde_json::Value>,
    #[schema(value_type = Object)]
    #[serde(default)]
    pub peer_selector: Option<serde_json::Value>,
    #[serde(default = "default_replication_mode")]
    pub replication_mode: String,
    #[serde(default)]
    pub priority: i32,
    #[schema(value_type = Object)]
    #[serde(default)]
    pub artifact_filter: Option<serde_json::Value>,
    #[serde(default = "default_precedence")]
    pub precedence: i32,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PreviewResultResponse {
    pub matched_repositories: Vec<MatchedRepoSchema>,
    pub matched_peers: Vec<MatchedPeerSchema>,
    pub subscription_count: usize,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RepoSelectorSchema {
    #[serde(default)]
    pub match_labels: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub match_formats: Vec<String>,
    #[serde(default)]
    pub match_pattern: Option<String>,
    #[serde(default)]
    pub match_repos: Vec<Uuid>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PeerSelectorSchema {
    #[serde(default)]
    pub all: bool,
    #[serde(default)]
    pub match_labels: std::collections::HashMap<String, String>,
    #[serde(default)]
    pub match_region: Option<String>,
    #[serde(default)]
    pub match_peers: Vec<Uuid>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ArtifactFilterSchema {
    #[serde(default)]
    pub max_age_days: Option<i32>,
    #[serde(default)]
    pub include_paths: Vec<String>,
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    #[serde(default)]
    pub max_size_bytes: Option<i64>,
    /// Tag selectors (AND semantics). Key = tag key, value = required tag value.
    /// Empty value means "key must exist with any value".
    #[serde(default)]
    pub match_tags: std::collections::HashMap<String, String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MatchedRepoSchema {
    pub id: Uuid,
    pub key: String,
    pub format: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MatchedPeerSchema {
    pub id: Uuid,
    pub name: String,
    pub region: Option<String>,
}

// ---------------------------------------------------------------------------
// Default helpers
// ---------------------------------------------------------------------------

fn default_true() -> bool {
    true
}

fn default_replication_mode() -> String {
    "push".to_string()
}

fn default_precedence() -> i32 {
    100
}

// ---------------------------------------------------------------------------
// Converters
// ---------------------------------------------------------------------------

/// Fold a convenience glob `filter` into an artifact_filter JSON value's
/// `include_paths`. If the caller already supplied `include_paths`, the
/// explicit value wins and the shorthand is ignored.
///
/// Returns the (possibly modified) artifact_filter as parsed `ArtifactFilter`.
fn apply_filter_shorthand(
    artifact_filter: ArtifactFilter,
    filter: Option<String>,
) -> ArtifactFilter {
    match filter {
        Some(glob) if !glob.trim().is_empty() && artifact_filter.include_paths.is_empty() => {
            ArtifactFilter {
                include_paths: vec![glob],
                ..artifact_filter
            }
        }
        _ => artifact_filter,
    }
}

/// Extract the convenience `filter` string from a stored artifact_filter
/// JSON value. Mirrors the first `include_paths` entry, or "" when absent.
fn filter_shorthand_from_value(artifact_filter: &serde_json::Value) -> String {
    artifact_filter
        .get("include_paths")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn policy_to_response(p: SyncPolicy) -> SyncPolicyResponse {
    let filter = filter_shorthand_from_value(&p.artifact_filter);
    SyncPolicyResponse {
        id: p.id,
        name: p.name,
        description: p.description,
        enabled: p.enabled,
        repo_selector: p.repo_selector,
        peer_selector: p.peer_selector,
        replication_mode: p.replication_mode,
        priority: p.priority,
        artifact_filter: p.artifact_filter,
        filter,
        precedence: p.precedence,
        created_at: p.created_at,
        updated_at: p.updated_at,
    }
}

fn evaluation_to_response(r: EvaluationResult) -> EvaluationResultResponse {
    EvaluationResultResponse {
        created: r.created,
        updated: r.updated,
        removed: r.removed,
        policies_evaluated: r.policies_evaluated,
        retroactive_tasks_queued: r.retroactive_tasks_queued,
    }
}

fn preview_to_response(p: PreviewResult) -> PreviewResultResponse {
    PreviewResultResponse {
        matched_repositories: p
            .matched_repositories
            .into_iter()
            .map(|r| MatchedRepoSchema {
                id: r.id,
                key: r.key,
                format: r.format,
            })
            .collect(),
        matched_peers: p
            .matched_peers
            .into_iter()
            .map(|p| MatchedPeerSchema {
                id: p.id,
                name: p.name,
                region: p.region,
            })
            .collect(),
        subscription_count: p.subscription_count,
    }
}

/// Max total number of values (including nested) in a selector JSON tree.
const MAX_SELECTOR_VALUES: usize = 5000;

/// Recursively count all values in a serde_json::Value tree.
fn count_json_values(v: &serde_json::Value) -> usize {
    match v {
        serde_json::Value::Array(arr) => 1 + arr.iter().map(count_json_values).sum::<usize>(),
        serde_json::Value::Object(obj) => 1 + obj.values().map(count_json_values).sum::<usize>(),
        _ => 1,
    }
}

fn parse_selector<T: serde::de::DeserializeOwned + Default>(
    value: Option<serde_json::Value>,
) -> Result<T> {
    let parsed = value
        .map(|v| {
            // Count all nested values to prevent unbounded allocation on
            // deeply nested or wide structures (CodeQL: uncontrolled-allocation-size).
            let total = count_json_values(&v);
            if total > MAX_SELECTOR_VALUES {
                return Err(AppError::Validation(format!(
                    "Selector too complex ({total} values, max {MAX_SELECTOR_VALUES})"
                )));
            }
            Ok(serde_json::from_value(v).unwrap_or_default())
        })
        .transpose()?
        .unwrap_or_default();
    Ok(parsed)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// List all sync policies
#[utoipa::path(
    get,
    operation_id = "list_sync_policies",
    path = "",
    context_path = "/api/v1/sync-policies",
    tag = "peers",
    responses(
        (status = 200, description = "List of sync policies", body = SyncPolicyListResponse),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
async fn list_policies(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<SyncPolicyListResponse>> {
    auth.require_admin()?;
    let service = SyncPolicyService::new(state.db.clone());
    let policies = service.list_policies().await?;
    let items: Vec<SyncPolicyResponse> = policies.into_iter().map(policy_to_response).collect();
    let total = items.len();
    Ok(Json(SyncPolicyListResponse { items, total }))
}

/// Create a new sync policy
#[utoipa::path(
    post,
    operation_id = "create_sync_policy",
    path = "",
    context_path = "/api/v1/sync-policies",
    tag = "peers",
    request_body = CreateSyncPolicyPayload,
    responses(
        (status = 200, description = "Sync policy created", body = SyncPolicyResponse),
        (status = 400, description = "Validation error"),
        (status = 409, description = "Policy name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
async fn create_policy(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(payload): Json<CreateSyncPolicyPayload>,
) -> Result<Json<SyncPolicyResponse>> {
    auth.require_admin()?;
    let repo_selector: RepoSelector = parse_selector(payload.repo_selector)?;
    let peer_selector: PeerSelector = parse_selector(payload.peer_selector)?;
    let artifact_filter: ArtifactFilter = parse_selector(payload.artifact_filter)?;
    let artifact_filter = apply_filter_shorthand(artifact_filter, payload.filter);

    let req = CreateSyncPolicyRequest {
        name: payload.name,
        description: payload.description,
        enabled: payload.enabled,
        repo_selector,
        peer_selector,
        replication_mode: payload.replication_mode,
        priority: payload.priority,
        artifact_filter,
        precedence: payload.precedence,
    };

    let service = SyncPolicyService::new(state.db.clone());
    let policy = service.create_policy(req).await?;

    // Auto-evaluate so peer_repo_subscriptions are created immediately.
    // Without this, uploads won't trigger sync tasks until a manual
    // POST /api/v1/sync-policies/evaluate call.
    if let Err(e) = service.evaluate_policies().await {
        tracing::warn!("Post-create policy evaluation failed: {e}");
    }

    Ok(Json(policy_to_response(policy)))
}

/// Get a sync policy by ID
#[utoipa::path(
    get,
    operation_id = "get_sync_policy",
    path = "/{id}",
    context_path = "/api/v1/sync-policies",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Sync policy ID")
    ),
    responses(
        (status = 200, description = "Sync policy details", body = SyncPolicyResponse),
        (status = 404, description = "Sync policy not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
async fn get_policy(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<SyncPolicyResponse>> {
    auth.require_admin()?;
    let service = SyncPolicyService::new(state.db.clone());
    let policy = service.get_policy(id).await?;
    Ok(Json(policy_to_response(policy)))
}

/// Update a sync policy
#[utoipa::path(
    put,
    operation_id = "update_sync_policy",
    path = "/{id}",
    context_path = "/api/v1/sync-policies",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Sync policy ID")
    ),
    request_body = UpdateSyncPolicyPayload,
    responses(
        (status = 200, description = "Sync policy updated", body = SyncPolicyResponse),
        (status = 404, description = "Sync policy not found"),
        (status = 409, description = "Policy name already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
async fn update_policy(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateSyncPolicyPayload>,
) -> Result<Json<SyncPolicyResponse>> {
    auth.require_admin()?;
    let repo_selector: Option<RepoSelector> = payload
        .repo_selector
        .map(|v| parse_selector(Some(v)))
        .transpose()?;
    let peer_selector: Option<PeerSelector> = payload
        .peer_selector
        .map(|v| parse_selector(Some(v)))
        .transpose()?;
    let artifact_filter: Option<ArtifactFilter> = payload
        .artifact_filter
        .map(|v| parse_selector(Some(v)))
        .transpose()?;

    let req = UpdateSyncPolicyRequest {
        name: payload.name,
        description: payload.description,
        enabled: payload.enabled,
        repo_selector,
        peer_selector,
        replication_mode: payload.replication_mode,
        priority: payload.priority,
        artifact_filter,
        precedence: payload.precedence,
    };

    let service = SyncPolicyService::new(state.db.clone());
    let policy = service.update_policy(id, req).await?;

    if let Err(e) = service.evaluate_policies().await {
        tracing::warn!("Post-update policy evaluation failed: {e}");
    }

    Ok(Json(policy_to_response(policy)))
}

/// Delete a sync policy
#[utoipa::path(
    delete,
    operation_id = "delete_sync_policy",
    path = "/{id}",
    context_path = "/api/v1/sync-policies",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Sync policy ID")
    ),
    responses(
        (status = 204, description = "Sync policy deleted"),
        (status = 404, description = "Sync policy not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
async fn delete_policy(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<axum::http::StatusCode> {
    auth.require_admin()?;
    let service = SyncPolicyService::new(state.db.clone());
    service.delete_policy(id).await?;

    if let Err(e) = service.evaluate_policies().await {
        tracing::warn!("Post-delete policy evaluation failed: {e}");
    }

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Toggle a sync policy (enable/disable)
#[utoipa::path(
    post,
    path = "/{id}/toggle",
    context_path = "/api/v1/sync-policies",
    tag = "peers",
    params(
        ("id" = Uuid, Path, description = "Sync policy ID")
    ),
    request_body = TogglePolicyPayload,
    responses(
        (status = 200, description = "Sync policy toggled", body = SyncPolicyResponse),
        (status = 404, description = "Sync policy not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
async fn toggle_policy(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(payload): Json<TogglePolicyPayload>,
) -> Result<Json<SyncPolicyResponse>> {
    auth.require_admin()?;
    let service = SyncPolicyService::new(state.db.clone());
    let policy = service.toggle_policy(id, payload.enabled).await?;

    if let Err(e) = service.evaluate_policies().await {
        tracing::warn!("Post-toggle policy evaluation failed: {e}");
    }

    Ok(Json(policy_to_response(policy)))
}

/// Force re-evaluate all sync policies
#[utoipa::path(
    post,
    path = "/evaluate",
    context_path = "/api/v1/sync-policies",
    tag = "peers",
    responses(
        (status = 200, description = "Evaluation completed", body = EvaluationResultResponse),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
async fn evaluate_policies(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<EvaluationResultResponse>> {
    auth.require_admin()?;
    let service = SyncPolicyService::new(state.db.clone());
    let result = service.evaluate_policies().await?;
    Ok(Json(evaluation_to_response(result)))
}

/// Preview what a policy would match (dry-run)
#[utoipa::path(
    post,
    operation_id = "preview_sync_policy",
    path = "/preview",
    context_path = "/api/v1/sync-policies",
    tag = "peers",
    request_body = PreviewPolicyPayload,
    responses(
        (status = 200, description = "Preview result", body = PreviewResultResponse),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
async fn preview_policy(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(payload): Json<PreviewPolicyPayload>,
) -> Result<Json<PreviewResultResponse>> {
    auth.require_admin()?;
    let repo_selector: RepoSelector = parse_selector(payload.repo_selector)?;
    let peer_selector: PeerSelector = parse_selector(payload.peer_selector)?;
    let artifact_filter: ArtifactFilter = parse_selector(payload.artifact_filter)?;

    let req = CreateSyncPolicyRequest {
        name: payload.name,
        description: payload.description,
        enabled: payload.enabled,
        repo_selector,
        peer_selector,
        replication_mode: payload.replication_mode,
        priority: payload.priority,
        artifact_filter,
        precedence: payload.precedence,
    };

    let service = SyncPolicyService::new(state.db.clone());
    let result = service.preview_policy(req).await?;
    Ok(Json(preview_to_response(result)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DB-backed round-trip: create a policy with the convenience `filter`
    /// glob, then read it back and confirm the glob survives via the
    /// `filter` field (folded into and extracted from artifact_filter).
    ///
    /// Requires a migrated PostgreSQL at `DATABASE_URL`. Run with:
    ///   DATABASE_URL=postgres://... cargo test --lib \
    ///     api::handlers::sync_policies::tests::filter_round_trip -- --ignored
    #[tokio::test]
    #[ignore]
    async fn filter_round_trip_through_service() {
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let db = sqlx::PgPool::connect(&url).await.unwrap();
        let svc = SyncPolicyService::new(db);

        // Mirror the handler's create path: fold the shorthand into artifact_filter.
        let artifact_filter =
            apply_filter_shorthand(ArtifactFilter::default(), Some("*.tar.gz".to_string()));
        let req = crate::services::sync_policy_service::CreateSyncPolicyRequest {
            name: format!("filter-rt-{}", uuid::Uuid::new_v4()),
            description: String::new(),
            enabled: true,
            repo_selector: RepoSelector::default(),
            peer_selector: PeerSelector::default(),
            replication_mode: "push".to_string(),
            priority: 0,
            artifact_filter,
            precedence: 100,
        };
        let created = svc.create_policy(req).await.unwrap();

        // Read back and surface the response (mirrors GET handler).
        let fetched = svc.get_policy(created.id).await.unwrap();
        let resp = policy_to_response(fetched);
        assert_eq!(resp.filter, "*.tar.gz", "filter glob must round-trip");
        assert_eq!(
            resp.artifact_filter["include_paths"][0], "*.tar.gz",
            "glob must persist in artifact_filter.include_paths"
        );

        // Cleanup.
        svc.delete_policy(created.id).await.unwrap();
    }

    #[test]
    fn test_create_payload_deserialization_minimal() {
        let json = r#"{"name": "test-policy"}"#;
        let payload: CreateSyncPolicyPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.name, "test-policy");
        assert_eq!(payload.description, "");
        assert!(payload.enabled);
        assert_eq!(payload.replication_mode, "push");
        assert_eq!(payload.precedence, 100);
    }

    #[test]
    fn test_create_payload_deserialization_full() {
        let json = r#"{
            "name": "prod-sync",
            "description": "Sync prod repos",
            "enabled": false,
            "repo_selector": {"match_labels": {"env": "prod"}},
            "peer_selector": {"all": true},
            "replication_mode": "mirror",
            "priority": 5,
            "artifact_filter": {"max_age_days": 30},
            "precedence": 10
        }"#;
        let payload: CreateSyncPolicyPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.name, "prod-sync");
        assert!(!payload.enabled);
        assert_eq!(payload.replication_mode, "mirror");
        assert_eq!(payload.precedence, 10);
        assert!(payload.repo_selector.is_some());
        assert!(payload.peer_selector.is_some());
    }

    #[test]
    fn test_update_payload_partial() {
        let json = r#"{"name": "new-name", "enabled": false}"#;
        let payload: UpdateSyncPolicyPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.name, Some("new-name".to_string()));
        assert_eq!(payload.enabled, Some(false));
        assert!(payload.description.is_none());
        assert!(payload.repo_selector.is_none());
    }

    #[test]
    fn test_update_payload_empty() {
        let json = r#"{}"#;
        let payload: UpdateSyncPolicyPayload = serde_json::from_str(json).unwrap();
        assert!(payload.name.is_none());
        assert!(payload.enabled.is_none());
    }

    #[test]
    fn test_toggle_payload() {
        let json = r#"{"enabled": true}"#;
        let payload: TogglePolicyPayload = serde_json::from_str(json).unwrap();
        assert!(payload.enabled);
    }

    #[test]
    fn test_toggle_payload_requires_enabled() {
        let json = r#"{}"#;
        let result = serde_json::from_str::<TogglePolicyPayload>(json);
        assert!(result.is_err());
    }

    #[test]
    fn test_filter_shorthand_folded_into_include_paths() {
        let af = apply_filter_shorthand(ArtifactFilter::default(), Some("*.tar.gz".to_string()));
        assert_eq!(af.include_paths, vec!["*.tar.gz".to_string()]);
    }

    #[test]
    fn test_filter_shorthand_ignored_when_blank() {
        let af = apply_filter_shorthand(ArtifactFilter::default(), Some("   ".to_string()));
        assert!(af.include_paths.is_empty());
        let af = apply_filter_shorthand(ArtifactFilter::default(), None);
        assert!(af.include_paths.is_empty());
    }

    #[test]
    fn test_filter_shorthand_explicit_include_paths_win() {
        let explicit = ArtifactFilter {
            include_paths: vec!["release/*".to_string()],
            ..Default::default()
        };
        // Shorthand must not clobber an explicit include_paths.
        let af = apply_filter_shorthand(explicit, Some("*.tar.gz".to_string()));
        assert_eq!(af.include_paths, vec!["release/*".to_string()]);
    }

    #[test]
    fn test_filter_shorthand_roundtrip_from_value() {
        // Create-side fold, then read-side extract -> the glob survives.
        let af = apply_filter_shorthand(ArtifactFilter::default(), Some("*.tar.gz".to_string()));
        let stored = serde_json::to_value(&af).unwrap();
        assert_eq!(filter_shorthand_from_value(&stored), "*.tar.gz");
    }

    #[test]
    fn test_filter_shorthand_from_empty_value() {
        assert_eq!(filter_shorthand_from_value(&serde_json::json!({})), "");
        assert_eq!(
            filter_shorthand_from_value(&serde_json::json!({"include_paths": []})),
            ""
        );
    }

    #[test]
    fn test_create_payload_accepts_filter_field() {
        let json = r#"{"name":"f","filter":"*.tar.gz","schedule":"manual","direction":"push"}"#;
        let payload: CreateSyncPolicyPayload = serde_json::from_str(json).unwrap();
        // Unknown fields (schedule, direction) are ignored; filter is captured.
        assert_eq!(payload.filter.as_deref(), Some("*.tar.gz"));
    }

    #[test]
    fn test_policy_to_response_surfaces_filter() {
        let policy = SyncPolicy {
            id: uuid::Uuid::nil(),
            name: "t".to_string(),
            description: String::new(),
            enabled: true,
            repo_selector: serde_json::json!({}),
            peer_selector: serde_json::json!({}),
            replication_mode: "push".to_string(),
            priority: 0,
            artifact_filter: serde_json::json!({"include_paths": ["*.tar.gz"]}),
            precedence: 100,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let resp = policy_to_response(policy);
        assert_eq!(resp.filter, "*.tar.gz");
    }

    #[test]
    fn test_policy_to_response_mapping() {
        let policy = SyncPolicy {
            id: uuid::Uuid::nil(),
            name: "test".to_string(),
            description: "desc".to_string(),
            enabled: true,
            repo_selector: serde_json::json!({"match_formats": ["docker"]}),
            peer_selector: serde_json::json!({"all": true}),
            replication_mode: "push".to_string(),
            priority: 5,
            artifact_filter: serde_json::json!({}),
            precedence: 50,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let resp = policy_to_response(policy);
        assert_eq!(resp.name, "test");
        assert_eq!(resp.precedence, 50);
        assert_eq!(resp.priority, 5);
    }

    #[test]
    fn test_sync_policy_response_serialization() {
        let resp = SyncPolicyResponse {
            id: uuid::Uuid::nil(),
            name: "test".to_string(),
            description: "".to_string(),
            enabled: true,
            repo_selector: serde_json::json!({}),
            peer_selector: serde_json::json!({}),
            replication_mode: "push".to_string(),
            priority: 0,
            artifact_filter: serde_json::json!({}),
            filter: String::new(),
            precedence: 100,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"name\":\"test\""));
        assert!(json.contains("\"enabled\":true"));
        assert!(json.contains("\"replication_mode\":\"push\""));
    }

    #[test]
    fn test_sync_policy_list_response_serialization() {
        let resp = SyncPolicyListResponse {
            items: vec![],
            total: 0,
        };
        let json: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert!(json.get("items").is_some());
        assert!(json.get("total").is_some());
        assert_eq!(json["total"], 0);
        assert!(json["items"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_evaluation_result_response_serialization() {
        let resp = EvaluationResultResponse {
            created: 3,
            updated: 2,
            removed: 1,
            policies_evaluated: 5,
            retroactive_tasks_queued: 7,
        };
        let json: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["created"], 3);
        assert_eq!(json["updated"], 2);
        assert_eq!(json["removed"], 1);
        assert_eq!(json["policies_evaluated"], 5);
        assert_eq!(json["retroactive_tasks_queued"], 7);
    }

    #[test]
    fn test_preview_result_response_serialization() {
        let resp = PreviewResultResponse {
            matched_repositories: vec![MatchedRepoSchema {
                id: uuid::Uuid::nil(),
                key: "docker-prod".to_string(),
                format: "docker".to_string(),
            }],
            matched_peers: vec![MatchedPeerSchema {
                id: uuid::Uuid::nil(),
                name: "edge-east".to_string(),
                region: Some("us-east-1".to_string()),
            }],
            subscription_count: 1,
        };
        let json: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["subscription_count"], 1);
        assert_eq!(json["matched_repositories"].as_array().unwrap().len(), 1);
        assert_eq!(json["matched_peers"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_preview_payload_deserialization() {
        let json = r#"{
            "name": "preview-test",
            "repo_selector": {"match_formats": ["npm"]},
            "peer_selector": {"all": true}
        }"#;
        let payload: PreviewPolicyPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.name, "preview-test");
        assert!(payload.repo_selector.is_some());
        assert!(payload.peer_selector.is_some());
    }

    #[test]
    fn test_parse_selector_with_none() {
        let sel: RepoSelector = parse_selector(None).unwrap();
        assert!(sel.match_labels.is_empty());
        assert!(sel.match_formats.is_empty());
    }

    #[test]
    fn test_parse_selector_with_value() {
        let val = serde_json::json!({"match_formats": ["docker"]});
        let sel: RepoSelector = parse_selector(Some(val)).unwrap();
        assert_eq!(sel.match_formats, vec!["docker"]);
    }

    #[test]
    fn test_parse_selector_with_invalid_value() {
        let val = serde_json::json!("not an object");
        let sel: RepoSelector = parse_selector(Some(val)).unwrap();
        // Should fall back to default
        assert!(sel.match_labels.is_empty());
    }

    #[test]
    fn test_parse_selector_rejects_oversized_array() {
        // 5001 flat values exceeds MAX_SELECTOR_VALUES (5000)
        let items: Vec<serde_json::Value> = (0..5001).map(|i| serde_json::json!(i)).collect();
        let val = serde_json::Value::Array(items);
        let result: Result<RepoSelector> = parse_selector(Some(val));
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("too complex"),
            "expected 'too complex' error, got: {err_msg}"
        );
    }

    #[test]
    fn test_parse_selector_rejects_oversized_object() {
        let mut map = serde_json::Map::new();
        for i in 0..5001 {
            map.insert(format!("key_{i}"), serde_json::json!(i));
        }
        let val = serde_json::Value::Object(map);
        let result: Result<RepoSelector> = parse_selector(Some(val));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_selector_rejects_deeply_nested() {
        // Nested structure: object with 100 keys, each containing array of 60 values
        // Total: 1 (root) + 100 (keys with arrays) + 100*60 (values) = 6101 > 5000
        let mut map = serde_json::Map::new();
        for i in 0..100 {
            let items: Vec<serde_json::Value> = (0..60).map(|j| serde_json::json!(j)).collect();
            map.insert(format!("key_{i}"), serde_json::Value::Array(items));
        }
        let val = serde_json::Value::Object(map);
        let result: Result<RepoSelector> = parse_selector(Some(val));
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_selector_accepts_reasonable_size() {
        let items: Vec<serde_json::Value> = (0..1000).map(|i| serde_json::json!(i)).collect();
        let val = serde_json::Value::Array(items);
        // Array of ints won't deserialize to RepoSelector, so falls back to default
        let result: RepoSelector = parse_selector(Some(val)).unwrap();
        assert!(result.match_labels.is_empty());
    }

    #[test]
    fn test_sync_policy_response_json_contract() {
        let resp = SyncPolicyResponse {
            id: uuid::Uuid::nil(),
            name: "contract-test".to_string(),
            description: "test".to_string(),
            enabled: true,
            repo_selector: serde_json::json!({}),
            peer_selector: serde_json::json!({}),
            replication_mode: "push".to_string(),
            priority: 0,
            artifact_filter: serde_json::json!({}),
            filter: String::new(),
            precedence: 100,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let json: serde_json::Value = serde_json::to_value(&resp).unwrap();
        for field in [
            "id",
            "name",
            "description",
            "enabled",
            "repo_selector",
            "peer_selector",
            "replication_mode",
            "priority",
            "artifact_filter",
            "filter",
            "precedence",
            "created_at",
            "updated_at",
        ] {
            assert!(
                json.get(field).is_some(),
                "Missing field '{field}' in SyncPolicyResponse JSON"
            );
        }
        let obj = json.as_object().unwrap();
        assert_eq!(obj.len(), 13, "SyncPolicyResponse should have 13 fields");
    }

    // -----------------------------------------------------------------------
    // Admin gate: the mutating sync-policy handlers (create / update /
    // delete / toggle / evaluate) now call auth.require_admin()? before
    // touching the service. These tests exercise the exact guard
    // expression those handlers run.
    // -----------------------------------------------------------------------

    /// Build an [`AuthExtension`] with the given admin flag.
    fn policy_auth(is_admin: bool) -> AuthExtension {
        AuthExtension {
            user_id: Uuid::new_v4(),
            username: if is_admin { "admin" } else { "glen.globex" }.to_string(),
            email: "policy-test@example.com".to_string(),
            is_admin,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: None,
        }
    }

    #[test]
    fn test_policy_write_guard_rejects_non_admin() {
        let err = policy_auth(false).require_admin().unwrap_err();
        assert!(
            matches!(err, AppError::Authorization(_)),
            "non-admin must be rejected with an Authorization error, got: {err:?}"
        );
    }

    #[test]
    fn test_policy_write_guard_allows_admin() {
        assert!(policy_auth(true).require_admin().is_ok());
    }

    // -----------------------------------------------------------------------
    // Admin gate (reads): list_policies / get_policy / preview_policy now
    // also call auth.require_admin()? before touching the service, matching
    // their sibling mutations. Sync policies are a global federation-admin
    // feature, and preview resolves repositories with no per-caller
    // visibility scoping, so read access must be admin-only too. These tests
    // exercise the exact guard expression those read handlers run.
    // -----------------------------------------------------------------------

    #[test]
    fn test_policy_read_guard_rejects_non_admin() {
        let err = policy_auth(false).require_admin().unwrap_err();
        assert!(
            matches!(err, AppError::Authorization(_)),
            "non-admin read (list/get/preview) must be rejected with an Authorization error, got: {err:?}"
        );
    }

    #[test]
    fn test_policy_read_guard_allows_admin() {
        assert!(policy_auth(true).require_admin().is_ok());
    }
}
