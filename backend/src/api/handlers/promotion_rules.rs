//! Auto-promotion rules CRUD and evaluation handlers.
//!
//! Manages rules that automatically promote artifacts from staging repositories
//! to release repositories when all configured policies pass.

use axum::{
    extract::{Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::SharedState;
use crate::error::Result;
use crate::models::promotion::PromotionRule;
use crate::services::promotion_rule_service::{
    CreatePromotionRuleInput, PromotionRuleService, RuleEvaluationResult, UpdatePromotionRuleInput,
};

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_rules).post(create_rule))
        .route("/:id", get(get_rule).put(update_rule).delete(delete_rule))
        .route("/:id/evaluate", post(evaluate_rule))
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, IntoParams)]
pub struct ListRulesQuery {
    pub source_repo_id: Option<Uuid>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRuleRequest {
    pub name: String,
    pub source_repo_id: Uuid,
    pub target_repo_id: Uuid,
    #[serde(default = "default_true")]
    pub is_enabled: bool,
    #[serde(default = "default_max_cve_severity")]
    pub max_cve_severity: Option<String>,
    pub allowed_licenses: Option<Vec<String>>,
    #[serde(default)]
    pub require_signature: bool,
    pub min_staging_hours: Option<i32>,
    pub max_artifact_age_days: Option<i32>,
    pub min_health_score: Option<i32>,
    #[serde(default = "default_true")]
    pub auto_promote: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRuleRequest {
    pub name: Option<String>,
    pub is_enabled: Option<bool>,
    pub max_cve_severity: Option<String>,
    pub allowed_licenses: Option<Vec<String>>,
    pub require_signature: Option<bool>,
    pub min_staging_hours: Option<i32>,
    pub max_artifact_age_days: Option<i32>,
    pub min_health_score: Option<i32>,
    pub auto_promote: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PromotionRuleResponse {
    pub id: Uuid,
    pub name: String,
    pub source_repo_id: Uuid,
    pub target_repo_id: Uuid,
    pub is_enabled: bool,
    pub max_cve_severity: Option<String>,
    pub allowed_licenses: Option<Vec<String>>,
    pub require_signature: bool,
    pub min_staging_hours: Option<i32>,
    pub max_artifact_age_days: Option<i32>,
    pub min_health_score: Option<i32>,
    pub auto_promote: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PromotionRuleListResponse {
    pub items: Vec<PromotionRuleResponse>,
    pub total: usize,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RuleEvaluationResponse {
    pub rule_id: Uuid,
    pub rule_name: String,
    pub passed: bool,
    pub violations: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BulkEvaluationResponse {
    pub rule_id: Uuid,
    pub rule_name: String,
    pub total_artifacts: usize,
    pub passed: usize,
    pub failed: usize,
    pub results: Vec<ArtifactEvalEntry>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ArtifactEvalEntry {
    pub artifact_id: Uuid,
    pub passed: bool,
    pub violations: Vec<String>,
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

fn default_true() -> bool {
    true
}

fn default_max_cve_severity() -> Option<String> {
    Some("medium".to_string())
}

// ---------------------------------------------------------------------------
// Converters
// ---------------------------------------------------------------------------

fn rule_to_response(rule: PromotionRule) -> PromotionRuleResponse {
    PromotionRuleResponse {
        id: rule.id,
        name: rule.name,
        source_repo_id: rule.source_repo_id,
        target_repo_id: rule.target_repo_id,
        is_enabled: rule.is_enabled,
        max_cve_severity: rule.max_cve_severity,
        allowed_licenses: rule.allowed_licenses,
        require_signature: rule.require_signature,
        min_staging_hours: rule.min_staging_hours,
        max_artifact_age_days: rule.max_artifact_age_days,
        min_health_score: rule.min_health_score,
        auto_promote: rule.auto_promote,
        created_at: rule.created_at,
        updated_at: rule.updated_at,
    }
}

#[allow(dead_code)]
fn eval_to_response(eval: &RuleEvaluationResult) -> RuleEvaluationResponse {
    RuleEvaluationResponse {
        rule_id: eval.rule_id,
        rule_name: eval.rule_name.clone(),
        passed: eval.passed,
        violations: eval.violations.clone(),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// List all promotion rules
#[utoipa::path(
    get,
    path = "",
    context_path = "/api/v1/promotion-rules",
    tag = "promotion",
    params(ListRulesQuery),
    responses(
        (status = 200, description = "List of promotion rules", body = PromotionRuleListResponse),
        (status = 500, description = "Internal server error"),
    ),
    security(("bearer_auth" = []))
)]
async fn list_rules(
    State(state): State<SharedState>,
    Query(query): Query<ListRulesQuery>,
) -> Result<Json<PromotionRuleListResponse>> {
    let service = PromotionRuleService::new(state.db.clone());
    let rules = service.list(query.source_repo_id).await?;
    let items: Vec<PromotionRuleResponse> = rules.into_iter().map(rule_to_response).collect();
    let total = items.len();
    Ok(Json(PromotionRuleListResponse { items, total }))
}

/// Create a promotion rule
#[utoipa::path(
    post,
    path = "",
    context_path = "/api/v1/promotion-rules",
    tag = "promotion",
    request_body = CreateRuleRequest,
    responses(
        (status = 200, description = "Promotion rule created", body = PromotionRuleResponse),
        (status = 400, description = "Validation error", body = crate::api::openapi::ErrorResponse),
        (status = 500, description = "Internal server error"),
    ),
    security(("bearer_auth" = []))
)]
async fn create_rule(
    State(state): State<SharedState>,
    Json(body): Json<CreateRuleRequest>,
) -> Result<Json<PromotionRuleResponse>> {
    let service = PromotionRuleService::new(state.db.clone());
    let input = CreatePromotionRuleInput {
        name: body.name,
        source_repo_id: body.source_repo_id,
        target_repo_id: body.target_repo_id,
        is_enabled: body.is_enabled,
        max_cve_severity: body.max_cve_severity,
        allowed_licenses: body.allowed_licenses,
        require_signature: body.require_signature,
        min_staging_hours: body.min_staging_hours,
        max_artifact_age_days: body.max_artifact_age_days,
        min_health_score: body.min_health_score,
        auto_promote: body.auto_promote,
    };
    let rule = service.create(input).await?;
    Ok(Json(rule_to_response(rule)))
}

/// Get a promotion rule by ID
#[utoipa::path(
    get,
    path = "/{id}",
    context_path = "/api/v1/promotion-rules",
    tag = "promotion",
    params(
        ("id" = Uuid, Path, description = "Promotion rule ID"),
    ),
    responses(
        (status = 200, description = "Promotion rule details", body = PromotionRuleResponse),
        (status = 404, description = "Rule not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn get_rule(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<PromotionRuleResponse>> {
    let service = PromotionRuleService::new(state.db.clone());
    let rule = service.get(id).await?;
    Ok(Json(rule_to_response(rule)))
}

/// Update a promotion rule
#[utoipa::path(
    put,
    path = "/{id}",
    context_path = "/api/v1/promotion-rules",
    tag = "promotion",
    params(
        ("id" = Uuid, Path, description = "Promotion rule ID"),
    ),
    request_body = UpdateRuleRequest,
    responses(
        (status = 200, description = "Promotion rule updated", body = PromotionRuleResponse),
        (status = 404, description = "Rule not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn update_rule(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateRuleRequest>,
) -> Result<Json<PromotionRuleResponse>> {
    let service = PromotionRuleService::new(state.db.clone());
    let input = UpdatePromotionRuleInput {
        name: body.name,
        is_enabled: body.is_enabled,
        max_cve_severity: body.max_cve_severity,
        allowed_licenses: body.allowed_licenses,
        require_signature: body.require_signature,
        min_staging_hours: body.min_staging_hours,
        max_artifact_age_days: body.max_artifact_age_days,
        min_health_score: body.min_health_score,
        auto_promote: body.auto_promote,
    };
    let rule = service.update(id, input).await?;
    Ok(Json(rule_to_response(rule)))
}

/// Delete a promotion rule
#[utoipa::path(
    delete,
    path = "/{id}",
    context_path = "/api/v1/promotion-rules",
    tag = "promotion",
    params(
        ("id" = Uuid, Path, description = "Promotion rule ID"),
    ),
    responses(
        (status = 200, description = "Promotion rule deleted"),
        (status = 404, description = "Rule not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn delete_rule(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>> {
    let service = PromotionRuleService::new(state.db.clone());
    service.delete(id).await?;
    Ok(Json(serde_json::json!({ "deleted": true })))
}

/// Dry-run evaluate a rule against all artifacts in its source repository
#[utoipa::path(
    post,
    path = "/{id}/evaluate",
    context_path = "/api/v1/promotion-rules",
    tag = "promotion",
    params(
        ("id" = Uuid, Path, description = "Promotion rule ID to evaluate"),
    ),
    responses(
        (status = 200, description = "Evaluation results", body = BulkEvaluationResponse),
        (status = 404, description = "Rule not found", body = crate::api::openapi::ErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
async fn evaluate_rule(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<BulkEvaluationResponse>> {
    let service = PromotionRuleService::new(state.db.clone());
    let rule = service.get(id).await?;

    // Get all non-deleted artifacts in the source repo
    let artifact_ids: Vec<Uuid> = sqlx::query_scalar::<_, Uuid>(
        r#"SELECT id FROM artifacts WHERE repository_id = $1 AND is_deleted = false ORDER BY created_at DESC"#,
    )
    .bind(rule.source_repo_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| crate::error::AppError::Database(e.to_string()))?;

    let mut entries = Vec::new();
    let mut passed_count = 0;
    let mut failed_count = 0;

    for artifact_id in &artifact_ids {
        let eval = service.evaluate_artifact(*artifact_id, &rule).await?;
        if eval.passed {
            passed_count += 1;
        } else {
            failed_count += 1;
        }
        entries.push(ArtifactEvalEntry {
            artifact_id: *artifact_id,
            passed: eval.passed,
            violations: eval.violations,
        });
    }

    Ok(Json(BulkEvaluationResponse {
        rule_id: rule.id,
        rule_name: rule.name,
        total_artifacts: artifact_ids.len(),
        passed: passed_count,
        failed: failed_count,
        results: entries,
    }))
}

// ---------------------------------------------------------------------------
// OpenAPI doc
// ---------------------------------------------------------------------------

#[derive(OpenApi)]
#[openapi(
    paths(
        list_rules,
        create_rule,
        get_rule,
        update_rule,
        delete_rule,
        evaluate_rule,
    ),
    components(schemas(
        CreateRuleRequest,
        UpdateRuleRequest,
        PromotionRuleResponse,
        PromotionRuleListResponse,
        RuleEvaluationResponse,
        BulkEvaluationResponse,
        ArtifactEvalEntry,
    )),
    tags((name = "promotion", description = "Staging-to-release artifact promotion"))
)]
pub struct PromotionRulesApiDoc;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_rule_request_deserialization_minimal() {
        let json = r#"{
            "name": "staging-to-prod",
            "source_repo_id": "00000000-0000-0000-0000-000000000001",
            "target_repo_id": "00000000-0000-0000-0000-000000000002"
        }"#;
        let req: CreateRuleRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "staging-to-prod");
        assert!(req.is_enabled);
        assert!(req.auto_promote);
        assert_eq!(req.max_cve_severity, Some("medium".to_string()));
        assert!(!req.require_signature);
        assert!(req.allowed_licenses.is_none());
        assert!(req.min_staging_hours.is_none());
        assert!(req.max_artifact_age_days.is_none());
        assert!(req.min_health_score.is_none());
    }

    #[test]
    fn test_create_rule_request_deserialization_full() {
        let json = r#"{
            "name": "strict-gate",
            "source_repo_id": "00000000-0000-0000-0000-000000000001",
            "target_repo_id": "00000000-0000-0000-0000-000000000002",
            "is_enabled": false,
            "max_cve_severity": "high",
            "allowed_licenses": ["MIT", "Apache-2.0"],
            "require_signature": true,
            "min_staging_hours": 48,
            "max_artifact_age_days": 90,
            "min_health_score": 80,
            "auto_promote": false
        }"#;
        let req: CreateRuleRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "strict-gate");
        assert!(!req.is_enabled);
        assert_eq!(req.max_cve_severity, Some("high".to_string()));
        assert_eq!(
            req.allowed_licenses,
            Some(vec!["MIT".to_string(), "Apache-2.0".to_string()])
        );
        assert!(req.require_signature);
        assert_eq!(req.min_staging_hours, Some(48));
        assert_eq!(req.max_artifact_age_days, Some(90));
        assert_eq!(req.min_health_score, Some(80));
        assert!(!req.auto_promote);
    }

    #[test]
    fn test_update_rule_request_partial() {
        let json = r#"{"name": "renamed-rule", "is_enabled": false}"#;
        let req: UpdateRuleRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, Some("renamed-rule".to_string()));
        assert_eq!(req.is_enabled, Some(false));
        assert!(req.max_cve_severity.is_none());
        assert!(req.require_signature.is_none());
    }

    #[test]
    fn test_update_rule_request_empty() {
        let json = r#"{}"#;
        let req: UpdateRuleRequest = serde_json::from_str(json).unwrap();
        assert!(req.name.is_none());
        assert!(req.is_enabled.is_none());
        assert!(req.auto_promote.is_none());
    }

    #[test]
    fn test_promotion_rule_response_serialization() {
        let resp = PromotionRuleResponse {
            id: Uuid::nil(),
            name: "test-rule".to_string(),
            source_repo_id: Uuid::nil(),
            target_repo_id: Uuid::nil(),
            is_enabled: true,
            max_cve_severity: Some("high".to_string()),
            allowed_licenses: Some(vec!["MIT".to_string()]),
            require_signature: false,
            min_staging_hours: Some(24),
            max_artifact_age_days: None,
            min_health_score: Some(75),
            auto_promote: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let json: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["name"], "test-rule");
        assert_eq!(json["max_cve_severity"], "high");
        assert_eq!(json["min_staging_hours"], 24);
        assert!(json["max_artifact_age_days"].is_null());
    }

    #[test]
    fn test_promotion_rule_response_all_fields_present() {
        let resp = PromotionRuleResponse {
            id: Uuid::nil(),
            name: "contract-test".to_string(),
            source_repo_id: Uuid::nil(),
            target_repo_id: Uuid::nil(),
            is_enabled: true,
            max_cve_severity: None,
            allowed_licenses: None,
            require_signature: false,
            min_staging_hours: None,
            max_artifact_age_days: None,
            min_health_score: None,
            auto_promote: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let json: serde_json::Value = serde_json::to_value(&resp).unwrap();
        for field in [
            "id",
            "name",
            "source_repo_id",
            "target_repo_id",
            "is_enabled",
            "max_cve_severity",
            "allowed_licenses",
            "require_signature",
            "min_staging_hours",
            "max_artifact_age_days",
            "min_health_score",
            "auto_promote",
            "created_at",
            "updated_at",
        ] {
            assert!(
                json.get(field).is_some(),
                "Missing field '{}' in PromotionRuleResponse JSON",
                field
            );
        }
        let obj = json.as_object().unwrap();
        assert_eq!(obj.len(), 14, "PromotionRuleResponse should have 14 fields");
    }

    #[test]
    fn test_list_response_serialization() {
        let resp = PromotionRuleListResponse {
            items: vec![],
            total: 0,
        };
        let json: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["total"], 0);
        assert!(json["items"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_rule_evaluation_response_serialization() {
        let resp = RuleEvaluationResponse {
            rule_id: Uuid::nil(),
            rule_name: "test".to_string(),
            passed: false,
            violations: vec!["CVE threshold exceeded".to_string()],
        };
        let json: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["passed"], false);
        assert_eq!(json["violations"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_bulk_evaluation_response_serialization() {
        let resp = BulkEvaluationResponse {
            rule_id: Uuid::nil(),
            rule_name: "gate".to_string(),
            total_artifacts: 3,
            passed: 2,
            failed: 1,
            results: vec![
                ArtifactEvalEntry {
                    artifact_id: Uuid::nil(),
                    passed: true,
                    violations: vec![],
                },
                ArtifactEvalEntry {
                    artifact_id: Uuid::nil(),
                    passed: false,
                    violations: vec!["too old".to_string()],
                },
            ],
        };
        let json: serde_json::Value = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["total_artifacts"], 3);
        assert_eq!(json["passed"], 2);
        assert_eq!(json["failed"], 1);
        assert_eq!(json["results"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_rule_to_response_mapping() {
        let rule = PromotionRule {
            id: Uuid::nil(),
            name: "test".to_string(),
            source_repo_id: Uuid::nil(),
            target_repo_id: Uuid::nil(),
            is_enabled: true,
            max_cve_severity: Some("medium".to_string()),
            allowed_licenses: None,
            require_signature: false,
            min_staging_hours: Some(12),
            max_artifact_age_days: None,
            min_health_score: None,
            auto_promote: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let resp = rule_to_response(rule);
        assert_eq!(resp.name, "test");
        assert_eq!(resp.min_staging_hours, Some(12));
        assert!(resp.is_enabled);
    }

    #[test]
    fn test_eval_to_response_mapping() {
        let eval = RuleEvaluationResult {
            rule_id: Uuid::nil(),
            rule_name: "eval-test".to_string(),
            passed: false,
            violations: vec!["v1".to_string(), "v2".to_string()],
        };
        let resp = eval_to_response(&eval);
        assert_eq!(resp.rule_name, "eval-test");
        assert!(!resp.passed);
        assert_eq!(resp.violations.len(), 2);
    }
}
