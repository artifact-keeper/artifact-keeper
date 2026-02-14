//! Telemetry and crash reporting API handlers.

use axum::{
    extract::{Extension, Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::crash_reporting_service::{
    CrashReport, CrashReportingService, TelemetrySettings,
};

#[derive(OpenApi)]
#[openapi(
    paths(
        get_settings,
        update_settings,
        list_crashes,
        list_pending_crashes,
        get_crash,
        delete_crash,
        submit_crashes,
    ),
    components(schemas(
        SubmitCrashesRequest,
        CrashListResponse,
        SubmitResponse,
        TelemetrySettings,
        CrashReport,
    ))
)]
pub struct TelemetryApiDoc;

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/settings", get(get_settings).post(update_settings))
        .route("/crashes", get(list_crashes))
        .route("/crashes/pending", get(list_pending_crashes))
        .route("/crashes/:id", get(get_crash).delete(delete_crash))
        .route("/crashes/submit", post(submit_crashes))
}

/// GET /api/v1/admin/telemetry/settings
#[utoipa::path(
    get,
    path = "/settings",
    context_path = "/api/v1/admin/telemetry",
    tag = "telemetry",
    operation_id = "get_telemetry_settings",
    responses(
        (status = 200, description = "Current telemetry settings", body = TelemetrySettings),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn get_settings(State(state): State<SharedState>) -> Result<Json<TelemetrySettings>> {
    let service = CrashReportingService::new(state.db.clone());
    let settings = service.get_settings().await?;
    Ok(Json(settings))
}

/// POST /api/v1/admin/telemetry/settings
#[utoipa::path(
    post,
    path = "/settings",
    context_path = "/api/v1/admin/telemetry",
    tag = "telemetry",
    operation_id = "update_telemetry_settings",
    request_body = TelemetrySettings,
    responses(
        (status = 200, description = "Settings updated", body = TelemetrySettings),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn update_settings(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(settings): Json<TelemetrySettings>,
) -> Result<Json<TelemetrySettings>> {
    if !auth.is_admin {
        return Err(AppError::Unauthorized(
            "Admin privileges required".to_string(),
        ));
    }
    let service = CrashReportingService::new(state.db.clone());
    service.update_settings(&settings).await?;
    Ok(Json(settings))
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ListCrashesQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

/// GET /api/v1/admin/telemetry/crashes
#[utoipa::path(
    get,
    path = "/crashes",
    context_path = "/api/v1/admin/telemetry",
    tag = "telemetry",
    params(ListCrashesQuery),
    responses(
        (status = 200, description = "Paginated crash reports", body = CrashListResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn list_crashes(
    State(state): State<SharedState>,
    Query(query): Query<ListCrashesQuery>,
) -> Result<Json<CrashListResponse>> {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = ((page - 1) * per_page) as i64;

    let service = CrashReportingService::new(state.db.clone());
    let (crashes, total) = service.list_all(offset, per_page as i64).await?;

    Ok(Json(CrashListResponse {
        items: crashes,
        total,
    }))
}

/// GET /api/v1/admin/telemetry/crashes/pending
#[utoipa::path(
    get,
    path = "/crashes/pending",
    context_path = "/api/v1/admin/telemetry",
    tag = "telemetry",
    responses(
        (status = 200, description = "Pending crash reports", body = Vec<CrashReport>),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn list_pending_crashes(
    State(state): State<SharedState>,
) -> Result<Json<Vec<CrashReport>>> {
    let service = CrashReportingService::new(state.db.clone());
    let pending = service.list_pending(50).await?;
    Ok(Json(pending))
}

/// GET /api/v1/admin/telemetry/crashes/:id
#[utoipa::path(
    get,
    path = "/crashes/{id}",
    context_path = "/api/v1/admin/telemetry",
    tag = "telemetry",
    params(
        ("id" = Uuid, Path, description = "Crash report ID"),
    ),
    responses(
        (status = 200, description = "Crash report details", body = CrashReport),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn get_crash(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<CrashReport>> {
    let service = CrashReportingService::new(state.db.clone());
    let report = service.get_report(id).await?;
    Ok(Json(report))
}

/// DELETE /api/v1/admin/telemetry/crashes/:id
#[utoipa::path(
    delete,
    path = "/crashes/{id}",
    context_path = "/api/v1/admin/telemetry",
    tag = "telemetry",
    params(
        ("id" = Uuid, Path, description = "Crash report ID"),
    ),
    responses(
        (status = 200, description = "Crash report deleted"),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn delete_crash(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    if !auth.is_admin {
        return Err(AppError::Unauthorized(
            "Admin privileges required".to_string(),
        ));
    }
    let service = CrashReportingService::new(state.db.clone());
    service.delete_report(id).await?;
    Ok(())
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SubmitCrashesRequest {
    pub ids: Vec<Uuid>,
}

/// POST /api/v1/admin/telemetry/crashes/submit
#[utoipa::path(
    post,
    path = "/crashes/submit",
    context_path = "/api/v1/admin/telemetry",
    tag = "telemetry",
    request_body = SubmitCrashesRequest,
    responses(
        (status = 200, description = "Crashes submitted", body = SubmitResponse),
    ),
    security(("bearer_auth" = [])),
)]
pub async fn submit_crashes(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(payload): Json<SubmitCrashesRequest>,
) -> Result<Json<SubmitResponse>> {
    if !auth.is_admin {
        return Err(AppError::Unauthorized(
            "Admin privileges required".to_string(),
        ));
    }
    let service = CrashReportingService::new(state.db.clone());
    let marked = service.mark_submitted(&payload.ids).await?;
    Ok(Json(SubmitResponse {
        marked_submitted: marked,
    }))
}

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct CrashListResponse {
    pub items: Vec<CrashReport>,
    pub total: i64,
}

#[derive(Debug, serde::Serialize, ToSchema)]
pub struct SubmitResponse {
    pub marked_submitted: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ListCrashesQuery deserialization tests ───────────────────────

    #[test]
    fn test_list_crashes_query_empty() {
        let json = r#"{}"#;
        let q: ListCrashesQuery = serde_json::from_str(json).unwrap();
        assert!(q.page.is_none());
        assert!(q.per_page.is_none());
    }

    #[test]
    fn test_list_crashes_query_with_page() {
        let json = r#"{"page": 3}"#;
        let q: ListCrashesQuery = serde_json::from_str(json).unwrap();
        assert_eq!(q.page, Some(3));
        assert!(q.per_page.is_none());
    }

    #[test]
    fn test_list_crashes_query_with_per_page() {
        let json = r#"{"per_page": 50}"#;
        let q: ListCrashesQuery = serde_json::from_str(json).unwrap();
        assert!(q.page.is_none());
        assert_eq!(q.per_page, Some(50));
    }

    #[test]
    fn test_list_crashes_query_both_params() {
        let json = r#"{"page": 2, "per_page": 25}"#;
        let q: ListCrashesQuery = serde_json::from_str(json).unwrap();
        assert_eq!(q.page, Some(2));
        assert_eq!(q.per_page, Some(25));
    }

    // ── Pagination logic tests ──────────────────────────────────────

    #[test]
    fn test_pagination_defaults() {
        let query = ListCrashesQuery {
            page: None,
            per_page: None,
        };
        let page = query.page.unwrap_or(1).max(1);
        let per_page = query.per_page.unwrap_or(20).min(100);
        let offset = ((page - 1) * per_page) as i64;
        assert_eq!(page, 1);
        assert_eq!(per_page, 20);
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_pagination_page_zero_clamped_to_one() {
        let query = ListCrashesQuery {
            page: Some(0),
            per_page: None,
        };
        let page = query.page.unwrap_or(1).max(1);
        assert_eq!(page, 1);
    }

    #[test]
    fn test_pagination_per_page_clamped_to_100() {
        let query = ListCrashesQuery {
            page: None,
            per_page: Some(500),
        };
        let per_page = query.per_page.unwrap_or(20).min(100);
        assert_eq!(per_page, 100);
    }

    #[test]
    fn test_pagination_offset_calculation() {
        let query = ListCrashesQuery {
            page: Some(3),
            per_page: Some(25),
        };
        let page = query.page.unwrap_or(1).max(1);
        let per_page = query.per_page.unwrap_or(20).min(100);
        let offset = ((page - 1) * per_page) as i64;
        assert_eq!(offset, 50);
    }

    #[test]
    fn test_pagination_first_page_zero_offset() {
        let query = ListCrashesQuery {
            page: Some(1),
            per_page: Some(10),
        };
        let page = query.page.unwrap_or(1).max(1);
        let per_page = query.per_page.unwrap_or(20).min(100);
        let offset = ((page - 1) * per_page) as i64;
        assert_eq!(offset, 0);
    }

    // ── SubmitCrashesRequest deserialization tests ───────────────────

    #[test]
    fn test_submit_crashes_request_with_ids() {
        let json = r#"{"ids": ["550e8400-e29b-41d4-a716-446655440000", "6ba7b810-9dad-11d1-80b4-00c04fd430c8"]}"#;
        let req: SubmitCrashesRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.ids.len(), 2);
    }

    #[test]
    fn test_submit_crashes_request_empty_ids() {
        let json = r#"{"ids": []}"#;
        let req: SubmitCrashesRequest = serde_json::from_str(json).unwrap();
        assert!(req.ids.is_empty());
    }

    #[test]
    fn test_submit_crashes_request_missing_ids_fails() {
        let json = r#"{}"#;
        let result: std::result::Result<SubmitCrashesRequest, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // ── CrashListResponse serialization tests ───────────────────────

    #[test]
    fn test_crash_list_response_serialization_empty() {
        let response = CrashListResponse {
            items: vec![],
            total: 0,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert!(json["items"].as_array().unwrap().is_empty());
        assert_eq!(json["total"], 0);
    }

    #[test]
    fn test_crash_list_response_total_independent() {
        let response = CrashListResponse {
            items: vec![],
            total: 150,
        };
        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["total"], 150);
    }

    // ── SubmitResponse serialization tests ──────────────────────────

    #[test]
    fn test_submit_response_serialization() {
        let resp = SubmitResponse {
            marked_submitted: 5,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["marked_submitted"], 5);
    }

    #[test]
    fn test_submit_response_zero() {
        let resp = SubmitResponse {
            marked_submitted: 0,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["marked_submitted"], 0);
    }

    // ── TelemetrySettings tests ─────────────────────────────────────

    #[test]
    fn test_telemetry_settings_default() {
        let settings = TelemetrySettings::default();
        assert!(!settings.enabled);
        assert!(settings.review_before_send);
        assert_eq!(settings.scrub_level, "standard");
        assert!(!settings.include_logs);
    }

    #[test]
    fn test_telemetry_settings_roundtrip() {
        let settings = TelemetrySettings {
            enabled: true,
            review_before_send: false,
            scrub_level: "aggressive".to_string(),
            include_logs: true,
        };
        let json_str = serde_json::to_string(&settings).unwrap();
        let deserialized: TelemetrySettings = serde_json::from_str(&json_str).unwrap();
        assert!(deserialized.enabled);
        assert!(!deserialized.review_before_send);
        assert_eq!(deserialized.scrub_level, "aggressive");
        assert!(deserialized.include_logs);
    }
}
