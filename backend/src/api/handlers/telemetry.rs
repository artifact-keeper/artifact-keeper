//! Telemetry and crash reporting API handlers.

use axum::{
    extract::{Extension, Path, Query, State},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::crash_reporting_service::{
    CrashReport, CrashReportingService, TelemetrySettings,
};

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/settings", get(get_settings).post(update_settings))
        .route("/crashes", get(list_crashes))
        .route("/crashes/pending", get(list_pending_crashes))
        .route("/crashes/:id", get(get_crash).delete(delete_crash))
        .route("/crashes/submit", post(submit_crashes))
}

/// GET /api/v1/admin/telemetry/settings
pub async fn get_settings(State(state): State<SharedState>) -> Result<Json<TelemetrySettings>> {
    let service = CrashReportingService::new(state.db.clone());
    let settings = service.get_settings().await?;
    Ok(Json(settings))
}

/// POST /api/v1/admin/telemetry/settings
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

#[derive(Debug, Deserialize)]
pub struct ListCrashesQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

/// GET /api/v1/admin/telemetry/crashes
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
pub async fn list_pending_crashes(
    State(state): State<SharedState>,
) -> Result<Json<Vec<CrashReport>>> {
    let service = CrashReportingService::new(state.db.clone());
    let pending = service.list_pending(50).await?;
    Ok(Json(pending))
}

/// GET /api/v1/admin/telemetry/crashes/:id
pub async fn get_crash(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<CrashReport>> {
    let service = CrashReportingService::new(state.db.clone());
    let report = service.get_report(id).await?;
    Ok(Json(report))
}

/// DELETE /api/v1/admin/telemetry/crashes/:id
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

#[derive(Debug, Deserialize)]
pub struct SubmitCrashesRequest {
    pub ids: Vec<Uuid>,
}

/// POST /api/v1/admin/telemetry/crashes/submit
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

#[derive(Debug, serde::Serialize)]
pub struct CrashListResponse {
    pub items: Vec<CrashReport>,
    pub total: i64,
}

#[derive(Debug, serde::Serialize)]
pub struct SubmitResponse {
    pub marked_submitted: u64,
}
