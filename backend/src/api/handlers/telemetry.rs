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
    )),
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
