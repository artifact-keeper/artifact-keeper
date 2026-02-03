//! Analytics and reporting API handlers.

use axum::{
    extract::{Path, Query, State},
    routing::get,
    Json, Router,
};
use chrono::NaiveDate;
use serde::Deserialize;
use uuid::Uuid;

use crate::api::SharedState;
use crate::error::Result;
use crate::services::analytics_service::AnalyticsService;

pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/storage/trend", get(get_storage_trend))
        .route("/storage/breakdown", get(get_storage_breakdown))
        .route("/storage/growth", get(get_growth_summary))
        .route("/artifacts/stale", get(get_stale_artifacts))
        .route("/downloads/trend", get(get_download_trends))
        .route("/repositories/:id/trend", get(get_repository_trend))
        .route("/snapshot", axum::routing::post(capture_snapshot))
}

#[derive(Debug, Deserialize)]
pub struct DateRangeQuery {
    pub from: Option<String>,
    pub to: Option<String>,
}

impl DateRangeQuery {
    fn parse_dates(&self) -> (NaiveDate, NaiveDate) {
        let to = self
            .to
            .as_ref()
            .and_then(|s| NaiveDate::parse_from_str(s, "%Y-%m-%d").ok())
            .unwrap_or_else(|| chrono::Utc::now().date_naive());
        let from = self
            .from
            .as_ref()
            .and_then(|s| NaiveDate::parse_from_str(s, "%Y-%m-%d").ok())
            .unwrap_or_else(|| to - chrono::Duration::days(30));
        (from, to)
    }
}

#[derive(Debug, Deserialize)]
pub struct StaleQuery {
    pub days: Option<i32>,
    pub limit: Option<i64>,
}

/// GET /api/v1/admin/analytics/storage/trend
pub async fn get_storage_trend(
    State(state): State<SharedState>,
    Query(query): Query<DateRangeQuery>,
) -> Result<Json<Vec<crate::services::analytics_service::StorageSnapshot>>> {
    let (from, to) = query.parse_dates();
    let service = AnalyticsService::new(state.db.clone());
    let trend = service.get_storage_trend(from, to).await?;
    Ok(Json(trend))
}

/// GET /api/v1/admin/analytics/storage/breakdown
pub async fn get_storage_breakdown(
    State(state): State<SharedState>,
) -> Result<Json<Vec<crate::services::analytics_service::RepositoryStorageBreakdown>>> {
    let service = AnalyticsService::new(state.db.clone());
    let breakdown = service.get_storage_breakdown().await?;
    Ok(Json(breakdown))
}

/// GET /api/v1/admin/analytics/storage/growth
pub async fn get_growth_summary(
    State(state): State<SharedState>,
    Query(query): Query<DateRangeQuery>,
) -> Result<Json<crate::services::analytics_service::GrowthSummary>> {
    let (from, to) = query.parse_dates();
    let service = AnalyticsService::new(state.db.clone());
    let summary = service.get_growth_summary(from, to).await?;
    Ok(Json(summary))
}

/// GET /api/v1/admin/analytics/artifacts/stale
pub async fn get_stale_artifacts(
    State(state): State<SharedState>,
    Query(query): Query<StaleQuery>,
) -> Result<Json<Vec<crate::services::analytics_service::StaleArtifact>>> {
    let days = query.days.unwrap_or(90);
    let limit = query.limit.unwrap_or(100);
    let service = AnalyticsService::new(state.db.clone());
    let stale = service.get_stale_artifacts(days, limit).await?;
    Ok(Json(stale))
}

/// GET /api/v1/admin/analytics/downloads/trend
pub async fn get_download_trends(
    State(state): State<SharedState>,
    Query(query): Query<DateRangeQuery>,
) -> Result<Json<Vec<crate::services::analytics_service::DownloadTrend>>> {
    let (from, to) = query.parse_dates();
    let service = AnalyticsService::new(state.db.clone());
    let trends = service.get_download_trends(from, to).await?;
    Ok(Json(trends))
}

/// GET /api/v1/admin/analytics/repositories/:id/trend
pub async fn get_repository_trend(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
    Query(query): Query<DateRangeQuery>,
) -> Result<Json<Vec<crate::services::analytics_service::RepositorySnapshot>>> {
    let (from, to) = query.parse_dates();
    let service = AnalyticsService::new(state.db.clone());
    let trend = service.get_repository_trend(id, from, to).await?;
    Ok(Json(trend))
}

/// POST /api/v1/admin/analytics/snapshot - manually trigger a snapshot
pub async fn capture_snapshot(
    State(state): State<SharedState>,
) -> Result<Json<crate::services::analytics_service::StorageSnapshot>> {
    let service = AnalyticsService::new(state.db.clone());
    let snapshot = service.capture_daily_snapshot().await?;
    let _ = service.capture_repository_snapshots().await;
    Ok(Json(snapshot))
}
