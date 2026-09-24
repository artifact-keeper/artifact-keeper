//! Analytics and reporting API handlers.

use axum::{
    extract::{Path, Query, State},
    routing::get,
    Json, Router,
};
use chrono::NaiveDate;
use serde::Deserialize;
use utoipa::{IntoParams, OpenApi, ToSchema};
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

#[derive(Debug, Deserialize, ToSchema, IntoParams)]
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

#[derive(Debug, Deserialize, ToSchema, IntoParams)]
pub struct StaleQuery {
    pub days: Option<i32>,
    pub limit: Option<i64>,
}

/// GET /api/v1/admin/analytics/storage/trend
#[utoipa::path(
    get,
    path = "/storage/trend",
    context_path = "/api/v1/admin/analytics",
    tag = "analytics",
    params(DateRangeQuery),
    responses(
        (status = 200, description = "Storage trend over date range", body = Vec<crate::services::analytics_service::StorageSnapshot>),
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    get,
    path = "/storage/breakdown",
    context_path = "/api/v1/admin/analytics",
    tag = "analytics",
    responses(
        (status = 200, description = "Per-repository storage breakdown", body = Vec<crate::services::analytics_service::RepositoryStorageBreakdown>),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_storage_breakdown(
    State(state): State<SharedState>,
) -> Result<Json<Vec<crate::services::analytics_service::RepositoryStorageBreakdown>>> {
    let service = AnalyticsService::new(state.db.clone());
    let breakdown = service.get_storage_breakdown().await?;
    Ok(Json(breakdown))
}

/// GET /api/v1/admin/analytics/storage/growth
#[utoipa::path(
    get,
    path = "/storage/growth",
    context_path = "/api/v1/admin/analytics",
    tag = "analytics",
    params(DateRangeQuery),
    responses(
        (status = 200, description = "Growth summary for date range", body = crate::services::analytics_service::GrowthSummary),
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    get,
    path = "/artifacts/stale",
    context_path = "/api/v1/admin/analytics",
    tag = "analytics",
    params(StaleQuery),
    responses(
        (status = 200, description = "List of stale artifacts", body = Vec<crate::services::analytics_service::StaleArtifact>),
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    get,
    path = "/downloads/trend",
    context_path = "/api/v1/admin/analytics",
    tag = "analytics",
    params(DateRangeQuery),
    responses(
        (status = 200, description = "Download trends over date range", body = Vec<crate::services::analytics_service::DownloadTrend>),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_download_trends(
    State(state): State<SharedState>,
    Query(query): Query<DateRangeQuery>,
) -> Result<Json<Vec<crate::services::analytics_service::DownloadTrend>>> {
    let (from, to) = query.parse_dates();
    let service = AnalyticsService::new(state.db.clone());
    let trends = service.get_download_trends(from, to).await?;
    Ok(Json(trends))
}

/// GET /api/v1/admin/analytics/repositories/{id}/trend
#[utoipa::path(
    get,
    path = "/repositories/{id}/trend",
    context_path = "/api/v1/admin/analytics",
    tag = "analytics",
    params(
        ("id" = Uuid, Path, description = "Repository ID"),
        DateRangeQuery,
    ),
    responses(
        (status = 200, description = "Repository storage trend over date range", body = Vec<crate::services::analytics_service::RepositorySnapshot>),
    ),
    security(("bearer_auth" = []))
)]
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
#[utoipa::path(
    post,
    path = "/snapshot",
    context_path = "/api/v1/admin/analytics",
    tag = "analytics",
    responses(
        (status = 200, description = "Snapshot captured successfully", body = crate::services::analytics_service::StorageSnapshot),
    ),
    security(("bearer_auth" = []))
)]
pub async fn capture_snapshot(
    State(state): State<SharedState>,
) -> Result<Json<crate::services::analytics_service::StorageSnapshot>> {
    let service = AnalyticsService::new(state.db.clone());
    let snapshot = service.capture_daily_snapshot().await?;
    let _ = service.capture_repository_snapshots().await;
    Ok(Json(snapshot))
}

#[derive(OpenApi)]
#[openapi(
    paths(
        get_storage_trend,
        get_storage_breakdown,
        get_growth_summary,
        get_stale_artifacts,
        get_download_trends,
        get_repository_trend,
        capture_snapshot,
    ),
    components(schemas(
        DateRangeQuery,
        StaleQuery,
        crate::services::analytics_service::StorageSnapshot,
        crate::services::analytics_service::RepositorySnapshot,
        crate::services::analytics_service::RepositoryStorageBreakdown,
        crate::services::analytics_service::GrowthSummary,
        crate::services::analytics_service::StaleArtifact,
        crate::services::analytics_service::DownloadTrend,
    ))
)]
pub struct AnalyticsApiDoc;

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;

    // ── DateRangeQuery::parse_dates tests ────────────────────────────

    #[test]
    fn test_parse_dates_both_provided() {
        let query = DateRangeQuery {
            from: Some("2024-01-01".to_string()),
            to: Some("2024-01-31".to_string()),
        };
        let (from, to) = query.parse_dates();
        assert_eq!(from, NaiveDate::from_ymd_opt(2024, 1, 1).unwrap());
        assert_eq!(to, NaiveDate::from_ymd_opt(2024, 1, 31).unwrap());
    }

    #[test]
    fn test_parse_dates_neither_provided() {
        let query = DateRangeQuery {
            from: None,
            to: None,
        };
        let (from, to) = query.parse_dates();
        let today = chrono::Utc::now().date_naive();
        assert_eq!(to, today);
        assert_eq!(from, today - chrono::Duration::days(30));
    }

    #[test]
    fn test_parse_dates_only_to_provided() {
        let query = DateRangeQuery {
            from: None,
            to: Some("2024-06-15".to_string()),
        };
        let (from, to) = query.parse_dates();
        assert_eq!(to, NaiveDate::from_ymd_opt(2024, 6, 15).unwrap());
        assert_eq!(
            from,
            NaiveDate::from_ymd_opt(2024, 6, 15).unwrap() - chrono::Duration::days(30)
        );
    }

    #[test]
    fn test_parse_dates_only_from_provided() {
        let query = DateRangeQuery {
            from: Some("2024-03-01".to_string()),
            to: None,
        };
        let (from, to) = query.parse_dates();
        let today = chrono::Utc::now().date_naive();
        assert_eq!(to, today);
        assert_eq!(from, NaiveDate::from_ymd_opt(2024, 3, 1).unwrap());
    }

    #[test]
    fn test_parse_dates_invalid_from_uses_default() {
        let query = DateRangeQuery {
            from: Some("not-a-date".to_string()),
            to: Some("2024-06-15".to_string()),
        };
        let (from, to) = query.parse_dates();
        assert_eq!(to, NaiveDate::from_ymd_opt(2024, 6, 15).unwrap());
        // Invalid from falls back to to - 30 days
        assert_eq!(
            from,
            NaiveDate::from_ymd_opt(2024, 6, 15).unwrap() - chrono::Duration::days(30)
        );
    }

    #[test]
    fn test_parse_dates_invalid_to_uses_today() {
        let query = DateRangeQuery {
            from: Some("2024-01-01".to_string()),
            to: Some("invalid".to_string()),
        };
        let (from, to) = query.parse_dates();
        let today = chrono::Utc::now().date_naive();
        assert_eq!(to, today);
        assert_eq!(from, NaiveDate::from_ymd_opt(2024, 1, 1).unwrap());
    }

    #[test]
    fn test_parse_dates_both_invalid() {
        let query = DateRangeQuery {
            from: Some("xxx".to_string()),
            to: Some("yyy".to_string()),
        };
        let (from, to) = query.parse_dates();
        let today = chrono::Utc::now().date_naive();
        assert_eq!(to, today);
        assert_eq!(from, today - chrono::Duration::days(30));
    }

    #[test]
    fn test_parse_dates_empty_strings() {
        let query = DateRangeQuery {
            from: Some(String::new()),
            to: Some(String::new()),
        };
        let (from, to) = query.parse_dates();
        let today = chrono::Utc::now().date_naive();
        assert_eq!(to, today);
        assert_eq!(from, today - chrono::Duration::days(30));
    }

    // ── DateRangeQuery deserialization tests ─────────────────────────

    #[test]
    fn test_date_range_query_deserialize_full() {
        let json = r#"{"from": "2024-01-01", "to": "2024-12-31"}"#;
        let q: DateRangeQuery = serde_json::from_str(json).unwrap();
        assert_eq!(q.from, Some("2024-01-01".to_string()));
        assert_eq!(q.to, Some("2024-12-31".to_string()));
    }

    #[test]
    fn test_date_range_query_deserialize_empty() {
        let json = r#"{}"#;
        let q: DateRangeQuery = serde_json::from_str(json).unwrap();
        assert!(q.from.is_none());
        assert!(q.to.is_none());
    }

    // ── StaleQuery deserialization tests ─────────────────────────────

    #[test]
    fn test_stale_query_defaults() {
        let json = r#"{}"#;
        let q: StaleQuery = serde_json::from_str(json).unwrap();
        assert!(q.days.is_none());
        assert!(q.limit.is_none());
    }

    #[test]
    fn test_stale_query_with_values() {
        let json = r#"{"days": 60, "limit": 50}"#;
        let q: StaleQuery = serde_json::from_str(json).unwrap();
        assert_eq!(q.days, Some(60));
        assert_eq!(q.limit, Some(50));
    }

    #[test]
    fn test_stale_query_default_days_value() {
        let q = StaleQuery {
            days: None,
            limit: None,
        };
        let days = q.days.unwrap_or(90);
        assert_eq!(days, 90);
    }

    #[test]
    fn test_stale_query_default_limit_value() {
        let q = StaleQuery {
            days: None,
            limit: None,
        };
        let limit = q.limit.unwrap_or(100);
        assert_eq!(limit, 100);
    }

    #[test]
    fn test_stale_query_custom_days() {
        let q = StaleQuery {
            days: Some(30),
            limit: None,
        };
        let days = q.days.unwrap_or(90);
        assert_eq!(days, 30);
    }
}
