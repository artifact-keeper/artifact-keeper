//! Admin download-hold observability: hosted and proxy-cache quarantine queues.

use axum::extract::{Extension, Query, State};
use axum::routing::get;
use axum::Json;
use axum::Router;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::dto::Pagination;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::Result;
use crate::services::download_holds_service::{
    classify_hold, normalize_pagination, parse_hold_kinds, remaining_seconds, total_pages,
    DownloadHoldsService, HoldKind, QuarantineHoldRow,
};

pub fn admin_router() -> Router<SharedState> {
    Router::new()
        .route("/summary", get(holds_summary))
        .route("/quarantine", get(list_quarantine))
}

#[derive(Debug, Deserialize, IntoParams, ToSchema)]
pub struct HoldListQuery {
    pub repository_key: Option<String>,
    /// Comma-separated: `active`, `expired`, `rejected`. Default: `active,rejected`.
    pub kind: Option<String>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HoldsSummaryResponse {
    pub age_gate_pending: i64,
    pub quarantine_active: i64,
    pub quarantine_rejected: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct QuarantineHoldResponse {
    /// `hosted` (an `artifacts` row) or `proxy-cache` (`proxy_cache_artifacts`).
    pub source: String,
    /// Present for hosted rows; proxy-cache holds have no `artifacts` identity.
    pub artifact_id: Option<Uuid>,
    pub name: String,
    pub version: Option<String>,
    pub path: String,
    pub repository_key: String,
    pub repository_format: String,
    pub quarantine_status: String,
    pub kind: String,
    pub quarantine_until: Option<chrono::DateTime<chrono::Utc>>,
    pub remaining_seconds: Option<i64>,
    pub quarantine_reason: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub is_blocked: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct QuarantineHoldListResponse {
    pub items: Vec<QuarantineHoldResponse>,
    pub pagination: Pagination,
}

fn svc(state: &SharedState) -> DownloadHoldsService {
    DownloadHoldsService::new(state.db.clone())
}

fn to_quarantine_response(row: QuarantineHoldRow) -> QuarantineHoldResponse {
    let now = chrono::Utc::now();
    let kind = classify_hold(&row.quarantine_status, row.quarantine_until, now)
        .unwrap_or(HoldKind::Active);
    let remaining = if kind == HoldKind::Rejected {
        None
    } else {
        remaining_seconds(row.quarantine_until, now)
    };
    QuarantineHoldResponse {
        source: row.source,
        artifact_id: row.artifact_id,
        name: row.name,
        version: row.version,
        path: row.path,
        repository_key: row.repository_key,
        repository_format: row.repository_format,
        quarantine_status: row.quarantine_status,
        kind: kind.as_str().to_string(),
        quarantine_until: row.quarantine_until,
        remaining_seconds: remaining,
        quarantine_reason: row.quarantine_reason,
        created_at: row.created_at,
        is_blocked: matches!(kind, HoldKind::Active | HoldKind::Rejected),
    }
}

#[utoipa::path(
    get,
    path = "/holds/summary",
    context_path = "/api/v1/admin",
    tag = "holds",
    security(("bearer_auth" = [])),
    responses((status = 200, body = HoldsSummaryResponse))
)]
pub async fn holds_summary(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<HoldsSummaryResponse>> {
    auth.require_admin()?;
    let summary = svc(&state).summary().await?;
    Ok(Json(HoldsSummaryResponse {
        age_gate_pending: summary.age_gate_pending,
        quarantine_active: summary.quarantine_active,
        quarantine_rejected: summary.quarantine_rejected,
    }))
}

#[utoipa::path(
    get,
    path = "/holds/quarantine",
    context_path = "/api/v1/admin",
    tag = "holds",
    security(("bearer_auth" = [])),
    params(HoldListQuery),
    responses((status = 200, body = QuarantineHoldListResponse))
)]
pub async fn list_quarantine(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Query(query): Query<HoldListQuery>,
) -> Result<Json<QuarantineHoldListResponse>> {
    auth.require_admin()?;
    let kinds = parse_hold_kinds(query.kind.as_deref())?;
    let (page, per_page, offset) = normalize_pagination(query.page, query.per_page);
    let (rows, total) = svc(&state)
        .list_quarantine(
            query.repository_key.as_deref(),
            &kinds,
            offset,
            i64::from(per_page),
        )
        .await?;
    Ok(Json(QuarantineHoldListResponse {
        items: rows.into_iter().map(to_quarantine_response).collect(),
        pagination: Pagination {
            page,
            per_page,
            total,
            total_pages: total_pages(total, per_page),
        },
    }))
}

#[derive(OpenApi)]
#[openapi(
    paths(holds_summary, list_quarantine),
    components(schemas(
        HoldsSummaryResponse,
        QuarantineHoldResponse,
        QuarantineHoldListResponse,
        HoldListQuery,
        Pagination,
    )),
    tags((name = "holds", description = "Download-hold observability: hosted and proxy-cache quarantine"))
)]
pub struct DownloadHoldsApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use crate::api::middleware::auth::AuthExtension;
    use crate::error::AppError;
    use uuid::Uuid;

    fn admin() -> AuthExtension {
        tdh::admin_auth(Uuid::new_v4(), "holds-admin")
    }

    fn user() -> AuthExtension {
        tdh::make_auth(Uuid::new_v4(), "holds-user")
    }

    #[test]
    fn admin_router_builds() {
        let _ = admin_router();
    }

    #[tokio::test]
    async fn list_quarantine_rejects_non_admin() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let err = list_quarantine(
            State(fx.state.clone()),
            Extension(user()),
            Query(HoldListQuery {
                repository_key: None,
                kind: None,
                page: None,
                per_page: None,
            }),
        )
        .await
        .expect_err("non-admin must not list holds");
        fx.teardown().await;
        assert!(matches!(err, AppError::Authorization(_)));
    }

    #[tokio::test]
    async fn summary_rejects_non_admin() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let err = holds_summary(State(fx.state.clone()), Extension(user()))
            .await
            .expect_err("non-admin must not read holds summary");
        fx.teardown().await;
        assert!(matches!(err, AppError::Authorization(_)));
    }

    #[tokio::test]
    async fn list_quarantine_admin_sees_seeded_hold() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let artifact_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO artifacts (
                id, repository_id, name, path, size_bytes, checksum_sha256,
                content_type, storage_key, is_deleted,
                quarantine_status, quarantine_until, quarantine_reason
            )
            VALUES ($1, $2, 'held.bin', $3, 4, $4,
                    'application/octet-stream', $5, false,
                    'quarantined', NULL, 'manual hold')
            "#,
        )
        .bind(artifact_id)
        .bind(fx.repo_id)
        .bind(format!("holds/{artifact_id}.bin"))
        .bind(format!("{:064x}", artifact_id.as_u128()))
        .bind(format!("holds/{artifact_id}"))
        .execute(&fx.pool)
        .await
        .expect("insert held artifact");

        let Json(body) = list_quarantine(
            State(fx.state.clone()),
            Extension(admin()),
            Query(HoldListQuery {
                repository_key: Some(fx.repo_key.clone()),
                kind: Some("active".into()),
                page: Some(1),
                per_page: Some(20),
            }),
        )
        .await
        .expect("admin list");
        fx.teardown().await;

        assert_eq!(body.pagination.total, 1);
        assert_eq!(body.items[0].artifact_id, Some(artifact_id));
        assert_eq!(body.items[0].source, "hosted");
        assert_eq!(body.items[0].kind, "active");
        assert!(body.items[0].is_blocked);
        assert_eq!(
            body.items[0].quarantine_reason.as_deref(),
            Some("manual hold")
        );
        assert!(body.items[0].remaining_seconds.is_none());
    }

    #[tokio::test]
    async fn list_quarantine_includes_proxy_cache_hold() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let until = chrono::Utc::now() + chrono::Duration::hours(2);
        sqlx::query(
            r#"
            INSERT INTO proxy_cache_artifacts (
                repository_id, path, storage_key, metadata_key, size_bytes,
                quarantine_until, quarantine_released_at
            )
            VALUES ($1, $2, $3, $4, 8, $5, NULL)
            "#,
        )
        .bind(fx.repo_id)
        .bind("simple/held/held-1.0.whl")
        .bind(format!(
            "proxy-cache/{}/simple/held/held-1.0.whl/__content__",
            fx.repo_key
        ))
        .bind(format!(
            "proxy-cache/{}/simple/held/held-1.0.whl/__cache_meta__.json",
            fx.repo_key
        ))
        .bind(until)
        .execute(&fx.pool)
        .await
        .expect("insert proxy-cache hold");

        let Json(list) = list_quarantine(
            State(fx.state.clone()),
            Extension(admin()),
            Query(HoldListQuery {
                repository_key: Some(fx.repo_key.clone()),
                kind: Some("active".into()),
                page: Some(1),
                per_page: Some(20),
            }),
        )
        .await
        .expect("admin list");
        let Json(summary) = holds_summary(State(fx.state.clone()), Extension(admin()))
            .await
            .expect("admin summary");
        fx.teardown().await;

        assert_eq!(list.pagination.total, 1);
        assert_eq!(list.items[0].source, "proxy-cache");
        assert_eq!(list.items[0].artifact_id, None);
        assert_eq!(list.items[0].name, "held-1.0.whl");
        assert_eq!(list.items[0].path, "simple/held/held-1.0.whl");
        assert_eq!(list.items[0].kind, "active");
        assert!(list.items[0].is_blocked);
        assert!(summary.quarantine_active >= 1);
    }

    #[tokio::test]
    async fn list_quarantine_rejects_unknown_kind() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let err = list_quarantine(
            State(fx.state.clone()),
            Extension(admin()),
            Query(HoldListQuery {
                repository_key: None,
                kind: Some("pending".into()),
                page: None,
                per_page: None,
            }),
        )
        .await
        .expect_err("unknown kind");
        fx.teardown().await;
        assert!(matches!(err, AppError::Validation(_)));
    }
}
