//! Admin download-hold observability: quarantine queue + policy-blocked packages.

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
    DownloadHoldsService, HoldKind, PolicyBlockRow, QuarantineHoldRow,
};

pub fn admin_router() -> Router<SharedState> {
    Router::new()
        .route("/summary", get(holds_summary))
        .route("/quarantine", get(list_quarantine))
        .route("/policy-blocks", get(list_policy_blocks))
}

#[derive(Debug, Deserialize, IntoParams, ToSchema)]
pub struct HoldListQuery {
    pub repository_key: Option<String>,
    /// Comma-separated: `active`, `expired`, `rejected`. Default: `active,rejected`.
    pub kind: Option<String>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

#[derive(Debug, Deserialize, IntoParams, ToSchema)]
pub struct PolicyBlockListQuery {
    pub repository_key: Option<String>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HoldsSummaryResponse {
    pub age_gate_pending: i64,
    pub quarantine_active: i64,
    pub quarantine_rejected: i64,
    pub policy_blocked: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct QuarantineHoldResponse {
    pub artifact_id: Uuid,
    pub name: String,
    pub version: Option<String>,
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

#[derive(Debug, Serialize, ToSchema)]
pub struct PolicyBlockResponse {
    pub id: String,
    pub source: String,
    pub artifact_id: Option<Uuid>,
    pub package_name: String,
    pub package_version: Option<String>,
    pub path: String,
    pub repository_key: String,
    pub repository_format: String,
    pub uploaded_at: Option<chrono::DateTime<chrono::Utc>>,
    pub critical_count: i32,
    pub high_count: i32,
    pub medium_count: i32,
    pub low_count: i32,
    pub findings_count: i32,
    pub max_severity: Option<String>,
    pub policy_name: Option<String>,
    pub block_reason: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PolicyBlockListResponse {
    pub items: Vec<PolicyBlockResponse>,
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
        artifact_id: row.artifact_id,
        name: row.name,
        version: row.version,
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

fn to_policy_response(row: PolicyBlockRow) -> PolicyBlockResponse {
    PolicyBlockResponse {
        id: row.id,
        source: row.source,
        artifact_id: row.artifact_id,
        package_name: row.package_name,
        package_version: row.package_version,
        path: row.path,
        repository_key: row.repository_key,
        repository_format: row.repository_format,
        uploaded_at: row.uploaded_at,
        critical_count: row.critical_count,
        high_count: row.high_count,
        medium_count: row.medium_count,
        low_count: row.low_count,
        findings_count: row.findings_count,
        max_severity: row.max_severity,
        policy_name: row.policy_name,
        block_reason: row.block_reason,
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
        policy_blocked: summary.policy_blocked,
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

#[utoipa::path(
    get,
    path = "/holds/policy-blocks",
    context_path = "/api/v1/admin",
    tag = "holds",
    security(("bearer_auth" = [])),
    params(PolicyBlockListQuery),
    responses((status = 200, body = PolicyBlockListResponse))
)]
pub async fn list_policy_blocks(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Query(query): Query<PolicyBlockListQuery>,
) -> Result<Json<PolicyBlockListResponse>> {
    auth.require_admin()?;
    let (page, per_page, offset) = normalize_pagination(query.page, query.per_page);
    let (rows, total) = svc(&state)
        .list_policy_blocks(query.repository_key.as_deref(), offset, i64::from(per_page))
        .await?;
    Ok(Json(PolicyBlockListResponse {
        items: rows.into_iter().map(to_policy_response).collect(),
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
    paths(holds_summary, list_quarantine, list_policy_blocks),
    components(schemas(
        HoldsSummaryResponse,
        QuarantineHoldResponse,
        QuarantineHoldListResponse,
        PolicyBlockResponse,
        PolicyBlockListResponse,
        HoldListQuery,
        PolicyBlockListQuery,
        Pagination,
    )),
    tags((name = "holds", description = "Download-hold observability: quarantine and policy blocks"))
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
        assert_eq!(body.items[0].artifact_id, artifact_id);
        assert_eq!(body.items[0].kind, "active");
        assert!(body.items[0].is_blocked);
        assert_eq!(
            body.items[0].quarantine_reason.as_deref(),
            Some("manual hold")
        );
        assert!(body.items[0].remaining_seconds.is_none());
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

    #[tokio::test]
    async fn list_policy_blocks_rejects_non_admin() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let err = list_policy_blocks(
            State(fx.state.clone()),
            Extension(user()),
            Query(PolicyBlockListQuery {
                repository_key: None,
                page: None,
                per_page: None,
            }),
        )
        .await
        .expect_err("non-admin must not list policy blocks");
        fx.teardown().await;
        assert!(matches!(err, AppError::Authorization(_)));
    }
}
