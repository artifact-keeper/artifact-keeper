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
use crate::error::{AppError, Result};
use crate::models::access_scope::AccessScope;
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

/// Gate for both queues: an admin, holding an UNRESTRICTED credential.
///
/// The queues enumerate holds in every repository, including
/// `quarantine_reason` (policy names and admin incident notes). A
/// repository-scoped token binds ahead of `is_admin` (#3901 packages, #3174
/// quarantine reason, #903 SBOM listing): an admin holding a token minted for
/// repository A must not read repository B's holds with it, so such tokens
/// are refused outright rather than silently narrowed.
fn require_queue_admin(auth: &AuthExtension) -> Result<()> {
    auth.require_admin()?;
    if matches!(auth.allowed_repo_ids, AccessScope::Restricted(_)) {
        return Err(AppError::Authorization(
            "Repository-scoped tokens cannot read the admin hold queues".into(),
        ));
    }
    Ok(())
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
    require_queue_admin(&auth)?;
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
    require_queue_admin(&auth)?;
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
    use uuid::Uuid;

    fn admin() -> AuthExtension {
        tdh::admin_auth(Uuid::new_v4(), "holds-admin")
    }

    fn user() -> AuthExtension {
        tdh::make_auth(Uuid::new_v4(), "holds-user")
    }

    #[test]
    fn queue_gate_refuses_non_admin_and_repo_scoped_admin() {
        assert!(require_queue_admin(&admin()).is_ok());
        assert!(matches!(
            require_queue_admin(&user()),
            Err(AppError::Authorization(_))
        ));
        let mut scoped = admin();
        scoped.allowed_repo_ids = AccessScope::Restricted(vec![Uuid::new_v4()]);
        let err = require_queue_admin(&scoped).expect_err("repo-scoped admin token");
        assert!(err.to_string().contains("Repository-scoped"), "{err}");
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

    /// Seed a hosted `artifacts` row with the given quarantine state.
    async fn seed_hosted(
        pool: &sqlx::PgPool,
        repo_id: Uuid,
        label: &str,
        status: &str,
        until: Option<chrono::DateTime<chrono::Utc>>,
        deleted: bool,
    ) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO artifacts (
                id, repository_id, name, path, size_bytes, checksum_sha256,
                content_type, storage_key, is_deleted,
                quarantine_status, quarantine_until, quarantine_reason
            )
            VALUES ($1, $2, $3, $4, 4, $5,
                    'application/octet-stream', $6, $7,
                    $8, $9, 'seeded')
            "#,
        )
        .bind(id)
        .bind(repo_id)
        .bind(format!("{label}.bin"))
        .bind(format!("holds/{label}/{id}.bin"))
        .bind(format!("{:064x}", id.as_u128()))
        .bind(format!("holds/{id}"))
        .bind(deleted)
        .bind(status)
        .bind(until)
        .execute(pool)
        .await
        .expect("insert hosted hold");
        id
    }

    /// Seed a proxy-cache catalog row; returns its `path`.
    async fn seed_proxy(
        pool: &sqlx::PgPool,
        repo_id: Uuid,
        label: &str,
        until: chrono::DateTime<chrono::Utc>,
        released: bool,
    ) -> String {
        let path = format!("simple/{label}/{label}-1.0.whl");
        sqlx::query(
            r#"
            INSERT INTO proxy_cache_artifacts (
                repository_id, path, storage_key, metadata_key, size_bytes,
                quarantine_until, quarantine_released_at
            )
            VALUES ($1, $2, $3, $4, 8, $5, CASE WHEN $6 THEN NOW() END)
            "#,
        )
        .bind(repo_id)
        .bind(&path)
        .bind(format!("proxy-cache/{repo_id}/{path}/__content__"))
        .bind(format!("proxy-cache/{repo_id}/{path}/__cache_meta__.json"))
        .bind(until)
        .bind(released)
        .execute(pool)
        .await
        .expect("insert proxy-cache hold");
        path
    }

    async fn list_as_admin(
        state: &SharedState,
        repository_key: &str,
        kind: Option<&str>,
        page: u32,
        per_page: u32,
    ) -> QuarantineHoldListResponse {
        let Json(body) = list_quarantine(
            State(state.clone()),
            Extension(admin()),
            Query(HoldListQuery {
                repository_key: Some(repository_key.to_string()),
                kind: kind.map(str::to_string),
                page: Some(page),
                per_page: Some(per_page),
            }),
        )
        .await
        .expect("admin list");
        body
    }

    /// The `path` of every listed item, in response order.
    fn paths(body: &QuarantineHoldListResponse) -> Vec<String> {
        body.items.iter().map(|i| i.path.clone()).collect()
    }

    /// Every `kind` filter, the repository filter, the soft-delete and
    /// released-proxy exclusions, totals and OFFSET paging across BOTH union
    /// arms, and the documented sort order, against one seeded data set.
    #[tokio::test]
    async fn list_quarantine_filters_sorts_and_pages_both_sources() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let (other_repo_id, other_key, other_dir) =
            tdh::create_repo(&fx.pool, "local", "generic").await;
        let now = chrono::Utc::now();
        let hours = chrono::Duration::hours;
        let pool = &fx.pool;
        let repo = fx.repo_id;

        // Repository A: three active holds (two timed, one permanent), two
        // expired, one rejected, and two rows that must never be listed.
        let _ = seed_hosted(pool, repo, "h-permanent", "quarantined", None, false).await;
        let _ = seed_hosted(
            pool,
            repo,
            "h-active-3h",
            "quarantined",
            Some(now + hours(3)),
            false,
        )
        .await;
        let _ = seed_hosted(
            pool,
            repo,
            "h-expired",
            "quarantined",
            Some(now - hours(2)),
            false,
        )
        .await;
        let _ = seed_hosted(pool, repo, "h-rejected", "rejected", None, false).await;
        let _ = seed_hosted(pool, repo, "h-deleted", "quarantined", None, true).await;
        let p_active = seed_proxy(pool, repo, "p-active-1h", now + hours(1), false).await;
        let p_expired = seed_proxy(pool, repo, "p-expired", now - hours(1), false).await;
        let _ = seed_proxy(pool, repo, "p-released", now + hours(1), true).await;
        // Repository B: one active hold of each source that A must not see.
        let _ = seed_hosted(pool, other_repo_id, "b-hosted", "quarantined", None, false).await;
        let b_proxy = seed_proxy(pool, other_repo_id, "b-proxy", now + hours(1), false).await;

        let path_of = |label: &str| {
            let suffix = format!("/{label}/");
            move |p: &String| p.contains(&suffix)
        };
        let label_order = |body: &QuarantineHoldListResponse| -> Vec<String> {
            paths(body)
                .into_iter()
                .map(|p| p.split('/').nth(1).unwrap_or_default().to_string())
                .collect()
        };

        let active = list_as_admin(&fx.state, &fx.repo_key, Some("active"), 1, 20).await;
        let expired = list_as_admin(&fx.state, &fx.repo_key, Some("expired"), 1, 20).await;
        let rejected = list_as_admin(&fx.state, &fx.repo_key, Some("rejected"), 1, 20).await;
        let default = list_as_admin(&fx.state, &fx.repo_key, None, 1, 20).await;
        let all = list_as_admin(
            &fx.state,
            &fx.repo_key,
            Some("rejected,expired,active"),
            1,
            20,
        )
        .await;
        let mut paged = Vec::new();
        let mut page_meta = Vec::new();
        for page in 1..=4 {
            let body = list_as_admin(&fx.state, &fx.repo_key, Some("active"), page, 1).await;
            page_meta.push((body.pagination.total, body.pagination.total_pages));
            paged.extend(label_order(&body));
        }
        let other = list_as_admin(&fx.state, &other_key, None, 1, 20).await;

        tdh::cleanup_member_repo(&fx.pool, other_repo_id, &other_dir).await;
        let _ = std::fs::remove_dir_all(&other_dir);
        fx.teardown().await;

        // Active: quarantined rows, soonest-lapsing first, permanent last.
        assert_eq!(
            label_order(&active),
            vec!["p-active-1h", "h-active-3h", "h-permanent"]
        );
        assert_eq!(active.pagination.total, 3);
        assert_eq!(active.pagination.total_pages, 1);
        assert!(active
            .items
            .iter()
            .all(|i| i.kind == "active" && i.is_blocked));
        assert_eq!(active.items[0].source, "proxy-cache");
        assert_eq!(active.items[0].path, p_active);
        assert_eq!(active.items[1].source, "hosted");

        // Expired: both sources, oldest lapse first, never blocking.
        assert_eq!(label_order(&expired), vec!["h-expired", "p-expired"]);
        assert_eq!(expired.pagination.total, 2);
        assert!(expired
            .items
            .iter()
            .all(|i| i.kind == "expired" && !i.is_blocked));
        assert!(expired.items.iter().any(|i| path_of("p-expired")(&i.path)));
        assert_eq!(expired.items[1].path, p_expired);

        // Rejected: hosted only, no remaining time.
        assert_eq!(label_order(&rejected), vec!["h-rejected"]);
        assert_eq!(rejected.pagination.total, 1);
        assert_eq!(rejected.items[0].kind, "rejected");
        assert!(rejected.items[0].is_blocked);
        assert!(rejected.items[0].remaining_seconds.is_none());

        // Default = active + rejected; quarantined sorts ahead of rejected.
        assert_eq!(
            label_order(&default),
            vec!["p-active-1h", "h-active-3h", "h-permanent", "h-rejected"]
        );
        assert_eq!(default.pagination.total, 4);

        // Every kind: the soft-deleted hosted row and the released proxy row
        // never appear, and repository B's rows stay out of A's queue.
        assert_eq!(all.pagination.total, 6);
        assert_eq!(
            label_order(&all),
            vec![
                "h-expired",
                "p-expired",
                "p-active-1h",
                "h-active-3h",
                "h-permanent",
                "h-rejected"
            ]
        );
        for hidden in ["h-deleted", "p-released", "b-hosted", "b-proxy"] {
            assert!(
                !paths(&all).iter().any(path_of(hidden)),
                "{hidden} must not be listed for repository A"
            );
        }

        // OFFSET paging walks the union in the same order with no repeats.
        assert_eq!(paged, vec!["p-active-1h", "h-active-3h", "h-permanent"]);
        assert!(page_meta.iter().all(|m| *m == (3, 3)));

        // Repository B sees only its own two rows.
        assert_eq!(other.pagination.total, 2);
        assert_eq!(other.items[0].path, b_proxy);
        assert_eq!(label_order(&other), vec!["b-proxy", "b-hosted"]);
    }

    /// The summary's active count includes BOTH hosted and proxy-cache holds,
    /// and the rejected count picks up a rejected hosted row. Other tests share
    /// the database, so the seeded rows set a floor rather than exact values.
    #[tokio::test]
    async fn summary_counts_hosted_and_proxy_holds() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let now = chrono::Utc::now();
        let pool = &fx.pool;
        for i in 0..3 {
            let _ = seed_proxy(
                pool,
                fx.repo_id,
                &format!("sum-p{i}"),
                now + chrono::Duration::hours(1),
                false,
            )
            .await;
        }
        let _ = seed_hosted(pool, fx.repo_id, "sum-h", "quarantined", None, false).await;
        let _ = seed_hosted(pool, fx.repo_id, "sum-r", "rejected", None, false).await;
        let Json(summary) = holds_summary(State(fx.state.clone()), Extension(admin()))
            .await
            .expect("admin summary");
        fx.teardown().await;
        assert!(summary.quarantine_active >= 4, "{summary:?}");
        assert!(summary.quarantine_rejected >= 1, "{summary:?}");
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

/// Through the real router: the `/admin` nest's `admin_middleware` and the
/// handler gate together, for every credential shape that can reach them.
#[cfg(ak_test_shard = "router")]
#[cfg(test)]
mod router_tests {
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::http::StatusCode;

    const ROUTES: [&str; 2] = [
        "/api/v1/admin/holds/summary",
        "/api/v1/admin/holds/quarantine",
    ];

    async fn status_for(
        state: &crate::api::SharedState,
        credential: Option<&str>,
    ) -> Vec<StatusCode> {
        let mut out = Vec::new();
        for uri in ROUTES {
            let mut req = tdh::get(uri.to_string());
            if let Some(c) = credential {
                req.headers_mut().insert(
                    "authorization",
                    c.parse::<axum::http::HeaderValue>().expect("auth header"),
                );
            }
            let app = crate::api::routes::create_router(state.clone());
            let (status, _) = tdh::send(app, req).await;
            out.push(status);
        }
        out
    }

    #[tokio::test]
    async fn hold_queues_gate_anonymous_non_admin_and_repo_scoped_admin_tokens() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let (admin_id, _) = tdh::create_user(&fx.pool).await;
        sqlx::query("UPDATE users SET is_admin = true WHERE id = $1")
            .bind(admin_id)
            .execute(&fx.pool)
            .await
            .expect("promote admin");

        let auth_service = crate::services::auth_service::AuthService::new(
            fx.state.db.clone(),
            std::sync::Arc::new(fx.state.config.clone()),
        );
        // Admin-owned API tokens carrying the `admin` scope: one unrestricted,
        // one pinned to the fixture repository through `api_token_repositories`.
        let (open_token, _) = auth_service
            .generate_api_token(admin_id, "holds-open", vec!["admin".into()], None)
            .await
            .expect("mint unrestricted admin token");
        let (pinned_token, pinned_id) = auth_service
            .generate_api_token(admin_id, "holds-pinned", vec!["admin".into()], None)
            .await
            .expect("mint repo-scoped admin token");
        sqlx::query("INSERT INTO api_token_repositories (token_id, repo_id) VALUES ($1, $2)")
            .bind(pinned_id)
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await
            .expect("pin token to the fixture repository");
        // A repository-scoped JWT for the same admin.
        let admin_user =
            sqlx::query_as::<_, crate::models::user::User>("SELECT * FROM users WHERE id = $1")
                .bind(admin_id)
                .fetch_one(&fx.pool)
                .await
                .expect("load admin");
        let scoped_jwt = auth_service
            .generate_tokens_with_repo_scope(&admin_user, Some(vec![fx.repo_id]))
            .expect("mint repo-scoped JWT")
            .access_token;

        let user_bearer = tdh::bearer_for(&fx.state, fx.user_id).await;
        let admin_bearer = tdh::bearer_for(&fx.state, admin_id).await;

        let anonymous = status_for(&fx.state, None).await;
        let non_admin = status_for(&fx.state, Some(&user_bearer)).await;
        let admin = status_for(&fx.state, Some(&admin_bearer)).await;
        let open = status_for(&fx.state, Some(&format!("Bearer {open_token}"))).await;
        let pinned = status_for(&fx.state, Some(&format!("Bearer {pinned_token}"))).await;
        let scoped = status_for(&fx.state, Some(&format!("Bearer {scoped_jwt}"))).await;

        let _ = sqlx::query("DELETE FROM api_tokens WHERE user_id = $1")
            .bind(admin_id)
            .execute(&fx.pool)
            .await;
        tdh::cleanup_user(&fx.pool, admin_id).await;
        fx.teardown().await;

        let all = |s: StatusCode| vec![s; ROUTES.len()];
        assert_eq!(anonymous, all(StatusCode::UNAUTHORIZED), "anonymous");
        assert_eq!(non_admin, all(StatusCode::FORBIDDEN), "non-admin JWT");
        assert_eq!(admin, all(StatusCode::OK), "admin JWT");
        assert_eq!(open, all(StatusCode::OK), "unrestricted admin API token");
        assert_eq!(
            pinned,
            all(StatusCode::FORBIDDEN),
            "repo-pinned admin API token"
        );
        assert_eq!(scoped, all(StatusCode::FORBIDDEN), "repo-scoped admin JWT");
    }
}
