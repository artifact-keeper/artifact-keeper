//! Admin download-hold observability: hosted and proxy-cache quarantine
//! queues, and the scan-policy blocks queue (#4510).

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
    classify_hold, parse_hold_kinds, parse_hold_source, remaining_seconds, DownloadHoldsService,
    HoldKind, PolicyBlock, PolicyBlockCursor, QuarantineHoldRow,
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
    /// Only hosted holds recorded with this source: `upload`, `admin` or
    /// `scan_policy` (#4510). Proxy-cache rows record none and are left out
    /// when this is set.
    pub hold_source: Option<String>,
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
    /// Proxy-cache rows mirror the hold in the cache sidecar, which is what the
    /// download path enforces; the listing is a best-effort view of it.
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
    /// Where a hosted hold came from (#4510): `upload` (the quarantine
    /// period), `admin` (quarantine-now) or `scan_policy`. `null` for a
    /// proxy-cache row and for a hold that recorded no source (written before
    /// 1.12.0, or by the scanner, which does not record one yet).
    pub hold_source: Option<String>,
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
    auth.require_unscoped_admin("the admin hold queues")
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
        hold_source: row.hold_source,
        created_at: row.created_at,
        is_blocked: matches!(kind, HoldKind::Active | HoldKind::Rejected),
    }
}

#[utoipa::path(
    get,
    extensions(("x-required-permission" = json!("audit.read")), ("x-resource" = json!("instance"))),
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
    extensions(("x-required-permission" = json!("audit.read")), ("x-resource" = json!("instance"))),
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
    let hold_source = parse_hold_source(query.hold_source.as_deref())?;
    let (page, per_page, offset) = Pagination::clamp_offset(query.page, query.per_page);
    let (rows, total) = svc(&state)
        .list_quarantine(
            query.repository_key.as_deref(),
            &kinds,
            hold_source.as_deref(),
            offset,
            i64::from(per_page),
        )
        .await?;
    Ok(Json(QuarantineHoldListResponse {
        items: rows.into_iter().map(to_quarantine_response).collect(),
        pagination: Pagination::for_page(page, per_page, total),
    }))
}

#[derive(Debug, Deserialize, IntoParams, ToSchema)]
pub struct PolicyBlockListQuery {
    pub repository_key: Option<String>,
    /// The `next_cursor` of the previous page; omit for the first page.
    pub cursor: Option<String>,
    /// Items per page (default 50, max 200).
    pub per_page: Option<u32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PolicyBlockResponse {
    /// `proxy-cache` (a cached path whose stored `vulnerable` verdict this
    /// repository's proxy scan gate refuses) or `hosted` (an artifact a scan
    /// policy refuses). Proxy-cache items come first, then hosted ones,
    /// newest first.
    pub source: String,
    /// Hosted items only.
    pub artifact_id: Option<Uuid>,
    pub repository_key: String,
    pub repository_format: String,
    pub path: String,
    pub name: String,
    pub version: Option<String>,
    pub checksum_sha256: String,
    /// Hosted only: the stored quarantine status (a policy block is refused
    /// whether or not the scanner also stamped a hold).
    pub quarantine_status: Option<String>,
    /// Hosted only: `upload`, `admin`, `scan_policy` or `null`.
    pub hold_source: Option<String>,
    /// Hosted only: the violated policy rules, as the gate evaluated them.
    pub violations: Vec<String>,
    /// Proxy-cache only: the verdict's highest severity.
    pub max_severity: Option<String>,
    /// Proxy-cache only: when the verdict was recorded.
    pub scanned_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PolicyBlockListResponse {
    pub items: Vec<PolicyBlockResponse>,
    /// Pass as `cursor` for the next page; `null` when the queue is exhausted.
    /// A page can hold fewer than `per_page` items and still have a cursor:
    /// each page evaluates a bounded number of hosted artifacts.
    pub next_cursor: Option<String>,
    /// Hosted artifacts whose scan policy this page evaluated.
    pub evaluated: i64,
}

fn to_policy_block_response(b: PolicyBlock) -> PolicyBlockResponse {
    PolicyBlockResponse {
        source: b.source.to_string(),
        artifact_id: b.artifact_id,
        repository_key: b.repository_key,
        repository_format: b.repository_format,
        path: b.path,
        name: b.name,
        version: b.version,
        checksum_sha256: b.checksum_sha256,
        quarantine_status: b.quarantine_status,
        hold_source: b.hold_source,
        violations: b.violations,
        max_severity: b.max_severity,
        scanned_at: b.scanned_at,
    }
}

/// What the download gate's scan-policy decision refuses right now (#4510),
/// across every repository: hosted artifacts a scan policy refuses (evaluated
/// with the gate's own policy evaluation) and proxied paths whose stored
/// verdict the repository's proxy scan gate refuses. Not derived from the
/// quarantine stamp, so a policy block shows here whether or not a hold was
/// recorded, and a hold whose policy no longer refuses does not.
#[utoipa::path(
    get,
    extensions(("x-required-permission" = json!("audit.read")), ("x-resource" = json!("instance"))),
    path = "/holds/policy-blocks",
    context_path = "/api/v1/admin",
    tag = "holds",
    security(("bearer_auth" = [])),
    params(PolicyBlockListQuery),
    responses(
        (status = 200, body = PolicyBlockListResponse),
        (status = 400, description = "Invalid cursor", body = crate::api::openapi::ErrorResponse),
        (status = 403, description = "Admin privileges required", body = crate::api::openapi::ErrorResponse),
    )
)]
pub async fn list_policy_blocks(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Query(query): Query<PolicyBlockListQuery>,
) -> Result<Json<PolicyBlockListResponse>> {
    require_queue_admin(&auth)?;
    let cursor = query
        .cursor
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(PolicyBlockCursor::parse)
        .transpose()?;
    let per_page = i64::from(query.per_page.unwrap_or(50).clamp(1, 200));
    let page = svc(&state)
        .list_policy_blocks(query.repository_key.as_deref(), cursor.as_ref(), per_page)
        .await?;
    Ok(Json(PolicyBlockListResponse {
        items: page
            .items
            .into_iter()
            .map(to_policy_block_response)
            .collect(),
        next_cursor: page.next_cursor,
        evaluated: page.evaluated,
    }))
}

#[derive(OpenApi)]
#[openapi(
    paths(holds_summary, list_quarantine, list_policy_blocks),
    components(schemas(
        HoldsSummaryResponse,
        QuarantineHoldResponse,
        QuarantineHoldListResponse,
        HoldListQuery,
        PolicyBlockListQuery,
        PolicyBlockResponse,
        PolicyBlockListResponse,
        Pagination,
    )),
    tags((name = "holds", description = "Download-hold observability: hosted and proxy-cache quarantine, scan-policy blocks"))
)]
pub struct DownloadHoldsApiDoc;

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use crate::error::AppError;
    use crate::models::access_scope::AccessScope;
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
                hold_source: None,
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
                hold_source: None,
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
                hold_source: None,
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
                hold_source: None,
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
                hold_source: None,
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

    const ROUTES: [&str; 3] = [
        "/api/v1/admin/holds/summary",
        "/api/v1/admin/holds/quarantine",
        "/api/v1/admin/holds/policy-blocks",
    ];

    #[tokio::test]
    async fn hold_queues_gate_anonymous_non_admin_and_repo_scoped_admin_tokens() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        tdh::assert_admin_routes_refuse_repo_scoped_tokens(&fx, &ROUTES).await;
        fx.teardown().await;
    }
}

/// #4510: the policy-blocks queue is the gate's own decision, and the
/// quarantine queue reports and filters the hold source.
#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod policy_blocks_4510_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use sqlx::PgPool;

    fn admin() -> AuthExtension {
        tdh::admin_auth(Uuid::new_v4(), "admin")
    }

    async fn page(
        state: &SharedState,
        repository_key: &str,
        cursor: Option<String>,
        per_page: u32,
    ) -> PolicyBlockListResponse {
        let Json(body) = list_policy_blocks(
            State(state.clone()),
            Extension(admin()),
            Query(PolicyBlockListQuery {
                repository_key: Some(repository_key.to_string()),
                cursor,
                per_page: Some(per_page),
            }),
        )
        .await
        .expect("admin policy-blocks");
        body
    }

    async fn seed_hosted(fx: &tdh::Fixture, path: &str) -> Uuid {
        tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &fx.repo_info("local", None),
            path,
            path,
            "pkg",
            "1.0.0",
            "application/octet-stream",
            bytes::Bytes::from(path.to_string()),
            fx.user_id,
        )
        .await
    }

    async fn proxy_repo(pool: &PgPool, action: &str) -> (Uuid, String, std::path::PathBuf) {
        let (id, key, dir) = tdh::create_repo(pool, "remote", "npm").await;
        sqlx::query(
            "INSERT INTO scan_configs (repository_id, scan_enabled, scan_on_upload, \
                                       scan_on_proxy, block_on_policy_violation, \
                                       severity_threshold, proxy_scan_action) \
             VALUES ($1, true, false, true, true, 'high', $2)",
        )
        .bind(id)
        .bind(action)
        .execute(pool)
        .await
        .expect("scan config");
        (id, key, dir)
    }

    async fn cache_row(pool: &PgPool, repo_id: Uuid, repo_key: &str, path: &str, digest: &str) {
        sqlx::query(
            "INSERT INTO proxy_cache_artifacts (repository_id, path, storage_key, metadata_key, \
                                                size_bytes, checksum_sha256) \
             VALUES ($1, $2, $3, $4, 8, $5)",
        )
        .bind(repo_id)
        .bind(path)
        .bind(format!("proxy-cache/{repo_key}/{path}/__content__"))
        .bind(format!("proxy-cache/{repo_key}/{path}/__cache_meta__.json"))
        .bind(digest)
        .execute(pool)
        .await
        .expect("cache row");
    }

    async fn verdict(pool: &PgPool, digest: &str, max_severity: &str) {
        sqlx::query(
            "INSERT INTO proxy_scan_results (checksum_sha256, scan_type, verdict, findings_count, \
                                             critical_count, max_severity) \
             VALUES ($1, 'grype', 'vulnerable', 1, 1, $2)",
        )
        .bind(digest)
        .bind(max_severity)
        .execute(pool)
        .await
        .expect("verdict");
    }

    /// Hosted half: an artifact the repository's scan policy refuses is
    /// listed with its violations; one the policy allows (scanned clean) is
    /// not; without the policy the queue is empty. Paging by cursor visits
    /// every item once.
    #[tokio::test]
    async fn hosted_policy_blocks_follow_the_gate_decision() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let unscanned = seed_hosted(&fx, "pb/unscanned-1.0.bin").await;
        let also_unscanned = seed_hosted(&fx, "pb/unscanned-2.0.bin").await;
        let scanned = seed_hosted(&fx, "pb/scanned-1.0.bin").await;
        sqlx::query(
            "INSERT INTO scan_results (artifact_id, repository_id, scan_type, status, \
             findings_count, started_at, completed_at) \
             VALUES ($1, $2, 'dependency', 'completed', 0, NOW(), NOW())",
        )
        .bind(scanned)
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .expect("scan the third artifact");
        let without_policy = page(&fx.state, &fx.repo_key, None, 50).await;
        sqlx::query(
            "INSERT INTO scan_policies (name, repository_id, max_severity, block_unscanned, \
                                        block_on_fail, is_enabled) \
             VALUES ($1, $2, 'critical', true, false, true)",
        )
        .bind(format!("pb-4510-{}", fx.repo_id))
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .expect("policy");
        let with_policy = page(&fx.state, &fx.repo_key, None, 50).await;
        let first = page(&fx.state, &fx.repo_key, None, 1).await;
        let second = page(&fx.state, &fx.repo_key, first.next_cursor.clone(), 1).await;
        let third = page(&fx.state, &fx.repo_key, second.next_cursor.clone(), 1).await;
        let _ = sqlx::query("DELETE FROM scan_policies WHERE repository_id = $1")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await;
        let _ = sqlx::query("DELETE FROM scan_results WHERE repository_id = $1")
            .bind(fx.repo_id)
            .execute(&fx.pool)
            .await;
        fx.teardown().await;

        assert!(
            without_policy.items.is_empty(),
            "no policy, nothing blocked"
        );
        assert_eq!(without_policy.next_cursor, None);
        let mut ids: Vec<_> = with_policy.items.iter().map(|i| i.artifact_id).collect();
        ids.sort();
        let mut want = vec![Some(unscanned), Some(also_unscanned)];
        want.sort();
        assert_eq!(ids, want, "the unscanned artifacts only");
        assert!(with_policy.items.iter().all(|i| i.source == "hosted"));
        assert!(with_policy.items[0].violations[0].contains("not been scanned"));
        assert_eq!(with_policy.next_cursor, None);
        let mut paged: Vec<_> = [&first, &second, &third]
            .iter()
            .flat_map(|p| p.items.iter().map(|i| i.artifact_id))
            .collect();
        paged.sort();
        assert_eq!(paged, want, "cursor paging visits each block once");
        assert!(first.next_cursor.is_some());
    }

    /// Proxy half: one digest, a vulnerable verdict, cached in two
    /// repositories. Only the repository whose gate refuses it lists it: the
    /// record-only one serves it, so it is not a block there.
    #[tokio::test]
    async fn proxy_blocks_are_listed_only_where_that_repositorys_gate_refuses() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let digest = format!("{:064x}", Uuid::new_v4().as_u128());
        let (blocking, blocking_key, d1) = proxy_repo(&pool, "fail_open").await;
        let (recording, recording_key, d2) = proxy_repo(&pool, "record_only").await;
        cache_row(
            &pool,
            blocking,
            &blocking_key,
            "left-pad/-/left-pad-1.0.0.tgz",
            &digest,
        )
        .await;
        cache_row(
            &pool,
            recording,
            &recording_key,
            "left-pad/-/left-pad-1.0.0.tgz",
            &digest,
        )
        .await;
        verdict(&pool, &digest, "critical").await;
        let state = tdh::build_state(pool.clone(), d1.to_string_lossy().as_ref());
        let blocked = page(&state, &blocking_key, None, 50).await;
        let recorded = page(&state, &recording_key, None, 50).await;
        let _ = sqlx::query("DELETE FROM proxy_scan_results WHERE checksum_sha256 = $1")
            .bind(&digest)
            .execute(&pool)
            .await;
        for (id, dir) in [(blocking, d1), (recording, d2)] {
            let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
                .bind(id)
                .execute(&pool)
                .await;
            let _ = std::fs::remove_dir_all(dir);
        }

        assert_eq!(blocked.items.len(), 1, "{:?}", blocked.items.len());
        let item = &blocked.items[0];
        assert_eq!(item.source, "proxy-cache");
        assert_eq!(item.path, "left-pad/-/left-pad-1.0.0.tgz");
        assert_eq!(item.name, "left-pad-1.0.0.tgz");
        assert_eq!(item.checksum_sha256, digest);
        assert_eq!(item.max_severity.as_deref(), Some("critical"));
        assert!(
            recorded.items.is_empty(),
            "a record-only repository never refuses, so it lists nothing"
        );
    }

    /// #4987: the proxy half pages by keyset. A cached path that drops out
    /// between two pages (its verdict cleared, its cache row evicted) does
    /// not shift the next page past an entry it has not shown, as the offset
    /// cursor did; every remaining block is visited once, then the hosted
    /// half follows.
    #[tokio::test]
    async fn proxy_blocks_page_by_keyset_4987() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo, key, dir) = proxy_repo(&pool, "fail_open").await;
        let paths = ["a/-/a-1.0.0.tgz", "b/-/b-1.0.0.tgz", "c/-/c-1.0.0.tgz"];
        let mut digests = Vec::new();
        for path in paths {
            let digest = format!("{:064x}", Uuid::new_v4().as_u128());
            cache_row(&pool, repo, &key, path, &digest).await;
            verdict(&pool, &digest, "critical").await;
            digests.push(digest);
        }
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let first = page(&state, &key, None, 1).await;
        // The first entry drops out before the second page is read.
        let _ =
            sqlx::query("DELETE FROM proxy_cache_artifacts WHERE repository_id = $1 AND path = $2")
                .bind(repo)
                .bind(paths[0])
                .execute(&pool)
                .await;
        let second = page(&state, &key, first.next_cursor.clone(), 1).await;
        let third = page(&state, &key, second.next_cursor.clone(), 1).await;
        let fourth = page(&state, &key, third.next_cursor.clone(), 1).await;
        let _ = sqlx::query("DELETE FROM proxy_scan_results WHERE checksum_sha256 = ANY($1)")
            .bind(&digests)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo)
            .execute(&pool)
            .await;
        let _ = std::fs::remove_dir_all(dir);

        let path_of = |p: &PolicyBlockListResponse| {
            p.items.iter().map(|i| i.path.clone()).collect::<Vec<_>>()
        };
        assert_eq!(path_of(&first), [paths[0]]);
        assert_eq!(
            path_of(&second),
            [paths[1]],
            "the next unseen entry, not one past it"
        );
        assert_eq!(path_of(&third), [paths[2]]);
        assert!(third.next_cursor.is_some(), "a full page always resumes");
        assert!(fourth.items.is_empty());
        assert_eq!(
            fourth.next_cursor, None,
            "proxy and hosted halves exhausted"
        );
    }

    /// The quarantine queue reports `hold_source` and filters on it.
    #[tokio::test]
    async fn quarantine_queue_reports_and_filters_hold_source() {
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let by_admin = seed_hosted(&fx, "hs/admin-1.0.bin").await;
        let by_policy = seed_hosted(&fx, "hs/policy-1.0.bin").await;
        for (id, source) in [(by_admin, "admin"), (by_policy, "scan_policy")] {
            sqlx::query(
                "UPDATE artifacts SET quarantine_status = 'quarantined', quarantine_until = NULL, \
                 quarantine_source = $2 WHERE id = $1",
            )
            .bind(id)
            .bind(source)
            .execute(&fx.pool)
            .await
            .expect("hold");
        }
        let list = |hold_source: Option<&str>| {
            let state = fx.state.clone();
            let key = fx.repo_key.clone();
            let hold_source = hold_source.map(str::to_string);
            async move {
                list_quarantine(
                    State(state),
                    Extension(admin()),
                    Query(HoldListQuery {
                        repository_key: Some(key),
                        kind: None,
                        hold_source,
                        page: Some(1),
                        per_page: Some(20),
                    }),
                )
                .await
            }
        };
        let all = list(None).await.expect("all").0;
        let policy_only = list(Some("scan_policy")).await.expect("policy").0;
        let bad = list(Some("scanner")).await;
        fx.teardown().await;

        assert_eq!(all.pagination.total, 2);
        assert_eq!(policy_only.pagination.total, 1);
        assert_eq!(policy_only.items[0].artifact_id, Some(by_policy));
        assert_eq!(
            policy_only.items[0].hold_source.as_deref(),
            Some("scan_policy")
        );
        assert!(matches!(bad, Err(crate::error::AppError::Validation(_))));
    }

    #[test]
    fn policy_block_cursor_round_trips_and_rejects_garbage() {
        let now = chrono::DateTime::from_timestamp_micros(1_700_000_000_123_456).unwrap();
        for c in [
            PolicyBlockCursor::Proxy {
                after: crate::services::scan_result_service::ProxyBlockedKey {
                    repository_key: "npm.remote-1".into(),
                    path: "@scope/left-pad/-/left-pad-1.0.0.tgz".into(),
                    checksum_sha256: "ab".repeat(32),
                },
            },
            PolicyBlockCursor::Hosted {
                created_at: now,
                id: Uuid::new_v4(),
            },
        ] {
            assert_eq!(PolicyBlockCursor::parse(&c.encode()).unwrap(), c);
        }
        // `p.7` is the offset form of earlier releases (#4987).
        for bad in [
            "",
            "x.1",
            "p.7",
            "p.-1",
            "h.1",
            "h.abc.def",
            "p.1.2",
            "p.a.b.c.d",
            "p.!.a.a",
        ] {
            assert!(PolicyBlockCursor::parse(bad).is_err(), "{bad}");
        }
    }
}
