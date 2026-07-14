//! Admin-only security analytics: CVE / artifact blast radius (#2364).
//!
//! Given a CVE id (or a single artifact), report **who is exposed**: the
//! users — or anonymous clients — that downloaded an affected artifact,
//! plus a bounded per-repository classification of how widely each affected
//! repository is reachable. Read-only; joins the existing CVE seam
//! (`scan_findings.cve_id` / `scan_findings.artifact_id`) to the per-user
//! download attribution shipped in #2365 (`download_statistics.user_id` /
//! `ip_address`).
//!
//! Phase 1 answers "who **downloaded** the vulnerable artifact". Phase 2
//! (#2386) adds the latent blast radius: the principals who *can read* an
//! affected artifact in a **restricted** repository but have **no download
//! record** (`.../accessible-users`). It inverts the shared REST read predicate
//! (`repository_service::permissions_grant_exists_for` + `role_assignments` +
//! admin) and anti-joins `download_statistics`, so the report over-approximates
//! (superset) rather than under-reports who could pull a vulnerable artifact.
//! Public / global repos are never enumerated (`exposure: everyone` /
//! `effectively-everyone`).
//!
//! Everything here is mounted under the `/admin` nest (admin_middleware),
//! and each handler re-checks `is_admin` as defense in depth: download
//! attribution is sensitive telemetry.

use axum::{
    extract::{Extension, Path, Query, State},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::handlers::admin::parse_rfc3339_bound;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::services::repository_service::permissions_grant_exists_for;

/// Create admin security-analytics routes (nested at `/admin/security`).
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/cve/:cve_id/blast-radius", get(cve_blast_radius))
        .route(
            "/artifact/:artifact_id/blast-radius",
            get(artifact_blast_radius),
        )
        // Phase 2 (#2386): latent blast radius — accessible-but-not-downloaded
        // users for restricted repos. Same /admin nest, same admin gate.
        .route("/cve/:cve_id/accessible-users", get(cve_accessible_users))
        .route(
            "/artifact/:artifact_id/accessible-users",
            get(artifact_accessible_users),
        )
}

/// Default page size for the downloaders listing.
const BLAST_DEFAULT_PER_PAGE: u32 = 20;
/// Hard cap on page size so one request cannot pull an unbounded slice.
const BLAST_MAX_PER_PAGE: u32 = 100;
/// Cap on distinct IPs reported per downloader row (the counts stay exact;
/// only the sample list is truncated).
const MAX_IPS_PER_DOWNLOADER: u32 = 50;
/// Cap on the `affected_repos` block. `summary.affected_repo_count` remains
/// the true total even when the list is truncated.
const MAX_AFFECTED_REPOS: u32 = 200;
/// Fraction of active, non-service users at/above which a restricted repo's
/// accessible set is treated as "effectively everyone" — the page body is
/// suppressed (reporting ~all users is not actionable, and this catches the
/// global NULL-scoped `role_assignment` granted to every user). The count is
/// still returned so admins see the magnitude.
const BLAST_EVERYONE_THRESHOLD: f64 = 0.90;

/// Normalize/clamp blast-radius pagination into `(offset, limit, page,
/// per_page)`.
///
/// Pure (no I/O) so the coverage gate exercises the pagination arithmetic
/// without Postgres. `page` is 1-based and floored at 1; `per_page` defaults
/// to [`BLAST_DEFAULT_PER_PAGE`] and is clamped to `1..=BLAST_MAX_PER_PAGE`.
pub(crate) fn blast_page_bounds(page: Option<u32>, per_page: Option<u32>) -> (i64, i64, u32, u32) {
    let page = page.unwrap_or(1).max(1);
    let per_page = per_page
        .unwrap_or(BLAST_DEFAULT_PER_PAGE)
        .clamp(1, BLAST_MAX_PER_PAGE);
    let offset = i64::from(page - 1) * i64::from(per_page);
    (offset, i64::from(per_page), page, per_page)
}

/// Classify how widely a repository is reachable, for the blast-radius
/// exposure signal.
///
/// - `public` — anyone (including anonymous) can read the repository.
/// - `restricted_acl` — private, and at least one explicit ACL row targets
///   the repository (specific users/groups were granted access).
/// - `restricted_roles` — private with no repository ACL rows; access flows
///   only through role assignments / admin rights.
pub(crate) fn classify_access_scope(is_public: bool, has_acl_rules: bool) -> &'static str {
    if is_public {
        "public"
    } else if has_acl_rules {
        "restricted_acl"
    } else {
        "restricted_roles"
    }
}

/// What the blast radius is computed for.
#[derive(Debug, Clone)]
enum BlastRadiusTarget {
    /// All artifacts with a `scan_findings` row carrying this CVE id
    /// (exact match; scanners store canonical ids like `CVE-2021-44228`).
    Cve(String),
    /// One artifact, regardless of which CVE flagged it.
    Artifact(Uuid),
}

impl BlastRadiusTarget {
    fn kind(&self) -> &'static str {
        match self {
            BlastRadiusTarget::Cve(_) => "cve",
            BlastRadiusTarget::Artifact(_) => "artifact",
        }
    }

    fn value(&self) -> String {
        match self {
            BlastRadiusTarget::Cve(cve_id) => cve_id.clone(),
            BlastRadiusTarget::Artifact(artifact_id) => artifact_id.to_string(),
        }
    }
}

/// Push the deduplicated affected-artifact derived table (`f`) for the
/// target. Deduplication matters: one artifact can carry several
/// `scan_findings` rows for the same CVE (one per affected component), and a
/// naive join would multiply every download count by the number of findings.
fn push_affected_artifacts<'a>(
    builder: &mut sqlx::QueryBuilder<'a, sqlx::Postgres>,
    target: &'a BlastRadiusTarget,
) {
    builder.push("(SELECT DISTINCT artifact_id FROM scan_findings WHERE ");
    match target {
        BlastRadiusTarget::Cve(cve_id) => {
            builder.push("cve_id = ").push_bind(cve_id.as_str());
        }
        BlastRadiusTarget::Artifact(artifact_id) => {
            builder.push("artifact_id = ").push_bind(*artifact_id);
        }
    }
    builder.push(") f");
}

/// Append the optional `downloaded_at` window to a query that has already
/// opened its WHERE clause.
fn push_download_window<'a>(
    builder: &mut sqlx::QueryBuilder<'a, sqlx::Postgres>,
    from: Option<chrono::DateTime<chrono::Utc>>,
    to: Option<chrono::DateTime<chrono::Utc>>,
) {
    if let Some(from) = from {
        builder.push(" AND d.downloaded_at >= ").push_bind(from);
    }
    if let Some(to) = to {
        builder.push(" AND d.downloaded_at <= ").push_bind(to);
    }
}

/// Query parameters shared by the blast-radius endpoints.
#[derive(Debug, Default, Deserialize, IntoParams)]
pub struct BlastRadiusQuery {
    /// Inclusive lower bound on `downloaded_at` (RFC 3339).
    pub from: Option<String>,
    /// Inclusive upper bound on `downloaded_at` (RFC 3339).
    pub to: Option<String>,
    /// 1-based page over the downloaders list.
    pub page: Option<u32>,
    /// Downloaders per page (1..=100, default 20).
    pub per_page: Option<u32>,
}

/// Echo of what the blast radius was computed for.
#[derive(Debug, Serialize, ToSchema)]
pub struct BlastRadiusTargetInfo {
    /// `cve` or `artifact`.
    pub kind: String,
    /// The CVE id or artifact id.
    pub value: String,
}

/// Aggregate exposure counts, scoped to the requested download window.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct BlastRadiusSummary {
    /// Affected artifacts with at least one download in the window.
    pub affected_artifact_count: i64,
    /// Repositories holding those downloaded artifacts.
    pub affected_repo_count: i64,
    /// Distinct **authenticated** users who downloaded an affected artifact.
    pub downloader_user_count: i64,
    /// Whether any download in the window was anonymous.
    pub anonymous_download_present: bool,
    /// Distinct client IPs across all downloads in the window.
    pub distinct_ip_count: i64,
    /// Total download events of affected artifacts in the window.
    pub total_download_count: i64,
}

/// Internal row shape for the summary aggregate. `bool_or` yields NULL over
/// an empty set, so the anonymous flag decodes as an option first.
#[derive(sqlx::FromRow)]
struct SummaryRow {
    affected_artifact_count: i64,
    affected_repo_count: i64,
    downloader_user_count: i64,
    anonymous_download_present: Option<bool>,
    distinct_ip_count: i64,
    total_download_count: i64,
}

/// One repository containing an affected artifact, with its access exposure.
#[derive(Debug, Serialize, ToSchema)]
pub struct AffectedRepo {
    pub repository_id: Uuid,
    pub repository_key: String,
    pub is_public: bool,
    /// `public` | `restricted_acl` | `restricted_roles` — see
    /// [`classify_access_scope`].
    pub access_scope: String,
}

/// Internal row shape for the affected-repos query; `access_scope` is
/// classified in Rust from `is_public` + `has_acl_rules`.
#[derive(sqlx::FromRow)]
struct AffectedRepoRow {
    repository_id: Uuid,
    repository_key: String,
    is_public: bool,
    has_acl_rules: bool,
}

/// One downloader (or the anonymous bucket) of an affected artifact.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct BlastDownloader {
    /// `None` groups all anonymous downloads.
    pub user_id: Option<Uuid>,
    /// Username when the download was authenticated and the user still
    /// exists; `None` for the anonymous bucket (or a deleted user).
    pub username: Option<String>,
    pub download_count: i64,
    pub distinct_ip_count: i64,
    pub first_download: chrono::DateTime<chrono::Utc>,
    pub last_download: chrono::DateTime<chrono::Utc>,
    /// Sample of distinct client IPs (bounded; counts stay exact).
    pub ip_addresses: Vec<String>,
}

/// Full blast-radius report for a CVE or artifact.
#[derive(Debug, Serialize, ToSchema)]
pub struct BlastRadiusResponse {
    pub target: BlastRadiusTargetInfo,
    pub summary: BlastRadiusSummary,
    /// Every repository containing an affected artifact (downloaded or not),
    /// bounded to [`MAX_AFFECTED_REPOS`] entries.
    pub affected_repos: Vec<AffectedRepo>,
    /// Paginated distinct downloaders, most recent first.
    pub downloaders: Vec<BlastDownloader>,
    /// Total distinct downloader principals (the anonymous bucket counts as
    /// one) — the pagination total for `downloaders`.
    pub total_downloaders: i64,
    pub page: u32,
    pub per_page: u32,
}

fn require_admin(auth: &AuthExtension) -> Result<()> {
    // Defense-in-depth: the `/admin` nest already enforces admin_middleware,
    // but never rely on a single gate for sensitive download attribution.
    if auth.is_admin {
        Ok(())
    } else {
        Err(AppError::Authorization(
            "Admin privileges required".to_string(),
        ))
    }
}

fn db_err(e: sqlx::Error) -> AppError {
    AppError::Database(e.to_string())
}

/// Shared blast-radius core for the CVE and artifact endpoints.
async fn blast_radius_core(
    db: &sqlx::PgPool,
    target: BlastRadiusTarget,
    query: &BlastRadiusQuery,
) -> Result<BlastRadiusResponse> {
    let (offset, limit, page, per_page) = blast_page_bounds(query.page, query.per_page);
    let from = parse_rfc3339_bound(query.from.as_deref(), "from")?;
    let to = parse_rfc3339_bound(query.to.as_deref(), "to")?;

    // Aggregate exposure counts over the (deduped artifacts × downloads)
    // join. Single bounded aggregate; acceptable for an admin-only report.
    let mut summary_builder = sqlx::QueryBuilder::new(
        "SELECT COUNT(DISTINCT f.artifact_id) AS affected_artifact_count, \
         COUNT(DISTINCT a.repository_id) AS affected_repo_count, \
         COUNT(DISTINCT d.user_id) AS downloader_user_count, \
         bool_or(d.user_id IS NULL) AS anonymous_download_present, \
         COUNT(DISTINCT d.ip_address) AS distinct_ip_count, \
         COUNT(*) AS total_download_count FROM ",
    );
    push_affected_artifacts(&mut summary_builder, &target);
    summary_builder.push(
        " JOIN download_statistics d ON d.artifact_id = f.artifact_id \
         JOIN artifacts a ON a.id = f.artifact_id WHERE TRUE",
    );
    push_download_window(&mut summary_builder, from, to);
    let summary: SummaryRow = summary_builder
        .build_query_as()
        .fetch_one(db)
        .await
        .map_err(db_err)?;

    // Pagination total: distinct downloader principals (NULL user_id — the
    // anonymous bucket — is one DISTINCT group, matching the page query).
    let mut total_builder =
        sqlx::QueryBuilder::new("SELECT COUNT(*) FROM (SELECT DISTINCT d.user_id FROM ");
    push_affected_artifacts(&mut total_builder, &target);
    total_builder.push(" JOIN download_statistics d ON d.artifact_id = f.artifact_id WHERE TRUE");
    push_download_window(&mut total_builder, from, to);
    total_builder.push(") t");
    let total_downloaders: i64 = total_builder
        .build_query_scalar()
        .fetch_one(db)
        .await
        .map_err(db_err)?;

    // One page of downloaders, collapsed per principal, most recent first.
    let mut page_builder = sqlx::QueryBuilder::new(format!(
        "SELECT d.user_id, u.username, COUNT(*) AS download_count, \
         COUNT(DISTINCT d.ip_address) AS distinct_ip_count, \
         MIN(d.downloaded_at) AS first_download, \
         MAX(d.downloaded_at) AS last_download, \
         (COALESCE(ARRAY_AGG(DISTINCT d.ip_address) \
          FILTER (WHERE d.ip_address IS NOT NULL), ARRAY[]::varchar[]))[1:{}] \
          AS ip_addresses FROM ",
        MAX_IPS_PER_DOWNLOADER
    ));
    push_affected_artifacts(&mut page_builder, &target);
    page_builder.push(
        " JOIN download_statistics d ON d.artifact_id = f.artifact_id \
         LEFT JOIN users u ON u.id = d.user_id WHERE TRUE",
    );
    push_download_window(&mut page_builder, from, to);
    page_builder
        .push(" GROUP BY d.user_id, u.username ORDER BY MAX(d.downloaded_at) DESC LIMIT ")
        .push_bind(limit)
        .push(" OFFSET ")
        .push_bind(offset);
    let downloaders: Vec<BlastDownloader> = page_builder
        .build_query_as()
        .fetch_all(db)
        .await
        .map_err(db_err)?;

    // Every repository containing an affected artifact — independent of the
    // download window, so admins see exposure even before the first pull.
    let mut repos_builder = sqlx::QueryBuilder::new(
        "SELECT DISTINCT a.repository_id, r.key AS repository_key, r.is_public, \
         EXISTS(SELECT 1 FROM permissions p WHERE p.target_type = 'repository' \
         AND p.target_id = a.repository_id) AS has_acl_rules FROM ",
    );
    push_affected_artifacts(&mut repos_builder, &target);
    repos_builder.push(
        " JOIN artifacts a ON a.id = f.artifact_id \
         JOIN repositories r ON r.id = a.repository_id ORDER BY repository_key",
    );
    repos_builder
        .push(" LIMIT ")
        .push_bind(i64::from(MAX_AFFECTED_REPOS));
    let repo_rows: Vec<AffectedRepoRow> = repos_builder
        .build_query_as()
        .fetch_all(db)
        .await
        .map_err(db_err)?;
    let affected_repos = repo_rows
        .into_iter()
        .map(|r| AffectedRepo {
            repository_id: r.repository_id,
            repository_key: r.repository_key,
            is_public: r.is_public,
            access_scope: classify_access_scope(r.is_public, r.has_acl_rules).to_string(),
        })
        .collect();

    Ok(BlastRadiusResponse {
        target: BlastRadiusTargetInfo {
            kind: target.kind().to_string(),
            value: target.value(),
        },
        summary: BlastRadiusSummary {
            affected_artifact_count: summary.affected_artifact_count,
            affected_repo_count: summary.affected_repo_count,
            downloader_user_count: summary.downloader_user_count,
            anonymous_download_present: summary.anonymous_download_present.unwrap_or(false),
            distinct_ip_count: summary.distinct_ip_count,
            total_download_count: summary.total_download_count,
        },
        affected_repos,
        downloaders,
        total_downloaders,
        page,
        per_page,
    })
}

/// Blast radius for a CVE: who downloaded any artifact flagged with it, and
/// how exposed the repositories holding those artifacts are (#2364).
#[utoipa::path(
    get,
    path = "/cve/{cve_id}/blast-radius",
    context_path = "/api/v1/admin/security",
    tag = "admin",
    params(
        ("cve_id" = String, Path, description = "CVE id (exact match, e.g. CVE-2021-44228)"),
        BlastRadiusQuery
    ),
    responses(
        (status = 200, description = "Blast-radius report", body = BlastRadiusResponse),
        (status = 400, description = "Invalid parameter"),
        (status = 403, description = "Admin privileges required")
    ),
    security(("bearer_auth" = []))
)]
pub async fn cve_blast_radius(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(cve_id): Path<String>,
    Query(query): Query<BlastRadiusQuery>,
) -> Result<Json<BlastRadiusResponse>> {
    require_admin(&auth)?;
    let cve_id = cve_id.trim().to_string();
    if cve_id.is_empty() {
        return Err(AppError::Validation("cve_id must not be empty".to_string()));
    }
    Ok(Json(
        blast_radius_core(&state.db, BlastRadiusTarget::Cve(cve_id), &query).await?,
    ))
}

/// Blast radius for one artifact: who downloaded it, regardless of which
/// CVE flagged it (#2364).
#[utoipa::path(
    get,
    path = "/artifact/{artifact_id}/blast-radius",
    context_path = "/api/v1/admin/security",
    tag = "admin",
    params(
        ("artifact_id" = Uuid, Path, description = "Artifact id"),
        BlastRadiusQuery
    ),
    responses(
        (status = 200, description = "Blast-radius report", body = BlastRadiusResponse),
        (status = 400, description = "Invalid parameter"),
        (status = 403, description = "Admin privileges required")
    ),
    security(("bearer_auth" = []))
)]
pub async fn artifact_blast_radius(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(artifact_id): Path<Uuid>,
    Query(query): Query<BlastRadiusQuery>,
) -> Result<Json<BlastRadiusResponse>> {
    require_admin(&auth)?;
    Ok(Json(
        blast_radius_core(&state.db, BlastRadiusTarget::Artifact(artifact_id), &query).await?,
    ))
}

// ---------------------------------------------------------------------------
// Phase 2 (#2386): accessible-but-not-downloaded enumeration for restricted
// repositories. Read-only; inverts the shared REST read predicate and
// anti-joins download_statistics.
// ---------------------------------------------------------------------------

/// Decide whether an accessible set is large enough to be reported as
/// "effectively everyone" rather than enumerated. Pure so the coverage gate
/// exercises the threshold arithmetic without Postgres. Guards against a zero
/// or negative denominator (never collapses an empty deployment).
pub(crate) fn is_effectively_everyone(accessible_count: i64, active_user_count: i64) -> bool {
    active_user_count > 0
        && (accessible_count as f64) >= BLAST_EVERYONE_THRESHOLD * (active_user_count as f64)
}

/// Classify the repo's exposure for the accessible-users report:
/// - `public` scope           -> `everyone` (never enumerated),
/// - accessible ~ all users   -> `effectively-everyone` (count only, no list),
/// - otherwise                -> `enumerable`.
pub(crate) fn classify_exposure(
    access_scope: &str,
    accessible_count: i64,
    active_user_count: i64,
) -> &'static str {
    if access_scope == "public" {
        "everyone"
    } else if is_effectively_everyone(accessible_count, active_user_count) {
        "effectively-everyone"
    } else {
        "enumerable"
    }
}

/// Build the WHERE predicate that selects users who can read an affected
/// artifact in the repository but have not downloaded one. `affected_sql` is a
/// single-column `SELECT artifact_id ...` subquery for the target (binds its own
/// `$2`); `$1` is the repository id.
///
/// The permissions arm reuses the EXACT shared fragment
/// (`permissions_grant_exists_for`, project + group + fail-closed on empty
/// actions) instead of a hand-rolled copy, so the enumeration cannot drift from
/// the data-plane read predicate. The role arm mirrors the
/// `RepoVisibility::User` role_assignments branch (repo-scoped OR global NULL);
/// admins always read. The trailing anti-join yields `has-access` only.
fn accessible_users_predicate(affected_sql: &str) -> String {
    let perms = permissions_grant_exists_for("$1", "u.id");
    format!(
        "u.is_active \
         AND ( \
             u.is_admin \
             OR EXISTS ( \
                 SELECT 1 FROM role_assignments ra \
                 WHERE ra.user_id = u.id \
                   AND (ra.repository_id = $1 OR ra.repository_id IS NULL) \
             ) \
             OR {perms} \
         ) \
         AND NOT EXISTS ( \
             SELECT 1 FROM download_statistics d \
             WHERE d.user_id = u.id AND d.artifact_id IN ({affected_sql}) \
         )"
    )
}

/// Query parameters for the accessible-users endpoints.
#[derive(Debug, Default, Deserialize, IntoParams)]
pub struct AccessibleUsersQuery {
    /// Repository to scope the enumeration to. **Required** for the CVE route
    /// (a CVE spans many repos); ignored for the artifact route (implied by the
    /// artifact).
    pub repository_id: Option<Uuid>,
    /// 1-based page over the accessible-users list.
    pub page: Option<u32>,
    /// Users per page (1..=100, default 20).
    pub per_page: Option<u32>,
}

/// Repository exposure descriptor echoed in the response.
#[derive(Debug, Serialize, ToSchema)]
pub struct RepoExposure {
    pub repository_id: Uuid,
    pub repository_key: String,
    /// `public` | `restricted_acl` | `restricted_roles` — see
    /// [`classify_access_scope`].
    pub access_scope: String,
}

/// One principal that can read an affected artifact but has not downloaded it.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct AccessibleUser {
    pub user_id: Uuid,
    pub username: String,
    /// Always `has-access` for this endpoint (accessible minus downloaded).
    pub reason: String,
    /// How access is granted: `admin` (global), `permission` (fine-grained
    /// direct **or** group grant, repo or owning project), or `role`
    /// (role_assignment only). Direct and group grants both surface as
    /// `permission` because they share one read fragment.
    pub via: String,
}

/// Internal row shape for the accessible-users page query.
#[derive(sqlx::FromRow)]
struct AccessibleUserRow {
    user_id: Uuid,
    username: String,
    via: String,
}

/// Full accessible-but-not-downloaded report for a CVE or artifact, scoped to
/// one restricted repository.
#[derive(Debug, Serialize, ToSchema)]
pub struct AccessibleUsersResponse {
    pub target: BlastRadiusTargetInfo,
    pub repository: RepoExposure,
    /// `enumerable` | `everyone` | `effectively-everyone`.
    pub exposure: String,
    /// The page of accessible-but-not-downloaded principals. Empty when
    /// `exposure != "enumerable"`.
    pub accessible_not_downloaded: Vec<AccessibleUser>,
    /// Total accessible-not-downloaded principals (the pagination total).
    /// `null` for `public` repos (never enumerated).
    pub total: Option<i64>,
    pub page: u32,
    pub per_page: u32,
}

/// Fetched repository metadata for the enumeration.
struct RepoMeta {
    repository_key: String,
    is_public: bool,
    has_acl_rules: bool,
}

/// Load the repo's key, public flag, and whether any repository-scoped ACL row
/// exists (mirrors phase-1 `classify_access_scope`'s repository-only EXISTS).
async fn load_repo_meta(db: &sqlx::PgPool, repo_id: Uuid) -> Result<Option<RepoMeta>> {
    let row = sqlx::query_as::<_, (String, bool, bool)>(
        "SELECT r.key, r.is_public, \
         EXISTS(SELECT 1 FROM permissions p WHERE p.target_type = 'repository' \
                AND p.target_id = r.id) AS has_acl_rules \
         FROM repositories r WHERE r.id = $1",
    )
    .bind(repo_id)
    .fetch_optional(db)
    .await
    .map_err(db_err)?;
    Ok(
        row.map(|(repository_key, is_public, has_acl_rules)| RepoMeta {
            repository_key,
            is_public,
            has_acl_rules,
        }),
    )
}

/// Shared accessible-users core. `repo_id` is already resolved (from the path
/// artifact or the required `repository_id` query param); `affected_sql` binds
/// its own `$2` target value, supplied via `bind_target`.
async fn accessible_users_core(
    db: &sqlx::PgPool,
    target: BlastRadiusTarget,
    repo_id: Uuid,
    affected_sql: &str,
    query: &AccessibleUsersQuery,
) -> Result<AccessibleUsersResponse> {
    let (offset, limit, page, per_page) = blast_page_bounds(query.page, query.per_page);

    let meta = load_repo_meta(db, repo_id)
        .await?
        .ok_or_else(|| AppError::NotFound("repository not found".to_string()))?;
    let access_scope = classify_access_scope(meta.is_public, meta.has_acl_rules).to_string();

    let repository = RepoExposure {
        repository_id: repo_id,
        repository_key: meta.repository_key,
        access_scope: access_scope.clone(),
    };
    let target_info = BlastRadiusTargetInfo {
        kind: target.kind().to_string(),
        value: target.value(),
    };

    // Never enumerate a public/everyone-exposed repository.
    if meta.is_public {
        return Ok(AccessibleUsersResponse {
            target: target_info,
            repository,
            exposure: "everyone".to_string(),
            accessible_not_downloaded: vec![],
            total: None,
            page,
            per_page,
        });
    }

    let predicate = accessible_users_predicate(affected_sql);

    // (1) COUNT over the predicate for pagination + everyone-threshold.
    let count_sql = format!("SELECT COUNT(*) FROM users u WHERE {predicate}");
    let mut count_q = sqlx::query_scalar::<_, i64>(&count_sql).bind(repo_id);
    count_q = bind_target(count_q, &target);
    let accessible_count: i64 = count_q.fetch_one(db).await.map_err(db_err)?;

    // Active, non-service user population for the effectively-everyone check.
    let active_user_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_active AND NOT is_service_account")
            .fetch_one(db)
            .await
            .map_err(db_err)?;

    let exposure = classify_exposure(&access_scope, accessible_count, active_user_count);
    if exposure != "enumerable" {
        // effectively-everyone: report the count but suppress the page body.
        return Ok(AccessibleUsersResponse {
            target: target_info,
            repository,
            exposure: exposure.to_string(),
            accessible_not_downloaded: vec![],
            total: Some(accessible_count),
            page,
            per_page,
        });
    }

    // (2) One page of accessible-not-downloaded users.
    let page_sql = format!(
        "SELECT u.id AS user_id, u.username, \
         CASE WHEN u.is_admin THEN 'admin' \
              WHEN {perms} THEN 'permission' \
              ELSE 'role' END AS via \
         FROM users u WHERE {predicate} \
         ORDER BY u.username LIMIT $3 OFFSET $4",
        perms = permissions_grant_exists_for("$1", "u.id"),
        predicate = predicate,
    );
    let mut page_q = sqlx::query_as::<_, AccessibleUserRow>(&page_sql).bind(repo_id);
    page_q = bind_target_as(page_q, &target);
    let rows: Vec<AccessibleUserRow> = page_q
        .bind(limit)
        .bind(offset)
        .fetch_all(db)
        .await
        .map_err(db_err)?;

    let accessible_not_downloaded = rows
        .into_iter()
        .map(|r| AccessibleUser {
            user_id: r.user_id,
            username: r.username,
            reason: "has-access".to_string(),
            via: r.via,
        })
        .collect();

    Ok(AccessibleUsersResponse {
        target: target_info,
        repository,
        exposure: exposure.to_string(),
        accessible_not_downloaded,
        total: Some(accessible_count),
        page,
        per_page,
    })
}

/// Bind the `$2` affected-set target value onto a `query_scalar` builder.
fn bind_target<'a>(
    q: sqlx::query::QueryScalar<'a, sqlx::Postgres, i64, sqlx::postgres::PgArguments>,
    target: &'a BlastRadiusTarget,
) -> sqlx::query::QueryScalar<'a, sqlx::Postgres, i64, sqlx::postgres::PgArguments> {
    match target {
        BlastRadiusTarget::Cve(cve_id) => q.bind(cve_id.clone()),
        BlastRadiusTarget::Artifact(artifact_id) => q.bind(*artifact_id),
    }
}

/// Bind the `$2` affected-set target value onto a `query_as` builder.
fn bind_target_as<'a>(
    q: sqlx::query::QueryAs<'a, sqlx::Postgres, AccessibleUserRow, sqlx::postgres::PgArguments>,
    target: &'a BlastRadiusTarget,
) -> sqlx::query::QueryAs<'a, sqlx::Postgres, AccessibleUserRow, sqlx::postgres::PgArguments> {
    match target {
        BlastRadiusTarget::Cve(cve_id) => q.bind(cve_id.clone()),
        BlastRadiusTarget::Artifact(artifact_id) => q.bind(*artifact_id),
    }
}

/// The affected-artifact subquery for a CVE target: all artifacts flagged with
/// the CVE (binds `$2`).
const CVE_AFFECTED_SQL: &str = "SELECT DISTINCT artifact_id FROM scan_findings WHERE cve_id = $2";
/// The affected-artifact subquery for a single artifact target: the artifact
/// itself (binds `$2`), independent of whether a finding row exists.
const ARTIFACT_AFFECTED_SQL: &str = "SELECT $2::uuid";

/// Accessible-but-not-downloaded users for a CVE, scoped to one restricted
/// repository (#2386). `repository_id` is required and must be a repo the CVE
/// actually affects.
#[utoipa::path(
    get,
    path = "/cve/{cve_id}/accessible-users",
    context_path = "/api/v1/admin/security",
    tag = "admin",
    params(
        ("cve_id" = String, Path, description = "CVE id (exact match, e.g. CVE-2021-44228)"),
        AccessibleUsersQuery
    ),
    responses(
        (status = 200, description = "Accessible-not-downloaded report", body = AccessibleUsersResponse),
        (status = 400, description = "Invalid parameter"),
        (status = 403, description = "Admin privileges required"),
        (status = 404, description = "CVE does not affect the repository")
    ),
    security(("bearer_auth" = []))
)]
pub async fn cve_accessible_users(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(cve_id): Path<String>,
    Query(query): Query<AccessibleUsersQuery>,
) -> Result<Json<AccessibleUsersResponse>> {
    require_admin(&auth)?;
    let cve_id = cve_id.trim().to_string();
    if cve_id.is_empty() {
        return Err(AppError::Validation("cve_id must not be empty".to_string()));
    }
    let repo_id = query.repository_id.ok_or_else(|| {
        AppError::Validation("repository_id query parameter is required".to_string())
    })?;

    // The CVE must actually flag an artifact in this repository — otherwise the
    // enumeration would leak an unrelated repo's access graph.
    let affects: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM scan_findings sf \
         JOIN artifacts a ON a.id = sf.artifact_id \
         WHERE sf.cve_id = $1 AND a.repository_id = $2)",
    )
    .bind(&cve_id)
    .bind(repo_id)
    .fetch_one(&state.db)
    .await
    .map_err(db_err)?;
    if !affects {
        return Err(AppError::NotFound(
            "CVE does not affect the specified repository".to_string(),
        ));
    }

    Ok(Json(
        accessible_users_core(
            &state.db,
            BlastRadiusTarget::Cve(cve_id),
            repo_id,
            CVE_AFFECTED_SQL,
            &query,
        )
        .await?,
    ))
}

/// Accessible-but-not-downloaded users for one artifact (#2386). The repository
/// is implied by the artifact.
#[utoipa::path(
    get,
    path = "/artifact/{artifact_id}/accessible-users",
    context_path = "/api/v1/admin/security",
    tag = "admin",
    params(
        ("artifact_id" = Uuid, Path, description = "Artifact id"),
        AccessibleUsersQuery
    ),
    responses(
        (status = 200, description = "Accessible-not-downloaded report", body = AccessibleUsersResponse),
        (status = 403, description = "Admin privileges required"),
        (status = 404, description = "Artifact not found")
    ),
    security(("bearer_auth" = []))
)]
pub async fn artifact_accessible_users(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(artifact_id): Path<Uuid>,
    Query(query): Query<AccessibleUsersQuery>,
) -> Result<Json<AccessibleUsersResponse>> {
    require_admin(&auth)?;
    let repo_id: Option<Uuid> =
        sqlx::query_scalar("SELECT repository_id FROM artifacts WHERE id = $1")
            .bind(artifact_id)
            .fetch_optional(&state.db)
            .await
            .map_err(db_err)?;
    let repo_id = repo_id.ok_or_else(|| AppError::NotFound("artifact not found".to_string()))?;
    Ok(Json(
        accessible_users_core(
            &state.db,
            BlastRadiusTarget::Artifact(artifact_id),
            repo_id,
            ARTIFACT_AFFECTED_SQL,
            &query,
        )
        .await?,
    ))
}

#[derive(OpenApi)]
#[openapi(
    paths(
        cve_blast_radius,
        artifact_blast_radius,
        cve_accessible_users,
        artifact_accessible_users
    ),
    components(schemas(
        BlastRadiusResponse,
        BlastRadiusTargetInfo,
        BlastRadiusSummary,
        AffectedRepo,
        BlastDownloader,
        AccessibleUsersResponse,
        RepoExposure,
        AccessibleUser,
    ))
)]
pub struct AdminSecurityApiDoc;

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Pure helpers — no DB required.
    // -----------------------------------------------------------------------

    #[test]
    fn test_blast_page_bounds_defaults() {
        let (offset, limit, page, per_page) = blast_page_bounds(None, None);
        assert_eq!(offset, 0);
        assert_eq!(limit, i64::from(BLAST_DEFAULT_PER_PAGE));
        assert_eq!(page, 1);
        assert_eq!(per_page, BLAST_DEFAULT_PER_PAGE);
    }

    #[test]
    fn test_blast_page_bounds_clamps_oversized_per_page() {
        let (offset, limit, page, per_page) = blast_page_bounds(Some(2), Some(10_000));
        assert_eq!(per_page, BLAST_MAX_PER_PAGE);
        assert_eq!(limit, i64::from(BLAST_MAX_PER_PAGE));
        assert_eq!(page, 2);
        assert_eq!(offset, i64::from(BLAST_MAX_PER_PAGE));
    }

    #[test]
    fn test_blast_page_bounds_floors_page_and_per_page() {
        let (offset, limit, page, per_page) = blast_page_bounds(Some(0), Some(0));
        assert_eq!(page, 1);
        assert_eq!(per_page, 1);
        assert_eq!(limit, 1);
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_blast_page_bounds_offset_math() {
        let (offset, limit, page, per_page) = blast_page_bounds(Some(4), Some(25));
        assert_eq!(offset, 75);
        assert_eq!(limit, 25);
        assert_eq!(page, 4);
        assert_eq!(per_page, 25);
    }

    #[test]
    fn test_classify_access_scope_branches() {
        assert_eq!(classify_access_scope(true, false), "public");
        // Public wins even when ACL rows exist.
        assert_eq!(classify_access_scope(true, true), "public");
        assert_eq!(classify_access_scope(false, true), "restricted_acl");
        assert_eq!(classify_access_scope(false, false), "restricted_roles");
    }

    #[test]
    fn test_target_kind_and_value() {
        let cve = BlastRadiusTarget::Cve("CVE-2021-44228".to_string());
        assert_eq!(cve.kind(), "cve");
        assert_eq!(cve.value(), "CVE-2021-44228");
        let id = Uuid::new_v4();
        let artifact = BlastRadiusTarget::Artifact(id);
        assert_eq!(artifact.kind(), "artifact");
        assert_eq!(artifact.value(), id.to_string());
    }

    // ---- Phase 2 (#2386): accessible-users pure helpers ----

    #[test]
    fn test_is_effectively_everyone_threshold() {
        // 90% boundary is inclusive.
        assert!(is_effectively_everyone(90, 100));
        assert!(is_effectively_everyone(100, 100));
        assert!(!is_effectively_everyone(89, 100));
        // Empty / zero population never collapses.
        assert!(!is_effectively_everyone(0, 0));
        assert!(!is_effectively_everyone(5, 0));
    }

    #[test]
    fn test_classify_exposure_branches() {
        // Public is never enumerated regardless of counts.
        assert_eq!(classify_exposure("public", 1, 100), "everyone");
        // Restricted, small accessible set -> enumerable.
        assert_eq!(classify_exposure("restricted_acl", 3, 100), "enumerable");
        assert_eq!(classify_exposure("restricted_roles", 3, 100), "enumerable");
        // Restricted, ~everyone -> collapse.
        assert_eq!(
            classify_exposure("restricted_roles", 95, 100),
            "effectively-everyone"
        );
    }

    #[test]
    fn test_accessible_users_predicate_shape() {
        let sql = accessible_users_predicate(CVE_AFFECTED_SQL);
        // Role-assignment arm (repo-scoped OR global NULL).
        assert!(sql.contains("role_assignments"), "role arm missing: {sql}");
        assert!(
            sql.contains("ra.repository_id = $1 OR ra.repository_id IS NULL"),
            "role arm scoping missing: {sql}"
        );
        // The shared permissions fragment: project + group + fail-closed.
        assert!(
            sql.contains("p.target_type = 'project'"),
            "project arm: {sql}"
        );
        assert!(
            sql.contains("user_group_members"),
            "group UNION missing: {sql}"
        );
        assert!(
            sql.contains("p.actions <> '{}'"),
            "fail-closed missing: {sql}"
        );
        // Correlated over the outer users scan, not a positional bind.
        assert!(
            sql.contains("p.principal_id = u.id"),
            "correlated user: {sql}"
        );
        // The download anti-join (has-access ONLY).
        assert!(
            sql.contains("NOT EXISTS") && sql.contains("download_statistics"),
            "download anti-join missing: {sql}"
        );
        // Admin short-circuit.
        assert!(sql.contains("u.is_admin"), "admin arm missing: {sql}");
    }

    // -----------------------------------------------------------------------
    // DB-backed tests — skip cleanly without DATABASE_URL (CI coverage job
    // provides Postgres + migrations).
    // -----------------------------------------------------------------------

    use crate::api::handlers::test_db_helpers as tdh;

    /// Insert one artifact version into `repo_id`, returning its id.
    async fn seed_artifact_version(pool: &sqlx::PgPool, repo_id: Uuid, version: &str) -> Uuid {
        sqlx::query_scalar(
            "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
             checksum_sha256, content_type, storage_key) \
             VALUES ($1, $2, 'blast-radius', $3, 4, $4, 'application/octet-stream', $2) \
             RETURNING id",
        )
        .bind(repo_id)
        .bind(format!("blast-radius/{}/{}.bin", version, Uuid::new_v4()))
        .bind(version)
        .bind(format!("{:0>64}", "b"))
        .fetch_one(pool)
        .await
        .expect("insert artifact")
    }

    /// Attach a completed scan result + one finding for `cve_id` to the
    /// artifact, in a single statement.
    async fn seed_cve_finding(pool: &sqlx::PgPool, repo_id: Uuid, artifact_id: Uuid, cve_id: &str) {
        sqlx::query(
            "WITH sr AS ( \
                INSERT INTO scan_results (artifact_id, repository_id, scan_type, status, \
                    findings_count, started_at, completed_at) \
                VALUES ($1, $2, 'dependency', 'completed', 1, NOW(), NOW()) \
                RETURNING id) \
             INSERT INTO scan_findings (scan_result_id, artifact_id, severity, title, \
                cve_id, source) \
             SELECT sr.id, $1, 'high', 'blast-radius test finding', $3, 'trivy' FROM sr",
        )
        .bind(artifact_id)
        .bind(repo_id)
        .bind(cve_id)
        .execute(pool)
        .await
        .expect("seed scan finding");
    }

    /// Record one download of `artifact_id` (user `None` = anonymous).
    async fn seed_download(
        pool: &sqlx::PgPool,
        artifact_id: Uuid,
        user_id: Option<Uuid>,
        ip: &str,
    ) {
        sqlx::query(
            "INSERT INTO download_statistics (artifact_id, user_id, ip_address, \
             user_agent, downloaded_at) VALUES ($1, $2, $3, 'blast-test/1.0', NOW())",
        )
        .bind(artifact_id)
        .bind(user_id)
        .bind(ip)
        .execute(pool)
        .await
        .expect("seed download");
    }

    #[tokio::test]
    async fn test_blast_radius_core_aggregates_and_paginates_db() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let cve = format!("CVE-2364-{}", &Uuid::new_v4().to_string()[..8]);
        let (user1, name1) = tdh::create_user(&pool).await;
        let (user2, _name2) = tdh::create_user(&pool).await;
        let (repo_id, _key, _dir) = tdh::create_repo(&pool, "local", "generic").await;
        // The same CVE flags TWO versions of the artifact.
        let v1 = seed_artifact_version(&pool, repo_id, "1.0.0").await;
        let v2 = seed_artifact_version(&pool, repo_id, "1.1.0").await;
        seed_cve_finding(&pool, repo_id, v1, &cve).await;
        seed_cve_finding(&pool, repo_id, v2, &cve).await;
        // user1 pulls v1 twice from two IPs, user2 pulls v2 once, plus one
        // anonymous pull of v1.
        seed_download(&pool, v1, Some(user1), "203.0.113.20").await;
        seed_download(&pool, v1, Some(user1), "203.0.113.21").await;
        seed_download(&pool, v2, Some(user2), "203.0.113.22").await;
        seed_download(&pool, v1, None, "203.0.113.23").await;

        let resp = blast_radius_core(
            &pool,
            BlastRadiusTarget::Cve(cve.clone()),
            &BlastRadiusQuery::default(),
        )
        .await
        .expect("cve blast radius");
        assert_eq!(resp.target.kind, "cve");
        assert_eq!(resp.target.value, cve);
        assert_eq!(resp.summary.affected_artifact_count, 2);
        assert_eq!(resp.summary.affected_repo_count, 1);
        assert_eq!(resp.summary.downloader_user_count, 2);
        assert!(resp.summary.anonymous_download_present);
        assert_eq!(resp.summary.distinct_ip_count, 4);
        assert_eq!(resp.summary.total_download_count, 4);
        // Distinct principals: user1, user2, anonymous.
        assert_eq!(resp.total_downloaders, 3);
        assert_eq!(resp.downloaders.len(), 3);
        let u1 = resp
            .downloaders
            .iter()
            .find(|d| d.user_id == Some(user1))
            .expect("user1 row");
        assert_eq!(u1.username.as_deref(), Some(name1.as_str()));
        assert_eq!(u1.download_count, 2);
        assert_eq!(u1.distinct_ip_count, 2);
        assert_eq!(u1.ip_addresses.len(), 2);
        assert!(u1.first_download <= u1.last_download);
        let anon = resp
            .downloaders
            .iter()
            .find(|d| d.user_id.is_none())
            .expect("anonymous row");
        assert_eq!(anon.username, None);
        assert_eq!(anon.download_count, 1);
        // Private repo without ACL rows -> restricted_roles.
        assert_eq!(resp.affected_repos.len(), 1);
        assert_eq!(resp.affected_repos[0].repository_id, repo_id);
        assert_eq!(resp.affected_repos[0].access_scope, "restricted_roles");

        // per_page=1 -> one row per page, total unchanged.
        let paged = blast_radius_core(
            &pool,
            BlastRadiusTarget::Cve(cve.clone()),
            &BlastRadiusQuery {
                page: Some(2),
                per_page: Some(1),
                ..Default::default()
            },
        )
        .await
        .expect("paged blast radius");
        assert_eq!(paged.total_downloaders, 3);
        assert_eq!(paged.downloaders.len(), 1);
        assert_eq!(paged.page, 2);
        assert_eq!(paged.per_page, 1);

        // A future-only window sees no downloads, but the affected repos are
        // still listed (exposure exists before the first pull).
        let future = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
        let windowed = blast_radius_core(
            &pool,
            BlastRadiusTarget::Cve(cve.clone()),
            &BlastRadiusQuery {
                from: Some(future),
                ..Default::default()
            },
        )
        .await
        .expect("windowed blast radius");
        assert_eq!(windowed.total_downloaders, 0);
        assert_eq!(windowed.summary.total_download_count, 0);
        assert!(!windowed.summary.anonymous_download_present);
        assert_eq!(windowed.affected_repos.len(), 1);

        // Artifact scope: only v1's downloads (user1 x2 + anonymous).
        let scoped = blast_radius_core(
            &pool,
            BlastRadiusTarget::Artifact(v1),
            &BlastRadiusQuery::default(),
        )
        .await
        .expect("artifact blast radius");
        assert_eq!(scoped.target.kind, "artifact");
        assert_eq!(scoped.summary.affected_artifact_count, 1);
        assert_eq!(scoped.summary.total_download_count, 3);
        assert_eq!(scoped.total_downloaders, 2);

        // Malformed time bound -> validation error.
        let err = blast_radius_core(
            &pool,
            BlastRadiusTarget::Cve(cve),
            &BlastRadiusQuery {
                from: Some("yesterday".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));

        tdh::cleanup(&pool, repo_id, user1).await;
        tdh::cleanup_user(&pool, user2).await;
    }

    #[tokio::test]
    async fn test_blast_radius_access_scope_classification_db() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let cve = format!("CVE-2364-{}", &Uuid::new_v4().to_string()[..8]);
        let (user_id, _name) = tdh::create_user(&pool).await;
        // Public repo.
        let (repo_pub, key_pub, _d1) = tdh::create_repo(&pool, "local", "generic").await;
        sqlx::query("UPDATE repositories SET is_public = true WHERE id = $1")
            .bind(repo_pub)
            .execute(&pool)
            .await
            .expect("mark public");
        // Private repo with an explicit ACL row.
        let (repo_acl, key_acl, _d2) = tdh::create_repo(&pool, "local", "generic").await;
        sqlx::query(
            "INSERT INTO permissions (principal_type, principal_id, target_type, \
             target_id, actions) VALUES ('user', $1, 'repository', $2, '{read}')",
        )
        .bind(user_id)
        .bind(repo_acl)
        .execute(&pool)
        .await
        .expect("seed acl");

        for repo_id in [repo_pub, repo_acl] {
            let artifact = seed_artifact_version(&pool, repo_id, "2.0.0").await;
            seed_cve_finding(&pool, repo_id, artifact, &cve).await;
        }

        let resp = blast_radius_core(
            &pool,
            BlastRadiusTarget::Cve(cve),
            &BlastRadiusQuery::default(),
        )
        .await
        .expect("blast radius");
        let scope_of = |key: &str| {
            resp.affected_repos
                .iter()
                .find(|r| r.repository_key == key)
                .map(|r| r.access_scope.clone())
        };
        assert_eq!(scope_of(&key_pub).as_deref(), Some("public"));
        assert_eq!(scope_of(&key_acl).as_deref(), Some("restricted_acl"));

        let _ = sqlx::query("DELETE FROM permissions WHERE target_id = $1")
            .bind(repo_acl)
            .execute(&pool)
            .await;
        tdh::cleanup(&pool, repo_pub, user_id).await;
        // cleanup() also deletes the user; repo_acl needs its own pass.
        for q in [
            "DELETE FROM artifacts WHERE repository_id = $1",
            "DELETE FROM repositories WHERE id = $1",
        ] {
            let _ = sqlx::query(q).bind(repo_acl).execute(&pool).await;
        }
    }

    #[tokio::test]
    async fn test_blast_radius_admin_only_router_db() {
        use axum::http::StatusCode;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let state = tdh::build_state(pool.clone(), "/tmp");

        // Non-admin caller -> 403 (handler defense-in-depth, independent of
        // the /admin admin_middleware which is not mounted in this router).
        let non_admin = tdh::make_auth(user_id, &username);
        let app = tdh::router_with_auth_ext(router(), state.clone(), non_admin);
        let (status, _) = tdh::send(app, tdh::get("/cve/CVE-2021-44228/blast-radius".into())).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Admin caller -> 200 with an empty, well-formed report.
        let mut admin = tdh::make_auth(user_id, &username);
        admin.is_admin = true;
        let app = tdh::router_with_auth_ext(router(), state.clone(), admin.clone());
        let (status, body) =
            tdh::send(app, tdh::get("/cve/CVE-2021-44228/blast-radius".into())).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "admin blast radius; body: {}",
            String::from_utf8_lossy(&body)
        );
        let v: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(v["target"]["kind"], "cve");
        assert_eq!(v["total_downloaders"], 0);
        assert_eq!(v["summary"]["anonymous_download_present"], false);

        // Artifact route parses its UUID path segment.
        let app = tdh::router_with_auth_ext(router(), state, admin);
        let (status, _) = tdh::send(
            app,
            tdh::get(format!("/artifact/{}/blast-radius", Uuid::new_v4())),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        tdh::cleanup_user(&pool, user_id).await;
    }

    // -----------------------------------------------------------------------
    // Phase 2 (#2386): accessible-but-not-downloaded enumeration.
    // -----------------------------------------------------------------------

    async fn seed_group_grant(pool: &sqlx::PgPool, repo_id: Uuid, member: Uuid) -> Uuid {
        let group_id = Uuid::new_v4();
        sqlx::query("INSERT INTO groups (id, name) VALUES ($1, $2)")
            .bind(group_id)
            .bind(format!("ph-grp-{group_id}"))
            .execute(pool)
            .await
            .expect("insert group");
        sqlx::query("INSERT INTO user_group_members (user_id, group_id) VALUES ($1, $2)")
            .bind(member)
            .bind(group_id)
            .execute(pool)
            .await
            .expect("insert group member");
        sqlx::query(
            "INSERT INTO permissions (principal_type, principal_id, target_type, \
             target_id, actions) VALUES ('group', $1, 'repository', $2, '{read}')",
        )
        .bind(group_id)
        .bind(repo_id)
        .execute(pool)
        .await
        .expect("insert group grant");
        group_id
    }

    #[tokio::test]
    async fn test_accessible_users_enumeration_db() {
        use crate::services::repository_service::RepositoryService;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let cve = format!("CVE-2386-{}", &Uuid::new_v4().to_string()[..8]);
        // Restricted repo (private; create_repo defaults is_public = false) with
        // an explicit ACL row -> restricted_acl.
        let (repo_id, _key, _dir) = tdh::create_repo(&pool, "local", "generic").await;
        let artifact = seed_artifact_version(&pool, repo_id, "1.0.0").await;
        seed_cve_finding(&pool, repo_id, artifact, &cve).await;

        // Principals with read access via each distinct grant path.
        let (u_direct, _n) = tdh::create_user(&pool).await;
        tdh::grant_repo_actions(&pool, repo_id, u_direct, &["read"]).await; // permission
        let (u_group, _n) = tdh::create_user(&pool).await;
        let group_id = seed_group_grant(&pool, repo_id, u_group).await; // permission (group)
        let (u_role, _n) = tdh::create_user(&pool).await;
        tdh::grant_repo_access(&pool, repo_id, u_role).await; // role (repo-scoped)
        let (u_global, _n) = tdh::create_user(&pool).await;
        sqlx::query(
            "INSERT INTO role_assignments (user_id, role_id, repository_id) \
             SELECT $1, r.id, NULL FROM roles r WHERE r.name = 'reader'",
        )
        .bind(u_global)
        .execute(&pool)
        .await
        .expect("global role"); // role (global NULL)
        let (u_admin, _n) = tdh::create_user(&pool).await;
        sqlx::query("UPDATE users SET is_admin = true WHERE id = $1")
            .bind(u_admin)
            .execute(&pool)
            .await
            .expect("mark admin"); // admin
                                   // Downloader: has access AND downloaded an affected artifact -> excluded.
        let (u_dl, _n) = tdh::create_user(&pool).await;
        tdh::grant_repo_access(&pool, repo_id, u_dl).await;
        seed_download(&pool, artifact, Some(u_dl), "203.0.113.9").await;
        // No access at all -> excluded.
        let (u_none, _n) = tdh::create_user(&pool).await;

        let resp = accessible_users_core(
            &pool,
            BlastRadiusTarget::Cve(cve.clone()),
            repo_id,
            CVE_AFFECTED_SQL,
            &AccessibleUsersQuery {
                repository_id: Some(repo_id),
                per_page: Some(100),
                ..Default::default()
            },
        )
        .await
        .expect("accessible users");

        assert_eq!(resp.exposure, "enumerable");
        assert_eq!(resp.repository.access_scope, "restricted_acl");
        let via_of = |uid: Uuid| -> Option<String> {
            resp.accessible_not_downloaded
                .iter()
                .find(|a| a.user_id == uid)
                .map(|a| a.via.clone())
        };
        assert_eq!(via_of(u_direct).as_deref(), Some("permission"));
        assert_eq!(via_of(u_group).as_deref(), Some("permission"));
        assert_eq!(via_of(u_role).as_deref(), Some("role"));
        assert_eq!(via_of(u_global).as_deref(), Some("role"));
        assert_eq!(via_of(u_admin).as_deref(), Some("admin"));
        // Downloader and no-access are excluded.
        assert_eq!(via_of(u_dl), None, "downloader must be excluded");
        assert_eq!(via_of(u_none), None, "no-access user must be excluded");
        // reason is always has-access.
        assert!(resp
            .accessible_not_downloaded
            .iter()
            .all(|a| a.reason == "has-access"));

        // Predicate parity: every enumerated NON-admin user is actually granted
        // access by the shared REST read predicate (superset B). Admins are the
        // documented exception (user_can_access_repo bypasses is_admin).
        let repo_svc = RepositoryService::new(pool.clone());
        for a in &resp.accessible_not_downloaded {
            if a.via == "admin" {
                continue;
            }
            assert!(
                repo_svc
                    .user_can_access_repo(repo_id, a.user_id)
                    .await
                    .expect("parity check"),
                "enumerated user {} must pass user_can_access_repo",
                a.user_id
            );
        }

        // Pagination: page 1 and page 2 with per_page=2 are disjoint and bounded.
        let total = resp.total.expect("enumerable total");
        assert!(
            total >= 5,
            "at least the 5 seeded accessible users: {total}"
        );
        let p1 = accessible_users_core(
            &pool,
            BlastRadiusTarget::Cve(cve.clone()),
            repo_id,
            CVE_AFFECTED_SQL,
            &AccessibleUsersQuery {
                repository_id: Some(repo_id),
                page: Some(1),
                per_page: Some(2),
            },
        )
        .await
        .expect("page 1");
        assert_eq!(p1.accessible_not_downloaded.len(), 2);
        assert_eq!(p1.total, Some(total));
        let p2 = accessible_users_core(
            &pool,
            BlastRadiusTarget::Cve(cve.clone()),
            repo_id,
            CVE_AFFECTED_SQL,
            &AccessibleUsersQuery {
                repository_id: Some(repo_id),
                page: Some(2),
                per_page: Some(2),
            },
        )
        .await
        .expect("page 2");
        let p1_ids: std::collections::HashSet<_> = p1
            .accessible_not_downloaded
            .iter()
            .map(|a| a.user_id)
            .collect();
        assert!(
            p2.accessible_not_downloaded
                .iter()
                .all(|a| !p1_ids.contains(&a.user_id)),
            "pages must be disjoint"
        );

        // A public repo target -> exposure everyone, empty list, total null.
        let (repo_pub, _kp, _dp) = tdh::create_repo(&pool, "local", "generic").await;
        sqlx::query("UPDATE repositories SET is_public = true WHERE id = $1")
            .bind(repo_pub)
            .execute(&pool)
            .await
            .expect("mark public");
        let art_pub = seed_artifact_version(&pool, repo_pub, "1.0.0").await;
        seed_cve_finding(&pool, repo_pub, art_pub, &cve).await;
        let pub_resp = accessible_users_core(
            &pool,
            BlastRadiusTarget::Cve(cve.clone()),
            repo_pub,
            CVE_AFFECTED_SQL,
            &AccessibleUsersQuery {
                repository_id: Some(repo_pub),
                ..Default::default()
            },
        )
        .await
        .expect("public accessible users");
        assert_eq!(pub_resp.exposure, "everyone");
        assert!(pub_resp.accessible_not_downloaded.is_empty());
        assert_eq!(pub_resp.total, None);

        // Cleanup.
        let _ = sqlx::query("DELETE FROM permissions WHERE target_id = $1 OR principal_id = $2")
            .bind(repo_id)
            .bind(group_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM groups WHERE id = $1")
            .bind(group_id)
            .execute(&pool)
            .await;
        for repo in [repo_id, repo_pub] {
            for q in [
                "DELETE FROM scan_findings WHERE artifact_id IN (SELECT id FROM artifacts WHERE repository_id = $1)",
                "DELETE FROM scan_results WHERE repository_id = $1",
                "DELETE FROM download_statistics WHERE artifact_id IN (SELECT id FROM artifacts WHERE repository_id = $1)",
                "DELETE FROM role_assignments WHERE repository_id = $1",
                "DELETE FROM artifacts WHERE repository_id = $1",
                "DELETE FROM repositories WHERE id = $1",
            ] {
                let _ = sqlx::query(q).bind(repo).execute(&pool).await;
            }
        }
        for u in [u_direct, u_group, u_role, u_global, u_admin, u_dl, u_none] {
            let _ = sqlx::query("DELETE FROM role_assignments WHERE user_id = $1")
                .bind(u)
                .execute(&pool)
                .await;
            tdh::cleanup_user(&pool, u).await;
        }
    }

    #[tokio::test]
    async fn test_accessible_users_admin_only_router_db() {
        use axum::http::StatusCode;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let state = tdh::build_state(pool.clone(), "/tmp");

        // Non-admin caller -> 403 before any repo work (require_admin first).
        let non_admin = tdh::make_auth(user_id, &username);
        let app = tdh::router_with_auth_ext(router(), state.clone(), non_admin);
        let (status, _) = tdh::send(
            app,
            tdh::get(format!(
                "/cve/CVE-2021-44228/accessible-users?repository_id={}",
                Uuid::new_v4()
            )),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // Admin without repository_id -> 400 validation.
        let mut admin = tdh::make_auth(user_id, &username);
        admin.is_admin = true;
        let app = tdh::router_with_auth_ext(router(), state.clone(), admin.clone());
        let (status, _) =
            tdh::send(app, tdh::get("/cve/CVE-2021-44228/accessible-users".into())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Admin, artifact route, unknown artifact -> 404.
        let app = tdh::router_with_auth_ext(router(), state, admin);
        let (status, _) = tdh::send(
            app,
            tdh::get(format!("/artifact/{}/accessible-users", Uuid::new_v4())),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        tdh::cleanup_user(&pool, user_id).await;
    }
}
