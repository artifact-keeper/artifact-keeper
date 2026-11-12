//! Package management handlers.

use axum::{
    extract::{Path, Query, State},
    routing::get,
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::dto::Pagination;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::access_scope::AccessScope;
use crate::services::curation_service::version_compare;
use crate::services::package_service::{
    live_package_predicate, live_package_version_predicate, newest_catalog_version,
    package_download_count_over_versions, package_download_counts, version_download_count_sql,
};
use crate::services::repository_service::{
    build_visibility_clause_for, RepoVisibility, VisibilityBind,
};

/// Map an optional authenticated principal to the repository visibility scope
/// used to filter package listings. Mirrors `list_repositories` so that the
/// packages endpoints enforce the same per-user authorization model
/// (public repos plus any repo the user holds a role assignment for) instead
/// of treating every authenticated caller as entitled to all packages.
///
/// #3901: a repository-scoped token binds AHEAD of `is_admin`, matching
/// `search::intersect_token_scope` and the webhook reads (#1803, #3715): an
/// admin holding a token minted for repository A must not enumerate other
/// repositories' packages with it. Token scope is confinement, not a
/// privilege boundary, so it narrows admins too.
fn repo_visibility_for(auth: Option<&AuthExtension>) -> RepoVisibility {
    match auth {
        None => RepoVisibility::PublicOnly,
        // Repo-scoped token: restrict strictly to the token's allowed set,
        // whether its owner is an admin or not (#3901).
        Some(a) if matches!(a.allowed_repo_ids, AccessScope::Restricted(_)) => RepoVisibility::Ids(
            a.allowed_repo_ids
                .as_allowed_repo_ids()
                .unwrap_or_default()
                .to_vec(),
        ),
        Some(a) if a.is_admin => RepoVisibility::All,
        Some(a) => RepoVisibility::User(a.user_id),
    }
}

/// Split a [`VisibilityBind`] into the two concrete shapes its parameter can
/// take (single `user_id` uuid vs `uuid[]`). Exactly one is `Some` per call;
/// the unused one binds as a typed NULL the clause never references.
fn split_visibility_bind(bind: VisibilityBind) -> (Option<Uuid>, Option<Vec<Uuid>>) {
    match bind {
        VisibilityBind::User(uid) => (uid, None),
        VisibilityBind::Ids(ids) => (None, Some(ids)),
    }
}

/// Check if the packages table exists in the database.
async fn packages_table_exists(db: &sqlx::PgPool) -> bool {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'packages')",
    )
    .fetch_one(db)
    .await
    .unwrap_or(false)
}

/// Result of resolving a `repository_key` filter for the packages listing.
struct ResolvedRepoFilter {
    /// The repository ids whose packages should be listed. `None` means no
    /// `repository_key` was supplied, so the repository predicate is omitted.
    repo_ids: Option<Vec<Uuid>>,
    /// The key to report on every row when the filter is a virtual repository,
    /// matching the artifacts page which labels aggregated members with the
    /// URL repo's key (`list_artifacts` → `build_artifact_response`). `None`
    /// means each row reports its own owning repository's key.
    report_key: Option<String>,
}

impl ResolvedRepoFilter {
    fn empty() -> Self {
        Self {
            repo_ids: Some(Vec::new()),
            report_key: None,
        }
    }

    fn visibility(&self, auth: Option<&AuthExtension>) -> RepoVisibility {
        if self.report_key.is_some() {
            RepoVisibility::Ids(self.repo_ids.clone().unwrap_or_default())
        } else {
            repo_visibility_for(auth)
        }
    }
}

/// Resolve the `repository_key` filter into the concrete repository ids whose
/// packages should be listed, plus the key to report on each row.
///
/// A virtual repository is a read-only aggregate that owns no `packages` rows
/// of its own — pushes to it (and therefore its catalog rows) land in a
/// member. So filtering by a virtual repo's key must expand to its members,
/// otherwise the virtual repo's Packages page is always empty. Any other
/// repository type resolves to that single repository's id, and an unknown key
/// resolves to an empty set (nothing matches). `None` (no `repository_key`)
/// omits the repository predicate entirely.
async fn resolve_package_filter(
    db: &sqlx::PgPool,
    repository_key: Option<&str>,
    auth: Option<&AuthExtension>,
) -> Result<ResolvedRepoFilter> {
    let Some(key) = repository_key else {
        return Ok(ResolvedRepoFilter {
            repo_ids: None,
            report_key: None,
        });
    };

    // Single indexed lookup: the repository supplies its own type and ACL,
    // including an empty virtual repository with no membership edges.
    let service = crate::services::repository_service::RepositoryService::new(db.clone());
    let repo = match service.get_by_key(key).await {
        Ok(repo) => repo,
        Err(AppError::NotFound(_)) => {
            // Unknown key: no repository, therefore no packages.
            return Ok(ResolvedRepoFilter::empty());
        }
        Err(error) => return Err(error),
    };

    if repo.repo_type != crate::models::repository::RepositoryType::Virtual {
        return Ok(ResolvedRepoFilter {
            repo_ids: Some(vec![repo.id]),
            report_key: None,
        });
    }
    match super::repositories::require_visible(&repo, &auth.cloned(), &service).await {
        Ok(()) => {}
        Err(AppError::NotFound(_)) => return Ok(ResolvedRepoFilter::empty()),
        Err(error) => return Err(error),
    }
    if auth.is_some_and(|a| !a.has_scope("read:artifacts")) {
        return Ok(ResolvedRepoFilter::empty());
    }

    // Expand the virtual repo to its leaf members through the same recursive
    // walk as `fetch_virtual_members` (#3840): nested virtuals contribute
    // their own members, remote members their proxy-cached catalog rows,
    // hosted members their pushed artifacts. The walk's resolution order
    // (depth-first pre-order priority) keeps the listing stable and
    // deterministic.
    let members = super::proxy_helpers::fetch_virtual_members(db, repo.id)
        .await
        .map_err(|resp| super::proxy_helpers::member_walk_app_error(&resp))?;
    let members = super::proxy_helpers::try_authorize_virtual_members(db, auth, repo.id, members)
        .await
        .map_err(|resp| super::proxy_helpers::member_walk_app_error(&resp))?;

    // Aggregated rows are reported under the virtual repo's key, not the
    // member's, so the whole page reads as the virtual repo.
    Ok(ResolvedRepoFilter {
        repo_ids: Some(members.into_iter().map(|member| member.id).collect()),
        report_key: Some(key.to_string()),
    })
}

/// Create package routes
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_packages))
        .route("/:id", get(get_package))
        .route("/:id/versions", get(get_package_versions))
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ListPackagesQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub repository_key: Option<String>,
    pub format: Option<String>,
    #[serde(alias = "q")]
    pub search: Option<String>,
}

#[derive(Debug, Serialize, FromRow, ToSchema)]
pub struct PackageRow {
    pub id: Uuid,
    pub repository_key: String,
    pub name: String,
    pub version: String,
    pub format: String,
    pub description: Option<String>,
    pub size_bytes: i64,
    /// Downloads of the package's versions, from the same download history
    /// the artifact download stats read (#5346). `null` when the repository
    /// cannot attribute downloads to this package (a Remote package cataloged
    /// without a digest), so a client can tell "not tracked" from a real 0.
    pub download_count: Option<i64>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    #[schema(value_type = Object)]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PackageResponse {
    pub id: Uuid,
    pub repository_key: String,
    pub name: String,
    pub version: String,
    pub format: String,
    pub description: Option<String>,
    pub size_bytes: i64,
    /// Downloads of the package's versions, from the same download history
    /// the artifact download stats read (#5346). `null` when the repository
    /// cannot attribute downloads to this package (a Remote package cataloged
    /// without a digest), so a client can tell "not tracked" from a real 0.
    pub download_count: Option<i64>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    #[schema(value_type = Object)]
    pub metadata: Option<serde_json::Value>,
}

impl From<PackageRow> for PackageResponse {
    fn from(row: PackageRow) -> Self {
        Self {
            id: row.id,
            repository_key: row.repository_key,
            name: row.name,
            version: row.version,
            format: row.format,
            description: row.description,
            size_bytes: row.size_bytes,
            download_count: row.download_count,
            created_at: row.created_at,
            updated_at: row.updated_at,
            metadata: row.metadata,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PackageListResponse {
    pub items: Vec<PackageResponse>,
    pub pagination: Pagination,
}

/// List packages
#[utoipa::path(
    get,
    path = "",
    context_path = "/api/v1/packages",
    tag = "packages",
    params(ListPackagesQuery),
    responses(
        (status = 200, description = "Paginated list of packages", body = PackageListResponse),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_packages(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Query(query): Query<ListPackagesQuery>,
) -> Result<Json<PackageListResponse>> {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(24).min(100);
    let offset = ((page - 1) * per_page) as i64;

    // #3557: the free-text term is a literal substring, so `%`/`_`/`\` in it
    // must match themselves; escaped here and matched under `ESCAPE '\'`.
    let search_pattern = query
        .search
        .as_ref()
        .map(|s| format!("%{}%", super::escape_like_literal(s)));

    let table_exists = packages_table_exists(&state.db).await;

    if !table_exists {
        return Ok(Json(PackageListResponse {
            items: vec![],
            pagination: Pagination {
                page,
                per_page,
                total: 0,
                total_pages: 0,
            },
        }));
    }

    // A `repository_key` naming a virtual repo expands to its members' ids so
    // the aggregated Packages page shows the packages each member actually
    // owns. `None` means "no repository filter".
    let filter =
        resolve_package_filter(&state.db, query.repository_key.as_deref(), auth.as_ref()).await?;
    let visibility = filter.visibility(auth.as_ref());

    // Per-user repository visibility. The page query binds the visibility
    // parameter at $6 (after repo ids/format/search/offset/limit); the
    // count query binds it at $4 (after repo ids/format/search). The
    // generated `$N` MUST line up with the `.bind()` order below.
    let (page_clause, page_bind) = build_visibility_clause_for(&visibility, "r", 6);
    let (count_clause, count_bind) = build_visibility_clause_for(&visibility, "r", 4);
    let (page_user_id, page_ids) = split_visibility_bind(page_bind);
    let (count_user_id, count_ids) = split_visibility_bind(count_bind);

    // #3660: a catalog row whose backing artifacts are all soft-deleted (or
    // hard-deleted before the GC pruned the row) must not be listed. Filtering
    // on read rather than deleting the row on delete keeps a restore working
    // and keeps `total` honest at the same time.
    let live_packages = live_package_predicate();

    // MCP rows (#5253): the catalog rows of the whole filtered set this
    // caller is shown (`None`: the listing cannot contain an MCP row). The
    // page and the count both keep only those, so `total` and every page
    // count the rows the caller sees.
    let mcp_shown: Option<Vec<Uuid>> = if query.format.as_deref().is_none_or(|f| f == "mcp") {
        let mcp_sql = format!(
            r#"
            SELECT p.id, p.repository_id, p.name, p.version
            FROM packages p
            JOIN repositories r ON r.id = p.repository_id
            WHERE ($1::uuid[] IS NULL OR r.id = ANY($1))
              AND r.format::text = 'mcp'
              AND ($3::text IS NULL OR p.name ILIKE $3 ESCAPE '\')
              AND ({count_clause})
              AND {live_packages}
              AND ($2::text IS NULL OR $2 = 'mcp')
            ORDER BY p.updated_at DESC
            LIMIT $5
            "#
        );
        let mcp_query =
            sqlx::query_as::<_, (Uuid, Uuid, String, String)>(sqlx::AssertSqlSafe(&*mcp_sql))
                .bind(filter.repo_ids.clone())
                .bind(&query.format)
                .bind(&search_pattern);
        let mcp_query = match &count_ids {
            Some(ids) => mcp_query.bind(ids.clone()),
            None => mcp_query.bind(count_user_id),
        };
        let rows = mcp_query
            .bind(super::mcp::GENERIC_LISTING_VERSION_CAP)
            .fetch_all(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        let mut shown = Vec::with_capacity(rows.len());
        for (id, repo_id, name, version) in rows {
            let view =
                super::mcp::catalog_view(&state, auth.as_ref(), repo_id, &name, &version).await;
            if view != super::mcp::CatalogView::Hide {
                shown.push(id);
            }
        }
        Some(shown)
    } else {
        None
    };

    let page_sql = format!(
        r#"
        SELECT p.id, r.key as repository_key, p.name, p.version, r.format::text as format,
               p.description, p.size_bytes, NULL::BIGINT AS download_count, p.created_at, p.updated_at,
               p.metadata
        FROM packages p
        JOIN repositories r ON r.id = p.repository_id
        WHERE ($1::uuid[] IS NULL OR r.id = ANY($1))
          AND ($2::text IS NULL OR r.format::text = $2)
          AND ($3::text IS NULL OR p.name ILIKE $3 ESCAPE '\')
          AND ({page_clause})
          AND {live_packages}
          AND ($7::uuid[] IS NULL OR r.format::text <> 'mcp' OR p.id = ANY($7))
        ORDER BY p.updated_at DESC
        OFFSET $4
        LIMIT $5
        "#
    );
    let page_query = sqlx::query_as::<_, PackageRow>(sqlx::AssertSqlSafe(&*page_sql))
        .bind(filter.repo_ids.clone())
        .bind(&query.format)
        .bind(&search_pattern)
        .bind(offset)
        .bind(per_page as i64);
    // $6 shape depends on the visibility variant (single uuid vs uuid[]).
    let page_query = match &page_ids {
        Some(ids) => page_query.bind(ids.clone()),
        None => page_query.bind(page_user_id),
    };
    let packages: Vec<PackageRow> = page_query
        .bind(mcp_shown.clone())
        .fetch_all(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    // The rows were decided above; this applies each one's view (a held
    // version's row shows the newest servable one).
    let (packages, _hidden) = apply_mcp_catalog_views(&state, auth.as_ref(), packages).await;
    let packages = with_live_latest(&state, packages).await?;
    let packages = with_download_counts(&state, auth.as_ref(), packages).await?;

    let count_sql = format!(
        r#"
        SELECT COUNT(*)
        FROM packages p
        JOIN repositories r ON r.id = p.repository_id
        WHERE ($1::uuid[] IS NULL OR r.id = ANY($1))
          AND ($2::text IS NULL OR r.format::text = $2)
          AND ($3::text IS NULL OR p.name ILIKE $3 ESCAPE '\')
          AND ({count_clause})
          AND {live_packages}
          AND ($5::uuid[] IS NULL OR r.format::text <> 'mcp' OR p.id = ANY($5))
        "#
    );
    let count_query = sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(&*count_sql))
        .bind(filter.repo_ids.clone())
        .bind(&query.format)
        .bind(&search_pattern);
    // $4 shape depends on the visibility variant (single uuid vs uuid[]).
    let count_query = match &count_ids {
        Some(ids) => count_query.bind(ids.clone()),
        None => count_query.bind(count_user_id),
    };
    let total: i64 = count_query
        .bind(mcp_shown)
        .fetch_one(&state.db)
        .await
        .unwrap_or(0);

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;

    // Aggregated rows from a virtual repo are reported under the virtual key,
    // not the owning member's, matching the artifacts page.
    let items = packages
        .into_iter()
        .map(|mut p| {
            if let Some(key) = filter.report_key.as_deref() {
                p.repository_key = key.to_string();
            }
            PackageResponse::from(p)
        })
        .collect();

    Ok(Json(PackageListResponse {
        items,
        pagination: Pagination {
            page,
            per_page,
            total,
            total_pages,
        },
    }))
}

/// Query params for the package detail lookup.
#[derive(Debug, Deserialize, IntoParams)]
pub struct PackageDetailQuery {
    /// Optional repository key providing virtual-repo context. When it names a
    /// virtual repo that contains this package, the returned `repository_key`
    /// reports the virtual key (matching the aggregated listing).
    pub repository_key: Option<String>,
}

/// Get a package by ID
#[utoipa::path(
    get,
    path = "/{id}",
    context_path = "/api/v1/packages",
    tag = "packages",
    params(
        ("id" = Uuid, Path, description = "Package ID"),
        PackageDetailQuery,
    ),
    responses(
        (status = 200, description = "Package details", body = PackageResponse),
        (status = 404, description = "Package not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_package(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
    Query(detail_query): Query<PackageDetailQuery>,
) -> Result<Json<PackageResponse>> {
    let table_exists = packages_table_exists(&state.db).await;

    if !table_exists {
        return Err(AppError::NotFound("Package not found".to_string()));
    }
    let filter = resolve_package_filter(
        &state.db,
        detail_query.repository_key.as_deref(),
        auth.as_ref(),
    )
    .await?;
    let visibility = filter.visibility(auth.as_ref());

    // The visibility parameter is bound at $3, after the package id and context.
    let (clause, bind) = build_visibility_clause_for(&visibility, "r", 3);
    let (user_id, ids) = split_visibility_bind(bind);

    // #3660: the detail view must agree with the listing — a ghost row is a
    // 404 here, and reappears the moment its artifact is restored.
    let live_packages = live_package_predicate();

    let sql = format!(
        r#"
        SELECT p.id, r.key as repository_key, p.name, p.version, r.format::text as format,
               p.description, p.size_bytes, NULL::BIGINT AS download_count, p.created_at, p.updated_at,
               p.metadata
        FROM packages p
        JOIN repositories r ON r.id = p.repository_id
        WHERE p.id = $1
          AND ($2::uuid[] IS NULL OR r.id = ANY($2))
          AND ({clause})
          AND {live_packages}
        "#
    );
    let query = sqlx::query_as::<_, PackageRow>(sqlx::AssertSqlSafe(&*sql))
        .bind(id)
        .bind(filter.repo_ids);
    // $3 shape depends on the visibility variant (single uuid vs uuid[]).
    let query = match &ids {
        Some(ids) => query.bind(ids.clone()),
        None => query.bind(user_id),
    };
    let package: PackageRow = query
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Package not found".to_string()))?;
    let package = apply_mcp_catalog_views(&state, auth.as_ref(), vec![package])
        .await
        .0
        .pop()
        .ok_or_else(|| AppError::NotFound("Package not found".to_string()))?;
    let package = with_live_latest(&state, vec![package]).await?;
    let mut package = with_download_counts(&state, auth.as_ref(), package)
        .await?
        .pop()
        .ok_or_else(|| AppError::NotFound("Package not found".to_string()))?;

    // A virtual-repo context (`?repository_key=<virtual>`) reports the virtual
    // key so the detail view matches the aggregated listing. Without it (or
    // for a non-virtual key) the owning member's key is reported.
    if let Some(key) = filter.report_key {
        package.repository_key = key;
    }

    Ok(Json(PackageResponse::from(package)))
}

#[derive(Debug, Serialize, FromRow, ToSchema)]
pub struct PackageVersionRow {
    pub version: String,
    pub size_bytes: i64,
    /// Downloads of this version (#5346); `null` when not tracked, as on
    /// [`PackageResponse::download_count`].
    pub download_count: Option<i64>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub checksum_sha256: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PackageVersionResponse {
    pub version: String,
    pub size_bytes: i64,
    /// Downloads of this version (#5346); `null` when not tracked, as on
    /// [`PackageResponse::download_count`].
    pub download_count: Option<i64>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub checksum_sha256: String,
}

impl From<PackageVersionRow> for PackageVersionResponse {
    fn from(row: PackageVersionRow) -> Self {
        Self {
            version: row.version,
            size_bytes: row.size_bytes,
            download_count: row.download_count,
            created_at: row.created_at,
            checksum_sha256: row.checksum_sha256,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PackageVersionsResponse {
    pub versions: Vec<PackageVersionResponse>,
}

/// Get package versions
#[utoipa::path(
    get,
    path = "/{id}/versions",
    context_path = "/api/v1/packages",
    tag = "packages",
    params(
        ("id" = Uuid, Path, description = "Package ID"),
        PackageDetailQuery,
    ),
    responses(
        (status = 200, description = "List of package versions", body = PackageVersionsResponse),
        (status = 404, description = "Package not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_package_versions(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
    Query(context): Query<PackageDetailQuery>,
) -> Result<Json<PackageVersionsResponse>> {
    let table_exists = packages_table_exists(&state.db).await;

    if !table_exists {
        return Err(AppError::NotFound("Package not found".to_string()));
    }

    let filter =
        resolve_package_filter(&state.db, context.repository_key.as_deref(), auth.as_ref()).await?;
    let visibility = filter.visibility(auth.as_ref());
    // Verify the package exists and belongs to a repository visible to the
    // caller. The visibility parameter is bound at $3, after id and context.
    let (clause, bind) = build_visibility_clause_for(&visibility, "r", 3);
    let (user_id, ids) = split_visibility_bind(bind);

    let live_packages = live_package_predicate();

    let exists_sql = format!(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM packages p
            JOIN repositories r ON r.id = p.repository_id
            WHERE p.id = $1
              AND ($2::uuid[] IS NULL OR r.id = ANY($2))
              AND ({clause})
              AND {live_packages}
        )
        "#
    );
    let exists_query = sqlx::query_scalar::<_, bool>(sqlx::AssertSqlSafe(&*exists_sql))
        .bind(id)
        .bind(filter.repo_ids);
    // $3 shape depends on the visibility variant (single uuid vs uuid[]).
    let exists_query = match &ids {
        Some(ids) => exists_query.bind(ids.clone()),
        None => exists_query.bind(user_id),
    };
    let package_exists: bool = exists_query.fetch_one(&state.db).await.unwrap_or(false);

    if !package_exists {
        return Err(AppError::NotFound("Package not found".to_string()));
    }

    // Check if package_versions table exists
    let versions_table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'package_versions')"
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);

    if !versions_table_exists {
        return Ok(Json(PackageVersionsResponse { versions: vec![] }));
    }

    // #3660: list only the versions whose bytes are still there. A
    // soft-deleted version disappears from the list and comes back on restore
    // without any catalog write.
    let live_versions = live_package_version_predicate();
    let download_count = version_download_count_sql();
    let versions_sql = format!(
        r#"
        SELECT pv.version, pv.size_bytes, {download_count} AS download_count,
               pv.created_at, pv.checksum_sha256
        FROM package_versions pv
        JOIN packages p ON p.id = pv.package_id
        JOIN repositories r ON r.id = p.repository_id
        WHERE pv.package_id = $1
          AND {live_versions}
        "#
    );
    let mut versions: Vec<PackageVersionRow> = sqlx::query_as(sqlx::AssertSqlSafe(&*versions_sql))
        .bind(id)
        .fetch_all(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    if let Some(visible) = mcp_visible_versions(&state, auth.as_ref(), id).await {
        versions.retain(|v| visible.contains(&v.version));
    }

    versions.sort_by(|a, b| match version_compare(&a.version, &b.version) {
        n if n < 0 => std::cmp::Ordering::Greater,
        n if n > 0 => std::cmp::Ordering::Less,
        _ => b.created_at.cmp(&a.created_at),
    });

    Ok(Json(PackageVersionsResponse {
        versions: versions
            .into_iter()
            .map(PackageVersionResponse::from)
            .collect(),
    }))
}

/// Show each row's newest LIVE version as its Latest (#5632).
///
/// `packages.version` is moved off a deleted version when the delete runs
/// ([`crate::services::package_service::refresh_package_latest`]); this
/// is the read-side backstop for a row that still names a version whose bytes
/// are gone (a delete path that bypassed it, or rows written before it): the
/// row reports its newest version with a live artifact, by the same liveness
/// test the version list uses, instead of an install that fails. Rows whose
/// version is live, MCP rows (decided by [`apply_mcp_catalog_views`]) and
/// rows with no live version (already filtered out) pass through.
async fn with_live_latest(
    state: &SharedState,
    mut rows: Vec<PackageRow>,
) -> Result<Vec<PackageRow>> {
    let ids: Vec<Uuid> = rows
        .iter()
        .filter(|r| r.format != "mcp")
        .map(|r| r.id)
        .collect();
    if ids.is_empty() {
        return Ok(rows);
    }
    let live_versions = live_package_version_predicate();
    let sql = format!(
        r#"
        SELECT pv.package_id, pv.version, pv.size_bytes
        FROM package_versions pv
        JOIN packages p ON p.id = pv.package_id
        JOIN repositories r ON r.id = p.repository_id
        WHERE pv.package_id = ANY($1)
          AND {live_versions}
        "#
    );
    let live: Vec<(Uuid, String, i64)> = sqlx::query_as(sqlx::AssertSqlSafe(&*sql))
        .bind(&ids)
        .fetch_all(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    let mut by_package: std::collections::HashMap<Uuid, Vec<(String, i64)>> =
        std::collections::HashMap::new();
    for (id, version, size) in live {
        by_package.entry(id).or_default().push((version, size));
    }
    for row in rows.iter_mut().filter(|r| r.format != "mcp") {
        let Some(versions) = by_package.get(&row.id) else {
            continue;
        };
        if versions.iter().any(|(v, _)| *v == row.version) {
            continue;
        }
        if let Some((version, size)) = newest_catalog_version(versions) {
            row.version = version.clone();
            row.size_bytes = *size;
        }
    }
    Ok(rows)
}

/// Fill each row's `download_count` from the recorded download history
/// (#5346), one batched query for the whole page rather than one per row.
///
/// An MCP package (#5253) counts only the versions `auth` may list
/// ([`mcp_visible_versions`]), the same versions its version list shows, so
/// a reader who does not hold the registry never sees a held version's
/// downloads. A failed lookup lists no version, so the count is `null`.
async fn with_download_counts(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    mut rows: Vec<PackageRow>,
) -> Result<Vec<PackageRow>> {
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    let counts = package_download_counts(&state.db, &ids)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    for row in &mut rows {
        row.download_count = counts.get(&row.id).copied().flatten();
        if row.format != "mcp" {
            continue;
        }
        if let Some(versions) = mcp_visible_versions(state, auth, row.id).await {
            let versions: Vec<String> = versions.into_iter().collect();
            row.download_count = package_download_count_over_versions(&state.db, row.id, &versions)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
        }
    }
    Ok(rows)
}

/// The MCP rows of `rows` as `auth` may see them (#5253): a row whose
/// version is held is kept for a holder (with `metadata.servable: false`),
/// shown to any other reader as the server's newest servable version, or left
/// out when none is served ([`super::mcp::catalog_view`], the registry
/// surface's own decision). Other formats pass through. Also returns how
/// many rows were left out.
async fn apply_mcp_catalog_views(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    rows: Vec<PackageRow>,
) -> (Vec<PackageRow>, usize) {
    use super::mcp::CatalogView;
    let mut out = Vec::with_capacity(rows.len());
    let mut hidden = 0;
    for mut row in rows {
        if row.format != "mcp" {
            out.push(row);
            continue;
        }
        let repo_id: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM repositories WHERE key = $1")
                .bind(&row.repository_key)
                .fetch_optional(&state.db)
                .await
                .ok()
                .flatten();
        let view = match repo_id {
            Some(id) => super::mcp::catalog_view(state, auth, id, &row.name, &row.version).await,
            None => CatalogView::Hide,
        };
        match view {
            CatalogView::Keep { servable } => {
                if let Some(serde_json::Value::Object(m)) = row.metadata.as_mut() {
                    m.insert("servable".into(), servable.into());
                }
                out.push(row);
            }
            CatalogView::Show {
                artifact_id,
                version,
                description,
                metadata,
            } => {
                // The figures and times are the shown version's own, never
                // the held one's (#5253): its `package_versions` row, or its
                // artifact when it has none. A failed read hides the row.
                let Some(figures) =
                    shown_version_figures(state, row.id, artifact_id, &version).await
                else {
                    hidden += 1;
                    continue;
                };
                // The download count is filled afterwards over the versions
                // the reader may list ([`with_download_counts`]).
                row.size_bytes = figures.0;
                row.created_at = figures.1;
                row.updated_at = figures.2;
                row.version = version;
                row.description = description;
                let mut metadata = metadata;
                metadata["servable"] = true.into();
                row.metadata = Some(metadata);
                out.push(row);
            }
            CatalogView::Hide => hidden += 1,
        }
    }
    (out, hidden)
}

/// `(size_bytes, created_at, updated_at)` of the version an MCP catalog row
/// shows a reader in place of a held one: its `package_versions` row
/// (`updated_at` is the version's own creation), else its server.json
/// artifact. `None` on a read failure.
async fn shown_version_figures(
    state: &SharedState,
    package_id: Uuid,
    artifact_id: Uuid,
    version: &str,
) -> Option<(
    i64,
    chrono::DateTime<chrono::Utc>,
    chrono::DateTime<chrono::Utc>,
)> {
    let pv: Option<(i64, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT size_bytes, created_at FROM package_versions \
         WHERE package_id = $1 AND version = $2",
    )
    .bind(package_id)
    .bind(version)
    .fetch_optional(&state.db)
    .await
    .ok()?;
    if let Some((size, created)) = pv {
        return Some((size, created, created));
    }
    sqlx::query_as("SELECT size_bytes, created_at, updated_at FROM artifacts WHERE id = $1")
        .bind(artifact_id)
        .fetch_optional(&state.db)
        .await
        .ok()?
}

/// For an MCP package, the versions `auth` may list (`None`: all of them, a
/// holder or another format). A lookup that fails lists none (fail closed).
async fn mcp_visible_versions(
    state: &SharedState,
    auth: Option<&AuthExtension>,
    package_id: Uuid,
) -> Option<std::collections::HashSet<String>> {
    let row: Option<(Uuid, String)> = match sqlx::query_as(
        "SELECT p.repository_id, p.name FROM packages p \
         JOIN repositories r ON r.id = p.repository_id \
         WHERE p.id = $1 AND r.format = 'mcp'",
    )
    .bind(package_id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(row) => row,
        Err(_) => return Some(Default::default()),
    };
    let (repo_id, name) = row?;
    super::mcp::catalog_visible_versions(state, auth, repo_id, &name).await
}

#[derive(OpenApi)]
#[openapi(
    paths(list_packages, get_package, get_package_versions),
    components(schemas(
        PackageRow,
        PackageResponse,
        PackageListResponse,
        PackageVersionRow,
        PackageVersionResponse,
        PackageVersionsResponse,
    ))
)]
pub struct PackagesApiDoc;

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json;

    /// #5253: when the MCP package lookup fails, an MCP package's version
    /// list is empty (fail closed), never every version.
    #[tokio::test]
    async fn mcp_visible_versions_fails_closed() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(200))
            .connect_lazy("postgres://invalid:invalid@127.0.0.1:1/none")
            .expect("lazy pool");
        let dir = tempfile::tempdir().unwrap();
        let state =
            crate::api::handlers::test_db_helpers::build_state(pool, dir.path().to_str().unwrap());
        assert_eq!(
            mcp_visible_versions(&state, None, Uuid::new_v4()).await,
            Some(Default::default())
        );
    }

    fn make_package_row() -> PackageRow {
        let now = Utc::now();
        PackageRow {
            id: Uuid::new_v4(),
            repository_key: "my-repo".to_string(),
            name: "my-package".to_string(),
            version: "1.0.0".to_string(),
            format: "npm".to_string(),
            description: Some("A test package".to_string()),
            size_bytes: 1024,
            download_count: Some(42),
            created_at: now,
            updated_at: now,
            metadata: Some(serde_json::json!({"license": "MIT"})),
        }
    }

    fn make_auth(user_id: Uuid, is_admin: bool, allowed: Option<Vec<Uuid>>) -> AuthExtension {
        AuthExtension {
            user_id,
            username: "tester".to_string(),
            email: "tester@example.com".to_string(),
            is_admin,
            is_api_token: allowed.is_some(),
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: AccessScope::from(allowed),
            iat_ms: None,
        }
    }

    // -----------------------------------------------------------------------
    // repo_visibility_for: per-user authorization mapping (mirrors list_repositories)
    // -----------------------------------------------------------------------

    #[test]
    fn test_visibility_anonymous_is_public_only() {
        assert_eq!(repo_visibility_for(None), RepoVisibility::PublicOnly);
    }

    #[test]
    fn test_visibility_admin_is_all() {
        let auth = make_auth(Uuid::new_v4(), true, None);
        assert_eq!(repo_visibility_for(Some(&auth)), RepoVisibility::All);
    }

    #[test]
    fn test_visibility_authenticated_non_admin_is_user_scope() {
        let uid = Uuid::new_v4();
        let auth = make_auth(uid, false, None);
        assert_eq!(repo_visibility_for(Some(&auth)), RepoVisibility::User(uid));
    }

    #[test]
    fn test_visibility_scoped_token_is_ids() {
        let repo = Uuid::new_v4();
        let auth = make_auth(Uuid::new_v4(), false, Some(vec![repo]));
        assert_eq!(
            repo_visibility_for(Some(&auth)),
            RepoVisibility::Ids(vec![repo])
        );
    }

    #[test]
    fn test_visibility_admin_scoped_token_is_confined() {
        // #3901: token scope binds ahead of is_admin -- an admin holding a
        // repository-scoped token is confined to the token's set, matching
        // search::intersect_token_scope and the webhook reads.
        let repo = Uuid::new_v4();
        let auth = make_auth(Uuid::new_v4(), true, Some(vec![repo]));
        assert_eq!(
            repo_visibility_for(Some(&auth)),
            RepoVisibility::Ids(vec![repo])
        );
    }

    #[test]
    fn test_split_visibility_bind_user_and_ids() {
        let uid = Uuid::new_v4();
        assert_eq!(
            split_visibility_bind(VisibilityBind::User(Some(uid))),
            (Some(uid), None)
        );
        assert_eq!(
            split_visibility_bind(VisibilityBind::User(None)),
            (None, None)
        );
        let a = Uuid::new_v4();
        assert_eq!(
            split_visibility_bind(VisibilityBind::Ids(vec![a])),
            (None, Some(vec![a]))
        );
    }

    fn make_version_row() -> PackageVersionRow {
        PackageVersionRow {
            version: "2.0.0".to_string(),
            size_bytes: 2048,
            download_count: Some(10),
            created_at: Utc::now(),
            checksum_sha256: "abc123def456".to_string(),
        }
    }

    // -----------------------------------------------------------------------
    // PackageRow -> PackageResponse conversion
    // -----------------------------------------------------------------------

    #[test]
    fn test_package_row_to_response_all_fields() {
        let row = make_package_row();
        let id = row.id;
        let resp = PackageResponse::from(row);
        assert_eq!(resp.id, id);
        assert_eq!(resp.repository_key, "my-repo");
        assert_eq!(resp.name, "my-package");
        assert_eq!(resp.version, "1.0.0");
        assert_eq!(resp.format, "npm");
        assert_eq!(resp.description.as_deref(), Some("A test package"));
        assert_eq!(resp.size_bytes, 1024);
        assert_eq!(resp.download_count, Some(42));
        assert!(resp.metadata.is_some());
    }

    #[test]
    fn test_package_row_to_response_no_description() {
        let mut row = make_package_row();
        row.description = None;
        let resp = PackageResponse::from(row);
        assert!(resp.description.is_none());
    }

    #[test]
    fn test_package_row_to_response_no_metadata() {
        let mut row = make_package_row();
        row.metadata = None;
        let resp = PackageResponse::from(row);
        assert!(resp.metadata.is_none());
    }

    #[test]
    fn test_package_row_to_response_zero_size() {
        let mut row = make_package_row();
        row.size_bytes = 0;
        let resp = PackageResponse::from(row);
        assert_eq!(resp.size_bytes, 0);
    }

    #[test]
    fn test_package_row_to_response_zero_downloads() {
        let mut row = make_package_row();
        row.download_count = Some(0);
        let resp = PackageResponse::from(row);
        assert_eq!(resp.download_count, Some(0));
    }

    // -----------------------------------------------------------------------
    // PackageVersionRow -> PackageVersionResponse conversion
    // -----------------------------------------------------------------------

    #[test]
    fn test_version_row_to_response() {
        let row = make_version_row();
        let resp = PackageVersionResponse::from(row);
        assert_eq!(resp.version, "2.0.0");
        assert_eq!(resp.size_bytes, 2048);
        assert_eq!(resp.download_count, Some(10));
        assert_eq!(resp.checksum_sha256, "abc123def456");
    }

    #[test]
    fn test_version_row_to_response_empty_checksum() {
        let mut row = make_version_row();
        row.checksum_sha256 = String::new();
        let resp = PackageVersionResponse::from(row);
        assert_eq!(resp.checksum_sha256, "");
    }

    // -----------------------------------------------------------------------
    // ListPackagesQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_list_packages_query_empty() {
        let json = r#"{}"#;
        let query: ListPackagesQuery = serde_json::from_str(json).unwrap();
        assert!(query.page.is_none());
        assert!(query.per_page.is_none());
        assert!(query.repository_key.is_none());
        assert!(query.format.is_none());
        assert!(query.search.is_none());
    }

    #[test]
    fn test_list_packages_query_full() {
        let json = serde_json::json!({
            "page": 2,
            "per_page": 50,
            "repository_key": "main-repo",
            "format": "maven",
            "search": "spring"
        });
        let query: ListPackagesQuery = serde_json::from_value(json).unwrap();
        assert_eq!(query.page, Some(2));
        assert_eq!(query.per_page, Some(50));
        assert_eq!(query.repository_key.as_deref(), Some("main-repo"));
        assert_eq!(query.format.as_deref(), Some("maven"));
        assert_eq!(query.search.as_deref(), Some("spring"));
    }

    #[test]
    fn test_list_packages_query_q_alias() {
        let json = serde_json::json!({
            "q": "shared-pkg"
        });
        let query: ListPackagesQuery = serde_json::from_value(json).unwrap();
        assert_eq!(query.search.as_deref(), Some("shared-pkg"));
    }

    // -----------------------------------------------------------------------
    // Pagination logic (simulating handler code)
    // -----------------------------------------------------------------------

    #[test]
    fn test_pagination_defaults() {
        let query = ListPackagesQuery {
            page: None,
            per_page: None,
            repository_key: None,
            format: None,
            search: None,
        };
        let page = query.page.unwrap_or(1).max(1);
        let per_page = query.per_page.unwrap_or(24).min(100);
        assert_eq!(page, 1);
        assert_eq!(per_page, 24);
    }

    #[test]
    fn test_pagination_page_zero_clamped_to_one() {
        let query = ListPackagesQuery {
            page: Some(0),
            per_page: None,
            repository_key: None,
            format: None,
            search: None,
        };
        let page = query.page.unwrap_or(1).max(1);
        assert_eq!(page, 1);
    }

    #[test]
    fn test_pagination_per_page_clamped_to_100() {
        let query = ListPackagesQuery {
            page: None,
            per_page: Some(200),
            repository_key: None,
            format: None,
            search: None,
        };
        let per_page = query.per_page.unwrap_or(24).min(100);
        assert_eq!(per_page, 100);
    }

    #[test]
    fn test_pagination_offset_calculation() {
        let page: u32 = 3;
        let per_page: u32 = 10;
        let offset = ((page - 1) * per_page) as i64;
        assert_eq!(offset, 20);
    }

    #[test]
    fn test_pagination_offset_first_page() {
        let page: u32 = 1;
        let per_page: u32 = 24;
        let offset = ((page - 1) * per_page) as i64;
        assert_eq!(offset, 0);
    }

    #[test]
    fn test_total_pages_calculation() {
        let total: i64 = 50;
        let per_page: u32 = 24;
        let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
        assert_eq!(total_pages, 3); // ceil(50/24) = 3
    }

    #[test]
    fn test_total_pages_exact_division() {
        let total: i64 = 48;
        let per_page: u32 = 24;
        let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
        assert_eq!(total_pages, 2);
    }

    #[test]
    fn test_total_pages_zero_total() {
        let total: i64 = 0;
        let per_page: u32 = 24;
        let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
        assert_eq!(total_pages, 0);
    }

    // -----------------------------------------------------------------------
    // Search pattern construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_pattern_some() {
        let search = Some("react".to_string());
        let pattern = search.as_ref().map(|s| format!("%{}%", s));
        assert_eq!(pattern.as_deref(), Some("%react%"));
    }

    #[test]
    fn test_search_pattern_none() {
        let search: Option<String> = None;
        let pattern = search.as_ref().map(|s| format!("%{}%", s));
        assert!(pattern.is_none());
    }

    #[test]
    fn test_search_pattern_empty_string() {
        let search = Some("".to_string());
        let pattern = search.as_ref().map(|s| format!("%{}%", s));
        assert_eq!(pattern.as_deref(), Some("%%"));
    }

    // -----------------------------------------------------------------------
    // Serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_package_response_serialize() {
        let row = make_package_row();
        let resp = PackageResponse::from(row);
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["id"].is_string());
        assert_eq!(json["repository_key"], "my-repo");
        assert_eq!(json["name"], "my-package");
        assert_eq!(json["version"], "1.0.0");
        assert_eq!(json["format"], "npm");
        assert_eq!(json["size_bytes"], 1024);
        assert_eq!(json["download_count"], 42);
    }

    #[test]
    fn test_package_version_response_serialize() {
        let row = make_version_row();
        let resp = PackageVersionResponse::from(row);
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["version"], "2.0.0");
        assert_eq!(json["size_bytes"], 2048);
        assert_eq!(json["checksum_sha256"], "abc123def456");
    }

    #[test]
    fn test_package_versions_response_serialize_empty() {
        let resp = PackageVersionsResponse { versions: vec![] };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["versions"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_package_list_response_serialize() {
        let resp = PackageListResponse {
            items: vec![],
            pagination: Pagination {
                page: 1,
                per_page: 24,
                total: 0,
                total_pages: 0,
            },
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["items"].as_array().unwrap().is_empty());
        assert_eq!(json["pagination"]["page"], 1);
        assert_eq!(json["pagination"]["per_page"], 24);
        assert_eq!(json["pagination"]["total"], 0);
    }

    // -----------------------------------------------------------------------
    // DB-backed visibility tests: the listing/detail/versions endpoints must
    // enforce per-user repository visibility (skip cleanly without
    // DATABASE_URL, same as the other handler suites).
    // -----------------------------------------------------------------------
    mod visibility_db {
        use super::*;
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::http::StatusCode;

        struct VirtualCatalog {
            fixture: tdh::Fixture,
            member_id: Uuid,
            member_key: String,
            member_dir: std::path::PathBuf,
            package_id: Uuid,
        }

        impl VirtualCatalog {
            async fn setup() -> Option<Self> {
                Self::setup_with("local", "docker").await
            }

            async fn setup_with(member_type: &str, format: &str) -> Option<Self> {
                let fixture = tdh::Fixture::setup("virtual", format).await?;
                let (member_id, member_key, member_dir) =
                    tdh::create_repo(&fixture.pool, member_type, format).await;
                tdh::link_virtual_member(&fixture.pool, fixture.repo_id, member_id, 1).await;
                tdh::grant_repo_access(&fixture.pool, member_id, fixture.user_id).await;
                let package_id = seed_package(&fixture.pool, member_id).await;
                Some(Self {
                    fixture,
                    member_id,
                    member_key,
                    member_dir,
                    package_id,
                })
            }

            fn auth(&self) -> AuthExtension {
                make_auth(
                    self.fixture.user_id,
                    false,
                    Some(vec![self.fixture.repo_id]),
                )
            }

            async fn request(&self, path: String) -> (StatusCode, serde_json::Value) {
                let (status, body) =
                    tdh::send(app_for(&self.fixture, Some(self.auth())), tdh::get(path)).await;
                (
                    status,
                    serde_json::from_slice(&body).expect("catalog response"),
                )
            }

            async fn teardown(self) {
                tdh::cleanup_member_repo(&self.fixture.pool, self.member_id, &self.member_dir)
                    .await;
                self.fixture.teardown().await;
            }
        }

        #[tokio::test]
        async fn virtual_context_listing_uses_the_parent_token_scope() {
            let Some(f) = VirtualCatalog::setup().await else {
                return;
            };
            let (status, body) = f
                .request(format!("/?repository_key={}", f.fixture.repo_key))
                .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["pagination"]["total"], 1, "{body}");
            assert_eq!(body["items"][0]["id"], f.package_id.to_string());
            assert_eq!(body["items"][0]["repository_key"], f.fixture.repo_key);
            assert!(!f.auth().can_access_repo(f.member_id));
            f.teardown().await;
        }

        #[tokio::test]
        async fn virtual_context_detail_uses_the_parent_token_scope() {
            let Some(f) = VirtualCatalog::setup().await else {
                return;
            };
            let (status, body) = f
                .request(format!(
                    "/{}?repository_key={}",
                    f.package_id, f.fixture.repo_key
                ))
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["repository_key"], f.fixture.repo_key);
            assert!(!f.auth().can_access_repo(f.member_id));
            f.teardown().await;
        }

        #[tokio::test]
        async fn virtual_context_versions_use_the_parent_token_scope() {
            let Some(f) = VirtualCatalog::setup().await else {
                return;
            };
            let (status, body) = f
                .request(format!(
                    "/{}/versions?repository_key={}",
                    f.package_id, f.fixture.repo_key
                ))
                .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(body["versions"][0]["version"], "1.0.0");
            assert!(!f.auth().can_access_repo(f.member_id));
            f.teardown().await;
        }

        #[tokio::test]
        async fn virtual_context_does_not_authorize_direct_or_unrelated_reads() {
            let Some(f) = VirtualCatalog::setup().await else {
                return;
            };
            for path in [
                format!("/{}", f.package_id),
                format!("/{}/versions", f.package_id),
                format!("/{}?repository_key={}", f.package_id, f.member_key),
                format!("/{}?repository_key=unknown-virtual", f.package_id),
                format!("/{}/versions?repository_key=unknown-virtual", f.package_id),
            ] {
                let (status, body) = f.request(path.clone()).await;
                assert_eq!(status, StatusCode::NOT_FOUND, "{path}: {body}");
            }
            let (status, body) = f
                .request(format!("/?repository_key={}", f.member_key))
                .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["pagination"]["total"], 0);
            let (other_id, other_key, other_dir) =
                tdh::create_repo(&f.fixture.pool, "local", "docker").await;
            tdh::grant_repo_access(&f.fixture.pool, other_id, f.fixture.user_id).await;
            let other_package = seed_package(&f.fixture.pool, other_id).await;
            for suffix in ["", "/versions"] {
                let (status, body) = f
                    .request(format!(
                        "/{other_package}{suffix}?repository_key={}",
                        f.fixture.repo_key
                    ))
                    .await;
                assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
            }
            assert!(!f.auth().can_access_repo(other_id));
            let _ = other_key;
            tdh::cleanup_member_repo(&f.fixture.pool, other_id, &other_dir).await;
            f.teardown().await;
        }

        #[tokio::test]
        async fn virtual_context_requires_read_access_to_the_parent_and_member() {
            for revoke_parent in [false, true] {
                let Some(f) = VirtualCatalog::setup().await else {
                    return;
                };
                sqlx::query(
                    "DELETE FROM role_assignments WHERE user_id = $1 AND repository_id = $2",
                )
                .bind(f.fixture.user_id)
                .bind(if revoke_parent {
                    f.fixture.repo_id
                } else {
                    f.member_id
                })
                .execute(&f.fixture.pool)
                .await
                .expect("revoke fixture grant");
                let (status, body) = f
                    .request(format!("/?repository_key={}", f.fixture.repo_key))
                    .await;
                assert_eq!(status, StatusCode::OK, "{body}");
                assert_eq!(body["pagination"]["total"], 0, "{body}");
                for suffix in ["", "/versions"] {
                    let (status, body) = f
                        .request(format!(
                            "/{}{suffix}?repository_key={}",
                            f.package_id, f.fixture.repo_key
                        ))
                        .await;
                    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
                }
                f.teardown().await;
            }
        }

        #[tokio::test]
        async fn virtual_context_nested_members_and_remote_catalog_rows_are_readable() {
            for member_type in ["local", "remote"] {
                let Some(f) = VirtualCatalog::setup_with(member_type, "docker").await else {
                    return;
                };
                let (nested_id, nested_key, nested_dir) =
                    tdh::create_repo(&f.fixture.pool, "virtual", "docker").await;
                sqlx::query("DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1 AND member_repo_id = $2")
                    .bind(f.fixture.repo_id).bind(f.member_id).execute(&f.fixture.pool).await.unwrap();
                tdh::link_virtual_member(&f.fixture.pool, f.fixture.repo_id, nested_id, 1).await;
                tdh::link_virtual_member(&f.fixture.pool, nested_id, f.member_id, 1).await;
                let (status, body) = f
                    .request(format!("/?repository_key={}", f.fixture.repo_key))
                    .await;
                assert_eq!(status, StatusCode::OK, "{body}");
                assert_eq!(body["pagination"]["total"], 1);
                for suffix in ["", "/versions"] {
                    let (status, body) = f
                        .request(format!(
                            "/{}{suffix}?repository_key={}",
                            f.package_id, f.fixture.repo_key
                        ))
                        .await;
                    assert_eq!(status, StatusCode::OK, "{body}");
                    let (status, _) = f
                        .request(format!(
                            "/{}{suffix}?repository_key={nested_key}",
                            f.package_id
                        ))
                        .await;
                    assert_eq!(status, StatusCode::NOT_FOUND);
                }
                tdh::cleanup_member_repo(&f.fixture.pool, nested_id, &nested_dir).await;
                f.teardown().await;
            }
        }

        #[tokio::test]
        async fn virtual_context_does_not_disclose_an_unreadable_parent_to_a_member_reader() {
            let Some(f) = VirtualCatalog::setup().await else {
                return;
            };
            sqlx::query("DELETE FROM role_assignments WHERE user_id = $1 AND repository_id = $2")
                .bind(f.fixture.user_id)
                .bind(f.fixture.repo_id)
                .execute(&f.fixture.pool)
                .await
                .unwrap();
            let auth = make_auth(f.fixture.user_id, false, None);
            let (status, _) = tdh::send(
                app_for(&f.fixture, Some(auth.clone())),
                tdh::get(format!("/{}", f.package_id)),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            for context in [&f.fixture.repo_key[..], "unknown-virtual"] {
                let (status, body) = tdh::send(
                    app_for(&f.fixture, Some(auth.clone())),
                    tdh::get(format!("/?repository_key={context}")),
                )
                .await;
                assert_eq!(status, StatusCode::OK);
                let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(body["pagination"]["total"], 0);
                for suffix in ["", "/versions"] {
                    let (status, body) = tdh::send(
                        app_for(&f.fixture, Some(auth.clone())),
                        tdh::get(format!(
                            "/{}{suffix}?repository_key={context}",
                            f.package_id
                        )),
                    )
                    .await;
                    assert_eq!(status, StatusCode::NOT_FOUND);
                    assert_eq!(
                        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["message"],
                        "Package not found"
                    );
                }
            }
            f.teardown().await;
        }

        #[tokio::test]
        async fn virtual_context_keeps_token_action_ceilings_and_denies_write_only_member_grants() {
            let Some(f) = VirtualCatalog::setup().await else {
                return;
            };
            let mut auth = f.auth();
            auth.scopes = Some(vec!["write:artifacts".to_string()]);
            for suffix in ["", "/versions"] {
                let (status, _) = tdh::send(
                    app_for(&f.fixture, Some(auth.clone())),
                    tdh::get(format!(
                        "/{}{suffix}?repository_key={}",
                        f.package_id, f.fixture.repo_key
                    )),
                )
                .await;
                assert_eq!(status, StatusCode::NOT_FOUND);
            }
            sqlx::query("DELETE FROM role_assignments WHERE user_id = $1 AND repository_id = $2")
                .bind(f.fixture.user_id)
                .bind(f.member_id)
                .execute(&f.fixture.pool)
                .await
                .unwrap();
            tdh::grant_repo_actions(&f.fixture.pool, f.member_id, f.fixture.user_id, &["write"])
                .await;
            let (status, body) = f
                .request(format!("/?repository_key={}", f.fixture.repo_key))
                .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["pagination"]["total"], 0, "{body}");
            let (status, _) = f
                .request(format!(
                    "/{}?repository_key={}",
                    f.package_id, f.fixture.repo_key
                ))
                .await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            f.teardown().await;
        }

        #[tokio::test]
        async fn virtual_context_anonymous_and_internal_member_baselines_are_preserved() {
            let Some(f) = VirtualCatalog::setup().await else {
                return;
            };
            sqlx::query("UPDATE repositories SET visibility = 'public' WHERE id = $1 OR id = $2")
                .bind(f.fixture.repo_id)
                .bind(f.member_id)
                .execute(&f.fixture.pool)
                .await
                .unwrap();
            let (status, body) = tdh::send(
                app_for(&f.fixture, None),
                tdh::get(format!("/?repository_key={}", f.fixture.repo_key)),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap()["pagination"]["total"],
                1
            );
            sqlx::query("UPDATE repositories SET visibility = 'internal' WHERE id = $1")
                .bind(f.member_id)
                .execute(&f.fixture.pool)
                .await
                .unwrap();
            sqlx::query("DELETE FROM role_assignments WHERE user_id = $1 AND repository_id = $2")
                .bind(f.fixture.user_id)
                .bind(f.member_id)
                .execute(&f.fixture.pool)
                .await
                .unwrap();
            let (status, body) = f
                .request(format!("/?repository_key={}", f.fixture.repo_key))
                .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body["pagination"]["total"], 1);
            let (status, _) = f.request(format!("/{}", f.package_id)).await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            let (status, body) = tdh::send(
                app_for(&f.fixture, None),
                tdh::get(format!("/?repository_key={}", f.fixture.repo_key)),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap()["pagination"]["total"],
                0
            );
            f.teardown().await;
        }

        /// Insert a minimal `packages` row in `repo_id` and return its id.
        ///
        /// The row is backed by a live `artifacts` row and a matching
        /// `package_versions` row: since #3660 the read paths hide catalog
        /// rows whose artifacts are all gone, so an unbacked row would be
        /// invisible regardless of visibility and prove nothing here.
        async fn seed_package(pool: &sqlx::PgPool, repo_id: Uuid) -> Uuid {
            super::catalog_liveness_db::seed_backed_package(pool, repo_id, "vis-test-pkg", "1.0.0")
                .await
                .0
        }

        async fn set_repo_public(pool: &sqlx::PgPool, repo_id: Uuid) {
            sqlx::query("UPDATE repositories SET is_public = true WHERE id = $1")
                .bind(repo_id)
                .execute(pool)
                .await
                .expect("set is_public");
        }

        /// Build the packages router with `auth` injected (None = anonymous).
        fn app_for(f: &tdh::Fixture, auth: Option<AuthExtension>) -> axum::Router {
            match auth {
                Some(a) => tdh::router_with_auth(router(), f.state.clone(), a),
                None => f.router_anon(router()),
            }
        }

        /// How many packages of the fixture repo the caller can see in the
        /// listing (filtered by repository_key so parallel tests don't leak in).
        async fn visible_total(f: &tdh::Fixture, auth: Option<AuthExtension>) -> i64 {
            let (status, body) = tdh::send(
                app_for(f, auth),
                tdh::get(format!("/?repository_key={}", f.repo_key)),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let json: serde_json::Value = serde_json::from_slice(&body).expect("listing json");
            json["pagination"]["total"].as_i64().expect("total")
        }

        /// Status the caller gets for a packages-router GET (detail/versions).
        async fn status_of(
            f: &tdh::Fixture,
            auth: Option<AuthExtension>,
            path: String,
        ) -> StatusCode {
            let (status, _) = tdh::send(app_for(f, auth), tdh::get(path)).await;
            status
        }

        #[tokio::test]
        async fn test_private_repo_packages_hidden_without_access() {
            // create_repo leaves is_public at its default (false): private.
            let Some(f) = tdh::Fixture::setup("local", "npm").await else {
                return;
            };
            let pkg = seed_package(&f.pool, f.repo_id).await;
            // A user with no role assignment on the repo.
            let outsider = || Some(make_auth(Uuid::new_v4(), false, None));

            assert_eq!(visible_total(&f, None).await, 0);
            assert_eq!(visible_total(&f, outsider()).await, 0);
            assert_eq!(
                status_of(&f, None, format!("/{pkg}")).await,
                StatusCode::NOT_FOUND
            );
            assert_eq!(
                status_of(&f, outsider(), format!("/{pkg}")).await,
                StatusCode::NOT_FOUND
            );
            assert_eq!(
                status_of(&f, outsider(), format!("/{pkg}/versions")).await,
                StatusCode::NOT_FOUND
            );
            f.teardown().await;
        }

        #[tokio::test]
        async fn test_private_repo_packages_visible_with_grant_or_admin() {
            let Some(f) = tdh::Fixture::setup("local", "npm").await else {
                return;
            };
            let pkg = seed_package(&f.pool, f.repo_id).await;
            // Fixture::setup grants the fixture user a repo-scoped role.
            let granted = || Some(make_auth(f.user_id, false, None));
            let admin = || Some(make_auth(Uuid::new_v4(), true, None));

            assert_eq!(visible_total(&f, granted()).await, 1);
            assert_eq!(visible_total(&f, admin()).await, 1);
            assert_eq!(
                status_of(&f, granted(), format!("/{pkg}")).await,
                StatusCode::OK
            );
            assert_eq!(
                status_of(&f, admin(), format!("/{pkg}")).await,
                StatusCode::OK
            );
            assert_eq!(
                status_of(&f, granted(), format!("/{pkg}/versions")).await,
                StatusCode::OK
            );
            f.teardown().await;
        }

        #[tokio::test]
        async fn test_public_repo_packages_visible_to_anonymous() {
            let Some(f) = tdh::Fixture::setup("local", "npm").await else {
                return;
            };
            let pkg = seed_package(&f.pool, f.repo_id).await;
            set_repo_public(&f.pool, f.repo_id).await;

            assert_eq!(visible_total(&f, None).await, 1);
            assert_eq!(status_of(&f, None, format!("/{pkg}")).await, StatusCode::OK);
            f.teardown().await;
        }

        #[tokio::test]
        async fn test_repo_scoped_token_limited_to_allowed_repos() {
            let Some(f) = tdh::Fixture::setup("local", "npm").await else {
                return;
            };
            let pkg = seed_package(&f.pool, f.repo_id).await;
            let scoped_to = |ids: Vec<Uuid>| Some(make_auth(f.user_id, false, Some(ids)));

            // Token scoped to a different repository: nothing visible, even
            // though the underlying user holds a grant on the fixture repo.
            assert_eq!(visible_total(&f, scoped_to(vec![Uuid::new_v4()])).await, 0);
            assert_eq!(
                status_of(&f, scoped_to(vec![Uuid::new_v4()]), format!("/{pkg}")).await,
                StatusCode::NOT_FOUND
            );

            // Token scoped to the fixture repository: visible.
            assert_eq!(visible_total(&f, scoped_to(vec![f.repo_id])).await, 1);
            assert_eq!(
                status_of(&f, scoped_to(vec![f.repo_id]), format!("/{pkg}")).await,
                StatusCode::OK
            );
            f.teardown().await;
        }

        // -------------------------------------------------------------------
        // resolve_package_filter: repository_key -> repo id set + report key
        // -------------------------------------------------------------------

        #[tokio::test]
        async fn resolve_package_filter_no_key_omits_filter() {
            let Some(f) = tdh::Fixture::setup("local", "docker").await else {
                return;
            };
            let result = resolve_package_filter(&f.pool, None, None)
                .await
                .expect("resolve");
            assert_eq!(
                result.repo_ids, None,
                "no filter omits the repository predicate"
            );
            assert_eq!(result.report_key, None);
            f.teardown().await;
        }

        #[tokio::test]
        async fn resolve_package_filter_unknown_key_returns_empty() {
            let Some(f) = tdh::Fixture::setup("local", "docker").await else {
                return;
            };
            let result = resolve_package_filter(&f.pool, Some("definitely-not-a-key"), None)
                .await
                .expect("resolve");
            assert_eq!(
                result.repo_ids,
                Some(Vec::new()),
                "unknown key matches no packages"
            );
            assert_eq!(result.report_key, None);
            f.teardown().await;
        }

        #[tokio::test]
        async fn resolve_package_filter_hosted_key_returns_single_id() {
            let Some(f) = tdh::Fixture::setup("local", "docker").await else {
                return;
            };
            let result = resolve_package_filter(&f.pool, Some(&f.repo_key), None)
                .await
                .expect("resolve");
            assert_eq!(
                result.repo_ids,
                Some(vec![f.repo_id]),
                "non-virtual repo maps to itself"
            );
            assert_eq!(
                result.report_key, None,
                "non-virtual rows report their own key"
            );
            f.teardown().await;
        }

        #[tokio::test]
        async fn resolve_package_filter_virtual_key_expands_members() {
            let Some(member) = tdh::Fixture::setup("local", "docker").await else {
                return;
            };
            let (virtual_id, virtual_key, virtual_dir) =
                tdh::create_repo(&member.pool, "virtual", "docker").await;
            sqlx::query(
                "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
                 VALUES ($1, $2, 1)",
            )
            .bind(virtual_id)
            .bind(member.repo_id)
            .execute(&member.pool)
            .await
            .expect("link member into virtual repo");

            tdh::grant_repo_access(&member.pool, virtual_id, member.user_id).await;
            let result = resolve_package_filter(
                &member.pool,
                Some(&virtual_key),
                Some(&make_auth(member.user_id, false, None)),
            )
            .await
            .expect("resolve");
            assert_eq!(
                result.repo_ids,
                Some(vec![member.repo_id]),
                "virtual repo expands to members"
            );
            assert_eq!(
                result.report_key.as_deref(),
                Some(virtual_key.as_str()),
                "virtual rows report the virtual key"
            );

            sqlx::query("DELETE FROM repositories WHERE id = $1")
                .bind(virtual_id)
                .execute(&member.pool)
                .await
                .expect("delete virtual repo");
            let _ = std::fs::remove_dir_all(&virtual_dir);
            member.teardown().await;
        }

        // -------------------------------------------------------------------
        // Virtual-repo aggregation on the Packages listing endpoint
        // -------------------------------------------------------------------

        #[tokio::test]
        async fn test_virtual_repo_packages_aggregate_member_packages() {
            // A virtual repository owns no catalog rows itself; pushes (and the
            // packages they index) land in a Local member. The virtual repo's
            // Packages page must therefore aggregate the member's rows.
            let Some(member) = tdh::Fixture::setup("local", "docker").await else {
                return;
            };
            let (virtual_id, virtual_key, virtual_dir) =
                tdh::create_repo(&member.pool, "virtual", "docker").await;
            sqlx::query(
                "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
                 VALUES ($1, $2, 1)",
            )
            .bind(virtual_id)
            .bind(member.repo_id)
            .execute(&member.pool)
            .await
            .expect("link member into virtual repo");

            seed_package(&member.pool, member.repo_id).await;
            tdh::grant_repo_access(&member.pool, virtual_id, member.user_id).await;

            // The fixture user holds a grant on the member, so the aggregated
            // listing (visibility applied to the member repo) surfaces it.
            let (status, body) = tdh::send(
                member.router_with_auth(router()),
                tdh::get(format!("/?repository_key={}", virtual_key)),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let json: serde_json::Value = serde_json::from_slice(&body).expect("listing json");
            assert_eq!(json["pagination"]["total"].as_i64().expect("total"), 1);
            // Aggregated rows report the virtual repo's key, matching the
            // artifacts page, not the owning member's key.
            assert_eq!(
                json["items"][0]["repository_key"]
                    .as_str()
                    .expect("repo key"),
                virtual_key
            );

            sqlx::query("DELETE FROM repositories WHERE id = $1")
                .bind(virtual_id)
                .execute(&member.pool)
                .await
                .expect("delete virtual repo");
            let _ = std::fs::remove_dir_all(&virtual_dir);
            member.teardown().await;
        }

        // -------------------------------------------------------------------
        // get_package virtual-repo context override
        // -------------------------------------------------------------------

        #[tokio::test]
        async fn test_get_package_reports_virtual_key_in_virtual_context() {
            let Some(member) = tdh::Fixture::setup("local", "docker").await else {
                return;
            };
            let (virtual_id, virtual_key, virtual_dir) =
                tdh::create_repo(&member.pool, "virtual", "docker").await;
            sqlx::query(
                "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
                 VALUES ($1, $2, 1)",
            )
            .bind(virtual_id)
            .bind(member.repo_id)
            .execute(&member.pool)
            .await
            .expect("link member into virtual repo");

            let pkg = seed_package(&member.pool, member.repo_id).await;
            tdh::grant_repo_access(&member.pool, virtual_id, member.user_id).await;
            let auth = || Some(make_auth(member.user_id, false, None));

            // Without context: reports the owning member's key.
            let (status, body) =
                tdh::send(app_for(&member, auth()), tdh::get(format!("/{pkg}"))).await;
            assert_eq!(status, StatusCode::OK);
            let json: serde_json::Value = serde_json::from_slice(&body).expect("detail json");
            assert_eq!(
                json["repository_key"].as_str().expect("repo key"),
                member.repo_key
            );

            // With virtual context: reports the virtual key.
            let (status, body) = tdh::send(
                app_for(&member, auth()),
                tdh::get(format!("/{pkg}?repository_key={}", virtual_key)),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let json: serde_json::Value = serde_json::from_slice(&body).expect("detail json");
            assert_eq!(
                json["repository_key"].as_str().expect("repo key"),
                virtual_key
            );

            sqlx::query("DELETE FROM repositories WHERE id = $1")
                .bind(virtual_id)
                .execute(&member.pool)
                .await
                .expect("delete virtual repo");
            let _ = std::fs::remove_dir_all(&virtual_dir);
            member.teardown().await;
        }
    }

    // -----------------------------------------------------------------------
    // #3660: catalog rows whose backing artifacts are gone must not be listed.
    //
    // `package_versions` carries no `artifact_id`; the link is
    // `(packages.repository_id, package_versions.checksum_sha256)`, which is
    // the checksum every catalog writer passes in. The read paths filter on a
    // LIVE artifact at that pair, so a soft delete hides the row and a restore
    // brings it back with no catalog write at all.
    // -----------------------------------------------------------------------
    mod catalog_liveness_db {
        use super::*;
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::http::StatusCode;

        /// Seed a catalog row backed by a live artifact, returning
        /// `(package_id, checksum)`.
        pub(super) async fn seed_backed_package(
            pool: &sqlx::PgPool,
            repo_id: Uuid,
            name: &str,
            version: &str,
        ) -> (Uuid, String) {
            // Distinct per (name, version) so several versions of one package
            // can be soft-deleted independently.
            use sha2::{Digest, Sha256};
            let checksum = format!("{:x}", Sha256::digest(format!("{name}@{version}")));

            sqlx::query(
                "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
                 checksum_sha256, content_type, storage_key) \
                 VALUES ($1, $2, $3, $4, 1, $5, 'application/octet-stream', $2)",
            )
            .bind(repo_id)
            .bind(format!("{name}/{version}/asset.bin"))
            .bind(name)
            .bind(version)
            .bind(&checksum)
            .execute(pool)
            .await
            .expect("seed artifact");

            let package_id: Uuid = sqlx::query_scalar(
                "INSERT INTO packages (repository_id, name, version, size_bytes) \
                 VALUES ($1, $2, $3, 1) \
                 ON CONFLICT (repository_id, name) DO UPDATE SET version = EXCLUDED.version \
                 RETURNING id",
            )
            .bind(repo_id)
            .bind(name)
            .bind(version)
            .fetch_one(pool)
            .await
            .expect("seed package");

            sqlx::query(
                "INSERT INTO package_versions (package_id, version, size_bytes, checksum_sha256) \
                 VALUES ($1, $2, 1, $3)",
            )
            .bind(package_id)
            .bind(version)
            .bind(&checksum)
            .execute(pool)
            .await
            .expect("seed package version");

            (package_id, checksum)
        }

        async fn set_deleted(pool: &sqlx::PgPool, repo_id: Uuid, checksum: &str, deleted: bool) {
            sqlx::query(
                "UPDATE artifacts SET is_deleted = $3 \
                 WHERE repository_id = $1 AND checksum_sha256 = $2",
            )
            .bind(repo_id)
            .bind(checksum)
            .bind(deleted)
            .execute(pool)
            .await
            .expect("flip is_deleted");
        }

        fn app(f: &tdh::Fixture) -> axum::Router {
            tdh::router_with_auth(router(), f.state.clone(), make_auth(f.user_id, false, None))
        }

        async fn listed_total(f: &tdh::Fixture) -> i64 {
            let (status, body) =
                tdh::send(app(f), tdh::get(format!("/?repository_key={}", f.repo_key))).await;
            assert_eq!(status, StatusCode::OK);
            let json: serde_json::Value = serde_json::from_slice(&body).expect("listing json");
            json["pagination"]["total"].as_i64().expect("total")
        }

        async fn listed_versions(f: &tdh::Fixture, pkg: Uuid) -> Vec<String> {
            let (status, body) = tdh::send(app(f), tdh::get(format!("/{pkg}/versions"))).await;
            assert_eq!(status, StatusCode::OK);
            let json: serde_json::Value = serde_json::from_slice(&body).expect("versions json");
            json["versions"]
                .as_array()
                .expect("versions array")
                .iter()
                .map(|v| v["version"].as_str().expect("version").to_string())
                .collect()
        }

        /// Soft-deleting the only artifact behind a package hides the catalog
        /// row from the listing, the detail view and the version list; a
        /// restore brings all three back. This is the ghost-row report in
        /// #3660, and the reason the delete path does not remove the row.
        #[tokio::test]
        async fn soft_deleted_artifact_hides_the_catalog_row_and_restore_returns_it() {
            let Some(f) = tdh::Fixture::setup("local", "helm").await else {
                return;
            };
            let (pkg, checksum) =
                seed_backed_package(&f.pool, f.repo_id, "ghost-chart", "1.0.0").await;

            assert_eq!(listed_total(&f).await, 1, "a live package must be listed");

            set_deleted(&f.pool, f.repo_id, &checksum, true).await;
            assert_eq!(listed_total(&f).await, 0, "a ghost row must not be listed");
            let (detail_status, _) = tdh::send(app(&f), tdh::get(format!("/{pkg}"))).await;
            assert_eq!(detail_status, StatusCode::NOT_FOUND);
            let (versions_status, _) =
                tdh::send(app(&f), tdh::get(format!("/{pkg}/versions"))).await;
            assert_eq!(versions_status, StatusCode::NOT_FOUND);

            // The catalog rows are still there — nothing deleted them, which
            // is exactly what makes the restore below possible.
            let rows: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM packages WHERE repository_id = $1")
                    .bind(f.repo_id)
                    .fetch_one(&f.pool)
                    .await
                    .expect("count packages");
            assert_eq!(rows, 1, "a soft delete must not remove the catalog row");

            set_deleted(&f.pool, f.repo_id, &checksum, false).await;
            assert_eq!(listed_total(&f).await, 1, "a restore must bring it back");
            let (detail_status, _) = tdh::send(app(&f), tdh::get(format!("/{pkg}"))).await;
            assert_eq!(detail_status, StatusCode::OK);

            f.teardown().await;
        }

        /// Version-level filtering: soft-deleting one version's artifact drops
        /// only that version from the list.
        #[tokio::test]
        async fn version_list_hides_only_the_deleted_version() {
            let Some(f) = tdh::Fixture::setup("local", "helm").await else {
                return;
            };
            let (pkg, old) = seed_backed_package(&f.pool, f.repo_id, "multi-chart", "1.0.0").await;
            let (pkg2, _new) =
                seed_backed_package(&f.pool, f.repo_id, "multi-chart", "2.0.0").await;
            assert_eq!(pkg, pkg2, "one packages row per (repository, name)");

            assert_eq!(
                listed_versions(&f, pkg).await,
                vec!["2.0.0".to_string(), "1.0.0".to_string()]
            );

            set_deleted(&f.pool, f.repo_id, &old, true).await;
            assert_eq!(listed_versions(&f, pkg).await, vec!["2.0.0".to_string()]);
            assert_eq!(
                listed_total(&f).await,
                1,
                "the package still has a live version"
            );

            f.teardown().await;
        }

        /// #5632 read-side backstop: a row whose stored `packages.version`
        /// names a version with no live artifact (soft-deleted behind the
        /// delete hook's back) reports its newest live version as Latest, in
        /// the listing and the detail view, and goes back once it is restored.
        #[tokio::test]
        async fn latest_falls_back_to_newest_live_version_5632() {
            let Some(f) = tdh::Fixture::setup("local", "helm").await else {
                return;
            };
            let (pkg, _) = seed_backed_package(&f.pool, f.repo_id, "latest-chart", "1.0.0").await;
            seed_backed_package(&f.pool, f.repo_id, "latest-chart", "1.1.0").await;
            let (_, newest) =
                seed_backed_package(&f.pool, f.repo_id, "latest-chart", "2.0.0").await;

            let listed_latest = |f: &tdh::Fixture| {
                let app = app(f);
                let key = f.repo_key.clone();
                async move {
                    let (status, body) =
                        tdh::send(app, tdh::get(format!("/?repository_key={key}"))).await;
                    assert_eq!(status, StatusCode::OK);
                    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    json["items"][0]["version"].as_str().unwrap().to_string()
                }
            };
            let detail_latest = |f: &tdh::Fixture| {
                let app = app(f);
                async move {
                    let (status, body) = tdh::send(app, tdh::get(format!("/{pkg}"))).await;
                    assert_eq!(status, StatusCode::OK);
                    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    json["version"].as_str().unwrap().to_string()
                }
            };
            assert_eq!(listed_latest(&f).await, "2.0.0");

            set_deleted(&f.pool, f.repo_id, &newest, true).await;
            let after_listed = listed_latest(&f).await;
            let after_detail = detail_latest(&f).await;
            let after_versions = listed_versions(&f, pkg).await;

            // Restore through the real trash restore (its object must exist).
            let path = "latest-chart/2.0.0/asset.bin";
            let id: Uuid = sqlx::query_scalar(
                "SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2",
            )
            .bind(f.repo_id)
            .bind(path)
            .fetch_one(&f.pool)
            .await
            .unwrap();
            f.state
                .storage_for_repo(
                    &tdh::make_repo_info(f.repo_id, &f.repo_key, &f.storage_dir, "local", None)
                        .storage_location(),
                )
                .unwrap()
                .put(path, bytes::Bytes::from_static(b"chart"))
                .await
                .unwrap();
            crate::api::handlers::trash::trash_service(&f.state)
                .restore(id)
                .await
                .expect("restore");
            let restored = detail_latest(&f).await;
            f.teardown().await;

            assert_eq!(
                after_listed, "1.1.0",
                "listing Latest skips the deleted 2.0.0"
            );
            assert_eq!(
                after_detail, "1.1.0",
                "detail Latest skips the deleted 2.0.0"
            );
            assert_eq!(after_versions, vec!["1.1.0", "1.0.0"]);
            assert_eq!(restored, "2.0.0", "a restore makes 2.0.0 Latest again");
        }

        /// Remote repositories are exempt: proxy-cached artifacts are
        /// deliberately not written to `artifacts` (#1278/#1280) while their
        /// catalog rows are (#1999), so a liveness join must not hide them.
        #[tokio::test]
        async fn remote_repository_catalog_rows_stay_visible_without_artifacts() {
            let Some(f) = tdh::Fixture::setup("remote", "maven").await else {
                return;
            };
            sqlx::query(
                "INSERT INTO packages (repository_id, name, version, size_bytes) \
                 VALUES ($1, 'com.example:cached', '1.0.0', 1)",
            )
            .bind(f.repo_id)
            .execute(&f.pool)
            .await
            .expect("seed proxy catalog row");

            let total = listed_total(&f).await;
            f.teardown().await;
            assert_eq!(total, 1, "proxy-cached catalog rows must stay listed");
        }
    }

    /// An untracked count serializes as an explicit `null` (#5346), so a
    /// client can tell "not tracked" from a real 0.
    #[test]
    fn test_untracked_download_count_serializes_as_null() {
        let mut row = make_package_row();
        row.download_count = None;
        let json = serde_json::to_value(PackageResponse::from(row)).unwrap();
        assert!(json.as_object().unwrap().contains_key("download_count"));
        assert!(json["download_count"].is_null());
    }

    // -----------------------------------------------------------------------
    // #5346: package and version download counts come from the recorded
    // download history (`download_statistics`, `proxy_download_statistics`),
    // not from the never-written `download_count` columns.
    // -----------------------------------------------------------------------
    mod download_counts_db {
        use super::catalog_liveness_db::seed_backed_package;
        use super::*;
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::http::StatusCode;

        fn app(f: &tdh::Fixture) -> axum::Router {
            tdh::router_with_auth(router(), f.state.clone(), make_auth(f.user_id, false, None))
        }

        async fn get_json(f: &tdh::Fixture, path: String) -> serde_json::Value {
            let (status, body) = tdh::send(app(f), tdh::get(path)).await;
            assert_eq!(status, StatusCode::OK);
            serde_json::from_slice(&body).expect("json body")
        }

        async fn package_count(f: &tdh::Fixture, pkg: Uuid) -> serde_json::Value {
            get_json(f, format!("/{pkg}")).await["download_count"].clone()
        }

        async fn listed_count(f: &tdh::Fixture, name: &str) -> serde_json::Value {
            let json = get_json(f, format!("/?repository_key={}", f.repo_key)).await;
            json["items"]
                .as_array()
                .expect("items")
                .iter()
                .find(|i| i["name"] == name)
                .unwrap_or_else(|| panic!("{name} listed"))["download_count"]
                .clone()
        }

        async fn version_counts(
            f: &tdh::Fixture,
            pkg: Uuid,
        ) -> std::collections::HashMap<String, serde_json::Value> {
            get_json(f, format!("/{pkg}/versions")).await["versions"]
                .as_array()
                .expect("versions")
                .iter()
                .map(|v| {
                    (
                        v["version"].as_str().unwrap().to_string(),
                        v["download_count"].clone(),
                    )
                })
                .collect()
        }

        async fn artifact_id(pool: &sqlx::PgPool, repo_id: Uuid, checksum: &str) -> Uuid {
            sqlx::query_scalar(
                "SELECT id FROM artifacts WHERE repository_id = $1 AND checksum_sha256 = $2",
            )
            .bind(repo_id)
            .bind(checksum)
            .fetch_one(pool)
            .await
            .expect("artifact id")
        }

        /// What `record_download`'s batch flush writes: one row per served body.
        async fn record_downloads(pool: &sqlx::PgPool, artifact_id: Uuid, n: usize) {
            for _ in 0..n {
                sqlx::query("INSERT INTO download_statistics (artifact_id) VALUES ($1)")
                    .bind(artifact_id)
                    .execute(pool)
                    .await
                    .expect("record download");
            }
        }

        /// One proxy serve as `proxy_catalog::record_proxy_download` writes it.
        async fn record_proxy_download(
            pool: &sqlx::PgPool,
            repo_id: Uuid,
            path: &str,
            checksum: Option<&str>,
            proxy_cache_id: Option<Uuid>,
        ) {
            sqlx::query(
                "INSERT INTO proxy_download_statistics \
                 (proxy_cache_id, repository_id, path, checksum_sha256) VALUES ($1, $2, $3, $4)",
            )
            .bind(proxy_cache_id)
            .bind(repo_id)
            .bind(path)
            .bind(checksum)
            .execute(pool)
            .await
            .expect("record proxy download");
        }

        async fn seed_remote_version(
            pool: &sqlx::PgPool,
            repo_id: Uuid,
            name: &str,
            version: &str,
            checksum: &str,
        ) -> Uuid {
            let pkg: Uuid = sqlx::query_scalar(
                "INSERT INTO packages (repository_id, name, version, size_bytes) \
                 VALUES ($1, $2, $3, 1) \
                 ON CONFLICT (repository_id, name) DO UPDATE SET version = EXCLUDED.version \
                 RETURNING id",
            )
            .bind(repo_id)
            .bind(name)
            .bind(version)
            .fetch_one(pool)
            .await
            .expect("seed remote package");
            sqlx::query(
                "INSERT INTO package_versions (package_id, version, size_bytes, checksum_sha256) \
                 VALUES ($1, $2, 1, $3)",
            )
            .bind(pkg)
            .bind(version)
            .bind(checksum)
            .execute(pool)
            .await
            .expect("seed remote version");
            pkg
        }

        /// After N downloads of a hosted package version, the version list,
        /// the package detail and the listing all report them. A version's
        /// count includes every file of that version (here a second asset
        /// recorded under the same name and version), and a package with no
        /// downloads reports a real 0, not `null`.
        #[tokio::test]
        async fn hosted_package_and_versions_report_recorded_downloads() {
            let Some(f) = tdh::Fixture::setup("local", "helm").await else {
                return;
            };
            let (pkg, v1) = seed_backed_package(&f.pool, f.repo_id, "dl-chart", "1.0.0").await;
            let (_, v2) = seed_backed_package(&f.pool, f.repo_id, "dl-chart", "2.0.0").await;
            let (quiet, _) = seed_backed_package(&f.pool, f.repo_id, "quiet-chart", "1.0.0").await;
            let extra: Uuid = sqlx::query_scalar(
                "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
                 checksum_sha256, content_type, storage_key) \
                 VALUES ($1, 'dl-chart/1.0.0/extra.bin', 'dl-chart', '1.0.0', 1, $2, \
                 'application/octet-stream', 'dl-chart/1.0.0/extra.bin') RETURNING id",
            )
            .bind(f.repo_id)
            .bind("e".repeat(64))
            .fetch_one(&f.pool)
            .await
            .expect("seed second asset");

            record_downloads(&f.pool, artifact_id(&f.pool, f.repo_id, &v1).await, 3).await;
            record_downloads(&f.pool, extra, 1).await;
            record_downloads(&f.pool, artifact_id(&f.pool, f.repo_id, &v2).await, 2).await;

            let versions = version_counts(&f, pkg).await;
            let detail = package_count(&f, pkg).await;
            let listed = listed_count(&f, "dl-chart").await;
            let quiet_detail = package_count(&f, quiet).await;
            let quiet_listed = listed_count(&f, "quiet-chart").await;
            f.teardown().await;

            assert_eq!(versions["1.0.0"], 4, "1.0.0: 3 + 1 downloads of its files");
            assert_eq!(versions["2.0.0"], 2);
            assert_eq!(detail, 6, "package detail sums its versions");
            assert_eq!(listed, 6, "listing reports the same count");
            assert_eq!(quiet_detail, 0, "no downloads is a real 0");
            assert_eq!(quiet_listed, 0);
        }

        /// A Remote package reports its pull-through serves from
        /// `proxy_download_statistics`: rows that carry the version's digest,
        /// and older rows with no digest that link to a cached object with it.
        /// A version cataloged without a digest cannot be attributed and is
        /// `null`, as is a package with only such versions.
        #[tokio::test]
        async fn remote_package_reports_proxy_downloads_or_null() {
            let Some(f) = tdh::Fixture::setup("remote", "maven").await else {
                return;
            };
            let digest = "a".repeat(64);
            let pkg =
                seed_remote_version(&f.pool, f.repo_id, "com.example:proxied", "1.0.0", &digest)
                    .await;
            seed_remote_version(&f.pool, f.repo_id, "com.example:proxied", "0.9.0", "").await;
            let untracked =
                seed_remote_version(&f.pool, f.repo_id, "com.example:streamed", "1.0.0", "").await;

            let path = "com/example/proxied/1.0.0/proxied-1.0.0.jar";
            let cache_id: Uuid = sqlx::query_scalar(
                "INSERT INTO proxy_cache_artifacts \
                 (repository_id, path, storage_key, metadata_key, size_bytes, checksum_sha256) \
                 VALUES ($1, $2, $2, $2, 1, $3) RETURNING id",
            )
            .bind(f.repo_id)
            .bind(path)
            .bind(&digest)
            .fetch_one(&f.pool)
            .await
            .expect("seed proxy cache row");
            record_proxy_download(&f.pool, f.repo_id, path, Some(&digest), Some(cache_id)).await;
            record_proxy_download(&f.pool, f.repo_id, path, Some(&digest), None).await;
            // Recorded before the digest column existed (#4542).
            record_proxy_download(&f.pool, f.repo_id, path, None, Some(cache_id)).await;
            // Another object's serve.
            record_proxy_download(&f.pool, f.repo_id, "other.jar", Some(&"b".repeat(64)), None)
                .await;

            let versions = version_counts(&f, pkg).await;
            let detail = package_count(&f, pkg).await;
            let listed = listed_count(&f, "com.example:proxied").await;
            let untracked_detail = package_count(&f, untracked).await;
            let untracked_listed = listed_count(&f, "com.example:streamed").await;
            f.teardown().await;

            assert_eq!(versions["1.0.0"], 3, "three serves of the version's digest");
            assert!(versions["0.9.0"].is_null(), "no digest: not tracked");
            assert_eq!(detail, 3);
            assert_eq!(listed, 3);
            assert!(
                untracked_detail.is_null(),
                "untracked package is null, not 0"
            );
            assert!(untracked_listed.is_null());
        }
    }
}
