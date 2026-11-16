//! Build management handlers.

use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use std::collections::{HashMap, HashSet};

use crate::api::dto::Pagination;
use crate::api::handlers::last_promotion::readable_repo_ids;
// #3713: the crate's `Json` rather than `axum::Json`, so a body this module
// refuses (a NUL in a bound field included) is the 400 VALIDATION_ERROR
// envelope every other handler emits, not axum's 422 plain text (#1368).
use crate::api::extractors::Json;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::repository::RepositoryVisibility;
use crate::services::audit_service::{
    audit_fire_and_forget, AuditAction, AuditEntry, ResourceType,
};
use crate::services::build_service::{
    Build, BuildArtifact as StoredBuildArtifact, BuildArtifactInput, BuildService,
    CreateBuildInput, DeletedBuild, UpdateBuildStatusInput,
};

/// Require that the request is authenticated, returning an error if not.
fn require_auth(auth: Option<AuthExtension>) -> Result<AuthExtension> {
    auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))
}

/// Build records belong to the principal that created them: changing one
/// (status, attached artifacts) needs the `write:artifacts` token scope,
/// deleting one `delete:artifacts`, and either administrator rights or being
/// its creator. A build created before the creator was recorded is
/// administrator-only (GHSA-mvmh-g8wm-r3cp)
async fn require_build_owner(
    state: &SharedState,
    auth: &AuthExtension,
    build_id: Uuid,
    scope: &str,
) -> Result<()> {
    auth.require_scope(scope)?;
    let owner = BuildService::new(state.db.clone())
        .created_by(build_id)
        .await?;
    if build_mutation_allowed(auth.is_admin, auth.user_id, owner) {
        Ok(())
    } else {
        Err(AppError::Authorization(
            "Only the build's creator or an administrator can change it".to_string(),
        ))
    }
}

fn build_mutation_allowed(is_admin: bool, caller: Uuid, owner: Option<Uuid>) -> bool {
    is_admin || owner == Some(caller)
}

/// Whether `auth` may see a build's `metadata`, its VCS fields (`vcs_url`,
/// `vcs_revision`, `vcs_branch`, `vcs_message`) and every attached artifact
/// path (#6240). The same owner-or-admin rule `require_build_owner`
/// applies to writes, minus the `write:artifacts` scope: a read-only token of
/// the creator still sees its own build. Anyone else gets the build without
/// those fields, and only the artifacts in repositories it can read.
fn build_details_visible(auth: &AuthExtension, owner: Option<Uuid>) -> bool {
    build_mutation_allowed(auth.is_admin, auth.user_id, owner)
}

/// Most artifacts `GET /api/v1/builds/{id}` returns for one build (#6240).
const MAX_ARTIFACTS_PER_BUILD: i64 = 1000;

/// Most artifacts the list returns per build. With `per_page` capped at 100,
/// one list call returns at most 5000 artifact rows (#6240).
const MAX_ARTIFACTS_PER_LISTED_BUILD: i64 = 50;

/// Which rule set [`strip_vcs_userinfo`] applies.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum UserinfoRules {
    /// On write: cut only where the text cannot be a host (rules 1-4). The
    /// stored value cannot be recovered, so an ambiguous URL is kept whole.
    Write,
    /// On read: rules 1-5. A value stored before this change, or one rule 5
    /// would cut, is never echoed with what may be a credential. Reads of
    /// `vcs_url` reach only the build's creator or an administrator.
    Read,
}

/// `raw` without the userinfo (`user:password@`) of a `scheme://` URL
/// (#6240). CI systems commonly set the clone URL to
/// `https://x-access-token:<token>@host/org/repo`, and that token must not be
/// stored or returned. This works on the text, not on a parsed URL: a
/// password pasted without percent-encoding can contain `/`, `?` or `#`,
/// which would end a parsed authority early and leave the rest of the secret
/// in the "path".
///
/// `head` is the text between `://` and the first `/`, `?` or `#` (all of it
/// without one):
/// 1. `head` has a `:` before its first `@`: `user:password@`, the password
///    possibly holding `@`, `/`, `?` or `#`, so cut at the LAST `@`.
/// 2. Else `head` has an `@`: a password-less userinfo (`token@host`, or
///    `git@host:22`), cut at the last `@` in `head`. An `@` after it is in
///    the path (`https://token@host/repo@v1`).
/// 3. Else no `@` after `head`, or `head` is an IPv6 literal (`[`...) or
///    ends in `:<digits>` (a port): unchanged (`https://h:8443/r?ref=a@b`,
///    `https://[::1]/r@v1`).
/// 4. Else `head` has a `:`: a password with a `/` in it
///    (`https://ci:pa/ss@host/r`), cut at the last `@`.
/// 5. [`UserinfoRules::Read`] only. Else `head` is not a dotted host name
///    (a character outside `[A-Za-z0-9.-]`, or no `.` and not `localhost`):
///    possibly a password-less token with a `/` in it
///    (`https://ab/cd==@host/r`), cut at the last `@`. This also cuts a
///    single-label host with an `@` later (`https://gitlab/org/repo@v1`),
///    which is why it never runs on write.
/// 6. Else (`https://github.com/org/repo@v1`): unchanged.
///
/// A value without `://` (scp-style `git@host:org/repo`, a login name and
/// never a password) is returned unchanged. Known gap: a password that looks
/// like a port (`https://ci:1234/ss@host/r`) is kept by rule 3.
fn strip_vcs_userinfo(raw: &str, rules: UserinfoRules) -> String {
    let Some(scheme_end) = raw.find("://").map(|i| i + 3) else {
        return raw.to_string();
    };
    let rest = &raw[scheme_end..];
    let head = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let cut_at = |at: usize| format!("{}{}", &raw[..scheme_end], &rest[at + 1..]);
    let Some(last_at) = rest.rfind('@') else {
        return raw.to_string();
    };
    if let Some(first_at) = head.find('@') {
        if head[..first_at].contains(':') {
            return cut_at(last_at);
        }
        let in_head = head.rfind('@').unwrap_or(first_at);
        return cut_at(in_head);
    }
    let is_port = head
        .rsplit_once(':')
        .is_some_and(|(_, port)| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()));
    if head.starts_with('[') || is_port {
        return raw.to_string();
    }
    if head.contains(':') {
        return cut_at(last_at);
    }
    if rules == UserinfoRules::Write {
        return raw.to_string();
    }
    let host_chars = head
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
    let dotted_host = host_chars && (head.contains('.') || head.eq_ignore_ascii_case("localhost"));
    if dotted_host {
        raw.to_string()
    } else {
        cut_at(last_at)
    }
}

/// The repository key an artifact path names: its first segment, the
/// `<repo-key>/<path>` form a build records for an artifact it published.
fn artifact_repo_key(path: &str) -> Option<&str> {
    path.trim_start_matches('/')
        .split('/')
        .next()
        .filter(|k| !k.is_empty())
}

/// A build row with the creator, which decides who sees its details.
#[derive(FromRow)]
struct BuildReadRow {
    #[sqlx(flatten)]
    build: Build,
    created_by: Option<Uuid>,
}

/// Drop the artifacts of builds whose details `auth` may not see unless the
/// artifact's path names a repository `auth` can read (#6240). A path that
/// names no repository is dropped for such callers: it describes the
/// creator's build, not anything the caller may read. Readability is the
/// grant half plus the token-scope half (`readable_repo_ids`), the same
/// predicate the virtual-member and promotion listings use.
async fn readable_artifacts(
    state: &SharedState,
    auth: &AuthExtension,
    artifacts: Vec<StoredBuildArtifact>,
    details_visible: &HashSet<Uuid>,
) -> Result<Vec<StoredBuildArtifact>> {
    let keys: Vec<String> = artifacts
        .iter()
        .filter(|a| !details_visible.contains(&a.build_id))
        .filter_map(|a| artifact_repo_key(&a.path))
        .map(str::to_string)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let readable_keys: HashSet<String> = if keys.is_empty() {
        HashSet::new()
    } else {
        let repos: Vec<(Uuid, String, RepositoryVisibility)> =
            sqlx::query_as("SELECT id, key, visibility FROM repositories WHERE key = ANY($1)")
                .bind(&keys)
                .fetch_all(&state.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
        let readable = readable_repo_ids(
            &state.db,
            repos.iter().map(|(id, _, visibility)| (*id, *visibility)),
            Some(auth),
        )
        .await;
        repos
            .into_iter()
            .filter(|(id, _, _)| readable.contains(id))
            .map(|(_, key, _)| key)
            .collect()
    };
    Ok(artifacts
        .into_iter()
        .filter(|a| {
            details_visible.contains(&a.build_id)
                || artifact_repo_key(&a.path).is_some_and(|k| readable_keys.contains(k))
        })
        .collect())
}

/// The responses for `rows` as `auth` may see them: `metadata` and the VCS
/// fields only on the builds it created (or to an administrator), and `modules`
/// built from at most `per_build` of each build's readable artifacts.
async fn build_responses(
    state: &SharedState,
    auth: &AuthExtension,
    rows: Vec<BuildReadRow>,
    per_build: i64,
) -> Result<Vec<BuildResponse>> {
    let details_visible: HashSet<Uuid> = rows
        .iter()
        .filter(|r| build_details_visible(auth, r.created_by))
        .map(|r| r.build.id)
        .collect();
    let ids: Vec<Uuid> = rows.iter().map(|r| r.build.id).collect();
    let artifacts = BuildService::new(state.db.clone())
        .list_artifacts(&ids, per_build)
        .await?;
    let artifacts = readable_artifacts(state, auth, artifacts, &details_visible).await?;

    let mut by_build: HashMap<Uuid, Vec<StoredBuildArtifact>> = HashMap::new();
    for a in artifacts {
        by_build.entry(a.build_id).or_default().push(a);
    }
    Ok(rows
        .into_iter()
        .map(|row| {
            let visible = details_visible.contains(&row.build.id);
            let artifacts = by_build.remove(&row.build.id).unwrap_or_default();
            let mut response = BuildResponse::from(row.build);
            if !visible {
                response.metadata = None;
                response.vcs_url = None;
                response.vcs_revision = None;
                response.vcs_branch = None;
                response.vcs_message = None;
            }
            response.modules = Some(group_into_modules(artifacts));
            response
        })
        .collect())
}

/// Group a build's artifact rows by `module_name`, in first-seen order.
/// Artifacts attached without a module go to a module with an empty name.
/// A module has no row of its own: its id is the id of its first artifact.
fn group_into_modules(artifacts: Vec<StoredBuildArtifact>) -> Vec<BuildModule> {
    let mut modules: Vec<BuildModule> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    for a in artifacts {
        let name = a.module_name.unwrap_or_default();
        let artifact = BuildArtifact {
            name: a.name,
            path: a.path,
            checksum_sha256: a.checksum_sha256,
            size_bytes: a.size_bytes,
        };
        match index.get(&name) {
            Some(&i) => modules[i].artifacts.push(artifact),
            None => {
                index.insert(name.clone(), modules.len());
                modules.push(BuildModule {
                    id: a.id,
                    name,
                    artifacts: vec![artifact],
                });
            }
        }
    }
    modules
}

/// `ORDER BY` for the build list. `sort_by` picks from a fixed set of
/// columns, anything else keeps the build number order, so the value never
/// reaches the SQL text (#6046).
fn list_order_clause(sort_by: Option<&str>, desc: bool) -> String {
    let column = match sort_by {
        Some("created_at") => "created_at",
        Some("started_at") => "started_at",
        Some("finished_at") => "finished_at",
        Some("duration") | Some("duration_ms") => "duration_ms",
        Some("name") => "name",
        Some("status") => "status",
        _ => "build_number",
    };
    let direction = if desc { "DESC" } else { "ASC" };
    format!("ORDER BY {column} {direction} NULLS LAST, id {direction}")
}

/// Create build routes
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_builds).post(create_build))
        .route("/diff", get(get_build_diff))
        .route("/delete", post(delete_builds))
        .route(
            "/:id",
            get(get_build).put(update_build).delete(delete_build),
        )
        .route("/:id/artifacts", post(add_build_artifacts))
}

#[derive(Debug, Deserialize, IntoParams, ToSchema)]
pub struct ListBuildsQuery {
    pub page: Option<u32>,
    pub per_page: Option<u32>,
    pub status: Option<String>,
    pub search: Option<String>,
    pub sort_by: Option<String>,
    pub sort_order: Option<String>,
    /// Exact build name
    pub name: Option<String>,
    /// Exact VCS branch
    pub branch: Option<String>,
    /// Exact agent
    pub agent: Option<String>,
    /// Builds created at or after this time (RFC 3339)
    pub created_after: Option<chrono::DateTime<chrono::Utc>>,
    /// Builds created before this time (RFC 3339)
    pub created_before: Option<chrono::DateTime<chrono::Utc>>,
}

/// The list's `WHERE`, shared by the page and the count: `$1` status, `$2`
/// search pattern, `$3` to `$7` the exact filters
const LIST_FILTER: &str = r#"
        WHERE ($1::text IS NULL OR status = $1)
          AND ($2::text IS NULL OR name ILIKE $2 ESCAPE '\')
          AND ($3::text IS NULL OR name = $3)
          AND ($4::text IS NULL OR vcs_branch = $4)
          AND ($5::text IS NULL OR agent = $5)
          AND ($6::timestamptz IS NULL OR created_at >= $6)
          AND ($7::timestamptz IS NULL OR created_at < $7)
"#;

#[derive(Debug, Serialize, ToSchema)]
pub struct BuildArtifact {
    pub name: String,
    pub path: String,
    pub checksum_sha256: String,
    pub size_bytes: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BuildModule {
    pub id: Uuid,
    pub name: String,
    pub artifacts: Vec<BuildArtifact>,
}

#[derive(Debug, Serialize, FromRow, ToSchema)]
pub struct BuildRow {
    pub id: Uuid,
    pub name: String,
    pub build_number: i32,
    pub status: String,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
    pub duration_ms: Option<i64>,
    pub agent: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub artifact_count: Option<i32>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BuildResponse {
    pub id: Uuid,
    pub name: String,
    pub number: i32,
    pub status: String,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
    pub duration_ms: Option<i64>,
    pub agent: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub artifact_count: Option<i32>,
    pub modules: Option<Vec<BuildModule>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vcs_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vcs_revision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vcs_branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vcs_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Object)]
    pub metadata: Option<serde_json::Value>,
}

impl From<BuildRow> for BuildResponse {
    fn from(row: BuildRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            number: row.build_number,
            status: row.status,
            started_at: row.started_at,
            finished_at: row.finished_at,
            duration_ms: row.duration_ms,
            agent: row.agent,
            created_at: row.created_at,
            updated_at: row.updated_at,
            artifact_count: row.artifact_count,
            modules: None,
            vcs_url: None,
            vcs_revision: None,
            vcs_branch: None,
            vcs_message: None,
            metadata: None,
        }
    }
}

/// Every response carries `vcs_url` without its userinfo (#6240), including
/// the rows stored before create started stripping it.
impl From<Build> for BuildResponse {
    fn from(build: Build) -> Self {
        Self {
            id: build.id,
            name: build.name,
            number: build.build_number,
            status: build.status,
            started_at: build.started_at,
            finished_at: build.finished_at,
            duration_ms: build.duration_ms,
            agent: build.agent,
            created_at: build.created_at,
            updated_at: build.updated_at,
            artifact_count: build.artifact_count,
            modules: None,
            vcs_url: build
                .vcs_url
                .as_deref()
                .map(|u| strip_vcs_userinfo(u, UserinfoRules::Read)),
            vcs_revision: build.vcs_revision,
            vcs_branch: build.vcs_branch,
            vcs_message: build.vcs_message,
            metadata: build.metadata,
        }
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BuildListResponse {
    pub items: Vec<BuildResponse>,
    pub pagination: Pagination,
}

/// List builds
#[utoipa::path(
    get,
    path = "",
    context_path = "/api/v1/builds",
    tag = "builds",
    params(ListBuildsQuery),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "List of builds", body = BuildListResponse),
        (status = 401, description = "Authentication required"),
    )
)]
pub async fn list_builds(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Query(query): Query<ListBuildsQuery>,
) -> Result<Json<BuildListResponse>> {
    let auth = require_auth(auth)?;

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = ((page - 1) * per_page) as i64;

    // #3557: the free-text term is a literal substring, so `%`/`_`/`\` in it
    // must match themselves; escaped here and matched under `ESCAPE '\'`.
    let search_pattern = query
        .search
        .as_ref()
        .map(|s| format!("%{}%", super::escape_like_literal(s)));
    let sort_desc = query.sort_order.as_deref() == Some("desc");

    // Check if builds table exists first
    let table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'builds')",
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);

    if !table_exists {
        return Ok(Json(BuildListResponse {
            items: vec![],
            pagination: Pagination {
                page,
                per_page,
                total: 0,
                total_pages: 0,
            },
        }));
    }

    let order_clause = list_order_clause(query.sort_by.as_deref(), sort_desc);

    let sql = format!(
        r#"
        SELECT id, name, build_number, status, started_at, finished_at,
               duration_ms, agent, artifact_count,
               vcs_url, vcs_revision, vcs_branch, vcs_message, metadata,
               created_at, updated_at, created_by
        FROM builds
        {LIST_FILTER}
        {order_clause}
        OFFSET $8
        LIMIT $9
        "#
    );

    let builds: Vec<BuildReadRow> = sqlx::query_as(sqlx::AssertSqlSafe(&*sql))
        .bind(&query.status)
        .bind(&search_pattern)
        .bind(&query.name)
        .bind(&query.branch)
        .bind(&query.agent)
        .bind(query.created_after)
        .bind(query.created_before)
        .bind(offset)
        .bind(per_page as i64)
        .fetch_all(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let count_sql = format!("SELECT COUNT(*) FROM builds {LIST_FILTER}");
    let total: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(&*count_sql))
        .bind(&query.status)
        .bind(&search_pattern)
        .bind(&query.name)
        .bind(&query.branch)
        .bind(&query.agent)
        .bind(query.created_after)
        .bind(query.created_before)
        .fetch_one(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;

    let items = build_responses(&state, &auth, builds, MAX_ARTIFACTS_PER_LISTED_BUILD).await?;

    Ok(Json(BuildListResponse {
        items,
        pagination: Pagination {
            page,
            per_page,
            total,
            total_pages,
        },
    }))
}

/// Get a build by ID
#[utoipa::path(
    get,
    path = "/{id}",
    context_path = "/api/v1/builds",
    tag = "builds",
    params(
        ("id" = Uuid, Path, description = "Build ID"),
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Build details", body = BuildResponse),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Build not found"),
    )
)]
pub async fn get_build(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
) -> Result<Json<BuildResponse>> {
    let auth = require_auth(auth)?;

    // Check if builds table exists first
    let table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'builds')",
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);

    if !table_exists {
        return Err(AppError::NotFound("Build not found".to_string()));
    }

    let build: BuildReadRow = sqlx::query_as(
        r#"
        SELECT id, name, build_number, status, started_at, finished_at,
               duration_ms, agent, artifact_count,
               vcs_url, vcs_revision, vcs_branch, vcs_message, metadata,
               created_at, updated_at, created_by
        FROM builds
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("Build not found".to_string()))?;

    let mut responses =
        build_responses(&state, &auth, vec![build], MAX_ARTIFACTS_PER_BUILD).await?;
    let response = responses
        .pop()
        .ok_or_else(|| AppError::NotFound("Build not found".to_string()))?;
    Ok(Json(response))
}

#[derive(Debug, Deserialize, IntoParams, ToSchema)]
pub struct BuildDiffQuery {
    pub build_a: Uuid,
    pub build_b: Uuid,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BuildArtifactDiff {
    pub name: String,
    pub path: String,
    pub old_checksum: String,
    pub new_checksum: String,
    pub old_size_bytes: i64,
    pub new_size_bytes: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BuildDiffResponse {
    pub build_a: Uuid,
    pub build_b: Uuid,
    pub added: Vec<BuildArtifact>,
    pub removed: Vec<BuildArtifact>,
    pub modified: Vec<BuildArtifactDiff>,
}

/// Get diff between two builds
#[utoipa::path(
    get,
    path = "/diff",
    context_path = "/api/v1/builds",
    tag = "builds",
    params(BuildDiffQuery),
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Diff between two builds", body = BuildDiffResponse),
        (status = 401, description = "Authentication required"),
    )
)]
pub async fn get_build_diff(
    State(_state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Query(query): Query<BuildDiffQuery>,
) -> Result<Json<BuildDiffResponse>> {
    let _auth = require_auth(auth)?;

    // For now, return empty diff - this would require build_artifacts table
    Ok(Json(BuildDiffResponse {
        build_a: query.build_a,
        build_b: query.build_b,
        added: vec![],
        removed: vec![],
        modified: vec![],
    }))
}

// --- Write endpoints ---

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateBuildRequest {
    // #3713: every text field here is bound verbatim into the `INSERT INTO
    // builds`, so a `\0` in any of them was a 500 from the driver for any
    // logged-in user. Each refuses one at deserialization instead, so the
    // 400 comes out of the `Json` extractor before the query (as
    // `LoginRequest::username` does, #3673). The optional ones need
    // `default` too: a `deserialize_with` hook only runs for a present key.
    #[serde(deserialize_with = "crate::api::extractors::deserialize_nul_free_string")]
    pub name: String,
    pub build_number: i32,
    #[serde(
        default,
        deserialize_with = "crate::api::extractors::deserialize_nul_free_opt_string"
    )]
    pub agent: Option<String>,
    pub started_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(
        default,
        deserialize_with = "crate::api::extractors::deserialize_nul_free_opt_string"
    )]
    pub vcs_url: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::api::extractors::deserialize_nul_free_opt_string"
    )]
    pub vcs_revision: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::api::extractors::deserialize_nul_free_opt_string"
    )]
    pub vcs_branch: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::api::extractors::deserialize_nul_free_opt_string"
    )]
    pub vcs_message: Option<String>,
    #[schema(value_type = Object)]
    pub metadata: Option<serde_json::Value>,
}

/// Create a new build (POST /api/v1/builds)
#[utoipa::path(
    post,
    path = "",
    context_path = "/api/v1/builds",
    tag = "builds",
    request_body = CreateBuildRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Build created successfully", body = BuildResponse),
        (status = 403, description = "The token lacks write:artifacts"),
        (status = 401, description = "Authentication required"),
    )
)]
pub async fn create_build(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Json(payload): Json<CreateBuildRequest>,
) -> Result<Json<BuildResponse>> {
    let auth = require_auth(auth)?;
    auth.require_scope("write:artifacts")?;

    let service = BuildService::new(state.db.clone());
    let build = service
        .create(CreateBuildInput {
            name: payload.name,
            build_number: payload.build_number,
            agent: payload.agent,
            started_at: payload.started_at,
            // #6240: a clone URL's credentials are never stored.
            vcs_url: payload
                .vcs_url
                .as_deref()
                .map(|u| strip_vcs_userinfo(u, UserinfoRules::Write)),
            vcs_revision: payload.vcs_revision,
            vcs_branch: payload.vcs_branch,
            vcs_message: payload.vcs_message,
            metadata: payload.metadata,
            created_by: Some(auth.user_id),
        })
        .await?;

    Ok(Json(BuildResponse::from(build)))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateBuildRequest {
    pub status: String,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Update build status (PUT /api/v1/builds/:id)
#[utoipa::path(
    put,
    path = "/{id}",
    context_path = "/api/v1/builds",
    tag = "builds",
    params(
        ("id" = Uuid, Path, description = "Build ID"),
    ),
    request_body = UpdateBuildRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Build updated successfully", body = BuildResponse),
        (status = 403, description = "Caller is neither the build's creator nor an administrator, or the token lacks write:artifacts"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Build not found"),
    )
)]
pub async fn update_build(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateBuildRequest>,
) -> Result<Json<BuildResponse>> {
    let auth = require_auth(auth)?;
    require_build_owner(&state, &auth, id, "write:artifacts").await?;

    let service = BuildService::new(state.db.clone());
    let build = service
        .update_status(
            id,
            UpdateBuildStatusInput {
                status: payload.status,
                finished_at: payload.finished_at,
            },
        )
        .await?;

    Ok(Json(BuildResponse::from(build)))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AddBuildArtifactsRequest {
    pub artifacts: Vec<BuildArtifactInputPayload>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct BuildArtifactInputPayload {
    // #3713: the four text fields are bound verbatim into the `INSERT INTO
    // build_artifacts`, the same shape as `CreateBuildRequest` above, so each
    // refuses a `\0` at deserialization for the same reason.
    #[serde(
        default,
        deserialize_with = "crate::api::extractors::deserialize_nul_free_opt_string"
    )]
    pub module_name: Option<String>,
    #[serde(deserialize_with = "crate::api::extractors::deserialize_nul_free_string")]
    pub name: String,
    #[serde(deserialize_with = "crate::api::extractors::deserialize_nul_free_string")]
    pub path: String,
    #[serde(deserialize_with = "crate::api::extractors::deserialize_nul_free_string")]
    pub checksum_sha256: String,
    pub size_bytes: i64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BuildArtifactResponse {
    pub id: Uuid,
    pub build_id: Uuid,
    pub module_name: Option<String>,
    pub name: String,
    pub path: String,
    pub checksum_sha256: String,
    pub size_bytes: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AddBuildArtifactsResponse {
    pub artifacts: Vec<BuildArtifactResponse>,
}

/// Attach artifacts to a build (POST /api/v1/builds/:id/artifacts)
#[utoipa::path(
    post,
    path = "/{id}/artifacts",
    context_path = "/api/v1/builds",
    tag = "builds",
    params(
        ("id" = Uuid, Path, description = "Build ID"),
    ),
    request_body = AddBuildArtifactsRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Artifacts added to build", body = AddBuildArtifactsResponse),
        (status = 403, description = "Caller is neither the build's creator nor an administrator, or the token lacks write:artifacts"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Build not found"),
    )
)]
pub async fn add_build_artifacts(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
    Json(payload): Json<AddBuildArtifactsRequest>,
) -> Result<Json<AddBuildArtifactsResponse>> {
    let auth = require_auth(auth)?;
    require_build_owner(&state, &auth, id, "write:artifacts").await?;

    let service = BuildService::new(state.db.clone());
    let inputs: Vec<BuildArtifactInput> = payload
        .artifacts
        .into_iter()
        .map(|a| BuildArtifactInput {
            module_name: a.module_name,
            name: a.name,
            path: a.path,
            checksum_sha256: a.checksum_sha256,
            size_bytes: a.size_bytes,
        })
        .collect();

    let artifacts = service.add_artifacts(id, inputs).await?;

    let response_artifacts = artifacts
        .into_iter()
        .map(|a| BuildArtifactResponse {
            id: a.id,
            build_id: a.build_id,
            module_name: a.module_name,
            name: a.name,
            path: a.path,
            checksum_sha256: a.checksum_sha256,
            size_bytes: a.size_bytes,
            created_at: a.created_at,
        })
        .collect();

    Ok(Json(AddBuildArtifactsResponse {
        artifacts: response_artifacts,
    }))
}

/// Most builds one `POST /api/v1/builds/delete` takes
pub const MAX_BULK_DELETE: usize = 100;

/// Delete a build record (DELETE /api/v1/builds/:id)
///
/// Only the record and its attached artifact list are deleted, the artifacts
/// in repositories stay
#[utoipa::path(
    delete,
    path = "/{id}",
    context_path = "/api/v1/builds",
    tag = "builds",
    params(
        ("id" = Uuid, Path, description = "Build ID"),
    ),
    security(("bearer_auth" = [])),
    responses(
        (status = 204, description = "Build deleted"),
        (status = 403, description = "Caller is neither the build's creator nor an administrator, or the token lacks delete:artifacts"),
        (status = 401, description = "Authentication required"),
        (status = 404, description = "Build not found"),
    )
)]
pub async fn delete_build(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode> {
    let auth = require_auth(auth)?;
    require_build_owner(&state, &auth, id, "delete:artifacts").await?;

    let deleted = BuildService::new(state.db.clone()).delete(&[id]).await?;
    if deleted.is_empty() {
        return Err(AppError::NotFound(format!("Build {} not found", id)));
    }
    audit_builds_deleted(&state, &auth, &deleted, false).await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DeleteBuildsRequest {
    /// Build ids, at most 100
    pub ids: Vec<Uuid>,
}

#[derive(Debug, Serialize, ToSchema, PartialEq)]
pub struct DeleteBuildFailure {
    pub id: Uuid,
    /// `not_found` or `forbidden`
    pub reason: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DeleteBuildsResponse {
    pub deleted: Vec<Uuid>,
    pub failed: Vec<DeleteBuildFailure>,
}

/// Delete several build records (POST /api/v1/builds/delete)
///
/// Each id is deleted when the caller created it or is an administrator,
/// an unknown or foreign id is reported in `failed` and does not stop the
/// others. Only the records go, the artifacts in repositories stay
#[utoipa::path(
    post,
    path = "/delete",
    context_path = "/api/v1/builds",
    tag = "builds",
    request_body = DeleteBuildsRequest,
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Per-id result", body = DeleteBuildsResponse),
        (status = 400, description = "No ids, or more than 100"),
        (status = 403, description = "The token lacks delete:artifacts"),
        (status = 401, description = "Authentication required"),
    )
)]
pub async fn delete_builds(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Json(payload): Json<DeleteBuildsRequest>,
) -> Result<Json<DeleteBuildsResponse>> {
    let auth = require_auth(auth)?;
    auth.require_scope("delete:artifacts")?;

    let mut ids = payload.ids;
    let mut seen = std::collections::HashSet::new();
    ids.retain(|id| seen.insert(*id));
    if ids.is_empty() || ids.len() > MAX_BULK_DELETE {
        return Err(AppError::Validation(format!(
            "ids must hold between 1 and {MAX_BULK_DELETE} build ids"
        )));
    }

    let service = BuildService::new(state.db.clone());
    let owners = service.owners(&ids).await?;
    let (allowed, mut failed) = partition_bulk_delete(&ids, &owners, auth.is_admin, auth.user_id);
    let deleted = service.delete(&allowed).await?;

    // A build deleted by someone else between the two queries is gone too
    let gone: std::collections::HashSet<Uuid> = deleted.iter().map(|b| b.id).collect();
    failed.extend(
        allowed
            .iter()
            .filter(|id| !gone.contains(id))
            .map(|id| DeleteBuildFailure {
                id: *id,
                reason: "not_found".to_string(),
            }),
    );
    audit_builds_deleted(&state, &auth, &deleted, true).await;

    Ok(Json(DeleteBuildsResponse {
        deleted: allowed.into_iter().filter(|id| gone.contains(id)).collect(),
        failed,
    }))
}

/// Split a bulk delete into the ids the caller may delete and the refused
/// ones, keeping the request order
fn partition_bulk_delete(
    ids: &[Uuid],
    owners: &std::collections::HashMap<Uuid, Option<Uuid>>,
    is_admin: bool,
    caller: Uuid,
) -> (Vec<Uuid>, Vec<DeleteBuildFailure>) {
    let mut allowed = Vec::new();
    let mut failed = Vec::new();
    for id in ids {
        let reason = match owners.get(id) {
            None => "not_found",
            Some(owner) if build_mutation_allowed(is_admin, caller, *owner) => {
                allowed.push(*id);
                continue;
            }
            Some(_) => "forbidden",
        };
        failed.push(DeleteBuildFailure {
            id: *id,
            reason: reason.to_string(),
        });
    }
    (allowed, failed)
}

async fn audit_builds_deleted(
    state: &SharedState,
    auth: &AuthExtension,
    deleted: &[DeletedBuild],
    bulk: bool,
) {
    for build in deleted {
        audit_fire_and_forget(
            state.db.clone(),
            AuditEntry::new(AuditAction::BuildDeleted, ResourceType::Build)
                .user(auth.user_id)
                .resource(build.id)
                .actor_name(auth.username.clone())
                .resource_name(format!("{} #{}", build.name, build.build_number))
                .with_request_client_ip()
                .details(serde_json::json!({
                    "name": build.name,
                    "build_number": build.build_number,
                    "bulk": bulk,
                })),
        )
        .await;
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list_builds,
        get_build,
        get_build_diff,
        create_build,
        update_build,
        add_build_artifacts,
        delete_build,
        delete_builds,
    ),
    components(schemas(
        ListBuildsQuery,
        BuildArtifact,
        BuildModule,
        BuildRow,
        BuildResponse,
        BuildListResponse,
        BuildDiffQuery,
        BuildArtifactDiff,
        BuildDiffResponse,
        CreateBuildRequest,
        UpdateBuildRequest,
        AddBuildArtifactsRequest,
        BuildArtifactInputPayload,
        BuildArtifactResponse,
        AddBuildArtifactsResponse,
        DeleteBuildsRequest,
        DeleteBuildFailure,
        DeleteBuildsResponse,
    ))
)]
pub struct BuildsApiDoc;

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;

    // -----------------------------------------------------------------------
    // CreateBuildRequest — NUL in a bound text field (#3713)
    // -----------------------------------------------------------------------

    /// All six text fields of the create-build body are bound verbatim into
    /// the `INSERT INTO builds`, and Postgres rejects a `\0` at the wire
    /// protocol, so a NUL in any of them was a 500 for any logged-in user.
    /// Each field refuses one at deserialization — the `Json` extractor's
    /// ordinary 400 VALIDATION_ERROR envelope, before the handler and before
    /// the pool checkout. Router-level and DB-backed (no-op without
    /// `DATABASE_URL`) because the counterfactual *is* the query: with a hook
    /// removed that field's request answers 500.
    #[tokio::test]
    async fn create_build_rejects_a_nul_in_any_bound_text_field() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let dir = std::env::temp_dir().join(format!("ph-3713-{}", Uuid::new_v4()));
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let (user_id, username) = tdh::create_user(&pool).await;
        let app = tdh::router_with_auth(super::router(), state, tdh::make_auth(user_id, &username));
        let name = format!("ph-3713-{}", Uuid::new_v4());

        fn post(body: String) -> axum::http::Request<axum::body::Body> {
            axum::http::Request::builder()
                .method("POST")
                .uri("/")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body))
                .unwrap()
        }

        for field in [
            "name",
            "agent",
            "vcs_url",
            "vcs_revision",
            "vcs_branch",
            "vcs_message",
        ] {
            let mut body = json!({ "name": name, "build_number": 1 });
            body[field] = json!("a\u{0}b");
            let (status, bytes) = tdh::send(app.clone(), post(body.to_string())).await;
            assert_eq!(
                status,
                axum::http::StatusCode::BAD_REQUEST,
                "a NUL in `{field}` must be refused before the query (#3713), got {status} {}",
                String::from_utf8_lossy(&bytes)
            );
            assert!(
                String::from_utf8_lossy(&bytes).contains("VALIDATION_ERROR"),
                "the refusal for `{field}` must be the ordinary validation envelope, got {}",
                String::from_utf8_lossy(&bytes)
            );
            let lower = String::from_utf8_lossy(&bytes).to_lowercase();
            assert!(
                !lower.contains("database") && !lower.contains("utf8"),
                "the 400 for `{field}` must not leak driver/database detail, got: {lower}"
            );
        }

        // Control: the same six fields without a NUL still create the build,
        // and the optional ones still default when absent.
        let body = json!({
            "name": name,
            "build_number": 1,
            "agent": "ph-3713-agent",
            "vcs_url": "https://vcs.example.test/r.git",
            "vcs_revision": "0123abcd",
            "vcs_branch": "main",
            "vcs_message": "ph-3713 control",
        });
        let (status, bytes) = tdh::send(app.clone(), post(body.to_string())).await;
        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "the control body must still create the build, got {status} {}",
            String::from_utf8_lossy(&bytes)
        );
        let (status, bytes) = tdh::send(
            app,
            post(json!({ "name": name, "build_number": 2 }).to_string()),
        )
        .await;
        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "absent optional fields must still default to None, got {status} {}",
            String::from_utf8_lossy(&bytes)
        );

        let _ = sqlx::query("DELETE FROM builds WHERE name = $1")
            .bind(&name)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await;
    }

    /// The sibling route: the four text fields of each artifact entry on
    /// `POST /builds/:id/artifacts` are bound verbatim into the `INSERT INTO
    /// build_artifacts`, so a NUL in any of them was the same 500 for any
    /// logged-in user (measured in the #3726 audits). Same hook, same
    /// envelope, same counterfactual.
    #[tokio::test]
    async fn add_build_artifacts_rejects_a_nul_in_any_bound_text_field() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let dir = std::env::temp_dir().join(format!("ph-3713-{}", Uuid::new_v4()));
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let (user_id, username) = tdh::create_user(&pool).await;
        let app = tdh::router_with_auth(super::router(), state, tdh::make_auth(user_id, &username));
        let build_name = format!("ph-3713-artifacts-{}", Uuid::new_v4());

        fn post(uri: &str, body: String) -> axum::http::Request<axum::body::Body> {
            axum::http::Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(axum::body::Body::from(body))
                .unwrap()
        }

        // A build to attach to, created through the route itself.
        let (status, bytes) = tdh::send(
            app.clone(),
            post(
                "/",
                json!({ "name": build_name, "build_number": 1 }).to_string(),
            ),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK, "fixture build");
        let build: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let build_id = build["id"].as_str().expect("build id").to_string();
        let uri = format!("/{build_id}/artifacts");

        let clean = json!({
            "module_name": "ph-3713-module",
            "name": "ph-3713-artifact.jar",
            "path": "/maven/ph-3713/artifact.jar",
            "checksum_sha256": "0123abcd",
            "size_bytes": 1,
        });
        for field in ["module_name", "name", "path", "checksum_sha256"] {
            let mut entry = clean.clone();
            entry[field] = json!("a\u{0}b");
            let body = json!({ "artifacts": [entry] }).to_string();
            let (status, bytes) = tdh::send(app.clone(), post(&uri, body)).await;
            assert_eq!(
                status,
                axum::http::StatusCode::BAD_REQUEST,
                "a NUL in `{field}` must be refused before the query (#3713), got {status} {}",
                String::from_utf8_lossy(&bytes)
            );
            assert!(
                String::from_utf8_lossy(&bytes).contains("VALIDATION_ERROR"),
                "the refusal for `{field}` must be the ordinary validation envelope, got {}",
                String::from_utf8_lossy(&bytes)
            );
            let lower = String::from_utf8_lossy(&bytes).to_lowercase();
            assert!(
                !lower.contains("database") && !lower.contains("utf8"),
                "the 400 for `{field}` must not leak driver/database detail, got: {lower}"
            );
        }

        // Control: the same entry without a NUL is inserted, and an absent
        // `module_name` still defaults to None.
        let body = json!({ "artifacts": [clean] }).to_string();
        let (status, bytes) = tdh::send(app.clone(), post(&uri, body)).await;
        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "the control entry must still be inserted, got {status} {}",
            String::from_utf8_lossy(&bytes)
        );
        let mut no_module = clean.clone();
        no_module.as_object_mut().unwrap().remove("module_name");
        let body = json!({ "artifacts": [no_module] }).to_string();
        let (status, bytes) = tdh::send(app, post(&uri, body)).await;
        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "an absent `module_name` must still default to None, got {status} {}",
            String::from_utf8_lossy(&bytes)
        );

        let build_uuid = Uuid::parse_str(&build_id).unwrap();
        let _ = sqlx::query("DELETE FROM build_artifacts WHERE build_id = $1")
            .bind(build_uuid)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM builds WHERE id = $1")
            .bind(build_uuid)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await;
    }

    // -----------------------------------------------------------------------
    // require_auth tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_require_auth_passes_with_some() {
        let auth = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "user".to_string(),
            email: "user@example.com".to_string(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
        };
        let result = require_auth(Some(auth));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().username, "user");
    }

    #[test]
    fn test_require_auth_fails_with_none() {
        let err = require_auth(None).unwrap_err();
        assert!(
            format!("{}", err).contains("Authentication required"),
            "Expected 'Authentication required' in error: {}",
            err
        );
    }

    // -----------------------------------------------------------------------
    // Read-endpoint auth-gate tests
    //
    // Mirrors the guard behaviour of the sibling write handlers: anonymous
    // (None) callers must be rejected with an Authentication error before any
    // database access, while an authenticated caller is admitted. The auth
    // check runs first, so a lazily-connected (never-dialed) pool is enough to
    // exercise the anon path without a live database.
    // -----------------------------------------------------------------------

    fn test_state() -> crate::api::SharedState {
        use std::sync::Arc;
        let pool = sqlx::PgPool::connect_lazy("postgres://fake:fake@localhost/fake")
            .expect("connect_lazy should not fail");
        let storage: Arc<dyn crate::storage::StorageBackend> = Arc::new(
            crate::storage::filesystem::FilesystemStorage::new("/tmp/test-builds"),
        );
        let registry = Arc::new(crate::storage::StorageRegistry::new(
            std::collections::HashMap::new(),
            "filesystem".to_string(),
        ));
        Arc::new(crate::api::AppState::new(
            crate::config::Config::test_config(),
            pool,
            storage,
            registry,
        ))
    }

    fn sample_auth() -> AuthExtension {
        AuthExtension {
            user_id: Uuid::new_v4(),
            username: "builder".to_string(),
            email: "builder@example.com".to_string(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
        }
    }

    #[tokio::test]
    async fn test_list_builds_rejects_anonymous() {
        let state = test_state();
        let query = ListBuildsQuery {
            page: None,
            per_page: None,
            status: None,
            search: None,
            sort_by: None,
            sort_order: None,
            name: None,
            branch: None,
            agent: None,
            created_after: None,
            created_before: None,
        };
        let err = list_builds(State(state), Extension(None), Query(query))
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Authentication(_)), "got: {err}");
    }

    #[tokio::test]
    async fn test_get_build_rejects_anonymous() {
        let state = test_state();
        let err = get_build(State(state), Extension(None), Path(Uuid::new_v4()))
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Authentication(_)), "got: {err}");
    }

    #[tokio::test]
    async fn test_get_build_diff_rejects_anonymous() {
        let state = test_state();
        let query = BuildDiffQuery {
            build_a: Uuid::new_v4(),
            build_b: Uuid::new_v4(),
        };
        let err = get_build_diff(State(state), Extension(None), Query(query))
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Authentication(_)), "got: {err}");
    }

    #[tokio::test]
    async fn test_get_build_diff_allows_authenticated() {
        // get_build_diff performs no database access, so an authenticated call
        // exercises the full success path and returns an (empty) diff.
        let state = test_state();
        let build_a = Uuid::new_v4();
        let build_b = Uuid::new_v4();
        let query = BuildDiffQuery { build_a, build_b };
        let resp = get_build_diff(State(state), Extension(Some(sample_auth())), Query(query))
            .await
            .expect("authenticated diff should succeed");
        assert_eq!(resp.0.build_a, build_a);
        assert_eq!(resp.0.build_b, build_b);
        assert!(resp.0.added.is_empty());
        assert!(resp.0.removed.is_empty());
        assert!(resp.0.modified.is_empty());
    }

    // -----------------------------------------------------------------------
    // ListBuildsQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_list_builds_query_deserialize_full() {
        let json = json!({
            "page": 2,
            "per_page": 50,
            "status": "running",
            "search": "my-build",
            "sort_by": "build_number",
            "sort_order": "desc"
        });
        let query: ListBuildsQuery = serde_json::from_value(json).unwrap();
        assert_eq!(query.page, Some(2));
        assert_eq!(query.per_page, Some(50));
        assert_eq!(query.status.as_deref(), Some("running"));
        assert_eq!(query.search.as_deref(), Some("my-build"));
        assert_eq!(query.sort_by.as_deref(), Some("build_number"));
        assert_eq!(query.sort_order.as_deref(), Some("desc"));
    }

    #[test]
    fn test_list_builds_query_deserialize_empty() {
        let json = json!({});
        let query: ListBuildsQuery = serde_json::from_value(json).unwrap();
        assert!(query.page.is_none());
        assert!(query.per_page.is_none());
        assert!(query.status.is_none());
        assert!(query.search.is_none());
        assert!(query.sort_by.is_none());
        assert!(query.sort_order.is_none());
    }

    // -----------------------------------------------------------------------
    // Builds pagination logic
    // -----------------------------------------------------------------------

    #[test]
    fn test_builds_pagination_defaults() {
        let page = 1;
        let per_page = 20_u32;
        assert_eq!(page, 1);
        assert_eq!(per_page, 20);
    }

    #[test]
    fn test_builds_pagination_page_clamped() {
        let page = 1;
        assert_eq!(page, 1);
    }

    #[test]
    fn test_builds_pagination_per_page_capped() {
        let per_page = 100;
        assert_eq!(per_page, 100);
    }

    #[test]
    fn test_builds_offset_calculation() {
        let page: u32 = 5;
        let per_page: u32 = 10;
        let offset = ((page - 1) * per_page) as i64;
        assert_eq!(offset, 40);
    }

    // -----------------------------------------------------------------------
    // Search pattern construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_search_pattern_construction() {
        let search = Some("my-build".to_string());
        let search_pattern = search.as_ref().map(|s| format!("%{}%", s));
        assert_eq!(search_pattern.as_deref(), Some("%my-build%"));
    }

    #[test]
    fn test_search_pattern_none() {
        let search: Option<String> = None;
        let search_pattern = search.as_ref().map(|s| format!("%{}%", s));
        assert!(search_pattern.is_none());
    }

    // -----------------------------------------------------------------------
    // Sort order parsing
    // -----------------------------------------------------------------------

    #[test]
    fn test_sort_order_parsing() {
        assert!(Some("desc".to_string()).as_deref() == Some("desc"));
        assert!(Some("asc".to_string()).as_deref() != Some("desc"));
        assert!(None::<String>.as_deref() != Some("desc"));
    }

    #[test]
    fn test_sort_order_clause() {
        for (sort_by, desc, expected) in [
            (None, true, "ORDER BY build_number DESC NULLS LAST, id DESC"),
            (None, false, "ORDER BY build_number ASC NULLS LAST, id ASC"),
            (
                Some("created_at"),
                true,
                "ORDER BY created_at DESC NULLS LAST, id DESC",
            ),
            (
                Some("started_at"),
                false,
                "ORDER BY started_at ASC NULLS LAST, id ASC",
            ),
            (
                Some("finished_at"),
                false,
                "ORDER BY finished_at ASC NULLS LAST, id ASC",
            ),
            (
                Some("duration"),
                true,
                "ORDER BY duration_ms DESC NULLS LAST, id DESC",
            ),
            (
                Some("duration_ms"),
                false,
                "ORDER BY duration_ms ASC NULLS LAST, id ASC",
            ),
            (Some("name"), false, "ORDER BY name ASC NULLS LAST, id ASC"),
            (
                Some("status"),
                true,
                "ORDER BY status DESC NULLS LAST, id DESC",
            ),
            (
                Some("name; DROP TABLE builds"),
                true,
                "ORDER BY build_number DESC NULLS LAST, id DESC",
            ),
            (
                Some("metadata"),
                false,
                "ORDER BY build_number ASC NULLS LAST, id ASC",
            ),
        ] {
            assert_eq!(list_order_clause(sort_by, desc), expected, "{sort_by:?}");
        }
    }

    fn stored_artifact(build_id: Uuid, module: Option<&str>, path: &str) -> StoredBuildArtifact {
        StoredBuildArtifact {
            id: Uuid::new_v4(),
            build_id,
            module_name: module.map(str::to_string),
            name: path.rsplit('/').next().unwrap_or(path).to_string(),
            path: path.to_string(),
            checksum_sha256: "0".repeat(64),
            size_bytes: 1,
            created_at: Utc::now(),
        }
    }

    #[test]
    fn test_group_into_modules_keeps_every_artifact_in_first_seen_order() {
        let build_id = Uuid::new_v4();
        let rows = vec![
            stored_artifact(build_id, Some("app"), "dist/a.jar"),
            stored_artifact(build_id, None, "dist/notes.txt"),
            stored_artifact(build_id, Some("app"), "dist/b.jar"),
            stored_artifact(build_id, Some("lib"), "dist/c.jar"),
        ];
        let first_app_id = rows[0].id;
        let modules = group_into_modules(rows);
        let names: Vec<&str> = modules.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, ["app", "", "lib"]);
        assert_eq!(modules[0].id, first_app_id);
        let app: Vec<&str> = modules[0]
            .artifacts
            .iter()
            .map(|a| a.path.as_str())
            .collect();
        assert_eq!(app, ["dist/a.jar", "dist/b.jar"]);
        assert_eq!(modules[1].artifacts[0].path, "dist/notes.txt");
        assert!(group_into_modules(vec![]).is_empty());
    }

    /// #6240: one module per name however many artifacts share it, without
    /// a scan of the module list per artifact.
    #[test]
    fn test_group_into_modules_many_artifacts() {
        let build_id = Uuid::new_v4();
        let rows: Vec<_> = (0..5000)
            .map(|i| stored_artifact(build_id, Some(&format!("m{}", i % 500)), &format!("d/{i}")))
            .collect();
        let modules = group_into_modules(rows);
        assert_eq!(modules.len(), 500);
        assert!(modules.iter().all(|m| m.artifacts.len() == 10));
    }

    #[test]
    fn test_strip_vcs_userinfo() {
        use UserinfoRules::{Read, Write};
        // (raw, on write, on read)
        for (raw, write, read) in [
            // Plain credentials, and a CI token as the password.
            ("https://user:pass@host", "https://host", "https://host"),
            (
                "https://x-access-token:ghs_SECRET@github.com/org/private",
                "https://github.com/org/private",
                "https://github.com/org/private",
            ),
            // Percent-encoded userinfo.
            (
                "https://user:p%40ss%2Fword@git.example.test/r",
                "https://git.example.test/r",
                "https://git.example.test/r",
            ),
            // A password with an unencoded `/` and `@` still goes entirely.
            (
                "https://ci:pa/ss@word@git.example.test/r",
                "https://git.example.test/r",
                "https://git.example.test/r",
            ),
            // A password-less token, and one with an `@` in the path too.
            (
                "https://token@github.com/org/repo.git",
                "https://github.com/org/repo.git",
                "https://github.com/org/repo.git",
            ),
            (
                "https://ghp_TOKEN@github.com/org/repo@v1",
                "https://github.com/org/repo@v1",
                "https://github.com/org/repo@v1",
            ),
            // ssh with a login name and a port, `@` in the path kept.
            (
                "ssh://git@h:22/r@tag",
                "ssh://h:22/r@tag",
                "ssh://h:22/r@tag",
            ),
            (
                "ssh://git:pw@host:2222/org/repo",
                "ssh://host:2222/org/repo",
                "ssh://host:2222/org/repo",
            ),
            // No userinfo: port plus `@` in the path or query, IPv6, plain.
            (
                "https://h:8443/r?ref=a@b",
                "https://h:8443/r?ref=a@b",
                "https://h:8443/r?ref=a@b",
            ),
            (
                "https://[::1]/r@v1",
                "https://[::1]/r@v1",
                "https://[::1]/r@v1",
            ),
            ("https://u:p@[::1]/r", "https://[::1]/r", "https://[::1]/r"),
            (
                "https://github.com/org/repo@v1",
                "https://github.com/org/repo@v1",
                "https://github.com/org/repo@v1",
            ),
            (
                "https://github.com/org/repo",
                "https://github.com/org/repo",
                "https://github.com/org/repo",
            ),
            (
                "https://localhost/r@v1",
                "https://localhost/r@v1",
                "https://localhost/r@v1",
            ),
            // `head` ends at `?` and `#` too.
            (
                "https://git.example.test?x=a@b",
                "https://git.example.test?x=a@b",
                "https://git.example.test?x=a@b",
            ),
            (
                "https://git.example.test#a@b",
                "https://git.example.test#a@b",
                "https://git.example.test#a@b",
            ),
            ("https://u:p?w@host/r", "https://host/r", "https://host/r"),
            // Rule 5 is read-only: a single-label host or a password-less
            // base64 token with `/` is stored whole and read back cut.
            ("https://host?x=a@b", "https://host?x=a@b", "https://b"),
            (
                "https://gitlab/org/repo@v1",
                "https://gitlab/org/repo@v1",
                "https://v1",
            ),
            (
                "https://ab/cd==@host/r",
                "https://ab/cd==@host/r",
                "https://host/r",
            ),
            // scp-style: a login name, never a password.
            (
                "git@github.com:org/repo.git",
                "git@github.com:org/repo.git",
                "git@github.com:org/repo.git",
            ),
            ("", "", ""),
        ] {
            assert_eq!(strip_vcs_userinfo(raw, Write), write, "write {raw}");
            assert_eq!(strip_vcs_userinfo(raw, Read), read, "read {raw}");
            // Reading what was written gives what reading the raw value gives.
            assert_eq!(strip_vcs_userinfo(write, Read), read, "read(write) {raw}");
        }
    }

    #[test]
    fn test_artifact_repo_key() {
        assert_eq!(
            artifact_repo_key("libs-release/com/x.jar"),
            Some("libs-release")
        );
        assert_eq!(
            artifact_repo_key("/libs-release/x.jar"),
            Some("libs-release")
        );
        assert_eq!(artifact_repo_key("x.jar"), Some("x.jar"));
        assert_eq!(artifact_repo_key(""), None);
        assert_eq!(artifact_repo_key("/"), None);
    }

    // -----------------------------------------------------------------------
    // BuildRow -> BuildResponse conversion
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_row_to_response() {
        let now = Utc::now();
        let id = Uuid::new_v4();
        let row = BuildRow {
            id,
            name: "my-project".to_string(),
            build_number: 42,
            status: "success".to_string(),
            started_at: Some(now),
            finished_at: Some(now),
            duration_ms: Some(30000),
            agent: Some("agent-1".to_string()),
            created_at: now,
            updated_at: now,
            artifact_count: Some(5),
        };
        let resp = BuildResponse::from(row);
        assert_eq!(resp.id, id);
        assert_eq!(resp.name, "my-project");
        assert_eq!(resp.number, 42);
        assert_eq!(resp.status, "success");
        assert_eq!(resp.duration_ms, Some(30000));
        assert_eq!(resp.agent.as_deref(), Some("agent-1"));
        assert_eq!(resp.artifact_count, Some(5));
        // BuildRow doesn't carry these fields
        assert!(resp.modules.is_none());
        assert!(resp.vcs_url.is_none());
        assert!(resp.vcs_revision.is_none());
        assert!(resp.vcs_branch.is_none());
        assert!(resp.vcs_message.is_none());
        assert!(resp.metadata.is_none());
    }

    #[test]
    fn test_build_row_to_response_minimal() {
        let now = Utc::now();
        let row = BuildRow {
            id: Uuid::nil(),
            name: "test".to_string(),
            build_number: 1,
            status: "running".to_string(),
            started_at: None,
            finished_at: None,
            duration_ms: None,
            agent: None,
            created_at: now,
            updated_at: now,
            artifact_count: None,
        };
        let resp = BuildResponse::from(row);
        assert_eq!(resp.number, 1);
        assert!(resp.started_at.is_none());
        assert!(resp.finished_at.is_none());
        assert!(resp.duration_ms.is_none());
        assert!(resp.agent.is_none());
        assert!(resp.artifact_count.is_none());
    }

    // -----------------------------------------------------------------------
    // Build (service model) -> BuildResponse conversion
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_service_model_to_response() {
        let now = Utc::now();
        let id = Uuid::new_v4();
        let build = crate::services::build_service::Build {
            id,
            name: "my-app".to_string(),
            build_number: 100,
            status: "failed".to_string(),
            started_at: Some(now),
            finished_at: Some(now),
            duration_ms: Some(60000),
            agent: Some("ci-runner".to_string()),
            artifact_count: Some(3),
            // #6240: a stored URL with credentials reads back without them.
            vcs_url: Some("https://user:secret@github.com/org/repo".to_string()),
            vcs_revision: Some("abc123".to_string()),
            vcs_branch: Some("main".to_string()),
            vcs_message: Some("fix: bug".to_string()),
            metadata: Some(json!({"ci": "github-actions"})),
            created_at: now,
            updated_at: now,
        };
        let resp = BuildResponse::from(build);
        assert_eq!(resp.id, id);
        assert_eq!(resp.name, "my-app");
        assert_eq!(resp.number, 100);
        assert_eq!(resp.status, "failed");
        assert_eq!(resp.vcs_url.as_deref(), Some("https://github.com/org/repo"));
        assert_eq!(resp.vcs_revision.as_deref(), Some("abc123"));
        assert_eq!(resp.vcs_branch.as_deref(), Some("main"));
        assert_eq!(resp.vcs_message.as_deref(), Some("fix: bug"));
        assert!(resp.metadata.is_some());
        assert!(resp.modules.is_none()); // Never set in From impl
    }

    // -----------------------------------------------------------------------
    // BuildResponse serialization (skip_serializing_if)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_response_serialize_skips_none_vcs() {
        let now = Utc::now();
        let resp = BuildResponse {
            id: Uuid::nil(),
            name: "test".to_string(),
            number: 1,
            status: "running".to_string(),
            started_at: None,
            finished_at: None,
            duration_ms: None,
            agent: None,
            created_at: now,
            updated_at: now,
            artifact_count: None,
            modules: None,
            vcs_url: None,
            vcs_revision: None,
            vcs_branch: None,
            vcs_message: None,
            metadata: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        // skip_serializing_if fields should not be present
        assert!(json.get("vcs_url").is_none());
        assert!(json.get("vcs_revision").is_none());
        assert!(json.get("vcs_branch").is_none());
        assert!(json.get("vcs_message").is_none());
        assert!(json.get("metadata").is_none());
    }

    #[test]
    fn test_build_response_serialize_includes_vcs() {
        let now = Utc::now();
        let resp = BuildResponse {
            id: Uuid::nil(),
            name: "test".to_string(),
            number: 1,
            status: "success".to_string(),
            started_at: None,
            finished_at: None,
            duration_ms: None,
            agent: None,
            created_at: now,
            updated_at: now,
            artifact_count: None,
            modules: None,
            vcs_url: Some("https://github.com/test".to_string()),
            vcs_revision: Some("deadbeef".to_string()),
            vcs_branch: Some("feat/new".to_string()),
            vcs_message: Some("feat: new feature".to_string()),
            metadata: Some(json!({"key": "value"})),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["vcs_url"], "https://github.com/test");
        assert_eq!(json["vcs_revision"], "deadbeef");
        assert_eq!(json["vcs_branch"], "feat/new");
        assert_eq!(json["vcs_message"], "feat: new feature");
        assert_eq!(json["metadata"]["key"], "value");
    }

    // -----------------------------------------------------------------------
    // CreateBuildRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_build_request_deserialize_minimal() {
        let json = json!({"name": "my-build", "build_number": 1});
        let req: CreateBuildRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.name, "my-build");
        assert_eq!(req.build_number, 1);
        assert!(req.agent.is_none());
        assert!(req.started_at.is_none());
        assert!(req.vcs_url.is_none());
        assert!(req.metadata.is_none());
    }

    #[test]
    fn test_create_build_request_deserialize_full() {
        let now = Utc::now();
        let json = json!({
            "name": "release-build",
            "build_number": 42,
            "agent": "jenkins-1",
            "started_at": now.to_rfc3339(),
            "vcs_url": "https://github.com/org/repo",
            "vcs_revision": "abc123",
            "vcs_branch": "main",
            "vcs_message": "release v1.0",
            "metadata": {"ci": "jenkins"}
        });
        let req: CreateBuildRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.name, "release-build");
        assert_eq!(req.build_number, 42);
        assert_eq!(req.agent.as_deref(), Some("jenkins-1"));
        assert_eq!(req.vcs_url.as_deref(), Some("https://github.com/org/repo"));
        assert!(req.metadata.is_some());
    }

    // -----------------------------------------------------------------------
    // UpdateBuildRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_update_build_request_deserialize() {
        let json = json!({"status": "success"});
        let req: UpdateBuildRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.status, "success");
        assert!(req.finished_at.is_none());
    }

    #[test]
    fn test_update_build_request_with_finished_at() {
        let now = Utc::now();
        let json = json!({"status": "failed", "finished_at": now.to_rfc3339()});
        let req: UpdateBuildRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.status, "failed");
        assert!(req.finished_at.is_some());
    }

    // -----------------------------------------------------------------------
    // BuildDiffQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_diff_query_deserialize() {
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();
        let json = json!({"build_a": id_a, "build_b": id_b});
        let query: BuildDiffQuery = serde_json::from_value(json).unwrap();
        assert_eq!(query.build_a, id_a);
        assert_eq!(query.build_b, id_b);
    }

    // -----------------------------------------------------------------------
    // AddBuildArtifactsRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_add_build_artifacts_request_deserialize() {
        let json = json!({
            "artifacts": [
                {
                    "module_name": "core",
                    "name": "core.jar",
                    "path": "/com/example/core/1.0/core-1.0.jar",
                    "checksum_sha256": "abc123",
                    "size_bytes": 1024
                },
                {
                    "name": "api.jar",
                    "path": "/com/example/api/1.0/api-1.0.jar",
                    "checksum_sha256": "def456",
                    "size_bytes": 2048
                }
            ]
        });
        let req: AddBuildArtifactsRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.artifacts.len(), 2);
        assert_eq!(req.artifacts[0].module_name.as_deref(), Some("core"));
        assert!(req.artifacts[1].module_name.is_none());
        assert_eq!(req.artifacts[0].size_bytes, 1024);
        assert_eq!(req.artifacts[1].size_bytes, 2048);
    }

    // -----------------------------------------------------------------------
    // BuildArtifactDiff serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_artifact_diff_serialize() {
        let diff = BuildArtifactDiff {
            name: "app.jar".to_string(),
            path: "/com/example/app.jar".to_string(),
            old_checksum: "aaa".to_string(),
            new_checksum: "bbb".to_string(),
            old_size_bytes: 1000,
            new_size_bytes: 1500,
        };
        let json = serde_json::to_value(&diff).unwrap();
        assert_eq!(json["name"], "app.jar");
        assert_eq!(json["old_checksum"], "aaa");
        assert_eq!(json["new_checksum"], "bbb");
        assert_eq!(json["old_size_bytes"], 1000);
        assert_eq!(json["new_size_bytes"], 1500);
    }

    // -----------------------------------------------------------------------
    // BuildDiffResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_diff_response_empty() {
        let id_a = Uuid::new_v4();
        let id_b = Uuid::new_v4();
        let resp = BuildDiffResponse {
            build_a: id_a,
            build_b: id_b,
            added: vec![],
            removed: vec![],
            modified: vec![],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["build_a"], id_a.to_string());
        assert_eq!(json["build_b"], id_b.to_string());
        assert_eq!(json["added"].as_array().unwrap().len(), 0);
        assert_eq!(json["removed"].as_array().unwrap().len(), 0);
        assert_eq!(json["modified"].as_array().unwrap().len(), 0);
    }

    // -----------------------------------------------------------------------
    // Total pages calculation
    // -----------------------------------------------------------------------

    #[test]
    fn test_builds_total_pages_calculation() {
        let total: i64 = 55;
        let per_page: u32 = 20;
        let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
        assert_eq!(total_pages, 3);
    }

    #[test]
    fn build_mutation_allowed_is_owner_or_admin() {
        let (me, other) = (Uuid::new_v4(), Uuid::new_v4());
        assert!(build_mutation_allowed(false, me, Some(me)));
        assert!(!build_mutation_allowed(false, me, Some(other)));
        assert!(!build_mutation_allowed(false, me, None));
        assert!(build_mutation_allowed(true, me, Some(other)));
        assert!(build_mutation_allowed(true, me, None));
    }

    /// GHSA-mvmh-g8wm-r3cp #7: a build record belongs to the principal that
    /// created it. Another signed-in user used to be able to change its
    /// status and attach artifacts to it (authentication was the only
    /// check). Now only the creator or an administrator may, a build
    /// created before ownership was recorded is administrator-only, and a
    /// token needs `write:artifacts` to create or change one.
    #[tokio::test]
    async fn build_mutations_are_owner_or_admin_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let state = tdh::build_state(pool.clone(), "/tmp/ph-mvmh-builds");
        let (owner_id, owner_name) = tdh::create_user(&pool).await;
        let (other_id, other_name) = tdh::create_user(&pool).await;
        let owner = tdh::make_auth(owner_id, &owner_name);
        let other = tdh::make_auth(other_id, &other_name);
        let admin = tdh::admin_auth(other_id, &other_name);
        let create = |auth: AuthExtension| {
            create_build(
                State(state.clone()),
                Extension(Some(auth)),
                Json(CreateBuildRequest {
                    name: "ph-mvmh-build".to_string(),
                    build_number: 1,
                    agent: None,
                    started_at: None,
                    vcs_url: None,
                    vcs_revision: None,
                    vcs_branch: None,
                    vcs_message: None,
                    metadata: None,
                }),
            )
        };
        let update = |auth: AuthExtension, id: Uuid| {
            update_build(
                State(state.clone()),
                Extension(Some(auth)),
                Path(id),
                Json(UpdateBuildRequest {
                    status: "failed".to_string(),
                    finished_at: None,
                }),
            )
        };
        let attach = |auth: AuthExtension, id: Uuid| {
            add_build_artifacts(
                State(state.clone()),
                Extension(Some(auth)),
                Path(id),
                Json(AddBuildArtifactsRequest {
                    artifacts: vec![BuildArtifactInputPayload {
                        module_name: None,
                        name: "forged.bin".to_string(),
                        path: "forged.bin".to_string(),
                        checksum_sha256: "0".repeat(64),
                        size_bytes: 1,
                    }],
                }),
            )
        };
        let status_of = |id: Uuid| {
            let pool = pool.clone();
            async move {
                sqlx::query_scalar::<_, String>("SELECT status FROM builds WHERE id = $1")
                    .bind(id)
                    .fetch_one(&pool)
                    .await
                    .expect("build status")
            }
        };
        let forbidden = |e: Option<AppError>| matches!(e, Some(AppError::Authorization(_)));

        let Json(build) = create(owner.clone()).await.expect("owner creates");

        // Another user: refused, and the record is untouched.
        assert!(forbidden(update(other.clone(), build.id).await.err()));
        assert!(forbidden(attach(other.clone(), build.id).await.err()));
        assert_eq!(status_of(build.id).await, "running");

        // A read-only token of the owner: refused at the scope gate.
        let read_token = AuthExtension {
            is_api_token: true,
            scopes: Some(vec!["read:artifacts".to_string()]),
            ..owner.clone()
        };
        assert!(forbidden(update(read_token.clone(), build.id).await.err()));
        assert!(forbidden(create(read_token).await.err()));

        // The owner and an administrator: allowed.
        update(owner.clone(), build.id)
            .await
            .expect("owner updates");
        attach(owner.clone(), build.id)
            .await
            .expect("owner attaches");
        update(admin.clone(), build.id)
            .await
            .expect("admin updates");

        // A build with no recorded creator (created before this change).
        let legacy: Uuid = sqlx::query_scalar(
            "INSERT INTO builds (name, build_number, status) \
             VALUES ('ph-mvmh-legacy', 1, 'running') RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .expect("legacy build");
        assert!(forbidden(update(owner.clone(), legacy).await.err()));
        update(admin, legacy)
            .await
            .expect("admin updates a legacy build");

        let _ = sqlx::query("DELETE FROM builds WHERE id = ANY($1)")
            .bind(vec![build.id, legacy])
            .execute(&pool)
            .await;
        tdh::cleanup_user(&pool, owner_id).await;
        tdh::cleanup_user(&pool, other_id).await;
    }

    fn post_json(uri: &str, body: serde_json::Value) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(body.to_string()))
            .unwrap()
    }

    async fn send_json(
        app: axum::Router,
        req: axum::http::Request<axum::body::Body>,
    ) -> serde_json::Value {
        use crate::api::handlers::test_db_helpers as tdh;
        let (status, bytes) = tdh::send(app, req).await;
        assert_eq!(
            status,
            axum::http::StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&bytes)
        );
        serde_json::from_slice(&bytes).expect("json body")
    }

    fn artifact_paths(build: &serde_json::Value) -> Vec<String> {
        let mut paths: Vec<String> = build["modules"]
            .as_array()
            .expect("modules")
            .iter()
            .flat_map(|m| m["artifacts"].as_array().expect("artifacts").iter())
            .map(|a| a["path"].as_str().expect("path").to_string())
            .collect();
        paths.sort();
        paths
    }

    /// #6046 + #6240: the reads return the VCS fields, metadata and attached
    /// artifacts the writes store, but `metadata` and the VCS fields only to
    /// the build's creator or an administrator, `vcs_url` never with its
    /// credentials (stripped on create, and on read for older rows), and the
    /// artifact paths of another user's build only where they name a
    /// repository the caller can read. #6048 returned all of it to any
    /// signed-in caller, a `read:artifacts` token included.
    #[tokio::test]
    async fn build_reads_are_owner_gated_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let state = tdh::build_state(pool.clone(), "/tmp/ph-6240-builds");
        let (owner_id, owner_name) = tdh::create_user(&pool).await;
        let (other_id, other_name) = tdh::create_user(&pool).await;
        let (admin_id, admin_name) = tdh::create_user(&pool).await;
        let (open_repo, open_key, _) = tdh::create_repo(&pool, "local", "generic").await;
        let (hidden_repo, hidden_key, _) = tdh::create_repo(&pool, "local", "generic").await;
        tdh::grant_repo_role(&pool, open_repo, other_id, "reader").await;

        let owner = tdh::router_with_auth(
            super::router(),
            state.clone(),
            tdh::make_auth(owner_id, &owner_name),
        );
        // A different, non-admin user holding only a `read:artifacts` token.
        let other = tdh::router_with_auth(
            super::router(),
            state.clone(),
            AuthExtension {
                is_api_token: true,
                scopes: Some(vec!["read:artifacts".to_string()]),
                ..tdh::make_auth(other_id, &other_name)
            },
        );
        let admin = tdh::router_with_auth(
            super::router(),
            state.clone(),
            tdh::admin_auth(admin_id, &admin_name),
        );

        let name = format!("ph-6240-{}", Uuid::new_v4());
        let metadata = json!({ "env": { "NPM_TOKEN": "npm_SECRET6240" }, "runner": "linux" });
        let created = send_json(
            owner.clone(),
            post_json(
                "/",
                json!({
                    "name": name,
                    "build_number": 7,
                    "vcs_url": "https://x-access-token:ghs_SECRET6240@github.com/org/private",
                    "vcs_revision": "0123456789abcdef",
                    "vcs_branch": "main",
                    "vcs_message": "ph-6240 commit",
                    "metadata": metadata,
                }),
            ),
        )
        .await;
        let id = created["id"].as_str().expect("build id").to_string();
        assert_eq!(created["vcs_url"], "https://github.com/org/private");
        let stored: Option<String> =
            sqlx::query_scalar("SELECT vcs_url FROM builds WHERE id = $1::uuid")
                .bind(&id)
                .fetch_one(&pool)
                .await
                .expect("stored vcs_url");
        assert_eq!(
            stored.as_deref(),
            Some("https://github.com/org/private"),
            "credentials are stripped before the row is written"
        );

        let open_path = format!("{open_key}/com/org/app.jar");
        let hidden_path = format!("{hidden_key}/com/org/secret.jar");
        send_json(
            owner.clone(),
            post_json(
                &format!("/{id}/artifacts"),
                json!({ "artifacts": [
                    { "module_name": "app", "name": "app.jar", "path": open_path,
                      "checksum_sha256": "a".repeat(64), "size_bytes": 10 },
                    { "module_name": "app", "name": "secret.jar", "path": hidden_path,
                      "checksum_sha256": "b".repeat(64), "size_bytes": 20 },
                    { "name": "local.bin", "path": "dist/local.bin",
                      "checksum_sha256": "c".repeat(64), "size_bytes": 30 },
                ] }),
            ),
        )
        .await;
        // A row stored before create stripped credentials reads back without them.
        sqlx::query(
            "UPDATE builds SET vcs_url = 'https://u:legacy_SECRET@github.com/org/private' \
             WHERE id = $1::uuid",
        )
        .bind(&id)
        .execute(&pool)
        .await
        .expect("legacy vcs_url");

        let mut all = vec![
            open_path.clone(),
            hidden_path.clone(),
            "dist/local.bin".to_string(),
        ];
        all.sort();

        // The creator and an administrator see everything, minus credentials.
        for (who, app) in [("owner", &owner), ("admin", &admin)] {
            let got = send_json(app.clone(), tdh::get(format!("/{id}"))).await;
            assert_eq!(
                got["vcs_url"], "https://github.com/org/private",
                "{who}: {got}"
            );
            assert_eq!(got["vcs_revision"], "0123456789abcdef", "{who}");
            assert_eq!(got["vcs_branch"], "main", "{who}");
            assert_eq!(got["vcs_message"], "ph-6240 commit", "{who}");
            assert_eq!(got["metadata"], metadata, "{who}");
            assert_eq!(got["artifact_count"], 3, "{who}");
            assert_eq!(artifact_paths(&got), all, "{who}");

            let list = send_json(app.clone(), tdh::get(format!("/?search={name}"))).await;
            let items = list["items"].as_array().expect("items");
            assert_eq!(items.len(), 1, "{who}: {list}");
            assert_eq!(items[0]["metadata"], metadata, "{who}");
            assert_eq!(
                items[0]["vcs_url"], "https://github.com/org/private",
                "{who}"
            );
            assert_eq!(artifact_paths(&items[0]), all, "{who}");
        }

        // Anyone else: the build, without metadata or any VCS field, and
        // only the artifact in the repository it can read.
        let got = send_json(other.clone(), tdh::get(format!("/{id}"))).await;
        let list = send_json(other.clone(), tdh::get(format!("/?search={name}"))).await;
        let items = list["items"].as_array().expect("items");
        assert_eq!(items.len(), 1, "{list}");
        for b in [&got, &items[0]] {
            assert!(b.get("metadata").is_none(), "{b}");
            for field in ["vcs_url", "vcs_revision", "vcs_branch", "vcs_message"] {
                assert!(b.get(field).is_none(), "{field}: {b}");
            }
            assert_eq!(artifact_paths(b), std::slice::from_ref(&open_path), "{b}");
            let text = b.to_string();
            for secret in [
                "SECRET6240",
                "legacy_SECRET",
                hidden_key.as_str(),
                "dist/local.bin",
            ] {
                assert!(!text.contains(secret), "{secret} leaked: {text}");
            }
        }

        let _ = sqlx::query("DELETE FROM builds WHERE name = $1")
            .bind(&name)
            .execute(&pool)
            .await;
        tdh::cleanup(&pool, open_repo, other_id).await;
        tdh::cleanup(&pool, hidden_repo, owner_id).await;
        tdh::cleanup_user(&pool, admin_id).await;
    }

    /// #6240 review: the write keeps a URL whose userinfo is ambiguous (a
    /// single-label host with an `@` in the path) whole, since a cut there is
    /// unrecoverable, and the read applies the strict rules to it.
    #[tokio::test]
    async fn ambiguous_vcs_url_is_stored_whole_and_read_strict_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let state = tdh::build_state(pool.clone(), "/tmp/ph-6240-ambiguous");
        let (user_id, username) = tdh::create_user(&pool).await;
        let app = tdh::router_with_auth(super::router(), state, tdh::make_auth(user_id, &username));
        let name = format!("ph-6240-amb-{}", Uuid::new_v4());
        let raw = "https://gitlab/org/repo@v1";
        let created = send_json(
            app.clone(),
            post_json(
                "/",
                json!({ "name": name, "build_number": 1, "vcs_url": raw }),
            ),
        )
        .await;
        let id = created["id"].as_str().expect("build id").to_string();
        let stored: Option<String> =
            sqlx::query_scalar("SELECT vcs_url FROM builds WHERE id = $1::uuid")
                .bind(&id)
                .fetch_one(&pool)
                .await
                .expect("stored vcs_url");
        assert_eq!(stored.as_deref(), Some(raw), "nothing is lost in storage");
        let read = strip_vcs_userinfo(raw, UserinfoRules::Read);
        assert_eq!(created["vcs_url"], read.as_str());
        let got = send_json(app, tdh::get(format!("/{id}"))).await;
        assert_eq!(got["vcs_url"], read.as_str(), "{got}");

        let _ = sqlx::query("DELETE FROM builds WHERE name = $1")
            .bind(&name)
            .execute(&pool)
            .await;
        tdh::cleanup_user(&pool, user_id).await;
    }

    /// #6240: the artifacts a read returns per build are capped.
    #[tokio::test]
    async fn build_reads_cap_artifacts_per_build_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, _) = tdh::create_user(&pool).await;
        let name = format!("ph-6240-cap-{}", Uuid::new_v4());
        let build_id: Uuid = sqlx::query_scalar(
            "INSERT INTO builds (name, build_number, status, created_by) \
             VALUES ($1, 1, 'running', $2) RETURNING id",
        )
        .bind(&name)
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .expect("build");
        sqlx::query(
            "INSERT INTO build_artifacts (build_id, name, path, checksum_sha256) \
             SELECT $1, 'a' || g, 'dist/a' || g, repeat('0', 64) FROM generate_series(1, 60) g",
        )
        .bind(build_id)
        .execute(&pool)
        .await
        .expect("artifacts");
        let service = BuildService::new(pool.clone());
        let rows = service
            .list_artifacts(&[build_id], MAX_ARTIFACTS_PER_LISTED_BUILD)
            .await
            .expect("list");
        assert_eq!(rows.len() as i64, MAX_ARTIFACTS_PER_LISTED_BUILD);
        let rows = service
            .list_artifacts(&[build_id], MAX_ARTIFACTS_PER_BUILD)
            .await
            .expect("list");
        assert_eq!(rows.len(), 60);
        assert!(rows
            .windows(2)
            .all(|w| (w[0].created_at, w[0].id) <= (w[1].created_at, w[1].id)));

        let _ = sqlx::query("DELETE FROM builds WHERE id = $1")
            .bind(build_id)
            .execute(&pool)
            .await;
        tdh::cleanup_user(&pool, user_id).await;
    }

    #[test]
    fn partition_bulk_delete_keeps_order_and_reports_each_refusal() {
        let (me, other) = (Uuid::new_v4(), Uuid::new_v4());
        let (mine, theirs, legacy, unknown) = (
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        let owners = std::collections::HashMap::from([
            (mine, Some(me)),
            (theirs, Some(other)),
            (legacy, None),
        ]);
        let ids = [unknown, mine, theirs, legacy];
        let (allowed, failed) = partition_bulk_delete(&ids, &owners, false, me);
        assert_eq!(allowed, [mine]);
        let failure = |id, reason: &str| DeleteBuildFailure {
            id,
            reason: reason.to_string(),
        };
        assert_eq!(
            failed,
            [
                failure(unknown, "not_found"),
                failure(theirs, "forbidden"),
                failure(legacy, "forbidden"),
            ]
        );
        let (allowed, failed) = partition_bulk_delete(&ids, &owners, true, me);
        assert_eq!(allowed, [mine, theirs, legacy]);
        assert_eq!(failed, [failure(unknown, "not_found")]);
    }

    fn delete_req(uri: &str) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .method("DELETE")
            .uri(uri)
            .body(axum::body::Body::empty())
            .unwrap()
    }

    /// web#618: builds could not be deleted at all, no route answered
    /// DELETE. A build goes with its artifact list, only its creator or an
    /// administrator may delete it, a token needs `delete:artifacts`, and a
    /// bulk delete reports foreign and unknown ids without stopping
    #[tokio::test]
    async fn build_delete_single_and_bulk_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::http::StatusCode;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let state = tdh::build_state(pool.clone(), "/tmp/ph-618-delete");
        let (owner_id, owner_name) = tdh::create_user(&pool).await;
        let (other_id, other_name) = tdh::create_user(&pool).await;
        let owner = tdh::make_auth(owner_id, &owner_name);
        let app = |auth: AuthExtension| tdh::router_with_auth(super::router(), state.clone(), auth);
        let as_owner = app(owner.clone());
        let as_other = app(tdh::make_auth(other_id, &other_name));
        let as_admin = app(tdh::admin_auth(other_id, &other_name));
        let write_token = app(AuthExtension {
            is_api_token: true,
            scopes: Some(vec!["write:artifacts".to_string()]),
            ..owner.clone()
        });
        let prefix = format!("ph-618-del-{}", Uuid::new_v4());

        let create = |app: axum::Router, n: i32| {
            let name = format!("{prefix}-{n}");
            async move {
                let b = send_json(
                    app,
                    post_json("/", json!({ "name": name, "build_number": n })),
                )
                .await;
                Uuid::parse_str(b["id"].as_str().expect("id")).expect("uuid")
            }
        };
        let exists = |id: Uuid| {
            let pool = pool.clone();
            async move {
                sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM builds WHERE id = $1)")
                    .bind(id)
                    .fetch_one(&pool)
                    .await
                    .expect("exists")
            }
        };

        let first = create(as_owner.clone(), 1).await;
        let second = create(as_owner.clone(), 2).await;
        let foreign = create(as_other.clone(), 3).await;
        send_json(
            as_owner.clone(),
            post_json(
                &format!("/{first}/artifacts"),
                json!({ "artifacts": [{ "name": "a.jar", "path": "dist/a.jar",
                    "checksum_sha256": "a".repeat(64), "size_bytes": 1 }] }),
            ),
        )
        .await;

        // Another user and a token without delete:artifacts are refused
        let (status, _) = tdh::send(as_other.clone(), delete_req(&format!("/{first}"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) = tdh::send(write_token.clone(), delete_req(&format!("/{first}"))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _) =
            tdh::send(write_token, post_json("/delete", json!({ "ids": [first] }))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(exists(first).await);

        // The owner deletes it, its artifact list goes with it
        let (status, body) = tdh::send(as_owner.clone(), delete_req(&format!("/{first}"))).await;
        assert_eq!(
            status,
            StatusCode::NO_CONTENT,
            "{}",
            String::from_utf8_lossy(&body)
        );
        assert!(!exists(first).await);
        let rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM build_artifacts WHERE build_id = $1")
                .bind(first)
                .fetch_one(&pool)
                .await
                .expect("count");
        assert_eq!(rows, 0);
        let (status, _) = tdh::send(as_owner.clone(), tdh::get(format!("/{first}"))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let (status, _) = tdh::send(as_owner.clone(), delete_req(&format!("/{first}"))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let audit = tdh::audit_row_eventually(&pool, first, "BUILD_DELETED").await;
        assert_eq!(audit.user_id, Some(owner_id));
        assert_eq!(audit.resource_type, "build");
        assert_eq!(audit.details["build_number"], 1);
        assert_eq!(audit.details["bulk"], false);

        // Bulk: own, foreign, unknown and a duplicate in one call
        let unknown = Uuid::new_v4();
        let got = send_json(
            as_owner.clone(),
            post_json(
                "/delete",
                json!({ "ids": [second, foreign, unknown, second] }),
            ),
        )
        .await;
        assert_eq!(got["deleted"], json!([second]));
        assert_eq!(
            got["failed"],
            json!([
                { "id": foreign, "reason": "forbidden" },
                { "id": unknown, "reason": "not_found" },
            ])
        );
        assert!(!exists(second).await);
        assert!(exists(foreign).await);
        assert_eq!(
            tdh::audit_row_eventually(&pool, second, "BUILD_DELETED")
                .await
                .details["bulk"],
            true
        );

        // Empty and oversized requests are refused whole
        let (status, _) =
            tdh::send(as_owner.clone(), post_json("/delete", json!({ "ids": [] }))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let too_many: Vec<Uuid> = (0..=MAX_BULK_DELETE).map(|_| Uuid::new_v4()).collect();
        let (status, _) =
            tdh::send(as_owner, post_json("/delete", json!({ "ids": too_many }))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // An administrator deletes any build, one without a creator included
        let legacy: Uuid = sqlx::query_scalar(
            "INSERT INTO builds (name, build_number, status) VALUES ($1, 9, 'running') RETURNING id",
        )
        .bind(format!("{prefix}-legacy"))
        .fetch_one(&pool)
        .await
        .expect("legacy build");
        let got = send_json(
            as_admin,
            post_json("/delete", json!({ "ids": [foreign, legacy] })),
        )
        .await;
        assert_eq!(got["deleted"], json!([foreign, legacy]));
        assert_eq!(got["failed"], json!([]));

        let _ = sqlx::query("DELETE FROM builds WHERE name LIKE $1")
            .bind(format!("{prefix}-%"))
            .execute(&pool)
            .await;
        tdh::cleanup_user(&pool, owner_id).await;
        tdh::cleanup_user(&pool, other_id).await;
    }

    /// web#618: the list only filtered by status and a name substring. It now
    /// takes an exact name, branch and agent and a creation time range, and
    /// the total counts the same rows
    #[tokio::test]
    async fn list_builds_filters_by_name_branch_agent_and_time_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let state = tdh::build_state(pool.clone(), "/tmp/ph-618-filter");
        let (user_id, username) = tdh::create_user(&pool).await;
        let app = tdh::router_with_auth(super::router(), state, tdh::make_auth(user_id, &username));
        let p = format!("ph-618-filter-{}", Uuid::new_v4());
        let (app_name, lib_name) = (format!("{p}-app"), format!("{p}-app-lib"));

        // number, name, branch, agent, created hours ago
        for (number, name, branch, agent, hours) in [
            (1, &app_name, "main", "runner-a", 50),
            (2, &app_name, "feat/x", "runner-b", 26),
            (3, &app_name, "main", "runner-b", 2),
            (4, &lib_name, "main", "runner-a", 1),
        ] {
            let b = send_json(
                app.clone(),
                post_json(
                    "/",
                    json!({ "name": name, "build_number": number,
                            "vcs_branch": branch, "agent": agent }),
                ),
            )
            .await;
            sqlx::query(
                "UPDATE builds SET created_at = NOW() - make_interval(hours => $2) WHERE id = $1",
            )
            .bind(Uuid::parse_str(b["id"].as_str().expect("id")).expect("uuid"))
            .bind(hours)
            .execute(&pool)
            .await
            .expect("backdate");
        }

        let after = (Utc::now() - chrono::Duration::hours(30)).format("%Y-%m-%dT%H:%M:%SZ");
        let before = (Utc::now() - chrono::Duration::hours(3)).format("%Y-%m-%dT%H:%M:%SZ");
        let numbers = |filter: String| {
            let app = app.clone();
            let p = p.clone();
            async move {
                let list = send_json(
                    app,
                    tdh::get(format!("/?search={p}&sort_by=build_number&{filter}")),
                )
                .await;
                let items: Vec<i64> = list["items"]
                    .as_array()
                    .expect("items")
                    .iter()
                    .map(|b| b["number"].as_i64().expect("number"))
                    .collect();
                assert_eq!(list["pagination"]["total"], items.len(), "{list}");
                items
            }
        };

        assert_eq!(numbers(String::new()).await, [1, 2, 3, 4]);
        assert_eq!(numbers(format!("name={app_name}")).await, [1, 2, 3]);
        assert_eq!(numbers("branch=main".to_string()).await, [1, 3, 4]);
        assert_eq!(numbers("branch=feat%2Fx".to_string()).await, [2]);
        assert_eq!(numbers("agent=runner-b".to_string()).await, [2, 3]);
        assert_eq!(numbers(format!("created_after={after}")).await, [2, 3, 4]);
        assert_eq!(numbers(format!("created_before={before}")).await, [1, 2]);
        assert_eq!(
            numbers(format!("name={app_name}&branch=main&created_after={after}")).await,
            [3]
        );
        assert!(numbers("name=nope".to_string()).await.is_empty());

        let _ = sqlx::query("DELETE FROM builds WHERE name LIKE $1")
            .bind(format!("{p}-%"))
            .execute(&pool)
            .await;
        tdh::cleanup_user(&pool, user_id).await;
    }

    /// #6046: the list parsed `sort_by` and always ordered by build number.
    #[tokio::test]
    async fn list_builds_honours_sort_by_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let state = tdh::build_state(pool.clone(), "/tmp/ph-6046-sort");
        let (user_id, username) = tdh::create_user(&pool).await;
        let app = tdh::router_with_auth(super::router(), state, tdh::make_auth(user_id, &username));
        let prefix = format!("ph-6046-sort-{}", Uuid::new_v4());

        // Build 1 is `-c` created 1h ago, build 2 `-b` 3h ago, build 3 `-a`
        // 2h ago, so number, name and creation order all differ.
        for (number, suffix, hours) in [(1, "c", 1), (2, "b", 3), (3, "a", 2)] {
            let created = send_json(
                app.clone(),
                post_json(
                    "/",
                    json!({ "name": format!("{prefix}-{suffix}"), "build_number": number }),
                ),
            )
            .await;
            sqlx::query(
                "UPDATE builds SET created_at = NOW() - make_interval(hours => $2) WHERE id = $1",
            )
            .bind(Uuid::parse_str(created["id"].as_str().expect("id")).expect("uuid"))
            .bind(hours)
            .execute(&pool)
            .await
            .expect("backdate");
        }

        let numbers = |sort: &'static str| {
            let app = app.clone();
            let prefix = prefix.clone();
            async move {
                let list = send_json(app, tdh::get(format!("/?search={prefix}&{sort}"))).await;
                list["items"]
                    .as_array()
                    .expect("items")
                    .iter()
                    .map(|b| b["number"].as_i64().expect("number"))
                    .collect::<Vec<_>>()
            }
        };

        assert_eq!(
            numbers("sort_by=created_at&sort_order=asc").await,
            [2, 3, 1]
        );
        assert_eq!(
            numbers("sort_by=created_at&sort_order=desc").await,
            [1, 3, 2]
        );
        assert_eq!(numbers("sort_by=name&sort_order=asc").await, [3, 2, 1]);
        assert_eq!(numbers("sort_order=desc").await, [3, 2, 1]);
        assert_eq!(numbers("sort_by=nope&sort_order=asc").await, [1, 2, 3]);

        let _ = sqlx::query("DELETE FROM builds WHERE name LIKE $1")
            .bind(format!("{prefix}-%"))
            .execute(&pool)
            .await;
        tdh::cleanup_user(&pool, user_id).await;
    }
}
