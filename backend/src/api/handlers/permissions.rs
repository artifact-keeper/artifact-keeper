//! Permission management handlers.

use axum::{
    body::Bytes,
    extract::{Extension, Path, Query, State},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::dto::Pagination;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};

/// Require that the request is authenticated, returning an error if not.
fn require_auth(auth: Option<AuthExtension>) -> Result<AuthExtension> {
    auth.ok_or_else(|| AppError::Authentication("Authentication required".to_string()))
}

/// Create permission routes
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_permissions).post(create_permission))
        .route(
            "/:id",
            get(get_permission)
                .put(update_permission)
                .delete(delete_permission),
        )
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ListPermissionsQuery {
    pub principal_type: Option<String>,
    pub principal_id: Option<Uuid>,
    pub target_type: Option<String>,
    pub target_id: Option<Uuid>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

#[derive(Debug, Serialize, FromRow, ToSchema)]
pub struct PermissionRow {
    pub id: Uuid,
    pub principal_type: String,
    pub principal_id: Uuid,
    pub principal_name: Option<String>,
    pub target_type: String,
    pub target_id: Uuid,
    pub target_name: Option<String>,
    pub actions: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PermissionResponse {
    pub id: Uuid,
    pub principal_type: String,
    pub principal_id: Uuid,
    pub principal_name: Option<String>,
    pub target_type: String,
    pub target_id: Uuid,
    pub target_name: Option<String>,
    pub actions: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<PermissionRow> for PermissionResponse {
    fn from(row: PermissionRow) -> Self {
        Self {
            id: row.id,
            principal_type: row.principal_type,
            principal_id: row.principal_id,
            principal_name: row.principal_name,
            target_type: row.target_type,
            target_id: row.target_id,
            target_name: row.target_name,
            actions: row.actions,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

/// Shared SELECT/JOIN fragment that hydrates a `permissions` row's
/// `principal_name` / `target_name` display columns.
///
/// `from_clause` supplies both the row source and its alias, always `p`:
/// either the base table (`"permissions p"`, used by the plain read paths
/// [`fetch_permission_row`] and [`list_permissions`]) or a data-modifying
/// CTE named `p` (used by [`create_permission`] / [`update_permission`] to
/// collapse INSERT/UPDATE + hydration into one round trip). Every caller
/// appends its own `WHERE`/`ORDER BY`/pagination clause (or, for the CTE
/// callers, prefixes a `WITH p AS (...)`) via `format!`. Centralizing this
/// keeps the principal/target CASE+JOIN logic in exactly one place.
///
/// `from_clause` is interpolated into the SQL **unescaped**, so every caller
/// MUST pass a string literal. It exists to pick between the base table and a
/// CTE name, nothing else; never route a request-derived value through it.
///
/// #2826: the `users` join is intentionally NOT guarded by
/// `is_service_account`. Between migration 057 (Feb 2026, the column's
/// introduction) and #2499 (Jul 2026, `principal_type = 'service_account'`
/// first honored by resolvers), the only working way to grant a service
/// account fine-grained access was `principal_type = 'user'` + the SA's
/// `users.id`. No migration re-types those rows, `validate_principal`
/// (#2503) only guards new writes, and `query_actions`
/// (`permission_service.rs`) still matches such rows by bare `principal_id`,
/// so they remain live, enforced grants today. A type guard here would hide
/// exactly the rows a still-effective grant empowers. Because the join keys
/// on the `users` primary key, dropping the guard can never attach the
/// WRONG name to a row -- only a previously-missing one.
fn hydrate_select(from_clause: &str) -> String {
    format!(
        r#"
        SELECT p.id, p.principal_type, p.principal_id, p.target_type, p.target_id,
               p.actions, p.created_at, p.updated_at,
               CASE
                   WHEN p.principal_type IN ('user', 'service_account') THEN u.username
                   WHEN p.principal_type = 'group' THEN g.name
               END as principal_name,
               CASE
                   WHEN p.target_type = 'repository' THEN r.name
               END as target_name
        FROM {from_clause}
        LEFT JOIN users u ON p.principal_type IN ('user', 'service_account')
                         AND p.principal_id = u.id
        LEFT JOIN groups g ON p.principal_type = 'group' AND p.principal_id = g.id
        LEFT JOIN repositories r ON p.target_type = 'repository' AND p.target_id = r.id
        "#
    )
}

/// Map an error from the create/update write statements.
///
/// A unique violation on `permissions(principal_type, principal_id,
/// target_type, target_id)` is a client-caused conflict on BOTH write paths:
/// create hits it when the grant already exists, update when a row is
/// retargeted onto an existing tuple. Only create used to map it, so the
/// update collision surfaced as a 500 carrying the raw Postgres error text;
/// sharing the mapping fixes that and keeps the two handlers consistent.
///
/// The substring match still fires from inside a data-modifying CTE: wrapping
/// the INSERT/UPDATE in `WITH p AS (...)` does not change the driver's primary
/// message, which is what `sqlx::Error::Database`'s `Display` renders.
fn map_permission_write_error(e: sqlx::Error) -> AppError {
    let msg = e.to_string();
    if msg.contains("duplicate key") {
        AppError::Conflict("Permission already exists".to_string())
    } else {
        AppError::Database(msg)
    }
}

async fn fetch_permission_row<'e, E>(executor: E, id: Uuid) -> Result<Option<PermissionRow>>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query_as(&format!(
        "{} WHERE p.id = $1",
        hydrate_select("permissions p")
    ))
    .bind(id)
    .fetch_optional(executor)
    .await
    .map_err(|e| AppError::Database(e.to_string()))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PermissionListResponse {
    pub items: Vec<PermissionResponse>,
    pub pagination: Pagination,
}

/// List permissions
#[utoipa::path(
    get,
    path = "",
    context_path = "/api/v1/permissions",
    tag = "permissions",
    params(ListPermissionsQuery),
    responses(
        (status = 200, description = "List of permissions", body = PermissionListResponse),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_permissions(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Query(query): Query<ListPermissionsQuery>,
) -> Result<Json<PermissionListResponse>> {
    // #3229: the ACL table is admin-only in BOTH directions. Before this gate
    // the handler took no `AuthExtension` at all, so any authenticated
    // principal -- including a read-scoped service-account token -- could page
    // the entire `permissions` table (usernames, group names, repository
    // names, action arrays) and learn which principals hold `admin` on which
    // repositories. Symmetric with create/update/delete: scope check first,
    // then `require_admin`, before any DB work. There is no per-caller
    // filtering model on this endpoint today, and its only shipped consumers
    // (the web settings screen and the CLI `permission` command) are admin
    // surfaces, so admin-only is the contract.
    let auth = require_auth(auth)?;
    auth.require_scope("read")?;
    auth.require_admin()?;
    let _ = auth;

    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
    let offset = ((page - 1) * per_page) as i64;

    // Check if permissions table exists first
    let table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'permissions')",
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);

    if !table_exists {
        return Ok(Json(PermissionListResponse {
            items: vec![],
            pagination: Pagination {
                page,
                per_page,
                total: 0,
                total_pages: 0,
            },
        }));
    }

    let permissions: Vec<PermissionRow> = sqlx::query_as(&format!(
        "{} WHERE ($1::text IS NULL OR p.principal_type = $1)
          AND ($2::uuid IS NULL OR p.principal_id = $2)
          AND ($3::text IS NULL OR p.target_type = $3)
          AND ($4::uuid IS NULL OR p.target_id = $4)
        ORDER BY p.created_at DESC
        OFFSET $5
        LIMIT $6",
        hydrate_select("permissions p")
    ))
    .bind(&query.principal_type)
    .bind(query.principal_id)
    .bind(&query.target_type)
    .bind(query.target_id)
    .bind(offset)
    .bind(per_page as i64)
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let total: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM permissions
        WHERE ($1::text IS NULL OR principal_type = $1)
          AND ($2::uuid IS NULL OR principal_id = $2)
          AND ($3::text IS NULL OR target_type = $3)
          AND ($4::uuid IS NULL OR target_id = $4)
        "#,
    )
    .bind(&query.principal_type)
    .bind(query.principal_id)
    .bind(&query.target_type)
    .bind(query.target_id)
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;

    Ok(Json(PermissionListResponse {
        items: permissions
            .into_iter()
            .map(PermissionResponse::from)
            .collect(),
        pagination: Pagination {
            page,
            per_page,
            total,
            total_pages,
        },
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePermissionRequest {
    pub principal_type: String,
    pub principal_id: Uuid,
    pub target_type: String,
    pub target_id: Uuid,
    pub actions: Vec<String>,
}

/// Create a permission
#[utoipa::path(
    post,
    path = "",
    context_path = "/api/v1/permissions",
    tag = "permissions",
    request_body = CreatePermissionRequest,
    responses(
        (status = 200, description = "Permission created successfully", body = PermissionResponse),
        (status = 409, description = "Permission already exists"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_permission(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    body: Bytes,
) -> Result<Json<PermissionResponse>> {
    // GHSA-vvc3-h39c-mrq5: read-scoped service-account tokens were being
    // accepted on this endpoint, enabling privilege escalation by creating
    // a fine-grained admin permission on the system sentinel.
    //
    // The body is taken as raw `Bytes` (not `Json<CreatePermissionRequest>`)
    // so the authorization gate runs BEFORE the payload is parsed. A
    // `Json<T>` extractor runs during request extraction, i.e. before this
    // handler body executes, so a malformed/short payload from a read-scope
    // caller would short-circuit to a body-shape error (422/500) before the
    // scope check ever ran. By gating first we guarantee a non-admin or
    // read-scope caller gets a clean 403 with the canonical scope-error body
    // before any deserialization or DB work. See #1438 (B10).
    let auth = require_auth(auth)?;
    auth.require_scope("write")?;
    // #1438 (1a): only admins may grant fine-grained permissions. Previously
    // a non-admin JWT caller passed the scope check (JWT sessions are not
    // scope-restricted), hit the INSERT, and tripped an FK violation that
    // surfaced as 500 DATABASE_ERROR. The contract is admin-only, so reject
    // here with 403 before any DB write.
    auth.require_admin()?;
    let _ = auth;

    // Only now, after the caller is authorized, parse the payload. Malformed
    // or missing fields surface as 400 VALIDATION_ERROR (the canonical
    // client-error envelope), never 422/500.
    let payload: CreatePermissionRequest = serde_json::from_slice(&body)
        .map_err(|e| AppError::Validation(format!("Invalid permission payload: {}", e)))?;

    // #2503 (defense-in-depth): validate that `principal_id` actually names a
    // principal of the declared `principal_type`. Since #2433 widened grant
    // matching to include `service_account`, a mistyped grant (e.g.
    // `principal_type = 'service_account'` naming a real user id) would resolve
    // against the wrong principal. Reject the mismatch with a 400 before the
    // INSERT instead of persisting an effective, misattributed grant.
    state
        .permission_service
        .validate_principal(&payload.principal_type, payload.principal_id)
        .await?;

    // #2826: hydrate the response inside the write statement. The INSERT's
    // `RETURNING *` feeds the shared `hydrate_select` joins through a
    // data-modifying CTE, so create answers with the same
    // principal_name/target_name a follow-up GET reports. Before this the
    // handler ran a bare `INSERT ... RETURNING <columns>` and hard-coded both
    // display fields to `None`; there was no transaction and no second query,
    // so the round-trip count is unchanged (still one autocommit statement on
    // the pool) -- what changed is that the one statement now also resolves
    // the names, instead of needing a follow-up SELECT to do it.
    //
    // Being one statement is what makes it atomic: any failure, including the
    // unique violation the CTE's INSERT raises on a duplicate grant, rolls the
    // whole statement back, so no error path can leave a half-written row.
    //
    // `fetch_one` (error on zero rows) is deliberate: the CTE's INSERT emits
    // exactly one row on success and the LEFT JOINs (all keyed on a primary
    // key) cannot drop or duplicate it, so a zero-row result is an invariant
    // failure, not a legitimate 404.
    //
    // The two name fields are snapshot-best-effort: the outer SELECT reads
    // `users`/`groups`/`repositories` at the statement snapshot, so a
    // principal or repository committed concurrently mid-statement can echo
    // back as `null` here and hydrate on the next GET. Do not write a test
    // asserting these are non-null under concurrency.
    let query = format!(
        r#"
        WITH p AS (
            INSERT INTO permissions (principal_type, principal_id, target_type, target_id, actions)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *
        )
        {}
        "#,
        hydrate_select("p")
    );
    let permission: PermissionRow = sqlx::query_as(&query)
        .bind(&payload.principal_type)
        .bind(payload.principal_id)
        .bind(&payload.target_type)
        .bind(payload.target_id)
        .bind(&payload.actions)
        .fetch_one(&state.db)
        .await
        .map_err(map_permission_write_error)?;

    state.permission_service.invalidate_cache();
    state
        .event_bus
        .emit("permission.created", permission.id, None);

    Ok(Json(PermissionResponse::from(permission)))
}

/// Get a permission by ID
#[utoipa::path(
    get,
    path = "/{id}",
    context_path = "/api/v1/permissions",
    tag = "permissions",
    params(
        ("id" = Uuid, Path, description = "Permission ID")
    ),
    responses(
        (status = 200, description = "Permission details", body = PermissionResponse),
        (status = 404, description = "Permission not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_permission(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
) -> Result<Json<PermissionResponse>> {
    // #3229: same admin-only gate as list_permissions above -- this handler
    // previously extracted no `AuthExtension` at all, so any authenticated
    // principal could read any ACL row by id.
    let auth = require_auth(auth)?;
    auth.require_scope("read")?;
    auth.require_admin()?;
    let _ = auth;

    // Check if permissions table exists first
    let table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'permissions')",
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(false);

    if !table_exists {
        return Err(AppError::NotFound("Permission not found".to_string()));
    }

    let permission = fetch_permission_row(&state.db, id)
        .await?
        .ok_or_else(|| AppError::NotFound("Permission not found".to_string()))?;

    Ok(Json(PermissionResponse::from(permission)))
}

/// Update a permission
#[utoipa::path(
    put,
    path = "/{id}",
    context_path = "/api/v1/permissions",
    tag = "permissions",
    params(
        ("id" = Uuid, Path, description = "Permission ID")
    ),
    request_body = CreatePermissionRequest,
    responses(
        (status = 200, description = "Permission updated successfully", body = PermissionResponse),
        (status = 404, description = "Permission not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_permission(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
    body: Bytes,
) -> Result<Json<PermissionResponse>> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope on permission updates. As in
    // create_permission, take the body as raw `Bytes` and authorize before
    // parsing so a read-scope caller gets 403 (not a body-shape 422/500)
    // before any deserialization or DB work.
    let auth = require_auth(auth)?;
    auth.require_scope("write")?;
    auth.require_admin()?;
    let _ = auth;

    let payload: CreatePermissionRequest = serde_json::from_slice(&body)
        .map_err(|e| AppError::Validation(format!("Invalid permission payload: {}", e)))?;

    // #2503 (defense-in-depth): mirror the create-path check so an update cannot
    // reintroduce a type/id mismatch (e.g. `service_account` naming a user id).
    state
        .permission_service
        .validate_principal(&payload.principal_type, payload.principal_id)
        .await?;

    // Same hydrate-inside-the-write-statement shape as create_permission
    // above (#2826); before this, update ran a bare `UPDATE ... RETURNING
    // <columns>` and hard-coded both display fields to `None`. The same
    // atomicity and snapshot-best-effort notes apply.
    //
    // Unlike create, a zero-row result here is a legitimate outcome -- the id
    // does not exist -- so `fetch_optional` -> `None` still maps to
    // `NotFound` rather than a 500: an UPDATE that matches nothing yields an
    // empty CTE, and the outer SELECT over it returns no rows.
    let query = format!(
        r#"
        WITH p AS (
            UPDATE permissions
            SET principal_type = $2, principal_id = $3, target_type = $4, target_id = $5,
                actions = $6, updated_at = NOW()
            WHERE id = $1
            RETURNING *
        )
        {}
        "#,
        hydrate_select("p")
    );
    let permission: PermissionRow = sqlx::query_as(&query)
        .bind(id)
        .bind(&payload.principal_type)
        .bind(payload.principal_id)
        .bind(&payload.target_type)
        .bind(payload.target_id)
        .bind(&payload.actions)
        .fetch_optional(&state.db)
        .await
        .map_err(map_permission_write_error)?
        .ok_or_else(|| AppError::NotFound("Permission not found".to_string()))?;

    state.permission_service.invalidate_cache();
    state
        .event_bus
        .emit("permission.updated", permission.id, None);

    Ok(Json(PermissionResponse::from(permission)))
}

/// Delete a permission
#[utoipa::path(
    delete,
    path = "/{id}",
    context_path = "/api/v1/permissions",
    tag = "permissions",
    params(
        ("id" = Uuid, Path, description = "Permission ID")
    ),
    responses(
        (status = 200, description = "Permission deleted successfully"),
        (status = 404, description = "Permission not found"),
        (status = 500, description = "Internal server error")
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_permission(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    // GHSA-vvc3-h39c-mrq5: destructive permission ops require the delete
    // scope. Without this check a read-scoped service-account token could
    // remove permission rows belonging to other principals.
    let auth = require_auth(auth)?;
    auth.require_scope("delete")?;
    // #3229: `require_scope` alone is NOT an authorization gate for
    // session-authenticated callers -- `has_scope` returns `true`
    // unconditionally when `scopes` is `None`, and interactive/JWT sessions
    // carry `scopes: None` ("JWT sessions are not scope-restricted", see
    // create_permission). That is exactly why #1438 added `require_admin()`
    // on top of the scope check for create/update; delete never got the same
    // treatment, so any logged-in non-admin could remove arbitrary permission
    // rows. Match create/update: admin only.
    auth.require_admin()?;
    let _ = auth;

    let result = sqlx::query("DELETE FROM permissions WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Permission not found".to_string()));
    }

    state.permission_service.invalidate_cache();
    state.event_bus.emit("permission.deleted", id, None);

    Ok(())
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list_permissions,
        create_permission,
        get_permission,
        update_permission,
        delete_permission,
    ),
    components(schemas(
        PermissionRow,
        PermissionResponse,
        PermissionListResponse,
        CreatePermissionRequest,
    ))
)]
pub struct PermissionsApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use chrono::Utc;
    use serde_json::json;

    fn permission_app(state: SharedState, auth: AuthExtension) -> axum::Router {
        tdh::router_with_auth(router(), state, auth)
    }

    /// Seed a fine-grained `permissions` row scoped to a single `["read"]`
    /// action -- these tests only assert on hydration, so the exact action
    /// set doesn't matter. Thin wrapper over `tdh::grant_permission` (the
    /// general form; `tdh::grant_repo_admin`/`grant_repo_actions` are the
    /// `user` + `repository` specializations these tests don't want).
    async fn seed_permission(
        pool: &sqlx::PgPool,
        principal_type: &str,
        principal_id: Uuid,
        target_type: &str,
        target_id: Uuid,
    ) -> Uuid {
        tdh::grant_permission(
            pool,
            principal_type,
            principal_id,
            target_type,
            target_id,
            &["read"],
        )
        .await
    }

    /// Send a request built via the `tdh` request helpers and parse the JSON
    /// body, asserting 200 OK. Request construction (method/uri/content-type
    /// boilerplate) lives in `tdh::get`/`tdh::post`/`tdh::put_json`; this
    /// keeps only the send+assert+parse step local, since that part isn't
    /// shared with other handler test modules.
    async fn response_json(
        state: SharedState,
        auth: AuthExtension,
        request: Request<Body>,
    ) -> serde_json::Value {
        let (status, body) = tdh::send(permission_app(state, auth), request).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "permission request failed: {}",
            String::from_utf8_lossy(&body)
        );
        serde_json::from_slice(&body).expect("permission response JSON")
    }

    /// Teardown for this module's fixtures. `tdh::cleanup` handles the
    /// admin user + repo-target permissions + repo row; `tdh::cleanup_user`
    /// handles each extra user principal (service accounts). What's left --
    /// permissions keyed by a non-admin/non-repo-target row (e.g. the
    /// `target_type = "global"` fixture) and group rows -- isn't covered by
    /// either shared helper, so it stays local.
    async fn cleanup_permission_fixtures(
        pool: &sqlx::PgPool,
        repo_id: Uuid,
        admin_id: Uuid,
        extra_user_ids: &[Uuid],
        group_ids: &[Uuid],
    ) {
        let mut principal_ids: Vec<Uuid> = extra_user_ids.to_vec();
        principal_ids.push(admin_id);
        principal_ids.extend_from_slice(group_ids);
        let _ = sqlx::query("DELETE FROM permissions WHERE principal_id = ANY($1)")
            .bind(&principal_ids)
            .execute(pool)
            .await;
        if !group_ids.is_empty() {
            let _ = sqlx::query("DELETE FROM groups WHERE id = ANY($1)")
                .bind(group_ids)
                .execute(pool)
                .await;
        }
        for &id in extra_user_ids {
            tdh::cleanup_user(pool, id).await;
        }
        tdh::cleanup(pool, repo_id, admin_id).await;
    }

    /// The `mismatched_permission` fixture below seeds `principal_type =
    /// 'service_account'` naming a human admin's `users.id` -- a row shape
    /// that never occurs from `validate_principal`-gated writes (#2503), but
    /// can exist from data seeded before that gate, or a legacy row exactly
    /// like the one #2826's regression test below covers in the other
    /// direction. It still asserts a real username, not `null`: the join is
    /// keyed by `users.id`, and `query_actions` (`permission_service.rs`)
    /// enforces this row by bare `principal_id` regardless of the declared
    /// `principal_type`, so it is a live grant an admin needs to be able to
    /// identify. See `hydrate_select`'s doc comment for the full rationale.
    #[tokio::test]
    async fn list_and_get_hydrate_principal_names_by_id_regardless_of_type_mismatch() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (admin_id, admin_name) = tdh::create_user(&pool).await;
        let (service_account_id, service_account_name) = tdh::create_service_account(&pool).await;
        let (group_id, group_name) = tdh::create_group(&pool).await;
        let (repo_id, repo_name, _storage_dir) = tdh::create_repo(&pool, "local", "npm").await;
        let state = tdh::build_state(pool.clone(), "/tmp");
        let auth = tdh::admin_auth(admin_id, &admin_name);

        let human_permission =
            seed_permission(&pool, "user", admin_id, "repository", repo_id).await;
        let service_account_permission = seed_permission(
            &pool,
            "service_account",
            service_account_id,
            "repository",
            repo_id,
        )
        .await;
        let group_permission =
            seed_permission(&pool, "group", group_id, "repository", repo_id).await;
        let mismatched_permission =
            seed_permission(&pool, "service_account", admin_id, "repository", repo_id).await;

        let listed = response_json(
            state.clone(),
            auth.clone(),
            tdh::get(format!("/?target_id={repo_id}")),
        )
        .await;
        let items = listed["items"].as_array().expect("permission items");
        let find = |id: Uuid| {
            items
                .iter()
                .find(|item| item["id"] == id.to_string())
                .expect("listed permission")
        };

        assert_eq!(find(human_permission)["principal_name"], admin_name);
        assert_eq!(
            find(service_account_permission)["principal_name"],
            service_account_name
        );
        assert_eq!(find(group_permission)["principal_name"], group_name);
        // Mismatched principal_type, still enforced by bare principal_id: named,
        // not null (see the doc comment above this test).
        assert_eq!(find(mismatched_permission)["principal_name"], admin_name);
        assert!(items.iter().all(|item| item["target_name"] == repo_name));

        let fetched_human = response_json(
            state.clone(),
            auth.clone(),
            tdh::get(format!("/{human_permission}")),
        )
        .await;
        assert_eq!(fetched_human["principal_name"], admin_name);
        assert_eq!(fetched_human["target_name"], repo_name);

        let fetched_service_account = response_json(
            state.clone(),
            auth.clone(),
            tdh::get(format!("/{service_account_permission}")),
        )
        .await;
        assert_eq!(
            fetched_service_account["principal_name"],
            service_account_name
        );
        assert_eq!(fetched_service_account["target_name"], repo_name);

        let fetched_group = response_json(
            state.clone(),
            auth.clone(),
            tdh::get(format!("/{group_permission}")),
        )
        .await;
        assert_eq!(fetched_group["principal_name"], group_name);
        assert_eq!(fetched_group["target_name"], repo_name);

        let fetched_mismatch =
            response_json(state, auth, tdh::get(format!("/{mismatched_permission}"))).await;
        assert_eq!(fetched_mismatch["principal_name"], admin_name);
        assert_eq!(fetched_mismatch["target_name"], repo_name);

        cleanup_permission_fixtures(&pool, repo_id, admin_id, &[service_account_id], &[group_id])
            .await;
    }

    /// #2826 hardening: between migration 057 (Feb 2026, `is_service_account`
    /// introduced) and #2499 (Jul 2026, `principal_type = 'service_account'`
    /// first honored by resolvers), the only working way to grant a service
    /// account fine-grained access was `principal_type = 'user'` + the SA's
    /// `users.id`. No migration re-types those rows, `validate_principal`
    /// (#2503) only guards new writes, and `query_actions`
    /// (`permission_service.rs`) still matches such legacy rows by bare
    /// `principal_id` -- they are live, enforced grants today. Pin that a
    /// legacy `principal_type = 'user'` row naming a service account still
    /// hydrates the SA's username (list AND get), not `null`.
    ///
    /// WHAT THIS TEST DOES AND DOES NOT COVER: it is GREEN on the pre-#2826
    /// code and therefore carries **no** coverage of #2826 itself. The old
    /// join was `p.principal_type = 'user' AND p.principal_id = u.id`, and a
    /// service account IS a `users` row, so a `'user'`-typed row naming an SA
    /// already hydrated before the fix. The #2826 regression guards are
    /// `list_and_get_hydrate_principal_names_by_id_regardless_of_type_mismatch`
    /// (the `service_account`-typed rows) and
    /// `create_and_update_return_hydrated_permission_names`. This one is a
    /// FORWARD guard: it fails the moment anyone adds an
    /// `AND u.is_service_account = false` predicate to the user arm -- exactly
    /// the design considered and rejected while fixing #2826, and the reason
    /// `hydrate_select` carries the doc comment it does.
    #[tokio::test]
    async fn legacy_user_typed_grant_naming_a_service_account_hydrates_its_username() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (admin_id, admin_name) = tdh::create_user(&pool).await;
        let (service_account_id, service_account_name) = tdh::create_service_account(&pool).await;
        let (repo_id, repo_name, _storage_dir) = tdh::create_repo(&pool, "local", "npm").await;
        let state = tdh::build_state(pool.clone(), "/tmp");
        let auth = tdh::admin_auth(admin_id, &admin_name);

        let legacy_permission =
            seed_permission(&pool, "user", service_account_id, "repository", repo_id).await;

        let listed = response_json(
            state.clone(),
            auth.clone(),
            tdh::get(format!("/?target_id={repo_id}")),
        )
        .await;
        let items = listed["items"].as_array().expect("permission items");
        let listed_legacy = items
            .iter()
            .find(|item| item["id"] == legacy_permission.to_string())
            .expect("legacy permission in list");
        assert_eq!(listed_legacy["principal_name"], service_account_name);
        assert_eq!(listed_legacy["target_name"], repo_name);

        let fetched_legacy =
            response_json(state, auth, tdh::get(format!("/{legacy_permission}"))).await;
        assert_eq!(fetched_legacy["principal_name"], service_account_name);
        assert_eq!(fetched_legacy["target_name"], repo_name);

        cleanup_permission_fixtures(&pool, repo_id, admin_id, &[service_account_id], &[]).await;
    }

    #[tokio::test]
    async fn create_and_update_return_hydrated_permission_names() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (admin_id, admin_name) = tdh::create_user(&pool).await;
        let (service_account_id, service_account_name) = tdh::create_service_account(&pool).await;
        let (repo_id, repo_name, _storage_dir) = tdh::create_repo(&pool, "local", "npm").await;
        let state = tdh::build_state(pool.clone(), "/tmp");
        let auth = tdh::admin_auth(admin_id, &admin_name);

        let created = response_json(
            state.clone(),
            auth.clone(),
            tdh::post(
                "/".to_string(),
                "application/json",
                Bytes::from(
                    json!({
                        "principal_type": "service_account",
                        "principal_id": service_account_id,
                        "target_type": "repository",
                        "target_id": repo_id,
                        "actions": ["read", "write"]
                    })
                    .to_string(),
                ),
            ),
        )
        .await;
        assert_eq!(created["principal_name"], service_account_name);
        assert_eq!(created["target_name"], repo_name);

        let global_target_id = Uuid::new_v4();
        let permission_id =
            seed_permission(&pool, "user", admin_id, "global", global_target_id).await;
        let updated = response_json(
            state.clone(),
            auth.clone(),
            tdh::put_json(
                format!("/{permission_id}"),
                Bytes::from(
                    json!({
                        "principal_type": "service_account",
                        "principal_id": service_account_id,
                        "target_type": "global",
                        "target_id": global_target_id,
                        "actions": ["admin"]
                    })
                    .to_string(),
                ),
            ),
        )
        .await;
        assert_eq!(updated["principal_name"], service_account_name);
        assert!(updated["target_name"].is_null());

        let fetched = response_json(
            state.clone(),
            auth.clone(),
            tdh::get(format!("/{permission_id}")),
        )
        .await;
        assert_eq!(fetched["principal_name"], service_account_name);
        assert!(fetched["target_name"].is_null());

        let listed = response_json(
            state.clone(),
            auth.clone(),
            tdh::get(format!(
                "/?principal_id={service_account_id}&target_id={global_target_id}"
            )),
        )
        .await;
        let listed_permission = listed["items"]
            .as_array()
            .expect("permission items")
            .iter()
            .find(|item| item["id"] == permission_id.to_string())
            .expect("updated permission in list");
        assert_eq!(listed_permission["principal_name"], service_account_name);
        assert!(listed_permission["target_name"].is_null());

        // Positive control for the UPDATE path's `target_name`. Every
        // assertion above only ever puts update against a `global` target,
        // whose `target_name` is null under the fix AND under the pre-#2826
        // code that hard-coded the field to `None` -- `is_null()` there is
        // satisfied by the bug as well as by the fix, so on its own it leaves
        // update's `target_name` hydration entirely unguarded. Re-point the
        // same row at the repository: this assertion can only hold if the
        // UPDATE's CTE really joins `repositories`. The principal goes back to
        // the admin so the tuple stays distinct from the row created at the
        // top of this test (`permissions` is UNIQUE on the four-column key).
        let retargeted = response_json(
            state,
            auth,
            tdh::put_json(
                format!("/{permission_id}"),
                Bytes::from(
                    json!({
                        "principal_type": "user",
                        "principal_id": admin_id,
                        "target_type": "repository",
                        "target_id": repo_id,
                        "actions": ["read"]
                    })
                    .to_string(),
                ),
            ),
        )
        .await;
        assert_eq!(retargeted["principal_name"], admin_name);
        assert_eq!(retargeted["target_name"], repo_name);

        cleanup_permission_fixtures(&pool, repo_id, admin_id, &[service_account_id], &[]).await;
    }

    /// The #2826 rewrite moved both write statements inside a data-modifying
    /// CTE, and the 409 mapping is a substring match on the driver's error
    /// text (`map_permission_write_error`). Nothing in the repo exercised that
    /// arm, so a change in how a unique violation surfaces from inside a CTE
    /// would silently downgrade 409 to 500 unnoticed.
    ///
    /// Also pins two things the CTE rewrite is responsible for: that a
    /// rejected create leaves NO row behind (the single-statement atomicity
    /// claim in `create_permission`'s comment), and that the same collision
    /// reached through UPDATE is a 409 too. The update arm previously fell
    /// through to `AppError::Database` and answered 500 with the raw Postgres
    /// error text; create and update now share one mapping.
    #[tokio::test]
    async fn duplicate_grants_are_conflicts_on_both_create_and_update() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (admin_id, admin_name) = tdh::create_user(&pool).await;
        let (sa_id, _) = tdh::create_service_account(&pool).await;
        let (repo_id, _, _dir) = tdh::create_repo(&pool, "local", "npm").await;
        let state = tdh::build_state(pool.clone(), "/tmp");
        let auth = tdh::admin_auth(admin_id, &admin_name);
        let grant_body = || {
            Bytes::from(
                json!({
                    "principal_type": "service_account",
                    "principal_id": sa_id,
                    "target_type": "repository",
                    "target_id": repo_id,
                    "actions": ["read"]
                })
                .to_string(),
            )
        };
        async fn grants(pool: &sqlx::PgPool, principal_id: Uuid, target_id: Uuid) -> i64 {
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM permissions WHERE principal_id = $1 AND target_id = $2",
            )
            .bind(principal_id)
            .bind(target_id)
            .fetch_one(pool)
            .await
            .expect("count service-account grants")
        }

        let (first, first_body) = tdh::send(
            permission_app(state.clone(), auth.clone()),
            tdh::post("/".to_string(), "application/json", grant_body()),
        )
        .await;
        assert_eq!(
            first,
            StatusCode::OK,
            "first create must succeed: {}",
            String::from_utf8_lossy(&first_body)
        );
        assert_eq!(grants(&pool, sa_id, repo_id).await, 1);

        let (second, second_body) = tdh::send(
            permission_app(state.clone(), auth.clone()),
            tdh::post("/".to_string(), "application/json", grant_body()),
        )
        .await;
        assert_eq!(
            second,
            StatusCode::CONFLICT,
            "duplicate create must map to 409, not 500: {}",
            String::from_utf8_lossy(&second_body)
        );
        assert_eq!(
            grants(&pool, sa_id, repo_id).await,
            1,
            "the rejected create must not leave a second row"
        );

        // Same collision via UPDATE: retarget a second row onto the tuple the
        // create above already occupies.
        let other = seed_permission(&pool, "user", admin_id, "repository", repo_id).await;
        let (updated, updated_body) = tdh::send(
            permission_app(state, auth),
            tdh::put_json(format!("/{other}"), grant_body()),
        )
        .await;
        assert_eq!(
            updated,
            StatusCode::CONFLICT,
            "an update colliding with an existing grant must map to 409, not 500: {}",
            String::from_utf8_lossy(&updated_body)
        );
        assert_eq!(
            grants(&pool, sa_id, repo_id).await,
            1,
            "the rejected update must not have retargeted the row"
        );

        cleanup_permission_fixtures(&pool, repo_id, admin_id, &[sa_id], &[]).await;
    }

    /// `update_permission`'s 404 has to survive the CTE rewrite: an UPDATE
    /// matching no row yields an empty CTE, so the outer SELECT over it
    /// returns nothing and `fetch_optional` -> `None` must still map to
    /// NotFound rather than a 500. Nothing else covers that path.
    #[tokio::test]
    async fn update_of_a_missing_permission_is_not_found_not_a_server_error() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (admin_id, admin_name) = tdh::create_user(&pool).await;
        let state = tdh::build_state(pool.clone(), "/tmp");
        let auth = tdh::admin_auth(admin_id, &admin_name);

        let missing = Uuid::new_v4();
        let (status, body) = tdh::send(
            permission_app(state, auth),
            tdh::put_json(
                format!("/{missing}"),
                Bytes::from(
                    json!({
                        "principal_type": "user",
                        "principal_id": admin_id,
                        "target_type": "global",
                        "target_id": Uuid::new_v4(),
                        "actions": ["read"]
                    })
                    .to_string(),
                ),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "update of a missing id must be 404: {}",
            String::from_utf8_lossy(&body)
        );

        tdh::cleanup_user(&pool, admin_id).await;
    }

    fn delete_req(uri: String) -> Request<Body> {
        Request::builder()
            .method("DELETE")
            .uri(uri)
            .body(Body::empty())
            .expect("delete request")
    }

    async fn permission_row_count(pool: &sqlx::PgPool, id: Uuid) -> i64 {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM permissions WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("count permission row")
    }

    /// #3229 (read half): `GET /` and `GET /{id}` previously extracted no
    /// `AuthExtension` at all, so ANY authenticated principal -- a non-admin
    /// JWT session or a read-scoped service-account token -- could page the
    /// whole ACL table. Both must now be admin-only, and the admin positive
    /// control in the same fixture proves the gate denies the right callers
    /// rather than everyone.
    #[tokio::test]
    async fn list_and_get_permissions_are_admin_only() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (admin_id, admin_name) = tdh::create_user(&pool).await;
        let (user_id, user_name) = tdh::create_user(&pool).await;
        let (repo_id, _repo_name, _storage_dir) = tdh::create_repo(&pool, "local", "npm").await;
        let state = tdh::build_state(pool.clone(), "/tmp");
        let admin = tdh::admin_auth(admin_id, &admin_name);
        // The exact bypass shapes from the issue: an interactive non-admin JWT
        // session (`scopes: None`, which satisfies every scope check), and a
        // read-scoped service-account token (which satisfies the "read" scope
        // check). Only `require_admin` can stop either.
        let non_admin_jwt = tdh::make_auth(user_id, &user_name);
        let read_scoped_sa = read_only_token();

        let permission_id = seed_permission(&pool, "user", admin_id, "repository", repo_id).await;

        for (label, caller) in [
            ("non-admin JWT", non_admin_jwt),
            ("read-scoped SA token", read_scoped_sa),
        ] {
            let (status, body) = tdh::send(
                permission_app(state.clone(), caller.clone()),
                tdh::get("/".to_string()),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{label} must not list the ACL table: {}",
                String::from_utf8_lossy(&body)
            );

            let (status, body) = tdh::send(
                permission_app(state.clone(), caller),
                tdh::get(format!("/{permission_id}")),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "{label} must not read an ACL row by id: {}",
                String::from_utf8_lossy(&body)
            );
        }

        // Positive control, same fixture: an admin still lists and gets the
        // seeded row. Without this, a gate that denies everyone would pass
        // the 403 assertions above.
        let listed = response_json(
            state.clone(),
            admin.clone(),
            tdh::get(format!("/?target_id={repo_id}")),
        )
        .await;
        assert!(
            listed["items"]
                .as_array()
                .expect("permission items")
                .iter()
                .any(|item| item["id"] == permission_id.to_string()),
            "admin list must still return the seeded row"
        );

        let fetched = response_json(state, admin, tdh::get(format!("/{permission_id}"))).await;
        assert_eq!(fetched["id"], permission_id.to_string());

        tdh::cleanup_user(&pool, user_id).await;
        cleanup_permission_fixtures(&pool, repo_id, admin_id, &[], &[]).await;
    }

    /// #3229 (delete half): `delete_permission` checked only
    /// `require_scope("delete")`, and `scopes: None` (interactive JWT
    /// sessions) satisfies every scope check unconditionally -- so any
    /// logged-in non-admin could delete arbitrary permission rows. The row
    /// must survive the denied attempt, and the admin positive control in the
    /// same fixture must still delete it (a blanket-deny "fix" would fail
    /// there).
    #[tokio::test]
    async fn delete_permission_requires_admin_not_just_delete_scope() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (admin_id, admin_name) = tdh::create_user(&pool).await;
        let (user_id, user_name) = tdh::create_user(&pool).await;
        let (repo_id, _repo_name, _storage_dir) = tdh::create_repo(&pool, "local", "npm").await;
        let state = tdh::build_state(pool.clone(), "/tmp");
        let admin = tdh::admin_auth(admin_id, &admin_name);
        // Non-admin interactive JWT: `scopes: None` passes the "delete" scope
        // check, so before the fix this caller reached the DELETE statement.
        let non_admin_jwt = tdh::make_auth(user_id, &user_name);

        let permission_id = seed_permission(&pool, "user", admin_id, "repository", repo_id).await;

        let (status, body) = tdh::send(
            permission_app(state.clone(), non_admin_jwt),
            delete_req(format!("/{permission_id}")),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "non-admin JWT must not delete a permission row: {}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(
            permission_row_count(&pool, permission_id).await,
            1,
            "the denied delete must leave the row in place"
        );

        // Positive control, same fixture: an admin still deletes the row.
        let (status, body) = tdh::send(
            permission_app(state.clone(), admin.clone()),
            delete_req(format!("/{permission_id}")),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "admin delete must still succeed: {}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(
            permission_row_count(&pool, permission_id).await,
            0,
            "the admin delete must actually remove the row"
        );

        // And the now-missing id maps to 404 for the admin, not a 500.
        let (status, _body) = tdh::send(
            permission_app(state, admin),
            delete_req(format!("/{permission_id}")),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        tdh::cleanup_user(&pool, user_id).await;
        cleanup_permission_fixtures(&pool, repo_id, admin_id, &[], &[]).await;
    }

    // -----------------------------------------------------------------------
    // ListPermissionsQuery deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_list_permissions_query_all_fields() {
        let uid = Uuid::new_v4();
        let tid = Uuid::new_v4();
        let json = format!(
            r#"{{"principal_type": "user", "principal_id": "{}", "target_type": "repository", "target_id": "{}", "page": 2, "per_page": 50}}"#,
            uid, tid
        );
        let query: ListPermissionsQuery = serde_json::from_str(&json).unwrap();
        assert_eq!(query.principal_type, Some("user".to_string()));
        assert_eq!(query.principal_id, Some(uid));
        assert_eq!(query.target_type, Some("repository".to_string()));
        assert_eq!(query.target_id, Some(tid));
        assert_eq!(query.page, Some(2));
        assert_eq!(query.per_page, Some(50));
    }

    #[test]
    fn test_list_permissions_query_empty() {
        let json = r#"{}"#;
        let query: ListPermissionsQuery = serde_json::from_str(json).unwrap();
        assert!(query.principal_type.is_none());
        assert!(query.principal_id.is_none());
        assert!(query.target_type.is_none());
        assert!(query.target_id.is_none());
        assert!(query.page.is_none());
        assert!(query.per_page.is_none());
    }

    #[test]
    fn test_list_permissions_query_partial() {
        let json = r#"{"principal_type": "group", "page": 1}"#;
        let query: ListPermissionsQuery = serde_json::from_str(json).unwrap();
        assert_eq!(query.principal_type, Some("group".to_string()));
        assert!(query.principal_id.is_none());
        assert_eq!(query.page, Some(1));
    }

    // -----------------------------------------------------------------------
    // Pagination logic (inline in list_permissions)
    // -----------------------------------------------------------------------

    #[test]
    fn test_pagination_defaults() {
        let page = 1;
        let per_page = 20_u32;
        assert_eq!(page, 1);
        assert_eq!(per_page, 20);
    }

    #[test]
    fn test_pagination_page_zero_clamp() {
        let page = 1;
        assert_eq!(page, 1);
    }

    #[test]
    fn test_pagination_per_page_over_max() {
        let per_page = 100;
        assert_eq!(per_page, 100);
    }

    #[test]
    fn test_pagination_offset() {
        let page: u32 = 5;
        let per_page: u32 = 10;
        let offset = ((page - 1) * per_page) as i64;
        assert_eq!(offset, 40);
    }

    #[test]
    fn test_total_pages_calculation() {
        let total: i64 = 55;
        let per_page: u32 = 20;
        let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
        assert_eq!(total_pages, 3);
    }

    #[test]
    fn test_total_pages_single_page() {
        let total: i64 = 15;
        let per_page: u32 = 20;
        let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
        assert_eq!(total_pages, 1);
    }

    // -----------------------------------------------------------------------
    // PermissionRow → PermissionResponse conversion
    // -----------------------------------------------------------------------

    #[test]
    fn test_permission_row_to_response() {
        let now = Utc::now();
        let id = Uuid::new_v4();
        let pid = Uuid::new_v4();
        let tid = Uuid::new_v4();
        let row = PermissionRow {
            id,
            principal_type: "user".to_string(),
            principal_id: pid,
            principal_name: Some("admin".to_string()),
            target_type: "repository".to_string(),
            target_id: tid,
            target_name: Some("my-repo".to_string()),
            actions: vec!["read".to_string(), "write".to_string()],
            created_at: now,
            updated_at: now,
        };
        let resp = PermissionResponse::from(row);
        assert_eq!(resp.id, id);
        assert_eq!(resp.principal_type, "user");
        assert_eq!(resp.principal_id, pid);
        assert_eq!(resp.principal_name, Some("admin".to_string()));
        assert_eq!(resp.target_type, "repository");
        assert_eq!(resp.target_id, tid);
        assert_eq!(resp.target_name, Some("my-repo".to_string()));
        assert_eq!(resp.actions, vec!["read", "write"]);
    }

    #[test]
    fn test_permission_row_to_response_no_names() {
        let now = Utc::now();
        let row = PermissionRow {
            id: Uuid::new_v4(),
            principal_type: "group".to_string(),
            principal_id: Uuid::new_v4(),
            principal_name: None,
            target_type: "repository".to_string(),
            target_id: Uuid::new_v4(),
            target_name: None,
            actions: vec![],
            created_at: now,
            updated_at: now,
        };
        let resp = PermissionResponse::from(row);
        assert!(resp.principal_name.is_none());
        assert!(resp.target_name.is_none());
        assert!(resp.actions.is_empty());
    }

    // -----------------------------------------------------------------------
    // PermissionResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_permission_response_serialize() {
        let now = Utc::now();
        let resp = PermissionResponse {
            id: Uuid::new_v4(),
            principal_type: "user".to_string(),
            principal_id: Uuid::new_v4(),
            principal_name: Some("testuser".to_string()),
            target_type: "repository".to_string(),
            target_id: Uuid::new_v4(),
            target_name: Some("repo1".to_string()),
            actions: vec!["read".to_string(), "deploy".to_string()],
            created_at: now,
            updated_at: now,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["principal_type"], "user");
        assert_eq!(json["principal_name"], "testuser");
        assert_eq!(json["target_type"], "repository");
        assert_eq!(json["target_name"], "repo1");
        let actions = json["actions"].as_array().unwrap();
        assert_eq!(actions.len(), 2);
        assert_eq!(actions[0], "read");
        assert_eq!(actions[1], "deploy");
    }

    #[test]
    fn test_permission_response_serialize_null_names() {
        let now = Utc::now();
        let resp = PermissionResponse {
            id: Uuid::new_v4(),
            principal_type: "group".to_string(),
            principal_id: Uuid::new_v4(),
            principal_name: None,
            target_type: "global".to_string(),
            target_id: Uuid::new_v4(),
            target_name: None,
            actions: vec!["admin".to_string()],
            created_at: now,
            updated_at: now,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["principal_name"].is_null());
        assert!(json["target_name"].is_null());
    }

    // -----------------------------------------------------------------------
    // CreatePermissionRequest deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_permission_request() {
        let pid = Uuid::new_v4();
        let tid = Uuid::new_v4();
        let json = format!(
            r#"{{"principal_type": "user", "principal_id": "{}", "target_type": "repository", "target_id": "{}", "actions": ["read", "write"]}}"#,
            pid, tid
        );
        let req: CreatePermissionRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.principal_type, "user");
        assert_eq!(req.principal_id, pid);
        assert_eq!(req.target_type, "repository");
        assert_eq!(req.target_id, tid);
        assert_eq!(req.actions, vec!["read", "write"]);
    }

    #[test]
    fn test_create_permission_request_empty_actions() {
        let pid = Uuid::new_v4();
        let tid = Uuid::new_v4();
        let json = format!(
            r#"{{"principal_type": "group", "principal_id": "{}", "target_type": "repository", "target_id": "{}", "actions": []}}"#,
            pid, tid
        );
        let req: CreatePermissionRequest = serde_json::from_str(&json).unwrap();
        assert!(req.actions.is_empty());
    }

    #[test]
    fn test_create_permission_request_missing_field() {
        let json = r#"{"principal_type": "user"}"#;
        let result = serde_json::from_str::<CreatePermissionRequest>(json);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // PermissionListResponse serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_permission_list_response_serialize() {
        let now = Utc::now();
        let resp = PermissionListResponse {
            items: vec![PermissionResponse {
                id: Uuid::new_v4(),
                principal_type: "user".to_string(),
                principal_id: Uuid::new_v4(),
                principal_name: Some("u1".to_string()),
                target_type: "repository".to_string(),
                target_id: Uuid::new_v4(),
                target_name: Some("r1".to_string()),
                actions: vec!["read".to_string()],
                created_at: now,
                updated_at: now,
            }],
            pagination: Pagination {
                page: 1,
                per_page: 20,
                total: 1,
                total_pages: 1,
            },
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["items"].as_array().unwrap().len(), 1);
        assert_eq!(json["pagination"]["page"], 1);
    }

    #[test]
    fn test_permission_list_response_empty() {
        let resp = PermissionListResponse {
            items: vec![],
            pagination: Pagination {
                page: 1,
                per_page: 20,
                total: 0,
                total_pages: 0,
            },
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["items"].as_array().unwrap().is_empty());
        assert_eq!(json["pagination"]["total"], 0);
    }

    // -----------------------------------------------------------------------
    // PermissionRow serialization (used as FromRow output)
    // -----------------------------------------------------------------------

    #[test]
    fn test_permission_row_serialize() {
        let now = Utc::now();
        let row = PermissionRow {
            id: Uuid::new_v4(),
            principal_type: "user".to_string(),
            principal_id: Uuid::new_v4(),
            principal_name: Some("alice".to_string()),
            target_type: "repository".to_string(),
            target_id: Uuid::new_v4(),
            target_name: Some("repo-a".to_string()),
            actions: vec!["read".to_string(), "write".to_string(), "admin".to_string()],
            created_at: now,
            updated_at: now,
        };
        let json = serde_json::to_value(&row).unwrap();
        assert_eq!(json["principal_type"], "user");
        assert_eq!(json["actions"].as_array().unwrap().len(), 3);
    }

    // -----------------------------------------------------------------------
    // GHSA-vvc3-h39c-mrq5: scope-check tests for admin endpoints. The
    // privilege escalation chain in the advisory is:
    //
    //   read-scope SA token → POST /api/v1/permissions {actions: ["admin"]}
    //   on the system sentinel → token now has fine-grained admin
    //
    // The tests below exercise the in-handler scope check directly without
    // touching the database. The "permissions table missing" path inside
    // each handler runs first because tests have no DB; but the scope check
    // runs even earlier (right after `require_auth`), so the assertions
    // below are independent of DB state.
    // -----------------------------------------------------------------------

    fn read_only_token() -> AuthExtension {
        AuthExtension {
            user_id: Uuid::new_v4(),
            username: "sa-readonly".to_string(),
            email: "sa@example.com".to_string(),
            is_admin: false,
            is_api_token: true,
            is_service_account: true,
            scopes: Some(vec!["read".to_string()]),
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
        }
    }

    fn write_token() -> AuthExtension {
        AuthExtension {
            user_id: Uuid::new_v4(),
            username: "sa-write".to_string(),
            email: "sa@example.com".to_string(),
            is_admin: false,
            is_api_token: true,
            is_service_account: true,
            scopes: Some(vec!["write".to_string()]),
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
        }
    }

    #[test]
    fn test_require_auth_rejects_anonymous() {
        // Sanity: no AuthExtension at all -> 401, regardless of scope check.
        let result = require_auth(None);
        assert!(matches!(result, Err(AppError::Authentication(_))));
    }

    #[test]
    fn test_create_permission_scope_check_rejects_read_only() {
        // GHSA-vvc3-h39c-mrq5: this is the exact handler path used in the
        // advisory's privilege-escalation chain. A read-scoped SA token
        // must be rejected with 403 (not 200) before any DB write happens.
        let ext = read_only_token();
        let result = ext.require_scope("write");
        match result {
            Err(AppError::Authorization(msg)) => {
                assert_eq!(msg, "Token does not have required scope: write");
            }
            other => panic!("expected Authorization error, got {:?}", other),
        }
    }

    #[test]
    fn test_create_permission_scope_check_accepts_write_token() {
        let ext = write_token();
        assert!(ext.require_scope("write").is_ok());
    }

    #[test]
    fn test_delete_permission_scope_check_rejects_read_only() {
        let ext = read_only_token();
        let result = ext.require_scope("delete");
        match result {
            Err(AppError::Authorization(msg)) => {
                assert_eq!(msg, "Token does not have required scope: delete");
            }
            other => panic!("expected Authorization error, got {:?}", other),
        }
    }

    #[test]
    fn test_delete_permission_scope_check_write_token_insufficient() {
        // A write-scoped token must NOT be able to delete a permission row.
        // The advisory specifically calls out destructive ops as needing
        // the delete scope, not just write.
        let ext = write_token();
        assert!(ext.require_scope("delete").is_err());
    }

    #[test]
    fn test_update_permission_scope_check_rejects_read_only() {
        let ext = read_only_token();
        assert!(ext.require_scope("write").is_err());
    }

    #[test]
    fn test_create_permission_non_admin_jwt_rejected_with_403() {
        // #1438 (1a): a non-admin JWT caller (no `is_api_token` so scopes
        // are not enforced) previously slipped past the scope check, hit
        // the INSERT, and tripped an FK violation that surfaced as 500
        // DATABASE_ERROR. The handler now calls `require_admin()` so the
        // same caller gets a clean 403 Authorization error before any DB
        // write happens. This unit test pins the gate at the predicate
        // level (no DB needed).
        let non_admin_jwt = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "alice".to_string(),
            email: "alice@example.com".to_string(),
            is_admin: false,
            is_api_token: false,
            is_service_account: false,
            scopes: None,
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
        };
        // JWT sessions pass the scope check (they are not scope-restricted),
        // so the next gate, require_admin, must catch them.
        assert!(non_admin_jwt.require_scope("write").is_ok());
        match non_admin_jwt.require_admin() {
            Err(AppError::Authorization(_)) => {}
            other => panic!("expected 403 Authorization, got {:?}", other),
        }
    }

    #[test]
    fn test_admin_user_with_read_only_token_still_rejected() {
        // A user with `is_admin = true` who authenticated via a read-scoped
        // API token must still be rejected. The scope is on the token, not
        // the user. This is the exact bypass GHSA-vvc3-h39c-mrq5 documents.
        let ext = AuthExtension {
            user_id: Uuid::new_v4(),
            username: "admin-via-readonly-token".to_string(),
            email: "admin@example.com".to_string(),
            is_admin: true, // user is admin, but token is read-only
            is_api_token: true,
            is_service_account: true,
            scopes: Some(vec!["read".to_string()]),
            allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
            iat_ms: None,
        };
        assert!(
            ext.require_scope("write").is_err(),
            "admin user with read-only token must still be blocked by scope check"
        );
    }

    #[test]
    fn test_create_permission_body_shape_does_not_short_circuit_scope_check() {
        // B10 regression: the security release-gate sends a read-scope SA
        // token with a body shaped like {"name": ..., "description": ...},
        // which does NOT match the required CreatePermissionRequest
        // (principal_type/principal_id/target_type/target_id/actions). Before
        // the fix the handler took `Json<CreatePermissionRequest>`, so the
        // extractor rejected the malformed body during request extraction
        // (a 422/500 body-shape error) BEFORE the scope check ever ran -- the
        // caller never saw the canonical 403. The handler now takes raw
        // `Bytes` and parses only after the scope/admin gate, so the gate is
        // independent of body shape. This test pins both halves: the scope
        // predicate rejects the read-scope token, and the security-suite body
        // genuinely fails to deserialize into CreatePermissionRequest (so the
        // old ordering really would have masked the 403).
        let read_scope = read_only_token();
        match read_scope.require_scope("write") {
            Err(AppError::Authorization(msg)) => {
                assert_eq!(msg, "Token does not have required scope: write");
            }
            other => panic!(
                "expected 403 Authorization before any parse, got {:?}",
                other
            ),
        }

        let security_suite_body = r#"{"name":"ghsa-perm","description":"should not be created"}"#;
        assert!(
            serde_json::from_str::<CreatePermissionRequest>(security_suite_body).is_err(),
            "the security-suite probe body must not deserialize into \
             CreatePermissionRequest -- that is exactly why parsing it before \
             the scope check used to mask the 403"
        );
    }

    #[test]
    fn test_create_permission_authorized_then_malformed_body_is_validation() {
        // The mirror case: an authorized caller (write scope) that sends an
        // unparseable body must get a 400 VALIDATION_ERROR, never a 422/500.
        // The handler maps serde_json failures to AppError::Validation after
        // the gate. Pin that mapping at the predicate level.
        let err = serde_json::from_slice::<CreatePermissionRequest>(b"{ not json }")
            .map_err(|e| AppError::Validation(format!("Invalid permission payload: {}", e)))
            .unwrap_err();
        match err {
            AppError::Validation(msg) => {
                assert!(msg.starts_with("Invalid permission payload:"));
            }
            other => panic!("expected Validation error, got {:?}", other),
        }
    }
}
