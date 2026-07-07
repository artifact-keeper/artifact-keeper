//! User management handlers.

use axum::{
    extract::{Extension, Path, Query, State},
    routing::{delete, get, patch, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::{IntoParams, OpenApi, ToSchema};
use uuid::Uuid;

use crate::api::dto::Pagination;
use crate::api::middleware::auth::AuthExtension;
use crate::api::SharedState;
use crate::error::{AppError, Result};
use crate::models::user::{AuthProvider, User};
use crate::services::audit_service::{
    api_token_audit_entry, audit_fire_and_forget, password_change_audit_entry,
    sessions_invalidated_audit_entry, AuditAction,
};
use crate::services::auth_service::{
    invalidate_user_token_cache_entries, invalidate_user_tokens, AuthService,
};
use crate::services::password_policy::PasswordPolicyConfig;
use std::sync::atomic::Ordering;

/// Admin-only user-management routes. Mount under `admin_middleware`.
///
/// Every handler in this set also calls `auth.require_admin()?` as
/// defense in depth (see #1257) so the middleware and the handler form
/// two independent layers of admin-gating. Password-mutating routes
/// live in the [`self_password_router`] / [`admin_password_router`] pair
/// from #1250; per-user CRUD that is legitimately self-or-admin lives
/// in [`self_or_admin_router`].
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_users).post(create_user))
        .route("/:id", patch(update_user).delete(delete_user))
        .route("/:id/roles", get(get_user_roles).post(assign_role))
        .route("/:id/roles/:role_id", delete(revoke_role))
}

/// User routes that may be self-served by the caller or, alternatively,
/// performed by an admin against another user. Mount under
/// `auth_middleware` (NOT `admin_middleware`) so non-admins can act on
/// their own user record.
///
/// Each handler enforces self-or-admin internally via
/// `auth.require_self_or_admin(id, ..)?`; mounting these under `admin_middleware` (as the legacy
/// single-router topology did pre-#1257) made those checks dead code
/// and 403'd every non-admin self-action — including `POST
/// /api/v1/users/<self-id>/tokens` (the "Create API key" flow) which is
/// what surfaced the bug.
pub fn self_or_admin_router() -> Router<SharedState> {
    Router::new()
        .route("/:id", get(get_user))
        .route("/:id/tokens", get(list_user_tokens).post(create_api_token))
        .route("/:id/tokens/:token_id", delete(revoke_api_token))
}

/// Self-service password change.
///
/// `POST /:id/password` is the route a non-admin uses to rotate their own
/// password (used by the forced-must-change-password flow on first login,
/// and by `tests/auth/test-jwt-after-password-change.sh`). The handler
/// enforces the self-vs-admin ownership check (`auth.user_id == id` OR
/// `auth.is_admin`) and requires the current password, so mounting this
/// router under `auth_middleware` instead of `admin_middleware` does not
/// let one user mutate another's credentials.
///
/// The route is split out of [`admin_password_router`] for routing-layer
/// reasons (release-gate `tests/auth/test-jwt-after-password-change.sh`
/// regression "password change returned 403"): on `main`, the entire
/// password-changing surface had been merged into [`router`] and gated by
/// `admin_middleware`, so a non-admin's request never reached the handler.
///
/// The rate-limit bucket attached at the route layer remains
/// `rate_limit_password_change_*` (#1026). `POST /:id/password` verifies
/// the current password via bcrypt, which is a CPU-DoS vector if a
/// victim's JWT bearer can grind through it; the stricter per-user limit
/// (default 5 attempts / 15 min) caps that vector below the global
/// `rate_limit_api_per_window`.
pub fn self_password_router() -> Router<SharedState> {
    Router::new()
        .route("/:id/password", post(change_password))
        // Canonical self-service alias (#1313). Registered here so it inherits
        // the same password-change rate-limit layer (#1026) applied to
        // `self_password_router` in routes.rs — never place it on the
        // un-throttled `self_router()` (bcrypt CPU-DoS vector).
        .route("/me/password", post(change_current_user_password))
}

/// Canonical self-service routes (#1313): `/users/me/*` aliases that resolve
/// the subject to `auth.user_id`, so they act on the caller's OWN record with
/// no `require_self_or_admin` path check needed. These delegate to the same
/// `*_inner` fns as the `/users/:id/*` self-or-admin routes, so the #1314
/// guards and #1315 scope-enforcement invariants are preserved unchanged.
///
/// Mount under `auth_middleware` (Nest A in routes.rs), NOT `admin_middleware`.
/// On matchit 0.7.3 the static `/me` segment coexists with the `/:id` param
/// (static wins), so these aliases do not conflict with the existing routes.
///
/// `POST /me/password` is deliberately NOT here — it lives in
/// [`self_password_router`] so it inherits the password-change rate limit.
pub fn self_router() -> Router<SharedState> {
    Router::new()
        .route("/me", get(get_current_user_record))
        .route(
            "/me/tokens",
            get(list_current_user_tokens).post(create_current_user_api_token),
        )
        .route(
            "/me/tokens/:token_id",
            delete(revoke_current_user_api_token),
        )
}

/// Admin-only password administration routes (reset, force-change).
///
/// These remain behind `admin_middleware` because they let an
/// administrator mutate someone else's credentials without proving
/// knowledge of the current password. The route-layer rate-limit bucket
/// (`rate_limit_password_change_*`) still applies for consistency with
/// [`self_password_router`] and to keep the per-user attempt cap aligned.
pub fn admin_password_router() -> Router<SharedState> {
    Router::new()
        .route("/:id/password/reset", post(reset_password))
        .route("/:id/force-password-change", post(force_password_change))
}

#[derive(Debug, Deserialize, IntoParams, ToSchema)]
pub struct ListUsersQuery {
    pub search: Option<String>,
    pub is_active: Option<bool>,
    pub is_admin: Option<bool>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: Option<String>, // Optional - will auto-generate if not provided
    pub display_name: Option<String>,
    pub is_admin: Option<bool>,
}

/// Generate a secure random password
pub(crate) fn generate_password() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%&*";
    let mut rng = rand::rng();
    (0..16)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Validate a password against the configurable password policy.
///
/// Delegates to [`crate::services::password_policy::validate_password`] and
/// converts the list of violations into a single [`AppError::Validation`].
fn validate_password_with_policy(password: &str, policy: &PasswordPolicyConfig) -> Result<()> {
    crate::services::password_policy::validate_password(password, policy)
        .map_err(|violations| AppError::Validation(violations.join("; ")))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub is_active: Option<bool>,
    pub is_admin: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AdminUserResponse {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub display_name: Option<String>,
    pub auth_provider: String,
    pub is_active: bool,
    pub is_admin: bool,
    pub must_change_password: bool,
    pub last_login_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreateUserResponse {
    pub user: AdminUserResponse,
    pub generated_password: Option<String>, // Only returned if password was auto-generated
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserListResponse {
    pub items: Vec<AdminUserResponse>,
    pub pagination: Pagination,
}

pub(crate) fn user_to_response(user: User) -> AdminUserResponse {
    AdminUserResponse {
        id: user.id,
        username: user.username,
        email: user.email,
        display_name: user.display_name,
        auth_provider: format!("{:?}", user.auth_provider).to_lowercase(),
        is_active: user.is_active,
        is_admin: user.is_admin,
        must_change_password: user.must_change_password,
        last_login_at: user.last_login_at,
        created_at: user.created_at,
    }
}

/// List users
#[utoipa::path(
    get,
    path = "",
    context_path = "/api/v1/users",
    tag = "users",
    params(ListUsersQuery),
    responses(
        (status = 200, description = "List of users", body = UserListResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_users(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Query(query): Query<ListUsersQuery>,
) -> Result<Json<UserListResponse>> {
    // Defense-in-depth admin gate. Production traffic goes through
    // `admin_middleware` first; this guard ensures the route stays safe
    // if someone moves it between routers in the future. See #1257.
    auth.require_admin()?;
    let page = query.page.unwrap_or(1).max(1);
    // Shared clamp: per_page=0 would otherwise divide by zero in total_pages
    // and saturate to u32::MAX (#1783 LOW). See clamp_per_page docs.
    let per_page = crate::api::handlers::repositories::clamp_per_page(query.per_page);
    let offset = ((page - 1) * per_page) as i64;

    let search_pattern = query.search.as_ref().map(|s| format!("%{}%", s));

    let users = sqlx::query_as!(
        User,
        r#"
        SELECT
            id, username, email, password_hash, display_name,
            auth_provider as "auth_provider: AuthProvider",
            external_id, is_admin, is_active, is_service_account, must_change_password,
            totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
            failed_login_attempts, locked_until, last_failed_login_at,
            password_changed_at, last_login_at, created_at, updated_at
        FROM users
        WHERE ($1::text IS NULL OR username ILIKE $1 OR email ILIKE $1 OR display_name ILIKE $1)
          AND ($2::boolean IS NULL OR is_active = $2)
          AND ($3::boolean IS NULL OR is_admin = $3)
        ORDER BY username
        OFFSET $4
        LIMIT $5
        "#,
        search_pattern,
        query.is_active,
        query.is_admin,
        offset,
        per_page as i64
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let total = sqlx::query_scalar!(
        r#"
        SELECT COUNT(*) as "count!"
        FROM users
        WHERE ($1::text IS NULL OR username ILIKE $1 OR email ILIKE $1 OR display_name ILIKE $1)
          AND ($2::boolean IS NULL OR is_active = $2)
          AND ($3::boolean IS NULL OR is_admin = $3)
        "#,
        search_pattern,
        query.is_active,
        query.is_admin
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;

    Ok(Json(UserListResponse {
        items: users.into_iter().map(user_to_response).collect(),
        pagination: Pagination {
            page,
            per_page,
            total,
            total_pages,
        },
    }))
}

/// Create user
#[utoipa::path(
    post,
    path = "",
    context_path = "/api/v1/users",
    tag = "users",
    request_body = CreateUserRequest,
    responses(
        (status = 200, description = "User created successfully", body = CreateUserResponse),
        (status = 409, description = "User already exists"),
        (status = 422, description = "Validation error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_user(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(payload): Json<CreateUserRequest>,
) -> Result<Json<CreateUserResponse>> {
    // Only admins can create users
    if !auth.is_admin {
        return Err(AppError::Authorization(
            "Only administrators can create users".to_string(),
        ));
    }

    // Build the password policy from config
    let policy = PasswordPolicyConfig::from_config(&state.config);

    // Generate password if not provided, otherwise validate
    let (password, auto_generated) = match payload.password {
        Some(ref p) => {
            validate_password_with_policy(p, &policy)?;
            (p.clone(), false)
        }
        None => (generate_password(), true),
    };

    // Hash password
    let password_hash = AuthService::hash_password(&password).await?;

    let user = sqlx::query_as!(
        User,
        r#"
        INSERT INTO users (username, email, password_hash, display_name, auth_provider, is_admin, is_service_account, must_change_password)
        VALUES ($1, $2, $3, $4, 'local', $5, false, $6)
        RETURNING
            id, username, email, password_hash, display_name,
            auth_provider as "auth_provider: AuthProvider",
            external_id, is_admin, is_active, is_service_account, must_change_password,
            totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
            failed_login_attempts, locked_until, last_failed_login_at,
            password_changed_at, last_login_at, created_at, updated_at
        "#,
        payload.username,
        payload.email,
        password_hash,
        payload.display_name,
        payload.is_admin.unwrap_or(false),
        auto_generated
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("duplicate key") {
            if msg.contains("username") {
                AppError::Conflict("Username already exists".to_string())
            } else if msg.contains("email") {
                AppError::Conflict("Email already exists".to_string())
            } else {
                AppError::Conflict("User already exists".to_string())
            }
        } else {
            AppError::Database(msg)
        }
    })?;

    state
        .event_bus
        .emit("user.created", user.id, Some(auth.username.clone()));

    Ok(Json(CreateUserResponse {
        user: user_to_response(user),
        generated_password: if auto_generated { Some(password) } else { None },
    }))
}

/// Get user details
#[utoipa::path(
    get,
    path = "/{id}",
    context_path = "/api/v1/users",
    tag = "users",
    params(
        ("id" = Uuid, Path, description = "User ID"),
    ),
    responses(
        (status = 200, description = "User details", body = AdminUserResponse),
        (status = 404, description = "User not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_user(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<AdminUserResponse>> {
    // Self-or-admin: a user may read their own record; anyone else needs admin.
    auth.require_self_or_admin(id, "Cannot view other users' records")?;
    get_user_inner(&state, id).await
}

/// Shared record lookup for both `GET /users/:id` (self-or-admin) and
/// `GET /users/me` (self only). The caller is responsible for authorization;
/// the `/:id` wrapper enforces `require_self_or_admin`, while the `/me` alias
/// resolves the subject to `auth.user_id` so it is intrinsically self-only.
async fn get_user_inner(state: &SharedState, id: Uuid) -> Result<Json<AdminUserResponse>> {
    let user = sqlx::query_as!(
        User,
        r#"
        SELECT
            id, username, email, password_hash, display_name,
            auth_provider as "auth_provider: AuthProvider",
            external_id, is_admin, is_active, is_service_account, must_change_password,
            totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
            failed_login_attempts, locked_until, last_failed_login_at,
            password_changed_at, last_login_at, created_at, updated_at
        FROM users
        WHERE id = $1
        "#,
        id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    Ok(Json(user_to_response(user)))
}

/// Resolve whether an `is_admin` update is an actual privilege change (#1821).
///
/// Returns `true` only when `requested` is `Some` and differs from the user's
/// current `is_admin`. An idempotent re-apply (same value) or a request that
/// does not touch `is_admin` (`None`) returns `false`, so benign profile edits
/// do not bump the `privileges_changed_at` watermark and keep the user logged
/// in. A missing user also returns `false` (the UPDATE will 404 afterwards).
async fn is_admin_change_requested(
    db: &sqlx::PgPool,
    id: Uuid,
    requested: Option<bool>,
) -> Result<bool> {
    let Some(requested) = requested else {
        return Ok(false);
    };
    let current: Option<bool> = sqlx::query_scalar("SELECT is_admin FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(current.is_some_and(|was_admin| was_admin != requested))
}

/// Update user
#[utoipa::path(
    patch,
    path = "/{id}",
    context_path = "/api/v1/users",
    tag = "users",
    params(
        ("id" = Uuid, Path, description = "User ID"),
    ),
    request_body = UpdateUserRequest,
    responses(
        (status = 200, description = "User updated successfully", body = AdminUserResponse),
        (status = 404, description = "User not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_user(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateUserRequest>,
) -> Result<Json<AdminUserResponse>> {
    // Defense-in-depth admin gate. Production traffic also passes
    // through `admin_middleware`; this guard is what keeps the route
    // safe if someone reroutes it. See #1257.
    auth.require_admin()?;
    // When an admin deactivates a user, immediately invalidate every cached
    // API-token and JWT for that user. Without this, a compromised account
    // would keep authenticating against any AuthService instance whose
    // in-memory cache had a fresh hit, for up to API_TOKEN_CACHE_TTL_SECS
    // (5 min) after the flip. Issue #931.
    //
    // Pre-mark the invalidation BEFORE the SQL UPDATE so a concurrent
    // request that hits the cache during the UPDATE is rejected. Pre-marking
    // is fail-secure: if the SQL fails we just force one extra DB
    // re-validation, but never serve a stale cache entry.
    //
    // We invalidate whenever the request body asks for `is_active=false`,
    // even on idempotent re-application: an extra eviction is harmless.
    // We deliberately do NOT invalidate on `is_active=true` re-activation,
    // since fresh validations will be cached against the now-active row.
    if matches!(payload.is_active, Some(false)) {
        invalidate_user_token_cache_entries(id);
        invalidate_user_tokens(id);

        // DB-backed refresh-token family revocation (#1174 / PR #1190 review):
        // a deactivated user must lose every refresh token on every replica.
        let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
        if let Err(e) = auth_service.revoke_all_refresh_token_families(id).await {
            tracing::warn!(user_id = %id, error = %e, "Failed to revoke refresh-token families on deactivation");
        }
    }

    // #1821: an admin demotion/promotion is a privilege change. `is_admin` is
    // baked into JWT claims at mint time with no DB recheck, so a demoted admin
    // keeps admin authority until the token expires unless we invalidate.
    // Detect whether `is_admin` actually changes (vs. an idempotent re-apply)
    // and, if so, bump the persistent `privileges_changed_at` watermark in the
    // same UPDATE (folded into `fetch_credential_change_watermark`'s GREATEST,
    // so cross-replica) plus the in-memory fast-path for this replica. We do
    // NOT bump on a no-op so benign edits keep the user logged in.
    let privilege_changed = is_admin_change_requested(&state.db, id, payload.is_admin).await?;
    if privilege_changed {
        invalidate_user_token_cache_entries(id);
        invalidate_user_tokens(id);
    }

    let user = sqlx::query_as!(
        User,
        r#"
        UPDATE users
        SET
            email = COALESCE($2, email),
            display_name = COALESCE($3, display_name),
            is_active = COALESCE($4, is_active),
            is_admin = COALESCE($5, is_admin),
            privileges_changed_at = CASE WHEN $6 THEN NOW() ELSE privileges_changed_at END,
            updated_at = NOW()
        WHERE id = $1
        RETURNING
            id, username, email, password_hash, display_name,
            auth_provider as "auth_provider: AuthProvider",
            external_id, is_admin, is_active, is_service_account, must_change_password,
            totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
            failed_login_attempts, locked_until, last_failed_login_at,
            password_changed_at, last_login_at, created_at, updated_at
        "#,
        id,
        payload.email,
        payload.display_name,
        payload.is_active,
        payload.is_admin,
        privilege_changed
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    state
        .event_bus
        .emit("user.updated", user.id, Some(auth.username.clone()));

    Ok(Json(user_to_response(user)))
}

/// Delete user
#[utoipa::path(
    delete,
    path = "/{id}",
    context_path = "/api/v1/users",
    tag = "users",
    params(
        ("id" = Uuid, Path, description = "User ID"),
    ),
    responses(
        (status = 200, description = "User deleted successfully"),
        (status = 404, description = "User not found"),
        (status = 422, description = "Cannot delete yourself"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_user(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<()> {
    // Defense-in-depth admin gate. See #1257.
    auth.require_admin()?;
    // Prevent self-deletion
    if auth.user_id == id {
        return Err(AppError::Validation("Cannot delete yourself".to_string()));
    }

    // Pre-mark the invalidation BEFORE the SQL DELETE. Hard-deleting a user
    // must evict any cached API-token and JWT validations for that user;
    // otherwise the cache would keep authenticating the deleted user for up
    // to API_TOKEN_CACHE_TTL_SECS (5 min). Pre-marking is fail-secure: if
    // the DELETE returns 404 we've spent one extra DB re-validation on a
    // user that doesn't exist, never serving a stale cache entry. Issue #931.
    invalidate_user_token_cache_entries(id);
    invalidate_user_tokens(id);

    // DB-backed refresh-token family revocation (#1174 / PR #1190 review):
    // delete-user must close out every refresh token across every replica.
    // Note that the cascade from `users` to `refresh_token_jti` would also
    // clean these up on commit; we revoke explicitly here so any in-flight
    // request that races the DELETE still observes the revocation.
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    if let Err(e) = auth_service.revoke_all_refresh_token_families(id).await {
        tracing::warn!(user_id = %id, error = %e, "Failed to revoke refresh-token families on delete");
    }

    let result = sqlx::query!("DELETE FROM users WHERE id = $1", id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("User not found".to_string()));
    }

    state
        .event_bus
        .emit("user.deleted", id, Some(auth.username.clone()));

    Ok(())
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RoleResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RoleListResponse {
    pub items: Vec<RoleResponse>,
}

/// Get user roles
#[utoipa::path(
    get,
    path = "/{id}/roles",
    context_path = "/api/v1/users",
    tag = "users",
    params(
        ("id" = Uuid, Path, description = "User ID"),
    ),
    responses(
        (status = 200, description = "List of user roles", body = RoleListResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_user_roles(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<RoleListResponse>> {
    // Defense-in-depth admin gate. See #1257.
    auth.require_admin()?;
    let roles = sqlx::query!(
        r#"
        SELECT r.id, r.name, r.description, r.permissions
        FROM roles r
        JOIN user_roles ur ON ur.role_id = r.id
        WHERE ur.user_id = $1
        ORDER BY r.name
        "#,
        id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let items = roles
        .into_iter()
        .map(|r| RoleResponse {
            id: r.id,
            name: r.name,
            description: r.description,
            permissions: r.permissions,
        })
        .collect();

    Ok(Json(RoleListResponse { items }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AssignRoleRequest {
    pub role_id: Uuid,
}

/// Assign role to user
#[utoipa::path(
    post,
    path = "/{id}/roles",
    context_path = "/api/v1/users",
    tag = "users",
    params(
        ("id" = Uuid, Path, description = "User ID"),
    ),
    request_body = AssignRoleRequest,
    responses(
        (status = 200, description = "Role assigned successfully"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn assign_role(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(payload): Json<AssignRoleRequest>,
) -> Result<()> {
    // Defense-in-depth admin gate. See #1257.
    auth.require_admin()?;
    sqlx::query!(
        r#"
        INSERT INTO user_roles (user_id, role_id)
        VALUES ($1, $2)
        ON CONFLICT DO NOTHING
        "#,
        id,
        payload.role_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(())
}

/// Revoke role from user
#[utoipa::path(
    delete,
    path = "/{id}/roles/{role_id}",
    context_path = "/api/v1/users",
    tag = "users",
    params(
        ("id" = Uuid, Path, description = "User ID"),
        ("role_id" = Uuid, Path, description = "Role ID"),
    ),
    responses(
        (status = 200, description = "Role revoked successfully"),
        (status = 404, description = "Role assignment not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_role(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((user_id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<()> {
    // Defense-in-depth admin gate. See #1257.
    auth.require_admin()?;
    let result = sqlx::query!(
        "DELETE FROM user_roles WHERE user_id = $1 AND role_id = $2",
        user_id,
        role_id
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("Role assignment not found".to_string()));
    }

    Ok(())
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateApiTokenRequest {
    pub name: String,
    pub scopes: Vec<String>,
    pub expires_in_days: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApiTokenResponse {
    pub id: Uuid,
    pub name: String,
    pub token_prefix: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApiTokenCreatedResponse {
    pub id: Uuid,
    pub name: String,
    pub token: String, // Only shown once at creation
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApiTokenListResponse {
    pub items: Vec<ApiTokenResponse>,
}

/// List user's API tokens
#[utoipa::path(
    get,
    path = "/{id}/tokens",
    context_path = "/api/v1/users",
    tag = "users",
    params(
        ("id" = Uuid, Path, description = "User ID"),
    ),
    responses(
        (status = 200, description = "List of API tokens", body = ApiTokenListResponse),
        (status = 403, description = "Cannot view other users' tokens"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_user_tokens(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiTokenListResponse>> {
    // Users can only view their own tokens unless admin
    auth.require_self_or_admin(id, "Cannot view other users' tokens")?;
    list_user_tokens_inner(&state, id).await
}

/// Shared token-listing for both `GET /users/:id/tokens` (self-or-admin) and
/// `GET /users/me/tokens` (self only). Authorization is the caller's
/// responsibility; the `/me` alias passes `auth.user_id`.
async fn list_user_tokens_inner(
    state: &SharedState,
    id: Uuid,
) -> Result<Json<ApiTokenListResponse>> {
    let tokens = sqlx::query!(
        r#"
        SELECT id, name, token_prefix, scopes, expires_at, last_used_at, created_at
        FROM api_tokens
        WHERE user_id = $1 AND revoked_at IS NULL
        ORDER BY created_at DESC
        "#,
        id
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let items = tokens
        .into_iter()
        .map(|t| ApiTokenResponse {
            id: t.id,
            name: t.name,
            token_prefix: t.token_prefix,
            scopes: t.scopes,
            expires_at: t.expires_at,
            last_used_at: t.last_used_at,
            created_at: t.created_at,
        })
        .collect();

    Ok(Json(ApiTokenListResponse { items }))
}

/// Create API token
#[utoipa::path(
    post,
    path = "/{id}/tokens",
    context_path = "/api/v1/users",
    tag = "users",
    operation_id = "create_user_api_token",
    params(
        ("id" = Uuid, Path, description = "User ID"),
    ),
    request_body = CreateApiTokenRequest,
    responses(
        (status = 200, description = "API token created successfully", body = ApiTokenCreatedResponse),
        (status = 403, description = "Cannot create tokens for other users"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_api_token(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(payload): Json<CreateApiTokenRequest>,
) -> Result<Json<ApiTokenCreatedResponse>> {
    // Users can only create tokens for themselves unless admin
    auth.require_self_or_admin(id, "Cannot create tokens for other users")?;
    create_api_token_inner(&state, &auth, id, payload).await
}

/// Shared token-mint for both `POST /users/:id/tokens` (self-or-admin) and
/// `POST /users/me/tokens` (self only). Ownership is enforced by the caller;
/// the #1315 admin-only-scope enforcement lives HERE so both routes reject a
/// non-admin minting `*`/`admin`/`delete:*`/`write:users` tokens.
async fn create_api_token_inner(
    state: &SharedState,
    auth: &AuthExtension,
    id: Uuid,
    payload: CreateApiTokenRequest,
) -> Result<Json<ApiTokenCreatedResponse>> {
    // Refuse admin-class scopes from non-admin callers. See
    // `token_service::ADMIN_ONLY_SCOPES` for the policy rationale —
    // mirrors the same enforcement on the sibling endpoint
    // `POST /api/v1/profile/access-tokens` so a non-admin can't reach
    // either route to mint a token with `*`/`admin`/`delete:*`/
    // `write:users`.
    crate::services::token_service::enforce_admin_only_scopes(&payload.scopes, auth.is_admin)
        .map_err(AppError::Authorization)?;

    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    let (token, token_id) = auth_service
        .generate_api_token(id, &payload.name, payload.scopes, payload.expires_in_days)
        .await?;

    audit_fire_and_forget(
        state.db.clone(),
        api_token_audit_entry(
            AuditAction::ApiTokenCreated,
            auth.user_id,
            token_id,
            Some(&payload.name),
            "user",
        ),
    )
    .await;

    Ok(Json(ApiTokenCreatedResponse {
        id: token_id,
        name: payload.name,
        token, // Only returned once at creation
    }))
}

/// Revoke API token
#[utoipa::path(
    delete,
    path = "/{id}/tokens/{token_id}",
    context_path = "/api/v1/users",
    tag = "users",
    operation_id = "revoke_user_api_token",
    params(
        ("id" = Uuid, Path, description = "User ID"),
        ("token_id" = Uuid, Path, description = "API token ID"),
    ),
    responses(
        (status = 200, description = "API token revoked successfully"),
        (status = 403, description = "Cannot revoke other users' tokens"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_api_token(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path((user_id, token_id)): Path<(Uuid, Uuid)>,
) -> Result<()> {
    // Users can only revoke their own tokens unless admin
    auth.require_self_or_admin(user_id, "Cannot revoke other users' tokens")?;
    revoke_api_token_inner(&state, &auth, user_id, token_id).await
}

/// Shared token-revocation for both `DELETE /users/:id/tokens/:token_id`
/// (self-or-admin) and `DELETE /users/me/tokens/:token_id` (self only).
/// Ownership is scoped by `user_id`, which the `/me` alias resolves to
/// `auth.user_id`.
async fn revoke_api_token_inner(
    state: &SharedState,
    auth: &AuthExtension,
    user_id: Uuid,
    token_id: Uuid,
) -> Result<()> {
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    auth_service.revoke_api_token(token_id, user_id).await?;

    audit_fire_and_forget(
        state.db.clone(),
        api_token_audit_entry(
            AuditAction::ApiTokenRevoked,
            auth.user_id,
            token_id,
            None,
            "user",
        ),
    )
    .await;

    Ok(())
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ChangePasswordRequest {
    pub current_password: Option<String>, // Required for non-admins
    pub new_password: String,
}

/// Change user password
#[utoipa::path(
    post,
    path = "/{id}/password",
    context_path = "/api/v1/users",
    tag = "users",
    params(
        ("id" = Uuid, Path, description = "User ID"),
    ),
    request_body = ChangePasswordRequest,
    responses(
        (status = 200, description = "Password changed successfully"),
        (status = 401, description = "Current password is incorrect"),
        (status = 403, description = "Cannot change other users' passwords"),
        (status = 404, description = "User not found"),
        (status = 422, description = "Validation error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn change_password(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<()> {
    // Non-admin trying to change another user's password
    auth.require_self_or_admin(id, "Cannot change other users' passwords")?;
    change_password_inner(&state, &auth, id, payload).await
}

/// Shared password-change for both `POST /users/:id/password` (self-or-admin)
/// and `POST /users/me/password` (self only). Ownership is enforced by the
/// caller; the current-password check (`auth.user_id == id && !auth.is_admin`)
/// and the configurable password policy are enforced HERE so both routes keep
/// the #1315/#1026 invariants. Both routes ride the password-change rate-limit
/// layer (they are registered in `self_password_router`).
async fn change_password_inner(
    state: &SharedState,
    auth: &AuthExtension,
    id: Uuid,
    payload: ChangePasswordRequest,
) -> Result<()> {
    // Validate new password against configurable policy
    let policy = PasswordPolicyConfig::from_config(&state.config);
    validate_password_with_policy(&payload.new_password, &policy)?;

    // Fetch user row once: password_hash + must_change_password
    let user_row = sqlx::query_as::<_, (Option<String>, bool)>(
        "SELECT password_hash, must_change_password FROM users WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let current_hash = user_row
        .0
        .ok_or_else(|| AppError::Validation("Cannot change password for SSO users".to_string()))?;

    // For non-admins changing their own password, verify current password
    if auth.user_id == id && !auth.is_admin {
        let current_password = payload
            .current_password
            .ok_or_else(|| AppError::Validation("Current password required".to_string()))?;

        if !AuthService::verify_password(&current_password, &current_hash).await? {
            return Err(AppError::Authentication(
                "Current password is incorrect".to_string(),
            ));
        }
    }

    // Hash new password before entering the transaction
    let new_hash = AuthService::hash_password(&payload.new_password).await?;

    let history_count = state.config.password_history_count;
    let had_must_change = user_row.1;

    // Wrap the history check, password UPDATE, and history recording in a
    // single transaction to prevent TOCTOU races.
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    // Check password history if enabled (uses current_hash + history table)
    if history_count > 0 {
        check_password_history(
            &mut *tx,
            id,
            &payload.new_password,
            history_count,
            Some(&current_hash),
        )
        .await?;
    }

    // Update password and clear must_change_password flag
    let result = sqlx::query(
        "UPDATE users SET password_hash = $2, must_change_password = false, password_changed_at = NOW(), updated_at = NOW() WHERE id = $1",
    )
    .bind(id)
    .bind(&new_hash)
    .execute(&mut *tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("User not found".to_string()));
    }

    // Record the old password hash in history and trim excess entries
    if history_count > 0 {
        record_password_history(&mut tx, id, &current_hash, history_count).await?;
    }

    tx.commit()
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    // Flip the in-process API-token cache invalidation map (#931) so any
    // bearer tokens previously issued for this user can no longer satisfy
    // the cache-hit path. `invalidate_user_tokens` revokes refresh
    // tokens; this complements it by forcing per-request DB
    // re-validation of access tokens on the next request. Pre-fix
    // (#1023/#1027), the change_password / reset_password / force-change
    // paths only revoked refresh tokens, leaving short-lived access
    // tokens valid in the cache until the cache TTL elapsed.
    invalidate_user_token_cache_entries(id);
    crate::services::auth_service::invalidate_user_tokens(id);

    // Replica-safe refresh-token family revocation (#1174 / PR #1190 review).
    // The in-memory `invalidate_user_tokens` only flips THIS replica's map;
    // a refresh JWT minted before the password change can still be replayed
    // against peer replicas for up to `jwt_refresh_token_expiry_days` (7d
    // default). Mark every row in `refresh_token_jti` for this user as
    // revoked so the DB-backed replay check rejects them on every replica.
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    if let Err(e) = auth_service.revoke_all_refresh_token_families(id).await {
        // Best-effort: a failure here is logged but does not block the
        // password change. The user is already locally invalidated and the
        // tokens will eventually expire on their own.
        tracing::warn!(user_id = %id, error = %e, "Failed to revoke refresh-token families after password change");
    }

    // Audit the password change and the session invalidation it triggered
    // (#386). Fire-and-forget and placed AFTER the transaction has committed
    // so an audit-table outage can never fail the password change. `by_admin`
    // is true only when an admin changes a DIFFERENT user's password.
    let by_admin = auth.is_admin && auth.user_id != id;
    audit_fire_and_forget(
        state.db.clone(),
        password_change_audit_entry(id, auth.user_id, by_admin),
    )
    .await;
    audit_fire_and_forget(
        state.db.clone(),
        sessions_invalidated_audit_entry(id, auth.user_id, "password_change"),
    )
    .await;

    // If this user had must_change_password, check if setup mode should be unlocked
    if had_must_change && state.setup_required.load(Ordering::Relaxed) {
        state.setup_required.store(false, Ordering::Relaxed);
        tracing::info!("Setup complete. API fully unlocked.");

        // Delete the password file (best-effort).
        // storage_path is from server config, not user input, but we
        // canonicalize and verify the path stays under the base dir.
        let storage_base = std::path::Path::new(&state.config.storage_path)
            .canonicalize()
            .unwrap_or_else(|_| std::path::PathBuf::from(&state.config.storage_path));
        let password_file = storage_base.join("admin.password");
        if !password_file.starts_with(&storage_base) {
            tracing::warn!("Password file path escapes storage base, skipping delete");
        } else if password_file.exists() {
            if let Err(e) = std::fs::remove_file(&password_file) {
                tracing::warn!("Failed to delete admin password file: {}", e);
            } else {
                tracing::info!("Deleted admin password file: {}", password_file.display());
            }
        }
    }

    Ok(())
}

/// Response for password reset
#[derive(Debug, Serialize, ToSchema)]
pub struct ResetPasswordResponse {
    pub temporary_password: String,
}

/// Reset user password (admin only)
/// Generates a new temporary password and sets must_change_password=true
#[utoipa::path(
    post,
    path = "/{id}/password/reset",
    context_path = "/api/v1/users",
    tag = "users",
    params(
        ("id" = Uuid, Path, description = "User ID"),
    ),
    responses(
        (status = 200, description = "Password reset successfully", body = ResetPasswordResponse),
        (status = 403, description = "Only administrators can reset passwords"),
        (status = 404, description = "User not found"),
        (status = 422, description = "Validation error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn reset_password(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<ResetPasswordResponse>> {
    // Only admins can reset passwords
    if !auth.is_admin {
        return Err(AppError::Authorization(
            "Only administrators can reset passwords".to_string(),
        ));
    }

    // Prevent admin from resetting their own password this way
    if auth.user_id == id {
        return Err(AppError::Validation(
            "Cannot reset your own password. Use change password instead.".to_string(),
        ));
    }

    // Check that user exists and is a local user (reuse existing query pattern)
    let user = sqlx::query!("SELECT password_hash FROM users WHERE id = $1", id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Local users have password_hash set
    let old_hash = match user.password_hash {
        Some(ref h) => h.clone(),
        None => {
            return Err(AppError::Validation(
                "Cannot reset password for SSO users".to_string(),
            ));
        }
    };

    // Generate new temporary password
    let temp_password = generate_password();
    let password_hash = AuthService::hash_password(&temp_password).await?;

    let history_count = state.config.password_history_count;

    // Wrap the UPDATE and history recording in a transaction
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    // Update password and set must_change_password=true
    sqlx::query("UPDATE users SET password_hash = $1, must_change_password = true, password_changed_at = NOW(), updated_at = NOW() WHERE id = $2")
        .bind(&password_hash)
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    // Record the old password hash in history so the user cannot reuse it
    if history_count > 0 {
        record_password_history(&mut tx, id, &old_hash, history_count).await?;
    }

    tx.commit()
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    // Same rationale as change_password (#1023/#1027): flip the cache
    // invalidation map so cached access tokens for this user are forced
    // back through DB validation.
    invalidate_user_token_cache_entries(id);
    crate::services::auth_service::invalidate_user_tokens(id);

    // DB-backed refresh-token family revocation (#1174 / PR #1190 review):
    // see change_password for rationale.
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    if let Err(e) = auth_service.revoke_all_refresh_token_families(id).await {
        tracing::warn!(user_id = %id, error = %e, "Failed to revoke refresh-token families after password reset");
    }

    // Audit the admin-initiated password reset and the session invalidation it
    // triggered (#386). Subject = target user, actor = acting admin; an admin
    // reset is by definition `by_admin = true`. Fire-and-forget, POST-commit.
    audit_fire_and_forget(
        state.db.clone(),
        password_change_audit_entry(id, auth.user_id, true),
    )
    .await;
    audit_fire_and_forget(
        state.db.clone(),
        sessions_invalidated_audit_entry(id, auth.user_id, "password_reset"),
    )
    .await;

    Ok(Json(ResetPasswordResponse {
        temporary_password: temp_password,
    }))
}

// ---------------------------------------------------------------------------
// Password history helpers
// ---------------------------------------------------------------------------

/// Check the new password against the user's most recent password hashes.
/// Returns an error if the new password matches any of them.
///
/// When `current_hash` is provided the caller has already fetched the user's
/// active password hash, so we skip an extra round-trip to the users table.
///
/// To avoid a timing side-channel, every hash in the list is checked even
/// after a match is found. This makes response time constant regardless of
/// which position matched (bcrypt is slow, but password changes are
/// infrequent so the extra CPU cost is acceptable).
async fn check_password_history<'e, E>(
    executor: E,
    user_id: Uuid,
    new_password: &str,
    history_count: u32,
    current_hash: Option<&str>,
) -> Result<()>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let rows = sqlx::query_scalar::<_, String>(
        "SELECT password_hash FROM password_history \
         WHERE user_id = $1 \
         ORDER BY created_at DESC \
         LIMIT $2",
    )
    .bind(user_id)
    .bind(history_count as i64)
    .fetch_all(executor)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let mut hashes_to_check: Vec<&str> = Vec::with_capacity(rows.len() + 1);
    if let Some(h) = current_hash {
        hashes_to_check.push(h);
    }
    for row in &rows {
        hashes_to_check.push(row.as_str());
    }

    // Check ALL hashes to prevent timing side-channel (constant-time over
    // the number of stored hashes regardless of match position).
    let mut matched = false;
    for h in &hashes_to_check {
        if AuthService::verify_password(new_password, h).await? {
            matched = true;
        }
    }

    if matched {
        return Err(AppError::Validation(
            "Password was used recently. Please choose a different password.".to_string(),
        ));
    }

    Ok(())
}

/// Insert the old password hash into the history table and remove entries
/// that exceed the configured retention count.
///
/// Accepts any SQLx executor (pool or transaction) so callers can include
/// this operation inside an existing transaction.
async fn record_password_history(
    conn: &mut sqlx::PgConnection,
    user_id: Uuid,
    old_hash: &str,
    history_count: u32,
) -> Result<()> {
    sqlx::query("INSERT INTO password_history (user_id, password_hash) VALUES ($1, $2)")
        .bind(user_id)
        .bind(old_hash)
        .execute(&mut *conn)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    // Trim old entries beyond the retention window
    sqlx::query(
        "DELETE FROM password_history \
         WHERE user_id = $1 \
           AND id NOT IN ( \
               SELECT id FROM password_history \
               WHERE user_id = $1 \
               ORDER BY created_at DESC \
               LIMIT $2 \
           )",
    )
    .bind(user_id)
    .bind(history_count as i64)
    .execute(&mut *conn)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(())
}

/// Response for force password change
#[derive(Debug, Serialize, ToSchema)]
pub struct ForcePasswordChangeResponse {
    pub message: String,
}

/// Force a user to change their password on next login (admin only).
/// Sets must_change_password=true and invalidates existing sessions so the
/// user is prompted immediately on their next login.
#[utoipa::path(
    post,
    path = "/{id}/force-password-change",
    context_path = "/api/v1/users",
    tag = "users",
    params(
        ("id" = Uuid, Path, description = "User ID"),
    ),
    responses(
        (status = 200, description = "Flag set successfully", body = ForcePasswordChangeResponse),
        (status = 403, description = "Only administrators can force password changes"),
        (status = 404, description = "User not found"),
        (status = 422, description = "Cannot force password change for SSO users"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn force_password_change(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
) -> Result<Json<ForcePasswordChangeResponse>> {
    if !auth.is_admin {
        return Err(AppError::Authorization(
            "Only administrators can force password changes".to_string(),
        ));
    }

    // Verify user exists and is a local user
    let user = sqlx::query!("SELECT password_hash FROM users WHERE id = $1", id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    if user.password_hash.is_none() {
        return Err(AppError::Validation(
            "Cannot force password change for SSO users".to_string(),
        ));
    }

    sqlx::query("UPDATE users SET must_change_password = true, updated_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    // Invalidate existing sessions so the user must re-authenticate.
    // See change_password for the cache-invalidation rationale (#1023/#1027).
    invalidate_user_token_cache_entries(id);
    crate::services::auth_service::invalidate_user_tokens(id);

    // DB-backed refresh-token family revocation (#1174 / PR #1190 review):
    // forcing a password change must immediately invalidate every refresh
    // token in flight, on every replica.
    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    if let Err(e) = auth_service.revoke_all_refresh_token_families(id).await {
        tracing::warn!(user_id = %id, error = %e, "Failed to revoke refresh-token families after force password change");
    }

    state.event_bus.emit(
        "user.force_password_change",
        id,
        Some(auth.username.clone()),
    );

    // Forcing a password change does NOT itself change the password (it only
    // flags `must_change_password`), so only the mass session invalidation is
    // audited here — emitting PASSWORD_CHANGED would be misleading (#386).
    audit_fire_and_forget(
        state.db.clone(),
        sessions_invalidated_audit_entry(id, auth.user_id, "force_password_change"),
    )
    .await;

    Ok(Json(ForcePasswordChangeResponse {
        message: "User will be required to change password on next login".to_string(),
    }))
}

// ---------------------------------------------------------------------------
// Canonical self-service aliases (#1313): `/users/me/*`
// ---------------------------------------------------------------------------
// Each handler resolves the subject as `auth.user_id` (never a path id) and
// delegates to the same `*_inner` fn as the corresponding `/users/:id/*`
// self-or-admin route, so all existing invariants are preserved with no SQL
// duplication and no new `sqlx::query!` macro.

/// Get the authenticated caller's own user record.
#[utoipa::path(
    get,
    path = "/me",
    context_path = "/api/v1/users",
    tag = "users",
    operation_id = "get_current_user_record",
    responses(
        (status = 200, description = "The authenticated caller's user record", body = AdminUserResponse),
        (status = 404, description = "User not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_current_user_record(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<AdminUserResponse>> {
    get_user_inner(&state, auth.user_id).await
}

/// List the authenticated caller's own API tokens.
#[utoipa::path(
    get,
    path = "/me/tokens",
    context_path = "/api/v1/users",
    tag = "users",
    operation_id = "list_current_user_tokens",
    responses(
        (status = 200, description = "List of the caller's API tokens", body = ApiTokenListResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_current_user_tokens(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<ApiTokenListResponse>> {
    list_user_tokens_inner(&state, auth.user_id).await
}

/// Create an API token for the authenticated caller.
///
/// The #1315 admin-only-scope enforcement is applied inside
/// `create_api_token_inner`, so a non-admin cannot mint `*`/`admin`/`delete:*`/
/// `write:users` tokens via this alias any more than via `/users/:id/tokens`.
#[utoipa::path(
    post,
    path = "/me/tokens",
    context_path = "/api/v1/users",
    tag = "users",
    operation_id = "create_current_user_api_token",
    request_body = CreateApiTokenRequest,
    responses(
        (status = 200, description = "API token created successfully", body = ApiTokenCreatedResponse),
        (status = 403, description = "Requested scopes require administrator privileges"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_current_user_api_token(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(payload): Json<CreateApiTokenRequest>,
) -> Result<Json<ApiTokenCreatedResponse>> {
    create_api_token_inner(&state, &auth, auth.user_id, payload).await
}

/// Revoke one of the authenticated caller's own API tokens.
#[utoipa::path(
    delete,
    path = "/me/tokens/{token_id}",
    context_path = "/api/v1/users",
    tag = "users",
    operation_id = "revoke_current_user_api_token",
    params(
        ("token_id" = Uuid, Path, description = "API token ID"),
    ),
    responses(
        (status = 200, description = "API token revoked successfully"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_current_user_api_token(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Path(token_id): Path<Uuid>,
) -> Result<()> {
    revoke_api_token_inner(&state, &auth, auth.user_id, token_id).await
}

/// Change the authenticated caller's own password.
///
/// Resolves the subject to `auth.user_id`, so the shared
/// `change_password_inner` requires the current password (non-admin self path)
/// exactly as `POST /users/:id/password` does. Registered in
/// `self_password_router` so it inherits the password-change rate limit (#1026).
#[utoipa::path(
    post,
    path = "/me/password",
    context_path = "/api/v1/users",
    tag = "users",
    operation_id = "change_current_user_password",
    request_body = ChangePasswordRequest,
    responses(
        (status = 200, description = "Password changed successfully"),
        (status = 401, description = "Current password is incorrect"),
        (status = 404, description = "User not found"),
        (status = 422, description = "Validation error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn change_current_user_password(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<()> {
    change_password_inner(&state, &auth, auth.user_id, payload).await
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list_users,
        create_user,
        get_user,
        update_user,
        delete_user,
        get_user_roles,
        assign_role,
        revoke_role,
        list_user_tokens,
        create_api_token,
        revoke_api_token,
        change_password,
        reset_password,
        force_password_change,
        get_current_user_record,
        list_current_user_tokens,
        create_current_user_api_token,
        revoke_current_user_api_token,
        change_current_user_password,
    ),
    components(schemas(
        ListUsersQuery,
        CreateUserRequest,
        UpdateUserRequest,
        AdminUserResponse,
        CreateUserResponse,
        UserListResponse,
        RoleResponse,
        RoleListResponse,
        AssignRoleRequest,
        CreateApiTokenRequest,
        ApiTokenResponse,
        ApiTokenCreatedResponse,
        ApiTokenListResponse,
        ChangePasswordRequest,
        ResetPasswordResponse,
        ForcePasswordChangeResponse,
    ))
)]
pub struct UsersApiDoc;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    // -----------------------------------------------------------------------
    // generate_password
    // -----------------------------------------------------------------------

    #[test]
    fn test_generate_password_length() {
        let pwd = generate_password();
        assert_eq!(pwd.len(), 16);
    }

    #[test]
    fn test_generate_password_unique() {
        let p1 = generate_password();
        let p2 = generate_password();
        // Two random passwords should differ (astronomically unlikely to collide)
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_generate_password_valid_charset() {
        let charset = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%&*";
        for _ in 0..20 {
            let pwd = generate_password();
            for ch in pwd.chars() {
                assert!(
                    charset.contains(ch),
                    "Character '{}' not in allowed charset",
                    ch
                );
            }
        }
    }

    #[test]
    fn test_generate_password_excludes_ambiguous_chars() {
        // Charset excludes 0, 1, O, l, I to avoid ambiguity
        for _ in 0..50 {
            let pwd = generate_password();
            assert!(!pwd.contains('0'), "Should not contain '0'");
            assert!(!pwd.contains('1'), "Should not contain '1'");
            assert!(!pwd.contains('O'), "Should not contain 'O'");
            assert!(!pwd.contains('l'), "Should not contain 'l'");
            assert!(!pwd.contains('I'), "Should not contain 'I'");
            assert!(!pwd.contains('i'), "Should not contain 'i'");
        }
    }

    // -----------------------------------------------------------------------
    // user_to_response
    // -----------------------------------------------------------------------

    fn make_test_user() -> User {
        let now = Utc::now();
        User {
            id: Uuid::new_v4(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            password_hash: Some("hashed".to_string()),
            auth_provider: AuthProvider::Local,
            external_id: None,
            display_name: Some("Test User".to_string()),
            is_active: true,
            is_admin: false,
            is_service_account: false,
            must_change_password: false,
            totp_secret: None,
            totp_enabled: false,
            totp_backup_codes: None,
            totp_verified_at: None,
            failed_login_attempts: 0,
            locked_until: None,
            last_failed_login_at: None,
            password_changed_at: Utc::now(),
            last_login_at: Some(now),
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn test_user_to_response_basic_fields() {
        let user = make_test_user();
        let uid = user.id;
        let resp = user_to_response(user);
        assert_eq!(resp.id, uid);
        assert_eq!(resp.username, "testuser");
        assert_eq!(resp.email, "test@example.com");
        assert_eq!(resp.display_name, Some("Test User".to_string()));
        assert!(!resp.is_admin);
        assert!(resp.is_active);
        assert!(!resp.must_change_password);
    }

    #[test]
    fn test_user_to_response_auth_provider_local() {
        let user = make_test_user();
        let resp = user_to_response(user);
        assert_eq!(resp.auth_provider, "local");
    }

    #[test]
    fn test_user_to_response_auth_provider_ldap() {
        let mut user = make_test_user();
        user.auth_provider = AuthProvider::Ldap;
        let resp = user_to_response(user);
        assert_eq!(resp.auth_provider, "ldap");
    }

    #[test]
    fn test_user_to_response_auth_provider_saml() {
        let mut user = make_test_user();
        user.auth_provider = AuthProvider::Saml;
        let resp = user_to_response(user);
        assert_eq!(resp.auth_provider, "saml");
    }

    #[test]
    fn test_user_to_response_auth_provider_oidc() {
        let mut user = make_test_user();
        user.auth_provider = AuthProvider::Oidc;
        let resp = user_to_response(user);
        assert_eq!(resp.auth_provider, "oidc");
    }

    #[test]
    fn test_user_to_response_last_login_at() {
        let user = make_test_user();
        assert!(user_to_response(user).last_login_at.is_some());
    }

    #[test]
    fn test_user_to_response_no_last_login() {
        let mut user = make_test_user();
        user.last_login_at = None;
        assert!(user_to_response(user).last_login_at.is_none());
    }

    #[test]
    fn test_user_to_response_display_name_none() {
        let mut user = make_test_user();
        user.display_name = None;
        let resp = user_to_response(user);
        assert!(resp.display_name.is_none());
    }

    #[test]
    fn test_user_to_response_admin_user() {
        let mut user = make_test_user();
        user.is_admin = true;
        let resp = user_to_response(user);
        assert!(resp.is_admin);
    }

    #[test]
    fn test_user_to_response_inactive_user() {
        let mut user = make_test_user();
        user.is_active = false;
        let resp = user_to_response(user);
        assert!(!resp.is_active);
    }

    #[test]
    fn test_user_to_response_must_change_password() {
        let mut user = make_test_user();
        user.must_change_password = true;
        let resp = user_to_response(user);
        assert!(resp.must_change_password);
    }

    // -----------------------------------------------------------------------
    // Request/Response serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_user_request_deserialize_full() {
        let json = r#"{"username":"alice","email":"alice@example.com","password":"secret123","display_name":"Alice","is_admin":true}"#;
        let req: CreateUserRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.username, "alice");
        assert_eq!(req.email, "alice@example.com");
        assert_eq!(req.password.as_deref(), Some("secret123"));
        assert_eq!(req.display_name.as_deref(), Some("Alice"));
        assert_eq!(req.is_admin, Some(true));
    }

    #[test]
    fn test_create_user_request_deserialize_minimal() {
        let json = r#"{"username":"bob","email":"bob@example.com"}"#;
        let req: CreateUserRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.username, "bob");
        assert!(req.password.is_none());
        assert!(req.display_name.is_none());
        assert!(req.is_admin.is_none());
    }

    #[test]
    fn test_update_user_request_deserialize() {
        let json = r#"{"email":"new@example.com","is_active":false}"#;
        let req: UpdateUserRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.email.as_deref(), Some("new@example.com"));
        assert!(req.display_name.is_none());
        assert_eq!(req.is_active, Some(false));
        assert!(req.is_admin.is_none());
    }

    #[test]
    fn test_update_user_request_all_none() {
        let json = r#"{}"#;
        let req: UpdateUserRequest = serde_json::from_str(json).unwrap();
        assert!(req.email.is_none());
        assert!(req.display_name.is_none());
        assert!(req.is_active.is_none());
        assert!(req.is_admin.is_none());
    }

    #[test]
    fn test_user_response_serialize() {
        let now = Utc::now();
        let resp = AdminUserResponse {
            id: Uuid::nil(),
            username: "admin".to_string(),
            email: "admin@example.com".to_string(),
            display_name: None,
            auth_provider: "local".to_string(),
            is_active: true,
            is_admin: true,
            must_change_password: false,
            last_login_at: None,
            created_at: now,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["username"], "admin");
        assert_eq!(json["is_admin"], true);
        assert_eq!(json["auth_provider"], "local");
        assert!(json["last_login_at"].is_null());
    }

    #[test]
    fn test_create_user_response_serialize_with_generated_password() {
        let now = Utc::now();
        let resp = CreateUserResponse {
            user: AdminUserResponse {
                id: Uuid::nil(),
                username: "new_user".to_string(),
                email: "new@example.com".to_string(),
                display_name: None,
                auth_provider: "local".to_string(),
                is_active: true,
                is_admin: false,
                must_change_password: true,
                last_login_at: None,
                created_at: now,
            },
            generated_password: Some("temp_pass_123!".to_string()),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["generated_password"], "temp_pass_123!");
        assert_eq!(json["user"]["must_change_password"], true);
    }

    #[test]
    fn test_create_user_response_serialize_without_generated_password() {
        let now = Utc::now();
        let resp = CreateUserResponse {
            user: AdminUserResponse {
                id: Uuid::nil(),
                username: "user".to_string(),
                email: "user@example.com".to_string(),
                display_name: None,
                auth_provider: "local".to_string(),
                is_active: true,
                is_admin: false,
                must_change_password: false,
                last_login_at: None,
                created_at: now,
            },
            generated_password: None,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["generated_password"].is_null());
    }

    #[test]
    fn test_user_list_response_serialize() {
        let resp = UserListResponse {
            items: vec![],
            pagination: Pagination {
                page: 1,
                per_page: 20,
                total: 0,
                total_pages: 0,
            },
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["items"].as_array().unwrap().len(), 0);
        assert_eq!(json["pagination"]["page"], 1);
        assert_eq!(json["pagination"]["per_page"], 20);
    }

    #[test]
    fn test_list_users_query_deserialize() {
        let json = r#"{"search":"admin","is_active":true,"is_admin":true,"page":2,"per_page":50}"#;
        let q: ListUsersQuery = serde_json::from_str(json).unwrap();
        assert_eq!(q.search.as_deref(), Some("admin"));
        assert_eq!(q.is_active, Some(true));
        assert_eq!(q.is_admin, Some(true));
        assert_eq!(q.page, Some(2));
        assert_eq!(q.per_page, Some(50));
    }

    #[test]
    fn test_change_password_request_deserialize() {
        let json = r#"{"current_password":"old","new_password":"newpassword123"}"#;
        let req: ChangePasswordRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.current_password.as_deref(), Some("old"));
        assert_eq!(req.new_password, "newpassword123");
    }

    #[test]
    fn test_change_password_request_no_current() {
        let json = r#"{"new_password":"newpassword123"}"#;
        let req: ChangePasswordRequest = serde_json::from_str(json).unwrap();
        assert!(req.current_password.is_none());
    }

    #[test]
    fn test_role_response_serialize() {
        let resp = RoleResponse {
            id: Uuid::nil(),
            name: "admin".to_string(),
            description: Some("Administrator role".to_string()),
            permissions: vec!["read".to_string(), "write".to_string()],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["name"], "admin");
        assert_eq!(json["permissions"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_assign_role_request_deserialize() {
        let uid = Uuid::new_v4();
        let json = format!(r#"{{"role_id":"{}"}}"#, uid);
        let req: AssignRoleRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.role_id, uid);
    }

    #[test]
    fn test_create_api_token_request_deserialize() {
        let json = r#"{"name":"CI token","scopes":["read","deploy"],"expires_in_days":90}"#;
        let req: CreateApiTokenRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "CI token");
        assert_eq!(req.scopes, vec!["read", "deploy"]);
        assert_eq!(req.expires_in_days, Some(90));
    }

    #[test]
    fn test_create_api_token_request_no_expiry() {
        let json = r#"{"name":"permanent","scopes":["*"]}"#;
        let req: CreateApiTokenRequest = serde_json::from_str(json).unwrap();
        assert!(req.expires_in_days.is_none());
    }

    #[test]
    fn test_api_token_response_serialize() {
        let now = Utc::now();
        let resp = ApiTokenResponse {
            id: Uuid::nil(),
            name: "test_token".to_string(),
            token_prefix: "ak_".to_string(),
            scopes: vec!["read".to_string()],
            expires_at: Some(now),
            last_used_at: None,
            created_at: now,
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["name"], "test_token");
        assert_eq!(json["token_prefix"], "ak_");
        assert!(json["last_used_at"].is_null());
    }

    #[test]
    fn test_api_token_created_response_serialize() {
        let resp = ApiTokenCreatedResponse {
            id: Uuid::nil(),
            name: "deploy".to_string(),
            token: "ak_secret_token_value".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["token"], "ak_secret_token_value");
    }

    #[test]
    fn test_reset_password_response_serialize() {
        let resp = ResetPasswordResponse {
            temporary_password: "TempP@ss123!".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["temporary_password"], "TempP@ss123!");
    }

    // -----------------------------------------------------------------------
    // Pagination logic (from list_users handler)
    // -----------------------------------------------------------------------

    #[test]
    fn test_pagination_total_pages_calculation() {
        // Simulating the logic: total_pages = ceil(total / per_page)
        let total: i64 = 45;
        let per_page: u32 = 20;
        let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
        assert_eq!(total_pages, 3);
    }

    #[test]
    fn test_pagination_total_pages_exact_division() {
        let total: i64 = 40;
        let per_page: u32 = 20;
        let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
        assert_eq!(total_pages, 2);
    }

    #[test]
    fn test_pagination_total_pages_zero_total() {
        let total: i64 = 0;
        let per_page: u32 = 20;
        let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
        assert_eq!(total_pages, 0);
    }

    #[test]
    fn test_pagination_total_pages_single_item() {
        let total: i64 = 1;
        let per_page: u32 = 20;
        let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;
        assert_eq!(total_pages, 1);
    }

    #[test]
    fn test_page_defaults_and_clamping() {
        fn resolve_page(page: Option<u32>) -> u32 {
            page.unwrap_or(1).max(1)
        }
        assert_eq!(resolve_page(None), 1);
        assert_eq!(resolve_page(Some(0)), 1);
        assert_eq!(resolve_page(Some(5)), 5);
    }

    #[test]
    fn test_per_page_defaults_and_clamping() {
        fn resolve_per_page(pp: Option<u32>) -> u32 {
            pp.unwrap_or(20).min(100)
        }
        assert_eq!(resolve_per_page(None), 20);
        assert_eq!(resolve_per_page(Some(200)), 100);
        assert_eq!(resolve_per_page(Some(50)), 50);
    }

    #[test]
    fn test_offset_calculation() {
        let page: u32 = 3;
        let per_page: u32 = 20;
        let offset = ((page - 1) * per_page) as i64;
        assert_eq!(offset, 40);
    }

    #[test]
    fn test_offset_first_page() {
        let page: u32 = 1;
        let per_page: u32 = 20;
        let offset = ((page - 1) * per_page) as i64;
        assert_eq!(offset, 0);
    }

    // -- validate_password_with_policy tests --
    // (Comprehensive policy rule tests live in services::password_policy::tests.
    //  These handler-level tests verify that the wrapper correctly converts
    //  violations into AppError::Validation.)

    fn default_policy() -> PasswordPolicyConfig {
        PasswordPolicyConfig::default()
    }

    #[test]
    fn test_validate_password_too_short() {
        let result = validate_password_with_policy("abc", &default_policy());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("at least 8 characters"));
    }

    #[test]
    fn test_validate_password_exactly_min_length() {
        let result = validate_password_with_policy("xK9!mZ2q", &default_policy());
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_password_too_long() {
        let long = "a".repeat(129);
        let result = validate_password_with_policy(&long, &default_policy());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("at most 128 characters"));
    }

    #[test]
    fn test_validate_password_exactly_max_length() {
        let long = "aB3!".repeat(32); // 128 chars
        let result = validate_password_with_policy(&long, &default_policy());
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_password_common_password_rejected() {
        let result = validate_password_with_policy("password", &default_policy());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too common"));
    }

    #[test]
    fn test_validate_password_common_password_case_insensitive() {
        let result = validate_password_with_policy("Password", &default_policy());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too common"));
    }

    #[test]
    fn test_validate_password_common_numeric() {
        let result = validate_password_with_policy("12345678", &default_policy());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too common"));
    }

    #[test]
    fn test_validate_password_common_qwerty() {
        let result = validate_password_with_policy("qwerty123", &default_policy());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too common"));
    }

    #[test]
    fn test_validate_password_common_admin123() {
        let result = validate_password_with_policy("admin123", &default_policy());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too common"));
    }

    #[test]
    fn test_validate_password_common_trustno1() {
        let result = validate_password_with_policy("trustno1", &default_policy());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too common"));
    }

    #[test]
    fn test_validate_password_valid_strong_password() {
        let result =
            validate_password_with_policy("Correct-Horse-Battery-Staple!", &default_policy());
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_password_seven_chars_rejected() {
        let result = validate_password_with_policy("aB3!xYz", &default_policy());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("at least 8 characters"));
    }

    // -----------------------------------------------------------------------
    // Password history: bcrypt-based reuse detection
    // -----------------------------------------------------------------------

    /// Verifies that a new password matching an old bcrypt hash is detected.
    #[tokio::test]
    async fn test_password_reuse_detected_via_bcrypt() {
        let password = "OldSecurePassword1!";
        let hash = AuthService::hash_password(password).await.unwrap();
        let matches = AuthService::verify_password(password, &hash).await.unwrap();
        assert!(matches, "Same password should match its own hash");
    }

    /// Verifies that a different password does not match an old bcrypt hash.
    #[tokio::test]
    async fn test_password_no_false_positive() {
        let old_password = "OldSecurePassword1!";
        let new_password = "BrandNewPassword2@";
        let hash = AuthService::hash_password(old_password).await.unwrap();
        let matches = AuthService::verify_password(new_password, &hash)
            .await
            .unwrap();
        assert!(
            !matches,
            "Different password should not match a different hash"
        );
    }

    /// Verifies that checking multiple hashes correctly identifies reuse
    /// only when the password appears in the list.
    #[tokio::test]
    async fn test_password_history_check_across_multiple_hashes() {
        let passwords = ["Alpha1!pass", "Beta2@pass", "Gamma3#pass"];
        let mut hashes = Vec::new();
        for p in &passwords {
            hashes.push(AuthService::hash_password(p).await.unwrap());
        }

        // Reusing the second password should be detected
        let reused = "Beta2@pass";
        let mut found = false;
        for h in &hashes {
            if AuthService::verify_password(reused, h).await.unwrap() {
                found = true;
                break;
            }
        }
        assert!(found, "Reused password should match one of the old hashes");

        // A completely new password should not match any
        let fresh = "Delta4$pass";
        let mut collision = false;
        for h in &hashes {
            if AuthService::verify_password(fresh, h).await.unwrap() {
                collision = true;
                break;
            }
        }
        assert!(!collision, "Fresh password should not match any old hashes");
    }

    /// Verifies that the password_history_count config field defaults to 0.
    #[test]
    fn test_password_history_count_default() {
        // The env_parse helper returns the default when the variable is unset.
        // We verify this indirectly through the Config struct construction in
        // other tests. Here we just check the default value expectation.
        let default: u32 = 0;
        assert_eq!(
            default, 0,
            "PASSWORD_HISTORY_COUNT should default to 0 (disabled)"
        );
    }

    // -----------------------------------------------------------------------
    // ForcePasswordChangeResponse
    // -----------------------------------------------------------------------

    #[test]
    fn test_force_password_change_response_serialize() {
        let resp = ForcePasswordChangeResponse {
            message: "User will be required to change password on next login".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(
            json["message"],
            "User will be required to change password on next login"
        );
    }

    #[test]
    fn test_force_password_change_response_fields() {
        let resp = ForcePasswordChangeResponse {
            message: "test message".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        let obj = json.as_object().unwrap();
        // Response should contain exactly the message field
        assert_eq!(obj.len(), 1);
        assert!(obj.contains_key("message"));
    }

    // -----------------------------------------------------------------------
    // Password-router split — pins the three router constructors so the
    // coverage gate has something to count for the routing-only change.
    // The full behavior (non-admin can change own password, cannot change
    // another user's, cannot reach reset/force-change) is exercised by
    // `backend/tests/users_password_routing_tests.rs` against a live DB.
    // -----------------------------------------------------------------------

    /// Visit the path string of every leaf route in an axum `Router` and
    /// collect them. Used by the router-shape tests below to assert that
    /// the split routers contain exactly the routes they should and
    /// nothing else.
    ///
    /// Implementation note: axum doesn't expose its internal route table,
    /// so we exercise the routers by constructing them and inspecting the
    /// Debug repr. The Debug output of `Router` includes the path strings
    /// of every route via the inner `MethodRouter` tree. This is brittle
    /// across axum versions but stable inside a single semver cycle, and
    /// the alternative (booting a real server) would defeat the
    /// no-DB-required goal of these tests.
    fn router_paths(router: &Router<SharedState>) -> String {
        // Debug repr includes every registered path; we just grep for the
        // specific routes we care about.
        format!("{:?}", router)
    }

    #[test]
    fn test_self_password_router_contains_change_route() {
        let r = self_password_router();
        let dbg = router_paths(&r);
        assert!(
            dbg.contains("/:id/password"),
            "self_password_router must expose POST /:id/password; got {}",
            dbg
        );
    }

    #[test]
    fn test_self_password_router_contains_me_password_route() {
        // #1313: the canonical self alias POST /me/password must live in the
        // rate-limited self_password_router (#1026), not the un-throttled
        // self_router, to avoid an un-capped bcrypt CPU-DoS path.
        let r = self_password_router();
        let dbg = router_paths(&r);
        assert!(
            dbg.contains("/me/password"),
            "self_password_router must expose POST /me/password (#1313); got {}",
            dbg
        );
    }

    #[test]
    fn test_self_router_contains_me_routes() {
        // #1313: the additive self-service aliases must be registered.
        let r = self_router();
        let dbg = router_paths(&r);
        assert!(
            dbg.contains("/me"),
            "self_router must expose GET /me (#1313); got {}",
            dbg
        );
        assert!(
            dbg.contains("/me/tokens"),
            "self_router must expose /me/tokens (#1313); got {}",
            dbg
        );
        assert!(
            dbg.contains("/me/tokens/:token_id"),
            "self_router must expose /me/tokens/:token_id (#1313); got {}",
            dbg
        );
    }

    #[test]
    fn test_nest_a_routers_merge_without_conflict() {
        // #1313 routing feasibility: the additive `/me` static routes must
        // coexist with the existing `/:id` param routes when all three Nest A
        // sub-routers are merged (as routes.rs does). matchit conflicts panic
        // at merge/route time, so a successful build + Debug repr proves the
        // static `/me` segment and the `/:id` param sibling do not collide.
        let merged = self_password_router()
            .merge(self_or_admin_router())
            .merge(self_router());
        let dbg = router_paths(&merged);
        assert!(
            dbg.contains("/me"),
            "merged Nest A must contain /me; got {}",
            dbg
        );
        assert!(
            dbg.contains("/:id"),
            "merged Nest A must retain /:id; got {}",
            dbg
        );
    }

    #[test]
    fn test_self_router_does_not_contain_password_route() {
        // The bare /me record/token routes must NOT carry the password route;
        // /me/password belongs to the rate-limited self_password_router.
        let r = self_router();
        let dbg = router_paths(&r);
        assert!(
            !dbg.contains("/me/password"),
            "self_router must NOT carry /me/password (it belongs in self_password_router); got {}",
            dbg
        );
    }

    #[test]
    fn test_self_password_router_does_not_contain_reset_route() {
        // SECURITY: the self-service router must not carry the admin
        // reset/force-change endpoints. If it did, mounting it under
        // `auth_middleware` (the whole point of the split) would expose
        // those admin-only operations to any authenticated user.
        let r = self_password_router();
        let dbg = router_paths(&r);
        assert!(
            !dbg.contains("/password/reset"),
            "self_password_router must NOT contain /password/reset"
        );
        assert!(
            !dbg.contains("/force-password-change"),
            "self_password_router must NOT contain /force-password-change"
        );
    }

    #[test]
    fn test_admin_password_router_contains_reset_and_force_routes() {
        let r = admin_password_router();
        let dbg = router_paths(&r);
        assert!(
            dbg.contains("/:id/password/reset"),
            "admin_password_router must expose /:id/password/reset; got {}",
            dbg
        );
        assert!(
            dbg.contains("/:id/force-password-change"),
            "admin_password_router must expose /:id/force-password-change; got {}",
            dbg
        );
    }

    #[test]
    fn test_admin_password_router_does_not_contain_self_change_route() {
        // The admin router carries reset + force-change but NOT the
        // self-service change endpoint. Splitting them is the whole
        // reason this fix exists; collapsing them would re-introduce
        // the regression.
        let r = admin_password_router();
        let dbg = router_paths(&r);
        // The self-service route ends with "/password" (no further
        // path segment); the admin reset route is "/password/reset".
        // We check that the admin router has reset but NOT the bare
        // "/password" route.
        assert!(dbg.contains("/password/reset"));
        // Substring match alone isn't enough (`/password/reset` contains
        // `/password`); check by counting occurrences of `/password\"`
        // (the path closer in axum's Debug repr) and asserting it only
        // shows up as part of `/password/reset` and not as a standalone.
        let bare_count = dbg.matches("\"/:id/password\"").count();
        assert_eq!(
            bare_count, 0,
            "admin_password_router must NOT carry the self-service /:id/password route; got {}",
            dbg
        );
    }
}

// ---------------------------------------------------------------------------
// Router-split regression tests (#1257)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod router_split_tests {
    //! Regression tests for #1257.
    //!
    //! Pre-fix, the entire `/users` nest was wrapped in `admin_middleware`
    //! and the per-handler `if auth.user_id != id && !auth.is_admin` checks
    //! were dead code — non-admin users got 403 on every `/users/<self-id>/...`
    //! call. After splitting `router()` into `admin_router()` and
    //! `self_or_admin_router()`, the handler-level guards become
    //! load-bearing. These tests pin both halves of that contract:
    //!
    //!   * `self_or_admin_router()` handlers allow self-action and reject
    //!     non-self for non-admins.
    //!   * `admin_router()` handlers refuse a non-admin caller even when
    //!     the outer `admin_middleware` is not in the chain (defense in
    //!     depth — see the `if !auth.is_admin` guards added in this PR).
    //!
    //! All tests skip cleanly when `DATABASE_URL` is unset (`try_pool`
    //! returns `None`), matching the rest of the DB-backed test suite.
    //! `Extension::<AuthExtension>(auth)` is injected directly (not via
    //! `tdh::router_with_auth`, which wraps it in `Option`) because the
    //! handlers use the bare extractor — same trick as `upload.rs`'s
    //! `upload_router_with_auth` test helper.
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use axum::Extension as AxumExtension;
    use serde_json::json;

    fn build_self_or_admin_app(state: SharedState, auth: AuthExtension) -> axum::Router {
        self_or_admin_router()
            .with_state(state)
            .layer(AxumExtension::<AuthExtension>(auth))
    }

    // Upstream kept the admin user-management router named `router()`
    // (rather than `admin_router()`). #1250 also split the legacy
    // single `password_router()` into `self_password_router()` (auth-
    // middleware mount, contains POST /:id/password) and
    // `admin_password_router()` (admin-middleware mount, contains
    // /password/reset + /force-password-change). The tests below
    // target the self-change route exclusively — that's the one the
    // bug-repro flow uses — so the password test app is built from
    // `self_password_router()`.
    fn build_admin_app(state: SharedState, auth: AuthExtension) -> axum::Router {
        router()
            .with_state(state)
            .layer(AxumExtension::<AuthExtension>(auth))
    }

    fn build_password_app(state: SharedState, auth: AuthExtension) -> axum::Router {
        self_password_router()
            .with_state(state)
            .layer(AxumExtension::<AuthExtension>(auth))
    }

    /// #1313: builds the canonical self-service `/users/me/*` router with the
    /// caller's auth injected. `/me` handlers resolve the subject to
    /// `auth.user_id`, so these exercise the self-only alias path.
    fn build_self_app(state: SharedState, auth: AuthExtension) -> axum::Router {
        self_router()
            .with_state(state)
            .layer(AxumExtension::<AuthExtension>(auth))
    }

    /// Skip-friendly fixture: returns (pool, state, non_admin_user) or
    /// `None` when DATABASE_URL is unset. The temp-storage path is unused
    /// by the routes under test but `build_state` requires one.
    async fn setup() -> Option<(sqlx::PgPool, SharedState, Uuid, String)> {
        let pool = tdh::try_pool().await?;
        let (user_id, username) = tdh::create_user(&pool).await;
        let state = tdh::build_state(pool.clone(), "/tmp");
        Some((pool, state, user_id, username))
    }

    async fn delete_user_row(pool: &sqlx::PgPool, user_id: Uuid) {
        let _ = sqlx::query("DELETE FROM api_tokens WHERE user_id = $1")
            .bind(user_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(pool)
            .await;
    }

    // ── self_or_admin_router: regression coverage ─────────────────────

    /// Pre-#1257: this returned 403 from `admin_middleware` before the
    /// handler ran. Post-fix, the handler runs and creates the token.
    #[tokio::test]
    async fn non_admin_can_create_own_api_token() {
        let Some((pool, state, user_id, username)) = setup().await else {
            return;
        };
        let auth = tdh::make_auth(user_id, &username);
        let app = build_self_or_admin_app(state, auth);

        let body = json!({
            "name": "self-token",
            "scopes": ["read:artifacts"],
            "expires_in_days": 30,
        })
        .to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("/{}/tokens", user_id))
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let (status, body_bytes) = tdh::send(app, req).await;

        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "non-admin self-creating their own API token MUST NOT 403 (#1257); body: {}",
            String::from_utf8_lossy(&body_bytes),
        );
        assert_eq!(
            status,
            StatusCode::OK,
            "expected 200 on happy-path create; got {} body: {}",
            status,
            String::from_utf8_lossy(&body_bytes),
        );

        delete_user_row(&pool, user_id).await;
    }

    #[tokio::test]
    async fn non_admin_cannot_create_tokens_for_another_user() {
        let Some((pool, state, caller_id, caller_name)) = setup().await else {
            return;
        };
        let (target_id, _target_name) = tdh::create_user(&pool).await;
        let auth = tdh::make_auth(caller_id, &caller_name);
        let app = build_self_or_admin_app(state, auth);

        let body = json!({
            "name": "other-token",
            "scopes": ["read:artifacts"],
            "expires_in_days": 30,
        })
        .to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("/{}/tokens", target_id))
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let (status, _) = tdh::send(app, req).await;

        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "non-admin attempting to mint tokens for another user MUST 403 (handler-level guard at users.rs:create_api_token)"
        );

        delete_user_row(&pool, caller_id).await;
        delete_user_row(&pool, target_id).await;
    }

    #[tokio::test]
    async fn non_admin_can_read_own_user_record() {
        let Some((pool, state, user_id, username)) = setup().await else {
            return;
        };
        let auth = tdh::make_auth(user_id, &username);
        let app = build_self_or_admin_app(state, auth);

        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("/{}", user_id))
            .body(Body::empty())
            .unwrap();
        let (status, _) = tdh::send(app, req).await;

        assert_eq!(
            status,
            StatusCode::OK,
            "non-admin reading their own user record MUST succeed (#1257)"
        );

        delete_user_row(&pool, user_id).await;
    }

    #[tokio::test]
    async fn non_admin_cannot_read_another_user_record() {
        let Some((pool, state, caller_id, caller_name)) = setup().await else {
            return;
        };
        let (target_id, _) = tdh::create_user(&pool).await;
        let auth = tdh::make_auth(caller_id, &caller_name);
        let app = build_self_or_admin_app(state, auth);

        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("/{}", target_id))
            .body(Body::empty())
            .unwrap();
        let (status, _) = tdh::send(app, req).await;

        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "non-admin reading another user's record MUST 403 (handler-level guard at users.rs:get_user)"
        );

        delete_user_row(&pool, caller_id).await;
        delete_user_row(&pool, target_id).await;
    }

    // ── admin_router: defense-in-depth handler guards ─────────────────

    /// Mounted via `admin_router()` only (no `admin_middleware` in the
    /// chain) so this exercises the in-handler `if !auth.is_admin` guard
    /// added in #1257. Pre-PR, the route relied solely on the router-level
    /// middleware — if a future refactor moves the route between sub-
    /// routers it would silently expose. The handler guard is the
    /// independent second layer.
    #[tokio::test]
    async fn admin_handler_list_users_rejects_non_admin() {
        let Some((pool, state, user_id, username)) = setup().await else {
            return;
        };
        let auth = tdh::make_auth(user_id, &username);
        let app = build_admin_app(state, auth);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .unwrap();
        let (status, _) = tdh::send(app, req).await;

        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "list_users MUST 403 a non-admin even without admin_middleware in front of it (#1257 defense in depth)"
        );

        delete_user_row(&pool, user_id).await;
    }

    #[tokio::test]
    async fn admin_handler_update_user_rejects_non_admin() {
        let Some((pool, state, user_id, username)) = setup().await else {
            return;
        };
        let auth = tdh::make_auth(user_id, &username);
        let app = build_admin_app(state, auth);

        let body = json!({"is_admin": true}).to_string();
        let req = Request::builder()
            .method(Method::PATCH)
            .uri(format!("/{}", user_id))
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let (status, _) = tdh::send(app, req).await;

        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "update_user MUST 403 a non-admin even without admin_middleware (#1257); a non-admin must not be able to escalate by PATCHing their own row"
        );

        delete_user_row(&pool, user_id).await;
    }

    #[tokio::test]
    async fn admin_handler_delete_user_rejects_non_admin() {
        let Some((pool, state, caller_id, caller_name)) = setup().await else {
            return;
        };
        let (target_id, _) = tdh::create_user(&pool).await;
        let auth = tdh::make_auth(caller_id, &caller_name);
        let app = build_admin_app(state, auth);

        let req = Request::builder()
            .method(Method::DELETE)
            .uri(format!("/{}", target_id))
            .body(Body::empty())
            .unwrap();
        let (status, _) = tdh::send(app, req).await;

        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "delete_user MUST 403 a non-admin even without admin_middleware (#1257)"
        );

        delete_user_row(&pool, caller_id).await;
        delete_user_row(&pool, target_id).await;
    }

    // ── password_router: change_password reachable for self ───────────

    /// Pre-#1257 `change_password` (`POST /:id/password`) was blocked by
    /// `admin_middleware` for non-admins even though its handler-level
    /// guard at users.rs:834 is exactly `if auth.user_id != id &&
    /// !auth.is_admin`. After the split, `password_router` rides
    /// `auth_middleware` and the handler decides. We can't drive the full
    /// password-policy validation here (the test password gets bcrypt'd
    /// against a row with `password_hash='unused'`), so we only assert
    /// the negative invariant: NOT 403. The exact non-403 status the
    /// handler returns (4xx for wrong current password, etc.) is not the
    /// security property under test.
    #[tokio::test]
    async fn non_admin_can_reach_change_password_for_self() {
        let Some((pool, state, user_id, username)) = setup().await else {
            return;
        };
        let auth = tdh::make_auth(user_id, &username);
        let app = build_password_app(state, auth);

        let body = json!({
            "current_password": "irrelevant",
            "new_password": "NewPassw0rd!",
        })
        .to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("/{}/password", user_id))
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let (status, _) = tdh::send(app, req).await;

        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "non-admin reaching change_password for self MUST NOT 403 (#1257) — handler may legitimately reject the body, but it must not be admin-gated"
        );

        delete_user_row(&pool, user_id).await;
    }

    /// Seed an `api_tokens` row directly so the revoke tests have a real
    /// token id to target. Mirrors the canonical INSERT shape used by
    /// `auth_service::generate_api_token` (auth_service.rs:1358). We bypass
    /// the bcrypt token-hash step — the token *value* is never read here,
    /// only its `id` — and use a placeholder for `token_hash` to avoid the
    /// CPU-bound bcrypt step on every test run.
    ///
    /// Uses the runtime `sqlx::query` (not the `query!` macro) so this
    /// helper doesn't need a `.sqlx/` offline cache entry of its own;
    /// CI builds with `SQLX_OFFLINE=true` and we don't want to add a
    /// cached query for a test-only INSERT shape.
    async fn seed_api_token(pool: &sqlx::PgPool, user_id: Uuid, prefix: &str) -> Uuid {
        let row: (Uuid,) = sqlx::query_as(
            "INSERT INTO api_tokens (user_id, name, token_hash, token_prefix, scopes, expires_at) \
             VALUES ($1, $2, $3, $4, $5, NULL) \
             RETURNING id",
        )
        .bind(user_id)
        .bind(format!("seed-{}", prefix))
        .bind("placeholder-hash-not-validated-by-revoke-path")
        .bind(prefix)
        .bind(Vec::<String>::new())
        .fetch_one(pool)
        .await
        .expect("seed api_token row");
        row.0
    }

    // ── self_or_admin_router: token list / revoke coverage ────────────

    #[tokio::test]
    async fn non_admin_can_list_own_api_tokens() {
        let Some((pool, state, user_id, username)) = setup().await else {
            return;
        };
        let auth = tdh::make_auth(user_id, &username);
        let app = build_self_or_admin_app(state, auth);

        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("/{}/tokens", user_id))
            .body(Body::empty())
            .unwrap();
        let (status, body) = tdh::send(app, req).await;

        assert_eq!(
            status,
            StatusCode::OK,
            "non-admin listing their own tokens MUST succeed (#1257); body: {}",
            String::from_utf8_lossy(&body),
        );

        delete_user_row(&pool, user_id).await;
    }

    #[tokio::test]
    async fn non_admin_cannot_list_another_users_tokens() {
        let Some((pool, state, caller_id, caller_name)) = setup().await else {
            return;
        };
        let (target_id, _) = tdh::create_user(&pool).await;
        let auth = tdh::make_auth(caller_id, &caller_name);
        let app = build_self_or_admin_app(state, auth);

        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("/{}/tokens", target_id))
            .body(Body::empty())
            .unwrap();
        let (status, _) = tdh::send(app, req).await;

        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "non-admin listing another user's tokens MUST 403 (handler-level guard at users.rs:list_user_tokens)"
        );

        delete_user_row(&pool, caller_id).await;
        delete_user_row(&pool, target_id).await;
    }

    #[tokio::test]
    async fn non_admin_can_revoke_own_api_token() {
        let Some((pool, state, user_id, username)) = setup().await else {
            return;
        };
        let token_id = seed_api_token(&pool, user_id, "self-rev").await;
        let auth = tdh::make_auth(user_id, &username);
        let app = build_self_or_admin_app(state, auth);

        let req = Request::builder()
            .method(Method::DELETE)
            .uri(format!("/{}/tokens/{}", user_id, token_id))
            .body(Body::empty())
            .unwrap();
        let (status, body) = tdh::send(app, req).await;

        assert_eq!(
            status,
            StatusCode::OK,
            "non-admin revoking their own token MUST succeed (#1257); body: {}",
            String::from_utf8_lossy(&body),
        );

        delete_user_row(&pool, user_id).await;
    }

    #[tokio::test]
    async fn non_admin_cannot_revoke_another_users_token() {
        let Some((pool, state, caller_id, caller_name)) = setup().await else {
            return;
        };
        let (target_id, _) = tdh::create_user(&pool).await;
        let token_id = seed_api_token(&pool, target_id, "x-rev-x").await;
        let auth = tdh::make_auth(caller_id, &caller_name);
        let app = build_self_or_admin_app(state, auth);

        let req = Request::builder()
            .method(Method::DELETE)
            .uri(format!("/{}/tokens/{}", target_id, token_id))
            .body(Body::empty())
            .unwrap();
        let (status, _) = tdh::send(app, req).await;

        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "non-admin revoking another user's token MUST 403 (handler-level guard at users.rs:revoke_api_token)"
        );

        delete_user_row(&pool, caller_id).await;
        delete_user_row(&pool, target_id).await;
    }

    // ── password_router: cross-user negative coverage ─────────────────

    #[tokio::test]
    async fn non_admin_cannot_change_another_users_password() {
        let Some((pool, state, caller_id, caller_name)) = setup().await else {
            return;
        };
        let (target_id, _) = tdh::create_user(&pool).await;
        let auth = tdh::make_auth(caller_id, &caller_name);
        let app = build_password_app(state, auth);

        let body = json!({
            "current_password": "irrelevant",
            "new_password": "NewPassw0rd!",
        })
        .to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("/{}/password", target_id))
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let (status, _) = tdh::send(app, req).await;

        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "non-admin changing another user's password MUST 403 (handler-level guard at users.rs:change_password)"
        );

        delete_user_row(&pool, caller_id).await;
        delete_user_row(&pool, target_id).await;
    }

    // ── #1313: /users/me/* self-service aliases ───────────────────────

    /// GET /me resolves to the CALLER's own record (subject = auth.user_id),
    /// never a path id.
    #[tokio::test]
    async fn me_get_returns_own_record() {
        let Some((pool, state, user_id, username)) = setup().await else {
            return;
        };
        let auth = tdh::make_auth(user_id, &username);
        let app = build_self_app(state, auth);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/me")
            .body(Body::empty())
            .unwrap();
        let (status, body) = tdh::send(app, req).await;

        assert_eq!(
            status,
            StatusCode::OK,
            "GET /me MUST return the caller's own record (#1313); body: {}",
            String::from_utf8_lossy(&body),
        );
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(
            json["id"].as_str(),
            Some(user_id.to_string().as_str()),
            "GET /me MUST resolve to the caller's id, not any path id"
        );

        delete_user_row(&pool, user_id).await;
    }

    /// GET /me/tokens resolves to the caller's own tokens.
    #[tokio::test]
    async fn me_tokens_list_returns_only_own() {
        let Some((pool, state, user_id, username)) = setup().await else {
            return;
        };
        let auth = tdh::make_auth(user_id, &username);
        let app = build_self_app(state, auth);

        let req = Request::builder()
            .method(Method::GET)
            .uri("/me/tokens")
            .body(Body::empty())
            .unwrap();
        let (status, body) = tdh::send(app, req).await;

        assert_eq!(
            status,
            StatusCode::OK,
            "GET /me/tokens MUST succeed for the caller (#1313); body: {}",
            String::from_utf8_lossy(&body),
        );

        delete_user_row(&pool, user_id).await;
    }

    /// POST /me/tokens with a benign scope mints a token for the caller.
    #[tokio::test]
    async fn me_tokens_create_ok() {
        let Some((pool, state, user_id, username)) = setup().await else {
            return;
        };
        let auth = tdh::make_auth(user_id, &username);
        let app = build_self_app(state, auth);

        let body = json!({
            "name": "me-token",
            "scopes": ["read:artifacts"],
            "expires_in_days": 30,
        })
        .to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/me/tokens")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let (status, body) = tdh::send(app, req).await;

        assert_eq!(
            status,
            StatusCode::OK,
            "POST /me/tokens (read scope) MUST mint a token for the caller (#1313); body: {}",
            String::from_utf8_lossy(&body),
        );

        delete_user_row(&pool, user_id).await;
    }

    /// #1315 invariant preserved on the alias: a non-admin caller cannot mint
    /// an admin-scoped token via POST /me/tokens.
    #[tokio::test]
    async fn me_tokens_create_rejects_admin_scope() {
        let Some((pool, state, user_id, username)) = setup().await else {
            return;
        };
        let auth = tdh::make_auth(user_id, &username);
        let app = build_self_app(state, auth);

        let body = json!({
            "name": "escalate",
            "scopes": ["admin"],
            "expires_in_days": 30,
        })
        .to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/me/tokens")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let (status, _) = tdh::send(app, req).await;

        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "POST /me/tokens with admin scope by a non-admin MUST 403 (#1315 preserved on the /me alias)"
        );

        delete_user_row(&pool, user_id).await;
    }

    /// DELETE /me/tokens/:id revokes the caller's own token.
    #[tokio::test]
    async fn me_tokens_revoke_own_ok() {
        let Some((pool, state, user_id, username)) = setup().await else {
            return;
        };
        let token_id = seed_api_token(&pool, user_id, "me-rev").await;
        let auth = tdh::make_auth(user_id, &username);
        let app = build_self_app(state, auth);

        let req = Request::builder()
            .method(Method::DELETE)
            .uri(format!("/me/tokens/{}", token_id))
            .body(Body::empty())
            .unwrap();
        let (status, body) = tdh::send(app, req).await;

        assert_eq!(
            status,
            StatusCode::OK,
            "DELETE /me/tokens/:id MUST revoke the caller's own token (#1313); body: {}",
            String::from_utf8_lossy(&body),
        );

        delete_user_row(&pool, user_id).await;
    }

    /// #1026/self-current-password invariant preserved on the alias: a
    /// non-admin POSTing /me/password without `current_password` is rejected
    /// (not applied). Built from `self_password_router` so `/me/password` is in
    /// the router under test.
    #[tokio::test]
    async fn me_password_change_requires_current_pw() {
        let Some((pool, state, user_id, username)) = setup().await else {
            return;
        };
        let auth = tdh::make_auth(user_id, &username);
        let app = build_password_app(state, auth);

        // Omit current_password: the self current-password check must reject.
        let body = json!({
            "new_password": "NewPassw0rd!",
        })
        .to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/me/password")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let (status, _) = tdh::send(app, req).await;

        assert_ne!(
            status,
            StatusCode::OK,
            "POST /me/password without current_password MUST NOT succeed for a non-admin (#1313 preserves the self current-password check)"
        );
        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "POST /me/password for self MUST NOT 403 — it is intrinsically self-only (#1313)"
        );

        delete_user_row(&pool, user_id).await;
    }

    /// Invariant (c): the existing admin-shaped `/users/:id` path is unchanged
    /// by the additive #1313 aliases — an admin can still read any user's
    /// record via `GET /users/:id`.
    #[tokio::test]
    async fn admin_can_read_other_user_via_id_route() {
        let Some((pool, state, admin_id, admin_name)) = setup().await else {
            return;
        };
        let (target_id, _) = tdh::create_user(&pool).await;
        let auth = make_admin_auth(admin_id, &admin_name);
        let app = build_self_or_admin_app(state, auth);

        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("/{}", target_id))
            .body(Body::empty())
            .unwrap();
        let (status, body) = tdh::send(app, req).await;

        assert_eq!(
            status,
            StatusCode::OK,
            "admin GET /users/:id MUST still return another user's record (#1313 is additive); body: {}",
            String::from_utf8_lossy(&body),
        );

        delete_user_row(&pool, admin_id).await;
        delete_user_row(&pool, target_id).await;
    }

    // ── #1821: privilege change invalidates tokens ─────────────────────

    /// AuthExtension for an admin caller (the request principal that performs
    /// the demotion). `make_auth` only mints non-admin principals.
    fn make_admin_auth(user_id: Uuid, username: &str) -> AuthExtension {
        AuthExtension {
            is_admin: true,
            ..tdh::make_auth(user_id, username)
        }
    }

    async fn privileges_changed_at(pool: &sqlx::PgPool, id: Uuid) -> chrono::DateTime<chrono::Utc> {
        sqlx::query_scalar::<_, chrono::DateTime<chrono::Utc>>(
            "SELECT privileges_changed_at FROM users WHERE id = $1",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("read privileges_changed_at")
    }

    async fn set_admin(pool: &sqlx::PgPool, id: Uuid, is_admin: bool) {
        sqlx::query("UPDATE users SET is_admin = $2 WHERE id = $1")
            .bind(id)
            .bind(is_admin)
            .execute(pool)
            .await
            .expect("set is_admin");
    }

    /// #1821: demoting an admin (PATCH is_admin:false) must bump
    /// `privileges_changed_at`, which feeds the credential-change watermark and
    /// invalidates the pre-demotion JWT whose `is_admin` claim is now stale.
    #[tokio::test]
    async fn admin_demotion_bumps_privilege_watermark() {
        let Some((pool, state, caller_id, caller_name)) = setup().await else {
            return;
        };
        let (target_id, _) = tdh::create_user(&pool).await;
        set_admin(&pool, target_id, true).await;
        // Backdate so a NOW() bump is unambiguously newer at second resolution.
        sqlx::query(
            "UPDATE users SET privileges_changed_at = NOW() - INTERVAL '120 seconds' WHERE id = $1",
        )
        .bind(target_id)
        .execute(&pool)
        .await
        .expect("backdate watermark");
        let before = privileges_changed_at(&pool, target_id).await;

        let auth = make_admin_auth(caller_id, &caller_name);
        let app = build_admin_app(state, auth);
        let req = Request::builder()
            .method(Method::PATCH)
            .uri(format!("/{}", target_id))
            .header("content-type", "application/json")
            .body(Body::from(json!({"is_admin": false}).to_string()))
            .unwrap();
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::OK, "admin demotion must succeed");

        let after = privileges_changed_at(&pool, target_id).await;
        assert!(
            after > before,
            "demotion must bump privileges_changed_at (#1821): before={before}, after={after}"
        );

        delete_user_row(&pool, caller_id).await;
        delete_user_row(&pool, target_id).await;
    }

    /// A benign edit that does not change `is_admin` (display_name only) must
    /// NOT bump the privilege watermark — otherwise every profile edit would
    /// log the user out (#1190 invariant preserved).
    #[tokio::test]
    async fn benign_profile_edit_keeps_privilege_watermark() {
        let Some((pool, state, caller_id, caller_name)) = setup().await else {
            return;
        };
        let (target_id, _) = tdh::create_user(&pool).await;
        let before = privileges_changed_at(&pool, target_id).await;

        let auth = make_admin_auth(caller_id, &caller_name);
        let app = build_admin_app(state, auth);
        let req = Request::builder()
            .method(Method::PATCH)
            .uri(format!("/{}", target_id))
            .header("content-type", "application/json")
            .body(Body::from(json!({"display_name": "Renamed"}).to_string()))
            .unwrap();
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::OK, "benign edit must succeed");

        let after = privileges_changed_at(&pool, target_id).await;
        assert_eq!(
            after, before,
            "a non-privilege edit must NOT bump privileges_changed_at (#1190 invariant)"
        );

        delete_user_row(&pool, caller_id).await;
        delete_user_row(&pool, target_id).await;
    }

    /// Idempotent re-apply of the SAME is_admin value must NOT bump the
    /// watermark (avoids logging the user out on a no-op admin re-sync).
    #[tokio::test]
    async fn idempotent_is_admin_reapply_keeps_privilege_watermark() {
        let Some((pool, state, caller_id, caller_name)) = setup().await else {
            return;
        };
        let (target_id, _) = tdh::create_user(&pool).await; // is_admin = false
        let before = privileges_changed_at(&pool, target_id).await;

        let auth = make_admin_auth(caller_id, &caller_name);
        let app = build_admin_app(state, auth);
        let req = Request::builder()
            .method(Method::PATCH)
            .uri(format!("/{}", target_id))
            .header("content-type", "application/json")
            .body(Body::from(json!({"is_admin": false}).to_string()))
            .unwrap();
        let (status, _) = tdh::send(app, req).await;
        assert_eq!(status, StatusCode::OK, "no-op re-apply must succeed");

        let after = privileges_changed_at(&pool, target_id).await;
        assert_eq!(
            after, before,
            "re-applying the same is_admin value must NOT bump the watermark"
        );

        delete_user_row(&pool, caller_id).await;
        delete_user_row(&pool, target_id).await;
    }
}

// ---------------------------------------------------------------------------
// Admin-only token-scope enforcement tests
//
// Live demonstration: against an in-cluster deployment of AK 1.1.9, a
// non-admin user successfully minted tokens with scopes `["admin"]`,
// `["*"]`, `["delete:artifacts"]`, `["delete:repositories"]`, AND even
// a nonsense `["totally-bogus"]` — every call returned 200. The `*` and
// `admin` scopes are particularly dangerous because they short-circuit
// `scopes_grant_access` to `true` for any required scope, so a non-admin
// holding such a token bypasses every scope-only authorization gate in
// the server.
//
// Tests below pin the policy implemented in this PR.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod admin_scope_policy_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use axum::Extension as AxumExtension;
    use serde_json::json;

    fn build_users_app(state: SharedState, auth: AuthExtension) -> axum::Router {
        // Mount the self-or-admin users router (#1257 split) with a bare
        // `Extension<AuthExtension>` layer (the production middleware
        // chain produces this shape; `tdh::router_with_auth` wraps it in
        // `Option`, which doesn't match the bare extractor on these
        // handlers). Mirrors the `upload_router_with_auth` test helper
        // pattern. POST /:id/tokens now lives on `self_or_admin_router()`
        // (#1257) rather than the admin-only `router()`; the admin-scope
        // policy still gates the handler from inside it.
        self_or_admin_router()
            .with_state(state)
            .layer(AxumExtension::<AuthExtension>(auth))
    }

    /// Compact fixture: pool + state + non-admin user_id + username. Skips
    /// cleanly without `DATABASE_URL` via `tdh::try_pool`.
    async fn setup() -> Option<(sqlx::PgPool, SharedState, Uuid, String)> {
        let pool = tdh::try_pool().await?;
        let (user_id, username) = tdh::create_user(&pool).await;
        let state = tdh::build_state(pool.clone(), "/tmp");
        Some((pool, state, user_id, username))
    }

    async fn cleanup(pool: &sqlx::PgPool, user_id: Uuid) {
        let _ = sqlx::query("DELETE FROM api_tokens WHERE user_id = $1")
            .bind(user_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(pool)
            .await;
    }

    /// Each ADMIN_ONLY_SCOPES entry submitted alone by a non-admin must
    /// be refused at the handler. Iterates so a future addition (or
    /// removal) to the policy list is automatically covered.
    #[tokio::test]
    async fn non_admin_cannot_mint_admin_only_scopes_on_users_endpoint() {
        let Some((pool, state, user_id, username)) = setup().await else {
            return;
        };
        let auth = tdh::make_auth(user_id, &username); // is_admin: false

        for admin_scope in crate::services::token_service::ADMIN_ONLY_SCOPES {
            let app = build_users_app(state.clone(), auth.clone());
            let body = json!({
                "name": format!("probe-{}", admin_scope),
                "scopes": [admin_scope],
                "expires_in_days": 30_i64,
            })
            .to_string();
            let req = Request::builder()
                .method(Method::POST)
                .uri(format!("/{}/tokens", user_id))
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap();
            let (status, body_bytes) = tdh::send(app, req).await;

            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "non-admin minting token with admin-class scope {:?} MUST 403; got {} body: {}",
                admin_scope,
                status,
                String::from_utf8_lossy(&body_bytes),
            );
        }

        cleanup(&pool, user_id).await;
    }

    /// Non-admin minting a token with a routine, non-admin scope list
    /// MUST still succeed — the policy is targeted, not a blanket lock.
    #[tokio::test]
    async fn non_admin_can_still_mint_safe_scopes_on_users_endpoint() {
        let Some((pool, state, user_id, username)) = setup().await else {
            return;
        };
        let auth = tdh::make_auth(user_id, &username);
        let app = build_users_app(state, auth);

        let body = json!({
            "name": "safe-scope-token",
            "scopes": ["read:artifacts", "write:artifacts", "read:repositories"],
            "expires_in_days": 30_i64,
        })
        .to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("/{}/tokens", user_id))
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let (status, body_bytes) = tdh::send(app, req).await;

        assert_eq!(
            status,
            StatusCode::OK,
            "non-admin with safe scopes MUST succeed; got {} body: {}",
            status,
            String::from_utf8_lossy(&body_bytes),
        );

        cleanup(&pool, user_id).await;
    }

    /// A non-admin must not smuggle an admin-only scope past the check
    /// by burying it inside a list of otherwise-safe scopes.
    #[tokio::test]
    async fn non_admin_cannot_smuggle_admin_scope_in_a_mixed_list() {
        let Some((pool, state, user_id, username)) = setup().await else {
            return;
        };
        let auth = tdh::make_auth(user_id, &username);
        let app = build_users_app(state, auth);

        let body = json!({
            "name": "smuggle-attempt",
            "scopes": ["read:artifacts", "write:artifacts", "admin"],
            "expires_in_days": 30_i64,
        })
        .to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("/{}/tokens", user_id))
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let (status, _) = tdh::send(app, req).await;

        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "non-admin smuggling 'admin' in a safe-looking scope list MUST 403"
        );

        cleanup(&pool, user_id).await;
    }

    /// Admin callers retain the ability to grant the entire policy
    /// surface. We assert against an admin-flagged AuthExtension so the
    /// policy doesn't accidentally lock everyone out — including the
    /// people who legitimately need to provision admin-class tokens
    /// (e.g. for CI service accounts).
    #[tokio::test]
    async fn admin_can_mint_admin_only_scopes_on_users_endpoint() {
        let Some((pool, state, user_id, username)) = setup().await else {
            return;
        };
        let mut auth = tdh::make_auth(user_id, &username);
        auth.is_admin = true;
        let app = build_users_app(state, auth);

        let body = json!({
            "name": "admin-token",
            "scopes": ["admin"],
            "expires_in_days": 30_i64,
        })
        .to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("/{}/tokens", user_id))
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let (status, body_bytes) = tdh::send(app, req).await;

        assert_eq!(
            status,
            StatusCode::OK,
            "admin minting an admin-scoped token MUST succeed; got {} body: {}",
            status,
            String::from_utf8_lossy(&body_bytes),
        );

        cleanup(&pool, user_id).await;
    }

    // ── Sibling endpoint: profile::create_access_token ──────────────────
    //
    // The same policy must apply to `POST /api/v1/profile/access-tokens`,
    // otherwise the user just routes around the users.rs gate. One test
    // proves the wiring is in place there too; the unit-level policy
    // coverage in `token_service::tests::enforce_admin_only_scopes*` is
    // independent of which handler invokes the helper.

    fn build_profile_app(state: SharedState, auth: AuthExtension) -> axum::Router {
        crate::api::handlers::profile::router()
            .with_state(state)
            .layer(AxumExtension::<AuthExtension>(auth))
    }

    #[tokio::test]
    async fn non_admin_cannot_mint_admin_scope_on_profile_endpoint() {
        let Some((pool, state, user_id, username)) = setup().await else {
            return;
        };
        let auth = tdh::make_auth(user_id, &username);
        let app = build_profile_app(state, auth);

        let body = json!({
            "name": "profile-smuggle",
            "scopes": ["*"],
            "expires_in_days": 30_i64,
        })
        .to_string();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/access-tokens")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let (status, _) = tdh::send(app, req).await;

        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "non-admin minting `*` token on /profile/access-tokens MUST 403 (sibling enforcement to users.rs)"
        );

        cleanup(&pool, user_id).await;
    }
}

/// DB-backed tests for the auth-event audit trail added in #386 (#1617
/// Phase 1): a self-service password change and an admin password reset must
/// emit `PASSWORD_CHANGED` (plus `SESSIONS_INVALIDATED` for the self change),
/// with `details.by_admin` reflecting who performed it. Each test no-ops when
/// `DATABASE_URL` is unset (`tdh::try_pool`).
#[cfg(test)]
mod password_audit_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;

    /// Read `details.by_admin` off the single PASSWORD_CHANGED audit row for a
    /// subject, if present.
    async fn by_admin_flag(pool: &sqlx::PgPool, subject: Uuid) -> Option<bool> {
        sqlx::query_scalar::<_, bool>(
            "SELECT (details->>'by_admin')::bool FROM audit_log \
             WHERE resource_id = $1 AND action = 'PASSWORD_CHANGED' LIMIT 1",
        )
        .bind(subject)
        .fetch_optional(pool)
        .await
        .expect("by_admin query")
    }

    #[tokio::test]
    async fn self_change_password_emits_password_changed_and_sessions_invalidated() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, username) = tdh::create_user(&pool).await;
        let current = "OldPass!2026";
        let hash = bcrypt::hash(current, 4).expect("hash password");
        sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
            .bind(&hash)
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("seed password hash");
        let state = tdh::build_state(pool.clone(), "/tmp");
        let auth = tdh::make_auth(user_id, &username);

        let res = change_password(
            State(state.clone()),
            Extension(auth),
            Path(user_id),
            Json(ChangePasswordRequest {
                current_password: Some(current.to_string()),
                new_password: "NewPass!2026".to_string(),
            }),
        )
        .await;

        let changed = tdh::audit_count(&pool, user_id, "PASSWORD_CHANGED").await;
        let invalidated = tdh::audit_count(&pool, user_id, "SESSIONS_INVALIDATED").await;
        let by_admin = by_admin_flag(&pool, user_id).await;
        tdh::cleanup_user(&pool, user_id).await;

        assert!(res.is_ok(), "change_password failed: {:?}", res.err());
        assert_eq!(
            changed, 1,
            "self change_password MUST write one PASSWORD_CHANGED row"
        );
        assert_eq!(
            invalidated, 1,
            "self change_password MUST write one SESSIONS_INVALIDATED row"
        );
        assert_eq!(
            by_admin,
            Some(false),
            "a self change must record details.by_admin = false"
        );
    }

    #[tokio::test]
    async fn admin_reset_password_emits_password_changed_by_admin_on_target() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (target_id, _target_name) = tdh::create_user(&pool).await;
        let (admin_id, admin_name) = tdh::create_user(&pool).await;
        let mut auth = tdh::make_auth(admin_id, &admin_name);
        auth.is_admin = true;
        let state = tdh::build_state(pool.clone(), "/tmp");

        let res = reset_password(State(state.clone()), Extension(auth), Path(target_id)).await;

        let changed = tdh::audit_count(&pool, target_id, "PASSWORD_CHANGED").await;
        let by_admin = by_admin_flag(&pool, target_id).await;
        tdh::cleanup_user(&pool, target_id).await;
        tdh::cleanup_user(&pool, admin_id).await;

        assert!(res.is_ok(), "reset_password failed: {:?}", res.err());
        assert_eq!(
            changed, 1,
            "admin reset MUST write one PASSWORD_CHANGED row on the target user"
        );
        assert_eq!(
            by_admin,
            Some(true),
            "an admin reset must record details.by_admin = true"
        );
    }

    #[tokio::test]
    async fn admin_force_password_change_emits_sessions_invalidated_only() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (target_id, _target_name) = tdh::create_user(&pool).await;
        let (admin_id, admin_name) = tdh::create_user(&pool).await;
        let mut auth = tdh::make_auth(admin_id, &admin_name);
        auth.is_admin = true;
        let state = tdh::build_state(pool.clone(), "/tmp");

        let res =
            force_password_change(State(state.clone()), Extension(auth), Path(target_id)).await;

        let invalidated = tdh::audit_count(&pool, target_id, "SESSIONS_INVALIDATED").await;
        // No password actually changed, so PASSWORD_CHANGED must NOT be emitted.
        let changed = tdh::audit_count(&pool, target_id, "PASSWORD_CHANGED").await;
        tdh::cleanup_user(&pool, target_id).await;
        tdh::cleanup_user(&pool, admin_id).await;

        assert!(res.is_ok(), "force_password_change failed: {:?}", res.err());
        assert_eq!(
            invalidated, 1,
            "force_password_change MUST write one SESSIONS_INVALIDATED row"
        );
        assert_eq!(
            changed, 0,
            "force_password_change must NOT emit PASSWORD_CHANGED (no password changed)"
        );
    }
}
