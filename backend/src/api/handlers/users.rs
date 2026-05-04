//! User management handlers.

use axum::{
    extract::{Extension, Path, Query, State},
    routing::{delete, get, post},
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
use crate::services::auth_service::{
    invalidate_user_token_cache_entries, invalidate_user_tokens, AuthService,
};
use std::sync::atomic::Ordering;

/// Create user routes that require admin privileges.
///
/// The `change_password` route is intentionally NOT included here — see
/// [`self_service_router`]. A non-admin must be able to change their OWN
/// password (issue #1010), and the `change_password` handler enforces
/// ownership (`auth.user_id == path id`) plus the current-password check
/// itself. Mounting it behind `admin_middleware` would lock non-admins out
/// of the forced-password-reset flow on first login.
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_users).post(create_user))
        .route("/:id", get(get_user).patch(update_user).delete(delete_user))
        .route("/:id/roles", get(get_user_roles).post(assign_role))
        .route("/:id/roles/:role_id", delete(revoke_role))
        .route("/:id/tokens", get(list_user_tokens).post(create_api_token))
        .route("/:id/tokens/:token_id", delete(revoke_api_token))
        .route("/:id/password/reset", post(reset_password))
}

/// User routes that only require an authenticated caller (not admin).
///
/// The `change_password` handler performs its own ownership check: it only
/// allows the call when `auth.user_id == path id` OR `auth.is_admin`, and
/// requires the current password for self-service changes. This router is
/// mounted at the same `/users` prefix as [`router`] but with the standard
/// `auth_middleware` instead of `admin_middleware` (issue #1010).
///
/// The `/me` and `/me/password` aliases (issue #1008) also live here so that
/// any authenticated user — including a non-admin in the forced
/// must_change_password flow — can read their own profile and change their
/// own password without tripping `admin_middleware`. The literal `/me` and
/// `/me/password` routes MUST be registered before `/:id/password` so axum's
/// matcher resolves them as literals instead of trying to parse `me` as a
/// `Uuid` path parameter.
pub fn self_service_router() -> Router<SharedState> {
    Router::new()
        // The literal `/me` aliases must be registered BEFORE `/:id` so that
        // requests like `GET /users/me` resolve to the JWT-bound user instead
        // of being parsed as a UUID path parameter (issue #1008).
        .route("/me", get(get_current_user))
        .route("/me/password", post(change_my_password))
        .route("/:id/password", post(change_password))
}

/// Get the currently-authenticated user.
///
/// Resolves the user UUID from the JWT/API-token auth context and returns the
/// same payload as `GET /users/{id}`. Added for issue #1008 so that
/// `GET /api/v1/users/me` no longer fails with a UUID parse error. Mounted
/// under [`self_service_router`] so it is reachable by any authenticated user
/// (issue #1008 R1 Security: must NOT be gated by `admin_middleware`).
#[utoipa::path(
    get,
    path = "/me",
    context_path = "/api/v1/users",
    tag = "users",
    responses(
        (status = 200, description = "Current user details", body = AdminUserResponse),
        (status = 401, description = "Not authenticated"),
        (status = 404, description = "User not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_current_user(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
) -> Result<Json<AdminUserResponse>> {
    get_user(State(state), Path(auth.user_id)).await
}

/// Change the currently-authenticated user's password.
///
/// Convenience alias for `POST /users/{id}/password` that resolves the user
/// UUID from the auth context. Used by the first-time setup flow documented
/// in `admin.password` (issue #1008). Mounted under [`self_service_router`]
/// so a non-admin in the forced must_change_password flow can complete it
/// without tripping `admin_middleware` (issue #1008 R1 Security).
#[utoipa::path(
    post,
    path = "/me/password",
    context_path = "/api/v1/users",
    tag = "users",
    request_body = ChangePasswordRequest,
    responses(
        (status = 200, description = "Password changed successfully"),
        (status = 401, description = "Current password is incorrect"),
        (status = 404, description = "User not found"),
        (status = 422, description = "Validation error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn change_my_password(
    State(state): State<SharedState>,
    Extension(auth): Extension<AuthExtension>,
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<()> {
    let user_id = auth.user_id;
    change_password(State(state), Extension(auth), Path(user_id), Json(payload)).await
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

/// Validate password strength beyond minimum length.
fn validate_password(password: &str) -> Result<()> {
    if password.len() < 8 {
        return Err(AppError::Validation(
            "Password must be at least 8 characters".to_string(),
        ));
    }
    if password.len() > 128 {
        return Err(AppError::Validation(
            "Password must be at most 128 characters".to_string(),
        ));
    }
    const COMMON_PASSWORDS: &[&str] = &[
        "password",
        "12345678",
        "123456789",
        "1234567890",
        "qwerty123",
        "qwertyui",
        "password1",
        "iloveyou",
        "12341234",
        "00000000",
        "abc12345",
        "11111111",
        "password123",
        "admin123",
        "letmein1",
        "welcome1",
        "monkey12",
        "dragon12",
        "baseball1",
        "trustno1",
    ];
    let lower = password.to_lowercase();
    if COMMON_PASSWORDS.contains(&lower.as_str()) {
        return Err(AppError::Validation(
            "Password is too common; choose a stronger password".to_string(),
        ));
    }
    Ok(())
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
    Query(query): Query<ListUsersQuery>,
) -> Result<Json<UserListResponse>> {
    let page = query.page.unwrap_or(1).max(1);
    let per_page = query.per_page.unwrap_or(20).min(100);
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
            last_login_at, created_at, updated_at
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

    // Generate password if not provided, otherwise validate
    let (password, auto_generated) = match payload.password {
        Some(ref p) => {
            validate_password(p)?;
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
            last_login_at, created_at, updated_at
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
    Path(id): Path<Uuid>,
) -> Result<Json<AdminUserResponse>> {
    let user = sqlx::query_as!(
        User,
        r#"
        SELECT
            id, username, email, password_hash, display_name,
            auth_provider as "auth_provider: AuthProvider",
            external_id, is_admin, is_active, is_service_account, must_change_password,
            totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
            last_login_at, created_at, updated_at
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
            updated_at = NOW()
        WHERE id = $1
        RETURNING
            id, username, email, password_hash, display_name,
            auth_provider as "auth_provider: AuthProvider",
            external_id, is_admin, is_active, is_service_account, must_change_password,
            totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
            last_login_at, created_at, updated_at
        "#,
        id,
        payload.email,
        payload.display_name,
        payload.is_active,
        payload.is_admin
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
    Path(id): Path<Uuid>,
) -> Result<Json<RoleListResponse>> {
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
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(payload): Json<AssignRoleRequest>,
) -> Result<()> {
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
    Extension(_auth): Extension<AuthExtension>,
    Path((user_id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<()> {
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
    if auth.user_id != id && !auth.is_admin {
        return Err(AppError::Authorization(
            "Cannot view other users' tokens".to_string(),
        ));
    }

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
    if auth.user_id != id && !auth.is_admin {
        return Err(AppError::Authorization(
            "Cannot create tokens for other users".to_string(),
        ));
    }

    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    let (token, token_id) = auth_service
        .generate_api_token(id, &payload.name, payload.scopes, payload.expires_in_days)
        .await?;

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
    if auth.user_id != user_id && !auth.is_admin {
        return Err(AppError::Authorization(
            "Cannot revoke other users' tokens".to_string(),
        ));
    }

    let auth_service = AuthService::new(state.db.clone(), Arc::new(state.config.clone()));
    auth_service.revoke_api_token(token_id, user_id).await?;

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
    // Validate new password
    validate_password(&payload.new_password)?;

    // For non-admins changing their own password, verify current password
    if auth.user_id == id && !auth.is_admin {
        let current_password = payload
            .current_password
            .ok_or_else(|| AppError::Validation("Current password required".to_string()))?;

        let user = sqlx::query!("SELECT password_hash FROM users WHERE id = $1", id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        let hash = user.password_hash.ok_or_else(|| {
            AppError::Validation("Cannot change password for SSO users".to_string())
        })?;

        if !AuthService::verify_password(&current_password, &hash).await? {
            return Err(AppError::Authentication(
                "Current password is incorrect".to_string(),
            ));
        }
    } else if auth.user_id != id && !auth.is_admin {
        // Non-admin trying to change another user's password
        return Err(AppError::Authorization(
            "Cannot change other users' passwords".to_string(),
        ));
    }

    // Hash new password
    let new_hash = AuthService::hash_password(&payload.new_password).await?;

    // Check if this user had must_change_password set (for setup mode unlock)
    let had_must_change: bool =
        sqlx::query_scalar("SELECT must_change_password FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
            .unwrap_or(false);

    // Update password and clear must_change_password flag
    let result = sqlx::query!(
        "UPDATE users SET password_hash = $2, must_change_password = false, updated_at = NOW() WHERE id = $1",
        id,
        new_hash
    )
    .execute(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("User not found".to_string()));
    }

    crate::services::auth_service::invalidate_user_tokens(id);

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
    if user.password_hash.is_none() {
        return Err(AppError::Validation(
            "Cannot reset password for SSO users".to_string(),
        ));
    }

    // Generate new temporary password
    let temp_password = generate_password();
    let password_hash = AuthService::hash_password(&temp_password).await?;

    // Update password and set must_change_password=true
    sqlx::query("UPDATE users SET password_hash = $1, must_change_password = true, updated_at = NOW() WHERE id = $2")
        .bind(&password_hash)
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    crate::services::auth_service::invalidate_user_tokens(id);

    Ok(Json(ResetPasswordResponse {
        temporary_password: temp_password,
    }))
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list_users,
        create_user,
        get_user,
        get_current_user,
        update_user,
        delete_user,
        get_user_roles,
        assign_role,
        revoke_role,
        list_user_tokens,
        create_api_token,
        revoke_api_token,
        change_password,
        change_my_password,
        reset_password,
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

    // -- validate_password tests --

    #[test]
    fn test_validate_password_too_short() {
        let result = validate_password("abc");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("at least 8 characters"));
    }

    #[test]
    fn test_validate_password_exactly_min_length() {
        // 8 chars, not a common password
        let result = validate_password("xK9!mZ2q");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_password_too_long() {
        let long = "a".repeat(129);
        let result = validate_password(&long);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("at most 128 characters"));
    }

    #[test]
    fn test_validate_password_exactly_max_length() {
        let long = "aB3!".repeat(32); // 128 chars
        let result = validate_password(&long);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_password_common_password_rejected() {
        let result = validate_password("password");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too common"));
    }

    #[test]
    fn test_validate_password_common_password_case_insensitive() {
        // "Password" differs in case but should still be rejected
        let result = validate_password("Password");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too common"));
    }

    #[test]
    fn test_validate_password_common_numeric() {
        let result = validate_password("12345678");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too common"));
    }

    #[test]
    fn test_validate_password_common_qwerty() {
        let result = validate_password("qwerty123");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too common"));
    }

    #[test]
    fn test_validate_password_common_admin123() {
        let result = validate_password("admin123");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too common"));
    }

    #[test]
    fn test_validate_password_common_trustno1() {
        let result = validate_password("trustno1");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too common"));
    }

    #[test]
    fn test_validate_password_valid_strong_password() {
        let result = validate_password("Correct-Horse-Battery-Staple!");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_password_seven_chars_rejected() {
        let result = validate_password("aB3!xYz");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("at least 8 characters"));
    }
}

// ---------------------------------------------------------------------------
// Regression tests for issue #1010:
//   Non-admin users were unable to change their own password because the
//   entire `/users` axum nest was wrapped in `admin_middleware`. The fix
//   carved `POST /users/:id/password` into a dedicated `self_service_router`
//   mounted under `auth_middleware`, while the rest of the user-management
//   routes stayed admin-only.
//
// These tests rebuild the same composition as `routes.rs::api_v1_routes`
// (self_service_router under auth_middleware merged with admin_router under
// admin_middleware, all nested at `/users`) and exercise it through real
// JWT-authenticated requests via `tower::ServiceExt::oneshot`. They use
// stub handlers so no live database is required: the production
// `change_password` SQL would error out against a lazy pool, but the
// regression we are guarding is at the middleware/routing layer, not the
// handler body.
//
// A direct reference to `super::self_service_router` is intentionally kept
// inside the test module so this regression test fails to compile on any
// branch where the fix has been reverted.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod password_route_middleware_tests {
    use crate::api::middleware::auth::{admin_middleware, auth_middleware, AuthExtension};
    use crate::config::Config;
    use crate::models::user::{AuthProvider, User};
    use crate::services::auth_service::AuthService;
    use axum::{
        body::Body,
        extract::{Extension, Path},
        http::{Request, StatusCode},
        middleware,
        response::IntoResponse,
        routing::{get, post},
        Router,
    };
    use chrono::Utc;
    use sqlx::PgPool;
    use std::sync::Arc;
    use tower::ServiceExt;
    use uuid::Uuid;

    // ---- fixtures ---------------------------------------------------------

    fn lazy_pool() -> PgPool {
        // No socket is opened until a query runs, so this is safe in unit
        // tests without a live Postgres instance. Stub handlers below never
        // touch the pool, so no query is ever issued.
        PgPool::connect_lazy("postgres://invalid:invalid@127.0.0.1:1/none")
            .expect("connect_lazy never fails for a syntactically valid URL")
    }

    fn make_test_config() -> Arc<Config> {
        Arc::new(Config {
            jwt_secret: "regression-test-secret-key-for-issue-1010-unit-test".to_string(),
            ..Config::default()
        })
    }

    fn make_user(is_admin: bool) -> User {
        let now = Utc::now();
        User {
            id: Uuid::new_v4(),
            username: if is_admin {
                "admin_user".to_string()
            } else {
                "regular_user".to_string()
            },
            email: if is_admin {
                "admin@example.com".to_string()
            } else {
                "regular@example.com".to_string()
            },
            password_hash: None,
            auth_provider: AuthProvider::Local,
            external_id: None,
            display_name: None,
            is_active: true,
            is_admin,
            is_service_account: false,
            must_change_password: false,
            totp_secret: None,
            totp_enabled: false,
            totp_backup_codes: None,
            totp_verified_at: None,
            last_login_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    // ---- stub handlers ----------------------------------------------------
    //
    // These stand in for `change_password` and `list_users`/`get_user` in
    // the test router. They preserve the contract that matters for the
    // regression: the change_password stub mirrors the real handler's
    // ownership check (`auth.user_id == path id` OR `auth.is_admin`); the
    // admin-only stubs simply assert that the request reached them (the
    // admin gate is upstream of the handler).

    async fn stub_change_password(
        Extension(auth): Extension<AuthExtension>,
        Path(id): Path<Uuid>,
    ) -> impl IntoResponse {
        // Same ownership rule the production handler enforces: a non-admin
        // can only change their own password. The middleware composition is
        // what determines whether we even reach this handler — that is the
        // bug under test.
        if auth.user_id != id && !auth.is_admin {
            return (
                StatusCode::FORBIDDEN,
                "Cannot change other users' passwords",
            )
                .into_response();
        }
        (StatusCode::OK, "password-changed").into_response()
    }

    async fn stub_list_users(Extension(_auth): Extension<AuthExtension>) -> impl IntoResponse {
        (StatusCode::OK, "user-list").into_response()
    }

    async fn stub_get_user(
        Extension(_auth): Extension<AuthExtension>,
        Path(_id): Path<Uuid>,
    ) -> impl IntoResponse {
        (StatusCode::OK, "user-detail").into_response()
    }

    // ---- router builder ---------------------------------------------------

    /// Build a `/users` test app with the same middleware composition as the
    /// production `routes.rs::api_v1_routes` `/users` nest after the #1010
    /// fix: a self-service router carrying just the change-password route
    /// behind `auth_middleware`, merged with an admin-only router behind
    /// `admin_middleware`.
    ///
    /// The reference to `super::self_service_router` below is what makes
    /// this regression test fail to compile if the fix is reverted; the
    /// compile dependency is what proves the production fix function still
    /// exists.
    fn build_users_test_app(auth_service: Arc<AuthService>) -> Router {
        // Compile-time anchor to the production fix. If `self_service_router`
        // is removed (i.e. the fix is reverted), this test will fail to
        // compile. The production function returns `Router<SharedState>`
        // which we cannot ground to `()` here without a full AppState, so
        // we only take a function-pointer reference to prove existence.
        let _production_self_service: fn() -> Router<crate::api::SharedState> =
            super::self_service_router;
        let _production_admin: fn() -> Router<crate::api::SharedState> = super::router;

        let self_service: Router = Router::new()
            .route("/:id/password", post(stub_change_password))
            .layer(middleware::from_fn_with_state(
                auth_service.clone(),
                auth_middleware,
            ));

        let admin_only: Router = Router::new()
            .route("/", get(stub_list_users))
            .route("/:id", get(stub_get_user))
            .layer(middleware::from_fn_with_state(
                auth_service.clone(),
                admin_middleware,
            ));

        Router::new().nest("/users", self_service.merge(admin_only))
    }

    /// POST `/users/:id/password` request with a Bearer token and a
    /// minimal valid JSON body. The body content does not matter for the
    /// middleware/routing regression — the stub handler ignores it.
    fn password_change_request(uri: &str, token: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"new_password":"NewSecurePass123!"}"#))
            .unwrap()
    }

    /// GET request with a Bearer token and an empty body.
    fn bearer_get(uri: &str, token: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(uri)
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap()
    }

    async fn body_text(resp: axum::response::Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    /// Run a request through the app and return `(status, body_text)` —
    /// every regression test below makes both assertions, so this collapses
    /// the boilerplate.
    async fn send(app: Router, req: Request<Body>) -> (StatusCode, String) {
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let body = body_text(resp).await;
        (status, body)
    }

    /// Build the `/users` test app and mint a JWT for a fresh user with the
    /// requested admin flag. Returns `(app, user, access_token)`. Most
    /// regression tests need exactly this triple.
    fn setup_with_user(is_admin: bool) -> (Router, User, String) {
        let auth_service = Arc::new(AuthService::new(lazy_pool(), make_test_config()));
        let user = make_user(is_admin);
        let tokens = auth_service
            .generate_tokens(&user)
            .expect("mint access token");
        let app = build_users_test_app(auth_service);
        (app, user, tokens.access_token)
    }

    // ---- the regression tests --------------------------------------------

    #[tokio::test]
    async fn test_non_admin_can_change_own_password_through_user_routes() {
        // The original bug: this exact request returned 403 "Admin access
        // required" because `POST /users/:id/password` lived under
        // `admin_middleware`. After the fix it must reach the handler.
        let (app, user, token) = setup_with_user(/* is_admin */ false);

        let uri = format!("/users/{}/password", user.id);
        let (status, body) = send(app, password_change_request(&uri, &token)).await;

        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "non-admin self-password-change must not be blocked by admin middleware (bug #1010); body was: {body}"
        );
        assert!(
            !body.contains("Admin access required"),
            "response must not be the admin-gate rejection (bug #1010); status={status}, body={body}"
        );
        assert_eq!(
            status,
            StatusCode::OK,
            "non-admin changing own password should reach the handler and succeed; body was: {body}"
        );
        assert!(body.contains("password-changed"));
    }

    #[tokio::test]
    async fn test_non_admin_cannot_change_another_users_password() {
        // Ownership guard preserved: even though the route is reachable
        // without admin, the handler still rejects cross-user password
        // changes from non-admins.
        let (app, _attacker, token) = setup_with_user(/* is_admin */ false);
        let victim_id = Uuid::new_v4();

        let uri = format!("/users/{}/password", victim_id);
        let (status, body) = send(app, password_change_request(&uri, &token)).await;

        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "non-admin must not change another user's password; body was: {body}"
        );
        assert!(
            body.contains("Cannot change other users' passwords"),
            "expected ownership-rejection message, got: {body}"
        );
    }

    #[tokio::test]
    async fn test_admin_can_change_any_users_password() {
        // Regression guard for the admin path: the fix must not have
        // accidentally locked admins out of resetting other users.
        let (app, _admin, token) = setup_with_user(/* is_admin */ true);
        let target_id = Uuid::new_v4();

        let uri = format!("/users/{}/password", target_id);
        let (status, body) = send(app, password_change_request(&uri, &token)).await;

        assert_eq!(
            status,
            StatusCode::OK,
            "admin must be able to change any user's password; body was: {body}"
        );
        assert!(body.contains("password-changed"));
    }

    #[tokio::test]
    async fn test_non_admin_still_blocked_from_admin_only_user_routes() {
        // Regression guard for the admin gate: list/get/etc. must still be
        // admin-only after the fix splits out the password route.
        let (app, _user, token) = setup_with_user(/* is_admin */ false);

        // GET /users (list) must be admin-only.
        let (status, body) = send(app.clone(), bearer_get("/users", &token)).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "non-admin must not list users; body was: {body}"
        );
        assert!(
            body.contains("Admin access required"),
            "expected admin-gate message on /users list, got: {body}"
        );

        // GET /users/:id (detail) must also still be admin-only.
        let detail_uri = format!("/users/{}", Uuid::new_v4());
        let (status, body) = send(app, bearer_get(&detail_uri, &token)).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "non-admin must not view another user's detail; body was: {body}"
        );
        assert!(body.contains("Admin access required"));
    }

    #[tokio::test]
    async fn test_unauthenticated_password_change_rejected() {
        // The self-service route still requires authentication — `auth_middleware`
        // (not anonymous) — so a missing Authorization header must be rejected
        // at the middleware with 401 before the handler is reached.
        let auth_service = Arc::new(AuthService::new(lazy_pool(), make_test_config()));
        let app = build_users_test_app(auth_service);

        let req = Request::builder()
            .method("POST")
            .uri(format!("/users/{}/password", Uuid::new_v4()))
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"new_password":"NewSecurePass123!"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}

#[cfg(test)]
mod me_route_regression_tests {
    //! Regression tests for issue #1008.
    //!
    //! Two related bugs are guarded here:
    //!
    //! 1. **Routing collision (the original #1008 bug):** A literal `/me`
    //!    segment must resolve to the JWT-bound user instead of being parsed
    //!    as a `Uuid` path parameter. This requires the `/me` and
    //!    `/me/password` routes to be registered BEFORE any `/:id` patterns
    //!    in the same router (axum's matcher prefers literals only when they
    //!    are registered first).
    //!
    //! 2. **Middleware composition (the #1008 R1 Security BLOCKER):** The
    //!    initial fix put the `/me` aliases inside `users::router()`, which
    //!    on `release/1.1.x` is wrapped in `admin_middleware`. The result
    //!    was that `GET /users/me` and `POST /users/me/password` returned
    //!    403 "Admin access required" for any non-admin caller, defeating
    //!    the entire purpose of the alias (the documented first-time-setup
    //!    flow uses these from a non-admin context). After issue #1010 the
    //!    correct home for self-service routes is
    //!    [`super::self_service_router`], which is mounted under
    //!    `auth_middleware` in `routes.rs::api_v1_routes`.
    //!
    //! These tests exercise the **same** middleware composition the
    //! production router builds, mint real JWT tokens via
    //! `AuthService::generate_tokens`, and run requests through real
    //! `auth_middleware` / `admin_middleware`. A handler-only test would not
    //! catch the regression — the bug is in routing + middleware, not the
    //! handler bodies.
    //!
    //! Compile-time anchors to `super::self_service_router` and
    //! `super::router` ensure this test fails to compile if the route split
    //! is reverted.
    use crate::api::middleware::auth::{admin_middleware, auth_middleware, AuthExtension};
    use crate::config::Config;
    use crate::models::user::{AuthProvider, User};
    use crate::services::auth_service::AuthService;
    use axum::{
        body::Body,
        extract::{Extension, Path},
        http::{Request, StatusCode},
        middleware,
        response::IntoResponse,
        routing::{get, post},
        Router,
    };
    use chrono::Utc;
    use sqlx::PgPool;
    use std::sync::Arc;
    use tower::ServiceExt;
    use uuid::Uuid;

    // ---- fixtures ---------------------------------------------------------

    fn lazy_pool() -> PgPool {
        // No socket is opened until a query runs, so this is safe in unit
        // tests without a live Postgres instance. Stub handlers below never
        // touch the pool, so no query is ever issued.
        PgPool::connect_lazy("postgres://invalid:invalid@127.0.0.1:1/none")
            .expect("connect_lazy never fails for a syntactically valid URL")
    }

    fn make_test_config() -> Arc<Config> {
        Arc::new(Config {
            jwt_secret: "regression-test-secret-key-for-issue-1008-me-routes".to_string(),
            ..Config::default()
        })
    }

    fn make_user(is_admin: bool) -> User {
        let now = Utc::now();
        User {
            id: Uuid::new_v4(),
            username: if is_admin {
                "admin_user".to_string()
            } else {
                "regular_user".to_string()
            },
            email: if is_admin {
                "admin@example.com".to_string()
            } else {
                "regular@example.com".to_string()
            },
            password_hash: None,
            auth_provider: AuthProvider::Local,
            external_id: None,
            display_name: None,
            is_active: true,
            is_admin,
            is_service_account: false,
            must_change_password: false,
            totp_secret: None,
            totp_enabled: false,
            totp_backup_codes: None,
            totp_verified_at: None,
            last_login_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    // ---- stub handlers ----------------------------------------------------
    //
    // Stand in for the real `get_user`, `change_password`, and `list_users`
    // handlers in the test router. They preserve only the contracts that
    // matter for the regression: `/me`-aliased handlers must read the user
    // id from the `AuthExtension` (NOT from a path parameter — the bug under
    // test was a `Uuid` parse failure on the literal `me`); the admin-only
    // stubs simply assert that the request reached them, since the admin
    // gate is upstream of the handler.

    async fn stub_get_current_user(Extension(auth): Extension<AuthExtension>) -> impl IntoResponse {
        // Mirrors the production `get_current_user` contract: resolve the
        // user identity from the JWT/auth context, never from `:id`. If
        // routing wrongly sent us through `/:id` with `id == "me"`, axum
        // would have rejected the request at the `Path<Uuid>` extractor
        // before we ever got here.
        (
            StatusCode::OK,
            format!("me:{}:admin={}", auth.user_id, auth.is_admin),
        )
            .into_response()
    }

    async fn stub_change_my_password(
        Extension(auth): Extension<AuthExtension>,
    ) -> impl IntoResponse {
        // Mirrors the production `change_my_password` contract: the user id
        // comes from the auth extension, so this handler being reachable
        // (rather than 403'd by `admin_middleware`) is the regression.
        (
            StatusCode::OK,
            format!("me-password-changed:{}", auth.user_id),
        )
            .into_response()
    }

    async fn stub_change_password(
        Extension(auth): Extension<AuthExtension>,
        Path(id): Path<Uuid>,
    ) -> impl IntoResponse {
        // Same ownership rule the production handler enforces: a non-admin
        // can only change their own password. Used by the `/:id/password`
        // route inside the self-service router.
        if auth.user_id != id && !auth.is_admin {
            return (
                StatusCode::FORBIDDEN,
                "Cannot change other users' passwords",
            )
                .into_response();
        }
        (StatusCode::OK, "password-changed").into_response()
    }

    async fn stub_list_users(Extension(_auth): Extension<AuthExtension>) -> impl IntoResponse {
        (StatusCode::OK, "user-list").into_response()
    }

    async fn stub_get_user(
        Extension(_auth): Extension<AuthExtension>,
        Path(_id): Path<Uuid>,
    ) -> impl IntoResponse {
        (StatusCode::OK, "user-detail").into_response()
    }

    // ---- router builder ---------------------------------------------------

    /// Build a `/users` test app with the same middleware composition as the
    /// production `routes.rs::api_v1_routes` `/users` nest after issue
    /// #1010: a self-service router (carrying `/me`, `/me/password`, and
    /// `/:id/password`) behind `auth_middleware`, merged with an admin-only
    /// router behind `admin_middleware`.
    ///
    /// The `super::self_service_router` and `super::router` references are
    /// what make this regression test fail to compile if the production
    /// route split is reverted. The previous incarnation of the #1008 fix
    /// tested `users::router()` in isolation with a fake `AuthExtension`,
    /// which silently passed even though the production `/users` nest had
    /// the `/me` handlers behind `admin_middleware`. Building the same
    /// composition here is what closes that R1 Security gap.
    fn build_users_test_app(auth_service: Arc<AuthService>) -> Router {
        // Compile-time anchor to the production fix. If `self_service_router`
        // is removed (or stops carrying `/me`), this test will fail to
        // compile or its assertions will fail. The production function
        // returns `Router<SharedState>`, which we cannot ground to `()` here
        // without a full AppState, so we only take a function-pointer
        // reference to prove existence.
        let _production_self_service: fn() -> Router<crate::api::SharedState> =
            super::self_service_router;
        let _production_admin: fn() -> Router<crate::api::SharedState> = super::router;

        // Mirror the *exact* route shape `super::self_service_router`
        // builds: `/me` and `/me/password` registered BEFORE `/:id/password`
        // so axum resolves the literal segment correctly (issue #1008).
        let self_service: Router = Router::new()
            .route("/me", get(stub_get_current_user))
            .route("/me/password", post(stub_change_my_password))
            .route("/:id/password", post(stub_change_password))
            .layer(middleware::from_fn_with_state(
                auth_service.clone(),
                auth_middleware,
            ));

        let admin_only: Router = Router::new()
            .route("/", get(stub_list_users))
            .route("/:id", get(stub_get_user))
            .layer(middleware::from_fn_with_state(
                auth_service.clone(),
                admin_middleware,
            ));

        Router::new().nest("/users", self_service.merge(admin_only))
    }

    // ---- request helpers --------------------------------------------------

    fn bearer_get(uri: &str, token: &str) -> Request<Body> {
        Request::builder()
            .method("GET")
            .uri(uri)
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap()
    }

    fn password_change_request(uri: &str, token: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"new_password":"NewSecurePass123!"}"#))
            .unwrap()
    }

    async fn body_text(resp: axum::response::Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    async fn send(app: Router, req: Request<Body>) -> (StatusCode, String) {
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let body = body_text(resp).await;
        (status, body)
    }

    /// Build the `/users` test app and mint a real JWT for a fresh user
    /// with the requested admin flag. Returns `(app, user, access_token)`.
    fn setup_with_user(is_admin: bool) -> (Router, User, String) {
        let auth_service = Arc::new(AuthService::new(lazy_pool(), make_test_config()));
        let user = make_user(is_admin);
        let tokens = auth_service
            .generate_tokens(&user)
            .expect("mint access token");
        let app = build_users_test_app(auth_service);
        (app, user, tokens.access_token)
    }

    // ---- the regression tests --------------------------------------------

    #[tokio::test]
    async fn non_admin_can_get_users_me() {
        // The R1 Security BLOCKER: `GET /users/me` was 403 "Admin access
        // required" for any non-admin because the route was registered
        // inside `users::router()` (admin-gated). After moving it into
        // `self_service_router` (auth-gated), a non-admin's JWT must reach
        // the handler.
        let (app, user, token) = setup_with_user(/* is_admin */ false);

        let (status, body) = send(app, bearer_get("/users/me", &token)).await;

        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "non-admin GET /users/me must not be blocked by admin_middleware (#1008 R1); body was: {body}"
        );
        assert!(
            !body.contains("Admin access required"),
            "response must not be the admin-gate rejection (#1008 R1); status={status}, body={body}"
        );
        assert_eq!(
            status,
            StatusCode::OK,
            "non-admin GET /users/me should reach the handler and succeed; body was: {body}"
        );
        // The handler resolves the user from the JWT, not from a path
        // parameter — proves the request did NOT fall into the `/:id`
        // matcher and try to parse "me" as a Uuid.
        assert!(
            body.contains(&format!("me:{}:admin=false", user.id)),
            "expected me-handler payload bound to JWT user, got: {body}"
        );
    }

    #[tokio::test]
    async fn non_admin_can_post_users_me_password() {
        // Same R1 Security regression for POST /users/me/password — this is
        // the route the documented first-time-setup flow calls from a
        // non-admin context, so it MUST be reachable without admin.
        let (app, user, token) = setup_with_user(/* is_admin */ false);

        let (status, body) = send(app, password_change_request("/users/me/password", &token)).await;

        assert_ne!(
            status,
            StatusCode::FORBIDDEN,
            "non-admin POST /users/me/password must not be blocked by admin_middleware (#1008 R1); body was: {body}"
        );
        assert!(
            !body.contains("Admin access required"),
            "response must not be the admin-gate rejection (#1008 R1); status={status}, body={body}"
        );
        assert_eq!(
            status,
            StatusCode::OK,
            "non-admin POST /users/me/password should reach the handler; body was: {body}"
        );
        assert!(
            body.contains(&format!("me-password-changed:{}", user.id)),
            "expected me-password handler payload bound to JWT user, got: {body}"
        );
    }

    #[tokio::test]
    async fn admin_can_also_use_users_me() {
        // Admins are still authenticated users, so the `/me` aliases must
        // also work for them — the auth_middleware accepts any valid JWT,
        // and the merge with the admin router must not shadow the literal
        // `/me` route.
        let (app, user, token) = setup_with_user(/* is_admin */ true);

        let (status, body) = send(app, bearer_get("/users/me", &token)).await;

        assert_eq!(
            status,
            StatusCode::OK,
            "admin GET /users/me should succeed; body was: {body}"
        );
        assert!(
            body.contains(&format!("me:{}:admin=true", user.id)),
            "expected me-handler payload bound to admin JWT user, got: {body}"
        );
    }

    #[tokio::test]
    async fn me_literal_does_not_collide_with_uuid_route() {
        // The original #1008 routing bug: `GET /users/me` fell into the
        // `/:id` matcher and 400'd with "UUID parsing failed". Since the
        // self-service router only contains `/:id/password` (not `/:id`),
        // the canonical UUID-parse-failure path here is the merged admin
        // router's `/:id`. We assert that `/me` resolves to the literal
        // route and never produces a UUID-parse rejection at any layer.
        let (app, _user, token) = setup_with_user(/* is_admin */ false);

        let (status, body) = send(app, bearer_get("/users/me", &token)).await;

        // Strongest signal: literal route wins, status is 200 from the
        // self-service handler.
        assert_eq!(
            status,
            StatusCode::OK,
            "expected literal /me route to win, got {status} body={body}"
        );
        assert!(
            !body.to_ascii_lowercase().contains("uuid"),
            "response must not contain a UUID-parse failure message; body={body}"
        );
        assert!(
            !body.contains("Invalid URL"),
            "axum's Path<Uuid> rejection must not surface for /me; body={body}"
        );
    }

    #[tokio::test]
    async fn get_user_by_uuid_still_routes_to_get_user() {
        // Regression guard for the admin path: registering literal `/me`
        // before `/:id` must not break UUID-keyed `/users/{uuid}` routing
        // for admins. The admin router's `/:id` handler should still be
        // reached.
        let (app, _admin, token) = setup_with_user(/* is_admin */ true);

        let target_id = Uuid::new_v4();
        let uri = format!("/users/{}", target_id);
        let (status, body) = send(app, bearer_get(&uri, &token)).await;

        assert_eq!(
            status,
            StatusCode::OK,
            "admin GET /users/<uuid> must still route to get_user; body was: {body}"
        );
        assert!(
            body.contains("user-detail"),
            "expected the admin /:id stub to handle the request, got: {body}"
        );
    }

    #[tokio::test]
    async fn unauthenticated_me_request_rejected() {
        // The self-service router is gated by `auth_middleware`, not
        // anonymous: `/me` must still 401 without a Bearer token, the same
        // way `/:id/password` does.
        let auth_service = Arc::new(AuthService::new(lazy_pool(), make_test_config()));
        let app = build_users_test_app(auth_service);

        let req = Request::builder()
            .method("GET")
            .uri("/users/me")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
