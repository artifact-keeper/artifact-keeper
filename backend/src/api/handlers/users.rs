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
use crate::services::auth_service::AuthService;
use std::sync::atomic::Ordering;

/// Create user routes
pub fn router() -> Router<SharedState> {
    Router::new()
        .route("/", get(list_users).post(create_user))
        .route("/:id", get(get_user).patch(update_user).delete(delete_user))
        .route("/:id/roles", get(get_user_roles).post(assign_role))
        .route("/:id/roles/:role_id", delete(revoke_role))
        .route("/:id/tokens", get(list_user_tokens).post(create_api_token))
        .route("/:id/tokens/:token_id", delete(revoke_api_token))
        .route("/:id/password", post(change_password))
        .route("/:id/password/reset", post(reset_password))
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

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub is_active: Option<bool>,
    pub is_admin: Option<bool>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserResponse {
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
    pub user: UserResponse,
    pub generated_password: Option<String>, // Only returned if password was auto-generated
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserListResponse {
    pub items: Vec<UserResponse>,
    pub pagination: Pagination,
}

pub(crate) fn user_to_response(user: User) -> UserResponse {
    UserResponse {
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
            external_id, is_admin, is_active, must_change_password,
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
    Extension(_auth): Extension<AuthExtension>,
    Json(payload): Json<CreateUserRequest>,
) -> Result<Json<CreateUserResponse>> {
    // Generate password if not provided, otherwise validate
    let (password, auto_generated) = match payload.password {
        Some(ref p) if p.len() >= 8 => (p.clone(), false),
        Some(_) => {
            return Err(AppError::Validation(
                "Password must be at least 8 characters".to_string(),
            ));
        }
        None => (generate_password(), true),
    };

    // Hash password
    let password_hash = AuthService::hash_password(&password)?;

    let user = sqlx::query_as!(
        User,
        r#"
        INSERT INTO users (username, email, password_hash, display_name, auth_provider, is_admin, must_change_password)
        VALUES ($1, $2, $3, $4, 'local', $5, $6)
        RETURNING
            id, username, email, password_hash, display_name,
            auth_provider as "auth_provider: AuthProvider",
            external_id, is_admin, is_active, must_change_password,
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
        (status = 200, description = "User details", body = UserResponse),
        (status = 404, description = "User not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_user(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<UserResponse>> {
    let user = sqlx::query_as!(
        User,
        r#"
        SELECT
            id, username, email, password_hash, display_name,
            auth_provider as "auth_provider: AuthProvider",
            external_id, is_admin, is_active, must_change_password,
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
        (status = 200, description = "User updated successfully", body = UserResponse),
        (status = 404, description = "User not found"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_user(
    State(state): State<SharedState>,
    Extension(_auth): Extension<AuthExtension>,
    Path(id): Path<Uuid>,
    Json(payload): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>> {
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
            external_id, is_admin, is_active, must_change_password,
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

    let result = sqlx::query!("DELETE FROM users WHERE id = $1", id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound("User not found".to_string()));
    }

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
        WHERE user_id = $1
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
    if payload.new_password.len() < 8 {
        return Err(AppError::Validation(
            "Password must be at least 8 characters".to_string(),
        ));
    }

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

        if !AuthService::verify_password(&current_password, &hash)? {
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
    let new_hash = AuthService::hash_password(&payload.new_password)?;

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

    // If this user had must_change_password, check if setup mode should be unlocked
    if had_must_change && state.setup_required.load(Ordering::Relaxed) {
        state.setup_required.store(false, Ordering::Relaxed);
        tracing::info!("Setup complete. API fully unlocked.");

        // Delete the password file (best-effort)
        let password_file = std::path::Path::new(&state.config.storage_path).join("admin.password");
        if password_file.exists() {
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
    let password_hash = AuthService::hash_password(&temp_password)?;

    // Update password and set must_change_password=true
    sqlx::query("UPDATE users SET password_hash = $1, must_change_password = true, updated_at = NOW() WHERE id = $2")
        .bind(&password_hash)
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

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
    ),
    components(schemas(
        ListUsersQuery,
        CreateUserRequest,
        UpdateUserRequest,
        UserResponse,
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
        let resp = UserResponse {
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
            user: UserResponse {
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
            user: UserResponse {
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
}
