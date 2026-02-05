//! User management handlers.

use axum::{
    extract::{Extension, Path, Query, State},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
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

#[derive(Debug, Deserialize)]
pub struct ListUsersQuery {
    pub search: Option<String>,
    pub is_active: Option<bool>,
    pub is_admin: Option<bool>,
    pub page: Option<u32>,
    pub per_page: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: Option<String>, // Optional - will auto-generate if not provided
    pub display_name: Option<String>,
    pub is_admin: Option<bool>,
}

/// Generate a secure random password
fn generate_password() -> String {
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

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub is_active: Option<bool>,
    pub is_admin: Option<bool>,
}

#[derive(Debug, Serialize)]
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

#[derive(Debug, Serialize)]
pub struct CreateUserResponse {
    pub user: UserResponse,
    pub generated_password: Option<String>, // Only returned if password was auto-generated
}

#[derive(Debug, Serialize)]
pub struct UserListResponse {
    pub items: Vec<UserResponse>,
    pub pagination: Pagination,
}

fn user_to_response(user: User) -> UserResponse {
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

#[derive(Debug, Serialize)]
pub struct RoleResponse {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RoleListResponse {
    pub items: Vec<RoleResponse>,
}

/// Get user roles
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

#[derive(Debug, Deserialize)]
pub struct AssignRoleRequest {
    pub role_id: Uuid,
}

/// Assign role to user
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

#[derive(Debug, Deserialize)]
pub struct CreateApiTokenRequest {
    pub name: String,
    pub scopes: Vec<String>,
    pub expires_in_days: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ApiTokenResponse {
    pub id: Uuid,
    pub name: String,
    pub token_prefix: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct ApiTokenCreatedResponse {
    pub id: Uuid,
    pub name: String,
    pub token: String, // Only shown once at creation
}

#[derive(Debug, Serialize)]
pub struct ApiTokenListResponse {
    pub items: Vec<ApiTokenResponse>,
}

/// List user's API tokens
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

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: Option<String>, // Required for non-admins
    pub new_password: String,
}

/// Change user password
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
#[derive(Debug, Serialize)]
pub struct ResetPasswordResponse {
    pub temporary_password: String,
}

/// Reset user password (admin only)
/// Generates a new temporary password and sets must_change_password=true
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
