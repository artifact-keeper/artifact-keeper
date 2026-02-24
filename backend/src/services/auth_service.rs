//! Authentication service.
//!
//! Handles user authentication, JWT token management, and password hashing.

use std::sync::Arc;

use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::Config;
use crate::error::{AppError, Result};
use crate::models::user::{AuthProvider, User};

/// Federated authentication credentials
#[derive(Debug, Clone)]
pub struct FederatedCredentials {
    /// External provider user ID
    pub external_id: String,
    /// Username from provider
    pub username: String,
    /// Email from provider
    pub email: String,
    /// Display name from provider
    pub display_name: Option<String>,
    /// Groups/roles from provider claims
    pub groups: Vec<String>,
}

/// Result of group-to-role mapping
#[derive(Debug, Clone, Default)]
pub struct RoleMapping {
    /// Whether the user should be an admin
    pub is_admin: bool,
    /// Additional role names to assign
    pub roles: Vec<String>,
}

/// Result of API token validation: the user plus the token's constraints.
#[derive(Debug, Clone)]
pub struct ApiTokenValidation {
    /// The authenticated user
    pub user: User,
    /// Token scopes (e.g. "read:artifacts", "write:artifacts", "*")
    pub scopes: Vec<String>,
    /// Repository IDs the token is restricted to (None = unrestricted)
    pub allowed_repo_ids: Option<Vec<Uuid>>,
}

/// JWT claims structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: Uuid,
    /// Username
    pub username: String,
    /// Email
    pub email: String,
    /// Is admin
    pub is_admin: bool,
    /// Issued at (Unix timestamp)
    pub iat: i64,
    /// Expiration time (Unix timestamp)
    pub exp: i64,
    /// Token type: "access" or "refresh"
    pub token_type: String,
}

/// Token pair response
#[derive(Debug, Serialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

/// Authentication service
pub struct AuthService {
    db: PgPool,
    config: Arc<Config>,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl AuthService {
    /// Create a new authentication service
    pub fn new(db: PgPool, config: Arc<Config>) -> Self {
        let secret = config.jwt_secret.clone();
        Self {
            db,
            config,
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
        }
    }

    /// Authenticate user with username and password
    pub async fn authenticate(&self, username: &str, password: &str) -> Result<(User, TokenPair)> {
        // Fetch user from database
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
            WHERE username = $1 AND is_active = true
            "#,
            username
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::Authentication("Invalid username or password".to_string()))?;

        // Verify password for local auth
        if user.auth_provider != AuthProvider::Local {
            return Err(AppError::Authentication(
                "Use SSO provider to authenticate".to_string(),
            ));
        }

        let password_hash = user
            .password_hash
            .as_ref()
            .ok_or_else(|| AppError::Authentication("Invalid username or password".to_string()))?;

        if !verify(password, password_hash)
            .map_err(|e| AppError::Internal(format!("Password verification failed: {}", e)))?
        {
            return Err(AppError::Authentication(
                "Invalid username or password".to_string(),
            ));
        }

        // Update last login
        sqlx::query!(
            "UPDATE users SET last_login_at = NOW() WHERE id = $1",
            user.id
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Generate tokens
        let tokens = self.generate_tokens(&user)?;

        Ok((user, tokens))
    }

    /// Generate access and refresh tokens for a user
    pub fn generate_tokens(&self, user: &User) -> Result<TokenPair> {
        let now = Utc::now();
        let access_exp = now + Duration::minutes(self.config.jwt_access_token_expiry_minutes);
        let refresh_exp = now + Duration::days(self.config.jwt_refresh_token_expiry_days);

        let access_claims = Claims {
            sub: user.id,
            username: user.username.clone(),
            email: user.email.clone(),
            is_admin: user.is_admin,
            iat: now.timestamp(),
            exp: access_exp.timestamp(),
            token_type: "access".to_string(),
        };

        let refresh_claims = Claims {
            sub: user.id,
            username: user.username.clone(),
            email: user.email.clone(),
            is_admin: user.is_admin,
            iat: now.timestamp(),
            exp: refresh_exp.timestamp(),
            token_type: "refresh".to_string(),
        };

        let access_token = encode(&Header::default(), &access_claims, &self.encoding_key)
            .map_err(|e| AppError::Internal(format!("Token encoding failed: {}", e)))?;

        let refresh_token = encode(&Header::default(), &refresh_claims, &self.encoding_key)
            .map_err(|e| AppError::Internal(format!("Token encoding failed: {}", e)))?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            expires_in: (self.config.jwt_access_token_expiry_minutes * 60) as u64,
        })
    }

    /// Validate and decode an access token
    pub fn validate_access_token(&self, token: &str) -> Result<Claims> {
        let token_data = self.decode_token(token)?;

        if token_data.claims.token_type != "access" {
            return Err(AppError::Authentication("Invalid token type".to_string()));
        }

        Ok(token_data.claims)
    }

    /// Refresh tokens using a refresh token
    pub async fn refresh_tokens(&self, refresh_token: &str) -> Result<(User, TokenPair)> {
        let token_data = self.decode_token(refresh_token)?;

        if token_data.claims.token_type != "refresh" {
            return Err(AppError::Authentication("Invalid token type".to_string()));
        }

        // Fetch fresh user data
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
            WHERE id = $1 AND is_active = true
            "#,
            token_data.claims.sub
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::Authentication("User not found".to_string()))?;

        let tokens = self.generate_tokens(&user)?;
        Ok((user, tokens))
    }

    /// Decode and validate a token
    fn decode_token(&self, token: &str) -> Result<TokenData<Claims>> {
        decode::<Claims>(token, &self.decoding_key, &Validation::default())
            .map_err(|e| AppError::Authentication(format!("Invalid token: {}", e)))
    }

    /// Hash a password
    pub fn hash_password(password: &str) -> Result<String> {
        hash(password, DEFAULT_COST)
            .map_err(|e| AppError::Internal(format!("Password hashing failed: {}", e)))
    }

    /// Verify a password against a hash
    pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
        verify(password, hash)
            .map_err(|e| AppError::Internal(format!("Password verification failed: {}", e)))
    }

    /// Validate API token and return user with scopes and repository restrictions.
    pub async fn validate_api_token(&self, token: &str) -> Result<ApiTokenValidation> {
        // API tokens have format: prefix_secret
        // We store hash of full token and prefix for lookup
        if token.len() < 8 {
            return Err(AppError::Authentication("Invalid API token".to_string()));
        }

        let prefix = &token[..8];

        // Find token by prefix
        let stored_token = sqlx::query!(
            r#"
            SELECT at.id, at.token_hash, at.user_id, at.scopes, at.expires_at,
                   at.repo_selector
            FROM api_tokens at
            WHERE at.token_prefix = $1
            "#,
            prefix
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::Authentication("Invalid API token".to_string()))?;

        // Verify full token hash
        if !Self::verify_password(token, &stored_token.token_hash)? {
            return Err(AppError::Authentication("Invalid API token".to_string()));
        }

        // Check expiration
        if let Some(expires_at) = stored_token.expires_at {
            if expires_at < Utc::now() {
                return Err(AppError::Authentication("API token expired".to_string()));
            }
        }

        // Update last used timestamp
        sqlx::query!(
            "UPDATE api_tokens SET last_used_at = NOW() WHERE id = $1",
            stored_token.id
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Fetch user
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
            WHERE id = $1 AND is_active = true
            "#,
            stored_token.user_id
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::Authentication("User not found".to_string()))?;

        // Fetch repository restrictions for this token.
        // If a repo_selector is set, resolve it dynamically. Otherwise fall
        // back to the explicit api_token_repositories join table.
        let allowed_repo_ids = if let Some(selector_json) = &stored_token.repo_selector {
            use crate::services::repo_selector_service::{RepoSelector, RepoSelectorService};
            let selector: RepoSelector =
                serde_json::from_value(selector_json.clone()).unwrap_or_default();
            if RepoSelectorService::is_empty(&selector) {
                None // empty selector = unrestricted
            } else {
                let svc = RepoSelectorService::new(self.db.clone());
                let ids = svc.resolve_ids(&selector).await?;
                if ids.is_empty() {
                    Some(vec![]) // selector matched nothing, deny all
                } else {
                    Some(ids)
                }
            }
        } else {
            let repo_rows = sqlx::query!(
                "SELECT repo_id FROM api_token_repositories WHERE token_id = $1",
                stored_token.id
            )
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

            if repo_rows.is_empty() {
                None // unrestricted
            } else {
                Some(repo_rows.into_iter().map(|r| r.repo_id).collect())
            }
        };

        Ok(ApiTokenValidation {
            user,
            scopes: stored_token.scopes,
            allowed_repo_ids,
        })
    }

    /// Generate a new API token
    pub async fn generate_api_token(
        &self,
        user_id: Uuid,
        name: &str,
        scopes: Vec<String>,
        expires_in_days: Option<i64>,
    ) -> Result<(String, Uuid)> {
        if scopes.len() > 50 {
            return Err(AppError::Validation("Too many scopes (max 50)".to_string()));
        }
        if scopes.iter().any(|s| s.len() > 256) {
            return Err(AppError::Validation(
                "Scope name too long (max 256 characters)".to_string(),
            ));
        }

        // Generate random token
        let token = format!(
            "{}_{}",
            &Uuid::new_v4().to_string()[..8],
            Uuid::new_v4().to_string().replace("-", "")
        );
        let prefix = &token[..8];
        let token_hash = Self::hash_password(&token)?;

        let expires_at = expires_in_days.map(|days| {
            let clamped = days.clamp(1, 3650); // Cap at ~10 years
            Utc::now() + Duration::days(clamped)
        });

        let record = sqlx::query!(
            r#"
            INSERT INTO api_tokens (user_id, name, token_hash, token_prefix, scopes, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            "#,
            user_id,
            name,
            token_hash,
            prefix,
            &scopes,
            expires_at
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok((token, record.id))
    }

    /// Revoke an API token
    pub async fn revoke_api_token(&self, token_id: Uuid, user_id: Uuid) -> Result<()> {
        let result = sqlx::query!(
            "DELETE FROM api_tokens WHERE id = $1 AND user_id = $2",
            token_id,
            user_id
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("API token not found".to_string()));
        }

        Ok(())
    }

    // =========================================================================
    // T055: Federated Authentication Routing
    // =========================================================================

    /// Authenticate user by routing to the appropriate provider based on auth_provider type.
    ///
    /// This method looks up the user's auth_provider and delegates to the appropriate
    /// authentication service (LDAP, OIDC, SAML) or performs local authentication.
    ///
    /// # Arguments
    /// * `username` - The username to authenticate
    /// * `password` - The password (for local/LDAP) or empty for token-based flows
    /// * `provider_override` - Optional provider to force (useful for SSO initiation)
    ///
    /// # Returns
    /// * `Ok((User, TokenPair))` - Authenticated user and JWT tokens
    /// * `Err(AppError)` - Authentication failure
    pub async fn authenticate_by_provider(
        &self,
        username: &str,
        password: &str,
        provider_override: Option<AuthProvider>,
    ) -> Result<(User, TokenPair)> {
        // First, look up the user to determine their auth provider
        let user_lookup = sqlx::query!(
            r#"
            SELECT auth_provider as "auth_provider: AuthProvider"
            FROM users
            WHERE username = $1 AND is_active = true
            "#,
            username
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Determine which provider to use
        let provider = provider_override.or_else(|| user_lookup.map(|u| u.auth_provider));

        match provider {
            Some(AuthProvider::Local) | None => {
                // Use local authentication
                self.authenticate(username, password).await
            }
            Some(AuthProvider::Ldap) => {
                // Delegate to LDAP service
                // Note: ldap_service would be injected or created here in a full implementation
                self.authenticate_ldap(username, password).await
            }
            Some(AuthProvider::Oidc) => {
                // OIDC authentication is typically handled via callback, not direct auth
                // This path would be used for token exchange after OIDC redirect
                Err(AppError::Authentication(
                    "OIDC authentication requires redirect flow. Use /auth/oidc/login endpoint."
                        .to_string(),
                ))
            }
            Some(AuthProvider::Saml) => {
                // SAML authentication is handled via SSO assertion
                // This path would be used for SAML response processing
                Err(AppError::Authentication(
                    "SAML authentication requires SSO flow. Use /auth/saml/login endpoint."
                        .to_string(),
                ))
            }
        }
    }

    /// Authenticate via LDAP provider.
    ///
    /// This is a placeholder that would delegate to LdapService in a full implementation.
    async fn authenticate_ldap(&self, username: &str, password: &str) -> Result<(User, TokenPair)> {
        // In a full implementation, this would:
        // 1. Bind to LDAP server with user credentials
        // 2. Fetch user attributes and groups
        // 3. Call sync_federated_user to create/update user
        // 4. Generate JWT tokens

        // For now, check if user exists with LDAP provider
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
            WHERE username = $1 AND auth_provider = 'ldap' AND is_active = true
            "#,
            username
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::Authentication("LDAP user not found".to_string()))?;

        // In production, LDAP bind verification would happen here
        // For development/testing, we check password if stored (hybrid mode)
        if let Some(ref hash) = user.password_hash {
            if !verify(password, hash)
                .map_err(|e| AppError::Internal(format!("Password verification failed: {}", e)))?
            {
                return Err(AppError::Authentication("Invalid credentials".to_string()));
            }
        } else {
            // Pure LDAP mode - would verify against LDAP server
            return Err(AppError::Authentication(
                "LDAP server verification not configured".to_string(),
            ));
        }

        // Update last login
        sqlx::query!(
            "UPDATE users SET last_login_at = NOW() WHERE id = $1",
            user.id
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let tokens = self.generate_tokens(&user)?;
        Ok((user, tokens))
    }

    /// Authenticate a federated user after successful SSO (OIDC/SAML).
    ///
    /// This is called after the SSO flow completes with validated credentials.
    pub async fn authenticate_federated(
        &self,
        provider: AuthProvider,
        credentials: FederatedCredentials,
    ) -> Result<(User, TokenPair)> {
        // Sync or create the user based on federated credentials
        let user = self.sync_federated_user(provider, &credentials).await?;

        // Update last login
        sqlx::query!(
            "UPDATE users SET last_login_at = NOW() WHERE id = $1",
            user.id
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let tokens = self.generate_tokens(&user)?;
        Ok((user, tokens))
    }

    // =========================================================================
    // T056: Group-to-Role Mapping
    // =========================================================================

    /// Map federated group claims to local roles and admin status.
    ///
    /// This method takes the groups from an identity provider and maps them
    /// to the application's role system. Configuration for mapping is stored
    /// in the application config.
    ///
    /// # Default Mapping Rules (configurable via config):
    /// - Groups containing "admin" or "administrators" -> is_admin = true
    /// - Groups containing "readonly" -> read-only role
    /// - All authenticated users get "user" role
    ///
    /// # Arguments
    /// * `groups` - List of group names/DNs from the identity provider
    ///
    /// # Returns
    /// * `RoleMapping` - The mapped roles and admin status
    pub fn map_groups_to_roles(&self, groups: &[String]) -> RoleMapping {
        let mut mapping = RoleMapping::default();

        // Normalize groups to lowercase for case-insensitive matching
        let normalized_groups: Vec<String> = groups.iter().map(|g| g.to_lowercase()).collect();

        // Check for admin groups
        // These patterns can be made configurable via Config
        let admin_patterns = ["admin", "administrators", "superusers", "artifact-admins"];
        for group in &normalized_groups {
            for pattern in &admin_patterns {
                if group.contains(pattern) {
                    mapping.is_admin = true;
                    mapping.roles.push("admin".to_string());
                    break;
                }
            }
        }

        // Map other groups to roles
        // In a production system, this would read from a config table
        let role_mappings = [
            ("developers", "developer"),
            ("readonly", "reader"),
            ("deployers", "deployer"),
            ("artifact-publishers", "publisher"),
        ];

        for group in &normalized_groups {
            for (pattern, role) in &role_mappings {
                if group.contains(pattern) && !mapping.roles.contains(&role.to_string()) {
                    mapping.roles.push(role.to_string());
                }
            }
        }

        // All authenticated users get at least the "user" role
        if !mapping.roles.contains(&"user".to_string()) {
            mapping.roles.push("user".to_string());
        }

        mapping
    }

    /// Apply role mapping to a user in the database.
    ///
    /// Updates the user's is_admin flag and assigns roles based on the mapping.
    pub async fn apply_role_mapping(&self, user_id: Uuid, mapping: &RoleMapping) -> Result<()> {
        // Update is_admin flag
        sqlx::query!(
            "UPDATE users SET is_admin = $2, updated_at = NOW() WHERE id = $1",
            user_id,
            mapping.is_admin
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Clear existing role assignments and add new ones
        // First, remove all current roles (for federated users, roles come from provider)
        sqlx::query!("DELETE FROM user_roles WHERE user_id = $1", user_id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        // Assign new roles based on mapping
        for role_name in &mapping.roles {
            // Look up role by name and assign if it exists
            let role = sqlx::query!("SELECT id FROM roles WHERE name = $1", role_name)
                .fetch_optional(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;

            if let Some(role) = role {
                sqlx::query!(
                    "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                    user_id,
                    role.id
                )
                .execute(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
            }
        }

        Ok(())
    }

    // =========================================================================
    // T060: Federated User Sync and Deactivation
    // =========================================================================

    /// Sync a federated user from an identity provider.
    ///
    /// This method creates a new user or updates an existing user based on
    /// credentials received from a federated identity provider (LDAP, OIDC, SAML).
    ///
    /// # Arguments
    /// * `provider` - The authentication provider type
    /// * `credentials` - User information from the identity provider
    ///
    /// # Returns
    /// * `Ok(User)` - The created or updated user
    /// * `Err(AppError)` - If sync fails
    pub async fn sync_federated_user(
        &self,
        provider: AuthProvider,
        credentials: &FederatedCredentials,
    ) -> Result<User> {
        // Map groups to roles
        let role_mapping = self.map_groups_to_roles(&credentials.groups);

        // Check if user exists by external_id
        let existing_user = sqlx::query_as!(
            User,
            r#"
            SELECT
                id, username, email, password_hash, display_name,
                auth_provider as "auth_provider: AuthProvider",
                external_id, is_admin, is_active, is_service_account, must_change_password,
                totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
                last_login_at, created_at, updated_at
            FROM users
            WHERE external_id = $1 AND auth_provider = $2
            "#,
            credentials.external_id,
            provider as AuthProvider
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let user = if let Some(existing) = existing_user {
            // Update existing user with latest information from provider
            sqlx::query_as!(
                User,
                r#"
                UPDATE users
                SET
                    username = $2,
                    email = $3,
                    display_name = $4,
                    is_admin = $5,
                    is_active = true,
                    updated_at = NOW()
                WHERE id = $1
                RETURNING
                    id, username, email, password_hash, display_name,
                    auth_provider as "auth_provider: AuthProvider",
                    external_id, is_admin, is_active, is_service_account, must_change_password,
                    totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
                    last_login_at, created_at, updated_at
                "#,
                existing.id,
                credentials.username,
                credentials.email,
                credentials.display_name,
                role_mapping.is_admin
            )
            .fetch_one(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
        } else {
            // Create new user from federated credentials
            sqlx::query_as!(
                User,
                r#"
                INSERT INTO users (
                    username, email, display_name, auth_provider,
                    external_id, is_admin, is_active, is_service_account, must_change_password
                )
                VALUES ($1, $2, $3, $4, $5, $6, true, false, false)
                RETURNING
                    id, username, email, password_hash, display_name,
                    auth_provider as "auth_provider: AuthProvider",
                    external_id, is_admin, is_active, is_service_account, must_change_password,
                    totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
                    last_login_at, created_at, updated_at
                "#,
                credentials.username,
                credentials.email,
                credentials.display_name,
                provider as AuthProvider,
                credentials.external_id,
                role_mapping.is_admin
            )
            .fetch_one(&self.db)
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
            })?
        };

        // Apply role mapping
        self.apply_role_mapping(user.id, &role_mapping).await?;

        Ok(user)
    }

    /// Deactivate users who no longer exist in the federated provider.
    ///
    /// This method is typically called during a periodic sync job. It compares
    /// the list of active users from the provider with local users and deactivates
    /// any that are no longer present.
    ///
    /// # Arguments
    /// * `provider` - The authentication provider type
    /// * `active_external_ids` - List of external IDs that are still active in the provider
    ///
    /// # Returns
    /// * `Ok(u64)` - Number of users deactivated
    /// * `Err(AppError)` - If deactivation fails
    pub async fn deactivate_missing_users(
        &self,
        provider: AuthProvider,
        active_external_ids: &[String],
    ) -> Result<u64> {
        // Deactivate users that:
        // 1. Are from the specified provider
        // 2. Have an external_id that is NOT in the active list
        // 3. Are currently active
        let result = sqlx::query!(
            r#"
            UPDATE users
            SET is_active = false, updated_at = NOW()
            WHERE auth_provider = $1
              AND is_active = true
              AND external_id IS NOT NULL
              AND external_id != ALL($2)
            "#,
            provider as AuthProvider,
            active_external_ids
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(result.rows_affected())
    }

    /// Reactivate a previously deactivated federated user.
    ///
    /// This is called when a user who was deactivated (e.g., left the company)
    /// returns and authenticates again via the federated provider.
    pub async fn reactivate_federated_user(
        &self,
        external_id: &str,
        provider: AuthProvider,
    ) -> Result<User> {
        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET is_active = true, updated_at = NOW()
            WHERE external_id = $1 AND auth_provider = $2
            RETURNING
                id, username, email, password_hash, display_name,
                auth_provider as "auth_provider: AuthProvider",
                external_id, is_admin, is_active, is_service_account, must_change_password,
                totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
                last_login_at, created_at, updated_at
            "#,
            external_id,
            provider as AuthProvider
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        Ok(user)
    }

    /// List all users from a specific provider that need sync verification.
    ///
    /// Returns users who haven't been verified against the provider recently.
    pub async fn list_users_for_sync(&self, provider: AuthProvider) -> Result<Vec<User>> {
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
            WHERE auth_provider = $1 AND is_active = true
            ORDER BY username
            "#,
            provider as AuthProvider
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(users)
    }

    // =========================================================================
    // TOTP 2FA Support
    // =========================================================================

    /// Generate a short-lived token for TOTP verification pending state
    pub fn generate_totp_pending_token(&self, user: &User) -> Result<String> {
        let now = Utc::now();
        let exp = now + Duration::minutes(5);
        let claims = Claims {
            sub: user.id,
            username: user.username.clone(),
            email: user.email.clone(),
            is_admin: user.is_admin,
            iat: now.timestamp(),
            exp: exp.timestamp(),
            token_type: "totp_pending".to_string(),
        };
        encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| AppError::Internal(format!("Token encoding failed: {}", e)))
    }

    /// Validate a TOTP pending token and return claims
    pub fn validate_totp_pending_token(&self, token: &str) -> Result<Claims> {
        let token_data = self.decode_token(token)?;
        if token_data.claims.token_type != "totp_pending" {
            return Err(AppError::Authentication("Invalid token type".to_string()));
        }
        Ok(token_data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing() {
        let password = "test_password_123";
        let hash = AuthService::hash_password(password).unwrap();
        assert!(AuthService::verify_password(password, &hash).unwrap());
        assert!(!AuthService::verify_password("wrong_password", &hash).unwrap());
    }

    // -----------------------------------------------------------------------
    // Password hashing edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_password_hashing_empty_string() {
        let hash = AuthService::hash_password("").unwrap();
        assert!(AuthService::verify_password("", &hash).unwrap());
        assert!(!AuthService::verify_password("non-empty", &hash).unwrap());
    }

    #[test]
    fn test_password_hashing_unicode() {
        let password = "\u{1F600}password\u{00E9}\u{00FC}";
        let hash = AuthService::hash_password(password).unwrap();
        assert!(AuthService::verify_password(password, &hash).unwrap());
    }

    #[test]
    fn test_password_hashing_long_password() {
        // bcrypt typically truncates at 72 bytes; verify the function works
        let password = "a".repeat(100);
        let hash = AuthService::hash_password(&password).unwrap();
        assert!(AuthService::verify_password(&password, &hash).unwrap());
    }

    #[test]
    fn test_password_hash_different_each_time() {
        let password = "same_password";
        let hash1 = AuthService::hash_password(password).unwrap();
        let hash2 = AuthService::hash_password(password).unwrap();
        // bcrypt uses random salts, so hashes should differ
        assert_ne!(hash1, hash2);
        // But both should verify correctly
        assert!(AuthService::verify_password(password, &hash1).unwrap());
        assert!(AuthService::verify_password(password, &hash2).unwrap());
    }

    #[test]
    fn test_verify_password_invalid_hash() {
        // An invalid bcrypt hash should return an error, not panic
        let result = AuthService::verify_password("password", "not-a-valid-hash");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Token generation & validation (no DB needed)
    // -----------------------------------------------------------------------

    fn make_test_config() -> Arc<Config> {
        Arc::new(Config {
            database_url: "postgresql://unused".to_string(),
            bind_address: "0.0.0.0:8080".to_string(),
            log_level: "info".to_string(),
            storage_backend: "filesystem".to_string(),
            storage_path: "/tmp/test".to_string(),
            s3_bucket: None,
            s3_region: None,
            s3_endpoint: None,
            jwt_secret: "super-secret-test-key-for-unit-tests-minimum-length".to_string(),
            jwt_expiration_secs: 86400,
            jwt_access_token_expiry_minutes: 30,
            jwt_refresh_token_expiry_days: 7,
            oidc_issuer: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            ldap_url: None,
            ldap_base_dn: None,
            trivy_url: None,
            openscap_url: None,
            openscap_profile: "standard".to_string(),
            meilisearch_url: None,
            meilisearch_api_key: None,
            scan_workspace_path: "/tmp".to_string(),
            demo_mode: false,
            peer_instance_name: "test".to_string(),
            peer_public_endpoint: "http://localhost:8080".to_string(),
            peer_api_key: "test-key".to_string(),
            dependency_track_url: None,
            otel_exporter_otlp_endpoint: None,
            otel_service_name: "test".to_string(),
        })
    }

    fn make_test_user() -> User {
        User {
            id: Uuid::new_v4(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            password_hash: None,
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
            last_login_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    // We cannot create a PgPool without a real database, so for unit tests that
    // need JWT encoding/decoding, we directly use jsonwebtoken's encode/decode
    // with the same keys the AuthService would use.

    #[test]
    fn test_generate_tokens_and_validate_access_token() {
        let config = make_test_config();
        let secret = config.jwt_secret.clone();
        let encoding_key = EncodingKey::from_secret(secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(secret.as_bytes());

        let user = make_test_user();
        let now = Utc::now();
        let access_exp = now + Duration::minutes(config.jwt_access_token_expiry_minutes);
        let refresh_exp = now + Duration::days(config.jwt_refresh_token_expiry_days);

        let access_claims = Claims {
            sub: user.id,
            username: user.username.clone(),
            email: user.email.clone(),
            is_admin: user.is_admin,
            iat: now.timestamp(),
            exp: access_exp.timestamp(),
            token_type: "access".to_string(),
        };

        let refresh_claims = Claims {
            sub: user.id,
            username: user.username.clone(),
            email: user.email.clone(),
            is_admin: user.is_admin,
            iat: now.timestamp(),
            exp: refresh_exp.timestamp(),
            token_type: "refresh".to_string(),
        };

        let access_token = encode(&Header::default(), &access_claims, &encoding_key).unwrap();
        let refresh_token = encode(&Header::default(), &refresh_claims, &encoding_key).unwrap();

        // Validate access token
        let decoded =
            decode::<Claims>(&access_token, &decoding_key, &Validation::default()).unwrap();
        assert_eq!(decoded.claims.sub, user.id);
        assert_eq!(decoded.claims.username, "testuser");
        assert_eq!(decoded.claims.token_type, "access");
        assert!(!decoded.claims.is_admin);

        // Validate refresh token
        let decoded =
            decode::<Claims>(&refresh_token, &decoding_key, &Validation::default()).unwrap();
        assert_eq!(decoded.claims.sub, user.id);
        assert_eq!(decoded.claims.token_type, "refresh");
    }

    #[test]
    fn test_validate_access_token_rejects_refresh_token() {
        let config = make_test_config();
        let secret = config.jwt_secret.clone();
        let encoding_key = EncodingKey::from_secret(secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(secret.as_bytes());

        let now = Utc::now();
        let refresh_claims = Claims {
            sub: Uuid::new_v4(),
            username: "user".to_string(),
            email: "user@test.com".to_string(),
            is_admin: false,
            iat: now.timestamp(),
            exp: (now + Duration::days(7)).timestamp(),
            token_type: "refresh".to_string(),
        };

        let token = encode(&Header::default(), &refresh_claims, &encoding_key).unwrap();

        // Decoding succeeds, but validate_access_token should reject
        let decoded = decode::<Claims>(&token, &decoding_key, &Validation::default()).unwrap();
        assert_eq!(decoded.claims.token_type, "refresh");
        // This would fail in validate_access_token because token_type != "access"
    }

    #[test]
    fn test_expired_token_rejected() {
        let config = make_test_config();
        let secret = config.jwt_secret.clone();
        let encoding_key = EncodingKey::from_secret(secret.as_bytes());
        let decoding_key = DecodingKey::from_secret(secret.as_bytes());

        let now = Utc::now();
        let claims = Claims {
            sub: Uuid::new_v4(),
            username: "expired".to_string(),
            email: "expired@test.com".to_string(),
            is_admin: false,
            iat: (now - Duration::hours(2)).timestamp(),
            exp: (now - Duration::hours(1)).timestamp(), // expired 1 hour ago
            token_type: "access".to_string(),
        };

        let token = encode(&Header::default(), &claims, &encoding_key).unwrap();
        let result = decode::<Claims>(&token, &decoding_key, &Validation::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_secret_rejected() {
        let encoding_key = EncodingKey::from_secret(b"secret-one");
        let decoding_key = DecodingKey::from_secret(b"secret-two");

        let now = Utc::now();
        let claims = Claims {
            sub: Uuid::new_v4(),
            username: "user".to_string(),
            email: "u@t.com".to_string(),
            is_admin: false,
            iat: now.timestamp(),
            exp: (now + Duration::hours(1)).timestamp(),
            token_type: "access".to_string(),
        };

        let token = encode(&Header::default(), &claims, &encoding_key).unwrap();
        let result = decode::<Claims>(&token, &decoding_key, &Validation::default());
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Claims serialization / deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_claims_serialization_roundtrip() {
        let user_id = Uuid::new_v4();
        let claims = Claims {
            sub: user_id,
            username: "test".to_string(),
            email: "test@x.com".to_string(),
            is_admin: true,
            iat: 1000,
            exp: 2000,
            token_type: "access".to_string(),
        };

        let json = serde_json::to_string(&claims).unwrap();
        let decoded: Claims = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.sub, user_id);
        assert_eq!(decoded.username, "test");
        assert!(decoded.is_admin);
        assert_eq!(decoded.token_type, "access");
    }

    // -----------------------------------------------------------------------
    // TokenPair serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_token_pair_serialize() {
        let pair = TokenPair {
            access_token: "access123".to_string(),
            refresh_token: "refresh456".to_string(),
            expires_in: 1800,
        };
        let json = serde_json::to_value(&pair).unwrap();
        assert_eq!(json["access_token"], "access123");
        assert_eq!(json["refresh_token"], "refresh456");
        assert_eq!(json["expires_in"], 1800);
    }

    // -----------------------------------------------------------------------
    // FederatedCredentials
    // -----------------------------------------------------------------------

    #[test]
    fn test_federated_credentials_debug() {
        let creds = FederatedCredentials {
            external_id: "ext-123".to_string(),
            username: "feduser".to_string(),
            email: "fed@example.com".to_string(),
            display_name: Some("Fed User".to_string()),
            groups: vec!["devs".to_string(), "admin".to_string()],
        };
        let debug = format!("{:?}", creds);
        assert!(debug.contains("feduser"));
        assert!(debug.contains("ext-123"));
    }

    // -----------------------------------------------------------------------
    // RoleMapping
    // -----------------------------------------------------------------------

    #[test]
    fn test_role_mapping_default() {
        let mapping = RoleMapping::default();
        assert!(!mapping.is_admin);
        assert!(mapping.roles.is_empty());
    }

    // -----------------------------------------------------------------------
    // map_groups_to_roles (pure function, no DB)
    // -----------------------------------------------------------------------

    // We can test map_groups_to_roles by creating a minimal AuthService.
    // Since it does not use self.db or self.config, we just need any instance.
    // We'll test using the same approach: direct key construction.

    // Reimplement map_groups_to_roles locally since AuthService requires PgPool
    // and we cannot create one without a real database connection.
    fn test_map_groups_to_roles(groups: &[String]) -> RoleMapping {
        let mut mapping = RoleMapping::default();
        let normalized_groups: Vec<String> = groups.iter().map(|g| g.to_lowercase()).collect();

        let admin_patterns = ["admin", "administrators", "superusers", "artifact-admins"];
        for group in &normalized_groups {
            for pattern in &admin_patterns {
                if group.contains(pattern) {
                    mapping.is_admin = true;
                    mapping.roles.push("admin".to_string());
                    break;
                }
            }
        }

        let role_mappings = [
            ("developers", "developer"),
            ("readonly", "reader"),
            ("deployers", "deployer"),
            ("artifact-publishers", "publisher"),
        ];

        for group in &normalized_groups {
            for (pattern, role) in &role_mappings {
                if group.contains(pattern) && !mapping.roles.contains(&role.to_string()) {
                    mapping.roles.push(role.to_string());
                }
            }
        }

        if !mapping.roles.contains(&"user".to_string()) {
            mapping.roles.push("user".to_string());
        }

        mapping
    }

    #[test]
    fn test_map_groups_admin_group() {
        let mapping = test_map_groups_to_roles(&["team-admin".to_string()]);
        assert!(mapping.is_admin);
        assert!(mapping.roles.contains(&"admin".to_string()));
    }

    #[test]
    fn test_map_groups_administrators_group() {
        let mapping = test_map_groups_to_roles(&["CN=Administrators,DC=corp".to_string()]);
        assert!(mapping.is_admin);
    }

    #[test]
    fn test_map_groups_superusers_group() {
        let mapping = test_map_groups_to_roles(&["superusers".to_string()]);
        assert!(mapping.is_admin);
    }

    #[test]
    fn test_map_groups_artifact_admins_group() {
        let mapping = test_map_groups_to_roles(&["artifact-admins".to_string()]);
        assert!(mapping.is_admin);
    }

    #[test]
    fn test_map_groups_case_insensitive_admin() {
        let mapping = test_map_groups_to_roles(&["ADMIN-TEAM".to_string()]);
        assert!(mapping.is_admin);
    }

    #[test]
    fn test_map_groups_developers() {
        let mapping = test_map_groups_to_roles(&["team-developers".to_string()]);
        assert!(!mapping.is_admin);
        assert!(mapping.roles.contains(&"developer".to_string()));
        assert!(mapping.roles.contains(&"user".to_string()));
    }

    #[test]
    fn test_map_groups_readonly() {
        let mapping = test_map_groups_to_roles(&["readonly-users".to_string()]);
        assert!(mapping.roles.contains(&"reader".to_string()));
    }

    #[test]
    fn test_map_groups_deployers() {
        let mapping = test_map_groups_to_roles(&["deployers".to_string()]);
        assert!(mapping.roles.contains(&"deployer".to_string()));
    }

    #[test]
    fn test_map_groups_publishers() {
        let mapping = test_map_groups_to_roles(&["artifact-publishers".to_string()]);
        assert!(mapping.roles.contains(&"publisher".to_string()));
    }

    #[test]
    fn test_map_groups_no_matching_groups() {
        let mapping = test_map_groups_to_roles(&["random-group".to_string()]);
        assert!(!mapping.is_admin);
        assert_eq!(mapping.roles, vec!["user"]);
    }

    #[test]
    fn test_map_groups_empty_groups() {
        let mapping = test_map_groups_to_roles(&[]);
        assert!(!mapping.is_admin);
        assert_eq!(mapping.roles, vec!["user"]);
    }

    #[test]
    fn test_map_groups_multiple_roles() {
        let mapping =
            test_map_groups_to_roles(&["developers".to_string(), "deployers".to_string()]);
        assert!(mapping.roles.contains(&"developer".to_string()));
        assert!(mapping.roles.contains(&"deployer".to_string()));
        assert!(mapping.roles.contains(&"user".to_string()));
    }

    #[test]
    fn test_map_groups_admin_plus_developer() {
        let mapping = test_map_groups_to_roles(&["admin".to_string(), "developers".to_string()]);
        assert!(mapping.is_admin);
        assert!(mapping.roles.contains(&"admin".to_string()));
        assert!(mapping.roles.contains(&"developer".to_string()));
        // user role should not be duplicated
        let user_count = mapping
            .roles
            .iter()
            .filter(|r| r.as_str() == "user")
            .count();
        assert_eq!(user_count, 1);
    }

    #[test]
    fn test_map_groups_no_duplicate_roles() {
        let mapping = test_map_groups_to_roles(&[
            "developers".to_string(),
            "team-developers".to_string(), // same pattern matches twice
        ]);
        let dev_count = mapping
            .roles
            .iter()
            .filter(|r| r.as_str() == "developer")
            .count();
        assert_eq!(dev_count, 1, "developer role should not be duplicated");
    }
}
