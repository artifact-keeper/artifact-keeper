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
                external_id, is_admin, is_active, must_change_password,
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
                external_id, is_admin, is_active, must_change_password,
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

    /// Validate API token and return user
    pub async fn validate_api_token(&self, token: &str) -> Result<User> {
        // API tokens have format: prefix_secret
        // We store hash of full token and prefix for lookup
        if token.len() < 8 {
            return Err(AppError::Authentication("Invalid API token".to_string()));
        }

        let prefix = &token[..8];

        // Find token by prefix
        let stored_token = sqlx::query!(
            r#"
            SELECT at.id, at.token_hash, at.user_id, at.scopes, at.expires_at
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
                external_id, is_admin, is_active, must_change_password,
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

        Ok(user)
    }

    /// Generate a new API token
    pub async fn generate_api_token(
        &self,
        user_id: Uuid,
        name: &str,
        scopes: Vec<String>,
        expires_in_days: Option<i64>,
    ) -> Result<(String, Uuid)> {
        // Generate random token
        let token = format!(
            "{}_{}",
            &Uuid::new_v4().to_string()[..8],
            Uuid::new_v4().to_string().replace("-", "")
        );
        let prefix = &token[..8];
        let token_hash = Self::hash_password(&token)?;

        let expires_at = expires_in_days.map(|days| Utc::now() + Duration::days(days));

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
}
