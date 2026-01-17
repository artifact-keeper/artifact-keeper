//! API Token Service.
//!
//! Provides token management functionality including creation, validation,
//! revocation, and listing of API tokens. This service can be used independently
//! or in conjunction with AuthService for comprehensive authentication needs.

use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::Config;
use crate::error::{AppError, Result};
use crate::models::api_token::{ApiToken, ApiTokenCreated};
use crate::services::auth_service::AuthService;

/// Token validation result
#[derive(Debug, Clone, Serialize)]
pub struct TokenValidation {
    /// Whether the token is valid
    pub is_valid: bool,
    /// The user ID associated with the token
    pub user_id: Option<Uuid>,
    /// Token scopes
    pub scopes: Vec<String>,
    /// Time until expiration (None if no expiration)
    pub expires_in: Option<i64>,
    /// Error message if invalid
    pub error: Option<String>,
}

/// Request for creating a new API token
#[derive(Debug, Clone, Deserialize)]
pub struct CreateTokenRequest {
    /// Display name for the token
    pub name: String,
    /// Scopes/permissions for the token
    pub scopes: Vec<String>,
    /// Days until expiration (None for no expiration)
    pub expires_in_days: Option<i64>,
}

/// Token information (without the actual token value)
#[derive(Debug, Clone, Serialize)]
pub struct TokenInfo {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub token_prefix: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub is_expired: bool,
}

impl From<ApiToken> for TokenInfo {
    fn from(token: ApiToken) -> Self {
        let is_expired = token
            .expires_at
            .map(|exp| exp < Utc::now())
            .unwrap_or(false);

        Self {
            id: token.id,
            user_id: token.user_id,
            name: token.name,
            token_prefix: token.token_prefix,
            scopes: token.scopes,
            expires_at: token.expires_at,
            last_used_at: token.last_used_at,
            created_at: token.created_at,
            is_expired,
        }
    }
}

/// API Token Service for managing programmatic access tokens.
///
/// This service provides a higher-level API for token management,
/// delegating core operations to AuthService while adding additional
/// functionality like listing, filtering, and bulk operations.
pub struct TokenService {
    db: PgPool,
    config: Arc<Config>,
}

impl TokenService {
    /// Create a new token service instance.
    pub fn new(db: PgPool, config: Arc<Config>) -> Self {
        Self { db, config }
    }

    /// Create a new API token for a user.
    ///
    /// # Arguments
    /// * `user_id` - The user to create the token for
    /// * `request` - Token creation parameters
    ///
    /// # Returns
    /// * `Ok(ApiTokenCreated)` - The created token with the actual token value
    /// * `Err(AppError)` - If creation fails
    ///
    /// Note: The actual token value is only returned once at creation time
    /// and cannot be retrieved later.
    pub async fn create_token(
        &self,
        user_id: Uuid,
        request: CreateTokenRequest,
    ) -> Result<ApiTokenCreated> {
        // Validate scopes
        self.validate_scopes(&request.scopes)?;

        // Validate expiration
        if let Some(days) = request.expires_in_days {
            if days < 1 || days > 365 {
                return Err(AppError::Validation(
                    "Token expiration must be between 1 and 365 days".to_string(),
                ));
            }
        }

        // Delegate to AuthService for actual token generation
        let auth_service = AuthService::new(self.db.clone(), self.config.clone());
        let (token, token_id) = auth_service
            .generate_api_token(user_id, &request.name, request.scopes.clone(), request.expires_in_days)
            .await?;

        let expires_at = request
            .expires_in_days
            .map(|days| Utc::now() + Duration::days(days));

        Ok(ApiTokenCreated {
            id: token_id,
            user_id,
            name: request.name,
            token,
            token_prefix: token_id.to_string()[..8].to_string(),
            scopes: request.scopes,
            expires_at,
            created_at: Utc::now(),
        })
    }

    /// Validate token scopes against allowed scopes.
    fn validate_scopes(&self, scopes: &[String]) -> Result<()> {
        // Define allowed scopes
        let allowed_scopes = [
            "read:artifacts",
            "write:artifacts",
            "delete:artifacts",
            "read:repositories",
            "write:repositories",
            "delete:repositories",
            "read:users",
            "write:users",
            "admin",
            "*", // Full access
        ];

        for scope in scopes {
            if !allowed_scopes.contains(&scope.as_str()) {
                return Err(AppError::Validation(format!(
                    "Invalid scope: '{}'. Allowed scopes: {:?}",
                    scope, allowed_scopes
                )));
            }
        }

        Ok(())
    }

    /// List all tokens for a user.
    ///
    /// # Arguments
    /// * `user_id` - The user to list tokens for
    ///
    /// # Returns
    /// * `Ok(Vec<TokenInfo>)` - List of token information (without actual token values)
    pub async fn list_tokens(&self, user_id: Uuid) -> Result<Vec<TokenInfo>> {
        let tokens = sqlx::query_as!(
            ApiToken,
            r#"
            SELECT id, user_id, name, token_hash, token_prefix, scopes,
                   expires_at, last_used_at, created_at
            FROM api_tokens
            WHERE user_id = $1
            ORDER BY created_at DESC
            "#,
            user_id
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(tokens.into_iter().map(TokenInfo::from).collect())
    }

    /// Get a specific token by ID.
    ///
    /// # Arguments
    /// * `token_id` - The token ID
    /// * `user_id` - The user ID (for authorization)
    ///
    /// # Returns
    /// * `Ok(TokenInfo)` - Token information
    /// * `Err(AppError::NotFound)` - If token doesn't exist or belongs to another user
    pub async fn get_token(&self, token_id: Uuid, user_id: Uuid) -> Result<TokenInfo> {
        let token = sqlx::query_as!(
            ApiToken,
            r#"
            SELECT id, user_id, name, token_hash, token_prefix, scopes,
                   expires_at, last_used_at, created_at
            FROM api_tokens
            WHERE id = $1 AND user_id = $2
            "#,
            token_id,
            user_id
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("API token not found".to_string()))?;

        Ok(TokenInfo::from(token))
    }

    /// Revoke (delete) an API token.
    ///
    /// # Arguments
    /// * `token_id` - The token ID to revoke
    /// * `user_id` - The user ID (for authorization)
    ///
    /// # Returns
    /// * `Ok(())` - Token successfully revoked
    /// * `Err(AppError::NotFound)` - If token doesn't exist or belongs to another user
    pub async fn revoke_token(&self, token_id: Uuid, user_id: Uuid) -> Result<()> {
        let auth_service = AuthService::new(self.db.clone(), self.config.clone());
        auth_service.revoke_api_token(token_id, user_id).await
    }

    /// Revoke all tokens for a user.
    ///
    /// # Arguments
    /// * `user_id` - The user to revoke all tokens for
    ///
    /// # Returns
    /// * `Ok(u64)` - Number of tokens revoked
    pub async fn revoke_all_tokens(&self, user_id: Uuid) -> Result<u64> {
        let result = sqlx::query!(
            "DELETE FROM api_tokens WHERE user_id = $1",
            user_id
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(result.rows_affected())
    }

    /// Validate a token and return its details.
    ///
    /// This is useful for checking if a token is valid without performing
    /// full authentication.
    ///
    /// # Arguments
    /// * `token` - The full token string
    ///
    /// # Returns
    /// * `TokenValidation` - Validation result with details
    pub async fn validate_token(&self, token: &str) -> TokenValidation {
        let auth_service = AuthService::new(self.db.clone(), self.config.clone());

        match auth_service.validate_api_token(token).await {
            Ok(user) => {
                // Get token details
                if token.len() >= 8 {
                    let prefix = &token[..8];
                    if let Ok(Some(token_info)) = sqlx::query!(
                        "SELECT scopes, expires_at FROM api_tokens WHERE token_prefix = $1",
                        prefix
                    )
                    .fetch_optional(&self.db)
                    .await
                    {
                        let expires_in = token_info
                            .expires_at
                            .map(|exp| (exp - Utc::now()).num_seconds())
                            .filter(|&s| s > 0);

                        return TokenValidation {
                            is_valid: true,
                            user_id: Some(user.id),
                            scopes: token_info.scopes,
                            expires_in,
                            error: None,
                        };
                    }
                }

                TokenValidation {
                    is_valid: true,
                    user_id: Some(user.id),
                    scopes: vec![],
                    expires_in: None,
                    error: None,
                }
            }
            Err(e) => TokenValidation {
                is_valid: false,
                user_id: None,
                scopes: vec![],
                expires_in: None,
                error: Some(e.to_string()),
            },
        }
    }

    /// Check if a token has a specific scope.
    ///
    /// # Arguments
    /// * `token` - The full token string
    /// * `required_scope` - The scope to check for
    ///
    /// # Returns
    /// * `Ok(bool)` - Whether the token has the scope
    pub async fn has_scope(&self, token: &str, required_scope: &str) -> Result<bool> {
        if token.len() < 8 {
            return Err(AppError::Authentication("Invalid token format".to_string()));
        }

        let prefix = &token[..8];
        let token_info = sqlx::query!(
            "SELECT scopes FROM api_tokens WHERE token_prefix = $1",
            prefix
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::Authentication("Invalid token".to_string()))?;

        // Check if token has the required scope or wildcard
        Ok(token_info.scopes.contains(&required_scope.to_string())
            || token_info.scopes.contains(&"*".to_string())
            || token_info.scopes.contains(&"admin".to_string()))
    }

    /// Clean up expired tokens.
    ///
    /// This should be run periodically to remove expired tokens from the database.
    ///
    /// # Returns
    /// * `Ok(u64)` - Number of expired tokens deleted
    pub async fn cleanup_expired_tokens(&self) -> Result<u64> {
        let result = sqlx::query!(
            "DELETE FROM api_tokens WHERE expires_at IS NOT NULL AND expires_at < NOW()"
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(result.rows_affected())
    }

    /// Get token usage statistics for a user.
    ///
    /// # Arguments
    /// * `user_id` - The user to get statistics for
    ///
    /// # Returns
    /// * `Ok(TokenStats)` - Token statistics
    pub async fn get_token_stats(&self, user_id: Uuid) -> Result<TokenStats> {
        let stats = sqlx::query!(
            r#"
            SELECT
                COUNT(*)::bigint as "total!: i64",
                (COUNT(*) FILTER (WHERE expires_at IS NOT NULL AND expires_at < NOW()))::bigint as "expired!: i64",
                (COUNT(*) FILTER (WHERE last_used_at > NOW() - INTERVAL '24 hours'))::bigint as "used_last_24h!: i64",
                (COUNT(*) FILTER (WHERE last_used_at IS NULL))::bigint as "never_used!: i64"
            FROM api_tokens
            WHERE user_id = $1
            "#,
            user_id
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(TokenStats {
            total: stats.total,
            expired: stats.expired,
            used_last_24h: stats.used_last_24h,
            never_used: stats.never_used,
        })
    }
}

/// Token usage statistics
#[derive(Debug, Clone, Serialize)]
pub struct TokenStats {
    /// Total number of tokens
    pub total: i64,
    /// Number of expired tokens
    pub expired: i64,
    /// Number of tokens used in the last 24 hours
    pub used_last_24h: i64,
    /// Number of tokens never used
    pub never_used: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_info_from_api_token() {
        let token = ApiToken {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            name: "test-token".to_string(),
            token_hash: "hash".to_string(),
            token_prefix: "abc12345".to_string(),
            scopes: vec!["read:artifacts".to_string()],
            expires_at: Some(Utc::now() + Duration::days(30)),
            last_used_at: None,
            created_at: Utc::now(),
        };

        let info = TokenInfo::from(token.clone());
        assert_eq!(info.id, token.id);
        assert_eq!(info.name, token.name);
        assert!(!info.is_expired);
    }

    #[test]
    fn test_expired_token_info() {
        let token = ApiToken {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            name: "expired-token".to_string(),
            token_hash: "hash".to_string(),
            token_prefix: "abc12345".to_string(),
            scopes: vec!["read:artifacts".to_string()],
            expires_at: Some(Utc::now() - Duration::days(1)),
            last_used_at: None,
            created_at: Utc::now() - Duration::days(30),
        };

        let info = TokenInfo::from(token);
        assert!(info.is_expired);
    }
}
