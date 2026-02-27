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
    pub is_revoked: bool,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_used_ip: Option<String>,
    pub last_used_user_agent: Option<String>,
}

impl From<ApiToken> for TokenInfo {
    fn from(token: ApiToken) -> Self {
        let is_expired = is_token_expired(token.expires_at);
        let is_revoked = is_token_revoked(token.revoked_at);

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
            is_revoked,
            revoked_at: token.revoked_at,
            last_used_ip: token.last_used_ip,
            last_used_user_agent: token.last_used_user_agent,
        }
    }
}

// ---------------------------------------------------------------------------
// Pure helper functions (no DB, testable in isolation)
// ---------------------------------------------------------------------------

/// The canonical list of allowed API token scopes.
pub(crate) const ALLOWED_SCOPES: &[&str] = &[
    "read:artifacts",
    "write:artifacts",
    "delete:artifacts",
    "read:repositories",
    "write:repositories",
    "delete:repositories",
    "read:users",
    "write:users",
    "admin",
    "*",
];

/// Validate token scopes against the allowed scope list.
/// Returns Ok(()) if all scopes are valid, Err(message) otherwise.
pub(crate) fn validate_scopes_pure(scopes: &[String]) -> std::result::Result<(), String> {
    for scope in scopes {
        if !ALLOWED_SCOPES.contains(&scope.as_str()) {
            return Err(format!(
                "Invalid scope: '{}'. Allowed scopes: {:?}",
                scope, ALLOWED_SCOPES
            ));
        }
    }
    Ok(())
}

/// Determine if a token is expired given an optional expiration timestamp.
pub(crate) fn is_token_expired(expires_at: Option<DateTime<Utc>>) -> bool {
    expires_at.map(|exp| exp < Utc::now()).unwrap_or(false)
}

/// Determine if a token has been revoked.
pub(crate) fn is_token_revoked(revoked_at: Option<DateTime<Utc>>) -> bool {
    revoked_at.is_some()
}

/// Check if a set of scopes grants access for a required scope.
/// Scopes match if the exact scope is present, or `*` or `admin` is present.
pub(crate) fn scopes_grant_access(scopes: &[String], required_scope: &str) -> bool {
    scopes.contains(&required_scope.to_string())
        || scopes.contains(&"*".to_string())
        || scopes.contains(&"admin".to_string())
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
            if !(1..=365).contains(&days) {
                return Err(AppError::Validation(
                    "Token expiration must be between 1 and 365 days".to_string(),
                ));
            }
        }

        // Delegate to AuthService for actual token generation
        let auth_service = AuthService::new(self.db.clone(), self.config.clone());
        let (token, token_id) = auth_service
            .generate_api_token(
                user_id,
                &request.name,
                request.scopes.clone(),
                request.expires_in_days,
            )
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
            description: None,
            repository_ids: vec![],
        })
    }

    /// Validate token scopes against allowed scopes.
    fn validate_scopes(&self, scopes: &[String]) -> Result<()> {
        validate_scopes_pure(scopes).map_err(AppError::Validation)
    }

    /// List all tokens for a user.
    ///
    /// # Arguments
    /// * `user_id` - The user to list tokens for
    ///
    /// # Returns
    /// * `Ok(Vec<TokenInfo>)` - List of token information (without actual token values)
    pub async fn list_tokens(&self, user_id: Uuid) -> Result<Vec<TokenInfo>> {
        let tokens = sqlx::query_as::<_, ApiToken>(
            r#"
            SELECT id, user_id, name, token_hash, token_prefix, scopes,
                   expires_at, last_used_at, created_at,
                   created_by_user_id, description, repo_selector,
                   revoked_at, last_used_ip, last_used_user_agent
            FROM api_tokens
            WHERE user_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
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
        let token = sqlx::query_as::<_, ApiToken>(
            r#"
            SELECT id, user_id, name, token_hash, token_prefix, scopes,
                   expires_at, last_used_at, created_at,
                   created_by_user_id, description, repo_selector,
                   revoked_at, last_used_ip, last_used_user_agent
            FROM api_tokens
            WHERE id = $1 AND user_id = $2
            "#,
        )
        .bind(token_id)
        .bind(user_id)
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
        let result = sqlx::query(
            "UPDATE api_tokens SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL",
        )
        .bind(user_id)
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
            Ok(validation) => {
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
                            user_id: Some(validation.user.id),
                            scopes: token_info.scopes,
                            expires_in,
                            error: None,
                        };
                    }
                }

                TokenValidation {
                    is_valid: true,
                    user_id: Some(validation.user.id),
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
        Ok(scopes_grant_access(&token_info.scopes, required_scope))
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

    fn validate_expiration_days(days: Option<i64>) -> std::result::Result<(), String> {
        if let Some(d) = days {
            if !(1..=365).contains(&d) {
                return Err("Token expiration must be between 1 and 365 days".to_string());
            }
        }
        Ok(())
    }

    fn compute_expiry(days: Option<i64>) -> Option<DateTime<Utc>> {
        days.map(|d| Utc::now() + Duration::days(d))
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_api_token(
        expires_at: Option<DateTime<Utc>>,
        last_used_at: Option<DateTime<Utc>>,
        scopes: Vec<String>,
    ) -> ApiToken {
        ApiToken {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            name: "test-token".to_string(),
            token_hash: "hash".to_string(),
            token_prefix: "abc12345".to_string(),
            scopes,
            expires_at,
            last_used_at,
            created_at: Utc::now(),
            created_by_user_id: None,
            description: None,
            repo_selector: None,
            revoked_at: None,
            last_used_ip: None,
            last_used_user_agent: None,
        }
    }

    // -----------------------------------------------------------------------
    // TokenInfo::from (existing tests + new ones)
    // -----------------------------------------------------------------------

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
            created_by_user_id: None,
            description: None,
            repo_selector: None,
            revoked_at: None,
            last_used_ip: None,
            last_used_user_agent: None,
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
            created_by_user_id: None,
            description: None,
            repo_selector: None,
            revoked_at: None,
            last_used_ip: None,
            last_used_user_agent: None,
        };

        let info = TokenInfo::from(token);
        assert!(info.is_expired);
    }

    #[test]
    fn test_token_info_no_expiration_is_not_expired() {
        let token = make_api_token(None, None, vec!["*".to_string()]);
        let info = TokenInfo::from(token);
        assert!(!info.is_expired);
        assert!(info.expires_at.is_none());
    }

    #[test]
    fn test_token_info_preserves_all_fields() {
        let user_id = Uuid::new_v4();
        let token_id = Uuid::new_v4();
        let now = Utc::now();
        let last_used = now - Duration::hours(2);

        let token = ApiToken {
            id: token_id,
            user_id,
            name: "my-ci-token".to_string(),
            token_hash: "sha256hash".to_string(),
            token_prefix: "xy789012".to_string(),
            scopes: vec!["read:artifacts".to_string(), "write:artifacts".to_string()],
            expires_at: Some(now + Duration::days(90)),
            last_used_at: Some(last_used),
            created_at: now - Duration::days(10),
            created_by_user_id: None,
            description: None,
            repo_selector: None,
            revoked_at: None,
            last_used_ip: Some("192.168.1.1".to_string()),
            last_used_user_agent: Some("curl/7.88".to_string()),
        };

        let info = TokenInfo::from(token);
        assert_eq!(info.id, token_id);
        assert_eq!(info.user_id, user_id);
        assert_eq!(info.name, "my-ci-token");
        assert_eq!(info.token_prefix, "xy789012");
        assert_eq!(info.scopes.len(), 2);
        assert!(info.expires_at.is_some());
        assert!(info.last_used_at.is_some());
        assert!(!info.is_expired);
        assert!(!info.is_revoked);
        assert_eq!(info.last_used_ip.as_deref(), Some("192.168.1.1"));
        assert_eq!(info.last_used_user_agent.as_deref(), Some("curl/7.88"));
    }

    #[test]
    fn test_token_info_just_expired() {
        // Token expired 1 second ago
        let token = make_api_token(
            Some(Utc::now() - Duration::seconds(1)),
            None,
            vec!["read:artifacts".to_string()],
        );
        let info = TokenInfo::from(token);
        assert!(info.is_expired);
    }

    #[test]
    fn test_token_info_empty_scopes() {
        let token = make_api_token(None, None, vec![]);
        let info = TokenInfo::from(token);
        assert!(info.scopes.is_empty());
    }

    // -----------------------------------------------------------------------
    // validate_scopes_pure (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_scopes_all_valid() {
        let scopes = vec![
            "read:artifacts".to_string(),
            "write:artifacts".to_string(),
            "admin".to_string(),
        ];
        assert!(validate_scopes_pure(&scopes).is_ok());
    }

    #[test]
    fn test_validate_scopes_wildcard() {
        let scopes = vec!["*".to_string()];
        assert!(validate_scopes_pure(&scopes).is_ok());
    }

    #[test]
    fn test_validate_scopes_invalid_scope() {
        let scopes = vec!["read:artifacts".to_string(), "hack:system".to_string()];
        let result = validate_scopes_pure(&scopes);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("hack:system"));
    }

    #[test]
    fn test_validate_scopes_empty() {
        let scopes: Vec<String> = vec![];
        assert!(validate_scopes_pure(&scopes).is_ok());
    }

    #[test]
    fn test_validate_scopes_all_allowed_scopes() {
        let all: Vec<String> = ALLOWED_SCOPES.iter().map(|s| s.to_string()).collect();
        assert!(validate_scopes_pure(&all).is_ok());
    }

    #[test]
    fn test_validate_scopes_case_sensitive() {
        let scopes = vec!["Admin".to_string()];
        assert!(validate_scopes_pure(&scopes).is_err());
    }

    #[test]
    fn test_validate_scopes_partial_match_fails() {
        let scopes = vec!["read:artifact".to_string()]; // missing 's'
        assert!(validate_scopes_pure(&scopes).is_err());
    }

    // -----------------------------------------------------------------------
    // validate_expiration_days (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_expiration_days_valid() {
        assert!(validate_expiration_days(Some(1)).is_ok());
        assert!(validate_expiration_days(Some(30)).is_ok());
        assert!(validate_expiration_days(Some(365)).is_ok());
    }

    #[test]
    fn test_validate_expiration_days_invalid() {
        assert!(validate_expiration_days(Some(0)).is_err());
        assert!(validate_expiration_days(Some(-1)).is_err());
        assert!(validate_expiration_days(Some(366)).is_err());
        assert!(validate_expiration_days(Some(1000)).is_err());
    }

    #[test]
    fn test_validate_expiration_days_none_is_valid() {
        assert!(validate_expiration_days(None).is_ok());
    }

    // -----------------------------------------------------------------------
    // is_token_expired (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_token_expired_future() {
        assert!(!is_token_expired(Some(Utc::now() + Duration::days(30))));
    }

    #[test]
    fn test_is_token_expired_past() {
        assert!(is_token_expired(Some(Utc::now() - Duration::days(1))));
    }

    #[test]
    fn test_is_token_expired_none() {
        assert!(!is_token_expired(None));
    }

    #[test]
    fn test_is_token_expired_just_expired() {
        assert!(is_token_expired(Some(Utc::now() - Duration::seconds(1))));
    }

    // -----------------------------------------------------------------------
    // is_token_revoked (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_token_revoked_none() {
        assert!(!is_token_revoked(None));
    }

    #[test]
    fn test_is_token_revoked_some() {
        assert!(is_token_revoked(Some(Utc::now())));
    }

    #[test]
    fn test_is_token_revoked_past_timestamp() {
        assert!(is_token_revoked(Some(Utc::now() - Duration::days(30))));
    }

    // -----------------------------------------------------------------------
    // TokenInfo revocation fields
    // -----------------------------------------------------------------------

    #[test]
    fn test_token_info_revoked_token() {
        let revoked_at = Some(Utc::now() - Duration::hours(1));
        let mut token = make_api_token(None, None, vec!["read:artifacts".to_string()]);
        token.revoked_at = revoked_at;

        let info = TokenInfo::from(token);
        assert!(info.is_revoked);
        assert!(info.revoked_at.is_some());
    }

    #[test]
    fn test_token_info_active_token_not_revoked() {
        let token = make_api_token(None, None, vec!["read:artifacts".to_string()]);
        let info = TokenInfo::from(token);
        assert!(!info.is_revoked);
        assert!(info.revoked_at.is_none());
    }

    // -----------------------------------------------------------------------
    // scopes_grant_access (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_scopes_grant_access_exact_match() {
        let scopes = vec!["read:artifacts".to_string()];
        assert!(scopes_grant_access(&scopes, "read:artifacts"));
    }

    #[test]
    fn test_scopes_grant_access_wildcard() {
        let scopes = vec!["*".to_string()];
        assert!(scopes_grant_access(&scopes, "read:artifacts"));
        assert!(scopes_grant_access(&scopes, "write:repositories"));
    }

    #[test]
    fn test_scopes_grant_access_admin() {
        let scopes = vec!["admin".to_string()];
        assert!(scopes_grant_access(&scopes, "delete:artifacts"));
    }

    #[test]
    fn test_scopes_grant_access_no_match() {
        let scopes = vec!["read:artifacts".to_string()];
        assert!(!scopes_grant_access(&scopes, "write:artifacts"));
    }

    #[test]
    fn test_scopes_grant_access_empty_scopes() {
        let scopes: Vec<String> = vec![];
        assert!(!scopes_grant_access(&scopes, "read:artifacts"));
    }

    // -----------------------------------------------------------------------
    // compute_expiry (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_expiry_some() {
        let expiry = compute_expiry(Some(30));
        assert!(expiry.is_some());
        let diff = expiry.unwrap() - Utc::now();
        assert!(diff.num_days() >= 29 && diff.num_days() <= 30);
    }

    #[test]
    fn test_compute_expiry_none() {
        assert!(compute_expiry(None).is_none());
    }

    // -----------------------------------------------------------------------
    // TokenStats structure
    // -----------------------------------------------------------------------

    #[test]
    fn test_token_stats_serialization() {
        let stats = TokenStats {
            total: 10,
            expired: 2,
            used_last_24h: 5,
            never_used: 3,
        };
        let json = serde_json::to_value(&stats).unwrap();
        assert_eq!(json["total"], 10);
        assert_eq!(json["expired"], 2);
        assert_eq!(json["used_last_24h"], 5);
        assert_eq!(json["never_used"], 3);
    }

    // -----------------------------------------------------------------------
    // TokenValidation structure
    // -----------------------------------------------------------------------

    #[test]
    fn test_token_validation_serialization() {
        let valid = TokenValidation {
            is_valid: true,
            user_id: Some(Uuid::new_v4()),
            scopes: vec!["read:artifacts".to_string()],
            expires_in: Some(3600),
            error: None,
        };
        let json = serde_json::to_value(&valid).unwrap();
        assert_eq!(json["is_valid"], true);
        assert!(json["user_id"].is_string());
        assert!(json["error"].is_null());

        let invalid = TokenValidation {
            is_valid: false,
            user_id: None,
            scopes: vec![],
            expires_in: None,
            error: Some("Token expired".to_string()),
        };
        let json = serde_json::to_value(&invalid).unwrap();
        assert_eq!(json["is_valid"], false);
        assert!(json["user_id"].is_null());
        assert_eq!(json["error"], "Token expired");
    }
}
