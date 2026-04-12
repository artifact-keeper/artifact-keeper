//! Service account management.
//!
//! Service accounts are machine identities managed by admins. They
//! authenticate only via API tokens (no password, no TOTP, no SSO).

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::user::{AuthProvider, User};

/// Summary of a service account for list responses.
#[derive(Debug, Clone, Serialize)]
pub struct ServiceAccountSummary {
    pub id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub is_active: bool,
    pub token_count: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct ServiceAccountService {
    db: PgPool,
}

pub(crate) fn build_service_account_username(name: &str) -> String {
    format!("svc-{}", name.to_lowercase().replace(' ', "-"))
}

pub(crate) fn validate_service_account_username(username: &str) -> Result<()> {
    if username.len() > 64 || !username.chars().all(|c| c.is_alphanumeric() || c == '-') {
        return Err(AppError::Validation(
            "Service account name must be alphanumeric with hyphens, 2-64 characters".to_string(),
        ));
    }
    Ok(())
}

pub(crate) fn build_service_account_email(username: &str) -> String {
    format!("{}@service-accounts.local", username)
}

impl ServiceAccountService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Create a new service account.
    pub async fn create(&self, name: &str, description: Option<&str>) -> Result<User> {
        let username = build_service_account_username(name);
        validate_service_account_username(&username)?;

        let email = build_service_account_email(&username);
        let id = Uuid::new_v4();

        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (
                id, username, email, display_name, auth_provider,
                is_admin, is_active, is_service_account, must_change_password
            )
            VALUES ($1, $2, $3, $4, 'local', false, true, true, false)
            RETURNING
                id, username, email, password_hash, display_name,
                auth_provider as "auth_provider: AuthProvider",
                external_id, is_admin, is_active, is_service_account, must_change_password,
                totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
                failed_login_attempts, locked_until, last_failed_login_at,
                password_changed_at, last_login_at, created_at, updated_at
            "#,
            id,
            username,
            email,
            description,
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| {
            if e.to_string().contains("duplicate key") {
                AppError::Validation(format!("Service account '{}' already exists", username))
            } else {
                AppError::Database(e.to_string())
            }
        })?;

        Ok(user)
    }

    /// List all service accounts.
    pub async fn list(&self, include_inactive: bool) -> Result<Vec<ServiceAccountSummary>> {
        let rows = sqlx::query_as!(
            ServiceAccountSummary,
            r#"
            SELECT
                u.id,
                u.username,
                u.display_name,
                u.is_active,
                COALESCE(t.cnt, 0) as "token_count!: i64",
                u.created_at,
                u.updated_at
            FROM users u
            LEFT JOIN (
                SELECT user_id, COUNT(*) as cnt
                FROM api_tokens
                GROUP BY user_id
            ) t ON t.user_id = u.id
            WHERE u.is_service_account = true
              AND ($1 OR u.is_active = true)
            ORDER BY u.created_at DESC
            "#,
            include_inactive
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(rows)
    }

    /// Get a single service account by ID.
    pub async fn get(&self, id: Uuid) -> Result<User> {
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
            WHERE id = $1 AND is_service_account = true
            "#,
            id
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Service account not found".to_string()))?;

        Ok(user)
    }

    /// Update a service account's display name or active status.
    pub async fn update(
        &self,
        id: Uuid,
        display_name: Option<&str>,
        is_active: Option<bool>,
    ) -> Result<User> {
        // Verify it's a service account
        self.get(id).await?;

        let user = sqlx::query_as!(
            User,
            r#"
            UPDATE users
            SET display_name = COALESCE($2, display_name),
                is_active = COALESCE($3, is_active),
                updated_at = NOW()
            WHERE id = $1 AND is_service_account = true
            RETURNING
                id, username, email, password_hash, display_name,
                auth_provider as "auth_provider: AuthProvider",
                external_id, is_admin, is_active, is_service_account, must_change_password,
                totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
                failed_login_attempts, locked_until, last_failed_login_at,
                password_changed_at, last_login_at, created_at, updated_at
            "#,
            id,
            display_name,
            is_active
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(user)
    }

    /// Delete a service account and all its tokens (via CASCADE).
    pub async fn delete(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query!(
            "DELETE FROM users WHERE id = $1 AND is_service_account = true",
            id
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Service account not found".to_string()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // build_service_account_username
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_username_simple() {
        assert_eq!(build_service_account_username("deploy"), "svc-deploy");
    }

    #[test]
    fn test_build_username_lowercases() {
        assert_eq!(build_service_account_username("CI-Runner"), "svc-ci-runner");
    }

    #[test]
    fn test_build_username_spaces_to_hyphens() {
        assert_eq!(
            build_service_account_username("my build agent"),
            "svc-my-build-agent"
        );
    }

    #[test]
    fn test_build_username_already_lowercase() {
        assert_eq!(build_service_account_username("scanner"), "svc-scanner");
    }

    #[test]
    fn test_build_username_mixed_case_and_spaces() {
        assert_eq!(
            build_service_account_username("GitHub Actions Runner"),
            "svc-github-actions-runner"
        );
    }

    #[test]
    fn test_build_username_empty_name() {
        assert_eq!(build_service_account_username(""), "svc-");
    }

    // -----------------------------------------------------------------------
    // validate_service_account_username
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_username_valid() {
        assert!(validate_service_account_username("svc-deploy").is_ok());
    }

    #[test]
    fn test_validate_username_with_hyphens() {
        assert!(validate_service_account_username("svc-ci-runner").is_ok());
    }

    #[test]
    fn test_validate_username_alphanumeric() {
        assert!(validate_service_account_username("svc-agent42").is_ok());
    }

    #[test]
    fn test_validate_username_too_long() {
        let long = format!("svc-{}", "a".repeat(61));
        assert!(validate_service_account_username(&long).is_err());
    }

    #[test]
    fn test_validate_username_exactly_64() {
        let name = format!("svc-{}", "a".repeat(60));
        assert_eq!(name.len(), 64);
        assert!(validate_service_account_username(&name).is_ok());
    }

    #[test]
    fn test_validate_username_with_underscore_rejected() {
        assert!(validate_service_account_username("svc-my_agent").is_err());
    }

    #[test]
    fn test_validate_username_with_dot_rejected() {
        assert!(validate_service_account_username("svc-my.agent").is_err());
    }

    #[test]
    fn test_validate_username_with_space_rejected() {
        assert!(validate_service_account_username("svc-my agent").is_err());
    }

    // -----------------------------------------------------------------------
    // build_service_account_email
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_email() {
        assert_eq!(
            build_service_account_email("svc-deploy"),
            "svc-deploy@service-accounts.local"
        );
    }

    #[test]
    fn test_build_email_complex_username() {
        assert_eq!(
            build_service_account_email("svc-ci-runner-42"),
            "svc-ci-runner-42@service-accounts.local"
        );
    }

    // -----------------------------------------------------------------------
    // build + validate integration
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_then_validate_simple_name() {
        let username = build_service_account_username("deploy");
        assert!(validate_service_account_username(&username).is_ok());
    }

    #[test]
    fn test_build_then_validate_with_spaces() {
        let username = build_service_account_username("my build agent");
        assert!(validate_service_account_username(&username).is_ok());
    }

    #[test]
    fn test_build_then_email_round_trip() {
        let username = build_service_account_username("scanner");
        let email = build_service_account_email(&username);
        assert_eq!(email, "svc-scanner@service-accounts.local");
    }

    // -----------------------------------------------------------------------
    // ServiceAccountSummary serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_summary_serialization() {
        let now = Utc::now();
        let summary = ServiceAccountSummary {
            id: Uuid::nil(),
            username: "svc-deploy".to_string(),
            display_name: Some("Deploy Agent".to_string()),
            is_active: true,
            token_count: 3,
            created_at: now,
            updated_at: now,
        };
        let json: serde_json::Value = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["username"], "svc-deploy");
        assert_eq!(json["display_name"], "Deploy Agent");
        assert_eq!(json["is_active"], true);
        assert_eq!(json["token_count"], 3);
        assert!(json.get("id").is_some());
        assert!(json.get("created_at").is_some());
        assert!(json.get("updated_at").is_some());
    }

    #[test]
    fn test_summary_serialization_null_display_name() {
        let now = Utc::now();
        let summary = ServiceAccountSummary {
            id: Uuid::new_v4(),
            username: "svc-scanner".to_string(),
            display_name: None,
            is_active: false,
            token_count: 0,
            created_at: now,
            updated_at: now,
        };
        let json: serde_json::Value = serde_json::to_value(&summary).unwrap();
        assert!(json["display_name"].is_null());
        assert_eq!(json["is_active"], false);
        assert_eq!(json["token_count"], 0);
    }

    #[test]
    fn test_summary_has_exactly_seven_fields() {
        let now = Utc::now();
        let summary = ServiceAccountSummary {
            id: Uuid::nil(),
            username: "svc-test".to_string(),
            display_name: None,
            is_active: true,
            token_count: 0,
            created_at: now,
            updated_at: now,
        };
        let json: serde_json::Value = serde_json::to_value(&summary).unwrap();
        let obj = json.as_object().unwrap();
        assert_eq!(obj.len(), 7);
    }

    #[test]
    fn test_summary_clone() {
        let now = Utc::now();
        let summary = ServiceAccountSummary {
            id: Uuid::new_v4(),
            username: "svc-clone".to_string(),
            display_name: Some("Cloned".to_string()),
            is_active: true,
            token_count: 5,
            created_at: now,
            updated_at: now,
        };
        let cloned = summary.clone();
        assert_eq!(cloned.id, summary.id);
        assert_eq!(cloned.username, summary.username);
        assert_eq!(cloned.display_name, summary.display_name);
        assert_eq!(cloned.token_count, summary.token_count);
    }

    #[test]
    fn test_summary_debug() {
        let now = Utc::now();
        let summary = ServiceAccountSummary {
            id: Uuid::nil(),
            username: "svc-debug".to_string(),
            display_name: None,
            is_active: true,
            token_count: 0,
            created_at: now,
            updated_at: now,
        };
        let debug = format!("{:?}", summary);
        assert!(debug.contains("ServiceAccountSummary"));
        assert!(debug.contains("svc-debug"));
    }

    #[test]
    fn test_summary_timestamps_are_rfc3339() {
        let now = Utc::now();
        let summary = ServiceAccountSummary {
            id: Uuid::nil(),
            username: "svc-ts".to_string(),
            display_name: None,
            is_active: true,
            token_count: 0,
            created_at: now,
            updated_at: now,
        };
        let json: serde_json::Value = serde_json::to_value(&summary).unwrap();
        let created_str = json["created_at"].as_str().unwrap();
        assert!(DateTime::parse_from_rfc3339(created_str).is_ok());
        let updated_str = json["updated_at"].as_str().unwrap();
        assert!(DateTime::parse_from_rfc3339(updated_str).is_ok());
    }

    // -----------------------------------------------------------------------
    // Edge cases for name validation through build + validate
    // -----------------------------------------------------------------------

    #[test]
    fn test_name_with_special_chars_fails_validation() {
        let username = build_service_account_username("my@agent!");
        assert!(validate_service_account_username(&username).is_err());
    }

    #[test]
    fn test_name_with_numbers_valid() {
        let username = build_service_account_username("agent42");
        assert!(validate_service_account_username(&username).is_ok());
        assert_eq!(username, "svc-agent42");
    }

    #[test]
    fn test_name_preserves_hyphens() {
        let username = build_service_account_username("ci-cd-pipeline");
        assert_eq!(username, "svc-ci-cd-pipeline");
        assert!(validate_service_account_username(&username).is_ok());
    }
}
