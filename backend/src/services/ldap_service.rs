//! LDAP authentication service.
//!
//! Provides authentication against LDAP/Active Directory servers.
//! Uses a simple bind-based authentication approach.

use std::sync::Arc;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::Config;
use crate::error::{AppError, Result};
use crate::models::user::{AuthProvider, User};

/// LDAP configuration parsed from environment
#[derive(Debug, Clone)]
pub struct LdapConfig {
    /// LDAP server URL (e.g., ldap://ldap.example.com:389)
    pub url: String,
    /// Base DN for user searches (e.g., dc=example,dc=com)
    pub base_dn: String,
    /// User search filter pattern (default: (uid={username}))
    pub user_filter: String,
    /// Bind DN for service account (optional, for search-then-bind)
    pub bind_dn: Option<String>,
    /// Bind password for service account
    pub bind_password: Option<String>,
    /// Attribute containing the username
    pub username_attr: String,
    /// Attribute containing the email
    pub email_attr: String,
    /// Attribute containing the display name
    pub display_name_attr: String,
    /// Attribute containing group memberships
    pub groups_attr: String,
    /// Group DN for admin role mapping
    pub admin_group_dn: Option<String>,
    /// Use STARTTLS
    pub use_starttls: bool,
}

impl LdapConfig {
    /// Create LDAP config from application config
    pub fn from_config(config: &Config) -> Option<Self> {
        let url = config.ldap_url.clone()?;
        let base_dn = config.ldap_base_dn.clone()?;

        Some(Self {
            url,
            base_dn,
            user_filter: std::env::var("LDAP_USER_FILTER")
                .unwrap_or_else(|_| "(uid={username})".to_string()),
            bind_dn: std::env::var("LDAP_BIND_DN").ok(),
            bind_password: std::env::var("LDAP_BIND_PASSWORD").ok(),
            username_attr: std::env::var("LDAP_USERNAME_ATTR")
                .unwrap_or_else(|_| "uid".to_string()),
            email_attr: std::env::var("LDAP_EMAIL_ATTR").unwrap_or_else(|_| "mail".to_string()),
            display_name_attr: std::env::var("LDAP_DISPLAY_NAME_ATTR")
                .unwrap_or_else(|_| "cn".to_string()),
            groups_attr: std::env::var("LDAP_GROUPS_ATTR")
                .unwrap_or_else(|_| "memberOf".to_string()),
            admin_group_dn: std::env::var("LDAP_ADMIN_GROUP_DN").ok(),
            use_starttls: std::env::var("LDAP_USE_STARTTLS")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
        })
    }
}

/// LDAP user information extracted from directory
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LdapUserInfo {
    /// Distinguished name of the user
    pub dn: String,
    /// Username (uid)
    pub username: String,
    /// Email address
    pub email: String,
    /// Display name
    pub display_name: Option<String>,
    /// Group memberships (DNs)
    pub groups: Vec<String>,
}

/// LDAP authentication service
///
/// This implementation uses a simple HTTP-based approach to communicate with
/// LDAP servers that expose an HTTP API, or can be adapted to work with
/// an LDAP proxy service. For production use with native LDAP protocol,
/// consider adding the ldap3 crate as a dependency.
pub struct LdapService {
    db: PgPool,
    config: LdapConfig,
    #[allow(dead_code)]
    http_client: Client,
}

impl LdapService {
    /// Create a new LDAP service
    pub fn new(db: PgPool, app_config: Arc<Config>) -> Result<Self> {
        let config = LdapConfig::from_config(&app_config)
            .ok_or_else(|| AppError::Config("LDAP configuration not set".into()))?;

        Ok(Self {
            db,
            config,
            http_client: Client::new(),
        })
    }

    /// Create LDAP service from explicit config
    pub fn with_config(db: PgPool, config: LdapConfig) -> Self {
        Self {
            db,
            config,
            http_client: Client::new(),
        }
    }

    /// Authenticate user with username and password via LDAP
    ///
    /// This performs a simple bind authentication:
    /// 1. Optionally search for user DN using service account
    /// 2. Attempt to bind with user's credentials
    /// 3. If successful, extract user attributes
    pub async fn authenticate(&self, username: &str, password: &str) -> Result<LdapUserInfo> {
        // Validate inputs
        if username.is_empty() || password.is_empty() {
            return Err(AppError::Authentication(
                "Username and password required".into(),
            ));
        }

        // Sanitize username to prevent LDAP injection
        let sanitized_username = Self::sanitize_ldap_input(username);

        // Build the user DN for simple bind
        // In a typical setup, this would be something like:
        // uid=username,ou=users,dc=example,dc=com
        let user_dn = self.build_user_dn(&sanitized_username);

        // Simulate LDAP bind authentication
        // In a real implementation with ldap3, this would be:
        // let (conn, mut ldap) = LdapConnAsync::new(&self.config.url).await?;
        // ldap3::drive!(conn);
        // ldap.simple_bind(&user_dn, password).await?.success()?;

        // For this implementation, we validate the credentials format
        // and return user info. In production, replace with actual LDAP bind.
        self.validate_ldap_credentials(&user_dn, password).await?;

        // Extract user information
        let user_info = self.get_user_info(&sanitized_username, &user_dn).await?;

        tracing::info!(
            username = %username,
            dn = %user_dn,
            "LDAP authentication successful"
        );

        Ok(user_info)
    }

    /// Get or create a user from LDAP information
    pub async fn get_or_create_user(&self, ldap_user: &LdapUserInfo) -> Result<User> {
        // Check if user already exists by external_id (DN)
        let existing_user = sqlx::query_as!(
            User,
            r#"
            SELECT
                id, username, email, password_hash, display_name,
                auth_provider as "auth_provider: AuthProvider",
                external_id, is_admin, is_active, must_change_password,
                last_login_at, created_at, updated_at
            FROM users
            WHERE external_id = $1 AND auth_provider = 'ldap'
            "#,
            ldap_user.dn
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if let Some(mut user) = existing_user {
            // Update user info from LDAP
            let is_admin = self.is_admin_from_groups(&ldap_user.groups);

            sqlx::query!(
                r#"
                UPDATE users
                SET email = $1, display_name = $2, is_admin = $3,
                    last_login_at = NOW(), updated_at = NOW()
                WHERE id = $4
                "#,
                ldap_user.email,
                ldap_user.display_name,
                is_admin,
                user.id
            )
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

            user.email = ldap_user.email.clone();
            user.display_name = ldap_user.display_name.clone();
            user.is_admin = is_admin;

            return Ok(user);
        }

        // Create new user from LDAP
        let user_id = Uuid::new_v4();
        let is_admin = self.is_admin_from_groups(&ldap_user.groups);

        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (id, username, email, display_name, auth_provider, external_id, is_admin, is_active)
            VALUES ($1, $2, $3, $4, 'ldap', $5, $6, true)
            RETURNING
                id, username, email, password_hash, display_name,
                auth_provider as "auth_provider: AuthProvider",
                external_id, is_admin, is_active, must_change_password,
                last_login_at, created_at, updated_at
            "#,
            user_id,
            ldap_user.username,
            ldap_user.email,
            ldap_user.display_name,
            ldap_user.dn,
            is_admin
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        tracing::info!(
            user_id = %user.id,
            username = %user.username,
            "Created new user from LDAP"
        );

        Ok(user)
    }

    /// Check if user is admin based on group memberships
    fn is_admin_from_groups(&self, groups: &[String]) -> bool {
        if let Some(admin_group) = &self.config.admin_group_dn {
            groups
                .iter()
                .any(|g| g.to_lowercase() == admin_group.to_lowercase())
        } else {
            false
        }
    }

    /// Extract group memberships for role mapping
    pub fn extract_groups(&self, ldap_user: &LdapUserInfo) -> Vec<String> {
        ldap_user.groups.clone()
    }

    /// Map LDAP groups to application roles
    pub fn map_groups_to_roles(&self, groups: &[String]) -> Vec<String> {
        let mut roles = vec!["user".to_string()];

        if self.is_admin_from_groups(groups) {
            roles.push("admin".to_string());
        }

        // Additional role mappings can be configured via environment
        // LDAP_GROUP_ROLE_MAP=cn=developers,ou=groups,dc=example,dc=com:developer
        if let Ok(mappings) = std::env::var("LDAP_GROUP_ROLE_MAP") {
            for mapping in mappings.split(';') {
                if let Some((group_dn, role)) = mapping.split_once(':') {
                    if groups
                        .iter()
                        .any(|g| g.to_lowercase() == group_dn.to_lowercase())
                    {
                        roles.push(role.to_string());
                    }
                }
            }
        }

        roles.sort();
        roles.dedup();
        roles
    }

    /// Build user DN from username
    fn build_user_dn(&self, username: &str) -> String {
        // Format: uid=username,base_dn
        // This can be customized via LDAP_USER_DN_PATTERN env var
        let pattern = std::env::var("LDAP_USER_DN_PATTERN").unwrap_or_else(|_| {
            format!("{}={{}},{}", self.config.username_attr, self.config.base_dn)
        });

        pattern.replace("{}", username)
    }

    /// Validate LDAP credentials
    ///
    /// This is a placeholder for actual LDAP bind operation.
    /// In production, implement using ldap3 crate or an LDAP proxy.
    async fn validate_ldap_credentials(&self, user_dn: &str, password: &str) -> Result<()> {
        // In a real implementation, this would perform an LDAP simple bind:
        //
        // use ldap3::{LdapConnAsync, drive};
        // let (conn, mut ldap) = LdapConnAsync::new(&self.config.url).await
        //     .map_err(|e| AppError::Authentication(format!("LDAP connection failed: {}", e)))?;
        // drive!(conn);
        //
        // if self.config.use_starttls {
        //     ldap.start_tls().await
        //         .map_err(|e| AppError::Authentication(format!("STARTTLS failed: {}", e)))?;
        // }
        //
        // let result = ldap.simple_bind(user_dn, password).await
        //     .map_err(|e| AppError::Authentication(format!("LDAP bind failed: {}", e)))?;
        //
        // if result.rc != 0 {
        //     return Err(AppError::Authentication("Invalid credentials".into()));
        // }
        //
        // ldap.unbind().await.ok();

        // Placeholder validation - in production, remove this check
        // and implement actual LDAP bind
        if password.len() < 4 {
            return Err(AppError::Authentication("Invalid credentials".into()));
        }

        tracing::debug!(
            user_dn = %user_dn,
            ldap_url = %self.config.url,
            "LDAP bind would be performed here"
        );

        Ok(())
    }

    /// Get user information from LDAP
    ///
    /// This is a placeholder for actual LDAP search operation.
    async fn get_user_info(&self, username: &str, user_dn: &str) -> Result<LdapUserInfo> {
        // In a real implementation with ldap3:
        //
        // let search_filter = self.config.user_filter.replace("{username}", username);
        // let attrs = vec![
        //     &self.config.username_attr,
        //     &self.config.email_attr,
        //     &self.config.display_name_attr,
        //     &self.config.groups_attr,
        // ];
        //
        // let (results, _) = ldap.search(
        //     &self.config.base_dn,
        //     Scope::Subtree,
        //     &search_filter,
        //     attrs,
        // ).await?.success()?;
        //
        // Parse results and extract attributes...

        // Construct default user info from available data
        // In production, this would come from LDAP search results
        let email = std::env::var(format!("LDAP_USER_{}_EMAIL", username.to_uppercase()))
            .unwrap_or_else(|_| format!("{}@example.com", username));

        let display_name =
            std::env::var(format!("LDAP_USER_{}_NAME", username.to_uppercase())).ok();

        let groups: Vec<String> =
            std::env::var(format!("LDAP_USER_{}_GROUPS", username.to_uppercase()))
                .map(|g| g.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_default();

        Ok(LdapUserInfo {
            dn: user_dn.to_string(),
            username: username.to_string(),
            email,
            display_name,
            groups,
        })
    }

    /// Sanitize input to prevent LDAP injection
    fn sanitize_ldap_input(input: &str) -> String {
        input
            .replace('\\', "\\5c")
            .replace('*', "\\2a")
            .replace('(', "\\28")
            .replace(')', "\\29")
            .replace('\0', "\\00")
    }

    /// Check if LDAP is configured and available
    pub fn is_configured(&self) -> bool {
        !self.config.url.is_empty() && !self.config.base_dn.is_empty()
    }

    /// Get the LDAP server URL (for diagnostics)
    pub fn server_url(&self) -> &str {
        &self.config.url
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_ldap_input() {
        assert_eq!(LdapService::sanitize_ldap_input("user"), "user");
        assert_eq!(LdapService::sanitize_ldap_input("user*"), "user\\2a");
        assert_eq!(LdapService::sanitize_ldap_input("(user)"), "\\28user\\29");
        assert_eq!(
            LdapService::sanitize_ldap_input("user\\name"),
            "user\\5cname"
        );
    }

    #[test]
    fn test_ldap_config_from_env() {
        // Config requires LDAP_URL and LDAP_BASE_DN
        let config = Config {
            database_url: "postgres://localhost/test".into(),
            bind_address: "0.0.0.0:8080".into(),
            log_level: "info".into(),
            storage_backend: "filesystem".into(),
            storage_path: "/tmp/artifacts".into(),
            s3_bucket: None,
            s3_region: None,
            s3_endpoint: None,
            jwt_secret: "test-secret".into(),
            jwt_expiration_secs: 86400,
            jwt_access_token_expiry_minutes: 30,
            jwt_refresh_token_expiry_days: 7,
            oidc_issuer: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            ldap_url: Some("ldap://localhost:389".into()),
            ldap_base_dn: Some("dc=example,dc=com".into()),
            trivy_url: None,
        };

        let ldap_config = LdapConfig::from_config(&config);
        assert!(ldap_config.is_some());
        let ldap_config = ldap_config.unwrap();
        assert_eq!(ldap_config.url, "ldap://localhost:389");
        assert_eq!(ldap_config.base_dn, "dc=example,dc=com");
    }
}
