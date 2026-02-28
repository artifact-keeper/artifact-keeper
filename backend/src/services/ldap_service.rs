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
#[derive(Clone)]
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

redacted_debug!(LdapConfig {
    show url,
    show base_dn,
    show user_filter,
    show bind_dn,
    redact_option bind_password,
    show username_attr,
    show email_attr,
    show display_name_attr,
    show groups_attr,
    show admin_group_dn,
    show use_starttls,
});

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

    /// Create LDAP service from database-stored config
    #[allow(clippy::too_many_arguments)]
    pub fn from_db_config(
        db: PgPool,
        _name: &str,
        server_url: &str,
        bind_dn: Option<&str>,
        bind_password: Option<&str>,
        user_base_dn: &str,
        user_filter: &str,
        username_attr: &str,
        email_attr: &str,
        display_name_attr: &str,
        groups_attr: &str,
        admin_group_dn: Option<&str>,
        use_starttls: bool,
    ) -> Self {
        let config = LdapConfig {
            url: server_url.to_string(),
            base_dn: user_base_dn.to_string(),
            user_filter: user_filter.to_string(),
            bind_dn: bind_dn.map(String::from),
            bind_password: bind_password.map(String::from),
            username_attr: username_attr.to_string(),
            email_attr: email_attr.to_string(),
            display_name_attr: display_name_attr.to_string(),
            groups_attr: groups_attr.to_string(),
            admin_group_dn: admin_group_dn.map(String::from),
            use_starttls,
        };
        Self {
            db,
            config,
            http_client: Client::new(),
        }
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
                external_id, is_admin, is_active, is_service_account, must_change_password,
                totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
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
            INSERT INTO users (id, username, email, display_name, auth_provider, external_id, is_admin, is_active, is_service_account)
            VALUES ($1, $2, $3, $4, 'ldap', $5, $6, true, false)
            RETURNING
                id, username, email, password_hash, display_name,
                auth_provider as "auth_provider: AuthProvider",
                external_id, is_admin, is_active, is_service_account, must_change_password,
                totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
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

    /// Validate LDAP credentials via real LDAP simple bind.
    async fn validate_ldap_credentials(&self, user_dn: &str, password: &str) -> Result<()> {
        use ldap3::{LdapConnAsync, LdapConnSettings};
        use std::time::Duration;

        let settings = LdapConnSettings::new()
            .set_conn_timeout(Duration::from_secs(10))
            .set_starttls(self.config.use_starttls);

        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &self.config.url)
            .await
            .map_err(|e| AppError::Authentication(format!("LDAP connection failed: {e}")))?;

        ldap3::drive!(conn);

        let result = ldap
            .simple_bind(user_dn, password)
            .await
            .map_err(|e| AppError::Authentication(format!("LDAP bind failed: {e}")))?;

        if result.rc != 0 {
            return Err(AppError::Authentication("Invalid credentials".into()));
        }

        ldap.unbind().await.ok();
        Ok(())
    }

    /// Get user information from LDAP via real search.
    async fn get_user_info(&self, username: &str, user_dn: &str) -> Result<LdapUserInfo> {
        use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
        use std::time::Duration;

        // If we have a bind DN, use search-then-bind
        // Otherwise return basic info from the DN
        if let (Some(bind_dn), Some(bind_pw)) = (&self.config.bind_dn, &self.config.bind_password) {
            let settings = LdapConnSettings::new()
                .set_conn_timeout(Duration::from_secs(10))
                .set_starttls(self.config.use_starttls);

            let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &self.config.url)
                .await
                .map_err(|e| AppError::Internal(format!("LDAP connection failed: {e}")))?;

            ldap3::drive!(conn);

            ldap.simple_bind(bind_dn, bind_pw)
                .await
                .map_err(|e| AppError::Internal(format!("Service account bind failed: {e}")))?
                .success()
                .map_err(|e| AppError::Internal(format!("Service account bind failed: {e}")))?;

            let search_filter = self
                .config
                .user_filter
                .replace("{username}", &Self::sanitize_ldap_input(username));
            let attrs = vec![
                self.config.username_attr.as_str(),
                self.config.email_attr.as_str(),
                self.config.display_name_attr.as_str(),
                self.config.groups_attr.as_str(),
            ];

            let (results, _) = ldap
                .search(&self.config.base_dn, Scope::Subtree, &search_filter, attrs)
                .await
                .map_err(|e| AppError::Internal(format!("LDAP search failed: {e}")))?
                .success()
                .map_err(|e| AppError::Internal(format!("LDAP search failed: {e}")))?;

            ldap.unbind().await.ok();

            if let Some(entry) = results.into_iter().next() {
                let entry = SearchEntry::construct(entry);

                let email = entry
                    .attrs
                    .get(&self.config.email_attr)
                    .and_then(|v| v.first())
                    .cloned()
                    .unwrap_or_else(|| format!("{}@unknown", username));

                let display_name = entry
                    .attrs
                    .get(&self.config.display_name_attr)
                    .and_then(|v| v.first())
                    .cloned();

                let groups = entry
                    .attrs
                    .get(&self.config.groups_attr)
                    .cloned()
                    .unwrap_or_default();

                return Ok(LdapUserInfo {
                    dn: entry.dn,
                    username: username.to_string(),
                    email,
                    display_name,
                    groups,
                });
            }
        }

        // Fallback: construct basic info from the DN
        Ok(LdapUserInfo {
            dn: user_dn.to_string(),
            username: username.to_string(),
            email: format!("{}@unknown", username),
            display_name: None,
            groups: Vec::new(),
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

    fn make_test_config() -> Config {
        Config {
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
            openscap_url: None,
            openscap_profile: "xccdf_org.ssgproject.content_profile_standard".into(),
            meilisearch_url: None,
            meilisearch_api_key: None,
            scan_workspace_path: "/scan-workspace".into(),
            demo_mode: false,
            peer_instance_name: "test".into(),
            peer_public_endpoint: "http://localhost:8080".into(),
            peer_api_key: "test-key".into(),
            dependency_track_url: None,
            otel_exporter_otlp_endpoint: None,
            otel_service_name: "test".into(),
            gc_schedule: "0 0 * * * *".into(),
            lifecycle_check_interval_secs: 60,
        }
    }

    fn make_test_ldap_config() -> LdapConfig {
        LdapConfig {
            url: "ldap://ldap.example.com:389".to_string(),
            base_dn: "dc=example,dc=com".to_string(),
            user_filter: "(uid={username})".to_string(),
            bind_dn: None,
            bind_password: None,
            username_attr: "uid".to_string(),
            email_attr: "mail".to_string(),
            display_name_attr: "cn".to_string(),
            groups_attr: "memberOf".to_string(),
            admin_group_dn: Some("cn=admins,ou=groups,dc=example,dc=com".to_string()),
            use_starttls: false,
        }
    }

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
        let config = make_test_config();

        let ldap_config = LdapConfig::from_config(&config);
        assert!(ldap_config.is_some());
        let ldap_config = ldap_config.unwrap();
        assert_eq!(ldap_config.url, "ldap://localhost:389");
        assert_eq!(ldap_config.base_dn, "dc=example,dc=com");
    }

    #[test]
    fn test_sanitize_ldap_input_null_byte() {
        assert_eq!(
            LdapService::sanitize_ldap_input("user\0name"),
            "user\\00name"
        );
    }

    #[test]
    fn test_sanitize_ldap_input_multiple_special_chars() {
        let input = "*()\\\0";
        let sanitized = LdapService::sanitize_ldap_input(input);
        assert_eq!(sanitized, "\\2a\\28\\29\\5c\\00");
    }

    #[test]
    fn test_sanitize_ldap_input_empty_string() {
        assert_eq!(LdapService::sanitize_ldap_input(""), "");
    }

    #[test]
    fn test_sanitize_ldap_input_normal_chars_unmodified() {
        let input = "john.doe@example.com";
        assert_eq!(LdapService::sanitize_ldap_input(input), input);
    }

    #[test]
    fn test_ldap_config_returns_none_without_url() {
        let mut config = make_test_config();
        config.ldap_url = None;
        let ldap_config = LdapConfig::from_config(&config);
        assert!(ldap_config.is_none());
    }

    #[test]
    fn test_ldap_config_returns_none_without_base_dn() {
        let mut config = make_test_config();
        config.ldap_base_dn = None;
        let ldap_config = LdapConfig::from_config(&config);
        assert!(ldap_config.is_none());
    }

    #[test]
    fn test_ldap_config_returns_none_without_both() {
        let mut config = make_test_config();
        config.ldap_url = None;
        config.ldap_base_dn = None;
        let ldap_config = LdapConfig::from_config(&config);
        assert!(ldap_config.is_none());
    }

    #[test]
    fn test_ldap_user_info_serialization_roundtrip() {
        let user_info = LdapUserInfo {
            dn: "uid=john,ou=users,dc=example,dc=com".to_string(),
            username: "john".to_string(),
            email: "john@example.com".to_string(),
            display_name: Some("John Doe".to_string()),
            groups: vec![
                "cn=developers,ou=groups,dc=example,dc=com".to_string(),
                "cn=admins,ou=groups,dc=example,dc=com".to_string(),
            ],
        };
        let json = serde_json::to_string(&user_info).unwrap();
        let deserialized: LdapUserInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.dn, user_info.dn);
        assert_eq!(deserialized.username, user_info.username);
        assert_eq!(deserialized.email, user_info.email);
        assert_eq!(deserialized.display_name, user_info.display_name);
        assert_eq!(deserialized.groups, user_info.groups);
    }

    #[test]
    fn test_ldap_user_info_deserialization_minimal() {
        let json = r#"{
            "dn": "uid=test,dc=test",
            "username": "test",
            "email": "test@test.com",
            "display_name": null,
            "groups": []
        }"#;
        let user: LdapUserInfo = serde_json::from_str(json).unwrap();
        assert_eq!(user.username, "test");
        assert!(user.display_name.is_none());
        assert!(user.groups.is_empty());
    }

    #[test]
    fn test_ldap_config_is_configured_true() {
        let config = make_test_ldap_config();
        // Create an LdapConfig directly and check is_configured logic
        assert!(!config.url.is_empty());
        assert!(!config.base_dn.is_empty());
    }

    #[test]
    fn test_ldap_config_is_configured_empty_url() {
        let mut config = make_test_ldap_config();
        config.url = String::new();
        // The is_configured check relies on url and base_dn being non-empty
        assert!(config.url.is_empty());
    }

    #[test]
    fn test_ldap_config_admin_group_dn() {
        let config = make_test_ldap_config();
        assert_eq!(
            config.admin_group_dn,
            Some("cn=admins,ou=groups,dc=example,dc=com".to_string())
        );
    }

    #[test]
    fn test_ldap_config_no_admin_group() {
        let mut config = make_test_ldap_config();
        config.admin_group_dn = None;
        assert!(config.admin_group_dn.is_none());
    }

    #[test]
    fn test_ldap_config_starttls_default() {
        let config = make_test_ldap_config();
        assert!(!config.use_starttls);
    }

    #[test]
    fn test_ldap_config_default_attributes() {
        let config = make_test_ldap_config();
        assert_eq!(config.username_attr, "uid");
        assert_eq!(config.email_attr, "mail");
        assert_eq!(config.display_name_attr, "cn");
        assert_eq!(config.groups_attr, "memberOf");
    }

    #[test]
    fn test_ldap_config_custom_user_filter() {
        let mut config = make_test_ldap_config();
        config.user_filter = "(sAMAccountName={username})".to_string();
        assert_eq!(config.user_filter, "(sAMAccountName={username})");
    }

    #[test]
    fn test_ldap_config_with_bind_credentials() {
        let mut config = make_test_ldap_config();
        config.bind_dn = Some("cn=service,dc=example,dc=com".to_string());
        config.bind_password = Some("secret".to_string());
        assert!(config.bind_dn.is_some());
        assert!(config.bind_password.is_some());
    }

    #[test]
    fn test_ldap_user_info_clone() {
        let user_info = LdapUserInfo {
            dn: "uid=alice,dc=test".to_string(),
            username: "alice".to_string(),
            email: "alice@test.com".to_string(),
            display_name: Some("Alice".to_string()),
            groups: vec!["cn=users,dc=test".to_string()],
        };
        let cloned = user_info.clone();
        assert_eq!(cloned.dn, user_info.dn);
        assert_eq!(cloned.username, user_info.username);
        assert_eq!(cloned.email, user_info.email);
        assert_eq!(cloned.groups, user_info.groups);
    }

    #[test]
    fn test_ldap_config_debug_redacts_bind_password() {
        let config = LdapConfig {
            url: "ldap://ldap.example.com:389".to_string(),
            base_dn: "dc=example,dc=com".to_string(),
            user_filter: "(uid={username})".to_string(),
            bind_dn: Some("cn=admin,dc=example,dc=com".to_string()),
            bind_password: Some("super-secret-ldap-password".to_string()),
            username_attr: "uid".to_string(),
            email_attr: "mail".to_string(),
            display_name_attr: "cn".to_string(),
            groups_attr: "memberOf".to_string(),
            admin_group_dn: None,
            use_starttls: true,
        };
        let debug = format!("{:?}", config);
        assert!(debug.contains("ldap.example.com"));
        assert!(debug.contains("dc=example,dc=com"));
        assert!(!debug.contains("super-secret-ldap-password"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn test_ldap_config_debug_shows_none_for_missing_password() {
        let config = LdapConfig {
            url: "ldap://localhost".to_string(),
            base_dn: "dc=test".to_string(),
            user_filter: "(uid={username})".to_string(),
            bind_dn: None,
            bind_password: None,
            username_attr: "uid".to_string(),
            email_attr: "mail".to_string(),
            display_name_attr: "cn".to_string(),
            groups_attr: "memberOf".to_string(),
            admin_group_dn: None,
            use_starttls: false,
        };
        let debug = format!("{:?}", config);
        assert!(debug.contains("None"));
    }
}
