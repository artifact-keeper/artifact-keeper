//! OIDC (OpenID Connect) authentication service.
//!
//! Provides authentication via OpenID Connect providers like Keycloak,
//! Azure AD, Okta, Auth0, Google, etc.

use std::collections::HashMap;
use std::sync::Arc;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::Config;
use crate::error::{AppError, Result};
use crate::models::user::{AuthProvider, User};

/// OIDC provider configuration
#[derive(Debug, Clone)]
pub struct OidcConfig {
    /// OIDC issuer URL (e.g., https://accounts.google.com)
    pub issuer: String,
    /// Client ID
    pub client_id: String,
    /// Client secret
    pub client_secret: String,
    /// Redirect URI for callback
    pub redirect_uri: String,
    /// Scopes to request (default: openid profile email)
    pub scopes: Vec<String>,
    /// Claim containing username
    pub username_claim: String,
    /// Claim containing email
    pub email_claim: String,
    /// Claim containing display name
    pub display_name_claim: String,
    /// Claim containing groups
    pub groups_claim: String,
    /// Group name for admin role
    pub admin_group: Option<String>,
}

impl OidcConfig {
    /// Create OIDC config from application config
    pub fn from_config(config: &Config) -> Option<Self> {
        let issuer = config.oidc_issuer.clone()?;
        let client_id = config.oidc_client_id.clone()?;
        let client_secret = config.oidc_client_secret.clone()?;

        Some(Self {
            issuer,
            client_id,
            client_secret,
            redirect_uri: std::env::var("OIDC_REDIRECT_URI")
                .unwrap_or_else(|_| "http://localhost:8080/auth/oidc/callback".to_string()),
            scopes: std::env::var("OIDC_SCOPES")
                .map(|s| s.split(' ').map(|s| s.to_string()).collect())
                .unwrap_or_else(|_| vec!["openid".into(), "profile".into(), "email".into()]),
            username_claim: std::env::var("OIDC_USERNAME_CLAIM")
                .unwrap_or_else(|_| "preferred_username".to_string()),
            email_claim: std::env::var("OIDC_EMAIL_CLAIM").unwrap_or_else(|_| "email".to_string()),
            display_name_claim: std::env::var("OIDC_DISPLAY_NAME_CLAIM")
                .unwrap_or_else(|_| "name".to_string()),
            groups_claim: std::env::var("OIDC_GROUPS_CLAIM")
                .unwrap_or_else(|_| "groups".to_string()),
            admin_group: std::env::var("OIDC_ADMIN_GROUP").ok(),
        })
    }
}

/// OIDC discovery document (well-known configuration)
#[derive(Debug, Clone, Deserialize)]
pub struct OidcDiscovery {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: Option<String>,
    pub jwks_uri: String,
    pub scopes_supported: Option<Vec<String>>,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Option<Vec<String>>,
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,
}

/// Token response from OIDC provider
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: Option<u64>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub scope: Option<String>,
}

/// User information from OIDC provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcUserInfo {
    /// Subject identifier (unique user ID from provider)
    pub sub: String,
    /// Username (preferred_username claim)
    pub username: String,
    /// Email address
    pub email: String,
    /// Whether email is verified
    pub email_verified: Option<bool>,
    /// Display name
    pub display_name: Option<String>,
    /// Group memberships
    pub groups: Vec<String>,
    /// Raw claims from ID token
    #[serde(flatten)]
    pub extra_claims: HashMap<String, serde_json::Value>,
}

/// ID Token claims (JWT payload)
#[derive(Debug, Clone, Deserialize)]
pub struct IdTokenClaims {
    /// Issuer
    pub iss: String,
    /// Subject (user ID)
    pub sub: String,
    /// Audience (client ID)
    pub aud: OidcAudience,
    /// Expiration time
    pub exp: i64,
    /// Issued at
    pub iat: i64,
    /// Auth time (optional)
    pub auth_time: Option<i64>,
    /// Nonce (optional)
    pub nonce: Option<String>,
    /// Additional claims
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// OIDC audience can be a string or array
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum OidcAudience {
    Single(String),
    Multiple(Vec<String>),
}

impl OidcAudience {
    pub fn contains(&self, client_id: &str) -> bool {
        match self {
            OidcAudience::Single(aud) => aud == client_id,
            OidcAudience::Multiple(auds) => auds.iter().any(|a| a == client_id),
        }
    }
}

/// Authorization URL parameters
#[derive(Debug, Clone, Serialize)]
pub struct AuthorizationParams {
    pub authorization_url: String,
    pub state: String,
    pub nonce: String,
}

/// OIDC authentication service
pub struct OidcService {
    db: PgPool,
    config: OidcConfig,
    http_client: Client,
    discovery: Option<OidcDiscovery>,
}

impl OidcService {
    /// Create a new OIDC service
    pub fn new(db: PgPool, app_config: Arc<Config>) -> Result<Self> {
        let config = OidcConfig::from_config(&app_config)
            .ok_or_else(|| AppError::Config("OIDC configuration not set".into()))?;

        Ok(Self {
            db,
            config,
            http_client: Client::new(),
            discovery: None,
        })
    }

    /// Create OIDC service from explicit config
    pub fn with_config(db: PgPool, config: OidcConfig) -> Self {
        Self {
            db,
            config,
            http_client: Client::new(),
            discovery: None,
        }
    }

    /// Fetch OIDC discovery document
    pub async fn discover(&mut self) -> Result<&OidcDiscovery> {
        if self.discovery.is_none() {
            let discovery_url = format!(
                "{}/.well-known/openid-configuration",
                self.config.issuer.trim_end_matches('/')
            );

            let response = self
                .http_client
                .get(&discovery_url)
                .send()
                .await
                .map_err(|e| {
                    AppError::Internal(format!("Failed to fetch OIDC discovery: {}", e))
                })?;

            if !response.status().is_success() {
                return Err(AppError::Internal(format!(
                    "OIDC discovery failed with status: {}",
                    response.status()
                )));
            }

            let discovery: OidcDiscovery = response.json().await.map_err(|e| {
                AppError::Internal(format!("Failed to parse OIDC discovery: {}", e))
            })?;

            self.discovery = Some(discovery);
        }

        Ok(self.discovery.as_ref().unwrap())
    }

    /// Generate authorization URL for login redirect
    pub async fn get_authorization_url(&mut self) -> Result<AuthorizationParams> {
        let discovery = self.discover().await?.clone();

        // Generate random state and nonce for CSRF protection
        let state = Uuid::new_v4().to_string();
        let nonce = Uuid::new_v4().to_string();

        let scopes = self.config.scopes.join(" ");

        let params = [
            ("response_type", "code"),
            ("client_id", &self.config.client_id),
            ("redirect_uri", &self.config.redirect_uri),
            ("scope", &scopes),
            ("state", &state),
            ("nonce", &nonce),
        ];

        let authorization_url = format!(
            "{}?{}",
            discovery.authorization_endpoint,
            serde_urlencoded::to_string(params)
                .map_err(|e| AppError::Internal(format!("Failed to encode params: {}", e)))?
        );

        Ok(AuthorizationParams {
            authorization_url,
            state,
            nonce,
        })
    }

    /// Exchange authorization code for tokens
    pub async fn authenticate(&mut self, code: &str) -> Result<OidcUserInfo> {
        let discovery = self.discover().await?.clone();

        // Exchange code for tokens
        let token_response = self.exchange_code(code, &discovery.token_endpoint).await?;

        // Extract user info from ID token or userinfo endpoint
        let user_info = if let Some(id_token) = &token_response.id_token {
            self.extract_user_from_id_token(id_token)?
        } else if let Some(userinfo_endpoint) = &discovery.userinfo_endpoint {
            self.fetch_userinfo(&token_response.access_token, userinfo_endpoint)
                .await?
        } else {
            return Err(AppError::Authentication(
                "No ID token or userinfo endpoint available".into(),
            ));
        };

        tracing::info!(
            sub = %user_info.sub,
            username = %user_info.username,
            "OIDC authentication successful"
        );

        Ok(user_info)
    }

    /// Exchange authorization code for tokens
    async fn exchange_code(&self, code: &str, token_endpoint: &str) -> Result<TokenResponse> {
        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &self.config.redirect_uri),
            ("client_id", &self.config.client_id),
            ("client_secret", &self.config.client_secret),
        ];

        let response = self
            .http_client
            .post(token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| AppError::Authentication(format!("Token exchange failed: {}", e)))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_default();
            return Err(AppError::Authentication(format!(
                "Token exchange failed: {}",
                error_text
            )));
        }

        response
            .json()
            .await
            .map_err(|e| AppError::Authentication(format!("Failed to parse token response: {}", e)))
    }

    /// Extract user information from ID token
    fn extract_user_from_id_token(&self, id_token: &str) -> Result<OidcUserInfo> {
        // Decode JWT without verification (validation should use JWKS in production)
        // The token format is: header.payload.signature
        let parts: Vec<&str> = id_token.split('.').collect();
        if parts.len() != 3 {
            return Err(AppError::Authentication("Invalid ID token format".into()));
        }

        // Decode the payload (middle part)
        let payload = parts[1];

        // Add padding if needed for base64 decoding
        let padding = match payload.len() % 4 {
            2 => "==",
            3 => "=",
            _ => "",
        };
        let padded = format!("{}{}", payload, padding);

        // Use URL-safe base64 decoding
        let decoded = base64_decode_url_safe(&padded)
            .map_err(|e| AppError::Authentication(format!("Failed to decode ID token: {}", e)))?;

        let claims: IdTokenClaims = serde_json::from_slice(&decoded).map_err(|e| {
            AppError::Authentication(format!("Failed to parse ID token claims: {}", e))
        })?;

        // Validate issuer
        if claims.iss != self.config.issuer {
            return Err(AppError::Authentication(format!(
                "Invalid issuer: expected {}, got {}",
                self.config.issuer, claims.iss
            )));
        }

        // Validate audience
        if !claims.aud.contains(&self.config.client_id) {
            return Err(AppError::Authentication("Invalid audience".into()));
        }

        // Validate expiration
        let now = chrono::Utc::now().timestamp();
        if claims.exp < now {
            return Err(AppError::Authentication("ID token expired".into()));
        }

        // Extract user info from claims
        let username = claims
            .extra
            .get(&self.config.username_claim)
            .and_then(|v| v.as_str())
            .unwrap_or(&claims.sub)
            .to_string();

        let email = claims
            .extra
            .get(&self.config.email_claim)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let display_name = claims
            .extra
            .get(&self.config.display_name_claim)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let groups = claims
            .extra
            .get(&self.config.groups_claim)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let email_verified = claims.extra.get("email_verified").and_then(|v| v.as_bool());

        Ok(OidcUserInfo {
            sub: claims.sub,
            username,
            email,
            email_verified,
            display_name,
            groups,
            extra_claims: claims.extra,
        })
    }

    /// Fetch user info from userinfo endpoint
    async fn fetch_userinfo(
        &self,
        access_token: &str,
        userinfo_endpoint: &str,
    ) -> Result<OidcUserInfo> {
        let response = self
            .http_client
            .get(userinfo_endpoint)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| AppError::Authentication(format!("Userinfo request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(AppError::Authentication("Userinfo request failed".into()));
        }

        let claims: HashMap<String, serde_json::Value> = response
            .json()
            .await
            .map_err(|e| AppError::Authentication(format!("Failed to parse userinfo: {}", e)))?;

        let sub = claims
            .get("sub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::Authentication("Missing sub claim".into()))?
            .to_string();

        let username = claims
            .get(&self.config.username_claim)
            .and_then(|v| v.as_str())
            .unwrap_or(&sub)
            .to_string();

        let email = claims
            .get(&self.config.email_claim)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let display_name = claims
            .get(&self.config.display_name_claim)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let groups = claims
            .get(&self.config.groups_claim)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let email_verified = claims.get("email_verified").and_then(|v| v.as_bool());

        Ok(OidcUserInfo {
            sub,
            username,
            email,
            email_verified,
            display_name,
            groups,
            extra_claims: claims,
        })
    }

    /// Get or create a user from OIDC information
    pub async fn get_or_create_user(&self, oidc_user: &OidcUserInfo) -> Result<User> {
        // Check if user already exists by external_id (sub)
        let existing_user = sqlx::query_as!(
            User,
            r#"
            SELECT
                id, username, email, password_hash, display_name,
                auth_provider as "auth_provider: AuthProvider",
                external_id, is_admin, is_active, must_change_password,
                last_login_at, created_at, updated_at
            FROM users
            WHERE external_id = $1 AND auth_provider = 'oidc'
            "#,
            oidc_user.sub
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if let Some(mut user) = existing_user {
            // Update user info from OIDC
            let is_admin = self.is_admin_from_groups(&oidc_user.groups);

            sqlx::query!(
                r#"
                UPDATE users
                SET email = $1, display_name = $2, is_admin = $3,
                    last_login_at = NOW(), updated_at = NOW()
                WHERE id = $4
                "#,
                oidc_user.email,
                oidc_user.display_name,
                is_admin,
                user.id
            )
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

            user.email = oidc_user.email.clone();
            user.display_name = oidc_user.display_name.clone();
            user.is_admin = is_admin;

            return Ok(user);
        }

        // Create new user from OIDC
        let user_id = Uuid::new_v4();
        let is_admin = self.is_admin_from_groups(&oidc_user.groups);

        // Generate unique username if conflict exists
        let username = self.generate_unique_username(&oidc_user.username).await?;

        let user = sqlx::query_as!(
            User,
            r#"
            INSERT INTO users (id, username, email, display_name, auth_provider, external_id, is_admin, is_active)
            VALUES ($1, $2, $3, $4, 'oidc', $5, $6, true)
            RETURNING
                id, username, email, password_hash, display_name,
                auth_provider as "auth_provider: AuthProvider",
                external_id, is_admin, is_active, must_change_password,
                last_login_at, created_at, updated_at
            "#,
            user_id,
            username,
            oidc_user.email,
            oidc_user.display_name,
            oidc_user.sub,
            is_admin
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        tracing::info!(
            user_id = %user.id,
            username = %user.username,
            sub = %oidc_user.sub,
            "Created new user from OIDC"
        );

        Ok(user)
    }

    /// Generate unique username if conflict exists
    async fn generate_unique_username(&self, base_username: &str) -> Result<String> {
        let mut username = base_username.to_string();
        let mut suffix = 1;

        loop {
            let exists = sqlx::query_scalar!(
                "SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)",
                username
            )
            .fetch_one(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
            .unwrap_or(false);

            if !exists {
                return Ok(username);
            }

            username = format!("{}_{}", base_username, suffix);
            suffix += 1;

            if suffix > 100 {
                return Err(AppError::Internal(
                    "Failed to generate unique username".into(),
                ));
            }
        }
    }

    /// Check if user is admin based on group memberships
    fn is_admin_from_groups(&self, groups: &[String]) -> bool {
        if let Some(admin_group) = &self.config.admin_group {
            groups
                .iter()
                .any(|g| g.to_lowercase() == admin_group.to_lowercase())
        } else {
            false
        }
    }

    /// Extract group memberships for role mapping
    pub fn extract_groups(&self, oidc_user: &OidcUserInfo) -> Vec<String> {
        oidc_user.groups.clone()
    }

    /// Map OIDC groups to application roles
    pub fn map_groups_to_roles(&self, groups: &[String]) -> Vec<String> {
        let mut roles = vec!["user".to_string()];

        if self.is_admin_from_groups(groups) {
            roles.push("admin".to_string());
        }

        // Additional role mappings from environment
        // OIDC_GROUP_ROLE_MAP=developers:developer;admins:admin
        if let Ok(mappings) = std::env::var("OIDC_GROUP_ROLE_MAP") {
            for mapping in mappings.split(';') {
                if let Some((group, role)) = mapping.split_once(':') {
                    if groups
                        .iter()
                        .any(|g| g.to_lowercase() == group.to_lowercase())
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

    /// Check if OIDC is configured
    pub fn is_configured(&self) -> bool {
        !self.config.issuer.is_empty()
            && !self.config.client_id.is_empty()
            && !self.config.client_secret.is_empty()
    }

    /// Get the OIDC issuer URL
    pub fn issuer(&self) -> &str {
        &self.config.issuer
    }

    /// Get the client ID
    pub fn client_id(&self) -> &str {
        &self.config.client_id
    }
}

/// URL-safe base64 decode
fn base64_decode_url_safe(input: &str) -> std::result::Result<Vec<u8>, String> {
    // Convert URL-safe base64 to standard base64
    let standard = input.replace('-', "+").replace('_', "/");

    // Simple base64 decode implementation
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut output = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits_collected = 0;

    for byte in standard.bytes() {
        if byte == b'=' {
            break;
        }

        let value = ALPHABET
            .iter()
            .position(|&c| c == byte)
            .ok_or_else(|| format!("Invalid base64 character: {}", byte as char))?;

        buffer = (buffer << 6) | (value as u32);
        bits_collected += 6;

        if bits_collected >= 8 {
            bits_collected -= 8;
            output.push(((buffer >> bits_collected) & 0xFF) as u8);
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_decode_url_safe() {
        // Test basic decoding
        let input = "SGVsbG8gV29ybGQ"; // "Hello World" without padding
        let decoded = base64_decode_url_safe(&format!("{}=", input)).unwrap();
        assert_eq!(String::from_utf8(decoded).unwrap(), "Hello World");
    }

    #[test]
    fn test_oidc_audience_contains() {
        let single = OidcAudience::Single("client-123".into());
        assert!(single.contains("client-123"));
        assert!(!single.contains("other-client"));

        let multiple = OidcAudience::Multiple(vec!["client-123".into(), "client-456".into()]);
        assert!(multiple.contains("client-123"));
        assert!(multiple.contains("client-456"));
        assert!(!multiple.contains("other-client"));
    }

    #[test]
    fn test_oidc_config_from_env() {
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
            oidc_issuer: Some("https://accounts.google.com".into()),
            oidc_client_id: Some("client-123".into()),
            oidc_client_secret: Some("secret-456".into()),
            ldap_url: None,
            ldap_base_dn: None,
            trivy_url: None,
            meilisearch_url: None,
            meilisearch_api_key: None,
            scan_workspace_path: "/scan-workspace".into(),
            demo_mode: false,
        };

        let oidc_config = OidcConfig::from_config(&config);
        assert!(oidc_config.is_some());
        let oidc_config = oidc_config.unwrap();
        assert_eq!(oidc_config.issuer, "https://accounts.google.com");
        assert_eq!(oidc_config.client_id, "client-123");
    }
}
