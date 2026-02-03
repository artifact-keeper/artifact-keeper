//! Application configuration loaded from environment variables.

use crate::error::{AppError, Result};
use std::env;

/// Read an environment variable and parse it, falling back to a default on missing or invalid values.
fn env_parse<T: std::str::FromStr>(key: &str, default: T) -> T {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Application configuration
#[derive(Debug, Clone)]
pub struct Config {
    /// Database connection URL
    pub database_url: String,

    /// Server bind address (host:port)
    pub bind_address: String,

    /// Log level
    pub log_level: String,

    /// Storage backend: "filesystem" or "s3"
    pub storage_backend: String,

    /// Filesystem storage path (when storage_backend = "filesystem")
    pub storage_path: String,

    /// S3 bucket name (when storage_backend = "s3")
    pub s3_bucket: Option<String>,

    /// S3 region
    pub s3_region: Option<String>,

    /// S3 endpoint URL (for MinIO or other S3-compatible services)
    pub s3_endpoint: Option<String>,

    /// JWT secret key for signing tokens
    pub jwt_secret: String,

    /// JWT token expiration in seconds (legacy, use jwt_access_token_expiry_minutes)
    pub jwt_expiration_secs: u64,

    /// JWT access token expiry in minutes
    pub jwt_access_token_expiry_minutes: i64,

    /// JWT refresh token expiry in days
    pub jwt_refresh_token_expiry_days: i64,

    /// OIDC issuer URL (optional)
    pub oidc_issuer: Option<String>,

    /// OIDC client ID (optional)
    pub oidc_client_id: Option<String>,

    /// OIDC client secret (optional)
    pub oidc_client_secret: Option<String>,

    /// LDAP server URL (optional)
    pub ldap_url: Option<String>,

    /// LDAP base DN (optional)
    pub ldap_base_dn: Option<String>,

    /// Trivy server URL for container image scanning (optional)
    pub trivy_url: Option<String>,

    /// OpenSCAP wrapper URL for compliance scanning (optional)
    pub openscap_url: Option<String>,

    /// OpenSCAP SCAP profile to evaluate (default: standard)
    pub openscap_profile: String,

    /// Meilisearch URL for search indexing (optional)
    pub meilisearch_url: Option<String>,

    /// Meilisearch API key
    pub meilisearch_api_key: Option<String>,

    /// Path for scan workspace shared with Trivy
    pub scan_workspace_path: String,

    /// Demo mode: blocks all write operations (POST/PUT/DELETE/PATCH) except auth
    pub demo_mode: bool,

    /// Peer instance name for mesh identification
    pub peer_instance_name: String,

    /// Public endpoint URL where this instance can be reached by peers
    pub peer_public_endpoint: String,

    /// API key for authenticating peer-to-peer requests
    pub peer_api_key: String,
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            database_url: env::var("DATABASE_URL")
                .map_err(|_| AppError::Config("DATABASE_URL not set".into()))?,
            bind_address: env::var("BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8080".into()),
            log_level: env::var("LOG_LEVEL").unwrap_or_else(|_| "info".into()),
            storage_backend: env::var("STORAGE_BACKEND").unwrap_or_else(|_| "filesystem".into()),
            storage_path: env::var("STORAGE_PATH")
                .unwrap_or_else(|_| "/var/lib/artifact-keeper/artifacts".into()),
            s3_bucket: env::var("S3_BUCKET").ok(),
            s3_region: env::var("S3_REGION").ok(),
            s3_endpoint: env::var("S3_ENDPOINT").ok(),
            jwt_secret: env::var("JWT_SECRET")
                .map_err(|_| AppError::Config("JWT_SECRET not set".into()))?,
            jwt_expiration_secs: env_parse("JWT_EXPIRATION_SECS", 86400),
            jwt_access_token_expiry_minutes: env_parse("JWT_ACCESS_TOKEN_EXPIRY_MINUTES", 30),
            jwt_refresh_token_expiry_days: env_parse("JWT_REFRESH_TOKEN_EXPIRY_DAYS", 7),
            oidc_issuer: env::var("OIDC_ISSUER").ok(),
            oidc_client_id: env::var("OIDC_CLIENT_ID").ok(),
            oidc_client_secret: env::var("OIDC_CLIENT_SECRET").ok(),
            ldap_url: env::var("LDAP_URL").ok(),
            ldap_base_dn: env::var("LDAP_BASE_DN").ok(),
            trivy_url: env::var("TRIVY_URL").ok(),
            openscap_url: env::var("OPENSCAP_URL").ok(),
            openscap_profile: env::var("OPENSCAP_PROFILE")
                .unwrap_or_else(|_| "xccdf_org.ssgproject.content_profile_standard".into()),
            meilisearch_url: env::var("MEILISEARCH_URL").ok(),
            meilisearch_api_key: env::var("MEILISEARCH_API_KEY").ok(),
            scan_workspace_path: env::var("SCAN_WORKSPACE_PATH")
                .unwrap_or_else(|_| "/scan-workspace".into()),
            demo_mode: matches!(env::var("DEMO_MODE").as_deref(), Ok("true" | "1")),
            peer_instance_name: env::var("PEER_INSTANCE_NAME")
                .unwrap_or_else(|_| "artifact-keeper-local".into()),
            peer_public_endpoint: env::var("PEER_PUBLIC_ENDPOINT")
                .unwrap_or_else(|_| "http://localhost:8080".into()),
            peer_api_key: env::var("PEER_API_KEY")
                .unwrap_or_else(|_| "change-me-in-production".into()),
        })
    }
}
