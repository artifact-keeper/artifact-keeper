//! Application configuration loaded from environment variables.

use crate::error::{AppError, Result};
use std::env;

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
            jwt_expiration_secs: env::var("JWT_EXPIRATION_SECS")
                .unwrap_or_else(|_| "86400".into())
                .parse()
                .unwrap_or(86400),
            jwt_access_token_expiry_minutes: env::var("JWT_ACCESS_TOKEN_EXPIRY_MINUTES")
                .unwrap_or_else(|_| "30".into())
                .parse()
                .unwrap_or(30),
            jwt_refresh_token_expiry_days: env::var("JWT_REFRESH_TOKEN_EXPIRY_DAYS")
                .unwrap_or_else(|_| "7".into())
                .parse()
                .unwrap_or(7),
            oidc_issuer: env::var("OIDC_ISSUER").ok(),
            oidc_client_id: env::var("OIDC_CLIENT_ID").ok(),
            oidc_client_secret: env::var("OIDC_CLIENT_SECRET").ok(),
            ldap_url: env::var("LDAP_URL").ok(),
            ldap_base_dn: env::var("LDAP_BASE_DN").ok(),
            trivy_url: env::var("TRIVY_URL").ok(),
        })
    }
}
