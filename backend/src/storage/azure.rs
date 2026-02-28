//! Azure Blob Storage backend with SAS URL and Azure RBAC support.
//!
//! Supports two authentication modes:
//!
//! **Shared Key** (access key): Signs requests with HMAC-SHA256. Supports SAS
//! URL redirect downloads.
//!
//! **Azure RBAC** (OAuth2 bearer token): Uses service principal credentials or
//! managed identity to acquire tokens from Azure AD. Requires the identity to
//! have the `Storage Blob Data Contributor` role on the storage account.
//!
//! ## Configuration
//!
//! ```bash
//! STORAGE_BACKEND=azure
//! AZURE_STORAGE_ACCOUNT=myaccount
//! AZURE_STORAGE_CONTAINER=artifacts
//!
//! # Option 1: Shared Key auth
//! AZURE_STORAGE_ACCESS_KEY=base64-encoded-key
//!
//! # Option 2: Service Principal (RBAC)
//! AZURE_TENANT_ID=tenant-uuid
//! AZURE_CLIENT_ID=client-uuid
//! AZURE_CLIENT_SECRET=secret
//!
//! # Option 3: Managed Identity (RBAC, no env vars needed on Azure)
//! # Optionally set AZURE_CLIENT_ID for user-assigned managed identity
//!
//! # SAS redirect downloads (Shared Key only)
//! AZURE_REDIRECT_DOWNLOADS=true
//! AZURE_SAS_EXPIRY=3600  # seconds, default 1 hour
//!
//! # For Artifactory migration:
//! STORAGE_PATH_FORMAT=migration  # native, artifactory, or migration
//! ```

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use bytes::Bytes;
use chrono::{Duration as ChronoDuration, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::error::{AppError, Result};
use crate::storage::{PresignedUrl, PresignedUrlSource, StorageBackend, StoragePathFormat};

type HmacSha256 = Hmac<Sha256>;

/// How the backend authenticates to Azure Blob Storage.
#[derive(Debug, Clone)]
pub(crate) enum AzureAuthMode {
    /// Shared Key: HMAC-SHA256 signed requests + SAS URLs.
    SharedKey {
        /// Base64-decoded storage account key.
        decoded_key: Vec<u8>,
    },
    /// OAuth2 bearer token via service principal or managed identity.
    TokenCredential {
        provider: Arc<TokenCredentialProvider>,
    },
}

/// Azure Blob Storage configuration
#[derive(Debug, Clone)]
pub struct AzureConfig {
    /// Storage account name
    pub account_name: String,
    /// Container name
    pub container_name: String,
    /// Storage account access key (base64 encoded). None triggers RBAC mode.
    pub access_key: Option<String>,
    /// Optional custom endpoint (for Azure Government, China, etc.)
    pub endpoint: Option<String>,
    /// Enable redirect downloads via SAS URLs (requires access key)
    pub redirect_downloads: bool,
    /// SAS URL expiry duration
    pub sas_expiry: Duration,
    /// Storage path format (native, artifactory, or migration)
    pub path_format: StoragePathFormat,
}

impl AzureConfig {
    /// Create config from environment variables.
    ///
    /// If `AZURE_STORAGE_ACCESS_KEY` is set, uses Shared Key auth.
    /// Otherwise, falls back to Azure RBAC (service principal or managed identity).
    pub fn from_env() -> Result<Self> {
        let account_name = std::env::var("AZURE_STORAGE_ACCOUNT")
            .map_err(|_| AppError::Config("AZURE_STORAGE_ACCOUNT not set".to_string()))?;

        let container_name = std::env::var("AZURE_STORAGE_CONTAINER")
            .map_err(|_| AppError::Config("AZURE_STORAGE_CONTAINER not set".to_string()))?;

        let access_key = std::env::var("AZURE_STORAGE_ACCESS_KEY").ok();

        let endpoint = std::env::var("AZURE_STORAGE_ENDPOINT").ok();

        let redirect_downloads = std::env::var("AZURE_REDIRECT_DOWNLOADS")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);

        let sas_expiry = std::env::var("AZURE_SAS_EXPIRY")
            .ok()
            .and_then(|v| v.parse().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(3600));

        let path_format = StoragePathFormat::from_env();

        Ok(Self {
            account_name,
            container_name,
            access_key,
            endpoint,
            redirect_downloads,
            sas_expiry,
            path_format,
        })
    }

    /// Builder: set redirect downloads
    pub fn with_redirect_downloads(mut self, enabled: bool) -> Self {
        self.redirect_downloads = enabled;
        self
    }

    /// Builder: set SAS expiry
    pub fn with_sas_expiry(mut self, expiry: Duration) -> Self {
        self.sas_expiry = expiry;
        self
    }
}

// ---------------------------------------------------------------------------
// OAuth2 token credential provider
// ---------------------------------------------------------------------------

/// A cached OAuth2 access token.
#[derive(Debug, Clone)]
struct CachedToken {
    access_token: String,
    /// When this token expires (with a safety margin applied before storage).
    expires_at: chrono::DateTime<Utc>,
}

/// Acquires and caches OAuth2 bearer tokens for Azure Storage.
///
/// Credential resolution order:
/// 1. Service principal: `AZURE_TENANT_ID` + `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET`
/// 2. Managed identity (IMDS): auto-detected on Azure VMs, AKS, App Service, etc.
///    Set `AZURE_CLIENT_ID` for user-assigned managed identity.
#[derive(Debug)]
pub(crate) struct TokenCredentialProvider {
    client: reqwest::Client,
    credential: TokenCredentialSource,
    cache: RwLock<Option<CachedToken>>,
}

#[derive(Debug, Clone)]
enum TokenCredentialSource {
    ServicePrincipal {
        tenant_id: String,
        client_id: String,
        client_secret: String,
    },
    ManagedIdentity {
        client_id: Option<String>,
    },
}

/// The Azure Storage OAuth2 scope.
const STORAGE_SCOPE: &str = "https://storage.azure.com/.default";

/// Refresh tokens 5 minutes before expiry.
const TOKEN_REFRESH_MARGIN_SECS: i64 = 300;

impl TokenCredentialProvider {
    /// Build a provider from environment variables.
    fn from_env(client: &reqwest::Client) -> Result<Self> {
        let tenant_id = std::env::var("AZURE_TENANT_ID").ok();
        let client_id = std::env::var("AZURE_CLIENT_ID").ok();
        let client_secret = std::env::var("AZURE_CLIENT_SECRET").ok();

        let credential = match (tenant_id, client_id.clone(), client_secret) {
            (Some(t), Some(c), Some(s)) => {
                tracing::info!("Azure RBAC: using service principal credentials");
                TokenCredentialSource::ServicePrincipal {
                    tenant_id: t,
                    client_id: c,
                    client_secret: s,
                }
            }
            _ => {
                if client_id.is_some() {
                    tracing::info!("Azure RBAC: using user-assigned managed identity");
                } else {
                    tracing::info!("Azure RBAC: using system-assigned managed identity");
                }
                TokenCredentialSource::ManagedIdentity {
                    client_id: std::env::var("AZURE_CLIENT_ID").ok(),
                }
            }
        };

        Ok(Self {
            client: client.clone(),
            credential,
            cache: RwLock::new(None),
        })
    }

    /// Get a valid access token, refreshing if needed.
    async fn get_token(&self) -> Result<String> {
        // Fast path: check cache with read lock
        {
            let cache = self.cache.read().await;
            if let Some(ref cached) = *cache {
                if Utc::now() < cached.expires_at {
                    return Ok(cached.access_token.clone());
                }
            }
        }

        // Slow path: acquire write lock and refresh
        let mut cache = self.cache.write().await;
        // Double-check after acquiring write lock
        if let Some(ref cached) = *cache {
            if Utc::now() < cached.expires_at {
                return Ok(cached.access_token.clone());
            }
        }

        let token = self.acquire_token().await?;
        let access_token = token.access_token.clone();
        *cache = Some(token);
        Ok(access_token)
    }

    /// Acquire a fresh token from Azure AD or IMDS.
    async fn acquire_token(&self) -> Result<CachedToken> {
        match &self.credential {
            TokenCredentialSource::ServicePrincipal {
                tenant_id,
                client_id,
                client_secret,
            } => {
                self.acquire_service_principal_token(tenant_id, client_id, client_secret)
                    .await
            }
            TokenCredentialSource::ManagedIdentity { client_id } => {
                self.acquire_managed_identity_token(client_id.as_deref())
                    .await
            }
        }
    }

    async fn acquire_service_principal_token(
        &self,
        tenant_id: &str,
        client_id: &str,
        client_secret: &str,
    ) -> Result<CachedToken> {
        let url = format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            tenant_id
        );

        let response = self
            .client
            .post(&url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", client_id),
                ("client_secret", client_secret),
                ("scope", STORAGE_SCOPE),
            ])
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("Failed to request Azure AD token: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Storage(format!(
                "Azure AD token request failed ({}): {}",
                status, body
            )));
        }

        self.parse_token_response(response).await
    }

    async fn acquire_managed_identity_token(&self, client_id: Option<&str>) -> Result<CachedToken> {
        // Azure IMDS endpoint for managed identity
        let mut url = format!(
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-08-01&resource={}",
            urlencoding::encode("https://storage.azure.com/")
        );
        if let Some(cid) = client_id {
            url.push_str(&format!("&client_id={}", urlencoding::encode(cid)));
        }

        let response = self
            .client
            .get(&url)
            .header("Metadata", "true")
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| {
                AppError::Storage(format!(
                    "Failed to reach Azure IMDS for managed identity token. \
                     Are you running on Azure? Error: {}",
                    e
                ))
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Storage(format!(
                "Azure IMDS token request failed ({}): {}",
                status, body
            )));
        }

        self.parse_token_response(response).await
    }

    async fn parse_token_response(&self, response: reqwest::Response) -> Result<CachedToken> {
        let body: serde_json::Value = response.json().await.map_err(|e| {
            AppError::Storage(format!("Failed to parse Azure token response: {}", e))
        })?;

        let access_token = body["access_token"]
            .as_str()
            .ok_or_else(|| {
                AppError::Storage("Azure token response missing access_token".to_string())
            })?
            .to_string();

        // expires_in is seconds from now. IMDS returns it as a string,
        // Azure AD returns it as a number. Handle both.
        let expires_in_secs: i64 = body["expires_in"]
            .as_i64()
            .or_else(|| body["expires_in"].as_str().and_then(|s| s.parse().ok()))
            .unwrap_or(3600);

        let expires_at =
            Utc::now() + ChronoDuration::seconds(expires_in_secs - TOKEN_REFRESH_MARGIN_SECS);

        tracing::debug!(
            expires_in_secs = expires_in_secs,
            "Acquired Azure RBAC token"
        );

        Ok(CachedToken {
            access_token,
            expires_at,
        })
    }
}

// ---------------------------------------------------------------------------
// Determine auth mode from config - pure function, easily testable
// ---------------------------------------------------------------------------

/// Resolve whether to use SharedKey or RBAC based on the presence of an access key.
pub(crate) fn resolve_auth_mode(access_key: &Option<String>) -> &'static str {
    if access_key.is_some() {
        "shared_key"
    } else {
        "rbac"
    }
}

/// Check whether SAS-based redirect downloads are compatible with the auth mode.
/// SAS tokens require Shared Key; RBAC mode cannot generate them.
pub(crate) fn is_redirect_compatible(
    access_key: &Option<String>,
    redirect_downloads: bool,
) -> bool {
    if redirect_downloads && access_key.is_none() {
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// Azure Blob Storage backend
// ---------------------------------------------------------------------------

/// Azure Blob Storage backend
pub struct AzureBackend {
    config: AzureConfig,
    client: reqwest::Client,
    auth: AzureAuthMode,
    path_format: StoragePathFormat,
}

impl AzureBackend {
    /// Create a new Azure Blob Storage backend
    pub async fn new(config: AzureConfig) -> Result<Self> {
        // Validate HTTPS for custom endpoints
        let allow_http = std::env::var("ALLOW_HTTP_INTEGRATIONS")
            .map(|v| v == "1" || v == "true")
            .unwrap_or(false);
        if let Some(ref endpoint) = config.endpoint {
            if !allow_http && !endpoint.starts_with("https://") {
                tracing::warn!(
                    endpoint = %endpoint,
                    "Azure storage endpoint is not HTTPS. Set ALLOW_HTTP_INTEGRATIONS=1 for local dev."
                );
            }
        }

        // The managed identity IMDS endpoint uses plain HTTP on a link-local address,
        // so the HTTP client must allow non-TLS when RBAC mode might use managed identity.
        let needs_http = allow_http || config.access_key.is_none();

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .https_only(!needs_http)
            .build()
            .map_err(|e| AppError::Storage(format!("Failed to create HTTP client: {}", e)))?;

        // Resolve auth mode
        let auth = match &config.access_key {
            Some(key) => {
                let decoded_key = BASE64.decode(key).map_err(|e| {
                    AppError::Config(format!(
                        "Invalid AZURE_STORAGE_ACCESS_KEY (not valid base64): {}",
                        e
                    ))
                })?;
                AzureAuthMode::SharedKey { decoded_key }
            }
            None => {
                let provider = TokenCredentialProvider::from_env(&client)?;
                AzureAuthMode::TokenCredential {
                    provider: Arc::new(provider),
                }
            }
        };

        // Warn if redirect downloads requested but RBAC mode cannot generate SAS
        if !is_redirect_compatible(&config.access_key, config.redirect_downloads) {
            tracing::warn!(
                "AZURE_REDIRECT_DOWNLOADS is enabled but no AZURE_STORAGE_ACCESS_KEY is set. \
                 SAS URL generation requires an access key. Redirect downloads will be disabled."
            );
        }

        let path_format = config.path_format;

        if path_format != StoragePathFormat::Native {
            tracing::info!(
                path_format = %path_format,
                "Azure storage path format configured"
            );
        }

        let auth_mode_label = resolve_auth_mode(&config.access_key);
        tracing::info!(auth_mode = auth_mode_label, "Azure storage auth mode");

        Ok(Self {
            config,
            client,
            auth,
            path_format,
        })
    }

    /// Try to generate an Artifactory fallback path from a native path
    fn try_artifactory_fallback(&self, key: &str) -> Option<String> {
        let parts: Vec<&str> = key.split('/').collect();
        if parts.len() >= 3 {
            let checksum = parts[parts.len() - 1];
            if checksum.len() == 64 && checksum.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(format!("{}/{}", &checksum[..2], checksum));
            }
        }
        None
    }

    /// Get the base URL for the storage account
    fn base_url(&self) -> String {
        self.config.endpoint.clone().unwrap_or_else(|| {
            format!("https://{}.blob.core.windows.net", self.config.account_name)
        })
    }

    /// Get the full URL for a blob
    fn blob_url(&self, key: &str) -> String {
        format!("{}/{}/{}", self.base_url(), self.config.container_name, key)
    }

    /// Generate a Shared Key authorization header for a request.
    fn shared_key_auth(
        decoded_key: &[u8],
        account_name: &str,
        string_to_sign: &str,
    ) -> Result<String> {
        let mut mac = HmacSha256::new_from_slice(decoded_key)
            .map_err(|e| AppError::Storage(format!("Failed to create HMAC: {}", e)))?;
        mac.update(string_to_sign.as_bytes());
        let signature = BASE64.encode(mac.finalize().into_bytes());
        Ok(format!("SharedKey {}:{}", account_name, signature))
    }

    /// Build an authorized request based on the current auth mode.
    async fn authorized_put(
        &self,
        url: &str,
        key: &str,
        content: &Bytes,
    ) -> Result<reqwest::Response> {
        let date_str = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();

        match &self.auth {
            AzureAuthMode::SharedKey { decoded_key } => {
                let content_length = content.len();
                let string_to_sign = format!(
                    "PUT\n\n\n{}\n\napplication/octet-stream\n\n\n\n\n\n\nx-ms-blob-type:BlockBlob\nx-ms-date:{}\nx-ms-version:2021-06-08\n/{}/{}/{}",
                    content_length,
                    date_str,
                    self.config.account_name,
                    self.config.container_name,
                    key
                );
                let auth_header =
                    Self::shared_key_auth(decoded_key, &self.config.account_name, &string_to_sign)?;

                self.client
                    .put(url)
                    .header("Authorization", auth_header)
                    .header("x-ms-date", &date_str)
                    .header("x-ms-version", "2021-06-08")
                    .header("x-ms-blob-type", "BlockBlob")
                    .header("Content-Type", "application/octet-stream")
                    .header("Content-Length", content.len())
                    .body(content.to_vec())
                    .send()
                    .await
                    .map_err(|e| AppError::Storage(format!("Azure upload failed: {}", e)))
            }
            AzureAuthMode::TokenCredential { provider } => {
                let token = provider.get_token().await?;

                self.client
                    .put(url)
                    .header("Authorization", format!("Bearer {}", token))
                    .header("x-ms-date", &date_str)
                    .header("x-ms-version", "2021-06-08")
                    .header("x-ms-blob-type", "BlockBlob")
                    .header("Content-Type", "application/octet-stream")
                    .header("Content-Length", content.len())
                    .body(content.to_vec())
                    .send()
                    .await
                    .map_err(|e| AppError::Storage(format!("Azure upload failed: {}", e)))
            }
        }
    }

    /// Build an authorized GET request.
    async fn authorized_get(&self, url: &str) -> Result<reqwest::Response> {
        match &self.auth {
            AzureAuthMode::SharedKey { .. } => {
                // SharedKey mode uses SAS URLs (already signed), no extra header needed
                self.client
                    .get(url)
                    .send()
                    .await
                    .map_err(|e| AppError::Storage(format!("Azure download failed: {}", e)))
            }
            AzureAuthMode::TokenCredential { provider } => {
                let token = provider.get_token().await?;
                let date_str = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();

                self.client
                    .get(url)
                    .header("Authorization", format!("Bearer {}", token))
                    .header("x-ms-date", &date_str)
                    .header("x-ms-version", "2021-06-08")
                    .send()
                    .await
                    .map_err(|e| AppError::Storage(format!("Azure download failed: {}", e)))
            }
        }
    }

    /// Build an authorized HEAD request.
    async fn authorized_head(&self, url: &str) -> Result<reqwest::Response> {
        match &self.auth {
            AzureAuthMode::SharedKey { .. } => self
                .client
                .head(url)
                .send()
                .await
                .map_err(|e| AppError::Storage(format!("Azure HEAD request failed: {}", e))),
            AzureAuthMode::TokenCredential { provider } => {
                let token = provider.get_token().await?;
                let date_str = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();

                self.client
                    .head(url)
                    .header("Authorization", format!("Bearer {}", token))
                    .header("x-ms-date", &date_str)
                    .header("x-ms-version", "2021-06-08")
                    .send()
                    .await
                    .map_err(|e| AppError::Storage(format!("Azure HEAD request failed: {}", e)))
            }
        }
    }

    /// Build an authorized DELETE request.
    async fn authorized_delete(&self, url: &str, key: &str) -> Result<reqwest::Response> {
        let date_str = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();

        match &self.auth {
            AzureAuthMode::SharedKey { decoded_key } => {
                let string_to_sign = format!(
                    "DELETE\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:{}\nx-ms-version:2021-06-08\n/{}/{}/{}",
                    date_str, self.config.account_name, self.config.container_name, key
                );
                let auth_header =
                    Self::shared_key_auth(decoded_key, &self.config.account_name, &string_to_sign)?;

                self.client
                    .delete(url)
                    .header("Authorization", auth_header)
                    .header("x-ms-date", &date_str)
                    .header("x-ms-version", "2021-06-08")
                    .send()
                    .await
                    .map_err(|e| AppError::Storage(format!("Azure delete failed: {}", e)))
            }
            AzureAuthMode::TokenCredential { provider } => {
                let token = provider.get_token().await?;

                self.client
                    .delete(url)
                    .header("Authorization", format!("Bearer {}", token))
                    .header("x-ms-date", &date_str)
                    .header("x-ms-version", "2021-06-08")
                    .send()
                    .await
                    .map_err(|e| AppError::Storage(format!("Azure delete failed: {}", e)))
            }
        }
    }

    /// Get the URL to use for a read operation.
    /// SharedKey mode appends a SAS token; RBAC mode uses the bare blob URL
    /// (authorization comes from the bearer token header).
    fn read_url(&self, key: &str, sas_expiry: Duration) -> Result<String> {
        match &self.auth {
            AzureAuthMode::SharedKey { .. } => self.generate_sas_url(key, sas_expiry),
            AzureAuthMode::TokenCredential { .. } => Ok(self.blob_url(key)),
        }
    }

    /// Generate a SAS token for a blob (Shared Key mode only).
    ///
    /// Uses Service SAS with blob resource type.
    fn generate_sas_token(&self, key: &str, expires_in: Duration) -> Result<String> {
        let decoded_key = match &self.auth {
            AzureAuthMode::SharedKey { decoded_key } => decoded_key,
            AzureAuthMode::TokenCredential { .. } => {
                return Err(AppError::Storage(
                    "SAS token generation requires Shared Key auth (AZURE_STORAGE_ACCESS_KEY)"
                        .to_string(),
                ));
            }
        };

        let now = Utc::now();
        let expiry = now + ChronoDuration::seconds(expires_in.as_secs() as i64);

        let signed_version = "2021-06-08";
        let signed_resource = "b";
        let signed_permissions = "r";
        let signed_start = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let signed_expiry = expiry.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let signed_protocol = "https";

        let canonicalized_resource = format!(
            "/blob/{}/{}/{}",
            self.config.account_name, self.config.container_name, key
        );

        // Service SAS string-to-sign for API version 2021-06-08 (16 fields, 15 newlines):
        // sp, st, se, canonicalizedResource, si, sip, spr, sv, sr,
        // snapshotTime, encryptionScope, rscc, rscd, rsce, rscl, rsct
        let string_to_sign = format!(
            "{}\n{}\n{}\n{}\n\n\n{}\n{}\n{}\n\n\n\n\n\n\n",
            signed_permissions,
            signed_start,
            signed_expiry,
            canonicalized_resource,
            // si (signedIdentifier) - empty
            // sip (signedIP) - empty
            signed_protocol,
            signed_version,
            signed_resource,
            // snapshotTime - empty
            // encryptionScope - empty
            // rscc, rscd, rsce, rscl, rsct - empty
        );

        let mut mac = HmacSha256::new_from_slice(decoded_key)
            .map_err(|e| AppError::Storage(format!("Failed to create HMAC: {}", e)))?;
        mac.update(string_to_sign.as_bytes());
        let signature = BASE64.encode(mac.finalize().into_bytes());

        let sas_token = format!(
            "sv={}&st={}&se={}&sr={}&sp={}&spr={}&sig={}",
            urlencoding::encode(signed_version),
            urlencoding::encode(&signed_start),
            urlencoding::encode(&signed_expiry),
            signed_resource,
            signed_permissions,
            signed_protocol,
            urlencoding::encode(&signature),
        );

        Ok(sas_token)
    }

    /// Generate a SAS URL for a blob (Shared Key mode only).
    pub fn generate_sas_url(&self, key: &str, expires_in: Duration) -> Result<String> {
        let sas_token = self.generate_sas_token(key, expires_in)?;
        Ok(format!("{}?{}", self.blob_url(key), sas_token))
    }

    /// Whether this backend is using RBAC (token credential) auth.
    pub fn is_rbac(&self) -> bool {
        matches!(self.auth, AzureAuthMode::TokenCredential { .. })
    }
}

#[async_trait]
impl StorageBackend for AzureBackend {
    async fn put(&self, key: &str, content: Bytes) -> Result<()> {
        let url = self.blob_url(key);
        let response = self.authorized_put(&url, key, &content).await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Storage(format!(
                "Azure upload failed with status {}: {}",
                status, body
            )));
        }

        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Bytes> {
        let url = self.read_url(key, Duration::from_secs(300))?;
        let response = self.authorized_get(&url).await?;

        if !response.status().is_success() {
            let status = response.status();
            if status == reqwest::StatusCode::NOT_FOUND {
                // In migration mode, try Artifactory fallback path
                if self.path_format.has_fallback() {
                    if let Some(fallback_key) = self.try_artifactory_fallback(key) {
                        tracing::debug!(
                            original = %key,
                            fallback = %fallback_key,
                            "Trying Artifactory fallback path"
                        );
                        let fallback_url =
                            self.read_url(&fallback_key, Duration::from_secs(300))?;
                        let fallback_response = self.authorized_get(&fallback_url).await?;

                        if fallback_response.status().is_success() {
                            tracing::info!(
                                key = %key,
                                fallback = %fallback_key,
                                "Found artifact at Artifactory fallback path"
                            );
                            let bytes = fallback_response.bytes().await.map_err(|e| {
                                AppError::Storage(format!("Failed to read response: {}", e))
                            })?;
                            return Ok(bytes);
                        }
                    }
                }
                return Err(AppError::NotFound(format!("Blob not found: {}", key)));
            }
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Storage(format!(
                "Azure download failed with status {}: {}",
                status, body
            )));
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| AppError::Storage(format!("Failed to read response: {}", e)))?;

        Ok(bytes)
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let url = self.read_url(key, Duration::from_secs(60))?;
        let response = self.authorized_head(&url).await?;

        if response.status().is_success() {
            return Ok(true);
        }

        // In migration mode, also check the Artifactory fallback path
        if self.path_format.has_fallback() {
            if let Some(fallback_key) = self.try_artifactory_fallback(key) {
                let fallback_url = self.read_url(&fallback_key, Duration::from_secs(60))?;
                let fallback_response = self.authorized_head(&fallback_url).await.ok();
                if let Some(resp) = fallback_response {
                    if resp.status().is_success() {
                        tracing::debug!(
                            key = %key,
                            fallback = %fallback_key,
                            "Found artifact at Artifactory fallback path"
                        );
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let url = self.blob_url(key);
        let response = self.authorized_delete(&url, key).await?;

        if !response.status().is_success() && response.status() != reqwest::StatusCode::NOT_FOUND {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Storage(format!(
                "Azure delete failed with status {}: {}",
                status, body
            )));
        }

        Ok(())
    }

    fn supports_redirect(&self) -> bool {
        // SAS redirect downloads require Shared Key auth
        self.config.redirect_downloads && !self.is_rbac()
    }

    async fn get_presigned_url(
        &self,
        key: &str,
        expires_in: Duration,
    ) -> Result<Option<PresignedUrl>> {
        if !self.supports_redirect() {
            return Ok(None);
        }

        let url = self.generate_sas_url(key, expires_in)?;

        tracing::debug!(
            key = %key,
            expires_in = ?expires_in,
            "Generated Azure SAS URL"
        );

        Ok(Some(PresignedUrl {
            url,
            expires_in,
            source: PresignedUrlSource::Azure,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> AzureConfig {
        AzureConfig {
            account_name: "testaccount".to_string(),
            container_name: "testcontainer".to_string(),
            // This is a fake key for testing - 64 bytes base64 encoded
            access_key: Some(
                "dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleXRlc3RrZXk="
                    .to_string(),
            ),
            endpoint: None,
            redirect_downloads: true,
            sas_expiry: Duration::from_secs(3600),
            path_format: StoragePathFormat::Native,
        }
    }

    fn create_rbac_config() -> AzureConfig {
        AzureConfig {
            account_name: "testaccount".to_string(),
            container_name: "testcontainer".to_string(),
            access_key: None,
            endpoint: None,
            redirect_downloads: false,
            sas_expiry: Duration::from_secs(3600),
            path_format: StoragePathFormat::Native,
        }
    }

    async fn create_test_backend() -> AzureBackend {
        AzureBackend::new(create_test_config()).await.unwrap()
    }

    // ── Auth mode resolution (pure functions) ────────────────────────────

    #[test]
    fn test_resolve_auth_mode_shared_key() {
        let key = Some("somekey".to_string());
        assert_eq!(resolve_auth_mode(&key), "shared_key");
    }

    #[test]
    fn test_resolve_auth_mode_rbac() {
        let key: Option<String> = None;
        assert_eq!(resolve_auth_mode(&key), "rbac");
    }

    #[test]
    fn test_redirect_compatible_shared_key_enabled() {
        let key = Some("key".to_string());
        assert!(is_redirect_compatible(&key, true));
    }

    #[test]
    fn test_redirect_compatible_shared_key_disabled() {
        let key = Some("key".to_string());
        assert!(is_redirect_compatible(&key, false));
    }

    #[test]
    fn test_redirect_incompatible_rbac_with_redirect() {
        let key: Option<String> = None;
        assert!(!is_redirect_compatible(&key, true));
    }

    #[test]
    fn test_redirect_compatible_rbac_without_redirect() {
        let key: Option<String> = None;
        assert!(is_redirect_compatible(&key, false));
    }

    // ── Config ───────────────────────────────────────────────────────────

    #[test]
    fn test_config_access_key_optional() {
        let config = create_rbac_config();
        assert!(config.access_key.is_none());
    }

    #[test]
    fn test_config_access_key_present() {
        let config = create_test_config();
        assert!(config.access_key.is_some());
    }

    // ── Backend creation ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_azure_backend_creation() {
        let config = create_test_config();
        let backend = AzureBackend::new(config).await;
        assert!(backend.is_ok());
    }

    #[tokio::test]
    async fn test_azure_backend_shared_key_mode() {
        let backend = create_test_backend().await;
        assert!(!backend.is_rbac());
    }

    #[test]
    fn test_invalid_access_key() {
        let mut config = create_test_config();
        config.access_key = Some("not-valid-base64!!!".to_string());

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(AzureBackend::new(config));
        assert!(result.is_err());
    }

    // ── SAS URL generation (Shared Key only) ─────────────────────────────

    #[tokio::test]
    async fn test_sas_url_generation() {
        let backend = create_test_backend().await;

        let url = backend
            .generate_sas_url("test/artifact.txt", Duration::from_secs(3600))
            .unwrap();

        assert!(url.contains("testaccount.blob.core.windows.net"));
        assert!(url.contains("testcontainer"));
        assert!(url.contains("test/artifact.txt"));
        assert!(url.contains("sv="), "Missing signed version");
        assert!(url.contains("st="), "Missing signed start");
        assert!(url.contains("se="), "Missing signed expiry");
        assert!(url.contains("sr=b"), "Missing signed resource (blob)");
        assert!(url.contains("sp=r"), "Missing signed permissions");
        assert!(url.contains("spr=https"), "Missing signed protocol");
        assert!(url.contains("sig="), "Missing signature");
    }

    #[tokio::test]
    async fn test_sas_token_generation() {
        let backend = create_test_backend().await;

        let token = backend
            .generate_sas_token("test/file.txt", Duration::from_secs(3600))
            .unwrap();
        assert!(token.contains("sv="));
        assert!(token.contains("se="));
        assert!(token.contains("sig="));
        assert!(token.contains("sp=r"));
        assert!(token.contains("sr=b"));
        assert!(token.contains("spr=https"));
    }

    #[tokio::test]
    async fn test_sas_url_different_keys() {
        let backend = create_test_backend().await;

        let url1 = backend
            .generate_sas_url("file1.txt", Duration::from_secs(3600))
            .unwrap();
        let url2 = backend
            .generate_sas_url("file2.txt", Duration::from_secs(3600))
            .unwrap();
        assert_ne!(url1, url2);
    }

    #[tokio::test]
    async fn test_sas_url_contains_blob_url() {
        let backend = create_test_backend().await;

        let url = backend
            .generate_sas_url("path/to/blob.dat", Duration::from_secs(300))
            .unwrap();
        assert!(url.starts_with(
            "https://testaccount.blob.core.windows.net/testcontainer/path/to/blob.dat?"
        ));
    }

    // ── Redirect support ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_supports_redirect_shared_key() {
        let mut config = create_test_config();
        config.redirect_downloads = false;

        let backend = AzureBackend::new(config.clone()).await.unwrap();
        assert!(!backend.supports_redirect());

        let config_with_redirect = config.with_redirect_downloads(true);
        let backend = AzureBackend::new(config_with_redirect).await.unwrap();
        assert!(backend.supports_redirect());
    }

    #[tokio::test]
    async fn test_get_presigned_url_returns_none_when_disabled() {
        let config = create_test_config().with_redirect_downloads(false);
        let backend = AzureBackend::new(config).await.unwrap();

        let result = backend
            .get_presigned_url("test.txt", Duration::from_secs(3600))
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_get_presigned_url_returns_url_when_enabled() {
        let config = create_test_config().with_redirect_downloads(true);
        let backend = AzureBackend::new(config).await.unwrap();

        let result = backend
            .get_presigned_url("test.txt", Duration::from_secs(3600))
            .await
            .unwrap();
        assert!(result.is_some());

        let presigned = result.unwrap();
        assert_eq!(presigned.source, PresignedUrlSource::Azure);
        assert!(presigned.url.contains("sig="));
    }

    #[tokio::test]
    async fn test_presigned_url_expiry_preserved() {
        let config = create_test_config().with_redirect_downloads(true);
        let backend = AzureBackend::new(config).await.unwrap();

        let expires = Duration::from_secs(1800);
        let presigned = backend
            .get_presigned_url("test.txt", expires)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(presigned.expires_in, expires);
    }

    // ── URL construction ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_blob_url_format() {
        let backend = create_test_backend().await;

        assert_eq!(
            backend.blob_url("path/to/artifact.jar"),
            "https://testaccount.blob.core.windows.net/testcontainer/path/to/artifact.jar"
        );
    }

    #[tokio::test]
    async fn test_custom_endpoint() {
        let mut config = create_test_config();
        config.endpoint = Some("https://custom.blob.endpoint.com".to_string());

        let backend = AzureBackend::new(config).await.unwrap();
        let url = backend.blob_url("test.txt");
        assert!(url.starts_with("https://custom.blob.endpoint.com"));
    }

    #[tokio::test]
    async fn test_base_url_default() {
        let backend = create_test_backend().await;
        assert_eq!(
            backend.base_url(),
            "https://testaccount.blob.core.windows.net"
        );
    }

    #[tokio::test]
    async fn test_base_url_custom_endpoint() {
        let mut config = create_test_config();
        config.endpoint = Some("https://government.blob.core.usgovcloudapi.net".to_string());
        let backend = AzureBackend::new(config).await.unwrap();
        assert_eq!(
            backend.base_url(),
            "https://government.blob.core.usgovcloudapi.net"
        );
    }

    #[tokio::test]
    async fn test_blob_url_nested_path() {
        let backend = create_test_backend().await;
        assert_eq!(
            backend.blob_url("a/b/c/d.jar"),
            "https://testaccount.blob.core.windows.net/testcontainer/a/b/c/d.jar"
        );
    }

    #[tokio::test]
    async fn test_read_url_shared_key_uses_sas() {
        let backend = create_test_backend().await;
        let url = backend
            .read_url("test.txt", Duration::from_secs(300))
            .unwrap();
        assert!(
            url.contains("sig="),
            "SharedKey read URL should contain SAS signature"
        );
    }

    // ── Artifactory fallback ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_try_artifactory_fallback_valid_checksum() {
        let backend = create_test_backend().await;

        let key = "repos/maven/abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let fallback = backend.try_artifactory_fallback(key);
        assert_eq!(
            fallback.unwrap(),
            "ab/abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        );
    }

    #[tokio::test]
    async fn test_try_artifactory_fallback_rejected_inputs() {
        let backend = create_test_backend().await;

        // Not hex
        assert!(backend
            .try_artifactory_fallback(
                "repos/maven/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
            )
            .is_none());
        // Too short
        assert!(backend
            .try_artifactory_fallback("repos/maven/short")
            .is_none());
        // Too few path parts (only 2)
        assert!(backend
            .try_artifactory_fallback(
                "repos/abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
            )
            .is_none());
    }

    // ── Config builders ──────────────────────────────────────────────────

    #[test]
    fn test_azure_config_builder_redirect_downloads() {
        let config = create_test_config();
        assert!(config.redirect_downloads);
        let config = config.with_redirect_downloads(false);
        assert!(!config.redirect_downloads);
    }

    #[test]
    fn test_azure_config_builder_sas_expiry() {
        let config = create_test_config();
        let config = config.with_sas_expiry(Duration::from_secs(7200));
        assert_eq!(config.sas_expiry, Duration::from_secs(7200));
    }

    #[test]
    fn test_azure_config_clone() {
        let config = create_test_config();
        let cloned = config.clone();
        assert_eq!(cloned.account_name, "testaccount");
        assert_eq!(cloned.container_name, "testcontainer");
        assert_eq!(cloned.access_key, config.access_key);
        assert_eq!(cloned.redirect_downloads, config.redirect_downloads);
    }

    // ── Token credential provider ────────────────────────────────────────

    #[test]
    fn test_cached_token_expiry_check() {
        let fresh = CachedToken {
            access_token: "tok".to_string(),
            expires_at: Utc::now() + ChronoDuration::hours(1),
        };
        assert!(Utc::now() < fresh.expires_at);

        let expired = CachedToken {
            access_token: "tok".to_string(),
            expires_at: Utc::now() - ChronoDuration::hours(1),
        };
        assert!(Utc::now() >= expired.expires_at);
    }

    #[test]
    fn test_token_credential_source_service_principal_debug() {
        let source = TokenCredentialSource::ServicePrincipal {
            tenant_id: "t".to_string(),
            client_id: "c".to_string(),
            client_secret: "s".to_string(),
        };
        let dbg = format!("{:?}", source);
        assert!(dbg.contains("ServicePrincipal"));
    }

    #[test]
    fn test_token_credential_source_managed_identity_debug() {
        let source = TokenCredentialSource::ManagedIdentity {
            client_id: Some("cid".to_string()),
        };
        let dbg = format!("{:?}", source);
        assert!(dbg.contains("ManagedIdentity"));

        let system = TokenCredentialSource::ManagedIdentity { client_id: None };
        let dbg = format!("{:?}", system);
        assert!(dbg.contains("ManagedIdentity"));
    }

    #[test]
    fn test_is_rbac_shared_key() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let backend = rt.block_on(create_test_backend());
        assert!(!backend.is_rbac());
    }

    #[test]
    fn test_token_refresh_margin() {
        // Verify the margin constant is 5 minutes
        assert_eq!(TOKEN_REFRESH_MARGIN_SECS, 300);
    }

    #[test]
    fn test_storage_scope() {
        assert_eq!(STORAGE_SCOPE, "https://storage.azure.com/.default");
    }
}
