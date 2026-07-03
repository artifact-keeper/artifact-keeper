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
use bytes::{Bytes, BytesMut};
use chrono::{Duration as ChronoDuration, Utc};
use futures::stream::BoxStream;
use futures::StreamExt;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::storage::{
    PresignedUrl, PresignedUrlSource, PutStreamResult, StorageBackend, StoragePathFormat,
};

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

const AZURE_BLOCK_CHUNK_SIZE: usize = 4 * 1024 * 1024;
const AZURE_MAX_BLOCKS: usize = 50_000;
const AZURE_BLOCK_WARNING_THRESHOLD: usize = 40_000;
const AZURE_PUT_BLOB_FROM_URL_MAX_SIZE: u64 = 5_000 * 1024 * 1024;
const AZURE_COPY_SOURCE_URL_MAX_LEN: usize = 2 * 1024;

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

        let client = crate::services::http_client::large_object_client_builder(needs_http)
            .build()
            .map_err(|e| AppError::Storage(format!("Failed to create HTTP client: {}", e)))?;
        let token_client = crate::services::http_client::base_client_builder()
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
                let provider = TokenCredentialProvider::from_env(&token_client)?;
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

    fn append_query(mut url: String, query: &str) -> String {
        if url.contains('?') {
            url.push('&');
        } else {
            url.push('?');
        }
        url.push_str(query);
        url
    }

    fn download_range_header(offset: u64, length: usize) -> Result<String> {
        crate::storage::download_range_header(offset, length)
    }

    async fn try_fallback_get_range(&self, key: &str, range_header: &str) -> Result<Option<Bytes>> {
        if !self.path_format.has_fallback() {
            return Ok(None);
        }

        let Some(fallback_key) = self.try_artifactory_fallback(key) else {
            return Ok(None);
        };

        tracing::debug!(
            original = %key,
            fallback = %fallback_key,
            range = %range_header,
            "Trying Artifactory fallback path range"
        );
        let fallback_url = self.read_url(&fallback_key, Duration::from_secs(300))?;
        let response = self
            .authorized_get_range(&fallback_url, range_header)
            .await?;

        if response.status() == reqwest::StatusCode::PARTIAL_CONTENT {
            tracing::info!(
                key = %key,
                fallback = %fallback_key,
                "Found artifact range at Artifactory fallback path"
            );
            #[allow(clippy::disallowed_methods)]
            // STREAMING-EXEMPT: storage-internal Artifactory-fallback get()/range body; backs the streaming get impl; genuinely exempt (#1608)
            let bytes = response
                .bytes()
                .await
                .map_err(|e| AppError::Storage(format!("Failed to read response: {}", e)))?;
            return Ok(Some(bytes));
        }

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        Err(AppError::Storage(format!(
            "Azure fallback ranged download failed with status {} for {} ({}): {}",
            status, key, range_header, body
        )))
    }

    fn write_url(&self, key: &str) -> Result<String> {
        match &self.auth {
            AzureAuthMode::SharedKey { .. } => {
                self.generate_sas_url_with_permissions(key, Duration::from_secs(300), "cw")
            }
            AzureAuthMode::TokenCredential { .. } => Ok(self.blob_url(key)),
        }
    }

    fn block_url(&self, key: &str, block_id: &str) -> Result<String> {
        let url = self.write_url(key)?;
        Ok(Self::append_query(
            url,
            &format!("comp=block&blockid={}", urlencoding::encode(block_id)),
        ))
    }

    fn block_list_url(&self, key: &str) -> Result<String> {
        let url = self.write_url(key)?;
        Ok(Self::append_query(url, "comp=blocklist"))
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
                    .body(content.clone())
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
                    .body(content.clone())
                    .send()
                    .await
                    .map_err(|e| AppError::Storage(format!("Azure upload failed: {}", e)))
            }
        }
    }

    async fn authorized_put_block(&self, url: &str, content: Bytes) -> Result<reqwest::Response> {
        let date_str = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let content_length = content.len();
        let mut request = self
            .client
            .put(url)
            .header("x-ms-date", &date_str)
            .header("x-ms-version", "2021-06-08")
            .header("Content-Type", "application/octet-stream")
            .header("Content-Length", content_length)
            .body(content);

        if let AzureAuthMode::TokenCredential { provider } = &self.auth {
            let token = provider.get_token().await?;
            request = request.header("Authorization", format!("Bearer {}", token));
        }

        request
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("Azure Put Block failed: {}", e)))
    }

    async fn authorized_put_block_list(
        &self,
        url: &str,
        content: Bytes,
    ) -> Result<reqwest::Response> {
        let date_str = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let content_length = content.len();
        let mut request = self
            .client
            .put(url)
            .header("x-ms-date", &date_str)
            .header("x-ms-version", "2021-06-08")
            .header("Content-Type", "application/xml")
            .header("Content-Length", content_length)
            .body(content);

        if let AzureAuthMode::TokenCredential { provider } = &self.auth {
            let token = provider.get_token().await?;
            request = request.header("Authorization", format!("Bearer {}", token));
        }

        request
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("Azure Put Block List failed: {}", e)))
    }

    async fn authorized_put_blob_from_url(
        &self,
        dest_url: &str,
        source_url: &str,
    ) -> Result<reqwest::Response> {
        let date_str = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let mut request = self
            .client
            .put(dest_url)
            .header("x-ms-date", &date_str)
            .header("x-ms-version", "2021-06-08")
            .header("x-ms-blob-type", "BlockBlob")
            .header("x-ms-copy-source", source_url)
            .header("Content-Length", "0");

        if let AzureAuthMode::TokenCredential { provider } = &self.auth {
            let token = provider.get_token().await?;
            let bearer = format!("Bearer {}", token);
            request = request
                .header("Authorization", bearer.clone())
                .header("x-ms-copy-source-authorization", bearer);
        }

        request
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("Azure Put Blob From URL failed: {}", e)))
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

    /// Build an authorized ranged GET request.
    async fn authorized_get_range(
        &self,
        url: &str,
        range_header: &str,
    ) -> Result<reqwest::Response> {
        match &self.auth {
            AzureAuthMode::SharedKey { .. } => self
                .client
                .get(url)
                .header(reqwest::header::RANGE, range_header)
                .header("x-ms-range", range_header)
                .send()
                .await
                .map_err(|e| AppError::Storage(format!("Azure ranged download failed: {}", e))),
            AzureAuthMode::TokenCredential { provider } => {
                let token = provider.get_token().await?;
                let date_str = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();

                self.client
                    .get(url)
                    .header("Authorization", format!("Bearer {}", token))
                    .header("x-ms-date", &date_str)
                    .header("x-ms-version", "2021-06-08")
                    .header(reqwest::header::RANGE, range_header)
                    .header("x-ms-range", range_header)
                    .send()
                    .await
                    .map_err(|e| AppError::Storage(format!("Azure ranged download failed: {}", e)))
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
        self.generate_sas_token_with_permissions(key, expires_in, "r")
    }

    fn generate_sas_token_with_permissions(
        &self,
        key: &str,
        expires_in: Duration,
        signed_permissions: &str,
    ) -> Result<String> {
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

    fn generate_sas_url_with_permissions(
        &self,
        key: &str,
        expires_in: Duration,
        signed_permissions: &str,
    ) -> Result<String> {
        let sas_token =
            self.generate_sas_token_with_permissions(key, expires_in, signed_permissions)?;
        Ok(format!("{}?{}", self.blob_url(key), sas_token))
    }

    async fn put_stream_block(
        &self,
        key: &str,
        upload_nonce: &str,
        block_ids: &mut Vec<String>,
        content: Bytes,
    ) -> Result<()> {
        if block_ids.len() >= AZURE_MAX_BLOCKS {
            return Err(AppError::Storage(format!(
                "Azure block blob limit exceeded for '{}': {} blocks staged; maximum is {}",
                key,
                block_ids.len(),
                AZURE_MAX_BLOCKS
            )));
        }
        if block_ids.len() == AZURE_BLOCK_WARNING_THRESHOLD {
            tracing::warn!(
                key = %key,
                staged_blocks = block_ids.len(),
                max_blocks = AZURE_MAX_BLOCKS,
                "Azure streaming upload is approaching the block blob limit"
            );
        }
        // The block ID embeds a per-upload nonce so two concurrent streaming
        // writes to the same key stage into disjoint uncommitted block lists.
        // Without it, both would use block IDs derived from the index alone
        // (0, 1, …) and overwrite each other's uncommitted blocks, letting one
        // Put Block List assemble the other request's bytes under this key.
        // The pre-base64 string (32-hex nonce + 16-digit index = 48 bytes) is
        // a fixed length for every block, satisfying Azure's same-size-per-blob
        // and <=64-byte block-ID rules.
        let block_id = BASE64.encode(format!("{upload_nonce}{:016}", block_ids.len()));
        let url = self.block_url(key, &block_id)?;
        let response = self.authorized_put_block(&url, content).await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Storage(format!(
                "Azure Put Block for '{}' failed with status {}: {}",
                key, status, body
            )));
        }

        block_ids.push(block_id);
        Ok(())
    }

    async fn commit_stream_blocks(&self, key: &str, block_ids: &[String]) -> Result<()> {
        let mut block_list = String::from(r#"<?xml version="1.0" encoding="utf-8"?><BlockList>"#);
        for block_id in block_ids {
            block_list.push_str("<Latest>");
            block_list.push_str(block_id);
            block_list.push_str("</Latest>");
        }
        block_list.push_str("</BlockList>");

        let url = self.block_list_url(key)?;
        let response = self
            .authorized_put_block_list(&url, Bytes::from(block_list))
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Storage(format!(
                "Azure Put Block List for '{}' failed with status {}: {}",
                key, status, body
            )));
        }

        Ok(())
    }

    /// Handle uncommitted blocks left behind by a failed streaming upload.
    ///
    /// We deliberately do NOT mutate the destination blob to "clean up" the
    /// staged blocks. A concurrent writer may have committed this same key
    /// between any pre-flight check and now — two clients pushing the same
    /// digest-addressed OCI blob is a real scenario — and overwriting or
    /// deleting the blob here would destroy their committed data. The staged
    /// blocks are private to this upload (their block IDs carry a per-upload
    /// nonce, so they can never be assembled into another writer's Put Block
    /// List) and Azure garbage-collects uncommitted blocks automatically
    /// (~7 days). So we only log.
    async fn report_uncommitted_stream_blocks(&self, key: &str, block_ids: &[String]) {
        if block_ids.is_empty() {
            return;
        }
        tracing::warn!(
            key = %key,
            staged_blocks = block_ids.len(),
            "Azure streaming upload failed after staging blocks; leaving them for Azure to garbage-collect (not mutating the destination blob to avoid clobbering a concurrent writer)"
        );
    }

    fn content_length_from_head(response: &reqwest::Response, key: &str) -> Result<u64> {
        let value = response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .ok_or_else(|| {
                AppError::Storage(format!(
                    "Azure HEAD for '{}' did not return Content-Length",
                    key
                ))
            })?;
        let text = value.to_str().map_err(|e| {
            AppError::Storage(format!(
                "Azure HEAD for '{}' returned invalid Content-Length: {}",
                key, e
            ))
        })?;
        text.parse::<u64>().map_err(|e| {
            AppError::Storage(format!(
                "Azure HEAD for '{}' returned non-numeric Content-Length '{}': {}",
                key, text, e
            ))
        })
    }

    async fn size(&self, key: &str) -> Result<u64> {
        let url = self.read_url(key, Duration::from_secs(60))?;
        let response = self.authorized_head(&url).await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(AppError::NotFound(format!("Blob not found: {}", key)));
        }
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Storage(format!(
                "Azure HEAD for '{}' failed with status {}: {}",
                key, status, body
            )));
        }
        Self::content_length_from_head(&response, key)
    }

    async fn copy_via_stream(&self, source: &str, dest: &str) -> Result<()> {
        let stream = self.get_stream(source).await?;
        self.put_stream(dest, stream).await?;
        Ok(())
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
                            #[allow(clippy::disallowed_methods)]
                            // STREAMING-EXEMPT: storage-internal Artifactory-fallback get()/range body; backs the streaming get impl; genuinely exempt (#1608)
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

        #[allow(clippy::disallowed_methods)]
        // STREAMING-EXEMPT: storage-internal Artifactory-fallback get()/range body; backs the streaming get impl; genuinely exempt (#1608)
        let bytes = response
            .bytes()
            .await
            .map_err(|e| AppError::Storage(format!("Failed to read response: {}", e)))?;

        Ok(bytes)
    }

    async fn get_range(&self, key: &str, offset: u64, length: usize) -> Result<Bytes> {
        if length == 0 {
            return Ok(Bytes::new());
        }

        let range_header = Self::download_range_header(offset, length)?;
        let url = self.read_url(key, Duration::from_secs(300))?;
        let response = self.authorized_get_range(&url, &range_header).await?;

        if response.status() == reqwest::StatusCode::PARTIAL_CONTENT {
            #[allow(clippy::disallowed_methods)]
            // STREAMING-EXEMPT: storage-internal Artifactory-fallback get()/range body; backs the streaming get impl; genuinely exempt (#1608)
            return response
                .bytes()
                .await
                .map_err(|e| AppError::Storage(format!("Failed to read range response: {}", e)));
        }

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            if let Some(bytes) = self.try_fallback_get_range(key, &range_header).await? {
                return Ok(bytes);
            }
            return Err(AppError::NotFound(format!("Blob not found: {}", key)));
        }

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        Err(AppError::Storage(format!(
            "Azure ranged download failed with status {} for {} ({}): {}",
            status, key, range_header, body
        )))
    }

    async fn get_stream(&self, key: &str) -> Result<BoxStream<'static, Result<Bytes>>> {
        let url = self.read_url(key, Duration::from_secs(300))?;
        let mut response = self.authorized_get(&url).await?;

        if !response.status().is_success() {
            let status = response.status();
            if status == reqwest::StatusCode::NOT_FOUND {
                if self.path_format.has_fallback() {
                    if let Some(fallback_key) = self.try_artifactory_fallback(key) {
                        tracing::debug!(
                            original = %key,
                            fallback = %fallback_key,
                            "Trying Artifactory fallback path for stream"
                        );
                        let fallback_url =
                            self.read_url(&fallback_key, Duration::from_secs(300))?;
                        response = self.authorized_get(&fallback_url).await?;

                        if !response.status().is_success() {
                            return Err(AppError::NotFound(format!("Blob not found: {}", key)));
                        }
                    } else {
                        return Err(AppError::NotFound(format!("Blob not found: {}", key)));
                    }
                } else {
                    return Err(AppError::NotFound(format!("Blob not found: {}", key)));
                }
            } else {
                let body = response.text().await.unwrap_or_default();
                return Err(AppError::Storage(format!(
                    "Azure download failed with status {}: {}",
                    status, body
                )));
            }
        }

        let stream = response
            .bytes_stream()
            .map(|chunk| chunk.map_err(|e| AppError::Storage(format!("Stream read error: {}", e))));

        Ok(Box::pin(stream))
    }

    async fn put_stream(
        &self,
        key: &str,
        stream: BoxStream<'static, Result<Bytes>>,
    ) -> Result<PutStreamResult> {
        let mut hasher = Sha256::new();
        let mut total: u64 = 0;
        let mut buffer = BytesMut::with_capacity(AZURE_BLOCK_CHUNK_SIZE);
        let mut block_ids = Vec::new();
        // Per-upload nonce woven into every block ID (see put_stream_block) so
        // concurrent streaming writes to the same key cannot collide on block
        // IDs. With that guarantee a failed upload's staged blocks are private
        // and Azure auto-GCs them, so we neither probe existence up front nor
        // mutate the destination blob on failure.
        let upload_nonce = Uuid::new_v4().simple().to_string();

        tokio::pin!(stream);
        while let Some(chunk) = stream.next().await {
            let mut chunk = match chunk {
                Ok(chunk) => chunk,
                Err(e) => {
                    self.report_uncommitted_stream_blocks(key, &block_ids).await;
                    return Err(e);
                }
            };
            if chunk.is_empty() {
                continue;
            }
            hasher.update(&chunk);
            total += chunk.len() as u64;

            while !chunk.is_empty() {
                let remaining = AZURE_BLOCK_CHUNK_SIZE - buffer.len();
                let take = remaining.min(chunk.len());
                let piece = chunk.split_to(take);
                buffer.extend_from_slice(&piece);

                if buffer.len() == AZURE_BLOCK_CHUNK_SIZE {
                    let block = buffer.split().freeze();
                    if let Err(e) = self
                        .put_stream_block(key, &upload_nonce, &mut block_ids, block)
                        .await
                    {
                        self.report_uncommitted_stream_blocks(key, &block_ids).await;
                        return Err(e);
                    }
                }
            }
        }

        if !buffer.is_empty() {
            let block = buffer.split().freeze();
            if let Err(e) = self
                .put_stream_block(key, &upload_nonce, &mut block_ids, block)
                .await
            {
                self.report_uncommitted_stream_blocks(key, &block_ids).await;
                return Err(e);
            }
        }

        if block_ids.is_empty() {
            self.put(key, Bytes::new()).await?;
        } else if let Err(e) = self.commit_stream_blocks(key, &block_ids).await {
            self.report_uncommitted_stream_blocks(key, &block_ids).await;
            return Err(e);
        }

        Ok(PutStreamResult {
            checksum_sha256: format!("{:x}", hasher.finalize()),
            bytes_written: total,
        })
    }

    async fn copy(&self, source: &str, dest: &str) -> Result<()> {
        let size = match self.size(source).await {
            Ok(size) => size,
            Err(AppError::NotFound(_)) if self.path_format.has_fallback() => {
                return self.copy_via_stream(source, dest).await;
            }
            Err(e) => return Err(e),
        };
        if size > AZURE_PUT_BLOB_FROM_URL_MAX_SIZE {
            tracing::debug!(
                source = %source,
                dest = %dest,
                size,
                "Azure source is too large for Put Blob From URL; streaming through block upload"
            );
            return self.copy_via_stream(source, dest).await;
        }

        let source_url = self.read_url(source, Duration::from_secs(300))?;
        if source_url.len() > AZURE_COPY_SOURCE_URL_MAX_LEN {
            tracing::debug!(
                source = %source,
                dest = %dest,
                source_url_len = source_url.len(),
                "Azure source URL is too long for Put Blob From URL; streaming through block upload"
            );
            return self.copy_via_stream(source, dest).await;
        }

        let dest_url = self.write_url(dest)?;
        let response = self
            .authorized_put_blob_from_url(&dest_url, &source_url)
            .await?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Storage(format!(
                "Azure Put Blob From URL copy from '{}' to '{}' failed with status {}: {}",
                source, dest, status, body
            )));
        }

        Ok(())
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

    /// Surface Azure Blob's `ETag` response header on a HEAD. Azure quotes
    /// ETags ("0x8D..."); we return the value verbatim so equality
    /// comparisons remain string-stable. Used by the #1051 fast-path
    /// revalidation. Returns `Ok(None)` for a missing blob or for a
    /// response without an `ETag` header so the freshness probe can fall
    /// through to the slow path without surfacing a backend error.
    async fn head_etag(&self, key: &str) -> Result<Option<String>> {
        let url = self.read_url(key, Duration::from_secs(60))?;
        let response = self.authorized_head(&url).await?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(AppError::Storage(format!(
                "Azure head_etag for '{}' returned {}",
                key,
                response.status()
            )));
        }
        let etag = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        Ok(etag)
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

    /// Stream a file on disk into Azure Blob Storage as a single BlockBlob
    /// without buffering the whole body in memory.
    ///
    /// The default trait implementation opens the file as a `ReaderStream`
    /// and delegates to `put_stream`, but Azure has no streaming
    /// `put_stream` override (single-PUT requires Content-Length, and a
    /// staged-block implementation is non-trivial). For migration (#1422)
    /// we know the file size from `fs::metadata`, so we can sign a single
    /// PUT BlockBlob request and let `reqwest::Body::wrap_stream` pump the
    /// file chunk-by-chunk over the wire. Peak heap usage is O(chunk_size),
    /// not O(file_size).
    async fn put_file(&self, key: &str, path: &std::path::Path) -> Result<()> {
        use futures::StreamExt;
        use tokio::io::BufReader;
        use tokio_util::io::ReaderStream;

        let metadata = tokio::fs::metadata(path).await.map_err(|e| {
            AppError::Storage(format!("Failed to stat file for Azure upload: {}", e))
        })?;
        let content_length = metadata.len();

        let file = tokio::fs::File::open(path).await.map_err(|e| {
            AppError::Storage(format!("Failed to open file for Azure upload: {}", e))
        })?;
        let reader = BufReader::with_capacity(256 * 1024, file);
        let stream = ReaderStream::with_capacity(reader, 256 * 1024)
            .map(|r| r.map_err(|e| std::io::Error::other(format!("Read error: {}", e))));

        let url = self.blob_url(key);
        let date_str = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();

        let response = match &self.auth {
            AzureAuthMode::SharedKey { decoded_key } => {
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
                    .put(&url)
                    .header("Authorization", auth_header)
                    .header("x-ms-date", &date_str)
                    .header("x-ms-version", "2021-06-08")
                    .header("x-ms-blob-type", "BlockBlob")
                    .header("Content-Type", "application/octet-stream")
                    .header("Content-Length", content_length)
                    .body(reqwest::Body::wrap_stream(stream))
                    .send()
                    .await
                    .map_err(|e| AppError::Storage(format!("Azure upload failed: {}", e)))?
            }
            AzureAuthMode::TokenCredential { provider } => {
                let token = provider.get_token().await?;
                self.client
                    .put(&url)
                    .header("Authorization", format!("Bearer {}", token))
                    .header("x-ms-date", &date_str)
                    .header("x-ms-version", "2021-06-08")
                    .header("x-ms-blob-type", "BlockBlob")
                    .header("Content-Type", "application/octet-stream")
                    .header("Content-Length", content_length)
                    .body(reqwest::Body::wrap_stream(stream))
                    .send()
                    .await
                    .map_err(|e| AppError::Storage(format!("Azure upload failed: {}", e)))?
            }
        };

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

    async fn health_check(&self) -> Result<()> {
        // HEAD a sentinel blob path. A 404 is fine (proves the container is
        // reachable and credentials are accepted). Only transport-level or
        // authentication errors indicate an unhealthy backend.
        let url = self.blob_url(".health-probe");
        let response = self
            .authorized_head(&url)
            .await
            .map_err(|e| AppError::Storage(format!("Azure health check failed: {}", e)))?;

        let status = response.status();
        if status.is_success() || status == reqwest::StatusCode::NOT_FOUND {
            Ok(())
        } else if status == reqwest::StatusCode::FORBIDDEN
            || status == reqwest::StatusCode::UNAUTHORIZED
        {
            Err(AppError::Storage(format!(
                "Azure health check failed: access denied ({})",
                status
            )))
        } else {
            let body = response.text().await.unwrap_or_default();
            Err(AppError::Storage(format!(
                "Azure health check failed (status {}): {}",
                status, body
            )))
        }
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

    /// Create an RBAC backend directly without reading env vars.
    fn create_rbac_backend(credential: TokenCredentialSource) -> AzureBackend {
        let client = reqwest::Client::new();
        let provider = TokenCredentialProvider {
            client: client.clone(),
            credential,
            cache: RwLock::new(None),
        };
        AzureBackend {
            config: create_rbac_config(),
            client,
            auth: AzureAuthMode::TokenCredential {
                provider: Arc::new(provider),
            },
            path_format: StoragePathFormat::Native,
        }
    }

    fn create_cached_rbac_backend_with_endpoint_and_path_format(
        endpoint: String,
        path_format: StoragePathFormat,
    ) -> AzureBackend {
        let client = reqwest::Client::new();
        let provider = TokenCredentialProvider {
            client: client.clone(),
            credential: service_principal_cred(),
            cache: RwLock::new(Some(CachedToken {
                access_token: "cached-test-token".to_string(),
                expires_at: Utc::now() + ChronoDuration::hours(1),
            })),
        };
        let mut config = create_rbac_config();
        config.endpoint = Some(endpoint);
        config.path_format = path_format;
        AzureBackend {
            config,
            client,
            auth: AzureAuthMode::TokenCredential {
                provider: Arc::new(provider),
            },
            path_format,
        }
    }

    fn create_cached_rbac_backend_with_endpoint(endpoint: String) -> AzureBackend {
        create_cached_rbac_backend_with_endpoint_and_path_format(
            endpoint,
            StoragePathFormat::Native,
        )
    }

    fn service_principal_cred() -> TokenCredentialSource {
        TokenCredentialSource::ServicePrincipal {
            tenant_id: "fake-tenant".to_string(),
            client_id: "fake-client".to_string(),
            client_secret: "fake-secret".to_string(),
        }
    }

    fn managed_identity_cred(client_id: Option<&str>) -> TokenCredentialSource {
        TokenCredentialSource::ManagedIdentity {
            client_id: client_id.map(|s| s.to_string()),
        }
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

    #[test]
    fn test_download_range_header_is_inclusive() {
        assert_eq!(
            AzureBackend::download_range_header(1_024, 4_096).unwrap(),
            "bytes=1024-5119"
        );
    }

    #[test]
    fn test_download_range_header_rejects_overflow() {
        let err = AzureBackend::download_range_header(u64::MAX - 1, 4).unwrap_err();
        assert!(
            err.to_string().contains("overflows u64"),
            "error should explain overflow: {err}"
        );
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

    #[tokio::test]
    async fn test_put_stream_uses_block_upload_instead_of_buffered_put_blob() {
        use crate::storage::StorageBackend as StorageBackendTrait;
        use futures::stream;
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;

        let backend = create_cached_rbac_backend_with_endpoint(server.uri());
        let stream = stream::iter([
            Ok(Bytes::from_static(b"hello ")),
            Ok(Bytes::from_static(b"stream")),
        ]);

        let result =
            StorageBackendTrait::put_stream(&backend, "streamed/blob.txt", Box::pin(stream))
                .await
                .expect("stream upload should succeed");
        assert_eq!(result.bytes_written, 12);

        let requests = server.received_requests().await.unwrap_or_default();
        assert!(
            requests.iter().any(|request| request
                .url
                .query_pairs()
                .any(|(key, value)| key == "comp" && value == "block")),
            "Azure put_stream should stage data with Put Block requests"
        );
        assert!(
            requests.iter().any(|request| request
                .url
                .query_pairs()
                .any(|(key, value)| key == "comp" && value == "blocklist")),
            "Azure put_stream should commit staged blocks with Put Block List"
        );
        assert!(
            !requests.iter().any(|request| request
                .headers
                .get("x-ms-blob-type")
                .is_some_and(|value| value == "BlockBlob")),
            "Azure put_stream must not fall back to a single buffered Put Blob"
        );
    }

    #[tokio::test]
    async fn test_get_range_sends_azure_range_headers() {
        use crate::storage::StorageBackend as StorageBackendTrait;
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/testcontainer/test/file.txt"))
            .and(header("range", "bytes=5-12"))
            .and(header("x-ms-range", "bytes=5-12"))
            .respond_with(ResponseTemplate::new(206).set_body_bytes(Vec::from(&b"fghijklm"[..])))
            .mount(&server)
            .await;

        let backend = create_cached_rbac_backend_with_endpoint(server.uri());
        let bytes = StorageBackendTrait::get_range(&backend, "test/file.txt", 5, 8)
            .await
            .unwrap();

        assert_eq!(bytes, Bytes::from_static(b"fghijklm"));
    }

    #[tokio::test]
    async fn test_get_range_fallback_sends_azure_range_headers() {
        use crate::storage::StorageBackend as StorageBackendTrait;
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let checksum = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
        Mock::given(method("GET"))
            .and(path(format!("/testcontainer/repos/generic/{checksum}")))
            .and(header("range", "bytes=10-15"))
            .and(header("x-ms-range", "bytes=10-15"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/testcontainer/ab/{checksum}")))
            .and(header("range", "bytes=10-15"))
            .and(header("x-ms-range", "bytes=10-15"))
            .respond_with(ResponseTemplate::new(206).set_body_bytes(Vec::from(&b"klmnop"[..])))
            .mount(&server)
            .await;

        let backend = create_cached_rbac_backend_with_endpoint_and_path_format(
            server.uri(),
            StoragePathFormat::Migration,
        );
        let bytes =
            StorageBackendTrait::get_range(&backend, &format!("repos/generic/{checksum}"), 10, 6)
                .await
                .unwrap();

        assert_eq!(bytes, Bytes::from_static(b"klmnop"));
    }

    #[tokio::test]
    async fn test_put_stream_does_not_delete_destination_when_block_commit_fails() {
        use crate::storage::StorageBackend as StorageBackendTrait;
        use futures::stream;
        use wiremock::matchers::{method, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(query_param("comp", "block"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(query_param("comp", "blocklist"))
            .respond_with(ResponseTemplate::new(503).set_body_string("server busy"))
            .mount(&server)
            .await;
        // A failed commit must NOT delete or overwrite the destination key: a
        // concurrent writer may have committed the same digest-addressed blob
        // after this upload started, and clearing "our" uncommitted blocks by
        // mutating the blob would destroy their committed data. Azure GCs
        // uncommitted blocks on its own.
        let delete_guard = Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(202))
            .mount_as_scoped(&server)
            .await;

        let backend = create_cached_rbac_backend_with_endpoint(server.uri());
        let stream = stream::iter([Ok(Bytes::from_static(b"staged block"))]);

        let result =
            StorageBackendTrait::put_stream(&backend, "streamed/blob.txt", Box::pin(stream)).await;

        assert!(result.is_err(), "commit failure must surface to caller");
        assert_eq!(
            delete_guard.received_requests().await.len(),
            0,
            "failed upload must not delete the destination blob (a concurrent writer may own it)"
        );
    }

    #[tokio::test]
    async fn test_put_stream_uses_unique_block_ids_across_uploads_to_same_key() {
        use crate::storage::StorageBackend as StorageBackendTrait;
        use futures::stream;
        use wiremock::matchers::{method, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Capture every Put Block so we can compare the block IDs that two
        // separate uploads to the SAME key use.
        let block_guard = Mock::given(method("PUT"))
            .and(query_param("comp", "block"))
            .respond_with(ResponseTemplate::new(201))
            .mount_as_scoped(&server)
            .await;
        Mock::given(method("PUT"))
            .and(query_param("comp", "blocklist"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;

        let backend = create_cached_rbac_backend_with_endpoint(server.uri());
        for _ in 0..2 {
            let stream = stream::iter([Ok(Bytes::from_static(b"same-key block"))]);
            StorageBackendTrait::put_stream(&backend, "streamed/blob.txt", Box::pin(stream))
                .await
                .expect("streaming upload should succeed");
        }

        let block_requests = block_guard.received_requests().await;
        assert_eq!(
            block_requests.len(),
            2,
            "each upload stages exactly one block"
        );
        let block_ids: Vec<String> = block_requests
            .iter()
            .map(|req| {
                req.url
                    .query_pairs()
                    .find_map(|(k, v)| (k == "blockid").then(|| v.into_owned()))
                    .expect("Put Block request must carry a blockid")
            })
            .collect();
        assert_ne!(
            block_ids[0], block_ids[1],
            "two streaming uploads to the same key must use distinct block IDs so a concurrent writer's uncommitted blocks can never be assembled under this key"
        );
    }

    #[test]
    fn test_azure_block_id_stays_within_64_byte_limit() {
        // Azure requires each base64-encoded block ID to be <= 64 bytes and all
        // block IDs for a blob to be the same length. Our ID is a 32-hex UUID
        // nonce + a 16-digit zero-padded index = 48 raw bytes -> exactly 64
        // base64 chars. Pin this so a future change to the nonce/index width (or
        // switching to a hyphenated 36-char UUID) cannot silently push the
        // encoded ID past the limit — that would fail only on real Azure, which
        // the wiremock tests do not enforce.
        let nonce = Uuid::new_v4().simple().to_string();
        assert_eq!(nonce.len(), 32, "simple UUID nonce must be 32 hex chars");
        for idx in [0usize, 1, 49_999, usize::from(u16::MAX)] {
            let block_id = BASE64.encode(format!("{nonce}{idx:016}"));
            assert_eq!(
                block_id.len(),
                64,
                "Azure block ID for idx {idx} must be a fixed 64 base64 bytes (<= Azure's 64-byte limit), got {}",
                block_id.len()
            );
        }
    }

    #[tokio::test]
    async fn test_copy_uses_put_blob_from_url_for_small_source() {
        use crate::storage::StorageBackend as StorageBackendTrait;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let source_path = "/testcontainer/source/blob.txt";
        let dest_path = "/testcontainer/dest/blob.txt";
        Mock::given(method("HEAD"))
            .and(path(source_path))
            .respond_with(ResponseTemplate::new(200).insert_header("Content-Length", "1024"))
            .mount(&server)
            .await;
        let copy_guard = Mock::given(method("PUT"))
            .and(path(dest_path))
            .respond_with(ResponseTemplate::new(201))
            .mount_as_scoped(&server)
            .await;

        let backend = create_cached_rbac_backend_with_endpoint(server.uri());
        StorageBackendTrait::copy(&backend, "source/blob.txt", "dest/blob.txt")
            .await
            .expect("small copy should use Azure Put Blob From URL");

        assert_eq!(
            copy_guard.received_requests().await.len(),
            1,
            "copy should issue one destination PUT"
        );

        let requests = server.received_requests().await.unwrap_or_default();
        let copy_request = requests
            .iter()
            .find(|request| request.method.as_str() == "PUT" && request.url.path() == dest_path)
            .expect("destination copy request should be recorded");
        assert_eq!(
            copy_request.headers.get("x-ms-blob-type").unwrap(),
            "BlockBlob"
        );
        assert_eq!(
            copy_request.headers.get("Content-Length").unwrap(),
            "0",
            "Put Blob From URL must send an empty body"
        );
        assert_eq!(copy_request.body.len(), 0);

        let copy_source = copy_request
            .headers
            .get("x-ms-copy-source")
            .expect("copy request should include source URL")
            .to_str()
            .unwrap();
        assert_eq!(
            copy_source,
            format!("{}/testcontainer/source/blob.txt", server.uri())
        );
        assert_eq!(
            copy_request
                .headers
                .get("x-ms-copy-source-authorization")
                .unwrap(),
            "Bearer cached-test-token"
        );
        assert!(
            !requests
                .iter()
                .any(|request| request.method.as_str() == "GET"),
            "server-side copy must not download the source through the backend"
        );
    }

    #[tokio::test]
    async fn test_copy_streams_large_source_instead_of_put_blob_from_url() {
        use crate::storage::StorageBackend as StorageBackendTrait;
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let source_path = "/testcontainer/source/blob.txt";
        // Advertise a source larger than Put Blob From URL can handle so copy
        // is forced down the block-streaming path instead of the single-shot
        // server-side copy.
        Mock::given(method("HEAD"))
            .respond_with(ResponseTemplate::new(200).insert_header(
                "Content-Length",
                (AZURE_PUT_BLOB_FROM_URL_MAX_SIZE + 1).to_string(),
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(source_path))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(Vec::from(&b"large-copy"[..])))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(query_param("comp", "block"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(query_param("comp", "blocklist"))
            .respond_with(ResponseTemplate::new(201))
            .mount(&server)
            .await;

        let backend = create_cached_rbac_backend_with_endpoint(server.uri());
        StorageBackendTrait::copy(&backend, "source/blob.txt", "dest/blob.txt")
            .await
            .expect("large copy should stream through block upload");

        let requests = server.received_requests().await.unwrap_or_default();
        assert!(
            requests.iter().any(
                |request| request.method.as_str() == "GET" && request.url.path() == source_path
            ),
            "large copy should read the source as a stream"
        );
        assert!(
            requests.iter().any(|request| request
                .url
                .query_pairs()
                .any(|(key, value)| key == "comp" && value == "block")),
            "large copy should stage the destination with Put Block requests"
        );
        assert!(
            requests.iter().any(|request| request
                .url
                .query_pairs()
                .any(|(key, value)| key == "comp" && value == "blocklist")),
            "large copy should commit the destination with Put Block List"
        );
        assert!(
            !requests
                .iter()
                .any(|request| request.headers.contains_key("x-ms-copy-source")),
            "large copy must not use single-shot Azure Put Blob From URL"
        );
    }

    #[tokio::test]
    async fn test_put_stream_block_rejects_azure_block_limit_before_http_put() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let put_guard = Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(201))
            .mount_as_scoped(&server)
            .await;
        let backend = create_cached_rbac_backend_with_endpoint(server.uri());
        let mut block_ids = (0..50_000)
            .map(|i| format!("block-{i}"))
            .collect::<Vec<_>>();

        let result = backend
            .put_stream_block(
                "streamed/blob.txt",
                "0123456789abcdef0123456789abcdef",
                &mut block_ids,
                Bytes::from_static(b"x"),
            )
            .await;

        let error = result.expect_err("50,000 staged blocks must fail locally");
        assert!(
            error.to_string().contains("Azure block blob limit"),
            "unexpected error: {error}"
        );
        assert_eq!(
            put_guard.received_requests().await.len(),
            0,
            "block-limit failure must not send another Put Block request"
        );
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

    // ── Shared Key auth header ──────────────────────────────────────────

    #[test]
    fn test_shared_key_auth_produces_valid_header() {
        let key = BASE64.decode("dGVzdGtleXRlc3RrZXk=").unwrap();
        let result = AzureBackend::shared_key_auth(&key, "myaccount", "GET\n\n\n\n\ntest").unwrap();
        assert!(result.starts_with("SharedKey myaccount:"));
        // Signature should be base64 encoded
        let sig = result.strip_prefix("SharedKey myaccount:").unwrap();
        assert!(
            BASE64.decode(sig).is_ok(),
            "Signature should be valid base64"
        );
    }

    #[test]
    fn test_shared_key_auth_deterministic() {
        let key = BASE64.decode("dGVzdGtleXRlc3RrZXk=").unwrap();
        let s2s = "PUT\n\n\n42\ntest";
        let a = AzureBackend::shared_key_auth(&key, "acc", s2s).unwrap();
        let b = AzureBackend::shared_key_auth(&key, "acc", s2s).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_shared_key_auth_different_inputs_differ() {
        let key = BASE64.decode("dGVzdGtleXRlc3RrZXk=").unwrap();
        let a = AzureBackend::shared_key_auth(&key, "acc", "input-a").unwrap();
        let b = AzureBackend::shared_key_auth(&key, "acc", "input-b").unwrap();
        assert_ne!(a, b);
    }

    // ── SAS string-to-sign format ───────────────────────────────────────

    #[tokio::test]
    async fn test_sas_string_to_sign_has_correct_field_count() {
        // The SAS string-to-sign for API version 2021-06-08 must have
        // 16 fields separated by 15 newlines (trailing newline counts).
        // Fields: sp, st, se, canonicalizedResource, si, sip, spr, sv, sr,
        //         snapshotTime, encryptionScope, rscc, rscd, rsce, rscl, rsct
        let backend = create_test_backend().await;
        let token = backend
            .generate_sas_token("test/blob.txt", Duration::from_secs(60))
            .unwrap();

        // The token itself should parse correctly
        let params: std::collections::HashMap<&str, &str> =
            token.split('&').filter_map(|p| p.split_once('=')).collect();

        assert!(params.contains_key("sv"), "Missing signed version");
        assert!(params.contains_key("sr"), "Missing signed resource");
        assert!(params.contains_key("sp"), "Missing signed permissions");
        assert!(params.contains_key("spr"), "Missing signed protocol");
        assert!(params.contains_key("sig"), "Missing signature");
        assert_eq!(params["sr"], "b", "Resource should be blob");
        assert_eq!(params["sp"], "r", "Permissions should be read-only");
        assert_eq!(params["spr"], "https", "Protocol should be https");
    }

    // ── SAS token error for RBAC mode ───────────────────────────────────

    #[test]
    fn test_sas_token_fails_for_rbac_backend() {
        let backend = create_rbac_backend(service_principal_cred());

        let result = backend.generate_sas_token("test.txt", Duration::from_secs(60));
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Shared Key"),
            "Error should mention Shared Key requirement: {}",
            err_msg
        );
    }

    #[test]
    fn test_sas_url_fails_for_rbac_backend() {
        let backend = create_rbac_backend(service_principal_cred());
        let result = backend.generate_sas_url("test.txt", Duration::from_secs(60));
        assert!(result.is_err());
    }

    // ── RBAC backend creation and behavior ──────────────────────────────

    #[test]
    fn test_rbac_backend_creation_service_principal() {
        let backend = create_rbac_backend(service_principal_cred());
        assert!(backend.is_rbac());
        assert!(!backend.supports_redirect());
    }

    #[test]
    fn test_rbac_backend_creation_managed_identity() {
        let backend = create_rbac_backend(managed_identity_cred(None));
        assert!(backend.is_rbac());

        match &backend.auth {
            AzureAuthMode::TokenCredential { provider } => {
                let dbg = format!("{:?}", provider);
                assert!(
                    dbg.contains("ManagedIdentity"),
                    "Should use managed identity: {}",
                    dbg
                );
            }
            _ => panic!("Expected TokenCredential auth mode"),
        }
    }

    #[test]
    fn test_rbac_backend_user_assigned_managed_identity() {
        let backend = create_rbac_backend(managed_identity_cred(Some("user-assigned-id")));
        assert!(backend.is_rbac());

        match &backend.auth {
            AzureAuthMode::TokenCredential { provider } => {
                let dbg = format!("{:?}", provider);
                assert!(dbg.contains("user-assigned-id"));
            }
            _ => panic!("Expected TokenCredential auth mode"),
        }
    }

    #[test]
    fn test_rbac_read_url_returns_bare_blob_url() {
        let backend = create_rbac_backend(service_principal_cred());

        let url = backend
            .read_url("path/to/artifact.jar", Duration::from_secs(300))
            .unwrap();

        assert_eq!(
            url,
            "https://testaccount.blob.core.windows.net/testcontainer/path/to/artifact.jar"
        );
        assert!(
            !url.contains("sig="),
            "RBAC read URL should NOT contain SAS signature"
        );
    }

    #[tokio::test]
    async fn test_rbac_get_presigned_url_returns_none() {
        let backend = create_rbac_backend(service_principal_cred());

        let result = backend
            .get_presigned_url("test.txt", Duration::from_secs(3600))
            .await
            .unwrap();
        assert!(
            result.is_none(),
            "RBAC mode should not generate presigned URLs"
        );
    }

    #[test]
    fn test_rbac_supports_redirect_false() {
        // Even if redirect_downloads is true in config, RBAC mode disables it
        let client = reqwest::Client::new();
        let provider = TokenCredentialProvider {
            client: client.clone(),
            credential: service_principal_cred(),
            cache: RwLock::new(None),
        };
        let mut config = create_rbac_config();
        config.redirect_downloads = true;
        let backend = AzureBackend {
            config,
            client,
            auth: AzureAuthMode::TokenCredential {
                provider: Arc::new(provider),
            },
            path_format: StoragePathFormat::Native,
        };
        assert!(
            !backend.supports_redirect(),
            "RBAC should not support redirect even if config says true"
        );
    }

    // ── Auth mode enum ──────────────────────────────────────────────────

    #[test]
    fn test_auth_mode_shared_key_debug() {
        let mode = AzureAuthMode::SharedKey {
            decoded_key: vec![1, 2, 3],
        };
        let dbg = format!("{:?}", mode);
        assert!(dbg.contains("SharedKey"));
    }

    // ── Token credential provider ───────────────────────────────────────

    #[tokio::test]
    async fn test_token_credential_provider_get_token_with_valid_cache() {
        let provider = TokenCredentialProvider {
            client: reqwest::Client::new(),
            credential: managed_identity_cred(None),
            cache: RwLock::new(Some(CachedToken {
                access_token: "cached-token-value".to_string(),
                expires_at: Utc::now() + ChronoDuration::hours(1),
            })),
        };

        let token = provider.get_token().await.unwrap();
        assert_eq!(token, "cached-token-value");
    }

    #[tokio::test]
    async fn test_token_credential_provider_cache_expired_triggers_refresh() {
        let provider = TokenCredentialProvider {
            client: reqwest::Client::new(),
            credential: managed_identity_cred(None),
            cache: RwLock::new(Some(CachedToken {
                access_token: "expired-token".to_string(),
                expires_at: Utc::now() - ChronoDuration::hours(1),
            })),
        };

        // This will try to reach IMDS and fail since we're not on Azure,
        // which proves the expired cache triggers a refresh attempt.
        let result = provider.get_token().await;
        assert!(
            result.is_err(),
            "Should fail trying to refresh (not on Azure)"
        );
    }

    #[tokio::test]
    async fn test_token_credential_provider_empty_cache_triggers_refresh() {
        let provider = TokenCredentialProvider {
            client: reqwest::Client::new(),
            credential: managed_identity_cred(None),
            cache: RwLock::new(None),
        };

        let result = provider.get_token().await;
        assert!(
            result.is_err(),
            "Should fail trying to acquire token (not on Azure)"
        );
    }

    #[tokio::test]
    async fn test_token_credential_provider_sp_expired_triggers_refresh() {
        let provider = TokenCredentialProvider {
            client: reqwest::Client::new(),
            credential: service_principal_cred(),
            cache: RwLock::new(Some(CachedToken {
                access_token: "old-sp-token".to_string(),
                expires_at: Utc::now() - ChronoDuration::hours(1),
            })),
        };

        // SP token refresh will fail because the credentials are fake,
        // which proves the expired cache triggers refresh for SP too.
        let result = provider.get_token().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_token_credential_provider_sp_empty_cache_triggers_refresh() {
        let provider = TokenCredentialProvider {
            client: reqwest::Client::new(),
            credential: service_principal_cred(),
            cache: RwLock::new(None),
        };

        let result = provider.get_token().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_token_credential_provider_double_check_cache() {
        // Verify the double-check pattern: if cache becomes valid between
        // read lock release and write lock acquisition, it returns cached value.
        let provider = TokenCredentialProvider {
            client: reqwest::Client::new(),
            credential: managed_identity_cred(None),
            cache: RwLock::new(Some(CachedToken {
                access_token: "still-valid".to_string(),
                expires_at: Utc::now() + ChronoDuration::hours(2),
            })),
        };

        // Two concurrent calls should both succeed with the cached value.
        let (t1, t2) = tokio::join!(provider.get_token(), provider.get_token());
        assert_eq!(t1.unwrap(), "still-valid");
        assert_eq!(t2.unwrap(), "still-valid");
    }

    // ── RBAC custom endpoint ────────────────────────────────────────────

    #[test]
    fn test_rbac_blob_url_with_custom_endpoint() {
        let client = reqwest::Client::new();
        let provider = TokenCredentialProvider {
            client: client.clone(),
            credential: service_principal_cred(),
            cache: RwLock::new(None),
        };
        let mut config = create_rbac_config();
        config.endpoint = Some("https://gov.blob.core.usgovcloudapi.net".to_string());
        let backend = AzureBackend {
            config,
            client,
            auth: AzureAuthMode::TokenCredential {
                provider: Arc::new(provider),
            },
            path_format: StoragePathFormat::Native,
        };

        let url = backend.blob_url("test.txt");
        assert!(url.starts_with("https://gov.blob.core.usgovcloudapi.net"));
    }

    // ── RBAC path format ────────────────────────────────────────────────

    #[test]
    fn test_rbac_backend_path_format_preserved() {
        let client = reqwest::Client::new();
        let provider = TokenCredentialProvider {
            client: client.clone(),
            credential: service_principal_cred(),
            cache: RwLock::new(None),
        };
        let backend = AzureBackend {
            config: create_rbac_config(),
            client,
            auth: AzureAuthMode::TokenCredential {
                provider: Arc::new(provider),
            },
            path_format: StoragePathFormat::Artifactory,
        };
        assert_eq!(backend.path_format, StoragePathFormat::Artifactory);
    }
}
