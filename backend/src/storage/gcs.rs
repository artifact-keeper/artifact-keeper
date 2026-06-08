//! Google Cloud Storage backend with signed URL and Workload Identity support.
//!
//! Supports two authentication modes:
//!
//! ## Mode A: Service Account Key
//!
//! Triggered when `GCS_PRIVATE_KEY` or `GCS_PRIVATE_KEY_PATH` is set. Requires
//! `GCS_PROJECT_ID` and `GCS_SERVICE_ACCOUNT_EMAIL`. Uses the RSA key to mint
//! self-signed JWTs exchanged for OAuth2 bearer tokens at Google's token
//! endpoint. All API calls are authenticated. Redirect downloads via V4 signed
//! URLs are available in this mode.
//!
//! ```bash
//! STORAGE_BACKEND=gcs
//! GCS_BUCKET=my-bucket
//! GCS_PROJECT_ID=my-project
//! GCS_SERVICE_ACCOUNT_EMAIL=sa@project.iam.gserviceaccount.com
//! GCS_PRIVATE_KEY_PATH=/path/to/service-account-key.pem
//! # Or inline:
//! GCS_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n..."
//! GCS_REDIRECT_DOWNLOADS=true
//! GCS_SIGNED_URL_EXPIRY=3600  # seconds, default 1 hour
//! ```
//!
//! ## Mode B: Application Default Credentials / Workload Identity
//!
//! Triggered when neither `GCS_PRIVATE_KEY` nor `GCS_PRIVATE_KEY_PATH` is set.
//! Authenticates via the GCP metadata server (works on GKE with Workload
//! Identity). Only `GCS_BUCKET` is required. `supports_redirect()` returns
//! `false` in this mode because V4 signed URLs require an RSA private key.
//!
//! ```bash
//! STORAGE_BACKEND=gcs
//! GCS_BUCKET=my-bucket
//! ```
//!
//! ## Path format
//!
//! ```bash
//! # For Artifactory migration:
//! STORAGE_PATH_FORMAT=migration  # native, artifactory, or migration
//! ```

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL, Engine};
use bytes::Bytes;
use chrono::Utc;
use futures::stream::BoxStream;
use futures::StreamExt;
use rsa::pkcs8::DecodePrivateKey;
use rsa::sha2::Sha256;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::RsaPrivateKey;
use sha2::Digest;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::error::{AppError, Result};
use crate::storage::{
    download_range_header, PresignedUrl, PresignedUrlSource, PutStreamResult, StorageBackend,
    StoragePathFormat,
};

/// GCP metadata server URL for fetching access tokens.
const GCP_METADATA_TOKEN_URL: &str =
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token";

/// Google OAuth2 token endpoint.
const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

/// OAuth2 scope for full GCS access.
const GCS_SCOPE: &str = "https://www.googleapis.com/auth/devstorage.full_control";

/// Default GCS JSON API base URL.
const GCS_BASE_URL: &str = "https://storage.googleapis.com";

/// OAuth2 token response from Google token endpoint or GCE metadata server.
#[derive(serde::Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

/// Response from the GCS objects.rewrite endpoint.
#[derive(serde::Deserialize)]
struct RewriteResponse {
    done: bool,
    #[serde(rename = "rewriteToken")]
    rewrite_token: Option<String>,
}

/// Chunk size for the resumable upload protocol. GCS requires every
/// non-final chunk to be an exact multiple of 256 KiB. 32 MiB satisfies that
/// (32 MiB = 128 * 256 KiB) and keeps the in-flight heap footprint bounded
/// regardless of artifact size.
const RESUMABLE_CHUNK_SIZE: usize = 32 * 1024 * 1024;

/// Max attempts for a single resumable chunk PUT before giving up.
const CHUNK_MAX_ATTEMPTS: u32 = 3;

/// Build the `Content-Range` header value for a resumable chunk PUT.
///
/// `start` is the byte offset of the first byte in this chunk, `len` is the
/// chunk's byte length, and `total` is `Some(total_size)` only for the final
/// chunk (GCS finalizes the object once it learns the total) and `None` for
/// intermediate chunks ("more to come").
///
/// Examples:
/// - intermediate first chunk: `bytes 0-33554431/*`
/// - final chunk of a 40 MiB object: `bytes 33554432-41943039/41943040`
fn content_range(start: u64, len: u64, total: Option<u64>) -> String {
    let total_str = match total {
        Some(t) => t.to_string(),
        None => "*".to_string(),
    };
    if len == 0 {
        // No bytes in this request: used for the terminal "finalize" PUT when
        // the upload ended exactly on a chunk boundary, or a zero-byte object.
        format!("bytes */{}", total_str)
    } else {
        let end = start + len - 1;
        format!("bytes {}-{}/{}", start, end, total_str)
    }
}

/// Parse the `Range` header GCS returns on a 308 status-query response and
/// return the next byte offset to send (the confirmed-last byte + 1).
///
/// GCS resumable uploads always start at byte 0, so a valid header is exactly
/// `bytes=0-<n>` (case-insensitive `bytes=` prefix). Returns `None` for any
/// other shape (missing `bytes=` prefix, a non-zero start, a non-numeric end,
/// or trailing junk) so the caller can treat it as a hard error rather than
/// silently resyncing to offset 0.
fn parse_resumable_range_next(header: &str) -> Option<u64> {
    let header = header.trim();
    // Strip the "bytes=" prefix (case-insensitive on the literal "bytes").
    let rest = header
        .get(..6)
        .filter(|p| p.eq_ignore_ascii_case("bytes="))
        .map(|_| &header[6..])?;
    let (start, end) = rest.split_once('-')?;
    // Resumable uploads always begin at byte 0.
    if start.trim() != "0" {
        return None;
    }
    let confirmed_last: u64 = end.trim().parse().ok()?;
    confirmed_last.checked_add(1)
}

/// True if an upstream HTTP status is a transient failure worth retrying
/// (429 Too Many Requests, or any 5xx).
fn is_transient_status(status: u16) -> bool {
    status == 429 || (500..=599).contains(&status)
}

/// Map a failed upstream status to the right `AppError`. Transient statuses
/// (429/5xx) become `ServiceUnavailable` (HTTP 503, retryable by callers);
/// everything else stays `Storage` (HTTP 500).
fn map_status_error(status: u16, context: &str, body: &str) -> AppError {
    let msg = format!("{} (status {}): {}", context, status, body);
    if is_transient_status(status) {
        AppError::ServiceUnavailable(msg)
    } else {
        AppError::Storage(msg)
    }
}

/// Check that an HTTP response indicates success; return an error with context otherwise.
async fn require_success(
    response: reqwest::Response,
    context: &str,
) -> std::result::Result<reqwest::Response, AppError> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();
    Err(map_status_error(status, context, &body))
}

// ---------------------------------------------------------------------------
// Token caching
// ---------------------------------------------------------------------------

/// Cached GCP access token.
struct CachedToken {
    token: String,
    expires_at: Instant,
}

/// Where tokens come from.
enum TokenSource {
    /// Self-signed JWT exchanged at Google's token endpoint (service account key).
    ServiceAccountJwt {
        service_account_email: String,
        signing_key: Box<RsaPrivateKey>,
    },
    /// GCE metadata server (ADC / Workload Identity).
    MetadataServer,
}

/// Token provider with RwLock cache, mirroring Azure's `TokenCredentialProvider`.
struct GcsTokenProvider {
    source: TokenSource,
    cache: RwLock<Option<CachedToken>>,
    client: reqwest::Client,
}

impl GcsTokenProvider {
    fn new(source: TokenSource, client: reqwest::Client) -> Self {
        Self {
            source,
            cache: RwLock::new(None),
            client,
        }
    }

    /// Get a valid access token, refreshing if the cached one expires within 60s.
    async fn get_token(&self) -> Result<String> {
        // Fast path: read lock
        {
            let cache = self.cache.read().await;
            if let Some(ref cached) = *cache {
                if cached.expires_at > Instant::now() + Duration::from_secs(60) {
                    return Ok(cached.token.clone());
                }
            }
        }

        // Slow path: write lock
        let mut cache = self.cache.write().await;
        // Double-check: another task may have refreshed while we waited
        if let Some(ref cached) = *cache {
            if cached.expires_at > Instant::now() + Duration::from_secs(60) {
                return Ok(cached.token.clone());
            }
        }

        let (token, expires_in) = match &self.source {
            TokenSource::ServiceAccountJwt {
                service_account_email,
                signing_key,
            } => {
                self.fetch_jwt_token(service_account_email, signing_key)
                    .await?
            }
            TokenSource::MetadataServer => self.fetch_metadata_token().await?,
        };

        *cache = Some(CachedToken {
            token: token.clone(),
            expires_at: Instant::now() + Duration::from_secs(expires_in),
        });

        Ok(token)
    }

    /// Mint a self-signed JWT and exchange it for an access token.
    async fn fetch_jwt_token(
        &self,
        email: &str,
        signing_key: &RsaPrivateKey,
    ) -> Result<(String, u64)> {
        let now = Utc::now().timestamp();

        let header = serde_json::json!({"alg": "RS256", "typ": "JWT"});
        let claims = serde_json::json!({
            "iss": email,
            "scope": GCS_SCOPE,
            "aud": GOOGLE_TOKEN_URL,
            "iat": now,
            "exp": now + 3600,
        });

        let header_b64 = BASE64_URL.encode(header.to_string().as_bytes());
        let claims_b64 = BASE64_URL.encode(claims.to_string().as_bytes());
        let unsigned = format!("{}.{}", header_b64, claims_b64);

        let signer = rsa::pkcs1v15::SigningKey::<Sha256>::new(signing_key.clone());
        let signature = signer.sign(unsigned.as_bytes());
        let jwt = format!("{}.{}", unsigned, BASE64_URL.encode(signature.to_bytes()));

        let response = self
            .client
            .post(GOOGLE_TOKEN_URL)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &jwt),
            ])
            .send()
            .await
            .map_err(|e| {
                AppError::Storage(format!("Failed to exchange JWT for access token: {}", e))
            })?;

        let response = require_success(response, "Google token endpoint error").await?;
        let token_resp: TokenResponse = response
            .json()
            .await
            .map_err(|e| AppError::Storage(format!("Failed to parse token response: {}", e)))?;

        Ok((token_resp.access_token, token_resp.expires_in))
    }

    /// Fetch a token from the GCE metadata server.
    async fn fetch_metadata_token(&self) -> Result<(String, u64)> {
        let response = self
            .client
            .get(GCP_METADATA_TOKEN_URL)
            .header("Metadata-Flavor", "Google")
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("Failed to fetch GCP access token: {}", e)))?;

        let response = require_success(response, "GCP metadata server error").await?;
        let token_resp: TokenResponse = response
            .json()
            .await
            .map_err(|e| AppError::Storage(format!("Failed to parse GCP token response: {}", e)))?;

        Ok((token_resp.access_token, token_resp.expires_in))
    }
}

// ---------------------------------------------------------------------------
// Auth mode
// ---------------------------------------------------------------------------

/// Authentication mode for GCS operations.
///
/// Mirrors `AzureAuthMode` in `azure.rs`: both variants carry a token provider
/// that acquires OAuth2 bearer tokens. The `ServiceAccountKey` variant also
/// holds the RSA private key needed for V4 signed URL generation.
enum GcsAuthMode {
    /// Service account with RSA key: bearer tokens via JWT exchange, V4 signed
    /// URLs available.
    ServiceAccountKey {
        signing_key: Box<RsaPrivateKey>,
        provider: GcsTokenProvider,
    },
    /// Application Default Credentials via GCE metadata server.
    Adc { provider: GcsTokenProvider },
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Google Cloud Storage configuration.
#[derive(Debug, Clone)]
pub struct GcsConfig {
    /// GCS bucket name.
    pub bucket: String,
    /// GCP project ID (required with private key, optional in ADC mode).
    pub project_id: Option<String>,
    /// Service account email (required with private key, optional in ADC mode).
    pub service_account_email: Option<String>,
    /// RSA private key in PEM format.
    pub private_key: Option<String>,
    /// Enable redirect downloads via V4 signed URLs.
    pub redirect_downloads: bool,
    /// Signed URL expiry duration.
    pub signed_url_expiry: Duration,
    /// Storage path format (native, artifactory, or migration).
    pub path_format: StoragePathFormat,
}

impl GcsConfig {
    /// Create config from environment variables.
    ///
    /// `GCS_BUCKET` is always required.
    ///
    /// When `GCS_PRIVATE_KEY` or `GCS_PRIVATE_KEY_PATH` is set (service account
    /// key mode), `GCS_PROJECT_ID` and `GCS_SERVICE_ACCOUNT_EMAIL` are also
    /// required.
    ///
    /// When neither key variable is set (ADC mode), `GCS_PROJECT_ID` and
    /// `GCS_SERVICE_ACCOUNT_EMAIL` are optional.
    pub fn from_env() -> Result<Self> {
        let bucket = std::env::var("GCS_BUCKET")
            .map_err(|_| AppError::Config("GCS_BUCKET not set".to_string()))?;

        // Load private key from file or environment variable
        let private_key = if let Ok(key_path) = std::env::var("GCS_PRIVATE_KEY_PATH") {
            std::fs::read_to_string(&key_path)
                .map_err(|e| {
                    tracing::warn!("Failed to read GCS private key from {}: {}", key_path, e);
                    e
                })
                .ok()
        } else {
            std::env::var("GCS_PRIVATE_KEY").ok()
        };

        let project_id = std::env::var("GCS_PROJECT_ID").ok();
        let service_account_email = std::env::var("GCS_SERVICE_ACCOUNT_EMAIL").ok();

        // Service account key mode requires project_id and service_account_email
        if private_key.is_some() {
            if project_id.is_none() {
                return Err(AppError::Config(
                    "GCS_PROJECT_ID not set (required when using RSA key signing)".to_string(),
                ));
            }
            if service_account_email.is_none() {
                return Err(AppError::Config(
                    "GCS_SERVICE_ACCOUNT_EMAIL not set (required when using RSA key signing)"
                        .to_string(),
                ));
            }
        }

        let redirect_downloads = std::env::var("GCS_REDIRECT_DOWNLOADS")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);

        let signed_url_expiry = std::env::var("GCS_SIGNED_URL_EXPIRY")
            .ok()
            .and_then(|v| v.parse().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(3600));

        let path_format = StoragePathFormat::from_env();

        Ok(Self {
            bucket,
            project_id,
            service_account_email,
            private_key,
            redirect_downloads,
            signed_url_expiry,
            path_format,
        })
    }

    /// Builder: set redirect downloads.
    pub fn with_redirect_downloads(mut self, enabled: bool) -> Self {
        self.redirect_downloads = enabled;
        self
    }

    /// Builder: set signed URL expiry.
    pub fn with_signed_url_expiry(mut self, expiry: Duration) -> Self {
        self.signed_url_expiry = expiry;
        self
    }

    /// Builder: set private key.
    pub fn with_private_key(mut self, key: String) -> Self {
        self.private_key = Some(key);
        self
    }
}

// ---------------------------------------------------------------------------
// Backend
// ---------------------------------------------------------------------------

/// Google Cloud Storage backend.
pub struct GcsBackend {
    config: GcsConfig,
    /// Control-plane client (get/put/exists/delete/metadata/list, token
    /// acquisition). Short 30 s timeout so a stuck control op fails fast.
    client: reqwest::Client,
    /// Long-timeout client used only for the streaming GET (`get_stream`) and
    /// the resumable PUT chunks in `put_stream`. A multi-GiB resumable upload's
    /// total can run for many minutes; bounding it at 30 min keeps a cliff in
    /// place without leaking that long timeout onto fast control-plane calls.
    stream_client: reqwest::Client,
    auth: GcsAuthMode,
    path_format: StoragePathFormat,
    /// API base URL (overridable in tests via `with_base_url`).
    base_url: String,
}

impl GcsBackend {
    /// Create a new GCS backend.
    pub async fn new(config: GcsConfig) -> Result<Self> {
        // Control-plane client: 30 s is plenty for metadata, list, delete, and
        // single-shot puts of single-MB OCI layers. Token acquisition rides
        // this client too.
        let client = crate::services::http_client::base_client_builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| AppError::Storage(format!("Failed to create HTTP client: {}", e)))?;

        // Streaming client: a multi-GiB resumable upload's total can run for
        // many minutes; bound the cliff at 30 min. Per-chunk PUTs stay well
        // under this on intra-GCP networking, but the streaming GET of a large
        // object can legitimately run long.
        let stream_client = crate::services::http_client::base_client_builder()
            .timeout(Duration::from_secs(1800))
            .build()
            .map_err(|e| {
                AppError::Storage(format!("Failed to create streaming HTTP client: {}", e))
            })?;

        let auth = if let Some(ref key_pem) = config.private_key {
            let key_pem = key_pem.replace("\\n", "\n");
            let signing_key = RsaPrivateKey::from_pkcs8_pem(&key_pem)
                .map_err(|e| AppError::Config(format!("Invalid GCS private key: {}", e)))?;

            let email = config.service_account_email.clone().ok_or_else(|| {
                AppError::Config(
                    "GCS_SERVICE_ACCOUNT_EMAIL required for service account key mode".to_string(),
                )
            })?;

            let provider = GcsTokenProvider::new(
                TokenSource::ServiceAccountJwt {
                    service_account_email: email,
                    signing_key: Box::new(signing_key.clone()),
                },
                client.clone(),
            );

            GcsAuthMode::ServiceAccountKey {
                signing_key: Box::new(signing_key),
                provider,
            }
        } else {
            let provider = GcsTokenProvider::new(TokenSource::MetadataServer, client.clone());
            GcsAuthMode::Adc { provider }
        };

        let path_format = config.path_format;
        if path_format != StoragePathFormat::Native {
            tracing::info!(
                path_format = %path_format,
                "GCS storage path format configured"
            );
        }

        Ok(Self {
            config,
            client,
            stream_client,
            auth,
            path_format,
            base_url: GCS_BASE_URL.to_string(),
        })
    }

    /// Return the bucket name this backend is configured to use.
    #[allow(dead_code)] // Used in tests across modules
    pub(crate) fn bucket(&self) -> &str {
        &self.config.bucket
    }

    // ---- Bearer token ----

    /// Obtain an OAuth2 bearer token from the active auth mode's provider.
    async fn get_bearer_token(&self) -> Result<String> {
        match &self.auth {
            GcsAuthMode::ServiceAccountKey { provider, .. } => provider.get_token().await,
            GcsAuthMode::Adc { provider } => provider.get_token().await,
        }
    }

    // ---- JSON API URL helpers ----

    /// JSON API URL for downloading object data (`?alt=media`).
    fn object_download_url(&self, key: &str) -> String {
        format!(
            "{}/storage/v1/b/{}/o/{}?alt=media",
            self.base_url,
            urlencoding::encode(&self.config.bucket),
            urlencoding::encode(key),
        )
    }

    /// JSON API URL for object metadata (also used for DELETE).
    fn object_metadata_url(&self, key: &str) -> String {
        format!(
            "{}/storage/v1/b/{}/o/{}",
            self.base_url,
            urlencoding::encode(&self.config.bucket),
            urlencoding::encode(key),
        )
    }

    /// JSON API simple upload URL.
    fn upload_url(&self, key: &str) -> String {
        format!(
            "{}/upload/storage/v1/b/{}/o?uploadType=media&name={}",
            self.base_url,
            urlencoding::encode(&self.config.bucket),
            urlencoding::encode(key),
        )
    }

    /// XML API URL for V4 signed URL generation (not used for bearer-authed calls).
    #[cfg(test)]
    fn object_url(&self, key: &str) -> String {
        format!(
            "https://storage.googleapis.com/{}/{}",
            self.config.bucket, key
        )
    }

    // ---- Authorized request helpers ----

    /// Upload an object via the JSON API with bearer auth.
    async fn authorized_put(&self, key: &str, content: Bytes) -> Result<reqwest::Response> {
        let token = self.get_bearer_token().await?;
        let url = self.upload_url(key);

        self.client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/octet-stream")
            .body(content)
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("GCS upload failed: {}", e)))
    }

    /// GET request with bearer auth. Caller provides the full URL.
    async fn authorized_get(&self, url: &str) -> Result<reqwest::Response> {
        let token = self.get_bearer_token().await?;

        self.client
            .get(url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("GCS request failed: {}", e)))
    }

    /// GET request on the long-timeout streaming client. Used only by
    /// `get_stream`, where pulling a multi-GiB body can legitimately run far
    /// past the 30 s control-plane budget.
    async fn authorized_get_stream(&self, url: &str) -> Result<reqwest::Response> {
        let token = self.get_bearer_token().await?;

        self.stream_client
            .get(url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("GCS request failed: {}", e)))
    }

    /// Ranged GET request with bearer auth. Caller provides the full URL.
    async fn authorized_get_range(
        &self,
        url: &str,
        range_header: &str,
    ) -> Result<reqwest::Response> {
        let token = self.get_bearer_token().await?;

        self.client
            .get(url)
            .header("Authorization", format!("Bearer {}", token))
            .header(reqwest::header::RANGE, range_header)
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("GCS ranged request failed: {}", e)))
    }

    /// DELETE request with bearer auth via the JSON API metadata URL.
    async fn authorized_delete(&self, key: &str) -> Result<reqwest::Response> {
        let token = self.get_bearer_token().await?;
        let url = self.object_metadata_url(key);

        self.client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("GCS delete failed: {}", e)))
    }

    // ---- Fallback helpers ----

    /// Try to generate an Artifactory fallback path from a native path.
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

    /// Try a fallback GET in migration mode. Returns `Ok(Some(bytes))` if found
    /// at the fallback path, `Ok(None)` otherwise.
    async fn try_fallback_get(&self, key: &str) -> Result<Option<Bytes>> {
        if !self.path_format.has_fallback() {
            return Ok(None);
        }
        if let Some(fallback_key) = self.try_artifactory_fallback(key) {
            tracing::debug!(
                original = %key,
                fallback = %fallback_key,
                "Trying Artifactory fallback path"
            );
            let url = self.object_download_url(&fallback_key);
            let response = self.authorized_get(&url).await?;
            if response.status().is_success() {
                tracing::info!(
                    key = %key,
                    fallback = %fallback_key,
                    "Found artifact at Artifactory fallback path"
                );
                let bytes = response
                    .bytes()
                    .await
                    .map_err(|e| AppError::Storage(format!("Failed to read response: {}", e)))?;
                return Ok(Some(bytes));
            }
        }
        Ok(None)
    }

    /// Try a fallback ranged GET in migration mode. Returns `Ok(Some(bytes))`
    /// if found at the fallback path, `Ok(None)` otherwise.
    async fn try_fallback_get_range(&self, key: &str, range_header: &str) -> Result<Option<Bytes>> {
        if !self.path_format.has_fallback() {
            return Ok(None);
        }
        if let Some(fallback_key) = self.try_artifactory_fallback(key) {
            tracing::debug!(
                original = %key,
                fallback = %fallback_key,
                range = %range_header,
                "Trying Artifactory fallback path range"
            );
            let url = self.object_download_url(&fallback_key);
            let response = self.authorized_get_range(&url, range_header).await?;
            if response.status() == reqwest::StatusCode::PARTIAL_CONTENT {
                tracing::info!(
                    key = %key,
                    fallback = %fallback_key,
                    "Found artifact range at Artifactory fallback path"
                );
                let bytes = response
                    .bytes()
                    .await
                    .map_err(|e| AppError::Storage(format!("Failed to read response: {}", e)))?;
                return Ok(Some(bytes));
            }
        }
        Ok(None)
    }

    /// Try a fallback existence check in migration mode. Returns `Ok(true)` if
    /// found at the fallback path, `Ok(false)` otherwise. Propagates network errors.
    async fn try_fallback_exists(&self, key: &str) -> Result<bool> {
        if !self.path_format.has_fallback() {
            return Ok(false);
        }
        if let Some(fallback_key) = self.try_artifactory_fallback(key) {
            let url = self.object_metadata_url(&fallback_key);
            let response = self.authorized_get(&url).await?;
            if response.status().is_success() {
                tracing::debug!(
                    key = %key,
                    fallback = %fallback_key,
                    "Found artifact at Artifactory fallback path"
                );
                return Ok(true);
            }
        }
        Ok(false)
    }

    // ---- Methods not on the StorageBackend trait (like S3Backend) ----

    /// List objects with optional prefix. Handles pagination via `nextPageToken`.
    pub async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        #[derive(serde::Deserialize)]
        struct GcsObject {
            name: String,
        }
        #[derive(serde::Deserialize)]
        struct GcsListResponse {
            #[serde(default)]
            items: Vec<GcsObject>,
            #[serde(rename = "nextPageToken")]
            next_page_token: Option<String>,
        }

        let mut all_keys = Vec::new();
        let mut page_token: Option<String> = None;

        loop {
            let token = self.get_bearer_token().await?;
            let base = format!(
                "{}/storage/v1/b/{}/o",
                self.base_url,
                urlencoding::encode(&self.config.bucket)
            );

            let mut params = Vec::new();
            if let Some(p) = prefix {
                params.push(format!("prefix={}", urlencoding::encode(p)));
            }
            if let Some(ref pt) = page_token {
                params.push(format!("pageToken={}", urlencoding::encode(pt)));
            }

            let url = if params.is_empty() {
                base
            } else {
                format!("{}?{}", base, params.join("&"))
            };

            let response = self
                .client
                .get(&url)
                .header("Authorization", format!("Bearer {}", token))
                .send()
                .await
                .map_err(|e| AppError::Storage(format!("GCS list failed: {}", e)))?;

            let response = require_success(response, "GCS list failed").await?;
            let list_response: GcsListResponse = response.json().await.map_err(|e| {
                AppError::Storage(format!("Failed to parse GCS list response: {}", e))
            })?;

            all_keys.extend(list_response.items.into_iter().map(|o| o.name));

            match list_response.next_page_token {
                Some(pt) => page_token = Some(pt),
                None => break,
            }
        }

        Ok(all_keys)
    }

    /// Copy an object within the same bucket.
    pub async fn copy(&self, source: &str, dest: &str) -> Result<()> {
        let token = self.get_bearer_token().await?;
        let bucket_enc = urlencoding::encode(&self.config.bucket);
        let base_url = format!(
            "{}/storage/v1/b/{}/o/{}/rewriteTo/b/{}/o/{}",
            self.base_url,
            bucket_enc,
            urlencoding::encode(source),
            bucket_enc,
            urlencoding::encode(dest),
        );
        let mut rewrite_token: Option<String> = None;

        // GCS server-side rewrite is paginated: each continuation copies as much
        // as GCS chooses (we set no `maxBytesRewrittenPerCall`) and is a fast
        // sub-second metadata op, so even a 5 TiB object (GCS's max) completes in
        // far fewer than this cap, reusing the single bearer token fetched above
        // well within its lifetime. The cap is purely a defensive backstop
        // against a non-conformant endpoint that never reports `done` (or rotates
        // a token without progressing), matching the explicit limits on the S3
        // part / Azure block loops.
        const MAX_REWRITE_ITERATIONS: usize = 100_000;

        for _ in 0..MAX_REWRITE_ITERATIONS {
            let url = match rewrite_token.as_deref() {
                Some(token) => format!("{}?rewriteToken={}", base_url, urlencoding::encode(token)),
                None => base_url.clone(),
            };

            let response = self
                .client
                .post(&url)
                .header("Authorization", format!("Bearer {}", token))
                .header("Content-Length", "0")
                .send()
                .await
                .map_err(|e| AppError::Storage(format!("GCS rewrite failed: {}", e)))?;

            let response = require_success(response, "GCS rewrite failed").await?;
            let rewrite: RewriteResponse = response.json().await.map_err(|e| {
                AppError::Storage(format!("Failed to parse GCS rewrite response: {}", e))
            })?;

            if rewrite.done {
                return Ok(());
            }

            rewrite_token = rewrite.rewrite_token;
            if rewrite_token.is_none() {
                tracing::warn!(
                    source = %source,
                    dest = %dest,
                    "GCS rewrite response was incomplete and did not include rewriteToken"
                );
                return Err(AppError::Storage(
                    "GCS rewrite response missing rewriteToken".to_string(),
                ));
            }
        }

        Err(AppError::Storage(format!(
            "GCS rewrite of '{}' -> '{}' did not complete within {} iterations",
            source, dest, MAX_REWRITE_ITERATIONS
        )))
    }

    /// Get the size of an object in bytes.
    pub async fn size(&self, key: &str) -> Result<u64> {
        #[derive(serde::Deserialize)]
        struct GcsObjectMetadata {
            size: String,
        }

        let url = self.object_metadata_url(key);
        let response = self.authorized_get(&url).await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(AppError::NotFound(format!("Object not found: {}", key)));
        }
        let response = require_success(response, "GCS size request failed").await?;

        let metadata: GcsObjectMetadata = response.json().await.map_err(|e| {
            AppError::Storage(format!("Failed to parse GCS object metadata: {}", e))
        })?;

        metadata
            .size
            .parse::<u64>()
            .map_err(|e| AppError::Storage(format!("Failed to parse GCS object size: {}", e)))
    }

    // ---- V4 signed URL generation ----

    /// Generate a V4 signed URL for an object.
    ///
    /// Only available in service account key mode. Used for redirect downloads.
    ///
    /// Reference: <https://cloud.google.com/storage/docs/access-control/signing-urls-manually>
    pub fn generate_signed_url(&self, key: &str, expires_in: Duration) -> Result<String> {
        let signing_key = match &self.auth {
            GcsAuthMode::ServiceAccountKey { signing_key, .. } => signing_key,
            GcsAuthMode::Adc { .. } => {
                return Err(AppError::Config(
                    "GCS private key not configured for signed URLs".to_string(),
                ));
            }
        };

        let service_account_email =
            self.config
                .service_account_email
                .as_deref()
                .ok_or_else(|| {
                    AppError::Config(
                        "GCS_SERVICE_ACCOUNT_EMAIL not configured (required for signed URLs)"
                            .to_string(),
                    )
                })?;

        let now = Utc::now();
        let expiry_seconds = expires_in.as_secs().min(604800); // Max 7 days

        // Credential scope
        let date_stamp = now.format("%Y%m%d").to_string();
        let credential_scope = format!("{}/auto/storage/goog4_request", date_stamp);
        let credential = format!("{}/{}", service_account_email, credential_scope);

        // Request timestamp
        let request_timestamp = now.format("%Y%m%dT%H%M%SZ").to_string();

        // Canonical headers
        let host = "storage.googleapis.com";
        let signed_headers = "host";

        // Build canonical query string (alphabetically sorted)
        let query_params = [
            ("X-Goog-Algorithm", "GOOG4-RSA-SHA256".to_string()),
            ("X-Goog-Credential", credential.clone()),
            ("X-Goog-Date", request_timestamp.clone()),
            ("X-Goog-Expires", expiry_seconds.to_string()),
            ("X-Goog-SignedHeaders", signed_headers.to_string()),
        ];

        let canonical_query_string: String = query_params
            .iter()
            .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
            .collect::<Vec<_>>()
            .join("&");

        // Canonical request
        let canonical_uri = format!("/{}/{}", self.config.bucket, key);
        let canonical_headers = format!("host:{}\n", host);
        let payload_hash = "UNSIGNED-PAYLOAD";

        let canonical_request = format!(
            "GET\n{}\n{}\n{}\n{}\n{}",
            canonical_uri, canonical_query_string, canonical_headers, signed_headers, payload_hash
        );

        // Hash the canonical request
        let mut hasher = Sha256::new();
        hasher.update(canonical_request.as_bytes());
        let canonical_request_hash = hex::encode(hasher.finalize());

        // String to sign
        let string_to_sign = format!(
            "GOOG4-RSA-SHA256\n{}\n{}\n{}",
            request_timestamp, credential_scope, canonical_request_hash
        );

        // Sign with RSA-SHA256
        let signing_key_with_digest =
            rsa::pkcs1v15::SigningKey::<Sha256>::new(*signing_key.clone());
        let signature = signing_key_with_digest.sign(string_to_sign.as_bytes());
        let signature_hex = hex::encode(signature.to_bytes());

        // Build final URL
        let signed_url = format!(
            "https://{}{}?{}&X-Goog-Signature={}",
            host, canonical_uri, canonical_query_string, signature_hex
        );

        Ok(signed_url)
    }

    // ---- Resumable upload helpers ----

    /// Initiate a resumable upload session. Returns the session URL from the
    /// `Location` header.
    async fn initiate_resumable_session(&self, key: &str) -> Result<String> {
        let token = self.get_bearer_token().await?;
        let initiate_url = format!(
            "{}/upload/storage/v1/b/{}/o?uploadType=resumable&name={}",
            self.base_url,
            urlencoding::encode(&self.config.bucket),
            urlencoding::encode(key),
        );

        let init_response = self
            .stream_client
            .post(&initiate_url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/octet-stream")
            .header("Content-Length", "0")
            .body(Vec::<u8>::new())
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("GCS resumable initiate failed: {}", e)))?;

        if !init_response.status().is_success() {
            let status = init_response.status().as_u16();
            let body = init_response.text().await.unwrap_or_default();
            return Err(map_status_error(
                status,
                "GCS resumable initiate failed",
                &body,
            ));
        }

        init_response
            .headers()
            .get("Location")
            .ok_or_else(|| {
                AppError::Storage("GCS resumable initiate returned no Location header".to_string())
            })?
            .to_str()
            .map_err(|e| AppError::Storage(format!("GCS Location header not valid UTF-8: {}", e)))
            .map(|s| s.to_string())
    }

    /// Best-effort abort of a resumable session so a failed upload does not
    /// leave an orphaned, billable session behind. Errors are logged and
    /// swallowed: the caller is already returning the original failure.
    async fn abort_resumable_session(&self, session_url: &str) {
        match self.stream_client.delete(session_url).send().await {
            Ok(resp) => {
                let status = resp.status();
                // GCS returns 499 / 4xx for an aborted session; any non-error
                // outcome means the session is gone.
                if !(status.is_success() || status.as_u16() == 499) {
                    tracing::warn!(
                        status = %status,
                        "GCS resumable session abort returned unexpected status"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "GCS resumable session abort request failed");
            }
        }
    }

    /// Query the confirmed offset of a resumable session. GCS replies 308 with
    /// a `Range: bytes=0-N` header indicating bytes it has durably received
    /// (so the next byte to send is N+1). No `Range` header means zero bytes
    /// confirmed. A 2xx means the object is already finalized.
    ///
    /// Returns `Some(next_offset)` for an in-progress session, `None` if the
    /// session is already complete.
    async fn query_resumable_offset(
        &self,
        session_url: &str,
        total: Option<u64>,
    ) -> Result<Option<u64>> {
        let resp = self
            .stream_client
            .put(session_url)
            .header("Content-Length", "0")
            .header("Content-Range", content_range(0, 0, total))
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("GCS resumable status query failed: {}", e)))?;

        let status = resp.status().as_u16();
        if resp.status().is_success() {
            // Already finalized.
            return Ok(None);
        }
        if status != 308 {
            let body = resp.text().await.unwrap_or_default();
            return Err(map_status_error(
                status,
                "GCS resumable status query failed",
                &body,
            ));
        }

        // No Range header on a 308 means GCS has durably received zero bytes,
        // so the next byte to send is offset 0.
        let range_header = match resp.headers().get("Range") {
            None => return Ok(Some(0)),
            Some(v) => v,
        };

        // A present Range header must be exactly "bytes=0-N" (resumable uploads
        // always start at byte 0). Anything else is malformed: rather than
        // silently resyncing to offset 0 (which would re-PUT already-accepted
        // bytes and can leave the session in a mismatched state), fail the chunk
        // so the upload aborts cleanly.
        let parsed = range_header
            .to_str()
            .ok()
            .and_then(parse_resumable_range_next)
            .ok_or_else(|| {
                let raw = range_header.to_str().unwrap_or("<non-utf8>").to_string();
                AppError::Storage(format!(
                    "GCS resumable status query returned malformed Range header: {:?}",
                    raw
                ))
            })?;
        Ok(Some(parsed))
    }

    /// Issue an explicit terminal finalize PUT (`Content-Range: bytes */<total>`,
    /// zero-length body) and require a 2xx response.
    ///
    /// A 308-confirmed offset from `query_resumable_offset` only means GCS has
    /// durably *received* every byte; it does NOT mean the object is finalized.
    /// GCS only finalizes when a PUT declares the total size and it answers
    /// 200/201. On a resumed final chunk the total may only have been declared
    /// on the PUT that failed, so the session can still be open even though all
    /// bytes landed. This terminal PUT closes that gap: we treat the upload as
    /// done only once GCS confirms finalization with a 2xx. A non-2xx (other
    /// than a transient that the caller may retry) is surfaced as an error.
    async fn finalize_resumable(&self, session_url: &str, total: u64) -> Result<()> {
        let range = content_range(0, 0, Some(total));
        let resp = self
            .stream_client
            .put(session_url)
            .header("Content-Length", "0")
            .header("Content-Range", &range)
            .body(Vec::<u8>::new())
            .send()
            .await
            .map_err(|e| {
                AppError::ServiceUnavailable(format!(
                    "GCS resumable finalize (range {}) network error: {}",
                    range, e
                ))
            })?;

        if resp.status().is_success() {
            return Ok(());
        }

        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        Err(map_status_error(
            status,
            &format!("GCS resumable finalize (range {}) not confirmed", range),
            &body,
        ))
    }

    /// PUT one resumable chunk with bounded retry on transient failures.
    ///
    /// `start` is the absolute offset of the first byte; `final_total` is
    /// `Some(total)` for the terminal chunk, `None` otherwise. On a transient
    /// status (429/5xx) or a network error the chunk is retried after a short
    /// backoff; before each retry we query the confirmed offset and slice the
    /// already-accepted prefix off the chunk so we resume cleanly rather than
    /// re-sending bytes GCS already has.
    ///
    /// Returns the new absolute offset after the chunk is accepted.
    async fn put_chunk_with_retry(
        &self,
        session_url: &str,
        start: u64,
        chunk: Vec<u8>,
        final_total: Option<u64>,
    ) -> Result<u64> {
        let mut offset = start;
        let mut body = chunk;
        let chunk_end_exclusive = start + body.len() as u64;
        let mut last_err: Option<AppError> = None;

        for attempt in 1..=CHUNK_MAX_ATTEMPTS {
            let len = body.len() as u64;
            let range = content_range(offset, len, final_total);

            let send_result = self
                .stream_client
                .put(session_url)
                .header("Content-Length", len.to_string())
                .header("Content-Range", &range)
                .body(body.clone())
                .send()
                .await;

            match send_result {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let ok = if final_total.is_some() {
                        // Final chunk: GCS finalizes with 200/201.
                        resp.status().is_success()
                    } else {
                        // Intermediate chunk: 308 Resume Incomplete.
                        status == 308
                    };
                    if ok {
                        return Ok(chunk_end_exclusive);
                    }

                    if is_transient_status(status) && attempt < CHUNK_MAX_ATTEMPTS {
                        last_err = Some(map_status_error(
                            status,
                            &format!("GCS resumable PUT (range {})", range),
                            "",
                        ));
                    } else {
                        let resp_body = resp.text().await.unwrap_or_default();
                        return Err(map_status_error(
                            status,
                            &format!("GCS resumable PUT (range {}) returned {}", range, status),
                            &resp_body,
                        ));
                    }
                }
                Err(e) => {
                    if attempt < CHUNK_MAX_ATTEMPTS {
                        last_err = Some(AppError::ServiceUnavailable(format!(
                            "GCS resumable PUT (range {}) network error: {}",
                            range, e
                        )));
                    } else {
                        return Err(AppError::ServiceUnavailable(format!(
                            "GCS resumable PUT (range {}) network error: {}",
                            range, e
                        )));
                    }
                }
            }

            // Backoff, then resync against the confirmed offset so we don't
            // resend bytes GCS already durably accepted.
            tokio::time::sleep(Duration::from_millis(200 * attempt as u64)).await;
            match self.query_resumable_offset(session_url, final_total).await {
                Ok(None) => {
                    // The status query saw a 2xx: the object is already
                    // finalized. This is the only signal that confirms
                    // finalization, so it is safe to report success.
                    return Ok(chunk_end_exclusive);
                }
                Ok(Some(confirmed_next)) => {
                    if confirmed_next >= chunk_end_exclusive {
                        // Every byte of this chunk landed during the failed
                        // attempt, but a 308 only confirms bytes RECEIVED, not
                        // a finalized object. For the terminal chunk we must
                        // still send an explicit finalize PUT and require a 2xx
                        // before reporting success, otherwise we would return Ok
                        // on a session GCS never closed.
                        if let Some(total) = final_total {
                            self.finalize_resumable(session_url, total).await?;
                        }
                        return Ok(chunk_end_exclusive);
                    }
                    if confirmed_next > offset {
                        let drop = (confirmed_next - offset) as usize;
                        body.drain(0..drop.min(body.len()));
                        offset = confirmed_next;
                    }
                }
                Err(e) => {
                    // A status query that itself fails (e.g. malformed Range,
                    // see parse_resumable_range_next) is not recoverable: abort
                    // the chunk rather than blindly resending from a guessed
                    // offset.
                    return Err(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            AppError::ServiceUnavailable("GCS resumable PUT exhausted retries".to_string())
        }))
    }

    /// Drive the resumable upload loop after the session is initiated.
    ///
    /// `initial` is the first buffer already read by `put_stream` (guaranteed
    /// to be at least one full chunk when this is called). `stream_done`
    /// indicates whether `initial` is the entire remaining input. The hasher is
    /// updated by the caller as bytes are read, so this method does not hash.
    ///
    /// Intermediate PUTs send exactly `RESUMABLE_CHUNK_SIZE` bytes (256-KiB
    /// aligned); the remainder is carried forward. The final PUT carries the
    /// known total so GCS finalizes the object. An upload that ends exactly on
    /// a chunk boundary still sends a terminal zero-length `PUT bytes */<total>`
    /// to finalize.
    ///
    /// Returns the total number of bytes written.
    async fn stream_resumable_chunks(
        &self,
        session_url: &str,
        hasher: &mut sha2::Sha256,
        initial: Vec<u8>,
        stream: &mut BoxStream<'static, Result<Bytes>>,
        mut stream_done: bool,
    ) -> Result<u64> {
        let mut buffer = initial;
        let mut total_bytes: u64 = 0;

        loop {
            // Top up the buffer to at least one chunk (unless the stream ended).
            while buffer.len() < RESUMABLE_CHUNK_SIZE && !stream_done {
                match stream.next().await {
                    Some(Ok(bytes)) => {
                        hasher.update(&bytes);
                        buffer.extend_from_slice(&bytes);
                    }
                    Some(Err(e)) => {
                        return Err(AppError::Storage(format!(
                            "stream read error during GCS upload: {}",
                            e
                        )));
                    }
                    None => stream_done = true,
                }
            }

            if stream_done {
                // Final flush: send everything left as the terminal chunk with
                // the known total so GCS finalizes the object.
                let final_total = total_bytes + buffer.len() as u64;

                if buffer.is_empty() {
                    // Upload ended exactly on a chunk boundary. Send a terminal
                    // zero-length PUT so GCS finalizes (it has all bytes but has
                    // not been told the total yet).
                    let _ = self
                        .put_chunk_with_retry(
                            session_url,
                            total_bytes,
                            Vec::new(),
                            Some(final_total),
                        )
                        .await?;
                } else {
                    let chunk = std::mem::take(&mut buffer);
                    total_bytes = self
                        .put_chunk_with_retry(session_url, total_bytes, chunk, Some(final_total))
                        .await?;
                }
                return Ok(total_bytes);
            }

            // Intermediate flush: send exactly one 256-KiB-aligned chunk and
            // carry the overshoot into the next iteration.
            debug_assert!(buffer.len() >= RESUMABLE_CHUNK_SIZE);
            let remainder = buffer.split_off(RESUMABLE_CHUNK_SIZE);
            let chunk = std::mem::replace(&mut buffer, remainder);
            total_bytes = self
                .put_chunk_with_retry(session_url, total_bytes, chunk, None)
                .await?;
        }
    }
}

// ---------------------------------------------------------------------------
// StorageBackend trait
// ---------------------------------------------------------------------------

#[async_trait]
impl StorageBackend for GcsBackend {
    async fn put(&self, key: &str, content: Bytes) -> Result<()> {
        let response = self.authorized_put(key, content).await?;
        require_success(response, "GCS upload failed").await?;
        Ok(())
    }

    /// Streaming upload to GCS via the JSON API's resumable-upload protocol.
    /// Splits the input stream into 32 MiB chunks; each chunk is a short PUT to
    /// the session URL. The final chunk sends the known total size; intermediate
    /// chunks use `*` ("more to come") per the GCS spec.
    ///
    /// Why not a single `reqwest::Body::wrap_stream` PUT? That dies on the
    /// gateway timeout for multi-GiB artifacts — Envoy / GCP's HTTPS LB caps an
    /// individual request at ~3 min, which a 3.4 GiB single-shot upload exceeds.
    /// Resumable upload moves the work into many short requests (each chunk PUT
    /// completes in ~1 s on intra-GCP networking), so the per-request budget is
    /// never the bottleneck; total time tracks GCS throughput, not a timeout.
    ///
    /// Chunk alignment: GCS requires every non-final chunk to be an exact
    /// multiple of 256 KiB or it rejects the intermediate `Content-Range` with
    /// HTTP 400. We therefore flush exactly `RESUMABLE_CHUNK_SIZE` bytes per
    /// intermediate PUT (32 MiB is 256-KiB-aligned) and carry the remainder
    /// into the next iteration, never letting an incoming `Bytes` chunk that
    /// straddles the boundary push the request size off the alignment.
    ///
    /// Small objects (the whole stream fits in the first sub-chunk buffer) skip
    /// the resumable handshake entirely and go through a single-shot `put()`,
    /// avoiding two extra round-trips for tiny artifacts the proxy cache writes.
    ///
    /// On any error after the session is initiated the session is aborted with
    /// a best-effort DELETE so GCS does not retain an orphaned upload session.
    async fn put_stream(
        &self,
        key: &str,
        mut stream: BoxStream<'static, Result<Bytes>>,
    ) -> Result<PutStreamResult> {
        use sha2::Sha256 as Sha256Inner;

        let mut hasher = Sha256Inner::new();
        // Accumulate enough to decide whether this is a small object. We buffer
        // up to one full chunk before initiating the session.
        let mut buffer: Vec<u8> = Vec::with_capacity(RESUMABLE_CHUNK_SIZE);
        let mut stream_done = false;

        while buffer.len() < RESUMABLE_CHUNK_SIZE && !stream_done {
            match stream.next().await {
                Some(Ok(bytes)) => {
                    hasher.update(&bytes);
                    buffer.extend_from_slice(&bytes);
                }
                Some(Err(e)) => {
                    return Err(AppError::Storage(format!(
                        "stream read error before GCS upload: {}",
                        e
                    )));
                }
                None => stream_done = true,
            }
        }

        // Small-object fast path: the entire stream fit in the first buffer
        // (strictly less than one chunk). Skip the resumable handshake and do a
        // single-shot upload. Covers zero-byte objects too.
        if stream_done && buffer.len() < RESUMABLE_CHUNK_SIZE {
            let bytes_written = buffer.len() as u64;
            let response = self.authorized_put(key, Bytes::from(buffer)).await?;
            require_success(response, "GCS upload failed").await?;
            return Ok(PutStreamResult {
                checksum_sha256: format!("{:x}", hasher.finalize()),
                bytes_written,
            });
        }

        // Large object: run the resumable protocol. Initiate the session first.
        let session_url = self.initiate_resumable_session(key).await?;

        // From here on, any error must abort the session to avoid leaking it.
        let result = self
            .stream_resumable_chunks(&session_url, &mut hasher, buffer, &mut stream, stream_done)
            .await;

        match result {
            Ok(total_bytes) => Ok(PutStreamResult {
                checksum_sha256: format!("{:x}", hasher.finalize()),
                bytes_written: total_bytes,
            }),
            Err(e) => {
                self.abort_resumable_session(&session_url).await;
                Err(e)
            }
        }
    }

    async fn get(&self, key: &str) -> Result<Bytes> {
        let url = self.object_download_url(key);
        let response = self.authorized_get(&url).await?;

        if response.status().is_success() {
            return response
                .bytes()
                .await
                .map_err(|e| AppError::Storage(format!("Failed to read response: {}", e)));
        }

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            if let Some(bytes) = self.try_fallback_get(key).await? {
                return Ok(bytes);
            }
            return Err(AppError::NotFound(format!("Object not found: {}", key)));
        }

        // Propagate the error via require_success (always fails for non-2xx)
        require_success(response, "GCS download failed").await?;
        unreachable!()
    }

    async fn get_range(&self, key: &str, offset: u64, length: usize) -> Result<Bytes> {
        if length == 0 {
            return Ok(Bytes::new());
        }

        let range_header = download_range_header(offset, length)?;
        let url = self.object_download_url(key);
        let response = self.authorized_get_range(&url, &range_header).await?;

        if response.status() == reqwest::StatusCode::PARTIAL_CONTENT {
            return response
                .bytes()
                .await
                .map_err(|e| AppError::Storage(format!("Failed to read range response: {}", e)));
        }

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            if let Some(bytes) = self.try_fallback_get_range(key, &range_header).await? {
                return Ok(bytes);
            }
            return Err(AppError::NotFound(format!("Object not found: {}", key)));
        }

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        Err(AppError::Storage(format!(
            "GCS ranged download failed with status {} for {} ({}): {}",
            status, key, range_header, body
        )))
    }

    /// Stream the object body without buffering it in a single `Bytes`. The
    /// default trait impl wraps `get()` in a one-item stream, which forces the
    /// entire object onto the heap before the consumer can write it to disk —
    /// for a 3+ GiB scan input that alone can exceed node-allocatable on small
    /// pools and OOM-kill the pod. `bytes_stream()` pulls chunks straight from
    /// the HTTPS connection, keeping the in-flight footprint at reqwest's TCP
    /// read buffer (~64 KiB) instead of object-size.
    async fn get_stream(&self, key: &str) -> Result<BoxStream<'static, Result<Bytes>>> {
        let url = self.object_download_url(key);
        let response = self.authorized_get_stream(&url).await?;

        if response.status().is_success() {
            let stream = response.bytes_stream().map(|r| {
                r.map_err(|e| AppError::Storage(format!("GCS stream chunk read failed: {}", e)))
            });
            return Ok(Box::pin(stream));
        }

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            // The migration-mode Artifactory fallback still buffers
            // (try_fallback_get returns Bytes); wrap it in a single-item stream
            // so the caller's interface stays uniform.
            if let Some(bytes) = self.try_fallback_get(key).await? {
                return Ok(Box::pin(futures::stream::once(async move { Ok(bytes) })));
            }
            return Err(AppError::NotFound(format!("Object not found: {}", key)));
        }

        require_success(response, "GCS download failed").await?;
        unreachable!()
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let url = self.object_metadata_url(key);
        let response = self.authorized_get(&url).await?;

        if response.status().is_success() {
            return Ok(true);
        }

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return self.try_fallback_exists(key).await;
        }

        require_success(response, "GCS exists check failed").await?;
        unreachable!()
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let response = self.authorized_delete(key).await?;

        // 404 is acceptable (already deleted)
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        require_success(response, "GCS delete failed").await?;
        Ok(())
    }

    async fn copy(&self, source: &str, dest: &str) -> Result<()> {
        GcsBackend::copy(self, source, dest).await
    }

    /// Fetch the GCS object's `etag` field via the JSON metadata endpoint
    /// (no body transfer). GCS ETags change on every object replacement,
    /// which makes them suitable for the #1051 fast-path tamper check.
    /// Returns `Ok(None)` for a missing object so the freshness probe can
    /// fall through to the slow path without losing the I/O-error
    /// distinction.
    async fn head_etag(&self, key: &str) -> Result<Option<String>> {
        let url = self.object_metadata_url(key);
        let response = self.authorized_get(&url).await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            require_success(response, "GCS head_etag failed").await?;
            unreachable!();
        }

        // Object metadata is a small JSON blob. We only need the `etag`
        // field; deserialize directly rather than pulling in a full schema.
        #[derive(serde::Deserialize)]
        struct ObjectMeta {
            etag: Option<String>,
        }
        let meta: ObjectMeta = response
            .json()
            .await
            .map_err(|e| AppError::Storage(format!("GCS head_etag: parse metadata json: {}", e)))?;
        Ok(meta.etag)
    }

    fn supports_redirect(&self) -> bool {
        matches!(self.auth, GcsAuthMode::ServiceAccountKey { .. }) && self.config.redirect_downloads
    }

    async fn get_presigned_url(
        &self,
        key: &str,
        expires_in: Duration,
    ) -> Result<Option<PresignedUrl>> {
        if !matches!(self.auth, GcsAuthMode::ServiceAccountKey { .. }) {
            return Ok(None);
        }

        if !self.config.redirect_downloads {
            return Ok(None);
        }

        let url = self.generate_signed_url(key, expires_in)?;

        tracing::debug!(
            key = %key,
            expires_in = ?expires_in,
            "Generated GCS signed URL"
        );

        Ok(Some(PresignedUrl {
            url,
            expires_in,
            source: PresignedUrlSource::Gcs,
        }))
    }

    async fn health_check(&self) -> Result<()> {
        // GET the metadata of a sentinel object (`.health-probe`). This exercises
        // the same object-level permission the backend actually uses at runtime
        // (`storage.objects.get`), so a least-privilege object-scoped credential
        // — e.g. GCS `roles/storage.objectUser` / `roles/storage.objectViewer`,
        // or the S3/Azure equivalents — passes. The old probe hit the bucket
        // metadata endpoint (`GET /storage/v1/b/{bucket}`), which demands
        // `storage.buckets.get` (bucket-admin level), so object-only deployments
        // got 403 and `/health` reported storage unhealthy even though all reads
        // and writes worked (issue #1569).
        //
        // A 404 is healthy: it proves the bucket is reachable, credentials are
        // valid, and object reads are authorized — the probe object simply does
        // not exist. Only transport errors or auth failures indicate a genuinely
        // broken backend.
        let url = self.object_metadata_url(".health-probe");
        let response = self
            .authorized_get(&url)
            .await
            .map_err(|e| AppError::Storage(format!("GCS health check failed: {}", e)))?;

        let status = response.status();
        if status.is_success() || status == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }

        let body = response.text().await.unwrap_or_default();
        Err(AppError::Storage(format!(
            "GCS health check failed (status {}): {}",
            status, body
        )))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Generated test-only RSA key, not used anywhere, safe to commit
    const TEST_PRIVATE_KEY: &str = include_str!("../../test_fixtures/test_rsa_key.pem");

    fn create_test_config() -> GcsConfig {
        GcsConfig {
            bucket: "test-bucket".to_string(),
            project_id: Some("test-project".to_string()),
            service_account_email: Some("test@test-project.iam.gserviceaccount.com".to_string()),
            private_key: Some(TEST_PRIVATE_KEY.to_string()),
            redirect_downloads: true,
            signed_url_expiry: Duration::from_secs(3600),
            path_format: StoragePathFormat::Native,
        }
    }

    async fn create_test_backend() -> GcsBackend {
        GcsBackend::new(create_test_config()).await.unwrap()
    }

    // ---- content_range pure helper (off-by-one lives here) ----

    #[test]
    fn test_content_range_intermediate_chunk() {
        // First 32 MiB chunk, more to come: bytes 0-33554431/*
        assert_eq!(
            content_range(0, RESUMABLE_CHUNK_SIZE as u64, None),
            "bytes 0-33554431/*"
        );
        // Second 32 MiB chunk, more to come.
        assert_eq!(
            content_range(
                RESUMABLE_CHUNK_SIZE as u64,
                RESUMABLE_CHUNK_SIZE as u64,
                None
            ),
            "bytes 33554432-67108863/*"
        );
    }

    #[test]
    fn test_content_range_final_chunk() {
        // A 40 MiB object: final 8 MiB chunk starting at 32 MiB, total known.
        let total = RESUMABLE_CHUNK_SIZE as u64 + 8 * 1024 * 1024;
        assert_eq!(
            content_range(RESUMABLE_CHUNK_SIZE as u64, 8 * 1024 * 1024, Some(total)),
            "bytes 33554432-41943039/41943040"
        );
    }

    #[test]
    fn test_content_range_single_small_object() {
        // 5-byte object as a final chunk from offset 0.
        assert_eq!(content_range(0, 5, Some(5)), "bytes 0-4/5");
    }

    #[test]
    fn test_content_range_zero_length_finalize_on_boundary() {
        // Terminal zero-length PUT when the upload ended on a chunk boundary:
        // GCS already has all bytes, we only need to tell it the total.
        assert_eq!(
            content_range(
                RESUMABLE_CHUNK_SIZE as u64,
                0,
                Some(RESUMABLE_CHUNK_SIZE as u64)
            ),
            "bytes */33554432"
        );
    }

    #[test]
    fn test_content_range_zero_byte_object() {
        assert_eq!(content_range(0, 0, Some(0)), "bytes */0");
    }

    #[test]
    fn test_download_range_header_is_inclusive() {
        assert_eq!(
            download_range_header(1_024, 4_096).unwrap(),
            "bytes=1024-5119"
        );
    }

    #[test]
    fn test_download_range_header_rejects_overflow() {
        let err = download_range_header(u64::MAX - 1, 4).unwrap_err();
        assert!(
            err.to_string().contains("overflows u64"),
            "error should explain overflow: {err}"
        );
    }

    // ---- parse_resumable_range_next pure helper ----

    #[test]
    fn test_parse_resumable_range_next_valid() {
        // bytes=0-N → next offset is N+1.
        assert_eq!(parse_resumable_range_next("bytes=0-0"), Some(1));
        assert_eq!(
            parse_resumable_range_next("bytes=0-16777215"),
            Some(16777216)
        );
        // Case-insensitive on the "bytes=" literal, tolerant of surrounding ws.
        assert_eq!(parse_resumable_range_next("  Bytes=0-9  "), Some(10));
    }

    #[test]
    fn test_parse_resumable_range_next_rejects_malformed() {
        // Non-zero start (resumable uploads always begin at 0).
        assert_eq!(parse_resumable_range_next("bytes=5-10"), None);
        // Missing the "bytes=" prefix.
        assert_eq!(parse_resumable_range_next("0-10"), None);
        assert_eq!(parse_resumable_range_next("0-10/100"), None);
        // No dash separator.
        assert_eq!(parse_resumable_range_next("bytes=0"), None);
        // Non-numeric end.
        assert_eq!(parse_resumable_range_next("bytes=0-abc"), None);
        // Empty / garbage.
        assert_eq!(parse_resumable_range_next(""), None);
        assert_eq!(parse_resumable_range_next("nonsense"), None);
    }

    #[test]
    fn test_content_range_status_query() {
        // Status query uses len 0 with unknown total.
        assert_eq!(content_range(0, 0, None), "bytes */*");
    }

    #[test]
    fn test_is_transient_status() {
        assert!(is_transient_status(429));
        assert!(is_transient_status(500));
        assert!(is_transient_status(503));
        assert!(is_transient_status(599));
        assert!(!is_transient_status(200));
        assert!(!is_transient_status(308));
        assert!(!is_transient_status(400));
        assert!(!is_transient_status(404));
    }

    #[test]
    fn test_map_status_error_transient_is_service_unavailable() {
        assert!(matches!(
            map_status_error(503, "ctx", "body"),
            AppError::ServiceUnavailable(_)
        ));
        assert!(matches!(
            map_status_error(429, "ctx", "body"),
            AppError::ServiceUnavailable(_)
        ));
    }

    #[test]
    fn test_map_status_error_permanent_is_storage() {
        assert!(matches!(
            map_status_error(400, "ctx", "body"),
            AppError::Storage(_)
        ));
        assert!(matches!(
            map_status_error(403, "ctx", "body"),
            AppError::Storage(_)
        ));
    }

    #[tokio::test]
    async fn test_get_stream_success() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let body = b"streamed body contents".to_vec();
        Mock::given(method("GET"))
            .and(path_regex("/storage/v1/b/.*/o/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        let mut stream = backend.get_stream("test/file.txt").await.unwrap();
        let mut collected = Vec::new();
        while let Some(chunk) = stream.next().await {
            collected.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(collected, body);
    }

    #[tokio::test]
    async fn test_get_stream_not_found() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex("/storage/v1/b/.*/o/.*"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        match backend.get_stream("missing.txt").await {
            Err(AppError::NotFound(_)) => {}
            Err(e) => panic!("Expected NotFound, got {:?}", e),
            Ok(_) => panic!("Expected NotFound, got Ok stream"),
        }
    }

    #[tokio::test]
    async fn test_get_range_sends_http_range_header() {
        use wiremock::matchers::{header, method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex("/storage/v1/b/.*/o/test%2Ffile\\.txt"))
            .and(header("range", "bytes=5-12"))
            .respond_with(ResponseTemplate::new(206).set_body_bytes(Vec::from(&b"fghijklm"[..])))
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        let bytes = backend.get_range("test/file.txt", 5, 8).await.unwrap();

        assert_eq!(bytes, Bytes::from_static(b"fghijklm"));
    }

    #[tokio::test]
    async fn test_get_range_fallback_sends_http_range_header() {
        use wiremock::matchers::{header, method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let checksum = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
        Mock::given(method("GET"))
            .and(path_regex(
                "/storage/v1/b/.*/o/repos%2Fgeneric%2Fabcdefabcdef",
            ))
            .and(header("range", "bytes=10-15"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex("/storage/v1/b/.*/o/ab%2Fabcdefabcdef"))
            .and(header("range", "bytes=10-15"))
            .respond_with(ResponseTemplate::new(206).set_body_bytes(Vec::from(&b"klmnop"[..])))
            .mount(&server)
            .await;

        let backend =
            mock_backend_with_path_format(&server.uri(), StoragePathFormat::Migration).await;
        let bytes = backend
            .get_range(&format!("repos/generic/{checksum}"), 10, 6)
            .await
            .unwrap();

        assert_eq!(bytes, Bytes::from_static(b"klmnop"));
    }

    // ---- Backend creation ----

    #[tokio::test]
    async fn test_gcs_backend_creation() {
        let backend = GcsBackend::new(create_test_config()).await;
        assert!(backend.is_ok());
    }

    #[tokio::test]
    async fn test_gcs_backend_creation_without_key() {
        let mut config = create_test_config();
        config.private_key = None;

        let backend = GcsBackend::new(config).await;
        assert!(backend.is_ok());
        assert!(!backend.unwrap().supports_redirect());
    }

    // ---- Auth mode resolution ----

    #[tokio::test]
    async fn test_auth_mode_service_account_key_with_private_key() {
        let backend = create_test_backend().await;
        assert!(matches!(
            backend.auth,
            GcsAuthMode::ServiceAccountKey { .. }
        ));
    }

    #[tokio::test]
    async fn test_auth_mode_adc_without_private_key() {
        let mut config = create_test_config();
        config.private_key = None;
        let backend = GcsBackend::new(config).await.unwrap();
        assert!(matches!(backend.auth, GcsAuthMode::Adc { .. }));
    }

    // ---- V4 signed URL generation ----

    #[tokio::test]
    async fn test_signed_url_generation() {
        let backend = create_test_backend().await;

        let url = backend
            .generate_signed_url("test/artifact.txt", Duration::from_secs(3600))
            .unwrap();

        assert!(url.contains("storage.googleapis.com"));
        assert!(url.contains("test-bucket"));
        assert!(url.contains("test/artifact.txt"));
        assert!(
            url.contains("X-Goog-Algorithm=GOOG4-RSA-SHA256"),
            "Missing algorithm"
        );
        assert!(url.contains("X-Goog-Credential="), "Missing credential");
        assert!(url.contains("X-Goog-Date="), "Missing date");
        assert!(url.contains("X-Goog-Expires="), "Missing expires");
        assert!(
            url.contains("X-Goog-SignedHeaders=host"),
            "Missing signed headers"
        );
        assert!(url.contains("X-Goog-Signature="), "Missing signature");
    }

    #[tokio::test]
    async fn test_expiry_capped_at_7_days() {
        let backend = create_test_backend().await;

        let url = backend
            .generate_signed_url("test.txt", Duration::from_secs(30 * 24 * 3600))
            .unwrap();
        assert!(url.contains("X-Goog-Expires=604800"));
    }

    #[tokio::test]
    async fn test_signed_url_without_key_returns_error() {
        let mut config = create_test_config();
        config.private_key = None;
        let backend = GcsBackend::new(config).await.unwrap();
        assert!(backend
            .generate_signed_url("test.txt", Duration::from_secs(3600))
            .is_err());
    }

    #[tokio::test]
    async fn test_signed_url_different_keys_different_urls() {
        let backend = create_test_backend().await;

        let url1 = backend
            .generate_signed_url("file1.txt", Duration::from_secs(3600))
            .unwrap();
        let url2 = backend
            .generate_signed_url("file2.txt", Duration::from_secs(3600))
            .unwrap();
        assert_ne!(url1, url2);
    }

    // ---- Redirect / presigned URL ----

    #[tokio::test]
    async fn test_supports_redirect() {
        let mut config = create_test_config();
        config.redirect_downloads = false;

        let backend = GcsBackend::new(config.clone()).await.unwrap();
        assert!(!backend.supports_redirect());

        let config_with_redirect = config.with_redirect_downloads(true);
        let backend = GcsBackend::new(config_with_redirect).await.unwrap();
        assert!(backend.supports_redirect());
    }

    #[tokio::test]
    async fn test_supports_redirect_requires_key() {
        let mut config = create_test_config();
        config.redirect_downloads = true;
        config.private_key = None;

        let backend = GcsBackend::new(config).await.unwrap();
        assert!(!backend.supports_redirect());
    }

    #[tokio::test]
    async fn test_get_presigned_url_returns_none_when_disabled() {
        let config = create_test_config().with_redirect_downloads(false);
        let backend = GcsBackend::new(config).await.unwrap();

        let result = backend
            .get_presigned_url("test.txt", Duration::from_secs(3600))
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_get_presigned_url_returns_url_when_enabled() {
        let backend = create_test_backend().await;

        let presigned = backend
            .get_presigned_url("test.txt", Duration::from_secs(3600))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(presigned.source, PresignedUrlSource::Gcs);
        assert!(presigned.url.contains("X-Goog-Signature="));
    }

    #[tokio::test]
    async fn test_presigned_url_expiry_preserved() {
        let backend = create_test_backend().await;

        let expires = Duration::from_secs(1800);
        let presigned = backend
            .get_presigned_url("test.txt", expires)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(presigned.expires_in, expires);
    }

    #[tokio::test]
    async fn test_adc_mode_supports_redirect_false() {
        let config = GcsConfig {
            bucket: "test-bucket".to_string(),
            project_id: None,
            service_account_email: None,
            private_key: None,
            redirect_downloads: true,
            signed_url_expiry: Duration::from_secs(3600),
            path_format: StoragePathFormat::Native,
        };
        let backend = GcsBackend::new(config).await.unwrap();
        assert!(
            !backend.supports_redirect(),
            "ADC mode must never return true for supports_redirect"
        );
    }

    #[tokio::test]
    async fn test_mode_a_supports_redirect_with_key_and_flag() {
        let backend = GcsBackend::new(create_test_config()).await.unwrap();
        assert!(
            backend.supports_redirect(),
            "Mode A with key and redirect_downloads=true should support redirect"
        );
    }

    #[tokio::test]
    async fn test_adc_mode_get_presigned_url_returns_none() {
        let config = GcsConfig {
            bucket: "test-bucket".to_string(),
            project_id: None,
            service_account_email: None,
            private_key: None,
            redirect_downloads: true,
            signed_url_expiry: Duration::from_secs(3600),
            path_format: StoragePathFormat::Native,
        };
        let backend = GcsBackend::new(config).await.unwrap();
        let result = backend
            .get_presigned_url("test.txt", Duration::from_secs(3600))
            .await
            .unwrap();
        assert!(
            result.is_none(),
            "ADC mode get_presigned_url must return None"
        );
    }

    // ---- URL format ----

    #[tokio::test]
    async fn test_object_url_format() {
        let backend = create_test_backend().await;
        assert_eq!(
            backend.object_url("path/to/artifact.jar"),
            "https://storage.googleapis.com/test-bucket/path/to/artifact.jar"
        );
    }

    #[tokio::test]
    async fn test_object_url_variants() {
        let backend = create_test_backend().await;

        assert_eq!(
            backend.object_url("path/with spaces/file.tar.gz"),
            "https://storage.googleapis.com/test-bucket/path/with spaces/file.tar.gz"
        );

        let nested = backend.object_url("a/b/c/d/e/f.bin");
        assert!(nested.starts_with("https://storage.googleapis.com/test-bucket/"));
        assert!(nested.ends_with("a/b/c/d/e/f.bin"));
    }

    #[tokio::test]
    async fn test_object_download_url_format() {
        let backend = create_test_backend().await;
        let url = backend.object_download_url("repos/maven/artifact.jar");
        assert!(url.contains("/storage/v1/b/"));
        assert!(url.contains("?alt=media"));
        assert!(url.contains("repos%2Fmaven%2Fartifact.jar"));
    }

    #[tokio::test]
    async fn test_object_metadata_url_format() {
        let backend = create_test_backend().await;
        let url = backend.object_metadata_url("repos/maven/artifact.jar");
        assert!(url.contains("/storage/v1/b/"));
        assert!(!url.contains("alt=media"));
        assert!(url.contains("repos%2Fmaven%2Fartifact.jar"));
    }

    #[tokio::test]
    async fn test_upload_url_format() {
        let backend = create_test_backend().await;
        let url = backend.upload_url("repos/maven/artifact.jar");
        assert!(url.contains("/upload/storage/v1/b/"));
        assert!(url.contains("uploadType=media"));
        assert!(url.contains("name=repos%2Fmaven%2Fartifact.jar"));
    }

    // ---- Fallback paths ----

    #[tokio::test]
    async fn test_try_artifactory_fallback_valid_checksum() {
        let backend = create_test_backend().await;

        let key = "repos/maven/abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        assert_eq!(
            backend.try_artifactory_fallback(key).unwrap(),
            "ab/abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
        );
    }

    #[tokio::test]
    async fn test_try_artifactory_fallback_rejected_inputs() {
        let backend = create_test_backend().await;

        // Too short
        assert!(backend
            .try_artifactory_fallback("repos/maven/abc123")
            .is_none());
        // Non-hex chars (64 chars but 'g' is not hex)
        assert!(backend
            .try_artifactory_fallback(
                "repos/maven/gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"
            )
            .is_none());
        // Too few path components (only 1)
        assert!(backend
            .try_artifactory_fallback(
                "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
            )
            .is_none());
    }

    // ---- Key parsing / config ----

    #[test]
    fn test_invalid_private_key() {
        let mut config = create_test_config();
        config.private_key = Some("not a valid PEM key".to_string());

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(GcsBackend::new(config));
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_escaped_newlines_in_key() {
        let mut config = create_test_config();
        config.private_key = Some(TEST_PRIVATE_KEY.replace('\n', "\\n"));

        let backend = GcsBackend::new(config).await;
        assert!(backend.is_ok());
    }

    #[test]
    fn test_gcs_config_builder_redirect_downloads() {
        let config = create_test_config().with_redirect_downloads(false);
        assert!(!config.redirect_downloads);
        let config = config.with_redirect_downloads(true);
        assert!(config.redirect_downloads);
    }

    #[test]
    fn test_gcs_config_builder_signed_url_expiry() {
        let config = create_test_config().with_signed_url_expiry(Duration::from_secs(7200));
        assert_eq!(config.signed_url_expiry, Duration::from_secs(7200));
    }

    #[test]
    fn test_gcs_config_builder_private_key() {
        let mut config = create_test_config();
        config.private_key = None;
        assert!(config.private_key.is_none());
        let config = config.with_private_key("test-key".to_string());
        assert_eq!(config.private_key, Some("test-key".to_string()));
    }

    #[test]
    fn test_gcs_config_clone() {
        let config = create_test_config();
        let cloned = config.clone();
        assert_eq!(cloned.bucket, "test-bucket");
        assert_eq!(cloned.project_id, Some("test-project".to_string()));
        assert_eq!(cloned.service_account_email, config.service_account_email);
    }

    // ---- Token cache validity ----

    #[test]
    fn test_token_cache_validity() {
        // A token expiring in 120s has >60s buffer: valid
        let valid = CachedToken {
            token: "ya29.valid".to_string(),
            expires_at: Instant::now() + Duration::from_secs(120),
        };
        assert!(
            valid.expires_at > Instant::now() + Duration::from_secs(60),
            "Token with 120s remaining should be considered valid"
        );

        // A token expiring in 30s has <60s buffer: needs refresh
        let expiring = CachedToken {
            token: "ya29.expiring".to_string(),
            expires_at: Instant::now() + Duration::from_secs(30),
        };
        assert!(
            expiring.expires_at <= Instant::now() + Duration::from_secs(60),
            "Token with 30s remaining should trigger a refresh"
        );

        // An already-expired token also needs refresh
        let expired = CachedToken {
            token: "ya29.expired".to_string(),
            expires_at: Instant::now() - Duration::from_secs(1),
        };
        assert!(
            expired.expires_at <= Instant::now() + Duration::from_secs(60),
            "Expired token should trigger a refresh"
        );
    }

    // ---- from_env() tests ----

    // Serialize env-var tests to avoid cross-test interference.
    static ENV_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();

    fn env_lock() -> &'static std::sync::Mutex<()> {
        ENV_LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    #[test]
    fn test_from_env_adc_mode_only_bucket() {
        let _guard = env_lock().lock().unwrap();
        std::env::remove_var("GCS_PROJECT_ID");
        std::env::remove_var("GCS_SERVICE_ACCOUNT_EMAIL");
        std::env::remove_var("GCS_PRIVATE_KEY");
        std::env::remove_var("GCS_PRIVATE_KEY_PATH");
        std::env::remove_var("GCS_REDIRECT_DOWNLOADS");
        std::env::remove_var("GCS_SIGNED_URL_EXPIRY");
        std::env::set_var("GCS_BUCKET", "adc-bucket");

        let result = GcsConfig::from_env();
        std::env::remove_var("GCS_BUCKET");

        assert!(
            result.is_ok(),
            "ADC mode should succeed with only GCS_BUCKET"
        );
        let config = result.unwrap();
        assert_eq!(config.bucket, "adc-bucket");
        assert!(config.project_id.is_none());
        assert!(config.service_account_email.is_none());
        assert!(config.private_key.is_none());
    }

    #[test]
    fn test_from_env_mode_a_full_config() {
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("GCS_BUCKET", "my-bucket");
        std::env::set_var(
            "GCS_PRIVATE_KEY",
            "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----",
        );
        std::env::set_var("GCS_PROJECT_ID", "my-project");
        std::env::set_var(
            "GCS_SERVICE_ACCOUNT_EMAIL",
            "sa@my-project.iam.gserviceaccount.com",
        );
        std::env::remove_var("GCS_PRIVATE_KEY_PATH");

        let result = GcsConfig::from_env();
        std::env::remove_var("GCS_BUCKET");
        std::env::remove_var("GCS_PRIVATE_KEY");
        std::env::remove_var("GCS_PROJECT_ID");
        std::env::remove_var("GCS_SERVICE_ACCOUNT_EMAIL");

        assert!(
            result.is_ok(),
            "Mode A full config should succeed in from_env"
        );
        let config = result.unwrap();
        assert_eq!(config.bucket, "my-bucket");
        assert_eq!(config.project_id, Some("my-project".to_string()));
        assert!(config.private_key.is_some());
    }

    #[test]
    fn test_from_env_fails_without_bucket() {
        let _guard = env_lock().lock().unwrap();
        std::env::remove_var("GCS_BUCKET");
        std::env::remove_var("GCS_PRIVATE_KEY");
        std::env::remove_var("GCS_PRIVATE_KEY_PATH");

        let result = GcsConfig::from_env();
        assert!(result.is_err(), "Should fail without GCS_BUCKET");
    }

    #[test]
    fn test_from_env_fails_mode_a_without_project_id() {
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("GCS_BUCKET", "my-bucket");
        std::env::set_var("GCS_PRIVATE_KEY", "some-key");
        std::env::remove_var("GCS_PRIVATE_KEY_PATH");
        std::env::remove_var("GCS_PROJECT_ID");
        std::env::set_var(
            "GCS_SERVICE_ACCOUNT_EMAIL",
            "sa@my-project.iam.gserviceaccount.com",
        );

        let result = GcsConfig::from_env();
        std::env::remove_var("GCS_BUCKET");
        std::env::remove_var("GCS_PRIVATE_KEY");
        std::env::remove_var("GCS_SERVICE_ACCOUNT_EMAIL");

        assert!(result.is_err(), "Mode A should fail without GCS_PROJECT_ID");
    }

    #[test]
    fn test_from_env_fails_mode_a_without_service_account_email() {
        let _guard = env_lock().lock().unwrap();
        std::env::set_var("GCS_BUCKET", "my-bucket");
        std::env::set_var("GCS_PRIVATE_KEY", "some-key");
        std::env::remove_var("GCS_PRIVATE_KEY_PATH");
        std::env::set_var("GCS_PROJECT_ID", "my-project");
        std::env::remove_var("GCS_SERVICE_ACCOUNT_EMAIL");

        let result = GcsConfig::from_env();
        std::env::remove_var("GCS_BUCKET");
        std::env::remove_var("GCS_PRIVATE_KEY");
        std::env::remove_var("GCS_PROJECT_ID");

        assert!(
            result.is_err(),
            "Mode A should fail without GCS_SERVICE_ACCOUNT_EMAIL"
        );
    }

    // ---- require_success helper (tested via wiremock) ----

    #[tokio::test]
    async fn test_require_success_passes_2xx() {
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&server)
            .await;

        let resp = reqwest::get(&server.uri()).await.unwrap();
        assert!(require_success(resp, "test").await.is_ok());
    }

    #[tokio::test]
    async fn test_require_success_rejects_4xx() {
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
            .mount(&server)
            .await;

        let resp = reqwest::get(&server.uri()).await.unwrap();
        let err = require_success(resp, "auth check").await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("auth check"), "error: {}", msg);
        assert!(msg.contains("403"), "error: {}", msg);
    }

    #[tokio::test]
    async fn test_require_success_rejects_5xx() {
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .mount(&server)
            .await;

        let resp = reqwest::get(&server.uri()).await.unwrap();
        let err = require_success(resp, "server op").await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("500"), "error: {}", msg);
    }

    // ---- Wiremock-based StorageBackend tests ----

    /// Create an ADC-mode GcsBackend pointed at the given base URL with a
    /// pre-seeded token cache so it never contacts the metadata server.
    async fn mock_backend_with_path_format(
        base_url: &str,
        path_format: StoragePathFormat,
    ) -> GcsBackend {
        let config = GcsConfig {
            bucket: "test-bucket".to_string(),
            project_id: None,
            service_account_email: None,
            private_key: None,
            redirect_downloads: false,
            signed_url_expiry: Duration::from_secs(3600),
            path_format,
        };
        let client = reqwest::Client::new();
        let provider = GcsTokenProvider::new(TokenSource::MetadataServer, client.clone());

        // Seed the token cache so get_token() never hits the metadata server
        {
            let mut cache = provider.cache.write().await;
            *cache = Some(CachedToken {
                token: "mock-token".to_string(),
                expires_at: Instant::now() + Duration::from_secs(3600),
            });
        }

        GcsBackend {
            config,
            stream_client: client.clone(),
            client,
            auth: GcsAuthMode::Adc { provider },
            path_format,
            base_url: base_url.to_string(),
        }
    }

    async fn mock_backend(base_url: &str) -> GcsBackend {
        mock_backend_with_path_format(base_url, StoragePathFormat::Native).await
    }

    #[tokio::test]
    async fn test_put_success() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex("/upload/storage/v1/b/.*/o"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        let result = backend.put("test/file.txt", Bytes::from("hello")).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_put_server_error() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex("/upload/storage/v1/b/.*/o"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        let result = backend.put("test/file.txt", Bytes::from("hello")).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("500"));
    }

    // ---- put_stream (resumable upload) tests ----

    /// Build a stream from a list of byte chunks for put_stream input.
    fn stream_of(chunks: Vec<Vec<u8>>) -> BoxStream<'static, Result<Bytes>> {
        let items: Vec<Result<Bytes>> = chunks.into_iter().map(|c| Ok(Bytes::from(c))).collect();
        Box::pin(futures::stream::iter(items))
    }

    #[tokio::test]
    async fn test_put_stream_small_object_single_shot() {
        // A sub-chunk object must take the single-shot put() fast path: a POST
        // to the simple upload endpoint, never a resumable initiate.
        use wiremock::matchers::{method, path_regex, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Simple upload (uploadType=media) — the fast path.
        Mock::given(method("POST"))
            .and(path_regex("/upload/storage/v1/b/.*/o"))
            .and(query_param("uploadType", "media"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        let data = b"a small artifact".to_vec();
        let result = backend
            .put_stream("repos/small.txt", stream_of(vec![data.clone()]))
            .await
            .unwrap();
        assert_eq!(result.bytes_written, data.len() as u64);
        // sha256 of the payload must match.
        let expected = {
            let mut h = sha2::Sha256::new();
            h.update(&data);
            format!("{:x}", h.finalize())
        };
        assert_eq!(result.checksum_sha256, expected);
    }

    #[tokio::test]
    async fn test_put_stream_zero_byte_single_shot() {
        use wiremock::matchers::{method, path_regex, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex("/upload/storage/v1/b/.*/o"))
            .and(query_param("uploadType", "media"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        let result = backend
            .put_stream("repos/empty.txt", stream_of(vec![]))
            .await
            .unwrap();
        assert_eq!(result.bytes_written, 0);
        // sha256 of empty input.
        assert_eq!(
            result.checksum_sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[tokio::test]
    async fn test_put_stream_multi_chunk_alignment_and_finalize() {
        // Feed > 32 MiB so the resumable protocol runs with an intermediate
        // 256-KiB-aligned chunk followed by a final chunk carrying the total.
        use wiremock::matchers::{header, method, path_regex, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let session_path = "/resumable-session/abc123";
        let location = format!("{}{}", server.uri(), session_path);

        // Initiate resumable session.
        Mock::given(method("POST"))
            .and(path_regex("/upload/storage/v1/b/.*/o"))
            .and(query_param("uploadType", "resumable"))
            .respond_with(ResponseTemplate::new(200).insert_header("Location", location.as_str()))
            .expect(1)
            .mount(&server)
            .await;

        // Intermediate chunk: exactly 32 MiB, range bytes 0-33554431/* → 308.
        Mock::given(method("PUT"))
            .and(path_regex(session_path))
            .and(header("Content-Range", "bytes 0-33554431/*"))
            .respond_with(ResponseTemplate::new(308))
            .expect(1)
            .mount(&server)
            .await;

        // Final chunk: remaining 9 MiB, range bytes 33554432-.../41943040 → 200.
        let total = RESUMABLE_CHUNK_SIZE + 9 * 1024 * 1024;
        let final_range = format!("bytes 33554432-{}/{}", total - 1, total);
        Mock::given(method("PUT"))
            .and(path_regex(session_path))
            .and(header("Content-Range", final_range.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        // Feed in oddly-sized chunks that straddle the 32 MiB boundary to prove
        // the buffer re-alignment: 20 MiB + 20 MiB + 1 MiB = 41 MiB total. The
        // first 32 MiB must be sent as one aligned intermediate chunk and the
        // remaining 9 MiB as the final chunk, regardless of the input framing.
        let part = 20 * 1024 * 1024;
        let chunks = vec![
            vec![0xABu8; part],
            vec![0xCDu8; part],
            vec![0xEFu8; total - 2 * part],
        ];
        let result = backend
            .put_stream("repos/big.bin", stream_of(chunks))
            .await
            .unwrap();
        assert_eq!(result.bytes_written, total as u64);
    }

    #[tokio::test]
    async fn test_put_stream_finalize_on_exact_boundary() {
        // Upload ends exactly on a 32 MiB boundary → one intermediate 308 PUT
        // plus a terminal zero-length PUT (bytes */<total>) to finalize.
        use wiremock::matchers::{header, method, path_regex, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let session_path = "/resumable-session/boundary";
        let location = format!("{}{}", server.uri(), session_path);

        Mock::given(method("POST"))
            .and(path_regex("/upload/storage/v1/b/.*/o"))
            .and(query_param("uploadType", "resumable"))
            .respond_with(ResponseTemplate::new(200).insert_header("Location", location.as_str()))
            .expect(1)
            .mount(&server)
            .await;

        // Intermediate chunk → 308.
        Mock::given(method("PUT"))
            .and(path_regex(session_path))
            .and(header("Content-Range", "bytes 0-33554431/*"))
            .respond_with(ResponseTemplate::new(308))
            .expect(1)
            .mount(&server)
            .await;

        // Terminal zero-length finalize PUT.
        let finalize_range = format!("bytes */{}", RESUMABLE_CHUNK_SIZE);
        Mock::given(method("PUT"))
            .and(path_regex(session_path))
            .and(header("Content-Range", finalize_range.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .expect(1)
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        let result = backend
            .put_stream(
                "repos/exact.bin",
                stream_of(vec![vec![0x11u8; RESUMABLE_CHUNK_SIZE]]),
            )
            .await
            .unwrap();
        assert_eq!(result.bytes_written, RESUMABLE_CHUNK_SIZE as u64);
    }

    #[tokio::test]
    async fn test_put_stream_initiate_missing_location_header() {
        use wiremock::matchers::{method, path_regex, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Initiate succeeds but omits Location → must error.
        Mock::given(method("POST"))
            .and(path_regex("/upload/storage/v1/b/.*/o"))
            .and(query_param("uploadType", "resumable"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        // > 32 MiB so we go through the resumable path (not the small fast path).
        let big = vec![0x22u8; RESUMABLE_CHUNK_SIZE + 1];
        let err = backend
            .put_stream("repos/x.bin", stream_of(vec![big]))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("Location"),
            "error should mention missing Location header: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_put_stream_mid_stream_error_aborts_session() {
        // A stream error after the session is initiated must trigger a
        // best-effort DELETE on the session URL and return Err.
        use wiremock::matchers::{method, path_regex, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let session_path = "/resumable-session/aborted";
        let location = format!("{}{}", server.uri(), session_path);

        Mock::given(method("POST"))
            .and(path_regex("/upload/storage/v1/b/.*/o"))
            .and(query_param("uploadType", "resumable"))
            .respond_with(ResponseTemplate::new(200).insert_header("Location", location.as_str()))
            .mount(&server)
            .await;

        // The abort DELETE on the session URL. Assert it is called exactly once.
        Mock::given(method("DELETE"))
            .and(path_regex(session_path))
            .respond_with(ResponseTemplate::new(499))
            .expect(1)
            .mount(&server)
            .await;

        // Also accept any chunk PUTs that happen before the error (308).
        Mock::given(method("PUT"))
            .and(path_regex(session_path))
            .respond_with(ResponseTemplate::new(308))
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        // First a full chunk (forces resumable + at least one PUT), then an Err.
        let good = vec![0x33u8; RESUMABLE_CHUNK_SIZE];
        let items: Vec<Result<Bytes>> = vec![
            Ok(Bytes::from(good)),
            Ok(Bytes::from(vec![0x44u8; 16])),
            Err(AppError::Storage("simulated upstream read failure".into())),
        ];
        let stream: BoxStream<'static, Result<Bytes>> = Box::pin(futures::stream::iter(items));
        let err = backend.put_stream("repos/fail.bin", stream).await;
        assert!(err.is_err(), "stream error must propagate");
        // Mock .expect(1) on DELETE is verified on server drop.
        drop(server);
    }

    #[tokio::test]
    async fn test_put_stream_retries_on_transient_503() {
        // A chunk PUT that returns 503 once then succeeds must be retried and
        // ultimately succeed without surfacing an error.
        use wiremock::matchers::{header, method, path_regex, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let session_path = "/resumable-session/retry";
        let location = format!("{}{}", server.uri(), session_path);

        Mock::given(method("POST"))
            .and(path_regex("/upload/storage/v1/b/.*/o"))
            .and(query_param("uploadType", "resumable"))
            .respond_with(ResponseTemplate::new(200).insert_header("Location", location.as_str()))
            .mount(&server)
            .await;

        // First intermediate PUT attempt returns 503 (transient).
        Mock::given(method("PUT"))
            .and(path_regex(session_path))
            .and(header("Content-Range", "bytes 0-33554431/*"))
            .respond_with(ResponseTemplate::new(503).set_body_string("slow down"))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;

        // Status query after the failed attempt: 308 with no Range (0 confirmed).
        Mock::given(method("PUT"))
            .and(path_regex(session_path))
            .and(header("Content-Range", "bytes */*"))
            .respond_with(ResponseTemplate::new(308))
            .with_priority(2)
            .mount(&server)
            .await;

        // Retry of the intermediate chunk succeeds with 308.
        Mock::given(method("PUT"))
            .and(path_regex(session_path))
            .and(header("Content-Range", "bytes 0-33554431/*"))
            .respond_with(ResponseTemplate::new(308))
            .with_priority(3)
            .mount(&server)
            .await;

        // Final chunk succeeds.
        let total = RESUMABLE_CHUNK_SIZE + 8;
        let final_range = format!("bytes 33554432-{}/{}", total - 1, total);
        Mock::given(method("PUT"))
            .and(path_regex(session_path))
            .and(header("Content-Range", final_range.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .with_priority(3)
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        let chunks = vec![vec![0x55u8; RESUMABLE_CHUNK_SIZE], vec![0x66u8; 8]];
        let result = backend
            .put_stream("repos/retry.bin", stream_of(chunks))
            .await
            .unwrap();
        assert_eq!(result.bytes_written, total as u64);
    }

    #[tokio::test]
    async fn test_put_stream_resume_from_nonzero_offset() {
        // An intermediate chunk PUT fails transiently, and the status query
        // reports that GCS already durably accepted the first 16 MiB of the
        // 32 MiB chunk (Range: bytes=0-16777215). The retry must resume from
        // byte 16777216 with exactly the remaining 16 MiB body, not resend from
        // 0. This exercises the body.drain / offset = confirmed_next slicing.
        use wiremock::matchers::{header, method, path_regex, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let session_path = "/resumable-session/resume-nonzero";
        let location = format!("{}{}", server.uri(), session_path);

        Mock::given(method("POST"))
            .and(path_regex("/upload/storage/v1/b/.*/o"))
            .and(query_param("uploadType", "resumable"))
            .respond_with(ResponseTemplate::new(200).insert_header("Location", location.as_str()))
            .mount(&server)
            .await;

        // First full-chunk PUT (bytes 0-33554431/*) fails once with 503.
        Mock::given(method("PUT"))
            .and(path_regex(session_path))
            .and(header("Content-Range", "bytes 0-33554431/*"))
            .respond_with(ResponseTemplate::new(503).set_body_string("transient"))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;

        // Status query (bytes */*): 308 with Range showing 16 MiB confirmed, so
        // confirmed_next == 16777216.
        let half = 16 * 1024 * 1024u64;
        Mock::given(method("PUT"))
            .and(path_regex(session_path))
            .and(header("Content-Range", "bytes */*"))
            .respond_with(
                ResponseTemplate::new(308)
                    .insert_header("Range", format!("bytes=0-{}", half - 1).as_str()),
            )
            .with_priority(2)
            .mount(&server)
            .await;

        // Retry must resume from byte 16777216 carrying exactly the remaining
        // 16 MiB. Assert both the start offset (Content-Range) and the remaining
        // body length (Content-Length).
        let resume_range = format!("bytes {}-{}/*", half, RESUMABLE_CHUNK_SIZE - 1);
        Mock::given(method("PUT"))
            .and(path_regex(session_path))
            .and(header("Content-Range", resume_range.as_str()))
            .and(header("Content-Length", half.to_string().as_str()))
            .respond_with(ResponseTemplate::new(308))
            .with_priority(2)
            .expect(1)
            .mount(&server)
            .await;

        // Final chunk carrying the total → 200.
        let total = RESUMABLE_CHUNK_SIZE + 8;
        let final_range = format!("bytes 33554432-{}/{}", total - 1, total);
        Mock::given(method("PUT"))
            .and(path_regex(session_path))
            .and(header("Content-Range", final_range.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .with_priority(2)
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        let chunks = vec![vec![0x77u8; RESUMABLE_CHUNK_SIZE], vec![0x88u8; 8]];
        let result = backend
            .put_stream("repos/resume.bin", stream_of(chunks))
            .await
            .unwrap();
        assert_eq!(result.bytes_written, total as u64);
        // The .expect(1) on the resume PUT is verified on server drop.
        drop(server);
    }

    #[tokio::test]
    async fn test_put_stream_finalize_after_resume() {
        // The FINAL chunk PUT fails transiently, the status query then reports
        // every byte received (308, Range covering the whole object). A 308 only
        // confirms bytes received, NOT a finalized object, so the code must send
        // an explicit terminal finalize PUT (bytes */<total>) and require a 2xx
        // before reporting success.
        use wiremock::matchers::{header, method, path_regex, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let session_path = "/resumable-session/finalize-resume";
        let location = format!("{}{}", server.uri(), session_path);
        let total = RESUMABLE_CHUNK_SIZE + 8;
        let finalize_range = format!("bytes */{}", total);

        Mock::given(method("POST"))
            .and(path_regex("/upload/storage/v1/b/.*/o"))
            .and(query_param("uploadType", "resumable"))
            .respond_with(ResponseTemplate::new(200).insert_header("Location", location.as_str()))
            .mount(&server)
            .await;

        // Intermediate chunk → 308.
        Mock::given(method("PUT"))
            .and(path_regex(session_path))
            .and(header("Content-Range", "bytes 0-33554431/*"))
            .respond_with(ResponseTemplate::new(308))
            .mount(&server)
            .await;

        // Final chunk PUT fails once with 503 (transient).
        let final_range = format!("bytes 33554432-{}/{}", total - 1, total);
        Mock::given(method("PUT"))
            .and(path_regex(session_path))
            .and(header("Content-Range", final_range.as_str()))
            .respond_with(ResponseTemplate::new(503).set_body_string("transient"))
            .with_priority(1)
            .mount(&server)
            .await;

        // Status query (bytes */<total>): first call returns 308 with a Range
        // showing the whole object is durably received.
        Mock::given(method("PUT"))
            .and(path_regex(session_path))
            .and(header("Content-Range", finalize_range.as_str()))
            .respond_with(
                ResponseTemplate::new(308)
                    .insert_header("Range", format!("bytes=0-{}", total - 1).as_str()),
            )
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;

        // Terminal finalize PUT (same bytes */<total> shape) must fire and is
        // answered with 200. Assert it is called exactly once.
        Mock::given(method("PUT"))
            .and(path_regex(session_path))
            .and(header("Content-Range", finalize_range.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .with_priority(2)
            .expect(1)
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        let chunks = vec![vec![0x99u8; RESUMABLE_CHUNK_SIZE], vec![0xAAu8; 8]];
        let result = backend
            .put_stream("repos/finalize.bin", stream_of(chunks))
            .await
            .unwrap();
        assert_eq!(result.bytes_written, total as u64);
        // The .expect(1) on the finalize PUT is verified on server drop.
        drop(server);
    }

    #[tokio::test]
    async fn test_put_stream_finalize_after_resume_non_2xx_errors() {
        // Same resumed-final-chunk path as above, but the terminal finalize PUT
        // comes back non-2xx (the session never closed). The upload must NOT be
        // reported as successful: the error is surfaced to the caller.
        use wiremock::matchers::{header, method, path_regex, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let session_path = "/resumable-session/finalize-fail";
        let location = format!("{}{}", server.uri(), session_path);
        let total = RESUMABLE_CHUNK_SIZE + 8;
        let finalize_range = format!("bytes */{}", total);

        Mock::given(method("POST"))
            .and(path_regex("/upload/storage/v1/b/.*/o"))
            .and(query_param("uploadType", "resumable"))
            .respond_with(ResponseTemplate::new(200).insert_header("Location", location.as_str()))
            .mount(&server)
            .await;

        // The abort DELETE that put_stream issues on failure.
        Mock::given(method("DELETE"))
            .and(path_regex(session_path))
            .respond_with(ResponseTemplate::new(499))
            .mount(&server)
            .await;

        Mock::given(method("PUT"))
            .and(path_regex(session_path))
            .and(header("Content-Range", "bytes 0-33554431/*"))
            .respond_with(ResponseTemplate::new(308))
            .mount(&server)
            .await;

        // Final chunk PUT fails once with 503.
        let final_range = format!("bytes 33554432-{}/{}", total - 1, total);
        Mock::given(method("PUT"))
            .and(path_regex(session_path))
            .and(header("Content-Range", final_range.as_str()))
            .respond_with(ResponseTemplate::new(503).set_body_string("transient"))
            .with_priority(1)
            .mount(&server)
            .await;

        // Status query: 308, whole object received.
        Mock::given(method("PUT"))
            .and(path_regex(session_path))
            .and(header("Content-Range", finalize_range.as_str()))
            .respond_with(
                ResponseTemplate::new(308)
                    .insert_header("Range", format!("bytes=0-{}", total - 1).as_str()),
            )
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&server)
            .await;

        // Terminal finalize PUT returns 500: the object is not finalized.
        Mock::given(method("PUT"))
            .and(path_regex(session_path))
            .and(header("Content-Range", finalize_range.as_str()))
            .respond_with(ResponseTemplate::new(500).set_body_string("finalize failed"))
            .with_priority(2)
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        let chunks = vec![vec![0xBBu8; RESUMABLE_CHUNK_SIZE], vec![0xCCu8; 8]];
        let err = backend
            .put_stream("repos/finalize-fail.bin", stream_of(chunks))
            .await;
        assert!(
            err.is_err(),
            "a non-2xx finalize after resume must be surfaced as an error, got: {:?}",
            err.map(|r| r.bytes_written)
        );
    }

    #[tokio::test]
    async fn test_get_success() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex("/storage/v1/b/.*/o/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"file content".to_vec()))
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        let data = backend.get("test/file.txt").await.unwrap();
        assert_eq!(data.as_ref(), b"file content");
    }

    #[tokio::test]
    async fn test_get_not_found() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex("/storage/v1/b/.*/o/.*"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        let result = backend.get("missing.txt").await;
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), AppError::NotFound(_)),
            "Expected NotFound error"
        );
    }

    #[tokio::test]
    async fn test_get_server_error() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex("/storage/v1/b/.*/o/.*"))
            .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        let result = backend.get("test.txt").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("503"));
    }

    #[tokio::test]
    async fn test_exists_true() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex("/storage/v1/b/.*/o/.*"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"name": "test.txt", "size": "42"})),
            )
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        assert!(backend.exists("test.txt").await.unwrap());
    }

    #[tokio::test]
    async fn test_exists_false() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex("/storage/v1/b/.*/o/.*"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        assert!(!backend.exists("missing.txt").await.unwrap());
    }

    #[tokio::test]
    async fn test_delete_success() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path_regex("/storage/v1/b/.*/o/.*"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        assert!(backend.delete("test.txt").await.is_ok());
    }

    #[tokio::test]
    async fn test_delete_not_found_is_ok() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path_regex("/storage/v1/b/.*/o/.*"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        assert!(
            backend.delete("already-gone.txt").await.is_ok(),
            "Deleting a non-existent object should succeed"
        );
    }

    #[tokio::test]
    async fn test_delete_forbidden() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path_regex("/storage/v1/b/.*/o/.*"))
            .respond_with(ResponseTemplate::new(403).set_body_string("access denied"))
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        let result = backend.delete("protected.txt").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("403"));
    }

    #[tokio::test]
    async fn test_list_single_page() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex("/storage/v1/b/.*/o"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [
                    {"name": "a.txt"},
                    {"name": "b.txt"},
                    {"name": "c.txt"}
                ]
            })))
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        let keys = backend.list(None).await.unwrap();
        assert_eq!(keys, vec!["a.txt", "b.txt", "c.txt"]);
    }

    #[tokio::test]
    async fn test_list_empty() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex("/storage/v1/b/.*/o"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        let keys = backend.list(None).await.unwrap();
        assert!(keys.is_empty());
    }

    #[tokio::test]
    async fn test_copy_success() {
        use wiremock::matchers::{method, path_regex, query_param, query_param_is_missing};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex("/storage/v1/b/.*/o/.*/rewriteTo/b/.*/o/.*"))
            .and(query_param_is_missing("rewriteToken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "done": false,
                "rewriteToken": "continue-copy",
                "totalBytesRewritten": "1048576",
                "objectSize": "2097152"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path_regex("/storage/v1/b/.*/o/.*/rewriteTo/b/.*/o/.*"))
            .and(query_param("rewriteToken", "continue-copy"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "done": true,
                "resource": {"name": "dest.txt"}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        assert!(backend.copy("src.txt", "dest.txt").await.is_ok());
    }

    #[tokio::test]
    async fn test_copy_not_found() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex("/storage/v1/b/.*/o/.*/rewriteTo/b/.*/o/.*"))
            .respond_with(ResponseTemplate::new(404).set_body_string("source not found"))
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        assert!(backend.copy("missing.txt", "dest.txt").await.is_err());
    }

    #[tokio::test]
    async fn test_copy_rejects_rewrite_without_continuation_token() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex("/storage/v1/b/.*/o/.*/rewriteTo/b/.*/o/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "done": false
            })))
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        let err = backend
            .copy("src.txt", "dest.txt")
            .await
            .expect_err("incomplete rewrite without token must fail");
        assert!(
            err.to_string().contains("rewriteToken"),
            "unexpected error: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_copy_forwards_rewrite_token_on_continuation() {
        use wiremock::matchers::{method, path_regex, query_param, query_param_is_missing};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // First rewrite POST has no rewriteToken and is incomplete.
        Mock::given(method("POST"))
            .and(path_regex("/storage/v1/b/.*/o/.*/rewriteTo/b/.*/o/.*"))
            .and(query_param_is_missing("rewriteToken"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "done": false,
                "rewriteToken": "t1",
                "totalBytesRewritten": "1048576",
                "objectSize": "2097152"
            })))
            .expect(1)
            .mount(&server)
            .await;
        // Continuation POST must carry the token returned above.
        Mock::given(method("POST"))
            .and(path_regex("/storage/v1/b/.*/o/.*/rewriteTo/b/.*/o/.*"))
            .and(query_param("rewriteToken", "t1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "done": true,
                "resource": {"name": "dest.txt"}
            })))
            .expect(1)
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        assert!(backend.copy("src.txt", "dest.txt").await.is_ok());

        // Exactly two POSTs: the initial rewrite and one continuation that
        // forwards the rewriteToken on the query string.
        let requests = server
            .received_requests()
            .await
            .expect("recorded requests should be available");
        assert_eq!(requests.len(), 2, "expected two rewrite POSTs");
        assert!(
            !requests[0]
                .url
                .query_pairs()
                .any(|(k, _)| k == "rewriteToken"),
            "first request must not carry a rewriteToken"
        );
        assert!(
            requests[1]
                .url
                .query_pairs()
                .any(|(k, v)| k == "rewriteToken" && v == "t1"),
            "continuation request must forward rewriteToken=t1, got {}",
            requests[1].url
        );
    }

    #[tokio::test]
    async fn test_size_success() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex("/storage/v1/b/.*/o/.*"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"size": "1048576"})),
            )
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        let sz = backend.size("large.bin").await.unwrap();
        assert_eq!(sz, 1_048_576);
    }

    #[tokio::test]
    async fn test_size_not_found() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex("/storage/v1/b/.*/o/.*"))
            .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        let result = backend.size("missing.bin").await;
        assert!(matches!(result.unwrap_err(), AppError::NotFound(_)));
    }

    // ---- health_check (issue #1569: object-level, not bucket-admin) ----

    /// The probe must hit the OBJECT metadata endpoint
    /// (`/storage/v1/b/<bucket>/o/.health-probe`), which only needs
    /// `storage.objects.get`. It must NOT hit the bucket metadata endpoint
    /// (`/storage/v1/b/<bucket>` with no `/o/...`), which needs the
    /// bucket-admin `storage.buckets.get`. We assert this by mounting ONLY the
    /// object endpoint with `expect(1)` and explicitly failing the bucket
    /// endpoint; wiremock's `verify()` (on drop) confirms the expected call.
    #[tokio::test]
    async fn test_health_check_uses_object_endpoint_not_bucket() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        // Object-level metadata GET: this is the only call the probe is allowed
        // to make. Respond 200 (object exists) -> healthy.
        Mock::given(method("GET"))
            .and(path_regex(r"/storage/v1/b/[^/]+/o/\.health-probe$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": ".health-probe",
                "size": "0"
            })))
            .expect(1)
            .mount(&server)
            .await;

        // Bucket-level metadata GET (the old over-privileged call): if the probe
        // ever hits this, the test fails because we return 403, mimicking a
        // least-privilege credential without storage.buckets.get.
        Mock::given(method("GET"))
            .and(path_regex(r"/storage/v1/b/[^/]+$"))
            .respond_with(
                ResponseTemplate::new(403).set_body_string(
                    "Caller does not have storage.buckets.get access to the bucket.",
                ),
            )
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        let result = backend.health_check().await;
        assert!(
            result.is_ok(),
            "health_check should pass via object endpoint: {:?}",
            result
        );
        // verify() on drop asserts the object endpoint was hit exactly once.
    }

    /// A 404 on the probe object means the bucket is reachable, credentials are
    /// valid, and object reads are authorized — the sentinel object just does
    /// not exist. That is healthy.
    #[tokio::test]
    async fn test_health_check_object_not_found_is_healthy() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"/storage/v1/b/[^/]+/o/\.health-probe$"))
            .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        assert!(backend.health_check().await.is_ok());
    }

    /// A 403 on the OBJECT endpoint is a genuinely broken/under-privileged
    /// backend (the credential cannot even read objects), so the probe fails.
    #[tokio::test]
    async fn test_health_check_object_forbidden_is_unhealthy() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"/storage/v1/b/[^/]+/o/\.health-probe$"))
            .respond_with(ResponseTemplate::new(403).set_body_string("Access Denied"))
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        let err = backend.health_check().await.unwrap_err();
        assert!(
            matches!(&err, AppError::Storage(m) if m.contains("403")),
            "expected storage error mentioning 403, got: {:?}",
            err
        );
    }
}
