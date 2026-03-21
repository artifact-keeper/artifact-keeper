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
use rsa::pkcs8::DecodePrivateKey;
use rsa::sha2::Sha256;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::RsaPrivateKey;
use sha2::Digest;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::error::{AppError, Result};
use crate::storage::{PresignedUrl, PresignedUrlSource, StorageBackend, StoragePathFormat};

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

/// Check that an HTTP response indicates success; return an error with context otherwise.
async fn require_success(
    response: reqwest::Response,
    context: &str,
) -> std::result::Result<reqwest::Response, AppError> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    Err(AppError::Storage(format!(
        "{} (status {}): {}",
        context, status, body
    )))
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
    client: reqwest::Client,
    auth: GcsAuthMode,
    path_format: StoragePathFormat,
    /// API base URL (overridable in tests via `with_base_url`).
    base_url: String,
}

impl GcsBackend {
    /// Create a new GCS backend.
    pub async fn new(config: GcsConfig) -> Result<Self> {
        let client = crate::services::http_client::base_client_builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| AppError::Storage(format!("Failed to create HTTP client: {}", e)))?;

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
            .body(content.to_vec())
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
        let url = format!(
            "{}/storage/v1/b/{}/o/{}/copyTo/b/{}/o/{}",
            self.base_url,
            bucket_enc,
            urlencoding::encode(source),
            bucket_enc,
            urlencoding::encode(dest),
        );

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Length", "0")
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("GCS copy failed: {}", e)))?;

        require_success(response, "GCS copy failed").await?;
        Ok(())
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
        // GET the bucket metadata endpoint. A successful response proves that
        // the bucket exists, credentials are valid, and the network path works.
        let url = format!(
            "{}/storage/v1/b/{}",
            self.base_url,
            urlencoding::encode(&self.config.bucket),
        );
        let response = self.authorized_get(&url).await.map_err(|e| {
            AppError::Storage(format!("GCS health check failed: {}", e))
        })?;

        if response.status().is_success() {
            return Ok(());
        }

        let status = response.status();
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
    async fn mock_backend(base_url: &str) -> GcsBackend {
        let config = GcsConfig {
            bucket: "test-bucket".to_string(),
            project_id: None,
            service_account_email: None,
            private_key: None,
            redirect_downloads: false,
            signed_url_expiry: Duration::from_secs(3600),
            path_format: StoragePathFormat::Native,
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
            client,
            auth: GcsAuthMode::Adc { provider },
            path_format: StoragePathFormat::Native,
            base_url: base_url.to_string(),
        }
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
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path_regex("/storage/v1/b/.*/o/.*/copyTo/b/.*/o/.*"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"name": "dest.txt"})),
            )
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
            .and(path_regex("/storage/v1/b/.*/o/.*/copyTo/b/.*/o/.*"))
            .respond_with(ResponseTemplate::new(404).set_body_string("source not found"))
            .mount(&server)
            .await;

        let backend = mock_backend(&server.uri()).await;
        assert!(backend.copy("missing.txt", "dest.txt").await.is_err());
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
}
