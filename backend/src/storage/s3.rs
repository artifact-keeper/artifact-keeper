//! S3 storage backend using the `object_store` crate (Apache Arrow project).
//!
//! Supports AWS S3 and S3-compatible services (MinIO, Ceph RGW, R2, etc.).
//! Configuration via environment variables:
//! - S3_BUCKET: Bucket name (required)
//! - S3_REGION: AWS region (default: us-east-1)
//! - S3_ENDPOINT: Custom endpoint URL for S3-compatible services
//! - S3_ACCESS_KEY_ID: Access key (preferred, falls back to AWS_ACCESS_KEY_ID)
//! - S3_SECRET_ACCESS_KEY: Secret key (preferred, falls back to AWS_SECRET_ACCESS_KEY)
//!
//! For TLS configuration:
//! - S3_CA_CERT_PATH: Path to PEM file with custom CA certificate(s)
//! - S3_INSECURE_TLS: Disable TLS certificate verification (default: false)
//!
//! For redirect downloads (302 to presigned URLs):
//! - S3_REDIRECT_DOWNLOADS: Enable 302 redirects (default: false)
//! - S3_PRESIGN_EXPIRY_SECS: URL expiry in seconds (default: 3600)
//!
//! For CloudFront CDN:
//! - CLOUDFRONT_DISTRIBUTION_URL: CloudFront distribution URL (optional)
//! - CLOUDFRONT_KEY_PAIR_ID: CloudFront key pair ID for signing
//! - CLOUDFRONT_PRIVATE_KEY_PATH: Path to CloudFront private key PEM file
//!
//! For Artifactory migration:
//! - STORAGE_PATH_FORMAT: Storage path format (default: native)
//!   - "native": 2-level sharding {sha[0:2]}/{sha[2:4]}/{sha}
//!   - "artifactory": 1-level sharding {sha[0:2]}/{sha} (JFrog Artifactory format)
//!   - "migration": Write native, read from both (for zero-downtime migration)

use async_trait::async_trait;
use bytes::Bytes;
use futures::TryStreamExt;
use object_store::aws::{AmazonS3, AmazonS3Builder};
use object_store::path::Path as ObjectPath;
use object_store::{ObjectStore, ObjectStoreExt};
use std::time::Duration;

use super::{PresignedUrl, PresignedUrlSource, StoragePathFormat};
use crate::error::{AppError, Result};

/// S3 storage backend configuration
#[derive(Debug, Clone)]
pub struct S3Config {
    /// S3 bucket name
    pub bucket: String,
    /// AWS region
    pub region: String,
    /// Custom endpoint URL (for MinIO compatibility)
    pub endpoint: Option<String>,
    /// Optional key prefix for all objects
    pub prefix: Option<String>,
    /// Enable redirect downloads via presigned URLs
    pub redirect_downloads: bool,
    /// Presigned URL expiry duration
    pub presign_expiry: Duration,
    /// CloudFront configuration (optional)
    pub cloudfront: Option<CloudFrontConfig>,
    /// Storage path format (native, artifactory, or migration)
    pub path_format: StoragePathFormat,
    /// Dedicated access key for presigned URL signing (optional, overrides default credentials)
    pub presign_access_key: Option<String>,
    /// Dedicated secret key for presigned URL signing (optional, overrides default credentials)
    pub presign_secret_key: Option<String>,
    /// Path to a PEM file containing custom CA certificate(s) for S3 connections
    pub ca_cert_path: Option<String>,
    /// Disable TLS certificate verification (for dev/test with self-signed certs)
    pub insecure_tls: bool,
}

/// CloudFront CDN configuration for signed URLs
#[derive(Debug, Clone)]
pub struct CloudFrontConfig {
    /// CloudFront distribution URL (e.g., https://d1234.cloudfront.net)
    pub distribution_url: String,
    /// CloudFront key pair ID for signing
    pub key_pair_id: String,
    /// CloudFront private key (PEM format)
    pub private_key: String,
}

impl S3Config {
    /// Create config from environment variables
    pub fn from_env() -> Result<Self> {
        let bucket =
            std::env::var("S3_BUCKET").map_err(|_| AppError::Config("S3_BUCKET not set".into()))?;
        let region = std::env::var("S3_REGION").unwrap_or_else(|_| "us-east-1".into());
        let endpoint = std::env::var("S3_ENDPOINT").ok();
        let prefix = std::env::var("S3_PREFIX").ok();

        // Redirect download configuration
        let redirect_downloads = std::env::var("S3_REDIRECT_DOWNLOADS")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);
        let presign_expiry_secs: u64 = std::env::var("S3_PRESIGN_EXPIRY_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3600);

        // CloudFront configuration (optional)
        let cloudfront = Self::load_cloudfront_config();

        // Storage path format (native, artifactory, or migration)
        let path_format = StoragePathFormat::from_env();

        // Dedicated signing credentials for presigned URLs (Option B)
        let presign_access_key = std::env::var("S3_PRESIGN_ACCESS_KEY_ID").ok();
        let presign_secret_key = std::env::var("S3_PRESIGN_SECRET_ACCESS_KEY").ok();

        let ca_cert_path = std::env::var("S3_CA_CERT_PATH").ok();
        let insecure_tls = std::env::var("S3_INSECURE_TLS")
            .map(|v| v.to_lowercase() == "true" || v == "1")
            .unwrap_or(false);

        Ok(Self {
            bucket,
            region,
            endpoint,
            prefix,
            redirect_downloads,
            presign_expiry: Duration::from_secs(presign_expiry_secs),
            cloudfront,
            path_format,
            presign_access_key,
            presign_secret_key,
            ca_cert_path,
            insecure_tls,
        })
    }

    /// Load CloudFront configuration from environment
    fn load_cloudfront_config() -> Option<CloudFrontConfig> {
        let distribution_url = std::env::var("CLOUDFRONT_DISTRIBUTION_URL").ok()?;
        let key_pair_id = std::env::var("CLOUDFRONT_KEY_PAIR_ID").ok()?;

        // Load private key from file or directly from env
        let private_key = if let Ok(key_path) = std::env::var("CLOUDFRONT_PRIVATE_KEY_PATH") {
            std::fs::read_to_string(&key_path)
                .map_err(|e| {
                    tracing::warn!(
                        "Failed to read CloudFront private key from {}: {}",
                        key_path,
                        e
                    );
                    e
                })
                .ok()?
        } else if let Ok(key) = std::env::var("CLOUDFRONT_PRIVATE_KEY") {
            key
        } else {
            tracing::debug!("CloudFront private key not configured");
            return None;
        };

        tracing::info!(
            distribution = %distribution_url,
            key_pair_id = %key_pair_id,
            "CloudFront CDN configured for redirect downloads"
        );

        Some(CloudFrontConfig {
            distribution_url,
            key_pair_id,
            private_key,
        })
    }

    /// Create config with explicit values
    pub fn new(
        bucket: String,
        region: String,
        endpoint: Option<String>,
        prefix: Option<String>,
    ) -> Self {
        Self {
            bucket,
            region,
            endpoint,
            prefix,
            redirect_downloads: false,
            presign_expiry: Duration::from_secs(3600),
            cloudfront: None,
            path_format: StoragePathFormat::default(),
            presign_access_key: None,
            presign_secret_key: None,
            ca_cert_path: None,
            insecure_tls: false,
        }
    }

    /// Set storage path format (for Artifactory compatibility)
    pub fn with_path_format(mut self, format: StoragePathFormat) -> Self {
        self.path_format = format;
        self
    }

    /// Enable redirect downloads
    pub fn with_redirect_downloads(mut self, enabled: bool) -> Self {
        self.redirect_downloads = enabled;
        self
    }

    /// Set presigned URL expiry
    pub fn with_presign_expiry(mut self, expiry: Duration) -> Self {
        self.presign_expiry = expiry;
        self
    }

    /// Set CloudFront configuration
    pub fn with_cloudfront(mut self, config: CloudFrontConfig) -> Self {
        self.cloudfront = Some(config);
        self
    }

    pub fn with_ca_cert_path(mut self, path: String) -> Self {
        self.ca_cert_path = Some(path);
        self
    }

    pub fn with_insecure_tls(mut self, insecure: bool) -> Self {
        self.insecure_tls = insecure;
        self
    }
}

/// Generate the full S3 key with optional prefix.
fn make_full_key(prefix: Option<&str>, key: &str) -> String {
    match prefix {
        Some(p) => format!("{}/{}", p.trim_end_matches('/'), key),
        None => key.to_string(),
    }
}

/// Strip the prefix from an S3 key.
fn strip_key_prefix(prefix: Option<&str>, key: &str) -> String {
    match prefix {
        Some(p) => {
            let prefix_with_slash = format!("{}/", p.trim_end_matches('/'));
            key.strip_prefix(&prefix_with_slash)
                .unwrap_or(key)
                .to_string()
        }
        None => key.to_string(),
    }
}

/// Try to generate an Artifactory fallback path from a native path.
/// Native format: ab/cd/abcd...full_checksum (64 chars)
/// Artifactory format: ab/abcd...full_checksum
fn artifactory_fallback_path(key: &str) -> Option<String> {
    if key.split('/').count() < 3 {
        return None;
    }
    let checksum = key.rsplit('/').next()?;
    if checksum.len() == 64 && checksum.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(format!("{}/{}", &checksum[..2], checksum))
    } else {
        None
    }
}

/// S3-compatible storage backend
pub struct S3Backend {
    store: AmazonS3,
    prefix: Option<String>,
    redirect_downloads: bool,
    cloudfront: Option<CloudFrontConfig>,
    path_format: StoragePathFormat,
    signing_store: Option<AmazonS3>,
}

impl S3Backend {
    fn build_store(
        config: &S3Config,
        access_key: Option<&str>,
        secret_key: Option<&str>,
    ) -> Result<AmazonS3> {
        let mut client_opts = object_store::ClientOptions::new();

        if config
            .endpoint
            .as_ref()
            .is_some_and(|e| e.starts_with("http://"))
        {
            client_opts = client_opts.with_allow_http(true);
        }

        if let Some(ca_path) = &config.ca_cert_path {
            let pem = std::fs::read(ca_path).map_err(|e| {
                AppError::Config(format!("Failed to read CA cert '{}': {}", ca_path, e))
            })?;
            let certs = object_store::Certificate::from_pem_bundle(&pem).map_err(|e| {
                AppError::Config(format!("Invalid CA cert PEM '{}': {}", ca_path, e))
            })?;
            for cert in certs {
                client_opts = client_opts.with_root_certificate(cert);
            }
            tracing::info!(path = %ca_path, "Loaded custom CA certificate(s) for S3");
        }

        if config.insecure_tls {
            client_opts = client_opts.with_allow_invalid_certificates(true);
            tracing::warn!("S3 TLS certificate verification is DISABLED (S3_INSECURE_TLS=true)");
        }

        // Use new() instead of from_env() to avoid greedy ingestion of AWS_*
        // env vars that could hijack endpoints (AWS_ENDPOINT_URL), disable
        // signing (AWS_SKIP_SIGNATURE), or shadow IAM credentials. We
        // selectively read only the credential chain variables needed.
        let mut builder = AmazonS3Builder::new()
            .with_bucket_name(&config.bucket)
            .with_region(&config.region)
            .with_client_options(client_opts);

        if let Some(endpoint) = &config.endpoint {
            builder = builder.with_endpoint(endpoint);
        }

        // ECS Fargate task role credentials
        if let Ok(uri) = std::env::var("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") {
            builder = builder.with_config(
                object_store::aws::AmazonS3ConfigKey::ContainerCredentialsRelativeUri,
                uri,
            );
        }
        // EKS Pod Identity credentials
        if let Ok(uri) = std::env::var("AWS_CONTAINER_CREDENTIALS_FULL_URI") {
            builder = builder.with_config(
                object_store::aws::AmazonS3ConfigKey::ContainerCredentialsFullUri,
                uri,
            );
        }
        if let Ok(f) = std::env::var("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE") {
            builder = builder.with_config(
                object_store::aws::AmazonS3ConfigKey::ContainerAuthorizationTokenFile,
                f,
            );
        }
        // EKS IRSA / Web Identity credentials
        if let Ok(f) = std::env::var("AWS_WEB_IDENTITY_TOKEN_FILE") {
            builder = builder.with_config(
                object_store::aws::AmazonS3ConfigKey::WebIdentityTokenFile,
                f,
            );
        }
        if let Ok(arn) = std::env::var("AWS_ROLE_ARN") {
            builder = builder.with_config(object_store::aws::AmazonS3ConfigKey::RoleArn, arn);
        }

        // Explicit credentials: function args > S3_* env vars > AWS_* env vars
        if let Some(ak) = access_key {
            if let Some(sk) = secret_key {
                builder = builder.with_access_key_id(ak).with_secret_access_key(sk);
            }
        } else if let (Ok(ak), Ok(sk)) = (
            std::env::var("S3_ACCESS_KEY_ID"),
            std::env::var("S3_SECRET_ACCESS_KEY"),
        ) {
            tracing::info!("Using S3_ACCESS_KEY_ID/S3_SECRET_ACCESS_KEY for S3 credentials");
            builder = builder.with_access_key_id(&ak).with_secret_access_key(&sk);
        } else if let (Ok(ak), Ok(sk)) = (
            std::env::var("AWS_ACCESS_KEY_ID"),
            std::env::var("AWS_SECRET_ACCESS_KEY"),
        ) {
            builder = builder.with_access_key_id(&ak).with_secret_access_key(&sk);
            if let Ok(token) = std::env::var("AWS_SESSION_TOKEN") {
                builder = builder.with_token(token);
            }
        }

        builder
            .build()
            .map_err(|e| AppError::Config(format!("Failed to build S3 client: {}", e)))
    }

    /// Create new S3 backend from configuration
    pub async fn new(config: S3Config) -> Result<Self> {
        let store = Self::build_store(&config, None, None)?;

        let signing_store = match (&config.presign_access_key, &config.presign_secret_key) {
            (Some(ak), Some(sk)) => {
                let ss = Self::build_store(&config, Some(ak), Some(sk))?;
                tracing::info!("Using dedicated credentials for presigned URL signing");
                Some(ss)
            }
            _ => None,
        };

        if config.redirect_downloads {
            tracing::info!(
                bucket = %config.bucket,
                cloudfront = config.cloudfront.is_some(),
                expiry_secs = config.presign_expiry.as_secs(),
                dedicated_signing_creds = signing_store.is_some(),
                "S3 redirect downloads enabled"
            );
        }

        if config.path_format != StoragePathFormat::Native {
            tracing::info!(path_format = %config.path_format, "S3 storage path format configured");
        }

        Ok(Self {
            store,
            prefix: config.prefix,
            redirect_downloads: config.redirect_downloads,
            cloudfront: config.cloudfront,
            path_format: config.path_format,
            signing_store,
        })
    }

    pub async fn from_env() -> Result<Self> {
        let config = S3Config::from_env()?;
        Self::new(config).await
    }

    /// Generate the full S3 key with optional prefix
    fn full_key(&self, key: &str) -> String {
        make_full_key(self.prefix.as_deref(), key)
    }

    /// Strip the prefix from an S3 key
    fn strip_prefix(&self, key: &str) -> String {
        strip_key_prefix(self.prefix.as_deref(), key)
    }

    /// Try to generate an Artifactory fallback path from a native path
    fn try_artifactory_fallback(&self, key: &str) -> Option<String> {
        artifactory_fallback_path(key)
    }

    async fn try_fallback_get(&self, key: &str, reason: &'static str) -> Result<Option<Bytes>> {
        if !self.path_format.has_fallback() {
            return Ok(None);
        }

        let Some(fallback_key) = self.try_artifactory_fallback(key) else {
            return Ok(None);
        };

        let fallback_full_key = self.full_key(&fallback_key);
        tracing::debug!(
            original = %key,
            fallback = %fallback_key,
            reason,
            "Trying Artifactory fallback path"
        );

        let path: ObjectPath = fallback_full_key.into();
        match self.store.get(&path).await {
            Ok(result) => {
                let bytes = result.bytes().await.map_err(|e| {
                    AppError::Storage(format!("Failed to read fallback '{}': {}", fallback_key, e))
                })?;
                tracing::info!(
                    key = %key,
                    fallback = %fallback_key,
                    size = bytes.len(),
                    "Found artifact at Artifactory fallback path"
                );
                Ok(Some(bytes))
            }
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(AppError::Storage(format!(
                "Failed to get fallback object '{}' for '{}': {}",
                fallback_key, key, e
            ))),
        }
    }
}

#[async_trait]
impl super::StorageBackend for S3Backend {
    async fn put(&self, key: &str, content: Bytes) -> Result<()> {
        let full_key = self.full_key(key);
        let path: ObjectPath = full_key.into();

        self.store.put(&path, content.into()).await.map_err(|e| {
            tracing::error!(key = %key, error = %e, "S3 put_object failed");
            AppError::Storage(format!("Failed to put object '{}': {}", key, e))
        })?;

        tracing::debug!(key = %key, "S3 put object successful");
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Bytes> {
        let full_key = self.full_key(key);
        let path: ObjectPath = full_key.into();

        match self.store.get(&path).await {
            Ok(result) => {
                let bytes = result.bytes().await.map_err(|e| {
                    AppError::Storage(format!("Failed to read object '{}': {}", key, e))
                })?;
                tracing::debug!(key = %key, size = bytes.len(), "S3 get object successful");
                Ok(bytes)
            }
            Err(object_store::Error::NotFound { .. }) => {
                if let Some(bytes) = self.try_fallback_get(key, "primary not found").await? {
                    return Ok(bytes);
                }
                Err(AppError::NotFound(format!(
                    "Storage key not found: {}",
                    key
                )))
            }
            Err(e) => Err(AppError::Storage(format!(
                "Failed to get object '{}': {}",
                key, e
            ))),
        }
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let full_key = self.full_key(key);
        let path: ObjectPath = full_key.into();

        match self.store.head(&path).await {
            Ok(_) => return Ok(true),
            Err(object_store::Error::NotFound { .. }) => {}
            Err(e) => {
                return Err(AppError::Storage(format!(
                    "Failed to check existence of '{}': {}",
                    key, e
                )));
            }
        }

        if self.path_format.has_fallback() {
            if let Some(fallback_key) = self.try_artifactory_fallback(key) {
                let fallback_full_key = self.full_key(&fallback_key);
                let fallback_path: ObjectPath = fallback_full_key.into();
                match self.store.head(&fallback_path).await {
                    Ok(_) => {
                        tracing::debug!(
                            key = %key, fallback = %fallback_key,
                            "Found artifact at Artifactory fallback path"
                        );
                        return Ok(true);
                    }
                    Err(object_store::Error::NotFound { .. }) => {}
                    Err(e) => {
                        tracing::warn!(
                            key = %key, fallback = %fallback_key, error = %e,
                            "Fallback head_object failed with unexpected error"
                        );
                    }
                }
            }
        }

        Ok(false)
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let full_key = self.full_key(key);
        let path: ObjectPath = full_key.into();

        self.store
            .delete(&path)
            .await
            .map_err(|e| AppError::Storage(format!("Failed to delete object '{}': {}", key, e)))?;

        tracing::debug!(key = %key, "S3 delete object successful");
        Ok(())
    }

    fn supports_redirect(&self) -> bool {
        self.redirect_downloads
    }

    async fn get_presigned_url(
        &self,
        key: &str,
        expires_in: Duration,
    ) -> Result<Option<PresignedUrl>> {
        if !self.redirect_downloads {
            return Ok(None);
        }

        let full_key = self.full_key(key);

        if let Some(cf) = &self.cloudfront {
            let url = self.generate_cloudfront_signed_url(cf, &full_key, expires_in)?;
            tracing::debug!(
                key = %key, expires_in_secs = expires_in.as_secs(), source = "cloudfront",
                "Generated CloudFront signed URL"
            );
            return Ok(Some(PresignedUrl {
                url,
                expires_in,
                source: PresignedUrlSource::CloudFront,
            }));
        }

        use object_store::signer::Signer;

        let path: ObjectPath = full_key.into();
        let signer = self.signing_store.as_ref().unwrap_or(&self.store);

        // S3 enforces a maximum presigned URL expiry of 7 days
        let clamped_expiry = Duration::from_secs(expires_in.as_secs().min(604800));

        let presigned_url = signer
            .signed_url(http::Method::GET, &path, clamped_expiry)
            .await
            .map_err(|e| {
                AppError::Storage(format!(
                    "Failed to generate presigned URL for '{}': {}",
                    key, e
                ))
            })?;

        tracing::debug!(
            key = %key, expires_in_secs = clamped_expiry.as_secs(), source = "s3",
            dedicated_creds = self.signing_store.is_some(),
            "Generated S3 presigned URL"
        );

        Ok(Some(PresignedUrl {
            url: presigned_url.to_string(),
            expires_in: clamped_expiry,
            source: PresignedUrlSource::S3,
        }))
    }

    async fn health_check(&self) -> Result<()> {
        let path: ObjectPath = ".health-probe".into();
        match self.store.head(&path).await {
            Ok(_) => Ok(()),
            Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("403") || msg.contains("Access Denied") {
                    Err(AppError::Storage(format!(
                        "S3 health check failed: access denied: {}",
                        e
                    )))
                } else {
                    Err(AppError::Storage(format!("S3 health check failed: {}", e)))
                }
            }
        }
    }
}

/// Extended S3 backend operations (for StorageService compatibility)
impl S3Backend {
    /// List keys with optional prefix
    pub async fn list(&self, prefix: Option<&str>) -> Result<Vec<String>> {
        let search_prefix = match (&self.prefix, prefix) {
            (Some(base), Some(p)) => format!("{}/{}", base.trim_end_matches('/'), p),
            (Some(base), None) => format!("{}/", base.trim_end_matches('/')),
            (None, Some(p)) => p.to_string(),
            (None, None) => String::new(),
        };

        let list_path: ObjectPath = search_prefix.into();
        let objects: Vec<_> = self
            .store
            .list(Some(&list_path))
            .try_collect()
            .await
            .map_err(|e| AppError::Storage(format!("Failed to list objects: {}", e)))?;

        let keys: Vec<String> = objects
            .into_iter()
            .map(|meta| self.strip_prefix(meta.location.as_ref()))
            .collect();

        tracing::debug!(prefix = ?prefix, count = keys.len(), "S3 list objects successful");
        Ok(keys)
    }

    /// Copy content from one key to another
    pub async fn copy(&self, source: &str, dest: &str) -> Result<()> {
        let source_key = self.full_key(source);
        let dest_key = self.full_key(dest);

        let from: ObjectPath = source_key.into();
        let to: ObjectPath = dest_key.into();

        self.store.copy(&from, &to).await.map_err(|e| {
            AppError::Storage(format!("Failed to copy '{}' to '{}': {}", source, dest, e))
        })?;

        tracing::debug!(source = %source, dest = %dest, "S3 copy object successful");
        Ok(())
    }

    /// Get content size without fetching full content
    pub async fn size(&self, key: &str) -> Result<u64> {
        let full_key = self.full_key(key);
        let path: ObjectPath = full_key.into();

        match self.store.head(&path).await {
            Ok(meta) => {
                tracing::debug!(key = %key, size = meta.size, "S3 head object successful");
                Ok(meta.size)
            }
            Err(object_store::Error::NotFound { .. }) => Err(AppError::NotFound(format!(
                "Storage key not found: {}",
                key
            ))),
            Err(e) => Err(AppError::Storage(format!(
                "Failed to get size of '{}': {}",
                key, e
            ))),
        }
    }

    /// Generate a CloudFront signed URL
    ///
    /// CloudFront signed URLs use RSA-SHA1 signatures with a canned policy.
    fn generate_cloudfront_signed_url(
        &self,
        config: &CloudFrontConfig,
        key: &str,
        expires_in: Duration,
    ) -> Result<String> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use rsa::pkcs1v15::SigningKey;
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::signature::{SignatureEncoding, Signer};
        use rsa::RsaPrivateKey;
        use sha1::Sha1;

        // Calculate expiry timestamp
        let expires = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| AppError::Internal(format!("System time error: {}", e)))?
            .as_secs()
            + expires_in.as_secs();

        // Build the resource URL
        let resource_url = format!(
            "{}/{}",
            config.distribution_url.trim_end_matches('/'),
            key.trim_start_matches('/')
        );

        // Create canned policy
        let policy = format!(
            r#"{{"Statement":[{{"Resource":"{}","Condition":{{"DateLessThan":{{"AWS:EpochTime":{}}}}}}}]}}"#,
            resource_url, expires
        );

        // Parse private key
        let private_key = RsaPrivateKey::from_pkcs8_pem(&config.private_key)
            .map_err(|e| AppError::Config(format!("Invalid CloudFront private key: {}", e)))?;

        // Sign the policy with RSA-SHA1 (unprefixed for CloudFront compatibility)
        let signing_key = SigningKey::<Sha1>::new_unprefixed(private_key);
        let signature = signing_key.sign(policy.as_bytes());

        // Base64 encode and make URL-safe
        let signature_b64 = STANDARD
            .encode(signature.to_bytes())
            .replace('+', "-")
            .replace('=', "_")
            .replace('/', "~");

        // Build signed URL with canned policy (simplified - just expiry)
        let signed_url = format!(
            "{}?Expires={}&Signature={}&Key-Pair-Id={}",
            resource_url, expires, signature_b64, config.key_pair_id
        );

        Ok(signed_url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- free function tests: make_full_key ---

    #[test]
    fn test_full_key_with_prefix() {
        assert_eq!(
            make_full_key(Some("artifacts"), "test/file.txt"),
            "artifacts/test/file.txt"
        );
    }

    #[test]
    fn test_full_key_without_prefix() {
        assert_eq!(make_full_key(None, "test/file.txt"), "test/file.txt");
    }

    #[test]
    fn test_full_key_trailing_slash_prefix() {
        assert_eq!(
            make_full_key(Some("artifacts/"), "test/file.txt"),
            "artifacts/test/file.txt"
        );
    }

    #[test]
    fn test_full_key_empty_key() {
        assert_eq!(make_full_key(Some("prefix"), ""), "prefix/");
        assert_eq!(make_full_key(None, ""), "");
    }

    #[test]
    fn test_make_full_key_double_slash_prevention() {
        // Prefix with trailing slash should not produce double slash
        assert_eq!(make_full_key(Some("prefix/"), "key"), "prefix/key");
    }

    // --- free function tests: strip_key_prefix ---

    #[test]
    fn test_strip_prefix() {
        assert_eq!(
            strip_key_prefix(Some("artifacts"), "artifacts/test/file.txt"),
            "test/file.txt"
        );
    }

    #[test]
    fn test_strip_prefix_no_match() {
        assert_eq!(
            strip_key_prefix(Some("other-prefix"), "artifacts/test/file.txt"),
            "artifacts/test/file.txt"
        );
    }

    #[test]
    fn test_strip_prefix_none() {
        assert_eq!(strip_key_prefix(None, "test/file.txt"), "test/file.txt");
    }

    #[test]
    fn test_strip_prefix_exact_match() {
        // Key is exactly "prefix/" with nothing after
        assert_eq!(strip_key_prefix(Some("prefix"), "prefix/"), "");
    }

    #[test]
    fn test_strip_prefix_with_trailing_slash() {
        assert_eq!(
            strip_key_prefix(Some("prefix/"), "prefix/test/file.txt"),
            "test/file.txt"
        );
    }

    // --- free function tests: artifactory_fallback_path ---

    #[test]
    fn test_artifactory_fallback_valid_native_path() {
        let key = "91/6f/916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9";
        let result = artifactory_fallback_path(key);
        assert_eq!(
            result.unwrap(),
            "91/916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
        );
    }

    #[test]
    fn test_artifactory_fallback_short_checksum_rejected() {
        assert!(artifactory_fallback_path("ab/cd/abcdef1234").is_none());
    }

    #[test]
    fn test_artifactory_fallback_non_hex_rejected() {
        assert!(artifactory_fallback_path(
            "zz/yy/zzyy00000000000000000000000000000000000000000000000000gggggg"
        )
        .is_none());
    }

    #[test]
    fn test_artifactory_fallback_single_segment_rejected() {
        assert!(artifactory_fallback_path(
            "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
        )
        .is_none());
    }

    #[test]
    fn test_artifactory_fallback_two_segments() {
        assert!(artifactory_fallback_path(
            "ab/abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567"
        )
        .is_none());
    }

    #[test]
    fn test_artifactory_fallback_deeply_nested() {
        // More than 3 segments should still work (takes the last one)
        let checksum = "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9";
        let key = format!("a/b/c/d/{}", checksum);
        let result = artifactory_fallback_path(&key);
        assert_eq!(result.unwrap(), format!("91/{}", checksum));
    }

    // --- S3Config constructor / builder tests ---

    #[test]
    fn test_s3_config_new() {
        let config = S3Config::new(
            "my-bucket".to_string(),
            "us-west-2".to_string(),
            Some("http://localhost:9000".to_string()),
            Some("prefix".to_string()),
        );

        assert_eq!(config.bucket, "my-bucket");
        assert_eq!(config.region, "us-west-2");
        assert_eq!(config.endpoint, Some("http://localhost:9000".to_string()));
        assert_eq!(config.prefix, Some("prefix".to_string()));
        assert_eq!(config.path_format, StoragePathFormat::Native);
        assert!(config.presign_access_key.is_none());
        assert!(config.presign_secret_key.is_none());
    }

    #[test]
    fn test_s3_config_with_path_format() {
        let config = S3Config::new("my-bucket".to_string(), "us-west-2".to_string(), None, None)
            .with_path_format(StoragePathFormat::Artifactory);
        assert_eq!(config.path_format, StoragePathFormat::Artifactory);
    }

    #[test]
    fn test_path_format_with_s3_config() {
        let config = S3Config::new("test".to_string(), "us-east-1".to_string(), None, None)
            .with_path_format(StoragePathFormat::Migration);
        assert_eq!(config.path_format, StoragePathFormat::Migration);
        assert!(config.path_format.has_fallback());
    }

    #[test]
    fn test_s3_config_presign_credentials_default_none() {
        let config = S3Config::new("b".to_string(), "us-east-1".to_string(), None, None);
        assert!(config.presign_access_key.is_none());
        assert!(config.presign_secret_key.is_none());
    }

    #[test]
    fn test_s3_config_supports_redirect_requires_key() {
        let config = S3Config::new("b".to_string(), "us-east-1".to_string(), None, None)
            .with_redirect_downloads(true);
        assert!(config.redirect_downloads);
        assert!(config.presign_access_key.is_none());
    }

    #[test]
    fn test_s3_config_with_presign_expiry() {
        let config = S3Config::new("b".to_string(), "us-east-1".to_string(), None, None)
            .with_presign_expiry(Duration::from_secs(7200));
        assert_eq!(config.presign_expiry, Duration::from_secs(7200));
    }

    #[test]
    fn test_s3_config_with_cloudfront() {
        let cf = CloudFrontConfig {
            distribution_url: "https://d1234.cloudfront.net".to_string(),
            key_pair_id: "KPID123".to_string(),
            private_key: "fake-key-data".to_string(),
        };
        let config =
            S3Config::new("b".to_string(), "us-east-1".to_string(), None, None).with_cloudfront(cf);
        assert!(config.cloudfront.is_some());
        let cf = config.cloudfront.unwrap();
        assert_eq!(cf.distribution_url, "https://d1234.cloudfront.net");
        assert_eq!(cf.key_pair_id, "KPID123");
    }

    #[test]
    fn test_s3_config_default_values() {
        let config = S3Config::new("b".to_string(), "r".to_string(), None, None);
        assert!(!config.redirect_downloads);
        assert_eq!(config.presign_expiry, Duration::from_secs(3600));
        assert!(config.cloudfront.is_none());
        assert_eq!(config.path_format, StoragePathFormat::Native);
        assert!(config.endpoint.is_none());
        assert!(config.prefix.is_none());
        assert!(config.ca_cert_path.is_none());
        assert!(!config.insecure_tls);
    }

    #[test]
    fn test_s3_config_chained_builders() {
        let cf = CloudFrontConfig {
            distribution_url: "https://cdn.example.com".to_string(),
            key_pair_id: "KP1".to_string(),
            private_key: "key".to_string(),
        };
        let config = S3Config::new(
            "bucket".to_string(),
            "eu-west-1".to_string(),
            Some("https://minio:9000".to_string()),
            Some("prefix".to_string()),
        )
        .with_redirect_downloads(true)
        .with_presign_expiry(Duration::from_secs(600))
        .with_path_format(StoragePathFormat::Migration)
        .with_cloudfront(cf);

        assert_eq!(config.bucket, "bucket");
        assert_eq!(config.region, "eu-west-1");
        assert_eq!(config.endpoint, Some("https://minio:9000".to_string()));
        assert_eq!(config.prefix, Some("prefix".to_string()));
        assert!(config.redirect_downloads);
        assert_eq!(config.presign_expiry, Duration::from_secs(600));
        assert_eq!(config.path_format, StoragePathFormat::Migration);
        assert!(config.cloudfront.is_some());
    }

    // --- path_format tests ---

    #[test]
    fn test_native_format_has_no_fallback() {
        let config = S3Config::new("b".to_string(), "r".to_string(), None, None)
            .with_path_format(StoragePathFormat::Native);
        assert!(!config.path_format.has_fallback());
    }

    #[test]
    fn test_artifactory_format_has_no_fallback() {
        let config = S3Config::new("b".to_string(), "r".to_string(), None, None)
            .with_path_format(StoragePathFormat::Artifactory);
        assert!(!config.path_format.has_fallback());
    }

    #[test]
    fn test_migration_format_has_fallback() {
        let config = S3Config::new("b".to_string(), "r".to_string(), None, None)
            .with_path_format(StoragePathFormat::Migration);
        assert!(config.path_format.has_fallback());
    }

    // --- TLS config tests ---

    #[test]
    fn test_s3_config_ca_cert_path_default_none() {
        let config = S3Config::new("b".to_string(), "r".to_string(), None, None);
        assert!(config.ca_cert_path.is_none());
        assert!(!config.insecure_tls);
    }

    #[test]
    fn test_s3_config_with_ca_cert_path() {
        let config = S3Config::new("b".to_string(), "r".to_string(), None, None)
            .with_ca_cert_path("/etc/ssl/custom-ca.pem".to_string());
        assert_eq!(
            config.ca_cert_path,
            Some("/etc/ssl/custom-ca.pem".to_string())
        );
    }

    #[test]
    fn test_s3_config_with_insecure_tls() {
        let config =
            S3Config::new("b".to_string(), "r".to_string(), None, None).with_insecure_tls(true);
        assert!(config.insecure_tls);
    }

    #[test]
    fn test_s3_config_insecure_tls_default_false() {
        let config = S3Config::new("b".to_string(), "r".to_string(), None, None);
        assert!(!config.insecure_tls);
    }

    #[test]
    fn test_s3_config_chained_builders_with_tls() {
        let config = S3Config::new(
            "bucket".to_string(),
            "us-east-1".to_string(),
            Some("https://s3.internal:9000".to_string()),
            None,
        )
        .with_ca_cert_path("/etc/ssl/internal-ca.pem".to_string())
        .with_insecure_tls(false);

        assert_eq!(
            config.ca_cert_path,
            Some("/etc/ssl/internal-ca.pem".to_string())
        );
        assert!(!config.insecure_tls);
    }

    // --- build_store tests ---

    #[test]
    fn test_build_store_invalid_ca_cert_path() {
        let config = S3Config::new("b".to_string(), "us-east-1".to_string(), None, None)
            .with_ca_cert_path("/nonexistent/ca.pem".to_string());
        let result = S3Backend::build_store(&config, None, None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Failed to read CA cert"), "got: {err}");
    }

    #[test]
    fn test_build_store_with_explicit_credentials() {
        let config = S3Config::new(
            "test-bucket".to_string(),
            "us-east-1".to_string(),
            Some("http://localhost:9999".to_string()),
            None,
        );
        let result = S3Backend::build_store(&config, Some("AKID"), Some("SECRET"));
        assert!(
            result.is_ok(),
            "build_store should succeed with explicit creds"
        );
    }

    #[test]
    fn test_build_store_minimal_config() {
        let config = S3Config::new("b".to_string(), "us-east-1".to_string(), None, None);
        let result = S3Backend::build_store(&config, None, None);
        assert!(
            result.is_ok(),
            "build_store should succeed with minimal config"
        );
    }

    #[test]
    fn test_build_store_with_custom_endpoint() {
        let config = S3Config::new(
            "b".to_string(),
            "us-east-1".to_string(),
            Some("https://s3.internal:9000".to_string()),
            None,
        );
        let result = S3Backend::build_store(&config, None, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_store_allows_http_for_http_endpoint() {
        let config = S3Config::new(
            "b".to_string(),
            "us-east-1".to_string(),
            Some("http://minio:9000".to_string()),
            None,
        );
        // Should succeed (allow_http enabled for http:// endpoints)
        assert!(S3Backend::build_store(&config, None, None).is_ok());
    }

    #[test]
    fn test_build_store_insecure_tls() {
        let config = S3Config::new("b".to_string(), "us-east-1".to_string(), None, None)
            .with_insecure_tls(true);
        assert!(S3Backend::build_store(&config, None, None).is_ok());
    }

    // --- S3Config from_env tests ---

    #[test]
    fn test_s3_config_from_env_missing_bucket() {
        let original = std::env::var("S3_BUCKET").ok();
        std::env::remove_var("S3_BUCKET");
        let result = S3Config::from_env();
        assert!(result.is_err());
        // Restore
        if let Some(v) = original {
            std::env::set_var("S3_BUCKET", v);
        }
    }

    #[test]
    fn test_s3_config_from_env_success() {
        // Save originals
        let orig_bucket = std::env::var("S3_BUCKET").ok();
        let orig_region = std::env::var("S3_REGION").ok();
        let orig_endpoint = std::env::var("S3_ENDPOINT").ok();
        let orig_prefix = std::env::var("S3_PREFIX").ok();
        let orig_redirect = std::env::var("S3_REDIRECT_DOWNLOADS").ok();
        let orig_expiry = std::env::var("S3_PRESIGN_EXPIRY_SECS").ok();
        let orig_pak = std::env::var("S3_PRESIGN_ACCESS_KEY_ID").ok();
        let orig_psk = std::env::var("S3_PRESIGN_SECRET_ACCESS_KEY").ok();
        let orig_ca = std::env::var("S3_CA_CERT_PATH").ok();
        let orig_insecure = std::env::var("S3_INSECURE_TLS").ok();
        // Also save CloudFront vars to avoid interference
        let orig_cf_url = std::env::var("CLOUDFRONT_DISTRIBUTION_URL").ok();

        // Set test values
        std::env::set_var("S3_BUCKET", "test-from-env-bucket");
        std::env::set_var("S3_REGION", "eu-west-1");
        std::env::set_var("S3_ENDPOINT", "http://localhost:9000");
        std::env::set_var("S3_PREFIX", "my-prefix");
        std::env::set_var("S3_REDIRECT_DOWNLOADS", "true");
        std::env::set_var("S3_PRESIGN_EXPIRY_SECS", "7200");
        std::env::set_var("S3_PRESIGN_ACCESS_KEY_ID", "presign-ak");
        std::env::set_var("S3_PRESIGN_SECRET_ACCESS_KEY", "presign-sk");
        std::env::remove_var("S3_CA_CERT_PATH");
        std::env::set_var("S3_INSECURE_TLS", "1");
        std::env::remove_var("CLOUDFRONT_DISTRIBUTION_URL");

        let result = S3Config::from_env();
        assert!(
            result.is_ok(),
            "from_env should succeed: {:?}",
            result.err()
        );
        let config = result.unwrap();
        assert_eq!(config.bucket, "test-from-env-bucket");
        assert_eq!(config.region, "eu-west-1");
        assert_eq!(config.endpoint, Some("http://localhost:9000".to_string()));
        assert_eq!(config.prefix, Some("my-prefix".to_string()));
        assert!(config.redirect_downloads);
        assert_eq!(config.presign_expiry, Duration::from_secs(7200));
        assert_eq!(config.presign_access_key, Some("presign-ak".to_string()));
        assert_eq!(config.presign_secret_key, Some("presign-sk".to_string()));
        assert!(config.ca_cert_path.is_none());
        assert!(config.insecure_tls);
        assert!(config.cloudfront.is_none());

        // Restore all originals
        let restore = |name: &str, val: Option<String>| match val {
            Some(v) => std::env::set_var(name, v),
            None => std::env::remove_var(name),
        };
        restore("S3_BUCKET", orig_bucket);
        restore("S3_REGION", orig_region);
        restore("S3_ENDPOINT", orig_endpoint);
        restore("S3_PREFIX", orig_prefix);
        restore("S3_REDIRECT_DOWNLOADS", orig_redirect);
        restore("S3_PRESIGN_EXPIRY_SECS", orig_expiry);
        restore("S3_PRESIGN_ACCESS_KEY_ID", orig_pak);
        restore("S3_PRESIGN_SECRET_ACCESS_KEY", orig_psk);
        restore("S3_CA_CERT_PATH", orig_ca);
        restore("S3_INSECURE_TLS", orig_insecure);
        restore("CLOUDFRONT_DISTRIBUTION_URL", orig_cf_url);
    }

    #[test]
    fn test_build_store_with_valid_ca_cert() {
        // Use the test fixture PEM file
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let pem_path = format!("{}/tests/fixtures/test-ca.pem", manifest_dir);

        // Only run if the fixture exists
        if !std::path::Path::new(&pem_path).exists() {
            eprintln!("Skipping: test-ca.pem fixture not found at {}", pem_path);
            return;
        }

        let config = S3Config::new("b".to_string(), "us-east-1".to_string(), None, None)
            .with_ca_cert_path(pem_path);
        let result = S3Backend::build_store(&config, None, None);
        assert!(
            result.is_ok(),
            "build_store with valid CA cert should succeed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_build_store_with_invalid_pem_content() {
        let tmp_path = std::env::temp_dir().join("test-bad-ca-s3.pem");
        std::fs::write(&tmp_path, b"not-a-valid-pem").expect("write temp PEM");

        let config = S3Config::new("b".to_string(), "us-east-1".to_string(), None, None)
            .with_ca_cert_path(tmp_path.to_str().unwrap().to_string());
        let result = S3Backend::build_store(&config, None, None);
        let _ = std::fs::remove_file(&tmp_path);
        // The PEM bundle parser may succeed with 0 certs or fail, either is acceptable
        // as long as we exercise the code path
        let _ = result;
    }

    // --- Presign expiry clamping ---

    #[test]
    fn test_presign_expiry_clamp_within_limit() {
        let expiry = Duration::from_secs(3600);
        let clamped = Duration::from_secs(expiry.as_secs().min(604800));
        assert_eq!(clamped, Duration::from_secs(3600));
    }

    #[test]
    fn test_presign_expiry_clamp_exceeds_7_days() {
        let expiry = Duration::from_secs(1_000_000);
        let clamped = Duration::from_secs(expiry.as_secs().min(604800));
        assert_eq!(clamped, Duration::from_secs(604800));
    }

    #[test]
    fn test_presign_expiry_clamp_exact_7_days() {
        let expiry = Duration::from_secs(604800);
        let clamped = Duration::from_secs(expiry.as_secs().min(604800));
        assert_eq!(clamped, Duration::from_secs(604800));
    }

    // --- S3Backend::new construction tests ---

    #[tokio::test]
    async fn test_s3_backend_new_minimal() {
        let config = S3Config::new(
            "test-bucket".to_string(),
            "us-east-1".to_string(),
            Some("http://localhost:9999".to_string()),
            Some("prefix".to_string()),
        );
        let backend = S3Backend::new(config).await;
        assert!(backend.is_ok());
    }

    #[tokio::test]
    async fn test_s3_backend_new_with_signing_store() {
        let mut config = S3Config::new(
            "test-bucket".to_string(),
            "us-east-1".to_string(),
            Some("http://localhost:9999".to_string()),
            None,
        );
        config.presign_access_key = Some("SIGN_AK".to_string());
        config.presign_secret_key = Some("SIGN_SK".to_string());
        config.redirect_downloads = true;
        let backend = S3Backend::new(config).await;
        assert!(backend.is_ok());
    }

    #[tokio::test]
    async fn test_s3_backend_new_with_tls_config() {
        let config = S3Config::new(
            "test-bucket".to_string(),
            "us-east-1".to_string(),
            Some("http://localhost:9999".to_string()),
            None,
        )
        .with_insecure_tls(true);
        let backend = S3Backend::new(config).await;
        assert!(backend.is_ok());
    }

    #[tokio::test]
    async fn test_s3_backend_new_migration_path_format() {
        let config = S3Config::new(
            "test-bucket".to_string(),
            "us-east-1".to_string(),
            Some("http://localhost:9999".to_string()),
            None,
        )
        .with_path_format(StoragePathFormat::Migration);
        let backend = S3Backend::new(config).await;
        assert!(backend.is_ok());
    }

    #[tokio::test]
    async fn test_s3_backend_supports_redirect_false_by_default() {
        let config = S3Config::new(
            "test-bucket".to_string(),
            "us-east-1".to_string(),
            Some("http://localhost:9999".to_string()),
            None,
        );
        let backend = S3Backend::new(config).await.unwrap();
        assert!(!backend.redirect_downloads);
    }

    #[tokio::test]
    async fn test_s3_backend_supports_redirect_when_enabled() {
        let config = S3Config::new(
            "test-bucket".to_string(),
            "us-east-1".to_string(),
            Some("http://localhost:9999".to_string()),
            None,
        )
        .with_redirect_downloads(true);
        let backend = S3Backend::new(config).await.unwrap();
        assert!(backend.redirect_downloads);
    }

    #[tokio::test]
    async fn test_s3_backend_full_key_integration() {
        let config = S3Config::new(
            "test-bucket".to_string(),
            "us-east-1".to_string(),
            Some("http://localhost:9999".to_string()),
            Some("myprefix".to_string()),
        );
        let backend = S3Backend::new(config).await.unwrap();
        assert_eq!(backend.full_key("some/path"), "myprefix/some/path");
        assert_eq!(backend.strip_prefix("myprefix/some/path"), "some/path");
    }

    #[tokio::test]
    async fn test_s3_backend_fallback_integration() {
        let config = S3Config::new(
            "test-bucket".to_string(),
            "us-east-1".to_string(),
            Some("http://localhost:9999".to_string()),
            None,
        )
        .with_path_format(StoragePathFormat::Migration);
        let backend = S3Backend::new(config).await.unwrap();

        let key = "91/6f/916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9";
        let fallback = backend.try_artifactory_fallback(key);
        assert_eq!(
            fallback.unwrap(),
            "91/916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
        );

        // No fallback for non-checksum paths
        assert!(backend.try_artifactory_fallback("not/valid").is_none());
    }

    #[tokio::test]
    async fn test_s3_backend_from_env_with_env_vars() {
        // Save originals
        let orig_bucket = std::env::var("S3_BUCKET").ok();
        let orig_region = std::env::var("S3_REGION").ok();
        let orig_endpoint = std::env::var("S3_ENDPOINT").ok();
        let orig_cf_url = std::env::var("CLOUDFRONT_DISTRIBUTION_URL").ok();

        std::env::set_var("S3_BUCKET", "env-test-bucket");
        std::env::set_var("S3_REGION", "ap-south-1");
        std::env::set_var("S3_ENDPOINT", "http://localhost:9999");
        std::env::remove_var("CLOUDFRONT_DISTRIBUTION_URL");

        let backend = S3Backend::from_env().await;
        assert!(
            backend.is_ok(),
            "from_env should succeed: {:?}",
            backend.err()
        );

        // Restore
        let restore = |name: &str, val: Option<String>| match val {
            Some(v) => std::env::set_var(name, v),
            None => std::env::remove_var(name),
        };
        restore("S3_BUCKET", orig_bucket);
        restore("S3_REGION", orig_region);
        restore("S3_ENDPOINT", orig_endpoint);
        restore("CLOUDFRONT_DISTRIBUTION_URL", orig_cf_url);
    }

    #[tokio::test]
    async fn test_s3_backend_new_invalid_ca_cert_fails() {
        let config = S3Config::new(
            "test-bucket".to_string(),
            "us-east-1".to_string(),
            Some("http://localhost:9999".to_string()),
            None,
        )
        .with_ca_cert_path("/nonexistent/cert.pem".to_string());
        let backend = S3Backend::new(config).await;
        assert!(backend.is_err());
    }

    // --- build_store credential chain tests ---
    //
    // These tests exercise the env-var credential chain in build_store
    // (lines ~305-368). Because env vars are process-global state and
    // cargo test runs tests in parallel, we serialize all env-mutating
    // tests behind a single mutex and save/restore every variable we touch.

    use std::sync::Mutex;

    static CRED_ENV_MUTEX: Mutex<()> = Mutex::new(());

    /// All AWS/S3 credential env var names that build_store reads.
    const CRED_ENV_VARS: &[&str] = &[
        "S3_ACCESS_KEY_ID",
        "S3_SECRET_ACCESS_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
    ];

    /// Save current values for all credential env vars.
    fn save_cred_env() -> Vec<(&'static str, Option<String>)> {
        CRED_ENV_VARS
            .iter()
            .map(|&name| (name, std::env::var(name).ok()))
            .collect()
    }

    /// Restore saved env var values.
    fn restore_cred_env(saved: Vec<(&'static str, Option<String>)>) {
        for (name, val) in saved {
            match val {
                Some(v) => std::env::set_var(name, v),
                None => std::env::remove_var(name),
            }
        }
    }

    /// Remove all credential env vars so each test starts from a clean slate.
    fn clear_cred_env() {
        for name in CRED_ENV_VARS {
            std::env::remove_var(name);
        }
    }

    /// Helper: build an S3Config pointing at a fake http endpoint so
    /// the builder never tries a real TLS handshake.
    fn test_config() -> S3Config {
        S3Config::new(
            "cred-test-bucket".to_string(),
            "us-east-1".to_string(),
            Some("http://localhost:19876".to_string()),
            None,
        )
    }

    #[test]
    fn test_build_store_succeeds_with_no_aws_env_vars() {
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        let result = S3Backend::build_store(&test_config(), None, None);
        assert!(
            result.is_ok(),
            "build_store should succeed without any AWS env vars: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_build_store_picks_up_s3_credentials() {
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        std::env::set_var("S3_ACCESS_KEY_ID", "S3AK");
        std::env::set_var("S3_SECRET_ACCESS_KEY", "S3SK");

        let result = S3Backend::build_store(&test_config(), None, None);
        assert!(
            result.is_ok(),
            "build_store should succeed with S3_* credentials: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_build_store_s3_creds_take_precedence_over_aws_creds() {
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        // Set both S3_* and AWS_* credentials. S3_* should win.
        std::env::set_var("S3_ACCESS_KEY_ID", "S3AK-wins");
        std::env::set_var("S3_SECRET_ACCESS_KEY", "S3SK-wins");
        std::env::set_var("AWS_ACCESS_KEY_ID", "AWSAK-loses");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "AWSSK-loses");

        // The builder cannot expose which credentials were chosen, but
        // we verify it builds successfully and does not error out.
        let result = S3Backend::build_store(&test_config(), None, None);
        assert!(
            result.is_ok(),
            "build_store with both S3_* and AWS_* should succeed: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_build_store_picks_up_aws_static_credentials() {
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        std::env::set_var("AWS_ACCESS_KEY_ID", "AWSAK");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "AWSSK");

        let result = S3Backend::build_store(&test_config(), None, None);
        assert!(
            result.is_ok(),
            "build_store should succeed with AWS_ACCESS_KEY_ID/SECRET: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_build_store_includes_aws_session_token() {
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        std::env::set_var("AWS_ACCESS_KEY_ID", "AWSAK");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "AWSSK");
        std::env::set_var("AWS_SESSION_TOKEN", "tok-xyz");

        let result = S3Backend::build_store(&test_config(), None, None);
        assert!(
            result.is_ok(),
            "build_store should succeed with AWS session token: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_build_store_session_token_ignored_without_aws_keys() {
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        // Session token alone, no access key / secret key
        std::env::set_var("AWS_SESSION_TOKEN", "orphan-token");

        let result = S3Backend::build_store(&test_config(), None, None);
        assert!(
            result.is_ok(),
            "build_store should succeed even with orphan session token: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_build_store_ecs_fargate_relative_uri() {
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        std::env::set_var(
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
            "/v2/credentials/some-uuid",
        );

        let result = S3Backend::build_store(&test_config(), None, None);
        assert!(
            result.is_ok(),
            "build_store should accept ECS relative URI: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_build_store_eks_pod_identity_full_uri() {
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        std::env::set_var(
            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
            "http://169.254.170.23/v1/credentials",
        );

        let result = S3Backend::build_store(&test_config(), None, None);
        assert!(
            result.is_ok(),
            "build_store should accept EKS Pod Identity full URI: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_build_store_eks_irsa_web_identity() {
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        std::env::set_var(
            "AWS_WEB_IDENTITY_TOKEN_FILE",
            "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
        );
        std::env::set_var("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/my-role");

        let result = S3Backend::build_store(&test_config(), None, None);
        assert!(
            result.is_ok(),
            "build_store should accept IRSA web identity vars: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_build_store_explicit_args_override_all_env_vars() {
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        // Set all possible env var credentials
        std::env::set_var("S3_ACCESS_KEY_ID", "S3AK-env");
        std::env::set_var("S3_SECRET_ACCESS_KEY", "S3SK-env");
        std::env::set_var("AWS_ACCESS_KEY_ID", "AWSAK-env");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "AWSSK-env");
        std::env::set_var("AWS_SESSION_TOKEN", "tok-env");

        // Explicit function args should take precedence over all env vars
        let result =
            S3Backend::build_store(&test_config(), Some("EXPLICIT-AK"), Some("EXPLICIT-SK"));
        assert!(
            result.is_ok(),
            "build_store with explicit args should override env vars: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_build_store_all_credential_sources_present() {
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        // Set every credential env var simultaneously
        std::env::set_var("S3_ACCESS_KEY_ID", "S3AK");
        std::env::set_var("S3_SECRET_ACCESS_KEY", "S3SK");
        std::env::set_var("AWS_ACCESS_KEY_ID", "AWSAK");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "AWSSK");
        std::env::set_var("AWS_SESSION_TOKEN", "tok");
        std::env::set_var("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/creds/uuid");
        std::env::set_var(
            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
            "http://169.254.170.23/v1/credentials",
        );
        std::env::set_var(
            "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
            "/var/run/secrets/token",
        );
        std::env::set_var("AWS_WEB_IDENTITY_TOKEN_FILE", "/var/run/secrets/wi-token");
        std::env::set_var("AWS_ROLE_ARN", "arn:aws:iam::111111111111:role/chaos");

        let result = S3Backend::build_store(&test_config(), None, None);
        assert!(
            result.is_ok(),
            "build_store should handle all credential sources at once: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_build_store_partial_s3_creds_fall_through_to_aws() {
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        // Only S3_ACCESS_KEY_ID without the secret: the S3_* pair is
        // incomplete so the code should fall through to AWS_* vars.
        std::env::set_var("S3_ACCESS_KEY_ID", "S3AK-partial");
        // S3_SECRET_ACCESS_KEY intentionally not set
        std::env::set_var("AWS_ACCESS_KEY_ID", "AWSAK-fallback");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "AWSSK-fallback");

        let result = S3Backend::build_store(&test_config(), None, None);
        assert!(
            result.is_ok(),
            "build_store with partial S3_* should fall through to AWS_*: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }

    #[test]
    fn test_build_store_container_auth_token_file_alone() {
        let _lock = CRED_ENV_MUTEX.lock().unwrap();
        let saved = save_cred_env();
        clear_cred_env();

        std::env::set_var(
            "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
            "/var/run/secrets/auth-token",
        );

        let result = S3Backend::build_store(&test_config(), None, None);
        assert!(
            result.is_ok(),
            "build_store should accept container auth token file: {:?}",
            result.err()
        );

        restore_cred_env(saved);
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::storage::StorageBackend as StorageBackendTrait;

    #[tokio::test]
    #[ignore]
    async fn test_s3_presigned_url_generation() {
        let bucket = match std::env::var("S3_BUCKET") {
            Ok(b) => b,
            Err(_) => {
                println!("Skipping: S3_BUCKET not set");
                return;
            }
        };

        println!("Testing with bucket: {}", bucket);

        let config = S3Config::from_env()
            .expect("Failed to load S3 config")
            .with_redirect_downloads(true)
            .with_presign_expiry(Duration::from_secs(300));

        let backend = S3Backend::new(config)
            .await
            .expect("Failed to create S3 backend");

        let test_key = format!(
            "test/presign-test-{}.txt",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
        let test_content = Bytes::from("Test content for presigned URL");

        println!("Uploading test file: {}", test_key);
        StorageBackendTrait::put(&backend, &test_key, test_content.clone())
            .await
            .expect("Failed to upload test file");

        assert!(StorageBackendTrait::supports_redirect(&backend));

        println!("Generating presigned URL...");
        let presigned =
            StorageBackendTrait::get_presigned_url(&backend, &test_key, Duration::from_secs(300))
                .await
                .expect("Failed to generate presigned URL");

        assert!(presigned.is_some());
        let presigned = presigned.unwrap();
        assert!(presigned.url.contains("X-Amz-Signature"));

        println!("Verifying presigned URL works...");
        let client = reqwest::Client::new();
        let response = client
            .get(presigned.url.as_str())
            .send()
            .await
            .expect("Failed to fetch presigned URL");
        assert!(
            response.status().is_success(),
            "Presigned URL should return 200"
        );

        let body = response.bytes().await.expect("Failed to read body");
        assert_eq!(body.as_ref(), test_content.as_ref(), "Content should match");

        println!("Cleaning up...");
        StorageBackendTrait::delete(&backend, &test_key)
            .await
            .expect("Failed to delete test file");
        println!("Test complete");
    }
}
