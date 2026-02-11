//! S3 storage backend using rust-s3 crate.
//!
//! Supports AWS S3 and S3-compatible services (MinIO, etc.).
//! Configuration via environment variables:
//! - S3_BUCKET: Bucket name (required)
//! - S3_REGION: AWS region (default: us-east-1)
//! - S3_ENDPOINT: Custom endpoint URL for S3-compatible services
//! - AWS_ACCESS_KEY_ID: Access key (optional if using instance roles/IRSA)
//! - AWS_SECRET_ACCESS_KEY: Secret key (optional if using instance roles/IRSA)
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
use s3::bucket::Bucket;
use s3::creds::Credentials;
use s3::region::Region;
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
}

/// S3-compatible storage backend
pub struct S3Backend {
    bucket: Box<Bucket>,
    prefix: Option<String>,
    /// Enable redirect downloads via presigned URLs
    redirect_downloads: bool,
    /// Default presigned URL expiry
    presign_expiry: Duration,
    /// CloudFront configuration (optional)
    cloudfront: Option<CloudFrontConfig>,
    /// Storage path format (for Artifactory compatibility)
    path_format: StoragePathFormat,
    /// Pre-built signing bucket with dedicated credentials (Option B)
    signing_bucket: Option<Box<Bucket>>,
    /// Stored region for creating fresh signing buckets (Option A)
    region: Region,
    /// Stored bucket name for creating fresh signing buckets (Option A)
    bucket_name: String,
    /// Whether to use path-style access (for MinIO)
    use_path_style: bool,
}

impl S3Backend {
    /// Create new S3 backend from configuration
    pub async fn new(config: S3Config) -> Result<Self> {
        // Load credentials using the default credential chain:
        // env vars -> ~/.aws/credentials -> container credentials -> instance metadata (IRSA/EC2)
        let credentials = Credentials::default()
            .map_err(|e| AppError::Config(format!("Failed to load AWS credentials: {}", e)))?;

        // Create region (with optional custom endpoint)
        let region = match &config.endpoint {
            Some(endpoint) => Region::Custom {
                region: config.region.clone(),
                endpoint: endpoint.clone(),
            },
            None => config
                .region
                .parse()
                .map_err(|_| AppError::Config(format!("Invalid S3 region: {}", config.region)))?,
        };

        let use_path_style = config.endpoint.is_some();

        // Create bucket handle
        let bucket = Bucket::new(&config.bucket, region.clone(), credentials)
            .map_err(|e| AppError::Config(format!("Failed to create S3 bucket: {}", e)))?;

        // Enable path-style access for MinIO compatibility
        let bucket = if use_path_style {
            bucket.with_path_style()
        } else {
            bucket
        };

        // Build dedicated signing bucket if explicit presign credentials are provided
        let signing_bucket = match (&config.presign_access_key, &config.presign_secret_key) {
            (Some(ak), Some(sk)) => {
                let signing_creds = Credentials::new(Some(ak), Some(sk), None, None, None)
                    .map_err(|e| AppError::Config(format!("Invalid presign credentials: {}", e)))?;
                let sb =
                    Bucket::new(&config.bucket, region.clone(), signing_creds).map_err(|e| {
                        AppError::Config(format!("Failed to create signing bucket: {}", e))
                    })?;
                let sb = if use_path_style {
                    sb.with_path_style()
                } else {
                    sb
                };
                tracing::info!("Using dedicated credentials for presigned URL signing");
                Some(sb)
            }
            _ => None,
        };

        if config.redirect_downloads {
            tracing::info!(
                bucket = %config.bucket,
                cloudfront = config.cloudfront.is_some(),
                expiry_secs = config.presign_expiry.as_secs(),
                dedicated_signing_creds = signing_bucket.is_some(),
                "S3 redirect downloads enabled"
            );
        }

        if config.path_format != StoragePathFormat::Native {
            tracing::info!(
                path_format = %config.path_format,
                "S3 storage path format configured"
            );
        }

        let bucket_name = config.bucket;

        Ok(Self {
            bucket,
            prefix: config.prefix,
            redirect_downloads: config.redirect_downloads,
            presign_expiry: config.presign_expiry,
            cloudfront: config.cloudfront,
            path_format: config.path_format,
            signing_bucket,
            region,
            bucket_name,
            use_path_style,
        })
    }

    /// Create S3 backend from environment variables
    pub async fn from_env() -> Result<Self> {
        let config = S3Config::from_env()?;
        Self::new(config).await
    }

    /// Generate the full S3 key with optional prefix
    fn full_key(&self, key: &str) -> String {
        match &self.prefix {
            Some(prefix) => format!("{}/{}", prefix.trim_end_matches('/'), key),
            None => key.to_string(),
        }
    }

    /// Strip the prefix from an S3 key
    fn strip_prefix(&self, key: &str) -> String {
        match &self.prefix {
            Some(prefix) => {
                let prefix_with_slash = format!("{}/", prefix.trim_end_matches('/'));
                key.strip_prefix(&prefix_with_slash)
                    .unwrap_or(key)
                    .to_string()
            }
            None => key.to_string(),
        }
    }

    /// Try to generate an Artifactory fallback path from a native path
    ///
    /// Native format: ab/cd/abcd...full_checksum (64 chars)
    /// Artifactory format: ab/abcd...full_checksum
    fn try_artifactory_fallback(&self, key: &str) -> Option<String> {
        // Parse native format: {checksum[0:2]}/{checksum[2:4]}/{checksum}
        let parts: Vec<&str> = key.split('/').collect();
        if parts.len() >= 3 {
            // Last part should be the full checksum
            let checksum = parts[parts.len() - 1];
            if checksum.len() == 64 && checksum.chars().all(|c| c.is_ascii_hexdigit()) {
                // Generate Artifactory format: {checksum[0:2]}/{checksum}
                return Some(format!("{}/{}", &checksum[..2], checksum));
            }
        }
        None
    }
}

#[async_trait]
impl super::StorageBackend for S3Backend {
    async fn put(&self, key: &str, content: Bytes) -> Result<()> {
        let full_key = self.full_key(key);

        self.bucket
            .put_object(&full_key, &content)
            .await
            .map_err(|e| AppError::Storage(format!("Failed to put object '{}': {}", key, e)))?;

        tracing::debug!(key = %key, "S3 put object successful");
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Bytes> {
        let full_key = self.full_key(key);

        let response = match self.bucket.get_object(&full_key).await {
            Ok(resp) => resp,
            Err(e) => {
                // Check for 404 errors - if in migration mode, try fallback path
                let err_str = e.to_string();
                if (err_str.contains("404") || err_str.contains("NoSuchKey"))
                    && self.path_format.has_fallback()
                {
                    // Extract checksum from the key to generate fallback path
                    // Key format is like: ab/cd/abcd...full_checksum
                    if let Some(fallback_key) = self.try_artifactory_fallback(key) {
                        let fallback_full_key = self.full_key(&fallback_key);
                        tracing::debug!(
                            original = %key,
                            fallback = %fallback_key,
                            "Trying Artifactory fallback path"
                        );
                        match self.bucket.get_object(&fallback_full_key).await {
                            Ok(resp) => {
                                tracing::info!(
                                    key = %key,
                                    fallback = %fallback_key,
                                    size = resp.bytes().len(),
                                    "Found artifact at Artifactory fallback path"
                                );
                                return Ok(Bytes::from(resp.to_vec()));
                            }
                            Err(_) => {
                                // Fallback also failed, return original error
                            }
                        }
                    }
                }

                // Original error handling
                if err_str.contains("404") || err_str.contains("NoSuchKey") {
                    return Err(AppError::NotFound(format!(
                        "Storage key not found: {}",
                        key
                    )));
                } else {
                    return Err(AppError::Storage(format!(
                        "Failed to get object '{}': {}",
                        key, e
                    )));
                }
            }
        };

        tracing::debug!(key = %key, size = response.bytes().len(), "S3 get object successful");
        Ok(Bytes::from(response.to_vec()))
    }

    async fn exists(&self, key: &str) -> Result<bool> {
        let full_key = self.full_key(key);

        match self.bucket.head_object(&full_key).await {
            Ok(_) => Ok(true),
            Err(e) => {
                // Check if it's a "not found" error
                let err_str = e.to_string();
                if err_str.contains("404")
                    || err_str.contains("NoSuchKey")
                    || err_str.contains("Not Found")
                {
                    // In migration mode, also check the Artifactory fallback path
                    if self.path_format.has_fallback() {
                        if let Some(fallback_key) = self.try_artifactory_fallback(key) {
                            let fallback_full_key = self.full_key(&fallback_key);
                            if self.bucket.head_object(&fallback_full_key).await.is_ok() {
                                tracing::debug!(
                                    key = %key,
                                    fallback = %fallback_key,
                                    "Found artifact at Artifactory fallback path"
                                );
                                return Ok(true);
                            }
                        }
                    }
                    Ok(false)
                } else {
                    Err(AppError::Storage(format!(
                        "Failed to check existence of '{}': {}",
                        key, e
                    )))
                }
            }
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let full_key = self.full_key(key);

        self.bucket
            .delete_object(&full_key)
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
        let expiry_secs = expires_in.as_secs().min(604800) as u32; // Max 7 days for S3

        // If CloudFront is configured, use CloudFront signed URLs
        if let Some(cf) = &self.cloudfront {
            let url = self.generate_cloudfront_signed_url(cf, &full_key, expires_in)?;
            tracing::debug!(
                key = %key,
                expires_in_secs = expiry_secs,
                source = "cloudfront",
                "Generated CloudFront signed URL"
            );
            return Ok(Some(PresignedUrl {
                url,
                expires_in,
                source: PresignedUrlSource::CloudFront,
            }));
        }

        // Generate S3 presigned URL with fresh or dedicated credentials
        let presign_result = if let Some(sb) = &self.signing_bucket {
            // Option B: use dedicated signing credentials (long-lived, no STS expiry concern)
            sb.presign_get(&full_key, expiry_secs, None).await
        } else {
            // Option A: refresh credentials from default chain before signing
            // This ensures STS/IRSA credentials are current, so the presigned URL
            // gets the full requested lifetime instead of being limited by
            // the remaining TTL of stale credentials.
            match Credentials::default() {
                Ok(fresh_creds) => {
                    match Bucket::new(&self.bucket_name, self.region.clone(), fresh_creds) {
                        Ok(fresh_bucket) => {
                            let fresh_bucket = if self.use_path_style {
                                fresh_bucket.with_path_style()
                            } else {
                                fresh_bucket
                            };
                            fresh_bucket.presign_get(&full_key, expiry_secs, None).await
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to create fresh signing bucket, using cached credentials: {}",
                                e
                            );
                            self.bucket.presign_get(&full_key, expiry_secs, None).await
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to refresh credentials for presigning, using cached credentials: {}",
                        e
                    );
                    self.bucket.presign_get(&full_key, expiry_secs, None).await
                }
            }
        };

        let url = presign_result.map_err(|e| {
            AppError::Storage(format!(
                "Failed to generate presigned URL for '{}': {}",
                key, e
            ))
        })?;

        tracing::debug!(
            key = %key,
            expires_in_secs = expiry_secs,
            source = "s3",
            dedicated_creds = self.signing_bucket.is_some(),
            "Generated S3 presigned URL"
        );

        Ok(Some(PresignedUrl {
            url,
            expires_in,
            source: PresignedUrlSource::S3,
        }))
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

        let results = self
            .bucket
            .list(search_prefix, None)
            .await
            .map_err(|e| AppError::Storage(format!("Failed to list objects: {}", e)))?;

        let keys: Vec<String> = results
            .into_iter()
            .flat_map(|result| result.contents)
            .map(|obj| self.strip_prefix(&obj.key))
            .collect();

        tracing::debug!(prefix = ?prefix, count = keys.len(), "S3 list objects successful");
        Ok(keys)
    }

    /// Copy content from one key to another
    pub async fn copy(&self, source: &str, dest: &str) -> Result<()> {
        let source_key = self.full_key(source);
        let dest_key = self.full_key(dest);

        // S3 CopyObject requires source in format "bucket/key"
        let copy_source = format!("{}/{}", self.bucket.name(), source_key);

        self.bucket
            .copy_object_internal(&copy_source, &dest_key)
            .await
            .map_err(|e| {
                AppError::Storage(format!("Failed to copy '{}' to '{}': {}", source, dest, e))
            })?;

        tracing::debug!(source = %source, dest = %dest, "S3 copy object successful");
        Ok(())
    }

    /// Get content size without fetching full content
    pub async fn size(&self, key: &str) -> Result<u64> {
        let full_key = self.full_key(key);

        let (head, _) = self.bucket.head_object(&full_key).await.map_err(|e| {
            let err_str = e.to_string();
            if err_str.contains("404")
                || err_str.contains("NoSuchKey")
                || err_str.contains("Not Found")
            {
                AppError::NotFound(format!("Storage key not found: {}", key))
            } else {
                AppError::Storage(format!("Failed to get size of '{}': {}", key, e))
            }
        })?;

        let size = head.content_length.unwrap_or(0) as u64;
        tracing::debug!(key = %key, size = size, "S3 head object successful");
        Ok(size)
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

    /// Check if redirect downloads are enabled
    pub fn redirect_enabled(&self) -> bool {
        self.redirect_downloads
    }

    /// Get the default presign expiry duration
    pub fn default_presign_expiry(&self) -> Duration {
        self.presign_expiry
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_key_with_prefix() {
        // We can't create a real S3Backend without credentials, but we can test the key logic
        // by testing the string operations directly
        let prefix = Some("artifacts".to_string());
        let key = "test/file.txt";

        let full = match &prefix {
            Some(p) => format!("{}/{}", p.trim_end_matches('/'), key),
            None => key.to_string(),
        };

        assert_eq!(full, "artifacts/test/file.txt");
    }

    #[test]
    fn test_full_key_without_prefix() {
        let prefix: Option<String> = None;
        let key = "test/file.txt";

        let full = match &prefix {
            Some(p) => format!("{}/{}", p.trim_end_matches('/'), key),
            None => key.to_string(),
        };

        assert_eq!(full, "test/file.txt");
    }

    #[test]
    fn test_strip_prefix() {
        let prefix = Some("artifacts".to_string());
        let key = "artifacts/test/file.txt";

        let stripped = match &prefix {
            Some(p) => {
                let prefix_with_slash = format!("{}/", p.trim_end_matches('/'));
                key.strip_prefix(&prefix_with_slash)
                    .unwrap_or(key)
                    .to_string()
            }
            None => key.to_string(),
        };

        assert_eq!(stripped, "test/file.txt");
    }

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
    fn test_artifactory_fallback_path_extraction() {
        // Test the path extraction logic directly
        let native_key = "91/6f/916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9";

        // Parse native format: {checksum[0:2]}/{checksum[2:4]}/{checksum}
        let parts: Vec<&str> = native_key.split('/').collect();
        assert_eq!(parts.len(), 3);

        let checksum = parts[2];
        assert_eq!(checksum.len(), 64);

        // Generate Artifactory format
        let artifactory_key = format!("{}/{}", &checksum[..2], checksum);
        assert_eq!(
            artifactory_key,
            "91/916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
        );
    }

    #[test]
    fn test_artifactory_fallback_invalid_key() {
        // Test with invalid key (not a valid checksum path)
        let invalid_key = "not/a/valid/path.txt";

        let parts: Vec<&str> = invalid_key.split('/').collect();
        let last_part = parts.last().unwrap();

        // Should not match: not 64 chars and not all hex
        assert!(last_part.len() != 64 || !last_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_path_format_with_s3_config() {
        // Test that path format is properly set via with_path_format
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
        // Without presign credentials, Option A (auto-refresh) will be used
        assert!(config.presign_access_key.is_none());
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::storage::StorageBackend as StorageBackendTrait;

    /// Integration test for S3 presigned URLs
    /// Run with: S3_BUCKET=your-bucket cargo test s3_presigned --lib -- --ignored --nocapture
    #[tokio::test]
    #[ignore] // Requires AWS credentials and S3 bucket
    async fn test_s3_presigned_url_generation() {
        // Skip if S3_BUCKET not set
        let bucket = match std::env::var("S3_BUCKET") {
            Ok(b) => b,
            Err(_) => {
                println!("Skipping: S3_BUCKET not set");
                return;
            }
        };

        println!("Testing with bucket: {}", bucket);

        // Create config with redirect enabled
        let config = S3Config::from_env()
            .expect("Failed to load S3 config")
            .with_redirect_downloads(true)
            .with_presign_expiry(Duration::from_secs(300));

        let backend = S3Backend::new(config)
            .await
            .expect("Failed to create S3 backend");

        // Upload a test file
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

        // Check supports_redirect
        assert!(
            StorageBackendTrait::supports_redirect(&backend),
            "Backend should support redirect"
        );

        // Generate presigned URL
        println!("Generating presigned URL...");
        let presigned =
            StorageBackendTrait::get_presigned_url(&backend, &test_key, Duration::from_secs(300))
                .await
                .expect("Failed to generate presigned URL");

        assert!(presigned.is_some(), "Should return presigned URL");
        let presigned = presigned.unwrap();

        println!(
            "Presigned URL: {}...",
            &presigned.url[..80.min(presigned.url.len())]
        );
        println!("Source: {:?}", presigned.source);
        println!("Expires in: {:?}", presigned.expires_in);

        assert!(
            presigned.url.contains(&bucket),
            "URL should contain bucket name"
        );
        assert!(
            presigned.url.contains("X-Amz-Signature"),
            "URL should have signature"
        );

        // Verify URL works by downloading
        println!("Verifying presigned URL works...");
        let client = reqwest::Client::new();
        let response = client
            .get(&presigned.url)
            .send()
            .await
            .expect("Failed to fetch presigned URL");
        assert!(
            response.status().is_success(),
            "Presigned URL should return 200"
        );

        let body = response.bytes().await.expect("Failed to read body");
        assert_eq!(body.as_ref(), test_content.as_ref(), "Content should match");
        println!("✓ Presigned URL works!");

        // Cleanup
        println!("Cleaning up...");
        StorageBackendTrait::delete(&backend, &test_key)
            .await
            .expect("Failed to delete test file");
        println!("✓ Test complete");
    }
}
