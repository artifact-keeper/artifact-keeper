//! Google Cloud Storage backend with signed URL support.
//!
//! Supports redirect downloads via V4 signed URLs.
//!
//! ## Configuration
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
//!
//! # For Artifactory migration:
//! STORAGE_PATH_FORMAT=migration  # native, artifactory, or migration
//! ```

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use rsa::pkcs8::DecodePrivateKey;
use rsa::sha2::Sha256;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::RsaPrivateKey;
use sha2::Digest;
use std::time::Duration;

use crate::error::{AppError, Result};
use crate::storage::{PresignedUrl, PresignedUrlSource, StorageBackend, StoragePathFormat};

/// Google Cloud Storage configuration
#[derive(Debug, Clone)]
pub struct GcsConfig {
    /// GCS bucket name
    pub bucket: String,
    /// GCP project ID
    pub project_id: String,
    /// Service account email
    pub service_account_email: String,
    /// RSA private key (PEM format)
    pub private_key: Option<String>,
    /// Enable redirect downloads via signed URLs
    pub redirect_downloads: bool,
    /// Signed URL expiry duration
    pub signed_url_expiry: Duration,
    /// Storage path format (native, artifactory, or migration)
    pub path_format: StoragePathFormat,
}

impl GcsConfig {
    /// Create config from environment variables
    pub fn from_env() -> Result<Self> {
        let bucket = std::env::var("GCS_BUCKET")
            .map_err(|_| AppError::Config("GCS_BUCKET not set".to_string()))?;

        let project_id = std::env::var("GCS_PROJECT_ID")
            .map_err(|_| AppError::Config("GCS_PROJECT_ID not set".to_string()))?;

        let service_account_email = std::env::var("GCS_SERVICE_ACCOUNT_EMAIL")
            .map_err(|_| AppError::Config("GCS_SERVICE_ACCOUNT_EMAIL not set".to_string()))?;

        // Load private key from file or environment
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

    /// Builder: set redirect downloads
    pub fn with_redirect_downloads(mut self, enabled: bool) -> Self {
        self.redirect_downloads = enabled;
        self
    }

    /// Builder: set signed URL expiry
    pub fn with_signed_url_expiry(mut self, expiry: Duration) -> Self {
        self.signed_url_expiry = expiry;
        self
    }

    /// Builder: set private key
    pub fn with_private_key(mut self, key: String) -> Self {
        self.private_key = Some(key);
        self
    }
}

/// Google Cloud Storage backend
pub struct GcsBackend {
    config: GcsConfig,
    client: reqwest::Client,
    signing_key: Option<RsaPrivateKey>,
    path_format: StoragePathFormat,
}

impl GcsBackend {
    /// Create a new GCS backend
    pub async fn new(config: GcsConfig) -> Result<Self> {
        // Parse private key if provided
        let signing_key = if let Some(ref key_pem) = config.private_key {
            // Handle escaped newlines in environment variables
            let key_pem = key_pem.replace("\\n", "\n");

            let key = RsaPrivateKey::from_pkcs8_pem(&key_pem)
                .map_err(|e| AppError::Config(format!("Invalid GCS private key: {}", e)))?;
            Some(key)
        } else {
            None
        };

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| AppError::Storage(format!("Failed to create HTTP client: {}", e)))?;

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
            signing_key,
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

    /// Get the GCS API URL for an object
    fn object_url(&self, key: &str) -> String {
        format!(
            "https://storage.googleapis.com/{}/{}",
            self.config.bucket, key
        )
    }

    /// Generate a V4 signed URL for an object
    ///
    /// Reference: https://cloud.google.com/storage/docs/access-control/signing-urls-manually
    pub fn generate_signed_url(&self, key: &str, expires_in: Duration) -> Result<String> {
        let signing_key = self.signing_key.as_ref().ok_or_else(|| {
            AppError::Config("GCS private key not configured for signed URLs".to_string())
        })?;

        let now = Utc::now();
        let expiry_seconds = expires_in.as_secs().min(604800); // Max 7 days

        // Credential scope
        let date_stamp = now.format("%Y%m%d").to_string();
        let credential_scope = format!("{}/auto/storage/goog4_request", date_stamp);
        let credential = format!("{}/{}", self.config.service_account_email, credential_scope);

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
        let signing_key_with_digest = rsa::pkcs1v15::SigningKey::<Sha256>::new(signing_key.clone());
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

#[async_trait]
impl StorageBackend for GcsBackend {
    async fn put(&self, key: &str, content: Bytes) -> Result<()> {
        // For uploads, we need OAuth2 authentication or signed URLs
        // This is a simplified implementation - in production, use google-cloud-storage crate
        // or implement proper OAuth2 flow

        // For now, we generate a signed URL for upload (PUT)
        // Note: This requires the service account to have storage.objects.create permission
        let url = self.object_url(key);

        // Generate upload signed URL (would need PUT permission in signing)
        // For simplicity, this assumes the bucket allows uploads via some auth mechanism
        let response = self
            .client
            .put(&url)
            .header("Content-Type", "application/octet-stream")
            .body(content.to_vec())
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("GCS upload failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Storage(format!(
                "GCS upload failed with status {}: {}",
                status, body
            )));
        }

        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Bytes> {
        // For reads, generate a signed URL and fetch
        let signed_url = self.generate_signed_url(key, Duration::from_secs(300))?;

        let response = self
            .client
            .get(&signed_url)
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("GCS download failed: {}", e)))?;

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
                            self.generate_signed_url(&fallback_key, Duration::from_secs(300))?;
                        let fallback_response =
                            self.client.get(&fallback_url).send().await.map_err(|e| {
                                AppError::Storage(format!("GCS fallback download failed: {}", e))
                            })?;

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
                return Err(AppError::NotFound(format!("Object not found: {}", key)));
            }
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Storage(format!(
                "GCS download failed with status {}: {}",
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
        let signed_url = self.generate_signed_url(key, Duration::from_secs(60))?;

        let response = self
            .client
            .head(&signed_url)
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("GCS HEAD request failed: {}", e)))?;

        if response.status().is_success() {
            return Ok(true);
        }

        // In migration mode, also check the Artifactory fallback path
        if self.path_format.has_fallback() {
            if let Some(fallback_key) = self.try_artifactory_fallback(key) {
                let fallback_url =
                    self.generate_signed_url(&fallback_key, Duration::from_secs(60))?;
                let fallback_response = self.client.head(&fallback_url).send().await.ok();
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
        let url = self.object_url(key);

        let response = self
            .client
            .delete(&url)
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("GCS delete failed: {}", e)))?;

        if !response.status().is_success() && response.status() != reqwest::StatusCode::NOT_FOUND {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::Storage(format!(
                "GCS delete failed with status {}: {}",
                status, body
            )));
        }

        Ok(())
    }

    fn supports_redirect(&self) -> bool {
        self.config.redirect_downloads && self.signing_key.is_some()
    }

    async fn get_presigned_url(
        &self,
        key: &str,
        expires_in: Duration,
    ) -> Result<Option<PresignedUrl>> {
        if !self.config.redirect_downloads {
            return Ok(None);
        }

        if self.signing_key.is_none() {
            tracing::warn!("GCS redirect enabled but private key not configured");
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
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test RSA private key in PKCS#8 format (DO NOT USE IN PRODUCTION - for testing only)
    const TEST_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDGFba6RcDmJ3+E
ae/+ewT/KBq64g31LmNxUrPso7VDJayu/GL+sEDw1afq2YZIHbLehJIzy5b7YCRF
xqgpMO+T+xSvK5gCdtr7uz9k6B7gmrGthLWDYNfqcBXy1YoUdhujdBRCpClp87vI
03G+jOw3JpB2nCz01cPkEjsWyIAd0XJnReRYbtvrtQaljI5PWbz/SBzA6YcAjMWk
hmMydLTNRppqVfdzTDgmauhmJikhIoikfTg0k8LH4dB57kRJPw1LqP5gQcIODVzh
f3STviGxgSYumldXgtKcmS1BLufPVmVGfBxIn9qZBYdY8aBF5Tuw31xKBxuoj6Da
MfO9lY6BAgMBAAECggEADfkUJbmr7NBWd3G9ozbsWE9s60fs8iGulBzgYk3+CFmM
/97/4LVwL0zzBmcHyOiHaJjzc0HmSZ8zj9R+okE4dTjd8alilLHrqpw/0Y9qNi/T
XskgwL7BHGGButqDXgQi2PnkP/syjK3LzlPUDzwDobRPtn430aGOqvT6RBYqq2+u
B3KVLwToRBRZSODrxMUP3NJuJQF4L7HdSBBFKi8PsRvnoX4PZFBkZBUvE9j/I1gk
RzJEf1eQt73bt1j424kbON12uw3+pfU5LHumK5Pw5W6QBpYEbnmZMWt5sw6nd1/i
2xh/iM7nkqDM3ShRxLOMgRGkT49clEfjYDt9zD7jbQKBgQDx07EbXVnNqUcao8Zp
HYEqylnCWBa/sLFHEOckzAT8V2PPlIU7dIkFmqrYIWiV/NwZOVVN3Zs2kg9zZCDF
2mjvrN4wUOOWjluXPGMfpi6/0j67xCtoeYhcZjKxQ3FYJUNFATYFrWTO0lx9LomW
Cm/0lPjFnmRVzqfTn78jBCkeOwKBgQDRsboStRU0vv1hDsabmq5I5XOIWMkwINdJ
h/Zye7Ag/+dKyRieLrq9ydl40Lmk18lO1tSl3LLh29xAHMwZH5ipnFFVerNMVsd4
zOFD+HZ+F8WvZ7ex+33iv0BEztFpdCzOtCvACa4YQubd3iT8DhaTGuVZagjENbEc
IaXQdkVOcwKBgCyjF6DmdUoaAe7v5hLHCG2eljziR6iwc7ibbR8ErbLqapkJYCJe
W2B2cSyd1hFBcFsTkyRhUGIdSc7R357FtvLupMCkXa4PruZWljFkWmK76yp7hkut
izcLAjZoLYbIsgcNtywLGn12pO3SZkEUwh+SU+0eVITmNWJBrWVIQlK7AoGANa70
Xhmx5iEHKTPpMKj2+X6Uh1GDoCioNRDzzPdRbgFVq1W0UbrQ4Amu/Tkibcs4pFBn
fFb2DNCGoHs+3Sezo6h7QhD5mg+VXZ3GBeq0Gy/m0jMRWiVyYvxnbbYs8nxlhD2n
/a/8vAVUqXRXr5fDu8Fk+fElcWX1g6gxlR7SO3UCgYAkle2pUbhtYzXo6Jhb0nFE
VOvOXph5MBRtp7Iz9DxfIiFIHRS9GHt3152oEjZYwwC/uywvXSqyAkP4af0iwEMO
0JhIjLu/cFu68UNTgURA60XjxMRKU1P4kxfY6lqI27x0My9denhrrd/BkhyUSi/l
mpzFW04qb46Uh1fAvnM0cg==
-----END PRIVATE KEY-----"#;

    fn create_test_config() -> GcsConfig {
        GcsConfig {
            bucket: "test-bucket".to_string(),
            project_id: "test-project".to_string(),
            service_account_email: "test@test-project.iam.gserviceaccount.com".to_string(),
            private_key: Some(TEST_PRIVATE_KEY.to_string()),
            redirect_downloads: true,
            signed_url_expiry: Duration::from_secs(3600),
            path_format: StoragePathFormat::Native,
        }
    }

    #[tokio::test]
    async fn test_gcs_backend_creation() {
        let config = create_test_config();
        let backend = GcsBackend::new(config).await;
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

    #[tokio::test]
    async fn test_signed_url_generation() {
        let config = create_test_config();
        let backend = GcsBackend::new(config).await.unwrap();

        let url = backend.generate_signed_url("test/artifact.txt", Duration::from_secs(3600));
        assert!(url.is_ok());

        let url = url.unwrap();
        assert!(url.contains("storage.googleapis.com"));
        assert!(url.contains("test-bucket"));
        assert!(url.contains("test/artifact.txt"));
        assert!(url.contains("X-Goog-Algorithm=GOOG4-RSA-SHA256"));
        assert!(url.contains("X-Goog-Credential="));
        assert!(url.contains("X-Goog-Date="));
        assert!(url.contains("X-Goog-Expires="));
        assert!(url.contains("X-Goog-SignedHeaders=host"));
        assert!(url.contains("X-Goog-Signature="));
    }

    #[tokio::test]
    async fn test_signed_url_contains_required_params() {
        let config = create_test_config();
        let backend = GcsBackend::new(config).await.unwrap();

        let url = backend
            .generate_signed_url("path/to/file.tar.gz", Duration::from_secs(1800))
            .unwrap();

        // Check all required V4 signed URL parameters
        assert!(url.contains("X-Goog-Algorithm="), "Missing algorithm");
        assert!(url.contains("X-Goog-Credential="), "Missing credential");
        assert!(url.contains("X-Goog-Date="), "Missing date");
        assert!(url.contains("X-Goog-Expires="), "Missing expires");
        assert!(
            url.contains("X-Goog-SignedHeaders="),
            "Missing signed headers"
        );
        assert!(url.contains("X-Goog-Signature="), "Missing signature");
    }

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
        assert!(!backend.supports_redirect()); // No key, so no redirect
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
        let config = create_test_config().with_redirect_downloads(true);
        let backend = GcsBackend::new(config).await.unwrap();

        let result = backend
            .get_presigned_url("test.txt", Duration::from_secs(3600))
            .await
            .unwrap();
        assert!(result.is_some());

        let presigned = result.unwrap();
        assert_eq!(presigned.source, PresignedUrlSource::Gcs);
        assert!(presigned.url.contains("X-Goog-Signature="));
    }

    #[tokio::test]
    async fn test_object_url_format() {
        let config = create_test_config();
        let backend = GcsBackend::new(config).await.unwrap();

        let url = backend.object_url("path/to/artifact.jar");
        assert_eq!(
            url,
            "https://storage.googleapis.com/test-bucket/path/to/artifact.jar"
        );
    }

    #[tokio::test]
    async fn test_expiry_capped_at_7_days() {
        let config = create_test_config();
        let backend = GcsBackend::new(config).await.unwrap();

        // Request 30 days, should be capped to 7 days (604800 seconds)
        let url = backend
            .generate_signed_url("test.txt", Duration::from_secs(30 * 24 * 3600))
            .unwrap();

        assert!(url.contains("X-Goog-Expires=604800"));
    }

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
        // Simulate environment variable with escaped newlines
        let mut config = create_test_config();
        config.private_key = Some(TEST_PRIVATE_KEY.replace('\n', "\\n"));

        let backend = GcsBackend::new(config).await;
        assert!(backend.is_ok());
    }
}
