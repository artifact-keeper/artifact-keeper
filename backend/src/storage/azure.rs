//! Azure Blob Storage backend with SAS URL support.
//!
//! Supports redirect downloads via Shared Access Signature (SAS) URLs.
//!
//! ## Configuration
//!
//! ```bash
//! STORAGE_BACKEND=azure
//! AZURE_STORAGE_ACCOUNT=myaccount
//! AZURE_STORAGE_CONTAINER=artifacts
//! AZURE_STORAGE_ACCESS_KEY=base64-encoded-key
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
use std::time::Duration;

use crate::error::{AppError, Result};
use crate::storage::{PresignedUrl, PresignedUrlSource, StorageBackend, StoragePathFormat};

type HmacSha256 = Hmac<Sha256>;

/// Azure Blob Storage configuration
#[derive(Debug, Clone)]
pub struct AzureConfig {
    /// Storage account name
    pub account_name: String,
    /// Container name
    pub container_name: String,
    /// Storage account access key (base64 encoded)
    pub access_key: String,
    /// Optional custom endpoint (for Azure Government, China, etc.)
    pub endpoint: Option<String>,
    /// Enable redirect downloads via SAS URLs
    pub redirect_downloads: bool,
    /// SAS URL expiry duration
    pub sas_expiry: Duration,
    /// Storage path format (native, artifactory, or migration)
    pub path_format: StoragePathFormat,
}

impl AzureConfig {
    /// Create config from environment variables
    pub fn from_env() -> Result<Self> {
        let account_name = std::env::var("AZURE_STORAGE_ACCOUNT")
            .map_err(|_| AppError::Config("AZURE_STORAGE_ACCOUNT not set".to_string()))?;

        let container_name = std::env::var("AZURE_STORAGE_CONTAINER")
            .map_err(|_| AppError::Config("AZURE_STORAGE_CONTAINER not set".to_string()))?;

        let access_key = std::env::var("AZURE_STORAGE_ACCESS_KEY")
            .map_err(|_| AppError::Config("AZURE_STORAGE_ACCESS_KEY not set".to_string()))?;

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

/// Azure Blob Storage backend
pub struct AzureBackend {
    config: AzureConfig,
    client: reqwest::Client,
    decoded_key: Vec<u8>,
    path_format: StoragePathFormat,
}

impl AzureBackend {
    /// Create a new Azure Blob Storage backend
    pub async fn new(config: AzureConfig) -> Result<Self> {
        // Decode the access key
        let decoded_key = BASE64.decode(&config.access_key).map_err(|e| {
            AppError::Config(format!(
                "Invalid AZURE_STORAGE_ACCESS_KEY (not valid base64): {}",
                e
            ))
        })?;

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| AppError::Storage(format!("Failed to create HTTP client: {}", e)))?;

        let path_format = config.path_format;

        if path_format != StoragePathFormat::Native {
            tracing::info!(
                path_format = %path_format,
                "Azure storage path format configured"
            );
        }

        Ok(Self {
            config,
            client,
            decoded_key,
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

    /// Generate a SAS token for a blob
    ///
    /// Uses Service SAS with blob resource type.
    /// Reference: https://docs.microsoft.com/en-us/rest/api/storageservices/create-service-sas
    fn generate_sas_token(&self, key: &str, expires_in: Duration) -> Result<String> {
        let now = Utc::now();
        let expiry = now + ChronoDuration::seconds(expires_in.as_secs() as i64);

        // SAS token parameters
        let signed_version = "2021-06-08"; // API version
        let signed_resource = "b"; // blob
        let signed_permissions = "r"; // read only
        let signed_start = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let signed_expiry = expiry.format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let signed_protocol = "https";

        // Canonicalized resource: /blob/{account}/{container}/{blob}
        let canonicalized_resource = format!(
            "/blob/{}/{}/{}",
            self.config.account_name, self.config.container_name, key
        );

        // String to sign (order matters!)
        // Reference: https://docs.microsoft.com/en-us/rest/api/storageservices/create-service-sas#version-2020-12-06-and-later
        let string_to_sign = format!(
            "{}\n{}\n{}\n{}\n\n{}\n\n\n\n{}\n\n\n\n",
            signed_permissions,     // signedPermissions
            signed_start,           // signedStart
            signed_expiry,          // signedExpiry
            canonicalized_resource, // canonicalizedResource
            signed_protocol,        // signedProtocol
            signed_version,         // signedVersion
        );

        // Sign with HMAC-SHA256
        let mut mac = HmacSha256::new_from_slice(&self.decoded_key)
            .map_err(|e| AppError::Storage(format!("Failed to create HMAC: {}", e)))?;
        mac.update(string_to_sign.as_bytes());
        let signature = BASE64.encode(mac.finalize().into_bytes());

        // Build the SAS query string
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

    /// Generate a SAS URL for a blob
    pub fn generate_sas_url(&self, key: &str, expires_in: Duration) -> Result<String> {
        let sas_token = self.generate_sas_token(key, expires_in)?;
        Ok(format!("{}?{}", self.blob_url(key), sas_token))
    }
}

#[async_trait]
impl StorageBackend for AzureBackend {
    async fn put(&self, key: &str, content: Bytes) -> Result<()> {
        let url = self.blob_url(key);

        // For actual uploads, we'd need to implement Azure REST API authentication
        // This is a simplified version - in production, use azure_storage_blobs crate
        let now = Utc::now();
        let date_str = now.format("%a, %d %b %Y %H:%M:%S GMT").to_string();

        // Generate authorization header using Shared Key
        let content_length = content.len();
        let string_to_sign = format!(
            "PUT\n\n\n{}\n\napplication/octet-stream\n\n\n\n\n\n\nx-ms-blob-type:BlockBlob\nx-ms-date:{}\nx-ms-version:2021-06-08\n/{}/{}/{}",
            content_length,
            date_str,
            self.config.account_name,
            self.config.container_name,
            key
        );

        let mut mac = HmacSha256::new_from_slice(&self.decoded_key)
            .map_err(|e| AppError::Storage(format!("Failed to create HMAC: {}", e)))?;
        mac.update(string_to_sign.as_bytes());
        let signature = BASE64.encode(mac.finalize().into_bytes());

        let auth_header = format!("SharedKey {}:{}", self.config.account_name, signature);

        let response = self
            .client
            .put(&url)
            .header("Authorization", auth_header)
            .header("x-ms-date", &date_str)
            .header("x-ms-version", "2021-06-08")
            .header("x-ms-blob-type", "BlockBlob")
            .header("Content-Type", "application/octet-stream")
            .header("Content-Length", content_length)
            .body(content.to_vec())
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("Azure upload failed: {}", e)))?;

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
        // For reads, generate a SAS URL and fetch
        let sas_url = self.generate_sas_url(key, Duration::from_secs(300))?;

        let response = self
            .client
            .get(&sas_url)
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("Azure download failed: {}", e)))?;

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
                            self.generate_sas_url(&fallback_key, Duration::from_secs(300))?;
                        let fallback_response =
                            self.client.get(&fallback_url).send().await.map_err(|e| {
                                AppError::Storage(format!("Azure fallback download failed: {}", e))
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
        let sas_url = self.generate_sas_url(key, Duration::from_secs(60))?;

        let response = self
            .client
            .head(&sas_url)
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("Azure HEAD request failed: {}", e)))?;

        if response.status().is_success() {
            return Ok(true);
        }

        // In migration mode, also check the Artifactory fallback path
        if self.path_format.has_fallback() {
            if let Some(fallback_key) = self.try_artifactory_fallback(key) {
                let fallback_url = self.generate_sas_url(&fallback_key, Duration::from_secs(60))?;
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
        let url = self.blob_url(key);
        let now = Utc::now();
        let date_str = now.format("%a, %d %b %Y %H:%M:%S GMT").to_string();

        let string_to_sign = format!(
            "DELETE\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:{}\nx-ms-version:2021-06-08\n/{}/{}/{}",
            date_str, self.config.account_name, self.config.container_name, key
        );

        let mut mac = HmacSha256::new_from_slice(&self.decoded_key)
            .map_err(|e| AppError::Storage(format!("Failed to create HMAC: {}", e)))?;
        mac.update(string_to_sign.as_bytes());
        let signature = BASE64.encode(mac.finalize().into_bytes());

        let auth_header = format!("SharedKey {}:{}", self.config.account_name, signature);

        let response = self
            .client
            .delete(&url)
            .header("Authorization", auth_header)
            .header("x-ms-date", &date_str)
            .header("x-ms-version", "2021-06-08")
            .send()
            .await
            .map_err(|e| AppError::Storage(format!("Azure delete failed: {}", e)))?;

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
        self.config.redirect_downloads
    }

    async fn get_presigned_url(
        &self,
        key: &str,
        expires_in: Duration,
    ) -> Result<Option<PresignedUrl>> {
        if !self.config.redirect_downloads {
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
            access_key:
                "dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleXRlc3RrZXk="
                    .to_string(),
            endpoint: None,
            redirect_downloads: true,
            sas_expiry: Duration::from_secs(3600),
            path_format: StoragePathFormat::Native,
        }
    }

    #[tokio::test]
    async fn test_azure_backend_creation() {
        let config = create_test_config();
        let backend = AzureBackend::new(config).await;
        assert!(backend.is_ok());
    }

    #[tokio::test]
    async fn test_sas_url_generation() {
        let config = create_test_config();
        let backend = AzureBackend::new(config).await.unwrap();

        let url = backend.generate_sas_url("test/artifact.txt", Duration::from_secs(3600));
        assert!(url.is_ok());

        let url = url.unwrap();
        assert!(url.contains("testaccount.blob.core.windows.net"));
        assert!(url.contains("testcontainer"));
        assert!(url.contains("test/artifact.txt"));
        assert!(url.contains("sv=")); // signed version
        assert!(url.contains("se=")); // signed expiry
        assert!(url.contains("sig=")); // signature
        assert!(url.contains("sp=r")); // read permission
    }

    #[tokio::test]
    async fn test_sas_url_contains_required_params() {
        let config = create_test_config();
        let backend = AzureBackend::new(config).await.unwrap();

        let url = backend
            .generate_sas_url("path/to/file.tar.gz", Duration::from_secs(1800))
            .unwrap();

        // Check all required SAS parameters
        assert!(url.contains("sv="), "Missing signed version");
        assert!(url.contains("st="), "Missing signed start");
        assert!(url.contains("se="), "Missing signed expiry");
        assert!(url.contains("sr=b"), "Missing signed resource (blob)");
        assert!(url.contains("sp=r"), "Missing signed permissions");
        assert!(url.contains("spr=https"), "Missing signed protocol");
        assert!(url.contains("sig="), "Missing signature");
    }

    #[tokio::test]
    async fn test_supports_redirect() {
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
    async fn test_blob_url_format() {
        let config = create_test_config();
        let backend = AzureBackend::new(config).await.unwrap();

        let url = backend.blob_url("path/to/artifact.jar");
        assert_eq!(
            url,
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

    #[test]
    fn test_invalid_access_key() {
        let mut config = create_test_config();
        config.access_key = "not-valid-base64!!!".to_string();

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(AzureBackend::new(config));
        assert!(result.is_err());
    }
}
