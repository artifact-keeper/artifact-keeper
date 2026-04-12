//! Download response helper for redirect support.
//!
//! Provides utilities for handlers to return either:
//! - 302 redirect to presigned URL (S3/CloudFront/Azure/GCS)
//! - Streamed content (filesystem or when redirect is disabled)

use axum::body::Body;
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE, LOCATION};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use std::time::Duration;

use crate::storage::{PresignedUrl, PresignedUrlSource, StorageBackend};

/// Header to indicate how the artifact was served
pub const X_ARTIFACT_STORAGE: &str = "x-artifact-storage";

/// Download response that can be either a redirect or streamed content
pub enum DownloadResponse {
    /// 302 redirect to presigned URL
    Redirect(PresignedUrl),
    /// Stream content directly
    Content {
        data: Bytes,
        content_type: String,
        filename: Option<String>,
    },
}

impl DownloadResponse {
    /// Create a redirect response
    pub fn redirect(url: PresignedUrl) -> Self {
        Self::Redirect(url)
    }

    /// Create a content response
    pub fn content(data: Bytes, content_type: impl Into<String>) -> Self {
        Self::Content {
            data,
            content_type: content_type.into(),
            filename: None,
        }
    }

    /// Create a content response with filename for Content-Disposition
    pub fn content_with_filename(
        data: Bytes,
        content_type: impl Into<String>,
        filename: impl Into<String>,
    ) -> Self {
        Self::Content {
            data,
            content_type: content_type.into(),
            filename: Some(filename.into()),
        }
    }
}

impl IntoResponse for DownloadResponse {
    fn into_response(self) -> Response {
        match self {
            DownloadResponse::Redirect(presigned) => {
                let source = match presigned.source {
                    PresignedUrlSource::S3 => "redirect-s3",
                    PresignedUrlSource::CloudFront => "redirect-cloudfront",
                    PresignedUrlSource::Azure => "redirect-azure",
                    PresignedUrlSource::Gcs => "redirect-gcs",
                };

                Response::builder()
                    .status(StatusCode::FOUND)
                    .header(LOCATION, presigned.url)
                    .header(X_ARTIFACT_STORAGE, source)
                    .header(
                        "Cache-Control",
                        format!("private, max-age={}", presigned.expires_in.as_secs()),
                    )
                    .body(Body::empty())
                    .unwrap()
            }
            DownloadResponse::Content {
                data,
                content_type,
                filename,
            } => {
                let mut builder = Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, content_type)
                    .header(CONTENT_LENGTH, data.len())
                    .header(X_ARTIFACT_STORAGE, "proxy");

                if let Some(name) = filename {
                    builder = builder.header(
                        "Content-Disposition",
                        format!("attachment; filename=\"{}\"", name),
                    );
                }

                builder.body(Body::from(data)).unwrap()
            }
        }
    }
}

/// Serve content from storage, using redirect if available
///
/// This helper checks if the storage backend supports redirects and returns
/// either a 302 redirect to a presigned URL or streams the content directly.
pub async fn serve_from_storage<S: StorageBackend + ?Sized>(
    storage: &S,
    key: &str,
    content_type: &str,
    filename: Option<&str>,
) -> Result<DownloadResponse, crate::error::AppError> {
    // Check if redirect is supported
    if storage.supports_redirect() {
        // Try to get presigned URL with default expiry (1 hour)
        if let Some(presigned) = storage
            .get_presigned_url(key, Duration::from_secs(3600))
            .await?
        {
            tracing::debug!(
                key = %key,
                source = ?presigned.source,
                "Serving artifact via redirect"
            );
            return Ok(DownloadResponse::redirect(presigned));
        }
    }

    // Fall back to streaming content
    let data = storage.get(key).await?;
    tracing::debug!(
        key = %key,
        size = data.len(),
        "Serving artifact via proxy"
    );

    Ok(match filename {
        Some(name) => DownloadResponse::content_with_filename(data, content_type, name),
        None => DownloadResponse::content(data, content_type),
    })
}

/// Serve content with custom expiry for presigned URLs
pub async fn serve_from_storage_with_expiry<S: StorageBackend + ?Sized>(
    storage: &S,
    key: &str,
    content_type: &str,
    filename: Option<&str>,
    expiry: Duration,
) -> Result<DownloadResponse, crate::error::AppError> {
    if storage.supports_redirect() {
        if let Some(presigned) = storage.get_presigned_url(key, expiry).await? {
            tracing::debug!(
                key = %key,
                source = ?presigned.source,
                expiry_secs = expiry.as_secs(),
                "Serving artifact via redirect"
            );
            return Ok(DownloadResponse::redirect(presigned));
        }
    }

    let data = storage.get(key).await?;
    Ok(match filename {
        Some(name) => DownloadResponse::content_with_filename(data, content_type, name),
        None => DownloadResponse::content(data, content_type),
    })
}

/// Try to generate a presigned redirect response for a storage key.
///
/// Returns `Some(Response)` with a 302 redirect if `presigned_enabled` is true
/// and the storage backend supports presigned URLs. Returns `None` otherwise,
/// signaling the caller should fall back to streaming the content.
///
/// This is the primary entry point for format handlers that want to opt in to
/// presigned download redirects without restructuring their response logic.
pub async fn try_presigned_redirect<S: StorageBackend + ?Sized>(
    storage: &S,
    key: &str,
    presigned_enabled: bool,
    expiry: Duration,
) -> Option<axum::response::Response> {
    if !presigned_enabled || !storage.supports_redirect() {
        return None;
    }

    match storage.get_presigned_url(key, expiry).await {
        Ok(Some(presigned)) => {
            tracing::debug!(
                key = %key,
                source = ?presigned.source,
                expiry_secs = expiry.as_secs(),
                "Serving artifact via presigned redirect"
            );
            Some(DownloadResponse::redirect(presigned).into_response())
        }
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(
                key = %key,
                error = %e,
                "Failed to generate presigned URL, falling back to proxy"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use bytes::Bytes;

    #[test]
    fn test_redirect_constructor() {
        let presigned = PresignedUrl {
            url: "https://s3.example.com/bucket/key?sig=abc".to_string(),
            expires_in: Duration::from_secs(3600),
            source: PresignedUrlSource::S3,
        };
        let resp = DownloadResponse::redirect(presigned);
        assert!(matches!(resp, DownloadResponse::Redirect(_)));
    }

    #[test]
    fn test_content_constructor() {
        let data = Bytes::from_static(b"hello world");
        let resp = DownloadResponse::content(data, "text/plain");
        match resp {
            DownloadResponse::Content {
                data,
                content_type,
                filename,
            } => {
                assert_eq!(data.as_ref(), b"hello world");
                assert_eq!(content_type, "text/plain");
                assert!(filename.is_none());
            }
            _ => panic!("Expected Content variant"),
        }
    }

    #[test]
    fn test_content_with_filename_constructor() {
        let data = Bytes::from_static(b"jar content");
        let resp = DownloadResponse::content_with_filename(
            data,
            "application/java-archive",
            "mylib-1.0.jar",
        );
        match resp {
            DownloadResponse::Content {
                data,
                content_type,
                filename,
            } => {
                assert_eq!(data.as_ref(), b"jar content");
                assert_eq!(content_type, "application/java-archive");
                assert_eq!(filename.as_deref(), Some("mylib-1.0.jar"));
            }
            _ => panic!("Expected Content variant"),
        }
    }

    fn make_redirect_response(source: PresignedUrlSource) -> Response {
        let presigned = PresignedUrl {
            url: "https://storage.example.com/artifact".to_string(),
            expires_in: Duration::from_secs(1800),
            source,
        };
        DownloadResponse::Redirect(presigned).into_response()
    }

    #[test]
    fn test_redirect_s3_into_response() {
        let resp = make_redirect_response(PresignedUrlSource::S3);
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(
            resp.headers().get("location").unwrap().to_str().unwrap(),
            "https://storage.example.com/artifact"
        );
        assert_eq!(
            resp.headers()
                .get(X_ARTIFACT_STORAGE)
                .unwrap()
                .to_str()
                .unwrap(),
            "redirect-s3"
        );
        assert_eq!(
            resp.headers()
                .get("cache-control")
                .unwrap()
                .to_str()
                .unwrap(),
            "private, max-age=1800"
        );
    }

    #[test]
    fn test_redirect_cloudfront_into_response() {
        let resp = make_redirect_response(PresignedUrlSource::CloudFront);
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(
            resp.headers()
                .get(X_ARTIFACT_STORAGE)
                .unwrap()
                .to_str()
                .unwrap(),
            "redirect-cloudfront"
        );
    }

    #[test]
    fn test_redirect_azure_into_response() {
        let resp = make_redirect_response(PresignedUrlSource::Azure);
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(
            resp.headers()
                .get(X_ARTIFACT_STORAGE)
                .unwrap()
                .to_str()
                .unwrap(),
            "redirect-azure"
        );
    }

    #[test]
    fn test_redirect_gcs_into_response() {
        let resp = make_redirect_response(PresignedUrlSource::Gcs);
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(
            resp.headers()
                .get(X_ARTIFACT_STORAGE)
                .unwrap()
                .to_str()
                .unwrap(),
            "redirect-gcs"
        );
    }

    #[test]
    fn test_content_into_response_without_filename() {
        let data = Bytes::from_static(b"file contents here");
        let resp = DownloadResponse::Content {
            data,
            content_type: "application/octet-stream".to_string(),
            filename: None,
        }
        .into_response();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap(),
            "application/octet-stream"
        );
        assert_eq!(
            resp.headers()
                .get("content-length")
                .unwrap()
                .to_str()
                .unwrap(),
            "18"
        );
        assert_eq!(
            resp.headers()
                .get(X_ARTIFACT_STORAGE)
                .unwrap()
                .to_str()
                .unwrap(),
            "proxy"
        );
        assert!(resp.headers().get("content-disposition").is_none());
    }

    #[test]
    fn test_content_into_response_with_filename() {
        let data = Bytes::from_static(b"PKzip");
        let resp = DownloadResponse::Content {
            data,
            content_type: "application/zip".to_string(),
            filename: Some("archive.zip".to_string()),
        }
        .into_response();

        assert_eq!(resp.status(), StatusCode::OK);
        let cd = resp
            .headers()
            .get("content-disposition")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cd, "attachment; filename=\"archive.zip\"");
    }

    #[test]
    fn test_content_into_response_empty_body() {
        let data = Bytes::new();
        let resp = DownloadResponse::content(data, "text/plain").into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("content-length")
                .unwrap()
                .to_str()
                .unwrap(),
            "0"
        );
    }

    #[test]
    fn test_redirect_cache_control_uses_expires_in() {
        let presigned = PresignedUrl {
            url: "https://cdn.example.com/file".to_string(),
            expires_in: Duration::from_secs(7200),
            source: PresignedUrlSource::CloudFront,
        };
        let resp = DownloadResponse::redirect(presigned).into_response();
        assert_eq!(
            resp.headers()
                .get("cache-control")
                .unwrap()
                .to_str()
                .unwrap(),
            "private, max-age=7200"
        );
    }

    #[test]
    fn test_x_artifact_storage_header_constant() {
        assert_eq!(X_ARTIFACT_STORAGE, "x-artifact-storage");
    }

    // -- try_presigned_redirect tests -----------------------------------------

    use crate::error::Result as AppResult;
    use crate::storage::PresignedUrl as PU;
    use async_trait::async_trait;

    /// A mock backend that supports presigned URLs.
    struct RedirectBackend;

    #[async_trait]
    impl StorageBackend for RedirectBackend {
        async fn put(&self, _key: &str, _content: Bytes) -> AppResult<()> {
            Ok(())
        }
        async fn get(&self, _key: &str) -> AppResult<Bytes> {
            Ok(Bytes::from_static(b"data"))
        }
        async fn exists(&self, _key: &str) -> AppResult<bool> {
            Ok(true)
        }
        async fn delete(&self, _key: &str) -> AppResult<()> {
            Ok(())
        }
        fn supports_redirect(&self) -> bool {
            true
        }
        async fn get_presigned_url(
            &self,
            key: &str,
            expires_in: Duration,
        ) -> AppResult<Option<PU>> {
            Ok(Some(PU {
                url: format!("https://s3.example.com/{}", key),
                expires_in,
                source: PresignedUrlSource::S3,
            }))
        }
    }

    /// A mock backend that does not support presigned URLs.
    struct NoRedirectBackend;

    #[async_trait]
    impl StorageBackend for NoRedirectBackend {
        async fn put(&self, _key: &str, _content: Bytes) -> AppResult<()> {
            Ok(())
        }
        async fn get(&self, _key: &str) -> AppResult<Bytes> {
            Ok(Bytes::from_static(b"data"))
        }
        async fn exists(&self, _key: &str) -> AppResult<bool> {
            Ok(true)
        }
        async fn delete(&self, _key: &str) -> AppResult<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_try_presigned_redirect_enabled_and_supported() {
        let backend = RedirectBackend;
        let result = super::try_presigned_redirect(
            &backend,
            "cas/ab/cd/abcdef",
            true,
            Duration::from_secs(300),
        )
        .await;

        assert!(result.is_some(), "Should return a redirect response");
        let resp = result.unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("s3.example.com"));
        assert!(location.contains("cas/ab/cd/abcdef"));
    }

    #[tokio::test]
    async fn test_try_presigned_redirect_disabled() {
        let backend = RedirectBackend;
        let result = super::try_presigned_redirect(
            &backend,
            "cas/ab/cd/abcdef",
            false,
            Duration::from_secs(300),
        )
        .await;

        assert!(
            result.is_none(),
            "Should return None when feature is disabled"
        );
    }

    #[tokio::test]
    async fn test_try_presigned_redirect_backend_no_support() {
        let backend = NoRedirectBackend;
        let result = super::try_presigned_redirect(
            &backend,
            "cas/ab/cd/abcdef",
            true,
            Duration::from_secs(300),
        )
        .await;

        assert!(
            result.is_none(),
            "Should return None when backend does not support redirect"
        );
    }

    #[tokio::test]
    async fn test_try_presigned_redirect_uses_configured_expiry() {
        let backend = RedirectBackend;
        let result =
            super::try_presigned_redirect(&backend, "test-key", true, Duration::from_secs(600))
                .await;

        let resp = result.unwrap();
        let cache_control = resp
            .headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cache_control, "private, max-age=600");
    }
}
