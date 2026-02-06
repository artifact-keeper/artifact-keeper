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
pub const X_ARTIFACT_STORAGE: &str = "X-Artifact-Storage";

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
