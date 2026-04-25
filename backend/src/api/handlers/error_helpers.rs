//! Shared error-mapping helpers for format handlers.
//!
//! The `map_db_err` and `map_storage_err` functions convert an error into an
//! `AppError` response, replacing the repetitive closure pattern that was
//! copy-pasted across maven, npm, pypi, and cargo handlers.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::error::AppError;

/// Convert any `Display`-able error into a `Database` `AppError` response.
///
/// Usage: `.map_err(map_db_err)?`
pub fn map_db_err(e: impl std::fmt::Display) -> Response {
    AppError::Database(e.to_string()).into_response()
}

/// Convert any `Display`-able error into a `Storage` `AppError` response.
///
/// Filesystem ENAMETOOLONG (a path or name segment exceeds the underlying FS
/// limit, typically 255 bytes on ext4/xfs) is mapped to 400 Bad Request
/// rather than 500. The client supplied an invalid path; that is a client
/// problem, not a server failure.
///
/// Usage: `.map_err(map_storage_err)?`
pub fn map_storage_err(e: impl std::fmt::Display) -> Response {
    let s = e.to_string();
    if is_name_too_long(&s) {
        return (
            StatusCode::BAD_REQUEST,
            "Path segment exceeds filesystem name length limit",
        )
            .into_response();
    }
    AppError::Storage(s).into_response()
}

/// Detect filesystem name-too-long errors across the message strings that
/// surface from std::io and object_store/S3 backends. Linux io::Error
/// renders as "File name too long (os error 36)"; some layers prefix or
/// wrap the message, so match canonical fragments rather than an exact
/// string.
fn is_name_too_long(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("file name too long")
        || lower.contains("name too long")
        || lower.contains("enametoolong")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_map_db_err_returns_500() {
        let resp = map_db_err("connection refused");
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_map_storage_err_returns_500() {
        let resp = map_storage_err("disk full");
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_map_db_err_with_sqlx_error() {
        let err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "pg down");
        let resp = map_db_err(err);
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_map_storage_err_with_io_error() {
        let err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let resp = map_storage_err(err);
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_map_storage_err_linux_name_too_long_returns_400() {
        // Canonical Linux io::Error rendering for ENAMETOOLONG.
        let resp = map_storage_err("File name too long (os error 36)");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_map_storage_err_wrapped_name_too_long_returns_400() {
        // Some storage backends wrap or prefix the underlying message.
        let resp = map_storage_err("storage put failed: file name too long");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_map_storage_err_enametoolong_token_returns_400() {
        // Raw errno tokens occasionally bubble up unchanged.
        let resp = map_storage_err("io error: ENAMETOOLONG");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_is_name_too_long_negative() {
        // Unrelated storage messages must not be misclassified.
        assert!(!is_name_too_long("disk quota exceeded"));
        assert!(!is_name_too_long("connection reset"));
        assert!(!is_name_too_long(""));
    }
}
