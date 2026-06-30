//! Shared error-mapping helpers for format handlers.
//!
//! The `map_db_err` and `map_storage_err` functions convert an error into an
//! `AppError` response, replacing the repetitive closure pattern that was
//! copy-pasted across maven, npm, pypi, and cargo handlers.

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
/// problem, not a server failure. Since #1047, this mapping is enforced
/// inside `AppError::Storage` directly so every handler that returns
/// `AppError::Storage(...)` benefits (not just the four formats that adopted
/// this helper). This wrapper is kept for the existing call sites; new code
/// can return `Err(AppError::Storage(e.to_string()))` and get the same
/// behavior.
///
/// Usage: `.map_err(map_storage_err)?`
pub fn map_storage_err(e: impl std::fmt::Display) -> Response {
    AppError::Storage(e.to_string()).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn test_map_db_err_returns_500() {
        let resp = map_db_err("connection refused");
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_map_db_err_pool_timeout_returns_503() {
        // Proxy/format handlers funnel sqlx errors through map_db_err after
        // stringifying them. A pool timeout must surface as 503 (capacity
        // shed) so saturated clients back off, not 500 (#1437). Reproduce the
        // exact sqlx Display string rather than a synthetic one.
        let resp = map_db_err(sqlx::Error::PoolTimedOut.to_string());
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
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
    fn test_map_storage_err_unrelated_error_still_500() {
        // Unrelated storage messages must not be misclassified as 400.
        let resp = map_storage_err("disk quota exceeded");
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let resp = map_storage_err("connection reset");
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
