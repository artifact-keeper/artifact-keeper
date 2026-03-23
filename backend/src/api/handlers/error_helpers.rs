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
}
