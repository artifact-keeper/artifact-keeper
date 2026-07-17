//! Shared error-mapping helpers for format handlers.
//!
//! The `map_db_err` and `map_storage_err` functions convert an error into an
//! `AppError` response, replacing the repetitive closure pattern that was
//! copy-pasted across maven, npm, pypi, and cargo handlers.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::error::AppError;
use crate::models::signing_key::SigningKey;

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

/// Resolve the outcome of an active-signing-key lookup for a repository
/// metadata-signing endpoint (`InRelease`, `Release.gpg`, `repomd.xml.asc`, ...).
///
/// The two failure modes are deliberately kept distinct (#2636):
///
///   * `Ok(None)`  — the repository genuinely has no active signing key.
///     That is a client-visible configuration state: **404**.
///   * `Err(e)`    — the key exists but could not be loaded (decrypt failure,
///     DB error, unparseable key material). That is a *server* failure and
///     must stay loud: **500**, carrying the real error.
///
/// Collapsing the second case into the first is what let the RPM signing
/// breakage hide: a repo that advertised a key it could not sign with reported
/// "No signing key configured for this repository", so the real parse error
/// was never seen. Taking the lookup `Result` by value keeps this decision a
/// pure function, so the distinction is unit-testable without a database.
// `Response` is the crate-wide handler error type; boxing it here would just
// force every call site to unbox (see the same allow on the format handlers).
#[allow(clippy::result_large_err)]
pub fn require_signing_key(
    lookup: crate::error::Result<Option<SigningKey>>,
) -> Result<SigningKey, Response> {
    match lookup {
        Ok(Some(key)) => Ok(key),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            "No signing key configured for this repository",
        )
            .into_response()),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to load signing key: {}", e),
        )
            .into_response()),
    }
}

/// Require that a repository's active signing key can produce an OpenPGP
/// chain, for the endpoints that can only serve OpenPGP (`repomd.xml.asc`,
/// `repomd.xml.key`, `Release.gpg`, ...).
///
/// An `rsa` key (the *default* `key_type`) holds X.509 material and can never
/// satisfy these endpoints, so this is **409 Conflict**, not 500: the request
/// is fine and the server is healthy — the repository's signing *configuration*
/// conflicts with what the endpoint must produce, and only an operator can
/// resolve it. Nothing will change until they do (#2651 proposes rejecting the
/// combination at config time, upstream of here).
///
/// The status matters operationally, because these endpoints are anonymous:
/// every `dnf` poll of a misconfigured repo hits this path. Returning 500 +
/// `ERROR!` would let any unauthenticated client drive unbounded error logs and
/// 500-rate alerts — paging an on-call engineer for someone else's config
/// mistake. A 500 must keep meaning "this server is broken"; callers log this
/// at `WARN` instead.
///
/// A key that *claims* `key_type=gpg` but whose material will not parse is a
/// different animal — that is a genuine server-side fault and stays a loud 500
/// at the point of signing.
///
/// Pure, like `require_signing_key`, so the mapping is unit-testable.
#[allow(clippy::result_large_err)]
pub fn require_openpgp_capable_key(key: SigningKey) -> Result<SigningKey, Response> {
    if key.supports_openpgp() {
        return Ok(key);
    }
    Err((
        StatusCode::CONFLICT,
        format!(
            "This repository's active signing key '{}' has key_type='{}', which cannot \
             produce an OpenPGP signature. Metadata signing requires a key with \
             key_type='gpg'.",
            key.name, key.key_type
        ),
    )
        .into_response())
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
