//! Application error types and result alias.

use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

/// Retry-After hint (seconds) sent on 503 Service Unavailable responses so
/// well-behaved clients back off instead of hammering a saturated server.
const RETRY_AFTER_SECS_ON_503: &str = "1";

/// Application result type alias
pub type Result<T> = std::result::Result<T, AppError>;

/// Detect filesystem name-too-long errors across the message strings that
/// surface from std::io and object_store/S3 backends. Linux io::Error
/// renders as "File name too long (os error 36)"; some layers prefix or
/// wrap the message, so match canonical fragments rather than an exact
/// string. Exposed at `pub(crate)` so callers outside this module share the
/// single source of truth for the ENAMETOOLONG -> 400 mapping (#1047).
/// `AppError::Storage` and `AppError::Io` both consult this function during
/// status mapping so every handler benefits, including the 30+ format
/// handlers that never adopted `error_helpers`.
pub(crate) fn is_name_too_long(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("file name too long")
        || lower.contains("name too long")
        || lower.contains("enametoolong")
}

/// Detect SQLx connection-pool saturation across both the typed
/// `sqlx::Error::PoolTimedOut` and its stringified forms.
///
/// The hot proxy path wraps DB errors as `AppError::Database(e.to_string())`,
/// which erases the typed variant. `e.to_string()` for `PoolTimedOut` renders
/// "pool timed out while waiting for an open connection" (sqlx 0.8), which does
/// NOT contain the literal "PoolTimedOut". Matching only the variant name
/// therefore missed every stringified pool timeout on the proxy hot path and
/// surfaced 500 instead of 503 (#1437 follow-up). We match both fragments so
/// the mapping holds whether the error arrived typed or stringified.
pub(crate) fn is_pool_timeout(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("pool timed out") || lower.contains("pooltimedout")
}

/// Application error types.
#[derive(Error, Debug)]
pub enum AppError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("Database error: {0}")]
    Sqlx(#[from] sqlx::Error),

    #[error("Migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    #[error("Authentication failed: {0}")]
    Authentication(String),

    /// Missing credentials
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Access denied: {0}")]
    Authorization(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Duplicate resource (e.g., artifact version already exists)
    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Quota exceeded: {0}")]
    QuotaExceeded(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Address parse error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("WASM error: {0}")]
    Wasm(#[from] crate::services::wasm_runtime::WasmError),

    #[error("Bad gateway: {0}")]
    BadGateway(String),

    /// A required dependency or feature is not configured / not enabled on
    /// this deployment. Distinct from `Internal` (which is "the server
    /// failed unexpectedly") because operators alert on 500s but not on
    /// 503s, and clients can distinguish "feature off" from "server bug"
    /// by status code alone.
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),
}

impl AppError {
    /// True when this error is a SQLx connection-pool acquire timeout, in
    /// either its typed (`Sqlx(PoolTimedOut)`) or stringified
    /// (`Database("pool timed out …")`) form.
    ///
    /// This is the single source of truth for the POOL_EXHAUSTED -> 503
    /// classification (#1437 / #2101 / #2102): `status_and_code` and
    /// `user_message` consult it below, and callers outside this module reuse
    /// it instead of re-deriving the variant/string check. In particular the
    /// auth pre-check (`api::middleware::auth`) uses it to reclassify a
    /// pool-acquire timeout during its own DB lookup as a retryable 503 rather
    /// than flattening it to a misleading 401 (#2125). A pool timeout is a
    /// transient capacity problem, never a bad credential.
    pub(crate) fn is_pool_timeout(&self) -> bool {
        match self {
            Self::Sqlx(sqlx::Error::PoolTimedOut) => true,
            Self::Database(msg) => is_pool_timeout(msg),
            _ => false,
        }
    }

    /// Map error variant to HTTP status code and machine-readable error code.
    fn status_and_code(&self) -> (StatusCode, &'static str) {
        match self {
            Self::Config(_) => (StatusCode::INTERNAL_SERVER_ERROR, "CONFIG_ERROR"),
            // SQLx pool exhaustion is a transient capacity problem, not a
            // server bug: requests timed out waiting for a DB connection
            // because peers held them all. Surfacing this as 500 trips
            // alerts and makes saturation look like a fault; 503 +
            // Retry-After lets clients back off and retry on the same
            // path. See #1437 / #1442.
            e if e.is_pool_timeout() => (StatusCode::SERVICE_UNAVAILABLE, "POOL_EXHAUSTED"),
            Self::Database(_) | Self::Sqlx(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR")
            }
            Self::Migration(_) => (StatusCode::INTERNAL_SERVER_ERROR, "MIGRATION_ERROR"),
            Self::Authentication(_) => (StatusCode::UNAUTHORIZED, "AUTH_ERROR"),
            Self::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
            Self::Authorization(_) => (StatusCode::FORBIDDEN, "FORBIDDEN"),
            Self::NotFound(_) => (StatusCode::NOT_FOUND, "NOT_FOUND"),
            Self::Conflict(_) => (StatusCode::CONFLICT, "CONFLICT"),
            Self::Validation(_) => (StatusCode::BAD_REQUEST, "VALIDATION_ERROR"),
            Self::QuotaExceeded(_) => (StatusCode::INSUFFICIENT_STORAGE, "QUOTA_EXCEEDED"),
            // ENAMETOOLONG is a client-supplied path that exceeds the
            // underlying filesystem's name limit (255 bytes on ext4/xfs).
            // Surfacing this as 500 makes abuse / fuzzing payloads look
            // like server faults in monitoring. Map to 400 instead - it is
            // a client problem, not a server failure. This mirrors the
            // `map_storage_err` helper but applies to every handler that
            // returns `AppError::Storage(...)` or `AppError::Io(...)`,
            // including the 30+ format handlers that never adopted
            // `error_helpers`. See #1047 (audit of #990's three patterns).
            Self::Storage(msg) if is_name_too_long(msg) => {
                (StatusCode::BAD_REQUEST, "PATH_TOO_LONG")
            }
            Self::Io(err) if is_name_too_long(&err.to_string()) => {
                (StatusCode::BAD_REQUEST, "PATH_TOO_LONG")
            }
            Self::Storage(_) => (StatusCode::INTERNAL_SERVER_ERROR, "STORAGE_ERROR"),
            Self::Io(_) => (StatusCode::INTERNAL_SERVER_ERROR, "IO_ERROR"),
            Self::AddrParse(_) => (StatusCode::INTERNAL_SERVER_ERROR, "ADDR_PARSE_ERROR"),
            Self::Json(_) => (StatusCode::BAD_REQUEST, "JSON_ERROR"),
            Self::Jwt(_) => (StatusCode::UNAUTHORIZED, "JWT_ERROR"),
            Self::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR"),
            Self::Wasm(_) => (StatusCode::INTERNAL_SERVER_ERROR, "WASM_ERROR"),
            Self::BadGateway(_) => (StatusCode::BAD_GATEWAY, "BAD_GATEWAY"),
            Self::ServiceUnavailable(_) => (StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE"),
        }
    }

    /// Return a user-facing message. Internal details are hidden for server-side
    /// errors to avoid leaking table names, SQL queries, file paths, or config
    /// values. The full error is still logged via `tracing::error!` in
    /// `into_response`.
    fn user_message(&self) -> String {
        match self {
            // Server-side errors: return generic messages (details are logged)
            e if e.is_pool_timeout() => {
                "Database connection pool is saturated, retry shortly".to_string()
            }
            Self::Database(_) | Self::Sqlx(_) => "Database operation failed".to_string(),
            Self::Migration(_) => "Database migration failed".to_string(),
            Self::Storage(msg) if is_name_too_long(msg) => {
                "Path segment exceeds filesystem name length limit".to_string()
            }
            Self::Io(err) if is_name_too_long(&err.to_string()) => {
                "Path segment exceeds filesystem name length limit".to_string()
            }
            Self::Storage(_) => "Storage operation failed".to_string(),
            Self::Config(_) => "Server configuration error".to_string(),
            Self::Internal(_) => "Internal server error".to_string(),
            Self::Io(_) => "IO operation failed".to_string(),
            Self::AddrParse(_) => "Invalid address".to_string(),
            Self::Jwt(_) => "Invalid token".to_string(),
            Self::Wasm(_) => "Plugin execution failed".to_string(),
            // Client-facing errors: pass through their message
            Self::Authentication(msg)
            | Self::Unauthorized(msg)
            | Self::Authorization(msg)
            | Self::NotFound(msg)
            | Self::Conflict(msg)
            | Self::Validation(msg)
            | Self::QuotaExceeded(msg)
            | Self::BadGateway(msg)
            | Self::ServiceUnavailable(msg) => msg.clone(),
            Self::Json(_) => "Invalid JSON".to_string(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code) = self.status_and_code();
        let message = self.user_message();

        tracing::error!(error = %self, code = code, "Request error");

        let body = Json(json!({
            "code": code,
            "message": message,
        }));

        let mut response = (status, body).into_response();
        // Tell well-behaved clients to back off on capacity-shed responses so
        // they retry on a slower cadence and don't compound the saturation.
        if status == StatusCode::SERVICE_UNAVAILABLE {
            response.headers_mut().insert(
                header::RETRY_AFTER,
                HeaderValue::from_static(RETRY_AFTER_SECS_ON_503),
            );
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Server-side errors: user_message must NOT leak internal details
    // -----------------------------------------------------------------------

    #[test]
    fn test_database_error_hides_details() {
        let err = AppError::Database("SELECT * FROM users WHERE id = 42".into());
        assert_eq!(err.user_message(), "Database operation failed");
        assert!(!err.user_message().contains("SELECT"));
    }

    // -----------------------------------------------------------------------
    // #1437 / #1442: SQLx pool-timeout must map to 503 (transient capacity),
    // not 500 (server fault). Operators alert on 500s; the previous mapping
    // hid pool exhaustion behind alert fatigue and made saturated stress
    // tests look like backend bugs instead of capacity-shed events.
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_pool_timeout_predicate_matches_typed_and_stringified() {
        // Typed variant.
        assert!(AppError::Sqlx(sqlx::Error::PoolTimedOut).is_pool_timeout());
        // Stringified form the hot path (and the auth layer's
        // `map_err(|e| AppError::Database(e.to_string()))`) produces.
        assert!(AppError::Database(sqlx::Error::PoolTimedOut.to_string()).is_pool_timeout());
        // Genuine non-pool errors must NOT be classified as pool timeouts, so
        // real DB faults and bad credentials keep their existing status codes.
        assert!(!AppError::Sqlx(sqlx::Error::RowNotFound).is_pool_timeout());
        assert!(!AppError::Database("connection refused".to_string()).is_pool_timeout());
        assert!(
            !AppError::Authentication("Invalid username or password".to_string()).is_pool_timeout()
        );
        assert!(!AppError::Unauthorized("Token has been revoked".to_string()).is_pool_timeout());
    }

    #[test]
    fn test_sqlx_pool_timed_out_maps_to_503() {
        let err = AppError::Sqlx(sqlx::Error::PoolTimedOut);
        let (status, code) = err.status_and_code();
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(code, "POOL_EXHAUSTED");
    }

    #[test]
    fn test_sqlx_pool_timed_out_user_message_is_actionable() {
        let err = AppError::Sqlx(sqlx::Error::PoolTimedOut);
        let msg = err.user_message();
        // Operators see the actual cause in logs; clients see "retry shortly".
        assert!(
            msg.contains("retry"),
            "user message should advise retry, got: {msg}"
        );
        // Generic non-pool-timeout SQLx errors still hide details.
        let other = AppError::Sqlx(sqlx::Error::RowNotFound);
        assert_eq!(other.user_message(), "Database operation failed");
    }

    #[test]
    fn test_pool_timeout_string_wrapped_as_database_also_503s() {
        // The proxy hot path stringifies sqlx errors
        // (`map_err(|e| AppError::Database(e.to_string()))`) before wrapping
        // them, which erases the typed variant. Reproduce the EXACT string
        // sqlx produces for a pool timeout rather than a synthetic string that
        // merely contains the variant name -- the real Display does NOT contain
        // "PoolTimedOut", so a guard keyed off the variant name silently let
        // saturated proxy requests fall back to 500 (#1437).
        let real = sqlx::Error::PoolTimedOut.to_string();
        assert!(
            !real.contains("PoolTimedOut"),
            "guard must not rely on the Debug variant name; sqlx Display = {real:?}"
        );
        let err = AppError::Database(real);
        let (status, code) = err.status_and_code();
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(code, "POOL_EXHAUSTED");
        assert!(err.user_message().contains("retry"));
    }

    #[test]
    fn test_other_sqlx_errors_still_map_to_500() {
        // Only pool-timeout is reclassified; everything else stays 500 so
        // genuine SQL faults still trip ops alerts.
        let err = AppError::Sqlx(sqlx::Error::RowNotFound);
        let (status, code) = err.status_and_code();
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(code, "DATABASE_ERROR");
    }

    #[test]
    fn test_storage_error_hides_details() {
        let err = AppError::Storage("/var/data/artifacts/secret-file.tar".into());
        assert_eq!(err.user_message(), "Storage operation failed");
        assert!(!err.user_message().contains("/var"));
    }

    #[test]
    fn test_config_error_hides_details() {
        let err = AppError::Config("AWS_SECRET_KEY is invalid".into());
        assert_eq!(err.user_message(), "Server configuration error");
        assert!(!err.user_message().contains("AWS"));
    }

    #[test]
    fn test_internal_error_hides_details() {
        let err = AppError::Internal("stack trace at 0x7fff".into());
        assert_eq!(err.user_message(), "Internal server error");
        assert!(!err.user_message().contains("stack"));
    }

    #[test]
    fn test_io_error_hides_details() {
        let err = AppError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "/etc/shadow: permission denied",
        ));
        assert_eq!(err.user_message(), "IO operation failed");
        assert!(!err.user_message().contains("/etc"));
    }

    #[test]
    fn test_jwt_error_hides_details() {
        // Construct a JWT error by decoding garbage
        let err: jsonwebtoken::errors::Error = jsonwebtoken::decode::<serde_json::Value>(
            "not-a-token",
            &jsonwebtoken::DecodingKey::from_secret(b"x"),
            &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256),
        )
        .unwrap_err();
        let app_err = AppError::Jwt(err);
        assert_eq!(app_err.user_message(), "Invalid token");
    }

    // -----------------------------------------------------------------------
    // Client-facing errors: user_message passes through
    // -----------------------------------------------------------------------

    #[test]
    fn test_authentication_passes_through() {
        let err = AppError::Authentication("bad credentials".into());
        assert_eq!(err.user_message(), "bad credentials");
    }

    #[test]
    fn test_not_found_passes_through() {
        let err = AppError::NotFound("artifact foo:1.0 not found".into());
        assert_eq!(err.user_message(), "artifact foo:1.0 not found");
    }

    #[test]
    fn test_validation_passes_through() {
        let err = AppError::Validation("name is required".into());
        assert_eq!(err.user_message(), "name is required");
    }

    #[test]
    fn test_conflict_passes_through() {
        let err = AppError::Conflict("version already exists".into());
        assert_eq!(err.user_message(), "version already exists");
    }

    #[test]
    fn test_quota_exceeded_passes_through() {
        let err = AppError::QuotaExceeded("storage limit reached".into());
        assert_eq!(err.user_message(), "storage limit reached");
    }

    #[test]
    fn test_service_unavailable_passes_through() {
        let err = AppError::ServiceUnavailable("Scanner service not configured".into());
        assert_eq!(err.user_message(), "Scanner service not configured");
        assert_eq!(
            err.to_string(),
            "Service unavailable: Scanner service not configured"
        );
    }

    // -----------------------------------------------------------------------
    // HTTP status codes
    // -----------------------------------------------------------------------

    #[test]
    fn test_status_codes() {
        assert_eq!(
            AppError::Database("x".into()).status_and_code().0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            AppError::Authentication("x".into()).status_and_code().0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AppError::Authorization("x".into()).status_and_code().0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            AppError::NotFound("x".into()).status_and_code().0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            AppError::Conflict("x".into()).status_and_code().0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            AppError::Validation("x".into()).status_and_code().0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            AppError::QuotaExceeded("x".into()).status_and_code().0,
            StatusCode::INSUFFICIENT_STORAGE
        );
        assert_eq!(
            AppError::BadGateway("x".into()).status_and_code().0,
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            AppError::BadGateway("x".into()).status_and_code().1,
            "BAD_GATEWAY"
        );
        assert_eq!(
            AppError::ServiceUnavailable("x".into()).status_and_code().0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            AppError::ServiceUnavailable("x".into()).status_and_code().1,
            "SERVICE_UNAVAILABLE"
        );
    }

    #[test]
    fn test_bad_gateway_message() {
        let err = AppError::BadGateway("upstream failed".to_string());
        assert_eq!(err.user_message(), "upstream failed");
        assert_eq!(err.to_string(), "Bad gateway: upstream failed");
    }

    // -----------------------------------------------------------------------
    // #1047: ENAMETOOLONG must map to 400, not 500, regardless of which
    // handler returned the error.
    // -----------------------------------------------------------------------

    #[test]
    fn test_storage_enametoolong_maps_to_400() {
        // Canonical Linux io::Error rendering.
        let err = AppError::Storage("File name too long (os error 36)".into());
        let (status, code) = err.status_and_code();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(code, "PATH_TOO_LONG");
        assert_eq!(
            err.user_message(),
            "Path segment exceeds filesystem name length limit"
        );
    }

    #[test]
    fn test_storage_enametoolong_wrapped_message_maps_to_400() {
        // Some storage backends wrap the underlying message.
        let err = AppError::Storage("storage put failed: file name too long".into());
        let (status, _) = err.status_and_code();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_io_enametoolong_maps_to_400() {
        // The host's `from_raw_os_error(36 | 63)` lookup is platform-specific
        // (Linux: 36 => ENAMETOOLONG; macOS: 36 => EINPROGRESS, 63 =>
        // ENAMETOOLONG), so use a constructed io::Error whose Display string
        // matches the canonical ENAMETOOLONG fragment instead. The detector
        // matches on the rendered string, not the errno.
        let io_err = std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "File name too long (os error 36)",
        );
        let err = AppError::Io(io_err);
        let (status, code) = err.status_and_code();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(code, "PATH_TOO_LONG");
    }

    #[test]
    fn test_storage_unrelated_error_still_500() {
        let err = AppError::Storage("disk quota exceeded".into());
        let (status, _) = err.status_and_code();
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_io_unrelated_error_still_500() {
        let err = AppError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "access denied",
        ));
        let (status, _) = err.status_and_code();
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    // -----------------------------------------------------------------------
    // #1088 / #991: 503 responses must carry a Retry-After hint so well-
    // behaved clients (cargo, npm, gha runners) back off during a saturation
    // shed and do not amplify load while the server is recovering.
    // -----------------------------------------------------------------------

    #[test]
    fn test_service_unavailable_sets_retry_after_header() {
        let err = AppError::ServiceUnavailable("at capacity".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let retry_after = response
            .headers()
            .get(header::RETRY_AFTER)
            .expect("503 response should carry Retry-After");
        assert_eq!(retry_after.to_str().unwrap(), RETRY_AFTER_SECS_ON_503);
    }

    #[test]
    fn test_non_503_does_not_set_retry_after_header() {
        // Retry-After should not leak onto non-shed errors: a 400 or 401
        // is a client problem, not a transient capacity issue.
        let err = AppError::Validation("bad input".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get(header::RETRY_AFTER).is_none());
    }
}
