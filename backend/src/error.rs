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
pub(crate) const RETRY_AFTER_SECS_ON_503: &str = "1";

/// Client-facing message for `507 STORAGE_FULL` (#5650). Every route uses this
/// wording, the OCI `/v2` envelope included, so no backend error text (bucket
/// names, request ids, XML) reaches a client.
pub(crate) const STORAGE_FULL_MESSAGE: &str =
    "Storage is full: the storage backend refused the write for lack of space";

/// Client-facing message for `503 STORAGE_UNAVAILABLE` (#5649).
pub(crate) const STORAGE_UNAVAILABLE_MESSAGE: &str =
    "Storage backend is temporarily unavailable, retry shortly";

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

/// Stringified database failures that mean "the database could not answer
/// right now", as opposed to "the query was wrong" or "the data was bad"
/// (#4750). Matched on the rendered text because most call sites wrap sqlx
/// errors as `AppError::Database(e.to_string())`, which drops the variant
/// and the SQLSTATE. Deliberately excludes data exceptions such as
/// `invalid byte sequence for encoding "UTF8": 0x00`: those are caused by
/// client-supplied bytes, and retrying them can never succeed.
fn is_db_unavailable_message(msg: &str) -> bool {
    const MARKERS: &[&str] = &[
        // sqlx::Error::PoolClosed / Io / Tls / WorkerCrashed renderings.
        "closed pool",
        "error communicating with database",
        "tls connection",
        "crashed background worker",
        // Server-side cancellation and connection loss.
        "canceling statement due to statement timeout",
        "canceling statement due to lock timeout",
        "terminating connection",
        "connection refused",
        "connection reset",
        "too many clients already",
        "the database system is starting up",
        "the database system is shutting down",
        "the database system is in recovery mode",
    ];
    if is_pool_timeout(msg) {
        return true;
    }
    let lower = msg.to_ascii_lowercase();
    MARKERS.iter().any(|m| lower.contains(m))
}

/// PostgreSQL SQLSTATE for `foreign_key_violation`.
const PG_FOREIGN_KEY_VIOLATION: &str = "23503";

/// Whether a `sqlx` error is a foreign-key violation (#3957).
///
/// The storage-stats recompute writes rows keyed by a repository that a
/// concurrent DELETE can remove at any moment. `SELECT ... FROM repositories
/// WHERE id = $1` narrows the window but cannot close it: the SELECT reads the
/// statement's own snapshot, while the FK is enforced by a referential-
/// integrity trigger that re-reads the LATEST committed state, so a DELETE
/// committing between the two still raises 23503. Both writers classify
/// exactly that error as "repository gone, skip" and let everything else
/// propagate.
pub(crate) fn is_fk_violation(e: &sqlx::Error) -> bool {
    e.as_database_error().and_then(|db| db.code()).as_deref() == Some(PG_FOREIGN_KEY_VIOLATION)
}

/// PostgreSQL SQLSTATE for `deadlock_detected`.
pub(crate) const PG_DEADLOCK_DETECTED: &str = "40P01";

/// Whether a `sqlx` error is Postgres' `40P01 deadlock detected` (#4004).
///
/// Postgres breaks a lock cycle by aborting one of the transactions in it, so
/// 40P01 is never a bug in the statement that receives it and never means the
/// work is impossible — the loser simply has to run again. Every caller that
/// can lose such a race classifies exactly this error as "retry me" through
/// [`crate::db::retry_on_deadlock`] and lets everything else propagate.
///
/// Lives beside [`is_fk_violation`] and [`is_pool_timeout`]: one place for
/// every "what kind of database failure is this" question, so a call site
/// cannot classify one SQLSTATE here and another three modules away.
pub(crate) fn is_deadlock(e: &sqlx::Error) -> bool {
    e.as_database_error().and_then(|db| db.code()).as_deref() == Some(PG_DEADLOCK_DETECTED)
}

/// Error types that can carry a Postgres deadlock, so
/// [`crate::db::retry_on_deadlock`] can wrap a closure whatever error it
/// returns — the raw `sqlx::Error` at the DB boundary, or the [`AppError`] a
/// service method has already mapped it into.
pub(crate) trait DeadlockError {
    fn is_deadlock(&self) -> bool;
}

impl DeadlockError for sqlx::Error {
    fn is_deadlock(&self) -> bool {
        is_deadlock(self)
    }
}

impl DeadlockError for AppError {
    fn is_deadlock(&self) -> bool {
        match self {
            Self::Sqlx(e) => is_deadlock(e),
            // Stringified form, like `is_pool_timeout` above: much of the
            // codebase flattens DB failures to `Database(e.to_string())`,
            // which erases the SQLSTATE. `sqlx::Error::Database` renders as
            // "error returned from database: deadlock detected", so the
            // message is all that is left to match on. Retrying is the only
            // thing this decides, so a miss (a non-English `lc_messages`, say)
            // degrades to today's behaviour rather than to a wrong answer;
            // prefer `AppError::Sqlx` at new call sites and keep the typed arm
            // authoritative.
            Self::Database(msg) => msg.to_ascii_lowercase().contains("deadlock detected"),
            _ => false,
        }
    }
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

    /// A conditional write whose `If-Match` / `If-None-Match` precondition
    /// does not hold against the current state of the target (#4186). Mapped
    /// to 412 so a compare-and-swap client can tell "someone else wrote first"
    /// apart from the 409 an unconditional write to an immutable path gets.
    #[error("Precondition failed: {0}")]
    PreconditionFailed(String),

    #[error("Validation error: {0}")]
    Validation(String),

    /// A 400 that carries its own machine-readable `code` instead of the
    /// generic `VALIDATION_ERROR`, for a refusal a client is expected to
    /// recognise and act on (e.g. `PUBLIC_REMOTE_UPSTREAM_CREDENTIALS`,
    /// #4662, which a client answers by sending an explicit override).
    #[error("Validation error ({code}): {message}")]
    CodedValidation { code: &'static str, message: String },

    /// The request was well-formed and syntactically valid but asks for a
    /// configuration that is semantically unsupported in this release (e.g. a
    /// Debian proxy filter that requests metadata regeneration/re-signing, or
    /// an internally inconsistent filter). Mapped to 422 so clients can tell
    /// "the server understood but won't do this yet" apart from a plain 400
    /// schema/validation error.
    #[error("Unprocessable entity: {0}")]
    UnprocessableEntity(String),

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

    /// An upstream refused to authenticate the proxy: an OCI token service
    /// answered 401/403 for the Remote's credentials (#4453). A gateway error
    /// (502) like any other upstream refusal, but with its own code so a
    /// credentials problem is not reported as a storage fault or as "not
    /// found". The message names the (redacted) service, never credentials.
    #[error("Upstream authentication failed: {0}")]
    UpstreamAuth(String),

    /// An OIDC identity provider answered the authorization-code exchange
    /// without an `id_token` (#4699). A gateway error (502) with its own code
    /// so an IdP-side configuration problem is not reported as an opaque
    /// `INTERNAL_ERROR`. The message names the provider, never secrets.
    #[error("OIDC token response missing id_token: {0}")]
    OidcNoIdToken(String),

    /// A 502 that carries its own machine-readable `code` instead of the
    /// generic `BAD_GATEWAY`, for an upstream fault a client or operator is
    /// expected to tell apart from other gateway errors (e.g.
    /// `UPSTREAM_SHORT_BODY`, #4759: the upstream promised a `Content-Length`
    /// and its body ended first). The message names the repository and the
    /// byte counts, never credentials or upstream URLs.
    #[error("Bad gateway ({code}): {message}")]
    CodedBadGateway { code: &'static str, message: String },

    /// A required dependency or feature is not configured / not enabled on
    /// this deployment. Distinct from `Internal` (which is "the server
    /// failed unexpectedly") because operators alert on 500s but not on
    /// 503s, and clients can distinguish "feature off" from "server bug"
    /// by status code alone.
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    /// A scanner's backing engine/CLI is not present in this deployment, so the
    /// scan cannot run at all — distinct from the scan running and failing. The
    /// hardened runtime image routes container-image scans through the Harbor
    /// scanner-adapter over HTTP and does not bundle the `trivy` CLI; the
    /// filesystem/incus scanners spawn it directly and hit
    /// `io::ErrorKind::NotFound`. The scan orchestrator maps this to a terminal
    /// `not_applicable` scan row (grype still covers the same artifacts) rather
    /// than `failed`, so an intentionally-absent optional scanner engine does
    /// not fail closed. Genuine scan errors (unreachable server, malformed
    /// output) are NOT `NotFound` and stay on the `Internal` -> `failed` path.
    #[error("Scanner engine unavailable: {0}")]
    ScannerEngineUnavailable(String),

    /// A route that exists in the API surface but whose behaviour is a known,
    /// intentional gap in this release (#4671). 501 with a stable
    /// `NOT_IMPLEMENTED` code rather than a 500: nothing failed, so it must
    /// not page anyone, and a client can tell "not built" from "broke".
    #[error("Not implemented: {0}")]
    NotImplemented(String),
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

    /// True when the database could not be reached or could not answer in
    /// time: a pool-acquire timeout ([`Self::is_pool_timeout`]), a closed
    /// pool, a lost or refused connection, or a statement / lock timeout
    /// (#4750). This is an infrastructure failure, so a credential check that
    /// hits it must answer a retryable 503, never a 401. A data error caused
    /// by the request's own bytes is not included.
    pub(crate) fn is_db_unavailable(&self) -> bool {
        match self {
            Self::Sqlx(
                sqlx::Error::PoolTimedOut
                | sqlx::Error::PoolClosed
                | sqlx::Error::Io(_)
                | sqlx::Error::Tls(_)
                | sqlx::Error::WorkerCrashed,
            ) => true,
            Self::Sqlx(e) => is_db_unavailable_message(&e.to_string()),
            Self::Database(msg) => is_db_unavailable_message(msg),
            _ => false,
        }
    }

    /// The storage failure class this error carries (#5649, #5650): the
    /// backend could not be reached in time, or refused the write for lack
    /// of space.
    ///
    /// Read from the message because storage errors are re-wrapped as
    /// strings on their way to the handler (`AppError::Storage(e.to_string())`
    /// in most format handlers, `Internal(format!(..))` in a few services);
    /// the backends tag the message with a fixed marker so the class survives
    /// that (see [`crate::storage::failure`]). An `Io` error only ever
    /// classifies as out of space: a reset connection there is usually the
    /// client hanging up mid-upload, not the store.
    pub(crate) fn storage_failure(&self) -> Option<crate::storage::StorageFailure> {
        use crate::storage::StorageFailure;
        match self {
            Self::Storage(msg) | Self::Internal(msg) => StorageFailure::from_message(msg),
            Self::Io(err) => StorageFailure::from_io(err),
            _ => None,
        }
    }

    /// The Postgres SQLSTATE this error carries, when it is still typed.
    ///
    /// Only `Display` reaches most logs, and neither `sqlx::Error` nor
    /// `AppError` renders the code — so a failure logged from a swallowing
    /// call site ("the tick failed, carry on") loses the one field that says
    /// what kind of failure it was. Call sites that log-and-continue attach
    /// this explicitly (#4004).
    pub(crate) fn sqlstate(&self) -> Option<String> {
        match self {
            Self::Sqlx(e) => e.as_database_error()?.code().map(|c| c.into_owned()),
            _ => None,
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
            // The database could not be reached or could not answer: a lost,
            // refused or closed connection, a statement timeout, a server
            // shutting down (#4750's classification). Nothing was decided, so
            // the request is retryable; a 500 makes clients that read
            // "5xx but not 503" as a server bug give up, including on
            // `POST /api/v1/auth/login` (#4756). Query and data errors stay
            // 500 below.
            e if e.is_db_unavailable() => (StatusCode::SERVICE_UNAVAILABLE, "DATABASE_UNAVAILABLE"),
            // Postgres broke a lock cycle by rolling this transaction back, so
            // it changed nothing and running it again succeeds (#5168). The
            // log line stays at error: a deadlock that reaches a client is
            // still a lock-order bug somebody should look at.
            e if e.is_deadlock() => (StatusCode::SERVICE_UNAVAILABLE, "DATABASE_DEADLOCK"),
            Self::Database(_) | Self::Sqlx(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR")
            }
            Self::Migration(_) => (StatusCode::INTERNAL_SERVER_ERROR, "MIGRATION_ERROR"),
            Self::Authentication(_) => (StatusCode::UNAUTHORIZED, "AUTH_ERROR"),
            Self::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
            Self::Authorization(_) => (StatusCode::FORBIDDEN, "FORBIDDEN"),
            Self::NotFound(_) => (StatusCode::NOT_FOUND, "NOT_FOUND"),
            Self::Conflict(_) => (StatusCode::CONFLICT, "CONFLICT"),
            Self::PreconditionFailed(_) => (StatusCode::PRECONDITION_FAILED, "PRECONDITION_FAILED"),
            Self::Validation(_) => (StatusCode::BAD_REQUEST, "VALIDATION_ERROR"),
            Self::CodedValidation { code, .. } => (StatusCode::BAD_REQUEST, code),
            Self::UnprocessableEntity(_) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "UNPROCESSABLE_ENTITY")
            }
            Self::QuotaExceeded(_) => (StatusCode::INSUFFICIENT_STORAGE, "QUOTA_EXCEEDED"),
            // #5650: the storage backend refused the write for lack of space
            // (a MinIO bucket quota, a full volume). Not a server bug and not
            // retryable until an operator frees space.
            e if e.storage_failure() == Some(crate::storage::StorageFailure::Full) => {
                (StatusCode::INSUFFICIENT_STORAGE, "STORAGE_FULL")
            }
            // #5649: the storage backend could not be reached or did not
            // answer within the connect timeout / retry budget. Nothing was
            // stored, so the request is retryable: 503 + Retry-After, the
            // same contract as `DATABASE_UNAVAILABLE`.
            e if e.storage_failure() == Some(crate::storage::StorageFailure::Unavailable) => {
                (StatusCode::SERVICE_UNAVAILABLE, "STORAGE_UNAVAILABLE")
            }
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
            Self::UpstreamAuth(_) => (StatusCode::BAD_GATEWAY, "UPSTREAM_AUTH_FAILED"),
            Self::OidcNoIdToken(_) => (StatusCode::BAD_GATEWAY, "OIDC_NO_ID_TOKEN"),
            Self::CodedBadGateway { code, .. } => (StatusCode::BAD_GATEWAY, code),
            Self::ServiceUnavailable(_) => (StatusCode::SERVICE_UNAVAILABLE, "SERVICE_UNAVAILABLE"),
            Self::ScannerEngineUnavailable(_) => (
                StatusCode::SERVICE_UNAVAILABLE,
                "SCANNER_ENGINE_UNAVAILABLE",
            ),
            Self::NotImplemented(_) => (StatusCode::NOT_IMPLEMENTED, "NOT_IMPLEMENTED"),
        }
    }

    /// Log severity for `into_response`'s `"Request error"` line. Previously
    /// every variant logged at `error`, unconditionally -- so a routine 404
    /// from a Maven virtual repo checking its members (completely expected
    /// multi-repo-fallback behavior) was indistinguishable from a genuine
    /// server fault in error-log-volume dashboards/alerts. This generalizes
    /// the same distinction #1139 already established for the proxy-fetch
    /// path (`map_proxy_error`) to every handler that returns an `AppError`
    /// directly.
    ///
    /// Derived from `status_and_code()` rather than a hand-maintained variant
    /// list so it can't drift from the status mapping: any variant already
    /// classified as a 4xx (including the `Jwt`/ENAMETOOLONG special cases
    /// folded into `Storage`/`Io`) is client-caused and logs at `info`.
    /// Exceptions:
    /// - Pool-timeout is a transient capacity problem, not the client's
    ///   fault, but also not proof the server is broken -- `warn` so it's
    ///   still visible without paging on error-rate alerts.
    /// - Credential failures (`Authentication`/`Unauthorized`/`Authorization`)
    ///   can signal credential stuffing or a broken client, not purely
    ///   routine even though the client caused them -- `warn`.
    /// - `QuotaExceeded` maps to 507, outside the 4xx range, but is a client
    ///   condition (they hit their quota), so it's called out explicitly.
    fn log_level(&self) -> tracing::Level {
        if self.is_pool_timeout() {
            return tracing::Level::WARN;
        }
        match self {
            Self::Authentication(_) | Self::Unauthorized(_) | Self::Authorization(_) => {
                tracing::Level::WARN
            }
            Self::QuotaExceeded(_) => tracing::Level::INFO,
            // A 5xx by status, but an intentional, documented gap: nothing
            // failed, so it must not read as a server fault in the logs.
            Self::NotImplemented(_) => tracing::Level::INFO,
            _ if self.status_and_code().0.is_client_error() => tracing::Level::INFO,
            _ => tracing::Level::ERROR,
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
            e if e.is_db_unavailable() => {
                "Database is temporarily unavailable, retry shortly".to_string()
            }
            e if e.is_deadlock() => {
                "Database transaction was rolled back by a lock conflict, retry shortly".to_string()
            }
            Self::Database(_) | Self::Sqlx(_) => "Database operation failed".to_string(),
            Self::Migration(_) => "Database migration failed".to_string(),
            // #5649 / #5650: fixed wording. The backend's own text (a MinIO
            // XML error naming the bucket and request ids) stays in the log.
            e if e.storage_failure() == Some(crate::storage::StorageFailure::Full) => {
                STORAGE_FULL_MESSAGE.to_string()
            }
            e if e.storage_failure() == Some(crate::storage::StorageFailure::Unavailable) => {
                STORAGE_UNAVAILABLE_MESSAGE.to_string()
            }
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
            | Self::PreconditionFailed(msg)
            | Self::Validation(msg)
            | Self::UnprocessableEntity(msg)
            | Self::QuotaExceeded(msg)
            | Self::BadGateway(msg)
            | Self::UpstreamAuth(msg)
            | Self::OidcNoIdToken(msg)
            | Self::ServiceUnavailable(msg)
            | Self::ScannerEngineUnavailable(msg)
            | Self::NotImplemented(msg) => msg.clone(),
            Self::CodedValidation { message, .. } | Self::CodedBadGateway { message, .. } => {
                message.clone()
            }
            Self::Json(_) => "Invalid JSON".to_string(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // A pool acquire that timed out is about to become a client-visible
        // `503 POOL_EXHAUSTED`: count it (#4549) so saturation is visible as
        // `rate(ak_db_pool_connection_failures_total{stage="request"})` before
        // operators have to correlate scattered response logs. Counted here,
        // on the response path, so every handler error conversion is covered
        // exactly once.
        if self.is_pool_timeout() {
            crate::services::metrics_service::record_db_pool_connection_failure("request");
        }
        let layout_error = match &self {
            Self::Database(message) => crate::services::rpm_layout::database_error(message),
            Self::Sqlx(error) => crate::services::rpm_layout::database_error(&error.to_string()),
            _ => None,
        };
        if let Some(error) = layout_error {
            return error.into_response();
        }
        let (status, code) = self.status_and_code();
        let message = self.user_message();
        if let Some(class) = self.storage_failure() {
            // Feeds the storage check on `/health` and `/readyz`: a full
            // bucket still answers the connectivity probe (#5650).
            crate::storage::failure::record_failure(class);
        }

        match self.log_level() {
            tracing::Level::ERROR => tracing::error!(error = %self, code = code, "Request error"),
            tracing::Level::WARN => tracing::warn!(error = %self, code = code, "Request error"),
            _ => tracing::info!(error = %self, code = code, "Request error"),
        }

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

#[cfg(ak_test_shard = "services-2")]
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

    /// #4750: "the database could not answer" vs "the request was bad".
    #[test]
    fn test_is_db_unavailable_separates_outages_from_bad_input_4750() {
        for typed in [
            sqlx::Error::PoolTimedOut,
            sqlx::Error::PoolClosed,
            sqlx::Error::WorkerCrashed,
            sqlx::Error::Io(std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
        ] {
            let rendered = typed.to_string();
            assert!(AppError::Sqlx(typed).is_db_unavailable(), "{rendered}");
            assert!(
                AppError::Database(rendered.clone()).is_db_unavailable(),
                "stringified: {rendered}"
            );
        }
        for msg in [
            "error returned from database: canceling statement due to lock timeout",
            "error returned from database: canceling statement due to statement timeout",
            "error returned from database: terminating connection due to administrator command",
            "error returned from database: sorry, too many clients already",
            "error returned from database: the database system is shutting down",
        ] {
            assert!(AppError::Database(msg.into()).is_db_unavailable(), "{msg}");
        }
        // A data error caused by client bytes is not an outage: retrying it
        // can never succeed, so a credential check that hits it stays 401.
        assert!(!AppError::Database(
            "error returned from database: invalid byte sequence for encoding \"UTF8\": 0x00"
                .into()
        )
        .is_db_unavailable());
        assert!(!AppError::Sqlx(sqlx::Error::RowNotFound).is_db_unavailable());
        assert!(!AppError::Authentication("Invalid API token".into()).is_db_unavailable());
    }

    #[test]
    fn test_sqlx_pool_timed_out_maps_to_503() {
        let err = AppError::Sqlx(sqlx::Error::PoolTimedOut);
        let (status, code) = err.status_and_code();
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(code, "POOL_EXHAUSTED");
    }

    // -----------------------------------------------------------------------
    // #4549: a pool acquire timeout that reaches a client response is counted,
    // so saturation shows up in Prometheus as
    // `ak_db_pool_connection_failures_total{stage="request"}` and not only as
    // scattered 503s in the logs.
    // -----------------------------------------------------------------------

    #[test]
    fn pool_timeout_response_counts_the_failure_4549() {
        use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};

        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = metrics::set_default_local_recorder(&recorder);

        // Read the counter once at the end: a `DebuggingRecorder` snapshot
        // *resets* counters on read (`swap(0)`), so calling it mid-test would
        // return only the increment since the previous call.
        fn counted(snapshotter: &Snapshotter) -> u64 {
            snapshotter
                .snapshot()
                .into_vec()
                .into_iter()
                .find(|(key, ..)| key.key().name() == "ak_db_pool_connection_failures_total")
                .map(|(.., value)| match value {
                    DebugValue::Counter(n) => n,
                    other => panic!("expected a counter, got {other:?}"),
                })
                .unwrap_or(0)
        }

        let response = AppError::Sqlx(sqlx::Error::PoolTimedOut).into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        // The stringified form the proxy hot path produces counts too: it is
        // the same saturation, seen one layer further from sqlx.
        let response = AppError::Database(sqlx::Error::PoolTimedOut.to_string()).into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        // Errors that are not pool exhaustion leave the counter alone, so the
        // total after all three responses is exactly the two pool timeouts.
        let _ = AppError::NotFound("nope".into()).into_response();
        assert_eq!(
            counted(&snapshotter),
            2,
            "each pool timeout reaching the client increments the failure counter once"
        );
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

    /// #4756: a database outage raised inside a handler's own query (not a
    /// credential check) is a retryable 503 with Retry-After, in both the
    /// typed and the stringified forms. Before the fix only a pool-acquire
    /// timeout was; a lost, refused or closed connection answered
    /// 500 DATABASE_ERROR. Other database errors stay 500.
    #[test]
    fn test_db_unavailable_maps_to_503_with_retry_after_4756() {
        let refused = || {
            sqlx::Error::Io(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "Connection refused (os error 111)",
            ))
        };
        let outages = [
            AppError::Sqlx(refused()),
            AppError::Database(refused().to_string()),
            AppError::Sqlx(sqlx::Error::PoolClosed),
            AppError::Database(sqlx::Error::PoolClosed.to_string()),
            AppError::Database(
                "error returned from database: terminating connection due to administrator command"
                    .into(),
            ),
        ];
        for err in outages {
            let rendered = err.to_string();
            let (status, code) = err.status_and_code();
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{rendered}");
            assert_eq!(code, "DATABASE_UNAVAILABLE", "{rendered}");
            let msg = err.user_message();
            assert!(msg.contains("retry"), "{rendered}: {msg}");
            assert!(!msg.contains("refused"), "details must not leak: {msg}");
            let response = err.into_response();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(
                response.headers().get(header::RETRY_AFTER).unwrap(),
                RETRY_AFTER_SECS_ON_503
            );
        }

        // A pool-acquire timeout keeps its own, more specific code.
        assert_eq!(
            AppError::Sqlx(sqlx::Error::PoolTimedOut)
                .status_and_code()
                .1,
            "POOL_EXHAUSTED"
        );
        // Query and data errors are still server faults.
        for err in [
            AppError::Sqlx(sqlx::Error::RowNotFound),
            AppError::Database(
                "error returned from database: duplicate key value violates unique constraint"
                    .into(),
            ),
            AppError::Database(
                "error returned from database: invalid byte sequence for encoding \"UTF8\": 0x00"
                    .into(),
            ),
        ] {
            assert_eq!(
                err.status_and_code(),
                (StatusCode::INTERNAL_SERVER_ERROR, "DATABASE_ERROR"),
                "{err}"
            );
        }
    }

    /// #5168: a deadlock Postgres broke by rolling the transaction back is a
    /// retryable 503 with Retry-After, not a 500. Most call sites flatten DB
    /// errors to `Database(e.to_string())`; the typed form is pinned against a
    /// real 40P01 in `db.rs`.
    #[test]
    fn test_deadlock_maps_to_503_with_retry_after_5168() {
        let err = AppError::Database("error returned from database: deadlock detected".to_string());
        assert_eq!(
            err.status_and_code(),
            (StatusCode::SERVICE_UNAVAILABLE, "DATABASE_DEADLOCK")
        );
        let msg = err.user_message();
        assert!(msg.contains("retry"), "{msg}");
        assert!(!msg.contains("deadlock detected"), "details leak: {msg}");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get(header::RETRY_AFTER).unwrap(),
            RETRY_AFTER_SECS_ON_503
        );
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

    #[test]
    fn test_scanner_engine_unavailable_passes_through() {
        let err = AppError::ScannerEngineUnavailable("Trivy CLI not available".into());
        assert_eq!(err.user_message(), "Trivy CLI not available");
        assert_eq!(
            err.to_string(),
            "Scanner engine unavailable: Trivy CLI not available"
        );
        assert_eq!(
            err.status_and_code(),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "SCANNER_ENGINE_UNAVAILABLE"
            )
        );
    }

    #[test]
    fn test_not_implemented_is_501_with_a_stable_code() {
        let err = AppError::NotImplemented("Local plugin installation is not implemented".into());
        assert_eq!(
            err.status_and_code(),
            (StatusCode::NOT_IMPLEMENTED, "NOT_IMPLEMENTED")
        );
        assert_eq!(
            err.user_message(),
            "Local plugin installation is not implemented"
        );
        assert_eq!(err.log_level(), tracing::Level::INFO);
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
    fn test_upstream_auth_maps_to_502_with_its_own_code_4453() {
        let err = AppError::UpstreamAuth("token service rejected".into());
        assert_eq!(
            err.status_and_code(),
            (StatusCode::BAD_GATEWAY, "UPSTREAM_AUTH_FAILED")
        );
        assert_eq!(err.user_message(), "token service rejected");
    }

    #[test]
    fn test_coded_validation_is_a_400_with_its_own_code_4662() {
        let err = AppError::CodedValidation {
            code: "PUBLIC_REMOTE_UPSTREAM_CREDENTIALS",
            message: "refused".into(),
        };
        assert_eq!(
            err.status_and_code(),
            (
                StatusCode::BAD_REQUEST,
                "PUBLIC_REMOTE_UPSTREAM_CREDENTIALS"
            )
        );
        assert_eq!(err.user_message(), "refused");
        assert_eq!(err.log_level(), tracing::Level::INFO);
    }

    #[test]
    fn test_coded_bad_gateway_is_a_502_with_its_own_code_4759() {
        let err = AppError::CodedBadGateway {
            code: "UPSTREAM_SHORT_BODY",
            message: "upstream of 'r' ended after 0 of 4096 bytes".into(),
        };
        assert_eq!(
            err.status_and_code(),
            (StatusCode::BAD_GATEWAY, "UPSTREAM_SHORT_BODY")
        );
        assert_eq!(
            err.user_message(),
            "upstream of 'r' ended after 0 of 4096 bytes"
        );
    }

    #[test]
    fn test_oidc_no_id_token_is_502_with_its_own_code() {
        let err = AppError::OidcNoIdToken("provider 'entra' returned no id_token".into());
        assert_eq!(
            err.status_and_code(),
            (StatusCode::BAD_GATEWAY, "OIDC_NO_ID_TOKEN")
        );
        assert_eq!(err.user_message(), "provider 'entra' returned no id_token");
        assert_eq!(err.log_level(), tracing::Level::ERROR);
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
        let err = AppError::Storage("object checksum mismatch".into());
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

    // -----------------------------------------------------------------------
    // `log_level`: routine client-caused conditions must not log at `error`,
    // or error-log-volume dashboards/alerts can't distinguish them from
    // genuine server faults (this is what made a normal Maven virtual-repo
    // 404 indistinguishable from a real incident before this fix).
    // -----------------------------------------------------------------------

    #[test]
    fn test_log_level_pool_timeout_is_warn() {
        // Capacity signal, not the client's fault, but not proof the server
        // is broken either -- worth a glance without paging on error rate.
        let err = AppError::Sqlx(sqlx::Error::PoolTimedOut);
        assert_eq!(err.log_level(), tracing::Level::WARN);
        let stringified = AppError::Database(sqlx::Error::PoolTimedOut.to_string());
        assert_eq!(stringified.log_level(), tracing::Level::WARN);
    }

    #[test]
    fn test_log_level_credential_failures_are_warn() {
        // Client-caused, but repeated failures can signal credential
        // stuffing or a broken client -- more than routine INFO, but not
        // an error-rate-alert-worthy server fault either.
        assert_eq!(
            AppError::Authentication("bad credentials".into()).log_level(),
            tracing::Level::WARN
        );
        assert_eq!(
            AppError::Unauthorized("missing token".into()).log_level(),
            tracing::Level::WARN
        );
        assert_eq!(
            AppError::Authorization("access denied".into()).log_level(),
            tracing::Level::WARN
        );
    }

    #[test]
    fn test_log_level_routine_client_conditions_are_info() {
        // The direct case this fix targets: a missing artifact/repo is
        // completely routine (e.g. Maven checking multiple virtual-repo
        // members), not a bug.
        assert_eq!(
            AppError::NotFound("File not found".into()).log_level(),
            tracing::Level::INFO
        );
        assert_eq!(
            AppError::Conflict("already exists".into()).log_level(),
            tracing::Level::INFO
        );
        assert_eq!(
            AppError::Validation("bad input".into()).log_level(),
            tracing::Level::INFO
        );
        // 507, outside the 4xx range `status_and_code` otherwise keys off of,
        // so it needs its own arm -- still a client condition (they hit
        // their quota), not a server fault.
        assert_eq!(
            AppError::QuotaExceeded("over limit".into()).log_level(),
            tracing::Level::INFO
        );
        let json_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        assert_eq!(AppError::Json(json_err).log_level(), tracing::Level::INFO);
    }

    #[test]
    fn test_log_level_jwt_and_name_too_long_are_info() {
        // Regression coverage for the two variants a hand-maintained variant
        // list previously missed: both classify as 400/401 via
        // `status_and_code`, so deriving `log_level` from that mapping picks
        // them up automatically instead of needing a second list to keep in
        // sync.
        let jwt_err: jsonwebtoken::errors::Error = jsonwebtoken::decode::<serde_json::Value>(
            "not-a-token",
            &jsonwebtoken::DecodingKey::from_secret(b"x"),
            &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256),
        )
        .unwrap_err();
        assert_eq!(AppError::Jwt(jwt_err).log_level(), tracing::Level::INFO);

        let name_too_long = AppError::Storage("File name too long (os error 36)".into());
        assert_eq!(name_too_long.log_level(), tracing::Level::INFO);
    }

    #[test]
    fn test_log_level_server_faults_are_error() {
        // Genuine server-side faults must keep logging at `error` --
        // unchanged from before this fix.
        assert_eq!(
            AppError::Database("connection refused".into()).log_level(),
            tracing::Level::ERROR
        );
        assert_eq!(
            AppError::Storage("disk full".into()).log_level(),
            tracing::Level::ERROR
        );
        assert_eq!(
            AppError::Internal("panic".into()).log_level(),
            tracing::Level::ERROR
        );
        assert_eq!(
            AppError::Config("bad config".into()).log_level(),
            tracing::Level::ERROR
        );
        assert_eq!(
            AppError::BadGateway("upstream failed".into()).log_level(),
            tracing::Level::ERROR
        );
        assert_eq!(
            AppError::ServiceUnavailable("at capacity".into()).log_level(),
            tracing::Level::ERROR
        );
    }

    // -----------------------------------------------------------------------
    // #5649 / #5650: storage outage -> 503 + Retry-After, storage full -> 507,
    // neither echoing the backend's own error text.
    // -----------------------------------------------------------------------

    /// What MinIO answers a PUT into a bucket at its quota, as the S3 backend
    /// renders it: the XML names the bucket and carries request ids.
    fn minio_quota_error() -> String {
        format!(
            "Failed to put object 'generic/x.bin': {}",
            crate::storage::StorageFailure::Full.tag(
                "S3 request failed. caused by: Server returned non-2xx status code: \
                 400 Bad Request: <?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>\
                 XMinioAdminBucketQuotaExceeded</Code><Message>Bucket quota exceeded</Message>\
                 <BucketName>ak-secret-bucket</BucketName><RequestId>17A2B3C4D5E6F708</RequestId>\
                 <HostId>dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8</HostId>\
                 </Error>"
            )
        )
    }

    /// streaming-invariant: test scaffolding exempt — an error body is a small
    /// bounded JSON document, not an artifact path (#1608).
    #[allow(clippy::disallowed_methods)]
    async fn rendered(err: AppError) -> (StatusCode, axum::http::HeaderMap, String) {
        let response = err.into_response();
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("body");
        (status, headers, String::from_utf8_lossy(&body).into_owned())
    }

    fn assert_no_backend_text(body: &str) {
        for needle in [
            "XMinio",
            "<Error>",
            "<?xml",
            "ak-secret-bucket",
            "17A2B3C4D5E6F708",
            "caused by",
            "connection refused",
        ] {
            assert!(
                !body.contains(needle),
                "response body must not carry backend text {needle:?}: {body}"
            );
        }
    }

    #[tokio::test]
    async fn storage_full_maps_to_507_with_a_neutral_body_5650() {
        crate::storage::failure::reset_failure_signal();
        // Re-wrapped the way the format handlers do (`map_storage_err`).
        let inner = AppError::Storage(minio_quota_error());
        for err in [
            AppError::Storage(inner.to_string()),
            AppError::Internal(format!("upload failed: {inner}")),
            AppError::Io(std::io::Error::from_raw_os_error(28)),
        ] {
            let label = format!("{err:?}");
            let (status, headers, body) = rendered(err).await;
            assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE, "{label}");
            assert!(headers.get(header::RETRY_AFTER).is_none(), "{label}");
            let json: serde_json::Value = serde_json::from_str(&body).expect("json");
            assert_eq!(json["code"], "STORAGE_FULL", "{label}");
            assert_eq!(json["message"], STORAGE_FULL_MESSAGE, "{label}");
            assert_no_backend_text(&body);
        }
        assert!(
            crate::storage::failure::refused_for_space_within(
                crate::storage::failure::STORAGE_FULL_SIGNAL_WINDOW
            ),
            "a 507 must feed the storage health signal"
        );
    }

    #[tokio::test]
    async fn storage_unavailable_maps_to_503_with_retry_after_5649() {
        let err = AppError::Storage(format!(
            "Failed to put object 'k': {}",
            crate::storage::StorageFailure::Unavailable.tag(
                "S3 connection refused. caused by: Error performing PUT <url> in 10.2s, \
                 after 6 retries - HTTP error: error sending request: connection refused"
            )
        ));
        let (status, headers, body) = rendered(err).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            headers.get(header::RETRY_AFTER).unwrap(),
            RETRY_AFTER_SECS_ON_503
        );
        let json: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(json["code"], "STORAGE_UNAVAILABLE");
        assert_eq!(json["message"], STORAGE_UNAVAILABLE_MESSAGE);
        assert_no_backend_text(&body);
    }

    /// An upstream-proxy failure also travels as `AppError::Storage`; without
    /// a backend's marker it keeps its old status.
    #[test]
    fn untagged_storage_errors_keep_their_status() {
        let err = AppError::Storage("Failed to fetch from upstream: operation timed out".into());
        assert_eq!(
            err.status_and_code(),
            (StatusCode::INTERNAL_SERVER_ERROR, "STORAGE_ERROR")
        );
        let reset = AppError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
        assert_eq!(reset.status_and_code().1, "IO_ERROR");
    }
}
