//! Receiving an upload body in full before anything parses it (#4609).
//!
//! The archive-parsing publish routes (conda, RubyGems, npm, Cargo, Composer,
//! ...) need the whole package in memory before they can open it. They used to
//! take it through axum's `Bytes` extractor, which has two problems for a
//! registry:
//!
//! * Every failure while receiving the body came back as `400 Failed to buffer
//!   the request body`, a client error, even when the server ran out of room.
//!   A client whose body was cut short (connection reset, a proxy giving up)
//!   got the same 400 as one that sent garbage.
//! * It collects the body as a list of frames and then copies them into one
//!   contiguous buffer, so a 1.5 GB package peaked at roughly twice its size
//!   in memory. Two of those at once killed a 4 GiB replica (red-team S9).
//!
//! [`UploadBody`] replaces it. It receives the body into one buffer sized from
//! `Content-Length` (one copy, not two), charges the buffer to a process-wide
//! [`UploadMemoryBudget`], checks that it received exactly the bytes the client
//! declared, and only then hands the body to the handler. Every way receiving
//! can fail has its own status, so the parser only ever sees a complete body
//! and a parse error (400) always means the package itself is bad:
//!
//! | outcome | status |
//! |---|---|
//! | body larger than `MAX_UPLOAD_SIZE` (or than the whole memory budget) | `413` |
//! | body ended before `Content-Length` bytes arrived, or the connection broke | `408`, code `incomplete_body` |
//! | upload stalled (GHSA-9f9r-c4w8-rjv9 progress deadline) | `408` (the middleware's own response) |
//! | memory budget exhausted by other in-flight uploads, or the allocation failed | `503` + `Retry-After`, code `upload_capacity_exhausted` |
//! | any other failure reading the body | `503` + `Retry-After`, code `upload_receive_failed` |
//!
//! The same classification is used by the spooling routes (`proxy_helpers`
//! staging helpers), which add one more: a scratch or storage write that fails
//! because the disk is full is `507 Insufficient Storage` with `Retry-After`,
//! and any other spool I/O failure is `503` with `Retry-After`.
//!
//! The budget is `UPLOAD_MEMORY_BUDGET_BYTES`: unset means half the memory
//! limit of the container's cgroup when there is one (no cap otherwise), `0`
//! disables it, and any other value is the cap in bytes.

use std::io;
use std::sync::{Arc, OnceLock};

use axum::extract::{FromRequest, Request};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{async_trait, Json};
use bytes::Bytes;
use http_body_util::BodyExt;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

use crate::api::SharedState;

/// Env var that sets the in-memory upload budget (bytes; `0` disables it).
pub const UPLOAD_MEMORY_BUDGET_ENV: &str = "UPLOAD_MEMORY_BUDGET_BYTES";

/// `Retry-After` value on the retryable responses below. Long enough for one
/// in-flight multi-GB upload to finish on a typical link.
const RETRY_AFTER_SECS: &str = "30";

/// Budget accounting granularity. The semaphore counts 64 KiB units so a
/// multi-TiB budget still fits its permit count and `acquire_many`'s `u32`.
const BUDGET_UNIT: u64 = 64 * 1024;

/// Initial reservation, and growth step, for a body without `Content-Length`.
const CHUNKED_STEP: u64 = 8 * 1024 * 1024;

/// Why an upload body could not be received in full. See the module docs for
/// the status each maps to.
#[derive(Debug)]
pub enum UploadBodyError {
    /// Bigger than the route's size limit, or than the whole memory budget.
    TooLarge { limit: u64, what: &'static str },
    /// Fewer bytes arrived than the client declared, or the connection broke
    /// mid-body.
    Incomplete {
        received: u64,
        expected: Option<u64>,
    },
    /// The upload progress deadline fired (GHSA-9f9r-c4w8-rjv9).
    Stalled,
    /// Other uploads hold the memory budget, or the buffer allocation failed.
    CapacityExhausted { requested: u64, reason: String },
    /// Reading the body failed for a reason that is not the client's.
    ReceiveFailed { received: u64, cause: String },
    /// Writing the body to scratch or storage failed because the disk is full.
    DiskFull { cause: String },
    /// Writing the body to scratch failed for another reason.
    SpoolFailed { cause: String },
    /// A malformed multipart envelope: the client's fault, stays 400.
    Malformed(String),
}

impl std::fmt::Display for UploadBodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { limit, what } => {
                write!(f, "Upload exceeds the {what} of {limit} bytes")
            }
            Self::Incomplete {
                received,
                expected: Some(expected),
            } => write!(
                f,
                "Incomplete request body: received {received} of {expected} declared bytes"
            ),
            Self::Incomplete {
                received,
                expected: None,
            } => write!(
                f,
                "Incomplete request body: the body ended abnormally after {received} bytes"
            ),
            Self::Stalled => {
                f.write_str("Upload stalled: the request body made too little progress")
            }
            Self::CapacityExhausted { requested, reason } => write!(
                f,
                "The server cannot hold a {requested}-byte upload right now ({reason}); retry later"
            ),
            // Server-side causes (I/O errors, paths) never reach the client
            // (#3718); `cause()` carries them to the log.
            Self::ReceiveFailed { received, .. } => write!(
                f,
                "The server failed to receive the request body after {received} bytes; retry the upload"
            ),
            Self::DiskFull { .. } => {
                f.write_str("The server has no disk space for this upload right now; retry later")
            }
            Self::SpoolFailed { .. } => {
                f.write_str("The server could not stage this upload; retry the upload")
            }
            Self::Malformed(msg) => f.write_str(msg),
        }
    }
}

impl UploadBodyError {
    /// HTTP status and machine-readable code for this outcome.
    pub fn status_and_code(&self) -> (StatusCode, &'static str) {
        match self {
            Self::TooLarge { .. } => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
            Self::Incomplete { .. } => (StatusCode::REQUEST_TIMEOUT, "incomplete_body"),
            Self::Stalled => (StatusCode::REQUEST_TIMEOUT, "upload_stalled"),
            Self::CapacityExhausted { .. } => {
                (StatusCode::SERVICE_UNAVAILABLE, "upload_capacity_exhausted")
            }
            Self::ReceiveFailed { .. } => {
                (StatusCode::SERVICE_UNAVAILABLE, "upload_receive_failed")
            }
            Self::DiskFull { .. } => (StatusCode::INSUFFICIENT_STORAGE, "insufficient_storage"),
            Self::SpoolFailed { .. } => (StatusCode::SERVICE_UNAVAILABLE, "upload_spool_failed"),
            Self::Malformed(_) => (StatusCode::BAD_REQUEST, "malformed_body"),
        }
    }

    /// The server-side cause, for the log only.
    pub fn cause(&self) -> Option<&str> {
        match self {
            Self::ReceiveFailed { cause, .. }
            | Self::DiskFull { cause }
            | Self::SpoolFailed { cause } => Some(cause),
            Self::CapacityExhausted { reason, .. } => Some(reason),
            _ => None,
        }
    }
}

impl IntoResponse for UploadBodyError {
    fn into_response(self) -> Response {
        let (status, code) = self.status_and_code();
        match &self {
            Self::CapacityExhausted { .. }
            | Self::ReceiveFailed { .. }
            | Self::DiskFull { .. }
            | Self::SpoolFailed { .. } => {
                tracing::error!(
                    code,
                    error = %self,
                    cause = self.cause().unwrap_or_default(),
                    "upload body could not be received in full"
                );
            }
            Self::Incomplete { .. } | Self::Stalled => {
                tracing::warn!(code, error = %self, "upload body incomplete");
            }
            Self::TooLarge { .. } | Self::Malformed(_) => {
                tracing::info!(code, error = %self, "upload body refused");
            }
        }
        let mut response = (
            status,
            Json(serde_json::json!({ "code": code, "message": self.to_string() })),
        )
            .into_response();
        let headers = response.headers_mut();
        match status {
            StatusCode::SERVICE_UNAVAILABLE | StatusCode::INSUFFICIENT_STORAGE => {
                headers.insert(
                    header::RETRY_AFTER,
                    HeaderValue::from_static(RETRY_AFTER_SECS),
                );
            }
            StatusCode::REQUEST_TIMEOUT | StatusCode::PAYLOAD_TOO_LARGE => {
                // The rest of the body is never read; do not reuse the
                // connection for another request.
                headers.insert(header::CONNECTION, HeaderValue::from_static("close"));
            }
            _ => {}
        }
        response
    }
}

// ---------------------------------------------------------------------------
// Memory budget
// ---------------------------------------------------------------------------

/// Process-wide cap on the bytes of upload bodies held in memory at once.
///
/// Reservations are taken without waiting: a request that does not fit is
/// answered `503` with `Retry-After` straight away instead of queueing while
/// its client keeps sending (and the progress deadline keeps running).
#[derive(Debug)]
pub struct UploadMemoryBudget {
    total_bytes: u64,
    semaphore: Option<Arc<Semaphore>>,
}

impl UploadMemoryBudget {
    /// A budget of `total_bytes`; `0` means unlimited.
    pub fn new(total_bytes: u64) -> Arc<Self> {
        let semaphore = (total_bytes > 0).then(|| {
            let units = units_for(total_bytes).min(Semaphore::MAX_PERMITS as u64) as usize;
            Arc::new(Semaphore::new(units))
        });
        Arc::new(Self {
            total_bytes,
            semaphore,
        })
    }

    /// The configured cap in bytes (`0` = unlimited).
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// Bytes not currently reserved (`u64::MAX` when unlimited).
    pub fn available_bytes(&self) -> u64 {
        match &self.semaphore {
            Some(s) => s.available_permits() as u64 * BUDGET_UNIT,
            None => u64::MAX,
        }
    }

    /// Reserve `bytes` without waiting.
    pub fn try_reserve(self: &Arc<Self>, bytes: u64) -> Result<Reservation, UploadBodyError> {
        let mut reservation = Reservation {
            budget: Arc::clone(self),
            permit: None,
            bytes: 0,
        };
        reservation.grow_to(bytes)?;
        Ok(reservation)
    }
}

fn units_for(bytes: u64) -> u64 {
    bytes.div_ceil(BUDGET_UNIT)
}

/// Bytes held against an [`UploadMemoryBudget`]; released on drop.
#[derive(Debug)]
pub struct Reservation {
    budget: Arc<UploadMemoryBudget>,
    permit: Option<OwnedSemaphorePermit>,
    bytes: u64,
}

impl Reservation {
    /// Grow the reservation to cover `bytes` in total.
    pub fn grow_to(&mut self, bytes: u64) -> Result<(), UploadBodyError> {
        if bytes <= self.bytes {
            return Ok(());
        }
        let Some(semaphore) = &self.budget.semaphore else {
            self.bytes = bytes;
            return Ok(());
        };
        if bytes > self.budget.total_bytes {
            return Err(UploadBodyError::TooLarge {
                limit: self.budget.total_bytes,
                what: "in-memory upload budget (UPLOAD_MEMORY_BUDGET_BYTES)",
            });
        }
        let extra = units_for(bytes) - units_for(self.bytes);
        if extra > 0 {
            let extra = u32::try_from(extra).map_err(|_| UploadBodyError::TooLarge {
                limit: self.budget.total_bytes,
                what: "in-memory upload budget (UPLOAD_MEMORY_BUDGET_BYTES)",
            })?;
            let permit = Arc::clone(semaphore)
                .try_acquire_many_owned(extra)
                .map_err(|e| UploadBodyError::CapacityExhausted {
                    requested: bytes,
                    reason: match e {
                        TryAcquireError::NoPermits => format!(
                            "in-memory upload budget exhausted: {} of {} bytes free",
                            self.budget.available_bytes(),
                            self.budget.total_bytes
                        ),
                        TryAcquireError::Closed => "in-memory upload budget closed".to_string(),
                    },
                })?;
            match &mut self.permit {
                Some(held) => held.merge(permit),
                None => self.permit = Some(permit),
            }
        }
        self.bytes = bytes;
        Ok(())
    }
}

/// The process-wide budget, built on first use from
/// [`UPLOAD_MEMORY_BUDGET_ENV`] (or the cgroup memory limit when unset).
pub fn global_upload_memory_budget() -> &'static Arc<UploadMemoryBudget> {
    static BUDGET: OnceLock<Arc<UploadMemoryBudget>> = OnceLock::new();
    BUDGET.get_or_init(|| {
        let (bytes, source) = resolve_budget_bytes(
            std::env::var(UPLOAD_MEMORY_BUDGET_ENV).ok().as_deref(),
            cgroup_memory_limit(),
        );
        tracing::info!(
            budget_bytes = bytes,
            source,
            "in-memory upload budget (0 = unlimited)"
        );
        UploadMemoryBudget::new(bytes)
    })
}

/// Resolve the budget from the env value and the cgroup limit. Pure so the
/// rules are testable: an explicit number wins (`0` = unlimited); unset or
/// unparseable falls back to half the cgroup limit, or unlimited without one.
fn resolve_budget_bytes(env: Option<&str>, cgroup_limit: Option<u64>) -> (u64, &'static str) {
    if let Some(v) = env.map(str::trim).filter(|v| !v.is_empty()) {
        match v.parse::<u64>() {
            Ok(n) => return (n, UPLOAD_MEMORY_BUDGET_ENV),
            Err(_) => tracing::warn!(
                value = v,
                "{UPLOAD_MEMORY_BUDGET_ENV} is not a byte count; using the default"
            ),
        }
    }
    match cgroup_limit {
        Some(limit) => (limit / 2, "half the cgroup memory limit"),
        None => (0, "no cgroup memory limit"),
    }
}

/// The container's memory limit, from cgroup v2 `memory.max` or cgroup v1
/// `memory.limit_in_bytes`; `None` when unlimited or unreadable.
fn cgroup_memory_limit() -> Option<u64> {
    const V2: &str = "/sys/fs/cgroup/memory.max";
    const V1: &str = "/sys/fs/cgroup/memory/memory.limit_in_bytes";
    [V2, V1]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| parse_cgroup_limit(&s))
}

fn parse_cgroup_limit(raw: &str) -> Option<u64> {
    let raw = raw.trim();
    if raw == "max" {
        return None;
    }
    // cgroup v1 reports "unlimited" as a page-rounded i64::MAX.
    raw.parse::<u64>().ok().filter(|&n| n > 0 && n < (1 << 60))
}

// ---------------------------------------------------------------------------
// Receiving
// ---------------------------------------------------------------------------

/// The declared `Content-Length`, if present and well-formed.
pub fn declared_content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// A buffer whose memory is charged to the budget for as long as any `Bytes`
/// handle to it is alive (`Bytes::from_owner`).
struct BudgetedBuffer {
    data: Vec<u8>,
    _reservation: Reservation,
}

impl AsRef<[u8]> for BudgetedBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

/// Classify an error raised while reading the body, given how far it got.
///
/// `max_bytes` is the size cap the body was read under (`0` = none), only used
/// to word the 413.
pub fn classify_body_error(
    err: &(dyn std::error::Error + 'static),
    received: u64,
    expected: Option<u64>,
    max_bytes: u64,
) -> UploadBodyError {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(err);
    let mut broken_connection = false;
    while let Some(e) = cur {
        if e.downcast_ref::<http_body_util::LengthLimitError>()
            .is_some()
        {
            return UploadBodyError::TooLarge {
                limit: max_bytes,
                what: "maximum upload size (MAX_UPLOAD_SIZE)",
            };
        }
        if e.downcast_ref::<crate::api::middleware::upload_guard::UploadStalled>()
            .is_some()
        {
            return UploadBodyError::Stalled;
        }
        if let Some(m) = e.downcast_ref::<multer::Error>() {
            match m {
                multer::Error::StreamSizeExceeded { limit }
                | multer::Error::FieldSizeExceeded { limit, .. } => {
                    return UploadBodyError::TooLarge {
                        limit: *limit,
                        what: "maximum upload size (MAX_UPLOAD_SIZE)",
                    };
                }
                // The underlying body failed: keep walking to classify it.
                multer::Error::StreamReadFailed(_) => {}
                // A multipart envelope that ends early on an intact transport
                // is the client's malformed request (#3848), not a cut-short
                // body: a broken transport surfaces as StreamReadFailed.
                other => {
                    return UploadBodyError::Malformed(format!(
                        "Malformed multipart/form-data request: {other}"
                    ))
                }
            }
        }
        if let Some(io) = e.downcast_ref::<io::Error>() {
            if matches!(
                io.kind(),
                io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
            ) {
                broken_connection = true;
            }
        }
        cur = e.source();
    }
    let short = expected.is_some_and(|n| received < n);
    if broken_connection || short {
        return UploadBodyError::Incomplete { received, expected };
    }
    UploadBodyError::ReceiveFailed {
        received,
        cause: error_chain(err),
    }
}

fn error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut out = err.to_string();
    let mut cur = err.source();
    while let Some(e) = cur {
        out.push_str(": ");
        out.push_str(&e.to_string());
        cur = e.source();
    }
    out
}

/// Receive `body` in full into one budget-charged buffer.
///
/// `declared` is the request's `Content-Length`; `max_bytes` the route's size
/// cap (`0` = none). Returns the complete body or the reason it could not be
/// had. Never returns a partial body.
pub async fn receive_body<B>(
    body: B,
    declared: Option<u64>,
    max_bytes: u64,
    budget: &Arc<UploadMemoryBudget>,
) -> Result<Bytes, UploadBodyError>
where
    B: http_body::Body<Data = Bytes>,
    B::Error: Into<axum::BoxError>,
{
    if let Some(n) = declared {
        if max_bytes != 0 && n > max_bytes {
            return Err(UploadBodyError::TooLarge {
                limit: max_bytes,
                what: "maximum upload size (MAX_UPLOAD_SIZE)",
            });
        }
    }

    let initial = declared.unwrap_or(CHUNKED_STEP.min(if max_bytes == 0 {
        CHUNKED_STEP
    } else {
        max_bytes
    }));
    let mut reservation = budget.try_reserve(initial)?;
    let mut data: Vec<u8> = Vec::new();
    if let Some(n) = declared {
        let n_usize = usize::try_from(n).map_err(|_| UploadBodyError::CapacityExhausted {
            requested: n,
            reason: "body does not fit in addressable memory".to_string(),
        })?;
        data.try_reserve_exact(n_usize)
            .map_err(|e| UploadBodyError::CapacityExhausted {
                requested: n,
                reason: format!("buffer allocation failed: {e}"),
            })?;
    }

    let mut received: u64 = 0;
    tokio::pin!(body);
    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(f) => f,
            Err(e) => {
                let e: axum::BoxError = e.into();
                return Err(classify_body_error(&*e, received, declared, max_bytes));
            }
        };
        let Ok(chunk) = frame.into_data() else {
            continue; // trailers
        };
        let next = received + chunk.len() as u64;
        if max_bytes != 0 && next > max_bytes {
            return Err(UploadBodyError::TooLarge {
                limit: max_bytes,
                what: "maximum upload size (MAX_UPLOAD_SIZE)",
            });
        }
        if declared.is_some_and(|n| next > n) {
            // hyper never yields more than Content-Length; a body that does
            // has been altered on the way, so refuse it rather than parse it.
            return Err(UploadBodyError::ReceiveFailed {
                received: next,
                cause: "body longer than its Content-Length".to_string(),
            });
        }
        if data.capacity() - data.len() < chunk.len() {
            // Only bodies without Content-Length grow; charge the budget for
            // the capacity before allocating it.
            let want = (data.len() + chunk.len()).max(data.capacity().saturating_mul(2));
            let want = want.max(CHUNKED_STEP as usize);
            reservation.grow_to(want as u64)?;
            data.try_reserve_exact(want - data.len()).map_err(|e| {
                UploadBodyError::CapacityExhausted {
                    requested: want as u64,
                    reason: format!("buffer allocation failed: {e}"),
                }
            })?;
        }
        data.extend_from_slice(&chunk);
        received = next;
    }

    if let Some(n) = declared {
        if received != n {
            return Err(UploadBodyError::Incomplete {
                received,
                expected: Some(n),
            });
        }
    }
    Ok(Bytes::from_owner(BudgetedBuffer {
        data,
        _reservation: reservation,
    }))
}

/// Drop-in replacement for the `Bytes` body extractor on archive-parsing
/// upload routes: `UploadBody(body): UploadBody` yields the complete body or
/// answers with the status from the module docs.
///
/// The memory stays charged to the budget until the last clone of `body` is
/// dropped. Tests can inject their own budget as an
/// `Extension(Arc<UploadMemoryBudget>)`.
pub struct UploadBody(pub Bytes);

#[async_trait]
impl FromRequest<SharedState> for UploadBody {
    type Rejection = Response;

    async fn from_request(req: Request, state: &SharedState) -> Result<Self, Self::Rejection> {
        use axum::RequestExt;
        let declared = declared_content_length(req.headers());
        let budget = req
            .extensions()
            .get::<Arc<UploadMemoryBudget>>()
            .cloned()
            .unwrap_or_else(|| Arc::clone(global_upload_memory_budget()));
        let max = state.config.max_upload_size_bytes;
        receive_body(req.into_limited_body(), declared, max, &budget)
            .await
            .map(UploadBody)
            .map_err(IntoResponse::into_response)
    }
}

/// Map a failed scratch-file or storage write. A full disk or exhausted quota
/// is `507` with `Retry-After`; any other I/O failure is `503` with
/// `Retry-After`. Both are logged at `error` with the cause.
pub fn spool_write_error(label: &str, err: &io::Error) -> UploadBodyError {
    let cause = format!("{label}: {err}");
    if is_disk_full_io(err) {
        UploadBodyError::DiskFull { cause }
    } else {
        UploadBodyError::SpoolFailed { cause }
    }
}

/// Whether an I/O error means the disk (or the user's quota on it) is full.
pub fn is_disk_full_io(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::StorageFull | io::ErrorKind::QuotaExceeded
    ) || matches!(err.raw_os_error(), Some(28) | Some(122))
}

/// Whether a storage-layer error message reports a full disk. Storage
/// backends flatten I/O errors into text, so this looks for the OS wording.
pub fn is_disk_full_message(msg: &str) -> bool {
    msg.contains("No space left on device")
        || msg.contains("os error 28")
        || msg.contains("Disk quota exceeded")
        || msg.contains("os error 122")
        || msg.contains("StorageFull")
}

/// `507` + `Retry-After` when a storage write failed on a full disk, else
/// `None` so the caller keeps its own mapping.
pub fn disk_full_response(err: &impl std::fmt::Display) -> Option<Response> {
    let text = err.to_string();
    is_disk_full_message(&text).then(|| UploadBodyError::DiskFull { cause: text }.into_response())
}

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream;
    use http_body_util::StreamBody;

    type FrameResult = Result<http_body::Frame<Bytes>, io::Error>;

    fn body_of(
        chunks: Vec<FrameResult>,
    ) -> StreamBody<stream::Iter<std::vec::IntoIter<FrameResult>>> {
        StreamBody::new(stream::iter(chunks))
    }

    fn data(b: &'static [u8]) -> FrameResult {
        Ok(http_body::Frame::data(Bytes::from_static(b)))
    }

    #[tokio::test]
    async fn complete_body_is_returned_whole() {
        let budget = UploadMemoryBudget::new(0);
        let got = receive_body(
            body_of(vec![data(b"abc"), data(b"def")]),
            Some(6),
            0,
            &budget,
        )
        .await
        .unwrap();
        assert_eq!(&got[..], b"abcdef");
    }

    #[tokio::test]
    async fn short_clean_body_is_incomplete_not_parsed() {
        let budget = UploadMemoryBudget::new(0);
        let err = receive_body(body_of(vec![data(b"abc")]), Some(10), 0, &budget)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            UploadBodyError::Incomplete {
                received: 3,
                expected: Some(10)
            }
        ));
        assert_eq!(err.status_and_code().0, StatusCode::REQUEST_TIMEOUT);
    }

    #[tokio::test]
    async fn connection_reset_mid_body_is_incomplete() {
        let budget = UploadMemoryBudget::new(0);
        let err = receive_body(
            body_of(vec![
                data(b"abc"),
                Err(io::Error::new(io::ErrorKind::ConnectionReset, "reset")),
            ]),
            None,
            0,
            &budget,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            UploadBodyError::Incomplete { received: 3, .. }
        ));
    }

    #[tokio::test]
    async fn unexplained_read_error_is_a_retryable_server_error() {
        let budget = UploadMemoryBudget::new(0);
        let err = receive_body(
            body_of(vec![Err(io::Error::other("decoder exploded"))]),
            None,
            0,
            &budget,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, UploadBodyError::ReceiveFailed { .. }));
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(resp.headers().contains_key(header::RETRY_AFTER));
    }

    #[tokio::test]
    async fn declared_size_over_route_limit_is_413_before_reading() {
        let budget = UploadMemoryBudget::new(0);
        let err = receive_body(body_of(vec![]), Some(100), 10, &budget)
            .await
            .unwrap_err();
        assert_eq!(err.status_and_code().0, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn budget_exhausted_by_another_upload_is_503_with_retry_after() {
        let budget = UploadMemoryBudget::new(1024 * 1024);
        let held = budget.try_reserve(900 * 1024).unwrap();
        let err = receive_body(body_of(vec![data(b"x")]), Some(512 * 1024), 0, &budget)
            .await
            .unwrap_err();
        assert!(matches!(err, UploadBodyError::CapacityExhausted { .. }));
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(resp.headers()[header::RETRY_AFTER], RETRY_AFTER_SECS);
        drop(held);
        assert_eq!(budget.available_bytes(), 1024 * 1024);
    }

    #[tokio::test]
    async fn budget_is_held_until_the_last_bytes_handle_drops() {
        let budget = UploadMemoryBudget::new(1024 * 1024);
        let got = receive_body(body_of(vec![data(b"hello")]), Some(5), 0, &budget)
            .await
            .unwrap();
        let clone = got.clone();
        drop(got);
        assert!(budget.available_bytes() < 1024 * 1024);
        drop(clone);
        assert_eq!(budget.available_bytes(), 1024 * 1024);
    }

    #[tokio::test]
    async fn body_bigger_than_the_whole_budget_is_413() {
        let budget = UploadMemoryBudget::new(1024 * 1024);
        let err = receive_body(body_of(vec![]), Some(2 * 1024 * 1024), 0, &budget)
            .await
            .unwrap_err();
        assert_eq!(err.status_and_code().0, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn allocation_failure_is_503_not_a_crash() {
        let budget = UploadMemoryBudget::new(0);
        let err = receive_body(body_of(vec![]), Some(u64::MAX / 2), 0, &budget)
            .await
            .unwrap_err();
        assert!(
            matches!(err, UploadBodyError::CapacityExhausted { .. }),
            "{err}"
        );
    }

    #[tokio::test]
    async fn chunked_body_grows_its_reservation() {
        let budget = UploadMemoryBudget::new(64 * 1024 * 1024);
        let big = vec![7u8; 9 * 1024 * 1024];
        let frames: Vec<FrameResult> = vec![Ok(http_body::Frame::data(Bytes::from(big)))];
        let got = receive_body(body_of(frames), None, 0, &budget)
            .await
            .unwrap();
        assert_eq!(got.len(), 9 * 1024 * 1024);
    }

    #[test]
    fn spool_errors_map_disk_full_to_507() {
        let full = io::Error::from_raw_os_error(28);
        let resp = spool_write_error("Staging write", &full).into_response();
        assert_eq!(resp.status(), StatusCode::INSUFFICIENT_STORAGE);
        assert!(resp.headers().contains_key(header::RETRY_AFTER));

        let quota = io::Error::from_raw_os_error(122);
        assert!(is_disk_full_io(&quota));

        let other = io::Error::new(io::ErrorKind::PermissionDenied, "nope");
        let resp = spool_write_error("Staging file", &other).into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(resp.headers().contains_key(header::RETRY_AFTER));
    }

    #[test]
    fn storage_message_disk_full_detection() {
        assert!(disk_full_response(&"IO error: No space left on device (os error 28)").is_some());
        assert!(disk_full_response(&"IO error: permission denied").is_none());
    }

    #[test]
    fn budget_resolution_rules() {
        assert_eq!(resolve_budget_bytes(Some("1234"), Some(8 << 30)).0, 1234);
        assert_eq!(resolve_budget_bytes(Some("0"), Some(8 << 30)).0, 0);
        assert_eq!(resolve_budget_bytes(None, Some(4 << 30)).0, 2 << 30);
        assert_eq!(resolve_budget_bytes(Some("junk"), None).0, 0);
        assert_eq!(parse_cgroup_limit("max\n"), None);
        assert_eq!(parse_cgroup_limit("4294967296\n"), Some(4 << 30));
        assert_eq!(parse_cgroup_limit("9223372036854771712"), None);
    }

    #[test]
    fn incomplete_body_response_names_the_code_and_closes() {
        let resp = UploadBodyError::Incomplete {
            received: 1,
            expected: Some(2),
        }
        .into_response();
        assert_eq!(resp.status(), StatusCode::REQUEST_TIMEOUT);
        assert_eq!(resp.headers()[header::CONNECTION], "close");
    }
}
