//! Storage failures that answer with their own HTTP status (#5649, #5650).
//!
//! Most storage errors reach the HTTP layer as `AppError::Storage(String)`:
//! the format handlers re-wrap them freely, so the error type does not
//! survive. Two classes still need a status of their own:
//!
//! * **Unavailable** -- the object store could not be reached or did not
//!   answer in time (connection refused, DNS failure, timeout, 502/503/504,
//!   throttling). Nothing was stored, so the request can be retried:
//!   `503 STORAGE_UNAVAILABLE` with `Retry-After`. Before #5649 these surfaced
//!   as a 500 at best and, on S3, as a request that hung for minutes while
//!   `object_store` retried connection attempts to the gone host.
//! * **Full** -- the backend refused the write for lack of space (a MinIO
//!   bucket quota, a full volume, a GCS storage quota): `507 STORAGE_FULL`.
//!   Before #5650 this was a 500, and the OCI routes echoed the MinIO XML
//!   error document (bucket name, request ids) to the client.
//!
//! The storage backends know which class a failure belongs to when they
//! build the error, so they put a marker into the message
//! ([`StorageFailure::tag`]). The HTTP layer recognises the marker however
//! many times the message was re-wrapped ([`StorageFailure::from_message`]).
//!
//! Classification never reads text a client controls. Error messages carry
//! object keys and request URLs, so a key named `QuotaExceeded.bin` or
//! `no space left on device` must not turn a failure into a 507:
//!
//! * the class is decided from typed data only: the transport error kind,
//!   the `io::Error` kind / OS error number, the HTTP status, and the exact
//!   error *code* of the response (S3/Azure `<Code>`, GCS `reason`), never
//!   from a substring of the whole message;
//! * the marker embeds a per-process random token, so a key cannot spell
//!   it. It reaches no client: a classified error answers with a fixed
//!   message.
//!
//! Matching on the marker rather than on raw fragments such as "timed out"
//! also keeps an upstream-proxy failure, which travels as `AppError::Storage`
//! too, from being reported as a storage outage.

use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::error::AppError;

/// Exact error codes (S3/MinIO `<Code>`) for a write refused for lack of
/// space: MinIO's bucket quota and full-disk codes, the `QuotaExceeded` of
/// Ceph RGW and other S3-compatible stores, and `InsufficientStorage`.
const CODES_OUT_OF_SPACE: &[&str] = &[
    "XMinioAdminBucketQuotaExceeded",
    "XMinioStorageFull",
    "QuotaExceeded",
    "InsufficientStorage",
];

/// Exact error codes for a store that is overloaded or timing out rather than
/// refusing the request (S3 `SlowDown` / `ServiceUnavailable`, Azure
/// `ServerBusy` / `OperationTimedOut`).
const CODES_UNAVAILABLE: &[&str] = &[
    "SlowDown",
    "ServiceUnavailable",
    "ServerBusy",
    "OperationTimedOut",
];

/// A storage failure with a dedicated HTTP status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageFailure {
    /// The backend could not be reached or did not answer in time: 503.
    Unavailable,
    /// The backend refused the write for lack of space: 507.
    Full,
}

/// The two markers, each carrying a token drawn once per process.
fn markers() -> &'static (String, String) {
    static MARKERS: OnceLock<(String, String)> = OnceLock::new();
    MARKERS.get_or_init(|| {
        let token = uuid::Uuid::new_v4().simple().to_string();
        let token = &token[..16];
        (
            format!("storage backend unavailable [{token}]"),
            format!("storage backend out of space [{token}]"),
        )
    })
}

impl StorageFailure {
    /// The marker [`Self::tag`] inserts and [`Self::from_message`] finds.
    pub fn marker(self) -> &'static str {
        let (unavailable, full) = markers();
        match self {
            Self::Unavailable => unavailable,
            Self::Full => full,
        }
    }

    /// `message` with this class's marker in front, so the class survives
    /// any amount of re-wrapping into other error strings.
    pub fn tag(self, message: impl std::fmt::Display) -> String {
        format!("{}: {message}", self.marker())
    }

    /// The class a storage error message carries, if any: only a backend's
    /// marker counts, never the wording of the message itself.
    pub fn from_message(message: &str) -> Option<Self> {
        if message.contains(Self::Full.marker()) {
            Some(Self::Full)
        } else if message.contains(Self::Unavailable.marker()) {
            Some(Self::Unavailable)
        } else {
            None
        }
    }

    /// The class of a local I/O error, from its kind and OS error number
    /// only: ENOSPC / EDQUOT is "out of space". A connection reset on an
    /// `io::Error` is far more often the client hanging up mid-upload than
    /// the storage backend failing, so it has no class.
    pub fn from_io(err: &std::io::Error) -> Option<Self> {
        (matches!(
            err.kind(),
            std::io::ErrorKind::StorageFull | std::io::ErrorKind::QuotaExceeded
        ) || matches!(err.raw_os_error(), Some(28) | Some(122)))
        .then_some(Self::Full)
    }

    /// The class of a non-success response from an S3-compatible store or
    /// Azure, from its status and its exact error code.
    pub fn from_http_status(status: u16, code: Option<&str>) -> Option<Self> {
        if status == 507 || code.is_some_and(|c| CODES_OUT_OF_SPACE.contains(&c)) {
            Some(Self::Full)
        } else if matches!(status, 429 | 502 | 503 | 504)
            || code.is_some_and(|c| CODES_UNAVAILABLE.contains(&c))
        {
            Some(Self::Unavailable)
        } else {
            None
        }
    }

    /// The class of a transport error from a hand-rolled storage request:
    /// a failed connect or a timeout means the backend did not answer.
    pub fn from_reqwest(err: &reqwest::Error) -> Option<Self> {
        (err.is_connect() || err.is_timeout()).then_some(Self::Unavailable)
    }
}

/// The `<Code>` of an S3-style XML error document. The code is the first
/// element of `<Error>`, ahead of the key, resource and message elements that
/// can quote a client-chosen name, so the first match is the code.
pub(crate) fn xml_error_code(body: &str) -> Option<&str> {
    let start = body.find("<Code>")? + "<Code>".len();
    let len = body[start..].find("</Code>")?;
    Some(body[start..start + len].trim())
}

/// `AppError::Storage(message)`, tagged with the class `status` and the
/// response's exact error `code` imply.
pub(crate) fn status_storage_error(status: u16, code: Option<&str>, message: String) -> AppError {
    match StorageFailure::from_http_status(status, code) {
        Some(class) => AppError::Storage(class.tag(message)),
        None => AppError::Storage(message),
    }
}

/// `AppError::Storage(message)` for a failed local I/O call, tagged full when
/// `err` is ENOSPC / EDQUOT.
pub(crate) fn io_storage_error(err: &std::io::Error, message: String) -> AppError {
    match StorageFailure::from_io(err) {
        Some(class) => AppError::Storage(class.tag(message)),
        None => AppError::Storage(message),
    }
}

/// `AppError::Storage("{context}: {err}")` with the request URL left out of
/// `err` (it names the endpoint, bucket and key), tagged unavailable when
/// `err` is a failed connect or a timeout.
pub(crate) fn transport_storage_error(context: &str, err: reqwest::Error) -> AppError {
    let class = StorageFailure::from_reqwest(&err);
    let message = format!("{context}: {}", err.without_url());
    match class {
        Some(class) => AppError::Storage(class.tag(message)),
        None => AppError::Storage(message),
    }
}

// ---------------------------------------------------------------------------
// Out-of-space signal for the health endpoints
// ---------------------------------------------------------------------------

/// How long after the last out-of-space refusal `/health` and `/readyz` keep
/// reporting storage as degraded. A connectivity probe cannot see a full
/// bucket (a HEAD still succeeds), so the signal comes from the writes that
/// were refused; once none has been refused for this long the check clears
/// on its own, which is what recovery after an operator raises the quota
/// looks like.
pub const STORAGE_FULL_SIGNAL_WINDOW: Duration = Duration::from_secs(60);

static LAST_FULL_REFUSAL: Mutex<Option<Instant>> = Mutex::new(None);

/// Record that a request failed with `class`. Only [`StorageFailure::Full`]
/// is kept: unavailability is what the health probe itself detects.
pub fn record_failure(class: StorageFailure) {
    if class == StorageFailure::Full {
        if let Ok(mut last) = LAST_FULL_REFUSAL.lock() {
            *last = Some(Instant::now());
        }
    }
}

/// Whether a write was refused for lack of space within `window`.
pub fn refused_for_space_within(window: Duration) -> bool {
    LAST_FULL_REFUSAL
        .lock()
        .ok()
        .and_then(|last| *last)
        .is_some_and(|at| at.elapsed() < window)
}

/// Forget any recorded out-of-space refusal (tests share the process-wide
/// signal, so each starts from a clean slate).
#[cfg(test)]
pub fn reset_failure_signal() {
    if let Ok(mut last) = LAST_FULL_REFUSAL.lock() {
        *last = None;
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markers_round_trip_through_rewrapping() {
        for class in [StorageFailure::Unavailable, StorageFailure::Full] {
            let inner = AppError::Storage(class.tag("Failed to put object 'k'"));
            let rewrapped = AppError::Storage(format!("upload failed: {inner}")).to_string();
            assert_eq!(StorageFailure::from_message(&rewrapped), Some(class));
        }
        assert_eq!(
            StorageFailure::from_message("Failed to fetch: timed out"),
            None
        );
        assert_eq!(
            StorageFailure::from_message("Upstream returned 503 Service Unavailable"),
            None,
            "an upstream proxy failure is not a storage outage"
        );
    }

    /// Spoofing: a message whose wording (a key, an OS phrase) reads like a
    /// class carries no class. Only the backend's tokenised marker does.
    #[test]
    fn message_wording_never_classifies() {
        for msg in [
            "Failed to write k: No space left on device (os error 28)",
            "Failed to put object 'generic/QuotaExceeded.bin': AccessDenied",
            "Failed to get 'storage backend out of space': SlowDown ServerBusy",
        ] {
            assert_eq!(StorageFailure::from_message(msg), None, "{msg}");
        }
        assert_eq!(
            StorageFailure::from_message(&StorageFailure::Full.tag("x")),
            Some(StorageFailure::Full)
        );
    }

    #[test]
    fn io_errors_only_classify_out_of_space() {
        assert_eq!(
            StorageFailure::from_io(&std::io::Error::from_raw_os_error(28)),
            Some(StorageFailure::Full)
        );
        assert_eq!(
            StorageFailure::from_io(&std::io::Error::from(std::io::ErrorKind::StorageFull)),
            Some(StorageFailure::Full)
        );
        assert_eq!(
            StorageFailure::from_io(&std::io::Error::other("No space left on device")),
            None,
            "the text of an io::Error is not its kind"
        );
        assert_eq!(
            StorageFailure::from_io(&std::io::Error::from(std::io::ErrorKind::ConnectionReset)),
            None
        );
        let tagged = io_storage_error(&std::io::Error::from_raw_os_error(28), "Write error".into());
        assert_eq!(tagged.storage_failure(), Some(StorageFailure::Full));
    }

    #[test]
    fn http_statuses_and_exact_codes_classify() {
        let minio_quota = "<?xml version=\"1.0\"?><Error><Code>XMinioAdminBucketQuotaExceeded\
                           </Code><Message>Bucket quota exceeded</Message>\
                           <Key>SlowDown.bin</Key></Error>";
        let code = xml_error_code(minio_quota);
        assert_eq!(code, Some("XMinioAdminBucketQuotaExceeded"));
        assert_eq!(
            StorageFailure::from_http_status(400, code),
            Some(StorageFailure::Full)
        );
        assert_eq!(
            StorageFailure::from_http_status(507, None),
            Some(StorageFailure::Full)
        );
        for status in [429, 502, 503, 504] {
            assert_eq!(
                StorageFailure::from_http_status(status, None),
                Some(StorageFailure::Unavailable),
                "{status}"
            );
        }
        assert_eq!(
            StorageFailure::from_http_status(500, Some("ServerBusy")),
            Some(StorageFailure::Unavailable)
        );
        // A key or message quoting a code is not the code.
        let access_denied = "<Error><Code>AccessDenied</Code><Key>QuotaExceeded.bin</Key>\
                             <Message>SlowDown</Message></Error>";
        assert_eq!(
            StorageFailure::from_http_status(403, xml_error_code(access_denied)),
            None
        );
        for status in [400, 403, 404, 409, 500] {
            assert_eq!(
                StorageFailure::from_http_status(status, Some("AccessDenied")),
                None
            );
        }
    }

    #[test]
    fn status_storage_error_tags_only_classified_statuses() {
        let full = status_storage_error(507, None, "Azure upload failed".into());
        assert_eq!(full.storage_failure(), Some(StorageFailure::Full), "{full}");
        let plain = status_storage_error(403, Some("AuthorizationFailure"), "Azure upload".into());
        assert_eq!(plain.storage_failure(), None);
    }

    #[tokio::test]
    async fn transport_storage_error_tags_a_refused_connection() {
        let err = reqwest::Client::new()
            .get("http://127.0.0.1:1/")
            .send()
            .await
            .expect_err("nothing listens on port 1");
        let tagged = transport_storage_error("Azure HEAD failed", err);
        assert_eq!(
            StorageFailure::from_message(&tagged.to_string()),
            Some(StorageFailure::Unavailable)
        );
    }
}
