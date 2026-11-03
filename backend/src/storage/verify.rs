//! Integrity verification of stored object bytes against their recorded
//! SHA-256 (#3919, #3910).
//!
//! Content-addressed artifact rows record the SHA-256 of the bytes they were
//! written with (`artifacts.checksum_sha256`), and the generic download route
//! advertises it as `X-Checksum-Sha256` before the first body byte. If the
//! stored object is later corrupted (bit rot, a truncated write, an operator
//! touching the bucket), serving it as a clean `200` with the original digest
//! header hands the client bytes the server itself vouched for.
//!
//! [`verify_sha256_stream`] wraps a body stream so it is hashed incrementally
//! while it is served, without buffering the object: it holds back exactly
//! one chunk, and only releases that last chunk once the digest and length at
//! end-of-stream match the record. On a mismatch the stream ends in an error
//! instead, which aborts the HTTP response before `Content-Length` bytes were
//! delivered, so no client can mistake the corrupted body for a complete one.

use bytes::Bytes;
use futures::stream::BoxStream;
use futures::StreamExt;
use sha2::{Digest, Sha256};

use crate::error::{AppError, Result};
use crate::util::byte_budget::{budget_from_env, ByteBudget};

/// Parse a recorded SHA-256 into raw digest bytes.
///
/// Returns `None` when the value is not exactly 64 hex characters (after
/// trimming the CHAR(64) blank padding). Such a value cannot be the digest of
/// the stored bytes, so there is nothing to verify against; callers serve the
/// object unverified exactly as before rather than failing it.
pub fn parse_sha256_hex(recorded: &str) -> Option<[u8; 32]> {
    let trimmed = recorded.trim();
    let trimmed = trimmed.strip_prefix("sha256:").unwrap_or(trimmed);
    if trimmed.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(trimmed, &mut out).ok()?;
    Some(out)
}

/// Whether an artifact row's `checksum_sha256` is the SHA-256 of the bytes
/// stored at its `storage_key`, i.e. whether the bytes can be verified
/// against it at all (#3919/#3910).
///
/// Almost every writer records the digest of the stored object. The known
/// exception is a protobuf (BSR) module commit (`modules/{name}/commits/
/// {digest}`): its row records the *commit digest* (SHA-256 over the module's
/// file paths and contents), while the stored object is the gzip bundle of
/// those files. Verifying it would abort every commit download and make the
/// scrub flag every protobuf row, so such rows are excluded from both. Kept
/// deliberately narrow: add a case here only for a writer whose recorded
/// checksum is known not to describe the stored bytes.
pub fn checksum_is_content_digest(format_key: &str, path: &str) -> bool {
    let protobuf_commit_bundle = format_key == "protobuf"
        && path.trim_start_matches('/').starts_with("modules/")
        && path.contains("/commits/");
    !protobuf_commit_bundle
}

/// Outcome of comparing observed bytes with the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityVerdict {
    /// Digest (and, when known, length) match.
    Intact,
    /// The bytes do not hash to the recorded digest, or their length differs.
    Mismatch {
        actual_sha256: String,
        actual_len: u64,
    },
}

/// Compare a finished hash and byte count with the expected digest/length.
/// `expected_len` of `None` skips the length check.
pub fn verdict(
    expected: &[u8; 32],
    expected_len: Option<u64>,
    actual: &[u8],
    actual_len: u64,
) -> IntegrityVerdict {
    let len_ok = expected_len.is_none_or(|l| l == actual_len);
    if len_ok && actual == expected.as_slice() {
        IntegrityVerdict::Intact
    } else {
        IntegrityVerdict::Mismatch {
            actual_sha256: hex::encode(actual),
            actual_len,
        }
    }
}

/// Hash a whole stream to completion, returning `(hex sha256, byte count)`.
/// Memory stays at one chunk; used by the scrub and reindex passes.
pub async fn hash_stream(mut body: BoxStream<'static, Result<Bytes>>) -> Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut len = 0u64;
    while let Some(chunk) = body.next().await {
        let chunk = chunk?;
        len += chunk.len() as u64;
        hasher.update(&chunk);
    }
    Ok((hex::encode(hasher.finalize()), len))
}

struct VerifyState {
    inner: BoxStream<'static, Result<Bytes>>,
    hasher: Sha256,
    len: u64,
    pending: Option<Bytes>,
    done: bool,
    on_mismatch: Option<MismatchHook>,
}

/// Runs once when a streaming verification finds that the bytes do not match
/// their record (#5169). A storage read error or a client that went away
/// before the end is not a mismatch and does not run it.
pub type MismatchHook = Box<dyn FnOnce() + Send + 'static>;

/// Wrap `body` so it is verified against `expected` (and `expected_len`)
/// while streaming.
///
/// Every chunk but the last is passed through as soon as the next one
/// arrives; the last chunk is released only after the end-of-stream digest
/// check passes. On a mismatch the stream yields an [`AppError::Storage`]
/// in place of the final chunk and logs the corruption with `label` (the
/// repository/path the caller is serving) so an operator can find it.
pub fn verify_sha256_stream(
    body: BoxStream<'static, Result<Bytes>>,
    expected: [u8; 32],
    expected_len: Option<u64>,
    label: String,
) -> BoxStream<'static, Result<Bytes>> {
    verify_sha256_stream_with_hook(body, expected, expected_len, label, None)
}

/// [`verify_sha256_stream`] that also runs `on_mismatch` when it aborts the
/// stream over a mismatch.
pub fn verify_sha256_stream_with_hook(
    body: BoxStream<'static, Result<Bytes>>,
    expected: [u8; 32],
    expected_len: Option<u64>,
    label: String,
    on_mismatch: Option<MismatchHook>,
) -> BoxStream<'static, Result<Bytes>> {
    let state = VerifyState {
        inner: body,
        hasher: Sha256::new(),
        len: 0,
        pending: None,
        done: false,
        on_mismatch,
    };
    futures::stream::unfold(state, move |mut st| {
        let label = label.clone();
        async move {
            if st.done {
                return None;
            }
            loop {
                match st.inner.next().await {
                    Some(Ok(chunk)) => {
                        if chunk.is_empty() {
                            continue;
                        }
                        st.hasher.update(&chunk);
                        st.len += chunk.len() as u64;
                        // A stored object LONGER than the record: the
                        // response's Content-Length would cut it to exactly
                        // the recorded size (hyper truncates, and so does a
                        // whole-object range slice), so the end-of-stream
                        // check would never run and a clean prefix would be
                        // served. Fail now, before releasing the held chunk.
                        if expected_len.is_some_and(|l| st.len > l) {
                            st.done = true;
                            st.pending = None;
                            tracing::error!(
                                object = %label,
                                expected_len = ?expected_len,
                                "stored object is longer than its record; aborting response"
                            );
                            if let Some(hook) = st.on_mismatch.take() {
                                hook();
                            }
                            return Some((
                                Err(AppError::Storage(format!(
                                    "stored object for {label} is longer than recorded"
                                ))),
                                st,
                            ));
                        }
                        if let Some(prev) = st.pending.replace(chunk) {
                            return Some((Ok(prev), st));
                        }
                    }
                    Some(Err(e)) => {
                        st.done = true;
                        return Some((Err(e), st));
                    }
                    None => {
                        st.done = true;
                        let actual = std::mem::take(&mut st.hasher).finalize();
                        match verdict(&expected, expected_len, &actual, st.len) {
                            IntegrityVerdict::Intact => {
                                return st.pending.take().map(|last| (Ok(last), st));
                            }
                            IntegrityVerdict::Mismatch {
                                actual_sha256,
                                actual_len,
                            } => {
                                tracing::error!(
                                    object = %label,
                                    expected_sha256 = %hex::encode(expected),
                                    actual_sha256 = %actual_sha256,
                                    expected_len = ?expected_len,
                                    actual_len,
                                    "stored object failed integrity verification on serve; aborting response"
                                );
                                st.pending = None;
                                if let Some(hook) = st.on_mismatch.take() {
                                    hook();
                                }
                                return Some((
                                    Err(AppError::Storage(format!(
                                        "stored object for {label} failed SHA-256 verification"
                                    ))),
                                    st,
                                ));
                            }
                        }
                    }
                }
            }
        }
    })
    .boxed()
}

/// Objects up to this size are verified before the response status is sent
/// (#4323): the body is read and hashed first, so a mismatch is answered with
/// a clean `502` and no byte of the bad object. A larger object is verified
/// while it streams ([`verify_sha256_stream`]); a mismatch there can only
/// abort the transfer, because the `200` and its headers are already on the
/// wire. Memory per serve stays bounded by this value, and memory across all
/// serves by [`serve_verify_buffer_budget`] (#4989).
pub const VERIFY_BEFORE_HEADERS_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// Default ceiling on the TOTAL bytes the before-headers verification buffer
/// may hold across every in-flight serve (#4989). 256 MiB is 64 objects at
/// [`VERIFY_BEFORE_HEADERS_MAX_BYTES`], or thousands of typical package files,
/// and leaves most of the chart's default 2 GiB backend limit to the rest of
/// the process.
pub const DEFAULT_SERVE_VERIFY_BUFFER_BUDGET_BYTES: usize = 256 * 1024 * 1024;

/// Env override for [`DEFAULT_SERVE_VERIFY_BUFFER_BUDGET_BYTES`]. A blank,
/// non-numeric or zero value falls back to the default, and a value too large
/// to represent is clamped; either case logs a warning at startup, as for
/// `AK_PROXY_METADATA_BUDGET_BYTES` (#4881).
pub const SERVE_VERIFY_BUFFER_BUDGET_BYTES_ENV: &str = "AK_SERVE_VERIFY_BUFFER_BUDGET_BYTES";

/// The process-wide budget for the before-headers verification buffer (#4989).
///
/// A buffered serve holds its object in memory until the client has read it,
/// and the request's concurrency permit is released when the handler returns
/// the response, before the body is sent. Without this budget the total was
/// bounded only by how many connections clients kept open, about 4 MiB each,
/// and slow readers on a public repository could hold that anonymously. It is
/// separate from the proxy-metadata budget, whose callers wait for room: a
/// serve here never waits, so it must not take room those callers wait for.
pub fn serve_verify_buffer_budget() -> &'static ByteBudget {
    static BUDGET: std::sync::LazyLock<ByteBudget> = std::sync::LazyLock::new(|| {
        budget_from_env(
            SERVE_VERIFY_BUFFER_BUDGET_BYTES_ENV,
            DEFAULT_SERVE_VERIFY_BUFFER_BUDGET_BYTES,
        )
    });
    &BUDGET
}

/// A reservation of the before-headers verification budget (#4989). The
/// buffered body owns it, so it is given back when the last buffered chunk
/// has been handed out or the body is dropped (sent, or the client went
/// away). Each change is reported as
/// `ak_serve_verify_buffer_bytes_reserved`.
struct VerifyBufferHold {
    budget: &'static ByteBudget,
    /// `Option` so `drop` can release the permit BEFORE it reports: a field
    /// is only dropped after `Drop::drop` returns.
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl VerifyBufferHold {
    /// Reserve `total` bytes, rounded up to whole budget units, or `None` when
    /// the budget cannot hold them now, or ever (a total above the whole
    /// budget, which a reservation would otherwise clamp to the budget and so
    /// under-count). Never waits: a reservation is held for as long as a
    /// client takes to read the body, so waiting would let slow readers stall
    /// every small download.
    fn try_reserve(budget: &'static ByteBudget, total: u64) -> Option<Self> {
        let bytes = usize::try_from(total).unwrap_or(usize::MAX);
        if bytes > budget.total_bytes() {
            return None;
        }
        let permit = budget.try_reserve(bytes)?;
        report_verify_buffer_reserved(budget);
        Some(Self {
            budget,
            permit: Some(permit),
        })
    }
}

impl Drop for VerifyBufferHold {
    fn drop(&mut self) {
        drop(self.permit.take());
        report_verify_buffer_reserved(self.budget);
    }
}

fn report_verify_buffer_reserved(budget: &ByteBudget) {
    crate::services::metrics_service::set_serve_verify_buffer_bytes_reserved(
        budget.total_bytes() - budget.available_bytes(),
    );
}

/// The buffered chunks as a body stream that keeps `hold` until the last
/// chunk has been handed out, or the stream is dropped.
fn held_body(
    held: Vec<Result<Bytes>>,
    hold: VerifyBufferHold,
) -> BoxStream<'static, Result<Bytes>> {
    futures::stream::unfold((held.into_iter(), hold), |(mut chunks, hold)| async move {
        let chunk = chunks.next()?;
        Some((chunk, (chunks, hold)))
    })
    .boxed()
}

/// Stream `body` into `spool` while hashing it. Returns whether the bytes hash
/// to `expected` (and match `expected_len`, when given), with the number of
/// bytes read. Reading stops as soon as the body is longer than `expected_len`,
/// so a body that never ends cannot fill the disk. Memory stays at one chunk. A
/// caller must not use the spool unless this returned `true`.
pub async fn spool_and_verify(
    mut body: BoxStream<'static, Result<Bytes>>,
    spool: &tempfile::NamedTempFile,
    expected: &[u8; 32],
    expected_len: Option<u64>,
) -> Result<(bool, u64)> {
    use tokio::io::AsyncWriteExt;

    let spool_error = |e: std::io::Error| AppError::Storage(format!("spool file: {e}"));
    let mut file = tokio::fs::File::create(spool.path())
        .await
        .map_err(spool_error)?;
    let mut hasher = Sha256::new();
    let mut read = 0u64;
    while let Some(chunk) = body.next().await {
        let chunk = chunk?;
        read += chunk.len() as u64;
        if expected_len.is_some_and(|l| read > l) {
            return Ok((false, read));
        }
        hasher.update(&chunk);
        file.write_all(&chunk).await.map_err(spool_error)?;
    }
    file.flush().await.map_err(spool_error)?;
    let intact =
        verdict(expected, expected_len, &hasher.finalize(), read) == IntegrityVerdict::Intact;
    Ok((intact, read))
}

/// Machine-readable `code` of the `502` a failed verification answers with.
pub const STORED_OBJECT_INTEGRITY_CODE: &str = "STORED_OBJECT_INTEGRITY";

/// Marker in the extensions of a failed-verification response (#4323).
///
/// Virtual-member resolution treats an error from a member as "this member
/// does not have it" unless it is a terminal refusal. A member whose stored
/// bytes failed verification HOLDS the artifact, so falling through to the
/// next member would serve different bytes for the same path and hide the
/// corruption; the marker makes it terminal without also making an
/// upstream's ordinary `502` terminal.
#[derive(Debug, Clone, Copy)]
pub struct IntegrityFailure;

/// Whether `response` is a failed stored-object verification.
pub fn is_integrity_failure(response: &axum::response::Response) -> bool {
    response.extensions().get::<IntegrityFailure>().is_some()
}

/// Whether serve-time verification is on (`DOWNLOAD_VERIFY_CHECKSUMS`,
/// default true), for serve paths that have no `Config` at hand (#4323). Read
/// once, with the exact parse `Config::from_env` uses for
/// `download_verify_checksums`.
pub fn serve_verification_enabled() -> bool {
    static ENABLED: std::sync::LazyLock<bool> = std::sync::LazyLock::new(|| {
        !matches!(
            std::env::var("DOWNLOAD_VERIFY_CHECKSUMS").as_deref(),
            Ok("false" | "0")
        )
    });
    *ENABLED
}

fn integrity_error(label: &str) -> AppError {
    AppError::CodedBadGateway {
        code: STORED_OBJECT_INTEGRITY_CODE,
        message: format!("The stored object for {label} failed integrity verification"),
    }
}

/// The `502` response for a failed verification, carrying [`IntegrityFailure`].
pub fn integrity_failure_response(label: &str) -> axum::response::Response {
    use axum::response::IntoResponse;
    let mut response = integrity_error(label).into_response();
    response.extensions_mut().insert(IntegrityFailure);
    response
}

fn log_mismatch(label: &str, expected: &[u8; 32], expected_len: u64, verdict: &IntegrityVerdict) {
    if let IntegrityVerdict::Mismatch {
        actual_sha256,
        actual_len,
    } = verdict
    {
        tracing::error!(
            object = %label,
            expected_sha256 = %hex::encode(expected),
            actual_sha256 = %actual_sha256,
            expected_len,
            actual_len,
            "stored object failed integrity verification on serve; answering 502"
        );
    }
}

/// Verify `body` against `expected` and `total` for a whole-object serve
/// (#4323). An object of at most [`VERIFY_BEFORE_HEADERS_MAX_BYTES`] is read
/// and checked now: a mismatch is an `Err` carrying the `502`
/// ([`STORED_OBJECT_INTEGRITY_CODE`]) and nothing of the object is served. A
/// larger object is returned wrapped in [`verify_sha256_stream`], and so is a
/// small one when [`serve_verify_buffer_budget`] has no room for it (#4989):
/// it is still never delivered complete if it is corrupt, but the mismatch
/// then aborts the transfer instead of answering `502`.
pub async fn verify_before_serve(
    body: BoxStream<'static, Result<Bytes>>,
    expected: [u8; 32],
    total: u64,
    label: String,
) -> Result<BoxStream<'static, Result<Bytes>>> {
    verify_before_serve_with_hook(body, expected, total, label, None).await
}

/// [`verify_before_serve`] that runs `on_mismatch` if the object ends up
/// verified while streaming and fails there (#5169). A mismatch found before
/// the headers is the returned `Err`, and the hook does not run.
pub async fn verify_before_serve_with_hook(
    body: BoxStream<'static, Result<Bytes>>,
    expected: [u8; 32],
    total: u64,
    label: String,
    on_mismatch: Option<MismatchHook>,
) -> Result<BoxStream<'static, Result<Bytes>>> {
    verify_against_budget(
        serve_verify_buffer_budget(),
        body,
        expected,
        total,
        label,
        on_mismatch,
    )
    .await
}

/// [`verify_before_serve`] against an explicit budget, so a test can exhaust
/// one of its own without touching the process-wide budget other serves use.
#[cfg(test)]
pub(crate) async fn verify_before_serve_with_budget(
    budget: &'static ByteBudget,
    body: BoxStream<'static, Result<Bytes>>,
    expected: [u8; 32],
    total: u64,
    label: String,
) -> Result<BoxStream<'static, Result<Bytes>>> {
    verify_against_budget(budget, body, expected, total, label, None).await
}

async fn verify_against_budget(
    budget: &'static ByteBudget,
    mut body: BoxStream<'static, Result<Bytes>>,
    expected: [u8; 32],
    total: u64,
    label: String,
    on_mismatch: Option<MismatchHook>,
) -> Result<BoxStream<'static, Result<Bytes>>> {
    if total > VERIFY_BEFORE_HEADERS_MAX_BYTES {
        return Ok(verify_sha256_stream_with_hook(
            body,
            expected,
            Some(total),
            label,
            on_mismatch,
        ));
    }
    let Some(hold) = VerifyBufferHold::try_reserve(budget, total) else {
        crate::services::metrics_service::record_serve_verify_buffer_fallback();
        tracing::debug!(
            object = %label,
            total,
            "verification buffer budget has no room; verifying while streaming instead (#4989)"
        );
        return Ok(verify_sha256_stream_with_hook(
            body,
            expected,
            Some(total),
            label,
            on_mismatch,
        ));
    };
    let mut hasher = Sha256::new();
    let mut held = Vec::new();
    let mut len = 0u64;
    while let Some(chunk) = body.next().await {
        let chunk = chunk?;
        len += chunk.len() as u64;
        // Longer than recorded: stop reading, it cannot be intact.
        if len > total {
            break;
        }
        hasher.update(&chunk);
        held.push(Ok(chunk));
    }
    let verdict = if len > total {
        IntegrityVerdict::Mismatch {
            actual_sha256: String::from("(not computed: longer than recorded)"),
            actual_len: len,
        }
    } else {
        verdict(&expected, Some(total), &hasher.finalize(), len)
    };
    if verdict != IntegrityVerdict::Intact {
        log_mismatch(&label, &expected, total, &verdict);
        return Err(integrity_error(&label));
    }
    Ok(held_body(held, hold))
}

/// Verify a stored artifact body on a format-native or virtual-member serve
/// (#4323), from the artifact row's recorded `checksum_sha256`, `path` and
/// `size_bytes`. Unverified (returned as is) when verification is off, the
/// recorded value is not a SHA-256, or the path has the protobuf commit
/// bundle shape whose recorded checksum is not a content digest (the row's
/// format is not known on these paths, so the shape alone decides). A
/// mismatch on a small object is the `502` [`integrity_failure_response`].
pub async fn verify_stored_body(
    body: BoxStream<'static, Result<Bytes>>,
    recorded_sha256: &str,
    path: &str,
    size_bytes: i64,
    label: impl FnOnce() -> String,
) -> std::result::Result<BoxStream<'static, Result<Bytes>>, axum::response::Response> {
    let Some(expected) = stored_body_expectation(recorded_sha256, path) else {
        return Ok(body);
    };
    let label = label();
    verify_before_serve(body, expected, size_bytes.max(0) as u64, label.clone())
        .await
        .map_err(|e| match e {
            AppError::CodedBadGateway {
                code: STORED_OBJECT_INTEGRITY_CODE,
                ..
            } => integrity_failure_response(&label),
            other => {
                use axum::response::IntoResponse;
                other.into_response()
            }
        })
}

/// Buffered sibling of [`verify_stored_body`] for a body already in memory.
#[allow(clippy::result_large_err)]
pub fn verify_stored_bytes(
    bytes: &Bytes,
    recorded_sha256: &str,
    path: &str,
    size_bytes: i64,
    label: impl FnOnce() -> String,
) -> std::result::Result<(), axum::response::Response> {
    let Some(expected) = stored_body_expectation(recorded_sha256, path) else {
        return Ok(());
    };
    let total = size_bytes.max(0) as u64;
    let verdict = verdict(
        &expected,
        Some(total),
        &Sha256::digest(bytes),
        bytes.len() as u64,
    );
    if verdict == IntegrityVerdict::Intact {
        return Ok(());
    }
    let label = label();
    log_mismatch(&label, &expected, total, &verdict);
    Err(integrity_failure_response(&label))
}

fn stored_body_expectation(recorded_sha256: &str, path: &str) -> Option<[u8; 32]> {
    if !serve_verification_enabled() || !checksum_is_content_digest("protobuf", path) {
        return None;
    }
    parse_sha256_hex(recorded_sha256)
}

/// The SHA-256 a response's own headers vouch for (#4323): `X-Checksum-Sha256`
/// or a `sha256:` `Docker-Content-Digest`. `None` when the response declares
/// a `Content-Encoding` (the digest then names the decoded bytes while the
/// body is the coded ones) or carries no SHA-256 digest header.
pub fn advertised_sha256(headers: &[(axum::http::HeaderName, String)]) -> Option<[u8; 32]> {
    use axum::http::header::CONTENT_ENCODING;
    if headers.iter().any(|(name, _)| name == CONTENT_ENCODING) {
        return None;
    }
    headers
        .iter()
        .find_map(|(name, value)| match name.as_str() {
            "x-checksum-sha256" => parse_sha256_hex(value),
            "docker-content-digest" => value
                .trim()
                .strip_prefix("sha256:")
                .and_then(parse_sha256_hex),
            _ => None,
        })
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    fn sha(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    fn chunks(parts: &[&'static [u8]]) -> BoxStream<'static, Result<Bytes>> {
        let v: Vec<Result<Bytes>> = parts.iter().map(|p| Ok(Bytes::from_static(p))).collect();
        futures::stream::iter(v).boxed()
    }

    async fn collect(s: BoxStream<'static, Result<Bytes>>) -> (Vec<u8>, Option<AppError>) {
        let mut out = Vec::new();
        let mut s = s;
        while let Some(item) = s.next().await {
            match item {
                Ok(b) => out.extend_from_slice(&b),
                Err(e) => return (out, Some(e)),
            }
        }
        (out, None)
    }

    #[test]
    fn parse_sha256_hex_accepts_only_64_hex() {
        let hex64 = "ab".repeat(32);
        assert!(parse_sha256_hex(&hex64).is_some());
        assert!(parse_sha256_hex(&format!("{hex64}   ")).is_some());
        assert!(parse_sha256_hex(&format!("sha256:{hex64}")).is_some());
        assert!(parse_sha256_hex("test-seed").is_none());
        assert!(parse_sha256_hex(&"g".repeat(64)).is_none());
        assert!(parse_sha256_hex("").is_none());
    }

    #[tokio::test]
    async fn intact_stream_passes_all_bytes_through() {
        let expected = sha(b"hello world");
        let s = verify_sha256_stream(
            chunks(&[b"hello", b"", b" ", b"world"]),
            expected,
            Some(11),
            "t".into(),
        );
        let (bytes, err) = collect(s).await;
        assert!(err.is_none());
        assert_eq!(bytes, b"hello world");
    }

    /// #3919: a corrupted object must never be delivered in full. The final
    /// chunk is withheld and the stream ends in an error instead.
    #[tokio::test]
    async fn corrupted_stream_withholds_last_chunk_and_errors() {
        let expected = sha(b"hello world");
        let s = verify_sha256_stream(
            chunks(&[b"hello", b" ", b"worlD"]),
            expected,
            Some(11),
            "t".into(),
        );
        let (bytes, err) = collect(s).await;
        assert!(matches!(err, Some(AppError::Storage(_))), "got {err:?}");
        assert_eq!(bytes, b"hello ", "the last chunk must be withheld");
    }

    fn counting_hook() -> (std::sync::Arc<std::sync::atomic::AtomicUsize>, MismatchHook) {
        let ran = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = ran.clone();
        let hook: MismatchHook = Box::new(move || {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        (ran, hook)
    }

    /// #5169: the hook is how a Remote learns that a transfer it could only
    /// abort found corruption, for a digest mismatch and for an overlong
    /// object alike, and for nothing else.
    #[tokio::test]
    async fn mismatch_hook_runs_once_on_a_mismatch_only_5169() {
        let digest = sha(b"abc");
        let hook_runs = |body: BoxStream<'static, Result<Bytes>>| async move {
            let (ran, hook) = counting_hook();
            let s = verify_sha256_stream_with_hook(body, digest, Some(3), "t".into(), Some(hook));
            collect(s).await;
            ran.load(std::sync::atomic::Ordering::SeqCst)
        };
        assert_eq!(hook_runs(chunks(&[b"abd"])).await, 1, "wrong bytes");
        assert_eq!(hook_runs(chunks(&[b"ab"])).await, 1, "short");
        assert_eq!(hook_runs(chunks(&[b"abc", b"d"])).await, 1, "long");
        assert_eq!(hook_runs(chunks(&[b"a", b"bc"])).await, 0, "intact");
        let read_error = futures::stream::iter(vec![Err(AppError::Storage("io".into()))]).boxed();
        assert_eq!(hook_runs(read_error).await, 0, "a read error");
    }

    /// #5169: above the before-headers limit the hook reaches the streaming
    /// verifier; a mismatch found before the headers is the `Err` instead.
    #[tokio::test]
    async fn verify_before_serve_hands_the_hook_to_the_streaming_verifier_5169() {
        let (ran, hook) = counting_hook();
        let err = verify_before_serve_with_hook(
            chunks(&[b"abd"]),
            sha(b"abc"),
            3,
            "t".into(),
            Some(hook),
        )
        .await;
        assert!(err.is_err());
        assert_eq!(ran.load(std::sync::atomic::Ordering::SeqCst), 0);

        let (ran, hook) = counting_hook();
        let total = VERIFY_BEFORE_HEADERS_MAX_BYTES + 1;
        let s = verify_before_serve_with_hook(
            chunks(&[b"x"]),
            sha(b"x"),
            total,
            "t".into(),
            Some(hook),
        )
        .await
        .expect("streamed, not checked yet");
        collect(s).await;
        assert_eq!(ran.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// #5169: the spool says yes only for the exact bytes, and stops reading a
    /// body that outgrows the record.
    #[tokio::test]
    async fn spool_and_verify_accepts_only_the_exact_bytes_5169() {
        let spool = tempfile::NamedTempFile::new().unwrap();
        let expected = sha(b"abc");
        let (ok, read) = spool_and_verify(chunks(&[b"a", b"bc"]), &spool, &expected, Some(3))
            .await
            .unwrap();
        assert!(ok);
        assert_eq!(read, 3);
        assert_eq!(std::fs::read(spool.path()).unwrap(), b"abc");

        for (body, what) in [
            (chunks(&[b"abd"]), "wrong bytes"),
            (chunks(&[b"ab"]), "short"),
            (chunks(&[b"abc", b"d"]), "long"),
        ] {
            let spool = tempfile::NamedTempFile::new().unwrap();
            let (ok, _) = spool_and_verify(body, &spool, &expected, Some(3))
                .await
                .unwrap();
            assert!(!ok, "{what}");
        }

        // Without a recorded length only the digest decides.
        let spool = tempfile::NamedTempFile::new().unwrap();
        let (ok, read) = spool_and_verify(chunks(&[b"abc"]), &spool, &expected, None)
            .await
            .unwrap();
        assert!(ok);
        assert_eq!(read, 3);

        let spool = tempfile::NamedTempFile::new().unwrap();
        let failing = futures::stream::iter(vec![Err(AppError::Storage("io".into()))]).boxed();
        assert!(spool_and_verify(failing, &spool, &expected, None)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn single_chunk_corruption_delivers_nothing() {
        let expected = sha(b"abc");
        let s = verify_sha256_stream(chunks(&[b"abd"]), expected, None, "t".into());
        let (bytes, err) = collect(s).await;
        assert!(err.is_some());
        assert!(bytes.is_empty());
    }

    #[tokio::test]
    async fn truncated_stream_fails_on_length() {
        let expected = sha(b"abc");
        let s = verify_sha256_stream(chunks(&[b"ab"]), expected, Some(3), "t".into());
        assert!(collect(s).await.1.is_some());
    }

    #[tokio::test]
    async fn empty_object_verifies() {
        let expected = sha(b"");
        let s = verify_sha256_stream(chunks(&[]), expected, Some(0), "t".into());
        let (bytes, err) = collect(s).await;
        assert!(err.is_none());
        assert!(bytes.is_empty());
    }

    #[tokio::test]
    async fn inner_error_is_propagated() {
        let v: Vec<Result<Bytes>> = vec![
            Ok(Bytes::from_static(b"a")),
            Err(AppError::Storage("boom".into())),
        ];
        let s = verify_sha256_stream(
            futures::stream::iter(v).boxed(),
            sha(b"a"),
            None,
            "t".into(),
        );
        let (_, err) = collect(s).await;
        assert!(matches!(err, Some(AppError::Storage(m)) if m == "boom"));
    }

    #[tokio::test]
    async fn hash_stream_reports_digest_and_len() {
        let (hex, len) = hash_stream(chunks(&[b"hello", b" world"])).await.unwrap();
        assert_eq!(hex, hex::encode(sha(b"hello world")));
        assert_eq!(len, 11);
    }

    #[test]
    fn protobuf_commit_bundles_are_not_content_digests() {
        assert!(!checksum_is_content_digest(
            "protobuf",
            "modules/acme/widgets/commits/abc"
        ));
        assert!(checksum_is_content_digest(
            "protobuf",
            "acme/widgets/_labels"
        ));
        assert!(checksum_is_content_digest("generic", "modules/a/commits/b"));
        assert!(checksum_is_content_digest("maven", "com/x/1.0/x-1.0.jar"));
    }

    /// #3919 review (S-a): an object LONGER than the record, whose first N
    /// bytes are corrupt, must not be delivered as N bytes and a clean end.
    #[tokio::test]
    async fn longer_object_with_corrupt_prefix_errors_before_n_bytes() {
        let expected = sha(b"abcdef");
        let s = verify_sha256_stream(
            chunks(&[b"abcdeX", b"extra"]),
            expected,
            Some(6),
            "t".into(),
        );
        let (bytes, err) = collect(s).await;
        assert!(err.is_some());
        assert!(bytes.len() < 6, "delivered {} bytes", bytes.len());
    }

    /// Same with a CORRECT prefix: the recorded length is exceeded, so the
    /// object is not what was recorded, even though a truncated read would
    /// hash correctly.
    #[tokio::test]
    async fn longer_object_with_correct_prefix_errors_before_n_bytes() {
        let expected = sha(b"abcdef");
        let s = verify_sha256_stream(
            chunks(&[b"abc", b"def", b"tail"]),
            expected,
            Some(6),
            "t".into(),
        );
        let (bytes, err) = collect(s).await;
        assert!(matches!(err, Some(AppError::Storage(_))), "{err:?}");
        assert!(bytes.len() < 6, "delivered {} bytes", bytes.len());
    }

    /// Longer object inside a single chunk.
    #[tokio::test]
    async fn longer_object_single_chunk_delivers_nothing() {
        let expected = sha(b"abc");
        let s = verify_sha256_stream(chunks(&[b"abcd"]), expected, Some(3), "t".into());
        let (bytes, err) = collect(s).await;
        assert!(err.is_some());
        assert!(bytes.is_empty());
    }

    #[test]
    fn verdict_reports_mismatch_details() {
        let e = sha(b"x");
        assert_eq!(verdict(&e, Some(1), &e, 1), IntegrityVerdict::Intact);
        assert!(matches!(
            verdict(&e, Some(2), &e, 1),
            IntegrityVerdict::Mismatch { actual_len: 1, .. }
        ));
    }
    /// #4323: a small object is checked before anything is served, so a
    /// mismatch is an error (the route's 502), not a stream cut short.
    #[tokio::test]
    async fn verify_before_serve_refuses_a_small_mismatch_up_front() {
        let err = verify_before_serve(chunks(&[b"abd"]), sha(b"abc"), 3, "t".into())
            .await
            .err()
            .expect("mismatch");
        assert!(
            matches!(
                err,
                AppError::CodedBadGateway {
                    code: STORED_OBJECT_INTEGRITY_CODE,
                    ..
                }
            ),
            "{err:?}"
        );
        let longer = verify_before_serve(chunks(&[b"abc", b"d"]), sha(b"abc"), 3, "t".into()).await;
        assert!(longer.is_err(), "longer than recorded");
        let shorter = verify_before_serve(chunks(&[b"ab"]), sha(b"abc"), 3, "t".into()).await;
        assert!(shorter.is_err(), "shorter than recorded");
        let ok = verify_before_serve(chunks(&[b"a", b"bc"]), sha(b"abc"), 3, "t".into())
            .await
            .expect("intact");
        let (bytes, err) = collect(ok).await;
        assert!(err.is_none());
        assert_eq!(bytes, b"abc");
    }

    /// Above the limit the object streams through the streaming verifier.
    #[tokio::test]
    async fn verify_before_serve_streams_a_large_object() {
        let total = VERIFY_BEFORE_HEADERS_MAX_BYTES + 1;
        let s = verify_before_serve(chunks(&[b"x"]), sha(b"x"), total, "t".into())
            .await
            .expect("large objects are not read up front");
        assert!(collect(s).await.1.is_some(), "and still fail at the end");
    }

    #[test]
    fn advertised_sha256_reads_the_digest_headers() {
        use axum::http::{header::CONTENT_ENCODING, HeaderName};
        let hex = "ab".repeat(32);
        let x = HeaderName::from_static("x-checksum-sha256");
        let d = HeaderName::from_static("docker-content-digest");
        assert!(advertised_sha256(&[(x.clone(), hex.clone())]).is_some());
        assert!(advertised_sha256(&[(d.clone(), format!("sha256:{hex}"))]).is_some());
        assert!(advertised_sha256(&[(d.clone(), format!("sha512:{hex}"))]).is_none());
        assert!(
            advertised_sha256(&[(x, hex), (CONTENT_ENCODING, "gzip".into())]).is_none(),
            "a coded body is not what the digest names"
        );
    }

    #[test]
    fn integrity_failure_response_is_marked() {
        let r = integrity_failure_response("repo/path");
        assert_eq!(r.status(), axum::http::StatusCode::BAD_GATEWAY);
        assert!(is_integrity_failure(&r));
    }

    // -----------------------------------------------------------------------
    // #4989: the before-headers buffer draws on one process-wide budget.
    // Every test uses a budget of its own (leaked, so it is `'static` like the
    // global), never the global: exhausting that would turn other tests'
    // up-front 502s into aborted transfers.
    // -----------------------------------------------------------------------

    use crate::util::byte_budget::BYTE_BUDGET_UNIT_BYTES as UNIT;

    fn leaked_budget(bytes: usize) -> &'static ByteBudget {
        Box::leak(Box::new(ByteBudget::new(bytes)))
    }

    /// A buffered serve reserves its size rounded up to whole units (not the
    /// 4 MiB ceiling), holds it while the body is unread, and gives it back
    /// once the body has been read to the end.
    #[tokio::test]
    async fn buffered_serve_reserves_its_size_until_the_body_is_read() {
        let budget = leaked_budget(4 * UNIT);
        let object = vec![7u8; 1024];
        let body = futures::stream::iter(vec![Ok(Bytes::from(object.clone()))]).boxed();
        let served = verify_before_serve_with_budget(budget, body, sha(&object), 1024, "t".into())
            .await
            .expect("intact");
        assert_eq!(
            budget.available_bytes(),
            3 * UNIT,
            "a 1 KiB object reserves one 4 KiB unit, not the ceiling"
        );
        let (bytes, err) = collect(served).await;
        assert!(err.is_none());
        assert_eq!(bytes, object);
        assert_eq!(budget.available_bytes(), 4 * UNIT, "released once read");
    }

    /// A client that goes away before reading the body still gives the
    /// reservation back, when the body is dropped.
    #[tokio::test]
    async fn dropped_body_releases_its_reservation() {
        let budget = leaked_budget(2 * UNIT);
        let served =
            verify_before_serve_with_budget(budget, chunks(&[b"abc"]), sha(b"abc"), 3, "t".into())
                .await
                .expect("intact");
        assert_eq!(budget.available_bytes(), UNIT);
        drop(served);
        assert_eq!(budget.available_bytes(), 2 * UNIT);
    }

    /// A zero-byte object reserves the one unit a reservation is rounded up
    /// to, and releases it like any other.
    #[tokio::test]
    async fn empty_object_reserves_one_unit_and_releases_it() {
        let budget = leaked_budget(UNIT);
        let served = verify_before_serve_with_budget(budget, chunks(&[]), sha(b""), 0, "t".into())
            .await
            .expect("intact");
        assert_eq!(budget.available_bytes(), 0);
        let (bytes, err) = collect(served).await;
        assert!(bytes.is_empty() && err.is_none());
        assert_eq!(budget.available_bytes(), UNIT);
    }

    /// A mismatch found while buffering is still the up-front 502, and the
    /// reservation does not outlive the refusal.
    #[tokio::test]
    async fn buffered_mismatch_refuses_and_releases() {
        let budget = leaked_budget(2 * UNIT);
        let err =
            verify_before_serve_with_budget(budget, chunks(&[b"abd"]), sha(b"abc"), 3, "t".into())
                .await
                .err()
                .expect("mismatch");
        assert!(
            matches!(
                err,
                AppError::CodedBadGateway {
                    code: STORED_OBJECT_INTEGRITY_CODE,
                    ..
                }
            ),
            "{err:?}"
        );
        assert_eq!(budget.available_bytes(), 2 * UNIT);
    }

    /// With the budget exhausted a small object is NOT buffered: it streams
    /// through the streaming verifier, which still serves intact bytes and
    /// still never completes a corrupt body. The mismatch now ends the stream
    /// instead of failing up front.
    #[tokio::test]
    async fn exhausted_budget_streams_instead_of_buffering() {
        let budget = leaked_budget(UNIT);
        let _occupied = budget.try_reserve(UNIT).expect("take the whole budget");

        let intact = verify_before_serve_with_budget(
            budget,
            chunks(&[b"a", b"bc"]),
            sha(b"abc"),
            3,
            "t".into(),
        )
        .await
        .expect("no budget is no reason to refuse");
        {
            let (bytes, err) = collect(intact).await;
            assert!(err.is_none(), "{err:?}");
            assert_eq!(bytes, b"abc".to_vec());
        }

        let corrupt = verify_before_serve_with_budget(
            budget,
            chunks(&[b"a", b"bd"]),
            sha(b"abc"),
            3,
            "t".into(),
        )
        .await
        .expect("without a buffer the mismatch is only known at the end");
        let (bytes, err) = collect(corrupt).await;
        assert!(err.is_some(), "a corrupt body is never completed");
        assert_eq!(bytes, b"a", "the last chunk is withheld");
        assert_eq!(
            budget.available_bytes(),
            0,
            "nothing reserved for the streamed serves"
        );
    }

    /// An object larger than the whole budget streams: a reservation would be
    /// clamped to the budget and under-count what is buffered.
    #[tokio::test]
    async fn object_larger_than_the_budget_streams() {
        let budget = leaked_budget(UNIT);
        let object = vec![1u8; 2 * UNIT];
        let body = futures::stream::iter(vec![Ok(Bytes::from(object.clone()))]).boxed();
        let served = verify_before_serve_with_budget(
            budget,
            body,
            sha(&object),
            object.len() as u64,
            "t".into(),
        )
        .await
        .expect("streams");
        assert_eq!(budget.available_bytes(), UNIT, "never reserved");
        {
            let (bytes, err) = collect(served).await;
            assert!(err.is_none(), "{err:?}");
            assert_eq!(bytes, object);
        }
    }

    /// The env override follows the shared rules with its own default.
    #[test]
    fn serve_verify_budget_resolves_with_its_own_default() {
        use crate::util::byte_budget::resolve_budget_bytes;
        let default = DEFAULT_SERVE_VERIFY_BUFFER_BUDGET_BYTES;
        assert_eq!(resolve_budget_bytes(None, default), (default, None));
        assert_eq!(
            resolve_budget_bytes(Some("8388608"), default),
            (8_388_608, None)
        );
        for junk in ["", "   ", "0", "lots"] {
            let (bytes, reason) = resolve_budget_bytes(Some(junk), default);
            assert_eq!(bytes, default, "{junk:?}");
            assert!(reason.is_some(), "{junk:?} is reported");
        }
        assert!(serve_verify_buffer_budget().total_bytes() > 0);
    }
}
