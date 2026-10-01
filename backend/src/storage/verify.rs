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
}

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
    let state = VerifyState {
        inner: body,
        hasher: Sha256::new(),
        len: 0,
        pending: None,
        done: false,
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
}
