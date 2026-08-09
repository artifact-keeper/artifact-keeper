//! Bounded stripping of an HTTP **content coding** from a buffered proxied
//! body, for the handlers that have to *parse* upstream bytes.
//!
//! # Why this exists
//!
//! `http_client::base_client_builder` disables reqwest's transparent
//! decompression (`no_gzip`/`no_brotli`/`no_deflate`/`no_zstd`) so a proxied
//! `Content-Length` survives intact. The consequence is that every buffered
//! upstream body now arrives **still coded** whenever the upstream declared a
//! coding — and object stores (notably S3) return a *stored* `Content-Encoding`
//! regardless of what the request's `Accept-Encoding` advertised, so this is
//! reachable even though the shared client asks for `identity`.
//!
//! That splits proxy callers into two kinds, and they need opposite treatment:
//!
//! * a caller that forwards the buffered bytes **verbatim** must re-declare the
//!   upstream coding on its own response (#3149 / #3176 / #3184). It must NOT
//!   use this module — decoding on the client's behalf would also invalidate
//!   the `Content-Length` it copies from `bytes.len()`.
//! * a caller that **parses or transforms** the buffered bytes (a zip/tar
//!   walker, a JSON or index parser) sees compressed bytes where it expects the
//!   payload format, and fails. Forwarding a header does nothing for it; it has
//!   to decode *before* it parses. That is what this module is for (#3193).
//!
//! # Bounding
//!
//! The input is attacker-influenceable upstream data, so every decode runs
//! through [`bounded_archive::read_capped`] against the shared ingest
//! decompressed-byte budget ([`bounded_archive::max_ingest_decompressed_bytes`],
//! 128 MiB by default and env-tunable). A coded body that inflates past the
//! budget is rejected as a suspected decompression bomb rather than buffered.
//! Callers should additionally hold an ingest-extraction permit
//! ([`bounded_archive::with_ingest_extraction`]) around the decode + parse pair
//! so the CPU cost is admission-controlled like every other serve-time
//! extraction.

use std::borrow::Cow;

use crate::error::{AppError, Result};
use crate::util::bounded_archive;

/// What was made of a (possibly) content-coded body.
///
/// The `Unsupported` arm is deliberately not an `Err`: "the upstream used a
/// coding this build cannot strip" is a different decision for each caller than
/// "the stream is corrupt or is a bomb", and collapsing the two would force
/// every caller into the same status code. See the PyPI wheel-extraction
/// fallback, which degrades an unsupported coding to its existing
/// "metadata not available" answer (a client can recover from that by fetching
/// the wheel itself) rather than to a hard upstream error.
#[derive(Debug)]
pub enum Decoded<'a> {
    /// Bytes that are safe to hand to a parser: either the body was already
    /// identity-coded (borrowed unchanged) or it was successfully decoded.
    Bytes(Cow<'a, [u8]>),
    /// The upstream declared a coding this build has no decoder for — `br` is
    /// the live example, since no brotli decoder is linked in. The caller must
    /// NOT parse the bytes: they are still compressed.
    Unsupported,
}

/// Strip the content coding named by `coding` off `body`.
///
/// `coding` is the raw upstream `Content-Encoding` header value, so it may name
/// several codings applied in order (`gzip, deflate` means deflate was applied
/// first, then gzip); they are stripped right-to-left, as RFC 9110 §8.4
/// requires. `None`, an empty value, and `identity` all borrow the body
/// unchanged and never allocate.
///
/// Returns `Err` when a coding this module *does* support fails to decode — a
/// truncated or corrupt stream, or one that inflates past the shared
/// decompression budget.
pub fn strip_content_coding<'a>(body: &'a [u8], coding: Option<&str>) -> Result<Decoded<'a>> {
    strip_content_coding_to(
        body,
        coding,
        bounded_archive::max_ingest_decompressed_bytes(),
    )
}

/// Like [`strip_content_coding`] but with an explicit decompressed-byte budget,
/// mirroring [`bounded_archive::budgeted_to`]. Exists so the bomb-rejection
/// tests can drive a tiny budget against a tiny fixture instead of mutating a
/// process-global env var, which would race every other test in the binary.
pub fn strip_content_coding_to<'a>(
    body: &'a [u8],
    coding: Option<&str>,
    budget: u64,
) -> Result<Decoded<'a>> {
    let Some(coding) = coding else {
        return Ok(Decoded::Bytes(Cow::Borrowed(body)));
    };

    let tokens: Vec<&str> = coding
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty() && !t.eq_ignore_ascii_case("identity"))
        .collect();
    if tokens.is_empty() {
        return Ok(Decoded::Bytes(Cow::Borrowed(body)));
    }
    if !tokens.iter().all(|t| is_supported_token(t)) {
        return Ok(Decoded::Unsupported);
    }

    // Applied in the order listed, so they come off in reverse.
    let mut current = Cow::Borrowed(body);
    for token in tokens.iter().rev() {
        current = Cow::Owned(strip_one(&current, token, budget)?);
    }
    Ok(Decoded::Bytes(current))
}

/// Whether this build can strip `token`. Kept private so it cannot drift out of
/// step with [`strip_one`]'s match — the two are checked against each other by
/// `test_supported_tokens_all_decode`.
fn is_supported_token(token: &str) -> bool {
    matches!(
        token.to_ascii_lowercase().as_str(),
        "gzip" | "x-gzip" | "deflate" | "zstd"
    )
}

fn strip_one(body: &[u8], token: &str, cap: u64) -> Result<Vec<u8>> {
    let what = "content-coded upstream body";
    match token.to_ascii_lowercase().as_str() {
        "gzip" | "x-gzip" => {
            bounded_archive::read_capped(flate2::read::GzDecoder::new(body), cap, what)
        }
        // RFC 9110 defines `deflate` as the zlib wrapper, but a long tail of
        // servers emits RAW deflate under the same token and every browser
        // accepts both, so a proxy that only handled one would reject bodies
        // its own clients would have decoded. Sniff the zlib header to choose
        // which to try first, then fall back to the other; the *first*
        // attempt's error is the one reported, so a genuine budget breach is
        // not masked by the fallback's "invalid stream".
        "deflate" => {
            type Inflate = fn(&[u8], u64, &str) -> Result<Vec<u8>>;
            let (first, second): (Inflate, Inflate) = if looks_like_zlib(body) {
                (inflate_zlib, inflate_raw_deflate)
            } else {
                (inflate_raw_deflate, inflate_zlib)
            };
            first(body, cap, what).or_else(|primary| second(body, cap, what).map_err(|_| primary))
        }
        "zstd" => bounded_archive::read_capped(
            zstd::stream::read::Decoder::new(body)
                .map_err(|e| AppError::BadGateway(format!("Invalid zstd upstream body: {e}")))?,
            cap,
            what,
        ),
        // Unreachable: `strip_content_coding` returns `Unsupported` before
        // calling this for anything `is_supported_token` rejects.
        other => Err(AppError::BadGateway(format!(
            "Unsupported upstream content coding: {other}"
        ))),
    }
}

fn inflate_zlib(body: &[u8], cap: u64, what: &str) -> Result<Vec<u8>> {
    bounded_archive::read_capped(flate2::read::ZlibDecoder::new(body), cap, what)
}

fn inflate_raw_deflate(body: &[u8], cap: u64, what: &str) -> Result<Vec<u8>> {
    bounded_archive::read_capped(flate2::read::DeflateDecoder::new(body), cap, what)
}

/// RFC 1950 §2.2: a zlib stream starts with CMF/FLG where the compression
/// method (low nibble of CMF) is 8 and the two bytes together are a multiple
/// of 31. Raw deflate can coincidentally satisfy this, which is why this only
/// *orders* the two attempts rather than deciding between them.
fn looks_like_zlib(body: &[u8]) -> bool {
    body.len() >= 2
        && body[0] & 0x0f == 0x08
        && (u16::from(body[0]) << 8 | u16::from(body[1])) % 31 == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn gzip(plain: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(plain).unwrap();
        e.finish().unwrap()
    }

    fn raw_deflate(plain: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(plain).unwrap();
        e.finish().unwrap()
    }

    fn zlib(plain: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(plain).unwrap();
        e.finish().unwrap()
    }

    fn bytes(d: Decoded<'_>) -> Vec<u8> {
        match d {
            Decoded::Bytes(b) => b.into_owned(),
            Decoded::Unsupported => panic!("expected a decoded body, got Unsupported"),
        }
    }

    #[test]
    fn test_identity_and_absent_coding_pass_through() {
        let body = b"PK\x03\x04not-coded";
        assert_eq!(bytes(strip_content_coding(body, None).unwrap()), body);
        assert_eq!(bytes(strip_content_coding(body, Some("")).unwrap()), body);
        assert_eq!(
            bytes(strip_content_coding(body, Some("identity")).unwrap()),
            body
        );
    }

    /// The coding actually in play must decide the decoder. Every arm here is
    /// checked against a DIFFERENT encoder's output so a decoder hardcoded to
    /// one coding cannot pass.
    #[test]
    fn test_supported_tokens_all_decode() {
        let plain = b"payload-".repeat(64);
        for (token, coded) in [
            ("gzip", gzip(&plain)),
            ("x-gzip", gzip(&plain)),
            ("deflate", raw_deflate(&plain)),
            ("zstd", zstd::encode_all(&plain[..], 3).unwrap()),
        ] {
            assert!(is_supported_token(token), "{token} must be advertised");
            assert_eq!(
                bytes(strip_content_coding(&coded, Some(token)).unwrap()),
                plain,
                "{token} body must decode to the plaintext"
            );
        }
    }

    /// `deflate` covers both the RFC's zlib wrapper and the raw form real
    /// servers emit. Both must work under the single token.
    #[test]
    fn test_deflate_accepts_both_zlib_wrapped_and_raw() {
        let plain = b"deflate-both-forms-".repeat(64);
        assert_eq!(
            bytes(strip_content_coding(&zlib(&plain), Some("deflate")).unwrap()),
            plain
        );
        assert_eq!(
            bytes(strip_content_coding(&raw_deflate(&plain), Some("deflate")).unwrap()),
            plain
        );
    }

    #[test]
    fn test_case_insensitive_and_whitespace_tolerant() {
        let plain = b"case-".repeat(64);
        assert_eq!(
            bytes(strip_content_coding(&gzip(&plain), Some("  GZip ")).unwrap()),
            plain
        );
    }

    /// Multiple codings come off in reverse application order (RFC 9110 §8.4).
    #[test]
    fn test_layered_codings_are_stripped_right_to_left() {
        let plain = b"layered-".repeat(64);
        let coded = gzip(&raw_deflate(&plain));
        assert_eq!(
            bytes(strip_content_coding(&coded, Some("deflate, gzip")).unwrap()),
            plain
        );
    }

    /// `br` is the live unsupported case (no brotli decoder is linked in). It
    /// must be reported as `Unsupported`, NOT as an error and above all not as
    /// a successful "decode" of still-compressed bytes.
    #[test]
    fn test_unsupported_coding_is_reported_not_silently_passed_through() {
        let body = b"\x1b\x0e\x00brotli-ish";
        assert!(matches!(
            strip_content_coding(body, Some("br")).unwrap(),
            Decoded::Unsupported
        ));
        // A layered list is unsupported if ANY member is: stripping only the
        // outer gzip would still leave a brotli payload behind.
        assert!(matches!(
            strip_content_coding(body, Some("br, gzip")).unwrap(),
            Decoded::Unsupported
        ));
    }

    #[test]
    fn test_corrupt_stream_is_an_error_not_a_silent_passthrough() {
        let err = strip_content_coding(b"not-actually-gzip-at-all", Some("gzip"))
            .expect_err("a corrupt gzip stream must not decode");
        assert!(
            matches!(err, AppError::Validation(_)),
            "unexpected error shape: {err:?}"
        );
    }

    /// A decompression bomb must be rejected by the budget rather than
    /// buffered. The input here is upstream-controlled, so an unbounded decode
    /// would be a remote memory-exhaustion primitive on the serve path.
    #[test]
    fn test_bomb_is_rejected_by_the_budget() {
        let plain = vec![0u8; 4 * 1024 * 1024];
        let coded = gzip(&plain);
        assert!(
            coded.len() < 64 * 1024,
            "fixture must actually amplify or the test proves nothing"
        );
        assert!(
            strip_content_coding_to(&coded, Some("gzip"), 4096).is_err(),
            "a body inflating past the budget must be rejected, not buffered"
        );
        // ...and the same fixture decodes fine under a budget that fits it, so
        // the rejection above is the budget and not a broken fixture.
        assert_eq!(
            bytes(strip_content_coding_to(&coded, Some("gzip"), 8 * 1024 * 1024).unwrap()).len(),
            plain.len()
        );
    }
}
