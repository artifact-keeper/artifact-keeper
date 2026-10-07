//! OCI content-addressable digest helpers (#1425).
//!
//! Pure functions shared by the OCI Distribution handlers in
//! [`super::oci_v2`] and the OCI migration reindex service: computing the
//! canonical `sha256:<hex>` digest of a byte slice, recognising a digest
//! reference (as opposed to a tag), and the virtual-repo resolver's
//! "verify the served bytes or fall through to the next member" decision.

use sha2::{Digest, Sha256};

pub(crate) fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("sha256:{:x}", hasher.finalize())
}

/// Check whether `reference` looks like an OCI content-addressable digest
/// rather than a human-readable tag. The grammar (from the OCI Distribution
/// Spec) is:
///
/// ```text
/// digest    ::= algorithm ":" encoded
/// algorithm ::= [a-z0-9]([a-z0-9._+-]*[a-z0-9])?
/// encoded   ::= [a-zA-Z0-9=_-]+
/// ```
pub(crate) fn is_digest_reference(reference: &str) -> bool {
    let Some((algorithm, encoded)) = reference.split_once(':') else {
        return false;
    };

    // OCI spec: algorithm = `[a-z0-9]+([+._-][a-z0-9]+)*` (lowercase only)
    !algorithm.is_empty()
        && !encoded.is_empty()
        && algorithm.chars().all(|ch| {
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '_' | '+' | '.' | '-')
        })
        && encoded
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '=' | '_' | '-'))
}

/// Pure decision: given a requested `digest` reference and the actual
/// `content` bytes served by an upstream, decide whether to *reject* the
/// response on a digest mismatch.
///
/// Returns `true` only when (a) the requested reference is itself a
/// content-addressable digest, and (b) the SHA-256 of the served bytes
/// does not match it. Tags and other non-digest references always return
/// `false` (nothing to compare against).
///
/// Extracted out of `resolve_virtual_blob` / `resolve_virtual_manifest`
/// for unit-test coverage of the #1348 round-1 security fix without
/// having to stand up a wiremock upstream.
fn upstream_content_violates_digest(reference: &str, content: &[u8]) -> bool {
    is_digest_reference(reference) && compute_sha256(content) != reference
}

/// Positive-sense counterpart to [`upstream_content_violates_digest`].
///
/// Returns `true` when the served `content` is acceptable to forward to the
/// client: either the reference is a human-readable tag (no digest to
/// verify against) or the SHA-256 of the bytes matches the requested
/// content-addressable digest. Returns `false` only on a true digest
/// mismatch, in which case the caller must "fall through" to the next
/// virtual-repo member (or surface a 404).
///
/// Reads at call sites as
/// `if !verify_digest_or_fall_through(content, reference) { continue }`,
/// matching the resolver's existing control flow without the double
/// negative of the older `if upstream_content_violates_digest(..)` form.
/// Kept as a thin wrapper instead of replacing the original so existing
/// call sites + their tests stay stable.
pub(crate) fn verify_digest_or_fall_through(content: &[u8], reference: &str) -> bool {
    !upstream_content_violates_digest(reference, content)
}

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // compute_sha256
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_sha256_empty() {
        let hash = compute_sha256(b"");
        assert!(hash.starts_with("sha256:"));
        // SHA256 of empty string is a well-known value
        assert_eq!(
            hash,
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_compute_sha256_hello_world() {
        let hash = compute_sha256(b"hello world");
        assert!(hash.starts_with("sha256:"));
        assert_eq!(
            hash,
            "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_compute_sha256_deterministic() {
        let h1 = compute_sha256(b"test data");
        let h2 = compute_sha256(b"test data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_compute_sha256_different_data() {
        let h1 = compute_sha256(b"data1");
        let h2 = compute_sha256(b"data2");
        assert_ne!(h1, h2);
    }
    #[test]
    fn test_is_digest_reference_accepts_sha256_reference() {
        assert!(is_digest_reference(
            "sha256:4d3f1c5bcf9f2f7e4a3e2d1c0b9a887766554433221100ffeeddccbbaa998877"
        ));
    }

    #[test]
    fn test_is_digest_reference_accepts_non_hex_encoded() {
        // OCI spec allows [a-zA-Z0-9=_-]+ in the encoded part
        assert!(is_digest_reference(
            "multihash+base58:QmRZxt2b1FVZPNqd8hsiykDL3TdBDeTSPX9Kv46HmX4Kgd"
        ));
    }

    #[test]
    fn test_is_digest_reference_rejects_tag_name() {
        assert!(!is_digest_reference("latest"));
    }

    #[test]
    fn test_is_digest_reference_rejects_tag_with_dot() {
        assert!(!is_digest_reference("v1.0.0"));
    }

    // upstream_content_violates_digest: pure decision used by both
    // resolve_virtual_blob and resolve_virtual_manifest before serving
    // upstream content. This is the #1348 round-1 security fix.

    #[test]
    fn test_upstream_content_violates_digest_tag_reference_never_rejects() {
        // Tags carry no content-addressable contract: the resolver must
        // accept whatever upstream serves and let the caller compute the
        // digest itself.
        assert!(!upstream_content_violates_digest(
            "latest",
            b"any bytes here"
        ));
        assert!(!upstream_content_violates_digest("v1.2.3", b""));
    }

    #[test]
    fn test_upstream_content_violates_digest_matching_digest_accepts() {
        // sha256 of "hello world" is a well-known value. The resolver must
        // accept content whose computed digest equals the requested digest.
        let bytes = b"hello world";
        let digest = "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assert!(!upstream_content_violates_digest(digest, bytes));
    }

    #[test]
    fn test_upstream_content_violates_digest_mismatch_rejects() {
        // Requesting a digest that does *not* match the upstream's bytes
        // must trip the violation guard. This is the bytes-substitution
        // attack vector PR #1348 round 1 concern #3 closes.
        let bytes = b"hello world";
        // Anything other than the real sha256 of "hello world".
        let fake_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        assert!(upstream_content_violates_digest(fake_digest, bytes));
    }

    #[test]
    fn test_upstream_content_violates_digest_empty_content_with_wrong_digest() {
        // Real sha256 of "" is e3b0c44...b855. Anything else with empty
        // content must be rejected.
        assert!(upstream_content_violates_digest(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            b""
        ));
    }

    #[test]
    fn test_upstream_content_violates_digest_empty_content_with_correct_digest() {
        // The canonical empty-string sha256 must pass.
        assert!(!upstream_content_violates_digest(
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            b""
        ));
    }

    #[test]
    fn test_upstream_content_violates_digest_invalid_digest_format_rejects() {
        // A reference that *looks* like a digest but fails `is_digest_reference`
        // (uppercase algorithm, empty algorithm, empty encoded) must not be
        // treated as a content-addressable assertion, even when the bytes
        // would not match. Belt-and-braces: violates_digest returns false
        // because `is_digest_reference` short-circuits to false first.
        assert!(!upstream_content_violates_digest("SHA256:abc", b"hi"));
        assert!(!upstream_content_violates_digest(":abc", b"hi"));
        assert!(!upstream_content_violates_digest("sha256:", b"hi"));
    }

    #[test]
    fn test_upstream_content_violates_digest_case_sensitive_hex_mismatch() {
        // sha256 hex digests are lowercase per the OCI grammar. An uppercase
        // hex reference does not equal the lowercase computed digest, so the
        // helper must reject it as a mismatch.
        let bytes = b"hello world";
        let upper = "sha256:B94D27B9934D3E08A52E52D7DA7DABFAC484EFE37A5380EE9088F7ACE2EFCDE9";
        assert!(upstream_content_violates_digest(upper, bytes));
    }

    // verify_digest_or_fall_through: positive-sense counterpart used by
    // resolver call sites to keep the control flow readable. The wrapper is
    // a strict negation of upstream_content_violates_digest; the tests here
    // pin both that contract and the call-site idiom ("continue when false").

    #[test]
    fn test_verify_digest_or_fall_through_tag_reference_always_accepts() {
        // Tags have no content-addressable contract — the caller must
        // forward whatever upstream served and compute the digest itself.
        assert!(verify_digest_or_fall_through(b"anything", "latest"));
        assert!(verify_digest_or_fall_through(b"", "v1.2.3"));
        assert!(verify_digest_or_fall_through(
            b"\x00\x01\x02",
            "release-candidate"
        ));
    }

    #[test]
    fn test_verify_digest_or_fall_through_matching_digest_accepts() {
        let bytes = b"hello world";
        let digest = "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assert!(verify_digest_or_fall_through(bytes, digest));
    }

    #[test]
    fn test_verify_digest_or_fall_through_mismatched_digest_falls_through() {
        // The exact resolver idiom: "false" means the caller should `continue`
        // to the next virtual-repo member instead of forwarding bytes.
        let bytes = b"hello world";
        let wrong = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        assert!(!verify_digest_or_fall_through(bytes, wrong));
    }

    #[test]
    fn test_verify_digest_or_fall_through_empty_content_with_canonical_digest() {
        // The canonical empty-string sha256 verifies correctly.
        let canonical = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(verify_digest_or_fall_through(b"", canonical));
    }

    #[test]
    fn test_verify_digest_or_fall_through_empty_content_with_wrong_digest_falls_through() {
        // Empty body + non-canonical empty-digest = mismatch, must fall through.
        let wrong = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        assert!(!verify_digest_or_fall_through(b"", wrong));
    }

    #[test]
    fn test_verify_digest_or_fall_through_invalid_digest_format_accepts() {
        // Malformed digest references (uppercase algorithm, empty parts) are
        // *not* content-addressable. The wrapper treats them as tag-like and
        // accepts the content; the caller still computes a digest from the
        // bytes for response headers.
        assert!(verify_digest_or_fall_through(b"hi", "SHA256:abc"));
        assert!(verify_digest_or_fall_through(b"hi", ":abc"));
        assert!(verify_digest_or_fall_through(b"hi", "sha256:"));
    }

    #[test]
    fn test_verify_digest_or_fall_through_is_inverse_of_violates_digest() {
        // Property: the wrapper is the strict negation of the underlying
        // helper across both branch outputs.
        let cases: &[(&[u8], &str)] = &[
            (b"hello world", "latest"),
            (
                b"hello world",
                "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
            ),
            (
                b"hello world",
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                b"",
                "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (b"hi", "SHA256:abc"),
        ];
        for (bytes, reference) in cases {
            assert_eq!(
                verify_digest_or_fall_through(bytes, reference),
                !upstream_content_violates_digest(reference, bytes),
                "wrapper must invert violates_digest for ({:?}, {:?})",
                std::str::from_utf8(bytes).unwrap_or("<binary>"),
                reference,
            );
        }
    }

    #[test]
    fn test_verify_digest_or_fall_through_large_content_canonical_digest() {
        // Realistic OCI blob size (~256KiB) of a deterministic byte pattern.
        // Confirms the helper computes the digest over the *whole* slice,
        // not just a prefix, by feeding a pattern whose sha256 we precompute.
        let bytes: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
        let computed = compute_sha256(&bytes);
        assert!(verify_digest_or_fall_through(&bytes, &computed));

        // And a one-byte truncation must trip the mismatch path.
        let truncated = &bytes[..bytes.len() - 1];
        assert!(!verify_digest_or_fall_through(truncated, &computed));
    }
}
