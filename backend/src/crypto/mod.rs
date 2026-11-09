//! The single entry point for security cryptography (#5579).
//!
//! Every security function in the backend (hashing that protects something,
//! HMAC, authenticated encryption, key derivation, password hashing,
//! signatures, randomness) goes through this module, and this module is
//! implemented on exactly one provider: `aws-lc-rs`. That is what makes the
//! FIPS 140-3 mode (#5577) a build flag rather than an audit: with
//! `--features fips` the same calls run inside the AWS-LC FIPS module, and
//! nothing outside `src/crypto/` can reach a non-validated primitive because
//! clippy's `disallowed-methods` / `disallowed-types` (`.clippy.toml`) refuse
//! direct use of the RustCrypto crates, `bcrypt`, `ed25519-dalek`, `rsa` and
//! the `rand` entropy sources anywhere else.
//!
//! Two kinds of hashing are deliberately **not** here:
//!
//! * **Protocol checksums.** MD5, SHA-1 and BLAKE2 fields that a package
//!   format defines (Maven `.md5`/`.sha1`, npm `shasum`, apk, conda,
//!   CocoaPods, git object ids) are interoperability data, not security
//!   functions, and FIPS 140-3 permits them as long as no security decision
//!   rests on them. They stay on the RustCrypto crates in the format modules
//!   and are enumerated in `docs/fips.md`.
//! * **Content digests used as identifiers** (CAS keys, OCI digests) are
//!   SHA-2 and *are* routed through [`digest`] (#5585), so that an integrity
//!   gate built on them is inside the boundary.
//!
//! Module map:
//!
//! | module        | provides                                          |
//! |---------------|---------------------------------------------------|
//! | [`digest`]    | SHA-256/384/512 one-shot and streaming             |
//! | [`hmac`]      | HMAC-SHA256/512 sign and constant-time verify      |
//! | [`aead`]      | AES-256-GCM with module-generated nonces           |
//! | [`kdf`]       | PBKDF2-HMAC-SHA512, HKDF-SHA256, SP 800-108 KBKDF   |
//! | [`password`]  | PHC-string PBKDF2 hashes, legacy bcrypt verify     |
//! | [`rng`]       | module DRBG: bytes, tokens, `RngCore` adapters     |
//! | [`signature`] | Ed25519, ECDSA P-256 and RSA verify; Ed25519 sign  |
//! | [`token`]     | keyed-HMAC stored form for API tokens and codes    |
//!
//! Nothing here consults `FIPS_MODE`: the facade always runs on the module,
//! and policy (what is refused in strict mode) lives in `crate::fips`
//! (#5580) so that the primitives stay mode-independent and testable.

pub mod aead;
pub mod digest;
pub mod hmac;
pub mod kdf;
pub mod password;
pub mod rng;
pub mod signature;
pub mod token;

/// Name of the linked cryptographic library, for `/health` and logs.
pub fn provider_name() -> &'static str {
    if cfg!(feature = "fips") {
        "AWS-LC FIPS"
    } else {
        "AWS-LC"
    }
}

/// Version of the `aws-lc-rs` binding the binary was built with.
pub fn provider_version() -> &'static str {
    env!("AWS_LC_RS_VERSION")
}

/// Whether the linked module reports itself as running in FIPS mode.
///
/// `true` only for a `--features fips` build whose module passed its
/// power-on self-tests. The `FIPS_MODE` gate (#5580) turns this into a
/// startup decision; callers that only want to *report* use this directly.
pub fn module_fips_active() -> bool {
    aws_lc_rs::try_fips_mode().is_ok()
}

/// Constant-time equality for secrets (tokens, tags, codes).
///
/// Returns `false` for inputs of different length without leaking where
/// they differ. Use this instead of `==` wherever one side came from a
/// client.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    aws_lc_rs::constant_time::verify_slices_are_equal(a, b).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_equal_and_rejects_unequal() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn provider_name_matches_build_feature() {
        assert_eq!(provider_name().starts_with("AWS-LC"), true);
        assert_eq!(cfg!(feature = "fips"), provider_name().ends_with("FIPS"));
    }

    #[test]
    fn module_fips_flag_matches_build_feature() {
        // A non-FIPS build never reports FIPS; a FIPS build must, or its
        // self-tests failed and the binary is unusable in strict mode.
        assert_eq!(module_fips_active(), cfg!(feature = "fips"));
    }
}
