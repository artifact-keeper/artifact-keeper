//! Key derivation on the module.
//!
//! * [`pbkdf2_sha512`] / [`pbkdf2_sha512_verify`]: SP 800-132 password-based
//!   derivation; [`super::password`] builds the stored-hash format on it.
//! * [`hkdf_sha256`]: RFC 5869 extract-and-expand for turning one secret
//!   into a fixed-length key (`FIPS_MODE` off keeps today's derivations).
//! * [`kbkdf_sha256`]: SP 800-108 counter-mode KBKDF for per-purpose subkeys
//!   under the dedicated data key (#5583).

use std::num::NonZeroU32;

use aws_lc_rs::hkdf as lc_hkdf;
#[cfg(test)]
use aws_lc_rs::hmac as lc_hmac;
use aws_lc_rs::kdf as lc_kdf;
use aws_lc_rs::pbkdf2 as lc_pbkdf2;

/// Default PBKDF2 iteration count for new password hashes (OWASP 2023
/// guidance for HMAC-SHA512 is 210,000).
pub const PBKDF2_DEFAULT_ITERATIONS: u32 = 210_000;

/// Derive `out.len()` bytes with PBKDF2-HMAC-SHA512.
pub fn pbkdf2_sha512(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    let iterations = NonZeroU32::new(iterations.max(1)).expect("max(1) is non-zero");
    lc_pbkdf2::derive(
        lc_pbkdf2::PBKDF2_HMAC_SHA512,
        iterations,
        salt,
        password,
        out,
    );
}

/// Constant-time check of `password` against a previously derived key.
pub fn pbkdf2_sha512_verify(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    expected: &[u8],
) -> bool {
    let Some(iterations) = NonZeroU32::new(iterations) else {
        return false;
    };
    lc_pbkdf2::verify(
        lc_pbkdf2::PBKDF2_HMAC_SHA512,
        iterations,
        salt,
        password,
        expected,
    )
    .is_ok()
}

/// Derive `out.len()` bytes with PBKDF2-HMAC-SHA256 (hashes written by
/// other components in the `$pbkdf2-sha256$` PHC form are verified with
/// this; new hashes here use SHA-512).
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    let iterations = NonZeroU32::new(iterations.max(1)).expect("max(1) is non-zero");
    lc_pbkdf2::derive(
        lc_pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        password,
        out,
    );
}

/// Constant-time PBKDF2-HMAC-SHA256 check.
pub fn pbkdf2_sha256_verify(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    expected: &[u8],
) -> bool {
    let Some(iterations) = NonZeroU32::new(iterations) else {
        return false;
    };
    lc_pbkdf2::verify(
        lc_pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        password,
        expected,
    )
    .is_ok()
}

struct OutLen(usize);

impl lc_hkdf::KeyType for OutLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// HKDF-SHA256: extract with `salt` (empty allowed), expand `info` to `len`
/// bytes. `len` is at most 255 * 32.
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let prk = lc_hkdf::Salt::new(lc_hkdf::HKDF_SHA256, salt).extract(ikm);
    let mut out = vec![0u8; len];
    prk.expand(&[info], OutLen(len))
        .and_then(|okm| okm.fill(&mut out))
        .expect("HKDF output length within the 255*HashLen bound");
    out
}

/// SP 800-108 KBKDF in counter mode with HMAC-SHA256.
///
/// `label` names the purpose ("token-hmac", "credential-aead"), `context`
/// binds instance data (a key id). Both are mixed into the fixed input as
/// `label || 0x00 || context || [L]_32` per SP 800-108 §4.1 so that two
/// purposes can never collide on a prefix.
pub fn kbkdf_sha256(secret: &[u8], label: &[u8], context: &[u8], len: usize) -> Vec<u8> {
    let bits = u32::try_from(len * 8).expect("output length fits in 32 bits");
    let mut info = Vec::with_capacity(label.len() + 1 + context.len() + 4);
    info.extend_from_slice(label);
    info.push(0);
    info.extend_from_slice(context);
    info.extend_from_slice(&bits.to_be_bytes());
    let alg = lc_kdf::get_kbkdf_ctr_hmac_algorithm(lc_kdf::KbkdfCtrHmacAlgorithmId::Sha256)
        .expect("KBKDF-CTR-HMAC-SHA256 is always available");
    let mut out = vec![0u8; len];
    lc_kdf::kbkdf_ctr_hmac(alg, secret, &info, &mut out).expect("KBKDF output within bounds");
    out
}

/// Reference KBKDF-CTR for the self-test: K(i) = HMAC(secret, [i]_32 || info).
#[cfg(test)]
fn kbkdf_sha256_reference(secret: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let key = lc_hmac::Key::new(lc_hmac::HMAC_SHA256, secret);
    let mut out = Vec::with_capacity(len + 32);
    let mut i: u32 = 1;
    while out.len() < len {
        let mut ctx = lc_hmac::Context::with_key(&key);
        ctx.update(&i.to_be_bytes());
        ctx.update(info);
        out.extend_from_slice(ctx.sign().as_ref());
        i += 1;
    }
    out.truncate(len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // PBKDF2-HMAC-SHA512 known answers (RFC 6070 inputs, SHA-512 variant as
    // published in the Python/OpenSSL test suites).
    #[test]
    fn pbkdf2_sha512_known_answers() {
        let mut out = [0u8; 64];
        pbkdf2_sha512(b"password", b"salt", 1, &mut out);
        assert_eq!(
            hex::encode(out),
            "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce"
        );
        pbkdf2_sha512(b"password", b"salt", 2, &mut out);
        assert_eq!(
            hex::encode(out),
            "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e"
        );
        pbkdf2_sha512(b"password", b"salt", 4096, &mut out);
        assert_eq!(
            hex::encode(out),
            "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5"
        );
    }

    #[test]
    fn pbkdf2_verify_accepts_right_password_and_rejects_wrong() {
        let mut out = [0u8; 32];
        pbkdf2_sha512(b"correct horse", b"s", 1000, &mut out);
        assert!(pbkdf2_sha512_verify(b"correct horse", b"s", 1000, &out));
        assert!(!pbkdf2_sha512_verify(b"correct hors", b"s", 1000, &out));
        assert!(!pbkdf2_sha512_verify(b"correct horse", b"t", 1000, &out));
        assert!(!pbkdf2_sha512_verify(b"correct horse", b"s", 999, &out));
        assert!(!pbkdf2_sha512_verify(b"correct horse", b"s", 0, &out));
    }

    // RFC 7914 §11 PBKDF2-HMAC-SHA256 vector.
    #[test]
    fn pbkdf2_sha256_known_answer_and_verify() {
        let mut out = [0u8; 64];
        pbkdf2_sha256(b"passwd", b"salt", 1, &mut out);
        assert_eq!(
            hex::encode(out),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
        );
        assert!(pbkdf2_sha256_verify(b"passwd", b"salt", 1, &out));
        assert!(!pbkdf2_sha256_verify(b"passwd", b"salt", 2, &out));
        assert!(!pbkdf2_sha256_verify(b"passwd", b"salt", 0, &out));
    }

    #[test]
    fn pbkdf2_zero_iterations_is_clamped_to_one() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        pbkdf2_sha512(b"p", b"s", 0, &mut a);
        pbkdf2_sha512(b"p", b"s", 1, &mut b);
        assert_eq!(a, b);
    }

    // RFC 5869 test case 1.
    #[test]
    fn hkdf_sha256_rfc_5869_case_1() {
        let ikm = [0x0bu8; 22];
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let okm = hkdf_sha256(&ikm, &salt, &info, 42);
        assert_eq!(
            hex::encode(okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    // RFC 5869 test case 3: empty salt and info.
    #[test]
    fn hkdf_sha256_rfc_5869_case_3() {
        let okm = hkdf_sha256(&[0x0bu8; 22], b"", b"", 42);
        assert_eq!(
            hex::encode(okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );
    }

    #[test]
    fn kbkdf_matches_sp800_108_counter_mode_reference() {
        let secret = [0x42u8; 32];
        for len in [16usize, 32, 33, 64, 100] {
            let bits = (len * 8) as u32;
            let mut info = b"purpose".to_vec();
            info.push(0);
            info.extend_from_slice(b"ctx");
            info.extend_from_slice(&bits.to_be_bytes());
            assert_eq!(
                kbkdf_sha256(&secret, b"purpose", b"ctx", len),
                kbkdf_sha256_reference(&secret, &info, len),
                "len {len}"
            );
        }
    }

    #[test]
    fn kbkdf_separates_purposes_and_contexts() {
        let secret = [9u8; 32];
        let a = kbkdf_sha256(&secret, b"token-hmac", b"", 32);
        let b = kbkdf_sha256(&secret, b"credential-aead", b"", 32);
        let c = kbkdf_sha256(&secret, b"token-hmac", b"key-2", 32);
        let d = kbkdf_sha256(&[8u8; 32], b"token-hmac", b"", 32);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_eq!(a, kbkdf_sha256(&secret, b"token-hmac", b"", 32));
        // label||0x00||context framing: ("ab","c") and ("a","bc") differ.
        assert_ne!(
            kbkdf_sha256(&secret, b"ab", b"c", 32),
            kbkdf_sha256(&secret, b"a", b"bc", 32)
        );
    }
}
