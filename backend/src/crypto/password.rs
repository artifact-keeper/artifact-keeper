//! Password hashing: PBKDF2-HMAC-SHA512 on the module, with legacy bcrypt
//! verification so existing hashes keep working (#5582).
//!
//! Stored format for new hashes is a PHC string:
//!
//! ```text
//! $pbkdf2-sha512$i=210000$<salt, base64 no padding>$<hash, base64 no padding>
//! ```
//!
//! `bcrypt` hashes (`$2a$`, `$2b$`, `$2y$`) are recognised by prefix and
//! verified with the `bcrypt` crate. Which format gets *written* is a policy
//! decision made by the caller from `FIPS_MODE`; this module only knows how
//! to produce and check each one. The `bcrypt` crate is used nowhere else
//! (clippy `disallowed-methods`), so when the legacy path is finally
//! removed the dependency goes with it.

use base64::engine::general_purpose::STANDARD_NO_PAD as B64;
use base64::Engine;

use super::kdf;
use super::rng;

/// PHC identifier for the PBKDF2 format.
pub const PBKDF2_ID: &str = "pbkdf2-sha512";
/// Salt length for new hashes (SP 800-132 requires at least 128 bits).
pub const SALT_LEN: usize = 16;
/// Derived key length for new hashes.
pub const HASH_LEN: usize = 32;
/// Lowest iteration count a stored hash may carry and still verify.
pub const MIN_ITERATIONS: u32 = 1_000;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("unrecognised password hash format")]
    UnknownFormat,
    #[error("malformed PBKDF2 hash: {0}")]
    Malformed(&'static str),
}

/// PHC identifier of the SHA-256 variant, accepted on verify only (hashes
/// written by other components of a deployment).
pub const PBKDF2_SHA256_ID: &str = "pbkdf2-sha256";

/// Which family a stored hash belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Pbkdf2Sha512,
    Pbkdf2Sha256,
    Bcrypt,
}

/// Identify a stored hash by prefix.
pub fn format_of(stored: &str) -> Result<Format, Error> {
    if stored.starts_with(&format!("${PBKDF2_ID}$")) {
        Ok(Format::Pbkdf2Sha512)
    } else if stored.starts_with(&format!("${PBKDF2_SHA256_ID}$")) {
        Ok(Format::Pbkdf2Sha256)
    } else if stored.starts_with("$2a$") || stored.starts_with("$2b$") || stored.starts_with("$2y$")
    {
        Ok(Format::Bcrypt)
    } else {
        Err(Error::UnknownFormat)
    }
}

/// Hash `password` with PBKDF2-HMAC-SHA512 at the default iteration count.
pub fn hash_pbkdf2(password: &str) -> String {
    hash_pbkdf2_with(password, kdf::PBKDF2_DEFAULT_ITERATIONS)
}

/// Hash with an explicit iteration count (tests, or an operator-tuned value).
pub fn hash_pbkdf2_with(password: &str, iterations: u32) -> String {
    let iterations = iterations.max(MIN_ITERATIONS);
    let salt: [u8; SALT_LEN] = rng::bytes();
    let mut out = [0u8; HASH_LEN];
    kdf::pbkdf2_sha512(password.as_bytes(), &salt, iterations, &mut out);
    format!(
        "${PBKDF2_ID}$i={iterations}${}${}",
        B64.encode(salt),
        B64.encode(out)
    )
}

/// PHC base64 (standard alphabet, no padding), also accepting passlib's
/// "adapted base64" which uses `.` in place of `+`.
fn decode_phc_b64(field: &str) -> Option<Vec<u8>> {
    let field = field.trim_end_matches('=');
    B64.decode(field)
        .or_else(|_| B64.decode(field.replace('.', "+")))
        .ok()
}

struct Pbkdf2Parts {
    iterations: u32,
    salt: Vec<u8>,
    hash: Vec<u8>,
}

fn parse_pbkdf2(stored: &str) -> Result<Pbkdf2Parts, Error> {
    let mut parts = stored.split('$');
    if parts.next() != Some("") || !matches!(parts.next(), Some(PBKDF2_ID) | Some(PBKDF2_SHA256_ID))
    {
        return Err(Error::UnknownFormat);
    }
    let params = parts.next().ok_or(Error::Malformed("missing parameters"))?;
    // PHC proper is `i=N`; passlib writes the bare count (`$pbkdf2-sha256$29000$…`).
    let iterations = params
        .strip_prefix("i=")
        .unwrap_or(params)
        .parse::<u32>()
        .map_err(|_| Error::Malformed("iteration count is not a number"))?;
    if iterations < MIN_ITERATIONS {
        return Err(Error::Malformed("iteration count below minimum"));
    }
    let salt = decode_phc_b64(parts.next().ok_or(Error::Malformed("missing salt"))?)
        .ok_or(Error::Malformed("salt is not base64"))?;
    let hash = decode_phc_b64(parts.next().ok_or(Error::Malformed("missing hash"))?)
        .ok_or(Error::Malformed("hash is not base64"))?;
    if parts.next().is_some() {
        return Err(Error::Malformed("trailing data"));
    }
    // New hashes carry a 16-byte salt; on verify any non-empty salt is
    // accepted (other producers, test vectors) but the derived key must be
    // at least 128 bits or a match proves nothing.
    if salt.is_empty() || hash.len() < 16 {
        return Err(Error::Malformed("salt or hash too short"));
    }
    Ok(Pbkdf2Parts {
        iterations,
        salt,
        hash,
    })
}

/// Verify `password` against a stored hash of either format.
///
/// `Ok(false)` is a wrong password; `Err` is a hash the backend cannot
/// interpret, which callers should treat as a failed login *and* log.
pub fn verify(password: &str, stored: &str) -> Result<bool, Error> {
    match format_of(stored)? {
        Format::Pbkdf2Sha512 => {
            let p = parse_pbkdf2(stored)?;
            Ok(kdf::pbkdf2_sha512_verify(
                password.as_bytes(),
                &p.salt,
                p.iterations,
                &p.hash,
            ))
        }
        Format::Pbkdf2Sha256 => {
            let p = parse_pbkdf2(stored)?;
            Ok(kdf::pbkdf2_sha256_verify(
                password.as_bytes(),
                &p.salt,
                p.iterations,
                &p.hash,
            ))
        }
        #[allow(clippy::disallowed_methods)] // the facade is where bcrypt lives
        Format::Bcrypt => Ok(bcrypt::verify(password, stored).unwrap_or(false)),
    }
}

/// Whether a stored hash should be upgraded on next successful login:
/// legacy bcrypt, or PBKDF2 below `target_iterations`. A `$pbkdf2-sha256$`
/// hash is module-backed too and is judged on its iteration count alone.
pub fn needs_rehash(stored: &str, target_iterations: u32) -> bool {
    match format_of(stored) {
        Ok(Format::Bcrypt) => true,
        Ok(Format::Pbkdf2Sha512) | Ok(Format::Pbkdf2Sha256) => parse_pbkdf2(stored)
            .map(|p| p.iterations < target_iterations.max(MIN_ITERATIONS))
            .unwrap_or(true),
        Err(_) => true,
    }
}

/// Legacy bcrypt hashing, kept for the non-FIPS default write path (#5582)
/// and test fixtures. `cost` follows the `bcrypt` crate (4..=31).
#[allow(clippy::disallowed_methods)] // the facade is where bcrypt lives
pub fn hash_bcrypt(password: &str, cost: u32) -> Result<String, bcrypt::BcryptError> {
    bcrypt::hash(password, cost)
}

/// The `bcrypt` crate's default cost, re-exported so callers do not import
/// the crate.
pub const BCRYPT_DEFAULT_COST: u32 = bcrypt::DEFAULT_COST;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_round_trip_and_format() {
        let h = hash_pbkdf2_with("hunter2", 1_000);
        assert!(h.starts_with("$pbkdf2-sha512$i=1000$"), "{h}");
        assert_eq!(format_of(&h), Ok(Format::Pbkdf2Sha512));
        assert_eq!(verify("hunter2", &h), Ok(true));
        assert_eq!(verify("hunter3", &h), Ok(false));
        assert_eq!(verify("", &h), Ok(false));
        // Fresh salt every time.
        assert_ne!(h, hash_pbkdf2_with("hunter2", 1_000));
    }

    #[test]
    fn pbkdf2_default_iterations_and_floor() {
        let h = hash_pbkdf2("x");
        assert!(h.contains(&format!("$i={}$", kdf::PBKDF2_DEFAULT_ITERATIONS)));
        let low = hash_pbkdf2_with("x", 1);
        assert!(low.contains(&format!("$i={MIN_ITERATIONS}$")), "{low}");
        assert_eq!(verify("x", &low), Ok(true));
    }

    #[test]
    fn pbkdf2_known_answer_verifies() {
        // password/salt from the kdf test vector, 4096 iterations, first 32
        // bytes of the derived key.
        let salt = B64.encode(b"salt");
        let hash = B64.encode(
            hex::decode("d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5")
                .unwrap(),
        );
        let stored = format!("$pbkdf2-sha512$i=4096${salt}${hash}");
        assert_eq!(verify("password", &stored), Ok(true));
        assert_eq!(verify("Password", &stored), Ok(false));
    }

    #[test]
    fn pbkdf2_sha256_phc_from_other_components_verifies() {
        // RFC 7914 vector: PBKDF2-HMAC-SHA256("passwd", "salt", 1), first
        // 32 bytes, written the way a `$pbkdf2-sha256$` producer would.
        let salt = B64.encode(b"salt");
        let hash = B64.encode(
            hex::decode("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc")
                .unwrap(),
        );
        // MIN_ITERATIONS applies, so build a 1000-iteration hash with the
        // facade for the positive case and use the vector only for format.
        assert_eq!(
            format_of(&format!("$pbkdf2-sha256$i=1${salt}${hash}")),
            Ok(Format::Pbkdf2Sha256)
        );
        let mut out = [0u8; 32];
        kdf::pbkdf2_sha256(b"passwd", b"salt", 1000, &mut out);
        let stored = format!("$pbkdf2-sha256$i=1000${salt}${}", B64.encode(out));
        assert_eq!(verify("passwd", &stored), Ok(true));
        assert_eq!(verify("passwd!", &stored), Ok(false));
        assert!(!needs_rehash(&stored, 1000));
        assert!(needs_rehash(&stored, 600_000));
    }

    #[test]
    fn passlib_style_pbkdf2_sha256_verifies() {
        // passlib: bare iteration count and "adapted base64" (`.` for `+`,
        // no padding). Build one from the facade's own derivation.
        let salt = [
            0xfbu8, 0xff, 0xef, 0xbe, 0x3e, 0xfa, 0xfb, 0xff, 0x01, 0x02, 0x03, 0x04,
        ];
        let mut out = [0u8; 32];
        kdf::pbkdf2_sha256(b"passlib-user", &salt, 29_000, &mut out);
        let ab64 = |b: &[u8]| B64.encode(b).replace('+', ".");
        let stored = format!("$pbkdf2-sha256$29000${}${}", ab64(&salt), ab64(&out));
        assert!(
            stored.contains('.'),
            "vector must exercise the `.` alphabet: {stored}"
        );
        assert_eq!(verify("passlib-user", &stored), Ok(true));
        assert_eq!(verify("passlib-usr", &stored), Ok(false));
        assert_eq!(format_of(&stored), Ok(Format::Pbkdf2Sha256));
    }

    #[test]
    fn bcrypt_hashes_still_verify() {
        let h = hash_bcrypt("legacy", 4).unwrap();
        assert_eq!(format_of(&h), Ok(Format::Bcrypt));
        assert_eq!(verify("legacy", &h), Ok(true));
        assert_eq!(verify("legacy!", &h), Ok(false));
    }

    #[test]
    fn unknown_and_malformed_hashes_are_errors_not_matches() {
        assert_eq!(verify("x", ""), Err(Error::UnknownFormat));
        assert_eq!(verify("x", "plaintext"), Err(Error::UnknownFormat));
        assert_eq!(
            verify("x", "$argon2id$v=19$m=65536"),
            Err(Error::UnknownFormat)
        );
        assert_eq!(
            verify("x", "$pbkdf2-sha512$i=abc$c2FsdA$aGFzaGhhc2hoYXNoaGFzaA"),
            Err(Error::Malformed("iteration count is not a number"))
        );
        assert_eq!(
            verify("x", "$pbkdf2-sha512$i=10$c2FsdA$aGFzaGhhc2hoYXNoaGFzaA"),
            Err(Error::Malformed("iteration count below minimum"))
        );
        assert_eq!(
            verify("x", "$pbkdf2-sha512$i=1000$c2FsdA"),
            Err(Error::Malformed("missing hash"))
        );
        assert_eq!(
            verify("x", "$pbkdf2-sha512$i=1000$!!$aGFzaGhhc2hoYXNoaGFzaA"),
            Err(Error::Malformed("salt is not base64"))
        );
        assert_eq!(
            verify("x", "$pbkdf2-sha512$i=1000$c2FsdA$aGFzaGhhc2hoYXNoaGFzaA$x"),
            Err(Error::Malformed("trailing data"))
        );
        assert_eq!(
            verify("x", "$pbkdf2-sha512$i=1000$c2FsdA$YQ"),
            Err(Error::Malformed("salt or hash too short"))
        );
        // A bare iteration count is the passlib spelling: parsed, and this
        // one simply does not match.
        assert_eq!(
            verify("x", "$pbkdf2-sha512$1000$c2FsdA$aGFzaGhhc2hoYXNoaGFzaA"),
            Ok(false)
        );
        assert_eq!(
            verify(
                "x",
                "$pbkdf2-sha512$iterations$c2FsdA$aGFzaGhhc2hoYXNoaGFzaA"
            ),
            Err(Error::Malformed("iteration count is not a number"))
        );
        // Without the closing `$` the prefix is not the format at all.
        assert_eq!(verify("x", "$pbkdf2-sha512"), Err(Error::UnknownFormat));
        assert_eq!(
            verify("x", "$pbkdf2-sha512$"),
            Err(Error::Malformed("iteration count is not a number"))
        );
        // A bcrypt-looking string that isn't a valid bcrypt hash is a miss.
        assert_eq!(verify("x", "$2b$garbage"), Ok(false));
    }

    #[test]
    fn needs_rehash_policy() {
        let bc = hash_bcrypt("p", 4).unwrap();
        assert!(needs_rehash(&bc, 210_000));
        let weak = hash_pbkdf2_with("p", 1_000);
        assert!(needs_rehash(&weak, 210_000));
        assert!(!needs_rehash(&weak, 1_000));
        assert!(!needs_rehash(&weak, 1)); // target clamps to MIN_ITERATIONS
        assert!(needs_rehash("garbage", 1_000));
    }
}
