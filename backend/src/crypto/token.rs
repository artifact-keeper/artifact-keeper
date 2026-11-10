//! Stored form of high-entropy secrets: API tokens, TOTP backup codes,
//! device codes (#5582).
//!
//! A token already carries 128+ bits of DRBG entropy, so a slow password
//! hash buys nothing; what the stored form needs is to be useless if the
//! table leaks. HMAC-SHA256 under a server-side key gives that, on the
//! module, in microseconds:
//!
//! ```text
//! $hmac-sha256$<hex tag>
//! ```
//!
//! Legacy rows hold bcrypt hashes and keep verifying through
//! [`super::password::verify`]. Which form gets *written* is the caller's
//! policy decision (`FIPS_MODE=strict` writes HMAC).

use super::hmac;
use super::password;

/// Prefix of the HMAC stored form.
pub const HMAC_PREFIX: &str = "$hmac-sha256$";

/// Server-side key for token tags, derived once per process from the
/// deployment secret (KBKDF label `token-hmac`) so the key is never the raw
/// `JWT_SECRET` and a future dedicated data key (#5583) slots in unchanged.
#[derive(Clone)]
pub struct TokenKey(hmac::Key);

impl TokenKey {
    /// Derive the token key from a deployment secret.
    pub fn derive(secret: &[u8]) -> Self {
        let k = super::kdf::kbkdf_sha256(secret, b"token-hmac", b"", 32);
        Self(hmac::Key::sha256(&k))
    }

    /// Use an already-derived 32-byte subkey (the `token-hmac` subkey of the
    /// dedicated data key, #5583) as the token key.
    pub fn from_subkey(subkey: &[u8]) -> Self {
        Self(hmac::Key::sha256(subkey))
    }

    /// The stored form of `token`.
    pub fn hash(&self, token: &str) -> String {
        format!("{HMAC_PREFIX}{}", self.0.sign_hex(token.as_bytes()))
    }

    /// Verify `token` against a stored form of either family.
    ///
    /// Returns `Ok(true)`/`Ok(false)` for a recognised form and the
    /// password module's error for an unrecognised one.
    pub fn verify(&self, token: &str, stored: &str) -> Result<bool, password::Error> {
        match stored.strip_prefix(HMAC_PREFIX) {
            Some(tag_hex) => {
                let Ok(tag) = hex::decode(tag_hex) else {
                    return Err(password::Error::Malformed("HMAC tag is not hex"));
                };
                Ok(self.0.verify(token.as_bytes(), &tag))
            }
            None => password::verify(token, stored),
        }
    }
}

impl std::fmt::Debug for TokenKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TokenKey(HMAC-SHA256)")
    }
}

/// Whether a stored form is the module-backed HMAC one.
pub fn is_hmac(stored: &str) -> bool {
    stored.starts_with(HMAC_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_form_round_trips_and_is_keyed() {
        let k = TokenKey::derive(b"deployment-secret-at-least-32-bytes!!");
        let other = TokenKey::derive(b"another-secret-that-is-also-32-bytes");
        let stored = k.hash("abcd1234_deadbeef");
        assert!(stored.starts_with(HMAC_PREFIX));
        assert!(is_hmac(&stored));
        assert_eq!(stored.len(), HMAC_PREFIX.len() + 64);
        assert_eq!(k.verify("abcd1234_deadbeef", &stored), Ok(true));
        assert_eq!(k.verify("abcd1234_deadbeeg", &stored), Ok(false));
        assert_eq!(other.verify("abcd1234_deadbeef", &stored), Ok(false));
        // Deterministic: the same token always maps to the same stored form.
        assert_eq!(stored, k.hash("abcd1234_deadbeef"));
        assert_eq!(format!("{k:?}"), "TokenKey(HMAC-SHA256)");
    }

    #[test]
    fn legacy_bcrypt_rows_verify_through_the_same_call() {
        let k = TokenKey::derive(b"s");
        let legacy = password::hash_bcrypt("tok", 4).unwrap();
        assert!(!is_hmac(&legacy));
        assert_eq!(k.verify("tok", &legacy), Ok(true));
        assert_eq!(k.verify("tik", &legacy), Ok(false));
        assert_eq!(
            k.verify("tok", "nonsense"),
            Err(password::Error::UnknownFormat)
        );
        assert_eq!(
            k.verify("tok", "$hmac-sha256$zz"),
            Err(password::Error::Malformed("HMAC tag is not hex"))
        );
    }

    #[test]
    fn derived_key_is_not_the_raw_secret() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let k = TokenKey::derive(secret);
        let raw = hmac::Key::sha256(secret);
        assert_ne!(k.hash("t"), format!("{HMAC_PREFIX}{}", raw.sign_hex(b"t")));
    }
}
