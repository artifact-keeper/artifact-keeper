//! AES-256-GCM on the module, with module-generated nonces.
//!
//! Wire format is `nonce (12) || ciphertext || tag (16)`, the same layout the
//! `aes-gcm` crate produced before (#5583), so ciphertext written by either
//! implementation decrypts with the other. Nonces come from the module DRBG
//! via `RandomizedNonceKey`; callers never pick one.

use aws_lc_rs::aead as lc;
use aws_lc_rs::aead::{Aad, RandomizedNonceKey};

/// AES-256-GCM key length.
pub const KEY_LEN: usize = 32;
/// GCM nonce length.
pub const NONCE_LEN: usize = lc::NONCE_LEN;
/// GCM tag length.
pub const TAG_LEN: usize = 16;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("AES-256-GCM key must be {KEY_LEN} bytes, got {0}")]
    KeyLength(usize),
    #[error("ciphertext too short")]
    TooShort,
    #[error("decryption failed: wrong key, corrupted data or tampered ciphertext")]
    Open,
}

/// An AES-256-GCM key.
pub struct Key {
    inner: RandomizedNonceKey,
}

impl Key {
    pub fn new(key: &[u8]) -> Result<Self, Error> {
        if key.len() != KEY_LEN {
            return Err(Error::KeyLength(key.len()));
        }
        let inner = RandomizedNonceKey::new(&lc::AES_256_GCM, key)
            .map_err(|_| Error::KeyLength(key.len()))?;
        Ok(Self { inner })
    }

    /// Encrypt `plaintext` with `aad` bound to it; returns `nonce || ct || tag`.
    pub fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        let mut in_out = Vec::with_capacity(NONCE_LEN + plaintext.len() + TAG_LEN);
        in_out.extend_from_slice(plaintext);
        let nonce = self
            .inner
            .seal_in_place_append_tag(Aad::from(aad), &mut in_out)
            .expect("AES-256-GCM seal cannot fail for an in-range plaintext");
        let mut out = Vec::with_capacity(NONCE_LEN + in_out.len());
        out.extend_from_slice(nonce.as_ref());
        out.extend_from_slice(&in_out);
        out
    }

    /// Decrypt `data` (`nonce || ct || tag`) produced by [`Key::seal`] or by
    /// any standard AES-256-GCM implementation using this layout.
    pub fn open(&self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
        if data.len() < NONCE_LEN + TAG_LEN {
            return Err(Error::TooShort);
        }
        let (nonce, ct) = data.split_at(NONCE_LEN);
        let nonce = lc::Nonce::try_assume_unique_for_key(nonce).map_err(|_| Error::TooShort)?;
        let mut in_out = ct.to_vec();
        let plain = self
            .inner
            .open_in_place(nonce, Aad::from(aad), &mut in_out)
            .map_err(|_| Error::Open)?;
        Ok(plain.to_vec())
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("aead::Key(AES-256-GCM)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_with_and_without_aad() {
        let key = Key::new(&[7u8; 32]).unwrap();
        for (pt, aad) in [
            (&b""[..], &b""[..]),
            (&b"hello"[..], &b""[..]),
            (&b"hello"[..], &b"ctx"[..]),
            (&[0u8; 4096][..], &b"big"[..]),
        ] {
            let ct = key.seal(pt, aad);
            assert_eq!(ct.len(), NONCE_LEN + pt.len() + TAG_LEN);
            assert_eq!(key.open(&ct, aad).unwrap(), pt);
        }
    }

    #[test]
    fn nonces_are_fresh_per_call() {
        let key = Key::new(&[1u8; 32]).unwrap();
        let a = key.seal(b"same", b"");
        let b = key.seal(b"same", b"");
        assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
        assert_ne!(a, b);
    }

    #[test]
    fn tamper_wrong_key_wrong_aad_and_short_inputs_fail() {
        let key = Key::new(&[2u8; 32]).unwrap();
        let other = Key::new(&[3u8; 32]).unwrap();
        let ct = key.seal(b"secret", b"aad");
        assert_eq!(other.open(&ct, b"aad"), Err(Error::Open));
        assert_eq!(key.open(&ct, b"other"), Err(Error::Open));
        let mut flipped = ct.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        assert_eq!(key.open(&flipped, b"aad"), Err(Error::Open));
        let mut body = ct.clone();
        body[NONCE_LEN] ^= 1;
        assert_eq!(key.open(&body, b"aad"), Err(Error::Open));
        assert_eq!(
            key.open(&ct[..NONCE_LEN + TAG_LEN - 1], b"aad"),
            Err(Error::TooShort)
        );
        assert_eq!(key.open(&[], b""), Err(Error::TooShort));
    }

    #[test]
    fn key_length_is_enforced() {
        assert_eq!(Key::new(&[0u8; 16]).err(), Some(Error::KeyLength(16)));
        assert_eq!(Key::new(&[0u8; 33]).err(), Some(Error::KeyLength(33)));
        assert!(Key::new(&[0u8; 32]).is_ok());
        assert_eq!(
            format!("{:?}", Key::new(&[0u8; 32]).unwrap()),
            "aead::Key(AES-256-GCM)"
        );
    }

    /// NIST GCM test case 16 (AES-256, 96-bit IV, with AAD), re-framed into
    /// this module's `nonce || ct || tag` layout: a known-answer decrypt
    /// proves the module's GCM, not just self-consistency.
    #[test]
    fn decrypts_nist_known_answer() {
        let key = hex::decode("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
            .unwrap();
        let iv = hex::decode("cafebabefacedbaddecaf888").unwrap();
        let aad = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();
        let pt = hex::decode(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        )
        .unwrap();
        let ct = hex::decode(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        )
        .unwrap();
        let tag = hex::decode("76fc6ece0f4e1768cddf8853bb2d551b").unwrap();
        let mut framed = iv.clone();
        framed.extend_from_slice(&ct);
        framed.extend_from_slice(&tag);
        let k = Key::new(&key).unwrap();
        assert_eq!(k.open(&framed, &aad).unwrap(), pt);
    }
}
