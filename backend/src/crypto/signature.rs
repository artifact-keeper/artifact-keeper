//! Digital signatures on the module.
//!
//! This module carries the primitives the first FIPS slices need: Ed25519
//! key generation, signing and verification (webhook instance key, plugin
//! signatures, #5585), and verification of ECDSA P-256 and RSA PKCS#1 v1.5 /
//! PSS signatures with SHA-256 (plugin and bundle verification). RSA signing
//! for repository metadata moves here in #5586.
//!
//! Key material in and out is raw bytes (32-byte Ed25519 seed, SPKI or
//! raw public keys) so the storage format of existing keys does not change.

use aws_lc_rs::signature as lc;
use aws_lc_rs::signature::KeyPair as _;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid key: {0}")]
    InvalidKey(&'static str),
    #[error("signature verification failed")]
    BadSignature,
}

/// Ed25519 seed length.
pub const ED25519_SEED_LEN: usize = 32;
/// Ed25519 public key length.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
/// Ed25519 signature length.
pub const ED25519_SIGNATURE_LEN: usize = 64;

/// An Ed25519 signing key.
pub struct Ed25519KeyPair {
    inner: lc::Ed25519KeyPair,
    seed: [u8; ED25519_SEED_LEN],
}

impl Ed25519KeyPair {
    /// Generate a fresh key from the module DRBG.
    pub fn generate() -> Self {
        let seed: [u8; ED25519_SEED_LEN] = super::rng::bytes();
        Self::from_seed(&seed).expect("a random 32-byte seed is always a valid Ed25519 key")
    }

    /// Rebuild a key from its 32-byte seed (the format existing keys are
    /// stored in).
    pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        let seed: [u8; ED25519_SEED_LEN] = seed
            .try_into()
            .map_err(|_| Error::InvalidKey("Ed25519 seed must be 32 bytes"))?;
        let inner = lc::Ed25519KeyPair::from_seed_unchecked(&seed)
            .map_err(|_| Error::InvalidKey("Ed25519 seed rejected"))?;
        Ok(Self { inner, seed })
    }

    /// The 32-byte seed, for storage (encrypt it first, #5583).
    pub fn seed(&self) -> &[u8; ED25519_SEED_LEN] {
        &self.seed
    }

    /// The 32-byte public key.
    pub fn public_key(&self) -> [u8; ED25519_PUBLIC_KEY_LEN] {
        let mut out = [0u8; ED25519_PUBLIC_KEY_LEN];
        out.copy_from_slice(self.inner.public_key().as_ref());
        out
    }

    /// Sign `message`; the signature is 64 bytes.
    pub fn sign(&self, message: &[u8]) -> [u8; ED25519_SIGNATURE_LEN] {
        let mut out = [0u8; ED25519_SIGNATURE_LEN];
        out.copy_from_slice(self.inner.sign(message).as_ref());
        out
    }
}

impl Clone for Ed25519KeyPair {
    fn clone(&self) -> Self {
        Self::from_seed(&self.seed).expect("a seed that built a key builds it again")
    }
}

impl std::fmt::Debug for Ed25519KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519KeyPair")
            .field("public_key", &hex::encode(self.public_key()))
            .finish_non_exhaustive()
    }
}

/// Verify an Ed25519 signature with a raw 32-byte public key.
pub fn ed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
    if public_key.len() != ED25519_PUBLIC_KEY_LEN {
        return Err(Error::InvalidKey("Ed25519 public key must be 32 bytes"));
    }
    lc::UnparsedPublicKey::new(&lc::ED25519, public_key)
        .verify(message, signature)
        .map_err(|_| Error::BadSignature)
}

/// Verify an ECDSA P-256 / SHA-256 signature in ASN.1 DER form with an
/// uncompressed SEC1 public key (`0x04 || x || y`, 65 bytes).
pub fn ecdsa_p256_verify_asn1(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    lc::UnparsedPublicKey::new(&lc::ECDSA_P256_SHA256_ASN1, public_key)
        .verify(message, signature)
        .map_err(|_| Error::BadSignature)
}

/// Verify an ECDSA P-256 / SHA-256 signature in fixed `r || s` form (64
/// bytes, the JWS `ES256` encoding) with an uncompressed SEC1 public key.
pub fn ecdsa_p256_verify_fixed(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    lc::UnparsedPublicKey::new(&lc::ECDSA_P256_SHA256_FIXED, public_key)
        .verify(message, signature)
        .map_err(|_| Error::BadSignature)
}

/// RSA signature schemes the facade verifies. Keys below 2048 bits are
/// rejected by the module for every variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaScheme {
    Pkcs1v15Sha256,
    Pkcs1v15Sha512,
    PssSha256,
}

/// Verify an RSA signature with a PKCS#1 `RSAPublicKey` DER public key.
pub fn rsa_verify(
    scheme: RsaScheme,
    public_key_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    let alg: &'static lc::RsaParameters = match scheme {
        RsaScheme::Pkcs1v15Sha256 => &lc::RSA_PKCS1_2048_8192_SHA256,
        RsaScheme::Pkcs1v15Sha512 => &lc::RSA_PKCS1_2048_8192_SHA512,
        RsaScheme::PssSha256 => &lc::RSA_PSS_2048_8192_SHA256,
    };
    lc::UnparsedPublicKey::new(alg, public_key_der)
        .verify(message, signature)
        .map_err(|_| Error::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8032 §7.1 test 1.
    const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const SIG_EMPTY: &str = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    #[test]
    fn ed25519_matches_rfc_8032_vector() {
        let kp = Ed25519KeyPair::from_seed(&hex::decode(SEED).unwrap()).unwrap();
        assert_eq!(hex::encode(kp.public_key()), PUBLIC);
        assert_eq!(hex::encode(kp.sign(b"")), SIG_EMPTY);
        assert_eq!(kp.seed(), &hex::decode(SEED).unwrap()[..]);
        assert!(ed25519_verify(&kp.public_key(), b"", &hex::decode(SIG_EMPTY).unwrap()).is_ok());
        assert!(format!("{kp:?}").contains(PUBLIC));
    }

    #[test]
    fn ed25519_generate_sign_verify_and_reject() {
        let kp = Ed25519KeyPair::generate();
        let other = Ed25519KeyPair::generate();
        assert_ne!(kp.seed(), other.seed());
        let sig = kp.sign(b"payload");
        assert_eq!(ed25519_verify(&kp.public_key(), b"payload", &sig), Ok(()));
        assert_eq!(
            ed25519_verify(&kp.public_key(), b"payloae", &sig),
            Err(Error::BadSignature)
        );
        assert_eq!(
            ed25519_verify(&other.public_key(), b"payload", &sig),
            Err(Error::BadSignature)
        );
        assert_eq!(
            ed25519_verify(&kp.public_key(), b"payload", &sig[..63]),
            Err(Error::BadSignature)
        );
        assert_eq!(
            ed25519_verify(&kp.public_key()[..31], b"payload", &sig),
            Err(Error::InvalidKey("Ed25519 public key must be 32 bytes"))
        );
        // Round-trip through the stored seed.
        let again = Ed25519KeyPair::from_seed(kp.seed()).unwrap();
        assert_eq!(again.public_key(), kp.public_key());
        assert_eq!(again.sign(b"payload"), sig);
    }

    #[test]
    fn ed25519_seed_length_is_enforced() {
        assert_eq!(
            Ed25519KeyPair::from_seed(&[1u8; 31]).err(),
            Some(Error::InvalidKey("Ed25519 seed must be 32 bytes"))
        );
        assert!(Ed25519KeyPair::from_seed(&[1u8; 32]).is_ok());
    }

    #[test]
    fn ecdsa_p256_rejects_garbage_and_wrong_key_shape() {
        // A random 65-byte blob is not a valid point; the module rejects it as
        // a bad signature (it never accepts), and a wrong-length key likewise.
        let pk = [4u8; 65];
        assert_eq!(
            ecdsa_p256_verify_asn1(&pk, b"m", &[0u8; 70]),
            Err(Error::BadSignature)
        );
        assert_eq!(
            ecdsa_p256_verify_fixed(&pk, b"m", &[0u8; 64]),
            Err(Error::BadSignature)
        );
        assert_eq!(
            ecdsa_p256_verify_fixed(&[4u8; 10], b"m", &[0u8; 64]),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn ecdsa_p256_verifies_a_module_produced_signature() {
        // Sign with the module's own ECDSA key (test-only use of the raw
        // API) and verify through the facade in both encodings.
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let pkcs8 =
            lc::EcdsaKeyPair::generate_pkcs8(&lc::ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let kp = lc::EcdsaKeyPair::from_pkcs8(&lc::ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref())
            .unwrap();
        let pk = kp.public_key().as_ref().to_vec();
        let sig = kp.sign(&rng, b"message").unwrap();
        assert_eq!(
            ecdsa_p256_verify_asn1(&pk, b"message", sig.as_ref()),
            Ok(())
        );
        assert_eq!(
            ecdsa_p256_verify_asn1(&pk, b"messagf", sig.as_ref()),
            Err(Error::BadSignature)
        );

        let kp_fixed =
            lc::EcdsaKeyPair::from_pkcs8(&lc::ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref())
                .unwrap();
        let sig_fixed = kp_fixed.sign(&rng, b"message").unwrap();
        assert_eq!(sig_fixed.as_ref().len(), 64);
        assert_eq!(
            ecdsa_p256_verify_fixed(&pk, b"message", sig_fixed.as_ref()),
            Ok(())
        );
    }

    #[test]
    fn rsa_verifies_module_signatures_and_rejects_tampering() {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let kp = lc::RsaKeyPair::generate(aws_lc_rs::rsa::KeySize::Rsa2048).unwrap();
        let pk = kp.public_key().as_ref().to_vec();
        let mut sig = vec![0u8; kp.public_modulus_len()];
        kp.sign(&lc::RSA_PKCS1_SHA256, &rng, b"doc", &mut sig)
            .unwrap();
        assert_eq!(
            rsa_verify(RsaScheme::Pkcs1v15Sha256, &pk, b"doc", &sig),
            Ok(())
        );
        assert_eq!(
            rsa_verify(RsaScheme::Pkcs1v15Sha256, &pk, b"dod", &sig),
            Err(Error::BadSignature)
        );
        assert_eq!(
            rsa_verify(RsaScheme::Pkcs1v15Sha512, &pk, b"doc", &sig),
            Err(Error::BadSignature)
        );
        assert_eq!(
            rsa_verify(RsaScheme::PssSha256, &pk, b"doc", &sig),
            Err(Error::BadSignature)
        );

        let mut pss = vec![0u8; kp.public_modulus_len()];
        kp.sign(&lc::RSA_PSS_SHA256, &rng, b"doc", &mut pss)
            .unwrap();
        assert_eq!(rsa_verify(RsaScheme::PssSha256, &pk, b"doc", &pss), Ok(()));

        let mut s512 = vec![0u8; kp.public_modulus_len()];
        kp.sign(&lc::RSA_PKCS1_SHA512, &rng, b"doc", &mut s512)
            .unwrap();
        assert_eq!(
            rsa_verify(RsaScheme::Pkcs1v15Sha512, &pk, b"doc", &s512),
            Ok(())
        );

        assert_eq!(
            rsa_verify(RsaScheme::Pkcs1v15Sha256, b"not a key", b"doc", &sig),
            Err(Error::BadSignature)
        );
    }
}
