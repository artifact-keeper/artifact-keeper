//! HMAC on the module: keyed hashing for webhook signatures, token
//! storage (#5582) and key derivation inputs.

use aws_lc_rs::hmac as lc;

/// HMAC algorithms the facade exposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha256,
    Sha512,
}

impl Algorithm {
    fn inner(self) -> lc::Algorithm {
        match self {
            Algorithm::Sha256 => lc::HMAC_SHA256,
            Algorithm::Sha512 => lc::HMAC_SHA512,
        }
    }

    /// Tag length in bytes.
    pub fn tag_len(self) -> usize {
        match self {
            Algorithm::Sha256 => 32,
            Algorithm::Sha512 => 64,
        }
    }
}

/// A keyed HMAC instance. Cheap to clone; keep one per key rather than
/// re-deriving it per message.
#[derive(Clone)]
pub struct Key {
    algorithm: Algorithm,
    key: lc::Key,
}

impl Key {
    pub fn new(algorithm: Algorithm, key: &[u8]) -> Self {
        Self {
            algorithm,
            key: lc::Key::new(algorithm.inner(), key),
        }
    }

    pub fn sha256(key: &[u8]) -> Self {
        Self::new(Algorithm::Sha256, key)
    }

    pub fn sha512(key: &[u8]) -> Self {
        Self::new(Algorithm::Sha512, key)
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Compute the tag over `data`.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        lc::sign(&self.key, data).as_ref().to_vec()
    }

    /// Lower-case hex tag, the form webhook headers carry.
    pub fn sign_hex(&self, data: &[u8]) -> String {
        hex::encode(self.sign(data))
    }

    /// Constant-time check of `tag` against the tag of `data`.
    pub fn verify(&self, data: &[u8], tag: &[u8]) -> bool {
        lc::verify(&self.key, data, tag).is_ok()
    }

    /// Start a streaming computation for multi-part messages.
    pub fn context(&self) -> Context {
        Context {
            ctx: lc::Context::with_key(&self.key),
        }
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("hmac::Key")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// Streaming HMAC.
pub struct Context {
    ctx: lc::Context,
}

impl Context {
    pub fn update(&mut self, data: &[u8]) {
        self.ctx.update(data);
    }

    pub fn finish(self) -> Vec<u8> {
        self.ctx.sign().as_ref().to_vec()
    }
}

/// One-shot HMAC-SHA256.
pub fn sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let tag = lc::sign(&lc::Key::new(lc::HMAC_SHA256, key), data);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// One-shot HMAC-SHA512.
pub fn sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let tag = lc::sign(&lc::Key::new(lc::HMAC_SHA512, key), data);
    let mut out = [0u8; 64];
    out.copy_from_slice(tag.as_ref());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?"
    const KEY: &[u8] = b"Jefe";
    const DATA: &[u8] = b"what do ya want for nothing?";
    const TAG_256: &str = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
    const TAG_512: &str = "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737";

    #[test]
    fn one_shot_matches_rfc_4231() {
        assert_eq!(hex::encode(sha256(KEY, DATA)), TAG_256);
        assert_eq!(hex::encode(sha512(KEY, DATA)), TAG_512);
    }

    #[test]
    fn key_sign_verify_and_hex() {
        let k = Key::sha256(KEY);
        assert_eq!(k.sign_hex(DATA), TAG_256);
        assert!(k.verify(DATA, &hex::decode(TAG_256).unwrap()));
        assert!(!k.verify(
            b"what do ya want for something?",
            &hex::decode(TAG_256).unwrap()
        ));
        assert!(!k.verify(DATA, &[0u8; 32]));
        assert!(!k.verify(DATA, &[]));
        assert_eq!(Key::sha512(KEY).sign_hex(DATA), TAG_512);
    }

    #[test]
    fn streaming_context_matches_one_shot() {
        let k = Key::sha512(KEY);
        let mut c = k.context();
        c.update(b"what do ya ");
        c.update(b"want for nothing?");
        assert_eq!(hex::encode(c.finish()), TAG_512);
    }

    #[test]
    fn metadata() {
        assert_eq!(Algorithm::Sha256.tag_len(), 32);
        assert_eq!(Algorithm::Sha512.tag_len(), 64);
        assert_eq!(Key::sha256(KEY).algorithm(), Algorithm::Sha256);
        assert!(format!("{:?}", Key::sha256(KEY)).contains("Sha256"));
    }
}
