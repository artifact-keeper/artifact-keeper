//! SHA-2 digests on the module.
//!
//! One-shot helpers for the common cases and a streaming [`Hasher`] for
//! bodies that must never be buffered (#1608). SHA-1 is *not* offered here:
//! the protocol fields that need it are checksums, not security functions,
//! and keep using the `sha1` crate in their format module (see
//! `docs/fips.md`).

use aws_lc_rs::digest as lc;

/// Digest algorithms the facade exposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl Algorithm {
    fn inner(self) -> &'static lc::Algorithm {
        match self {
            Algorithm::Sha256 => &lc::SHA256,
            Algorithm::Sha384 => &lc::SHA384,
            Algorithm::Sha512 => &lc::SHA512,
        }
    }

    /// Output length in bytes.
    pub fn output_len(self) -> usize {
        self.inner().output_len()
    }

    /// The name used in digest strings (`sha256:<hex>`).
    pub fn name(self) -> &'static str {
        match self {
            Algorithm::Sha256 => "sha256",
            Algorithm::Sha384 => "sha384",
            Algorithm::Sha512 => "sha512",
        }
    }
}

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = lc::digest(&lc::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// SHA-384 of `data`.
pub fn sha384(data: &[u8]) -> [u8; 48] {
    let d = lc::digest(&lc::SHA384, data);
    let mut out = [0u8; 48];
    out.copy_from_slice(d.as_ref());
    out
}

/// SHA-512 of `data`.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let d = lc::digest(&lc::SHA512, data);
    let mut out = [0u8; 64];
    out.copy_from_slice(d.as_ref());
    out
}

/// Lower-case hex SHA-256 of `data`, the form most APIs store.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

/// Streaming digest.
///
/// ```ignore
/// let mut h = Hasher::new(Algorithm::Sha256);
/// h.update(chunk);
/// let hex = h.finish_hex();
/// ```
#[derive(Clone)]
pub struct Hasher {
    algorithm: Algorithm,
    ctx: lc::Context,
}

impl Hasher {
    pub fn new(algorithm: Algorithm) -> Self {
        Self {
            algorithm,
            ctx: lc::Context::new(algorithm.inner()),
        }
    }

    /// Shorthand for the SHA-256 hasher.
    pub fn sha256() -> Self {
        Self::new(Algorithm::Sha256)
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    pub fn update(&mut self, data: &[u8]) {
        self.ctx.update(data);
    }

    /// Consume the hasher and return the raw digest.
    pub fn finish(self) -> Vec<u8> {
        self.ctx.finish().as_ref().to_vec()
    }

    /// Consume the hasher and return the lower-case hex digest.
    pub fn finish_hex(self) -> String {
        hex::encode(self.ctx.finish().as_ref())
    }
}

impl std::fmt::Debug for Hasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hasher")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

impl std::io::Write for Hasher {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A fixed-size digest output that behaves like the RustCrypto
/// `GenericArray` the call sites were written against: `AsRef<[u8]>`,
/// `Deref<Target = [u8]>`, `LowerHex`, `Into<[u8; N]>` and `Into<Vec<u8>>`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Output<const N: usize>(pub [u8; N]);

impl<const N: usize> Output<N> {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn into_bytes(self) -> [u8; N] {
        self.0
    }
}

impl<const N: usize> AsRef<[u8]> for Output<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> std::ops::Deref for Output<N> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> From<Output<N>> for [u8; N] {
    fn from(o: Output<N>) -> Self {
        o.0
    }
}

impl<const N: usize> From<Output<N>> for Vec<u8> {
    fn from(o: Output<N>) -> Self {
        o.0.to_vec()
    }
}

impl<const N: usize> std::fmt::LowerHex for Output<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl<const N: usize> std::fmt::UpperHex for Output<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode_upper(self.0))
    }
}

impl<const N: usize> std::fmt::Debug for Output<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Output({})", hex::encode(self.0))
    }
}

impl<const N: usize> PartialEq<[u8; N]> for Output<N> {
    fn eq(&self, other: &[u8; N]) -> bool {
        self.0 == *other
    }
}

impl<const N: usize> PartialEq<[u8]> for Output<N> {
    fn eq(&self, other: &[u8]) -> bool {
        self.0[..] == *other
    }
}

impl<const N: usize> PartialEq<Vec<u8>> for Output<N> {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.0[..] == other[..]
    }
}

macro_rules! sha2_compat {
    ($name:ident, $alg:expr, $len:literal, $typenum:ident, $oid:literal, $doc:literal) => {
        // RustCrypto `digest` 0.10 traits, so `rsa::pkcs1v15::SigningKey<Sha256>`
        // and other hasher-generic crates run their hashing on the module.
        impl digest::HashMarker for $name {}

        impl digest::OutputSizeUser for $name {
            type OutputSize = digest::typenum::$typenum;
        }

        impl digest::Update for $name {
            fn update(&mut self, data: &[u8]) {
                self.0.update(data);
            }
        }

        impl digest::FixedOutput for $name {
            fn finalize_into(self, out: &mut digest::Output<Self>) {
                out.copy_from_slice(self.0.finish().as_ref());
            }
        }

        impl digest::Reset for $name {
            fn reset(&mut self) {
                *self = Self::new();
            }
        }

        impl digest::FixedOutputReset for $name {
            fn finalize_into_reset(&mut self, out: &mut digest::Output<Self>) {
                let done = std::mem::replace(self, Self::new());
                out.copy_from_slice(done.0.finish().as_ref());
            }
        }

        impl const_oid::AssociatedOid for $name {
            const OID: const_oid::ObjectIdentifier = const_oid::ObjectIdentifier::new_unwrap($oid);
        }

        #[doc = $doc]
        ///
        /// Drop-in for the RustCrypto hasher of the same name (`new`,
        /// `update`, `finalize`, `digest`), on the module. Call sites that
        /// compute content digests (#5585) keep their shape; only the import
        /// changes to `crate::crypto::digest`.
        #[derive(Clone)]
        pub struct $name(lc::Context);

        impl $name {
            pub fn new() -> Self {
                Self(lc::Context::new($alg))
            }

            pub fn update(&mut self, data: impl AsRef<[u8]>) {
                self.0.update(data.as_ref());
            }

            pub fn chain_update(mut self, data: impl AsRef<[u8]>) -> Self {
                self.update(data);
                self
            }

            pub fn finalize(self) -> Output<$len> {
                let mut out = [0u8; $len];
                out.copy_from_slice(self.0.finish().as_ref());
                Output(out)
            }

            pub fn finalize_reset(&mut self) -> Output<$len> {
                let done = std::mem::replace(self, Self::new());
                done.finalize()
            }

            pub fn digest(data: impl AsRef<[u8]>) -> Output<$len> {
                let mut out = [0u8; $len];
                out.copy_from_slice(lc::digest($alg, data.as_ref()).as_ref());
                Output(out)
            }

            pub const fn output_size() -> usize {
                $len
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(stringify!($name))
            }
        }

        impl std::io::Write for $name {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.update(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
    };
}

sha2_compat!(
    Sha256,
    &lc::SHA256,
    32,
    U32,
    "2.16.840.1.101.3.4.2.1",
    "SHA-256 hasher."
);
sha2_compat!(
    Sha384,
    &lc::SHA384,
    48,
    U48,
    "2.16.840.1.101.3.4.2.2",
    "SHA-384 hasher."
);
sha2_compat!(
    Sha512,
    &lc::SHA512,
    64,
    U64,
    "2.16.840.1.101.3.4.2.3",
    "SHA-512 hasher."
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compat_hashers_match_one_shot_helpers() {
        let mut h = Sha256::new();
        h.update(b"ab");
        h.update("c");
        let out = h.finalize();
        assert_eq!(format!("{out:x}"), ABC_SHA256);
        assert_eq!(hex::encode(out), ABC_SHA256);
        assert_eq!(out, sha256(b"abc"));
        assert_eq!(out.to_vec(), sha256(b"abc").to_vec());
        let arr: [u8; 32] = out.into();
        assert_eq!(arr, sha256(b"abc"));
        let v: Vec<u8> = out.into();
        assert_eq!(v, sha256(b"abc").to_vec());
        assert_eq!(&out[..4], &sha256(b"abc")[..4]);
        assert_eq!(Sha256::digest("abc"), sha256(b"abc"));
        assert_eq!(hex::encode(Sha384::digest(b"abc")), ABC_SHA384);
        assert_eq!(
            hex::encode(Sha512::new().chain_update(b"abc").finalize()),
            ABC_SHA512
        );
        assert_eq!(Sha256::output_size(), 32);
        assert_eq!(Sha512::output_size(), 64);
        let mut r = Sha256::default();
        r.update(b"abc");
        assert_eq!(hex::encode(r.finalize_reset()), ABC_SHA256);
        assert_eq!(
            hex::encode(r.finalize()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(format!("{:?}", Sha256::new()), "Sha256");
        assert!(format!("{:?}", Sha256::digest(b"abc")).starts_with("Output(ba7816bf"));
        use std::io::Write;
        let mut w = Sha384::new();
        w.write_all(b"abc").unwrap();
        w.flush().unwrap();
        assert_eq!(hex::encode(w.finalize()), ABC_SHA384);
    }

    // FIPS 180-4 / NIST CAVP "abc" vectors.
    const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const ABC_SHA384: &str = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7";
    const ABC_SHA512: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

    #[test]
    fn one_shot_matches_nist_vectors() {
        assert_eq!(hex::encode(sha256(b"abc")), ABC_SHA256);
        assert_eq!(hex::encode(sha384(b"abc")), ABC_SHA384);
        assert_eq!(hex::encode(sha512(b"abc")), ABC_SHA512);
        assert_eq!(sha256_hex(b"abc"), ABC_SHA256);
    }

    #[test]
    fn empty_input_sha256() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn streaming_equals_one_shot_across_chunk_boundaries() {
        let data: Vec<u8> = (0..=255u8).cycle().take(10_000).collect();
        for chunk in [1usize, 7, 64, 1000, 10_000] {
            let mut h = Hasher::new(Algorithm::Sha512);
            for c in data.chunks(chunk) {
                h.update(c);
            }
            assert_eq!(h.finish(), sha512(&data).to_vec(), "chunk size {chunk}");
        }
    }

    #[test]
    fn hasher_implements_write() {
        use std::io::Write;
        let mut h = Hasher::sha256();
        h.write_all(b"ab").unwrap();
        h.write_all(b"c").unwrap();
        h.flush().unwrap();
        assert_eq!(h.finish_hex(), ABC_SHA256);
    }

    #[test]
    fn algorithm_metadata() {
        assert_eq!(Algorithm::Sha256.output_len(), 32);
        assert_eq!(Algorithm::Sha384.output_len(), 48);
        assert_eq!(Algorithm::Sha512.output_len(), 64);
        assert_eq!(Algorithm::Sha256.name(), "sha256");
        assert_eq!(
            Hasher::new(Algorithm::Sha384).algorithm(),
            Algorithm::Sha384
        );
        assert!(format!("{:?}", Hasher::sha256()).contains("Sha256"));
    }
}
