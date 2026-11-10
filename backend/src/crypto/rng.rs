//! Security randomness from the module DRBG.
//!
//! Every secret, key, nonce, salt, token, code and SAML RelayState comes from
//! here. Jitter and backoff may keep using `rand`; nothing that an attacker
//! would want to predict may. [`ModuleRng`] adapts the DRBG to the
//! `rand_core` traits (both the 0.10 line used by `rand`, and the 0.6 line
//! used by `rsa` and `pgp`) for crates that take an RNG argument.

use aws_lc_rs::rand as lc;

/// Fill `dest` from the module DRBG.
pub fn fill(dest: &mut [u8]) {
    lc::fill(dest).expect("the module DRBG never fails after power-on self-tests");
}

/// `N` random bytes.
pub fn bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    fill(&mut out);
    out
}

/// `n` random bytes.
pub fn vec(n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    fill(&mut out);
    out
}

/// A random `u64`.
pub fn u64() -> u64 {
    u64::from_le_bytes(bytes())
}

/// A random `u128`.
pub fn u128() -> u128 {
    u128::from_le_bytes(bytes())
}

/// Lower-case hex of `n_bytes` random bytes (`2 * n_bytes` characters).
pub fn hex(n_bytes: usize) -> String {
    hex::encode(vec(n_bytes))
}

/// URL-safe base64 (no padding) of `n_bytes` random bytes.
pub fn base64url(n_bytes: usize) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(vec(n_bytes))
}

/// `len` characters drawn uniformly from `alphabet` by rejection sampling,
/// so no character is more likely than another (a plain modulo would bias
/// towards the start of the alphabet).
pub fn string_from_alphabet(alphabet: &[u8], len: usize) -> String {
    assert!(
        !alphabet.is_empty() && alphabet.len() <= 256,
        "alphabet must have 1..=256 symbols"
    );
    let n = alphabet.len();
    // Largest multiple of n that fits in a byte; values at or above it are
    // rejected so the remaining range divides evenly.
    let limit = 256 - (256 % n);
    let mut out = String::with_capacity(len);
    let mut buf = [0u8; 64];
    while out.len() < len {
        fill(&mut buf);
        for &b in &buf {
            if (b as usize) < limit {
                out.push(alphabet[b as usize % n] as char);
                if out.len() == len {
                    break;
                }
            }
        }
    }
    out
}

/// `len` characters from `[A-Za-z0-9]`.
pub fn alphanumeric(len: usize) -> String {
    string_from_alphabet(
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        len,
    )
}

/// `len` digits.
pub fn digits(len: usize) -> String {
    string_from_alphabet(b"0123456789", len)
}

/// A uniformly distributed value in `0..upper` (rejection sampling).
pub fn below(upper: u64) -> u64 {
    assert!(upper > 0, "upper bound must be positive");
    if upper.is_power_of_two() {
        return u64() & (upper - 1);
    }
    let zone = u64::MAX - (u64::MAX % upper);
    loop {
        let v = u64();
        if v < zone {
            return v % upper;
        }
    }
}

/// The module DRBG as a `rand_core` RNG, for crates that take one.
///
/// Zero-sized and `Copy`; create it inline: `&mut ModuleRng`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ModuleRng;

// rand_core 0.10: `Rng` and `CryptoRng` are blanket-implemented for any
// infallible `TryRng` / `TryCryptoRng`.
impl rand::TryRng for ModuleRng {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(u32::from_le_bytes(bytes()))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(u64())
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        fill(dest);
        Ok(())
    }
}

impl rand::TryCryptoRng for ModuleRng {}

impl rand08::RngCore for ModuleRng {
    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes(bytes())
    }

    fn next_u64(&mut self) -> u64 {
        u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        fill(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand08::Error> {
        fill(dest);
        Ok(())
    }
}

impl rand08::CryptoRng for ModuleRng {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn bytes_are_not_constant_and_not_repeated() {
        let mut seen = HashSet::new();
        for _ in 0..10_000 {
            assert!(
                seen.insert(bytes::<16>()),
                "DRBG produced a repeated 128-bit value"
            );
        }
        assert_ne!(bytes::<32>(), [0u8; 32]);
        assert_eq!(vec(0).len(), 0);
        assert_eq!(vec(100).len(), 100);
        let mut buf = [0u8; 9];
        fill(&mut buf);
        assert_ne!(buf, [0u8; 9]);
    }

    #[test]
    fn integers_vary() {
        let a: HashSet<u64> = (0..100).map(|_| u64()).collect();
        assert!(a.len() > 90);
        let b: HashSet<u128> = (0..100).map(|_| u128()).collect();
        assert!(b.len() > 90);
    }

    #[test]
    fn encodings_have_expected_shape() {
        let h = hex(16);
        assert_eq!(h.len(), 32);
        assert!(h
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        let b = base64url(32);
        assert_eq!(b.len(), 43);
        assert!(b
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn alphabet_strings_are_uniform_enough() {
        let s = alphanumeric(62 * 500);
        assert_eq!(s.len(), 31_000);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
        // Each of 62 symbols expected ~500 times; a biased modulo would give
        // the first few symbols ~750. Allow a wide band for randomness.
        let mut counts = std::collections::HashMap::new();
        for c in s.chars() {
            *counts.entry(c).or_insert(0usize) += 1;
        }
        assert_eq!(counts.len(), 62);
        for (c, n) in counts {
            assert!((350..=650).contains(&n), "symbol {c} appeared {n} times");
        }
        let d = digits(12);
        assert_eq!(d.len(), 12);
        assert!(d.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(string_from_alphabet(b"x", 5), "xxxxx");
        assert_eq!(alphanumeric(0), "");
    }

    #[test]
    fn below_respects_bound() {
        for upper in [1u64, 2, 3, 7, 16, 1000, 1 << 40, u64::MAX] {
            for _ in 0..200 {
                assert!(below(upper) < upper, "upper {upper}");
            }
        }
        assert_eq!(below(1), 0);
    }

    #[test]
    fn module_rng_implements_both_rand_core_lines() {
        {
            use rand::Rng;
            let mut r = ModuleRng;
            let mut buf = [0u8; 24];
            r.fill_bytes(&mut buf);
            assert_ne!(buf, [0u8; 24]);
            assert_ne!(r.next_u32(), r.next_u32());
            assert_ne!(r.next_u64(), r.next_u64());
        }
        {
            use rand08::RngCore;
            let mut r = ModuleRng;
            let mut buf = [0u8; 24];
            r.fill_bytes(&mut buf);
            assert_ne!(buf, [0u8; 24]);
            r.try_fill_bytes(&mut buf).unwrap();
            assert_ne!(r.next_u32(), r.next_u32());
            assert_ne!(r.next_u64(), r.next_u64());
        }
        fn takes_crypto_rng<R: rand::CryptoRng>(_: &mut R) {}
        fn takes_crypto_rng08<R: rand08::CryptoRng + rand08::RngCore>(_: &mut R) {}
        takes_crypto_rng(&mut ModuleRng);
        takes_crypto_rng08(&mut ModuleRng);
        assert_eq!(format!("{:?}", ModuleRng), "ModuleRng");
    }
}
