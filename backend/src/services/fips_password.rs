//! Password and API-token hashing in the `fips` build: PBKDF2-HMAC-SHA256.
//!
//! For deployments that require FIPS 140-3 validated cryptography. Compiled
//! only with the `fips` cargo feature; the default build keeps bcrypt and
//! never sees this module.
//!
//! bcrypt is not a FIPS-approved algorithm, so a `fips` build hashes every new
//! password, API token and TOTP backup code with PBKDF2-HMAC-SHA256
//! (NIST SP 800-132) from the AWS-LC FIPS module, and stores it as a
//! self-describing PHC-style string:
//!
//! ```text
//! $pbkdf2-sha256$i=600000$<salt>$<derived key>
//! ```
//!
//! `salt` is 16 random bytes from the module's DRBG and `derived key` is
//! 32 bytes, both standard base64 without padding. The iteration count is read
//! back from the stored string on verify, so raising it later only affects new
//! hashes (and [`needs_rehash`] upgrades old ones on the next successful
//! login).
//!
//! Hashes written by a default build (bcrypt, `$2a$` / `$2b$` / `$2x$` /
//! `$2y$`) are handled according to `FIPS_LEGACY_PASSWORD_HASHES`, see
//! [`LegacyHashPolicy`].

use std::num::NonZeroU32;
use std::sync::OnceLock;

use aws_lc_rs::pbkdf2;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use base64::engine::general_purpose::STANDARD_NO_PAD;
use base64::Engine as _;

use crate::error::{AppError, Result};

/// The PHC identifier of the scheme, and the prefix of every hash it writes.
const PREFIX: &str = "$pbkdf2-sha256$";

/// Iteration count for new hashes in production: the OWASP Password Storage
/// Cheat Sheet (2023) figure for PBKDF2-HMAC-SHA256.
pub const PRODUCTION_ITERATIONS: u32 = 600_000;

/// Smallest iteration count a stored hash may declare. Also the count the lib
/// unit-test binary hashes at, see [`iterations`].
const MIN_ITERATIONS: u32 = 1_000;

/// Largest iteration count a stored hash may declare. The count comes from
/// the database; without a bound an edited row could pin a blocking thread
/// for minutes per login attempt.
const MAX_ITERATIONS: u32 = 10_000_000;

const SALT_LEN: usize = 16;
const OUTPUT_LEN: usize = 32;

/// Accepted derived-key lengths on verify (we always write [`OUTPUT_LEN`]).
const MIN_STORED_OUTPUT_LEN: usize = 16;
const MAX_STORED_OUTPUT_LEN: usize = 64;

/// Environment variable selecting the [`LegacyHashPolicy`].
pub const POLICY_ENV: &str = "FIPS_LEGACY_PASSWORD_HASHES";

/// The iteration count every new hash is written with.
///
/// Production is [`PRODUCTION_ITERATIONS`]. The lib unit-test binary uses
/// [`MIN_ITERATIONS`] for the same reason it hashes bcrypt at cost 4 (#3407,
/// see `auth_service::bcrypt_cost`): every authenticating test holds an
/// auth-concurrency permit for the whole computation. `cfg(test)` is never
/// set for the shipped binary.
#[cfg(not(test))]
pub(crate) fn iterations() -> u32 {
    PRODUCTION_ITERATIONS
}

/// See [`iterations`]: the test-binary work factor.
#[cfg(test)]
pub(crate) fn iterations() -> u32 {
    MIN_ITERATIONS
}

/// What a `fips` build does with a bcrypt hash written by a default build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyHashPolicy {
    /// `rehash` (the default): verify the bcrypt hash once, and on success
    /// the caller replaces it with a PBKDF2 hash. bcrypt runs only for
    /// accounts and tokens that still carry a legacy hash, and only until
    /// their next successful use.
    Rehash,
    /// `refuse`: a bcrypt hash never verifies. The account needs a password
    /// reset (or the API token a reissue) by an administrator.
    Refuse,
}

impl LegacyHashPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rehash => "rehash",
            Self::Refuse => "refuse",
        }
    }
}

/// Parse a [`POLICY_ENV`] value. Unset or empty is the default, `rehash`.
pub fn parse_policy(value: Option<&str>) -> std::result::Result<LegacyHashPolicy, String> {
    let value = value.map(str::trim).unwrap_or("");
    if value.is_empty() || value.eq_ignore_ascii_case("rehash") {
        Ok(LegacyHashPolicy::Rehash)
    } else if value.eq_ignore_ascii_case("refuse") {
        Ok(LegacyHashPolicy::Refuse)
    } else {
        Err(format!(
            "{POLICY_ENV}={value:?} is not recognised: expected `rehash` (the default) or `refuse`"
        ))
    }
}

static POLICY: OnceLock<LegacyHashPolicy> = OnceLock::new();

/// The process-wide policy, read from [`POLICY_ENV`] once.
///
/// `main` calls [`validate_policy_env`] at startup and refuses to start on an
/// unknown value, so the fallback here only matters for a caller that never
/// went through `main` (a test, an embedding): it fails closed to `refuse`
/// and logs why once.
pub fn legacy_policy() -> LegacyHashPolicy {
    *POLICY.get_or_init(
        || match parse_policy(std::env::var(POLICY_ENV).ok().as_deref()) {
            Ok(policy) => policy,
            Err(e) => {
                tracing::error!(
                    target: "security",
                    "{e}; treating legacy bcrypt password hashes as `refuse`"
                );
                LegacyHashPolicy::Refuse
            }
        },
    )
}

/// Startup check: parse [`POLICY_ENV`] and fix the process-wide policy, or
/// return the error that should stop the server from starting.
pub fn validate_policy_env() -> std::result::Result<LegacyHashPolicy, String> {
    let policy = parse_policy(std::env::var(POLICY_ENV).ok().as_deref())?;
    Ok(*POLICY.get_or_init(|| policy))
}

/// True for a bcrypt modular-crypt string, the format a default build writes.
pub fn is_legacy_bcrypt(hash: &str) -> bool {
    ["$2a$", "$2b$", "$2x$", "$2y$"]
        .iter()
        .any(|p| hash.starts_with(p))
}

/// True for a hash in this module's PBKDF2 format (well-formed or not).
pub fn is_pbkdf2(hash: &str) -> bool {
    hash.starts_with(PREFIX)
}

/// Whether a stored hash that just verified should be replaced: it is a
/// legacy bcrypt hash, or a PBKDF2 hash with fewer iterations than new hashes
/// get.
pub fn needs_rehash(hash: &str) -> bool {
    if is_legacy_bcrypt(hash) {
        return true;
    }
    match parse(hash) {
        Ok(parsed) => parsed.iterations.get() < iterations(),
        Err(_) => false,
    }
}

/// Hash `secret` with a fresh random salt at `iterations`.
pub fn hash(secret: &str, iterations: u32) -> Result<String> {
    let rounds = NonZeroU32::new(iterations)
        .filter(|n| (MIN_ITERATIONS..=MAX_ITERATIONS).contains(&n.get()))
        .ok_or_else(|| {
            AppError::Internal(format!(
                "Password hashing failed: iteration count {iterations} out of range"
            ))
        })?;
    let mut salt = [0u8; SALT_LEN];
    SystemRandom::new().fill(&mut salt).map_err(|_| {
        AppError::Internal("Password hashing failed: random salt unavailable".to_string())
    })?;
    let mut derived = [0u8; OUTPUT_LEN];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        rounds,
        &salt,
        secret.as_bytes(),
        &mut derived,
    );
    Ok(format!(
        "{PREFIX}i={}${}${}",
        rounds.get(),
        STANDARD_NO_PAD.encode(salt),
        STANDARD_NO_PAD.encode(derived)
    ))
}

#[derive(Debug)]
struct Parsed {
    iterations: NonZeroU32,
    salt: Vec<u8>,
    derived: Vec<u8>,
}

fn malformed(what: &str) -> AppError {
    AppError::Internal(format!(
        "Password verification failed: malformed PBKDF2 hash ({what})"
    ))
}

fn parse(stored: &str) -> Result<Parsed> {
    let rest = stored
        .strip_prefix(PREFIX)
        .ok_or_else(|| malformed("scheme"))?;
    let mut fields = rest.splitn(3, '$');
    let params = fields.next().ok_or_else(|| malformed("parameters"))?;
    let salt = fields.next().ok_or_else(|| malformed("salt"))?;
    let derived = fields.next().ok_or_else(|| malformed("derived key"))?;

    let digits = params
        .strip_prefix("i=")
        .ok_or_else(|| malformed("parameters"))?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(malformed("iteration count"));
    }
    let iterations = digits
        .parse::<u32>()
        .ok()
        .filter(|n| (MIN_ITERATIONS..=MAX_ITERATIONS).contains(n))
        .and_then(NonZeroU32::new)
        .ok_or_else(|| malformed("iteration count"))?;

    let salt = STANDARD_NO_PAD
        .decode(salt)
        .map_err(|_| malformed("salt"))?;
    if salt.len() < SALT_LEN {
        return Err(malformed("salt"));
    }
    let derived = STANDARD_NO_PAD
        .decode(derived)
        .map_err(|_| malformed("derived key"))?;
    if !(MIN_STORED_OUTPUT_LEN..=MAX_STORED_OUTPUT_LEN).contains(&derived.len()) {
        return Err(malformed("derived key"));
    }
    Ok(Parsed {
        iterations,
        salt,
        derived,
    })
}

/// Constant-time PBKDF2 verify (`aws_lc_rs::pbkdf2::verify`).
fn verify_pbkdf2(secret: &str, stored: &str) -> Result<bool> {
    let parsed = parse(stored)?;
    Ok(pbkdf2::verify(
        pbkdf2::PBKDF2_HMAC_SHA256,
        parsed.iterations,
        &parsed.salt,
        secret.as_bytes(),
        &parsed.derived,
    )
    .is_ok())
}

/// A PBKDF2 hash of a fixed throwaway value at [`iterations`], generated once:
/// the timing pad for rejection arms that have no stored hash of their own,
/// so an unknown username costs the same as a wrong password.
pub fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new(); //NOSONAR - intentional dummy hash for constant-time rejection
    DUMMY.get_or_init(|| {
        hash("__dummy_timing_pad__", iterations()).expect("PBKDF2 hash generation must not fail")
    })
}

/// Verify `secret` against `stored`, dispatching on the stored format.
///
/// * PBKDF2: verified in the FIPS module.
/// * bcrypt: per `policy`. `Rehash` verifies it with bcrypt (logged as a
///   non-approved legacy verification); `Refuse` never matches, after paying
///   the PBKDF2 timing pad so a legacy account is not distinguishable by
///   response time.
/// * anything else: an error, as an unparseable bcrypt hash is in the default
///   build.
///
/// Blocking (CPU-bound); callers run it under the auth permit on a blocking
/// thread.
pub fn verify(secret: &str, stored: &str, policy: LegacyHashPolicy) -> Result<bool> {
    if is_pbkdf2(stored) {
        return verify_pbkdf2(secret, stored);
    }
    if !is_legacy_bcrypt(stored) {
        return Err(AppError::Internal(
            "Password verification failed: unrecognised hash format".to_string(),
        ));
    }
    match policy {
        LegacyHashPolicy::Rehash => {
            tracing::warn!(
                target: "security",
                policy = policy.as_str(),
                "verifying a legacy bcrypt hash, which is not a FIPS-approved algorithm; \
                 it is replaced with PBKDF2-HMAC-SHA256 once it verifies"
            );
            bcrypt::verify(secret, stored)
                .map_err(|e| AppError::Internal(format!("Password verification failed: {e}")))
        }
        LegacyHashPolicy::Refuse => {
            tracing::warn!(
                target: "security",
                policy = policy.as_str(),
                "refused a legacy bcrypt password or token hash ({POLICY_ENV}=refuse); \
                 the account needs a password reset, or the API token a reissue"
            );
            let _ = verify_pbkdf2(secret, dummy_hash());
            Ok(false)
        }
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_wrong_secret() {
        let h = hash("correct horse", iterations()).unwrap();
        assert!(is_pbkdf2(&h));
        assert!(verify("correct horse", &h, LegacyHashPolicy::Refuse).unwrap());
        assert!(!verify("correct horsf", &h, LegacyHashPolicy::Refuse).unwrap());
        assert!(!verify("", &h, LegacyHashPolicy::Refuse).unwrap());
    }

    #[test]
    fn format_is_phc_style_with_16_byte_salt_and_32_byte_key() {
        let h = hash("pw", 1234).unwrap();
        let fields: Vec<&str> = h.split('$').collect();
        assert_eq!(fields.len(), 5, "{h}");
        assert_eq!(fields[0], "");
        assert_eq!(fields[1], "pbkdf2-sha256");
        assert_eq!(fields[2], "i=1234");
        assert_eq!(STANDARD_NO_PAD.decode(fields[3]).unwrap().len(), SALT_LEN);
        assert_eq!(STANDARD_NO_PAD.decode(fields[4]).unwrap().len(), OUTPUT_LEN);
        assert!(
            !fields[3].contains('=') && !fields[4].contains('='),
            "no base64 padding: {h}"
        );
    }

    #[test]
    fn salts_differ_between_hashes() {
        let a = hash("same", iterations()).unwrap();
        let b = hash("same", iterations()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn production_iteration_count_is_owasp_2023() {
        assert_eq!(PRODUCTION_ITERATIONS, 600_000);
        // The test binary hashes cheaply (#3407).
        assert_eq!(iterations(), MIN_ITERATIONS);
    }

    /// The count is read from the stored string, not from the current
    /// setting: a hash written at a different count still verifies, and
    /// changing the count in the string breaks it.
    #[test]
    fn iteration_count_is_parsed_from_the_stored_string() {
        let h = hash("pw", 2000).unwrap();
        assert_eq!(parse(&h).unwrap().iterations.get(), 2000);
        assert!(verify("pw", &h, LegacyHashPolicy::Refuse).unwrap());
        let edited = h.replacen("i=2000", "i=2001", 1);
        assert!(!verify("pw", &edited, LegacyHashPolicy::Refuse).unwrap());
    }

    #[test]
    fn tampered_derived_key_or_salt_does_not_verify() {
        let h = hash("pw", iterations()).unwrap();
        let fields: Vec<&str> = h.split('$').collect();
        let mut key = STANDARD_NO_PAD.decode(fields[4]).unwrap();
        key[0] ^= 1;
        let bad_key = format!(
            "$pbkdf2-sha256${}${}${}",
            fields[2],
            fields[3],
            STANDARD_NO_PAD.encode(&key)
        );
        assert!(!verify("pw", &bad_key, LegacyHashPolicy::Rehash).unwrap());

        let mut salt = STANDARD_NO_PAD.decode(fields[3]).unwrap();
        salt[0] ^= 1;
        let bad_salt = format!(
            "$pbkdf2-sha256${}${}${}",
            fields[2],
            STANDARD_NO_PAD.encode(&salt),
            fields[4]
        );
        assert!(!verify("pw", &bad_salt, LegacyHashPolicy::Rehash).unwrap());
    }

    #[test]
    fn malformed_hashes_are_errors() {
        let good = hash("pw", iterations()).unwrap();
        let fields: Vec<&str> = good.split('$').collect();
        let (salt, key) = (fields[3], fields[4]);
        for bad in [
            "$pbkdf2-sha256$".to_string(),
            format!("$pbkdf2-sha256$i=1000${salt}"),
            format!("$pbkdf2-sha256$r=1000${salt}${key}"),
            format!("$pbkdf2-sha256$i=+1000${salt}${key}"),
            format!("$pbkdf2-sha256$i=999${salt}${key}"),
            format!("$pbkdf2-sha256$i=10000001${salt}${key}"),
            format!("$pbkdf2-sha256$i=99999999999${salt}${key}"),
            format!("$pbkdf2-sha256$i=1000$AAAA${key}"),
            format!("$pbkdf2-sha256$i=1000${salt}$AAAA"),
            format!("$pbkdf2-sha256$i=1000${salt}${key}$extra"),
            format!("$pbkdf2-sha256$i=1000${salt}=${key}"),
            "not-a-valid-hash".to_string(),
            String::new(),
        ] {
            assert!(
                verify("pw", &bad, LegacyHashPolicy::Rehash).is_err(),
                "{bad:?} must be an error"
            );
        }
    }

    #[test]
    fn legacy_bcrypt_verifies_under_rehash() {
        let legacy = bcrypt::hash("old-password", 4).unwrap();
        assert!(is_legacy_bcrypt(&legacy));
        assert!(verify("old-password", &legacy, LegacyHashPolicy::Rehash).unwrap());
        assert!(!verify("wrong", &legacy, LegacyHashPolicy::Rehash).unwrap());
        assert!(needs_rehash(&legacy));
    }

    #[test]
    fn legacy_bcrypt_never_verifies_under_refuse() {
        let legacy = bcrypt::hash("old-password", 4).unwrap();
        assert!(!verify("old-password", &legacy, LegacyHashPolicy::Refuse).unwrap());
        assert!(!verify("wrong", &legacy, LegacyHashPolicy::Refuse).unwrap());
    }

    #[test]
    fn needs_rehash_only_for_legacy_or_weaker_hashes() {
        assert!(!needs_rehash(&hash("pw", iterations()).unwrap()));
        assert!(!needs_rehash(&hash("pw", iterations() + 1).unwrap()));
        assert!(needs_rehash("$2y$04$abcdefghijklmnopqrstuu"));
        assert!(!needs_rehash("not-a-hash"));
    }

    #[test]
    fn policy_parsing() {
        assert_eq!(parse_policy(None), Ok(LegacyHashPolicy::Rehash));
        assert_eq!(parse_policy(Some("")), Ok(LegacyHashPolicy::Rehash));
        assert_eq!(parse_policy(Some(" rehash ")), Ok(LegacyHashPolicy::Rehash));
        assert_eq!(parse_policy(Some("REFUSE")), Ok(LegacyHashPolicy::Refuse));
        let err = parse_policy(Some("allow")).unwrap_err();
        assert!(err.contains(POLICY_ENV), "{err}");
        assert!(parse_policy(Some("bcrypt")).is_err());
    }

    #[test]
    fn dummy_hash_is_pbkdf2_at_the_current_count_and_never_matches() {
        let dummy = dummy_hash();
        assert_eq!(dummy, dummy_hash());
        assert_eq!(parse(dummy).unwrap().iterations.get(), iterations());
        assert!(!verify("", dummy, LegacyHashPolicy::Refuse).unwrap());
        assert!(!verify("any-token-value", dummy, LegacyHashPolicy::Refuse).unwrap());
    }

    #[test]
    fn aws_lc_is_in_fips_mode_for_pbkdf2() {
        aws_lc_rs::try_fips_mode().expect("PBKDF2 must come from the FIPS module");
    }
}
