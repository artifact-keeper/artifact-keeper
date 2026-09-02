//! Cryptographic verification of publisher attestations (#2955).
//!
//! Makes `publisher_trust match:attestation` mean what it says: `verified=true`
//! is set **only** after the full provenance chain verifies. PyPI (PEP 740) is
//! supported; npm is ingested but recorded unsupported (see
//! [`NPM_UNSUPPORTED_REASON`]) — it never overclaims and stays on the shipped
//! fail-safe Flag.
//!
//! # What the crate does vs. what we do
//!
//! The verification is `sigstore` crate primitives, fail-closed at every step,
//! but two checks are **our** code because the crate does not do them (or does
//! them misleadingly) — this is exactly the hand-rolled-crypto-defect class the
//! issue exists to prevent, so it is called out explicitly:
//!
//! | Check | Who |
//! |---|---|
//! | DSSE envelope signature | crate (`verify_digest`) |
//! | Fulcio certificate chain | crate (`verify_digest`) |
//! | SCT (signed certificate timestamp) | crate (`verify_digest`) |
//! | Certificate validity at Rekor integrated time | crate (`verify_digest`) |
//! | **Rekor inclusion proof + signed checkpoint** | **us** ([`rekor_glue`]) — the crate's `verify_digest` skips it (`TODO(tnytown)` in 0.14.0 and git main; it accepts forged proofs) |
//! | **Rekor Signed Entry Timestamp (SET)** | **us** ([`rekor_glue`]) — the crate's `verify_digest` skips it too (`TODO(tnytown) SET verification`), though its *cosign* path implements the same check privately |
//! | **OIDC issuer allowlist** | **us** — the crate's `policy::AnyOf` is secretly an AND, so we iterate the allowlist |
//! | **Certificate identity extraction** | **us** ([`identity`]) — the crate exposes only assertion policies, never the parsed identity, and reads only Fulcio's deprecated `1.1` extensions |
//! | **Subject-digest binding** | **us** — the crate reports a misleading `Transparency` error; our compare distinguishes replay from a bad signature |
//! | **Claimed-publisher owner binding** | **us** — cert-bound owner must equal the self-asserted `publisher.repository` owner |
//!
//! Both `verify_digest` **and** the Rekor inclusion glue must pass. A structural
//! guard ([`AttestationVerdict::from_mask`]) makes "every check actually ran" an
//! asserted property of *our* code, not an assumption about the crate's.
//!
//! # `integratedTime` is authenticated by the SET (#3231, closed)
//!
//! The Signed Entry Timestamp is the field that binds a Rekor entry's
//! `integratedTime`. `verify_digest` does not verify it (`TODO(tnytown) SET
//! verification` in 0.14.0) and the inclusion glue does not cover it either,
//! because the SET is not part of `canonicalizedBody` and not part of the Merkle
//! leaf — so until #3231 the `integratedTime` that [`Check::CryptoAndChain`]
//! compares against the certificate's validity window was a value the bundle's
//! author chose, and that comparison was trivially satisfiable.
//!
//! [`Check::RekorSet`] now verifies it against the Rekor log key from the pinned
//! trusted root ([`rekor_glue::verify_signed_entry_timestamp`]), **fail-closed
//! including a missing `inclusionPromise`**: an entry with no SET carries no
//! authenticated timestamp, so it is rejected rather than downgraded. The
//! practical effect is that "the certificate was valid when it signed" is now an
//! independent statement by the log rather than corroborating evidence.
//!
//! The residual that remains is narrow and worth naming: verifying the SET
//! proves the log *issued a promise* for this entry at that time; it is the
//! inclusion proof ([`Check::RekorInclusion`]) that proves the entry is really
//! in the log. Both are required here, so neither stands alone.

use serde_json::Value;
use sha2::{Digest, Sha256};

pub mod bundle_convert;
pub mod identity;
pub mod rekor_glue;
pub mod trust_root;

pub use trust_root::TrustRoot;

/// Default OIDC issuer allowlist: GitHub Actions first. Extensible — a future
/// config surface can widen it (e.g. GitLab CI). We iterate this list and
/// accept the first match, because `sigstore::bundle::verify::policy::AnyOf` is
/// implemented as a logical AND (it rejects the moment the list has >1 entry).
pub const DEFAULT_ISSUER_ALLOWLIST: &[&str] = &["https://token.actions.githubusercontent.com"];

/// Why npm attestations are recorded unsupported rather than verified.
///
/// npm provenance binds its subject with **sha512 only**, and `sigstore` 0.14.0
/// hard-requires a sha256 subject at bundle construction — every npm bundle
/// dies before any crypto, universally (surveyed across packages in Stage 1).
/// The upstream limitation is sigstore-rs#596, with a fix proposed in
/// sigstore-rs#615. Until that lands and releases, npm stays on the fail-safe
/// Flag with this reason so nothing overclaims.
pub const NPM_UNSUPPORTED_REASON: &str = "attestation format unsupported: npm sha512-only subject binding is not verifiable by sigstore-rs 0.14.0 (https://github.com/sigstore/sigstore-rs/issues/596; fix proposed in https://github.com/sigstore/sigstore-rs/pull/615); npm stays on fail-safe review until it lands";

/// The ordered verification checks. `verified=true` requires **all** of them to
/// pass; the coverage bitmask records which ran so success cannot be reached
/// with any check skipped. The discriminant is the bit position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Check {
    /// Bundle deserializes, has exactly one tlog entry, v0.2/v0.3 profile.
    BundleWellFormed = 0,
    /// Statement subject sha256 == artifact digest, and subject name ==
    /// distribution filename (our own compare; distinguishes replay).
    SubjectDigestBound = 1,
    /// `verify_digest`: DSSE signature, Fulcio chain, SCT, cert validity at the
    /// Rekor integrated time.
    CryptoAndChain = 2,
    /// Rekor inclusion proof + signed checkpoint (our glue).
    RekorInclusion = 3,
    /// Leaf-certificate identity parsed (SAN, issuer, repository/owner).
    IdentityExtracted = 4,
    /// Certificate OIDC issuer is on the allowlist (our own iteration).
    IssuerAllowlisted = 5,
    /// Cert-bound repository owner == claimed `publisher.repository` owner.
    PublisherOwnerBound = 6,
    /// Rekor Signed Entry Timestamp, which authenticates `integratedTime` (our
    /// glue — #3231). Runs *before* [`Check::RekorInclusion`] (the order the
    /// crate's own cosign path uses), but takes the next free bit rather than
    /// renumbering, so every bit position already reported in a log line or a
    /// verdict keeps meaning what it meant.
    RekorSet = 7,
}

impl Check {
    fn bit(self) -> u16 {
        1 << (self as u16)
    }

    fn reason_label(self) -> &'static str {
        match self {
            Check::BundleWellFormed => "bundle",
            Check::SubjectDigestBound => "subject binding",
            Check::CryptoAndChain => "signature/certificate chain",
            Check::RekorSet => "transparency (Rekor SET)",
            Check::RekorInclusion => "transparency (Rekor inclusion)",
            Check::IssuerAllowlisted => "issuer",
            Check::IdentityExtracted => "identity",
            Check::PublisherOwnerBound => "identity binding",
        }
    }
}

/// All checks in order; `ALL_MASK` is the bitmask with every check set.
pub const ALL_CHECKS: &[Check] = &[
    Check::BundleWellFormed,
    Check::SubjectDigestBound,
    Check::CryptoAndChain,
    Check::RekorSet,
    Check::RekorInclusion,
    Check::IdentityExtracted,
    Check::IssuerAllowlisted,
    Check::PublisherOwnerBound,
];

/// The bitmask value that means every check passed.
pub fn all_mask() -> u16 {
    ALL_CHECKS.iter().fold(0, |m, c| m | c.bit())
}

/// Persisted verification state (mirrors the `attestation_state` column).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationState {
    /// No verification attempted / no material present.
    Unverified,
    /// Full chain verified: safe to set `verified=true`.
    Verified,
    /// Material present but verification failed (includes the npm-unsupported
    /// case, distinguished by the error string).
    Failed,
}

impl AttestationState {
    pub fn as_str(self) -> &'static str {
        match self {
            AttestationState::Unverified => "unverified",
            AttestationState::Verified => "verified",
            AttestationState::Failed => "failed",
        }
    }
}

/// The outcome of an attestation verification attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationVerdict {
    pub state: AttestationState,
    /// Cert-bound workflow identity (SAN URI) — present only on success.
    pub identity: Option<String>,
    /// Cert-bound repository owner (org/user) — the value that may set
    /// `verified=true`. Present only on success. Never from the metadata blob.
    pub owner: Option<String>,
    /// Cert-bound `owner/repo` — present only on success.
    pub repository: Option<String>,
    /// OIDC issuer — present only on success.
    pub issuer: Option<String>,
    /// Specific failing-check reason (or unsupported reason).
    pub error: Option<String>,
    /// Coverage bitmask of checks that passed.
    pub checks_passed: u16,
}

impl AttestationVerdict {
    /// A clean "no attestation material / nothing attempted" verdict.
    pub fn unverified() -> Self {
        Self {
            state: AttestationState::Unverified,
            identity: None,
            owner: None,
            repository: None,
            issuer: None,
            error: None,
            checks_passed: 0,
        }
    }

    /// A failure verdict for the given check with a specific reason.
    fn failed(check: Check, mask: u16, reason: impl Into<String>) -> Self {
        Self {
            state: AttestationState::Failed,
            identity: None,
            owner: None,
            repository: None,
            issuer: None,
            error: Some(format!("{}: {}", check.reason_label(), reason.into())),
            checks_passed: mask,
        }
    }

    /// A bare failure with a caller-supplied reason (no single check).
    pub fn failure(reason: impl Into<String>) -> Self {
        Self {
            state: AttestationState::Failed,
            identity: None,
            owner: None,
            repository: None,
            issuer: None,
            error: Some(reason.into()),
            checks_passed: 0,
        }
    }

    /// **The structural short-circuit guard.** A verdict is `Verified` if and
    /// only if the coverage bitmask has *every* check set. This is the only
    /// place a *live* verification can mint a `Verified` state, so "no check was
    /// skipped" is a property of our code — proven by
    /// [`tests::success_requires_every_check`].
    ///
    /// The one other minting site is [`AttestationVerdict::from_record`], which
    /// re-hydrates a verdict this function already produced and persisted; it
    /// runs no checks of its own and is reachable only through
    /// [`reusable_verdict`]'s guards.
    fn from_mask(mask: u16, id: &identity::CertIdentity) -> Self {
        if mask != all_mask() {
            // Defensive: a caller that reached here without all bits is a bug;
            // fail closed rather than mint trust.
            return Self::failure(format!(
                "internal: verification reached finalize with incomplete coverage mask {mask:#b}"
            ));
        }
        Self {
            state: AttestationState::Verified,
            identity: id.san.first().cloned(),
            owner: id.owner(),
            repository: id.repository(),
            issuer: id.issuer.clone(),
            error: None,
            checks_passed: mask,
        }
    }

    /// Re-hydrate a `Verified` verdict from the persisted record of an earlier
    /// successful verification (#3230). Private on purpose: the only caller is
    /// [`reusable_verdict`], which owns the guards that decide the record may
    /// stand in for a fresh run.
    ///
    /// `repository` is `None` because migration 195 records the cert-bound
    /// *owner* and identity but not the repository; the owner is what the
    /// publisher binding and [`verified_marker`] consume.
    fn from_record(identity: &str, issuer: &str, owner: &str) -> Self {
        Self {
            state: AttestationState::Verified,
            identity: Some(identity.to_string()),
            owner: Some(owner.to_string()),
            repository: None,
            issuer: Some(issuer.to_string()),
            error: None,
            checks_passed: all_mask(),
        }
    }

    pub fn is_verified(&self) -> bool {
        self.state == AttestationState::Verified
    }
}

/// Everything the PyPI verification needs, all offline once assembled.
pub struct PypiVerifyInput<'a> {
    /// The exact distribution file bytes (wheel / sdist) being gated.
    pub artifact_bytes: &'a [u8],
    /// The distribution filename (matched against the statement subject name).
    pub expected_filename: &'a str,
    /// The self-asserted `publisher.repository` claim (`owner/repo`), compared
    /// against the certificate — never trusted on its own.
    pub claimed_repository: &'a str,
    /// OIDC issuer allowlist (use [`DEFAULT_ISSUER_ALLOWLIST`]).
    pub issuer_allowlist: &'a [String],
}

/// A no-op verification policy: makes `verify_digest` run the DSSE signature,
/// Fulcio chain, SCT, and cert-validity checks **without** asserting identity —
/// we extract and check identity/issuer/owner ourselves, post-verification,
/// against Fulcio's current `1.8` extensions (the crate policies read only the
/// deprecated `1.1` extensions).
struct AcceptCryptoOnly;

impl sigstore::bundle::verify::policy::VerificationPolicy for AcceptCryptoOnly {
    fn verify(
        &self,
        _cert: &x509_cert::Certificate,
    ) -> sigstore::bundle::verify::policy::PolicyResult {
        Ok(())
    }
}

fn subject_of(statement: &Value) -> Option<(&str, &str)> {
    let subj = statement.get("subject")?.as_array()?.first()?;
    let name = subj.get("name")?.as_str()?;
    let sha256 = subj.get("digest")?.get("sha256")?.as_str()?;
    Some((name, sha256))
}

/// Verify one already-converted PEP 740 sigstore bundle against an artifact.
///
/// Runs the full ordered chain, fail-closed, and returns a typed verdict whose
/// `error` names the *specific* failing check. `verified=true` (from
/// [`AttestationVerdict::from_mask`]) requires every check to have passed.
pub async fn verify_pypi_bundle(
    bundle_json: &Value,
    input: &PypiVerifyInput<'_>,
    trust: &TrustRoot,
) -> AttestationVerdict {
    let mut mask: u16 = 0;

    // 1) Bundle well-formed: deserialize + exactly one tlog entry + statement
    //    present. (`verify_digest` re-checks the tlog count; we pre-check for a
    //    clean reason and to read the subject.)
    let statement = match bundle_convert::statement_of(bundle_json) {
        Ok(s) => s,
        Err(e) => return AttestationVerdict::failed(Check::BundleWellFormed, mask, e.to_string()),
    };
    let tlog_count = bundle_json
        .get("verificationMaterial")
        .and_then(|v| v.get("tlogEntries"))
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    if tlog_count != 1 {
        return AttestationVerdict::failed(
            Check::BundleWellFormed,
            mask,
            format!("bundle must carry exactly one tlog entry, found {tlog_count}"),
        );
    }
    mask |= Check::BundleWellFormed.bit();

    // Artifact digest (our own — SHA-256 of the exact bytes being gated).
    let artifact_sha256 = hex::encode(Sha256::digest(input.artifact_bytes));

    // 2) Subject-digest binding (OUR compare). Done before the crypto so a
    //    replay (valid attestation for a different artifact) is reported as a
    //    subject-binding failure, not the crate's misleading `Transparency`
    //    error. A mismatch rejects; a match is still cryptographically
    //    confirmed by step 3 — no trust is placed in the unverified payload.
    let (subj_name, subj_sha256) = match subject_of(&statement) {
        Some(s) => s,
        None => {
            return AttestationVerdict::failed(
                Check::SubjectDigestBound,
                mask,
                "statement carries no subject[0].digest.sha256",
            )
        }
    };
    if !subj_sha256.eq_ignore_ascii_case(&artifact_sha256) {
        return AttestationVerdict::failed(
            Check::SubjectDigestBound,
            mask,
            format!(
                "statement subject sha256 {} does not match artifact sha256 {}",
                short(subj_sha256),
                short(&artifact_sha256)
            ),
        );
    }
    if subj_name != input.expected_filename {
        return AttestationVerdict::failed(
            Check::SubjectDigestBound,
            mask,
            format!(
                "statement subject name `{subj_name}` != distribution filename `{}`",
                input.expected_filename
            ),
        );
    }
    mask |= Check::SubjectDigestBound.bit();

    // 3) Crypto + chain via the crate: DSSE signature, Fulcio chain, SCT, cert
    //    validity at the Rekor integrated time. Identity is NOT asserted here
    //    (pass-through policy) — we do it ourselves below.
    let verifier = match trust.verifier() {
        Ok(v) => v,
        Err(e) => {
            return AttestationVerdict::failed(
                Check::CryptoAndChain,
                mask,
                format!("trust root unusable: {e}"),
            )
        }
    };
    let bundle = match serde_json::from_value::<sigstore::bundle::Bundle>(bundle_json.clone()) {
        Ok(b) => b,
        Err(e) => {
            return AttestationVerdict::failed(
                Check::CryptoAndChain,
                mask,
                format!("bundle does not deserialize: {e}"),
            )
        }
    };
    let mut hasher = Sha256::new();
    hasher.update(input.artifact_bytes);
    if let Err(e) = verifier
        .verify_digest(hasher, bundle, &AcceptCryptoOnly, /* offline = */ true)
        .await
    {
        return AttestationVerdict::failed(
            Check::CryptoAndChain,
            mask,
            format!("{}: {}", verification_error_class(&e), err_chain(&e)),
        );
    }
    mask |= Check::CryptoAndChain.bit();

    // 4a) Rekor Signed Entry Timestamp (OUR glue — #3231). Runs before the
    //     inclusion proof, the order the crate's own cosign path uses. This is
    //     what makes the `integratedTime` that step 3 just compared against the
    //     certificate's validity window a value the LOG asserted rather than one
    //     the bundle's author picked. Fail-closed, missing promise included.
    if let Err(e) = rekor_glue::verify_signed_entry_timestamp(bundle_json, trust.bytes()) {
        return AttestationVerdict::failed(Check::RekorSet, mask, format!("{e:#}"));
    }
    mask |= Check::RekorSet.bit();

    // 4b) Rekor inclusion proof + signed checkpoint (OUR glue over the crate's
    //    own primitives — `verify_digest` skips this entirely).
    if let Err(e) = rekor_glue::verify_inclusion(bundle_json, trust.bytes()) {
        return AttestationVerdict::failed(Check::RekorInclusion, mask, format!("{e:#}"));
    }
    mask |= Check::RekorInclusion.bit();

    // 5) Extract identity from the leaf certificate — AFTER verification, so we
    //    are reading a certificate the chain already vouched for.
    let der = match bundle_convert::leaf_cert_der(bundle_json) {
        Ok(d) => d,
        Err(e) => return AttestationVerdict::failed(Check::IdentityExtracted, mask, e.to_string()),
    };
    let id = match identity::extract(&der) {
        Ok(i) => i,
        Err(e) => return AttestationVerdict::failed(Check::IdentityExtracted, mask, e.to_string()),
    };
    if id.san.is_empty() || id.repository().is_none() {
        return AttestationVerdict::failed(
            Check::IdentityExtracted,
            mask,
            "certificate carries no usable SAN / repository identity",
        );
    }
    mask |= Check::IdentityExtracted.bit();

    // 6) Issuer allowlist (OUR iteration — never `policy::AnyOf`).
    let issuer = id.issuer.clone().unwrap_or_default();
    if !input
        .issuer_allowlist
        .iter()
        .any(|allowed| allowed == &issuer)
    {
        return AttestationVerdict::failed(
            Check::IssuerAllowlisted,
            mask,
            format!("OIDC issuer `{issuer}` is not on the allowlist"),
        );
    }
    mask |= Check::IssuerAllowlisted.bit();

    // 7) Claimed-publisher owner binding: the cert-bound owner must equal the
    //    self-asserted `publisher.repository` owner. The verified name comes
    //    from the CERTIFICATE, never from the forgeable claim.
    let cert_owner = id.owner().unwrap_or_default();
    let claimed_owner = input
        .claimed_repository
        .split('/')
        .next()
        .unwrap_or("")
        .trim();
    if cert_owner.is_empty() || !cert_owner.eq_ignore_ascii_case(claimed_owner) {
        return AttestationVerdict::failed(
            Check::PublisherOwnerBound,
            mask,
            format!("cert-bound owner `{cert_owner}` != claimed publisher owner `{claimed_owner}`"),
        );
    }
    mask |= Check::PublisherOwnerBound.bit();

    AttestationVerdict::from_mask(mask, &id)
}

/// Verify a full PyPI PEP 740 provenance document against an artifact. Iterates
/// every `attestation_bundles[].attestations[]` and returns the first that
/// verifies; if none verify, returns the last failure (or an empty-material
/// failure). The claimed publisher for the owner binding is taken from the same
/// bundle's `publisher` block (self-asserted; only trusted once the cert
/// confirms it).
pub async fn verify_pypi_provenance(
    provenance: &Value,
    artifact_bytes: &[u8],
    expected_filename: &str,
    issuer_allowlist: &[String],
    trust: &TrustRoot,
) -> AttestationVerdict {
    let converted = bundle_convert::provenance_to_bundles(provenance);
    if converted.is_empty() {
        return AttestationVerdict::failure(
            "no convertible PEP 740 attestation found in provenance document".to_string(),
        );
    }
    let mut last = AttestationVerdict::unverified();
    for ca in &converted {
        let claimed_repository = ca.publisher.repository.clone().unwrap_or_default();
        let input = PypiVerifyInput {
            artifact_bytes,
            expected_filename,
            claimed_repository: &claimed_repository,
            issuer_allowlist,
        };
        let v = verify_pypi_bundle(&ca.bundle_json, &input, trust).await;
        if v.is_verified() {
            return v;
        }
        last = v;
    }
    last
}

/// Build the metadata-context marker the evaluation loop injects on a
/// verification SUCCESS. Consumed by
/// [`crate::services::curation::publisher_source::extract_publisher`], which
/// emits the CERT-BOUND owner with `verified = true`. Returns `None` for any
/// non-verified verdict, so a failure can never inject trust (fail-safe).
pub fn verified_marker(verdict: &AttestationVerdict) -> Option<Value> {
    if !verdict.is_verified() {
        return None;
    }
    Some(serde_json::json!({
        "state": "verified",
        "owner": verdict.owner,
        "identity": verdict.identity,
        "issuer": verdict.issuer,
    }))
}

/// Prepare the evaluation-context metadata for one catalog row: drop whatever
/// verification marker the stored row carried, then inject the one this
/// `verdict` earns (if any). Returns `true` if a pre-existing marker was
/// dropped, which is always worth logging — a persisted marker can only come
/// from a blob that asserted its own verification.
///
/// The marker is a trusted server-side assertion: `extract_publisher`
/// short-circuits on it and returns `verified = true`. Strip-then-inject in one
/// place is what keeps "the only way to reach the verified arm is a verdict we
/// produced" true at every call site.
pub fn apply_verified_marker(metadata: &mut Value, verdict: Option<&AttestationVerdict>) -> bool {
    let dropped = crate::services::curation::publisher_source::strip_verification_marker(metadata);
    if let Some(marker) = verdict.and_then(verified_marker) {
        if let Some(obj) = metadata.as_object_mut() {
            obj.insert(
                crate::services::curation::publisher_source::VERIFICATION_MARKER.to_string(),
                marker,
            );
        }
    }
    dropped
}

/// How long a persisted `verified` record may be reused before the verification
/// is re-run against the upstream distribution (#3230).
///
/// A verification is a statement about an immutable artifact digest, so it does
/// not go stale the way a vulnerability scan does. What *can* change under it is
/// the policy the statement was made against: the OIDC issuer allowlist (checked
/// explicitly below, so a narrowed allowlist invalidates the record
/// immediately), the pinned Sigstore trusted root, and the certificate-chain and
/// transparency logic in this module and the crate under it. A bounded window
/// makes those re-run on their own without an operator having to know they must
/// force a re-verification.
pub const VERIFIED_RECORD_MAX_AGE_DAYS: i64 = 30;

/// The persisted attestation-verification record of one curation row — the
/// columns migration 195 added, read back (#3230).
///
/// Borrowed rather than owned so the caller can build it straight off a
/// [`crate::models::curation::CurationPackage`] with no allocation.
#[derive(Debug, Clone, Copy)]
pub struct AttestationRecord<'a> {
    /// `attestation_state`: `unverified` | `verified` | `failed`.
    pub state: &'a str,
    /// `attestation_identity` — the cert-bound workflow identity (SAN URI).
    pub identity: Option<&'a str>,
    /// `attestation_issuer` — the cert-bound OIDC issuer.
    pub issuer: Option<&'a str>,
    /// `attestation_owner` — the cert-bound repository owner.
    pub owner: Option<&'a str>,
    /// `attestation_verified_at` — when verification last ran.
    pub verified_at: Option<chrono::DateTime<chrono::Utc>>,
    /// `upstream_updated_at` — when the row's catalog content was last
    /// re-ingested from the upstream. A record older than this describes
    /// *different* row content and must not be reused.
    pub upstream_updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl<'a> AttestationRecord<'a> {
    /// Read the record off a catalog row.
    pub fn of(pkg: &'a crate::models::curation::CurationPackage) -> Self {
        Self {
            state: pkg.attestation_state.as_str(),
            identity: pkg.attestation_identity.as_deref(),
            issuer: pkg.attestation_issuer.as_deref(),
            owner: pkg.attestation_owner.as_deref(),
            verified_at: pkg.attestation_verified_at,
            upstream_updated_at: pkg.upstream_updated_at,
        }
    }
}

/// Rehydrate a `Verified` verdict from a persisted record, or `None` if the
/// record cannot be trusted to stand in for a fresh verification (#3230).
///
/// This is what stops a verification from evaporating with the scheduler tick
/// that computed it: without it, any later re-evaluation of the row — an
/// operator resetting a package to `pending`, `re_evaluate_pending`, a manual
/// sync — loses `verified = true` and an `approved` package silently returns to
/// `review`. It also means a re-evaluation does not re-download the distribution
/// from the upstream, which is the reason the columns were added.
///
/// Fail-safe: every guard below returning `None` means "verify again", never
/// "trust anyway". `None` is therefore always at most today's behaviour.
///
/// Guards, in order:
/// 1. the record says `verified` (the column is `CHECK`-constrained to the three
///    states, and only [`verified_marker`]'s own source can write `verified`);
/// 2. all three cert-bound values are present and non-empty — a `verified` row
///    without them is a partial write, not a verification;
/// 3. the recorded issuer is **still** on the caller's current allowlist, so
///    narrowing the allowlist takes effect on the next evaluation rather than at
///    the next re-verification window;
/// 4. the record is within [`VERIFIED_RECORD_MAX_AGE_DAYS`];
/// 5. the row has not been re-ingested from the upstream since the record was
///    written (`upstream_updated_at <= verified_at`) — otherwise the record
///    describes content the row no longer carries.
pub fn reusable_verdict(
    record: &AttestationRecord<'_>,
    issuer_allowlist: &[String],
    now: chrono::DateTime<chrono::Utc>,
) -> Option<AttestationVerdict> {
    if record.state != AttestationState::Verified.as_str() {
        return None;
    }
    fn nonempty(v: Option<&str>) -> Option<&str> {
        v.map(str::trim).filter(|s| !s.is_empty())
    }
    let identity = nonempty(record.identity)?;
    let issuer = nonempty(record.issuer)?;
    let owner = nonempty(record.owner)?;

    if !issuer_allowlist.iter().any(|allowed| allowed == issuer) {
        return None;
    }

    let verified_at = record.verified_at?;
    if now.signed_duration_since(verified_at) > chrono::Duration::days(VERIFIED_RECORD_MAX_AGE_DAYS)
    {
        return None;
    }
    if let Some(updated) = record.upstream_updated_at {
        if updated > verified_at {
            return None;
        }
    }

    Some(AttestationVerdict::from_record(identity, issuer, owner))
}

/// npm verification: ingested but unsupported. Always returns a `Failed`
/// verdict carrying [`NPM_UNSUPPORTED_REASON`] — npm must never set
/// `verified=true` (it stays on the shipped fail-safe Flag).
pub fn verify_npm_unsupported() -> AttestationVerdict {
    AttestationVerdict::failure(NPM_UNSUPPORTED_REASON.to_string())
}

fn short(hex: &str) -> String {
    hex.chars().take(16).collect()
}

fn verification_error_class(e: &sigstore::bundle::verify::VerificationError) -> &'static str {
    use sigstore::bundle::verify::VerificationError as V;
    match e {
        V::Input(_) => "input",
        V::Bundle(_) => "bundle",
        V::Certificate(_) => "certificate",
        V::Signature(_) => "signature",
        V::Policy(_) => "policy",
    }
}

fn err_chain(e: &sigstore::bundle::verify::VerificationError) -> String {
    let mut s = format!("{e}");
    let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(e);
    while let Some(inner) = src {
        s.push_str(&format!(" <- {inner}"));
        src = inner.source();
    }
    s
}

#[cfg(test)]
mod tests;
