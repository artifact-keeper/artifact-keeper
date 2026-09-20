//! CEP-27 conda publish-attestation verification (#4048).
//!
//! # What was wrong
//!
//! The conda attestation endpoint used to check the in-toto Statement's
//! *shape*: `_type`, `predicateType`, exactly one subject, subject name ==
//! filename, subject digest == the package's stored sha256. That is
//! well-formedness, not verification. No signature was checked, no
//! transparency-log entry, no identity. The only thing binding the document to
//! the package was a digest, and **an attacker who can write to the channel
//! controls both the package and the digest** — so they can always write a
//! matching attestation. It was attestation theatre in exactly the sense
//! [`super`] was written to prevent for PyPI.
//!
//! # What CEP-27 actually says
//!
//! The Statement is distributed **only inside a Sigstore bundle**, never as
//! bare JSON. The old endpoint therefore accepted the unsigned *payload* of an
//! attestation and rejected every real one, so there is no
//! backwards-compatible client to preserve: a bare Statement is now rejected
//! outright with [`BARE_STATEMENT_REASON`].
//!
//! # How this module verifies
//!
//! [`verify_conda_bundle`] runs [`super::CORE_CHECKS`] — the same
//! ecosystem-agnostic transport chain PyPI runs, including the Rekor inclusion
//! proof and SET glue the `sigstore` crate skips — and then appends
//! [`Check::StatementPolicy`], which applies the CEP-27 rules
//! ([`check_statement`]) to the statement the DSSE signature has *already*
//! vouched for. Satisfying the policy check therefore requires the Fulcio
//! signing key, not a text editor.
//!
//! [`Check::PublisherOwnerBound`] is absent by construction, not by oversight:
//! it compares the cert-bound owner against PyPI's self-asserted
//! `publisher.repository`, and CEP-27 has no claimed-publisher field to compare
//! against. See [`super::CONDA_CHECKS`].

use serde_json::Value;
use sha2::Sha256;

use super::{
    AttestationFormat, AttestationState, AttestationVerdict, Check, TrustRoot, VerifiedCore,
};

/// The in-toto Statement v1 type URI.
pub const INTOTO_STATEMENT_V1: &str = "https://in-toto.io/Statement/v1";

/// The CEP-27 predicate type for conda publish attestations.
pub const CEP27_PREDICATE_TYPE: &str =
    "https://schemas.conda.org/attestations-publish-1.schema.json";

/// Maximum length of `predicate.targetChannel`, per the CEP-27 schema's URL
/// bound (the practical browser/URL ceiling).
const MAX_TARGET_CHANNEL_LEN: usize = 2083;

/// Why a bare in-toto Statement — the shape the pre-#4048 endpoint accepted —
/// is rejected rather than checked.
pub const BARE_STATEMENT_REASON: &str = "attestation format unsupported: CEP-27 distributes the in-toto Statement only inside a Sigstore bundle; a bare Statement carries no signature, no transparency-log entry and no certificate identity, so nothing binds it to a publisher and it cannot be verified";

/// The metadata key under which a conda verification result is persisted
/// alongside the stored attestation.
pub const VERIFICATION_METADATA_KEY: &str = "attestation_verification";

/// Apply the CEP-27 statement rules to an in-toto Statement.
///
/// On success returns the `predicate.targetChannel` if one was declared (it is
/// optional), so a caller can record or policy-check the channel the publisher
/// signed for. On failure returns the specific reason.
///
/// This is the rule set ported from the old endpoint's shape check, **minus**
/// the subject-digest comparison: [`Check::SubjectDigestBound`] in
/// [`super::verify_bundle_core`] already binds `subject[0].digest.sha256` to
/// the bytes actually being gated, and does it against a hash this server
/// computed rather than a value read out of the database. The subject *name*
/// compare is kept here as well as in the core so this function is a complete,
/// independently testable statement of the CEP-27 rules.
///
/// Note what changed about the rules' *meaning* rather than their content: they
/// are now evaluated on a payload the DSSE signature covers. The same
/// predicate-type check that an attacker could trivially satisfy by typing it
/// now requires them to have signed it.
pub fn check_statement(
    statement: &Value,
    expected_filename: &str,
) -> Result<Option<String>, String> {
    let stmt_type = statement
        .get("_type")
        .and_then(Value::as_str)
        .ok_or("attestation missing '_type' field")?;
    if stmt_type != INTOTO_STATEMENT_V1 {
        return Err(format!(
            "attestation _type must be '{INTOTO_STATEMENT_V1}', got '{stmt_type}'"
        ));
    }

    let predicate_type = statement
        .get("predicateType")
        .and_then(Value::as_str)
        .ok_or("attestation missing 'predicateType' field")?;
    if predicate_type != CEP27_PREDICATE_TYPE {
        return Err(format!(
            "attestation predicateType must be '{CEP27_PREDICATE_TYPE}', got '{predicate_type}'"
        ));
    }

    let subjects = statement
        .get("subject")
        .and_then(Value::as_array)
        .ok_or("attestation missing 'subject' array")?;
    if subjects.len() != 1 {
        return Err(format!(
            "attestation subject must have exactly 1 entry, got {}",
            subjects.len()
        ));
    }
    let subject = &subjects[0];

    let name = subject
        .get("name")
        .and_then(Value::as_str)
        .ok_or("attestation subject missing 'name' field")?;
    if name != expected_filename {
        return Err(format!(
            "attestation subject name '{name}' does not match package filename '{expected_filename}'"
        ));
    }

    let sha256 = subject
        .get("digest")
        .and_then(Value::as_object)
        .ok_or("attestation subject missing 'digest' object")?
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or("attestation subject digest missing 'sha256' field")?;
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "attestation sha256 must be a 64-character hex string, got '{sha256}'"
        ));
    }

    // `predicate` is optional and may be explicitly null; when present it must
    // be an object, and a declared `targetChannel` must be a sane URL.
    let Some(predicate) = statement.get("predicate").filter(|p| !p.is_null()) else {
        return Ok(None);
    };
    let pred_obj = predicate
        .as_object()
        .ok_or("attestation predicate must be an object or null")?;
    let Some(target) = pred_obj.get("targetChannel") else {
        return Ok(None);
    };
    let url = target.as_str().ok_or("targetChannel must be a string")?;
    if url.is_empty() || url.len() > MAX_TARGET_CHANNEL_LEN {
        return Err(format!(
            "targetChannel must be 1-{MAX_TARGET_CHANNEL_LEN} characters, got {}",
            url.len()
        ));
    }
    if url.ends_with('/') {
        return Err("targetChannel must not end with a trailing slash".to_string());
    }
    Ok(Some(url.to_string()))
}

/// Everything a conda bundle verification needs.
///
/// `artifact_digest` is a `Sha256` **already fed with the exact package bytes**
/// rather than the bytes themselves: a `.conda` package can run to gigabytes
/// and the upload path streams it out of object storage, so it must never be
/// required to sit in memory as a `&[u8]`.
pub struct CondaVerifyInput<'a> {
    /// Hasher already fed with the exact package bytes being gated.
    pub artifact_digest: Sha256,
    /// The package filename (matched against the statement subject name).
    pub expected_filename: &'a str,
    /// OIDC issuer allowlist (use [`super::DEFAULT_ISSUER_ALLOWLIST`]).
    pub issuer_allowlist: &'a [String],
}

/// Is this JSON a bare in-toto Statement rather than a Sigstore bundle?
///
/// Recognised so the pre-#4048 input gets a reason that says *why* it is no
/// longer accepted, instead of the generic "no dsseEnvelope.payload" a bundle
/// parse failure would produce.
fn is_bare_statement(v: &Value) -> bool {
    v.get("dsseEnvelope").is_none()
        && v.get("verificationMaterial").is_none()
        && v.get("_type").and_then(Value::as_str).is_some()
}

/// Verify one CEP-27 Sigstore bundle against a conda package.
///
/// Runs [`super::CORE_CHECKS`] then [`Check::StatementPolicy`], fail-closed.
/// `verified=true` requires every check in [`super::CONDA_CHECKS`].
pub async fn verify_conda_bundle(
    bundle_json: &Value,
    input: CondaVerifyInput<'_>,
    trust: &TrustRoot,
) -> AttestationVerdict {
    if is_bare_statement(bundle_json) {
        return AttestationVerdict::failure(BARE_STATEMENT_REASON.to_string());
    }

    let core = match super::verify_bundle_core(
        bundle_json,
        input.artifact_digest,
        input.expected_filename,
        input.issuer_allowlist,
        trust,
    )
    .await
    {
        Ok(c) => c,
        Err(v) => return v,
    };
    let VerifiedCore {
        mut mask,
        id,
        statement,
    } = core;

    // 8) CEP-27 statement policy, on the DSSE-signed payload.
    if let Err(e) = check_statement(&statement, input.expected_filename) {
        return AttestationVerdict::failed(Check::StatementPolicy, mask, e);
    }
    mask |= Check::StatementPolicy.bit();

    AttestationVerdict::from_mask(mask, AttestationFormat::Conda, &id)
}

/// Build the JSON record of a conda verification, for persisting next to the
/// stored attestation under [`VERIFICATION_METADATA_KEY`].
///
/// Records the failure reason too: an operator looking at a rejected upload
/// needs to know *which* check failed, and `checks_passed` says how far the
/// chain got before it did.
pub fn verification_record(
    verdict: &AttestationVerdict,
    now: chrono::DateTime<chrono::Utc>,
) -> Value {
    serde_json::json!({
        "format": "conda",
        "state": verdict.state.as_str(),
        "identity": verdict.identity,
        "issuer": verdict.issuer,
        "owner": verdict.owner,
        "error": verdict.error,
        "checks_passed": verdict.checks_passed,
        "verified_at": now.to_rfc3339(),
    })
}

/// Read a persisted [`verification_record`] back into a verdict.
///
/// Fail-safe in the same shape as [`super::reusable_verdict`]: a `Verified`
/// state is re-minted **only** when the record carries the full conda coverage
/// mask, all three cert-bound values, and an issuer that is *still* on the
/// caller's current allowlist — so narrowing the allowlist takes effect on the
/// next read rather than at the next re-verification. Anything short of that
/// degrades to `Failed`, never to `Verified`.
pub fn record_to_verdict(record: &Value, issuer_allowlist: &[String]) -> AttestationVerdict {
    let state = record.get("state").and_then(Value::as_str).unwrap_or("");
    if state != AttestationState::Verified.as_str() {
        if state == AttestationState::Failed.as_str() {
            return AttestationVerdict {
                state: AttestationState::Failed,
                identity: None,
                owner: None,
                repository: None,
                issuer: None,
                error: Some(
                    record
                        .get("error")
                        .and_then(Value::as_str)
                        .unwrap_or("attestation verification failed")
                        .to_string(),
                ),
                checks_passed: record
                    .get("checks_passed")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as u16,
            };
        }
        return AttestationVerdict::unverified();
    }

    fn nonempty<'a>(record: &'a Value, key: &str) -> Option<&'a str> {
        record
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }
    let stale = |why: &str| {
        AttestationVerdict::failure(format!(
            "stored attestation verification cannot be reused ({why}); re-verify"
        ))
    };

    let mask = record
        .get("checks_passed")
        .and_then(Value::as_u64)
        .unwrap_or(0) as u16;
    if mask != AttestationFormat::Conda.required_mask() {
        return stale("incomplete coverage mask");
    }
    let (Some(identity), Some(issuer), Some(owner)) = (
        nonempty(record, "identity"),
        nonempty(record, "issuer"),
        nonempty(record, "owner"),
    ) else {
        return stale("missing cert-bound identity/issuer/owner");
    };
    if !issuer_allowlist.iter().any(|allowed| allowed == issuer) {
        return stale("recorded OIDC issuer is no longer on the allowlist");
    }

    AttestationVerdict::from_record(AttestationFormat::Conda, identity, issuer, owner)
}
