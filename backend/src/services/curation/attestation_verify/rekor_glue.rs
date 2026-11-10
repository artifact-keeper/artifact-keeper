//! Rekor transparency glue — the gap `sigstore::bundle::verify::Verifier`
//! leaves open (#2955, #3231).
//!
//! `Verifier::verify_digest` documents seven steps; steps 5 and 6 (Merkle
//! inclusion, Signed Entry Timestamp) are `TODO(tnytown)` in 0.14.0 **and on
//! git `main`**. The verifier only checks that the tlog entry is *consistent*
//! with the bundle (the CVE-2022-36056 defence), which a forger controls end to
//! end — the Stage-1 spike proved it accepts wholly forged inclusion proofs.
//!
//! The crate ships the real primitives, they are just not wired into the bundle
//! verifier:
//!   * [`sigstore::rekor::models::InclusionProof::verify`] — RFC 6962 Merkle
//!     inclusion plus signed-checkpoint verification against the log key.
//!   * [`sigstore::trust::TrustRoot::rekor_keys`] — the log keys, keyed by
//!     `hex(logId.keyId)`.
//!   * [`sigstore::crypto::CosignVerificationKey::try_from_der`] and its
//!     `verify_signature`, which is what verifies the SET.
//!
//! So this is *assembly of vetted primitives*, not new crypto. Production must
//! run `Verifier::verify_digest` **and** this glue, treating either failing as
//! `verified = false`. This is the module Drew reviewed and approved in Stage 1.
//!
//! # The SET payload canonicalisation (#3231)
//!
//! [`verify_signed_entry_timestamp`] is not a new construction either: the same
//! crate canonicalises and verifies exactly this payload in its **cosign** path
//! (`cosign::bundle::Bundle::verify_bundle`, and `verify_bundle_tlog_entry`
//! step 2), which the backend cannot call because both are private and the
//! `cosign` feature is not enabled. The payload shape below is the field set of
//! `sigstore::cosign::bundle::Payload`, canonicalised with the same
//! `serde_json_canonicalizer` (RFC 8785 JCS) the crate uses, and verified with
//! the same `CosignVerificationKey`. Keeping the JCS library rather than
//! hand-formatting the JSON is deliberate: a byte that differs from the crate's
//! encoding is a signature that never verifies.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde::Serialize;
use sigstore::crypto::{CosignVerificationKey, Signature};
use sigstore::rekor::models::checkpoint::SignedCheckpoint;
use sigstore::rekor::models::InclusionProof;
use sigstore::trust::sigstore::SigstoreTrustRoot;
use sigstore::trust::TrustRoot;

fn b64_32(v: &serde_json::Value, what: &str) -> Result<[u8; 32]> {
    let s = v
        .as_str()
        .ok_or_else(|| anyhow!("{what} is not a base64 string"))?;
    let raw = B64.decode(s).with_context(|| format!("{what} base64"))?;
    raw.try_into()
        .map_err(|_| anyhow!("{what} is not 32 bytes"))
}

fn as_u64(v: &serde_json::Value, what: &str) -> Result<u64> {
    // protobuf-JSON encodes 64-bit ints as strings.
    match v {
        serde_json::Value::String(s) => Ok(s.parse()?),
        serde_json::Value::Number(n) => n.as_u64().ok_or_else(|| anyhow!("{what} is not a u64")),
        _ => bail!("{what} missing"),
    }
}

/// The bundle's single tlog entry resolved together with the Rekor log key it
/// names — the shared preamble of both transparency checks.
struct TlogEntry<'a> {
    /// The `verificationMaterial.tlogEntries[0]` object.
    entry: &'a serde_json::Value,
    /// `hex(logId.keyId)` — the trusted-root key-map key, and the value the SET
    /// payload carries as `logID`.
    key_id_hex: String,
    /// The Rekor log public key, selected by the entry's own log id.
    rekor_key: CosignVerificationKey,
    /// The raw (base64-decoded) `canonicalizedBody`.
    canonicalized_body: Vec<u8>,
}

/// Locate the single tlog entry and the Rekor log key it claims, from the
/// pinned trusted root. Fail-closed: a missing entry, an unparseable body, or a
/// log id the trusted root does not carry is an `Err`.
fn resolve_tlog_entry<'a>(
    bundle_json: &'a serde_json::Value,
    trusted_root_json: &[u8],
) -> Result<TlogEntry<'a>> {
    let entry = bundle_json
        .get("verificationMaterial")
        .and_then(|v| v.get("tlogEntries"))
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .ok_or_else(|| anyhow!("bundle has no tlogEntries[0]"))?;

    let key_id_b64 = entry
        .get("logId")
        .and_then(|l| l.get("keyId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("tlog entry has no logId.keyId"))?;
    let key_id_hex = hex::encode(B64.decode(key_id_b64).context("logId.keyId base64")?);

    let root = SigstoreTrustRoot::from_trusted_root_json_unchecked(trusted_root_json)?;
    let keys = root.rekor_keys()?;
    let key_der = keys
        .get(&key_id_hex)
        .ok_or_else(|| anyhow!("log id {key_id_hex} is not in the trusted root (fail closed)"))?;
    let rekor_key =
        CosignVerificationKey::try_from_der(key_der).context("parse Rekor log public key")?;

    let canonicalized_body = B64
        .decode(
            entry["canonicalizedBody"]
                .as_str()
                .ok_or_else(|| anyhow!("canonicalizedBody missing"))?,
        )
        .context("canonicalizedBody base64")?;

    Ok(TlogEntry {
        entry,
        key_id_hex,
        rekor_key,
        canonicalized_body,
    })
}

/// The Rekor Signed Entry Timestamp payload — the exact field set (and, once
/// canonicalised, the exact bytes) the log signs. Mirrors
/// `sigstore::cosign::bundle::Payload`, which is unreachable here because the
/// crate's `cosign` feature is not enabled.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SetPayload<'a> {
    /// Base64 of `canonicalizedBody`, exactly as the entry carries it.
    body: &'a str,
    integrated_time: i64,
    log_index: i64,
    #[serde(rename = "logID")]
    log_id: &'a str,
}

/// Verify the Signed Entry Timestamp Rekor issued for this entry (#3231).
///
/// The SET is the log's signature over the entry's `(body, integratedTime,
/// logIndex, logID)`, and it is the **only** thing that authenticates
/// `integratedTime` — the value the crate's `verify_digest` compares against the
/// signing certificate's validity window. It is not part of `canonicalizedBody`
/// and not part of the Merkle leaf, so [`verify_inclusion`] does not cover it:
/// without this check `integratedTime` is a number the bundle's author picked,
/// and "the certificate was valid when it signed" is unfalsifiable.
///
/// Fail-closed everywhere, **including a missing promise**: a tlog entry with no
/// `inclusionPromise` carries no authenticated timestamp, so it is rejected
/// rather than silently downgraded. Every PyPI PEP 740 bundle observed carries
/// one (the captured `sigstore` 4.5.0 fixture included), and PyPI is the only
/// format this verifier accepts today.
pub fn verify_signed_entry_timestamp(
    bundle_json: &serde_json::Value,
    trusted_root_json: &[u8],
) -> Result<()> {
    let te = resolve_tlog_entry(bundle_json, trusted_root_json)?;

    let set_b64 = te
        .entry
        .get("inclusionPromise")
        .and_then(|p| p.get("signedEntryTimestamp"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            anyhow!(
                "tlog entry has no inclusionPromise.signedEntryTimestamp, so integratedTime is unauthenticated (fail closed)"
            )
        })?;
    let set = B64
        .decode(set_b64)
        .context("inclusionPromise.signedEntryTimestamp base64")?;

    let body_b64 = te.entry["canonicalizedBody"]
        .as_str()
        .ok_or_else(|| anyhow!("canonicalizedBody missing"))?;
    let payload = SetPayload {
        body: body_b64,
        integrated_time: as_u64(&te.entry["integratedTime"], "integratedTime")? as i64,
        log_index: as_u64(&te.entry["logIndex"], "logIndex")? as i64,
        log_id: &te.key_id_hex,
    };
    let canonical = serde_json_canonicalizer::to_vec(&payload)
        .map_err(|e| anyhow!("cannot canonicalize SET payload: {e}"))?;

    te.rekor_key
        .verify_signature(Signature::Raw(&set), &canonical)
        .map_err(|e| anyhow!("Rekor signed entry timestamp (SET) verification failed: {e}"))
}

/// Verify that the bundle's single tlog entry is really included in the Rekor
/// log, against a signed checkpoint, using the log key from the pinned trusted
/// root. This is the check that makes "Rekor inclusion" in the issue's
/// requirement list actually true.
///
/// Fail-closed everywhere: any missing field, malformed proof, unknown log id,
/// or failed Merkle/checkpoint check is an `Err`.
pub fn verify_inclusion(bundle_json: &serde_json::Value, trusted_root_json: &[u8]) -> Result<()> {
    let te = resolve_tlog_entry(bundle_json, trusted_root_json)?;

    let ip = te
        .entry
        .get("inclusionProof")
        .ok_or_else(|| anyhow!("tlog entry has no inclusionProof (fail closed)"))?;

    let root_hash = b64_32(&ip["rootHash"], "inclusionProof.rootHash")?;
    let tree_size = as_u64(&ip["treeSize"], "inclusionProof.treeSize")?;
    let log_index = as_u64(&ip["logIndex"], "inclusionProof.logIndex")? as i64;
    let hashes = ip["hashes"]
        .as_array()
        .ok_or_else(|| anyhow!("inclusionProof.hashes missing"))?
        .iter()
        .map(|h| b64_32(h, "inclusionProof.hashes[]"))
        .collect::<Result<Vec<_>>>()?;

    // `SignedCheckpoint::decode` is pub(crate), but the type's `Deserialize`
    // impl calls it, so a JSON round-trip is the public door.
    let cp_env = ip
        .get("checkpoint")
        .and_then(|c| c.get("envelope"))
        .ok_or_else(|| anyhow!("inclusionProof has no checkpoint envelope (fail closed)"))?;
    let checkpoint: SignedCheckpoint =
        serde_json::from_value(cp_env.clone()).context("checkpoint envelope decode")?;

    let proof = InclusionProof::new(log_index, root_hash, tree_size, hashes, Some(checkpoint));
    proof
        .verify(&te.canonicalized_body, &te.rekor_key)
        .map_err(|e| anyhow!("Rekor inclusion proof verification failed: {e}"))
}

/// Which serialization of the bundle's DSSE envelope the Rekor `dsse` entry's
/// `spec.envelopeHash` was computed over (#4082).
///
/// Rekor hashes the envelope **exactly as it was submitted**, so the hash
/// inherits the submitting tool's JSON spacing. `verify_digest` re-serializes
/// the envelope compactly (`{"payload":...}`) and compares; PyPI's publishing
/// tooling submitted Python's default spaced form (`{"payload": ...}`) until
/// about 2026-05, so every attestation from that window fails the crate's
/// consistency check although nothing about it is wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeHashForm {
    /// Not a DSSE bundle with a `dsse` v0.0.1 entry carrying a sha256
    /// `envelopeHash` we could read. Nothing to adjust: the crate decides.
    NotApplicable,
    /// The hash is over the compact serialization, which is what the crate
    /// checks.
    Compact,
    /// The hash is over the Python-spaced serialization of the same envelope.
    /// `compact_sha256` is the hash the crate expects in its place.
    Spaced { compact_sha256: String },
    /// The hash matches neither serialization: the entry does not describe
    /// this envelope.
    Neither {
        recorded: String,
        compact: String,
        spaced: String,
    },
}

/// The bundle's DSSE envelope serialized exactly as `sigstore` 0.14.0's
/// `CheckedBundle` does before hashing it (`serde_json::to_vec` of the
/// protobuf type), or `None` for a bundle without one.
fn compact_envelope_json(bundle_json: &serde_json::Value) -> Option<Vec<u8>> {
    use sigstore_protobuf_specs::dev::sigstore::bundle::v1::bundle::Content;
    let bundle: sigstore::bundle::Bundle = serde_json::from_value(bundle_json.clone()).ok()?;
    match bundle.content? {
        Content::DsseEnvelope(dsse) => serde_json::to_vec(&dsse).ok(),
        Content::MessageSignature(_) => None,
    }
}

/// Re-space compact JSON the way Python's `json.dumps` does by default: a
/// space after every `,` and `:` that is not inside a string.
pub fn python_spaced_json(compact: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(compact.len() + compact.len() / 8);
    let (mut in_string, mut escaped) = (false, false);
    for &b in compact {
        out.push(b);
        if in_string {
            match (escaped, b) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                _ => {}
            }
        } else if b == b'"' {
            in_string = true;
        } else if b == b',' || b == b':' {
            out.push(b' ');
        }
    }
    out
}

/// The `dsse` v0.0.1 body's sha256 `spec.envelopeHash.value`, if it has one.
fn recorded_envelope_hash(body: &serde_json::Value) -> Option<String> {
    if body.get("kind")?.as_str()? != "dsse" || body.get("apiVersion")?.as_str()? != "0.0.1" {
        return None;
    }
    let hash = body.get("spec")?.get("envelopeHash")?;
    if hash.get("algorithm")?.as_str()? != "sha256" {
        return None;
    }
    Some(hash.get("value")?.as_str()?.to_ascii_lowercase())
}

/// The bundle's single tlog entry's decoded `canonicalizedBody`.
fn tlog_body(bundle_json: &serde_json::Value) -> Option<serde_json::Value> {
    let body_b64 = bundle_json
        .get("verificationMaterial")?
        .get("tlogEntries")?
        .as_array()?
        .first()?
        .get("canonicalizedBody")?
        .as_str()?;
    serde_json::from_slice(&B64.decode(body_b64).ok()?).ok()
}

/// Classify the Rekor entry's `envelopeHash` against both serializations of
/// the bundle's own DSSE envelope (#4082). Pure: reads only the bundle.
pub fn dsse_envelope_hash_form(bundle_json: &serde_json::Value) -> EnvelopeHashForm {
    let (Some(recorded), Some(compact)) = (
        tlog_body(bundle_json)
            .as_ref()
            .and_then(recorded_envelope_hash),
        compact_envelope_json(bundle_json),
    ) else {
        return EnvelopeHashForm::NotApplicable;
    };
    let compact_sha256 = hex::encode(crate::crypto::digest::Sha256::digest(&compact));
    if recorded == compact_sha256 {
        return EnvelopeHashForm::Compact;
    }
    let spaced_sha256 = hex::encode(crate::crypto::digest::Sha256::digest(python_spaced_json(
        &compact,
    )));
    if recorded == spaced_sha256 {
        EnvelopeHashForm::Spaced { compact_sha256 }
    } else {
        EnvelopeHashForm::Neither {
            recorded,
            compact: compact_sha256,
            spaced: spaced_sha256,
        }
    }
}

/// A copy of `bundle_json` whose tlog body carries `envelope_hash` as its
/// `spec.envelopeHash.value`, for `verify_digest` only (#4082).
///
/// Used once [`dsse_envelope_hash_form`] has established that the recorded
/// hash is the spaced serialization of this very envelope: the crate then
/// re-checks everything else in the body (payloadHash, signature, verifier
/// certificate) against the envelope it verifies. The original, unmodified
/// body is what [`verify_signed_entry_timestamp`] and [`verify_inclusion`]
/// check against the log, so the log still vouches for the bytes we read the
/// spaced hash from.
pub fn with_envelope_hash(
    bundle_json: &serde_json::Value,
    envelope_hash: &str,
) -> Result<serde_json::Value> {
    let mut body = tlog_body(bundle_json).ok_or_else(|| anyhow!("tlog body unreadable"))?;
    body["spec"]["envelopeHash"]["value"] = serde_json::Value::String(envelope_hash.to_owned());
    let mut out = bundle_json.clone();
    out["verificationMaterial"]["tlogEntries"][0]["canonicalizedBody"] =
        serde_json::Value::String(B64.encode(serde_json::to_vec(&body)?));
    Ok(out)
}
