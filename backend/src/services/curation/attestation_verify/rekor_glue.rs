//! Rekor inclusion-proof glue — the gap `sigstore::bundle::verify::Verifier`
//! leaves open (#2955).
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
//!   * [`sigstore::crypto::CosignVerificationKey::try_from_der`].
//!
//! So this is *assembly of vetted primitives*, not new crypto. Production must
//! run `Verifier::verify_digest` **and** this glue, treating either failing as
//! `verified = false`. This is the module Drew reviewed and approved in Stage 1.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use sigstore::crypto::CosignVerificationKey;
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

/// Verify that the bundle's single tlog entry is really included in the Rekor
/// log, against a signed checkpoint, using the log key from the pinned trusted
/// root. This is the check that makes "Rekor inclusion" in the issue's
/// requirement list actually true.
///
/// Fail-closed everywhere: any missing field, malformed proof, unknown log id,
/// or failed Merkle/checkpoint check is an `Err`.
pub fn verify_inclusion(bundle_json: &serde_json::Value, trusted_root_json: &[u8]) -> Result<()> {
    let te = bundle_json
        .get("verificationMaterial")
        .and_then(|v| v.get("tlogEntries"))
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .ok_or_else(|| anyhow!("bundle has no tlogEntries[0]"))?;

    let ip = te
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

    // Rekor log key, selected by the entry's own logId, from the pinned root.
    let key_id_b64 = te
        .get("logId")
        .and_then(|l| l.get("keyId"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("tlog entry has no logId.keyId"))?;
    let key_id_hex = hex::encode(B64.decode(key_id_b64)?);

    let root = SigstoreTrustRoot::from_trusted_root_json_unchecked(trusted_root_json)?;
    let keys = root.rekor_keys()?;
    let key_der = keys
        .get(&key_id_hex)
        .ok_or_else(|| anyhow!("log id {key_id_hex} is not in the trusted root (fail closed)"))?;
    let rekor_key =
        CosignVerificationKey::try_from_der(key_der).context("parse Rekor log public key")?;

    let entry = B64
        .decode(
            te["canonicalizedBody"]
                .as_str()
                .ok_or_else(|| anyhow!("canonicalizedBody missing"))?,
        )
        .context("canonicalizedBody base64")?;

    let proof = InclusionProof::new(log_index, root_hash, tree_size, hashes, Some(checkpoint));
    proof
        .verify(&entry, &rekor_key)
        .map_err(|e| anyhow!("Rekor inclusion proof verification failed: {e}"))
}
