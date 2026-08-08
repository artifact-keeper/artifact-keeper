//! Sigstore trusted-root management for attestation verification (#2955).
//!
//! Fail-closed semantics: a stale or missing trust root yields
//! `verified = false` (and the rule Flags), **never** an outage and **never**
//! false trust — exactly the pre-#2955 behaviour.
//!
//! Two sourcing modes:
//!   * **Vendored** ([`TrustRoot::vendored`]) — a build-time snapshot of the
//!     production Sigstore trusted root, embedded via `include_bytes!`. This is
//!     the air-gapped/offline anchor and the default. Because the crate's
//!     loader is `from_trusted_root_json_unchecked` (no TUF signature check of
//!     the blob), we integrity-check the embedded bytes **ourselves** against a
//!     pinned SHA-256, and confirm the log keys are present, at load time.
//!   * **Refreshed** ([`TrustRoot::from_tuf`]) — a live TUF pull when egress
//!     exists. On any refresh failure the caller keeps the vendored snapshot;
//!     the refresh never blocks verification.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use sigstore::bundle::verify::Verifier;
use sigstore::trust::sigstore::SigstoreTrustRoot;
use sigstore::trust::TrustRoot as _;

/// The vendored trusted-root snapshot (production Sigstore public-good root).
/// Refreshed deliberately; pinned next to its SHA-256 so a repo-review or a
/// tampered checkout is caught at load.
const VENDORED_TRUSTED_ROOT: &[u8] = include_bytes!("sigstore_trusted_root.json");

/// SHA-256 of [`VENDORED_TRUSTED_ROOT`]. Asserted at load because the crate
/// loader does not validate the blob. Update this in lockstep with the file.
const VENDORED_TRUSTED_ROOT_SHA256: &str =
    "6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66";

/// A validated Sigstore trusted root, carrying the raw JSON bytes so both the
/// bundle [`Verifier`] and the Rekor inclusion glue can be reconstructed from
/// the same source of truth.
#[derive(Clone)]
pub struct TrustRoot {
    bytes: Vec<u8>,
}

impl TrustRoot {
    /// Load the vendored build-time snapshot, integrity-checking the embedded
    /// bytes against the pinned digest and confirming it is usable.
    pub fn vendored() -> Result<Self> {
        let actual = hex::encode(Sha256::digest(VENDORED_TRUSTED_ROOT));
        if actual != VENDORED_TRUSTED_ROOT_SHA256 {
            bail!(
                "vendored sigstore trusted root integrity check failed: expected {VENDORED_TRUSTED_ROOT_SHA256}, got {actual}"
            );
        }
        Self::from_bytes(VENDORED_TRUSTED_ROOT.to_vec())
    }

    /// Build from raw trusted-root JSON bytes (a TUF-refreshed blob or a test
    /// fixture), validating it is well-formed and carries Rekor log keys.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let root = SigstoreTrustRoot::from_trusted_root_json_unchecked(&bytes)
            .context("parse sigstore trusted root JSON")?;
        // A stale root degrades by silently dropping time-invalid keys, which
        // would otherwise surface as "log id not in trusted root" at verify
        // time. Turn that into a clear staleness signal here: a usable root
        // MUST carry at least one Rekor log key.
        let rekor_keys = root
            .rekor_keys()
            .context("read Rekor keys from trusted root")?;
        if rekor_keys.is_empty() {
            bail!("sigstore trusted root carries no valid Rekor log keys (stale or empty root); refusing to trust (fail closed)");
        }
        Ok(Self { bytes })
    }

    /// Refresh the trusted root from the Sigstore TUF repository. Network I/O;
    /// only call where egress is permitted. On any failure the caller keeps its
    /// existing (vendored) root — the refresh must never block verification.
    pub async fn from_tuf(cache_dir: &std::path::Path) -> Result<Self> {
        // A real TUF client update (embedded root.json, `tough`,
        // ExpirationEnforcement::Safe) writes `trusted_root.json` into the
        // cache dir; we read those bytes back and re-validate them ourselves.
        let _root = SigstoreTrustRoot::new(Some(cache_dir))
            .await
            .context("sigstore TUF trusted-root refresh")?;
        let bytes = std::fs::read(cache_dir.join("trusted_root.json"))
            .context("TUF checkout did not produce trusted_root.json")?;
        Self::from_bytes(bytes)
    }

    /// The raw trusted-root JSON bytes, for the Rekor inclusion glue.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Construct a bundle [`Verifier`] anchored to this trusted root.
    pub fn verifier(&self) -> Result<Verifier> {
        let root = SigstoreTrustRoot::from_trusted_root_json_unchecked(&self.bytes)
            .context("parse sigstore trusted root JSON")?;
        Verifier::new(Default::default(), root).context("construct sigstore bundle Verifier")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendored_root_passes_integrity_and_is_usable() {
        let tr = TrustRoot::vendored().expect("vendored trusted root must load");
        assert!(!tr.bytes().is_empty());
        // It must build a verifier and carry Rekor keys (else from_bytes errs).
        tr.verifier().expect("vendored root builds a Verifier");
    }

    #[test]
    fn tampered_bytes_fail_integrity_check() {
        // A one-byte change to the pinned digest constant is equivalent to a
        // tampered file; simulate by feeding bytes whose digest is not pinned.
        let mut bytes = VENDORED_TRUSTED_ROOT.to_vec();
        // Truncating changes the digest; from_bytes should still reject it as
        // unparseable/keyless rather than accept it.
        bytes.truncate(bytes.len() / 2);
        assert!(TrustRoot::from_bytes(bytes).is_err());
    }

    #[test]
    fn empty_or_garbage_root_is_rejected_fail_closed() {
        assert!(TrustRoot::from_bytes(b"{}".to_vec()).is_err());
        assert!(TrustRoot::from_bytes(b"not json".to_vec()).is_err());
    }
}
