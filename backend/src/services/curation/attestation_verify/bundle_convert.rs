//! PEP 740 → sigstore-bundle conversion and bundle-JSON accessors (#2955).
//!
//! PyPI's provenance document (served by
//! `GET /integrity/{name}/{version}/{file}/provenance`) is **not** a sigstore
//! bundle: it is a flattened, snake_case projection with a bare-base64
//! certificate and no `mediaType`/`payloadType`. This module performs the
//! mechanical, lossless conversion to the camelCase sigstore bundle JSON the
//! `sigstore` crate deserializes, and exposes the small accessors the verifier
//! needs. No crypto here — this is data reshaping only.

use anyhow::{anyhow, bail, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde_json::Value;

/// A claimed Trusted-Publisher, as PyPI self-asserts it in each
/// `attestation_bundles[].publisher`. **Self-asserted, unsigned metadata** — it
/// is the value to compare *against* the certificate-bound owner, never to
/// trust on its own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaimedPublisher {
    pub kind: Option<String>,
    /// `owner/repo`.
    pub repository: Option<String>,
    pub workflow: Option<String>,
    pub environment: Option<String>,
}

impl ClaimedPublisher {
    /// The repository owner (org / user) an allowlist would match.
    pub fn owner(&self) -> Option<String> {
        self.repository
            .as_deref()
            .and_then(|r| r.split('/').next())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    }
}

/// One PEP 740 attestation paired with its (self-asserted) publisher claim,
/// already converted to a sigstore bundle JSON ready for the verifier.
#[derive(Debug, Clone)]
pub struct ConvertedAttestation {
    pub publisher: ClaimedPublisher,
    pub bundle_json: Value,
}

fn parse_publisher(v: &Value) -> ClaimedPublisher {
    ClaimedPublisher {
        kind: v.get("kind").and_then(Value::as_str).map(str::to_string),
        repository: v
            .get("repository")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        workflow: v
            .get("workflow")
            .and_then(Value::as_str)
            .map(str::to_string),
        environment: v
            .get("environment")
            .and_then(Value::as_str)
            .map(str::to_string),
    }
}

/// Convert one PEP 740 attestation object into a sigstore bundle JSON.
///
/// The mapping (see the Stage-1 findings doc):
///   * synthesise `mediaType: v0.3` and `dsseEnvelope.payloadType`;
///   * `verification_material.certificate` (bare base64 DER) →
///     `verificationMaterial.certificate.rawBytes`;
///   * `verification_material.transparency_entries[]` → `tlogEntries[]`
///     (already in protobuf-JSON shape, copied verbatim);
///   * `envelope.statement` → `dsseEnvelope.payload`;
///   * `envelope.signature` → `dsseEnvelope.signatures[0].sig`.
///
/// `version` is validated (`== 1`); an unknown version fails closed rather than
/// being coerced, because a future version could change envelope semantics.
pub fn pep740_attestation_to_bundle_json(att: &Value) -> Result<Value> {
    let version = att.get("version").and_then(Value::as_u64).unwrap_or(1);
    if version != 1 {
        bail!("unsupported PEP 740 attestation version {version}");
    }

    let vm = att
        .get("verification_material")
        .ok_or_else(|| anyhow!("attestation missing verification_material"))?;
    let cert_b64 = vm
        .get("certificate")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("verification_material.certificate missing/not a string"))?;
    let tlog = vm
        .get("transparency_entries")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("verification_material.transparency_entries missing"))?;
    let env = att
        .get("envelope")
        .ok_or_else(|| anyhow!("attestation missing envelope"))?;
    let statement_b64 = env
        .get("statement")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("envelope.statement missing"))?;
    let signature_b64 = env
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("envelope.signature missing"))?;

    Ok(serde_json::json!({
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": { "rawBytes": cert_b64 },
            "tlogEntries": tlog,
        },
        "dsseEnvelope": {
            "payload": statement_b64,
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [ { "sig": signature_b64, "keyid": "" } ],
        }
    }))
}

/// Iterate every `attestation_bundles[].attestations[]` in a PEP 740 provenance
/// document, converting each to a sigstore bundle JSON paired with its claimed
/// publisher. Production must try *all* of them (not assume index 0). Malformed
/// individual attestations are skipped; if none convert, the result is empty.
pub fn provenance_to_bundles(provenance: &Value) -> Vec<ConvertedAttestation> {
    let mut out = Vec::new();
    let Some(bundles) = provenance
        .get("attestation_bundles")
        .and_then(Value::as_array)
    else {
        return out;
    };
    for ab in bundles {
        let publisher = ab.get("publisher").map(parse_publisher).unwrap_or_default();
        let Some(atts) = ab.get("attestations").and_then(Value::as_array) else {
            continue;
        };
        for att in atts {
            if let Ok(bundle_json) = pep740_attestation_to_bundle_json(att) {
                out.push(ConvertedAttestation {
                    publisher: publisher.clone(),
                    bundle_json,
                });
            }
        }
    }
    out
}

/// Pull the leaf-certificate DER out of a bundle JSON (either the single
/// `certificate` shape or a `x509CertificateChain`).
pub fn leaf_cert_der(bundle_json: &Value) -> Result<Vec<u8>> {
    let vm = bundle_json
        .get("verificationMaterial")
        .ok_or_else(|| anyhow!("no verificationMaterial"))?;
    let b64 = if let Some(c) = vm.get("certificate") {
        c.get("rawBytes")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("certificate.rawBytes missing"))?
    } else if let Some(ch) = vm.get("x509CertificateChain") {
        ch.get("certificates")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(|c| c.get("rawBytes"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("x509CertificateChain[0].rawBytes missing"))?
    } else {
        bail!("bundle has no certificate material (publicKey-only bundle?)");
    };
    Ok(B64.decode(b64)?)
}

/// Decode the in-toto statement carried in a bundle's DSSE envelope.
pub fn statement_of(bundle_json: &Value) -> Result<Value> {
    let p = bundle_json
        .get("dsseEnvelope")
        .and_then(|e| e.get("payload"))
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("no dsseEnvelope.payload"))?;
    Ok(serde_json::from_slice(&B64.decode(p)?)?)
}
