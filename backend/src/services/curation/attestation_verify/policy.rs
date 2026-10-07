//! Operator trust policy for CEP-27 conda publish attestations.
//!
//! Before this module the conda upload path verified only one kind of
//! attestation: a keyless Sigstore bundle whose Fulcio certificate was issued
//! to a GitHub Actions workflow, against the public-good trusted root. That is
//! what public open-source CI produces, and it is not what a regulated
//! organization's on-premises CI can produce: no public OIDC issuer, often no
//! route to the public transparency log, and a signing key held in the
//! organization's own KMS or HSM.
//!
//! The policy has three parts, all set from the environment:
//!
//! * `CONDA_ATTESTATION_ISSUERS`: the OIDC issuers a keyless bundle's
//!   certificate may name (comma list). Defaults to the GitHub Actions issuer,
//!   which is the behaviour before this setting existed.
//! * `CONDA_ATTESTATION_IDENTITIES`: an optional allowlist of certificate
//!   identities (the SAN, e.g. a workflow URI). `*` matches any run of
//!   characters. Empty means any identity the issuer vouches for.
//! * `CONDA_ATTESTATION_PUBLIC_KEYS`: public keys for key-based bundles, as
//!   produced by `cosign attest-blob --key ...`. Each comma-separated entry is
//!   a PEM file path or an inline PEM, optionally prefixed with `name=`. A
//!   key-based bundle verifies when its DSSE signature verifies under one of
//!   these keys; no Fulcio certificate and no transparency log are involved,
//!   so the key IS the trust anchor and must be managed like one.
//!
//! A key that fails to load is reported (logged at startup and on every
//! policy read) and simply absent from the policy: it can never make a bundle
//! verify, so a typo fails closed.

use base64::Engine;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sigstore::crypto::CosignVerificationKey;

/// Verification method recorded for a keyless (Fulcio certificate) bundle.
pub const KEYLESS_METHOD: &str = "sigstore-keyless";

/// Verification method recorded for a bundle signed by a configured key.
pub const KEY_METHOD: &str = "sigstore-key";

/// One configured public key.
#[derive(Debug, Clone)]
pub struct TrustedKey {
    /// Short stable id: the first 16 hex digits of [`Self::fingerprint`].
    pub id: String,
    /// Operator-facing name: the `name=` prefix, else the file stem, else
    /// `inline-<n>`.
    pub name: String,
    /// Lowercase hex SHA-256 of the key's DER `SubjectPublicKeyInfo`.
    pub fingerprint: String,
    /// Signature algorithm the key verifies (`ecdsa-p256-sha256`, ...).
    pub algorithm: &'static str,
    /// The cosign/Sigstore key hint: base64 SHA-256 of the DER SPKI. A
    /// key-based bundle names its key with this in
    /// `verificationMaterial.publicKey.hint`.
    pub hint: String,
    pub(crate) key: CosignVerificationKey,
}

/// The public, serializable description of a configured key.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, utoipa::ToSchema)]
pub struct TrustedKeyInfo {
    pub id: String,
    pub name: String,
    pub fingerprint: String,
    pub algorithm: String,
}

impl TrustedKey {
    pub fn info(&self) -> TrustedKeyInfo {
        TrustedKeyInfo {
            id: self.id.clone(),
            name: self.name.clone(),
            fingerprint: self.fingerprint.clone(),
            algorithm: self.algorithm.to_string(),
        }
    }
}

/// The effective CEP-27 attestation trust policy.
#[derive(Debug, Clone, Default)]
pub struct CondaTrustPolicy {
    /// OIDC issuers accepted on keyless bundles.
    pub issuers: Vec<String>,
    /// Identity patterns accepted on keyless bundles (empty = any).
    pub identities: Vec<String>,
    /// Keys accepted on key-based bundles.
    pub keys: Vec<TrustedKey>,
    /// Why configured key entries were not loaded.
    pub key_errors: Vec<String>,
}

impl CondaTrustPolicy {
    /// Build the policy from configuration.
    pub fn from_config(config: &crate::config::Config) -> Self {
        Self::from_parts(
            &config.conda_attestation_issuers,
            &config.conda_attestation_identities,
            &config.conda_attestation_public_keys,
        )
    }

    /// Build the policy from its three raw lists. An empty issuer list means
    /// the default ([`super::DEFAULT_ISSUER_ALLOWLIST`]).
    pub fn from_parts(issuers: &[String], identities: &[String], key_specs: &[String]) -> Self {
        let issuers = if issuers.is_empty() {
            super::DEFAULT_ISSUER_ALLOWLIST
                .iter()
                .map(|s| s.to_string())
                .collect()
        } else {
            issuers.to_vec()
        };
        let mut keys = Vec::new();
        let mut key_errors = Vec::new();
        for (index, spec) in key_specs.iter().enumerate() {
            match load_key_spec(spec, index) {
                Ok(key) => keys.push(key),
                Err(e) => {
                    tracing::warn!("CONDA_ATTESTATION_PUBLIC_KEYS entry {index} ignored: {e}");
                    key_errors.push(format!("entry {index}: {e}"));
                }
            }
        }
        Self {
            issuers,
            identities: identities.to_vec(),
            keys,
            key_errors,
        }
    }

    /// Whether a keyless bundle's certificate identity is allowed.
    pub fn identity_allowed(&self, identity: &str) -> bool {
        self.identities.is_empty() || self.identities.iter().any(|p| glob_match(p, identity))
    }
}

/// `*`-glob match (no other metacharacters), anchored at both ends.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == text;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !text.starts_with(first) || text.len() < first.len() + last.len() || !text.ends_with(last) {
        return false;
    }
    let mut rest = &text[first.len()..text.len() - last.len()];
    for middle in &parts[1..parts.len() - 1] {
        match rest.find(middle) {
            Some(at) => rest = &rest[at + middle.len()..],
            None => return false,
        }
    }
    true
}

/// Split a `name=` prefix off a key spec. Only a prefix of name characters
/// counts, so a path containing `=` later, or an inline PEM (which starts
/// with `-----BEGIN`), is left whole.
fn split_name(spec: &str) -> (Option<&str>, &str) {
    if let Some((name, rest)) = spec.split_once('=') {
        let is_name = !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
        if is_name && !rest.is_empty() {
            return (Some(name), rest);
        }
    }
    (None, spec)
}

/// Load one `CONDA_ATTESTATION_PUBLIC_KEYS` entry.
pub fn load_key_spec(spec: &str, index: usize) -> Result<TrustedKey, String> {
    let spec = spec.trim();
    let (name, body) = if spec.starts_with("-----BEGIN") {
        (None, spec)
    } else {
        split_name(spec)
    };
    let body = body.trim();
    let (default_name, pem) = if body.starts_with("-----BEGIN") {
        (format!("inline-{index}"), body.to_string())
    } else {
        let pem = std::fs::read_to_string(body).map_err(|e| format!("cannot read {body}: {e}"))?;
        let stem = std::path::Path::new(body)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("key")
            .to_string();
        (stem, pem)
    };
    trusted_key_from_pem(name.map(str::to_string).unwrap_or(default_name), &pem)
}

/// Parse a PEM `PUBLIC KEY` into a [`TrustedKey`].
pub fn trusted_key_from_pem(name: String, pem: &str) -> Result<TrustedKey, String> {
    let key = CosignVerificationKey::try_from_pem(pem.as_bytes())
        .map_err(|e| format!("not a supported PEM public key: {e}"))?;
    let (algorithm, der) = match &key {
        CosignVerificationKey::ECDSA_P256_SHA256_ASN1(d) => ("ecdsa-p256-sha256", d),
        CosignVerificationKey::ECDSA_P384_SHA384_ASN1(d) => ("ecdsa-p384-sha384", d),
        CosignVerificationKey::ECDSA_P521_SHA512_ASN1(d) => ("ecdsa-p521-sha512", d),
        CosignVerificationKey::ED25519(d) => ("ed25519", d),
        CosignVerificationKey::RSA_PKCS1_SHA256(d) => ("rsa-pkcs1v15-sha256", d),
        CosignVerificationKey::RSA_PSS_SHA256(d) => ("rsa-pss-sha256", d),
    };
    let digest = Sha256::digest(der);
    let fingerprint = hex::encode(digest);
    Ok(TrustedKey {
        id: fingerprint[..16].to_string(),
        name,
        hint: base64::engine::general_purpose::STANDARD.encode(digest),
        fingerprint,
        algorithm,
        key,
    })
}

/// The DSSE pre-authentication encoding the envelope signature covers.
pub fn dsse_pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "DSSEv1 {} {} {} ",
        payload_type.len(),
        payload_type,
        payload.len()
    )
    .into_bytes();
    out.extend_from_slice(payload);
    out
}

/// The response body of `GET /api/v1/attestations/policy`.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct AttestationPolicyResponse {
    /// `CONDA_ATTESTATION_REQUIRE_VERIFIED`: an attestation that does not
    /// verify is refused rather than stored.
    pub require_verified: bool,
    /// OIDC issuers accepted on keyless bundles.
    pub issuers: Vec<String>,
    /// Identity patterns accepted on keyless bundles (empty: any).
    pub identities: Vec<String>,
    /// Public keys accepted on key-based bundles. Public material only.
    pub keys: Vec<TrustedKeyInfo>,
}

impl AttestationPolicyResponse {
    pub fn from_policy(policy: &CondaTrustPolicy, require_verified: bool) -> Self {
        Self {
            require_verified,
            issuers: policy.issuers.clone(),
            identities: policy.identities.clone(),
            keys: policy.keys.iter().map(TrustedKey::info).collect(),
        }
    }
}
