//! Certificate-identity extraction for attestation verification (#2955).
//!
//! `sigstore` 0.14.0 exposes only *assertion* policies
//! ([`sigstore::bundle::verify::policy::Identity`], `OIDCIssuer`,
//! `GitHubWorkflowRepository`, …). There is no public API that hands the parsed
//! identity back, and `Verifier::verify_digest` consumes the `Bundle` **by
//! value**, so the leaf certificate is not reachable after a successful verify.
//!
//! Production therefore parses the leaf certificate itself (out of the same
//! bundle JSON it hands the verifier) to learn *who* signed. This module is
//! that glue: `x509_cert` only, **no crypto** — the trust decision still comes
//! from `verify_digest`. It is a straight port of the Stage-1 spike glue that
//! Drew reviewed, hardened only for production error handling.
//!
//! Security note: the identity extracted here MUST be consulted only *after*
//! `verify_digest` returns `Ok` (extract-then-trust would be a parse-before-
//! verify bug). The verdict struct in the parent module enforces that ordering.

use anyhow::{Context, Result};
use x509_cert::der::{Decode, Encode};
use x509_cert::ext::pkix::{name::GeneralName, SubjectAltName};
use x509_cert::Certificate;

/// Fulcio OIDs. See <https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md>.
///
/// `1.1`–`1.6` are the *deprecated* raw-string extensions (Fulcio still emits
/// them for backward compatibility); `1.8`+ are the current extensions,
/// DER-encoded as `UTF8String`. Current certs carry both.
pub const OID_ISSUER_V1: &str = "1.3.6.1.4.1.57264.1.1";
pub const OID_GH_WORKFLOW_TRIGGER: &str = "1.3.6.1.4.1.57264.1.2";
pub const OID_GH_WORKFLOW_SHA: &str = "1.3.6.1.4.1.57264.1.3";
pub const OID_GH_WORKFLOW_NAME: &str = "1.3.6.1.4.1.57264.1.4";
pub const OID_GH_WORKFLOW_REPOSITORY: &str = "1.3.6.1.4.1.57264.1.5";
pub const OID_GH_WORKFLOW_REF: &str = "1.3.6.1.4.1.57264.1.6";
pub const OID_ISSUER_V2: &str = "1.3.6.1.4.1.57264.1.8";
pub const OID_BUILD_SIGNER_URI: &str = "1.3.6.1.4.1.57264.1.9";
pub const OID_RUNNER_ENVIRONMENT: &str = "1.3.6.1.4.1.57264.1.11";
pub const OID_SOURCE_REPO_URI: &str = "1.3.6.1.4.1.57264.1.12";
pub const OID_SOURCE_REPO_REF: &str = "1.3.6.1.4.1.57264.1.14";
pub const OID_SOURCE_REPO_OWNER_URI: &str = "1.3.6.1.4.1.57264.1.16";
pub const OID_BUILD_CONFIG_URI: &str = "1.3.6.1.4.1.57264.1.18";
pub const OID_RUN_INVOCATION_URI: &str = "1.3.6.1.4.1.57264.1.21";

/// Sigstore "OtherName" SAN type.
pub const OID_OTHERNAME: &str = "1.3.6.1.4.1.57264.1.7";

/// The identity bound into a Fulcio leaf certificate, extracted post-verification.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CertIdentity {
    /// SAN values (rfc822 / URI / sigstore OtherName), in certificate order.
    /// The first entry is the workflow identity URI.
    pub san: Vec<String>,
    /// OIDC issuer, preferring the v2 (DER `UTF8String`) extension.
    pub issuer: Option<String>,
    /// `owner/repo` from the deprecated GitHub-workflow-repository extension.
    pub gh_workflow_repository: Option<String>,
    pub gh_workflow_ref: Option<String>,
    pub gh_workflow_name: Option<String>,
    pub gh_workflow_sha: Option<String>,
    pub gh_workflow_trigger: Option<String>,
    /// `https://github.com/owner/repo` from the current source-repository ext.
    pub source_repo_uri: Option<String>,
    /// `https://github.com/owner` from the current source-repository-owner ext.
    pub source_repo_owner_uri: Option<String>,
    pub source_repo_ref: Option<String>,
    pub build_signer_uri: Option<String>,
    pub build_config_uri: Option<String>,
    pub runner_environment: Option<String>,
    pub run_invocation_uri: Option<String>,
    pub not_before: u64,
    pub not_after: u64,
}

impl CertIdentity {
    /// The repository owner (the org / user), derived from whichever extension
    /// is present. This is the value an allowlist like `["Microsoft"]` matches
    /// and the value bound to a claimed publisher.
    pub fn owner(&self) -> Option<String> {
        if let Some(uri) = &self.source_repo_owner_uri {
            return uri
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .filter(|s| !s.is_empty())
                .map(str::to_string);
        }
        if let Some(repo) = &self.gh_workflow_repository {
            return repo
                .split('/')
                .next()
                .filter(|s| !s.is_empty())
                .map(str::to_string);
        }
        None
    }

    /// `owner/repo`, derived from whichever extension is present.
    pub fn repository(&self) -> Option<String> {
        if let Some(repo) = &self.gh_workflow_repository {
            if !repo.is_empty() {
                return Some(repo.clone());
            }
        }
        if let Some(uri) = &self.source_repo_uri {
            // https://github.com/owner/repo -> owner/repo
            let parts: Vec<&str> = uri.trim_end_matches('/').rsplit('/').collect();
            if parts.len() >= 2 && !parts[0].is_empty() && !parts[1].is_empty() {
                return Some(format!("{}/{}", parts[1], parts[0]));
            }
        }
        None
    }
}

/// Decode a Fulcio extension value. The deprecated `1.1`–`1.6` extensions carry
/// the raw string; the `1.8`+ extensions carry a DER-encoded `UTF8String`. We
/// try DER first and fall back to raw UTF-8 — which is exactly what `sigstore`'s
/// own `SingleX509ExtPolicy` does *not* do (it reads raw bytes only, so its
/// `OIDCIssuer`/`GitHubWorkflowRepository` policies silently mismatch the `1.8`
/// generation). Preferring our own extraction is the reason the crate policies
/// are used only as a belt-and-braces check, never the primary binding.
fn decode_ext_value(raw: &[u8]) -> String {
    // DER UTF8String is tag 0x0C.
    if raw.len() >= 2 && raw[0] == 0x0c {
        if let Ok(s) = x509_cert::der::asn1::Utf8StringRef::from_der(raw) {
            return s.as_str().to_string();
        }
    }
    String::from_utf8_lossy(raw).to_string()
}

/// Parse a leaf-certificate DER blob into its bound identity.
pub fn extract(cert_der: &[u8]) -> Result<CertIdentity> {
    let cert = Certificate::from_der(cert_der).context("leaf certificate is not valid DER")?;
    extract_from_cert(&cert)
}

pub fn extract_from_cert(cert: &Certificate) -> Result<CertIdentity> {
    let mut out = CertIdentity {
        not_before: cert
            .tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_secs(),
        not_after: cert
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs(),
        ..Default::default()
    };

    // SAN — the workflow identity URI.
    if let Ok(Some((_critical, san))) = cert.tbs_certificate.get::<SubjectAltName>() {
        for name in san.0.iter() {
            match name {
                GeneralName::Rfc822Name(n) => out.san.push(n.as_str().to_string()),
                GeneralName::UniformResourceIdentifier(n) => out.san.push(n.as_str().to_string()),
                GeneralName::OtherName(n) if n.type_id.to_string() == OID_OTHERNAME => {
                    if let Ok(s) = std::str::from_utf8(n.value.value()) {
                        out.san.push(s.to_string());
                    }
                }
                _ => {}
            }
        }
    }

    for ext in cert.tbs_certificate.extensions.as_deref().unwrap_or(&[]) {
        let oid = ext.extn_id.to_string();
        if !oid.starts_with("1.3.6.1.4.1.57264.1.") {
            continue;
        }
        let val = decode_ext_value(ext.extn_value.as_bytes());

        match oid.as_str() {
            OID_ISSUER_V2 => out.issuer = Some(val),
            OID_ISSUER_V1 => {
                if out.issuer.is_none() {
                    out.issuer = Some(val);
                }
            }
            OID_GH_WORKFLOW_TRIGGER => out.gh_workflow_trigger = Some(val),
            OID_GH_WORKFLOW_SHA => out.gh_workflow_sha = Some(val),
            OID_GH_WORKFLOW_NAME => out.gh_workflow_name = Some(val),
            OID_GH_WORKFLOW_REPOSITORY => out.gh_workflow_repository = Some(val),
            OID_GH_WORKFLOW_REF => out.gh_workflow_ref = Some(val),
            OID_BUILD_SIGNER_URI => out.build_signer_uri = Some(val),
            OID_RUNNER_ENVIRONMENT => out.runner_environment = Some(val),
            OID_SOURCE_REPO_URI => out.source_repo_uri = Some(val),
            OID_SOURCE_REPO_REF => out.source_repo_ref = Some(val),
            OID_SOURCE_REPO_OWNER_URI => out.source_repo_owner_uri = Some(val),
            OID_BUILD_CONFIG_URI => out.build_config_uri = Some(val),
            OID_RUN_INVOCATION_URI => out.run_invocation_uri = Some(val),
            _ => {}
        }
    }

    // Sanity: a cert we parsed must re-encode, so we know we are looking at the
    // same bytes the verifier saw.
    let _ = cert.to_der().context("cert re-encode")?;

    Ok(out)
}
