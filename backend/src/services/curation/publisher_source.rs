//! Publisher identity extraction for `publisher_trust` curation rules (#2948).
//!
//! Security model: a publisher identity is only as trustworthy as where it
//! came from. This module makes that provenance explicit:
//!
//! * [`PublisherSource::Attestation`] — the identity comes from a registry
//!   provenance/attestation record (PyPI Trusted Publishers / integrity API
//!   attestation bundles, npm sigstore provenance). When cryptographically
//!   verified, these are bound to an OIDC identity at publish time and are
//!   the *strong* trust signal. Verification of the envelope
//!   (sigstore/DSSE/PEP 740) is NOT implemented yet (#2955): structural
//!   presence of a provenance record is not verification, so extraction
//!   currently always reports `verified = false` for this source.
//! * [`PublisherSource::Metadata`] — the identity is self-asserted package
//!   metadata (`author`, `maintainer`, `_npmUser`, ...). Anyone can put
//!   "Microsoft" in an `author` field, so this is a *weak*, spoofable signal
//!   (a classic dependency-confusion vector). It is surfaced as a labeled
//!   fallback and must never be treated as equivalent to an attestation.
//!
//! Parsing is deliberately defensive: any missing or malformed field yields
//! `None` rather than a guess, so callers can fail safe.

use serde_json::Value;

/// Where a publisher identity was sourced from. Ordering of trust:
/// `Attestation` (provenance record) > `Metadata` (self-asserted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublisherSource {
    /// A registry provenance record (PyPI Trusted Publisher attestation
    /// bundle, npm sigstore attestation) was present and an identity was
    /// extracted from it. Presence alone is NOT trust: until the envelope is
    /// cryptographically verified (#2955), this identity is unverified and
    /// [`PublisherIdentity::verified`] stays `false`.
    Attestation,
    /// Self-asserted package metadata (`author` / `maintainer` / `_npmUser`).
    /// Weak, spoofable signal — never sufficient on its own for trust
    /// decisions under `match: "attestation"`.
    Metadata,
}

/// A publisher identity extracted from package metadata, labeled with the
/// signal it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublisherIdentity {
    /// Publisher name as extracted (e.g. a GitHub org from an attestation
    /// bundle, or an `author` string from self-asserted metadata).
    pub name: String,
    /// Which class of signal produced [`Self::name`].
    pub source: PublisherSource,
    /// `true` only once the provenance envelope backing the identity has been
    /// cryptographically verified. Always `false` for
    /// [`PublisherSource::Metadata`], and — because attestation verification
    /// (sigstore/DSSE/PEP 740) is not implemented yet (#2955) — currently
    /// always `false` for [`PublisherSource::Attestation`] too. Structural
    /// presence of an attestation must never set this to `true`.
    pub verified: bool,
}

/// Package formats for which a publisher/provenance concept exists and this
/// module knows how to extract it. Formats outside this set have no
/// meaningful publisher signal (e.g. `raw`/`generic`), so a global
/// publisher-trust policy should treat them as not applicable rather than
/// flagging everything.
pub const APPLICABLE_FORMATS: &[&str] = &["pypi", "npm"];

/// Returns `true` if `format` has a publisher concept this module can
/// evaluate (see [`APPLICABLE_FORMATS`]).
pub fn is_applicable_format(format: &str) -> bool {
    APPLICABLE_FORMATS.contains(&format.to_ascii_lowercase().as_str())
}

/// Extracts the strongest available publisher identity from `metadata` for
/// the given package `format`.
///
/// * `pypi` — expects the PyPI JSON API shape (`/pypi/{pkg}/json`): the
///   self-asserted fields live under `info.author` / `info.maintainer` /
///   `info.author_email` / `info.maintainer_email`. If a PyPI integrity-API
///   provenance object has been merged into the blob (top-level
///   `provenance.attestation_bundles[].publisher`, as returned by
///   `/integrity/{pkg}/{version}/{file}/provenance`), the Trusted-Publisher
///   identity (repository owner, e.g. the GitHub org) is preferred with
///   `source = Attestation` — but `verified = false`, because the envelope
///   is not cryptographically verified yet (#2955).
/// * `npm` — expects the registry packument / version-document shape:
///   self-asserted fields are `_npmUser.name` and `maintainers[].name`. If
///   the version's `dist.attestations` carries a sigstore `provenance`
///   record, the identity is labeled `Attestation` (again with
///   `verified = false` pending #2955).
///
/// Any other format, and any metadata where no non-empty publisher can be
/// found, returns `None` — callers must not fabricate trust from absence.
pub fn extract_publisher(format: &str, metadata: &Value) -> Option<PublisherIdentity> {
    match format.to_ascii_lowercase().as_str() {
        "pypi" => extract_pypi(metadata),
        "npm" => extract_npm(metadata),
        _ => None,
    }
}

// -- PyPI --------------------------------------------------------------------

fn extract_pypi(metadata: &Value) -> Option<PublisherIdentity> {
    if let Some(name) = pypi_attestation_publisher(metadata) {
        return Some(PublisherIdentity {
            name,
            source: PublisherSource::Attestation,
            // Presence != trust: the attestation envelope is NOT
            // cryptographically verified here. Until sigstore/PEP 740
            // verification lands (#2955), a structurally present provenance
            // blob — which anyone can forge — must stay unverified.
            verified: false,
        });
    }

    let info = metadata.get("info")?;
    let name = non_empty_str(info.get("author"))
        .or_else(|| non_empty_str(info.get("maintainer")))
        .or_else(|| display_name_from_contact(info.get("author_email")))
        .or_else(|| display_name_from_contact(info.get("maintainer_email")))?;

    Some(PublisherIdentity {
        name,
        source: PublisherSource::Metadata,
        verified: false,
    })
}

/// Reads the Trusted-Publisher identity from a merged PyPI integrity-API
/// provenance object: `provenance.attestation_bundles[].publisher` where the
/// publisher is e.g. `{ "kind": "GitHub", "repository": "owner/repo", ... }`.
/// The publisher *name* is the repository owner (the org), which is what an
/// allowlist like `["Microsoft", "NumFOCUS"]` is meant to match.
fn pypi_attestation_publisher(metadata: &Value) -> Option<String> {
    let bundles = metadata.get("provenance")?.get("attestation_bundles")?;
    let publisher = bundles
        .as_array()?
        .iter()
        .find_map(|b| b.get("publisher"))?;
    let repository = non_empty_str(publisher.get("repository"))?;
    let owner = repository.split('/').next().unwrap_or(&repository).trim();
    if owner.is_empty() {
        return None;
    }
    Some(owner.to_string())
}

// -- npm ---------------------------------------------------------------------

fn extract_npm(metadata: &Value) -> Option<PublisherIdentity> {
    let name =
        non_empty_str(metadata.get("_npmUser").and_then(|u| u.get("name"))).or_else(|| {
            metadata
                .get("maintainers")?
                .as_array()?
                .iter()
                .find_map(|m| non_empty_str(m.get("name")))
        })?;

    if npm_has_provenance(metadata) {
        return Some(PublisherIdentity {
            name,
            source: PublisherSource::Attestation,
            // Presence != trust: the sigstore provenance record is NOT
            // cryptographically verified here (#2955). A planted
            // `dist.attestations.provenance` field must stay unverified.
            verified: false,
        });
    }

    Some(PublisherIdentity {
        name,
        source: PublisherSource::Metadata,
        verified: false,
    })
}

/// npm marks provenance on the version document as
/// `dist.attestations: { "url": ..., "provenance": { "predicateType": ... } }`.
/// Presence of the `provenance` record only *claims* a sigstore attestation
/// exists for this publish — this module does not fetch or cryptographically
/// verify it (#2955), so presence is a labeling signal, never trust.
fn npm_has_provenance(metadata: &Value) -> bool {
    metadata
        .get("dist")
        .and_then(|d| d.get("attestations"))
        .and_then(|a| a.get("provenance"))
        .is_some_and(|p| !p.is_null())
}

// -- helpers -----------------------------------------------------------------

fn non_empty_str(value: Option<&Value>) -> Option<String> {
    let s = value?.as_str()?.trim();
    if s.is_empty() {
        return None;
    }
    Some(s.to_string())
}

/// Extracts a display name from an RFC 5322-style contact field such as
/// `"NumFOCUS <admin@numfocus.org>"`. A bare email address carries no
/// publisher *name* and yields `None` (an allowlist should never be matched
/// against a raw email address).
fn display_name_from_contact(value: Option<&Value>) -> Option<String> {
    let contact = value?.as_str()?.trim();
    let angle = contact.find('<')?;
    let name = contact[..angle].trim().trim_matches('"').trim();
    if name.is_empty() {
        return None;
    }
    Some(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pypi_metadata_only() -> Value {
        json!({
            "info": {
                "author": "Microsoft Corporation",
                "author_email": "opensource@microsoft.com",
                "maintainer": null,
                "maintainer_email": null,
                "name": "azure-core",
                "version": "1.30.0"
            },
            "urls": [{"filename": "azure_core-1.30.0-py3-none-any.whl"}]
        })
    }

    fn pypi_with_attestation() -> Value {
        json!({
            "info": {
                "author": "Totally Microsoft",
                "name": "numpy",
                "version": "2.0.0"
            },
            "provenance": {
                "attestation_bundles": [{
                    "publisher": {
                        "kind": "GitHub",
                        "repository": "NumFOCUS/numpy",
                        "workflow": "release.yml",
                        "environment": "pypi"
                    },
                    "attestations": [{"envelope": {}}]
                }]
            }
        })
    }

    #[test]
    fn pypi_prefers_attestation_over_self_asserted_author_but_stays_unverified() {
        let id = extract_publisher("pypi", &pypi_with_attestation()).unwrap();
        // The attestation org wins over the spoofable `author` string...
        assert_eq!(id.name, "NumFOCUS");
        assert_eq!(id.source, PublisherSource::Attestation);
        // ...but structural presence of a provenance blob is NOT
        // cryptographic verification (#2955): a forged blob must never
        // surface as verified.
        assert!(!id.verified);
    }

    #[test]
    fn pypi_falls_back_to_author_metadata_unverified() {
        let id = extract_publisher("pypi", &pypi_metadata_only()).unwrap();
        assert_eq!(id.name, "Microsoft Corporation");
        assert_eq!(id.source, PublisherSource::Metadata);
        assert!(!id.verified);
    }

    #[test]
    fn pypi_null_author_uses_maintainer_then_contact_display_name() {
        let md = json!({
            "info": {
                "author": null,
                "maintainer": "  ",
                "author_email": "NumFOCUS <admin@numfocus.org>"
            }
        });
        let id = extract_publisher("pypi", &md).unwrap();
        assert_eq!(id.name, "NumFOCUS");
        assert_eq!(id.source, PublisherSource::Metadata);
        assert!(!id.verified);
    }

    #[test]
    fn pypi_bare_email_is_not_a_publisher_name() {
        let md = json!({"info": {"author_email": "admin@numfocus.org"}});
        assert_eq!(extract_publisher("pypi", &md), None);
    }

    #[test]
    fn pypi_empty_or_malformed_yields_none() {
        assert_eq!(extract_publisher("pypi", &json!({})), None);
        assert_eq!(extract_publisher("pypi", &json!({"info": {}})), None);
        assert_eq!(extract_publisher("pypi", &json!({"info": "oops"})), None);
        // Malformed provenance must not panic and must not fabricate identity.
        let md =
            json!({"provenance": {"attestation_bundles": [{"publisher": {"repository": "/"}}]}});
        assert_eq!(extract_publisher("pypi", &md), None);
    }

    fn npm_with_provenance() -> Value {
        json!({
            "name": "@azure/core-rest-pipeline",
            "version": "1.16.0",
            "_npmUser": {"name": "microsoft", "email": "npmjs@microsoft.com"},
            "maintainers": [{"name": "azure-sdk", "email": "azuresdk@microsoft.com"}],
            "dist": {
                "tarball": "https://registry.npmjs.org/...",
                "attestations": {
                    "url": "https://registry.npmjs.org/-/npm/v1/attestations/@azure%2fcore-rest-pipeline@1.16.0",
                    "provenance": {"predicateType": "https://slsa.dev/provenance/v1"}
                }
            }
        })
    }

    #[test]
    fn npm_provenance_marks_attested_but_not_verified() {
        let id = extract_publisher("npm", &npm_with_provenance()).unwrap();
        assert_eq!(id.name, "microsoft");
        assert_eq!(id.source, PublisherSource::Attestation);
        // Presence of `dist.attestations.provenance` is unverified until
        // #2955 lands actual sigstore envelope verification.
        assert!(!id.verified);
    }

    #[test]
    fn npm_without_provenance_is_metadata_only() {
        let md = json!({
            "maintainers": [{"name": "microsoft", "email": "npmjs@microsoft.com"}],
            "dist": {"tarball": "https://registry.npmjs.org/..."}
        });
        let id = extract_publisher("npm", &md).unwrap();
        assert_eq!(id.name, "microsoft");
        assert_eq!(id.source, PublisherSource::Metadata);
        assert!(!id.verified);
    }

    #[test]
    fn npm_missing_fields_yield_none() {
        assert_eq!(extract_publisher("npm", &json!({})), None);
        assert_eq!(extract_publisher("npm", &json!({"maintainers": []})), None);
        assert_eq!(
            extract_publisher("npm", &json!({"maintainers": "oops", "_npmUser": 42})),
            None
        );
    }

    #[test]
    fn unknown_format_yields_none() {
        assert_eq!(extract_publisher("raw", &pypi_metadata_only()), None);
        assert_eq!(extract_publisher("maven", &json!({})), None);
    }

    #[test]
    fn applicable_format_set() {
        assert!(is_applicable_format("pypi"));
        assert!(is_applicable_format("npm"));
        assert!(is_applicable_format("PyPI"));
        assert!(!is_applicable_format("raw"));
        assert!(!is_applicable_format("docker"));
        assert!(!is_applicable_format("maven"));
    }
}
