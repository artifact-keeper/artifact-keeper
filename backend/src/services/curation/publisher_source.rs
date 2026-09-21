//! Publisher identity extraction for `publisher_trust` curation rules (#2948).
//!
//! Security model: a publisher identity is only as trustworthy as where it
//! came from. This module makes that provenance explicit:
//!
//! * [`PublisherSource::Attestation`] — the identity comes from a registry
//!   provenance/attestation record (PyPI Trusted Publishers / integrity API
//!   attestation bundles, npm sigstore provenance, conda CEP-27 publish
//!   attestations). When cryptographically verified, these are bound to an
//!   OIDC identity at publish time and are the *strong* trust signal.
//!   Verification of the envelope (sigstore/DSSE/PEP 740, CEP-27) now runs in
//!   `attestation_verify` (#2955, #4048); a verified record reaches this
//!   module through [`VERIFICATION_MARKER`] and yields `verified = true` with
//!   the cert-bound owner. Structural presence of a provenance record is
//!   still not verification, so without that marker extraction always
//!   reports `verified = false` for this source.
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
    /// bundle, npm sigstore attestation, conda CEP-27 publish attestation)
    /// was present and an identity was extracted from it. Presence alone is
    /// NOT trust: only a record cryptographically verified by
    /// `attestation_verify` (#2955, #4048) — delivered through
    /// [`VERIFICATION_MARKER`] — sets [`PublisherIdentity::verified`] to
    /// `true`; an unverified provenance blob keeps it `false`.
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
    /// [`PublisherSource::Metadata`]. For [`PublisherSource::Attestation`] it
    /// is `true` only when a verified record reaches this module through
    /// [`VERIFICATION_MARKER`] (#2955): structural presence of an attestation
    /// must never set this to `true`.
    pub verified: bool,
}

/// Package formats for which a publisher/provenance concept exists and this
/// module knows how to extract it. Formats outside this set have no
/// meaningful publisher signal (e.g. `raw`/`generic`), so a global
/// publisher-trust policy should treat them as not applicable rather than
/// flagging everything.
///
/// `conda` is applicable (#4049): CEP-27 attestation verification (#4048)
/// gives it a verifiable provenance record whose cert-bound owner is a
/// publisher identity, and its `about.json` metadata carries a self-asserted
/// fallback — the same two-tier shape as PyPI and npm.
pub const APPLICABLE_FORMATS: &[&str] = &["pypi", "npm", "conda"];

/// Returns `true` if `format` has a publisher concept this module can
/// evaluate (see [`APPLICABLE_FORMATS`]).
///
/// Alias formats are resolved to their family first (#3787): a `jupyter` or
/// `poetry` repository's packages carry PyPI publisher metadata, a `yarn` or
/// `pnpm` repository's carry npm's.
pub fn is_applicable_format(format: &str) -> bool {
    publisher_family(format).is_some_and(|family| APPLICABLE_FORMATS.contains(&family))
}

/// The publisher-metadata family for a repository format: the label under
/// which the proxy seam enqueued the row and whose extractor applies.
///
/// The PyPI/npm families delegate to
/// `popularity_source::ecosystem_for_format` — the same alias mapping, so the
/// two curation signals never disagree about what a `jupyter` package is.
/// `conda` is mapped here directly instead: it has no public download-count
/// source wired into the popularity signal, so adding it there would claim a
/// popularity answer that does not exist, while publisher trust needs only
/// the extraction mapping.
fn publisher_family(format: &str) -> Option<&'static str> {
    if format.eq_ignore_ascii_case("conda") {
        return Some("conda");
    }
    super::popularity_source::ecosystem_for_format(format)
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
/// * `conda` (#4049) — expects the artifact-metadata blob
///   `build_conda_metadata` persists: the self-asserted publisher lives in
///   the parsed `info/about.json` under `about.maintainer` /
///   `about.maintainers[]`, always `source = Metadata`,
///   `verified = false`. There is deliberately **no** unverified-attestation
///   tier for conda: CEP-27 has no claimed-publisher field (that is why
///   `attestation_verify::Check::PublisherOwnerBound` does not exist for
///   conda), so a stored-but-unverified attestation blob carries no honest
///   publisher name to extract, and presence must never upgrade a metadata
///   identity. The only attestation-grade conda identity is the cert-bound
///   owner a *verified* CEP-27 record yields, delivered through
///   [`VERIFICATION_MARKER`] like every other format.
///
/// Any other format, and any metadata where no non-empty publisher can be
/// found, returns `None` — callers must not fabricate trust from absence.
pub fn extract_publisher(format: &str, metadata: &Value) -> Option<PublisherIdentity> {
    // Verified path (#2955): the sync/evaluation loop runs the sigstore verifier
    // and, on a persisted SUCCESS, injects a verification record into the
    // metadata context under [`VERIFICATION_MARKER`]. When present, the
    // publisher identity is the CERTIFICATE-BOUND owner with `verified = true` —
    // never the forgeable metadata blob. Absence of the marker reproduces
    // exactly the pre-#2955 behavior below, so this stays a strict superset of
    // the shipped fail-safe. Only honored for formats with a publisher concept.
    if is_applicable_format(format) {
        if let Some(verified) = verified_identity_from_marker(metadata) {
            return Some(verified);
        }
    }

    match publisher_family(format) {
        Some("pypi") => extract_pypi(metadata),
        Some("npm") => extract_npm(metadata),
        Some("conda") => extract_conda(metadata),
        _ => None,
    }
}

/// Metadata-context key under which the evaluation loop injects a successful
/// attestation-verification record (#2955). This is NOT part of the registry
/// blob — it is added by trusted server code after `attestation_verify` returns
/// `verified`, carrying the certificate-bound owner.
///
/// **The marker is a server-side assertion and reading it is equivalent to
/// trusting it**, so no untrusted document may ever carry the key. That is
/// enforced by [`strip_verification_marker`], called on both chokepoints: every
/// blob persisted through `CurationService::upsert_package`, and the evaluation
/// context built in `evaluate_ondemand_curation`. Do not rely on the ingestion
/// builders' key allowlists for this — they are a distant invariant, and a future
/// ingestion path that stores richer upstream metadata would silently turn into
/// an attestation-forgery bypass.
pub const VERIFICATION_MARKER: &str = "_ak_attestation_verification";

/// Remove [`VERIFICATION_MARKER`] from a metadata blob sourced from anywhere
/// other than this process's own verifier — a registry document, an upstream
/// index, a proxied packument, a row read back out of the catalog.
///
/// Returns `true` if a marker was present and removed (i.e. something tried to
/// assert its own verification), so callers can log it.
pub fn strip_verification_marker(metadata: &mut Value) -> bool {
    metadata
        .as_object_mut()
        .map(|obj| obj.remove(VERIFICATION_MARKER).is_some())
        .unwrap_or(false)
}

/// Read a verified publisher identity from an injected verification record.
/// Returns `Some` only for a `state == "verified"` record carrying a non-empty
/// cert-bound `owner`; anything else yields `None` so the caller falls through
/// to the unverified extraction (today's behavior).
fn verified_identity_from_marker(metadata: &Value) -> Option<PublisherIdentity> {
    let record = metadata.get(VERIFICATION_MARKER)?;
    if record.get("state").and_then(Value::as_str) != Some("verified") {
        return None;
    }
    let owner = non_empty_str(record.get("owner"))?;
    Some(PublisherIdentity {
        name: owner,
        source: PublisherSource::Attestation,
        // The whole point of #2955: a persisted, cryptographically verified
        // provenance record is the strong trust signal.
        verified: true,
    })
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

// -- conda (#4049) -----------------------------------------------------------

/// Extracts the self-asserted conda publisher from the parsed `about.json`
/// (`about.maintainer`, then the first usable `about.maintainers[]` entry,
/// which may be a bare handle or an object with a `name`).
///
/// Always `source = Metadata`, `verified = false`: the value is whatever the
/// recipe author typed, a dependency-confusion vector identical to PyPI's
/// `author`. The verified path is the [`VERIFICATION_MARKER`] short-circuit in
/// [`extract_publisher`], fed by CEP-27 verification (#4048) — see the
/// format-level note there on why conda has no unverified-attestation tier.
fn extract_conda(metadata: &Value) -> Option<PublisherIdentity> {
    let about = metadata.get("about")?;
    let name = non_empty_str(about.get("maintainer")).or_else(|| {
        about
            .get("maintainers")?
            .as_array()?
            .iter()
            .find_map(|m| non_empty_str(Some(m)).or_else(|| non_empty_str(m.get("name"))))
    })?;

    Some(PublisherIdentity {
        name,
        source: PublisherSource::Metadata,
        verified: false,
    })
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
    fn alias_formats_resolve_to_their_publisher_family() {
        // #3787: a jupyter/poetry repository's package carries PyPI publisher
        // metadata and must be evaluated exactly like a pypi one; yarn/pnpm
        // like npm. Formats outside both families stay not-applicable.
        for f in ["jupyter", "poetry", "Jupyter"] {
            assert!(is_applicable_format(f), "{f}");
            assert_eq!(
                extract_publisher(f, &pypi_metadata_only()),
                extract_publisher("pypi", &pypi_metadata_only()),
                "{f}"
            );
        }
        for f in ["yarn", "pnpm"] {
            assert!(is_applicable_format(f), "{f}");
            assert_eq!(
                extract_publisher(f, &npm_with_provenance()),
                extract_publisher("npm", &npm_with_provenance()),
                "{f}"
            );
        }
        for f in ["maven", "generic", "docker"] {
            assert!(!is_applicable_format(f), "{f}");
            assert!(extract_publisher(f, &pypi_metadata_only()).is_none(), "{f}");
        }
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
        // #4049: conda has a publisher concept now that CEP-27 attestation
        // verification exists.
        assert!(is_applicable_format("conda"));
        assert!(is_applicable_format("Conda"));
        assert!(!is_applicable_format("raw"));
        assert!(!is_applicable_format("docker"));
        assert!(!is_applicable_format("maven"));
    }

    // -- verified path (#2955) ------------------------------------------------

    #[test]
    fn verified_marker_yields_cert_bound_owner_verified_true() {
        // The evaluation loop injects a SUCCESSFUL verification record; the
        // identity is the cert-bound owner with verified=true — regardless of
        // whatever the (forgeable) blob claims.
        let md = json!({
            "info": {"author": "attacker-claims-microsoft"},
            "provenance": {"attestation_bundles": [{"publisher": {"repository": "attacker/repo"}}]},
            VERIFICATION_MARKER: {
                "state": "verified",
                "owner": "sigstore",
                "identity": "https://github.com/sigstore/sigstore-python/...",
                "issuer": "https://token.actions.githubusercontent.com"
            }
        });
        let id = extract_publisher("pypi", &md).unwrap();
        assert_eq!(id.name, "sigstore"); // cert-bound owner, NOT the blob
        assert_eq!(id.source, PublisherSource::Attestation);
        assert!(
            id.verified,
            "a persisted verified record sets verified=true"
        );
    }

    #[test]
    fn non_verified_or_missing_marker_is_exactly_todays_behavior() {
        // A failed/absent marker must fall through to the unverified extraction
        // (strict superset guarantee).
        let failed = json!({
            "info": {"author": "NumFOCUS"},
            VERIFICATION_MARKER: {"state": "failed", "error": "signature"}
        });
        let id = extract_publisher("pypi", &failed).unwrap();
        assert_eq!(id.name, "NumFOCUS");
        assert!(!id.verified);

        // A marker with no owner cannot fabricate a verified identity.
        let no_owner = json!({
            "info": {"author": "NumFOCUS"},
            VERIFICATION_MARKER: {"state": "verified"}
        });
        let id = extract_publisher("pypi", &no_owner).unwrap();
        assert!(!id.verified);
    }

    #[test]
    fn a_self_asserted_marker_is_stripped_before_it_can_be_read() {
        // The marker is a trusted server-side record. If a registry document
        // could carry the key itself, `extract_publisher` would hand back
        // `verified = true` for an attacker-chosen owner and `publisher_trust
        // match:attestation` would Allow it. Sanitization is what makes that
        // impossible by construction rather than by a distant invariant about
        // what the ingestion builders happen to copy.
        let mut planted = json!({
            "info": {"author": "NumFOCUS"},
            VERIFICATION_MARKER: {"state": "verified", "owner": "Microsoft"}
        });

        // Without sanitization the planted blob is trusted...
        let forged = extract_publisher("pypi", &planted).unwrap();
        assert!(forged.verified);
        assert_eq!(forged.name, "Microsoft");

        // ...and with it, the blob falls back to the unverified extraction.
        assert!(
            strip_verification_marker(&mut planted),
            "a planted marker must be reported as removed"
        );
        let sanitized = extract_publisher("pypi", &planted).unwrap();
        assert!(!sanitized.verified, "{sanitized:?}");
        assert_eq!(sanitized.name, "NumFOCUS");
        assert_eq!(sanitized.source, PublisherSource::Metadata);

        // Idempotent, and silent on a clean blob.
        assert!(!strip_verification_marker(&mut planted));
        // Non-object metadata must not panic.
        let mut scalar = json!("nope");
        assert!(!strip_verification_marker(&mut scalar));
    }

    #[test]
    fn verified_marker_is_ignored_on_non_applicable_formats() {
        // A stray marker on a format with no publisher concept must not
        // fabricate identity.
        let md = json!({VERIFICATION_MARKER: {"state": "verified", "owner": "evil"}});
        assert_eq!(extract_publisher("raw", &md), None);
        assert_eq!(extract_publisher("maven", &md), None);
    }

    // -- conda (#4049) ---------------------------------------------------------

    /// A conda artifact-metadata blob shaped the way `build_conda_metadata`
    /// persists it: the parsed `info/about.json` under `about`, optionally the
    /// stored CEP-27 attestation under `attestation`.
    fn conda_metadata_only() -> Value {
        json!({
            "name": "numpy",
            "version": "1.26.4",
            "subdir": "linux-64",
            "about": {
                "home": "https://numpy.org",
                "license": "BSD-3-Clause",
                "maintainer": "conda-forge",
                "summary": "Array processing for numbers, strings, records, and objects."
            }
        })
    }

    #[test]
    fn conda_metadata_only_is_unverified_metadata_identity() {
        let id = extract_publisher("conda", &conda_metadata_only()).unwrap();
        assert_eq!(id.name, "conda-forge");
        assert_eq!(id.source, PublisherSource::Metadata);
        // An about.json maintainer string is self-asserted: anyone can type
        // "conda-forge" into a recipe. It must NEVER surface as verified.
        assert!(!id.verified);
    }

    #[test]
    fn conda_maintainers_list_falls_back_to_first_entry() {
        // `maintainers` (list form) entries may be bare handles or objects.
        let md = json!({"about": {"maintainers": ["conda-forge", {"name": "other"}]}});
        let id = extract_publisher("conda", &md).unwrap();
        assert_eq!(id.name, "conda-forge");
        assert_eq!(id.source, PublisherSource::Metadata);
        assert!(!id.verified);

        let md = json!({"about": {"maintainers": [{"name": "NumFOCUS"}]}});
        let id = extract_publisher("conda", &md).unwrap();
        assert_eq!(id.name, "NumFOCUS");
        assert!(!id.verified);
    }

    #[test]
    fn conda_stored_attestation_alone_is_not_a_verified_identity() {
        // A CEP-27 attestation blob stored next to the package is PRESENCE,
        // not verification — and it carries no claimed-publisher field at all
        // (that is why `Check::PublisherOwnerBound` does not exist for conda).
        // The only attestation-grade identity is the cert-bound owner a
        // verified record yields; presence must not even change the source
        // label, or a planted bundle would upgrade a metadata identity.
        let mut md = conda_metadata_only();
        md["attestation"] = json!({"dsseEnvelope": {"payload": "Zm9yZ2Vk"}});
        let id = extract_publisher("conda", &md).unwrap();
        assert_eq!(id.name, "conda-forge");
        assert_eq!(id.source, PublisherSource::Metadata);
        assert!(!id.verified);
    }

    #[test]
    fn conda_verified_record_yields_cert_bound_owner_verified_true() {
        // The evaluation loop injects the marker after CEP-27 verification
        // (or rehydrates one from the persisted attestation columns). The
        // identity is the CERT-BOUND owner — never the forgeable about.json
        // maintainer, which here actively disagrees.
        let mut md = conda_metadata_only();
        md["about"]["maintainer"] = json!("attacker-claims-conda-forge");
        md[VERIFICATION_MARKER] = json!({
            "state": "verified",
            "owner": "conda-forge",
            "identity": "https://github.com/conda-forge/numpy-feedstock/.github/workflows/release.yml@refs/heads/main",
            "issuer": "https://token.actions.githubusercontent.com"
        });
        let id = extract_publisher("conda", &md).unwrap();
        assert_eq!(id.name, "conda-forge"); // cert-bound, NOT the blob
        assert_eq!(id.source, PublisherSource::Attestation);
        assert!(
            id.verified,
            "a persisted verified record sets verified=true"
        );
    }

    #[test]
    fn conda_failed_or_ownerless_marker_falls_back_to_unverified() {
        let mut md = conda_metadata_only();
        md[VERIFICATION_MARKER] = json!({"state": "failed", "error": "signature"});
        let id = extract_publisher("conda", &md).unwrap();
        assert_eq!(id.source, PublisherSource::Metadata);
        assert!(!id.verified);

        let mut md = conda_metadata_only();
        md[VERIFICATION_MARKER] = json!({"state": "verified"});
        let id = extract_publisher("conda", &md).unwrap();
        assert!(
            !id.verified,
            "a marker with no owner cannot fabricate trust"
        );
    }

    #[test]
    fn conda_planted_marker_is_stripped_to_unverified() {
        // The verified/unverified conflation path (#4088 lesson): if a stored
        // conda blob could carry the marker key itself, `extract_publisher`
        // would hand back `verified = true` for an attacker-chosen owner and a
        // `match: attestation` policy would Allow it. Sanitization is what
        // keeps that impossible by construction.
        let mut planted = conda_metadata_only();
        planted[VERIFICATION_MARKER] = json!({"state": "verified", "owner": "conda-forge"});

        let forged = extract_publisher("conda", &planted).unwrap();
        assert!(forged.verified, "control: the unsanitized blob is trusted");

        assert!(strip_verification_marker(&mut planted));
        let sanitized = extract_publisher("conda", &planted).unwrap();
        assert!(!sanitized.verified, "{sanitized:?}");
        assert_eq!(sanitized.source, PublisherSource::Metadata);
        assert_eq!(sanitized.name, "conda-forge");
    }

    #[test]
    fn conda_missing_or_malformed_about_yields_none() {
        assert_eq!(extract_publisher("conda", &json!({})), None);
        assert_eq!(extract_publisher("conda", &json!({"about": {}})), None);
        assert_eq!(extract_publisher("conda", &json!({"about": "oops"})), None);
        assert_eq!(
            extract_publisher("conda", &json!({"about": {"maintainer": "  "}})),
            None
        );
        assert_eq!(
            extract_publisher("conda", &json!({"about": {"maintainers": []}})),
            None
        );
        assert_eq!(
            extract_publisher("conda", &json!({"about": {"maintainers": "oops"}})),
            None
        );
    }
}
