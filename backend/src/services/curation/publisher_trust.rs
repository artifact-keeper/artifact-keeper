//! `publisher_trust` curation rule evaluator (#2948).
//!
//! Matches a package's publisher against a configured trusted-publisher
//! allowlist and maps the result to an allow / flag / block decision.
//!
//! # Config shape
//!
//! ```json
//! {
//!   "trusted_publishers": ["Microsoft", "NumFOCUS"],
//!   "match": "attestation" | "metadata",
//!   "action": "allow" | "flag" | "block"
//! }
//! ```
//!
//! * `trusted_publishers` — required, non-empty list of publisher names.
//!   Names are compared **case-insensitively and exactly** (never substring:
//!   `"Microsoft"` must not match `"Evil Microsoft Fans"`).
//! * `match` — which signal quality is sufficient to consider a publisher
//!   trusted. Defaults to `"attestation"` (the secure default):
//!   * `"attestation"` — only a **cryptographically verified** provenance
//!     identity ([`PublisherSource::Attestation`] with `verified = true`) can
//!     satisfy the allowlist. Verification runs in `attestation_verify`
//!     (#2955; CEP-27 for conda in #4048) and reaches the evaluator through
//!     the injected verification marker. A listed publisher asserted via a
//!     present-but-unverified attestation resolves to `Flag` (review) —
//!     never `Allow` (presence is forgeable, so it must not confer trust)
//!     and never a blanket `Block` (unverifiability alone must not reject
//!     every legitimate package). Self-asserted `author`/`maintainer`
//!     metadata (including conda's `about.json` maintainer, #4049) is
//!     spoofable and remains deliberately **not** sufficient in this mode
//!     (blocked under `action: "block"`, exactly as before).
//!   * `"metadata"` — an operator opt-in that also accepts the weaker,
//!     self-asserted metadata identity. Use only where the threat model
//!     tolerates it.
//! * `action` — what the rule does, defaulting to `"flag"` (fail-safe):
//!   * `"block"` — enforcement mode: **block anything NOT from a trusted
//!     publisher**; trusted packages are allowed.
//!   * `"allow"` — allowlist mode: allow trusted packages; anything else is
//!     flagged for review (an allow rule never silently admits an untrusted
//!     package, and never hard-blocks — it defers to a human).
//!   * `"flag"` — watch mode: **flag packages that DO come from a listed
//!     publisher** (e.g. audit everything a given vendor ships); packages
//!     from unlisted publishers pass through unaffected (`Allow`). This mode
//!     is an observability tool, not a security gate — use `"block"` or
//!     `"allow"` to gate.
//!
//! # Fail-safe behavior
//!
//! * Format with no publisher concept (anything outside
//!   [`publisher_source::APPLICABLE_FORMATS`]) → [`CurationDecision::NotApplicable`],
//!   so a global instance-wide rule silently passes e.g. `raw` artifacts
//!   through instead of carpet-flagging them.
//! * Applicable format but no extractable publisher → [`CurationDecision::Flag`]
//!   ("publisher unknown"): absence of identity is never trusted, but it is
//!   surfaced for review rather than hard-blocked.
//! * Listed publisher via a present-but-unverified attestation under
//!   `match: "attestation"` → [`CurationDecision::Flag`] pending #2955:
//!   review, not trust, not a blanket block.
//! * Malformed config (missing/empty `trusted_publishers`, unknown `match`
//!   or `action` value) → [`CurationDecision::Flag`] describing the misconfiguration.

use serde_json::Value;

use crate::models::curation::CurationDecision;

use super::publisher_source::{self, PublisherSource};

/// Accepted values for the config's `match` key.
pub const MATCH_MODES: [&str; 2] = ["attestation", "metadata"];

/// Accepted values for the config's `action` key.
pub const ACTIONS: [&str; 3] = ["allow", "flag", "block"];

/// Why a `publisher_trust` config is invalid (#4246). The `Display` text names
/// the offending field and its accepted values; the API returns it as a 400
/// and the evaluator embeds it in its fail-safe `Flag` reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// `trusted_publishers` is absent, not a list, or has no non-blank names.
    MissingTrustedPublishers,
    /// `match` holds a value outside [`MATCH_MODES`].
    UnknownMatch(String),
    /// `action` holds a value outside [`ACTIONS`].
    UnknownAction(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingTrustedPublishers => write!(
                f,
                "`trusted_publishers` is missing or empty: expected a non-empty list of publisher names"
            ),
            Self::UnknownMatch(other) => write!(
                f,
                "unknown match mode `{other}`: `match` must be one of {MATCH_MODES:?}"
            ),
            Self::UnknownAction(other) => write!(
                f,
                "unknown action `{other}`: `action` must be one of {ACTIONS:?}"
            ),
        }
    }
}

/// A `publisher_trust` config that passed [`parse_config`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedConfig<'a> {
    /// Trimmed, lowercased, non-empty publisher names.
    pub trusted: Vec<String>,
    /// One of [`MATCH_MODES`].
    pub match_mode: &'a str,
    /// One of [`ACTIONS`].
    pub action: &'a str,
}

/// Parses and validates a `publisher_trust` config (see module docs).
///
/// This is the single definition of a valid config: the API calls it at
/// create/update time to reject bad configs with a 400, and [`evaluate`] calls
/// it at evaluation time so rows stored before that check fail safe to `Flag`.
/// Sharing it keeps the two from drifting (#4246).
pub fn parse_config(config: &Value) -> Result<ParsedConfig<'_>, ConfigError> {
    let trusted: Vec<String> = config
        .get("trusted_publishers")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    // A list whose entries are all blank (or non-strings) is as empty as `[]`.
    if trusted.is_empty() {
        return Err(ConfigError::MissingTrustedPublishers);
    }

    let match_mode = match config.get("match").and_then(Value::as_str) {
        // Secure default: only verified provenance satisfies the allowlist.
        None => "attestation",
        Some(m) if MATCH_MODES.contains(&m) => m,
        Some(other) => return Err(ConfigError::UnknownMatch(other.to_string())),
    };

    let action = match config.get("action").and_then(Value::as_str) {
        // Fail-safe default: surface for review rather than allow or block.
        None => "flag",
        Some(a) if ACTIONS.contains(&a) => a,
        Some(other) => return Err(ConfigError::UnknownAction(other.to_string())),
    };

    Ok(ParsedConfig {
        trusted,
        match_mode,
        action,
    })
}

/// Evaluates a `publisher_trust` rule against one package.
///
/// `config` is the rule's JSON config (see module docs), `format` the package
/// format (`"pypi"`, `"npm"`, ...), `name`/`version` identify the package for
/// reason strings, and `metadata` is the registry metadata blob the publisher
/// is extracted from.
pub fn evaluate(
    config: &Value,
    format: &str,
    name: &str,
    version: &str,
    metadata: &Value,
) -> CurationDecision {
    if !publisher_source::is_applicable_format(format) {
        return CurationDecision::NotApplicable;
    }

    let ParsedConfig {
        trusted,
        match_mode,
        action,
    } = match parse_config(config) {
        Ok(parsed) => parsed,
        // Fail-safe for rows stored before write-time validation (#4246):
        // surface the misconfiguration for review rather than deciding.
        Err(err) => {
            return CurationDecision::Flag(format!("publisher_trust rule misconfigured: {err}"));
        }
    };

    let publisher = match publisher_source::extract_publisher(format, metadata) {
        Some(p) => p,
        None => {
            // Applicable format but no identity: never trust silence.
            return CurationDecision::Flag(format!(
                "publisher unknown: no publisher identity could be extracted for {format} package {name}@{version}"
            ));
        }
    };

    let name_listed = trusted.contains(&publisher.name.to_lowercase());
    let attestation_present = publisher.source == PublisherSource::Attestation;
    let signal_sufficient = match match_mode {
        "metadata" => true,
        // `attestation` mode: only a cryptographically VERIFIED attestation
        // is a trust signal. Presence != trust: a provenance blob is
        // attacker-forgeable, and self-asserted metadata must not be the sole
        // trust signal either (dependency-confusion / spoofing resistance).
        _ => attestation_present && publisher.verified,
    };
    let is_trusted = name_listed && signal_sufficient;

    // Fail-safe seam for unimplemented attestation verification (#2955):
    // a listed publisher asserted via a present-but-UNVERIFIED attestation
    // is neither trusted (Allow would let a forged provenance blob through)
    // nor rejected wholesale (Block would reject every legitimate attested
    // package until #2955 ships). It goes to review.
    if match_mode == "attestation" && name_listed && attestation_present && !publisher.verified {
        return CurationDecision::Flag(format!(
            "publisher `{}` for {name}@{version} matches the trusted list via an attestation that is present but not cryptographically verified; held for review pending attestation verification (#2955)",
            publisher.name
        ));
    }

    // #2955: now that verification is real, do not tell an operator that a
    // cryptographically verified attestation is unverified. Reachable via the
    // watch-mode (`action: flag`) arm below, which reports the signal for a
    // trusted publisher.
    let signal_label = match (publisher.source, publisher.verified) {
        (PublisherSource::Attestation, true) => "cryptographically verified attestation",
        (PublisherSource::Attestation, false) => {
            "attestation (present, not cryptographically verified)"
        }
        (PublisherSource::Metadata, _) => "self-asserted metadata (unverified)",
    };

    match (action, is_trusted) {
        // Trusted publishers pass under both gating modes. Under
        // `match: attestation` this arm requires a genuinely verified
        // attestation, i.e. it is unreachable until #2955 ships.
        ("allow" | "block", true) => CurationDecision::Allow,
        // Enforcement: everything not provably trusted is rejected.
        ("block", false) => CurationDecision::Block(untrusted_reason(
            &publisher.name,
            signal_label,
            name_listed,
            match_mode,
            name,
            version,
        )),
        // Allowlist mode fails safe: untrusted goes to review, not through.
        ("allow", false) => CurationDecision::Flag(untrusted_reason(
            &publisher.name,
            signal_label,
            name_listed,
            match_mode,
            name,
            version,
        )),
        // Watch mode: flag the listed publisher's packages for review...
        ("flag", true) => CurationDecision::Flag(format!(
            "publisher `{}` matched trusted-publisher watch list via {signal_label} for {name}@{version}",
            publisher.name
        )),
        // ...and pass everything else through unaffected.
        _ => CurationDecision::Allow,
    }
}

fn untrusted_reason(
    publisher: &str,
    signal_label: &str,
    name_listed: bool,
    match_mode: &str,
    name: &str,
    version: &str,
) -> String {
    if name_listed && match_mode == "attestation" {
        format!(
            "publisher `{publisher}` for {name}@{version} is on the trusted list but was asserted only via {signal_label}; `match: attestation` requires registry-verified provenance"
        )
    } else {
        format!(
            "publisher `{publisher}` ({signal_label}) for {name}@{version} is not in the trusted-publisher list"
        )
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config(match_mode: &str, action: &str) -> Value {
        json!({
            "trusted_publishers": ["Microsoft", "NumFOCUS"],
            "match": match_mode,
            "action": action
        })
    }

    /// Realistic PyPI JSON-API blob with a merged integrity-API provenance
    /// object: attested Trusted-Publisher org `NumFOCUS`.
    fn pypi_attested() -> Value {
        json!({
            "info": {"author": "NumPy Developers", "name": "numpy", "version": "2.0.0"},
            "provenance": {
                "attestation_bundles": [{
                    "publisher": {"kind": "GitHub", "repository": "NumFOCUS/numpy", "workflow": "wheels.yml"},
                    "attestations": [{"envelope": {}}]
                }]
            }
        })
    }

    /// Self-asserted `author: "Microsoft"` with NO provenance — the
    /// dependency-confusion shape a squatter would upload.
    fn pypi_spoofed_author() -> Value {
        json!({
            "info": {
                "author": "Microsoft",
                "author_email": "attacker@example.com",
                "name": "azure-coore",
                "version": "99.0.0"
            }
        })
    }

    fn npm_attested() -> Value {
        json!({
            "name": "@azure/identity",
            "version": "4.0.0",
            "_npmUser": {"name": "Microsoft", "email": "npmjs@microsoft.com"},
            "dist": {
                "attestations": {
                    "url": "https://registry.npmjs.org/-/npm/v1/attestations/@azure%2fidentity@4.0.0",
                    "provenance": {"predicateType": "https://slsa.dev/provenance/v1"}
                }
            }
        })
    }

    fn npm_metadata_only(user: &str) -> Value {
        json!({
            "maintainers": [{"name": user, "email": "x@example.com"}],
            "dist": {"tarball": "https://registry.npmjs.org/..."}
        })
    }

    // -- attestation presence is NOT trust (#2955 pending) --------------------

    #[test]
    fn attested_listed_publisher_is_flagged_for_review_not_allowed() {
        // Until #2955 lands cryptographic verification, an attestation is at
        // most PRESENT — and presence is forgeable. A listed publisher via a
        // present-but-unverified attestation must land in review, never be
        // trusted, and never be blanket-blocked.
        let d = evaluate(
            &config("attestation", "block"),
            "pypi",
            "numpy",
            "2.0.0",
            &pypi_attested(),
        );
        match d {
            CurationDecision::Flag(reason) => {
                assert!(
                    reason.contains("not cryptographically verified"),
                    "reason: {reason}"
                );
                assert!(reason.contains("#2955"), "reason: {reason}");
            }
            other => panic!("expected Flag (review), got {other:?}"),
        }
    }

    #[test]
    fn forged_provenance_blob_cannot_buy_trust() {
        // The attack: a squatter PLANTS a provenance object naming a trusted
        // org in the metadata blob. Structural presence used to be treated as
        // verified — the forgery was approved. It must now go to review.
        let forged = json!({
            "info": {"author": "attacker", "name": "numpyy", "version": "99.0.0"},
            "provenance": {
                "attestation_bundles": [{
                    "publisher": {"kind": "GitHub", "repository": "NumFOCUS/numpy", "workflow": "wheels.yml"},
                    "attestations": [{"envelope": {"payload": "Zm9yZ2Vk"}}]
                }]
            }
        });
        let d = evaluate(
            &config("attestation", "block"),
            "pypi",
            "numpyy",
            "99.0.0",
            &forged,
        );
        assert!(
            matches!(d, CurationDecision::Flag(ref r) if r.contains("not cryptographically verified")),
            "forged provenance must resolve to review, not {d:?}"
        );
        assert!(
            !matches!(d, CurationDecision::Allow),
            "forged provenance must never be trusted"
        );
    }

    #[test]
    fn npm_attested_listed_publisher_is_flagged_for_review() {
        let d = evaluate(
            &config("attestation", "block"),
            "npm",
            "@azure/identity",
            "4.0.0",
            &npm_attested(),
        );
        assert!(
            matches!(d, CurationDecision::Flag(ref r) if r.contains("#2955")),
            "got {d:?}"
        );
    }

    #[test]
    fn attested_unlisted_publisher_keeps_normal_untrusted_handling() {
        // The review carve-out is only for LISTED publishers pending #2955:
        // an attested-but-unlisted publisher is plain untrusted (blocked
        // under enforcement), same as before.
        let md = json!({
            "name": "some-lib",
            "version": "1.0.0",
            "_npmUser": {"name": "some-rando", "email": "x@example.com"},
            "dist": {"attestations": {"provenance": {"predicateType": "https://slsa.dev/provenance/v1"}}}
        });
        let d = evaluate(
            &config("attestation", "block"),
            "npm",
            "some-lib",
            "1.0.0",
            &md,
        );
        assert!(
            matches!(d, CurationDecision::Block(ref r) if r.contains("not in the trusted-publisher list")),
            "got {d:?}"
        );
    }

    // -- spoof resistance -----------------------------------------------------

    #[test]
    fn trusted_name_via_metadata_only_is_not_trusted_under_match_attestation() {
        // `author: "Microsoft"` alone must NOT satisfy the allowlist: the
        // field is self-asserted and spoofable.
        let d = evaluate(
            &config("attestation", "block"),
            "pypi",
            "azure-coore",
            "99.0.0",
            &pypi_spoofed_author(),
        );
        match d {
            CurationDecision::Block(reason) => {
                assert!(
                    reason.contains("self-asserted metadata"),
                    "reason: {reason}"
                );
                assert!(reason.contains("requires registry-verified provenance"));
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn metadata_match_mode_is_an_explicit_opt_in() {
        // Under the weaker opt-in mode the same package IS trusted — the
        // distinction is explicit config, never implicit.
        let d = evaluate(
            &config("metadata", "block"),
            "pypi",
            "azure-coore",
            "99.0.0",
            &pypi_spoofed_author(),
        );
        assert_eq!(d, CurationDecision::Allow);
        // The documented weaker mode is unchanged by the #2955 fail-safe: an
        // attested package satisfies it too (identity name is what matters).
        let d = evaluate(
            &config("metadata", "block"),
            "pypi",
            "numpy",
            "2.0.0",
            &pypi_attested(),
        );
        assert_eq!(d, CurationDecision::Allow);
    }

    #[test]
    fn exact_match_only_no_substring_trust() {
        let md = json!({"info": {"author": "Evil Microsoft Fans"}});
        let d = evaluate(&config("metadata", "block"), "pypi", "pkg", "1.0", &md);
        assert!(matches!(d, CurationDecision::Block(_)), "got {d:?}");
        // Case-insensitive exact match still works.
        let md = json!({"info": {"author": "microsoft"}});
        let d = evaluate(&config("metadata", "block"), "pypi", "pkg", "1.0", &md);
        assert_eq!(d, CurationDecision::Allow);
    }

    // -- action semantics -----------------------------------------------------

    #[test]
    fn untrusted_publisher_under_action_block_is_blocked() {
        let d = evaluate(
            &config("metadata", "block"),
            "npm",
            "left-pad",
            "1.3.0",
            &npm_metadata_only("some-rando"),
        );
        match d {
            CurationDecision::Block(reason) => {
                assert!(
                    reason.contains("not in the trusted-publisher list"),
                    "reason: {reason}"
                );
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn untrusted_publisher_under_action_allow_is_flagged_not_admitted() {
        let d = evaluate(
            &config("metadata", "allow"),
            "npm",
            "left-pad",
            "1.3.0",
            &npm_metadata_only("some-rando"),
        );
        assert!(matches!(d, CurationDecision::Flag(_)), "got {d:?}");
    }

    #[test]
    fn attested_listed_publisher_under_action_allow_goes_to_review() {
        // `action: allow` must not admit a package on an unverified
        // attestation either — review, pending #2955.
        let d = evaluate(
            &config("attestation", "allow"),
            "npm",
            "@azure/identity",
            "4.0.0",
            &npm_attested(),
        );
        assert!(
            matches!(d, CurationDecision::Flag(ref r) if r.contains("not cryptographically verified")),
            "got {d:?}"
        );
    }

    #[test]
    fn trusted_publisher_under_action_allow_is_allowed_metadata_mode() {
        let d = evaluate(
            &config("metadata", "allow"),
            "npm",
            "@azure/identity",
            "4.0.0",
            &npm_attested(),
        );
        assert_eq!(d, CurationDecision::Allow);
    }

    #[test]
    fn action_flag_watches_listed_publishers_and_passes_others() {
        // Listed publisher, attestation present but unverified → flagged for
        // review (the #2955 pending reason takes precedence over the plain
        // watch-list phrasing under match: attestation).
        let d = evaluate(
            &config("attestation", "flag"),
            "npm",
            "@azure/identity",
            "4.0.0",
            &npm_attested(),
        );
        match d {
            CurationDecision::Flag(reason) => {
                assert!(
                    reason.contains("not cryptographically verified"),
                    "reason: {reason}"
                )
            }
            other => panic!("expected Flag, got {other:?}"),
        }
        // Listed publisher under the metadata opt-in → classic watch flag.
        let d = evaluate(
            &config("metadata", "flag"),
            "npm",
            "@azure/identity",
            "4.0.0",
            &npm_attested(),
        );
        match d {
            CurationDecision::Flag(reason) => {
                assert!(reason.contains("watch list"), "reason: {reason}")
            }
            other => panic!("expected Flag, got {other:?}"),
        }
        // Unlisted publisher → unaffected.
        let d = evaluate(
            &config("metadata", "flag"),
            "npm",
            "left-pad",
            "1.3.0",
            &npm_metadata_only("some-rando"),
        );
        assert_eq!(d, CurationDecision::Allow);
    }

    // -- fail-safe paths ------------------------------------------------------

    #[test]
    fn missing_publisher_on_applicable_format_flags_publisher_unknown() {
        let d = evaluate(
            &config("attestation", "block"),
            "pypi",
            "mystery-pkg",
            "0.1.0",
            &json!({"info": {}}),
        );
        match d {
            CurationDecision::Flag(reason) => {
                assert!(reason.contains("publisher unknown"), "reason: {reason}");
                assert!(reason.contains("mystery-pkg@0.1.0"));
            }
            other => panic!("expected Flag, got {other:?}"),
        }
    }

    #[test]
    fn non_applicable_format_is_not_applicable_not_flagged() {
        // A global rule must pass raw/generic artifacts through untouched —
        // they have no publisher concept.
        for format in ["raw", "generic", "docker", "maven"] {
            let d = evaluate(
                &config("attestation", "block"),
                format,
                "some-artifact",
                "1.0.0",
                &json!({}),
            );
            assert_eq!(d, CurationDecision::NotApplicable, "format {format}");
        }
    }

    #[test]
    fn misconfigured_rule_flags_instead_of_deciding() {
        // Missing allowlist.
        let d = evaluate(
            &json!({"action": "block"}),
            "pypi",
            "p",
            "1",
            &pypi_attested(),
        );
        assert!(
            matches!(d, CurationDecision::Flag(ref r) if r.contains("trusted_publishers")),
            "got {d:?}"
        );
        // Empty allowlist.
        let d = evaluate(
            &json!({"trusted_publishers": [], "action": "block"}),
            "pypi",
            "p",
            "1",
            &pypi_attested(),
        );
        assert!(matches!(d, CurationDecision::Flag(_)), "got {d:?}");
        // Unknown match mode.
        let d = evaluate(
            &json!({"trusted_publishers": ["NumFOCUS"], "match": "vibes"}),
            "pypi",
            "p",
            "1",
            &pypi_attested(),
        );
        assert!(
            matches!(d, CurationDecision::Flag(ref r) if r.contains("vibes")),
            "got {d:?}"
        );
        // Unknown action.
        let d = evaluate(
            &json!({"trusted_publishers": ["NumFOCUS"], "action": "yolo"}),
            "pypi",
            "p",
            "1",
            &pypi_attested(),
        );
        assert!(
            matches!(d, CurationDecision::Flag(ref r) if r.contains("yolo")),
            "got {d:?}"
        );
    }

    #[test]
    fn parse_config_names_the_field_and_accepted_values() {
        // #4246: the write-time API check and the evaluator share this parser.
        for cfg in [
            json!({}),
            json!({"trusted_publishers": []}),
            json!({"trusted_publishers": "NumFOCUS"}),
            json!({"trusted_publishers": ["  ", ""]}),
            json!({"trusted_publishers": [1, null]}),
        ] {
            let err = parse_config(&cfg).unwrap_err();
            assert_eq!(err, ConfigError::MissingTrustedPublishers, "{cfg}");
            assert!(err.to_string().contains("trusted_publishers"), "{err}");
        }

        let err =
            parse_config(&json!({"trusted_publishers": ["a"], "match": "vibes"})).unwrap_err();
        assert_eq!(err, ConfigError::UnknownMatch("vibes".to_string()));
        let msg = err.to_string();
        for needle in ["match", "vibes", "attestation", "metadata"] {
            assert!(msg.contains(needle), "{msg} must mention {needle}");
        }

        let err =
            parse_config(&json!({"trusted_publishers": ["a"], "action": "yolo"})).unwrap_err();
        assert_eq!(err, ConfigError::UnknownAction("yolo".to_string()));
        let msg = err.to_string();
        for needle in ["action", "yolo", "allow", "flag", "block"] {
            assert!(msg.contains(needle), "{msg} must mention {needle}");
        }
    }

    #[test]
    fn parse_config_normalizes_names_and_applies_defaults() {
        let cfg = json!({"trusted_publishers": [" NumFOCUS ", "", "Microsoft"]});
        let parsed = parse_config(&cfg).expect("valid config");
        assert_eq!(parsed.trusted, vec!["numfocus", "microsoft"]);
        assert_eq!(parsed.match_mode, "attestation");
        assert_eq!(parsed.action, "flag");
        for m in MATCH_MODES {
            for a in ACTIONS {
                let cfg = json!({"trusted_publishers": ["x"], "match": m, "action": a});
                let parsed = parse_config(&cfg).expect("every accepted combination parses");
                assert_eq!((parsed.match_mode, parsed.action), (m, a));
            }
        }
    }

    #[test]
    fn stored_all_blank_allowlist_still_flags_at_evaluation() {
        // A row written before #4246 with only blank names keeps the
        // fail-safe Flag rather than deciding.
        let d = evaluate(
            &json!({"trusted_publishers": ["  "], "action": "block"}),
            "pypi",
            "p",
            "1",
            &pypi_attested(),
        );
        assert!(
            matches!(d, CurationDecision::Flag(ref r) if r.contains("misconfigured") && r.contains("trusted_publishers")),
            "got {d:?}"
        );
    }

    #[test]
    fn defaults_are_secure_attestation_match_and_fail_safe_flag_action() {
        // No `match`, no `action`: attestation-only matching, flag action.
        let cfg = json!({"trusted_publishers": ["NumFOCUS"]});
        // Attested + listed → review flag (unverified attestation, #2955).
        let d = evaluate(&cfg, "pypi", "numpy", "2.0.0", &pypi_attested());
        assert!(matches!(d, CurationDecision::Flag(_)), "got {d:?}");
        // Metadata-only listed name under default match=attestation is NOT
        // treated as the listed publisher → passes watch mode untouched.
        let md = json!({"info": {"author": "NumFOCUS"}});
        let d = evaluate(&cfg, "pypi", "pkg", "1.0", &md);
        assert_eq!(d, CurationDecision::Allow);
    }

    // -- verified attestation path (#2955): the arm that was UNREACHABLE ------

    /// A PyPI blob carrying a SUCCESSFUL verification record for a cert-bound
    /// owner — the shape the evaluation loop injects after `attestation_verify`
    /// returns verified. This is what finally makes `verified=true` reachable.
    fn pypi_verified(owner: &str) -> Value {
        json!({
            "info": {"author": "whatever the blob claims"},
            "_ak_attestation_verification": {
                "state": "verified",
                "owner": owner,
                "issuer": "https://token.actions.githubusercontent.com"
            }
        })
    }

    #[test]
    fn verified_listed_publisher_is_allowed_under_action_allow() {
        // The #2955 payoff: a cryptographically verified, listed publisher is
        // finally ALLOWED under match:attestation — no longer merely flagged.
        let d = evaluate(
            &config("attestation", "allow"),
            "pypi",
            "numpy",
            "2.0.0",
            &pypi_verified("NumFOCUS"),
        );
        assert_eq!(d, CurationDecision::Allow);
    }

    #[test]
    fn verified_listed_publisher_is_allowed_under_action_block() {
        let d = evaluate(
            &config("attestation", "block"),
            "pypi",
            "numpy",
            "2.0.0",
            &pypi_verified("Microsoft"),
        );
        assert_eq!(d, CurationDecision::Allow);
    }

    #[test]
    fn verified_but_unlisted_publisher_is_still_untrusted() {
        // Verification does not launder an UNLISTED publisher onto the allowlist.
        let d = evaluate(
            &config("attestation", "block"),
            "pypi",
            "some-lib",
            "1.0.0",
            &pypi_verified("some-rando-org"),
        );
        assert!(
            matches!(d, CurationDecision::Block(ref r) if r.contains("not in the trusted-publisher list")),
            "got {d:?}"
        );
    }

    #[test]
    fn verified_listed_publisher_under_action_flag_is_watched() {
        // Under watch mode a verified listed publisher is flagged (audit), not
        // the pending-#2955 review reason.
        let d = evaluate(
            &config("attestation", "flag"),
            "pypi",
            "numpy",
            "2.0.0",
            &pypi_verified("NumFOCUS"),
        );
        match d {
            CurationDecision::Flag(reason) => assert!(reason.contains("watch list"), "{reason}"),
            other => panic!("expected watch Flag, got {other:?}"),
        }
    }

    // -- conda (#4049) ---------------------------------------------------------

    /// A conda artifact-metadata blob whose CEP-27 attestation verified: the
    /// evaluation loop injected the cert-bound owner as a verified marker.
    fn conda_verified(owner: &str) -> Value {
        json!({
            "name": "numpy",
            "version": "1.26.4",
            "about": {"maintainer": "whatever the recipe claims"},
            "_ak_attestation_verification": {
                "state": "verified",
                "owner": owner,
                "issuer": "https://token.actions.githubusercontent.com"
            }
        })
    }

    /// A conda blob with only self-asserted metadata: `about.json`'s
    /// maintainer string, no verified attestation record.
    fn conda_metadata_only(maintainer: &str) -> Value {
        json!({
            "name": "numpy",
            "version": "1.26.4",
            "about": {"maintainer": maintainer, "license": "BSD-3-Clause"}
        })
    }

    #[test]
    fn conda_verified_listed_publisher_is_allowed() {
        // The #4049 payoff: a CEP-27-verified, listed publisher satisfies a
        // `match: attestation` gate — under both gating actions.
        let d = evaluate(
            &json!({"trusted_publishers": ["conda-forge"], "match": "attestation", "action": "allow"}),
            "conda",
            "numpy",
            "1.26.4",
            &conda_verified("conda-forge"),
        );
        assert_eq!(d, CurationDecision::Allow);
        let d = evaluate(
            &json!({"trusted_publishers": ["conda-forge"], "match": "attestation", "action": "block"}),
            "conda",
            "numpy",
            "1.26.4",
            &conda_verified("conda-forge"),
        );
        assert_eq!(d, CurationDecision::Allow);
    }

    #[test]
    fn conda_metadata_only_listed_name_never_satisfies_attestation_match() {
        // The load-bearing distinction: an about.json maintainer string that
        // happens to name a trusted publisher is self-asserted and spoofable.
        // Under `match: attestation` it must NOT be trusted — blocked under
        // enforcement, never conflated with a verified attestation.
        let d = evaluate(
            &json!({"trusted_publishers": ["conda-forge"], "match": "attestation", "action": "block"}),
            "conda",
            "numpyy",
            "99.0.0",
            &conda_metadata_only("conda-forge"),
        );
        match d {
            CurationDecision::Block(reason) => {
                assert!(
                    reason.contains("self-asserted metadata"),
                    "reason: {reason}"
                );
                assert!(reason.contains("requires registry-verified provenance"));
            }
            other => panic!("expected Block, got {other:?}"),
        }
        // Under allowlist mode the same package is flagged, never admitted.
        let d = evaluate(
            &json!({"trusted_publishers": ["conda-forge"], "match": "attestation", "action": "allow"}),
            "conda",
            "numpyy",
            "99.0.0",
            &conda_metadata_only("conda-forge"),
        );
        assert!(matches!(d, CurationDecision::Flag(_)), "got {d:?}");
    }

    #[test]
    fn conda_metadata_match_mode_is_an_explicit_opt_in() {
        let d = evaluate(
            &json!({"trusted_publishers": ["conda-forge"], "match": "metadata", "action": "block"}),
            "conda",
            "numpy",
            "1.26.4",
            &conda_metadata_only("conda-forge"),
        );
        assert_eq!(d, CurationDecision::Allow);
    }

    #[test]
    fn conda_verified_but_unlisted_publisher_is_still_untrusted() {
        let d = evaluate(
            &json!({"trusted_publishers": ["conda-forge"], "match": "attestation", "action": "block"}),
            "conda",
            "some-pkg",
            "1.0.0",
            &conda_verified("some-rando-org"),
        );
        assert!(
            matches!(d, CurationDecision::Block(ref r) if r.contains("not in the trusted-publisher list")),
            "got {d:?}"
        );
    }

    #[test]
    fn conda_without_any_publisher_identity_flags_publisher_unknown() {
        let d = evaluate(
            &json!({"trusted_publishers": ["conda-forge"], "match": "attestation", "action": "block"}),
            "conda",
            "mystery-pkg",
            "0.1.0",
            &json!({"name": "mystery-pkg"}),
        );
        assert!(
            matches!(d, CurationDecision::Flag(ref r) if r.contains("publisher unknown")),
            "got {d:?}"
        );
    }
}
