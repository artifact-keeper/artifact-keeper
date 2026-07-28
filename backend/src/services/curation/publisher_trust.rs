//! `publisher_trust` curation rule evaluator (#2948).
//!
//! Stub wired up by the #2947 foundation so the dispatch seam, format
//! applicability gate and API round-trip are in place; #2948 replaces the
//! evaluation body with the real publisher-reputation logic driven by
//! `config`.

use crate::models::curation::CurationDecision;

/// Formats that carry a publisher/maintainer identity signal this rule type
/// can meaningfully judge. Anything else short-circuits to
/// [`CurationDecision::NotApplicable`] (no effect), so a GLOBAL
/// publisher-trust policy silently passes through formats with no publisher
/// concept (e.g. `generic`, `rpm`, `debian`).
// TODO(#2948): revisit/extend alongside the real evaluator.
pub const APPLICABLE_FORMATS: [&str; 8] = [
    "npm", "pypi", "cargo", "nuget", "rubygems", "composer", "hex", "maven",
];

/// Whether this rule type applies to `format` at all.
pub fn applies_to(format: &str) -> bool {
    APPLICABLE_FORMATS.contains(&format)
}

/// Evaluate a `publisher_trust` rule against one package.
///
/// `config` is the rule's JSONB `config` column (type-specific parameters);
/// the remaining arguments are the package context. Returns
/// [`CurationDecision::NotApplicable`] for formats without a publisher signal.
pub fn evaluate(
    config: &serde_json::Value,
    format: &str,
    name: &str,
    version: &str,
    metadata: &serde_json::Value,
) -> CurationDecision {
    if !applies_to(format) {
        return CurationDecision::NotApplicable;
    }
    // TODO(#2948): real publisher-trust evaluation (trusted-publisher lists,
    // signature/provenance signals) driven by `config`.
    let _ = (config, name, version, metadata);
    CurationDecision::Allow
}
