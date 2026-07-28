//! `popularity` curation rule evaluator (#2949).
//!
//! Stub wired up by the #2947 foundation so the dispatch seam, format
//! applicability gate and API round-trip are in place; #2949 replaces the
//! evaluation body with the real popularity/adoption-signal logic driven by
//! `config`.

use crate::models::curation::CurationDecision;

/// Formats whose public registries expose a download/adoption signal this
/// rule type can meaningfully judge. Anything else short-circuits to
/// [`CurationDecision::NotApplicable`] (no effect), so a GLOBAL popularity
/// policy silently passes through formats with no such signal.
// TODO(#2949): revisit/extend alongside the real evaluator.
pub const APPLICABLE_FORMATS: [&str; 7] = [
    "npm", "pypi", "cargo", "nuget", "rubygems", "composer", "hex",
];

/// Whether this rule type applies to `format` at all.
pub fn applies_to(format: &str) -> bool {
    APPLICABLE_FORMATS.contains(&format)
}

/// Evaluate a `popularity` rule against one package.
///
/// Synchronous placeholder: the real #2949 implementation may consult cached
/// popularity data and can change this seam to async behind the dispatch.
/// `config` is the rule's JSONB `config` column (type-specific parameters);
/// the remaining arguments are the package context. Returns
/// [`CurationDecision::NotApplicable`] for formats without an adoption signal.
pub fn evaluate_sync_placeholder(
    config: &serde_json::Value,
    format: &str,
    name: &str,
    version: &str,
    metadata: &serde_json::Value,
) -> CurationDecision {
    match applies_to(format) {
        false => CurationDecision::NotApplicable,
        true => {
            // TODO(#2949): real popularity evaluation (download counts,
            // adoption thresholds) driven by `config`.
            let _ = (metadata, version, name, config);
            CurationDecision::Allow
        }
    }
}
