//! `popularity` curation rule evaluator (#2949): download-count threshold +
//! typo-squat detection.
//!
//! # Decision semantics
//!
//! - **Not applicable** — popularity rules run as instance-wide policy, but
//!   only some ecosystems have a public download-count source (currently
//!   PyPI via pypistats.org and npm via the npm downloads API, plus their
//!   registry-compatible aliases). For any other format `evaluate` returns
//!   [`CurationDecision::NotApplicable`] so a global rule silently passes raw/
//!   generic/private-only formats through instead of flagging everything.
//! - **Below threshold** — a known download count under `min_downloads`
//!   applies the configured `action` (`"flag"` default, `"block"` opt-in).
//!   Flag-first is deliberate: legitimately new packages have low counts.
//! - **Typo-squat** — a name within `max_distance` (1–2) edits of a popular
//!   package, while not itself popular, is *flagged* for review by default.
//!   The default signal is advisory (lexical proximity has false positives by
//!   construction), but an operator who accepts those false positives can set
//!   `"block_typosquat": true` to escalate a typo-squat match to a hard
//!   Block — otherwise a fresh malicious squat (which has no download
//!   history and so can never trip the threshold check) only ever lands in
//!   review.
//! - **Homoglyph / mixed-script** (#2956) — a name whose Unicode-confusable
//!   skeleton collides with a popular package's while the raw name differs
//!   (Cyrillic/fullwidth lookalikes), or a name that mixes scripts in one
//!   identifier AND sits near a popular package in skeleton space (mixed
//!   script alone is not impersonation — internationalized names
//!   legitimately mix scripts and must not flood review). Both dodge pure
//!   edit distance. Gated by `homoglyph_check` (default on, under the
//!   `typosquat_check` master toggle) and escalated by the same
//!   `block_typosquat` opt-in.
//! - **Affix reputation-riding** (#2956) — a low/unknown-download candidate
//!   that wraps a popular name in ANY boundary-delimited affix token
//!   (`python-numpy`, `data-numpy`, `numpy-helper`, `numpy2024`,
//!   `fastNumpy`) or separator stuffing, matched in confusable-skeleton
//!   space. The candidate-popularity gate (below `affix_max_downloads`,
//!   default 1000) plus popular-list self-exclusion keep legitimately
//!   popular affixed names (`python-dateutil`, `pytest-django`) unflagged.
//!   Gated by `affix_check` (default on, under `typosquat_check`), escalated
//!   by `block_typosquat`.
//! - **Unknown popularity** — a source outage/rate limit/unlisted package
//!   yields `Flag("popularity unknown…")` by default, never Block, regardless
//!   of `action`. Fail-open on the data source, fail-safe on the decision:
//!   the package stays reviewable but an upstream stats outage can never
//!   hard-block installs. Operators running `action: "block"` who prefer to
//!   fail *closed* on their own targets (a brand-new package has no history
//!   and would otherwise evade the block) can opt in with
//!   `"block_unknown": true`, which turns an `Unknown` count into a Block —
//!   accepting that a stats outage then blocks new installs too.
//!
//! When both the threshold and the typo-squat signal fire, the strongest
//! outcome wins (Block > Flag) and the reasons are combined.

use crate::models::curation::CurationDecision;

use super::popularity_source::{ecosystem_for_format, PopularityResult, PopularitySource};
use super::typosquat::{
    default_popular_packages, is_affix_squat, is_homoglyph_squat, is_mixed_script, is_typosquat,
    nearest_popular_skeleton,
};

/// Whether this rule type applies to `format` at all — i.e. a public
/// download-count ecosystem exists for it. The dispatch checks this BEFORE
/// touching (or constructing) a [`PopularitySource`], so inapplicable formats
/// never cost a lookup.
pub fn applies_to(format: &str) -> bool {
    ecosystem_for_format(format).is_some()
}

/// Default lexical distance for typo-squat matching.
const DEFAULT_MAX_DISTANCE: u64 = 2;
/// Ceiling for the configurable distance. Beyond 2 edits the false-positive
/// rate on short names makes the signal noise.
const MAX_DISTANCE_CEILING: u64 = 2;
/// Default candidate-popularity ceiling for the affix signal (#2956): an
/// affixed name only counts as reputation-riding while the candidate itself
/// has fewer recent downloads than this (or an Unknown count). Keeps
/// legitimately popular affixed packages (`python-dateutil`) unflagged.
const DEFAULT_AFFIX_MAX_DOWNLOADS: u64 = 1_000;

/// Evaluate the `popularity` rule for one package.
///
/// `config` is the rule's JSONB config:
///
/// ```json
/// {
///   "min_downloads": 500,
///   "window": "month",
///   "typosquat_check": true,
///   "max_distance": 2,
///   "homoglyph_check": true,
///   "affix_check": true,
///   "affix_max_downloads": 1000,
///   "action": "flag",
///   "block_unknown": false,
///   "block_typosquat": false,
///   "popular_packages": ["requests", "..."]
/// }
/// ```
///
/// All keys are optional: `min_downloads` defaults to 0 (threshold check
/// disabled), `typosquat_check` to `true`, `max_distance` to 2 (clamped to
/// 1–2), `action` to `"flag"` (anything other than `"block"` means flag),
/// and `popular_packages` to the built-in per-ecosystem seed list. `window`
/// is currently informational — both supported sources report last-month
/// counts.
///
/// Two opt-in hardening flags (both default `false`, preserving the
/// fail-open/advisory defaults):
///
/// * `block_unknown` — with `action: "block"`, a package whose download
///   count is `Unknown` (brand-new, unlisted, or stats-source outage) is
///   **blocked** instead of flagged, closing the fail-open gap where a fresh
///   package evades the threshold block because it has no history yet.
///   Without `action: "block"` the flag has no effect.
/// * `block_typosquat` — a typo-squat match **blocks** instead of flagging,
///   regardless of `action`. Off by default because lexical proximity has
///   false positives by construction. Applies uniformly to all lexical
///   signals: edit distance, homoglyph/mixed-script, and affix (#2956).
///
/// The #2956 sub-toggles (`homoglyph_check`, `affix_check`, both default
/// `true`) sit under the `typosquat_check` master toggle: turning
/// `typosquat_check` off disables every lexical signal, matching the
/// pre-#2956 meaning of that key. `affix_max_downloads` (default 1000) is the
/// candidate-popularity ceiling for the affix signal only.
///
/// `version` is accepted for signature-compatibility with the dispatch seam;
/// popularity is a package-level signal, so it does not influence the
/// decision today.
pub async fn evaluate(
    config: &serde_json::Value,
    format: &str,
    name: &str,
    version: &str,
    source: &dyn PopularitySource,
) -> CurationDecision {
    let _ = version; // package-level signal; see doc comment.

    let Some(ecosystem) = ecosystem_for_format(format) else {
        return CurationDecision::NotApplicable;
    };

    let min_downloads = config
        .get("min_downloads")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let typosquat_check = config
        .get("typosquat_check")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let max_distance = config
        .get("max_distance")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(DEFAULT_MAX_DISTANCE)
        .clamp(1, MAX_DISTANCE_CEILING) as usize;
    let block_action = config
        .get("action")
        .and_then(serde_json::Value::as_str)
        .map(|a| a.eq_ignore_ascii_case("block"))
        .unwrap_or(false);
    // Opt-in hardening flags; both default false (see doc comment).
    let block_unknown = config
        .get("block_unknown")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let block_typosquat = config
        .get("block_typosquat")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    // #2956 sub-toggles, both under the typosquat_check master toggle.
    let homoglyph_check = config
        .get("homoglyph_check")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let affix_check = config
        .get("affix_check")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true);
    let affix_max_downloads = config
        .get("affix_max_downloads")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(DEFAULT_AFFIX_MAX_DOWNLOADS);

    let popular: Vec<String> = match config
        .get("popular_packages")
        .and_then(serde_json::Value::as_array)
    {
        Some(list) => list
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_string)
            .collect(),
        None => default_popular_packages(ecosystem)
            .iter()
            .map(|s| s.to_string())
            .collect(),
    };

    let downloads = source.downloads(format, name).await;

    let mut block_reasons: Vec<String> = Vec::new();
    let mut flag_reasons: Vec<String> = Vec::new();

    match downloads {
        PopularityResult::Known(d) if min_downloads > 0 && d < min_downloads => {
            let reason = format!(
                "package '{name}' has {d} recent downloads, below the configured minimum of {min_downloads}"
            );
            if block_action {
                block_reasons.push(reason);
            } else {
                flag_reasons.push(reason);
            }
        }
        PopularityResult::Known(_) => {}
        PopularityResult::Unknown => {
            let reason = format!(
                "popularity unknown for package '{name}' (download-count source unavailable or package not listed)"
            );
            if block_action && block_unknown {
                // Opt-in fail-closed: a brand-new package with no download
                // history must not evade a block rule just because the count
                // is Unknown.
                block_reasons.push(reason);
            } else {
                // Default: fail-open on the data source, fail-safe on the
                // decision — a stats outage or unlisted package is
                // reviewable, never a block.
                flag_reasons.push(reason);
            }
        }
    }

    if typosquat_check {
        // All lexical signals share the block_typosquat escalation: opt-in
        // enforcement where the operator accepts the false-positive rate of
        // lexical matching in exchange for hard-blocking fresh squats that
        // have no download history to trip on. Default: advisory only.
        let mut lexical_reasons: Vec<String> = Vec::new();

        if let Some(target) = is_typosquat(name, &popular, max_distance) {
            lexical_reasons.push(format!(
                "name '{name}' is within edit distance {max_distance} of popular package '{target}' (possible typo-squat)"
            ));
        }

        if homoglyph_check {
            if let Some(target) = is_homoglyph_squat(name, &popular) {
                lexical_reasons.push(format!(
                    "name '{name}' is a Unicode-confusable (homoglyph) lookalike of popular package '{target}'"
                ));
            }
            // Mixed script alone is NOT impersonation (internationalized
            // names legitimately mix scripts); it only signals when the name
            // ALSO sits near a popular package in confusable-skeleton space
            // (collision = distance 0, or within max_distance edits).
            if is_mixed_script(name) {
                if let Some((target, distance)) = nearest_popular_skeleton(name, &popular) {
                    if distance <= max_distance {
                        lexical_reasons.push(format!(
                            "name '{name}' mixes Unicode scripts and visually resembles popular package '{target}' (homoglyph-impersonation indicator)"
                        ));
                    }
                }
            }
        }

        if affix_check {
            // Reputation-riding requires the candidate itself to be
            // unpopular: a legitimately popular affixed name (e.g.
            // `python-dateutil`, were it missing from the popular list) is
            // not riding anyone's reputation.
            let candidate_low_popularity = match downloads {
                PopularityResult::Known(d) => d < affix_max_downloads,
                PopularityResult::Unknown => true,
            };
            if candidate_low_popularity {
                if let Some(target) = is_affix_squat(name, &popular) {
                    lexical_reasons.push(format!(
                        "name '{name}' is popular package '{target}' plus an ecosystem affix, and '{name}' itself has low/unknown downloads (possible reputation-riding)"
                    ));
                }
            }
        }

        if block_typosquat {
            block_reasons.extend(lexical_reasons);
        } else {
            flag_reasons.extend(lexical_reasons);
        }
    }

    if !block_reasons.is_empty() {
        block_reasons.extend(flag_reasons);
        CurationDecision::Block(block_reasons.join("; "))
    } else if !flag_reasons.is_empty() {
        CurationDecision::Flag(flag_reasons.join("; "))
    } else {
        CurationDecision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::super::popularity_source::FakePopularitySource;
    use super::*;

    fn config(json: serde_json::Value) -> serde_json::Value {
        json
    }

    #[tokio::test]
    async fn below_threshold_flags_by_default() {
        let source = FakePopularitySource::new().with("pypi", "obscure-pkg", 42);
        let cfg = config(serde_json::json!({"min_downloads": 500}));
        let decision = evaluate(&cfg, "pypi", "obscure-pkg", "1.0.0", &source).await;
        match decision {
            CurationDecision::Flag(reason) => {
                assert!(
                    reason.contains("42"),
                    "reason should include the count: {reason}"
                );
                assert!(
                    reason.contains("500"),
                    "reason should include the threshold: {reason}"
                );
            }
            other => panic!("expected Flag, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn below_threshold_blocks_when_opted_in() {
        let source = FakePopularitySource::new().with("npm", "obscure-pkg", 3);
        let cfg = config(serde_json::json!({"min_downloads": 1000, "action": "block"}));
        let decision = evaluate(&cfg, "npm", "obscure-pkg", "0.0.1", &source).await;
        match decision {
            CurationDecision::Block(reason) => {
                assert!(reason.contains("below the configured minimum"))
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn above_threshold_allows() {
        let source = FakePopularitySource::new().with("pypi", "healthy-pkg", 10_000);
        let cfg = config(serde_json::json!({"min_downloads": 500}));
        assert_eq!(
            evaluate(&cfg, "pypi", "healthy-pkg", "2.1.0", &source).await,
            CurationDecision::Allow
        );
    }

    #[tokio::test]
    async fn zero_threshold_disables_count_check() {
        let source = FakePopularitySource::new().with("npm", "tiny-pkg", 1);
        let cfg = config(serde_json::json!({"typosquat_check": false}));
        assert_eq!(
            evaluate(&cfg, "npm", "tiny-pkg", "1.0.0", &source).await,
            CurationDecision::Allow
        );
    }

    #[tokio::test]
    async fn typosquat_flags_and_names_the_target() {
        // `reqeusts` is popular-ish by count but one transposition from
        // `requests`: the advisory typo-squat flag fires on its own.
        let source = FakePopularitySource::new().with("pypi", "reqeusts", 900);
        let cfg = config(serde_json::json!({"min_downloads": 500, "max_distance": 2}));
        let decision = evaluate(&cfg, "pypi", "reqeusts", "1.0.0", &source).await;
        match decision {
            CurationDecision::Flag(reason) => {
                assert!(
                    reason.contains("requests"),
                    "should name the target: {reason}"
                );
                assert!(reason.contains("typo-squat"), "{reason}");
            }
            other => panic!("expected Flag, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn typosquat_is_advisory_even_with_block_action() {
        // action=block applies to the threshold check only; without the
        // block_typosquat opt-in, a typo-squat match on an above-threshold
        // package stays a Flag.
        let source = FakePopularitySource::new().with("pypi", "reqeusts", 9_999_999);
        let cfg = config(serde_json::json!({"min_downloads": 500, "action": "block"}));
        match evaluate(&cfg, "pypi", "reqeusts", "1.0.0", &source).await {
            CurationDecision::Flag(reason) => assert!(reason.contains("typo-squat")),
            other => panic!("expected Flag, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn typosquat_respects_custom_popular_list_and_toggle() {
        let source = FakePopularitySource::new().with("npm", "lodahs", 700);
        // Custom list without lodash: no match.
        let cfg = config(serde_json::json!({
            "min_downloads": 500,
            "popular_packages": ["express", "react"]
        }));
        assert_eq!(
            evaluate(&cfg, "npm", "lodahs", "4.0.0", &source).await,
            CurationDecision::Allow
        );
        // Toggle off: no match even against the default list.
        let cfg = config(serde_json::json!({"min_downloads": 500, "typosquat_check": false}));
        assert_eq!(
            evaluate(&cfg, "npm", "lodahs", "4.0.0", &source).await,
            CurationDecision::Allow
        );
    }

    #[tokio::test]
    async fn unknown_popularity_flags_by_default_never_blocks() {
        // Default (no block_unknown): fail-open on the source, Flag only.
        let source = FakePopularitySource::new(); // everything Unknown
        let cfg = config(serde_json::json!({"min_downloads": 1000, "action": "block"}));
        match evaluate(&cfg, "pypi", "brand-new-pkg", "0.1.0", &source).await {
            CurationDecision::Flag(reason) => {
                assert!(reason.contains("popularity unknown"), "{reason}");
            }
            other => panic!("expected Flag (fail-open on source outage), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_popularity_blocks_when_block_unknown_opted_in() {
        // block_unknown=true + action=block: a brand-new package with no
        // download history no longer evades the block rule.
        let source = FakePopularitySource::new(); // everything Unknown
        let cfg = config(serde_json::json!({
            "min_downloads": 1000,
            "action": "block",
            "block_unknown": true
        }));
        match evaluate(&cfg, "pypi", "brand-new-pkg", "0.1.0", &source).await {
            CurationDecision::Block(reason) => {
                assert!(reason.contains("popularity unknown"), "{reason}");
            }
            other => panic!("expected Block (opt-in fail-closed), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn block_unknown_without_block_action_still_flags() {
        // block_unknown only has effect together with action=block; a
        // flag-mode rule stays advisory.
        let source = FakePopularitySource::new(); // everything Unknown
        let cfg = config(serde_json::json!({"min_downloads": 1000, "block_unknown": true}));
        match evaluate(&cfg, "npm", "brand-new-pkg", "0.1.0", &source).await {
            CurationDecision::Flag(reason) => {
                assert!(reason.contains("popularity unknown"), "{reason}");
            }
            other => panic!("expected Flag, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn typosquat_blocks_when_block_typosquat_opted_in() {
        // block_typosquat=true escalates the lexical match to a hard Block,
        // even for a package that clears the download threshold.
        let source = FakePopularitySource::new().with("pypi", "reqeusts", 9_999_999);
        let cfg = config(serde_json::json!({
            "min_downloads": 500,
            "action": "block",
            "block_typosquat": true
        }));
        match evaluate(&cfg, "pypi", "reqeusts", "1.0.0", &source).await {
            CurationDecision::Block(reason) => {
                assert!(reason.contains("typo-squat"), "{reason}");
                assert!(reason.contains("requests"), "{reason}");
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fresh_typosquat_with_both_optins_is_blocked_not_reviewed() {
        // The finding scenario: a brand-new malicious typo-squat has no
        // download history (Unknown) AND a near-popular name. With the
        // default config it only ever lands in review; with both opt-ins a
        // block rule now actually blocks it, combining both reasons.
        let source = FakePopularitySource::new(); // everything Unknown
        let cfg = config(serde_json::json!({
            "min_downloads": 500,
            "action": "block",
            "block_unknown": true,
            "block_typosquat": true
        }));
        match evaluate(&cfg, "pypi", "reqeusts", "0.0.1", &source).await {
            CurationDecision::Block(reason) => {
                assert!(reason.contains("popularity unknown"), "{reason}");
                assert!(reason.contains("typo-squat"), "{reason}");
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn homoglyph_lookalike_flags_and_names_the_target() {
        // Fullwidth ｕ: pixel-identical to numpy, edit distance 1 BUT the
        // point is full-substitution lookalikes; use Cyrillic multi-swap
        // "пumру"-style too. Candidate is even "popular" by count — the
        // homoglyph signal is not popularity-gated.
        let source = FakePopularitySource::new().with("pypi", "n\u{ff55}mpy", 9_999);
        let cfg = config(serde_json::json!({"min_downloads": 500}));
        match evaluate(&cfg, "pypi", "n\u{ff55}mpy", "1.0.0", &source).await {
            CurationDecision::Flag(reason) => {
                assert!(reason.contains("homoglyph"), "{reason}");
                assert!(reason.contains("numpy"), "{reason}");
            }
            other => panic!("expected Flag, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn cyrillic_multiswap_beyond_edit_distance_is_caught() {
        // "requests" with FOUR Cyrillic substitutions (е U+0435, у... use
        // е/а-style): distance > 2 so the pre-#2956 check misses it; the
        // skeleton collision and mixed-script signals both fire.
        let name4 = "\u{0433}\u{0435}qu\u{0435}\u{0455}ts"; // г е е ѕ — distance 4
        let source = FakePopularitySource::new().with("pypi", name4, 100_000);
        let cfg = config(serde_json::json!({"max_distance": 2}));
        match evaluate(&cfg, "pypi", name4, "1.0.0", &source).await {
            CurationDecision::Flag(reason) => {
                assert!(reason.contains("mixes Unicode scripts"), "{reason}");
            }
            other => panic!("expected Flag, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn real_package_not_flagged_by_homoglyph_check() {
        let source = FakePopularitySource::new().with("pypi", "numpy", 50_000_000);
        let cfg = config(serde_json::json!({"min_downloads": 500}));
        assert_eq!(
            evaluate(&cfg, "pypi", "numpy", "2.0.0", &source).await,
            CurationDecision::Allow
        );
    }

    #[tokio::test]
    async fn homoglyph_check_can_be_disabled() {
        let source = FakePopularitySource::new().with("pypi", "n\u{ff55}mpy", 9_999);
        let cfg = config(serde_json::json!({
            "min_downloads": 500,
            "homoglyph_check": false,
            // distance("nｕmpy","numpy") == 1, so silence the distance
            // heuristic too to isolate the homoglyph toggle.
            "max_distance": 1,
            "popular_packages": ["numpy"]
        }));
        // With homoglyph off the only signal left is edit distance 1 — verify
        // the homoglyph-specific reason is gone when fully disabled.
        let cfg_off = config(serde_json::json!({
            "min_downloads": 500,
            "typosquat_check": false
        }));
        assert_eq!(
            evaluate(&cfg_off, "pypi", "n\u{ff55}mpy", "1.0.0", &source).await,
            CurationDecision::Allow,
            "master toggle off: no lexical flagging at all"
        );
        match evaluate(&cfg, "pypi", "n\u{ff55}mpy", "1.0.0", &source).await {
            CurationDecision::Flag(reason) => {
                assert!(!reason.contains("homoglyph"), "{reason}");
                assert!(!reason.contains("mixes Unicode scripts"), "{reason}");
            }
            CurationDecision::Allow => {}
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn benign_multiscript_name_far_from_popular_is_not_lexically_flagged() {
        // #3005 red-team finding 2: mixed script alone must NOT flag —
        // internationalized names that resemble nothing popular stay clean.
        for name in ["py中文tools", "sigma-δ", "бank-utils"] {
            let source = FakePopularitySource::new().with("pypi", name, 5_000);
            let cfg = config(serde_json::json!({"affix_max_downloads": 1}));
            assert_eq!(
                evaluate(&cfg, "pypi", name, "1.0.0", &source).await,
                CurationDecision::Allow,
                "benign multi-script '{name}' must not be flagged"
            );
        }
    }

    #[tokio::test]
    async fn mixed_script_near_popular_still_flags() {
        // A mixed-script homoglyph of a popular name (skeleton distance 0)
        // still carries the mixed-script reason after the proximity gate.
        let source = FakePopularitySource::new().with("pypi", "nump\u{0443}", 50_000);
        let cfg = config(serde_json::json!({}));
        match evaluate(&cfg, "pypi", "nump\u{0443}", "1.0.0", &source).await {
            CurationDecision::Flag(reason) => {
                assert!(reason.contains("mixes Unicode scripts"), "{reason}");
                assert!(reason.contains("homoglyph"), "{reason}");
            }
            other => panic!("expected Flag, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn generalized_affix_tokens_flag_when_low_popularity() {
        // #3005 red-team finding 1: arbitrary (non-allowlisted) affix tokens.
        for (name, base) in [
            ("data-numpy", "numpy"),
            ("fast-numpy", "numpy"),
            ("numpy-helper", "numpy"),
            ("numpy-extras", "numpy"),
            ("awesome-lodash", "lodash"),
            ("numpy2024", "numpy"),
            ("numpy-python", "numpy"),
        ] {
            let eco = if base == "lodash" { "npm" } else { "pypi" };
            let source = FakePopularitySource::new().with(eco, name, 3);
            let cfg = config(serde_json::json!({}));
            match evaluate(&cfg, eco, name, "0.0.1", &source).await {
                CurationDecision::Flag(reason) => {
                    assert!(reason.contains("reputation-riding"), "{name}: {reason}");
                    assert!(reason.contains(&format!("'{base}'")), "{name}: {reason}");
                }
                other => panic!("{name}: expected Flag, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn homoglyph_with_unlisted_affix_is_caught() {
        // #3005 red-team finding 3: fullwidth ｕ + arbitrary affix `-x`
        // evaded raw-byte affix matching, whole-name skeleton collision, and
        // mixed-script (fullwidth is script-Latin). Skeleton-space affix
        // matching with generalized tokens closes it.
        let name = "n\u{ff55}mpy-x";
        let source = FakePopularitySource::new(); // Unknown -> low-popularity
        let cfg = config(serde_json::json!({}));
        match evaluate(&cfg, "pypi", name, "0.0.1", &source).await {
            CurationDecision::Flag(reason) => {
                assert!(reason.contains("reputation-riding"), "{reason}");
                assert!(reason.contains("'numpy'"), "{reason}");
            }
            other => panic!("expected Flag, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn affix_squat_low_popularity_flags() {
        for name in ["python-numpy", "numpy-dev", "numpy2"] {
            // Fresh squat: no download history at all (Unknown) — the
            // threshold reason and the affix reason both surface.
            let source = FakePopularitySource::new();
            let cfg = config(serde_json::json!({"min_downloads": 500}));
            match evaluate(&cfg, "pypi", name, "0.0.1", &source).await {
                CurationDecision::Flag(reason) => {
                    assert!(reason.contains("reputation-riding"), "{name}: {reason}");
                    assert!(reason.contains("'numpy'"), "{name}: {reason}");
                }
                other => panic!("{name}: expected Flag, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn legitimately_popular_affixed_name_is_not_flagged() {
        // python-dateutil is on the popular list itself (self-exclusion) AND
        // has a huge download count — must not be flagged.
        let source = FakePopularitySource::new().with("pypi", "python-dateutil", 40_000_000);
        let cfg = config(serde_json::json!({"min_downloads": 500}));
        assert_eq!(
            evaluate(&cfg, "pypi", "python-dateutil", "2.9.0", &source).await,
            CurationDecision::Allow
        );
        // And the popularity gate alone also protects a popular affixed name
        // NOT on the list: custom list with only the base name.
        let source = FakePopularitySource::new().with("pypi", "python-dateutil", 40_000_000);
        let cfg = config(serde_json::json!({
            "min_downloads": 500,
            "popular_packages": ["dateutil"]
        }));
        assert_eq!(
            evaluate(&cfg, "pypi", "python-dateutil", "2.9.0", &source).await,
            CurationDecision::Allow,
            "high candidate downloads must gate the affix signal"
        );
    }

    #[tokio::test]
    async fn affix_check_toggle_and_threshold_are_respected() {
        // Disabled: low-pop python-numpy only gets the threshold flag reason.
        let source = FakePopularitySource::new().with("pypi", "python-numpy", 10);
        let cfg = config(serde_json::json!({"min_downloads": 500, "affix_check": false}));
        match evaluate(&cfg, "pypi", "python-numpy", "0.0.1", &source).await {
            CurationDecision::Flag(reason) => {
                assert!(!reason.contains("reputation-riding"), "{reason}");
            }
            other => panic!("expected Flag, got {other:?}"),
        }
        // Custom affix_max_downloads: candidate at 5000 downloads is above
        // the default 1000 ceiling (no affix flag), but below a raised one.
        let source = FakePopularitySource::new().with("pypi", "numpy-dev", 5_000);
        let cfg = config(serde_json::json!({}));
        assert_eq!(
            evaluate(&cfg, "pypi", "numpy-dev", "1.0.0", &source).await,
            CurationDecision::Allow,
            "default ceiling 1000: 5000-download candidate not reputation-riding"
        );
        let cfg = config(serde_json::json!({"affix_max_downloads": 10_000}));
        match evaluate(&cfg, "pypi", "numpy-dev", "1.0.0", &source).await {
            CurationDecision::Flag(reason) => {
                assert!(reason.contains("reputation-riding"), "{reason}");
            }
            other => panic!("expected Flag, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn homoglyph_and_affix_escalate_with_block_typosquat() {
        let source = FakePopularitySource::new().with("pypi", "n\u{ff55}mpy", 9_999);
        let cfg = config(serde_json::json!({"min_downloads": 500, "block_typosquat": true}));
        match evaluate(&cfg, "pypi", "n\u{ff55}mpy", "1.0.0", &source).await {
            CurationDecision::Block(reason) => assert!(reason.contains("homoglyph"), "{reason}"),
            other => panic!("expected Block, got {other:?}"),
        }
        let source = FakePopularitySource::new().with("pypi", "numpy-dev", 10);
        let cfg = config(serde_json::json!({"block_typosquat": true}));
        match evaluate(&cfg, "pypi", "numpy-dev", "1.0.0", &source).await {
            CurationDecision::Block(reason) => {
                assert!(reason.contains("reputation-riding"), "{reason}")
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn inapplicable_format_returns_not_applicable() {
        // Global policy over a format with no download-count source must have
        // no effect — even though the fake would return Unknown (which for an
        // applicable format means Flag).
        let source = FakePopularitySource::new();
        let cfg = config(serde_json::json!({"min_downloads": 1000, "action": "block"}));
        for format in ["generic", "docker", "maven", "rpm", "helm"] {
            assert_eq!(
                evaluate(&cfg, format, "anything", "1.0.0", &source).await,
                CurationDecision::NotApplicable,
                "format {format} should be NotApplicable"
            );
        }
        // And the source was never consulted for inapplicable formats.
        assert_eq!(source.call_count(), 0);
    }

    #[tokio::test]
    async fn block_and_typosquat_reasons_combine() {
        let source = FakePopularitySource::new().with("pypi", "reqeusts", 5);
        let cfg = config(serde_json::json!({"min_downloads": 500, "action": "block"}));
        match evaluate(&cfg, "pypi", "reqeusts", "1.0.0", &source).await {
            CurationDecision::Block(reason) => {
                assert!(reason.contains("below the configured minimum"), "{reason}");
                assert!(reason.contains("typo-squat"), "{reason}");
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn empty_config_allows_popular_known_package() {
        let source = FakePopularitySource::new().with("npm", "some-lib", 123);
        assert_eq!(
            evaluate(&serde_json::json!({}), "npm", "some-lib", "1.0.0", &source).await,
            CurationDecision::Allow
        );
    }

    #[tokio::test]
    async fn max_distance_is_clamped_to_ceiling() {
        // Distance 3 name; configured max_distance=5 clamps to 2 → no flag.
        let source = FakePopularitySource::new().with("pypi", "reqzzzts", 10_000);
        let cfg = config(serde_json::json!({"min_downloads": 500, "max_distance": 5}));
        assert_eq!(
            evaluate(&cfg, "pypi", "reqzzzts", "1.0.0", &source).await,
            CurationDecision::Allow
        );
    }
}
