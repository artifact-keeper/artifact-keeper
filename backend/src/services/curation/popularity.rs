//! `popularity` curation rule evaluator (#2949): download-count threshold +
//! typo-squat detection.
//!
//! # Decision semantics
//!
//! - **Not applicable** — popularity rules run as instance-wide policy, but
//!   only some ecosystems have a public download-count source (currently
//!   PyPI via pypistats.org and npm via the npm downloads API, plus their
//!   registry-compatible aliases). For any other format `evaluate` returns
//!   [`Decision::NotApplicable`] so a global rule silently passes raw/
//!   generic/private-only formats through instead of flagging everything.
//! - **Below threshold** — a known download count under `min_downloads`
//!   applies the configured `action` (`"flag"` default, `"block"` opt-in).
//!   Flag-first is deliberate: legitimately new packages have low counts.
//! - **Typo-squat** — a name within `max_distance` (1–2) edits of a popular
//!   package, while not itself popular, is *flagged* for review. The signal
//!   is advisory (never a block from this check alone): lexical proximity has
//!   false positives by construction.
//! - **Unknown popularity** — a source outage/rate limit/unlisted package
//!   yields `Flag("popularity unknown…")`, never Block, regardless of
//!   `action`. Fail-open on the data source, fail-safe on the decision: the
//!   package stays reviewable but an upstream stats outage can never
//!   hard-block installs.
//!
//! When both the threshold and the typo-squat signal fire, the strongest
//! outcome wins (Block > Flag) and the reasons are combined.

use super::popularity_source::{ecosystem_for_format, PopularityResult, PopularitySource};
use super::typosquat::{default_popular_packages, is_typosquat};

/// Evaluation outcome for a single package against one `popularity` rule.
///
/// Variants mirror the curation foundation's `CurationDecision` (#2947); the
/// integration layer maps 1:1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Package passes this rule.
    Allow,
    /// Package should be held for human review, with a reason.
    Flag(String),
    /// Package should be rejected, with a reason.
    Block(String),
    /// This rule cannot meaningfully evaluate the package's format (no
    /// popularity data source exists); it must have no effect.
    NotApplicable,
}

/// Default lexical distance for typo-squat matching.
const DEFAULT_MAX_DISTANCE: u64 = 2;
/// Ceiling for the configurable distance. Beyond 2 edits the false-positive
/// rate on short names makes the signal noise.
const MAX_DISTANCE_CEILING: u64 = 2;

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
///   "action": "flag",
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
/// `version` is accepted for signature-compatibility with the dispatch seam;
/// popularity is a package-level signal, so it does not influence the
/// decision today.
pub async fn evaluate(
    config: &serde_json::Value,
    format: &str,
    name: &str,
    version: &str,
    source: &dyn PopularitySource,
) -> Decision {
    let _ = version; // package-level signal; see doc comment.

    let Some(ecosystem) = ecosystem_for_format(format) else {
        return Decision::NotApplicable;
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
            // Fail-open on the data source, fail-safe on the decision: a
            // stats outage or unlisted package is reviewable, never a block.
            flag_reasons.push(format!(
                "popularity unknown for package '{name}' (download-count source unavailable or package not listed)"
            ));
        }
    }

    if typosquat_check {
        if let Some(target) = is_typosquat(name, &popular, max_distance) {
            // Advisory signal only: lexical proximity alone never blocks.
            flag_reasons.push(format!(
                "name '{name}' is within edit distance {max_distance} of popular package '{target}' (possible typo-squat)"
            ));
        }
    }

    if !block_reasons.is_empty() {
        block_reasons.extend(flag_reasons);
        Decision::Block(block_reasons.join("; "))
    } else if !flag_reasons.is_empty() {
        Decision::Flag(flag_reasons.join("; "))
    } else {
        Decision::Allow
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
            Decision::Flag(reason) => {
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
            Decision::Block(reason) => assert!(reason.contains("below the configured minimum")),
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn above_threshold_allows() {
        let source = FakePopularitySource::new().with("pypi", "healthy-pkg", 10_000);
        let cfg = config(serde_json::json!({"min_downloads": 500}));
        assert_eq!(
            evaluate(&cfg, "pypi", "healthy-pkg", "2.1.0", &source).await,
            Decision::Allow
        );
    }

    #[tokio::test]
    async fn zero_threshold_disables_count_check() {
        let source = FakePopularitySource::new().with("npm", "tiny-pkg", 1);
        let cfg = config(serde_json::json!({"typosquat_check": false}));
        assert_eq!(
            evaluate(&cfg, "npm", "tiny-pkg", "1.0.0", &source).await,
            Decision::Allow
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
            Decision::Flag(reason) => {
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
        // action=block applies to the threshold check only; a typo-squat
        // match on an above-threshold package stays a Flag.
        let source = FakePopularitySource::new().with("pypi", "reqeusts", 9_999_999);
        let cfg = config(serde_json::json!({"min_downloads": 500, "action": "block"}));
        match evaluate(&cfg, "pypi", "reqeusts", "1.0.0", &source).await {
            Decision::Flag(reason) => assert!(reason.contains("typo-squat")),
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
            Decision::Allow
        );
        // Toggle off: no match even against the default list.
        let cfg = config(serde_json::json!({"min_downloads": 500, "typosquat_check": false}));
        assert_eq!(
            evaluate(&cfg, "npm", "lodahs", "4.0.0", &source).await,
            Decision::Allow
        );
    }

    #[tokio::test]
    async fn unknown_popularity_flags_never_blocks() {
        let source = FakePopularitySource::new(); // everything Unknown
        let cfg = config(serde_json::json!({"min_downloads": 1000, "action": "block"}));
        match evaluate(&cfg, "pypi", "brand-new-pkg", "0.1.0", &source).await {
            Decision::Flag(reason) => {
                assert!(reason.contains("popularity unknown"), "{reason}");
            }
            other => panic!("expected Flag (fail-open on source outage), got {other:?}"),
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
                Decision::NotApplicable,
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
            Decision::Block(reason) => {
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
            Decision::Allow
        );
    }

    #[tokio::test]
    async fn max_distance_is_clamped_to_ceiling() {
        // Distance 3 name; configured max_distance=5 clamps to 2 → no flag.
        let source = FakePopularitySource::new().with("pypi", "reqzzzts", 10_000);
        let cfg = config(serde_json::json!({"min_downloads": 500, "max_distance": 5}));
        assert_eq!(
            evaluate(&cfg, "pypi", "reqzzzts", "1.0.0", &source).await,
            Decision::Allow
        );
    }
}
