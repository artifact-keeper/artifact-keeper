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
//!
//! Remote and Virtual downloads (#5159) run only the lexical half, through
//! [`evaluate_name_only`], and only for a rule that opts in with
//! `"download_name_checks": true` ([`checks_downloads`]); a rule without it
//! is not evaluated on downloads at all. No download-count lookup happens on
//! that path.
//! There, `block_typosquat` blocks only homoglyph and mixed-script matches.
//! Edit-distance and affix matches only flag, because a download has no
//! review step to absorb their false positives: edit distance 2 from the
//! seed list reaches real packages such as npm `preact`, `vite`, `chai` and
//! `vuex`, and PyPI `numba`, `httpie`, `attr` and `pipx`.

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

/// Config key that opts a `popularity` rule into the name checks on Remote
/// and Virtual downloads (#5274). Off unless set to `true`.
pub const DOWNLOAD_NAME_CHECKS_KEY: &str = "download_name_checks";

/// Whether a `popularity` rule's config opts into [`evaluate_name_only`] on
/// Remote and Virtual downloads (#5274).
///
/// Off by default, so a rule written before the download checks existed
/// (including one with `block_typosquat: true`) keeps its old behaviour
/// after an upgrade: it runs only in the staging sync, and downloads are
/// served exactly as before. Only a JSON `true` opts in.
pub fn checks_downloads(config: &serde_json::Value) -> bool {
    config
        .get(DOWNLOAD_NAME_CHECKS_KEY)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
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
///   "download_name_checks": false,
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
/// `download_name_checks` (default `false`) does not affect this function:
/// it opts the rule into [`evaluate_name_only`] on Remote and Virtual
/// downloads (#5274); see [`checks_downloads`].
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
    let cfg = PopularityConfig::parse(config, ecosystem);

    let downloads = source.downloads(format, name).await;

    let mut block_reasons: Vec<String> = Vec::new();
    let mut flag_reasons: Vec<String> = Vec::new();

    match downloads {
        PopularityResult::Known(d) if cfg.min_downloads > 0 && d < cfg.min_downloads => {
            let reason = format!(
                "package '{name}' has {d} recent downloads, below the configured minimum of {}",
                cfg.min_downloads
            );
            if cfg.block_action {
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
            if cfg.block_action && cfg.block_unknown {
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

    if cfg.typosquat_check {
        // All lexical signals share the block_typosquat escalation: opt-in
        // enforcement where the operator accepts the false-positive rate of
        // lexical matching in exchange for hard-blocking fresh squats that
        // have no download history to trip on. Default: advisory only.
        let mut lexical_reasons: Vec<String> = cfg.distance_reason(name).into_iter().collect();
        lexical_reasons.extend(cfg.homoglyph_reasons(name));

        if cfg.affix_check {
            // Reputation-riding requires the candidate itself to be
            // unpopular: a legitimately popular affixed name (e.g.
            // `python-dateutil`, were it missing from the popular list) is
            // not riding anyone's reputation.
            let candidate_low_popularity = match downloads {
                PopularityResult::Known(d) => d < cfg.affix_max_downloads,
                PopularityResult::Unknown => true,
            };
            if candidate_low_popularity {
                if let Some(target) = is_affix_squat(name, &cfg.popular) {
                    lexical_reasons.push(format!(
                        "name '{name}' is popular package '{target}' plus an ecosystem affix, and '{name}' itself has low/unknown downloads (possible reputation-riding)"
                    ));
                }
            }
        }

        if cfg.block_typosquat {
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

/// The name-only half of [`evaluate`], for the proxy download path (#5159).
///
/// The proxy path calls this only for a rule that opts in with
/// `"download_name_checks": true` ([`checks_downloads`]); this function does
/// not check the key itself.
///
/// A Remote or Virtual download cannot afford a download-count lookup, so
/// this runs only the lexical checks, which compare the name against the
/// popular list locally: edit-distance typo-squat, homoglyph and
/// mixed-script, and affix. It takes no [`PopularitySource`] and is not
/// `async`, so it cannot reach pypistats or the npm downloads API.
///
/// The download-count half is NOT evaluated, so the result differs from
/// [`evaluate`] in three ways:
///
/// * `min_downloads`, `action`, `block_unknown` and `window` have no effect,
///   and no "popularity unknown" flag is raised for every package.
/// * `block_typosquat` escalates to `Block` only on a homoglyph or
///   mixed-script match, the signals with essentially no legitimate cause.
///   Edit-distance and affix matches are only ever a `Flag` here. On the
///   staging sync a false positive lands in review; on a download it would
///   refuse a real package outright, and both signals have known ones:
///   - Edit distance is up to 2 against short seed names, which reaches
///     popular real packages: npm `preact`, `vite`, `chai` and `vuex`, and
///     PyPI `numba`, `httpie`, `attr` and `pipx`.
///   - The affix signal relies on the candidate's own download count (below
///     `affix_max_downloads`) to spare popular affixed names such as
///     `eslint-plugin-react` or `pytest-django`, and there is no count here.
/// * A name with no lexical signal is `NotApplicable`, never `Allow`. This
///   evaluation has not checked the download-count threshold, so it cannot
///   vouch for the package, and a lower-priority rule still decides.
///
/// When a blocking and a flagging signal both fire, the `Block` carries
/// every reason.
pub fn evaluate_name_only(
    config: &serde_json::Value,
    format: &str,
    name: &str,
) -> CurationDecision {
    let Some(ecosystem) = ecosystem_for_format(format) else {
        return CurationDecision::NotApplicable;
    };
    if !is_checkable_name(ecosystem, name) {
        return CurationDecision::NotApplicable;
    }
    let cfg = PopularityConfig::parse(config, ecosystem);
    if !cfg.typosquat_check {
        return CurationDecision::NotApplicable;
    }

    let homoglyph = cfg.homoglyph_reasons(name);
    let escalate = cfg.block_typosquat && !homoglyph.is_empty();
    // Same order as `evaluate`: distance, homoglyph, affix.
    let mut reasons: Vec<String> = cfg.distance_reason(name).into_iter().collect();
    reasons.extend(homoglyph);
    if cfg.affix_check {
        if let Some(target) = is_affix_squat(name, &cfg.popular) {
            reasons.push(format!(
                "name '{name}' is popular package '{target}' plus an ecosystem affix (possible reputation-riding; its download count is not checked on downloads)"
            ));
        }
    }

    if reasons.is_empty() {
        CurationDecision::NotApplicable
    } else if escalate {
        CurationDecision::Block(reasons.join("; "))
    } else {
        CurationDecision::Flag(reasons.join("; "))
    }
}

/// Longest package name the download-path name checks look at, in bytes:
/// npm's published limit, and far beyond any real PyPI project name.
const MAX_CHECKED_NAME_BYTES: usize = 214;

/// Whether the download-path name checks should look at `name` at all.
///
/// The checks cost name length times popular-list length (edit distance and
/// skeletons), and a download runs them before the format handler has
/// validated the name, so an unbounded name from an anonymous request would
/// tie up a worker. Anything that cannot be a real package name gets no
/// verdict ([`CurationDecision::NotApplicable`]) and goes on to the format's
/// own handling unchanged:
///
/// * any name over [`MAX_CHECKED_NAME_BYTES`];
/// * on PyPI, a name outside PEP 508, which the PyPI handlers refuse anyway.
///   So only ASCII confusables (`c1ick`) can match on PyPI;
/// * on npm, an empty name, one with whitespace or control characters, or
///   one with a `/` other than the single scope separator of `@scope/name`.
///   Non-ASCII names stay checkable on npm on purpose: a Unicode lookalike
///   is what the homoglyph signal is for, and an npm-compatible upstream may
///   serve one even though the public registry no longer accepts new ones.
fn is_checkable_name(ecosystem: &str, name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_CHECKED_NAME_BYTES {
        return false;
    }
    match ecosystem {
        "pypi" => crate::formats::pypi_name::is_valid_project_name(name),
        "npm" => {
            if name.chars().any(|c| c.is_whitespace() || c.is_control()) {
                return false;
            }
            match name.strip_prefix('@') {
                Some(rest) => match rest.split_once('/') {
                    Some((scope, pkg)) => {
                        !scope.is_empty() && !pkg.is_empty() && !pkg.contains('/')
                    }
                    None => false,
                },
                None => !name.contains('/'),
            }
        }
        _ => false,
    }
}

/// A `popularity` rule's config with every default applied (see
/// [`evaluate`] for the keys and their meaning).
struct PopularityConfig {
    min_downloads: u64,
    typosquat_check: bool,
    max_distance: usize,
    block_action: bool,
    block_unknown: bool,
    block_typosquat: bool,
    homoglyph_check: bool,
    affix_check: bool,
    affix_max_downloads: u64,
    popular: Vec<String>,
}

impl PopularityConfig {
    fn parse(config: &serde_json::Value, ecosystem: &str) -> Self {
        let flag = |key: &str, default: bool| {
            config
                .get(key)
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(default)
        };
        let popular = match config
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
        Self {
            min_downloads: config
                .get("min_downloads")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0),
            typosquat_check: flag("typosquat_check", true),
            max_distance: config
                .get("max_distance")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(DEFAULT_MAX_DISTANCE)
                .clamp(1, MAX_DISTANCE_CEILING) as usize,
            block_action: config
                .get("action")
                .and_then(serde_json::Value::as_str)
                .map(|a| a.eq_ignore_ascii_case("block"))
                .unwrap_or(false),
            // Opt-in hardening flags; both default false (see `evaluate`).
            block_unknown: flag("block_unknown", false),
            block_typosquat: flag("block_typosquat", false),
            // #2956 sub-toggles, both under the typosquat_check master toggle.
            homoglyph_check: flag("homoglyph_check", true),
            affix_check: flag("affix_check", true),
            affix_max_downloads: config
                .get("affix_max_downloads")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(DEFAULT_AFFIX_MAX_DOWNLOADS),
            popular,
        }
    }

    /// The edit-distance typo-squat signal, which needs no download count.
    /// The caller checks `typosquat_check`.
    fn distance_reason(&self, name: &str) -> Option<String> {
        is_typosquat(name, &self.popular, self.max_distance).map(|target| {
            format!(
                "name '{name}' is within edit distance {} of popular package '{target}' (possible typo-squat)",
                self.max_distance
            )
        })
    }

    /// The homoglyph and mixed-script signals (under `homoglyph_check`),
    /// which need no download count. The caller checks `typosquat_check`.
    fn homoglyph_reasons(&self, name: &str) -> Vec<String> {
        let mut reasons = Vec::new();
        if self.homoglyph_check {
            if let Some(target) = is_homoglyph_squat(name, &self.popular) {
                reasons.push(format!(
                    "name '{name}' is a Unicode-confusable (homoglyph) lookalike of popular package '{target}'"
                ));
            }
            // Mixed script alone is NOT impersonation (internationalized
            // names legitimately mix scripts); it only signals when the name
            // ALSO sits near a popular package in confusable-skeleton space
            // (collision = distance 0, or within max_distance edits).
            if is_mixed_script(name) {
                if let Some((target, distance)) = nearest_popular_skeleton(name, &self.popular) {
                    if distance <= self.max_distance {
                        reasons.push(format!(
                            "name '{name}' mixes Unicode scripts and visually resembles popular package '{target}' (homoglyph-impersonation indicator)"
                        ));
                    }
                }
            }
        }
        reasons
    }
}

#[cfg(ak_test_shard = "services-1")]
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

    // -- evaluate_name_only: the proxy download path (#5159) ------------------

    /// Cyrillic `о` (U+043E) for the first `o` of `lodash`: pixel-identical,
    /// one edit away, and mixed-script.
    const LODASH_HOMOGLYPH: &str = "l\u{043e}dash";

    #[test]
    fn name_only_gives_no_verdict_on_oversized_or_invalid_names_5274() {
        // A huge name must cost nothing: without the guard a 400 KB name took
        // seconds per check against the seed list.
        let cfg = config(serde_json::json!({"block_typosquat": true}));
        let huge = "l\u{043e}dash".repeat(400 * 1024 / 7);
        assert!(huge.len() >= 400 * 1000);
        for format in ["npm", "pypi"] {
            let start = std::time::Instant::now();
            assert_eq!(
                evaluate_name_only(&cfg, format, &huge),
                CurationDecision::NotApplicable,
                "{format}"
            );
            assert!(
                start.elapsed() < std::time::Duration::from_millis(100),
                "{format}: {:?}",
                start.elapsed()
            );
        }
        // Just past the cap: no verdict, even though it starts like a squat.
        let long = format!("reqeusts{}", "x".repeat(MAX_CHECKED_NAME_BYTES));
        assert_eq!(
            evaluate_name_only(&cfg, "pypi", &long),
            CurationDecision::NotApplicable
        );
        // Names the format cannot carry get no verdict either.
        for (format, name) in [
            ("pypi", LODASH_HOMOGLYPH),
            ("pypi", "req uests"),
            ("pypi", ""),
            ("npm", ""),
            ("npm", "lod ash"),
            ("npm", "a/b"),
            ("npm", "@scope"),
            ("npm", "@scope/a/b"),
            ("npm", "lodash\n"),
        ] {
            assert_eq!(
                evaluate_name_only(&cfg, format, name),
                CurationDecision::NotApplicable,
                "{format} {name:?}"
            );
        }
        // Real-looking names still get their verdicts.
        assert!(matches!(
            evaluate_name_only(&cfg, "npm", LODASH_HOMOGLYPH),
            CurationDecision::Block(_)
        ));
        assert!(matches!(
            evaluate_name_only(&cfg, "pypi", "c1ick"),
            CurationDecision::Block(_)
        ));
        assert!(matches!(
            evaluate_name_only(&cfg, "npm", "@scope/preact"),
            CurationDecision::NotApplicable | CurationDecision::Flag(_)
        ));
    }

    #[test]
    fn download_name_checks_are_opt_in_5274() {
        // Upgrade safety: a rule written before #5274, even one that blocks
        // typo-squats in the staging sync, does not opt into downloads.
        for cfg in [
            serde_json::json!({}),
            serde_json::json!({"block_typosquat": true}),
            serde_json::json!({"download_name_checks": false}),
            serde_json::json!({"download_name_checks": "true"}),
            serde_json::json!({"download_name_checks": 1}),
        ] {
            assert!(!checks_downloads(&cfg), "{cfg}");
        }
        assert!(checks_downloads(
            &serde_json::json!({"download_name_checks": true})
        ));
    }

    #[test]
    fn name_only_blocks_homoglyph_with_block_typosquat() {
        let cfg = config(serde_json::json!({"block_typosquat": true}));
        match evaluate_name_only(&cfg, "npm", LODASH_HOMOGLYPH) {
            CurationDecision::Block(reason) => {
                assert!(reason.contains("homoglyph"), "{reason}");
                assert!(reason.contains("'lodash'"), "{reason}");
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn name_only_flags_typosquat_by_default() {
        let cfg = config(serde_json::json!({}));
        match evaluate_name_only(&cfg, "pypi", "reqeusts") {
            CurationDecision::Flag(reason) => {
                assert!(reason.contains("typo-squat"), "{reason}");
                assert!(reason.contains("'requests'"), "{reason}");
            }
            other => panic!("expected Flag, got {other:?}"),
        }
    }

    #[test]
    fn name_only_has_no_opinion_on_a_clean_or_seed_name() {
        // The seed package itself and an unrelated name carry no lexical
        // signal. The result is NotApplicable, not Allow: the threshold half
        // was not evaluated, so a lower-priority rule must still decide.
        let cfg = config(serde_json::json!({"block_typosquat": true, "min_downloads": 500}));
        for (format, name) in [
            ("npm", "lodash"),
            ("npm", "left-pad-of-my-own"),
            ("pypi", "requests"),
        ] {
            assert_eq!(
                evaluate_name_only(&cfg, format, name),
                CurationDecision::NotApplicable,
                "{format}/{name}"
            );
        }
    }

    #[test]
    fn name_only_ignores_the_download_count_settings() {
        // min_downloads/action/block_unknown would Block an unknown count on
        // the staging path; here they are not evaluated at all, so a name
        // with no lexical signal raises no "popularity unknown" flag.
        let cfg = config(serde_json::json!({
            "min_downloads": 1_000_000,
            "action": "block",
            "block_unknown": true
        }));
        assert_eq!(
            evaluate_name_only(&cfg, "npm", "brand-new-pkg"),
            CurationDecision::NotApplicable
        );
    }

    #[test]
    fn name_only_affix_match_only_flags() {
        // Without a download count the affix popularity gate cannot run, so
        // an affix match stays a Flag even with block_typosquat: blocking
        // would refuse legitimately popular affixed names.
        let cfg = config(serde_json::json!({"block_typosquat": true}));
        match evaluate_name_only(&cfg, "npm", "eslint-plugin-react") {
            CurationDecision::Flag(reason) => {
                assert!(reason.contains("reputation-riding"), "{reason}");
                assert!(reason.contains("not checked on downloads"), "{reason}");
            }
            other => panic!("expected Flag, got {other:?}"),
        }
        // affix_check off: no signal at all.
        let cfg = config(serde_json::json!({"block_typosquat": true, "affix_check": false}));
        assert_eq!(
            evaluate_name_only(&cfg, "npm", "eslint-plugin-react"),
            CurationDecision::NotApplicable
        );
    }

    #[test]
    fn name_only_affix_reason_rides_along_with_an_escalated_block() {
        // A homoglyph `lodash` plus an affix: three edits from `lodash`, so
        // the escalating signal is the mixed-script one, and the affix reason
        // joins the Block instead of being dropped.
        let name = "l\u{043e}dash-x";
        let cfg = config(serde_json::json!({"block_typosquat": true}));
        match evaluate_name_only(&cfg, "npm", name) {
            CurationDecision::Block(reason) => {
                assert!(reason.contains("mixes Unicode scripts"), "{reason}");
                assert!(reason.contains("reputation-riding"), "{reason}");
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn name_only_respects_toggles_custom_list_and_format() {
        let off = config(serde_json::json!({"typosquat_check": false, "block_typosquat": true}));
        assert_eq!(
            evaluate_name_only(&off, "npm", LODASH_HOMOGLYPH),
            CurationDecision::NotApplicable,
            "typosquat_check is the master toggle"
        );
        let custom = config(serde_json::json!({
            "block_typosquat": true,
            "popular_packages": ["express"]
        }));
        assert_eq!(
            evaluate_name_only(&custom, "npm", LODASH_HOMOGLYPH),
            CurationDecision::NotApplicable,
            "a custom popular list replaces the seed list"
        );
        let cfg = config(serde_json::json!({"block_typosquat": true}));
        for format in ["maven", "docker", "cargo", "generic"] {
            assert_eq!(
                evaluate_name_only(&cfg, format, LODASH_HOMOGLYPH),
                CurationDecision::NotApplicable,
                "{format} has no popularity ecosystem"
            );
        }
        // Registry-compatible aliases share the npm seed list.
        assert!(matches!(
            evaluate_name_only(&cfg, "yarn", LODASH_HOMOGLYPH),
            CurationDecision::Block(_)
        ));
    }

    #[tokio::test]
    async fn name_only_matches_the_full_evaluator_on_lexical_signals() {
        // The refactor shares one implementation: for a name the threshold
        // check passes, the two evaluators fire the same signals with the
        // same reasons. With block_typosquat they differ only in verdict on
        // an edit-distance match (Block on staging, Flag on downloads).
        let flag_cfg = config(serde_json::json!({"min_downloads": 10}));
        let block_cfg = config(serde_json::json!({"block_typosquat": true, "min_downloads": 10}));
        let source = FakePopularitySource::new()
            .with("npm", LODASH_HOMOGLYPH, 50)
            .with("npm", "preact", 5_000);
        for name in [LODASH_HOMOGLYPH, "preact"] {
            assert_eq!(
                evaluate(&flag_cfg, "npm", name, "1.0.0", &source).await,
                evaluate_name_only(&flag_cfg, "npm", name),
                "{name}: same signals, same reasons"
            );
        }
        // A homoglyph blocks on both paths.
        assert_eq!(
            evaluate(&block_cfg, "npm", LODASH_HOMOGLYPH, "1.0.0", &source).await,
            evaluate_name_only(&block_cfg, "npm", LODASH_HOMOGLYPH)
        );
        // An edit-distance match: the same reason, Block on staging, Flag on
        // downloads.
        let staging = evaluate(&block_cfg, "npm", "preact", "1.0.0", &source).await;
        let download = evaluate_name_only(&block_cfg, "npm", "preact");
        match (staging, download) {
            (CurationDecision::Block(s), CurationDecision::Flag(d)) => assert_eq!(s, d),
            other => panic!("expected (Block, Flag), got {other:?}"),
        }
    }

    #[test]
    fn name_only_edit_distance_only_flags_real_short_names() {
        // Edit distance <= 2 from short seed names reaches popular real
        // packages; on a download a block would refuse them outright.
        let cfg = config(serde_json::json!({"block_typosquat": true}));
        for (format, name) in [
            ("npm", "preact"),
            ("npm", "vite"),
            ("npm", "chai"),
            ("npm", "vuex"),
            ("pypi", "numba"),
            ("pypi", "httpie"),
            ("pypi", "attr"),
            ("pypi", "pipx"),
        ] {
            match evaluate_name_only(&cfg, format, name) {
                CurationDecision::Flag(reason) => {
                    assert!(reason.contains("typo-squat"), "{format}/{name}: {reason}")
                }
                other => panic!("{format}/{name}: expected Flag, got {other:?}"),
            }
        }
    }

    #[test]
    fn name_only_ascii_confusable_still_blocks() {
        // `c1ick`: digit `1` is a UTS #39 confusable of `l`, so the skeleton
        // collides with `click`. ASCII survives PEP 503 normalization, so a
        // PyPI download can still be refused on a homoglyph.
        let cfg = config(serde_json::json!({"block_typosquat": true}));
        match evaluate_name_only(&cfg, "pypi", "c1ick") {
            CurationDecision::Block(reason) => {
                assert!(reason.contains("homoglyph"), "{reason}");
                assert!(reason.contains("typo-squat"), "all reasons kept: {reason}");
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }
}
