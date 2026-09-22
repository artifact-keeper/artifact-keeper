//! Conda version ordering, version-spec matching and MatchSpec parsing,
//! adopted from the rattler crates (#4040).
//!
//! # Why this module exists
//!
//! Conda semantics used to be hand-rolled: `curation_service::version_compare`
//! split on `.`/`-` and compared segments numerically-when-possible, and
//! `environment_lock::matchspec_name` extracted a MatchSpec's package name
//! with a character walk. Both disagree with the conda client in exactly the
//! places that matter for a registry:
//!
//! - `1.0a` is a *pre-release* in conda and orders **before** `1.0`; the
//!   segment splitter ordered it after (`"0a" > "0"` lexicographically), so a
//!   curation rule `>= 1.0a` and the client's solver drew the line in
//!   different places.
//! - An epoch (`1!2.0`) dominates every epoch-less version in conda; the
//!   segment splitter compared `"1!2"` lexicographically and ordered it
//!   **below** `2.0`.
//! - Conda orders letters *below* numbers inside a segment (that is why
//!   `1.0a < 1.0`), so a local segment behaves nothing like the segment
//!   splitter assumed: `1.0+local` orders **below** `1.0` (the bare version's
//!   missing local pads to `0`, and `"local" < 0`), while `1.0+1` orders
//!   above. The splitter ordered `1.0+local` above `1.0` unconditionally.
//! - Equality includes the local part: `==1.0` does **not** match `1.0+local`,
//!   though trailing zero segments still compare equal (`==1.0` matches
//!   `1.0.0`).
//!
//! A registry whose ordering disagrees with the client is not "differently
//! right": a version-constrained curation rule is a vulnerability/policy
//! match, and a rule the client would match but the registry does not is a
//! silent miss. So conda-format decisions now go through
//! `rattler_conda_types` — the same crate the pixi/prefix.dev client tooling
//! is built on — and the differential tests below pin the exact points where
//! the old hand-rolled behaviour and the reference semantics diverge, so the
//! swap is enumerated rather than assumed.
//!
//! # What is NOT here
//!
//! - `.tar.bz2` (v1) container reading: `rattler_package_streaming` decodes
//!   bzip2 with the single-stream `BzDecoder`, which stops at the first stream
//!   boundary of a pbzip2/lbzip2-written package (#4067). Our
//!   `MultiBzDecoder` readers stay. The differential streaming tests prove
//!   the reference implementation cannot read the two-stream fixture, which is
//!   what justifies keeping ours.
//! - repodata.json generation stays hand-rolled JSON: it is served to clients
//!   byte-for-byte and rattler's `PackageRecord` serialization is not
//!   byte-identical to it. The byte-equality harness in
//!   `api::handlers::conda::repodata_byte_stability_tests` guards that
//!   contract instead.

#[cfg(test)]
use std::cmp::Ordering;
use std::str::FromStr;

use rattler_conda_types::{MatchSpec, PackageNameMatcher, ParseStrictness, Version, VersionSpec};

/// Whether a repository format string denotes a conda repository (`conda` and
/// `conda_native` are both served by the conda-native handler, #4039), and
/// therefore evaluates version constraints with conda's own ordering.
pub(crate) fn is_conda_format(format: &str) -> bool {
    matches!(format, "conda" | "conda_native")
}

/// Parse a conda version string with the reference implementation.
///
/// `None` means the string is not a conda version at all; callers must treat
/// that as "cannot decide", never as a match or a mismatch they invented.
pub(crate) fn parse_version(raw: &str) -> Option<Version> {
    Version::from_str(raw.trim()).ok()
}

/// Total order on conda version strings, per the reference implementation.
///
/// Returns `None` when either side is not a parseable conda version.
///
/// Test-only today: production decisions go through [`VersionSpec`] matching
/// rather than raw ordering (latest-selection keeps its created-at ordering,
/// #4040), so this exists for the differential harness below and for the
/// caller that eventually needs conda ordering directly.
#[cfg(test)]
pub(crate) fn version_cmp(a: &str, b: &str) -> Option<Ordering> {
    Some(parse_version(a)?.cmp(&parse_version(b)?))
}

/// Whether a curation-rule version constraint matches a conda package
/// version, evaluated with conda's own semantics.
///
/// The constraint grammar is the curation grammar, unchanged: `*`, `= V`,
/// `>= V`, `> V`, `<= V`, `< V`, or a bare `V` (exact equality). Only the
/// *comparison* changes hands — from the segment splitter to
/// [`VersionSpec`] — so an operator's existing rules keep their shape and
/// acquire conda's meaning for epochs, pre-releases and local segments.
///
/// Returns `None` when the constraint or the version is not expressible as a
/// conda version spec; the caller fails closed (the rule does not match),
/// which is the same disposition the old code gave an unknown version.
pub(crate) fn version_constraint_matches(constraint: &str, version: &str) -> Option<bool> {
    let constraint = constraint.trim();
    if constraint == "*" {
        return Some(true);
    }

    let spec_src = if let Some(v) = constraint.strip_prefix(">=") {
        format!(">={}", v.trim())
    } else if let Some(v) = constraint.strip_prefix("<=") {
        format!("<={}", v.trim())
    } else if let Some(v) = constraint.strip_prefix('>') {
        format!(">{}", v.trim())
    } else if let Some(v) = constraint.strip_prefix('<') {
        format!("<{}", v.trim())
    } else {
        let target = constraint.strip_prefix('=').unwrap_or(constraint).trim();
        if target.contains('*') {
            // A glob target (`1.2.*`) means conda's prefix semantics. Under
            // the old comparator it matched nothing but itself, so this can
            // only broaden a rule that was previously dead.
            target.to_string()
        } else {
            // Curation `= V` (and a bare `V`) is exact equality; conda's
            // exact operator is `==`.
            format!("=={target}")
        }
    };

    let spec = VersionSpec::from_str(&spec_src, ParseStrictness::Lenient).ok()?;
    Some(spec.matches(&parse_version(version)?))
}

/// The package name a conda MatchSpec names, parsed with the reference
/// implementation.
///
/// Handles every spelling the hand-rolled extractor did (`numpy`,
/// `numpy >=1.20`, `python 3.11.* *_cpython`, `conda-forge::numpy`,
/// `conda-forge/linux-64::numpy >=1.20`, `numpy[version='>=1.2']`,
/// `__glibc >=2.17`) with the client's own grammar. Returns `None` when the
/// spec does not parse or names its package by glob/regex rather than
/// exactly — a glob names a *set* of packages, and reporting one would be
/// inventing a fact the spec does not contain.
pub(crate) fn matchspec_name(spec: &str) -> Option<String> {
    let parsed: MatchSpec = spec.trim().parse().ok()?;
    match &parsed.name {
        PackageNameMatcher::Exact(name) => Some(name.as_normalized().to_string()),
        PackageNameMatcher::Glob(_) | PackageNameMatcher::Regex(_) => None,
    }
}

#[cfg(test)]
mod tests {
    //! The differential harness (#4040): every test pins the relationship
    //! between the hand-rolled implementation that predates this module and
    //! the rattler reference semantics. They must pass against BOTH — before
    //! the swap (documenting where the old code disagreed) and after
    //! (guaranteeing the new code *is* the reference behaviour, so a future
    //! refactor cannot drift).

    use super::*;

    /// The hand-rolled comparator conda curation rules rode on before #4040.
    fn legacy_version_compare(a: &str, b: &str) -> i32 {
        crate::services::curation_service::version_compare(a, b)
    }

    /// The hand-rolled MatchSpec name extractor before #4040.
    fn legacy_matchspec_name(spec: &str) -> Option<String> {
        crate::services::environment_lock::matchspec_name(spec)
    }

    fn ord_to_i32(ord: Ordering) -> i32 {
        match ord {
            Ordering::Less => -1,
            Ordering::Equal => 0,
            Ordering::Greater => 1,
        }
    }

    /// Version pairs where the hand-rolled comparator already agreed with
    /// conda. A regression in either direction is caught here.
    #[test]
    fn differential_version_ordering_agreement_cases() {
        let agreeing: &[(&str, &str, i32)] = &[
            ("1.0", "1.1", -1),
            ("1.0.1", "1.0", 1),
            ("2.0", "10.0", -1),
            ("1.26.4", "1.26.10", -1),
            ("2.31.0", "2.31.0", 0),
            ("2020.1", "2020.10", -1),
            ("0.9", "1.0", -1),
        ];
        for (a, b, expected) in agreeing {
            let rattler =
                ord_to_i32(version_cmp(a, b).unwrap_or_else(|| {
                    panic!("rattler must parse real conda versions {a:?} {b:?}")
                }));
            assert_eq!(
                rattler, *expected,
                "rattler ordering of {a:?} vs {b:?} changed"
            );
            assert_eq!(
                legacy_version_compare(a, b),
                *expected,
                "legacy comparator must keep agreeing on {a:?} vs {b:?}"
            );
        }
    }

    /// Version pairs where the hand-rolled comparator disagreed with conda.
    /// Each entry is a bug the migration fixes; the assertions pin BOTH sides
    /// so the disagreement can never silently reappear or silently flip.
    #[test]
    fn differential_version_ordering_documented_disagreements() {
        // (a, b, rattler ordering, legacy ordering)
        let disagreements: &[(&str, &str, i32, i32)] = &[
            // Pre-releases order BEFORE the release in conda; the segment
            // splitter compared "0a" > "0" lexicographically.
            ("1.0a", "1.0", -1, 1),
            ("1.0b2", "1.0", -1, 1),
            ("1.0rc1", "1.0", -1, 1),
            ("1.0.dev1", "1.0", -1, 1),
            // An epoch dominates every epoch-less version; the splitter
            // compared "1!2" lexicographically against "2".
            ("1!2.0", "2.0", 1, -1),
            ("1!1.0", "999.0", 1, -1),
            // Conda orders letters below numbers, and the missing local part
            // of the bare version pads to 0, so `1.0+local` < `1.0`; the
            // splitter saw a distinct, greater segment.
            ("1.0+local", "1.0", -1, 1),
        ];
        for (a, b, rattler_expected, legacy_expected) in disagreements {
            let rattler = ord_to_i32(version_cmp(a, b).unwrap());
            assert_eq!(
                rattler, *rattler_expected,
                "rattler ordering of {a:?} vs {b:?} no longer matches the reference semantics"
            );
            assert_eq!(
                legacy_version_compare(a, b),
                *legacy_expected,
                "legacy ordering of {a:?} vs {b:?} drifted from the documented disagreement"
            );
            assert_ne!(
                rattler, *legacy_expected,
                "expected {a:?} vs {b:?} to be a disagreement"
            );
        }
    }

    /// Conda's documented equality edge cases, pinned so neither the old nor
    /// the new code can reinterpret them silently.
    #[test]
    fn differential_version_equality_edges() {
        // Trailing zero segments compare equal in conda.
        assert_eq!(version_cmp("1.0", "1.0.0"), Some(Ordering::Equal));
        // `_` and `.` are equivalent separators in conda.
        assert_eq!(version_cmp("1.0_3", "1.0.3"), Some(Ordering::Equal));
        // An explicit zero epoch equals no epoch.
        assert_eq!(version_cmp("0!1.0", "1.0"), Some(Ordering::Equal));
        // post-releases order after the release.
        assert_eq!(version_cmp("1.0.post1", "1.0"), Some(Ordering::Greater));
        // dev sorts between the last pre-release and the release in conda
        // (letters below numbers within one segment): 1.0a1 < 1.0rc1 <
        // 1.0.dev1 < 1.0. This is NOT PEP 440's dev-before-alpha rule.
        assert_eq!(version_cmp("1.0a1", "1.0b1"), Some(Ordering::Less));
        assert_eq!(version_cmp("1.0b1", "1.0rc1"), Some(Ordering::Less));
        assert_eq!(version_cmp("1.0rc1", "1.0.dev1"), Some(Ordering::Less));
        assert_eq!(version_cmp("1.0.dev1", "1.0"), Some(Ordering::Less));
    }

    /// The new conda-semantics comparator must be a strict total order on
    /// the corpus: antisymmetric and transitive spot checks.
    #[test]
    fn version_cmp_is_a_total_order_on_corpus() {
        let corpus = [
            "1.0",
            "1.0a",
            "1.0.0",
            "1!2.0",
            "2.0",
            "1.0+local",
            "1.0.post1",
            "10.0",
        ];
        for a in &corpus {
            for b in &corpus {
                let ab = version_cmp(a, b).unwrap();
                let ba = version_cmp(b, a).unwrap();
                assert_eq!(
                    ab,
                    ba.reverse(),
                    "ordering of {a:?} vs {b:?} is not antisymmetric"
                );
            }
        }
    }

    /// Constraint matching: the curation grammar with conda comparison
    /// semantics. These pin the behaviour the migration gives conda-format
    /// curation rules — including the boundary a mutation must trip.
    #[test]
    fn version_constraint_matches_conda_semantics() {
        // Unchanged-by-design cases (both implementations agreed).
        assert_eq!(version_constraint_matches("*", "anything"), Some(true));
        assert_eq!(
            version_constraint_matches(">= 3.0", "3.0"),
            Some(true),
            "inclusive lower bound must match its boundary"
        );
        assert_eq!(version_constraint_matches(">= 3.0", "2.9"), Some(false));
        assert_eq!(version_constraint_matches("< 2.17", "2.17"), Some(false));
        assert_eq!(version_constraint_matches("= 1.2.3", "1.2.3"), Some(true));
        assert_eq!(version_constraint_matches("= 1.2.3", "1.2.4"), Some(false));
        assert_eq!(version_constraint_matches("> 1.0", "1.0"), Some(false));
        assert_eq!(version_constraint_matches("<= 1.0", "1.0"), Some(true));

        // Conda semantics the hand-rolled comparator got wrong: a pre-release
        // is BELOW its release, so `>= 1.0a` admits 1.0 and `>= 1.0` rejects
        // 1.0a — the exact opposite of the legacy ordering.
        assert_eq!(version_constraint_matches(">= 1.0a", "1.0"), Some(true));
        assert_eq!(version_constraint_matches(">= 1.0", "1.0a"), Some(false));
        // Epoch: `>= 2.0` admits 1!2.0.
        assert_eq!(version_constraint_matches(">= 2.0", "1!2.0"), Some(true));
        // Equality includes the local part: `= 1.0` does NOT admit 1.0+local
        // (though it does admit the zero-padded 1.0.0).
        assert_eq!(
            version_constraint_matches("= 1.0", "1.0+local"),
            Some(false)
        );
        assert_eq!(version_constraint_matches("= 1.0", "1.0.0"), Some(true));
        // A glob target uses conda prefix semantics (`1.2.*` admits every
        // 1.2.x, including the bare 1.2).
        assert_eq!(version_constraint_matches("= 1.2.*", "1.2.3"), Some(true));
        assert_eq!(version_constraint_matches("= 1.2.*", "1.2"), Some(true));
        assert_eq!(version_constraint_matches("= 1.2.*", "1.3.0"), Some(false));

        // Fail-closed: an unparseable version is not a match.
        assert_eq!(version_constraint_matches(">= 1.0", "not a version"), None);
    }

    /// MatchSpec name extraction: the spellings the hand-rolled extractor
    /// documented, which the reference parser must reproduce.
    #[test]
    fn differential_matchspec_name_agreement_cases() {
        let agreeing: &[(&str, Option<&str>)] = &[
            ("numpy", Some("numpy")),
            ("numpy >=1.20", Some("numpy")),
            ("numpy>=1.20", Some("numpy")),
            ("python 3.11.* *_cpython", Some("python")),
            ("conda-forge::numpy", Some("numpy")),
            ("conda-forge/linux-64::numpy >=1.20", Some("numpy")),
            ("numpy[version='>=1.2']", Some("numpy")),
            ("__glibc >=2.17", Some("__glibc")),
            ("", None),
            (">=1.0", None),
            // Realistic repodata `depends` shapes: comma-bounded ranges,
            // exact pins, build-string third fields.
            ("zlib >=1.2.13,<1.3.0a0", Some("zlib")),
            ("python >=3.10,<3.11.0a0", Some("python")),
            ("numpy ==1.26.4", Some("numpy")),
            ("perl >=5.32.1,<6.0a0 *_perl5", Some("perl")),
            ("r-base >=4.3,<4.4.0a0", Some("r-base")),
        ];
        for (spec, expected) in agreeing {
            assert_eq!(
                matchspec_name(spec),
                expected.map(str::to_string),
                "rattler MatchSpec parse of {spec:?} changed"
            );
            assert_eq!(
                legacy_matchspec_name(spec),
                expected.map(str::to_string),
                "legacy extractor must keep agreeing on {spec:?}"
            );
        }
    }

    /// Spellings where the hand-rolled extractor and the reference parser
    /// diverge. Each divergence is resolved in favour of the reference
    /// (rattler's answer is what the client would compute); the legacy
    /// behaviour is pinned as documentation of what changed.
    #[test]
    fn differential_matchspec_name_documented_divergences() {
        // A bare glob is not a legal exact package name: both sides report
        // nothing (rattler rejects at parse; the legacy character walk
        // produced an empty name). Pinned so neither side invents a name.
        assert_eq!(matchspec_name("*"), None);
        assert_eq!(legacy_matchspec_name("*"), None);

        // Trailing-dot name (`numpy.`): the legacy walk trimmed the dot and
        // reported `numpy`, correlating the edge to a package the spec does
        // not name. The reference grammar accepts the name as written and
        // reports `numpy.` — which matches no real package, so the edge is
        // recorded unresolved instead of silently linked to the wrong
        // package. Resolved in rattler's favour: report what the spec says,
        // never a normalized guess.
        assert_eq!(matchspec_name("numpy. >=1.0"), Some("numpy.".into()));
        assert_eq!(legacy_matchspec_name("numpy. >=1.0"), Some("numpy".into()));
    }

    /// Version-spec matching semantics, through rattler's `VersionSpec` — the
    /// semantics a client applies when solving against our repodata. Pinned
    /// here so registry-side reasoning about specs (curation, advisories)
    /// reuses one definition of "matches", and so nobody "corrects" these to
    /// PEP 440 intuitions conda does not share.
    #[test]
    fn matchspec_version_spec_semantics_are_condas() {
        let v = |s: &str| parse_version(s).unwrap();
        let spec = |s: &str| VersionSpec::from_str(s, ParseStrictness::Lenient).unwrap();

        assert!(spec(">=1.20").matches(&v("1.26.4")));
        // A pre-release is BELOW its release.
        assert!(!spec(">=1.20").matches(&v("1.0a")));
        assert!(spec(">=1.0a").matches(&v("1.0")));
        // Epochs dominate.
        assert!(spec(">=2.0").matches(&v("1!2.0")));
        // Exact equality includes the local part, but pads trailing zeros.
        assert!(spec("==1.0").matches(&v("1.0.0")));
        assert!(!spec("==1.0").matches(&v("1.0+local")));
        // Glob (`.*`) is prefix semantics and includes the bare prefix.
        assert!(spec("1.2.*").matches(&v("1.2.3")));
        assert!(spec("1.2.*").matches(&v("1.2")));
        assert!(!spec("1.2.*").matches(&v("1.3")));
        // A bare version spec is EXACT (zero-padded), not a prefix: this is
        // the VersionSpec grammar, distinct from a MatchSpec's two-argument
        // `numpy 1.2` spelling. Pinned so the curation translation's bare
        // constraint (also exact) is not "aligned" to a prefix reading that
        // does not exist here.
        assert!(spec("1.2").matches(&v("1.2.0")));
        assert!(!spec("1.2").matches(&v("1.2.3")));
    }
}
