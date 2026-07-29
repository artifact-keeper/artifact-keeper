//! Lexical typo-squat detection for the `popularity` curation rule (#2949,
//! extended by #2956).
//!
//! A classic supply-chain attack registers a package whose name is one or two
//! keystrokes away from a heavily downloaded package (`reqeusts` vs
//! `requests`). This module provides the string-distance primitive
//! ([`damerau_levenshtein`], optimal-string-alignment variant, which counts
//! adjacent transpositions as a single edit), a nearest-neighbor search over a
//! popular-package list, and a small built-in seed list of top packages per
//! ecosystem. The seed list is a default only — rules can supply their own
//! list via config.
//!
//! #2956 adds two detectors for evasion classes pure edit distance misses:
//!
//! - **Homoglyph / Unicode-confusable** ([`is_homoglyph_squat`],
//!   [`is_mixed_script`]) — a name built from visually-identical-but-different
//!   codepoints (Cyrillic `а` U+0430 for Latin `a`, fullwidth `ｕ` U+FF55 for
//!   `u`). Every substituted codepoint costs one edit, so a fully
//!   confusable-substituted name sits far beyond `max_distance` while looking
//!   pixel-identical. Detection normalizes through NFKC plus the UTS #39
//!   confusable *skeleton* (via the `unicode-security` crate — the same
//!   implementation rustc's `non_ascii_idents` lints use) and flags a skeleton
//!   collision with a popular name whose raw name differs.
//! - **Affix** ([`is_affix_squat`]) — a popular name wrapped in a bounded
//!   ecosystem prefix/suffix (`python-numpy`, `numpy-dev`, `numpy2`) or
//!   stuffed with separators (`l.o.d.a.s.h`), riding the base name's
//!   reputation. Lexically this is `len(affix)+1` edits away, again beyond
//!   `max_distance`. This signal is *popularity-gated by the caller*: a
//!   legitimately popular affixed name (`python-dateutil`) must not be
//!   flagged, so [`super::popularity::evaluate`] only applies it to
//!   low/unknown-download candidates (and self-exclusion covers affixed names
//!   that are themselves on the popular list).

use unicode_normalization::UnicodeNormalization;
use unicode_security::MixedScript;

/// Damerau-Levenshtein distance (optimal string alignment variant): the
/// minimum number of single-character insertions, deletions, substitutions,
/// and adjacent transpositions needed to turn `a` into `b`.
///
/// Operates on Unicode scalar values, not bytes.
pub fn damerau_levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }

    // Three rolling rows: two-back (for transpositions), previous, current.
    let mut prev_prev: Vec<usize> = vec![0; n + 1];
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr: Vec<usize> = vec![0; n + 1];

    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            let mut d = (prev[j] + 1) // deletion
                .min(curr[j - 1] + 1) // insertion
                .min(prev[j - 1] + cost); // substitution
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d = d.min(prev_prev[j - 2] + 1); // adjacent transposition
            }
            curr[j] = d;
        }
        std::mem::swap(&mut prev_prev, &mut prev);
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}

/// Find the popular package name closest to `name` (case-insensitive) and its
/// distance. Returns `None` for an empty popular list. Ties resolve to the
/// first entry in list order.
pub fn nearest_popular(name: &str, popular: &[String]) -> Option<(String, usize)> {
    let name_lc = name.to_lowercase();
    let mut best: Option<(String, usize)> = None;
    for candidate in popular {
        let d = damerau_levenshtein(&name_lc, &candidate.to_lowercase());
        match &best {
            Some((_, best_d)) if *best_d <= d => {}
            _ => best = Some((candidate.clone(), d)),
        }
    }
    best
}

/// Return `Some(target)` when `name` looks like a typo-squat of a popular
/// package: within `max_distance` edits (but not identical) of an entry in
/// `popular`, while `name` itself is NOT in the popular list.
///
/// The self-exclusion matters: `request` (a real, once-hugely-popular npm
/// package) is distance 1 from `requests`, so a curated popular list that
/// contains both must not flag either.
pub fn is_typosquat(name: &str, popular: &[String], max_distance: usize) -> Option<String> {
    let name_lc = name.to_lowercase();
    // A package that IS popular by name is never a squat of another entry.
    if popular.iter().any(|p| p.to_lowercase() == name_lc) {
        return None;
    }
    let (target, distance) = nearest_popular(name, popular)?;
    // Homoglyph and affix squats sit beyond max_distance by construction;
    // they are handled by `is_homoglyph_squat` / `is_affix_squat` (#2956).
    if distance >= 1 && distance <= max_distance {
        Some(target)
    } else {
        None
    }
}

/// UTS #39 confusable skeleton of a package name, case-folded.
///
/// Pipeline: NFKC (folds compatibility forms such as fullwidth `ｕ` U+FF55
/// and ligatures) → `unicode-security` confusable skeleton (maps
/// visually-confusable codepoints, e.g. Cyrillic `а` U+0430, onto a canonical
/// exemplar) → lowercase. Two names whose skeletons collide are visually
/// interchangeable to a human reader even when their raw codepoints differ.
pub fn confusable_skeleton(name: &str) -> String {
    let nfkc: String = name.nfkc().collect();
    let skeleton: String = unicode_security::confusable_detection::skeleton(&nfkc).collect();
    skeleton.to_lowercase()
}

/// Return `Some(target)` when `name` is a Unicode-confusable (homoglyph)
/// impersonation of a popular package: its confusable skeleton collides with
/// a popular name's skeleton while the raw (case-folded) names differ, and
/// `name` itself is not on the popular list.
///
/// Unlike edit distance, this catches full-substitution lookalikes
/// (`nｕmpy`, Cyrillic `реqueѕts`) that are pixel-identical but many edits
/// away. A skeleton collision with a differing raw name has essentially no
/// legitimate cause, so callers may treat this as a stronger signal than the
/// distance heuristic.
pub fn is_homoglyph_squat(name: &str, popular: &[String]) -> Option<String> {
    let name_lc = name.to_lowercase();
    // A package that IS popular by name is never a squat of another entry.
    if popular.iter().any(|p| p.to_lowercase() == name_lc) {
        return None;
    }
    let name_skeleton = confusable_skeleton(name);
    popular
        .iter()
        .find(|p| confusable_skeleton(p) == name_skeleton)
        .cloned()
}

/// Whether `name` mixes Unicode scripts (e.g. Latin and Cyrillic letters in
/// one identifier). Package names have no legitimate reason to mix scripts;
/// mixing is the standard way to smuggle confusables past a reader, so it is
/// a strong impersonation signal on its own (UTS #39 mixed-script
/// restriction). ASCII digits and separators are script-Common and never
/// count as mixing.
pub fn is_mixed_script(name: &str) -> bool {
    !name.is_single_script()
}

/// Ecosystem-style prefixes commonly prepended to a popular base name.
const AFFIX_PREFIXES: &[&str] = &[
    "py", "python", "node", "nodejs", "js", "go", "rs", "lib", "the", "dev", "test",
];

/// Ecosystem-style suffixes commonly appended to a popular base name.
const AFFIX_SUFFIXES: &[&str] = &[
    "dev", "devel", "js", "py", "node", "cli", "util", "utils", "lib", "libs", "api", "sdk",
    "core", "plugin", "tools", "test", "rs", "bin", "beta", "pro", "new", "official", "update",
    "updated", "secure",
];

/// Separator characters allowed between a base name and an affix.
const AFFIX_SEPARATORS: &[char] = &['-', '_', '.'];

/// Strip every separator character from `s` (for separator-stuffing
/// comparison, e.g. `l.o.d.a.s.h` → `lodash`).
fn strip_separators(s: &str) -> String {
    s.chars()
        .filter(|c| !AFFIX_SEPARATORS.contains(c))
        .collect()
}

/// Return `Some(target)` when `name` is a popular name wrapped in a bounded
/// affix, riding the base name's reputation:
///
/// - a known prefix plus separator (`py-numpy`, `python-numpy`),
/// - separator? plus a known suffix (`numpy-dev`, `numpy_utils`),
/// - separator? plus 1–2 trailing digits (`numpy2`, `lodash-4`), or
/// - separator stuffing (`l.o.d.a.s.h` collapses to `lodash`).
///
/// Matching is case-insensitive and `name` must not itself be on the popular
/// list (so a curated list containing `python-dateutil` never flags it). This
/// function is purely lexical — the caller MUST additionally gate on the
/// candidate's own popularity (low/unknown downloads) before acting, because
/// a legitimately popular affixed package is not reputation-riding.
pub fn is_affix_squat(name: &str, popular: &[String]) -> Option<String> {
    let name_lc = name.to_lowercase();
    // A package that IS popular by name is never a squat of another entry.
    if popular.iter().any(|p| p.to_lowercase() == name_lc) {
        return None;
    }
    for candidate in popular {
        let base = candidate.to_lowercase();
        if base.is_empty() || name_lc == base {
            continue;
        }
        // Prefix: <prefix><sep><base>
        if let Some(rest) = name_lc.strip_suffix(&base) {
            if let Some(prefix) = rest.strip_suffix(AFFIX_SEPARATORS) {
                if AFFIX_PREFIXES.contains(&prefix) {
                    return Some(candidate.clone());
                }
            }
        }
        // Suffix: <base><sep?><suffix> or <base><sep?><1-2 digits>
        if let Some(rest) = name_lc.strip_prefix(&base) {
            let rest = rest.strip_prefix(AFFIX_SEPARATORS).unwrap_or(rest);
            if AFFIX_SUFFIXES.contains(&rest)
                || ((1..=2).contains(&rest.len()) && rest.chars().all(|c| c.is_ascii_digit()))
            {
                return Some(candidate.clone());
            }
        }
        // Separator stuffing: collapsing separators reproduces the base name.
        if strip_separators(&name_lc) == strip_separators(&base) {
            return Some(candidate.clone());
        }
    }
    None
}

/// Built-in seed list of heavily downloaded package names per ecosystem
/// (`"pypi"` / `"npm"`). A pragmatic default so the rule is useful out of the
/// box; rules can replace it with a curated list via the `popular_packages`
/// config key. Unknown ecosystems get an empty list.
pub fn default_popular_packages(ecosystem: &str) -> &'static [&'static str] {
    match ecosystem {
        "pypi" => &[
            "requests",
            "urllib3",
            "boto3",
            "botocore",
            "numpy",
            "pandas",
            "setuptools",
            "certifi",
            "idna",
            "charset-normalizer",
            "typing-extensions",
            "python-dateutil",
            "six",
            "pyyaml",
            "cryptography",
            "packaging",
            "pip",
            "wheel",
            "s3transfer",
            "attrs",
            "click",
            "jinja2",
            "markupsafe",
            "pydantic",
            "sqlalchemy",
            "aiohttp",
            "flask",
            "django",
            "pytest",
            "scipy",
            "matplotlib",
            "pillow",
            "rich",
            "httpx",
            "colorama",
        ],
        "npm" => &[
            "lodash",
            "react",
            "react-dom",
            "express",
            "axios",
            "chalk",
            "commander",
            "tslib",
            "vue",
            "webpack",
            "typescript",
            "jquery",
            "next",
            "eslint",
            "prettier",
            "uuid",
            "dotenv",
            "glob",
            "semver",
            "minimist",
            "debug",
            "async",
            "rxjs",
            "redux",
            "moment",
            "inquirer",
            "yargs",
            "ajv",
            "classnames",
            "prop-types",
            "node-fetch",
            "fs-extra",
            "body-parser",
            "cors",
            "zod",
        ],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn distance_basics() {
        assert_eq!(damerau_levenshtein("", ""), 0);
        assert_eq!(damerau_levenshtein("abc", "abc"), 0);
        assert_eq!(damerau_levenshtein("", "abc"), 3);
        assert_eq!(damerau_levenshtein("abc", ""), 3);
        assert_eq!(damerau_levenshtein("kitten", "sitting"), 3);
    }

    #[test]
    fn distance_counts_transposition_as_one_edit() {
        // Plain Levenshtein would be 2 here; Damerau counts the swap as 1.
        assert_eq!(damerau_levenshtein("reqeusts", "requests"), 1);
        assert_eq!(damerau_levenshtein("ab", "ba"), 1);
        assert_eq!(damerau_levenshtein("lodahs", "lodash"), 1);
    }

    #[test]
    fn distance_single_edits() {
        assert_eq!(damerau_levenshtein("request", "requests"), 1); // insertion
        assert_eq!(damerau_levenshtein("requests", "request"), 1); // deletion
        assert_eq!(damerau_levenshtein("reqvests", "requests"), 1); // substitution
    }

    #[test]
    fn distance_handles_unicode() {
        assert_eq!(damerau_levenshtein("café", "cafe"), 1);
    }

    #[test]
    fn nearest_popular_finds_closest() {
        let popular = strings(&["requests", "numpy", "pandas"]);
        assert_eq!(
            nearest_popular("reqeusts", &popular),
            Some(("requests".to_string(), 1))
        );
        assert_eq!(
            nearest_popular("nunpy", &popular),
            Some(("numpy".to_string(), 1))
        );
        assert_eq!(nearest_popular("anything", &[]), None);
    }

    #[test]
    fn typosquat_flags_within_distance() {
        let popular = strings(&["requests", "numpy"]);
        assert_eq!(
            is_typosquat("reqeusts", &popular, 2),
            Some("requests".to_string())
        );
        assert_eq!(
            is_typosquat("Reqeusts", &popular, 2),
            Some("requests".to_string()),
            "matching is case-insensitive"
        );
    }

    #[test]
    fn typosquat_ignores_exact_and_distant_names() {
        let popular = strings(&["requests", "numpy"]);
        // Exact match: it IS the popular package.
        assert_eq!(is_typosquat("requests", &popular, 2), None);
        // Far away: unrelated name.
        assert_eq!(is_typosquat("completely-different", &popular, 2), None);
        // Distance 3 with max 2: not flagged.
        assert_eq!(is_typosquat("reqzzsts", &popular, 1), None);
    }

    #[test]
    fn typosquat_never_flags_a_listed_popular_package() {
        // `request` is itself popular; distance 1 from `requests` must not flag.
        let popular = strings(&["requests", "request"]);
        assert_eq!(is_typosquat("request", &popular, 2), None);
        assert_eq!(is_typosquat("requests", &popular, 2), None);
    }

    #[test]
    fn skeleton_folds_confusables_and_compatibility_forms() {
        // Skeletons are canonical-exemplar strings, not readable names (the
        // UTS #39 table maps e.g. `m` → `rn`), so correctness is skeleton
        // EQUALITY with the impersonated name, not a literal value.
        // Fullwidth ｕ (U+FF55) and Cyrillic а (U+0430) fold onto their Latin
        // exemplars:
        assert_eq!(
            confusable_skeleton("n\u{ff55}mpy"),
            confusable_skeleton("numpy")
        );
        assert_eq!(
            confusable_skeleton("p\u{0430}ndas"),
            confusable_skeleton("pandas")
        );
        // Case-insensitive: the cased name collides with the lowercase one.
        assert_eq!(confusable_skeleton("NumPy"), confusable_skeleton("numpy"));
        // Distinct real names do NOT collide.
        assert_ne!(confusable_skeleton("numpy"), confusable_skeleton("pandas"));
    }

    #[test]
    fn homoglyph_flags_confusable_lookalikes() {
        let popular = strings(&["numpy", "requests"]);
        // Fullwidth ｕ: skeleton collides with numpy, raw differs.
        assert_eq!(
            is_homoglyph_squat("n\u{ff55}mpy", &popular),
            Some("numpy".to_string())
        );
        // Cyrillic е/у/р/ѕ substitution of "requests".
        assert_eq!(
            is_homoglyph_squat("r\u{0435}quests", &popular),
            Some("requests".to_string())
        );
        // All-Cyrillic-confusable numpy (у U+0443 for y is confusable).
        assert_eq!(
            is_homoglyph_squat("nump\u{0443}", &popular),
            Some("numpy".to_string())
        );
    }

    #[test]
    fn homoglyph_never_flags_the_real_or_unrelated_package() {
        let popular = strings(&["numpy", "requests"]);
        // The real package: raw name matches a popular entry.
        assert_eq!(is_homoglyph_squat("numpy", &popular), None);
        assert_eq!(is_homoglyph_squat("NumPy", &popular), None);
        // Unrelated ASCII name: no skeleton collision.
        assert_eq!(is_homoglyph_squat("leftpad", &popular), None);
        // Edit-distance-1 ASCII typo is NOT a skeleton collision (that is the
        // distance heuristic's job).
        assert_eq!(is_homoglyph_squat("nunpy", &popular), None);
    }

    #[test]
    fn mixed_script_detection() {
        // Latin + Cyrillic in one identifier.
        assert!(is_mixed_script("num\u{0440}y")); // Cyrillic р
        assert!(is_mixed_script("lod\u{0430}sh")); // Cyrillic а
                                                   // Single script (digits and separators are script-Common).
        assert!(!is_mixed_script("numpy"));
        assert!(!is_mixed_script("numpy2"));
        assert!(!is_mixed_script("python-dateutil"));
        assert!(!is_mixed_script("charset_normalizer.v2"));
    }

    #[test]
    fn unicode_edge_cases_do_not_panic_or_mis_skeleton() {
        let popular = strings(&["numpy"]);
        // Combining chars: n + u + combining-acute + mpy — NFC-composes to ú,
        // which is not a plain-u confusable; must not panic either way.
        let _ = is_homoglyph_squat("nu\u{0301}mpy", &popular);
        // Multibyte CJK, emoji, empty string, lone combining mark.
        assert_eq!(is_homoglyph_squat("包管理器", &popular), None);
        assert_eq!(is_homoglyph_squat("🦀crate", &popular), None);
        assert_eq!(is_homoglyph_squat("", &popular), None);
        let _ = confusable_skeleton("\u{0301}");
        let _ = is_mixed_script("");
        // NFKC folding of the ﬁ ligature (U+FB01) — collides with "file".
        assert_eq!(
            confusable_skeleton("\u{fb01}le"),
            confusable_skeleton("file")
        );
    }

    #[test]
    fn affix_flags_prefix_suffix_digit_and_separator_stuffing() {
        let popular = strings(&["numpy", "lodash"]);
        for name in [
            "python-numpy",
            "py-numpy",
            "py_numpy",
            "numpy-dev",
            "numpy_utils",
            "numpy2",
            "numpy-2",
            "lodash-js",
            "l.o.d.a.s.h",
        ] {
            assert_eq!(
                is_affix_squat(name, &popular),
                Some(
                    if name.contains("lodash") || name.contains("l.o") {
                        "lodash"
                    } else {
                        "numpy"
                    }
                    .to_string()
                ),
                "{name} should be an affix squat"
            );
        }
    }

    #[test]
    fn affix_ignores_popular_unrelated_and_unbounded_names() {
        let popular = strings(&["numpy", "python-dateutil", "react", "react-dom"]);
        // On the popular list itself: never a squat (the legit-affix guard).
        assert_eq!(is_affix_squat("python-dateutil", &popular), None);
        assert_eq!(is_affix_squat("react-dom", &popular), None);
        // Unknown affix token: not in the bounded set.
        assert_eq!(is_affix_squat("numpy-extras-for-science", &popular), None);
        assert_eq!(is_affix_squat("mycompany-numpy", &popular), None);
        // 3+ digit suffix is out of bounds (e.g. a year-fork naming scheme).
        assert_eq!(is_affix_squat("numpy2024", &popular), None);
        // Unrelated name.
        assert_eq!(is_affix_squat("leftpad", &popular), None);
        // Base embedded mid-name without a bounded affix.
        assert_eq!(is_affix_squat("supernumpyish", &popular), None);
    }

    #[test]
    fn seed_lists_present_for_supported_ecosystems() {
        let pypi = default_popular_packages("pypi");
        let npm = default_popular_packages("npm");
        assert!(pypi.contains(&"requests"));
        assert!(npm.contains(&"lodash"));
        assert!(pypi.len() >= 20 && npm.len() >= 20);
        assert!(default_popular_packages("docker").is_empty());
    }
}
