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
//! - **Affix** ([`is_affix_squat`]) — a popular name wrapped in an arbitrary
//!   boundary-delimited affix token (`python-numpy`, `numpy-helper`,
//!   `data-numpy`, `numpy2024`, `fastNumpy`) or stuffed with separators
//!   (`l.o.d.a.s.h`), riding the base name's reputation. Lexically this is
//!   `len(affix)+1` edits away, again beyond `max_distance`. This signal is
//!   *popularity-gated by the caller*: a legitimately popular affixed name
//!   (`python-dateutil`, `pytest-django`) must not be flagged, so
//!   [`super::popularity::evaluate`] only applies it to low/unknown-download
//!   candidates (and self-exclusion covers affixed names that are themselves
//!   on the popular list).

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
/// one identifier — UTS #39 mixed-script restriction). Mixing is the standard
/// way to smuggle confusables past a reader, but it is NOT an impersonation
/// signal on its own: internationalized names legitimately mix scripts.
/// Callers must pair this predicate with popular-list proximity
/// ([`nearest_popular_skeleton`]) before flagging. ASCII digits and
/// separators are script-Common and never count as mixing.
pub fn is_mixed_script(name: &str) -> bool {
    !name.is_single_script()
}

/// Separator characters allowed between a base name and an affix.
const AFFIX_SEPARATORS: &[char] = &['-', '_', '.'];

/// Insert a `-` at camelCase boundaries (`fastNumpy` → `fast-Numpy`) so case
/// transitions count as affix separators downstream.
fn split_camel(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    let mut prev_lower_or_digit = false;
    for c in name.chars() {
        if c.is_uppercase() && prev_lower_or_digit {
            out.push('-');
        }
        prev_lower_or_digit = c.is_lowercase() || c.is_ascii_digit();
        out.push(c);
    }
    out
}

/// Split a skeleton key into affix tokens: on separator characters and on
/// letter↔digit boundaries (`numpy2024` → `["numpy", "2024"]`).
fn tokenize(key: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut prev_is_digit: Option<bool> = None;
    for c in key.chars() {
        if AFFIX_SEPARATORS.contains(&c) {
            if !cur.is_empty() {
                tokens.push(std::mem::take(&mut cur));
            }
            prev_is_digit = None;
            continue;
        }
        let is_digit = c.is_ascii_digit();
        if prev_is_digit.is_some_and(|p| p != is_digit) && !cur.is_empty() {
            tokens.push(std::mem::take(&mut cur));
        }
        cur.push(c);
        prev_is_digit = Some(is_digit);
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

/// Whether `needle` occurs as a CONTIGUOUS token run inside `haystack`.
fn contains_contiguous(haystack: &[String], needle: &[String]) -> bool {
    !needle.is_empty()
        && needle.len() <= haystack.len()
        && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Strip every separator character from `s` (for separator-stuffing
/// comparison, e.g. `l.o.d.a.s.h` → `lodash`).
fn strip_separators(s: &str) -> String {
    s.chars()
        .filter(|c| !AFFIX_SEPARATORS.contains(c))
        .collect()
}

/// Return `Some(target)` when `name` rides a popular base name's reputation:
/// the popular name occurs as a contiguous, boundary-delimited token run
/// inside the candidate with at least one extra affix token on either side
/// (ANY token, not an allowlist — `data-numpy`, `numpy-helper`,
/// `awesome-lodash`, `numpy2024`, `fastNumpy` all match), or the candidate is
/// the base with separators stuffed in (`l.o.d.a.s.h`). Token boundaries are
/// the separators `-`/`_`/`.`, letter↔digit transitions, and camelCase
/// transitions; a base merely EMBEDDED without a boundary
/// (`supernumpyish`) does not match.
///
/// Matching is case-insensitive and `name` must not itself be on the popular
/// list (so a curated list containing `python-dateutil` never flags it). The
/// comparison runs in confusable-skeleton space ([`confusable_skeleton`]) so
/// a homoglyph-obfuscated affix form (`python-nｕmpy` with fullwidth `ｕ`, or
/// `nｕmpy-x` with an arbitrary affix) cannot dodge the match — a combined
/// affix+homoglyph name neither collides as a whole-name skeleton nor (for
/// compatibility codepoints) trips the mixed-script signal, so the affix arm
/// must fold confusables itself.
///
/// This function is purely lexical — the caller MUST additionally gate on the
/// candidate's own popularity (low/unknown downloads) before acting, because
/// a legitimately popular affixed package (`pytest-django`,
/// `django-rest-framework`) is not riding anyone's reputation.
pub fn is_affix_squat(name: &str, popular: &[String]) -> Option<String> {
    let name_lc = name.to_lowercase();
    // A package that IS popular by name is never a squat of another entry.
    if popular.iter().any(|p| p.to_lowercase() == name_lc) {
        return None;
    }
    let name_key = confusable_skeleton(&split_camel(name));
    let name_tokens = tokenize(&name_key);
    // Prefer the most specific (longest token run) base for attribution:
    // `react-dom-utils` rides `react-dom`, not merely `react`. Ties resolve
    // to list order.
    let mut best: Option<(String, usize)> = None;
    for candidate in popular {
        let base_key = confusable_skeleton(candidate);
        if base_key.is_empty() || name_key == base_key {
            // Whole-name skeleton collision is the homoglyph signal's job.
            continue;
        }
        // Separator stuffing: collapsing separators reproduces the base name
        // — an exact visual reproduction, always the most specific match.
        if strip_separators(&name_key) == strip_separators(&base_key) {
            return Some(candidate.clone());
        }
        // Generalized affix: the base's token run appears intact inside the
        // candidate, which carries at least one additional affix token.
        let base_tokens = tokenize(&base_key);
        if base_tokens.len() < name_tokens.len()
            && contains_contiguous(&name_tokens, &base_tokens)
            && best.as_ref().map_or(true, |(_, n)| *n < base_tokens.len())
        {
            best = Some((candidate.clone(), base_tokens.len()));
        }
    }
    best.map(|(candidate, _)| candidate)
}

/// Nearest popular package to `name` in confusable-skeleton space: the entry
/// whose skeleton has the smallest Damerau-Levenshtein distance to `name`'s
/// skeleton, with that distance (0 = skeleton collision). `None` for an empty
/// popular list. Used to proximity-gate the mixed-script signal: a
/// multi-script name that resembles nothing popular is not an impersonation.
pub fn nearest_popular_skeleton(name: &str, popular: &[String]) -> Option<(String, usize)> {
    let name_key = confusable_skeleton(name);
    let mut best: Option<(String, usize)> = None;
    for candidate in popular {
        let d = damerau_levenshtein(&name_key, &confusable_skeleton(candidate));
        match &best {
            Some((_, best_d)) if *best_d <= d => {}
            _ => best = Some((candidate.clone(), d)),
        }
    }
    best
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
            // Ecosystem-style affixes.
            "python-numpy",
            "py-numpy",
            "py_numpy",
            "numpy-dev",
            "numpy_utils",
            "numpy2",
            "numpy-2",
            "lodash-js",
            // Arbitrary (non-allowlisted) affix tokens — the 95%-evasion
            // class from the #3005 red-team.
            "data-numpy",
            "fast-numpy",
            "numpy-helper",
            "numpy-extras",
            "awesome-lodash",
            "numpy2024",
            "numpy-python",
            "mycompany-numpy",
            "numpy-extras-for-science",
            // camelCase boundary.
            "fastNumpy",
            "numpyHelper",
            // Separator stuffing.
            "l.o.d.a.s.h",
        ] {
            assert_eq!(
                is_affix_squat(name, &popular),
                Some(
                    if name.to_lowercase().contains("lodash") || name.contains("l.o") {
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
    fn affix_requires_a_token_boundary_and_a_full_base_run() {
        let popular = strings(&["numpy", "react", "react-dom", "s3transfer"]);
        // Base merely embedded without a boundary: not an affix.
        assert_eq!(is_affix_squat("supernumpyish", &popular), None);
        assert_eq!(is_affix_squat("numpyish", &popular), None);
        // Partial token overlap with the multi-token base `react-dom` is not
        // a react-dom match — but the first token alone still rides `react`.
        assert_eq!(
            is_affix_squat("react-domx", &popular),
            Some("react".to_string())
        );
        // Multi-token base as a contiguous run IS a match.
        assert_eq!(
            is_affix_squat("react-dom-utils", &popular),
            Some("react-dom".to_string())
        );
        // Digit-containing base tokenizes consistently on both sides.
        assert_eq!(
            is_affix_squat("s3transfer-stubs", &popular),
            Some("s3transfer".to_string())
        );
    }

    #[test]
    fn nearest_popular_skeleton_distances() {
        let popular = strings(&["numpy", "requests"]);
        // Homoglyph collision: distance 0.
        assert_eq!(
            nearest_popular_skeleton("nump\u{0443}", &popular),
            Some(("numpy".to_string(), 0))
        );
        // Near miss in skeleton space.
        let (t, d) = nearest_popular_skeleton("nump\u{0443}1", &popular).unwrap();
        assert_eq!((t.as_str(), d), ("numpy", 1));
        // Unrelated multi-script name: far from everything popular.
        let (_, d) = nearest_popular_skeleton("py中文tools", &popular).unwrap();
        assert!(d > 2, "unrelated international name must not be near: {d}");
        assert_eq!(nearest_popular_skeleton("anything", &[]), None);
    }

    #[test]
    fn affix_matches_in_skeleton_space_closing_homoglyph_affix_combo() {
        // Red-team evasion (#2956): homoglyph INSIDE an affix form. Fullwidth
        // ｕ (U+FF55) is script-Latin (no mixed-script flag) and the whole
        // name's skeleton includes the prefix (no whole-name collision), so a
        // raw-byte affix comparison would miss it entirely.
        let popular = strings(&["numpy"]);
        assert_eq!(
            is_affix_squat("python-n\u{ff55}mpy", &popular),
            Some("numpy".to_string())
        );
        // Cyrillic-у variant of the same combo (also caught by mixed-script,
        // but the affix arm must name the ridden base).
        assert_eq!(
            is_affix_squat("nump\u{0443}-dev", &popular),
            Some("numpy".to_string())
        );
    }

    #[test]
    fn affix_ignores_popular_and_unrelated_names() {
        let popular = strings(&["numpy", "python-dateutil", "react", "react-dom"]);
        // On the popular list itself: never a squat (the legit-affix guard).
        assert_eq!(is_affix_squat("python-dateutil", &popular), None);
        assert_eq!(is_affix_squat("react-dom", &popular), None);
        // Unrelated names: no popular base token run inside.
        assert_eq!(is_affix_squat("leftpad", &popular), None);
        assert_eq!(is_affix_squat("some-random-lib", &popular), None);
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
