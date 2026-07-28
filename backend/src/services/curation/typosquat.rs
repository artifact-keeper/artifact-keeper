//! Lexical typo-squat detection for the `popularity` curation rule (#2949).
//!
//! A classic supply-chain attack registers a package whose name is one or two
//! keystrokes away from a heavily downloaded package (`reqeusts` vs
//! `requests`). This module provides the string-distance primitive
//! ([`damerau_levenshtein`], optimal-string-alignment variant, which counts
//! adjacent transpositions as a single edit), a nearest-neighbor search over a
//! popular-package list, and a small built-in seed list of top packages per
//! ecosystem. The seed list is a default only — rules can supply their own
//! list via config.

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
    // TODO(#2956): pure edit distance misses homoglyph squats (Unicode
    // confusables, e.g. Cyrillic lookalikes) and affix-style squats
    // ("requests2", "python-requests"), which can sit beyond max_distance.
    if distance >= 1 && distance <= max_distance {
        Some(target)
    } else {
        None
    }
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
    fn seed_lists_present_for_supported_ecosystems() {
        let pypi = default_popular_packages("pypi");
        let npm = default_popular_packages("npm");
        assert!(pypi.contains(&"requests"));
        assert!(npm.contains(&"lodash"));
        assert!(pypi.len() >= 20 && npm.len() >= 20);
        assert!(default_popular_packages("docker").is_empty());
    }
}
