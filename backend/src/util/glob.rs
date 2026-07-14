//! Shared glob matching used by several allow-list / pattern features.
//!
//! Extracted from `curation_service` so callers that need the same `*` / `?`
//! semantics (curation package rules, npm scope-policy name patterns #2424)
//! share a single implementation rather than copy-pasting it.

/// Simple glob matching: `*` matches any sequence of characters (including the
/// empty sequence) and `?` matches exactly one character. All other characters
/// match literally. Callers that need case-insensitive matching should fold the
/// case of both `pattern` and `text` before calling.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p = pattern.chars().collect::<Vec<_>>();
    let t = text.chars().collect::<Vec<_>>();
    glob_match_inner(&p, &t, 0, 0)
}

fn glob_match_inner(pattern: &[char], text: &[char], pi: usize, ti: usize) -> bool {
    if pi == pattern.len() && ti == text.len() {
        return true;
    }
    if pi == pattern.len() {
        return false;
    }

    if pattern[pi] == '*' {
        // Try matching * against 0..n characters
        for skip in 0..=(text.len() - ti) {
            if glob_match_inner(pattern, text, pi + 1, ti + skip) {
                return true;
            }
        }
        return false;
    }

    if ti == text.len() {
        return false;
    }

    if pattern[pi] == '?' || pattern[pi] == text[ti] {
        return glob_match_inner(pattern, text, pi + 1, ti + 1);
    }

    false
}

#[cfg(test)]
mod tests {
    use super::glob_match;

    #[test]
    fn star_matches_any_sequence() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
        assert!(glob_match("@acme/*", "@acme/foo"));
        assert!(!glob_match("@acme/*", "@evil/foo"));
        assert!(glob_match("internal-*", "internal-utils"));
        assert!(!glob_match("internal-*", "lodash"));
    }

    #[test]
    fn question_mark_matches_single_char() {
        assert!(glob_match("lib?", "liba"));
        assert!(!glob_match("lib?", "libab"));
    }

    #[test]
    fn literal_match() {
        assert!(glob_match("lodash", "lodash"));
        assert!(!glob_match("lodash", "lodashx"));
    }
}
