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

    // Two cursors and one remembered `*`: on a mismatch, go back to the most
    // recent `*` and let it take one more character. An earlier `*` never
    // needs revisiting (if the later one cannot finish the match, giving the
    // earlier one more text cannot either), so this is O(pattern * text)
    // where trying every split of every `*` was exponential in the number of
    // stars (#5716).
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<(usize, usize)> = None; // (index after `*`, text index it resumes from)
    while ti < t.len() {
        if pi < p.len() && p[pi] == '*' {
            star = Some((pi + 1, ti));
            pi += 1;
        } else if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if let Some((after_star, resume)) = star {
            pi = after_star;
            ti = resume + 1;
            star = Some((after_star, resume + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

#[cfg(ak_test_shard = "services-2")]
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

    /// Many wildcards against a long non-matching name used to take seconds
    /// (six stars against 120 characters: 10 s). It is now linear enough that
    /// a generous bound holds even on a loaded CI runner.
    #[test]
    fn many_wildcards_do_not_blow_up() {
        let pattern = format!("{}b", "*a".repeat(12));
        let text = "a".repeat(400);
        let started = std::time::Instant::now();
        assert!(!glob_match(&pattern, &text));
        assert!(glob_match(&"*a".repeat(12), &text));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "took {:?}",
            started.elapsed()
        );
    }
}
