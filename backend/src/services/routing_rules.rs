//! Routing rule evaluation for remote/proxy repositories.
//!
//! A routing rule rewrites the request path before it is forwarded to the
//! upstream server. This enables use cases such as proxying GitHub Releases
//! through a raw/generic remote repository, where the download URL structure
//! differs from the path the client uses locally.
//!
//! Each rule contains a regex `path_pattern` and a `rewrite_to` template that
//! may reference captured groups (`$1`, `$2`, ...).

use regex::Regex;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// A single routing rule that maps an incoming path to a rewritten path.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RoutingRule {
    /// Regex pattern matched against the full request path.
    /// Use capture groups to extract portions for the rewrite template.
    pub path_pattern: String,

    /// Rewrite template. Use `$1`, `$2`, etc. to reference captured groups
    /// from `path_pattern`.
    pub rewrite_to: String,
}

/// Apply routing rules to an incoming path.
///
/// Rules are evaluated in order. The first rule whose `path_pattern` matches
/// the entire path wins. If no rule matches, `None` is returned and the
/// caller should use the original path unchanged.
///
/// This is a pure function with no I/O, making it straightforward to test.
pub fn apply_routing_rules(path: &str, rules: &[RoutingRule]) -> Option<String> {
    for rule in rules {
        let pattern = if rule.path_pattern.starts_with('^') {
            rule.path_pattern.clone()
        } else {
            format!("^{}$", rule.path_pattern)
        };

        let Ok(re) = Regex::new(&pattern) else {
            tracing::warn!(
                pattern = %rule.path_pattern,
                "Skipping routing rule with invalid regex"
            );
            continue;
        };

        if let Some(caps) = re.captures(path) {
            let mut result = rule.rewrite_to.clone();
            // Replace $0 .. $N with capture group values
            for i in (0..caps.len()).rev() {
                let placeholder = format!("${}", i);
                let value = caps.get(i).map(|m| m.as_str()).unwrap_or("");
                result = result.replace(&placeholder, value);
            }
            return Some(result);
        }
    }
    None
}

/// Validate that a routing rule's pattern compiles as a valid regex and that
/// the rewrite template only references capture groups that exist. Returns
/// `Ok(())` on success or an error message describing the problem.
pub fn validate_routing_rule(rule: &RoutingRule) -> Result<(), String> {
    let pattern = if rule.path_pattern.starts_with('^') {
        rule.path_pattern.clone()
    } else {
        format!("^{}$", rule.path_pattern)
    };

    let re = Regex::new(&pattern).map_err(|e| format!("invalid regex: {}", e))?;

    // Count capture groups (total captures minus the implicit group 0)
    let group_count = re.captures_len() - 1;

    // Check that $N references in rewrite_to don't exceed the capture count
    let dollar_re = Regex::new(r"\$(\d+)").unwrap();
    for cap in dollar_re.captures_iter(&rule.rewrite_to) {
        let n: usize = cap[1].parse().unwrap_or(0);
        if n > group_count {
            return Err(format!(
                "rewrite_to references ${}  but pattern only has {} capture group(s)",
                n, group_count
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(pattern: &str, rewrite: &str) -> RoutingRule {
        RoutingRule {
            path_pattern: pattern.to_string(),
            rewrite_to: rewrite.to_string(),
        }
    }

    // -- apply_routing_rules --------------------------------------------------

    #[test]
    fn test_no_rules_returns_none() {
        assert_eq!(apply_routing_rules("some/path", &[]), None);
    }

    #[test]
    fn test_no_match_returns_none() {
        let rules = vec![rule("^foo/(.*)$", "bar/$1")];
        assert_eq!(apply_routing_rules("baz/file.txt", &rules), None);
    }

    #[test]
    fn test_simple_capture_group() {
        let rules = vec![rule("^releases/(.*)$", "download/$1")];
        assert_eq!(
            apply_routing_rules("releases/v1.0/app.zip", &rules),
            Some("download/v1.0/app.zip".to_string())
        );
    }

    #[test]
    fn test_multiple_capture_groups() {
        let rules = vec![rule(
            "^([^/]+)/([^/]+)/(.*)$",
            "repos/$1/$2/releases/download/$3",
        )];
        assert_eq!(
            apply_routing_rules("owner/repo/v1.0.0/binary.tar.gz", &rules),
            Some("repos/owner/repo/releases/download/v1.0.0/binary.tar.gz".to_string())
        );
    }

    #[test]
    fn test_first_matching_rule_wins() {
        let rules = vec![
            rule("^alpha/(.*)$", "first/$1"),
            rule("^alpha/(.*)$", "second/$1"),
        ];
        assert_eq!(
            apply_routing_rules("alpha/file", &rules),
            Some("first/file".to_string())
        );
    }

    #[test]
    fn test_second_rule_matches_when_first_does_not() {
        let rules = vec![
            rule("^alpha/(.*)$", "first/$1"),
            rule("^beta/(.*)$", "second/$1"),
        ];
        assert_eq!(
            apply_routing_rules("beta/file", &rules),
            Some("second/file".to_string())
        );
    }

    #[test]
    fn test_github_releases_use_case() {
        // Nexus-style routing for GitHub releases:
        // client requests: owner/repo/releases/download/v1.0/file.tar.gz
        // upstream expects: /owner/repo/releases/download/v1.0/file.tar.gz
        // In this case the pattern maps the path directly.
        let rules = vec![rule(
            "^([^/]+)/([^/]+)/releases/download/(.*)$",
            "$1/$2/releases/download/$3",
        )];
        let result = apply_routing_rules(
            "gleske/project/releases/download/v2.1/artifact.tar.gz",
            &rules,
        );
        assert_eq!(
            result,
            Some("gleske/project/releases/download/v2.1/artifact.tar.gz".to_string())
        );
    }

    #[test]
    fn test_path_prefix_rewrite() {
        let rules = vec![rule("^assets/(.*)$", "cdn/v2/assets/$1")];
        assert_eq!(
            apply_routing_rules("assets/image.png", &rules),
            Some("cdn/v2/assets/image.png".to_string())
        );
    }

    #[test]
    fn test_static_rewrite_no_captures() {
        let rules = vec![rule("^health$", "api/v1/healthz")];
        assert_eq!(
            apply_routing_rules("health", &rules),
            Some("api/v1/healthz".to_string())
        );
    }

    #[test]
    fn test_invalid_regex_is_skipped() {
        let rules = vec![
            rule("[invalid", "bad"),      // invalid regex
            rule("^good/(.*)$", "ok/$1"), // valid
        ];
        assert_eq!(
            apply_routing_rules("good/file", &rules),
            Some("ok/file".to_string())
        );
    }

    #[test]
    fn test_anchoring_applied_when_missing() {
        // Pattern without anchors should still match the entire path
        let rules = vec![rule("foo/(.*)", "bar/$1")];
        assert_eq!(
            apply_routing_rules("foo/baz", &rules),
            Some("bar/baz".to_string())
        );
    }

    #[test]
    fn test_anchored_pattern_used_as_is() {
        let rules = vec![rule("^exact$", "replacement")];
        assert_eq!(
            apply_routing_rules("exact", &rules),
            Some("replacement".to_string())
        );
        assert_eq!(apply_routing_rules("not-exact", &rules), None);
    }

    #[test]
    fn test_dollar_zero_references_full_match() {
        let rules = vec![rule("^(.*)$", "prefix/$0")];
        assert_eq!(
            apply_routing_rules("anything", &rules),
            Some("prefix/anything".to_string())
        );
    }

    #[test]
    fn test_empty_path() {
        let rules = vec![rule("^$", "index.html")];
        assert_eq!(
            apply_routing_rules("", &rules),
            Some("index.html".to_string())
        );
    }

    #[test]
    fn test_path_with_query_like_characters() {
        let rules = vec![rule("^files/(.*)$", "dl/$1")];
        assert_eq!(
            apply_routing_rules("files/doc.pdf", &rules),
            Some("dl/doc.pdf".to_string())
        );
    }

    #[test]
    fn test_rewrite_with_literal_dollar_not_followed_by_digit() {
        // "$foo" is not a capture reference, so it stays as-is
        let rules = vec![rule("^(.*)$", "$foo/$1")];
        assert_eq!(
            apply_routing_rules("path", &rules),
            Some("$foo/path".to_string())
        );
    }

    // -- validate_routing_rule ------------------------------------------------

    #[test]
    fn test_validate_valid_rule() {
        let r = rule("^releases/(.*)$", "download/$1");
        assert!(validate_routing_rule(&r).is_ok());
    }

    #[test]
    fn test_validate_invalid_regex() {
        let r = rule("[unclosed", "nope");
        assert!(validate_routing_rule(&r).is_err());
    }

    #[test]
    fn test_validate_bad_group_reference() {
        let r = rule("^(.*)$", "$2");
        let err = validate_routing_rule(&r).unwrap_err();
        assert!(err.contains("$2"));
        assert!(err.contains("1 capture group"));
    }

    #[test]
    fn test_validate_no_captures_dollar_one_rejected() {
        let r = rule("^exact$", "rewrite/$1");
        let err = validate_routing_rule(&r).unwrap_err();
        assert!(err.contains("$1"));
        assert!(err.contains("0 capture group"));
    }

    #[test]
    fn test_validate_dollar_zero_always_valid() {
        let r = rule("^exact$", "$0-copy");
        assert!(validate_routing_rule(&r).is_ok());
    }

    #[test]
    fn test_validate_multiple_groups() {
        let r = rule("^([^/]+)/([^/]+)/(.*)$", "$1/$2/$3");
        assert!(validate_routing_rule(&r).is_ok());
    }

    #[test]
    fn test_validate_group_reference_exceeds_count() {
        let r = rule("^([^/]+)/(.*)$", "$1/$2/$3");
        let err = validate_routing_rule(&r).unwrap_err();
        assert!(err.contains("$3"));
    }

    // -- RoutingRule serialization --------------------------------------------

    #[test]
    fn test_routing_rule_roundtrip_json() {
        let r = rule("^test/(.*)$", "out/$1");
        let json = serde_json::to_string(&r).unwrap();
        let deserialized: RoutingRule = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.path_pattern, r.path_pattern);
        assert_eq!(deserialized.rewrite_to, r.rewrite_to);
    }

    #[test]
    fn test_routing_rule_deserialize_from_json() {
        let json = r#"{"path_pattern":"^a/(.*)$","rewrite_to":"b/$1"}"#;
        let r: RoutingRule = serde_json::from_str(json).unwrap();
        assert_eq!(r.path_pattern, "^a/(.*)$");
        assert_eq!(r.rewrite_to, "b/$1");
    }

    #[test]
    fn test_routing_rules_array_deserialize() {
        let json = r#"[
            {"path_pattern":"^a$","rewrite_to":"x"},
            {"path_pattern":"^b$","rewrite_to":"y"}
        ]"#;
        let rules: Vec<RoutingRule> = serde_json::from_str(json).unwrap();
        assert_eq!(rules.len(), 2);
    }
}
