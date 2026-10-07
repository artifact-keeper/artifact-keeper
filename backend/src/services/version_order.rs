//! Segment comparators for ordering version strings.
//!
//! Both are total orders, which `sort_by` requires: since Rust 1.81 the
//! standard sort may panic with "user-provided comparison function does not
//! correctly implement a total order" when handed a comparator with a cycle.
//! A comparator that compares two numeric segments by value but falls back to
//! a lexical compare when only one side is numeric has one: `74 < 103` by
//! value, `103 < 2150693d` and `2150693d < 74` lexically.

use std::cmp::Ordering;

/// Compare two version segments in natural order: the leading run of ASCII
/// digits by value, then the rest of the segment lexically. A segment with no
/// leading digit ranks above every digit-led one.
///
/// This is the ordering a lexical fallback gives for the common shapes
/// (`1rc1 < 2`, `0+local < 1`, `1ubuntu1 < 2`) without its cycle,
/// and the digit run is compared without parsing, so a run too long for
/// `u64` still compares by value.
pub(crate) fn compare_natural_segment(a: &str, b: &str) -> Ordering {
    match (split_leading_digits(a), split_leading_digits(b)) {
        ((Some(da), ra), (Some(db), rb)) => compare_digit_runs(da, db).then_with(|| ra.cmp(rb)),
        ((Some(_), _), (None, _)) => Ordering::Less,
        ((None, _), (Some(_), _)) => Ordering::Greater,
        ((None, ra), (None, rb)) => ra.cmp(rb),
    }
}

/// Compare two SemVer prerelease identifiers (SemVer 2.0.0 §11.4): numeric
/// identifiers by value, alphanumeric ones lexically in ASCII order, and a
/// numeric identifier always below an alphanumeric one.
pub(crate) fn compare_semver_prerelease_identifier(a: &str, b: &str) -> Ordering {
    let numeric = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit());
    match (numeric(a), numeric(b)) {
        (true, true) => compare_digit_runs(a, b),
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (false, false) => a.cmp(b),
    }
}

fn split_leading_digits(s: &str) -> (Option<&str>, &str) {
    let n = s.bytes().take_while(u8::is_ascii_digit).count();
    if n == 0 {
        (None, s)
    } else {
        (Some(&s[..n]), &s[n..])
    }
}

/// Compare two non-empty runs of ASCII digits by value, ignoring leading zeros.
fn compare_digit_runs(a: &str, b: &str) -> Ordering {
    let a = a.trim_start_matches('0');
    let b = b.trim_start_matches('0');
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    /// Every ordered triple drawn from `corpus` must be consistent and
    /// transitive under `cmp`.
    fn assert_total_order(corpus: &[&str], cmp: fn(&str, &str) -> Ordering) {
        for a in corpus {
            assert_eq!(cmp(a, a), Ordering::Equal, "{a:?} must equal itself");
            for b in corpus {
                assert_eq!(cmp(a, b), cmp(b, a).reverse(), "{a:?} vs {b:?}");
                for c in corpus {
                    if cmp(a, b) != Ordering::Greater && cmp(b, c) != Ordering::Greater {
                        assert_ne!(cmp(a, c), Ordering::Greater, "{a:?} <= {b:?} <= {c:?}");
                    }
                }
            }
        }
    }

    const CORPUS: &[&str] = &[
        "",
        "0",
        "00",
        "01",
        "1",
        "2",
        "9",
        "10",
        "74",
        "103",
        "2150693d",
        "03604a46",
        "9754a231",
        "fb6e6f70",
        "alpha",
        "beta",
        "rc1",
        "1rc1",
        "0rc1",
        "0+local",
        "0+cu118",
        "30-1ubuntu1",
        "30-2",
        "1!2",
        "+1",
        "18446744073709551616",
        "18446744073709551615x",
    ];

    #[test]
    fn natural_segment_order_is_total() {
        assert_total_order(CORPUS, compare_natural_segment);
    }

    #[test]
    fn semver_prerelease_identifier_order_is_total() {
        assert_total_order(CORPUS, compare_semver_prerelease_identifier);
    }

    #[test]
    fn natural_segment_breaks_the_lexical_fallback_cycle() {
        use Ordering::*;
        assert_eq!(compare_natural_segment("74", "103"), Less);
        assert_eq!(compare_natural_segment("103", "2150693d"), Less);
        assert_eq!(compare_natural_segment("74", "2150693d"), Less);
    }

    #[test]
    fn natural_segment_keeps_digit_led_suffixes_below_the_next_number() {
        use Ordering::*;
        // PEP 440 pre-releases and local versions, Debian revisions.
        assert_eq!(compare_natural_segment("1rc1", "2"), Less);
        assert_eq!(compare_natural_segment("0+cu118", "1"), Less);
        assert_eq!(compare_natural_segment("1ubuntu1", "2"), Less);
        // The digit run is compared by value, not by parsing into u64.
        assert_eq!(
            compare_natural_segment("18446744073709551616", "18446744073709551615x"),
            Greater
        );
        assert_eq!(compare_natural_segment("01", "1"), Equal);
        assert_eq!(compare_natural_segment("alpha", "9"), Greater);
    }

    #[test]
    fn semver_prerelease_numeric_identifier_ranks_below_alphanumeric() {
        use Ordering::*;
        assert_eq!(
            compare_semver_prerelease_identifier("103", "2150693d"),
            Less
        );
        assert_eq!(
            compare_semver_prerelease_identifier("999999", "2150693d"),
            Less
        );
        assert_eq!(compare_semver_prerelease_identifier("74", "103"), Less);
        assert_eq!(compare_semver_prerelease_identifier("alpha", "beta"), Less);
        assert_eq!(compare_semver_prerelease_identifier("1", "alpha"), Less);
    }
}
