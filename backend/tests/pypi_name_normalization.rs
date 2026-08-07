//! PEP 503 / PEP 685 project-name normalization for `PypiHandler::normalize_name`.
//!
//! Behaviors re-derived from PEP 503/685 and the pypa/packaging test suite
//! (`packaging.utils.canonicalize_name`, Apache-2.0 OR BSD-2-Clause) and
//! credited via the conformance corpus CREDITS ledger (no upstream code/data
//! copied). Any run of non-alphanumerics folds to a single `-`, the result is
//! lowercased, and leading/trailing separators are dropped.

use artifact_keeper_backend::formats::pypi::PypiHandler;

fn norm(name: &str) -> String {
    PypiHandler::normalize_name(name)
}

#[test]
fn pep503_folds_separators_and_lowercases() {
    let cases = [
        ("Foo.Bar_Baz", "foo-bar-baz"),
        ("zope.interface", "zope-interface"),
        ("ruamel.yaml", "ruamel-yaml"),
        ("Django", "django"),
        ("PyYAML", "pyyaml"),
        ("Twisted", "twisted"),
        ("already-normalized", "already-normalized"),
        ("a--b__c..d", "a-b-c-d"),
        ("back.....slash", "back-slash"),
    ];
    for (raw, want) in cases {
        assert_eq!(norm(raw), want, "normalize_name('{raw}')");
    }
}

#[test]
fn pep503_strips_leading_and_trailing_separators() {
    assert_eq!(norm("__foo__"), "foo");
    assert_eq!(norm("...bar..."), "bar");
    assert_eq!(norm("-baz-"), "baz");
}

#[test]
fn pep503_all_separator_input_normalizes_to_empty() {
    assert_eq!(norm("___"), "");
    assert_eq!(norm("..--.."), "");
    assert_eq!(norm(""), "");
}

#[test]
fn pep503_is_idempotent() {
    for raw in ["Foo.Bar", "a--b", "zope.interface", "Already-Norm"] {
        let once = norm(raw);
        assert_eq!(
            norm(&once),
            once,
            "normalize_name not idempotent for '{raw}'"
        );
    }
}
