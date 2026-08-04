//! PEP 440 version-equivalence conformance for `PypiHandler::canonical_version`.
//!
//! Vectors derived from PEP 440 and the pypa/packaging test suite
//! (`tests/test_version.py`), dual-licensed Apache-2.0 OR BSD-2-Clause. The
//! *behaviors* are re-derived and credited here (no upstream code or data
//! copied) — see the conformance corpus and its CREDITS ledger in the
//! artifact-keeper-test repo. This is the backend (unit-layer) consumer for the
//! version-normalization slice of that corpus: the part that maps to a real AK
//! function. Ordering / specifier / marker / tag vectors are NOT included
//! because AK does not implement those engines (tracked as conformance gaps,
//! not tests).
//!
//! Contract under test: two version strings that PEP 440 considers EQUAL must
//! canonicalize to the same non-None key; unequal versions must not collide;
//! syntactically invalid versions must be rejected (None).

use artifact_keeper_backend::formats::pypi::PypiHandler;

fn canon(v: &str) -> Option<String> {
    PypiHandler::canonical_version(v)
}

/// Every spelling in `group` must canonicalize to the same non-None key.
fn assert_group_equal(group: &[&str]) {
    let keys: Vec<Option<String>> = group.iter().map(|v| canon(v)).collect();
    let first = &keys[0];
    assert!(
        first.is_some(),
        "expected a canonical form for '{}', got None",
        group[0]
    );
    for (v, k) in group.iter().zip(&keys) {
        assert_eq!(
            k, first,
            "'{v}' canonicalized to {k:?}, expected same as '{}' -> {first:?}",
            group[0]
        );
    }
}

#[test]
fn pep440_prerelease_alpha_spellings_are_equivalent() {
    assert_group_equal(&["1.0a1", "1.0alpha1", "1.0.alpha.1", "1.0-a-1", "1.0_a_1"]);
}

#[test]
fn pep440_prerelease_beta_spellings_are_equivalent() {
    assert_group_equal(&["1.0b2", "1.0beta2", "1.0.b.2", "1.0-beta-2"]);
}

#[test]
fn pep440_prerelease_rc_spellings_are_equivalent() {
    // PEP 440 folds c / rc / pre / preview to the same "rc" pre-release.
    assert_group_equal(&["1.0rc1", "1.0c1", "1.0pre1", "1.0preview1", "1.0.rc.1"]);
}

#[test]
fn pep440_post_release_spellings_are_equivalent() {
    // post / rev / r, plus the implicit-post form "1.0-1".
    assert_group_equal(&["1.0post1", "1.0rev1", "1.0r1", "1.0-1", "1.0.post.1"]);
}

#[test]
fn pep440_dev_release_spellings_are_equivalent() {
    assert_group_equal(&["1.0dev1", "1.0.dev1", "1.0-dev-1", "1.0_dev_1"]);
}

#[test]
fn pep440_v_prefix_is_stripped() {
    assert_group_equal(&["1.0", "v1.0", "V1.0"]);
}

#[test]
fn pep440_epoch_leading_zeros_are_normalized() {
    assert_group_equal(&["1!1.0", "01!1.0", "001!1.0"]);
}

#[test]
fn pep440_distinct_versions_do_not_collide() {
    assert_ne!(canon("1.0a1"), canon("1.0b1"), "alpha vs beta");
    assert_ne!(canon("1.0"), canon("1!1.0"), "epoch 0 vs 1");
    assert_ne!(canon("1.0.post1"), canon("1.0.dev1"), "post vs dev");
    assert_ne!(canon("1.0"), canon("2.0"), "different release");
    assert_ne!(canon("1.0rc1"), canon("1.0rc2"), "rc1 vs rc2");
    // All of these are valid, so distinctness is a real (not vacuous) check.
    for v in ["1.0a1", "1.0b1", "1.0", "1!1.0", "1.0.post1", "1.0.dev1", "2.0"] {
        assert!(canon(v).is_some(), "'{v}' should be a valid version");
    }
}

#[test]
fn pep440_invalid_versions_are_rejected() {
    for bad in ["", "   ", "v", "V", "!1.0", "x!1.0", "abc", "+local"] {
        assert_eq!(canon(bad), None, "'{bad}' should be rejected as invalid");
    }
}
