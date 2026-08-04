//! PEP 427 wheel / sdist filename parsing for `PypiHandler::parse_filename`.
//!
//! Behaviors from PEP 427 and the binary-distribution spec, re-derived and
//! credited via the conformance corpus (no upstream code/data copied). The
//! distribution name is normalized (PEP 503); the version is taken verbatim
//! from the filename.

use artifact_keeper_backend::formats::pypi::PypiHandler;

#[test]
fn wheel_filename_yields_normalized_name_and_version() {
    let info = PypiHandler::parse_filename("Foo_Bar-1.2.3-py3-none-any.whl").unwrap();
    assert_eq!(info.name.as_deref(), Some("foo-bar"), "name normalized");
    assert_eq!(info.version.as_deref(), Some("1.2.3"));
    assert_eq!(
        info.filename.as_deref(),
        Some("Foo_Bar-1.2.3-py3-none-any.whl")
    );
    assert!(!info.is_simple_index && !info.is_package_index);
}

#[test]
fn wheel_filename_with_build_tag_still_parses_name_version() {
    let info =
        PypiHandler::parse_filename("numpy-1.26.0-1-cp39-cp39-manylinux1_x86_64.whl").unwrap();
    assert_eq!(info.name.as_deref(), Some("numpy"));
    assert_eq!(info.version.as_deref(), Some("1.26.0"));
}

#[test]
fn sdist_targz_splits_on_the_last_hyphen() {
    let info = PypiHandler::parse_filename("my-cool-pkg-2.0.tar.gz").unwrap();
    assert_eq!(info.name.as_deref(), Some("my-cool-pkg"));
    assert_eq!(info.version.as_deref(), Some("2.0"));
}

#[test]
fn sdist_zip_parses_name_and_version() {
    let info = PypiHandler::parse_filename("pkg-1.0.zip").unwrap();
    assert_eq!(info.name.as_deref(), Some("pkg"));
    assert_eq!(info.version.as_deref(), Some("1.0"));
}

#[test]
fn unknown_extension_and_malformed_names_are_rejected() {
    assert!(PypiHandler::parse_filename("pkg-1.0.rpm").is_err(), "unknown ext");
    assert!(
        PypiHandler::parse_filename("too-short.whl").is_err(),
        "wheel needs >=5 hyphen fields"
    );
    assert!(
        PypiHandler::parse_filename("nodash.tar.gz").is_err(),
        "sdist needs a name-version hyphen"
    );
}
