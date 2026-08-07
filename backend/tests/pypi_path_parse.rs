//! PyPI request-path routing for `PypiHandler::parse_path`: root simple index,
//! per-package simple index, `packages/<name>/<version>/<file>`, direct file
//! paths, and rejection of anything else. Behaviors from PEP 503 + AK's path
//! scheme; corpus-credited (no upstream code copied).

use artifact_keeper_backend::formats::pypi::PypiHandler;

#[test]
fn root_simple_index_with_or_without_slash() {
    let i = PypiHandler::parse_path("/simple/").unwrap();
    assert!(i.is_simple_index && !i.is_package_index);
    assert!(i.name.is_none());
    assert!(PypiHandler::parse_path("simple").unwrap().is_simple_index);
}

#[test]
fn per_package_simple_index_normalizes_name() {
    let i = PypiHandler::parse_path("/simple/Flask_Login/").unwrap();
    assert!(i.is_package_index && !i.is_simple_index);
    assert_eq!(i.name.as_deref(), Some("flask-login"));
    assert!(i.version.is_none());
}

#[test]
fn packages_file_path_extracts_name_version_filename() {
    let i = PypiHandler::parse_path("packages/foo/1.0/foo-1.0-py3-none-any.whl").unwrap();
    assert_eq!(i.name.as_deref(), Some("foo"));
    assert_eq!(i.version.as_deref(), Some("1.0"));
    assert_eq!(i.filename.as_deref(), Some("foo-1.0-py3-none-any.whl"));
}

#[test]
fn direct_wheel_path_delegates_to_filename_parser() {
    let i = PypiHandler::parse_path("some/dir/pkg-2.0-py3-none-any.whl").unwrap();
    assert_eq!(i.name.as_deref(), Some("pkg"));
    assert_eq!(i.version.as_deref(), Some("2.0"));
}

#[test]
fn unroutable_path_is_rejected() {
    assert!(PypiHandler::parse_path("nonsense/path").is_err());
}
