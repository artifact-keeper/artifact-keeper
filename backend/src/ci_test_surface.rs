//! CI test-surface contract (#3494).
//!
//! CI's integration-test jobs run an explicit `--test <name>` allowlist, so a
//! new file under `backend/tests/` is **silently dead** unless someone
//! remembers to wire it into `.github/workflows/ci.yml`. That is exactly how
//! 44 of 61 integration targets (232 test functions) came to exist without
//! ever executing — including `security_tests`, `streaming_invariant` (#3607)
//! and `workflow_scan_gate_tests` (#3437), each of which was written to be a
//! gate and then never ran.
//!
//! This module closes the loop: every target under `backend/tests/` must be
//! either
//!
//!   * **wired** — named in a `--test` invocation in some workflow under
//!     `.github/workflows/`, in the *right kind* of step for its tests
//!     (see below), or
//!   * **exempt** — listed in [`EXEMPT`] with a justification, for targets
//!     that genuinely cannot run in CI (live cloud credentials, a running
//!     HTTP backend the job does not provision).
//!
//! "Right kind of step" matters because the Tier 2 integration job runs
//! `cargo test ... -- --ignored`: a target whose tests are NOT `#[ignore]`d
//! yields `running 0 tests` there and passes vacuously. So a target with
//! non-`#[ignore]`d tests must appear in a step that runs the default set
//! (Tier 1), and a target with `#[ignore]`d tests must appear in an
//! `-- --ignored` step. A mixed target must appear in both.
//!
//! It lives in the LIBRARY (not `backend/tests/`) on purpose: `--lib` runs
//! unconditionally in both the unit-test and coverage jobs, so this gate
//! cannot itself fall out of the very allowlist it polices.
//!
//! The checks are text-level scans of the workflow YAML, in the same spirit
//! as `backend/tests/streaming_invariant.rs` and
//! `backend/tests/workflow_scan_gate_tests.rs`.

#![allow(dead_code)]

/// Integration targets that deliberately do NOT run in CI. Every entry
/// carries the reason; the gate fails on a stale entry (file deleted or the
/// target got wired after all), so this list cannot silently rot.
const EXEMPT: &[(&str, &str)] = &[
    (
        "azure_rbac_live_test",
        "requires live Azure credentials via std::env::var().expect(); CI has no cloud creds",
    ),
    (
        "azure_shared_key_live_test",
        "requires live Azure credentials via std::env::var().expect(); CI has no cloud creds",
    ),
    (
        "s3_integration",
        "requires live S3 credentials; the release-gate S3 compose job covers this path",
    ),
    (
        "download_ticket_tests",
        "reads TEST_BASE_URL and drives a running HTTP backend; the CI integration job provisions Postgres only",
    ),
    (
        "integration_tests",
        "reads TEST_BASE_URL and drives a running HTTP backend; the CI integration job provisions Postgres only",
    ),
    (
        "replication_integration",
        "reads TEST_BASE_URL and drives a running HTTP backend; the CI integration job provisions Postgres only",
    ),
    (
        "storage_backend_tests",
        "reads TEST_BASE_URL and drives a running HTTP backend; the CI integration job provisions Postgres only",
    ),
    (
        "tag_filtered_replication_tests",
        "reads TEST_BASE_URL and drives a running HTTP backend; the CI integration job provisions Postgres only",
    ),
];

/// Join shell backslash-continuations so a multi-line `cargo test \`
/// invocation in a YAML `run:` block scans as one logical command line.
fn logical_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(stripped) = trimmed.strip_suffix('\\') {
            cur.push_str(stripped.trim_end());
            cur.push(' ');
        } else {
            cur.push_str(trimmed);
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Every `--test <name>` target named on one logical command line. Does not
/// match `--test-threads` (no space) or `--test=...` (the repo style is
/// space-separated).
fn test_target_names(logical: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = logical;
    while let Some(idx) = rest.find("--test ") {
        rest = &rest[idx + "--test ".len()..];
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            names.push(name);
        }
    }
    names
}

/// Whether a logical `cargo test` / `cargo nextest run` line executes the
/// `#[ignore]`d set instead of the default set.
fn runs_ignored_set(logical: &str) -> bool {
    logical.contains("-- --ignored") || logical.contains("--run-ignored")
}

/// Count `(non_ignored, ignored)` test functions in one test source file by
/// scanning the attribute lines above each `fn`. The corpus uses single-line
/// attributes exclusively (`#[test]`, `#[tokio::test]`, `#[ignore]`,
/// `#[ignore = "..."]`), which is all this recognises; a misparse fails
/// toward "test exists but is unclassified", which the gate reports.
fn count_tests(source: &str) -> (usize, usize) {
    let mut non_ignored = 0usize;
    let mut ignored = 0usize;
    let mut pending_test = false;
    let mut pending_ignore = false;
    for raw in source.lines() {
        let line = raw.trim_start();
        if let Some(attr) = line.strip_prefix("#[") {
            let name: String = attr
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == ':' || *c == '_')
                .collect();
            match name.as_str() {
                "test" | "tokio::test" => pending_test = true,
                "ignore" => pending_ignore = true,
                _ => {}
            }
        } else if line.starts_with("fn ")
            || line.starts_with("async fn ")
            || line.starts_with("pub fn ")
            || line.starts_with("pub async fn ")
        {
            if pending_test {
                if pending_ignore {
                    ignored += 1;
                } else {
                    non_ignored += 1;
                }
            }
            pending_test = false;
            pending_ignore = false;
        } else if line.is_empty() || line.starts_with("//") {
            // doc/comment lines between attributes and the fn keep state
        } else {
            pending_test = false;
            pending_ignore = false;
        }
    }
    (non_ignored, ignored)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("backend/ has a parent")
            .to_path_buf()
    }

    /// All workflow YAML under `.github/workflows/`, concatenated per file.
    fn workflow_sources() -> Vec<(String, String)> {
        let dir = repo_root().join(".github/workflows");
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&dir).expect(".github/workflows/ readable") {
            let path = entry.expect("dir entry").path();
            let is_yaml = path.extension().is_some_and(|e| e == "yml" || e == "yaml");
            if is_yaml {
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                let body = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
                out.push((name, body));
            }
        }
        assert!(
            !out.is_empty(),
            "no workflow files found — wrong repo root?"
        );
        out
    }

    /// The set of integration target names, i.e. `backend/tests/*.rs` stems.
    fn integration_targets() -> BTreeSet<String> {
        let dir = repo_root().join("backend/tests");
        let mut out = BTreeSet::new();
        for entry in std::fs::read_dir(&dir).expect("backend/tests/ readable") {
            let path = entry.expect("dir entry").path();
            if path.is_file() && path.extension().is_some_and(|e| e == "rs") {
                out.insert(path.file_stem().unwrap().to_string_lossy().into_owned());
            }
        }
        assert!(
            out.len() >= 60,
            "found only {} integration targets — wrong repo root?",
            out.len()
        );
        out
    }

    /// THE gate (#3494): every `backend/tests/*.rs` target is either named in
    /// a `--test` invocation of the right kind in some workflow, or carries a
    /// justified [`EXEMPT`] entry. A new test file that is neither is a red
    /// CI, not a silently dead test.
    #[test]
    fn every_integration_target_is_wired_into_ci_or_exempt() {
        let targets = integration_targets();
        let mut wired_default = BTreeSet::new(); // runs the default (non-ignored) set
        let mut wired_ignored = BTreeSet::new(); // runs the `-- --ignored` set
        for (_file, body) in workflow_sources() {
            for logical in logical_lines(&body) {
                let names = test_target_names(&logical);
                if names.is_empty() {
                    continue;
                }
                let dest = if runs_ignored_set(&logical) {
                    &mut wired_ignored
                } else {
                    &mut wired_default
                };
                dest.extend(names);
            }
        }
        let wired: BTreeSet<_> = wired_default.union(&wired_ignored).cloned().collect();
        let exempt: BTreeSet<String> = EXEMPT.iter().map(|(n, _)| n.to_string()).collect();

        // 1. No dangling `--test` naming a target that no longer exists.
        let dangling: Vec<_> = wired.difference(&targets).collect();
        assert!(
            dangling.is_empty(),
            "workflow --test flags name targets that do not exist under backend/tests/ \
             (renamed or deleted?): {dangling:?}"
        );

        // 2. No stale exemption: an EXEMPT entry must exist and must not
        //    also be wired.
        let stale: Vec<_> = exempt.difference(&targets).collect();
        assert!(
            stale.is_empty(),
            "EXEMPT entries in backend/src/ci_test_surface.rs name targets that do not \
             exist under backend/tests/: {stale:?}"
        );
        let both: Vec<_> = exempt.intersection(&wired).collect();
        assert!(
            both.is_empty(),
            "targets are wired into CI but still listed EXEMPT in \
             backend/src/ci_test_surface.rs — delete the stale exemption: {both:?}"
        );

        // 3. Every target is wired or exempt.
        let dead: Vec<_> = targets
            .iter()
            .filter(|t| !wired.contains(*t) && !exempt.contains(*t))
            .collect();
        assert!(
            dead.is_empty(),
            "integration targets that run in NO CI workflow: {dead:?}\n\
             Every backend/tests/*.rs file must be named in a `--test` invocation in \
             .github/workflows/ (Tier 1 'integration targets' step for non-#[ignore]d \
             tests, the Tier 2 integration job for `-- --ignored` DB suites), or carry \
             a justified entry in EXEMPT in backend/src/ci_test_surface.rs. \
             Without that the tests here will never execute anywhere (#3494)."
        );

        // 4. Wired in the right kind of step for the tests it contains: a
        //    non-#[ignore]d test never runs under `-- --ignored`, and vice
        //    versa (`running 0 tests` + exit 0 — a vacuous green).
        let tests_dir = repo_root().join("backend/tests");
        let mut miswired = Vec::new();
        for target in targets.iter().filter(|t| !exempt.contains(*t)) {
            let src = std::fs::read_to_string(tests_dir.join(format!("{target}.rs")))
                .expect("test source readable");
            let (non_ignored, ignored) = count_tests(&src);
            if non_ignored > 0 && !wired_default.contains(target) {
                miswired.push(format!(
                    "{target}: {non_ignored} non-#[ignore]d tests but only wired via an \
                     `-- --ignored` step — they never run"
                ));
            }
            if ignored > 0 && !wired_ignored.contains(target) {
                miswired.push(format!(
                    "{target}: {ignored} #[ignore]d tests but not wired into an \
                     `-- --ignored` step — they never run"
                ));
            }
        }
        assert!(
            miswired.is_empty(),
            "mis-wired targets:\n{}",
            miswired.join("\n")
        );
    }

    /// Bin-target tests (`backend/src/main.rs`) are only executed when the
    /// nextest invocations say `--bins`; plain `--lib` silently excludes them
    /// (28 tests never ran before #3494). Pin that both unit-test jobs keep
    /// `--bins`.
    #[test]
    fn nextest_lib_invocations_include_bins() {
        let ci = std::fs::read_to_string(repo_root().join(".github/workflows/ci.yml"))
            .expect("ci.yml readable");
        let mut with_bins = 0usize;
        let mut violations = Vec::new();
        for logical in logical_lines(&ci) {
            if logical.contains("nextest run") && logical.contains("--lib") {
                if logical.contains("--bins") {
                    with_bins += 1;
                } else {
                    violations.push(logical);
                }
            }
        }
        assert!(
            violations.is_empty(),
            "nextest `--lib` invocations in ci.yml without `--bins` — the \
             backend/src/main.rs bin-target tests will silently stop running \
             (#3494): {violations:?}"
        );
        assert!(
            with_bins >= 2,
            "expected the unit-test and coverage jobs to both run `--lib --bins`; \
             found {with_bins} such invocations — did the jobs get restructured? \
             Update this pin deliberately, not by deletion."
        );
    }

    /// Every nextest invocation that names explicit `--test` targets must
    /// carry `--no-tests=fail`, so a renamed or compiled-out target is a red
    /// job instead of a silent zero-test pass — the mechanism that let
    /// `streaming_invariant` go stale (#3607).
    #[test]
    fn nextest_explicit_target_invocations_fail_on_zero_tests() {
        let ci = std::fs::read_to_string(repo_root().join(".github/workflows/ci.yml"))
            .expect("ci.yml readable");
        let violations: Vec<_> = logical_lines(&ci)
            .into_iter()
            .filter(|l| {
                l.contains("nextest run") && l.contains("--test ") && !l.contains("--no-tests=fail")
            })
            .collect();
        assert!(
            violations.is_empty(),
            "nextest invocations with explicit --test targets but no \
             `--no-tests=fail` in ci.yml: {violations:?}"
        );
    }

    // ── unit tests for the pure helpers ────────────────────────────────────

    #[test]
    fn logical_lines_joins_backslash_continuations() {
        let text = "cargo test --workspace \\\n  --test foo_tests \\\n  -- --ignored\nnext";
        let lines = logical_lines(text);
        assert_eq!(
            lines[0],
            "cargo test --workspace --test foo_tests -- --ignored"
        );
        assert_eq!(lines[1], "next");
    }

    #[test]
    fn test_target_names_extracts_all_and_skips_test_threads() {
        let l = "cargo test --test alpha --test beta_2 -- --ignored --test-threads=1";
        assert_eq!(test_target_names(l), vec!["alpha", "beta_2"]);
        assert!(test_target_names("cargo nextest run --workspace --lib").is_empty());
    }

    #[test]
    fn runs_ignored_set_detects_both_runner_styles() {
        assert!(runs_ignored_set(
            "cargo test --test a -- --ignored --test-threads=1"
        ));
        assert!(runs_ignored_set(
            "cargo nextest run --test a --run-ignored ignored-only"
        ));
        assert!(!runs_ignored_set(
            "cargo nextest run --test a --no-tests=fail"
        ));
    }

    #[test]
    fn count_tests_classifies_ignored_and_plain() {
        let src = r#"
#[test]
fn plain() {}

#[tokio::test]
#[ignore] // requires PostgreSQL
async fn db_backed() {}

#[ignore = "requires DATABASE_URL"]
#[tokio::test]
// a comment between attrs and fn
async fn db_backed_reversed_attrs() {}

fn not_a_test() {}
"#;
        assert_eq!(count_tests(src), (1, 2));
    }
}
