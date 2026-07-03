//! Streaming-invariant enforcement gate — source-scan (Part of #1608, Phase 1).
//!
//! This is the belt-and-suspenders companion to the clippy `disallowed-methods`
//! gate configured in `.clippy.toml`. Clippy is the primary enforcement (it
//! resolves `reqwest::Response::bytes`, `axum::extract::multipart::Field::bytes`
//! and `axum::body::to_bytes` by type and fails the build on any un-annotated
//! call). This test adds a text-level ratchet that:
//!
//!   1. asserts the set of `STREAMING-EXEMPT`-annotated buffering sites in the
//!      production source tree exactly equals the known allowlist below, and
//!   2. fails if a new, un-annotated full-body-buffering call appears (including
//!      same-syntax calls on types clippy resolves differently, e.g. the
//!      `object_store::GetResult::bytes()` storage reads).
//!
//! The invariant: no artifact-path handler may read a full artifact body into
//! memory. Every entry below is a CURRENT legitimate buffer site carrying a
//! `#[allow(clippy::disallowed_methods)] // STREAMING-EXEMPT: <why>` annotation
//! (or, for calls clippy does not gate, a bare `// STREAMING-EXEMPT:` comment).
//! As later phases convert a site to streaming, delete its annotation AND shrink
//! its count here — the count is meant to trend to zero.
//!
//! Test code (buffering a response body in an assertion is not an artifact-path
//! handler) is intentionally excluded: `#[cfg(test)]` modules are stripped, and
//! whole-file test scaffolds carrying a file-level
//! `#![allow(clippy::disallowed_methods)]` are skipped.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Per-file count of legitimate, annotated full-body-buffering sites in the
/// production (non-test) source tree. Paths are relative to the crate root.
///
/// Phase 1 total: 38 exempt sites (36 clippy-gated + 2 `object_store` storage
/// reads). Shrink these as streaming conversions land in later phases of #1608.
const ALLOWLIST: &[(&str, usize)] = &[
    ("src/api/handlers/ansible.rs", 2),
    ("src/api/handlers/chef.rs", 2),
    ("src/api/handlers/goproxy.rs", 1),
    ("src/api/handlers/helm.rs", 1),
    ("src/api/handlers/npm.rs", 5),
    ("src/api/handlers/oci_v2.rs", 1),
    ("src/api/handlers/plugins.rs", 2),
    ("src/api/handlers/proxy_helpers.rs", 2),
    ("src/api/handlers/pub_registry.rs", 1),
    ("src/api/handlers/pypi.rs", 1),
    ("src/api/handlers/remote_instances.rs", 1),
    ("src/api/handlers/repositories.rs", 2),
    ("src/api/middleware/rate_limit.rs", 1),
    ("src/main.rs", 1),
    ("src/services/artifactory_client.rs", 1),
    ("src/services/nexus_client.rs", 1),
    ("src/services/proxy_service.rs", 1),
    ("src/services/scheduler_service.rs", 2),
    ("src/storage/azure.rs", 4),
    ("src/storage/gcs.rs", 4),
    ("src/storage/s3.rs", 2),
];

/// Marker that annotates an exempt buffer site.
const MARKER: &str = "STREAMING-EXEMPT";
/// Whole-file test-scaffold exemption (file-level inner attribute).
const FILE_EXEMPT: &str = "#![allow(clippy::disallowed_methods)]";

/// Replace every character that lives inside a string literal, char literal or
/// comment with a space (newlines preserved), so that later text scanning and
/// brace matching operate on *code* only. This is deliberately conservative: it
/// only needs to be correct enough that braces and the disallowed-call syntax
/// inside strings/comments are neutralised.
fn code_mask(src: &str) -> String {
    #[derive(PartialEq)]
    enum St {
        Normal,
        Line,
        Block(u32),
        Str,
        Raw(usize),
        Char,
    }
    let b = src.as_bytes();
    let n = b.len();
    let mut out = Vec::with_capacity(n);
    let mut i = 0usize;
    let mut st = St::Normal;
    let push = |out: &mut Vec<u8>, c: u8| out.push(if c == b'\n' { b'\n' } else { b' ' });
    while i < n {
        let c = b[i];
        let nx = if i + 1 < n { b[i + 1] } else { 0 };
        match st {
            St::Normal => {
                if c == b'/' && nx == b'/' {
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                    st = St::Line;
                } else if c == b'/' && nx == b'*' {
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                    st = St::Block(1);
                } else if c == b'r' && (nx == b'"' || nx == b'#') {
                    // Raw string: r followed by zero+ '#' then '"'.
                    let mut j = i + 1;
                    let mut h = 0usize;
                    while j < n && b[j] == b'#' {
                        h += 1;
                        j += 1;
                    }
                    if j < n && b[j] == b'"' {
                        // The opener `r#*"` contains no newlines — blank it out.
                        out.resize(out.len() + (j - i + 1), b' ');
                        i = j + 1;
                        st = St::Raw(h);
                    } else {
                        out.push(c);
                        i += 1;
                    }
                } else if c == b'"' {
                    out.push(b' ');
                    i += 1;
                    st = St::Str;
                } else if c == b'\'' {
                    // Char literal vs lifetime. Char: '\?.'  ; lifetime: 'ident.
                    if nx == b'\\' || (i + 2 < n && b[i + 2] == b'\'') {
                        out.push(b' ');
                        i += 1;
                        st = St::Char;
                    } else {
                        // Lifetime — harmless as code (contains no braces).
                        out.push(c);
                        i += 1;
                    }
                } else {
                    out.push(c);
                    i += 1;
                }
            }
            St::Line => {
                if c == b'\n' {
                    out.push(b'\n');
                    st = St::Normal;
                } else {
                    out.push(b' ');
                }
                i += 1;
            }
            St::Block(depth) => {
                if c == b'/' && nx == b'*' {
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                    st = St::Block(depth + 1);
                } else if c == b'*' && nx == b'/' {
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                    st = if depth == 1 {
                        St::Normal
                    } else {
                        St::Block(depth - 1)
                    };
                } else {
                    push(&mut out, c);
                    i += 1;
                }
            }
            St::Str => {
                if c == b'\\' {
                    out.push(b' ');
                    push(&mut out, nx);
                    i += 2;
                } else if c == b'"' {
                    out.push(b' ');
                    i += 1;
                    st = St::Normal;
                } else {
                    push(&mut out, c);
                    i += 1;
                }
            }
            St::Raw(h) => {
                if c == b'"' && (0..h).all(|k| i + 1 + k < n && b[i + 1 + k] == b'#') {
                    out.resize(out.len() + h + 1, b' ');
                    i += 1 + h;
                    st = St::Normal;
                } else {
                    push(&mut out, c);
                    i += 1;
                }
            }
            St::Char => {
                if c == b'\\' {
                    out.push(b' ');
                    out.push(b' ');
                    i += 2;
                } else if c == b'\'' {
                    out.push(b' ');
                    i += 1;
                    st = St::Normal;
                } else {
                    out.push(b' ');
                    i += 1;
                }
            }
        }
    }
    // Safe: we only ever pushed ASCII spaces/newlines or copied original ASCII
    // bytes at code positions; multi-byte UTF-8 only occurs inside strings (now
    // blanked) so the result is valid UTF-8.
    String::from_utf8(out).expect("masked code is valid UTF-8")
}

/// 1-based line numbers that live inside a `#[cfg(test)]` item (module, fn, ...),
/// found by brace-matching on the masked code so string/comment braces are
/// ignored.
fn test_lines(masked: &str) -> std::collections::HashSet<usize> {
    let bytes = masked.as_bytes();
    let mut out = std::collections::HashSet::new();
    let mut search_from = 0usize;
    while let Some(rel) = masked[search_from..].find("#[cfg(test)]") {
        let p = search_from + rel;
        // First '{' at/after the attribute opens the guarded item's body.
        let Some(open) = masked[p..].find('{').map(|o| p + o) else {
            break;
        };
        let mut depth = 0i32;
        let mut end = None;
        let mut j = open;
        while j < bytes.len() {
            match bytes[j] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(j);
                        break;
                    }
                }
                _ => {}
            }
            j += 1;
        }
        let Some(end) = end else { break };
        let start_line = masked[..p].bytes().filter(|&c| c == b'\n').count() + 1;
        let end_line = masked[..end].bytes().filter(|&c| c == b'\n').count() + 1;
        for l in start_line..=end_line {
            out.insert(l);
        }
        search_from = end + 1;
    }
    out
}

/// Count disallowed full-body-buffering call *candidates* on a production
/// (non-test) masked-code line. Handles `.bytes().await` chains that wrap across
/// lines (the `.await` may sit on the next non-blank line).
fn count_calls(codelines: &[&str], idx: usize, test: &std::collections::HashSet<usize>) -> usize {
    let line = codelines[idx];
    let mut calls = 0usize;

    // reqwest::Response::bytes / Field::bytes -> `.bytes()` immediately awaited.
    let mut from = 0usize;
    while let Some(rel) = line[from..].find(".bytes()") {
        let at = from + rel;
        from = at + ".bytes()".len();
        let tail = line[from..].trim_start();
        if tail.starts_with(".await") {
            calls += 1;
        } else if tail.is_empty() {
            // Look at the next non-blank code line for a leading `.await`.
            let mut k = idx + 1;
            while k < codelines.len() && codelines[k].trim().is_empty() {
                k += 1;
            }
            if k < codelines.len()
                && !test.contains(&(k + 1))
                && codelines[k].trim_start().starts_with(".await")
            {
                calls += 1;
            }
        }
    }

    // axum::body::to_bytes -> free function `to_bytes(` (not `.to_bytes()` and
    // not the tail of `into_bytes(`).
    let mut from = 0usize;
    let bytes = line.as_bytes();
    while let Some(rel) = line[from..].find("to_bytes") {
        let at = from + rel;
        from = at + "to_bytes".len();
        let before = if at == 0 { b' ' } else { bytes[at - 1] };
        let is_word = before == b'.' || before == b'_' || before.is_ascii_alphanumeric();
        // require an opening paren (allowing whitespace) after `to_bytes`
        let rest = line[from..].trim_start();
        if !is_word && rest.starts_with('(') {
            calls += 1;
        }
    }
    calls
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_rs_files(&p, out);
        } else if p.extension().map(|e| e == "rs").unwrap_or(false) {
            out.push(p);
        }
    }
}

#[test]
fn streaming_invariant_exempt_sites_match_allowlist() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let src = root.join("src");
    let mut files = Vec::new();
    collect_rs_files(&src, &mut files);
    files.sort();

    let allow: BTreeMap<&str, usize> = ALLOWLIST.iter().copied().collect();

    let mut actual_marks: BTreeMap<String, usize> = BTreeMap::new();
    let mut unannotated: Vec<String> = Vec::new();

    for file in &files {
        let raw = std::fs::read_to_string(file).expect("read source file");
        let rel = file
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");

        // Whole-file test scaffold: skip entirely.
        if raw.lines().any(|l| l.trim_start().starts_with(FILE_EXEMPT)) {
            continue;
        }

        let masked = code_mask(&raw);
        let codelines: Vec<&str> = masked.lines().collect();
        let rawlines: Vec<&str> = raw.lines().collect();
        let test = test_lines(&masked);

        let mut calls = 0usize;
        for (i, _) in codelines.iter().enumerate() {
            if test.contains(&(i + 1)) {
                continue;
            }
            calls += count_calls(&codelines, i, &test);
        }

        let marks = rawlines
            .iter()
            .enumerate()
            .filter(|(i, l)| !test.contains(&(i + 1)) && l.contains(MARKER))
            .count();

        if marks > 0 {
            actual_marks.insert(rel.clone(), marks);
        }
        // Every disallowed-call candidate outside test code must be annotated.
        if calls > marks {
            unannotated.push(format!(
                "{rel}: {calls} disallowed-call candidate(s) but only {marks} `{MARKER}` \
                 annotation(s) — annotate the new full-body read (or convert it to streaming) \
                 and update ALLOWLIST in tests/streaming_invariant.rs"
            ));
        }
    }

    assert!(
        unannotated.is_empty(),
        "New un-annotated full-body-buffering call(s) detected (Core Invariant ①, #1608):\n  {}",
        unannotated.join("\n  ")
    );

    let expected: BTreeMap<String, usize> =
        allow.iter().map(|(k, v)| (k.to_string(), *v)).collect();

    if actual_marks != expected {
        let mut diff = String::new();
        for (k, v) in &expected {
            match actual_marks.get(k) {
                Some(a) if a == v => {}
                Some(a) => diff.push_str(&format!("  {k}: allowlist={v} actual={a}\n")),
                None => diff.push_str(&format!("  {k}: allowlist={v} actual=0 (site removed?)\n")),
            }
        }
        for (k, a) in &actual_marks {
            if !expected.contains_key(k) {
                diff.push_str(&format!(
                    "  {k}: allowlist=<absent> actual={a} (new exempt file)\n"
                ));
            }
        }
        panic!(
            "STREAMING-EXEMPT annotations no longer match the allowlist. If you removed a buffer \
             site (good — Phase progress!), shrink the count in ALLOWLIST. If you added one, it \
             must be justified and tracked under #1608.\n{diff}"
        );
    }

    let total: usize = actual_marks.values().sum();
    assert_eq!(
        total, 38,
        "expected 38 exempt sites in Phase 1; got {total}"
    );
}
