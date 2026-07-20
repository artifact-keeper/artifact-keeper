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
///
/// Phase 2 (#1608) streamed the light-format multipart uploads to storage via
/// `put_artifact_stream`, removing all 5 exempt sites in ansible.rs (2),
/// chef.rs (2) and pub_registry.rs (1): 38 -> 33.
///
/// Phase 3 (#1608) streamed the helm chart upload — the metadata (Chart.yaml)
/// is now parsed from a single on-disk tar entry and the body is streamed to
/// storage via `put_artifact_stream`, removing the 1 exempt site in helm.rs:
/// 33 -> 32.
///
/// Phase 4b (#1608 / #2181) capped the last unbounded buffered upstream read.
/// `ProxyService::read_upstream_response` (the single proxy_service.rs exempt
/// site) is replaced by `read_upstream_response_capped`, which accumulates
/// `response.bytes_stream()` under a running byte ceiling instead of calling
/// `response.bytes()`. With no gated call left, the proxy_service.rs row is
/// removed: 32 -> 31.
///
/// Reconciliation (#2491): three post-Phase-4b merges drifted the source from
/// this allowlist. Reconciled to match the current, correct source:
///   * npm.rs 5 -> 6: the packument stale-while-revalidate cache (#2166) added a
///     bounded `axum::body::to_bytes` read of a computed packument JSON, capped
///     at `NPM_PACKUMENT_BUFFER_CAP`. A legitimate new metadata buffer site.
///   * pypi.rs 1 -> removed: the shared content-addressed upload primitive
///     (#2199) streamed the pypi upload to storage, deleting the last `.bytes()`
///     multipart-field read. Phase progress — the row is gone.
///   * remote_instances.rs 1 -> removed: the remote-instance proxy (#2532) now
///     forwards `resp.bytes_stream()` instead of buffering `.bytes()`. Phase
///     progress — the row is gone.
///
/// Net: 31 -> 30 (+1 npm, -1 pypi, -1 remote_instances).
///
/// PF-005 (#2517) streamed the generic multipart upload extractors
/// (`stage_multipart_file` / `stage_multipart_file_and_path`) onto the shared
/// content-addressed staging primitive, deleting both `Field::bytes()` reads in
/// repositories.rs: the repositories.rs row is removed, 30 -> 28.
///
/// Reconciliation (independent of PF-005): the RPM curation-sync merges (#2567 /
/// #2599) added a third capped-metadata buffer site in scheduler_service.rs
/// (an upstream repo-index gz-decode, not an artifact blob) without updating
/// this allowlist. Reconciled here to match the current source: 2 -> 3, so the
/// total is 28 + 1 = 29.
const ALLOWLIST: &[(&str, usize)] = &[
    ("src/api/handlers/goproxy.rs", 1),
    ("src/api/handlers/npm.rs", 6),
    ("src/api/handlers/oci_v2.rs", 1),
    ("src/api/handlers/plugins.rs", 2),
    ("src/api/handlers/proxy_helpers.rs", 2),
    ("src/api/middleware/rate_limit.rs", 1),
    ("src/main.rs", 1),
    ("src/services/artifactory_client.rs", 1),
    ("src/services/nexus_client.rs", 1),
    ("src/services/scheduler_service.rs", 3),
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
        total, 29,
        "expected 29 exempt sites after #1608 Phase 4b + #2491 reconciliation \
         + PF-005 (#2517) generic multipart streaming (repositories.rs -2) \
         + RPM curation-sync reconciliation (scheduler_service.rs +1); got {total}"
    );
}

// ---------------------------------------------------------------------------
// PF-005 (#2517): `body: Bytes` blob-upload extractor guard.
// ---------------------------------------------------------------------------

/// Per-file count of `body: Bytes` request-body extractors that ALSO perform a
/// blob storage write in the same function — i.e. artifact-upload routes that
/// buffer the whole body on the heap before writing it to storage.
///
/// The clippy `disallowed-methods` gate and the `.bytes()` / `to_bytes` scan
/// above cannot see a `body: Bytes` axum extractor: it is an ordinary typed
/// handler argument resolved by axum, with no gated method call. This ratchet
/// closes that gap — any handler that takes `body: Bytes` and, in the same fn,
/// calls a blob storage write (`storage.put(`, `put_stream(`,
/// `put_artifact_stream(`, `upload[_stream]_with_sync_options(`) must be listed
/// here with a justification, and the list must trend to zero as routes stream.
///
/// Control-plane / JSON routes that take `body: Bytes` for auth-before-parse
/// (post-#1438, e.g. `create_repository`) are NOT matched: they perform no blob
/// storage write in-fn, so they never appear here.
///
/// PF-005 (#2517) Phase 1 streamed the four "common" buffered blob routes
/// (`repositories::upload_artifact` generic PUT, `maven::upload`, and
/// `terraform::upload_module` + `upload_provider`), removing them from this
/// list. The remainder are the long-tail format handlers (tracked for later
/// PF-005 phases) plus two intentional small-body sinks that stay:
///   * `oci_v2::handle_put_manifest` — an OCI *manifest* is a small bounded JSON
///     document (blobs upload via the streamed `/blobs/uploads` path), and
///   * `proxy_helpers::put_artifact_bytes` — the shared buffered helper the
///     long-tail light-format handlers still call; it goes away when they do.
const RAW_BODY_BLOB_ALLOWLIST: &[(&str, usize)] = &[
    ("src/api/handlers/cocoapods.rs", 1),
    ("src/api/handlers/composer.rs", 1),
    ("src/api/handlers/conan.rs", 2),
    ("src/api/handlers/debian.rs", 1),
    ("src/api/handlers/gitlfs.rs", 1),
    ("src/api/handlers/goproxy.rs", 2),
    ("src/api/handlers/jetbrains.rs", 1),
    ("src/api/handlers/oci_v2.rs", 1),
    ("src/api/handlers/proxy_helpers.rs", 1),
    ("src/api/handlers/sbt.rs", 1),
    ("src/api/handlers/swift.rs", 1),
    ("src/api/handlers/vscode.rs", 1),
];

/// Blob storage-write call fragments (matched after collapsing all whitespace,
/// so a `storage\n    .put(` method chain split across lines is still found).
const BLOB_WRITE_TOKENS: &[&str] = &[
    "storage.put(",
    ".put_stream(",
    "put_artifact_stream(",
    "upload_with_sync_options(",
    "upload_stream_with_sync_options(",
];

/// `{ .. }` span of the function whose signature contains byte offset
/// `sig_pos` (a `body: Bytes` match): the first `{` at/after `sig_pos` opens the
/// fn body; brace-match to its close. Returns `(open, close)` byte offsets into
/// `masked`, or `None` if unbalanced. Handler return types contain no `{`, so
/// the first brace after the signature is always the body opener.
fn fn_body_span(masked: &str, sig_pos: usize) -> Option<(usize, usize)> {
    let bytes = masked.as_bytes();
    let open = masked[sig_pos..].find('{').map(|o| sig_pos + o)?;
    let mut depth = 0i32;
    let mut j = open;
    while j < bytes.len() {
        match bytes[j] {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((open, j));
                }
            }
            _ => {}
        }
        j += 1;
    }
    None
}

/// Byte offsets of every standalone `body: Bytes` parameter in masked code (any
/// run of spaces between `body:` and `Bytes`, with both `body` and `Bytes` whole
/// words).
fn raw_body_bytes_positions(masked: &str) -> Vec<usize> {
    let b = masked.as_bytes();
    let mut out = Vec::new();
    let mut from = 0usize;
    while let Some(rel) = masked[from..].find("body:") {
        let at = from + rel;
        from = at + "body:".len();
        // `body` must be a whole word (previous char not an identifier char).
        let prev_ok = at == 0 || !(b[at - 1].is_ascii_alphanumeric() || b[at - 1] == b'_');
        if !prev_ok {
            continue;
        }
        let rest = masked[from..].trim_start();
        if let Some(after) = rest.strip_prefix("Bytes") {
            // `Bytes` must be a whole word too (next char not identifier char).
            let next_ok = after
                .chars()
                .next()
                .map(|c| !(c.is_alphanumeric() || c == '_'))
                .unwrap_or(true);
            if next_ok {
                out.push(at);
            }
        }
    }
    out
}

#[test]
fn streaming_invariant_no_new_buffered_blob_upload_routes() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let src = root.join("src");
    let mut files = Vec::new();
    collect_rs_files(&src, &mut files);
    files.sort();

    let allow: BTreeMap<&str, usize> = RAW_BODY_BLOB_ALLOWLIST.iter().copied().collect();
    let mut actual: BTreeMap<String, usize> = BTreeMap::new();

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
        let test = test_lines(&masked);

        let mut count = 0usize;
        for pos in raw_body_bytes_positions(&masked) {
            let line = masked[..pos].bytes().filter(|&c| c == b'\n').count() + 1;
            if test.contains(&line) {
                continue;
            }
            let Some((open, close)) = fn_body_span(&masked, pos) else {
                continue;
            };
            let body: String = masked[open..close].split_whitespace().collect();
            if BLOB_WRITE_TOKENS.iter().any(|t| body.contains(t)) {
                count += 1;
            }
        }
        if count > 0 {
            actual.insert(rel, count);
        }
    }

    let expected: BTreeMap<String, usize> =
        allow.iter().map(|(k, v)| (k.to_string(), *v)).collect();

    if actual != expected {
        let mut diff = String::new();
        for (k, v) in &expected {
            match actual.get(k) {
                Some(a) if a == v => {}
                Some(a) => diff.push_str(&format!("  {k}: allowlist={v} actual={a}\n")),
                None => diff.push_str(&format!(
                    "  {k}: allowlist={v} actual=0 (route streamed — shrink RAW_BODY_BLOB_ALLOWLIST)\n"
                )),
            }
        }
        for (k, a) in &actual {
            if !expected.contains_key(k) {
                diff.push_str(&format!(
                    "  {k}: allowlist=<absent> actual={a} (new buffered blob-upload route)\n"
                ));
            }
        }
        panic!(
            "`body: Bytes` blob-upload routes no longer match the allowlist (PF-005, #2517).\n\
             A handler that takes `body: Bytes` AND writes that body to storage in the same fn \
             buffers the whole artifact in memory. Convert it to the streaming staging primitives \
             (`stage_stream_content_addressed` + `upload_stream_with_sync_options` / \
             `put_artifact_stream`) and shrink the list; or — if the body is genuinely small and \
             bounded — add it with a justification.\n{diff}"
        );
    }
}
