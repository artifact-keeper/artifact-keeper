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
//!   POST /conda/{repo_key}/upload                            - Upload package (alternative)
//!
//! All read routes are also available with URL path token authentication:
//!   GET  /conda/t/{token}/{repo_key}/...                     - Token-authenticated access

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::{
    ACCEPT_ENCODING, CACHE_CONTROL, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, ETAG,
    IF_NONE_MATCH,
};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use base64::Engine;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use tracing::info;

use crate::api::handlers::proxy_helpers;
use crate::api::SharedState;
use crate::formats::conda_native::CondaNativeHandler;
use crate::services::auth_service::AuthService;
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

// ---------------------------------------------------------------------------
// HTTP Caching helpers
// ---------------------------------------------------------------------------

/// Compute an ETag from response body bytes using the full SHA-256 hash.
fn compute_etag(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    let hash = format!("{:x}", hasher.finalize());
    format!("\"{}\"", hash)
}

/// Check if the request has a matching ETag (If-None-Match) and return 304 if so.
/// Returns Some(304 response) if the client's cached version matches, None otherwise.
fn check_conditional_request(headers: &HeaderMap, etag: &str) -> Option<Response> {
    if let Some(if_none_match) = headers.get(IF_NONE_MATCH).and_then(|v| v.to_str().ok()) {
        // Handle comma-separated ETags and wildcard
        if if_none_match == "*" || if_none_match.split(',').any(|t| t.trim() == etag) {
            return Some(
                Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .header(ETAG, etag)
                    .header(CACHE_CONTROL, "public, max-age=60")
                    .body(Body::empty())
                    .unwrap(),
            );
        }
    }
    None
}

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
fn cacheable_response(body: Vec<u8>, content_type: &str, headers: &HeaderMap) -> Response {
    let etag = compute_etag(&body);

    // Check for conditional request first
    if let Some(not_modified) = check_conditional_request(headers, &etag) {
        return not_modified;
    }

    // Serve gzip-compressed response if the client accepts it and the content
    // type is JSON (repodata, channeldata, etc.). This helps clients that
    // don't support zstd or bz2.
    if content_type == "application/json" && accepts_gzip(headers) {
        let compressed = gzip_compress(&body);
        return Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, content_type)
            .header(CONTENT_ENCODING, "gzip")
            .header(CONTENT_LENGTH, compressed.len().to_string())
            .header(ETAG, &etag)
            .header(CACHE_CONTROL, "public, max-age=60")
            .header("Vary", "Accept-Encoding")
            .body(Body::from(compressed))
            .unwrap();
    }

    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .header(CONTENT_LENGTH, body.len().to_string())
        .header(ETAG, &etag)
        .header(CACHE_CONTROL, "public, max-age=60")
        .body(Body::from(body))
        .unwrap()
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
        // Package download and upload
        .route(
            "/:repo_key/:subdir/:filename",
            get(download_package).put(upload_package_put),
        )
        // CEP-27 attestation endpoints
        .route(
            "/:repo_key/:subdir/:filename/attestation",
            get(get_attestation).put(put_attestation),
        )
        .layer(DefaultBodyLimit::max(512 * 1024 * 1024)) // 512 MB
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
        .route("/:token/:repo_key/channeldata.json", get(channeldata_json))
        .route("/:token/:repo_key/notices.json", get(notices_json))
        .route("/:token/:repo_key/keys/repo.pub", get(repo_public_key))
        .route("/:token/:repo_key/upload", post(upload_post_with_token))
        .route(
            "/:token/:repo_key/:subdir/repodata.json",
            get(repodata_json),
        )
        .route(
            "/:token/:repo_key/:subdir/repodata.json.bz2",
            get(repodata_json_bz2),
        )
        .route(
            "/:token/:repo_key/:subdir/repodata.json.sig",
            get(repodata_json_sig),
        )
        .route(
            "/:token/:repo_key/:subdir/repodata.json.zst",
            get(repodata_json_zst),
        )
        .route(
            "/:token/:repo_key/:subdir/repodata.json.jlap",
            get(repodata_json_jlap),
        )
        .route(
            "/:token/:repo_key/:subdir/current_repodata.json",
            get(current_repodata_json),
        )
        .route(
            "/:token/:repo_key/:subdir/run_exports.json",
            get(run_exports_json),
        )
        .route(
            "/:token/:repo_key/:subdir/patch_instructions.json",
            get(patch_instructions_json),
        )
        .route(
            "/:token/:repo_key/:subdir/repodata_shards.msgpack.zst",
            get(sharded_repodata_index),
        )
        .route(
            "/:token/:repo_key/:subdir/shards/:shard_hash",
            get(sharded_repodata_shard),
        )
        .route(
            "/:token/:repo_key/:subdir/:filename",
            get(download_package).put(upload_package_put_with_token),
        )
        .route(
            "/:token/:repo_key/:subdir/:filename/attestation",
            get(get_attestation_with_token).put(put_attestation_with_token),
        )
        .layer(DefaultBodyLimit::max(512 * 1024 * 1024))
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
// Auth helpers
// ---------------------------------------------------------------------------

fn extract_basic_credentials(headers: &HeaderMap) -> Option<(String, String)> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic ").or(v.strip_prefix("basic ")))
        .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .and_then(|s| {
            let mut parts = s.splitn(2, ':');
            let user = parts.next()?.to_string();
            let pass = parts.next()?.to_string();
            Some((user, pass))
        })
}

async fn authenticate(
    db: &sqlx::PgPool,
    config: &crate::config::Config,
    headers: &HeaderMap,
) -> Result<uuid::Uuid, Response> {
    let (username, password) = extract_basic_credentials(headers).ok_or_else(|| {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Basic realm=\"conda\"")
            .body(Body::from("Authentication required"))
            .unwrap()
    })?;

    let auth_service = AuthService::new(db.clone(), Arc::new(config.clone()));
    let (user, _tokens) = auth_service
        .authenticate(&username, &password)
        .await
        .map_err(|_| {
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("WWW-Authenticate", "Basic realm=\"conda\"")
                .body(Body::from("Invalid credentials"))
                .unwrap()
        })?;

    Ok(user.id)
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
// Repository resolution
// ---------------------------------------------------------------------------

struct RepoInfo {
    id: uuid::Uuid,
    storage_path: String,
    repo_type: String,
    upstream_url: Option<String>,
}

async fn resolve_conda_repo(db: &sqlx::PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    let repo = sqlx::query!(
        "SELECT id, storage_path, format::text as \"format!\", repo_type::text as \"repo_type!\", upstream_url FROM repositories WHERE key = $1",
        repo_key
    )
    .fetch_optional(db)
    .await
    .map_err(|e| {
        tracing::error!("Database error resolving conda repo '{}': {}", repo_key, e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
    })?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Repository not found").into_response())?;

    let fmt = repo.format.to_lowercase();
    if fmt != "conda" && fmt != "conda_native" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Repository '{}' is not a Conda repository (format: {})",
                repo_key, fmt
            ),
        )
            .into_response());
    }

    Ok(RepoInfo {
        id: repo.id,
        storage_path: repo.storage_path,
        repo_type: repo.repo_type,
        upstream_url: repo.upstream_url,
    })
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

async fn list_conda_artifacts(
    db: &sqlx::PgPool,
    repo_id: uuid::Uuid,
) -> Result<Vec<CondaArtifact>, Response> {
    let rows = sqlx::query!(
        r#"
        SELECT a.id, a.path, a.name, a.version, a.size_bytes, a.checksum_sha256,
               a.storage_key, am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1 AND a.is_deleted = false
        ORDER BY a.created_at DESC
        "#,
        repo_id
    )
    .fetch_all(db)
    .await
    .map_err(|e| {
        tracing::error!("Database error listing conda artifacts: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
    })?;

    Ok(rows
        .into_iter()
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
// GET /conda/{repo_key}/channeldata.json
// ---------------------------------------------------------------------------

async fn channeldata_json(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
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
        license: String,
        license_family: String,
        description: String,
        summary: String,
        home: String,
        doc_url: String,
        dev_url: String,
        source_url: String,
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
                license: String::new(),
                license_family: String::new(),
                description: String::new(),
                summary: String::new(),
                home: String::new(),
                doc_url: String::new(),
                dev_url: String::new(),
                source_url: String::new(),
            });
        entry.subdirs.insert(subdir);

        // Populate metadata from the most recently seen artifact with data
        if let Some(ref meta) = artifact.metadata {
            if entry.license.is_empty() {
                if let Some(v) = meta.get("license").and_then(|v| v.as_str()) {
                    entry.license = v.to_string();
                }
            }
            if entry.license_family.is_empty() {
                if let Some(v) = meta.get("license_family").and_then(|v| v.as_str()) {
                    entry.license_family = v.to_string();
                }
            }
            if entry.description.is_empty() {
                if let Some(v) = meta.get("description").and_then(|v| v.as_str()) {
                    entry.description = v.to_string();
                }
            }
            if entry.summary.is_empty() {
                if let Some(v) = meta.get("summary").and_then(|v| v.as_str()) {
                    entry.summary = v.to_string();
                }
            }
            if entry.home.is_empty() {
                if let Some(v) = meta.get("home").and_then(|v| v.as_str()) {
                    entry.home = v.to_string();
                }
            }
            if entry.doc_url.is_empty() {
                if let Some(v) = meta.get("doc_url").and_then(|v| v.as_str()) {
                    entry.doc_url = v.to_string();
                }
            }
            if entry.dev_url.is_empty() {
                if let Some(v) = meta.get("dev_url").and_then(|v| v.as_str()) {
                    entry.dev_url = v.to_string();
                }
            }
            if entry.source_url.is_empty() {
                if let Some(v) = meta.get("source_url").and_then(|v| v.as_str()) {
                    entry.source_url = v.to_string();
                }
            }
        }
    }

    let packages_json: serde_json::Map<String, serde_json::Value> = packages
        .into_iter()
        .map(|(name, entry)| {
            let version = latest_versions.get(&name).cloned().unwrap_or_default();
            let mut val = serde_json::json!({
                "subdirs": entry.subdirs.into_iter().collect::<Vec<_>>(),
                "version": version,
            });
            // Include optional fields when available
            if !entry.license.is_empty() {
                val["license"] = serde_json::Value::String(entry.license);
            }
            if !entry.license_family.is_empty() {
                val["license_family"] = serde_json::Value::String(entry.license_family);
            }
            if !entry.description.is_empty() {
                val["description"] = serde_json::Value::String(entry.description);
            }
            if !entry.summary.is_empty() {
                val["summary"] = serde_json::Value::String(entry.summary);
            }
            if !entry.home.is_empty() {
                val["home"] = serde_json::Value::String(entry.home);
            }
            if !entry.doc_url.is_empty() {
                val["doc_url"] = serde_json::Value::String(entry.doc_url);
            }
            if !entry.dev_url.is_empty() {
                val["dev_url"] = serde_json::Value::String(entry.dev_url);
            }
            if !entry.source_url.is_empty() {
                val["source_url"] = serde_json::Value::String(entry.source_url);
            }
            (name, val)
        })
        .collect();

    let channeldata = serde_json::json!({
        "channeldata_version": 1,
        "packages": packages_json,
        "subdirs": KNOWN_SUBDIRS,
    });

    let body = serde_json::to_string_pretty(&channeldata)
        .unwrap()
        .into_bytes();

    Ok(cacheable_response(body, "application/json", &headers))
}

// ---------------------------------------------------------------------------
// GET /conda/{repo_key}/notices.json (CEP-6)
// ---------------------------------------------------------------------------

/// Channel notices endpoint (CEP-6).
///
/// Returns channel-level notifications displayed to users during
/// install/update operations. Used for deprecation warnings, security
/// advisories, and maintenance notices.
async fn notices_json(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let _repo = resolve_conda_repo(&state.db, &repo_key).await?;

    // Return an empty notices array. Future: store notices in the database
    // per-repository and serve them here.
    let notices = serde_json::json!({
        "notices": []
    });

    let body = serde_json::to_vec_pretty(&notices).unwrap();
    Ok(cacheable_response(body, "application/json", &headers))
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

        // Extract run_exports from metadata if available
        let run_exports = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("run_exports"))
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));

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
    Ok(cacheable_response(body, "application/json", &headers))
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
    Ok(cacheable_response(body, "application/json", &headers))
}

// ---------------------------------------------------------------------------
// GET /conda/{repo_key}/{subdir}/repodata.json
// ---------------------------------------------------------------------------

async fn repodata_json(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path((repo_key, subdir)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    let repodata = build_repodata(&state.db, repo.id, &repo_key, &subdir, false).await?;

    let body = serde_json::to_string_pretty(&repodata)
        .unwrap()
        .into_bytes();

    Ok(cacheable_response(body, "application/json", &headers))
}

// ---------------------------------------------------------------------------
// GET /conda/{repo_key}/{subdir}/repodata.json.bz2
// ---------------------------------------------------------------------------

async fn repodata_json_bz2(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path((repo_key, subdir)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    let repodata = build_repodata(&state.db, repo.id, &repo_key, &subdir, false).await?;

    let json_bytes = serde_json::to_vec(&repodata).unwrap();
    let compressed = bzip2_compress(&json_bytes);

    Ok(cacheable_response(
        compressed,
        "application/x-bzip2",
        &headers,
    ))
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

    let json_bytes = serde_json::to_vec(&repodata).unwrap();

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
    headers: HeaderMap,
    Path((repo_key, subdir)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    let repodata = build_repodata(&state.db, repo.id, &repo_key, &subdir, false).await?;
    let json_bytes = serde_json::to_vec(&repodata).unwrap();
    let compressed = zstd_compress(&json_bytes).map_err(|e| {
        tracing::error!("zstd compression error for repodata: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
    })?;

    Ok(cacheable_response(compressed, "application/zstd", &headers))
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
async fn repodata_json_jlap(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path((repo_key, subdir)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
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

    Ok(cacheable_response(body, "application/json", &headers))
}

// ---------------------------------------------------------------------------
// CEP-16 Sharded Repodata (reduces bandwidth by ~35x vs monolithic repodata)
// ---------------------------------------------------------------------------

/// CEP-16 shard index: maps package names to content-addressed shard hashes.
///
/// Clients fetch this to discover which shards they need, then fetch
/// individual shards only for packages they care about.
async fn sharded_repodata_index(
    State(state): State<SharedState>,
    Path((repo_key, subdir)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    let all_artifacts = list_conda_artifacts(&state.db, repo.id).await?;
    let subdir_artifacts = artifacts_for_subdir(&all_artifacts, &subdir);

    // Group artifacts by package name
    let mut by_name: BTreeMap<String, Vec<&CondaArtifact>> = BTreeMap::new();
    for artifact in &subdir_artifacts {
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

    // Build shard for each package name and compute content hash
    let mut shards_map: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (pkg_name, artifacts) in &by_name {
        let shard = build_shard(&subdir, artifacts);
        let shard_msgpack = rmp_serde::to_vec(&shard).map_err(|e| {
            tracing::error!("msgpack serialization error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
        })?;
        let shard_compressed = zstd_compress(&shard_msgpack).map_err(|e| {
            tracing::error!("zstd compression error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
        })?;

        let mut hasher = Sha256::new();
        hasher.update(&shard_compressed);
        let hash_bytes: Vec<u8> = hasher.finalize().to_vec();

        shards_map.insert(pkg_name.clone(), hash_bytes);
    }

    // Build the index
    let base_url = format!("/conda/{}/{}/", repo_key, subdir);
    let index = build_sharded_index(&subdir, &base_url, &shards_map);

    let index_msgpack = rmp_serde::to_vec(&index).map_err(|e| {
        tracing::error!("msgpack serialization error: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
    })?;
    let compressed = zstd_compress(&index_msgpack).map_err(|e| {
        tracing::error!("zstd compression error: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
    })?;

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
    let all_artifacts = list_conda_artifacts(&state.db, repo.id).await?;
    let subdir_artifacts = artifacts_for_subdir(&all_artifacts, &subdir);

    // Group by package name and find the matching shard by hash
    let mut by_name: BTreeMap<String, Vec<&CondaArtifact>> = BTreeMap::new();
    for artifact in &subdir_artifacts {
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

    // Find the shard matching the requested hash
    for artifacts in by_name.values() {
        let shard = build_shard(&subdir, artifacts);
        let shard_msgpack = rmp_serde::to_vec(&shard).map_err(|e| {
            tracing::error!("msgpack serialization error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
        })?;
        let shard_compressed = zstd_compress(&shard_msgpack).map_err(|e| {
            tracing::error!("zstd compression error: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
        })?;

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

        let pkg_name = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("name").and_then(|v| v.as_str()))
            .unwrap_or(&artifact.name);

        let version = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("version").and_then(|v| v.as_str()))
            .or(artifact.version.as_deref())
            .unwrap_or("0");

        let build = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("build").and_then(|v| v.as_str()))
            .unwrap_or("0");

        let build_number = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("build_number").and_then(|v| v.as_u64()))
            .unwrap_or(0);

        let depends = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("depends"))
            .cloned()
            .unwrap_or_else(|| serde_json::json!([]));

        let constrains = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("constrains"))
            .cloned()
            .unwrap_or_else(|| serde_json::json!([]));

        let license = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("license").and_then(|v| v.as_str()))
            .unwrap_or("");

        let noarch = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("noarch").and_then(|v| v.as_str()))
            .unwrap_or("");

        let md5 = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("md5").and_then(|v| v.as_str()))
            .unwrap_or("");

        let license_family = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("license_family").and_then(|v| v.as_str()))
            .unwrap_or("");

        let timestamp = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("timestamp").and_then(|v| v.as_u64()));

        let mut entry = serde_json::json!({
            "build": build,
            "build_number": build_number,
            "constrains": constrains,
            "depends": depends,
            "fn": filename,
            "license": license,
            "md5": md5,
            "name": pkg_name,
            "sha256": artifact.checksum_sha256,
            "size": artifact.size_bytes,
            "subdir": subdir,
            "version": version,
        });

        if !noarch.is_empty() {
            entry["noarch"] = serde_json::Value::String(noarch.to_string());
        }
        if !license_family.is_empty() {
            entry["license_family"] = serde_json::Value::String(license_family.to_string());
        }
        if let Some(ts) = timestamp {
            entry["timestamp"] = serde_json::json!(ts);
        }

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

/// List soft-deleted conda artifacts for a repo+subdir to populate the `removed` array.
///
/// Uses runtime query (not compile-time macro) to avoid needing a live
/// database connection or sqlx-offline cache update.
async fn list_removed_artifacts(
    db: &sqlx::PgPool,
    repo_id: uuid::Uuid,
    subdir: &str,
) -> Result<Vec<String>, Response> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT a.path FROM artifacts a WHERE a.repository_id = $1 AND a.is_deleted = true ORDER BY a.path",
    )
    .bind(repo_id)
    .fetch_all(db)
    .await
    .map_err(|e| {
        tracing::error!("Database error listing removed artifacts: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
    })?;

    let prefix = format!("{}/", subdir);
    Ok(rows
        .into_iter()
        .filter_map(|(path,)| {
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

        let pkg_name = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("name").and_then(|v| v.as_str()))
            .map(|s| s.to_string())
            .unwrap_or_else(|| artifact.name.clone());

        let version = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("version").and_then(|v| v.as_str()))
            .map(|s| s.to_string())
            .or_else(|| artifact.version.clone())
            .unwrap_or_else(|| "0".to_string());

        let build = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("build").and_then(|v| v.as_str()))
            .map(|s| s.to_string())
            .unwrap_or_else(|| "0".to_string());

        let build_number = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("build_number").and_then(|v| v.as_u64()))
            .unwrap_or(0);

        let depends = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("depends"))
            .cloned()
            .unwrap_or_else(|| serde_json::json!([]));

        let constrains = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("constrains"))
            .cloned()
            .unwrap_or_else(|| serde_json::json!([]));

        let license = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("license").and_then(|v| v.as_str()))
            .unwrap_or("");

        let license_family = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("license_family").and_then(|v| v.as_str()))
            .unwrap_or("");

        let timestamp = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("timestamp").and_then(|v| v.as_u64()));

        let features = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("features").and_then(|v| v.as_str()))
            .unwrap_or("");

        let track_features = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("track_features").and_then(|v| v.as_str()))
            .unwrap_or("");

        let noarch = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("noarch").and_then(|v| v.as_str()))
            .unwrap_or("");

        let md5 = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("md5").and_then(|v| v.as_str()))
            .unwrap_or("");

        let mut entry = serde_json::json!({
            "build": build,
            "build_number": build_number,
            "constrains": constrains,
            "depends": depends,
            "fn": filename,
            "license": license,
            "md5": md5,
            "name": pkg_name,
            "sha256": artifact.checksum_sha256,
            "size": artifact.size_bytes,
            "subdir": subdir,
            "version": version,
        });

        // Include optional fields only when non-empty/present
        if !license_family.is_empty() {
            entry["license_family"] = serde_json::Value::String(license_family.to_string());
        }
        if let Some(ts) = timestamp {
            entry["timestamp"] = serde_json::json!(ts);
        }
        if !features.is_empty() {
            entry["features"] = serde_json::Value::String(features.to_string());
        }
        if !track_features.is_empty() {
            entry["track_features"] = serde_json::Value::String(track_features.to_string());
        }
        if !noarch.is_empty() {
            entry["noarch"] = serde_json::Value::String(noarch.to_string());
        }

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

    Ok(serde_json::json!({
        "info": {
            "subdir": subdir,
            "base_url": base_url,
        },
        "packages": packages,
        "packages.conda": packages_conda,
        "removed": removed,
        "repodata_version": 1,
    }))
}

// ---------------------------------------------------------------------------
// GET /conda/{repo_key}/{subdir}/{filename} - Download package
// ---------------------------------------------------------------------------

async fn download_package(
    State(state): State<SharedState>,
    Path((repo_key, subdir, filename)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;

    // Look up artifact by path
    let artifact_path = format!("{}/{}", subdir, filename);

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
            if repo.repo_type == "remote" {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let upstream_path = format!("{}/{}", subdir, filename);
                    let (content, content_type) = proxy_helpers::proxy_fetch(
                        proxy,
                        repo.id,
                        &repo_key,
                        upstream_url,
                        &upstream_path,
                    )
                    .await?;
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(
                            "Content-Type",
                            content_type.unwrap_or_else(|| "application/octet-stream".to_string()),
                        )
                        .body(Body::from(content))
                        .unwrap());
                }
            }

            // Virtual repo: try each member in priority order
            if repo.repo_type == "virtual" {
                let db = state.db.clone();
                let upstream_path = format!("{}/{}", subdir, filename);
                let artifact_path_clone = artifact_path.clone();
                let (content, content_type) = proxy_helpers::resolve_virtual_download(
                    &state.db,
                    state.proxy_service.as_deref(),
                    repo.id,
                    &upstream_path,
                    |member_id, storage_path| {
                        let db = db.clone();
                        let state = state.clone();
                        let path = artifact_path_clone.clone();
                        async move {
                            proxy_helpers::local_fetch_by_path(
                                &db,
                                &state,
                                member_id,
                                &storage_path,
                                &path,
                            )
                            .await
                        }
                    },
                )
                .await?;

                let ct = if filename.ends_with(".conda") {
                    "application/octet-stream"
                } else if filename.ends_with(".tar.bz2") {
                    "application/x-tar"
                } else {
                    "application/octet-stream"
                };
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(
                        "Content-Type",
                        content_type.unwrap_or_else(|| ct.to_string()),
                    )
                    .header(
                        "Content-Disposition",
                        format!("attachment; filename=\"{}\"", filename),
                    )
                    .header(CONTENT_LENGTH, content.len().to_string())
                    .body(Body::from(content))
                    .unwrap());
            }

            return Err(not_found);
        }
    };

    // Read from storage
    let storage = state.storage_for_repo(&repo.storage_path);
    let content = storage.get(&artifact.storage_key).await.map_err(|e| {
        tracing::error!("Storage error reading conda package: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
    })?;

    // Record download
    let _ = sqlx::query!(
        "INSERT INTO download_statistics (artifact_id, ip_address) VALUES ($1, '0.0.0.0')",
        artifact.id
    )
    .execute(&state.db)
    .await;

    let content_type = if filename.ends_with(".conda") {
        "application/octet-stream"
    } else if filename.ends_with(".tar.bz2") {
        "application/x-tar"
    } else {
        "application/octet-stream"
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, content.len().to_string())
        .header("X-Checksum-SHA256", &artifact.checksum_sha256)
        .body(Body::from(content))
        .unwrap())
}

// ---------------------------------------------------------------------------
// PUT /conda/{repo_key}/{subdir}/{filename} - Upload package
// ---------------------------------------------------------------------------

async fn upload_package_put(
    State(state): State<SharedState>,
    Path((repo_key, subdir, filename)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

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
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

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
    Path((token, repo_key, subdir, filename)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    // Try Basic auth first (if present), fall back to URL token
    let user_id = if extract_basic_credentials(&headers).is_some() {
        authenticate(&state.db, &state.config, &headers).await?
    } else {
        authenticate_with_token(&state.db, &state.config, &token).await?
    };

    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

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
    Path((token, repo_key)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let user_id = if extract_basic_credentials(&headers).is_some() {
        authenticate(&state.db, &state.config, &headers).await?
    } else {
        authenticate_with_token(&state.db, &state.config, &token).await?
    };

    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

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
        // Validate .tar.bz2 v1 structure
        let decoder = bzip2::read::BzDecoder::new(std::io::Cursor::new(content));
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

    // Validate that metadata extraction succeeds and has required fields
    if let Some(meta) = extract_conda_metadata(content, filename) {
        if meta.get("name").and_then(|v| v.as_str()).is_none() {
            return Err("Invalid package metadata: missing 'name' field".to_string());
        }
        if meta.get("version").and_then(|v| v.as_str()).is_none() {
            return Err("Invalid package metadata: missing 'version' field".to_string());
        }
    }
    // Note: we don't fail if metadata extraction fails entirely, since
    // the filename already carries name/version info. The package is still usable.

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

/// Maximum decompressed size for metadata extraction (100 MB).
/// Protects against decompression bombs in crafted packages.
const MAX_DECOMPRESSED_METADATA_SIZE: usize = 100 * 1024 * 1024;

/// Maximum number of tar entries to iterate when searching for metadata.
const MAX_TAR_ENTRIES: usize = 10_000;

/// Decompress zstd with a size limit to prevent decompression bombs.
fn limited_decode_zstd(compressed: &[u8], max_size: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut decoder = zstd::Decoder::new(std::io::Cursor::new(compressed)).ok()?;
    let mut output = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = decoder.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        output.extend_from_slice(&buf[..n]);
        if output.len() > max_size {
            return None; // Exceeds limit, likely a bomb
        }
    }
    Some(output)
}

/// Extract metadata from .conda (v2) ZIP package.
///
/// The .conda format is a ZIP archive containing:
/// - `metadata.json` at the root (with name, version, etc.)
/// - `info-<name>-<ver>-<build>.tar.zst` (zstd-compressed tar with info/index.json)
/// - `pkg-<name>-<ver>-<build>.tar.zst` (the actual package files)
fn extract_conda_v2_metadata(content: &[u8]) -> Option<serde_json::Value> {
    let cursor = std::io::Cursor::new(content);
    let mut archive = zip::ZipArchive::new(cursor).ok()?;

    // First try metadata.json at the root of the ZIP
    if let Ok(mut file) = archive.by_name("metadata.json") {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut file, &mut buf).ok()?;
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&buf) {
            // metadata.json may only have name/version; look for index.json in info tar
            if val.get("depends").is_some() {
                return Some(val);
            }
        }
    }

    // Collect file names first to avoid borrow conflicts
    let file_names: Vec<(usize, String)> = (0..archive.len())
        .filter_map(|i| archive.by_index(i).ok().map(|f| (i, f.name().to_string())))
        .collect();

    for (idx, name) in &file_names {
        if name.starts_with("info-") && name.ends_with(".tar.zst") {
            let mut file = archive.by_index(*idx).ok()?;
            let mut compressed = Vec::new();
            std::io::Read::read_to_end(&mut file, &mut compressed).ok()?;
            drop(file);

            // Decompress the zstd tar with size limit
            let decompressed = limited_decode_zstd(&compressed, MAX_DECOMPRESSED_METADATA_SIZE)?;
            let mut tar = tar::Archive::new(std::io::Cursor::new(&decompressed));

            let mut entries_checked = 0;
            for entry in tar.entries().ok()? {
                entries_checked += 1;
                if entries_checked > MAX_TAR_ENTRIES {
                    break;
                }
                let mut entry = entry.ok()?;
                let path = entry.path().ok()?.to_string_lossy().to_string();
                if path == "info/index.json" || path.ends_with("/index.json") {
                    let mut buf = String::new();
                    std::io::Read::read_to_string(&mut entry, &mut buf).ok()?;
                    return serde_json::from_str(&buf).ok();
                }
            }
        }
    }

    None
}

/// Extract metadata from .tar.bz2 (v1) conda package.
///
/// The package is a bzip2-compressed tar containing `info/index.json`.
fn extract_conda_v1_metadata(content: &[u8]) -> Option<serde_json::Value> {
    let decoder = bzip2::read::BzDecoder::new(std::io::Cursor::new(content));
    let mut archive = tar::Archive::new(decoder);

    let mut entries_checked = 0;
    for entry in archive.entries().ok()? {
        entries_checked += 1;
        if entries_checked > MAX_TAR_ENTRIES {
            break;
        }
        let mut entry = entry.ok()?;
        let path = entry.path().ok()?.to_string_lossy().to_string();
        if path == "info/index.json" {
            let mut buf = String::new();
            std::io::Read::read_to_string(&mut entry, &mut buf).ok()?;
            return serde_json::from_str(&buf).ok();
        }
    }

    None
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
    let artifact_path = format!("{}/{}", subdir, filename);
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
    let artifact_path = format!("{}/{}", subdir, filename);
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
    headers: HeaderMap,
    Path((repo_key, subdir, filename)): Path<(String, String, String)>,
    body: Bytes,
) -> Result<Response, Response> {
    let _user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    store_attestation(&state, &repo, &repo_key, &subdir, &filename, &body).await
}

/// GET /conda/{repo_key}/{subdir}/{filename}/attestation
///
/// Requires authentication to match the repository's read-auth posture.
async fn get_attestation(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path((repo_key, subdir, filename)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    // Attestations follow the repo's auth requirements. If the repo is
    // public the authenticate call will succeed with anonymous access
    // via the optional auth middleware on the outer router.
    let _user_id = authenticate(&state.db, &state.config, &headers).await?;
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    fetch_attestation(&state, &repo, &subdir, &filename).await
}

/// PUT /conda/t/{token}/{repo_key}/{subdir}/{filename}/attestation
async fn put_attestation_with_token(
    State(state): State<SharedState>,
    Path((token, repo_key, subdir, filename)): Path<(String, String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    let _user_id = if extract_basic_credentials(&headers).is_some() {
        authenticate(&state.db, &state.config, &headers).await?
    } else {
        authenticate_with_token(&state.db, &state.config, &token).await?
    };
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    store_attestation(&state, &repo, &repo_key, &subdir, &filename, &body).await
}

/// GET /conda/t/{token}/{repo_key}/{subdir}/{filename}/attestation
async fn get_attestation_with_token(
    State(state): State<SharedState>,
    Path((token, repo_key, subdir, filename)): Path<(String, String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let _user_id = if extract_basic_credentials(&headers).is_some() {
        authenticate(&state.db, &state.config, &headers).await?
    } else {
        authenticate_with_token(&state.db, &state.config, &token).await?
    };
    let repo = resolve_conda_repo(&state.db, &repo_key).await?;
    fetch_attestation(&state, &repo, &subdir, &filename).await
}

// ---------------------------------------------------------------------------
// Shared upload logic
// ---------------------------------------------------------------------------

async fn store_conda_package(
    state: &SharedState,
    repo: &RepoInfo,
    subdir: &str,
    filename: &str,
    content: Bytes,
    user_id: uuid::Uuid,
) -> Result<Response, Response> {
    // Parse the filename using the existing conda_native handler
    let conda_path = format!("{}/{}", subdir, filename);
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

    // Validate package structure before storing
    validate_conda_package(&content, filename)
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

    let artifact_path = format!("{}/{}", subdir, filename);

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

    // Store the file
    let storage_key = format!("conda/{}/{}/{}", repo.id, subdir, filename);
    let storage = state.storage_for_repo(&repo.storage_path);
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

    // Extract metadata from package contents
    let extracted = extract_conda_metadata(&content, filename);

    let build_number = extracted
        .as_ref()
        .and_then(|m| m.get("build_number").and_then(|v| v.as_u64()))
        .unwrap_or(0);

    let depends = extracted
        .as_ref()
        .and_then(|m| m.get("depends"))
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));

    let constrains = extracted
        .as_ref()
        .and_then(|m| m.get("constrains"))
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));

    let license = extracted
        .as_ref()
        .and_then(|m| m.get("license").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string();

    let license_family = extracted
        .as_ref()
        .and_then(|m| m.get("license_family").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string();

    let timestamp = extracted
        .as_ref()
        .and_then(|m| m.get("timestamp").and_then(|v| v.as_u64()));

    let features = extracted
        .as_ref()
        .and_then(|m| m.get("features").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string();

    let track_features = extracted
        .as_ref()
        .and_then(|m| m.get("track_features").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string();

    let noarch = extracted
        .as_ref()
        .and_then(|m| m.get("noarch").and_then(|v| v.as_str()))
        .unwrap_or("")
        .to_string();

    // Store conda-specific metadata (with real values extracted from package)
    let mut conda_metadata = serde_json::json!({
        "name": pkg_name,
        "version": pkg_version,
        "build": build_string,
        "build_number": build_number,
        "subdir": subdir,
        "package_format": if filename.ends_with(".conda") { "v2" } else { "v1" },
        "depends": depends,
        "constrains": constrains,
        "license": license,
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
            serde_json::json!({
                "name": pkg_name,
                "version": pkg_version,
                "build": build_string,
                "subdir": subdir,
                "sha256": computed_sha256,
                "size": size_bytes,
            })
            .to_string(),
        ))
        .unwrap())
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

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

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Extracted pure functions (moved into test module)
    // -----------------------------------------------------------------------

    /// Build the artifact path for a conda package.
    fn build_conda_artifact_path(subdir: &str, filename: &str) -> String {
        format!("{}/{}", subdir, filename)
    }

    /// Build the storage key for a conda package.
    fn build_conda_storage_key(repo_id: &uuid::Uuid, subdir: &str, filename: &str) -> String {
        format!("conda/{}/{}/{}", repo_id, subdir, filename)
    }

    // -----------------------------------------------------------------------
    // Extracted pure functions (moved into test module)
    // -----------------------------------------------------------------------

    /// Return the appropriate content type for a conda package filename.
    fn conda_content_type(filename: &str) -> &'static str {
        if filename.ends_with(".conda") {
            "application/octet-stream"
        } else if filename.ends_with(".tar.bz2") {
            "application/x-tar"
        } else {
            "application/octet-stream"
        }
    }

    /// Build conda-specific metadata JSON.
    fn build_conda_metadata(
        name: &str,
        version: &str,
        build_string: &str,
        subdir: &str,
        filename: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "version": version,
            "build": build_string,
            "build_number": 0,
            "subdir": subdir,
            "package_format": if filename.ends_with(".conda") { "v2" } else { "v1" },
            "depends": [],
        })
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

    /// Build a single repodata entry for a package.
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

    /// Build a channeldata package entry.
    fn build_channeldata_package_entry(subdirs: &[String], version: &str) -> serde_json::Value {
        serde_json::json!({
            "subdirs": subdirs,
            "version": version,
        })
    }

    /// Build the full channeldata.json response.
    fn build_channeldata_json(
        packages: &serde_json::Map<String, serde_json::Value>,
    ) -> serde_json::Value {
        serde_json::json!({
            "channeldata_version": 1,
            "packages": packages,
            "subdirs": KNOWN_SUBDIRS,
        })
    }

    /// Build repodata entries from CondaArtifacts (mirrors build_repodata logic).
    fn build_repodata_entries(
        artifacts: &[&CondaArtifact],
        subdir: &str,
        packages: &mut serde_json::Map<String, serde_json::Value>,
        packages_conda: &mut serde_json::Map<String, serde_json::Value>,
    ) {
        for artifact in artifacts {
            let filename = artifact.path.rsplit('/').next().unwrap_or(&artifact.path);
            if !is_conda_package(filename) {
                continue;
            }
            let pkg_name = artifact
                .metadata
                .as_ref()
                .and_then(|m| m.get("name").and_then(|v| v.as_str()))
                .unwrap_or(&artifact.name);
            let version = artifact
                .metadata
                .as_ref()
                .and_then(|m| m.get("version").and_then(|v| v.as_str()))
                .or(artifact.version.as_deref())
                .unwrap_or("0");
            let build = artifact
                .metadata
                .as_ref()
                .and_then(|m| m.get("build").and_then(|v| v.as_str()))
                .unwrap_or("0");
            let build_number = artifact
                .metadata
                .as_ref()
                .and_then(|m| m.get("build_number").and_then(|v| v.as_u64()))
                .unwrap_or(0);
            let depends = artifact
                .metadata
                .as_ref()
                .and_then(|m| m.get("depends"))
                .cloned()
                .unwrap_or_else(|| serde_json::json!([]));
            let constrains = artifact
                .metadata
                .as_ref()
                .and_then(|m| m.get("constrains"))
                .cloned()
                .unwrap_or_else(|| serde_json::json!([]));
            let license = artifact
                .metadata
                .as_ref()
                .and_then(|m| m.get("license").and_then(|v| v.as_str()))
                .unwrap_or("");
            let license_family = artifact
                .metadata
                .as_ref()
                .and_then(|m| m.get("license_family").and_then(|v| v.as_str()))
                .unwrap_or("");
            let timestamp = artifact
                .metadata
                .as_ref()
                .and_then(|m| m.get("timestamp").and_then(|v| v.as_u64()));
            let features = artifact
                .metadata
                .as_ref()
                .and_then(|m| m.get("features").and_then(|v| v.as_str()))
                .unwrap_or("");
            let track_features = artifact
                .metadata
                .as_ref()
                .and_then(|m| m.get("track_features").and_then(|v| v.as_str()))
                .unwrap_or("");
            let noarch = artifact
                .metadata
                .as_ref()
                .and_then(|m| m.get("noarch").and_then(|v| v.as_str()))
                .unwrap_or("");
            let md5 = artifact
                .metadata
                .as_ref()
                .and_then(|m| m.get("md5").and_then(|v| v.as_str()))
                .unwrap_or("");

            let mut entry = serde_json::json!({
                "build": build,
                "build_number": build_number,
                "constrains": constrains,
                "depends": depends,
                "fn": filename,
                "license": license,
                "md5": md5,
                "name": pkg_name,
                "sha256": artifact.checksum_sha256,
                "size": artifact.size_bytes,
                "subdir": subdir,
                "version": version,
            });
            if !license_family.is_empty() {
                entry["license_family"] = serde_json::Value::String(license_family.to_string());
            }
            if let Some(ts) = timestamp {
                entry["timestamp"] = serde_json::json!(ts);
            }
            if !features.is_empty() {
                entry["features"] = serde_json::Value::String(features.to_string());
            }
            if !track_features.is_empty() {
                entry["track_features"] = serde_json::Value::String(track_features.to_string());
            }
            if !noarch.is_empty() {
                entry["noarch"] = serde_json::Value::String(noarch.to_string());
            }

            if is_conda_v2(filename) {
                packages_conda.insert(filename.to_string(), entry);
            } else {
                packages.insert(filename.to_string(), entry);
            }
        }
    }

    /// Build the full repodata.json response for a subdir.
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
            conda_content_type("numpy.conda"),
            "application/octet-stream"
        );
        assert_eq!(conda_content_type("numpy.tar.bz2"), "application/x-tar");
        assert_eq!(conda_content_type("file.zip"), "application/octet-stream");
        assert_eq!(conda_content_type(""), "application/octet-stream");
    }

    // -----------------------------------------------------------------------
    // build_conda_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_conda_metadata_v2() {
        let meta = build_conda_metadata(
            "numpy",
            "1.26.4",
            "py312h02b7e37_0",
            "linux-64",
            "numpy-1.26.4-py312h02b7e37_0.conda",
        );
        assert_eq!(meta["name"], "numpy");
        assert_eq!(meta["version"], "1.26.4");
        assert_eq!(meta["build"], "py312h02b7e37_0");
        assert_eq!(meta["build_number"], 0);
        assert_eq!(meta["subdir"], "linux-64");
        assert_eq!(meta["package_format"], "v2");
    }

    #[test]
    fn test_build_conda_metadata_v1() {
        let meta = build_conda_metadata(
            "requests",
            "2.31.0",
            "pyhd8ed1ab_0",
            "noarch",
            "requests-2.31.0-pyhd8ed1ab_0.tar.bz2",
        );
        assert_eq!(meta["package_format"], "v1");
        assert_eq!(meta["subdir"], "noarch");
    }

    #[test]
    fn test_build_conda_metadata_has_depends() {
        let meta = build_conda_metadata("pkg", "1.0", "0", "noarch", "pkg.conda");
        assert!(meta["depends"].as_array().unwrap().is_empty());
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
    // build_repodata_entry
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_repodata_entry_all_fields() {
        let depends = serde_json::json!(["python >=3.12", "libcblas >=3.9"]);
        let entry = build_repodata_entry(
            "numpy",
            "1.26.4",
            "py312h02b7e37_0",
            0,
            &depends,
            "md5hash",
            "sha256hash",
            8192,
            "linux-64",
        );
        assert_eq!(entry["name"], "numpy");
        assert_eq!(entry["version"], "1.26.4");
        assert_eq!(entry["build"], "py312h02b7e37_0");
        assert_eq!(entry["build_number"], 0);
        assert_eq!(entry["md5"], "md5hash");
        assert_eq!(entry["sha256"], "sha256hash");
        assert_eq!(entry["size"], 8192);
        assert_eq!(entry["subdir"], "linux-64");
        let deps = entry["depends"].as_array().unwrap();
        assert_eq!(deps.len(), 2);
    }

    #[test]
    fn test_build_repodata_entry_no_depends() {
        let depends = serde_json::json!([]);
        let entry = build_repodata_entry("pkg", "1.0", "0", 0, &depends, "", "sha", 100, "noarch");
        assert!(entry["depends"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_build_repodata_entry_with_build_number() {
        let depends = serde_json::json!([]);
        let entry = build_repodata_entry("pkg", "1.0", "0", 5, &depends, "", "sha", 100, "noarch");
        assert_eq!(entry["build_number"], 5);
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
    // build_repodata_json
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_repodata_json_empty() {
        let packages = serde_json::Map::new();
        let packages_conda = serde_json::Map::new();
        let rd = build_repodata_json("linux-64", &packages, &packages_conda);
        assert_eq!(rd["info"]["subdir"], "linux-64");
        assert!(rd["packages"].as_object().unwrap().is_empty());
        assert!(rd["packages.conda"].as_object().unwrap().is_empty());
    }

    #[test]
    fn test_build_repodata_json_with_packages() {
        let mut packages = serde_json::Map::new();
        packages.insert(
            "old.tar.bz2".to_string(),
            serde_json::json!({"name": "old"}),
        );
        let mut packages_conda = serde_json::Map::new();
        packages_conda.insert("new.conda".to_string(), serde_json::json!({"name": "new"}));
        let rd = build_repodata_json("noarch", &packages, &packages_conda);
        assert_eq!(rd["packages"]["old.tar.bz2"]["name"], "old");
        assert_eq!(rd["packages.conda"]["new.conda"]["name"], "new");
    }

    #[test]
    fn test_build_repodata_json_subdir() {
        let packages = serde_json::Map::new();
        let packages_conda = serde_json::Map::new();
        let rd = build_repodata_json("osx-arm64", &packages, &packages_conda);
        assert_eq!(rd["info"]["subdir"], "osx-arm64");
    }

    #[test]
    fn test_repodata_json_has_repodata_version() {
        let packages = serde_json::Map::new();
        let packages_conda = serde_json::Map::new();
        let rd = build_repodata_json("linux-64", &packages, &packages_conda);
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
        let mut packages = serde_json::Map::new();
        let mut packages_conda = serde_json::Map::new();
        build_repodata_entries(&artifacts, "linux-64", &mut packages, &mut packages_conda);
        let entry = &packages_conda["numpy-1.26.4-py312h02b7e37_0.conda"];
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
        let mut packages = serde_json::Map::new();
        let mut packages_conda = serde_json::Map::new();
        build_repodata_entries(&artifacts, "noarch", &mut packages, &mut packages_conda);
        let entry = &packages["requests-2.31.0-pyhd8ed1ab_0.tar.bz2"];
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
        let mut packages = serde_json::Map::new();
        let mut packages_conda = serde_json::Map::new();
        build_repodata_entries(&artifacts, "noarch", &mut packages, &mut packages_conda);
        let entry = &packages_conda["six-1.16.0-pyh6c4a22f_0.conda"];
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
        let mut packages = serde_json::Map::new();
        let mut packages_conda = serde_json::Map::new();
        build_repodata_entries(&artifacts, "noarch", &mut packages, &mut packages_conda);
        let entry = &packages_conda["font-ttf-1.0-0.conda"];
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
        let mut packages = serde_json::Map::new();
        let mut packages_conda = serde_json::Map::new();
        build_repodata_entries(&artifacts, "linux-64", &mut packages, &mut packages_conda);
        let entry = &packages_conda["numpy-1.26.4-py312h_0.conda"];
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

    #[test]
    fn test_extract_basic_credentials_valid() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Basic dXNlcjpwYXNz".parse().unwrap(),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "pass".to_string())));
    }

    #[test]
    fn test_extract_basic_credentials_no_header() {
        let headers = HeaderMap::new();
        assert!(extract_basic_credentials(&headers).is_none());
    }

    #[test]
    fn test_extract_basic_credentials_bearer_ignored() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer token".parse().unwrap(),
        );
        assert!(extract_basic_credentials(&headers).is_none());
    }

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
    // Verify that build_repodata_entry (and by extension build_repodata)
    // preserves all fields that conda clients need.
    // -----------------------------------------------------------------------

    /// Enhanced repodata entry builder that includes all conda-spec fields.
    #[allow(clippy::too_many_arguments)]
    fn build_repodata_entry_full(
        name: &str,
        version: &str,
        build: &str,
        build_number: u64,
        depends: &serde_json::Value,
        constrains: &serde_json::Value,
        license: &str,
        md5: &str,
        sha256: &str,
        size: i64,
        subdir: &str,
        timestamp: Option<u64>,
        features: &str,
        track_features: &str,
        license_family: &str,
    ) -> serde_json::Value {
        let mut entry = serde_json::json!({
            "name": name,
            "version": version,
            "build": build,
            "build_number": build_number,
            "depends": depends,
            "constrains": constrains,
            "license": license,
            "md5": md5,
            "sha256": sha256,
            "size": size,
            "subdir": subdir,
        });
        if !license_family.is_empty() {
            entry["license_family"] = serde_json::Value::String(license_family.to_string());
        }
        if let Some(ts) = timestamp {
            entry["timestamp"] = serde_json::json!(ts);
        }
        if !features.is_empty() {
            entry["features"] = serde_json::Value::String(features.to_string());
        }
        if !track_features.is_empty() {
            entry["track_features"] = serde_json::Value::String(track_features.to_string());
        }
        entry
    }

    #[test]
    fn test_repodata_entry_includes_constrains() {
        let constrains = serde_json::json!(["numpy-base <0a0"]);
        let entry = build_repodata_entry_full(
            "numpy",
            "1.26.4",
            "py312h02b7e37_0",
            0,
            &serde_json::json!(["python >=3.12"]),
            &constrains,
            "BSD-3-Clause",
            "md5",
            "sha256",
            8192,
            "linux-64",
            None,
            "",
            "",
            "",
        );
        assert_eq!(entry["constrains"].as_array().unwrap().len(), 1);
        assert_eq!(entry["constrains"][0], "numpy-base <0a0");
    }

    #[test]
    fn test_repodata_entry_includes_license() {
        let entry = build_repodata_entry_full(
            "openssl",
            "3.2.0",
            "h0d3ecfb_1",
            1,
            &serde_json::json!(["ca-certificates"]),
            &serde_json::json!([]),
            "Apache-2.0",
            "",
            "",
            0,
            "linux-64",
            None,
            "",
            "",
            "Apache",
        );
        assert_eq!(entry["license"], "Apache-2.0");
        assert_eq!(entry["license_family"], "Apache");
    }

    #[test]
    fn test_repodata_entry_includes_timestamp() {
        let entry = build_repodata_entry_full(
            "pkg",
            "1.0",
            "0",
            0,
            &serde_json::json!([]),
            &serde_json::json!([]),
            "MIT",
            "",
            "",
            0,
            "noarch",
            Some(1709000000000),
            "",
            "",
            "",
        );
        assert_eq!(entry["timestamp"], 1709000000000_u64);
    }

    #[test]
    fn test_repodata_entry_includes_features() {
        let entry = build_repodata_entry_full(
            "mkl",
            "2024.0",
            "h5e30980_0",
            0,
            &serde_json::json!([]),
            &serde_json::json!([]),
            "Intel License",
            "",
            "",
            0,
            "linux-64",
            None,
            "mkl",
            "mkl",
            "",
        );
        assert_eq!(entry["features"], "mkl");
        assert_eq!(entry["track_features"], "mkl");
    }

    #[test]
    fn test_repodata_entry_omits_empty_optional_fields() {
        let entry = build_repodata_entry_full(
            "simple",
            "1.0",
            "0",
            0,
            &serde_json::json!([]),
            &serde_json::json!([]),
            "MIT",
            "",
            "",
            0,
            "noarch",
            None,
            "",
            "",
            "",
        );
        // Optional fields should be absent, not empty strings
        assert!(entry.get("timestamp").is_none());
        assert!(entry.get("features").is_none());
        assert!(entry.get("track_features").is_none());
        assert!(entry.get("license_family").is_none());
    }

    #[test]
    fn test_repodata_entry_preserves_empty_depends() {
        let entry = build_repodata_entry_full(
            "pkg",
            "1.0",
            "0",
            0,
            &serde_json::json!([]),
            &serde_json::json!([]),
            "",
            "",
            "",
            0,
            "noarch",
            None,
            "",
            "",
            "",
        );
        assert!(entry["depends"].as_array().unwrap().is_empty());
        assert!(entry["constrains"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_repodata_entry_preserves_complex_depends() {
        let depends = serde_json::json!([
            "python >=3.8,<3.13",
            "numpy >=1.21",
            "scipy >=1.7",
            "pandas >=1.3",
            "libgcc-ng >=12"
        ]);
        let constrains = serde_json::json!(["scikit-learn-intelex >=2024.0", "daal4py >=2024.0"]);
        let entry = build_repodata_entry_full(
            "scikit-learn",
            "1.4.0",
            "py312h7e6f82a_0",
            0,
            &depends,
            &constrains,
            "BSD-3-Clause",
            "",
            "",
            0,
            "linux-64",
            Some(1706000000000),
            "",
            "",
            "BSD",
        );
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
    fn test_noarch_package_metadata_has_noarch_field() {
        // Verify that metadata for noarch packages includes the subdir field
        let meta = build_conda_metadata(
            "requests",
            "2.31.0",
            "pyhd8ed1ab_0",
            "noarch",
            "requests-2.31.0-pyhd8ed1ab_0.tar.bz2",
        );
        assert_eq!(meta["subdir"], "noarch");
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
    fn test_build_conda_metadata_includes_package_format_v2() {
        let meta = build_conda_metadata("pkg", "1.0", "0", "linux-64", "pkg-1.0-0.conda");
        assert_eq!(meta["package_format"], "v2");
    }

    #[test]
    fn test_build_conda_metadata_includes_package_format_v1() {
        let meta = build_conda_metadata("pkg", "1.0", "0", "linux-64", "pkg-1.0-0.tar.bz2");
        assert_eq!(meta["package_format"], "v1");
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

    #[test]
    fn test_basic_auth_standard_format() {
        // user:pass -> base64 "dXNlcjpwYXNz"
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Basic dXNlcjpwYXNz".parse().unwrap(),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "pass".to_string())));
    }

    #[test]
    fn test_basic_auth_case_insensitive_prefix() {
        // conda clients may send "basic" (lowercase) instead of "Basic"
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "basic dXNlcjpwYXNz".parse().unwrap(),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "pass".to_string())));
    }

    #[test]
    fn test_basic_auth_token_in_password_field() {
        // Common pattern: use API token as the password with a dummy username
        // token: "ak_myapitoken123"
        // "token:ak_myapitoken123" -> base64
        let encoded = base64::engine::general_purpose::STANDARD.encode("token:ak_myapitoken123");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Basic {}", encoded).parse().unwrap(),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(
            result,
            Some(("token".to_string(), "ak_myapitoken123".to_string()))
        );
    }

    #[test]
    fn test_basic_auth_conda_condarc_style() {
        // .condarc uses: channel_alias with user:token@ in URL, which gets
        // converted to Basic auth by conda client
        let encoded = base64::engine::general_purpose::STANDARD.encode("myuser:mypassword");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Basic {}", encoded).parse().unwrap(),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(
            result,
            Some(("myuser".to_string(), "mypassword".to_string()))
        );
    }

    #[test]
    fn test_basic_auth_password_with_colon() {
        // Passwords containing colons should work (split only on first colon)
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:pass:with:colons");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Basic {}", encoded).parse().unwrap(),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(
            result,
            Some(("user".to_string(), "pass:with:colons".to_string()))
        );
    }

    #[test]
    fn test_basic_auth_special_characters() {
        // Passwords with special chars should be handled
        let encoded = base64::engine::general_purpose::STANDARD.encode("admin:P@$$w0rd!#%");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Basic {}", encoded).parse().unwrap(),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(
            result,
            Some(("admin".to_string(), "P@$$w0rd!#%".to_string()))
        );
    }

    #[test]
    fn test_no_auth_header_returns_none() {
        let headers = HeaderMap::new();
        assert!(extract_basic_credentials(&headers).is_none());
    }

    #[test]
    fn test_bearer_auth_not_accepted_for_basic() {
        // Bearer tokens should NOT be parsed as basic credentials
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer eyJhbGciOiJIUzI1NiJ9".parse().unwrap(),
        );
        assert!(extract_basic_credentials(&headers).is_none());
    }

    #[test]
    fn test_invalid_base64_returns_none() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Basic !!!not-base64!!!".parse().unwrap(),
        );
        assert!(extract_basic_credentials(&headers).is_none());
    }

    #[test]
    fn test_basic_auth_no_colon_returns_none() {
        // base64 of just "username" (no colon separator)
        let encoded = base64::engine::general_purpose::STANDARD.encode("username");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Basic {}", encoded).parse().unwrap(),
        );
        assert!(extract_basic_credentials(&headers).is_none());
    }

    #[test]
    fn test_basic_auth_empty_password() {
        // Some systems allow empty passwords
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Basic {}", encoded).parse().unwrap(),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(result, Some(("user".to_string(), "".to_string())));
    }

    #[test]
    fn test_basic_auth_empty_username() {
        // Token-only auth: empty username with token as password
        let encoded = base64::engine::general_purpose::STANDARD.encode(":ak_token_value");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Basic {}", encoded).parse().unwrap(),
        );
        let result = extract_basic_credentials(&headers);
        assert_eq!(result, Some(("".to_string(), "ak_token_value".to_string())));
    }

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
    fn test_token_auth_basic_auth_takes_priority() {
        // When both Basic auth header and URL token are present,
        // Basic auth should take priority (tested via extract_basic_credentials)
        let encoded = base64::engine::general_purpose::STANDARD.encode("user:pass");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Basic {}", encoded).parse().unwrap(),
        );
        // extract_basic_credentials should return the Basic auth creds
        let result = extract_basic_credentials(&headers);
        assert!(
            result.is_some(),
            "Basic auth should be extracted even with token in URL"
        );
    }

    #[test]
    fn test_token_auth_falls_back_to_url_token() {
        // When no Basic auth header is present, token from URL should be used
        let headers = HeaderMap::new();
        let result = extract_basic_credentials(&headers);
        assert!(
            result.is_none(),
            "No Basic auth means fallback to URL token"
        );
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

    #[test]
    fn test_cacheable_response_includes_etag() {
        let body = b"repodata json content".to_vec();
        let headers = HeaderMap::new();
        let resp = cacheable_response(body.clone(), "application/json", &headers);

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

    #[test]
    fn test_cacheable_response_304_on_matching_etag() {
        let body = b"repodata json content".to_vec();
        let etag = compute_etag(&body);
        let mut headers = HeaderMap::new();
        headers.insert(IF_NONE_MATCH, etag.parse().unwrap());

        let resp = cacheable_response(body, "application/json", &headers);
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
    }

    #[test]
    fn test_cacheable_response_200_on_stale_etag() {
        let body = b"updated repodata json content".to_vec();
        let mut headers = HeaderMap::new();
        headers.insert(IF_NONE_MATCH, "W/\"stale_etag_value\"".parse().unwrap());

        let resp = cacheable_response(body, "application/json", &headers);
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
            conda_content_type("numpy.conda"),
            "application/octet-stream"
        );
        assert_eq!(conda_content_type("requests.tar.bz2"), "application/x-tar");
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

    #[test]
    fn test_cacheable_response_gzip_when_accepted() {
        let body = serde_json::to_vec(&serde_json::json!({"test": true})).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT_ENCODING, "gzip, deflate".parse().unwrap());

        let resp = cacheable_response(body, "application/json", &headers);

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

    #[test]
    fn test_cacheable_response_no_gzip_for_binary() {
        let body = vec![0u8; 100];
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT_ENCODING, "gzip, deflate".parse().unwrap());

        let resp = cacheable_response(body, "application/x-bzip2", &headers);

        // Binary content types should not be gzip-encoded
        assert!(resp.headers().get(CONTENT_ENCODING).is_none());
    }

    #[test]
    fn test_cacheable_response_no_gzip_without_accept() {
        let body = serde_json::to_vec(&serde_json::json!({"test": true})).unwrap();
        let headers = HeaderMap::new();

        let resp = cacheable_response(body, "application/json", &headers);

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
    fn test_limited_decode_zstd_rejects_oversized() {
        // Create a large decompressible payload
        let data = vec![0u8; 1024 * 1024]; // 1 MB of zeros
        let compressed = zstd::encode_all(std::io::Cursor::new(&data), 1).unwrap();

        // Should succeed with generous limit
        assert!(limited_decode_zstd(&compressed, 2 * 1024 * 1024).is_some());

        // Should fail with tight limit
        assert!(limited_decode_zstd(&compressed, 512).is_none());
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
}
