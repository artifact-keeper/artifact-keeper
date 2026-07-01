//! Maven 2 Repository Layout handlers.
//!
//! Implements the path-based Maven repository layout for `mvn deploy` and
//! `mvn dependency:resolve`.
//!
//! Routes are mounted at `/maven/{repo_key}/...`:
//!   GET  /maven/{repo_key}      — Repository root probe (proxy/group → upstream root; hosted → 404)
//!   GET  /maven/{repo_key}/*path — Download artifact, metadata, or checksum
//!   PUT  /maven/{repo_key}/*path — Upload artifact (mvn deploy)

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Extension;
use axum::Router;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::{info, warn};

use crate::api::handlers::error_helpers::{map_db_err, map_storage_err};
use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::SharedState;
use crate::error::AppError;
use crate::formats::maven::{generate_metadata_xml, MavenCoordinates, MavenHandler};
use crate::models::repository::RepositoryType;

// TODO: Remaining format handlers (beyond maven, npm, pypi, cargo) still use
// plain-text error responses and should be migrated to AppError (#553).

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Root probe: `/:repo_key/*path` (axum 0.7 wildcard) does NOT match
        // when the path segment after the repo key is empty — i.e. a request
        // for exactly `GET /maven/<repo>/`.  We register the bare key route so
        // proxy and group repos can forward that root probe to their upstream.
        // See download_root for details.  The trailing-slash variant is listed
        // separately because axum treats `/x` and `/x/` as distinct routes.
        .route("/:repo_key", get(download_root))
        .route("/:repo_key/", get(download_root))
        .route("/:repo_key/*path", get(download).put(upload))
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_maven_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["maven", "gradle"], "a Maven").await
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/// Escape SQL LIKE metacharacters in a user-supplied literal so it can be
/// safely concatenated into a LIKE pattern.
///
/// The returned string is intended to be used with an `ESCAPE '\'` clause.
/// Three characters are escaped: the escape character `\` itself (must come
/// first so we do not double-escape escapes we just inserted), the
/// zero-or-more wildcard `%`, and the single-character wildcard `_`.
///
/// Without this, user-controlled segments in artifact paths could inject LIKE
/// wildcards and cause queries to match unrelated artifact rows in the same
/// repository (wrong artifact served, information disclosure).
///
/// Visibility is `pub` (not `pub(crate)`) so that the
/// `tests/security_regression_tests.rs` integration test can reach this
/// helper from outside the crate to verify GHSA-7f39-724h-cccm and
/// GHSA-cxcr-cmqm-6rrw remain fixed.
pub fn escape_like_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' | '%' | '_' => {
                out.push('\\');
                out.push(ch);
            }
            other => out.push(other),
        }
    }
    out
}

/// Given a `-SNAPSHOT` artifact path, build a SQL LIKE pattern that matches
/// the corresponding timestamp-resolved filename stored in the database.
///
/// Example: `com/example/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar`
///       -> `com/example/lib/1.0-SNAPSHOT/lib-1.0-%.jar`
///
/// User-supplied LIKE metacharacters (`%`, `_`, `\`) in the path are escaped
/// so they match literally; only the `%` introduced by this function in place
/// of `-SNAPSHOT` is treated as a wildcard. Callers MUST pair the returned
/// pattern with an `ESCAPE '\'` clause in the SQL query.
///
/// Returns `None` if the path does not contain a `-SNAPSHOT` filename segment.
///
/// Visibility is `pub` (not `pub(crate)`) so the
/// `tests/security_regression_tests.rs` integration test can verify the
/// composed wildcard-escape behavior from outside the crate.
pub fn snapshot_like_pattern(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if parts.len() < 2 {
        return None;
    }
    let filename = parts[parts.len() - 1];
    let version_dir = parts[parts.len() - 2];

    // Only applies when the version directory is a SNAPSHOT version
    if !version_dir.ends_with("-SNAPSHOT") {
        return None;
    }

    // The base version is taken from the request directory and is itself
    // user-controlled, so it must be LIKE-escaped before being interpolated.
    // The `-SNAPSHOT` suffix and the `-%` we introduce ourselves are trusted
    // literals (the `%` is the one and only intentional wildcard).
    let base_version = version_dir.strip_suffix("-SNAPSHOT").unwrap();
    let snapshot_token = format!("{}-SNAPSHOT", base_version);

    if !filename.contains(&snapshot_token) {
        return None;
    }

    // Build the escaped pieces of the resulting pattern. We split on the
    // (un-escaped) snapshot_token first, escape each surrounding fragment of
    // user input, then join with the trusted `-%` wildcard substitute.
    let escaped_base_version = escape_like_literal(base_version);
    let escaped_filename_segments: Vec<String> = filename
        .split(&snapshot_token)
        .map(escape_like_literal)
        .collect();
    let timestamp_wildcard_escaped = format!("{}-%", escaped_base_version);
    let resolved_filename = escaped_filename_segments.join(&timestamp_wildcard_escaped);

    // Every directory segment is also user-controlled and must be escaped.
    let dir = parts[..parts.len() - 1]
        .iter()
        .map(|seg| escape_like_literal(seg))
        .collect::<Vec<_>>()
        .join("/");
    Some(format!("{}/{}", dir, resolved_filename))
}

/// Look up the latest timestamped artifact path matching a SNAPSHOT pattern.
/// Uses a SQL LIKE query to find artifacts stored under timestamp-resolved names
/// when the client requests the `-SNAPSHOT` form.
async fn resolve_snapshot_artifact(
    db: &PgPool,
    repo_id: uuid::Uuid,
    snapshot_path: &str,
) -> Option<ResolvedSnapshot> {
    let pattern = snapshot_like_pattern(snapshot_path)?;

    // Use runtime sqlx::query (not the query! macro) to avoid needing an
    // offline cache entry. The LIKE pattern matches timestamped filenames
    // and we pick the latest one by created_at.
    //
    // `pattern` is built by `snapshot_like_pattern`, which escapes any LIKE
    // metacharacters (`%`, `_`, `\`) coming from user input so only the
    // intentional `%` in place of `-SNAPSHOT` acts as a wildcard. The
    // `ESCAPE '\'` clause makes that contract explicit to PostgreSQL.
    let row = sqlx::query(
        r#"
        SELECT id, storage_key, checksum_sha256, path
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND path LIKE $2 ESCAPE '\'
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(repo_id)
    .bind(&pattern)
    .fetch_optional(db)
    .await
    .ok()??;

    use sqlx::Row;
    Some(ResolvedSnapshot {
        storage_key: row.get("storage_key"),
        checksum_sha256: row.get("checksum_sha256"),
        path: row.get("path"),
    })
}

struct ResolvedSnapshot {
    storage_key: String,
    checksum_sha256: String,
    path: String,
}

/// Collect all stored timestamped SNAPSHOT files in a specific version directory
/// for a given member repository. Returns the parsed `SnapshotEntry`s ready to
/// feed into [`generate_snapshot_metadata_xml`].
async fn collect_snapshot_entries(
    db: &PgPool,
    repo_id: uuid::Uuid,
    group_id: &str,
    artifact_id: &str,
    version: &str,
) -> Vec<SnapshotEntry> {
    // Build the directory path: com/example/my-lib/1.0-SNAPSHOT/
    // group_id, artifact_id and version are all derived from the user's
    // request path, so each segment must be LIKE-escaped before we append the
    // trailing `%` directory wildcard. Without escaping, an attacker could
    // inject `%` or `_` (e.g., a `version` of `1.0-SNAPSHOT_evil`) to enumerate
    // unrelated artifacts in the same repository.
    let group_path = escape_like_literal(&group_id.replace('.', "/"));
    let dir_prefix = format!(
        "{}/{}/{}/",
        group_path,
        escape_like_literal(artifact_id),
        escape_like_literal(version)
    );
    let like_pattern = format!("{}%", dir_prefix);

    // Fetch every artifact under that version directory. We do NOT restrict the
    // filename to timestamp-bearing forms here; the extractor below ignores any
    // filenames that don't match the expected pattern.
    let rows = match sqlx::query(
        r#"
        SELECT path
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND path LIKE $2 ESCAPE '\'
        "#,
    )
    .bind(repo_id)
    .bind(&like_pattern)
    .fetch_all(db)
    .await
    {
        Ok(rows) => rows,
        Err(_) => return Vec::new(),
    };

    use sqlx::Row;
    let base_version = match version.strip_suffix("-SNAPSHOT") {
        Some(v) => v,
        None => return Vec::new(),
    };

    let mut entries: Vec<SnapshotEntry> = Vec::new();
    for row in rows {
        let path: String = row.get("path");
        // Only files directly inside the version directory contribute.
        let filename = match path.rsplit('/').next() {
            Some(f) => f,
            None => continue,
        };
        if let Some(info) = extract_snapshot_info_from_filename(filename, artifact_id, base_version)
        {
            entries.push(SnapshotEntry {
                classifier: info.classifier,
                extension: info.extension,
                timestamp: info.timestamp,
                build_number: info.build_number,
            });
        }
    }
    entries
}

fn checksum_suffix(ct: ChecksumType) -> &'static str {
    match ct {
        ChecksumType::Md5 => "md5",
        ChecksumType::Sha1 => "sha1",
        ChecksumType::Sha256 => "sha256",
        ChecksumType::Sha512 => "sha512",
    }
}

/// Maven-specific fallback for [`proxy_helpers::local_fetch_by_path`] that
/// resolves a `-SNAPSHOT` filename alias to the latest timestamped artifact.
///
/// Returns the same shape as `local_fetch_by_path` so it can be dropped into
/// the `resolve_virtual_download` callback.
async fn maven_local_fetch_snapshot(
    db: &PgPool,
    state: &SharedState,
    repo_id: uuid::Uuid,
    location: &crate::storage::StorageLocation,
    path: &str,
) -> Result<proxy_helpers::StreamingFetchResult, Response> {
    if !path.contains("-SNAPSHOT") {
        return Err((StatusCode::NOT_FOUND, "Artifact not found").into_response());
    }

    let resolved = resolve_snapshot_artifact(db, repo_id, path)
        .await
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Artifact not found").into_response())?;

    let storage = state.storage_for_repo_or_500(location)?;
    let stream = storage
        .get_stream(&resolved.storage_key)
        .await
        .map_err(map_storage_err)?;

    let ct = content_type_for_path(path).to_string();
    Ok(proxy_helpers::StreamingFetchResult {
        body: stream,
        content_type: Some(ct),
        content_length: None,
    })
}

// ---------------------------------------------------------------------------
// Pure (non-async) helper functions for testability
// ---------------------------------------------------------------------------

/// Determine if a Maven path is for artifact-level metadata (groupId/artifactId level).
/// Returns (groupId, artifactId) if the path ends with maven-metadata.xml AND the
/// segment before it is an artifactId (not a version).
///
/// Version-level metadata (groupId/artifactId/version/maven-metadata.xml) returns None
/// so the caller can serve it from storage instead of generating it dynamically.
fn parse_metadata_path(path: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    // Minimum: groupSegment/artifactId/maven-metadata.xml
    if parts.len() < 3 {
        return None;
    }
    let filename = parts[parts.len() - 1];
    if filename != "maven-metadata.xml" {
        return None;
    }
    let candidate = parts[parts.len() - 2];
    // If the segment before maven-metadata.xml looks like a version, this is
    // version-level metadata (e.g. .../1.0.0-SNAPSHOT/maven-metadata.xml).
    // Return None so the download handler serves it from storage.
    if looks_like_maven_version(candidate) {
        return None;
    }
    let artifact_id = candidate.to_string();
    let group_id = parts[..parts.len() - 2].join(".");
    Some((group_id, artifact_id))
}

/// Heuristic: Maven versions start with a digit (1.0.0, 2.0-rc1, 3.12.0-SNAPSHOT).
/// Artifact IDs practically never start with a digit.
fn looks_like_maven_version(s: &str) -> bool {
    s.starts_with(|c: char| c.is_ascii_digit())
}

/// Parse a SNAPSHOT version-level metadata path and return (groupId, artifactId, version).
///
/// Example: `com/example/my-lib/1.0-SNAPSHOT/maven-metadata.xml`
///       -> `Some(("com.example", "my-lib", "1.0-SNAPSHOT"))`
///
/// Returns `None` for non-SNAPSHOT version paths and for artifact-level metadata paths.
fn parse_snapshot_metadata_path(path: &str) -> Option<(String, String, String)> {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    // Minimum: groupSegment/artifactId/version/maven-metadata.xml
    if parts.len() < 4 {
        return None;
    }
    if parts[parts.len() - 1] != "maven-metadata.xml" {
        return None;
    }
    let version = parts[parts.len() - 2];
    if !version.ends_with("-SNAPSHOT") {
        return None;
    }
    let artifact_id = parts[parts.len() - 3].to_string();
    let group_id = parts[..parts.len() - 3].join(".");
    Some((group_id, artifact_id, version.to_string()))
}

/// Information extracted from a timestamped SNAPSHOT filename.
///
/// Example: filename `mylib-1.0-20260101.120000-3-sources.jar`
///   with base version `1.0` ->
/// `SnapshotFileInfo { timestamp: "20260101.120000", build_number: 3,
///                     classifier: Some("sources"), extension: "jar" }`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SnapshotFileInfo {
    timestamp: String,
    build_number: u32,
    classifier: Option<String>,
    extension: String,
}

/// Parse a timestamped SNAPSHOT filename to extract its snapshot components.
///
/// The expected form is `{artifactId}-{baseVersion}-{YYYYMMDD.HHMMSS}-{N}[-{classifier}].{extension}`.
/// Returns `None` if the filename does not match this pattern.
fn extract_snapshot_info_from_filename(
    filename: &str,
    artifact_id: &str,
    base_version: &str,
) -> Option<SnapshotFileInfo> {
    // Strip the extension (handle common compound extensions like tar.gz).
    let (stem, extension) = if let Some(stem) = filename.strip_suffix(".tar.gz") {
        (stem, "tar.gz".to_string())
    } else {
        let dot = filename.rfind('.')?;
        (&filename[..dot], filename[dot + 1..].to_string())
    };

    // Strip the `{artifactId}-{baseVersion}-` prefix.
    let prefix = format!("{}-{}-", artifact_id, base_version);
    let rest = stem.strip_prefix(&prefix)?;

    // Now rest is `{YYYYMMDD.HHMMSS}-{N}` or `{YYYYMMDD.HHMMSS}-{N}-{classifier}`.
    // Find the timestamp segment: must contain exactly one '.' and be 15 chars (8.6).
    let mut segments = rest.splitn(3, '-');
    let ts = segments.next()?;
    let build_str = segments.next()?;
    let classifier = segments.next().map(|s| s.to_string());

    // Validate the timestamp looks like YYYYMMDD.HHMMSS.
    if ts.len() != 15 || ts.as_bytes().get(8) != Some(&b'.') {
        return None;
    }
    if !ts.bytes().enumerate().all(|(i, b)| {
        if i == 8 {
            b == b'.'
        } else {
            b.is_ascii_digit()
        }
    }) {
        return None;
    }

    let build_number: u32 = build_str.parse().ok()?;

    Some(SnapshotFileInfo {
        timestamp: ts.to_string(),
        build_number,
        classifier,
        extension,
    })
}

/// A resolved snapshot file descriptor used when building snapshot metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SnapshotEntry {
    /// Classifier, if any (e.g. "sources", "javadoc").
    classifier: Option<String>,
    /// Extension without the leading dot (e.g. "jar", "pom", "tar.gz").
    extension: String,
    /// Timestamp string in `YYYYMMDD.HHMMSS` form.
    timestamp: String,
    /// Build number for the snapshot.
    build_number: u32,
}

/// Build the `value` field for a snapshotVersion entry: `{baseVersion}-{timestamp}-{N}`.
fn snapshot_version_value(base_version: &str, entry: &SnapshotEntry) -> String {
    format!(
        "{}-{}-{}",
        base_version, entry.timestamp, entry.build_number
    )
}

/// Parse `<snapshotVersion>` elements out of a SNAPSHOT maven-metadata.xml.
///
/// The parser is intentionally lightweight (string-splitting) to match the
/// style of [`parse_metadata_versions`] elsewhere in the code base.
fn parse_snapshot_versions_xml(xml: &str) -> Vec<SnapshotEntry> {
    let mut out = Vec::new();
    let snapshot_versions_block = match xml
        .split("<snapshotVersions>")
        .nth(1)
        .and_then(|s| s.split("</snapshotVersions>").next())
    {
        Some(block) => block,
        None => return out,
    };

    for segment in snapshot_versions_block.split("<snapshotVersion>").skip(1) {
        let item = match segment.split("</snapshotVersion>").next() {
            Some(i) => i,
            None => continue,
        };
        let extension = item
            .split("<extension>")
            .nth(1)
            .and_then(|s| s.split("</extension>").next())
            .map(|s| s.trim().to_string());
        let value = item
            .split("<value>")
            .nth(1)
            .and_then(|s| s.split("</value>").next())
            .map(|s| s.trim().to_string());
        let classifier = item
            .split("<classifier>")
            .nth(1)
            .and_then(|s| s.split("</classifier>").next())
            .map(|s| s.trim().to_string());

        let (Some(ext), Some(val)) = (extension, value) else {
            continue;
        };

        // Value is `{baseVersion}-{timestamp}-{buildNumber}`. The timestamp is
        // a 15-char `YYYYMMDD.HHMMSS` segment. The base version itself may
        // contain dots (`1.0`, `1.2.3`), so we must scan for a timestamp-
        // shaped segment bounded by `-` on both sides rather than anchoring
        // on the first `.`.
        let bytes = val.as_bytes();
        let mut parsed: Option<(String, u32)> = None;
        for ts_start in 0..val.len().saturating_sub(15) {
            // Must be preceded by `-` (timestamp follows the base version).
            if ts_start == 0 || bytes[ts_start - 1] != b'-' {
                continue;
            }
            let ts_end = ts_start + 15;
            if ts_end >= val.len() {
                break;
            }
            // Must be YYYYMMDD.HHMMSS then `-`.
            if bytes[ts_end] != b'-' {
                continue;
            }
            let ts = &val[ts_start..ts_end];
            let shape_ok = ts.bytes().enumerate().all(|(i, b)| {
                if i == 8 {
                    b == b'.'
                } else {
                    b.is_ascii_digit()
                }
            });
            if !shape_ok {
                continue;
            }
            let Ok(build_number) = val[ts_end + 1..].parse::<u32>() else {
                continue;
            };
            parsed = Some((ts.to_string(), build_number));
            break;
        }
        let Some((timestamp, build_number)) = parsed else {
            continue;
        };

        out.push(SnapshotEntry {
            classifier,
            extension: ext,
            timestamp,
            build_number,
        });
    }
    out
}

/// Generate `maven-metadata.xml` for a SNAPSHOT version folder.
///
/// `version` is the `-SNAPSHOT` alias (e.g. `1.0-SNAPSHOT`). `entries` is the set
/// of (classifier, extension, timestamp, buildNumber) triples found for this folder
/// across one or more member repos. Only the latest timestamp/buildNumber wins
/// inside the top-level `<snapshot>` block; all entries are listed under
/// `<snapshotVersions>`.
fn generate_snapshot_metadata_xml(
    group_id: &str,
    artifact_id: &str,
    version: &str,
    entries: &[SnapshotEntry],
) -> Option<String> {
    if entries.is_empty() {
        return None;
    }
    let base_version = version.strip_suffix("-SNAPSHOT")?;

    // Pick the latest (timestamp, buildNumber) for the top-level snapshot block.
    // Ordering is lexicographic on timestamp then numeric on build_number.
    let latest = entries
        .iter()
        .max_by(|a, b| {
            a.timestamp
                .cmp(&b.timestamp)
                .then(a.build_number.cmp(&b.build_number))
        })
        .unwrap();

    // Deduplicate entries: keep the latest (timestamp, buildNumber) per
    // (classifier, extension) key. Same logical file may appear in multiple
    // member repos; the most recent wins.
    let mut dedup: std::collections::BTreeMap<(Option<String>, String), SnapshotEntry> =
        std::collections::BTreeMap::new();
    for e in entries {
        let key = (e.classifier.clone(), e.extension.clone());
        dedup
            .entry(key)
            .and_modify(|existing| {
                if (e.timestamp.as_str(), e.build_number)
                    > (existing.timestamp.as_str(), existing.build_number)
                {
                    *existing = e.clone();
                }
            })
            .or_insert_with(|| e.clone());
    }

    let last_updated = latest.timestamp.replace('.', "");

    let mut snapshot_versions = String::new();
    for entry in dedup.values() {
        let value = snapshot_version_value(base_version, entry);
        let classifier_line = match &entry.classifier {
            Some(c) => format!("        <classifier>{}</classifier>\n", c),
            None => String::new(),
        };
        let updated = entry.timestamp.replace('.', "");
        snapshot_versions.push_str(&format!(
            "      <snapshotVersion>\n\
{classifier_line}        <extension>{ext}</extension>\n        <value>{value}</value>\n        <updated>{updated}</updated>\n      </snapshotVersion>\n",
            ext = entry.extension,
            value = value,
            updated = updated,
            classifier_line = classifier_line,
        ));
    }

    Some(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>{group_id}</groupId>
  <artifactId>{artifact_id}</artifactId>
  <version>{version}</version>
  <versioning>
    <snapshot>
      <timestamp>{timestamp}</timestamp>
      <buildNumber>{build_number}</buildNumber>
    </snapshot>
    <lastUpdated>{last_updated}</lastUpdated>
    <snapshotVersions>
{snapshot_versions}    </snapshotVersions>
  </versioning>
</metadata>
"#,
        group_id = group_id,
        artifact_id = artifact_id,
        version = version,
        timestamp = latest.timestamp,
        build_number = latest.build_number,
        last_updated = last_updated,
        snapshot_versions = snapshot_versions,
    ))
}

/// Check if a path is a checksum request. Returns the base path and checksum type.
fn parse_checksum_path(path: &str) -> Option<(&str, ChecksumType)> {
    if let Some(base) = path.strip_suffix(".sha512") {
        Some((base, ChecksumType::Sha512))
    } else if let Some(base) = path.strip_suffix(".sha256") {
        Some((base, ChecksumType::Sha256))
    } else if let Some(base) = path.strip_suffix(".sha1") {
        Some((base, ChecksumType::Sha1))
    } else if let Some(base) = path.strip_suffix(".md5") {
        Some((base, ChecksumType::Md5))
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy)]
enum ChecksumType {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

fn content_type_for_path(path: &str) -> &'static str {
    if path.ends_with(".pom") || path.ends_with(".xml") {
        "text/xml"
    } else if path.ends_with(".jar") || path.ends_with(".war") || path.ends_with(".ear") {
        "application/java-archive"
    } else if path.ends_with(".asc") {
        "text/plain"
    } else {
        "application/octet-stream"
    }
}

// ---------------------------------------------------------------------------
// GET /maven/{repo_key}  (and /maven/{repo_key}/) — Repository root probe
// ---------------------------------------------------------------------------

/// Handle a request for the repository root — i.e. `GET /maven/<repo>/` with
/// no artifact path after the repo key.
///
/// In axum 0.7 the wildcard segment `*path` in `/:repo_key/*path` does NOT
/// match when the trailing segment is empty (just a `/`).  That means the
/// route that serves ordinary artifact downloads never fires for the bare root
/// URL, and the framework falls back to a generic 404.  This handler fills
/// the gap by explicitly matching `/:repo_key` (and `/:repo_key/`).
///
/// Behaviour by repo type:
/// * **Remote (proxy)**: forward the request to the upstream root URL
///   (`<upstream_url>` with no path appended) and return whatever the upstream
///   returns.  The response is cached under the sentinel path `"_root_"` so
///   repeated probes are served from cache without hitting the upstream.
/// * **Virtual (group)**: walk members in priority order; return the upstream
///   root from the first Remote member that responds successfully.
/// * **Local / Staging**: return 404 — hosted repos have no upstream to
///   forward to, so there is no meaningful root content to serve.
///
/// This makes `GET /maven/<proxy-repo>/` consistent with every other path
/// against the same repo (which all proxy transparently).  Tools that probe
/// `<registry>/` to verify credentials or check repo existence now work
/// correctly for Maven proxy and group repos.  Fixes #1880.
async fn download_root(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    let repo = resolve_maven_repo(&state.db, &repo_key).await?;

    if repo.repo_type == RepositoryType::Remote {
        if let (Some(ref upstream_url), Some(ref proxy)) =
            (&repo.upstream_url, &state.proxy_service)
        {
            // Build the minimal Repository value that ProxyService needs.
            // fetch_artifact_with_cache_path(fetch_path="", cache_path="_root_")
            // fetches `upstream_url + ""` = upstream root and stores the result
            // under the non-empty sentinel key "_root_" to satisfy the cache-
            // path validation that rejects empty strings.
            let remote = proxy_helpers::build_remote_repo(repo.id, &repo_key, upstream_url);
            let (content, content_type) = proxy
                .fetch_artifact_with_cache_path(&remote, "", "_root_")
                .await
                .map_err(|e| e.into_response())?;
            let ct = content_type.unwrap_or_else(|| "text/html".to_string());
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, ct)
                .header(CONTENT_LENGTH, content.len().to_string())
                .body(Body::from(content))
                .unwrap());
        }
    }

    if repo.repo_type == RepositoryType::Virtual {
        let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
        for member in &members {
            if member.repo_type == RepositoryType::Remote {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&member.upstream_url, &state.proxy_service)
                {
                    let remote =
                        proxy_helpers::build_remote_repo(member.id, &member.key, upstream_url);
                    if let Ok((content, content_type)) = proxy
                        .fetch_artifact_with_cache_path(&remote, "", "_root_")
                        .await
                    {
                        let ct = content_type.unwrap_or_else(|| "text/html".to_string());
                        return Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header(CONTENT_TYPE, ct)
                            .header(CONTENT_LENGTH, content.len().to_string())
                            .body(Body::from(content))
                            .unwrap());
                    }
                }
            }
        }
    }

    Err(AppError::NotFound("Repository root not available".to_string()).into_response())
}

// ---------------------------------------------------------------------------
// GET /maven/{repo_key}/*path — Download artifact/metadata/checksum
// ---------------------------------------------------------------------------

async fn download(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, path)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_maven_repo(&state.db, &repo_key).await?;
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;

    // 1. Check if this is a checksum request for metadata.
    //    Always compute the checksum from the actual metadata XML bytes
    //    so the result is guaranteed to match what this same URL returns
    //    for the base maven-metadata.xml request — regardless of whether
    //    the repo is local, remote, or virtual (with merge).
    if let Some((base_path, checksum_type)) = parse_checksum_path(&path) {
        if MavenHandler::is_metadata(base_path) {
            let content =
                fetch_maven_metadata_bytes(&state, &repo, &repo_key, base_path, auth.as_ref())
                    .await?;
            let checksum = compute_checksum(&content, checksum_type);
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "text/plain")
                .body(Body::from(checksum))
                .unwrap());
        }
    }

    // 2. Check if this is a maven-metadata.xml request
    if MavenHandler::is_metadata(&path) {
        let content =
            fetch_maven_metadata_bytes(&state, &repo, &repo_key, &path, auth.as_ref()).await?;
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/xml")
            .header(CONTENT_LENGTH, content.len().to_string())
            .body(Body::from(content))
            .unwrap());
    }

    // 3. Check if this is a checksum request for a stored file
    if let Some((base_path, checksum_type)) = parse_checksum_path(&path) {
        // First try to find a stored checksum file
        let checksum_storage_key = format!("maven/{}", path);
        if let Ok(content) = storage.get(&checksum_storage_key).await {
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "text/plain")
                .body(Body::from(content))
                .unwrap());
        }

        // If this is a SNAPSHOT path, try the stored checksum under the
        // timestamp-resolved filename before falling through to compute.
        if base_path.contains("-SNAPSHOT") {
            if let Some(resolved) = resolve_snapshot_artifact(&state.db, repo.id, base_path).await {
                let resolved_checksum_key =
                    format!("maven/{}.{}", resolved.path, checksum_suffix(checksum_type));
                if let Ok(content) = storage.get(&resolved_checksum_key).await {
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, "text/plain")
                        .body(Body::from(content))
                        .unwrap());
                }
            }
        }

        // Compute checksum from locally-stored artifact (Local/Staging only).
        // Remote repos cache artifacts in the proxy cache, not the `artifacts`
        // table, so the DB lookup inside serve_computed_checksum always fails.
        if checksum_compute_eligible(&repo.repo_type) {
            if let Ok(response) = serve_computed_checksum(
                &state,
                repo.id,
                &repo.storage_location(),
                base_path,
                checksum_type,
            )
            .await
            {
                return Ok(response);
            }
        }

        // Fallback: proxy the checksum file from upstream for remote repos
        if repo.repo_type == RepositoryType::Remote {
            if let (Some(ref upstream_url), Some(ref proxy)) =
                (&repo.upstream_url, &state.proxy_service)
            {
                let (content, _content_type) =
                    proxy_helpers::proxy_fetch(proxy, repo.id, &repo_key, upstream_url, &path)
                        .await?;
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "text/plain")
                    .body(Body::from(content))
                    .unwrap());
            }
        }

        // Virtual repo: try each member in priority order
        if repo.repo_type == RepositoryType::Virtual {
            // #1804: only members the caller could read directly may serve a
            // checksum. A private member's checksum reveals the existence and
            // exact content hash of its artifact, so it must be gated the same
            // way the artifact bytes are.
            let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
            let members = proxy_helpers::authorize_virtual_members(
                &state.permission_service,
                auth.as_ref(),
                members,
            )
            .await;

            for member in &members {
                if member.repo_type == RepositoryType::Remote {
                    // Remote member: proxy checksum from upstream directly.
                    // serve_computed_checksum always fails — proxy-cached
                    // artifacts are NOT in the `artifacts` table (#1280).
                    if let (Some(ref upstream_url), Some(ref proxy)) =
                        (&member.upstream_url, &state.proxy_service)
                    {
                        if let Ok((content, _)) = proxy_helpers::proxy_fetch(
                            proxy,
                            member.id,
                            &member.key,
                            upstream_url,
                            &path,
                        )
                        .await
                        {
                            return Ok(Response::builder()
                                .status(StatusCode::OK)
                                .header(CONTENT_TYPE, "text/plain")
                                .body(Body::from(content))
                                .unwrap());
                        }
                    }
                } else if member.repo_type.is_hosted() {
                    // Local/Staging member: compute checksum from stored artifact.
                    if let Ok(response) = serve_computed_checksum(
                        &state,
                        member.id,
                        &member.storage_location(),
                        base_path,
                        checksum_type,
                    )
                    .await
                    {
                        return Ok(response);
                    }
                }
            }
        }

        return Err(AppError::NotFound("File not found".to_string()).into_response());
    }

    // 4. Serve the artifact file
    serve_artifact(&state, &repo, &repo_key, &path, auth.as_ref()).await
}

async fn fetch_maven_metadata_bytes(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    path: &str,
    auth: Option<&AuthExtension>,
) -> Result<Bytes, Response> {
    // Remote repos: proxy from upstream. No local storage probe, no dynamic
    // generation — the upstream is the source of truth.
    if repo.repo_type == RepositoryType::Remote {
        if let (Some(ref upstream_url), Some(ref proxy)) =
            (&repo.upstream_url, &state.proxy_service)
        {
            let (content, _) =
                proxy_helpers::proxy_fetch(proxy, repo.id, repo_key, upstream_url, path).await?;
            return Ok(content);
        }
        return Err(AppError::NotFound("Metadata not found".to_string()).into_response());
    }

    // Virtual repos: merge metadata from all members.
    if repo.repo_type == RepositoryType::Virtual {
        let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
        let members =
            proxy_helpers::authorize_virtual_members(&state.permission_service, auth, members)
                .await;

        if let Some((group_id, artifact_id)) = parse_metadata_path(path) {
            let mut all_versions: Vec<String> = Vec::new();

            for member in &members {
                if member.repo_type == RepositoryType::Remote {
                    // Remote members: proxy metadata from upstream directly.
                    if let (Some(upstream_url), Some(ref proxy)) =
                        (member.upstream_url.as_deref(), &state.proxy_service)
                    {
                        if let Ok((content, _)) = proxy_helpers::proxy_fetch(
                            proxy,
                            member.id,
                            &member.key,
                            upstream_url,
                            path,
                        )
                        .await
                        {
                            if let Ok(xml_str) = std::str::from_utf8(&content) {
                                if let Some((_, _, versions)) =
                                    crate::formats::maven::parse_metadata_versions(xml_str)
                                {
                                    all_versions.extend(versions);
                                }
                            }
                        }
                    }
                } else {
                    // Local/Staging members: generate from artifact rows.
                    if let Ok(xml) = generate_metadata_for_artifact(
                        &state.db,
                        member.id,
                        &group_id,
                        &artifact_id,
                    )
                    .await
                    {
                        if let Some((_, _, versions)) =
                            crate::formats::maven::parse_metadata_versions(&xml)
                        {
                            all_versions.extend(versions);
                        }
                    }
                }
            }

            if !all_versions.is_empty() {
                all_versions.sort();
                all_versions.dedup();

                use crate::formats::maven_version;
                let sorted = maven_version::sort_maven_versions(&all_versions);
                let latest = sorted.last().unwrap().clone();
                let release = maven_version::latest_release(&sorted).cloned();

                let xml = generate_metadata_xml(
                    &group_id,
                    &artifact_id,
                    &sorted,
                    &latest,
                    release.as_deref(),
                );

                return Ok(Bytes::from(xml));
            }

            // Group-level plugin-prefix metadata (#1595). A path like
            // `org/apache/maven/plugins/maven-metadata.xml` matches
            // parse_metadata_path but carries <plugins> entries instead of a
            // <versions> block. Collect each member's plugin-prefix metadata
            // and serve the union of <plugin> entries deduped by <prefix>.
            let mut member_docs: Vec<String> = Vec::new();
            for member in &members {
                if member.repo_type == RepositoryType::Remote {
                    // Remote members: fetch from upstream.
                    if let (Some(upstream_url), Some(ref proxy)) =
                        (member.upstream_url.as_deref(), &state.proxy_service)
                    {
                        if let Ok((content, _)) = proxy_helpers::proxy_fetch(
                            proxy,
                            member.id,
                            &member.key,
                            upstream_url,
                            path,
                        )
                        .await
                        {
                            if let Ok(xml_str) = std::str::from_utf8(&content) {
                                member_docs.push(xml_str.to_string());
                            }
                        }
                    }
                } else {
                    // Local/Staging members: try stored metadata file.
                    let member_storage_key = format!("maven/{}", path);
                    if let Ok(member_storage) = state.storage_for_repo(&member.storage_location()) {
                        if let Ok(content) = member_storage.get(&member_storage_key).await {
                            if let Ok(xml_str) = std::str::from_utf8(&content) {
                                member_docs.push(xml_str.to_string());
                            }
                        }
                    }
                }
            }

            if let Some(xml) = crate::formats::maven::merge_plugin_prefix_metadata(&member_docs) {
                return Ok(Bytes::from(xml));
            }
        }

        // Virtual repo: SNAPSHOT version-level metadata (#839).
        // parse_metadata_path returns None for `g/a/v-SNAPSHOT/maven-metadata.xml`
        // paths, so handle those separately.
        if let Some((group_id, artifact_id, version)) = parse_snapshot_metadata_path(path) {
            let mut all_entries: Vec<SnapshotEntry> = Vec::new();

            for member in &members {
                if member.repo_type == RepositoryType::Remote {
                    // Remote members: proxy snapshot metadata from upstream.
                    if let (Some(upstream_url), Some(ref proxy)) =
                        (member.upstream_url.as_deref(), &state.proxy_service)
                    {
                        if let Ok((content, _)) = proxy_helpers::proxy_fetch(
                            proxy,
                            member.id,
                            &member.key,
                            upstream_url,
                            path,
                        )
                        .await
                        {
                            if let Ok(xml_str) = std::str::from_utf8(&content) {
                                all_entries.extend(parse_snapshot_versions_xml(xml_str));
                            }
                        }
                    }
                } else {
                    // Local/Staging members: try stored metadata file, then
                    // collect entries from artifact rows.
                    let member_storage_key = format!("maven/{}", path);
                    if let Ok(member_storage) = state.storage_for_repo(&member.storage_location()) {
                        if let Ok(content) = member_storage.get(&member_storage_key).await {
                            if let Ok(xml_str) = std::str::from_utf8(&content) {
                                all_entries.extend(parse_snapshot_versions_xml(xml_str));
                            }
                        }
                    }

                    let entries = collect_snapshot_entries(
                        &state.db,
                        member.id,
                        &group_id,
                        &artifact_id,
                        &version,
                    )
                    .await;
                    all_entries.extend(entries);
                }
            }

            if !all_entries.is_empty() {
                if let Some(xml) =
                    generate_snapshot_metadata_xml(&group_id, &artifact_id, &version, &all_entries)
                {
                    return Ok(Bytes::from(xml));
                }
            }
        }

        return Err(AppError::NotFound("Metadata not found".to_string()).into_response());
    }

    // Local/Staging repos: try stored metadata file, then dynamic generation.
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;

    let meta_storage_key = format!("maven/{}", path);
    if let Ok(content) = storage.get(&meta_storage_key).await {
        return Ok(content);
    }

    if let Some((group_id, artifact_id)) = parse_metadata_path(path) {
        if let Ok(xml) =
            generate_metadata_for_artifact(&state.db, repo.id, &group_id, &artifact_id).await
        {
            return Ok(Bytes::from(xml));
        }
    }

    Err(AppError::NotFound("Metadata not found".to_string()).into_response())
}

async fn generate_metadata_for_artifact(
    db: &PgPool,
    repo_id: uuid::Uuid,
    group_id: &str,
    artifact_id: &str,
) -> Result<String, Response> {
    let rows = sqlx::query!(
        r#"
        SELECT DISTINCT a.version as "version?"
        FROM artifacts a
        JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND am.format = 'maven'
          AND am.metadata->>'groupId' = $2
          AND am.metadata->>'artifactId' = $3
          AND a.version IS NOT NULL
        "#,
        repo_id,
        group_id,
        artifact_id,
    )
    .fetch_all(db)
    .await
    .map_err(map_db_err)?;

    let versions: Vec<String> = rows.into_iter().filter_map(|r| r.version).collect();

    if versions.is_empty() {
        return Err(AppError::NotFound("No versions found".to_string()).into_response());
    }

    use crate::formats::maven_version;

    let sorted = maven_version::sort_maven_versions(&versions);
    let latest = sorted.last().unwrap().clone();
    let release = maven_version::latest_release(&sorted).cloned();

    let xml = generate_metadata_xml(group_id, artifact_id, &sorted, &latest, release.as_deref());

    Ok(xml)
}

async fn serve_artifact(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    path: &str,
    auth: Option<&AuthExtension>,
) -> Result<Response, Response> {
    // Remote (proxy) repos never persist rows in the `artifacts` table: the
    // proxy cache writes to the package catalog + filesystem only (guarded by
    // `test_cache_artifact_does_not_insert_into_artifacts_table`, #1278). So the
    // exact-path lookup and SNAPSHOT resolution below always miss for them.
    // Skip those 1-2 DB acquires and fall straight through to the upstream
    // proxy fetch, cutting the per-request DB pressure on the remote
    // artifact-GET hot path. Hosted/Virtual repos are unaffected.
    let artifact = if repo.repo_type == RepositoryType::Remote {
        None
    } else {
        // NOTE: the SQL string keeps its original 8-space indentation (not the
        // block's) so the compile-time-checked query text matches the committed
        // .sqlx offline cache key byte-for-byte.
        let artifact = sqlx::query!(
            r#"
        SELECT id, path, size_bytes, checksum_sha256,
               checksum_md5, checksum_sha1,
               content_type, storage_key
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND path = $2
        LIMIT 1
        "#,
            repo.id,
            path,
        )
        .fetch_optional(&state.db)
        .await
        .map_err(map_db_err)?;

        // If artifact not found by exact path, try SNAPSHOT resolution
        match artifact {
            Some(a) => Some(a),
            None if path.contains("-SNAPSHOT") => {
                if let Some(resolved) = resolve_snapshot_artifact(&state.db, repo.id, path).await {
                    let storage = state
                        .storage_for_repo(&repo.storage_location())
                        .map_err(|e| e.into_response())?;
                    let content = storage
                        .get(&resolved.storage_key)
                        .await
                        .map_err(map_storage_err)?;

                    let ct = content_type_for_path(path);
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, ct)
                        .header(CONTENT_LENGTH, content.len().to_string())
                        .header("X-Checksum-SHA256", &resolved.checksum_sha256)
                        .body(Body::from(content))
                        .unwrap());
                }
                None
            }
            None => None,
        }
    };

    // If artifact not found locally, try proxy for remote repos
    let artifact = match artifact {
        Some(a) => a,
        None => {
            if repo.repo_type == RepositoryType::Remote {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    // #895: stream large bodies; pass content_type_for_path
                    // so .pom -> text/xml, .jar -> application/java-archive
                    // when upstream omits Content-Type (closes review N2).
                    return proxy_helpers::proxy_fetch_streaming(
                        proxy,
                        repo.id,
                        repo_key,
                        upstream_url,
                        path,
                        content_type_for_path(path),
                    )
                    .await;
                }
            }
            // Virtual repo: try each member in priority order
            if repo.repo_type == RepositoryType::Virtual {
                let db = state.db.clone();
                let artifact_path = path.to_string();

                // Supply-chain shadowing guard (#1217 follow-up, ak-hv3s).
                // Originally this used the generic `name`-only guard
                // (`virtual_non_remote_owns_name`) keyed off
                // `coords.artifact_id`. That over-matched across
                // groupIds: a local `com.example.mylib:common:1.0` shadowed
                // every remote `com/.../common/...` lookup, returning
                // 404 instead of falling through to the remote member
                // (#1287). The Maven-aware variant matches the full
                // groupId+artifactId path prefix so only true GA
                // collisions activate the suppression. The guard
                // remains a safety net rather than an authority check:
                // different versions under the same GA still
                // legitimately share a directory, and we accept the
                // false-positive within a single GA in exchange for
                // closing the shadowing attack. If the path fails to
                // parse as a Maven coordinate (eg. dynamic
                // metadata.xml requests reach this branch from earlier
                // fall-through), skip the guard rather than block the
                // request.
                let local_owns = match MavenHandler::parse_coordinates(path) {
                    Ok(coords) => {
                        proxy_helpers::virtual_non_remote_owns_maven_ga(
                            &state.db,
                            repo.id,
                            &coords.group_id,
                            &coords.artifact_id,
                        )
                        .await?
                    }
                    Err(_) => false,
                };
                let proxy_for_virtual = if local_owns {
                    None
                } else {
                    state.proxy_service.as_deref()
                };

                // #1804: authorize each member against the caller before any of
                // its bytes can be served. A public virtual repo must not turn
                // into a confused deputy that streams its PRIVATE members'
                // artifacts to anonymous / unprivileged callers. Members the
                // caller could not read directly are dropped, so a denied
                // member behaves exactly as if it did not contain the artifact
                // (404), never leaking its existence.
                let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
                let members = proxy_helpers::authorize_virtual_members(
                    &state.permission_service,
                    auth,
                    members,
                )
                .await;

                let result = proxy_helpers::resolve_virtual_download_from_members(
                    members,
                    proxy_for_virtual,
                    path,
                    |member_id, location| {
                        let db = db.clone();
                        let state = state.clone();
                        let artifact_path = artifact_path.clone();
                        async move {
                            // Fast path: strict path match (covers release artifacts
                            // and SNAPSHOT files deployed under their `-SNAPSHOT` alias).
                            if let Ok(result) = proxy_helpers::local_fetch_by_path(
                                &db,
                                &state,
                                member_id,
                                &location,
                                &artifact_path,
                            )
                            .await
                            {
                                return Ok(result);
                            }

                            // Fallback A: SNAPSHOT alias resolution (#839).
                            // Maven deploys store SNAPSHOTs under timestamped filenames
                            // (`foo-1.0-20260101.120000-1.jar`). The client still asks
                            // for the `-SNAPSHOT` filename, so map that alias to the
                            // latest timestamped file before giving up.
                            //
                            // For SNAPSHOT paths we ALWAYS stop here — never fall
                            // through to the storage-direct fallback below. The
                            // storage path is keyed by the literal `-SNAPSHOT`
                            // string the client sent, but SNAPSHOT bytes on disk
                            // live under the timestamped filename — so the storage
                            // probe would either 404 cleanly (best case) or, if
                            // member A happens to carry a stale snapshot of a
                            // different artifact at the same -SNAPSHOT path, serve
                            // that stale byte stream instead of advancing the
                            // virtual-resolution loop to member B. Confine the
                            // SNAPSHOT codepath to its dedicated helper.
                            let is_snapshot = artifact_path.contains("-SNAPSHOT");
                            if is_snapshot {
                                return maven_local_fetch_snapshot(
                                    &db,
                                    &state,
                                    member_id,
                                    &location,
                                    &artifact_path,
                                )
                                .await;
                            }
                            if let Ok(result) = maven_local_fetch_snapshot(
                                &db,
                                &state,
                                member_id,
                                &location,
                                &artifact_path,
                            )
                            .await
                            {
                                return Ok(result);
                            }

                            // Legacy storage-direct fallback for old Maven rows
                            // created by the former GAV grouping model. Fresh
                            // uploads now create one artifact row per physical
                            // Maven asset, but older repositories may still only
                            // have a primary row while companion bytes live at
                            // `maven/<path>`. The helper gates this on a known
                            // Maven companion path and an active, non-quarantined
                            // primary artifact in the same GAV directory.
                            crate::api::handlers::maven_proxy::maven_local_fetch_storage_fallback(
                                &db,
                                &state,
                                member_id,
                                &location,
                                &artifact_path,
                            )
                            .await
                        }
                    },
                )
                .await?;

                return proxy_helpers::stream_fetch_result(
                    result,
                    content_type_for_path(path),
                    None,
                );
            }

            // Legacy hosted fallback for repositories populated before Maven
            // uploads started indexing every physical asset as an artifact row.
            // Direct byte access remains available for those older companion
            // files while new uploads resolve through the exact `artifacts.path`.
            if repo.repo_type == RepositoryType::Local || repo.repo_type == RepositoryType::Staging
            {
                let storage = state
                    .storage_for_repo(&repo.storage_location())
                    .map_err(|e| e.into_response())?;
                let storage_key = format!("maven/{}", path);
                if let Ok(stream) = storage.get_stream(&storage_key).await {
                    let ct = content_type_for_path(path);
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(CONTENT_TYPE, ct)
                        .body(Body::from_stream(stream))
                        .unwrap());
                }
            }

            return Err(AppError::NotFound("File not found".to_string()).into_response());
        }
    };

    // Check quarantine status before serving
    crate::services::quarantine_service::check_artifact_download(&state.db, artifact.id)
        .await
        .map_err(|e| e.into_response())?;

    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    let stream = storage
        .get_stream(&artifact.storage_key)
        .await
        .map_err(map_storage_err)?;

    // Record download
    let _ = sqlx::query!(
        "INSERT INTO download_statistics (artifact_id, ip_address) VALUES ($1, '0.0.0.0')",
        artifact.id
    )
    .execute(&state.db)
    .await;

    let ct = content_type_for_path(path);
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, ct)
        .header(CONTENT_LENGTH, artifact.size_bytes.to_string())
        .header("X-Checksum-SHA256", &artifact.checksum_sha256);

    if let Some(ref md5) = artifact.checksum_md5 {
        builder = builder.header("X-Checksum-MD5", md5);
    }
    if let Some(ref sha1) = artifact.checksum_sha1 {
        builder = builder.header("X-Checksum-SHA1", sha1);
    }

    Ok(builder.body(Body::from_stream(stream)).unwrap())
}

/// Whether a Maven checksum (`*.md5` / `*.sha1`) for an artifact should be
/// computed from a locally-stored artifact via [`serve_computed_checksum`]
/// (i.e. a DB lookup in the `artifacts` table).
///
/// Only hosted repositories (`Local` / `Staging`) store artifacts in the
/// `artifacts` table. `Remote` repos cache artifacts in the proxy cache, so the
/// DB lookup always fails and the request must be proxied upstream instead
/// (#1599). `Virtual` repos are resolved per-member, so this returns `false`
/// for the virtual itself.
///
/// Takes the raw `repo_type` string (as stored on `RepoInfo`) so it can be
/// unit-tested without constructing a full repository row.
fn checksum_compute_eligible(repo_type: &str) -> bool {
    repo_type == RepositoryType::Local || repo_type == RepositoryType::Staging
}

async fn serve_computed_checksum(
    state: &SharedState,
    repo_id: uuid::Uuid,
    location: &crate::storage::StorageLocation,
    base_path: &str,
    checksum_type: ChecksumType,
) -> Result<Response, Response> {
    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key, checksum_sha256
        FROM artifacts
        WHERE repository_id = $1
          AND is_deleted = false
          AND path = $2
        LIMIT 1
        "#,
        repo_id,
        base_path,
    )
    .fetch_optional(&state.db)
    .await
    .map_err(map_db_err)?;

    // If the exact path was not found and this is a SNAPSHOT request, resolve
    // the `-SNAPSHOT` filename to the latest timestamped version.
    let (resolved_storage_key, resolved_sha256) = match artifact {
        Some(a) => (a.storage_key, a.checksum_sha256),
        None => {
            if base_path.contains("-SNAPSHOT") {
                let resolved = resolve_snapshot_artifact(&state.db, repo_id, base_path)
                    .await
                    .ok_or_else(|| {
                        AppError::NotFound("File not found".to_string()).into_response()
                    })?;
                (resolved.storage_key, resolved.checksum_sha256)
            } else {
                return Err(AppError::NotFound("File not found".to_string()).into_response());
            }
        }
    };

    // For SHA-256 we already have it stored
    let checksum = match checksum_type {
        ChecksumType::Sha256 => resolved_sha256,
        _ => {
            let storage = state.storage_for_repo_or_500(location)?;
            let content = storage
                .get(&resolved_storage_key)
                .await
                .map_err(map_storage_err)?;
            compute_checksum(&content, checksum_type)
        }
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain")
        .body(Body::from(checksum))
        .unwrap())
}

fn compute_checksum(data: &[u8], checksum_type: ChecksumType) -> String {
    match checksum_type {
        ChecksumType::Md5 => {
            use md5::Md5;
            let mut hasher = Md5::new();
            md5::Digest::update(&mut hasher, data);
            format!("{:x}", md5::Digest::finalize(hasher))
        }
        ChecksumType::Sha1 => {
            use sha1::Sha1;
            let mut hasher = Sha1::new();
            sha1::Digest::update(&mut hasher, data);
            format!("{:x}", sha1::Digest::finalize(hasher))
        }
        ChecksumType::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
        ChecksumType::Sha512 => {
            use sha2::Sha512;
            let mut hasher = Sha512::new();
            hasher.update(data);
            format!("{:x}", hasher.finalize())
        }
    }
}

fn maven_package_name(coords: &MavenCoordinates) -> String {
    format!("{}:{}", coords.group_id, coords.artifact_id)
}

fn maven_package_description(metadata: &serde_json::Value) -> Option<String> {
    metadata
        .get("description")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
}

fn build_maven_package_catalog_metadata(
    coords: &MavenCoordinates,
    metadata: &serde_json::Value,
) -> serde_json::Value {
    let mut catalog = serde_json::json!({
        "format": "maven",
        "groupId": coords.group_id,
        "artifactId": coords.artifact_id,
    });

    for key in ["name", "description", "url", "dependencies"] {
        if let Some(value) = metadata.get(key) {
            catalog[key] = value.clone();
        }
    }

    catalog
}

fn should_enqueue_maven_sync_tasks(headers: &HeaderMap) -> bool {
    !super::is_replication_request(headers)
}

async fn queue_maven_sync_tasks(
    state: &SharedState,
    repo_id: uuid::Uuid,
    artifact_id: uuid::Uuid,
    artifact_path: &str,
    artifact_size: i64,
    artifact_created: chrono::DateTime<chrono::Utc>,
) {
    #[derive(sqlx::FromRow)]
    struct SubWithFilter {
        peer_instance_id: uuid::Uuid,
        artifact_filter: Option<serde_json::Value>,
    }

    let subscriptions = match sqlx::query_as::<_, SubWithFilter>(
        r#"
        SELECT prs.peer_instance_id, sp.artifact_filter
        FROM peer_repo_subscriptions prs
        LEFT JOIN sync_policies sp ON sp.id = prs.policy_id
        WHERE prs.repository_id = $1
          AND prs.sync_enabled = true
          AND prs.replication_mode::text IN ('push', 'mirror')
        "#,
    )
    .bind(repo_id)
    .fetch_all(&state.db)
    .await
    {
        Ok(subs) => subs,
        Err(e) => {
            warn!(
                "Failed to query Maven peer subscriptions for repo {} artifact {}: {}",
                repo_id, artifact_id, e
            );
            return;
        }
    };

    for sub in subscriptions {
        let filter: crate::services::sync_policy_service::ArtifactFilter = sub
            .artifact_filter
            .as_ref()
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        if !filter.matches(artifact_path, artifact_size, artifact_created) {
            continue;
        }

        if let Err(e) = sqlx::query(
            r#"
            INSERT INTO sync_tasks (peer_instance_id, artifact_id, priority)
            VALUES ($1, $2, 0)
            ON CONFLICT (peer_instance_id, artifact_id, task_type)
            DO UPDATE SET priority = GREATEST(sync_tasks.priority, 0)
            "#,
        )
        .bind(sub.peer_instance_id)
        .bind(artifact_id)
        .execute(&state.db)
        .await
        {
            warn!(
                "Failed to queue Maven sync task for peer {} artifact {}: {}",
                sub.peer_instance_id, artifact_id, e
            );
        }
    }
}

// ---------------------------------------------------------------------------
// PUT /maven/{repo_key}/*path — Upload artifact
// ---------------------------------------------------------------------------

async fn upload(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, path)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: read-scoped API tokens were being accepted on
    // this push endpoint. Require the write scope before doing any work.
    let auth = require_auth_basic_scope(auth, "maven", "write")?;
    let user_id = auth.user_id;
    let repo = resolve_maven_repo(&state.db, &repo_key).await?;

    // Reject writes to remote/virtual repos
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;

    // Reject direct uploads to promotion-only repositories (non-admins). Such
    // repos accept artifacts only via the promotion path, not direct push.
    let promotion_only = sqlx::query_scalar!(
        "SELECT promotion_only FROM repositories WHERE id = $1",
        repo.id
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| proxy_helpers::internal_error("Database", e))?
    .unwrap_or(false);
    proxy_helpers::reject_direct_upload_if_promotion_only(promotion_only, auth.is_admin)?;

    let storage_key = format!("maven/{}", path);
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;

    // If this is a checksum file (.sha1, .md5, .sha256), just store it and return
    if parse_checksum_path(&path).is_some() {
        storage
            .put(&storage_key, body)
            .await
            .map_err(map_storage_err)?;
        return Ok(Response::builder()
            .status(StatusCode::CREATED)
            .body(Body::from("Created"))
            .unwrap());
    }

    // If this is a maven-metadata.xml upload, just store it
    if MavenHandler::is_metadata(&path) {
        storage
            .put(&storage_key, body)
            .await
            .map_err(map_storage_err)?;
        return Ok(Response::builder()
            .status(StatusCode::CREATED)
            .body(Body::from("Created"))
            .unwrap());
    }

    // Parse Maven coordinates from the path
    let coords = MavenHandler::parse_coordinates(&path)
        .map_err(|e| AppError::Validation(format!("Invalid Maven path: {}", e)).into_response())?;

    // Compute checksums for the canonical artifact row. Maven checksum
    // sidecars are stored separately, but the artifact ledger should still
    // carry the common digests so checksum search, replication, and API
    // responses have the same fidelity as generic uploads.
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let checksum_sha256 = format!("{:x}", hasher.finalize());
    let checksum_sha1 = compute_checksum(&body, ChecksumType::Sha1);
    let checksum_md5 = compute_checksum(&body, ChecksumType::Md5);

    let size_bytes = body.len() as i64;
    let ct = content_type_for_path(&path);

    // Check for active (non-deleted) duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        repo.id,
        path,
    )
    .fetch_optional(&state.db)
    .await
    .map_err(map_db_err)?;

    if existing.is_some() {
        if !coords.version.contains("SNAPSHOT") {
            return Err(AppError::Conflict("Artifact already exists".to_string()).into_response());
        }
        // Hard-delete old SNAPSHOT version so the UNIQUE(repository_id, path)
        // constraint allows re-insert. Safe because SNAPSHOTs are mutable by design.
        let _ = sqlx::query!(
            "DELETE FROM artifacts WHERE repository_id = $1 AND path = $2",
            repo.id,
            path,
        )
        .execute(&state.db)
        .await;
    } else {
        // Clean up any soft-deleted artifact at the same path so the
        // UNIQUE(repository_id, path) constraint doesn't block re-upload —
        // unless this is a release-immutability swap (delete + re-upload of
        // DIFFERENT bytes to an immutable coordinate), which is rejected.
        super::cleanup_soft_deleted_artifact_checked(
            &state.db,
            &crate::models::repository::RepositoryFormat::Maven,
            repo.id,
            &path,
            &checksum_sha256,
        )
        .await
        .map_err(|e| e.into_response())?;
    }

    // Store file in object storage regardless of grouping outcome
    storage
        .put(&storage_key, body.clone())
        .await
        .map_err(map_storage_err)?;

    // Build metadata JSON for this physical Maven file.
    let handler = MavenHandler::new();
    let mut file_metadata = crate::formats::FormatHandler::parse_metadata(&handler, &path, &body)
        .await
        .unwrap_or_else(|_| {
            serde_json::json!({
                "groupId": coords.group_id,
                "artifactId": coords.artifact_id,
                "version": coords.version,
                "extension": coords.extension,
            })
        });

    let name = coords.artifact_id.clone();
    let package_name = maven_package_name(&coords);
    let (package_description, package_metadata) = if MavenHandler::is_pom(&path) {
        (
            maven_package_description(&file_metadata),
            Some(build_maven_package_catalog_metadata(
                &coords,
                &file_metadata,
            )),
        )
    } else {
        (None, None)
    };

    file_metadata["groupId"] = serde_json::Value::String(coords.group_id.clone());
    file_metadata["artifactId"] = serde_json::Value::String(coords.artifact_id.clone());
    file_metadata["version"] = serde_json::Value::String(coords.version.clone());
    file_metadata["extension"] = serde_json::Value::String(coords.extension.clone());
    if let Some(classifier) = &coords.classifier {
        file_metadata["classifier"] = serde_json::Value::String(classifier.clone());
    }

    let (artifact_id, artifact_created): (uuid::Uuid, chrono::DateTime<chrono::Utc>) =
        sqlx::query_as(
            r#"
            INSERT INTO artifacts (
                repository_id, path, name, version, size_bytes,
                checksum_sha256, checksum_sha1, checksum_md5,
                content_type, storage_key, uploaded_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING id, created_at
            "#,
        )
        .bind(repo.id)
        .bind(&path)
        .bind(&name)
        .bind(&coords.version)
        .bind(size_bytes)
        .bind(&checksum_sha256)
        .bind(&checksum_sha1)
        .bind(&checksum_md5)
        .bind(ct)
        .bind(&storage_key)
        .bind(user_id)
        .fetch_one(&state.db)
        .await
        .map_err(map_db_err)?;

    sqlx::query(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'maven', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
    )
    .bind(artifact_id)
    .bind(&file_metadata)
    .execute(&state.db)
    .await
    .map_err(map_db_err)?;

    crate::services::package_service::PackageService::new(state.db.clone())
        .try_create_or_update_from_artifact(
            repo.id,
            &package_name,
            &coords.version,
            size_bytes,
            &checksum_sha256,
            package_description.as_deref(),
            package_metadata,
        )
        .await;

    if should_enqueue_maven_sync_tasks(&headers) {
        queue_maven_sync_tasks(
            &state,
            repo.id,
            artifact_id,
            &path,
            size_bytes,
            artifact_created,
        )
        .await;
    }

    // Update repository timestamp
    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    info!(
        "Maven upload: {}:{}:{} ({}) to repo {}",
        coords.group_id, coords.artifact_id, coords.version, coords.extension, repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .body(Body::from("Created"))
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // checksum_compute_eligible (#1599): which repo types do a DB checksum
    // lookup vs proxy/resolve-per-member.
    // -----------------------------------------------------------------------

    #[test]
    fn test_checksum_compute_eligible_local_and_staging() {
        // Hosted repos store artifacts in the `artifacts` table, so the DB
        // checksum lookup is valid for them.
        assert!(checksum_compute_eligible(RepositoryType::Local.as_str()));
        assert!(checksum_compute_eligible(RepositoryType::Staging.as_str()));
    }

    #[test]
    fn test_checksum_compute_eligible_remote_skips_db_lookup() {
        // Remote repos are pull-through caches; their artifacts are not in the
        // `artifacts` table, so the DB lookup must be skipped (it always fails)
        // and the request proxied upstream instead. Regression guard for #1599.
        assert!(!checksum_compute_eligible(RepositoryType::Remote.as_str()));
    }

    #[test]
    fn test_checksum_compute_eligible_virtual_resolved_per_member() {
        // A virtual repo itself owns no artifacts; it is resolved per-member,
        // so the top-level DB lookup must be skipped.
        assert!(!checksum_compute_eligible(RepositoryType::Virtual.as_str()));
    }

    #[test]
    fn test_checksum_compute_eligible_unknown_type_skips_lookup() {
        // Defensive: an unrecognized repo_type string must not trigger a DB
        // checksum lookup.
        assert!(!checksum_compute_eligible("bogus"));
    }

    #[test]
    fn test_virtual_member_compute_branch_matches_hosted() {
        // The virtual-member loop computes checksums only for hosted members
        // (Local/Staging) and proxies for Remote members (#1599). This mirrors
        // the branch condition used in `download`.
        assert!(RepositoryType::Local.is_hosted());
        assert!(RepositoryType::Staging.is_hosted());
        assert!(!RepositoryType::Remote.is_hosted());
        assert!(!RepositoryType::Virtual.is_hosted());
    }

    fn sample_coords() -> MavenCoordinates {
        MavenCoordinates {
            group_id: "com.example".to_string(),
            artifact_id: "demo".to_string(),
            version: "1.0.0".to_string(),
            extension: "pom".to_string(),
            classifier: None,
        }
    }

    #[test]
    fn test_maven_package_name_uses_group_and_artifact() {
        let coords =
            MavenHandler::parse_coordinates("org/example/ak/maven/ak-core/1.0.0/ak-core-1.0.0.jar")
                .unwrap();

        assert_eq!(maven_package_name(&coords), "org.example.ak.maven:ak-core");
    }

    #[test]
    fn test_maven_package_catalog_metadata_carries_pom_fields() {
        let coords = sample_coords();
        let metadata = serde_json::json!({
            "name": "Demo",
            "description": "Catalog metadata test",
            "url": "https://example.test/demo",
            "dependencies": [
                {"groupId": "com.example", "artifactId": "dep", "version": "1.0.0"}
            ],
            "files": [{"path": "ignored-by-package-catalog"}]
        });

        let catalog = build_maven_package_catalog_metadata(&coords, &metadata);

        assert_eq!(catalog["format"], "maven");
        assert_eq!(catalog["groupId"], "com.example");
        assert_eq!(catalog["artifactId"], "demo");
        assert_eq!(catalog["description"], "Catalog metadata test");
        assert!(catalog.get("files").is_none());
    }

    // -----------------------------------------------------------------------
    // parse_metadata_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_metadata_path_valid_simple() {
        let result = parse_metadata_path("com/example/my-lib/maven-metadata.xml");
        assert_eq!(
            result,
            Some(("com.example".to_string(), "my-lib".to_string()))
        );
    }

    #[test]
    fn test_parse_metadata_path_deep_group() {
        let result = parse_metadata_path("org/apache/commons/commons-lang3/maven-metadata.xml");
        assert_eq!(
            result,
            Some((
                "org.apache.commons".to_string(),
                "commons-lang3".to_string()
            ))
        );
    }

    #[test]
    fn test_parse_metadata_path_leading_slash() {
        let result = parse_metadata_path("/com/google/guava/guava/maven-metadata.xml");
        assert_eq!(
            result,
            Some(("com.google.guava".to_string(), "guava".to_string()))
        );
    }

    #[test]
    fn test_parse_metadata_path_not_metadata() {
        let result = parse_metadata_path("com/example/my-lib/1.0.0/my-lib-1.0.0.jar");
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_metadata_path_too_short() {
        let result = parse_metadata_path("maven-metadata.xml");
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_metadata_path_two_parts_only() {
        // groupSegment/artifactId/maven-metadata.xml minimum
        let result = parse_metadata_path("com/my-lib/maven-metadata.xml");
        assert_eq!(result, Some(("com".to_string(), "my-lib".to_string())));
    }

    #[test]
    fn test_parse_metadata_path_version_level_snapshot() {
        let result = parse_metadata_path("com/test/artifacthub/0.0.1-SNAPSHOT/maven-metadata.xml");
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_metadata_path_version_level_release() {
        let result = parse_metadata_path("com/example/my-lib/1.0.0/maven-metadata.xml");
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_metadata_path_version_level_complex() {
        let result = parse_metadata_path(
            "org/apache/commons/commons-lang3/3.12.0-SNAPSHOT/maven-metadata.xml",
        );
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_metadata_path_artifact_level_still_works() {
        let result = parse_metadata_path("com/example/my-lib/maven-metadata.xml");
        assert_eq!(
            result,
            Some(("com.example".to_string(), "my-lib".to_string())),
        );
    }

    // -----------------------------------------------------------------------
    // parse_checksum_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_checksum_path_sha1() {
        let result = parse_checksum_path("com/example/my-lib/1.0/my-lib-1.0.jar.sha1");
        assert!(result.is_some());
        let (base, ct) = result.unwrap();
        assert_eq!(base, "com/example/my-lib/1.0/my-lib-1.0.jar");
        assert!(matches!(ct, ChecksumType::Sha1));
    }

    #[test]
    fn test_parse_checksum_path_md5() {
        let result = parse_checksum_path("com/example/my-lib/1.0/my-lib-1.0.jar.md5");
        assert!(result.is_some());
        let (base, ct) = result.unwrap();
        assert_eq!(base, "com/example/my-lib/1.0/my-lib-1.0.jar");
        assert!(matches!(ct, ChecksumType::Md5));
    }

    #[test]
    fn test_parse_checksum_path_sha256() {
        let result = parse_checksum_path("com/example/my-lib/1.0/my-lib-1.0.pom.sha256");
        assert!(result.is_some());
        let (base, ct) = result.unwrap();
        assert_eq!(base, "com/example/my-lib/1.0/my-lib-1.0.pom");
        assert!(matches!(ct, ChecksumType::Sha256));
    }

    #[test]
    fn test_parse_checksum_path_sha512() {
        let result = parse_checksum_path("com/example/my-lib/1.0/my-lib-1.0.jar.sha512");
        assert!(result.is_some());
        let (base, ct) = result.unwrap();
        assert_eq!(base, "com/example/my-lib/1.0/my-lib-1.0.jar");
        assert!(matches!(ct, ChecksumType::Sha512));
    }

    #[test]
    fn test_parse_checksum_path_no_checksum_suffix() {
        let result = parse_checksum_path("com/example/my-lib/1.0/my-lib-1.0.jar");
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_checksum_metadata_sha1() {
        let result = parse_checksum_path("com/example/lib/maven-metadata.xml.sha1");
        assert!(result.is_some());
        let (base, ct) = result.unwrap();
        assert_eq!(base, "com/example/lib/maven-metadata.xml");
        assert!(matches!(ct, ChecksumType::Sha1));
    }

    #[test]
    fn test_parse_checksum_group_level_plugin_metadata_sha1() {
        let result = parse_checksum_path("org/codehaus/mojo/maven-metadata.xml.sha1");
        assert!(result.is_some());
        let (base, ct) = result.unwrap();
        assert_eq!(base, "org/codehaus/mojo/maven-metadata.xml");
        assert!(matches!(ct, ChecksumType::Sha1));
        assert_eq!(
            parse_metadata_path(base),
            Some(("org.codehaus".to_string(), "mojo".to_string()))
        );
    }

    // -----------------------------------------------------------------------
    // content_type_for_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_content_type_pom() {
        assert_eq!(content_type_for_path("artifact.pom"), "text/xml");
    }

    #[test]
    fn test_content_type_xml() {
        assert_eq!(content_type_for_path("maven-metadata.xml"), "text/xml");
    }

    #[test]
    fn test_content_type_jar() {
        assert_eq!(
            content_type_for_path("my-lib-1.0.jar"),
            "application/java-archive"
        );
    }

    #[test]
    fn test_content_type_war() {
        assert_eq!(
            content_type_for_path("webapp-1.0.war"),
            "application/java-archive"
        );
    }

    #[test]
    fn test_content_type_other() {
        assert_eq!(
            content_type_for_path("artifact.tar.gz"),
            "application/octet-stream"
        );
    }

    #[test]
    fn test_content_type_txt() {
        assert_eq!(
            content_type_for_path("notes.txt"),
            "application/octet-stream"
        );
    }

    #[test]
    fn test_content_type_asc() {
        assert_eq!(content_type_for_path("artifact.jar.asc"), "text/plain");
    }

    #[test]
    fn test_content_type_ear() {
        assert_eq!(
            content_type_for_path("app-1.0.ear"),
            "application/java-archive"
        );
    }

    // -----------------------------------------------------------------------
    // compute_checksum
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_checksum_sha256() {
        let data = b"hello maven";
        let result = compute_checksum(data, ChecksumType::Sha256);
        assert_eq!(result.len(), 64);
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));

        // Verify determinism
        let result2 = compute_checksum(data, ChecksumType::Sha256);
        assert_eq!(result, result2);
    }

    #[test]
    fn test_compute_checksum_sha512() {
        let data = b"hello maven";
        let result = compute_checksum(data, ChecksumType::Sha512);
        assert_eq!(result.len(), 128); // SHA-512 produces 128 hex chars
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_compute_checksum_sha1() {
        let data = b"hello maven";
        let result = compute_checksum(data, ChecksumType::Sha1);
        assert_eq!(result.len(), 40); // SHA-1 produces 40 hex chars
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_compute_checksum_md5() {
        let data = b"hello maven";
        let result = compute_checksum(data, ChecksumType::Md5);
        assert_eq!(result.len(), 32); // MD5 produces 32 hex chars
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_compute_checksum_empty_data() {
        let data: &[u8] = b"";
        let sha256 = compute_checksum(data, ChecksumType::Sha256);
        let sha1 = compute_checksum(data, ChecksumType::Sha1);
        let md5 = compute_checksum(data, ChecksumType::Md5);

        // Well-known hashes for empty data
        assert_eq!(
            sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(md5, "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn test_compute_checksum_different_types_differ() {
        let data = b"test";
        let sha256 = compute_checksum(data, ChecksumType::Sha256);
        let sha1 = compute_checksum(data, ChecksumType::Sha1);
        let md5 = compute_checksum(data, ChecksumType::Md5);

        assert_ne!(sha256, sha1);
        assert_ne!(sha256, md5);
        assert_ne!(sha1, md5);
    }

    #[test]
    fn test_virtual_plugin_metadata_checksum_uses_merged_xml() {
        let member_a = r#"<metadata>
  <plugins>
    <plugin>
      <name>Mojo Plugin A</name>
      <prefix>a</prefix>
      <artifactId>a-maven-plugin</artifactId>
    </plugin>
  </plugins>
</metadata>
"#
        .to_string();
        let member_b = r#"<metadata>
  <plugins>
    <plugin>
      <name>Mojo Plugin B</name>
      <prefix>b</prefix>
      <artifactId>b-maven-plugin</artifactId>
    </plugin>
  </plugins>
</metadata>
"#
        .to_string();

        let merged =
            crate::formats::maven::merge_plugin_prefix_metadata(&[member_a.clone(), member_b])
                .unwrap();
        let merged_sha1 = compute_checksum(merged.as_bytes(), ChecksumType::Sha1);

        assert_eq!(merged_sha1.len(), 40);
        assert!(merged.contains("<prefix>a</prefix>"));
        assert!(merged.contains("<prefix>b</prefix>"));
        assert_ne!(
            merged_sha1,
            compute_checksum(member_a.as_bytes(), ChecksumType::Sha1)
        );
    }

    // -----------------------------------------------------------------------
    // RepoInfo
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // build_maven_storage_key
    // -----------------------------------------------------------------------

    /// Build the Maven storage key from a raw path.
    fn build_maven_storage_key(path: &str) -> String {
        format!("maven/{}", path)
    }

    #[test]
    fn test_build_maven_storage_key_jar() {
        assert_eq!(
            build_maven_storage_key("com/example/lib/1.0/lib-1.0.jar"),
            "maven/com/example/lib/1.0/lib-1.0.jar"
        );
    }

    #[test]
    fn test_build_maven_storage_key_pom() {
        assert_eq!(
            build_maven_storage_key(
                "org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.pom"
            ),
            "maven/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.pom"
        );
    }

    #[test]
    fn test_build_maven_storage_key_starts_with_maven() {
        let key = build_maven_storage_key("com/example/lib.jar");
        assert!(key.starts_with("maven/"));
    }

    #[test]
    fn test_build_maven_storage_key_metadata() {
        assert_eq!(
            build_maven_storage_key("com/example/lib/maven-metadata.xml"),
            "maven/com/example/lib/maven-metadata.xml"
        );
    }

    #[test]
    fn test_build_maven_storage_key_checksum() {
        assert_eq!(
            build_maven_storage_key("com/example/lib/1.0/lib-1.0.jar.sha1"),
            "maven/com/example/lib/1.0/lib-1.0.jar.sha1"
        );
    }

    // -----------------------------------------------------------------------
    // RepoInfo
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_info_construction() {
        let id = uuid::Uuid::new_v4();
        let repo = RepoInfo {
            id,
            key: String::new(),
            storage_path: "/data/maven".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "hosted".to_string(),
            upstream_url: None,
            promotion_only: false,
        };
        assert_eq!(repo.id, id);
        assert_eq!(repo.repo_type, "hosted");
    }

    #[test]
    fn test_repo_info_remote() {
        let repo = RepoInfo {
            id: uuid::Uuid::new_v4(),
            key: String::new(),
            storage_path: "/cache/maven".to_string(),
            storage_backend: "filesystem".to_string(),
            repo_type: "remote".to_string(),
            upstream_url: Some("https://repo1.maven.org/maven2".to_string()),
            promotion_only: false,
        };
        assert_eq!(repo.repo_type, "remote");
        assert_eq!(
            repo.upstream_url.as_deref(),
            Some("https://repo1.maven.org/maven2")
        );
    }

    // -----------------------------------------------------------------------
    // snapshot_like_pattern
    // -----------------------------------------------------------------------

    #[test]
    fn test_snapshot_like_pattern_jar() {
        let result = snapshot_like_pattern(
            "com/test/artifacthub/0.0.1-SNAPSHOT/artifacthub-0.0.1-SNAPSHOT.jar",
        );
        assert_eq!(
            result,
            Some("com/test/artifacthub/0.0.1-SNAPSHOT/artifacthub-0.0.1-%.jar".to_string())
        );
    }

    #[test]
    fn test_snapshot_like_pattern_pom() {
        let result =
            snapshot_like_pattern("com/example/mylib/1.0.0-SNAPSHOT/mylib-1.0.0-SNAPSHOT.pom");
        assert_eq!(
            result,
            Some("com/example/mylib/1.0.0-SNAPSHOT/mylib-1.0.0-%.pom".to_string())
        );
    }

    #[test]
    fn test_snapshot_like_pattern_with_classifier() {
        let result =
            snapshot_like_pattern("com/example/lib/2.0-SNAPSHOT/lib-2.0-SNAPSHOT-sources.jar");
        assert_eq!(
            result,
            Some("com/example/lib/2.0-SNAPSHOT/lib-2.0-%-sources.jar".to_string())
        );
    }

    #[test]
    fn test_snapshot_like_pattern_non_snapshot_returns_none() {
        let result = snapshot_like_pattern("com/example/lib/1.0.0/lib-1.0.0.jar");
        assert_eq!(result, None);
    }

    #[test]
    fn test_snapshot_like_pattern_metadata_returns_none() {
        // maven-metadata.xml does not contain -SNAPSHOT in the filename
        let result = snapshot_like_pattern("com/example/lib/1.0.0-SNAPSHOT/maven-metadata.xml");
        assert_eq!(result, None);
    }

    #[test]
    fn test_snapshot_like_pattern_leading_slash() {
        let result = snapshot_like_pattern("/com/test/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar");
        assert_eq!(
            result,
            Some("com/test/lib/1.0-SNAPSHOT/lib-1.0-%.jar".to_string())
        );
    }

    #[test]
    fn test_snapshot_like_pattern_deep_group() {
        let result = snapshot_like_pattern(
            "org/apache/commons/commons-lang3/3.12.0-SNAPSHOT/commons-lang3-3.12.0-SNAPSHOT.jar",
        );
        assert_eq!(
            result,
            Some(
                "org/apache/commons/commons-lang3/3.12.0-SNAPSHOT/commons-lang3-3.12.0-%.jar"
                    .to_string()
            )
        );
    }

    /// Regression: user-supplied `%` and `_` characters in the request path
    /// must NOT be passed through as SQL LIKE wildcards. An attacker crafting
    /// a request like `com/x/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT%.jar` could
    /// otherwise match arbitrary timestamped artifacts whose filenames have
    /// any content after the (legitimate) wildcard segment, instead of only
    /// the exact `.jar` extension. With a `repository_id` constraint the
    /// blast radius is bounded to a single repo, but it still serves the
    /// wrong artifact and discloses the existence of unrelated rows.
    ///
    /// Expected behavior: literal `%` / `_` in user input must be escaped so
    /// the resulting LIKE pattern only contains intentional wildcards. The
    /// returned pattern must be paired with an `ESCAPE '\'` clause in the SQL.
    #[test]
    fn test_snapshot_like_pattern_escapes_user_wildcard_percent() {
        // Attacker appends a literal `%` so the LIKE matches any suffix.
        let result = snapshot_like_pattern("com/example/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT%.jar");
        // The single intentional wildcard introduced by the helper (replacing
        // `-SNAPSHOT` with `-%`) is allowed; any `%` originating from user
        // input must be escaped with a backslash so it matches a literal `%`.
        assert_eq!(
            result,
            Some("com/example/lib/1.0-SNAPSHOT/lib-1.0-%\\%.jar".to_string()),
            "user-supplied `%` must be escaped, not passed through as a wildcard"
        );
    }

    #[test]
    fn test_snapshot_like_pattern_escapes_user_wildcard_underscore() {
        // `_` is a single-character LIKE wildcard; user input must not be
        // able to introduce one. Filename keeps the legitimate `-SNAPSHOT`
        // token but adds a `_` that an attacker controls.
        let result = snapshot_like_pattern("com/example/lib/1.0-SNAPSHOT/lib_-1.0-SNAPSHOT.jar");
        assert_eq!(
            result,
            Some("com/example/lib/1.0-SNAPSHOT/lib\\_-1.0-%.jar".to_string()),
            "user-supplied `_` must be escaped, not passed through as a wildcard"
        );
    }

    #[test]
    fn test_snapshot_like_pattern_escapes_user_backslash() {
        // The escape character itself must also be escaped to avoid breaking
        // the ESCAPE '\' contract.
        let result =
            snapshot_like_pattern("com/example/lib/1.0-SNAPSHOT/lib\\path-1.0-SNAPSHOT.jar");
        assert_eq!(
            result,
            Some("com/example/lib/1.0-SNAPSHOT/lib\\\\path-1.0-%.jar".to_string()),
            "user-supplied `\\` must be escaped to preserve ESCAPE '\\' semantics"
        );
    }

    #[test]
    fn test_snapshot_like_pattern_escapes_wildcards_in_directory() {
        // Wildcards in any user-controlled segment (not just the filename)
        // must also be escaped. The version directory must still end with
        // `-SNAPSHOT` to trigger the helper.
        let result = snapshot_like_pattern("com/example/lib%/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar");
        assert_eq!(
            result,
            Some("com/example/lib\\%/1.0-SNAPSHOT/lib-1.0-%.jar".to_string()),
            "user-supplied wildcards in directory segments must also be escaped"
        );
    }

    // -----------------------------------------------------------------------
    // checksum_suffix
    // -----------------------------------------------------------------------

    #[test]
    fn test_checksum_suffix_md5() {
        assert_eq!(checksum_suffix(ChecksumType::Md5), "md5");
    }

    #[test]
    fn test_checksum_suffix_sha1() {
        assert_eq!(checksum_suffix(ChecksumType::Sha1), "sha1");
    }

    #[test]
    fn test_checksum_suffix_sha256() {
        assert_eq!(checksum_suffix(ChecksumType::Sha256), "sha256");
    }

    #[test]
    fn test_checksum_suffix_sha512() {
        assert_eq!(checksum_suffix(ChecksumType::Sha512), "sha512");
    }

    // -----------------------------------------------------------------------
    // checksum_suffix (used in virtual repo checksum resolution, #660)
    // -----------------------------------------------------------------------

    #[test]
    fn test_checksum_suffix_mapping() {
        assert_eq!(checksum_suffix(ChecksumType::Sha1), "sha1");
        assert_eq!(checksum_suffix(ChecksumType::Md5), "md5");
        assert_eq!(checksum_suffix(ChecksumType::Sha256), "sha256");
        assert_eq!(checksum_suffix(ChecksumType::Sha512), "sha512");
    }

    #[test]
    fn test_checksum_path_round_trip() {
        // Verify that parsing a checksum path and re-appending the suffix
        // yields the original path (important for virtual repo resolution).
        let paths = vec![
            "org/junit/junit/4.13.2/junit-4.13.2.jar.sha1",
            "com/example/lib/1.0/lib-1.0.pom.md5",
            "org/apache/maven/maven-core/3.9.6/maven-core-3.9.6.jar.sha256",
        ];
        for path in paths {
            let (base, ct) = parse_checksum_path(path).unwrap();
            let reconstructed = format!("{}.{}", base, checksum_suffix(ct));
            assert_eq!(reconstructed, path);
        }
    }

    // -----------------------------------------------------------------------
    // parse_snapshot_metadata_path (#839)
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_snapshot_metadata_path_basic() {
        let result =
            parse_snapshot_metadata_path("com/example/my-lib/1.0-SNAPSHOT/maven-metadata.xml");
        assert_eq!(
            result,
            Some((
                "com.example".to_string(),
                "my-lib".to_string(),
                "1.0-SNAPSHOT".to_string()
            ))
        );
    }

    #[test]
    fn test_parse_snapshot_metadata_path_deep_group() {
        let result =
            parse_snapshot_metadata_path("com/test/artifacthub/0.0.1-SNAPSHOT/maven-metadata.xml");
        assert_eq!(
            result,
            Some((
                "com.test".to_string(),
                "artifacthub".to_string(),
                "0.0.1-SNAPSHOT".to_string()
            ))
        );
    }

    #[test]
    fn test_parse_snapshot_metadata_path_leading_slash() {
        let result =
            parse_snapshot_metadata_path("/com/example/lib/2.0-SNAPSHOT/maven-metadata.xml");
        assert_eq!(
            result,
            Some((
                "com.example".to_string(),
                "lib".to_string(),
                "2.0-SNAPSHOT".to_string()
            ))
        );
    }

    #[test]
    fn test_parse_snapshot_metadata_path_release_returns_none() {
        let result = parse_snapshot_metadata_path("com/example/lib/1.0.0/maven-metadata.xml");
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_snapshot_metadata_path_artifact_level_returns_none() {
        // Artifact-level metadata is handled by parse_metadata_path instead.
        let result = parse_snapshot_metadata_path("com/example/lib/maven-metadata.xml");
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_snapshot_metadata_path_not_metadata_returns_none() {
        let result =
            parse_snapshot_metadata_path("com/example/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar");
        assert_eq!(result, None);
    }

    // -----------------------------------------------------------------------
    // extract_snapshot_info_from_filename (#839)
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_snapshot_info_primary_jar() {
        let info =
            extract_snapshot_info_from_filename("mylib-1.0-20260101.120000-3.jar", "mylib", "1.0")
                .unwrap();
        assert_eq!(info.timestamp, "20260101.120000");
        assert_eq!(info.build_number, 3);
        assert_eq!(info.classifier, None);
        assert_eq!(info.extension, "jar");
    }

    #[test]
    fn test_extract_snapshot_info_with_classifier() {
        let info = extract_snapshot_info_from_filename(
            "mylib-1.0-20260101.120000-3-sources.jar",
            "mylib",
            "1.0",
        )
        .unwrap();
        assert_eq!(info.classifier, Some("sources".to_string()));
        assert_eq!(info.extension, "jar");
        assert_eq!(info.build_number, 3);
    }

    #[test]
    fn test_extract_snapshot_info_pom() {
        let info = extract_snapshot_info_from_filename(
            "artifacthub-0.0.1-20260415.091234-7.pom",
            "artifacthub",
            "0.0.1",
        )
        .unwrap();
        assert_eq!(info.extension, "pom");
        assert_eq!(info.timestamp, "20260415.091234");
        assert_eq!(info.build_number, 7);
    }

    #[test]
    fn test_extract_snapshot_info_tar_gz() {
        let info = extract_snapshot_info_from_filename(
            "bundle-1.0-20260101.120000-1.tar.gz",
            "bundle",
            "1.0",
        )
        .unwrap();
        assert_eq!(info.extension, "tar.gz");
    }

    #[test]
    fn test_extract_snapshot_info_wrong_artifact_returns_none() {
        let result =
            extract_snapshot_info_from_filename("other-1.0-20260101.120000-3.jar", "mylib", "1.0");
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_snapshot_info_non_timestamped_returns_none() {
        // Deployed under the SNAPSHOT alias (no timestamp) - not our pattern.
        let result = extract_snapshot_info_from_filename("mylib-1.0-SNAPSHOT.jar", "mylib", "1.0");
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_snapshot_info_bad_timestamp_returns_none() {
        // Garbage where the timestamp should be.
        let result =
            extract_snapshot_info_from_filename("mylib-1.0-notatimestamp-3.jar", "mylib", "1.0");
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // snapshot_version_value
    // -----------------------------------------------------------------------

    #[test]
    fn test_snapshot_version_value_basic() {
        let entry = SnapshotEntry {
            classifier: None,
            extension: "jar".into(),
            timestamp: "20260101.120000".into(),
            build_number: 3,
        };
        assert_eq!(
            snapshot_version_value("1.0", &entry),
            "1.0-20260101.120000-3"
        );
    }

    // -----------------------------------------------------------------------
    // generate_snapshot_metadata_xml (#839)
    // -----------------------------------------------------------------------

    #[test]
    fn test_generate_snapshot_metadata_xml_single_entry() {
        let entries = vec![SnapshotEntry {
            classifier: None,
            extension: "jar".into(),
            timestamp: "20260101.120000".into(),
            build_number: 1,
        }];
        let xml = generate_snapshot_metadata_xml("com.example", "mylib", "1.0-SNAPSHOT", &entries)
            .unwrap();
        assert!(xml.contains("<groupId>com.example</groupId>"));
        assert!(xml.contains("<artifactId>mylib</artifactId>"));
        assert!(xml.contains("<version>1.0-SNAPSHOT</version>"));
        assert!(xml.contains("<timestamp>20260101.120000</timestamp>"));
        assert!(xml.contains("<buildNumber>1</buildNumber>"));
        assert!(xml.contains("<value>1.0-20260101.120000-1</value>"));
        assert!(xml.contains("<extension>jar</extension>"));
        assert!(xml.contains("<lastUpdated>20260101120000</lastUpdated>"));
    }

    #[test]
    fn test_generate_snapshot_metadata_xml_empty_returns_none() {
        let xml = generate_snapshot_metadata_xml("com.example", "lib", "1.0-SNAPSHOT", &[]);
        assert!(xml.is_none());
    }

    #[test]
    fn test_generate_snapshot_metadata_xml_non_snapshot_returns_none() {
        let entries = vec![SnapshotEntry {
            classifier: None,
            extension: "jar".into(),
            timestamp: "20260101.120000".into(),
            build_number: 1,
        }];
        // version must end with -SNAPSHOT
        let xml = generate_snapshot_metadata_xml("com.example", "lib", "1.0", &entries);
        assert!(xml.is_none());
    }

    #[test]
    fn test_generate_snapshot_metadata_xml_picks_latest_timestamp() {
        let entries = vec![
            SnapshotEntry {
                classifier: None,
                extension: "jar".into(),
                timestamp: "20260101.120000".into(),
                build_number: 1,
            },
            SnapshotEntry {
                classifier: None,
                extension: "jar".into(),
                timestamp: "20260201.120000".into(),
                build_number: 2,
            },
        ];
        let xml = generate_snapshot_metadata_xml("com.example", "mylib", "1.0-SNAPSHOT", &entries)
            .unwrap();
        // Top-level snapshot should reflect the later one (20260201 > 20260101).
        assert!(xml.contains("<timestamp>20260201.120000</timestamp>"));
        assert!(xml.contains("<buildNumber>2</buildNumber>"));
    }

    #[test]
    fn test_generate_snapshot_metadata_xml_with_classifier() {
        let entries = vec![
            SnapshotEntry {
                classifier: None,
                extension: "jar".into(),
                timestamp: "20260101.120000".into(),
                build_number: 1,
            },
            SnapshotEntry {
                classifier: Some("sources".into()),
                extension: "jar".into(),
                timestamp: "20260101.120000".into(),
                build_number: 1,
            },
        ];
        let xml = generate_snapshot_metadata_xml("com.example", "mylib", "1.0-SNAPSHOT", &entries)
            .unwrap();
        assert!(xml.contains("<classifier>sources</classifier>"));
        // Both entries should appear in snapshotVersions.
        let occurrences = xml.matches("<snapshotVersion>").count();
        assert_eq!(occurrences, 2);
    }

    #[test]
    fn test_generate_snapshot_metadata_xml_dedupes_by_key() {
        // Two entries for the same (classifier=None, extension=jar) key; the
        // later timestamp should win and only one snapshotVersion entry emitted.
        let entries = vec![
            SnapshotEntry {
                classifier: None,
                extension: "jar".into(),
                timestamp: "20260101.120000".into(),
                build_number: 1,
            },
            SnapshotEntry {
                classifier: None,
                extension: "jar".into(),
                timestamp: "20260201.120000".into(),
                build_number: 2,
            },
        ];
        let xml = generate_snapshot_metadata_xml("com.example", "mylib", "1.0-SNAPSHOT", &entries)
            .unwrap();
        let occurrences = xml.matches("<snapshotVersion>").count();
        assert_eq!(occurrences, 1);
        assert!(xml.contains("<value>1.0-20260201.120000-2</value>"));
    }

    // -----------------------------------------------------------------------
    // parse_snapshot_versions_xml (#839)
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_snapshot_versions_xml_roundtrip() {
        // Generate XML from a known set of entries, then parse it back. The
        // parsed entries must contain every (classifier, extension, timestamp,
        // buildNumber) from the input.
        let entries = vec![
            SnapshotEntry {
                classifier: None,
                extension: "jar".into(),
                timestamp: "20260101.120000".into(),
                build_number: 1,
            },
            SnapshotEntry {
                classifier: Some("sources".into()),
                extension: "jar".into(),
                timestamp: "20260101.120000".into(),
                build_number: 1,
            },
        ];
        let xml = generate_snapshot_metadata_xml("com.example", "mylib", "1.0-SNAPSHOT", &entries)
            .unwrap();
        let parsed = parse_snapshot_versions_xml(&xml);
        assert_eq!(parsed.len(), 2);
        assert!(parsed.iter().any(|e| e.classifier.is_none()
            && e.extension == "jar"
            && e.build_number == 1
            && e.timestamp == "20260101.120000"));
        assert!(parsed
            .iter()
            .any(|e| e.classifier.as_deref() == Some("sources")
                && e.extension == "jar"
                && e.build_number == 1
                && e.timestamp == "20260101.120000"));
    }

    #[test]
    fn test_parse_snapshot_versions_xml_no_snapshot_block() {
        // Metadata without a <snapshotVersions> block yields an empty list.
        let xml = r#"<metadata><groupId>g</groupId><artifactId>a</artifactId></metadata>"#;
        let parsed = parse_snapshot_versions_xml(xml);
        assert!(parsed.is_empty());
    }

    // ── DB-backed HTTP-level regression tests (no_op without DATABASE_URL) ──
    //
    // These exercise the maven `download` handler end-to-end through the
    // actual axum Router so a future refactor that breaks virtual-repo
    // routing surfaces the failure here, not at release-gate time.

    /// Regression for Maven Package API visibility: Maven uploads bypass the
    /// generic ArtifactService path, so the handler itself must populate the
    /// package catalog.
    #[tokio::test]
    async fn test_maven_upload_populates_package_catalog() {
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::http::StatusCode;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let (repo_id, repo_key, storage_dir) = tdh::create_repo(&pool, "local", "maven").await;
        let (user_id, username) = tdh::create_user(&pool).await;
        let state = tdh::build_state(pool.clone(), storage_dir.to_str().unwrap());
        let auth = tdh::make_auth(user_id, &username);
        let router = tdh::router_with_auth(super::router(), state, auth);

        let path = "com/example/catalog/demo-lib/1.2.3/demo-lib-1.2.3.pom";
        let pom = bytes::Bytes::from_static(
            br#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example.catalog</groupId>
  <artifactId>demo-lib</artifactId>
  <version>1.2.3</version>
  <name>Demo Lib</name>
  <description>Visible Maven package</description>
</project>"#,
        );
        let (status, body) =
            tdh::send(router, tdh::put(format!("/{}/{}", repo_key, path), pom)).await;

        let row = if status == StatusCode::CREATED {
            sqlx::query_as::<
                _,
                (
                    String,
                    String,
                    Option<String>,
                    Option<serde_json::Value>,
                    String,
                ),
            >(
                r#"
                SELECT p.name, p.version, p.description, p.metadata, pv.version
                FROM packages p
                JOIN package_versions pv ON pv.package_id = p.id
                WHERE p.repository_id = $1
                  AND p.name = 'com.example.catalog:demo-lib'
                "#,
            )
            .bind(repo_id)
            .fetch_optional(&pool)
            .await
            .expect("query package catalog")
        } else {
            None
        };

        tdh::cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&storage_dir);

        assert_eq!(
            status,
            StatusCode::CREATED,
            "Maven PUT must succeed before catalog assertion. body={}",
            String::from_utf8_lossy(&body)
        );
        let (name, version, description, metadata, version_row) =
            row.expect("Maven upload must create a package catalog row");
        assert_eq!(name, "com.example.catalog:demo-lib");
        assert_eq!(version, "1.2.3");
        assert_eq!(version_row, "1.2.3");
        assert_eq!(description.as_deref(), Some("Visible Maven package"));
        let metadata = metadata.expect("Maven package metadata");
        assert_eq!(metadata["format"], "maven");
        assert_eq!(metadata["groupId"], "com.example.catalog");
        assert_eq!(metadata["artifactId"], "demo-lib");
    }

    /// Maven uploads must keep a physical artifact row for every uploaded
    /// asset path. The package catalog groups them into one package, but the
    /// `artifacts` table is the canonical ledger used by exact-path APIs,
    /// checksums, scanning, and replication.
    #[tokio::test]
    async fn test_maven_upload_indexes_each_physical_artifact_path() {
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::http::StatusCode;
        use std::collections::BTreeSet;

        let Some(fx) = tdh::Fixture::setup("local", "maven").await else {
            return;
        };

        let router = fx.router_with_auth(super::router());
        let base = "com/example/ledger/demo/1.0.0";
        let uploads = vec![
            (
                format!("{base}/demo-1.0.0-javadoc.jar"),
                bytes::Bytes::from_static(b"javadocs"),
            ),
            (
                format!("{base}/demo-1.0.0-sources.jar"),
                bytes::Bytes::from_static(b"sources"),
            ),
            (
                format!("{base}/demo-1.0.0.jar"),
                bytes::Bytes::from_static(b"jar-bytes"),
            ),
            (
                format!("{base}/demo-1.0.0.module"),
                bytes::Bytes::from_static(br#"{"formatVersion":"1.1"}"#),
            ),
            (
                format!("{base}/demo-1.0.0.pom"),
                bytes::Bytes::from_static(
                    br#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example.ledger</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <description>Physical artifact ledger test</description>
</project>"#,
                ),
            ),
            (
                format!("{base}/demo-1.0.0-linux-x86_64.jar"),
                bytes::Bytes::from_static(b"classifier"),
            ),
            (
                format!("{base}/demo-1.0.0.tgz"),
                bytes::Bytes::from_static(b"tgz-bytes"),
            ),
        ];

        for (path, body) in &uploads {
            let (status, response_body) = tdh::send(
                router.clone(),
                tdh::put(format!("/{}/{}", fx.repo_key, path), body.clone()),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::CREATED,
                "Maven PUT must create {path}; body={}",
                String::from_utf8_lossy(&response_body)
            );
        }

        let expected_paths: Vec<String> = uploads.iter().map(|(p, _)| p.clone()).collect();
        let rows: Vec<(String, String, Option<String>, Option<String>)> = sqlx::query_as(
            r#"
            SELECT path, storage_key, checksum_sha1, checksum_md5
            FROM artifacts
            WHERE repository_id = $1
              AND path = ANY($2)
              AND is_deleted = false
            "#,
        )
        .bind(fx.repo_id)
        .bind(&expected_paths)
        .fetch_all(&fx.pool)
        .await
        .expect("query Maven artifact rows");
        let actual_paths: BTreeSet<String> = rows.iter().map(|r| r.0.clone()).collect();
        let expected_set: BTreeSet<String> = expected_paths.iter().cloned().collect();
        assert_eq!(actual_paths, expected_set);
        for (path, storage_key, sha1, md5) in &rows {
            assert_eq!(storage_key, &format!("maven/{path}"));
            assert!(sha1.as_deref().is_some_and(|v| v.len() == 40));
            assert!(md5.as_deref().is_some_and(|v| v.len() == 32));
        }

        let metadata_rows: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM artifact_metadata am
            JOIN artifacts a ON a.id = am.artifact_id
            WHERE a.repository_id = $1
              AND a.path = ANY($2)
              AND am.format = 'maven'
            "#,
        )
        .bind(fx.repo_id)
        .bind(&expected_paths)
        .fetch_one(&fx.pool)
        .await
        .expect("count Maven metadata rows");
        assert_eq!(metadata_rows, expected_paths.len() as i64);

        let (package_count, version_count): (i64, i64) = sqlx::query_as(
            r#"
            SELECT
              COUNT(DISTINCT p.id)::bigint,
              COUNT(DISTINCT pv.id)::bigint
            FROM packages p
            JOIN package_versions pv ON pv.package_id = p.id
            WHERE p.repository_id = $1
              AND p.name = 'com.example.ledger:demo'
              AND pv.version = '1.0.0'
            "#,
        )
        .bind(fx.repo_id)
        .fetch_one(&fx.pool)
        .await
        .expect("count Maven package rows");
        assert_eq!(package_count, 1);
        assert_eq!(version_count, 1);

        fx.teardown().await;
    }

    /// Direct Maven uploads bypass the generic ArtifactService upload path, so
    /// the Maven handler must explicitly fan out peer sync tasks for each
    /// physical artifact row it creates.
    #[tokio::test]
    async fn test_maven_upload_queues_sync_tasks_per_artifact_path() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::peer_instance_service::{
            PeerInstanceService, RegisterPeerInstanceRequest, ReplicationMode,
        };
        use axum::http::StatusCode;

        let Some(fx) = tdh::Fixture::setup("local", "maven").await else {
            return;
        };

        let peer_service = PeerInstanceService::new(fx.pool.clone());
        let peer = peer_service
            .register(RegisterPeerInstanceRequest {
                name: format!("maven-repl-peer-{}", fx.repo_id),
                endpoint_url: "https://peer.example.test".to_string(),
                region: None,
                cache_size_bytes: 1024 * 1024,
                sync_filter: None,
                api_key: "peer-key".to_string(),
            })
            .await
            .expect("register test peer");
        peer_service
            .assign_repository(
                peer.id,
                fx.repo_id,
                true,
                Some(ReplicationMode::Mirror),
                None,
                None,
            )
            .await
            .expect("assign Maven repo to peer");

        let router = fx.router_with_auth(super::router());
        let paths = vec![
            "com/example/repl/demo/1.0.0/demo-1.0.0.pom".to_string(),
            "com/example/repl/demo/1.0.0/demo-1.0.0.jar".to_string(),
        ];
        for path in &paths {
            let body = if path.ends_with(".pom") {
                bytes::Bytes::from_static(
                    br#"<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example.repl</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
</project>"#,
                )
            } else {
                bytes::Bytes::from_static(b"jar")
            };
            let (status, response_body) = tdh::send(
                router.clone(),
                tdh::put(format!("/{}/{}", fx.repo_key, path), body),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::CREATED,
                "Maven PUT must create {path}; body={}",
                String::from_utf8_lossy(&response_body)
            );
        }

        let queued: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM sync_tasks st
            JOIN artifacts a ON a.id = st.artifact_id
            WHERE st.peer_instance_id = $1
              AND a.repository_id = $2
              AND a.path = ANY($3)
              AND st.task_type = 'push'
            "#,
        )
        .bind(peer.id)
        .bind(fx.repo_id)
        .bind(&paths)
        .fetch_one(&fx.pool)
        .await
        .expect("count Maven sync tasks");
        assert_eq!(queued, paths.len() as i64);

        let _ = sqlx::query("DELETE FROM peer_instances WHERE id = $1")
            .bind(peer.id)
            .execute(&fx.pool)
            .await;
        fx.teardown().await;
    }

    /// HTTP-level regression test for #1444 / #839 (re-test): GET a Maven
    /// SNAPSHOT jar by its `-SNAPSHOT` alias through a virtual repo returns
    /// 200 and the original bytes.
    ///
    /// Setup: hosted Maven repo holds the SNAPSHOT jar at its timestamped
    /// filename (the shape Maven actually deploys). A second virtual Maven
    /// repo has the hosted as its sole member. We hit
    /// `GET /maven/<virtual>/.../<artifact>-<base>-SNAPSHOT.jar`, which
    /// goes through the `serve_artifact` virtual branch and the
    /// `maven_local_fetch_snapshot` alias-resolution fallback.
    #[tokio::test]
    async fn test_virtual_repo_serves_snapshot_jar_by_alias_1444() {
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use uuid::Uuid;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        // -- Build the hosted (local) member: insert repo + JAR row + bytes.
        let (hosted_id, _hosted_key, hosted_dir) = tdh::create_repo(&pool, "local", "maven").await;
        let (user_id, _username) = tdh::create_user(&pool).await;

        let group_id = "com.example.snapj1444";
        let group_path = "com/example/snapj1444";
        let artifact_id = "snap";
        let version = "1.0.0-SNAPSHOT";
        let snap_ts_value = "1.0.0-20261231.235959-1";

        // Timestamped path is what Maven deploy actually writes.
        let timestamped_path = format!(
            "{}/{}/{}/{}-{}.jar",
            group_path, artifact_id, version, artifact_id, snap_ts_value
        );
        let jar_bytes = bytes::Bytes::from_static(b"snapshot-jar-bytes-for-1444");
        let storage_key = format!("maven/{}", timestamped_path);

        // Put the jar onto the hosted repo's storage.
        let hosted_state = tdh::build_state(pool.clone(), hosted_dir.to_str().unwrap());
        let hosted_storage = hosted_state
            .storage_for_repo(&crate::storage::StorageLocation {
                backend: "filesystem".to_string(),
                path: hosted_dir.to_string_lossy().into_owned(),
            })
            .expect("storage_for_repo");
        hosted_storage
            .put(&storage_key, jar_bytes.clone())
            .await
            .expect("put jar bytes on hosted storage");

        // Insert the artifact row at the timestamped path; this is what
        // `resolve_snapshot_artifact` looks up to map the -SNAPSHOT alias.
        let artifact_id_db = Uuid::new_v4();
        let sha256 = "deadbeef".repeat(8); // 64 hex chars
        sqlx::query(
            r#"
            INSERT INTO artifacts
                (id, repository_id, path, name, version, size_bytes,
                 checksum_sha256, content_type, storage_key, uploaded_by, is_deleted)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, false)
            "#,
        )
        .bind(artifact_id_db)
        .bind(hosted_id)
        .bind(&timestamped_path)
        .bind(artifact_id)
        .bind(version)
        .bind(jar_bytes.len() as i64)
        .bind(&sha256)
        .bind("application/java-archive")
        .bind(&storage_key)
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("insert artifact row");

        // Insert artifact_metadata so `resolve_snapshot_artifact`'s join finds
        // groupId+artifactId. The resolver SELECTs from artifact_metadata.
        sqlx::query(
            r#"
            INSERT INTO artifact_metadata (artifact_id, format, metadata)
            VALUES ($1, 'maven', jsonb_build_object(
                'groupId', $2::text, 'artifactId', $3::text, 'version', $4::text,
                'extension', 'jar'
            ))
            "#,
        )
        .bind(artifact_id_db)
        .bind(group_id)
        .bind(artifact_id)
        .bind(version)
        .execute(&pool)
        .await
        .expect("insert artifact_metadata");

        // -- Build the virtual repo with the hosted as its sole member.
        let virtual_id = Uuid::new_v4();
        let virtual_key = format!("v-snapj-1444-{}", virtual_id.simple());
        let virtual_dir = std::env::temp_dir().join(format!("snapj-1444-{}", virtual_id));
        std::fs::create_dir_all(&virtual_dir).expect("create virtual storage dir");
        sqlx::query(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
             VALUES ($1, $2, $3, $4, 'virtual'::repository_type, 'maven'::repository_format)",
        )
        .bind(virtual_id)
        .bind(&virtual_key)
        .bind(&virtual_key)
        .bind(virtual_dir.to_string_lossy().as_ref())
        .execute(&pool)
        .await
        .expect("insert virtual repo");
        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, 1)",
        )
        .bind(virtual_id)
        .bind(hosted_id)
        .execute(&pool)
        .await
        .expect("insert virtual member");

        // -- Build a state rooted at the hosted storage dir so the
        //    virtual-resolution callback can read the jar bytes back.
        let state = tdh::build_state(pool.clone(), hosted_dir.to_str().unwrap());
        let auth = tdh::make_auth(user_id, "snapj-1444-user");
        let router = tdh::router_with_auth(super::router(), state.clone(), auth);

        let alias_uri = format!(
            "/{}/{}/{}/{}/{}-{}.jar",
            virtual_key, group_path, artifact_id, version, artifact_id, version
        );
        let req = Request::builder()
            .method("GET")
            .uri(&alias_uri)
            .body(Body::empty())
            .expect("build GET alias jar");
        let (status, body) = tdh::send(router, req).await;

        // -- Cleanup first so a failed assert does not leak DB state.
        let _ = sqlx::query("DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1")
            .bind(virtual_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(virtual_id)
            .execute(&pool)
            .await;
        tdh::cleanup(&pool, hosted_id, user_id).await;
        let _ = std::fs::remove_dir_all(&hosted_dir);
        let _ = std::fs::remove_dir_all(&virtual_dir);

        assert_eq!(
            status,
            StatusCode::OK,
            "GET SNAPSHOT jar via -SNAPSHOT alias through virtual must return 200 \
             (regression of #1444 / #839). uri={} body={}",
            alias_uri,
            String::from_utf8_lossy(&body[..body.len().min(300)])
        );
        assert_eq!(
            &body[..],
            &jar_bytes[..],
            "virtual-served bytes must match the original jar content"
        );
    }

    // -----------------------------------------------------------------------
    // Router registration for the empty-artifact-path fix (#1880)
    // -----------------------------------------------------------------------

    /// Source-level pin for the root-probe routes added in #1880.
    ///
    /// In axum 0.7, `/:repo_key/*path` does NOT match when the path after the
    /// repo key is just a trailing slash.  Without the `/:repo_key` and
    /// `/:repo_key/` routes the framework returns a bare 404, meaning
    /// `GET /maven/<proxy-repo>/` is the only path in the proxy that does not
    /// forward to upstream.  These assertions guard against a future refactor
    /// accidentally removing the new routes.
    ///
    /// A full HTTP-level integration test is omitted because the proxy path
    /// requires a live upstream.  The routing assertions give us a lightweight
    /// regression signal without a network dependency.
    const MAVEN_HANDLER_SRC: &str = include_str!("maven.rs");

    #[test]
    fn root_probe_routes_are_registered() {
        assert!(
            MAVEN_HANDLER_SRC.contains(".route(\"/:repo_key\", get(download_root))"),
            "/:repo_key route missing — GET /maven/<repo>/ will 404 for all \
             repo types instead of proxying to upstream (regression of #1880)"
        );
        assert!(
            MAVEN_HANDLER_SRC.contains(".route(\"/:repo_key/\", get(download_root))"),
            "/:repo_key/ route missing — GET /maven/<repo>/ with trailing slash \
             will 404 for all repo types instead of proxying to upstream \
             (regression of #1880)"
        );
    }

    #[test]
    fn root_probe_handler_uses_root_cache_sentinel() {
        // The download_root handler must cache the upstream root response under
        // the non-empty sentinel path "_root_" rather than "" so that the proxy
        // service's validate_cache_path check does not reject it.  Pin the
        // string so a future edit cannot accidentally swap it for "" or "/".
        assert!(
            MAVEN_HANDLER_SRC.contains("\"_root_\""),
            "download_root must use \"_root_\" as the cache-path sentinel for \
             empty-path upstream fetches; validate_cache_path rejects empty \
             strings and \"\" or \"/\" would both fail that check"
        );
    }

    /// DB-backed behavioral test for `download_root` (#1880): an empty/root
    /// request is forwarded to the upstream root for REMOTE and VIRTUAL repos
    /// (200 from upstream) and returns NotFound for a hosted LOCAL repo. Skips
    /// cleanly without a DATABASE_URL (the `try_pool` convention).
    #[tokio::test]
    async fn test_download_root_forwards_remote_and_virtual_but_404s_local() {
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::extract::{Path, State};
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        // Upstream root index served by wiremock (any GET → the index body).
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("maven-root-index"))
            .mount(&mock)
            .await;

        // Remote member pointed at the mock.
        let (remote_id, remote_key, dir) = tdh::create_repo(&pool, "remote", "maven").await;
        sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
            .bind(mock.uri())
            .bind(remote_id)
            .execute(&pool)
            .await
            .expect("point remote upstream at mock");

        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), dir.to_str().unwrap());
        let state = tdh::build_state_with_proxy(pool.clone(), dir.to_str().unwrap(), proxy);

        async fn root_body(resp: axum::response::Response) -> bytes::Bytes {
            axum::body::to_bytes(resp.into_body(), 1 << 20)
                .await
                .expect("read body")
        }

        // REMOTE: GET /maven/<remote>/ → 200 from the upstream root.
        let remote_resp = download_root(State(state.clone()), Path(remote_key.clone()))
            .await
            .expect("remote root must proxy 200");
        assert_eq!(remote_resp.status(), axum::http::StatusCode::OK);
        assert_eq!(&root_body(remote_resp).await[..], b"maven-root-index");

        // VIRTUAL: a virtual repo with the remote as a member forwards the same.
        let (virtual_id, virtual_key, _vdir) = tdh::create_repo(&pool, "virtual", "maven").await;
        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, 0)",
        )
        .bind(virtual_id)
        .bind(remote_id)
        .execute(&pool)
        .await
        .expect("link remote as virtual member");
        let virtual_resp = download_root(State(state.clone()), Path(virtual_key.clone()))
            .await
            .expect("virtual root must proxy 200 from its remote member");
        assert_eq!(virtual_resp.status(), axum::http::StatusCode::OK);
        assert_eq!(&root_body(virtual_resp).await[..], b"maven-root-index");

        // LOCAL: a hosted repo does not forward an empty path → NotFound.
        let (local_id, local_key, _ldir) = tdh::create_repo(&pool, "local", "maven").await;
        let denied = download_root(State(state.clone()), Path(local_key.clone())).await;
        assert!(
            denied.is_err(),
            "local repo root must be NotFound, not forwarded upstream"
        );

        // cleanup (members cascade on repo delete).
        for id in [virtual_id, remote_id, local_id] {
            let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
                .bind(id)
                .execute(&pool)
                .await;
        }
    }

    // ── Coverage for fetch_maven_metadata_bytes (the centralized resolver) ──
    //
    // These DB-backed tests drive the `download` handler through the actual
    // axum extractors so they exercise `fetch_maven_metadata_bytes` for every
    // repo type. They guard the load-bearing invariant of the refactor:
    //
    //   the `.sha1`/`.sha256` served for `maven-metadata.xml` must equal the
    //   checksum of the metadata XML bytes that the SAME URL serves.
    //
    // Before #1922 the checksum path and the metadata path diverged (the
    // checksum was computed from a stored sidecar, the body was generated /
    // merged dynamically), so a virtual or merged repo could serve a `.sha1`
    // that did not match its own `maven-metadata.xml`. Centralizing both on
    // `fetch_maven_metadata_bytes` closes that gap; these tests pin it shut.
    //
    // All skip cleanly when `DATABASE_URL` is unset (the `try_pool`
    // convention). The CI coverage job (`cargo llvm-cov --lib` with a seeded
    // Postgres) runs them, so the resolver's new lines are instrumented.

    /// Insert an `artifacts` + `artifact_metadata` row so a hosted repo's
    /// `generate_metadata_for_artifact` query (and any version-sort) finds the
    /// version under `group_id`/`artifact_id`.
    async fn seed_maven_version(
        pool: &PgPool,
        repo_id: uuid::Uuid,
        user_id: uuid::Uuid,
        group_id: &str,
        artifact_id: &str,
        version: &str,
    ) {
        let aid = uuid::Uuid::new_v4();
        let path = format!(
            "{}/{}/{}/{}-{}.jar",
            group_id.replace('.', "/"),
            artifact_id,
            version,
            artifact_id,
            version
        );
        sqlx::query(
            r#"
            INSERT INTO artifacts
                (id, repository_id, path, name, version, size_bytes,
                 checksum_sha256, content_type, storage_key, uploaded_by, is_deleted)
            VALUES ($1, $2, $3, $4, $5, 1, $6, 'application/java-archive', $7, $8, false)
            "#,
        )
        .bind(aid)
        .bind(repo_id)
        .bind(&path)
        .bind(artifact_id)
        .bind(version)
        .bind("ab".repeat(32))
        .bind(format!("maven/{}", path))
        .bind(user_id)
        .execute(pool)
        .await
        .expect("seed artifact row");

        sqlx::query(
            r#"
            INSERT INTO artifact_metadata (artifact_id, format, metadata)
            VALUES ($1, 'maven', jsonb_build_object(
                'groupId', $2::text, 'artifactId', $3::text,
                'version', $4::text, 'extension', 'jar'
            ))
            "#,
        )
        .bind(aid)
        .bind(group_id)
        .bind(artifact_id)
        .bind(version)
        .execute(pool)
        .await
        .expect("seed artifact_metadata row");
    }

    /// Drive `download` for `<repo_key>/<meta_path>` and its `.<ext>` checksum
    /// sibling, returning `(metadata_bytes, served_checksum_string)`.
    async fn served_metadata_and_checksum(
        state: &SharedState,
        auth: &AuthExtension,
        repo_key: &str,
        meta_path: &str,
        ext: &str,
    ) -> (bytes::Bytes, String) {
        use axum::extract::{Path, State};
        use axum::Extension;

        let meta_resp = download(
            State(state.clone()),
            Extension(Some(auth.clone())),
            Path((repo_key.to_string(), meta_path.to_string())),
        )
        .await
        .expect("metadata download must succeed");
        assert_eq!(
            meta_resp.status(),
            axum::http::StatusCode::OK,
            "metadata GET must be 200"
        );
        let meta_bytes = axum::body::to_bytes(meta_resp.into_body(), 1 << 20)
            .await
            .expect("read metadata body");

        let csum_resp = download(
            State(state.clone()),
            Extension(Some(auth.clone())),
            Path((repo_key.to_string(), format!("{}.{}", meta_path, ext))),
        )
        .await
        .expect("checksum download must succeed");
        assert_eq!(
            csum_resp.status(),
            axum::http::StatusCode::OK,
            "checksum GET must be 200"
        );
        let csum_bytes = axum::body::to_bytes(csum_resp.into_body(), 1 << 20)
            .await
            .expect("read checksum body");
        let csum = String::from_utf8(csum_bytes.to_vec()).expect("checksum is utf-8");
        (meta_bytes, csum.trim().to_string())
    }

    /// LOCAL repo: the served `.sha1`/`.sha256` for `maven-metadata.xml` must
    /// equal the checksum of the served (dynamically-generated) metadata bytes.
    #[tokio::test]
    async fn test_resolver_local_metadata_checksum_matches_body_1922() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let (repo_id, repo_key, dir) = tdh::create_repo(&pool, "local", "maven").await;
        let (user_id, username) = tdh::create_user(&pool).await;
        tdh::grant_repo_access(&pool, repo_id, user_id).await;

        let group_id = "com.example.cov1922local";
        let artifact_id = "lib";
        seed_maven_version(&pool, repo_id, user_id, group_id, artifact_id, "1.0.0").await;
        seed_maven_version(&pool, repo_id, user_id, group_id, artifact_id, "1.1.0").await;

        let state = tdh::build_state(pool.clone(), dir.to_str().unwrap());
        let auth = tdh::make_auth(user_id, &username);
        let meta_path = format!(
            "{}/{}/maven-metadata.xml",
            group_id.replace('.', "/"),
            artifact_id
        );

        let (sha1_body, sha1) =
            served_metadata_and_checksum(&state, &auth, &repo_key, &meta_path, "sha1").await;
        let (sha256_body, sha256) =
            served_metadata_and_checksum(&state, &auth, &repo_key, &meta_path, "sha256").await;

        tdh::cleanup(&pool, repo_id, user_id).await;
        let _ = std::fs::remove_dir_all(&dir);

        // The generated metadata must actually carry the versions we seeded.
        let body_str = String::from_utf8_lossy(&sha1_body);
        assert!(
            body_str.contains("1.0.0") && body_str.contains("1.1.0"),
            "local metadata must list seeded versions; got: {}",
            body_str
        );
        assert_eq!(
            sha1,
            compute_checksum(&sha1_body, ChecksumType::Sha1),
            "local .sha1 must equal sha1 of the served metadata body (#1922)"
        );
        assert_eq!(
            sha256,
            compute_checksum(&sha256_body, ChecksumType::Sha256),
            "local .sha256 must equal sha256 of the served metadata body (#1922)"
        );
    }

    /// VIRTUAL repo over two LOCAL members: the served checksum must match the
    /// MERGED metadata body. This is the case the refactor most directly fixes
    /// — the merged body is generated on the fly, so a stored sidecar could
    /// never have matched it.
    #[tokio::test]
    async fn test_resolver_virtual_merged_metadata_checksum_matches_body_1922() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let (member_a, _ka, dir_a) = tdh::create_repo(&pool, "local", "maven").await;
        let (member_b, _kb, dir_b) = tdh::create_repo(&pool, "local", "maven").await;
        let (user_id, username) = tdh::create_user(&pool).await;

        let group_id = "com.example.cov1922virt";
        let artifact_id = "lib";
        // Each member carries a DISJOINT version so the merge is observable.
        seed_maven_version(&pool, member_a, user_id, group_id, artifact_id, "1.0.0").await;
        seed_maven_version(&pool, member_b, user_id, group_id, artifact_id, "2.0.0").await;

        // Virtual repo with both locals as members.
        let virtual_id = uuid::Uuid::new_v4();
        let virtual_key = format!("v-cov1922-{}", virtual_id.simple());
        let virtual_dir = std::env::temp_dir().join(format!("cov1922-virt-{}", virtual_id));
        std::fs::create_dir_all(&virtual_dir).expect("create virtual dir");
        sqlx::query(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
             VALUES ($1, $2, $3, $4, 'virtual'::repository_type, 'maven'::repository_format)",
        )
        .bind(virtual_id)
        .bind(&virtual_key)
        .bind(&virtual_key)
        .bind(virtual_dir.to_string_lossy().as_ref())
        .execute(&pool)
        .await
        .expect("insert virtual repo");
        for (i, m) in [member_a, member_b].iter().enumerate() {
            sqlx::query(
                "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
                 VALUES ($1, $2, $3)",
            )
            .bind(virtual_id)
            .bind(m)
            .bind(i as i32)
            .execute(&pool)
            .await
            .expect("insert virtual member");
        }

        let state = tdh::build_state(pool.clone(), dir_a.to_str().unwrap());
        let auth = tdh::make_auth(user_id, &username);
        let meta_path = format!(
            "{}/{}/maven-metadata.xml",
            group_id.replace('.', "/"),
            artifact_id
        );

        let (sha1_body, sha1) =
            served_metadata_and_checksum(&state, &auth, &virtual_key, &meta_path, "sha1").await;
        let (sha256_body, sha256) =
            served_metadata_and_checksum(&state, &auth, &virtual_key, &meta_path, "sha256").await;

        // cleanup (members cascade; explicit deletes for the extras).
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(virtual_id)
            .execute(&pool)
            .await;
        tdh::cleanup(&pool, member_a, user_id).await;
        tdh::cleanup(&pool, member_b, user_id).await;
        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
        let _ = std::fs::remove_dir_all(&virtual_dir);

        // The merged body must contain BOTH members' versions — proving the
        // merge path (not a single-member shortcut) produced these bytes.
        let body_str = String::from_utf8_lossy(&sha1_body);
        assert!(
            body_str.contains("1.0.0") && body_str.contains("2.0.0"),
            "virtual metadata must merge both members' versions; got: {}",
            body_str
        );
        assert_eq!(
            sha1,
            compute_checksum(&sha1_body, ChecksumType::Sha1),
            "virtual .sha1 must equal sha1 of the merged metadata body (#1922)"
        );
        assert_eq!(
            sha256,
            compute_checksum(&sha256_body, ChecksumType::Sha256),
            "virtual .sha256 must equal sha256 of the merged metadata body (#1922)"
        );
    }

    /// REMOTE repo: the served checksum must match the upstream metadata body
    /// the resolver proxied (the resolver computes the checksum from the same
    /// bytes it serves, so an upstream that ships a mismatched `.sha1` no
    /// longer leaks through). Uses a wiremock upstream — no real egress.
    #[tokio::test]
    async fn test_resolver_remote_metadata_checksum_matches_body_1922() {
        use crate::api::handlers::test_db_helpers as tdh;
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let group_id = "com.example.cov1922remote";
        let artifact_id = "lib";
        let meta_path = format!(
            "{}/{}/maven-metadata.xml",
            group_id.replace('.', "/"),
            artifact_id
        );
        // The upstream serves a real metadata document for the .xml request.
        let upstream_meta = generate_metadata_xml(
            group_id,
            artifact_id,
            &["1.0.0".to_string(), "1.1.0".to_string()],
            "1.1.0",
            Some("1.1.0"),
        );

        let mock = MockServer::start().await;
        // Upstream deliberately serves a WRONG sidecar `.sha1` to prove the
        // resolver recomputes from the body rather than forwarding it.
        Mock::given(method("GET"))
            .and(path_regex(r".*maven-metadata\.xml\.sha1$"))
            .respond_with(ResponseTemplate::new(200).set_body_string("0000bogussha1value0000"))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(r".*maven-metadata\.xml$"))
            .respond_with(ResponseTemplate::new(200).set_body_string(upstream_meta.clone()))
            .mount(&mock)
            .await;

        let (remote_id, remote_key, dir) = tdh::create_repo(&pool, "remote", "maven").await;
        sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
            .bind(mock.uri())
            .bind(remote_id)
            .execute(&pool)
            .await
            .expect("point remote upstream at mock");
        let (user_id, username) = tdh::create_user(&pool).await;
        tdh::grant_repo_access(&pool, remote_id, user_id).await;

        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), dir.to_str().unwrap());
        let state = tdh::build_state_with_proxy(pool.clone(), dir.to_str().unwrap(), proxy);
        let auth = tdh::make_auth(user_id, &username);

        let (sha1_body, sha1) =
            served_metadata_and_checksum(&state, &auth, &remote_key, &meta_path, "sha1").await;

        tdh::cleanup(&pool, remote_id, user_id).await;
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(
            String::from_utf8_lossy(&sha1_body),
            upstream_meta,
            "remote metadata body must be the proxied upstream document"
        );
        assert_eq!(
            sha1,
            compute_checksum(&sha1_body, ChecksumType::Sha1),
            "remote .sha1 must be recomputed from the served body, NOT the \
             upstream's (bogus) sidecar (#1922)"
        );
        assert_ne!(
            sha1, "0000bogussha1value0000",
            "resolver must not forward the upstream's mismatched sidecar"
        );
    }

    /// #1562: a virtual repo must serve an artifact that one of its REMOTE
    /// members can proxy-fetch on first request, even when no local member
    /// holds it (e.g. a remote-only parent POM like `io.confluent:common`).
    /// Reproduces the reported 404: a `.pom` that the remote member serves
    /// 200 directly must also resolve 200 through the virtual, with a
    /// non-remote (local) member listed at higher priority that does NOT
    /// hold the artifact.
    ///
    /// The `serve_artifact` virtual branch routes Remote members through
    /// `resolve_virtual_download_from_members` ->
    /// `ProxyService::fetch_artifact_streaming` — the same helper the direct
    /// Remote path uses — so the fall-through to the remote member must
    /// stream the upstream POM rather than 404. This test pins that
    /// behaviour so the buffered-helper regression cannot return.
    #[tokio::test]
    async fn test_virtual_serves_remote_only_pom_through_local_priority_member_1562() {
        use crate::api::handlers::test_db_helpers as tdh;
        use axum::extract::{Path, State};
        use axum::Extension;
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        // Remote-only artifact path (a parent POM not cached anywhere local).
        let pom_path = "io/confluent/common/5.3.1/common-5.3.1.pom";
        let pom_body = "<project><artifactId>common</artifactId></project>";

        // Upstream serves the POM for the exact path; 404 for anything else.
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(pom_body))
            .mount(&mock)
            .await;

        // Remote member pointed at the mock. Deliberately PRIVATE to mirror a
        // proxy of an upstream that the operator has not marked public; the
        // direct-read middleware still allows an authenticated caller via the
        // looser `is_public || has_auth` model.
        let (remote_id, _remote_key, dir) = tdh::create_repo(&pool, "remote", "maven").await;
        sqlx::query("UPDATE repositories SET upstream_url = $1, is_public = false WHERE id = $2")
            .bind(mock.uri())
            .bind(remote_id)
            .execute(&pool)
            .await
            .expect("point remote upstream at mock");

        // Local member that does NOT hold the artifact, listed at higher
        // priority than the remote so the loop must fall through to it.
        let (local_id, _local_key, _ldir) = tdh::create_repo(&pool, "local", "maven").await;
        sqlx::query("UPDATE repositories SET is_public = true WHERE id = $1")
            .bind(local_id)
            .execute(&pool)
            .await
            .expect("make local member public");

        // Virtual repo with [local (prio 1), remote (prio 2)].
        let (virtual_id, virtual_key, _vdir) = tdh::create_repo(&pool, "virtual", "maven").await;
        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, 1), ($1, $3, 2)",
        )
        .bind(virtual_id)
        .bind(local_id)
        .bind(remote_id)
        .execute(&pool)
        .await
        .expect("link local (prio 1) and remote (prio 2) as virtual members");

        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), dir.to_str().unwrap());
        let state = tdh::build_state_with_proxy(pool.clone(), dir.to_str().unwrap(), proxy);

        // An ordinary authenticated caller (JWT/session: not repo-scoped).
        let auth = tdh::make_auth(uuid::Uuid::new_v4(), "ph-1562-user");

        // The caller through the virtual must resolve 200 from the remote
        // member (the artifact lives only there).
        let resp = download(
            State(state.clone()),
            Extension(Some(auth)),
            Path((virtual_key.clone(), pom_path.to_string())),
        )
        .await;

        // cleanup (members cascade on repo delete).
        for id in [virtual_id, remote_id, local_id] {
            let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
                .bind(id)
                .execute(&pool)
                .await;
        }
        let _ = std::fs::remove_dir_all(&dir);

        let resp = resp.expect("virtual must serve the remote-only POM, not 404 (#1562)");
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "virtual repo must proxy the remote-only POM with 200 (#1562)"
        );
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("read body");
        assert_eq!(
            &body[..],
            pom_body.as_bytes(),
            "virtual must return the upstream POM bytes (#1562)"
        );
    }
}

#[cfg(test)]
mod remote_skip_tests {
    use crate::api::handlers::test_db_helpers as tdh;

    // Remote (proxy) repos never persist rows in `artifacts` (the proxy cache
    // writes to the package catalog + filesystem only, #1278), so serve_artifact
    // must skip the artifacts-table lookup for them. Proof: seed an `artifacts`
    // row for a REMOTE repo, then GET it with no proxy service configured. The
    // pre-fix code consulted the table and served the seeded row (200); the fix
    // skips the lookup and falls through to a not-found (non-200).
    #[tokio::test]
    async fn test_serve_artifact_remote_skips_artifacts_lookup() {
        let Some(fx) = tdh::Fixture::setup("remote", "maven").await else {
            return;
        };
        let repo = fx.repo_info("remote", Some("https://upstream.example.test"));
        let path = "com/example/lib/1.0/lib-1.0.jar";
        tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &repo,
            "pr2-remote-skip",
            path,
            "lib",
            "1.0",
            "application/java-archive",
            bytes::Bytes::from_static(b"seeded"),
            fx.user_id,
        )
        .await;
        let app = fx.router_with_auth(super::router());
        let (status, _) = tdh::send(app, tdh::get(format!("/{}/{}", fx.repo_key, path))).await;
        assert_ne!(
            status,
            axum::http::StatusCode::OK,
            "Remote repo must not serve rows from the artifacts table; the lookup should be skipped"
        );
        fx.teardown().await;
    }

    // Hosted repos still resolve the `-SNAPSHOT` alias to the timestamped file
    // Maven actually deploys. Seed the timestamped artifact, request the
    // `-SNAPSHOT` alias, and assert serve_artifact resolves + streams it. This
    // exercises the SNAPSHOT-resolution branch that the Remote skip wraps.
    #[tokio::test]
    async fn test_serve_artifact_snapshot_alias_resolves_and_serves() {
        let Some(fx) = tdh::Fixture::setup("local", "maven").await else {
            return;
        };
        let repo = fx.repo_info("local", None);
        let stored = "com/example/lib/1.0-SNAPSHOT/lib-1.0-20260101.120000-1.jar";
        tdh::seed_artifact(
            &fx.state,
            &fx.pool,
            &repo,
            "pr2-snapshot-key",
            stored,
            "lib",
            "1.0-SNAPSHOT",
            "application/java-archive",
            bytes::Bytes::from_static(b"snap-bytes"),
            fx.user_id,
        )
        .await;
        let alias = "com/example/lib/1.0-SNAPSHOT/lib-1.0-SNAPSHOT.jar";
        let app = fx.router_with_auth(super::router());
        let (status, body) = tdh::send(app, tdh::get(format!("/{}/{}", fx.repo_key, alias))).await;
        assert_eq!(status, axum::http::StatusCode::OK);
        assert_eq!(&body[..], b"snap-bytes");
        fx.teardown().await;
    }
}
