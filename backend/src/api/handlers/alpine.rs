//! Alpine/APK repository API handlers.
//!
//! Implements the endpoints required for `apk` package management.
//!
//! Routes are mounted at `/alpine/{repo_key}/...`:
//!   GET  /alpine/{repo_key}/{branch}/{repository}/{arch}/APKINDEX.tar.gz  - Package index
//!   GET  /alpine/{repo_key}/{branch}/{repository}/{arch}/{filename}.apk   - Download package
//!   PUT  /alpine/{repo_key}/{branch}/{repository}/{arch}/{filename}.apk   - Upload package
//!   POST /alpine/{repo_key}/upload                                        - Upload package (alternative)

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Extension;
use axum::Router;
use base64::Engine as _;
use bytes::Bytes;
use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::io::Read;
use tracing::info;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::SharedState;
use crate::models::repository::RepositoryType;
use crate::services::signing_service::SigningService;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // APKINDEX endpoint
        .route(
            "/:repo_key/:branch/:repository/:arch/APKINDEX.tar.gz",
            get(apk_index),
        )
        // Package download and upload
        .route(
            "/:repo_key/:branch/:repository/:arch/:filename",
            get(download_package).put(upload_package_put),
        )
        // Alternative upload endpoint
        .route("/:repo_key/upload", post(upload_package_post))
        // Public key endpoint for signature verification
        .route(
            "/:repo_key/:branch/keys/artifact-keeper.rsa.pub",
            get(public_key),
        )
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_alpine_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["alpine", "apk"], "an Alpine").await
}

// ---------------------------------------------------------------------------
// APK filename parsing
// ---------------------------------------------------------------------------

/// Parse an APK filename into (name, version).
/// Expected format: `{name}-{version}.apk`
/// Version starts at the first hyphen followed by a digit.
///
/// Examples:
///   curl-8.5.0-r0.apk   -> ("curl", "8.5.0-r0")
///   my-app-1.2.3-r1.apk -> ("my-app", "1.2.3-r1")
fn parse_apk_filename(filename: &str) -> Option<(String, String)> {
    let stem = filename.strip_suffix(".apk")?;

    // Find version boundary: first hyphen followed by a digit
    let chars: Vec<char> = stem.chars().collect();
    for i in 1..chars.len() {
        if chars[i - 1] == '-' && chars[i].is_ascii_digit() {
            let name = &stem[..i - 1];
            let version = &stem[i..];
            if !name.is_empty() && !version.is_empty() {
                return Some((name.to_string(), version.to_string()));
            }
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Artifact query helper
// ---------------------------------------------------------------------------

#[allow(dead_code)]
struct AlpineArtifact {
    id: uuid::Uuid,
    path: String,
    name: String,
    version: Option<String>,
    size_bytes: i64,
    checksum_sha256: String,
    storage_key: String,
    metadata: Option<serde_json::Value>,
}

async fn list_alpine_artifacts(
    db: &PgPool,
    repo_id: uuid::Uuid,
    branch: &str,
    repository: &str,
    arch: &str,
) -> Result<Vec<AlpineArtifact>, Response> {
    let path_prefix = super::escape_path_prefix(&[branch, repository, arch]);
    let rows = sqlx::query!(
        r#"
        SELECT a.id, a.path, a.name, a.version, a.size_bytes, a.checksum_sha256,
               a.storage_key, am.metadata as "metadata?"
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND a.path LIKE $2 || '%' ESCAPE '\'
        ORDER BY a.name, a.created_at DESC
        "#,
        repo_id,
        path_prefix
    )
    .fetch_all(db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    Ok(rows
        .into_iter()
        .map(|r| AlpineArtifact {
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

// ---------------------------------------------------------------------------
// .apk package parsing
// ---------------------------------------------------------------------------

/// Maximum inflated size accepted for an `.apk` segment while looking for the
/// control segment. The control segment only carries `.PKGINFO` plus install
/// scripts, so anything bigger is not one; the cap keeps a crafted upload from
/// exhausting memory here.
const APK_MAX_SEGMENT_INFLATED_BYTES: usize = 4 * 1024 * 1024;

/// Number of leading gzip segments searched for `.PKGINFO`. An apk v2 package is
/// `[signature segment] control segment data segment`, so the control segment is
/// always one of the first two — the same assumption apk-tools makes. Stopping
/// there also means the (potentially huge) data segment is never inflated.
const APK_MAX_SEGMENTS_SCANNED: usize = 2;

/// Fields read out of an `.apk` `.PKGINFO`.
#[derive(Debug, Default, Clone, PartialEq)]
struct ApkPkgInfo {
    /// Uncompressed size of the installed files (`size`), the APKINDEX `I:` field.
    installed_size: Option<i64>,
    description: Option<String>,
    url: Option<String>,
    license: Option<String>,
    origin: Option<String>,
    maintainer: Option<String>,
    build_time: Option<i64>,
    commit: Option<String>,
    depends: Vec<String>,
    provides: Vec<String>,
}

/// What the index generator needs from an uploaded `.apk`.
#[derive(Debug, Clone, PartialEq)]
struct ApkPackageInfo {
    /// apk-native package checksum for the APKINDEX `C:` field.
    checksum: String,
    pkginfo: ApkPkgInfo,
}

/// Inflate one gzip member from the front of `data`.
///
/// Returns how many *compressed* bytes the member occupies along with its
/// inflated contents. An `.apk` is a run of concatenated gzip members and the
/// apk-native checksum is taken over the raw compressed bytes of one of them,
/// so the exact member length matters.
fn read_gzip_member(data: &[u8]) -> Option<(usize, Vec<u8>)> {
    let mut decoder = flate2::bufread::GzDecoder::new(data);
    let mut inflated = Vec::new();
    {
        // Uploaded packages are untrusted input: bound the inflated size rather
        // than reading the member to its end unconditionally.
        let mut capped = Read::take(&mut decoder, APK_MAX_SEGMENT_INFLATED_BYTES as u64 + 1);
        capped.read_to_end(&mut inflated).ok()?;
    }
    if inflated.len() > APK_MAX_SEGMENT_INFLATED_BYTES {
        return None;
    }
    // `GzDecoder` stops at the end of a single member, so whatever it left in the
    // inner reader marks the member boundary.
    let remaining = decoder.into_inner();
    let consumed = data.len().checked_sub(remaining.len())?;
    if consumed == 0 {
        return None;
    }
    Some((consumed, inflated))
}

/// Read `.PKGINFO` out of an inflated control-segment tar.
fn pkginfo_from_tar(inflated: &[u8]) -> Option<String> {
    let mut archive = tar::Archive::new(inflated);
    for entry in archive.entries().ok()? {
        let mut entry = entry.ok()?;
        let is_pkginfo = entry
            .path()
            .map(|p| p.ends_with(".PKGINFO"))
            .unwrap_or(false);
        if is_pkginfo {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).ok()?;
            return Some(String::from_utf8_lossy(&buf).into_owned());
        }
    }
    None
}

/// Locate the control segment of an `.apk`: the gzip member whose tar holds
/// `.PKGINFO`. Returns its raw compressed bytes together with the `.PKGINFO` text.
fn apk_control_segment(data: &[u8]) -> Option<(&[u8], String)> {
    let mut offset = 0usize;
    for _ in 0..APK_MAX_SEGMENTS_SCANNED {
        if offset >= data.len() {
            break;
        }
        let (len, inflated) = read_gzip_member(&data[offset..])?;
        if let Some(pkginfo) = pkginfo_from_tar(&inflated) {
            return Some((&data[offset..offset + len], pkginfo));
        }
        offset += len;
    }
    None
}

/// Compute the apk-native package checksum: `Q1` + base64(SHA1(control segment)).
///
/// apk-tools stores this in the index `C:` field and recomputes it from the
/// downloaded package to identify it. The digest is taken over the raw
/// *compressed* bytes of the control segment (gzip header and trailer included),
/// which is what `apk index` produces for the same package.
fn apk_control_checksum(control_segment: &[u8]) -> String {
    let mut hasher = sha1::Sha1::new();
    sha1::Digest::update(&mut hasher, control_segment);
    let digest = sha1::Digest::finalize(hasher);
    format!(
        "Q1{}",
        base64::engine::general_purpose::STANDARD.encode(digest)
    )
}

/// Parse the `key = value` lines of an `.apk` `.PKGINFO`.
fn parse_pkginfo(text: &str) -> ApkPkgInfo {
    let mut info = ApkPkgInfo::default();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        if value.is_empty() {
            continue;
        }

        match key {
            "size" => info.installed_size = value.parse().ok(),
            "pkgdesc" => info.description = Some(value.to_string()),
            "url" => info.url = Some(value.to_string()),
            "license" => info.license = Some(value.to_string()),
            "origin" => info.origin = Some(value.to_string()),
            "maintainer" => info.maintainer = Some(value.to_string()),
            "builddate" => info.build_time = value.parse().ok(),
            "commit" => info.commit = Some(value.to_string()),
            // `depend`/`provides` may each appear multiple times; APKINDEX joins
            // them into a single space-separated field.
            "depend" => info.depends.push(value.to_string()),
            "provides" => info.provides.push(value.to_string()),
            _ => {}
        }
    }

    info
}

/// Parse an uploaded `.apk` into the metadata the APKINDEX needs.
///
/// Returns `None` when the bytes are not a readable apk v2 package (no control
/// segment); callers treat that as "no index metadata" rather than an error.
fn parse_apk_package(data: &[u8]) -> Option<ApkPackageInfo> {
    let (control_segment, pkginfo_text) = apk_control_segment(data)?;
    Some(ApkPackageInfo {
        checksum: apk_control_checksum(control_segment),
        pkginfo: parse_pkginfo(&pkginfo_text),
    })
}

// ---------------------------------------------------------------------------
// APKINDEX generation
// ---------------------------------------------------------------------------

/// Generate APKINDEX text content from artifact entries.
///
/// Each package entry has the format:
/// ```text
/// C:<apk checksum: Q1 + base64(SHA1(control segment))>
/// P:<pkgname>
/// V:<version>
/// A:<arch>
/// S:<size on disk>
/// I:<installed_size>
/// T:<description>
/// U:<url>
/// L:<license>
/// o:<origin>
/// m:<maintainer>
/// t:<build time>
/// c:<commit>
/// D:<dependencies>
/// p:<provides>
///
/// ```
///
/// Entries without a stored apk checksum are skipped: apk-tools rejects an index
/// it cannot parse a `C:` value from, so emitting such an entry would make the
/// whole repository unusable instead of just that one package.
fn generate_apkindex_text(artifacts: &[AlpineArtifact], arch: &str) -> String {
    let mut text = String::new();

    for artifact in artifacts {
        let filename = artifact.path.rsplit('/').next().unwrap_or(&artifact.path);

        // Extract metadata from artifact_metadata if available, else parse filename
        let (name, version) = if let Some(ref meta) = artifact.metadata {
            (
                meta.get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&artifact.name)
                    .to_string(),
                meta.get("version")
                    .and_then(|v| v.as_str())
                    .or(artifact.version.as_deref())
                    .unwrap_or("0")
                    .to_string(),
            )
        } else if let Some((n, v)) = parse_apk_filename(filename) {
            (n, v)
        } else {
            (
                artifact.name.clone(),
                artifact.version.clone().unwrap_or_else(|| "0".to_string()),
            )
        };

        let description = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("description"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let url = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("url"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let license = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("license"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let depends = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("depends"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let installed_size = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("installed_size"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // The `C:` value is the apk-native package checksum recorded at upload
        // (`Q1` + base64(SHA1(control segment))). Without it apk-tools cannot key
        // the entry, so leave the package out of the index rather than emitting
        // something it will reject.
        let Some(checksum) = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("apk_checksum"))
            .and_then(|v| v.as_str())
            .filter(|c| !c.is_empty())
        else {
            tracing::warn!(
                artifact_id = %artifact.id,
                path = %artifact.path,
                "skipping Alpine package with no apk checksum in metadata"
            );
            continue;
        };

        text.push_str(&format!("C:{}\n", checksum));
        text.push_str(&format!("P:{}\n", name));
        text.push_str(&format!("V:{}\n", version));
        text.push_str(&format!("A:{}\n", arch));
        text.push_str(&format!("S:{}\n", artifact.size_bytes));
        text.push_str(&format!("I:{}\n", installed_size));
        text.push_str(&format!("T:{}\n", description));
        text.push_str(&format!("U:{}\n", url));
        text.push_str(&format!("L:{}\n", license));
        push_optional_field(&mut text, 'o', artifact.metadata.as_ref(), "origin");
        push_optional_field(&mut text, 'm', artifact.metadata.as_ref(), "maintainer");
        if let Some(build_time) = artifact
            .metadata
            .as_ref()
            .and_then(|m| m.get("build_time"))
            .and_then(|v| v.as_i64())
        {
            text.push_str(&format!("t:{}\n", build_time));
        }
        push_optional_field(&mut text, 'c', artifact.metadata.as_ref(), "commit");
        if !depends.is_empty() {
            text.push_str(&format!("D:{}\n", depends));
        }
        push_optional_field(&mut text, 'p', artifact.metadata.as_ref(), "provides");
        text.push('\n');
    }

    text
}

/// Append `<key>:<value>` for a non-empty string field of the artifact metadata.
fn push_optional_field(
    text: &mut String,
    key: char,
    metadata: Option<&serde_json::Value>,
    field: &str,
) {
    if let Some(value) = metadata
        .and_then(|m| m.get(field))
        .and_then(|v| v.as_str())
        .filter(|v| !v.is_empty())
    {
        text.push_str(&format!("{}:{}\n", key, value));
    }
}

/// Create an APKINDEX.tar.gz from the text content with an optional RSA signature.
///
/// When `signature` is `Some`, the archive contains:
///   1. `.SIGN.RSA.artifact-keeper.rsa.pub` — raw RSA signature bytes
///   2. `APKINDEX` — the package index
///
/// When `signature` is `None`, only the `APKINDEX` entry is included.
#[allow(clippy::result_large_err)]
fn create_apkindex_tar_gz(
    apkindex_text: &str,
    signature: Option<&[u8]>,
) -> Result<Vec<u8>, Response> {
    let gz_buf = Vec::new();
    let gz_encoder = GzEncoder::new(gz_buf, Compression::default());
    let mut tar_builder = tar::Builder::new(gz_encoder);

    let mtime = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // If a signature is available, add .SIGN file FIRST (apk verifies order)
    if let Some(sig_bytes) = signature {
        let mut sig_header = tar::Header::new_gnu();
        sig_header
            .set_path(".SIGN.RSA.artifact-keeper.rsa.pub")
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to set tar path for signature: {}", e),
                )
                    .into_response()
            })?;
        sig_header.set_size(sig_bytes.len() as u64);
        sig_header.set_mode(0o644);
        sig_header.set_mtime(mtime);
        // A bare GNU header defaults to a NUL typeflag; apk-tools only accepts
        // index entries that are marked as regular files.
        sig_header.set_entry_type(tar::EntryType::Regular);
        sig_header.set_cksum();

        tar_builder.append(&sig_header, sig_bytes).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to append signature to tar: {}", e),
            )
                .into_response()
        })?;
    }

    let content_bytes = apkindex_text.as_bytes();
    let mut header = tar::Header::new_gnu();
    header.set_path("APKINDEX").map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to set tar path: {}", e),
        )
            .into_response()
    })?;
    header.set_size(content_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(mtime);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();

    tar_builder.append(&header, content_bytes).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to append to tar: {}", e),
        )
            .into_response()
    })?;

    let gz_encoder = tar_builder.into_inner().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to finalize tar: {}", e),
        )
            .into_response()
    })?;

    gz_encoder.finish().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to finalize gzip: {}", e),
        )
            .into_response()
    })
}

// ---------------------------------------------------------------------------
// GET /alpine/{repo_key}/{branch}/{repository}/{arch}/APKINDEX.tar.gz
// ---------------------------------------------------------------------------

async fn apk_index(
    State(state): State<SharedState>,
    Path((repo_key, branch, repository, arch)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_alpine_repo(&state.db, &repo_key).await?;

    // For remote repos, proxy the APKINDEX.tar.gz from upstream as-is so that
    // the upstream cryptographic signatures are preserved. Generating a local
    // index would break apk's signature verification.
    if repo.repo_type == RepositoryType::Remote {
        if let (Some(ref upstream_url), Some(ref proxy)) =
            (&repo.upstream_url, &state.proxy_service)
        {
            let upstream_path = build_apk_index_upstream_path(&branch, &repository, &arch);
            let (content, content_type) = proxy_helpers::proxy_fetch_capped(
                proxy,
                repo.id,
                &repo_key,
                upstream_url,
                &upstream_path,
                proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
            )
            .await?;

            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(
                    CONTENT_TYPE,
                    content_type.unwrap_or_else(|| "application/gzip".to_string()),
                )
                .header(CONTENT_LENGTH, content.len().to_string())
                .body(Body::from(content))
                .unwrap());
        }
    }

    // For virtual repos, try each remote member in priority order so that
    // upstream-signed indexes are returned when available.
    if repo.repo_type == RepositoryType::Virtual {
        let upstream_path = build_apk_index_upstream_path(&branch, &repository, &arch);
        let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;

        for member in &members {
            if member.repo_type != RepositoryType::Remote {
                continue;
            }
            let Some(ref upstream_url) = member.upstream_url else {
                continue;
            };
            let Some(ref proxy) = state.proxy_service else {
                continue;
            };

            let result = proxy_helpers::proxy_fetch_capped(
                proxy,
                member.id,
                &member.key,
                upstream_url,
                &upstream_path,
                proxy_helpers::DEFAULT_METADATA_MAX_BYTES,
            )
            .await;

            match result {
                Ok((content, content_type)) => {
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(
                            CONTENT_TYPE,
                            content_type.unwrap_or_else(|| "application/gzip".to_string()),
                        )
                        .header(CONTENT_LENGTH, content.len().to_string())
                        .body(Body::from(content))
                        .unwrap());
                }
                Err(_e) => {
                    tracing::debug!(
                        member_key = %member.key,
                        "APKINDEX proxy fetch failed for virtual member, trying next"
                    );
                    continue;
                }
            }
        }
    }

    // Hosted repos (and virtual fallback): generate APKINDEX from local artifacts.
    // TODO: For virtual repos this fallback queries `repo.id` (the virtual repo itself),
    // which won't find artifacts stored under hosted members. A follow-up should aggregate
    // artifacts from all hosted members of the virtual repo.
    let mut artifacts =
        list_alpine_artifacts(&state.db, repo.id, &branch, &repository, &arch).await?;

    backfill_apk_metadata(&state, &repo, &mut artifacts).await;

    let apkindex_text = generate_apkindex_text(&artifacts, &arch);

    // Sign the APKINDEX content if signing is configured for this repository
    let signing_svc = SigningService::new(state.db.clone(), &state.config.jwt_secret);
    let signature = signing_svc
        .sign_data(repo.id, apkindex_text.as_bytes())
        .await
        .unwrap_or(None);

    let tar_gz = create_apkindex_tar_gz(&apkindex_text, signature.as_deref())?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/gzip")
        .header(CONTENT_LENGTH, tar_gz.len().to_string())
        .body(Body::from(tar_gz))
        .unwrap())
}

/// Whether an artifact already carries the apk-native checksum in its metadata.
fn has_apk_checksum(artifact: &AlpineArtifact) -> bool {
    artifact
        .metadata
        .as_ref()
        .and_then(|m| m.get("apk_checksum"))
        .and_then(|v| v.as_str())
        .is_some_and(|c| !c.is_empty())
}

/// Derive the missing index metadata for packages stored before it was recorded
/// at upload time, so they are not silently dropped from the index.
///
/// The values are read back from the stored package and persisted, making this a
/// one-off cost per artifact. Failures are logged and leave the artifact
/// unindexed rather than failing the whole index request.
async fn backfill_apk_metadata(
    state: &SharedState,
    repo: &RepoInfo,
    artifacts: &mut [AlpineArtifact],
) {
    if artifacts.iter().all(has_apk_checksum) {
        return;
    }

    let storage = match state.storage_for_repo(&repo.storage_location()) {
        Ok(storage) => storage,
        Err(e) => {
            tracing::warn!("Alpine index backfill: storage unavailable: {}", e);
            return;
        }
    };

    for artifact in artifacts.iter_mut().filter(|a| !has_apk_checksum(a)) {
        let content = match storage.get(&artifact.storage_key).await {
            Ok(content) => content,
            Err(e) => {
                tracing::warn!(
                    "Alpine index backfill: cannot read {}: {}",
                    artifact.storage_key,
                    e
                );
                continue;
            }
        };
        let Some(apk_info) = parse_apk_package(&content) else {
            tracing::warn!(
                "Alpine index backfill: no apk control segment in {}",
                artifact.path
            );
            continue;
        };

        let mut metadata = artifact
            .metadata
            .clone()
            .unwrap_or_else(|| serde_json::json!({}));
        let Some(map) = metadata.as_object_mut() else {
            continue;
        };
        map.extend(apk_info_metadata_fields(&apk_info));

        let stored = sqlx::query!(
            r#"
            INSERT INTO artifact_metadata (artifact_id, format, metadata)
            VALUES ($1, 'alpine', $2)
            ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
            "#,
            artifact.id,
            metadata,
        )
        .execute(&state.db)
        .await;

        if let Err(e) = stored {
            tracing::warn!(
                "Alpine index backfill: cannot persist metadata for {}: {}",
                artifact.path,
                e
            );
        }
        artifact.metadata = Some(metadata);
    }
}

// ---------------------------------------------------------------------------
// GET /alpine/{repo_key}/{branch}/keys/artifact-keeper.rsa.pub - Public key
// ---------------------------------------------------------------------------

async fn public_key(
    State(state): State<SharedState>,
    Path((repo_key, _branch)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_alpine_repo(&state.db, &repo_key).await?;

    let signing_svc = SigningService::new(state.db.clone(), &state.config.jwt_secret);
    let public_pem = signing_svc
        .get_repo_public_key(repo.id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to retrieve public key: {}", e),
            )
                .into_response()
        })?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                "No signing key configured for this repository",
            )
                .into_response()
        })?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/x-pem-file")
        .header(
            "Content-Disposition",
            "attachment; filename=\"artifact-keeper.rsa.pub\"",
        )
        .header(CONTENT_LENGTH, public_pem.len().to_string())
        .body(Body::from(public_pem))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /alpine/{repo_key}/{branch}/{repository}/{arch}/{filename} - Download
// ---------------------------------------------------------------------------

async fn download_package(
    State(state): State<SharedState>,
    Path((repo_key, branch, repository, arch, filename)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    if !filename.ends_with(".apk") {
        return Err((StatusCode::BAD_REQUEST, "File must have .apk extension").into_response());
    }

    let repo = resolve_alpine_repo(&state.db, &repo_key).await?;

    let artifact_path = format!("{}/{}/{}/{}", branch, repository, arch, filename);

    let artifact = sqlx::query!(
        r#"
        SELECT id, storage_key, size_bytes, checksum_sha256
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
    .map_err(crate::api::handlers::db_err)?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Package not found").into_response());

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == RepositoryType::Remote {
                if let Some(response) = try_proxy_apk(
                    &state,
                    &repo,
                    &repo_key,
                    &branch,
                    &repository,
                    &arch,
                    &filename,
                )
                .await?
                {
                    return Ok(response);
                }
            }

            // Virtual repo: try each member in priority order
            if repo.repo_type == RepositoryType::Virtual {
                let db = state.db.clone();
                let upstream_path = format!("{}/{}/{}/{}", branch, repository, arch, filename);
                let artifact_path_clone = artifact_path.clone();
                let result = proxy_helpers::resolve_virtual_download(
                    &state.db,
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
                    "application/vnd.alpine.package",
                    None,
                );
            }

            return Err(not_found);
        }
    };

    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    // Check quarantine status before serving
    crate::services::quarantine_service::check_artifact_download(&state.db, artifact.id)
        .await
        .map_err(|e| e.into_response())?;

    match storage.get_stream(&artifact.storage_key).await {
        Ok(stream) => {
            // Record download
            crate::services::artifact_service::record_download(&state.db, artifact.id, &ctx).await;

            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/vnd.alpine.package")
                .header(
                    "Content-Disposition",
                    format!("attachment; filename=\"{}\"", filename),
                )
                .header(CONTENT_LENGTH, artifact.size_bytes.to_string())
                .header("X-Checksum-SHA256", &artifact.checksum_sha256)
                .body(Body::from_stream(stream))
                .unwrap())
        }
        Err(crate::error::AppError::NotFound(_)) if repo.repo_type != RepositoryType::Remote => {
            // Hosted artifact: file absent from storage. Serialise concurrent
            // readers with local hydration coordination and retry once.
            // Returns 507 if the file is still missing after the retry window.
            let content = proxy_helpers::coordinated_retry_get(
                &state.db,
                artifact.id,
                &artifact.storage_key,
                &*storage,
            )
            .await?;

            crate::services::artifact_service::record_download(&state.db, artifact.id, &ctx).await;

            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/vnd.alpine.package")
                .header(
                    "Content-Disposition",
                    format!("attachment; filename=\"{}\"", filename),
                )
                .header(CONTENT_LENGTH, content.len().to_string())
                .header("X-Checksum-SHA256", &artifact.checksum_sha256)
                .body(Body::from(content))
                .unwrap())
        }
        Err(e) => {
            // Storage retrieval failed. For remote repos, the DB record may
            // have been created by the proxy cache with a storage key that
            // is not accessible via the repo's own storage backend. Fall
            // through to proxy fetch to re-download from upstream.
            tracing::warn!(
                "Storage get failed for artifact {} (key: {}): {}. Falling through to proxy.",
                artifact.id,
                artifact.storage_key,
                e,
            );
            if repo.repo_type == RepositoryType::Remote {
                if let Some(response) = try_proxy_apk(
                    &state,
                    &repo,
                    &repo_key,
                    &branch,
                    &repository,
                    &arch,
                    &filename,
                )
                .await?
                {
                    return Ok(response);
                }
            }
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Storage error: {}", e),
            )
                .into_response())
        }
    }
}

/// Attempt to proxy-fetch an APK package from the upstream remote repository.
/// Returns `Ok(Some(response))` on success, `Ok(None)` if the repo has no
/// upstream or proxy configured, or `Err(response)` on proxy failure.
async fn try_proxy_apk(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    branch: &str,
    repository: &str,
    arch: &str,
    filename: &str,
) -> Result<Option<Response>, Response> {
    let (upstream_url, proxy) = match (&repo.upstream_url, &state.proxy_service) {
        (Some(u), Some(p)) => (u, p),
        _ => return Ok(None),
    };
    let upstream_path = format!("{}/{}/{}/{}", branch, repository, arch, filename);
    // #895: stream large .apk bodies (a few MiB to ~100 MiB for LLVM-class
    // packages). Default Content-Type matches the buffered handler's
    // prior fallback.
    proxy_helpers::proxy_fetch_streaming(
        proxy,
        repo.id,
        repo_key,
        upstream_url,
        &upstream_path,
        "application/octet-stream",
    )
    .await
    .map(Some)
}

// ---------------------------------------------------------------------------
// PUT /alpine/{repo_key}/{branch}/{repository}/{arch}/{filename} - Upload
// ---------------------------------------------------------------------------

async fn upload_package_put(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, branch, repository, arch, filename)): Path<(
        String,
        String,
        String,
        String,
        String,
    )>,
    body: Bytes,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "alpine", "write")?.user_id;
    let repo = resolve_alpine_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    if !filename.ends_with(".apk") {
        return Err((StatusCode::BAD_REQUEST, "File must have .apk extension").into_response());
    }

    store_apk(
        &state,
        &repo,
        &branch,
        &repository,
        &arch,
        &filename,
        body,
        user_id,
    )
    .await
}

// ---------------------------------------------------------------------------
// POST /alpine/{repo_key}/upload - Upload (alternative)
// ---------------------------------------------------------------------------

async fn upload_package_post(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "alpine", "write")?.user_id;
    let repo = resolve_alpine_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    // Extract filename from headers
    let filename = headers
        .get("Content-Disposition")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.split("filename=")
                .nth(1)
                .map(|f| f.trim_matches('"').trim_matches('\'').to_string())
        })
        .or_else(|| {
            headers
                .get("X-Package-Filename")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| {
            let hash = sha256_hex(&body);
            format!("{}.apk", &hash[..16])
        });

    if !filename.ends_with(".apk") {
        return Err((StatusCode::BAD_REQUEST, "File must have .apk extension").into_response());
    }

    // Extract branch/repository/arch from headers or use defaults
    let branch = headers
        .get("X-Alpine-Branch")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("edge")
        .to_string();

    let repository = headers
        .get("X-Alpine-Repository")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("main")
        .to_string();

    let arch = headers
        .get("X-Alpine-Arch")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("x86_64")
        .to_string();

    store_apk(
        &state,
        &repo,
        &branch,
        &repository,
        &arch,
        &filename,
        body,
        user_id,
    )
    .await
}

// ---------------------------------------------------------------------------
// Shared upload logic
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
async fn store_apk(
    state: &SharedState,
    repo: &RepoInfo,
    branch: &str,
    repository: &str,
    arch: &str,
    filename: &str,
    content: Bytes,
    user_id: uuid::Uuid,
) -> Result<Response, Response> {
    let computed_sha256 = sha256_hex(&content);

    // Parse APK filename for metadata
    let (pkg_name, pkg_version) = parse_apk_filename(filename).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!(
                "Invalid APK filename '{}'. Expected format: {{name}}-{{version}}.apk",
                filename
            ),
        )
            .into_response()
    })?;

    // Read the index metadata out of the package itself. An unreadable package is
    // stored anyway (uploads are not gated on parsing), but it cannot be indexed:
    // apk-tools keys every entry on the checksum of the package's control segment.
    let apk_info = parse_apk_package(&content);
    if apk_info.is_none() {
        tracing::warn!(
            "Alpine upload {}: no apk control segment found; package will not be indexed",
            filename
        );
    }

    let artifact_path = format!("{}/{}/{}/{}", branch, repository, arch, filename);

    // Check for duplicate
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        repo.id,
        artifact_path
    )
    .fetch_optional(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    if existing.is_some() {
        return Err((StatusCode::CONFLICT, "Package already exists").into_response());
    }

    super::cleanup_soft_deleted_artifact(&state.db, repo.id, &artifact_path).await;

    // Store the file
    let storage_key = format!("alpine/{}/{}", repo.id, artifact_path);
    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    storage
        .put(&storage_key, content.clone())
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Storage error: {}", e),
            )
                .into_response()
        })?;

    let size_bytes = content.len() as i64;

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
        "application/vnd.alpine.package",
        storage_key,
        user_id,
    )
    .fetch_one(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    crate::services::quarantine_service::apply_upload_hold_hosted(&state.db, repo.id, artifact_id)
        .await;

    // Store Alpine-specific metadata, including everything the APKINDEX needs
    // from the package itself (apk-native checksum + `.PKGINFO` fields).
    let alpine_metadata = build_alpine_artifact_metadata(
        &pkg_name,
        &pkg_version,
        arch,
        branch,
        repository,
        filename,
        apk_info.as_ref(),
    );

    let _ = sqlx::query!(
        r#"
        INSERT INTO artifact_metadata (artifact_id, format, metadata)
        VALUES ($1, 'alpine', $2)
        ON CONFLICT (artifact_id) DO UPDATE SET metadata = $2
        "#,
        artifact_id,
        alpine_metadata,
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
        "Alpine upload: {}-{} arch={} to repo {} ({}/{}/{})",
        pkg_name, pkg_version, arch, repo.id, branch, repository, arch
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "name": pkg_name,
                "version": pkg_version,
                "arch": arch,
                "branch": branch,
                "repository": repository,
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

/// Build the `artifact_metadata` JSON for an uploaded Alpine package.
///
/// `apk_info` carries the values read from the package itself; when it is absent
/// the entry keeps its filename-derived fields but has no `apk_checksum`, which
/// leaves it out of the generated APKINDEX.
fn build_alpine_artifact_metadata(
    pkg_name: &str,
    pkg_version: &str,
    arch: &str,
    branch: &str,
    repository: &str,
    filename: &str,
    apk_info: Option<&ApkPackageInfo>,
) -> serde_json::Value {
    let mut metadata = serde_json::json!({
        "name": pkg_name,
        "version": pkg_version,
        "arch": arch,
        "branch": branch,
        "repository": repository,
        "filename": filename,
    });

    if let (Some(apk_info), Some(map)) = (apk_info, metadata.as_object_mut()) {
        map.extend(apk_info_metadata_fields(apk_info));
    }

    metadata
}

/// The `artifact_metadata` fields derived from the `.apk` file itself.
fn apk_info_metadata_fields(
    apk_info: &ApkPackageInfo,
) -> serde_json::Map<String, serde_json::Value> {
    let mut fields = serde_json::Map::new();
    let info = &apk_info.pkginfo;

    fields.insert("apk_checksum".into(), apk_info.checksum.clone().into());
    if let Some(installed_size) = info.installed_size {
        fields.insert("installed_size".into(), installed_size.into());
    }
    if let Some(build_time) = info.build_time {
        fields.insert("build_time".into(), build_time.into());
    }
    for (field, value) in [
        ("description", &info.description),
        ("url", &info.url),
        ("license", &info.license),
        ("origin", &info.origin),
        ("maintainer", &info.maintainer),
        ("commit", &info.commit),
    ] {
        if let Some(value) = value {
            fields.insert(field.into(), value.clone().into());
        }
    }
    // APKINDEX carries these as single space-separated fields.
    for (field, values) in [("depends", &info.depends), ("provides", &info.provides)] {
        if !values.is_empty() {
            fields.insert(field.into(), values.join(" ").into());
        }
    }

    fields
}

/// Build the upstream path for an APKINDEX request.
///
/// Alpine mirrors structure their content as:
///   `{branch}/{repository}/{arch}/APKINDEX.tar.gz`
///
/// For example, `v3.22/main/x86_64/APKINDEX.tar.gz`.
fn build_apk_index_upstream_path(branch: &str, repository: &str, arch: &str) -> String {
    format!("{}/{}/{}/APKINDEX.tar.gz", branch, repository, arch)
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

/// A real `.apk` built by `abuild -F` (apk-tools 2.14.6, aarch64).
#[cfg(test)]
const MARKER_APK: &[u8] = include_bytes!("../../../tests/fixtures/dtf-marker-1.0-r0.apk");

/// The `C:` value real `apk index` emits for [`MARKER_APK`]. Captured by running
/// `apk index -o APKINDEX.tar.gz dtf-marker-1.0-r0.apk` on the same bytes, so the
/// tests pin our checksum to apk-tools rather than to our own implementation.
#[cfg(test)]
const MARKER_APK_APK_TOOLS_CHECKSUM: &str = "Q11jnfYL890CWXj/b2WxBdoVucrs4=";

/// `I:` real `apk index` emits for [`MARKER_APK`] (`.PKGINFO` `size = 22`).
#[cfg(test)]
const MARKER_APK_INSTALLED_SIZE: i64 = 22;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn marker_apk_info() -> ApkPackageInfo {
        parse_apk_package(MARKER_APK).expect("marker .apk should parse")
    }

    fn alpine_artifact(metadata: serde_json::Value) -> AlpineArtifact {
        AlpineArtifact {
            id: uuid::Uuid::nil(),
            path: "v3.21/main/aarch64/dtf-marker-1.0-r0.apk".to_string(),
            name: "dtf-marker".to_string(),
            version: Some("1.0-r0".to_string()),
            size_bytes: MARKER_APK.len() as i64,
            checksum_sha256: "8e37c3d1bd0d0b061c509aabe0a34be30f794936b3e502e0db29422233452317"
                .to_string(),
            storage_key: "alpine/repo/v3.21/main/aarch64/dtf-marker-1.0-r0.apk".to_string(),
            metadata: Some(metadata),
        }
    }

    /// Read the `<key>:` line values out of an APKINDEX text block.
    fn index_field(text: &str, key: &str) -> Option<String> {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{}:", key)))
            .map(|v| v.to_string())
    }

    // -----------------------------------------------------------------------
    // C: checksum — the apk-native package checksum
    // -----------------------------------------------------------------------

    #[test]
    fn test_apk_checksum_matches_apk_tools_output() {
        assert_eq!(marker_apk_info().checksum, MARKER_APK_APK_TOOLS_CHECKSUM);
    }

    #[test]
    fn test_apk_checksum_has_q1_base64_shape() {
        let checksum = marker_apk_info().checksum;
        let re = regex::Regex::new(r"^Q1[A-Za-z0-9+/]+=*$").unwrap();
        assert!(re.is_match(&checksum), "unexpected C: value {}", checksum);
        // Q1 + base64 of a 20-byte SHA1 digest.
        assert_eq!(checksum.len(), 2 + 28);
    }

    #[test]
    fn test_apk_checksum_is_sha1_of_control_segment_not_sha256_hex() {
        let checksum = marker_apk_info().checksum;
        // Regression guard for the original bug: a bare hex SHA256 of the file.
        assert!(!checksum.contains(&sha256_hex(MARKER_APK)));
        assert!(checksum.starts_with("Q1"));
    }

    #[test]
    fn test_apk_control_checksum_known_digest() {
        // "Q1" + base64(SHA1(b"")) — SHA1 of empty input is da39a3ee...
        assert_eq!(apk_control_checksum(b""), "Q12jmj7l5rSw0yVb/vlWAYkK/YBwk=");
    }

    #[test]
    fn test_apk_checksum_covers_control_segment_only() {
        // The digest input is the control segment, so changing the *data* segment
        // (the tail of the file) must not move the checksum.
        let (control, _) = apk_control_segment(MARKER_APK).expect("control segment");
        let control_end = control.as_ptr() as usize - MARKER_APK.as_ptr() as usize + control.len();
        assert!(control_end < MARKER_APK.len(), "data segment should follow");

        let mut mutated = MARKER_APK.to_vec();
        let last = mutated.len() - 1;
        mutated[last] ^= 0xff;
        assert_eq!(
            parse_apk_package(&mutated).map(|i| i.checksum),
            Some(MARKER_APK_APK_TOOLS_CHECKSUM.to_string())
        );
    }

    // -----------------------------------------------------------------------
    // .PKGINFO parsing (I: and friends)
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_apk_package_reads_installed_size() {
        let info = marker_apk_info();
        assert_eq!(info.pkginfo.installed_size, Some(MARKER_APK_INSTALLED_SIZE));
        assert!(info.pkginfo.installed_size.unwrap() > 0);
    }

    #[test]
    fn test_parse_apk_package_reads_pkginfo_fields() {
        let info = marker_apk_info().pkginfo;
        assert_eq!(
            info.description.as_deref(),
            Some("DTF format-conformance marker")
        );
        assert_eq!(info.url.as_deref(), Some("https://example.com"));
        assert_eq!(info.license.as_deref(), Some("MIT"));
        assert_eq!(info.origin.as_deref(), Some("dtf-marker"));
        assert_eq!(info.maintainer.as_deref(), Some("dtf <dtf@example.com>"));
        assert!(info.build_time.is_some());
    }

    #[test]
    fn test_parse_pkginfo_collects_repeated_and_skips_comments() {
        let info = parse_pkginfo(
            "# Generated by abuild\n\
             pkgname = busybox\n\
             size = 927849\n\
             builddate = 1763903404\n\
             commit = 284d827a\n\
             depend = so:libc.musl-aarch64.so.1\n\
             depend = so:libz.so.1\n\
             provides = cmd:busybox=1.37.0-r14\n\
             # automatically detected:\n\
             datahash = a2922bb6\n",
        );
        assert_eq!(info.installed_size, Some(927_849));
        assert_eq!(info.build_time, Some(1_763_903_404));
        assert_eq!(info.commit.as_deref(), Some("284d827a"));
        assert_eq!(
            info.depends,
            vec!["so:libc.musl-aarch64.so.1", "so:libz.so.1"]
        );
        assert_eq!(info.provides, vec!["cmd:busybox=1.37.0-r14"]);
    }

    #[test]
    fn test_parse_pkginfo_ignores_empty_and_malformed_lines() {
        let info = parse_pkginfo("\ncommit = \nnot a field\nsize = notanumber\n");
        assert_eq!(info.commit, None);
        assert_eq!(info.installed_size, None);
    }

    #[test]
    fn test_parse_apk_package_rejects_non_apk_bytes() {
        assert!(parse_apk_package(b"not a gzip stream at all").is_none());
        assert!(parse_apk_package(&[]).is_none());
    }

    #[test]
    fn test_parse_apk_package_rejects_gzip_without_pkginfo() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        std::io::Write::write_all(&mut encoder, &[0u8; 1024]).unwrap();
        let gz = encoder.finish().unwrap();
        assert!(parse_apk_package(&gz).is_none());
    }

    #[test]
    fn test_read_gzip_member_stops_at_member_boundary() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        std::io::Write::write_all(&mut encoder, b"first member").unwrap();
        let mut data = encoder.finish().unwrap();
        let first_len = data.len();
        data.extend_from_slice(b"trailing bytes of the next segment");

        let (consumed, inflated) = read_gzip_member(&data).expect("member");
        assert_eq!(consumed, first_len);
        assert_eq!(inflated, b"first member");
    }

    #[test]
    fn test_read_gzip_member_walks_the_apk_segments() {
        // [signature][control][data] — each member accounted for exactly once.
        let mut offset = 0usize;
        let mut segments = 0;
        while offset < MARKER_APK.len() {
            let (len, _) = read_gzip_member(&MARKER_APK[offset..]).expect("gzip member");
            offset += len;
            segments += 1;
        }
        assert_eq!(offset, MARKER_APK.len());
        assert_eq!(segments, 3);
    }

    // -----------------------------------------------------------------------
    // APKINDEX text generation
    // -----------------------------------------------------------------------

    #[test]
    fn test_generate_apkindex_text_emits_apk_checksum_and_size() {
        let metadata = build_alpine_artifact_metadata(
            "dtf-marker",
            "1.0-r0",
            "aarch64",
            "v3.21",
            "main",
            "dtf-marker-1.0-r0.apk",
            Some(&marker_apk_info()),
        );
        let text = generate_apkindex_text(&[alpine_artifact(metadata)], "aarch64");

        assert_eq!(
            index_field(&text, "C").as_deref(),
            Some(MARKER_APK_APK_TOOLS_CHECKSUM)
        );
        assert_eq!(
            index_field(&text, "I").as_deref(),
            Some(MARKER_APK_INSTALLED_SIZE.to_string().as_str())
        );
        assert_ne!(index_field(&text, "I").as_deref(), Some("0"));
        assert_eq!(index_field(&text, "P").as_deref(), Some("dtf-marker"));
        assert_eq!(index_field(&text, "V").as_deref(), Some("1.0-r0"));
        assert_eq!(index_field(&text, "A").as_deref(), Some("aarch64"));
        assert_eq!(
            index_field(&text, "S").as_deref(),
            Some(MARKER_APK.len().to_string().as_str())
        );
        assert_eq!(index_field(&text, "o").as_deref(), Some("dtf-marker"));
        assert_eq!(
            index_field(&text, "m").as_deref(),
            Some("dtf <dtf@example.com>")
        );
        assert!(text.ends_with("\n\n"));
    }

    #[test]
    fn test_generate_apkindex_text_skips_entry_without_apk_checksum() {
        // A package stored before the checksum was recorded must not poison the
        // whole index: apk-tools rejects an index entry it cannot key.
        let metadata = serde_json::json!({ "name": "legacy", "version": "1.0-r0" });
        let text = generate_apkindex_text(&[alpine_artifact(metadata)], "aarch64");
        assert!(text.is_empty(), "unexpected index text: {}", text);
    }

    #[test]
    fn test_generate_apkindex_text_never_emits_bare_sha256() {
        let metadata = build_alpine_artifact_metadata(
            "dtf-marker",
            "1.0-r0",
            "aarch64",
            "v3.21",
            "main",
            "dtf-marker-1.0-r0.apk",
            Some(&marker_apk_info()),
        );
        let artifact = alpine_artifact(metadata);
        let sha256 = artifact.checksum_sha256.clone();
        let text = generate_apkindex_text(&[artifact], "aarch64");
        assert!(!text.contains(&sha256));
        assert!(text.starts_with("C:Q1"));
    }

    #[test]
    fn test_generate_apkindex_text_joins_depends_and_provides() {
        let mut info = marker_apk_info();
        info.pkginfo.depends = vec!["so:libc.musl-aarch64.so.1".into(), "so:libz.so.1".into()];
        info.pkginfo.provides = vec!["cmd:dtf".into()];
        let metadata = build_alpine_artifact_metadata(
            "dtf-marker",
            "1.0-r0",
            "aarch64",
            "v3.21",
            "main",
            "dtf-marker-1.0-r0.apk",
            Some(&info),
        );
        let text = generate_apkindex_text(&[alpine_artifact(metadata)], "aarch64");
        assert_eq!(
            index_field(&text, "D").as_deref(),
            Some("so:libc.musl-aarch64.so.1 so:libz.so.1")
        );
        assert_eq!(index_field(&text, "p").as_deref(), Some("cmd:dtf"));
    }

    // -----------------------------------------------------------------------
    // artifact metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_alpine_artifact_metadata_carries_apk_fields() {
        let metadata = build_alpine_artifact_metadata(
            "dtf-marker",
            "1.0-r0",
            "aarch64",
            "v3.21",
            "main",
            "dtf-marker-1.0-r0.apk",
            Some(&marker_apk_info()),
        );
        assert_eq!(
            metadata["apk_checksum"],
            serde_json::json!(MARKER_APK_APK_TOOLS_CHECKSUM)
        );
        assert_eq!(
            metadata["installed_size"],
            serde_json::json!(MARKER_APK_INSTALLED_SIZE)
        );
        assert_eq!(metadata["name"], serde_json::json!("dtf-marker"));
        assert_eq!(metadata["arch"], serde_json::json!("aarch64"));
    }

    #[test]
    fn test_build_alpine_artifact_metadata_without_parsed_package() {
        let metadata = build_alpine_artifact_metadata(
            "mystery",
            "1.0-r0",
            "aarch64",
            "v3.21",
            "main",
            "mystery-1.0-r0.apk",
            None,
        );
        assert_eq!(metadata.get("apk_checksum"), None);
        assert_eq!(metadata["name"], serde_json::json!("mystery"));
    }

    #[test]
    fn test_has_apk_checksum() {
        assert!(has_apk_checksum(&alpine_artifact(
            serde_json::json!({ "apk_checksum": "Q1abc" })
        )));
        assert!(!has_apk_checksum(&alpine_artifact(
            serde_json::json!({ "apk_checksum": "" })
        )));
        assert!(!has_apk_checksum(&alpine_artifact(serde_json::json!({}))));
    }

    // -----------------------------------------------------------------------
    // Extracted pure functions (moved into test module)
    // -----------------------------------------------------------------------

    /// Build the artifact path for an Alpine package.
    fn build_alpine_artifact_path(
        branch: &str,
        repository: &str,
        arch: &str,
        filename: &str,
    ) -> String {
        format!("{}/{}/{}/{}", branch, repository, arch, filename)
    }

    /// Build the storage key for an Alpine package.
    fn build_alpine_storage_key(repo_id: uuid::Uuid, artifact_path: &str) -> String {
        format!("alpine/{}/{}", repo_id, artifact_path)
    }

    /// Build Alpine-specific metadata JSON.
    fn build_alpine_metadata(
        pkg_name: &str,
        pkg_version: &str,
        arch: &str,
        branch: &str,
        repository: &str,
        filename: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "name": pkg_name,
            "version": pkg_version,
            "arch": arch,
            "branch": branch,
            "repository": repository,
            "filename": filename,
        })
    }

    /// Build the JSON upload response for an Alpine package.
    fn build_alpine_upload_response(
        pkg_name: &str,
        pkg_version: &str,
        arch: &str,
        branch: &str,
        repository: &str,
        sha256: &str,
        size: i64,
    ) -> serde_json::Value {
        serde_json::json!({
            "name": pkg_name,
            "version": pkg_version,
            "arch": arch,
            "branch": branch,
            "repository": repository,
            "sha256": sha256,
            "size": size,
        })
    }

    /// Build the path prefix used for listing Alpine artifacts.
    fn build_alpine_path_prefix(branch: &str, repository: &str, arch: &str) -> String {
        format!("{}/{}/{}/", branch, repository, arch)
    }

    /// Extract filename from a Content-Disposition header value.
    fn extract_filename_from_content_disposition(value: &str) -> Option<String> {
        value
            .split("filename=")
            .nth(1)
            .map(|f| f.trim_matches('"').trim_matches('\'').to_string())
    }

    #[test]
    fn test_parse_apk_filename_simple() {
        let result = parse_apk_filename("curl-8.5.0-r0.apk");
        assert_eq!(result, Some(("curl".to_string(), "8.5.0-r0".to_string())));
    }

    #[test]
    fn test_parse_apk_filename_hyphenated_name() {
        let result = parse_apk_filename("my-app-1.2.3-r1.apk");
        assert_eq!(result, Some(("my-app".to_string(), "1.2.3-r1".to_string())));
    }

    #[test]
    fn test_parse_apk_filename_complex() {
        let result = parse_apk_filename("libxml2-dev-2.12.4-r0.apk");
        assert_eq!(
            result,
            Some(("libxml2-dev".to_string(), "2.12.4-r0".to_string()))
        );
    }

    #[test]
    fn test_parse_apk_filename_invalid() {
        assert_eq!(parse_apk_filename("notanapk.txt"), None);
        assert_eq!(parse_apk_filename("bad.apk"), None);
        assert_eq!(parse_apk_filename(""), None);
    }

    #[test]
    fn test_sha256_hex() {
        let hash = sha256_hex(b"hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_generate_apkindex_text_empty() {
        let text = generate_apkindex_text(&[], "x86_64");
        assert!(text.is_empty());
    }

    #[test]
    fn test_create_apkindex_tar_gz_empty() {
        let result = create_apkindex_tar_gz("", None);
        assert!(result.is_ok());
        let tar_gz = result.unwrap();
        assert!(!tar_gz.is_empty());
    }

    #[test]
    fn test_create_apkindex_tar_gz_with_content() {
        let content = "C:abc123\nP:curl\nV:8.5.0-r0\nA:x86_64\nS:1234\nI:5678\nT:URL retrieval utility\nU:https://curl.se\nL:MIT\n\n";
        let result = create_apkindex_tar_gz(content, None);
        assert!(result.is_ok());

        // Verify it's a valid tar.gz by decompressing
        let tar_gz = result.unwrap();
        let gz = flate2::read::GzDecoder::new(&tar_gz[..]);
        let mut archive = tar::Archive::new(gz);
        let entries: Vec<_> = archive.entries().unwrap().collect();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn test_create_apkindex_tar_gz_with_signature() {
        let content = "C:abc123\nP:curl\nV:8.5.0-r0\nA:x86_64\nS:1234\nI:5678\nT:URL retrieval utility\nU:https://curl.se\nL:MIT\n\n";
        let fake_signature = b"fake-rsa-signature-bytes";
        let result = create_apkindex_tar_gz(content, Some(fake_signature));
        assert!(result.is_ok());

        // Verify both entries exist in the correct order
        let tar_gz = result.unwrap();
        let gz = flate2::read::GzDecoder::new(&tar_gz[..]);
        let mut archive = tar::Archive::new(gz);
        let entry_names: Vec<String> = archive
            .entries()
            .unwrap()
            .filter_map(|e| {
                let e = e.ok()?;
                e.path().ok().map(|p| p.to_string_lossy().to_string())
            })
            .collect();
        assert_eq!(entry_names.len(), 2);
        assert_eq!(entry_names[0], ".SIGN.RSA.artifact-keeper.rsa.pub");
        assert_eq!(entry_names[1], "APKINDEX");
    }

    /// Typeflag byte of every tar header in an uncompressed tar stream.
    fn tar_typeflags(tar_gz: &[u8]) -> Vec<u8> {
        let mut tar_bytes = Vec::new();
        flate2::read::GzDecoder::new(tar_gz)
            .read_to_end(&mut tar_bytes)
            .unwrap();
        let mut flags = Vec::new();
        let mut offset = 0usize;
        while offset + 512 <= tar_bytes.len() {
            let header = &tar_bytes[offset..offset + 512];
            // End-of-archive marker.
            if header.iter().all(|b| *b == 0) {
                break;
            }
            flags.push(header[156]);
            let size = std::str::from_utf8(&header[124..135])
                .ok()
                .and_then(|s| usize::from_str_radix(s.trim_end_matches([' ', '\0']).trim(), 8).ok())
                .unwrap_or(0);
            offset += 512 + size.div_ceil(512) * 512;
        }
        flags
    }

    #[test]
    fn test_apkindex_tar_entry_is_a_regular_file() {
        // apk-tools rejects the index unless the entry is typeflag '0'; a bare GNU
        // header would leave a NUL here.
        let tar_gz = create_apkindex_tar_gz("C:Q1abc\nP:curl\n\n", None).unwrap();
        assert_eq!(tar_typeflags(&tar_gz), vec![b'0']);
    }

    #[test]
    fn test_apkindex_signature_tar_entry_is_a_regular_file() {
        let tar_gz = create_apkindex_tar_gz("C:Q1abc\nP:curl\n\n", Some(b"sig-bytes")).unwrap();
        assert_eq!(tar_typeflags(&tar_gz), vec![b'0', b'0']);
    }

    // -----------------------------------------------------------------------
    // build_alpine_artifact_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_alpine_artifact_path_basic() {
        assert_eq!(
            build_alpine_artifact_path("edge", "main", "x86_64", "curl-8.5.0-r0.apk"),
            "edge/main/x86_64/curl-8.5.0-r0.apk"
        );
    }

    #[test]
    fn test_build_alpine_artifact_path_v3() {
        assert_eq!(
            build_alpine_artifact_path("v3.18", "community", "aarch64", "nginx-1.25.4-r0.apk"),
            "v3.18/community/aarch64/nginx-1.25.4-r0.apk"
        );
    }

    #[test]
    fn test_build_alpine_artifact_path_testing() {
        assert_eq!(
            build_alpine_artifact_path("edge", "testing", "x86_64", "zsh-5.9-r0.apk"),
            "edge/testing/x86_64/zsh-5.9-r0.apk"
        );
    }

    // -----------------------------------------------------------------------
    // build_alpine_storage_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_alpine_storage_key_basic() {
        let repo_id = uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        assert_eq!(
            build_alpine_storage_key(repo_id, "edge/main/x86_64/curl-8.5.0-r0.apk"),
            "alpine/550e8400-e29b-41d4-a716-446655440000/edge/main/x86_64/curl-8.5.0-r0.apk"
        );
    }

    // -----------------------------------------------------------------------
    // build_alpine_metadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_alpine_metadata_basic() {
        let meta = build_alpine_metadata(
            "curl",
            "8.5.0-r0",
            "x86_64",
            "edge",
            "main",
            "curl-8.5.0-r0.apk",
        );
        assert_eq!(meta["name"], "curl");
        assert_eq!(meta["version"], "8.5.0-r0");
        assert_eq!(meta["arch"], "x86_64");
        assert_eq!(meta["branch"], "edge");
        assert_eq!(meta["repository"], "main");
        assert_eq!(meta["filename"], "curl-8.5.0-r0.apk");
    }

    #[test]
    fn test_build_alpine_metadata_different_arch() {
        let meta = build_alpine_metadata(
            "nginx",
            "1.25.4-r0",
            "aarch64",
            "v3.19",
            "community",
            "nginx-1.25.4-r0.apk",
        );
        assert_eq!(meta["arch"], "aarch64");
        assert_eq!(meta["branch"], "v3.19");
        assert_eq!(meta["repository"], "community");
    }

    // -----------------------------------------------------------------------
    // build_alpine_upload_response
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_alpine_upload_response_basic() {
        let resp = build_alpine_upload_response(
            "curl",
            "8.5.0-r0",
            "x86_64",
            "edge",
            "main",
            "abc123def456",
            1024,
        );
        assert_eq!(resp["name"], "curl");
        assert_eq!(resp["version"], "8.5.0-r0");
        assert_eq!(resp["arch"], "x86_64");
        assert_eq!(resp["branch"], "edge");
        assert_eq!(resp["repository"], "main");
        assert_eq!(resp["sha256"], "abc123def456");
        assert_eq!(resp["size"], 1024);
    }

    #[test]
    fn test_build_alpine_upload_response_zero_size() {
        let resp = build_alpine_upload_response("pkg", "1.0", "x86", "edge", "main", "hash", 0);
        assert_eq!(resp["size"], 0);
    }

    #[test]
    fn test_build_alpine_upload_response_large_size() {
        let resp = build_alpine_upload_response(
            "big-pkg",
            "2.0",
            "x86_64",
            "edge",
            "main",
            "hash",
            1_073_741_824,
        );
        assert_eq!(resp["size"], 1_073_741_824);
    }

    // -----------------------------------------------------------------------
    // build_alpine_path_prefix
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_alpine_path_prefix_basic() {
        assert_eq!(
            build_alpine_path_prefix("edge", "main", "x86_64"),
            "edge/main/x86_64/"
        );
    }

    #[test]
    fn test_build_alpine_path_prefix_versioned() {
        assert_eq!(
            build_alpine_path_prefix("v3.18", "community", "aarch64"),
            "v3.18/community/aarch64/"
        );
    }

    // -----------------------------------------------------------------------
    // extract_filename_from_content_disposition
    // -----------------------------------------------------------------------

    #[test]
    fn test_extract_filename_from_cd_basic() {
        assert_eq!(
            extract_filename_from_content_disposition("attachment; filename=curl-8.5.0-r0.apk"),
            Some("curl-8.5.0-r0.apk".to_string())
        );
    }

    #[test]
    fn test_extract_filename_from_cd_quoted() {
        assert_eq!(
            extract_filename_from_content_disposition("attachment; filename=\"my-pkg-1.0.apk\""),
            Some("my-pkg-1.0.apk".to_string())
        );
    }

    #[test]
    fn test_extract_filename_from_cd_single_quoted() {
        assert_eq!(
            extract_filename_from_content_disposition("attachment; filename='test.apk'"),
            Some("test.apk".to_string())
        );
    }

    #[test]
    fn test_extract_filename_from_cd_no_filename() {
        assert_eq!(
            extract_filename_from_content_disposition("attachment"),
            None
        );
    }

    #[test]
    fn test_extract_filename_from_cd_inline() {
        assert_eq!(
            extract_filename_from_content_disposition("inline; filename=data.apk"),
            Some("data.apk".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // generate_apkindex_text with artifacts
    // -----------------------------------------------------------------------

    #[test]
    fn test_generate_apkindex_text_single_artifact() {
        let artifacts = vec![AlpineArtifact {
            id: uuid::Uuid::new_v4(),
            path: "edge/main/x86_64/curl-8.5.0-r0.apk".to_string(),
            name: "curl".to_string(),
            version: Some("8.5.0-r0".to_string()),
            size_bytes: 1234,
            checksum_sha256: "abc123".to_string(),
            storage_key: "alpine/xxx/edge/main/x86_64/curl-8.5.0-r0.apk".to_string(),
            metadata: Some(serde_json::json!({
                "name": "curl",
                "version": "8.5.0-r0",
                "description": "URL retrieval utility",
                "url": "https://curl.se",
                "license": "MIT",
                "depends": "libc",
                "installed_size": 5678,
                "apk_checksum": "Q1O3f05G1QIlK5QBrIDIGE0gDWKs4="
            })),
        }];
        let text = generate_apkindex_text(&artifacts, "x86_64");
        assert!(text.contains("P:curl"));
        assert!(text.contains("V:8.5.0-r0"));
        assert!(text.contains("A:x86_64"));
        assert!(text.contains("S:1234"));
        assert!(text.contains("I:5678"));
        assert!(text.contains("T:URL retrieval utility"));
        assert!(text.contains("U:https://curl.se"));
        assert!(text.contains("L:MIT"));
        assert!(text.contains("D:libc"));
        // The C: value is the apk-native checksum recorded at upload, never the
        // artifact's hex SHA256.
        assert!(text.contains("C:Q1O3f05G1QIlK5QBrIDIGE0gDWKs4="));
        assert!(!text.contains("abc123"));
    }

    #[test]
    fn test_generate_apkindex_text_multiple_artifacts() {
        let artifacts = vec![
            AlpineArtifact {
                id: uuid::Uuid::new_v4(),
                path: "edge/main/x86_64/curl-8.5.0-r0.apk".to_string(),
                name: "curl".to_string(),
                version: Some("8.5.0-r0".to_string()),
                size_bytes: 1234,
                checksum_sha256: "hash1".to_string(),
                storage_key: "key1".to_string(),
                metadata: Some(serde_json::json!({
                    "apk_checksum": "Q1O3f05G1QIlK5QBrIDIGE0gDWKs4="
                })),
            },
            AlpineArtifact {
                id: uuid::Uuid::new_v4(),
                path: "edge/main/x86_64/nginx-1.25.4-r0.apk".to_string(),
                name: "nginx".to_string(),
                version: Some("1.25.4-r0".to_string()),
                size_bytes: 5678,
                checksum_sha256: "hash2".to_string(),
                storage_key: "key2".to_string(),
                metadata: Some(serde_json::json!({
                    "apk_checksum": "Q1eqUIbEJ3d0FoAdQOSHqPQoUw7cQ="
                })),
            },
        ];
        let text = generate_apkindex_text(&artifacts, "x86_64");
        assert!(text.contains("P:curl"));
        assert!(text.contains("P:nginx"));
        // Should have two blank-line-terminated entries
        let entries: Vec<&str> = text.split("\n\n").filter(|s| !s.is_empty()).collect();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_generate_apkindex_text_no_depends() {
        let artifacts = vec![AlpineArtifact {
            id: uuid::Uuid::new_v4(),
            path: "edge/main/x86_64/busybox-1.36.apk".to_string(),
            name: "busybox".to_string(),
            version: Some("1.36".to_string()),
            size_bytes: 100,
            checksum_sha256: "hash".to_string(),
            storage_key: "key".to_string(),
            metadata: Some(serde_json::json!({
                "name": "busybox",
                "version": "1.36",
                "apk_checksum": "Q1O3f05G1QIlK5QBrIDIGE0gDWKs4=",
            })),
        }];
        let text = generate_apkindex_text(&artifacts, "x86_64");
        // depends is empty, D: line should NOT be present
        assert!(!text.contains("D:"));
        assert!(text.contains("P:busybox"));
    }

    // -----------------------------------------------------------------------
    // sha256_hex with different inputs
    // -----------------------------------------------------------------------

    #[test]
    fn test_sha256_hex_empty() {
        let hash = sha256_hex(b"");
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_hex_deterministic() {
        let h1 = sha256_hex(b"alpine package");
        let h2 = sha256_hex(b"alpine package");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_sha256_hex_different_inputs() {
        let h1 = sha256_hex(b"data1");
        let h2 = sha256_hex(b"data2");
        assert_ne!(h1, h2);
    }

    // -----------------------------------------------------------------------
    // parse_apk_filename edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_apk_filename_leading_digit() {
        // Package name starts with number but has no hyphen-digit boundary
        assert_eq!(parse_apk_filename("123pkg.apk"), None);
    }

    #[test]
    fn test_parse_apk_filename_just_dash_digit() {
        let result = parse_apk_filename("a-1.apk");
        assert_eq!(result, Some(("a".to_string(), "1".to_string())));
    }

    #[test]
    fn test_parse_apk_filename_multiple_dashes() {
        let result = parse_apk_filename("my-cool-app-2.0.0-r0.apk");
        assert_eq!(
            result,
            Some(("my-cool-app".to_string(), "2.0.0-r0".to_string()))
        );
    }

    #[test]
    fn test_parse_apk_filename_no_apk_extension() {
        assert_eq!(parse_apk_filename("curl-8.5.0-r0.tar.gz"), None);
    }

    // -----------------------------------------------------------------------
    // build_apk_index_upstream_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_apk_index_upstream_path_versioned() {
        assert_eq!(
            build_apk_index_upstream_path("v3.22", "main", "x86_64"),
            "v3.22/main/x86_64/APKINDEX.tar.gz"
        );
    }

    #[test]
    fn test_build_apk_index_upstream_path_edge() {
        assert_eq!(
            build_apk_index_upstream_path("edge", "community", "aarch64"),
            "edge/community/aarch64/APKINDEX.tar.gz"
        );
    }

    #[test]
    fn test_build_apk_index_upstream_path_testing() {
        assert_eq!(
            build_apk_index_upstream_path("v3.21", "testing", "armv7"),
            "v3.21/testing/armv7/APKINDEX.tar.gz"
        );
    }

    /// Verify the upstream path matches the real Alpine mirror structure.
    /// Given upstream_url = "https://dl-cdn.alpinelinux.org/alpine", the
    /// full URL must be:
    ///   https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64/APKINDEX.tar.gz
    #[test]
    fn test_build_apk_index_upstream_path_matches_alpine_mirror_structure() {
        let path = build_apk_index_upstream_path("v3.22", "main", "x86_64");
        let upstream = "https://dl-cdn.alpinelinux.org/alpine";
        let full_url = format!("{}/{}", upstream.trim_end_matches('/'), path);
        assert_eq!(
            full_url,
            "https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64/APKINDEX.tar.gz"
        );
    }

    // -----------------------------------------------------------------------
    // Multi-version path differentiation (#653)
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifact_paths_differ_across_alpine_versions() {
        // The same package name must produce different artifact paths for
        // different Alpine versions, preventing cross-version collisions.
        let path_v322 = build_alpine_artifact_path("v3.22", "main", "x86_64", "curl-8.5.0-r0.apk");
        let path_v323 = build_alpine_artifact_path("v3.23", "main", "x86_64", "curl-8.5.0-r0.apk");
        assert_ne!(path_v322, path_v323);
        assert!(path_v322.starts_with("v3.22/"));
        assert!(path_v323.starts_with("v3.23/"));
    }

    #[test]
    fn test_artifact_path_includes_all_components() {
        let path =
            build_alpine_artifact_path("v3.21", "community", "aarch64", "nginx-1.26.0-r0.apk");
        assert_eq!(path, "v3.21/community/aarch64/nginx-1.26.0-r0.apk");
    }

    #[test]
    fn test_storage_keys_differ_across_alpine_versions() {
        let repo_id = uuid::Uuid::new_v4();
        let path_v322 =
            build_alpine_artifact_path("v3.22", "main", "x86_64", "busybox-1.37.0-r10.apk");
        let path_v323 =
            build_alpine_artifact_path("v3.23", "main", "x86_64", "busybox-1.37.0-r10.apk");
        let key_v322 = build_alpine_storage_key(repo_id, &path_v322);
        let key_v323 = build_alpine_storage_key(repo_id, &path_v323);
        assert_ne!(key_v322, key_v323);
    }
}

#[cfg(test)]
mod db_cov_tests {
    use crate::api::handlers::test_db_helpers as tdh;

    // Exercises the DB-query happy paths so the sweep's db_err/db_status
    // call-site lines are covered by cargo llvm-cov --lib (#2083).
    #[tokio::test]
    async fn test_alpine_db_query_paths_smoke() {
        let Some(fx) = tdh::Fixture::setup("local", "alpine").await else {
            return;
        };
        let k = fx.repo_key.clone();
        let uris: Vec<String> = vec![
            format!("/{k}/main/repo/x86_64/APKINDEX.tar.gz"),
            format!("/{k}/main/repo/x86_64/pkg-1.0.0.apk"),
            format!("/{k}/main/keys/artifact-keeper.rsa.pub"),
        ];
        for uri in uris {
            let app = fx.router_with_auth(super::router());
            let _ = tdh::send(app, tdh::get(uri)).await;
        }
        fx.teardown().await;
    }

    /// Upload a real `.apk` and read back the generated index.
    async fn publish_marker_and_fetch_index(fx: &tdh::Fixture) -> String {
        let k = fx.repo_key.clone();
        let app = fx.router_with_auth(super::router());
        let (status, _) = tdh::send(
            app,
            tdh::put(
                format!("/{k}/v3.21/main/aarch64/dtf-marker-1.0-r0.apk"),
                bytes::Bytes::from_static(super::MARKER_APK),
            ),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::CREATED);
        fetch_index(fx).await
    }

    /// GET the APKINDEX and return the decompressed `APKINDEX` member.
    async fn fetch_index(fx: &tdh::Fixture) -> String {
        let k = fx.repo_key.clone();
        let app = fx.router_with_auth(super::router());
        let (status, body) = tdh::send(
            app,
            tdh::get(format!("/{k}/v3.21/main/aarch64/APKINDEX.tar.gz")),
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::OK);

        let gz = flate2::read::GzDecoder::new(&body[..]);
        let mut archive = tar::Archive::new(gz);
        for entry in archive.entries().expect("tar entries") {
            let mut entry = entry.expect("tar entry");
            if entry.path().expect("path").ends_with("APKINDEX") {
                // The entry apk-tools reads must be a regular file.
                assert_eq!(entry.header().entry_type(), tar::EntryType::Regular);
                let mut text = String::new();
                std::io::Read::read_to_string(&mut entry, &mut text).expect("read APKINDEX");
                return text;
            }
        }
        panic!("APKINDEX entry missing from the served tarball");
    }

    /// Publishing a real `.apk` must produce the index apk-tools expects: a `C:`
    /// matching what `apk index` computes for the same bytes and a real `I:`.
    #[tokio::test]
    async fn test_publish_apk_indexes_with_apk_tools_checksum() {
        let Some(fx) = tdh::Fixture::setup("local", "alpine").await else {
            return;
        };
        let text = publish_marker_and_fetch_index(&fx).await;

        assert!(
            text.contains(&format!("C:{}\n", super::MARKER_APK_APK_TOOLS_CHECKSUM)),
            "index does not carry the apk-tools checksum: {}",
            text
        );
        assert!(
            text.contains(&format!("I:{}\n", super::MARKER_APK_INSTALLED_SIZE)),
            "index does not carry the installed size: {}",
            text
        );
        assert!(text.contains("P:dtf-marker\n"));
        assert!(!text.contains("I:0\n"));
        fx.teardown().await;
    }

    /// A package stored before the apk checksum was recorded is backfilled from
    /// the stored bytes on the next index request, instead of dropping out of it.
    #[tokio::test]
    async fn test_index_backfills_apk_checksum_for_legacy_artifact() {
        let Some(fx) = tdh::Fixture::setup("local", "alpine").await else {
            return;
        };
        publish_marker_and_fetch_index(&fx).await;

        // Rewind the artifact to how an older backend would have stored it.
        sqlx::query(
            "UPDATE artifact_metadata SET metadata = metadata - 'apk_checksum' - 'installed_size' \
             WHERE artifact_id IN (SELECT id FROM artifacts WHERE repository_id = $1)",
        )
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .expect("strip apk metadata");

        let text = fetch_index(&fx).await;
        assert!(
            text.contains(&format!("C:{}\n", super::MARKER_APK_APK_TOOLS_CHECKSUM)),
            "legacy artifact was not backfilled: {}",
            text
        );
        assert!(text.contains(&format!("I:{}\n", super::MARKER_APK_INSTALLED_SIZE)));

        // The backfill is persisted, so it is a one-off per artifact.
        let stored: Option<String> = sqlx::query_scalar(
            "SELECT metadata->>'apk_checksum' FROM artifact_metadata \
             WHERE artifact_id IN (SELECT id FROM artifacts WHERE repository_id = $1)",
        )
        .bind(fx.repo_id)
        .fetch_one(&fx.pool)
        .await
        .expect("read back metadata");
        assert_eq!(
            stored.as_deref(),
            Some(super::MARKER_APK_APK_TOOLS_CHECKSUM)
        );
        fx.teardown().await;
    }
}
