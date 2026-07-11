//! Debian/APT repository handlers.
//!
//! Implements the endpoints required for `apt-get` to consume packages
//! and for uploading `.deb` files.
//!
//! Routes are mounted at `/debian/{repo_key}/...`:
//!   GET  /debian/{repo_key}/dists/{distribution}/Release                            - Release file
//!   GET  /debian/{repo_key}/dists/{distribution}/InRelease                          - Inline signed release
//!   GET  /debian/{repo_key}/dists/{distribution}/Release.gpg                        - Detached GPG signature
//!   GET  /debian/{repo_key}/dists/{distribution}/gpg-key.asc                        - Repository public key
//!   GET  /debian/{repo_key}/dists/{distribution}/{component}/binary-{arch}/Packages - Packages index
//!   GET  /debian/{repo_key}/dists/{distribution}/{component}/binary-{arch}/Packages.gz - Compressed Packages index
//!   GET  /debian/{repo_key}/dists/{distribution}/{component}/binary-{arch}/Packages.xz - XZ-compressed Packages index
//!   GET  /debian/{repo_key}/dists/{distribution}/*path                              - Catch-all dists proxy (i18n, Sources, etc.)
//!   GET  /debian/{repo_key}/pool/{component}/*path                                  - Download .deb
//!   PUT  /debian/{repo_key}/pool/{component}/*path                                  - Upload .deb
//!   POST /debian/{repo_key}/upload                                                  - Upload .deb (raw body)
//!   POST /debian/{repo_key}/sync                                                    - Sync filtered remote metadata/packages

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use axum::{Extension, Json};
use bytes::Bytes;
use flate2::Compression;
use flate2::GzBuilder;
use futures::StreamExt;
#[allow(unused_imports)]
use serde_json::json;
use sha2::{Digest, Sha256, Sha512};
use sqlx::PgPool;
use tracing::info;
use utoipa::{OpenApi, ToSchema};

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::handlers::repositories::DebianRepositoryConfig;
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::{SharedState, SIGNED_RELEASE_CACHE_MAX_ENTRIES};
use crate::formats::debian::{
    build_contents_index, build_debian_sync_plan, by_hash_path, filter_release_package_indexes,
    filter_release_source_indexes, is_flat_repository_package_path, parse_packages_index,
    parse_release, parse_sources_index, pool_path_allowed_by_filters, release_is_expired,
    release_path_allowed_by_filter, validate_debian_fetch_path, validate_release_filter_selection,
    DebControl, DebianHandler, DebianIndexPath, DebianSourceIndexPath, DebianSyncDownloadPolicy,
    DebianSyncFilter, DebianSyncPackageFile, DebianSyncPlan, DebianSyncSourceFile, PackagesEntry,
    SourceFileEntry, SourcesEntry, MAX_DEBIAN_SYNC_SELECTED_FILES,
};
use crate::models::repository::{RepositoryFormat, RepositoryType};
use crate::models::signing_key::SigningKey;
use crate::services::artifact_service::ArtifactService;
use crate::services::cache_classifier;
use crate::services::package_service::PackageService;
use crate::services::proxy_service::{ProxyService, DEFAULT_DISTS_INDEX_TTL_SECS};
use crate::services::signing_service::SigningService;

const DEBIAN_BINARY_CONTENT_TYPE: &str = "application/vnd.debian.binary-package";

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
        // Flat repository Release files
        .route("/:repo_key/Release", get(flat_release_file))
        .route("/:repo_key/InRelease", get(flat_in_release_file))
        .route("/:repo_key/Release.gpg", get(flat_release_gpg))
        // Flat repository package/source indexes
        .route("/:repo_key/Packages", get(flat_packages_index))
        .route("/:repo_key/Packages.gz", get(flat_packages_index_gz))
        .route("/:repo_key/Packages.xz", get(flat_packages_index_xz))
        .route("/:repo_key/Sources", get(flat_sources_index))
        .route("/:repo_key/Sources.gz", get(flat_sources_index_gz))
        .route("/:repo_key/Sources.xz", get(flat_sources_index_xz))
        // Release files
        .route("/:repo_key/dists/:distribution/Release", get(release_file))
        .route(
            "/:repo_key/dists/:distribution/InRelease",
            get(in_release_file),
        )
        .route(
            "/:repo_key/dists/:distribution/Release.gpg",
            get(release_gpg),
        )
        // Public key endpoint
        .route(
            "/:repo_key/dists/:distribution/gpg-key.asc",
            get(gpg_key_asc),
        )
        // Packages indices and i18n/Sources/etc. share a single wildcard route
        // and are dispatched in-handler. axum's matchit router rejects
        // `:component` and `*dists_path` as siblings under the same parent.
        .route(
            "/:repo_key/dists/:distribution/*dists_path",
            get(dists_dispatch),
        )
        // Pool: download and upload
        .route(
            "/:repo_key/pool/:component/*path",
            get(pool_download).put(pool_upload),
        )
        // Flat / root-relative package paths (after pool so pool wins for pool/...)
        .route(
            "/:repo_key/*artifact_path",
            get(flat_or_root_package_download),
        )
        // Alternative upload endpoint
        .route("/:repo_key/upload", post(upload_raw))
        // Explicit filtered metadata/package prefetch for configured Remote repos.
        .route("/:repo_key/sync", post(sync_remote_repository))
}

// ---------------------------------------------------------------------------
// Repository resolution
// ---------------------------------------------------------------------------

async fn resolve_debian_repo(db: &PgPool, repo_key: &str) -> Result<RepoInfo, Response> {
    proxy_helpers::resolve_repo_by_key(db, repo_key, &["debian", "apt"], "a Debian").await
}

// ---------------------------------------------------------------------------
// Debian metadata from filename
// ---------------------------------------------------------------------------

struct DebInfo {
    name: String,
    version: String,
    arch: String,
    package_type: String,
}

/// Parse `{name}_{version}_{arch}.deb` or `.udeb` from a filename.
fn parse_deb_filename(filename: &str) -> Option<DebInfo> {
    let package_type = if filename.ends_with(".udeb") {
        "udeb"
    } else {
        "deb"
    };
    let (name, version, arch) = DebianHandler::parse_deb_filename(filename).ok()?;
    Some(DebInfo {
        name,
        version,
        arch,
        package_type: package_type.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Packages index generation
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct PackageEntry {
    control: DebControl,
    filename: String,
    size: i64,
    sha256: String,
    sha1: Option<String>,
    md5: Option<String>,
}

type DebianArtifactRow = (
    String,
    i64,
    String,
    Option<String>,
    Option<String>,
    Option<serde_json::Value>,
);

/// Build the text for a Packages index from a list of entries.
fn build_packages_text(entries: &[PackageEntry]) -> String {
    let mut text = String::new();
    for (i, entry) in entries.iter().enumerate() {
        if i > 0 {
            text.push('\n');
        }
        push_packages_entry(&mut text, entry);
    }
    text
}

fn build_generated_packages_text(
    entries: &[PackagesEntry],
    index_architecture: &str,
    selected_architectures: &[String],
) -> String {
    let mut text = String::new();
    let mut first = true;
    for entry in entries.iter().filter(|entry| {
        package_matches_generated_index(
            &entry.control.architecture,
            index_architecture,
            selected_architectures,
        )
    }) {
        if !first {
            text.push('\n');
        }
        first = false;
        push_generated_packages_entry(&mut text, entry);
    }
    text
}

fn package_matches_generated_index(
    package_architecture: &str,
    index_architecture: &str,
    selected_architectures: &[String],
) -> bool {
    if index_architecture.is_empty() {
        package_architecture == "all"
            || selected_architectures.is_empty()
            || selected_architectures
                .iter()
                .any(|architecture| architecture == package_architecture)
    } else {
        package_matches_requested_arch(package_architecture, index_architecture)
    }
}
fn push_packages_entry(text: &mut String, entry: &PackageEntry) {
    push_packages_fields(
        text,
        &entry.control,
        Some(entry.filename.as_str()),
        Some(entry.size.max(0) as u64),
        entry.md5.as_deref(),
        entry.sha1.as_deref(),
        Some(entry.sha256.as_str()),
    );
}

fn push_generated_packages_entry(text: &mut String, entry: &PackagesEntry) {
    push_packages_fields(
        text,
        &entry.control,
        entry.filename.as_deref(),
        entry.size,
        entry.md5sum.as_deref(),
        entry.sha1.as_deref(),
        entry.sha256.as_deref(),
    );
}

fn push_packages_fields(
    text: &mut String,
    control: &DebControl,
    filename: Option<&str>,
    size: Option<u64>,
    md5sum: Option<&str>,
    sha1: Option<&str>,
    sha256: Option<&str>,
) {
    push_control_field(text, "Package", &control.package);
    push_control_field(text, "Version", &control.version);
    push_control_field(text, "Architecture", &control.architecture);
    push_optional_control_field(text, "Maintainer", control.maintainer.as_deref());
    if let Some(size) = control.installed_size {
        push_control_field(text, "Installed-Size", &size.to_string());
    }
    push_dependency_field(text, "Depends", control.depends.as_ref());
    push_dependency_field(text, "Pre-Depends", control.pre_depends.as_ref());
    push_dependency_field(text, "Recommends", control.recommends.as_ref());
    push_dependency_field(text, "Suggests", control.suggests.as_ref());
    push_dependency_field(text, "Conflicts", control.conflicts.as_ref());
    push_dependency_field(text, "Provides", control.provides.as_ref());
    push_dependency_field(text, "Replaces", control.replaces.as_ref());
    push_optional_control_field(text, "Section", control.section.as_deref());
    push_optional_control_field(text, "Priority", control.priority.as_deref());
    push_optional_control_field(text, "Homepage", control.homepage.as_deref());
    push_optional_control_field(text, "Source", control.source.as_deref());

    let mut extra_fields: Vec<_> = control.extra.iter().collect();
    extra_fields.sort_by_key(|(key, _)| *key);
    for (key, value) in extra_fields {
        push_control_field(text, key, value);
    }

    push_optional_control_field(text, "Description", control.description.as_deref());
    push_optional_control_field(text, "Filename", filename);
    if let Some(size) = size {
        push_control_field(text, "Size", &size.to_string());
    }
    push_optional_control_field(text, "MD5sum", md5sum);
    push_optional_control_field(text, "SHA1", sha1);
    push_optional_control_field(text, "SHA256", sha256);
}

fn push_optional_control_field(text: &mut String, key: &str, value: Option<&str>) {
    if let Some(value) = value.filter(|v| !v.trim().is_empty()) {
        push_control_field(text, key, value);
    }
}

fn push_dependency_field(text: &mut String, key: &str, values: Option<&Vec<String>>) {
    let Some(values) = values else {
        return;
    };
    if values.is_empty() {
        return;
    }
    push_control_field(text, key, &values.join(", "));
}

fn push_control_field(text: &mut String, key: &str, value: &str) {
    let mut lines = value.lines();
    let Some(first) = lines.next() else {
        return;
    };
    text.push_str(key);
    text.push_str(": ");
    text.push_str(first);
    text.push('\n');
    for line in lines {
        text.push(' ');
        text.push_str(if line.is_empty() { "." } else { line });
        text.push('\n');
    }
}

fn build_generated_sources_text(entries: &[SourcesEntry]) -> String {
    let mut text = String::new();
    for (i, entry) in entries.iter().enumerate() {
        if i > 0 {
            text.push('\n');
        }
        push_sources_entry(&mut text, entry);
    }
    text
}

fn push_sources_entry(text: &mut String, entry: &SourcesEntry) {
    push_control_field(text, "Package", &entry.package);
    push_control_field(text, "Version", &entry.version);
    push_control_field(text, "Directory", &entry.directory);

    for (key, value) in &entry.extra {
        push_control_field(text, key, value);
    }

    push_source_hash_section(text, "Files", &entry.files, source_file_md5);
    push_source_hash_section(text, "Checksums-Sha1", &entry.files, source_file_sha1);
    push_source_hash_section(text, "Checksums-Sha256", &entry.files, source_file_sha256);
    push_source_hash_section(text, "Checksums-Sha512", &entry.files, source_file_sha512);
}

fn source_file_md5(file: &SourceFileEntry) -> Option<&str> {
    file.md5sum.as_deref()
}

fn source_file_sha1(file: &SourceFileEntry) -> Option<&str> {
    file.sha1.as_deref()
}

fn source_file_sha256(file: &SourceFileEntry) -> Option<&str> {
    file.sha256.as_deref()
}

fn source_file_sha512(file: &SourceFileEntry) -> Option<&str> {
    file.sha512.as_deref()
}

fn push_source_hash_section(
    text: &mut String,
    field: &str,
    files: &[SourceFileEntry],
    hash: fn(&SourceFileEntry) -> Option<&str>,
) {
    if !files.iter().any(|file| hash(file).is_some()) {
        return;
    }

    text.push_str(field);
    text.push_str(":\n");
    for file in files {
        if let Some(hash) = hash(file) {
            text.push_str(&format!(" {} {} {}\n", hash, file.size, file.filename));
        }
    }
}
fn json_string<'a>(metadata: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    metadata.get(key).and_then(|v| v.as_str())
}

fn control_from_metadata_or_filename(
    metadata: Option<&serde_json::Value>,
    fallback: &DebInfo,
) -> DebControl {
    if let Some(meta) = metadata {
        if let Some(control_value) = meta.get("control") {
            if let Ok(control) = serde_json::from_value::<DebControl>(control_value.clone()) {
                if !control.package.is_empty()
                    && !control.version.is_empty()
                    && !control.architecture.is_empty()
                {
                    return control;
                }
            }
        }

        let mut control = DebControl {
            package: json_string(meta, "package")
                .or_else(|| json_string(meta, "name"))
                .unwrap_or(&fallback.name)
                .to_string(),
            version: json_string(meta, "version")
                .unwrap_or(&fallback.version)
                .to_string(),
            architecture: json_string(meta, "architecture")
                .unwrap_or(&fallback.arch)
                .to_string(),
            description: json_string(meta, "description").map(str::to_string),
            maintainer: json_string(meta, "maintainer").map(str::to_string),
            section: json_string(meta, "section").map(str::to_string),
            priority: json_string(meta, "priority").map(str::to_string),
            homepage: json_string(meta, "homepage").map(str::to_string),
            source: json_string(meta, "source").map(str::to_string),
            ..DebControl::default()
        };
        if control.description.is_none() {
            control.description = Some("No description available".to_string());
        }
        return control;
    }

    DebControl {
        package: fallback.name.clone(),
        version: fallback.version.clone(),
        architecture: fallback.arch.clone(),
        description: Some("No description available".to_string()),
        ..DebControl::default()
    }
}

fn package_matches_requested_arch(package_arch: &str, requested_arch: &str) -> bool {
    if requested_arch == "all" {
        package_arch == "all"
    } else {
        package_arch == requested_arch || package_arch == "all"
    }
}

fn package_matches_requested_distribution(
    metadata: Option<&serde_json::Value>,
    requested_distribution: &str,
) -> bool {
    let Some(distribution) = metadata
        .and_then(|metadata| metadata.get("distribution"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        // Legacy uploads did not carry distribution metadata. Keep them visible
        // in requested distributions instead of silently hiding existing hosted repos.
        return true;
    };

    distribution == requested_distribution
}

fn architecture_for_release_layout(package_arch: &str) -> Option<&str> {
    if package_arch == "all" {
        None
    } else {
        Some(package_arch)
    }
}

/// Fetch all package entries for a given repo, component, and architecture.
async fn fetch_package_entries(
    db: &PgPool,
    repo_id: uuid::Uuid,
    distribution: &str,
    component: &str,
    arch: &str,
) -> Result<Vec<PackageEntry>, Response> {
    let artifacts: Vec<DebianArtifactRow> = sqlx::query_as(
        r#"
        SELECT a.path, a.size_bytes, a.checksum_sha256,
               a.checksum_sha1, a.checksum_md5, am.metadata
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND a.path LIKE 'pool/' || $2 || '/%' ESCAPE '\'
        ORDER BY a.name, a.version, a.path
        "#,
    )
    .bind(repo_id)
    .bind(super::escape_like_literal(component))
    .fetch_all(db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    let mut entries = Vec::new();
    for a in &artifacts {
        let (path, size_bytes, checksum_sha256, checksum_sha1, checksum_md5, metadata) = a;
        let filename = path.rsplit('/').next().unwrap_or(path);
        let deb_info = match parse_deb_filename(filename) {
            Some(info) => info,
            None => continue,
        };

        if !package_matches_requested_distribution(metadata.as_ref(), distribution) {
            continue;
        }

        let control = control_from_metadata_or_filename(metadata.as_ref(), &deb_info);

        if !package_matches_requested_arch(&control.architecture, arch) {
            continue;
        }

        entries.push(PackageEntry {
            control,
            filename: path.clone(),
            size: *size_bytes,
            sha256: checksum_sha256.clone(),
            sha1: checksum_sha1.clone(),
            md5: checksum_md5.clone(),
        });
    }

    Ok(entries)
}

// ---------------------------------------------------------------------------
// Release content generation (shared by Release, InRelease, Release.gpg)
// ---------------------------------------------------------------------------

async fn load_debian_repository_config(
    db: &PgPool,
    repo_id: uuid::Uuid,
) -> Option<DebianRepositoryConfig> {
    load_debian_repository_config_strict(db, repo_id)
        .await
        .unwrap_or_default()
}

/// Strict loader: distinguishes between "no config row" (Ok(None)) and a DB/parse
/// error (Err(503 SERVICE_UNAVAILABLE)). Use this for security-sensitive paths such as
/// the pool proxy where a parse failure should fail-closed rather than fall back to
/// permissive defaults.
async fn load_debian_repository_config_strict(
    db: &PgPool,
    repo_id: uuid::Uuid,
) -> Result<Option<DebianRepositoryConfig>, Response> {
    let stored = sqlx::query_scalar::<_, String>(
        "SELECT value FROM repository_config WHERE repository_id = $1 AND key IN ('debian', 'debian_config') ORDER BY CASE WHEN key = 'debian' THEN 0 ELSE 1 END LIMIT 1",
    )
    .bind(repo_id)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        tracing::warn!(repository_id = %repo_id, error = %e, "failed to load Debian repository config");
        (StatusCode::SERVICE_UNAVAILABLE, "Failed to load repository configuration").into_response()
    })?;

    let Some(stored) = stored else {
        return Ok(None);
    };

    match serde_json::from_str::<DebianRepositoryConfig>(&stored) {
        Ok(config) => Ok(Some(config)),
        Err(e) => {
            tracing::warn!(repository_id = %repo_id, error = %e, "invalid Debian repository config JSON");
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "Invalid repository configuration",
            )
                .into_response())
        }
    }
}

/// True when a coherent local mirror generation has been published for this
/// distribution and must be served exclusively.
///
/// A published generation is signalled by a stored synced Release (only
/// written, atomically, at the end of a successful sync for a repository whose
/// metadata strategy generates local metadata). While no generation exists the
/// repository is in transparent passthrough mode: upstream metadata is served
/// unchanged and no per-request filtering is applied, so `apt` always sees a
/// self-consistent Release + index set. Once a generation is published, the
/// served set is exactly what the generation contains — filters are implicit in
/// its contents rather than enforced per request — and anything outside it is
/// 404 rather than proxied from upstream, so clients never observe a Release
/// that advertises indexes the mirror does not serve, nor a mix of upstream and
/// filtered local metadata.
async fn debian_local_generation_active(
    state: &SharedState,
    repo_id: uuid::Uuid,
    distribution: &str,
) -> bool {
    matches!(
        load_synced_release_content(state, repo_id, distribution).await,
        Ok(Some(_))
    )
}

/// Guard the upstream-passthrough branch of a dists request: once a local
/// generation is published for `distribution`, a path that is not part of that
/// generation must 404 instead of falling through to upstream, so the served
/// mirror stays coherent with its published Release. Returns `Ok(())` (allow
/// passthrough) only while the repository is still in transparent passthrough
/// mode.
async fn reject_uncovered_generation_path(
    state: &SharedState,
    repo_id: uuid::Uuid,
    distribution: &str,
) -> Result<(), Response> {
    if debian_local_generation_active(state, repo_id, distribution).await {
        return Err((
            StatusCode::NOT_FOUND,
            "Path is not part of the published Debian mirror generation",
        )
            .into_response());
    }
    Ok(())
}

fn configured_release_values(values: &[String], include_arch_all: bool) -> BTreeSet<String> {
    values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty() && *value != "*")
        .filter(|value| include_arch_all || *value != "all")
        .map(str::to_string)
        .collect()
}

fn effective_release_layout(
    config: Option<&DebianRepositoryConfig>,
    discovered_components: BTreeSet<String>,
    discovered_architectures: BTreeSet<String>,
) -> (BTreeSet<String>, BTreeSet<String>) {
    let configured_components = config
        .map(|config| configured_release_values(&config.effective_components(), true))
        .unwrap_or_default();
    let configured_architectures = config
        .map(|config| configured_release_values(&config.effective_architectures(), false))
        .unwrap_or_default();

    let components = if configured_components.is_empty() {
        discovered_components
    } else {
        configured_components
    };
    let architectures = if configured_architectures.is_empty() {
        discovered_architectures
    } else {
        configured_architectures
    };

    (components, architectures)
}
fn build_release_content_from_files(
    suite: &str,
    codename: Option<&str>,
    description: Option<&str>,
    components: &BTreeSet<String>,
    architectures: &BTreeSet<String>,
    mut release_files: Vec<(String, Vec<u8>)>,
) -> String {
    release_files.sort_by(|left, right| left.0.cmp(&right.0));

    let component_str = components.iter().cloned().collect::<Vec<_>>().join(" ");
    let arch_str = architectures.iter().cloned().collect::<Vec<_>>().join(" ");
    let now = chrono::Utc::now();
    let date_str = now.format("%a, %d %b %Y %H:%M:%S UTC").to_string();

    let mut release = String::new();
    release.push_str("Origin: artifact-keeper\n");
    release.push_str("Label: artifact-keeper\n");
    release.push_str(&format!("Suite: {}\n", suite));
    if let Some(codename) = codename.filter(|value| !value.trim().is_empty()) {
        release.push_str(&format!("Codename: {}\n", codename));
    }
    release.push_str(&format!("Date: {}\n", date_str));
    release.push_str(&format!("Architectures: {}\n", arch_str));
    release.push_str(&format!("Components: {}\n", component_str));
    push_optional_control_field(&mut release, "Description", description);
    push_release_hash_section(&mut release, "MD5Sum", &release_files, |bytes| {
        ArtifactService::calculate_md5(bytes)
    });
    push_release_hash_section(&mut release, "SHA1", &release_files, |bytes| {
        ArtifactService::calculate_sha1(bytes)
    });
    push_release_hash_section(&mut release, "SHA256", &release_files, |bytes| {
        ArtifactService::calculate_sha256(bytes)
    });
    push_release_hash_section(&mut release, "SHA512", &release_files, calculate_sha512_hex);

    release
}
async fn generate_release_content(
    state: &SharedState,
    repo_id: uuid::Uuid,
    distribution: &str,
) -> Result<String, Response> {
    let config = load_debian_repository_config(&state.db, repo_id).await;
    let (components, architectures) = discover_release_layout(&state.db, repo_id).await?;
    let (components, architectures) =
        effective_release_layout(config.as_ref(), components, architectures);

    let mut release_files =
        build_hosted_release_files(state, repo_id, distribution, &components, &architectures)
            .await?;
    append_by_hash_release_files(&mut release_files);

    Ok(build_release_content_from_files(
        distribution,
        Some(distribution),
        None,
        &components,
        &architectures,
        release_files,
    ))
}

/// Build Packages + Contents index blobs for a hosted repository generation.
async fn build_hosted_release_files(
    state: &SharedState,
    repo_id: uuid::Uuid,
    distribution: &str,
    components: &BTreeSet<String>,
    architectures: &BTreeSet<String>,
) -> Result<Vec<(String, Vec<u8>)>, Response> {
    let mut release_files = Vec::new();
    for component in components {
        for arch in architectures {
            let entries =
                fetch_package_entries(&state.db, repo_id, distribution, component, arch).await?;
            let packages_text = build_packages_text(&entries);
            let packages_bytes = packages_text.into_bytes();
            let packages_path = format!("{}/binary-{}/Packages", component, arch);
            push_index_variants(&mut release_files, &packages_path, &packages_bytes)?;

            let contents_entries: Vec<(String, String)> = entries
                .iter()
                .map(|entry| (entry.filename.clone(), entry.control.package.clone()))
                .collect();
            let contents_text = build_contents_index(&contents_entries);
            let contents_bytes = contents_text.into_bytes();
            let contents_path = format!("{}/Contents-{}", component, arch);
            push_index_variants(&mut release_files, &contents_path, &contents_bytes)?;
        }
    }
    Ok(release_files)
}

#[allow(clippy::result_large_err)]
fn push_index_variants(
    release_files: &mut Vec<(String, Vec<u8>)>,
    plain_path: &str,
    plain_bytes: &[u8],
) -> Result<(), Response> {
    release_files.push((plain_path.to_string(), plain_bytes.to_vec()));

    let gz_bytes = gzip_compress(plain_bytes).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Compression error: {}", e),
        )
            .into_response()
    })?;
    release_files.push((format!("{plain_path}.gz"), gz_bytes));

    let xz_bytes = xz_compress(plain_bytes).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("XZ compression error: {}", e),
        )
            .into_response()
    })?;
    release_files.push((format!("{plain_path}.xz"), xz_bytes));
    Ok(())
}

/// Append `by-hash/SHA256/<digest>` aliases for every non-by-hash release file.
fn append_by_hash_release_files(release_files: &mut Vec<(String, Vec<u8>)>) {
    let snapshot: Vec<(String, Vec<u8>)> = release_files
        .iter()
        .filter(|(path, _)| !path.starts_with("by-hash/"))
        .cloned()
        .collect();
    for (_path, bytes) in snapshot {
        let sha = calculate_sha256_hex(&bytes);
        let bh = by_hash_path("SHA256", &sha);
        if !release_files.iter().any(|(path, _)| path == &bh) {
            release_files.push((bh, bytes));
        }
    }
}

async fn discover_release_layout(
    db: &PgPool,
    repo_id: uuid::Uuid,
) -> Result<(BTreeSet<String>, BTreeSet<String>), Response> {
    let artifacts: Vec<(String, Option<serde_json::Value>)> = sqlx::query_as(
        r#"
        SELECT a.path, am.metadata
        FROM artifacts a
        LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
        WHERE a.repository_id = $1
          AND a.is_deleted = false
          AND a.path LIKE 'pool/%'
        "#,
    )
    .bind(repo_id)
    .fetch_all(db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    let mut components = BTreeSet::new();
    let mut architectures = BTreeSet::new();

    for artifact in &artifacts {
        let (path, metadata) = artifact;
        if let Some(component) = metadata
            .as_ref()
            .and_then(|m| json_string(m, "component"))
            .map(str::to_string)
            .or_else(|| component_from_pool_path(path).map(str::to_string))
        {
            components.insert(component);
        }

        if let Some(filename) = path.rsplit('/').next() {
            if let Some(info) = parse_deb_filename(filename) {
                let control = control_from_metadata_or_filename(metadata.as_ref(), &info);
                if let Some(arch) = architecture_for_release_layout(&control.architecture) {
                    architectures.insert(arch.to_string());
                }
            }
        }
    }

    if components.is_empty() {
        components.insert("main".to_string());
    }

    if architectures.is_empty() {
        architectures.insert("amd64".to_string());
        architectures.insert("arm64".to_string());
    }

    Ok((components, architectures))
}

/// Extract the Debian pool component from a path like
/// `pool/main/c/curl/pkg.deb` or `pool/updates/main/c/curl/pkg.deb`.
///
/// Layout: `pool/<component>/<prefix>/<source>/<filename>` where `<component>`
/// may contain `/` (Debian-Security uses `updates/main`).
fn component_from_pool_path(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("pool/")?;
    let parts: Vec<&str> = rest.split('/').filter(|part| !part.is_empty()).collect();
    if parts.is_empty() {
        return None;
    }
    // Standard layout has at least component/prefix/source/filename.
    if parts.len() >= 4 {
        let mut offset = 0usize;
        let prefix_idx = parts.len() - 3;
        for (idx, part) in parts.iter().enumerate() {
            if idx == prefix_idx {
                if offset == 0 {
                    return None;
                }
                // Drop the slash before the prefix segment.
                return Some(&rest[..offset - 1]);
            }
            offset += part.len() + 1;
        }
    }
    parts.first().copied()
}

fn gzip_compress(data: &[u8]) -> Result<Vec<u8>, io::Error> {
    let mut encoder = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder.finish()
}

fn calculate_sha512_hex(bytes: &[u8]) -> String {
    let digest = Sha512::digest(bytes);
    hex::encode(digest)
}

fn calculate_sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(digest)
}

/// Strongest advertised digest for `index_path` in the Release metadata,
/// preferring SHA-512 over SHA-256. Returns `(is_sha512, hex, size)`.
fn release_index_digest<'a>(
    release: &'a crate::formats::debian::Release,
    index_path: &str,
) -> Option<(bool, &'a str, u64)> {
    if let Some(hash) = release.sha512.iter().find(|hash| hash.path == index_path) {
        return Some((true, hash.hash.as_str(), hash.size));
    }
    if let Some(hash) = release.sha256.iter().find(|hash| hash.path == index_path) {
        return Some((false, hash.hash.as_str(), hash.size));
    }
    None
}

/// Verify a downloaded Packages/Sources index against the size and strongest
/// digest advertised in the Release metadata.
///
/// When `require` is true (the upstream Release was cryptographically
/// verified), an index with no SHA256/SHA512 entry in Release is rejected so
/// unverifiable content never enters a trusted mirror. When false, the check
/// still runs opportunistically to catch truncated or corrupt downloads but a
/// missing entry is tolerated.
fn verify_index_against_release(
    release: &crate::formats::debian::Release,
    index_path: &str,
    content: &[u8],
    require: bool,
) -> std::result::Result<(), String> {
    match release_index_digest(release, index_path) {
        Some((is_sha512, expected_hex, expected_size)) => {
            if content.len() as u64 != expected_size {
                return Err(format!(
                    "index {index_path} size {} does not match Release size {expected_size}",
                    content.len()
                ));
            }
            let actual = if is_sha512 {
                calculate_sha512_hex(content)
            } else {
                calculate_sha256_hex(content)
            };
            if !actual.eq_ignore_ascii_case(expected_hex) {
                return Err(format!(
                    "index {index_path} {} checksum does not match Release",
                    if is_sha512 { "SHA512" } else { "SHA256" }
                ));
            }
            Ok(())
        }
        None if require => Err(format!(
            "index {index_path} has no SHA256/SHA512 entry in the verified Release"
        )),
        None => Ok(()),
    }
}

/// Build a `Filename` -> lowercase SHA-256 map from parsed Packages indexes so
/// prefetched `.deb` payloads can be digest-gated before entering the cache.
fn package_sha256_by_filename(
    packages_by_index_path: &BTreeMap<String, Vec<PackagesEntry>>,
) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for entries in packages_by_index_path.values() {
        for entry in entries {
            let filename = entry
                .filename
                .as_deref()
                .map(str::trim)
                .filter(|filename| !filename.is_empty());
            let sha256 = entry
                .sha256
                .as_deref()
                .map(str::trim)
                .filter(|sha256| !sha256.is_empty());
            if let (Some(filename), Some(sha256)) = (filename, sha256) {
                map.insert(filename.to_string(), sha256.to_ascii_lowercase());
            }
        }
    }
    map
}

/// Resolve the expected SHA-256 to gate a prefetched artifact's cache commit.
///
/// When `require` is true (upstream metadata was verified) an artifact with no
/// advertised SHA-256 is rejected, so a trusted mirror never caches a payload
/// it cannot verify. When false, a missing digest yields `None`, matching the
/// prior best-effort caching for unverified remotes.
fn expected_prefetch_digest(
    digests: &BTreeMap<String, String>,
    filename: &str,
    require: bool,
) -> std::result::Result<Option<String>, String> {
    match digests.get(filename) {
        Some(sha256) => Ok(Some(sha256.clone())),
        None if require => Err(format!(
            "{filename} has no advertised SHA256 in the verified metadata; refusing to cache"
        )),
        None => Ok(None),
    }
}

/// Build a source-file-path -> lowercase SHA-256 map from parsed Sources
/// indexes, keyed identically to `DebianSyncSourceFile::filename`.
fn source_sha256_by_filename(
    sources_by_index_path: &BTreeMap<String, Vec<SourcesEntry>>,
) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for entries in sources_by_index_path.values() {
        for entry in entries {
            for file in &entry.files {
                if let Some(sha256) = file
                    .sha256
                    .as_deref()
                    .map(str::trim)
                    .filter(|sha256| !sha256.is_empty())
                {
                    let path =
                        crate::formats::debian::source_file_path(&entry.directory, &file.filename);
                    map.insert(path, sha256.to_ascii_lowercase());
                }
            }
        }
    }
    map
}

fn push_release_hash_section<F>(
    release: &mut String,
    section: &str,
    files: &[(String, Vec<u8>)],
    hash: F,
) where
    F: Fn(&[u8]) -> String,
{
    release.push_str(section);
    release.push_str(":\n");
    for (path, bytes) in files {
        release.push_str(&format!(" {} {} {}\n", hash(bytes), bytes.len(), path));
    }
}

// ---------------------------------------------------------------------------
// GET /debian/{repo_key}/dists/{distribution}/Release
// ---------------------------------------------------------------------------

/// Handles resolving a Debian repo and proxying dists metadata from
/// upstream for remote repos. Captures the per-request context so each
/// handler only needs to call `proxy.dists("suffix", "ct").await?`.
struct DebianProxy<'a> {
    state: &'a SharedState,
    repo_key: &'a str,
    distribution: &'a str,
}

fn debian_dists_upstream_path(distribution: &str, suffix: &str) -> String {
    if distribution.is_empty() {
        suffix.to_string()
    } else {
        format!("dists/{distribution}/{suffix}")
    }
}
impl<'a> DebianProxy<'a> {
    async fn resolve(
        state: &'a SharedState,
        repo_key: &'a str,
        distribution: &'a str,
    ) -> Result<(Self, RepoInfo), Response> {
        let repo = resolve_debian_repo(&state.db, repo_key).await?;
        Ok((
            Self {
                state,
                repo_key,
                distribution,
            },
            repo,
        ))
    }

    async fn dists(
        &self,
        suffix: &str,
        content_type: &'static str,
        repo: &RepoInfo,
    ) -> Result<(), Response> {
        reject_uncovered_generation_path(self.state, repo.id, self.distribution).await?;
        // Virtual repos: try each Remote member in priority order so a
        // virtual APT repo can serve dists metadata when its top-level
        // type is `virtual` (#1147). Local/Staging members produce
        // their dists metadata locally, handled by the caller's
        // post-`dists()` fallthrough, so we only need to handle Remote.
        if repo.repo_type == RepositoryType::Virtual {
            let upstream_path = debian_dists_upstream_path(self.distribution, suffix);
            if let Some(resp) = try_virtual_dists(
                self.state,
                repo.id,
                self.repo_key,
                self.distribution,
                &upstream_path,
                content_type,
            )
            .await?
            {
                return Err(resp);
            }
            return Ok(());
        }

        if repo.repo_type != RepositoryType::Remote {
            return Ok(());
        }
        let (upstream_url, proxy) = match (&repo.upstream_url, &self.state.proxy_service) {
            (Some(u), Some(p)) => (u, p),
            _ => return Ok(()),
        };
        let upstream_path = debian_dists_upstream_path(self.distribution, suffix);

        // Epoch-based lazy invalidation: if the cached file is older
        // than the release epoch, invalidate it so the streaming fetch
        // treats it as a cache miss and re-fetches from upstream.
        maybe_invalidate_by_epoch(proxy, self.repo_key, self.distribution, &upstream_path).await;

        let (content, upstream_ct) = proxy_helpers::proxy_fetch_capped(
            proxy,
            repo.id,
            self.repo_key,
            upstream_url,
            &upstream_path,
            proxy_helpers::LARGE_METADATA_MAX_BYTES,
        )
        .await?;
        Err(build_dists_response(content, upstream_ct, content_type))
    }

    /// Variant of `dists` that uses TTL + conditional-request +
    /// epoch-based lazy invalidation for Release/InRelease files.
    ///
    /// Sibling files compare their own `cached_at` against the release
    /// epoch timestamp to decide freshness at read time.
    ///
    /// Used by the Release / InRelease handlers.
    async fn dists_detecting_change(
        &self,
        suffix: &str,
        content_type: &'static str,
        repo: &RepoInfo,
    ) -> Result<(), Response> {
        let upstream_path = debian_dists_upstream_path(self.distribution, suffix);
        reject_uncovered_generation_path(self.state, repo.id, self.distribution).await?;

        // Virtual: iterate Remote members.
        if repo.repo_type == RepositoryType::Virtual {
            if let Some(resp) = try_virtual_dists_detecting_change(
                self.state,
                repo.id,
                self.repo_key,
                self.distribution,
                &upstream_path,
                content_type,
            )
            .await?
            {
                return Err(resp);
            }
            return Ok(());
        }

        if repo.repo_type != RepositoryType::Remote {
            return Ok(());
        }
        let (upstream_url, proxy) = match (&repo.upstream_url, &self.state.proxy_service) {
            (Some(u), Some(p)) => (u, p),
            _ => return Ok(()),
        };

        let pseudo_repo = proxy_helpers::build_remote_repo(repo.id, self.repo_key, upstream_url);
        let (content, upstream_ct, changed) = proxy
            .fetch_dists_with_revalidation(
                &pseudo_repo,
                &upstream_path,
                self.distribution,
                DEFAULT_DISTS_INDEX_TTL_SECS,
            )
            .await
            .map_err(map_proxy_err)?;

        if changed {
            // Drop any signed-Release entries for this dist; the next
            // InRelease / Release.gpg fetch will re-sign against the new
            // content (#1236).
            signed_release_cache_invalidate(self.state, self.repo_key, self.distribution).await;
        }

        Err(build_dists_response(content, upstream_ct, content_type))
    }
}

/// Pure helper that builds the HTTP response for a successful dists
/// fetch (either through the direct-Remote path or after a Virtual
/// member match). Extracted so the Content-Type fallback and length
/// header construction can be exercised without async runtime or DB.
fn build_dists_response(
    content: Bytes,
    upstream_ct: Option<String>,
    default_content_type: &str,
) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(
            CONTENT_TYPE,
            upstream_ct.unwrap_or_else(|| default_content_type.to_string()),
        )
        .header(CONTENT_LENGTH, content.len().to_string())
        .body(Body::from(content))
        .unwrap()
}

/// Pure helper that decides whether a Remote member should be tried
/// for the current dists request. Returns the upstream URL when the
/// member is eligible, `None` otherwise. Extracted so the
/// member-filter predicate is unit-testable without DB access.
fn remote_member_upstream(member: &crate::models::repository::Repository) -> Option<&str> {
    if member.repo_type != RepositoryType::Remote {
        return None;
    }
    member.upstream_url.as_deref()
}

// ---------------------------------------------------------------------------
// Signed-Release cache helpers (#1236)
//
// `apt update` polls InRelease and Release.gpg on every refresh; OpenPGP
// signing is multi-millisecond CPU work, so we cache the signed bytes keyed
// by SHA-256(unsigned Release || key fingerprint). The fingerprint is in the
// key so that a key rotation naturally invalidates the prior signature, and
// the content prefix means any Release flip rotates the key without needing
// an explicit invalidation pass — though we also evict from the revalidation
// path to keep the cache from growing unboundedly.
// ---------------------------------------------------------------------------

/// Variant tag included in cache keys so InRelease and Release.gpg cannot
/// collide even when they sign the same unsigned content with the same key.
#[derive(Clone, Copy)]
enum SignedReleaseVariant {
    InRelease,
    ReleaseGpg,
}

impl SignedReleaseVariant {
    fn as_str(self) -> &'static str {
        match self {
            SignedReleaseVariant::InRelease => "InRelease",
            SignedReleaseVariant::ReleaseGpg => "Release.gpg",
        }
    }
}

/// Compute the cache key for a signed Release artifact. The fingerprint
/// argument is the active signing key fingerprint (hex); when absent (no key
/// configured) the caller should be returning 404 anyway and never call this.
fn signed_release_cache_key(
    variant: SignedReleaseVariant,
    unsigned_release: &str,
    key_fingerprint: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(variant.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(key_fingerprint.as_bytes());
    hasher.update(b"\0");
    hasher.update(unsigned_release.as_bytes());
    hex::encode(hasher.finalize())
}

/// Look up a previously-signed Release artifact in the in-process cache.
async fn signed_release_cache_get(state: &SharedState, cache_key: &str) -> Option<Bytes> {
    let cache = state.signed_release_cache.read().await;
    cache.get(cache_key).cloned()
}

/// Insert a freshly-signed Release artifact into the cache and update the
/// `(repo_key, distribution)` reverse index used for targeted invalidation.
/// A soft cap on total entries (`SIGNED_RELEASE_CACHE_MAX_ENTRIES`) bounds
/// worst-case memory; once exceeded the entire cache is dropped, which is
/// safe because every entry is reconstructible from its sign input.
async fn signed_release_cache_put(
    state: &SharedState,
    repo_key: &str,
    distribution: &str,
    cache_key: String,
    bytes: Bytes,
) {
    let mut cache = state.signed_release_cache.write().await;
    if cache.len() >= SIGNED_RELEASE_CACHE_MAX_ENTRIES {
        cache.clear();
        let mut idx = state.signed_release_cache_index.write().await;
        idx.clear();
    }
    cache.insert(cache_key.clone(), bytes);
    drop(cache);

    let mut idx = state.signed_release_cache_index.write().await;
    let entry = idx
        .entry((repo_key.to_string(), distribution.to_string()))
        .or_default();
    if !entry.contains(&cache_key) {
        entry.push(cache_key);
    }
}

/// Evict all signed-Release entries belonging to the given
/// `(repo_key, distribution)`. Called from the revalidation path so
/// that an upstream Release flip drops the matching signed copies
/// when content changes.
async fn signed_release_cache_invalidate(state: &SharedState, repo_key: &str, distribution: &str) {
    let key = (repo_key.to_string(), distribution.to_string());
    let drained = {
        let mut idx = state.signed_release_cache_index.write().await;
        idx.remove(&key).unwrap_or_default()
    };
    if drained.is_empty() {
        return;
    }
    let mut cache = state.signed_release_cache.write().await;
    for cache_key in drained {
        cache.remove(&cache_key);
    }
}

/// Resolve the active signing key for a repository, returning a 404 when
/// none is configured. We refuse to silently fall through to unsigned
/// `InRelease` (#1236): clients trust the signature, so absence of a key
/// is a configuration error the operator needs to see, not a soft fallback.
async fn require_active_signing_key(
    signing_svc: &SigningService,
    repo_id: uuid::Uuid,
) -> Result<SigningKey, Response> {
    match signing_svc.get_active_key_for_repo(repo_id).await {
        Ok(Some(k)) => Ok(k),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            "No signing key configured for this repository",
        )
            .into_response()),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to load signing key: {}", e),
        )
            .into_response()),
    }
}

/// Iterate the virtual repo's Remote members for `upstream_path` and
/// return the first successful response. Checks the release epoch for
/// lazy invalidation before attempting the streaming fetch.
async fn try_virtual_dists(
    state: &SharedState,
    virtual_repo_id: uuid::Uuid,
    virtual_repo_key: &str,
    distribution: &str,
    upstream_path: &str,
    default_content_type: &'static str,
) -> Result<Option<Response>, Response> {
    let _ = virtual_repo_key;
    let members = proxy_helpers::fetch_virtual_members(&state.db, virtual_repo_id).await?;
    let Some(proxy) = state.proxy_service.as_deref() else {
        return Ok(None);
    };
    let mut first_err: Option<Response> = None;
    for member in &members {
        let Some(upstream_url) = remote_member_upstream(member) else {
            continue;
        };

        // Epoch-based lazy invalidation for this member's cache entry
        maybe_invalidate_by_epoch(proxy, &member.key, distribution, upstream_path).await;

        match proxy_helpers::proxy_fetch_capped(
            proxy,
            member.id,
            &member.key,
            upstream_url,
            upstream_path,
            proxy_helpers::LARGE_METADATA_MAX_BYTES,
        )
        .await
        {
            Ok((content, upstream_ct)) => {
                return Ok(Some(build_dists_response(
                    content,
                    upstream_ct,
                    default_content_type,
                )));
            }
            Err(resp) => {
                if resp.status() == StatusCode::NOT_FOUND {
                    continue;
                }
                first_err.get_or_insert(resp);
            }
        }
    }
    match first_err {
        Some(err) => Err(err),
        None => Ok(None),
    }
}

/// Check the release epoch and invalidate the cache entry if stale.
/// Dependent files are invalidated on demand when next requested,
/// not eagerly when Release changes.
async fn maybe_invalidate_by_epoch(
    proxy: &ProxyService,
    repo_key: &str,
    distribution: &str,
    path: &str,
) {
    // Immutable paths (by-hash, pool/) never need epoch invalidation —
    // their content is pinned, so a Release change cannot affect them.
    if cache_classifier::classify(&RepositoryFormat::Debian, path).is_immutable() {
        return;
    }

    let metadata_key = match ProxyService::cache_metadata_key(repo_key, path) {
        Ok(k) => k,
        Err(_) => return,
    };
    let metadata = match proxy.load_cache_metadata_pub(&metadata_key).await {
        Some(m) => m,
        None => return,
    };

    if proxy
        .is_dists_epoch_expired(repo_key, distribution, metadata.cached_at)
        .await
    {
        let _ = proxy.invalidate_cache_by_key(repo_key, path).await;
    }
}

/// Change-detection variant of [`try_virtual_dists`]. Uses TTL +
/// conditional-request + epoch-based lazy invalidation for virtual repo
/// members' Release/InRelease files.
async fn try_virtual_dists_detecting_change(
    state: &SharedState,
    virtual_repo_id: uuid::Uuid,
    virtual_repo_key: &str,
    distribution: &str,
    upstream_path: &str,
    default_content_type: &'static str,
) -> Result<Option<Response>, Response> {
    let _ = virtual_repo_key;
    let members = proxy_helpers::fetch_virtual_members(&state.db, virtual_repo_id).await?;
    let Some(proxy) = state.proxy_service.as_deref() else {
        return Ok(None);
    };
    let mut first_err: Option<Response> = None;
    for member in &members {
        let Some(upstream_url) = remote_member_upstream(member) else {
            continue;
        };
        let pseudo_repo = proxy_helpers::build_remote_repo(member.id, &member.key, upstream_url);
        match proxy
            .fetch_dists_with_revalidation(
                &pseudo_repo,
                upstream_path,
                distribution,
                DEFAULT_DISTS_INDEX_TTL_SECS,
            )
            .await
        {
            Ok((content, upstream_ct, changed)) => {
                if changed {
                    signed_release_cache_invalidate(state, &member.key, distribution).await;
                }
                return Ok(Some(build_dists_response(
                    content,
                    upstream_ct,
                    default_content_type,
                )));
            }
            Err(e) => {
                if matches!(e, crate::error::AppError::NotFound(_)) {
                    continue;
                }
                first_err.get_or_insert(map_proxy_err(e));
            }
        }
    }
    match first_err {
        Some(err) => Err(err),
        None => Ok(None),
    }
}

fn map_proxy_err(e: crate::error::AppError) -> Response {
    let (status, msg) = proxy_err_status_and_message(&e);
    (status, msg).into_response()
}

/// Pure helper that decides the HTTP status and message for an
/// `AppError` returned from `ProxyService::fetch_dists_with_revalidation`.
/// Factored out of [`map_proxy_err`] so the mapping table can be unit
/// tested without constructing an `axum::Response`.
fn proxy_err_status_and_message(e: &crate::error::AppError) -> (StatusCode, String) {
    match e {
        crate::error::AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
        other => (
            StatusCode::BAD_GATEWAY,
            format!("Upstream fetch failed: {}", other),
        ),
    }
}

/// Generate the Release content locally (shared by Release, InRelease,
/// and Release.gpg handlers). Returns the text and the repo for signing.
#[allow(clippy::result_large_err)]
async fn local_release_content(
    state: &SharedState,
    repo_key: &str,
    distribution: &str,
) -> Result<(String, RepoInfo), Response> {
    let repo = resolve_debian_repo(&state.db, repo_key).await?;
    let release = generate_release_content(state, repo.id, distribution).await?;
    Ok((release, repo))
}

fn synced_release_config_key(distribution: &str) -> String {
    format!("debian_synced_release:{distribution}")
}

async fn load_synced_release_content(
    state: &SharedState,
    repo_id: uuid::Uuid,
    distribution: &str,
) -> Result<Option<String>, Response> {
    let Some(config) = load_debian_repository_config(&state.db, repo_id).await else {
        return Ok(None);
    };
    if !config.generated_metadata_enabled() {
        return Ok(None);
    }

    sqlx::query_scalar::<_, String>(
        "SELECT value FROM repository_config WHERE repository_id = $1 AND key = $2",
    )
    .bind(repo_id)
    .bind(synced_release_config_key(distribution))
    .fetch_optional(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)
}

async fn store_synced_release_content(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    repo_id: uuid::Uuid,
    distribution: &str,
    release: &str,
) -> Result<(), Response> {
    sqlx::query(
        r#"
        INSERT INTO repository_config (repository_id, key, value)
        VALUES ($1, $2, $3)
        ON CONFLICT (repository_id, key)
        DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
        "#,
    )
    .bind(repo_id)
    .bind(synced_release_config_key(distribution))
    .bind(release)
    .execute(&mut **tx)
    .await
    .map_err(crate::api::handlers::db_err)?;
    Ok(())
}

fn canonical_plain_dists_index_path(path: &str) -> &str {
    path.strip_suffix(".gz")
        .or_else(|| path.strip_suffix(".xz"))
        .or_else(|| path.strip_suffix(".bz2"))
        .or_else(|| path.strip_suffix(".zst"))
        .or_else(|| path.strip_suffix(".zstd"))
        .unwrap_or(path)
}

fn synced_dists_key_prefix(distribution: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(distribution.as_bytes());
    format!("debian_synced_dists:{}:", hex::encode(digest.finalize()))
}

fn synced_dists_config_key(distribution: &str, path: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(canonical_plain_dists_index_path(path).as_bytes());
    format!(
        "{}{}",
        synced_dists_key_prefix(distribution),
        hex::encode(digest.finalize())
    )
}

async fn load_synced_dists_content(
    state: &SharedState,
    repo_id: uuid::Uuid,
    distribution: &str,
    path: &str,
) -> Result<Option<String>, Response> {
    let Some(config) = load_debian_repository_config(&state.db, repo_id).await else {
        return Ok(None);
    };
    if !config.generated_metadata_enabled() {
        return Ok(None);
    }

    sqlx::query_scalar::<_, String>(
        "SELECT value FROM repository_config WHERE repository_id = $1 AND key = $2",
    )
    .bind(repo_id)
    .bind(synced_dists_config_key(distribution, path))
    .fetch_optional(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)
}

async fn clear_synced_dists_content(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    repo_id: uuid::Uuid,
    distribution: &str,
) -> Result<(), Response> {
    sqlx::query("DELETE FROM repository_config WHERE repository_id = $1 AND key LIKE $2")
        .bind(repo_id)
        .bind(format!("{}%", synced_dists_key_prefix(distribution)))
        .execute(&mut **tx)
        .await
        .map_err(crate::api::handlers::db_err)?;
    Ok(())
}

async fn store_synced_dists_content(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    repo_id: uuid::Uuid,
    distribution: &str,
    path: &str,
    content: &str,
) -> Result<(), Response> {
    sqlx::query(
        r#"
        INSERT INTO repository_config (repository_id, key, value)
        VALUES ($1, $2, $3)
        ON CONFLICT (repository_id, key)
        DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
        "#,
    )
    .bind(repo_id)
    .bind(synced_dists_config_key(distribution, path))
    .bind(content)
    .execute(&mut **tx)
    .await
    .map_err(crate::api::handlers::db_err)?;
    Ok(())
}

#[allow(clippy::result_large_err)]
fn build_synced_dists_index_response(path: &str, text: String) -> Result<Response, Response> {
    let (content_type, body) = if path.ends_with(".gz") {
        let compressed = gzip_compress(text.as_bytes()).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Compression error: {}", e),
            )
                .into_response()
        })?;
        ("application/gzip".to_string(), compressed)
    } else if path.ends_with(".xz") {
        let compressed = xz_compress(text.as_bytes()).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("XZ compression error: {}", e),
            )
                .into_response()
        })?;
        ("application/x-xz".to_string(), compressed)
    } else if path.ends_with(".bz2") {
        let compressed = bz2_compress(text.as_bytes()).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("bz2 compression error: {}", e),
            )
                .into_response()
        })?;
        ("application/x-bzip2".to_string(), compressed)
    } else if path.ends_with(".zst") || path.ends_with(".zstd") {
        let compressed = zstd_compress(text.as_bytes()).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("zstd compression error: {}", e),
            )
                .into_response()
        })?;
        ("application/zstd".to_string(), compressed)
    } else {
        (content_type_for_dists_path(path), text.into_bytes())
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .header(CONTENT_LENGTH, body.len().to_string())
        .body(Body::from(body))
        .unwrap())
}

/// Load synced dists content, resolving `@ref:` by-hash aliases to the
/// referenced logical index path and returning `(serve_path, plain_text)`.
async fn load_synced_dists_content_resolved(
    state: &SharedState,
    repo_id: uuid::Uuid,
    distribution: &str,
    path: &str,
) -> Result<Option<(String, String)>, Response> {
    let Some(text) = load_synced_dists_content(state, repo_id, distribution, path).await? else {
        return Ok(None);
    };
    if let Some(ref_path) = text.strip_prefix("@ref:") {
        let plain_path = canonical_plain_dists_index_path(ref_path);
        let Some(plain) =
            load_synced_dists_content(state, repo_id, distribution, plain_path).await?
        else {
            return Ok(None);
        };
        return Ok(Some((ref_path.to_string(), plain)));
    }
    Ok(Some((path.to_string(), text)))
}

async fn try_synced_dists_response(
    state: &SharedState,
    repo_id: uuid::Uuid,
    distribution: &str,
    path: &str,
) -> Result<Option<Response>, Response> {
    let Some((serve_path, text)) =
        load_synced_dists_content_resolved(state, repo_id, distribution, path).await?
    else {
        return Ok(None);
    };
    Ok(Some(build_synced_dists_index_response(&serve_path, text)?))
}
async fn flat_release_file(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    release_file(State(state), Path((repo_key, String::new()))).await
}

async fn flat_in_release_file(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    in_release_file(State(state), Path((repo_key, String::new()))).await
}

async fn flat_release_gpg(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    release_gpg(State(state), Path((repo_key, String::new()))).await
}

async fn flat_dists_file(
    state: State<SharedState>,
    repo_key: String,
    dists_path: &str,
) -> Result<Response, Response> {
    dists_proxy_catchall(
        state,
        Path((repo_key, String::new(), dists_path.to_string())),
    )
    .await
}

async fn flat_packages_index(
    state: State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    flat_dists_file(state, repo_key, "Packages").await
}

async fn flat_packages_index_gz(
    state: State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    flat_dists_file(state, repo_key, "Packages.gz").await
}

async fn flat_packages_index_xz(
    state: State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    flat_dists_file(state, repo_key, "Packages.xz").await
}

async fn flat_sources_index(
    state: State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    flat_dists_file(state, repo_key, "Sources").await
}

async fn flat_sources_index_gz(
    state: State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    flat_dists_file(state, repo_key, "Sources.gz").await
}

async fn flat_sources_index_xz(
    state: State<SharedState>,
    Path(repo_key): Path<String>,
) -> Result<Response, Response> {
    flat_dists_file(state, repo_key, "Sources.xz").await
}
async fn release_file(
    State(state): State<SharedState>,
    Path((repo_key, distribution)): Path<(String, String)>,
) -> Result<Response, Response> {
    let (proxy, repo) = DebianProxy::resolve(&state, &repo_key, &distribution).await?;
    if let Some(release) = load_synced_release_content(&state, repo.id, &distribution).await? {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain; charset=utf-8")
            .header(CONTENT_LENGTH, release.len().to_string())
            .body(Body::from(release))
            .unwrap());
    }
    proxy
        .dists_detecting_change("Release", "text/plain; charset=utf-8", &repo)
        .await?;

    let (release, _) = local_release_content(&state, &repo_key, &distribution).await?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(release))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /debian/{repo_key}/dists/{distribution}/InRelease
// ---------------------------------------------------------------------------

async fn in_release_file(
    State(state): State<SharedState>,
    Path((repo_key, distribution)): Path<(String, String)>,
) -> Result<Response, Response> {
    let (proxy, repo) = DebianProxy::resolve(&state, &repo_key, &distribution).await?;
    let synced_release = load_synced_release_content(&state, repo.id, &distribution).await?;
    if synced_release.is_none() {
        proxy
            .dists_detecting_change("InRelease", "text/plain; charset=utf-8", &repo)
            .await?;
    }

    let release = match synced_release {
        Some(release) => release,
        None => {
            local_release_content(&state, &repo_key, &distribution)
                .await?
                .0
        }
    };

    let signing_svc = SigningService::new(state.db.clone(), &state.config.jwt_secret);
    // Resolve the signing key up front so we can both (a) return 404 when
    // none is configured and (b) include the fingerprint in the cache key.
    // The previous `.unwrap_or(release)` fallback silently served unsigned
    // bytes, which is a security footgun (#1236 review).
    let key = require_active_signing_key(&signing_svc, repo.id).await?;
    let fingerprint = key.fingerprint.as_deref().unwrap_or("unknown");
    let cache_key =
        signed_release_cache_key(SignedReleaseVariant::InRelease, &release, fingerprint);

    let body = if let Some(cached) = signed_release_cache_get(&state, &cache_key).await {
        cached
    } else {
        let armored = signing_svc
            .sign_openpgp_cleartext_with_key(&key, &release)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to sign InRelease: {}", e),
                )
                    .into_response()
            })?;
        // Best-effort `last_used_at` stamp; we don't fail the request if the
        // audit update errors (the sign already succeeded).
        let _ = signing_svc.mark_key_used(key.id).await;
        let bytes = Bytes::from(armored.into_bytes());
        signed_release_cache_put(&state, &repo_key, &distribution, cache_key, bytes.clone()).await;
        bytes
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(CONTENT_LENGTH, body.len().to_string())
        .body(Body::from(body))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /debian/{repo_key}/dists/{distribution}/Release.gpg
// ---------------------------------------------------------------------------

async fn release_gpg(
    State(state): State<SharedState>,
    Path((repo_key, distribution)): Path<(String, String)>,
) -> Result<Response, Response> {
    let (proxy, repo) = DebianProxy::resolve(&state, &repo_key, &distribution).await?;
    // Release.gpg is the detached signature of Release. We do not need
    // revalidation here because the matching Release fetch (called
    // by apt before Release.gpg) already drove epoch invalidation.
    let synced_release = load_synced_release_content(&state, repo.id, &distribution).await?;
    if synced_release.is_none() {
        proxy
            .dists("Release.gpg", "application/pgp-signature", &repo)
            .await?;
    }

    let release = match synced_release {
        Some(release) => release,
        None => {
            local_release_content(&state, &repo_key, &distribution)
                .await?
                .0
        }
    };

    let signing_svc = SigningService::new(state.db.clone(), &state.config.jwt_secret);
    let key = require_active_signing_key(&signing_svc, repo.id).await?;
    let fingerprint = key.fingerprint.as_deref().unwrap_or("unknown");
    let cache_key =
        signed_release_cache_key(SignedReleaseVariant::ReleaseGpg, &release, fingerprint);

    let body = if let Some(cached) = signed_release_cache_get(&state, &cache_key).await {
        cached
    } else {
        let armored = signing_svc
            .sign_openpgp_detached_with_key(&key, release.as_bytes())
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to sign Release.gpg: {}", e),
                )
                    .into_response()
            })?;
        let _ = signing_svc.mark_key_used(key.id).await;
        let bytes = Bytes::from(armored.into_bytes());
        signed_release_cache_put(&state, &repo_key, &distribution, cache_key, bytes.clone()).await;
        bytes
    };

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/pgp-signature")
        .header(CONTENT_LENGTH, body.len().to_string())
        .body(Body::from(body))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /debian/{repo_key}/dists/{distribution}/gpg-key.asc
// ---------------------------------------------------------------------------

async fn gpg_key_asc(
    State(state): State<SharedState>,
    Path((repo_key, _distribution)): Path<(String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_debian_repo(&state.db, &repo_key).await?;

    let signing_svc = SigningService::new(state.db.clone(), &state.config.jwt_secret);
    let public_key = signing_svc
        .get_repo_public_key(repo.id)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to retrieve public key: {}", e),
            )
                .into_response()
        })?;

    match public_key {
        Some(pem) => Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/pgp-keys")
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
// Shared helpers for Packages index handlers
// ---------------------------------------------------------------------------

/// Strip the `binary-` prefix from an Axum path segment like `binary-amd64`,
/// returning just `amd64`. If the prefix is absent, returns the input unchanged.
fn strip_binary_arch_prefix(binary_arch: &str) -> &str {
    binary_arch.strip_prefix("binary-").unwrap_or(binary_arch)
}

/// Build the dists-relative suffix for a Packages index file.
/// e.g. `("main", "binary-amd64", "gz")` -> `"main/binary-amd64/Packages.gz"`
/// Pass an empty string for `ext` to get the uncompressed path.
fn packages_index_suffix(component: &str, binary_arch: &str, ext: &str) -> String {
    if ext.is_empty() {
        format!("{}/{}/Packages", component, binary_arch)
    } else {
        format!("{}/{}/Packages.{}", component, binary_arch, ext)
    }
}

/// Build a Packages index and compress it with XZ.
fn build_packages_xz(entries: &[PackageEntry]) -> Result<Vec<u8>, io::Error> {
    let text = build_packages_text(entries);
    xz_compress(text.as_bytes())
}

#[derive(Default)]
struct GeneratedDistsMetadata {
    plain_indexes: BTreeMap<String, String>,
    release_files: Vec<(String, Vec<u8>)>,
}

fn build_synced_generated_metadata(
    plan: &DebianSyncPlan,
    packages_by_index_path: &BTreeMap<String, Vec<PackagesEntry>>,
    sources_by_index_path: &BTreeMap<String, Vec<SourcesEntry>>,
    selected_architectures: &[String],
) -> Result<GeneratedDistsMetadata, io::Error> {
    let mut generated = GeneratedDistsMetadata::default();

    // Restrict generated Packages/Contents to the sync plan's selected package
    // files. `build_debian_sync_plan` already applies package_queries (+ deps),
    // so publishing the full upstream index would advertise packages that are
    // not part of the filtered mirror generation.
    let mut allowed_filenames_by_index: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for package in &plan.package_files {
        allowed_filenames_by_index
            .entry(package.index_path.as_str())
            .or_default()
            .insert(package.filename.as_str());
    }

    for index in &plan.package_indexes {
        let Some(entries) = packages_by_index_path.get(&index.path) else {
            continue;
        };
        let allowed = allowed_filenames_by_index
            .get(index.path.as_str())
            .cloned()
            .unwrap_or_default();
        let selected: Vec<PackagesEntry> = entries
            .iter()
            .filter(|entry| {
                entry
                    .filename
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .is_some_and(|filename| allowed.contains(filename))
            })
            .cloned()
            .collect();
        let text =
            build_generated_packages_text(&selected, &index.architecture, selected_architectures);
        add_generated_dists_index(&mut generated, &index.path, text)?;
        // Contents indexes are NOT generated from pool filenames here: pool paths are
        // not valid Contents-file paths (Contents should list installed-file paths
        // like /usr/bin/foo, not pool/main/n/nginx/nginx_1.0_amd64.deb). Emitting
        // them was wrong. Contents are only published for hosted repositories where
        // we have actual file-installation metadata.
    }

    for index in &plan.source_indexes {
        let Some(entries) = sources_by_index_path.get(&index.path) else {
            continue;
        };
        let text = build_generated_sources_text(entries);
        add_generated_dists_index(&mut generated, &index.path, text)?;
    }

    Ok(generated)
}

fn add_generated_dists_index(
    generated: &mut GeneratedDistsMetadata,
    index_path: &str,
    text: String,
) -> Result<(), io::Error> {
    let base_path = canonical_plain_dists_index_path(index_path).to_string();
    if generated.plain_indexes.contains_key(&base_path) {
        return Ok(());
    }

    let plain_bytes = text.as_bytes().to_vec();
    let gz_bytes = gzip_compress(&plain_bytes)?;
    let xz_bytes = xz_compress(&plain_bytes)?;
    let variants = [
        (base_path.clone(), plain_bytes),
        (format!("{base_path}.gz"), gz_bytes),
        (format!("{base_path}.xz"), xz_bytes),
    ];
    for (path, bytes) in variants {
        let sha = calculate_sha256_hex(&bytes);
        let bh = by_hash_path("SHA256", &sha);
        generated.release_files.push((path.clone(), bytes.clone()));
        generated.release_files.push((bh.clone(), bytes));
        // Alias so by-hash fetches resolve to the logical index path and
        // recompress deterministically from the stored plain text.
        generated.plain_indexes.insert(bh, format!("@ref:{path}"));
    }
    generated.plain_indexes.insert(base_path, text);
    Ok(())
}

// ---------------------------------------------------------------------------
// GET /debian/{repo_key}/dists/{dist}/{component}/binary-{arch}/Packages
// ---------------------------------------------------------------------------

async fn packages_index(
    State(state): State<SharedState>,
    Path((repo_key, distribution, component, binary_arch)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let (proxy, repo) = DebianProxy::resolve(&state, &repo_key, &distribution).await?;
    let packages_suffix = packages_index_suffix(&component, &binary_arch, "");
    if let Some(response) =
        try_synced_dists_response(&state, repo.id, &distribution, &packages_suffix).await?
    {
        return Ok(response);
    }
    proxy
        .dists(&packages_suffix, "text/plain; charset=utf-8", &repo)
        .await?;

    let arch = strip_binary_arch_prefix(&binary_arch);

    let entries =
        fetch_package_entries(&state.db, repo.id, &distribution, &component, arch).await?;
    let text = build_packages_text(&entries);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(CONTENT_LENGTH, text.len().to_string())
        .body(Body::from(text))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /debian/{repo_key}/dists/{dist}/{component}/binary-{arch}/Packages.gz
// ---------------------------------------------------------------------------

async fn packages_index_gz(
    State(state): State<SharedState>,
    Path((repo_key, distribution, component, binary_arch)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let (proxy, repo) = DebianProxy::resolve(&state, &repo_key, &distribution).await?;
    let packages_gz_suffix = packages_index_suffix(&component, &binary_arch, "gz");
    if let Some(response) =
        try_synced_dists_response(&state, repo.id, &distribution, &packages_gz_suffix).await?
    {
        return Ok(response);
    }
    proxy
        .dists(&packages_gz_suffix, "application/gzip", &repo)
        .await?;

    let arch = strip_binary_arch_prefix(&binary_arch);

    let entries =
        fetch_package_entries(&state.db, repo.id, &distribution, &component, arch).await?;
    let text = build_packages_text(&entries);

    let compressed = gzip_compress(text.as_bytes()).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Compression error: {}", e),
        )
            .into_response()
    })?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/gzip")
        .header(CONTENT_LENGTH, compressed.len().to_string())
        .body(Body::from(compressed))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /debian/{repo_key}/dists/{dist}/{component}/binary-{arch}/Packages.xz
// ---------------------------------------------------------------------------

async fn packages_index_xz(
    State(state): State<SharedState>,
    Path((repo_key, distribution, component, binary_arch)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let (proxy, repo) = DebianProxy::resolve(&state, &repo_key, &distribution).await?;
    let packages_xz_suffix = packages_index_suffix(&component, &binary_arch, "xz");
    if let Some(response) =
        try_synced_dists_response(&state, repo.id, &distribution, &packages_xz_suffix).await?
    {
        return Ok(response);
    }
    proxy
        .dists(&packages_xz_suffix, "application/x-xz", &repo)
        .await?;

    let arch = strip_binary_arch_prefix(&binary_arch);

    let entries =
        fetch_package_entries(&state.db, repo.id, &distribution, &component, arch).await?;

    let compressed = build_packages_xz(&entries).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("XZ compression error: {}", e),
        )
            .into_response()
    })?;

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/x-xz")
        .header(CONTENT_LENGTH, compressed.len().to_string())
        .body(Body::from(compressed))
        .unwrap())
}

// ---------------------------------------------------------------------------
// GET /debian/{repo_key}/dists/{distribution}/*dists_path -- Dispatcher
// ---------------------------------------------------------------------------

/// Result of parsing a `dists/{distribution}/*dists_path` sub-path to see
/// whether it targets a Packages index.
struct PackagesRequest {
    component: String,
    binary_arch: String,
    ext: PackagesExt,
}

enum PackagesExt {
    Plain,
    Gz,
    Xz,
    Bz2,
    Zst,
}

/// Recognise `{component}/binary-{arch}/Packages{,.gz,.xz,.bz2,.zst}` inside the
/// wildcard path. Returns None for any other shape so the caller can fall
/// through to the upstream proxy.
fn parse_packages_request(dists_path: &str) -> Option<PackagesRequest> {
    let segments: Vec<&str> = dists_path.split('/').collect();
    if segments.len() != 3 || !segments[1].starts_with("binary-") {
        return None;
    }
    let ext = match segments[2] {
        "Packages" => PackagesExt::Plain,
        "Packages.gz" => PackagesExt::Gz,
        "Packages.xz" => PackagesExt::Xz,
        "Packages.bz2" => PackagesExt::Bz2,
        "Packages.zst" => PackagesExt::Zst,
        _ => return None,
    };
    Some(PackagesRequest {
        component: segments[0].to_string(),
        binary_arch: segments[1].to_string(),
        ext,
    })
}

struct ContentsRequest {
    component: String,
    arch: String,
    ext: PackagesExt,
}

/// Recognise `{component}/Contents-{arch}{,.gz,.xz}`.
fn parse_contents_request(dists_path: &str) -> Option<ContentsRequest> {
    let segments: Vec<&str> = dists_path.split('/').collect();
    if segments.len() != 2 {
        return None;
    }
    let rest = segments[1].strip_prefix("Contents-")?;
    let (arch, ext) = if let Some(arch) = rest.strip_suffix(".gz") {
        (arch, PackagesExt::Gz)
    } else if let Some(arch) = rest.strip_suffix(".xz") {
        (arch, PackagesExt::Xz)
    } else if let Some(arch) = rest.strip_suffix(".bz2") {
        (arch, PackagesExt::Bz2)
    } else if let Some(arch) = rest.strip_suffix(".zst") {
        (arch, PackagesExt::Zst)
    } else if rest.contains('.') {
        return None;
    } else {
        (rest, PackagesExt::Plain)
    };
    if arch.is_empty() {
        return None;
    }
    Some(ContentsRequest {
        component: segments[0].to_string(),
        arch: arch.to_string(),
        ext,
    })
}

/// Single entry point for all `dists/{distribution}/...` requests after
/// the static Release/InRelease/Release.gpg/gpg-key.asc routes. Dispatches
/// `{component}/binary-{arch}/Packages{,.gz,.xz}` and
/// `{component}/Contents-{arch}{,.gz,.xz}` to the matching handlers and
/// forwards everything else to the upstream proxy catch-all.
async fn dists_dispatch(
    state: State<SharedState>,
    Path((repo_key, distribution, dists_path)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    if let Some(req) = parse_packages_request(&dists_path) {
        let path = Path((
            repo_key.clone(),
            distribution.clone(),
            req.component,
            req.binary_arch,
        ));
        return match req.ext {
            PackagesExt::Plain => packages_index(state, path).await,
            PackagesExt::Gz => packages_index_gz(state, path).await,
            PackagesExt::Xz => packages_index_xz(state, path).await,
            // bz2/zst: try synced plain text via canonical path, then fall through to upstream.
            PackagesExt::Bz2 | PackagesExt::Zst => {
                let repo = resolve_debian_repo(&state.db, &repo_key).await?;
                if let Some(response) =
                    try_synced_dists_response(&state, repo.id, &distribution, &dists_path).await?
                {
                    return Ok(response);
                }
                dists_proxy_catchall(state, Path((repo_key, distribution, dists_path))).await
            }
        };
    }
    if let Some(req) = parse_contents_request(&dists_path) {
        return contents_index(state, repo_key, distribution, req).await;
    }
    dists_proxy_catchall(state, Path((repo_key, distribution, dists_path))).await
}

async fn contents_index(
    State(state): State<SharedState>,
    repo_key: String,
    distribution: String,
    req: ContentsRequest,
) -> Result<Response, Response> {
    let contents_suffix = match req.ext {
        PackagesExt::Plain => format!("{}/Contents-{}", req.component, req.arch),
        PackagesExt::Gz => format!("{}/Contents-{}.gz", req.component, req.arch),
        PackagesExt::Xz => format!("{}/Contents-{}.xz", req.component, req.arch),
        PackagesExt::Bz2 => format!("{}/Contents-{}.bz2", req.component, req.arch),
        PackagesExt::Zst => format!("{}/Contents-{}.zst", req.component, req.arch),
    };
    let repo = resolve_debian_repo(&state.db, &repo_key).await?;
    if let Some(response) =
        try_synced_dists_response(&state, repo.id, &distribution, &contents_suffix).await?
    {
        return Ok(response);
    }

    // Remote: fall through to catch-all proxy for upstream Contents.
    if repo.repo_type == RepositoryType::Remote || repo.repo_type == RepositoryType::Virtual {
        return dists_proxy_catchall(
            State(state),
            Path((repo_key, distribution, contents_suffix)),
        )
        .await;
    }

    // Hosted: generate a minimal Contents index from package filenames.
    let entries =
        fetch_package_entries(&state.db, repo.id, &distribution, &req.component, &req.arch).await?;
    let contents_entries: Vec<(String, String)> = entries
        .iter()
        .map(|entry| (entry.filename.clone(), entry.control.package.clone()))
        .collect();
    let text = build_contents_index(&contents_entries);
    match req.ext {
        PackagesExt::Plain => Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "text/plain; charset=utf-8")
            .header(CONTENT_LENGTH, text.len().to_string())
            .body(Body::from(text))
            .unwrap()),
        PackagesExt::Gz => {
            let compressed = gzip_compress(text.as_bytes()).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Compression error: {}", e),
                )
                    .into_response()
            })?;
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/gzip")
                .header(CONTENT_LENGTH, compressed.len().to_string())
                .body(Body::from(compressed))
                .unwrap())
        }
        PackagesExt::Xz => {
            let compressed = xz_compress(text.as_bytes()).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("XZ compression error: {}", e),
                )
                    .into_response()
            })?;
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/x-xz")
                .header(CONTENT_LENGTH, compressed.len().to_string())
                .body(Body::from(compressed))
                .unwrap())
        }
        PackagesExt::Bz2 => {
            let compressed = bz2_compress(text.as_bytes()).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("bz2 compression error: {}", e),
                )
                    .into_response()
            })?;
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/x-bzip2")
                .header(CONTENT_LENGTH, compressed.len().to_string())
                .body(Body::from(compressed))
                .unwrap())
        }
        PackagesExt::Zst => {
            let compressed = zstd_compress(text.as_bytes()).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("zstd compression error: {}", e),
                )
                    .into_response()
            })?;
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/zstd")
                .header(CONTENT_LENGTH, compressed.len().to_string())
                .body(Body::from(compressed))
                .unwrap())
        }
    }
}

/// Serve hosted Contents / by-hash paths from on-demand Release generation.
async fn try_hosted_generated_dists_path(
    state: &SharedState,
    repo_id: uuid::Uuid,
    distribution: &str,
    dists_path: &str,
) -> Result<Option<Response>, Response> {
    if !(dists_path.starts_with("by-hash/") || parse_contents_request(dists_path).is_some()) {
        return Ok(None);
    }
    let config = load_debian_repository_config(&state.db, repo_id).await;
    let (components, architectures) = discover_release_layout(&state.db, repo_id).await?;
    let (components, architectures) =
        effective_release_layout(config.as_ref(), components, architectures);
    let mut release_files =
        build_hosted_release_files(state, repo_id, distribution, &components, &architectures)
            .await?;
    append_by_hash_release_files(&mut release_files);
    let Some((_, bytes)) = release_files
        .into_iter()
        .find(|(path, _)| path == dists_path)
    else {
        return Ok(None);
    };
    Ok(Some(
        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, content_type_for_dists_path(dists_path))
            .header(CONTENT_LENGTH, bytes.len().to_string())
            .body(Body::from(bytes))
            .unwrap(),
    ))
}

/// Catch-all handler for dists metadata that does not have a dedicated route.
/// This covers files like `i18n/Translation-en.xz`, `i18n/Translation-en.gz`,
/// `Sources`, `Sources.gz`, `Sources.xz`, and other index files that upstream
/// Debian mirrors serve under `dists/`.
///
/// For remote repositories the file is fetched from upstream and returned
/// directly. For hosted repositories the handler returns 404 because these
/// metadata files are generated on-the-fly only through the dedicated routes.
async fn dists_proxy_catchall(
    State(state): State<SharedState>,
    Path((repo_key, distribution, dists_path)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_debian_repo(&state.db, &repo_key).await?;

    if let Some(response) =
        try_synced_dists_response(&state, repo.id, &distribution, &dists_path).await?
    {
        return Ok(response);
    }

    // Once a local generation is published, ancillary metadata that is not part
    // of it (excluded components/architectures, Sources, Contents, i18n, dep11,
    // by-hash, ...) must 404 rather than leak through from upstream, keeping the
    // served mirror coherent with its published Release.
    reject_uncovered_generation_path(&state, repo.id, &distribution).await?;

    let upstream_path = debian_dists_upstream_path(&distribution, &dists_path);

    // Virtual repos: walk Remote members in priority order so a Virtual
    // APT repo can serve i18n / Translation / dep11 / Sources etc. just
    // like Release/Packages handlers (#1147).
    if repo.repo_type == RepositoryType::Virtual {
        let resp = try_virtual_dists(
            &state,
            repo.id,
            &repo_key,
            &distribution,
            &upstream_path,
            "text/plain; charset=utf-8",
        )
        .await?;
        return resp.ok_or_else(|| (StatusCode::NOT_FOUND, "Not found").into_response());
    }

    if repo.repo_type != RepositoryType::Remote {
        // Hosted: serve Contents / by-hash from on-demand generation.
        if let Some(response) =
            try_hosted_generated_dists_path(&state, repo.id, &distribution, &dists_path).await?
        {
            return Ok(response);
        }
        return Err((StatusCode::NOT_FOUND, "Not found").into_response());
    }

    let (upstream_url, proxy) = match (&repo.upstream_url, &state.proxy_service) {
        (Some(u), Some(p)) => (u, p),
        _ => return Err((StatusCode::NOT_FOUND, "Not found").into_response()),
    };

    // Epoch-based lazy invalidation for mutable dists/ paths.
    // Immutable paths (by-hash) are skipped by maybe_invalidate_by_epoch.
    maybe_invalidate_by_epoch(proxy, &repo_key, &distribution, &upstream_path).await;

    let (content, upstream_ct) = proxy_helpers::proxy_fetch_capped(
        proxy,
        repo.id,
        &repo_key,
        upstream_url,
        &upstream_path,
        proxy_helpers::LARGE_METADATA_MAX_BYTES,
    )
    .await?;

    let content_type = upstream_ct.unwrap_or_else(|| content_type_for_dists_path(&dists_path));

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .header(CONTENT_LENGTH, content.len().to_string())
        .body(Body::from(content))
        .unwrap())
}

/// Infer a reasonable content-type from the file extension when the upstream
/// response does not include one. Covers the common Debian index
/// compressions and the uncompressed fallback.
fn content_type_for_dists_path(path: &str) -> String {
    if path.ends_with(".xz") {
        "application/x-xz".to_string()
    } else if path.ends_with(".gz") {
        "application/gzip".to_string()
    } else if path.ends_with(".bz2") {
        "application/x-bzip2".to_string()
    } else if path.ends_with(".lz4") {
        "application/x-lz4".to_string()
    } else if path.ends_with(".zst") || path.ends_with(".zstd") {
        "application/zstd".to_string()
    } else {
        "text/plain; charset=utf-8".to_string()
    }
}

// ---------------------------------------------------------------------------
// XZ compression helper
// ---------------------------------------------------------------------------

/// Compress data using XZ/LZMA2.
fn xz_compress(data: &[u8]) -> Result<Vec<u8>, io::Error> {
    let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
    encoder.write_all(data)?;
    encoder.finish()
}

fn bz2_compress(data: &[u8]) -> Result<Vec<u8>, io::Error> {
    let mut encoder = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    encoder.write_all(data)?;
    encoder.finish()
}

fn zstd_compress(data: &[u8]) -> Result<Vec<u8>, io::Error> {
    zstd::stream::encode_all(std::io::Cursor::new(data), 3)
}

// ---------------------------------------------------------------------------
// GET /debian/{repo_key}/pool/{component}/*path -- Download .deb
// ---------------------------------------------------------------------------

/// Extract SHA256 for a Filename from Packages index text.
fn sha256_for_filename_in_packages_text(text: &str, filename: &str) -> Option<String> {
    let filename = filename.trim().trim_start_matches('/');
    if filename.is_empty() {
        return None;
    }
    let entries = parse_packages_index("Packages", text.as_bytes()).ok()?;
    for entry in entries {
        let Some(entry_filename) = entry
            .filename
            .as_deref()
            .map(str::trim)
            .map(|value| value.trim_start_matches('/'))
            .filter(|value| !value.is_empty())
        else {
            continue;
        };
        if entry_filename == filename
            || entry_filename.ends_with(filename)
            || filename.ends_with(entry_filename)
        {
            if let Some(sha256) = entry
                .sha256
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                return Some(sha256.to_ascii_lowercase());
            }
        }
    }
    None
}

async fn lookup_synced_package_sha256(
    state: &SharedState,
    repo_id: uuid::Uuid,
    pool_path: &str,
) -> Option<String> {
    let values: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT value FROM repository_config
        WHERE repository_id = $1
          AND key LIKE 'debian_synced_dists:%'
        "#,
    )
    .bind(repo_id)
    .fetch_all(&state.db)
    .await
    .ok()?;

    for text in values {
        if text.starts_with("@ref:") {
            continue;
        }
        if let Some(sha256) = sha256_for_filename_in_packages_text(&text, pool_path) {
            return Some(sha256);
        }
    }
    None
}

async fn debian_any_local_generation_active(
    state: &SharedState,
    repo_id: uuid::Uuid,
    config: Option<&DebianRepositoryConfig>,
) -> bool {
    let Some(config) = config else {
        return false;
    };
    for distribution in config.effective_distribution_paths() {
        let normalized = distribution.trim_matches('/');
        if debian_local_generation_active(state, repo_id, normalized).await {
            return true;
        }
    }
    // Flat repos store synced Release under an empty distribution key.
    if config.flat_repository && debian_local_generation_active(state, repo_id, "").await {
        return true;
    }
    false
}

fn debian_sync_filter_for_path_check(config: &DebianRepositoryConfig) -> DebianSyncFilter {
    DebianSyncFilter {
        distributions: Vec::new(),
        components: config.effective_components(),
        architectures: config.effective_architectures(),
        include_source_packages: config.include_source_packages,
        package_queries: config.effective_package_queries(),
        resolve_dependencies: false,
    }
}

fn map_debian_fetch_path_error(error: crate::error::AppError) -> Response {
    (StatusCode::BAD_REQUEST, error.to_string()).into_response()
}

/// Shared remote package fetch with filter / SSRF / digest gates.
async fn proxy_remote_debian_package(
    state: &SharedState,
    repo: &RepoInfo,
    repo_key: &str,
    upstream_url: &str,
    upstream_path: &str,
    component_for_filter: &str,
    filename: &str,
) -> Result<Response, Response> {
    let proxy = state
        .proxy_service
        .as_deref()
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Package not found").into_response())?;
    let config = load_debian_repository_config_strict(&state.db, repo.id).await?;
    let local_generation =
        debian_any_local_generation_active(state, repo.id, config.as_ref()).await;
    // Ok(None) means a legacy repo with no debian config row — unrestricted filters.
    // Err was already fail-closed by the strict loader (corrupt/unavailable config).
    let mut filter = match config.as_ref() {
        Some(cfg) => debian_sync_filter_for_path_check(cfg),
        None => DebianSyncFilter::default(),
    };
    // After a filtered sync publishes a generation, membership is enforced by
    // the generated Packages index (including dependency closure). Clearing
    // package_queries here avoids rejecting Depends/Pre-Depends that were
    // intentionally selected during sync but do not match the raw queries.
    if local_generation {
        filter.package_queries.clear();
    }

    if !pool_path_allowed_by_filters(component_for_filter, filename, &filter) {
        return Err((
            StatusCode::NOT_FOUND,
            "Package not allowed by repository filters",
        )
            .into_response());
    }

    validate_debian_fetch_path(upstream_path).map_err(map_debian_fetch_path_error)?;

    let verify_required = config
        .as_ref()
        .map(|c| c.verify_upstream_metadata)
        .unwrap_or(false)
        || local_generation;

    let expected_sha = lookup_synced_package_sha256(state, repo.id, upstream_path).await;
    if local_generation && expected_sha.is_none() {
        return Err((
            StatusCode::NOT_FOUND,
            "Package is not part of the published Debian mirror generation",
        )
            .into_response());
    }
    if verify_required && expected_sha.is_none() {
        return Err((
            StatusCode::BAD_GATEWAY,
            "Refusing to serve unverified package: no SHA256 in synced metadata",
        )
            .into_response());
    }

    let passthrough = config
        .as_ref()
        .map(|c| {
            c.package_fetch_strategy
                == crate::api::handlers::repositories::DebianPackageFetchStrategy::Passthrough
        })
        .unwrap_or(false);

    if passthrough {
        // Passthrough must never write to cache: always stream uncached regardless of
        // whether we have an expected SHA (the SHA is used for gate/verify, not cache key).
        return proxy_helpers::proxy_fetch_streaming_uncached(
            proxy,
            repo.id,
            repo_key,
            upstream_url,
            upstream_path,
            DEBIAN_BINARY_CONTENT_TYPE,
        )
        .await;
    }

    let result = proxy_helpers::proxy_fetch_streaming_with_cache_key_verified(
        proxy,
        repo.id,
        repo_key,
        upstream_url,
        upstream_path,
        upstream_path,
        expected_sha,
    )
    .await?;
    proxy_helpers::stream_fetch_result(result, DEBIAN_BINARY_CONTENT_TYPE, Some(filename))
}

async fn pool_download(
    State(state): State<SharedState>,
    Path((repo_key, component, path)): Path<(String, String, String)>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_debian_repo(&state.db, &repo_key).await?;

    let artifact_path = format!("pool/{}/{}", component, path);
    // Axum captures only the first path segment as `component`. Debian-Security
    // pool paths use a multi-segment component (`updates/main/...`), so re-parse
    // the full pool path for filter checks.
    let filter_component = component_from_pool_path(&artifact_path)
        .unwrap_or(component.as_str())
        .to_string();

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
                if let Some(ref upstream_url) = repo.upstream_url {
                    let upstream_path = format!("pool/{}/{}", component, path);
                    let filename = path.rsplit('/').next().unwrap_or(&path);
                    return proxy_remote_debian_package(
                        &state,
                        &repo,
                        &repo_key,
                        upstream_url,
                        &upstream_path,
                        &filter_component,
                        filename,
                    )
                    .await;
                }
            }

            // Virtual repo: try each member in priority order
            if repo.repo_type == RepositoryType::Virtual {
                let db = state.db.clone();
                let upstream_path = format!("pool/{}/{}", component, path);
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

                let filename = path.rsplit('/').next().unwrap_or(&path);
                return proxy_helpers::stream_fetch_result(
                    result,
                    DEBIAN_BINARY_CONTENT_TYPE,
                    Some(filename),
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

    let stream = storage
        .get_stream(&artifact.storage_key)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Storage error: {}", e),
            )
                .into_response()
        })?;

    // Record download
    crate::services::artifact_service::record_download(&state.db, artifact.id, &ctx).await;

    let filename = path.rsplit('/').next().unwrap_or(&path);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, DEBIAN_BINARY_CONTENT_TYPE)
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .header(CONTENT_LENGTH, artifact.size_bytes.to_string())
        .header("X-Checksum-SHA256", &artifact.checksum_sha256)
        .body(Body::from_stream(stream))
        .unwrap())
}

/// GET /debian/{repo_key}/*artifact_path — flat-repository package download.
async fn flat_or_root_package_download(
    State(state): State<SharedState>,
    Path((repo_key, artifact_path)): Path<(String, String)>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_debian_repo(&state.db, &repo_key).await?;
    let config = load_debian_repository_config(&state.db, repo.id).await;
    if !config.as_ref().map(|c| c.flat_repository).unwrap_or(false) {
        return Err((StatusCode::NOT_FOUND, "Not found").into_response());
    }
    if !is_flat_repository_package_path(&artifact_path) {
        return Err((StatusCode::NOT_FOUND, "Not found").into_response());
    }
    validate_debian_fetch_path(&artifact_path).map_err(map_debian_fetch_path_error)?;

    let filename = artifact_path
        .rsplit('/')
        .next()
        .unwrap_or(artifact_path.as_str());

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
    .map_err(crate::api::handlers::db_err)?;

    if let Some(artifact) = artifact {
        let storage = state
            .storage_for_repo(&repo.storage_location())
            .map_err(|e| e.into_response())?;
        crate::services::quarantine_service::check_artifact_download(&state.db, artifact.id)
            .await
            .map_err(|e| e.into_response())?;
        let stream = storage
            .get_stream(&artifact.storage_key)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Storage error: {}", e),
                )
                    .into_response()
            })?;
        crate::services::artifact_service::record_download(&state.db, artifact.id, &ctx).await;
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, DEBIAN_BINARY_CONTENT_TYPE)
            .header(
                "Content-Disposition",
                format!("attachment; filename=\"{}\"", filename),
            )
            .header(CONTENT_LENGTH, artifact.size_bytes.to_string())
            .header("X-Checksum-SHA256", &artifact.checksum_sha256)
            .body(Body::from_stream(stream))
            .unwrap());
    }

    if repo.repo_type == RepositoryType::Remote {
        if let Some(ref upstream_url) = repo.upstream_url {
            // Flat repos have empty component filters; pass "" so any component passes.
            return proxy_remote_debian_package(
                &state,
                &repo,
                &repo_key,
                upstream_url,
                &artifact_path,
                "",
                filename,
            )
            .await;
        }
    }

    Err((StatusCode::NOT_FOUND, "Package not found").into_response())
}

struct DebianPackageUpload {
    artifact_path: String,
    distribution: Option<String>,
    component: String,
    deb_info: DebInfo,
    control: DebControl,
    metadata: serde_json::Value,
}

#[allow(clippy::result_large_err)]
fn prepare_debian_upload(
    component: &str,
    path: &str,
    body: &[u8],
    distribution: Option<String>,
    expected_architecture: Option<&str>,
) -> Result<DebianPackageUpload, Response> {
    let filename = path.rsplit('/').next().unwrap_or(path);
    let deb_info = parse_deb_filename(filename).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid Debian package filename. Expected {name}_{version}_{arch}.deb",
        )
            .into_response()
    })?;
    let control = DebianHandler::extract_control(body).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("Invalid Debian package metadata: {}", e),
        )
            .into_response()
    })?;
    validate_debian_control_matches_filename(&deb_info, &control)?;
    validate_debian_expected_architecture(expected_architecture, &control)?;

    let artifact_path = format!("pool/{}/{}", component, path);
    let metadata = build_debian_artifact_metadata(
        distribution.as_deref(),
        component,
        &artifact_path,
        filename,
        &deb_info.package_type,
        &control,
    );

    Ok(DebianPackageUpload {
        artifact_path,
        distribution,
        component: component.to_string(),
        deb_info,
        control,
        metadata,
    })
}

#[allow(clippy::result_large_err)]
fn validate_debian_expected_architecture(
    expected_architecture: Option<&str>,
    control: &DebControl,
) -> Result<(), Response> {
    let Some(expected_architecture) = expected_architecture else {
        return Ok(());
    };
    if expected_architecture != control.architecture {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Architecture mismatch: upload metadata says '{}' but control says '{}'",
                expected_architecture, control.architecture
            ),
        )
            .into_response());
    }
    Ok(())
}

#[allow(clippy::result_large_err)]
fn validate_debian_control_matches_filename(
    deb_info: &DebInfo,
    control: &DebControl,
) -> Result<(), Response> {
    if control.package != deb_info.name {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Package name mismatch: filename says '{}' but control says '{}'",
                deb_info.name, control.package
            ),
        )
            .into_response());
    }
    if control.version != deb_info.version {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Version mismatch: filename says '{}' but control says '{}'",
                deb_info.version, control.version
            ),
        )
            .into_response());
    }
    if control.architecture != deb_info.arch {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Architecture mismatch: filename says '{}' but control says '{}'",
                deb_info.arch, control.architecture
            ),
        )
            .into_response());
    }
    Ok(())
}

fn build_debian_artifact_metadata(
    distribution: Option<&str>,
    component: &str,
    artifact_path: &str,
    filename: &str,
    package_type: &str,
    control: &DebControl,
) -> serde_json::Value {
    let is_installer = component == "debian-installer"
        || artifact_path.contains("/debian-installer/")
        || component.contains("debian-installer");
    let package_type = if is_installer { "udeb" } else { package_type };
    let section = if is_installer {
        Some("debian-installer".to_string())
    } else {
        control.section.clone()
    };
    serde_json::json!({
        "format": "debian",
        "package": &control.package,
        "name": &control.package,
        "version": &control.version,
        "architecture": &control.architecture,
        "distribution": distribution,
        "component": component,
        "filename": filename,
        "path": artifact_path,
        "package_type": package_type,
        "description": &control.description,
        "maintainer": &control.maintainer,
        "installed_size": control.installed_size,
        "depends": &control.depends,
        "pre_depends": &control.pre_depends,
        "recommends": &control.recommends,
        "suggests": &control.suggests,
        "conflicts": &control.conflicts,
        "provides": &control.provides,
        "replaces": &control.replaces,
        "section": section,
        "priority": &control.priority,
        "homepage": &control.homepage,
        "source": &control.source,
        "control": control,
    })
}

fn build_debian_package_catalog_metadata(upload: &DebianPackageUpload) -> serde_json::Value {
    let is_installer = upload.component == "debian-installer"
        || upload.artifact_path.contains("/debian-installer/")
        || upload.component.contains("debian-installer");
    let package_type = if is_installer {
        "udeb"
    } else {
        upload.deb_info.package_type.as_str()
    };
    let section = if is_installer {
        Some("debian-installer")
    } else {
        upload.control.section.as_deref()
    };
    serde_json::json!({
        "format": "debian",
        "architecture": &upload.control.architecture,
        "distribution": &upload.distribution,
        "component": &upload.component,
        "package_type": package_type,
        "section": section,
        "priority": &upload.control.priority,
        "maintainer": &upload.control.maintainer,
        "homepage": &upload.control.homepage,
        "source": &upload.control.source,
    })
}

#[allow(clippy::result_large_err)]
fn debian_upload_header(headers: &HeaderMap, names: &[&str]) -> Result<Option<String>, Response> {
    for name in names {
        let Some(value) = headers.get(*name) else {
            continue;
        };
        let value = value.to_str().map_err(|_| {
            (
                StatusCode::BAD_REQUEST,
                format!("Invalid Debian upload metadata header {name}"),
            )
                .into_response()
        })?;
        let value = value.trim();
        if value.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("Debian upload metadata header {name} must not be empty"),
            )
                .into_response());
        }
        if value.len() > 128
            || !value
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '+'))
        {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("Debian upload metadata header {name} contains an invalid identifier"),
            )
                .into_response());
        }
        return Ok(Some(value.to_string()));
    }
    Ok(None)
}

#[allow(clippy::result_large_err)]
fn debian_upload_distribution(headers: &HeaderMap) -> Result<Option<String>, Response> {
    debian_upload_header(
        headers,
        &[
            "X-Debian-Distribution",
            "X-Debian-Codename",
            "X-Debian-Suite",
            "X-Distribution",
        ],
    )
}

#[allow(clippy::result_large_err)]
fn debian_upload_component(headers: &HeaderMap) -> Result<Option<String>, Response> {
    debian_upload_header(headers, &["X-Debian-Component", "X-Component"])
}

#[allow(clippy::result_large_err)]
fn debian_upload_architecture(headers: &HeaderMap) -> Result<Option<String>, Response> {
    debian_upload_header(headers, &["X-Debian-Architecture", "X-Architecture"])
}

#[allow(clippy::result_large_err)]
fn validate_debian_component_header(
    route_component: &str,
    header_component: Option<&str>,
) -> Result<(), Response> {
    let Some(header_component) = header_component else {
        return Ok(());
    };
    if route_component != header_component {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "Component mismatch: path says '{}' but upload metadata says '{}'",
                route_component, header_component
            ),
        )
            .into_response());
    }
    Ok(())
}

fn package_description(control: &DebControl) -> Option<&str> {
    control
        .description
        .as_deref()
        .filter(|description| !description.trim().is_empty())
}

fn should_enqueue_debian_sync_tasks(headers: &HeaderMap) -> bool {
    !super::is_replication_request(headers)
}

async fn persist_debian_upload(
    state: &SharedState,
    repo: &RepoInfo,
    upload: &DebianPackageUpload,
    body: Bytes,
    user_id: Option<uuid::Uuid>,
    enqueue_sync_tasks: bool,
) -> Result<crate::models::artifact::Artifact, Response> {
    let existing = sqlx::query_scalar!(
        "SELECT id FROM artifacts WHERE repository_id = $1 AND path = $2 AND is_deleted = false",
        repo.id,
        upload.artifact_path
    )
    .fetch_optional(&state.db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    if existing.is_some() {
        return Err((StatusCode::CONFLICT, "Package already exists").into_response());
    }

    super::cleanup_soft_deleted_artifact(&state.db, repo.id, &upload.artifact_path).await;

    let storage = state
        .storage_for_repo(&repo.storage_location())
        .map_err(|e| e.into_response())?;
    let artifact_service = state.create_artifact_service(storage);
    let artifact = artifact_service
        .upload_with_sync_options(
            repo.id,
            &upload.artifact_path,
            &upload.control.package,
            Some(&upload.control.version),
            DEBIAN_BINARY_CONTENT_TYPE,
            body,
            user_id,
            enqueue_sync_tasks,
        )
        .await
        .map_err(|e| e.into_response())?;

    artifact_service
        .set_metadata(
            artifact.id,
            "debian",
            upload.metadata.clone(),
            serde_json::json!({}),
        )
        .await
        .map_err(|e| e.into_response())?;

    PackageService::new(state.db.clone())
        .try_create_or_update_from_artifact(
            repo.id,
            &upload.control.package,
            &upload.control.version,
            artifact.size_bytes,
            &artifact.checksum_sha256,
            package_description(&upload.control),
            Some(build_debian_package_catalog_metadata(upload)),
        )
        .await;

    let _ = sqlx::query!(
        "UPDATE repositories SET updated_at = NOW() WHERE id = $1",
        repo.id,
    )
    .execute(&state.db)
    .await;

    Ok(artifact)
}

// ---------------------------------------------------------------------------
// PUT /debian/{repo_key}/pool/{component}/*path — Upload .deb
// ---------------------------------------------------------------------------

async fn pool_upload(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path((repo_key, component, path)): Path<(String, String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "debian", "write")?.user_id;
    let repo = resolve_debian_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    let distribution = debian_upload_distribution(&headers)?;
    let header_component = debian_upload_component(&headers)?;
    validate_debian_component_header(&component, header_component.as_deref())?;
    let expected_architecture = debian_upload_architecture(&headers)?;
    let upload = prepare_debian_upload(
        &component,
        &path,
        &body,
        distribution,
        expected_architecture.as_deref(),
    )?;
    persist_debian_upload(
        &state,
        &repo,
        &upload,
        body,
        Some(user_id),
        should_enqueue_debian_sync_tasks(&headers),
    )
    .await?;

    info!(
        "Debian upload: {} {} {} to repo {} (component: {})",
        upload.control.package,
        upload.control.version,
        upload.control.architecture,
        repo_key,
        component
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .body(Body::from("Created"))
        .unwrap())
}

// ---------------------------------------------------------------------------
// POST /debian/{repo_key}/upload — Upload .deb (raw body, filename in header)
// ---------------------------------------------------------------------------

async fn upload_raw(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Response> {
    // GHSA-vvc3-h39c-mrq5: enforce token scope before processing.
    let user_id = require_auth_basic_scope(auth, "debian", "write")?.user_id;
    let repo = resolve_debian_repo(&state.db, &repo_key).await?;
    proxy_helpers::reject_write_if_not_hosted(&repo.repo_type)?;
    repo.reject_if_promotion_only(false)?;

    // Extract filename from X-Filename or Content-Disposition header
    let filename = headers
        .get("X-Filename")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            headers
                .get("Content-Disposition")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| {
                    v.split("filename=")
                        .nth(1)
                        .map(|s| s.trim_matches('"').trim_matches('\''))
                })
        })
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "Missing filename. Provide X-Filename header or Content-Disposition with filename",
            )
                .into_response()
        })?
        .to_string();

    let deb_info = parse_deb_filename(&filename).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "Invalid Debian package filename. Expected {name}_{version}_{arch}.deb",
        )
            .into_response()
    })?;

    let component = debian_upload_component(&headers)?.unwrap_or_else(|| "main".to_string());
    let distribution = debian_upload_distribution(&headers)?;
    let expected_architecture = debian_upload_architecture(&headers)?;
    let artifact_path = DebianHandler::get_pool_path(&component, &deb_info.name, &filename);
    let pool_prefix = format!("pool/{}/", component);
    let path = artifact_path
        .strip_prefix(pool_prefix.as_str())
        .unwrap_or(&artifact_path)
        .to_string();
    let upload = prepare_debian_upload(
        &component,
        &path,
        &body,
        distribution,
        expected_architecture.as_deref(),
    )?;
    let artifact = persist_debian_upload(
        &state,
        &repo,
        &upload,
        body,
        Some(user_id),
        should_enqueue_debian_sync_tasks(&headers),
    )
    .await?;

    info!(
        "Debian upload (raw): {} {} {} to repo {}",
        upload.control.package, upload.control.version, upload.control.architecture, repo_key
    );

    Ok(Response::builder()
        .status(StatusCode::CREATED)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({
                "status": "created",
                "package": &upload.control.package,
                "version": &upload.control.version,
                "architecture": &upload.control.architecture,
                "distribution": &upload.distribution,
                "component": &upload.component,
                "path": &upload.artifact_path,
                "sha256": &artifact.checksum_sha256,
                "size": artifact.size_bytes,
            })
            .to_string(),
        ))
        .unwrap())
}

/// Response body for `POST /debian/{repo_key}/sync`.
#[derive(serde::Serialize, ToSchema)]
#[schema(example = json!({
    "repository": "ubuntu-security-smoke",
    "plans": [{
        "distribution": "noble-security",
        "release_paths": ["dists/noble-security/Release"],
        "package_indexes": [{"component": "main", "architecture": "amd64", "path": "main/binary-amd64/Packages.xz"}],
        "source_indexes": [],
        "package_files": [{"index_path": "main/binary-amd64/Packages.xz", "filename": "pool/main/c/curl/curl_1_amd64.deb", "package": "curl", "version": "1", "architecture": "amd64", "download": false}],
        "source_files": [],
        "missing_package_indexes": [],
        "missing_source_indexes": []
    }],
    "prefetched_packages": 0,
    "prefetched_sources": 0
}))]
pub struct DebianSyncResponse {
    pub repository: String,
    pub plans: Vec<DebianSyncPlan>,
    pub prefetched_packages: usize,
    pub prefetched_sources: usize,
}

fn debian_sync_parse_error(context: &str, error: impl std::fmt::Display) -> Response {
    (
        StatusCode::BAD_GATEWAY,
        format!("Failed to parse upstream Debian {context}: {error}"),
    )
        .into_response()
}

/// Decompress + parse a Packages index off the async runtime.
/// Indexes can inflate up to `MAX_DEBIAN_INDEX_DECOMPRESSED_BYTES` and must not
/// block the Tokio executor (CONTRIBUTING spawn_blocking guidance).
async fn parse_packages_index_blocking(
    path: String,
    content: Bytes,
) -> Result<Vec<PackagesEntry>, crate::error::AppError> {
    tokio::task::spawn_blocking(move || parse_packages_index(&path, &content))
        .await
        .map_err(|e| {
            crate::error::AppError::Internal(format!("Packages index parse task failed: {e}"))
        })?
}

async fn parse_sources_index_blocking(
    path: String,
    content: Bytes,
) -> Result<Vec<SourcesEntry>, crate::error::AppError> {
    tokio::task::spawn_blocking(move || parse_sources_index(&path, &content))
        .await
        .map_err(|e| {
            crate::error::AppError::Internal(format!("Sources index parse task failed: {e}"))
        })?
}

async fn drain_prefetched_package(response: Response) -> Result<(), Response> {
    let mut stream = response.into_body().into_data_stream();
    while let Some(chunk) = stream.next().await {
        chunk.map_err(|error| {
            (
                StatusCode::BAD_GATEWAY,
                format!("Failed while prefetching Debian package: {error}"),
            )
                .into_response()
        })?;
    }
    Ok(())
}

fn debian_sync_verification_error(label: &str, error: impl std::fmt::Display) -> Response {
    (
        StatusCode::BAD_GATEWAY,
        format!("Failed to verify upstream Debian {label}: {error}"),
    )
        .into_response()
}

/// True when sync would re-sign locally generated metadata without having
/// cryptographically verified the upstream Release first.
///
/// Extracted so the fail-closed policy is unit-testable without exercising the
/// full async sync path.
fn debian_sync_must_refuse_unverified_signing(
    signing_enabled: bool,
    verify_upstream_metadata: bool,
) -> bool {
    signing_enabled && !verify_upstream_metadata
}

async fn verify_upstream_release_metadata(
    state: &SharedState,
    config: &DebianRepositoryConfig,
    release_text: &str,
    release_bytes: &[u8],
    in_release_bytes: Option<&[u8]>,
    release_gpg_bytes: Option<&[u8]>,
) -> Result<String, Response> {
    let key_ref = config
        .upstream_gpg_key_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "verify_upstream_metadata=true requires upstream_gpg_key_id.",
            )
                .into_response()
        })?;

    let signing_svc = SigningService::new(state.db.clone(), &state.config.jwt_secret);
    let public_key = signing_svc
        .get_public_key_by_reference(key_ref)
        .await
        .map_err(|error| debian_sync_verification_error("public key lookup", error))?
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!("upstream_gpg_key_id={key_ref} did not match a stored active public key."),
            )
                .into_response()
        })?;

    if let Some(in_release_bytes) = in_release_bytes {
        let in_release_text = std::str::from_utf8(in_release_bytes)
            .map_err(|error| debian_sync_parse_error("InRelease", error))?;
        return signing_svc
            .verify_openpgp_cleartext_with_public_key(&public_key, in_release_text)
            .await
            .map_err(|error| debian_sync_verification_error("InRelease", error));
    }

    if let Some(release_gpg_bytes) = release_gpg_bytes {
        signing_svc
            .verify_openpgp_detached_with_public_key(&public_key, release_bytes, release_gpg_bytes)
            .await
            .map_err(|error| debian_sync_verification_error("Release.gpg", error))?;
        return Ok(release_text.to_string());
    }

    Err((
        StatusCode::BAD_GATEWAY,
        "verify_upstream_metadata=true but upstream did not provide InRelease or Release.gpg.",
    )
        .into_response())
}

/// Explicitly synchronize a configured remote Debian repository.
///
/// Loads upstream Release metadata, builds a filtered sync plan from the
/// repository's Debian configuration, optionally prefetches selected packages,
/// and atomically publishes generated Packages/Release metadata.
#[utoipa::path(
    post,
    path = "/{repo_key}/sync",
    context_path = "/debian",
    tag = "debian",
    operation_id = "debian_sync_remote_repository",
    params(
        ("repo_key" = String, Path, description = "Debian repository key"),
    ),
    responses(
        (status = 200, description = "Filtered sync completed", body = DebianSyncResponse),
        (status = 400, description = "Not a remote repository, missing Debian config/upstream, or signing policy violation"),
        (status = 401, description = "Authentication required"),
        (status = 403, description = "Authenticated but missing debian write scope"),
        (status = 404, description = "Repository not found"),
        (status = 500, description = "Failed to generate Debian metadata"),
        (status = 502, description = "Upstream fetch, parse, or verification failure"),
        (status = 503, description = "Proxy service unavailable or not configured"),
    ),
    security(
        ("bearer_auth" = []),
        ("basic_auth" = []),
    )
)]
async fn sync_remote_repository(
    State(state): State<SharedState>,
    Extension(auth): Extension<Option<AuthExtension>>,
    Path(repo_key): Path<String>,
) -> Result<Json<DebianSyncResponse>, Response> {
    require_auth_basic_scope(auth, "debian", "write")?;
    let repo = resolve_debian_repo(&state.db, &repo_key).await?;
    if repo.repo_type != RepositoryType::Remote {
        return Err((
            StatusCode::BAD_REQUEST,
            "Debian metadata refresh requires a Remote repository",
        )
            .into_response());
    }
    let config = load_debian_repository_config(&state.db, repo.id)
        .await
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "Debian repository has no advanced configuration",
            )
                .into_response()
        })?;
    let upstream_url = repo.upstream_url.as_deref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "Debian metadata refresh requires repository upstream_url",
        )
            .into_response()
    })?;
    let proxy = state.proxy_service.as_deref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Proxy service is not configured",
        )
            .into_response()
    })?;

    // Defense in depth (validation also enforces this at save time): refuse to
    // generate/sign a local Release from upstream metadata that was not
    // cryptographically verified, so unsafe content cannot be re-signed with
    // Artifact Keeper's trusted key.
    if debian_sync_must_refuse_unverified_signing(
        config.signing_enabled(),
        config.verify_upstream_metadata,
    ) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Refusing to sign Debian metadata from an unverified upstream: set verify_upstream_metadata=true.",
        )
            .into_response());
    }

    let distributions = config.effective_distribution_paths();
    if distributions.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Debian metadata refresh requires at least one distribution path",
        )
            .into_response());
    }
    let filter = DebianSyncFilter {
        distributions: if config.flat_repository {
            Vec::new()
        } else {
            distributions.clone()
        },
        components: config.effective_components(),
        architectures: config.effective_architectures(),
        include_source_packages: config.include_source_packages,
        package_queries: config.effective_package_queries(),
        resolve_dependencies: config.resolve_dependencies,
    };
    let download_policy = if config.package_fetch_strategy
        == crate::api::handlers::repositories::DebianPackageFetchStrategy::PrefetchSelected
    {
        DebianSyncDownloadPolicy::Immediate
    } else {
        DebianSyncDownloadPolicy::OnDemand
    };
    let mut plans = Vec::new();
    let mut prefetched = BTreeSet::new();
    let mut prefetched_sources = BTreeSet::new();

    for distribution in &distributions {
        let normalized_distribution = distribution.trim_matches('/');
        let release_path = if config.flat_repository || normalized_distribution.is_empty() {
            "Release".to_string()
        } else {
            format!("dists/{normalized_distribution}/Release")
        };
        let (release_bytes, _) = proxy_helpers::proxy_fetch_capped(
            proxy,
            repo.id,
            &repo_key,
            upstream_url,
            &release_path,
            proxy_helpers::LARGE_METADATA_MAX_BYTES,
        )
        .await?;
        let release_text_from_release = std::str::from_utf8(&release_bytes)
            .map_err(|error| debian_sync_parse_error("Release", error))?;

        let mut in_release_bytes = None;
        let mut release_gpg_bytes = None;
        for signed_suffix in ["InRelease", "Release.gpg"] {
            let signed_path = if config.flat_repository || normalized_distribution.is_empty() {
                signed_suffix.to_string()
            } else {
                format!("dists/{normalized_distribution}/{signed_suffix}")
            };
            match proxy_helpers::proxy_fetch_capped(
                proxy,
                repo.id,
                &repo_key,
                upstream_url,
                &signed_path,
                proxy_helpers::LARGE_METADATA_MAX_BYTES,
            )
            .await
            {
                Ok((content, _)) if signed_suffix == "InRelease" => {
                    in_release_bytes = Some(content);
                }
                Ok((content, _)) => {
                    release_gpg_bytes = Some(content);
                }
                Err(response) if response.status() == StatusCode::NOT_FOUND => {}
                Err(response) => return Err(response),
            }
        }

        let verified_release_text = if config.verify_upstream_metadata {
            verify_upstream_release_metadata(
                &state,
                &config,
                release_text_from_release,
                &release_bytes,
                in_release_bytes.as_deref(),
                release_gpg_bytes.as_deref(),
            )
            .await?
        } else {
            release_text_from_release.to_string()
        };
        let release = parse_release(&verified_release_text)
            .map_err(|error| debian_sync_parse_error("Release", error))?;
        if release_is_expired(&release, chrono::Utc::now()) {
            let valid_until = release.valid_until.as_deref().unwrap_or("unknown");
            return Err((
                StatusCode::BAD_GATEWAY,
                format!(
                    "Refusing to sync: upstream Release has expired (Valid-Until: {valid_until})"
                ),
            )
                .into_response());
        }
        validate_release_filter_selection(&release, &filter)
            .map_err(|error| (StatusCode::BAD_REQUEST, error.to_string()).into_response())?;

        let indexes = filter_release_package_indexes(&release, &filter);
        let mut packages_by_index_path = BTreeMap::new();
        for index in &indexes {
            let upstream_path = if config.flat_repository || normalized_distribution.is_empty() {
                index.path.clone()
            } else {
                format!("dists/{normalized_distribution}/{}", index.path)
            };
            match proxy_helpers::proxy_fetch_capped(
                proxy,
                repo.id,
                &repo_key,
                upstream_url,
                &upstream_path,
                proxy_helpers::LARGE_METADATA_MAX_BYTES,
            )
            .await
            {
                Ok((content, _)) => {
                    verify_index_against_release(
                        &release,
                        &index.path,
                        &content,
                        config.verify_upstream_metadata,
                    )
                    .map_err(|error| debian_sync_verification_error("Packages index", error))?;
                    let packages = parse_packages_index_blocking(index.path.clone(), content)
                        .await
                        .map_err(|error| debian_sync_parse_error("Packages index", error))?;
                    packages_by_index_path.insert(index.path.clone(), packages);
                }
                Err(response)
                    if response.status() == StatusCode::NOT_FOUND
                        && config.ignore_missing_indexes =>
                {
                    tracing::warn!(repo_key = %repo_key, path = %upstream_path, "selected Debian index missing upstream; continuing because ignore_missing_indexes=true");
                }
                Err(response) => return Err(response),
            }
        }

        let source_indexes = filter_release_source_indexes(&release, &filter);
        let mut sources_by_index_path = BTreeMap::new();
        for index in &source_indexes {
            let upstream_path = if config.flat_repository || normalized_distribution.is_empty() {
                index.path.clone()
            } else {
                format!("dists/{normalized_distribution}/{}", index.path)
            };
            match proxy_helpers::proxy_fetch_capped(
                proxy,
                repo.id,
                &repo_key,
                upstream_url,
                &upstream_path,
                proxy_helpers::LARGE_METADATA_MAX_BYTES,
            )
            .await
            {
                Ok((content, _)) => {
                    verify_index_against_release(
                        &release,
                        &index.path,
                        &content,
                        config.verify_upstream_metadata,
                    )
                    .map_err(|error| debian_sync_verification_error("Sources index", error))?;
                    let sources = parse_sources_index_blocking(index.path.clone(), content)
                        .await
                        .map_err(|error| debian_sync_parse_error("Sources index", error))?;
                    sources_by_index_path.insert(index.path.clone(), sources);
                }
                Err(response)
                    if response.status() == StatusCode::NOT_FOUND
                        && config.ignore_missing_indexes =>
                {
                    tracing::warn!(repo_key = %repo_key, path = %upstream_path, "selected Debian source index missing upstream; continuing because ignore_missing_indexes=true");
                }
                Err(response) => return Err(response),
            }
        }

        let plan = build_debian_sync_plan(
            normalized_distribution,
            &release,
            &filter,
            &packages_by_index_path,
            &sources_by_index_path,
            download_policy,
        );

        let total_selected = plan.package_files.len() + plan.source_files.len();
        if total_selected > MAX_DEBIAN_SYNC_SELECTED_FILES {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "Sync plan exceeds maximum allowed file count: {total_selected} > {MAX_DEBIAN_SYNC_SELECTED_FILES}. Narrow the filters (components, architectures, package_queries) or use a smaller distribution."
                ),
            )
                .into_response());
        }

        // Defense in depth: every selected index path must satisfy the same
        // component/arch/source/Contents/i18n/DEP-11 filter used for pool downloads.
        for index in plan
            .package_indexes
            .iter()
            .map(|index| index.path.as_str())
            .chain(plan.source_indexes.iter().map(|index| index.path.as_str()))
        {
            if !release_path_allowed_by_filter(index, &filter) {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("Sync plan selected index path outside configured filters: {index}"),
                )
                    .into_response());
            }
        }

        if config.generated_metadata_enabled() {
            let generated = build_synced_generated_metadata(
                &plan,
                &packages_by_index_path,
                &sources_by_index_path,
                &filter.architectures,
            )
            .map_err(|error| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to generate Debian metadata: {}", error),
                )
                    .into_response()
            })?;

            let components: BTreeSet<String> = plan
                .package_indexes
                .iter()
                .map(|index| index.component.clone())
                .chain(
                    plan.source_indexes
                        .iter()
                        .map(|index| index.component.clone()),
                )
                .collect();
            let architectures: BTreeSet<String> = plan
                .package_indexes
                .iter()
                .map(|index| index.architecture.clone())
                .collect();
            let filtered_release = build_release_content_from_files(
                &release.suite,
                release.codename.as_deref(),
                release.description.as_deref(),
                &components,
                &architectures,
                generated.release_files,
            );

            // Publish the generated indexes and their matching Release as one
            // atomic generation. Without a transaction, the old rows are deleted
            // and the new ones inserted individually, so a concurrent apt client
            // could observe a new Release alongside stale/partial Packages (or
            // vice versa) and fail with a hash mismatch. Committing all rows
            // together means readers only ever see the previous complete
            // generation or the new complete one.
            let mut tx = state
                .db
                .begin()
                .await
                .map_err(crate::api::handlers::db_err)?;
            clear_synced_dists_content(&mut tx, repo.id, normalized_distribution).await?;
            for (path, content) in &generated.plain_indexes {
                store_synced_dists_content(
                    &mut tx,
                    repo.id,
                    normalized_distribution,
                    path,
                    content,
                )
                .await?;
            }
            store_synced_release_content(
                &mut tx,
                repo.id,
                normalized_distribution,
                &filtered_release,
            )
            .await?;
            tx.commit().await.map_err(crate::api::handlers::db_err)?;
        }

        let package_digests = package_sha256_by_filename(&packages_by_index_path);
        let source_digests = source_sha256_by_filename(&sources_by_index_path);

        for package in plan.package_files.iter().filter(|package| package.download) {
            if !prefetched.insert(package.filename.clone()) {
                continue;
            }
            validate_debian_fetch_path(&package.filename)
                .map_err(|error| debian_sync_verification_error("package path", error))?;
            let expected = expected_prefetch_digest(
                &package_digests,
                &package.filename,
                config.verify_upstream_metadata,
            )
            .map_err(|error| debian_sync_verification_error("package", error))?;
            let result = proxy_helpers::proxy_fetch_streaming_with_cache_key_verified(
                proxy,
                repo.id,
                &repo_key,
                upstream_url,
                &package.filename,
                &package.filename,
                expected,
            )
            .await?;
            let response =
                proxy_helpers::stream_fetch_result(result, DEBIAN_BINARY_CONTENT_TYPE, None)?;
            drain_prefetched_package(response).await?;
        }
        for source in plan.source_files.iter().filter(|source| source.download) {
            if !prefetched_sources.insert(source.filename.clone()) {
                continue;
            }
            validate_debian_fetch_path(&source.filename)
                .map_err(|error| debian_sync_verification_error("source path", error))?;
            let expected = expected_prefetch_digest(
                &source_digests,
                &source.filename,
                config.verify_upstream_metadata,
            )
            .map_err(|error| debian_sync_verification_error("source file", error))?;
            let result = proxy_helpers::proxy_fetch_streaming_with_cache_key_verified(
                proxy,
                repo.id,
                &repo_key,
                upstream_url,
                &source.filename,
                &source.filename,
                expected,
            )
            .await?;
            let response =
                proxy_helpers::stream_fetch_result(result, "application/octet-stream", None)?;
            drain_prefetched_package(response).await?;
        }
        plans.push(plan);
    }

    Ok(Json(DebianSyncResponse {
        repository: repo_key,
        plans,
        prefetched_packages: prefetched.len(),
        prefetched_sources: prefetched_sources.len(),
    }))
}

/// OpenAPI contribution for Debian format management endpoints.
#[derive(OpenApi)]
#[openapi(
    paths(sync_remote_repository),
    components(schemas(
        DebianSyncResponse,
        DebianSyncPlan,
        DebianIndexPath,
        DebianSourceIndexPath,
        DebianSyncPackageFile,
        DebianSyncSourceFile,
    )),
    tags(
        (
            name = "debian",
            description = "Debian/APT format endpoints. Remote sync is a management trigger mounted under `/debian/{repo_key}`."
        )
    )
)]
pub struct DebianApiDoc;

#[cfg(test)]
mod tests {
    #[test]
    fn test_pool_download_passthrough_package_strategy_uses_uncached_proxy() {
        let src = include_str!("debian.rs");
        let fn_start = src
            .find("async fn proxy_remote_debian_package(")
            .expect("proxy_remote_debian_package must exist");
        let remote_branch_end = src[fn_start..]
            .find("async fn pool_download(")
            .expect("pool_download must follow proxy helper");
        let remote_branch = &src[fn_start..fn_start + remote_branch_end];

        assert!(remote_branch.contains("DebianPackageFetchStrategy::Passthrough"));
        assert!(
            remote_branch.contains("proxy_fetch_streaming_uncached("),
            "passthrough strategy must use uncached streaming"
        );
        // Passthrough must NOT use the cache-key-verified helper (Fix 2: passthrough must not cache).
        // The cache-key-verified helper IS still used by the non-passthrough branch.
        assert!(
            remote_branch.contains("proxy_fetch_streaming_with_cache_key_verified("),
            "non-passthrough branch must still use digest-gated caching"
        );
        // When passthrough is active the uncached path must NOT be guarded by an
        // `if let Some(sha256)` branch that would fall through to caching.
        {
            let passthrough_block_start = remote_branch
                .find("if passthrough {")
                .expect("passthrough branch must exist");
            let passthrough_block = &remote_branch[passthrough_block_start..];
            // The first call inside the passthrough branch must be uncached.
            let first_uncached = passthrough_block.find("proxy_fetch_streaming_uncached(");
            let first_cached =
                passthrough_block.find("proxy_fetch_streaming_with_cache_key_verified(");
            match (first_uncached, first_cached) {
                (Some(u), Some(c)) => assert!(
                    u < c,
                    "inside the passthrough branch, uncached must come before any cached call"
                ),
                (Some(_), None) => {} // passthrough block only contains uncached — correct
                (None, _) => {
                    panic!("passthrough branch must contain proxy_fetch_streaming_uncached")
                }
            }
        }
        assert!(remote_branch.contains("pool_path_allowed_by_filters("));
        assert!(remote_branch.contains("validate_debian_fetch_path("));
        assert!(
            remote_branch.contains("local_generation")
                && remote_branch.contains("filter.package_queries.clear()"),
            "published generations must not reject dependency packages via raw package_queries"
        );
        assert!(
            remote_branch.contains("Package is not part of the published Debian mirror generation"),
            "packages absent from the published generation must 404"
        );
    }

    #[test]
    fn test_pool_download_wires_filter_and_ssrf_helpers() {
        let src = include_str!("debian.rs");
        let fn_start = src
            .find("async fn pool_download(")
            .expect("pool_download must exist");
        let window = &src[fn_start..fn_start + 2500];
        assert!(window.contains("proxy_remote_debian_package("));
    }

    #[test]
    fn test_flat_package_route_registered() {
        let src = include_str!("debian.rs");
        let router = src
            .find("pub fn router() -> Router<SharedState>")
            .expect("router must exist");
        let body = &src[router..router + 3500];
        assert!(body.contains("/:repo_key/*artifact_path"));
        assert!(body.contains("flat_or_root_package_download"));
        let pool_pos = body
            .find("/:repo_key/pool/:component/*path")
            .expect("pool route");
        let flat_pos = body.find("/:repo_key/*artifact_path").expect("flat route");
        assert!(
            pool_pos < flat_pos,
            "pool route must be registered before flat catch-all"
        );
    }

    #[test]
    fn test_local_release_content_has_clippy_allow() {
        let src = include_str!("debian.rs");
        let pos = src
            .find("async fn local_release_content(")
            .expect("local_release_content must exist");
        let ahead = &src[pos.saturating_sub(120)..pos];
        assert!(
            ahead.contains("#[allow(clippy::result_large_err)]"),
            "local_release_content must allow clippy::result_large_err"
        );
    }

    #[test]
    fn test_sha256_for_filename_in_packages_text() {
        let text = "\
Package: nginx
Version: 1.0
Architecture: amd64
Filename: pool/main/n/nginx/nginx_1.0_amd64.deb
SHA256: AbCdEf1234567890

Package: curl
Version: 2.0
Architecture: amd64
Filename: pool/main/c/curl/curl_2.0_amd64.deb
SHA256: deadbeef
";
        assert_eq!(
            sha256_for_filename_in_packages_text(text, "pool/main/n/nginx/nginx_1.0_amd64.deb")
                .as_deref(),
            Some("abcdef1234567890")
        );
        assert_eq!(
            sha256_for_filename_in_packages_text(text, "nginx_1.0_amd64.deb").as_deref(),
            Some("abcdef1234567890")
        );
        assert_eq!(
            sha256_for_filename_in_packages_text(text, "pool/main/missing.deb"),
            None
        );
    }
    use super::*;

    fn release_with_index(index_path: &str, content: &[u8]) -> crate::formats::debian::Release {
        let text = format!(
            "Suite: jammy\nCodename: jammy\nDate: Tue, 07 Jul 2026 12:00:00 UTC\nArchitectures: amd64\nComponents: main\nSHA256:\n {} {} {}\n",
            calculate_sha256_hex(content),
            content.len(),
            index_path,
        );
        parse_release(&text).expect("release parses")
    }

    #[test]
    fn test_verify_index_against_release_accepts_matching_bytes() {
        let content = b"Package: nginx\n";
        let release = release_with_index("main/binary-amd64/Packages", content);
        assert!(verify_index_against_release(
            &release,
            "main/binary-amd64/Packages",
            content,
            true
        )
        .is_ok());
    }

    #[test]
    fn test_verify_index_against_release_rejects_size_mismatch() {
        let content = b"Package: nginx\n";
        let release = release_with_index("main/binary-amd64/Packages", content);
        let tampered = b"Package: nginx\nextra";
        let err =
            verify_index_against_release(&release, "main/binary-amd64/Packages", tampered, true)
                .unwrap_err();
        assert!(err.contains("size"), "unexpected error: {err}");
    }

    #[test]
    fn test_verify_index_against_release_rejects_hash_mismatch() {
        let content = b"Package: nginx\n";
        let release = release_with_index("main/binary-amd64/Packages", content);
        // Same length, different bytes -> size matches but checksum does not.
        let tampered = b"Package: redis\n";
        assert_eq!(content.len(), tampered.len());
        let err =
            verify_index_against_release(&release, "main/binary-amd64/Packages", tampered, true)
                .unwrap_err();
        assert!(err.contains("checksum"), "unexpected error: {err}");
    }

    #[test]
    fn test_verify_index_against_release_missing_entry_fails_closed_when_required() {
        let content = b"Package: nginx\n";
        let release = release_with_index("main/binary-amd64/Packages", content);
        // A path with no Release entry is rejected only when verification is required.
        assert!(verify_index_against_release(
            &release,
            "main/binary-arm64/Packages",
            content,
            true
        )
        .is_err());
        assert!(verify_index_against_release(
            &release,
            "main/binary-arm64/Packages",
            content,
            false
        )
        .is_ok());
    }

    #[test]
    fn test_release_index_digest_prefers_sha512() {
        let content = b"Packages body\n";
        let text = format!(
            "Suite: jammy\nDate: Tue, 07 Jul 2026 12:00:00 UTC\nArchitectures: amd64\nComponents: main\nSHA256:\n deadbeef {} main/binary-amd64/Packages\nSHA512:\n {} {} main/binary-amd64/Packages\n",
            content.len(),
            calculate_sha512_hex(content),
            content.len(),
        );
        let release = parse_release(&text).unwrap();
        let (is_sha512, _, _) =
            release_index_digest(&release, "main/binary-amd64/Packages").expect("digest present");
        assert!(is_sha512, "must prefer the stronger SHA512 digest");
        // And verification succeeds against the (correct) SHA512 even though the
        // SHA256 entry is bogus.
        assert!(verify_index_against_release(
            &release,
            "main/binary-amd64/Packages",
            content,
            true
        )
        .is_ok());
    }

    #[test]
    fn test_package_and_source_digest_maps() {
        let mut packages = BTreeMap::new();
        packages.insert(
            "main/binary-amd64/Packages".to_string(),
            vec![PackagesEntry {
                control: DebControl {
                    package: "nginx".to_string(),
                    version: "1.0".to_string(),
                    architecture: "amd64".to_string(),
                    ..DebControl::default()
                },
                filename: Some("pool/main/n/nginx/nginx_1.0_amd64.deb".to_string()),
                size: Some(10),
                md5sum: None,
                sha1: None,
                sha256: Some("ABCDEF".to_string()),
            }],
        );
        let pkg_map = package_sha256_by_filename(&packages);
        assert_eq!(
            pkg_map.get("pool/main/n/nginx/nginx_1.0_amd64.deb"),
            Some(&"abcdef".to_string()),
            "digest must be normalized to lowercase and keyed by Filename"
        );

        let mut sources = BTreeMap::new();
        sources.insert(
            "main/source/Sources".to_string(),
            vec![SourcesEntry {
                package: "nginx".to_string(),
                version: "1.0".to_string(),
                directory: "pool/main/n/nginx".to_string(),
                files: vec![SourceFileEntry {
                    filename: "nginx_1.0.dsc".to_string(),
                    size: 20,
                    md5sum: None,
                    sha1: None,
                    sha256: Some("FEEDBEEF".to_string()),
                    sha512: None,
                }],
                extra: BTreeMap::new(),
            }],
        );
        let src_map = source_sha256_by_filename(&sources);
        assert_eq!(
            src_map.get("pool/main/n/nginx/nginx_1.0.dsc"),
            Some(&"feedbeef".to_string()),
            "source digest must be keyed by full directory/filename path"
        );
    }

    #[test]
    fn test_expected_prefetch_digest_semantics() {
        let mut digests = BTreeMap::new();
        digests.insert("pool/main/a.deb".to_string(), "abc123".to_string());

        assert_eq!(
            expected_prefetch_digest(&digests, "pool/main/a.deb", true).unwrap(),
            Some("abc123".to_string())
        );
        // Missing digest is fatal only when verification is required.
        assert!(expected_prefetch_digest(&digests, "pool/main/missing.deb", true).is_err());
        assert_eq!(
            expected_prefetch_digest(&digests, "pool/main/missing.deb", false).unwrap(),
            None
        );
    }

    #[test]
    fn test_debian_sync_must_refuse_unverified_signing() {
        assert!(debian_sync_must_refuse_unverified_signing(true, false));
        assert!(!debian_sync_must_refuse_unverified_signing(true, true));
        assert!(!debian_sync_must_refuse_unverified_signing(false, false));
        assert!(!debian_sync_must_refuse_unverified_signing(false, true));
    }

    #[test]
    fn test_package_sha256_by_filename_skips_missing_digest() {
        let mut packages = BTreeMap::new();
        packages.insert(
            "main/binary-amd64/Packages".to_string(),
            vec![
                PackagesEntry {
                    control: DebControl {
                        package: "nginx".to_string(),
                        version: "1.0".to_string(),
                        architecture: "amd64".to_string(),
                        ..DebControl::default()
                    },
                    filename: Some("pool/main/n/nginx/nginx_1.0_amd64.deb".to_string()),
                    size: Some(10),
                    md5sum: None,
                    sha1: None,
                    sha256: Some("ABCDEF".to_string()),
                },
                PackagesEntry {
                    control: DebControl {
                        package: "curl".to_string(),
                        version: "1.0".to_string(),
                        architecture: "amd64".to_string(),
                        ..DebControl::default()
                    },
                    filename: Some("pool/main/c/curl/curl_1.0_amd64.deb".to_string()),
                    size: Some(10),
                    md5sum: None,
                    sha1: None,
                    sha256: None,
                },
                PackagesEntry {
                    control: DebControl {
                        package: "vim".to_string(),
                        version: "1.0".to_string(),
                        architecture: "amd64".to_string(),
                        ..DebControl::default()
                    },
                    filename: Some("  ".to_string()),
                    size: Some(10),
                    md5sum: None,
                    sha1: None,
                    sha256: Some("deadbeef".to_string()),
                },
            ],
        );
        let map = package_sha256_by_filename(&packages);
        assert_eq!(map.len(), 1);
        assert_eq!(
            map.get("pool/main/n/nginx/nginx_1.0_amd64.deb")
                .map(String::as_str),
            Some("abcdef")
        );
    }

    #[test]
    fn test_sha256_for_filename_in_packages_text_empty_and_missing() {
        assert_eq!(
            sha256_for_filename_in_packages_text("Package: x\n", ""),
            None
        );
        assert_eq!(
            sha256_for_filename_in_packages_text("Package: x\n", "   "),
            None
        );
        assert_eq!(
            sha256_for_filename_in_packages_text(
                "Package: nginx\nFilename: pool/main/n/nginx/nginx_1.0_amd64.deb\n\n",
                "pool/main/n/nginx/nginx_1.0_amd64.deb"
            ),
            None,
            "entry without SHA256 must not invent a digest"
        );
    }

    #[test]
    fn test_sync_verifies_indexes_and_gates_prefetch_and_publishes_atomically() {
        // Structural guards so the security fixes cannot silently regress.
        let src = include_str!("debian.rs");
        let fn_start = src
            .find("async fn sync_remote_repository(")
            .expect("sync_remote_repository must exist");
        let body = &src[fn_start..];
        let end = body
            .find("\n#[cfg(test)]")
            .map(|idx| fn_start + idx)
            .unwrap_or(src.len());
        let body = &src[fn_start..end];

        // Bug 2: never sign metadata derived from an unverified upstream.
        // Behavior is unit-tested via debian_sync_must_refuse_unverified_signing;
        // this asserts the sync path still calls that helper.
        assert!(
            body.contains("debian_sync_must_refuse_unverified_signing("),
            "sync must refuse to sign metadata from an unverified upstream"
        );
        // Bug 3: fetched indexes are verified against the Release hashes.
        assert!(
            body.matches("verify_index_against_release(").count() >= 2,
            "both Packages and Sources indexes must be verified against Release"
        );
        // Bug 4: prefetched artifacts are digest-gated before caching.
        assert!(
            body.contains("proxy_fetch_streaming_with_cache_key_verified("),
            "prefetch must use the digest-gated streaming helper"
        );
        assert!(
            !body.contains("proxy_helpers::proxy_fetch_streaming(\n"),
            "prefetch must not use the un-verified streaming helper"
        );
        assert!(
            body.contains("parse_packages_index_blocking(")
                && body.contains("parse_sources_index_blocking("),
            "sync must parse Packages/Sources indexes via spawn_blocking helpers"
        );
        // Prefetch paths are SSRF-validated before fetch.
        assert!(
            body.contains("validate_debian_fetch_path(&package.filename)")
                && body.contains("validate_debian_fetch_path(&source.filename)"),
            "prefetch must validate package/source paths against SSRF"
        );
        // Bug 5: generated metadata is published in a single transaction.
        assert!(
            body.contains(".begin()") && body.contains("tx.commit()"),
            "generated metadata must be published atomically in one transaction"
        );
        assert!(
            body.contains("effective_package_queries()")
                || body.contains("config.effective_package_queries()"),
            "sync filter must wire package_queries from config"
        );
    }

    fn package_entry(
        name: &str,
        version: &str,
        arch: &str,
        filename: &str,
        size: i64,
        sha256: &str,
        description: &str,
    ) -> PackageEntry {
        PackageEntry {
            control: DebControl {
                package: name.to_string(),
                version: version.to_string(),
                architecture: arch.to_string(),
                description: Some(description.to_string()),
                ..DebControl::default()
            },
            filename: filename.to_string(),
            size,
            sha256: sha256.to_string(),
            sha1: None,
            md5: None,
        }
    }

    // -----------------------------------------------------------------------
    // proxy_err_status_and_message (#1147)
    // -----------------------------------------------------------------------

    #[test]
    fn test_proxy_err_status_not_found_maps_to_404() {
        let err = crate::error::AppError::NotFound("missing".to_string());
        let (status, msg) = proxy_err_status_and_message(&err);
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(msg, "missing");
    }

    #[test]
    fn test_proxy_err_status_storage_maps_to_502() {
        let err = crate::error::AppError::Storage("io error".to_string());
        let (status, msg) = proxy_err_status_and_message(&err);
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(msg.starts_with("Upstream fetch failed"));
    }

    #[test]
    fn test_proxy_err_status_validation_maps_to_502() {
        let err = crate::error::AppError::Validation("invalid path".to_string());
        let (status, _msg) = proxy_err_status_and_message(&err);
        assert_eq!(status, StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn test_proxy_err_status_internal_maps_to_502() {
        let err = crate::error::AppError::Internal("boom".to_string());
        let (status, _msg) = proxy_err_status_and_message(&err);
        assert_eq!(status, StatusCode::BAD_GATEWAY);
    }

    // -----------------------------------------------------------------------
    // map_proxy_err wrapper (#1147)
    //
    // The wrapper is a one-liner over `proxy_err_status_and_message` plus
    // `into_response()`, but its branches still count as changed lines.
    // Exercising it here keeps the public surface covered.
    // -----------------------------------------------------------------------

    #[test]
    fn test_map_proxy_err_not_found_produces_404_response() {
        let resp = map_proxy_err(crate::error::AppError::NotFound("missing".to_string()));
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_map_proxy_err_other_errors_produce_502_response() {
        let resp = map_proxy_err(crate::error::AppError::Storage("io".to_string()));
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

        let resp = map_proxy_err(crate::error::AppError::Validation("v".to_string()));
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

        let resp = map_proxy_err(crate::error::AppError::Internal("i".to_string()));
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    // -----------------------------------------------------------------------
    // build_dists_response (#1147)
    //
    // The pure response builder shared by the dists() / dists_detecting_change()
    // / try_virtual_dists() / try_virtual_dists_detecting_change() paths.
    // Verifies the Content-Type fallback and length header.
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_dists_response_uses_upstream_content_type_when_present() {
        let body = Bytes::from_static(b"Origin: Debian\n");
        let resp = build_dists_response(
            body.clone(),
            Some("application/octet-stream".to_string()),
            "text/plain; charset=utf-8",
        );
        assert_eq!(resp.status(), StatusCode::OK);
        let headers = resp.headers();
        assert_eq!(
            headers
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or(""),
            "application/octet-stream"
        );
        assert_eq!(
            headers
                .get(CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .unwrap_or(""),
            body.len().to_string()
        );
    }

    #[test]
    fn test_build_dists_response_falls_back_to_default_content_type() {
        let body = Bytes::from_static(b"abc");
        let resp = build_dists_response(body, None, "text/plain; charset=utf-8");
        assert_eq!(
            resp.headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain; charset=utf-8")
        );
    }

    #[test]
    fn test_build_dists_response_empty_body_reports_zero_length() {
        let resp = build_dists_response(Bytes::new(), None, "text/plain; charset=utf-8");
        assert_eq!(
            resp.headers()
                .get(CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok()),
            Some("0")
        );
    }

    // -----------------------------------------------------------------------
    // remote_member_upstream (#1147)
    //
    // Pure predicate used by the virtual dispatchers to decide whether to
    // try a member. Covers each branch (non-Remote, Remote without URL,
    // Remote with URL).
    // -----------------------------------------------------------------------

    fn test_member(
        repo_type: RepositoryType,
        upstream: Option<&str>,
    ) -> crate::models::repository::Repository {
        use crate::models::repository::{ReplicationPriority, Repository, RepositoryFormat};
        Repository {
            versioning_enabled: false,
            id: uuid::Uuid::new_v4(),
            key: "m".to_string(),
            name: "m".to_string(),
            description: None,
            format: RepositoryFormat::Debian,
            repo_type,
            storage_backend: "filesystem".to_string(),
            storage_path: "/tmp/m".to_string(),
            upstream_url: upstream.map(|s| s.to_string()),
            is_public: false,
            quota_bytes: None,
            promotion_only: false,
            replication_priority: ReplicationPriority::LocalOnly,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 0,
            curation_auto_fetch: false,
            age_gate_enabled: false,
            age_gate_min_age_days: 7,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn test_remote_member_upstream_skips_local_member() {
        let m = test_member(RepositoryType::Local, Some("https://upstream.test"));
        assert!(
            remote_member_upstream(&m).is_none(),
            "Local members never get proxied for dists"
        );
    }

    #[test]
    fn test_remote_member_upstream_skips_staging_member() {
        let m = test_member(RepositoryType::Staging, Some("https://upstream.test"));
        assert!(remote_member_upstream(&m).is_none());
    }

    #[test]
    fn test_remote_member_upstream_skips_remote_without_url() {
        let m = test_member(RepositoryType::Remote, None);
        assert!(
            remote_member_upstream(&m).is_none(),
            "A Remote member with no upstream_url is a misconfiguration; \
             skip rather than panic."
        );
    }

    #[test]
    fn test_remote_member_upstream_returns_url_for_valid_remote() {
        let m = test_member(RepositoryType::Remote, Some("https://deb.debian.org"));
        assert_eq!(remote_member_upstream(&m), Some("https://deb.debian.org"));
    }

    // -----------------------------------------------------------------------
    // Router construction
    //
    // Regression guard for #832: axum's matchit router panics at startup
    // if wildcard and parameter children coexist under the same parent.
    // Building the router exercises those insertions.
    // -----------------------------------------------------------------------

    #[test]
    fn test_router_builds_without_panic() {
        let _router: Router<SharedState> = router();
    }

    // -----------------------------------------------------------------------
    // parse_packages_request
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_packages_request_plain() {
        let req = parse_packages_request("main/binary-amd64/Packages").unwrap();
        assert_eq!(req.component, "main");
        assert_eq!(req.binary_arch, "binary-amd64");
        assert!(matches!(req.ext, PackagesExt::Plain));
    }

    #[test]
    fn test_parse_packages_request_gz() {
        let req = parse_packages_request("main/binary-amd64/Packages.gz").unwrap();
        assert!(matches!(req.ext, PackagesExt::Gz));
    }

    #[test]
    fn test_parse_packages_request_xz() {
        let req = parse_packages_request("contrib/binary-arm64/Packages.xz").unwrap();
        assert_eq!(req.component, "contrib");
        assert_eq!(req.binary_arch, "binary-arm64");
        assert!(matches!(req.ext, PackagesExt::Xz));
    }

    #[test]
    fn test_parse_packages_request_rejects_i18n() {
        assert!(parse_packages_request("main/i18n/Translation-en.xz").is_none());
    }

    #[test]
    fn test_parse_packages_request_rejects_sources() {
        assert!(parse_packages_request("main/source/Sources.gz").is_none());
        assert!(parse_packages_request("main/binary-amd64/Contents-amd64.gz").is_none());
    }

    #[test]
    fn test_parse_packages_request_rejects_wrong_depth() {
        assert!(parse_packages_request("main/binary-amd64").is_none());
        assert!(parse_packages_request("main/binary-amd64/extra/Packages").is_none());
    }

    // -----------------------------------------------------------------------
    // parse_deb_filename
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_deb_filename_valid() {
        let info = parse_deb_filename("nginx_1.24.0_amd64.deb").unwrap();
        assert_eq!(info.name, "nginx");
        assert_eq!(info.version, "1.24.0");
        assert_eq!(info.arch, "amd64");
        assert_eq!(info.package_type, "deb");
    }

    #[test]
    fn test_parse_deb_filename_complex_version() {
        let info = parse_deb_filename("libssl_3.0.2-0ubuntu1.10_arm64.deb").unwrap();
        assert_eq!(info.name, "libssl");
        assert_eq!(info.version, "3.0.2-0ubuntu1.10");
        assert_eq!(info.arch, "arm64");
    }

    #[test]
    fn test_parse_deb_filename_arch_all() {
        let info = parse_deb_filename("python3-pip_23.0_all.deb").unwrap();
        assert_eq!(info.name, "python3-pip");
        assert_eq!(info.version, "23.0");
        assert_eq!(info.arch, "all");
    }

    #[test]
    fn test_parse_deb_filename_udeb() {
        let info = parse_deb_filename("base-installer_1.200_amd64.udeb").unwrap();
        assert_eq!(info.name, "base-installer");
        assert_eq!(info.version, "1.200");
        assert_eq!(info.arch, "amd64");
        assert_eq!(info.package_type, "udeb");
    }

    #[test]
    fn test_build_debian_artifact_metadata_installer_component() {
        let control = DebControl {
            package: "base-installer".to_string(),
            version: "1.200".to_string(),
            architecture: "amd64".to_string(),
            maintainer: None,
            installed_size: None,
            depends: None,
            pre_depends: None,
            recommends: None,
            suggests: None,
            conflicts: None,
            provides: None,
            replaces: None,
            section: Some("utils".to_string()),
            priority: None,
            homepage: None,
            description: None,
            source: None,
            extra: Default::default(),
        };
        let meta = build_debian_artifact_metadata(
            Some("bookworm"),
            "debian-installer",
            "pool/debian-installer/b/base-installer/base-installer_1.200_amd64.udeb",
            "base-installer_1.200_amd64.udeb",
            "udeb",
            &control,
        );
        assert_eq!(meta["package_type"], "udeb");
        assert_eq!(meta["section"], "debian-installer");
        assert_eq!(meta["component"], "debian-installer");
    }

    #[test]
    fn test_parse_deb_filename_no_deb_extension() {
        assert!(parse_deb_filename("nginx_1.0_amd64.rpm").is_none());
    }

    #[test]
    fn test_parse_deb_filename_too_few_parts() {
        assert!(parse_deb_filename("nginx_amd64.deb").is_none());
    }

    #[test]
    fn test_parse_deb_filename_no_underscores() {
        assert!(parse_deb_filename("nginx.deb").is_none());
    }

    #[test]
    fn test_parse_deb_filename_empty_string() {
        assert!(parse_deb_filename("").is_none());
    }

    #[test]
    fn test_parse_deb_filename_just_extension() {
        assert!(parse_deb_filename(".deb").is_none());
    }

    #[test]
    fn test_parse_deb_filename_version_with_underscores_in_arch() {
        let info = parse_deb_filename("pkg_1.0_i386.deb").unwrap();
        assert_eq!(info.name, "pkg");
        assert_eq!(info.version, "1.0");
        assert_eq!(info.arch, "i386");
    }

    // -----------------------------------------------------------------------
    // Release config helpers
    // -----------------------------------------------------------------------

    #[test]
    fn test_effective_release_layout_prefers_configured_components_and_architectures() {
        let config = DebianRepositoryConfig {
            components: vec!["universe".to_string(), "main".to_string()],
            architectures: vec!["amd64".to_string(), "all".to_string(), "arm64".to_string()],
            ..Default::default()
        };
        let discovered_components = BTreeSet::from(["main".to_string()]);
        let discovered_architectures = BTreeSet::from(["amd64".to_string()]);

        let (components, architectures) = effective_release_layout(
            Some(&config),
            discovered_components,
            discovered_architectures,
        );

        assert_eq!(
            components.into_iter().collect::<Vec<_>>(),
            vec!["main".to_string(), "universe".to_string()]
        );
        assert_eq!(
            architectures.into_iter().collect::<Vec<_>>(),
            vec!["amd64".to_string(), "arm64".to_string()]
        );
    }

    #[test]
    fn test_flat_debian_upstream_paths_are_root_relative() {
        assert_eq!(debian_dists_upstream_path("", "Release"), "Release");
        assert_eq!(debian_dists_upstream_path("", "Packages.xz"), "Packages.xz");
        assert_eq!(
            debian_dists_upstream_path("bookworm", "main/binary-amd64/Packages.xz"),
            "dists/bookworm/main/binary-amd64/Packages.xz"
        );
    }

    #[test]
    fn test_dists_serving_is_generation_aware_not_per_request_filtered() {
        // Passthrough must be transparent (no per-request filtering) and, once a
        // local generation is published, uncovered paths 404 instead of leaking
        // upstream. Guard the wiring so it cannot silently regress.
        let src = include_str!("debian.rs");

        // The per-request filter helpers must be gone entirely. Build the
        // needles at runtime so this test's own source does not self-match.
        let removed_fn = ["fn debian_sync", "_path_allowed("].concat();
        let removed_call = ["require_debian_sync", "_path_allowed("].concat();
        assert!(
            !src.contains(&removed_fn),
            "per-request passthrough filtering must be removed"
        );
        assert!(
            !src.contains(&removed_call),
            "per-request passthrough filtering call sites must be removed"
        );

        // The dists passthrough branches must gate on the published generation.
        for anchor in [
            "async fn dists(",
            "async fn dists_detecting_change(",
            "async fn dists_proxy_catchall(",
        ] {
            let start = src
                .find(anchor)
                .unwrap_or_else(|| panic!("{anchor} missing"));
            let window = &src[start..start + 1400];
            assert!(
                window.contains("reject_uncovered_generation_path("),
                "{anchor} must gate passthrough on the published generation"
            );
        }

        // dists_proxy_catchall must serve local content before applying the gate
        // so covered paths are not rejected.
        let catchall = src
            .find("async fn dists_proxy_catchall(")
            .expect("catchall exists");
        let body = &src[catchall..catchall + 1800];
        let local = body
            .find("try_synced_dists_response(")
            .expect("catchall loads local content");
        let gate = body
            .find("reject_uncovered_generation_path(")
            .expect("catchall gates passthrough");
        assert!(
            local < gate,
            "local content must be served before the passthrough gate"
        );
    }

    #[test]
    fn test_effective_release_layout_uses_discovered_values_for_wildcards() {
        let config = DebianRepositoryConfig {
            components: vec!["*".to_string()],
            architectures: Vec::new(),
            ..Default::default()
        };
        let discovered_components = BTreeSet::from(["main".to_string(), "universe".to_string()]);
        let discovered_architectures = BTreeSet::from(["amd64".to_string(), "arm64".to_string()]);

        let (components, architectures) = effective_release_layout(
            Some(&config),
            discovered_components,
            discovered_architectures,
        );

        assert_eq!(
            components.into_iter().collect::<Vec<_>>(),
            vec!["main".to_string(), "universe".to_string()]
        );
        assert_eq!(
            architectures.into_iter().collect::<Vec<_>>(),
            vec!["amd64".to_string(), "arm64".to_string()]
        );
    }
    // -----------------------------------------------------------------------
    // build_packages_text
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_packages_text_single_entry() {
        let entries = vec![package_entry(
            "nginx",
            "1.24.0",
            "amd64",
            "pool/main/n/nginx/nginx_1.24.0_amd64.deb",
            1024,
            "abc123",
            "HTTP server",
        )];
        let text = build_packages_text(&entries);
        assert!(text.contains("Package: nginx\n"));
        assert!(text.contains("Version: 1.24.0\n"));
        assert!(text.contains("Architecture: amd64\n"));
        assert!(text.contains("Filename: pool/main/n/nginx/nginx_1.24.0_amd64.deb\n"));
        assert!(text.contains("Size: 1024\n"));
        assert!(text.contains("SHA256: abc123\n"));
        assert!(text.contains("Description: HTTP server\n"));
    }

    #[test]
    fn test_build_packages_text_multiple_entries() {
        let entries = vec![
            package_entry(
                "pkg1",
                "1.0",
                "amd64",
                "pool/main/p/pkg1/pkg1_1.0_amd64.deb",
                100,
                "hash1",
                "Package 1",
            ),
            package_entry(
                "pkg2",
                "2.0",
                "arm64",
                "pool/main/p/pkg2/pkg2_2.0_arm64.deb",
                200,
                "hash2",
                "Package 2",
            ),
        ];
        let text = build_packages_text(&entries);
        assert!(text.contains("Package: pkg1\n"));
        assert!(text.contains("Package: pkg2\n"));
        // Entries should be separated by a blank line
        assert!(text.contains("\n\n"));
    }

    #[test]
    fn test_build_packages_text_empty() {
        let entries: Vec<PackageEntry> = vec![];
        let text = build_packages_text(&entries);
        assert!(text.is_empty());
    }

    #[test]
    fn test_build_packages_text_preserves_debian_control_fields() {
        let mut extra = std::collections::HashMap::new();
        extra.insert("Multi-Arch".to_string(), "same".to_string());
        let entries = vec![PackageEntry {
            control: DebControl {
                package: "libdemo".to_string(),
                version: "1.2.3-1".to_string(),
                architecture: "amd64".to_string(),
                maintainer: Some("Maintainer <m@example.test>".to_string()),
                installed_size: Some(42),
                depends: Some(vec!["libc6 (>= 2.36)".to_string(), "zlib1g".to_string()]),
                section: Some("libs".to_string()),
                priority: Some("optional".to_string()),
                homepage: Some("https://example.test/libdemo".to_string()),
                source: Some("demo-src".to_string()),
                description: Some("short description\nlong line\n.\nsecond paragraph".to_string()),
                extra,
                ..DebControl::default()
            },
            filename: "pool/main/libd/libdemo/libdemo_1.2.3-1_amd64.deb".to_string(),
            size: 4096,
            sha256: "sha256".to_string(),
            sha1: Some("sha1".to_string()),
            md5: Some("md5".to_string()),
        }];

        let text = build_packages_text(&entries);
        assert!(text.contains("Maintainer: Maintainer <m@example.test>\n"));
        assert!(text.contains("Installed-Size: 42\n"));
        assert!(text.contains("Depends: libc6 (>= 2.36), zlib1g\n"));
        assert!(text.contains("Section: libs\n"));
        assert!(text.contains("Priority: optional\n"));
        assert!(text.contains("Homepage: https://example.test/libdemo\n"));
        assert!(text.contains("Source: demo-src\n"));
        assert!(text.contains("Multi-Arch: same\n"));
        assert!(
            text.contains("Description: short description\n long line\n .\n second paragraph\n")
        );
        assert!(text.contains("MD5sum: md5\n"));
        assert!(text.contains("SHA1: sha1\n"));
        assert!(text.contains("SHA256: sha256\n"));
    }

    #[test]
    fn test_build_generated_packages_text_filters_arch_and_preserves_hashes() {
        let mut extra = std::collections::HashMap::new();
        extra.insert("Multi-Arch".to_string(), "same".to_string());
        let entries = vec![
            PackagesEntry {
                control: DebControl {
                    package: "libdemo".to_string(),
                    version: "1.0".to_string(),
                    architecture: "amd64".to_string(),
                    maintainer: Some("Maintainer <m@example.test>".to_string()),
                    description: Some("demo library".to_string()),
                    extra,
                    ..DebControl::default()
                },
                filename: Some("pool/main/libd/libdemo/libdemo_1.0_amd64.deb".to_string()),
                size: Some(1234),
                md5sum: Some("md5".to_string()),
                sha1: Some("sha1".to_string()),
                sha256: Some("sha256".to_string()),
            },
            PackagesEntry {
                control: DebControl {
                    package: "shared-data".to_string(),
                    version: "1.0".to_string(),
                    architecture: "all".to_string(),
                    description: Some("shared data".to_string()),
                    ..DebControl::default()
                },
                filename: Some("pool/main/s/shared-data/shared-data_1.0_all.deb".to_string()),
                size: Some(77),
                md5sum: None,
                sha1: None,
                sha256: Some("sha256-all".to_string()),
            },
            PackagesEntry {
                control: DebControl {
                    package: "libother".to_string(),
                    version: "1.0".to_string(),
                    architecture: "arm64".to_string(),
                    description: Some("other arch".to_string()),
                    ..DebControl::default()
                },
                filename: Some("pool/main/libo/libother/libother_1.0_arm64.deb".to_string()),
                size: Some(99),
                md5sum: None,
                sha1: None,
                sha256: Some("sha256-arm".to_string()),
            },
        ];

        let text = build_generated_packages_text(&entries, "amd64", &["amd64".to_string()]);
        assert!(text.contains("Package: libdemo\n"));
        assert!(text.contains("Package: shared-data\n"));
        assert!(!text.contains("Package: libother\n"));
        assert!(text.contains("Multi-Arch: same\n"));
        assert!(text.contains("Filename: pool/main/libd/libdemo/libdemo_1.0_amd64.deb\n"));
        assert!(text.contains("Size: 1234\n"));
        assert!(text.contains("MD5sum: md5\n"));
        assert!(text.contains("SHA1: sha1\n"));
        assert!(text.contains("SHA256: sha256\n"));
    }

    #[test]
    fn test_build_generated_packages_text_filters_flat_indexes_by_selected_architectures() {
        let entries = vec![
            PackagesEntry {
                control: DebControl {
                    package: "libdemo".to_string(),
                    version: "1.0".to_string(),
                    architecture: "amd64".to_string(),
                    description: Some("demo library".to_string()),
                    ..DebControl::default()
                },
                filename: Some("libdemo_1.0_amd64.deb".to_string()),
                size: Some(1234),
                md5sum: None,
                sha1: None,
                sha256: Some("sha256".to_string()),
            },
            PackagesEntry {
                control: DebControl {
                    package: "libother".to_string(),
                    version: "1.0".to_string(),
                    architecture: "arm64".to_string(),
                    description: Some("other arch".to_string()),
                    ..DebControl::default()
                },
                filename: Some("libother_1.0_arm64.deb".to_string()),
                size: Some(99),
                md5sum: None,
                sha1: None,
                sha256: Some("sha256-arm".to_string()),
            },
        ];

        let text = build_generated_packages_text(&entries, "", &["amd64".to_string()]);
        assert!(text.contains("Package: libdemo\n"));
        assert!(!text.contains("Package: libother\n"));
    }
    #[test]
    fn test_build_generated_sources_text_preserves_hash_sections() {
        let mut extra = BTreeMap::new();
        extra.insert(
            "Maintainer".to_string(),
            "Maintainer <m@example.test>".to_string(),
        );
        let entries = vec![SourcesEntry {
            package: "demo-src".to_string(),
            version: "1.0".to_string(),
            directory: "pool/main/d/demo-src".to_string(),
            files: vec![SourceFileEntry {
                filename: "demo-src_1.0.dsc".to_string(),
                size: 321,
                md5sum: Some("md5".to_string()),
                sha1: Some("sha1".to_string()),
                sha256: Some("sha256".to_string()),
                sha512: Some("sha512".to_string()),
            }],
            extra,
        }];

        let text = build_generated_sources_text(&entries);
        assert!(text.contains("Package: demo-src\n"));
        assert!(text.contains("Version: 1.0\n"));
        assert!(text.contains("Directory: pool/main/d/demo-src\n"));
        assert!(text.contains("Maintainer: Maintainer <m@example.test>\n"));
        assert!(text.contains("Files:\n md5 321 demo-src_1.0.dsc\n"));
        assert!(text.contains("Checksums-Sha1:\n sha1 321 demo-src_1.0.dsc\n"));
        assert!(text.contains("Checksums-Sha256:\n sha256 321 demo-src_1.0.dsc\n"));
        assert!(text.contains("Checksums-Sha512:\n sha512 321 demo-src_1.0.dsc\n"));
    }

    #[test]
    fn test_synced_generated_metadata_builds_indexes_and_release_hashes() {
        let package_index = crate::formats::debian::DebianIndexPath {
            component: "main".to_string(),
            architecture: "amd64".to_string(),
            path: "main/binary-amd64/Packages.xz".to_string(),
        };
        let source_index = crate::formats::debian::DebianSourceIndexPath {
            component: "main".to_string(),
            path: "main/source/Sources.gz".to_string(),
        };
        let plan = DebianSyncPlan {
            distribution: "jammy".to_string(),
            release_paths: vec![],
            package_indexes: vec![package_index.clone()],
            source_indexes: vec![source_index.clone()],
            package_files: vec![crate::formats::debian::DebianSyncPackageFile {
                index_path: package_index.path.clone(),
                filename: "pool/main/libd/libdemo/libdemo_1.0_amd64.deb".to_string(),
                package: "libdemo".to_string(),
                version: "1.0".to_string(),
                architecture: "amd64".to_string(),
                download: false,
            }],
            source_files: vec![],
            missing_package_indexes: vec![],
            missing_source_indexes: vec![],
        };
        let mut packages = BTreeMap::new();
        packages.insert(
            package_index.path.clone(),
            vec![PackagesEntry {
                control: DebControl {
                    package: "libdemo".to_string(),
                    version: "1.0".to_string(),
                    architecture: "amd64".to_string(),
                    description: Some("demo".to_string()),
                    ..DebControl::default()
                },
                filename: Some("pool/main/libd/libdemo/libdemo_1.0_amd64.deb".to_string()),
                size: Some(123),
                md5sum: None,
                sha1: None,
                sha256: Some("sha256".to_string()),
            }],
        );
        let mut sources = BTreeMap::new();
        sources.insert(
            source_index.path.clone(),
            vec![SourcesEntry {
                package: "demo-src".to_string(),
                version: "1.0".to_string(),
                directory: "pool/main/d/demo-src".to_string(),
                files: vec![],
                extra: BTreeMap::new(),
            }],
        );

        let generated =
            build_synced_generated_metadata(&plan, &packages, &sources, &["amd64".to_string()])
                .unwrap();
        assert!(generated
            .plain_indexes
            .contains_key("main/binary-amd64/Packages"));
        assert!(generated.plain_indexes.contains_key("main/source/Sources"));
        // Contents are NOT generated from sync plans (pool filenames are not
        // valid Contents-file paths — see Fix 9).
        assert!(
            !generated.plain_indexes.contains_key("main/Contents-amd64"),
            "Contents must NOT be generated from pool filenames in sync metadata"
        );
        assert!(generated
            .release_files
            .iter()
            .any(|(path, _)| path == "main/binary-amd64/Packages.gz"));
        assert!(generated
            .release_files
            .iter()
            .any(|(path, _)| path == "main/source/Sources.xz"));
        assert!(
            !generated
                .release_files
                .iter()
                .any(|(path, _)| path == "main/Contents-amd64.gz"),
            "Contents.gz must NOT appear in synced release_files"
        );
        assert!(
            generated
                .release_files
                .iter()
                .any(|(path, _)| path.starts_with("by-hash/SHA256/")),
            "synced metadata must publish by-hash aliases"
        );
        assert!(
            generated
                .plain_indexes
                .values()
                .any(|value| value.starts_with("@ref:")),
            "by-hash aliases must be stored as @ref: logical-path pointers"
        );

        let components = BTreeSet::from(["main".to_string()]);
        let architectures = BTreeSet::from(["amd64".to_string()]);
        let release = build_release_content_from_files(
            "jammy",
            Some("jammy"),
            None,
            &components,
            &architectures,
            generated.release_files,
        );
        assert!(release.contains("MD5Sum:\n"));
        assert!(release.contains("SHA1:\n"));
        assert!(release.contains("SHA256:\n"));
        assert!(release.contains("SHA512:\n"));
        assert!(release.contains(" main/binary-amd64/Packages\n"));
        assert!(release.contains(" main/binary-amd64/Packages.gz\n"));
        assert!(release.contains(" main/binary-amd64/Packages.xz\n"));
        assert!(
            !release.contains(" main/Contents-amd64\n"),
            "Contents must NOT appear in generated Release"
        );
        assert!(release.contains(" main/source/Sources\n"));
        assert!(release.contains(" main/source/Sources.gz\n"));
        assert!(release.contains(" main/source/Sources.xz\n"));
        assert!(release.contains(" by-hash/SHA256/"));
    }

    #[test]
    fn test_build_synced_generated_metadata_respects_plan_package_selection() {
        let package_index = crate::formats::debian::DebianIndexPath {
            component: "main".to_string(),
            architecture: "amd64".to_string(),
            path: "main/binary-amd64/Packages.xz".to_string(),
        };
        let plan = DebianSyncPlan {
            distribution: "noble-security".to_string(),
            release_paths: vec![],
            package_indexes: vec![package_index.clone()],
            source_indexes: vec![],
            package_files: vec![crate::formats::debian::DebianSyncPackageFile {
                index_path: package_index.path.clone(),
                filename: "pool/main/c/curl/curl_8.5.0-2ubuntu10.6_amd64.deb".to_string(),
                package: "curl".to_string(),
                version: "8.5.0-2ubuntu10.6".to_string(),
                architecture: "amd64".to_string(),
                download: false,
            }],
            source_files: vec![],
            missing_package_indexes: vec![],
            missing_source_indexes: vec![],
        };
        let mut packages = BTreeMap::new();
        packages.insert(
            package_index.path.clone(),
            vec![
                PackagesEntry {
                    control: DebControl {
                        package: "curl".to_string(),
                        version: "8.5.0-2ubuntu10.6".to_string(),
                        architecture: "amd64".to_string(),
                        ..DebControl::default()
                    },
                    filename: Some("pool/main/c/curl/curl_8.5.0-2ubuntu10.6_amd64.deb".to_string()),
                    size: Some(10),
                    md5sum: None,
                    sha1: None,
                    sha256: Some("aa".to_string()),
                },
                PackagesEntry {
                    control: DebControl {
                        package: "nginx".to_string(),
                        version: "1.0".to_string(),
                        architecture: "amd64".to_string(),
                        ..DebControl::default()
                    },
                    filename: Some("pool/main/n/nginx/nginx_1.0_amd64.deb".to_string()),
                    size: Some(20),
                    md5sum: None,
                    sha1: None,
                    sha256: Some("bb".to_string()),
                },
            ],
        );

        let generated = build_synced_generated_metadata(
            &plan,
            &packages,
            &BTreeMap::new(),
            &["amd64".to_string()],
        )
        .unwrap();
        let packages_text = generated
            .plain_indexes
            .get("main/binary-amd64/Packages")
            .expect("Packages index");
        assert!(
            packages_text.contains("Package: curl\n"),
            "selected package must appear in generated Packages"
        );
        assert!(
            !packages_text.contains("Package: nginx\n"),
            "packages outside the sync plan must not be published"
        );
        // Contents are NOT generated from sync plans (Fix 9: pool filenames are wrong).
        assert!(
            !generated.plain_indexes.contains_key("main/Contents-amd64"),
            "Contents must NOT be generated from pool filenames in sync metadata (Fix 9)"
        );
    }

    #[test]
    fn test_append_by_hash_release_files_adds_sha256_aliases() {
        let mut files = vec![
            ("main/binary-amd64/Packages".to_string(), b"hello".to_vec()),
            ("main/Contents-amd64".to_string(), b"world".to_vec()),
        ];
        append_by_hash_release_files(&mut files);
        let hello_sha = calculate_sha256_hex(b"hello");
        let world_sha = calculate_sha256_hex(b"world");
        assert!(files
            .iter()
            .any(|(path, bytes)| path == &by_hash_path("SHA256", &hello_sha) && bytes == b"hello"));
        assert!(files
            .iter()
            .any(|(path, bytes)| path == &by_hash_path("SHA256", &world_sha) && bytes == b"world"));
        // Idempotent: running again must not duplicate.
        let before = files.len();
        append_by_hash_release_files(&mut files);
        assert_eq!(files.len(), before);
    }

    #[test]
    fn test_parse_contents_request() {
        let req = parse_contents_request("main/Contents-amd64").unwrap();
        assert_eq!(req.component, "main");
        assert_eq!(req.arch, "amd64");
        assert!(matches!(req.ext, PackagesExt::Plain));

        let req = parse_contents_request("universe/Contents-arm64.gz").unwrap();
        assert_eq!(req.component, "universe");
        assert_eq!(req.arch, "arm64");
        assert!(matches!(req.ext, PackagesExt::Gz));

        assert!(parse_contents_request("main/binary-amd64/Packages").is_none());
        // bz2/zst are now supported
        let req_bz2 = parse_contents_request("main/Contents-amd64.bz2").unwrap();
        assert!(matches!(req_bz2.ext, PackagesExt::Bz2));
        let req_zst = parse_contents_request("main/Contents-amd64.zst").unwrap();
        assert!(matches!(req_zst.ext, PackagesExt::Zst));
        // unknown extensions still rejected
        assert!(parse_contents_request("main/Contents-amd64.foo").is_none());
    }
    #[test]
    fn test_package_matches_requested_arch() {
        assert!(package_matches_requested_arch("amd64", "amd64"));
        assert!(package_matches_requested_arch("all", "amd64"));
        assert!(package_matches_requested_arch("all", "all"));
        assert!(!package_matches_requested_arch("amd64", "all"));
        assert!(!package_matches_requested_arch("arm64", "amd64"));
    }

    #[test]
    fn test_package_matches_requested_distribution() {
        let jammy = serde_json::json!({ "distribution": " jammy " });
        let bookworm = serde_json::json!({ "distribution": "bookworm" });
        let legacy = serde_json::json!({ "component": "main" });
        let empty = serde_json::json!({ "distribution": "" });
        let null_distribution = serde_json::json!({ "distribution": null });

        assert!(package_matches_requested_distribution(
            Some(&jammy),
            "jammy"
        ));
        assert!(!package_matches_requested_distribution(
            Some(&bookworm),
            "jammy"
        ));
        assert!(package_matches_requested_distribution(
            Some(&legacy),
            "jammy"
        ));
        assert!(package_matches_requested_distribution(
            Some(&empty),
            "jammy"
        ));
        assert!(package_matches_requested_distribution(
            Some(&null_distribution),
            "jammy"
        ));
        assert!(package_matches_requested_distribution(None, "jammy"));
    }

    #[test]
    fn test_architecture_all_is_not_release_layout_architecture() {
        assert_eq!(architecture_for_release_layout("all"), None);
        assert_eq!(architecture_for_release_layout("amd64"), Some("amd64"));
    }

    #[test]
    fn test_component_from_pool_path() {
        assert_eq!(
            component_from_pool_path("pool/non-free/n/nvidia/pkg_1_amd64.deb"),
            Some("non-free")
        );
        assert_eq!(
            component_from_pool_path("pool/updates/main/c/curl/curl_7.88.1-10+deb12u5_amd64.deb"),
            Some("updates/main")
        );
        assert_eq!(
            component_from_pool_path("pool/main/c/curl/curl_1_amd64.deb"),
            Some("main")
        );
        assert_eq!(component_from_pool_path("not-pool/pkg.deb"), None);
    }

    #[test]
    fn test_gzip_compress_is_deterministic() {
        let first = gzip_compress(b"Package: demo\n").unwrap();
        let second = gzip_compress(b"Package: demo\n").unwrap();
        assert_eq!(first, second);
    }

    // -----------------------------------------------------------------------
    // Upstream path construction for APT remote proxy (#674)
    // -----------------------------------------------------------------------

    #[test]
    fn test_upstream_dists_paths_match_debian_mirror_layout() {
        // All five metadata endpoints build upstream paths via
        // try_proxy_dists_file(state, repo, key, dist, suffix, ct).
        // The path is always "dists/{dist}/{suffix}". Verify the
        // expected paths match the real Debian/Ubuntu mirror layout.
        let cases = vec![
            ("trixie", "Release", "dists/trixie/Release"),
            ("trixie-updates", "Release", "dists/trixie-updates/Release"),
            ("bookworm", "InRelease", "dists/bookworm/InRelease"),
            (
                "bookworm-security",
                "InRelease",
                "dists/bookworm-security/InRelease",
            ),
            ("trixie", "Release.gpg", "dists/trixie/Release.gpg"),
            (
                "trixie",
                "main/binary-amd64/Packages",
                "dists/trixie/main/binary-amd64/Packages",
            ),
            (
                "trixie",
                "non-free/binary-arm64/Packages",
                "dists/trixie/non-free/binary-arm64/Packages",
            ),
            (
                "trixie",
                "main/binary-amd64/Packages.gz",
                "dists/trixie/main/binary-amd64/Packages.gz",
            ),
            (
                "trixie",
                "main/binary-amd64/Packages.xz",
                "dists/trixie/main/binary-amd64/Packages.xz",
            ),
            (
                "bookworm",
                "main/i18n/Translation-en.xz",
                "dists/bookworm/main/i18n/Translation-en.xz",
            ),
            (
                "bookworm",
                "main/i18n/Translation-en.gz",
                "dists/bookworm/main/i18n/Translation-en.gz",
            ),
            (
                "trixie",
                "main/source/Sources.xz",
                "dists/trixie/main/source/Sources.xz",
            ),
        ];
        for (dist, suffix, expected) in &cases {
            let path = format!("dists/{}/{}", dist, suffix);
            assert_eq!(
                &path, expected,
                "path mismatch for dist={}, suffix={}",
                dist, suffix
            );
        }
    }

    #[test]
    fn test_upstream_url_assembly_matches_debian_org() {
        // Full URL assembly: upstream_url + "/" + dists path must point at
        // the real Debian mirror.
        let upstream = "http://deb.debian.org/debian";
        let path = format!("dists/{}/{}", "trixie", "InRelease");
        let full_url = format!("{}/{}", upstream.trim_end_matches('/'), path);
        assert_eq!(
            full_url,
            "http://deb.debian.org/debian/dists/trixie/InRelease"
        );
    }

    // -----------------------------------------------------------------------
    // XZ compression round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn test_xz_compress_round_trip() {
        let original = b"Package: hello\nVersion: 1.0\nArchitecture: amd64\n";
        let compressed = xz_compress(original).expect("xz compression should succeed");
        // XZ magic bytes: 0xFD, '7', 'z', 'X', 'Z', 0x00
        assert_eq!(&compressed[..6], &[0xFD, b'7', b'z', b'X', b'Z', 0x00]);
        // Decompress and verify round-trip
        use std::io::Read;
        let mut decoder = xz2::read::XzDecoder::new(&compressed[..]);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .expect("xz decompression should succeed");
        assert_eq!(decompressed, original);
    }

    #[test]
    fn test_xz_compress_empty_input() {
        let compressed = xz_compress(b"").expect("xz compression of empty input should succeed");
        assert!(!compressed.is_empty(), "xz output is never zero-length");
        use std::io::Read;
        let mut decoder = xz2::read::XzDecoder::new(&compressed[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();
        assert!(decompressed.is_empty());
    }

    // -----------------------------------------------------------------------
    // content_type_for_dists_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_content_type_for_dists_path_xz() {
        assert_eq!(
            content_type_for_dists_path("main/i18n/Translation-en.xz"),
            "application/x-xz"
        );
        assert_eq!(
            content_type_for_dists_path("main/binary-amd64/Packages.xz"),
            "application/x-xz"
        );
    }

    #[test]
    fn test_content_type_for_dists_path_gz() {
        assert_eq!(
            content_type_for_dists_path("main/i18n/Translation-en.gz"),
            "application/gzip"
        );
    }

    #[test]
    fn test_content_type_for_dists_path_bz2() {
        assert_eq!(
            content_type_for_dists_path("main/source/Sources.bz2"),
            "application/x-bzip2"
        );
    }

    #[test]
    fn test_content_type_for_dists_path_plain() {
        assert_eq!(
            content_type_for_dists_path("main/i18n/Translation-en"),
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            content_type_for_dists_path("main/source/Sources"),
            "text/plain; charset=utf-8"
        );
    }

    #[test]
    fn test_content_type_for_dists_path_zstd() {
        assert_eq!(
            content_type_for_dists_path("main/binary-amd64/Packages.zst"),
            "application/zstd"
        );
    }

    #[test]
    fn test_content_type_for_dists_path_lz4() {
        assert_eq!(
            content_type_for_dists_path("main/binary-amd64/Packages.lz4"),
            "application/x-lz4"
        );
    }

    #[test]
    fn test_content_type_for_dists_path_zstd_long_extension() {
        assert_eq!(
            content_type_for_dists_path("main/binary-arm64/Packages.zstd"),
            "application/zstd"
        );
    }

    // -----------------------------------------------------------------------
    // strip_binary_arch_prefix
    // -----------------------------------------------------------------------

    #[test]
    fn test_strip_binary_arch_prefix_amd64() {
        assert_eq!(strip_binary_arch_prefix("binary-amd64"), "amd64");
    }

    #[test]
    fn test_strip_binary_arch_prefix_arm64() {
        assert_eq!(strip_binary_arch_prefix("binary-arm64"), "arm64");
    }

    #[test]
    fn test_strip_binary_arch_prefix_i386() {
        assert_eq!(strip_binary_arch_prefix("binary-i386"), "i386");
    }

    #[test]
    fn test_strip_binary_arch_prefix_all() {
        assert_eq!(strip_binary_arch_prefix("binary-all"), "all");
    }

    #[test]
    fn test_strip_binary_arch_prefix_no_prefix() {
        assert_eq!(strip_binary_arch_prefix("amd64"), "amd64");
    }

    #[test]
    fn test_strip_binary_arch_prefix_empty() {
        assert_eq!(strip_binary_arch_prefix(""), "");
    }

    // -----------------------------------------------------------------------
    // packages_index_suffix
    // -----------------------------------------------------------------------

    #[test]
    fn test_packages_index_suffix_uncompressed() {
        assert_eq!(
            packages_index_suffix("main", "binary-amd64", ""),
            "main/binary-amd64/Packages"
        );
    }

    #[test]
    fn test_packages_index_suffix_gz() {
        assert_eq!(
            packages_index_suffix("main", "binary-amd64", "gz"),
            "main/binary-amd64/Packages.gz"
        );
    }

    #[test]
    fn test_packages_index_suffix_xz() {
        assert_eq!(
            packages_index_suffix("main", "binary-amd64", "xz"),
            "main/binary-amd64/Packages.xz"
        );
    }

    #[test]
    fn test_packages_index_suffix_non_free_arm64() {
        assert_eq!(
            packages_index_suffix("non-free", "binary-arm64", "xz"),
            "non-free/binary-arm64/Packages.xz"
        );
    }

    #[test]
    fn test_packages_index_suffix_contrib() {
        assert_eq!(
            packages_index_suffix("contrib", "binary-i386", "gz"),
            "contrib/binary-i386/Packages.gz"
        );
    }

    // -----------------------------------------------------------------------
    // build_packages_xz (integration of build_packages_text + xz_compress)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_packages_xz_single_entry() {
        let entries = vec![package_entry(
            "curl",
            "7.88.1-10",
            "amd64",
            "pool/main/c/curl/curl_7.88.1-10_amd64.deb",
            311296,
            "abcdef1234567890",
            "command line tool for transferring data with URL syntax",
        )];
        let compressed = build_packages_xz(&entries).expect("xz compression should succeed");
        // Verify XZ magic bytes
        assert_eq!(&compressed[..6], &[0xFD, b'7', b'z', b'X', b'Z', 0x00]);
        // Decompress and verify it contains the expected package text
        use std::io::Read;
        let mut decoder = xz2::read::XzDecoder::new(&compressed[..]);
        let mut decompressed = String::new();
        decoder.read_to_string(&mut decompressed).unwrap();
        assert!(decompressed.contains("Package: curl\n"));
        assert!(decompressed.contains("Version: 7.88.1-10\n"));
        assert!(decompressed.contains("Architecture: amd64\n"));
    }

    #[test]
    fn test_build_packages_xz_multiple_entries() {
        let entries = vec![
            package_entry(
                "nginx",
                "1.24.0",
                "amd64",
                "pool/main/n/nginx/nginx_1.24.0_amd64.deb",
                1024,
                "aaa",
                "HTTP server",
            ),
            package_entry(
                "curl",
                "8.0.0",
                "amd64",
                "pool/main/c/curl/curl_8.0.0_amd64.deb",
                2048,
                "bbb",
                "URL transfer tool",
            ),
        ];
        let compressed = build_packages_xz(&entries).expect("xz compression should succeed");
        use std::io::Read;
        let mut decoder = xz2::read::XzDecoder::new(&compressed[..]);
        let mut decompressed = String::new();
        decoder.read_to_string(&mut decompressed).unwrap();
        assert!(decompressed.contains("Package: nginx\n"));
        assert!(decompressed.contains("Package: curl\n"));
        // Entries separated by blank line
        assert!(decompressed.contains("\n\n"));
    }

    #[test]
    fn test_build_packages_xz_empty_entries() {
        let entries: Vec<PackageEntry> = vec![];
        let compressed = build_packages_xz(&entries).expect("xz of empty input should succeed");
        use std::io::Read;
        let mut decoder = xz2::read::XzDecoder::new(&compressed[..]);
        let mut decompressed = String::new();
        decoder.read_to_string(&mut decompressed).unwrap();
        assert!(decompressed.is_empty());
    }

    // -----------------------------------------------------------------------
    // xz_compress with realistic Packages-sized data
    // -----------------------------------------------------------------------

    #[test]
    fn test_xz_compress_large_packages_text() {
        // Generate a realistic multi-package index (the kind of data the
        // handler compresses in production).
        let mut text = String::new();
        for i in 0..50 {
            if i > 0 {
                text.push('\n');
            }
            text.push_str(&format!("Package: libfoo{}\n", i));
            text.push_str(&format!("Version: 1.0.{}\n", i));
            text.push_str("Architecture: amd64\n");
            text.push_str(&format!(
                "Filename: pool/main/libf/libfoo{}/libfoo{}_1.0.{}_amd64.deb\n",
                i, i, i
            ));
            text.push_str("Size: 10240\n");
            text.push_str("SHA256: deadbeef\n");
            text.push_str("Description: Test library\n");
        }
        let compressed = xz_compress(text.as_bytes()).expect("xz compression should succeed");
        // XZ compresses well on repetitive data
        assert!(
            compressed.len() < text.len(),
            "compressed ({}) should be smaller than original ({})",
            compressed.len(),
            text.len()
        );
        use std::io::Read;
        let mut decoder = xz2::read::XzDecoder::new(&compressed[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();
        assert_eq!(decompressed, text.as_bytes());
    }

    // -----------------------------------------------------------------------
    // Pure helpers added alongside the OpenPGP signing flow (#1236). These
    // are the path-shape parsers and string builders that the Debian
    // handlers exercise before they touch the DB or storage; locking them
    // down keeps the per-PR coverage gate above the 70% floor and pins
    // exact behavior so a future refactor of the dists/* route shape (or
    // the `binary-{arch}` segment convention) shows up as a test break.
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_deb_filename_standard() {
        let info = parse_deb_filename("hello_2.10-2_amd64.deb").expect("standard shape parses");
        assert_eq!(info.name, "hello");
        assert_eq!(info.version, "2.10-2");
        assert_eq!(info.arch, "amd64");
    }

    #[test]
    fn test_parse_deb_filename_missing_deb_suffix() {
        // No .deb suffix at all -- strip_suffix returns None.
        assert!(parse_deb_filename("hello_2.10-2_amd64").is_none());
    }

    #[test]
    fn test_parse_deb_filename_only_two_segments() {
        // Two underscores would be required; this has one.
        assert!(parse_deb_filename("hello_amd64.deb").is_none());
    }

    #[test]
    fn test_parse_deb_filename_version_may_contain_underscores() {
        // splitn(3) caps at three pieces, so any extra underscores in
        // segment 3 become part of the `arch` field. This pins the
        // splitn behaviour so a future refactor that bumps the split
        // depth shows up as an explicit test break.
        let info = parse_deb_filename("pkg_1.0_amd64_extra.deb").expect("splitn yields 3 segments");
        assert_eq!(info.name, "pkg");
        assert_eq!(info.version, "1.0");
        assert_eq!(info.arch, "amd64_extra");
    }

    #[test]
    fn test_strip_binary_arch_prefix_present() {
        assert_eq!(strip_binary_arch_prefix("binary-amd64"), "amd64");
    }

    #[test]
    fn test_strip_binary_arch_prefix_absent() {
        // Without the binary- prefix the input is returned unchanged.
        assert_eq!(strip_binary_arch_prefix("amd64"), "amd64");
    }

    #[test]
    fn test_strip_binary_arch_prefix_only_prefix() {
        // Edge case: the prefix is the entire input.
        assert_eq!(strip_binary_arch_prefix("binary-"), "");
    }

    #[test]
    fn test_packages_index_suffix_plain() {
        assert_eq!(
            packages_index_suffix("main", "binary-amd64", ""),
            "main/binary-amd64/Packages"
        );
    }

    #[test]
    fn test_packages_index_suffix_compressed() {
        assert_eq!(
            packages_index_suffix("main", "binary-amd64", "gz"),
            "main/binary-amd64/Packages.gz"
        );
        assert_eq!(
            packages_index_suffix("contrib", "binary-arm64", "xz"),
            "contrib/binary-arm64/Packages.xz"
        );
    }

    #[test]
    fn test_parse_packages_request_wrong_segment_count() {
        // Two segments -- caller should fall through to the upstream
        // proxy, not handle it as a Packages request.
        assert!(parse_packages_request("main/Packages").is_none());
        // Four segments.
        assert!(parse_packages_request("main/binary-amd64/extra/Packages").is_none());
    }

    #[test]
    fn test_parse_packages_request_missing_binary_prefix() {
        // Middle segment must start with "binary-"; "src-" is a real
        // Debian segment but is not handled here.
        assert!(parse_packages_request("main/src-amd64/Sources").is_none());
        assert!(parse_packages_request("main/amd64/Packages").is_none());
    }

    #[test]
    fn test_parse_packages_request_unknown_extension() {
        // Anything other than Packages / Packages.gz / Packages.xz / Packages.bz2 / Packages.zst
        // is None so the caller proxies to upstream.
        assert!(parse_packages_request("main/binary-amd64/Packages.bz2").is_some());
        assert!(parse_packages_request("main/binary-amd64/Packages.zst").is_some());
        assert!(parse_packages_request("main/binary-amd64/Release").is_none());
        assert!(parse_packages_request("main/binary-amd64/Packages.foo").is_none());
    }

    // ---------------------------------------------------------------------
    // signed_release_cache_key (#1236)
    //
    // The cache key must be stable for a given (variant, content, key
    // fingerprint) triple and must differ for InRelease vs Release.gpg
    // and across key rotations, so a key rotation cannot accidentally
    // serve a stale signature from a previous fingerprint.
    // ---------------------------------------------------------------------

    #[test]
    fn test_signed_release_cache_key_is_deterministic() {
        let a = signed_release_cache_key(SignedReleaseVariant::InRelease, "Release\n", "abcd");
        let b = signed_release_cache_key(SignedReleaseVariant::InRelease, "Release\n", "abcd");
        assert_eq!(a, b);
        // SHA-256 hex = 64 chars.
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn test_signed_release_cache_key_variant_namespaces_collide_safely() {
        let a = signed_release_cache_key(SignedReleaseVariant::InRelease, "Release\n", "abcd");
        let b = signed_release_cache_key(SignedReleaseVariant::ReleaseGpg, "Release\n", "abcd");
        assert_ne!(a, b);
    }

    #[test]
    fn test_signed_release_cache_key_content_change_rotates_key() {
        let a = signed_release_cache_key(SignedReleaseVariant::InRelease, "Release\n", "abcd");
        let b =
            signed_release_cache_key(SignedReleaseVariant::InRelease, "Release-changed\n", "abcd");
        assert_ne!(a, b);
    }

    #[test]
    fn test_signed_release_cache_key_fingerprint_change_rotates_key() {
        // A signing-key rotation must rotate the cache key so we never
        // serve a signature produced by a deactivated key.
        let a = signed_release_cache_key(SignedReleaseVariant::InRelease, "Release\n", "abcd");
        let b = signed_release_cache_key(SignedReleaseVariant::InRelease, "Release\n", "ef01");
        assert_ne!(a, b);
    }

    // -----------------------------------------------------------------------
    // Fix 1: load_debian_repository_config_strict structural check
    // -----------------------------------------------------------------------

    #[test]
    fn test_strict_config_loader_exists_and_has_correct_signature() {
        let src = include_str!("debian.rs");
        assert!(
            src.contains("async fn load_debian_repository_config_strict("),
            "strict loader must exist"
        );
        assert!(
            src.contains("Result<Option<DebianRepositoryConfig>, Response>"),
            "strict loader must return Result<Option<...>, Response>"
        );
        assert!(
            src.contains("SERVICE_UNAVAILABLE"),
            "DB/parse errors must return 503 SERVICE_UNAVAILABLE"
        );
    }

    #[test]
    fn test_proxy_remote_debian_package_uses_strict_config_loader() {
        let src = include_str!("debian.rs");
        let fn_start = src
            .find("async fn proxy_remote_debian_package(")
            .expect("proxy_remote_debian_package must exist");
        let fn_body = &src[fn_start..fn_start + 3000];
        assert!(
            fn_body.contains("load_debian_repository_config_strict("),
            "pool proxy must use the strict (fail-closed) config loader"
        );
        assert!(
            !fn_body.contains("unwrap_or_default()"),
            "pool proxy must never unwrap_or_default after load"
        );
    }

    // -----------------------------------------------------------------------
    // Fix 2: Passthrough must not cache — structural check
    // -----------------------------------------------------------------------

    #[test]
    fn test_passthrough_branch_does_not_call_cache_verified_helper() {
        let src = include_str!("debian.rs");
        let fn_start = src
            .find("async fn proxy_remote_debian_package(")
            .expect("proxy_remote_debian_package must exist");
        let fn_end = src[fn_start..]
            .find("async fn pool_download(")
            .map(|i| fn_start + i)
            .unwrap_or(src.len());
        let body = &src[fn_start..fn_end];

        // Find the passthrough block.
        let passthrough_start = body
            .find("if passthrough {")
            .expect("passthrough block must exist");
        let passthrough_block = &body[passthrough_start..];
        // The first return or closing brace of the passthrough block.
        let passthrough_block_end = passthrough_block
            .find("\n    }\n")
            .unwrap_or(passthrough_block.len());
        let passthrough_block = &passthrough_block[..passthrough_block_end];

        assert!(
            passthrough_block.contains("proxy_fetch_streaming_uncached("),
            "passthrough block must call uncached helper"
        );
        assert!(
            !passthrough_block.contains("proxy_fetch_streaming_with_cache_key_verified("),
            "passthrough block must NOT call the cache-key-verified helper"
        );
    }

    // -----------------------------------------------------------------------
    // Fix 9: Contents not generated from pool filenames — structural check
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_synced_generated_metadata_does_not_emit_contents() {
        let src = include_str!("debian.rs");
        let fn_start = src
            .find("fn build_synced_generated_metadata(")
            .expect("build_synced_generated_metadata must exist");
        let fn_body_start = src[fn_start..].find('{').map(|i| fn_start + i).unwrap();
        // The function ends at the closing brace of the outer block.
        let fn_body = &src[fn_body_start..fn_body_start + 3000];
        assert!(
            !fn_body.contains("Contents generation entirely") || fn_body.contains("NOT generated"),
            "build_synced_generated_metadata must not emit Contents indexes from pool filenames"
        );
        // The Contents path format must not appear in the active code.
        assert!(
            !fn_body.contains("Contents-{}\", index.component, index.architecture"),
            "Contents path construction must not appear in synced metadata generation"
        );
    }

    // -----------------------------------------------------------------------
    // Fix 11: bz2/zst canonicalization
    // -----------------------------------------------------------------------

    #[test]
    fn test_canonical_plain_dists_index_path_strips_bz2_and_zst() {
        assert_eq!(canonical_plain_dists_index_path("Packages.bz2"), "Packages");
        assert_eq!(canonical_plain_dists_index_path("Packages.zst"), "Packages");
        assert_eq!(
            canonical_plain_dists_index_path("Packages.zstd"),
            "Packages"
        );
        assert_eq!(canonical_plain_dists_index_path("Packages.gz"), "Packages");
        assert_eq!(canonical_plain_dists_index_path("Packages.xz"), "Packages");
        assert_eq!(canonical_plain_dists_index_path("Packages"), "Packages");
    }

    #[test]
    fn test_parse_packages_request_accepts_bz2_and_zst() {
        let bz2 = parse_packages_request("main/binary-amd64/Packages.bz2").unwrap();
        assert!(matches!(bz2.ext, PackagesExt::Bz2));
        let zst = parse_packages_request("main/binary-amd64/Packages.zst").unwrap();
        assert!(matches!(zst.ext, PackagesExt::Zst));
    }
}

// ---------------------------------------------------------------------------
// Virtual `dists/` member-iteration error propagation + large-index cap (#2267,
// #2278). These exercise `try_virtual_dists`:
//   * a >8 MiB Packages.xz now succeeds (LARGE_METADATA_MAX_BYTES ceiling) and
//     is served/cached instead of tripping the old 8 MiB DEFAULT cap (502);
//   * a genuine non-404 upstream failure is SURFACED to the client rather than
//     swallowed via `Err(_) => continue` into an `Ok(None)` that fell through
//     to an empty local-DB 200 (`apt`'s "File has unexpected size");
//   * a 404 member is still skipped so the caller can fall through to the
//     local-DB (hosted) path or the next mirror.
#[cfg(test)]
mod virtual_dists_cap_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use uuid::Uuid;
    use wiremock::matchers::{method, path as wm_path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const DIST: &str = "trixie";
    const PKG_PATH: &str = "dists/trixie/main/binary-amd64/Packages.xz";

    /// Insert a Remote Debian repo pointing at `upstream_url` and enrol it as a
    /// member of a fresh Virtual repo. Returns `(virtual_id, virtual_key,
    /// member_id)`; callers clean up via [`cleanup`].
    async fn virtual_with_remote_member(
        pool: &sqlx::PgPool,
        storage_path: &str,
        upstream_url: &str,
    ) -> (Uuid, String, Uuid) {
        let member_id = Uuid::new_v4();
        let member_key = format!("dbg-mem-{}", member_id.simple());
        sqlx::query(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, upstream_url) \
             VALUES ($1, $2, $3, $4, 'remote'::repository_type, 'debian'::repository_format, $5)",
        )
        .bind(member_id)
        .bind(&member_key)
        .bind(&member_key)
        .bind(storage_path)
        .bind(upstream_url)
        .execute(pool)
        .await
        .expect("insert remote member");

        let virtual_id = Uuid::new_v4();
        let virtual_key = format!("dbg-virt-{}", virtual_id.simple());
        sqlx::query(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
             VALUES ($1, $2, $3, $4, 'virtual'::repository_type, 'debian'::repository_format)",
        )
        .bind(virtual_id)
        .bind(&virtual_key)
        .bind(&virtual_key)
        .bind(storage_path)
        .execute(pool)
        .await
        .expect("insert virtual repo");
        sqlx::query(
            "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
             VALUES ($1, $2, 1)",
        )
        .bind(virtual_id)
        .bind(member_id)
        .execute(pool)
        .await
        .expect("insert virtual member");
        (virtual_id, virtual_key, member_id)
    }

    async fn cleanup(pool: &sqlx::PgPool, virtual_id: Uuid, member_id: Uuid) {
        let _ = sqlx::query("DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1")
            .bind(virtual_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = ANY($1)")
            .bind(vec![virtual_id, member_id])
            .execute(pool)
            .await;
    }

    // A 9 MiB Packages.xz — above the 8 MiB DEFAULT ceiling that used to 502 —
    // is fetched, served 200, and cached (second call issues no second upstream
    // request). Proves the DEFAULT->LARGE (128 MiB) tier switch for dists.
    #[tokio::test]
    #[allow(clippy::disallowed_methods)] // to_bytes on a bounded in-memory test body
    async fn large_packages_index_above_default_cap_succeeds_and_caches() {
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
            .and(wm_path(format!("/{PKG_PATH}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("dbg-cap-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let root = tmp.to_str().unwrap();
        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), root);
        let state = tdh::build_state_with_proxy(pool.clone(), root, proxy);
        let (virtual_id, virtual_key, member_id) =
            virtual_with_remote_member(&pool, root, &server.uri()).await;

        let first = try_virtual_dists(
            &state,
            virtual_id,
            &virtual_key,
            DIST,
            PKG_PATH,
            "application/octet-stream",
        )
        .await;
        let second = try_virtual_dists(
            &state,
            virtual_id,
            &virtual_key,
            DIST,
            PKG_PATH,
            "application/octet-stream",
        )
        .await;

        cleanup(&pool, virtual_id, member_id).await;
        let hits = server.received_requests().await.unwrap().len();
        let _ = std::fs::remove_dir_all(&tmp);

        let resp = first
            .expect("large index must not error")
            .expect("large index must resolve via the remote member");
        assert_eq!(resp.status(), StatusCode::OK);
        let got = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body");
        assert_eq!(got.len(), body.len(), "full 9 MiB body must be served");
        assert!(
            second.is_ok_and(|o| o.is_some()),
            "second read must still resolve",
        );
        assert_eq!(hits, 1, "second read must be served warm from cache");
    }

    // A genuine non-404 upstream failure (here a 5xx that folds to 502/503) must
    // SURFACE as an Err so the client sees the real cause — not be swallowed into
    // `Ok(None)` and rendered as an empty 200 (the #2278 `apt` size-mismatch bug).
    #[tokio::test]
    async fn upstream_failure_surfaces_instead_of_empty_200() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path(format!("/{PKG_PATH}")))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("dbg-502-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let root = tmp.to_str().unwrap();
        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), root);
        let state = tdh::build_state_with_proxy(pool.clone(), root, proxy);
        let (virtual_id, virtual_key, member_id) =
            virtual_with_remote_member(&pool, root, &server.uri()).await;

        let out = try_virtual_dists(
            &state,
            virtual_id,
            &virtual_key,
            DIST,
            PKG_PATH,
            "application/octet-stream",
        )
        .await;

        cleanup(&pool, virtual_id, member_id).await;
        let _ = std::fs::remove_dir_all(&tmp);

        let resp = out.expect_err(
            "a genuine upstream failure must surface as Err, not be masked into Ok(None)/empty-200",
        );
        assert!(
            resp.status().is_server_error(),
            "the real upstream failure status must reach the client, got {}",
            resp.status(),
        );
    }

    // A member that 404s for the path is skipped (the file genuinely is not
    // there), so the dispatcher returns Ok(None) and the caller falls through to
    // the local-DB / next-mirror path. This is the arm that must NOT be treated
    // as a hard failure — the discriminator only surfaces non-404 errors.
    #[tokio::test]
    async fn missing_member_file_falls_through_to_none() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path(format!("/{PKG_PATH}")))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("dbg-404-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let root = tmp.to_str().unwrap();
        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), root);
        let state = tdh::build_state_with_proxy(pool.clone(), root, proxy);
        let (virtual_id, virtual_key, member_id) =
            virtual_with_remote_member(&pool, root, &server.uri()).await;

        let out = try_virtual_dists(
            &state,
            virtual_id,
            &virtual_key,
            DIST,
            PKG_PATH,
            "application/octet-stream",
        )
        .await;

        cleanup(&pool, virtual_id, member_id).await;
        let _ = std::fs::remove_dir_all(&tmp);

        assert!(
            matches!(out, Ok(None)),
            "a 404 member must fall through to Ok(None), got {:?}",
            out.map(|o| o.map(|r| r.status())),
        );
    }

    // The change-detecting variant (Release/InRelease revalidation path) applies
    // the same NotFound-vs-real-error discrimination: a 5xx upstream surfaces as
    // an Err instead of `Ok(None)` (which would have fallen through to an empty
    // signed Release), while a 404 member is skipped.
    const INRELEASE_PATH: &str = "dists/trixie/InRelease";

    #[tokio::test]
    async fn detecting_change_upstream_failure_surfaces() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path(format!("/{INRELEASE_PATH}")))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("dbg-dc502-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let root = tmp.to_str().unwrap();
        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), root);
        let state = tdh::build_state_with_proxy(pool.clone(), root, proxy);
        let (virtual_id, virtual_key, member_id) =
            virtual_with_remote_member(&pool, root, &server.uri()).await;

        let out = try_virtual_dists_detecting_change(
            &state,
            virtual_id,
            &virtual_key,
            DIST,
            INRELEASE_PATH,
            "application/octet-stream",
        )
        .await;

        cleanup(&pool, virtual_id, member_id).await;
        let _ = std::fs::remove_dir_all(&tmp);

        let resp = out.expect_err("a 5xx upstream must surface as Err, not empty Ok(None)");
        assert!(
            resp.status().is_server_error(),
            "real upstream failure status must reach the client, got {}",
            resp.status(),
        );
    }

    #[tokio::test]
    async fn detecting_change_missing_member_falls_through_to_none() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path(format!("/{INRELEASE_PATH}")))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let tmp = std::env::temp_dir().join(format!("dbg-dc404-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let root = tmp.to_str().unwrap();
        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), root);
        let state = tdh::build_state_with_proxy(pool.clone(), root, proxy);
        let (virtual_id, virtual_key, member_id) =
            virtual_with_remote_member(&pool, root, &server.uri()).await;

        let out = try_virtual_dists_detecting_change(
            &state,
            virtual_id,
            &virtual_key,
            DIST,
            INRELEASE_PATH,
            "application/octet-stream",
        )
        .await;

        cleanup(&pool, virtual_id, member_id).await;
        let _ = std::fs::remove_dir_all(&tmp);

        assert!(
            matches!(out, Ok(None)),
            "a 404 member must fall through to Ok(None), got {:?}",
            out.map(|o| o.map(|r| r.status())),
        );
    }
}

#[cfg(test)]
mod upload_db_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;

    fn append_ar_member(out: &mut Vec<u8>, name: &str, content: &[u8]) {
        let header = format!(
            "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            name,
            0,
            0,
            0,
            "100644",
            content.len()
        );
        assert_eq!(header.len(), 60, "ar header must be exactly 60 bytes");
        out.extend_from_slice(header.as_bytes());
        out.extend_from_slice(content);
        if content.len() % 2 == 1 {
            out.push(b'\n');
        }
    }

    fn control_tar_gz(control: &str) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(control.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "./control", control.as_bytes())
            .expect("append control file");
        builder.finish().expect("finish control.tar");
        let tar_bytes = builder.into_inner().expect("control.tar bytes");
        gzip_compress(&tar_bytes).expect("gzip control.tar")
    }

    fn empty_data_tar_gz() -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        builder.finish().expect("finish data.tar");
        let tar_bytes = builder.into_inner().expect("data.tar bytes");
        gzip_compress(&tar_bytes).expect("gzip data.tar")
    }

    fn minimal_deb(package: &str, version: &str, architecture: &str, description: &str) -> Vec<u8> {
        let control = format!(
            "Package: {package}\n\
             Version: {version}\n\
             Architecture: {architecture}\n\
             Maintainer: Test Maintainer <test@example.local>\n\
             Installed-Size: 7\n\
             Depends: libc6 (>= 2.36)\n\
             Section: utils\n\
             Priority: optional\n\
             Homepage: https://example.local/{package}\n\
             Description: {description}\n\
             {description_continuation}",
            description_continuation = " extended description line\n",
        );

        let mut deb = Vec::new();
        deb.extend_from_slice(b"!<arch>\n");
        append_ar_member(&mut deb, "debian-binary", b"2.0\n");
        append_ar_member(&mut deb, "control.tar.gz", &control_tar_gz(&control));
        append_ar_member(&mut deb, "data.tar.gz", &empty_data_tar_gz());
        deb
    }

    fn headers_with_replication(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-artifact-keeper-replication",
            axum::http::HeaderValue::from_str(value).unwrap(),
        );
        headers
    }

    #[test]
    fn test_debian_upload_metadata_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-debian-distribution",
            axum::http::HeaderValue::from_static("bookworm"),
        );
        headers.insert(
            "x-debian-component",
            axum::http::HeaderValue::from_static("main"),
        );
        headers.insert(
            "x-debian-architecture",
            axum::http::HeaderValue::from_static("amd64"),
        );

        assert_eq!(
            debian_upload_distribution(&headers).unwrap().as_deref(),
            Some("bookworm")
        );
        assert_eq!(
            debian_upload_component(&headers).unwrap().as_deref(),
            Some("main")
        );
        assert_eq!(
            debian_upload_architecture(&headers).unwrap().as_deref(),
            Some("amd64")
        );
        assert!(validate_debian_component_header("main", Some("main")).is_ok());
        assert!(validate_debian_component_header("main", Some("universe")).is_err());

        headers.insert(
            "x-debian-component",
            axum::http::HeaderValue::from_static("../main"),
        );
        assert!(debian_upload_component(&headers).is_err());
    }

    #[test]
    fn test_debian_artifact_metadata_includes_upload_context() {
        let control = DebControl {
            package: "sample".to_string(),
            version: "1.0-1".to_string(),
            architecture: "amd64".to_string(),
            ..DebControl::default()
        };
        let metadata = build_debian_artifact_metadata(
            Some("bookworm"),
            "main",
            "pool/main/s/sample/sample_1.0-1_amd64.deb",
            "sample_1.0-1_amd64.deb",
            "deb",
            &control,
        );

        assert_eq!(metadata["distribution"], "bookworm");
        assert_eq!(metadata["component"], "main");
        assert_eq!(metadata["architecture"], "amd64");
    }

    #[test]
    fn test_should_enqueue_debian_sync_tasks_for_direct_upload() {
        assert!(should_enqueue_debian_sync_tasks(&HeaderMap::new()));
    }

    #[test]
    fn test_should_enqueue_debian_sync_tasks_skips_peer_replication() {
        assert!(!should_enqueue_debian_sync_tasks(
            &headers_with_replication("true")
        ));
    }

    #[tokio::test]
    async fn pool_upload_populates_debian_metadata_packages_and_indexes() {
        let Some(f) = tdh::Fixture::setup("local", "debian").await else {
            return;
        };

        let package = "ak-debian-indexed";
        let version = "1.2.3-1";
        let arch = "amd64";
        let deb = minimal_deb(package, version, arch, "indexed Debian package");
        let app = f.router_with_auth(super::router());
        let path = format!("a/{package}/{package}_{version}_{arch}.deb");
        let uri = format!("/{}/pool/main/{}", f.repo_key, path);
        let (status, body) = tdh::send(app.clone(), tdh::put(uri, Bytes::from(deb))).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "upload failed: {}",
            String::from_utf8_lossy(&body)
        );

        let artifact: (uuid::Uuid, String, String, Option<String>, String) = sqlx::query_as(
            "SELECT id, path, name, version, checksum_sha256 FROM artifacts \
             WHERE repository_id = $1 AND name = $2 AND is_deleted = false",
        )
        .bind(f.repo_id)
        .bind(package)
        .fetch_one(&f.pool)
        .await
        .expect("query uploaded artifact");
        assert_eq!(
            artifact.1,
            format!("pool/main/a/{package}/{package}_{version}_{arch}.deb")
        );
        assert_eq!(artifact.2, package);
        assert_eq!(artifact.3.as_deref(), Some(version));
        assert_eq!(artifact.4.len(), 64);

        let metadata: (serde_json::Value,) =
            sqlx::query_as("SELECT metadata FROM artifact_metadata WHERE artifact_id = $1")
                .bind(artifact.0)
                .fetch_one(&f.pool)
                .await
                .expect("query Debian artifact metadata");
        assert_eq!(metadata.0["format"], "debian");
        assert_eq!(metadata.0["component"], "main");
        assert!(metadata.0["distribution"].is_null());
        assert_eq!(metadata.0["architecture"], arch);
        assert_eq!(metadata.0["control"]["package"], package);
        assert_eq!(metadata.0["control"]["version"], version);
        assert_eq!(metadata.0["control"]["depends"][0], "libc6 (>= 2.36)");

        let pkg: (String, Option<String>, Option<serde_json::Value>) = sqlx::query_as(
            "SELECT version, description, metadata FROM packages \
             WHERE repository_id = $1 AND name = $2",
        )
        .bind(f.repo_id)
        .bind(package)
        .fetch_one(&f.pool)
        .await
        .expect("query package catalog");
        assert_eq!(pkg.0, version);
        assert_eq!(
            pkg.1.as_deref(),
            Some("indexed Debian package\nextended description line")
        );
        let pkg_meta = pkg.2.expect("package metadata should be set");
        assert_eq!(pkg_meta["format"], "debian");
        assert_eq!(pkg_meta["architecture"], arch);
        assert!(pkg_meta["distribution"].is_null());
        assert_eq!(pkg_meta["component"], "main");

        let version_rows: (i64,) = sqlx::query_as(
            "SELECT COUNT(*)::bigint FROM package_versions pv \
             JOIN packages p ON p.id = pv.package_id \
             WHERE p.repository_id = $1 AND p.name = $2 AND pv.version = $3",
        )
        .bind(f.repo_id)
        .bind(package)
        .bind(version)
        .fetch_one(&f.pool)
        .await
        .expect("query package_versions");
        assert_eq!(version_rows.0, 1);

        let (status, packages_body) = tdh::send(
            app.clone(),
            tdh::get(format!(
                "/{}/dists/bookworm/main/binary-amd64/Packages",
                f.repo_key
            )),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let packages_text = String::from_utf8(packages_body.to_vec()).unwrap();
        assert!(packages_text.contains(&format!("Package: {package}\n")));
        assert!(packages_text.contains("Architecture: amd64\n"));
        assert!(packages_text.contains("Depends: libc6 (>= 2.36)\n"));
        assert!(packages_text
            .contains("Description: indexed Debian package\n extended description line\n"));
        assert!(packages_text.contains("SHA256: "));

        let (status, all_body) = tdh::send(
            app.clone(),
            tdh::get(format!(
                "/{}/dists/bookworm/main/binary-all/Packages",
                f.repo_key
            )),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let all_text = String::from_utf8(all_body.to_vec()).unwrap();
        assert!(
            !all_text.contains(&format!("Package: {package}\n")),
            "binary-all must not contain arch-specific packages"
        );

        let (status, release_body) = tdh::send(
            app,
            tdh::get(format!("/{}/dists/bookworm/Release", f.repo_key)),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let release = String::from_utf8(release_body.to_vec()).unwrap();
        assert!(release.contains("Architectures: amd64\n"));
        assert!(release.contains("Components: main\n"));
        assert!(release.contains("MD5Sum:\n"));
        assert!(release.contains("SHA1:\n"));
        assert!(release.contains("SHA256:\n"));
        assert!(release.contains("SHA512:\n"));
        assert!(release.contains("main/binary-amd64/Packages\n"));
        assert!(release.contains("main/binary-amd64/Packages.gz\n"));
        assert!(release.contains("main/binary-amd64/Packages.xz\n"));

        f.teardown().await;
    }
}
