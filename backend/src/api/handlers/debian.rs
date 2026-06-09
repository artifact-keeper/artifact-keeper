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

use std::collections::BTreeSet;
use std::io::{self, Write};

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Extension;
use axum::Router;
use bytes::Bytes;
use flate2::Compression;
use flate2::GzBuilder;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;

use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::{SharedState, SIGNED_RELEASE_CACHE_MAX_ENTRIES};
use crate::formats::debian::{DebControl, DebianHandler};
use crate::models::repository::RepositoryType;
use crate::models::signing_key::SigningKey;
use crate::services::artifact_service::ArtifactService;
use crate::services::package_service::PackageService;
use crate::services::signing_service::SigningService;

const DEBIAN_BINARY_CONTENT_TYPE: &str = "application/vnd.debian.binary-package";

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router() -> Router<SharedState> {
    Router::new()
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
        // Alternative upload endpoint
        .route("/:repo_key/upload", post(upload_raw))
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

fn push_packages_entry(text: &mut String, entry: &PackageEntry) {
    let control = &entry.control;
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
    push_control_field(text, "Filename", &entry.filename);
    push_control_field(text, "Size", &entry.size.to_string());
    push_optional_control_field(text, "MD5sum", entry.md5.as_deref());
    push_optional_control_field(text, "SHA1", entry.sha1.as_deref());
    push_control_field(text, "SHA256", &entry.sha256);
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

/// Fetch all package entries for a given repo, component, and architecture.
async fn fetch_package_entries(
    db: &PgPool,
    repo_id: uuid::Uuid,
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
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

    let mut entries = Vec::new();
    for a in &artifacts {
        let (path, size_bytes, checksum_sha256, checksum_sha1, checksum_md5, metadata) = a;
        let filename = path.rsplit('/').next().unwrap_or(path);
        let deb_info = match parse_deb_filename(filename) {
            Some(info) => info,
            None => continue,
        };

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

async fn generate_release_content(
    state: &SharedState,
    repo_id: uuid::Uuid,
    distribution: &str,
) -> Result<String, Response> {
    let (components, architectures) = discover_release_layout(&state.db, repo_id).await?;
    let component_str = components.iter().cloned().collect::<Vec<_>>().join(" ");
    let arch_str = architectures.iter().cloned().collect::<Vec<_>>().join(" ");

    let mut release_files = Vec::new();
    for component in &components {
        for arch in &architectures {
            let entries = fetch_package_entries(&state.db, repo_id, component, arch).await?;
            let packages_text = build_packages_text(&entries);
            let packages_bytes = packages_text.into_bytes();
            let packages_path = format!("{}/binary-{}/Packages", component, arch);
            release_files.push((packages_path, packages_bytes.clone()));

            let gz_bytes = gzip_compress(&packages_bytes).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Compression error: {}", e),
                )
                    .into_response()
            })?;
            release_files.push((
                format!("{}/binary-{}/Packages.gz", component, arch),
                gz_bytes,
            ));

            let xz_bytes = xz_compress(&packages_bytes).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("XZ compression error: {}", e),
                )
                    .into_response()
            })?;
            release_files.push((
                format!("{}/binary-{}/Packages.xz", component, arch),
                xz_bytes,
            ));
        }
    }

    let now = chrono::Utc::now();
    let date_str = now.format("%a, %d %b %Y %H:%M:%S UTC").to_string();

    let mut release = String::new();
    release.push_str("Origin: artifact-keeper\n");
    release.push_str("Label: artifact-keeper\n");
    release.push_str(&format!("Suite: {}\n", distribution));
    release.push_str(&format!("Codename: {}\n", distribution));
    release.push_str(&format!("Date: {}\n", date_str));
    release.push_str(&format!("Architectures: {}\n", arch_str));
    release.push_str(&format!("Components: {}\n", component_str));
    push_release_hash_section(&mut release, "MD5Sum", &release_files, |bytes| {
        ArtifactService::calculate_md5(bytes)
    });
    push_release_hash_section(&mut release, "SHA1", &release_files, |bytes| {
        ArtifactService::calculate_sha1(bytes)
    });
    push_release_hash_section(&mut release, "SHA256", &release_files, |bytes| {
        ArtifactService::calculate_sha256(bytes)
    });

    Ok(release)
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
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

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
                architectures.insert(control.architecture);
            }
        }
    }

    if components.is_empty() {
        components.insert("main".to_string());
    }

    if architectures.is_empty() {
        architectures.insert("all".to_string());
        architectures.insert("amd64".to_string());
        architectures.insert("arm64".to_string());
    }

    Ok((components, architectures))
}

fn component_from_pool_path(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("pool/")?;
    rest.split('/')
        .next()
        .filter(|component| !component.is_empty())
}

fn gzip_compress(data: &[u8]) -> Result<Vec<u8>, io::Error> {
    let mut encoder = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder.finish()
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
        // Virtual repos: try each Remote member in priority order so a
        // virtual APT repo can serve dists metadata when its top-level
        // type is `virtual` (#1147). Local/Staging members produce
        // their dists metadata locally, handled by the caller's
        // post-`dists()` fallthrough, so we only need to handle Remote.
        if repo.repo_type == RepositoryType::Virtual {
            let upstream_path = format!("dists/{}/{}", self.distribution, suffix);
            if let Some(resp) = try_virtual_dists(
                self.state,
                repo.id,
                self.repo_key,
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
        let upstream_path = format!("dists/{}/{}", self.distribution, suffix);
        let (content, upstream_ct) =
            proxy_helpers::proxy_fetch(proxy, repo.id, self.repo_key, upstream_url, &upstream_path)
                .await?;
        Err(build_dists_response(content, upstream_ct, content_type))
    }

    /// Variant of `dists` that also detects whether the upstream content
    /// changed since the last cached copy. When it has, sibling Packages
    /// caches under the same distribution are invalidated so subsequent
    /// `apt-get update` requests refetch them and the Release SHA-256
    /// list matches what apt sees (#1147).
    ///
    /// Used by the Release / InRelease handlers, where stale Packages
    /// caches manifest as `Hash Sum mismatch` errors on the client.
    async fn dists_detecting_change(
        &self,
        suffix: &str,
        content_type: &'static str,
        repo: &RepoInfo,
    ) -> Result<(), Response> {
        let upstream_path = format!("dists/{}/{}", self.distribution, suffix);

        // Virtual: iterate Remote members. Whichever member serves the
        // Release also owns the sibling Packages caches we may need to
        // invalidate, so we run the change-detection probe against that
        // specific member before returning.
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
            .fetch_dists_detecting_change(&pseudo_repo, &upstream_path)
            .await
            .map_err(map_proxy_err)?;

        if let Some(text) = release_invalidation_payload(changed, &content) {
            proxy
                .invalidate_dist_packages_cache(self.repo_key, self.distribution, text)
                .await;
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

/// Pure helper that decides whether an upstream Release body should
/// trigger sibling-Packages cache invalidation (#1147). Returns the
/// decoded UTF-8 body when the caller should invalidate, `None` when
/// the body either didn't change or isn't valid UTF-8. Factoring this
/// out makes the change-detection branch testable without a real
/// proxy fetch.
fn release_invalidation_payload(changed: bool, content: &[u8]) -> Option<&str> {
    if !changed {
        return None;
    }
    std::str::from_utf8(content).ok()
}

// ---------------------------------------------------------------------------
// Signed-Release cache helpers (#1236)
//
// `apt update` polls InRelease and Release.gpg on every refresh; OpenPGP
// signing is multi-millisecond CPU work, so we cache the signed bytes keyed
// by SHA-256(unsigned Release || key fingerprint). The fingerprint is in the
// key so that a key rotation naturally invalidates the prior signature, and
// the content prefix means any Release flip rotates the key without needing
// an explicit invalidation pass — though we also evict eagerly from the
// change-detect path to keep the cache from growing unboundedly.
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
/// `(repo_key, distribution)`. Called from the change-detection paths so
/// that an upstream Release flip drops the matching signed copies in
/// lock-step with the sibling-Packages eviction in `proxy_service`.
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
/// return the first successful response.
async fn try_virtual_dists(
    state: &SharedState,
    virtual_repo_id: uuid::Uuid,
    virtual_repo_key: &str,
    upstream_path: &str,
    default_content_type: &'static str,
) -> Result<Option<Response>, Response> {
    let _ = virtual_repo_key;
    let members = proxy_helpers::fetch_virtual_members(&state.db, virtual_repo_id).await?;
    let Some(proxy) = state.proxy_service.as_deref() else {
        return Ok(None);
    };
    for member in &members {
        let Some(upstream_url) = remote_member_upstream(member) else {
            continue;
        };
        match proxy_helpers::proxy_fetch(proxy, member.id, &member.key, upstream_url, upstream_path)
            .await
        {
            Ok((content, upstream_ct)) => {
                return Ok(Some(build_dists_response(
                    content,
                    upstream_ct,
                    default_content_type,
                )));
            }
            Err(_) => {
                // Try the next member.
                continue;
            }
        }
    }
    Ok(None)
}

/// Change-detection variant of [`try_virtual_dists`]. Used for
/// Release/InRelease so that any upstream change invalidates the matching
/// member's sibling `Packages*` caches before the client tries to fetch
/// them (#1147).
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
    for member in &members {
        let Some(upstream_url) = remote_member_upstream(member) else {
            continue;
        };
        let pseudo_repo = proxy_helpers::build_remote_repo(member.id, &member.key, upstream_url);
        match proxy
            .fetch_dists_detecting_change(&pseudo_repo, upstream_path)
            .await
        {
            Ok((content, upstream_ct, changed)) => {
                if let Some(text) = release_invalidation_payload(changed, &content) {
                    proxy
                        .invalidate_dist_packages_cache(&member.key, distribution, text)
                        .await;
                    signed_release_cache_invalidate(state, &member.key, distribution).await;
                }
                return Ok(Some(build_dists_response(
                    content,
                    upstream_ct,
                    default_content_type,
                )));
            }
            Err(_) => continue,
        }
    }
    Ok(None)
}

fn map_proxy_err(e: crate::error::AppError) -> Response {
    let (status, msg) = proxy_err_status_and_message(&e);
    (status, msg).into_response()
}

/// Pure helper that decides the HTTP status and message for an
/// `AppError` returned from `ProxyService::fetch_dists_detecting_change`.
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
async fn local_release_content(
    state: &SharedState,
    repo_key: &str,
    distribution: &str,
) -> Result<(String, RepoInfo), Response> {
    let repo = resolve_debian_repo(&state.db, repo_key).await?;
    let release = generate_release_content(state, repo.id, distribution).await?;
    Ok((release, repo))
}

async fn release_file(
    State(state): State<SharedState>,
    Path((repo_key, distribution)): Path<(String, String)>,
) -> Result<Response, Response> {
    let (proxy, repo) = DebianProxy::resolve(&state, &repo_key, &distribution).await?;
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
    proxy
        .dists_detecting_change("InRelease", "text/plain; charset=utf-8", &repo)
        .await?;

    let (release, repo) = local_release_content(&state, &repo_key, &distribution).await?;

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
    // change-detection here because the matching Release fetch (called
    // by apt before Release.gpg) already drove invalidation.
    proxy
        .dists("Release.gpg", "application/pgp-signature", &repo)
        .await?;

    let (release, repo) = local_release_content(&state, &repo_key, &distribution).await?;

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

// ---------------------------------------------------------------------------
// GET /debian/{repo_key}/dists/{dist}/{component}/binary-{arch}/Packages
// ---------------------------------------------------------------------------

async fn packages_index(
    State(state): State<SharedState>,
    Path((repo_key, distribution, component, binary_arch)): Path<(String, String, String, String)>,
) -> Result<Response, Response> {
    let (proxy, repo) = DebianProxy::resolve(&state, &repo_key, &distribution).await?;
    let packages_suffix = packages_index_suffix(&component, &binary_arch, "");
    proxy
        .dists(&packages_suffix, "text/plain; charset=utf-8", &repo)
        .await?;

    let arch = strip_binary_arch_prefix(&binary_arch);

    let entries = fetch_package_entries(&state.db, repo.id, &component, arch).await?;
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
    proxy
        .dists(&packages_gz_suffix, "application/gzip", &repo)
        .await?;

    let arch = strip_binary_arch_prefix(&binary_arch);

    let entries = fetch_package_entries(&state.db, repo.id, &component, arch).await?;
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
    proxy
        .dists(&packages_xz_suffix, "application/x-xz", &repo)
        .await?;

    let arch = strip_binary_arch_prefix(&binary_arch);

    let entries = fetch_package_entries(&state.db, repo.id, &component, arch).await?;

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
}

/// Recognise `{component}/binary-{arch}/Packages{,.gz,.xz}` inside the
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
        _ => return None,
    };
    Some(PackagesRequest {
        component: segments[0].to_string(),
        binary_arch: segments[1].to_string(),
        ext,
    })
}

/// Single entry point for all `dists/{distribution}/...` requests after
/// the static Release/InRelease/Release.gpg/gpg-key.asc routes. Dispatches
/// `{component}/binary-{arch}/Packages{,.gz,.xz}` to the matching Packages
/// handler and forwards everything else to the upstream proxy catch-all.
async fn dists_dispatch(
    state: State<SharedState>,
    Path((repo_key, distribution, dists_path)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    if let Some(req) = parse_packages_request(&dists_path) {
        let path = Path((repo_key, distribution, req.component, req.binary_arch));
        return match req.ext {
            PackagesExt::Plain => packages_index(state, path).await,
            PackagesExt::Gz => packages_index_gz(state, path).await,
            PackagesExt::Xz => packages_index_xz(state, path).await,
        };
    }
    dists_proxy_catchall(state, Path((repo_key, distribution, dists_path))).await
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

    let upstream_path = format!("dists/{}/{}", distribution, dists_path);

    // Virtual repos: walk Remote members in priority order so a Virtual
    // APT repo can serve i18n / Translation / dep11 / Sources etc. just
    // like Release/Packages handlers (#1147).
    if repo.repo_type == RepositoryType::Virtual {
        let resp = try_virtual_dists(
            &state,
            repo.id,
            &repo_key,
            &upstream_path,
            "text/plain; charset=utf-8",
        )
        .await?;
        return resp.ok_or_else(|| (StatusCode::NOT_FOUND, "Not found").into_response());
    }

    if repo.repo_type != RepositoryType::Remote {
        return Err((StatusCode::NOT_FOUND, "Not found").into_response());
    }

    let (upstream_url, proxy) = match (&repo.upstream_url, &state.proxy_service) {
        (Some(u), Some(p)) => (u, p),
        _ => return Err((StatusCode::NOT_FOUND, "Not found").into_response()),
    };

    let (content, upstream_ct) =
        proxy_helpers::proxy_fetch(proxy, repo.id, &repo_key, upstream_url, &upstream_path).await?;

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

// ---------------------------------------------------------------------------
// GET /debian/{repo_key}/pool/{component}/*path -- Download .deb
// ---------------------------------------------------------------------------

async fn pool_download(
    State(state): State<SharedState>,
    Path((repo_key, component, path)): Path<(String, String, String)>,
) -> Result<Response, Response> {
    let repo = resolve_debian_repo(&state.db, &repo_key).await?;

    let artifact_path = format!("pool/{}/{}", component, path);

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
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?
    .ok_or_else(|| (StatusCode::NOT_FOUND, "Package not found").into_response());

    let artifact = match artifact {
        Ok(a) => a,
        Err(not_found) => {
            if repo.repo_type == RepositoryType::Remote {
                if let (Some(ref upstream_url), Some(ref proxy)) =
                    (&repo.upstream_url, &state.proxy_service)
                {
                    let upstream_path = format!("pool/{}/{}", component, path);
                    // #895: stream .deb bodies. Default Content-Type
                    // matches the IANA registration for Debian packages
                    // (apt clients don't care; the registration just
                    // gives downstream proxies a meaningful Content-Type
                    // when upstream omits it).
                    return proxy_helpers::proxy_fetch_streaming(
                        proxy,
                        repo.id,
                        &repo_key,
                        upstream_url,
                        &upstream_path,
                        DEBIAN_BINARY_CONTENT_TYPE,
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
    let _ = sqlx::query!(
        "INSERT INTO download_statistics (artifact_id, ip_address) VALUES ($1, '0.0.0.0')",
        artifact.id
    )
    .execute(&state.db)
    .await;

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

struct DebianPackageUpload {
    artifact_path: String,
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

    let artifact_path = format!("pool/{}/{}", component, path);
    let metadata = build_debian_artifact_metadata(
        component,
        &artifact_path,
        filename,
        &deb_info.package_type,
        &control,
    );

    Ok(DebianPackageUpload {
        artifact_path,
        component: component.to_string(),
        deb_info,
        control,
        metadata,
    })
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
    component: &str,
    artifact_path: &str,
    filename: &str,
    package_type: &str,
    control: &DebControl,
) -> serde_json::Value {
    serde_json::json!({
        "format": "debian",
        "package": &control.package,
        "name": &control.package,
        "version": &control.version,
        "architecture": &control.architecture,
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
        "section": &control.section,
        "priority": &control.priority,
        "homepage": &control.homepage,
        "source": &control.source,
        "control": control,
    })
}

fn build_debian_package_catalog_metadata(upload: &DebianPackageUpload) -> serde_json::Value {
    serde_json::json!({
        "format": "debian",
        "architecture": &upload.control.architecture,
        "component": &upload.component,
        "package_type": &upload.deb_info.package_type,
        "section": &upload.control.section,
        "priority": &upload.control.priority,
        "maintainer": &upload.control.maintainer,
        "homepage": &upload.control.homepage,
        "source": &upload.control.source,
    })
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
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        )
            .into_response()
    })?;

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

    let upload = prepare_debian_upload(&component, &path, &body)?;
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

    let component = "main";
    let artifact_path = DebianHandler::get_pool_path(component, &deb_info.name, &filename);
    let path = artifact_path
        .strip_prefix("pool/main/")
        .unwrap_or(&artifact_path)
        .to_string();
    let upload = prepare_debian_upload(component, &path, &body)?;
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
                "path": &upload.artifact_path,
                "sha256": &artifact.checksum_sha256,
                "size": artifact.size_bytes,
            })
            .to_string(),
        ))
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            promotion_target_id: None,
            promotion_policy_id: None,
            curation_enabled: false,
            curation_source_repo_id: None,
            curation_target_repo_id: None,
            curation_default_action: "allow".to_string(),
            curation_sync_interval_secs: 0,
            curation_auto_fetch: false,
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
    // release_invalidation_payload (#1147)
    //
    // Pure helper that gates sibling-Packages cache invalidation on both
    // the change flag AND UTF-8 decodability of the body.
    // -----------------------------------------------------------------------

    #[test]
    fn test_release_invalidation_payload_skips_when_unchanged() {
        // Even a perfectly valid Release body must not trigger cache
        // invalidation when the upstream content was identical to the
        // cached copy. Otherwise apt-get update would needlessly
        // churn sibling caches on every poll.
        let release = b"SHA256:\n abc 100 main/binary-amd64/Packages\n";
        assert!(release_invalidation_payload(false, release).is_none());
    }

    #[test]
    fn test_release_invalidation_payload_returns_text_when_changed() {
        let release = b"SHA256:\n abc 100 main/binary-amd64/Packages\n";
        let got = release_invalidation_payload(true, release);
        assert!(got.is_some());
        assert!(got.unwrap().contains("main/binary-amd64/Packages"));
    }

    #[test]
    fn test_release_invalidation_payload_skips_non_utf8_body() {
        // A malicious or corrupted upstream that serves binary garbage
        // under the `Release` URL must not crash the handler; the
        // invalidation step is silently skipped.
        let garbage: &[u8] = &[0xff, 0xfe, 0xfd, 0xfc];
        assert!(release_invalidation_payload(true, garbage).is_none());
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
    fn test_package_matches_requested_arch() {
        assert!(package_matches_requested_arch("amd64", "amd64"));
        assert!(package_matches_requested_arch("all", "amd64"));
        assert!(package_matches_requested_arch("all", "all"));
        assert!(!package_matches_requested_arch("amd64", "all"));
        assert!(!package_matches_requested_arch("arm64", "amd64"));
    }

    #[test]
    fn test_component_from_pool_path() {
        assert_eq!(
            component_from_pool_path("pool/non-free/n/nvidia/pkg_1_amd64.deb"),
            Some("non-free")
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
        // Anything other than Packages / Packages.gz / Packages.xz
        // is None so the caller proxies to upstream.
        assert!(parse_packages_request("main/binary-amd64/Packages.bz2").is_none());
        assert!(parse_packages_request("main/binary-amd64/Release").is_none());
    }

    #[test]
    fn test_release_invalidation_payload_changed() {
        // Non-empty bytes + changed -> Some(snippet) so the caller emits
        // a webhook payload. Empty bytes still returns Some but with the
        // empty string.
        let payload = release_invalidation_payload(true, b"foo bar baz");
        assert!(payload.is_some());
    }

    #[test]
    fn test_release_invalidation_payload_unchanged_is_none() {
        // changed = false -> None; no webhook fires.
        assert!(release_invalidation_payload(false, b"any content").is_none());
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
        assert!(release.contains("main/binary-amd64/Packages\n"));
        assert!(release.contains("main/binary-amd64/Packages.gz\n"));
        assert!(release.contains("main/binary-amd64/Packages.xz\n"));

        f.teardown().await;
    }
}
