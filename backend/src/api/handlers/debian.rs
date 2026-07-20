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
//!   GET  /debian/{repo_key}/gpg-key.asc                                             - Repository public key
//!   GET  /debian/{repo_key}/pool/{component}/*path                                  - Download .deb
//!   PUT  /debian/{repo_key}/pool/{component}/*path                                  - Upload .deb
//!   POST /debian/{repo_key}/upload                                                  - Upload .deb (raw body)

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::io::{self, Read, Write};

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Extension;
use axum::Router;
use bytes::Bytes;
use flate2::read::GzDecoder;
use flate2::Compression;
use flate2::GzBuilder;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tracing::info;
use xz2::read::XzDecoder;

use crate::api::handlers::error_helpers::require_signing_key;
use crate::api::handlers::proxy_helpers::{self, RepoInfo};
use crate::api::middleware::auth::{require_auth_basic_scope, AuthExtension};
use crate::api::{SharedState, SIGNED_RELEASE_CACHE_MAX_ENTRIES};
use crate::formats::debian::{
    DebControl, DebianHandler, DebianRepositoryConfig, DEBIAN_CONFIG_KEY,
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
        .route("/:repo_key/gpg-key.asc", get(gpg_key_asc))
        // Public key endpoint (legacy)
        .route(
            "/:repo_key/dists/:distribution/gpg-key.asc",
            get(gpg_key_asc_legacy),
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
// P2 (#2460) — pre-fetch distribution/component/architecture filter gate
// ---------------------------------------------------------------------------

/// Load the operator-configured Debian proxy filter (dist/component/arch
/// allowlists) for a repository.
///
/// An *absent* config (no `debian_config` row) yields the default (empty)
/// filter, which selects everything — i.e. the pre-#2460 full-proxy behaviour
/// is preserved for repositories with no filter set (unset = allow all).
///
/// An *error* loading the filter — a database failure, or a config row that is
/// present but cannot be parsed — must NOT be silently downgraded to that
/// allow-all default (#2672). Both are returned as an `Err(Response)` (503) so
/// the request fails CLOSED: a transient DB blip or a corrupt config can no
/// longer convert a configured request filter into no filter.
#[allow(clippy::result_large_err)]
async fn load_debian_filter(
    db: &PgPool,
    repo_id: uuid::Uuid,
) -> Result<DebianRepositoryConfig, Response> {
    let value: Option<String> = sqlx::query_scalar(
        "SELECT value FROM repository_config WHERE repository_id = $1 AND key = $2",
    )
    .bind(repo_id)
    .bind(DEBIAN_CONFIG_KEY)
    .fetch_optional(db)
    .await
    .map_err(|e| {
        // Fail CLOSED on a genuine DB error rather than treating it as
        // "no filter configured" (allow all) — see #2672.
        tracing::error!(
            repo_id = %repo_id,
            error = %e,
            "failed to load Debian proxy filter; failing closed (#2672)"
        );
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Debian proxy filter temporarily unavailable",
        )
            .into_response()
    })?;

    match value.as_deref() {
        // No config row: the documented default is "empty filter = allow all".
        None => Ok(DebianRepositoryConfig::default()),
        // A config row exists but cannot be parsed: this is an *error loading*
        // the operator's intended filter, not an unset filter, so fail closed
        // rather than fall open to allow-all (#2672).
        Some(v) => serde_json::from_str::<DebianRepositoryConfig>(v).map_err(|e| {
            tracing::error!(
                repo_id = %repo_id,
                error = %e,
                "Debian proxy filter config present but unparseable; failing closed (#2672)"
            );
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Debian proxy filter configuration is invalid",
            )
                .into_response()
        }),
    }
}

/// Response returned when a request is refused by the P2 filter. A filtered-out
/// path is answered with 404 (not 403) so the proxy does not advertise which
/// distributions/components/architectures it actually mirrors.
fn debian_filter_denied(dimension: &str, value: &str) -> Response {
    tracing::debug!(
        dimension = dimension,
        value = value,
        "debian proxy request denied by #2460 filter allowlist"
    );
    (StatusCode::NOT_FOUND, "Not found").into_response()
}

/// Response for a request refused by the #2562 encoded-separator guard. Unlike
/// a filter miss (404, which hides mirror contents), an encoded path separator
/// is a malformed request regardless of what the mirror holds, so it is
/// answered with an explicit 400 that names the reason.
fn debian_encoded_separator_rejected(path: &str) -> Response {
    tracing::debug!(
        path = path,
        "debian proxy request rejected: encoded path separator (#2562)"
    );
    (
        StatusCode::BAD_REQUEST,
        "Encoded path separators (%2f/%5c) are not permitted in Debian proxy paths",
    )
        .into_response()
}

/// Detect a percent-encoded path separator (`%2f` = `/`, `%5c` = `\`) anywhere
/// in a proxy request path, at any percent-decoding layer up to a fixpoint (so
/// a singly- OR multiply-encoded separator is caught). APT never
/// percent-encodes path separators, so a hit here is always a path-confusion or
/// traversal probe rather than a legitimate request. Note this deliberately
/// does NOT flag other encoded bytes (e.g. an epoch `%3a`), which are legal in
/// Debian filenames.
fn has_encoded_path_separator(raw: &str) -> bool {
    let mut cur = raw.to_string();
    for _ in 0..8 {
        let lower = cur.to_ascii_lowercase();
        if lower.contains("%2f") || lower.contains("%5c") {
            return true;
        }
        if !cur.contains('%') {
            return false;
        }
        match urlencoding::decode(&cur) {
            Ok(decoded) => {
                let decoded = decoded.into_owned();
                if decoded == cur {
                    // A `%` that is not part of a valid escape — no separator.
                    return false;
                }
                cur = decoded;
            }
            // Invalid UTF-8 in an escape: not a decodable separator.
            Err(_) => return false,
        }
    }
    // Pathological over-encoding: treat as suspicious and let the caller decide
    // via the normal reject path below (return true so it is refused).
    true
}

/// Pre-fetch allow/deny decision for a Debian proxy request. Each dimension is
/// checked only when supplied (`Some`); an empty allowlist for a dimension
/// permits everything. Returns a 404 [`Response`] as `Err` when any supplied
/// dimension falls outside the configured allowlist. This runs BEFORE any
/// upstream fetch, so an allowed request is left byte-identical through the P1
/// integrity/passthrough path.
#[allow(clippy::result_large_err)]
fn debian_filter_decision(
    filter: &DebianRepositoryConfig,
    distribution: Option<&str>,
    component: Option<&str>,
    arch: Option<&str>,
) -> Result<(), Response> {
    if let Some(d) = distribution {
        if !filter.distribution_selected(d) {
            return Err(debian_filter_denied("distribution", d));
        }
    }
    if let Some(c) = component {
        if !filter.component_selected(c) {
            return Err(debian_filter_denied("component", c));
        }
    }
    if let Some(a) = arch {
        if !filter.arch_selected(a) {
            return Err(debian_filter_denied("architecture", a));
        }
    }
    Ok(())
}

/// Return the component of a `dists/{dist}/*` sub-path when it is
/// component-scoped (e.g. `main/i18n/Translation-en` -> `Some("main")`),
/// or `None` for dist-level files that are not under a component
/// (`Contents-amd64.gz`, `by-hash/...`, single-segment paths). Used to scope
/// the catch-all metadata proxy to the component allowlist.
fn catchall_component(dists_path: &str) -> Option<&str> {
    let mut segments = dists_path.splitn(2, '/');
    let first = segments.next()?;
    // Not component-scoped: single-segment dist-level file, the by-hash tree,
    // or dist-level Contents indices.
    if segments.next().is_none() || first == "by-hash" || first.starts_with("Contents-") {
        return None;
    }
    Some(first)
}

/// Strip a trailing index-compression suffix (`.gz`/`.xz`/`.bz2`/`.zst`/
/// `.zstd`/`.lz4`) from a metadata leaf name, so an embedded architecture can
/// be recovered from e.g. `Contents-arm64.gz`.
fn strip_index_compression_suffix(name: &str) -> &str {
    for suffix in [".gz", ".xz", ".bz2", ".zst", ".zstd", ".lz4"] {
        if let Some(base) = name.strip_suffix(suffix) {
            return base;
        }
    }
    name
}

/// Extract the architecture a catch-all `dists/{dist}/*` metadata path is
/// scoped to, if any, so the allowlist can gate it. Recognises
/// `.../binary-<arch>/...` (Packages-family), `.../Contents-[udeb-]<arch>[.comp]`
/// (Contents index), and `.../Components-<arch>.yml[.comp]` (dep11 metadata).
///
/// Architecture-independent metadata (`all`/`source`, i18n/Translation,
/// Sources, Release, by-hash, and so on) returns `None` and is never
/// arch-gated.
fn catchall_arch(dists_path: &str) -> Option<String> {
    for seg in dists_path.split('/') {
        let candidate = if let Some(rest) = seg.strip_prefix("binary-") {
            Some(rest.to_string())
        } else if let Some(rest) = seg.strip_prefix("Contents-") {
            // `Contents-amd64.gz` and `Contents-udeb-amd64.gz`: the arch is the
            // last `-`-separated token of the compression-stripped base.
            strip_index_compression_suffix(rest)
                .rsplit('-')
                .next()
                .map(|s| s.to_string())
        } else if let Some(rest) = seg.strip_prefix("Components-") {
            // dep11 `Components-<arch>.yml[.comp]`.
            rest.split('.').next().map(|s| s.to_string())
        } else {
            None
        };
        if let Some(arch) = candidate {
            if arch.is_empty() || arch == "all" || arch == "source" {
                // Architecture-independent — not gated.
                return None;
            }
            return Some(arch);
        }
    }
    None
}

/// Percent-decode `raw` repeatedly until it stops changing (a fixpoint), so a
/// single- OR multiply-encoded sequence collapses to the exact form reqwest's
/// WHATWG URL parser will resolve when it builds the upstream request. Returns
/// `None` on invalid UTF-8 or if more than a small number of decode layers are
/// required (a pathological over-encoding, refused out of caution).
fn decode_to_fixpoint(raw: &str) -> Option<String> {
    let mut cur = raw.to_string();
    for _ in 0..8 {
        if !cur.contains('%') {
            return Some(cur);
        }
        let decoded = urlencoding::decode(&cur).ok()?.into_owned();
        if decoded == cur {
            // A `%` that is not part of a valid escape — treat as a literal.
            return Some(cur);
        }
        cur = decoded;
    }
    None
}

/// The upstream base URL to gate against, or `None` for repositories the P2
/// filter does not apply to (hosted/virtual, or a remote with no upstream).
fn repo_remote_upstream(repo: &RepoInfo) -> Option<&str> {
    if repo.repo_type == RepositoryType::Remote {
        repo.upstream_url.as_deref()
    } else {
        None
    }
}

/// Resolve the exact path reqwest will fetch for `relative`, returned relative
/// to the upstream base. This is the structural defence against gate/fetch
/// divergence: rather than hand-rolling normalisation, we build the URL the
/// same way the proxy does and let the SAME WHATWG parser reqwest uses do the
/// tab/LF/CR stripping and `.`/`..` dot-segment resolution, then gate on the
/// result — so a request like `main/%2e%09%2e/contrib` (which axum decodes to a
/// literal-tab segment that reqwest reforms into `..` -> contrib) is gated on
/// the `contrib` it actually fetches.
///
/// A belt runs first: any C0 control byte (incl. tab/LF/CR) or space in the
/// (already once-decoded) request path is refused outright rather than left to
/// be silently stripped. Escapes above the base (scheme/host/port/prefix
/// change) are refused too.
#[allow(clippy::result_large_err)]
fn normalized_debian_relpath(
    base_url: &str,
    relative: &str,
    allow_encoded_separators: bool,
) -> Result<String, Response> {
    // #2562 defense-in-depth: reject an encoded path separator (%2f/%5c) before
    // it can be forwarded opaquely upstream. reqwest keeps `%2f` encoded (it is
    // NOT split into a segment), so such a request is gated as one opaque
    // segment yet a nonstandard upstream that decodes it could still traverse.
    // APT never encodes separators, so this never blocks a legitimate path.
    if !allow_encoded_separators && has_encoded_path_separator(relative) {
        return Err(debian_encoded_separator_rejected(relative));
    }
    if relative.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return Err(debian_filter_denied("path", relative));
    }
    let base = reqwest::Url::parse(base_url).map_err(|_| debian_filter_denied("path", relative))?;
    let full = format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        relative.trim_start_matches('/')
    );
    let parsed = reqwest::Url::parse(&full).map_err(|_| debian_filter_denied("path", relative))?;
    // The normalised URL must stay on the same origin as the base — a path that
    // rewrites the host/scheme/port must never slip past the filter.
    if parsed.scheme() != base.scheme()
        || parsed.host_str() != base.host_str()
        || parsed.port_or_known_default() != base.port_or_known_default()
    {
        return Err(debian_filter_denied("path", relative));
    }
    let base_prefix = base.path().trim_end_matches('/');
    let rel = parsed
        .path()
        .strip_prefix(base_prefix)
        .map(|r| r.trim_start_matches('/'))
        .filter(|r| !r.is_empty())
        .ok_or_else(|| debian_filter_denied("path", relative))?;
    Ok(rel.to_string())
}

/// Normalise a `dists/{distribution}/{raw_suffix}` request to the path reqwest
/// will fetch, returning `(distribution, suffix)` where `suffix` is everything
/// after `dists/{distribution}/`. Errors (404) on a control byte, over-encoding,
/// base escape, or a normalised path no longer rooted at `dists/`.
#[allow(clippy::result_large_err)]
fn normalized_dists_parts(
    base_url: &str,
    distribution: &str,
    raw_suffix: &str,
    allow_encoded_separators: bool,
) -> Result<(String, String), Response> {
    let relative = format!("dists/{}/{}", distribution, raw_suffix);
    let norm = normalized_debian_relpath(base_url, &relative, allow_encoded_separators)?;
    let mut it = norm.splitn(3, '/');
    match it.next() {
        Some("dists") => {}
        _ => return Err(debian_filter_denied("path", &norm)),
    }
    let dist = it.next().unwrap_or("").to_string();
    let suffix = it.next().unwrap_or("").to_string();
    if dist.is_empty() {
        return Err(debian_filter_denied("path", &norm));
    }
    Ok((dist, suffix))
}

/// Gate a `dists/...` proxy request on the reqwest-normalised path. Extracts the
/// effective distribution/component/architecture from the path that will
/// actually be fetched (not the raw axum segments), so encoded/tab/dot
/// traversal cannot split the gate from the fetch. `raw_suffix` is the part
/// after `dists/{distribution}/` (e.g. `Release`, `main/binary-amd64/Packages`).
#[allow(clippy::result_large_err)]
fn gate_debian_dists(
    filter: &DebianRepositoryConfig,
    base_url: &str,
    distribution: &str,
    raw_suffix: &str,
) -> Result<(), Response> {
    let (dist, suffix) = normalized_dists_parts(
        base_url,
        distribution,
        raw_suffix,
        filter.allow_encoded_separators,
    )?;
    debian_filter_decision(
        filter,
        Some(&dist),
        catchall_component(&suffix),
        catchall_arch(&suffix).as_deref(),
    )
}

/// Gate a `pool/{component}/{path}` proxy request on the reqwest-normalised
/// path. Gates the component, then the architecture (fail CLOSED: when an arch
/// allowlist is set but the `.deb` filename does not yield a parseable arch,
/// deny rather than skip).
#[allow(clippy::result_large_err)]
fn gate_debian_pool(
    filter: &DebianRepositoryConfig,
    base_url: &str,
    component: &str,
    path: &str,
) -> Result<(), Response> {
    let relative = format!("pool/{}/{}", component, path);
    let norm = normalized_debian_relpath(base_url, &relative, filter.allow_encoded_separators)?;
    let mut it = norm.splitn(3, '/');
    match it.next() {
        Some("pool") => {}
        _ => return Err(debian_filter_denied("path", &norm)),
    }
    let comp = it.next().unwrap_or("");
    let rest = it.next().unwrap_or("");
    if comp.is_empty() || rest.is_empty() {
        return Err(debian_filter_denied("path", &norm));
    }
    debian_filter_decision(filter, None, Some(comp), None)?;
    if !filter.architectures.is_empty() {
        let filename = rest.rsplit('/').next().unwrap_or(rest);
        let decoded = decode_to_fixpoint(filename).unwrap_or_else(|| filename.to_string());
        match parse_deb_filename(&decoded).map(|d| d.arch) {
            Some(arch) => debian_filter_decision(filter, None, None, Some(&arch))?,
            None => return Err(debian_filter_denied("architecture", filename)),
        }
    }
    Ok(())
}

/// Gate the architecture of a `by-hash` metadata request, where the arch is
/// encoded in the content HASH rather than the path (so `catchall_arch` cannot
/// see it). Cross-references the requested SHA-256 against the arch-scoped
/// entries in the already-verified signed `Release`: the by-hash content is
/// served only when its hash maps to an allowed-architecture index. Unknown
/// hashes and non-SHA-256 by-hash trees fail CLOSED under an arch allowlist.
/// A no-op when no arch allowlist is configured or the request is not by-hash.
#[allow(clippy::result_large_err)]
async fn enforce_by_hash_arch(
    proxy: &ProxyService,
    repo_id: uuid::Uuid,
    repo_key: &str,
    upstream_url: &str,
    filter: &DebianRepositoryConfig,
    distribution: &str,
    raw_suffix: &str,
) -> Result<(), Response> {
    if filter.architectures.is_empty() {
        return Ok(());
    }
    let (ndist, suffix) = normalized_dists_parts(
        upstream_url,
        distribution,
        raw_suffix,
        filter.allow_encoded_separators,
    )?;
    if !suffix.contains("by-hash/") {
        return Ok(());
    }
    // A by-hash tree under a non-SHA-256 algorithm cannot be arch-resolved from
    // the SHA-256 Release table: refuse it under an arch filter.
    let want_hash = match by_hash_sha256(&suffix) {
        Some(h) => h,
        None => return Err(debian_filter_denied("by-hash", &suffix)),
    };
    let table = match load_release_checksums(proxy, repo_id, repo_key, upstream_url, &ndist).await {
        Some(t) => t,
        None => return Err(debian_filter_denied("by-hash", want_hash)),
    };
    if by_hash_arch_allowed(&table, want_hash, filter) {
        Ok(())
    } else {
        // Either the hash maps to a denied architecture, or the signed Release
        // does not vouch for it at all — fail closed under an arch filter.
        Err(debian_filter_denied("by-hash", want_hash))
    }
}

/// Decide whether a by-hash request for `want_hash` is permitted under
/// `filter`'s architecture allowlist, by cross-referencing the requested
/// SHA-256 against the signed-Release checksum table (`path -> (hash, size)`).
/// Returns `true` only when the hash is vouched for by the Release AND every
/// index path it maps to is an allowed (or architecture-independent) arch;
/// `false` for a denied arch or an unknown hash (fail closed).
fn by_hash_arch_allowed(
    table: &HashMap<String, (String, u64)>,
    want_hash: &str,
    filter: &DebianRepositoryConfig,
) -> bool {
    let mut matched = false;
    for (path, (hash, _size)) in table {
        if hash.eq_ignore_ascii_case(want_hash) {
            matched = true;
            if let Some(arch) = catchall_arch(path) {
                if !filter.arch_selected(&arch) {
                    return false;
                }
            }
        }
    }
    matched
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

/// Parse `{name}_{version}_{arch}.deb`, `.udeb`, or `.ddeb` from a filename.
fn parse_deb_filename(filename: &str) -> Option<DebInfo> {
    let package_type = if filename.ends_with(".udeb") {
        "udeb"
    } else if filename.ends_with(".ddeb") {
        "ddeb"
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
    let normalized = normalize_newlines(value);
    let mut lines = normalized.lines();
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
    .map_err(crate::api::handlers::db_err)?;

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

/// Default values for Debian/APT Release Origin and Label fields.
const DEFAULT_APT_ORIGIN: &str = "artifact-keeper";
const DEFAULT_APT_LABEL: &str = "artifact-keeper";

/// Returns `true` when `s` contains any line-ending character
/// (`\n`, `\r\n`, or bare `\r`).
fn contains_newline(s: &str) -> bool {
    s.contains('\n') || s.contains('\r')
}

/// Normalize `\r\n` and bare `\r` to plain `\n` so that
/// `.lines()` and friends operate on a single canonical form.
fn normalize_newlines(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push('\n');
            }
            other => out.push(other),
        }
    }
    out
}

/// Format a multi-line description string according to the deb822
/// continuation convention: the first line carries no leading
/// space; every subsequent non-empty line is trimmed and prefixed with
/// a single space; empty lines are rendered as a bare ` .` (space-dot).
///
/// Example input:
///   "Cross-binutils for Win32\n\nMinGW-w64 provides a runtime\n\nLast line"
///
/// Example output:
///   "Cross-binutils for Win32\n .\n MinGW-w64 provides a runtime\n .\n Last line"
fn format_deb822_description(desc: &str) -> String {
    let normalized = normalize_newlines(desc);
    let mut out = String::with_capacity(normalized.len());
    let mut lines = normalized.lines();
    if let Some(first) = lines.next() {
        out.push_str(first.trim());
    }
    for line in lines {
        out.push('\n');
        let trimmed = line.trim();
        if trimmed.is_empty() {
            out.push_str(" .");
        } else {
            out.push(' ');
            out.push_str(trimmed);
        }
    }
    out
}

/// Read per-repository APT release metadata overrides from
/// `repository_config`. `apt_origin` and `apt_label` fall back to
/// defaults (`DEFAULT_APT_ORIGIN` / `DEFAULT_APT_LABEL`) when unset.
/// `apt_release_version` and `apt_description` are returned as
/// `Option<String>` — `None` when unset or empty, meaning the caller
/// omits those lines from the Release file.
///
/// Errors propagate for the same reason they do in `release_publish_timestamp`:
/// these values are rendered into the signed document, so falling back to the
/// defaults on a transient DB fault would flip `Origin:`/`Label:` between the
/// `Release` and `Release.gpg` renders and break the detached signature.
async fn fetch_apt_release_metadata(
    db: &PgPool,
    repo_id: uuid::Uuid,
) -> Result<(String, String, Option<String>, Option<String>), Response> {
    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT key, value FROM repository_config \
         WHERE repository_id = $1 \
           AND key IN ('apt_origin', 'apt_label', 'apt_release_version', 'apt_description')",
    )
    .bind(repo_id)
    .fetch_all(db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    let mut origin: Option<String> = None;
    let mut label: Option<String> = None;
    let mut release_version: Option<String> = None;
    let mut description: Option<String> = None;

    for (key, value) in &rows {
        let raw = value.as_deref().unwrap_or("");
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        match key.as_str() {
            "apt_origin" | "apt_label" | "apt_release_version" => {
                let single_line = take_first_line(trimmed);
                if contains_newline(trimmed) {
                    tracing::warn!(
                        repo_id = %repo_id,
                        key = %key,
                        "{} is multi-line; only the first line will be used",
                        key
                    );
                }
                match key.as_str() {
                    "apt_origin" => origin = Some(single_line),
                    "apt_label" => label = Some(single_line),
                    "apt_release_version" => release_version = Some(single_line),
                    _ => unreachable!(),
                }
            }
            "apt_description" => {
                if contains_newline(trimmed) {
                    tracing::warn!(
                        repo_id = %repo_id,
                        "apt_description is multi-line; will be formatted per deb822"
                    );
                }
                description = Some(trimmed.to_string());
            }
            _ => {}
        }
    }

    Ok((
        origin.unwrap_or_else(|| DEFAULT_APT_ORIGIN.to_string()),
        label.unwrap_or_else(|| DEFAULT_APT_LABEL.to_string()),
        release_version,
        description,
    ))
}

/// Return the first line of `s` (up to but not including the first
/// newline of any style).
fn take_first_line(s: &str) -> String {
    // Normalize \r\n and bare \r to \n so `.lines()` splits correctly.
    let normalized = normalize_newlines(s);
    normalized
        .lines()
        .next()
        .unwrap_or(&normalized)
        .trim()
        .to_string()
}

/// Resolve the `Date:` stamped into a generated `Release`.
///
/// This MUST be a pure function of repository state and MUST NOT read the wall
/// clock. `Release` and `Release.gpg` are rendered by two *independent*
/// requests, and the detached signature only verifies if both renders produce
/// byte-identical documents. A `Utc::now()` here made the document depend on
/// the second in which each request happened to land, so an untampered repo
/// served a `Release` whose bytes differed from the bytes `Release.gpg` had
/// signed whenever the two fetches straddled a second boundary — `apt-secure`
/// then reports `BAD signature` on an honest repo.
///
/// The publish timestamp is the newest mutation of the repository's artifacts
/// (`created_at`/`updated_at`, deleted rows included), falling back to the
/// repository's own `created_at` for an empty repo. It is identical for every
/// reader of a given repository state, including separate backend replicas.
///
/// Counting deleted rows is deliberate: it keeps the stamp monotonic. Filtering
/// them out would move `Date:` *backward* when the newest artifact is removed —
/// and apt clients holding a newer cached `Date:` do not reject a backward
/// step, they silently keep the cached metadata and `apt-get update` exits 0
/// with no diagnostics (see `release_date_floor` for the measured mechanism),
/// so the repo would freeze for existing clients with nothing alerting anyone.
/// It does not follow that every content
/// change moves the stamp forward — only writers that stamp `updated_at` do.
/// `ArtifactService::delete_artifact` does; the retention/lifecycle sweeps in
/// `lifecycle_service` and the Conan overwrite-supersede path do not, so those
/// deletions change the index without advancing `Date:`. That is a fidelity gap
/// in what `Date:` reports, not a signature hazard: both renders of a given
/// state still agree, which is the invariant this function exists to hold.
///
/// The state stamp is floored at [`release_date_floor`] (the binary's build
/// timestamp). Without the floor, deploying the state-derived `Date:` would
/// step it *backward* exactly once on every pre-existing repo — from the last
/// `Utc::now()` a pre-fix build served to the last repo mutation — and every
/// apt client that had already cached the newer value would silently pin to
/// its pre-deploy metadata (see [`release_date_floor`]).
///
/// Errors propagate. A failed read here must fail the request, not fall back to
/// a default: `Release` and `Release.gpg` are separate requests, so a transient
/// DB fault on one of them would otherwise stamp a different `Date:` than the
/// other and produce a detached signature over bytes the client never received
/// — reintroducing the `BAD signature` this function exists to prevent, and
/// doing so under load, exactly when the inter-request gap is widest.
async fn release_publish_timestamp(
    db: &PgPool,
    repo_id: uuid::Uuid,
) -> Result<chrono::DateTime<chrono::Utc>, Response> {
    let stamp: Option<(Option<chrono::DateTime<chrono::Utc>>,)> = sqlx::query_as(
        r#"
        SELECT GREATEST(
                 (SELECT MAX(GREATEST(a.created_at, a.updated_at))
                    FROM artifacts a
                   WHERE a.repository_id = $1),
                 (SELECT r.created_at FROM repositories r WHERE r.id = $1)
               )
        "#,
    )
    .bind(repo_id)
    .fetch_optional(db)
    .await
    .map_err(crate::api::handlers::db_err)?;

    // `repositories.created_at` is NOT NULL and the row was resolved earlier in
    // this request, so a NULL here means the repository was deleted mid-render.
    // Fail rather than stamp a placeholder: a placeholder would differ from the
    // sibling request that still saw the repo.
    stamp
        .and_then(|(t,)| t)
        .map(|t| t.max(release_date_floor()))
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                "Repository no longer exists".to_string(),
            )
                .into_response()
        })
}

/// Monotonic floor for the `Release` `Date:` field: the moment this binary was
/// built (`RELEASE_DATE_FLOOR_EPOCH`, baked by `build.rs`; honors
/// `SOURCE_DATE_EPOCH` so reproducible builds stay reproducible).
///
/// Why a floor exists: [`release_publish_timestamp`] replaced a `Utc::now()`
/// stamp with a state-derived one, so at deploy every pre-existing repo steps
/// `Date:` backward exactly once — from "the last time a client fetched
/// `Release`" to "the last time anything changed", potentially months on a
/// quiescent repo. apt does not reject a backward `Date:` and does not warn:
/// `pkgAcqMetaBase::VerifyVendor` (apt-pkg/acquire-item.cc; verified identical
/// in apt 2.2.4, 2.6.1 and 2.8.3, detached `Release`+`Release.gpg` and
/// `InRelease` alike) converts it into a fake If-Modified-Since hit, discards
/// the downloaded metadata, keeps the client's cached set, and `apt-get
/// update` exits 0 with zero diagnostics. No configuration option controls
/// that path (`Acquire::Check-Date=false` does not unlock it — that option
/// governs the separate *future*-Date check). Every existing client would
/// therefore silently freeze on pre-deploy metadata until `Date:` climbs past
/// its cached value — indefinitely on a quiescent repo. Flooring the stamp at
/// the build timestamp keeps the first post-deploy render at least as new as
/// any wall-clock `Date:` the previous build served before this build existed.
///
/// Why the *build* timestamp specifically: the floor must be (a) at least the
/// last `Utc::now()` a pre-fix build served, (b) identical across replicas —
/// every replica runs the same image, so a compile-time constant is — and
/// (c) stable across process restarts. A process-start time fails (b) and (c):
/// replicas start at different moments, so the same repository state would
/// render different bytes on different replicas and the detached-signature
/// invariant this file exists to hold would break again.
fn release_date_floor() -> chrono::DateTime<chrono::Utc> {
    // Compile-time constant; build.rs validates it parses, but degrade to
    // "no floor" (epoch 0) rather than panic inside a request handler.
    env!("RELEASE_DATE_FLOOR_EPOCH")
        .parse::<i64>()
        .ok()
        .and_then(|secs| chrono::DateTime::from_timestamp(secs, 0))
        .unwrap_or(chrono::DateTime::<chrono::Utc>::UNIX_EPOCH)
}

/// Render the `Date:` field value. Split out so the exact wire format is
/// pinned by a unit test.
fn format_release_date(published_at: chrono::DateTime<chrono::Utc>) -> String {
    published_at.format("%a, %d %b %Y %H:%M:%S UTC").to_string()
}

/// Everything the `Release` document is rendered from. Constructing this is the
/// only place repository state is read; `render_release_document` is then a
/// pure function of it, so the same repository state always renders the same
/// bytes no matter which request (or which replica) does the rendering.
struct ReleaseRenderInput<'a> {
    origin: &'a str,
    label: &'a str,
    distribution: &'a str,
    version: Option<&'a str>,
    description: Option<&'a str>,
    published_at: chrono::DateTime<chrono::Utc>,
    architectures: &'a str,
    components: &'a str,
    /// `(path, bytes)` for every index file the hash sections cover.
    files: &'a [(String, Vec<u8>)],
}

/// Render the Debian `Release` document. Pure: identical input renders
/// byte-identical output, which is what makes the detached `Release.gpg`
/// signature verify against the separately-rendered `Release`.
fn render_release_document(input: &ReleaseRenderInput<'_>) -> String {
    let mut release = String::new();
    release.push_str(&format!("Origin: {}\n", input.origin));
    release.push_str(&format!("Label: {}\n", input.label));
    release.push_str(&format!("Suite: {}\n", input.distribution));
    release.push_str(&format!("Codename: {}\n", input.distribution));
    if let Some(ver) = input.version {
        release.push_str(&format!("Version: {}\n", ver));
    }
    if let Some(desc) = input.description {
        release.push_str("Description: ");
        release.push_str(&format_deb822_description(desc));
        release.push('\n');
    }
    release.push_str(&format!(
        "Date: {}\n",
        format_release_date(input.published_at)
    ));
    release.push_str(&format!("Architectures: {}\n", input.architectures));
    release.push_str(&format!("Components: {}\n", input.components));
    push_release_hash_section(&mut release, "MD5Sum", input.files, |bytes| {
        ArtifactService::calculate_md5(bytes)
    });
    push_release_hash_section(&mut release, "SHA1", input.files, |bytes| {
        ArtifactService::calculate_sha1(bytes)
    });
    push_release_hash_section(&mut release, "SHA256", input.files, |bytes| {
        ArtifactService::calculate_sha256(bytes)
    });
    release
}

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

    // Derived from repository state, never from the wall clock: see
    // `release_publish_timestamp`. Both reads propagate their errors so a
    // transient DB fault fails this request instead of silently rendering a
    // document that differs from the sibling `Release`/`Release.gpg` render.
    let published_at = release_publish_timestamp(&state.db, repo_id).await?;

    let (origin, label, version, description) =
        fetch_apt_release_metadata(&state.db, repo_id).await?;

    Ok(render_release_document(&ReleaseRenderInput {
        origin: &origin,
        label: &label,
        distribution,
        version: version.as_deref(),
        description: description.as_deref(),
        published_at,
        architectures: &arch_str,
        components: &component_str,
        files: &release_files,
    }))
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
        let upstream_path = format!("dists/{}/{}", self.distribution, suffix);

        // Epoch-based lazy invalidation: if the cached file is older
        // than the release epoch, invalidate it so the streaming fetch
        // treats it as a cache miss and re-fetches from upstream.
        maybe_invalidate_by_epoch(proxy, self.repo_key, self.distribution, &upstream_path).await;

        // Use a Debian-format repo so the cache TTL classifier sees the
        // real format: by-hash paths classify as Immutable (10-year TTL),
        // while ordinary dists/ index files stay Mutable (5-min TTL).
        // The generic proxy_fetch_capped helper defaults to Generic,
        // which treats every path as mutable.
        let proxy_repo = proxy_helpers::build_remote_repo_with_format(
            repo.id,
            self.repo_key,
            upstream_url,
            RepositoryFormat::Debian,
        );
        let (content, upstream_ct) = proxy
            .fetch_artifact_capped(
                &proxy_repo,
                &upstream_path,
                proxy_helpers::LARGE_METADATA_MAX_BYTES,
            )
            .await
            .map_err(map_proxy_err)?;
        // #2459 Tier A: reject an index the signed Release does not vouch for.
        enforce_dists_integrity(
            proxy,
            repo.id,
            self.repo_key,
            upstream_url,
            self.distribution,
            &upstream_path,
            suffix,
            &content,
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
        let upstream_path = format!("dists/{}/{}", self.distribution, suffix);

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
// Remote-proxy integrity verification (#2459)
//
// Tier A (mandatory): every dists index proxied from a Remote upstream is
// checked against the checksum table of the repo's signed Release/InRelease
// before it is served or persisted. A mismatch means the upstream (or a MITM)
// answered a signed-Release-covered path with content the signature does not
// vouch for, so the fetch is rejected with 502 and the poisoned cache entry
// is evicted.
//
// Tier B (best-effort): a pool `.deb` download is gated on the SHA-256 the
// cached Packages index records for its `Filename`, so a mismatching body is
// still streamed to the client (which verifies it itself) but never written
// to the proxy cache. Both tiers apply to `repo_type == Remote` only.
// ---------------------------------------------------------------------------

/// Outcome of checking a proxied dists index against the signed Release.
#[derive(Debug, PartialEq, Eq)]
enum IndexVerification {
    /// The path is covered by the signed Release (or is a by-hash path) and
    /// the fetched content matched.
    Verified,
    /// The signed Release does not cover this path; nothing to enforce.
    NotCovered,
    /// The content did not match the signed Release entry (or by-hash digest).
    Mismatch,
}

/// If `path` is a `by-hash/SHA256/<hex>` index variant, return the embedded
/// digest. Such paths are content-addressed, so the digest in the path is the
/// integrity claim apt selected from the (already-verified) signed Release.
fn by_hash_sha256(path: &str) -> Option<&str> {
    let idx = path.find("by-hash/SHA256/")?;
    let tail = &path[idx + "by-hash/SHA256/".len()..];
    let hex = tail.split('/').next()?;
    if hex.is_empty() {
        None
    } else {
        Some(hex)
    }
}

/// Verify a fetched dists index (`dist_relative_path`, relative to
/// `dists/{distribution}/`) against the signed Release checksum table. Pure so
/// the match / sha-mismatch / size-mismatch / by-hash / not-covered branches
/// are unit-testable without a runtime or storage.
fn verify_index_against_release(
    release_checksums: &HashMap<String, (String, u64)>,
    dist_relative_path: &str,
    content: &[u8],
) -> IndexVerification {
    let actual_sha = hex::encode(Sha256::digest(content));
    let actual_size = content.len() as u64;

    if let Some(expected) = by_hash_sha256(dist_relative_path) {
        return if actual_sha.eq_ignore_ascii_case(expected) {
            IndexVerification::Verified
        } else {
            IndexVerification::Mismatch
        };
    }

    match release_checksums.get(dist_relative_path) {
        Some((sha, size)) => {
            if actual_sha.eq_ignore_ascii_case(sha) && actual_size == *size {
                IndexVerification::Verified
            } else {
                IndexVerification::Mismatch
            }
        }
        None => IndexVerification::NotCovered,
    }
}

/// Load and parse the SHA256 checksum table from the repo's signed Release,
/// preferring `InRelease` and falling back to `Release`. Best-effort: returns
/// `None` when neither can be loaded or neither carries a SHA256 section (in
/// which case the caller serves the fetch unchanged, mirroring apt, which
/// itself refuses unsigned indices downstream).
async fn load_release_checksums(
    proxy: &ProxyService,
    repo_id: uuid::Uuid,
    repo_key: &str,
    upstream_url: &str,
    distribution: &str,
) -> Option<HashMap<String, (String, u64)>> {
    let pseudo_repo = proxy_helpers::build_remote_repo(repo_id, repo_key, upstream_url);
    for name in ["InRelease", "Release"] {
        let path = format!("dists/{}/{}", distribution, name);
        if let Ok((bytes, _ct, _changed)) = proxy
            .fetch_dists_with_revalidation(
                &pseudo_repo,
                &path,
                distribution,
                DEFAULT_DISTS_INDEX_TTL_SECS,
            )
            .await
        {
            let text = String::from_utf8_lossy(&bytes);
            let table = crate::formats::debian::parse_release_checksums(&text);
            if !table.is_empty() {
                return Some(table);
            }
        }
    }
    None
}

/// Tier A guard: verify a freshly-proxied dists index against the signed
/// Release and, on a checksum/size mismatch, evict the just-written cache
/// entry and return a 502. `dist_relative_path` is the tail of `upstream_path`
/// beneath `dists/{distribution}/`.
#[allow(clippy::too_many_arguments)]
async fn enforce_dists_integrity(
    proxy: &ProxyService,
    repo_id: uuid::Uuid,
    repo_key: &str,
    upstream_url: &str,
    distribution: &str,
    upstream_path: &str,
    dist_relative_path: &str,
    content: &[u8],
) -> Result<(), Response> {
    let Some(table) =
        load_release_checksums(proxy, repo_id, repo_key, upstream_url, distribution).await
    else {
        return Ok(());
    };
    if verify_index_against_release(&table, dist_relative_path, content)
        == IndexVerification::Mismatch
    {
        // Evict the poisoned entry so a later read cannot serve it.
        let _ = proxy.invalidate_cache_by_key(repo_key, upstream_path).await;
        return Err((
            StatusCode::BAD_GATEWAY,
            "Upstream index failed integrity verification against the signed Release",
        )
            .into_response());
    }
    Ok(())
}

/// Resolve the expected SHA-256 for a pool artifact from a parsed Packages
/// `Filename` -> (sha, size) map. The Packages `Filename` field carries the
/// full pool-relative path, so a direct lookup suffices. Pure (map lookup).
fn resolve_pool_deb_checksum(
    packages: &HashMap<String, (String, u64)>,
    artifact_path: &str,
) -> Option<String> {
    packages.get(artifact_path).map(|(sha, _)| sha.clone())
}

/// True when `cache_path` names a cached Packages index for `component` and
/// `arch` (any distribution / compression). Pure so the shape match is
/// unit-testable. Used to narrow the cached-index scan at pool download time.
fn is_matching_packages_index(cache_path: &str, component: &str, arch: &str) -> bool {
    if !cache_path.starts_with("dists/") {
        return false;
    }
    let needle = format!("/{}/binary-{}/Packages", component, arch);
    if !cache_path.contains(&needle) {
        return false;
    }
    let leaf = cache_path.rsplit('/').next().unwrap_or("");
    matches!(leaf, "Packages" | "Packages.gz" | "Packages.xz")
}

/// Ceiling on the *decompressed* size of a cached Packages index we will
/// expand while resolving a pool `.deb`'s expected checksum (#2459 Tier B DoS
/// guard). A signed Release can vouch for a small compressed index that passes
/// Tier A (checksum + size ≤ the metadata cap) yet expands unbounded (>100x →
/// multi-GiB) — capping the decode bounds worst-case memory. A stream that
/// would exceed this is treated as "unresolvable" (returns `None`) so the pool
/// download falls back to the Content-Length-gated cache commit; Tier B is
/// best-effort and must never hard-fail the download.
const MAX_DECOMPRESSED_INDEX_BYTES: u64 = 128 * 1024 * 1024;

/// Skip decompressing a cached *compressed* index whose body is already this
/// large. A legitimately-published Packages index compresses far smaller
/// (tens of MiB for the largest suites), so this bounds the work before the
/// decoder even starts and cheaply rejects an oversized bomb payload.
const MAX_COMPRESSED_INDEX_BYTES: usize = 32 * 1024 * 1024;

/// Decompress a cached Packages index body into text based on the cache
/// path's extension (`.gz` / `.xz` / plain). Returns `None` on a decode error
/// or when the input would exceed the decompression-bomb caps
/// ([`MAX_COMPRESSED_INDEX_BYTES`] / [`MAX_DECOMPRESSED_INDEX_BYTES`]).
fn decompress_packages_index(cache_path: &str, bytes: &[u8]) -> Option<String> {
    let compressed = cache_path.ends_with(".gz") || cache_path.ends_with(".xz");
    if compressed && bytes.len() > MAX_COMPRESSED_INDEX_BYTES {
        return None;
    }
    if cache_path.ends_with(".gz") {
        read_index_capped(GzDecoder::new(bytes))
    } else if cache_path.ends_with(".xz") {
        read_index_capped(XzDecoder::new(bytes))
    } else {
        Some(String::from_utf8_lossy(bytes).into_owned())
    }
}

/// Read a decoder to completion, bounded at [`MAX_DECOMPRESSED_INDEX_BYTES`].
/// Returns `None` on a decode error OR when the decompressed stream would
/// exceed the cap (a decompression bomb), so the caller treats the index as
/// unresolvable rather than expanding it into memory unbounded.
fn read_index_capped<R: Read>(reader: R) -> Option<String> {
    // Read one byte past the cap so a stream that exactly fills it but carries
    // more data is still detected as over-limit.
    let mut buf = Vec::new();
    reader
        .take(MAX_DECOMPRESSED_INDEX_BYTES + 1)
        .read_to_end(&mut buf)
        .ok()?;
    if buf.len() as u64 > MAX_DECOMPRESSED_INDEX_BYTES {
        return None;
    }
    String::from_utf8(buf).ok()
}

/// Tier B resolver: find the SHA-256 the cached Packages index records for a
/// pool artifact, so the streamed `.deb` download can gate its cache commit on
/// it. Best-effort: `Ok(None)` when no cached Packages index covers the file
/// (which leaves the download's cache behaviour unchanged from before #2459).
/// `Err` only when the server is saturated with concurrent ingestion decodes
/// (#2561), which sheds the request with a retryable 503 before any upstream
/// fetch or cache write — the resolve fails cleanly, no partial state.
async fn resolve_pool_expected_checksum(
    proxy: &ProxyService,
    repo_key: &str,
    component: &str,
    artifact_path: &str,
) -> crate::error::Result<Option<String>> {
    let Some(filename) = artifact_path.rsplit('/').next() else {
        return Ok(None);
    };
    let Ok((_, _, arch)) = DebianHandler::parse_deb_filename(filename) else {
        return Ok(None);
    };
    for cache_path in proxy.list_cached_paths(repo_key).await {
        if !is_matching_packages_index(&cache_path, component, &arch) {
            continue;
        }
        let Ok(Some((bytes, _))) = proxy
            .get_cached_artifact_by_path(repo_key, &cache_path)
            .await
        else {
            continue;
        };
        // #2561: permit-scoped decode on this serve path (each cached index
        // inflates up to the 128 MiB budget), fast-fail 503 on saturation; the
        // permit is released before the next cache read.
        let Some(text) = crate::util::bounded_archive::with_ingest_extraction(|| {
            decompress_packages_index(&cache_path, &bytes)
        })?
        else {
            continue;
        };
        let map = crate::formats::debian::parse_packages_index(&text);
        if let Some(sha) = resolve_pool_deb_checksum(&map, artifact_path) {
            return Ok(Some(sha));
        }
    }
    Ok(None)
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
///
/// The 404-vs-500 decision itself lives in `error_helpers::require_signing_key`
/// so RPM's repomd.xml.asc resolves its key identically (#2636).
async fn require_active_signing_key(
    signing_svc: &SigningService,
    repo_id: uuid::Uuid,
) -> Result<SigningKey, Response> {
    require_signing_key(signing_svc.get_active_key_for_repo(repo_id).await)
}

/// Apply a Virtual repo member's own P2 dist/component/architecture filter to
/// the requested `dists/` path, exactly as if the request had been served
/// directly from that Remote member (#2727).
///
/// The direct-fetch gate (`load_debian_filter` + `gate_debian_dists`) lives
/// behind `repo_remote_upstream`, which is `None` for a Virtual repo (a virtual
/// repo has no upstream of its own; the upstream lives on its MEMBERS). Before
/// this check the virtual paths enumerated their Remote members and fetched from
/// each WITHOUT consulting that member's allowlist, letting a client pull a
/// filtered-out distribution/component/architecture through the virtual repo.
///
/// Fail-closed for the member: an error loading the member's filter (DB error or
/// unparseable config, per #2672/#2725) OR an allowlist that excludes the
/// requested dist/component/arch (including the by-hash arch cross-check) marks
/// the member as DENY, so the caller skips it. Skipping affects only that
/// member: sibling members whose filter allows the path still aggregate
/// normally, and a member's filter-load error never fails the whole virtual
/// request open (skip-that-member is the safer default per #2727).
async fn virtual_member_dists_allowed(
    state: &SharedState,
    proxy: &ProxyService,
    member: &crate::models::repository::Repository,
    upstream_url: &str,
    distribution: &str,
    dists_suffix: &str,
) -> bool {
    let filter = match load_debian_filter(&state.db, member.id).await {
        Ok(f) => f,
        // Fail closed for THIS member (do not fall open to allow-all, and do not
        // 503 the whole virtual request over one member's config blip).
        Err(_) => return false,
    };
    if gate_debian_dists(&filter, upstream_url, distribution, dists_suffix).is_err() {
        return false;
    }
    // Cross-check the by-hash arch (arch encoded in the content hash, not the
    // path) against the member's signed Release, mirroring the direct catch-all.
    enforce_by_hash_arch(
        proxy,
        member.id,
        &member.key,
        upstream_url,
        &filter,
        distribution,
        dists_suffix,
    )
    .await
    .is_ok()
}

/// Iterate the virtual repo's Remote members for `upstream_path` and
/// return the first successful response. Checks the release epoch for
/// lazy invalidation before attempting the streaming fetch.
///
/// Error propagation:
///   * `404 / NotFound` — the member genuinely doesn't have this file;
///     continue to the next member.
///   * Non-404 (502 cap-exceeded, 503 upstream-down, etc.) — record the
///     first occurrence but **continue** to the next member so a
///     transient failure on a higher-priority mirror doesn't block a
///     healthy lower-priority one. If all members fail, the first
///     non-404 error is returned so the client sees the real cause. If
///     every member returned 404, `Ok(None)` lets the caller fall through
///     to the local-DB path (hosted repos).
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
    // The path after `dists/{distribution}/`, used to gate each member's filter
    // (component/arch are derived from it). All callers build `upstream_path`
    // as `dists/{distribution}/{suffix}`; a path not of that shape has nothing
    // to serve here.
    let Some(dists_suffix) = upstream_path.strip_prefix(&format!("dists/{distribution}/")) else {
        return Ok(None);
    };
    let mut first_err: Option<Response> = None;
    for member in &members {
        let Some(upstream_url) = remote_member_upstream(member) else {
            continue;
        };

        // #2727: honor THIS member's own dist/component/arch allowlist before
        // serving its content through the virtual repo. A member whose filter
        // excludes the requested path (or whose filter cannot be loaded) is
        // skipped — treated as deny — so a filtered-out dist/component/arch
        // cannot be pulled via the virtual repo, while members that allow it
        // still aggregate.
        if !virtual_member_dists_allowed(
            state,
            proxy,
            member,
            upstream_url,
            distribution,
            dists_suffix,
        )
        .await
        {
            continue;
        }

        // Epoch-based lazy invalidation for this member's cache entry
        maybe_invalidate_by_epoch(proxy, &member.key, distribution, upstream_path).await;

        // Use a Debian-format repo so the cache TTL classifier sees the
        // real format: by-hash paths classify as Immutable (10-year TTL),
        // while ordinary dists/ index files stay Mutable (5-min TTL).
        let proxy_repo = proxy_helpers::build_remote_repo_with_format(
            member.id,
            &member.key,
            upstream_url,
            RepositoryFormat::Debian,
        );
        match proxy
            .fetch_artifact_capped(
                &proxy_repo,
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
///
/// Error propagation mirrors [`try_virtual_dists`]:
///   * `NotFound` (404) — continue to the next member.
///   * Non-404 — record the first occurrence but continue; return it
///     only if no member succeeds. This preserves multi-mirror failover
///     while still surfacing real failures (502, 503, etc.) instead of
///     silently falling through to an empty local DB.
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
    // The path after `dists/{distribution}/`, used to gate each member's filter.
    let Some(dists_suffix) = upstream_path.strip_prefix(&format!("dists/{distribution}/")) else {
        return Ok(None);
    };
    let mut first_err: Option<Response> = None;
    for member in &members {
        let Some(upstream_url) = remote_member_upstream(member) else {
            continue;
        };

        // #2727: honor THIS member's own dist/component/arch allowlist before
        // revalidating/serving its Release/InRelease content through the virtual
        // repo. A member that excludes the requested dist (or whose filter fails
        // to load) is skipped — treated as deny.
        if !virtual_member_dists_allowed(
            state,
            proxy,
            member,
            upstream_url,
            distribution,
            dists_suffix,
        )
        .await
        {
            continue;
        }

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
    // #2460 P2: deny a distribution outside the operator allowlist before any
    // upstream fetch, gating on the reqwest-normalised path. An allowed
    // distribution passes through unchanged so the P1 signed-Release integrity
    // path stays byte-identical.
    if let Some(base) = repo_remote_upstream(&repo) {
        let filter = load_debian_filter(&state.db, repo.id).await?;
        gate_debian_dists(&filter, base, &distribution, "Release")?;
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
    // #2460 P2: deny a distribution outside the operator allowlist (pre-fetch),
    // gating on the reqwest-normalised path.
    if let Some(base) = repo_remote_upstream(&repo) {
        let filter = load_debian_filter(&state.db, repo.id).await?;
        gate_debian_dists(&filter, base, &distribution, "InRelease")?;
    }
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
    // #2460 P2: deny a distribution outside the operator allowlist (pre-fetch),
    // gating on the reqwest-normalised path.
    if let Some(base) = repo_remote_upstream(&repo) {
        let filter = load_debian_filter(&state.db, repo.id).await?;
        gate_debian_dists(&filter, base, &distribution, "Release.gpg")?;
    }
    // Release.gpg is the detached signature of Release. We do not need
    // revalidation here because the matching Release fetch (called
    // by apt before Release.gpg) already drove epoch invalidation.
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
// GET /debian/{repo_key}/gpg-key.asc
// ---------------------------------------------------------------------------

async fn gpg_key_asc(
    State(state): State<SharedState>,
    Path(repo_key): Path<String>,
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
// GET /debian/{repo_key}/dists/{distribution}/gpg-key.asc
// ---------------------------------------------------------------------------

async fn gpg_key_asc_legacy(
    state: State<SharedState>,
    Path((repo_key, _distribution)): Path<(String, String)>,
) -> Result<Response, Response> {
    gpg_key_asc(state, Path(repo_key)).await
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
        // #2460 P2: gate the Packages index on the reqwest-normalised path so a
        // dist/component/arch escape cannot split the gate from the fetch. An
        // empty filter (default) permits everything. Non-Packages shapes fall
        // through to the catch-all, which applies the same normalised gate.
        let repo = resolve_debian_repo(&state.0.db, &repo_key).await?;
        if let Some(base) = repo_remote_upstream(&repo) {
            let filter = load_debian_filter(&state.0.db, repo.id).await?;
            gate_debian_dists(&filter, base, &distribution, &dists_path)?;
        }

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

    // #2460 P2: pre-fetch allowlist gate for catch-all dists metadata
    // (i18n/Translation, Sources, dep11, Contents, ...), gating on the exact
    // reqwest-normalised path. Gates the distribution, the component when the
    // path is component-scoped, and the architecture when the metadata is
    // arch-scoped (Contents-<arch>, dep11 Components-<arch>, binary-<arch>).
    // by-hash requests carry the arch in the content hash, not the path, so a
    // second pass cross-references the requested SHA-256 against the signed
    // Release. An empty filter permits everything.
    if let Some(base) = repo_remote_upstream(&repo) {
        let filter = load_debian_filter(&state.db, repo.id).await?;
        gate_debian_dists(&filter, base, &distribution, &dists_path)?;
        if let Some(proxy) = state.proxy_service.as_deref() {
            enforce_by_hash_arch(
                proxy,
                repo.id,
                &repo_key,
                base,
                &filter,
                &distribution,
                &dists_path,
            )
            .await?;
        }
    }

    let upstream_path = format!("dists/{}/{}", distribution, dists_path);

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
        return Err((StatusCode::NOT_FOUND, "Not found").into_response());
    }

    let (upstream_url, proxy) = match (&repo.upstream_url, &state.proxy_service) {
        (Some(u), Some(p)) => (u, p),
        _ => return Err((StatusCode::NOT_FOUND, "Not found").into_response()),
    };

    // Epoch-based lazy invalidation for mutable dists/ paths.
    // Immutable paths (by-hash) are skipped by maybe_invalidate_by_epoch.
    maybe_invalidate_by_epoch(proxy, &repo_key, &distribution, &upstream_path).await;

    // Use a Debian-format repo so the cache TTL classifier sees the real
    // format: by-hash paths under dists/ classify as Immutable (10-year
    // TTL), while ordinary dists/ index files (Packages, Sources,
    // Translation, etc.) stay Mutable (5-min TTL).
    let proxy_repo = proxy_helpers::build_remote_repo_with_format(
        repo.id,
        &repo_key,
        upstream_url,
        RepositoryFormat::Debian,
    );
    let (content, upstream_ct) = proxy
        .fetch_artifact_capped(
            &proxy_repo,
            &upstream_path,
            proxy_helpers::LARGE_METADATA_MAX_BYTES,
        )
        .await
        .map_err(map_proxy_err)?;
    // #2459 Tier A: reject an index the signed Release does not vouch for.
    enforce_dists_integrity(
        proxy,
        repo.id,
        &repo_key,
        upstream_url,
        &distribution,
        &upstream_path,
        &dists_path,
        &content,
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

// ---------------------------------------------------------------------------
// GET /debian/{repo_key}/pool/{component}/*path -- Download .deb
// ---------------------------------------------------------------------------

async fn pool_download(
    State(state): State<SharedState>,
    Path((repo_key, component, path)): Path<(String, String, String)>,
    ctx: crate::api::middleware::download_telemetry::DownloadContext,
) -> Result<Response, Response> {
    let repo = resolve_debian_repo(&state.db, &repo_key).await?;

    // #2460 P2: pre-fetch allowlist gate for pool downloads, gating on the
    // reqwest-normalised path. Gates the component and the architecture (derived
    // from the `.deb` filename, fail-closed when unparseable). An empty filter
    // permits everything.
    if let Some(base) = repo_remote_upstream(&repo) {
        let filter = load_debian_filter(&state.db, repo.id).await?;
        gate_debian_pool(&filter, base, &component, &path)?;
    }

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
    .map_err(crate::api::handlers::db_err)?
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
                    //
                    // #2459 Tier B: gate the proxy-cache commit on the
                    // SHA-256 the cached Packages index records for this
                    // `Filename`. A body that does not match is still
                    // streamed to the client (which verifies it itself)
                    // but never persisted, so a mismatching upstream cannot
                    // poison the cache. The body STAYS streamed — it is
                    // never buffered (#1608). `None` (no covering Packages
                    // index cached) preserves the prior cache behaviour.
                    let expected_checksum = resolve_pool_expected_checksum(
                        proxy,
                        &repo_key,
                        &component,
                        &artifact_path,
                    )
                    .await
                    .map_err(|e| e.into_response())?;
                    let result = proxy_helpers::proxy_fetch_streaming_with_cache_key_verified(
                        proxy,
                        repo.id,
                        &repo_key,
                        upstream_url,
                        &upstream_path,
                        &upstream_path,
                        expected_checksum,
                        RepositoryFormat::Debian,
                    )
                    .await?;
                    return proxy_helpers::stream_fetch_result(
                        result,
                        DEBIAN_BINARY_CONTENT_TYPE,
                        None,
                    );
                }
            }

            // Virtual repo: try each member in priority order
            if repo.repo_type == RepositoryType::Virtual {
                // #2727: enforce EACH member's own pool (component/arch)
                // allowlist before it can serve a `.deb` through the virtual
                // repo. A Remote member whose filter excludes the requested pool
                // path — or whose filter cannot be loaded — is dropped from the
                // candidate set (treated as deny), exactly as a direct member
                // fetch would 404, while members that DO allow the path still
                // aggregate. Fail-closed per member: a filter-load error skips
                // only that member, it does not fail the whole request open.
                let members = proxy_helpers::fetch_virtual_members(&state.db, repo.id).await?;
                let mut allowed_members = Vec::with_capacity(members.len());
                for member in members {
                    match remote_member_upstream(&member) {
                        Some(base) => {
                            let filter = match load_debian_filter(&state.db, member.id).await {
                                Ok(f) => f,
                                Err(_) => continue,
                            };
                            if gate_debian_pool(&filter, base, &component, &path).is_ok() {
                                allowed_members.push(member);
                            }
                        }
                        // Non-Remote members (Local/Staging) serve hosted
                        // content the proxy allowlist does not apply to —
                        // matching the direct-repo path, which only gates repos
                        // with a Remote upstream.
                        None => allowed_members.push(member),
                    }
                }

                let db = state.db.clone();
                let upstream_path = format!("pool/{}/{}", component, path);
                let artifact_path_clone = artifact_path.clone();
                let result = proxy_helpers::resolve_virtual_download_from_members(
                    allowed_members,
                    state.proxy_service.as_deref(),
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
    // #2460 P2 — pre-fetch filter gate
    // -----------------------------------------------------------------------

    #[test]
    fn test_catchall_component_scoping() {
        // Component-scoped metadata paths return their component.
        assert_eq!(catchall_component("main/i18n/Translation-en"), Some("main"));
        assert_eq!(
            catchall_component("contrib/dep11/Components-amd64.yml.gz"),
            Some("contrib")
        );
        assert_eq!(catchall_component("main/Contents-amd64.gz"), Some("main"));
        // Dist-level (non component-scoped) paths return None.
        assert_eq!(catchall_component("Contents-amd64.gz"), None);
        assert_eq!(catchall_component("Release"), None);
        assert_eq!(catchall_component("by-hash/SHA256/abcdef"), None);
    }

    #[test]
    fn test_filter_decision_empty_allows_everything() {
        let filter = DebianRepositoryConfig::default();
        assert!(
            debian_filter_decision(&filter, Some("bookworm"), Some("contrib"), Some("arm64"))
                .is_ok()
        );
    }

    #[test]
    fn test_filter_decision_allows_in_allowlist() {
        let filter = DebianRepositoryConfig {
            distribution_paths: vec!["bookworm".to_string()],
            components: vec!["main".to_string()],
            architectures: vec!["amd64".to_string()],
            ..Default::default()
        };
        assert!(
            debian_filter_decision(&filter, Some("bookworm"), Some("main"), Some("amd64")).is_ok()
        );
        // Arch-independent packages are always permitted.
        assert!(
            debian_filter_decision(&filter, Some("bookworm"), Some("main"), Some("all")).is_ok()
        );
    }

    #[test]
    fn test_filter_decision_denies_out_of_allowlist_with_404() {
        let filter = DebianRepositoryConfig {
            distribution_paths: vec!["bookworm".to_string()],
            components: vec!["main".to_string()],
            architectures: vec!["amd64".to_string()],
            ..Default::default()
        };
        // Denied distribution.
        let resp = debian_filter_decision(&filter, Some("trixie"), None, None).unwrap_err();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        // Denied component.
        let resp =
            debian_filter_decision(&filter, Some("bookworm"), Some("contrib"), None).unwrap_err();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        // Denied architecture.
        let resp = debian_filter_decision(&filter, Some("bookworm"), Some("main"), Some("arm64"))
            .unwrap_err();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // -----------------------------------------------------------------------
    // #2460 hardening — encoded traversal, catch-all arch, pool fail-closed
    // -----------------------------------------------------------------------

    #[test]
    fn test_decode_to_fixpoint_collapses_multi_encoding() {
        assert_eq!(decode_to_fixpoint("main").as_deref(), Some("main"));
        // Single-encoded dot-dot.
        assert_eq!(
            decode_to_fixpoint("main/%2e%2e/contrib").as_deref(),
            Some("main/../contrib")
        );
        // Double-encoded dot-dot.
        assert_eq!(
            decode_to_fixpoint("main/%252e%252e/contrib").as_deref(),
            Some("main/../contrib")
        );
        // Legit epoch colon survives (not a separator).
        assert_eq!(
            decode_to_fixpoint("gcc_4%3a10.2.1-1_amd64.deb").as_deref(),
            Some("gcc_4:10.2.1-1_amd64.deb")
        );
        // Encoded `.deb` extension.
        assert_eq!(
            decode_to_fixpoint("0ad_1_arm64%252edeb").as_deref(),
            Some("0ad_1_arm64.deb")
        );
    }

    const TEST_BASE: &str = "http://deb.debian.org/debian";

    #[test]
    fn test_normalized_relpath_matches_reqwest_fetch_path() {
        // The gate input must equal the exact path reqwest fetches. For every
        // tricky encoding, assert normalized_debian_relpath == the path reqwest
        // (url crate) resolves for the same joined URL — no gate/fetch drift.
        for raw in [
            "dists/bookworm/main/binary-amd64/Packages.gz",
            "dists/bookworm/main/%2e%2e/contrib/binary-amd64/Packages.gz",
            // Literal-tab dot segment (what axum yields for %2e%09%2e).
            "dists/bookworm/main/.\t./contrib/binary-amd64/Packages.gz",
        ] {
            let full = format!("{}/{}", TEST_BASE, raw);
            let fetched = reqwest::Url::parse(&full).unwrap();
            let base = reqwest::Url::parse(TEST_BASE).unwrap();
            let expected = fetched
                .path()
                .strip_prefix(base.path().trim_end_matches('/'))
                .unwrap()
                .trim_start_matches('/')
                .to_string();
            // A control byte is refused up front (belt); otherwise parity holds.
            if raw.bytes().any(|b| b <= 0x20 || b == 0x7f) {
                assert!(normalized_debian_relpath(TEST_BASE, raw, false).is_err());
            } else {
                assert_eq!(
                    normalized_debian_relpath(TEST_BASE, raw, false).unwrap(),
                    expected,
                    "gate input must equal reqwest fetch path for: {raw:?}"
                );
            }
        }
    }

    #[test]
    fn test_gate_dists_blocks_tab_and_encoded_traversal() {
        let filter = DebianRepositoryConfig {
            distribution_paths: vec!["bookworm".to_string()],
            components: vec!["main".to_string()],
            architectures: vec!["amd64".to_string()],
            ..Default::default()
        };
        // Allowed request passes.
        assert!(gate_debian_dists(
            &filter,
            TEST_BASE,
            "bookworm",
            "main/binary-amd64/Packages.gz"
        )
        .is_ok());
        // Tab-formed dot-segment (axum-decoded %2e%09%2e) -> reforms to contrib.
        let resp = gate_debian_dists(
            &filter,
            TEST_BASE,
            "bookworm",
            "main/.\t./contrib/binary-amd64/Packages.gz",
        )
        .unwrap_err();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        // Distribution escape via tab dot-segments -> trixie.
        let resp = gate_debian_dists(
            &filter,
            TEST_BASE,
            "bookworm",
            "main/.\t./.\t./trixie/main/binary-amd64/Packages.gz",
        )
        .unwrap_err();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        // Single-encoded %2e%2e -> contrib.
        let resp = gate_debian_dists(
            &filter,
            TEST_BASE,
            "bookworm",
            "main/%2e%2e/contrib/binary-amd64/Packages.gz",
        )
        .unwrap_err();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_has_encoded_path_separator() {
        // Encoded forward slash / backslash, any case, any decode layer.
        assert!(has_encoded_path_separator("main%2f..%2fcontrib"));
        assert!(has_encoded_path_separator("main%2F..%2Fcontrib"));
        assert!(has_encoded_path_separator("a%5cb"));
        assert!(has_encoded_path_separator("a%5Cb"));
        // Double-encoded (axum decodes once -> %2f reaches the fixpoint scan).
        assert!(has_encoded_path_separator("main%252f..%252fcontrib"));
        // Legitimate Debian paths: real separators and an epoch colon are fine.
        assert!(!has_encoded_path_separator("main/binary-amd64/Packages.gz"));
        assert!(!has_encoded_path_separator("gcc_4%3a10.2.1-1_amd64.deb"));
        assert!(!has_encoded_path_separator("0ad_1_arm64%252edeb"));
        assert!(!has_encoded_path_separator("Release"));
    }

    #[test]
    fn test_gate_dists_rejects_encoded_separator_with_400() {
        // Default filter (allow_encoded_separators = false) rejects an encoded
        // separator in the dists path with a clear 400 (#2562).
        let filter = DebianRepositoryConfig::default();
        let resp = gate_debian_dists(
            &filter,
            TEST_BASE,
            "bookworm",
            "main%2f..%2fcontrib/binary-amd64/Packages.gz",
        )
        .unwrap_err();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        // An encoded separator smuggled through the distribution segment is also
        // caught (the whole relative path is scanned).
        let resp = gate_debian_dists(&filter, TEST_BASE, "book%2f..worm", "Release").unwrap_err();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        // A legitimate path (real separators, epoch colon) still passes.
        assert!(gate_debian_dists(
            &filter,
            TEST_BASE,
            "bookworm",
            "main/binary-amd64/Packages.gz"
        )
        .is_ok());
    }

    #[test]
    fn test_gate_dists_encoded_separator_opt_out() {
        // With the per-repo opt-out on, the encoded separator is no longer
        // rejected by the #2562 guard (it then flows to the normal gate, which
        // for an empty allowlist permits it).
        let filter = DebianRepositoryConfig {
            allow_encoded_separators: true,
            ..Default::default()
        };
        assert!(gate_debian_dists(
            &filter,
            TEST_BASE,
            "bookworm",
            "main%2f..%2fcontrib/binary-amd64/Packages.gz",
        )
        .is_ok());
    }

    #[test]
    fn test_gate_pool_rejects_encoded_separator_with_400() {
        let filter = DebianRepositoryConfig::default();
        let resp = gate_debian_pool(
            &filter,
            TEST_BASE,
            "main",
            "0/0ad/..%2f..%2f..%2fetc%2fpasswd",
        )
        .unwrap_err();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        // Legitimate pool path with an epoch-colon filename still passes.
        assert!(gate_debian_pool(
            &filter,
            TEST_BASE,
            "main",
            "g/gcc/gcc_4%3a10.2.1-1_amd64.deb"
        )
        .is_ok());
    }

    #[test]
    fn test_normalized_relpath_rejects_control_bytes_and_escape() {
        // Raw control byte (tab/LF/CR/space) refused up front.
        for bad in ["main/\t/Packages", "main/\n/Packages", "main/ /Packages"] {
            assert!(
                normalized_debian_relpath(TEST_BASE, bad, false).is_err(),
                "should reject control/ws: {bad:?}"
            );
        }
        // Escape above the base path is refused.
        assert!(normalized_debian_relpath(TEST_BASE, "../../etc/passwd", false).is_err());
    }

    #[test]
    fn test_gate_pool_fail_closed_on_unparseable_arch() {
        let filter = DebianRepositoryConfig {
            components: vec!["main".to_string()],
            architectures: vec!["amd64".to_string()],
            ..Default::default()
        };
        // Allowed amd64 .deb passes.
        assert!(
            gate_debian_pool(&filter, TEST_BASE, "main", "0/0ad/0ad_0.0.26-3_amd64.deb").is_ok()
        );
        // arm64 denied.
        let resp = gate_debian_pool(&filter, TEST_BASE, "main", "0/0ad/0ad_0.0.26-3_arm64.deb")
            .unwrap_err();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        // Denied component.
        let resp =
            gate_debian_pool(&filter, TEST_BASE, "contrib", "1/1oom/1oom_1_amd64.deb").unwrap_err();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        // Unparseable arch (encoded extension) -> fail closed.
        let resp = gate_debian_pool(
            &filter,
            TEST_BASE,
            "main",
            "0/0ad/0ad_0.0.26-3_arm64%252edeb",
        )
        .unwrap_err();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_by_hash_arch_allowed_cross_reference() {
        use std::collections::HashMap;
        let filter = DebianRepositoryConfig {
            architectures: vec!["amd64".to_string()],
            ..Default::default()
        };
        let mut table: HashMap<String, (String, u64)> = HashMap::new();
        table.insert("main/Contents-amd64.gz".into(), ("aaa".into(), 1));
        table.insert("main/Contents-arm64.gz".into(), ("bbb".into(), 2));
        table.insert(
            "main/dep11/Components-arm64.yml.gz".into(),
            ("ccc".into(), 3),
        );
        table.insert("main/i18n/Translation-en".into(), ("ddd".into(), 4));
        // amd64 index hash -> allowed.
        assert!(by_hash_arch_allowed(&table, "aaa", &filter));
        // arm64 Contents hash -> denied.
        assert!(!by_hash_arch_allowed(&table, "bbb", &filter));
        // arm64 dep11 hash -> denied.
        assert!(!by_hash_arch_allowed(&table, "ccc", &filter));
        // arch-independent i18n hash -> allowed.
        assert!(by_hash_arch_allowed(&table, "ddd", &filter));
        // Unknown hash -> fail closed.
        assert!(!by_hash_arch_allowed(&table, "zzz", &filter));
    }

    #[test]
    fn test_catchall_arch_gates_arch_scoped_metadata() {
        // Contents / dep11 expose the architecture in the leaf name.
        assert_eq!(
            catchall_arch("main/Contents-arm64.gz").as_deref(),
            Some("arm64")
        );
        assert_eq!(catchall_arch("Contents-amd64.gz").as_deref(), Some("amd64"));
        assert_eq!(
            catchall_arch("main/dep11/Components-arm64.yml.gz").as_deref(),
            Some("arm64")
        );
        assert_eq!(
            catchall_arch("main/Contents-udeb-arm64.gz").as_deref(),
            Some("arm64")
        );
        // Architecture-independent / non-arch metadata is not gated.
        assert_eq!(catchall_arch("main/Contents-all.gz"), None);
        assert_eq!(catchall_arch("main/Contents-source.gz"), None);
        assert_eq!(catchall_arch("main/i18n/Translation-en.gz"), None);
        assert_eq!(catchall_arch("main/source/Sources.gz"), None);
        assert_eq!(catchall_arch("main/binary-all/Packages.gz"), None);
    }

    #[test]
    fn test_catchall_arch_denies_out_of_allowlist() {
        let filter = DebianRepositoryConfig {
            architectures: vec!["amd64".to_string()],
            ..Default::default()
        };
        // Contents-arm64 (F3a) must be denied.
        let arch = catchall_arch("main/Contents-arm64.gz");
        let resp = debian_filter_decision(&filter, None, None, arch.as_deref()).unwrap_err();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        // Contents-amd64 stays allowed.
        let arch = catchall_arch("main/Contents-amd64.gz");
        assert!(debian_filter_decision(&filter, None, None, arch.as_deref()).is_ok());
    }

    #[test]
    fn test_pool_arch_parse_fail_closed_semantics() {
        // The pool handler denies when an arch allowlist is set but the arch
        // cannot be parsed. Model that decision here: a percent-encoded `.deb`
        // extension collapses to a parseable filename via decode_to_fixpoint,
        // and a genuinely unparseable name yields None (handler -> 404).
        let decoded = decode_to_fixpoint("0ad_0.0.26-3_arm64%252edeb").unwrap();
        let fname = decoded.rsplit('/').next().unwrap();
        assert_eq!(
            parse_deb_filename(fname).map(|d| d.arch).as_deref(),
            Some("arm64")
        );
        // Unparseable -> None (fail-closed at the call site).
        assert!(parse_deb_filename("not-a-package").is_none());
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
            project_id: None,
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
    fn test_parse_deb_filename_ddeb() {
        let info = parse_deb_filename("systemd-dbgsym_256_amd64.ddeb").unwrap();
        assert_eq!(info.name, "systemd-dbgsym");
        assert_eq!(info.version, "256");
        assert_eq!(info.arch, "amd64");
        assert_eq!(info.package_type, "ddeb");
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

    /// Insert a Remote Debian repo pointing at `upstream_url`. Returns its id.
    async fn insert_remote_debian_member(
        pool: &sqlx::PgPool,
        storage_path: &str,
        upstream_url: &str,
    ) -> Uuid {
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
        member_id
    }

    /// Insert a Virtual Debian repo and enrol `members` (as `(id, priority)`).
    /// Returns `(virtual_id, virtual_key)`.
    async fn insert_virtual_debian(
        pool: &sqlx::PgPool,
        storage_path: &str,
        members: &[(Uuid, i32)],
    ) -> (Uuid, String) {
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
        for (member_id, priority) in members {
            sqlx::query(
                "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
                 VALUES ($1, $2, $3)",
            )
            .bind(virtual_id)
            .bind(member_id)
            .bind(priority)
            .execute(pool)
            .await
            .expect("insert virtual member");
        }
        (virtual_id, virtual_key)
    }

    /// Set a member's P2 Debian proxy filter (dist/component/arch allowlist).
    async fn set_member_debian_filter(pool: &sqlx::PgPool, member_id: Uuid, json: &str) {
        sqlx::query(
            "INSERT INTO repository_config (repository_id, key, value) VALUES ($1, $2, $3)",
        )
        .bind(member_id)
        .bind(DEBIAN_CONFIG_KEY)
        .bind(json)
        .execute(pool)
        .await
        .expect("insert member debian filter");
    }

    /// Insert a Remote Debian repo pointing at `upstream_url` and enrol it as a
    /// member of a fresh Virtual repo. Returns `(virtual_id, virtual_key,
    /// member_id)`; callers clean up via [`cleanup`].
    async fn virtual_with_remote_member(
        pool: &sqlx::PgPool,
        storage_path: &str,
        upstream_url: &str,
    ) -> (Uuid, String, Uuid) {
        let member_id = insert_remote_debian_member(pool, storage_path, upstream_url).await;
        let (virtual_id, virtual_key) =
            insert_virtual_debian(pool, storage_path, &[(member_id, 1)]).await;
        (virtual_id, virtual_key, member_id)
    }

    async fn cleanup(pool: &sqlx::PgPool, virtual_id: Uuid, member_id: Uuid) {
        cleanup_members(pool, virtual_id, &[member_id]).await;
    }

    async fn cleanup_members(pool: &sqlx::PgPool, virtual_id: Uuid, members: &[Uuid]) {
        let _ = sqlx::query("DELETE FROM repository_config WHERE repository_id = ANY($1)")
            .bind(members)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1")
            .bind(virtual_id)
            .execute(pool)
            .await;
        let mut ids = members.to_vec();
        ids.push(virtual_id);
        let _ = sqlx::query("DELETE FROM repositories WHERE id = ANY($1)")
            .bind(ids)
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

    // -----------------------------------------------------------------------
    // #2727 — a Virtual Debian repo must apply EACH member's own P2
    // dist/component/arch allowlist before serving that member's content, so a
    // filtered-out distribution cannot be pulled through the virtual repo.
    // -----------------------------------------------------------------------

    /// The higher-priority member's filter EXCLUDES the requested distribution,
    /// while a lower-priority member allows it. The request must be served from
    /// the ALLOWING member, and the excluded member must never be contacted.
    ///
    /// Before the fix the virtual path never consulted a member's filter, so the
    /// higher-priority (excluded) member would serve the filtered-out dist:
    /// `denying_hits == 1` and the body would be `DENYING-MEMBER-BODY`. After the
    /// fix that member is skipped (deny) and the allowing member serves.
    #[tokio::test]
    #[allow(clippy::disallowed_methods)] // to_bytes on a bounded in-memory test body
    async fn virtual_member_filter_excludes_dist_skips_that_member() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        // Member A (priority 1, tried first): filter restricts to a DIFFERENT
        // distribution, so the requested `trixie` is denied for this member.
        let denying = MockServer::start().await;
        Mock::given(method("GET"))
            .and(wm_path(format!("/{PKG_PATH}")))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(b"DENYING-MEMBER-BODY".to_vec()),
            )
            .mount(&denying)
            .await;

        // Member B (priority 2): no filter (allow all), so it serves `trixie`.
        let allowing = MockServer::start().await;
        let allow_body = b"ALLOWING-MEMBER-BODY".to_vec();
        Mock::given(method("GET"))
            .and(wm_path(format!("/{PKG_PATH}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(allow_body.clone()))
            .mount(&allowing)
            .await;

        let tmp = std::env::temp_dir().join(format!("dbg-2727-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&tmp).expect("tmp");
        let root = tmp.to_str().unwrap();
        let proxy = tdh::build_proxy_service_with_fs(pool.clone(), root);
        let state = tdh::build_state_with_proxy(pool.clone(), root, proxy);

        let member_a = insert_remote_debian_member(&pool, root, &denying.uri()).await;
        let member_b = insert_remote_debian_member(&pool, root, &allowing.uri()).await;
        // A is higher priority (1) than B (2), so A is tried first.
        let (virtual_id, virtual_key) =
            insert_virtual_debian(&pool, root, &[(member_a, 1), (member_b, 2)]).await;
        // Member A's allowlist EXCLUDES the requested `trixie`.
        set_member_debian_filter(&pool, member_a, r#"{"distribution_paths":["bookworm"]}"#).await;

        let out = try_virtual_dists(
            &state,
            virtual_id,
            &virtual_key,
            DIST,
            PKG_PATH,
            "application/octet-stream",
        )
        .await;

        let denying_hits = denying.received_requests().await.unwrap().len();
        let allowing_hits = allowing.received_requests().await.unwrap().len();

        cleanup_members(&pool, virtual_id, &[member_a, member_b]).await;
        let _ = std::fs::remove_dir_all(&tmp);

        let resp = out
            .expect("must not error")
            .expect("the allowing member must serve the request");
        assert_eq!(resp.status(), StatusCode::OK);
        let got = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body");
        assert_eq!(
            got.as_ref(),
            allow_body.as_slice(),
            "content must come from the member whose filter allows `trixie`, not the excluded one",
        );
        assert_eq!(
            denying_hits, 0,
            "the member whose filter EXCLUDES `trixie` must never be fetched (P2 bypass #2727)",
        );
        assert_eq!(
            allowing_hits, 1,
            "the allowing member must be fetched exactly once",
        );
    }

    // -----------------------------------------------------------------------
    // #2459 remote-proxy integrity verification (pure helpers)
    // -----------------------------------------------------------------------

    fn release_table(path: &str, sha: &str, size: u64) -> HashMap<String, (String, u64)> {
        let mut m = HashMap::new();
        m.insert(path.to_string(), (sha.to_string(), size));
        m
    }

    #[test]
    fn test_verify_index_against_release_ok_on_match() {
        let content = b"Packages index body";
        let sha = hex::encode(Sha256::digest(content));
        let table = release_table("main/binary-amd64/Packages", &sha, content.len() as u64);
        assert_eq!(
            verify_index_against_release(&table, "main/binary-amd64/Packages", content),
            IndexVerification::Verified
        );
    }

    #[test]
    fn test_verify_index_against_release_err_on_sha_mismatch() {
        let content = b"poisoned body";
        // Correct size, wrong sha.
        let table = release_table(
            "main/binary-amd64/Packages",
            "0000000000000000000000000000000000000000000000000000000000000000",
            content.len() as u64,
        );
        assert_eq!(
            verify_index_against_release(&table, "main/binary-amd64/Packages", content),
            IndexVerification::Mismatch
        );
    }

    #[test]
    fn test_verify_index_against_release_err_on_size_mismatch() {
        let content = b"body";
        let sha = hex::encode(Sha256::digest(content));
        // Correct sha, wrong size.
        let table = release_table("main/binary-amd64/Packages", &sha, 999_999);
        assert_eq!(
            verify_index_against_release(&table, "main/binary-amd64/Packages", content),
            IndexVerification::Mismatch
        );
    }

    #[test]
    fn test_verify_index_against_release_not_covered() {
        let table = release_table("main/binary-amd64/Packages", "abc", 3);
        assert_eq!(
            verify_index_against_release(&table, "main/i18n/Translation-en", b"anything"),
            IndexVerification::NotCovered
        );
    }

    #[test]
    fn test_verify_index_against_release_by_hash() {
        let content = b"by-hash body";
        let sha = hex::encode(Sha256::digest(content));
        let path = format!("main/binary-amd64/by-hash/SHA256/{}", sha);
        let empty = HashMap::new();
        assert_eq!(
            verify_index_against_release(&empty, &path, content),
            IndexVerification::Verified
        );
        // Wrong bytes for the claimed by-hash digest -> mismatch.
        assert_eq!(
            verify_index_against_release(&empty, &path, b"tampered"),
            IndexVerification::Mismatch
        );
    }

    #[test]
    fn test_resolve_pool_deb_checksum_hit_and_miss() {
        let mut map = HashMap::new();
        map.insert(
            "pool/main/n/nginx/nginx_1.24.0-1_amd64.deb".to_string(),
            ("deadbeef".to_string(), 512u64),
        );
        assert_eq!(
            resolve_pool_deb_checksum(&map, "pool/main/n/nginx/nginx_1.24.0-1_amd64.deb"),
            Some("deadbeef".to_string())
        );
        assert_eq!(
            resolve_pool_deb_checksum(&map, "pool/main/c/curl/curl_8.0.1-1_amd64.deb"),
            None
        );
    }

    #[test]
    fn test_is_matching_packages_index() {
        assert!(is_matching_packages_index(
            "dists/bookworm/main/binary-amd64/Packages.gz",
            "main",
            "amd64"
        ));
        assert!(is_matching_packages_index(
            "dists/jammy/main/binary-amd64/Packages",
            "main",
            "amd64"
        ));
        // Wrong component / arch / not a Packages leaf.
        assert!(!is_matching_packages_index(
            "dists/bookworm/contrib/binary-amd64/Packages.gz",
            "main",
            "amd64"
        ));
        assert!(!is_matching_packages_index(
            "dists/bookworm/main/binary-arm64/Packages.gz",
            "main",
            "amd64"
        ));
        assert!(!is_matching_packages_index(
            "dists/bookworm/main/binary-amd64/Release",
            "main",
            "amd64"
        ));
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut enc = GzBuilder::new().write(Vec::new(), Compression::default());
        enc.write_all(bytes).unwrap();
        enc.finish().unwrap()
    }

    fn xz(bytes: &[u8]) -> Vec<u8> {
        let mut enc = xz2::write::XzEncoder::new(Vec::new(), 6);
        enc.write_all(bytes).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn test_decompress_packages_index_honest_gz_and_xz() {
        let body = b"Package: hello\nFilename: pool/main/h/hello/hello_1.0_amd64.deb\nSHA256: abc\nSize: 10\n";
        assert_eq!(
            decompress_packages_index("dists/x/main/binary-amd64/Packages.gz", &gzip(body)),
            Some(String::from_utf8(body.to_vec()).unwrap())
        );
        assert_eq!(
            decompress_packages_index("dists/x/main/binary-amd64/Packages.xz", &xz(body)),
            Some(String::from_utf8(body.to_vec()).unwrap())
        );
        // Plain (uncompressed) passes through unchanged.
        assert_eq!(
            decompress_packages_index("dists/x/main/binary-amd64/Packages", body),
            Some(String::from_utf8(body.to_vec()).unwrap())
        );
    }

    #[test]
    fn test_decompress_packages_index_bomb_hits_cap_returns_none() {
        // A highly-compressible payload that expands past the decompressed cap.
        // ~200 MiB of zeros compresses to a few hundred KiB but must NOT be
        // expanded into memory — the cap returns None (unresolvable), no OOM.
        let bomb = vec![0u8; (MAX_DECOMPRESSED_INDEX_BYTES as usize) + (16 * 1024 * 1024)];
        let gz = gzip(&bomb);
        assert!(
            gz.len() <= MAX_COMPRESSED_INDEX_BYTES,
            "test bomb should slip past the compressed-size pre-check to exercise the decode cap"
        );
        assert_eq!(
            decompress_packages_index("dists/x/main/binary-amd64/Packages.gz", &gz),
            None
        );
    }

    #[test]
    fn test_decompress_packages_index_oversized_compressed_skipped() {
        let too_big = vec![7u8; MAX_COMPRESSED_INDEX_BYTES + 1];
        assert_eq!(
            decompress_packages_index("dists/x/main/binary-amd64/Packages.gz", &too_big),
            None
        );
    }
}

// --------------------------------------------------------------------------
// Unit tests: newline normalization & deb822 formatting helpers
// --------------------------------------------------------------------------

#[cfg(test)]
mod apt_release_helpers_tests {
    use super::*;

    // -- contains_newline ---------------------------------------------------

    #[test]
    fn test_contains_newline_no_newline() {
        assert!(!contains_newline("plain text"));
        assert!(!contains_newline(""));
    }

    #[test]
    fn test_contains_newline_lf() {
        assert!(contains_newline("line1\nline2"));
    }

    #[test]
    fn test_contains_newline_crlf() {
        assert!(contains_newline("line1\r\nline2"));
    }

    #[test]
    fn test_contains_newline_cr() {
        assert!(contains_newline("line1\rline2"));
    }

    // -- normalize_newlines -------------------------------------------------

    #[test]
    fn test_normalize_newlines_no_change() {
        assert_eq!(normalize_newlines("plain text"), "plain text");
    }

    #[test]
    fn test_normalize_newlines_lf_unchanged() {
        assert_eq!(normalize_newlines("a\nb"), "a\nb");
    }

    #[test]
    fn test_normalize_newlines_crlf_to_lf() {
        assert_eq!(normalize_newlines("a\r\nb"), "a\nb");
    }

    #[test]
    fn test_normalize_newlines_cr_to_lf() {
        assert_eq!(normalize_newlines("a\rb"), "a\nb");
    }

    #[test]
    fn test_normalize_newlines_mixed() {
        let input = "line1\r\nline2\nline3\rline4";
        let expected = "line1\nline2\nline3\nline4";
        assert_eq!(normalize_newlines(input), expected);
    }

    // -- take_first_line ----------------------------------------------------

    #[test]
    fn test_take_first_line_single() {
        assert_eq!(take_first_line("hello"), "hello");
    }

    #[test]
    fn test_take_first_line_lf() {
        assert_eq!(take_first_line("hello\nworld"), "hello");
    }

    #[test]
    fn test_take_first_line_crlf() {
        assert_eq!(take_first_line("hello\r\nworld"), "hello");
    }

    #[test]
    fn test_take_first_line_cr() {
        assert_eq!(take_first_line("hello\rworld"), "hello");
    }

    #[test]
    fn test_take_first_line_trims() {
        assert_eq!(take_first_line("  hello  \nworld"), "hello");
    }

    // -- format_deb822_description ------------------------------------------

    #[test]
    fn test_format_deb822_single_line() {
        assert_eq!(format_deb822_description("A single line"), "A single line");
    }

    #[test]
    fn test_format_deb822_multi_line_continuation() {
        let input = "First line\nSecond line";
        assert_eq!(format_deb822_description(input), "First line\n Second line");
    }

    #[test]
    fn test_format_deb822_empty_lines_bare_dot() {
        let input = "Header\n\nBody\n\nFooter";
        assert_eq!(
            format_deb822_description(input),
            "Header\n .\n Body\n .\n Footer"
        );
    }

    #[test]
    fn test_format_deb822_trims_continuation_lines() {
        let input = "First\n  indented line  ";
        assert_eq!(format_deb822_description(input), "First\n indented line");
    }

    #[test]
    fn test_format_deb822_crlf_handling() {
        let input = "Header\r\n\r\nBody";
        assert_eq!(format_deb822_description(input), "Header\n .\n Body");
    }

    // -- push_control_field -------------------------------------------------

    #[test]
    fn test_push_control_field_single_line() {
        let mut text = String::new();
        push_control_field(&mut text, "Key", "value");
        assert_eq!(text, "Key: value\n");
    }

    #[test]
    fn test_push_control_field_multi_line() {
        let mut text = String::new();
        push_control_field(&mut text, "Desc", "Line1\nLine2");
        assert_eq!(text, "Desc: Line1\n Line2\n");
    }

    #[test]
    fn test_push_control_field_empty_line_bare_dot() {
        let mut text = String::new();
        push_control_field(&mut text, "Desc", "Line1\n\nLine3");
        assert_eq!(text, "Desc: Line1\n .\n Line3\n");
    }

    #[test]
    fn test_push_control_field_empty_value() {
        let mut text = String::new();
        push_control_field(&mut text, "Key", "");
        assert_eq!(text, "");
    }
}

// --------------------------------------------------------------------------
// DB-backed tests: fetch_apt_release_metadata defaults + injection defense
// (generation-layer, defense-in-depth for #2489)
// --------------------------------------------------------------------------

#[cfg(test)]
mod apt_release_metadata_db_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;
    use uuid::Uuid;

    /// Insert a hosted (local) Debian repo and return its id + storage dir.
    async fn insert_hosted_debian(pool: &sqlx::PgPool) -> (Uuid, std::path::PathBuf) {
        let id = Uuid::new_v4();
        let key = format!("apt-meta-{}", id.simple());
        let dir = std::env::temp_dir().join(format!("apt-meta-{id}"));
        std::fs::create_dir_all(&dir).expect("create storage dir");
        sqlx::query(
            "INSERT INTO repositories (id, key, name, storage_path, repo_type, format) \
             VALUES ($1, $2, $3, $4, 'local'::repository_type, 'debian'::repository_format)",
        )
        .bind(id)
        .bind(&key)
        .bind(&key)
        .bind(dir.to_string_lossy().as_ref())
        .execute(pool)
        .await
        .expect("insert hosted debian repo");
        (id, dir)
    }

    async fn set_cfg(pool: &sqlx::PgPool, repo_id: Uuid, key: &str, value: &str) {
        sqlx::query(
            "INSERT INTO repository_config (repository_id, key, value) VALUES ($1, $2, $3)",
        )
        .bind(repo_id)
        .bind(key)
        .bind(value)
        .execute(pool)
        .await
        .expect("insert repository_config");
    }

    async fn cleanup(pool: &sqlx::PgPool, repo_id: Uuid, dir: &std::path::Path) {
        let _ = sqlx::query("DELETE FROM repository_config WHERE repository_id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A repo with no apt_* config must fall back to the "artifact-keeper"
    /// defaults for Origin/Label and omit Version/Description — i.e. the exact
    /// pre-#2489 behavior, so existing hosted Debian repos never regress.
    #[tokio::test]
    async fn test_fetch_apt_release_metadata_defaults() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, dir) = insert_hosted_debian(&pool).await;

        let (origin, label, version, description) = fetch_apt_release_metadata(&pool, repo_id)
            .await
            .expect("read apt release metadata");
        assert_eq!(
            origin, "artifact-keeper",
            "default Origin must be preserved"
        );
        assert_eq!(label, "artifact-keeper", "default Label must be preserved");
        assert_eq!(version, None, "Version omitted when unset");
        assert_eq!(description, None, "Description omitted when unset");

        cleanup(&pool, repo_id, &dir).await;
    }

    /// Configured values are read back verbatim.
    #[tokio::test]
    async fn test_fetch_apt_release_metadata_custom_values() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, dir) = insert_hosted_debian(&pool).await;
        set_cfg(&pool, repo_id, "apt_origin", "Acme Corp").await;
        set_cfg(&pool, repo_id, "apt_label", "Acme Staging").await;
        set_cfg(&pool, repo_id, "apt_release_version", "2026.07").await;
        set_cfg(&pool, repo_id, "apt_description", "Internal mirror").await;

        let (origin, label, version, description) = fetch_apt_release_metadata(&pool, repo_id)
            .await
            .expect("read apt release metadata");
        assert_eq!(origin, "Acme Corp");
        assert_eq!(label, "Acme Staging");
        assert_eq!(version.as_deref(), Some("2026.07"));
        assert_eq!(description.as_deref(), Some("Internal mirror"));

        cleanup(&pool, repo_id, &dir).await;
    }

    /// Defense-in-depth: even if a multi-line value bypasses the API layer and
    /// lands in `repository_config` directly (e.g. via a migration, an admin
    /// SQL edit, or a future code path), the generation layer must NOT emit the
    /// injected trailing content as forged Release fields. `apt_origin`,
    /// `apt_label`, and `apt_release_version` are reduced to their first line;
    /// this is what prevents `Origin:`/`Label:`/`Version:` newline injection
    /// from appending arbitrary lines to the signed Release file.
    #[tokio::test]
    async fn test_fetch_apt_release_metadata_strips_injected_newlines() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, dir) = insert_hosted_debian(&pool).await;
        // Directly plant forged values that the API would have rejected.
        set_cfg(&pool, repo_id, "apt_origin", "evil\nForged-Field: pwned").await;
        set_cfg(&pool, repo_id, "apt_label", "l1\r\nSigned-By: attacker").await;
        set_cfg(
            &pool,
            repo_id,
            "apt_release_version",
            "9.9\rNotAutomatic: no",
        )
        .await;

        let (origin, label, version, _desc) = fetch_apt_release_metadata(&pool, repo_id)
            .await
            .expect("read apt release metadata");
        assert_eq!(origin, "evil", "Origin must be reduced to its first line");
        assert!(!origin.contains('\n') && !origin.contains('\r'));
        assert_eq!(label, "l1", "Label must be reduced to its first line");
        assert!(!label.contains('\n') && !label.contains('\r'));
        assert_eq!(
            version.as_deref(),
            Some("9.9"),
            "Version must be reduced to its first line"
        );

        // Prove it end-to-end at the Release string level: a forged field name
        // must never appear at column 0 (which is how apt parses a new field).
        let origin_line = format!("Origin: {origin}\n");
        assert!(!origin_line.contains("\nForged-Field:"));

        cleanup(&pool, repo_id, &dir).await;
    }

    /// A multi-line `apt_description` is preserved (it is deb822-formatted at
    /// render time) but must not be usable to inject a bare field: every
    /// continuation line is space-prefixed by `format_deb822_description`.
    #[tokio::test]
    async fn test_apt_description_multiline_cannot_forge_field() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, dir) = insert_hosted_debian(&pool).await;
        set_cfg(
            &pool,
            repo_id,
            "apt_description",
            "Summary line\nForged-Field: pwned",
        )
        .await;

        let (_o, _l, _v, description) = fetch_apt_release_metadata(&pool, repo_id)
            .await
            .expect("read apt release metadata");
        let desc = description.expect("description present");
        let rendered = format!("Description: {}\n", format_deb822_description(&desc));
        // The second line must be a space-prefixed continuation, never a field.
        assert!(
            rendered.contains("\n Forged-Field: pwned"),
            "continuation line must be space-prefixed: {rendered:?}"
        );
        assert!(
            !rendered.contains("\nForged-Field:"),
            "must not emit a bare (column-0) forged field: {rendered:?}"
        );

        cleanup(&pool, repo_id, &dir).await;
    }

    // -----------------------------------------------------------------------
    // Release document determinism.
    //
    // `Release` and `Release.gpg` are rendered by two independent requests, so
    // the detached signature only verifies if the two renders are byte-
    // identical. These pin that invariant: the render must depend on
    // repository state ONLY, never on when the request arrived.
    // -----------------------------------------------------------------------

    fn render_input_fixture(
        published_at: chrono::DateTime<chrono::Utc>,
        files: &[(String, Vec<u8>)],
    ) -> ReleaseRenderInput<'_> {
        ReleaseRenderInput {
            origin: "artifact-keeper",
            label: "artifact-keeper",
            distribution: "stable",
            version: None,
            description: None,
            published_at,
            architectures: "amd64",
            components: "main",
            files,
        }
    }

    /// The `Date:` field must come from the supplied publish timestamp, not
    /// from the clock. Rendering with a timestamp far in the past must emit
    /// that past date — a `now()` read would emit today instead.
    #[test]
    fn release_date_comes_from_publish_timestamp_not_the_wall_clock() {
        let published_at = chrono::DateTime::<chrono::Utc>::UNIX_EPOCH + chrono::Duration::days(1);
        let doc = render_release_document(&render_input_fixture(published_at, &[]));

        assert!(
            doc.contains("Date: Fri, 02 Jan 1970 00:00:00 UTC\n"),
            "Date: must render the publish timestamp verbatim, got:\n{doc}"
        );
        let this_year = chrono::Utc::now().format("%Y").to_string();
        assert!(
            !doc.contains(&format!("Date: {this_year}"))
                && !doc.contains(&format!(" {this_year} ")),
            "Date: must not be stamped from the wall clock, got:\n{doc}"
        );
    }

    /// Pin the exact `Date:` wire format apt parses (RFC-1123-ish, UTC).
    #[test]
    fn format_release_date_matches_the_apt_wire_format() {
        let t = chrono::DateTime::parse_from_rfc3339("2026-07-17T01:24:11Z")
            .expect("parse fixture")
            .with_timezone(&chrono::Utc);
        assert_eq!(format_release_date(t), "Fri, 17 Jul 2026 01:24:11 UTC");
    }

    /// Same repository state must render identically regardless of how many
    /// times (or in which order) it is rendered — the property that lets the
    /// content-addressed signature cache hand back a signature that still
    /// matches a freshly-rendered `Release`.
    #[test]
    fn release_render_is_stable_across_repeated_calls() {
        let files = vec![(
            "main/binary-amd64/Packages".to_string(),
            b"Package: a\n".to_vec(),
        )];
        let published_at = chrono::DateTime::<chrono::Utc>::UNIX_EPOCH + chrono::Duration::days(2);
        let first = render_release_document(&render_input_fixture(published_at, &files));
        for _ in 0..5 {
            assert_eq!(
                first,
                render_release_document(&render_input_fixture(published_at, &files)),
                "repeated renders of unchanged state must be byte-identical"
            );
        }
    }

    /// THE regression guard for the `Release`/`Release.gpg` BAD-signature bug.
    ///
    /// End-to-end against the DB: `generate_release_content` — the single
    /// function behind `Release`, `InRelease` and `Release.gpg` — must return
    /// identical bytes when called twice across a wall-clock second boundary
    /// for an unchanged repository. This is the served-vs-signed invariant at
    /// the exact call site both endpoints use, so it fails against any clock
    /// read reintroduced anywhere beneath it (not just in the renderer).
    ///
    /// Against the pre-fix `Utc::now()` stamp this fails on exactly one byte —
    /// the seconds digit of `Date:` — which is what made `gpg --verify` report
    /// `BAD signature` on an untampered repo.
    #[tokio::test]
    async fn generate_release_content_is_stable_across_a_second_boundary() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, dir) = insert_hosted_debian(&pool).await;
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());

        let served = generate_release_content(&state, repo_id, "stable")
            .await
            .map_err(|_| "generate_release_content failed")
            .expect("render Release");
        // Cross a real second boundary between the served and signed renders.
        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        let signed = generate_release_content(&state, repo_id, "stable")
            .await
            .map_err(|_| "generate_release_content failed")
            .expect("render Release");

        assert_eq!(
            served, signed,
            "Release render changed across a second boundary: the bytes served by \
             GET Release would differ from the bytes signed by GET Release.gpg, so \
             apt-secure would report BAD signature on an untampered repo"
        );

        cleanup(&pool, repo_id, &dir).await;
    }

    /// The publish timestamp must be repository *state*, not the clock: for a
    /// repo with no artifacts it must equal that repo's own `created_at` read
    /// back from the DB. A `Utc::now()` implementation fails this — the repo
    /// was created a moment before, so the two differ.
    #[tokio::test]
    async fn release_publish_timestamp_is_the_repository_created_at() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, dir) = insert_hosted_debian(&pool).await;

        let (created_at,): (chrono::DateTime<chrono::Utc>,) =
            sqlx::query_as("SELECT created_at FROM repositories WHERE id = $1")
                .bind(repo_id)
                .fetch_one(&pool)
                .await
                .expect("read repo created_at");

        let stamp = release_publish_timestamp(&pool, repo_id)
            .await
            .map_err(|_| "release_publish_timestamp failed")
            .expect("publish timestamp");

        assert_eq!(
            stamp, created_at,
            "publish timestamp must be the repository's stored created_at, not a \
             wall-clock read"
        );

        cleanup(&pool, repo_id, &dir).await;
    }

    /// A failed publish-timestamp read must fail the request, never degrade to
    /// a default stamp.
    ///
    /// `.ok()` on this read would swallow a pool timeout / connection reset and
    /// render `Date: Thu, 01 Jan 1970`. `Release` and `Release.gpg` are separate
    /// requests: if only one of them hit the blip, the signature would cover
    /// bytes the client never received — the same BAD-signature bug with a new
    /// trigger, and one that fires under load, precisely when the gap between
    /// the two requests is widest.
    ///
    /// Needs no live Postgres: an unreachable lazy pool fails on connect.
    #[tokio::test]
    async fn release_publish_timestamp_errors_when_the_database_is_unreachable() {
        let dead = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_secs(2))
            .connect_lazy("postgres://invalid:invalid@127.0.0.1:1/none")
            .expect("lazy pool");

        let result = release_publish_timestamp(&dead, Uuid::new_v4()).await;

        assert!(
            result.is_err(),
            "a failed publish-timestamp read must propagate an error; falling back \
             to a default stamp would let Release and Release.gpg disagree and \
             produce a signature over bytes never served"
        );
    }

    /// Deploy-time monotonic floor: repository state older than the binary's
    /// build timestamp must render `Date:` == the floor, never the older
    /// state stamp.
    ///
    /// Why: swapping `Utc::now()` for a state-derived stamp steps `Date:`
    /// backward once at deploy on every pre-existing repo. apt does not
    /// reject a backward `Date:` — it silently fakes an IMS hit
    /// (`pkgAcqMetaBase::VerifyVendor`, measured identical on apt
    /// 2.2.4/2.6.1/2.8.3, no option controls it), keeps its cached
    /// pre-deploy metadata, and `apt-get update` exits 0. Without the floor
    /// every existing client freezes on stale metadata — indefinitely on a
    /// quiescent repo — with nothing alerting anyone.
    #[tokio::test]
    async fn release_publish_timestamp_is_floored_at_the_build_timestamp() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, dir) = insert_hosted_debian(&pool).await;

        // Deploy-shape state: a quiescent repo whose newest mutation is far
        // older than this binary. No artifacts, so the repo's own created_at
        // is the raw state stamp.
        sqlx::query("UPDATE repositories SET created_at = '2001-02-03T04:05:06Z' WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .expect("backdate repository");

        let floor = release_date_floor();
        assert!(
            floor
                > chrono::DateTime::parse_from_rfc3339("2001-02-03T04:05:06Z")
                    .expect("parse fixture")
                    .with_timezone(&chrono::Utc),
            "build-time floor must postdate the backdated fixture"
        );

        let stamp = release_publish_timestamp(&pool, repo_id)
            .await
            .map_err(|_| "release_publish_timestamp failed")
            .expect("publish timestamp");
        assert_eq!(
            stamp, floor,
            "state older than the build-time floor must be floored: apt clients \
             that cached a pre-deploy wall-clock Date silently pin to stale \
             metadata (fake IMS hit, exit 0, no diagnostics) whenever Date: \
             steps backward"
        );

        // The floored render must stay deterministic: the floor is a
        // compile-time constant, not a clock read, so two renders across a
        // second boundary are still byte-identical and stamp the floor.
        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let served = generate_release_content(&state, repo_id, "stable")
            .await
            .map_err(|_| "generate_release_content failed")
            .expect("render Release");
        tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
        let signed = generate_release_content(&state, repo_id, "stable")
            .await
            .map_err(|_| "generate_release_content failed")
            .expect("render Release");
        assert_eq!(
            served, signed,
            "floored renders must be byte-identical across a second boundary"
        );
        assert!(
            served.contains(&format!("Date: {}\n", format_release_date(floor))),
            "rendered Date: must be the floor, got:\n{served}"
        );

        cleanup(&pool, repo_id, &dir).await;
    }

    // -----------------------------------------------------------------------
    // #2672 — load_debian_filter must fail CLOSED on an *error*, while an
    // *absent* config still means "allow all". A DB error or an unparseable
    // config row must no longer be silently downgraded to the empty (allow-all)
    // filter.
    // -----------------------------------------------------------------------

    /// A genuine DB error while loading the filter must fail CLOSED (503),
    /// NOT be swallowed into the empty allow-all default. This is the core
    /// regression for #2672 and needs no live database: a lazily-connected
    /// pool pointed at an unreachable server errors on first query.
    #[tokio::test]
    async fn test_load_debian_filter_db_error_fails_closed() {
        let pool = sqlx::PgPool::connect_lazy("postgres://fake:fake@127.0.0.1:1/fake")
            .expect("connect_lazy");
        let result = load_debian_filter(&pool, Uuid::new_v4()).await;
        let resp =
            result.expect_err("a DB error must fail closed (Err), not fall open to allow-all");
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a filter-load DB error must deny the request with 503, not allow it"
        );
    }

    /// A repository with NO `debian_config` row is a legitimate unset state:
    /// the documented default is "empty filter = allow all". This must keep
    /// working after the #2672 fail-closed change.
    #[tokio::test]
    async fn test_load_debian_filter_absent_config_allows_all() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, dir) = insert_hosted_debian(&pool).await;

        let filter = load_debian_filter(&pool, repo_id)
            .await
            .expect("absent config must succeed with the allow-all default");
        assert_eq!(
            filter,
            DebianRepositoryConfig::default(),
            "no config row must yield the empty (allow-all) default"
        );
        // The empty filter still selects everything.
        assert!(
            debian_filter_decision(&filter, Some("bookworm"), Some("contrib"), Some("arm64"))
                .is_ok(),
            "unset filter must allow all dimensions"
        );

        cleanup(&pool, repo_id, &dir).await;
    }

    /// A validly-configured filter is loaded and honored (the legitimate
    /// configured path is unaffected by the fail-closed change).
    #[tokio::test]
    async fn test_load_debian_filter_valid_config_parses() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, dir) = insert_hosted_debian(&pool).await;
        set_cfg(
            &pool,
            repo_id,
            DEBIAN_CONFIG_KEY,
            r#"{"distributions":["bookworm"],"components":["main"],"architectures":["amd64"]}"#,
        )
        .await;

        let filter = load_debian_filter(&pool, repo_id)
            .await
            .expect("a valid config must load");
        assert_eq!(filter.distribution_paths, vec!["bookworm".to_string()]);
        assert_eq!(filter.components, vec!["main".to_string()]);
        assert_eq!(filter.architectures, vec!["amd64".to_string()]);
        // An out-of-allowlist request is denied by the loaded filter.
        assert!(
            debian_filter_decision(&filter, Some("sid"), None, None).is_err(),
            "a configured filter must still deny out-of-allowlist dimensions"
        );

        cleanup(&pool, repo_id, &dir).await;
    }

    /// A config row that is PRESENT but unparseable is an error loading the
    /// operator's intended filter, not an unset filter, so it must fail CLOSED
    /// (503) rather than fall open to allow-all (#2672 swallow class).
    #[tokio::test]
    async fn test_load_debian_filter_unparseable_config_fails_closed() {
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo_id, dir) = insert_hosted_debian(&pool).await;
        set_cfg(&pool, repo_id, DEBIAN_CONFIG_KEY, "{ not valid json").await;

        let result = load_debian_filter(&pool, repo_id).await;
        let status = result.as_ref().err().map(|r| r.status());

        cleanup(&pool, repo_id, &dir).await;

        assert!(
            result.is_err(),
            "a present-but-corrupt filter config must fail closed, not allow-all"
        );
        assert_eq!(status, Some(StatusCode::SERVICE_UNAVAILABLE));
    }
}
