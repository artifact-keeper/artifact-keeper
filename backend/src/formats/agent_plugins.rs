//! Agent Plugins format (#5251): AI coding-agent plugin bundles.
//!
//! A plugin version is one zip stored at `{name}/{version}/{name}-{version}.zip`.
//! The path is authoritative (D4): the slug and version come from the URL, and
//! any manifest inside the zip that carries a `name` or `version` must agree
//! with it (D5). Everything in this module is pure (no database, no storage)
//! so the publish rules and the five marketplace documents are unit tested
//! here and the HTTP handler in `api/handlers/agent_plugins.rs` only wires
//! them to rows.
//!
//! See `docs/agent-plugins.md` for the protocol reference.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Seek};

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;
use crate::util::bounded_archive;

/// The format key, the route prefix and the `artifact_metadata.format` value.
pub const FORMAT_KEY: &str = "agentplugins";

/// Longest accepted plugin slug (D4).
pub const MAX_SLUG_LEN: usize = 64;

/// `$schema` prefix that marks an Agent Plugins Standard root `plugin.json`.
pub const STANDARD_SCHEMA_PREFIX: &str = "https://agent-plugins.org/schemas/";

/// `$schema` of the unified `marketplace.json` document.
pub const UNIFIED_SCHEMA: &str =
    "https://artifactkeeper.com/schemas/agent-plugins/marketplace-v1.json";

/// The marketplace owner every generated document names.
pub const OWNER_NAME: &str = "Artifact Keeper";

/// Largest manifest file read out of a bundle.
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

/// Top-level entries a zip tool adds on its own; never part of a plugin.
const IGNORED_TOP_LEVEL: &[&str] = &["__MACOSX", ".DS_Store"];

/// Marketplace names Claude Code reserves. A repository key equal to one of
/// these (or starting with `claudeai-`) gets an `-ak` suffix.
const RESERVED_MARKETPLACE_NAMES: &[&str] = &[
    "claude-plugins-official",
    "claude-code-plugins",
    "anthropic-marketplace",
    "knowledge-work-plugins",
    "first-party-plugins",
    "claude-community",
    "inline",
    "builtin",
    "skills-dir",
    "synced",
    "claude-plugin-test",
    "npm",
    "pip",
    "uv",
    "cargo",
    "github",
    "gh",
];

// ---------------------------------------------------------------------------
// Harnesses and manifests
// ---------------------------------------------------------------------------

/// A coding agent a bundle declares support for, detected from its marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Harness {
    Claude,
    Standard,
    Cursor,
    Codex,
    Gemini,
}

impl Harness {
    /// Discovery order: the first match provides the descriptive metadata.
    pub const ALL: [Harness; 5] = [
        Harness::Claude,
        Harness::Standard,
        Harness::Cursor,
        Harness::Codex,
        Harness::Gemini,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Harness::Claude => "claude",
            Harness::Standard => "standard",
            Harness::Cursor => "cursor",
            Harness::Codex => "codex",
            Harness::Gemini => "gemini",
        }
    }

    /// The marker file, relative to the plugin root.
    pub fn marker(self) -> &'static str {
        match self {
            Harness::Claude => ".claude-plugin/plugin.json",
            Harness::Standard => "plugin.json",
            Harness::Cursor => ".cursor-plugin/plugin.json",
            Harness::Codex => ".codex-plugin/plugin.json",
            Harness::Gemini => "gemini-extension.json",
        }
    }
}

/// Whether a parsed root `plugin.json` is an Agent Plugins Standard manifest.
pub fn is_standard_manifest(manifest: &Value) -> bool {
    manifest
        .get("$schema")
        .and_then(Value::as_str)
        .is_some_and(|s| s.starts_with(STANDARD_SCHEMA_PREFIX))
}

// ---------------------------------------------------------------------------
// Coordinates: slug, SemVer, filename
// ---------------------------------------------------------------------------

/// Validate a plugin slug against D4: `^[a-z0-9][a-z0-9-]*$`, at most 64.
pub fn validate_slug(slug: &str) -> std::result::Result<(), String> {
    let valid_chars = slug
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    let valid_first = slug
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    if !valid_chars || !valid_first {
        return Err(format!(
            "Invalid plugin name {slug:?}: a plugin name must match ^[a-z0-9][a-z0-9-]*$ \
             (lowercase letters, digits and '-', starting with a letter or digit)"
        ));
    }
    if slug.len() > MAX_SLUG_LEN {
        return Err(format!(
            "Invalid plugin name {slug:?}: a plugin name is at most {MAX_SLUG_LEN} characters"
        ));
    }
    Ok(())
}

/// Parse a version as strict SemVer 2.0 (no `v` prefix, no leading zeros,
/// exactly three numeric components).
pub fn parse_semver(version: &str) -> std::result::Result<semver::Version, String> {
    semver::Version::parse(version).map_err(|e| {
        format!(
            "Invalid plugin version {version:?}: versions must be SemVer 2.0 \
             (for example 1.2.0 or 2.0.0-rc.1): {e}"
        )
    })
}

/// Validate the three path coordinates of a publish or download URL.
pub fn validate_coordinates(
    name: &str,
    version: &str,
    filename: &str,
) -> std::result::Result<semver::Version, String> {
    validate_slug(name)?;
    let parsed = parse_semver(version)?;
    let expected = archive_filename(name, version);
    if filename != expected {
        return Err(format!(
            "Invalid file name {filename:?}: the archive must be named {expected:?} \
             ({{name}}/{{version}}/{{name}}-{{version}}.zip)"
        ));
    }
    Ok(parsed)
}

/// `{name}-{version}.zip`.
pub fn archive_filename(name: &str, version: &str) -> String {
    format!("{name}-{version}.zip")
}

/// The authoritative artifact path, `{name}/{version}/{name}-{version}.zip`.
pub fn artifact_path(name: &str, version: &str) -> String {
    format!("{name}/{version}/{}", archive_filename(name, version))
}

/// Order version strings by SemVer precedence; a string that does not parse
/// (never stored, but defensive) sorts below every valid version.
pub fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    match (semver::Version::parse(a), semver::Version::parse(b)) {
        (Ok(a), Ok(b)) => a.cmp(&b),
        (Ok(_), Err(_)) => std::cmp::Ordering::Greater,
        (Err(_), Ok(_)) => std::cmp::Ordering::Less,
        (Err(_), Err(_)) => a.cmp(b),
    }
}

// ---------------------------------------------------------------------------
// Bundle inspection
// ---------------------------------------------------------------------------

/// One central-directory entry of an uploaded zip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleEntry {
    pub name: String,
    pub is_dir: bool,
    pub is_symlink: bool,
}

impl BundleEntry {
    pub fn file(name: &str) -> Self {
        Self {
            name: name.to_string(),
            is_dir: false,
            is_symlink: false,
        }
    }

    fn is_file(&self) -> bool {
        !self.is_dir && !self.is_symlink && !self.name.ends_with('/')
    }
}

/// Plugin components found under the plugin root. Recorded so a later
/// content policy (deny hooks, `bin/`, MCP) needs no re-index.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Components {
    pub skills: Vec<String>,
    pub commands: u32,
    pub agents: u32,
    pub hooks: bool,
    pub mcp: bool,
    pub lsp: bool,
    pub bin: bool,
}

/// A manifest author, normalised from either an object or a bare string.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Author {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// What a publish records in `artifact_metadata` (format `agentplugins`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub harnesses: Vec<String>,
    pub manifest_paths: Vec<String>,
    pub root_prefix: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<Author>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    pub keywords: Vec<String>,
    pub components: Components,
    pub sha256: String,
    pub size_bytes: i64,
}

/// Determine the plugin root prefix (`""` or `"<dir>/"`).
///
/// The root is the zip root when any harness marker sits there, otherwise
/// the single top-level directory that holds everything (the two shapes
/// Claude Code's `archive` source accepts).
pub fn detect_root(entries: &[BundleEntry]) -> std::result::Result<String, String> {
    let has_root_marker = Harness::ALL
        .iter()
        .any(|h| entries.iter().any(|e| e.is_file() && e.name == h.marker()));
    if has_root_marker {
        return Ok(String::new());
    }
    let mut dirs: BTreeSet<&str> = BTreeSet::new();
    let mut top_level_files = false;
    for entry in entries {
        let (first, rest) = match entry.name.split_once('/') {
            Some((first, rest)) => (first, Some(rest)),
            None => (entry.name.as_str(), None),
        };
        if first.is_empty() || IGNORED_TOP_LEVEL.contains(&first) {
            continue;
        }
        if rest.is_some() || entry.is_dir {
            dirs.insert(first);
        } else {
            top_level_files = true;
        }
    }
    match (dirs.len(), top_level_files) {
        (1, false) => Ok(format!("{}/", dirs.into_iter().next().unwrap_or_default())),
        (n, _) if n >= 2 => Err(format!(
            "The plugin root cannot be determined: the zip has {n} top-level directories \
             and no manifest at its root. Put the plugin at the zip root or inside exactly \
             one top-level directory"
        )),
        _ => Err(not_a_bundle()),
    }
}

fn not_a_bundle() -> String {
    format!(
        "Not an agent plugin bundle: no manifest found at the plugin root. Expected one of {}",
        Harness::ALL
            .iter()
            .map(|h| h.marker())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Inventory the plugin components under `root`.
pub fn inventory(entries: &[BundleEntry], root: &str) -> Components {
    let mut skills = BTreeSet::new();
    let mut c = Components::default();
    for entry in entries.iter().filter(|e| e.is_file()) {
        let Some(rel) = entry.name.strip_prefix(root) else {
            continue;
        };
        let parts: Vec<&str> = rel.split('/').collect();
        match parts.as_slice() {
            ["skills", skill, "SKILL.md"] => {
                skills.insert(skill.to_string());
            }
            ["commands", .., leaf] if leaf.ends_with(".md") => c.commands += 1,
            ["agents", .., leaf] if leaf.ends_with(".md") => c.agents += 1,
            ["hooks", "hooks.json"] => c.hooks = true,
            [".mcp.json"] | ["mcp.json"] => c.mcp = true,
            [".lsp.json"] => c.lsp = true,
            ["bin", _, ..] => c.bin = true,
            _ => {}
        }
    }
    c.skills = skills.into_iter().collect();
    c
}

/// A manifest found inside the bundle, parsed.
#[derive(Debug, Clone)]
pub struct FoundManifest {
    pub harness: Harness,
    pub path: String,
    pub value: Value,
}

/// Check a manifest's `name` and `version` against the path (D5).
pub fn check_manifest_identity(
    manifest_path: &str,
    manifest: &Value,
    slug: &str,
    version: &str,
) -> std::result::Result<(), String> {
    if let Some(name) = manifest.get("name") {
        match name.as_str() {
            Some(n) if n == slug => {}
            _ => {
                return Err(format!(
                    "{manifest_path} declares name {name} but the upload path names the plugin \
                     \"{slug}\". The manifest name must equal the slug in the URL \
                     ({slug}/{version}/{slug}-{version}.zip): agents identify an installed \
                     plugin by its manifest name, so a different name would install a plugin \
                     the marketplace index does not list. Set \"name\" to \"{slug}\" or remove it"
                ))
            }
        }
    }
    if let Some(declared) = manifest.get("version") {
        match declared.as_str() {
            Some(v) if v == version => {}
            _ => {
                return Err(format!(
                    "{manifest_path} declares version {declared} but the upload path version is \
                     \"{version}\". Claude Code resolves a plugin's version from plugin.json \
                     before the marketplace entry and re-downloads only when that version \
                     changes, so a stale manifest version would leave every install on the old \
                     code. Set \"version\" to \"{version}\" in {manifest_path} or remove it"
                ))
            }
        }
    }
    Ok(())
}

/// Discover the harness manifests under `root`, reading each candidate
/// marker through `read`, and enforce D5 on every one found.
pub fn discover_manifests(
    entries: &[BundleEntry],
    root: &str,
    slug: &str,
    version: &str,
    mut read: impl FnMut(&str) -> std::result::Result<Vec<u8>, String>,
) -> std::result::Result<Vec<FoundManifest>, String> {
    let mut found = Vec::new();
    for harness in Harness::ALL {
        let rel = harness.marker();
        let full = format!("{root}{rel}");
        if !entries.iter().any(|e| e.is_file() && e.name == full) {
            continue;
        }
        let bytes = read(&full)?;
        let parsed: Option<Value> = serde_json::from_slice(&bytes).ok();
        if harness == Harness::Standard {
            // A root plugin.json is a Standard manifest only with its `$schema`;
            // any other plugin.json is ordinary plugin content.
            match parsed {
                Some(v) if v.is_object() && is_standard_manifest(&v) => {
                    check_manifest_identity(rel, &v, slug, version)?;
                    found.push(FoundManifest {
                        harness,
                        path: rel.to_string(),
                        value: v,
                    });
                }
                _ => {}
            }
            continue;
        }
        let value = match parsed {
            Some(v) if v.is_object() => v,
            _ => return Err(format!("{rel} is not a JSON object")),
        };
        check_manifest_identity(rel, &value, slug, version)?;
        found.push(FoundManifest {
            harness,
            path: rel.to_string(),
            value,
        });
    }
    if found.is_empty() {
        return Err(not_a_bundle());
    }
    Ok(found)
}

fn string_field(v: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|k| v.get(*k).and_then(Value::as_str))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn author_field(v: &Value) -> Option<Author> {
    match v.get("author")? {
        Value::String(s) if !s.trim().is_empty() => Some(Author {
            name: Some(s.trim().to_string()),
            ..Author::default()
        }),
        obj @ Value::Object(_) => {
            let author = Author {
                name: string_field(obj, &["name"]),
                email: string_field(obj, &["email"]),
                url: string_field(obj, &["url"]),
            };
            (author != Author::default()).then_some(author)
        }
        _ => None,
    }
}

fn repository_field(v: &Value) -> Option<String> {
    match v.get("repository")? {
        Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
        obj @ Value::Object(_) => string_field(obj, &["url"]),
        _ => None,
    }
}

fn keywords_field(v: &Value) -> Vec<String> {
    v.get("keywords")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Build the recorded metadata from the discovered manifests.
pub fn build_metadata(
    slug: &str,
    version: &str,
    root: &str,
    manifests: &[FoundManifest],
    entries: &[BundleEntry],
) -> PluginMetadata {
    let primary = manifests.first().map(|m| &m.value).unwrap_or(&Value::Null);
    let mut components = inventory(entries, root);
    // Claude Code also accepts hooks / MCP / LSP servers inline in plugin.json.
    for m in manifests {
        components.hooks |= m.value.get("hooks").is_some();
        components.mcp |= m.value.get("mcpServers").is_some();
        components.lsp |= m.value.get("lspServers").is_some();
    }
    PluginMetadata {
        name: slug.to_string(),
        version: version.to_string(),
        harnesses: manifests
            .iter()
            .map(|m| m.harness.as_str().to_string())
            .collect(),
        manifest_paths: manifests.iter().map(|m| m.path.clone()).collect(),
        root_prefix: root.to_string(),
        description: string_field(primary, &["description"]),
        display_name: string_field(primary, &["displayName", "display_name", "title"]),
        author: author_field(primary),
        homepage: string_field(primary, &["homepage"]),
        repository: repository_field(primary),
        license: string_field(primary, &["license"]),
        keywords: keywords_field(primary),
        components,
        sha256: String::new(),
        size_bytes: 0,
    }
}

/// Analyse a bundle described by its entries, reading manifests through
/// `read`. Refuses unsafe entries and symlinks (D11).
pub fn analyze_entries(
    entries: &[BundleEntry],
    slug: &str,
    version: &str,
    read: impl FnMut(&str) -> std::result::Result<Vec<u8>, String>,
) -> std::result::Result<PluginMetadata, String> {
    for entry in entries {
        if bounded_archive::is_unsafe_archive_entry_name(&entry.name) {
            let shown: String = entry.name.chars().take(200).collect();
            return Err(format!(
                "ZIP archive entry {shown:?} is an absolute path or escapes the archive root"
            ));
        }
        if entry.name.contains('\\') {
            let shown: String = entry.name.chars().take(200).collect();
            return Err(format!(
                "ZIP archive entry {shown:?} contains a backslash; use '/' as the separator"
            ));
        }
        if entry.is_symlink {
            let shown: String = entry.name.chars().take(200).collect();
            return Err(format!(
                "ZIP archive entry {shown:?} is a symbolic link; plugin bundles may not contain links"
            ));
        }
    }
    let root = detect_root(entries)?;
    let manifests = discover_manifests(entries, &root, slug, version, read)?;
    Ok(build_metadata(slug, version, &root, &manifests, entries))
}

/// Open a zip and analyse it as a plugin bundle. Bounded: the entry count
/// and the declared uncompressed total are checked against the ingest caps
/// before anything is inflated, and only manifest files are ever read.
/// Callers hold an ingest-extraction permit.
pub fn analyze_zip<R: Read + Seek>(
    reader: R,
    slug: &str,
    version: &str,
) -> std::result::Result<PluginMetadata, String> {
    let mut archive =
        zip::ZipArchive::new(reader).map_err(|e| format!("Invalid ZIP archive: {e}"))?;
    bounded_archive::reject_unsafe_zip_entry_names(&archive).map_err(validation_message)?;
    if archive.has_duplicate_names() {
        return Err("ZIP archive contains duplicate entry names".to_string());
    }
    let max_total = bounded_archive::max_ingest_decompressed_bytes();
    let mut total: u64 = 0;
    let mut entries = Vec::with_capacity(archive.len());
    for i in 0..archive.len() {
        let entry = archive
            .by_index_data(i)
            .map_err(|e| format!("Cannot read ZIP entry {i}: {e}"))?;
        let name = entry
            .name()
            .map_err(|e| format!("ZIP archive entry {i} has an undecodable name: {e}"))?
            .to_string();
        total = total.saturating_add(entry.size());
        entries.push(BundleEntry {
            name,
            is_dir: entry.is_dir(),
            is_symlink: entry.is_symlink(),
        });
    }
    if total > max_total {
        return Err(format!(
            "ZIP archive expands to more than {max_total} bytes; refusing suspected decompression bomb"
        ));
    }
    analyze_entries(&entries, slug, version, |name| {
        let mut file = archive
            .by_name(name)
            .map_err(|e| format!("Cannot read {name}: {e}"))?;
        if file.size() > MAX_MANIFEST_BYTES {
            return Err(format!(
                "{name} exceeds the maximum manifest size of {MAX_MANIFEST_BYTES} bytes"
            ));
        }
        bounded_archive::read_capped(&mut file, MAX_MANIFEST_BYTES, name)
            .map_err(validation_message)
    })
}

fn validation_message(e: AppError) -> String {
    match e {
        AppError::Validation(msg) => msg,
        other => other.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Marketplace documents
// ---------------------------------------------------------------------------

/// One generated index document per variant (section 5 of the design).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Marketplace {
    All,
    Claude,
    Cursor,
    Codex,
    Vscode,
}

impl Marketplace {
    pub const ALL: [Marketplace; 5] = [
        Marketplace::All,
        Marketplace::Claude,
        Marketplace::Cursor,
        Marketplace::Codex,
        Marketplace::Vscode,
    ];

    pub fn file_name(self) -> &'static str {
        match self {
            Marketplace::All => "marketplace.json",
            Marketplace::Claude => "claude-marketplace.json",
            Marketplace::Cursor => "cursor-marketplace.json",
            Marketplace::Codex => "codex-marketplace.json",
            Marketplace::Vscode => "vscode-marketplace.json",
        }
    }

    /// The key this document has in a publish response's `marketplaces`.
    pub fn response_key(self) -> &'static str {
        match self {
            Marketplace::All => "all",
            Marketplace::Claude => "claude",
            Marketplace::Cursor => "cursor",
            Marketplace::Codex => "codex",
            Marketplace::Vscode => "vscode",
        }
    }

    /// Whether a plugin tagged with `harnesses` belongs in this document.
    pub fn includes(self, harnesses: &[String]) -> bool {
        let has = |h: Harness| harnesses.iter().any(|x| x == h.as_str());
        match self {
            Marketplace::All => true,
            Marketplace::Claude => has(Harness::Claude) || has(Harness::Standard),
            Marketplace::Cursor => has(Harness::Cursor) || has(Harness::Standard),
            Marketplace::Codex => has(Harness::Codex) || has(Harness::Standard),
            Marketplace::Vscode => has(Harness::Standard),
        }
    }
}

/// Derive the Claude Code marketplace `name` from a repository key.
///
/// Repository keys are already restricted (`validate_repository_key`: ASCII
/// alphanumerics, `-`, `_`, `.`, no leading `.` or `-`, no `..`), so the key
/// is used unchanged except: a key whose first character is not a letter or
/// digit (a leading `_`) gets an `ak-` prefix, and a key equal to a name
/// Claude Code reserves, or starting with `claudeai-`, gets an `-ak` suffix.
/// The web UI computes the same string for its `claude plugin install
/// <plugin>@<name>` hint, so this rule is pinned (section 7.2 of the design).
pub fn sanitize_marketplace_name(key: &str) -> String {
    let mut name = if key
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
    {
        key.to_string()
    } else {
        format!("ak-{key}")
    };
    if RESERVED_MARKETPLACE_NAMES.contains(&name.as_str()) || name.starts_with("claudeai-") {
        name.push_str("-ak");
    }
    name
}

/// Where the generated documents live and how their URLs are built.
#[derive(Debug, Clone)]
pub struct IndexContext {
    pub repo_key: String,
    pub description: Option<String>,
    /// Scheme, host and port, e.g. `https://ak.example.com`.
    pub origin: String,
    /// Read token embedded in the path (`/agentplugins/t/{token}/...`), if
    /// the documents are served through the token route (D8).
    pub token: Option<String>,
}

impl IndexContext {
    /// `{origin}/agentplugins[/t/{token}]/{repo}`, the prefix of every URL.
    pub fn repo_base(&self) -> String {
        let repo = urlencoding::encode(&self.repo_key);
        match &self.token {
            Some(t) => format!(
                "{}/{FORMAT_KEY}/t/{}/{repo}",
                self.origin,
                urlencoding::encode(t)
            ),
            None => format!("{}/{FORMAT_KEY}/{repo}", self.origin),
        }
    }

    pub fn download_url(&self, name: &str, version: &str) -> String {
        format!("{}/{}", self.repo_base(), artifact_path(name, version))
    }

    pub fn versions_url(&self, name: &str) -> String {
        format!("{}/{name}/index.json", self.repo_base())
    }

    pub fn marketplace_url(&self, kind: Marketplace) -> String {
        format!("{}/{}", self.repo_base(), kind.file_name())
    }

    /// The `marketplaces` object of a publish response.
    pub fn marketplace_urls(&self) -> Value {
        let mut out = Map::new();
        for kind in [
            Marketplace::Claude,
            Marketplace::Cursor,
            Marketplace::Codex,
            Marketplace::Vscode,
            Marketplace::All,
        ] {
            out.insert(
                kind.response_key().to_string(),
                Value::String(self.marketplace_url(kind)),
            );
        }
        Value::Object(out)
    }
}

/// One published, servable version, as the documents are built from it.
#[derive(Debug, Clone)]
pub struct IndexedVersion {
    pub name: String,
    pub version: String,
    pub sha256: String,
    pub size_bytes: i64,
    pub published_at: DateTime<Utc>,
    pub metadata: PluginMetadata,
}

/// The latest SemVer version of each plugin, sorted by plugin name.
pub fn latest_per_plugin(versions: &[IndexedVersion]) -> Vec<&IndexedVersion> {
    let mut latest: BTreeMap<&str, &IndexedVersion> = BTreeMap::new();
    for v in versions {
        latest
            .entry(v.name.as_str())
            .and_modify(|cur| {
                if compare_versions(&v.version, &cur.version).is_gt() {
                    *cur = v;
                }
            })
            .or_insert(v);
    }
    latest.into_values().collect()
}

fn timestamp(t: &DateTime<Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn insert_opt(obj: &mut Map<String, Value>, key: &str, value: Option<Value>) {
    if let Some(v) = value {
        obj.insert(key.to_string(), v);
    }
}

/// One `plugins[]` entry: a Claude Code `archive` source plus AK metadata
/// under `metadata`, which Claude Code documents as never read.
fn plugin_entry(ctx: &IndexContext, v: &IndexedVersion) -> Value {
    let m = &v.metadata;
    let mut entry = Map::new();
    entry.insert("name".into(), json!(v.name));
    insert_opt(
        &mut entry,
        "description",
        m.description.clone().map(Value::from),
    );
    entry.insert("version".into(), json!(v.version));
    insert_opt(&mut entry, "author", m.author.as_ref().map(|a| json!(a)));
    insert_opt(&mut entry, "homepage", m.homepage.clone().map(Value::from));
    insert_opt(
        &mut entry,
        "repository",
        m.repository.clone().map(Value::from),
    );
    insert_opt(&mut entry, "license", m.license.clone().map(Value::from));
    if !m.keywords.is_empty() {
        entry.insert("keywords".into(), json!(m.keywords));
    }
    entry.insert(
        "source".into(),
        json!({
            "source": "archive",
            "url": ctx.download_url(&v.name, &v.version),
            "sha256": v.sha256,
        }),
    );
    entry.insert(
        "metadata".into(),
        json!({
            "harnesses": m.harnesses,
            "size_bytes": v.size_bytes,
            "published_at": timestamp(&v.published_at),
            "versions_url": ctx.versions_url(&v.name),
            "components": m.components,
        }),
    );
    Value::Object(entry)
}

/// Build one marketplace document from the servable versions.
///
/// One generator serves all five variants: `marketplace.json` carries the AK
/// `$schema`, the per-harness documents omit it and keep only the plugins
/// section 5 of the design assigns them. `generated_at` is the publish time
/// of the newest version listed, so the body (and its ETag) only changes when
/// the listed data does.
pub fn build_marketplace(
    kind: Marketplace,
    ctx: &IndexContext,
    versions: &[IndexedVersion],
) -> Value {
    let listed: Vec<&IndexedVersion> = latest_per_plugin(versions)
        .into_iter()
        .filter(|v| kind.includes(&v.metadata.harnesses))
        .collect();
    let generated_at = listed.iter().map(|v| v.published_at).max();
    let mut doc = Map::new();
    if kind == Marketplace::All {
        doc.insert("$schema".into(), json!(UNIFIED_SCHEMA));
    }
    doc.insert(
        "name".into(),
        json!(sanitize_marketplace_name(&ctx.repo_key)),
    );
    let description = ctx
        .description
        .clone()
        .filter(|d| !d.trim().is_empty())
        .unwrap_or_else(|| format!("Agent plugins hosted in {}", ctx.repo_key));
    doc.insert("description".into(), json!(description));
    doc.insert(
        "owner".into(),
        json!({ "name": OWNER_NAME, "url": ctx.origin }),
    );
    doc.insert(
        "metadata".into(),
        json!({
            "generated_at": generated_at.as_ref().map(timestamp),
            "repository": ctx.repo_key,
            "plugin_count": listed.len(),
        }),
    );
    doc.insert(
        "plugins".into(),
        Value::Array(listed.iter().map(|v| plugin_entry(ctx, v)).collect()),
    );
    Value::Object(doc)
}

/// Build `{name}/index.json`: every servable version of one plugin, newest
/// first. `None` when the plugin has no servable version.
pub fn build_versions_index(
    name: &str,
    ctx: &IndexContext,
    versions: &[IndexedVersion],
) -> Option<Value> {
    let mut mine: Vec<&IndexedVersion> = versions.iter().filter(|v| v.name == name).collect();
    if mine.is_empty() {
        return None;
    }
    mine.sort_by(|a, b| compare_versions(&b.version, &a.version));
    let entries: Vec<Value> = mine
        .iter()
        .map(|v| {
            json!({
                "version": v.version,
                "sha256": v.sha256,
                "size_bytes": v.size_bytes,
                "harnesses": v.metadata.harnesses,
                "published_at": timestamp(&v.published_at),
                "url": ctx.download_url(&v.name, &v.version),
            })
        })
        .collect();
    Some(json!({
        "name": name,
        "latest": mine[0].version,
        "versions": entries,
    }))
}

/// A strong ETag over a serialised document.
pub fn document_etag(body: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("\"{:x}\"", Sha256::digest(body))
}

/// Whether an `If-None-Match` header value matches `etag` (weak comparison,
/// `*` and comma-separated lists accepted).
pub fn if_none_match_matches(header: &str, etag: &str) -> bool {
    let bare = etag.trim_start_matches("W/");
    header
        .split(',')
        .map(str::trim)
        .any(|candidate| candidate == "*" || candidate.trim_start_matches("W/") == bare)
}

// ---------------------------------------------------------------------------
// FormatHandler
// ---------------------------------------------------------------------------

/// Split `{name}/{version}/{file}` into its three coordinates.
pub fn split_artifact_path(path: &str) -> std::result::Result<(String, String, String), String> {
    let trimmed = path.trim_start_matches('/');
    let parts: Vec<&str> = trimmed.split('/').collect();
    match parts.as_slice() {
        [name, version, file] => Ok((name.to_string(), version.to_string(), file.to_string())),
        _ => Err(format!(
            "Invalid agent plugin path {path:?}: expected {{name}}/{{version}}/{{name}}-{{version}}.zip"
        )),
    }
}

/// Agent Plugins format handler.
pub struct AgentPluginsHandler;

impl AgentPluginsHandler {
    pub fn new() -> Self {
        Self
    }

    fn inspect(path: &str, content: &Bytes) -> Result<PluginMetadata> {
        let (name, version, file) = split_artifact_path(path).map_err(AppError::Validation)?;
        validate_coordinates(&name, &version, &file).map_err(AppError::Validation)?;
        analyze_zip(std::io::Cursor::new(content.as_ref()), &name, &version)
            .map_err(AppError::Validation)
    }
}

impl Default for AgentPluginsHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for AgentPluginsHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::AgentPlugins
    }

    async fn parse_metadata(&self, path: &str, content: &Bytes) -> Result<Value> {
        let mut meta = Self::inspect(path, content)?;
        {
            use sha2::{Digest, Sha256};
            meta.sha256 = format!("{:x}", Sha256::digest(content));
        }
        meta.size_bytes = content.len() as i64;
        Ok(serde_json::to_value(meta).unwrap_or_else(|_| json!({})))
    }

    async fn validate(&self, path: &str, content: &Bytes) -> Result<()> {
        Self::inspect(path, content).map(|_| ())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        Ok(None)
    }
}

/// Build a zip from `(name, bytes)` pairs. Test fixture builder shared by
/// the handler's inline tests.
#[cfg(test)]
pub(crate) fn test_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write;
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut w = zip::ZipWriter::new(&mut buf);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, bytes) in files {
            if name.ends_with('/') {
                w.add_directory(name.trim_end_matches('/'), opts).unwrap();
            } else {
                w.start_file(*name, opts).unwrap();
                w.write_all(bytes).unwrap();
            }
        }
        w.finish().unwrap();
    }
    buf.into_inner()
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    fn entries(names: &[&str]) -> Vec<BundleEntry> {
        names
            .iter()
            .map(|n| BundleEntry {
                name: n.to_string(),
                is_dir: n.ends_with('/'),
                is_symlink: false,
            })
            .collect()
    }

    fn reader_for(
        files: &'static [(&'static str, &'static str)],
    ) -> impl FnMut(&str) -> std::result::Result<Vec<u8>, String> {
        move |name| {
            files
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, b)| b.as_bytes().to_vec())
                .ok_or_else(|| format!("missing {name}"))
        }
    }

    // ---- slug / semver / filename ----------------------------------------

    #[test]
    fn slug_rules() {
        for ok in ["a", "deploy-tools", "0x", "a-b-c-1", &"a".repeat(64)] {
            assert!(validate_slug(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "-a",
            "A",
            "deploy_tools",
            "a.b",
            "a/b",
            "é",
            &"a".repeat(65),
        ] {
            assert!(validate_slug(bad).is_err(), "{bad}");
        }
        assert!(validate_slug(&"a".repeat(65))
            .unwrap_err()
            .contains("at most 64"));
    }

    #[test]
    fn semver_is_strict() {
        for ok in ["1.2.0", "0.0.1", "2.0.0-rc.1", "1.0.0+build.5"] {
            assert!(parse_semver(ok).is_ok(), "{ok}");
        }
        for bad in ["v1.2.0", "1.2", "01.2.0", "1.2.0.0", "latest", ""] {
            assert!(parse_semver(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn coordinates_require_matching_filename() {
        assert!(validate_coordinates("p", "1.0.0", "p-1.0.0.zip").is_ok());
        let err = validate_coordinates("p", "1.0.0", "q-1.0.0.zip").unwrap_err();
        assert!(err.contains("\"p-1.0.0.zip\""), "{err}");
        assert!(validate_coordinates("p", "1.0", "p-1.0.zip").is_err());
        assert!(validate_coordinates("P", "1.0.0", "P-1.0.0.zip").is_err());
        assert_eq!(artifact_path("p", "1.0.0"), "p/1.0.0/p-1.0.0.zip");
    }

    #[test]
    fn version_ordering_follows_semver_precedence() {
        use std::cmp::Ordering::*;
        assert_eq!(compare_versions("2.0.0-rc.1", "2.0.0"), Less);
        assert_eq!(compare_versions("1.10.0", "1.9.0"), Greater);
        assert_eq!(compare_versions("2.0.0-rc.2", "2.0.0-rc.10"), Less);
        assert_eq!(compare_versions("1.0.0", "junk"), Greater);
        assert_eq!(compare_versions("junk", "1.0.0"), Less);
        assert_eq!(compare_versions("a", "b"), Less);
    }

    // ---- root detection ------------------------------------------------------

    #[test]
    fn root_at_zip_top() {
        let e = entries(&[".claude-plugin/plugin.json", "commands/a.md"]);
        assert_eq!(detect_root(&e).unwrap(), "");
        let e = entries(&["plugin.json", "skills/x/SKILL.md"]);
        assert_eq!(detect_root(&e).unwrap(), "");
    }

    #[test]
    fn root_one_directory_down() {
        let e = entries(&[
            "deploy-tools/",
            "deploy-tools/.claude-plugin/plugin.json",
            "__MACOSX/._x",
            ".DS_Store",
        ]);
        assert_eq!(detect_root(&e).unwrap(), "deploy-tools/");
    }

    #[test]
    fn root_ambiguous_and_missing() {
        let e = entries(&["a/.claude-plugin/plugin.json", "b/plugin.json"]);
        let err = detect_root(&e).unwrap_err();
        assert!(err.contains("cannot be determined"), "{err}");
        let e = entries(&["README.md"]);
        assert!(detect_root(&e).unwrap_err().contains("Not an agent plugin"));
        let e = entries(&["README.md", "a/plugin.json"]);
        assert!(detect_root(&e).unwrap_err().contains("Not an agent plugin"));
        assert!(detect_root(&[]).is_err());
    }

    // ---- manifest discovery ----------------------------------------------------

    #[test]
    fn each_marker_is_tagged() {
        const FILES: &[(&str, &str)] = &[
            (".claude-plugin/plugin.json", r#"{"name":"p"}"#),
            (
                "plugin.json",
                r#"{"$schema":"https://agent-plugins.org/schemas/plugin-1.0.0.json","name":"p"}"#,
            ),
            (".cursor-plugin/plugin.json", r#"{"name":"p"}"#),
            (".codex-plugin/plugin.json", r#"{}"#),
            ("gemini-extension.json", r#"{"version":"1.0.0"}"#),
        ];
        let e = entries(&FILES.iter().map(|(n, _)| *n).collect::<Vec<_>>());
        let meta = analyze_entries(&e, "p", "1.0.0", reader_for(FILES)).unwrap();
        assert_eq!(
            meta.harnesses,
            vec!["claude", "standard", "cursor", "codex", "gemini"]
        );
        assert_eq!(meta.manifest_paths[1], "plugin.json");
        assert_eq!(meta.root_prefix, "");
    }

    #[test]
    fn plain_plugin_json_is_not_standard() {
        const FILES: &[(&str, &str)] = &[
            ("plugin.json", r#"{"name":"p"}"#),
            (".cursor-plugin/plugin.json", r#"{"name":"p"}"#),
        ];
        let e = entries(&["plugin.json", ".cursor-plugin/plugin.json"]);
        let meta = analyze_entries(&e, "p", "1.0.0", reader_for(FILES)).unwrap();
        assert_eq!(meta.harnesses, vec!["cursor"]);

        const ONLY: &[(&str, &str)] = &[("plugin.json", r#"[1]"#)];
        let err = analyze_entries(&entries(&["plugin.json"]), "p", "1.0.0", reader_for(ONLY))
            .unwrap_err();
        assert!(err.contains("Not an agent plugin bundle"), "{err}");
    }

    #[test]
    fn standard_schema_detection() {
        assert!(is_standard_manifest(
            &json!({"$schema": "https://agent-plugins.org/schemas/plugin-1.1.0.json"})
        ));
        assert!(!is_standard_manifest(
            &json!({"$schema": "https://example.com/agent-plugins.org/schemas/"})
        ));
        assert!(!is_standard_manifest(&json!({"$schema": 1})));
        assert!(!is_standard_manifest(&json!({})));
    }

    #[test]
    fn non_object_manifest_is_refused() {
        const FILES: &[(&str, &str)] = &[(".claude-plugin/plugin.json", "[]")];
        let err = analyze_entries(
            &entries(&[".claude-plugin/plugin.json"]),
            "p",
            "1.0.0",
            reader_for(FILES),
        )
        .unwrap_err();
        assert_eq!(err, ".claude-plugin/plugin.json is not a JSON object");
        const BAD: &[(&str, &str)] = &[(".codex-plugin/plugin.json", "{nope")];
        assert!(analyze_entries(
            &entries(&[".codex-plugin/plugin.json"]),
            "p",
            "1.0.0",
            reader_for(BAD)
        )
        .is_err());
    }

    #[test]
    fn d5_name_conflict_message() {
        let err = check_manifest_identity("plugin.json", &json!({"name": "other"}), "p", "1.0.0")
            .unwrap_err();
        assert!(
            err.starts_with("plugin.json declares name \"other\""),
            "{err}"
        );
        assert!(err.contains("must equal the slug in the URL"), "{err}");
        assert!(err.contains("p/1.0.0/p-1.0.0.zip"), "{err}");
        // A non-string name conflicts too.
        assert!(check_manifest_identity("x", &json!({"name": 3}), "p", "1.0.0").is_err());
    }

    #[test]
    fn d5_version_conflict_message() {
        let err = check_manifest_identity(
            ".claude-plugin/plugin.json",
            &json!({"name": "p", "version": "1.1.0"}),
            "p",
            "1.2.0",
        )
        .unwrap_err();
        assert!(
            err.starts_with(".claude-plugin/plugin.json declares version \"1.1.0\""),
            "{err}"
        );
        assert!(err.contains("Claude Code resolves a plugin's version from plugin.json"));
        assert!(err.contains("Set \"version\" to \"1.2.0\""));
        assert!(check_manifest_identity("x", &json!({"version": "1.2.0"}), "p", "1.2.0").is_ok());
        assert!(check_manifest_identity("x", &json!({}), "p", "1.2.0").is_ok());
    }

    #[test]
    fn unsafe_entries_are_refused() {
        let ok = |_: &str| Ok(br#"{}"#.to_vec());
        for bad in ["../x", "/abs", "a/../../b", "C:/x"] {
            let e = entries(&[".claude-plugin/plugin.json", bad]);
            assert!(analyze_entries(&e, "p", "1.0.0", ok).is_err(), "{bad}");
        }
        let e = entries(&[".claude-plugin/plugin.json", "a\\b"]);
        assert!(analyze_entries(&e, "p", "1.0.0", ok)
            .unwrap_err()
            .contains("backslash"));
        let mut e = entries(&[".claude-plugin/plugin.json"]);
        e.push(BundleEntry {
            name: "bin/tool".into(),
            is_dir: false,
            is_symlink: true,
        });
        assert!(analyze_entries(&e, "p", "1.0.0", ok)
            .unwrap_err()
            .contains("symbolic link"));
    }

    // ---- components and metadata -------------------------------------------

    #[test]
    fn component_inventory() {
        let e = entries(&[
            "root/skills/deploy/SKILL.md",
            "root/skills/rollback/SKILL.md",
            "root/skills/notes/README.md",
            "root/commands/a.md",
            "root/commands/ns/b.md",
            "root/commands/c.txt",
            "root/agents/reviewer.md",
            "root/hooks/hooks.json",
            "root/.mcp.json",
            "root/.lsp.json",
            "root/bin/tool",
            "root/bin/",
            "other/skills/x/SKILL.md",
        ]);
        let c = inventory(&e, "root/");
        assert_eq!(c.skills, vec!["deploy", "rollback"]);
        assert_eq!((c.commands, c.agents), (2, 1));
        assert!(c.hooks && c.mcp && c.lsp && c.bin);

        let c = inventory(&entries(&["mcp.json"]), "");
        assert!(c.mcp && !c.hooks && !c.lsp && !c.bin);
    }

    #[test]
    fn metadata_from_first_manifest() {
        const FILES: &[(&str, &str)] = &[
            (
                ".claude-plugin/plugin.json",
                r#"{"name":"p","version":"1.0.0","description":" Deploy ","displayName":"Deploy",
                    "author":{"name":"Team","email":"t@example.com"},"homepage":"https://h",
                    "repository":{"url":"https://r"},"license":"MIT","keywords":["a",1,"b"],
                    "hooks":{"PreToolUse":[]}}"#,
            ),
            (
                ".cursor-plugin/plugin.json",
                r#"{"description":"ignored","mcpServers":{}}"#,
            ),
        ];
        let e = entries(&[".claude-plugin/plugin.json", ".cursor-plugin/plugin.json"]);
        let m = analyze_entries(&e, "p", "1.0.0", reader_for(FILES)).unwrap();
        assert_eq!(m.description.as_deref(), Some("Deploy"));
        assert_eq!(m.display_name.as_deref(), Some("Deploy"));
        let author = m.author.clone().unwrap();
        assert_eq!(author.name.as_deref(), Some("Team"));
        assert_eq!(author.url, None);
        assert_eq!(m.repository.as_deref(), Some("https://r"));
        assert_eq!(m.keywords, vec!["a", "b"]);
        assert!(m.components.hooks && m.components.mcp && !m.components.lsp);

        // Round trip through the stored JSON.
        let stored = serde_json::to_value(&m).unwrap();
        let back: PluginMetadata = serde_json::from_value(stored).unwrap();
        assert_eq!(back, m);
        // Defaults for a sparse row.
        let sparse: PluginMetadata = serde_json::from_value(json!({"name": "x"})).unwrap();
        assert!(sparse.harnesses.is_empty());
    }

    #[test]
    fn author_and_repository_shapes() {
        assert_eq!(
            author_field(&json!({"author": "Jane"}))
                .unwrap()
                .name
                .as_deref(),
            Some("Jane")
        );
        assert!(author_field(&json!({"author": {}})).is_none());
        assert!(author_field(&json!({"author": 5})).is_none());
        assert_eq!(
            repository_field(&json!({"repository": "https://x"})).as_deref(),
            Some("https://x")
        );
        assert!(repository_field(&json!({"repository": []})).is_none());
    }

    // ---- real zips -------------------------------------------------------------

    #[test]
    fn analyze_zip_claude_layout_under_top_dir() {
        let zip = test_zip(&[
            ("deploy-tools/", b""),
            (
                "deploy-tools/.claude-plugin/plugin.json",
                br#"{"name":"deploy-tools","version":"1.2.0"}"#,
            ),
            ("deploy-tools/skills/deploy/SKILL.md", b"# deploy"),
        ]);
        let m = analyze_zip(std::io::Cursor::new(zip), "deploy-tools", "1.2.0").unwrap();
        assert_eq!(m.root_prefix, "deploy-tools/");
        assert_eq!(m.harnesses, vec!["claude"]);
        assert_eq!(m.components.skills, vec!["deploy"]);
    }

    #[test]
    fn analyze_zip_refusals() {
        assert!(
            analyze_zip(std::io::Cursor::new(b"not a zip".to_vec()), "p", "1.0.0")
                .unwrap_err()
                .starts_with("Invalid ZIP archive")
        );
        let traversal = test_zip(&[(".claude-plugin/plugin.json", b"{}"), ("../evil", b"x")]);
        assert!(analyze_zip(std::io::Cursor::new(traversal), "p", "1.0.0")
            .unwrap_err()
            .contains("escapes the archive root"));
        let conflict = test_zip(&[(".claude-plugin/plugin.json", br#"{"version":"9.9.9"}"#)]);
        assert!(analyze_zip(std::io::Cursor::new(conflict), "p", "1.0.0")
            .unwrap_err()
            .contains("declares version"));
    }

    #[tokio::test]
    async fn format_handler_contract() {
        let h = AgentPluginsHandler::new();
        assert_eq!(h.format_key(), "agentplugins");
        assert_eq!(h.format(), RepositoryFormat::AgentPlugins);
        let zip = Bytes::from(test_zip(&[(
            "plugin.json",
            br#"{"$schema":"https://agent-plugins.org/schemas/plugin-1.0.0.json","name":"p"}"#,
        )]));
        assert!(h.validate("p/1.0.0/p-1.0.0.zip", &zip).await.is_ok());
        assert!(h.validate("p/1.0.0/q.zip", &zip).await.is_err());
        assert!(h.validate("p/1.0.0", &zip).await.is_err());
        let meta = h
            .parse_metadata("/p/1.0.0/p-1.0.0.zip", &zip)
            .await
            .unwrap();
        assert_eq!(meta["harnesses"], json!(["standard"]));
        assert_eq!(meta["sha256"].as_str().unwrap().len(), 64);
        assert_eq!(meta["size_bytes"], json!(zip.len()));
        assert!(h.generate_index().await.unwrap().is_none());
        let via_default: Box<dyn FormatHandler> = Box::<AgentPluginsHandler>::default();
        assert!(via_default.validate("x", &zip).await.is_err());
    }

    // ---- documents --------------------------------------------------------------

    fn ctx(token: Option<&str>) -> IndexContext {
        IndexContext {
            repo_key: "plugins".into(),
            description: None,
            origin: "https://ak.example.com".into(),
            token: token.map(str::to_string),
        }
    }

    fn version(name: &str, v: &str, harnesses: &[&str], minute: u32) -> IndexedVersion {
        IndexedVersion {
            name: name.into(),
            version: v.into(),
            sha256: format!("{name}{v}"),
            size_bytes: 10,
            published_at: chrono::TimeZone::with_ymd_and_hms(&Utc, 2026, 11, 3, 18, minute, 0)
                .unwrap(),
            metadata: PluginMetadata {
                name: name.into(),
                version: v.into(),
                harnesses: harnesses.iter().map(|h| h.to_string()).collect(),
                description: Some(format!("{name} plugin")),
                keywords: vec!["k".into()],
                ..PluginMetadata::default()
            },
        }
    }

    fn fixture_versions() -> Vec<IndexedVersion> {
        vec![
            version("alpha", "1.0.0", &["claude"], 1),
            version("alpha", "2.0.0-rc.1", &["claude"], 2),
            version("alpha", "1.9.0", &["claude"], 3),
            version("std", "0.1.0", &["standard"], 4),
            version("cur", "1.0.0", &["cursor"], 5),
            version("cdx", "1.0.0", &["codex"], 6),
            version("gem", "1.0.0", &["gemini"], 7),
        ]
    }

    fn names(doc: &Value) -> Vec<String> {
        doc["plugins"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["name"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn latest_selection_honours_prerelease_ordering() {
        let vs = fixture_versions();
        let latest = latest_per_plugin(&vs);
        let alpha = latest.iter().find(|v| v.name == "alpha").unwrap();
        assert_eq!(alpha.version, "2.0.0-rc.1");
        let mut with_final = vs.clone();
        with_final.push(version("alpha", "2.0.0", &["claude"], 0));
        let latest = latest_per_plugin(&with_final);
        assert_eq!(
            latest.iter().find(|v| v.name == "alpha").unwrap().version,
            "2.0.0"
        );
    }

    #[test]
    fn membership_per_document() {
        let vs = fixture_versions();
        let c = ctx(None);
        let doc = |k| names(&build_marketplace(k, &c, &vs));
        assert_eq!(
            doc(Marketplace::All),
            vec!["alpha", "cdx", "cur", "gem", "std"]
        );
        assert_eq!(doc(Marketplace::Claude), vec!["alpha", "std"]);
        assert_eq!(doc(Marketplace::Cursor), vec!["cur", "std"]);
        assert_eq!(doc(Marketplace::Codex), vec!["cdx", "std"]);
        assert_eq!(doc(Marketplace::Vscode), vec!["std"]);
    }

    #[test]
    fn unified_document_shape() {
        let vs = fixture_versions();
        let doc = build_marketplace(Marketplace::All, &ctx(None), &vs);
        assert_eq!(doc["$schema"], UNIFIED_SCHEMA);
        assert_eq!(doc["name"], "plugins");
        assert_eq!(doc["description"], "Agent plugins hosted in plugins");
        assert_eq!(doc["owner"]["name"], OWNER_NAME);
        assert_eq!(doc["owner"]["url"], "https://ak.example.com");
        assert_eq!(doc["metadata"]["plugin_count"], 5);
        assert_eq!(doc["metadata"]["repository"], "plugins");
        assert_eq!(doc["metadata"]["generated_at"], "2026-11-03T18:07:00Z");
        let alpha = &doc["plugins"][0];
        assert_eq!(alpha["version"], "2.0.0-rc.1");
        assert_eq!(alpha["source"]["source"], "archive");
        assert_eq!(
            alpha["source"]["url"],
            "https://ak.example.com/agentplugins/plugins/alpha/2.0.0-rc.1/alpha-2.0.0-rc.1.zip"
        );
        assert_eq!(alpha["source"]["sha256"], "alpha2.0.0-rc.1");
        assert_eq!(
            alpha["metadata"]["versions_url"],
            "https://ak.example.com/agentplugins/plugins/alpha/index.json"
        );
        assert_eq!(alpha["metadata"]["published_at"], "2026-11-03T18:02:00Z");
        assert_eq!(alpha["keywords"], json!(["k"]));
        // Absent optional fields are omitted, never null.
        assert!(alpha.get("license").is_none());
        assert!(alpha.get("author").is_none());
    }

    #[test]
    fn harness_documents_omit_schema_and_sanitise_name() {
        let mut c = ctx(None);
        c.repo_key = "_team".into();
        c.description = Some("Team plugins".into());
        let doc = build_marketplace(Marketplace::Claude, &c, &[]);
        assert!(doc.get("$schema").is_none());
        assert_eq!(doc["name"], "ak-_team");
        assert_eq!(doc["description"], "Team plugins");
        assert_eq!(doc["plugins"], json!([]));
        assert_eq!(doc["metadata"]["generated_at"], Value::Null);
    }

    #[test]
    fn marketplace_name_sanitisation() {
        assert_eq!(sanitize_marketplace_name("plugins"), "plugins");
        assert_eq!(sanitize_marketplace_name("my.plugins_v2"), "my.plugins_v2");
        assert_eq!(sanitize_marketplace_name("_private"), "ak-_private");
        assert_eq!(sanitize_marketplace_name("npm"), "npm-ak");
        assert_eq!(sanitize_marketplace_name("claudeai-x"), "claudeai-x-ak");
        assert_eq!(
            sanitize_marketplace_name("claude-plugins-official"),
            "claude-plugins-official-ak"
        );
        assert_eq!(sanitize_marketplace_name("npm-internal"), "npm-internal");
    }

    #[test]
    fn token_prefix_is_kept_in_every_url() {
        let c = ctx(Some("tok/en"));
        assert_eq!(
            c.download_url("p", "1.0.0"),
            "https://ak.example.com/agentplugins/t/tok%2Fen/plugins/p/1.0.0/p-1.0.0.zip"
        );
        let doc = build_marketplace(Marketplace::All, &c, &fixture_versions());
        assert!(doc["plugins"][0]["source"]["url"]
            .as_str()
            .unwrap()
            .starts_with("https://ak.example.com/agentplugins/t/tok%2Fen/plugins/"));
        let urls = c.marketplace_urls();
        assert_eq!(
            urls["claude"],
            "https://ak.example.com/agentplugins/t/tok%2Fen/plugins/claude-marketplace.json"
        );
        assert_eq!(urls.as_object().unwrap().len(), 5);
        assert!(urls["all"].as_str().unwrap().ends_with("/marketplace.json"));
    }

    #[test]
    fn versions_index_newest_first() {
        let vs = fixture_versions();
        let doc = build_versions_index("alpha", &ctx(None), &vs).unwrap();
        assert_eq!(doc["name"], "alpha");
        assert_eq!(doc["latest"], "2.0.0-rc.1");
        let order: Vec<&str> = doc["versions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["version"].as_str().unwrap())
            .collect();
        assert_eq!(order, vec!["2.0.0-rc.1", "1.9.0", "1.0.0"]);
        assert_eq!(doc["versions"][0]["harnesses"], json!(["claude"]));
        assert!(build_versions_index("missing", &ctx(None), &vs).is_none());
    }

    #[test]
    fn marketplace_file_names_and_keys() {
        let files: Vec<&str> = Marketplace::ALL.iter().map(|m| m.file_name()).collect();
        assert_eq!(
            files,
            vec![
                "marketplace.json",
                "claude-marketplace.json",
                "cursor-marketplace.json",
                "codex-marketplace.json",
                "vscode-marketplace.json"
            ]
        );
        assert_eq!(Marketplace::Vscode.response_key(), "vscode");
    }

    #[test]
    fn etag_and_if_none_match() {
        let tag = document_etag(b"{}");
        assert!(tag.starts_with('"') && tag.len() == 66);
        assert!(if_none_match_matches(&tag, &tag));
        assert!(if_none_match_matches(&format!("W/{tag}"), &tag));
        assert!(if_none_match_matches(&format!("\"x\", {tag}"), &tag));
        assert!(if_none_match_matches("*", &tag));
        assert!(!if_none_match_matches("\"other\"", &tag));
    }

    #[test]
    fn split_paths() {
        assert_eq!(
            split_artifact_path("/a/1.0.0/a-1.0.0.zip").unwrap(),
            ("a".into(), "1.0.0".into(), "a-1.0.0.zip".into())
        );
        assert!(split_artifact_path("a/1.0.0").is_err());
    }
}
