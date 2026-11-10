//! MCP Registry format (#5253): `server.json` documents served through the
//! MCP registry API v0.1 (`/mcp/{repo}/v0.1/...`).
//!
//! Everything here is pure: the server.json types and their validation, the
//! OCI identifier grammar, canonicalisation, cursors, latest ordering, the
//! served-document rewrite, and [`decide_mcp_serve`], the one function that
//! decides whether a server version may be handed to a client. The DB-backed
//! package resolver lives in `services::mcp_packages`, the HTTP surface in
//! `api::handlers::mcp`.
//!
//! Schema: server.json 2025-12-11
//! (`https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json`)
//! as described by the upstream `docs/reference/api/openapi.yaml`. Validation
//! is hand-written (no JSON-Schema crate): typed serde structs refuse unknown
//! fields, `_meta` is the one permissive object.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use async_trait::async_trait;
use base64::Engine;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::formats::FormatHandler;
use crate::models::repository::RepositoryFormat;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Publish body cap. Larger bodies answer 413 before any parsing.
pub const MCP_PUBLISH_MAX_BYTES: usize = 256 * 1024;
pub const MAX_PACKAGES: usize = 16;
pub const MAX_REMOTES: usize = 8;
/// Cap on every other array (arguments, environment variables, headers,
/// icons, choices) and on every `variables` map.
pub const MAX_LIST_ITEMS: usize = 64;
/// Maximum JSON nesting depth of a submitted document.
pub const MAX_DEPTH: usize = 32;
/// Serialised size cap of the publisher-provided `_meta` object.
pub const PUBLISHER_META_MAX_BYTES: usize = 4096;
pub const PUBLISHER_META_KEY: &str = "io.modelcontextprotocol.registry/publisher-provided";
pub const OFFICIAL_META_KEY: &str = "io.modelcontextprotocol.registry/official";
pub const AK_SOURCE_META_KEY: &str = "com.artifactkeeper.registry/source";
pub const AK_RESOLVED_META_KEY: &str = "com.artifactkeeper/resolved";
/// Publisher-declared capabilities (tools/resources/prompts), kept next to
/// the publisher-provided member (`services::mcp_capabilities`).
pub const AK_CAPABILITIES_META_KEY: &str = "com.artifactkeeper/capabilities";
pub const SCHEMA_URL: &str =
    "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json";
pub const DEFAULT_LIMIT: i64 = 30;
pub const MAX_LIMIT: i64 = 100;
/// Namespaces no repository may publish into: the protocol's own.
pub const RESERVED_NAMESPACE_PREFIXES: &[&str] = &["io.modelcontextprotocol"];
/// `registryType` values the schema allows.
pub const REGISTRY_TYPES: &[&str] = &["npm", "pypi", "nuget", "oci", "mcpb", "cargo"];
/// `registryType` values whose packages resolve to an AK artifact row.
pub const ARTIFACT_REGISTRY_TYPES: &[&str] = &["npm", "pypi", "nuget", "cargo"];
/// `statusMessage` cap (upstream `StatusUpdateRequest`).
pub const STATUS_MESSAGE_MAX: usize = 500;

/// The exact bytes of every reader-facing refusal on the MCP surface and of
/// every unknown-name answer, so a held version cannot be told apart from a
/// name that does not exist. Keys are in the order `serde_json` serialises a
/// `Value` object (sorted), so `serde_json::to_vec` of the reader-only body
/// [`decide_mcp_serve`] returns is byte-identical to this constant.
pub const NOT_FOUND_BODY: &str =
    r#"{"detail":"Server not found","status":404,"title":"Not Found","type":"about:blank"}"#;

const NAME_RE: &str = r"^[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+$";
const OCI_TAG_RE: &str = r"^[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}$";
const OCI_PATH_COMPONENT_RE: &str = r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$";
const TRANSPORT_URL_RE: &str = r"^(https?://[^\s]+|\{[a-zA-Z_][a-zA-Z0-9_]*\}[^\s]*)$";
const SHA256_HEX_RE: &str = r"^[a-f0-9]{64}$";
const ICON_SIZE_RE: &str = r"^(\d+x\d+|any)$";

fn re(pattern: &'static str) -> &'static regex::Regex {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<HashMap<&'static str, &'static regex::Regex>>> = OnceLock::new();
    let mut map = CACHE
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    map.entry(pattern)
        .or_insert_with(|| Box::leak(Box::new(regex::Regex::new(pattern).expect("valid regex"))))
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Every refusal the MCP surface produces, with its status and machine code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpError {
    /// Body over [`MCP_PUBLISH_MAX_BYTES`] (413).
    TooLarge,
    /// Shape/validation failure (400); `path` is a JSON-pointer-ish field path.
    Invalid { path: String, msg: String },
    /// `version`/`registryBaseUrl`/`fileSha256` on an `oci` package (422).
    OciLegacyFields { index: usize },
    /// OCI identifier with `:latest` or no tag and no digest (422).
    OciFloatingTag { index: usize },
    /// Package outside this instance's backing repositories (422).
    ExternalRegistry { index: usize, detail: String },
    /// Package not present in its backing repository (422).
    PackageNotFound { index: usize, detail: String },
    /// A package a Virtual backing repository would serve from another
    /// member than the one holding it (422, #5456).
    PackageShadowed { index: usize, detail: String },
    /// An `mcpb` bundle that does not satisfy the publishing repository's
    /// `mcp_require_bundle_signature` (unsigned, or a signer not on the
    /// trusted list) (422).
    BundleSignatureRequired { index: usize, detail: String },
    /// npm/pypi/nuget/cargo package without an exact `version` (422).
    PackageVersionUnpinned { index: usize },
    /// Pinned OCI manifest is not a runnable image or index (422).
    OciNotAnImage { index: usize },
    /// Name in a reserved namespace (403).
    ReservedNamespace { namespace: String },
    /// Name outside the repository's namespace allowlist (403).
    NamespaceNotAllowed { namespace: String },
    /// Name matches the repository's `mcp_server_deny` list (403).
    ServerDenied { name: String },
    /// `(name, version)` already published (409).
    VersionExists,
    /// A new server name that differs only in letter case from `existing`,
    /// a name this hosted repository already recorded (409, #5434).
    NameCaseConflict { name: String, existing: String },
    /// `search` shorter than 3 characters (422, upstream parity).
    SearchTooShort,
    /// A malformed query parameter (`limit`, `cursor`, `updated_since`,
    /// `include_deleted`, ...) (400).
    InvalidQuery { path: String, msg: String },
    /// The repository's package settings are inconsistent (500).
    Misconfigured(String),
    /// A database or storage failure (500).
    Internal(String),
}

impl McpError {
    pub fn invalid(path: impl Into<String>, msg: impl Into<String>) -> Self {
        McpError::Invalid {
            path: path.into(),
            msg: msg.into(),
        }
    }

    /// A malformed query parameter.
    pub fn invalid_query(path: impl Into<String>, msg: impl Into<String>) -> Self {
        McpError::InvalidQuery {
            path: path.into(),
            msg: msg.into(),
        }
    }

    pub fn status(&self) -> u16 {
        match self {
            McpError::TooLarge => 413,
            McpError::Invalid { .. } | McpError::InvalidQuery { .. } => 400,
            McpError::OciLegacyFields { .. }
            | McpError::OciFloatingTag { .. }
            | McpError::ExternalRegistry { .. }
            | McpError::PackageNotFound { .. }
            | McpError::PackageShadowed { .. }
            | McpError::BundleSignatureRequired { .. }
            | McpError::PackageVersionUnpinned { .. }
            | McpError::OciNotAnImage { .. }
            | McpError::SearchTooShort => 422,
            McpError::ReservedNamespace { .. }
            | McpError::NamespaceNotAllowed { .. }
            | McpError::ServerDenied { .. } => 403,
            McpError::VersionExists | McpError::NameCaseConflict { .. } => 409,
            McpError::Misconfigured(_) | McpError::Internal(_) => 500,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            McpError::TooLarge => "mcp_too_large",
            McpError::Invalid { .. } => "mcp_invalid_server_json",
            McpError::InvalidQuery { .. } => "mcp_invalid_query",
            McpError::OciLegacyFields { .. } => "mcp_oci_legacy_fields",
            McpError::OciFloatingTag { .. } => "mcp_oci_floating_tag",
            McpError::ExternalRegistry { .. } => "mcp_external_registry",
            McpError::PackageNotFound { .. } => "mcp_package_not_found",
            McpError::PackageShadowed { .. } => "mcp_package_shadowed",
            McpError::BundleSignatureRequired { .. } => "mcp_bundle_signature_required",
            McpError::PackageVersionUnpinned { .. } => "mcp_package_version_unpinned",
            McpError::OciNotAnImage { .. } => "mcp_oci_not_an_image",
            McpError::ReservedNamespace { .. } => "mcp_namespace_reserved",
            McpError::NamespaceNotAllowed { .. } => "mcp_namespace_not_allowed",
            McpError::ServerDenied { .. } => "mcp_server_denied",
            McpError::VersionExists => "mcp_version_exists",
            McpError::NameCaseConflict { .. } => "mcp_name_case_conflict",
            McpError::SearchTooShort => "mcp_search_too_short",
            McpError::Misconfigured(_) => "mcp_repository_misconfigured",
            McpError::Internal(_) => "mcp_internal_error",
        }
    }

    /// One line naming the field or package entry and the fix.
    pub fn detail(&self) -> String {
        match self {
            McpError::TooLarge => format!(
                "server.json exceeds the {} KiB publish limit",
                MCP_PUBLISH_MAX_BYTES / 1024
            ),
            McpError::Invalid { path, msg } if path.is_empty() => msg.clone(),
            McpError::Invalid { path, msg } => format!("{path}: {msg}"),
            McpError::InvalidQuery { path, msg } => format!("query parameter `{path}`: {msg}"),
            McpError::OciLegacyFields { index } => format!(
                "packages[{index}]: an oci package carries its tag or digest in `identifier`; \
                 remove `version`, `registryBaseUrl` and `fileSha256`"
            ),
            McpError::OciFloatingTag { index } => format!(
                "packages[{index}].identifier: name a specific tag or digest; `latest` and \
                 tagless image references are not accepted (AK pins the digest at publish)"
            ),
            McpError::ExternalRegistry { index, detail }
            | McpError::PackageNotFound { index, detail }
            | McpError::PackageShadowed { index, detail }
            | McpError::BundleSignatureRequired { index, detail } => {
                format!("packages[{index}]: {detail}")
            }
            McpError::PackageVersionUnpinned { index } => format!(
                "packages[{index}].version: an exact package version is required so AK can pin it"
            ),
            McpError::OciNotAnImage { index } => format!(
                "packages[{index}].identifier: the referenced manifest is not a runnable \
                 container image or image index"
            ),
            McpError::ReservedNamespace { namespace } => {
                format!("namespace '{namespace}' is reserved")
            }
            McpError::NamespaceNotAllowed { namespace } => {
                format!("namespace '{namespace}' is not in this repository's namespace allowlist")
            }
            McpError::ServerDenied { name } => {
                format!("server '{name}' matches this repository's server deny list")
            }
            McpError::VersionExists => {
                "this server version already exists; publish a new version".to_string()
            }
            McpError::NameCaseConflict { name, existing } => format!(
                "server name '{name}' differs only in letter case from '{existing}', which \
                 this registry already holds; publish under '{existing}' or choose another name"
            ),
            McpError::SearchTooShort => "search must be at least 3 characters".to_string(),
            McpError::Misconfigured(_) => {
                "this repository's MCP package settings are inconsistent; ask an administrator"
                    .to_string()
            }
            McpError::Internal(_) => "internal error".to_string(),
        }
    }
}

impl From<McpError> for AppError {
    fn from(e: McpError) -> Self {
        match e.status() {
            400 | 413 | 422 => AppError::Validation(e.detail()),
            403 => AppError::Authorization(e.detail()),
            409 => AppError::Conflict(e.detail()),
            _ => AppError::Internal(e.detail()),
        }
    }
}

/// An RFC 9457 problem document with AK's machine code in `error`, plus any
/// `extra` members.
pub fn problem_body(
    status: u16,
    error_code: &str,
    detail: &str,
    extra: serde_json::Value,
) -> serde_json::Value {
    let mut body = serde_json::json!({
        "type": "about:blank",
        "title": status_title(status),
        "status": status,
        "detail": detail,
        "error": error_code,
    });
    if let (Some(obj), serde_json::Value::Object(more)) = (body.as_object_mut(), extra) {
        obj.extend(more);
    }
    body
}

fn status_title(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Content Too Large",
        422 => "Unprocessable Content",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        _ => "Internal Server Error",
    }
}

// ---------------------------------------------------------------------------
// server.json types
// ---------------------------------------------------------------------------

/// A server.json document (2025-12-11).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServerJson {
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub name: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub website_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<Repository>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub icons: Vec<Icon>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packages: Vec<Package>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remotes: Vec<Transport>,
    #[serde(rename = "_meta", default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Repository {
    pub url: String,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subfolder: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Icon {
    pub src: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sizes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub theme: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Package {
    pub registry_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_base_url: Option<String>,
    pub identifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_hint: Option<String>,
    pub transport: Transport,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_arguments: Vec<Input>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub package_arguments: Vec<Input>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub environment_variables: Vec<Input>,
}

/// A package transport (`stdio`/`streamable-http`/`sse`) or a remote
/// (`streamable-http`/`sse`, optionally with `variables`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Transport {
    pub r#type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<Input>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variables: Option<BTreeMap<String, Input>>,
}

/// The schema's `Input`, `KeyValueInput`, `PositionalArgument` and
/// `NamedArgument` in one struct; which members a role may carry is checked
/// by [`validate_input`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Input {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_hint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_repeated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_secret: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub choices: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variables: Option<BTreeMap<String, Input>>,
}

// ---------------------------------------------------------------------------
// Parsing and validation
// ---------------------------------------------------------------------------

/// Whether `bytes` nests arrays/objects deeper than `max` (string contents
/// are skipped). Checked before serde so a 2000-deep document is a clean 400
/// and never reaches a recursive parser.
pub fn json_depth_exceeds(bytes: &[u8], max: usize) -> bool {
    let (mut depth, mut in_str, mut escaped) = (0usize, false, false);
    for &b in bytes {
        if in_str {
            match (escaped, b) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_str = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_str = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > max {
                    return true;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

/// Size check, depth check, then the typed parse.
pub fn parse_server_json(bytes: &[u8]) -> std::result::Result<ServerJson, McpError> {
    if bytes.len() > MCP_PUBLISH_MAX_BYTES {
        return Err(McpError::TooLarge);
    }
    if json_depth_exceeds(bytes, MAX_DEPTH) {
        return Err(McpError::invalid(
            "",
            format!("document nests deeper than {MAX_DEPTH} levels"),
        ));
    }
    if let Err(e) = reject_duplicate_json_keys(bytes) {
        return Err(McpError::invalid("", format!("invalid server.json: {e}")));
    }
    serde_json::from_slice(bytes)
        .map_err(|e| McpError::invalid("", format!("invalid server.json: {e}")))
}

/// `s` as shown in an error detail: control characters and quotes escaped,
/// at most 200 characters (archive entry names, JSON member names).
pub fn shown(s: &str) -> String {
    s.chars()
        .take(200)
        .collect::<String>()
        .escape_debug()
        .to_string()
}

/// Fail when `bytes` is not JSON or holds an object with a repeated member
/// name anywhere (server.json, and an MCPB bundle's `manifest.json`, #5468):
/// `serde_json` would otherwise keep the last value, and another parser may
/// keep the first.
pub fn reject_duplicate_json_keys(bytes: &[u8]) -> serde_json::Result<()> {
    serde_json::from_slice::<NoDuplicateKeys>(bytes).map(|_| ())
}

/// Walks a JSON document and fails on an object with a repeated member name
/// anywhere (including the free-form `_meta`), so two parsers can never
/// disagree about which value a key holds. Values are not kept.
struct NoDuplicateKeys;

impl<'de> serde::Deserialize<'de> for NoDuplicateKeys {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Walk;
        impl<'de> serde::de::Visitor<'de> for Walk {
            type Value = NoDuplicateKeys;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_bool<E>(self, _: bool) -> std::result::Result<Self::Value, E> {
                Ok(NoDuplicateKeys)
            }
            fn visit_i64<E>(self, _: i64) -> std::result::Result<Self::Value, E> {
                Ok(NoDuplicateKeys)
            }
            fn visit_u64<E>(self, _: u64) -> std::result::Result<Self::Value, E> {
                Ok(NoDuplicateKeys)
            }
            fn visit_f64<E>(self, _: f64) -> std::result::Result<Self::Value, E> {
                Ok(NoDuplicateKeys)
            }
            fn visit_str<E>(self, _: &str) -> std::result::Result<Self::Value, E> {
                Ok(NoDuplicateKeys)
            }
            fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
                Ok(NoDuplicateKeys)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                while seq.next_element::<NoDuplicateKeys>()?.is_some() {}
                Ok(NoDuplicateKeys)
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut seen = std::collections::HashSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !seen.insert(key.clone()) {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate key `{}`",
                            shown(&key)
                        )));
                    }
                    map.next_value::<NoDuplicateKeys>()?;
                }
                Ok(NoDuplicateKeys)
            }
        }
        d.deserialize_any(Walk)
    }
}

/// Characters refused in any rendered string: control characters, bidi
/// marks, embeddings/overrides/isolates (incl. the Arabic letter mark),
/// zero-width and invisible formatting characters (word joiner, invisible
/// operators), line/paragraph separators, Unicode tag characters and the BOM.
pub fn has_forbidden_chars(s: &str) -> bool {
    s.chars().any(|c| {
        c.is_control()
            || matches!(c,
                '\u{061C}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
                | '\u{E0000}'..='\u{E007F}')
    })
}

/// The first string (object key or value) under `v` that
/// [`has_forbidden_chars`] refuses, as a JSON-pointer-ish path below `base`.
fn forbidden_in_json(v: &serde_json::Value, base: &str) -> Option<String> {
    match v {
        serde_json::Value::String(s) if has_forbidden_chars(s) => Some(base.to_string()),
        serde_json::Value::Array(items) => items
            .iter()
            .enumerate()
            .find_map(|(i, item)| forbidden_in_json(item, &format!("{base}[{i}]"))),
        serde_json::Value::Object(map) => map.iter().find_map(|(k, item)| {
            let path = format!("{base}.{k}");
            if has_forbidden_chars(k) {
                Some(path)
            } else {
                forbidden_in_json(item, &path)
            }
        }),
        _ => None,
    }
}

type V = std::result::Result<(), McpError>;

fn check_text(path: &str, value: Option<&str>, max: Option<usize>) -> V {
    let Some(s) = value else { return Ok(()) };
    if has_forbidden_chars(s) {
        return Err(McpError::invalid(
            path,
            "control, bidirectional or zero-width characters are not allowed",
        ));
    }
    if let Some(max) = max {
        if s.chars().count() > max {
            return Err(McpError::invalid(
                path,
                format!("must be at most {max} characters"),
            ));
        }
    }
    Ok(())
}

fn check_count(path: &str, len: usize, max: usize) -> V {
    if len > max {
        return Err(McpError::invalid(
            path,
            format!("at most {max} entries are allowed"),
        ));
    }
    Ok(())
}

/// An absolute `http(s)` URL with a host (refuses `javascript:`, `data:`,
/// `file:` and relative references).
pub fn is_http_url(s: &str) -> bool {
    url::Url::parse(s)
        .ok()
        .is_some_and(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some())
}

fn check_http_url(path: &str, value: Option<&str>) -> V {
    match value {
        Some(s) if !is_http_url(s) || has_forbidden_chars(s) => Err(McpError::invalid(
            path,
            "must be an absolute http or https URL",
        )),
        _ => Ok(()),
    }
}

/// Cap on the expansions of one transport URL template checked at publish
/// (#5529): the product of every variable's distinct publisher values.
pub const MAX_URL_TEMPLATE_EXPANSIONS: usize = 256;

/// What a variable with no publisher value stands for while the other
/// variables are expanded: a client-supplied value cannot change a scheme
/// the template spells out, and `1` is a valid host label, port and path.
/// A variable with no value in the scheme position stands for nothing
/// instead, so a later variable's value is checked as the scheme.
const UNBOUND_VARIABLE_STAND_IN: &str = "1";

/// Why a transport URL template can reach a client as something other than
/// an absolute `http(s)` URL (#5529).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlTemplateIssue {
    /// Filling the variables with these publisher values (`value`,
    /// `default`, `placeholder`, `choices`) yields `expansion`, not an
    /// `http(s)` URL.
    NotHttp {
        assignments: Vec<(String, String)>,
        expansion: String,
    },
    /// The variable that opens the template (and so picks the scheme),
    /// declared or not, has no publisher value.
    UnboundScheme { variable: String },
    /// More than [`MAX_URL_TEMPLATE_EXPANSIONS`] expansions (`count`
    /// saturates).
    TooManyExpansions { count: usize },
}

impl UrlTemplateIssue {
    pub fn message(&self) -> String {
        fn quoted(s: &str) -> String {
            const MAX: usize = 120;
            let clipped = if s.chars().count() > MAX {
                format!("{}...", s.chars().take(MAX).collect::<String>())
            } else {
                s.to_string()
            };
            format!("\"{}\"", shown(&clipped))
        }
        match self {
            UrlTemplateIssue::NotHttp {
                assignments,
                expansion,
            } => {
                let with = assignments
                    .iter()
                    .map(|(k, v)| format!("variable `{k}` = {}", quoted(v)))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    "with {with} this URL expands to {}, which is not an absolute http or https URL",
                    quoted(expansion)
                )
            }
            UrlTemplateIssue::UnboundScheme { variable } => format!(
                "variable `{variable}` picks the URL scheme and needs a `default` or `choices` \
                 that are absolute http or https URLs"
            ),
            UrlTemplateIssue::TooManyExpansions { count } => format!(
                "the URL template's variables expand to {count} URLs, more than the \
                 {MAX_URL_TEMPLATE_EXPANSIONS} checked: offer fewer `choices`"
            ),
        }
    }
}

/// How much of a URL template [`remote_url_issue`] / [`package_url_issue`]
/// expand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlExpansion {
    /// Every combination of every variable's values, refused past
    /// [`MAX_URL_TEMPLATE_EXPANSIONS`] (publish).
    All,
    /// Each value of the scheme-position variable on its own, the others
    /// standing in for client input: linear, never too many (the lint of a
    /// stored template that publish would refuse as too large).
    SchemeOnly,
}

/// The values a client that takes the publisher's word fills a URL
/// variable with: `value`, `default`, `placeholder` (clients pre-fill it)
/// and every `choices` entry.
fn publisher_values(input: &Input) -> impl Iterator<Item = &str> {
    input
        .value
        .iter()
        .chain(input.default.iter())
        .chain(input.placeholder.iter())
        .chain(input.choices.iter().flatten())
        .map(String::as_str)
}

/// The distinct publisher values of every input in `inputs`; `None` when
/// there is no input (an undeclared variable).
fn union_values<'a>(inputs: impl Iterator<Item = &'a Input>) -> Option<Vec<&'a str>> {
    let mut declared = false;
    let mut out: Vec<&str> = Vec::new();
    for input in inputs {
        declared = true;
        for v in publisher_values(input) {
            if !out.contains(&v) {
                out.push(v);
            }
        }
    }
    declared.then_some(out)
}

/// Every expansion of the `{variable}` template `template` against the
/// publisher values `values_of` finds (`None`: undeclared) must be an
/// absolute `http(s)` URL ([`is_http_url`], as for every other URL in a
/// server.json). A variable with no value stands in for client input; one
/// in the scheme position, declared or not, is refused, since whatever the
/// client fills in picks the scheme (the later variables are still
/// expanded, so a value of theirs that reaches the scheme is named). A
/// template with no publisher value and a literal scheme is left to the
/// shape check alone.
pub fn url_template_issue<'a>(
    template: &str,
    values_of: impl Fn(&str) -> Option<Vec<&'a str>>,
    mode: UrlExpansion,
) -> Option<UrlTemplateIssue> {
    enum Seg<'s> {
        Lit(&'s str),
        Var(&'s str),
    }
    let mut segs = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        let Some(len) = rest[open..].find('}') else {
            break;
        };
        if open > 0 {
            segs.push(Seg::Lit(&rest[..open]));
        }
        segs.push(Seg::Var(&rest[open + 1..open + len]));
        rest = &rest[open + len + 1..];
    }
    if !rest.is_empty() {
        segs.push(Seg::Lit(rest));
    }
    let mut names: Vec<&str> = Vec::new();
    for s in &segs {
        if let Seg::Var(n) = s {
            if !names.contains(n) {
                names.push(n);
            }
        }
    }
    let mut values: Vec<Vec<&str>> = names
        .iter()
        .map(|n| values_of(n).unwrap_or_default())
        .collect();
    // The variable in the scheme position, if the template opens with one.
    let scheme = match segs.first() {
        Some(Seg::Var(n)) => names.iter().position(|m| m == n),
        _ => None,
    };
    let unbound_scheme = scheme.filter(|&i| values[i].is_empty()).map(|i| names[i]);
    if mode == UrlExpansion::SchemeOnly {
        // Only the scheme variable varies; the others take one value each.
        for (i, v) in values.iter_mut().enumerate() {
            if Some(i) != scheme {
                v.truncate(1);
            }
        }
    }
    if unbound_scheme.is_none() && values.iter().all(Vec::is_empty) {
        return None;
    }
    let count = values
        .iter()
        .fold(1usize, |acc, v| acc.saturating_mul(v.len().max(1)));
    if count > MAX_URL_TEMPLATE_EXPANSIONS {
        return Some(UrlTemplateIssue::TooManyExpansions { count });
    }
    let mut pick = vec![0usize; names.len()];
    for _ in 0..count {
        let value_of = |i: usize| values[i].get(pick[i]).copied();
        let expansion: String = segs
            .iter()
            .map(|s| match s {
                Seg::Lit(l) => *l,
                Seg::Var(n) => {
                    let i = names.iter().position(|m| m == n).unwrap_or(0);
                    value_of(i).unwrap_or(if Some(i) == scheme {
                        ""
                    } else {
                        UNBOUND_VARIABLE_STAND_IN
                    })
                }
            })
            .collect();
        // With no scheme variable value, an expansion that is not a URL at
        // all is the unbound scheme (reported below), not a later value's
        // fault; one a later value gave a scheme is that value's.
        let blamed = unbound_scheme.is_none() || url::Url::parse(&expansion).is_ok();
        if blamed && (!is_http_url(&expansion) || has_forbidden_chars(&expansion)) {
            let assignments = (0..names.len())
                .filter_map(|i| value_of(i).map(|v| (names[i].to_string(), v.to_string())))
                .collect();
            return Some(UrlTemplateIssue::NotHttp {
                assignments,
                expansion,
            });
        }
        for (i, p) in pick.iter_mut().enumerate() {
            *p += 1;
            if *p < values[i].len() {
                break;
            }
            *p = 0;
        }
    }
    unbound_scheme.map(|v| UrlTemplateIssue::UnboundScheme {
        variable: v.to_string(),
    })
}

/// [`url_template_issue`] for a remote: its variables are the remote's
/// `variables` map.
pub fn remote_url_issue(remote: &Transport, mode: UrlExpansion) -> Option<UrlTemplateIssue> {
    let url = remote.url.as_deref()?;
    url_template_issue(
        url,
        |n| union_values(remote.variables.as_ref()?.get(n).into_iter()),
        mode,
    )
}

/// [`url_template_issue`] for a package transport: its variables are the
/// package's arguments (by `valueHint` or `name`) and environment variables
/// (by `name`), as the upstream schema describes `transport.url`. Every
/// matching input counts (several may share a name), so the values are the
/// union of all of theirs.
pub fn package_url_issue(p: &Package, mode: UrlExpansion) -> Option<UrlTemplateIssue> {
    let url = p.transport.url.as_deref()?;
    url_template_issue(
        url,
        |n| {
            let envs = p
                .environment_variables
                .iter()
                .filter(move |e| e.name.as_deref() == Some(n));
            let args = p
                .runtime_arguments
                .iter()
                .chain(&p.package_arguments)
                .filter(move |a| {
                    a.value_hint.as_deref() == Some(n) || a.name.as_deref() == Some(n)
                });
            union_values(envs.chain(args))
        },
        mode,
    )
}

fn check_url_template(path: &str, issue: Option<UrlTemplateIssue>) -> V {
    match issue {
        Some(i) => Err(McpError::invalid(path, i.message())),
        None => Ok(()),
    }
}

/// A version string a publisher may use: 1..=255 characters, not `latest`,
/// not a range, and safe as one path segment.
pub fn check_version(path: &str, v: &str) -> V {
    if v.is_empty() || v.chars().count() > 255 {
        return Err(McpError::invalid(path, "must be 1 to 255 characters"));
    }
    if v.eq_ignore_ascii_case("latest") {
        return Err(McpError::invalid(path, "`latest` is not a version"));
    }
    let wildcard_segment = v
        .split(['.', '-', '+'])
        .any(|seg| matches!(seg, "x" | "X" | "*"));
    if v.contains(['^', '~', '*', '>', '<', ' ', '/', '\\', '=', ','])
        || v.contains("||")
        || wildcard_segment
        || v == "."
        || v == ".."
        || has_forbidden_chars(v)
    {
        return Err(McpError::invalid(
            path,
            "must be an exact version, not a range or wildcard",
        ));
    }
    Ok(())
}

pub fn check_name(name: &str) -> V {
    let len = name.chars().count();
    if !(3..=200).contains(&len) {
        return Err(McpError::invalid("name", "must be 3 to 200 characters"));
    }
    if !re(NAME_RE).is_match(name) || name.contains("..") {
        return Err(McpError::invalid(
            "name",
            "must be `namespace/name` using letters, digits, `.`, `-` and `_` (namespace: letters, digits, `.` and `-`)",
        ));
    }
    let (ns, short) = name.split_once('/').unwrap_or_default();
    if ns.starts_with('.') || ns.ends_with('.') || short.starts_with('.') {
        return Err(McpError::invalid(
            "name",
            "namespace and name may not start or end with `.`",
        ));
    }
    Ok(())
}

/// Which members an [`Input`] may carry in a given position of the schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InputRole {
    /// `runtimeArguments[]` / `packageArguments[]`.
    Argument,
    /// `environmentVariables[]` / `headers[]` (`KeyValueInput`).
    KeyValue,
    /// A value of a `variables` map (`Input`).
    Variable,
}

const INPUT_FORMATS: &[&str] = &["string", "number", "boolean", "filepath"];

fn validate_input(path: &str, input: &Input, role: InputRole) -> V {
    let has_arg_members =
        input.r#type.is_some() || input.value_hint.is_some() || input.is_repeated.is_some();
    match role {
        InputRole::Argument => match input.r#type.as_deref() {
            Some("named") => {
                let Some(name) = input.name.as_deref() else {
                    return Err(McpError::invalid(
                        format!("{path}.name"),
                        "required for a named argument",
                    ));
                };
                check_argument_name(&format!("{path}.name"), name)?;
            }
            Some("positional") => {
                if input.value_hint.is_none() && input.value.is_none() {
                    return Err(McpError::invalid(
                        path,
                        "a positional argument needs `valueHint` or `value`",
                    ));
                }
                if let Some(name) = input.name.as_deref() {
                    check_argument_name(&format!("{path}.name"), name)?;
                }
            }
            _ => {
                return Err(McpError::invalid(
                    format!("{path}.type"),
                    "must be `positional` or `named`",
                ))
            }
        },
        InputRole::KeyValue => {
            if has_arg_members {
                return Err(McpError::invalid(
                    path,
                    "`type`, `valueHint` and `isRepeated` belong to arguments",
                ));
            }
            let Some(name) = input.name.as_deref() else {
                return Err(McpError::invalid(format!("{path}.name"), "required"));
            };
            check_argument_name(&format!("{path}.name"), name)?;
        }
        InputRole::Variable => {
            if has_arg_members || input.name.is_some() || input.variables.is_some() {
                return Err(McpError::invalid(
                    path,
                    "a variable carries only input members",
                ));
            }
        }
    }
    if let Some(f) = input.format.as_deref() {
        if !INPUT_FORMATS.contains(&f) {
            return Err(McpError::invalid(
                format!("{path}.format"),
                "must be one of string, number, boolean, filepath",
            ));
        }
    }
    check_text(
        &format!("{path}.description"),
        input.description.as_deref(),
        Some(1000),
    )?;
    for (field, value) in [
        ("valueHint", &input.value_hint),
        ("value", &input.value),
        ("default", &input.default),
        ("placeholder", &input.placeholder),
    ] {
        check_text(&format!("{path}.{field}"), value.as_deref(), Some(2048))?;
    }
    if let Some(choices) = &input.choices {
        check_count(&format!("{path}.choices"), choices.len(), MAX_LIST_ITEMS)?;
        for (i, c) in choices.iter().enumerate() {
            check_text(&format!("{path}.choices[{i}]"), Some(c), Some(255))?;
        }
    }
    if let Some(vars) = &input.variables {
        validate_variables(&format!("{path}.variables"), vars)?;
    }
    Ok(())
}

fn check_argument_name(path: &str, name: &str) -> V {
    if name.is_empty()
        || name.chars().count() > 255
        || name.contains(['<', '>', ' ', '$'])
        || has_forbidden_chars(name)
    {
        return Err(McpError::invalid(
            path,
            "must be non-empty and contain no `<`, `>`, `$` or whitespace",
        ));
    }
    Ok(())
}

fn validate_variables(path: &str, vars: &BTreeMap<String, Input>) -> V {
    check_count(path, vars.len(), MAX_LIST_ITEMS)?;
    for (key, input) in vars {
        let p = format!("{path}.{key}");
        if !re(r"^[a-zA-Z_][a-zA-Z0-9_]*$").is_match(key) {
            return Err(McpError::invalid(p, "variable names are identifiers"));
        }
        validate_input(&p, input, InputRole::Variable)?;
    }
    Ok(())
}

fn validate_inputs(path: &str, inputs: &[Input], role: InputRole) -> V {
    check_count(path, inputs.len(), MAX_LIST_ITEMS)?;
    for (i, input) in inputs.iter().enumerate() {
        validate_input(&format!("{path}[{i}]"), input, role)?;
    }
    Ok(())
}

fn validate_transport(path: &str, t: &Transport, remote: bool) -> V {
    let allowed: &[&str] = if remote {
        &["streamable-http", "sse"]
    } else {
        &["stdio", "streamable-http", "sse"]
    };
    if !allowed.contains(&t.r#type.as_str()) {
        return Err(McpError::invalid(
            format!("{path}.type"),
            format!("must be one of {}", allowed.join(", ")),
        ));
    }
    if t.r#type == "stdio" {
        if t.url.is_some() || !t.headers.is_empty() {
            return Err(McpError::invalid(
                path,
                "a stdio transport has no `url` or `headers`",
            ));
        }
    } else {
        match t.url.as_deref() {
            Some(u) if re(TRANSPORT_URL_RE).is_match(u) && !has_forbidden_chars(u) => {}
            Some(_) => {
                return Err(McpError::invalid(
                    format!("{path}.url"),
                    "must start with http://, https:// or a {variable}",
                ))
            }
            None => {
                return Err(McpError::invalid(
                    format!("{path}.url"),
                    "required for an http transport",
                ))
            }
        }
    }
    validate_inputs(&format!("{path}.headers"), &t.headers, InputRole::KeyValue)?;
    match (&t.variables, remote) {
        (Some(vars), true) => validate_variables(&format!("{path}.variables"), vars),
        (Some(_), false) => Err(McpError::invalid(
            format!("{path}.variables"),
            "only remotes carry `variables`",
        )),
        (None, _) => Ok(()),
    }
}

fn validate_package(i: usize, p: &Package, allow_floating_oci: bool) -> V {
    let path = format!("packages[{i}]");
    if !REGISTRY_TYPES.contains(&p.registry_type.as_str()) {
        return Err(McpError::invalid(
            format!("{path}.registryType"),
            format!("must be one of {}", REGISTRY_TYPES.join(", ")),
        ));
    }
    if p.identifier.trim().is_empty() || p.identifier.len() > 512 {
        return Err(McpError::invalid(
            format!("{path}.identifier"),
            "must be 1 to 512 characters",
        ));
    }
    check_text(&format!("{path}.identifier"), Some(&p.identifier), None)?;
    check_text(
        &format!("{path}.runtimeHint"),
        p.runtime_hint.as_deref(),
        Some(255),
    )?;
    if p.registry_type == "oci" {
        if p.version.is_some() || p.registry_base_url.is_some() || p.file_sha256.is_some() {
            return Err(McpError::OciLegacyFields { index: i });
        }
        match parse_oci_identifier(&p.identifier) {
            Ok(_) => {}
            Err(OciRefError::Floating) if allow_floating_oci => {}
            Err(OciRefError::Floating) => return Err(McpError::OciFloatingTag { index: i }),
            Err(OciRefError::Invalid(msg)) => {
                return Err(McpError::invalid(format!("{path}.identifier"), msg))
            }
        }
    }
    if let Some(v) = p.version.as_deref() {
        check_version(&format!("{path}.version"), v)?;
    }
    check_http_url(
        &format!("{path}.registryBaseUrl"),
        p.registry_base_url.as_deref(),
    )?;
    match p.file_sha256.as_deref() {
        Some(h) if !re(SHA256_HEX_RE).is_match(h) => {
            return Err(McpError::invalid(
                format!("{path}.fileSha256"),
                "must be 64 lower-case hex characters",
            ))
        }
        None if p.registry_type == "mcpb" => {
            return Err(McpError::invalid(
                format!("{path}.fileSha256"),
                "required for an mcpb package",
            ))
        }
        _ => {}
    }
    validate_transport(&format!("{path}.transport"), &p.transport, false)?;
    validate_inputs(
        &format!("{path}.runtimeArguments"),
        &p.runtime_arguments,
        InputRole::Argument,
    )?;
    validate_inputs(
        &format!("{path}.packageArguments"),
        &p.package_arguments,
        InputRole::Argument,
    )?;
    validate_inputs(
        &format!("{path}.environmentVariables"),
        &p.environment_variables,
        InputRole::KeyValue,
    )?;
    check_url_template(
        &format!("{path}.transport.url"),
        package_url_issue(p, UrlExpansion::All),
    )
}

const ICON_MIME_TYPES: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/jpg",
    "image/svg+xml",
    "image/webp",
];

fn validate_icon(i: usize, icon: &Icon) -> V {
    let path = format!("icons[{i}]");
    if icon.src.len() > 255 {
        return Err(McpError::invalid(
            format!("{path}.src"),
            "must be at most 255 characters",
        ));
    }
    check_http_url(&format!("{path}.src"), Some(&icon.src))?;
    if let Some(m) = icon.mime_type.as_deref() {
        if !ICON_MIME_TYPES.contains(&m) {
            return Err(McpError::invalid(
                format!("{path}.mimeType"),
                "unsupported icon type",
            ));
        }
    }
    if let Some(sizes) = &icon.sizes {
        check_count(&format!("{path}.sizes"), sizes.len(), MAX_LIST_ITEMS)?;
        if sizes.iter().any(|s| !re(ICON_SIZE_RE).is_match(s)) {
            return Err(McpError::invalid(
                format!("{path}.sizes"),
                "each size is `WxH` or `any`",
            ));
        }
    }
    match icon.theme.as_deref() {
        None | Some("light") | Some("dark") => Ok(()),
        Some(_) => Err(McpError::invalid(
            format!("{path}.theme"),
            "must be `light` or `dark`",
        )),
    }
}

/// Every rule of the plan's section 4.2 that does not need the database.
pub fn validate_server_json(s: &ServerJson) -> V {
    validate_server_json_opts(s, false)
}

/// [`validate_server_json`] with OCI `latest`/tagless identifiers admitted
/// when `allow_floating_oci` (documents ingested from an upstream registry
/// into a Remote repository, whose floating tags are pinned or hidden at
/// sync rather than refused).
pub fn validate_server_json_opts(s: &ServerJson, allow_floating_oci: bool) -> V {
    validate_document(s, allow_floating_oci, true)
}

/// [`validate_server_json`] without the installation check
/// ([`check_installable`]): a hosted publish adds the `mcpb` entries of the
/// bundles uploaded beside the version first, so a bundle-only document has
/// its `packages` only then. The caller runs [`check_installable`] after.
pub fn validate_server_json_before_bundles(s: &ServerJson) -> V {
    validate_document(s, false, false)
}

/// A server needs `packages`, `remotes` or a `websiteUrl` describing its
/// installation. The upstream specification's "custom installation path"
/// example has neither of the first two: such a server points at its setup
/// guide with `websiteUrl`.
pub fn check_installable(s: &ServerJson) -> V {
    if s.packages.is_empty() && s.remotes.is_empty() && s.website_url.is_none() {
        return Err(McpError::invalid(
            "",
            "a server needs `packages`, `remotes` or a `websiteUrl` describing its installation \
             (or an MCPB bundle uploaded for this version)",
        ));
    }
    Ok(())
}

fn validate_document(s: &ServerJson, allow_floating_oci: bool, require_install: bool) -> V {
    if let Some(schema) = s.schema.as_deref() {
        check_http_url("$schema", Some(schema))?;
    }
    check_name(&s.name)?;
    if s.description.trim().is_empty() {
        return Err(McpError::invalid("description", "must not be empty"));
    }
    check_text("description", Some(&s.description), Some(100))?;
    if let Some(t) = s.title.as_deref() {
        if t.trim().is_empty() {
            return Err(McpError::invalid("title", "must not be empty"));
        }
    }
    check_text("title", s.title.as_deref(), Some(100))?;
    check_version("version", &s.version)?;
    check_http_url("websiteUrl", s.website_url.as_deref())?;
    if let Some(r) = &s.repository {
        check_http_url("repository.url", Some(&r.url))?;
        check_text("repository.source", Some(&r.source), Some(64))?;
        check_text("repository.id", r.id.as_deref(), Some(255))?;
        check_text("repository.subfolder", r.subfolder.as_deref(), Some(512))?;
        if r.subfolder.as_deref().is_some_and(|f| f.contains("..")) {
            return Err(McpError::invalid(
                "repository.subfolder",
                "must not contain `..`",
            ));
        }
    }
    check_count("icons", s.icons.len(), MAX_LIST_ITEMS)?;
    for (i, icon) in s.icons.iter().enumerate() {
        validate_icon(i, icon)?;
    }
    if require_install {
        check_installable(s)?;
    }
    check_count("packages", s.packages.len(), MAX_PACKAGES)?;
    check_count("remotes", s.remotes.len(), MAX_REMOTES)?;
    for (i, p) in s.packages.iter().enumerate() {
        validate_package(i, p, allow_floating_oci)?;
    }
    for (i, r) in s.remotes.iter().enumerate() {
        validate_transport(&format!("remotes[{i}]"), r, true)?;
        check_url_template(
            &format!("remotes[{i}].url"),
            remote_url_issue(r, UrlExpansion::All),
        )?;
    }
    Ok(())
}

/// Keep only the publisher-provided `_meta` member (upstream rule) and refuse
/// it over [`PUBLISHER_META_MAX_BYTES`].
pub fn reduce_publisher_meta(s: &mut ServerJson) -> V {
    let Some(meta) = s.meta.take() else {
        return Ok(());
    };
    let declared = keep_declared_capabilities(&meta)?;
    let Some(provided) = meta.get(PUBLISHER_META_KEY) else {
        s.meta = declared.map(|d| {
            let mut kept = serde_json::Map::new();
            kept.insert(AK_CAPABILITIES_META_KEY.to_string(), d);
            kept
        });
        return Ok(());
    };
    if !provided.is_object() {
        return Err(McpError::invalid(
            format!("_meta.{PUBLISHER_META_KEY}"),
            "must be an object",
        ));
    }
    let size = serde_json::to_vec(provided)
        .map(|b| b.len())
        .unwrap_or(usize::MAX);
    if size > PUBLISHER_META_MAX_BYTES {
        return Err(McpError::invalid(
            format!("_meta.{PUBLISHER_META_KEY}"),
            format!("must be at most {PUBLISHER_META_MAX_BYTES} bytes"),
        ));
    }
    // Publisher-provided metadata is served verbatim to clients that may
    // render it, so it gets the same character rules as every other string.
    if let Some(path) = forbidden_in_json(provided, &format!("_meta.{PUBLISHER_META_KEY}")) {
        return Err(McpError::invalid(
            path,
            "control, bidirectional or zero-width characters are not allowed",
        ));
    }
    let mut kept = serde_json::Map::new();
    kept.insert(PUBLISHER_META_KEY.to_string(), provided.clone());
    if let Some(d) = declared {
        kept.insert(AK_CAPABILITIES_META_KEY.to_string(), d);
    }
    s.meta = Some(kept);
    Ok(())
}

/// The top-level `_meta[com.artifactkeeper/capabilities]` block, kept when
/// present (an object, same character rules as every rendered string). Its
/// shape and size are checked by `services::mcp_capabilities` at publish.
fn keep_declared_capabilities(
    meta: &serde_json::Map<String, serde_json::Value>,
) -> std::result::Result<Option<serde_json::Value>, McpError> {
    let Some(block) = meta.get(AK_CAPABILITIES_META_KEY) else {
        return Ok(None);
    };
    let path = format!("_meta.{AK_CAPABILITIES_META_KEY}");
    if !block.is_object() {
        return Err(McpError::invalid(path, "must be an object"));
    }
    if let Some(at) = forbidden_in_json(block, &path) {
        return Err(McpError::invalid(
            at,
            "control, bidirectional or zero-width characters are not allowed",
        ));
    }
    Ok(Some(block.clone()))
}

/// The stored form of a document: `serde_json` serialises a `Value`'s object
/// keys sorted (`preserve_order` is off), so this is key-sorted canonical
/// JSON of exactly the fields the typed parse kept.
pub fn canonical_bytes(s: &ServerJson) -> Vec<u8> {
    let value = serde_json::to_value(s).unwrap_or(serde_json::Value::Null);
    serde_json::to_vec(&value).unwrap_or_default()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

// ---------------------------------------------------------------------------
// Names, namespaces, paths, cursors
// ---------------------------------------------------------------------------

pub fn namespace_of(name: &str) -> &str {
    name.split_once('/').map(|(ns, _)| ns).unwrap_or(name)
}

/// Prefix match on the namespace: `com.acme` admits `com.acme` and
/// `com.acme.sub`, not `com.acmecorp`. An empty allowlist admits any name.
pub fn namespace_allowed(name: &str, allow: &[String]) -> bool {
    if allow.is_empty() {
        return true;
    }
    let ns = namespace_of(name).to_ascii_lowercase();
    allow.iter().any(|prefix| {
        let prefix = prefix.trim().trim_end_matches('.').to_ascii_lowercase();
        !prefix.is_empty()
            && (ns == prefix || ns.strip_prefix(&prefix).is_some_and(|r| r.starts_with('.')))
    })
}

pub fn is_reserved_namespace(name: &str) -> bool {
    namespace_allowed(
        name,
        &RESERVED_NAMESPACE_PREFIXES
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>(),
    )
}

/// `artifacts.path` of a server version.
pub fn storage_path(name: &str, version: &str) -> String {
    format!("servers/{name}/{version}/server.json")
}

/// Where one repository's new MCP objects are keyed: its id and storage
/// backend under the `STORAGE_KEY_SCHEME` (#2624).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyScope<'a> {
    pub scheme: crate::storage::StorageKeyScheme,
    pub storage_backend: &'a str,
    pub repository_id: Uuid,
}

impl<'a> KeyScope<'a> {
    /// The scope of a repository on `storage_backend`, under the scheme the
    /// environment selects.
    pub fn of(storage_backend: &'a str, repository_id: Uuid) -> Self {
        Self {
            scheme: crate::storage::StorageKeyScheme::from_env(),
            storage_backend,
            repository_id,
        }
    }

    fn key(self, path: &str) -> String {
        self.scheme
            .write_key(self.storage_backend, "mcp", self.repository_id, path)
    }
}

/// `artifacts.storage_key` a new server version is written to:
/// content-addressed, so a publish that loses the race for a version cannot
/// overwrite the bytes of the one that won.
///
/// On a shared cloud namespace (S3/GCS/Azure) the key is the repo-scoped
/// `mcp/{repository_id}/{name}/{version}/{sha256}.json`, so two MCP
/// repositories holding the same version (two Remotes of one upstream, a
/// hosted copy) write two objects. The flat `mcp/{name}/...` key they used to
/// share made the second repository's write fail the cross-repository write
/// guard with 409 (#5660). Filesystem backends and `STORAGE_KEY_SCHEME=flat`
/// keep the flat key. Existing objects are untouched: every MCP read resolves
/// the object through the `storage_key` its artifact row recorded.
pub fn storage_key(scope: KeyScope<'_>, name: &str, version: &str, sha256: &str) -> String {
    scope.key(&format!("{name}/{version}/{sha256}.json"))
}

/// `artifacts.storage_key` a new MCPB bundle is written to, scoped as
/// [`storage_key`] is (#5660).
pub fn bundle_storage_key(
    scope: KeyScope<'_>,
    name: &str,
    version: &str,
    sha256: &str,
    file: &str,
) -> String {
    scope.key(&format!("{name}/{version}/bundles/{sha256}/{file}"))
}

/// `(name, version)` from a [`storage_path`].
pub fn parse_storage_path(path: &str) -> Option<(String, String)> {
    let rest = path.trim_start_matches('/').strip_prefix("servers/")?;
    let rest = rest.strip_suffix("/server.json")?;
    let parts: Vec<&str> = rest.split('/').collect();
    match parts.as_slice() {
        [ns, short, version] => Some((format!("{ns}/{short}"), version.to_string())),
        _ => None,
    }
}

/// Listing cursors are sealed: AES-256-GCM under a key derived from the
/// instance's `jwt_secret`, bound to the repository that issued them and to
/// the listing kind. A client cannot read the position a cursor names and
/// cannot make one up. The MCP Registry API treats `cursor` as an opaque
/// string, so the format is free to change.
///
/// A reader listing's cursor never names a row the reader is not served,
/// not even sealed (#5453): it is a [`ListingResume`], the last row the
/// listing served and the internal id of the last row it read past it.
///
/// Wire form: `base64url(0x01 || nonce(12) || ciphertext+tag)`, no padding;
/// the plaintext is a JSON array of strings, the first the listing kind.
#[derive(Clone)]
pub struct CursorSeal {
    key: [u8; 32],
}

/// The listing a cursor belongs to (the first plaintext element).
pub mod cursor_kind {
    /// `GET /servers` of a hosted or Remote repository.
    pub const SERVERS: &str = "s";
    /// `GET /x/com.artifactkeeper/holds`.
    pub const HOLDS: &str = "h";
    /// `GET /servers` of a Virtual repository (member key, then position).
    pub const VIRTUAL: &str = "m";
}

const CURSOR_SEAL_VERSION: u8 = 1;
/// A cursor longer than this is refused before it is decoded.
const MAX_CURSOR_LEN: usize = 4096;

impl std::fmt::Debug for CursorSeal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CursorSeal(..)")
    }
}

impl CursorSeal {
    /// The seal of an instance whose `jwt_secret` is `secret`
    /// (HMAC-SHA256 key derivation with a label of its own, so the key is
    /// unrelated to the token-signing key).
    pub fn from_secret(secret: &str) -> Self {
        use hmac::{Hmac, Mac};
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes())
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(b"artifact-keeper/mcp-listing-cursor/aes-256-gcm/v1");
        Self {
            key: mac.finalize().into_bytes().into(),
        }
    }

    fn aad(scope: Uuid) -> Vec<u8> {
        let mut aad = b"ak-mcp-cursor/v1:".to_vec();
        aad.extend_from_slice(scope.as_bytes());
        aad
    }

    /// Seal `parts` for the listing of repository `scope`.
    pub fn seal(&self, scope: Uuid, parts: &[&str]) -> String {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::{Aes256Gcm, Nonce};
        let cipher = Aes256Gcm::new_from_slice(&self.key).expect("a 32-byte key");
        let nonce: [u8; 12] = rand::random();
        let plain = serde_json::to_vec(parts).expect("strings serialize");
        let aad = Self::aad(scope);
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: &aad,
                },
            )
            .expect("AES-256-GCM encryption does not fail");
        let mut out = Vec::with_capacity(1 + nonce.len() + ct.len());
        out.push(CURSOR_SEAL_VERSION);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(out)
    }

    /// The parts of a cursor this instance sealed for `scope`; anything else
    /// (made up, altered, issued by another repository or under another
    /// secret) is the listing's `400 invalid cursor`.
    pub fn open(&self, scope: Uuid, cursor: &str) -> std::result::Result<Vec<String>, McpError> {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::{Aes256Gcm, Nonce};
        let bad = || McpError::invalid_query("cursor", "invalid cursor");
        if cursor.len() > MAX_CURSOR_LEN {
            return Err(bad());
        }
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(cursor.trim_end_matches('='))
            .map_err(|_| bad())?;
        if raw.len() < 1 + 12 + 16 || raw[0] != CURSOR_SEAL_VERSION {
            return Err(bad());
        }
        let cipher = Aes256Gcm::new_from_slice(&self.key).expect("a 32-byte key");
        let aad = Self::aad(scope);
        let plain = cipher
            .decrypt(
                Nonce::from_slice(&raw[1..13]),
                Payload {
                    msg: &raw[13..],
                    aad: &aad,
                },
            )
            .map_err(|_| bad())?;
        serde_json::from_slice(&plain).map_err(|_| bad())
    }

    /// A `name, version` keyset position of listing `kind` of `scope`.
    pub fn encode_position(&self, scope: Uuid, kind: &str, name: &str, version: &str) -> String {
        self.seal(scope, &[kind, name, version])
    }

    /// Inverse of [`Self::encode_position`].
    pub fn decode_position(
        &self,
        scope: Uuid,
        kind: &str,
        cursor: &str,
    ) -> std::result::Result<(String, String), McpError> {
        let bad = || McpError::invalid_query("cursor", "invalid cursor");
        match <[String; 3]>::try_from(self.open(scope, cursor)?) {
            Ok([k, name, version]) if k == kind && !name.is_empty() && !version.is_empty() => {
                Ok((name, version))
            }
            _ => Err(bad()),
        }
    }

    /// A reader listing's [`ListingResume`] of listing `kind` of `scope`.
    pub fn encode_resume(&self, scope: Uuid, kind: &str, at: &ListingResume) -> String {
        let (name, version) = at
            .after
            .as_ref()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .unwrap_or(("", ""));
        self.seal(scope, &[kind, name, version, &encode_read(at.read)])
    }

    /// Inverse of [`Self::encode_resume`]. A plain position of
    /// [`Self::encode_position`] (a cursor issued before #5453) resumes after
    /// it.
    pub fn decode_resume(
        &self,
        scope: Uuid,
        kind: &str,
        cursor: &str,
    ) -> std::result::Result<ListingResume, McpError> {
        let bad = || McpError::invalid_query("cursor", "invalid cursor");
        let parts = self.open(scope, cursor)?;
        let (k, name, version, read) = match parts.as_slice() {
            [k, n, v] => (k, n, v, None),
            [k, n, v, r] => (k, n, v, decode_read(r).ok_or_else(bad)?),
            _ => return Err(bad()),
        };
        if k != kind {
            return Err(bad());
        }
        let after = match (name.is_empty(), version.is_empty()) {
            (false, false) => Some((name.clone(), version.clone())),
            (true, true) if read.is_some() => None,
            _ => return Err(bad()),
        };
        Ok(ListingResume { after, read })
    }
}

/// Where a reader listing resumes (#5453): after the keyset position
/// `after` (the last row it served, `None`: the start), or, when it read
/// past rows it does not serve (held, refused, unparseable), after the last
/// of them, which it names only by its internal artifact id `read`. The id
/// is a random UUID: fixed-length, unordered, and meaningless outside this
/// instance, so a cursor never carries the name or version of a row the
/// caller is not served, sealed or not. The listing looks the id up on
/// resume (deleted rows included) and continues strictly after it, at the
/// cost of a keyset resume at any depth; if the row was purged it resumes
/// after `after` instead.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListingResume {
    pub after: Option<(String, String)>,
    pub read: Option<Uuid>,
}

impl ListingResume {
    /// Resume after the served row `name@version`.
    pub fn after(name: &str, version: &str) -> Self {
        Self {
            after: Some((name.to_string(), version.to_string())),
            read: None,
        }
    }

    /// Account for one row a scan read, in order: a served row becomes the
    /// position; an unserved one is remembered by its id only.
    pub fn advance_one(&mut self, id: Uuid, key: (String, String), served: bool) {
        if served {
            self.after = Some(key);
            self.read = None;
        } else {
            self.read = Some(id);
        }
    }
}

/// `read` at a fixed width (the nil UUID for none), so the sealed cursor's
/// length does not say whether the listing read past unserved rows.
pub fn encode_read(read: Option<Uuid>) -> String {
    read.unwrap_or(Uuid::nil()).hyphenated().to_string()
}

/// Inverse of [`encode_read`]; `None` for anything that is not a UUID.
pub fn decode_read(s: &str) -> Option<Option<Uuid>> {
    let id = Uuid::parse_str(s).ok().filter(|_| s.len() == 36)?;
    Some((!id.is_nil()).then_some(id))
}

// ---------------------------------------------------------------------------
// Latest ordering
// ---------------------------------------------------------------------------

/// A strict SemVer 2.0.0 version split into core and prerelease, with the
/// optional `v` prefix upstream accepts (`golang.org/x/mod/semver` with
/// exactly three core parts, `internal/service/versioning.go`).
fn parse_semver(v: &str) -> Option<([&str; 3], Vec<&str>)> {
    let v = v.strip_prefix('v').unwrap_or(v);
    let v = v.split_once('+').map(|(c, _)| c).unwrap_or(v);
    let (core, pre) = match v.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (v, None),
    };
    let mut parts = core.split('.');
    let mut nums = [""; 3];
    for slot in nums.iter_mut() {
        let p = parts.next()?;
        if p.is_empty()
            || !p.bytes().all(|b| b.is_ascii_digit())
            || (p.len() > 1 && p.starts_with('0'))
        {
            return None;
        }
        *slot = p;
    }
    if parts.next().is_some() {
        return None;
    }
    let pre: Vec<&str> = match pre {
        Some(p) => {
            let ids: Vec<&str> = p.split('.').collect();
            if ids.iter().any(|i| i.is_empty()) {
                return None;
            }
            ids
        }
        None => Vec::new(),
    };
    Some((nums, pre))
}

/// Order two versions for "which is latest", as upstream's
/// `CompareVersions` (`internal/service/versioning.go`): both SemVer ->
/// SemVer order; one SemVer and one not -> the SemVer version is higher; two
/// non-SemVer versions are equal (the caller breaks the tie on
/// `publishedAt`).
pub fn compare_versions_for_latest(a: &str, b: &str) -> Ordering {
    use crate::services::version_order::{
        compare_digit_runs, compare_semver_prerelease_identifier,
    };
    match (parse_semver(a), parse_semver(b)) {
        (Some((ca, pa)), Some((cb, pb))) => {
            for (x, y) in ca.iter().zip(cb.iter()) {
                let o = compare_digit_runs(x, y);
                if o != Ordering::Equal {
                    return o;
                }
            }
            match (pa.is_empty(), pb.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => {
                    for (x, y) in pa.iter().zip(pb.iter()) {
                        let o = compare_semver_prerelease_identifier(x, y);
                        if o != Ordering::Equal {
                            return o;
                        }
                    }
                    pa.len().cmp(&pb.len())
                }
            }
        }
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

/// [`compare_versions_for_latest`] with the `publishedAt` tie break.
pub fn latest_order(
    a: (&str, Option<DateTime<Utc>>),
    b: (&str, Option<DateTime<Utc>>),
) -> Ordering {
    compare_versions_for_latest(a.0, b.0).then_with(|| a.1.cmp(&b.1))
}

/// Index of the latest of `candidates` (`(version, publishedAt)`), if any.
pub fn pick_latest(candidates: &[(&str, Option<DateTime<Utc>>)]) -> Option<usize> {
    (0..candidates.len()).max_by(|&i, &j| latest_order(candidates[i], candidates[j]))
}

// ---------------------------------------------------------------------------
// OCI identifiers
// ---------------------------------------------------------------------------

/// A parsed image reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OciRef {
    pub host: String,
    pub path: String,
    pub tag: Option<String>,
    pub digest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OciRefError {
    Invalid(String),
    /// `:latest`, or neither tag nor digest.
    Floating,
}

/// Parse an image reference the way go-containerregistry does: the first
/// component is a registry host when it contains `.` or `:` or is
/// `localhost`, otherwise the host is `docker.io` (and a one-component path
/// gains `library/`).
pub fn parse_oci_identifier(s: &str) -> std::result::Result<OciRef, OciRefError> {
    match parse_oci_reference(s)? {
        (_, true) => Err(OciRefError::Floating),
        (r, false) => Ok(r),
    }
}

/// [`parse_oci_identifier`] that resolves a floating reference instead of
/// refusing it: `:latest` and a tagless reference both come back with tag
/// `latest` and `true` (floating).
pub fn parse_oci_reference(s: &str) -> std::result::Result<(OciRef, bool), OciRefError> {
    let invalid = |m: &str| OciRefError::Invalid(m.to_string());
    if s.is_empty() || s.len() > 512 || s.chars().any(char::is_whitespace) {
        return Err(invalid("not an image reference"));
    }
    let (name_tag, digest) = match s.split_once('@') {
        Some((n, d)) => {
            crate::formats::oci::OciHandler::validate_digest(d)
                .map_err(|_| invalid("the digest must be sha256:<64 hex> or sha512:<128 hex>"))?;
            if !d.split_once(':').is_some_and(|(_, h)| {
                h.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            }) {
                return Err(invalid("the digest must be lower-case hex"));
            }
            (n, Some(d.to_string()))
        }
        None => (s, None),
    };
    let last_slash = name_tag.rfind('/').map(|i| i + 1).unwrap_or(0);
    let (name, tag) = match name_tag[last_slash..].rfind(':') {
        Some(i) => (
            &name_tag[..last_slash + i],
            Some(name_tag[last_slash + i + 1..].to_string()),
        ),
        None => (name_tag, None),
    };
    if let Some(t) = tag.as_deref() {
        if !re(OCI_TAG_RE).is_match(t) {
            return Err(invalid(
                "the tag does not match the distribution-spec grammar",
            ));
        }
    }
    let (host, path) = match name.split_once('/') {
        Some((first, rest))
            if first.contains('.') || first.contains(':') || first == "localhost" =>
        {
            (first.to_string(), rest.to_string())
        }
        _ if name.contains('/') => ("docker.io".to_string(), name.to_string()),
        _ => ("docker.io".to_string(), format!("library/{name}")),
    };
    if path.is_empty()
        || !path
            .split('/')
            .all(|c| re(OCI_PATH_COMPONENT_RE).is_match(c))
    {
        return Err(invalid("the repository path is not a valid image name"));
    }
    let floating = tag.as_deref() == Some("latest") || (tag.is_none() && digest.is_none());
    let tag = if floating {
        Some("latest".to_string())
    } else {
        tag
    };
    Ok((
        OciRef {
            host,
            path,
            tag,
            digest,
        },
        floating,
    ))
}

// ---------------------------------------------------------------------------
// Stored metadata
// ---------------------------------------------------------------------------

/// Upstream `_meta.official.status`: a closed enum, never a hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServerStatus {
    Active,
    Deprecated,
    Deleted,
}

impl ServerStatus {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "active" => Some(Self::Active),
            "deprecated" => Some(Self::Deprecated),
            "deleted" => Some(Self::Deleted),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Deprecated => "deprecated",
            Self::Deleted => "deleted",
        }
    }
}

/// `metadata.registry`: the mutable registry state of one server version,
/// served as `_meta["io.modelcontextprotocol.registry/official"]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryState {
    pub status: ServerStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_message: Option<String>,
    pub status_changed_at: DateTime<Utc>,
    pub published_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_latest: bool,
}

impl RegistryState {
    pub fn new_active(now: DateTime<Utc>) -> Self {
        Self {
            status: ServerStatus::Active,
            status_message: None,
            status_changed_at: now,
            published_at: now,
            updated_at: now,
            is_latest: false,
        }
    }
}

/// Validate a status PATCH body against the current status.
pub fn validate_status_change(
    current: ServerStatus,
    next: ServerStatus,
    message: Option<&str>,
) -> V {
    if current == next {
        return Err(McpError::invalid(
            "status",
            format!("the version is already {}", next.as_str()),
        ));
    }
    if message.is_some() && next == ServerStatus::Active {
        return Err(McpError::invalid(
            "statusMessage",
            "an active version carries no status message",
        ));
    }
    check_text("statusMessage", message, Some(STATUS_MESSAGE_MAX))
}

/// `metadata.policy.package`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PackagePolicy {
    /// Default: every package resolves to an AK repository of its format,
    /// and its coordinates must name that repository (`registryBaseUrl`
    /// omitted or this instance's, an OCI image on this instance or the
    /// backing Remote's upstream).
    OwnRepos,
    /// Foreign coordinates accepted (#5452): a `registryBaseUrl` or OCI image
    /// host naming another registry is not refused. The package itself is
    /// still looked up by name and version (an image by path and tag or
    /// digest) in the mapped backing repository, pinned, served at its AK
    /// coordinates and gated exactly as under `own-repos`; one that does not
    /// resolve is refused at publish, or held (`unresolvable`) when synced or
    /// stored without a pin. Nothing is served verbatim.
    Open,
}

impl PackagePolicy {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().trim_matches('"') {
            "own-repos" => Some(Self::OwnRepos),
            "open" => Some(Self::Open),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OwnRepos => "own-repos",
            Self::Open => "open",
        }
    }
}

/// One platform child of a pinned image index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciChild {
    pub platform: String,
    pub digest: String,
}

/// What a package was pinned to at publish.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedPin {
    /// Backing repository key (served in the rewritten coordinates).
    pub repository: String,
    pub repository_id: Uuid,
    /// The backing `artifacts` rows the gate evaluates.
    #[serde(default)]
    pub artifact_ids: Vec<Uuid>,
    /// The sha256 of each `artifact_ids` row at publish, in the same order
    /// (absent on pins taken before #5456): a row whose bytes changed in
    /// place no longer counts as the pinned row.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifact_sha256s: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<OciChild>,
    /// The digest the scanner gate keys on (an index's runner-arch child).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate_digest: Option<String>,
    pub resolved_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// A package pulled through a Remote backing repository: its path in the
    /// Remote's proxy cache (`proxy_cache_artifacts`), where the gate finds
    /// the pinned bytes (proxied content has no `artifacts` row).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_path: Option<String>,
    /// An `mcpb` bundle: the route it is downloaded from, relative to the
    /// instance base URL (`mcp/<repo>/v0.1/servers/.../bundles/<file>`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmittedRef {
    pub identifier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// One entry of `metadata.packages[]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackagePin {
    pub index: usize,
    pub registry_type: String,
    pub submitted: SubmittedRef,
    pub resolved: ResolvedPin,
    /// Set when the pinned OCI tag later moved (`MCP_PIN_DRIFT_DETECTED`).
    #[serde(default)]
    pub drift: Option<serde_json::Value>,
}

impl PackagePin {
    /// `"npm:@acme/x@1.0.0"` / `"oci:ghcr.io/acme/mcp:1.2"`: how a refusal
    /// names the package (never the backing repository or artifact id).
    pub fn label(&self) -> String {
        match &self.submitted.version {
            Some(v) => format!("{}:{}@{}", self.registry_type, self.submitted.identifier, v),
            None => format!("{}:{}", self.registry_type, self.submitted.identifier),
        }
    }
}

/// `metadata.index`: denormalised fields for listing filters.
pub fn index_doc(s: &ServerJson) -> serde_json::Value {
    let mut package_types: Vec<&str> = s
        .packages
        .iter()
        .map(|p| p.registry_type.as_str())
        .collect();
    package_types.sort_unstable();
    package_types.dedup();
    let mut remote_types: Vec<&str> = s.remotes.iter().map(|r| r.r#type.as_str()).collect();
    remote_types.sort_unstable();
    remote_types.dedup();
    let (ns, short) = s.name.split_once('/').unwrap_or((&s.name, ""));
    serde_json::json!({
        "namespace": ns,
        "shortName": short,
        "packageTypes": package_types,
        "remoteTypes": remote_types,
    })
}

/// The whole `artifact_metadata.metadata` document of a server version.
pub fn metadata_doc(
    server: &ServerJson,
    registry: &RegistryState,
    policy: PackagePolicy,
    pins: &[PackagePin],
) -> serde_json::Value {
    serde_json::json!({
        "schema": server.schema.as_deref().unwrap_or(SCHEMA_URL),
        "server": server,
        "registry": registry,
        "policy": { "package": policy.as_str() },
        "packages": pins,
        "index": index_doc(server),
    })
}

/// The parts of a stored metadata document the read paths use.
#[derive(Debug, Clone)]
pub struct StoredVersion {
    pub server: serde_json::Value,
    pub registry: RegistryState,
    pub policy: PackagePolicy,
    pub pins: Vec<PackagePin>,
    /// `metadata.upstream` of a version a Remote ingested from its upstream
    /// registry (`{origin, sha256, publishedAt, updatedAt}`); `None` when
    /// published here.
    pub upstream: Option<serde_json::Value>,
    /// The version's packages are still being resolved
    /// (`metadata.resolution.state == "resolving"`): held as
    /// [`HoldKind::Resolving`].
    pub resolving: bool,
}

impl StoredVersion {
    /// `None` when the document is not a well-formed MCP metadata document.
    pub fn from_metadata(doc: &serde_json::Value) -> Option<Self> {
        let server = doc.get("server")?.clone();
        if !server.is_object() {
            return None;
        }
        let registry: RegistryState = serde_json::from_value(doc.get("registry")?.clone()).ok()?;
        let policy = doc
            .pointer("/policy/package")
            .and_then(|v| v.as_str())
            .and_then(PackagePolicy::parse)
            .unwrap_or(PackagePolicy::OwnRepos);
        let pins: Vec<PackagePin> = match doc.get("packages") {
            Some(v) => serde_json::from_value(v.clone()).ok()?,
            None => Vec::new(),
        };
        let upstream = doc.get("upstream").filter(|u| u.is_object()).cloned();
        let resolving =
            doc.pointer("/resolution/state").and_then(|v| v.as_str()) == Some("resolving");
        Some(Self {
            server,
            registry,
            policy,
            pins,
            upstream,
            resolving,
        })
    }

    /// The first `packages[]` entry of the server with no pin, if any. Such a
    /// version is `unresolvable` under either policy: one stored before
    /// #5452 under `open` (which pinned nothing), one whose pins were lost,
    /// or a synced version a package of which did not resolve.
    pub fn unpinned_package(&self) -> Option<String> {
        self.unpinned_packages().into_iter().next().map(|(_, l)| l)
    }

    /// Every `packages[]` entry with no pin, as `(index, label)` (the label
    /// as [`PackagePin::label`] would name it).
    pub fn unpinned_packages(&self) -> Vec<(usize, String)> {
        let packages = self
            .server
            .get("packages")
            .and_then(|p| p.as_array())
            .cloned()
            .unwrap_or_default();
        packages
            .iter()
            .enumerate()
            .filter(|(i, _)| !self.pins.iter().any(|pin| pin.index == *i))
            .map(|(i, p)| {
                let ty = p.get("registryType").and_then(|v| v.as_str()).unwrap_or("");
                let id = p.get("identifier").and_then(|v| v.as_str()).unwrap_or("");
                let label = match p.get("version").and_then(|v| v.as_str()) {
                    Some(v) => format!("{ty}:{id}@{v}"),
                    None => format!("{ty}:{id}"),
                };
                (i, label)
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Serving
// ---------------------------------------------------------------------------

/// The URL path segment AK serves each artifact-backed registry type under.
fn backing_route(registry_type: &str, repo_key: &str) -> String {
    match registry_type {
        "nuget" => format!("nuget/{repo_key}/v3/index.json"),
        other => format!("{other}/{repo_key}"),
    }
}

/// `host[:port]` of a base URL.
pub fn host_of(base_url: &str) -> String {
    url::Url::parse(base_url)
        .ok()
        .and_then(|u| {
            u.host_str().map(|h| match u.port() {
                Some(p) => format!("{h}:{p}"),
                None => h.to_string(),
            })
        })
        .unwrap_or_else(|| "localhost".to_string())
}

/// The served form of a stored `server`: every pinned package is rewritten
/// to its AK coordinates (`registryBaseUrl` for npm/pypi/nuget/cargo,
/// `identifier` with `@sha256:` for OCI, original in
/// `_meta[com.artifactkeeper/resolved]`), whatever the package policy: an
/// `open` document is pinned and served the same way (#5452). A package with
/// no pin is left as stored, but the version is never served then: the
/// serve decision holds it `unresolvable` ([`StoredVersion::unpinned_package`]).
pub fn rewrite_packages_for_serve(
    server: &serde_json::Value,
    pins: &[PackagePin],
    base_url: &str,
) -> serde_json::Value {
    let mut out = server.clone();
    let base = base_url.trim_end_matches('/');
    let oci_host = host_of(base);
    let Some(packages) = out.get_mut("packages").and_then(|p| p.as_array_mut()) else {
        return out;
    };
    for pin in pins {
        let Some(pkg) = packages.get_mut(pin.index).and_then(|p| p.as_object_mut()) else {
            continue;
        };
        let r = &pin.resolved;
        if let Some(path) = r.download_path.as_deref() {
            // An `mcpb` bundle: served from this instance.
            pkg.insert("identifier".into(), format!("{base}/{path}").into());
        } else if pin.registry_type == "oci" {
            let (Some(name), Some(digest)) = (r.name.as_deref(), r.digest.as_deref()) else {
                continue;
            };
            let identifier = match r.tag.as_deref() {
                Some(tag) => format!("{oci_host}/{}/{name}:{tag}@{digest}", r.repository),
                None => format!("{oci_host}/{}/{name}@{digest}", r.repository),
            };
            pkg.insert("identifier".into(), identifier.into());
            let mut resolved = serde_json::json!({
                "submittedIdentifier": pin.submitted.identifier,
                "digest": digest,
                "mediaType": r.media_type,
                "children": r.children,
                "backingRepository": r.repository,
                "resolvedAt": r.resolved_at,
            });
            if !r.warnings.is_empty() {
                resolved["warnings"] = serde_json::json!(r.warnings);
            }
            set_resolved_meta(pkg, resolved);
        } else {
            // What the publisher named, so a client (and a reviewer) can see
            // that a foreign registry was replaced by this one (#5452).
            let submitted = pkg.get("registryBaseUrl").cloned();
            pkg.insert(
                "registryBaseUrl".into(),
                format!(
                    "{base}/{}",
                    backing_route(&pin.registry_type, &r.repository)
                )
                .into(),
            );
            let mut resolved = serde_json::json!({
                "submittedIdentifier": pin.submitted.identifier,
                "sha256": r.sha256,
                "backingRepository": r.repository,
                "resolvedAt": r.resolved_at,
            });
            if let Some(url) = submitted.filter(|u| !u.is_null()) {
                resolved["submittedRegistryBaseUrl"] = url;
            }
            if !r.warnings.is_empty() {
                resolved["warnings"] = serde_json::json!(r.warnings);
            }
            set_resolved_meta(pkg, resolved);
        }
    }
    out
}

/// Set `_meta["com.artifactkeeper/resolved"]` of a served package, replacing
/// whatever the stored document carried under that key.
fn set_resolved_meta(
    pkg: &mut serde_json::Map<String, serde_json::Value>,
    resolved: serde_json::Value,
) {
    let meta = pkg.entry("_meta").or_insert_with(|| serde_json::json!({}));
    if !meta.is_object() {
        *meta = serde_json::json!({});
    }
    if let Some(meta) = meta.as_object_mut() {
        meta.insert(AK_RESOLVED_META_KEY.into(), resolved);
    }
}

/// One server version as a list/detail entry: `{server, _meta}`.
pub fn envelope(
    server: serde_json::Value,
    registry: &RegistryState,
    source: serde_json::Value,
) -> serde_json::Value {
    let mut meta = serde_json::Map::new();
    meta.insert(
        OFFICIAL_META_KEY.into(),
        serde_json::to_value(registry).unwrap_or_default(),
    );
    meta.insert(AK_SOURCE_META_KEY.into(), source);
    serde_json::json!({ "server": server, "_meta": meta })
}

/// Host of the official MCP registry: an upstream there is trusted for
/// [`upstream_verified`].
pub const OFFICIAL_REGISTRY_HOST: &str = "registry.modelcontextprotocol.io";

/// How an upstream registry is classified at ingest (`metadata.upstream.kind`):
/// `official` (`https://registry.modelcontextprotocol.io`), `artifact-keeper`
/// (the entry carried another Artifact Keeper's
/// `_meta["com.artifactkeeper.registry/source"]`), else `other`.
pub fn upstream_kind(upstream_url: &str, entry_has_ak_source: bool) -> &'static str {
    let official = url::Url::parse(upstream_url).ok().is_some_and(|u| {
        u.scheme() == "https"
            && u.host_str()
                .is_some_and(|h| h.eq_ignore_ascii_case(OFFICIAL_REGISTRY_HOST))
    });
    if official {
        "official"
    } else if entry_has_ak_source {
        "artifact-keeper"
    } else {
        "other"
    }
}

/// `_meta["com.artifactkeeper.registry/source"].origin` of a stored version:
/// `hosted` (published to this instance), `mirror` (ingested by a Remote in
/// `mcp_remote_mode: mirror`) or `remote` (ingested by a Remote in
/// `allowlist` mode, and every ingested version recorded before the mode was).
pub fn served_origin(upstream: Option<&serde_json::Value>) -> &'static str {
    match upstream {
        None => "hosted",
        Some(u) if u.get("mode").and_then(|m| m.as_str()) == Some("mirror") => "mirror",
        Some(_) => "remote",
    }
}

/// `_meta["com.artifactkeeper.registry/source"].upstreamVerified`: `true`
/// only for a version ingested from an upstream that is the official
/// registry or another Artifact Keeper (`metadata.upstream.kind`), whose
/// content matched at ingest (`metadata.upstream.contentVerified`: an
/// Artifact Keeper upstream's advertised sha256 equals the sha256 of the
/// received document; the official registry advertises no content hash, so
/// there the document as fetched over HTTPS from it is the reference) and
/// whose upstream bytes have not changed since (`metadata.upstream.drifted`,
/// set by a later sync that saw other bytes). Hosted versions are `false`.
pub fn upstream_verified(upstream: Option<&serde_json::Value>) -> bool {
    let Some(u) = upstream else {
        return false;
    };
    let kind = u.get("kind").and_then(|k| k.as_str());
    let flag = |k: &str| u.get(k).and_then(|v| v.as_bool());
    matches!(kind, Some("official" | "artifact-keeper"))
        && flag("contentVerified") == Some(true)
        && flag("drifted") != Some(true)
}

/// The risk inputs of a server.json `server` object, as the Remote catalog
/// caches them (`CatalogItem.summary`): the transports (package
/// `transport.type` and remote `type`), package `registryType`s (both
/// sorted, de-duplicated), how many environment variables and headers
/// (package transport headers and remote headers) are marked `isSecret`, and
/// the package and remote counts.
pub fn server_risk_summary(server: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    let arr = |v: &Value, k: &str| {
        v.get(k)
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let (packages, remotes) = (arr(server, "packages"), arr(server, "remotes"));
    let sorted = |it: &mut dyn Iterator<Item = &Value>| {
        let mut v: Vec<String> = it.filter_map(Value::as_str).map(str::to_string).collect();
        v.sort();
        v.dedup();
        v
    };
    let transports = sorted(
        &mut packages
            .iter()
            .filter_map(|p| p.pointer("/transport/type"))
            .chain(remotes.iter().filter_map(|r| r.get("type"))),
    );
    let registry_types = sorted(&mut packages.iter().filter_map(|p| p.get("registryType")));
    let secret = |list: Vec<Value>| {
        list.iter()
            .filter(|e| e.get("isSecret").and_then(Value::as_bool) == Some(true))
            .count()
    };
    let secrets: usize = packages
        .iter()
        .map(|p| {
            secret(arr(p, "environmentVariables"))
                + secret(
                    p.get("transport")
                        .map(|t| arr(t, "headers"))
                        .unwrap_or_default(),
                )
        })
        .chain(remotes.iter().map(|r| secret(arr(r, "headers"))))
        .sum();
    serde_json::json!({
        "transports": transports,
        "registryTypes": registry_types,
        "secretsCount": secrets,
        "packagesCount": packages.len(),
        "remotesCount": remotes.len(),
    })
}

/// The catalog (`/api/v1/packages`) `metadata` of a stored MCP version: a
/// summary of its server.json so generic package views can show it without
/// the registry API.
pub fn catalog_metadata(doc: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    let server = doc.get("server").cloned().unwrap_or(Value::Null);
    let risk = server_risk_summary(&server);
    let upstream = doc.get("upstream").filter(|u| u.is_object());
    let field = |k: &str| server.get(k).cloned().unwrap_or(Value::Null);
    serde_json::json!({
        "format": "mcp",
        "source": if upstream.is_some() { "upstream" } else { "hosted" },
        "origin": served_origin(upstream),
        "name": field("name"),
        "version": field("version"),
        "title": field("title"),
        "description": field("description"),
        "status": doc.pointer("/registry/status").cloned().unwrap_or(Value::Null),
        "transports": risk["transports"],
        "packagesCount": risk["packagesCount"],
        "remotesCount": risk["remotesCount"],
        "registryTypes": risk["registryTypes"],
    })
}

/// The upstream list envelope.
pub fn list_envelope(
    entries: Vec<serde_json::Value>,
    next_cursor: Option<String>,
) -> serde_json::Value {
    let mut metadata = serde_json::json!({ "count": entries.len() });
    if let Some(c) = next_cursor {
        metadata["nextCursor"] = c.into();
    }
    serde_json::json!({ "servers": entries, "metadata": metadata })
}

// ---------------------------------------------------------------------------
// The serve decision
// ---------------------------------------------------------------------------

/// A hold on the server.json artifact itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldKind {
    /// Upload-period or administrator quarantine.
    Quarantine,
    /// Refused by scan policy, or rejected.
    ScanPolicy,
    /// Resolution still running (Phase 2 async resolver).
    Resolving,
    /// Remote repository: the server name (or this `name@version`) is not
    /// approved yet (curation `pending`/`review`).
    PendingApproval { review_id: Option<Uuid> },
    /// Remote repository: the server name is blocked, or matches a
    /// `mcp_server_deny` glob (deny always wins).
    Denied { review_id: Option<Uuid> },
    /// Remote repository: the upstream entry changed content under an already
    /// ingested `name@version`; approval is revoked and re-queued.
    ContentDrift { review_id: Option<Uuid> },
    /// The server version itself is newer than the repository's age gate
    /// allows (`FirstSeen` basis for server versions).
    AgeGate {
        review_id: Option<Uuid>,
        min_age_days: i64,
        requested_age_days: Option<i64>,
    },
}

/// The server version's own state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionState {
    pub name: String,
    pub version: String,
    pub status: ServerStatus,
    pub own_hold: Option<HoldKind>,
    pub include_deleted: bool,
    /// `instance` member of a reason-gated refusal: the authenticated AK URL
    /// of this version.
    pub instance: String,
}

/// What the download gate said about one pinned backing package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateOutcome {
    Allowed,
    Quarantine,
    ScanPolicy,
    AgeGate {
        review_id: Option<Uuid>,
        min_age_days: i64,
        requested_age_days: Option<i64>,
    },
    /// The pinned artifact or manifest is gone (or was never pinned).
    Unresolvable,
    /// A Virtual backing repository now serves the pinned coordinate from
    /// another member than the pinned one (#5456).
    Shadowed,
    /// The gate could not be evaluated.
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackingGate {
    /// `"npm:@acme/x@1.0.0"`.
    pub package: String,
    pub outcome: GateOutcome,
}

/// Who is asking: a caller who holds the repository (`in_scope AND (is_admin
/// OR grants)`, the predicate the quarantine status endpoint uses) may read
/// why; everyone else gets the unknown-name answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateAudience {
    ReasonGated,
    ReaderOnly,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ServeDecision {
    Serve,
    Refuse {
        status: u16,
        body: serde_json::Value,
        /// Short hold class for the audit row (`quarantine`, `backing`, ...).
        hold_class: &'static str,
    },
}

/// The reader-facing 404 body, as a `Value` that serialises to exactly
/// [`NOT_FOUND_BODY`].
pub fn not_found_value() -> serde_json::Value {
    serde_json::from_str(NOT_FOUND_BODY).expect("NOT_FOUND_BODY is JSON")
}

/// The one decision behind every read of the MCP surface. Order:
/// an unevaluable gate (503, same for everyone), `deleted` without
/// `include_deleted` (plain 404), the version's own hold, the first refusing
/// backing package, else serve. Reader-only callers get [`NOT_FOUND_BODY`]
/// for every 404; reason-gated callers get the reason, never a backing
/// repository key, artifact id, finding or policy text.
pub fn decide_mcp_serve(
    version: &VersionState,
    backing: &[BackingGate],
    audience: GateAudience,
) -> ServeDecision {
    if backing
        .iter()
        .any(|g| g.outcome == GateOutcome::Unavailable)
    {
        return ServeDecision::Refuse {
            status: 503,
            body: problem_body(
                503,
                "mcp_gate_unavailable",
                "The registry could not evaluate this server version's gates; retry later",
                serde_json::json!({}),
            ),
            hold_class: "unavailable",
        };
    }
    let refuse = |hold_class: &'static str, error: &str, detail: &str, extra: serde_json::Value| {
        let body = match audience {
            GateAudience::ReaderOnly => not_found_value(),
            GateAudience::ReasonGated => {
                let mut members = serde_json::json!({
                    "instance": version.instance,
                    "name": version.name,
                    "version": version.version,
                    "hold": hold_class,
                });
                if let (Some(m), serde_json::Value::Object(more)) = (members.as_object_mut(), extra)
                {
                    m.extend(more);
                }
                problem_body(404, error, detail, members)
            }
        };
        ServeDecision::Refuse {
            status: 404,
            body,
            hold_class,
        }
    };
    if version.status == ServerStatus::Deleted && !version.include_deleted {
        return ServeDecision::Refuse {
            status: 404,
            body: not_found_value(),
            hold_class: "deleted",
        };
    }
    match version.own_hold {
        Some(HoldKind::Quarantine) => {
            return refuse(
                "quarantine",
                "mcp_pending_review",
                "This server version is held pending review",
                serde_json::json!({}),
            )
        }
        Some(HoldKind::ScanPolicy) => {
            return refuse(
                "scan_policy",
                "mcp_rejected",
                "This server version is refused by the repository's security policy",
                serde_json::json!({}),
            )
        }
        Some(HoldKind::Resolving) => {
            return refuse(
                "resolving",
                "mcp_resolving",
                "This server version's packages are still being resolved",
                serde_json::json!({}),
            )
        }
        Some(HoldKind::PendingApproval { review_id }) => {
            return refuse(
                "curation",
                "mcp_pending_review",
                "This server is awaiting approval in this registry",
                serde_json::json!({"gate": "curation", "review_id": review_id}),
            )
        }
        Some(HoldKind::Denied { review_id }) => {
            return refuse(
                "curation",
                "mcp_rejected",
                "This server is not approved in this registry",
                serde_json::json!({"gate": "curation", "review_id": review_id}),
            )
        }
        Some(HoldKind::ContentDrift { review_id }) => {
            return refuse(
                "content_drift",
                "mcp_pending_review",
                "This server version changed upstream and is awaiting re-approval",
                serde_json::json!({"gate": "curation", "review_id": review_id}),
            )
        }
        Some(HoldKind::AgeGate {
            review_id,
            min_age_days,
            requested_age_days,
        }) => {
            return refuse(
                "age_gate",
                "mcp_age_gate_blocked",
                "This server version is newer than the age policy allows",
                serde_json::json!({
                    "gate": "age_gate",
                    "review_id": review_id,
                    "min_age_days": min_age_days,
                    "requested_age_days": requested_age_days,
                }),
            )
        }
        None => {}
    }
    for gate in backing {
        match &gate.outcome {
            GateOutcome::Allowed | GateOutcome::Unavailable => {}
            GateOutcome::Quarantine => {
                return refuse(
                    "backing",
                    "mcp_backing_artifact_blocked",
                    "A package this server version runs is held pending review",
                    serde_json::json!({"package": gate.package, "gate": "quarantine"}),
                )
            }
            GateOutcome::ScanPolicy => {
                return refuse(
                    "backing",
                    "mcp_backing_artifact_blocked",
                    "A package this server version runs is refused by security policy",
                    serde_json::json!({"package": gate.package, "gate": "scan_policy"}),
                )
            }
            GateOutcome::AgeGate {
                review_id,
                min_age_days,
                requested_age_days,
            } => {
                return refuse(
                    "age_gate",
                    "mcp_age_gate_blocked",
                    "A package this server version runs is newer than the age policy allows",
                    serde_json::json!({
                        "package": gate.package,
                        "gate": "age_gate",
                        "review_id": review_id,
                        "min_age_days": min_age_days,
                        "requested_age_days": requested_age_days,
                    }),
                )
            }
            GateOutcome::Unresolvable => {
                return refuse(
                    "unresolvable",
                    "mcp_unresolvable",
                    "A package this server version runs can no longer be resolved",
                    serde_json::json!({"package": gate.package}),
                )
            }
            GateOutcome::Shadowed => {
                return refuse(
                    "unresolvable",
                    "mcp_unresolvable",
                    "A package this server version runs can no longer be resolved",
                    serde_json::json!({"package": gate.package, "gate": "shadowed"}),
                )
            }
        }
    }
    ServeDecision::Serve
}

// ---------------------------------------------------------------------------
// FormatHandler
// ---------------------------------------------------------------------------

/// MCP registry format handler.
pub struct McpHandler;

impl McpHandler {
    pub fn new() -> Self {
        Self
    }

    /// Parse and validate `content`, and check it is stored at its own path.
    fn check(path: &str, content: &[u8]) -> Result<ServerJson> {
        let server = parse_server_json(content).map_err(AppError::from)?;
        validate_server_json(&server).map_err(AppError::from)?;
        if let Some((name, version)) = parse_storage_path(path) {
            if name != server.name || version != server.version {
                return Err(AppError::Validation(format!(
                    "server.json names {}@{} but is stored at {path}",
                    server.name, server.version
                )));
            }
        }
        Ok(server)
    }
}

impl Default for McpHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FormatHandler for McpHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Mcp
    }

    fn format_key(&self) -> &str {
        "mcp"
    }

    async fn parse_metadata(&self, path: &str, content: &Bytes) -> Result<serde_json::Value> {
        let s = Self::check(path, content)?;
        Ok(serde_json::json!({
            "name": s.name,
            "version": s.version,
            "description": s.description,
            "package_count": s.packages.len(),
            "remote_count": s.remotes.len(),
        }))
    }

    async fn validate(&self, path: &str, content: &Bytes) -> Result<()> {
        Self::check(path, content).map(|_| ())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        Ok(None)
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    fn doc(extra: serde_json::Value) -> serde_json::Value {
        let mut base = serde_json::json!({
            "name": "com.acme/weather",
            "description": "Weather tools",
            "version": "1.0.0",
            "remotes": [{"type": "streamable-http", "url": "https://mcp.acme.test/mcp"}],
        });
        if let (Some(b), serde_json::Value::Object(e)) = (base.as_object_mut(), extra) {
            b.extend(e);
        }
        base
    }

    fn check(v: serde_json::Value) -> std::result::Result<ServerJson, McpError> {
        let s = parse_server_json(&serde_json::to_vec(&v).unwrap())?;
        validate_server_json(&s)?;
        Ok(s)
    }

    fn invalid_path(v: serde_json::Value) -> String {
        match check(v) {
            Err(McpError::Invalid { path, .. }) => path,
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    fn npm(extra: serde_json::Value) -> serde_json::Value {
        let mut p = serde_json::json!({
            "registryType": "npm", "identifier": "@acme/weather", "version": "1.0.0",
            "transport": {"type": "stdio"},
        });
        if let (Some(b), serde_json::Value::Object(e)) = (p.as_object_mut(), extra) {
            b.extend(e);
        }
        p
    }

    #[test]
    fn minimal_documents_validate() {
        assert!(check(doc(serde_json::json!({}))).is_ok());
        assert!(check(doc(
            serde_json::json!({"remotes": [], "packages": [npm(serde_json::json!({}))]})
        ))
        .is_ok());
    }

    #[test]
    fn name_rules() {
        for bad in [
            "ab",
            "noslash",
            "a/b/c",
            "com..acme/x",
            "com.acme/../x",
            "com acme/x",
            ".com/x",
            "com./x",
            "com.acme/.x",
        ] {
            assert_eq!(
                invalid_path(doc(serde_json::json!({"name": bad}))),
                "name",
                "{bad}"
            );
        }
        let long = format!("com.acme/{}", "a".repeat(200));
        assert_eq!(invalid_path(doc(serde_json::json!({"name": long}))), "name");
        assert!(check(doc(
            serde_json::json!({"name": "io.github.user/my_server-2.x"})
        ))
        .is_ok());
    }

    #[test]
    fn description_title_and_text_rules() {
        assert_eq!(
            invalid_path(doc(serde_json::json!({"description": ""}))),
            "description"
        );
        assert_eq!(
            invalid_path(doc(serde_json::json!({"description": "x".repeat(101)}))),
            "description"
        );
        assert!(check(doc(serde_json::json!({"description": "é".repeat(100)}))).is_ok());
        for evil in [
            '\u{202E}',
            '\u{200B}',
            '\u{FEFF}',
            '\n',
            '\u{2066}',
            '\u{0007}',
            '\u{061C}',
            '\u{2028}',
            '\u{2029}',
            '\u{2060}',
            '\u{2064}',
            '\u{E0001}',
            '\u{E007F}',
        ] {
            let text = format!("a{evil}b");
            assert_eq!(
                invalid_path(doc(serde_json::json!({"description": text}))),
                "description"
            );
            assert_eq!(
                invalid_path(doc(serde_json::json!({"title": text}))),
                "title"
            );
        }
        assert_eq!(
            invalid_path(doc(serde_json::json!({"title": "t".repeat(101)}))),
            "title"
        );
        assert_eq!(
            invalid_path(doc(serde_json::json!({"title": " "}))),
            "title"
        );
    }

    #[test]
    fn version_rules() {
        for bad in [
            "",
            "latest",
            "LATEST",
            "^1.0.0",
            "~1.0",
            "1.x",
            "1.0.*",
            ">=1",
            "<2",
            "1.0 - 2.0",
            "1 || 2",
            "a/b",
            "..",
        ] {
            assert_eq!(
                invalid_path(doc(serde_json::json!({"version": bad}))),
                "version",
                "{bad}"
            );
        }
        assert_eq!(
            invalid_path(doc(serde_json::json!({"version": "1".repeat(256)}))),
            "version"
        );
        for good in [
            "1.0.0",
            "2025.01.02",
            "1.0.0-rc.1+build.5",
            "v1",
            "0.0.1-linux.x86",
        ] {
            assert!(
                check(doc(serde_json::json!({"version": good}))).is_ok(),
                "{good}"
            );
        }
    }

    #[test]
    fn url_rules() {
        for bad in [
            "javascript:alert(1)",
            "data:text/html,x",
            "file:///etc/passwd",
            "/relative",
            "ftp://x.test/",
        ] {
            assert_eq!(
                invalid_path(doc(serde_json::json!({"websiteUrl": bad}))),
                "websiteUrl"
            );
            assert_eq!(
                invalid_path(doc(
                    serde_json::json!({"repository": {"url": bad, "source": "github"}})
                )),
                "repository.url"
            );
            assert_eq!(
                invalid_path(doc(serde_json::json!({"icons": [{"src": bad}]}))),
                "icons[0].src"
            );
        }
        assert!(check(doc(serde_json::json!({"websiteUrl": "https://acme.test", "icons": [{"src": "https://acme.test/i.png", "mimeType": "image/png", "sizes": ["48x48", "any"], "theme": "dark"}]}))).is_ok());
        assert_eq!(
            invalid_path(doc(
                serde_json::json!({"icons": [{"src": "https://a.test/i", "mimeType": "text/html"}]})
            )),
            "icons[0].mimeType"
        );
        assert_eq!(
            invalid_path(doc(
                serde_json::json!({"icons": [{"src": "https://a.test/i", "sizes": ["big"]}]})
            )),
            "icons[0].sizes"
        );
        assert_eq!(
            invalid_path(doc(
                serde_json::json!({"icons": [{"src": "https://a.test/i", "theme": "blue"}]})
            )),
            "icons[0].theme"
        );
        assert_eq!(
            invalid_path(doc(
                serde_json::json!({"repository": {"url": "https://g.test/x", "source": "github", "subfolder": "../x"}})
            )),
            "repository.subfolder"
        );
    }

    #[test]
    fn package_rules() {
        let with = |p: serde_json::Value| doc(serde_json::json!({"remotes": [], "packages": [p]}));
        assert_eq!(
            invalid_path(with(npm(serde_json::json!({"registryType": "maven"})))),
            "packages[0].registryType"
        );
        assert_eq!(
            invalid_path(with(npm(serde_json::json!({"identifier": " "})))),
            "packages[0].identifier"
        );
        assert_eq!(
            invalid_path(with(npm(serde_json::json!({"version": "^1"})))),
            "packages[0].version"
        );
        assert_eq!(
            invalid_path(with(npm(
                serde_json::json!({"transport": {"type": "stdio", "url": "https://x.test"}})
            ))),
            "packages[0].transport"
        );
        assert_eq!(
            invalid_path(with(npm(
                serde_json::json!({"transport": {"type": "streamable-http"}})
            ))),
            "packages[0].transport.url"
        );
        assert_eq!(
            invalid_path(with(npm(serde_json::json!({"transport": {"type": "ws"}})))),
            "packages[0].transport.type"
        );
        assert!(check(with(npm(
            serde_json::json!({"transport": {"type": "streamable-http", "url": "{baseUrl}/mcp"}, "environmentVariables": [{"name": "baseUrl", "default": "https://mcp.acme.test"}]})
        )))
        .is_ok());
        assert_eq!(
            invalid_path(with(npm(
                serde_json::json!({"transport": {"type": "sse", "url": "javascript:x"}})
            ))),
            "packages[0].transport.url"
        );
        assert_eq!(
            invalid_path(with(npm(serde_json::json!({"fileSha256": "ABC"})))),
            "packages[0].fileSha256"
        );
        assert_eq!(
            invalid_path(with(npm(
                serde_json::json!({"registryType": "mcpb", "identifier": "https://g.test/x.mcpb"})
            ))),
            "packages[0].fileSha256"
        );
        assert!(check(with(npm(serde_json::json!({"registryType": "mcpb", "identifier": "https://g.test/x.mcpb", "fileSha256": "a".repeat(64)})))).is_ok());
        assert_eq!(
            invalid_path(with(npm(
                serde_json::json!({"registryBaseUrl": "file:///x"})
            ))),
            "packages[0].registryBaseUrl"
        );
        assert_eq!(
            invalid_path(with(npm(
                serde_json::json!({"transport": {"type": "stdio", "variables": {}}})
            ))),
            "packages[0].transport.variables"
        );
    }

    #[test]
    fn argument_and_input_rules() {
        let with = |field: &str, v: serde_json::Value| {
            doc(
                serde_json::json!({"remotes": [], "packages": [npm(serde_json::json!({field: [v]}))]}),
            )
        };
        assert!(check(with(
            "runtimeArguments",
            serde_json::json!({"type": "named", "name": "--port", "value": "8080"})
        ))
        .is_ok());
        assert!(check(with(
            "packageArguments",
            serde_json::json!({"type": "positional", "valueHint": "dir", "isRepeated": true})
        ))
        .is_ok());
        assert_eq!(
            invalid_path(with(
                "runtimeArguments",
                serde_json::json!({"type": "named"})
            )),
            "packages[0].runtimeArguments[0].name"
        );
        assert_eq!(
            invalid_path(with(
                "runtimeArguments",
                serde_json::json!({"type": "positional"})
            )),
            "packages[0].runtimeArguments[0]"
        );
        assert_eq!(
            invalid_path(with(
                "runtimeArguments",
                serde_json::json!({"type": "flag"})
            )),
            "packages[0].runtimeArguments[0].type"
        );
        for bad in ["--a b", "<x>", "$HOME", "a>b"] {
            assert_eq!(
                invalid_path(with(
                    "runtimeArguments",
                    serde_json::json!({"type": "named", "name": bad})
                )),
                "packages[0].runtimeArguments[0].name"
            );
        }
        assert_eq!(
            invalid_path(with(
                "environmentVariables",
                serde_json::json!({"description": "x"})
            )),
            "packages[0].environmentVariables[0].name"
        );
        assert_eq!(
            invalid_path(with(
                "environmentVariables",
                serde_json::json!({"name": "K", "type": "named"})
            )),
            "packages[0].environmentVariables[0]"
        );
        assert_eq!(
            invalid_path(with(
                "environmentVariables",
                serde_json::json!({"name": "K", "format": "url"})
            )),
            "packages[0].environmentVariables[0].format"
        );
        assert_eq!(
            invalid_path(with(
                "environmentVariables",
                serde_json::json!({"name": "K", "description": "a\u{202E}b"})
            )),
            "packages[0].environmentVariables[0].description"
        );
        assert_eq!(
            invalid_path(with(
                "runtimeArguments",
                serde_json::json!({"type": "named", "name": "-v", "value": "{x}", "variables": {"x": {"name": "no"}}})
            )),
            "packages[0].runtimeArguments[0].variables.x"
        );
        assert_eq!(
            invalid_path(with(
                "runtimeArguments",
                serde_json::json!({"type": "named", "name": "-v", "variables": {"bad-key": {}}})
            )),
            "packages[0].runtimeArguments[0].variables.bad-key"
        );
    }

    /// The refusal `check` gives one remote (`url`, `variables`), as
    /// `(path, detail)`; `None` when it publishes.
    fn remote_refusal(url: &str, variables: serde_json::Value) -> Option<(String, String)> {
        let mut remote = serde_json::json!({"type": "sse", "url": url});
        if !variables.is_null() {
            remote["variables"] = variables;
        }
        match check(doc(serde_json::json!({"remotes": [remote]}))) {
            Ok(_) => None,
            Err(e @ McpError::Invalid { .. }) => {
                assert_eq!(e.code(), "mcp_invalid_server_json");
                let McpError::Invalid { path, msg } = e else {
                    unreachable!()
                };
                Some((path, msg))
            }
            Err(other) => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn templated_remote_urls_expand_to_http_only() {
        // #5529: the issue's rig, a `choices`-only variant, and every
        // active scheme, all refused with the literal path's code and path.
        for (vars, var, value) in [
            (
                serde_json::json!({"base": {"default": "javascript:alert(1)//"}}),
                "base",
                "javascript:alert(1)//",
            ),
            (
                serde_json::json!({"base": {"choices": ["https://ok.example", "javascript:alert(1)//"]}}),
                "base",
                "javascript:alert(1)//",
            ),
            (
                serde_json::json!({"base": {"default": "data:text/html,<b>x</b>"}}),
                "base",
                "data:text/html,<b>x</b>",
            ),
            (
                serde_json::json!({"base": {"default": "https://ok.example", "choices": ["vbscript:msgbox(1)"]}}),
                "base",
                "vbscript:msgbox(1)",
            ),
        ] {
            let (path, msg) = remote_refusal("{base}/sse", vars.clone())
                .unwrap_or_else(|| panic!("{vars} published"));
            assert_eq!(path, "remotes[0].url");
            assert!(
                msg.contains(&format!("variable `{var}` = \"{value}\""))
                    && msg.contains(&format!("\"{value}/sse\"")),
                "{msg}"
            );
        }
        // The literal form, for the code and path the expansion reuses.
        assert_eq!(
            remote_refusal("javascript:alert(1)//sse", serde_json::Value::Null)
                .unwrap()
                .0,
            "remotes[0].url"
        );
        // A declared variable in the scheme position with no value: the
        // client's input picks the scheme.
        let (path, msg) = remote_refusal(
            "{base}/sse",
            serde_json::json!({"base": {"isRequired": true}}),
        )
        .unwrap();
        assert_eq!(path, "remotes[0].url");
        assert!(
            msg.contains("variable `base` picks the URL scheme"),
            "{msg}"
        );
        // A variable that is only the scheme segment, with a non-http
        // choice, beside a value-less path variable.
        assert!(remote_refusal(
            "{scheme}://x.example/{path}",
            serde_json::json!({"scheme": {"choices": ["https", "javascript"]}, "path": {}})
        )
        .is_some());
        // An undeclared variable in the scheme position is refused too; one
        // anywhere else stands for client input and publishes.
        let (_, msg) = remote_refusal("{base}/sse", serde_json::Value::Null).unwrap();
        assert!(
            msg.contains("variable `base` picks the URL scheme"),
            "{msg}"
        );
        // A later variable's value that reaches the scheme is named.
        let (_, msg) = remote_refusal(
            "{a}{b}",
            serde_json::json!({"b": {"default": "javascript:x"}}),
        )
        .unwrap();
        assert!(msg.contains(r#"variable `b` = "javascript:x""#), "{msg}");
        // An undeclared scheme variable whose neighbour supplies an http(s)
        // scheme still picks it.
        let (_, msg) = remote_refusal(
            "{a}{b}",
            serde_json::json!({"b": {"default": "https://x.example"}}),
        )
        .unwrap();
        assert!(msg.contains("variable `a` picks the URL scheme"), "{msg}");
        // A placeholder is pre-filled by clients, so it is a value too.
        assert!(remote_refusal(
            "{base}/sse",
            serde_json::json!({"base": {"placeholder": "javascript:alert(1)//"}})
        )
        .is_some());
        assert!(remote_refusal("https://x.example/{tenant}", serde_json::Value::Null).is_none());
        // More than 256 expansions: refused rather than enumerated.
        let choices = |n: usize| serde_json::json!({"choices": (0..n).map(|i| format!("v{i}")).collect::<Vec<_>>()});
        let (path, msg) = remote_refusal(
            "https://x.example/{a}/{b}/{c}",
            serde_json::json!({"a": choices(10), "b": choices(10), "c": choices(3)}),
        )
        .unwrap();
        assert_eq!(path, "remotes[0].url");
        assert!(
            msg.contains("expand to 300 URLs, more than the 256"),
            "{msg}"
        );
        assert!(remote_refusal(
            "https://x.example/{a}/{b}",
            serde_json::json!({"a": choices(16), "b": choices(16)})
        )
        .is_none());
        // Benign controls.
        assert!(remote_refusal(
            "https://{host}/sse",
            serde_json::json!({"host": {"default": "mcp.acme.test"}})
        )
        .is_none());
        assert!(remote_refusal(
            "{base}/sse",
            serde_json::json!({"base": {"default": "https://x.example", "choices": ["https://x.example", "http://y.example:8080"]}})
        )
        .is_none());
        assert!(remote_refusal(
            "https://x.example/{tenant}/sse",
            serde_json::json!({"tenant": {"isRequired": true}})
        )
        .is_none());
        assert!(remote_refusal(
            "https://{host}:{port}/{tenant}",
            serde_json::json!({"host": {}, "port": {"default": "8443"}, "tenant": {}})
        )
        .is_none());
        // A host default cannot leave the template's scheme; it only names
        // the authority, as a literal URL could.
        assert!(remote_refusal(
            "https://{host}/sse",
            serde_json::json!({"host": {"default": "bad host"}})
        )
        .is_some());
        // A long offending value is clipped in the detail.
        let long = format!("javascript:{}", "a".repeat(200));
        let (_, msg) =
            remote_refusal("{base}", serde_json::json!({"base": {"default": long}})).unwrap();
        assert!(msg.contains("...\"") && msg.len() < 400, "{msg}");
        // Quotes and backticks in a value cannot unbalance the detail.
        let (_, msg) = remote_refusal(
            "{base}/sse",
            serde_json::json!({"base": {"default": "javascript:`x`\"y\""}}),
        )
        .unwrap();
        assert!(msg.contains(r#"= "javascript:`x`\"y\"""#), "{msg}");
        // An unclosed brace is literal text, as before.
        assert_eq!(
            url_template_issue("https://x.example/{a", |_| None, UrlExpansion::All),
            None
        );
    }

    #[test]
    fn templated_package_transport_urls_expand_to_http_only() {
        let with = |p: serde_json::Value| doc(serde_json::json!({"remotes": [], "packages": [p]}));
        let transport = |url: &str| serde_json::json!({"type": "streamable-http", "url": url});
        for extra in [
            serde_json::json!({"transport": transport("{baseUrl}/mcp"), "environmentVariables": [{"name": "baseUrl", "default": "javascript:alert(1)//"}]}),
            serde_json::json!({"transport": transport("{baseUrl}/mcp"), "packageArguments": [{"type": "positional", "valueHint": "baseUrl", "choices": ["data:text/html,x"]}]}),
            serde_json::json!({"transport": transport("{baseUrl}/mcp"), "environmentVariables": [{"name": "baseUrl"}]}),
            serde_json::json!({"transport": transport("{baseUrl}/mcp")}),
            // Every input matching the variable counts, not the first.
            serde_json::json!({"transport": transport("{baseUrl}/mcp"),
                "environmentVariables": [{"name": "baseUrl", "default": "https://ok.example"}],
                "packageArguments": [{"type": "positional", "valueHint": "baseUrl", "default": "javascript:alert(1)//"}]}),
            serde_json::json!({"transport": transport("{baseUrl}/mcp"),
                "environmentVariables": [{"name": "baseUrl", "default": "https://ok.example"}, {"name": "baseUrl", "default": "javascript:alert(1)//"}]}),
            serde_json::json!({"transport": transport("{baseUrl}/mcp"),
                "runtimeArguments": [{"type": "positional", "valueHint": "baseUrl", "default": "https://ok.example"}],
                "packageArguments": [{"type": "named", "name": "baseUrl", "default": "javascript:alert(1)//"}]}),
        ] {
            assert_eq!(invalid_path(with(npm(extra))), "packages[0].transport.url");
        }
        for extra in [
            serde_json::json!({"transport": transport("{baseUrl}/mcp"), "environmentVariables": [{"name": "baseUrl", "default": "http://localhost:3000"}]}),
            serde_json::json!({"transport": transport("http://localhost:{port}/mcp"), "runtimeArguments": [{"type": "named", "name": "--port", "valueHint": "port", "default": "3000"}]}),
            serde_json::json!({"transport": transport("http://localhost:{port}/mcp"), "environmentVariables": [{"name": "port"}]}),
        ] {
            assert!(check(with(npm(extra.clone()))).is_ok(), "{extra}");
        }
    }

    #[test]
    fn remote_rules_and_caps() {
        assert_eq!(
            invalid_path(doc(serde_json::json!({"remotes": [{"type": "stdio"}]}))),
            "remotes[0].type"
        );
        assert_eq!(
            invalid_path(doc(serde_json::json!({"remotes": [{"type": "sse"}]}))),
            "remotes[0].url"
        );
        assert!(check(doc(serde_json::json!({"remotes": [{"type": "sse", "url": "https://x.test/{tenant}", "headers": [{"name": "Authorization", "isSecret": true}], "variables": {"tenant": {"isRequired": true}}}]}))).is_ok());
        assert_eq!(invalid_path(doc(serde_json::json!({"remotes": []}))), "");
        let many: Vec<_> = (0..9)
            .map(|_| serde_json::json!({"type": "sse", "url": "https://x.test"}))
            .collect();
        assert_eq!(
            invalid_path(doc(serde_json::json!({"remotes": many}))),
            "remotes"
        );
        let pkgs: Vec<_> = (0..17).map(|_| npm(serde_json::json!({}))).collect();
        assert_eq!(
            invalid_path(doc(serde_json::json!({"packages": pkgs}))),
            "packages"
        );
        let envs: Vec<_> = (0..65)
            .map(|i| serde_json::json!({"name": format!("K{i}")}))
            .collect();
        assert_eq!(
            invalid_path(doc(
                serde_json::json!({"packages": [npm(serde_json::json!({"environmentVariables": envs}))]})
            )),
            "packages[0].environmentVariables"
        );
    }

    #[test]
    fn unknown_fields_size_and_depth() {
        assert_eq!(
            invalid_path(doc(serde_json::json!({"status": "active"}))),
            ""
        );
        assert_eq!(
            invalid_path(doc(
                serde_json::json!({"packages": [npm(serde_json::json!({"registry_name": "npm"}))]})
            )),
            ""
        );
        let big = vec![b' '; MCP_PUBLISH_MAX_BYTES + 1];
        assert_eq!(parse_server_json(&big), Err(McpError::TooLarge));
        let deep = format!("{}{}", "[".repeat(2000), "]".repeat(2000));
        assert!(matches!(
            parse_server_json(deep.as_bytes()),
            Err(McpError::Invalid { .. })
        ));
        assert!(!json_depth_exceeds(
            br#"{"a":"[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["}"#,
            3
        ));
        assert!(!json_depth_exceeds(br#"{"a":"\"[[[["}"#, 1));
        assert!(json_depth_exceeds(b"[[[", 2));
    }

    #[test]
    fn oci_identifier_table() {
        let ok = |s: &str| parse_oci_identifier(s).unwrap();
        let r = ok("ghcr.io/acme/mcp:1.2");
        assert_eq!(
            (r.host.as_str(), r.path.as_str(), r.tag.as_deref(), r.digest),
            ("ghcr.io", "acme/mcp", Some("1.2"), None)
        );
        let d = format!("sha256:{}", "a".repeat(64));
        let r = ok(&format!("ghcr.io/acme/mcp:1.2@{d}"));
        assert_eq!(
            (r.tag.as_deref(), r.digest.as_deref()),
            (Some("1.2"), Some(d.as_str()))
        );
        let r = ok(&format!("acme/mcp@{d}"));
        assert_eq!((r.host.as_str(), r.tag), ("docker.io", None));
        assert_eq!(ok("nginx:1.25").path, "library/nginx");
        assert_eq!(ok("localhost:5000/x:1").host, "localhost:5000");
        assert_eq!(ok("localhost/x:1").host, "localhost");
        assert!(ok(&format!("ghcr.io/a/b@sha512:{}", "b".repeat(128)))
            .digest
            .is_some());
        assert!(ok(&format!("ghcr.io/a/b:{}", "t".repeat(128)))
            .tag
            .is_some());
        assert!(matches!(
            parse_oci_identifier(&format!("ghcr.io/a/b:{}", "t".repeat(129))),
            Err(OciRefError::Invalid(_))
        ));
        assert_eq!(
            parse_oci_identifier("ghcr.io/acme/mcp:latest"),
            Err(OciRefError::Floating)
        );
        assert_eq!(
            parse_oci_identifier("ghcr.io/acme/mcp"),
            Err(OciRefError::Floating)
        );
        for bad in [
            "",
            "ghcr.io/Acme/mcp:1",
            "ghcr.io/a/b:-x",
            "ghcr.io/a/b@sha256:abc",
            "ghcr.io/a b:1",
            &format!("ghcr.io/a/b@sha256:{}", "A".repeat(64)),
        ] {
            assert!(
                matches!(parse_oci_identifier(bad), Err(OciRefError::Invalid(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn oci_package_rules() {
        let with = |p: serde_json::Value| doc(serde_json::json!({"remotes": [], "packages": [p]}));
        let oci = |id: &str, extra: serde_json::Value| {
            let mut p = serde_json::json!({"registryType": "oci", "identifier": id, "transport": {"type": "stdio"}});
            if let (Some(b), serde_json::Value::Object(e)) = (p.as_object_mut(), extra) {
                b.extend(e);
            }
            p
        };
        assert!(check(with(oci("ghcr.io/acme/mcp:1.2", serde_json::json!({})))).is_ok());
        for legacy in [
            serde_json::json!({"version": "1.2"}),
            serde_json::json!({"registryBaseUrl": "https://ghcr.io"}),
            serde_json::json!({"fileSha256": "a".repeat(64)}),
        ] {
            assert_eq!(
                check(with(oci("ghcr.io/acme/mcp:1.2", legacy))),
                Err(McpError::OciLegacyFields { index: 0 })
            );
        }
        assert_eq!(
            check(with(oci("ghcr.io/acme/mcp:latest", serde_json::json!({})))),
            Err(McpError::OciFloatingTag { index: 0 })
        );
        assert_eq!(
            check(with(oci("ghcr.io/acme/mcp", serde_json::json!({})))),
            Err(McpError::OciFloatingTag { index: 0 })
        );
        assert_eq!(
            invalid_path(with(oci("ghcr.io/ACME/mcp:1", serde_json::json!({})))),
            "packages[0].identifier"
        );
    }

    #[test]
    fn publisher_meta_is_reduced_and_capped() {
        let mut s = check(doc(serde_json::json!({"_meta": {
            PUBLISHER_META_KEY: {"tool": "cli"},
            OFFICIAL_META_KEY: {"isLatest": true},
            "com.example/x": 1,
        }})))
        .unwrap();
        reduce_publisher_meta(&mut s).unwrap();
        let meta = s.meta.as_ref().unwrap();
        assert_eq!(meta.len(), 1);
        assert_eq!(meta[PUBLISHER_META_KEY]["tool"], "cli");
        let mut s = check(doc(serde_json::json!({"_meta": {"com.example/x": 1}}))).unwrap();
        reduce_publisher_meta(&mut s).unwrap();
        assert!(s.meta.is_none());
        let mut s = check(doc(
            serde_json::json!({"_meta": {PUBLISHER_META_KEY: {"x": "y".repeat(4100)}}}),
        ))
        .unwrap();
        assert!(matches!(
            reduce_publisher_meta(&mut s),
            Err(McpError::Invalid { .. })
        ));
        let mut s = check(doc(
            serde_json::json!({"_meta": {PUBLISHER_META_KEY: "str"}}),
        ))
        .unwrap();
        assert!(reduce_publisher_meta(&mut s).is_err());
        let mut s = check(doc(serde_json::json!({}))).unwrap();
        assert!(reduce_publisher_meta(&mut s).is_ok());
        // Publisher-provided strings (keys and values, nested) get the same
        // character rules as the rest of the document.
        for provided in [
            serde_json::json!({"note": "a\u{202E}b"}),
            serde_json::json!({"list": ["ok", "a\u{2028}b"]}),
            serde_json::json!({"k\u{200B}": 1}),
            serde_json::json!({"deep": {"x": "\u{E0041}"}}),
        ] {
            let mut s = check(doc(
                serde_json::json!({"_meta": {PUBLISHER_META_KEY: provided}}),
            ))
            .unwrap();
            assert!(
                matches!(reduce_publisher_meta(&mut s), Err(McpError::Invalid { .. })),
                "{provided}"
            );
        }
    }

    #[test]
    fn declared_capabilities_meta_is_kept() {
        let caps = serde_json::json!({"tools": [{"name": "a"}]});
        let mut s = check(doc(serde_json::json!({"_meta": {
            AK_CAPABILITIES_META_KEY: caps, "com.example/x": 1,
        }})))
        .unwrap();
        reduce_publisher_meta(&mut s).unwrap();
        let meta = s.meta.as_ref().unwrap();
        assert_eq!(meta.len(), 1);
        assert_eq!(meta[AK_CAPABILITIES_META_KEY], caps);
        let mut s = check(doc(serde_json::json!({"_meta": {
            AK_CAPABILITIES_META_KEY: caps, PUBLISHER_META_KEY: {"tool": "cli"},
        }})))
        .unwrap();
        reduce_publisher_meta(&mut s).unwrap();
        assert_eq!(s.meta.as_ref().unwrap().len(), 2);
        for bad in [
            serde_json::json!([]),
            serde_json::json!({"tools": [{"name": "a", "description": "x\u{200B}"}]}),
        ] {
            let mut s = check(doc(
                serde_json::json!({"_meta": {AK_CAPABILITIES_META_KEY: bad}}),
            ))
            .unwrap();
            assert!(
                matches!(reduce_publisher_meta(&mut s), Err(McpError::Invalid { .. })),
                "{bad}"
            );
        }
    }

    #[test]
    fn canonical_bytes_are_key_sorted_and_stable() {
        let a = check(serde_json::from_str(r#"{"version":"1.0.0","name":"com.acme/w","description":"d","remotes":[{"url":"https://x.test","type":"sse"}]}"#).unwrap()).unwrap();
        let b = check(serde_json::from_str(r#"{"remotes":[{"type":"sse","url":"https://x.test"}],"description":"d","name":"com.acme/w","version":"1.0.0"}"#).unwrap()).unwrap();
        assert_eq!(canonical_bytes(&a), canonical_bytes(&b));
        let text = String::from_utf8(canonical_bytes(&a)).unwrap();
        assert!(text.starts_with(r#"{"description":"d","name""#), "{text}");
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn risk_summary_counts_transports_types_and_secrets() {
        let server = serde_json::json!({
            "packages": [
                {"registryType": "npm", "transport": {"type": "stdio"},
                 "environmentVariables": [
                    {"name": "API_KEY", "isSecret": true},
                    {"name": "REGION", "isSecret": false},
                    {"name": "DEBUG"}]},
                {"registryType": "oci", "transport": {"type": "streamable-http",
                 "headers": [{"name": "Authorization", "isSecret": true}]}},
                {"registryType": "npm", "transport": {"type": "stdio"}},
            ],
            "remotes": [
                {"type": "sse", "url": "https://x.test/sse",
                 "headers": [{"name": "X-Token", "isSecret": true}]},
            ],
        });
        assert_eq!(
            server_risk_summary(&server),
            serde_json::json!({
                "transports": ["sse", "stdio", "streamable-http"],
                "registryTypes": ["npm", "oci"],
                "secretsCount": 3,
                "packagesCount": 3,
                "remotesCount": 1,
            })
        );
        assert_eq!(
            server_risk_summary(&serde_json::Value::Null),
            serde_json::json!({"transports": [], "registryTypes": [], "secretsCount": 0,
                               "packagesCount": 0, "remotesCount": 0})
        );
    }

    #[test]
    fn namespaces() {
        assert_eq!(namespace_of("com.acme/x"), "com.acme");
        let allow = vec!["com.acme".to_string()];
        assert!(namespace_allowed("com.acme/x", &allow));
        assert!(namespace_allowed("com.acme.sub/x", &allow));
        assert!(!namespace_allowed("com.acmecorp/x", &allow));
        assert!(!namespace_allowed("org.other/x", &allow));
        assert!(namespace_allowed("anything/x", &[]));
        assert!(!namespace_allowed("com.acme/x", &[" ".to_string()]));
        assert!(is_reserved_namespace("io.modelcontextprotocol/x"));
        assert!(is_reserved_namespace("io.modelcontextprotocol.anonymous/x"));
        assert!(is_reserved_namespace("IO.ModelContextProtocol/x"));
        assert!(!is_reserved_namespace("io.github.acme/x"));
    }

    #[test]
    fn paths_and_cursors() {
        assert_eq!(
            storage_path("com.acme/w", "1.0"),
            "servers/com.acme/w/1.0/server.json"
        );
        let on_filesystem = KeyScope::of("filesystem", Uuid::new_v4());
        assert_eq!(
            storage_key(on_filesystem, "com.acme/w", "1.0", "ab"),
            "mcp/com.acme/w/1.0/ab.json"
        );
        assert_eq!(
            bundle_storage_key(on_filesystem, "com.acme/w", "1.0", "ab", "w.mcpb"),
            "mcp/com.acme/w/1.0/bundles/ab/w.mcpb"
        );
        assert_eq!(
            parse_storage_path("servers/com.acme/w/1.0/server.json"),
            Some(("com.acme/w".into(), "1.0".into()))
        );
        assert_eq!(parse_storage_path("servers/w/1.0/server.json"), None);
        assert_eq!(parse_storage_path("other/a/b/c/server.json"), None);
    }

    /// #5660: a shared cloud namespace gets the repo-scoped key for a
    /// server version and a bundle alike, and the `STORAGE_KEY_SCHEME=flat`
    /// opt-out keeps the legacy shared key.
    #[test]
    fn storage_keys_are_repo_scoped_on_cloud_5660() {
        use crate::storage::StorageKeyScheme;
        let repository_id = Uuid::new_v4();
        for backend in ["s3", "gcs", "azure"] {
            let scoped = KeyScope {
                scheme: StorageKeyScheme::RepoScoped,
                storage_backend: backend,
                repository_id,
            };
            let flat = KeyScope {
                scheme: StorageKeyScheme::Flat,
                ..scoped
            };
            assert_eq!(
                storage_key(scoped, "com.acme/w", "1.0", "ab"),
                format!("mcp/{repository_id}/com.acme/w/1.0/ab.json"),
                "{backend}"
            );
            assert_eq!(
                bundle_storage_key(scoped, "com.acme/w", "1.0", "ab", "w.mcpb"),
                format!("mcp/{repository_id}/com.acme/w/1.0/bundles/ab/w.mcpb"),
                "{backend}"
            );
            assert_eq!(
                storage_key(flat, "com.acme/w", "1.0", "ab"),
                "mcp/com.acme/w/1.0/ab.json",
                "{backend}"
            );
            assert_eq!(
                bundle_storage_key(flat, "com.acme/w", "1.0", "ab", "w.mcpb"),
                "mcp/com.acme/w/1.0/bundles/ab/w.mcpb",
                "{backend}"
            );
        }
    }

    /// Finding 4: a listing cursor is opaque and sealed. It round-trips for
    /// the repository and listing that issued it, names nothing a client can
    /// read, and a made-up, altered, replayed (other repository, other
    /// listing) or foreign-secret cursor is the `400 invalid cursor`.
    #[test]
    fn cursors_are_sealed_and_bound() {
        use base64::Engine as _;
        let seal = CursorSeal::from_secret("a-test-secret-of-some-length-0123456789");
        let (repo, other) = (Uuid::new_v4(), Uuid::new_v4());
        let c = seal.encode_position(repo, cursor_kind::SERVERS, "com.acme/w", "1.0.0");
        assert_eq!(
            seal.decode_position(repo, cursor_kind::SERVERS, &c)
                .unwrap(),
            ("com.acme/w".into(), "1.0.0".into())
        );
        assert!(c
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&c)
            .unwrap();
        assert!(
            !String::from_utf8_lossy(&raw).contains("com.acme"),
            "the position is not readable"
        );
        // Two cursors for one position differ (random nonce).
        assert_ne!(
            c,
            seal.encode_position(repo, cursor_kind::SERVERS, "com.acme/w", "1.0.0")
        );
        let mut tampered = raw.clone();
        *tampered.last_mut().unwrap() ^= 1;
        let tampered = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(tampered);
        let plain = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("com.acme/w:1.0.0");
        let foreign = CursorSeal::from_secret("another-secret-of-some-length-0123456789")
            .encode_position(repo, cursor_kind::SERVERS, "com.acme/w", "1.0.0");
        let long = "A".repeat(5000);
        for bad in [
            "!!!",
            "bm9jb2xvbg",
            "",
            "Ondo",
            plain.as_str(),
            tampered.as_str(),
            foreign.as_str(),
            long.as_str(),
        ] {
            assert_eq!(
                seal.decode_position(repo, cursor_kind::SERVERS, bad)
                    .unwrap_err()
                    .code(),
                "mcp_invalid_query",
                "{bad}"
            );
        }
        assert!(seal
            .decode_position(other, cursor_kind::SERVERS, &c)
            .is_err());
        assert!(seal.decode_position(repo, cursor_kind::HOLDS, &c).is_err());
        let virt = seal.seal(repo, &[cursor_kind::VIRTUAL, "m1", "", ""]);
        assert_eq!(seal.open(repo, &virt).unwrap(), vec!["m", "m1", "", ""]);
        assert!(seal
            .decode_position(repo, cursor_kind::SERVERS, &virt)
            .is_err());
    }

    #[test]
    fn latest_ordering() {
        use Ordering::*;
        assert_eq!(compare_versions_for_latest("1.10.0", "1.2.0"), Greater);
        assert_eq!(compare_versions_for_latest("1.0.0", "1.0.0-rc.1"), Greater);
        assert_eq!(
            compare_versions_for_latest("1.0.0-rc.2", "1.0.0-rc.10"),
            Less
        );
        assert_eq!(
            compare_versions_for_latest("1.0.0-alpha", "1.0.0-alpha.1"),
            Less
        );
        assert_eq!(compare_versions_for_latest("1.0.0+b1", "1.0.0+b2"), Equal);
        // Upstream CompareVersions: a SemVer version always outranks a
        // non-SemVer one, whichever way round.
        assert_eq!(compare_versions_for_latest("2025-weird", "9.9.9"), Less);
        assert_eq!(compare_versions_for_latest("0.0.1", "2025-weird"), Greater);
        assert_eq!(compare_versions_for_latest("1.0", "1.0.0"), Less);
        assert_eq!(compare_versions_for_latest("x", "y"), Equal);
        // `v` prefix accepted, leading zeros are not SemVer.
        assert_eq!(compare_versions_for_latest("v1.2.0", "1.10.0"), Less);
        assert_eq!(compare_versions_for_latest("v2.0.0", "1.10.0"), Greater);
        assert_eq!(compare_versions_for_latest("01.0.0", "0.0.1"), Less);
        let t0 = Some(Utc::now());
        assert_eq!(
            pick_latest(&[
                ("1.0.0", t0),
                ("nightly", t0.map(|t| t + chrono::Duration::days(1)))
            ]),
            Some(0),
            "a newer non-SemVer version does not displace a SemVer one"
        );
        let t1 = Some(Utc::now());
        let t2 = t1.map(|t| t + chrono::Duration::seconds(1));
        assert_eq!(
            pick_latest(&[("1.0.0", t1), ("1.2.0", t1), ("1.10.0", t1)]),
            Some(2)
        );
        assert_eq!(pick_latest(&[("abc", t2), ("abd", t1)]), Some(0));
        assert_eq!(pick_latest(&[]), None);
    }

    fn pin(index: usize, ty: &str, tag: Option<&str>) -> PackagePin {
        PackagePin {
            index,
            registry_type: ty.into(),
            submitted: SubmittedRef {
                identifier: if ty == "oci" {
                    "ghcr.io/acme/mcp:1.2".into()
                } else {
                    "@acme/w".into()
                },
                version: (ty != "oci").then(|| "1.0.0".into()),
            },
            resolved: ResolvedPin {
                repository: format!("{ty}-local"),
                repository_id: Uuid::nil(),
                artifact_ids: vec![],
                artifact_sha256s: Vec::new(),
                sha256: None,
                name: Some("acme/mcp".into()),
                tag: tag.map(Into::into),
                digest: Some(format!("sha256:{}", "c".repeat(64))),
                media_type: Some("application/vnd.oci.image.index.v1+json".into()),
                children: vec![],
                gate_digest: None,
                resolved_at: Utc::now(),
                warnings: vec![],
                cache_path: None,
                download_path: None,
            },
            drift: None,
        }
    }

    #[test]
    fn rewrite_for_serve() {
        let server = serde_json::json!({"name": "com.acme/w", "packages": [
            {"registryType": "npm", "identifier": "@acme/w", "version": "1.0.0", "registryBaseUrl": "https://registry.npmjs.org"},
            {"registryType": "oci", "identifier": "ghcr.io/acme/mcp:1.2"},
            {"registryType": "nuget", "identifier": "Acme.W", "version": "1.0.0"},
            {"registryType": "oci", "identifier": "ghcr.io/acme/mcp@sha256:x"},
        ]});
        let pins = vec![
            pin(0, "npm", None),
            pin(1, "oci", Some("1.2")),
            pin(2, "nuget", None),
            pin(3, "oci", None),
            pin(9, "npm", None),
        ];
        let mut pins = pins;
        pins[0].resolved.warnings = vec!["foreign_coordinates_replaced".into()];
        let out = rewrite_packages_for_serve(&server, &pins, "https://ak.test:8443/");
        assert_eq!(
            out["packages"][0]["registryBaseUrl"],
            "https://ak.test:8443/npm/npm-local"
        );
        // #5452: the replaced coordinates and the pin's warnings are served.
        let npm = &out["packages"][0]["_meta"][AK_RESOLVED_META_KEY];
        assert_eq!(
            npm["submittedRegistryBaseUrl"],
            "https://registry.npmjs.org"
        );
        assert_eq!(
            npm["warnings"],
            serde_json::json!(["foreign_coordinates_replaced"])
        );
        assert_eq!(npm["backingRepository"], "npm-local");
        let nuget = &out["packages"][2]["_meta"][AK_RESOLVED_META_KEY];
        assert!(nuget.get("submittedRegistryBaseUrl").is_none() && nuget.get("warnings").is_none());
        let hex = "c".repeat(64);
        assert_eq!(
            out["packages"][1]["identifier"],
            format!("ak.test:8443/oci-local/acme/mcp:1.2@sha256:{hex}")
        );
        assert_eq!(
            out["packages"][1]["_meta"][AK_RESOLVED_META_KEY]["submittedIdentifier"],
            "ghcr.io/acme/mcp:1.2"
        );
        assert_eq!(
            out["packages"][2]["registryBaseUrl"],
            "https://ak.test:8443/nuget/nuget-local/v3/index.json"
        );
        assert_eq!(
            out["packages"][3]["identifier"],
            format!("ak.test:8443/oci-local/acme/mcp@sha256:{hex}")
        );
        assert_eq!(host_of("not a url"), "localhost");
        assert_eq!(pins[0].label(), "npm:@acme/w@1.0.0");
        assert_eq!(pins[1].label(), "oci:ghcr.io/acme/mcp:1.2");
    }

    #[test]
    fn stored_version_round_trip() {
        let s = check(doc(
            serde_json::json!({"packages": [npm(serde_json::json!({}))]}),
        ))
        .unwrap();
        let reg = RegistryState::new_active(Utc::now());
        let d = metadata_doc(&s, &reg, PackagePolicy::OwnRepos, &[pin(0, "npm", None)]);
        assert_eq!(d["index"]["namespace"], "com.acme");
        assert_eq!(d["index"]["packageTypes"], serde_json::json!(["npm"]));
        let v = StoredVersion::from_metadata(&d).unwrap();
        assert_eq!(v.registry, reg);
        assert_eq!(v.unpinned_package(), None);
        let d = metadata_doc(&s, &reg, PackagePolicy::Open, &[]);
        let v = StoredVersion::from_metadata(&d).unwrap();
        assert_eq!(v.policy, PackagePolicy::Open);
        assert_eq!(
            v.unpinned_package().as_deref(),
            Some("npm:@acme/weather@1.0.0")
        );
        assert!(StoredVersion::from_metadata(&serde_json::json!({"server": 1})).is_none());
        let e = envelope(
            serde_json::json!({}),
            &reg,
            serde_json::json!({"repository": "r"}),
        );
        assert_eq!(e["_meta"][OFFICIAL_META_KEY]["status"], "active");
        assert!(e["_meta"][OFFICIAL_META_KEY].get("statusMessage").is_none());
        let l = list_envelope(vec![e], Some("c".into()));
        assert_eq!(
            l["metadata"],
            serde_json::json!({"count": 1, "nextCursor": "c"})
        );
        assert_eq!(
            list_envelope(vec![], None)["metadata"],
            serde_json::json!({"count": 0})
        );
    }

    #[test]
    fn status_changes() {
        use ServerStatus::*;
        assert!(validate_status_change(Active, Deprecated, Some("use v2")).is_ok());
        assert!(validate_status_change(Active, Active, None).is_err());
        assert!(validate_status_change(Deprecated, Active, Some("x")).is_err());
        assert!(validate_status_change(Active, Deleted, Some(&"m".repeat(501))).is_err());
        assert!(validate_status_change(Active, Deleted, Some("a\u{202E}")).is_err());
        assert_eq!(ServerStatus::parse("deleted"), Some(Deleted));
        assert_eq!(ServerStatus::parse("held"), None);
        assert_eq!(PackagePolicy::parse("\"open\""), Some(PackagePolicy::Open));
        assert_eq!(PackagePolicy::parse("closed"), None);
    }

    #[test]
    fn errors_map_to_status_and_code() {
        let cases: Vec<(McpError, u16, &str)> = vec![
            (McpError::TooLarge, 413, "mcp_too_large"),
            (
                McpError::invalid("name", "bad"),
                400,
                "mcp_invalid_server_json",
            ),
            (
                McpError::OciLegacyFields { index: 0 },
                422,
                "mcp_oci_legacy_fields",
            ),
            (
                McpError::OciFloatingTag { index: 0 },
                422,
                "mcp_oci_floating_tag",
            ),
            (
                McpError::ExternalRegistry {
                    index: 0,
                    detail: "d".into(),
                },
                422,
                "mcp_external_registry",
            ),
            (
                McpError::PackageNotFound {
                    index: 0,
                    detail: "d".into(),
                },
                422,
                "mcp_package_not_found",
            ),
            (
                McpError::PackageVersionUnpinned { index: 0 },
                422,
                "mcp_package_version_unpinned",
            ),
            (
                McpError::OciNotAnImage { index: 0 },
                422,
                "mcp_oci_not_an_image",
            ),
            (
                McpError::ReservedNamespace {
                    namespace: "n".into(),
                },
                403,
                "mcp_namespace_reserved",
            ),
            (
                McpError::NamespaceNotAllowed {
                    namespace: "n".into(),
                },
                403,
                "mcp_namespace_not_allowed",
            ),
            (McpError::VersionExists, 409, "mcp_version_exists"),
            (
                McpError::NameCaseConflict {
                    name: "io.Acme/t".into(),
                    existing: "io.acme/t".into(),
                },
                409,
                "mcp_name_case_conflict",
            ),
            (McpError::SearchTooShort, 422, "mcp_search_too_short"),
            (
                McpError::Misconfigured("x".into()),
                500,
                "mcp_repository_misconfigured",
            ),
            (McpError::Internal("x".into()), 500, "mcp_internal_error"),
        ];
        for (e, status, code) in cases {
            assert_eq!((e.status(), e.code()), (status, code));
            assert!(!e.detail().is_empty());
            assert!(!e.detail().contains("x\""));
            let _: AppError = e.into();
        }
        assert_eq!(McpError::invalid("name", "bad").detail(), "name: bad");
        assert_eq!(McpError::invalid("", "bad").detail(), "bad");
        let b = problem_body(422, "mcp_x", "d", serde_json::json!({"package": "p"}));
        assert_eq!(b["title"], "Unprocessable Content");
        assert_eq!(b["package"], "p");
        assert_eq!(
            problem_body(418, "e", "d", serde_json::json!(null))["title"],
            "Internal Server Error"
        );
    }

    fn state(status: ServerStatus, hold: Option<HoldKind>, include_deleted: bool) -> VersionState {
        VersionState {
            name: "com.acme/w".into(),
            version: "1.0.0".into(),
            status,
            own_hold: hold,
            include_deleted,
            instance: "https://ak.test/mcp/r/v0.1/servers/com.acme%2Fw/versions/1.0.0".into(),
        }
    }

    fn gate(outcome: GateOutcome) -> BackingGate {
        BackingGate {
            package: "npm:@acme/db@2.0.0".into(),
            outcome,
        }
    }

    #[test]
    fn duplicate_keys_are_refused_anywhere() {
        let ok = br#"{"a":{"b":1,"c":[{"d":1},{"d":2}]}}"#;
        assert!(serde_json::from_slice::<NoDuplicateKeys>(ok).is_ok());
        for bad in [
            &br#"{"name":"a/b","name":"c/d"}"#[..],
            br#"{"_meta":{"x":1,"x":2}}"#,
            br#"[{"k":1,"k":1}]"#,
        ] {
            let e = parse_server_json(bad).unwrap_err();
            assert_eq!(e.code(), "mcp_invalid_server_json");
            assert!(e.detail().contains("duplicate"), "{}", e.detail());
        }
    }

    /// Every row of the plan's section 4.4 table, for both audiences.
    #[test]
    fn decide_mcp_serve_table() {
        use GateAudience::*;
        use ServerStatus::*;
        let age = GateOutcome::AgeGate {
            review_id: Some(Uuid::nil()),
            min_age_days: 7,
            requested_age_days: Some(2),
        };
        type Row = (
            VersionState,
            Vec<BackingGate>,
            Option<(u16, &'static str, &'static str)>,
        );
        let rows: Vec<Row> = vec![
            (
                state(Active, Some(HoldKind::Quarantine), false),
                vec![],
                Some((404, "mcp_pending_review", "quarantine")),
            ),
            (
                state(Active, Some(HoldKind::ScanPolicy), false),
                vec![],
                Some((404, "mcp_rejected", "scan_policy")),
            ),
            (
                state(Active, Some(HoldKind::Resolving), false),
                vec![],
                Some((404, "mcp_resolving", "resolving")),
            ),
            (
                state(
                    Active,
                    Some(HoldKind::PendingApproval {
                        review_id: Some(Uuid::from_u128(7)),
                    }),
                    false,
                ),
                vec![],
                Some((404, "mcp_pending_review", "curation")),
            ),
            (
                state(Active, Some(HoldKind::Denied { review_id: None }), false),
                vec![],
                Some((404, "mcp_rejected", "curation")),
            ),
            (
                state(
                    Active,
                    Some(HoldKind::ContentDrift { review_id: None }),
                    false,
                ),
                vec![],
                Some((404, "mcp_pending_review", "content_drift")),
            ),
            (
                state(
                    Active,
                    Some(HoldKind::AgeGate {
                        review_id: None,
                        min_age_days: 3,
                        requested_age_days: Some(1),
                    }),
                    false,
                ),
                vec![],
                Some((404, "mcp_age_gate_blocked", "age_gate")),
            ),
            (
                state(Active, None, false),
                vec![gate(GateOutcome::Quarantine)],
                Some((404, "mcp_backing_artifact_blocked", "backing")),
            ),
            (
                state(Active, None, false),
                vec![gate(GateOutcome::ScanPolicy)],
                Some((404, "mcp_backing_artifact_blocked", "backing")),
            ),
            (
                state(Active, None, false),
                vec![gate(age.clone())],
                Some((404, "mcp_age_gate_blocked", "age_gate")),
            ),
            (
                state(Active, None, false),
                vec![gate(GateOutcome::Unresolvable)],
                Some((404, "mcp_unresolvable", "unresolvable")),
            ),
            (
                state(Active, Some(HoldKind::Quarantine), false),
                vec![gate(GateOutcome::Unavailable)],
                Some((503, "mcp_gate_unavailable", "unavailable")),
            ),
            (
                state(Deprecated, None, false),
                vec![gate(GateOutcome::Allowed)],
                None,
            ),
            (
                state(Deleted, None, false),
                vec![],
                Some((404, "", "deleted")),
            ),
            (state(Deleted, None, true), vec![], None),
            (
                state(Deleted, Some(HoldKind::Quarantine), true),
                vec![],
                Some((404, "mcp_pending_review", "quarantine")),
            ),
            (
                state(Active, None, false),
                vec![gate(GateOutcome::Allowed), gate(GateOutcome::Quarantine)],
                Some((404, "mcp_backing_artifact_blocked", "backing")),
            ),
        ];
        for (i, (vs, gates, expected)) in rows.iter().enumerate() {
            for audience in [ReaderOnly, ReasonGated] {
                let d = decide_mcp_serve(vs, gates, audience);
                match (expected, d) {
                    (None, ServeDecision::Serve) => {}
                    (
                        Some((status, error, class)),
                        ServeDecision::Refuse {
                            status: s,
                            body,
                            hold_class,
                        },
                    ) => {
                        assert_eq!((s, hold_class), (*status, *class), "row {i}");
                        let bytes = serde_json::to_vec(&body).unwrap();
                        let reader_plain =
                            *status == 404 && (audience == ReaderOnly || error.is_empty());
                        if reader_plain {
                            assert_eq!(bytes, NOT_FOUND_BODY.as_bytes(), "row {i} {audience:?}");
                        } else {
                            assert_eq!(body["error"], *error, "row {i} {audience:?}");
                            assert_eq!(body["status"], *status);
                            assert_eq!(body["type"], "about:blank");
                            let text = String::from_utf8(bytes).unwrap();
                            assert!(
                                !text.contains("npm-local")
                                    && !text.contains(&Uuid::nil().to_string())
                                    || error == &"mcp_age_gate_blocked",
                                "row {i}"
                            );
                        }
                        if audience == ReasonGated && *status == 404 && !error.is_empty() {
                            assert_eq!(body["name"], "com.acme/w");
                            assert_eq!(body["version"], "1.0.0");
                            assert!(body["instance"]
                                .as_str()
                                .unwrap()
                                .starts_with("https://ak.test/"));
                        }
                    }
                    (e, d) => panic!("row {i} {audience:?}: expected {e:?}, got {d:?}"),
                }
            }
        }
        let ServeDecision::Refuse { body, .. } = decide_mcp_serve(
            &state(Active, None, false),
            &[gate(GateOutcome::Quarantine)],
            ReasonGated,
        ) else {
            panic!()
        };
        assert_eq!(
            (body["package"].as_str(), body["gate"].as_str()),
            (Some("npm:@acme/db@2.0.0"), Some("quarantine"))
        );
        let ServeDecision::Refuse { body, .. } =
            decide_mcp_serve(&state(Active, None, false), &[gate(age)], ReasonGated)
        else {
            panic!()
        };
        assert_eq!(
            (
                body["min_age_days"].as_i64(),
                body["requested_age_days"].as_i64()
            ),
            (Some(7), Some(2))
        );
        let ServeDecision::Refuse { body: a, .. } = decide_mcp_serve(
            &state(Active, None, false),
            &[gate(GateOutcome::Unavailable)],
            ReaderOnly,
        ) else {
            panic!()
        };
        let ServeDecision::Refuse { body: b, .. } = decide_mcp_serve(
            &state(Active, None, false),
            &[gate(GateOutcome::Unavailable)],
            ReasonGated,
        ) else {
            panic!()
        };
        assert_eq!(a, b, "503 is the same for everyone");
        assert_eq!(
            serde_json::to_vec(&not_found_value()).unwrap(),
            NOT_FOUND_BODY.as_bytes()
        );
    }

    #[tokio::test]
    async fn handler_checks_path_against_document() {
        let h = McpHandler::new();
        let body = Bytes::from(serde_json::to_vec(&doc(serde_json::json!({}))).unwrap());
        assert!(h
            .validate("servers/com.acme/weather/1.0.0/server.json", &body)
            .await
            .is_ok());
        assert!(h
            .validate("servers/com.acme/other/1.0.0/server.json", &body)
            .await
            .is_err());
        assert!(h.validate("anything", &body).await.is_ok());
        assert_eq!(h.format(), RepositoryFormat::Mcp);
        assert_eq!(h.format_key(), "mcp");
        assert!(h.generate_index().await.unwrap().is_none());
        assert_eq!(
            h.parse_metadata("x", &body).await.unwrap()["package_count"],
            0
        );
    }
}
