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
    /// npm/pypi/nuget/cargo package without an exact `version` (422).
    PackageVersionUnpinned { index: usize },
    /// Pinned OCI manifest is not a runnable image or index (422).
    OciNotAnImage { index: usize },
    /// Name in a reserved namespace (403).
    ReservedNamespace { namespace: String },
    /// Name outside the repository's namespace allowlist (403).
    NamespaceNotAllowed { namespace: String },
    /// `(name, version)` already published (409).
    VersionExists,
    /// `search` shorter than 3 characters (422, upstream parity).
    SearchTooShort,
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

    pub fn status(&self) -> u16 {
        match self {
            McpError::TooLarge => 413,
            McpError::Invalid { .. } => 400,
            McpError::OciLegacyFields { .. }
            | McpError::OciFloatingTag { .. }
            | McpError::ExternalRegistry { .. }
            | McpError::PackageNotFound { .. }
            | McpError::PackageVersionUnpinned { .. }
            | McpError::OciNotAnImage { .. }
            | McpError::SearchTooShort => 422,
            McpError::ReservedNamespace { .. } | McpError::NamespaceNotAllowed { .. } => 403,
            McpError::VersionExists => 409,
            McpError::Misconfigured(_) | McpError::Internal(_) => 500,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            McpError::TooLarge => "mcp_too_large",
            McpError::Invalid { .. } => "mcp_invalid_server_json",
            McpError::OciLegacyFields { .. } => "mcp_oci_legacy_fields",
            McpError::OciFloatingTag { .. } => "mcp_oci_floating_tag",
            McpError::ExternalRegistry { .. } => "mcp_external_registry",
            McpError::PackageNotFound { .. } => "mcp_package_not_found",
            McpError::PackageVersionUnpinned { .. } => "mcp_package_version_unpinned",
            McpError::OciNotAnImage { .. } => "mcp_oci_not_an_image",
            McpError::ReservedNamespace { .. } => "mcp_namespace_reserved",
            McpError::NamespaceNotAllowed { .. } => "mcp_namespace_not_allowed",
            McpError::VersionExists => "mcp_version_exists",
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
            McpError::OciLegacyFields { index } => format!(
                "packages[{index}]: an oci package carries its tag or digest in `identifier`; \
                 remove `version`, `registryBaseUrl` and `fileSha256`"
            ),
            McpError::OciFloatingTag { index } => format!(
                "packages[{index}].identifier: name a specific tag or digest; `latest` and \
                 tagless image references are not accepted (AK pins the digest at publish)"
            ),
            McpError::ExternalRegistry { index, detail }
            | McpError::PackageNotFound { index, detail } => {
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
            McpError::VersionExists => {
                "this server version already exists; publish a new version".to_string()
            }
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
    serde_json::from_slice(bytes)
        .map_err(|e| McpError::invalid("", format!("invalid server.json: {e}")))
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

fn validate_package(i: usize, p: &Package) -> V {
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
    // The upstream specification's "custom installation path" example has
    // neither: such a server points at its setup guide with `websiteUrl`.
    if s.packages.is_empty() && s.remotes.is_empty() && s.website_url.is_none() {
        return Err(McpError::invalid(
            "",
            "a server needs `packages`, `remotes` or a `websiteUrl` describing its installation",
        ));
    }
    check_count("packages", s.packages.len(), MAX_PACKAGES)?;
    check_count("remotes", s.remotes.len(), MAX_REMOTES)?;
    for (i, p) in s.packages.iter().enumerate() {
        validate_package(i, p)?;
    }
    for (i, r) in s.remotes.iter().enumerate() {
        validate_transport(&format!("remotes[{i}]"), r, true)?;
    }
    Ok(())
}

/// Keep only the publisher-provided `_meta` member (upstream rule) and refuse
/// it over [`PUBLISHER_META_MAX_BYTES`].
pub fn reduce_publisher_meta(s: &mut ServerJson) -> V {
    let Some(meta) = s.meta.take() else {
        return Ok(());
    };
    let Some(provided) = meta.get(PUBLISHER_META_KEY) else {
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
    s.meta = Some(kept);
    Ok(())
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

/// `artifacts.storage_key` of a server version: content-addressed, so a
/// publish that loses the race for a version cannot overwrite the bytes of
/// the one that won.
pub fn storage_key(name: &str, version: &str, sha256: &str) -> String {
    format!("mcp/{name}/{version}/{sha256}.json")
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

pub fn encode_cursor(name: &str, version: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("{name}:{version}"))
}

pub fn decode_cursor(cursor: &str) -> std::result::Result<(String, String), McpError> {
    let bad = || McpError::invalid("cursor", "invalid cursor");
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor.trim_end_matches('='))
        .map_err(|_| bad())?;
    let text = String::from_utf8(raw).map_err(|_| bad())?;
    let (name, version) = text.split_once(':').ok_or_else(bad)?;
    if name.is_empty() || version.is_empty() {
        return Err(bad());
    }
    Ok((name.to_string(), version.to_string()))
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
    if tag.as_deref() == Some("latest") || (tag.is_none() && digest.is_none()) {
        return Err(OciRefError::Floating);
    }
    Ok(OciRef {
        host,
        path,
        tag,
        digest,
    })
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
    /// Default: every package resolves to an AK repository of its format.
    OwnRepos,
    /// Explicit opt-out: packages stored and served verbatim, not gated.
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
        let resolving = doc.pointer("/resolution/state").and_then(|v| v.as_str()) == Some("resolving");
        Some(Self {
            server,
            registry,
            policy,
            pins,
            resolving,
        })
    }

    /// Whether every `packages[]` entry of the server has a pin. A version
    /// published under `open` and read under `own-repos` (or whose pins were
    /// lost) is `unresolvable`.
    pub fn unpinned_package(&self) -> Option<String> {
        let packages = self
            .server
            .get("packages")
            .and_then(|p| p.as_array())
            .cloned()
            .unwrap_or_default();
        packages.iter().enumerate().find_map(|(i, p)| {
            if self.pins.iter().any(|pin| pin.index == i) {
                return None;
            }
            let ty = p.get("registryType").and_then(|v| v.as_str()).unwrap_or("");
            let id = p.get("identifier").and_then(|v| v.as_str()).unwrap_or("");
            Some(match p.get("version").and_then(|v| v.as_str()) {
                Some(v) => format!("{ty}:{id}@{v}"),
                None => format!("{ty}:{id}"),
            })
        })
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

/// The served form of a stored `server`: under `own-repos` every pinned
/// package is rewritten to its AK coordinates (`registryBaseUrl` for
/// npm/pypi/nuget/cargo, `identifier` with `@sha256:` for OCI, original in
/// `_meta[com.artifactkeeper/resolved]`); under `open` the stored document is
/// returned untouched.
pub fn rewrite_packages_for_serve(
    server: &serde_json::Value,
    pins: &[PackagePin],
    policy: PackagePolicy,
    base_url: &str,
) -> serde_json::Value {
    let mut out = server.clone();
    if policy == PackagePolicy::Open {
        return out;
    }
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
            let meta = pkg.entry("_meta").or_insert_with(|| serde_json::json!({}));
            if let Some(meta) = meta.as_object_mut() {
                meta.insert(
                    AK_RESOLVED_META_KEY.into(),
                    serde_json::json!({
                        "submittedIdentifier": pin.submitted.identifier,
                        "digest": digest,
                        "mediaType": r.media_type,
                        "children": r.children,
                        "backingRepository": r.repository,
                        "resolvedAt": r.resolved_at,
                    }),
                );
            }
        } else {
            pkg.insert(
                "registryBaseUrl".into(),
                format!(
                    "{base}/{}",
                    backing_route(&pin.registry_type, &r.repository)
                )
                .into(),
            );
        }
    }
    out
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
            serde_json::json!({"transport": {"type": "streamable-http", "url": "{baseUrl}/mcp"}})
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
        assert_eq!(
            storage_key("com.acme/w", "1.0", "ab"),
            "mcp/com.acme/w/1.0/ab.json"
        );
        assert_eq!(
            parse_storage_path("servers/com.acme/w/1.0/server.json"),
            Some(("com.acme/w".into(), "1.0".into()))
        );
        assert_eq!(parse_storage_path("servers/w/1.0/server.json"), None);
        assert_eq!(parse_storage_path("other/a/b/c/server.json"), None);
        let c = encode_cursor("com.acme/w", "1.0.0");
        assert_eq!(
            decode_cursor(&c).unwrap(),
            ("com.acme/w".into(), "1.0.0".into())
        );
        for bad in ["!!!", "bm9jb2xvbg", "", "Ondo", "dzo"] {
            assert!(decode_cursor(bad).is_err(), "{bad}");
        }
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
        let out = rewrite_packages_for_serve(
            &server,
            &pins,
            PackagePolicy::OwnRepos,
            "https://ak.test:8443/",
        );
        assert_eq!(
            out["packages"][0]["registryBaseUrl"],
            "https://ak.test:8443/npm/npm-local"
        );
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
        assert_eq!(
            rewrite_packages_for_serve(&server, &pins, PackagePolicy::Open, "https://ak.test"),
            server
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
