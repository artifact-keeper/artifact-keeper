//! Capability snapshots of MCP server versions (#5253, Phase 2/3).
//!
//! A snapshot records what one server version advertises (tools, resources,
//! prompts, instructions) together with where that list came from:
//!
//! | `source` | Producer | Trust |
//! |---|---|---|
//! | `publisher_declared` | `_meta["com.artifactkeeper/capabilities"]` of the server.json, or an MCPB `manifest.json` (`metadata.bundles[*].manifest`) | a claim ("declared, not observed") |
//! | `ci_reported` | the publisher's pipeline, `POST .../capabilities` | an internal party's observation |
//! | `gateway_reported` | a Docker MCP Gateway / ToolHive inventory, `POST .../capabilities` or the introspector's `push` | an internal party's observation |
//! | `remote_probe` | the `ak-mcp-introspector` worker against `remotes[]` | unauthenticated observation |
//! | `sandbox_run` | the introspector's sandbox runner over stdio | observation of an unconfigured run |
//!
//! No snapshot ever marks a server safe: they inform the Tools tab, the
//! approval queue's tool diff and the `tool_drift` finding.
//!
//! The content hash is order independent (Trail of Bits semantics): each
//! object is hashed over its canonical (key-sorted) JSON, the per-object
//! hashes are sorted, and the kind hash is the hash of that list.
//!
//! Nothing in this module opens a connection: snapshots arrive through the
//! HTTP API or are built from stored metadata.

use chrono::{DateTime, Utc};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::formats::mcp::PUBLISHER_META_KEY;

/// The `_meta` key a publisher declares capabilities under, at the top level
/// of `_meta` or inside the publisher-provided member.
pub const CAPABILITIES_META_KEY: &str = crate::formats::mcp::AK_CAPABILITIES_META_KEY;
/// Serialised size cap of a declared capabilities block in a server.json.
pub const DECLARED_MAX_BYTES: usize = 128 * 1024;
/// Request body cap of `POST .../capabilities` and of a worker result.
pub const INGEST_MAX_BYTES: usize = 1024 * 1024;
/// Per-kind item cap.
pub const MAX_ITEMS: usize = 1000;
pub const MAX_NAME_LEN: usize = 256;
pub const MAX_URI_LEN: usize = 2048;
pub const MAX_INSTRUCTIONS_LEN: usize = 64 * 1024;
pub const MAX_LABEL_LEN: usize = 200;
/// The scanner name drift findings are recorded under.
pub const DRIFT_SCANNER: &str = "ak-mcp-capabilities";
pub const DRIFT_FINDING_SOURCE: &str = "mcp-capabilities";
/// Snapshots kept per (version, source, origin) by the retention pass
/// ([`prune_snapshots`], #5386), newest first. Rows still referenced are kept
/// on top of these.
pub const SNAPSHOT_KEEP: i64 = 20;
/// The freshest snapshots of a version read when choosing its current view
/// ([`pick_current`]) or listing its history.
pub const HISTORY_WINDOW: i64 = 200;
/// Snapshots deleted per retention pass at most.
pub const SNAPSHOT_PRUNE_BATCH: i64 = 1000;
/// How far a reported or observed `observedAt` may lie ahead of the
/// backend's clock (or, for an introspection result, before the job's claim)
/// and still be accepted: the clock skew between the reporter and the
/// backend.
pub const OBSERVED_AT_SKEW_SECS: i64 = 300;
/// The `cacheScope` values a report or an introspection result may carry
/// (#5466): the MCP list pages' cache scope (`private`: the list may differ
/// per caller).
pub const CACHE_SCOPES: &[&str] = &["public", "private"];
/// The freshness order of snapshots, freshest first (#5464): the latest time
/// the content was validly seen (`last_seen_at`, else `observed_at`), then
/// arrival, then id, so ties are deterministic. Every "newest" question (the
/// current view, the drift baseline, the deduplication check, retention)
/// asks it in this order: an observation that arrives late but was made
/// earlier never ranks above a fresher one.
const FRESHEST_FIRST: &str = "COALESCE(last_seen_at, observed_at) DESC, created_at DESC, id DESC";

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

macro_rules! str_enum {
    ($(#[$m:meta])* $name:ident { $($variant:ident => $s:literal),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name { $($variant),+ }
        impl $name {
            pub const ALL: &'static [$name] = &[$($name::$variant),+];
            pub fn as_str(self) -> &'static str {
                match self { $($name::$variant => $s),+ }
            }
            pub fn parse(s: &str) -> Option<Self> {
                match s { $($s => Some($name::$variant),)+ _ => None }
            }
        }
    };
}

str_enum!(
    /// Who produced a snapshot.
    Source {
        PublisherDeclared => "publisher_declared",
        CiReported => "ci_reported",
        GatewayReported => "gateway_reported",
        RemoteProbe => "remote_probe",
        SandboxRun => "sandbox_run",
    }
);

str_enum!(
    /// Whether the observed list depended on the caller's authorization.
    AuthState {
        None => "none",
        AuthRequired => "auth_required",
        CallerSpecific => "caller_specific",
        Unknown => "unknown",
    }
);

str_enum!(
    /// How the attempt that produced a snapshot ended.
    Outcome {
        Ok => "ok",
        AuthRequired => "auth_required",
        RateLimited => "rate_limited",
        Timeout => "timeout",
        StartFailed => "start_failed",
        NeedsConfig => "needs_config",
        Refused => "refused",
        Unsupported => "unsupported",
        Error => "error",
    }
);

impl Source {
    /// Whether AK's own worker observed the list (as opposed to a claim or a
    /// third-party report).
    pub fn is_observed(self) -> bool {
        matches!(self, Source::RemoteProbe | Source::SandboxRun)
    }

    /// The sources a client may post to `POST .../capabilities`.
    pub fn is_reportable(self) -> bool {
        matches!(self, Source::CiReported | Source::GatewayReported)
    }

    /// The default display label.
    pub fn default_provenance(self) -> &'static str {
        match self {
            Source::PublisherDeclared => "declared by the publisher",
            Source::CiReported => "reported by CI",
            Source::GatewayReported => "reported by a gateway",
            Source::RemoteProbe => "observed by remote probe",
            Source::SandboxRun => "observed in sandbox",
        }
    }

    /// Which snapshot "is" the current view when several sources exist:
    /// observations first, declarations last.
    pub fn precedence(self) -> u8 {
        match self {
            Source::SandboxRun => 0,
            Source::RemoteProbe => 1,
            Source::GatewayReported => 2,
            Source::CiReported => 3,
            Source::PublisherDeclared => 4,
        }
    }

    /// Severity of a `tool_drift` finding raised by a changed snapshot of
    /// this source. A remote that changes what it advertises under the same
    /// version is the rug pull (T4c) the probe exists for.
    pub fn drift_severity(self) -> crate::models::security::Severity {
        use crate::models::security::Severity;
        match self {
            Source::RemoteProbe | Source::SandboxRun => Severity::High,
            Source::CiReported | Source::GatewayReported => Severity::Medium,
            Source::PublisherDeclared => Severity::Low,
        }
    }
}

// ---------------------------------------------------------------------------
// Capability sets: validation and hashing
// ---------------------------------------------------------------------------

/// Why a submitted capability document was refused (400 on the API).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapError {
    pub path: String,
    pub message: String,
}

impl CapError {
    pub fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.path.is_empty() {
            write!(f, "{}", self.message)
        } else {
            write!(f, "{}: {}", self.path, self.message)
        }
    }
}

/// One kind of capability item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Tools,
    Resources,
    Prompts,
}

impl Kind {
    pub const ALL: [Kind; 3] = [Kind::Tools, Kind::Resources, Kind::Prompts];

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Tools => "tools",
            Kind::Resources => "resources",
            Kind::Prompts => "prompts",
        }
    }

    /// The member that identifies an item.
    pub fn key_field(self) -> &'static str {
        match self {
            Kind::Resources => "uri",
            Kind::Tools | Kind::Prompts => "name",
        }
    }

    /// The members the hash and the diff cover (anything else, `_meta`
    /// included, is carried but does not count as a change).
    pub fn hashed_fields(self) -> &'static [&'static str] {
        match self {
            Kind::Tools => &[
                "name",
                "title",
                "description",
                "inputSchema",
                "outputSchema",
                "annotations",
            ],
            Kind::Resources => &[
                "uri",
                "name",
                "title",
                "description",
                "mimeType",
                "annotations",
            ],
            Kind::Prompts => &["name", "title", "description", "arguments"],
        }
    }

    fn key_cap(self) -> usize {
        match self {
            Kind::Resources => MAX_URI_LEN,
            Kind::Tools | Kind::Prompts => MAX_NAME_LEN,
        }
    }
}

/// The validated content of a snapshot.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CapabilitySet {
    pub tools: Vec<Value>,
    pub resources: Vec<Value>,
    pub prompts: Vec<Value>,
    pub instructions: Option<String>,
}

impl CapabilitySet {
    pub fn items(&self, kind: Kind) -> &[Value] {
        match kind {
            Kind::Tools => &self.tools,
            Kind::Resources => &self.resources,
            Kind::Prompts => &self.prompts,
        }
    }

    /// Parse the `{tools, resources, prompts, instructions}` members of
    /// `doc` (each optional). Items must be objects with a non-empty string
    /// key (`name`, or `uri` for resources), unique per kind.
    ///
    /// Identifiers (the key, a resource's `name`, a prompt argument's
    /// `name`) with control, bidirectional, zero-width or tag characters
    /// are refused, as the publish path refuses them in a declared block
    /// (`formats::mcp::has_forbidden_chars`). Free text (titles,
    /// descriptions, `instructions`) is not refused here: the lint flags it
    /// (`mcp_lint::lint_capabilities`, `hidden_text`).
    pub fn from_doc(doc: &Value) -> Result<Self, CapError> {
        let Some(obj) = doc.as_object() else {
            return Err(CapError::new("", "must be a JSON object"));
        };
        let mut set = CapabilitySet::default();
        for kind in Kind::ALL {
            let items = match obj.get(kind.as_str()) {
                None | Some(Value::Null) => Vec::new(),
                Some(Value::Array(a)) => a.clone(),
                Some(_) => return Err(CapError::new(kind.as_str(), "must be an array")),
            };
            validate_items(kind, &items)?;
            match kind {
                Kind::Tools => set.tools = items,
                Kind::Resources => set.resources = items,
                Kind::Prompts => set.prompts = items,
            }
        }
        set.instructions = match obj.get("instructions") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if s.len() <= MAX_INSTRUCTIONS_LEN => Some(s.clone()),
            Some(Value::String(_)) => {
                return Err(CapError::new(
                    "instructions",
                    format!("must be at most {MAX_INSTRUCTIONS_LEN} bytes"),
                ))
            }
            Some(_) => return Err(CapError::new("instructions", "must be a string")),
        };
        Ok(set)
    }

    pub fn tools_hash(&self) -> String {
        kind_hash(Kind::Tools, &self.tools)
    }

    /// The order-independent hash of everything the snapshot advertises.
    pub fn content_hash(&self) -> String {
        let instructions = sha256_hex(self.instructions.as_deref().unwrap_or("").as_bytes());
        sha256_hex(
            format!(
                "tools:{}\nresources:{}\nprompts:{}\ninstructions:{}",
                self.tools_hash(),
                kind_hash(Kind::Resources, &self.resources),
                kind_hash(Kind::Prompts, &self.prompts),
                instructions
            )
            .as_bytes(),
        )
    }
}

fn validate_items(kind: Kind, items: &[Value]) -> Result<(), CapError> {
    if items.len() > MAX_ITEMS {
        return Err(CapError::new(
            kind.as_str(),
            format!("at most {MAX_ITEMS} entries"),
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for (i, item) in items.iter().enumerate() {
        let path = format!("{}[{i}]", kind.as_str());
        let Some(obj) = item.as_object() else {
            return Err(CapError::new(path, "must be an object"));
        };
        let field = kind.key_field();
        let key = match obj.get(field) {
            Some(Value::String(s)) if !s.is_empty() && s.len() <= kind.key_cap() => s,
            _ => {
                return Err(CapError::new(
                    format!("{path}.{field}"),
                    format!(
                        "must be a non-empty string of at most {} bytes",
                        kind.key_cap()
                    ),
                ))
            }
        };
        check_identifiers(kind, obj, &path)?;
        if !seen.insert(key.clone()) {
            return Err(CapError::new(
                format!("{path}.{field}"),
                format!("duplicate {field} `{key}`"),
            ));
        }
    }
    Ok(())
}

/// Refuse hidden characters in an item's identifiers (#5388): its key, a
/// resource's `name`, a prompt argument's `name`.
fn check_identifiers(kind: Kind, obj: &Map<String, Value>, path: &str) -> Result<(), CapError> {
    let refuse = |at: String| {
        Err(CapError::new(
            at,
            "control, bidirectional or zero-width characters are not allowed",
        ))
    };
    let hidden = |v: Option<&Value>| {
        v.and_then(Value::as_str)
            .is_some_and(crate::formats::mcp::has_forbidden_chars)
    };
    let field = kind.key_field();
    if hidden(obj.get(field)) {
        return refuse(format!("{path}.{field}"));
    }
    if kind == Kind::Resources && hidden(obj.get("name")) {
        return refuse(format!("{path}.name"));
    }
    if kind == Kind::Prompts {
        if let Some(args) = obj.get("arguments").and_then(Value::as_array) {
            for (j, arg) in args.iter().enumerate() {
                if hidden(arg.get("name")) {
                    return refuse(format!("{path}.arguments[{j}].name"));
                }
            }
        }
    }
    Ok(())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// The members of `item` that take part in its identity and diff.
fn hashed_view(kind: Kind, item: &Value) -> Value {
    let mut out = Map::new();
    if let Some(obj) = item.as_object() {
        for f in kind.hashed_fields() {
            if let Some(v) = obj.get(*f) {
                if !v.is_null() {
                    out.insert((*f).to_string(), v.clone());
                }
            }
        }
    }
    Value::Object(out)
}

/// `serde_json` serialises object keys sorted (`preserve_order` is off), so
/// this is canonical JSON of the hashed view.
pub fn item_hash(kind: Kind, item: &Value) -> String {
    sha256_hex(&serde_json::to_vec(&hashed_view(kind, item)).unwrap_or_default())
}

pub fn kind_hash(kind: Kind, items: &[Value]) -> String {
    let mut hashes: Vec<String> = items.iter().map(|i| item_hash(kind, i)).collect();
    hashes.sort_unstable();
    sha256_hex(hashes.join("\n").as_bytes())
}

fn item_key(kind: Kind, item: &Value) -> String {
    item.get(kind.key_field())
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string()
}

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

/// One changed item: which hashed members differ, and both versions.
#[derive(Debug, Clone, PartialEq)]
pub struct ChangedItem {
    pub key: String,
    pub fields: Vec<String>,
    pub before: Value,
    pub after: Value,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct KindDiff {
    pub added: Vec<Value>,
    pub removed: Vec<Value>,
    pub changed: Vec<ChangedItem>,
    pub unchanged: usize,
}

impl KindDiff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct CapabilityDiff {
    pub tools: KindDiff,
    pub resources: KindDiff,
    pub prompts: KindDiff,
    pub instructions_changed: bool,
}

impl CapabilityDiff {
    pub fn kind(&self, kind: Kind) -> &KindDiff {
        match kind {
            Kind::Tools => &self.tools,
            Kind::Resources => &self.resources,
            Kind::Prompts => &self.prompts,
        }
    }

    pub fn is_empty(&self) -> bool {
        Kind::ALL.iter().all(|k| self.kind(*k).is_empty()) && !self.instructions_changed
    }
}

fn diff_kind(kind: Kind, from: &[Value], to: &[Value]) -> KindDiff {
    let before: std::collections::BTreeMap<String, &Value> =
        from.iter().map(|i| (item_key(kind, i), i)).collect();
    let after: std::collections::BTreeMap<String, &Value> =
        to.iter().map(|i| (item_key(kind, i), i)).collect();
    let mut d = KindDiff::default();
    for (key, new) in &after {
        match before.get(key) {
            None => d.added.push((*new).clone()),
            Some(old) => {
                let (ov, nv) = (hashed_view(kind, old), hashed_view(kind, new));
                let fields: Vec<String> = kind
                    .hashed_fields()
                    .iter()
                    .filter(|f| ov.get(**f) != nv.get(**f))
                    .map(|f| f.to_string())
                    .collect();
                if fields.is_empty() {
                    d.unchanged += 1;
                } else {
                    d.changed.push(ChangedItem {
                        key: key.clone(),
                        fields,
                        before: (*old).clone(),
                        after: (*new).clone(),
                    });
                }
            }
        }
    }
    for (key, old) in &before {
        if !after.contains_key(key) {
            d.removed.push((*old).clone());
        }
    }
    d
}

/// What changed from `from` (absent: everything is new) to `to`.
pub fn diff(from: Option<&CapabilitySet>, to: &CapabilitySet) -> CapabilityDiff {
    let empty = CapabilitySet::default();
    let from = from.unwrap_or(&empty);
    CapabilityDiff {
        tools: diff_kind(Kind::Tools, &from.tools, &to.tools),
        resources: diff_kind(Kind::Resources, &from.resources, &to.resources),
        prompts: diff_kind(Kind::Prompts, &from.prompts, &to.prompts),
        instructions_changed: from.instructions != to.instructions,
    }
}

fn hint(item: &Value, name: &str) -> Option<bool> {
    item.pointer(&format!("/annotations/{name}"))
        .and_then(|v| v.as_bool())
}

/// Tools the diff makes destructive: added with `destructiveHint: true`, or
/// changed so that `destructiveHint` became true.
pub fn newly_destructive(d: &CapabilityDiff) -> Vec<String> {
    let mut out: Vec<String> = d
        .tools
        .added
        .iter()
        .filter(|t| hint(t, "destructiveHint") == Some(true))
        .map(|t| item_key(Kind::Tools, t))
        .collect();
    out.extend(
        d.tools
            .changed
            .iter()
            .filter(|c| {
                hint(&c.after, "destructiveHint") == Some(true)
                    && hint(&c.before, "destructiveHint") != Some(true)
            })
            .map(|c| c.key.clone()),
    );
    out
}

/// The approval queue's one-line summary, e.g.
/// "Tools: +3 added, 1 changed (`delete_repo` now destructiveHint: true)".
pub fn summary_text(d: &CapabilityDiff) -> String {
    let mut parts = Vec::new();
    for kind in Kind::ALL {
        let k = d.kind(kind);
        if k.is_empty() {
            continue;
        }
        let mut bits = Vec::new();
        if !k.added.is_empty() {
            bits.push(format!("+{} added", k.added.len()));
        }
        if !k.removed.is_empty() {
            bits.push(format!("-{} removed", k.removed.len()));
        }
        if !k.changed.is_empty() {
            bits.push(format!("{} changed", k.changed.len()));
        }
        let mut label = kind.as_str().to_string();
        label[..1].make_ascii_uppercase();
        let mut line = format!("{label}: {}", bits.join(", "));
        if kind == Kind::Tools {
            let destructive = newly_destructive(d);
            if !destructive.is_empty() {
                let names: Vec<String> = destructive
                    .iter()
                    .take(5)
                    .map(|n| format!("`{n}` now destructiveHint: true"))
                    .collect();
                line.push_str(&format!(" ({})", names.join(", ")));
            }
        }
        parts.push(line);
    }
    if d.instructions_changed {
        parts.push("Instructions changed".to_string());
    }
    if parts.is_empty() {
        "No changes".to_string()
    } else {
        parts.join("; ")
    }
}

fn kind_diff_json(kind: Kind, k: &KindDiff) -> Value {
    let key = |i: &Value| item_key(kind, i);
    json!({
        "added": k.added.iter().map(|i| json!({"key": key(i), "item": i})).collect::<Vec<_>>(),
        "removed": k.removed.iter().map(|i| json!({"key": key(i), "item": i})).collect::<Vec<_>>(),
        "changed": k.changed.iter().map(|c| json!({
            "key": c.key, "fields": c.fields, "before": c.before, "after": c.after,
        })).collect::<Vec<_>>(),
        "unchanged": k.unchanged,
    })
}

/// The wire form of a diff (the `GET .../capabilities/diff` body minus the
/// snapshot summaries).
pub fn diff_json(d: &CapabilityDiff) -> Value {
    json!({
        "summary": {
            "text": summary_text(d),
            "tools": counts(&d.tools),
            "resources": counts(&d.resources),
            "prompts": counts(&d.prompts),
            "instructionsChanged": d.instructions_changed,
            "destructiveAdded": newly_destructive(d),
            "identical": d.is_empty(),
        },
        "tools": kind_diff_json(Kind::Tools, &d.tools),
        "resources": kind_diff_json(Kind::Resources, &d.resources),
        "prompts": kind_diff_json(Kind::Prompts, &d.prompts),
        "instructionsChanged": d.instructions_changed,
    })
}

fn counts(k: &KindDiff) -> Value {
    json!({
        "added": k.added.len(),
        "removed": k.removed.len(),
        "changed": k.changed.len(),
        "unchanged": k.unchanged,
    })
}

// ---------------------------------------------------------------------------
// Declared snapshots from stored metadata
// ---------------------------------------------------------------------------

/// One publisher declaration found in a version's metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct Declared {
    /// `server.json` or `mcpb:<fileSha256>`.
    pub origin: String,
    pub provenance: String,
    pub set: CapabilitySet,
    pub protocol_version: Option<String>,
    pub details: Value,
}

/// The declared block of a server document: `_meta[CAPABILITIES_META_KEY]`
/// at the top level, else inside the publisher-provided member (the only
/// `_meta` member an upstream registry keeps).
pub fn declared_block(server: &Value) -> Option<&Value> {
    let meta = server.get("_meta")?;
    meta.get(CAPABILITIES_META_KEY)
        .or_else(|| meta.get(PUBLISHER_META_KEY)?.get(CAPABILITIES_META_KEY))
}

/// Validate a declared block at publish (the publish path refuses with 400
/// on error). Same shape as an ingest body, at most [`DECLARED_MAX_BYTES`].
pub fn validate_declared_block(block: &Value) -> Result<CapabilitySet, CapError> {
    let size = serde_json::to_vec(block)
        .map(|b| b.len())
        .unwrap_or(usize::MAX);
    if size > DECLARED_MAX_BYTES {
        return Err(CapError::new(
            format!("_meta.{CAPABILITIES_META_KEY}"),
            format!("must be at most {DECLARED_MAX_BYTES} bytes"),
        ));
    }
    CapabilitySet::from_doc(block).map_err(|e| {
        CapError::new(
            if e.path.is_empty() {
                format!("_meta.{CAPABILITIES_META_KEY}")
            } else {
                format!("_meta.{CAPABILITIES_META_KEY}.{}", e.path)
            },
            e.message,
        )
    })
}

fn opt_str(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(|s| s.as_str())
        .map(|s| s.chars().take(MAX_LABEL_LEN).collect())
}

/// MCPB `manifest.json` tools/prompts (name + description; prompts may carry
/// `arguments`) as a capability set. Entries without a string name are
/// skipped: a bundle is declared, not validated, here.
fn mcpb_set(manifest: &Value) -> CapabilitySet {
    let pick = |key: &str, fields: &[&str]| -> Vec<Value> {
        let mut seen = std::collections::HashSet::new();
        manifest
            .get(key)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|item| {
                        let name = item.get("name")?.as_str()?;
                        if name.is_empty() || name.len() > MAX_NAME_LEN || !seen.insert(name) {
                            return None;
                        }
                        let mut o = Map::new();
                        for f in fields {
                            if let Some(v) = item.get(*f) {
                                o.insert((*f).to_string(), v.clone());
                            }
                        }
                        Some(Value::Object(o))
                    })
                    .take(MAX_ITEMS)
                    .collect()
            })
            .unwrap_or_default()
    };
    CapabilitySet {
        tools: pick("tools", &["name", "description"]),
        resources: Vec::new(),
        prompts: pick("prompts", &["name", "description", "arguments"]),
        instructions: None,
    }
}

/// Every declaration in a version's `artifact_metadata.metadata`: the
/// server.json block and one per MCPB bundle (`metadata.bundles[]`) whose
/// manifest declares tools or prompts (or says it generates them).
pub fn declared_from_metadata(metadata: &Value) -> Vec<Declared> {
    let mut out = Vec::new();
    if let Some(block) = metadata.get("server").and_then(declared_block) {
        match CapabilitySet::from_doc(block) {
            Ok(set) => out.push(Declared {
                origin: "server.json".to_string(),
                provenance: "declared in server.json".to_string(),
                set,
                protocol_version: opt_str(block, "protocolVersion"),
                details: json!({ "generatedBy": opt_str(block, "generatedBy") }),
            }),
            Err(e) => tracing::warn!(error = %e, "unreadable declared capabilities skipped"),
        }
    }
    let bundles = metadata
        .get("bundles")
        .and_then(|b| b.as_array())
        .cloned()
        .unwrap_or_default();
    for bundle in &bundles {
        let Some(manifest) = bundle.get("manifest") else {
            continue;
        };
        let set = mcpb_set(manifest);
        let generated = |k: &str| manifest.get(k).and_then(|v| v.as_bool()).unwrap_or(false);
        let (tools_generated, prompts_generated) =
            (generated("tools_generated"), generated("prompts_generated"));
        if set.tools.is_empty() && set.prompts.is_empty() && !tools_generated && !prompts_generated
        {
            continue;
        }
        let id = opt_str(bundle, "fileSha256")
            .or_else(|| opt_str(bundle, "artifactId"))
            .unwrap_or_else(|| "unknown".to_string());
        out.push(Declared {
            origin: format!("mcpb:{id}"),
            provenance: "declared in MCPB manifest".to_string(),
            set,
            protocol_version: None,
            details: json!({
                "bundleArtifactId": bundle.get("artifactId"),
                "fileSha256": bundle.get("fileSha256"),
                "signature": bundle.pointer("/signature/state"),
                "toolsGenerated": tools_generated,
                "promptsGenerated": prompts_generated,
            }),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// A snapshot to store.
#[derive(Debug, Clone)]
pub struct NewSnapshot {
    pub repository_id: Uuid,
    pub artifact_id: Uuid,
    pub server_name: String,
    pub server_version: String,
    pub source: Source,
    pub provenance: String,
    pub origin: Option<String>,
    pub reported_by: Option<Uuid>,
    pub auth_state: AuthState,
    pub outcome: Outcome,
    pub protocol_version: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub ttl_ms: Option<i64>,
    pub cache_scope: Option<String>,
    pub set: CapabilitySet,
    pub worker_version: Option<String>,
    pub details: Value,
}

/// A stored snapshot.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SnapshotRow {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub artifact_id: Uuid,
    pub server_name: String,
    pub server_version: String,
    pub source: String,
    pub provenance: String,
    pub origin: Option<String>,
    pub reported_by: Option<Uuid>,
    pub auth_state: String,
    pub outcome: String,
    pub protocol_version: Option<String>,
    pub observed_at: DateTime<Utc>,
    pub ttl_ms: Option<i64>,
    pub cache_scope: Option<String>,
    pub tools: Value,
    pub resources: Value,
    pub prompts: Value,
    pub instructions: Option<String>,
    pub tools_hash: String,
    pub content_hash: String,
    pub worker_version: Option<String>,
    pub details: Value,
    pub created_at: DateTime<Utc>,
    /// The latest time this content was seen again (a deduplicated repeat,
    /// #5386); `None` until it is.
    pub last_seen_at: Option<DateTime<Utc>>,
}

const SNAPSHOT_COLUMNS: &str = "id, repository_id, artifact_id, server_name, server_version, \
     source, provenance, origin, reported_by, auth_state, outcome, protocol_version, observed_at, \
     ttl_ms, cache_scope, tools, resources, prompts, instructions, tools_hash, content_hash, \
     worker_version, details, created_at, last_seen_at";

fn arr(v: &Value) -> Vec<Value> {
    v.as_array().cloned().unwrap_or_default()
}

impl SnapshotRow {
    pub fn source(&self) -> Option<Source> {
        Source::parse(&self.source)
    }

    /// The latest time this content was validly seen: `last_seen_at`, else
    /// `observed_at` (#5464).
    pub fn freshness(&self) -> DateTime<Utc> {
        self.last_seen_at.unwrap_or(self.observed_at)
    }

    /// The [`FRESHEST_FIRST`] sort key, greatest first.
    fn freshness_key(&self) -> (DateTime<Utc>, DateTime<Utc>, Uuid) {
        (self.freshness(), self.created_at, self.id)
    }

    /// What [`pick_current`] ranks this snapshot by.
    pub fn rank(&self) -> SnapshotRank {
        SnapshotRank {
            id: self.id,
            source: self.source.clone(),
            outcome: self.outcome.clone(),
            observed_at: self.observed_at,
            last_seen_at: self.last_seen_at,
            created_at: self.created_at,
        }
    }

    pub fn set(&self) -> CapabilitySet {
        CapabilitySet {
            tools: arr(&self.tools),
            resources: arr(&self.resources),
            prompts: arr(&self.prompts),
            instructions: self.instructions.clone(),
        }
    }

    /// The wire summary (no item bodies).
    pub fn summary_json(&self) -> Value {
        let source = self.source();
        json!({
            "id": self.id,
            "source": self.source,
            "provenance": self.provenance,
            "origin": self.origin,
            "observed": source.is_some_and(Source::is_observed),
            "authState": self.auth_state,
            "outcome": self.outcome,
            "protocolVersion": self.protocol_version,
            "observedAt": self.observed_at,
            "lastSeenAt": self.last_seen_at.unwrap_or(self.observed_at),
            "ttlMs": self.ttl_ms,
            "cacheScope": self.cache_scope,
            "counts": {
                "tools": arr(&self.tools).len(),
                "resources": arr(&self.resources).len(),
                "prompts": arr(&self.prompts).len(),
            },
            "toolsHash": self.tools_hash,
            "contentHash": self.content_hash,
            "workerVersion": self.worker_version,
            "reportedBy": self.reported_by,
            "details": self.details,
            "createdAt": self.created_at,
        })
    }

    /// The full wire form: the summary plus the items.
    pub fn to_json(&self) -> Value {
        let mut v = self.summary_json();
        if let Some(o) = v.as_object_mut() {
            o.insert("tools".into(), self.tools.clone());
            o.insert("resources".into(), self.resources.clone());
            o.insert("prompts".into(), self.prompts.clone());
            o.insert("instructions".into(), json!(self.instructions));
        }
        v
    }
}

/// What [`insert_snapshot`] stored.
#[derive(Debug, Clone)]
pub struct Inserted {
    pub snapshot: SnapshotRow,
    /// The previous successful snapshot of the same source (and, for a
    /// declaration, the same origin).
    pub previous: Option<SnapshotRow>,
    /// `false` when nothing new was stored: an identical declaration already
    /// existed (idempotent), or the newest snapshot of the same (version,
    /// source, origin) has the same content, outcome and auth state and only
    /// its `last_seen_at` was bumped (#5386). No audit, lint or drift then.
    pub created: bool,
    /// The snapshot was stored as history only: a successful snapshot of the
    /// same source (`previous`) was seen more recently than this one was
    /// observed, so this one does not become current, raises no drift and is
    /// not linted (#5464).
    pub superseded: bool,
}

impl Inserted {
    /// A successful snapshot whose content differs from the previous
    /// successful one of the same source: `tool_drift`.
    pub fn drifted(&self) -> bool {
        self.created
            && !self.superseded
            && self.snapshot.outcome == Outcome::Ok.as_str()
            && self
                .previous
                .as_ref()
                .is_some_and(|p| p.content_hash != self.snapshot.content_hash)
    }
}

/// The newest successful snapshot of `source` for `artifact_id` (for a
/// declaration, of the same `origin`), excluding `except`.
async fn previous_ok(
    db: &mut sqlx::PgConnection,
    artifact_id: Uuid,
    source: Source,
    origin: Option<&str>,
    except: Option<Uuid>,
) -> sqlx::Result<Option<SnapshotRow>> {
    let sql = format!(
        "SELECT {SNAPSHOT_COLUMNS} FROM mcp_capability_snapshots \
         WHERE artifact_id = $1 AND source = $2 AND outcome = 'ok' \
           AND ($3::text IS NULL OR source <> 'publisher_declared' OR origin IS NOT DISTINCT FROM $3) \
           AND ($4::uuid IS NULL OR id <> $4) \
         ORDER BY {FRESHEST_FIRST} LIMIT 1"
    );
    sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(artifact_id)
        .bind(source.as_str())
        .bind(origin)
        .bind(except)
        .fetch_optional(db)
        .await
}

/// Store a snapshot in its own transaction. See [`insert_snapshot_in`].
pub async fn insert_snapshot(db: &PgPool, s: &NewSnapshot) -> sqlx::Result<Inserted> {
    let mut tx = db.begin().await?;
    let ins = insert_snapshot_in(&mut tx, s).await?;
    tx.commit().await?;
    Ok(ins)
}

/// The newest snapshot of (version, source, origin) when it already records
/// what `s` saw: same `content_hash`, `outcome` and `auth_state` (#5386).
async fn repeat_of_latest(
    db: &mut sqlx::PgConnection,
    s: &NewSnapshot,
    origin: Option<&str>,
) -> sqlx::Result<Option<SnapshotRow>> {
    let sql = format!(
        "SELECT {SNAPSHOT_COLUMNS} FROM mcp_capability_snapshots \
         WHERE artifact_id = $1 AND source = $2 AND origin IS NOT DISTINCT FROM $3 \
         ORDER BY {FRESHEST_FIRST} LIMIT 1"
    );
    let latest: Option<SnapshotRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(s.artifact_id)
        .bind(s.source.as_str())
        .bind(origin)
        .fetch_optional(db)
        .await?;
    Ok(latest.filter(|l| {
        l.content_hash == s.set.content_hash()
            && l.outcome == s.outcome.as_str()
            && l.auth_state == s.auth_state.as_str()
    }))
}

/// Store a snapshot on `db` (a transaction: the caller commits).
///
/// A reported or observed snapshot that repeats the newest one of the same
/// (version, source, origin) is not stored again: that row's `last_seen_at`
/// (and `ttl_ms`, the latest re-probe hint) is bumped and it is returned with
/// `created: false` (#5386). The check runs under a transaction-scoped
/// advisory lock on the (version, source, origin), so two concurrent repeats
/// cannot both insert. A declaration stays idempotent through its unique
/// index.
pub async fn insert_snapshot_in(
    db: &mut sqlx::PgConnection,
    s: &NewSnapshot,
) -> sqlx::Result<Inserted> {
    let origin = s.origin.as_deref().map(|o| truncate(o, MAX_URI_LEN));
    if s.source != Source::PublisherDeclared {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!(
                "mcp-snapshot/{}/{}/{}",
                s.artifact_id,
                s.source.as_str(),
                origin.as_deref().unwrap_or("")
            ))
            .execute(&mut *db)
            .await?;
        if let Some(latest) = repeat_of_latest(&mut *db, s, origin.as_deref()).await? {
            let sql = format!(
                "UPDATE mcp_capability_snapshots SET \
                   last_seen_at = GREATEST(COALESCE(last_seen_at, observed_at), $2), \
                   ttl_ms = $3 \
                 WHERE id = $1 RETURNING {SNAPSHOT_COLUMNS}"
            );
            let snapshot: SnapshotRow = sqlx::query_as(sqlx::AssertSqlSafe(sql))
                .bind(latest.id)
                .bind(s.observed_at)
                .bind(s.ttl_ms)
                .fetch_one(&mut *db)
                .await?;
            return Ok(Inserted {
                snapshot,
                previous: None,
                created: false,
                superseded: false,
            });
        }
    }
    let origin_scope =
        (s.source == Source::PublisherDeclared).then(|| s.origin.as_deref().unwrap_or(""));
    let previous = previous_ok(&mut *db, s.artifact_id, s.source, origin_scope, None).await?;
    let superseded = previous
        .as_ref()
        .is_some_and(|p| p.freshness() > s.observed_at);
    let sql = format!(
        "INSERT INTO mcp_capability_snapshots (repository_id, artifact_id, server_name, \
           server_version, source, provenance, origin, reported_by, auth_state, outcome, \
           protocol_version, observed_at, ttl_ms, cache_scope, tools, resources, prompts, \
           instructions, tools_hash, content_hash, worker_version, details) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22) \
         ON CONFLICT DO NOTHING RETURNING {SNAPSHOT_COLUMNS}"
    );
    let row: Option<SnapshotRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(s.repository_id)
        .bind(s.artifact_id)
        .bind(&s.server_name)
        .bind(&s.server_version)
        .bind(s.source.as_str())
        .bind(truncate(&s.provenance, MAX_LABEL_LEN))
        .bind(&origin)
        .bind(s.reported_by)
        .bind(s.auth_state.as_str())
        .bind(s.outcome.as_str())
        .bind(s.protocol_version.as_deref().map(|p| truncate(p, 64)))
        .bind(s.observed_at)
        .bind(s.ttl_ms)
        .bind(s.cache_scope.as_deref().map(|c| truncate(c, 32)))
        .bind(Value::Array(s.set.tools.clone()))
        .bind(Value::Array(s.set.resources.clone()))
        .bind(Value::Array(s.set.prompts.clone()))
        .bind(&s.set.instructions)
        .bind(s.set.tools_hash())
        .bind(s.set.content_hash())
        .bind(s.worker_version.as_deref().map(|w| truncate(w, 128)))
        .bind(&s.details)
        .fetch_optional(&mut *db)
        .await?;
    match row {
        Some(snapshot) => Ok(Inserted {
            snapshot,
            previous,
            created: true,
            superseded,
        }),
        // An identical declaration exists: return it, nothing new happened.
        None => {
            let sql = format!(
                "SELECT {SNAPSHOT_COLUMNS} FROM mcp_capability_snapshots \
                 WHERE artifact_id = $1 AND source = 'publisher_declared' \
                   AND COALESCE(origin, '') = COALESCE($2, '') AND content_hash = $3 LIMIT 1"
            );
            let snapshot: SnapshotRow = sqlx::query_as(sqlx::AssertSqlSafe(sql))
                .bind(s.artifact_id)
                .bind(&s.origin)
                .bind(s.set.content_hash())
                .fetch_one(&mut *db)
                .await?;
            Ok(Inserted {
                snapshot,
                previous: None,
                created: false,
                superseded: false,
            })
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

pub async fn get_snapshot(db: &PgPool, id: Uuid) -> sqlx::Result<Option<SnapshotRow>> {
    let sql = format!("SELECT {SNAPSHOT_COLUMNS} FROM mcp_capability_snapshots WHERE id = $1");
    sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(id)
        .fetch_optional(db)
        .await
}

/// Snapshots of one server version, freshest first ([`FRESHEST_FIRST`]),
/// optionally of one source.
pub async fn list_snapshots(
    db: impl sqlx::PgExecutor<'_>,
    artifact_id: Uuid,
    source: Option<Source>,
    limit: i64,
) -> sqlx::Result<Vec<SnapshotRow>> {
    let sql = format!(
        "SELECT {SNAPSHOT_COLUMNS} FROM mcp_capability_snapshots \
         WHERE artifact_id = $1 AND ($2::text IS NULL OR source = $2) \
         ORDER BY {FRESHEST_FIRST} LIMIT $3"
    );
    sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(artifact_id)
        .bind(source.map(Source::as_str))
        .bind(limit)
        .fetch_all(db)
        .await
}

/// Delete snapshot history beyond the freshest [`SNAPSHOT_KEEP`] of each
/// (version, source, origin), at most [`SNAPSHOT_PRUNE_BATCH`] rows (#5386).
/// Run by the introspection scheduler pass; idempotent.
///
/// Never deleted, whatever its rank:
/// * the freshest successful snapshot of each (version, source, origin): the
///   current view ([`pick_current`]) and the baseline the next snapshot is
///   compared against for drift;
/// * a snapshot a `tool_drift` finding names (its description carries both
///   snapshot ids, which the diff link uses);
/// * a snapshot an open job, or the newest job of its target, points at (the
///   re-probe schedule reads that snapshot's `ttlMs`). An older job's
///   `snapshot_id` is cleared by the foreign key (`ON DELETE SET NULL`);
///   the job row itself keeps its status and timestamps.
pub async fn prune_snapshots(db: &PgPool) -> sqlx::Result<u64> {
    let sql = format!(
        "WITH ranked AS ( \
           SELECT id, artifact_id, outcome, \
             row_number() OVER (PARTITION BY artifact_id, source, COALESCE(origin, '') \
                                ORDER BY {FRESHEST_FIRST}) AS rn, \
             row_number() OVER (PARTITION BY artifact_id, source, COALESCE(origin, ''), \
                                  outcome = 'ok' \
                                ORDER BY {FRESHEST_FIRST}) AS rn_outcome \
           FROM mcp_capability_snapshots), \
         victims AS ( \
           SELECT r.id FROM ranked r \
           WHERE r.rn > $1 \
             AND NOT (r.outcome = 'ok' AND r.rn_outcome = 1) \
             AND NOT EXISTS (SELECT 1 FROM scan_findings f \
                             WHERE f.artifact_id = r.artifact_id AND f.source = $3 \
                               AND strpos(f.description, r.id::text) > 0) \
             AND NOT EXISTS (SELECT 1 FROM mcp_introspection_jobs j \
                             WHERE j.snapshot_id = r.id \
                               AND (j.status IN ('pending', 'claimed') \
                                    OR NOT EXISTS (SELECT 1 FROM mcp_introspection_jobs n \
                                                   WHERE n.artifact_id = j.artifact_id \
                                                     AND n.kind = j.kind \
                                                     AND n.target_key = j.target_key \
                                                     AND n.created_at > j.created_at))) \
           LIMIT $2) \
         DELETE FROM mcp_capability_snapshots s USING victims v WHERE s.id = v.id"
    );
    let r = sqlx::query(sqlx::AssertSqlSafe(sql))
        .bind(SNAPSHOT_KEEP)
        .bind(SNAPSHOT_PRUNE_BATCH)
        .bind(DRIFT_FINDING_SOURCE)
        .execute(db)
        .await?;
    Ok(r.rows_affected())
}

/// The current snapshot: the freshest successful one ([`FRESHEST_FIRST`],
/// not the last to arrive, #5464) of the source with the best
/// [`Source::precedence`] (or of `source` when given).
pub fn pick_current(rows: &[SnapshotRow], source: Option<Source>) -> Option<&SnapshotRow> {
    let ranks: Vec<SnapshotRank> = rows.iter().map(SnapshotRow::rank).collect();
    let id = pick_current_rank(&ranks, source)?.id;
    rows.iter().find(|r| r.id == id)
}

/// The columns [`pick_current`] ranks a snapshot by, without its lists.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct SnapshotRank {
    pub id: Uuid,
    pub source: String,
    pub outcome: String,
    pub observed_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl SnapshotRank {
    fn freshness_key(&self) -> (DateTime<Utc>, DateTime<Utc>, Uuid) {
        (
            self.last_seen_at.unwrap_or(self.observed_at),
            self.created_at,
            self.id,
        )
    }
}

/// The current one of `ranks` (see [`pick_current`]): the freshest
/// successful one of the source with the best [`Source::precedence`], or of
/// `source` when given. The one ranking both [`pick_current`] and
/// [`is_current_in`] apply.
pub fn pick_current_rank(ranks: &[SnapshotRank], source: Option<Source>) -> Option<&SnapshotRank> {
    ranks
        .iter()
        .filter(|r| r.outcome == Outcome::Ok.as_str())
        .filter(|r| source.is_none_or(|s| r.source == s.as_str()))
        .min_by(|a, b| {
            let rank = |r: &SnapshotRank| {
                Source::parse(&r.source)
                    .map(Source::precedence)
                    .unwrap_or(u8::MAX)
            };
            rank(a)
                .cmp(&rank(b))
                .then(b.freshness_key().cmp(&a.freshness_key()))
        })
}

/// Whether snapshot `id` is the current view of `artifact_id`
/// ([`pick_current`] over the freshest [`HISTORY_WINDOW`]), read on `conn`
/// (the transaction that stored it). Reads only the ranking columns: this
/// runs while the job row is locked.
pub async fn is_current_in(
    conn: &mut sqlx::PgConnection,
    artifact_id: Uuid,
    id: Uuid,
) -> sqlx::Result<bool> {
    let sql = format!(
        "SELECT id, source, outcome, observed_at, last_seen_at, created_at \
         FROM mcp_capability_snapshots WHERE artifact_id = $1 \
         ORDER BY {FRESHEST_FIRST} LIMIT $2"
    );
    let ranks: Vec<SnapshotRank> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(artifact_id)
        .bind(HISTORY_WINDOW)
        .fetch_all(conn)
        .await?;
    Ok(pick_current_rank(&ranks, None).is_some_and(|c| c.id == id))
}

/// The successful snapshot just before `to` in freshness order among `rows`
/// of the same source, for a declaration of the same origin.
pub fn pick_previous<'a>(rows: &'a [SnapshotRow], to: &SnapshotRow) -> Option<&'a SnapshotRow> {
    rows.iter()
        .filter(|r| {
            r.id != to.id
                && r.source == to.source
                && r.outcome == Outcome::Ok.as_str()
                && r.freshness_key() < to.freshness_key()
                && (to.source != Source::PublisherDeclared.as_str() || r.origin == to.origin)
        })
        .max_by_key(|r| r.freshness_key())
}

// ---------------------------------------------------------------------------
// Audit and the drift finding
// ---------------------------------------------------------------------------

fn audit_details(s: &SnapshotRow, repo_key: &str) -> Value {
    json!({
        "repository": repo_key,
        "server": s.server_name,
        "version": s.server_version,
        "snapshot_id": s.id,
        "source": s.source,
        "provenance": s.provenance,
        "origin": s.origin,
        "outcome": s.outcome,
        "auth_state": s.auth_state,
        "content_hash": s.content_hash,
        "tools": arr(&s.tools).len(),
        "resources": arr(&s.resources).len(),
        "prompts": arr(&s.prompts).len(),
    })
}

/// `MCP_CAPABILITIES_INGESTED` for a stored snapshot.
pub fn audit_ingested(db: &PgPool, user_id: Option<Uuid>, s: &SnapshotRow, repo_key: &str) {
    use crate::services::audit_service::{
        audit_fire_and_forget, AuditAction, AuditEntry, ResourceType,
    };
    let mut entry = AuditEntry::new(AuditAction::McpCapabilitiesIngested, ResourceType::Artifact)
        .resource(s.artifact_id)
        .resource_name(format!("{}@{}", s.server_name, s.server_version))
        .with_request_client_ip()
        .details(audit_details(s, repo_key));
    if let Some(u) = user_id {
        entry = entry.user(u);
    }
    tokio::spawn(audit_fire_and_forget(db.clone(), entry));
}

/// The `tool_drift` finding for a changed snapshot.
pub fn drift_finding(
    current: &SnapshotRow,
    previous: &SnapshotRow,
    d: &CapabilityDiff,
) -> crate::models::security::RawFinding {
    use crate::models::security::{FindingClass, RawFinding};
    let source = current.source().unwrap_or(Source::CiReported);
    let short = |h: &str| h.chars().take(12).collect::<String>();
    let title = truncate(
        &format!(
            "tool_drift: {} snapshot of {}@{} changed ({} -> {})",
            source.as_str(),
            current.server_name,
            current.server_version,
            short(&previous.content_hash),
            short(&current.content_hash)
        ),
        500,
    );
    let description = format!(
        "The {} capability list of this server version differs from the previous {} snapshot \
         ({}, {}). {}. Review the diff (GET .../capabilities/diff?from={}&to={}) before relying \
         on this server; the change is not a version bump.",
        source.as_str(),
        source.as_str(),
        previous.id,
        previous.observed_at.to_rfc3339(),
        summary_text(d),
        previous.id,
        current.id
    );
    RawFinding {
        severity: source.drift_severity(),
        title,
        description: Some(description),
        cve_id: None,
        affected_component: Some(truncate(&current.server_name, 255)),
        affected_version: Some(truncate(&current.server_version, 100)),
        fixed_version: None,
        source: Some(DRIFT_FINDING_SOURCE.to_string()),
        source_url: None,
        finding_class: FindingClass::Policy,
    }
}

/// Record `tool_drift` for `ins` when it drifted: an `external` scan result
/// with one finding (so the findings UI, acknowledgement flow and the scan
/// policy gate apply), and `MCP_TOOLS_DRIFT`. Returns the scan id.
pub async fn record_drift_if_any(
    db: &PgPool,
    ins: &Inserted,
    repo_key: &str,
) -> crate::error::Result<Option<Uuid>> {
    use crate::services::audit_service::{
        audit_fire_and_forget, AuditAction, AuditEntry, ResourceType,
    };
    if !ins.drifted() {
        return Ok(None);
    }
    let (current, previous) = (&ins.snapshot, ins.previous.as_ref().expect("drifted"));
    let d = diff(Some(&previous.set()), &current.set());
    let finding = drift_finding(current, previous, &d);
    let counts = crate::api::handlers::security::tally_severities(std::slice::from_ref(&finding));
    let svc = crate::services::scan_result_service::ScanResultService::new(db.clone());
    let scan = svc
        .create_completed_scan_with_findings(
            current.artifact_id,
            current.repository_id,
            crate::api::handlers::security::EXTERNAL_SCAN_TYPE,
            counts,
            Some(DRIFT_SCANNER),
            std::slice::from_ref(&finding),
        )
        .await?;
    if let Err(e) = svc.recalculate_score(current.repository_id).await {
        tracing::warn!(error = %e, "score refresh after tool_drift failed");
    }
    let mut details = audit_details(current, repo_key);
    if let Some(o) = details.as_object_mut() {
        o.insert("previous_snapshot_id".into(), json!(previous.id));
        o.insert("previous_hash".into(), json!(previous.content_hash));
        o.insert("scan_id".into(), json!(scan.id));
        o.insert("severity".into(), json!(finding.severity.as_str()));
        o.insert("summary".into(), json!(summary_text(&d)));
        o.insert("destructive_added".into(), json!(newly_destructive(&d)));
    }
    let entry = AuditEntry::new(AuditAction::McpToolsDrift, ResourceType::Artifact)
        .resource(current.artifact_id)
        .resource_name(format!(
            "{}@{}",
            current.server_name, current.server_version
        ))
        .details(details);
    tokio::spawn(audit_fire_and_forget(db.clone(), entry));
    tracing::warn!(
        artifact_id = %current.artifact_id,
        server = %current.server_name,
        version = %current.server_version,
        source = %current.source,
        "MCP tool drift detected"
    );
    Ok(Some(scan.id))
}

/// Store a snapshot, audit it, and raise `tool_drift` when it changed.
pub async fn store(
    db: &PgPool,
    s: &NewSnapshot,
    repo_key: &str,
) -> crate::error::Result<(Inserted, Option<Uuid>)> {
    let ins = insert_snapshot(db, s)
        .await
        .map_err(|e| crate::error::AppError::Database(e.to_string()))?;
    let drift = record_stored(db, s, &ins, repo_key).await?;
    Ok((ins, drift))
}

/// The side effects of a stored snapshot, run after its transaction
/// committed: audit `MCP_CAPABILITIES_INGESTED`, lint the tools and raise
/// `tool_drift`. Nothing when `ins.created` is false (an idempotent
/// declaration or a deduplicated repeat); only the audit for a superseded
/// snapshot, which is history and never the current view (#5464). Returns
/// the drift scan id.
pub async fn record_stored(
    db: &PgPool,
    s: &NewSnapshot,
    ins: &Inserted,
    repo_key: &str,
) -> crate::error::Result<Option<Uuid>> {
    if ins.created {
        audit_ingested(db, s.reported_by, &ins.snapshot, repo_key);
        if let Some(source) = lint_source(s).filter(|_| !ins.superseded) {
            let findings = crate::services::mcp_lint::lint_capabilities(&s.set);
            crate::services::mcp_lint::record_after_write(db, s.artifact_id, &findings, &source)
                .await;
        }
    }
    record_drift_if_any(db, ins, repo_key).await
}

/// The lint source (`capabilities:<source>`) a stored snapshot's tools are
/// linted under, on the server.json artifact: every successful reported or
/// observed snapshot. A publisher declaration is not linted here: its tools
/// are part of the document, linted under the `server_json` source.
pub fn lint_source(s: &NewSnapshot) -> Option<String> {
    (s.source != Source::PublisherDeclared && s.outcome == Outcome::Ok)
        .then(|| format!("capabilities:{}", s.source.as_str()))
}

/// The server version a snapshot attaches to.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct VersionRef {
    pub artifact_id: Uuid,
    pub repository_id: Uuid,
    pub repository_key: String,
    pub name: String,
    pub version: String,
    pub metadata: Value,
}

/// The server version `artifact_id` with its repository, through any
/// executor: a pool, or the transaction that holds a job's claim locked, so a
/// completion reads it on its one connection (#5460).
pub async fn version_ref(
    db: impl sqlx::PgExecutor<'_>,
    artifact_id: Uuid,
) -> sqlx::Result<Option<VersionRef>> {
    sqlx::query_as(
        "SELECT a.id AS artifact_id, a.repository_id, r.key AS repository_key, a.name, a.version, \
                m.metadata \
         FROM artifacts a \
         JOIN artifact_metadata m ON m.artifact_id = a.id AND m.format = 'mcp' \
         JOIN repositories r ON r.id = a.repository_id \
         WHERE a.id = $1 AND a.is_deleted = false",
    )
    .bind(artifact_id)
    .fetch_optional(db)
    .await
}

/// Build and store the declared snapshots of a server version from its
/// stored metadata (`_meta["com.artifactkeeper/capabilities"]` and every
/// MCPB manifest in `metadata.bundles[]`). Idempotent: a declaration already
/// recorded is not stored again. Called after a hosted publish, and meant to
/// be called by the Remote ingest and the MCPB bundle upload. Returns the ids
/// of the snapshots (new or existing).
pub async fn record_declared_snapshot(
    db: &PgPool,
    artifact_id: Uuid,
) -> crate::error::Result<Vec<Uuid>> {
    let Some(v) = version_ref(db, artifact_id)
        .await
        .map_err(|e| crate::error::AppError::Database(e.to_string()))?
    else {
        return Ok(Vec::new());
    };
    let mut ids = Vec::new();
    for d in declared_from_metadata(&v.metadata) {
        let snap = NewSnapshot {
            repository_id: v.repository_id,
            artifact_id,
            server_name: v.name.clone(),
            server_version: v.version.clone(),
            source: Source::PublisherDeclared,
            provenance: d.provenance,
            origin: Some(d.origin),
            reported_by: None,
            auth_state: AuthState::Unknown,
            outcome: Outcome::Ok,
            protocol_version: d.protocol_version,
            observed_at: Utc::now(),
            ttl_ms: None,
            cache_scope: None,
            set: d.set,
            worker_version: None,
            details: d.details,
        };
        let (ins, _) = store(db, &snap, &v.repository_key).await?;
        ids.push(ins.snapshot.id);
    }
    Ok(ids)
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    fn tool(name: &str, desc: &str) -> Value {
        json!({"name": name, "description": desc, "inputSchema": {"type": "object"}})
    }

    #[test]
    fn vocabulary_round_trips() {
        for s in Source::ALL {
            assert_eq!(Source::parse(s.as_str()), Some(*s));
            assert!(!s.default_provenance().is_empty());
        }
        for a in AuthState::ALL {
            assert_eq!(AuthState::parse(a.as_str()), Some(*a));
        }
        for o in Outcome::ALL {
            assert_eq!(Outcome::parse(o.as_str()), Some(*o));
        }
        assert_eq!(Source::parse("bogus"), None);
        assert!(Source::RemoteProbe.is_observed() && Source::SandboxRun.is_observed());
        assert!(!Source::CiReported.is_observed());
        assert!(Source::CiReported.is_reportable() && Source::GatewayReported.is_reportable());
        assert!(!Source::RemoteProbe.is_reportable() && !Source::PublisherDeclared.is_reportable());
        use crate::models::security::Severity;
        assert_eq!(Source::RemoteProbe.drift_severity(), Severity::High);
        assert_eq!(Source::CiReported.drift_severity(), Severity::Medium);
        assert_eq!(Source::PublisherDeclared.drift_severity(), Severity::Low);
    }

    /// #5388: hidden characters in identifiers are refused (as at publish);
    /// in free text they are accepted here and left to the lint.
    #[test]
    fn from_doc_refuses_hidden_chars_in_identifiers_only() {
        let bad = [
            (
                json!({"tools": [{"name": "read\u{200B}file"}]}),
                "tools[0].name",
            ),
            (
                json!({"prompts": [{"name": "p\u{202E}"}]}),
                "prompts[0].name",
            ),
            (
                json!({"resources": [{"uri": "file:///x\u{2066}"}]}),
                "resources[0].uri",
            ),
            (
                json!({"resources": [{"uri": "file:///x", "name": "doc\u{FEFF}"}]}),
                "resources[0].name",
            ),
            (
                json!({"prompts": [{"name": "p", "arguments": [{"name": "a"}, {"name": "b\u{E0041}"}]}]}),
                "prompts[0].arguments[1].name",
            ),
        ];
        for (doc, path) in bad {
            let e = CapabilitySet::from_doc(&doc).unwrap_err();
            assert_eq!(e.path, path, "{doc}");
            assert!(e.message.contains("zero-width"), "{e}");
        }
        let text = CapabilitySet::from_doc(&json!({
            "resources": [{"uri": "file:///x", "description": "a\u{202E}b"}],
            "prompts": [{"name": "p", "arguments": [{"name": "a", "description": "z\u{200B}w"}]}],
            "instructions": "hi\u{200D}",
        }));
        assert!(text.is_ok(), "{text:?}");
    }

    #[test]
    fn from_doc_validates_shape() {
        let ok = CapabilitySet::from_doc(&json!({
            "tools": [tool("a", "x")], "resources": [{"uri": "file:///x"}],
            "prompts": [{"name": "p"}], "instructions": "use it",
        }))
        .unwrap();
        assert_eq!(ok.tools.len(), 1);
        assert_eq!(ok.instructions.as_deref(), Some("use it"));
        assert_eq!(
            CapabilitySet::from_doc(&json!({})).unwrap(),
            CapabilitySet::default()
        );
        let bad = [
            (json!([]), ""),
            (json!({"tools": {}}), "tools"),
            (json!({"tools": [1]}), "tools[0]"),
            (json!({"tools": [{"description": "x"}]}), "tools[0].name"),
            (json!({"tools": [{"name": ""}]}), "tools[0].name"),
            (
                json!({"tools": [tool("a", ""), tool("a", "")]}),
                "tools[1].name",
            ),
            (json!({"resources": [{"name": "x"}]}), "resources[0].uri"),
            (json!({"instructions": 3}), "instructions"),
            (
                json!({"instructions": "x".repeat(MAX_INSTRUCTIONS_LEN + 1)}),
                "instructions",
            ),
            (
                json!({"tools": [{"name": "n".repeat(MAX_NAME_LEN + 1)}]}),
                "tools[0].name",
            ),
        ];
        for (doc, path) in bad {
            let e = CapabilitySet::from_doc(&doc).unwrap_err();
            assert_eq!(e.path, path, "{doc}");
            assert!(!e.to_string().is_empty());
        }
        let many: Vec<Value> = (0..=MAX_ITEMS)
            .map(|i| tool(&format!("t{i}"), ""))
            .collect();
        assert_eq!(
            CapabilitySet::from_doc(&json!({"tools": many}))
                .unwrap_err()
                .path,
            "tools"
        );
    }

    #[test]
    fn hash_ignores_order_and_unhashed_members() {
        let a =
            CapabilitySet::from_doc(&json!({"tools": [tool("a", "1"), tool("b", "2")]})).unwrap();
        let mut b_tools = vec![tool("b", "2"), tool("a", "1")];
        b_tools[0]["_meta"] = json!({"x": 1});
        let b = CapabilitySet::from_doc(&json!({"tools": b_tools})).unwrap();
        assert_eq!(a.content_hash(), b.content_hash());
        assert_eq!(a.tools_hash(), b.tools_hash());
        let c =
            CapabilitySet::from_doc(&json!({"tools": [tool("a", "1"), tool("b", "3")]})).unwrap();
        assert_ne!(a.content_hash(), c.content_hash());
        let mut d = a.clone();
        d.instructions = Some("new".into());
        assert_ne!(a.content_hash(), d.content_hash());
        assert_eq!(a.tools_hash(), d.tools_hash());
        assert_eq!(a.content_hash().len(), 64);
    }

    #[test]
    fn diff_reports_added_removed_changed() {
        let from = CapabilitySet::from_doc(&json!({
            "tools": [tool("keep", "same"), tool("gone", "x"), tool("edit", "old")],
            "prompts": [{"name": "p"}],
        }))
        .unwrap();
        let mut destructive = tool("delete_repo", "deletes");
        destructive["annotations"] = json!({"destructiveHint": true});
        let mut edited = tool("edit", "new");
        edited["annotations"] = json!({"destructiveHint": true});
        let to = CapabilitySet::from_doc(&json!({
            "tools": [tool("keep", "same"), edited, destructive],
            "prompts": [{"name": "p"}],
            "instructions": "now",
        }))
        .unwrap();
        let d = diff(Some(&from), &to);
        assert_eq!(d.tools.added.len(), 1);
        assert_eq!(d.tools.removed.len(), 1);
        assert_eq!(d.tools.changed.len(), 1);
        assert_eq!(
            d.tools.changed[0].fields,
            vec!["description", "annotations"]
        );
        assert_eq!(d.tools.unchanged, 1);
        assert!(d.prompts.is_empty() && d.resources.is_empty());
        assert!(d.instructions_changed);
        assert_eq!(newly_destructive(&d), vec!["delete_repo", "edit"]);
        let text = summary_text(&d);
        assert!(
            text.starts_with("Tools: +1 added, -1 removed, 1 changed"),
            "{text}"
        );
        assert!(text.contains("`delete_repo` now destructiveHint: true"));
        assert!(text.ends_with("Instructions changed"));
        let j = diff_json(&d);
        assert_eq!(j["summary"]["tools"]["added"], 1);
        assert_eq!(j["tools"]["changed"][0]["key"], "edit");
        assert_eq!(j["summary"]["identical"], false);
        // Nothing before: everything is added.
        let d0 = diff(None, &to);
        assert_eq!(d0.tools.added.len(), 3);
        assert_eq!(summary_text(&diff(Some(&to), &to)), "No changes");
        assert!(diff(Some(&to), &to).is_empty());
    }

    #[test]
    fn declared_block_locations() {
        let caps = json!({"tools": [tool("a", "x")]});
        let top = json!({"_meta": {CAPABILITIES_META_KEY: caps}});
        let nested = json!({"_meta": {PUBLISHER_META_KEY: {CAPABILITIES_META_KEY: caps}}});
        assert_eq!(declared_block(&top), Some(&caps));
        assert_eq!(declared_block(&nested), Some(&caps));
        assert_eq!(declared_block(&json!({})), None);
        assert!(validate_declared_block(&caps).is_ok());
        let e = validate_declared_block(&json!({"tools": [{}]})).unwrap_err();
        assert_eq!(
            e.path,
            format!("_meta.{CAPABILITIES_META_KEY}.tools[0].name")
        );
        let e = validate_declared_block(&json!([])).unwrap_err();
        assert_eq!(e.path, format!("_meta.{CAPABILITIES_META_KEY}"));
        let big = json!({"instructions": "x".repeat(DECLARED_MAX_BYTES)});
        assert!(validate_declared_block(&big)
            .unwrap_err()
            .message
            .contains("bytes"));
    }

    #[test]
    fn declared_from_metadata_reads_server_and_bundles() {
        let meta = json!({
            "server": {"_meta": {CAPABILITIES_META_KEY: {
                "tools": [tool("a", "x")], "protocolVersion": "2026-07-28", "generatedBy": "ci"
            }}},
            "bundles": [
                {"artifactId": "b1", "fileSha256": "ab", "signature": {"state": "valid"},
                 "manifest": {"tools": [{"name": "t", "description": "d", "extra": 1},
                                        {"name": "t"}, {"nope": 1}],
                              "prompts": [{"name": "p", "text": "x", "arguments": []}]}},
                {"artifactId": "b2", "manifest": {"tools_generated": true}},
                {"artifactId": "b3", "manifest": {"name": "empty"}},
                {"artifactId": "b4"},
            ],
        });
        let d = declared_from_metadata(&meta);
        assert_eq!(d.len(), 3);
        assert_eq!(d[0].origin, "server.json");
        assert_eq!(d[0].protocol_version.as_deref(), Some("2026-07-28"));
        assert_eq!(d[0].details["generatedBy"], "ci");
        assert_eq!(d[1].origin, "mcpb:ab");
        assert_eq!(
            d[1].set.tools,
            vec![json!({"name": "t", "description": "d"})]
        );
        assert_eq!(
            d[1].set.prompts,
            vec![json!({"name": "p", "arguments": []})]
        );
        assert_eq!(d[1].details["signature"], "valid");
        assert_eq!(d[2].origin, "mcpb:b2");
        assert_eq!(d[2].details["toolsGenerated"], true);
        // Unreadable server block: skipped, bundles still read.
        let meta = json!({"server": {"_meta": {CAPABILITIES_META_KEY: []}}});
        assert!(declared_from_metadata(&meta).is_empty());
    }

    fn row(source: Source, created: i64, outcome: Outcome, origin: Option<&str>) -> SnapshotRow {
        let t = DateTime::from_timestamp(created, 0).unwrap();
        SnapshotRow {
            id: Uuid::new_v4(),
            repository_id: Uuid::nil(),
            artifact_id: Uuid::nil(),
            server_name: "com.acme/x".into(),
            server_version: "1.0.0".into(),
            source: source.as_str().into(),
            provenance: "p".into(),
            origin: origin.map(String::from),
            reported_by: None,
            auth_state: "none".into(),
            outcome: outcome.as_str().into(),
            protocol_version: None,
            observed_at: t,
            ttl_ms: None,
            cache_scope: None,
            tools: json!([tool("a", "x")]),
            resources: json!([]),
            prompts: json!([]),
            instructions: None,
            tools_hash: "t".into(),
            content_hash: format!("h{created}"),
            worker_version: None,
            details: json!({}),
            created_at: t,
            last_seen_at: None,
        }
    }

    #[test]
    fn current_and_previous_selection() {
        let rows = vec![
            row(Source::RemoteProbe, 50, Outcome::AuthRequired, None),
            row(Source::CiReported, 40, Outcome::Ok, None),
            row(Source::RemoteProbe, 30, Outcome::Ok, None),
            row(
                Source::PublisherDeclared,
                20,
                Outcome::Ok,
                Some("server.json"),
            ),
            row(Source::PublisherDeclared, 15, Outcome::Ok, Some("mcpb:x")),
            row(Source::RemoteProbe, 10, Outcome::Ok, None),
        ];
        let cur = pick_current(&rows, None).unwrap();
        assert_eq!(
            cur.id, rows[2].id,
            "observations win, failures never current"
        );
        assert_eq!(
            pick_current(&rows, Some(Source::PublisherDeclared))
                .unwrap()
                .id,
            rows[3].id
        );
        assert!(pick_current(&rows, Some(Source::SandboxRun)).is_none());
        assert_eq!(pick_previous(&rows, cur).unwrap().id, rows[5].id);
        assert!(
            pick_previous(&rows, &rows[3]).is_none(),
            "other origin is not previous"
        );
        // #5464: freshness, not arrival, picks the current one: a probe that
        // arrived last but was observed first is history, unless its content
        // was seen again since (`last_seen_at`).
        let mut late = row(Source::RemoteProbe, 60, Outcome::Ok, None);
        late.observed_at = DateTime::from_timestamp(5, 0).unwrap();
        let mut rows = rows;
        rows.insert(0, late.clone());
        assert_eq!(pick_current(&rows, None).unwrap().id, rows[3].id);
        assert_eq!(pick_previous(&rows, &rows[3]).unwrap().id, rows[6].id);
        assert_eq!(
            pick_previous(&rows, &rows[6]).unwrap().id,
            late.id,
            "the late arrival is the oldest observation"
        );
        rows[0].last_seen_at = DateTime::from_timestamp(35, 0);
        assert_eq!(pick_current(&rows, None).unwrap().id, late.id);
        // The ranking-columns path picks the same row.
        let ranks: Vec<SnapshotRank> = rows.iter().map(SnapshotRow::rank).collect();
        for source in [
            None,
            Some(Source::RemoteProbe),
            Some(Source::PublisherDeclared),
        ] {
            assert_eq!(
                pick_current_rank(&ranks, source).map(|r| r.id),
                pick_current(&rows, source).map(|r| r.id),
                "{source:?}"
            );
        }
        let rows = &rows[1..];
        let j = rows[2].to_json();
        assert_eq!(j["observed"], true);
        assert_eq!(j["counts"]["tools"], 1);
        assert_eq!(j["tools"][0]["name"], "a");
        assert_eq!(rows[2].set().tools.len(), 1);
    }

    #[test]
    fn drift_finding_and_inserted_semantics() {
        let prev = row(Source::RemoteProbe, 10, Outcome::Ok, None);
        let cur = row(Source::RemoteProbe, 20, Outcome::Ok, None);
        let ins = Inserted {
            snapshot: cur.clone(),
            previous: Some(prev.clone()),
            created: true,
            superseded: false,
        };
        assert!(ins.drifted());
        let same = Inserted {
            snapshot: cur.clone(),
            previous: Some(SnapshotRow {
                content_hash: cur.content_hash.clone(),
                ..prev.clone()
            }),
            created: true,
            superseded: false,
        };
        assert!(!same.drifted());
        let failed = Inserted {
            snapshot: row(Source::RemoteProbe, 30, Outcome::Timeout, None),
            previous: Some(prev.clone()),
            created: true,
            superseded: false,
        };
        assert!(!failed.drifted());
        // #5464: a snapshot stored as history behind a fresher one is no
        // drift from it.
        let stale = Inserted {
            superseded: true,
            ..ins.clone()
        };
        assert!(!stale.drifted());
        let f = drift_finding(&cur, &prev, &diff(Some(&prev.set()), &cur.set()));
        assert!(f
            .title
            .starts_with("tool_drift: remote_probe snapshot of com.acme/x@1.0.0"));
        assert_eq!(f.severity, crate::models::security::Severity::High);
        assert_eq!(f.source.as_deref(), Some(DRIFT_FINDING_SOURCE));
        assert!(f.description.unwrap().contains(&prev.id.to_string()));
        assert_eq!(truncate("héllo", 2), "h");
        assert_eq!(truncate("abc", 5), "abc");
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod db_tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;

    async fn seed_version(fx: &tdh::Fixture, metadata: Value) -> Uuid {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
               checksum_sha256, content_type, storage_key) \
             VALUES ($1, $2, 'com.acme/x', '1.0.0', 2, $3, 'application/json', $2) RETURNING id",
        )
        .bind(fx.repo_id)
        .bind(format!("com.acme/x/{}.json", Uuid::new_v4()))
        .bind("a".repeat(64))
        .fetch_one(&fx.pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO artifact_metadata (artifact_id, format, metadata) VALUES ($1, 'mcp', $2)",
        )
        .bind(id)
        .bind(metadata)
        .execute(&fx.pool)
        .await
        .unwrap();
        id
    }

    fn snap(fx: &tdh::Fixture, artifact_id: Uuid, tools: Value) -> NewSnapshot {
        NewSnapshot {
            repository_id: fx.repo_id,
            artifact_id,
            server_name: "com.acme/x".into(),
            server_version: "1.0.0".into(),
            source: Source::RemoteProbe,
            provenance: Source::RemoteProbe.default_provenance().into(),
            origin: Some("remote:0".into()),
            reported_by: None,
            auth_state: AuthState::None,
            outcome: Outcome::Ok,
            protocol_version: Some("2026-07-28".into()),
            observed_at: Utc::now(),
            ttl_ms: Some(1000),
            cache_scope: Some("public".into()),
            set: CapabilitySet::from_doc(&json!({ "tools": tools })).unwrap(),
            worker_version: Some("test".into()),
            details: json!({}),
        }
    }

    #[tokio::test]
    async fn declared_snapshots_are_idempotent_and_drift_raises_a_finding() {
        let Some(fx) = tdh::Fixture::setup("local", "mcp").await else {
            return;
        };
        let meta = json!({
            "server": {"_meta": {CAPABILITIES_META_KEY: {"tools": [{"name": "a"}]}}},
            "bundles": [{"fileSha256": "ff", "manifest": {"tools": [{"name": "b"}]}}],
        });
        let id = seed_version(&fx, meta).await;
        let first = record_declared_snapshot(&fx.pool, id).await.unwrap();
        assert_eq!(first.len(), 2);
        let again = record_declared_snapshot(&fx.pool, id).await.unwrap();
        assert_eq!(
            first, again,
            "re-recording a declaration stores nothing new"
        );
        assert!(record_declared_snapshot(&fx.pool, Uuid::new_v4())
            .await
            .unwrap()
            .is_empty());

        let (a, d0) = store(
            &fx.pool,
            &snap(&fx, id, json!([{"name": "a"}])),
            &fx.repo_key,
        )
        .await
        .unwrap();
        assert!(a.previous.is_none() && d0.is_none());
        let (same, d1) = store(
            &fx.pool,
            &snap(&fx, id, json!([{"name": "a"}])),
            &fx.repo_key,
        )
        .await
        .unwrap();
        // A repeat of the newest probe is deduplicated (#5386): the same row
        // comes back with only `last_seen_at` bumped, nothing is stored and
        // no drift is recorded.
        assert!(
            !same.created && same.snapshot.id == a.snapshot.id && d1.is_none(),
            "same content: deduplicated, no drift"
        );
        assert!(same.snapshot.last_seen_at.is_some(), "last_seen_at bumped");
        let (b, d2) = store(
            &fx.pool,
            &snap(
                &fx,
                id,
                json!([{"name": "a"}, {"name": "rm", "annotations": {"destructiveHint": true}}]),
            ),
            &fx.repo_key,
        )
        .await
        .unwrap();
        let scan_id = d2.expect("drift recorded");
        assert_eq!(b.previous.unwrap().id, same.snapshot.id);
        let (title, severity, class): (String, String, String) = sqlx::query_as(
            "SELECT title, severity, finding_class FROM scan_findings WHERE scan_result_id = $1",
        )
        .bind(scan_id)
        .fetch_one(&fx.pool)
        .await
        .unwrap();
        assert!(title.starts_with("tool_drift: remote_probe"), "{title}");
        assert_eq!(severity, "high");
        assert_eq!(class, "policy");

        // Two declarations and two stored probes: the repeat was not stored.
        let all = list_snapshots(&fx.pool, id, None, 50).await.unwrap();
        assert_eq!(all.len(), 4);
        let probes = list_snapshots(&fx.pool, id, Some(Source::RemoteProbe), 50)
            .await
            .unwrap();
        assert_eq!(probes.len(), 2);
        assert_eq!(pick_current(&all, None).unwrap().id, b.snapshot.id);
        let got = get_snapshot(&fx.pool, b.snapshot.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.content_hash, b.snapshot.content_hash);
        let v = version_ref(&fx.pool, id).await.unwrap().unwrap();
        assert_eq!(v.repository_key, fx.repo_key);

        let _ = sqlx::query("DELETE FROM artifacts WHERE id = $1")
            .bind(id)
            .execute(&fx.pool)
            .await;
        fx.teardown().await;
    }
}
