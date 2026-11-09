//! The MCP client side of a probe: `server/discover` (2026-07-28) with a
//! legacy `initialize` fallback, then `tools/list`, `resources/list` and
//! `prompts/list`. Transport-agnostic (streamable HTTP or stdio).
//!
//! Hard rules, enforced here rather than by the callers:
//!
//! * only the methods in [`ALLOWED_METHODS`] are ever sent: never
//!   `tools/call`, `resources/read` or `prompts/get`;
//! * every list is paginated with a page and item cap;
//! * whatever the server returns is untrusted: items without a usable key
//!   are dropped, duplicates are dropped, and nothing is interpreted;
//! * every response is correlated with the one outstanding request: a
//!   response whose `id` is missing or differs (in type or value), a second
//!   response to an answered request, or a batch (this client never sends
//!   one) is a [`Violation`] that fails the probe with nothing accepted.

use async_trait::async_trait;
use serde_json::{json, Map, Value};

/// The modern protocol revision this client speaks.
pub const MODERN_VERSION: &str = "2026-07-28";
/// Legacy (`initialize`-based) revisions, preferred first.
pub const LEGACY_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
/// Everything this client may send.
pub const ALLOWED_METHODS: &[&str] = &[
    "server/discover",
    "initialize",
    "notifications/initialized",
    "tools/list",
    "resources/list",
    "prompts/list",
];
pub const CLIENT_NAME: &str = "ak-mcp-introspector";
/// JSON-RPC error code of `UnsupportedProtocolVersionError`.
pub const UNSUPPORTED_VERSION: i64 = -32022;
pub const METHOD_NOT_FOUND: i64 = -32601;
/// Modern protocol error codes (a 4xx carrying one of these is a modern server).
pub const MODERN_ERRORS: &[i64] = &[UNSUPPORTED_VERSION, -32020, -32021, METHOD_NOT_FOUND];
pub const MAX_PAGES: usize = 50;

/// What a transport delivered for one message.
#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    /// A JSON-RPC response (or, for a notification, `Null`).
    Message(Value),
    /// A non-2xx HTTP answer (HTTP only).
    Status {
        status: u16,
        body: Option<Value>,
        retry_after_ms: Option<i64>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    Timeout,
    TooLarge,
    Redirect,
    Closed,
    Io(String),
    /// The server broke the protocol's response or session integrity.
    Protocol(Violation),
}

/// A protocol-integrity failure (#5450, #5451). Not transient: the probe
/// ends `refused` with `details.protocolViolation` set to [`Violation::code`],
/// and nothing the server sent in that probe is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    /// A response whose `id` is absent, `null`, or not the outstanding
    /// request's (`1` and `"1"` differ).
    ResponseIdMismatch,
    /// A second response to a request that was already answered.
    DuplicateResponse,
    /// A JSON-RPC batch, although this client never sends one.
    UnexpectedBatch,
    /// A response carried an `Mcp-Session-Id` other than the one
    /// `initialize` established.
    SessionIdChanged,
    /// `initialize` assigned an `Mcp-Session-Id` that is not 1-256 visible
    /// ASCII characters.
    SessionIdInvalid,
}

impl Violation {
    pub fn code(self) -> &'static str {
        match self {
            Violation::ResponseIdMismatch => "response_id_mismatch",
            Violation::DuplicateResponse => "duplicate_response",
            Violation::UnexpectedBatch => "unexpected_batch",
            Violation::SessionIdChanged => "session_id_changed",
            Violation::SessionIdInvalid => "session_id_invalid",
        }
    }
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Timeout => write!(f, "timed out"),
            TransportError::TooLarge => write!(f, "response over the size cap"),
            TransportError::Redirect => write!(f, "redirect refused"),
            TransportError::Closed => write!(f, "server closed the connection"),
            TransportError::Io(e) => write!(f, "{e}"),
            TransportError::Protocol(v) => write!(f, "protocol violation: {}", v.code()),
        }
    }
}

/// One way of talking to a server.
#[async_trait]
pub trait Transport: Send {
    /// Send `msg` (method `method`). `protocol_version` is the version this
    /// message speaks (HTTP mirrors it into `MCP-Protocol-Version`). For a
    /// notification (`id` absent) the reply is `Message(Null)`.
    async fn send(
        &mut self,
        method: &str,
        protocol_version: Option<&str>,
        msg: Value,
    ) -> Result<Reply, TransportError>;
}

/// The result of a probe, in the backend's worker-result vocabulary.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProbeReport {
    pub outcome: String,
    pub auth_state: String,
    pub protocol_version: Option<String>,
    pub ttl_ms: Option<i64>,
    pub cache_scope: Option<String>,
    pub tools: Vec<Value>,
    pub resources: Vec<Value>,
    pub prompts: Vec<Value>,
    pub instructions: Option<String>,
    pub retry_after_ms: Option<i64>,
    pub error: Option<String>,
    pub details: Map<String, Value>,
}

impl ProbeReport {
    fn failed(outcome: &str, error: impl Into<String>) -> Self {
        Self {
            outcome: outcome.into(),
            auth_state: if outcome == "auth_required" {
                "auth_required".into()
            } else {
                "none".into()
            },
            error: Some(error.into()),
            ..Default::default()
        }
    }

    /// The `complete` body (without the claim token).
    pub fn to_result_json(&self) -> Value {
        let ok = self.outcome == "ok";
        json!({
            "outcome": self.outcome,
            "authState": self.auth_state,
            "protocolVersion": self.protocol_version,
            "ttlMs": self.ttl_ms,
            "cacheScope": self.cache_scope,
            "tools": if ok { json!(self.tools) } else { Value::Null },
            "resources": if ok { json!(self.resources) } else { Value::Null },
            "prompts": if ok { json!(self.prompts) } else { Value::Null },
            "instructions": if ok { json!(self.instructions) } else { Value::Null },
            "retryAfterMs": self.retry_after_ms,
            "error": self.error,
            "details": self.details,
        })
    }
}

/// What a single request came back as.
#[derive(Debug, Clone, PartialEq)]
enum Rpc {
    Result(Value),
    Error {
        code: i64,
        data: Option<Value>,
    },
    Http {
        status: u16,
        modern: bool,
        retry_after_ms: Option<i64>,
    },
}

/// Classify a JSON-RPC error body (`{"error": {"code", "data"}}`).
fn rpc_error(body: &Value) -> Option<(i64, Option<Value>)> {
    let e = body.get("error")?;
    Some((e.get("code")?.as_i64()?, e.get("data").cloned()))
}

/// The `_meta` every modern request carries.
pub fn modern_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": MODERN_VERSION,
        "io.modelcontextprotocol/clientInfo": {
            "name": CLIENT_NAME,
            "version": artifact_keeper_backend::build_info::VERSION,
        },
        "io.modelcontextprotocol/clientCapabilities": {},
    })
}

/// The best legacy version both sides speak, from a server's list.
pub fn pick_legacy(supported: &[String]) -> Option<&'static str> {
    LEGACY_VERSIONS
        .iter()
        .find(|v| supported.iter().any(|s| s == *v))
        .copied()
}

fn strings(v: Option<&Value>) -> Vec<String> {
    v.and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// The longest key the backend stores: a resource `uri`, else a `name`.
fn key_limit(key: &str) -> usize {
    use artifact_keeper_backend::services::mcp_capabilities::{MAX_NAME_LEN, MAX_URI_LEN};
    if key == "uri" {
        MAX_URI_LEN
    } else {
        MAX_NAME_LEN
    }
}

/// Keep the usable items of one list page: objects with a non-empty string
/// key no longer than the backend stores, first occurrence of a key wins,
/// at most `cap` in total.
pub fn accept_items(
    out: &mut Vec<Value>,
    page: &[Value],
    key: &str,
    cap: usize,
    dropped: &mut usize,
) {
    for item in page {
        let usable = item
            .get(key)
            .and_then(|k| k.as_str())
            .is_some_and(|k| !k.is_empty() && k.len() <= key_limit(key));
        let dup = usable && out.iter().any(|o| o.get(key) == item.get(key));
        if !usable || dup || out.len() >= cap {
            *dropped += 1;
            continue;
        }
        out.push(item.clone());
    }
}

/// The JSON-RPC client over a transport.
pub struct Client<'t> {
    transport: &'t mut dyn Transport,
    next_id: i64,
    /// The ids of the requests already answered.
    answered: Vec<Value>,
    pub max_items: usize,
}

/// Whether `m` is a JSON-RPC response (as opposed to a request or a
/// notification).
pub fn is_response(m: &Value) -> bool {
    m.get("result").is_some() || m.get("error").is_some()
}

/// Whether `m` is a batch that carries a response: this client never sends
/// a batch, so nothing can answer one. A batch of only notifications or
/// server requests answers nothing and is not a violation.
pub fn is_response_batch(m: &Value) -> bool {
    m.as_array().is_some_and(|a| a.iter().any(is_response))
}

/// Check that `m`, delivered for the request `id`, is that request's
/// response: one object (never a batch) whose `id` is exactly `id`. A
/// response to an earlier, answered request is a duplicate.
fn correlate(m: &Value, id: &Value, answered: &[Value]) -> Result<(), Violation> {
    if is_response_batch(m) {
        return Err(Violation::UnexpectedBatch);
    }
    match m.get("id") {
        Some(got) if got == id => Ok(()),
        Some(got) if answered.contains(got) => Err(Violation::DuplicateResponse),
        _ => Err(Violation::ResponseIdMismatch),
    }
}

impl<'t> Client<'t> {
    pub fn new(transport: &'t mut dyn Transport, max_items: usize) -> Self {
        Self {
            transport,
            next_id: 1,
            answered: Vec::new(),
            max_items,
        }
    }

    async fn request(
        &mut self,
        method: &str,
        version: Option<&str>,
        params: Value,
    ) -> Result<Rpc, TransportError> {
        assert!(
            ALLOWED_METHODS.contains(&method),
            "the introspector never sends {method}"
        );
        let id = self.next_id;
        self.next_id += 1;
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        match self.transport.send(method, version, msg).await? {
            Reply::Message(m) => {
                if m.is_array() && !is_response_batch(&m) {
                    // Notifications or requests only: no answer at all.
                    return Err(TransportError::Io("malformed JSON-RPC response".into()));
                }
                let id = json!(id);
                correlate(&m, &id, &self.answered).map_err(TransportError::Protocol)?;
                self.answered.push(id);
                if let Some(r) = m.get("result") {
                    Ok(Rpc::Result(r.clone()))
                } else if let Some((code, data)) = rpc_error(&m) {
                    Ok(Rpc::Error { code, data })
                } else {
                    Err(TransportError::Io("malformed JSON-RPC response".into()))
                }
            }
            Reply::Status {
                status,
                body,
                retry_after_ms,
            } => {
                let modern = body
                    .as_ref()
                    .and_then(rpc_error)
                    .is_some_and(|(c, _)| MODERN_ERRORS.contains(&c));
                if modern && status != 401 && status != 403 && status != 429 {
                    // The body is consumed as this request's JSON-RPC error
                    // (its code and `data` steer the fallback), so it must
                    // not name another request. `"id": null` (or none) is
                    // what an error raised before the request was read
                    // carries, and is tolerated.
                    if let Some(got) = body
                        .as_ref()
                        .and_then(|b| b.get("id"))
                        .filter(|g| !g.is_null())
                    {
                        correlate(&json!({ "id": got }), &json!(id), &self.answered)
                            .map_err(TransportError::Protocol)?;
                    }
                    let (code, data) = body.as_ref().and_then(rpc_error).unwrap_or((0, None));
                    return Ok(Rpc::Error { code, data });
                }
                // Otherwise only the HTTP status is used, and the body's id
                // is not looked at: an HTTP-level error carries nothing the
                // probe accepts. (The MCP Python SDK v1.x answers these with
                // `"id": "server-error"`, e.g. a pre-initialize request's
                // 400 "Missing session ID".)
                Ok(Rpc::Http {
                    status,
                    modern,
                    retry_after_ms,
                })
            }
        }
    }

    async fn notify(&mut self, method: &str, version: Option<&str>) -> Result<(), TransportError> {
        assert!(ALLOWED_METHODS.contains(&method));
        let msg = json!({"jsonrpc": "2.0", "method": method});
        self.transport.send(method, version, msg).await.map(|_| ())
    }
}

/// How the server's era was determined.
#[derive(Debug, Clone, PartialEq)]
enum Era {
    Modern { capabilities: Value },
    Legacy { version: &'static str },
}

fn http_failure(status: u16, retry_after_ms: Option<i64>) -> Option<ProbeReport> {
    match status {
        401 | 403 => Some(ProbeReport::failed(
            "auth_required",
            format!("server answered {status}: not observable without credentials"),
        )),
        429 => Some(ProbeReport {
            retry_after_ms,
            ..ProbeReport::failed("rate_limited", "server answered 429")
        }),
        s if s >= 500 => Some(ProbeReport::failed("error", format!("server answered {s}"))),
        _ => None,
    }
}

fn transport_failure(e: &TransportError) -> ProbeReport {
    match e {
        TransportError::Timeout => ProbeReport::failed("timeout", e.to_string()),
        TransportError::Redirect => ProbeReport::failed("refused", e.to_string()),
        TransportError::TooLarge => ProbeReport::failed("refused", e.to_string()),
        TransportError::Closed => ProbeReport::failed("start_failed", e.to_string()),
        TransportError::Io(_) => ProbeReport::failed("error", e.to_string()),
        TransportError::Protocol(v) => {
            let mut r = ProbeReport::failed("refused", e.to_string());
            r.details
                .insert("protocolViolation".into(), json!(v.code()));
            r
        }
    }
}

/// Probe a server: discover its era, then list everything it advertises.
pub async fn probe(transport: &mut dyn Transport, max_items: usize) -> ProbeReport {
    let mut c = Client::new(transport, max_items);
    let mut report = ProbeReport {
        outcome: "ok".into(),
        auth_state: "none".into(),
        ..Default::default()
    };
    let era = match discover(&mut c, &mut report).await {
        Ok(e) => e,
        Err(failure) => return *failure,
    };
    let (version, caps_obj, meta) = match &era {
        Era::Modern { capabilities } => (MODERN_VERSION, capabilities.clone(), Some(modern_meta())),
        Era::Legacy { version } => match initialize(&mut c, version, &mut report).await {
            Ok((caps, negotiated)) => (negotiated, caps, None),
            Err(failure) => return *failure,
        },
    };
    report.protocol_version = Some(version.to_string());
    report.details.insert(
        "era".into(),
        json!(if meta.is_some() { "modern" } else { "legacy" }),
    );
    report
        .details
        .insert("capabilities".into(), caps_obj.clone());
    let mut dropped = 0usize;
    for (kind, method, key) in [
        ("tools", "tools/list", "name"),
        ("resources", "resources/list", "uri"),
        ("prompts", "prompts/list", "name"),
    ] {
        // A capability the server does not advertise is not asked for. A
        // modern server that did not answer discover is asked for tools.
        let advertised = caps_obj.get(kind).is_some()
            || (kind == "tools" && caps_obj.as_object().is_none_or(|o| o.is_empty()));
        if !advertised {
            continue;
        }
        let mut items = Vec::new();
        if let Err(failure) = list_all(
            &mut c,
            method,
            key,
            version,
            meta.as_ref(),
            &mut items,
            &mut dropped,
            &mut report,
        )
        .await
        {
            return *failure;
        }
        match kind {
            "tools" => report.tools = items,
            "resources" => report.resources = items,
            _ => report.prompts = items,
        }
    }
    if dropped > 0 {
        report.details.insert("droppedItems".into(), json!(dropped));
    }
    report
}

async fn discover(c: &mut Client<'_>, report: &mut ProbeReport) -> Result<Era, Box<ProbeReport>> {
    let rpc = match c
        .request(
            "server/discover",
            Some(MODERN_VERSION),
            json!({"_meta": modern_meta()}),
        )
        .await
    {
        Ok(r) => r,
        // No answer at all: a legacy stdio server may ignore an unknown
        // pre-initialize request (spec: fall back on timeout).
        Err(TransportError::Timeout) => {
            return Ok(Era::Legacy {
                version: LEGACY_VERSIONS[0],
            })
        }
        Err(e) => return Err(Box::new(transport_failure(&e))),
    };
    match rpc {
        Rpc::Result(r) => {
            let supported = strings(r.get("supportedVersions"));
            report.instructions = r
                .get("instructions")
                .and_then(|i| i.as_str())
                .map(String::from);
            note_cache(report, &r);
            if let Some(info) = r.pointer("/_meta/io.modelcontextprotocol~1serverInfo") {
                report.details.insert("serverInfo".into(), info.clone());
            }
            if supported.is_empty() || supported.iter().any(|v| v == MODERN_VERSION) {
                return Ok(Era::Modern {
                    capabilities: r.get("capabilities").cloned().unwrap_or(json!({})),
                });
            }
            pick_legacy(&supported)
                .map(|version| Era::Legacy { version })
                .ok_or_else(|| {
                    Box::new(ProbeReport::failed(
                        "unsupported",
                        format!("server speaks {supported:?}"),
                    ))
                })
        }
        Rpc::Error {
            code: UNSUPPORTED_VERSION,
            data,
        } => {
            let supported = strings(data.as_ref().and_then(|d| d.get("supported")));
            pick_legacy(&supported)
                .map(|version| Era::Legacy { version })
                .ok_or_else(|| {
                    Box::new(ProbeReport::failed(
                        "unsupported",
                        format!("server speaks {supported:?}"),
                    ))
                })
        }
        // Any other error (commonly -32601 or -32602): a legacy server.
        // Modern servers MUST implement `server/discover`, and the fallback
        // must not key on one specific code.
        Rpc::Error { .. } => Ok(Era::Legacy {
            version: LEGACY_VERSIONS[0],
        }),
        Rpc::Http {
            status,
            retry_after_ms,
            ..
        } => match http_failure(status, retry_after_ms) {
            Some(f) => Err(Box::new(f)),
            None => Ok(Era::Legacy {
                version: LEGACY_VERSIONS[0],
            }),
        },
    }
}

async fn initialize(
    c: &mut Client<'_>,
    version: &'static str,
    report: &mut ProbeReport,
) -> Result<(Value, &'static str), Box<ProbeReport>> {
    let params = json!({
        "protocolVersion": version,
        "capabilities": {},
        "clientInfo": {"name": CLIENT_NAME, "version": artifact_keeper_backend::build_info::VERSION},
    });
    let r = match c.request("initialize", Some(version), params).await {
        Ok(Rpc::Result(r)) => r,
        Ok(Rpc::Error { code, .. }) => {
            return Err(Box::new(ProbeReport::failed(
                "unsupported",
                format!("initialize refused ({code})"),
            )))
        }
        Ok(Rpc::Http {
            status,
            retry_after_ms,
            ..
        }) => {
            return Err(Box::new(
                http_failure(status, retry_after_ms).unwrap_or_else(|| {
                    ProbeReport::failed("unsupported", format!("initialize answered {status}"))
                }),
            ))
        }
        Err(e) => return Err(Box::new(transport_failure(&e))),
    };
    let asked = r
        .get("protocolVersion")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let Some(negotiated) = LEGACY_VERSIONS.iter().find(|v| **v == asked).copied() else {
        return Err(Box::new(ProbeReport::failed(
            "unsupported",
            format!("server negotiated protocol `{asked}`"),
        )));
    };
    if let Some(info) = r.get("serverInfo") {
        report.details.insert("serverInfo".into(), info.clone());
    }
    report.instructions = r
        .get("instructions")
        .and_then(|i| i.as_str())
        .map(String::from);
    c.notify("notifications/initialized", Some(negotiated))
        .await
        .map_err(|e| transport_failure(&e))?;
    Ok((
        r.get("capabilities").cloned().unwrap_or(json!({})),
        negotiated,
    ))
}

/// Fold a result's cache hints into the report: the smallest `ttlMs`
/// (capped at the backend's [`MAX_TTL_MS`]), and `caller_specific` once any
/// page is not exactly `public`. The remote's hints are normalised to what
/// the backend accepts (#5466): an unknown scope (`shared`, `Public`) is
/// treated as `private`, the safe reading, so the result is stored instead
/// of being refused on every attempt.
///
/// [`MAX_TTL_MS`]: artifact_keeper_backend::services::mcp_introspection::MAX_TTL_MS
fn note_cache(report: &mut ProbeReport, r: &Value) {
    use artifact_keeper_backend::services::mcp_introspection::MAX_TTL_MS;
    if let Some(t) = r.get("ttlMs").and_then(|t| t.as_i64()).filter(|t| *t >= 0) {
        let t = t.min(MAX_TTL_MS);
        report.ttl_ms = Some(report.ttl_ms.map_or(t, |cur| cur.min(t)));
    }
    if let Some(scope) = r.get("cacheScope").and_then(|s| s.as_str()) {
        if scope != "public" {
            report.auth_state = "caller_specific".into();
            report.cache_scope = Some("private".into());
        } else if report.cache_scope.is_none() {
            report.cache_scope = Some("public".into());
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn list_all(
    c: &mut Client<'_>,
    method: &str,
    key: &str,
    version: &str,
    meta: Option<&Value>,
    items: &mut Vec<Value>,
    dropped: &mut usize,
    report: &mut ProbeReport,
) -> Result<(), Box<ProbeReport>> {
    let kind = method.trim_end_matches("/list");
    let mut cursor: Option<String> = None;
    for _ in 0..MAX_PAGES {
        let mut params = Map::new();
        if let Some(m) = meta {
            params.insert("_meta".into(), m.clone());
        }
        if let Some(cur) = &cursor {
            params.insert("cursor".into(), json!(cur));
        }
        let r = match c
            .request(method, Some(version), Value::Object(params))
            .await
        {
            Ok(Rpc::Result(r)) => r,
            // The server does not implement this list after all.
            Ok(Rpc::Error {
                code: METHOD_NOT_FOUND,
                ..
            }) => return Ok(()),
            Ok(Rpc::Error { code, .. }) => {
                return Err(Box::new(ProbeReport::failed(
                    "error",
                    format!("{method} failed ({code})"),
                )))
            }
            Ok(Rpc::Http {
                status,
                retry_after_ms,
                ..
            }) => {
                return Err(Box::new(
                    http_failure(status, retry_after_ms).unwrap_or_else(|| {
                        ProbeReport::failed("error", format!("{method} answered {status}"))
                    }),
                ))
            }
            Err(e) => return Err(Box::new(transport_failure(&e))),
        };
        if r.get("resultType").and_then(|t| t.as_str()) == Some("input_required") {
            return Err(Box::new(ProbeReport::failed(
                "needs_config",
                format!("{method} asked for input"),
            )));
        }
        note_cache(report, &r);
        let page = r
            .get(kind)
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        accept_items(items, &page, key, c.max_items, dropped);
        cursor = r
            .get("nextCursor")
            .and_then(|n| n.as_str())
            .filter(|n| !n.is_empty())
            .map(String::from);
        if cursor.is_none() || items.len() >= c.max_items {
            return Ok(());
        }
    }
    report.details.insert("truncated".into(), json!(kind));
    Ok(())
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// Stands for "the id of the request being answered" in a scripted
    /// reply: [`Mock::ok`] and [`Mock::err`] answer with the right id, while
    /// [`Mock::on`] sends exactly what it was given (a wrong id included).
    const ECHO_ID: &str = "<echo request id>";

    /// A scripted transport: answers by method, records what was sent.
    #[derive(Default)]
    pub(crate) struct Mock {
        pub answers: VecDeque<(String, Result<Reply, TransportError>)>,
        pub sent: Vec<(String, Option<String>, Value)>,
    }

    impl Mock {
        pub(crate) fn on(mut self, method: &str, r: Result<Reply, TransportError>) -> Self {
            self.answers.push_back((method.to_string(), r));
            self
        }
        pub(crate) fn ok(self, method: &str, result: Value) -> Self {
            self.on(
                method,
                Ok(Reply::Message(
                    json!({"jsonrpc": "2.0", "id": ECHO_ID, "result": result}),
                )),
            )
        }
        pub(crate) fn err(self, method: &str, code: i64, data: Value) -> Self {
            self.on(
                method,
                Ok(Reply::Message(json!({"jsonrpc": "2.0", "id": ECHO_ID, "error": {"code": code, "message": "x", "data": data}}))),
            )
        }
        pub(crate) fn status(self, method: &str, status: u16, body: Option<Value>) -> Self {
            self.on(
                method,
                Ok(Reply::Status {
                    status,
                    body,
                    retry_after_ms: Some(30_000),
                }),
            )
        }
    }

    #[async_trait]
    impl Transport for Mock {
        async fn send(
            &mut self,
            method: &str,
            v: Option<&str>,
            msg: Value,
        ) -> Result<Reply, TransportError> {
            let id = msg.get("id").cloned();
            self.sent
                .push((method.to_string(), v.map(String::from), msg));
            if method.starts_with("notifications/") {
                return Ok(Reply::Message(Value::Null));
            }
            match self.answers.pop_front() {
                Some((m, mut r)) => {
                    assert_eq!(m, method, "unexpected request order");
                    if let Ok(Reply::Message(reply)) = &mut r {
                        if reply.get("id") == Some(&json!(ECHO_ID)) {
                            reply["id"] = id.unwrap_or(Value::Null);
                        }
                    }
                    r
                }
                None => Err(TransportError::Closed),
            }
        }
    }

    fn methods(m: &Mock) -> Vec<&str> {
        m.sent.iter().map(|(m, _, _)| m.as_str()).collect()
    }

    fn discover_ok(caps: Value) -> Value {
        json!({
            "resultType": "complete", "supportedVersions": [MODERN_VERSION],
            "capabilities": caps, "instructions": "hi",
            "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "s", "version": "1"}},
            "ttlMs": 60_000, "cacheScope": "public",
        })
    }

    #[tokio::test]
    async fn modern_probe_lists_advertised_kinds_with_pagination() {
        let mut m = Mock::default()
            .ok("server/discover", discover_ok(json!({"tools": {}, "prompts": {}})))
            .ok("tools/list", json!({"tools": [{"name": "a"}, {"name": "a"}, {"x": 1}], "nextCursor": "p2", "ttlMs": 5000}))
            .ok("tools/list", json!({"tools": [{"name": "b"}], "cacheScope": "private"}))
            .ok("prompts/list", json!({"prompts": [{"name": "p"}]}));
        let r = probe(&mut m, 1000).await;
        assert_eq!(r.outcome, "ok", "{:?}", r.error);
        assert_eq!(r.protocol_version.as_deref(), Some(MODERN_VERSION));
        assert_eq!(r.tools.len(), 2);
        assert_eq!(r.prompts.len(), 1);
        assert!(r.resources.is_empty());
        assert_eq!(r.ttl_ms, Some(5000));
        assert_eq!(r.auth_state, "caller_specific");
        assert_eq!(r.instructions.as_deref(), Some("hi"));
        assert_eq!(r.details["droppedItems"], 2);
        assert_eq!(r.details["era"], "modern");
        assert_eq!(
            methods(&m),
            vec![
                "server/discover",
                "tools/list",
                "tools/list",
                "prompts/list"
            ]
        );
        // Every modern request carries `_meta` and the protocol version; the
        // second page carries the cursor.
        for (_, v, msg) in &m.sent {
            assert_eq!(v.as_deref(), Some(MODERN_VERSION));
            assert_eq!(
                msg["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
                MODERN_VERSION
            );
        }
        assert_eq!(m.sent[2].2["params"]["cursor"], "p2");
        assert!(methods(&m).iter().all(|x| ALLOWED_METHODS.contains(x)));
        let j = r.to_result_json();
        assert_eq!(j["tools"][1]["name"], "b");
    }

    #[tokio::test]
    async fn legacy_fallback_on_unknown_method_error() {
        let mut m = Mock::default()
            .err("server/discover", -32600, json!(null))
            .ok("initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "old"}}))
            .ok("tools/list", json!({"tools": [{"name": "t"}]}));
        let r = probe(&mut m, 1000).await;
        assert_eq!(r.outcome, "ok");
        assert_eq!(r.protocol_version.as_deref(), Some("2025-06-18"));
        assert_eq!(r.details["era"], "legacy");
        assert_eq!(
            methods(&m),
            vec![
                "server/discover",
                "initialize",
                "notifications/initialized",
                "tools/list"
            ]
        );
        assert!(
            m.sent[3].2["params"].get("_meta").is_none(),
            "legacy requests carry no _meta"
        );
        assert_eq!(m.sent[1].2["params"]["clientInfo"]["name"], CLIENT_NAME);
    }

    #[tokio::test]
    async fn unsupported_version_error_picks_a_legacy_version() {
        let mut m = Mock::default()
            .err(
                "server/discover",
                UNSUPPORTED_VERSION,
                json!({"supported": ["2025-03-26"]}),
            )
            .ok(
                "initialize",
                json!({"protocolVersion": "2025-03-26", "capabilities": {}}),
            )
            .ok("tools/list", json!({"tools": []}));
        let r = probe(&mut m, 1000).await;
        assert_eq!(r.outcome, "ok");
        assert_eq!(r.protocol_version.as_deref(), Some("2025-03-26"));
        let mut m = Mock::default().err(
            "server/discover",
            UNSUPPORTED_VERSION,
            json!({"supported": ["2030-01-01"]}),
        );
        assert_eq!(probe(&mut m, 1000).await.outcome, "unsupported");
    }

    #[tokio::test]
    async fn http_failures_map_to_outcomes() {
        let mut m = Mock::default().status("server/discover", 401, None);
        let r = probe(&mut m, 10).await;
        assert_eq!(
            (r.outcome.as_str(), r.auth_state.as_str()),
            ("auth_required", "auth_required")
        );
        let mut m = Mock::default().status("server/discover", 429, None);
        let r = probe(&mut m, 10).await;
        assert_eq!(r.outcome, "rate_limited");
        assert_eq!(r.retry_after_ms, Some(30_000));
        let mut m = Mock::default().status("server/discover", 503, None);
        assert_eq!(probe(&mut m, 10).await.outcome, "error");
        // A 404 carrying a JSON-RPC error body: method not found, so the
        // server is legacy.
        let mut m = Mock::default()
            .status(
                "server/discover",
                404,
                Some(json!({"error": {"code": METHOD_NOT_FOUND}})),
            )
            .ok(
                "initialize",
                json!({"protocolVersion": "2025-11-25", "capabilities": {"tools": {}}}),
            )
            .ok("tools/list", json!({"tools": [{"name": "x"}]}));
        let r = probe(&mut m, 10).await;
        assert_eq!(r.outcome, "ok");
        assert_eq!(r.details["era"], "legacy");
        // A plain 404: legacy, and the legacy initialize fails too.
        let mut m =
            Mock::default()
                .status("server/discover", 404, None)
                .status("initialize", 405, None);
        assert_eq!(probe(&mut m, 10).await.outcome, "unsupported");
        // 401 on a list after discover.
        let mut m = Mock::default()
            .ok("server/discover", discover_ok(json!({"tools": {}})))
            .status("tools/list", 403, None);
        assert_eq!(probe(&mut m, 10).await.outcome, "auth_required");
    }

    #[tokio::test]
    async fn transport_failures_and_input_required() {
        let mut m = Mock::default().on("server/discover", Err(TransportError::Redirect));
        assert_eq!(probe(&mut m, 10).await.outcome, "refused");
        let mut m = Mock::default().on("server/discover", Err(TransportError::Closed));
        assert_eq!(probe(&mut m, 10).await.outcome, "start_failed");
        // Timeout on discover falls back to initialize; a timeout there too.
        let mut m = Mock::default()
            .on("server/discover", Err(TransportError::Timeout))
            .on("initialize", Err(TransportError::Timeout));
        assert_eq!(probe(&mut m, 10).await.outcome, "timeout");
        let mut m = Mock::default()
            .ok("server/discover", discover_ok(json!({"tools": {}})))
            .ok("tools/list", json!({"resultType": "input_required"}));
        assert_eq!(probe(&mut m, 10).await.outcome, "needs_config");
        let mut m = Mock::default()
            .ok("server/discover", discover_ok(json!({"tools": {}})))
            .err("tools/list", -32603, json!(null));
        assert_eq!(probe(&mut m, 10).await.outcome, "error");
        let mut m = Mock::default()
            .ok(
                "server/discover",
                discover_ok(json!({"tools": {}, "resources": {}})),
            )
            .ok("tools/list", json!({"tools": [{"name": "a"}]}))
            .err("resources/list", METHOD_NOT_FOUND, json!(null));
        assert_eq!(probe(&mut m, 10).await.outcome, "ok");
        // A legacy negotiation of an unknown version is refused.
        let mut m = Mock::default()
            .err("server/discover", -1, json!(null))
            .ok("initialize", json!({"protocolVersion": "1999-01-01"}));
        assert_eq!(probe(&mut m, 10).await.outcome, "unsupported");
        assert!(TransportError::Io("x".into()).to_string() == "x");
    }

    #[tokio::test]
    async fn caps_items_and_pages() {
        let mut m = Mock::default().ok("server/discover", discover_ok(json!({"tools": {}})));
        for i in 0..MAX_PAGES {
            m = m.ok(
                "tools/list",
                json!({"tools": [{"name": format!("t{i}")}], "nextCursor": "more"}),
            );
        }
        let r = probe(&mut m, 1000).await;
        assert_eq!(r.tools.len(), MAX_PAGES);
        assert_eq!(r.details["truncated"], "tools");
        let mut m = Mock::default()
            .ok("server/discover", discover_ok(json!({"tools": {}})))
            .ok(
                "tools/list",
                json!({"tools": [{"name": "a"}, {"name": "b"}, {"name": "c"}], "nextCursor": "x"}),
            );
        let r = probe(&mut m, 2).await;
        assert_eq!(r.tools.len(), 2, "item cap stops paging");
        assert_eq!(
            pick_legacy(&["2024-11-05".into(), "2025-06-18".into()]),
            Some("2025-06-18")
        );
        assert_eq!(pick_legacy(&[]), None);
    }

    #[tokio::test]
    #[should_panic(expected = "never sends tools/call")]
    async fn tools_call_is_impossible() {
        let mut m = Mock::default();
        let mut c = Client::new(&mut m, 10);
        let _ = c.request("tools/call", None, json!({})).await;
    }

    /// Keys longer than the backend stores are dropped like unusable ones:
    /// names up to 256 bytes, resource URIs up to 2048.
    #[test]
    fn item_keys_follow_the_backend_limits() {
        let mut out = Vec::new();
        let mut dropped = 0;
        let page = [
            json!({"name": "n".repeat(256)}),
            json!({"name": "m".repeat(257)}),
        ];
        accept_items(&mut out, &page, "name", 10, &mut dropped);
        assert_eq!((out.len(), dropped), (1, 1));
        let mut out = Vec::new();
        let mut dropped = 0;
        let page = [
            json!({"uri": format!("file:///{}", "u".repeat(2000))}),
            json!({"uri": format!("file:///{}", "v".repeat(2048))}),
        ];
        accept_items(&mut out, &page, "uri", 10, &mut dropped);
        assert_eq!((out.len(), dropped), (1, 1));
    }

    /// A reply to `method` carrying exactly `id` (`None`: no `id` member).
    fn reply_with_id(id: Option<Value>, result: Value) -> Result<Reply, TransportError> {
        let mut m = json!({"jsonrpc": "2.0", "result": result});
        if let Some(id) = id {
            m["id"] = id;
        }
        Ok(Reply::Message(m))
    }

    /// The probe failed closed on a protocol violation: `refused`, the code
    /// in `details.protocolViolation`, and nothing the server said kept.
    fn assert_violation(r: &ProbeReport, code: &str) {
        assert_eq!(r.outcome, "refused", "{r:?}");
        assert_eq!(
            r.details.get("protocolViolation"),
            Some(&json!(code)),
            "{r:?}"
        );
        assert!(r.details.get("capabilities").is_none(), "{r:?}");
        assert!(r.details.get("serverInfo").is_none(), "{r:?}");
        assert!(r.tools.is_empty() && r.resources.is_empty() && r.prompts.is_empty());
        assert_eq!(
            (r.protocol_version.as_ref(), r.instructions.as_ref()),
            (None, None)
        );
        let j = r.to_result_json();
        assert!(j["tools"].is_null() && j["instructions"].is_null());
    }

    /// #5450: a discover answer naming another id (or the right number as a
    /// string, or no id at all) is not the discover answer.
    #[tokio::test]
    async fn wrong_id_discovery_fails_closed() {
        for id in [
            Some(json!(7)),
            Some(json!("1")),
            Some(json!(1.0)),
            Some(Value::Null),
            None,
        ] {
            let mut m = Mock::default()
                .on(
                    "server/discover",
                    reply_with_id(id.clone(), discover_ok(json!({"tools": {}}))),
                )
                .ok("tools/list", json!({"tools": [{"name": "t"}]}));
            let r = probe(&mut m, 10).await;
            assert_violation(&r, "response_id_mismatch");
            assert_eq!(
                methods(&m),
                vec!["server/discover"],
                "{id:?}: nothing after"
            );
        }
        // The legacy path: an initialize answer for another id.
        let mut m = Mock::default()
            .err("server/discover", METHOD_NOT_FOUND, json!(null))
            .on(
                "initialize",
                reply_with_id(
                    Some(json!(9)),
                    json!({"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}}),
                ),
            );
        assert_violation(&probe(&mut m, 10).await, "response_id_mismatch");
        assert_eq!(methods(&m), vec!["server/discover", "initialize"]);
    }

    /// #5450: a tools/list answer for another request, or a second answer to
    /// the (answered) discover request, accepts no tool.
    #[tokio::test]
    async fn wrong_id_or_duplicate_tools_list_fails_closed() {
        let mut m = Mock::default()
            .ok("server/discover", discover_ok(json!({"tools": {}})))
            .on(
                "tools/list",
                reply_with_id(Some(json!(42)), json!({"tools": [{"name": "evil"}]})),
            );
        assert_violation(&probe(&mut m, 10).await, "response_id_mismatch");
        // discover was id 1: answering tools/list (id 2) with id 1 again.
        let mut m = Mock::default()
            .ok("server/discover", discover_ok(json!({"tools": {}})))
            .on(
                "tools/list",
                reply_with_id(Some(json!(1)), json!({"tools": [{"name": "evil"}]})),
            );
        assert_violation(&probe(&mut m, 10).await, "duplicate_response");
        // A later page of a paginated list, too.
        let mut m = Mock::default()
            .ok("server/discover", discover_ok(json!({"tools": {}})))
            .ok(
                "tools/list",
                json!({"tools": [{"name": "a"}], "nextCursor": "c"}),
            )
            .on(
                "tools/list",
                reply_with_id(Some(json!("3")), json!({"tools": [{"name": "b"}]})),
            );
        assert_violation(&probe(&mut m, 10).await, "response_id_mismatch");
    }

    /// #5450: this client never sends a batch, so a batch is no answer; an
    /// HTTP error body naming another request is refused too, while the
    /// common `"id": null` of an HTTP-level error is tolerated.
    #[tokio::test]
    async fn batches_and_foreign_error_bodies_fail_closed() {
        let mut m = Mock::default().on(
            "server/discover",
            Ok(Reply::Message(json!([
                {"jsonrpc": "2.0", "id": 1, "result": discover_ok(json!({"tools": {}}))}
            ]))),
        );
        assert_violation(&probe(&mut m, 10).await, "unexpected_batch");
        let mut m = Mock::default().status(
            "server/discover",
            400,
            Some(
                json!({"jsonrpc": "2.0", "id": 5, "error": {"code": UNSUPPORTED_VERSION,
                "data": {"supported": ["2025-06-18"]}}}),
            ),
        );
        assert_violation(&probe(&mut m, 10).await, "response_id_mismatch");
        let mut m = Mock::default()
            .status(
                "server/discover",
                400,
                Some(json!({"jsonrpc": "2.0", "id": null, "error": {"code": METHOD_NOT_FOUND}})),
            )
            .ok(
                "initialize",
                json!({"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}}),
            )
            .ok("tools/list", json!({"tools": [{"name": "t"}]}));
        let r = probe(&mut m, 10).await;
        assert_eq!(r.outcome, "ok", "{r:?}");
        assert_eq!(r.tools.len(), 1);
        // An HTTP-level error whose body is not consumed as a JSON-RPC error
        // (only its status is used): its id is not looked at. The MCP Python
        // SDK v1.x sends `"id": "server-error"` on a pre-initialize 400.
        for status in [400, 401, 429] {
            let mut m = Mock::default()
                .status(
                    "server/discover",
                    status,
                    Some(json!({"jsonrpc": "2.0", "id": "server-error",
                        "error": {"code": -32600, "message": "Bad Request: Missing session ID"}})),
                )
                .ok(
                    "initialize",
                    json!({"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}}),
                )
                .ok("tools/list", json!({"tools": [{"name": "t"}]}));
            let r = probe(&mut m, 10).await;
            assert!(
                r.details.get("protocolViolation").is_none(),
                "{status}: {r:?}"
            );
            if status == 400 {
                assert_eq!((r.outcome.as_str(), r.tools.len()), ("ok", 1), "{r:?}");
            }
        }
        // A batch of only notifications answers nothing: malformed, not a
        // violation (and nothing accepted).
        let mut m = Mock::default().on(
            "server/discover",
            Ok(Reply::Message(
                json!([{"jsonrpc": "2.0", "method": "notifications/progress"}]),
            )),
        );
        let r = probe(&mut m, 10).await;
        assert_eq!(r.outcome, "error", "{r:?}");
        assert!(r.details.get("protocolViolation").is_none());
    }

    /// The benign control: answers that echo each request's id (numbers, as
    /// sent) are accepted, request ids are never reused.
    #[tokio::test]
    async fn matching_ids_are_accepted() {
        let mut m = Mock::default()
            .ok(
                "server/discover",
                discover_ok(json!({"tools": {}, "prompts": {}})),
            )
            .ok(
                "tools/list",
                json!({"tools": [{"name": "a"}], "nextCursor": "c"}),
            )
            .ok("tools/list", json!({"tools": [{"name": "b"}]}))
            .ok("prompts/list", json!({"prompts": [{"name": "p"}]}));
        let r = probe(&mut m, 10).await;
        assert_eq!(r.outcome, "ok", "{r:?}");
        assert_eq!((r.tools.len(), r.prompts.len()), (2, 1));
        assert!(r.details.get("protocolViolation").is_none());
        let ids: Vec<&Value> = m.sent.iter().map(|(_, _, msg)| &msg["id"]).collect();
        assert_eq!(ids, vec![&json!(1), &json!(2), &json!(3), &json!(4)]);
    }

    #[test]
    fn failed_report_json_has_no_items() {
        let r = ProbeReport::failed("timeout", "slow");
        let j = r.to_result_json();
        assert_eq!(j["outcome"], "timeout");
        assert!(j["tools"].is_null());
        assert_eq!(j["error"], "slow");
    }

    /// #5466: a remote's cache hints the backend would refuse are
    /// normalised: an unknown scope is `private` (`caller_specific`), and a
    /// huge `ttlMs` is capped at the backend's limit.
    #[test]
    fn remote_cache_hints_are_normalised_for_the_backend() {
        use artifact_keeper_backend::services::mcp_introspection::MAX_TTL_MS;
        for scope in ["shared", "Public", "PRIVATE", ""] {
            let mut r = ProbeReport {
                outcome: "ok".into(),
                auth_state: "none".into(),
                ..Default::default()
            };
            note_cache(
                &mut r,
                &json!({"cacheScope": scope, "ttlMs": 10_000_000_000_000_i64}),
            );
            let body = r.to_result_json();
            assert_eq!(body["cacheScope"], "private", "{scope}");
            assert_eq!(body["authState"], "caller_specific", "{scope}");
            assert_eq!(body["ttlMs"], MAX_TTL_MS, "{scope}");
        }
        let mut r = ProbeReport {
            outcome: "ok".into(),
            auth_state: "none".into(),
            ..Default::default()
        };
        note_cache(&mut r, &json!({"cacheScope": "public", "ttlMs": 0}));
        let body = r.to_result_json();
        assert_eq!(
            (&body["cacheScope"], &body["authState"], &body["ttlMs"]),
            (&json!("public"), &json!("none"), &json!(0))
        );
    }

    /// #5466, through a probe: a remote answering `cacheScope: "shared"` and
    /// `ttlMs: 1e13` yields a result the backend accepts.
    #[tokio::test]
    async fn a_probe_normalises_the_remotes_cache_hints() {
        use artifact_keeper_backend::services::mcp_introspection::MAX_TTL_MS;
        // The discovery result advertises the same oversized hint, so the
        // smallest `ttlMs` of the probe is the oversized one.
        let mut discover = discover_ok(json!({"tools": {}}));
        discover["ttlMs"] = json!(10_000_000_000_000_i64);
        let mut m = Mock::default().ok("server/discover", discover).ok(
            "tools/list",
            json!({"tools": [{"name": "a"}], "cacheScope": "shared",
                       "ttlMs": 10_000_000_000_000_i64}),
        );
        let r = probe(&mut m, 1000).await;
        assert_eq!(r.outcome, "ok", "{:?}", r.error);
        let body = r.to_result_json();
        assert_eq!(body["cacheScope"], "private");
        assert_eq!(body["authState"], "caller_specific");
        assert_eq!(body["ttlMs"], MAX_TTL_MS);
    }
}
