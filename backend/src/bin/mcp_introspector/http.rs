//! Streamable HTTP transport for the remote probe.
//!
//! Egress rules (T6): the URL must pass `validate_outbound_url` (public
//! ranges only); the connection goes through `SsrfGuardResolver`
//! (resolve-then-check at connect, closing DNS rebinding); redirects are
//! refused outright; proxy environment variables are ignored (a proxy would
//! resolve the host itself, out of the guard's sight); every response is
//! read with a byte cap; only the protocol headers are sent (never a header
//! from the server.json's `remotes[].headers`), plus an identifying
//! `User-Agent`.
//!
//! Session integrity (#5451): an `Mcp-Session-Id` is adopted only from the
//! successful `initialize` response, the protocol's one assignment point.
//! One on any other response before that (or on a modern, sessionless
//! server) is ignored and never echoed; once a session is established, a
//! response naming a different one fails the probe
//! ([`Violation::SessionIdChanged`]) instead of switching. A redirect is
//! refused before its headers are looked at, so a session never follows one.

use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt;
use serde_json::Value;

use crate::protocol::{
    is_response, is_response_batch, Reply, Transport, TransportError, Violation,
};

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// `ak-mcp-introspector/<version> (+<docs>; capability probe; never calls tools)`.
pub fn user_agent() -> String {
    format!(
        "ak-mcp-introspector/{} (+https://github.com/artifact-keeper/artifact-keeper/blob/main/docs/mcp-registry.md; \
         capability probe; never calls tools)",
        artifact_keeper_backend::build_info::VERSION
    )
}

/// Refuse a probe target that is not a public http(s) URL.
pub fn check_url(url: &str) -> Result<(), String> {
    artifact_keeper_backend::api::validation::validate_outbound_url(url, "MCP remote")
        .map_err(|e| e.to_string())
}

/// The environment overrides that would let `validate_outbound_url` and the
/// resolver accept private addresses. The probe refuses to run with any of
/// them set: it is public ranges only.
pub const PRIVATE_OVERRIDES: &[&str] =
    &["UPSTREAM_ALLOW_PRIVATE_IPS", "AK_SSRF_ALLOW_PRIVATE_CIDRS"];

pub fn private_override_set(get: impl Fn(&str) -> Option<String>) -> Option<&'static str> {
    PRIVATE_OVERRIDES
        .iter()
        .find(|k| get(k).is_some_and(|v| !v.trim().is_empty() && v.trim() != "false"))
        .copied()
}

/// The production client: SSRF-guarded resolver, no redirects, no proxy.
pub fn guarded_client() -> reqwest::Client {
    artifact_keeper_backend::services::http_client::plain_client_builder()
        .user_agent(user_agent())
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .dns_resolver(artifact_keeper_backend::services::ssrf_dns::ssrf_guard_resolver())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
        .expect("HTTP client")
}

pub struct HttpTransport {
    client: reqwest::Client,
    url: String,
    max_bytes: usize,
    /// A legacy (2025-03-26 .. 2025-11-25) server's session, echoed back.
    session: Option<String>,
    /// `initialize` was answered: no session can be established any more.
    initialized: bool,
}

/// A session id the spec allows: 1-256 visible ASCII characters
/// (0x21..=0x7E).
fn valid_session_id(v: &[u8]) -> bool {
    !v.is_empty() && v.len() <= 256 && v.iter().all(|b| (0x21..=0x7E).contains(b))
}

impl HttpTransport {
    pub fn new(client: reqwest::Client, url: impl Into<String>, max_bytes: usize) -> Self {
        Self {
            client,
            url: url.into(),
            max_bytes,
            session: None,
            initialized: false,
        }
    }

    /// Apply the session rules to the `Mcp-Session-Id` (if any) of the
    /// response to `method`.
    fn note_session(
        &mut self,
        method: &str,
        success: bool,
        offered: Option<&[u8]>,
    ) -> Result<(), TransportError> {
        let assigns = method == "initialize" && success && !self.initialized;
        if assigns {
            self.initialized = true;
        }
        let Some(offered) = offered else {
            return Ok(());
        };
        if let Some(current) = &self.session {
            return if current.as_bytes() == offered {
                Ok(())
            } else {
                Err(TransportError::Protocol(Violation::SessionIdChanged))
            };
        }
        if !assigns {
            tracing::warn!(
                method,
                "ignoring an Mcp-Session-Id outside the initialize response"
            );
            return Ok(());
        }
        if !valid_session_id(offered) {
            return Err(TransportError::Protocol(Violation::SessionIdInvalid));
        }
        self.session = Some(String::from_utf8_lossy(offered).into_owned());
        Ok(())
    }
}

/// Parse `data:` payloads of the SSE events in `buf`; returns the first
/// JSON-RPC response once it arrived, whatever its `id` (the client checks
/// that it answers the outstanding request). Notifications and server
/// requests are skipped, as is a batch of only those. A batch carrying a
/// response, or a second response with the same `id` in the bytes read so
/// far, is a protocol violation. (The stream is not read past the first
/// response, so a duplicate sent later is never seen, nor accepted.)
pub fn sse_response(buf: &str) -> Result<Option<Value>, Violation> {
    let normalized = buf.replace("\r\n", "\n");
    let mut first: Option<Value> = None;
    for event in normalized.split("\n\n") {
        let data: Vec<&str> = event
            .lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .map(|d| d.strip_prefix(' ').unwrap_or(d))
            .collect();
        if data.is_empty() {
            continue;
        }
        let Ok(v) = serde_json::from_str::<Value>(&data.join("\n")) else {
            continue;
        };
        if is_response_batch(&v) {
            return Err(Violation::UnexpectedBatch);
        }
        if !is_response(&v) {
            continue;
        }
        match &first {
            None => first = Some(v),
            Some(f) if f.get("id") == v.get("id") => return Err(Violation::DuplicateResponse),
            // A response to something else after the first: the client
            // rejects the first already when it is not ours, and the stream
            // is not read past it otherwise.
            Some(_) => {}
        }
    }
    Ok(first)
}

fn retry_after_ms(h: &reqwest::header::HeaderMap) -> Option<i64> {
    h.get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<i64>()
        .ok()
        .map(|s| s.saturating_mul(1000))
}

#[async_trait]
impl Transport for HttpTransport {
    async fn send(
        &mut self,
        method: &str,
        protocol_version: Option<&str>,
        msg: Value,
    ) -> Result<Reply, TransportError> {
        let mut req = self
            .client
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(
                reqwest::header::ACCEPT,
                "application/json, text/event-stream",
            )
            .header("Mcp-Method", method);
        if let Some(v) = protocol_version {
            req = req.header("MCP-Protocol-Version", v);
        }
        if let Some(s) = &self.session {
            req = req.header("Mcp-Session-Id", s);
        }
        let resp = req
            .body(serde_json::to_vec(&msg).unwrap_or_default())
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    TransportError::Timeout
                } else {
                    TransportError::Io(format!("request failed: {e}"))
                }
            })?;
        let status = resp.status();
        if status.is_redirection() {
            return Err(TransportError::Redirect);
        }
        self.note_session(
            method,
            status.is_success(),
            resp.headers().get("mcp-session-id").map(|v| v.as_bytes()),
        )?;
        let headers = resp.headers().clone();
        let sse = headers
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|c| c.starts_with("text/event-stream"));
        let id = msg.get("id").cloned();
        let mut body: Vec<u8> = Vec::new();
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| {
                if e.is_timeout() {
                    TransportError::Timeout
                } else {
                    TransportError::Io(e.to_string())
                }
            })?;
            if body.len() + chunk.len() > self.max_bytes {
                return Err(TransportError::TooLarge);
            }
            body.extend_from_slice(&chunk);
            // An SSE stream may stay open after the response: stop reading
            // as soon as it arrived.
            if sse && status.is_success() && id.is_some() {
                if let Some(v) = sse_response(&String::from_utf8_lossy(&body))
                    .map_err(TransportError::Protocol)?
                {
                    return Ok(Reply::Message(v));
                }
            }
        }
        if !status.is_success() {
            return Ok(Reply::Status {
                status: status.as_u16(),
                body: serde_json::from_slice(&body).ok(),
                retry_after_ms: retry_after_ms(&headers),
            });
        }
        if id.is_none() {
            return Ok(Reply::Message(Value::Null));
        }
        if sse {
            return sse_response(&String::from_utf8_lossy(&body))
                .map_err(TransportError::Protocol)?
                .map(Reply::Message)
                .ok_or(TransportError::Closed);
        }
        serde_json::from_slice(&body)
            .map(Reply::Message)
            .map_err(|_| TransportError::Io("response is not JSON".into()))
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{header, headers, method};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// The guard refuses loopback, so the in-process mock server is reached
    /// with an unguarded client; `check_url` is tested separately.
    fn test_client() -> reqwest::Client {
        reqwest::Client::builder()
            .user_agent(user_agent())
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .unwrap()
    }

    #[test]
    fn url_policy() {
        assert!(check_url("https://example.com/mcp").is_ok());
        for bad in [
            "http://127.0.0.1/mcp",
            "http://169.254.169.254/latest",
            "http://10.0.0.1/mcp",
            "http://localhost:8080/mcp",
            "file:///etc/passwd",
        ] {
            assert!(check_url(bad).is_err(), "{bad}");
        }
        assert_eq!(private_override_set(|_| None), None);
        assert_eq!(
            private_override_set(
                |k| (k == "AK_SSRF_ALLOW_PRIVATE_CIDRS").then(|| "10.0.0.0/8".into())
            ),
            Some("AK_SSRF_ALLOW_PRIVATE_CIDRS")
        );
        assert_eq!(
            private_override_set(|k| (k == "UPSTREAM_ALLOW_PRIVATE_IPS").then(|| "false".into())),
            None
        );
        assert!(user_agent().contains("never calls tools"));
        let _ = guarded_client();
    }

    #[test]
    fn sse_parsing() {
        let buf = ": keepalive\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n\
                   data: {\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"roots/list\"}\n\n\
                   data: {\"jsonrpc\":\"2.0\",\"id\":3,\r\ndata: \"result\":{\"tools\":[]}}\r\n\r\n";
        let v = sse_response(buf).unwrap().unwrap();
        assert_eq!((&v["id"], &v["result"]["tools"]), (&json!(3), &json!([])));
        // The first response is returned whatever its id: the client
        // decides whether it answers the outstanding request.
        let v = sse_response("data: {\"id\":4,\"result\":{}}\n\n")
            .unwrap()
            .unwrap();
        assert_eq!(v["id"], 4);
        assert_eq!(sse_response("data: not json\n\n"), Ok(None));
        assert_eq!(
            sse_response("data: {\"id\":3,\"result\":{}}\n\ndata: {\"id\":3,\"error\":{}}\n\n"),
            Err(Violation::DuplicateResponse)
        );
        assert_eq!(
            sse_response("data: [{\"id\":3,\"result\":{}}]\n\n"),
            Err(Violation::UnexpectedBatch)
        );
        assert_eq!(
            sse_response("data: [{\"method\":\"notifications/progress\"}]\n\n"),
            Ok(None)
        );
        assert!(valid_session_id(b"a-B_9.~!"));
        for bad in [
            &b""[..],
            b"has space",
            b"tab\there",
            "\u{e9}".as_bytes(),
            &[b'x'; 257],
        ] {
            assert!(!valid_session_id(bad), "{bad:?}");
        }
    }

    #[tokio::test]
    async fn json_and_sse_replies_headers_and_caps() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header("Mcp-Method", "server/discover"))
            .and(header("MCP-Protocol-Version", "2026-07-28"))
            // wiremock splits a request header on `,` before comparing, so
            // a list-valued header is matched as its list of values (a
            // single comma-joined value never matches).
            .and(headers(
                "Accept",
                vec!["application/json", "text/event-stream"],
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Mcp-Session-Id", "s1")
                    .set_body_json(json!({"jsonrpc": "2.0", "id": 1, "result": {"ok": true}})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(header("Mcp-Method", "tools/list"))
            // `set_body_raw`: `set_body_string` would replace the content
            // type with `text/plain` whatever header was inserted before it.
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                "data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"a\"}]}}\n\n",
                "text/event-stream",
            ))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(header("Mcp-Method", "prompts/list"))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "7"))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(header("Mcp-Method", "resources/list"))
            .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(5000)))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(header("Mcp-Method", "notifications/initialized"))
            .respond_with(ResponseTemplate::new(202))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(header("Mcp-Method", "initialize"))
            .respond_with(
                ResponseTemplate::new(302).insert_header("Location", "http://169.254.169.254/"),
            )
            .mount(&server)
            .await;

        let mut t = HttpTransport::new(test_client(), format!("{}/mcp", server.uri()), 4096);
        let r = t
            .send(
                "server/discover",
                Some("2026-07-28"),
                json!({"jsonrpc": "2.0", "id": 1, "method": "server/discover"}),
            )
            .await
            .unwrap();
        assert_eq!(
            r,
            Reply::Message(json!({"jsonrpc": "2.0", "id": 1, "result": {"ok": true}}))
        );
        let r = t
            .send(
                "tools/list",
                Some("2026-07-28"),
                json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            )
            .await
            .unwrap();
        let Reply::Message(m) = r else { panic!() };
        assert_eq!(m["result"]["tools"][0]["name"], "a");
        let r = t
            .send(
                "prompts/list",
                None,
                json!({"jsonrpc": "2.0", "id": 3, "method": "prompts/list"}),
            )
            .await
            .unwrap();
        assert_eq!(
            r,
            Reply::Status {
                status: 429,
                body: None,
                retry_after_ms: Some(7000)
            }
        );
        assert_eq!(
            t.send("resources/list", None, json!({"id": 4})).await,
            Err(TransportError::TooLarge)
        );
        assert_eq!(
            t.send("notifications/initialized", None, json!({"jsonrpc": "2.0"}))
                .await,
            Ok(Reply::Message(Value::Null))
        );
        assert_eq!(
            t.send("initialize", None, json!({"id": 5})).await,
            Err(TransportError::Redirect)
        );
        // No header but the protocol's: the request log shows no
        // Authorization or publisher header ever went out, and the session
        // id the discover answer offered was not adopted (#5451).
        for req in server.received_requests().await.unwrap() {
            assert!(req.headers.get("authorization").is_none());
            assert!(req.headers.get("mcp-session-id").is_none());
            assert!(req
                .headers
                .get("user-agent")
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("ak-mcp-introspector/"));
        }
    }

    /// A legacy server: discover is method-not-found, then `initialize`,
    /// `notifications/initialized` and `tools/list`. `session_on` lists the
    /// methods whose response carries `Mcp-Session-Id: <value>`; `sse` sends
    /// the tools/list answer as an event stream with `tools_body` as data.
    async fn legacy_server(session_on: &[(&str, &str)], tools_body: &str, sse: bool) -> MockServer {
        let server = MockServer::start().await;
        let answers = [
            (
                "server/discover",
                json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "no"}}),
            ),
            (
                "initialize",
                json!({"jsonrpc": "2.0", "id": 2, "result": {
                    "protocolVersion": "2025-06-18", "capabilities": {"tools": {}}}}),
            ),
        ];
        for (m, body) in answers {
            let mut t = ResponseTemplate::new(200).set_body_json(body);
            for (_, v) in session_on.iter().filter(|(on, _)| *on == m) {
                t = t.insert_header("Mcp-Session-Id", *v);
            }
            Mock::given(method("POST"))
                .and(header("Mcp-Method", m))
                .respond_with(t)
                .mount(&server)
                .await;
        }
        let mut t = ResponseTemplate::new(202);
        for (_, v) in session_on
            .iter()
            .filter(|(on, _)| *on == "notifications/initialized")
        {
            t = t.insert_header("Mcp-Session-Id", *v);
        }
        Mock::given(method("POST"))
            .and(header("Mcp-Method", "notifications/initialized"))
            .respond_with(t)
            .mount(&server)
            .await;
        let mut t = if sse {
            ResponseTemplate::new(200).set_body_raw(tools_body.to_string(), "text/event-stream")
        } else {
            ResponseTemplate::new(200).set_body_raw(tools_body.to_string(), "application/json")
        };
        for (_, v) in session_on.iter().filter(|(on, _)| *on == "tools/list") {
            t = t.insert_header("Mcp-Session-Id", *v);
        }
        Mock::given(method("POST"))
            .and(header("Mcp-Method", "tools/list"))
            .respond_with(t)
            .mount(&server)
            .await;
        server
    }

    const TOOLS_3: &str = r#"{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"t"}]}}"#;

    async fn run(
        server: &MockServer,
    ) -> (crate::protocol::ProbeReport, Vec<(String, Option<String>)>) {
        let mut t = HttpTransport::new(test_client(), server.uri(), 1 << 20);
        let r = crate::protocol::probe(&mut t, 1000).await;
        let sent = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .map(|q| {
                (
                    q.headers
                        .get("mcp-method")
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .to_string(),
                    q.headers
                        .get("mcp-session-id")
                        .map(|v| v.to_str().unwrap().to_string()),
                )
            })
            .collect();
        (r, sent)
    }

    fn assert_refused(r: &crate::protocol::ProbeReport, code: &str) {
        assert_eq!(r.outcome, "refused", "{r:?}");
        assert_eq!(
            r.details.get("protocolViolation"),
            Some(&json!(code)),
            "{r:?}"
        );
        assert!(r.tools.is_empty() && r.details.get("capabilities").is_none());
    }

    /// #5450 over HTTP: a tools/list answer for another id, as a JSON body
    /// or an SSE event, and two answers in one stream, all fail closed.
    #[tokio::test]
    async fn wrong_id_and_duplicate_responses_over_http() {
        let wrong = r#"{"jsonrpc":"2.0","id":"3","result":{"tools":[{"name":"evil"}]}}"#;
        let (r, _) = run(&legacy_server(&[], wrong, false).await).await;
        assert_refused(&r, "response_id_mismatch");
        let (r, _) = run(&legacy_server(&[], &format!("data: {wrong}\n\n"), true).await).await;
        assert_refused(&r, "response_id_mismatch");
        let dup = format!("data: {TOOLS_3}\n\ndata: {TOOLS_3}\n\n");
        let (r, _) = run(&legacy_server(&[], &dup, true).await).await;
        assert_refused(&r, "duplicate_response");
        let batch = format!("[{TOOLS_3}]");
        let (r, _) = run(&legacy_server(&[], &batch, false).await).await;
        assert_refused(&r, "unexpected_batch");
        // Control: the matching id, as JSON and as SSE after a notification.
        let (r, _) = run(&legacy_server(&[], TOOLS_3, false).await).await;
        assert_eq!((r.outcome.as_str(), r.tools.len()), ("ok", 1), "{r:?}");
        let sse = format!(
            "data: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}}\n\ndata: {TOOLS_3}\n\n"
        );
        let (r, _) = run(&legacy_server(&[], &sse, true).await).await;
        assert_eq!((r.outcome.as_str(), r.tools.len()), ("ok", 1), "{r:?}");
    }

    /// #5451: a session id offered before `initialize` is never adopted or
    /// echoed; one introduced after it without a session is ignored too.
    #[tokio::test]
    async fn session_id_outside_initialize_is_ignored() {
        let server = legacy_server(
            &[("server/discover", "pre-init"), ("tools/list", "late")],
            TOOLS_3,
            false,
        )
        .await;
        let (r, sent) = run(&server).await;
        assert_eq!(r.outcome, "ok", "{r:?}");
        assert_eq!(sent.len(), 4);
        assert!(sent.iter().all(|(_, s)| s.is_none()), "{sent:?}");
    }

    /// #5451: a session established by `initialize` cannot be replaced.
    #[tokio::test]
    async fn session_id_replacement_fails_closed() {
        for on in ["notifications/initialized", "tools/list"] {
            let server = legacy_server(&[("initialize", "s1"), (on, "s2")], TOOLS_3, false).await;
            let (r, sent) = run(&server).await;
            assert_refused(&r, "session_id_changed");
            assert!(
                sent.iter().all(|(_, s)| s.as_deref() != Some("s2")),
                "{on}: the replacement is never sent: {sent:?}"
            );
        }
        let server = legacy_server(&[("initialize", "bad id")], TOOLS_3, false).await;
        assert_refused(&run(&server).await.0, "session_id_invalid");
    }

    /// The benign control: a stable session, echoed on every response, is
    /// sent on every request after `initialize` and on none before.
    #[tokio::test]
    async fn stable_session_is_used_after_initialize() {
        let server = legacy_server(
            &[
                ("initialize", "s1"),
                ("notifications/initialized", "s1"),
                ("tools/list", "s1"),
            ],
            TOOLS_3,
            false,
        )
        .await;
        let (r, sent) = run(&server).await;
        assert_eq!((r.outcome.as_str(), r.tools.len()), ("ok", 1), "{r:?}");
        let got: Vec<(&str, Option<&str>)> = sent
            .iter()
            .map(|(m, s)| (m.as_str(), s.as_deref()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("server/discover", None),
                ("initialize", None),
                ("notifications/initialized", Some("s1")),
                ("tools/list", Some("s1")),
            ]
        );
    }

    /// MCP Python SDK v1.x (FastMCP) streamable HTTP: a pre-initialize
    /// request is answered `400` with `"id": "server-error"` (stateful:
    /// missing session; stateless: unsupported `MCP-Protocol-Version`) and an
    /// unrelated session header. That is an HTTP-level error, so the probe
    /// falls back to `initialize` (SSE, assigning the session) and succeeds.
    #[tokio::test]
    async fn python_sdk_v1_pre_initialize_400_falls_back() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header("Mcp-Method", "server/discover"))
            .respond_with(
                ResponseTemplate::new(400)
                    .insert_header("Mcp-Session-Id", "orphan")
                    .set_body_raw(
                        r#"{"jsonrpc":"2.0","id":"server-error","error":{"code":-32600,"message":"Bad Request: Missing session ID"}}"#,
                        "application/json",
                    ),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(header("Mcp-Method", "initialize"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Mcp-Session-Id", "s1")
                    .set_body_raw(
                        "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{\"tools\":{}}}}\n\n",
                        "text/event-stream",
                    ),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(header("Mcp-Method", "notifications/initialized"))
            .respond_with(ResponseTemplate::new(202).insert_header("Mcp-Session-Id", "s1"))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(header("Mcp-Method", "tools/list"))
            .and(header("Mcp-Session-Id", "s1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Mcp-Session-Id", "s1")
                    .set_body_raw(
                        format!("data: [{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}}]\n\ndata: {TOOLS_3}\n\n"),
                        "text/event-stream",
                    ),
            )
            .mount(&server)
            .await;
        let (r, sent) = run(&server).await;
        assert_eq!((r.outcome.as_str(), r.tools.len()), ("ok", 1), "{r:?}");
        assert!(
            sent.iter().all(|(_, s)| s.as_deref() != Some("orphan")),
            "{sent:?}"
        );
    }

    /// An SSE response split across chunks (mid-event and mid-line, with a
    /// notification before it) is assembled and accepted; the stream stays
    /// open after it and is not read further.
    #[tokio::test]
    async fn sse_response_split_across_chunks() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let _ = sock.read(&mut buf).await.unwrap();
            let head = "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n\
                        transfer-encoding: chunked\r\n\r\n";
            sock.write_all(head.as_bytes()).await.unwrap();
            for part in [
                "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\nda",
                "ta: {\"jsonrpc\":\"2.0\",\"id\":3,",
                "\"result\":{\"tools\":[{\"name\":\"t\"}]}}\n",
                "\n",
            ] {
                sock.write_all(format!("{:x}\r\n{part}\r\n", part.len()).as_bytes())
                    .await
                    .unwrap();
                sock.flush().await.unwrap();
                tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            }
            // Keep the stream open: the reader must stop at the response.
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        });
        let mut t = HttpTransport::new(test_client(), format!("http://{addr}/mcp"), 1 << 20);
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            t.send(
                "tools/list",
                None,
                json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}),
            ),
        )
        .await
        .expect("the reader stops at the response")
        .unwrap();
        let Reply::Message(m) = r else {
            panic!("{r:?}")
        };
        assert_eq!(
            (&m["id"], &m["result"]["tools"][0]["name"]),
            (&json!(3), &json!("t"))
        );
        srv.abort();
    }

    /// A redirect from `initialize` is refused before its headers are read:
    /// its session id is not adopted and nothing reaches the other origin.
    #[tokio::test]
    async fn session_never_follows_a_redirect() {
        let other = MockServer::start().await;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header("Mcp-Method", "initialize"))
            .respond_with(
                ResponseTemplate::new(307)
                    .insert_header("Mcp-Session-Id", "s1")
                    .insert_header("Location", format!("{}/mcp", other.uri())),
            )
            .mount(&server)
            .await;
        let mut t = HttpTransport::new(test_client(), server.uri(), 1 << 20);
        assert_eq!(
            t.send(
                "initialize",
                None,
                json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
            )
            .await,
            Err(TransportError::Redirect)
        );
        assert_eq!(t.session, None);
        assert!(other.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn full_probe_over_http() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header("Mcp-Method", "server/discover"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0", "id": 1,
                "result": {"supportedVersions": ["2026-07-28"], "capabilities": {"tools": {}}, "ttlMs": 1000}
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(header("Mcp-Method", "tools/list"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0", "id": 2, "result": {"tools": [{"name": "w", "inputSchema": {"type": "object"}}]}
            })))
            .mount(&server)
            .await;
        let mut t = HttpTransport::new(test_client(), server.uri(), 1 << 20);
        let r = crate::protocol::probe(&mut t, 1000).await;
        assert_eq!(r.outcome, "ok", "{:?}", r.error);
        assert_eq!(r.tools[0]["name"], "w");
        assert_eq!(r.ttl_ms, Some(1000));
    }
}
