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

use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt;
use serde_json::Value;

use crate::protocol::{Reply, Transport, TransportError};

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
}

impl HttpTransport {
    pub fn new(client: reqwest::Client, url: impl Into<String>, max_bytes: usize) -> Self {
        Self {
            client,
            url: url.into(),
            max_bytes,
            session: None,
        }
    }
}

/// Parse `data:` payloads of complete SSE events in `buf`; returns the
/// JSON-RPC response with `id` once it arrived.
pub fn sse_response(buf: &str, id: &Value) -> Option<Value> {
    let normalized = buf.replace("\r\n", "\n");
    for event in normalized.split("\n\n") {
        let data: Vec<&str> = event
            .lines()
            .filter_map(|l| l.strip_prefix("data:"))
            .map(|d| d.strip_prefix(' ').unwrap_or(d))
            .collect();
        if data.is_empty() {
            continue;
        }
        if let Ok(v) = serde_json::from_str::<Value>(&data.join("\n")) {
            if v.get("id") == Some(id) && (v.get("result").is_some() || v.get("error").is_some()) {
                return Some(v);
            }
        }
    }
    None
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
        if let Some(s) = resp
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
        {
            if s.len() <= 256 {
                self.session = Some(s.to_string());
            }
        }
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
            if sse && status.is_success() {
                if let Some(id) = &id {
                    if let Some(v) = sse_response(&String::from_utf8_lossy(&body), id) {
                        return Ok(Reply::Message(v));
                    }
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
        let Some(id) = id else {
            return Ok(Reply::Message(Value::Null));
        };
        if sse {
            return sse_response(&String::from_utf8_lossy(&body), &id)
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
    use wiremock::matchers::{header, header_exists, method};
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
        let id = json!(3);
        let buf = ": keepalive\n\nevent: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n\
                   data: {\"jsonrpc\":\"2.0\",\"id\":3,\r\ndata: \"result\":{\"tools\":[]}}\r\n\r\n";
        assert_eq!(
            sse_response(buf, &id).unwrap()["result"]["tools"],
            json!([])
        );
        assert!(sse_response("data: {\"id\":4,\"result\":{}}\n\n", &id).is_none());
        assert!(sse_response("data: not json\n\n", &id).is_none());
    }

    #[tokio::test]
    async fn json_and_sse_replies_headers_and_caps() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header("Mcp-Method", "server/discover"))
            .and(header("MCP-Protocol-Version", "2026-07-28"))
            .and(header("Accept", "application/json, text/event-stream"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("Mcp-Session-Id", "s1")
                    .set_body_json(json!({"jsonrpc": "2.0", "id": 1, "result": {"ok": true}})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(header("Mcp-Method", "tools/list"))
            .and(header_exists("Mcp-Session-Id"))
            .respond_with(ResponseTemplate::new(200).insert_header("content-type", "text/event-stream").set_body_string(
                "data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"a\"}]}}\n\n",
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
        // Authorization or publisher header ever went out.
        for req in server.received_requests().await.unwrap() {
            assert!(req.headers.get("authorization").is_none());
            assert!(req
                .headers
                .get("user-agent")
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("ak-mcp-introspector/"));
        }
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
