//! stdio transport: newline-delimited JSON-RPC over a child's stdin/stdout
//! (the sandbox guest). Server-to-client requests a legacy server sends
//! (`roots/list`, `sampling/createMessage`, `elicitation/create`) are
//! answered with "method not found"; notifications are ignored; anything
//! that is not JSON is skipped. Every read is capped in bytes and bounded by
//! a per-message timeout.

use std::time::Duration;

use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::protocol::{Reply, Transport, TransportError};

pub struct StdioTransport<R, W> {
    reader: BufReader<R>,
    writer: W,
    pub message_timeout: Duration,
    pub max_bytes: usize,
    /// Bytes read so far over the whole run (all messages share the cap).
    read_total: usize,
}

impl<R: AsyncRead + Unpin + Send, W: AsyncWrite + Unpin + Send> StdioTransport<R, W> {
    pub fn new(reader: R, writer: W, message_timeout: Duration, max_bytes: usize) -> Self {
        Self {
            reader: BufReader::new(reader),
            writer,
            message_timeout,
            max_bytes,
            read_total: 0,
        }
    }

    async fn write_line(&mut self, v: &Value) -> Result<(), TransportError> {
        let mut line = serde_json::to_vec(v).unwrap_or_default();
        line.push(b'\n');
        self.writer
            .write_all(&line)
            .await
            .map_err(|_| TransportError::Closed)?;
        self.writer
            .flush()
            .await
            .map_err(|_| TransportError::Closed)
    }

    async fn read_reply(&mut self, id: &Value) -> Result<Value, TransportError> {
        use tokio::io::AsyncReadExt;
        loop {
            // Bound the read itself, not only what was read: a line with no
            // newline must not grow past the cap before it is checked.
            let remaining = self.max_bytes.saturating_sub(self.read_total);
            let mut line = Vec::new();
            let n = (&mut self.reader)
                .take(remaining as u64 + 1)
                .read_until(b'\n', &mut line)
                .await
                .map_err(|e| TransportError::Io(e.to_string()))?;
            if n == 0 {
                return Err(TransportError::Closed);
            }
            self.read_total += n;
            if self.read_total > self.max_bytes {
                return Err(TransportError::TooLarge);
            }
            let Ok(msg) = serde_json::from_slice::<Value>(line.trim_ascii()) else {
                continue;
            };
            let is_request = msg.get("method").is_some() && msg.get("id").is_some();
            if is_request {
                let reply = json!({
                    "jsonrpc": "2.0", "id": msg["id"],
                    "error": {"code": -32601, "message": "not supported by ak-mcp-introspector"},
                });
                self.write_line(&reply).await?;
                continue;
            }
            if msg.get("id") == Some(id) {
                return Ok(msg);
            }
        }
    }
}

#[async_trait]
impl<R: AsyncRead + Unpin + Send, W: AsyncWrite + Unpin + Send> Transport for StdioTransport<R, W> {
    async fn send(
        &mut self,
        _method: &str,
        _protocol_version: Option<&str>,
        msg: Value,
    ) -> Result<Reply, TransportError> {
        self.write_line(&msg).await?;
        let Some(id) = msg.get("id").cloned() else {
            return Ok(Reply::Message(Value::Null));
        };
        match tokio::time::timeout(self.message_timeout, self.read_reply(&id)).await {
            Ok(r) => r.map(Reply::Message),
            Err(_) => Err(TransportError::Timeout),
        }
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncBufReadExt, AsyncWriteExt, BufReader};

    /// An in-process legacy MCP server over a duplex pipe: answers
    /// `server/discover` with an error, then speaks 2025-06-18, and sends a
    /// `roots/list` request and noise before its answers.
    async fn fake_server(io: tokio::io::DuplexStream) -> Vec<String> {
        let (r, mut w) = tokio::io::split(io);
        let mut lines = BufReader::new(r).lines();
        let mut seen = Vec::new();
        while let Ok(Some(line)) = lines.next_line().await {
            let msg: Value = serde_json::from_str(&line).unwrap();
            let method = msg["method"].as_str().unwrap_or("<reply>").to_string();
            seen.push(method.clone());
            let id = msg["id"].clone();
            let out = match method.as_str() {
                "server/discover" => {
                    json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "no"}})
                }
                "initialize" => json!({"jsonrpc": "2.0", "id": id, "result": {
                    "protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "f"}}}),
                "tools/list" => {
                    w.write_all(b"not json\n").await.unwrap();
                    w.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"roots/list\"}\n")
                        .await
                        .unwrap();
                    w.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\"}\n")
                        .await
                        .unwrap();
                    json!({"jsonrpc": "2.0", "id": id, "result": {"tools": [{"name": "t"}]}})
                }
                _ => continue,
            };
            let mut b = serde_json::to_vec(&out).unwrap();
            b.push(b'\n');
            w.write_all(&b).await.unwrap();
        }
        seen
    }

    #[tokio::test]
    async fn probe_over_stdio_with_legacy_server() {
        let (client, server) = duplex(64 * 1024);
        let handle = tokio::spawn(fake_server(server));
        let (r, w) = tokio::io::split(client);
        let mut t = StdioTransport::new(r, w, Duration::from_secs(5), 1 << 20);
        let report = crate::protocol::probe(&mut t, 100).await;
        assert_eq!(report.outcome, "ok", "{:?}", report.error);
        assert_eq!(report.protocol_version.as_deref(), Some("2025-06-18"));
        assert_eq!(report.tools[0]["name"], "t");
        drop(t);
        let seen = handle.await.unwrap();
        assert!(
            seen.contains(&"<reply>".to_string()),
            "roots/list was answered: {seen:?}"
        );
        assert!(!seen.iter().any(|m| m == "tools/call"));
    }

    #[tokio::test]
    async fn timeout_closed_and_cap() {
        let (client, _server) = duplex(1024);
        let (r, w) = tokio::io::split(client);
        let mut t = StdioTransport::new(r, w, Duration::from_millis(50), 1024);
        assert_eq!(
            t.send("tools/list", None, json!({"id": 1})).await,
            Err(TransportError::Timeout)
        );
        assert_eq!(
            t.send("n", None, json!({"jsonrpc": "2.0"})).await,
            Ok(Reply::Message(Value::Null))
        );

        let (client, server) = duplex(1024);
        drop(server);
        let (r, w) = tokio::io::split(client);
        let mut t = StdioTransport::new(r, w, Duration::from_secs(1), 1024);
        assert_eq!(
            t.send("x", None, json!({"id": 1})).await,
            Err(TransportError::Closed)
        );

        let (client, server) = duplex(64 * 1024);
        tokio::spawn(async move {
            let (_r, mut w) = tokio::io::split(server);
            let _ = w
                .write_all(format!("{}\n", "y".repeat(4000)).as_bytes())
                .await;
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
        let (r, w) = tokio::io::split(client);
        let mut t = StdioTransport::new(r, w, Duration::from_secs(1), 1024);
        assert_eq!(
            t.send("x", None, json!({"id": 1})).await,
            Err(TransportError::TooLarge)
        );
    }

    /// A line with no newline is cut off at the cap, not buffered until it
    /// ends: 8 MiB of `a` and then silence is `TooLarge` at once, having
    /// read at most the cap plus one byte (and never a timeout after
    /// buffering all of it).
    #[tokio::test]
    async fn an_endless_line_is_cut_at_the_cap() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        /// Counts the bytes the transport pulled from the guest.
        struct Counting<R>(R, Arc<AtomicUsize>);
        impl<R: AsyncRead + Unpin> AsyncRead for Counting<R> {
            fn poll_read(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<std::io::Result<()>> {
                let before = buf.filled().len();
                let r = std::pin::Pin::new(&mut self.0).poll_read(cx, buf);
                self.1
                    .fetch_add(buf.filled().len() - before, Ordering::Relaxed);
                r
            }
        }

        use tokio::io::AsyncReadExt;
        // The pipe stays open (and silent) after the flood.
        let (_keep, silent) = duplex(8);
        let flood = tokio::io::repeat(b'a').take(8 << 20).chain(silent);
        let pulled = Arc::new(AtomicUsize::new(0));
        let cap = 64 * 1024;
        let mut t = StdioTransport::new(
            Counting(flood, pulled.clone()),
            tokio::io::sink(),
            Duration::from_secs(5),
            cap,
        );
        assert_eq!(
            t.send("tools/list", None, json!({"id": 1})).await,
            Err(TransportError::TooLarge)
        );
        // BufReader reads ahead by at most its buffer (8 KiB).
        assert!(
            pulled.load(Ordering::Relaxed) <= cap + 1 + 8 * 1024,
            "read {} bytes for a {cap} byte cap",
            pulled.load(Ordering::Relaxed)
        );
    }
}
