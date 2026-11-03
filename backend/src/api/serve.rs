//! HTTP accept loop with a header-read timeout (#4665).
//!
//! `axum::serve` (0.7) builds each hyper connection without a timer, so hyper
//! applies no header-read timeout at all: a client that connects and then
//! trickles the request line and headers one byte at a time holds the socket,
//! and the task serving it, for as long as it keeps trickling. This module is
//! the same accept loop (one `hyper_util` auto connection per TCP stream,
//! HTTP/1 with upgrades and HTTP/2 prior knowledge, graceful shutdown on a
//! signal) with a [`TokioTimer`] and `header_read_timeout` set on the HTTP/1
//! side.
//!
//! hyper's timer only starts once its HTTP/1 parser runs, and the auto builder
//! first waits, with no deadline, for enough bytes to tell HTTP/1 from the
//! HTTP/2 preface. A connection that sends nothing (or only part of the
//! preface) is therefore given the same deadline here before hyper sees it.
//!
//! Every connection closed by either deadline while a request head was
//! outstanding increments `ak_http_header_read_timeouts_total`. hyper also
//! uses the header-read timer to close idle keep-alive connections; those are
//! normal and are not counted. `ak_http_connections_open` is the number of
//! accepted connections whose task has not finished (#4676).

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::extract::connect_info::Connected;
use axum::response::Response;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio::sync::watch;
use tower::{Service, ServiceExt};

/// The HTTP/2 connection preface (RFC 9113 §3.4). The auto builder reads up
/// to this many bytes before it picks HTTP/1 or HTTP/2.
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Pause between peeks while a client has sent only a prefix of the HTTP/2
/// preface. Peeking returns at once when bytes are buffered, so without a
/// pause that wait would spin.
const PREFACE_PEEK_INTERVAL: Duration = Duration::from_millis(5);

/// What the make-service is called with for each accepted connection. The
/// `Connected` impl below lets `into_make_service_with_connect_info::<SocketAddr>()`
/// inject the TCP peer as `ConnectInfo<SocketAddr>`, exactly as `axum::serve`
/// does (#2023).
#[derive(Debug, Clone, Copy)]
pub struct IncomingConnection {
    remote_addr: SocketAddr,
}

impl IncomingConnection {
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

impl Connected<IncomingConnection> for SocketAddr {
    fn connect_info(target: IncomingConnection) -> Self {
        target.remote_addr
    }
}

/// Bind the API listener (#4647). `backlog` is the accept-queue length
/// (`HTTP_LISTEN_BACKLOG`); `None` binds exactly as `TcpListener::bind` does,
/// which on Linux asks for the OS maximum (`net.core.somaxconn`).
pub async fn bind_listener(addr: SocketAddr, backlog: Option<u32>) -> io::Result<TcpListener> {
    let Some(backlog) = backlog else {
        return TcpListener::bind(addr).await;
    };
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    // `TcpListener::bind` sets SO_REUSEADDR on Unix; keep that so a restart
    // can rebind while old connections sit in TIME_WAIT.
    #[cfg(unix)]
    socket.set_reuseaddr(true)?;
    socket.bind(addr)?;
    socket.listen(backlog)
}

/// The accept-queue length the kernel grants: Linux caps any request,
/// including the "OS maximum" default, at `net.core.somaxconn`.
pub fn effective_listen_backlog(requested: Option<u32>, somaxconn: Option<u32>) -> Option<u32> {
    match (requested, somaxconn) {
        (Some(requested), Some(cap)) => Some(requested.min(cap)),
        (Some(requested), None) => Some(requested),
        (None, cap) => cap,
    }
}

/// `net.core.somaxconn` for this network namespace, where it can be read.
pub fn read_somaxconn() -> Option<u32> {
    std::fs::read_to_string("/proc/sys/net/core/somaxconn")
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Serve `make_service` on `listener` until `shutdown` resolves, then stop
/// accepting and wait for in-flight connections to finish.
///
/// `header_read_timeout` bounds how long an HTTP/1 client may take to send a
/// complete request head; `None` disables it (the `axum::serve` behaviour).
pub async fn serve<M, S, F>(
    listener: TcpListener,
    mut make_service: M,
    header_read_timeout: Option<Duration>,
    shutdown: F,
) -> io::Result<()>
where
    M: Service<IncomingConnection, Response = S, Error = Infallible>,
    S: Service<axum::extract::Request, Response = Response, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    // Same shape as axum's graceful shutdown: dropping `signal_rx` closes
    // `signal_tx`, which every connection task watches; each task holds a
    // `close_rx` clone, so `close_tx.closed()` resolves once all are done.
    let (signal_tx, signal_rx) = watch::channel(());
    let signal_tx = Arc::new(signal_tx);
    tokio::spawn(async move {
        shutdown.await;
        drop(signal_rx);
    });
    let (close_tx, close_rx) = watch::channel(());

    loop {
        let (stream, remote_addr) = tokio::select! {
            accepted = accept(&listener) => match accepted {
                Some(conn) => conn,
                None => continue,
            },
            _ = signal_tx.closed() => break,
        };

        std::future::poll_fn(|cx| make_service.poll_ready(cx))
            .await
            .unwrap_or_else(|err| match err {});
        let tower_service = make_service
            .call(IncomingConnection { remote_addr })
            .await
            .unwrap_or_else(|err| match err {})
            .map_request(|req: hyper::Request<Incoming>| req.map(axum::body::Body::new));

        let signal_tx = Arc::clone(&signal_tx);
        let close_rx = close_rx.clone();
        // `ak_http_connections_open` (#4676), released when the task ends.
        let open = crate::services::metrics_service::OpenConnectionGuard::open();
        tokio::spawn(async move {
            let _open = open;
            serve_connection(stream, tower_service, header_read_timeout, signal_tx).await;
            tracing::trace!("connection {remote_addr} closed");
            drop(close_rx);
        });
    }

    drop(close_rx);
    drop(listener);
    close_tx.closed().await;
    Ok(())
}

async fn serve_connection<S>(
    stream: TcpStream,
    service: S,
    header_read_timeout: Option<Duration>,
    signal_tx: Arc<watch::Sender<()>>,
) where
    S: Service<hyper::Request<Incoming>, Response = Response, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    if let Some(timeout) = header_read_timeout {
        match tokio::time::timeout(timeout, await_protocol_bytes(&stream)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return,
            Err(_) => {
                record_header_read_timeout();
                return;
            }
        }
    }

    let head_pending = Arc::new(AtomicBool::new(false));
    let io = TokioIo::new(RequestHeadTracker {
        inner: stream,
        head_pending: Arc::clone(&head_pending),
    });

    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(header_read_timeout);
    let conn = builder.serve_connection_with_upgrades(io, TowerToHyperService::new(service));
    tokio::pin!(conn);

    let mut signal_closed = std::pin::pin!(signal_tx.closed());
    let mut shutting_down = false;
    let result = loop {
        tokio::select! {
            result = conn.as_mut() => break result,
            _ = &mut signal_closed, if !shutting_down => {
                shutting_down = true;
                conn.as_mut().graceful_shutdown();
            }
        }
    };

    if let Err(err) = result {
        if is_header_read_timeout(err.as_ref()) {
            if head_pending.load(Ordering::Relaxed) {
                record_header_read_timeout();
            } else {
                tracing::trace!("idle keep-alive connection closed by the header-read timeout");
            }
        } else {
            tracing::trace!("failed to serve connection: {err:#}");
        }
    }
}

/// Wait until the client has sent enough for the auto builder to choose a
/// protocol: one byte that rules out the HTTP/2 preface, or the whole
/// preface. Peeks, so hyper still reads every byte. An EOF returns `Ok` and
/// hyper sees the close.
async fn await_protocol_bytes(stream: &TcpStream) -> io::Result<()> {
    let mut buf = [0u8; H2_PREFACE.len()];
    loop {
        let n = stream.peek(&mut buf).await?;
        if n == 0 || n == H2_PREFACE.len() || !H2_PREFACE.starts_with(&buf[..n]) {
            return Ok(());
        }
        tokio::time::sleep(PREFACE_PEEK_INTERVAL).await;
    }
}

/// Whether a connection error is hyper's HTTP/1 header-read timeout.
fn is_header_read_timeout(err: &(dyn std::error::Error + 'static)) -> bool {
    err.downcast_ref::<hyper::Error>()
        .is_some_and(hyper::Error::is_timeout)
}

fn record_header_read_timeout() {
    crate::services::metrics_service::record_http_header_read_timeout();
}

/// Accept one connection with `TCP_NODELAY` set. Mirrors `axum::serve`:
/// per-connection errors are skipped, anything else (e.g. `EMFILE`) is logged
/// and retried after a second so a full fd table does not spin the loop.
async fn accept(listener: &TcpListener) -> Option<(TcpStream, SocketAddr)> {
    match listener.accept().await {
        Ok((stream, remote_addr)) => {
            // Without this, the second of two small writes (a response head,
            // then a small streamed body) waits for the peer's delayed ACK of
            // the first, about 40 ms on Linux (#5139). Serving still works if
            // the option cannot be set, so the connection is kept.
            if let Err(e) = stream.set_nodelay(true) {
                tracing::debug!("failed to set TCP_NODELAY for {remote_addr}: {e}");
            }
            Some((stream, remote_addr))
        }
        Err(e) => {
            if matches!(
                e.kind(),
                io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionReset
            ) {
                return None;
            }
            tracing::error!("accept error: {e}");
            tokio::time::sleep(Duration::from_secs(1)).await;
            None
        }
    }
}

/// A `TcpStream` that records whether the client has sent bytes since the
/// server last wrote a response. When the header-read timeout fires with that
/// flag set, a request head was in flight (a slow or stalled client); when it
/// is clear, the connection was an idle keep-alive one.
struct RequestHeadTracker {
    inner: TcpStream,
    head_pending: Arc<AtomicBool>,
}

impl AsyncRead for RequestHeadTracker {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(poll, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.head_pending.store(true, Ordering::Relaxed);
        }
        poll
    }
}

impl AsyncWrite for RequestHeadTracker {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.head_pending.store(false, Ordering::Relaxed);
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.head_pending.store(false, Ordering::Relaxed);
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use axum::Router;
    use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::sync::CancellationToken;

    const TIMEOUT: Duration = Duration::from_millis(300);
    /// Generous upper bound for "closed within the timeout" on a loaded CI
    /// runner; the point is that the close happens at all, and long before
    /// the half-sent client would give up.
    const CLOSE_BOUND: Duration = Duration::from_secs(5);

    async fn start(timeout: Option<Duration>) -> (SocketAddr, CancellationToken) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .route(
                "/peer",
                get(
                    |axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>| async move {
                        peer.ip().to_string()
                    },
                ),
            );
        let token = CancellationToken::new();
        let shutdown = token.clone();
        tokio::spawn(serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
            timeout,
            async move { shutdown.cancelled().await },
        ));
        (addr, token)
    }

    /// Read until EOF and report how long it took, or `None` if the server
    /// kept the connection open past `CLOSE_BOUND`.
    async fn time_until_closed(stream: &mut TcpStream) -> Option<(Duration, Vec<u8>)> {
        let started = Instant::now();
        let mut buf = Vec::new();
        match tokio::time::timeout(CLOSE_BOUND, stream.read_to_end(&mut buf)).await {
            Ok(_) => Some((started.elapsed(), buf)),
            Err(_) => None,
        }
    }

    fn header_timeouts(snapshotter: &Snapshotter) -> u64 {
        snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .find(|(key, ..)| key.key().name() == "ak_http_header_read_timeouts_total")
            .map(|(.., value)| match value {
                DebugValue::Counter(n) => n,
                other => panic!("expected a counter, got {other:?}"),
            })
            .unwrap_or(0)
    }

    #[tokio::test]
    async fn a_half_sent_request_is_closed_within_the_timeout() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        // Current-thread runtime: the spawned connection tasks run on this
        // thread and see the local recorder.
        let _guard = metrics::set_default_local_recorder(&recorder);

        let (addr, token) = start(Some(TIMEOUT)).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nX-Slow: ")
            .await
            .unwrap();

        let (elapsed, _) = time_until_closed(&mut stream)
            .await
            .expect("a half-sent request head must be closed by the server");
        assert!(elapsed >= TIMEOUT / 2, "closed too early: {elapsed:?}");
        assert_eq!(header_timeouts(&snapshotter), 1);
        token.cancel();
    }

    #[tokio::test]
    async fn a_silent_connection_is_closed_within_the_timeout() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = metrics::set_default_local_recorder(&recorder);

        let (addr, token) = start(Some(TIMEOUT)).await;
        // Nothing sent at all, and separately only part of the HTTP/2
        // preface: both stall hyper's protocol detection, before its own
        // header timer starts.
        let mut silent = TcpStream::connect(addr).await.unwrap();
        let mut partial_preface = TcpStream::connect(addr).await.unwrap();
        partial_preface.write_all(b"PRI * HT").await.unwrap();

        assert!(time_until_closed(&mut silent).await.is_some());
        assert!(time_until_closed(&mut partial_preface).await.is_some());
        assert_eq!(header_timeouts(&snapshotter), 2);
        token.cancel();
    }

    #[tokio::test]
    async fn a_complete_request_is_served_and_idle_keep_alive_is_not_counted() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = metrics::set_default_local_recorder(&recorder);

        let (addr, token) = start(Some(TIMEOUT)).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /peer HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        // The connection stays open for keep-alive and is then closed by the
        // same timer; the response must have been delivered first.
        let (_, body) = time_until_closed(&mut stream)
            .await
            .expect("an idle keep-alive connection is closed by the timer");
        let body = String::from_utf8_lossy(&body);
        assert!(body.starts_with("HTTP/1.1 200"), "got {body}");
        // ConnectInfo<SocketAddr> is wired through `IncomingConnection`.
        assert!(body.ends_with("127.0.0.1"), "got {body}");
        assert_eq!(
            header_timeouts(&snapshotter),
            0,
            "an idle keep-alive close is not a header-read timeout"
        );
        token.cancel();
    }

    #[tokio::test]
    async fn without_a_timeout_a_half_sent_request_is_held_open() {
        let (addr, token) = start(None).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(b"GET / HTTP/1.1\r\nHost").await.unwrap();
        let mut buf = [0u8; 1];
        let held = tokio::time::timeout(TIMEOUT * 3, stream.read(&mut buf)).await;
        assert!(held.is_err(), "with the timeout off the server waits");
        token.cancel();
    }

    /// `ak_http_connections_open` as of now. A debugging snapshot drains
    /// what it reports, so the reads are summed into `seen`.
    fn open_connections(snapshotter: &Snapshotter, seen: &mut f64) -> f64 {
        *seen += snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .find(|(key, ..)| key.key().name() == "ak_http_connections_open")
            .map(|(.., value)| match value {
                DebugValue::Gauge(n) => n.into_inner(),
                other => panic!("expected a gauge, got {other:?}"),
            })
            .unwrap_or(0.0);
        *seen
    }

    /// Poll until `ak_http_connections_open` reads `want`, or give up.
    async fn await_open_connections(snapshotter: &Snapshotter, seen: &mut f64, want: f64) -> f64 {
        let deadline = Instant::now() + CLOSE_BOUND;
        loop {
            let now = open_connections(snapshotter, seen);
            if now == want || Instant::now() > deadline {
                return now;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// #4676: `ak_http_connections_open` counts accepted connections until
    /// their task ends, however the client leaves.
    #[tokio::test]
    async fn open_connections_gauge_tracks_accepted_connections_4676() {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        let _guard = metrics::set_default_local_recorder(&recorder);
        let mut seen = 0.0;

        let (addr, token) = start(None).await;
        // A held connection that has sent half a request head, and an idle one.
        let mut slow = TcpStream::connect(addr).await.unwrap();
        slow.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n")
            .await
            .unwrap();
        let idle = TcpStream::connect(addr).await.unwrap();
        assert_eq!(
            await_open_connections(&snapshotter, &mut seen, 2.0).await,
            2.0
        );

        drop(idle);
        assert_eq!(
            await_open_connections(&snapshotter, &mut seen, 1.0).await,
            1.0
        );
        drop(slow);
        assert_eq!(
            await_open_connections(&snapshotter, &mut seen, 0.0).await,
            0.0
        );
        token.cancel();
    }

    #[tokio::test]
    async fn http2_prior_knowledge_still_negotiates() {
        let (addr, token) = start(Some(TIMEOUT)).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        // Preface plus an empty SETTINGS frame; the server must answer with
        // its own SETTINGS frame (type 0x4) rather than an HTTP/1 400.
        stream.write_all(H2_PREFACE).await.unwrap();
        stream
            .write_all(&[0, 0, 0, 0x4, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut head = [0u8; 9];
        tokio::time::timeout(CLOSE_BOUND, stream.read_exact(&mut head))
            .await
            .expect("server answers the preface")
            .unwrap();
        assert_eq!(head[3], 0x4, "expected a SETTINGS frame, got {head:?}");
        token.cancel();
    }

    #[tokio::test]
    async fn shutdown_stops_the_server() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let token = CancellationToken::new();
        let shutdown = token.clone();
        let server = tokio::spawn(serve(
            listener,
            Router::new().into_make_service(),
            Some(TIMEOUT),
            async move { shutdown.cancelled().await },
        ));
        token.cancel();
        tokio::time::timeout(CLOSE_BOUND, server)
            .await
            .expect("serve returns after the shutdown signal")
            .unwrap()
            .unwrap();
    }

    /// #5139: every accepted socket has Nagle off. A response head and a small
    /// streamed body go out as two writes; with Nagle on, the second waits for
    /// the ACK of the first, which the peer delays by ~40 ms. The latency itself
    /// depends on the peer's delayed-ACK state and is too timing-sensitive to
    /// assert here, so this pins the socket option that removes it.
    #[tokio::test]
    async fn accepted_connections_disable_nagle_5139() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, _) = accept(&listener).await.expect("connection accepted");
        assert!(
            stream.nodelay().unwrap(),
            "accepted connections must set TCP_NODELAY"
        );
    }

    #[test]
    fn only_hyper_header_timeouts_are_classified_as_such() {
        let io_err = io::Error::new(io::ErrorKind::TimedOut, "x");
        assert!(!is_header_read_timeout(&io_err));
    }

    /// #4647: `HTTP_LISTEN_BACKLOG` reaches the kernel. A listener nobody
    /// accepts from completes `backlog + 1` handshakes (Linux holds one more
    /// than the configured length); the next SYN is dropped, so its connect
    /// hangs rather than being refused. Without the setting the listener keeps
    /// the OS maximum (`net.core.somaxconn`), so the same burst all connects.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn listen_backlog_is_applied_4647() {
        use std::time::Duration;
        async fn connected(addr: SocketAddr, n: usize) -> usize {
            let mut held = Vec::new();
            for _ in 0..n {
                match tokio::time::timeout(Duration::from_millis(300), TcpStream::connect(addr))
                    .await
                {
                    Ok(Ok(stream)) => held.push(stream),
                    _ => break,
                }
            }
            held.len()
        }
        let any = SocketAddr::from(([127, 0, 0, 1], 0));

        let small = bind_listener(any, Some(1)).await.expect("bind backlog 1");
        assert_eq!(
            connected(small.local_addr().unwrap(), 6).await,
            2,
            "backlog 1 queues exactly two un-accepted connections"
        );

        let default = bind_listener(any, None).await.expect("bind default");
        assert_eq!(
            connected(default.local_addr().unwrap(), 32).await,
            32,
            "the default keeps the OS maximum"
        );
    }

    #[test]
    fn effective_listen_backlog_is_capped_by_somaxconn_4647() {
        assert_eq!(effective_listen_backlog(None, Some(4096)), Some(4096));
        assert_eq!(effective_listen_backlog(Some(1024), Some(4096)), Some(1024));
        assert_eq!(effective_listen_backlog(Some(8192), Some(4096)), Some(4096));
        assert_eq!(effective_listen_backlog(Some(512), None), Some(512));
        assert_eq!(effective_listen_backlog(None, None), None);
    }
}
