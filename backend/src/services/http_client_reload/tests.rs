use super::*;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct TestCa {
    pem: String,
    issuer: Issuer<'static, KeyPair>,
}

impl TestCa {
    fn new() -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        Self {
            pem: cert.pem(),
            issuer: Issuer::new(params, key),
        }
    }
}

struct TlsServer {
    addr: std::net::SocketAddr,
    connections: Arc<AtomicUsize>,
    resumed: Arc<AtomicUsize>,
    stream_release: Arc<tokio::sync::Notify>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TlsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TlsServer {
    async fn start(ca: &TestCa) -> Self {
        Self::start_with_close(ca, false).await
    }

    async fn start_with_close(ca: &TestCa, close_after_response: bool) -> Self {
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["localhost".to_string()])
            .unwrap()
            .signed_by(&key, &ca.issuer)
            .unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let accepted = connections.clone();
        let resumed = Arc::new(AtomicUsize::new(0));
        let resumed_handshakes = resumed.clone();
        let stream_release = Arc::new(tokio::sync::Notify::new());
        let release = stream_release.clone();
        let task = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    incoming = listener.accept() => {
                        let (socket, _) = incoming.unwrap();
                        let acceptor = acceptor.clone();
                        let accepted = accepted.clone();
                        let resumed = resumed_handshakes.clone();
                        let release = release.clone();
                        tasks.spawn(async move {
                            let Ok(mut stream) = acceptor.accept(socket).await else { return; };
                            accepted.fetch_add(1, Ordering::SeqCst);
                            if stream.get_ref().1.handshake_kind() == Some(rustls::HandshakeKind::Resumed) {
                                resumed.fetch_add(1, Ordering::SeqCst);
                            }
                            let mut pending = Vec::new();
                            loop {
                                let mut bytes = [0; 4096];
                                let Ok(n) = stream.read(&mut bytes).await else { return; };
                                if n == 0 { return; }
                                pending.extend_from_slice(&bytes[..n]);
                                if let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                                    let request = String::from_utf8_lossy(&pending[..end]);
                                    if request.starts_with("GET /stream ") {
                                        if stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nab").await.is_err() { return; }
                                        if stream.flush().await.is_err() { return; }
                                        release.notified().await;
                                        if stream.write_all(b"cd").await.is_err() { return; }
                                        if stream.flush().await.is_err() { return; }
                                        pending.drain(..end + 4);
                                        continue;
                                    }
                                    let response = if request.starts_with("GET /redirect ") {
                                        "HTTP/1.1 302 Found\r\nLocation: /ok\r\nContent-Length: 0\r\n\r\n"
                                    } else if close_after_response {
                                        "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok"
                                    } else {
                                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                                    };
                                    if stream.write_all(response.as_bytes()).await.is_err() { return; }
                                    if stream.flush().await.is_err() { return; }
                                    if close_after_response {
                                        let _ = stream.shutdown().await;
                                        return;
                                    }
                                    pending.drain(..end + 4);
                                }
                            }
                        });
                    }
                    _ = tasks.join_next(), if !tasks.is_empty() => {}
                }
            }
        });
        Self {
            addr,
            connections,
            resumed,
            stream_release,
            task,
        }
    }

    fn url(&self) -> String {
        format!("https://localhost:{}/ok", self.addr.port())
    }
}

fn publish(path: &std::path::Path, pem: &str) {
    let mut tmp = tempfile::NamedTempFile::new_in(path.parent().unwrap()).unwrap();
    std::io::Write::write_all(&mut tmp, pem.as_bytes()).unwrap();
    tmp.persist(path).unwrap();
}

fn manager(path: PathBuf) -> Arc<TrustManager> {
    Arc::new(TrustManager::new(path))
}

fn register(manager: &Arc<TrustManager>) -> Client {
    manager
        .register(Arc::new(|| {
            reqwest::Client::builder()
                .no_proxy()
                .http1_only()
                .timeout(Duration::from_secs(3))
        }))
        .unwrap()
}

async fn succeeds(client: &Client, server: &TlsServer) -> bool {
    match client.get(server.url()).send().await {
        Ok(response) => response.text().await.is_ok_and(|body| body == "ok"),
        Err(_) => false,
    }
}

#[tokio::test]
async fn ca_rotation_updates_retained_clones_and_replaces_a_live_pool() {
    let a = TestCa::new();
    let b = TestCa::new();
    let server_a = TlsServer::start(&a).await;
    let server_b = TlsServer::start(&b).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bundle.pem");
    publish(&path, &a.pem);
    let manager = manager(path.clone());
    let client = register(&manager);
    let retained = client.clone();

    assert!(succeeds(&client, &server_a).await);
    assert!(succeeds(&retained, &server_a).await);
    assert_eq!(
        server_a.connections.load(Ordering::SeqCst),
        1,
        "control: unchanged requests must reuse the pool"
    );
    assert!(!succeeds(&retained, &server_b).await);

    // Control for the old implementation: a fixed snapshot cannot learn B.
    let fixed: Client = client.current().into();
    publish(&path, &format!("{}{}", a.pem, b.pem));
    assert!(manager.refresh());
    assert!(succeeds(&retained, &server_b).await);
    assert!(!succeeds(&fixed, &server_b).await);
    assert!(succeeds(&retained, &server_a).await);
    assert_eq!(
        server_a.connections.load(Ordering::SeqCst),
        2,
        "activation must replace a warm connection pool"
    );

    // A was actually connected and pooled. A later request must not reuse it
    // after its only trust anchor is removed.
    let already_constructed = retained.get(server_a.url());
    publish(&path, &b.pem);
    assert!(manager.refresh());
    assert_eq!(
        already_constructed
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "ok"
    );
    assert!(!succeeds(&retained, &server_a).await);
    assert!(succeeds(&retained, &server_b).await);
    assert!(
        succeeds(&fixed, &server_a).await,
        "control: old fixed client still trusts A"
    );
}

#[tokio::test]
async fn removing_a_root_discards_cached_tls13_sessions() {
    let a = TestCa::new();
    let b = TestCa::new();
    // Closing each connection forces a fresh TLS handshake instead of HTTP pooling.
    let server_a = TlsServer::start_with_close(&a, true).await;
    let server_b = TlsServer::start(&b).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bundle.pem");
    publish(&path, &a.pem);
    let manager = manager(path.clone());
    let client = register(&manager);
    let fixed: Client = client.current().into();

    assert!(succeeds(&client, &server_a).await);
    assert!(succeeds(&client, &server_a).await);
    assert_eq!(server_a.connections.load(Ordering::SeqCst), 2);
    assert_eq!(
        server_a.resumed.load(Ordering::SeqCst),
        1,
        "control: the second TLS 1.3 handshake must actually resume"
    );

    publish(&path, &b.pem);
    assert!(manager.refresh());
    assert!(!succeeds(&client, &server_a).await);
    assert!(succeeds(&client, &server_b).await);
    assert_eq!(server_a.connections.load(Ordering::SeqCst), 2);
    assert_eq!(server_a.resumed.load(Ordering::SeqCst), 1);

    assert!(succeeds(&fixed, &server_a).await);
    assert_eq!(
        server_a.resumed.load(Ordering::SeqCst),
        2,
        "control: the retained old TLS configuration still has a usable ticket"
    );
}

#[tokio::test]
async fn an_in_flight_response_finishes_after_its_root_is_removed() {
    let a = TestCa::new();
    let b = TestCa::new();
    let server_a = TlsServer::start(&a).await;
    let server_b = TlsServer::start(&b).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bundle.pem");
    publish(&path, &a.pem);
    let manager = manager(path.clone());
    let client = register(&manager);
    let mut response = client
        .get(format!("https://localhost:{}/stream", server_a.addr.port()))
        .send()
        .await
        .unwrap();
    let mut first = Vec::new();
    while first.len() < 2 {
        first.extend_from_slice(&response.chunk().await.unwrap().unwrap());
    }
    assert_eq!(first, b"ab", "response must already be streaming");

    publish(&path, &b.pem);
    assert!(manager.refresh());
    assert!(!succeeds(&client, &server_a).await);
    assert!(succeeds(&client, &server_b).await);
    server_a.stream_release.notify_one();
    let remaining = tokio::time::timeout(Duration::from_secs(3), async {
        let mut remaining = Vec::new();
        while let Some(chunk) = response.chunk().await.unwrap() {
            assert!(
                remaining.len() + chunk.len() <= 2,
                "unexpected response body"
            );
            remaining.extend_from_slice(&chunk);
        }
        remaining
    })
    .await
    .expect("rotation must not cancel an active response");
    assert_eq!(remaining, b"cd");
    assert!(!succeeds(&client, &server_a).await);
}

#[test]
fn rejects_invalid_empty_truncated_and_oversized_updates_without_changing_trust() {
    let a = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bundle.pem");
    publish(&path, &a.pem);
    let manager = manager(path.clone());
    let original = manager.state.read().unwrap().bundle.digest;
    let invalid = [
        String::new(),
        "not a certificate".into(),
        format!("{}\n-----BEGIN CERTIFICATE-----\nAAAA", a.pem),
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----".into(),
        // Assemble the non-certificate marker so secret-scanning hooks do not
        // mistake this negative parser test for an actual credential.
        format!(
            "{}\n-----BEGIN {}-----\nAAAA\n-----END {}-----",
            a.pem, "PRIVATE KEY", "PRIVATE KEY"
        ),
        "x".repeat(MAX_BUNDLE_BYTES + 1),
    ];
    for pem in invalid {
        publish(&path, &pem);
        assert!(!manager.refresh());
        assert_eq!(manager.state.read().unwrap().bundle.digest, original);
        assert!(manager.state.read().unwrap().last_error.is_some());
    }
    std::fs::remove_file(&path).unwrap();
    assert!(!manager.refresh());
    assert_eq!(manager.state.read().unwrap().bundle.digest, original);
    publish(&path, &a.pem);
    assert!(!manager.refresh());
    assert!(manager.state.read().unwrap().last_error.is_none());
}

#[tokio::test]
async fn missing_at_startup_recovers_and_new_subscribers_use_current_revision() {
    let ca = TestCa::new();
    let server = TlsServer::start(&ca).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bundle.pem");
    let manager = manager(path.clone());
    let retained = register(&manager);
    assert!(!succeeds(&retained, &server).await);
    publish(&path, &ca.pem);
    assert!(retained.refresh_custom_ca_for_test());
    assert!(succeeds(&retained, &server).await);
    let later = register(&manager);
    assert!(succeeds(&later, &server).await);
    assert_eq!(manager.state.read().unwrap().clients.len(), 2);
}

#[tokio::test]
async fn a_failed_client_rebuild_rejects_the_whole_revision() {
    let a = TestCa::new();
    let b = TestCa::new();
    let server_a = TlsServer::start(&a).await;
    let server_b = TlsServer::start(&b).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bundle.pem");
    publish(&path, &a.pem);
    let manager = manager(path.clone());
    let first = register(&manager);
    let fail = Arc::new(AtomicBool::new(false));
    let flag = fail.clone();
    let last = manager
        .register(Arc::new(move || {
            let builder = reqwest::Client::builder().no_proxy();
            if flag.load(Ordering::SeqCst) {
                builder.user_agent("\n")
            } else {
                builder
            }
        }))
        .unwrap();
    let before = manager.state.read().unwrap().bundle.digest;
    publish(&path, &b.pem);
    fail.store(true, Ordering::SeqCst);
    assert!(!manager.refresh());
    assert_eq!(manager.state.read().unwrap().bundle.digest, before);
    assert!(succeeds(&first, &server_a).await);
    assert!(!succeeds(&first, &server_b).await);
    drop(last);
    assert!(manager.refresh());
    assert!(succeeds(&first, &server_b).await);
    assert!(!succeeds(&first, &server_a).await);
}

#[tokio::test]
async fn replay_preserves_redirect_https_and_timeout_configuration() {
    let a = TestCa::new();
    let b = TestCa::new();
    let server = TlsServer::start(&a).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bundle.pem");
    publish(&path, &a.pem);
    let manager = manager(path.clone());
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let builder = Client::builder()
        .no_proxy()
        .https_only(true)
        .timeout(Duration::from_millis(100))
        .redirect(reqwest::redirect::Policy::custom(move |attempt| {
            count.fetch_add(1, Ordering::SeqCst);
            attempt.stop()
        }));
    let client = manager.register(builder.factory).unwrap();
    let blackhole = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    for pem in [a.pem.clone(), format!("{}{}", a.pem, b.pem)] {
        publish(&path, &pem);
        manager.refresh();
        assert_eq!(
            client
                .get(server.url().replace("/ok", "/redirect"))
                .send()
                .await
                .unwrap()
                .status(),
            302
        );
        assert!(client
            .get(format!("http://{}", server.addr))
            .send()
            .await
            .is_err());
        let outcome = tokio::time::timeout(
            Duration::from_secs(2),
            client
                .get(format!(
                    "https://localhost:{}",
                    blackhole.local_addr().unwrap().port()
                ))
                .send(),
        )
        .await
        .unwrap();
        assert!(outcome.unwrap_err().is_timeout());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn concurrent_registration_requests_and_atomic_renames_are_serialized() {
    let a = TestCa::new();
    let b = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bundle.pem");
    publish(&path, &a.pem);
    let manager = manager(path.clone());
    let retained = register(&manager);
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let manager = manager.clone();
            let retained = retained.clone();
            scope.spawn(move || {
                for _ in 0..25 {
                    let client = register(&manager);
                    let _ = client.get("https://example.com");
                    let _ = retained.get("https://example.com");
                }
            });
        }
        for i in 0..20 {
            publish(&path, if i % 2 == 0 { &b.pem } else { &a.pem });
            assert!(manager.refresh());
        }
    });
    assert_eq!(
        manager.state.read().unwrap().bundle.digest,
        Bundle::parse(a.pem.as_bytes()).unwrap().digest
    );
    manager.refresh();
    assert_eq!(
        manager
            .state
            .read()
            .unwrap()
            .clients
            .iter()
            .filter(|w| w.strong_count() > 0)
            .count(),
        1
    );
}

#[test]
fn unchanged_content_does_not_rebuild_but_a_b_a_does() {
    let a = TestCa::new();
    let b = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bundle.pem");
    publish(&path, &a.pem);
    let manager = manager(path.clone());
    let builds = Arc::new(AtomicUsize::new(0));
    let counter = builds.clone();
    let _client = manager
        .register(Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            reqwest::Client::builder().no_proxy()
        }))
        .unwrap();
    assert!(!manager.refresh());
    publish(&path, &a.pem);
    assert!(!manager.refresh());
    assert_eq!(builds.load(Ordering::SeqCst), 1);
    for pem in [&b.pem, &a.pem] {
        publish(&path, pem);
        assert!(manager.refresh());
    }
    assert_eq!(builds.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn background_poller_observes_an_atomic_replacement() {
    let a = TestCa::new();
    let b = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bundle.pem");
    publish(&path, &a.pem);
    let manager = manager_for(path.clone());
    assert!(Arc::ptr_eq(&manager, &manager_for(path.clone())));
    let client = register(&manager);
    let server = TlsServer::start(&b).await;
    assert!(!succeeds(&client, &server).await);
    publish(&path, &b.pem);
    let expected = Bundle::parse(b.pem.as_bytes()).unwrap().digest;
    tokio::time::timeout(POLL_INTERVAL * 2 + Duration::from_secs(2), async {
        while manager.state.read().unwrap().bundle.digest != expected {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("background worker must activate the visible update");
    assert!(succeeds(&client, &server).await);
}

#[test]
fn reload_failure_reporting_is_rate_limited_and_recovers() {
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bundle.pem");
    publish(&path, &ca.pem);
    let manager = manager(path.clone());
    publish(&path, "invalid");
    assert!(!manager.refresh());
    let first = manager.state.read().unwrap().last_error.unwrap();
    assert!(!manager.refresh());
    assert_eq!(manager.state.read().unwrap().last_error, Some(first));
    manager.state.write().unwrap().last_error = Some((first.0, Instant::now() - ERROR_INTERVAL));
    assert!(!manager.refresh());
    assert!(manager.state.read().unwrap().last_error.unwrap().1 > first.1);
    publish(&path, &ca.pem);
    assert!(!manager.refresh());
    assert!(manager.state.read().unwrap().last_error.is_none());
}

#[tokio::test]
async fn proxy_routing_survives_pool_replacement() {
    let a = TestCa::new();
    let b = TestCa::new();
    let server = TlsServer::start(&a).await;
    let destination = server.addr;
    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_url = format!("http://{}", proxy.local_addr().unwrap());
    let tunnels = Arc::new(AtomicUsize::new(0));
    let counter = tunnels.clone();
    let proxy_task = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = proxy.accept() => {
                    let (mut socket, _) = accepted.unwrap();
                    let counter = counter.clone();
                    tasks.spawn(async move {
                        let mut head = Vec::new();
                        loop {
                            let mut byte = [0];
                            if socket.read_exact(&mut byte).await.is_err() { return; }
                            head.push(byte[0]);
                            if head.ends_with(b"\r\n\r\n") { break; }
                            assert!(head.len() < 4096);
                        }
                        assert!(head.starts_with(b"CONNECT localhost:"));
                        counter.fetch_add(1, Ordering::SeqCst);
                        let mut upstream = tokio::net::TcpStream::connect(destination).await.unwrap();
                        socket.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.unwrap();
                        let _ = tokio::io::copy_bidirectional(&mut socket, &mut upstream).await;
                    });
                }
                _ = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bundle.pem");
    publish(&path, &a.pem);
    let manager = manager(path.clone());
    let builder = Client::builder()
        .no_proxy()
        .proxy(reqwest::Proxy::all(proxy_url).unwrap())
        .timeout(Duration::from_secs(3));
    let client = manager.register(builder.factory).unwrap();
    assert!(succeeds(&client, &server).await);
    publish(&path, &format!("{}{}", a.pem, b.pem));
    assert!(manager.refresh());
    assert!(succeeds(&client, &server).await);
    assert_eq!(tunnels.load(Ordering::SeqCst), 2);
    proxy_task.abort();
}

#[test]
fn last_known_good_survives_a_period_with_no_live_clients() {
    let ca = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bundle.pem");
    publish(&path, &ca.pem);
    let original = manager_for(path.clone());
    let expected = original.state.read().unwrap().bundle.digest;
    let client = register(&original);
    drop(client);
    drop(original);
    publish(&path, "invalid");
    let later = manager_for(path);
    assert!(!later.refresh());
    assert_eq!(later.state.read().unwrap().bundle.digest, expected);
    let _client = register(&later);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_https_requests_continue_during_atomic_rotations() {
    let a = TestCa::new();
    let b = TestCa::new();
    let server_a = TlsServer::start(&a).await;
    let server_b = TlsServer::start(&b).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bundle.pem");
    publish(&path, &a.pem);
    let manager = manager(path.clone());
    let client = register(&manager);
    let barrier = Arc::new(tokio::sync::Barrier::new(5));
    let mut workers = tokio::task::JoinSet::new();
    for _ in 0..4 {
        let client = client.clone();
        let barrier = barrier.clone();
        let url = server_a.url();
        workers.spawn(async move {
            for _ in 0..20 {
                barrier.wait().await;
                let response = client.get(&url).send().await.unwrap();
                assert_eq!(response.text().await.unwrap(), "ok");
                barrier.wait().await;
            }
        });
    }
    tokio::time::timeout(Duration::from_secs(30), async {
        for revision in 0..20 {
            barrier.wait().await;
            let manager = manager.clone();
            let path = path.clone();
            let pem = if revision % 2 == 0 {
                format!("{}{}", a.pem, b.pem)
            } else {
                a.pem.clone()
            };
            tokio::task::spawn_blocking(move || {
                publish(&path, &pem);
                assert!(manager.refresh());
            })
            .await
            .unwrap();
            barrier.wait().await;
        }
        while let Some(result) = workers.join_next().await {
            result.unwrap();
        }
    })
    .await
    .expect("concurrent requests and rotation must not deadlock");

    publish(&path, &b.pem);
    assert!(manager.refresh());
    assert!(!succeeds(&client, &server_a).await);
    assert!(succeeds(&client, &server_b).await);
}

#[cfg(unix)]
#[tokio::test]
async fn projected_volume_symlink_rotation_reopens_the_configured_path() {
    let a = TestCa::new();
    let b = TestCa::new();
    let server_a = TlsServer::start(&a).await;
    let server_b = TlsServer::start(&b).await;
    let dir = tempfile::tempdir().unwrap();
    for (revision, pem) in [("revision-a", &a.pem), ("revision-b", &b.pem)] {
        std::fs::create_dir(dir.path().join(revision)).unwrap();
        std::fs::write(dir.path().join(revision).join("ca.pem"), pem).unwrap();
    }
    std::os::unix::fs::symlink("revision-a", dir.path().join("..data")).unwrap();
    std::os::unix::fs::symlink("..data/ca.pem", dir.path().join("ca.pem")).unwrap();
    let manager = manager(dir.path().join("ca.pem"));
    let client = register(&manager);
    assert!(succeeds(&client, &server_a).await);
    assert!(!succeeds(&client, &server_b).await);

    std::os::unix::fs::symlink("revision-b", dir.path().join("..data-next")).unwrap();
    std::fs::rename(dir.path().join("..data-next"), dir.path().join("..data")).unwrap();
    assert!(manager.refresh());
    assert!(!succeeds(&client, &server_a).await);
    assert!(succeeds(&client, &server_b).await);
}

#[test]
fn revision_logs_report_activations_and_throttle_unchanged_failures() {
    #[derive(Clone)]
    struct LogWriter(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for LogWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let output = Arc::new(Mutex::new(Vec::new()));
    let writer = LogWriter(output.clone());
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let _subscriber = tracing::subscriber::set_default(subscriber);
    let a = TestCa::new();
    let b = TestCa::new();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bundle.pem");
    publish(&path, &a.pem);
    let manager = manager(path.clone());
    assert!(!manager.refresh());
    publish(&path, "invalid");
    assert!(!manager.refresh());
    assert!(!manager.refresh());
    publish(&path, &b.pem);
    assert!(manager.refresh());
    assert!(!manager.refresh());

    let logs = String::from_utf8(output.lock().unwrap().clone()).unwrap();
    assert_eq!(logs.matches("Activated custom CA revision").count(), 2);
    assert_eq!(logs.matches("Custom CA reload failed").count(), 1);
    assert_eq!(logs.matches("count=1").count(), 2);
    for pem in [&a.pem, &b.pem] {
        let digest = hex::encode(Sha256::digest(pem.as_bytes()));
        assert_eq!(logs.matches(&digest).count(), 1);
    }
    assert!(!logs.contains(path.to_str().unwrap()));
    assert!(!logs.contains("BEGIN CERTIFICATE"));
}
