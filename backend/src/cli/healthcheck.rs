//! `artifact-keeper healthcheck [URL]`: a health probe built into the binary.
//!
//! The image HEALTHCHECK used to run `curl -sf http://localhost:8080/health`.
//! This subcommand does the same check without any external tool, so the probe
//! works whatever HTTP client the image does or does not ship (#5991: the UBI 9
//! curl RPMs pull krb5-libs into the image).
//!
//! It deliberately does not touch the async runtime, the config loader or the
//! database: a probe that loaded the whole configuration would fail on the
//! very misconfigurations the server reports through its endpoints, and would
//! repeat the server's startup work on every interval. `main` dispatches to it
//! before any server setup.
//!
//! Usage: `artifact-keeper healthcheck [URL]`
//!   - no argument: `GET /health` (what the image HEALTHCHECK has always
//!     checked: database and storage, 503 when either is down) on the address
//!     the server binds: `BIND_ADDRESS`, default `0.0.0.0:8080`, read and
//!     parsed exactly as `Config::from_env` and `run_server` do. An unspecified
//!     bind address (`0.0.0.0`, `::`) is probed on loopback.
//!   - a path (`/livez` for liveness only): that path on the same address.
//!   - an `http://host[:port][/path]` URL: exactly that. Every address the
//!     host resolves to is tried in turn, as curl does, so `localhost` works
//!     whether it resolves to `::1` or `127.0.0.1` first. `https` is not
//!     supported; the backend listener is plain HTTP.
//!
//! The whole probe -- name resolution, connect, request and reading the status
//! line -- runs under one deadline (5 s), so a peer that trickles bytes cannot
//! hold it open past Docker's HEALTHCHECK timeout.
//!
//! Exit status 0 when the server answers 2xx, 1 otherwise (not reachable,
//! non-2xx, timed out, or a usage error). Docker reserves exit status 2 for
//! HEALTHCHECK commands, so nothing here returns it.
//!
//! Needs an image with this subcommand (1.12.0 or later). On older images the
//! binary ignores its arguments and starts a second server, so a compose file
//! pinned to an older tag must keep a curl-based healthcheck.

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// The argument that selects this subcommand: `artifact-keeper healthcheck`.
pub const SUBCOMMAND: &str = "healthcheck";

/// `Config::from_env`'s default for `BIND_ADDRESS`.
const DEFAULT_BIND: &str = "0.0.0.0:8080";
/// `/health`, not `/livez`: the image HEALTHCHECK used `curl -sf .../health`
/// before this subcommand existed, so a backend that has lost its database
/// must keep reporting unhealthy to Docker.
const DEFAULT_PATH: &str = "/health";
/// Total budget for one probe, from name resolution to the status line.
const DEADLINE: Duration = Duration::from_secs(5);
/// Only the status line is needed; this bounds the read against a peer that
/// streams forever without a newline.
const MAX_RESPONSE_HEAD: usize = 8 * 1024;

/// The `BIND_ADDRESS` value the server would use, exactly as
/// `Config::from_env` computes it (no `PORT` fallback, no trimming).
pub fn bind_address(env_value: Option<String>) -> String {
    env_value.unwrap_or_else(|| DEFAULT_BIND.to_string())
}

/// The address to probe for a given `BIND_ADDRESS` value.
///
/// The server parses `BIND_ADDRESS` as a `SocketAddr` and refuses to start
/// otherwise, so this does the same. An unspecified IP (`0.0.0.0`, `[::]`)
/// means "every interface", which the probe reaches through loopback of the
/// same family.
pub fn probe_addr(bind: &str) -> Result<SocketAddr, String> {
    let mut addr: SocketAddr = bind.parse().map_err(|e| {
        format!("BIND_ADDRESS {bind:?} is not an ip:port (the server refuses it too): {e}")
    })?;
    if addr.ip().is_unspecified() {
        addr.set_ip(match addr.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        });
    }
    Ok(addr)
}

/// Parse the status code out of an HTTP response's status line.
pub fn parse_status(head: &[u8]) -> Option<u16> {
    let line_end = head.iter().position(|&b| b == b'\n').unwrap_or(head.len());
    let line = std::str::from_utf8(&head[..line_end]).ok()?;
    let mut parts = line.split_ascii_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    let code = parts.next()?;
    if code.len() != 3 {
        return None;
    }
    code.parse().ok()
}

/// Time left before `deadline`, or an error once it has passed. Never returns
/// a zero duration (`set_read_timeout(Some(0))` is an error).
fn remaining(deadline: Instant) -> Result<Duration, String> {
    match deadline.checked_duration_since(Instant::now()) {
        Some(d) if !d.is_zero() => Ok(d),
        _ => Err(format!(
            "timed out (the probe's whole budget is {}s)",
            DEADLINE.as_secs()
        )),
    }
}

/// Resolve `host:port`, bounded by `deadline`. A literal IP needs no lookup;
/// a hostname is resolved on a helper thread so a hung resolver cannot hold
/// the probe past the deadline (the thread is abandoned; the process exits).
fn resolve(host_port: &str, deadline: Instant) -> Result<Vec<SocketAddr>, String> {
    if let Ok(addr) = host_port.parse::<SocketAddr>() {
        return Ok(vec![addr]);
    }
    let (tx, rx) = mpsc::channel();
    let name = host_port.to_string();
    std::thread::spawn(move || {
        let _ = tx.send(name.to_socket_addrs().map(Iterator::collect::<Vec<_>>));
    });
    let addrs = match rx.recv_timeout(remaining(deadline)?) {
        Ok(Ok(addrs)) => addrs,
        Ok(Err(e)) => return Err(format!("cannot resolve {host_port:?}: {e}")),
        Err(_) => return Err(format!("resolving {host_port:?} timed out")),
    };
    if addrs.is_empty() {
        return Err(format!("{host_port:?} resolved to no address"));
    }
    Ok(addrs)
}

/// Where to send the probe: the addresses to try in order, the `Host` header
/// value and the request path.
#[derive(Debug, PartialEq, Eq)]
pub struct Target {
    pub addrs: Vec<SocketAddr>,
    pub host: String,
    pub path: String,
}

fn valid_path(path: &str) -> bool {
    path.starts_with('/') && !path.bytes().any(|b| b.is_ascii_whitespace() || b < 0x20)
}

/// Resolve the optional argument against the bind address.
pub fn target(arg: Option<&str>, bind: &str, deadline: Instant) -> Result<Target, String> {
    let arg = arg.unwrap_or(DEFAULT_PATH);
    if let Some(rest) = arg.strip_prefix("http://") {
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        if authority.is_empty() || authority.contains('@') || !valid_path(path) {
            return Err(format!("invalid URL {arg:?}"));
        }
        // `[::1]:8080`, `host:8080`, `host`, `[::1]`.
        let has_port = match authority.rfind(':') {
            Some(i) => !authority[i..].contains(']'),
            None => false,
        };
        let with_port = if has_port {
            authority.to_string()
        } else {
            format!("{authority}:80")
        };
        return Ok(Target {
            addrs: resolve(&with_port, deadline)?,
            host: authority.to_string(),
            path: path.to_string(),
        });
    }
    if arg.contains("://") {
        return Err(format!("only http:// URLs are supported, got {arg:?}"));
    }
    if !valid_path(arg) {
        return Err(format!(
            "expected an http:// URL or an absolute path, got {arg:?}"
        ));
    }
    let addr = probe_addr(bind)?;
    let host = match addr.ip() {
        IpAddr::V6(ip) => format!("[{ip}]:{}", addr.port()),
        IpAddr::V4(ip) => format!("{ip}:{}", addr.port()),
    };
    Ok(Target {
        addrs: vec![addr],
        host,
        path: arg.to_string(),
    })
}

/// Connect to the first of `addrs` that accepts, trying each in turn.
fn connect(addrs: &[SocketAddr], deadline: Instant) -> Result<TcpStream, String> {
    let mut errors = Vec::new();
    for addr in addrs {
        match TcpStream::connect_timeout(addr, remaining(deadline)?) {
            Ok(stream) => return Ok(stream),
            Err(e) => errors.push(format!("{addr}: {e}")),
        }
    }
    Err(format!("connect failed ({})", errors.join("; ")))
}

/// GET the target and return the response status code, all within `deadline`.
pub fn probe(target: &Target, deadline: Instant) -> Result<u16, String> {
    let mut stream = connect(&target.addrs, deadline)?;
    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nUser-Agent: artifact-keeper-healthcheck\r\n\
         Connection: close\r\n\r\n",
        target.path, target.host
    );
    stream
        .set_write_timeout(Some(remaining(deadline)?))
        .map_err(|e| format!("set timeout: {e}"))?;
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("send request: {e}"))?;

    let mut head = Vec::with_capacity(256);
    let mut buf = [0u8; 512];
    while !head.contains(&b'\n') && head.len() < MAX_RESPONSE_HEAD {
        // Re-armed every read with what is left of the ONE deadline, so a peer
        // that sends a byte just inside each read timeout still runs out.
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|e| format!("set timeout: {e}"))?;
        let n = match stream.read(&mut buf) {
            Ok(n) => n,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Err(remaining(deadline)
                    .err()
                    .unwrap_or_else(|| format!("read response: {e}")));
            }
            Err(e) => return Err(format!("read response: {e}")),
        };
        if n == 0 {
            break;
        }
        head.extend_from_slice(&buf[..n]);
    }
    parse_status(&head).ok_or_else(|| "no HTTP status line in response".to_string())
}

/// Probe `arg` (or the default) against `bind` within `budget`; the exit code.
fn check(arg: Option<&str>, bind: &str, budget: Duration) -> i32 {
    let deadline = Instant::now() + budget;
    let result = target(arg, bind, deadline).and_then(|t| probe(&t, deadline).map(|s| (t, s)));
    match result {
        Ok((_, status)) if (200..300).contains(&status) => 0,
        Ok((t, status)) => {
            eprintln!("healthcheck: GET {} returned HTTP {status}", t.path);
            1
        }
        Err(e) => {
            eprintln!("healthcheck: {e}");
            1
        }
    }
}

/// Run the subcommand. `args` are the arguments after `healthcheck`.
/// Returns the process exit code: 0 healthy, 1 anything else.
pub fn run(args: &[String]) -> i32 {
    if args.len() > 1 || args.first().is_some_and(|a| a == "-h" || a == "--help") {
        eprintln!("usage: artifact-keeper healthcheck [http://HOST[:PORT]/PATH | /PATH]");
        return 1;
    }
    let bind = bind_address(std::env::var("BIND_ADDRESS").ok());
    check(args.first().map(String::as_str), &bind, DEADLINE)
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    #[test]
    fn unspecified_bind_is_probed_on_loopback() {
        assert_eq!(
            probe_addr("0.0.0.0:8080").unwrap(),
            "127.0.0.1:8080".parse().unwrap()
        );
        assert_eq!(
            probe_addr("[::]:9000").unwrap(),
            "[::1]:9000".parse().unwrap()
        );
        assert_eq!(
            probe_addr("10.1.2.3:8081").unwrap(),
            "10.1.2.3:8081".parse().unwrap()
        );
    }

    #[test]
    fn bind_address_mirrors_config_from_env() {
        // Config::from_env: env::var("BIND_ADDRESS").unwrap_or("0.0.0.0:8080"),
        // then run_server parses it as a SocketAddr. No PORT fallback.
        assert_eq!(bind_address(None), "0.0.0.0:8080");
        assert_eq!(
            bind_address(Some("127.0.0.1:9000".into())),
            "127.0.0.1:9000"
        );
        // Values the server would refuse are refused here too.
        assert!(probe_addr("localhost:8080").is_err());
        assert!(probe_addr(" 0.0.0.0:8080").is_err());
        assert!(probe_addr("").is_err());
    }

    #[test]
    fn status_line_parsing() {
        assert_eq!(parse_status(b"HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(
            parse_status(b"HTTP/1.0 503 Service Unavailable\r\n"),
            Some(503)
        );
        assert_eq!(parse_status(b"HTTP/1.1 204"), Some(204));
        assert_eq!(parse_status(b"SSH-2.0-OpenSSH\r\n"), None);
        assert_eq!(parse_status(b"HTTP/1.1 20x OK\r\n"), None);
        assert_eq!(parse_status(b""), None);
    }

    #[test]
    fn target_defaults_to_health_on_the_bind_port() {
        let t = target(None, "0.0.0.0:8080", soon()).unwrap();
        assert_eq!(t.addrs, vec!["127.0.0.1:8080".parse().unwrap()]);
        assert_eq!(t.path, "/health");
        assert_eq!(
            target(Some("/livez"), "0.0.0.0:8080", soon()).unwrap().path,
            "/livez"
        );
    }

    #[test]
    fn target_accepts_http_urls() {
        let t = target(
            Some("http://127.0.0.1:9091/metrics"),
            "0.0.0.0:8080",
            soon(),
        )
        .unwrap();
        assert_eq!(t.addrs, vec!["127.0.0.1:9091".parse().unwrap()]);
        assert_eq!(t.host, "127.0.0.1:9091");
        assert_eq!(t.path, "/metrics");
        let t = target(Some("http://[::1]:8080"), "0.0.0.0:8080", soon()).unwrap();
        assert_eq!(t.addrs, vec!["[::1]:8080".parse().unwrap()]);
        assert_eq!(t.path, "/");
        let t = target(Some("http://localhost:8080/health"), "0.0.0.0:1", soon()).unwrap();
        assert!(!t.addrs.is_empty());
        assert!(t
            .addrs
            .iter()
            .all(|a| a.port() == 8080 && a.ip().is_loopback()));
    }

    #[test]
    fn target_rejects_what_it_cannot_probe() {
        for bad in [
            "https://localhost:8080/health",
            "health",
            "/health x",
            "http://user@localhost/",
            "http:///livez",
        ] {
            assert!(target(Some(bad), "0.0.0.0:8080", soon()).is_err(), "{bad}");
        }
    }

    fn loopback(addr: SocketAddr, path: &str) -> Target {
        Target {
            addrs: vec![addr],
            host: addr.to_string(),
            path: path.to_string(),
        }
    }

    /// Serve one canned response on an ephemeral IPv4 loopback port.
    fn serve_once(response: &'static [u8]) -> (SocketAddr, std::thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut req = [0u8; 1024];
            let n = sock.read(&mut req).unwrap();
            sock.write_all(response).unwrap();
            String::from_utf8_lossy(&req[..n]).into_owned()
        });
        (addr, handle)
    }

    /// A loopback address with nothing listening on it.
    fn closed_port() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        addr
    }

    #[test]
    fn probe_reads_status_and_sends_get() {
        let (addr, handle) = serve_once(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
        assert_eq!(probe(&loopback(addr, "/livez"), soon()), Ok(200));
        let req = handle.join().unwrap();
        assert!(req.starts_with("GET /livez HTTP/1.0\r\n"), "{req:?}");
    }

    #[test]
    fn probe_reports_non_2xx() {
        let (addr, handle) = serve_once(b"HTTP/1.1 503 Service Unavailable\r\n\r\n");
        assert_eq!(probe(&loopback(addr, "/health"), soon()), Ok(503));
        handle.join().unwrap();
    }

    #[test]
    fn probe_fails_when_nothing_listens() {
        assert!(probe(&loopback(closed_port(), "/health"), soon()).is_err());
    }

    #[test]
    fn probe_tries_every_resolved_address_in_turn() {
        // What `localhost` -> [::1, 127.0.0.1] looks like against a server that
        // binds 0.0.0.0: the first address refuses, the second answers.
        let (addr, handle) = serve_once(b"HTTP/1.1 200 OK\r\n\r\n");
        let t = Target {
            addrs: vec![closed_port(), addr],
            host: format!("localhost:{}", addr.port()),
            path: "/health".into(),
        };
        assert_eq!(probe(&t, soon()), Ok(200));
        handle.join().unwrap();
    }

    #[test]
    fn localhost_url_reaches_an_ipv4_only_listener() {
        // The review case: the server binds 0.0.0.0 (IPv4 only) and
        // `localhost` may resolve to ::1 first.
        let (addr, handle) = serve_once(b"HTTP/1.1 200 OK\r\n\r\n");
        let url = format!("http://localhost:{}/health", addr.port());
        assert_eq!(check(Some(&url), DEFAULT_BIND, DEADLINE), 0);
        handle.join().unwrap();
    }

    #[test]
    fn one_deadline_bounds_a_trickling_peer() {
        // A peer that sends one byte every 100 ms and never a newline would keep
        // per-read timeouts happy for 8 KiB x 100 ms; the single deadline ends it.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut req = [0u8; 1024];
            let _ = sock.read(&mut req);
            for _ in 0..40 {
                if sock.write_all(b"H").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let started = Instant::now();
        let deadline = started + Duration::from_millis(600);
        let err = probe(&loopback(addr, "/health"), deadline).unwrap_err();
        let elapsed = started.elapsed();
        assert!(err.contains("timed out"), "{err}");
        assert!(elapsed < Duration::from_secs(2), "took {elapsed:?}");
        handle.join().unwrap();
    }

    #[test]
    fn usage_errors_exit_1_not_dockers_reserved_2() {
        assert_eq!(run(&["https://localhost:8080/health".to_string()]), 1);
        assert_eq!(run(&["/health x".to_string()]), 1);
        assert_eq!(run(&["/a".to_string(), "/b".to_string()]), 1);
        assert_eq!(run(&["--help".to_string()]), 1);
    }

    #[test]
    fn run_exits_0_on_2xx_and_1_otherwise() {
        let (addr, handle) = serve_once(b"HTTP/1.1 200 OK\r\n\r\n");
        assert_eq!(run(&[format!("http://{addr}/livez")]), 0);
        handle.join().unwrap();
        let (addr, handle) = serve_once(b"HTTP/1.1 503 Service Unavailable\r\n\r\n");
        assert_eq!(run(&[format!("http://{addr}/livez")]), 1);
        handle.join().unwrap();
        assert_eq!(check(None, &closed_port().to_string(), DEADLINE), 1);
    }
}
