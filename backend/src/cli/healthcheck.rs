//! `artifact-keeper healthcheck [URL]`: a liveness probe built into the binary.
//!
//! The image HEALTHCHECK used to run `curl -sf http://localhost:8080/health`.
//! This subcommand does the same check without any external tool, so the probe
//! works whatever HTTP client the image does or does not ship (#5991: the UBI 9
//! curl RPMs pull krb5-libs into the image).
//!
//! It deliberately does not touch the async runtime, the config loader or the
//! database: a probe that loaded the whole configuration would fail on the
//! very misconfigurations the server reports through its endpoints, and would
//! cost a full startup every interval. `main` dispatches to it before any
//! server setup.
//!
//! Usage: `artifact-keeper healthcheck [URL]`
//!   - no argument: `GET /health` (what the image HEALTHCHECK has always
//!     checked: database and storage, 503 when either is down) on the port
//!     the server binds, taken from
//!     `BIND_ADDRESS` (default `0.0.0.0:8080`), else `PORT`, else 8080;
//!     an unspecified bind address (`0.0.0.0`, `::`) is probed on loopback.
//!   - a path (`/livez` for liveness only): that path on the same address.
//!   - an `http://host[:port][/path]` URL: exactly that. `https` is not
//!     supported; the backend listener is plain HTTP.
//!
//! Exit status 0 when the server answers 2xx, 1 when it does not or cannot be
//! reached, 2 for a usage error -- what Docker's `HEALTHCHECK` and Compose's
//! `healthcheck.test` expect (any non-zero is unhealthy).

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

/// The argument that selects this subcommand: `artifact-keeper healthcheck`.
pub const SUBCOMMAND: &str = "healthcheck";

const DEFAULT_BIND: &str = "0.0.0.0:8080";
/// `/health`, not `/livez`: the image HEALTHCHECK used `curl -sf .../health`
/// before this subcommand existed, so a backend that has lost its database
/// must keep reporting unhealthy to Docker.
const DEFAULT_PATH: &str = "/health";
const TIMEOUT: Duration = Duration::from_secs(5);
/// Only the status line is needed; this bounds the read against a peer that
/// streams forever.
const MAX_RESPONSE_HEAD: usize = 8 * 1024;

/// The address to probe for a given `BIND_ADDRESS` value.
///
/// An unspecified IP (`0.0.0.0`, `[::]`) means "every interface", which the
/// probe reaches through loopback of the same family. A specific IP is
/// probed as is. A value that is not `ip:port` (a hostname) is resolved.
pub fn probe_addr(bind: &str) -> Result<SocketAddr, String> {
    let bind = bind.trim();
    if let Ok(mut addr) = bind.parse::<SocketAddr>() {
        if addr.ip().is_unspecified() {
            addr.set_ip(match addr.ip() {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
            });
        }
        return Ok(addr);
    }
    bind.to_socket_addrs()
        .map_err(|e| format!("cannot resolve BIND_ADDRESS {bind:?}: {e}"))?
        .next()
        .ok_or_else(|| format!("BIND_ADDRESS {bind:?} resolved to no address"))
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

/// GET the target and return the response status code.
pub fn probe(target: &Target, timeout: Duration) -> Result<u16, String> {
    let addr = target.addr;
    let mut stream =
        TcpStream::connect_timeout(&addr, timeout).map_err(|e| format!("connect {addr}: {e}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .map_err(|e| format!("set timeout: {e}"))?;
    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nUser-Agent: artifact-keeper-healthcheck\r\n\
         Connection: close\r\n\r\n",
        target.path, target.host
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("send request: {e}"))?;

    let mut head = Vec::with_capacity(256);
    let mut buf = [0u8; 512];
    while !head.contains(&b'\n') && head.len() < MAX_RESPONSE_HEAD {
        let n = stream
            .read(&mut buf)
            .map_err(|e| format!("read response: {e}"))?;
        if n == 0 {
            break;
        }
        head.extend_from_slice(&buf[..n]);
    }
    parse_status(&head).ok_or_else(|| "no HTTP status line in response".to_string())
}

/// Where to send the probe: a socket address, the `Host` header value and the
/// request path.
#[derive(Debug, PartialEq, Eq)]
pub struct Target {
    pub addr: SocketAddr,
    pub host: String,
    pub path: String,
}

/// The default bind address when `BIND_ADDRESS` is unset: `PORT` if set, else
/// 8080, on every interface (what the server itself does with `0.0.0.0:8080`).
pub fn default_bind(bind_address: Option<&str>, port: Option<&str>) -> String {
    match (bind_address, port) {
        (Some(b), _) if !b.trim().is_empty() => b.trim().to_string(),
        (_, Some(p)) if !p.trim().is_empty() => format!("0.0.0.0:{}", p.trim()),
        _ => DEFAULT_BIND.to_string(),
    }
}

fn valid_path(path: &str) -> bool {
    path.starts_with('/') && !path.bytes().any(|b| b.is_ascii_whitespace() || b < 0x20)
}

/// Resolve the optional argument against the bind address.
pub fn target(arg: Option<&str>, bind: &str) -> Result<Target, String> {
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
        let addr = with_port
            .to_socket_addrs()
            .map_err(|e| format!("cannot resolve {authority:?}: {e}"))?
            .next()
            .ok_or_else(|| format!("{authority:?} resolved to no address"))?;
        return Ok(Target {
            addr,
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
        addr,
        host,
        path: arg.to_string(),
    })
}

/// Run the subcommand. `args` are the arguments after `healthcheck`.
/// Returns the process exit code.
pub fn run(args: &[String]) -> i32 {
    if args.len() > 1 || args.first().is_some_and(|a| a == "-h" || a == "--help") {
        eprintln!("usage: artifact-keeper healthcheck [http://HOST[:PORT]/PATH | /PATH]");
        return 2;
    }
    let bind = default_bind(
        std::env::var("BIND_ADDRESS").ok().as_deref(),
        std::env::var("PORT").ok().as_deref(),
    );
    let target = match target(args.first().map(String::as_str), &bind) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("healthcheck: {e}");
            return 2;
        }
    };
    match probe(&target, TIMEOUT) {
        Ok(status) if (200..300).contains(&status) => 0,
        Ok(status) => {
            eprintln!("healthcheck: GET {} returned HTTP {status}", target.path);
            1
        }
        Err(e) => {
            eprintln!("healthcheck: {e}");
            1
        }
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

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
            probe_addr(" 10.1.2.3:8081 ").unwrap(),
            "10.1.2.3:8081".parse().unwrap()
        );
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
    fn default_bind_prefers_bind_address_then_port() {
        assert_eq!(
            default_bind(Some("127.0.0.1:9000"), Some("1")),
            "127.0.0.1:9000"
        );
        assert_eq!(default_bind(None, Some("8081")), "0.0.0.0:8081");
        assert_eq!(default_bind(Some(" "), None), "0.0.0.0:8080");
        assert_eq!(default_bind(None, None), "0.0.0.0:8080");
    }

    #[test]
    fn target_defaults_to_health_on_the_bind_port() {
        let t = target(None, "0.0.0.0:8080").unwrap();
        assert_eq!(t.addr, "127.0.0.1:8080".parse().unwrap());
        assert_eq!(t.path, "/health");
        assert_eq!(
            target(Some("/livez"), "0.0.0.0:8080").unwrap().path,
            "/livez"
        );
    }

    #[test]
    fn target_accepts_http_urls() {
        let t = target(Some("http://127.0.0.1:9091/metrics"), "0.0.0.0:8080").unwrap();
        assert_eq!(t.addr, "127.0.0.1:9091".parse().unwrap());
        assert_eq!(t.host, "127.0.0.1:9091");
        assert_eq!(t.path, "/metrics");
        let t = target(Some("http://[::1]:8080"), "0.0.0.0:8080").unwrap();
        assert_eq!(t.addr, "[::1]:8080".parse().unwrap());
        assert_eq!(t.path, "/");
        let t = target(Some("http://localhost:8080/health"), "0.0.0.0:1").unwrap();
        assert_eq!(t.addr.port(), 8080);
        assert!(t.addr.ip().is_loopback());
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
            assert!(target(Some(bad), "0.0.0.0:8080").is_err(), "{bad}");
        }
    }

    fn loopback(addr: SocketAddr, path: &str) -> Target {
        Target {
            addr,
            host: addr.to_string(),
            path: path.to_string(),
        }
    }

    /// Serve one canned response on an ephemeral loopback port.
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

    #[test]
    fn probe_reads_status_and_sends_get() {
        let (addr, handle) = serve_once(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nok");
        assert_eq!(
            probe(&loopback(addr, "/livez"), Duration::from_secs(5)),
            Ok(200)
        );
        let req = handle.join().unwrap();
        assert!(req.starts_with("GET /livez HTTP/1.0\r\n"), "{req:?}");
    }

    #[test]
    fn probe_reports_non_2xx() {
        let (addr, handle) = serve_once(b"HTTP/1.1 503 Service Unavailable\r\n\r\n");
        assert_eq!(
            probe(&loopback(addr, "/health"), Duration::from_secs(5)),
            Ok(503)
        );
        handle.join().unwrap();
    }

    #[test]
    fn probe_fails_when_nothing_listens() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        assert!(probe(&loopback(addr, "/health"), Duration::from_secs(2)).is_err());
    }

    #[test]
    fn run_rejects_usage_errors_with_exit_2() {
        assert_eq!(run(&["https://localhost:8080/health".to_string()]), 2);
        assert_eq!(run(&["/health x".to_string()]), 2);
        assert_eq!(run(&["/a".to_string(), "/b".to_string()]), 2);
    }

    #[test]
    fn run_exits_0_on_2xx_and_1_otherwise() {
        let (addr, handle) = serve_once(b"HTTP/1.1 200 OK\r\n\r\n");
        assert_eq!(run(&[format!("http://{addr}/livez")]), 0);
        handle.join().unwrap();
        let (addr, handle) = serve_once(b"HTTP/1.1 503 Service Unavailable\r\n\r\n");
        assert_eq!(run(&[format!("http://{addr}/livez")]), 1);
        handle.join().unwrap();
    }
}
