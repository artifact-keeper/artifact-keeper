//! libgit2 smart-HTTP transport for plugin git sources, carried over the
//! SSRF-guarded HTTP client (GHSA-p28r-8m4q-w9pg).
//!
//! `validate_git_source_url` checks a plugin source before every clone, but
//! libgit2's built-in HTTP transport then resolved the hostname again on its
//! own, so a name that changed its address between the two lookups was
//! fetched from wherever it pointed by then. This transport makes libgit2
//! send its smart-HTTP requests through
//! [`base_client_builder`](crate::services::http_client::base_client_builder),
//! the client the other outbound fetches use: its resolver drops blocked
//! addresses at connect time and the connection goes to the address that
//! resolver returned, with the request's own Host and TLS server name. Its
//! redirect policy re-checks every hop.
//!
//! Only fetching is supported (clone is all plugin install and reload do).

use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use git2::transport::{Service, SmartSubtransport, SmartSubtransportStream, Transport};
use git2::Remote;

/// Sent as the User-Agent; some git hosts expect the `git/` prefix.
pub(super) const USER_AGENT: &str = "git/2.0 (artifact-keeper)";

/// Register the transport for `http://` and `https://` with libgit2, once
/// per process. Must run before any clone; registering is not synchronized
/// with transport creation inside libgit2, which the `OnceLock` (every
/// clone path calls this first) provides.
pub(super) fn ensure_registered() -> Result<(), String> {
    static REGISTERED: OnceLock<Result<(), String>> = OnceLock::new();
    REGISTERED
        .get_or_init(|| {
            for scheme in ["http", "https"] {
                // SAFETY: `git2::transport::register` must not race with
                // libgit2 creating a transport. Every git operation in this
                // crate is a plugin clone, and each one calls this function
                // (and so waits for this initializer) before it starts.
                unsafe { git2::transport::register(scheme, guarded_transport) }
                    .map_err(|e| format!("registering the {scheme} git transport: {e}"))?;
            }
            Ok(())
        })
        .clone()
}

fn guarded_transport(remote: &Remote<'_>) -> Result<Transport, git2::Error> {
    let handle = tokio::runtime::Handle::try_current().map_err(|_| {
        git2::Error::from_str("plugin git fetches must run inside the server runtime")
    })?;
    let client = crate::services::http_client::base_client_builder()
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(600))
        .build()
        .map_err(|e| git2::Error::from_str(&format!("building the git HTTP client: {e}")))?;
    Transport::smart(
        remote,
        true,
        GuardedHttp {
            handle,
            client,
            base_url: Arc::new(Mutex::new(None)),
        },
    )
}

struct GuardedHttp {
    handle: tokio::runtime::Handle,
    client: reqwest::Client,
    /// The repository URL, fixed by the first action and moved if the
    /// reference advertisement was redirected (so the pack request follows).
    base_url: Arc<Mutex<Option<String>>>,
}

impl SmartSubtransport for GuardedHttp {
    fn action(
        &self,
        url: &str,
        action: Service,
    ) -> Result<Box<dyn SmartSubtransportStream>, git2::Error> {
        let base = {
            let mut base = self
                .base_url
                .lock()
                .map_err(|_| git2::Error::from_str("git transport state poisoned"))?;
            base.get_or_insert_with(|| url.trim_end_matches('/').to_string())
                .clone()
        };
        let request = match action {
            Service::UploadPackLs => RequestKind::Advertisement,
            Service::UploadPack => RequestKind::UploadPack,
            Service::ReceivePackLs | Service::ReceivePack => {
                return Err(git2::Error::from_str(
                    "pushing to a plugin git source is not supported",
                ));
            }
        };
        Ok(Box::new(GuardedHttpStream {
            handle: self.handle.clone(),
            client: self.client.clone(),
            base_url: Arc::clone(&self.base_url),
            url: format!("{base}{}", request.path()),
            request,
            body: Vec::new(),
            response: None,
            pending: bytes::Bytes::new(),
        }))
    }

    fn close(&self) -> Result<(), git2::Error> {
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum RequestKind {
    Advertisement,
    UploadPack,
}

impl RequestKind {
    fn path(self) -> &'static str {
        match self {
            RequestKind::Advertisement => "/info/refs?service=git-upload-pack",
            RequestKind::UploadPack => "/git-upload-pack",
        }
    }

    fn response_type(self) -> &'static str {
        match self {
            RequestKind::Advertisement => "application/x-git-upload-pack-advertisement",
            RequestKind::UploadPack => "application/x-git-upload-pack-result",
        }
    }
}

/// One stateless smart-HTTP exchange: libgit2 writes the request body, then
/// reads; the request is sent on the first read.
struct GuardedHttpStream {
    handle: tokio::runtime::Handle,
    client: reqwest::Client,
    base_url: Arc<Mutex<Option<String>>>,
    url: String,
    request: RequestKind,
    body: Vec<u8>,
    response: Option<reqwest::Response>,
    pending: bytes::Bytes,
}

impl GuardedHttpStream {
    fn send(&mut self) -> io::Result<()> {
        let builder = match self.request {
            RequestKind::Advertisement => self.client.get(&self.url),
            RequestKind::UploadPack => self
                .client
                .post(&self.url)
                .header(
                    reqwest::header::CONTENT_TYPE,
                    "application/x-git-upload-pack-request",
                )
                .body(std::mem::take(&mut self.body)),
        }
        .header(reqwest::header::USER_AGENT, USER_AGENT)
        .header(reqwest::header::ACCEPT, self.request.response_type());

        let response = self
            .handle
            .block_on(builder.send())
            .map_err(|e| io::Error::other(describe(&e)))?;

        let status = response.status();
        if !status.is_success() {
            return Err(io::Error::other(format!(
                "git HTTP request failed with status {status}"
            )));
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !content_type.starts_with(self.request.response_type()) {
            return Err(io::Error::other(format!(
                "the server did not answer with the git smart HTTP protocol \
                 (content type {content_type:?})"
            )));
        }
        if let RequestKind::Advertisement = self.request {
            // Follow a redirected repository for the pack request too; the
            // redirect itself already passed the client's per-hop check.
            if let Some(moved) = response.url().as_str().strip_suffix(self.request.path()) {
                if let Ok(mut base) = self.base_url.lock() {
                    *base = Some(moved.to_string());
                }
            }
        }
        self.response = Some(response);
        Ok(())
    }
}

impl Read for GuardedHttpStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.response.is_none() {
            self.send()?;
        }
        loop {
            if !self.pending.is_empty() {
                let n = buf.len().min(self.pending.len());
                buf[..n].copy_from_slice(&self.pending.split_to(n));
                return Ok(n);
            }
            let Some(response) = self.response.as_mut() else {
                return Ok(0);
            };
            match self.handle.block_on(response.chunk()) {
                Ok(Some(chunk)) => self.pending = chunk,
                Ok(None) => return Ok(0),
                Err(e) => return Err(io::Error::other(describe(&e))),
            }
        }
    }
}

impl Write for GuardedHttpStream {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.response.is_some() {
            return Err(io::Error::other(
                "git transport wrote after the request was sent",
            ));
        }
        self.body.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The error and its causes, without the URL (it may carry credentials).
/// A connect-time SSRF refusal reads "... blocked by SSRF policy"; a
/// redirect refusal reads "... rejected by SSRF policy".
fn describe(err: &reqwest::Error) -> String {
    let mut msg = String::from(if err.is_timeout() {
        "git HTTP request timeout"
    } else if err.is_redirect() {
        "git HTTP redirect refused"
    } else if err.is_connect() {
        "git HTTP connection failed"
    } else {
        "git HTTP request failed"
    });
    let mut source = std::error::Error::source(err);
    while let Some(cause) = source {
        msg.push_str(": ");
        msg.push_str(&cause.to_string());
        source = cause.source();
    }
    msg
}
