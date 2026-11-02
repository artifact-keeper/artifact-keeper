//! Shared CA revisions and replaceable HTTP connection pools (#5193).
//!
//! Requests select a client under the revision read lock. Rotation prepares
//! every replacement before publishing any of them; old request builders and
//! in-flight responses may finish, but new requests cannot select an old pool.

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Once, OnceLock, RwLock, Weak};
use std::time::{Duration, Instant};

use reqwest::{Certificate, IntoUrl, Method, Request, RequestBuilder, Response};
use rustls::pki_types::{pem::PemObject, CertificateDer};
use sha2::{Digest, Sha256};

const POLL_INTERVAL: Duration = Duration::from_secs(5);
const ERROR_INTERVAL: Duration = Duration::from_secs(60);
const MAX_BUNDLE_BYTES: usize = 4 * 1024 * 1024;
const MAX_CERTIFICATES: usize = 2048;

type Factory = Arc<dyn Fn() -> reqwest::ClientBuilder + Send + Sync>;
// Keep the last-known-good bundle for the process lifetime, including
// periods with no live HTTP clients. Paths come only from server configuration.
type Registry = Mutex<Vec<Arc<TrustManager>>>;
static MANAGERS: OnceLock<Registry> = OnceLock::new();

#[derive(Clone, Default)]
struct Bundle {
    digest: Option<[u8; 32]>,
    certs: Vec<Certificate>,
}

impl Bundle {
    fn read_bytes(path: &PathBuf) -> Result<Vec<u8>, &'static str> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| "cannot open bundle")?
            .take((MAX_BUNDLE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| "cannot read bundle")?;
        if bytes.len() > MAX_BUNDLE_BYTES {
            return Err("bundle exceeds 4 MiB");
        }
        Ok(bytes)
    }

    fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        let text = std::str::from_utf8(bytes).map_err(|_| "bundle is not UTF-8 PEM")?;
        let mut inside = false;
        let mut blocks = 0;
        for line in text.lines().map(str::trim) {
            if line.starts_with("-----BEGIN ") {
                if inside || line != "-----BEGIN CERTIFICATE-----" {
                    return Err("bundle must contain only certificate PEM blocks");
                }
                inside = true;
                blocks += 1;
            } else if line.starts_with("-----END ") {
                if !inside || line != "-----END CERTIFICATE-----" {
                    return Err("unmatched certificate PEM boundary");
                }
                inside = false;
            }
        }
        if inside || blocks == 0 || blocks > MAX_CERTIFICATES {
            return Err("bundle is empty, incomplete, or has too many certificates");
        }
        let mut roots = rustls::RootCertStore::empty();
        let mut certs = Vec::new();
        for der in CertificateDer::pem_slice_iter(bytes) {
            let der = der.map_err(|_| "invalid certificate PEM")?;
            roots
                .add(der.clone())
                .map_err(|_| "invalid X.509 certificate")?;
            certs.push(Certificate::from_der(der.as_ref()).map_err(|_| "invalid certificate")?);
        }
        if certs.len() != blocks {
            return Err("not all certificate blocks could be parsed");
        }
        Ok(Self {
            digest: Some(Sha256::digest(bytes).into()),
            certs,
        })
    }

    fn apply(&self, mut builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
        for cert in &self.certs {
            builder = builder.add_root_certificate(cert.clone());
        }
        builder
    }
}

struct TrustState {
    bundle: Bundle,
    clients: Vec<Weak<ClientInner>>,
    last_error: Option<(&'static str, Instant)>,
}

struct TrustManager {
    path: PathBuf,
    // Serialize registrations and refreshes, without blocking requests while
    // replacement TLS configurations are being prepared.
    update: Mutex<()>,
    state: RwLock<TrustState>,
}

impl TrustManager {
    fn new(path: PathBuf) -> Self {
        let manager = Self {
            path,
            update: Mutex::new(()),
            state: RwLock::new(TrustState {
                bundle: Bundle::default(),
                clients: Vec::new(),
                last_error: None,
            }),
        };
        manager.refresh();
        manager
    }

    fn warn(&self, reason: &'static str) {
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        if state
            .last_error
            .is_none_or(|(previous, at)| previous != reason || at.elapsed() >= ERROR_INTERVAL)
        {
            tracing::warn!(
                source = "CUSTOM_CA_CERT_PATH",
                reason,
                "Custom CA reload failed; retaining previous trust (default roots if none loaded)"
            );
            state.last_error = Some((reason, Instant::now()));
        }
    }

    fn refresh(&self) -> bool {
        let _update = self.update.lock().unwrap_or_else(|e| e.into_inner());
        let bytes = match Bundle::read_bytes(&self.path) {
            Ok(bytes) => bytes,
            Err(reason) => {
                self.warn(reason);
                return false;
            }
        };
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let clients = {
            let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
            if state.bundle.digest == Some(digest) {
                if state.last_error.take().is_some() {
                    tracing::info!(
                        source = "CUSTOM_CA_CERT_PATH",
                        "Custom CA source recovered; active revision unchanged"
                    );
                }
                return false;
            }
            state.clients.retain(|client| client.strong_count() > 0);
            state
                .clients
                .iter()
                .filter_map(Weak::upgrade)
                .collect::<Vec<_>>()
        };
        let bundle = match Bundle::parse(&bytes) {
            Ok(bundle) => bundle,
            Err(reason) => {
                self.warn(reason);
                return false;
            }
        };
        let mut prepared = Vec::with_capacity(clients.len());
        for inner in clients {
            match bundle.apply((inner.factory)()).build() {
                Ok(client) => prepared.push((inner, client)),
                Err(_) => {
                    self.warn("cannot rebuild HTTP clients");
                    return false;
                }
            }
        }
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        for (inner, client) in prepared {
            *inner.client.write().unwrap_or_else(|e| e.into_inner()) = client;
        }
        tracing::info!(source = "CUSTOM_CA_CERT_PATH", count = bundle.certs.len(),
            sha256 = %hex::encode(bundle.digest.unwrap()), "Activated custom CA revision");
        state.bundle = bundle;
        state.last_error = None;
        true
    }

    fn register(self: &Arc<Self>, factory: Factory) -> Result<Client, reqwest::Error> {
        let _update = self.update.lock().unwrap_or_else(|e| e.into_inner());
        let bundle = self
            .state
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .bundle
            .clone();
        let client = bundle.apply(factory()).build()?;
        let inner = Arc::new(ClientInner {
            client: RwLock::new(client),
            factory,
        });
        let mut state = self.state.write().unwrap_or_else(|e| e.into_inner());
        state.clients.retain(|client| client.strong_count() > 0);
        state.clients.push(Arc::downgrade(&inner));
        Ok(Client {
            kind: ClientKind::Managed {
                inner,
                trust: self.clone(),
            },
        })
    }
}

fn manager_for(path: PathBuf) -> Arc<TrustManager> {
    let registry = MANAGERS.get_or_init(|| Mutex::new(Vec::new()));
    let mut managers = registry.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(manager) = managers.iter().find(|manager| manager.path == path) {
        return manager.clone();
    }
    let manager = Arc::new(TrustManager::new(path));
    managers.push(manager.clone());
    static WORKER: Once = Once::new();
    WORKER.call_once(|| {
        std::thread::Builder::new()
            .name("custom-ca-reload".into())
            .spawn(|| loop {
                std::thread::sleep(POLL_INTERVAL);
                let managers = MANAGERS
                    .get()
                    .unwrap()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone();
                for manager in managers {
                    manager.refresh();
                }
            })
            .expect("start custom CA reload worker");
    });
    manager
}

struct ClientInner {
    client: RwLock<reqwest::Client>,
    factory: Factory,
}

/// Cloneable HTTP client whose managed clones select the same active pool.
/// Requests created before activation retain their original client.
#[derive(Clone)]
pub struct Client {
    kind: ClientKind,
}

#[derive(Clone)]
enum ClientKind {
    // The common no-custom-CA path keeps reqwest's cheap Arc clone, with no
    // extra allocation, registry lookup, or lock on request construction.
    Fixed(reqwest::Client),
    Managed {
        inner: Arc<ClientInner>,
        trust: Arc<TrustManager>,
    },
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReloadableClient")
            .field(
                "custom_ca",
                &matches!(self.kind, ClientKind::Managed { .. }),
            )
            .finish_non_exhaustive()
    }
}

impl From<reqwest::Client> for Client {
    fn from(client: reqwest::Client) -> Self {
        // Explicitly injected clients (e.g. cloud metadata) retain their own
        // configuration and do not subscribe to the custom trust source.
        Self {
            kind: ClientKind::Fixed(client),
        }
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    pub fn new() -> Self {
        Self::builder().build().expect("build HTTP client")
    }

    pub fn builder() -> ClientBuilder {
        ClientBuilder::new(reqwest::Client::builder)
    }

    #[cfg(test)]
    pub(crate) fn refresh_custom_ca_for_test(&self) -> bool {
        match &self.kind {
            ClientKind::Fixed(_) => false,
            ClientKind::Managed { trust, .. } => trust.refresh(),
        }
    }

    fn current(&self) -> reqwest::Client {
        match &self.kind {
            ClientKind::Fixed(client) => client.clone(),
            ClientKind::Managed { inner, trust } => {
                // Lock order matches activation: trust state, then pool.
                let _revision = trust.state.read().unwrap_or_else(|e| e.into_inner());
                inner
                    .client
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone()
            }
        }
    }

    pub fn request<U: IntoUrl>(&self, method: Method, url: U) -> RequestBuilder {
        self.current().request(method, url)
    }

    pub async fn execute(&self, request: Request) -> Result<Response, reqwest::Error> {
        self.current().execute(request).await
    }
    pub fn get<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::GET, url)
    }
    pub fn post<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::POST, url)
    }
    pub fn put<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::PUT, url)
    }
    pub fn patch<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::PATCH, url)
    }
    pub fn delete<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::DELETE, url)
    }
    pub fn head<U: IntoUrl>(&self, url: U) -> RequestBuilder {
        self.request(Method::HEAD, url)
    }
}

/// Replays the original settings against a fresh TLS configuration on rotation.
/// Capture only immutable configuration; do not perform I/O in a factory.
#[must_use]
pub struct ClientBuilder {
    factory: Factory,
}

impl ClientBuilder {
    fn new(factory: impl Fn() -> reqwest::ClientBuilder + Send + Sync + 'static) -> Self {
        Self {
            factory: Arc::new(factory),
        }
    }

    pub fn configure(
        self,
        configure: impl Fn(reqwest::ClientBuilder) -> reqwest::ClientBuilder + Send + Sync + 'static,
    ) -> Self {
        Self::new(move || configure((self.factory)()))
    }

    pub fn build(self) -> Result<Client, reqwest::Error> {
        match std::env::var_os("CUSTOM_CA_CERT_PATH").filter(|path| !path.is_empty()) {
            Some(path) => manager_for(path.into()).register(self.factory),
            None => (self.factory)().build().map(Into::into),
        }
    }

    #[cfg(test)]
    pub(crate) fn build_with_ca_path_for_test(
        self,
        path: PathBuf,
    ) -> Result<Client, reqwest::Error> {
        Arc::new(TrustManager::new(path)).register(self.factory)
    }

    pub fn redirect(self, policy: reqwest::redirect::Policy) -> Self {
        let policy = Arc::new(policy);
        self.configure(move |builder| {
            let policy = policy.clone();
            builder.redirect(reqwest::redirect::Policy::custom(move |attempt| {
                policy.redirect(attempt)
            }))
        })
    }

    pub fn dns_resolver(self, resolver: Arc<dyn reqwest::dns::Resolve>) -> Self {
        self.configure(move |builder| builder.dns_resolver(resolver.clone()))
    }

    pub fn user_agent(self, value: impl Into<String>) -> Self {
        let value = value.into();
        self.configure(move |builder| builder.user_agent(value.clone()))
    }

    pub fn resolve(self, domain: &str, addr: std::net::SocketAddr) -> Self {
        let domain = domain.to_owned();
        self.configure(move |builder| builder.resolve(&domain, addr))
    }
    pub fn timeout(self, value: Duration) -> Self {
        self.configure(move |builder| builder.timeout(value))
    }
    pub fn connect_timeout(self, value: Duration) -> Self {
        self.configure(move |builder| builder.connect_timeout(value))
    }
    pub fn read_timeout(self, value: Duration) -> Self {
        self.configure(move |builder| builder.read_timeout(value))
    }
    pub fn https_only(self, value: bool) -> Self {
        self.configure(move |builder| builder.https_only(value))
    }
    pub fn pool_max_idle_per_host(self, value: usize) -> Self {
        self.configure(move |builder| builder.pool_max_idle_per_host(value))
    }
    pub fn pool_idle_timeout(self, value: impl Into<Option<Duration>>) -> Self {
        let value = value.into();
        self.configure(move |builder| builder.pool_idle_timeout(value))
    }
    pub fn default_headers(self, value: reqwest::header::HeaderMap) -> Self {
        self.configure(move |builder| builder.default_headers(value.clone()))
    }
    pub fn proxy(self, value: reqwest::Proxy) -> Self {
        self.configure(move |builder| builder.proxy(value.clone()))
    }
    pub fn add_root_certificate(self, value: Certificate) -> Self {
        self.configure(move |builder| builder.add_root_certificate(value.clone()))
    }
    pub fn tls_certs_only(self, value: Vec<Certificate>) -> Self {
        self.configure(move |builder| builder.tls_certs_only(value.clone()))
    }
    pub fn no_proxy(self) -> Self {
        self.configure(|builder| builder.no_proxy())
    }
    pub fn no_gzip(self) -> Self {
        self.configure(|builder| builder.no_gzip())
    }
    pub fn no_brotli(self) -> Self {
        self.configure(|builder| builder.no_brotli())
    }
    pub fn no_deflate(self) -> Self {
        self.configure(|builder| builder.no_deflate())
    }
    pub fn no_zstd(self) -> Self {
        self.configure(|builder| builder.no_zstd())
    }
    pub fn http1_only(self) -> Self {
        self.configure(|builder| builder.http1_only())
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
#[path = "http_client_reload/tests.rs"]
mod tests;
