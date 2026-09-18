//! HTTPS mock OIDC issuer for the CI OIDC exchange e2e
//! (`ci_oidc_exchange_e2e_tests`, #4031).
//!
//! `POST /api/v1/auth/ci/token` verifies the presented ID token against the
//! issuer's discovery document and JWKS, fetched by `sso_client()`, and
//! `fetch_discovery` refuses any issuer that is not `https://`. The SSO e2e's
//! wiremock IdP is plain HTTP, so this is its TLS sibling: a tiny axum app
//! serving discovery + JWKS behind `tokio-rustls`.
//!
//! The backend is made to trust it through production settings only — no
//! test-only switch exists in the code under test:
//!
//! * the leaf certificate is issued by a throwaway CA whose PEM is written to
//!   a temp file named by `CUSTOM_CA_CERT_PATH`, the documented private-CA knob
//!   `sso_client()` reads on every build;
//! * the server binds the host's non-loopback address, allowlisted with
//!   `AK_SSRF_ALLOW_PRIVATE_CIDRS` via [`allow_private_sso_ip`] (loopback is a
//!   hard SSRF block no setting relaxes).
//!
//! Both are process-global env writes, which is why the suite runs
//! `--test-threads=1` in its own process. Every issuer gets its own port — so
//! its own JWKS URI, which keeps the process-global JWKS cache from serving
//! one test's keys to another — and its own signing key.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};

use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{encode, EncodingKey, Header};
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{json, Value};

use super::sso_support::{allow_private_sso_ip, non_loopback_bind_ip};

const KID: &str = "ak-ci-e2e-kid";

/// The process-wide throwaway CA, installed as `CUSTOM_CA_CERT_PATH` once.
struct TestCa {
    cert: rcgen::Certificate,
    key: rcgen::KeyPair,
}

static TEST_CA: OnceLock<TestCa> = OnceLock::new();

fn test_ca() -> &'static TestCa {
    TEST_CA.get_or_init(|| {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "artifact-keeper CI OIDC e2e CA");
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let key = rcgen::KeyPair::generate().expect("CA key");
        let cert = params.self_signed(&key).expect("self-sign CA");

        let path =
            std::env::temp_dir().join(format!("ak-ci-oidc-e2e-ca-{}.pem", uuid::Uuid::new_v4()));
        std::fs::write(&path, cert.pem()).expect("write CA PEM");
        std::env::set_var("CUSTOM_CA_CERT_PATH", &path);
        TestCa { cert, key }
    })
}

/// A rustls server config presenting a leaf for `ip`, issued by [`test_ca`].
fn server_tls_config(ip: IpAddr) -> Arc<tokio_rustls::rustls::ServerConfig> {
    use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    let ca = test_ca();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("leaf params");
    params.subject_alt_names = vec![rcgen::SanType::IpAddress(ip)];
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let key = rcgen::KeyPair::generate().expect("leaf key");
    let leaf = params
        .signed_by(&key, &ca.cert, &ca.key)
        .expect("sign leaf");

    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let config = tokio_rustls::rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .expect("server cert");
    Arc::new(config)
}

fn rsa_encoding_key(key: &RsaPrivateKey) -> EncodingKey {
    let pem = key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .expect("pkcs8 pem");
    EncodingKey::from_rsa_pem(pem.as_bytes()).expect("encoding key")
}

fn new_rsa_key() -> RsaPrivateKey {
    RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).expect("generate RSA key")
}

/// A running HTTPS OIDC issuer and the key it signs with.
pub struct MockCiIssuer {
    issuer: String,
    signing_key: EncodingKey,
    /// Never published in the JWKS: a token signed with it must be refused.
    foreign_key: EncodingKey,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for MockCiIssuer {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl MockCiIssuer {
    /// Start an issuer on the host's non-loopback address.
    ///
    /// `None` when the host has no non-loopback interface; the caller skips
    /// exactly as the SSO e2e does in that case.
    pub async fn start() -> Option<Self> {
        let ip = non_loopback_bind_ip()?;
        allow_private_sso_ip(ip);
        let listener = tokio::net::TcpListener::bind((ip, 0)).await.ok()?;
        let addr: SocketAddr = listener.local_addr().ok()?;
        // SocketAddr's Display brackets an IPv6 host, as a URL needs.
        let issuer = format!("https://{addr}");

        let key = new_rsa_key();
        let public = RsaPublicKey::from(&key);
        let jwks = json!({ "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": KID,
            "n": URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
            "e": URL_SAFE_NO_PAD.encode(public.e().to_bytes_be()),
        }]});
        let discovery = json!({
            "issuer": issuer,
            "jwks_uri": format!("{issuer}/jwks"),
            "id_token_signing_alg_values_supported": ["RS256"],
        });
        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || async move { Json(discovery) }),
            )
            .route("/jwks", get(move || async move { Json(jwks) }));

        let acceptor = tokio_rustls::TlsAcceptor::from(server_tls_config(ip));
        let server = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let app = app.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let _ = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(
                        hyper_util::rt::TokioIo::new(tls),
                        hyper_util::service::TowerToHyperService::new(app),
                    )
                    .await;
                });
            }
        });

        Some(Self {
            issuer,
            signing_key: rsa_encoding_key(&key),
            foreign_key: rsa_encoding_key(&new_rsa_key()),
            server,
        })
    }

    /// The issuer URL, exactly as the provider row and the `iss` claim carry it.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// GitLab's ID-token claim set for one pipeline, valid for five minutes.
    pub fn gitlab_claims(
        &self,
        audience: &str,
        project: &str,
        ref_type: &str,
        git_ref: &str,
    ) -> Value {
        let now = chrono::Utc::now().timestamp();
        let namespace = project.rsplit_once('/').map_or(project, |(ns, _)| ns);
        json!({
            "iss": self.issuer,
            "aud": audience,
            "sub": format!("project_path:{project}:ref_type:{ref_type}:ref:{git_ref}"),
            "project_id": project_id(project),
            "project_path": project,
            "namespace_path": namespace,
            "ref": git_ref,
            "ref_type": ref_type,
            "ref_protected": "true",
            "iat": now,
            "nbf": now,
            "exp": now + 300,
        })
    }

    /// RS256-sign `claims` with the published key.
    pub fn sign(&self, claims: &Value) -> String {
        sign_rs256(&self.signing_key, claims)
    }

    /// RS256-sign `claims` with a key the JWKS does not publish, under the
    /// published `kid`.
    pub fn sign_with_foreign_key(&self, claims: &Value) -> String {
        sign_rs256(&self.foreign_key, claims)
    }
}

fn sign_rs256(key: &EncodingKey, claims: &Value) -> String {
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(KID.to_string());
    encode(&header, claims, key).expect("sign CI ID token")
}

/// An `alg: none` token carrying `claims`, assembled by hand: no JWT library
/// will produce one.
pub fn unsigned_alg_none(claims: &Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    format!("{header}.{payload}.")
}

/// A stable numeric project id derived from the path, as GitLab issues one.
fn project_id(project: &str) -> String {
    let sum: u64 = project.bytes().map(u64::from).sum();
    (1000 + sum).to_string()
}
