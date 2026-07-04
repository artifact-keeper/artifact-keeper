//! Shared SSO end-to-end test support (#1617, epic #1615).
//!
//! Cross-cutting helpers used by the OIDC (and, in the companion PR, SAML)
//! end-to-end harnesses that drive the real `api::handlers::sso` axum routes
//! against a mock identity provider backed by a throwaway Postgres.
//!
//! The load-bearing piece here is [`non_loopback_bind_ip`] +
//! [`allow_private_sso_ip`]: the OIDC handler performs three server-side
//! first-hop fetches (discovery, token, JWKS), each screened by the outbound
//! SSRF guard. Loopback (`127.0.0.0/8`) is a HARD block that no toggle relaxes
//! (`api::validation::is_hard_blocked_ipv4`), so a mock IdP on wiremock's
//! default `127.0.0.1` bind is unreachable. The harness instead binds the mock
//! to the host's primary non-loopback interface (an RFC1918/CGNAT private IP in
//! CI/ARC pods) and opts that single address into the private-IP allowlist via
//! `AK_SSRF_ALLOW_PRIVATE_CIDRS`, which relaxes private IPs only.

use std::collections::HashMap;
use std::net::{IpAddr, UdpSocket};
use std::sync::Arc;

use bergshamra::keys::loader::load_rsa_private_pem;
use bergshamra::{sign, DsigContext, KeysManager};
use sqlx::PgPool;
use uuid::Uuid;

use artifact_keeper_backend::api::{AppState, SharedState};
use artifact_keeper_backend::config::Config;

/// `AuthConfigService` encrypts the stored OIDC client secret with a key read
/// from `SSO_ENCRYPTION_KEY`/`JWT_SECRET` in the *process* environment (not the
/// `Config`). CI sets `JWT_SECRET`; for local runs we install a stable key so
/// `create_oidc` (encrypt) and `get_oidc_decrypted` (decrypt) agree. Setting it
/// to a fixed value is idempotent across the tests in a serial binary.
pub fn ensure_sso_encryption_key() {
    if std::env::var("SSO_ENCRYPTION_KEY").is_err() && std::env::var("JWT_SECRET").is_err() {
        std::env::set_var(
            "SSO_ENCRYPTION_KEY",
            "test-sso-encryption-key-at-least-32-bytes-long",
        );
    }
}

/// Connect to the throwaway Postgres named by `DATABASE_URL`, or return `None`
/// so the caller can skip cleanly (matching the repo `--ignored` convention).
pub async fn try_pool() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(3)
        .acquire_timeout(std::time::Duration::from_secs(3))
        .connect(&url)
        .await
        .ok()
}

/// Minimal `Config` for building `AppState` in the SSO e2e tests.
pub fn test_config() -> Config {
    Config {
        database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
        storage_path: std::env::temp_dir()
            .join(format!("ak-sso-e2e-{}", Uuid::new_v4()))
            .to_string_lossy()
            .into_owned(),
        jwt_secret: "test-secret-at-least-32-bytes-long-for-testing".into(),
        ..Default::default()
    }
}

/// Build a `SharedState` over the given pool with a filesystem storage backend.
pub fn build_state(pool: PgPool) -> SharedState {
    let cfg = test_config();
    std::fs::create_dir_all(&cfg.storage_path).expect("create storage dir");
    let storage: Arc<dyn artifact_keeper_backend::storage::StorageBackend> = Arc::new(
        artifact_keeper_backend::storage::filesystem::FilesystemStorage::new(&cfg.storage_path),
    );
    let registry = Arc::new(artifact_keeper_backend::storage::StorageRegistry::new(
        HashMap::new(),
        "filesystem".to_string(),
    ));
    Arc::new(AppState::new(cfg, pool, storage, registry))
}

/// Wrap the public SSO router in `with_state` (no auth layer — these are
/// pre-auth public endpoints).
pub fn sso_app(state: SharedState) -> axum::Router {
    artifact_keeper_backend::api::handlers::sso::router().with_state(state)
}

/// Discover a non-loopback local IP for binding the mock IdP.
///
/// Opens a UDP socket and `connect()`s it to a public address — no packets are
/// actually sent; the kernel just selects the primary outbound interface, whose
/// `local_addr()` is the address we bind the mock server to. Returns `None` when
/// the only reachable local address is loopback (isolated runner) so the caller
/// can skip the test the same way it skips when `DATABASE_URL` is unset.
pub fn non_loopback_bind_ip() -> Option<IpAddr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    let ip = sock.local_addr().ok()?.ip();
    if ip.is_loopback() {
        None
    } else {
        Some(ip)
    }
}

/// Opt a single mock-IdP IP into the outbound SSRF private-IP allowlist by
/// setting `AK_SSRF_ALLOW_PRIVATE_CIDRS=<ip>/32` (or `/128` for IPv6).
///
/// This is a process-global env write, which is why the SSO e2e suites run
/// `--test-threads=1`. The allowlist relaxes only private RFC1918/CGNAT/ULA
/// addresses; loopback and cloud-metadata IPs stay hard-blocked. If the primary
/// interface IP happens to be public the guard already permits it and this call
/// is harmless.
pub fn allow_private_sso_ip(ip: IpAddr) {
    let cidr = match ip {
        IpAddr::V4(_) => format!("{ip}/32"),
        IpAddr::V6(_) => format!("{ip}/128"),
    };
    std::env::set_var("AK_SSRF_ALLOW_PRIVATE_CIDRS", cidr);
}

// ===========================================================================
// SAML e2e signing support (#2212, part of #1617)
// ===========================================================================
//
// Unlike OIDC, `saml_acs` performs NO outbound fetch — the assertion signature
// is verified against the DB-stored provider `certificate` via `bergshamra`.
// So the mock SAML IdP is an in-process signer, not an HTTP server: there is no
// wiremock and no SSRF/non-loopback concern here.
//
// We sign the assertion with the SAME crate the app verifies it with
// (`bergshamra`), using an EPHEMERAL RSA keypair generated once per test
// process (no key material is checked into the repo — a committed private
// key, even a test-only one, trips secret scanning). The matching self-signed
// X.509 cert is minted in-memory from the same key and stored verbatim as the
// provider `certificate`; the app's `load_x509_cert_pem` only extracts the
// SPKI from it (no chain validation), so a minimal v1 cert suffices. All of
// this uses crates already in the dependency tree (`rsa` + its re-exported
// `sha2`/`pkcs8`) — no new dependency and no key files on disk.

/// Ephemeral per-process SAML IdP identity: a PKCS#8 RSA-2048 private key PEM
/// (fed to `bergshamra::keys::loader::load_rsa_private_pem` for signing) and
/// the matching self-signed X.509 certificate PEM (stored as the provider
/// `certificate` for verification).
pub struct SamlIdpKeys {
    pub signing_key_pem: String,
    pub cert_pem: String,
}

static SAML_IDP_KEYS: std::sync::OnceLock<SamlIdpKeys> = std::sync::OnceLock::new();

/// The process-wide ephemeral IdP keypair, generated on first use so every
/// SAML test shares one RSA keygen (~100ms) instead of paying it per test.
pub fn saml_idp_keys() -> &'static SamlIdpKeys {
    SAML_IDP_KEYS.get_or_init(|| {
        use rsa::pkcs8::EncodePrivateKey;
        let mut rng = rsa::rand_core::OsRng;
        let private = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA-2048 IdP key");
        let signing_key_pem = private
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .expect("encode PKCS#8 PEM")
            .to_string();
        let cert_pem = self_signed_cert_pem(&private);
        SamlIdpKeys {
            signing_key_pem,
            cert_pem,
        }
    })
}

/// The ephemeral IdP certificate PEM — what tests store as the SAML provider
/// `certificate` column value.
pub fn saml_idp_cert_pem() -> &'static str {
    &saml_idp_keys().cert_pem
}

// ---------------------------------------------------------------------------
// Minimal in-memory self-signed X.509 (v1) certificate builder.
//
// The app-side consumer (`bergshamra::keys::loader::load_x509_cert_pem` →
// `load_x509_cert_der`) parses the DER with `x509_cert::Certificate::from_der`
// and extracts only the SubjectPublicKeyInfo; it does not validate the chain,
// times, or the certificate's own signature on this path. We still emit a
// well-formed, genuinely self-signed (sha256WithRSAEncryption) certificate so
// the fixture also parses under stricter tooling. Hand-rolling ~60 lines of
// DER here avoids adding a cert-generation dependency (rcgen would drag in a
// second crypto backend) for what is a fixed, minimal structure.
// ---------------------------------------------------------------------------

/// DER definite-length encoding (short and long form up to 2^16-1).
fn der_len(len: usize) -> Vec<u8> {
    assert!(len < 0x1_0000, "DER length out of supported range");
    if len < 0x80 {
        vec![len as u8]
    } else if len < 0x100 {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, len as u8]
    }
}

/// One DER TLV: tag byte + definite length + content.
fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// `AlgorithmIdentifier` for sha256WithRSAEncryption (OID 1.2.840.113549.1.1.11
/// + NULL params).
fn der_sha256_rsa_alg_id() -> Vec<u8> {
    let oid = der_tlv(
        0x06,
        &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b],
    );
    let null = der_tlv(0x05, &[]);
    der_tlv(0x30, &[oid, null].concat())
}

/// X.501 `Name` with a single `CN=<cn>` RDN (UTF8String).
fn der_cn_name(cn: &str) -> Vec<u8> {
    let oid_cn = der_tlv(0x06, &[0x55, 0x04, 0x03]);
    let value = der_tlv(0x0c, cn.as_bytes());
    let atv = der_tlv(0x30, &[oid_cn, value].concat());
    let rdn = der_tlv(0x31, &atv);
    der_tlv(0x30, &rdn)
}

/// Build a minimal self-signed v1 certificate for `key` and PEM-wrap it.
fn self_signed_cert_pem(key: &rsa::RsaPrivateKey) -> String {
    use rsa::pkcs8::EncodePublicKey;
    use rsa::sha2::{Digest, Sha256};

    let spki_der = key
        .to_public_key()
        .to_public_key_der()
        .expect("encode SPKI DER");

    let serial = der_tlv(0x02, &[0x01]);
    let alg_id = der_sha256_rsa_alg_id();
    let name = der_cn_name("ak-saml-e2e-ephemeral-idp");
    // Fixed validity well inside the UTCTime range; the SAML verify path does
    // not check certificate validity times (only assertion Conditions).
    let validity = der_tlv(
        0x30,
        &[
            der_tlv(0x17, b"200101000000Z"),
            der_tlv(0x17, b"491231235959Z"),
        ]
        .concat(),
    );

    // TBSCertificate (v1: version field omitted, no extensions).
    let tbs = der_tlv(
        0x30,
        &[
            serial,
            alg_id.clone(),
            name.clone(),
            validity,
            name,
            spki_der.as_bytes().to_vec(),
        ]
        .concat(),
    );

    // Genuinely self-sign the TBS (PKCS#1 v1.5 / SHA-256).
    let digest = Sha256::digest(&tbs);
    let signature = key
        .sign(rsa::Pkcs1v15Sign::new::<Sha256>(), &digest)
        .expect("self-sign certificate");
    let mut bitstring_content = vec![0x00]; // zero unused bits
    bitstring_content.extend_from_slice(&signature);
    let sig_bits = der_tlv(0x03, &bitstring_content);

    let cert_der = der_tlv(0x30, &[tbs, alg_id, sig_bits].concat());
    pem_wrap("CERTIFICATE", &cert_der)
}

/// RFC 7468-style PEM wrapping (64-char base64 lines).
fn pem_wrap(label: &str, der: &[u8]) -> String {
    let b64 = base64_standard(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// Produce an enveloped XML-DSig signature over the `<Assertion>` referenced by
/// the template's `<ds:Reference URI="#...">`, using the supplied PKCS#8 RSA
/// key. Fills the empty `<ds:DigestValue>`/`<ds:SignatureValue>` and returns
/// the signed XML.
///
/// Uses bergshamra's hardened [`DsigContext::new`] defaults
/// (`trusted_keys_only` + `strict_verification`) — the same posture the
/// verifier (`SamlService::validate_response`) runs under — so a template that
/// signs here is one the app can actually verify.
pub fn sign_saml_document_with_key(pkcs8_pem: &[u8], template_xml: &str) -> String {
    let key = load_rsa_private_pem(pkcs8_pem).expect("load RSA signing key");
    let mut km = KeysManager::new();
    km.add_key(key);
    let ctx = DsigContext::new(km);
    sign(&ctx, template_xml).expect("sign SAML document")
}

/// Sign with the ephemeral IdP key that matches [`saml_idp_cert_pem`] — the
/// happy-path signer (produces an assertion the app trusts).
pub fn sign_saml_document(template_xml: &str) -> String {
    sign_saml_document_with_key(saml_idp_keys().signing_key_pem.as_bytes(), template_xml)
}

/// Inputs for a mock SAML `<Response>`. Sensible bearer-assertion defaults are
/// filled by [`SamlResponseSpec::new`]; individual cases tweak only the field
/// under test (missing `InResponseTo`, mismatched `Destination`, admin group…).
pub struct SamlResponseSpec {
    /// IdP entity ID; must equal the provider `entity_id` (response + assertion
    /// `<Issuer>`).
    pub issuer: String,
    /// SP entity ID placed in `<AudienceRestriction>`; must equal the provider
    /// `sp_entity_id`.
    pub audience: String,
    /// `InResponseTo` on the `<Response>` — the consumed AuthnRequest id.
    /// `None` models an unsolicited (IdP-initiated) response.
    pub in_response_to: Option<String>,
    /// Subject `<NameID>` (the external id / default username).
    pub name_id: String,
    /// `email` attribute value.
    pub email: String,
    /// `displayName` attribute value.
    pub display_name: String,
    /// `groups` attribute values.
    pub groups: Vec<String>,
    /// `<Response Destination>` — when `Some`, bound against the SP ACS URL.
    pub destination: Option<String>,
    /// `<SubjectConfirmationData Recipient>` — when `Some`, bound against the
    /// SP ACS URL.
    pub recipient: Option<String>,
}

impl SamlResponseSpec {
    /// A valid bearer assertion carrying `name_id` for `issuer`/`audience`,
    /// solicited by `in_response_to`, with no `Destination`/`Recipient` bound
    /// and a single non-privileged group.
    pub fn new(issuer: &str, audience: &str, in_response_to: &str, name_id: &str) -> Self {
        Self {
            issuer: issuer.to_string(),
            audience: audience.to_string(),
            in_response_to: Some(in_response_to.to_string()),
            name_id: name_id.to_string(),
            email: format!("{name_id}@saml-e2e.test"),
            display_name: "SAML E2E User".to_string(),
            groups: vec!["Developers".to_string()],
            destination: None,
            recipient: None,
        }
    }

    /// Render the (unsigned) `<Response>` XML plus the assertion id its
    /// `<ds:Reference>` points at. `sign_saml_document*` fills the empty
    /// Digest/Signature values.
    pub fn to_unsigned_xml(&self) -> String {
        let now = chrono::Utc::now();
        let issue_instant = now.format("%Y-%m-%dT%H:%M:%SZ");
        let not_before = (now - chrono::Duration::minutes(5)).format("%Y-%m-%dT%H:%M:%SZ");
        let not_on_or_after = (now + chrono::Duration::minutes(5)).format("%Y-%m-%dT%H:%M:%SZ");
        let response_id = format!("_resp{}", Uuid::new_v4().as_simple());
        let assertion_id = format!("_assertion{}", Uuid::new_v4().as_simple());
        let session_index = format!("_sess{}", Uuid::new_v4().as_simple());

        let in_response_to_attr = self
            .in_response_to
            .as_deref()
            .map(|v| format!(" InResponseTo=\"{}\"", xml_escape(v)))
            .unwrap_or_default();
        let destination_attr = self
            .destination
            .as_deref()
            .map(|v| format!(" Destination=\"{}\"", xml_escape(v)))
            .unwrap_or_default();
        let recipient_attr = self
            .recipient
            .as_deref()
            .map(|v| format!(" Recipient=\"{}\"", xml_escape(v)))
            .unwrap_or_default();
        let group_values = self
            .groups
            .iter()
            .map(|g| {
                format!(
                    "<saml:AttributeValue>{}</saml:AttributeValue>",
                    xml_escape(g)
                )
            })
            .collect::<String>();

        format!(
            r##"<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="{response_id}"{in_response_to_attr}{destination_attr}
                Version="2.0" IssueInstant="{issue_instant}">
    <saml:Issuer>{issuer}</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
    <saml:Assertion ID="{assertion_id}" Version="2.0" IssueInstant="{issue_instant}">
        <saml:Issuer>{issuer}</saml:Issuer>
        <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI="#{assertion_id}">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <ds:DigestValue></ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue></ds:SignatureValue>
        </ds:Signature>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{name_id}</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData{recipient_attr} NotOnOrAfter="{not_on_or_after}"/>
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_on_or_after}">
            <saml:AudienceRestriction>
                <saml:Audience>{audience}</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement SessionIndex="{session_index}" AuthnInstant="{issue_instant}"/>
        <saml:AttributeStatement>
            <saml:Attribute Name="email">
                <saml:AttributeValue>{email}</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="displayName">
                <saml:AttributeValue>{display_name}</saml:AttributeValue>
            </saml:Attribute>
            <saml:Attribute Name="groups">{group_values}</saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>"##,
            issuer = xml_escape(&self.issuer),
            audience = xml_escape(&self.audience),
            name_id = xml_escape(&self.name_id),
            email = xml_escape(&self.email),
            display_name = xml_escape(&self.display_name),
        )
    }

    /// Render, sign with the checked-in IdP key, and base64-encode into the
    /// `SAMLResponse` form value the ACS endpoint consumes.
    pub fn signed_b64(&self) -> String {
        base64_standard(sign_saml_document(&self.to_unsigned_xml()).as_bytes())
    }
}

/// Base64 (standard alphabet, padded) — the encoding `saml_acs` decodes the
/// `SAMLResponse` form field with.
pub fn base64_standard(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Minimal XML attribute/text escaping for values interpolated into the SAML
/// template.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace("\"", "&quot;")
        .replace('\'', "&apos;")
}
