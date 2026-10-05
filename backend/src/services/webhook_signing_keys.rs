//! Instance-wide Ed25519 key for asymmetric (`v2=`) webhook signatures (#921).
//!
//! Webhooks whose `signing_mode` is `asymmetric` or `both` carry a
//! `v2=<kid>:<sig>` token in `X-ArtifactKeeper-Signature`, where `sig` is an
//! Ed25519 signature over `"<t>.<webhook_id>.<body>"`, and the delivery also
//! carries `X-ArtifactKeeper-Webhook-Id: <webhook_id>`. Receivers verify it
//! against the public key published at `GET /api/v1/webhooks/jwks`, so no
//! shared secret has to be distributed.
//!
//! **Why the webhook id is signed.** One key signs for every webhook on the
//! instance. Over `"<t>.<body>"` alone (the `v1=` message), a delivery
//! captured at receiver A would verify as genuine at receiver B within the
//! replay window; `v1=` never allowed that because each webhook has its own
//! secret. Binding the destination webhook id restores the property, provided
//! receivers check it: a receiver MUST reject a delivery whose
//! `X-ArtifactKeeper-Webhook-Id` is not its own webhook's id (returned when
//! the webhook is created), and verify the signature over that id.
//!
//! One key signs for the whole instance. Its private half is stored in
//! `webhook_signing_keys.private_key_encrypted`, encrypted with the same
//! `AK_WEBHOOK_SECRET_KEY` AES-256-GCM key that protects per-webhook HMAC
//! secrets ([`crate::services::webhook_secret_crypto`]); the public half is
//! stored in the clear so the JWKS endpoint never has to decrypt anything.
//! The key is created lazily on first use (JWKS fetch, asymmetric delivery,
//! or creating an asymmetric webhook). A partial unique index allows only
//! one active (`retired_at IS NULL`) key, so replicas racing to create it
//! converge on a single row.
//!
//! The `kid` is the RFC 7638 JWK thumbprint of the public key, so it is
//! stable, derivable by receivers, and changes whenever the key does.
//! Rotation (a new active key while the old one stays published for an
//! overlap window) is a follow-up; the schema already carries `retired_at`
//! for it, and the JWKS lists every key whose `retired_at` is unset or in
//! the future.
//!
//! **Recovery until rotation ships.** If `AK_WEBHOOK_SECRET_KEY` changes, the
//! active key can no longer be decrypted: asymmetric deliveries go out
//! without `v2=` (logged) and asymmetric creates return 422 saying so. An
//! administrator retires the undecryptable key with
//! `UPDATE webhook_signing_keys SET retired_at = NOW() WHERE retired_at IS NULL;`
//! a new key is created on next use, and receivers pick it up from the JWKS.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::Rng;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::services::webhook_secret_crypto::{self, WebhookSecretError};

/// JOSE algorithm name for Ed25519 (RFC 8037).
pub const JWK_ALG: &str = "EdDSA";

/// Errors raised while loading or creating the instance signing key.
#[derive(Debug, thiserror::Error)]
pub enum SigningKeyError {
    /// `AK_WEBHOOK_SECRET_KEY` is unset or malformed, so no key can be
    /// encrypted or decrypted.
    #[error("webhook signing key unavailable: {0}")]
    EncryptionKeyUnavailable(WebhookSecretError),

    /// `AK_WEBHOOK_SECRET_KEY` is set but cannot decrypt the stored active
    /// key (typically: it was changed after the key was created).
    #[error("stored webhook signing key cannot be decrypted with the current AK_WEBHOOK_SECRET_KEY: {0}")]
    Undecryptable(WebhookSecretError),

    /// The stored private key decrypted but is not a 32-byte Ed25519 seed.
    #[error("stored webhook signing key is malformed")]
    Malformed,

    /// The insert succeeded or lost the race, yet no active key could be
    /// read back (e.g. it was retired concurrently).
    #[error("active webhook signing key vanished after insert")]
    VanishedAfterInsert,

    #[error("webhook signing key query failed: {0}")]
    Database(#[from] sqlx::Error),
}

/// Sort a crypto failure into "no usable AES key configured" versus "the
/// configured key does not open the stored ciphertext".
fn classify_crypto_error(e: WebhookSecretError) -> SigningKeyError {
    match e {
        WebhookSecretError::KeyMissing
        | WebhookSecretError::KeyNotBase64(_)
        | WebhookSecretError::KeyWrongLength(_) => SigningKeyError::EncryptionKeyUnavailable(e),
        WebhookSecretError::Crypto(_) | WebhookSecretError::NotUtf8 => {
            SigningKeyError::Undecryptable(e)
        }
    }
}

/// The instance Ed25519 signing key together with its `kid`.
#[derive(Clone)]
pub struct InstanceSigningKey {
    kid: String,
    signing_key: SigningKey,
}

impl std::fmt::Debug for InstanceSigningKey {
    // Never print the private key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstanceSigningKey")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl InstanceSigningKey {
    /// Build a key from its 32-byte Ed25519 seed (the RFC 8032 private key).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let kid = jwk_thumbprint(&signing_key.verifying_key().to_bytes());
        Self { kid, signing_key }
    }

    /// Generate a fresh key from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        rand::rng().fill_bytes(seed.as_mut());
        Self::from_seed(&seed)
    }

    /// RFC 7638 thumbprint of the public key; the `kid` in JWKS and `v2=`.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Raw 32-byte Ed25519 public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Sign `"<unix_secs>.<webhook_id>.<body>"` and return the signature
    /// base64url encoded without padding. `body` must be the exact bytes
    /// POSTed and `webhook_id` the destination webhook.
    pub fn sign_v2(&self, unix_secs: i64, webhook_id: Uuid, body: &[u8]) -> String {
        let sig = self
            .signing_key
            .sign(&signed_message(unix_secs, webhook_id, body));
        B64URL.encode(sig.to_bytes())
    }

    /// The public JWK for this key.
    pub fn to_jwk(&self) -> Jwk {
        Jwk::from_public_key(&self.public_key_bytes())
    }
}

/// The message a `v2=` token signs: `"<unix_secs>.<webhook_id>.<body>"`,
/// with the webhook id in its lowercase hyphenated form (exactly the
/// `X-ArtifactKeeper-Webhook-Id` header value). Unlike `v1=` (whose
/// per-webhook secret already binds the destination), the instance-wide key
/// needs the id in the message so a delivery cannot be replayed to another
/// webhook's receiver.
fn signed_message(unix_secs: i64, webhook_id: Uuid, body: &[u8]) -> Vec<u8> {
    let prefix = format!("{}.{}.", unix_secs, webhook_id.as_hyphenated());
    let mut msg = Vec::with_capacity(prefix.len() + body.len());
    msg.extend_from_slice(prefix.as_bytes());
    msg.extend_from_slice(body);
    msg
}

/// RFC 7638 JWK thumbprint of an Ed25519 public key: SHA-256 over the
/// canonical `{"crv":"Ed25519","kty":"OKP","x":"<b64url>"}` JSON (members
/// in lexicographic order, no whitespace), base64url without padding.
pub fn jwk_thumbprint(public_key: &[u8; 32]) -> String {
    let canonical = format!(
        r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
        B64URL.encode(public_key)
    );
    B64URL.encode(Sha256::digest(canonical.as_bytes()))
}

/// A public Ed25519 JSON Web Key (RFC 8037 `OKP`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct Jwk {
    /// Key type; always `OKP`.
    pub kty: String,
    /// Curve; always `Ed25519`.
    pub crv: String,
    /// Base64url (no padding) of the 32-byte public key.
    pub x: String,
    /// Key id: RFC 7638 thumbprint. Matches the `<kid>` in `v2=<kid>:<sig>`.
    pub kid: String,
    /// Algorithm; always `EdDSA`.
    pub alg: String,
    /// Public key use; always `sig`.
    #[serde(rename = "use")]
    pub use_: String,
}

impl Jwk {
    /// Build the JWK for a raw Ed25519 public key.
    pub fn from_public_key(public_key: &[u8; 32]) -> Self {
        Self {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            x: B64URL.encode(public_key),
            kid: jwk_thumbprint(public_key),
            alg: JWK_ALG.to_string(),
            use_: "sig".to_string(),
        }
    }

    /// Verify a `v2=` signature (base64url, no padding) over
    /// `"<unix_secs>.<webhook_id>.<body>"` against this key. This is what a
    /// receiver does after checking `webhook_id` is its own webhook and
    /// picking the JWK whose `kid` matches the token. Returns `false` on any
    /// decode, length, or signature failure.
    pub fn verify_v2(
        &self,
        unix_secs: i64,
        webhook_id: Uuid,
        body: &[u8],
        sig_b64url: &str,
    ) -> bool {
        let Ok(x) = B64URL.decode(&self.x) else {
            return false;
        };
        let Ok(x) = <[u8; 32]>::try_from(x.as_slice()) else {
            return false;
        };
        let Ok(key) = VerifyingKey::from_bytes(&x) else {
            return false;
        };
        let Ok(sig) = B64URL.decode(sig_b64url) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(&sig) else {
            return false;
        };
        key.verify(&signed_message(unix_secs, webhook_id, body), &sig)
            .is_ok()
    }
}

/// The JWKS document served at `GET /api/v1/webhooks/jwks`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct JwksDocument {
    pub keys: Vec<Jwk>,
}

/// Build the JWKS from raw public keys, skipping any stored value that is
/// not exactly 32 bytes (the table's CHECK makes that impossible, but a
/// public endpoint must not panic on it).
pub fn jwks_from_public_keys(public_keys: &[Vec<u8>]) -> JwksDocument {
    let keys = public_keys
        .iter()
        .filter_map(|k| <[u8; 32]>::try_from(k.as_slice()).ok())
        .map(|k| Jwk::from_public_key(&k))
        .collect();
    JwksDocument { keys }
}

/// Decode a decrypted private key column back into a signing key.
fn key_from_decrypted_seed(seed: &[u8]) -> Result<InstanceSigningKey, SigningKeyError> {
    let seed = <[u8; 32]>::try_from(seed).map_err(|_| SigningKeyError::Malformed)?;
    Ok(InstanceSigningKey::from_seed(&seed))
}

async fn load_active_encrypted(db: &PgPool) -> Result<Option<Vec<u8>>, sqlx::Error> {
    sqlx::query_scalar(
        "SELECT private_key_encrypted FROM webhook_signing_keys \
         WHERE retired_at IS NULL ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_optional(db)
    .await
}

/// Decrypt a stored private key into a signing key; the plaintext seed is
/// zeroized when dropped.
fn decrypt_stored_key(ciphertext: &[u8]) -> Result<InstanceSigningKey, SigningKeyError> {
    let seed = Zeroizing::new(
        webhook_secret_crypto::decrypt_bytes(ciphertext).map_err(classify_crypto_error)?,
    );
    key_from_decrypted_seed(&seed)
}

/// Return the active instance signing key, creating it on first use.
///
/// Creation needs `AK_WEBHOOK_SECRET_KEY` (to encrypt the private key at
/// rest). Concurrent creators race on the one-active-key unique index; the
/// loser's insert is a no-op and it re-reads the winner's row.
pub async fn ensure_instance_key(db: &PgPool) -> Result<InstanceSigningKey, SigningKeyError> {
    if let Some(ct) = load_active_encrypted(db).await? {
        return decrypt_stored_key(&ct);
    }

    let fresh = InstanceSigningKey::generate();
    let encrypted = webhook_secret_crypto::encrypt_bytes(fresh.signing_key.as_bytes())
        .map_err(classify_crypto_error)?;
    sqlx::query(
        "INSERT INTO webhook_signing_keys (kid, public_key, private_key_encrypted) \
         VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(fresh.kid())
    .bind(fresh.public_key_bytes().as_slice())
    .bind(&encrypted)
    .execute(db)
    .await?;

    let ct = load_active_encrypted(db)
        .await?
        .ok_or(SigningKeyError::VanishedAfterInsert)?;
    decrypt_stored_key(&ct)
}

/// Set once the JWKS path has warned that no key can be created, so an
/// anonymous caller cannot flood the log at warn level.
static JWKS_UNAVAILABLE_WARNED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Whether this call should emit the warn-level "unavailable" log (first
/// time per process); later occurrences log at debug.
fn first_unavailable_warning() -> bool {
    !JWKS_UNAVAILABLE_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed)
}

/// Load the public JWKS: every key not yet retired, newest first.
///
/// Public keys are read in the clear; the private key is never touched when
/// an active key exists. Only when none exists is the instance key created,
/// so a receiver that fetches the JWKS before the first asymmetric delivery
/// still gets it. When that is impossible (no `AK_WEBHOOK_SECRET_KEY`) the
/// document is empty rather than an error: asymmetric signing is simply not
/// available yet.
pub async fn load_jwks(db: &PgPool) -> Result<JwksDocument, sqlx::Error> {
    let has_active: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM webhook_signing_keys WHERE retired_at IS NULL)",
    )
    .fetch_one(db)
    .await?;
    if !has_active {
        match ensure_instance_key(db).await {
            Ok(_) => {}
            Err(SigningKeyError::Database(e)) => return Err(e),
            Err(other) if first_unavailable_warning() => {
                tracing::warn!("webhook JWKS: instance signing key unavailable: {}", other)
            }
            Err(other) => {
                tracing::debug!("webhook JWKS: instance signing key unavailable: {}", other)
            }
        }
    }
    let public_keys: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT public_key FROM webhook_signing_keys \
         WHERE retired_at IS NULL OR retired_at > NOW() \
         ORDER BY created_at DESC",
    )
    .fetch_all(db)
    .await?;
    Ok(jwks_from_public_keys(&public_keys))
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8032 section 7.1 TEST 1 secret key; RFC 8037 appendix A uses
    /// the same key, so its published JWK and thumbprint pin ours.
    const RFC8032_SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

    fn rfc_key() -> InstanceSigningKey {
        let seed: [u8; 32] = hex::decode(RFC8032_SEED).unwrap().try_into().unwrap();
        InstanceSigningKey::from_seed(&seed)
    }

    #[test]
    fn jwk_matches_rfc8037_appendix_a() {
        let jwk = rfc_key().to_jwk();
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv, "Ed25519");
        assert_eq!(jwk.x, "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");
        // RFC 8037 A.3: the RFC 7638 thumbprint of that key.
        assert_eq!(jwk.kid, "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");
        assert_eq!(jwk.alg, "EdDSA");
        assert_eq!(jwk.use_, "sig");
    }

    #[test]
    fn kid_is_the_jwk_thumbprint() {
        let k = rfc_key();
        assert_eq!(k.kid(), jwk_thumbprint(&k.public_key_bytes()));
        assert_eq!(k.kid(), k.to_jwk().kid);
    }

    #[test]
    fn jwk_serializes_use_member_name() {
        let v = serde_json::to_value(rfc_key().to_jwk()).unwrap();
        assert_eq!(v["use"], "sig");
        assert!(v.get("use_").is_none());
    }

    fn wh(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    #[test]
    fn v2_signature_verifies_against_published_jwk() {
        let k = rfc_key();
        let body = br#"{"event":"artifact.uploaded"}"#;
        let sig = k.sign_v2(1_700_000_000, wh(1), body);
        let jwks = jwks_from_public_keys(&[k.public_key_bytes().to_vec()]);
        let jwk = jwks.keys.iter().find(|j| j.kid == k.kid()).unwrap();
        assert!(jwk.verify_v2(1_700_000_000, wh(1), body, &sig));
    }

    #[test]
    fn v2_signature_rejects_tampering() {
        let k = rfc_key();
        let jwk = k.to_jwk();
        let sig = k.sign_v2(1_700_000_000, wh(1), b"hello");
        assert!(!jwk.verify_v2(1_700_000_001, wh(1), b"hello", &sig));
        assert!(!jwk.verify_v2(1_700_000_000, wh(1), b"hellO", &sig));
        let other = InstanceSigningKey::generate().to_jwk();
        assert!(!other.verify_v2(1_700_000_000, wh(1), b"hello", &sig));
    }

    /// Review finding on #4414: a delivery signed for webhook A must not
    /// verify as a delivery for webhook B, even though one instance key signs
    /// both.
    #[test]
    fn v2_signature_is_bound_to_the_destination_webhook() {
        let k = rfc_key();
        let jwk = k.to_jwk();
        let body = br#"{"event":"artifact.uploaded"}"#;
        let for_a = k.sign_v2(1_700_000_000, wh(0xA), body);
        assert!(jwk.verify_v2(1_700_000_000, wh(0xA), body, &for_a));
        assert!(!jwk.verify_v2(1_700_000_000, wh(0xB), body, &for_a));
        assert_ne!(for_a, k.sign_v2(1_700_000_000, wh(0xB), body));
    }

    #[test]
    fn v2_signature_is_unpadded_base64url_of_64_bytes() {
        let sig = rfc_key().sign_v2(1, wh(1), b"x");
        assert!(!sig.contains('='));
        assert!(!sig.contains('+') && !sig.contains('/'));
        assert_eq!(B64URL.decode(&sig).unwrap().len(), 64);
    }

    #[test]
    fn verify_v2_rejects_malformed_inputs() {
        let k = rfc_key();
        let jwk = k.to_jwk();
        assert!(!jwk.verify_v2(1, wh(1), b"x", "not base64!"));
        assert!(!jwk.verify_v2(1, wh(1), b"x", &B64URL.encode([0u8; 10])));
        let mut bad = jwk.clone();
        bad.x = B64URL.encode([1u8; 5]);
        assert!(!bad.verify_v2(1, wh(1), b"x", &k.sign_v2(1, wh(1), b"x")));
        bad.x = "%%%".to_string();
        assert!(!bad.verify_v2(1, wh(1), b"x", &k.sign_v2(1, wh(1), b"x")));
    }

    #[test]
    fn generated_keys_are_distinct() {
        assert_ne!(
            InstanceSigningKey::generate().kid(),
            InstanceSigningKey::generate().kid()
        );
    }

    #[test]
    fn jwks_skips_malformed_public_keys() {
        let good = rfc_key().public_key_bytes().to_vec();
        let doc = jwks_from_public_keys(&[vec![1, 2, 3], good]);
        assert_eq!(doc.keys.len(), 1);
        assert!(jwks_from_public_keys(&[]).keys.is_empty());
    }

    #[test]
    fn decrypted_seed_must_be_32_bytes() {
        assert!(matches!(
            key_from_decrypted_seed(&[0u8; 31]),
            Err(SigningKeyError::Malformed)
        ));
        let k = key_from_decrypted_seed(&[7u8; 32]).unwrap();
        assert_eq!(k.kid(), InstanceSigningKey::from_seed(&[7u8; 32]).kid());
    }

    #[test]
    fn debug_does_not_leak_private_key() {
        let k = InstanceSigningKey::from_seed(&[0xAB; 32]);
        let dbg = format!("{:?}", k);
        assert!(dbg.contains(k.kid()));
        assert!(!dbg.to_lowercase().contains("abababab"));
    }

    #[test]
    fn signed_message_layout() {
        assert_eq!(
            signed_message(42, wh(0xAB), b"body"),
            b"42.00000000-0000-0000-0000-0000000000ab.body".to_vec()
        );
    }

    #[test]
    fn crypto_errors_are_classified() {
        use crate::services::encryption::EncryptionError;
        for e in [
            WebhookSecretError::KeyMissing,
            WebhookSecretError::KeyNotBase64("x".into()),
            WebhookSecretError::KeyWrongLength(3),
        ] {
            assert!(matches!(
                classify_crypto_error(e),
                SigningKeyError::EncryptionKeyUnavailable(_)
            ));
        }
        assert!(matches!(
            classify_crypto_error(WebhookSecretError::NotUtf8),
            SigningKeyError::Undecryptable(_)
        ));
        let decrypt_failed = WebhookSecretError::Crypto(EncryptionError::DecryptionFailed);
        assert!(matches!(
            classify_crypto_error(decrypt_failed),
            SigningKeyError::Undecryptable(_)
        ));
    }

    #[test]
    fn unavailable_warning_fires_once_per_process() {
        // Other tests in this process may already have consumed the first
        // warning; either way the second call must be debug-only.
        let _ = first_unavailable_warning();
        assert!(!first_unavailable_warning());
    }
}
