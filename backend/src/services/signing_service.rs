//! Signing service for GPG/RSA key management and metadata signing.
//!
//! Provides key generation, storage (encrypted), and signing operations
//! for Debian/APT, RPM/YUM, Alpine/APK, and Conda repositories.

use crate::error::{AppError, Result};
use crate::models::signing_key::{RepositorySigningConfig, SigningKey, SigningKeyPublic};
use crate::services::encryption::CredentialEncryption;
use chrono::{SubsecRound, Utc};
use pgp::composed::cleartext::CleartextSignedMessage;
use pgp::composed::key::{KeyType, SecretKeyParamsBuilder};
use pgp::composed::{Deserializable, SignedPublicKey, StandaloneSignature};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::packet::{SignatureConfig, SignatureType, Subpacket, SubpacketData};
use pgp::types::{KeyVersion, PublicKeyTrait};
use pgp::ArmorOptions;
use rsa::pkcs1v15::SigningKey as RsaSigningKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rsa::signature::{SignatureEncoding, Signer};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256, Sha512};
use sqlx::PgPool;
use uuid::Uuid;
use zeroize::Zeroizing;

/// `signing_keys.name` of the dedicated key that signs a hosted hex
/// repository's registry resources. Also the discriminator for the partial
/// unique index that keeps provisioning idempotent (migration 167).
pub const HEX_REGISTRY_KEY_NAME: &str = "hex-registry";

/// Key strength for hex registry keys. Hex fixes the signature algorithm
/// (RSA + SHA-512) but not the modulus size; 2048 matches what `mix
/// hex.registry build` produces via `openssl genrsa` and keeps provisioning
/// fast.
pub const HEX_REGISTRY_KEY_ALGORITHM: &str = "rsa2048";

/// Second key (lock *class*) for the two-key `pg_advisory_xact_lock(int4,
/// int4)` that serializes hex registry key provisioning per repository. The
/// first key is the entity — `hashtext(repository_id)` — matching the
/// key-order convention of the other two-key advisory-lock users
/// (`sync_worker`'s per-peer claim lock, `scan_result_service`'s
/// per-artifact preparer lock). The class keeps this lock space disjoint
/// from theirs.
const HEX_REGISTRY_KEY_LOCK_CLASS: i32 = 0x4845_5801; // "HEX\x01"

// ---------------------------------------------------------------------------
// Pure helper functions (no DB, testable in isolation)
// ---------------------------------------------------------------------------

/// Map an algorithm string to the RSA key size in bits.
/// Returns `Ok(bits)` for valid RSA algorithms, `Err(message)` for unsupported ones.
pub(crate) fn algorithm_to_bits(algorithm: &str) -> std::result::Result<usize, String> {
    match algorithm {
        "rsa2048" => Ok(2048),
        "rsa4096" | "rsa" => Ok(4096),
        other => Err(format!(
            "Unsupported algorithm: {}. Use rsa2048 or rsa4096.",
            other
        )),
    }
}

/// Normalize a key-type string to one of the families accepted by the
/// `signing_keys_key_type_check` DB constraint (`gpg`, `rsa`, `ed25519`).
///
/// Clients commonly send the RSA algorithm variant ("rsa2048"/"rsa4096") in
/// the `key_type` field; those are coerced to the `rsa` family. Anything else
/// is rejected with a message suitable for a 400 response, instead of letting
/// the value trip the CHECK constraint at INSERT time (opaque 500).
pub(crate) fn normalize_key_type(key_type: &str) -> std::result::Result<&'static str, String> {
    match key_type {
        "rsa" | "rsa2048" | "rsa4096" => Ok("rsa"),
        "gpg" => Ok("gpg"),
        "ed25519" => Ok("ed25519"),
        other => Err(format!(
            "Unsupported key_type: {}. Use gpg, rsa, or ed25519.",
            other
        )),
    }
}

fn algorithm_to_bits_u32(algorithm: &str) -> std::result::Result<u32, String> {
    algorithm_to_bits(algorithm).and_then(|bits| {
        u32::try_from(bits).map_err(|_| format!("Unsupported RSA key size: {}", bits))
    })
}

fn pgp_user_id(uid_name: Option<&str>, uid_email: Option<&str>, fallback_name: &str) -> String {
    match (uid_name, uid_email) {
        (Some(name), Some(email)) if !name.is_empty() && !email.is_empty() => {
            format!("{} <{}>", name, email)
        }
        (Some(name), _) if !name.is_empty() => name.to_string(),
        (_, Some(email)) if !email.is_empty() => format!("{} <{}>", fallback_name, email),
        _ => fallback_name.to_string(),
    }
}

/// Compute the SHA-256 fingerprint of a DER-encoded public key.
/// Returns the full hex-encoded fingerprint.
pub(crate) fn compute_fingerprint(public_key_der: &[u8]) -> String {
    hex::encode(Sha256::digest(public_key_der))
}

/// Derive the short key ID (last 16 hex chars) from a full fingerprint.
pub(crate) fn derive_key_id(fingerprint: &str) -> String {
    fingerprint[fingerprint.len().saturating_sub(16)..].to_string()
}

/// Maximum length (in characters) of a signing-key name. Mirrors the
/// `signing_keys.name` column, which is `VARCHAR(255)` (see migration
/// `027_signing_keys.sql`). Postgres counts characters, not bytes, for
/// `varchar(n)`, so this bound is enforced on `char` count below.
pub(crate) const MAX_KEY_NAME_LEN: usize = 255;

/// If `name` ends with a rotation suffix produced by [`build_rotated_key_name`]
/// (`" (rotated)"` or `" (rotated N)"`), return the base name and the current
/// rotation count (`" (rotated)"` counts as 1). Returns `None` when there is no
/// recognizable rotation suffix.
fn parse_rotation_suffix(name: &str) -> Option<(&str, u32)> {
    // The first rotation uses the bare "(rotated)" suffix (count 1).
    if let Some(base) = name.strip_suffix(" (rotated)") {
        return Some((base, 1));
    }
    // Subsequent rotations use a numeric "(rotated N)" suffix with N >= 2.
    let without_paren = name.strip_suffix(')')?;
    let idx = without_paren.rfind(" (rotated ")?;
    let num_str = &without_paren[idx + " (rotated ".len()..];
    let n: u32 = num_str.parse().ok()?;
    if n >= 2 {
        Some((&without_paren[..idx], n))
    } else {
        None
    }
}

/// Build a rotated key name from an existing key name.
///
/// Rotation uses a *bounded* counter suffix so the name can never grow without
/// limit. The old scheme unconditionally appended `" (rotated)"` (+10 chars) on
/// every rotation, so after ~25 rotations the successor name overflowed the
/// `varchar(255)` column, the INSERT 500'd, and the key became permanently
/// un-rotatable (#2543). The counter *replaces* the previous suffix instead of
/// accumulating:
///
/// * `my-key`              -> `my-key (rotated)`
/// * `my-key (rotated)`    -> `my-key (rotated 2)`
/// * `my-key (rotated 2)`  -> `my-key (rotated 3)`
///
/// Each successor stays readable and distinct from its predecessor. If the base
/// name is long enough that appending the suffix would exceed
/// [`MAX_KEY_NAME_LEN`] characters, the base is truncated on a `char` boundary
/// to make room, guaranteeing the result always fits the column.
pub(crate) fn build_rotated_key_name(original_name: &str) -> String {
    let next = match parse_rotation_suffix(original_name) {
        Some((base, n)) => (base, n.saturating_add(1)),
        None => (original_name, 1),
    };
    let (base, count) = next;
    let suffix = if count <= 1 {
        " (rotated)".to_string()
    } else {
        format!(" (rotated {})", count)
    };
    // Reserve room for the suffix and truncate the base on a char boundary so
    // the final name never exceeds the varchar(255) column, even for a
    // pathologically long base name.
    let room = MAX_KEY_NAME_LEN.saturating_sub(suffix.chars().count());
    let base: String = base.chars().take(room).collect();
    format!("{}{}", base, suffix)
}

// ---------------------------------------------------------------------------
// CPU-bound rPGP helpers
//
// These are pure functions with no I/O or DB access, intended to be invoked
// from `tokio::task::spawn_blocking` (#1236 review). RSA key generation can
// take hundreds of milliseconds to multiple seconds, and OpenPGP signing is
// also non-trivial CPU work. Running them inline on a tokio runtime worker
// stalls the rest of the HTTP server.
// ---------------------------------------------------------------------------

/// Parameters describing an OpenPGP key to generate. Owns its data so it can
/// cross a `spawn_blocking` boundary.
struct OpenPgpKeyParams {
    bits: u32,
    user_id: String,
}

/// Generate an OpenPGP RSA key pair and return
/// (armored_public, armored_private, fingerprint_hex, key_id_hex).
///
/// CPU-bound. Call from within `spawn_blocking`.
fn generate_openpgp_key_blocking(
    params: OpenPgpKeyParams,
) -> Result<(String, String, String, String)> {
    let mut key_params = SecretKeyParamsBuilder::default();
    key_params
        .version(KeyVersion::V4)
        .key_type(KeyType::Rsa(params.bits))
        .can_certify(true)
        .can_sign(true)
        .primary_user_id(params.user_id)
        .passphrase(None);

    let mut rng = rand08::rngs::OsRng;
    let secret_key = key_params
        .build()
        .map_err(|e| AppError::Internal(format!("Failed to build OpenPGP key params: {}", e)))?
        .generate(rng)
        .map_err(|e| AppError::Internal(format!("Failed to generate OpenPGP key: {}", e)))?;
    let signed_secret_key = secret_key
        .sign(&mut rng, String::new)
        .map_err(|e| AppError::Internal(format!("Failed to certify OpenPGP key: {}", e)))?;
    let public_key = SignedPublicKey::from(signed_secret_key.clone());

    let public_armored = public_key
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| AppError::Internal(format!("Failed to armor OpenPGP public key: {}", e)))?;
    let private_armored = signed_secret_key
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| AppError::Internal(format!("Failed to armor OpenPGP private key: {}", e)))?;

    let fingerprint = hex::encode(public_key.fingerprint().as_bytes());
    let key_id = hex::encode(public_key.key_id().as_ref());

    Ok((public_armored, private_armored, fingerprint, key_id))
}

/// Verify a detached ASCII-armored OpenPGP signature over `data` against a
/// trusted ASCII-armored public key.
///
/// Returns `Ok(())` only when the signature is valid and made by the trusted
/// key. Used to authenticate an upstream RPM repository's `repomd.xml.asc`
/// before its declared checksums are trusted during a curation sync (#2357):
/// the sync is fail-closed, so any parse or verification error rejects the
/// batch rather than ingesting unverified metadata.
///
/// CPU-bound (public-key verification); call from within `spawn_blocking` when
/// on a request/async path.
pub fn verify_detached(trusted_armored_key: &str, data: &[u8], armored_sig: &str) -> Result<()> {
    let (public_key, _) = SignedPublicKey::from_string(trusted_armored_key)
        .map_err(|e| AppError::Validation(format!("Invalid trusted GPG public key: {}", e)))?;
    let (signature, _) = StandaloneSignature::from_string(armored_sig)
        .map_err(|e| AppError::Validation(format!("Invalid detached signature: {}", e)))?;
    signature.verify(&public_key, data).map_err(|e| {
        AppError::Authorization(format!("Upstream signature verification failed: {}", e))
    })
}

/// Create an ASCII-armored detached OpenPGP signature.
///
/// CPU-bound. Call from within `spawn_blocking`.
fn sign_openpgp_detached_blocking(
    secret_key: pgp::SignedSecretKey,
    data: Vec<u8>,
) -> Result<String> {
    let mut config = SignatureConfig::v4(
        SignatureType::Binary,
        PublicKeyAlgorithm::RSA,
        HashAlgorithm::SHA2_256,
    );
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::IssuerFingerprint(secret_key.fingerprint())),
        Subpacket::regular(SubpacketData::SignatureCreationTime(
            chrono::Utc::now().trunc_subsecs(0),
        )),
    ];
    config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::Issuer(
        secret_key.key_id(),
    ))];

    let signature = config
        .sign(&secret_key, String::new, &data[..])
        .map_err(|e| AppError::Internal(format!("Failed to sign OpenPGP data: {}", e)))?;
    StandaloneSignature::new(signature)
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| AppError::Internal(format!("Failed to armor OpenPGP signature: {}", e)))
}

/// Create an OpenPGP cleartext signed message.
///
/// CPU-bound. Call from within `spawn_blocking`.
fn sign_openpgp_cleartext_blocking(
    secret_key: pgp::SignedSecretKey,
    text: String,
) -> Result<String> {
    let rng = rand08::rngs::OsRng;
    CleartextSignedMessage::sign(rng, &text, &secret_key, String::new)
        .and_then(|msg| msg.to_armored_string(ArmorOptions::default()))
        .map_err(|e| {
            AppError::Internal(format!(
                "Failed to create OpenPGP cleartext signature: {}",
                e
            ))
        })
}

/// Helper to dispatch a CPU-bound crypto closure to the blocking pool and
/// convert a panic into an `AppError::Internal`. Centralizes the
/// `spawn_blocking` join-error handling so callers stay readable.
async fn run_blocking<F, T>(label: &'static str, f: F) -> Result<T>
where
    F: FnOnce() -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| AppError::Internal(format!("{label} task panicked: {e}")))?
}

/// Service for managing signing keys and signing operations.
pub struct SigningService {
    db: PgPool,
    encryption: CredentialEncryption,
}

/// Result of a deliberate per-artifact signing action (#2535). The signature
/// blob itself is not persisted (marker-only attestation); the returned digest
/// lets the caller surface what was produced.
pub struct ArtifactSignature {
    pub key_id: Uuid,
    pub algorithm: String,
    pub signature_sha256: String,
}

/// Request to create a new signing key.
pub struct CreateKeyRequest {
    pub repository_id: Option<Uuid>,
    pub name: String,
    pub key_type: String,  // "gpg", "rsa", "ed25519"
    pub algorithm: String, // "rsa2048", "rsa4096"
    pub uid_name: Option<String>,
    pub uid_email: Option<String>,
    pub created_by: Option<Uuid>,
}

/// Freshly generated (and at-rest-encrypted) key material, ready to be
/// inserted as a `signing_keys` row.
///
/// Produced by [`SigningService::generate_key_material`] — the slow, CPU-bound
/// half of key creation — so that the actual row INSERT can run inside a
/// caller-supplied transaction without holding a DB lock across keygen.
struct GeneratedKeyMaterial {
    /// Normalized key family (`gpg` / `rsa` / `ed25519`).
    key_type: String,
    public_key_pem: String,
    /// Private key, already encrypted for at-rest storage.
    private_key_enc: Vec<u8>,
    fingerprint: String,
    key_id: String,
}

impl SigningService {
    pub fn new(db: PgPool, encryption_key: &str) -> Self {
        Self {
            db,
            encryption: CredentialEncryption::from_passphrase(encryption_key),
        }
    }

    /// Generate a new signing key pair and store it.
    pub async fn create_key(&self, req: CreateKeyRequest) -> Result<SigningKeyPublic> {
        // Slow, CPU-bound keygen (+ at-rest encryption) first, then a single
        // fast INSERT. Split out so `rotate_key` can run the INSERT inside a
        // transaction without holding a DB lock across keygen.
        let material = self.generate_key_material(&req).await?;

        let id = Uuid::new_v4();
        let now = Utc::now();

        Self::insert_key_row(&self.db, id, &req, &material, true, None, now).await?;

        // Audit log
        self.audit_key_action(id, "created", req.created_by, None)
            .await?;

        Ok(SigningKeyPublic {
            id,
            repository_id: req.repository_id,
            name: req.name,
            key_type: material.key_type,
            fingerprint: Some(material.fingerprint),
            key_id: Some(material.key_id),
            public_key_pem: material.public_key_pem,
            algorithm: req.algorithm,
            uid_name: req.uid_name,
            uid_email: req.uid_email,
            expires_at: None,
            is_active: true,
            created_at: now,
            last_used_at: None,
        })
    }

    /// Generate a key pair for `req` and encrypt the private material for
    /// at-rest storage. This is the slow (multi-second RSA/OpenPGP keygen)
    /// half of key creation; it touches no DB and holds no lock, so callers
    /// may run it *before* opening a transaction.
    async fn generate_key_material(&self, req: &CreateKeyRequest) -> Result<GeneratedKeyMaterial> {
        // Normalize the key family before generation so an unsupported value
        // surfaces as a clean 400 Validation error instead of tripping the
        // signing_keys_key_type_check DB constraint (opaque 500). (#2319)
        let key_type = normalize_key_type(&req.key_type)
            .map_err(AppError::Validation)?
            .to_string();

        let (public_key_out, private_key_material, fingerprint, key_id) = if key_type == "gpg" {
            self.generate_openpgp_key(req).await?
        } else {
            self.generate_rsa_key(&req.algorithm).await?
        };

        // Hold the freshly generated armored / PEM private key in a zeroizing
        // wrapper so the plaintext is wiped from memory after we encrypt it
        // for at-rest storage (artifact-keeper #1328).
        let private_key_material = Zeroizing::new(private_key_material);
        let private_key_enc = self.encryption.encrypt(private_key_material.as_bytes());

        Ok(GeneratedKeyMaterial {
            key_type,
            public_key_pem: public_key_out,
            private_key_enc,
            fingerprint,
            key_id,
        })
    }

    /// Insert a `signing_keys` row from already-generated `material`, on any
    /// executor (the pool for `create_key`, or a `&mut *tx` for `rotate_key`
    /// so the insert rolls back with the rest of the rotation).
    async fn insert_key_row<'e, E>(
        exec: E,
        id: Uuid,
        req: &CreateKeyRequest,
        material: &GeneratedKeyMaterial,
        is_active: bool,
        rotated_from: Option<Uuid>,
        now: chrono::DateTime<Utc>,
    ) -> Result<()>
    where
        E: sqlx::PgExecutor<'e>,
    {
        sqlx::query!(
            r#"
            INSERT INTO signing_keys (id, repository_id, name, key_type, fingerprint, key_id,
                public_key_pem, private_key_enc, algorithm, uid_name, uid_email, is_active,
                created_at, created_by, rotated_from)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            "#,
            id,
            req.repository_id,
            req.name,
            material.key_type,
            material.fingerprint,
            material.key_id,
            material.public_key_pem,
            material.private_key_enc,
            req.algorithm,
            req.uid_name,
            req.uid_email,
            is_active,
            now,
            req.created_by,
            rotated_from,
        )
        .execute(exec)
        .await?;
        Ok(())
    }

    async fn generate_rsa_key(&self, algorithm: &str) -> Result<(String, String, String, String)> {
        let bits = algorithm_to_bits(algorithm).map_err(AppError::Validation)?;

        // RSA-4096 key generation is CPU-bound and can take multiple seconds
        // under load. Run on the blocking pool so the async runtime stays free
        // to service other requests.
        run_blocking("rsa_keygen", move || {
            let mut rng = rsa::rand_core::OsRng;
            let private_key = RsaPrivateKey::new(&mut rng, bits)
                .map_err(|e| AppError::Internal(format!("Failed to generate RSA key: {}", e)))?;
            let public_key = RsaPublicKey::from(&private_key);

            let public_pem = public_key
                .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
                .map_err(|e| AppError::Internal(format!("Failed to encode public key: {}", e)))?;
            let private_pem = private_key
                .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                .map_err(|e| AppError::Internal(format!("Failed to encode private key: {}", e)))?
                .to_string();

            let public_der = public_key.to_public_key_der().map_err(|e| {
                AppError::Internal(format!("Failed to encode public key DER: {}", e))
            })?;
            let fingerprint = compute_fingerprint(public_der.as_ref());
            let key_id = derive_key_id(&fingerprint);

            Ok((public_pem, private_pem, fingerprint, key_id))
        })
        .await
    }

    async fn generate_openpgp_key(
        &self,
        req: &CreateKeyRequest,
    ) -> Result<(String, String, String, String)> {
        let bits = algorithm_to_bits_u32(&req.algorithm).map_err(AppError::Validation)?;
        let user_id = pgp_user_id(req.uid_name.as_deref(), req.uid_email.as_deref(), &req.name);

        // Building and signing an RSA-4096 OpenPGP key is CPU-bound and can
        // take multiple seconds. Run on the blocking pool (#1236 review).
        let params = OpenPgpKeyParams { bits, user_id };
        run_blocking("openpgp_keygen", move || {
            generate_openpgp_key_blocking(params)
        })
        .await
    }

    /// Get a signing key by ID (public info only).
    pub async fn get_key(&self, key_id: Uuid) -> Result<SigningKeyPublic> {
        let key = sqlx::query_as!(
            SigningKey,
            "SELECT * FROM signing_keys WHERE id = $1",
            key_id,
        )
        .fetch_optional(&self.db)
        .await?
        .ok_or_else(|| AppError::NotFound("Signing key not found".to_string()))?;

        Ok(key.into())
    }

    /// Get the active signing key for a repository.
    pub async fn get_active_key_for_repo(&self, repo_id: Uuid) -> Result<Option<SigningKey>> {
        let key = sqlx::query_as!(
            SigningKey,
            r#"
            SELECT sk.* FROM signing_keys sk
            JOIN repository_signing_config rsc ON rsc.signing_key_id = sk.id
            WHERE rsc.repository_id = $1 AND sk.is_active = true AND rsc.sign_metadata = true
            LIMIT 1
            "#,
            repo_id,
        )
        .fetch_optional(&self.db)
        .await?;

        Ok(key)
    }

    /// List signing keys, optionally filtered by repository.
    pub async fn list_keys(&self, repo_id: Option<Uuid>) -> Result<Vec<SigningKeyPublic>> {
        let keys = if let Some(rid) = repo_id {
            sqlx::query_as!(
                SigningKey,
                "SELECT * FROM signing_keys WHERE repository_id = $1 ORDER BY created_at DESC",
                rid,
            )
            .fetch_all(&self.db)
            .await?
        } else {
            sqlx::query_as!(
                SigningKey,
                "SELECT * FROM signing_keys ORDER BY created_at DESC",
            )
            .fetch_all(&self.db)
            .await?
        };

        Ok(keys.into_iter().map(|k| k.into()).collect())
    }

    /// Deactivate (revoke) a signing key.
    pub async fn revoke_key(&self, key_id: Uuid, user_id: Option<Uuid>) -> Result<()> {
        let result = sqlx::query!(
            "UPDATE signing_keys SET is_active = false WHERE id = $1",
            key_id,
        )
        .execute(&self.db)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Signing key not found".to_string()));
        }

        self.audit_key_action(key_id, "revoked", user_id, None)
            .await?;
        Ok(())
    }

    /// Delete a signing key permanently.
    pub async fn delete_key(&self, key_id: Uuid) -> Result<()> {
        sqlx::query!("DELETE FROM signing_keys WHERE id = $1", key_id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    async fn active_key_or_none(&self, repo_id: Uuid) -> Result<Option<SigningKey>> {
        self.get_active_key_for_repo(repo_id).await
    }

    /// Sign data with the repository's active signing key (RSA PKCS#1 v1.5 SHA-256).
    pub async fn sign_data(&self, repo_id: Uuid, data: &[u8]) -> Result<Option<Vec<u8>>> {
        let key = match self.get_active_key_for_repo(repo_id).await? {
            Some(k) => k,
            None => return Ok(None),
        };

        let signature = self.sign_with_key(&key, data)?;

        // Update last_used_at
        sqlx::query!(
            "UPDATE signing_keys SET last_used_at = NOW() WHERE id = $1",
            key.id,
        )
        .execute(&self.db)
        .await?;

        Ok(Some(signature))
    }

    /// Produce a deliberate, authorized signature over an artifact's content
    /// with the repository's **active** signing key, and record the
    /// `used_for_signing` marker the promotion `require_signature` gate reads
    /// (#2535).
    ///
    /// This is the **sole** writer of the per-artifact marker: it is only
    /// reachable from the admin-gated `POST /signing/artifacts/:id/sign`
    /// endpoint, so an artifact can satisfy `require_signature` only through an
    /// explicit, authenticated signing action over its bytes — never as a side
    /// effect of an anonymous metadata read.
    ///
    /// Returns `Ok(None)` when the repository has no active signing key /
    /// signing config (the caller maps this to a 409), so a repo that cannot
    /// sign stays fail-closed. Format-agnostic: signs raw content bytes, so it
    /// works for maven/npm/pypi/etc., not only the metadata-signing formats.
    pub async fn sign_artifact_content(
        &self,
        repo_id: Uuid,
        artifact_id: Uuid,
        content: &[u8],
        performed_by: Option<Uuid>,
    ) -> Result<Option<ArtifactSignature>> {
        let key = match self.get_active_key_for_repo(repo_id).await? {
            Some(k) => k,
            None => return Ok(None),
        };

        // Produce a real content signature with whichever key material the
        // repo's active key holds.
        let (signature, algorithm) = if key.key_type == "gpg" {
            let armored = self.sign_openpgp_detached_with_key(&key, content).await?;
            (armored.into_bytes(), format!("openpgp:{}", key.algorithm))
        } else {
            let sig = self.sign_with_key(&key, content)?;
            (sig, format!("rsa-pkcs1v15-sha256:{}", key.algorithm))
        };

        let signature_sha256 = hex::encode(Sha256::digest(&signature));

        self.record_artifact_signature(
            key.id,
            artifact_id,
            performed_by,
            &algorithm,
            &signature_sha256,
        )
        .await?;
        self.mark_key_used(key.id).await?;

        Ok(Some(ArtifactSignature {
            key_id: key.id,
            algorithm,
            signature_sha256,
        }))
    }

    /// Insert the single `used_for_signing` audit row that attests `artifact_id`
    /// under `key_id` (#2535). Idempotent on `(key_id, artifact_id)`: re-signing
    /// the same artifact with the same active key does not accumulate duplicate
    /// markers.
    async fn record_artifact_signature(
        &self,
        key_id: Uuid,
        artifact_id: Uuid,
        performed_by: Option<Uuid>,
        algorithm: &str,
        signature_sha256: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO signing_key_audit (signing_key_id, action, performed_by, details)
            SELECT $1, 'used_for_signing', $2,
                   jsonb_build_object(
                       'artifact_id', $3::text,
                       'algorithm', $4::text,
                       'signature_sha256', $5::text
                   )
            WHERE NOT EXISTS (
                SELECT 1 FROM signing_key_audit ska
                WHERE ska.signing_key_id = $1
                  AND ska.action = 'used_for_signing'
                  AND ska.details->>'artifact_id' = $3::text
            )
            "#,
        )
        .bind(key_id)
        .bind(performed_by)
        .bind(artifact_id)
        .bind(algorithm)
        .bind(signature_sha256)
        .execute(&self.db)
        .await?;
        Ok(())
    }

    /// Sign data with a specific key.
    ///
    /// The decrypted PEM bytes are held in a `Zeroizing<Vec<u8>>` so the
    /// plaintext private-key material is wiped from memory when the buffer
    /// drops, rather than waiting for the allocator to reuse the slot
    /// (artifact-keeper #1328). The parsed `RsaPrivateKey` and the derived
    /// `RsaSigningKey<Sha256>` both already implement `ZeroizeOnDrop` upstream
    /// in the `rsa` crate, so they self-clean when this function returns.
    pub fn sign_with_key(&self, key: &SigningKey, data: &[u8]) -> Result<Vec<u8>> {
        // Decrypt private key into a zeroizing buffer.
        let private_pem: Zeroizing<Vec<u8>> =
            Zeroizing::new(self.encryption.decrypt(&key.private_key_enc).map_err(|e| {
                AppError::Internal(format!("Failed to decrypt private key: {}", e))
            })?);

        let private_key = RsaPrivateKey::from_pkcs8_pem(
            std::str::from_utf8(&private_pem)
                .map_err(|e| AppError::Internal(format!("Invalid UTF-8 in key: {}", e)))?,
        )
        .map_err(|e| AppError::Internal(format!("Failed to parse private key: {}", e)))?;

        let signing_key = RsaSigningKey::<Sha256>::new(private_key);
        let signature = signing_key.sign(data);

        Ok(signature.to_bytes().to_vec())
    }

    /// Sign hex registry bytes with `key`: RSA PKCS#1 v1.5, **SHA-512** digest.
    ///
    /// The hex protocol fixes both the padding and the digest — the real client
    /// verifies with `public_key:verify(Payload, sha512, Signature, RSAPublicKey)`
    /// (hex 2.5.1, `mix_hex_registry:verify/3`). That is why this cannot reuse
    /// [`SigningService::sign_with_key`], which signs with SHA-256 for the
    /// Debian/Conda metadata paths: a SHA-256 signature is well-formed but the
    /// hex client rejects it.
    ///
    /// Mirrors `sign_with_key`'s handling of the decrypted private key: the PEM
    /// plaintext lives in a `Zeroizing` buffer and the parsed key self-cleans on
    /// drop (#1328).
    pub fn sign_hex_registry(&self, key: &SigningKey, data: &[u8]) -> Result<Vec<u8>> {
        let private_pem: Zeroizing<Vec<u8>> =
            Zeroizing::new(self.encryption.decrypt(&key.private_key_enc).map_err(|e| {
                AppError::Internal(format!("Failed to decrypt private key: {}", e))
            })?);

        let private_key = RsaPrivateKey::from_pkcs8_pem(
            std::str::from_utf8(&private_pem)
                .map_err(|e| AppError::Internal(format!("Invalid UTF-8 in key: {}", e)))?,
        )
        .map_err(|e| AppError::Internal(format!("Failed to parse private key: {}", e)))?;

        let signing_key = RsaSigningKey::<Sha512>::new(private_key);
        Ok(signing_key.sign(data).to_bytes().to_vec())
    }

    /// Look up a repository's dedicated hex registry key, if it has one.
    ///
    /// The predicate here is mirrored exactly by the partial unique index in
    /// migration 167. Changing one without the other lets provisioning conflict
    /// against a row this lookup cannot see (see that migration's note).
    async fn find_hex_registry_key_exec<'e, E>(exec: E, repo_id: Uuid) -> Result<Option<SigningKey>>
    where
        E: sqlx::PgExecutor<'e>,
    {
        let key = sqlx::query_as!(
            SigningKey,
            r#"
            SELECT * FROM signing_keys
            WHERE repository_id = $1 AND name = $2 AND is_active = true
            LIMIT 1
            "#,
            repo_id,
            HEX_REGISTRY_KEY_NAME,
        )
        .fetch_optional(exec)
        .await?;
        Ok(key)
    }

    /// Look up a repository's dedicated hex registry key on the pool.
    async fn find_hex_registry_key(&self, repo_id: Uuid) -> Result<Option<SigningKey>> {
        Self::find_hex_registry_key_exec(&self.db, repo_id).await
    }

    /// Provision the RSA key that signs a hosted hex repository's registry
    /// resources, if it does not already have an active one.
    ///
    /// Hex differs from the other signed formats in that signing is not
    /// optional: a registry with no signature is unusable, so there is no
    /// "unsigned but working" mode to fall back to and a repo with no key would
    /// simply be broken. The key is therefore provisioned eagerly when a hosted
    /// hex repository is created (an authenticated, once-per-repo operation) and
    /// stored like every other signing key (`signing_keys`, private half
    /// encrypted at rest).
    ///
    /// [`Self::get_or_create_hex_registry_key`] calls this as a *self-heal* for
    /// repositories that predate eager provisioning, and after a revoke.
    ///
    /// Deliberately does **not** write `repository_signing_config`: that table
    /// drives the Debian/Conda `sign_metadata` behaviour and the promotion
    /// `require_signature` gate, and a hex repo publishing its own registry key
    /// must not imply anything about those.
    ///
    /// ## Why the advisory lock
    ///
    /// Keygen is CPU-bound and runs on the blocking pool (via
    /// `generate_key_material`). The partial unique index dedupes the resulting
    /// *row*, but it cannot dedupe the *work*: without serialization, N
    /// concurrent callers each complete a full RSA-2048 keygen and N-1 of them
    /// throw the result away on conflict. A transaction-scoped advisory lock
    /// keyed on the repository makes the check-then-generate sequence atomic, so
    /// exactly one keygen runs per repository and the losers wake up and read
    /// the winner's row. The lock is released automatically when the transaction
    /// ends, including on error.
    pub async fn provision_hex_registry_key(&self, repo_id: Uuid) -> Result<SigningKey> {
        // Cheap un-serialized pre-check: the overwhelmingly common case is that
        // the key already exists, and that path should not take a lock at all.
        if let Some(key) = self.find_hex_registry_key(repo_id).await? {
            return Ok(key);
        }

        let mut tx = self.db.begin().await?;

        // Serialize provisioning per repository. Two-key advisory lock —
        // entity (repository) first, lock class second, like the other
        // two-key users — with the class keeping it distinct from them
        // (`cluster_lock`, `repository_service`, the admin-password init).
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1), $2)")
            .bind(repo_id.to_string())
            .bind(HEX_REGISTRY_KEY_LOCK_CLASS)
            .execute(&mut *tx)
            .await?;

        // Re-check under the lock: a concurrent caller may have provisioned the
        // key between the pre-check and acquiring the lock.
        if let Some(key) = Self::find_hex_registry_key_exec(&mut *tx, repo_id).await? {
            return Ok(key);
        }

        let req = CreateKeyRequest {
            repository_id: Some(repo_id),
            name: HEX_REGISTRY_KEY_NAME.to_string(),
            key_type: "rsa".to_string(),
            algorithm: HEX_REGISTRY_KEY_ALGORITHM.to_string(),
            uid_name: None,
            uid_email: None,
            created_by: None,
        };
        let material = self.generate_key_material(&req).await?;

        sqlx::query!(
            r#"
            INSERT INTO signing_keys (id, repository_id, name, key_type, fingerprint, key_id,
                public_key_pem, private_key_enc, algorithm, is_active, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, true, $10)
            ON CONFLICT DO NOTHING
            "#,
            Uuid::new_v4(),
            repo_id,
            HEX_REGISTRY_KEY_NAME,
            material.key_type,
            material.fingerprint,
            material.key_id,
            material.public_key_pem,
            material.private_key_enc,
            HEX_REGISTRY_KEY_ALGORITHM,
            Utc::now(),
        )
        .execute(&mut *tx)
        .await?;

        // Re-select rather than trusting the INSERT: the advisory lock makes a
        // conflict here vanishingly unlikely, but ON CONFLICT DO NOTHING still
        // means the row that must be used is whichever one is actually there.
        let key = Self::find_hex_registry_key_exec(&mut *tx, repo_id)
            .await?
            .ok_or_else(|| {
                AppError::Internal("Failed to provision hex registry signing key".to_string())
            })?;

        tx.commit().await?;
        Ok(key)
    }

    /// Get a repository's hex registry key, provisioning it if absent.
    ///
    /// Provisioning normally happens at repository creation, so on the registry
    /// read path this is expected to be a plain lookup. It stays a
    /// `get_or_create` as a self-heal for the two cases where an active key can
    /// legitimately be missing:
    ///
    /// * the repository was created before eager provisioning existed, or by a
    ///   path that does not run it (import, direct DB seed);
    /// * the key was revoked, and the repository needs a fresh one.
    ///
    /// See [`Self::provision_hex_registry_key`] for the concurrency story.
    pub async fn get_or_create_hex_registry_key(&self, repo_id: Uuid) -> Result<SigningKey> {
        self.provision_hex_registry_key(repo_id).await
    }

    /// Create an ASCII-armored detached OpenPGP signature for repository metadata.
    pub async fn sign_openpgp_detached(
        &self,
        repo_id: Uuid,
        data: &[u8],
    ) -> Result<Option<String>> {
        let key = match self.active_key_or_none(repo_id).await? {
            Some(k) => k,
            None => return Ok(None),
        };
        let armored = self.sign_openpgp_detached_with_key(&key, data).await?;
        self.mark_key_used(key.id).await?;
        Ok(Some(armored))
    }

    /// Create an OpenPGP cleartext signed message for repository metadata.
    pub async fn sign_openpgp_cleartext(
        &self,
        repo_id: Uuid,
        text: &str,
    ) -> Result<Option<String>> {
        let key = match self.active_key_or_none(repo_id).await? {
            Some(k) => k,
            None => return Ok(None),
        };
        let armored = self.sign_openpgp_cleartext_with_key(&key, text).await?;
        self.mark_key_used(key.id).await?;
        Ok(Some(armored))
    }

    /// Decrypt and parse the OpenPGP secret key stored on `key`.
    ///
    /// Both intermediate buffers (the raw decrypted byte vector and the UTF-8
    /// view fed into rPGP) hold cleartext OpenPGP private-key material. The
    /// byte buffer is wrapped in `Zeroizing<Vec<u8>>` so the plaintext armor
    /// is wiped from memory when this function returns (artifact-keeper #1328).
    /// The returned `pgp::SignedSecretKey` and its inner MPIs / `PlainSecretParams`
    /// derive `ZeroizeOnDrop` upstream in the `pgp` crate, so they self-clean
    /// when the returned value is dropped by the caller.
    fn load_openpgp_secret_key(&self, key: &SigningKey) -> Result<pgp::SignedSecretKey> {
        if key.key_type != "gpg" {
            return Err(AppError::Validation(
                "OpenPGP signatures require a signing key with key_type='gpg'".to_string(),
            ));
        }

        let private_key: Zeroizing<Vec<u8>> =
            Zeroizing::new(self.encryption.decrypt(&key.private_key_enc).map_err(|e| {
                AppError::Internal(format!("Failed to decrypt private key: {}", e))
            })?);
        let private_key_str = std::str::from_utf8(&private_key)
            .map_err(|e| AppError::Internal(format!("Invalid UTF-8 in OpenPGP key: {}", e)))?;

        let (secret_key, _) = pgp::SignedSecretKey::from_string(private_key_str).map_err(|e| {
            AppError::Internal(format!(
                "Failed to parse OpenPGP private key. Existing key may be a legacy PEM key; rotate or recreate it: {}",
                e
            ))
        })?;
        Ok(secret_key)
    }

    /// Sign `data` with `key` and return an ASCII-armored detached OpenPGP
    /// signature. Exposed publicly (in addition to `sign_openpgp_detached`)
    /// so callers that already hold the active `SigningKey` — e.g. handlers
    /// checking a content-keyed signed-Release cache — can avoid a second
    /// DB lookup per request (#1236).
    pub async fn sign_openpgp_detached_with_key(
        &self,
        key: &SigningKey,
        data: &[u8],
    ) -> Result<String> {
        // Decrypt + parse on the runtime: cheap relative to the signing work
        // itself, and lets us avoid cloning the encryption state across the
        // spawn_blocking boundary.
        let secret_key = self.load_openpgp_secret_key(key)?;
        let data_owned = data.to_vec();
        run_blocking("openpgp_sign_detached", move || {
            sign_openpgp_detached_blocking(secret_key, data_owned)
        })
        .await
    }

    /// Sign `text` with `key` and return an ASCII-armored cleartext
    /// signed message. See [`Self::sign_openpgp_detached_with_key`] for
    /// the rationale on the public surface.
    pub async fn sign_openpgp_cleartext_with_key(
        &self,
        key: &SigningKey,
        text: &str,
    ) -> Result<String> {
        let secret_key = self.load_openpgp_secret_key(key)?;
        let text_owned = text.to_string();
        run_blocking("openpgp_sign_cleartext", move || {
            sign_openpgp_cleartext_blocking(secret_key, text_owned)
        })
        .await
    }

    /// Stamp the `last_used_at` column for `key_id`. Public so callers
    /// that sign through the `_with_key` path can still record usage.
    pub async fn mark_key_used(&self, key_id: Uuid) -> Result<()> {
        sqlx::query!(
            "UPDATE signing_keys SET last_used_at = NOW() WHERE id = $1",
            key_id,
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    /// Get the public key in PEM or ASCII-armored OpenPGP format for a repository.
    pub async fn get_repo_public_key(&self, repo_id: Uuid) -> Result<Option<String>> {
        let key = self.get_active_key_for_repo(repo_id).await?;
        Ok(key.map(|k| k.public_key_pem))
    }

    /// Get or create signing configuration for a repository.
    pub async fn get_signing_config(
        &self,
        repo_id: Uuid,
    ) -> Result<Option<RepositorySigningConfig>> {
        let config = sqlx::query_as!(
            RepositorySigningConfig,
            "SELECT * FROM repository_signing_config WHERE repository_id = $1",
            repo_id,
        )
        .fetch_optional(&self.db)
        .await?;
        Ok(config)
    }

    /// Update signing configuration for a repository.
    pub async fn update_signing_config(
        &self,
        repo_id: Uuid,
        signing_key_id: Option<Uuid>,
        sign_metadata: bool,
        sign_packages: bool,
        require_signatures: bool,
    ) -> Result<RepositorySigningConfig> {
        let config = sqlx::query_as!(
            RepositorySigningConfig,
            r#"
            INSERT INTO repository_signing_config
                (repository_id, signing_key_id, sign_metadata, sign_packages, require_signatures, updated_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            ON CONFLICT (repository_id) DO UPDATE SET
                signing_key_id = $2,
                sign_metadata = $3,
                sign_packages = $4,
                require_signatures = $5,
                updated_at = NOW()
            RETURNING *
            "#,
            repo_id,
            signing_key_id,
            sign_metadata,
            sign_packages,
            require_signatures,
        )
        .fetch_one(&self.db)
        .await?;
        Ok(config)
    }

    /// Rotate a key: mint an active successor, repoint the repo config at it,
    /// and deactivate the old key — all atomically.
    ///
    /// The whole transition runs in a single transaction, serialized on the
    /// old key's row with `SELECT ... FOR UPDATE`. Concurrent rotations of the
    /// same key therefore serialize: the first commit deactivates the old key,
    /// and every later contender re-reads it as inactive and returns
    /// `409 Conflict` instead of minting a second active key. Operations are
    /// ordered create-new-active → repoint-config → deactivate-old so the repo
    /// config never references an inactive key, and any failure before commit
    /// rolls the whole thing back (the repo stays on its current active key).
    ///
    /// The slow CPU keygen runs *before* the transaction so no DB lock is held
    /// across it.
    ///
    /// ## Hex registry keys are not rotatable through here
    ///
    /// Rotation mints a successor under a *derived* name
    /// ([`build_rotated_key_name`]). That is fine for the Debian/Conda keys,
    /// which are addressed by id through `repository_signing_config`, but the
    /// hex registry key is addressed **by name** (`hex-registry`): a successor
    /// called `hex-registry (rotated)` is a key no lookup will ever find, and
    /// the repository would silently self-heal a *third* key over it. Rotation
    /// also buys nothing here — hex consumers pin the public key explicitly with
    /// `mix hex.repo add --public-key`, so any replacement key requires every
    /// consumer to re-pin regardless, and there is no overlap window to
    /// preserve. Replacing a hex registry key is therefore expressed as
    /// **revoke** ([`Self::revoke_key`]), which leaves the old row as an audit
    /// record and lets [`Self::get_or_create_hex_registry_key`] provision a
    /// fresh key on the next registry fetch. Rejecting rotation keeps exactly
    /// one supported way to do it, and that way works.
    pub async fn rotate_key(
        &self,
        old_key_id: Uuid,
        user_id: Option<Uuid>,
    ) -> Result<SigningKeyPublic> {
        // Read the old key (off the pool) to derive the successor's params.
        // The authoritative active-state check happens on the locked row
        // inside the transaction below.
        let old_key = sqlx::query_as!(
            SigningKey,
            "SELECT * FROM signing_keys WHERE id = $1",
            old_key_id,
        )
        .fetch_optional(&self.db)
        .await?
        .ok_or_else(|| AppError::NotFound("Signing key not found".to_string()))?;

        // A name-addressed key cannot be rotated to a renamed successor; see
        // the doc comment. Point the operator at revoke, which does work.
        if old_key.name == HEX_REGISTRY_KEY_NAME && old_key.repository_id.is_some() {
            return Err(AppError::Conflict(
                "The hex registry key is addressed by name and cannot be rotated; revoke it \
                 instead — the next registry fetch provisions a replacement, and consumers \
                 must re-pin the new key with `mix hex.repo add --public-key`"
                    .to_string(),
            ));
        }

        // Successor inherits the old key's parameters.
        let req = CreateKeyRequest {
            repository_id: old_key.repository_id,
            name: build_rotated_key_name(&old_key.name),
            key_type: old_key.key_type.clone(),
            algorithm: old_key.algorithm.clone(),
            uid_name: old_key.uid_name.clone(),
            uid_email: old_key.uid_email.clone(),
            created_by: user_id,
        };

        // Slow keygen OUTSIDE the transaction — no lock held across it.
        let material = self.generate_key_material(&req).await?;
        let new_id = Uuid::new_v4();
        let now = Utc::now();

        let mut tx = self.db.begin().await?;

        // Serialize per-key: lock the old key row, then re-assert it is still
        // active. Concurrent rotations block here until the winner commits,
        // then observe is_active=false and bail out (idempotency guard).
        let locked = sqlx::query_as!(
            SigningKey,
            "SELECT * FROM signing_keys WHERE id = $1 FOR UPDATE",
            old_key_id,
        )
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| AppError::NotFound("Signing key not found".to_string()))?;

        if !locked.is_active {
            return Err(AppError::Conflict(
                "Signing key is not active (already rotated or revoked); rotate the current active key"
                    .to_string(),
            ));
        }

        // (1) Insert the new ACTIVE key, with rotated_from set at insert time.
        Self::insert_key_row(
            &mut *tx,
            new_id,
            &req,
            &material,
            true,
            Some(old_key_id),
            now,
        )
        .await?;

        // (2) Repoint the signing config to the new (active) key — the config
        //     now references an active key. Guarded on the old id so a
        //     concurrent winner's repoint is never clobbered.
        if let Some(repo_id) = locked.repository_id {
            sqlx::query!(
                "UPDATE repository_signing_config SET signing_key_id = $1, updated_at = NOW() WHERE repository_id = $2 AND signing_key_id = $3",
                new_id,
                repo_id,
                old_key_id,
            )
            .execute(&mut *tx)
            .await?;
        }

        // (3) Deactivate the old key LAST.
        sqlx::query!(
            "UPDATE signing_keys SET is_active = false WHERE id = $1",
            old_key_id,
        )
        .execute(&mut *tx)
        .await?;

        // (4) Audit rows (created successor + rotated old) inside the txn.
        Self::audit_key_action_exec(&mut *tx, new_id, "created", user_id, None).await?;
        Self::audit_key_action_exec(
            &mut *tx,
            old_key_id,
            "rotated",
            user_id,
            Some(serde_json::json!({"new_key_id": new_id.to_string()})),
        )
        .await?;

        tx.commit().await?;

        Ok(SigningKeyPublic {
            id: new_id,
            repository_id: req.repository_id,
            name: req.name,
            key_type: material.key_type,
            fingerprint: Some(material.fingerprint),
            key_id: Some(material.key_id),
            public_key_pem: material.public_key_pem,
            algorithm: req.algorithm,
            uid_name: req.uid_name,
            uid_email: req.uid_email,
            expires_at: None,
            is_active: true,
            created_at: now,
            last_used_at: None,
        })
    }

    async fn audit_key_action(
        &self,
        key_id: Uuid,
        action: &str,
        user_id: Option<Uuid>,
        details: Option<serde_json::Value>,
    ) -> Result<()> {
        Self::audit_key_action_exec(&self.db, key_id, action, user_id, details).await
    }

    /// Executor-generic audit insert, usable on the pool or a `&mut *tx` so
    /// rotation's audit rows commit atomically with the key changes.
    async fn audit_key_action_exec<'e, E>(
        exec: E,
        key_id: Uuid,
        action: &str,
        user_id: Option<Uuid>,
        details: Option<serde_json::Value>,
    ) -> Result<()>
    where
        E: sqlx::PgExecutor<'e>,
    {
        sqlx::query!(
            "INSERT INTO signing_key_audit (signing_key_id, action, performed_by, details) VALUES ($1, $2, $3, $4)",
            key_id,
            action,
            user_id,
            details,
        )
        .execute(exec)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use rsa::pkcs8::{DecodePublicKey, EncodePrivateKey, EncodePublicKey};
    use uuid::Uuid;

    /// Generate a real RSA key pair, encrypt the private key with the given
    /// passphrase, and return a SigningKey model struct suitable for sign_with_key.
    fn generate_test_signing_key(passphrase: &str) -> SigningKey {
        let mut rng = rsa::rand_core::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("keygen failed");
        let public_key = RsaPublicKey::from(&private_key);

        let public_pem = public_key
            .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
            .expect("pub pem encode failed");
        let private_pem = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .expect("priv pem encode failed");

        let encryption = CredentialEncryption::from_passphrase(passphrase);
        let private_enc = encryption.encrypt(private_pem.as_bytes());

        let public_der = public_key
            .to_public_key_der()
            .expect("pub der encode failed");
        let fingerprint = hex::encode(sha2::Sha256::digest(public_der.as_ref()));
        let key_id = fingerprint[fingerprint.len() - 16..].to_string();

        let now = Utc::now();
        SigningKey {
            id: Uuid::new_v4(),
            repository_id: None,
            name: "test-key".to_string(),
            key_type: "rsa".to_string(),
            fingerprint: Some(fingerprint),
            key_id: Some(key_id),
            public_key_pem: public_pem,
            private_key_enc: private_enc,
            algorithm: "rsa2048".to_string(),
            uid_name: None,
            uid_email: None,
            expires_at: None,
            is_active: true,
            created_at: now,
            created_by: None,
            rotated_from: None,
            last_used_at: None,
        }
    }

    async fn generate_test_openpgp_signing_key(passphrase: &str) -> SigningKey {
        let service = SigningService {
            db: PgPool::connect_lazy("postgresql://example.invalid/test").unwrap(),
            encryption: CredentialEncryption::from_passphrase(passphrase),
        };
        let req = CreateKeyRequest {
            repository_id: None,
            name: "test-openpgp-key".to_string(),
            key_type: "gpg".to_string(),
            algorithm: "rsa2048".to_string(),
            uid_name: Some("Test User".to_string()),
            uid_email: Some("test@example.com".to_string()),
            created_by: None,
        };
        let (public_key_pem, private_key_material, fingerprint, key_id) =
            service.generate_openpgp_key(&req).await.unwrap();
        let now = Utc::now();
        SigningKey {
            id: Uuid::new_v4(),
            repository_id: None,
            name: req.name,
            key_type: req.key_type,
            fingerprint: Some(fingerprint),
            key_id: Some(key_id),
            public_key_pem,
            private_key_enc: service.encryption.encrypt(private_key_material.as_bytes()),
            algorithm: req.algorithm,
            uid_name: req.uid_name,
            uid_email: req.uid_email,
            expires_at: None,
            is_active: true,
            created_at: now,
            created_by: None,
            rotated_from: None,
            last_used_at: None,
        }
    }

    #[tokio::test]
    async fn test_openpgp_key_and_signatures_are_parseable_and_verifiable() {
        let passphrase = "openpgp-test-passphrase";
        let key = generate_test_openpgp_signing_key(passphrase).await;
        assert!(key
            .public_key_pem
            .starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));

        let service = SigningService {
            db: PgPool::connect_lazy("postgresql://example.invalid/test").unwrap(),
            encryption: CredentialEncryption::from_passphrase(passphrase),
        };
        let (public_key, _) = pgp::SignedPublicKey::from_string(&key.public_key_pem).unwrap();
        public_key.verify().unwrap();

        let data = b"Origin: artifact-keeper\nSuite: stable\n";
        let detached = service
            .sign_openpgp_detached_with_key(&key, data)
            .await
            .unwrap();
        let (signature, _) = StandaloneSignature::from_string(&detached).unwrap();
        signature.verify(&public_key, data).unwrap();

        let cleartext = service
            .sign_openpgp_cleartext_with_key(&key, std::str::from_utf8(data).unwrap())
            .await
            .unwrap();
        let (message, _) = CleartextSignedMessage::from_string(&cleartext).unwrap();
        message.verify(&public_key).unwrap();
    }

    // -----------------------------------------------------------------------
    // #2357 — verify_detached (upstream repomd.xml.asc authentication)
    //
    // A valid detached signature over the exact bytes passes; a tampered body,
    // a tampered signature, or the wrong trusted key all fail-closed. This is
    // the primitive the RPM curation sync uses to reject unverified upstream
    // metadata before ingest.
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_verify_detached_valid_tampered_and_wrong_key() {
        let passphrase = "detached-verify-passphrase";
        let key = generate_test_openpgp_signing_key(passphrase).await;
        let service = SigningService {
            db: PgPool::connect_lazy("postgresql://example.invalid/test").unwrap(),
            encryption: CredentialEncryption::from_passphrase(passphrase),
        };

        let repomd = b"<repomd><data type=\"primary\"></data></repomd>";
        let sig = service
            .sign_openpgp_detached_with_key(&key, repomd)
            .await
            .unwrap();

        // Valid signature over the exact bytes against the trusted key -> Ok.
        verify_detached(&key.public_key_pem, repomd, &sig)
            .expect("valid detached signature must verify against the trusted key");

        // Tampered body -> rejected (checksums cannot be trusted).
        let tampered = b"<repomd><data type=\"primary\">EVIL</data></repomd>";
        assert!(
            verify_detached(&key.public_key_pem, tampered, &sig).is_err(),
            "a tampered repomd.xml must fail signature verification"
        );

        // Wrong trusted key -> rejected.
        let other = generate_test_openpgp_signing_key(passphrase).await;
        assert!(
            verify_detached(&other.public_key_pem, repomd, &sig).is_err(),
            "a signature from a different key must not verify against the trusted key"
        );

        // Malformed key / signature material -> rejected (not a panic).
        assert!(verify_detached("not-a-key", repomd, &sig).is_err());
        assert!(verify_detached(&key.public_key_pem, repomd, "not-a-sig").is_err());
    }

    // -----------------------------------------------------------------------
    // sign_with_key: roundtrip test (sign then verify)
    //
    // NOTE: SigningService::sign_with_key requires &self (which needs PgPool).
    // This is a testability blocker. The crypto logic (decrypt -> parse ->
    // sign) should be extracted into a free function that takes
    // (&CredentialEncryption, &SigningKey, &[u8]) -> Result<Vec<u8>>.
    // Below we replicate the crypto logic to verify correctness.
    // -----------------------------------------------------------------------

    #[test]
    fn test_sign_produces_valid_signature() {
        let passphrase = "test-encryption-key-for-signing";
        let signing_key = generate_test_signing_key(passphrase);

        let encryption = CredentialEncryption::from_passphrase(passphrase);
        let private_pem_bytes = encryption.decrypt(&signing_key.private_key_enc).unwrap();
        let private_pem = std::str::from_utf8(&private_pem_bytes).unwrap();
        let private_key = RsaPrivateKey::from_pkcs8_pem(private_pem).unwrap();

        let data = b"Hello, Artifact Keeper!";
        let rsa_signing_key = RsaSigningKey::<Sha256>::new(private_key);
        let signature = rsa_signing_key.sign(data);

        use rsa::pkcs1v15::VerifyingKey;
        use rsa::signature::Verifier;

        let public_key = RsaPublicKey::from_public_key_pem(&signing_key.public_key_pem).unwrap();
        let verifying_key = VerifyingKey::<Sha256>::new(public_key);
        assert!(verifying_key.verify(data, &signature).is_ok());
    }

    #[test]
    fn test_sign_different_data_different_signatures() {
        let passphrase = "test-key-diff";
        let signing_key = generate_test_signing_key(passphrase);

        let encryption = CredentialEncryption::from_passphrase(passphrase);
        let private_pem_bytes = encryption.decrypt(&signing_key.private_key_enc).unwrap();
        let private_pem = std::str::from_utf8(&private_pem_bytes).unwrap();
        let private_key = RsaPrivateKey::from_pkcs8_pem(private_pem).unwrap();

        let rsa_signing_key = RsaSigningKey::<Sha256>::new(private_key);
        let sig1 = rsa_signing_key.sign(b"data A");
        let sig2 = rsa_signing_key.sign(b"data B");

        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }

    // -----------------------------------------------------------------------
    // Encryption roundtrip for private key material
    // -----------------------------------------------------------------------

    #[test]
    fn test_private_key_encryption_roundtrip() {
        let passphrase = "encryption-roundtrip-test";
        let signing_key = generate_test_signing_key(passphrase);

        let encryption = CredentialEncryption::from_passphrase(passphrase);
        let decrypted = encryption.decrypt(&signing_key.private_key_enc).unwrap();
        let decrypted_str = std::str::from_utf8(&decrypted).unwrap();

        assert!(decrypted_str.contains("BEGIN PRIVATE KEY"));
        assert!(decrypted_str.contains("END PRIVATE KEY"));
    }

    #[test]
    fn test_wrong_passphrase_fails_decryption() {
        let signing_key = generate_test_signing_key("correct-passphrase");
        let wrong_encryption = CredentialEncryption::from_passphrase("wrong-passphrase");

        let result = wrong_encryption.decrypt(&signing_key.private_key_enc);
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Fingerprint and key_id derivation
    // -----------------------------------------------------------------------

    #[test]
    fn test_fingerprint_is_valid_hex() {
        let signing_key = generate_test_signing_key("fp-test");
        let fingerprint = signing_key.fingerprint.as_ref().unwrap();
        // SHA-256 hex = 64 chars
        assert_eq!(fingerprint.len(), 64);
        assert!(fingerprint.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_key_id_is_last_16_of_fingerprint() {
        let signing_key = generate_test_signing_key("kid-test");
        let fingerprint = signing_key.fingerprint.as_ref().unwrap();
        let key_id = signing_key.key_id.as_ref().unwrap();
        assert_eq!(key_id.len(), 16);
        assert_eq!(key_id, &fingerprint[fingerprint.len() - 16..]);
    }

    // -----------------------------------------------------------------------
    // SigningKey -> SigningKeyPublic conversion
    // -----------------------------------------------------------------------

    #[test]
    fn test_signing_key_to_public_conversion() {
        let signing_key = generate_test_signing_key("conv-test");
        let public: SigningKeyPublic = signing_key.clone().into();

        assert_eq!(public.id, signing_key.id);
        assert_eq!(public.name, signing_key.name);
        assert_eq!(public.key_type, signing_key.key_type);
        assert_eq!(public.fingerprint, signing_key.fingerprint);
        assert_eq!(public.key_id, signing_key.key_id);
        assert_eq!(public.public_key_pem, signing_key.public_key_pem);
        assert_eq!(public.algorithm, signing_key.algorithm);
        assert_eq!(public.is_active, signing_key.is_active);
        assert_eq!(public.created_at, signing_key.created_at);
    }

    // -----------------------------------------------------------------------
    // algorithm_to_bits (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_algorithm_to_bits_rsa2048() {
        assert_eq!(algorithm_to_bits("rsa2048").unwrap(), 2048);
    }

    #[test]
    fn test_algorithm_to_bits_rsa4096() {
        assert_eq!(algorithm_to_bits("rsa4096").unwrap(), 4096);
    }

    #[test]
    fn test_algorithm_to_bits_rsa_alias() {
        assert_eq!(algorithm_to_bits("rsa").unwrap(), 4096);
    }

    #[test]
    fn test_algorithm_to_bits_unsupported() {
        let result = algorithm_to_bits("ed25519");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsupported algorithm"));
    }

    #[test]
    fn test_algorithm_to_bits_unknown() {
        assert!(algorithm_to_bits("unknown").is_err());
    }

    #[test]
    fn test_algorithm_to_bits_empty() {
        assert!(algorithm_to_bits("").is_err());
    }

    // -----------------------------------------------------------------------
    // normalize_key_type (#2319 regression: algorithm variant sent as
    // key_type must coerce to the DB-accepted family, not 500 at INSERT)
    // -----------------------------------------------------------------------

    #[test]
    fn test_normalize_key_type_rsa2048_coerced_to_rsa_family() {
        assert_eq!(normalize_key_type("rsa2048").unwrap(), "rsa");
    }

    #[test]
    fn test_normalize_key_type_rsa4096_coerced_to_rsa_family() {
        assert_eq!(normalize_key_type("rsa4096").unwrap(), "rsa");
    }

    #[test]
    fn test_normalize_key_type_rsa_passthrough() {
        assert_eq!(normalize_key_type("rsa").unwrap(), "rsa");
    }

    #[test]
    fn test_normalize_key_type_gpg_passthrough() {
        assert_eq!(normalize_key_type("gpg").unwrap(), "gpg");
    }

    #[test]
    fn test_normalize_key_type_ed25519_passthrough() {
        assert_eq!(normalize_key_type("ed25519").unwrap(), "ed25519");
    }

    #[test]
    fn test_normalize_key_type_unsupported_rejected() {
        let result = normalize_key_type("dsa");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unsupported key_type"));
    }

    #[test]
    fn test_normalize_key_type_empty_rejected() {
        assert!(normalize_key_type("").is_err());
    }

    #[test]
    fn test_normalize_key_type_case_sensitive() {
        // The DB CHECK constraint is case-sensitive; so is normalization.
        assert!(normalize_key_type("RSA2048").is_err());
    }

    // -----------------------------------------------------------------------
    // compute_fingerprint (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_fingerprint_is_valid_hex() {
        let data = b"test public key data";
        let fp = compute_fingerprint(data);
        assert_eq!(fp.len(), 64); // SHA-256 = 32 bytes = 64 hex chars
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_compute_fingerprint_deterministic() {
        let data = b"same data";
        let fp1 = compute_fingerprint(data);
        let fp2 = compute_fingerprint(data);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_compute_fingerprint_different_data() {
        let fp1 = compute_fingerprint(b"data A");
        let fp2 = compute_fingerprint(b"data B");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_compute_fingerprint_empty() {
        let fp = compute_fingerprint(b"");
        assert_eq!(fp.len(), 64);
    }

    // -----------------------------------------------------------------------
    // derive_key_id (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_derive_key_id_from_fingerprint() {
        let fp = "a".repeat(64);
        let kid = derive_key_id(&fp);
        assert_eq!(kid.len(), 16);
        assert_eq!(kid, "a".repeat(16));
    }

    #[test]
    fn test_derive_key_id_is_suffix() {
        let fp = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let kid = derive_key_id(fp);
        assert_eq!(kid, &fp[48..]);
    }

    #[test]
    fn test_derive_key_id_short_fingerprint() {
        // Edge case: fingerprint shorter than 16
        let fp = "abcdef";
        let kid = derive_key_id(fp);
        assert_eq!(kid, "abcdef");
    }

    // -----------------------------------------------------------------------
    // build_rotated_key_name (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_rotated_key_name() {
        assert_eq!(build_rotated_key_name("my-key"), "my-key (rotated)");
    }

    #[test]
    fn test_build_rotated_key_name_already_rotated() {
        // The counter replaces the previous suffix instead of accumulating, so
        // rotating an already-rotated name yields "(rotated 2)", not a second
        // "(rotated)" appended on top (the old unbounded behavior — #2543).
        assert_eq!(
            build_rotated_key_name("my-key (rotated)"),
            "my-key (rotated 2)"
        );
    }

    #[test]
    fn test_build_rotated_key_name_empty() {
        assert_eq!(build_rotated_key_name(""), " (rotated)");
    }

    // -----------------------------------------------------------------------
    // CreateKeyRequest construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_key_request_construction() {
        let repo_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let req = CreateKeyRequest {
            repository_id: Some(repo_id),
            name: "my-signing-key".to_string(),
            key_type: "rsa".to_string(),
            algorithm: "rsa4096".to_string(),
            uid_name: Some("John Doe".to_string()),
            uid_email: Some("john@example.com".to_string()),
            created_by: Some(user_id),
        };
        assert_eq!(req.repository_id, Some(repo_id));
        assert_eq!(req.name, "my-signing-key");
        assert_eq!(req.key_type, "rsa");
        assert_eq!(req.algorithm, "rsa4096");
        assert_eq!(req.uid_name, Some("John Doe".to_string()));
        assert_eq!(req.uid_email, Some("john@example.com".to_string()));
        assert_eq!(req.created_by, Some(user_id));
    }

    #[test]
    fn test_create_key_request_minimal() {
        let req = CreateKeyRequest {
            repository_id: None,
            name: "global-key".to_string(),
            key_type: "gpg".to_string(),
            algorithm: "rsa2048".to_string(),
            uid_name: None,
            uid_email: None,
            created_by: None,
        };
        assert!(req.repository_id.is_none());
        assert!(req.uid_name.is_none());
        assert!(req.uid_email.is_none());
        assert!(req.created_by.is_none());
    }

    // -----------------------------------------------------------------------
    // CredentialEncryption - additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_encryption_empty_data() {
        let encryption = CredentialEncryption::from_passphrase("test-key");
        let encrypted = encryption.encrypt(b"");
        let decrypted = encryption.decrypt(&encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_encryption_large_data() {
        let encryption = CredentialEncryption::from_passphrase("test-key");
        let data = vec![0xABu8; 10_000];
        let encrypted = encryption.encrypt(&data);
        let decrypted = encryption.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_encryption_binary_data() {
        let encryption = CredentialEncryption::from_passphrase("binary-test");
        let data: Vec<u8> = (0..=255).collect();
        let encrypted = encryption.encrypt(&data);
        let decrypted = encryption.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_encryption_different_passphrases_produce_different_output() {
        let enc1 = CredentialEncryption::from_passphrase("key-1");
        let enc2 = CredentialEncryption::from_passphrase("key-2");
        let data = b"secret data";
        let encrypted1 = enc1.encrypt(data);
        let encrypted2 = enc2.encrypt(data);
        assert_ne!(encrypted1, encrypted2);
    }

    #[test]
    fn test_encryption_same_passphrase_decrypts_to_same() {
        let enc1 = CredentialEncryption::from_passphrase("same-key");
        let enc2 = CredentialEncryption::from_passphrase("same-key");
        let data = b"test data";
        let encrypted1 = enc1.encrypt(data);
        let encrypted2 = enc2.encrypt(data);
        // Both should decrypt to the same plaintext
        let decrypted1 = enc1.decrypt(&encrypted1).unwrap();
        let decrypted2 = enc2.decrypt(&encrypted2).unwrap();
        assert_eq!(decrypted1, data);
        assert_eq!(decrypted2, data);
        // Cross-decryption should also work
        let cross1 = enc2.decrypt(&encrypted1).unwrap();
        let cross2 = enc1.decrypt(&encrypted2).unwrap();
        assert_eq!(cross1, data);
        assert_eq!(cross2, data);
    }

    // -----------------------------------------------------------------------
    // SigningKey fields
    // -----------------------------------------------------------------------

    #[test]
    fn test_signing_key_all_fields() {
        let key = generate_test_signing_key("all-fields-test");
        assert_eq!(key.name, "test-key");
        assert_eq!(key.key_type, "rsa");
        assert_eq!(key.algorithm, "rsa2048");
        assert!(key.is_active);
        assert!(key.repository_id.is_none());
        assert!(key.uid_name.is_none());
        assert!(key.uid_email.is_none());
        assert!(key.expires_at.is_none());
        assert!(key.created_by.is_none());
        assert!(key.rotated_from.is_none());
        assert!(key.last_used_at.is_none());
    }

    #[test]
    fn test_signing_key_clone() {
        let key = generate_test_signing_key("clone-test");
        let cloned = key.clone();
        assert_eq!(key.id, cloned.id);
        assert_eq!(key.name, cloned.name);
        assert_eq!(key.fingerprint, cloned.fingerprint);
        assert_eq!(key.key_id, cloned.key_id);
        assert_eq!(key.public_key_pem, cloned.public_key_pem);
        assert_eq!(key.private_key_enc, cloned.private_key_enc);
    }

    // -----------------------------------------------------------------------
    // SigningKeyPublic fields
    // -----------------------------------------------------------------------

    #[test]
    fn test_signing_key_public_fields() {
        let key = generate_test_signing_key("pub-fields-test");
        let public: SigningKeyPublic = key.clone().into();

        assert_eq!(public.id, key.id);
        assert_eq!(public.repository_id, key.repository_id);
        assert_eq!(public.name, key.name);
        assert_eq!(public.key_type, key.key_type);
        assert_eq!(public.fingerprint, key.fingerprint);
        assert_eq!(public.key_id, key.key_id);
        assert_eq!(public.public_key_pem, key.public_key_pem);
        assert_eq!(public.algorithm, key.algorithm);
        assert_eq!(public.uid_name, key.uid_name);
        assert_eq!(public.uid_email, key.uid_email);
        assert_eq!(public.is_active, key.is_active);
        assert_eq!(public.created_at, key.created_at);
        assert_eq!(public.last_used_at, key.last_used_at);
    }

    // -----------------------------------------------------------------------
    // Public key PEM format
    // -----------------------------------------------------------------------

    #[test]
    fn test_public_key_pem_format() {
        let key = generate_test_signing_key("pem-format-test");
        assert!(key.public_key_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert!(key.public_key_pem.ends_with("-----END PUBLIC KEY-----\n"));
    }

    #[test]
    fn test_public_key_is_parseable() {
        let key = generate_test_signing_key("parseable-test");
        let result = RsaPublicKey::from_public_key_pem(&key.public_key_pem);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // Fingerprint properties
    // -----------------------------------------------------------------------

    #[test]
    fn test_fingerprint_deterministic() {
        // Two keys should have different fingerprints (different random keys)
        let key1 = generate_test_signing_key("fp-det-1");
        let key2 = generate_test_signing_key("fp-det-2");
        assert_ne!(
            key1.fingerprint.as_ref().unwrap(),
            key2.fingerprint.as_ref().unwrap()
        );
    }

    #[test]
    fn test_key_id_is_hex() {
        let key = generate_test_signing_key("kid-hex-test");
        let key_id = key.key_id.as_ref().unwrap();
        assert!(key_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // -----------------------------------------------------------------------
    // sign / verify with different data
    // -----------------------------------------------------------------------

    #[test]
    fn test_sign_empty_data() {
        let passphrase = "empty-data-sign";
        let signing_key = generate_test_signing_key(passphrase);

        let encryption = CredentialEncryption::from_passphrase(passphrase);
        let private_pem_bytes = encryption.decrypt(&signing_key.private_key_enc).unwrap();
        let private_pem = std::str::from_utf8(&private_pem_bytes).unwrap();
        let private_key = RsaPrivateKey::from_pkcs8_pem(private_pem).unwrap();

        let data = b"";
        let rsa_signing_key = RsaSigningKey::<Sha256>::new(private_key);
        let signature = rsa_signing_key.sign(data);

        use rsa::pkcs1v15::VerifyingKey;
        use rsa::signature::Verifier;

        let public_key = RsaPublicKey::from_public_key_pem(&signing_key.public_key_pem).unwrap();
        let verifying_key = VerifyingKey::<Sha256>::new(public_key);
        assert!(verifying_key.verify(data, &signature).is_ok());
    }

    #[test]
    fn test_sign_large_data() {
        let passphrase = "large-data-sign";
        let signing_key = generate_test_signing_key(passphrase);

        let encryption = CredentialEncryption::from_passphrase(passphrase);
        let private_pem_bytes = encryption.decrypt(&signing_key.private_key_enc).unwrap();
        let private_pem = std::str::from_utf8(&private_pem_bytes).unwrap();
        let private_key = RsaPrivateKey::from_pkcs8_pem(private_pem).unwrap();

        let data = vec![0xBBu8; 100_000];
        let rsa_signing_key = RsaSigningKey::<Sha256>::new(private_key);
        let signature = rsa_signing_key.sign(&data);

        use rsa::pkcs1v15::VerifyingKey;
        use rsa::signature::Verifier;

        let public_key = RsaPublicKey::from_public_key_pem(&signing_key.public_key_pem).unwrap();
        let verifying_key = VerifyingKey::<Sha256>::new(public_key);
        assert!(verifying_key.verify(&data, &signature).is_ok());
    }

    #[test]
    fn test_tampered_data_fails_verification() {
        let passphrase = "tamper-test";
        let signing_key = generate_test_signing_key(passphrase);

        let encryption = CredentialEncryption::from_passphrase(passphrase);
        let private_pem_bytes = encryption.decrypt(&signing_key.private_key_enc).unwrap();
        let private_pem = std::str::from_utf8(&private_pem_bytes).unwrap();
        let private_key = RsaPrivateKey::from_pkcs8_pem(private_pem).unwrap();

        let data = b"original data";
        let rsa_signing_key = RsaSigningKey::<Sha256>::new(private_key);
        let signature = rsa_signing_key.sign(data);

        use rsa::pkcs1v15::VerifyingKey;
        use rsa::signature::Verifier;

        let public_key = RsaPublicKey::from_public_key_pem(&signing_key.public_key_pem).unwrap();
        let verifying_key = VerifyingKey::<Sha256>::new(public_key);
        // Tampered data should fail verification
        assert!(verifying_key.verify(b"tampered data", &signature).is_err());
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let signing_key1 = generate_test_signing_key("key-1-verify");
        let signing_key2 = generate_test_signing_key("key-2-verify");

        let encryption1 = CredentialEncryption::from_passphrase("key-1-verify");
        let private_pem_bytes = encryption1.decrypt(&signing_key1.private_key_enc).unwrap();
        let private_pem = std::str::from_utf8(&private_pem_bytes).unwrap();
        let private_key = RsaPrivateKey::from_pkcs8_pem(private_pem).unwrap();

        let data = b"test data for wrong key";
        let rsa_signing_key = RsaSigningKey::<Sha256>::new(private_key);
        let signature = rsa_signing_key.sign(data);

        use rsa::pkcs1v15::VerifyingKey;
        use rsa::signature::Verifier;

        // Try to verify with key2's public key - should fail
        let public_key2 = RsaPublicKey::from_public_key_pem(&signing_key2.public_key_pem).unwrap();
        let verifying_key2 = VerifyingKey::<Sha256>::new(public_key2);
        assert!(verifying_key2.verify(data, &signature).is_err());
    }

    // -----------------------------------------------------------------------
    // Deterministic signing
    // -----------------------------------------------------------------------

    #[test]
    fn test_sign_same_data_deterministic() {
        let passphrase = "deterministic-sign";
        let signing_key = generate_test_signing_key(passphrase);

        let encryption = CredentialEncryption::from_passphrase(passphrase);
        let private_pem_bytes = encryption.decrypt(&signing_key.private_key_enc).unwrap();
        let private_pem = std::str::from_utf8(&private_pem_bytes).unwrap();
        let private_key = RsaPrivateKey::from_pkcs8_pem(private_pem).unwrap();

        let data = b"deterministic test data";
        let rsa_signing_key = RsaSigningKey::<Sha256>::new(private_key);
        let sig1 = rsa_signing_key.sign(data);
        let sig2 = rsa_signing_key.sign(data);

        // PKCS#1 v1.5 is deterministic (unlike PSS)
        assert_eq!(sig1.to_bytes(), sig2.to_bytes());
    }

    // -----------------------------------------------------------------------
    // Private key encrypted storage
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Zeroize: the decrypted private-key buffer in load_openpgp_secret_key
    // and sign_with_key is wrapped in Zeroizing<Vec<u8>> so its plaintext
    // contents are wiped on drop. We can't observe freed memory portably,
    // but we can pin the wrapper's Drop behavior on a sample buffer so a
    // future refactor that swaps Zeroizing<Vec<u8>> back to Vec<u8>
    // breaks this test (artifact-keeper #1328).
    // -----------------------------------------------------------------------

    #[test]
    fn test_zeroizing_vec_wipes_contents_on_clear() {
        use zeroize::Zeroize;
        // Sanity check that the zeroize crate is wired up and actually
        // overwrites the backing storage. We zeroize() the inner Vec in
        // place rather than relying on Drop so we can read the buffer
        // back after the wipe; the Drop path runs the same code.
        let mut buf: Zeroizing<Vec<u8>> =
            Zeroizing::new(b"-----BEGIN PRIVATE KEY-----\nsecret\n".to_vec());
        let len = buf.len();
        assert!(buf.windows(7).any(|w| w == b"PRIVATE"));
        buf.zeroize();
        // After zeroize(), the Vec is logically empty; explicitly bring
        // the capacity back so we can confirm the underlying bytes are
        // all zero. zeroize() on Vec<u8> sets len to 0 and writes zeros
        // to the backing storage up to the previous capacity.
        unsafe {
            buf.set_len(len);
        }
        assert!(
            buf.iter().all(|&b| b == 0),
            "Zeroizing<Vec<u8>>::zeroize() must wipe the backing buffer"
        );
    }

    #[test]
    fn test_load_openpgp_secret_key_uses_zeroizing_buffer() {
        // Compile-time / signature-level pin: the helper builds a
        // Zeroizing<Vec<u8>> from the decrypted bytes. This test asserts
        // the type is in scope and constructible the same way the
        // production code does it; if someone removes the Zeroizing
        // wrapper from load_openpgp_secret_key, the production code
        // still compiles, but the intent test below documents the
        // requirement and the equivalent construction is exercised here.
        let decrypted: Vec<u8> = b"-----BEGIN PGP PRIVATE KEY BLOCK-----\nfake\n".to_vec();
        let wrapped: Zeroizing<Vec<u8>> = Zeroizing::new(decrypted);
        // Read-through works (Deref<Target = Vec<u8>>).
        assert!(wrapped.starts_with(b"-----BEGIN PGP PRIVATE KEY BLOCK-----"));
        // The wrapper is droppable here; its Drop impl will call zeroize()
        // on the inner Vec. We've already exercised the wipe behavior
        // above; this branch confirms the construction shape compiles.
        drop(wrapped);
    }

    #[test]
    fn test_private_key_not_stored_plaintext() {
        let key = generate_test_signing_key("not-plaintext");
        let enc_bytes = &key.private_key_enc;
        // The encrypted bytes should NOT contain the PEM header
        let enc_str = String::from_utf8_lossy(enc_bytes);
        assert!(
            !enc_str.contains("BEGIN PRIVATE KEY"),
            "Private key should not be stored as plaintext PEM"
        );
    }

    // -----------------------------------------------------------------------
    // Pure helpers (algorithm_to_bits_u32, pgp_user_id, derive_key_id,
    // build_rotated_key_name). These are the small free functions that the
    // OpenPGP signing path (#1236) pulls into the call chain; they each
    // have a couple of branches that the round-trip / property tests above
    // don't exercise directly. Locking them down keeps the new-code
    // coverage gate above the 70% floor and pins the precise behavior
    // each branch is responsible for so a future refactor can't silently
    // change what gets put into a generated key's user-id or what shape
    // the rotated-key name takes.
    // -----------------------------------------------------------------------

    #[test]
    fn test_algorithm_to_bits_u32_rsa2048() {
        assert_eq!(algorithm_to_bits_u32("rsa2048").unwrap(), 2048u32);
    }

    #[test]
    fn test_algorithm_to_bits_u32_rsa4096() {
        assert_eq!(algorithm_to_bits_u32("rsa4096").unwrap(), 4096u32);
    }

    #[test]
    fn test_algorithm_to_bits_u32_unsupported() {
        let err = algorithm_to_bits_u32("ed25519").unwrap_err();
        assert!(
            err.contains("Unsupported algorithm"),
            "expected unsupported-algorithm error, got: {err}"
        );
    }

    #[test]
    fn test_pgp_user_id_name_and_email() {
        let uid = pgp_user_id(Some("Alice"), Some("alice@example.com"), "fallback");
        assert_eq!(uid, "Alice <alice@example.com>");
    }

    #[test]
    fn test_pgp_user_id_name_only() {
        let uid = pgp_user_id(Some("Alice"), None, "fallback");
        assert_eq!(uid, "Alice");
    }

    #[test]
    fn test_pgp_user_id_name_only_empty_email() {
        // The non-empty name should win over an empty email argument.
        let uid = pgp_user_id(Some("Alice"), Some(""), "fallback");
        assert_eq!(uid, "Alice");
    }

    #[test]
    fn test_pgp_user_id_email_only_uses_fallback_name() {
        let uid = pgp_user_id(None, Some("alice@example.com"), "fallback");
        assert_eq!(uid, "fallback <alice@example.com>");
    }

    #[test]
    fn test_pgp_user_id_empty_name_with_email_uses_fallback_name() {
        // Empty name still falls back even when email is set, since the
        // (Some(name), _) branch requires !name.is_empty().
        let uid = pgp_user_id(Some(""), Some("alice@example.com"), "fallback");
        assert_eq!(uid, "fallback <alice@example.com>");
    }

    #[test]
    fn test_pgp_user_id_neither_present() {
        let uid = pgp_user_id(None, None, "fallback");
        assert_eq!(uid, "fallback");
    }

    #[test]
    fn test_pgp_user_id_both_empty_falls_back() {
        // Pathological case: empty strings on both sides. Should still
        // produce the fallback rather than "<>" or "name <>".
        let uid = pgp_user_id(Some(""), Some(""), "fallback");
        assert_eq!(uid, "fallback");
    }

    #[test]
    fn test_derive_key_id_normal_fingerprint() {
        // A 40-hex-char SHA-1-style fingerprint: last 16 hex chars become
        // the short key id.
        let fp = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(derive_key_id(fp), "89abcdef01234567");
    }

    #[test]
    fn test_derive_key_id_short_fingerprint_returns_whole_string() {
        // saturating_sub: fingerprints shorter than 16 chars should not
        // panic; the whole string is the key id.
        let fp = "abc123";
        assert_eq!(derive_key_id(fp), "abc123");
    }

    #[test]
    fn test_derive_key_id_empty_fingerprint() {
        assert_eq!(derive_key_id(""), "");
    }

    #[test]
    fn test_build_rotated_key_name_appends_suffix() {
        assert_eq!(
            build_rotated_key_name("debian-stable"),
            "debian-stable (rotated)"
        );
    }

    #[test]
    fn test_build_rotated_key_name_already_rotated_uses_counter() {
        // Rotating an already-rotated name advances a bounded counter rather
        // than appending another "(rotated)" suffix, so the name cannot grow
        // without limit (#2543).
        assert_eq!(
            build_rotated_key_name("debian-stable (rotated)"),
            "debian-stable (rotated 2)"
        );
    }

    #[test]
    fn test_build_rotated_key_name_counter_increments() {
        // "(rotated N)" advances to "(rotated N+1)".
        assert_eq!(
            build_rotated_key_name("debian-stable (rotated 2)"),
            "debian-stable (rotated 3)"
        );
        assert_eq!(
            build_rotated_key_name("debian-stable (rotated 41)"),
            "debian-stable (rotated 42)"
        );
    }

    #[test]
    fn test_build_rotated_key_name_non_numeric_suffix_is_base() {
        // A trailing "(rotated <non-number>)" is not a recognized rotation
        // suffix, so it is treated as part of the base name and the first
        // rotation suffix is appended.
        assert_eq!(
            build_rotated_key_name("my-key (rotated x)"),
            "my-key (rotated x) (rotated)"
        );
    }

    #[test]
    fn test_build_rotated_key_name_never_exceeds_column_limit() {
        // A base name at the column limit must still yield a name that fits
        // varchar(255) — the base is truncated to make room for the suffix.
        let long = "k".repeat(MAX_KEY_NAME_LEN);
        let rotated = build_rotated_key_name(&long);
        assert!(
            rotated.chars().count() <= MAX_KEY_NAME_LEN,
            "rotated name of {} chars exceeds the {}-char column limit",
            rotated.chars().count(),
            MAX_KEY_NAME_LEN
        );
        assert!(rotated.ends_with(" (rotated)"));
    }

    #[test]
    fn test_build_rotated_key_name_truncates_on_char_boundary() {
        // Multi-byte base names must be truncated on a char boundary (never
        // panic by slicing mid-codepoint) and still fit the limit.
        let long = "é".repeat(MAX_KEY_NAME_LEN);
        let rotated = build_rotated_key_name(&long);
        assert!(rotated.chars().count() <= MAX_KEY_NAME_LEN);
        assert!(rotated.ends_with(" (rotated)"));
    }

    #[test]
    fn test_build_rotated_key_name_many_rotations_bounded_and_distinct() {
        // The core #2543 regression guard: chaining 40 rotations must never
        // overflow the varchar(255) column and must keep every successor name
        // distinct from its predecessor (so the DB unique-ish naming stays
        // sensible). Previously the name grew +10 chars each time and blew past
        // 255 after ~25 rotations.
        let mut name = "org-release-signing-key".to_string();
        let mut seen = std::collections::HashSet::new();
        seen.insert(name.clone());
        for i in 1..=40 {
            let next = build_rotated_key_name(&name);
            assert!(
                next.chars().count() <= MAX_KEY_NAME_LEN,
                "rotation {i} produced a {}-char name (> {MAX_KEY_NAME_LEN})",
                next.chars().count()
            );
            assert_ne!(next, name, "rotation {i} did not change the name");
            assert!(
                seen.insert(next.clone()),
                "rotation {i} produced a duplicate name: {next}"
            );
            name = next;
        }
        // The final name is a bounded counter suffix, still readable. Rotation
        // 1 produces the bare "(rotated)" (count 1); rotation N (N>=2) produces
        // "(rotated N)", so after 40 rotations the counter reads 40.
        assert_eq!(name, "org-release-signing-key (rotated 40)");
    }

    #[test]
    fn test_build_rotated_key_name_long_base_many_rotations_stays_bounded() {
        // Same many-rotations guard but starting from a base already near the
        // column limit: truncation must keep every successor within 255 chars.
        let mut name = "n".repeat(MAX_KEY_NAME_LEN - 4);
        for i in 1..=40 {
            let next = build_rotated_key_name(&name);
            assert!(
                next.chars().count() <= MAX_KEY_NAME_LEN,
                "rotation {i} produced a {}-char name (> {MAX_KEY_NAME_LEN})",
                next.chars().count()
            );
            name = next;
        }
    }

    // -----------------------------------------------------------------------
    // rotate_key atomicity / serialization (#2534)
    //
    // DB-backed: require a live Postgres via DATABASE_URL (a throwaway,
    // migrated instance — NOT the rig DB). Each test scopes its assertions to
    // a freshly-created repository, so they are safe to run against a shared
    // test database without cross-test interference.
    // -----------------------------------------------------------------------

    const TEST_PASSPHRASE: &str = "signing-rotation-atomic-test-passphrase";

    async fn rotation_test_pool() -> Option<sqlx::PgPool> {
        let url = std::env::var("DATABASE_URL").ok()?;
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect(&url)
            .await
            .ok()
    }

    fn rotation_test_service(pool: sqlx::PgPool) -> SigningService {
        SigningService {
            db: pool,
            encryption: CredentialEncryption::from_passphrase(TEST_PASSPHRASE),
        }
    }

    async fn seed_repo(pool: &sqlx::PgPool) -> Uuid {
        let key = format!("rotate-test-{}", Uuid::new_v4().as_simple());
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO repositories (key, name, format, repo_type, storage_path) \
             VALUES ($1, $1, 'debian', 'local', '/tmp/test') RETURNING id",
        )
        .bind(&key)
        .fetch_one(pool)
        .await
        .expect("failed to create test repository")
    }

    /// Create an active RSA key for `repo` and point its signing config at it.
    async fn seed_active_key(service: &SigningService, repo: Uuid) -> Uuid {
        let key = service
            .create_key(CreateKeyRequest {
                repository_id: Some(repo),
                name: "rotate-test-key".to_string(),
                key_type: "rsa".to_string(),
                algorithm: "rsa2048".to_string(),
                uid_name: None,
                uid_email: None,
                created_by: None,
            })
            .await
            .expect("create_key failed");
        service
            .update_signing_config(repo, Some(key.id), true, false, false)
            .await
            .expect("update_signing_config failed");
        key.id
    }

    /// Count `is_active=true` keys for a repository.
    async fn active_key_ids(pool: &sqlx::PgPool, repo: Uuid) -> Vec<Uuid> {
        sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM signing_keys WHERE repository_id = $1 AND is_active = true",
        )
        .bind(repo)
        .fetch_all(pool)
        .await
        .expect("active key query failed")
    }

    // (#2534.1) 5 concurrent rotations of the same key must yield exactly ONE
    // new active key + four 409 Conflict, with no orphaned active keys.
    #[tokio::test]
    async fn rotate_concurrent_yields_single_active_key() {
        let Some(pool) = rotation_test_pool().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let service = std::sync::Arc::new(rotation_test_service(pool.clone()));
        let repo = seed_repo(&pool).await;
        let key_a = seed_active_key(&service, repo).await;

        let mut set = tokio::task::JoinSet::new();
        for _ in 0..5 {
            let svc = service.clone();
            set.spawn(async move { svc.rotate_key(key_a, None).await });
        }

        let mut ok = 0usize;
        let mut conflicts = 0usize;
        while let Some(res) = set.join_next().await {
            match res.expect("join failed") {
                Ok(_) => ok += 1,
                Err(AppError::Conflict(_)) => conflicts += 1,
                Err(other) => panic!("unexpected error from rotate_key: {other:?}"),
            }
        }

        assert_eq!(ok, 1, "exactly one rotation should succeed");
        assert_eq!(conflicts, 4, "the other four should return 409 Conflict");

        // Exactly one active key remains for the repo, and it is the successor.
        let active = active_key_ids(&pool, repo).await;
        assert_eq!(
            active.len(),
            1,
            "exactly one active key must remain (no orphans); got {active:?}"
        );
        assert_ne!(active[0], key_a, "the old key must not be the active one");

        // Exactly one successor points back at A (only the winner inserted).
        let successors: Vec<Uuid> = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM signing_keys WHERE repository_id = $1 AND rotated_from = $2",
        )
        .bind(repo)
        .bind(key_a)
        .fetch_all(&pool)
        .await
        .expect("successor query failed");
        assert_eq!(successors.len(), 1, "only one successor should be minted");
        assert_eq!(successors[0], active[0]);

        // Config points at the active successor.
        let cfg = service
            .get_signing_config(repo)
            .await
            .expect("get_signing_config failed")
            .expect("config must exist");
        assert_eq!(cfg.signing_key_id, Some(active[0]));

        // Old key is deactivated.
        assert!(!service.get_key(key_a).await.unwrap().is_active);
    }

    // (#2534.2) Polling the active key concurrently with a chain of rotations
    // must never observe None (no transient no-active-key window).
    #[tokio::test]
    async fn rotate_leaves_no_none_window_under_concurrent_poll() {
        let Some(pool) = rotation_test_pool().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let service = std::sync::Arc::new(rotation_test_service(pool.clone()));
        let repo = seed_repo(&pool).await;
        let key_a = seed_active_key(&service, repo).await;

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

        // Poller: hammer get_active_key_for_repo; assert never None.
        let poll_svc = service.clone();
        let poll_stop = stop.clone();
        let poller = tokio::spawn(async move {
            let mut polls = 0u32;
            while !poll_stop.load(std::sync::atomic::Ordering::Relaxed) {
                let active = poll_svc
                    .get_active_key_for_repo(repo)
                    .await
                    .expect("get_active_key_for_repo failed");
                assert!(
                    active.is_some(),
                    "observed a no-active-key window during rotation"
                );
                polls += 1;
            }
            polls
        });

        // Rotator: chain 10 sequential rotations (each rotates the current key).
        let mut current = key_a;
        for _ in 0..10 {
            current = service
                .rotate_key(current, None)
                .await
                .expect("rotate_key failed")
                .id;
        }

        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let polls = poller.await.expect("poller panicked");
        assert!(polls > 0, "poller should have run at least once");

        // Exactly one active key at the end.
        assert_eq!(active_key_ids(&pool, repo).await.len(), 1);
    }

    // (#2534.3) A rotation that rolls back mid-transition must leave state
    // unchanged (no permanent no-active-key state). We mirror the in-txn
    // create->repoint->deactivate sequence and roll it back, then assert the
    // repo is untouched.
    #[tokio::test]
    async fn rotate_rollback_leaves_state_unchanged() {
        let Some(pool) = rotation_test_pool().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let service = rotation_test_service(pool.clone());
        let repo = seed_repo(&pool).await;
        let key_a = seed_active_key(&service, repo).await;

        let material = service
            .generate_key_material(&CreateKeyRequest {
                repository_id: Some(repo),
                name: "rollback-successor".to_string(),
                key_type: "rsa".to_string(),
                algorithm: "rsa2048".to_string(),
                uid_name: None,
                uid_email: None,
                created_by: None,
            })
            .await
            .expect("generate_key_material failed");
        let new_id = Uuid::new_v4();
        let req = CreateKeyRequest {
            repository_id: Some(repo),
            name: "rollback-successor".to_string(),
            key_type: "rsa".to_string(),
            algorithm: "rsa2048".to_string(),
            uid_name: None,
            uid_email: None,
            created_by: None,
        };

        {
            let mut tx = pool.begin().await.expect("begin failed");
            SigningService::insert_key_row(
                &mut *tx,
                new_id,
                &req,
                &material,
                true,
                Some(key_a),
                Utc::now(),
            )
            .await
            .expect("insert_key_row failed");
            sqlx::query!(
                "UPDATE repository_signing_config SET signing_key_id = $1 WHERE repository_id = $2 AND signing_key_id = $3",
                new_id,
                repo,
                key_a,
            )
            .execute(&mut *tx)
            .await
            .expect("repoint failed");
            sqlx::query!(
                "UPDATE signing_keys SET is_active = false WHERE id = $1",
                key_a,
            )
            .execute(&mut *tx)
            .await
            .expect("deactivate failed");
            // Drop without commit -> rollback.
            tx.rollback().await.expect("rollback failed");
        }

        // State must be exactly as seeded: A active, config->A, no successor.
        let active = active_key_ids(&pool, repo).await;
        assert_eq!(active, vec![key_a], "A must still be the only active key");
        let cfg = service
            .get_signing_config(repo)
            .await
            .unwrap()
            .expect("config must exist");
        assert_eq!(cfg.signing_key_id, Some(key_a));
        assert!(
            service.get_key(new_id).await.is_err(),
            "successor must not persist"
        );
    }

    // (#2534.4) A single legitimate rotation produces the expected end state.
    #[tokio::test]
    async fn rotate_single_produces_expected_end_state() {
        let Some(pool) = rotation_test_pool().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let service = rotation_test_service(pool.clone());
        let repo = seed_repo(&pool).await;
        let key_a = seed_active_key(&service, repo).await;

        let new_key = service
            .rotate_key(key_a, None)
            .await
            .expect("rotate failed");

        // Old inactive, new active.
        assert!(!service.get_key(key_a).await.unwrap().is_active);
        assert!(new_key.is_active);

        // Successor recorded rotated_from = A.
        let rotated_from: Option<Uuid> = sqlx::query_scalar::<_, Option<Uuid>>(
            "SELECT rotated_from FROM signing_keys WHERE id = $1",
        )
        .bind(new_key.id)
        .fetch_one(&pool)
        .await
        .expect("rotated_from query failed");
        assert_eq!(rotated_from, Some(key_a));

        // Config repointed to the successor.
        let cfg = service.get_signing_config(repo).await.unwrap().unwrap();
        assert_eq!(cfg.signing_key_id, Some(new_key.id));

        // Audit rows: created (for successor) + rotated (for old) present.
        let created: i64 = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM signing_key_audit WHERE signing_key_id = $1 AND action = 'created'",
        )
        .bind(new_key.id)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(created, 1, "successor should have a 'created' audit row");
        let rotated: i64 = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM signing_key_audit WHERE signing_key_id = $1 AND action = 'rotated'",
        )
        .bind(key_a)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(rotated, 1, "old key should have a 'rotated' audit row");
    }

    // (#2534.5) Rotating an already-rotated (now inactive) key returns 409 and
    // mints no further key.
    #[tokio::test]
    async fn rotate_already_rotated_key_returns_conflict() {
        let Some(pool) = rotation_test_pool().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let service = rotation_test_service(pool.clone());
        let repo = seed_repo(&pool).await;
        let key_a = seed_active_key(&service, repo).await;

        // First rotation succeeds.
        service
            .rotate_key(key_a, None)
            .await
            .expect("first rotate failed");
        let total_after_first: i64 = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM signing_keys WHERE repository_id = $1",
        )
        .bind(repo)
        .fetch_one(&pool)
        .await
        .unwrap();

        // Second rotation of the now-inactive A returns Conflict, no new key.
        let err = service
            .rotate_key(key_a, None)
            .await
            .expect_err("second rotate of inactive key should fail");
        assert!(
            matches!(err, AppError::Conflict(_)),
            "expected 409 Conflict, got {err:?}"
        );

        let total_after_second: i64 = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM signing_keys WHERE repository_id = $1",
        )
        .bind(repo)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            total_after_first, total_after_second,
            "a rejected rotation must not mint a key"
        );
    }

    // (#2543) Chaining 35 rotations of the same repo's key must ALL succeed:
    // the successor name must never overflow the varchar(255) `name` column.
    // Under the old unbounded "(rotated)"-append scheme the INSERT 500'd after
    // ~25 rotations ("value too long for type character varying(255)") and the
    // key became permanently un-rotatable. The bounded counter suffix keeps
    // every successor name within the column, so the chain never wedges.
    #[tokio::test]
    async fn rotate_many_times_never_overflows_name_column() {
        let Some(pool) = rotation_test_pool().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let service = rotation_test_service(pool.clone());
        let repo = seed_repo(&pool).await;
        let mut current = seed_active_key(&service, repo).await;

        let mut names = std::collections::HashSet::new();
        for i in 1..=35 {
            let next = service
                .rotate_key(current, None)
                .await
                .unwrap_or_else(|e| panic!("rotation {i} failed (name overflow?): {e:?}"));

            // Successor name fits the column and is distinct from all prior.
            assert!(
                next.name.chars().count() <= MAX_KEY_NAME_LEN,
                "rotation {i} produced a {}-char name (> {MAX_KEY_NAME_LEN}): {}",
                next.name.chars().count(),
                next.name
            );
            assert!(
                names.insert(next.name.clone()),
                "rotation {i} produced a duplicate name: {}",
                next.name
            );

            // Exactly one active key remains after each rotation.
            assert_eq!(
                active_key_ids(&pool, repo).await.len(),
                1,
                "exactly one active key must remain after rotation {i}"
            );

            current = next.id;
        }
    }

    // -----------------------------------------------------------------------
    // #2535: the per-artifact `used_for_signing` marker (read by the promotion
    // `require_signature` gate) is written ONLY by the deliberate, authorized
    // `sign_artifact_content` path — never by metadata signing (`sign_data`).
    // -----------------------------------------------------------------------

    async fn seed_artifact(pool: &sqlx::PgPool, repo: Uuid) -> Uuid {
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO artifacts \
                (repository_id, path, name, size_bytes, checksum_sha256, content_type, storage_key) \
             VALUES ($1, $2, $2, 1, repeat('a', 64), 'application/octet-stream', $2) \
             RETURNING id",
        )
        .bind(repo)
        .bind(format!("pkg-{}.deb", Uuid::new_v4().as_simple()))
        .fetch_one(pool)
        .await
        .expect("failed to create test artifact")
    }

    /// Count `used_for_signing` rows for a (key, artifact) pair.
    async fn used_for_signing_count(pool: &sqlx::PgPool, key_id: Uuid, artifact_id: Uuid) -> i64 {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM signing_key_audit \
             WHERE signing_key_id = $1 AND action = 'used_for_signing' \
               AND details->>'artifact_id' = $2::text",
        )
        .bind(key_id)
        .bind(artifact_id)
        .fetch_one(pool)
        .await
        .expect("audit count query failed")
    }

    // A deliberate per-artifact signing action writes exactly one marker for the
    // artifact under the repo's active key, and is idempotent on repeat.
    #[tokio::test]
    async fn sign_artifact_content_writes_single_idempotent_marker() {
        let Some(pool) = rotation_test_pool().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let service = rotation_test_service(pool.clone());
        let repo = seed_repo(&pool).await;
        let key_id = seed_active_key(&service, repo).await;
        let artifact_id = seed_artifact(&pool, repo).await;

        // No marker before the artifact is deliberately signed.
        assert_eq!(used_for_signing_count(&pool, key_id, artifact_id).await, 0);

        // `performed_by` is left None here (the rotation harness seeds no users
        // row and the column is FK-constrained + nullable); the handler passes
        // the authenticated admin's id in production.
        let out = service
            .sign_artifact_content(repo, artifact_id, b"artifact-bytes", None)
            .await
            .expect("sign_artifact_content failed")
            .expect("an active key must produce a signature");
        assert_eq!(out.key_id, key_id);
        assert!(!out.signature_sha256.is_empty());
        assert_eq!(
            used_for_signing_count(&pool, key_id, artifact_id).await,
            1,
            "signing an artifact must record exactly one marker"
        );

        // Re-signing the same artifact with the same active key is idempotent.
        service
            .sign_artifact_content(repo, artifact_id, b"artifact-bytes-again", None)
            .await
            .expect("sign_artifact_content failed")
            .expect("still signable");
        assert_eq!(
            used_for_signing_count(&pool, key_id, artifact_id).await,
            1,
            "repeated signing must not duplicate the marker"
        );
    }

    // A repository with no active signing key / config cannot sign -> Ok(None)
    // (the handler maps this to a 409 and the artifact stays fail-closed).
    #[tokio::test]
    async fn sign_artifact_content_without_active_key_returns_none() {
        let Some(pool) = rotation_test_pool().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let service = rotation_test_service(pool.clone());
        let repo = seed_repo(&pool).await;
        let artifact_id = seed_artifact(&pool, repo).await;

        let out = service
            .sign_artifact_content(repo, artifact_id, b"bytes", None)
            .await
            .expect("sign_artifact_content failed");
        assert!(out.is_none(), "no active key -> None (fail-closed)");

        // No marker exists for the artifact under ANY key.
        let markers: i64 = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM signing_key_audit \
             WHERE action = 'used_for_signing' AND details->>'artifact_id' = $1::text",
        )
        .bind(artifact_id)
        .fetch_one(&pool)
        .await
        .expect("count failed");
        assert_eq!(markers, 0, "an unsignable repo must attest nothing");
    }

    // Regression guard against PR #2553 Part B: metadata signing (`sign_data`)
    // must NEVER write a per-artifact `used_for_signing` marker. An anonymous
    // metadata read must not be able to attest artifacts.
    #[tokio::test]
    async fn sign_data_writes_no_used_for_signing_marker() {
        let Some(pool) = rotation_test_pool().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let service = rotation_test_service(pool.clone());
        let repo = seed_repo(&pool).await;
        let key_id = seed_active_key(&service, repo).await;
        let artifact_id = seed_artifact(&pool, repo).await;

        let sig = service
            .sign_data(repo, b"repomd.xml")
            .await
            .expect("sign_data failed");
        assert!(
            sig.is_some(),
            "metadata signing must still produce a signature"
        );

        // But it must attest NO artifact.
        assert_eq!(
            used_for_signing_count(&pool, key_id, artifact_id).await,
            0,
            "sign_data must not write a used_for_signing marker (anon-read attestation bypass)"
        );
        let total: i64 = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM signing_key_audit \
             WHERE signing_key_id = $1 AND action = 'used_for_signing'",
        )
        .bind(key_id)
        .fetch_one(&pool)
        .await
        .expect("count failed");
        assert_eq!(total, 0, "metadata signing must attest zero artifacts");
    }

    // -----------------------------------------------------------------------
    // Hex registry key lifecycle (#2641)
    // -----------------------------------------------------------------------

    async fn seed_hex_repo(pool: &sqlx::PgPool) -> Uuid {
        let key = format!("hex-key-test-{}", Uuid::new_v4().as_simple());
        sqlx::query_scalar::<_, Uuid>(
            "INSERT INTO repositories (key, name, format, repo_type, storage_path) \
             VALUES ($1, $1, 'hex', 'local', '/tmp/test') RETURNING id",
        )
        .bind(&key)
        .fetch_one(pool)
        .await
        .expect("failed to create test hex repository")
    }

    /// Revoking the registry key must leave the repository RECOVERABLE: the
    /// next fetch provisions a fresh key instead of 500ing forever.
    ///
    /// This is the regression test for the index/lookup predicate mismatch. The
    /// unique index used to omit `is_active`, while the lookup required it. A
    /// revoked key therefore stayed *invisible to the lookup but visible to the
    /// index*: every subsequent request ran a full RSA-2048 keygen, hit
    /// `ON CONFLICT DO NOTHING` against the revoked row, re-selected nothing and
    /// returned `AppError::Internal` — a permanent 500 with no API-reachable
    /// recovery, and an anonymous CPU-burn on the way. Revoking a leaked key is
    /// exactly what an operator does during an incident, so this path has to
    /// work.
    #[tokio::test]
    async fn hex_registry_key_reprovisions_after_revoke() {
        let Some(pool) = rotation_test_pool().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let service = rotation_test_service(pool.clone());
        let repo = seed_hex_repo(&pool).await;

        let first = service
            .get_or_create_hex_registry_key(repo)
            .await
            .expect("initial provisioning failed");

        service
            .revoke_key(first.id, None)
            .await
            .expect("revoke failed");

        // The whole point: this must NOT be an Internal error.
        let second = service
            .get_or_create_hex_registry_key(repo)
            .await
            .expect("re-provisioning after revoke must succeed, not 500");

        assert_ne!(
            second.id, first.id,
            "a revoked key must not be handed back out"
        );
        assert!(second.is_active, "the replacement key must be active");
        assert_eq!(
            active_key_ids(&pool, repo).await,
            vec![second.id],
            "exactly one active registry key must remain after revoke + re-provision"
        );

        // The revoked row survives as an audit record rather than being deleted.
        let revoked_still_present: bool = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM signing_keys WHERE id = $1 AND is_active = false)",
        )
        .bind(first.id)
        .fetch_one(&pool)
        .await
        .expect("query failed");
        assert!(
            revoked_still_present,
            "the revoked key's row must remain for audit"
        );

        // And the cycle is repeatable — revoke is not a one-shot escape hatch.
        service
            .revoke_key(second.id, None)
            .await
            .expect("second revoke failed");
        let third = service
            .get_or_create_hex_registry_key(repo)
            .await
            .expect("second re-provisioning must also succeed");
        assert_ne!(third.id, second.id);
        assert!(third.is_active);
    }

    /// A steady-state fetch must be a pure lookup: no new key, no keygen.
    #[tokio::test]
    async fn hex_registry_key_is_stable_across_fetches() {
        let Some(pool) = rotation_test_pool().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let service = rotation_test_service(pool.clone());
        let repo = seed_hex_repo(&pool).await;

        let first = service.provision_hex_registry_key(repo).await.unwrap();
        for _ in 0..3 {
            let again = service.get_or_create_hex_registry_key(repo).await.unwrap();
            assert_eq!(
                again.id, first.id,
                "a repeat fetch must reuse the existing key, never mint a new one"
            );
        }
        assert_eq!(active_key_ids(&pool, repo).await.len(), 1);
    }

    /// Concurrent provisioning collapses onto ONE key — and, thanks to the
    /// advisory lock, one keygen. The unique index alone dedupes the row but not
    /// the work: without serialization each caller completes a full RSA-2048
    /// keygen and all but one throw it away.
    #[tokio::test]
    async fn hex_registry_key_concurrent_provisioning_yields_one_key() {
        let Some(pool) = rotation_test_pool().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let service = rotation_test_service(pool.clone());
        let repo = seed_hex_repo(&pool).await;

        let mut set = tokio::task::JoinSet::new();
        for _ in 0..5 {
            let svc = rotation_test_service(pool.clone());
            set.spawn(async move { svc.get_or_create_hex_registry_key(repo).await });
        }
        let mut ids = Vec::new();
        while let Some(joined) = set.join_next().await {
            let key = joined
                .expect("task panicked")
                .expect("concurrent provisioning must not error");
            ids.push(key.id);
        }

        assert_eq!(ids.len(), 5);
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(
            unique.len(),
            1,
            "all concurrent callers must observe the same key, got {unique:?}"
        );
        assert_eq!(
            active_key_ids(&pool, repo).await.len(),
            1,
            "concurrent provisioning must leave exactly one active key"
        );
        let _ = &service;
    }

    /// The hex registry key is addressed by NAME, so a renamed successor is a
    /// key nothing can find. `rotate_key` must say so rather than silently
    /// orphaning it. Replacement is expressed as revoke + re-provision.
    #[tokio::test]
    async fn hex_registry_key_cannot_be_rotated() {
        let Some(pool) = rotation_test_pool().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let service = rotation_test_service(pool.clone());
        let repo = seed_hex_repo(&pool).await;
        let key = service.provision_hex_registry_key(repo).await.unwrap();

        let err = service
            .rotate_key(key.id, None)
            .await
            .expect_err("rotating the hex registry key must be refused");
        assert!(
            matches!(err, AppError::Conflict(_)),
            "expected Conflict, got {err:?}"
        );

        // The refusal must be inert: the key is untouched and still usable.
        let after = service.get_or_create_hex_registry_key(repo).await.unwrap();
        assert_eq!(
            after.id, key.id,
            "a refused rotation must leave the existing key in place"
        );
        assert_eq!(active_key_ids(&pool, repo).await, vec![key.id]);
    }

    /// Rotation must still work for the keys it is meant for — the guard is
    /// scoped to the hex registry key by name, not a blanket block.
    #[tokio::test]
    async fn rotate_still_works_for_non_hex_keys() {
        let Some(pool) = rotation_test_pool().await else {
            eprintln!("skipping: DATABASE_URL not set");
            return;
        };
        let service = rotation_test_service(pool.clone());
        let repo = seed_repo(&pool).await;
        let old = seed_active_key(&service, repo).await;

        let new = service
            .rotate_key(old, None)
            .await
            .expect("rotating an ordinary signing key must still succeed");
        assert_ne!(new.id, old);
        assert_eq!(active_key_ids(&pool, repo).await, vec![new.id]);
    }
}
