//! SSO provider configuration management service.
//!
//! Provides CRUD operations for OIDC, LDAP, and SAML provider configurations
//! stored in the database, including encrypted credential storage and
//! SSO session management for CSRF protection during auth flows.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::api::validation::validate_outbound_sso_url;
use crate::error::{AppError, Result};
use crate::services::encryption::{decrypt_credentials, encrypt_credentials};

/// Validate an OIDC `issuer_url` against the SSO outbound-URL SSRF guard
/// before it is persisted. Uses the dedicated `SsoDiscovery` context
/// (issue #1891) so a configured, trusted IdP at a private/internal
/// address can be saved when the operator allows it via
/// `AK_SSRF_ALLOW_PRIVATE_CIDRS` (preferred) or `SSO_ALLOW_PRIVATE_IPS`,
/// without relaxing the upstream-proxy / webhook SSRF guards. This must
/// stay consistent with the request-time `validate_oidc_fetch_url` check
/// in the SSO handler, otherwise a config could save but never log in
/// (or vice versa).
fn validate_oidc_issuer(url: &str) -> Result<()> {
    validate_outbound_sso_url(url, "OIDC issuer URL")
}

// ---------------------------------------------------------------------------
// Row structs (mapped directly from database columns)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, FromRow)]
pub struct OidcConfigRow {
    pub id: Uuid,
    pub name: String,
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret_encrypted: String,
    pub scopes: Vec<String>,
    pub attribute_mapping: serde_json::Value,
    pub is_enabled: bool,
    pub auto_create_users: bool,
    /// When true, PKCE with S256 challenge is added to the authorization
    /// request and the verifier is sent on token exchange (RFC 7636).
    pub pkce_enabled: bool,
    /// When true, the OIDC `groups` claim values are reflected as
    /// Artifact Keeper group memberships (auto-creating groups on first
    /// sight). Otherwise legacy role mapping is used.
    pub map_groups_to_groups: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, FromRow)]
pub struct LdapConfigRow {
    pub id: Uuid,
    pub name: String,
    pub server_url: String,
    pub bind_dn: Option<String>,
    pub bind_password_encrypted: Option<String>,
    pub user_base_dn: String,
    pub user_filter: String,
    pub group_base_dn: Option<String>,
    pub group_filter: Option<String>,
    pub email_attribute: String,
    pub display_name_attribute: String,
    pub username_attribute: String,
    pub groups_attribute: String,
    pub admin_group_dn: Option<String>,
    pub use_starttls: bool,
    pub is_enabled: bool,
    pub priority: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

redacted_debug!(LdapConfigRow {
    show id,
    show name,
    show server_url,
    show bind_dn,
    redact_option bind_password_encrypted,
    show user_base_dn,
    show is_enabled,
});

#[derive(Clone, FromRow)]
pub struct SamlConfigRow {
    pub id: Uuid,
    pub name: String,
    pub entity_id: String,
    pub sso_url: String,
    pub slo_url: Option<String>,
    pub certificate: String,
    pub name_id_format: String,
    pub attribute_mapping: serde_json::Value,
    pub sp_entity_id: String,
    pub sign_requests: bool,
    pub require_signed_assertions: bool,
    pub admin_group: Option<String>,
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

redacted_debug!(SamlConfigRow {
    show id,
    show name,
    show entity_id,
    show sso_url,
    redact certificate,
    show sp_entity_id,
    show is_enabled,
});

#[derive(Debug, Clone, FromRow)]
pub struct SsoSession {
    pub id: Uuid,
    pub provider_type: String,
    pub provider_id: Uuid,
    pub state: String,
    pub nonce: Option<String>,
    /// PKCE code_verifier (RFC 7636). Generated at login time, sent to the
    /// token endpoint during the callback to prove possession.
    pub pkce_code_verifier: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// API response structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct OidcConfigResponse {
    pub id: Uuid,
    pub name: String,
    pub issuer_url: String,
    pub client_id: String,
    pub has_secret: bool,
    pub scopes: Vec<String>,
    #[schema(value_type = Object)]
    pub attribute_mapping: serde_json::Value,
    pub is_enabled: bool,
    pub auto_create_users: bool,
    pub pkce_enabled: bool,
    pub map_groups_to_groups: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct LdapConfigResponse {
    pub id: Uuid,
    pub name: String,
    pub server_url: String,
    pub bind_dn: Option<String>,
    pub has_bind_password: bool,
    pub user_base_dn: String,
    pub user_filter: String,
    pub group_base_dn: Option<String>,
    pub group_filter: Option<String>,
    pub email_attribute: String,
    pub display_name_attribute: String,
    pub username_attribute: String,
    pub groups_attribute: String,
    pub admin_group_dn: Option<String>,
    pub use_starttls: bool,
    pub is_enabled: bool,
    pub priority: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SamlConfigResponse {
    pub id: Uuid,
    pub name: String,
    pub entity_id: String,
    pub sso_url: String,
    pub slo_url: Option<String>,
    pub has_certificate: bool,
    pub name_id_format: String,
    #[schema(value_type = Object)]
    pub attribute_mapping: serde_json::Value,
    pub sp_entity_id: String,
    pub sign_requests: bool,
    pub require_signed_assertions: bool,
    pub admin_group: Option<String>,
    pub is_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Request structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateOidcConfigRequest {
    pub name: String,
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub scopes: Option<Vec<String>>,
    #[schema(value_type = Option<Object>)]
    pub attribute_mapping: Option<serde_json::Value>,
    pub is_enabled: Option<bool>,
    pub auto_create_users: Option<bool>,
    /// Enable PKCE (S256) on the authorization request. Defaults to `true`.
    pub pkce_enabled: Option<bool>,
    /// When `true`, OIDC group claim values are reflected as Artifact Keeper
    /// group memberships (auto-creating groups on first sight). Defaults to
    /// `false` to preserve legacy role-mapping behavior.
    pub map_groups_to_groups: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdateOidcConfigRequest {
    pub name: Option<String>,
    pub issuer_url: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scopes: Option<Vec<String>>,
    /// Partial update for `attribute_mapping`. Keys present in this object
    /// overwrite the matching keys in the stored mapping. Keys not present
    /// are preserved. To remove a key, set it to `null`. To replace the
    /// whole mapping atomically, set `attribute_mapping_replace = true`.
    /// (See issue #1191.)
    #[schema(value_type = Option<Object>)]
    pub attribute_mapping: Option<serde_json::Value>,
    /// When `true`, treat `attribute_mapping` as a wholesale replacement
    /// (legacy behavior). Defaults to `false` — partial merge.
    pub attribute_mapping_replace: Option<bool>,
    pub is_enabled: Option<bool>,
    pub auto_create_users: Option<bool>,
    pub pkce_enabled: Option<bool>,
    pub map_groups_to_groups: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateLdapConfigRequest {
    pub name: String,
    pub server_url: String,
    pub bind_dn: Option<String>,
    pub bind_password: Option<String>,
    pub user_base_dn: String,
    pub user_filter: Option<String>,
    pub group_base_dn: Option<String>,
    pub group_filter: Option<String>,
    pub email_attribute: Option<String>,
    pub display_name_attribute: Option<String>,
    pub username_attribute: Option<String>,
    pub groups_attribute: Option<String>,
    pub admin_group_dn: Option<String>,
    pub use_starttls: Option<bool>,
    pub is_enabled: Option<bool>,
    pub priority: Option<i32>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdateLdapConfigRequest {
    pub name: Option<String>,
    pub server_url: Option<String>,
    pub bind_dn: Option<String>,
    pub bind_password: Option<String>,
    pub user_base_dn: Option<String>,
    pub user_filter: Option<String>,
    pub group_base_dn: Option<String>,
    pub group_filter: Option<String>,
    pub email_attribute: Option<String>,
    pub display_name_attribute: Option<String>,
    pub username_attribute: Option<String>,
    pub groups_attribute: Option<String>,
    pub admin_group_dn: Option<String>,
    pub use_starttls: Option<bool>,
    pub is_enabled: Option<bool>,
    pub priority: Option<i32>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateSamlConfigRequest {
    pub name: String,
    pub entity_id: String,
    pub sso_url: String,
    pub slo_url: Option<String>,
    pub certificate: String,
    pub name_id_format: Option<String>,
    #[schema(value_type = Option<Object>)]
    pub attribute_mapping: Option<serde_json::Value>,
    pub sp_entity_id: Option<String>,
    pub sign_requests: Option<bool>,
    pub require_signed_assertions: Option<bool>,
    pub admin_group: Option<String>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdateSamlConfigRequest {
    pub name: Option<String>,
    pub entity_id: Option<String>,
    pub sso_url: Option<String>,
    pub slo_url: Option<String>,
    pub certificate: Option<String>,
    pub name_id_format: Option<String>,
    #[schema(value_type = Option<Object>)]
    pub attribute_mapping: Option<serde_json::Value>,
    pub sp_entity_id: Option<String>,
    pub sign_requests: Option<bool>,
    pub require_signed_assertions: Option<bool>,
    pub admin_group: Option<String>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SsoProviderInfo {
    pub id: Uuid,
    pub name: String,
    pub provider_type: String,
    pub login_url: String,
}

impl SsoProviderInfo {
    pub fn new(id: Uuid, name: String, provider_type: &str) -> Self {
        Self {
            login_url: format!("/api/v1/auth/sso/{provider_type}/{id}/login"),
            id,
            name,
            provider_type: provider_type.to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ToggleRequest {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct LdapTestResult {
    pub success: bool,
    pub message: String,
    pub response_time_ms: u64,
}

// ---------------------------------------------------------------------------
// Encryption key — in production, load from config / env
// ---------------------------------------------------------------------------

pub fn encryption_key() -> String {
    std::env::var("SSO_ENCRYPTION_KEY")
        .or_else(|_| std::env::var("JWT_SECRET"))
        .expect(
            "Neither SSO_ENCRYPTION_KEY nor JWT_SECRET is set. \
             At least one must be configured for SSO credential encryption.",
        )
}

// ---------------------------------------------------------------------------
// PKCE helpers (RFC 7636)
// ---------------------------------------------------------------------------

/// Generate a cryptographically random PKCE code_verifier per RFC 7636 §4.1.
///
/// The verifier is a high-entropy string of 43-128 unreserved characters.
/// We produce 64 base64url-no-pad characters (48 random bytes encoded), which
/// yields 384 bits of entropy and stays well within the spec bounds.
///
/// RFC 7636 §7.1 requires the verifier be generated with a cryptographically
/// secure RNG. We pull bytes from the OS CSPRNG (`rand::rngs::OsRng`, backed
/// by `getrandom`) directly rather than via the thread-local PRNG so the
/// provenance of the entropy is unambiguous in source review and audits.
pub fn generate_pkce_verifier() -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use rand::rngs::OsRng;
    use rand::TryRngCore;

    let mut bytes = [0u8; 48];
    OsRng
        .try_fill_bytes(&mut bytes)
        .expect("OS CSPRNG must be available to mint PKCE verifiers");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Derive the S256 PKCE code_challenge from a verifier per RFC 7636 §4.2.
///
/// `challenge = base64url(SHA256(verifier))` with no padding.
pub fn pkce_challenge_s256(verifier: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

// ---------------------------------------------------------------------------
// JSON merge helper (for issue #1191 attribute_mapping PATCH semantics)
// ---------------------------------------------------------------------------

/// Deep-merge a JSON patch into a base object, returning the merged value.
///
/// Semantics:
/// - If both `base` and `patch` are objects, recursively merge keys.
/// - If a patch value is `null`, the corresponding key is **removed** from
///   the base (RFC 7396-ish merge-patch semantics).
/// - Otherwise, the patch value overwrites the base value at that key.
/// - Arrays and primitives in `patch` replace the corresponding `base` value.
///
/// This is intentionally narrow: it is only used to merge OIDC
/// `attribute_mapping` blobs, which are flat (or near-flat) JSON objects.
pub fn merge_attribute_mapping(
    base: &serde_json::Value,
    patch: &serde_json::Value,
) -> serde_json::Value {
    match (base, patch) {
        (serde_json::Value::Object(base_map), serde_json::Value::Object(patch_map)) => {
            let mut out = base_map.clone();
            for (k, v) in patch_map {
                if v.is_null() {
                    out.remove(k);
                } else if out.contains_key(k) {
                    let merged = merge_attribute_mapping(&out[k], v);
                    out.insert(k.clone(), merged);
                } else {
                    out.insert(k.clone(), v.clone());
                }
            }
            serde_json::Value::Object(out)
        }
        // Patch isn't an object, or base isn't an object: patch wins.
        (_, patch) => patch.clone(),
    }
}

// ---------------------------------------------------------------------------
// Service implementation
// ---------------------------------------------------------------------------

pub struct AuthConfigService;

impl AuthConfigService {
    // -----------------------------------------------------------------------
    // OIDC
    // -----------------------------------------------------------------------

    pub async fn list_oidc(pool: &PgPool) -> Result<Vec<OidcConfigResponse>> {
        let rows = sqlx::query_as::<_, OidcConfigRow>(
            r#"
            SELECT id, name, issuer_url, client_id, client_secret_encrypted,
                   scopes, attribute_mapping, is_enabled, auto_create_users,
                   pkce_enabled, map_groups_to_groups,
                   created_at, updated_at
            FROM oidc_configs
            ORDER BY name
            "#,
        )
        .fetch_all(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to list OIDC configs: {e}")))?;

        Ok(rows.into_iter().map(Self::oidc_row_to_response).collect())
    }

    pub async fn get_oidc(pool: &PgPool, id: Uuid) -> Result<OidcConfigResponse> {
        let row = sqlx::query_as::<_, OidcConfigRow>(
            r#"
            SELECT id, name, issuer_url, client_id, client_secret_encrypted,
                   scopes, attribute_mapping, is_enabled, auto_create_users,
                   pkce_enabled, map_groups_to_groups,
                   created_at, updated_at
            FROM oidc_configs
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get OIDC config: {e}")))?
        .ok_or_else(|| AppError::NotFound(format!("OIDC config {id} not found")))?;

        Ok(Self::oidc_row_to_response(row))
    }

    /// Internal helper that returns the decrypted client secret.
    pub async fn get_oidc_decrypted(pool: &PgPool, id: Uuid) -> Result<(OidcConfigRow, String)> {
        let row = sqlx::query_as::<_, OidcConfigRow>(
            r#"
            SELECT id, name, issuer_url, client_id, client_secret_encrypted,
                   scopes, attribute_mapping, is_enabled, auto_create_users,
                   pkce_enabled, map_groups_to_groups,
                   created_at, updated_at
            FROM oidc_configs
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get OIDC config: {e}")))?
        .ok_or_else(|| AppError::NotFound(format!("OIDC config {id} not found")))?;

        let encrypted_bytes = hex::decode(&row.client_secret_encrypted)
            .map_err(|e| AppError::Internal(format!("Failed to decode secret hex: {e}")))?;
        let secret = decrypt_credentials(&encrypted_bytes, &encryption_key())
            .map_err(|e| AppError::Internal(format!("Failed to decrypt secret: {e}")))?;

        Ok((row, secret))
    }

    pub async fn create_oidc(
        pool: &PgPool,
        req: CreateOidcConfigRequest,
    ) -> Result<OidcConfigResponse> {
        validate_oidc_issuer(&req.issuer_url)?;
        let id = Uuid::new_v4();
        let encrypted = encrypt_credentials(&req.client_secret, &encryption_key());
        let encrypted_hex = hex::encode(&encrypted);
        let scopes = req.scopes.unwrap_or_else(|| {
            vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ]
        });
        let attribute_mapping = req.attribute_mapping.unwrap_or(serde_json::json!({}));
        let is_enabled = req.is_enabled.unwrap_or(true);
        let auto_create_users = req.auto_create_users.unwrap_or(true);
        let pkce_enabled = req.pkce_enabled.unwrap_or(true);
        let map_groups_to_groups = req.map_groups_to_groups.unwrap_or(false);

        let row = sqlx::query_as::<_, OidcConfigRow>(
            r#"
            INSERT INTO oidc_configs (id, name, issuer_url, client_id, client_secret_encrypted,
                                      scopes, attribute_mapping, is_enabled, auto_create_users,
                                      pkce_enabled, map_groups_to_groups)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING id, name, issuer_url, client_id, client_secret_encrypted,
                      scopes, attribute_mapping, is_enabled, auto_create_users,
                      pkce_enabled, map_groups_to_groups,
                      created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(&req.name)
        .bind(&req.issuer_url)
        .bind(&req.client_id)
        .bind(&encrypted_hex)
        .bind(&scopes)
        .bind(&attribute_mapping)
        .bind(is_enabled)
        .bind(auto_create_users)
        .bind(pkce_enabled)
        .bind(map_groups_to_groups)
        .fetch_one(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to create OIDC config: {e}")))?;

        Ok(Self::oidc_row_to_response(row))
    }

    pub async fn update_oidc(
        pool: &PgPool,
        id: Uuid,
        req: UpdateOidcConfigRequest,
    ) -> Result<OidcConfigResponse> {
        let existing = sqlx::query_as::<_, OidcConfigRow>(
            r#"
            SELECT id, name, issuer_url, client_id, client_secret_encrypted,
                   scopes, attribute_mapping, is_enabled, auto_create_users,
                   pkce_enabled, map_groups_to_groups,
                   created_at, updated_at
            FROM oidc_configs
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get OIDC config: {e}")))?
        .ok_or_else(|| AppError::NotFound(format!("OIDC config {id} not found")))?;

        let name = req.name.unwrap_or(existing.name);
        let issuer_url = req.issuer_url.unwrap_or(existing.issuer_url);
        validate_oidc_issuer(&issuer_url)?;
        let client_id = req.client_id.unwrap_or(existing.client_id);
        let scopes = req.scopes.unwrap_or(existing.scopes);
        // Issue #1191: deep-merge attribute_mapping by default. Callers that
        // want the legacy wholesale-replace behavior must opt in.
        let attribute_mapping = match req.attribute_mapping {
            Some(patch) if req.attribute_mapping_replace.unwrap_or(false) => patch,
            Some(patch) => merge_attribute_mapping(&existing.attribute_mapping, &patch),
            None => existing.attribute_mapping,
        };
        let is_enabled = req.is_enabled.unwrap_or(existing.is_enabled);
        let auto_create_users = req.auto_create_users.unwrap_or(existing.auto_create_users);
        let pkce_enabled = req.pkce_enabled.unwrap_or(existing.pkce_enabled);
        let map_groups_to_groups = req
            .map_groups_to_groups
            .unwrap_or(existing.map_groups_to_groups);

        // Preserve existing encrypted secret if not provided
        let secret_hex = if let Some(new_secret) = &req.client_secret {
            let encrypted = encrypt_credentials(new_secret, &encryption_key());
            hex::encode(&encrypted)
        } else {
            existing.client_secret_encrypted
        };

        let row = sqlx::query_as::<_, OidcConfigRow>(
            r#"
            UPDATE oidc_configs
            SET name = $1, issuer_url = $2, client_id = $3, client_secret_encrypted = $4,
                scopes = $5, attribute_mapping = $6, is_enabled = $7, auto_create_users = $8,
                pkce_enabled = $9, map_groups_to_groups = $10,
                updated_at = NOW()
            WHERE id = $11
            RETURNING id, name, issuer_url, client_id, client_secret_encrypted,
                      scopes, attribute_mapping, is_enabled, auto_create_users,
                      pkce_enabled, map_groups_to_groups,
                      created_at, updated_at
            "#,
        )
        .bind(&name)
        .bind(&issuer_url)
        .bind(&client_id)
        .bind(&secret_hex)
        .bind(&scopes)
        .bind(&attribute_mapping)
        .bind(is_enabled)
        .bind(auto_create_users)
        .bind(pkce_enabled)
        .bind(map_groups_to_groups)
        .bind(id)
        .fetch_one(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to update OIDC config: {e}")))?;

        Ok(Self::oidc_row_to_response(row))
    }

    pub async fn delete_oidc(pool: &PgPool, id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM oidc_configs WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to delete OIDC config: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound(format!("OIDC config {id} not found")));
        }
        Ok(())
    }

    pub async fn toggle_oidc(
        pool: &PgPool,
        id: Uuid,
        toggle: ToggleRequest,
    ) -> Result<OidcConfigResponse> {
        let row = sqlx::query_as::<_, OidcConfigRow>(
            r#"
            UPDATE oidc_configs SET is_enabled = $1, updated_at = NOW()
            WHERE id = $2
            RETURNING id, name, issuer_url, client_id, client_secret_encrypted,
                      scopes, attribute_mapping, is_enabled, auto_create_users,
                      pkce_enabled, map_groups_to_groups,
                      created_at, updated_at
            "#,
        )
        .bind(toggle.enabled)
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to toggle OIDC config: {e}")))?
        .ok_or_else(|| AppError::NotFound(format!("OIDC config {id} not found")))?;

        Ok(Self::oidc_row_to_response(row))
    }

    fn oidc_row_to_response(row: OidcConfigRow) -> OidcConfigResponse {
        OidcConfigResponse {
            id: row.id,
            name: row.name,
            issuer_url: row.issuer_url,
            client_id: row.client_id,
            has_secret: !row.client_secret_encrypted.is_empty(),
            scopes: row.scopes,
            attribute_mapping: row.attribute_mapping,
            is_enabled: row.is_enabled,
            auto_create_users: row.auto_create_users,
            pkce_enabled: row.pkce_enabled,
            map_groups_to_groups: row.map_groups_to_groups,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }

    // -----------------------------------------------------------------------
    // LDAP
    // -----------------------------------------------------------------------

    pub async fn list_ldap(pool: &PgPool) -> Result<Vec<LdapConfigResponse>> {
        let rows = sqlx::query_as::<_, LdapConfigRow>(
            r#"
            SELECT id, name, server_url, bind_dn, bind_password_encrypted,
                   user_base_dn, user_filter, group_base_dn, group_filter,
                   email_attribute, display_name_attribute, username_attribute,
                   groups_attribute, admin_group_dn, use_starttls,
                   is_enabled, priority, created_at, updated_at
            FROM ldap_configs
            ORDER BY priority, name
            "#,
        )
        .fetch_all(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to list LDAP configs: {e}")))?;

        Ok(rows.into_iter().map(Self::ldap_row_to_response).collect())
    }

    pub async fn get_ldap(pool: &PgPool, id: Uuid) -> Result<LdapConfigResponse> {
        let row = sqlx::query_as::<_, LdapConfigRow>(
            r#"
            SELECT id, name, server_url, bind_dn, bind_password_encrypted,
                   user_base_dn, user_filter, group_base_dn, group_filter,
                   email_attribute, display_name_attribute, username_attribute,
                   groups_attribute, admin_group_dn, use_starttls,
                   is_enabled, priority, created_at, updated_at
            FROM ldap_configs
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get LDAP config: {e}")))?
        .ok_or_else(|| AppError::NotFound(format!("LDAP config {id} not found")))?;

        Ok(Self::ldap_row_to_response(row))
    }

    pub async fn get_ldap_decrypted(
        pool: &PgPool,
        id: Uuid,
    ) -> Result<(LdapConfigRow, Option<String>)> {
        let row = sqlx::query_as::<_, LdapConfigRow>(
            r#"
            SELECT id, name, server_url, bind_dn, bind_password_encrypted,
                   user_base_dn, user_filter, group_base_dn, group_filter,
                   email_attribute, display_name_attribute, username_attribute,
                   groups_attribute, admin_group_dn, use_starttls,
                   is_enabled, priority, created_at, updated_at
            FROM ldap_configs
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get LDAP config: {e}")))?
        .ok_or_else(|| AppError::NotFound(format!("LDAP config {id} not found")))?;

        let password = row
            .bind_password_encrypted
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(|hex_str| {
                let encrypted_bytes = hex::decode(hex_str).map_err(|e| {
                    AppError::Internal(format!("Failed to decode bind password hex: {e}"))
                })?;
                decrypt_credentials(&encrypted_bytes, &encryption_key()).map_err(|e| {
                    AppError::Internal(format!("Failed to decrypt bind password: {e}"))
                })
            })
            .transpose()?;

        Ok((row, password))
    }

    pub async fn create_ldap(
        pool: &PgPool,
        req: CreateLdapConfigRequest,
    ) -> Result<LdapConfigResponse> {
        let id = Uuid::new_v4();

        let bind_password_hex: Option<String> = req.bind_password.as_ref().map(|pw| {
            let encrypted = encrypt_credentials(pw, &encryption_key());
            hex::encode(&encrypted)
        });

        let user_filter = req.user_filter.unwrap_or_else(|| "(uid={0})".to_string());
        let email_attribute = req.email_attribute.unwrap_or_else(|| "mail".to_string());
        let display_name_attribute = req
            .display_name_attribute
            .unwrap_or_else(|| "cn".to_string());
        let username_attribute = req.username_attribute.unwrap_or_else(|| "uid".to_string());
        let groups_attribute = req
            .groups_attribute
            .unwrap_or_else(|| "memberOf".to_string());
        let use_starttls = req.use_starttls.unwrap_or(false);
        let is_enabled = req.is_enabled.unwrap_or(true);
        let priority = req.priority.unwrap_or(0);

        let row = sqlx::query_as::<_, LdapConfigRow>(
            r#"
            INSERT INTO ldap_configs (id, name, server_url, bind_dn, bind_password_encrypted,
                                      user_base_dn, user_filter, group_base_dn, group_filter,
                                      email_attribute, display_name_attribute, username_attribute,
                                      groups_attribute, admin_group_dn, use_starttls,
                                      is_enabled, priority)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
            RETURNING id, name, server_url, bind_dn, bind_password_encrypted,
                      user_base_dn, user_filter, group_base_dn, group_filter,
                      email_attribute, display_name_attribute, username_attribute,
                      groups_attribute, admin_group_dn, use_starttls,
                      is_enabled, priority, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(&req.name)
        .bind(&req.server_url)
        .bind(&req.bind_dn)
        .bind(&bind_password_hex)
        .bind(&req.user_base_dn)
        .bind(&user_filter)
        .bind(&req.group_base_dn)
        .bind(&req.group_filter)
        .bind(&email_attribute)
        .bind(&display_name_attribute)
        .bind(&username_attribute)
        .bind(&groups_attribute)
        .bind(&req.admin_group_dn)
        .bind(use_starttls)
        .bind(is_enabled)
        .bind(priority)
        .fetch_one(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to create LDAP config: {e}")))?;

        Ok(Self::ldap_row_to_response(row))
    }

    pub async fn update_ldap(
        pool: &PgPool,
        id: Uuid,
        req: UpdateLdapConfigRequest,
    ) -> Result<LdapConfigResponse> {
        let existing = sqlx::query_as::<_, LdapConfigRow>(
            r#"
            SELECT id, name, server_url, bind_dn, bind_password_encrypted,
                   user_base_dn, user_filter, group_base_dn, group_filter,
                   email_attribute, display_name_attribute, username_attribute,
                   groups_attribute, admin_group_dn, use_starttls,
                   is_enabled, priority, created_at, updated_at
            FROM ldap_configs
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get LDAP config: {e}")))?
        .ok_or_else(|| AppError::NotFound(format!("LDAP config {id} not found")))?;

        let name = req.name.unwrap_or(existing.name);
        let server_url = req.server_url.unwrap_or(existing.server_url);
        let bind_dn = req.bind_dn.or(existing.bind_dn);
        let user_base_dn = req.user_base_dn.unwrap_or(existing.user_base_dn);
        let user_filter = req.user_filter.unwrap_or(existing.user_filter);
        let group_base_dn = req.group_base_dn.or(existing.group_base_dn);
        let group_filter = req.group_filter.or(existing.group_filter);
        let email_attribute = req.email_attribute.unwrap_or(existing.email_attribute);
        let display_name_attribute = req
            .display_name_attribute
            .unwrap_or(existing.display_name_attribute);
        let username_attribute = req
            .username_attribute
            .unwrap_or(existing.username_attribute);
        let groups_attribute = req.groups_attribute.unwrap_or(existing.groups_attribute);
        let admin_group_dn = req.admin_group_dn.or(existing.admin_group_dn);
        let use_starttls = req.use_starttls.unwrap_or(existing.use_starttls);
        let is_enabled = req.is_enabled.unwrap_or(existing.is_enabled);
        let priority = req.priority.unwrap_or(existing.priority);

        // Preserve existing encrypted password if not provided
        let bind_password_hex: Option<String> = if let Some(new_pw) = &req.bind_password {
            let encrypted = encrypt_credentials(new_pw, &encryption_key());
            Some(hex::encode(&encrypted))
        } else {
            existing.bind_password_encrypted
        };

        let row = sqlx::query_as::<_, LdapConfigRow>(
            r#"
            UPDATE ldap_configs
            SET name = $1, server_url = $2, bind_dn = $3, bind_password_encrypted = $4,
                user_base_dn = $5, user_filter = $6, group_base_dn = $7, group_filter = $8,
                email_attribute = $9, display_name_attribute = $10, username_attribute = $11,
                groups_attribute = $12, admin_group_dn = $13, use_starttls = $14,
                is_enabled = $15, priority = $16, updated_at = NOW()
            WHERE id = $17
            RETURNING id, name, server_url, bind_dn, bind_password_encrypted,
                      user_base_dn, user_filter, group_base_dn, group_filter,
                      email_attribute, display_name_attribute, username_attribute,
                      groups_attribute, admin_group_dn, use_starttls,
                      is_enabled, priority, created_at, updated_at
            "#,
        )
        .bind(&name)
        .bind(&server_url)
        .bind(&bind_dn)
        .bind(&bind_password_hex)
        .bind(&user_base_dn)
        .bind(&user_filter)
        .bind(&group_base_dn)
        .bind(&group_filter)
        .bind(&email_attribute)
        .bind(&display_name_attribute)
        .bind(&username_attribute)
        .bind(&groups_attribute)
        .bind(&admin_group_dn)
        .bind(use_starttls)
        .bind(is_enabled)
        .bind(priority)
        .bind(id)
        .fetch_one(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to update LDAP config: {e}")))?;

        Ok(Self::ldap_row_to_response(row))
    }

    pub async fn delete_ldap(pool: &PgPool, id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM ldap_configs WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to delete LDAP config: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound(format!("LDAP config {id} not found")));
        }
        Ok(())
    }

    pub async fn toggle_ldap(
        pool: &PgPool,
        id: Uuid,
        toggle: ToggleRequest,
    ) -> Result<LdapConfigResponse> {
        let row = sqlx::query_as::<_, LdapConfigRow>(
            r#"
            UPDATE ldap_configs SET is_enabled = $1, updated_at = NOW()
            WHERE id = $2
            RETURNING id, name, server_url, bind_dn, bind_password_encrypted,
                      user_base_dn, user_filter, group_base_dn, group_filter,
                      email_attribute, display_name_attribute, username_attribute,
                      groups_attribute, admin_group_dn, use_starttls,
                      is_enabled, priority, created_at, updated_at
            "#,
        )
        .bind(toggle.enabled)
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to toggle LDAP config: {e}")))?
        .ok_or_else(|| AppError::NotFound(format!("LDAP config {id} not found")))?;

        Ok(Self::ldap_row_to_response(row))
    }

    /// Attempt a TCP connection to the LDAP server to verify reachability.
    pub async fn test_ldap_connection(pool: &PgPool, id: Uuid) -> Result<LdapTestResult> {
        let row = sqlx::query_as::<_, LdapConfigRow>(
            r#"
            SELECT id, name, server_url, bind_dn, bind_password_encrypted,
                   user_base_dn, user_filter, group_base_dn, group_filter,
                   email_attribute, display_name_attribute, username_attribute,
                   groups_attribute, admin_group_dn, use_starttls,
                   is_enabled, priority, created_at, updated_at
            FROM ldap_configs
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get LDAP config: {e}")))?
        .ok_or_else(|| AppError::NotFound(format!("LDAP config {id} not found")))?;

        // Parse host and port from server_url (e.g. ldap://host:389 or ldaps://host:636)
        let url = &row.server_url;
        let (host, port) = Self::parse_ldap_url(url)?;

        Self::probe_ldap_endpoint(&host, port).await
    }

    /// Resolve, SSRF-vet, and probe a TCP connection to `host:port`.
    ///
    /// The connectivity test is the only outbound surface that opens a raw
    /// socket to an operator-supplied target, so it re-checks the resolved
    /// IP against the SSRF allowlist before connecting (covering configs
    /// stored before write-time validation and the DNS-resolution oracle),
    /// connects to the vetted `SocketAddr` directly, and returns only a
    /// generic outcome — never the raw OS error or a refused-vs-filtered
    /// timing distinction — so it cannot be used as an internal port-scan
    /// oracle. Details are logged server-side via `tracing`.
    async fn probe_ldap_endpoint(host: &str, port: u16) -> Result<LdapTestResult> {
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(5);

        // Resolve the host. Honor the operator escape hatches via the
        // Upstream context (UPSTREAM_ALLOW_PRIVATE_IPS / AK_SSRF_ALLOW_PRIVATE_CIDRS).
        let resolved: Vec<std::net::SocketAddr> = match tokio::net::lookup_host((host, port)).await
        {
            Ok(addrs) => addrs.collect(),
            Err(e) => {
                tracing::warn!(target: "security", error = %e, "LDAP test: host resolution failed");
                return Ok(LdapTestResult {
                    success: false,
                    message: "Connection failed".to_string(),
                    response_time_ms: start.elapsed().as_millis() as u64,
                });
            }
        };

        // Reject if every resolved address is an internal/private target;
        // otherwise pin the first vetted address (do not re-resolve, to
        // avoid a TOCTOU / DNS-rebind window).
        let vetted = resolved
            .into_iter()
            .find(|sa| !crate::api::validation::is_blocked_resolved_ip(sa.ip()));
        let Some(vetted) = vetted else {
            return Err(AppError::Validation(
                "LDAP server URL is not allowed (private/internal network)".to_string(),
            ));
        };

        let result = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&vetted)).await;
        let elapsed = start.elapsed().as_millis() as u64;

        let (success, message) = match result {
            Ok(Ok(_)) => (true, format!("Successfully connected to {host}:{port}")),
            Ok(Err(e)) => {
                tracing::warn!(target: "security", error = %e, "LDAP test: connection failed");
                (false, "Connection failed".to_string())
            }
            Err(_) => (false, "Connection timed out".to_string()),
        };

        Ok(LdapTestResult {
            success,
            message,
            response_time_ms: elapsed,
        })
    }

    fn parse_ldap_url(url: &str) -> Result<(String, u16)> {
        // Handle ldap:// and ldaps:// schemes
        let (remainder, default_port) = if let Some(rest) = url.strip_prefix("ldaps://") {
            (rest, 636u16)
        } else if let Some(rest) = url.strip_prefix("ldap://") {
            (rest, 389u16)
        } else {
            // Assume plain host:port
            (url, 389u16)
        };

        // Strip trailing path if any
        let authority = remainder.split('/').next().unwrap_or(remainder);

        if let Some((host, port_str)) = authority.rsplit_once(':') {
            let port: u16 = port_str
                .parse()
                .map_err(|_| AppError::Validation(format!("Invalid port in LDAP URL: {url}")))?;
            Ok((host.to_string(), port))
        } else {
            Ok((authority.to_string(), default_port))
        }
    }

    fn ldap_row_to_response(row: LdapConfigRow) -> LdapConfigResponse {
        LdapConfigResponse {
            id: row.id,
            name: row.name,
            server_url: row.server_url,
            bind_dn: row.bind_dn,
            has_bind_password: row.bind_password_encrypted.is_some_and(|p| !p.is_empty()),
            user_base_dn: row.user_base_dn,
            user_filter: row.user_filter,
            group_base_dn: row.group_base_dn,
            group_filter: row.group_filter,
            email_attribute: row.email_attribute,
            display_name_attribute: row.display_name_attribute,
            username_attribute: row.username_attribute,
            groups_attribute: row.groups_attribute,
            admin_group_dn: row.admin_group_dn,
            use_starttls: row.use_starttls,
            is_enabled: row.is_enabled,
            priority: row.priority,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }

    // -----------------------------------------------------------------------
    // SAML
    // -----------------------------------------------------------------------

    pub async fn list_saml(pool: &PgPool) -> Result<Vec<SamlConfigResponse>> {
        let rows = sqlx::query_as::<_, SamlConfigRow>(
            r#"
            SELECT id, name, entity_id, sso_url, slo_url, certificate,
                   name_id_format, attribute_mapping, sp_entity_id,
                   sign_requests, require_signed_assertions, admin_group,
                   is_enabled, created_at, updated_at
            FROM saml_configs
            ORDER BY name
            "#,
        )
        .fetch_all(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to list SAML configs: {e}")))?;

        Ok(rows.into_iter().map(Self::saml_row_to_response).collect())
    }

    pub async fn get_saml(pool: &PgPool, id: Uuid) -> Result<SamlConfigResponse> {
        let row = sqlx::query_as::<_, SamlConfigRow>(
            r#"
            SELECT id, name, entity_id, sso_url, slo_url, certificate,
                   name_id_format, attribute_mapping, sp_entity_id,
                   sign_requests, require_signed_assertions, admin_group,
                   is_enabled, created_at, updated_at
            FROM saml_configs
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get SAML config: {e}")))?
        .ok_or_else(|| AppError::NotFound(format!("SAML config {id} not found")))?;

        Ok(Self::saml_row_to_response(row))
    }

    pub async fn get_saml_decrypted(pool: &PgPool, id: Uuid) -> Result<SamlConfigRow> {
        sqlx::query_as::<_, SamlConfigRow>(
            r#"
            SELECT id, name, entity_id, sso_url, slo_url, certificate,
                   name_id_format, attribute_mapping, sp_entity_id,
                   sign_requests, require_signed_assertions, admin_group,
                   is_enabled, created_at, updated_at
            FROM saml_configs
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get SAML config: {e}")))?
        .ok_or_else(|| AppError::NotFound(format!("SAML config {id} not found")))
    }

    pub async fn create_saml(
        pool: &PgPool,
        req: CreateSamlConfigRequest,
    ) -> Result<SamlConfigResponse> {
        let id = Uuid::new_v4();
        let name_id_format = req.name_id_format.unwrap_or_else(|| {
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string()
        });
        let attribute_mapping = req.attribute_mapping.unwrap_or(serde_json::json!({}));
        let sp_entity_id = req
            .sp_entity_id
            .unwrap_or_else(|| "artifact-keeper".to_string());
        let sign_requests = req.sign_requests.unwrap_or(false);
        let require_signed_assertions = req.require_signed_assertions.unwrap_or(true);
        let is_enabled = req.is_enabled.unwrap_or(true);

        let row = sqlx::query_as::<_, SamlConfigRow>(
            r#"
            INSERT INTO saml_configs (id, name, entity_id, sso_url, slo_url, certificate,
                                      name_id_format, attribute_mapping, sp_entity_id,
                                      sign_requests, require_signed_assertions, admin_group,
                                      is_enabled)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING id, name, entity_id, sso_url, slo_url, certificate,
                      name_id_format, attribute_mapping, sp_entity_id,
                      sign_requests, require_signed_assertions, admin_group,
                      is_enabled, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(&req.name)
        .bind(&req.entity_id)
        .bind(&req.sso_url)
        .bind(&req.slo_url)
        .bind(&req.certificate)
        .bind(&name_id_format)
        .bind(&attribute_mapping)
        .bind(&sp_entity_id)
        .bind(sign_requests)
        .bind(require_signed_assertions)
        .bind(&req.admin_group)
        .bind(is_enabled)
        .fetch_one(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to create SAML config: {e}")))?;

        Ok(Self::saml_row_to_response(row))
    }

    pub async fn update_saml(
        pool: &PgPool,
        id: Uuid,
        req: UpdateSamlConfigRequest,
    ) -> Result<SamlConfigResponse> {
        let existing = sqlx::query_as::<_, SamlConfigRow>(
            r#"
            SELECT id, name, entity_id, sso_url, slo_url, certificate,
                   name_id_format, attribute_mapping, sp_entity_id,
                   sign_requests, require_signed_assertions, admin_group,
                   is_enabled, created_at, updated_at
            FROM saml_configs
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get SAML config: {e}")))?
        .ok_or_else(|| AppError::NotFound(format!("SAML config {id} not found")))?;

        let name = req.name.unwrap_or(existing.name);
        let entity_id = req.entity_id.unwrap_or(existing.entity_id);
        let sso_url = req.sso_url.unwrap_or(existing.sso_url);
        let slo_url = req.slo_url.or(existing.slo_url);
        let certificate = req.certificate.unwrap_or(existing.certificate);
        let name_id_format = req.name_id_format.unwrap_or(existing.name_id_format);
        let attribute_mapping = req.attribute_mapping.unwrap_or(existing.attribute_mapping);
        let sp_entity_id = req.sp_entity_id.unwrap_or(existing.sp_entity_id);
        let sign_requests = req.sign_requests.unwrap_or(existing.sign_requests);
        let require_signed_assertions = req
            .require_signed_assertions
            .unwrap_or(existing.require_signed_assertions);
        let admin_group = req.admin_group.or(existing.admin_group);
        let is_enabled = req.is_enabled.unwrap_or(existing.is_enabled);

        let row = sqlx::query_as::<_, SamlConfigRow>(
            r#"
            UPDATE saml_configs
            SET name = $1, entity_id = $2, sso_url = $3, slo_url = $4,
                certificate = $5, name_id_format = $6, attribute_mapping = $7,
                sp_entity_id = $8, sign_requests = $9, require_signed_assertions = $10,
                admin_group = $11, is_enabled = $12, updated_at = NOW()
            WHERE id = $13
            RETURNING id, name, entity_id, sso_url, slo_url, certificate,
                      name_id_format, attribute_mapping, sp_entity_id,
                      sign_requests, require_signed_assertions, admin_group,
                      is_enabled, created_at, updated_at
            "#,
        )
        .bind(&name)
        .bind(&entity_id)
        .bind(&sso_url)
        .bind(&slo_url)
        .bind(&certificate)
        .bind(&name_id_format)
        .bind(&attribute_mapping)
        .bind(&sp_entity_id)
        .bind(sign_requests)
        .bind(require_signed_assertions)
        .bind(&admin_group)
        .bind(is_enabled)
        .bind(id)
        .fetch_one(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to update SAML config: {e}")))?;

        Ok(Self::saml_row_to_response(row))
    }

    pub async fn delete_saml(pool: &PgPool, id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM saml_configs WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to delete SAML config: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound(format!("SAML config {id} not found")));
        }
        Ok(())
    }

    pub async fn toggle_saml(
        pool: &PgPool,
        id: Uuid,
        toggle: ToggleRequest,
    ) -> Result<SamlConfigResponse> {
        let row = sqlx::query_as::<_, SamlConfigRow>(
            r#"
            UPDATE saml_configs SET is_enabled = $1, updated_at = NOW()
            WHERE id = $2
            RETURNING id, name, entity_id, sso_url, slo_url, certificate,
                      name_id_format, attribute_mapping, sp_entity_id,
                      sign_requests, require_signed_assertions, admin_group,
                      is_enabled, created_at, updated_at
            "#,
        )
        .bind(toggle.enabled)
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to toggle SAML config: {e}")))?
        .ok_or_else(|| AppError::NotFound(format!("SAML config {id} not found")))?;

        Ok(Self::saml_row_to_response(row))
    }

    fn saml_row_to_response(row: SamlConfigRow) -> SamlConfigResponse {
        SamlConfigResponse {
            id: row.id,
            name: row.name,
            entity_id: row.entity_id,
            sso_url: row.sso_url,
            slo_url: row.slo_url,
            has_certificate: !row.certificate.is_empty(),
            name_id_format: row.name_id_format,
            attribute_mapping: row.attribute_mapping,
            sp_entity_id: row.sp_entity_id,
            sign_requests: row.sign_requests,
            require_signed_assertions: row.require_signed_assertions,
            admin_group: row.admin_group,
            is_enabled: row.is_enabled,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }

    // -----------------------------------------------------------------------
    // Cross-provider: list all enabled SSO providers
    // -----------------------------------------------------------------------

    pub async fn list_enabled_providers(pool: &PgPool) -> Result<Vec<SsoProviderInfo>> {
        let mut providers: Vec<SsoProviderInfo> = Vec::new();

        // OIDC providers (only fetch id and name)
        let oidc_rows = sqlx::query_as::<_, (Uuid, String)>(
            "SELECT id, name FROM oidc_configs WHERE is_enabled = true ORDER BY name",
        )
        .fetch_all(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to list OIDC providers: {e}")))?;

        for (id, name) in oidc_rows {
            providers.push(SsoProviderInfo::new(id, name, "oidc"));
        }

        // LDAP providers (only fetch id and name)
        let ldap_rows = sqlx::query_as::<_, (Uuid, String)>(
            "SELECT id, name FROM ldap_configs WHERE is_enabled = true ORDER BY priority, name",
        )
        .fetch_all(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to list LDAP providers: {e}")))?;

        for (id, name) in ldap_rows {
            providers.push(SsoProviderInfo::new(id, name, "ldap"));
        }

        // SAML providers (only fetch id and name)
        let saml_rows = sqlx::query_as::<_, (Uuid, String)>(
            "SELECT id, name FROM saml_configs WHERE is_enabled = true ORDER BY name",
        )
        .fetch_all(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to list SAML providers: {e}")))?;

        for (id, name) in saml_rows {
            providers.push(SsoProviderInfo::new(id, name, "saml"));
        }

        Ok(providers)
    }

    // -----------------------------------------------------------------------
    // SSO Sessions (CSRF state for OAuth / SAML flows)
    // -----------------------------------------------------------------------

    pub async fn create_sso_session(
        pool: &PgPool,
        provider_type: &str,
        provider_id: Uuid,
    ) -> Result<SsoSession> {
        Self::create_sso_session_with_pkce(pool, provider_type, provider_id, None).await
    }

    /// Create an SSO session, optionally storing a PKCE code_verifier.
    /// The verifier is read back during the callback so it can be sent on
    /// the token-exchange request (RFC 7636).
    pub async fn create_sso_session_with_pkce(
        pool: &PgPool,
        provider_type: &str,
        provider_id: Uuid,
        pkce_code_verifier: Option<String>,
    ) -> Result<SsoSession> {
        let id = Uuid::new_v4();
        let state = Uuid::new_v4().to_string();
        let nonce = Uuid::new_v4().to_string();

        let session = sqlx::query_as::<_, SsoSession>(
            r#"
            INSERT INTO sso_sessions (id, provider_type, provider_id, state, nonce, pkce_code_verifier)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id, provider_type, provider_id, state, nonce, pkce_code_verifier,
                      created_at, expires_at
            "#,
        )
        .bind(id)
        .bind(provider_type)
        .bind(provider_id)
        .bind(&state)
        .bind(&nonce)
        .bind(pkce_code_verifier.as_deref())
        .fetch_one(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to create SSO session: {e}")))?;

        Ok(session)
    }

    /// Validate an SSO session state: checks existence, deletes the row, and
    /// verifies it has not expired. Returns the session if valid.
    pub async fn validate_sso_session(pool: &PgPool, state: &str) -> Result<SsoSession> {
        let session = sqlx::query_as::<_, SsoSession>(
            r#"
            DELETE FROM sso_sessions
            WHERE state = $1
            RETURNING id, provider_type, provider_id, state, nonce, pkce_code_verifier,
                      created_at, expires_at
            "#,
        )
        .bind(state)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to validate SSO session: {e}")))?
        .ok_or_else(|| AppError::Authentication("Invalid or expired SSO state".to_string()))?;

        if session.expires_at < Utc::now() {
            return Err(AppError::Authentication(
                "SSO session has expired".to_string(),
            ));
        }

        Ok(session)
    }

    /// Remove all expired SSO sessions. Intended to be called periodically.
    pub async fn cleanup_expired_sessions(pool: &PgPool) -> Result<u64> {
        let result = sqlx::query("DELETE FROM sso_sessions WHERE expires_at < NOW()")
            .execute(pool)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to cleanup SSO sessions: {e}")))?;

        Ok(result.rows_affected())
    }

    // -----------------------------------------------------------------------
    // SSO Exchange Codes (authorization code exchange pattern)
    // -----------------------------------------------------------------------

    /// Create a short-lived, single-use exchange code that wraps the given
    /// access and refresh tokens. The frontend will POST this code back to
    /// exchange it for the real tokens over a secure channel instead of
    /// receiving raw JWTs in URL query parameters.
    pub async fn create_exchange_code(
        pool: &PgPool,
        access_token: &str,
        refresh_token: &str,
    ) -> Result<String> {
        let code = format!(
            "{}{}",
            Uuid::new_v4().to_string().replace('-', ""),
            Uuid::new_v4().to_string().replace('-', ""),
        );

        sqlx::query(
            r#"
            INSERT INTO sso_exchange_codes (code, access_token, refresh_token)
            VALUES ($1, $2, $3)
            "#,
        )
        .bind(&code)
        .bind(access_token)
        .bind(refresh_token)
        .execute(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to create exchange code: {e}")))?;

        Ok(code)
    }

    /// Consume a single-use exchange code and return the associated tokens.
    /// The code is deleted atomically so it cannot be replayed.
    pub async fn exchange_code(pool: &PgPool, code: &str) -> Result<(String, String)> {
        let row = sqlx::query_as::<_, (String, String)>(
            r#"
            DELETE FROM sso_exchange_codes
            WHERE code = $1 AND expires_at > NOW()
            RETURNING access_token, refresh_token
            "#,
        )
        .bind(code)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to exchange code: {e}")))?
        .ok_or_else(|| AppError::Authentication("Invalid or expired exchange code".to_string()))?;

        Ok(row)
    }

    /// Remove all expired exchange codes. Intended to be called periodically.
    pub async fn cleanup_expired_exchange_codes(pool: &PgPool) -> Result<u64> {
        let result = sqlx::query("DELETE FROM sso_exchange_codes WHERE expires_at < NOW()")
            .execute(pool)
            .await
            .map_err(|e| AppError::Internal(format!("Failed to cleanup exchange codes: {e}")))?;

        Ok(result.rows_affected())
    }

    // -----------------------------------------------------------------------
    // Download Tickets (short-lived, single-use tokens for downloads/streams)
    // -----------------------------------------------------------------------

    /// Create a short-lived download ticket for a user.
    /// Tickets expire after 30 seconds and are single-use.
    pub async fn create_download_ticket(
        pool: &PgPool,
        user_id: Uuid,
        purpose: &str,
        resource_path: Option<&str>,
    ) -> Result<String> {
        let ticket = format!(
            "{}{}",
            Uuid::new_v4().to_string().replace('-', ""),
            Uuid::new_v4().to_string().replace('-', ""),
        );

        sqlx::query(
            r#"INSERT INTO download_tickets (ticket, user_id, purpose, resource_path)
               VALUES ($1, $2, $3, $4)"#,
        )
        .bind(&ticket)
        .bind(user_id)
        .bind(purpose)
        .bind(resource_path)
        .execute(pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(ticket)
    }

    /// Validate and consume a download ticket (single-use).
    /// Returns (user_id, purpose, resource_path) if valid.
    pub async fn validate_download_ticket(
        pool: &PgPool,
        ticket: &str,
    ) -> Result<(Uuid, String, Option<String>)> {
        let row: (Uuid, String, Option<String>) = sqlx::query_as(
            r#"DELETE FROM download_tickets
               WHERE ticket = $1 AND expires_at > NOW()
               RETURNING user_id, purpose, resource_path"#,
        )
        .bind(ticket)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::Authentication("Invalid or expired download ticket".into()))?;

        Ok(row)
    }

    /// Clean up expired download tickets. Intended to be called periodically.
    pub async fn cleanup_expired_download_tickets(pool: &PgPool) -> Result<u64> {
        let result = sqlx::query("DELETE FROM download_tickets WHERE expires_at < NOW()")
            .execute(pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(result.rows_affected())
    }
}

// ---------------------------------------------------------------------------
// Env-managed provider reconciliation (issue #1656)
// ---------------------------------------------------------------------------

/// Outcome of reconciling an env-managed provider against the DB on boot.
#[derive(Debug, PartialEq, Eq)]
pub enum ReconcileAction {
    Create,
    Update(Uuid),
}

/// Select the env-managed provider by name; UI-created providers with other
/// names are ignored.
pub fn plan_provider_reconcile(desired_name: &str, existing: &[(Uuid, String)]) -> ReconcileAction {
    match existing.iter().find(|(_, name)| name == desired_name) {
        Some((id, _)) => ReconcileAction::Update(*id),
        None => ReconcileAction::Create,
    }
}

impl From<CreateOidcConfigRequest> for UpdateOidcConfigRequest {
    fn from(c: CreateOidcConfigRequest) -> Self {
        UpdateOidcConfigRequest {
            name: Some(c.name),
            issuer_url: Some(c.issuer_url),
            client_id: Some(c.client_id),
            client_secret: Some(c.client_secret),
            scopes: c.scopes,
            attribute_mapping: c.attribute_mapping,
            // Env is definitive: replace the whole mapping so a key removed
            // from the environment is cleared from the stored config.
            attribute_mapping_replace: Some(true),
            is_enabled: c.is_enabled,
            auto_create_users: c.auto_create_users,
            pkce_enabled: c.pkce_enabled,
            map_groups_to_groups: c.map_groups_to_groups,
        }
    }
}

impl From<CreateLdapConfigRequest> for UpdateLdapConfigRequest {
    fn from(c: CreateLdapConfigRequest) -> Self {
        UpdateLdapConfigRequest {
            name: Some(c.name),
            server_url: Some(c.server_url),
            bind_dn: c.bind_dn,
            bind_password: c.bind_password,
            user_base_dn: Some(c.user_base_dn),
            user_filter: c.user_filter,
            group_base_dn: c.group_base_dn,
            group_filter: c.group_filter,
            email_attribute: c.email_attribute,
            display_name_attribute: c.display_name_attribute,
            username_attribute: c.username_attribute,
            groups_attribute: c.groups_attribute,
            admin_group_dn: c.admin_group_dn,
            use_starttls: c.use_starttls,
            is_enabled: c.is_enabled,
            priority: c.priority,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use chrono::Utc;
    #[allow(unused_imports)]
    use serde_json::json;
    #[allow(unused_imports)]
    use uuid::Uuid;

    // -----------------------------------------------------------------------
    // validate_oidc_issuer() tests (SSRF guard at the config trust boundary)
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_oidc_issuer_rejects_metadata_and_internal() {
        // Cloud metadata, loopback, and a private-IP host must all be
        // rejected by the shared outbound-URL SSRF guard (IP literals are
        // classified without DNS, so these are deterministic).
        assert!(validate_oidc_issuer("http://169.254.169.254/latest/meta-data").is_err());
        assert!(validate_oidc_issuer("http://127.0.0.1:8080/api/v1/admin/metrics").is_err());
        assert!(validate_oidc_issuer("http://172.19.0.1:9999/oidc").is_err());
        // `localhost` is an internal service name in BLOCKED_HOSTS, so it is
        // rejected regardless of DNS resolution on the test host.
        assert!(validate_oidc_issuer("http://localhost:5432/").is_err());
    }

    #[test]
    fn test_validate_oidc_issuer_accepts_public_idp() {
        assert!(validate_oidc_issuer("https://idp.example.com").is_ok());
    }

    // -----------------------------------------------------------------------
    // encryption_key() tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_encryption_key_panics_when_unset() {
        // When neither env var is set, the function should panic with a clear
        // message rather than falling back to a hardcoded key. We can only
        // assert this when both env vars are absent; in CI (where JWT_SECRET
        // is set so DB-backed SSO tests can encrypt credentials), the test
        // skips this branch.
        if std::env::var("SSO_ENCRYPTION_KEY").is_ok() || std::env::var("JWT_SECRET").is_ok() {
            return;
        }
        let result = std::panic::catch_unwind(encryption_key);
        let err = result.expect_err("encryption_key must panic when both env vars are unset");
        let msg = err
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| err.downcast_ref::<&str>().copied())
            .unwrap_or("");
        assert!(
            msg.contains("Neither SSO_ENCRYPTION_KEY nor JWT_SECRET is set"),
            "unexpected panic message: {msg}"
        );
    }

    #[test]
    fn test_encryption_key_uses_jwt_secret_fallback() {
        // When JWT_SECRET is set, encryption_key() should return it as fallback
        // for SSO_ENCRYPTION_KEY. We just verify it returns a non-empty string.
        // (In CI, JWT_SECRET is typically set.)
        if std::env::var("JWT_SECRET").is_ok() || std::env::var("SSO_ENCRYPTION_KEY").is_ok() {
            let key = encryption_key();
            assert!(!key.is_empty());
        }
    }

    // -----------------------------------------------------------------------
    // oidc_row_to_response tests
    // -----------------------------------------------------------------------

    fn make_oidc_row(secret_encrypted: &str) -> OidcConfigRow {
        let now = Utc::now();
        OidcConfigRow {
            id: Uuid::new_v4(),
            name: "Test OIDC".to_string(),
            issuer_url: "https://issuer.example.com".to_string(),
            client_id: "client-id-123".to_string(),
            client_secret_encrypted: secret_encrypted.to_string(),
            scopes: vec!["openid".to_string(), "profile".to_string()],
            attribute_mapping: json!({"email": "email"}),
            is_enabled: true,
            auto_create_users: false,
            pkce_enabled: true,
            map_groups_to_groups: false,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn test_oidc_row_to_response_has_secret_when_nonempty() {
        let row = make_oidc_row("encrypted_data_hex");
        let resp = AuthConfigService::oidc_row_to_response(row.clone());

        assert_eq!(resp.id, row.id);
        assert_eq!(resp.name, "Test OIDC");
        assert_eq!(resp.issuer_url, "https://issuer.example.com");
        assert_eq!(resp.client_id, "client-id-123");
        assert!(resp.has_secret);
        assert_eq!(resp.scopes, vec!["openid", "profile"]);
        assert_eq!(resp.attribute_mapping, json!({"email": "email"}));
        assert!(resp.is_enabled);
        assert!(!resp.auto_create_users);
    }

    #[test]
    fn test_oidc_row_to_response_no_secret_when_empty() {
        let row = make_oidc_row("");
        let resp = AuthConfigService::oidc_row_to_response(row);
        assert!(!resp.has_secret);
    }

    // -----------------------------------------------------------------------
    // ldap_row_to_response tests
    // -----------------------------------------------------------------------

    fn make_ldap_row(bind_password_encrypted: Option<String>) -> LdapConfigRow {
        let now = Utc::now();
        LdapConfigRow {
            id: Uuid::new_v4(),
            name: "Test LDAP".to_string(),
            server_url: "ldap://ldap.example.com:389".to_string(),
            bind_dn: Some("cn=admin,dc=example,dc=com".to_string()),
            bind_password_encrypted,
            user_base_dn: "ou=users,dc=example,dc=com".to_string(),
            user_filter: "(uid={0})".to_string(),
            group_base_dn: Some("ou=groups,dc=example,dc=com".to_string()),
            group_filter: Some("(member={0})".to_string()),
            email_attribute: "mail".to_string(),
            display_name_attribute: "cn".to_string(),
            username_attribute: "uid".to_string(),
            groups_attribute: "memberOf".to_string(),
            admin_group_dn: Some("cn=admins,ou=groups,dc=example,dc=com".to_string()),
            use_starttls: false,
            is_enabled: true,
            priority: 0,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn test_ldap_row_to_response_has_password() {
        let row = make_ldap_row(Some("encrypted_password".to_string()));
        let resp = AuthConfigService::ldap_row_to_response(row.clone());

        assert_eq!(resp.id, row.id);
        assert_eq!(resp.name, "Test LDAP");
        assert!(resp.has_bind_password);
        assert_eq!(resp.bind_dn, Some("cn=admin,dc=example,dc=com".to_string()));
        assert_eq!(resp.user_base_dn, "ou=users,dc=example,dc=com");
        assert_eq!(resp.user_filter, "(uid={0})");
        assert_eq!(resp.email_attribute, "mail");
        assert_eq!(resp.display_name_attribute, "cn");
        assert_eq!(resp.username_attribute, "uid");
        assert_eq!(resp.groups_attribute, "memberOf");
        assert_eq!(resp.priority, 0);
    }

    #[test]
    fn test_ldap_row_to_response_no_password_when_none() {
        let row = make_ldap_row(None);
        let resp = AuthConfigService::ldap_row_to_response(row);
        assert!(!resp.has_bind_password);
    }

    #[test]
    fn test_ldap_row_to_response_no_password_when_empty() {
        let row = make_ldap_row(Some("".to_string()));
        let resp = AuthConfigService::ldap_row_to_response(row);
        assert!(!resp.has_bind_password);
    }

    // -----------------------------------------------------------------------
    // saml_row_to_response tests
    // -----------------------------------------------------------------------

    fn make_saml_row(certificate: &str) -> SamlConfigRow {
        let now = Utc::now();
        SamlConfigRow {
            id: Uuid::new_v4(),
            name: "Test SAML".to_string(),
            entity_id: "https://idp.example.com/entity".to_string(),
            sso_url: "https://idp.example.com/sso".to_string(),
            slo_url: Some("https://idp.example.com/slo".to_string()),
            certificate: certificate.to_string(),
            name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string(),
            attribute_mapping: json!({"email": "email"}),
            sp_entity_id: "artifact-keeper".to_string(),
            sign_requests: false,
            require_signed_assertions: true,
            admin_group: Some("admins".to_string()),
            is_enabled: true,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn test_saml_row_to_response_has_certificate_when_nonempty() {
        let row = make_saml_row("MIIC...");
        let resp = AuthConfigService::saml_row_to_response(row.clone());

        assert_eq!(resp.id, row.id);
        assert_eq!(resp.name, "Test SAML");
        assert_eq!(resp.entity_id, "https://idp.example.com/entity");
        assert_eq!(resp.sso_url, "https://idp.example.com/sso");
        assert_eq!(
            resp.slo_url,
            Some("https://idp.example.com/slo".to_string())
        );
        assert!(resp.has_certificate);
        assert_eq!(
            resp.name_id_format,
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        );
        assert_eq!(resp.sp_entity_id, "artifact-keeper");
        assert!(!resp.sign_requests);
        assert!(resp.require_signed_assertions);
        assert_eq!(resp.admin_group, Some("admins".to_string()));
        assert!(resp.is_enabled);
    }

    #[test]
    fn test_saml_row_to_response_no_certificate_when_empty() {
        let row = make_saml_row("");
        let resp = AuthConfigService::saml_row_to_response(row);
        assert!(!resp.has_certificate);
    }

    // -----------------------------------------------------------------------
    // parse_ldap_url tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_ldap_url_ldap_with_port() {
        let (host, port) = AuthConfigService::parse_ldap_url("ldap://myhost:1389").unwrap();
        assert_eq!(host, "myhost");
        assert_eq!(port, 1389);
    }

    #[test]
    fn test_parse_ldap_url_ldap_default_port() {
        let (host, port) = AuthConfigService::parse_ldap_url("ldap://myhost").unwrap();
        assert_eq!(host, "myhost");
        assert_eq!(port, 389);
    }

    #[test]
    fn test_parse_ldap_url_ldaps_with_port() {
        let (host, port) = AuthConfigService::parse_ldap_url("ldaps://secure-host:1636").unwrap();
        assert_eq!(host, "secure-host");
        assert_eq!(port, 1636);
    }

    #[test]
    fn test_parse_ldap_url_ldaps_default_port() {
        let (host, port) = AuthConfigService::parse_ldap_url("ldaps://secure-host").unwrap();
        assert_eq!(host, "secure-host");
        assert_eq!(port, 636);
    }

    #[test]
    fn test_parse_ldap_url_plain_host_port() {
        let (host, port) = AuthConfigService::parse_ldap_url("plainhost:10389").unwrap();
        assert_eq!(host, "plainhost");
        assert_eq!(port, 10389);
    }

    #[test]
    fn test_parse_ldap_url_plain_host_default_port() {
        let (host, port) = AuthConfigService::parse_ldap_url("plainhost").unwrap();
        assert_eq!(host, "plainhost");
        assert_eq!(port, 389);
    }

    #[test]
    fn test_parse_ldap_url_with_trailing_path() {
        let (host, port) =
            AuthConfigService::parse_ldap_url("ldap://myhost:389/dc=example").unwrap();
        assert_eq!(host, "myhost");
        assert_eq!(port, 389);
    }

    #[test]
    fn test_parse_ldap_url_invalid_port() {
        let result = AuthConfigService::parse_ldap_url("ldap://myhost:notaport");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // probe_ldap_endpoint: SSRF-vets the resolved IP before connecting and
    // returns only a generic outcome (no raw OS error / port-scan oracle).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_probe_ldap_rejects_loopback_before_connect() {
        // Loopback is hard-blocked regardless of env, so this is stable even
        // if a parallel test toggles the private-IP allowlist env vars.
        let err = AuthConfigService::probe_ldap_endpoint("127.0.0.1", 9999)
            .await
            .expect_err("loopback must be rejected before any TCP connect");
        assert!(
            err.to_string().contains("private/internal network"),
            "expected a private/internal rejection, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_probe_ldap_rejects_metadata_ip_before_connect() {
        let err = AuthConfigService::probe_ldap_endpoint("169.254.169.254", 80)
            .await
            .expect_err("metadata IP must be rejected before connect");
        assert!(err.to_string().contains("private/internal network"));
    }

    #[tokio::test]
    async fn test_probe_ldap_generic_message_on_resolution_failure() {
        // `.invalid` never resolves (RFC 6761), so this is deterministic and
        // offline. The failure message must be generic — no OS error echoed.
        let res = AuthConfigService::probe_ldap_endpoint("nonexistent.invalid", 389)
            .await
            .expect("resolution failure returns a generic result, not an error");
        assert!(!res.success);
        assert_eq!(res.message, "Connection failed");
        assert!(
            !res.message.contains("os error"),
            "failure message must not leak the OS error string"
        );
    }

    // -----------------------------------------------------------------------
    // Serialization / deserialization tests for request/response structs
    // -----------------------------------------------------------------------

    #[test]
    fn test_oidc_config_response_serialization() {
        let now = Utc::now();
        let resp = OidcConfigResponse {
            id: Uuid::nil(),
            name: "Test".to_string(),
            issuer_url: "https://issuer.example.com".to_string(),
            client_id: "client-123".to_string(),
            has_secret: true,
            scopes: vec!["openid".to_string()],
            attribute_mapping: json!({}),
            is_enabled: true,
            auto_create_users: false,
            pkce_enabled: true,
            map_groups_to_groups: false,
            created_at: now,
            updated_at: now,
        };
        let json_str = serde_json::to_string(&resp).unwrap();
        assert!(json_str.contains("\"has_secret\":true"));
        assert!(json_str.contains("\"name\":\"Test\""));
        assert!(json_str.contains("\"pkce_enabled\":true"));
    }

    #[test]
    fn test_create_oidc_config_request_deserialization() {
        let json_str = r#"{
            "name": "My OIDC",
            "issuer_url": "https://issuer.example.com",
            "client_id": "id",
            "client_secret": "secret"
        }"#;
        let req: CreateOidcConfigRequest = serde_json::from_str(json_str).unwrap();
        assert_eq!(req.name, "My OIDC");
        assert!(req.scopes.is_none());
        assert!(req.attribute_mapping.is_none());
        assert!(req.is_enabled.is_none());
        assert!(req.auto_create_users.is_none());
    }

    #[test]
    fn test_create_oidc_config_request_with_all_fields() {
        let json_str = r#"{
            "name": "My OIDC",
            "issuer_url": "https://issuer.example.com",
            "client_id": "id",
            "client_secret": "secret",
            "scopes": ["openid", "profile"],
            "attribute_mapping": {"email": "mail"},
            "is_enabled": false,
            "auto_create_users": true
        }"#;
        let req: CreateOidcConfigRequest = serde_json::from_str(json_str).unwrap();
        assert_eq!(
            req.scopes,
            Some(vec!["openid".to_string(), "profile".to_string()])
        );
        assert_eq!(req.attribute_mapping, Some(json!({"email": "mail"})));
        assert_eq!(req.is_enabled, Some(false));
        assert_eq!(req.auto_create_users, Some(true));
    }

    #[test]
    fn test_update_oidc_config_request_empty() {
        let json_str = "{}";
        let req: UpdateOidcConfigRequest = serde_json::from_str(json_str).unwrap();
        assert!(req.name.is_none());
        assert!(req.issuer_url.is_none());
        assert!(req.client_id.is_none());
        assert!(req.client_secret.is_none());
        assert!(req.scopes.is_none());
    }

    #[test]
    fn test_create_ldap_config_request_defaults() {
        let json_str = r#"{
            "name": "LDAP",
            "server_url": "ldap://host:389",
            "user_base_dn": "ou=users,dc=example"
        }"#;
        let req: CreateLdapConfigRequest = serde_json::from_str(json_str).unwrap();
        assert_eq!(req.name, "LDAP");
        assert!(req.bind_dn.is_none());
        assert!(req.bind_password.is_none());
        assert!(req.user_filter.is_none());
        assert!(req.email_attribute.is_none());
        assert!(req.display_name_attribute.is_none());
        assert!(req.username_attribute.is_none());
        assert!(req.groups_attribute.is_none());
        assert!(req.use_starttls.is_none());
        assert!(req.is_enabled.is_none());
        assert!(req.priority.is_none());
    }

    #[test]
    fn test_create_saml_config_request_deserialization() {
        let json_str = r#"{
            "name": "SAML Provider",
            "entity_id": "https://idp/entity",
            "sso_url": "https://idp/sso",
            "certificate": "MIICxxx"
        }"#;
        let req: CreateSamlConfigRequest = serde_json::from_str(json_str).unwrap();
        assert_eq!(req.name, "SAML Provider");
        assert_eq!(req.certificate, "MIICxxx");
        assert!(req.slo_url.is_none());
        assert!(req.name_id_format.is_none());
        assert!(req.sp_entity_id.is_none());
        assert!(req.sign_requests.is_none());
        assert!(req.require_signed_assertions.is_none());
    }

    #[test]
    fn test_toggle_request_deserialization() {
        let json_str = r#"{"enabled": true}"#;
        let req: ToggleRequest = serde_json::from_str(json_str).unwrap();
        assert!(req.enabled);

        let json_str = r#"{"enabled": false}"#;
        let req: ToggleRequest = serde_json::from_str(json_str).unwrap();
        assert!(!req.enabled);
    }

    #[test]
    fn test_sso_provider_info_new_oidc() {
        let id = Uuid::nil();
        let info = SsoProviderInfo::new(id, "Keycloak".to_string(), "oidc");
        assert_eq!(info.provider_type, "oidc");
        assert_eq!(info.name, "Keycloak");
        assert_eq!(info.id, id);
        assert_eq!(
            info.login_url,
            "/api/v1/auth/sso/oidc/00000000-0000-0000-0000-000000000000/login"
        );
    }

    #[test]
    fn test_sso_provider_info_new_ldap() {
        let id = Uuid::nil();
        let info = SsoProviderInfo::new(id, "AD".to_string(), "ldap");
        assert_eq!(info.provider_type, "ldap");
        assert_eq!(
            info.login_url,
            "/api/v1/auth/sso/ldap/00000000-0000-0000-0000-000000000000/login"
        );
    }

    #[test]
    fn test_sso_provider_info_new_saml() {
        let id = Uuid::nil();
        let info = SsoProviderInfo::new(id, "Okta".to_string(), "saml");
        assert_eq!(info.provider_type, "saml");
        assert_eq!(
            info.login_url,
            "/api/v1/auth/sso/saml/00000000-0000-0000-0000-000000000000/login"
        );
    }

    #[test]
    fn test_sso_provider_info_serialization() {
        let info = SsoProviderInfo::new(Uuid::nil(), "My SSO".to_string(), "oidc");
        let json_str = serde_json::to_string(&info).unwrap();
        assert!(json_str.contains("\"provider_type\":\"oidc\""));
        assert!(json_str.contains("\"login_url\":\"/api/v1/auth/sso/oidc/"));
    }

    #[test]
    fn test_ldap_test_result_serialization() {
        let result = LdapTestResult {
            success: true,
            message: "Connected successfully".to_string(),
            response_time_ms: 42,
        };
        let json_str = serde_json::to_string(&result).unwrap();
        assert!(json_str.contains("\"success\":true"));
        assert!(json_str.contains("\"response_time_ms\":42"));
    }

    #[test]
    fn test_ldap_config_response_serialization() {
        let now = Utc::now();
        let resp = LdapConfigResponse {
            id: Uuid::nil(),
            name: "LDAP".to_string(),
            server_url: "ldap://host:389".to_string(),
            bind_dn: Some("cn=admin".to_string()),
            has_bind_password: true,
            user_base_dn: "ou=users".to_string(),
            user_filter: "(uid={0})".to_string(),
            group_base_dn: None,
            group_filter: None,
            email_attribute: "mail".to_string(),
            display_name_attribute: "cn".to_string(),
            username_attribute: "uid".to_string(),
            groups_attribute: "memberOf".to_string(),
            admin_group_dn: None,
            use_starttls: false,
            is_enabled: true,
            priority: 0,
            created_at: now,
            updated_at: now,
        };
        let json_str = serde_json::to_string(&resp).unwrap();
        assert!(json_str.contains("\"has_bind_password\":true"));
        assert!(json_str.contains("\"use_starttls\":false"));
    }

    #[test]
    fn test_saml_config_response_serialization() {
        let now = Utc::now();
        let resp = SamlConfigResponse {
            id: Uuid::nil(),
            name: "SAML".to_string(),
            entity_id: "entity".to_string(),
            sso_url: "https://sso".to_string(),
            slo_url: None,
            has_certificate: true,
            name_id_format: "email".to_string(),
            attribute_mapping: json!({}),
            sp_entity_id: "sp".to_string(),
            sign_requests: false,
            require_signed_assertions: true,
            admin_group: None,
            is_enabled: true,
            created_at: now,
            updated_at: now,
        };
        let json_str = serde_json::to_string(&resp).unwrap();
        assert!(json_str.contains("\"has_certificate\":true"));
        assert!(json_str.contains("\"sign_requests\":false"));
        assert!(json_str.contains("\"require_signed_assertions\":true"));
    }

    #[test]
    fn test_update_ldap_config_request_all_none() {
        let json_str = "{}";
        let req: UpdateLdapConfigRequest = serde_json::from_str(json_str).unwrap();
        assert!(req.name.is_none());
        assert!(req.server_url.is_none());
        assert!(req.bind_dn.is_none());
        assert!(req.bind_password.is_none());
        assert!(req.user_base_dn.is_none());
        assert!(req.user_filter.is_none());
        assert!(req.group_base_dn.is_none());
        assert!(req.group_filter.is_none());
        assert!(req.email_attribute.is_none());
        assert!(req.display_name_attribute.is_none());
        assert!(req.username_attribute.is_none());
        assert!(req.groups_attribute.is_none());
        assert!(req.admin_group_dn.is_none());
        assert!(req.use_starttls.is_none());
        assert!(req.is_enabled.is_none());
        assert!(req.priority.is_none());
    }

    #[test]
    fn test_update_saml_config_request_all_none() {
        let json_str = "{}";
        let req: UpdateSamlConfigRequest = serde_json::from_str(json_str).unwrap();
        assert!(req.name.is_none());
        assert!(req.entity_id.is_none());
        assert!(req.sso_url.is_none());
        assert!(req.slo_url.is_none());
        assert!(req.certificate.is_none());
        assert!(req.name_id_format.is_none());
        assert!(req.attribute_mapping.is_none());
        assert!(req.sp_entity_id.is_none());
        assert!(req.sign_requests.is_none());
        assert!(req.require_signed_assertions.is_none());
        assert!(req.admin_group.is_none());
        assert!(req.is_enabled.is_none());
    }

    #[test]
    fn test_ldap_config_row_debug_redacts_password() {
        let row = LdapConfigRow {
            id: uuid::Uuid::nil(),
            name: "test-ldap".to_string(),
            server_url: "ldap://example.com".to_string(),
            bind_dn: Some("cn=admin".to_string()),
            bind_password_encrypted: Some("super-secret-encrypted".to_string()),
            user_base_dn: "dc=example,dc=com".to_string(),
            user_filter: "(uid={0})".to_string(),
            group_base_dn: None,
            group_filter: None,
            email_attribute: "mail".to_string(),
            display_name_attribute: "cn".to_string(),
            username_attribute: "uid".to_string(),
            groups_attribute: "memberOf".to_string(),
            admin_group_dn: None,
            use_starttls: false,
            is_enabled: true,
            priority: 0,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let debug = format!("{:?}", row);
        assert!(debug.contains("test-ldap"));
        assert!(!debug.contains("super-secret-encrypted"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn test_saml_config_row_debug_redacts_certificate() {
        let row = SamlConfigRow {
            id: uuid::Uuid::nil(),
            name: "test-saml".to_string(),
            entity_id: "https://idp.example.com".to_string(),
            sso_url: "https://idp.example.com/sso".to_string(),
            slo_url: None,
            certificate: "-----BEGIN CERTIFICATE-----\nMIIBxTCCAW...".to_string(),
            name_id_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string(),
            attribute_mapping: serde_json::json!({}),
            sp_entity_id: "https://sp.example.com".to_string(),
            sign_requests: false,
            require_signed_assertions: true,
            admin_group: None,
            is_enabled: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let debug = format!("{:?}", row);
        assert!(debug.contains("test-saml"));
        assert!(!debug.contains("BEGIN CERTIFICATE"));
        assert!(debug.contains("[REDACTED]"));
    }

    // -----------------------------------------------------------------------
    // PKCE S256 (issue #1091)
    // -----------------------------------------------------------------------

    #[test]
    fn test_pkce_verifier_length_and_charset() {
        let v = generate_pkce_verifier();
        // 48 bytes base64url-no-pad => 64 characters
        assert_eq!(v.len(), 64);
        assert!(v
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn test_pkce_verifier_is_random() {
        let a = generate_pkce_verifier();
        let b = generate_pkce_verifier();
        assert_ne!(a, b, "two verifiers should not collide");
    }

    #[test]
    fn test_pkce_challenge_s256_known_vector() {
        // RFC 7636 Appendix B test vector.
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = pkce_challenge_s256(verifier);
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn test_pkce_challenge_s256_deterministic() {
        let verifier = generate_pkce_verifier();
        let c1 = pkce_challenge_s256(&verifier);
        let c2 = pkce_challenge_s256(&verifier);
        assert_eq!(c1, c2);
    }

    // -----------------------------------------------------------------------
    // attribute_mapping merge semantics (issue #1191)
    // -----------------------------------------------------------------------

    #[test]
    fn test_merge_preserves_keys_not_in_patch() {
        let base = serde_json::json!({
            "redirect_uri": "https://ak.example.com/cb",
            "username_claim": "preferred_username"
        });
        let patch = serde_json::json!({
            "username_claim": "email"
        });
        let out = merge_attribute_mapping(&base, &patch);
        // redirect_uri must survive.
        assert_eq!(out["redirect_uri"], "https://ak.example.com/cb");
        assert_eq!(out["username_claim"], "email");
    }

    #[test]
    fn test_merge_null_value_removes_key() {
        let base = serde_json::json!({
            "redirect_uri": "https://ak.example.com/cb",
            "admin_group": "platform-admins"
        });
        let patch = serde_json::json!({ "admin_group": null });
        let out = merge_attribute_mapping(&base, &patch);
        assert_eq!(out["redirect_uri"], "https://ak.example.com/cb");
        assert!(out.get("admin_group").is_none());
    }

    #[test]
    fn test_merge_adds_new_keys() {
        let base = serde_json::json!({"a": 1});
        let patch = serde_json::json!({"b": 2});
        let out = merge_attribute_mapping(&base, &patch);
        assert_eq!(out["a"], 1);
        assert_eq!(out["b"], 2);
    }

    #[test]
    fn test_merge_empty_patch_is_noop() {
        let base = serde_json::json!({"a": 1, "b": 2});
        let patch = serde_json::json!({});
        let out = merge_attribute_mapping(&base, &patch);
        assert_eq!(out, base);
    }

    #[test]
    fn test_merge_non_object_patch_replaces() {
        let base = serde_json::json!({"a": 1});
        let patch = serde_json::json!("scalar");
        let out = merge_attribute_mapping(&base, &patch);
        assert_eq!(out, serde_json::json!("scalar"));
    }

    // -----------------------------------------------------------------------
    // Env-managed provider reconciliation (issue #1656)
    // -----------------------------------------------------------------------

    #[test]
    fn test_plan_reconcile_create_when_absent() {
        let existing: Vec<(Uuid, String)> = vec![];
        assert_eq!(
            plan_provider_reconcile("default", &existing),
            ReconcileAction::Create
        );
    }

    #[test]
    fn test_plan_reconcile_update_when_name_matches() {
        let id = Uuid::new_v4();
        let existing = vec![(id, "default".to_string())];
        assert_eq!(
            plan_provider_reconcile("default", &existing),
            ReconcileAction::Update(id)
        );
    }

    #[test]
    fn test_plan_reconcile_create_ignores_other_named_providers() {
        let other = Uuid::new_v4();
        let existing = vec![(other, "Corporate SSO".to_string())];
        assert_eq!(
            plan_provider_reconcile("default", &existing),
            ReconcileAction::Create
        );
    }

    #[test]
    fn test_oidc_create_to_update_carries_secret_and_replaces_mapping() {
        let c = CreateOidcConfigRequest {
            name: "default".into(),
            issuer_url: "https://idp".into(),
            client_id: "c".into(),
            client_secret: "s".into(),
            scopes: None,
            attribute_mapping: None,
            is_enabled: None,
            auto_create_users: None,
            pkce_enabled: None,
            map_groups_to_groups: None,
        };
        let u: UpdateOidcConfigRequest = c.into();
        assert_eq!(u.issuer_url, Some("https://idp".to_string()));
        assert_eq!(u.client_id, Some("c".to_string()));
        assert_eq!(u.client_secret, Some("s".to_string()));
        assert_eq!(u.attribute_mapping_replace, Some(true));
    }

    #[test]
    fn test_ldap_create_to_update_maps_required_fields() {
        let c = CreateLdapConfigRequest {
            name: "default".into(),
            server_url: "ldap://host:389".into(),
            bind_dn: Some("cn=admin".into()),
            bind_password: Some("pw".into()),
            user_base_dn: "ou=users".into(),
            user_filter: None,
            group_base_dn: None,
            group_filter: None,
            email_attribute: None,
            display_name_attribute: None,
            username_attribute: None,
            groups_attribute: None,
            admin_group_dn: None,
            use_starttls: Some(true),
            is_enabled: Some(true),
            priority: Some(0),
        };
        let u: UpdateLdapConfigRequest = c.into();
        assert_eq!(u.name, Some("default".to_string()));
        assert_eq!(u.server_url, Some("ldap://host:389".to_string()));
        assert_eq!(u.user_base_dn, Some("ou=users".to_string()));
        assert_eq!(u.bind_dn, Some("cn=admin".to_string()));
        assert_eq!(u.use_starttls, Some(true));
    }

    // =======================================================================
    // DB-backed tests for OIDC config CRUD + SSO session lifecycle.
    //
    // These opt into a real Postgres via test_db_helpers::try_pool(): when
    // DATABASE_URL is unset they no-op so `cargo test --lib` stays usable
    // without a database. The coverage CI job provisions Postgres and runs
    // migrations, so these tests execute there and instrument the SQL paths
    // touched by the OIDC enhancements bundle (PKCE columns, map_groups_to_
    // groups column, attribute_mapping merge wiring, PKCE-stashing SSO
    // session, etc.).
    // =======================================================================

    mod db {
        use super::*;
        use crate::api::handlers::test_db_helpers as db_helpers;

        /// Build a CreateOidcConfigRequest with a unique name suffix so
        /// parallel tests do not collide on the UNIQUE constraint.
        fn make_create_req(suffix: &str) -> CreateOidcConfigRequest {
            CreateOidcConfigRequest {
                name: format!("acs-test-{suffix}"),
                issuer_url: "https://issuer.test.local".to_string(),
                client_id: format!("client-{suffix}"),
                client_secret: format!("secret-{suffix}"),
                scopes: Some(vec!["openid".to_string(), "email".to_string()]),
                attribute_mapping: Some(json!({"username_claim": "preferred_username"})),
                is_enabled: Some(true),
                auto_create_users: Some(true),
                pkce_enabled: None,
                map_groups_to_groups: None,
            }
        }

        /// Skip the test cleanly if no encryption key env var is configured.
        /// We deliberately do NOT set env vars from a test because doing so
        /// leaks into other tests in the same process (e.g. the
        /// `test_encryption_key_panics_when_unset` invariant). The coverage
        /// CI job sets JWT_SECRET, so these tests run there.
        fn encryption_key_available() -> bool {
            std::env::var("SSO_ENCRYPTION_KEY").is_ok() || std::env::var("JWT_SECRET").is_ok()
        }

        async fn cleanup_oidc(pool: &PgPool, id: Uuid) {
            let _ = sqlx::query("DELETE FROM oidc_configs WHERE id = $1")
                .bind(id)
                .execute(pool)
                .await;
        }

        #[tokio::test]
        async fn test_create_oidc_applies_pkce_defaults() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            if !encryption_key_available() {
                return;
            }
            let req = make_create_req("pkce-default");
            let resp = AuthConfigService::create_oidc(&pool, req)
                .await
                .expect("create_oidc");
            // pkce_enabled defaults to true; map_groups_to_groups to false.
            assert!(resp.pkce_enabled);
            assert!(!resp.map_groups_to_groups);
            assert!(resp.has_secret);
            assert!(resp.is_enabled);
            assert!(resp.auto_create_users);
            cleanup_oidc(&pool, resp.id).await;
        }

        #[tokio::test]
        async fn test_create_oidc_honors_explicit_pkce_false() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            if !encryption_key_available() {
                return;
            }
            let mut req = make_create_req("pkce-off");
            req.pkce_enabled = Some(false);
            req.map_groups_to_groups = Some(true);
            let resp = AuthConfigService::create_oidc(&pool, req)
                .await
                .expect("create_oidc");
            assert!(!resp.pkce_enabled);
            assert!(resp.map_groups_to_groups);
            cleanup_oidc(&pool, resp.id).await;
        }

        #[tokio::test]
        async fn test_get_oidc_round_trips_new_columns() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            if !encryption_key_available() {
                return;
            }
            let mut req = make_create_req("get-roundtrip");
            req.pkce_enabled = Some(true);
            req.map_groups_to_groups = Some(true);
            let created = AuthConfigService::create_oidc(&pool, req)
                .await
                .expect("create_oidc");
            let fetched = AuthConfigService::get_oidc(&pool, created.id)
                .await
                .expect("get_oidc");
            assert_eq!(fetched.id, created.id);
            assert!(fetched.pkce_enabled);
            assert!(fetched.map_groups_to_groups);
            assert_eq!(fetched.scopes, vec!["openid", "email"]);
            cleanup_oidc(&pool, created.id).await;
        }

        #[tokio::test]
        async fn test_get_oidc_decrypted_decodes_secret() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            if !encryption_key_available() {
                return;
            }
            let req = make_create_req("decrypt");
            let secret = req.client_secret.clone();
            let created = AuthConfigService::create_oidc(&pool, req)
                .await
                .expect("create_oidc");
            let (row, plaintext) = AuthConfigService::get_oidc_decrypted(&pool, created.id)
                .await
                .expect("get_oidc_decrypted");
            assert_eq!(plaintext, secret);
            assert!(row.pkce_enabled); // default true
            assert!(!row.map_groups_to_groups); // default false
            cleanup_oidc(&pool, created.id).await;
        }

        #[tokio::test]
        async fn test_list_oidc_includes_new_columns() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            if !encryption_key_available() {
                return;
            }
            let req = make_create_req("list");
            let created = AuthConfigService::create_oidc(&pool, req)
                .await
                .expect("create_oidc");
            let configs = AuthConfigService::list_oidc(&pool)
                .await
                .expect("list_oidc");
            let found = configs.iter().find(|c| c.id == created.id).expect("found");
            assert!(found.pkce_enabled);
            assert!(!found.map_groups_to_groups);
            cleanup_oidc(&pool, created.id).await;
        }

        #[tokio::test]
        async fn test_update_oidc_merges_attribute_mapping_by_default() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            if !encryption_key_available() {
                return;
            }
            // Seed with two attribute keys.
            let mut req = make_create_req("merge");
            req.attribute_mapping = Some(json!({
                "username_claim": "preferred_username",
                "redirect_uri": "https://ak.example.com/cb",
            }));
            let created = AuthConfigService::create_oidc(&pool, req)
                .await
                .expect("create_oidc");

            // Patch only username_claim. The other key must survive.
            let update = UpdateOidcConfigRequest {
                name: None,
                issuer_url: None,
                client_id: None,
                client_secret: None,
                scopes: None,
                attribute_mapping: Some(json!({"username_claim": "email"})),
                attribute_mapping_replace: None,
                is_enabled: None,
                auto_create_users: None,
                pkce_enabled: None,
                map_groups_to_groups: None,
            };
            let updated = AuthConfigService::update_oidc(&pool, created.id, update)
                .await
                .expect("update_oidc");
            assert_eq!(updated.attribute_mapping["username_claim"], "email");
            // redirect_uri must be preserved by the merge.
            assert_eq!(
                updated.attribute_mapping["redirect_uri"],
                "https://ak.example.com/cb"
            );
            cleanup_oidc(&pool, created.id).await;
        }

        #[tokio::test]
        async fn test_update_oidc_replace_drops_unlisted_keys() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            if !encryption_key_available() {
                return;
            }
            let mut req = make_create_req("replace");
            req.attribute_mapping = Some(json!({
                "username_claim": "preferred_username",
                "redirect_uri": "https://ak.example.com/cb",
            }));
            let created = AuthConfigService::create_oidc(&pool, req)
                .await
                .expect("create_oidc");

            // Opt into legacy wholesale-replace behavior.
            let update = UpdateOidcConfigRequest {
                name: None,
                issuer_url: None,
                client_id: None,
                client_secret: None,
                scopes: None,
                attribute_mapping: Some(json!({"username_claim": "email"})),
                attribute_mapping_replace: Some(true),
                is_enabled: None,
                auto_create_users: None,
                pkce_enabled: None,
                map_groups_to_groups: None,
            };
            let updated = AuthConfigService::update_oidc(&pool, created.id, update)
                .await
                .expect("update_oidc");
            assert_eq!(updated.attribute_mapping["username_claim"], "email");
            // redirect_uri must be GONE because we asked for replace semantics.
            assert!(updated.attribute_mapping.get("redirect_uri").is_none());
            cleanup_oidc(&pool, created.id).await;
        }

        #[tokio::test]
        async fn test_update_oidc_flips_pkce_and_group_mapping() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            if !encryption_key_available() {
                return;
            }
            let req = make_create_req("flip");
            let created = AuthConfigService::create_oidc(&pool, req)
                .await
                .expect("create_oidc");
            assert!(created.pkce_enabled);
            assert!(!created.map_groups_to_groups);

            let update = UpdateOidcConfigRequest {
                name: None,
                issuer_url: None,
                client_id: None,
                client_secret: None,
                scopes: None,
                attribute_mapping: None,
                attribute_mapping_replace: None,
                is_enabled: None,
                auto_create_users: None,
                pkce_enabled: Some(false),
                map_groups_to_groups: Some(true),
            };
            let updated = AuthConfigService::update_oidc(&pool, created.id, update)
                .await
                .expect("update_oidc");
            assert!(!updated.pkce_enabled);
            assert!(updated.map_groups_to_groups);
            cleanup_oidc(&pool, created.id).await;
        }

        #[tokio::test]
        async fn test_update_oidc_preserves_secret_when_not_provided() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            if !encryption_key_available() {
                return;
            }
            let req = make_create_req("preserve-secret");
            let original_secret = req.client_secret.clone();
            let created = AuthConfigService::create_oidc(&pool, req)
                .await
                .expect("create_oidc");
            let update = UpdateOidcConfigRequest {
                name: Some("renamed".to_string()),
                issuer_url: None,
                client_id: None,
                client_secret: None,
                scopes: None,
                attribute_mapping: None,
                attribute_mapping_replace: None,
                is_enabled: None,
                auto_create_users: None,
                pkce_enabled: None,
                map_groups_to_groups: None,
            };
            let updated = AuthConfigService::update_oidc(&pool, created.id, update)
                .await
                .expect("update_oidc");
            assert_eq!(updated.name, "renamed");
            assert!(updated.has_secret);
            // Verify decryption still yields the original.
            let (_row, plaintext) = AuthConfigService::get_oidc_decrypted(&pool, created.id)
                .await
                .expect("get_oidc_decrypted");
            assert_eq!(plaintext, original_secret);
            cleanup_oidc(&pool, created.id).await;
        }

        #[tokio::test]
        async fn test_toggle_oidc_returns_new_column_state() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            if !encryption_key_available() {
                return;
            }
            let req = make_create_req("toggle");
            let created = AuthConfigService::create_oidc(&pool, req)
                .await
                .expect("create_oidc");
            let toggled =
                AuthConfigService::toggle_oidc(&pool, created.id, ToggleRequest { enabled: false })
                    .await
                    .expect("toggle_oidc");
            assert!(!toggled.is_enabled);
            // New columns survive the toggle.
            assert!(toggled.pkce_enabled);
            assert!(!toggled.map_groups_to_groups);
            cleanup_oidc(&pool, created.id).await;
        }

        // -------------------------------------------------------------------
        // SSO session: PKCE verifier round-trip (issue #1091).
        // -------------------------------------------------------------------

        #[tokio::test]
        async fn test_create_sso_session_with_pkce_persists_verifier() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            let verifier = generate_pkce_verifier();
            let session = AuthConfigService::create_sso_session_with_pkce(
                &pool,
                "oidc",
                Uuid::new_v4(),
                Some(verifier.clone()),
            )
            .await
            .expect("create_sso_session_with_pkce");
            assert_eq!(
                session.pkce_code_verifier.as_deref(),
                Some(verifier.as_str())
            );

            // validate_sso_session deletes + returns; verifier must round-trip.
            let validated = AuthConfigService::validate_sso_session(&pool, &session.state)
                .await
                .expect("validate_sso_session");
            assert_eq!(validated.id, session.id);
            assert_eq!(
                validated.pkce_code_verifier.as_deref(),
                Some(verifier.as_str())
            );
        }

        #[tokio::test]
        async fn test_create_sso_session_legacy_path_has_no_verifier() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            // Legacy create_sso_session forwards None as the verifier.
            let session = AuthConfigService::create_sso_session(&pool, "oidc", Uuid::new_v4())
                .await
                .expect("create_sso_session");
            assert!(session.pkce_code_verifier.is_none());

            let validated = AuthConfigService::validate_sso_session(&pool, &session.state)
                .await
                .expect("validate_sso_session");
            assert!(validated.pkce_code_verifier.is_none());
        }

        /// Regression for cross-provider state replay: validate_sso_session
        /// must return the session that owns the state, so the handler can
        /// reject mismatched URL-path provider ids. We assert here that the
        /// returned provider_id is exactly the one we minted the session
        /// with, never one we picked at the call site.
        #[tokio::test]
        async fn test_validate_sso_session_returns_minted_provider_id() {
            let Some(pool) = db_helpers::try_pool().await else {
                return;
            };
            let provider_a = Uuid::new_v4();
            let session = AuthConfigService::create_sso_session(&pool, "oidc", provider_a)
                .await
                .expect("create_sso_session");
            let validated = AuthConfigService::validate_sso_session(&pool, &session.state)
                .await
                .expect("validate_sso_session");
            assert_eq!(
                validated.provider_id, provider_a,
                "session must report the provider_id it was minted with so callback handlers can compare it against the URL path"
            );
        }
    }
}
