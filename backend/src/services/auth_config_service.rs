//! SSO provider configuration management service.
//!
//! Provides CRUD operations for OIDC, LDAP, and SAML provider configurations
//! stored in the database, including encrypted credential storage and
//! SSO session management for CSRF protection during auth flows.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::encryption::{decrypt_credentials, encrypt_credentials};

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
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
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

#[derive(Debug, Clone, FromRow)]
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

#[derive(Debug, Clone, FromRow)]
pub struct SsoSession {
    pub id: Uuid,
    pub provider_type: String,
    pub provider_id: Uuid,
    pub state: String,
    pub nonce: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// API response structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct OidcConfigResponse {
    pub id: Uuid,
    pub name: String,
    pub issuer_url: String,
    pub client_id: String,
    pub has_secret: bool,
    pub scopes: Vec<String>,
    pub attribute_mapping: serde_json::Value,
    pub is_enabled: bool,
    pub auto_create_users: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
pub struct SamlConfigResponse {
    pub id: Uuid,
    pub name: String,
    pub entity_id: String,
    pub sso_url: String,
    pub slo_url: Option<String>,
    pub has_certificate: bool,
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

// ---------------------------------------------------------------------------
// Request structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct CreateOidcConfigRequest {
    pub name: String,
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub scopes: Option<Vec<String>>,
    pub attribute_mapping: Option<serde_json::Value>,
    pub is_enabled: Option<bool>,
    pub auto_create_users: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateOidcConfigRequest {
    pub name: Option<String>,
    pub issuer_url: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub attribute_mapping: Option<serde_json::Value>,
    pub is_enabled: Option<bool>,
    pub auto_create_users: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
pub struct CreateSamlConfigRequest {
    pub name: String,
    pub entity_id: String,
    pub sso_url: String,
    pub slo_url: Option<String>,
    pub certificate: String,
    pub name_id_format: Option<String>,
    pub attribute_mapping: Option<serde_json::Value>,
    pub sp_entity_id: Option<String>,
    pub sign_requests: Option<bool>,
    pub require_signed_assertions: Option<bool>,
    pub admin_group: Option<String>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateSamlConfigRequest {
    pub name: Option<String>,
    pub entity_id: Option<String>,
    pub sso_url: Option<String>,
    pub slo_url: Option<String>,
    pub certificate: Option<String>,
    pub name_id_format: Option<String>,
    pub attribute_mapping: Option<serde_json::Value>,
    pub sp_entity_id: Option<String>,
    pub sign_requests: Option<bool>,
    pub require_signed_assertions: Option<bool>,
    pub admin_group: Option<String>,
    pub is_enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SsoProviderInfo {
    pub id: Uuid,
    pub name: String,
    pub provider_type: String,
    pub login_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ToggleRequest {
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct LdapTestResult {
    pub success: bool,
    pub message: String,
    pub response_time_ms: u64,
}

// ---------------------------------------------------------------------------
// Encryption key — in production, load from config / env
// ---------------------------------------------------------------------------

fn encryption_key() -> String {
    std::env::var("SSO_ENCRYPTION_KEY")
        .or_else(|_| std::env::var("JWT_SECRET"))
        .unwrap_or_else(|_| "artifact-keeper-sso-encryption-key".to_string())
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

    pub async fn create_oidc(pool: &PgPool, req: CreateOidcConfigRequest) -> Result<OidcConfigResponse> {
        let id = Uuid::new_v4();
        let encrypted = encrypt_credentials(&req.client_secret, &encryption_key());
        let encrypted_hex = hex::encode(&encrypted);
        let scopes = req.scopes.unwrap_or_else(|| vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ]);
        let attribute_mapping = req.attribute_mapping.unwrap_or(serde_json::json!({}));
        let is_enabled = req.is_enabled.unwrap_or(true);
        let auto_create_users = req.auto_create_users.unwrap_or(true);

        let row = sqlx::query_as::<_, OidcConfigRow>(
            r#"
            INSERT INTO oidc_configs (id, name, issuer_url, client_id, client_secret_encrypted,
                                      scopes, attribute_mapping, is_enabled, auto_create_users)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id, name, issuer_url, client_id, client_secret_encrypted,
                      scopes, attribute_mapping, is_enabled, auto_create_users,
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
        let client_id = req.client_id.unwrap_or(existing.client_id);
        let scopes = req.scopes.unwrap_or(existing.scopes);
        let attribute_mapping = req.attribute_mapping.unwrap_or(existing.attribute_mapping);
        let is_enabled = req.is_enabled.unwrap_or(existing.is_enabled);
        let auto_create_users = req.auto_create_users.unwrap_or(existing.auto_create_users);

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
                updated_at = NOW()
            WHERE id = $9
            RETURNING id, name, issuer_url, client_id, client_secret_encrypted,
                      scopes, attribute_mapping, is_enabled, auto_create_users,
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

    pub async fn toggle_oidc(pool: &PgPool, id: Uuid, toggle: ToggleRequest) -> Result<OidcConfigResponse> {
        let row = sqlx::query_as::<_, OidcConfigRow>(
            r#"
            UPDATE oidc_configs SET is_enabled = $1, updated_at = NOW()
            WHERE id = $2
            RETURNING id, name, issuer_url, client_id, client_secret_encrypted,
                      scopes, attribute_mapping, is_enabled, auto_create_users,
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

    pub async fn get_ldap_decrypted(pool: &PgPool, id: Uuid) -> Result<(LdapConfigRow, Option<String>)> {
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
                let encrypted_bytes = hex::decode(hex_str)
                    .map_err(|e| AppError::Internal(format!("Failed to decode bind password hex: {e}")))?;
                decrypt_credentials(&encrypted_bytes, &encryption_key())
                    .map_err(|e| AppError::Internal(format!("Failed to decrypt bind password: {e}")))
            })
            .transpose()?;

        Ok((row, password))
    }

    pub async fn create_ldap(pool: &PgPool, req: CreateLdapConfigRequest) -> Result<LdapConfigResponse> {
        let id = Uuid::new_v4();

        let bind_password_hex: Option<String> = req.bind_password.as_ref().map(|pw| {
            let encrypted = encrypt_credentials(pw, &encryption_key());
            hex::encode(&encrypted)
        });

        let user_filter = req.user_filter.unwrap_or_else(|| "(uid={0})".to_string());
        let email_attribute = req.email_attribute.unwrap_or_else(|| "mail".to_string());
        let display_name_attribute = req.display_name_attribute.unwrap_or_else(|| "cn".to_string());
        let username_attribute = req.username_attribute.unwrap_or_else(|| "uid".to_string());
        let groups_attribute = req.groups_attribute.unwrap_or_else(|| "memberOf".to_string());
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
        let display_name_attribute = req.display_name_attribute.unwrap_or(existing.display_name_attribute);
        let username_attribute = req.username_attribute.unwrap_or(existing.username_attribute);
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

    pub async fn toggle_ldap(pool: &PgPool, id: Uuid, toggle: ToggleRequest) -> Result<LdapConfigResponse> {
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

        let start = std::time::Instant::now();

        // Parse host and port from server_url (e.g. ldap://host:389 or ldaps://host:636)
        let url = &row.server_url;
        let (host, port) = Self::parse_ldap_url(url)?;

        let addr = format!("{host}:{port}");
        let timeout = std::time::Duration::from_secs(5);

        let result = tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await;
        let elapsed = start.elapsed().as_millis() as u64;

        let (success, message) = match result {
            Ok(Ok(_)) => (true, format!("Successfully connected to {addr}")),
            Ok(Err(e)) => (false, format!("Connection to {addr} failed: {e}")),
            Err(_) => (false, format!("Connection to {addr} timed out after 5s")),
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
            has_bind_password: row.bind_password_encrypted.map_or(false, |p| !p.is_empty()),
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

    pub async fn create_saml(pool: &PgPool, req: CreateSamlConfigRequest) -> Result<SamlConfigResponse> {
        let id = Uuid::new_v4();
        let name_id_format = req.name_id_format.unwrap_or_else(|| {
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress".to_string()
        });
        let attribute_mapping = req.attribute_mapping.unwrap_or(serde_json::json!({}));
        let sp_entity_id = req.sp_entity_id.unwrap_or_else(|| "artifact-keeper".to_string());
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
        let require_signed_assertions = req.require_signed_assertions.unwrap_or(existing.require_signed_assertions);
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

    pub async fn toggle_saml(pool: &PgPool, id: Uuid, toggle: ToggleRequest) -> Result<SamlConfigResponse> {
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
            providers.push(SsoProviderInfo {
                login_url: format!("/auth/sso/oidc/{id}/login"),
                id,
                name,
                provider_type: "oidc".to_string(),
            });
        }

        // LDAP providers (only fetch id and name)
        let ldap_rows = sqlx::query_as::<_, (Uuid, String)>(
            "SELECT id, name FROM ldap_configs WHERE is_enabled = true ORDER BY priority, name",
        )
        .fetch_all(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to list LDAP providers: {e}")))?;

        for (id, name) in ldap_rows {
            providers.push(SsoProviderInfo {
                login_url: format!("/auth/sso/ldap/{id}/login"),
                id,
                name,
                provider_type: "ldap".to_string(),
            });
        }

        // SAML providers (only fetch id and name)
        let saml_rows = sqlx::query_as::<_, (Uuid, String)>(
            "SELECT id, name FROM saml_configs WHERE is_enabled = true ORDER BY name",
        )
        .fetch_all(pool)
        .await
        .map_err(|e| AppError::Internal(format!("Failed to list SAML providers: {e}")))?;

        for (id, name) in saml_rows {
            providers.push(SsoProviderInfo {
                login_url: format!("/auth/sso/saml/{id}/login"),
                id,
                name,
                provider_type: "saml".to_string(),
            });
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
        let id = Uuid::new_v4();
        let state = Uuid::new_v4().to_string();
        let nonce = Uuid::new_v4().to_string();

        let session = sqlx::query_as::<_, SsoSession>(
            r#"
            INSERT INTO sso_sessions (id, provider_type, provider_id, state, nonce)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, provider_type, provider_id, state, nonce, created_at, expires_at
            "#,
        )
        .bind(id)
        .bind(provider_type)
        .bind(provider_id)
        .bind(&state)
        .bind(&nonce)
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
            RETURNING id, provider_type, provider_id, state, nonce, created_at, expires_at
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
}
