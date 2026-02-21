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
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpdateOidcConfigRequest {
    pub name: Option<String>,
    pub issuer_url: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scopes: Option<Vec<String>>,
    #[schema(value_type = Option<Object>)]
    pub attribute_mapping: Option<serde_json::Value>,
    pub is_enabled: Option<bool>,
    pub auto_create_users: Option<bool>,
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

    pub async fn create_oidc(
        pool: &PgPool,
        req: CreateOidcConfigRequest,
    ) -> Result<OidcConfigResponse> {
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
    // encryption_key() tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_encryption_key_fallback() {
        // When neither env var is set, the default key is returned.
        // We cannot guarantee env vars are unset in CI, but we can at least
        // confirm the function returns a non-empty string.
        let key = encryption_key();
        assert!(!key.is_empty());
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
            created_at: now,
            updated_at: now,
        };
        let json_str = serde_json::to_string(&resp).unwrap();
        assert!(json_str.contains("\"has_secret\":true"));
        assert!(json_str.contains("\"name\":\"Test\""));
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
    fn test_sso_provider_info_serialization() {
        let info = SsoProviderInfo {
            id: Uuid::nil(),
            name: "My SSO".to_string(),
            provider_type: "oidc".to_string(),
            login_url: "/auth/sso/oidc/00000000-0000-0000-0000-000000000000/login".to_string(),
        };
        let json_str = serde_json::to_string(&info).unwrap();
        assert!(json_str.contains("\"provider_type\":\"oidc\""));
        assert!(json_str.contains("\"login_url\":\"/auth/sso/oidc/"));
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
}
