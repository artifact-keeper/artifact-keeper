//! Upstream authentication for remote/proxy repositories.
//!
//! Loads encrypted credentials from `repository_config` and applies them
//! to outgoing HTTP requests. Supports Basic and Bearer auth types.

use reqwest::RequestBuilder;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::auth_config_service::encryption_key;
use crate::services::encryption::{decrypt_credentials, encrypt_credentials};

/// Auth types supported for upstream repositories.
#[derive(Debug, Clone, PartialEq)]
pub enum UpstreamAuthType {
    Basic { username: String, password: String },
    Bearer { token: String },
}

/// Load upstream auth credentials for a repository.
/// Returns None if no auth is configured.
pub async fn load_upstream_auth(db: &PgPool, repo_id: Uuid) -> Result<Option<UpstreamAuthType>> {
    // Load auth type
    let auth_type: Option<String> = sqlx::query_scalar(
        "SELECT value FROM repository_config WHERE repository_id = $1 AND key = 'upstream_auth_type'",
    )
    .bind(repo_id)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .flatten();

    let auth_type = match auth_type {
        Some(t) if !t.is_empty() && t != "none" => t,
        _ => return Ok(None),
    };

    // Load and decrypt credentials
    let encrypted_hex: String = sqlx::query_scalar(
        "SELECT value FROM repository_config WHERE repository_id = $1 AND key = 'upstream_auth_credentials'",
    )
    .bind(repo_id)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .flatten()
    .ok_or_else(|| {
        AppError::Config(
            "Upstream auth type is configured but credentials are missing".to_string(),
        )
    })?;

    let encrypted_bytes = hex::decode(&encrypted_hex)
        .map_err(|e| AppError::Internal(format!("Failed to decode upstream credentials: {e}")))?;
    let credentials_json = decrypt_credentials(&encrypted_bytes, &encryption_key())
        .map_err(|e| AppError::Internal(format!("Failed to decrypt upstream credentials: {e}")))?;

    let creds: serde_json::Value = serde_json::from_str(&credentials_json)
        .map_err(|e| AppError::Internal(format!("Invalid upstream credentials JSON: {e}")))?;

    match auth_type.as_str() {
        "basic" => {
            let username = creds["username"].as_str().unwrap_or_default().to_string();
            let password = creds["password"].as_str().unwrap_or_default().to_string();
            Ok(Some(UpstreamAuthType::Basic { username, password }))
        }
        "bearer" => {
            let token = creds["token"].as_str().unwrap_or_default().to_string();
            Ok(Some(UpstreamAuthType::Bearer { token }))
        }
        other => Err(AppError::Config(format!(
            "Unknown upstream auth type: {other}"
        ))),
    }
}

/// Apply upstream auth to a reqwest RequestBuilder.
pub fn apply_upstream_auth(builder: RequestBuilder, auth: &UpstreamAuthType) -> RequestBuilder {
    match auth {
        UpstreamAuthType::Basic { username, password } => {
            builder.basic_auth(username, Some(password))
        }
        UpstreamAuthType::Bearer { token } => builder.bearer_auth(token),
    }
}

/// Store upstream auth credentials for a repository.
/// Encrypts credentials before writing to repository_config.
pub async fn save_upstream_auth(
    db: &PgPool,
    repo_id: Uuid,
    auth_type: &str,
    credentials_json: &str,
) -> Result<()> {
    let encrypted = encrypt_credentials(credentials_json, &encryption_key());
    let encrypted_hex = hex::encode(&encrypted);

    // Upsert auth type
    sqlx::query(
        "INSERT INTO repository_config (repository_id, key, value) \
         VALUES ($1, 'upstream_auth_type', $2) \
         ON CONFLICT (repository_id, key) DO UPDATE SET value = $2, updated_at = NOW()",
    )
    .bind(repo_id)
    .bind(auth_type)
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // Upsert encrypted credentials
    sqlx::query(
        "INSERT INTO repository_config (repository_id, key, value) \
         VALUES ($1, 'upstream_auth_credentials', $2) \
         ON CONFLICT (repository_id, key) DO UPDATE SET value = $2, updated_at = NOW()",
    )
    .bind(repo_id)
    .bind(&encrypted_hex)
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(())
}

/// Remove upstream auth credentials for a repository.
pub async fn remove_upstream_auth(db: &PgPool, repo_id: Uuid) -> Result<()> {
    sqlx::query(
        "DELETE FROM repository_config WHERE repository_id = $1 \
         AND key IN ('upstream_auth_type', 'upstream_auth_credentials')",
    )
    .bind(repo_id)
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(())
}

/// Check whether upstream auth is configured for a repository.
/// Returns the auth type string (e.g. "basic", "bearer") or None.
pub async fn get_upstream_auth_type(db: &PgPool, repo_id: Uuid) -> Result<Option<String>> {
    let val: Option<String> = sqlx::query_scalar(
        "SELECT value FROM repository_config WHERE repository_id = $1 AND key = 'upstream_auth_type'",
    )
    .bind(repo_id)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?
    .flatten();

    match val {
        Some(t) if !t.is_empty() && t != "none" => Ok(Some(t)),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_basic_auth() {
        let client = reqwest::Client::new();
        let auth = UpstreamAuthType::Basic {
            username: "user".to_string(),
            password: "pass".to_string(),
        };
        // Verify it builds without panic (reqwest doesn't expose headers on RequestBuilder)
        let _builder = apply_upstream_auth(client.get("http://example.com"), &auth);
    }

    #[test]
    fn test_apply_bearer_auth() {
        let client = reqwest::Client::new();
        let auth = UpstreamAuthType::Bearer {
            token: "tok_123".to_string(),
        };
        let _builder = apply_upstream_auth(client.get("http://example.com"), &auth);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Use the existing encryption infrastructure
        let key = "test-secret-key";
        let creds = r#"{"username":"bot","password":"s3cret"}"#;
        let encrypted = encrypt_credentials(creds, key);
        let decrypted = decrypt_credentials(&encrypted, key).unwrap();
        assert_eq!(creds, decrypted);
    }
}
