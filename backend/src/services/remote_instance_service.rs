//! Service for managing remote Artifact Keeper instances.
//!
//! Stores remote instance configs (URL + encrypted API key) so the frontend
//! never needs to hold API keys in the browser. All remote-instance requests
//! are proxied through the local backend which decrypts the key on-the-fly.

use serde::Serialize;
use sqlx::{FromRow, PgPool, Row};
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::auth_config_service::encryption_key;
use crate::services::encryption::{decrypt_credentials, encrypt_credentials};

#[derive(Debug, Serialize, FromRow)]
pub struct RemoteInstanceResponse {
    pub id: Uuid,
    pub name: String,
    pub url: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

pub struct RemoteInstanceService;

impl RemoteInstanceService {
    /// List all remote instances belonging to `user_id`.
    pub async fn list(pool: &PgPool, user_id: Uuid) -> Result<Vec<RemoteInstanceResponse>> {
        let rows: Vec<RemoteInstanceResponse> = sqlx::query_as(
            "SELECT id, name, url, created_at FROM remote_instances WHERE user_id = $1 ORDER BY name",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(rows)
    }

    /// Create a new remote instance, encrypting the API key before storage.
    pub async fn create(
        pool: &PgPool,
        user_id: Uuid,
        name: &str,
        url: &str,
        api_key: &str,
    ) -> Result<RemoteInstanceResponse> {
        let key = encryption_key();
        let encrypted = encrypt_credentials(api_key, &key);
        let encrypted_hex = hex::encode(encrypted);

        let row: RemoteInstanceResponse = sqlx::query_as(
            r#"INSERT INTO remote_instances (user_id, name, url, api_key_encrypted)
               VALUES ($1, $2, $3, $4)
               RETURNING id, name, url, created_at"#,
        )
        .bind(user_id)
        .bind(name)
        .bind(url)
        .bind(&encrypted_hex)
        .fetch_one(pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(row)
    }

    /// Delete a remote instance (only if it belongs to `user_id`).
    pub async fn delete(pool: &PgPool, id: Uuid, user_id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM remote_instances WHERE id = $1 AND user_id = $2")
            .bind(id)
            .bind(user_id)
            .execute(pool)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Remote instance not found".into()));
        }
        Ok(())
    }

    /// Return the (url, decrypted_api_key) for a remote instance.
    pub async fn get_decrypted(pool: &PgPool, id: Uuid, user_id: Uuid) -> Result<(String, String)> {
        let row = sqlx::query(
            "SELECT url, api_key_encrypted FROM remote_instances WHERE id = $1 AND user_id = $2",
        )
        .bind(id)
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Remote instance not found".into()))?;

        let url: String = row.get("url");
        let api_key_encrypted: String = row.get("api_key_encrypted");

        let key = encryption_key();
        let encrypted_bytes = hex::decode(&api_key_encrypted)
            .map_err(|e| AppError::Internal(format!("Failed to decode encrypted key: {e}")))?;
        let api_key = decrypt_credentials(&encrypted_bytes, &key)
            .map_err(|e| AppError::Internal(format!("Failed to decrypt API key: {e}")))?;

        Ok((url, api_key))
    }
}
