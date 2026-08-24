//! OIDC Device Authorization Grant (RFC 8628) session management.

use chrono::{DateTime, Utc};
use rand::RngCore;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct OidcDeviceSession {
    pub id: Uuid,
    pub provider_id: Uuid,
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_at: DateTime<Utc>,
    pub interval_secs: i32,
    pub status: String,
    pub scopes: Vec<String>,
    pub client_id: String,
    pub oidc_user_sub: Option<String>,
    pub oidc_user_email: Option<String>,
    pub oidc_user_name: Option<String>,
    pub approved_user_id: Option<Uuid>,
    pub last_polled_at: Option<DateTime<Utc>>,
    pub poll_count: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug)]
pub enum DevicePollResult {
    Pending,
    SlowDown,
    Approved { user_id: Uuid },
    Denied,
    Expired,
}

pub struct OidcDeviceService {
    pub db: PgPool,
}

impl OidcDeviceService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Generate a 32-byte random device code (hex-encoded, 64 chars).
    fn generate_device_code() -> String {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        hex::encode(bytes)
    }

    /// Generate an 8-char user-visible code in XXXX-XXXX format (uppercase alpha).
    fn generate_user_code() -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ"; // no I, O to avoid confusion
        let mut bytes = [0u8; 8];
        rand::rng().fill_bytes(&mut bytes);
        let chars: Vec<char> = bytes
            .iter()
            .map(|b| ALPHABET[(*b as usize) % ALPHABET.len()] as char)
            .collect();
        format!(
            "{}{}{}{}-{}{}{}{}",
            chars[0], chars[1], chars[2], chars[3], chars[4], chars[5], chars[6], chars[7]
        )
    }

    pub async fn create_session(
        &self,
        provider_id: Uuid,
        client_id: String,
        scopes: Vec<String>,
        base_url: &str,
    ) -> Result<OidcDeviceSession> {
        let device_code = Self::generate_device_code();
        let user_code = Self::generate_user_code();
        let verification_uri = format!("{}/device", base_url.trim_end_matches('/'));
        let expires_at = Utc::now() + chrono::Duration::seconds(600);

        let session = sqlx::query_as::<_, OidcDeviceSession>(
            r#"
            INSERT INTO oidc_device_sessions
                (provider_id, device_code, user_code, verification_uri,
                 expires_at, interval_secs, status, scopes, client_id)
            VALUES ($1, $2, $3, $4, $5, 5, 'pending', $6, $7)
            RETURNING *
            "#,
        )
        .bind(provider_id)
        .bind(&device_code)
        .bind(&user_code)
        .bind(&verification_uri)
        .bind(expires_at)
        .bind(&scopes)
        .bind(&client_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(session)
    }

    pub async fn poll_token(&self, device_code: &str, client_id: &str) -> Result<DevicePollResult> {
        let session = sqlx::query_as::<_, OidcDeviceSession>(
            "SELECT * FROM oidc_device_sessions WHERE device_code = $1 AND client_id = $2",
        )
        .bind(device_code)
        .bind(client_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let session = match session {
            None => return Ok(DevicePollResult::Expired),
            Some(s) => s,
        };

        if session.expires_at < Utc::now() {
            return Ok(DevicePollResult::Expired);
        }

        // Enforce polling interval (slow_down)
        let now = Utc::now();
        if let Some(last_polled) = session.last_polled_at {
            let elapsed = (now - last_polled).num_seconds();
            if elapsed < session.interval_secs as i64 {
                // Update timestamp but return slow_down
                sqlx::query(
                    "UPDATE oidc_device_sessions SET last_polled_at = $1, poll_count = poll_count + 1, updated_at = now() WHERE id = $2",
                )
                .bind(now)
                .bind(session.id)
                .execute(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
                return Ok(DevicePollResult::SlowDown);
            }
        }

        // Update polling metadata
        sqlx::query(
            "UPDATE oidc_device_sessions SET last_polled_at = $1, poll_count = poll_count + 1, updated_at = now() WHERE id = $2",
        )
        .bind(now)
        .bind(session.id)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        match session.status.as_str() {
            "pending" => Ok(DevicePollResult::Pending),
            "denied" => Ok(DevicePollResult::Denied),
            "approved" => {
                let user_id = session.approved_user_id.ok_or_else(|| {
                    AppError::Internal("approved session missing user_id".into())
                })?;
                Ok(DevicePollResult::Approved { user_id })
            }
            _ => Ok(DevicePollResult::Expired),
        }
    }

    pub async fn approve_session(
        &self,
        user_code: &str,
        user_id: Uuid,
        oidc_sub: String,
        oidc_email: String,
        oidc_name: String,
    ) -> Result<()> {
        let rows = sqlx::query(
            r#"
            UPDATE oidc_device_sessions
            SET status = 'approved',
                approved_user_id = $1,
                oidc_user_sub = $2,
                oidc_user_email = $3,
                oidc_user_name = $4,
                updated_at = now()
            WHERE user_code = $5 AND status = 'pending' AND expires_at > now()
            "#,
        )
        .bind(user_id)
        .bind(&oidc_sub)
        .bind(&oidc_email)
        .bind(&oidc_name)
        .bind(user_code)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .rows_affected();

        if rows == 0 {
            return Err(AppError::NotFound("Device session not found or expired".into()));
        }
        Ok(())
    }

    pub async fn deny_session(&self, user_code: &str) -> Result<()> {
        sqlx::query(
            "UPDATE oidc_device_sessions SET status = 'denied', updated_at = now() WHERE user_code = $1 AND status = 'pending'",
        )
        .bind(user_code)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(())
    }

    pub async fn cleanup_expired(&self) -> Result<u64> {
        let rows = sqlx::query("DELETE FROM oidc_device_sessions WHERE expires_at < now()")
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
            .rows_affected();
        Ok(rows)
    }
}
