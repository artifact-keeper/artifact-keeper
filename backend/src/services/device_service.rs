//! Device Authorization Grant (RFC 8628) session management.

use chrono::{DateTime, Utc};
use rand::RngCore;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DeviceSession {
    pub id: Uuid,
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_at: DateTime<Utc>,
    pub interval_secs: i32,
    pub status: String,
    pub scopes: Vec<String>,
    pub client_id: String,
    pub approved_user_id: Option<Uuid>,
    pub allowed_repo_ids: Option<Vec<Uuid>>,
    pub consumed_at: Option<DateTime<Utc>>,
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
    Expired,
}

pub struct DeviceService {
    pub db: PgPool,
}

impl DeviceService {
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
        client_id: String,
        scopes: Vec<String>,
        base_url: &str,
    ) -> Result<DeviceSession> {
        let device_code = Self::generate_device_code();
        let user_code = Self::generate_user_code();
        let verification_uri = format!("{}/device", base_url.trim_end_matches('/'));
        let expires_at = Utc::now() + chrono::Duration::seconds(600);

        let session = sqlx::query_as::<_, DeviceSession>(
            r#"
            INSERT INTO device_sessions
                (device_code, user_code, verification_uri,
                 expires_at, interval_secs, status, scopes, client_id)
            VALUES ($1, $2, $3, $4, 5, 'pending', $5, $6)
            RETURNING *
            "#,
        )
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
        let session = sqlx::query_as::<_, DeviceSession>(
            "SELECT * FROM device_sessions WHERE device_code = $1 AND client_id = $2",
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
                // Do not move the polling window on rejected requests.
                return Ok(DevicePollResult::SlowDown);
            }
        }

        // Update polling metadata
        sqlx::query(
            "UPDATE device_sessions SET last_polled_at = $1, poll_count = poll_count + 1, updated_at = now() WHERE id = $2",
        )
        .bind(now)
        .bind(session.id)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        match session.status.as_str() {
            "pending" => Ok(DevicePollResult::Pending),
            "approved" => {
                let user_id = session
                    .approved_user_id
                    .ok_or_else(|| AppError::Internal("approved session missing user_id".into()))?;
                Ok(DevicePollResult::Approved { user_id })
            }
            _ => Ok(DevicePollResult::Expired),
        }
    }

    pub async fn approve_session(
        &self,
        user_code: &str,
        user_id: Uuid,
        allowed_repo_ids: Option<Vec<Uuid>>,
        scope_ceiling: Vec<String>,
    ) -> Result<()> {
        let requested_scopes: Vec<String> =
            sqlx::query_scalar("SELECT scopes FROM device_sessions WHERE user_code = $1 AND status = 'pending' AND expires_at > now()")
                .bind(user_code)
                .fetch_optional(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?
                .ok_or_else(|| AppError::NotFound("Device session not found or expired".into()))?;
        let scopes: Vec<String> = requested_scopes
            .into_iter()
            .filter(|scope| scope_ceiling.iter().any(|allowed| allowed == scope))
            .collect();

        let rows = sqlx::query(
            r#"
            UPDATE device_sessions
            SET status = 'approved',
                approved_user_id = $1,
                allowed_repo_ids = $2,
                scopes = $3,
                updated_at = now()
            WHERE user_code = $4 AND status = 'pending' AND expires_at > now()
            "#,
        )
        .bind(user_id)
        .bind(&allowed_repo_ids)
        .bind(&scopes)
        .bind(user_code)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .rows_affected();

        if rows == 0 {
            return Err(AppError::NotFound(
                "Device session not found or expired".into(),
            ));
        }

        Ok(())
    }

    /// Atomically consume an approved code. Concurrent redemptions can only
    /// cause one row to be returned.
    pub async fn consume_approved(
        &self,
        device_code: &str,
        client_id: &str,
    ) -> Result<Option<DeviceSession>> {
        sqlx::query_as::<_, DeviceSession>(
            "UPDATE device_sessions SET status = 'consumed', consumed_at = now(), updated_at = now()
             WHERE device_code = $1 AND client_id = $2 AND status = 'approved' AND expires_at > now()
             RETURNING *",
        )
        .bind(device_code)
        .bind(client_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    pub async fn cleanup_expired(&self) -> Result<u64> {
        let rows = sqlx::query("DELETE FROM device_sessions WHERE expires_at < now()")
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
            .rows_affected();
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn seed_user(pool: &PgPool) -> Uuid {
        let id = Uuid::new_v4();
        let username = format!("device-user-{id}");
        sqlx::query(
            r#"
            INSERT INTO users (id, username, email, password_hash, auth_provider, is_active, is_admin)
            VALUES ($1, $2, $3, 'unused', 'local', true, false)
            "#,
        )
        .bind(id)
        .bind(&username)
        .bind(format!("{username}@example.com"))
        .execute(pool)
        .await
        .expect("seed user");
        id
    }

    #[test]
    fn generated_codes_are_rfc_friendly() {
        assert_eq!(DeviceService::generate_device_code().len(), 64);
        let code = DeviceService::generate_user_code();
        assert_eq!(code.len(), 9);
        assert_eq!(code.as_bytes()[4], b'-');
    }

    #[tokio::test]
    async fn approved_device_code_is_consumed_once_with_scope_intersection() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let user_id = seed_user(&pool).await;
        let service = DeviceService::new(pool.clone());
        let session = service
            .create_session(
                "test-client".to_string(),
                vec!["read:artifacts".to_string(), "write:artifacts".to_string()],
                "https://registry.example.com",
            )
            .await
            .expect("create session");

        service
            .approve_session(
                &session.user_code,
                user_id,
                Some(vec![Uuid::new_v4()]),
                vec!["read:artifacts".to_string()],
            )
            .await
            .expect("approve session");

        let consumed = service
            .consume_approved(&session.device_code, "test-client")
            .await
            .expect("consume session")
            .expect("first redemption");
        assert_eq!(consumed.status, "consumed");
        assert_eq!(consumed.scopes, vec!["read:artifacts".to_string()]);
        assert!(consumed.consumed_at.is_some());

        let replay = service
            .consume_approved(&session.device_code, "test-client")
            .await
            .expect("repeat consume");
        assert!(replay.is_none());

        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&pool)
            .await
            .expect("cleanup user");
    }
}
