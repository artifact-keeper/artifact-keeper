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
            return Err(AppError::NotFound(
                "Device session not found or expired".into(),
            ));
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

#[cfg(test)]
mod tests {
    use super::*;

    const USER_CODE_ALPHABET: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ";

    async fn seed_oidc_provider(pool: &PgPool, enabled: bool) -> Uuid {
        let id = Uuid::new_v4();
        let name = format!("oidc-device-provider-{id}");
        sqlx::query(
            r#"
            INSERT INTO oidc_configs
                (id, name, issuer_url, client_id, client_secret_encrypted,
                 scopes, attribute_mapping, is_enabled)
            VALUES ($1, $2, $3, $4, $5, $6, '{}'::jsonb, $7)
            "#,
        )
        .bind(id)
        .bind(name)
        .bind(format!("https://issuer-{id}.example.com"))
        .bind(format!("client-{id}"))
        .bind("encrypted-secret")
        .bind(vec!["openid".to_string(), "profile".to_string()])
        .bind(enabled)
        .execute(pool)
        .await
        .expect("seed oidc provider");
        id
    }

    async fn seed_user(pool: &PgPool) -> Uuid {
        let id = Uuid::new_v4();
        let username = format!("oidc-device-user-{id}");
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

    async fn expire_session(pool: &PgPool, session_id: Uuid) {
        sqlx::query(
            "UPDATE oidc_device_sessions SET expires_at = now() - interval '1 second' WHERE id = $1",
        )
        .bind(session_id)
        .execute(pool)
        .await
        .expect("expire session");
    }

    async fn allow_next_poll(pool: &PgPool, session_id: Uuid) {
        sqlx::query(
            "UPDATE oidc_device_sessions SET last_polled_at = now() - interval '10 seconds' WHERE id = $1",
        )
        .bind(session_id)
        .execute(pool)
        .await
        .expect("age poll timestamp");
    }

    async fn cleanup_provider(pool: &PgPool, provider_id: Uuid) {
        let _ = sqlx::query("DELETE FROM oidc_device_sessions WHERE provider_id = $1")
            .bind(provider_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM oidc_configs WHERE id = $1")
            .bind(provider_id)
            .execute(pool)
            .await;
    }

    async fn cleanup_user(pool: &PgPool, user_id: Uuid) {
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(pool)
            .await;
    }

    #[test]
    fn oidc_device_generated_codes_have_rfc_friendly_shapes() {
        let device_code = OidcDeviceService::generate_device_code();
        assert_eq!(device_code.len(), 64);
        assert!(device_code.chars().all(|c| c.is_ascii_hexdigit()));

        for _ in 0..100 {
            let user_code = OidcDeviceService::generate_user_code();
            assert_eq!(user_code.len(), 9);
            assert_eq!(user_code.as_bytes()[4], b'-');
            assert!(user_code
                .chars()
                .filter(|c| *c != '-')
                .all(|c| USER_CODE_ALPHABET.contains(c)));
        }
    }

    #[tokio::test]
    async fn oidc_device_create_session_persists_pending_codes_and_scopes() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let provider_id = seed_oidc_provider(&pool, true).await;
        let svc = OidcDeviceService::new(pool.clone());
        let scopes = vec![
            "openid".to_string(),
            "profile".to_string(),
            "read:artifacts".to_string(),
        ];

        let session = svc
            .create_session(
                provider_id,
                "device-client".to_string(),
                scopes.clone(),
                "https://registry.example.com/",
            )
            .await
            .expect("create device session");

        assert_eq!(session.provider_id, provider_id);
        assert_eq!(
            session.verification_uri,
            "https://registry.example.com/device"
        );
        assert_eq!(session.interval_secs, 5);
        assert_eq!(session.status, "pending");
        assert_eq!(session.scopes, scopes);
        assert_eq!(session.client_id, "device-client");
        assert!(session.expires_at > Utc::now());
        assert_eq!(session.device_code.len(), 64);
        assert!(session.device_code.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(session.user_code.len(), 9);
        assert_eq!(session.user_code.as_bytes()[4], b'-');

        let persisted: (String, Vec<String>, i32, i32) = sqlx::query_as(
            "SELECT status, scopes, interval_secs, poll_count FROM oidc_device_sessions WHERE id = $1",
        )
        .bind(session.id)
        .fetch_one(&pool)
        .await
        .expect("load persisted session");
        assert_eq!(persisted.0, "pending");
        assert_eq!(persisted.1, scopes);
        assert_eq!(persisted.2, 5);
        assert_eq!(persisted.3, 0);

        cleanup_provider(&pool, provider_id).await;
    }

    #[tokio::test]
    async fn oidc_device_poll_token_state_machine_covers_pending_slowdown_and_terminal_states() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let provider_id = seed_oidc_provider(&pool, true).await;
        let user_id = seed_user(&pool).await;
        let svc = OidcDeviceService::new(pool.clone());

        let pending = svc
            .create_session(
                provider_id,
                "state-client".to_string(),
                vec!["openid".to_string()],
                "https://registry.example.com",
            )
            .await
            .expect("create pending session");
        assert!(matches!(
            svc.poll_token(&pending.device_code, "state-client")
                .await
                .expect("poll pending"),
            DevicePollResult::Pending
        ));
        assert!(matches!(
            svc.poll_token(&pending.device_code, "state-client")
                .await
                .expect("poll too quickly"),
            DevicePollResult::SlowDown
        ));
        svc.approve_session(
            &pending.user_code,
            user_id,
            "oidc-sub".to_string(),
            "user@example.com".to_string(),
            "Example User".to_string(),
        )
        .await
        .expect("approve session");
        allow_next_poll(&pool, pending.id).await;
        match svc
            .poll_token(&pending.device_code, "state-client")
            .await
            .expect("poll approved")
        {
            DevicePollResult::Approved { user_id: approved } => assert_eq!(approved, user_id),
            other => panic!("expected approved, got {other:?}"),
        }

        let denied = svc
            .create_session(
                provider_id,
                "state-client".to_string(),
                vec!["openid".to_string()],
                "https://registry.example.com",
            )
            .await
            .expect("create denied session");
        svc.deny_session(&denied.user_code)
            .await
            .expect("deny session");
        assert!(matches!(
            svc.poll_token(&denied.device_code, "state-client")
                .await
                .expect("poll denied"),
            DevicePollResult::Denied
        ));

        let expired = svc
            .create_session(
                provider_id,
                "state-client".to_string(),
                vec!["openid".to_string()],
                "https://registry.example.com",
            )
            .await
            .expect("create expired session");
        expire_session(&pool, expired.id).await;
        assert!(matches!(
            svc.poll_token(&expired.device_code, "state-client")
                .await
                .expect("poll expired"),
            DevicePollResult::Expired
        ));
        assert!(matches!(
            svc.poll_token("missing-device-code", "state-client")
                .await
                .expect("poll missing"),
            DevicePollResult::Expired
        ));

        let missing = svc
            .approve_session(
                "NOPE-NOPE",
                user_id,
                "sub".to_string(),
                "email@example.com".to_string(),
                "Name".to_string(),
            )
            .await;
        assert!(matches!(missing, Err(AppError::NotFound(_))));

        cleanup_provider(&pool, provider_id).await;
        cleanup_user(&pool, user_id).await;
    }

    #[tokio::test]
    async fn oidc_device_cleanup_expired_removes_old_sessions() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let provider_id = seed_oidc_provider(&pool, true).await;
        let svc = OidcDeviceService::new(pool.clone());
        let expired = svc
            .create_session(
                provider_id,
                "cleanup-client".to_string(),
                vec!["openid".to_string()],
                "https://registry.example.com",
            )
            .await
            .expect("create expired cleanup session");
        let active = svc
            .create_session(
                provider_id,
                "cleanup-client".to_string(),
                vec!["openid".to_string()],
                "https://registry.example.com",
            )
            .await
            .expect("create active cleanup session");
        expire_session(&pool, expired.id).await;

        let removed = svc.cleanup_expired().await.expect("cleanup expired");
        assert!(removed >= 1);

        let expired_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM oidc_device_sessions WHERE id = $1")
                .bind(expired.id)
                .fetch_one(&pool)
                .await
                .expect("count expired session");
        let active_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM oidc_device_sessions WHERE id = $1")
                .bind(active.id)
                .fetch_one(&pool)
                .await
                .expect("count active session");
        assert_eq!(expired_count, 0);
        assert_eq!(active_count, 1);

        cleanup_provider(&pool, provider_id).await;
    }
}
