//! Device Authorization Grant (RFC 8628) session store (#3461).
//!
//! A headless client asks for a device code and a short user code
//! ([`DeviceService::create_session`]). The user types the user code into the
//! `/device` page of a signed-in browser session, which approves or denies it
//! ([`DeviceService::approve`], [`DeviceService::deny`]). The client meanwhile
//! polls with the device code ([`DeviceService::poll`]) and, once approved,
//! redeems it exactly once for AK tokens.
//!
//! Every state transition is a single conditional `UPDATE ... RETURNING`, so
//! two concurrent requests can never both win the same transition (two
//! approvals, or two redemptions of one approval). All time comparisons use
//! the database clock, so replicas with skewed clocks agree on expiry and on
//! the polling interval.

use chrono::{DateTime, Utc};
use rand::RngExt;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};

/// User-code alphabet: the 20 consonants RFC 8628 §6.1 suggests. No vowels
/// (so a code cannot spell a word) and no digits (no 0/O or 1/I confusion).
pub const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";
/// Characters in a user code, excluding the display hyphen. 20^8 ≈ 2^34.6
/// codes; with the failed-attempt throttle and a short lifetime this meets
/// the RFC 8628 §5.1 guidance for online guessing.
pub const USER_CODE_LEN: usize = 8;
/// Seconds added to a device code's polling interval on every `slow_down`
/// (RFC 8628 §3.5).
pub const SLOW_DOWN_INCREMENT_SECS: i32 = 5;
/// Ceiling for the per-code polling interval after repeated `slow_down`s.
pub const MAX_INTERVAL_SECS: i32 = 60;
/// Unexpired device authorizations allowed at once, instance-wide. The
/// per-IP limiter bounds each client; this bounds the table (and so the
/// number of live user codes a guesser could hit) against many clients.
pub const MAX_LIVE_SESSIONS: i64 = 10_000;

/// A stored device authorization. Neither code is present: only digests are
/// stored.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DeviceSession {
    pub id: Uuid,
    pub client_id: String,
    pub requested_scopes: Vec<String>,
    pub status: String,
    pub decided_by_user_id: Option<Uuid>,
    pub granted_scopes: Option<Vec<String>>,
    pub allowed_repo_ids: Option<Vec<Uuid>>,
    pub interval_secs: i32,
    pub expires_at: DateTime<Utc>,
    pub last_polled_at: Option<DateTime<Utc>>,
    pub poll_count: i32,
    pub decided_at: Option<DateTime<Utc>>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// A freshly created session plus the two plaintext codes, which exist only
/// in this value and in the response to the client.
#[derive(Debug)]
pub struct NewDeviceSession {
    pub session: DeviceSession,
    pub device_code: String,
    /// Display form, `XXXX-XXXX`.
    pub user_code: String,
}

/// Result of one token poll, mapped by the handler onto the RFC 8628 §3.5
/// responses.
#[derive(Debug)]
pub enum PollOutcome {
    /// No session for this device code and client (`invalid_grant`).
    Invalid,
    /// The code was already redeemed, or a concurrent poll redeemed it first
    /// (`invalid_grant`). Carries the session for the audit trail.
    Replayed(DeviceSession),
    /// The code expired before it was redeemed (`expired_token`).
    Expired,
    /// The user denied the request (`access_denied`).
    Denied,
    /// Polled before the interval elapsed. The interval has been raised to
    /// the carried value (`slow_down`).
    SlowDown { interval_secs: i32 },
    /// Not yet approved (`authorization_pending`).
    Pending,
    /// Approved and now consumed by this poll: mint tokens from it.
    Redeemed(DeviceSession),
}

/// An approved authorization deleted by the expiry sweep before anyone
/// redeemed it.
#[derive(Debug, sqlx::FromRow)]
pub struct ExpiredApproval {
    pub id: Uuid,
    pub client_id: String,
    pub decided_by_user_id: Option<Uuid>,
}

pub struct DeviceService {
    pub db: PgPool,
}

/// SHA-256 digest (hex) under which a code is stored and looked up.
fn code_digest(code: &str) -> String {
    hex::encode(Sha256::digest(code.as_bytes()))
}

/// Canonicalise user input into the stored user-code form: case-folded, with
/// the display hyphen and any other separators removed. Returns `None` for
/// anything that cannot be a user code, so malformed input never reaches the
/// database (RFC 8628 §6.1: be lenient about case and punctuation).
pub fn normalize_user_code(input: &str) -> Option<String> {
    if input.len() > 64 {
        return None;
    }
    let code: String = input
        .chars()
        .filter(|c| !matches!(c, '-' | ' ' | '\t'))
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let valid =
        code.len() == USER_CODE_LEN && code.bytes().all(|b| USER_CODE_ALPHABET.contains(&b));
    valid.then_some(code)
}

/// Display form of a canonical user code: `BCDF-GHJK`.
pub fn format_user_code(code: &str) -> String {
    let (head, tail) = code.split_at(code.len() / 2);
    format!("{head}-{tail}")
}

impl DeviceService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// 32 random bytes, hex-encoded: 256 bits, never guessable, and never
    /// typed by a human.
    fn generate_device_code() -> String {
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        hex::encode(bytes)
    }

    /// A canonical user code: [`USER_CODE_LEN`] characters drawn uniformly
    /// from [`USER_CODE_ALPHABET`] (`random_range` rejects rather than
    /// taking a biased modulus).
    fn generate_user_code() -> String {
        let mut rng = rand::rng();
        (0..USER_CODE_LEN)
            .map(|_| USER_CODE_ALPHABET[rng.random_range(0..USER_CODE_ALPHABET.len())] as char)
            .collect()
    }

    /// Start a device authorization. `scopes` must already be validated.
    ///
    /// Refuses with `ServiceUnavailable` once [`MAX_LIVE_SESSIONS`] unexpired
    /// authorizations exist. A user-code collision (possible, if rare, since
    /// the digest is `UNIQUE`) is retried with fresh codes.
    pub async fn create_session(
        &self,
        client_id: &str,
        scopes: &[String],
        ttl_secs: u32,
        interval_secs: u32,
    ) -> Result<NewDeviceSession> {
        let live: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM device_sessions WHERE expires_at > now()")
                .fetch_one(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
        if live >= MAX_LIVE_SESSIONS {
            return Err(AppError::ServiceUnavailable(
                "Too many device authorizations are in progress. Retry later.".into(),
            ));
        }

        for _ in 0..5 {
            let device_code = Self::generate_device_code();
            let user_code = Self::generate_user_code();
            let inserted = sqlx::query_as::<_, DeviceSession>(
                r#"
                INSERT INTO device_sessions
                    (device_code_hash, user_code_hash, client_id, requested_scopes,
                     interval_secs, expires_at)
                VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6))
                ON CONFLICT DO NOTHING
                RETURNING id, client_id, requested_scopes, status, decided_by_user_id,
                          granted_scopes, allowed_repo_ids, interval_secs, expires_at,
                          last_polled_at, poll_count, decided_at, consumed_at, created_at
                "#,
            )
            .bind(code_digest(&device_code))
            .bind(code_digest(&user_code))
            .bind(client_id)
            .bind(scopes)
            .bind(interval_secs as i32)
            .bind(f64::from(ttl_secs))
            .fetch_optional(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
            if let Some(session) = inserted {
                return Ok(NewDeviceSession {
                    session,
                    device_code,
                    user_code: format_user_code(&user_code),
                });
            }
        }
        Err(AppError::Internal(
            "Could not allocate a unique device user code".into(),
        ))
    }

    /// The pending, unexpired session for a canonical user code, if any.
    pub async fn find_pending(&self, user_code: &str) -> Result<Option<DeviceSession>> {
        sqlx::query_as::<_, DeviceSession>(
            r#"
            SELECT id, client_id, requested_scopes, status, decided_by_user_id,
                   granted_scopes, allowed_repo_ids, interval_secs, expires_at,
                   last_polled_at, poll_count, decided_at, consumed_at, created_at
            FROM device_sessions
            WHERE user_code_hash = $1 AND status = 'pending' AND expires_at > now()
            "#,
        )
        .bind(code_digest(user_code))
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    /// Approve pending session `id` for `user_id` with the already-capped
    /// `granted_scopes`. Returns `false` if the session is no longer pending
    /// and unexpired (a concurrent approval or denial won, or it expired).
    pub async fn approve(
        &self,
        id: Uuid,
        user_id: Uuid,
        granted_scopes: &[String],
        allowed_repo_ids: Option<&[Uuid]>,
    ) -> Result<bool> {
        let rows = sqlx::query(
            r#"
            UPDATE device_sessions
            SET status = 'approved',
                decided_by_user_id = $2,
                decided_at = now(),
                granted_scopes = $3,
                allowed_repo_ids = $4
            WHERE id = $1 AND status = 'pending' AND expires_at > now()
            "#,
        )
        .bind(id)
        .bind(user_id)
        .bind(granted_scopes)
        .bind(allowed_repo_ids)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .rows_affected();
        Ok(rows == 1)
    }

    /// Deny the pending session for a canonical user code. Returns the
    /// session id, or `None` when there is no pending, unexpired session.
    pub async fn deny(&self, user_code: &str, user_id: Uuid) -> Result<Option<Uuid>> {
        sqlx::query_scalar(
            r#"
            UPDATE device_sessions
            SET status = 'denied', decided_by_user_id = $2, decided_at = now()
            WHERE user_code_hash = $1 AND status = 'pending' AND expires_at > now()
            RETURNING id
            "#,
        )
        .bind(code_digest(user_code))
        .bind(user_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))
    }

    /// One RFC 8628 §3.4 token poll.
    ///
    /// 1. Claim the polling window: a single `UPDATE` that succeeds only for a
    ///    live pending/approved session whose interval has elapsed (with one
    ///    second of grace for network jitter). Concurrent polls serialize on
    ///    the row, so at most one per interval gets through.
    /// 2. If the claimed session is approved, consume it with a second
    ///    conditional `UPDATE ... WHERE status = 'approved' RETURNING`. Only
    ///    one caller can flip a row to `consumed`, so a device code yields
    ///    tokens at most once.
    /// 3. If the claim failed, classify why. A poll that arrived too early
    ///    raises the interval by [`SLOW_DOWN_INCREMENT_SECS`] and restarts the
    ///    window, as §3.5 requires ("for this and all subsequent requests").
    pub async fn poll(&self, device_code: &str, client_id: &str) -> Result<PollOutcome> {
        let digest = code_digest(device_code);

        let claimed: Option<String> = sqlx::query_scalar(
            r#"
            UPDATE device_sessions
            SET last_polled_at = now(), poll_count = poll_count + 1
            WHERE device_code_hash = $1 AND client_id = $2
              AND status IN ('pending', 'approved')
              AND expires_at > now()
              AND (last_polled_at IS NULL
                   OR last_polled_at + make_interval(secs => interval_secs - 1) <= now())
            RETURNING status
            "#,
        )
        .bind(&digest)
        .bind(client_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        match claimed.as_deref() {
            Some("pending") => return Ok(PollOutcome::Pending),
            Some(_) => {
                let redeemed = sqlx::query_as::<_, DeviceSession>(
                    r#"
                    UPDATE device_sessions
                    SET status = 'consumed', consumed_at = now()
                    WHERE device_code_hash = $1 AND client_id = $2
                      AND status = 'approved' AND expires_at > now()
                    RETURNING id, client_id, requested_scopes, status, decided_by_user_id,
                              granted_scopes, allowed_repo_ids, interval_secs, expires_at,
                              last_polled_at, poll_count, decided_at, consumed_at, created_at
                    "#,
                )
                .bind(&digest)
                .bind(client_id)
                .fetch_optional(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
                if let Some(session) = redeemed {
                    return Ok(PollOutcome::Redeemed(session));
                }
                // Lost a race with a concurrent redemption: fall through and
                // classify the (now consumed) row.
            }
            None => {}
        }

        #[derive(sqlx::FromRow)]
        struct Classified {
            #[sqlx(flatten)]
            session: DeviceSession,
            expired: bool,
        }
        let row = sqlx::query_as::<_, Classified>(
            r#"
            SELECT id, client_id, requested_scopes, status, decided_by_user_id,
                   granted_scopes, allowed_repo_ids, interval_secs, expires_at,
                   last_polled_at, poll_count, decided_at, consumed_at, created_at,
                   expires_at <= now() AS expired
            FROM device_sessions
            WHERE device_code_hash = $1 AND client_id = $2
            "#,
        )
        .bind(&digest)
        .bind(client_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let Some(row) = row else {
            return Ok(PollOutcome::Invalid);
        };
        if row.session.status == "consumed" {
            return Ok(PollOutcome::Replayed(row.session));
        }
        if row.expired {
            return Ok(PollOutcome::Expired);
        }
        if row.session.status == "denied" {
            return Ok(PollOutcome::Denied);
        }

        let interval_secs: i32 = sqlx::query_scalar(
            r#"
            UPDATE device_sessions
            SET interval_secs = LEAST(interval_secs + $2, $3), last_polled_at = now()
            WHERE id = $1
            RETURNING interval_secs
            "#,
        )
        .bind(row.session.id)
        .bind(SLOW_DOWN_INCREMENT_SECS)
        .bind(MAX_INTERVAL_SECS)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(PollOutcome::SlowDown { interval_secs })
    }

    /// Delete expired sessions. Returns how many rows were removed and the
    /// approved-but-never-redeemed ones among them, which the caller audits.
    pub async fn cleanup_expired(&self) -> Result<(u64, Vec<ExpiredApproval>)> {
        #[derive(sqlx::FromRow)]
        struct Deleted {
            #[sqlx(flatten)]
            approval: ExpiredApproval,
            status: String,
        }
        let deleted = sqlx::query_as::<_, Deleted>(
            r#"
            DELETE FROM device_sessions
            WHERE expires_at < now()
            RETURNING id, client_id, decided_by_user_id, status
            "#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        let total = deleted.len() as u64;
        let unredeemed = deleted
            .into_iter()
            .filter(|row| row.status == "approved")
            .map(|row| row.approval)
            .collect();
        Ok((total, unredeemed))
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    async fn seed_user(pool: &PgPool) -> Uuid {
        crate::api::handlers::test_db_helpers::create_user(pool)
            .await
            .0
    }

    async fn cleanup_user(pool: &PgPool, user_id: Uuid) {
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(pool)
            .await
            .expect("cleanup user");
    }

    fn scopes(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// Canonical form of a display user code.
    fn canon(display: &str) -> String {
        normalize_user_code(display).expect("generated user code normalizes")
    }

    #[test]
    fn generated_codes_have_the_documented_shape() {
        let device_code = DeviceService::generate_device_code();
        assert_eq!(device_code.len(), 64);
        assert!(device_code.bytes().all(|b| b.is_ascii_hexdigit()));

        for _ in 0..200 {
            let code = DeviceService::generate_user_code();
            assert_eq!(code.len(), USER_CODE_LEN);
            assert!(code.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)));
            let display = format_user_code(&code);
            assert_eq!(display.as_bytes()[4], b'-');
            assert_eq!(
                normalize_user_code(&display).as_deref(),
                Some(code.as_str())
            );
        }
    }

    #[test]
    fn user_code_alphabet_has_no_vowels_or_digits() {
        assert_eq!(USER_CODE_ALPHABET.len(), 20);
        for b in USER_CODE_ALPHABET {
            assert!(b.is_ascii_uppercase());
            assert!(!b"AEIOUY".contains(b));
        }
    }

    #[test]
    fn normalize_user_code_is_lenient_about_case_and_separators_only() {
        assert_eq!(
            normalize_user_code("bcdf-ghjk").as_deref(),
            Some("BCDFGHJK")
        );
        assert_eq!(
            normalize_user_code(" BCDF GHJK ").as_deref(),
            Some("BCDFGHJK")
        );
        assert_eq!(normalize_user_code("BCDFGHJK").as_deref(), Some("BCDFGHJK"));
        // Wrong length, characters outside the alphabet, and oversized input
        // are refused before any lookup.
        assert_eq!(normalize_user_code("BCDF-GHJ"), None);
        assert_eq!(normalize_user_code("BCDF-GHJKL"), None);
        assert_eq!(normalize_user_code("ABCD-EFGH"), None);
        assert_eq!(normalize_user_code("BCDF-GHJ1"), None);
        assert_eq!(normalize_user_code("BCDF_GHJK"), None);
        assert_eq!(normalize_user_code(&"-".repeat(65)), None);
        assert_eq!(normalize_user_code(""), None);
    }

    #[test]
    fn code_digest_is_sha256_hex() {
        assert_eq!(
            code_digest("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[tokio::test]
    async fn codes_are_stored_only_as_digests() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let service = DeviceService::new(pool.clone());
        let created = service
            .create_session("digest-client", &scopes(&["read:artifacts"]), 600, 5)
            .await
            .expect("create session");

        let (device_hash, user_hash): (String, String) = sqlx::query_as(
            "SELECT device_code_hash, user_code_hash FROM device_sessions WHERE id = $1",
        )
        .bind(created.session.id)
        .fetch_one(&pool)
        .await
        .expect("load digests");
        assert_eq!(device_hash, code_digest(&created.device_code));
        assert_eq!(user_hash, code_digest(&canon(&created.user_code)));
        assert_ne!(device_hash, created.device_code);
    }

    #[tokio::test]
    async fn approved_code_is_redeemed_exactly_once() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let user_id = seed_user(&pool).await;
        let service = DeviceService::new(pool.clone());
        let created = service
            .create_session("once-client", &scopes(&["read:artifacts"]), 600, 1)
            .await
            .expect("create session");
        let pending = service
            .find_pending(&canon(&created.user_code))
            .await
            .expect("find")
            .expect("pending session");
        assert!(service
            .approve(pending.id, user_id, &scopes(&["read:artifacts"]), None)
            .await
            .expect("approve"));

        match service
            .poll(&created.device_code, "once-client")
            .await
            .expect("first poll")
        {
            PollOutcome::Redeemed(session) => {
                assert_eq!(session.status, "consumed");
                assert!(session.consumed_at.is_some());
                assert_eq!(session.decided_by_user_id, Some(user_id));
                assert_eq!(session.granted_scopes, Some(scopes(&["read:artifacts"])));
            }
            other => panic!("expected Redeemed, got {other:?}"),
        }
        // Every later poll is a replay, whatever the interval.
        for _ in 0..3 {
            let outcome = service
                .poll(&created.device_code, "once-client")
                .await
                .expect("replayed poll");
            assert!(matches!(outcome, PollOutcome::Replayed(_)), "{outcome:?}");
        }

        cleanup_user(&pool, user_id).await;
    }

    #[tokio::test]
    async fn concurrent_redemptions_yield_one_winner() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let user_id = seed_user(&pool).await;
        let service = DeviceService::new(pool.clone());
        let created = service
            .create_session("race-client", &scopes(&["read:artifacts"]), 600, 1)
            .await
            .expect("create session");
        let pending = service
            .find_pending(&canon(&created.user_code))
            .await
            .expect("find")
            .expect("pending");
        assert!(service
            .approve(pending.id, user_id, &scopes(&["read:artifacts"]), None)
            .await
            .expect("approve"));

        let mut handles = Vec::new();
        for _ in 0..8 {
            let service = DeviceService::new(pool.clone());
            let code = created.device_code.clone();
            handles.push(tokio::spawn(async move {
                service.poll(&code, "race-client").await.expect("poll")
            }));
        }
        let mut redeemed = 0;
        for handle in handles {
            if matches!(handle.await.expect("join"), PollOutcome::Redeemed(_)) {
                redeemed += 1;
            }
        }
        assert_eq!(redeemed, 1, "exactly one concurrent poll may redeem");

        cleanup_user(&pool, user_id).await;
    }

    #[tokio::test]
    async fn early_poll_gets_slow_down_and_a_longer_interval() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let service = DeviceService::new(pool.clone());
        let created = service
            .create_session("slow-client", &scopes(&["read:artifacts"]), 600, 5)
            .await
            .expect("create session");

        assert!(matches!(
            service
                .poll(&created.device_code, "slow-client")
                .await
                .unwrap(),
            PollOutcome::Pending
        ));
        // Immediately again: inside the 5 s interval.
        match service
            .poll(&created.device_code, "slow-client")
            .await
            .unwrap()
        {
            PollOutcome::SlowDown { interval_secs } => assert_eq!(interval_secs, 10),
            other => panic!("expected SlowDown, got {other:?}"),
        }
        match service
            .poll(&created.device_code, "slow-client")
            .await
            .unwrap()
        {
            PollOutcome::SlowDown { interval_secs } => assert_eq!(interval_secs, 15),
            other => panic!("expected SlowDown, got {other:?}"),
        }

        // The increase is capped.
        sqlx::query("UPDATE device_sessions SET interval_secs = $2 WHERE id = $1")
            .bind(created.session.id)
            .bind(MAX_INTERVAL_SECS)
            .execute(&pool)
            .await
            .unwrap();
        match service
            .poll(&created.device_code, "slow-client")
            .await
            .unwrap()
        {
            PollOutcome::SlowDown { interval_secs } => assert_eq!(interval_secs, MAX_INTERVAL_SECS),
            other => panic!("expected SlowDown, got {other:?}"),
        }

        // Once the interval has passed the client is served again.
        sqlx::query(
            "UPDATE device_sessions SET last_polled_at = now() - interval '2 minutes' WHERE id = $1",
        )
        .bind(created.session.id)
        .execute(&pool)
        .await
        .unwrap();
        assert!(matches!(
            service
                .poll(&created.device_code, "slow-client")
                .await
                .unwrap(),
            PollOutcome::Pending
        ));
    }

    #[tokio::test]
    async fn expired_denied_and_unknown_codes_are_classified() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let user_id = seed_user(&pool).await;
        let service = DeviceService::new(pool.clone());

        // Unknown device code, and a real code presented by another client.
        let created = service
            .create_session("bound-client", &scopes(&["read:artifacts"]), 600, 1)
            .await
            .expect("create session");
        assert!(matches!(
            service.poll(&"0".repeat(64), "bound-client").await.unwrap(),
            PollOutcome::Invalid
        ));
        assert!(matches!(
            service
                .poll(&created.device_code, "other-client")
                .await
                .unwrap(),
            PollOutcome::Invalid
        ));

        // Denied.
        let denied = service
            .deny(&canon(&created.user_code), user_id)
            .await
            .expect("deny");
        assert_eq!(denied, Some(created.session.id));
        assert!(matches!(
            service
                .poll(&created.device_code, "bound-client")
                .await
                .unwrap(),
            PollOutcome::Denied
        ));
        // A decided code cannot be decided again.
        assert!(service
            .deny(&canon(&created.user_code), user_id)
            .await
            .unwrap()
            .is_none());
        assert!(service
            .find_pending(&canon(&created.user_code))
            .await
            .unwrap()
            .is_none());

        // Expired, even after approval: not redeemable, not approvable.
        let expiring = service
            .create_session("bound-client", &scopes(&["read:artifacts"]), 600, 1)
            .await
            .expect("create session");
        let pending = service
            .find_pending(&canon(&expiring.user_code))
            .await
            .unwrap()
            .expect("pending");
        assert!(service
            .approve(pending.id, user_id, &scopes(&["read:artifacts"]), None)
            .await
            .unwrap());
        sqlx::query(
            "UPDATE device_sessions SET expires_at = now() - interval '1 second' WHERE id = $1",
        )
        .bind(expiring.session.id)
        .execute(&pool)
        .await
        .unwrap();
        assert!(matches!(
            service
                .poll(&expiring.device_code, "bound-client")
                .await
                .unwrap(),
            PollOutcome::Expired
        ));

        // An expired pending code cannot be approved either.
        let stale = service
            .create_session("bound-client", &scopes(&["read:artifacts"]), 600, 1)
            .await
            .expect("create session");
        sqlx::query(
            "UPDATE device_sessions SET expires_at = now() - interval '1 second' WHERE id = $1",
        )
        .bind(stale.session.id)
        .execute(&pool)
        .await
        .unwrap();
        assert!(service
            .find_pending(&canon(&stale.user_code))
            .await
            .unwrap()
            .is_none());
        assert!(!service
            .approve(
                stale.session.id,
                user_id,
                &scopes(&["read:artifacts"]),
                None
            )
            .await
            .unwrap());

        // The sweep removes both expired rows and reports the approved one
        // that nobody redeemed.
        let (removed, unredeemed) = service.cleanup_expired().await.expect("cleanup");
        assert!(removed >= 2);
        assert!(unredeemed
            .iter()
            .any(|a| a.id == expiring.session.id && a.decided_by_user_id == Some(user_id)));
        assert!(!unredeemed.iter().any(|a| a.id == stale.session.id));
        let left: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM device_sessions WHERE id = ANY($1)")
                .bind(vec![expiring.session.id, stale.session.id])
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(left, 0);

        cleanup_user(&pool, user_id).await;
    }

    #[tokio::test]
    async fn approval_cannot_be_overwritten() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let first = seed_user(&pool).await;
        let second = seed_user(&pool).await;
        let service = DeviceService::new(pool.clone());
        let created = service
            .create_session("overwrite-client", &scopes(&["read:artifacts"]), 600, 1)
            .await
            .expect("create session");
        assert!(service
            .approve(
                created.session.id,
                first,
                &scopes(&["read:artifacts"]),
                None
            )
            .await
            .unwrap());
        assert!(!service
            .approve(
                created.session.id,
                second,
                &scopes(&["read:artifacts"]),
                None
            )
            .await
            .unwrap());
        assert!(service
            .deny(&canon(&created.user_code), second)
            .await
            .unwrap()
            .is_none());
        let decided: Option<Uuid> =
            sqlx::query_scalar("SELECT decided_by_user_id FROM device_sessions WHERE id = $1")
                .bind(created.session.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(decided, Some(first));

        cleanup_user(&pool, first).await;
        cleanup_user(&pool, second).await;
    }

    #[tokio::test]
    async fn deleting_the_approver_deletes_the_approval() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let user_id = seed_user(&pool).await;
        let service = DeviceService::new(pool.clone());
        let created = service
            .create_session("cascade-client", &scopes(&["read:artifacts"]), 600, 1)
            .await
            .expect("create session");
        assert!(service
            .approve(
                created.session.id,
                user_id,
                &scopes(&["read:artifacts"]),
                None
            )
            .await
            .unwrap());
        cleanup_user(&pool, user_id).await;
        assert!(matches!(
            service
                .poll(&created.device_code, "cascade-client")
                .await
                .unwrap(),
            PollOutcome::Invalid
        ));
    }
}
