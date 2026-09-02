//! Password expiry notification service.
//!
//! Provides pure-function helpers for deciding when to notify users about
//! upcoming password expiration, plus a background task that queries the
//! database and sends emails via `SmtpService`.

use chrono::{DateTime, Duration, Utc};

// ---------------------------------------------------------------------------
// Pure helpers (no I/O, easy to unit-test)
// ---------------------------------------------------------------------------

/// Compute how many days remain until a password expires.
///
/// Returns `None` when password expiration is disabled (`expiry_days == 0`).
/// A negative value means the password has already expired.
pub fn days_until_expiry(
    password_changed_at: DateTime<Utc>,
    expiry_days: u32,
    now: DateTime<Utc>,
) -> Option<i64> {
    if expiry_days == 0 {
        return None;
    }
    let expiry = password_changed_at + Duration::days(expiry_days as i64);
    Some((expiry - now).num_days())
}

/// Determine whether a notification should be sent for a given warning tier.
///
/// Returns `true` when all of these are true:
///   1. Password expiry is enabled (`expiry_days > 0`).
///   2. The remaining days are at or below `warning_days`.
///   3. The password has not already expired (remaining >= 0).
pub fn should_notify(
    password_changed_at: DateTime<Utc>,
    expiry_days: u32,
    warning_days: u32,
    now: DateTime<Utc>,
) -> bool {
    match days_until_expiry(password_changed_at, expiry_days, now) {
        Some(remaining) => remaining >= 0 && remaining <= warning_days as i64,
        None => false,
    }
}

/// Build the plain-text body for a password expiry warning email.
pub fn build_notification_text(username: &str, days_remaining: i64) -> String {
    if days_remaining <= 0 {
        format!(
            "Hello {username},\n\n\
             Your password has expired. Please log in and change your password \
             as soon as possible to avoid losing access to your account.\n\n\
             Artifact Keeper"
        )
    } else if days_remaining == 1 {
        format!(
            "Hello {username},\n\n\
             Your password will expire tomorrow. Please log in and change your \
             password to avoid any disruption.\n\n\
             Artifact Keeper"
        )
    } else {
        format!(
            "Hello {username},\n\n\
             Your password will expire in {days_remaining} days. Please log in \
             and change your password before it expires.\n\n\
             Artifact Keeper"
        )
    }
}

/// Build the HTML body for a password expiry warning email.
pub fn build_notification_html(username: &str, days_remaining: i64) -> String {
    let username = html_escape(username);
    let urgency_note = if days_remaining <= 0 {
        "Your password has <strong>expired</strong>. Please change it immediately.".to_string()
    } else if days_remaining == 1 {
        "Your password will expire <strong>tomorrow</strong>.".to_string()
    } else {
        format!("Your password will expire in <strong>{days_remaining} days</strong>.")
    };

    format!(
        "<h2>Password Expiry Notice</h2>\
         <p>Hello {username},</p>\
         <p>{urgency_note}</p>\
         <p>Please log in and change your password to avoid any disruption to \
         your account access.</p>\
         <p>Artifact Keeper</p>"
    )
}

/// Escape user-controlled text before interpolation into an HTML email body.
fn html_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            other => escaped.push(other),
        }
    }
    escaped
}

fn warning_tier_db_value(tier: u32) -> Option<i32> {
    i32::try_from(tier).ok()
}

// ---------------------------------------------------------------------------
// Database + SMTP logic (used by the scheduler)
// ---------------------------------------------------------------------------

/// Row returned by the user query in `send_expiry_notifications`.
#[derive(Debug, sqlx::FromRow)]
pub struct ExpiringUser {
    pub id: uuid::Uuid,
    pub username: String,
    pub email: String,
    pub password_changed_at: DateTime<Utc>,
}

/// A live SMTP attempt is reclaimable after five minutes if its worker dies.
const NOTIFICATION_CLAIM_TTL_SECS: f64 = 300.0;

/// Failed or ambiguous SMTP outcomes pause before another replica may retry.
const NOTIFICATION_RETRY_DELAY_SECS: f64 = 300.0;

/// Proof that this worker owns one notification attempt.
#[derive(Debug, Clone)]
pub(crate) struct NotificationClaim {
    pub id: uuid::Uuid,
    pub claim_token: uuid::Uuid,
}

/// Token-guarded claim extension for one `password_expiry_notifications` row;
/// executed through [`cluster_work::renew_row_claim`]'s shared `$1=id,
/// $2=token, $3=ttl` contract.
const RENEW_NOTIFICATION_CLAIM_SQL: &str = r#"
    UPDATE password_expiry_notifications
    SET claim_expires_at = NOW() + make_interval(secs => $3)
    WHERE id = $1
      AND claim_token = $2
      AND status = 'claimed'
"#;

/// Extend a live SMTP claim. `Ok(false)` means the claim was lost (expired
/// and reclaimed by another replica) and this worker no longer owns the row.
pub(crate) async fn renew_notification_claim(
    db: &sqlx::PgPool,
    claim: &NotificationClaim,
    claim_ttl_secs: f64,
) -> crate::error::Result<bool> {
    crate::services::cluster_work::renew_row_claim(
        db,
        RENEW_NOTIFICATION_CLAIM_SQL,
        claim.id,
        claim.claim_token,
        claim_ttl_secs,
    )
    .await
}

/// Heartbeat the SMTP claim for as long as the send attempt runs (#3086).
///
/// The claim's fixed TTL alone leaves a duplicate-email window: an SMTP
/// attempt that outlives the TTL lets a second replica reclaim the row and
/// send the same notification again. The heartbeat keeps the claim alive for
/// a live worker; the TTL remains the failover boundary for a dead one.
fn spawn_notification_claim_renewal(
    db: sqlx::PgPool,
    claim: &NotificationClaim,
    claim_ttl_secs: f64,
) -> crate::services::cluster_work::RenewalGuard {
    let claim = claim.clone();
    crate::services::cluster_work::spawn_renewal_loop(
        format!("password expiry notification {}", claim.id),
        claim_ttl_secs,
        move || {
            let db = db.clone();
            let claim = claim.clone();
            async move {
                renew_notification_claim(&db, &claim, claim_ttl_secs)
                    .await
                    .map_err(|e| e.to_string())
            }
        },
    )
}

/// Claim `(user, tier, password version)` before SMTP.
///
/// The INSERT source revalidates account eligibility and password_changed_at
/// at claim time, so a stale candidate list cannot email a user whose account
/// or password changed before the side effect.
pub(crate) async fn claim_notification(
    db: &sqlx::PgPool,
    user_id: uuid::Uuid,
    warning_days: i32,
    password_changed_at: DateTime<Utc>,
    claimed_by: &str,
    claim_ttl_secs: f64,
) -> Result<Option<NotificationClaim>, sqlx::Error> {
    let row: Option<(uuid::Uuid, uuid::Uuid)> = sqlx::query_as(
        r#"
        INSERT INTO password_expiry_notifications
            (user_id, warning_days, password_changed_at, status,
             claimed_by, claim_token, claimed_at, claim_expires_at, sent_at)
        SELECT u.id, $2, u.password_changed_at, 'claimed',
               $4, gen_random_uuid(), NOW(), NOW() + make_interval(secs => $5), NULL
        FROM users u
        WHERE u.id = $1
          AND u.password_changed_at = $3
          AND u.auth_provider = 'local'
          AND u.is_active = true
          AND u.is_service_account = false
        ON CONFLICT (user_id, warning_days, password_changed_at) DO UPDATE
        SET status = 'claimed',
            claimed_by = EXCLUDED.claimed_by,
            claim_token = EXCLUDED.claim_token,
            claimed_at = NOW(),
            claim_expires_at = EXCLUDED.claim_expires_at,
            sent_at = NULL,
            last_error = NULL
        WHERE password_expiry_notifications.status IN ('claimed', 'failed')
          AND password_expiry_notifications.claim_expires_at <= NOW()
        RETURNING id, claim_token
        "#,
    )
    .bind(user_id)
    .bind(warning_days)
    .bind(password_changed_at)
    .bind(claimed_by)
    .bind(claim_ttl_secs)
    .fetch_optional(db)
    .await?;

    Ok(row.map(|(id, claim_token)| NotificationClaim { id, claim_token }))
}

/// Token-guarded terminal sent transition.
pub(crate) async fn mark_notification_sent(db: &sqlx::PgPool, claim: &NotificationClaim) -> bool {
    let result = sqlx::query(
        r#"
        UPDATE password_expiry_notifications
        SET status = 'sent',
            sent_at = NOW(),
            claimed_by = NULL,
            claim_token = NULL,
            claimed_at = NULL,
            claim_expires_at = NULL,
            last_error = NULL
        WHERE id = $1
          AND claim_token = $2
          AND status = 'claimed'
        "#,
    )
    .bind(claim.id)
    .bind(claim.claim_token)
    .execute(db)
    .await;
    matches!(result, Ok(ref update) if update.rows_affected() == 1)
}

/// Token-guarded failed transition with a retry-not-before delay.
pub(crate) async fn mark_notification_failed(
    db: &sqlx::PgPool,
    claim: &NotificationClaim,
    error: &str,
    retry_delay_secs: f64,
) -> bool {
    let result = sqlx::query(
        r#"
        UPDATE password_expiry_notifications
        SET status = 'failed',
            claim_token = NULL,
            claim_expires_at = NOW() + make_interval(secs => $3),
            last_error = $4
        WHERE id = $1
          AND claim_token = $2
          AND status = 'claimed'
        "#,
    )
    .bind(claim.id)
    .bind(claim.claim_token)
    .bind(retry_delay_secs)
    .bind(error)
    .execute(db)
    .await;
    matches!(result, Ok(ref update) if update.rows_affected() == 1)
}

/// Run one cycle of the password expiry notification job.
///
/// For each configured warning tier, queries local users whose password is
/// within the warning window, checks the `password_expiry_notifications` table
/// for duplicates, sends an email, and records the notification.
pub async fn send_expiry_notifications(
    db: &sqlx::PgPool,
    smtp: &crate::services::smtp_service::SmtpService,
    expiry_days: u32,
    warning_tiers: &[u32],
) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
    if expiry_days == 0 || warning_tiers.is_empty() || !smtp.is_configured() {
        return Ok(0);
    }

    let now = Utc::now();
    let mut sent_count: u32 = 0;

    for &tier in warning_tiers {
        let tier_db = match warning_tier_db_value(tier) {
            Some(value) => value,
            None => {
                tracing::warn!(
                    tier,
                    "Skipping password-expiry warning tier that exceeds database INTEGER range"
                );
                continue;
            }
        };

        // Compute cutoff dates in Rust to avoid PG interval binding issues.
        //
        // A user's password enters the warning window when:
        //   password_changed_at <= now - (expiry_days - tier)
        // And the password has not yet expired when:
        //   password_changed_at > now - expiry_days
        let effective_tier = tier.min(expiry_days);
        let warning_cutoff = now - Duration::days((expiry_days - effective_tier) as i64);
        let expiry_cutoff = now - Duration::days(expiry_days as i64);

        let users: Vec<ExpiringUser> = sqlx::query_as::<_, ExpiringUser>(
            r#"
            SELECT u.id, u.username, u.email, u.password_changed_at
            FROM users u
            WHERE u.auth_provider = 'local'
              AND u.is_active = true
              AND u.is_service_account = false
              AND u.password_changed_at <= $1
              AND u.password_changed_at > $2
              AND NOT EXISTS (
                  SELECT 1 FROM password_expiry_notifications n
                  WHERE n.user_id = u.id
                    AND n.warning_days = $3
                    AND n.password_changed_at = u.password_changed_at
                    AND (
                        n.status = 'sent'
                        OR (n.status IN ('claimed', 'failed')
                            AND n.claim_expires_at > NOW())
                    )
              )
            "#,
        )
        .bind(warning_cutoff)
        .bind(expiry_cutoff)
        .bind(tier_db)
        .fetch_all(db)
        .await?;

        for user in &users {
            let remaining =
                days_until_expiry(user.password_changed_at, expiry_days, now).unwrap_or(0);

            let subject = if remaining <= 0 {
                "Your Artifact Keeper password has expired".to_string()
            } else if remaining == 1 {
                "Your Artifact Keeper password expires tomorrow".to_string()
            } else {
                format!(
                    "Your Artifact Keeper password expires in {} days",
                    remaining
                )
            };

            let body_text = build_notification_text(&user.username, remaining);
            let body_html = build_notification_html(&user.username, remaining);

            let claim = match claim_notification(
                db,
                user.id,
                tier_db,
                user.password_changed_at,
                crate::services::cluster_work::WorkerIdentity::for_process().as_str(),
                NOTIFICATION_CLAIM_TTL_SECS,
            )
            .await
            {
                Ok(Some(claim)) => claim,
                Ok(None) => continue,
                Err(e) => {
                    tracing::warn!(
                        user = %user.username,
                        tier,
                        error = %e,
                        "Failed to claim password expiry notification"
                    );
                    continue;
                }
            };

            // Keep the claim alive while SMTP (and finalization) runs, so a
            // slow send cannot outlive the claim TTL and be duplicated by
            // another replica (#3086). Dropped at the end of this iteration.
            let _claim_renewal =
                spawn_notification_claim_renewal(db.clone(), &claim, NOTIFICATION_CLAIM_TTL_SECS);

            if let Err(e) = smtp
                .send_email(&user.email, &subject, &body_html, &body_text)
                .await
            {
                tracing::warn!(
                    user = %user.username,
                    tier = tier,
                    "Failed to send password expiry notification: {}",
                    e,
                );
                if !mark_notification_failed(
                    db,
                    &claim,
                    &e.to_string(),
                    NOTIFICATION_RETRY_DELAY_SECS,
                )
                .await
                {
                    tracing::warn!(
                        notification_id = %claim.id,
                        "Failed to record password-expiry SMTP failure; claim will expire naturally"
                    );
                }
                continue;
            }

            if !mark_notification_sent(db, &claim).await {
                tracing::warn!(
                    notification_id = %claim.id,
                    "Password-expiry email sent but claim finalization failed; a later retry may duplicate it"
                );
            }

            tracing::info!(
                user = %user.username,
                days_remaining = remaining,
                tier = tier,
                "Sent password expiry warning email"
            );

            sent_count += 1;
        }
    }

    Ok(sent_count)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    // -------------------------------------------------------------------
    // days_until_expiry
    // -------------------------------------------------------------------

    #[test]
    fn test_days_until_expiry_disabled_when_zero() {
        let now = Utc::now();
        assert_eq!(days_until_expiry(now, 0, now), None);
    }

    #[test]
    fn test_days_until_expiry_future() {
        let now = Utc::now();
        let changed = now - Duration::days(80);
        let remaining = days_until_expiry(changed, 90, now);
        assert_eq!(remaining, Some(10));
    }

    #[test]
    fn test_days_until_expiry_exact() {
        let now = Utc::now();
        let changed = now - Duration::days(90);
        let remaining = days_until_expiry(changed, 90, now);
        assert_eq!(remaining, Some(0));
    }

    #[test]
    fn test_days_until_expiry_past() {
        let now = Utc::now();
        let changed = now - Duration::days(95);
        let remaining = days_until_expiry(changed, 90, now);
        assert_eq!(remaining, Some(-5));
    }

    #[test]
    fn test_days_until_expiry_just_changed() {
        let now = Utc::now();
        let remaining = days_until_expiry(now, 90, now);
        assert_eq!(remaining, Some(90));
    }

    // -------------------------------------------------------------------
    // should_notify
    // -------------------------------------------------------------------

    #[test]
    fn test_should_notify_disabled_when_expiry_zero() {
        let now = Utc::now();
        assert!(!should_notify(now, 0, 14, now));
    }

    #[test]
    fn test_should_notify_too_early() {
        let now = Utc::now();
        // Password changed today, 90-day expiry, 14-day warning.
        // 90 days remaining, which is > 14, so no notification.
        assert!(!should_notify(now, 90, 14, now));
    }

    #[test]
    fn test_should_notify_within_window() {
        let now = Utc::now();
        // Changed 80 days ago, 90-day expiry, 14-day warning.
        // 10 days remaining, which is <= 14.
        let changed = now - Duration::days(80);
        assert!(should_notify(changed, 90, 14, now));
    }

    #[test]
    fn test_should_notify_on_exact_boundary() {
        let now = Utc::now();
        // Changed 76 days ago, 90-day expiry, 14-day warning.
        // 14 days remaining == 14, should notify.
        let changed = now - Duration::days(76);
        assert!(should_notify(changed, 90, 14, now));
    }

    #[test]
    fn test_should_notify_one_day_remaining() {
        let now = Utc::now();
        let changed = now - Duration::days(89);
        assert!(should_notify(changed, 90, 1, now));
    }

    #[test]
    fn test_should_not_notify_when_already_expired() {
        let now = Utc::now();
        let changed = now - Duration::days(95);
        // -5 days remaining, so password already expired.
        assert!(!should_notify(changed, 90, 14, now));
    }

    #[test]
    fn test_should_notify_exact_expiry_day() {
        let now = Utc::now();
        // 0 days remaining (expires today).
        let changed = now - Duration::days(90);
        assert!(should_notify(changed, 90, 1, now));
    }

    // -------------------------------------------------------------------
    // build_notification_text
    // -------------------------------------------------------------------

    #[test]
    fn test_notification_text_multiple_days() {
        let text = build_notification_text("alice", 7);
        assert!(text.contains("alice"));
        assert!(text.contains("7 days"));
    }

    #[test]
    fn test_notification_text_one_day() {
        let text = build_notification_text("bob", 1);
        assert!(text.contains("bob"));
        assert!(text.contains("tomorrow"));
    }

    #[test]
    fn test_notification_text_expired() {
        let text = build_notification_text("carol", 0);
        assert!(text.contains("carol"));
        assert!(text.contains("expired"));
    }

    // -------------------------------------------------------------------
    // build_notification_html
    // -------------------------------------------------------------------

    #[test]
    fn test_notification_html_multiple_days() {
        let html = build_notification_html("alice", 7);
        assert!(html.contains("alice"));
        assert!(html.contains("7 days"));
        assert!(html.contains("<strong>"));
    }

    #[test]
    fn test_notification_html_one_day() {
        let html = build_notification_html("bob", 1);
        assert!(html.contains("bob"));
        assert!(html.contains("tomorrow"));
    }

    #[test]
    fn test_notification_html_expired() {
        let html = build_notification_html("carol", 0);
        assert!(html.contains("carol"));
        assert!(html.contains("expired"));
    }

    #[test]
    fn test_notification_html_escapes_username_markup() {
        let html = build_notification_html("<img src=x onerror='alert(1)'>&", 7);
        assert!(!html.contains("<img"));
        assert!(!html.contains("onerror='"));
        assert!(html.contains("&lt;img src=x onerror=&#39;alert(1)&#39;&gt;&amp;"));
    }

    #[test]
    fn test_warning_tier_db_value_rejects_integer_wrap() {
        assert_eq!(warning_tier_db_value(i32::MAX as u32), Some(i32::MAX));
        assert_eq!(warning_tier_db_value(i32::MAX as u32 + 1), None);
        assert_eq!(warning_tier_db_value(u32::MAX), None);
    }

    // -------------------------------------------------------------------
    // Edge cases
    // -------------------------------------------------------------------

    #[test]
    fn test_warning_tier_larger_than_expiry() {
        let now = Utc::now();
        // 7-day expiry with a 14-day warning tier: the entire expiry window
        // falls inside the warning window, so any non-expired password should
        // trigger a notification.
        let changed = now - Duration::days(3);
        assert!(should_notify(changed, 7, 14, now));
    }

    #[test]
    fn test_days_until_expiry_large_value() {
        let now = Utc::now();
        let changed = now;
        let remaining = days_until_expiry(changed, 3650, now);
        assert_eq!(remaining, Some(3650));
    }

    #[test]
    fn test_days_until_expiry_one_day_policy() {
        let now = Utc::now();
        let changed = now;
        let remaining = days_until_expiry(changed, 1, now);
        assert_eq!(remaining, Some(1));
    }

    // -------------------------------------------------------------------
    // build_notification_text (additional edge cases)
    // -------------------------------------------------------------------

    #[test]
    fn test_notification_text_negative_days() {
        let text = build_notification_text("dave", -3);
        assert!(text.contains("dave"));
        assert!(text.contains("expired"));
        assert!(!text.contains("-3"));
    }

    #[test]
    fn test_notification_text_many_days() {
        let text = build_notification_text("eve", 30);
        assert!(text.contains("eve"));
        assert!(text.contains("30 days"));
        assert!(!text.contains("tomorrow"));
        assert!(!text.contains("expired"));
    }

    #[test]
    fn test_notification_text_two_days() {
        let text = build_notification_text("frank", 2);
        assert!(text.contains("frank"));
        assert!(text.contains("2 days"));
        assert!(!text.contains("tomorrow"));
    }

    // -------------------------------------------------------------------
    // build_notification_html (additional edge cases)
    // -------------------------------------------------------------------

    #[test]
    fn test_notification_html_negative_days() {
        let html = build_notification_html("dave", -3);
        assert!(html.contains("dave"));
        assert!(html.contains("expired"));
        assert!(html.contains("<strong>"));
    }

    #[test]
    fn test_notification_html_many_days() {
        let html = build_notification_html("eve", 30);
        assert!(html.contains("eve"));
        assert!(html.contains("30 days"));
        assert!(html.contains("<strong>"));
    }

    #[test]
    fn test_notification_html_contains_structure() {
        let html = build_notification_html("test_user", 5);
        assert!(html.contains("<h2>"));
        assert!(html.contains("<p>"));
        assert!(html.contains("Password Expiry Notice"));
        assert!(html.contains("Artifact Keeper"));
    }

    #[test]
    fn test_notification_text_contains_signature() {
        let text = build_notification_text("test_user", 5);
        assert!(text.contains("Artifact Keeper"));
        assert!(text.contains("Hello test_user"));
    }

    // -------------------------------------------------------------------
    // should_notify (additional edge cases)
    // -------------------------------------------------------------------

    #[test]
    fn test_should_notify_warning_equals_expiry() {
        let now = Utc::now();
        // 7-day expiry with 7-day warning: notify for the entire lifecycle
        let changed = now - Duration::days(3);
        assert!(should_notify(changed, 7, 7, now));
    }

    #[test]
    fn test_should_not_notify_warning_zero() {
        let now = Utc::now();
        // 0-day warning tier should only notify on expiry day
        let changed = now - Duration::days(89);
        assert!(!should_notify(changed, 90, 0, now));
    }

    #[test]
    fn test_should_notify_warning_zero_on_expiry_day() {
        let now = Utc::now();
        // 0-day warning tier, password expires today (remaining = 0)
        let changed = now - Duration::days(90);
        assert!(should_notify(changed, 90, 0, now));
    }

    // -------------------------------------------------------------------
    // ExpiringUser struct
    // -------------------------------------------------------------------

    #[test]
    fn test_expiring_user_debug() {
        let user = ExpiringUser {
            id: uuid::Uuid::nil(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            password_changed_at: Utc::now(),
        };
        let debug_output = format!("{:?}", user);
        assert!(debug_output.contains("testuser"));
        assert!(debug_output.contains("test@example.com"));
    }

    // -------------------------------------------------------------------
    // Notification claims (Tier-2: no-op without DATABASE_URL)
    // -------------------------------------------------------------------

    async fn create_claim_test_user(pool: &sqlx::PgPool) -> (uuid::Uuid, chrono::DateTime<Utc>) {
        use crate::api::handlers::test_db_helpers as tdh;
        let (user_id, _) = tdh::create_user(pool).await;
        let changed_at = sqlx::query_scalar(
            "UPDATE users SET password_changed_at = NOW() - INTERVAL '10 days' \
             WHERE id = $1 RETURNING password_changed_at",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("set password version");
        (user_id, changed_at)
    }

    async fn cleanup_claim_test_user(pool: &sqlx::PgPool, user_id: uuid::Uuid) {
        let _ = sqlx::query("DELETE FROM password_expiry_notifications WHERE user_id = $1")
            .bind(user_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(pool)
            .await;
    }

    #[tokio::test]
    async fn notification_claim_is_exactly_once_per_password_version_and_tier() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, changed_at) = create_claim_test_user(&pool).await;

        let claim = claim_notification(&pool, user_id, 7, changed_at, "replica-a", 300.0)
            .await
            .expect("claim query")
            .expect("first claim wins");
        assert!(
            claim_notification(&pool, user_id, 7, changed_at, "replica-b", 300.0)
                .await
                .expect("claim query")
                .is_none(),
            "a live claim must block another replica"
        );
        assert!(
            claim_notification(&pool, user_id, 3, changed_at, "replica-b", 300.0)
                .await
                .expect("claim query")
                .is_some(),
            "another warning tier is independent"
        );

        assert!(mark_notification_sent(&pool, &claim).await);
        assert!(
            claim_notification(&pool, user_id, 7, changed_at, "replica-b", 300.0)
                .await
                .expect("claim query")
                .is_none(),
            "sent is terminal"
        );

        cleanup_claim_test_user(&pool, user_id).await;
    }

    #[tokio::test]
    async fn notification_claim_recovery_fences_stale_owner_and_backs_off_failure() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, changed_at) = create_claim_test_user(&pool).await;

        let stale = claim_notification(&pool, user_id, 7, changed_at, "dead", -1.0)
            .await
            .expect("claim query")
            .expect("claim");
        let fresh = claim_notification(&pool, user_id, 7, changed_at, "live", 300.0)
            .await
            .expect("claim query")
            .expect("expired claim is reclaimable");
        assert_eq!(stale.id, fresh.id);
        assert!(!mark_notification_sent(&pool, &stale).await);

        assert!(mark_notification_failed(&pool, &fresh, "smtp timeout", 60.0).await);
        assert!(
            claim_notification(&pool, user_id, 7, changed_at, "replica-c", 300.0)
                .await
                .expect("claim query")
                .is_none(),
            "a failed attempt must observe retry backoff"
        );

        sqlx::query(
            "UPDATE password_expiry_notifications \
             SET claim_expires_at = NOW() - INTERVAL '1 second' WHERE id = $1",
        )
        .bind(fresh.id)
        .execute(&pool)
        .await
        .expect("expire retry backoff");
        assert!(
            claim_notification(&pool, user_id, 7, changed_at, "replica-c", 300.0)
                .await
                .expect("claim query")
                .is_some(),
            "failed is retryable after its backoff"
        );

        cleanup_claim_test_user(&pool, user_id).await;
    }

    #[tokio::test]
    async fn notification_claim_revalidates_password_version_and_account_state() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, stale_changed_at) = create_claim_test_user(&pool).await;

        sqlx::query(
            "UPDATE users SET password_changed_at = NOW(), is_active = false WHERE id = $1",
        )
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("change password and deactivate user");

        assert!(
            claim_notification(&pool, user_id, 7, stale_changed_at, "replica-a", 300.0,)
                .await
                .expect("claim query")
                .is_none(),
            "a stale/inactive candidate must not reach SMTP"
        );

        cleanup_claim_test_user(&pool, user_id).await;
    }

    /// Tier-2: the SMTP heartbeat (#3086) extends a live claim, is fenced by
    /// the claim token, and stops renewing once the row reaches `sent`.
    #[tokio::test]
    async fn notification_claim_heartbeat_extends_and_is_token_fenced() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, changed_at) = create_claim_test_user(&pool).await;

        let claim = claim_notification(&pool, user_id, 7, changed_at, "replica-a", 60.0)
            .await
            .expect("claim query")
            .expect("claim");

        let before: chrono::DateTime<Utc> = sqlx::query_scalar(
            "SELECT claim_expires_at FROM password_expiry_notifications WHERE id = $1",
        )
        .bind(claim.id)
        .fetch_one(&pool)
        .await
        .expect("read claim expiry");

        assert!(
            renew_notification_claim(&pool, &claim, 600.0)
                .await
                .expect("renew query"),
            "a held claim must be renewable"
        );
        let after: chrono::DateTime<Utc> = sqlx::query_scalar(
            "SELECT claim_expires_at FROM password_expiry_notifications WHERE id = $1",
        )
        .bind(claim.id)
        .fetch_one(&pool)
        .await
        .expect("read claim expiry");
        assert!(
            after > before,
            "renewal must push claim_expires_at forward ({before} -> {after})"
        );

        let stranger = NotificationClaim {
            id: claim.id,
            claim_token: uuid::Uuid::new_v4(),
        };
        assert!(
            !renew_notification_claim(&pool, &stranger, 600.0)
                .await
                .expect("renew query"),
            "a mismatched token must not extend the claim"
        );

        assert!(mark_notification_sent(&pool, &claim).await);
        assert!(
            !renew_notification_claim(&pool, &claim, 600.0)
                .await
                .expect("renew query"),
            "a finalized notification must not be renewable"
        );

        cleanup_claim_test_user(&pool, user_id).await;
    }
}
