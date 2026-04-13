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
              )
            "#,
        )
        .bind(warning_cutoff)
        .bind(expiry_cutoff)
        .bind(tier as i32)
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
                continue;
            }

            // Record the sent notification to prevent duplicates
            let _ = sqlx::query(
                r#"
                INSERT INTO password_expiry_notifications
                    (user_id, warning_days, password_changed_at)
                VALUES ($1, $2, $3)
                ON CONFLICT (user_id, warning_days, password_changed_at) DO NOTHING
                "#,
            )
            .bind(user.id)
            .bind(tier as i32)
            .bind(user.password_changed_at)
            .execute(db)
            .await;

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
}
