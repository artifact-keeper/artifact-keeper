//! Auto-disable for dead-lettered webhooks.
//!
//! When the retry loop exhausts a delivery's retry budget, the webhook
//! is auto-disabled with `disabled_reason` set so operators can see
//! WHY their webhook stopped firing. Emits a structured tracing warn
//! that is paired with the `ak_webhook_dead_letter_total{event}`
//! counter to give ops visibility without depending on an in-app
//! notifications table (none exists in this codebase today).
//!
//! Idempotent: if the webhook is already disabled the row update is a
//! no-op (matched by the `is_enabled = true` predicate) and the warn
//! is still emitted so operators see every dead-letter on the wire.

use sqlx::PgPool;
use uuid::Uuid;

/// Mark a webhook as auto-disabled because its delivery exhausted the
/// retry budget. Returns `Ok(true)` if the row was actually flipped
/// (i.e. it was previously enabled), `Ok(false)` if it was already
/// disabled. Errors propagate to the caller, which logs and continues
/// — auto-disable failure must not retry the dead-lettered delivery.
pub async fn auto_disable_webhook_for_dead_letter(
    db: &PgPool,
    webhook_id: Uuid,
    last_delivery_id: Uuid,
) -> std::result::Result<bool, String> {
    let reason = format!(
        "Auto-disabled after dead-letter (delivery {})",
        last_delivery_id
    );

    let result = sqlx::query(
        r#"
        UPDATE webhooks
        SET is_enabled = false,
            disabled_reason = COALESCE(disabled_reason, $2),
            updated_at = NOW()
        WHERE id = $1
          AND is_enabled = true
        "#,
    )
    .bind(webhook_id)
    .bind(&reason)
    .execute(db)
    .await
    .map_err(|e| format!("auto-disable update failed: {}", e))?;

    let flipped = result.rows_affected() > 0;

    tracing::warn!(
        webhook_id = %webhook_id,
        delivery_id = %last_delivery_id,
        flipped = flipped,
        "Webhook auto-disabled after retry budget exhausted"
    );

    Ok(flipped)
}

#[cfg(test)]
mod tests {
    // The function above issues real SQL; full coverage lives in the
    // integration test suite (deferred). Pure-function unit testing of
    // the SQL is not feasible without an embedded-Postgres harness
    // (#952). Keeping this stub so future tests have a home.
    #[test]
    fn module_compiles() {}
}
