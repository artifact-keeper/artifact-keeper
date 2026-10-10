//! Navigation entries an administrator hid from the web UI (#4574).
//!
//! Many instances use only a few features, and the web sidebar lists all of
//! them. This setting lets an admin hide the entries nobody uses, for every
//! user at once. It is stored in the key/value `system_settings` table, edited
//! through `PATCH /api/v1/admin/settings/system`, and published to every caller
//! (anonymous included) by `GET /api/v1/system/config` as
//! `ui.hidden_nav_items`.
//!
//! # Scope
//!
//! * **Navigation only.** Hiding an entry removes a menu link. The page stays
//!   reachable by URL and every permission check on the page and its API
//!   endpoints is unchanged. Nothing on the server consults this list to allow
//!   or refuse a request.
//! * **Opaque identifiers.** The web UI owns its sidebar, so the server does not
//!   know which entries exist. It stores whatever identifiers the UI sends
//!   (today the entry's route, e.g. `/peers`) and only checks their shape:
//!   a bounded number of short, printable strings. Unknown identifiers are
//!   harmless; the UI ignores them.
//! * **Fail open.** No row, an unreadable row or a row that is not a list of
//!   strings all mean "nothing hidden", which is the historical behaviour.
//!   Hiding a menu entry is never worth a broken or empty sidebar.

use sqlx::PgPool;
use uuid::Uuid;

/// The `system_settings` key the stored list lives under.
pub const HIDDEN_NAV_ITEMS_SETTING_KEY: &str = "ui.hidden_nav_items";

/// Upper bound on the number of stored identifiers. The web sidebar has about
/// fifty entries; the headroom covers future entries without letting a client
/// store an unbounded list that every page load then downloads.
pub const MAX_HIDDEN_NAV_ITEMS: usize = 200;

/// Upper bound on the length of one identifier, in bytes.
pub const MAX_NAV_ITEM_ID_LEN: usize = 128;

/// Check and canonicalise a list of identifiers sent by an admin.
///
/// Each identifier is trimmed and must be 1 to [`MAX_NAV_ITEM_ID_LEN`] bytes
/// of ASCII letters, digits, `/`, `-`, `_` or `.`. The result is sorted and
/// de-duplicated so the stored value (and the audit diff) does not depend on
/// the order the UI sent. An invalid entry rejects the whole list instead of
/// being dropped, so a typo is never a silent no-op.
pub fn normalize(items: Vec<String>) -> Result<Vec<String>, String> {
    if items.len() > MAX_HIDDEN_NAV_ITEMS {
        return Err(format!(
            "hidden_nav_items accepts at most {MAX_HIDDEN_NAV_ITEMS} entries, got {}",
            items.len()
        ));
    }
    let mut out = Vec::with_capacity(items.len());
    for raw in items {
        let id = raw.trim();
        if id.is_empty() {
            return Err("hidden_nav_items entries must not be empty".to_string());
        }
        if id.len() > MAX_NAV_ITEM_ID_LEN {
            return Err(format!(
                "hidden_nav_items entries must be at most {MAX_NAV_ITEM_ID_LEN} characters"
            ));
        }
        if !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.'))
        {
            return Err(format!(
                "hidden_nav_items entry {id:?} may only contain letters, digits, '/', '-', '_' and '.'"
            ));
        }
        out.push(id.to_string());
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// Decode a stored value. Anything that is not a JSON array of strings reads
/// as "nothing hidden" (see the module docs on failing open).
pub fn decode(value: Option<&serde_json::Value>) -> Vec<String> {
    let Some(value) = value else {
        return Vec::new();
    };
    match serde_json::from_value::<Vec<String>>(value.clone()) {
        Ok(items) => items,
        Err(e) => {
            tracing::warn!(
                key = HIDDEN_NAV_ITEMS_SETTING_KEY,
                error = %e,
                "stored hidden navigation items are not a list of strings; showing every entry"
            );
            Vec::new()
        }
    }
}

/// Read the stored list. A database error is returned to the caller, which
/// decides whether to fail open (`/system/config`) or report it (admin API).
pub async fn try_load(db: &PgPool) -> Result<Vec<String>, sqlx::Error> {
    let value: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT value FROM system_settings WHERE key = $1")
            .bind(HIDDEN_NAV_ITEMS_SETTING_KEY)
            .fetch_optional(db)
            .await?;
    Ok(decode(value.as_ref()))
}

/// Read the stored list, treating a database error as "nothing hidden".
pub async fn load_or_default(db: &PgPool) -> Vec<String> {
    match try_load(db).await {
        Ok(items) => items,
        Err(e) => {
            tracing::warn!(error = %e, "failed to read hidden navigation items; showing every entry");
            Vec::new()
        }
    }
}

/// Persist an already [`normalize`]d list.
pub async fn store(db: &PgPool, items: &[String], updated_by: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        INSERT INTO system_settings (key, value, description, updated_by)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (key) DO UPDATE
            SET value = $2, updated_by = $4, updated_at = NOW()
        "#,
    )
    .bind(HIDDEN_NAV_ITEMS_SETTING_KEY)
    .bind(serde_json::json!(items))
    .bind("Web UI navigation entries hidden for every user (display only, not access control)")
    .bind(updated_by)
    .execute(db)
    .await?;
    Ok(())
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    fn s(items: &[&str]) -> Vec<String> {
        items.iter().map(|i| i.to_string()).collect()
    }

    #[test]
    fn normalize_sorts_dedups_and_trims() {
        let got = normalize(s(&[
            "/webhooks",
            " /peers ",
            "/webhooks",
            "/security/scans",
        ]))
        .unwrap();
        assert_eq!(got, s(&["/peers", "/security/scans", "/webhooks"]));
    }

    #[test]
    fn normalize_accepts_empty_list() {
        assert_eq!(normalize(Vec::new()).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn normalize_rejects_empty_entry() {
        assert!(normalize(s(&["/peers", "  "])).is_err());
    }

    #[test]
    fn normalize_rejects_too_long_entry() {
        let long = format!("/{}", "a".repeat(MAX_NAV_ITEM_ID_LEN));
        assert!(normalize(vec![long]).is_err());
        let max = "a".repeat(MAX_NAV_ITEM_ID_LEN);
        assert!(normalize(vec![max]).is_ok());
    }

    #[test]
    fn normalize_rejects_unexpected_characters() {
        for bad in ["<script>", "/peers?x=1", "/a b", "/ü"] {
            assert!(normalize(s(&[bad])).is_err(), "{bad} should be rejected");
        }
        assert!(normalize(s(&["/sync-policies", "dt_projects", "nav.v2"])).is_ok());
    }

    #[test]
    fn normalize_rejects_too_many_entries() {
        let many: Vec<String> = (0..=MAX_HIDDEN_NAV_ITEMS)
            .map(|i| format!("/x{i}"))
            .collect();
        assert!(normalize(many).is_err());
    }

    #[test]
    fn decode_fails_open() {
        assert!(decode(None).is_empty());
        assert!(decode(Some(&serde_json::json!(true))).is_empty());
        assert!(decode(Some(&serde_json::json!(["/a", 1]))).is_empty());
        assert_eq!(
            decode(Some(&serde_json::json!(["/peers", "/plugins"]))),
            s(&["/peers", "/plugins"])
        );
    }

    /// Put the shared row back the way a test found it (no row when nothing
    /// was hidden).
    async fn restore(pool: &PgPool, before: &[String], user_id: Uuid) {
        if before.is_empty() {
            sqlx::query("DELETE FROM system_settings WHERE key = $1")
                .bind(HIDDEN_NAV_ITEMS_SETTING_KEY)
                .execute(pool)
                .await
                .expect("delete hidden nav items row");
        } else {
            store(pool, before, user_id).await.expect("restore");
        }
    }

    #[tokio::test]
    async fn store_and_load_round_trip() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let _guard = tdh::hidden_nav_items_serial_lock().await;
        let (user_id, _) = tdh::create_user(&pool).await;
        let before = try_load(&pool).await.expect("read");

        store(&pool, &s(&["/peers", "/webhooks"]), user_id)
            .await
            .expect("store");
        let stored = try_load(&pool).await.expect("read back");

        restore(&pool, &before, user_id).await;
        tdh::cleanup_user(&pool, user_id).await;
        assert_eq!(stored, s(&["/peers", "/webhooks"]));
    }
}
