//! System-wide maintenance / downtime banners (#2155).
//!
//! Administrators create banners through `/api/v1/admin/banners`; everyone
//! (including anonymous callers, so the login page can show them) reads the
//! currently active ones from `GET /api/v1/banners`. A banner is active while
//! it is `enabled` and now() falls inside its optional `[starts_at, ends_at)`
//! window, so a banner expires by itself -- no cleanup job.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, Result};

/// Longest accepted banner title, in characters (matches the column).
pub const MAX_TITLE_CHARS: usize = 200;
/// Longest accepted banner message, in characters.
pub const MAX_MESSAGE_CHARS: usize = 4000;
/// Longest accepted link URL, in bytes (matches the column).
pub const MAX_LINK_URL_LEN: usize = 2048;

/// Visual weight of a banner; clients map it to colours/icons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum BannerSeverity {
    #[default]
    Info,
    Warning,
    Critical,
}

impl BannerSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            BannerSeverity::Info => "info",
            BannerSeverity::Warning => "warning",
            BannerSeverity::Critical => "critical",
        }
    }

    /// Parse the stored spelling; unknown values read as `info` (the column's
    /// CHECK constraint makes that unreachable in practice).
    pub fn from_db(raw: &str) -> Self {
        match raw {
            "warning" => BannerSeverity::Warning,
            "critical" => BannerSeverity::Critical,
            _ => BannerSeverity::Info,
        }
    }
}

/// Which surface a banner is meant for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum BannerTarget {
    /// Web UI and API/CLI clients.
    #[default]
    All,
    /// Web UI only.
    Ui,
    /// API / CLI clients only.
    Api,
}

impl BannerTarget {
    pub fn as_str(self) -> &'static str {
        match self {
            BannerTarget::All => "all",
            BannerTarget::Ui => "ui",
            BannerTarget::Api => "api",
        }
    }

    /// Parse the stored spelling; unknown values read as `all`.
    pub fn from_db(raw: &str) -> Self {
        match raw {
            "ui" => BannerTarget::Ui,
            "api" => BannerTarget::Api,
            _ => BannerTarget::All,
        }
    }

    /// Whether a banner aimed at `self` should be shown to a reader asking for
    /// `requested`. No filter (or `all`) shows everything; `ui`/`api` show
    /// banners for that surface plus the ones for every surface.
    pub fn shown_to(self, requested: Option<BannerTarget>) -> bool {
        match requested {
            None | Some(BannerTarget::All) => true,
            Some(r) => self == BannerTarget::All || self == r,
        }
    }
}

/// A banner as stored.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct Banner {
    pub id: Uuid,
    pub title: String,
    pub message: String,
    pub severity: BannerSeverity,
    pub target: BannerTarget,
    pub link_url: Option<String>,
    /// Shown from this instant; `null` = immediately.
    pub starts_at: Option<DateTime<Utc>>,
    /// Hidden from this instant; `null` = until disabled or deleted.
    pub ends_at: Option<DateTime<Utc>>,
    pub enabled: bool,
    pub created_by: Option<Uuid>,
    pub updated_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Banner {
    /// Whether the banner is displayed at `now`.
    pub fn is_active_at(&self, now: DateTime<Utc>) -> bool {
        is_active(self.enabled, self.starts_at, self.ends_at, now)
    }
}

/// Pure activity rule: enabled, started (or no start), not yet ended (or no
/// end). `ends_at` is exclusive so a banner set to end at 10:00 is gone at
/// 10:00 sharp. Mirrors the SQL in [`list_active`].
pub fn is_active(
    enabled: bool,
    starts_at: Option<DateTime<Utc>>,
    ends_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> bool {
    enabled && starts_at.is_none_or(|s| s <= now) && ends_at.is_none_or(|e| e > now)
}

/// Create / full-replace payload.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BannerInput {
    pub title: String,
    pub message: String,
    #[serde(default)]
    pub severity: BannerSeverity,
    #[serde(default)]
    pub target: BannerTarget,
    /// Optional call-to-action link (e.g. a status page). `http`/`https` only.
    #[serde(default)]
    pub link_url: Option<String>,
    #[serde(default)]
    pub starts_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub ends_at: Option<DateTime<Utc>>,
    /// Defaults to `true`.
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// A validated, normalised [`BannerInput`] ready to bind.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidBanner {
    pub title: String,
    pub message: String,
    pub severity: BannerSeverity,
    pub target: BannerTarget,
    pub link_url: Option<String>,
    pub starts_at: Option<DateTime<Utc>>,
    pub ends_at: Option<DateTime<Utc>>,
    pub enabled: bool,
}

/// Validate and normalise an input. Pure, so every rule is unit-testable.
///
/// The link is restricted to absolute `http`/`https` URLs because clients
/// render it as a clickable link: a `javascript:` or `data:` URL in an admin
/// banner would be script injection into every user's session.
pub fn validate_input(input: BannerInput) -> std::result::Result<ValidBanner, String> {
    let title = clean_text("title", &input.title, MAX_TITLE_CHARS)?;
    let message = clean_text("message", &input.message, MAX_MESSAGE_CHARS)?;
    let link_url = match input.link_url.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(raw) => Some(validate_link_url(raw)?),
    };
    if let (Some(s), Some(e)) = (input.starts_at, input.ends_at) {
        if e <= s {
            return Err("ends_at must be later than starts_at".into());
        }
    }
    Ok(ValidBanner {
        title,
        message,
        severity: input.severity,
        target: input.target,
        link_url,
        starts_at: input.starts_at,
        ends_at: input.ends_at,
        enabled: input.enabled.unwrap_or(true),
    })
}

/// Trim, normalise `\r\n` to `\n`, and refuse empty, oversized, or
/// control-character text. Only `\n` and `\t` are allowed: the CLI prints
/// banners to terminals, where an ESC / CSI / OSC sequence in an
/// admin-authored message would be a terminal-escape injection.
fn clean_text(field: &str, raw: &str, max_chars: usize) -> std::result::Result<String, String> {
    let text = raw.trim().replace("\r\n", "\n");
    if text.is_empty() {
        return Err(format!("{field} must not be empty"));
    }
    if text.chars().count() > max_chars {
        return Err(format!("{field} must be at most {max_chars} characters"));
    }
    if text
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\t')
    {
        return Err(format!(
            "{field} must not contain control characters (only newline and tab are allowed)"
        ));
    }
    Ok(text)
}

/// Absolute `http`/`https` only, stored in the parser's normalised form
/// (quotes, angle brackets and whitespace percent-encoded), so clients never
/// depend on a safe attribute API to render it.
fn validate_link_url(raw: &str) -> std::result::Result<String, String> {
    if raw.len() > MAX_LINK_URL_LEN {
        return Err(format!("link_url must be at most {MAX_LINK_URL_LEN} bytes"));
    }
    let parsed = url::Url::parse(raw).map_err(|e| format!("link_url is not a valid URL: {e}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("link_url must be an http or https URL".into());
    }
    let normalised = parsed.as_str();
    if normalised.len() > MAX_LINK_URL_LEN {
        return Err(format!("link_url must be at most {MAX_LINK_URL_LEN} bytes"));
    }
    Ok(normalised.to_string())
}

#[derive(sqlx::FromRow)]
struct BannerRow {
    id: Uuid,
    title: String,
    message: String,
    severity: String,
    target: String,
    link_url: Option<String>,
    starts_at: Option<DateTime<Utc>>,
    ends_at: Option<DateTime<Utc>>,
    enabled: bool,
    created_by: Option<Uuid>,
    updated_by: Option<Uuid>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<BannerRow> for Banner {
    fn from(r: BannerRow) -> Self {
        Banner {
            id: r.id,
            title: r.title,
            message: r.message,
            severity: BannerSeverity::from_db(&r.severity),
            target: BannerTarget::from_db(&r.target),
            link_url: r.link_url,
            starts_at: r.starts_at,
            ends_at: r.ends_at,
            enabled: r.enabled,
            created_by: r.created_by,
            updated_by: r.updated_by,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

/// The selected column list, as a literal so queries stay `&'static str`
/// (sqlx refuses dynamically built SQL).
macro_rules! banner_columns {
    () => {
        "id, title, message, severity, target, link_url, starts_at, ends_at, \
         enabled, created_by, updated_by, created_at, updated_at"
    };
}

/// Critical first, then warning, then info; newest first within a severity.
macro_rules! banner_order {
    () => {
        " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 \
         ELSE 2 END, created_at DESC"
    };
}

/// Bind a [`ValidBanner`]'s fields and the acting user as `$1..=$9`, the
/// order shared by the INSERT and UPDATE statements.
macro_rules! bind_banner {
    ($query:expr, $b:expr, $actor:expr) => {
        $query
            .bind(&$b.title)
            .bind(&$b.message)
            .bind($b.severity.as_str())
            .bind($b.target.as_str())
            .bind(&$b.link_url)
            .bind($b.starts_at)
            .bind($b.ends_at)
            .bind($b.enabled)
            .bind($actor)
    };
}

fn db_err(e: sqlx::Error) -> AppError {
    AppError::Database(e.to_string())
}

/// Every banner, active or not (admin view).
pub async fn list_all(db: &PgPool) -> Result<Vec<Banner>> {
    let rows: Vec<BannerRow> = sqlx::query_as(concat!(
        "SELECT ",
        banner_columns!(),
        " FROM system_banners",
        banner_order!()
    ))
    .fetch_all(db)
    .await
    .map_err(db_err)?;
    Ok(rows.into_iter().map(Banner::from).collect())
}

/// Banners active at `now`, filtered to the requested surface.
pub async fn list_active(
    db: &PgPool,
    now: DateTime<Utc>,
    target: Option<BannerTarget>,
) -> Result<Vec<Banner>> {
    let rows: Vec<BannerRow> = sqlx::query_as(concat!(
        "SELECT ",
        banner_columns!(),
        " FROM system_banners \
         WHERE enabled \
           AND (starts_at IS NULL OR starts_at <= $1) \
           AND (ends_at IS NULL OR ends_at > $1)",
        banner_order!()
    ))
    .bind(now)
    .fetch_all(db)
    .await
    .map_err(db_err)?;
    Ok(rows
        .into_iter()
        .map(Banner::from)
        .filter(|b| b.target.shown_to(target))
        .collect())
}

pub async fn get(db: &PgPool, id: Uuid) -> Result<Option<Banner>> {
    let row: Option<BannerRow> = sqlx::query_as(concat!(
        "SELECT ",
        banner_columns!(),
        " FROM system_banners WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(db_err)?;
    Ok(row.map(Banner::from))
}

pub async fn create(db: &PgPool, b: &ValidBanner, actor: Uuid) -> Result<Banner> {
    let query = sqlx::query_as(concat!(
        "INSERT INTO system_banners \
           (title, message, severity, target, link_url, starts_at, ends_at, enabled, \
            created_by, updated_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9) \
         RETURNING ",
        banner_columns!()
    ));
    let row: BannerRow = bind_banner!(query, b, actor)
        .fetch_one(db)
        .await
        .map_err(db_err)?;
    Ok(row.into())
}

/// Replace every editable field of banner `id`. `None` when it does not exist.
pub async fn update(db: &PgPool, id: Uuid, b: &ValidBanner, actor: Uuid) -> Result<Option<Banner>> {
    let query = sqlx::query_as(concat!(
        "UPDATE system_banners SET \
           title = $1, message = $2, severity = $3, target = $4, link_url = $5, \
           starts_at = $6, ends_at = $7, enabled = $8, updated_by = $9, updated_at = NOW() \
         WHERE id = $10 \
         RETURNING ",
        banner_columns!()
    ));
    let row: Option<BannerRow> = bind_banner!(query, b, actor)
        .bind(id)
        .fetch_optional(db)
        .await
        .map_err(db_err)?;
    Ok(row.map(Banner::from))
}

/// Delete banner `id`; the deleted row, or `None` when it did not exist.
pub async fn delete(db: &PgPool, id: Uuid) -> Result<Option<Banner>> {
    let row: Option<BannerRow> = sqlx::query_as(concat!(
        "DELETE FROM system_banners WHERE id = $1 RETURNING ",
        banner_columns!()
    ))
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(db_err)?;
    Ok(row.map(Banner::from))
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn input() -> BannerInput {
        BannerInput {
            title: "  Maintenance  ".into(),
            message: "Registry read-only 22:00-23:00 UTC".into(),
            severity: BannerSeverity::Warning,
            target: BannerTarget::All,
            link_url: None,
            starts_at: None,
            ends_at: None,
            enabled: None,
        }
    }

    #[test]
    fn active_window_is_start_inclusive_end_exclusive() {
        let now = Utc::now();
        let h = Duration::hours(1);
        assert!(is_active(true, None, None, now));
        assert!(!is_active(false, None, None, now));
        assert!(is_active(true, Some(now), None, now));
        assert!(!is_active(true, Some(now + h), None, now), "not started");
        assert!(!is_active(true, None, Some(now), now), "ended exactly now");
        assert!(
            !is_active(true, Some(now - h), Some(now - h / 2), now),
            "expired"
        );
        assert!(is_active(true, Some(now - h), Some(now + h), now));
    }

    #[test]
    fn target_filter() {
        use BannerTarget::*;
        for t in [All, Ui, Api] {
            assert!(t.shown_to(None));
            assert!(t.shown_to(Some(All)));
        }
        assert!(All.shown_to(Some(Ui)));
        assert!(Ui.shown_to(Some(Ui)));
        assert!(!Api.shown_to(Some(Ui)));
        assert!(!Ui.shown_to(Some(Api)));
        assert!(Api.shown_to(Some(Api)));
    }

    #[test]
    fn db_spellings_round_trip() {
        for s in [
            BannerSeverity::Info,
            BannerSeverity::Warning,
            BannerSeverity::Critical,
        ] {
            assert_eq!(BannerSeverity::from_db(s.as_str()), s);
        }
        for t in [BannerTarget::All, BannerTarget::Ui, BannerTarget::Api] {
            assert_eq!(BannerTarget::from_db(t.as_str()), t);
        }
        assert_eq!(BannerSeverity::from_db("bogus"), BannerSeverity::Info);
        assert_eq!(BannerTarget::from_db("bogus"), BannerTarget::All);
    }

    #[test]
    fn validation_trims_and_defaults() {
        let v = validate_input(input()).expect("valid");
        assert_eq!(v.title, "Maintenance");
        assert!(v.enabled);
        assert_eq!(v.link_url, None);
        let v = validate_input(BannerInput {
            link_url: Some("   ".into()),
            enabled: Some(false),
            ..input()
        })
        .expect("blank link is no link");
        assert_eq!(v.link_url, None);
        assert!(!v.enabled);
    }

    #[test]
    fn validation_rejects_empty_and_oversized_text() {
        assert!(validate_input(BannerInput {
            title: "  ".into(),
            ..input()
        })
        .is_err());
        assert!(validate_input(BannerInput {
            message: "".into(),
            ..input()
        })
        .is_err());
        assert!(validate_input(BannerInput {
            title: "x".repeat(MAX_TITLE_CHARS + 1),
            ..input()
        })
        .is_err());
        assert!(validate_input(BannerInput {
            message: "x".repeat(MAX_MESSAGE_CHARS + 1),
            ..input()
        })
        .is_err());
    }

    #[test]
    fn link_must_be_http_or_https() {
        for ok in ["https://status.example.com/incident/1", "http://intranet/x"] {
            let v = validate_input(BannerInput {
                link_url: Some(ok.into()),
                ..input()
            })
            .expect(ok);
            assert_eq!(v.link_url.as_deref(), Some(ok));
        }
        for bad in [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "/relative/path",
            "ftp://example.com/x",
        ] {
            let err = validate_input(BannerInput {
                link_url: Some(bad.into()),
                ..input()
            })
            .expect_err(bad);
            assert!(err.contains("link_url"), "{bad}: {err}");
        }
        let long = format!("https://e.com/{}", "a".repeat(MAX_LINK_URL_LEN));
        assert!(validate_input(BannerInput {
            link_url: Some(long),
            ..input()
        })
        .is_err());
    }

    #[test]
    fn link_is_stored_normalised() {
        let v = validate_input(BannerInput {
            link_url: Some("https://Status.Example.com/a b\"<x>".into()),
            ..input()
        })
        .expect("parseable");
        assert_eq!(
            v.link_url.as_deref(),
            Some("https://status.example.com/a%20b%22%3Cx%3E")
        );
    }

    #[test]
    fn control_characters_are_rejected_except_newline_and_tab() {
        for bad in [
            "\u{1b}[31mred",
            "bell\u{7}",
            "osc\u{1b}]8;;x\u{7}",
            "csi\u{9b}2J",
            "del\u{7f}",
        ] {
            let err = validate_input(BannerInput {
                message: bad.into(),
                ..input()
            })
            .expect_err(bad);
            assert!(err.contains("control characters"), "{err}");
            assert!(validate_input(BannerInput {
                title: bad.into(),
                ..input()
            })
            .is_err());
        }
        let v = validate_input(BannerInput {
            message: "line one\r\nline two\tindented".into(),
            ..input()
        })
        .expect("newline and tab are fine");
        assert_eq!(v.message, "line one\nline two\tindented");
    }

    #[test]
    fn window_must_be_ordered() {
        let now = Utc::now();
        let err = validate_input(BannerInput {
            starts_at: Some(now),
            ends_at: Some(now),
            ..input()
        })
        .expect_err("empty window");
        assert!(err.contains("ends_at"));
        assert!(validate_input(BannerInput {
            starts_at: Some(now),
            ends_at: Some(now + Duration::minutes(1)),
            ..input()
        })
        .is_ok());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let r: std::result::Result<BannerInput, _> = serde_json::from_value(serde_json::json!({
            "title": "t", "message": "m", "severity": "warning", "colour": "red"
        }));
        assert!(r.is_err());
        let r: BannerInput =
            serde_json::from_value(serde_json::json!({"title": "t", "message": "m"})).unwrap();
        assert_eq!(r.severity, BannerSeverity::Info);
        assert_eq!(r.target, BannerTarget::All);
    }

    /// DB-backed: CRUD round trip and active-window filtering in SQL.
    #[tokio::test]
    async fn crud_and_active_window_in_sql() {
        let Some(pool) = crate::api::handlers::test_db_helpers::try_pool().await else {
            return;
        };
        let (admin, _) = crate::api::handlers::test_db_helpers::create_user(&pool).await;
        let now = Utc::now();
        let h = Duration::hours(1);
        let tag = Uuid::new_v4().simple().to_string();
        let mk = |suffix: &str, target, starts_at, ends_at, enabled| ValidBanner {
            title: format!("{tag}-{suffix}"),
            message: "m".into(),
            severity: BannerSeverity::Critical,
            target,
            link_url: None,
            starts_at,
            ends_at,
            enabled,
        };
        let live = create(
            &pool,
            &mk("live", BannerTarget::All, None, None, true),
            admin,
        )
        .await
        .expect("create live");
        let ui_only = create(
            &pool,
            &mk("ui", BannerTarget::Ui, Some(now - h), Some(now + h), true),
            admin,
        )
        .await
        .expect("create ui");
        let expired = create(
            &pool,
            &mk(
                "expired",
                BannerTarget::All,
                Some(now - h * 2),
                Some(now - h),
                true,
            ),
            admin,
        )
        .await
        .expect("create expired");
        let future = create(
            &pool,
            &mk("future", BannerTarget::All, Some(now + h), None, true),
            admin,
        )
        .await
        .expect("create future");
        let disabled = create(
            &pool,
            &mk("disabled", BannerTarget::All, None, None, false),
            admin,
        )
        .await
        .expect("create disabled");
        assert_eq!(live.created_by, Some(admin));
        assert!(live.is_active_at(now));
        assert!(!expired.is_active_at(now));

        let ours = |v: Vec<Banner>| -> Vec<String> {
            let mut t: Vec<String> = v
                .into_iter()
                .filter(|b| b.title.starts_with(&tag))
                .map(|b| b.title[tag.len() + 1..].to_string())
                .collect();
            t.sort();
            t
        };
        assert_eq!(
            ours(list_active(&pool, now, None).await.unwrap()),
            ["live", "ui"]
        );
        assert_eq!(
            ours(
                list_active(&pool, now, Some(BannerTarget::Api))
                    .await
                    .unwrap()
            ),
            ["live"]
        );
        assert_eq!(ours(list_all(&pool).await.unwrap()).len(), 5);

        // Update re-enables the disabled one; a missing id is None.
        let mut re = mk("disabled", BannerTarget::Api, None, None, true);
        re.message = "changed".into();
        let updated = update(&pool, disabled.id, &re, admin)
            .await
            .unwrap()
            .expect("exists");
        assert_eq!(updated.message, "changed");
        assert_eq!(updated.target, BannerTarget::Api);
        assert!(update(&pool, Uuid::new_v4(), &re, admin)
            .await
            .unwrap()
            .is_none());
        assert_eq!(get(&pool, updated.id).await.unwrap(), Some(updated.clone()));

        // The DB refuses an inverted window even if validation were bypassed.
        let inverted = mk("bad", BannerTarget::All, Some(now), Some(now - h), true);
        assert!(create(&pool, &inverted, admin).await.is_err());

        for b in [&live, &ui_only, &expired, &future, &updated] {
            assert!(delete(&pool, b.id).await.unwrap().is_some());
        }
        assert!(delete(&pool, live.id).await.unwrap().is_none());
        assert!(get(&pool, live.id).await.unwrap().is_none());
        crate::api::handlers::test_db_helpers::cleanup_user(&pool, admin).await;
    }
}
