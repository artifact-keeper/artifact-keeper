//! Package-exception queue reads and auto-filing for the non-age gates
//! (migration 381).
//!
//! The age gate owns its own rows through `age_gate_service`, because its
//! decisions are bound to an age-specific policy identity (mode + upstream
//! fingerprint, migration 191) and its upsert encodes that. The scan and
//! curation gates have no such identity, so their filing and lookup live here
//! rather than growing another two branches into that machinery.
//!
//! Shared lifecycle (approve / reject / reopen / list) stays in
//! `age_gate_service` for every gate, so there is exactly one writer for a
//! reviewer decision.

use chrono::{Duration, Utc};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::age_gate_service::gate_event;
use crate::services::event_bus::EventBus;

/// Repeat refusals of the same coordinate within this window do not re-bump
/// `request_count`. Mirrors the age gate's listing debounce: a dependency
/// graph re-resolving 400 times in a build should read as demand, not as 400
/// separate requests.
const REFUSAL_DEBOUNCE_SECS: i64 = 3600;

/// The identity an exception is granted against.
///
/// `digest` is the content digest the refusal was recorded for. Proxy scan
/// verdicts are digest-keyed precisely so a lying upstream cannot rebind a
/// clean verdict to different bytes; an exception keyed only on
/// (name, version) would hand that property straight back, so the scan gate
/// always carries one. The curation gate has no bytes in hand at its seam and
/// passes `None`.
#[derive(Debug, Clone)]
pub struct ExceptionCoord {
    pub gate: &'static str,
    pub repository_id: Uuid,
    pub package_name: String,
    pub package_version: String,
    pub digest: Option<String>,
}

/// Is there a live exception that permits serving these exact bytes?
///
/// Every condition here is fail-closed by construction:
/// * only `approved` counts, so a pending request never serves;
/// * `expires_at` in the past stops counting with no sweep required;
/// * when the caller supplies a digest, a row whose `basis_digest` is NULL or
///   different does NOT match, so republished bytes under the same version
///   re-block rather than inheriting the acceptance.
///
/// A database error is an error, never a silent `true`: this function can only
/// ever widen access, so it must not fail open.
pub async fn exception_allows(db: &PgPool, coord: &ExceptionCoord) -> Result<bool> {
    sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM age_gate_reviews
            WHERE gate = $1
              AND repository_id = $2
              AND package_name = $3
              AND package_version = $4
              AND status = 'approved'
              AND (expires_at IS NULL OR expires_at > NOW())
              AND ($5::text IS NULL OR basis_digest = $5)
        )
        "#,
    )
    .bind(coord.gate)
    .bind(coord.repository_id)
    .bind(&coord.package_name)
    .bind(&coord.package_version)
    .bind(coord.digest.as_deref())
    .fetch_one(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))
}

/// Is there a live scan exception for these bytes in this repository, whatever coordinate it names?
/// Only lets a fast path step aside for the full gate, which then checks the coordinate too
pub async fn scan_digest_excepted(db: &PgPool, repository_id: Uuid, digest: &str) -> Result<bool> {
    sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS (
            SELECT 1
            FROM age_gate_reviews
            WHERE gate = 'scan'
              AND repository_id = $1
              AND basis_digest = $2
              AND status = 'approved'
              AND (expires_at IS NULL OR expires_at > NOW())
        )
        "#,
    )
    .bind(repository_id)
    .bind(digest)
    .fetch_one(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))
}

/// Record that a gate refused this coordinate, so the queue shows demand
/// without anyone having to file anything.
///
/// The row lands with `justification IS NULL`, which is what marks it
/// `attempted` rather than `requested` in the reviewer UI.
///
/// A CHANGED digest voids any prior decision and returns the row to `pending`:
/// the reviewer accepted specific bytes, and these are not those bytes. This
/// is the scan gate's analogue of the age gate's mode/upstream identity check.
/// An explicit `rejected` is the one decision a re-file does not disturb,
/// matching the age gate, where a rejection blocks coordinate-wide.
///
/// Best-effort by contract: the caller is already refusing the request, so a
/// failure to record must not turn a clean 403 into a 500. Errors are returned
/// for the caller to log, not to propagate to the client.
///
/// `event_bus` is optional because the curation seam
/// (`proxy_helpers::evaluate_curation`) is reached through ~10 call sites that
/// carry only a `&PgPool`, not the app state. Passing `None` files the row
/// (which is what the reviewer queue needs) and skips the notification; wiring
/// the bus through those callers is a mechanical follow-up, tracked with the
/// rest of the queue work.
pub async fn record_refusal(
    db: &PgPool,
    event_bus: Option<&Arc<EventBus>>,
    coord: &ExceptionCoord,
) -> Result<()> {
    let stale_before = Utc::now() - Duration::seconds(REFUSAL_DEBOUNCE_SECS);
    let row: Option<(Uuid, bool)> = sqlx::query_as(
        r#"
        INSERT INTO age_gate_reviews (
            gate, repository_id, package_name, package_version, status, basis_digest
        )
        VALUES ($1, $2, $3, $4, 'pending', $5)
        ON CONFLICT (gate, repository_id, package_name, package_version)
        DO UPDATE SET
            request_count = age_gate_reviews.request_count + 1,
            last_requested_at = NOW(),
            status = CASE
                WHEN age_gate_reviews.status = 'rejected' THEN age_gate_reviews.status
                WHEN age_gate_reviews.basis_digest IS DISTINCT FROM EXCLUDED.basis_digest
                THEN 'pending'
                ELSE age_gate_reviews.status
            END,
            reviewed_by = CASE
                WHEN age_gate_reviews.status = 'rejected' THEN age_gate_reviews.reviewed_by
                WHEN age_gate_reviews.basis_digest IS DISTINCT FROM EXCLUDED.basis_digest
                THEN NULL
                ELSE age_gate_reviews.reviewed_by
            END,
            expires_at = CASE
                WHEN age_gate_reviews.status = 'rejected' THEN age_gate_reviews.expires_at
                WHEN age_gate_reviews.basis_digest IS DISTINCT FROM EXCLUDED.basis_digest
                THEN NULL
                ELSE age_gate_reviews.expires_at
            END,
            basis_digest = EXCLUDED.basis_digest
        WHERE age_gate_reviews.last_requested_at < $6
           OR age_gate_reviews.basis_digest IS DISTINCT FROM EXCLUDED.basis_digest
        RETURNING id, (request_count = 1) AS is_new
        "#,
    )
    .bind(coord.gate)
    .bind(coord.repository_id)
    .bind(&coord.package_name)
    .bind(&coord.package_version)
    .bind(coord.digest.as_deref())
    .bind(stale_before)
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // No row means the debounce window swallowed the bump, which is the
    // common case under a dependency-graph burst.
    if let (Some((id, true)), Some(bus)) = (row, event_bus) {
        bus.emit_for_repo(
            &gate_event(Some(coord.gate), "age_gate.queued"),
            id,
            coord.repository_id,
            None,
        );
    }
    Ok(())
}

/// Operator-set template for the "request an exception" link put into every
/// refusal. Absent means "build an AK-native deep link", which is the sensible
/// default and is why this key has no seed row: a missing setting is a working
/// configuration, not an unconfigured one.
///
/// Placeholders (each URL-encoded on substitution): `{gate}`, `{repo}`,
/// `{package}`, `{version}`. An operator who wants requests to land in Jira or
/// a Slack workflow sets this; everyone else gets the built-in form.
pub const EXCEPTION_URL_SETTING_KEY: &str = "security.exception_request_url";

/// Substitute the coordinate into an operator template.
///
/// Pure, so the encoding and the placeholder set are testable without a DB.
/// Values are percent-encoded because a package name can legitimately contain
/// `/` (an npm scope, a Go module path) and a template almost always puts them
/// in a query string.
pub fn render_url_template(
    template: &str,
    gate: &str,
    repo: &str,
    package: &str,
    version: &str,
) -> String {
    let enc = |s: &str| urlencoding::encode(s).into_owned();
    template
        .replace("{gate}", &enc(gate))
        .replace("{repo}", &enc(repo))
        .replace("{package}", &enc(package))
        .replace("{version}", &enc(version))
}

/// Validate an operator template before it is stored. Every refused client is
/// handed the rendered link, and the web UI renders it as a link, so it must be
/// an absolute `http(s)` URL: no `javascript:` or relative target, and no
/// whitespace or control characters that could not go into a header. Empty
/// clears the setting and is always valid.
pub fn validate_url_template(template: &str) -> Result<()> {
    let t = template.trim();
    if t.is_empty() {
        return Ok(());
    }
    if t.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(AppError::Validation(
            "exception_request_url must not contain whitespace or control characters".to_string(),
        ));
    }
    let probe = render_url_template(t, "scan", "repo", "package", "1.0.0");
    match url::Url::parse(&probe) {
        Ok(u) if matches!(u.scheme(), "http" | "https") && u.host_str().is_some() => Ok(()),
        _ => Err(AppError::Validation(
            "exception_request_url must be an absolute http or https URL".to_string(),
        )),
    }
}

/// The link a refused client should be pointed at, or `None` when neither a
/// template nor an external base URL is configured.
///
/// Order: the operator's template wins; otherwise an AK-native deep link into
/// the built-in request form, which prefills from exactly these query
/// parameters. `trusted_external_url()` is used rather than anything derived
/// from request headers because this string is handed to a user to click.
///
/// Read per refusal rather than cached: this runs only on a path that is
/// already withholding bytes, and caching would mean an operator's change to
/// the setting did not take effect until a restart.
pub async fn exception_request_url(
    db: &PgPool,
    gate: &str,
    repo: &str,
    package: &str,
    version: &str,
) -> Option<String> {
    let configured: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT value FROM system_settings WHERE key = $1")
            .bind(EXCEPTION_URL_SETTING_KEY)
            .fetch_optional(db)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(
                    error = %e,
                    "failed to read {EXCEPTION_URL_SETTING_KEY}; falling back to the built-in form"
                );
                None
            })
            .flatten();

    if let Some(t) = configured.as_ref().and_then(|v| v.as_str()) {
        let t = t.trim();
        if !t.is_empty() {
            // A value written straight to the table skips the settings API's check
            if validate_url_template(t).is_ok() {
                return Some(render_url_template(t, gate, repo, package, version));
            }
            tracing::warn!(
                "{EXCEPTION_URL_SETTING_KEY} is not an absolute http(s) URL; using the built-in form"
            );
        }
    }

    let base = crate::api::extractors::trusted_external_url()?;
    Some(render_url_template(
        &format!(
            "{}/exceptions/request?gate={{gate}}&repo={{repo}}&package={{package}}&version={{version}}",
            base.trim_end_matches('/')
        ),
        gate,
        repo,
        package,
        version,
    ))
}

/// Longest justification accepted from a requester. Generous enough for a
/// real explanation, bounded because this is a write surface open to every
/// authenticated user.
pub const MAX_JUSTIFICATION_LEN: usize = 2000;

/// Longest package coordinate accepted. Mirrors what the formats themselves
/// can produce; the point is to bound the row, not to validate the ecosystem.
pub const MAX_COORD_LEN: usize = 512;

/// Validate a requester-supplied coordinate and justification.
///
/// Pure so the bounds are testable without a database. This is a trust
/// boundary: every field here comes from an authenticated but otherwise
/// unprivileged caller.
pub fn validate_request(
    package_name: &str,
    package_version: &str,
    justification: &str,
) -> Result<()> {
    let j = justification.trim();
    if j.is_empty() {
        return Err(AppError::Validation(
            "A justification is required: it is what turns a refused pull into a request"
                .to_string(),
        ));
    }
    if j.chars().count() > MAX_JUSTIFICATION_LEN {
        return Err(AppError::Validation(format!(
            "justification must be at most {MAX_JUSTIFICATION_LEN} characters"
        )));
    }
    for (field, value) in [
        ("package_name", package_name),
        ("package_version", package_version),
    ] {
        if value.trim().is_empty() {
            return Err(AppError::Validation(format!("{field} is required")));
        }
        if value.chars().count() > MAX_COORD_LEN {
            return Err(AppError::Validation(format!(
                "{field} must be at most {MAX_COORD_LEN} characters"
            )));
        }
    }
    Ok(())
}

/// Most undecided requests one user may have open at once. Filing is open to
/// every authenticated user and a request may name a coordinate no gate has
/// refused, so without a bound one account could fill the reviewer queue.
pub const MAX_OPEN_REQUESTS_PER_USER: i64 = 50;

/// Refuse a new request when `user_id` already has
/// [`MAX_OPEN_REQUESTS_PER_USER`] pending requests. Re-filing a coordinate the
/// user already asked for does not count against them.
pub async fn require_open_request_budget(
    db: &PgPool,
    user_id: Uuid,
    coord: &ExceptionCoord,
) -> Result<()> {
    let (open, already_mine): (i64, bool) = sqlx::query_as(
        r#"
        SELECT
            (SELECT COUNT(*) FROM (
                SELECT 1 FROM age_gate_reviews
                WHERE requested_by = $1 AND status = 'pending' AND justification IS NOT NULL
                LIMIT $6
            ) open_rows)::bigint,
            EXISTS (
                SELECT 1 FROM age_gate_reviews
                WHERE requested_by = $1 AND gate = $2 AND repository_id = $3
                  AND package_name = $4 AND package_version = $5
            )
        "#,
    )
    .bind(user_id)
    .bind(coord.gate)
    .bind(coord.repository_id)
    .bind(&coord.package_name)
    .bind(&coord.package_version)
    .bind(MAX_OPEN_REQUESTS_PER_USER)
    .fetch_one(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    if !already_mine && open >= MAX_OPEN_REQUESTS_PER_USER {
        return Err(AppError::Conflict(format!(
            "You already have {MAX_OPEN_REQUESTS_PER_USER} open exception requests; \
             wait for a reviewer to decide some of them"
        )));
    }
    Ok(())
}

/// File a human request against a coordinate, creating the row if the gate has
/// not already refused this package.
///
/// Writing `justification` is what promotes a row from `attempted` (the gate
/// refused it and nobody said why they wanted it) to `requested` (the
/// reviewer's default view). Filing against a coordinate that was never
/// refused is allowed on purpose: a developer who knows a package will be
/// blocked should be able to ask before their build breaks.
///
/// A request deliberately does NOT change `status`. Re-opening a decided row
/// is a reviewer action; an appeal shows up as a fresh justification on a
/// `rejected` row, which is exactly the signal a reviewer wants to see rather
/// than a silent return to the queue.
///
/// The last requester wins on `justification` and `requested_by`. Two people
/// wanting the same package is one request with the newer reason, not two
/// rows; `request_count` is what carries the "many people want this" signal.
pub async fn file_request(
    db: &PgPool,
    event_bus: Option<&Arc<EventBus>>,
    coord: &ExceptionCoord,
    requested_by: Uuid,
    justification: &str,
) -> Result<Uuid> {
    let (id, is_new): (Uuid, bool) = sqlx::query_as(
        r#"
        INSERT INTO age_gate_reviews (
            gate, repository_id, package_name, package_version, status,
            basis_digest, justification, requested_by
        )
        VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7)
        ON CONFLICT (gate, repository_id, package_name, package_version)
        DO UPDATE SET
            -- An approved row keeps the justification and requester it was
            -- granted on, so a later request cannot rewrite what the
            -- reviewer and the audit trail saw
            justification = CASE WHEN age_gate_reviews.status = 'approved'
                THEN age_gate_reviews.justification ELSE EXCLUDED.justification END,
            requested_by = CASE WHEN age_gate_reviews.status = 'approved'
                THEN age_gate_reviews.requested_by ELSE EXCLUDED.requested_by END,
            last_requested_at = NOW()
        RETURNING id, (request_count = 1 AND reviewed_at IS NULL) AS is_new
        "#,
    )
    .bind(coord.gate)
    .bind(coord.repository_id)
    .bind(&coord.package_name)
    .bind(&coord.package_version)
    .bind(coord.digest.as_deref())
    .bind(justification.trim())
    .bind(requested_by)
    .fetch_one(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if let Some(bus) = event_bus {
        // `requested` is a distinct event from `queued`: one is a human
        // asking, the other is a gate noticing. A reviewer subscribing to
        // Slack wants the first and would drown in the second.
        let age_event = if is_new {
            "age_gate.requested"
        } else {
            "age_gate.rerequested"
        };
        bus.emit_for_repo(
            &gate_event(Some(coord.gate), age_event),
            id,
            coord.repository_id,
            Some(requested_by.to_string()),
        );
    }
    Ok(id)
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::age_gate_service::{GATE_AGE, GATE_CURATION, GATE_SCAN};
    use chrono::DateTime;

    fn coord(digest: Option<&str>) -> ExceptionCoord {
        ExceptionCoord {
            gate: GATE_SCAN,
            repository_id: Uuid::new_v4(),
            package_name: "lodash".to_string(),
            package_version: "4.17.20".to_string(),
            digest: digest.map(str::to_string),
        }
    }

    #[tokio::test]
    async fn db_exception_allows_is_digest_bound_and_expiry_aware() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let bus = Arc::new(EventBus::new(16));

        let repo_id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO repositories (id, key, name, format, repo_type, storage_path, upstream_url)
               VALUES ($1, $2, $2, 'npm', 'remote', '/tmp/ph-exq', 'https://registry.npmjs.org')"#,
        )
        .bind(repo_id)
        .bind(format!("ph-exq-{repo_id}"))
        .execute(&pool)
        .await
        .expect("seed repo");

        let mut c = coord(Some("sha256:aaa"));
        c.repository_id = repo_id;

        // Nothing filed yet.
        assert!(!exception_allows(&pool, &c).await.expect("query ok"));

        // A refusal files a PENDING row, which must not serve.
        record_refusal(&pool, Some(&bus), &c).await.expect("record");
        assert!(
            !exception_allows(&pool, &c).await.expect("query ok"),
            "a pending request is not an exception"
        );

        let id: Uuid = sqlx::query_scalar(
            "SELECT id FROM age_gate_reviews WHERE gate = $1 AND repository_id = $2",
        )
        .bind(GATE_SCAN)
        .bind(repo_id)
        .fetch_one(&pool)
        .await
        .expect("row exists");

        // Approved and unexpired, bound to this digest -> serves.
        sqlx::query(
            "UPDATE age_gate_reviews SET status = 'approved', reviewed_by = NULL,
             expires_at = NOW() + INTERVAL '90 days' WHERE id = $1",
        )
        .bind(id)
        .execute(&pool)
        .await
        .expect("approve");
        assert!(exception_allows(&pool, &c).await.expect("query ok"));
        assert!(scan_digest_excepted(&pool, repo_id, "sha256:aaa")
            .await
            .expect("query ok"));
        assert!(!scan_digest_excepted(&pool, repo_id, "sha256:bbb")
            .await
            .expect("query ok"));

        // DIFFERENT bytes under the same version must NOT inherit it.
        let mut other = c.clone();
        other.digest = Some("sha256:bbb".to_string());
        assert!(
            !exception_allows(&pool, &other).await.expect("query ok"),
            "an exception must not carry over to a republished digest"
        );

        // Re-filing with the new digest voids the approval entirely.
        record_refusal(&pool, Some(&bus), &other)
            .await
            .expect("record");
        assert!(
            !exception_allows(&pool, &c).await.expect("query ok"),
            "a digest change returns the row to pending"
        );
        let (status, reviewed, expires): (String, Option<Uuid>, Option<DateTime<Utc>>) =
            sqlx::query_as(
                "SELECT status, reviewed_by, expires_at FROM age_gate_reviews WHERE id = $1",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .expect("reread");
        assert_eq!(status, "pending");
        assert!(reviewed.is_none());
        assert!(expires.is_none(), "a voided decision keeps no expiry");

        // An EXPIRED approval stops serving without any sweep running.
        sqlx::query(
            "UPDATE age_gate_reviews SET status = 'approved',
             expires_at = NOW() - INTERVAL '1 second' WHERE id = $1",
        )
        .bind(id)
        .execute(&pool)
        .await
        .expect("expire");
        assert!(!exception_allows(&pool, &other).await.expect("query ok"));
        assert!(!scan_digest_excepted(&pool, repo_id, "sha256:bbb")
            .await
            .expect("query ok"));

        // A NULL basis_digest never satisfies a digest-bound question.
        sqlx::query(
            "UPDATE age_gate_reviews SET status = 'approved', expires_at = NULL,
             basis_digest = NULL WHERE id = $1",
        )
        .bind(id)
        .execute(&pool)
        .await
        .expect("null digest");
        assert!(
            !exception_allows(&pool, &other).await.expect("query ok"),
            "an ungraded row must not satisfy a digest-bound check"
        );
        // ...but the same row does satisfy a gate that asks without one, which
        // is how curation (no bytes at its seam) is meant to work.
        let curation_shaped = ExceptionCoord {
            gate: GATE_SCAN,
            digest: None,
            ..other.clone()
        };
        assert!(exception_allows(&pool, &curation_shaped)
            .await
            .expect("query ok"));

        // A rejection survives a re-file, as it does on the age gate.
        sqlx::query("UPDATE age_gate_reviews SET status = 'rejected' WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .expect("reject");
        let mut third = other.clone();
        third.digest = Some("sha256:ccc".to_string());
        record_refusal(&pool, Some(&bus), &third)
            .await
            .expect("record");
        let status: String =
            sqlx::query_scalar("SELECT status FROM age_gate_reviews WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("reread");
        assert_eq!(status, "rejected", "a rejection is not undone by new bytes");

        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
    }

    #[test]
    fn render_url_template_encodes_every_placeholder() {
        let out = render_url_template(
            "https://jira.example/new?gate={gate}&repo={repo}&pkg={package}&v={version}",
            "scan",
            "npm-remote",
            "@scope/pkg",
            "1.0.0",
        );
        // A scoped npm name contains `/`, and a Go module path contains
        // several; unencoded they would break out of the query parameter.
        assert!(
            out.contains("pkg=%40scope%2Fpkg"),
            "package must be percent-encoded, got {out}"
        );
        assert!(out.contains("gate=scan"));
        assert!(out.contains("repo=npm-remote"));
        assert!(out.contains("v=1.0.0"));
    }

    #[test]
    fn a_hostile_package_name_cannot_break_out_of_the_link() {
        let out = render_url_template(
            "https://ak.example/exceptions/request?package={package}&version={version}",
            "curation",
            "r",
            "evil\r\nSet-Cookie: x=1&gate=age#",
            "1.0.0\"><script>",
        );
        assert!(!out.contains('\r') && !out.contains('\n') && !out.contains('<'));
        assert!(out.contains("package=evil%0D%0ASet-Cookie%3A%20x%3D1%26gate%3Dage%23"));
        assert!(axum::http::HeaderValue::from_str(&out).is_ok());
    }

    #[test]
    fn validate_url_template_accepts_only_absolute_http_urls() {
        assert!(validate_url_template("").is_ok());
        assert!(validate_url_template("https://jira.example/new?pkg={package}").is_ok());
        assert!(validate_url_template("http://help.internal/{gate}/{package}").is_ok());
        for bad in [
            "javascript:alert(1)",
            "data:text/html,hi",
            "//evil.example/{package}",
            "/exceptions/request",
            "https://a.example/{package} x",
            "https://a.example/\u{7}",
        ] {
            assert!(
                validate_url_template(bad).is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    /// The request surface is open to every signed-in user, so it is bounded per user,
    /// and a request never rewrites the reason an approved row was granted on.
    #[tokio::test]
    async fn db_request_budget_and_approved_rows_keep_their_justification() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (user_id, _) = tdh::create_user(&pool).await;
        let (other_id, _) = tdh::create_user(&pool).await;
        let repo_id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO repositories (id, key, name, format, repo_type, storage_path, upstream_url)
               VALUES ($1, $2, $2, 'npm', 'remote', '/tmp/ph-exq-budget', 'https://registry.npmjs.org')"#,
        )
        .bind(repo_id)
        .bind(format!("ph-exq-budget-{repo_id}"))
        .execute(&pool)
        .await
        .expect("seed repo");
        let at = |v: i64| ExceptionCoord {
            gate: GATE_CURATION,
            repository_id: repo_id,
            package_name: "left-pad".to_string(),
            package_version: format!("1.0.{v}"),
            digest: None,
        };

        for v in 0..MAX_OPEN_REQUESTS_PER_USER {
            require_open_request_budget(&pool, user_id, &at(v))
                .await
                .expect("under the cap");
            file_request(&pool, None, &at(v), user_id, "need it")
                .await
                .expect("file");
        }
        assert!(matches!(
            require_open_request_budget(&pool, user_id, &at(MAX_OPEN_REQUESTS_PER_USER)).await,
            Err(AppError::Conflict(_))
        ));
        // Re-filing one of their own does not count, and another user is unaffected
        require_open_request_budget(&pool, user_id, &at(0))
            .await
            .expect("re-filing an existing request is allowed");
        require_open_request_budget(&pool, other_id, &at(MAX_OPEN_REQUESTS_PER_USER))
            .await
            .expect("the cap is per user");

        let id = file_request(&pool, None, &at(0), user_id, "need it")
            .await
            .expect("file");
        sqlx::query("UPDATE age_gate_reviews SET status = 'approved' WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .expect("approve");
        file_request(&pool, None, &at(0), other_id, "rewritten")
            .await
            .expect("re-file");
        let (why, by): (Option<String>, Option<Uuid>) = sqlx::query_as(
            "SELECT justification, requested_by FROM age_gate_reviews WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("row");
        assert_eq!(why.as_deref(), Some("need it"));
        assert_eq!(by, Some(user_id));

        let _ = sqlx::query("DELETE FROM age_gate_reviews WHERE repository_id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        tdh::cleanup_user(&pool, user_id).await;
        tdh::cleanup_user(&pool, other_id).await;
    }

    #[test]
    fn render_url_template_replaces_repeats_and_ignores_unknown_braces() {
        let out = render_url_template("x/{package}/{package}?q={nope}", "age", "r", "p", "1");
        assert_eq!(out, "x/p/p?q={nope}");
    }

    /// An approval on ONE gate must never satisfy another gate's question.
    ///
    /// This is the property the whole per-gate design exists for: accepting
    /// "too new, but we need it" must not also release the same coordinate
    /// once a scan finds it vulnerable. Three things enforce it (the `gate`
    /// column in the UNIQUE key, the `WHERE gate = $1` filter, and each seam
    /// passing its own constant) and nothing pinned any of them, so a future
    /// read that drops the gate predicate would silently cross-release.
    ///
    /// The coordinate is identical in every field except `gate` -- same digest
    /// shape included -- so a pass here can only come from gate scoping.
    #[tokio::test]
    async fn db_an_approval_on_one_gate_never_satisfies_another() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let repo_id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO repositories (id, key, name, format, repo_type, storage_path, upstream_url)
               VALUES ($1, $2, $2, 'npm', 'remote', '/tmp/ph-exq-gate', 'https://registry.npmjs.org')"#,
        )
        .bind(repo_id)
        .bind(format!("ph-exq-gate-{repo_id}"))
        .execute(&pool)
        .await
        .expect("seed repo");

        // An APPROVED age exception, filed the way the age gate files one:
        // no bytes at its seam, so no basis digest.
        sqlx::query(
            r#"INSERT INTO age_gate_reviews
                 (gate, repository_id, package_name, package_version, status, expires_at)
               VALUES ($1, $2, 'lodash', '4.17.20', 'approved', NULL)"#,
        )
        .bind(GATE_AGE)
        .bind(repo_id)
        .execute(&pool)
        .await
        .expect("seed approved age exception");

        let mut asked = coord(None);
        asked.repository_id = repo_id;

        asked.gate = GATE_AGE;
        assert!(
            exception_allows(&pool, &asked).await.expect("query ok"),
            "the gate it was granted on must serve"
        );

        for other in [GATE_SCAN, GATE_CURATION] {
            asked.gate = other;
            assert!(
                !exception_allows(&pool, &asked).await.expect("query ok"),
                "an age-gate approval must not release the {other} gate"
            );
        }

        sqlx::query("DELETE FROM age_gate_reviews WHERE repository_id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .expect("cleanup");
        sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await
            .expect("cleanup repo");
    }

    #[tokio::test]
    async fn db_exception_request_url_prefers_the_operator_template() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        // No setting: falls back to the built-in form, or to None when no
        // external base URL is configured. Both are valid; assert the shape
        // rather than the presence, since AK_EXTERNAL_URL is environmental.
        let fallback =
            exception_request_url(&pool, "scan", "npm-remote", "lodash", "4.17.20").await;
        if let Some(u) = fallback.as_deref() {
            assert!(u.contains("/exceptions/request?"), "got {u}");
            assert!(u.contains("package=lodash"), "got {u}");
        }

        sqlx::query(
            "INSERT INTO system_settings (key, value) VALUES ($1, $2)
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(EXCEPTION_URL_SETTING_KEY)
        .bind(serde_json::json!("https://ask.example/{gate}/{package}"))
        .execute(&pool)
        .await
        .expect("seed setting");

        let url = exception_request_url(&pool, "scan", "npm-remote", "lodash", "4.17.20")
            .await
            .expect("template configured");
        assert_eq!(url, "https://ask.example/scan/lodash");

        // An empty template is treated as unset, not as a valid empty link.
        sqlx::query("UPDATE system_settings SET value = $2 WHERE key = $1")
            .bind(EXCEPTION_URL_SETTING_KEY)
            .bind(serde_json::json!("   "))
            .execute(&pool)
            .await
            .expect("blank setting");
        let blank = exception_request_url(&pool, "scan", "npm-remote", "lodash", "4.17.20").await;
        assert!(
            blank.as_deref().is_none_or(|u| !u.starts_with("   ")),
            "a blank template must not become the link"
        );

        let _ = sqlx::query("DELETE FROM system_settings WHERE key = $1")
            .bind(EXCEPTION_URL_SETTING_KEY)
            .execute(&pool)
            .await;
    }

    #[test]
    fn validate_request_bounds_a_public_write_surface() {
        assert!(validate_request("lodash", "4.17.20", "needed for the build").is_ok());
        // A justification IS the request; without one there is nothing to
        // distinguish this from a refused pull.
        assert!(validate_request("lodash", "4.17.20", "   ").is_err());
        assert!(validate_request("lodash", "4.17.20", "").is_err());
        assert!(validate_request("", "4.17.20", "why").is_err());
        assert!(validate_request("lodash", "", "why").is_err());
        assert!(validate_request("lodash", "4.17.20", &"x".repeat(MAX_JUSTIFICATION_LEN)).is_ok());
        assert!(
            validate_request("lodash", "4.17.20", &"x".repeat(MAX_JUSTIFICATION_LEN + 1)).is_err()
        );
        assert!(validate_request(&"p".repeat(MAX_COORD_LEN + 1), "1.0", "why").is_err());
    }

    #[tokio::test]
    async fn db_file_request_promotes_attempted_to_requested() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let bus = Arc::new(EventBus::new(16));
        let (user_id, _uname) = tdh::create_user(&pool).await;

        let repo_id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO repositories (id, key, name, format, repo_type, storage_path, upstream_url)
               VALUES ($1, $2, $2, 'npm', 'remote', '/tmp/ph-exq3', 'https://registry.npmjs.org')"#,
        )
        .bind(repo_id)
        .bind(format!("ph-exq3-{repo_id}"))
        .execute(&pool)
        .await
        .expect("seed repo");

        let mut c = coord(Some("sha256:aaa"));
        c.repository_id = repo_id;

        // A gate refused it first: the row exists but nobody asked.
        record_refusal(&pool, Some(&bus), &c).await.expect("record");
        let j: Option<String> = sqlx::query_scalar(
            "SELECT justification FROM age_gate_reviews WHERE gate = $1 AND repository_id = $2",
        )
        .bind(GATE_SCAN)
        .bind(repo_id)
        .fetch_one(&pool)
        .await
        .expect("row");
        assert!(j.is_none(), "auto-filed rows are `attempted`");

        // A human asks: same row, now `requested`.
        let id = file_request(&pool, Some(&bus), &c, user_id, "  we need this  ")
            .await
            .expect("file");
        let (j, by, status): (Option<String>, Option<Uuid>, String) = sqlx::query_as(
            "SELECT justification, requested_by, status FROM age_gate_reviews WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("row");
        assert_eq!(
            j.as_deref(),
            Some("we need this"),
            "justification is trimmed"
        );
        assert_eq!(by, Some(user_id));
        assert_eq!(status, "pending", "asking is not deciding");

        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM age_gate_reviews WHERE gate = $1 AND repository_id = $2",
        )
        .bind(GATE_SCAN)
        .bind(repo_id)
        .fetch_one(&pool)
        .await
        .expect("count");
        assert_eq!(
            count, 1,
            "a request annotates the existing row, never forks it"
        );

        // Filing for a coordinate no gate has refused is allowed: a developer
        // may ask before their build breaks.
        let mut fresh = c.clone();
        fresh.package_name = "never-pulled".to_string();
        fresh.digest = None;
        let fresh_id = file_request(&pool, Some(&bus), &fresh, user_id, "pre-emptive")
            .await
            .expect("file fresh");
        assert_ne!(fresh_id, id);

        // A request against a REJECTED row records the appeal without
        // silently returning it to the queue.
        sqlx::query("UPDATE age_gate_reviews SET status = 'rejected' WHERE id = $1")
            .bind(id)
            .execute(&pool)
            .await
            .expect("reject");
        file_request(&pool, Some(&bus), &c, user_id, "please reconsider")
            .await
            .expect("appeal");
        let status: String =
            sqlx::query_scalar("SELECT status FROM age_gate_reviews WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("row");
        assert_eq!(
            status, "rejected",
            "an appeal is visible to a reviewer, it does not undo their decision"
        );

        let _ = sqlx::query("DELETE FROM age_gate_reviews WHERE repository_id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
    }

    #[tokio::test]
    async fn db_record_refusal_debounces_repeat_pulls() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let bus = Arc::new(EventBus::new(16));

        let repo_id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO repositories (id, key, name, format, repo_type, storage_path, upstream_url)
               VALUES ($1, $2, $2, 'npm', 'remote', '/tmp/ph-exq2', 'https://registry.npmjs.org')"#,
        )
        .bind(repo_id)
        .bind(format!("ph-exq2-{repo_id}"))
        .execute(&pool)
        .await
        .expect("seed repo");

        let mut c = coord(Some("sha256:aaa"));
        c.gate = GATE_CURATION;
        c.repository_id = repo_id;
        c.digest = None;

        for _ in 0..5 {
            record_refusal(&pool, Some(&bus), &c).await.expect("record");
        }
        let count: i32 = sqlx::query_scalar(
            "SELECT request_count FROM age_gate_reviews WHERE gate = $1 AND repository_id = $2",
        )
        .bind(GATE_CURATION)
        .bind(repo_id)
        .fetch_one(&pool)
        .await
        .expect("row");
        assert_eq!(
            count, 1,
            "a burst inside the debounce window is one request, not five"
        );

        let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
            .bind(repo_id)
            .execute(&pool)
            .await;
    }
}
