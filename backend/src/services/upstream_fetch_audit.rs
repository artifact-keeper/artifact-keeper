//! `UPSTREAM_FETCHED` audit rows: a record, in the audit log, of every request
//! the proxy sends to an upstream (#5286).
//!
//! The hook sits inside [`crate::services::upstream_tracing::send_upstream_audited`],
//! the wrapper every `ProxyService` upstream request goes through, so a row is
//! written exactly when bytes leave for the internet: a cache hit sends nothing
//! and records nothing, and a single-flight fill records the leader's request
//! once however many clients wait on it. A `401` bearer challenge, the token
//! exchange it triggers and the retry are three requests and three rows.
//!
//! `AUDIT_UPSTREAM_FETCHES` ([`UpstreamFetchAuditMode`]) chooses what is
//! written: nothing (`off`, the default, which also skips all bookkeeping),
//! failed requests (`errors`) or every request (`all`).
//!
//! The write never delays or fails the request it describes: the row is
//! inserted from a spawned task bounded by a process-wide limiter, and a
//! failed insert is logged and dropped. While the limiter is saturated the
//! insert runs inline instead, so the trail stays complete under load (the
//! posture of `record_proxy_download_via_deferred`, #3778).
//!
//! The recorded URL never carries credentials: `host`, `port` and `path` are
//! taken from the parsed URL, so userinfo, the query string (where signed CDN
//! redirects and some registries carry tokens) and the fragment are never
//! part of the row.

use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use reqwest::header::{IF_MODIFIED_SINCE, IF_NONE_MATCH};
use reqwest::{Method, StatusCode, Url};
use sqlx::PgPool;
use tokio::sync::Semaphore;
use uuid::Uuid;

pub use crate::config::UpstreamFetchAuditMode;
use crate::services::audit_export::Outcome;
use crate::services::audit_service::{
    AuditAction, AuditEntry, AuditService, BlockPrincipal, ResourceType,
};

/// Which part of the proxy sent the request. A conditional request
/// (`If-None-Match` / `If-Modified-Since`) sent as [`UpstreamCaller::Proxy`]
/// is recorded as `revalidate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpstreamCaller {
    /// A cache miss (or uncached pass-through) fetching the resource itself.
    Proxy,
    /// A revalidation of a cached entry.
    Revalidate,
    /// An OCI bearer-token exchange with the realm a `401` named.
    OciToken,
}

impl UpstreamCaller {
    fn as_str(self) -> &'static str {
        match self {
            Self::Proxy => "proxy",
            Self::Revalidate => "revalidate",
            Self::OciToken => "oci_token",
        }
    }
}

/// Where an audited upstream request's row goes. Callers build one only when
/// the mode is not `off`, so an unaudited request costs nothing.
#[derive(Clone)]
pub(crate) struct UpstreamAuditTarget {
    pub(crate) db: PgPool,
    pub(crate) mode: UpstreamFetchAuditMode,
    /// The repository the request was made for; `None` for an instance-level
    /// caller.
    pub(crate) repository_id: Option<Uuid>,
    pub(crate) caller: UpstreamCaller,
}

impl UpstreamAuditTarget {
    /// The target for `mode`, or `None` when `mode` records nothing.
    pub(crate) fn for_mode(
        db: &PgPool,
        mode: UpstreamFetchAuditMode,
        repository_id: Option<Uuid>,
        caller: UpstreamCaller,
    ) -> Option<Self> {
        (mode != UpstreamFetchAuditMode::Off).then(|| Self {
            db: db.clone(),
            mode,
            repository_id,
            caller,
        })
    }
}

/// How an upstream request ended, as recorded in `details.result`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FetchResult {
    Ok,
    NotModified,
    NotFound,
    /// A `401` to a request sent without credentials: the OCI bearer
    /// challenge, which the proxy answers with a token exchange and a retry.
    AuthChallenge,
    Error,
    Timeout,
}

impl FetchResult {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::NotModified => "not_modified",
            Self::NotFound => "not_found",
            Self::AuthChallenge => "auth_challenge",
            Self::Error => "error",
            Self::Timeout => "timeout",
        }
    }

    /// Whether the request failed: what `errors` mode records.
    fn is_failure(self) -> bool {
        matches!(self, Self::NotFound | Self::Error | Self::Timeout)
    }

    /// Classify a request from its response status (`None`: no response,
    /// with `timed_out` set when reqwest gave up waiting).
    pub(crate) fn classify(status: Option<StatusCode>, had_auth: bool, timed_out: bool) -> Self {
        let Some(status) = status else {
            return if timed_out {
                Self::Timeout
            } else {
                Self::Error
            };
        };
        match status {
            StatusCode::NOT_MODIFIED => Self::NotModified,
            StatusCode::NOT_FOUND | StatusCode::GONE => Self::NotFound,
            StatusCode::UNAUTHORIZED if !had_auth => Self::AuthChallenge,
            s if s.is_client_error() || s.is_server_error() => Self::Error,
            _ => Self::Ok,
        }
    }
}

impl UpstreamFetchAuditMode {
    fn records(self, result: FetchResult) -> bool {
        match self {
            Self::Off => false,
            Self::Errors => result.is_failure(),
            Self::All => true,
        }
    }
}

/// One upstream request as it was sent and answered.
#[derive(Debug, Clone)]
pub(crate) struct UpstreamFetch {
    pub(crate) method: Method,
    pub(crate) url: Url,
    /// Whether the request carried `If-None-Match` or `If-Modified-Since`.
    pub(crate) conditional: bool,
    pub(crate) status: Option<StatusCode>,
    pub(crate) result: FetchResult,
    /// The transport error class when no response arrived.
    pub(crate) error_type: Option<&'static str>,
    /// The body length the upstream announced (`Content-Length`; `0` for a
    /// `HEAD` or `304`). `None` for a chunked body or no response.
    pub(crate) bytes: Option<u64>,
    /// The host the request ended on after redirects, when it differs from
    /// the requested one (a CDN a registry redirects blob downloads to).
    pub(crate) redirected_to_host: Option<String>,
    /// Time to response headers.
    pub(crate) duration: Duration,
}

impl UpstreamFetch {
    /// The recorded caller: a conditional `proxy` request is a revalidation.
    fn caller(&self, caller: UpstreamCaller) -> UpstreamCaller {
        if caller == UpstreamCaller::Proxy && self.conditional {
            UpstreamCaller::Revalidate
        } else {
            caller
        }
    }

    /// The row's `details`. Only the URL's host, port and path are recorded,
    /// never its userinfo, query or fragment.
    pub(crate) fn details(
        &self,
        caller: UpstreamCaller,
        repository_id: Option<Uuid>,
        repository: Option<&str>,
        principal: Option<&str>,
    ) -> serde_json::Value {
        serde_json::json!({
            "repository": repository,
            "repository_id": repository_id,
            "caller": self.caller(caller).as_str(),
            "method": self.method.as_str(),
            "host": self.url.host_str(),
            "port": self.url.port_or_known_default(),
            "path": self.url.path(),
            "redirected_to_host": self.redirected_to_host,
            "conditional": self.conditional,
            "status": self.status.map(|s| s.as_u16()),
            "result": self.result.as_str(),
            "error_type": self.error_type,
            "bytes": self.bytes,
            "duration_ms": u64::try_from(self.duration.as_millis()).unwrap_or(u64::MAX),
            "principal": principal,
        })
    }
}

/// What [`send_upstream_audited`](crate::services::upstream_tracing::send_upstream_audited)
/// captures before the request is sent, completed by [`Self::finish`].
pub(crate) struct PendingFetch {
    target: UpstreamAuditTarget,
    method: Method,
    url: Url,
    conditional: bool,
    had_auth: bool,
    principal: BlockPrincipal,
    started: Instant,
}

impl PendingFetch {
    /// Capture `request`. Must run on the calling task, so the principal and
    /// correlation id of the client request that caused it can be read.
    pub(crate) fn start(
        target: UpstreamAuditTarget,
        request: &reqwest::Request,
        had_auth: bool,
    ) -> Self {
        let headers = request.headers();
        Self {
            target,
            method: request.method().clone(),
            url: request.url().clone(),
            conditional: headers.contains_key(IF_NONE_MATCH)
                || headers.contains_key(IF_MODIFIED_SINCE),
            had_auth,
            principal: BlockPrincipal::current(),
            started: Instant::now(),
        }
    }

    /// Record the request's outcome, when the mode asks for it.
    pub(crate) async fn finish(self, result: &reqwest::Result<reqwest::Response>) {
        let duration = self.started.elapsed();
        let (status, bytes, redirected_to_host, error_type, timed_out) = match result {
            Ok(response) => {
                let final_host = response.url().host_str();
                let redirected = (final_host != self.url.host_str())
                    .then(|| final_host.map(str::to_owned))
                    .flatten();
                (
                    Some(response.status()),
                    response.content_length(),
                    redirected,
                    None,
                    false,
                )
            }
            Err(err) => (
                err.status(),
                None,
                None,
                Some(crate::services::upstream_tracing::transport_error_type(err)),
                err.is_timeout(),
            ),
        };
        let fetch = UpstreamFetch {
            method: self.method,
            url: self.url,
            conditional: self.conditional,
            status,
            result: FetchResult::classify(status, self.had_auth, timed_out),
            error_type,
            bytes,
            redirected_to_host,
            duration,
        };
        if self.target.mode.records(fetch.result) {
            record(self.target, self.principal, fetch).await;
        }
    }
}

/// Max concurrent spawned `UPSTREAM_FETCHED` writes: a small slice of the
/// pool, like `MAX_CONCURRENT_PROXY_DOWNLOAD_RECORDS`.
const MAX_CONCURRENT_UPSTREAM_FETCH_RECORDS: usize = 8;

static UPSTREAM_FETCH_RECORD_LIMITER: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_CONCURRENT_UPSTREAM_FETCH_RECORDS)));

async fn record(target: UpstreamAuditTarget, principal: BlockPrincipal, fetch: UpstreamFetch) {
    let Ok(permit) = Arc::clone(&UPSTREAM_FETCH_RECORD_LIMITER).try_acquire_owned() else {
        // Saturated: write inline rather than drop a row.
        write(&target, &principal, &fetch).await;
        return;
    };
    tokio::spawn(async move {
        let _permit = permit;
        write(&target, &principal, &fetch).await;
    });
}

async fn write(target: &UpstreamAuditTarget, principal: &BlockPrincipal, fetch: &UpstreamFetch) {
    let (repository, user_id): (Option<String>, Option<Uuid>) = sqlx::query_as(
        "SELECT (SELECT key FROM repositories WHERE id = $1), \
                (SELECT id FROM users WHERE username = $2 LIMIT 1)",
    )
    .bind(target.repository_id)
    .bind(principal.username.as_deref())
    .fetch_one(&target.db)
    .await
    .unwrap_or_else(|e| {
        tracing::warn!(error = %e, "UPSTREAM_FETCHED context lookup failed; recording without it");
        (None, None)
    });
    let details = fetch.details(
        target.caller,
        target.repository_id,
        repository.as_deref(),
        principal.username.as_deref(),
    );
    let mut entry =
        AuditEntry::new(AuditAction::UpstreamFetched, ResourceType::Repository).details(details);
    if fetch.result.is_failure() {
        entry = entry.outcome(Outcome::Failure);
    }
    if let Some(id) = target.repository_id {
        entry = entry.resource(id);
    }
    if let Some(name) = repository {
        entry = entry.resource_name(name);
    }
    if let Some(user_id) = user_id {
        entry = entry.user(user_id);
    }
    if let Some(username) = principal.username.clone() {
        entry = entry.actor_name(username);
    }
    // The spawned task does not inherit the request's task-locals.
    if let Some(ip) = principal.ip {
        entry = entry.ip(ip);
    }
    if let Some(cid) = principal.correlation_id.as_deref() {
        entry = entry.correlation(cid);
    }
    if let Err(e) = AuditService::new(target.db.clone()).log(entry).await {
        tracing::warn!(error = %e, "failed to record the UPSTREAM_FETCHED audit entry");
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    fn fetch(url: &str, status: Option<u16>, conditional: bool) -> UpstreamFetch {
        let status = status.map(|s| StatusCode::from_u16(s).unwrap());
        UpstreamFetch {
            method: Method::GET,
            url: Url::parse(url).unwrap(),
            conditional,
            status,
            result: FetchResult::classify(status, false, false),
            error_type: None,
            bytes: Some(42),
            redirected_to_host: None,
            duration: Duration::from_millis(7),
        }
    }

    #[test]
    fn details_carry_host_and_path_but_never_credentials_or_query() {
        let f = fetch(
            "https://user:s3cret@files.example:8443/simple/pkg/x.whl?token=abc#frag",
            Some(200),
            false,
        );
        let repo = Uuid::new_v4();
        let d = f.details(
            UpstreamCaller::Proxy,
            Some(repo),
            Some("pypi-remote"),
            Some("ci"),
        );
        assert_eq!(d["repository"], "pypi-remote");
        assert_eq!(d["repository_id"], repo.to_string());
        assert_eq!(d["caller"], "proxy");
        assert_eq!(d["method"], "GET");
        assert_eq!(d["host"], "files.example");
        assert_eq!(d["port"], 8443);
        assert_eq!(d["path"], "/simple/pkg/x.whl");
        assert_eq!(d["status"], 200);
        assert_eq!(d["result"], "ok");
        assert_eq!(d["bytes"], 42);
        assert_eq!(d["duration_ms"], 7);
        assert_eq!(d["principal"], "ci");
        let text = d.to_string();
        for secret in ["user", "s3cret", "token", "abc", "frag"] {
            assert!(!text.contains(secret), "{secret} leaked into {text}");
        }
    }

    #[test]
    fn a_conditional_proxy_request_is_a_revalidation() {
        let f = fetch("https://registry.example/v2/x/manifests/1", Some(304), true);
        let d = f.details(UpstreamCaller::Proxy, None, None, None);
        assert_eq!(d["caller"], "revalidate");
        assert_eq!(d["result"], "not_modified");
        assert_eq!(d["conditional"], true);
        assert_eq!(d["repository_id"], serde_json::Value::Null);
        assert_eq!(d["port"], 443);
        // An explicit caller is kept even for a conditional request.
        assert_eq!(
            f.details(UpstreamCaller::OciToken, None, None, None)["caller"],
            "oci_token"
        );
    }

    #[test]
    fn results_are_classified_from_status_and_transport_error() {
        let classify = |s: Option<u16>, auth, timeout| {
            FetchResult::classify(s.map(|s| StatusCode::from_u16(s).unwrap()), auth, timeout)
        };
        assert_eq!(classify(Some(200), false, false), FetchResult::Ok);
        assert_eq!(classify(Some(302), false, false), FetchResult::Ok);
        assert_eq!(classify(Some(304), false, false), FetchResult::NotModified);
        assert_eq!(classify(Some(404), false, false), FetchResult::NotFound);
        assert_eq!(classify(Some(410), true, false), FetchResult::NotFound);
        assert_eq!(
            classify(Some(401), false, false),
            FetchResult::AuthChallenge
        );
        assert_eq!(classify(Some(401), true, false), FetchResult::Error);
        assert_eq!(classify(Some(403), false, false), FetchResult::Error);
        assert_eq!(classify(Some(500), false, false), FetchResult::Error);
        assert_eq!(classify(Some(503), false, false), FetchResult::Error);
        assert_eq!(classify(None, false, true), FetchResult::Timeout);
        assert_eq!(classify(None, false, false), FetchResult::Error);
    }

    #[test]
    fn mode_selects_which_results_are_recorded() {
        use UpstreamFetchAuditMode::*;
        for result in [
            FetchResult::Ok,
            FetchResult::NotModified,
            FetchResult::AuthChallenge,
        ] {
            assert!(!Off.records(result));
            assert!(!Errors.records(result), "{result:?}");
            assert!(All.records(result));
        }
        for result in [
            FetchResult::NotFound,
            FetchResult::Error,
            FetchResult::Timeout,
        ] {
            assert!(!Off.records(result));
            assert!(Errors.records(result), "{result:?}");
            assert!(All.records(result));
        }
    }

    // A tokio test: `lazy_pool` needs a runtime even though it never connects.
    #[tokio::test]
    async fn mode_parses_from_the_env_value_and_defaults_off() {
        assert_eq!(
            UpstreamFetchAuditMode::default(),
            UpstreamFetchAuditMode::Off
        );
        assert_eq!(
            "off".parse::<UpstreamFetchAuditMode>(),
            Ok(UpstreamFetchAuditMode::Off)
        );
        assert_eq!(
            " Errors ".parse::<UpstreamFetchAuditMode>(),
            Ok(UpstreamFetchAuditMode::Errors)
        );
        assert_eq!(
            "ALL".parse::<UpstreamFetchAuditMode>(),
            Ok(UpstreamFetchAuditMode::All)
        );
        assert!("verbose".parse::<UpstreamFetchAuditMode>().is_err());
        let pool = crate::api::handlers::test_db_helpers::lazy_pool();
        assert!(UpstreamAuditTarget::for_mode(
            &pool,
            UpstreamFetchAuditMode::Off,
            None,
            UpstreamCaller::Proxy
        )
        .is_none());
        assert!(UpstreamAuditTarget::for_mode(
            &pool,
            UpstreamFetchAuditMode::Errors,
            None,
            UpstreamCaller::Proxy
        )
        .is_some());
    }
}
