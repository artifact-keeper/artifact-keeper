//! Composer `search.json` forwarded to a Remote's upstream, opt-in per Remote
//! (#6332).
//!
//! 1.12.4 answers a Composer search from hosted rows only (#6285): a Remote,
//! queried directly or as a Virtual member, adds nothing. Forwarding sends the
//! free-text term (possibly an internal package name) to the upstream, so it
//! is **off unless an administrator turns it on for that Remote**
//! (`composer_upstream_search` in `repository_config`, set through the
//! repository API).
//!
//! When it is on, each upstream read is:
//!
//! * **small**: the body is capped at [`MAX_BODY_BYTES`] (1 MiB), not the
//!   16 MiB metadata ceiling, and held under a buffered-metadata budget
//!   permit while it is read and parsed;
//! * **bounded in time**: [`search_timeout`] (default 5 s, never above the
//!   virtual member metadata deadline), counted against the upstream circuit
//!   like the other own deadlines;
//! * **bounded in fan-out**: one Virtual search forwards to at most
//!   [`MAX_REMOTES`] Remote members;
//! * **shared**: identical searches share one upstream read, in flight and
//!   for [`CACHE_TTL`] afterwards, in a cache bounded by
//!   [`CACHE_MAX_BYTES`]. The key carries the repository, its upstream URL,
//!   a fingerprint of its upstream credentials and every request parameter,
//!   so two Remotes (or one Remote before and after a credential change)
//!   never share an answer. The caller's own access is checked before the
//!   cache is consulted: only Remotes the caller may read are searched.
//! * **fail soft**: an upstream that is down, slow or answers garbage
//!   contributes nothing and the hosted hits are served. A Virtual that found
//!   nothing at all while a forwarded member was unavailable answers `503`
//!   (the virtual rule of #5495), since "no such package" is unknowable.
//!
//! Upstream hits pass the curation rules of the Remote they came from and of
//! the Virtual that was asked (a `block` drops the hit; an evaluation error
//! drops it too). Composer has no age gate, and a search hit names a package,
//! not a version, so there is no version rule to apply here; the age of what
//! is installed is decided when the client fetches the package metadata.

use std::collections::HashSet;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::response::Response;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use super::proxy_helpers::{self, RepoInfo};

/// `repository_config` key opting a Composer Remote into search forwarding.
pub const CONFIG_KEY: &str = "composer_upstream_search";

/// Largest upstream search answer read.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Most Remote members one Virtual search forwards to.
pub const MAX_REMOTES: usize = 4;

/// Env var: seconds one upstream search may take.
pub const SEARCH_TIMEOUT_ENV: &str = "AK_COMPOSER_UPSTREAM_SEARCH_TIMEOUT_SECS";

/// Default of [`SEARCH_TIMEOUT_ENV`].
pub const DEFAULT_SEARCH_TIMEOUT_SECS: u64 = 5;

/// How long an upstream answer is reused.
pub const CACHE_TTL: Duration = Duration::from_secs(60);

/// Bound on the cached answers, by body size.
pub const CACHE_MAX_BYTES: u64 = 16 * 1024 * 1024;

/// Upstream reads by outcome (`page`, `miss`, `unavailable`). A search served
/// from the cache or joined to one in flight reads nothing and is not counted.
pub const FETCHES_METRIC: &str = "ak_composer_upstream_search_fetches_total";

/// Whether the stored `value` turns forwarding on.
pub fn opted_in(value: Option<&str>) -> bool {
    value.is_some_and(|v| v.trim().eq_ignore_ascii_case("true"))
}

/// Whether the setting applies to a repository of this type and format.
pub fn applies_to(repo_type: &str, format: &str) -> bool {
    repo_type.eq_ignore_ascii_case("remote") && format.eq_ignore_ascii_case("composer")
}

/// The ones of `ids` that forward search upstream. A failed read is "none":
/// a lookup error must never send a search term out.
pub async fn enabled_for(db: &PgPool, ids: &[Uuid]) -> HashSet<Uuid> {
    if ids.is_empty() {
        return HashSet::new();
    }
    let rows: Result<Vec<(Uuid, Option<String>)>, _> = sqlx::query_as(
        "SELECT repository_id, value FROM repository_config \
         WHERE repository_id = ANY($1) AND key = $2",
    )
    .bind(ids)
    .bind(CONFIG_KEY)
    .fetch_all(db)
    .await;
    match rows {
        Ok(rows) => rows
            .into_iter()
            .filter(|(_, v)| opted_in(v.as_deref()))
            .map(|(id, _)| id)
            .collect(),
        Err(e) => {
            tracing::warn!(error = %e, "reading {CONFIG_KEY} failed; not forwarding the search");
            HashSet::new()
        }
    }
}

/// The time one upstream search may take: [`SEARCH_TIMEOUT_ENV`] (a zero or
/// unparsable value is the default), never above the virtual member deadline.
pub fn search_timeout() -> Duration {
    static SECS: OnceLock<u64> = OnceLock::new();
    let secs = *SECS.get_or_init(|| {
        std::env::var(SEARCH_TIMEOUT_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(DEFAULT_SEARCH_TIMEOUT_SECS)
    });
    Duration::from_secs(secs).min(proxy_helpers::virtual_member_metadata_timeout())
}

/// One search request, as every source is asked it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SearchRequest<'a> {
    pub query: &'a str,
    pub type_filter: Option<&'a str>,
    pub per_page: i64,
    pub page: i64,
}

/// The upstream `search.json` path for `req`: same term, type, page and size.
pub(crate) fn upstream_path(req: &SearchRequest<'_>) -> String {
    let type_param = req
        .type_filter
        .map(|t| format!("&type={}", urlencoding::encode(t)))
        .unwrap_or_default();
    format!(
        "search.json?q={}{}&per_page={}&page={}",
        urlencoding::encode(req.query),
        type_param,
        req.per_page,
        req.page,
    )
}

/// A plain `vendor/package` name, the only shape put into a hit's `url`.
/// Each part starts with a letter or digit, so `..` and other path segments
/// never pass.
pub(crate) fn is_plain_package_name(name: &str) -> bool {
    let plain = |s: &str| {
        s.starts_with(|c: char| c.is_ascii_alphanumeric())
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    let mut parts = name.split('/');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some(v), Some(p), None) if plain(v) && plain(p)
    )
}

/// One upstream hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UpstreamHit {
    pub name: String,
    pub description: String,
}

/// One upstream page.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct UpstreamPage {
    pub hits: Vec<UpstreamHit>,
    pub total: i64,
    pub has_next: bool,
}

/// Read an upstream answer (Packagist's `search.json` shape). `None` when it
/// is not a search answer. At most `per_page` hits; names that are not plain
/// package names are dropped.
pub(crate) fn parse(body: &[u8], req: &SearchRequest<'_>) -> Option<UpstreamPage> {
    let doc: serde_json::Value = serde_json::from_slice(body).ok()?;
    let hits: Vec<UpstreamHit> = doc
        .get("results")?
        .as_array()?
        .iter()
        .filter_map(|hit| {
            let name = hit.get("name")?.as_str()?;
            if !is_plain_package_name(name) {
                return None;
            }
            let description = hit
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("")
                .to_string();
            Some(UpstreamHit {
                name: name.to_string(),
                description,
            })
        })
        .take(usize::try_from(req.per_page).unwrap_or(0))
        .collect();
    let total = doc
        .get("total")
        .and_then(|t| t.as_i64())
        .unwrap_or(hits.len() as i64)
        .max(0);
    let has_next = doc
        .get("next")
        .and_then(|n| n.as_str())
        .is_some_and(|n| !n.is_empty())
        || req.page.saturating_mul(req.per_page) < total;
    Some(UpstreamPage {
        hits,
        total,
        has_next,
    })
}

/// What one Remote's upstream contributed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Outcome {
    Page(Arc<UpstreamPage>),
    /// No search there (404 and other refusals) or not a search answer.
    Miss,
    /// Down, slow, 5xx, or the metadata budget stayed full: unknown.
    Unavailable,
}

/// A cached answer. `Unavailable` is never cached, so a recovered upstream
/// is asked again on the next search.
#[derive(Debug, Clone)]
enum Cached {
    Page(Arc<UpstreamPage>),
    Miss,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    repo_id: Uuid,
    upstream_url: String,
    auth: String,
    query: String,
    type_filter: Option<String>,
    page: i64,
    per_page: i64,
}

fn cache() -> &'static moka::future::Cache<CacheKey, Cached> {
    static CACHE: OnceLock<moka::future::Cache<CacheKey, Cached>> = OnceLock::new();
    CACHE.get_or_init(|| {
        moka::future::Cache::builder()
            .max_capacity(CACHE_MAX_BYTES)
            .weigher(|k: &CacheKey, v: &Cached| {
                let body: usize = match v {
                    Cached::Page(p) => p
                        .hits
                        .iter()
                        .map(|h| h.name.len() + h.description.len() + 32)
                        .sum(),
                    Cached::Miss => 0,
                };
                u32::try_from(body + k.query.len() + k.upstream_url.len() + 128).unwrap_or(u32::MAX)
            })
            .time_to_live(CACHE_TTL)
            .build()
    })
}

/// A fingerprint of `repo_id`'s upstream credentials, for the cache key.
/// `None` when they cannot be read: that search is not cached.
async fn auth_fingerprint(db: &PgPool, repo_id: Uuid) -> Option<String> {
    match crate::services::upstream_auth::load_upstream_auth(db, repo_id).await {
        Ok(None) => Some("anonymous".to_string()),
        Ok(Some(auth)) => {
            let json = crate::services::upstream_auth::build_credentials_json(&auth);
            Some(hex::encode(&Sha256::digest(json.as_bytes())[..16]))
        }
        Err(e) => {
            tracing::debug!(repo_id = %repo_id, error = %e, "upstream credentials unreadable; search not cached");
            None
        }
    }
}

/// Read one Remote's upstream search: budget permit, cap, timeout.
async fn fetch(
    proxy: &crate::services::proxy_service::ProxyService,
    remote: &RepoInfo,
    upstream_url: &str,
    req: &SearchRequest<'_>,
) -> Outcome {
    let path = upstream_path(req);
    let timeout = search_timeout();
    let outcome =
        match proxy_helpers::reserve_metadata_budget_bounded(MAX_BODY_BYTES, Some(timeout), None)
            .await
        {
            Err(_) => Outcome::Unavailable,
            Ok(_permit) => {
                let read = crate::services::upstream_circuit::within_own_deadline(
                    timeout,
                    proxy_helpers::proxy_fetch_uncached_capped(
                        proxy,
                        remote.id,
                        &remote.key,
                        upstream_url,
                        &path,
                        MAX_BODY_BYTES,
                    ),
                )
                .await;
                match read {
                    Err(_) => {
                        tracing::warn!(
                            repo = %remote.key,
                            timeout_secs = timeout.as_secs_f64(),
                            "composer upstream search did not answer in time; serving local hits"
                        );
                        Outcome::Unavailable
                    }
                    Ok(Err(resp)) if proxy_helpers::is_member_unavailable_response(&resp) => {
                        Outcome::Unavailable
                    }
                    Ok(Err(_)) => Outcome::Miss,
                    Ok(Ok(body)) => {
                        parse(&body, req).map_or(Outcome::Miss, |p| Outcome::Page(Arc::new(p)))
                    }
                }
            }
        };
    let label = match outcome {
        Outcome::Page(_) => "page",
        Outcome::Miss => "miss",
        Outcome::Unavailable => "unavailable",
    };
    metrics::counter!(FETCHES_METRIC, "outcome" => label).increment(1);
    outcome
}

/// Search `remote`'s upstream for `req`, sharing identical searches.
pub(crate) async fn search_remote(
    db: &PgPool,
    proxy: &crate::services::proxy_service::ProxyService,
    remote: &RepoInfo,
    req: &SearchRequest<'_>,
) -> Outcome {
    let Some(upstream_url) = remote.upstream_url.as_deref() else {
        return Outcome::Miss;
    };
    let Some(auth) = auth_fingerprint(db, remote.id).await else {
        return fetch(proxy, remote, upstream_url, req).await;
    };
    let key = CacheKey {
        repo_id: remote.id,
        upstream_url: upstream_url.to_string(),
        auth,
        query: req.query.to_string(),
        type_filter: req.type_filter.map(str::to_string),
        page: req.page,
        per_page: req.per_page,
    };
    // `try_get_with` runs one read per key; concurrent callers wait for it.
    let got = cache()
        .try_get_with(key, async {
            match fetch(proxy, remote, upstream_url, req).await {
                Outcome::Page(p) => Ok(Cached::Page(p)),
                Outcome::Miss => Ok(Cached::Miss),
                Outcome::Unavailable => Err(()),
            }
        })
        .await;
    match got {
        Ok(Cached::Page(p)) => Outcome::Page(p),
        Ok(Cached::Miss) => Outcome::Miss,
        Err(_) => Outcome::Unavailable,
    }
}

/// The Remotes of `candidates` that forward search, at most [`MAX_REMOTES`],
/// in the order given (a Virtual's member priority).
pub(crate) async fn forwarding_remotes(db: &PgPool, candidates: Vec<RepoInfo>) -> Vec<RepoInfo> {
    let candidates: Vec<RepoInfo> = candidates
        .into_iter()
        .filter(|r| r.repo_type == "remote" && r.upstream_url.is_some())
        .collect();
    let ids: Vec<Uuid> = candidates.iter().map(|r| r.id).collect();
    let on = enabled_for(db, &ids).await;
    candidates
        .into_iter()
        .filter(|r| on.contains(&r.id))
        .take(MAX_REMOTES)
        .collect()
}

/// The hits of `page` that every one of `targets` lets through curation.
/// `targets` are the Remote that answered and, for a Virtual search, the
/// Virtual. An evaluation error drops the hit, as the proxy path refuses.
pub(crate) async fn curated(
    db: &PgPool,
    targets: &[&RepoInfo],
    page: &UpstreamPage,
) -> Vec<UpstreamHit> {
    if !targets.iter().any(|t| t.curation_enabled) {
        return page.hits.clone();
    }
    let mut kept = Vec::with_capacity(page.hits.len());
    'hits: for hit in &page.hits {
        for target in targets {
            if proxy_helpers::evaluate_curation(db, *target, &hit.name, None)
                .await
                .is_err()
            {
                continue 'hits;
            }
        }
        kept.push(hit.clone());
    }
    kept
}

/// The 503 a Virtual answers when it found nothing while a forwarded member
/// was unavailable (#5495).
pub(crate) fn nothing_found_while_unavailable() -> Response {
    proxy_helpers::member_unavailable_response()
}

#[cfg(ak_test_shard = "handlers-1")]
#[cfg(test)]
mod tests {
    use super::*;

    fn req(per_page: i64, page: i64) -> SearchRequest<'static> {
        SearchRequest {
            query: "a b&c",
            type_filter: Some("library"),
            per_page,
            page,
        }
    }

    #[test]
    fn upstream_path_forwards_term_type_and_page() {
        assert_eq!(
            upstream_path(&req(15, 2)),
            "search.json?q=a%20b%26c&type=library&per_page=15&page=2"
        );
        let no_type = SearchRequest {
            type_filter: None,
            ..req(5, 1)
        };
        assert_eq!(
            upstream_path(&no_type),
            "search.json?q=a%20b%26c&per_page=5&page=1"
        );
    }

    #[test]
    fn only_plain_package_names_pass() {
        for ok in ["monolog/monolog", "psr/log", "a1/b-c.d_e"] {
            assert!(is_plain_package_name(ok), "{ok}");
        }
        for bad in [
            "../evil", "a/b/c", "a", "/a", "a/", ".a/b", "a/.b", "a b/c", "a/b?x",
        ] {
            assert!(!is_plain_package_name(bad), "{bad}");
        }
    }

    #[test]
    fn parse_reads_packagist_shape_and_bounds_the_page() {
        let body = serde_json::json!({
            "results": [
                {"name": "monolog/monolog", "description": "Logs", "url": "https://x", "downloads": 9},
                {"name": "../evil", "description": "x"},
                {"name": "a/b/c"},
                {"name": "psr/log"},
                {"name": "psr/cache"}
            ],
            "total": 40,
            "next": "https://packagist.org/search.json?q=x&page=2"
        });
        let page = parse(body.to_string().as_bytes(), &req(2, 1)).expect("search answer");
        assert_eq!(
            page.hits
                .iter()
                .map(|h| h.name.as_str())
                .collect::<Vec<_>>(),
            ["monolog/monolog", "psr/log"]
        );
        assert_eq!(page.hits[0].description, "Logs");
        assert_eq!(page.hits[1].description, "");
        assert_eq!(page.total, 40);
        assert!(page.has_next);

        let last = parse(br#"{"results":[{"name":"a/b"}],"total":1}"#, &req(15, 1)).unwrap();
        assert!(!last.has_next);
        assert_eq!(last.total, 1);
        // Not a search answer: a miss, not an empty page.
        assert!(parse(b"<html>", &req(15, 1)).is_none());
        assert!(parse(br#"{"packages":{}}"#, &req(15, 1)).is_none());
    }

    #[test]
    fn opt_in_is_explicit_and_scoped_to_composer_remotes() {
        assert!(opted_in(Some("true")));
        assert!(opted_in(Some(" TRUE ")));
        for off in [None, Some(""), Some("false"), Some("1"), Some("yes")] {
            assert!(!opted_in(off), "{off:?}");
        }
        assert!(applies_to("remote", "composer"));
        assert!(!applies_to("virtual", "composer"));
        assert!(!applies_to("local", "composer"));
        assert!(!applies_to("remote", "npm"));
    }

    #[test]
    fn the_timeout_never_exceeds_the_member_deadline() {
        assert!(search_timeout() <= proxy_helpers::virtual_member_metadata_timeout());
        assert!(search_timeout() > Duration::ZERO);
    }
}
