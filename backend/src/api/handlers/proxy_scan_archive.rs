//! Scan-on-proxy for the archive ecosystems (#4097, 1.12.0): the shared
//! per-format half of the generic gate for Go, RubyGems, Composer and the
//! other archive formats that adopt it.
//!
//! Each of those handlers serves a proxied package file through
//! [`proxy_helpers::serve_scanned_proxy_file`] with a [`ScannedArchive`]: the
//! format supplies only the identity rule ([`ArchiveKind::identity`]) and its
//! content type, and everything else (buffered capped fetch, digest-keyed
//! verdict, fail-open / fail-closed / record-only, the `X-AK-Scan` header, the
//! over-cap stream, download recording) is the gate's. The Virtual walk is
//! [`walk_scanned_archive_members`], on
//! [`proxy_helpers::walk_virtual_members_with_scan`].
//!
//! **What the scan grades.** RubyGems (`Gemfile.lock`, #3603) and, since
//! #4952, Go (`go.mod` require), Composer (`composer.lock`) and Conan
//! (`conan.lock`) have a component pin, so the file is graded as the
//! coordinate the request names as well as on what it bundles. Pub, CocoaPods
//! and Swift have no pin and are graded on their CONTENTS (Pub's
//! `pubspec.yaml` is cataloged as the package itself), the same rule conda
//! follows (#4594). The identity check still runs first: bytes whose own
//! metadata names another coordinate than the request, or that are not a
//! readable package of that kind, are inconclusive and never scanned (no
//! verdict row), exactly like a Cargo crate whose `Cargo.toml` disagrees
//! with its request.

use axum::body::Body;
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::response::Response;
use bytes::Bytes;

use crate::api::handlers::proxy_helpers::{
    self, MemberScanPolicy, ProxyScanIdentity, ScannedProxyBody, ScannedProxyRequest,
};
use crate::api::middleware::download_telemetry::DownloadContext;
use crate::api::SharedState;
use crate::models::repository::Repository;
use crate::services::proxy_service::ProxyService;
use crate::services::scanner_service::ExpectedComponent;
use crate::storage::StorageLocation;

/// Entry-count ceiling for the identity readers below. A package archive is
/// already buffered under the proxy scan byte cap, so this bounds only the
/// central-directory / tar-header walk; it sits far above any real package so
/// a large one is never refused as unreadable (which would withhold it under
/// fail-closed).
pub(crate) const ARCHIVE_IDENTITY_MAX_ENTRIES: u64 = 1_000_000;

/// Read ceiling for the one metadata entry an identity reader opens
/// (`go.mod`, `composer.json`, ...). Real ones are a few KiB.
pub(crate) const ARCHIVE_IDENTITY_MAX_ENTRY_BYTES: u64 = 1024 * 1024;

/// What a proxied package archive says about itself, against the coordinate
/// the request names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ArchiveIdentity {
    /// The archive names the requested coordinate, and the scanner has a pin
    /// for this ecosystem: the engine must catalog exactly this component
    /// before a `clean` verdict is trusted.
    Pinned(ExpectedComponent),
    /// The archive names the requested coordinate (or names nothing that
    /// contradicts it) and the scanner has no pin for this ecosystem: the
    /// bytes are graded on their contents.
    ContentGraded,
    /// The archive names another coordinate than the request.
    Disagrees(String),
    /// Not a readable package of this kind.
    Unreadable(String),
}

impl ArchiveIdentity {
    /// The identity of an archive whose own metadata agreed with the request:
    /// pinned as the REQUEST coordinate (#4952), so the scanner grades the
    /// requested version itself and not only what the archive bundles.
    /// `Unreadable` when the coordinate is outside what a pin can carry
    /// exactly, the same refusal RubyGems makes.
    pub(crate) fn coordinate_pinned(
        ecosystem: crate::services::scanner_service::ComponentEcosystem,
        name: &str,
        version: &str,
    ) -> Self {
        match ExpectedComponent::coordinate_pin(ecosystem, name, version) {
            Some(pin) => ArchiveIdentity::Pinned(pin),
            None => ArchiveIdentity::Unreadable(format!("{name} {version} cannot be pinned")),
        }
    }

    /// The gate's view of this identity. Anything that does not establish the
    /// requested coordinate is [`ProxyScanIdentity::Unestablished`]:
    /// fail-closed withholds it (423) and fail-open serves it pending, both
    /// without scanning, so no verdict is recorded for bytes served under a
    /// coordinate they do not claim.
    pub(crate) fn into_gate_identity(
        self,
        label: &str,
        req: &ScannedProxyRequest<'_>,
        digest: &str,
        requested: &str,
    ) -> ProxyScanIdentity {
        match self {
            ArchiveIdentity::Pinned(pin) => ProxyScanIdentity::Established(pin),
            ArchiveIdentity::ContentGraded => ProxyScanIdentity::NotApplicable,
            ArchiveIdentity::Disagrees(why) | ArchiveIdentity::Unreadable(why) => {
                tracing::warn!(
                    repo_id = %req.repo_id, file = %req.filename, digest = %digest,
                    requested = %requested, reason = %why, format = %label,
                    "proxied package does not declare the identity it is served as"
                );
                ProxyScanIdentity::Unestablished
            }
        }
    }
}

/// The per-format rule of a [`ScannedArchive`].
pub(crate) trait ArchiveKind: Send + Sync {
    /// Short name for log lines, e.g. `"go module zip"`.
    const LABEL: &'static str;
    /// Content type served when the upstream sent none.
    const CONTENT_TYPE: &'static str;

    /// The requested coordinate, for log lines (`module@version`, ...).
    fn requested(&self) -> String;

    /// What these bytes say about themselves against the requested
    /// coordinate. Must come from the REQUEST coordinate and the archive's
    /// own metadata, never from an upstream index.
    fn identity(&self, filename: &str, bytes: &Bytes) -> ArchiveIdentity;
}

/// One proxied package file of an archive format, served through the generic
/// gate (#4097).
pub(crate) struct ScannedArchive<'a, K: ArchiveKind> {
    pub proxy: &'a ProxyService,
    pub kind: K,
    /// `Content-Disposition` file name, when the format's unscanned path sends
    /// one (it is kept identical so a client sees the same headers).
    pub disposition: Option<&'a str>,
}

#[async_trait::async_trait]
impl<K: ArchiveKind> proxy_helpers::ScannedProxyFile for ScannedArchive<'_, K> {
    const LABEL: &'static str = K::LABEL;

    fn synthetic_content_type(_filename: &str) -> String {
        K::CONTENT_TYPE.to_string()
    }

    fn identity(
        &self,
        req: &ScannedProxyRequest<'_>,
        bytes: &Bytes,
        digest: &str,
    ) -> ProxyScanIdentity {
        self.kind.identity(req.filename, bytes).into_gate_identity(
            K::LABEL,
            req,
            digest,
            &self.kind.requested(),
        )
    }

    async fn serve_unscanned_stream(
        &self,
        _state: &SharedState,
        req: &ScannedProxyRequest<'_>,
    ) -> Result<Response, Response> {
        // UNRECORDED-PROXY-SERVE: counted by the caller,
        // `proxy_helpers::serve_scanned_proxy_file`, which records this
        // fail-open over-cap fallback after it resolves (#4098). Needed because
        // the #3446 gate attributes this call to the impl method around it.
        let result = proxy_helpers::proxy_fetch_streaming_with_cache_key(
            self.proxy,
            req.repo_id,
            req.repo_key,
            req.fetch_base,
            req.source_path,
            req.cache_path,
            req.format.clone(),
        )
        .await?;
        proxy_helpers::stream_fetch_result(result, K::CONTENT_TYPE, self.disposition)
    }

    fn scanned_response(
        &self,
        _req: &ScannedProxyRequest<'_>,
        body: ScannedProxyBody,
        pending: bool,
    ) -> Response {
        scanned_archive_response(K::CONTENT_TYPE, self.disposition, body, pending)
    }
}

/// The 200 for buffered archive bytes the gate let through: the same headers
/// the format's streaming path sends (the upstream content type when it
/// declared one, the coding the bytes arrived under, the attachment name),
/// plus `Cache-Control: no-store` on a fail-open serve before the verdict, so
/// a shared cache does not keep bytes nothing has vouched for.
pub(crate) fn scanned_archive_response(
    default_content_type: &str,
    disposition: Option<&str>,
    body: ScannedProxyBody,
    pending: bool,
) -> Response {
    let content_type = body
        .content_type
        .clone()
        .unwrap_or_else(|| default_content_type.to_string());
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .header(CONTENT_LENGTH, body.bytes.len().to_string());
    // Buffered bytes are forwarded verbatim, so their coding is declared.
    if let Some(ref encoding) = body.content_encoding {
        builder = builder.header(CONTENT_ENCODING, encoding);
    }
    if let Some(name) = disposition {
        builder = builder.header(
            CONTENT_DISPOSITION,
            crate::api::download_response::content_disposition_attachment(name),
        );
    }
    if pending {
        builder = builder.header("cache-control", "no-store");
    }
    builder.body(Body::from(body.bytes)).unwrap()
}

/// How the unscanned runs of a scan-aware Virtual walk resolve: the format's
/// existing member resolver path and local lookup, and how the winner is
/// served.
pub(crate) struct UnscannedArchiveRuns<'a, L> {
    pub proxy: &'a ProxyService,
    /// The path the member resolver fetches and caches under.
    pub path: &'a str,
    pub local_fetch: L,
    pub default_content_type: &'a str,
    pub disposition: Option<&'a str>,
    pub ctx: &'a DownloadContext,
}

/// A Virtual download walk with scan-on-proxy for an archive format (#4097).
///
/// `None` when no member scans under the stricter-of-two policy: the caller
/// then takes its untouched resolver. Otherwise members are walked in strict
/// priority order ([`proxy_helpers::walk_virtual_members_with_scan`]): each
/// run of members that do not scan resolves through the format's existing
/// resolver, and each scanning Remote member is served by `scanned` (the
/// format's gate call, under that member's id and upstream). A member's 403,
/// 409 or 423 ends the walk; any other failure moves on.
pub(crate) async fn walk_scanned_archive_members<L, LFut, S, SFut>(
    state: &SharedState,
    virtual_id: uuid::Uuid,
    members: Vec<Repository>,
    runs: UnscannedArchiveRuns<'_, L>,
    scanned: S,
) -> Option<Result<Response, Response>>
where
    L: Fn(uuid::Uuid, StorageLocation) -> LFut,
    LFut: std::future::Future<
        Output = Result<crate::services::proxy_service::StreamingFetchResult, Response>,
    >,
    S: FnMut(Repository, MemberScanPolicy) -> SFut,
    SFut: std::future::Future<Output = Result<Response, Response>>,
{
    let runs = &runs;
    let unscanned_run = |run: Vec<Repository>| async move {
        match proxy_helpers::resolve_virtual_download_from_members(
            run,
            Some(runs.proxy),
            runs.path,
            Some(runs.ctx),
            &runs.local_fetch,
        )
        .await
        {
            Ok(result) => Some(proxy_helpers::stream_fetch_result(
                result,
                runs.default_content_type,
                runs.disposition,
            )),
            Err(resp) if proxy_helpers::is_member_policy_block_response(&resp) => Some(Err(resp)),
            Err(_) => None,
        }
    };
    proxy_helpers::walk_virtual_members_with_scan(
        &state.db,
        virtual_id,
        members,
        unscanned_run,
        scanned,
    )
    .await
}

/// One Remote repository a scanned download is served from:
/// `(id, key, upstream_url)`.
pub(crate) type ScannedRemote = (uuid::Uuid, String, String);

/// How a Virtual's hosted members are looked up for a package file, the
/// lookup the format's unscanned resolver already uses.
#[derive(Clone, Copy)]
pub(crate) enum LocalLookup<'a> {
    /// By trailing file name (RubyGems).
    PathSuffix(&'a str),
    /// By exact artifact path (Conan).
    ExactPath(&'a str),
    /// By `(name, version)` (Pub, CocoaPods, Swift).
    NameVersion { name: &'a str, version: &'a str },
}

/// The package file one scan-aware download route serves.
pub(crate) struct ScannedRoute<'a> {
    /// Upstream path a Remote (and each member) fetches and caches under.
    pub upstream_path: &'a str,
    pub lookup: LocalLookup<'a>,
    /// Content type of an unscanned member serve that declared none.
    pub default_content_type: &'a str,
    /// Attachment name the Virtual's responses carry, when the format sends
    /// one.
    pub virtual_disposition: Option<&'a str>,
}

/// The scan-on-proxy arms of a package download route that proxies
/// `route.upstream_path` from a Remote and walks a Virtual's members (the
/// shape of [`proxy_helpers::try_remote_or_virtual_download`]).
///
/// `Ok(None)` when nothing scans (a Remote with scanning off, a Virtual none
/// of whose Remote members scans, or a Virtual whose Remote members the
/// format's shadowing guard suppressed), so the caller keeps its untouched
/// path. Otherwise `scanned` (the format's gate call) serves the Remote, or
/// each scanning Remote member of the Virtual walk with the Virtual's
/// attachment name; the members that do not scan resolve as before.
pub(crate) async fn serve_scanned_package_download<S, SFut>(
    state: &SharedState,
    auth: Option<&crate::api::middleware::auth::AuthExtension>,
    repo: &proxy_helpers::RepoInfo,
    route: ScannedRoute<'_>,
    suppress_upstream: bool,
    ctx: &DownloadContext,
    scanned: S,
) -> Result<Option<Result<Response, Response>>, Response>
where
    S: Fn(ScannedRemote, MemberScanPolicy, Option<String>) -> SFut,
    SFut: std::future::Future<Output = Result<Response, Response>>,
{
    use crate::models::repository::RepositoryType;
    let Some(proxy) = state.proxy_service.as_deref() else {
        return Ok(None);
    };
    if repo.repo_type == RepositoryType::Remote {
        let Some(upstream_url) = repo.upstream_url.clone() else {
            return Ok(None);
        };
        let Some(policy) = proxy_helpers::remote_scan_policy(&state.db, repo.id).await? else {
            return Ok(None);
        };
        let served = scanned((repo.id, repo.key.clone(), upstream_url), policy, None).await;
        return Ok(Some(served));
    }
    if repo.repo_type != RepositoryType::Virtual || suppress_upstream {
        return Ok(None);
    }
    let members = proxy_helpers::authorized_virtual_members(&state.db, auth, repo.id).await?;
    let lookup = route.lookup;
    let local_fetch = |member_id: uuid::Uuid, location: StorageLocation| async move {
        match lookup {
            LocalLookup::PathSuffix(suffix) => {
                proxy_helpers::local_fetch_by_path_suffix(
                    &state.db, state, member_id, &location, suffix,
                )
                .await
            }
            LocalLookup::ExactPath(path) => {
                proxy_helpers::local_fetch_by_path(&state.db, state, member_id, &location, path)
                    .await
            }
            LocalLookup::NameVersion { name, version } => {
                proxy_helpers::local_fetch_by_name_version(
                    &state.db, state, member_id, &location, name, version,
                )
                .await
            }
        }
    };
    let runs = UnscannedArchiveRuns {
        proxy,
        path: route.upstream_path,
        local_fetch,
        default_content_type: route.default_content_type,
        disposition: route.virtual_disposition,
        ctx,
    };
    let scanned = &scanned;
    let disposition = route.virtual_disposition;
    let member_scanned = |member: Repository, policy| async move {
        let upstream_url = member.upstream_url.clone().unwrap_or_default();
        scanned(
            (member.id, member.key.clone(), upstream_url),
            policy,
            disposition.map(str::to_string),
        )
        .await
    };
    Ok(walk_scanned_archive_members(state, repo.id, members, runs, member_scanned).await)
}

/// The names in a zip's central directory, nothing opened or inflated, or
/// `None` when the bytes are not a readable zip (or exceed
/// [`ARCHIVE_IDENTITY_MAX_ENTRIES`]).
pub(crate) fn zip_entry_names(bytes: &Bytes) -> Option<Vec<String>> {
    let archive = zip::ZipArchive::new(std::io::Cursor::new(&bytes[..])).ok()?;
    if archive.len() as u64 > ARCHIVE_IDENTITY_MAX_ENTRIES {
        return None;
    }
    (0..archive.len())
        .map(|i| {
            archive
                .name_for_index(i)
                .and_then(|name| name.ok().map(|n| n.to_string()))
        })
        .collect()
}

/// The one zip entry named exactly `entry`, read under
/// [`ARCHIVE_IDENTITY_MAX_ENTRY_BYTES`]: `Ok(None)` when absent, `Err` when
/// the bytes are not a readable zip or the entry is oversized.
pub(crate) fn read_zip_entry(bytes: &Bytes, entry: &str) -> Result<Option<Vec<u8>>, String> {
    crate::util::bounded_archive::read_metadata_from_zip_limited(
        std::io::Cursor::new(&bytes[..]),
        |name| name == entry,
        ARCHIVE_IDENTITY_MAX_ENTRIES,
        ARCHIVE_IDENTITY_MAX_ENTRY_BYTES,
    )
    .map_err(|e| e.to_string())
}

/// The first entry of a gzipped tar whose path `matches`, read under the
/// identity caps: `Ok(None)` when none matches (every header was walked, so
/// the bytes are a readable gzipped tar), `Err` when they are not one or a cap
/// is breached.
pub(crate) fn read_tar_gz_entry(
    bytes: &Bytes,
    matches: impl Fn(&std::path::Path) -> bool,
) -> Result<Option<Vec<u8>>, String> {
    crate::util::bounded_archive::read_metadata_from_tar_gz_limited(
        &bytes[..],
        matches,
        crate::services::scanner_service::PROXY_SCAN_MAX_BYTES as u64 * 8,
        ARCHIVE_IDENTITY_MAX_ENTRIES,
        ARCHIVE_IDENTITY_MAX_ENTRY_BYTES,
    )
    .map_err(|e| e.to_string())
}

/// Shared DB-backed scenarios for the archive formats' scan-on-proxy suites
/// (#4097). Holds no tests itself; each format's suite drives these with its
/// own route and fixture, so the per-format suites stay a few lines each.
///
/// The state carries NO scanner service, so a first-pull scan is
/// inconclusive (fail-closed 423, fail-open served `pending`); clean and
/// vulnerable outcomes come from verdicts seeded for the content digest, the
/// same way the Cargo, npm and PyPI suites drive the gate.
#[cfg(test)]
#[allow(clippy::disallowed_methods)]
pub(crate) mod test_support {
    use crate::api::handlers::test_db_helpers as tdh;
    use crate::api::SharedState;
    use axum::http::{HeaderMap, StatusCode};
    use axum::Router;
    use bytes::Bytes;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// One format's fixture, built once the mock upstream's address is known
    /// (a Composer dist URL names it).
    pub(crate) struct ArchiveCase {
        /// `repository_format` of both Remotes and the Virtual.
        pub format: &'static str,
        /// The handler's router, mounted at the root as its own tests do.
        pub router: fn() -> Router<SharedState>,
        /// The client URI of the package file for a repository key.
        pub uri: Box<dyn Fn(&str) -> String + Send + Sync>,
        /// Upstream path the package bytes are fetched from.
        pub package_path: String,
        /// Other upstream documents the route reads first (metadata).
        pub extra: Vec<(String, Vec<u8>)>,
        /// The package bytes.
        pub body: Vec<u8>,
        /// The proxy-cache path the pull is recorded under.
        pub recorded_path: String,
        /// The `file` a 403 / 423 body names.
        pub file: String,
    }

    pub(crate) type CaseFn = fn(&str) -> ArchiveCase;

    /// A Remote repository and a Virtual over a second Remote member, both
    /// proxying one mock upstream (non-loopback, so a dist URL the upstream
    /// names passes the SSRF guard), each with scan-on-proxy at `action`.
    pub(crate) struct Rig {
        pub fx: tdh::Fixture,
        pub state: SharedState,
        _cache_dir: tempfile::TempDir,
        pub server: MockServer,
        _ssrf: tdh::SsrfTestAllowlistGuard,
        pub member_id: uuid::Uuid,
        pub virtual_id: uuid::Uuid,
        pub virtual_key: String,
        pub case: ArchiveCase,
    }

    impl Rig {
        pub(crate) async fn new(case: CaseFn, action: Option<&str>) -> Option<Self> {
            let (server, ssrf) = tdh::non_loopback_mock_server().await;
            let case = case(&server.uri());
            let fx = tdh::Fixture::setup("remote", case.format).await?;
            let (state, cache_dir) = tdh::rewire_remote_proxy(&fx, &server.uri()).await;
            let (member_id, _member_key, virtual_id, virtual_key) =
                tdh::create_remote_and_virtual(&fx.pool, case.format, &server.uri()).await;
            tdh::publish_repo(&fx.pool, virtual_id).await;
            if let Some(action) = action {
                tdh::enable_proxy_scan(&fx.pool, fx.repo_id, action).await;
                tdh::enable_proxy_scan(&fx.pool, member_id, action).await;
            }
            for (doc_path, doc) in &case.extra {
                Mock::given(method("GET"))
                    .and(path(doc_path.clone()))
                    .respond_with(ResponseTemplate::new(200).set_body_bytes(doc.clone()))
                    .mount(&server)
                    .await;
            }
            Mock::given(method("GET"))
                .and(path(case.package_path.clone()))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(case.body.clone()))
                .mount(&server)
                .await;
            Some(Self {
                fx,
                state,
                _cache_dir: cache_dir,
                server,
                _ssrf: ssrf,
                member_id,
                virtual_id,
                virtual_key,
                case,
            })
        }

        pub(crate) async fn get(&self, repo_key: &str) -> (StatusCode, Bytes, HeaderMap) {
            tdh::send_with_headers(
                tdh::router_anon((self.case.router)(), self.state.clone()),
                tdh::get((self.case.uri)(repo_key)),
            )
            .await
        }

        pub(crate) async fn pull_remote(&self) -> (StatusCode, Bytes, HeaderMap) {
            self.get(&self.fx.repo_key.clone()).await
        }

        pub(crate) async fn pull_virtual(&self) -> (StatusCode, Bytes, HeaderMap) {
            self.get(&self.virtual_key.clone()).await
        }

        pub(crate) fn digest(&self) -> String {
            crate::services::storage_service::StorageService::calculate_hash(&self.case.body)
        }

        /// Seed `verdict` for the package's digest (`clean` / `vulnerable`).
        pub(crate) async fn seed(&self, verdict: &str) {
            let vulnerable = verdict == "vulnerable";
            crate::services::proxy_scan_service::ProxyScanService::new(self.fx.pool.clone())
                .record_verdict(
                    &self.digest(),
                    "grype",
                    verdict,
                    i32::from(vulnerable),
                    i32::from(vulnerable),
                    0,
                    0,
                    0,
                    vulnerable.then_some("critical"),
                    Some("grype-4097-test"),
                    Some(self.fx.repo_id),
                )
                .await
                .expect("seed verdict");
        }

        /// Proxy downloads recorded for the package on `repo_id` (#3446).
        pub(crate) async fn recorded(&self, repo_id: uuid::Uuid) -> i64 {
            let path = self.case.recorded_path.clone();
            crate::services::proxy_catalog::download_counts_by_paths(
                &self.fx.pool,
                repo_id,
                std::slice::from_ref(&path),
            )
            .await
            .unwrap()
            .get(&path)
            .copied()
            .unwrap_or(0)
        }

        /// Upstream GETs of the package file so far.
        pub(crate) async fn package_fetches(&self) -> usize {
            self.server
                .received_requests()
                .await
                .unwrap_or_default()
                .iter()
                .filter(|r| r.url.path() == self.case.package_path)
                .count()
        }

        pub(crate) async fn teardown(self) {
            let pool = self.fx.pool.clone();
            for id in [self.virtual_id, self.member_id] {
                for sql in [
                    "DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1 OR member_repo_id = $1",
                    "DELETE FROM scan_configs WHERE repository_id = $1",
                    "DELETE FROM repositories WHERE id = $1",
                ] {
                    let _ = sqlx::query(sqlx::AssertSqlSafe(sql))
                        .bind(id)
                        .execute(&pool)
                        .await;
                }
            }
            let _ = sqlx::query("DELETE FROM scan_configs WHERE repository_id = $1")
                .bind(self.fx.repo_id)
                .execute(&pool)
                .await;
            self.fx.teardown().await;
        }
    }

    pub(crate) fn scan_header(headers: &HeaderMap) -> Option<String> {
        headers
            .get("X-AK-Scan")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    }

    fn json(body: &Bytes) -> serde_json::Value {
        serde_json::from_slice(body).unwrap_or_default()
    }

    /// A clean verdict serves the upstream bytes with `X-AK-Scan: clean`;
    /// the second pull reuses the verdict and the proxy cache (one upstream
    /// fetch) and each pull is counted once.
    pub(crate) async fn clean_is_served_and_the_verdict_reused(case: CaseFn) {
        // fail_open: a cached CLEAN verdict serves without a live scanner
        // (the #2976 unknown-live-version re-scan is fail_closed-only).
        let Some(rig) = Rig::new(case, Some("fail_open")).await else {
            return;
        };
        rig.seed("clean").await;
        for pull in 1..=2 {
            let (status, served, headers) = rig.pull_remote().await;
            assert_eq!(status, StatusCode::OK, "pull {pull}");
            assert_eq!(
                scan_header(&headers).as_deref(),
                Some("clean"),
                "pull {pull}"
            );
            assert_eq!(&served[..], &rig.case.body[..], "pull {pull}");
            assert_eq!(rig.recorded(rig.fx.repo_id).await, pull, "pull {pull}");
        }
        assert_eq!(
            rig.package_fetches().await,
            1,
            "the second pull is a cache hit"
        );
        rig.teardown().await;
    }

    /// A vulnerable verdict refuses the pull: 403 `scan_blocked` naming the
    /// file, nothing recorded.
    pub(crate) async fn vulnerable_is_blocked(case: CaseFn) {
        let Some(rig) = Rig::new(case, Some("fail_open")).await else {
            return;
        };
        rig.seed("vulnerable").await;
        let (status, body, _) = rig.pull_remote().await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(json(&body)["error"], "scan_blocked");
        assert_eq!(json(&body)["file"], rig.case.file.as_str());
        assert_eq!(rig.recorded(rig.fx.repo_id).await, 0);
        rig.teardown().await;
    }

    /// Fail-closed with no verdict and no scanner: 423, never the bytes.
    pub(crate) async fn fail_closed_without_a_verdict_is_locked(case: CaseFn) {
        let Some(rig) = Rig::new(case, Some("fail_closed")).await else {
            return;
        };
        let (status, body, _) = rig.pull_remote().await;
        assert_eq!(status, StatusCode::LOCKED);
        assert_eq!(json(&body)["error"], "scan_pending");
        assert_eq!(rig.recorded(rig.fx.repo_id).await, 0);
        rig.teardown().await;
    }

    /// Fail-open with no verdict: served loudly pending, not kept by shared
    /// caches, counted once.
    pub(crate) async fn fail_open_first_pull_is_served_pending(case: CaseFn) {
        let Some(rig) = Rig::new(case, Some("fail_open")).await else {
            return;
        };
        let (status, served, headers) = rig.pull_remote().await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(scan_header(&headers).as_deref(), Some("pending"));
        assert_eq!(headers["cache-control"], "no-store");
        assert_eq!(&served[..], &rig.case.body[..]);
        assert_eq!(rig.recorded(rig.fx.repo_id).await, 1);
        rig.teardown().await;
    }

    /// Record-only: a vulnerable verdict is recorded, not enforced.
    pub(crate) async fn record_only_serves_a_vulnerable_verdict(case: CaseFn) {
        let Some(rig) = Rig::new(case, Some("record_only")).await else {
            return;
        };
        rig.seed("vulnerable").await;
        let (status, served, headers) = rig.pull_remote().await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(scan_header(&headers).as_deref(), Some("recorded"));
        assert_eq!(&served[..], &rig.case.body[..]);
        rig.teardown().await;
    }

    /// The control: scan-on-proxy off streams the bytes through the
    /// untouched path, no verdict consulted.
    pub(crate) async fn without_scan_on_proxy_streams_unscanned(case: CaseFn) {
        let Some(rig) = Rig::new(case, None).await else {
            return;
        };
        rig.seed("vulnerable").await;
        let (status, served, headers) = rig.pull_remote().await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(scan_header(&headers), None);
        assert_eq!(&served[..], &rig.case.body[..]);
        let (status, _, headers) = rig.pull_virtual().await;
        assert_eq!(status, StatusCode::OK, "virtual over an unscanned member");
        assert_eq!(scan_header(&headers), None);
        rig.teardown().await;
    }

    /// Through a Virtual whose Remote member scans: the member's verdict
    /// decides (vulnerable 403, then clean 200 once the verdict says so), and
    /// the pull counts to the member.
    pub(crate) async fn virtual_member_is_gated(case: CaseFn) {
        let Some(rig) = Rig::new(case, Some("fail_open")).await else {
            return;
        };
        rig.seed("vulnerable").await;
        let (status, body, _) = rig.pull_virtual().await;
        assert_eq!(status, StatusCode::FORBIDDEN, "vulnerable via the virtual");
        assert_eq!(json(&body)["error"], "scan_blocked");
        sqlx::query("DELETE FROM proxy_scan_results WHERE checksum_sha256 = $1")
            .bind(rig.digest())
            .execute(&rig.fx.pool)
            .await
            .unwrap();
        rig.seed("clean").await;
        let (status, served, headers) = rig.pull_virtual().await;
        assert_eq!(status, StatusCode::OK, "clean via the virtual");
        assert_eq!(scan_header(&headers).as_deref(), Some("clean"));
        assert_eq!(&served[..], &rig.case.body[..]);
        assert_eq!(
            rig.recorded(rig.member_id).await,
            1,
            "counted to the member"
        );
        rig.teardown().await;
    }

    /// The scenarios above as one `#[tokio::test]` each, for one format's
    /// [`CaseFn`]: `archive_scan_suite!(my_case);` inside the format's test
    /// module.
    macro_rules! archive_scan_suite {
        ($case:path) => {
            #[tokio::test]
            async fn clean_is_served_and_the_verdict_reused() {
                $crate::api::handlers::proxy_scan_archive::test_support::clean_is_served_and_the_verdict_reused($case).await;
            }
            #[tokio::test]
            async fn vulnerable_is_blocked() {
                $crate::api::handlers::proxy_scan_archive::test_support::vulnerable_is_blocked($case).await;
            }
            #[tokio::test]
            async fn fail_closed_without_a_verdict_is_locked() {
                $crate::api::handlers::proxy_scan_archive::test_support::fail_closed_without_a_verdict_is_locked($case).await;
            }
            #[tokio::test]
            async fn fail_open_first_pull_is_served_pending() {
                $crate::api::handlers::proxy_scan_archive::test_support::fail_open_first_pull_is_served_pending($case).await;
            }
            #[tokio::test]
            async fn record_only_serves_a_vulnerable_verdict() {
                $crate::api::handlers::proxy_scan_archive::test_support::record_only_serves_a_vulnerable_verdict($case).await;
            }
            #[tokio::test]
            async fn without_scan_on_proxy_streams_unscanned() {
                $crate::api::handlers::proxy_scan_archive::test_support::without_scan_on_proxy_streams_unscanned($case).await;
            }
            #[tokio::test]
            async fn virtual_member_is_gated() {
                $crate::api::handlers::proxy_scan_archive::test_support::virtual_member_is_gated($case).await;
            }
        };
    }
    pub(crate) use archive_scan_suite;
}

#[cfg(ak_test_shard = "handlers-2")]
#[cfg(test)]
mod tests {
    use super::*;

    fn zip_with(entries: &[(&str, &[u8])]) -> Bytes {
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut buf);
            for (name, data) in entries {
                zip.start_file(*name, zip::write::SimpleFileOptions::default())
                    .unwrap();
                std::io::Write::write_all(&mut zip, data).unwrap();
            }
            zip.finish().unwrap();
        }
        Bytes::from(buf.into_inner())
    }

    #[test]
    fn zip_readers_list_names_and_read_one_entry() {
        let z = zip_with(&[("a/go.mod", b"module a\n"), ("a/x.go", b"package a\n")]);
        assert_eq!(
            zip_entry_names(&z).unwrap(),
            vec!["a/go.mod".to_string(), "a/x.go".to_string()]
        );
        assert_eq!(
            read_zip_entry(&z, "a/go.mod").unwrap().as_deref(),
            Some(&b"module a\n"[..])
        );
        assert_eq!(read_zip_entry(&z, "go.mod").unwrap(), None);
        assert!(zip_entry_names(&Bytes::from_static(b"not a zip")).is_none());
        assert!(read_zip_entry(&Bytes::from_static(b"not a zip"), "go.mod").is_err());
    }

    /// Only an archive that establishes the requested coordinate is
    /// scanned: a pinned one is graded as that component, a content-graded
    /// one on its contents, and anything else is `Unestablished` (never
    /// scanned, no verdict row).
    #[test]
    fn archive_identity_maps_onto_the_gate() {
        use crate::services::scanner_service::ComponentEcosystem;
        let req = ScannedProxyRequest {
            repo_id: uuid::Uuid::nil(),
            repo_key: "remote",
            fetch_base: "http://upstream.invalid",
            format: crate::models::repository::RepositoryFormat::Go,
            source_path: "m/@v/v1.zip",
            cache_path: "m/@v/v1.zip",
            filename: "v1.zip",
            action: crate::services::proxy_scan_service::ProxyScanAction::FailClosed,
            severity_gate: crate::services::proxy_scan_service::ProxySeverityGate::BlockOnAny,
            ctx: None,
        };
        let pin = ExpectedComponent::new(ComponentEcosystem::RubyGems, "rack", "2.0.7");
        let gate = |id: ArchiveIdentity| id.into_gate_identity("t", &req, "d", "m@v1");
        assert!(matches!(
            gate(ArchiveIdentity::Pinned(pin.clone())),
            ProxyScanIdentity::Established(p) if p == pin
        ));
        assert!(matches!(
            gate(ArchiveIdentity::ContentGraded),
            ProxyScanIdentity::NotApplicable
        ));
        assert!(matches!(
            gate(ArchiveIdentity::Disagrees("x".into())),
            ProxyScanIdentity::Unestablished
        ));
        assert!(matches!(
            gate(ArchiveIdentity::Unreadable("x".into())),
            ProxyScanIdentity::Unestablished
        ));
    }

    #[test]
    fn scanned_archive_response_declares_what_the_bytes_are() {
        let body = |ct: Option<&str>, enc: Option<&str>| ScannedProxyBody {
            bytes: Bytes::from_static(b"zipbytes"),
            content_type: ct.map(str::to_string),
            content_encoding: enc.map(str::to_string),
            digest: "d".to_string(),
        };
        let resp = scanned_archive_response("application/zip", None, body(None, None), false);
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()[CONTENT_TYPE], "application/zip");
        assert_eq!(resp.headers()[CONTENT_LENGTH], "8");
        assert!(resp.headers().get("cache-control").is_none());
        assert!(resp.headers().get(CONTENT_DISPOSITION).is_none());

        let resp = scanned_archive_response(
            "application/zip",
            Some("x-1.0.zip"),
            body(Some("application/octet-stream"), Some("gzip")),
            true,
        );
        assert_eq!(resp.headers()[CONTENT_TYPE], "application/octet-stream");
        assert_eq!(resp.headers()[CONTENT_ENCODING], "gzip");
        assert_eq!(resp.headers()["cache-control"], "no-store");
        assert!(resp.headers()[CONTENT_DISPOSITION]
            .to_str()
            .unwrap()
            .contains("x-1.0.zip"));
    }
}
