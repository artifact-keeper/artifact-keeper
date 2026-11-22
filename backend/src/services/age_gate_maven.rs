//! Maven and Gradle support for the publish-age gate (#4702).
//!
//! The shared policy (modes, reviews, approvals, the 451 refusal) lives in
//! [`crate::services::age_gate_service`]; this module holds what is specific
//! to the Maven repository layout: which request paths name a gated version,
//! where a version's publish time comes from, and how a
//! `maven-metadata.xml` version list is rewritten once some versions are
//! withheld.
//!
//! # Publish time
//!
//! A version's publish time is the upstream's `Last-Modified` on that
//! version's POM (`g/a/v/a-v.pom`). Every Maven release has a POM, the
//! repository manager (Maven Central, Nexus, Artifactory) stamps it when the
//! version is deployed, and a released coordinate is immutable, so the time
//! never moves once known. The POM is fetched through the proxy cache, which
//! already records the upstream `Last-Modified` on its cache entry (the same
//! release date the Package Age Policy reads, #3912), so a version is dated
//! once per repository and later decisions read the cached entry.
//!
//! The other candidates were rejected:
//! * `maven-metadata.xml` `lastUpdated` is one timestamp for the whole
//!   `groupId:artifactId` (the last deploy of any version), not per version.
//!   It is used for one thing only: when it is older than the minimum age,
//!   every version it lists is at least that old, so the listing filter needs
//!   no POM fetches at all. It is never used to admit a version on download.
//! * A search index (Maven Central's) is specific to one upstream and is not
//!   part of the repository layout other managers serve.
//!
//! No POM, or no parseable `Last-Modified`, means no publish time, and the
//! gate withholds the version (the #2066 rule every format follows). An
//! upstream that sends no `Last-Modified` should use the `first_seen` mode.
//!
//! # SNAPSHOT versions
//!
//! `-SNAPSHOT` versions are not gated. A SNAPSHOT is rebuilt under the same
//! version by design, so "this version is N days old" has no meaning for it
//! and a `first_seen` clock would age content that changes every build. Keep
//! snapshots in their own Remote, which the age gate is not meant for.

use std::collections::HashSet;
use std::time::Duration;

use chrono::{DateTime, NaiveDateTime, Utc};
use moka::future::Cache as MokaCache;
use once_cell::sync::Lazy;
use uuid::Uuid;

use crate::formats::maven::MavenHandler;
use crate::formats::maven_version;

/// The version a Maven-layout request path names, when the age gate applies
/// to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MavenGateTarget {
    /// `groupId:artifactId`, the identity curation and the proxy catalog use.
    pub package: String,
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
    /// The version directory exactly as the request spelled it (normalized
    /// as the proxy cache keys it). The POM that dates the version is read
    /// from this directory, never from a path rebuilt out of `group_id`: a
    /// request whose group segments contain a `.` would otherwise fetch its
    /// bytes from one upstream directory and be dated by another's POM.
    pub version_dir: String,
}

impl MavenGateTarget {
    /// Repository path of this version's POM, whose `Last-Modified` dates it:
    /// the POM in the same upstream directory the requested file comes from.
    pub fn pom_path(&self) -> String {
        format!(
            "{}/{}-{}.pom",
            self.version_dir, self.artifact_id, self.version
        )
    }
}

/// Sidecar suffixes that describe the file they are appended to: a gated
/// version's `.sha1` (and signature) answers exactly as the file does.
const SIDECAR_SUFFIXES: [&str; 5] = [".sha1", ".md5", ".sha256", ".sha512", ".asc"];

/// The gated version a request path names: any file in a version directory
/// (jar, POM, Gradle module, sources, javadoc, classifier archives) and its
/// checksum and signature sidecars, named by the path's own coordinate.
/// `None` for `maven-metadata.xml` (filtered instead, see
/// [`filter_metadata_versions`]), for paths that do not parse as a Maven
/// coordinate, and for `-SNAPSHOT` versions (see the module docs).
pub fn gate_target(path: &str) -> Option<MavenGateTarget> {
    let mut base = crate::services::proxy_service::normalize_cache_path(path);
    // Strip at most two sidecar layers (`x.jar.asc.sha1` is a real layout).
    for _ in 0..2 {
        let lower = base.to_ascii_lowercase();
        match SIDECAR_SUFFIXES.iter().find(|s| lower.ends_with(*s)) {
            Some(suffix) => base = &base[..base.len() - suffix.len()],
            None => break,
        }
    }
    let file = base.rsplit('/').next().unwrap_or(base);
    if file.eq_ignore_ascii_case("maven-metadata.xml") {
        return None;
    }
    let coords = MavenHandler::parse_coordinates(base).ok()?;
    if coords.version.ends_with("-SNAPSHOT") {
        return None;
    }
    let (version_dir, _) = base.rsplit_once('/')?;
    Some(MavenGateTarget {
        package: format!("{}:{}", coords.group_id, coords.artifact_id),
        group_id: coords.group_id,
        artifact_id: coords.artifact_id,
        version: coords.version,
        version_dir: version_dir.to_string(),
    })
}

/// Parse an HTTP `Last-Modified` value (RFC 7231 IMF-fixdate, RFC 2822
/// compatible). `None` when absent or unparseable.
pub fn parse_last_modified(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc2822(value.trim())
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

/// Parse a `maven-metadata.xml` `<lastUpdated>` value (`yyyyMMddHHmmss`, UTC).
pub fn parse_last_updated(value: &str) -> Option<DateTime<Utc>> {
    NaiveDateTime::parse_from_str(value.trim(), "%Y%m%d%H%M%S")
        .ok()
        .map(|naive| naive.and_utc())
}

/// Process-local memo of resolved publish times, keyed by (repository,
/// upstream base URL, POM path). A released Maven version's POM never
/// changes, so its date is stable; the key carries the upstream so a repointed
/// Remote never reuses a date read from its previous upstream, and the bound
/// and TTL only cap memory.
static PUBLISH_TIMES: Lazy<MokaCache<(Uuid, String, String), DateTime<Utc>>> = Lazy::new(|| {
    MokaCache::builder()
        .max_capacity(100_000)
        .time_to_live(Duration::from_secs(24 * 3600))
        .build()
});

pub async fn memo_publish_time(
    repo_id: Uuid,
    upstream_url: &str,
    target: &MavenGateTarget,
) -> Option<DateTime<Utc>> {
    PUBLISH_TIMES
        .get(&(repo_id, upstream_url.to_string(), target.pom_path()))
        .await
}

pub async fn remember_publish_time(
    repo_id: Uuid,
    upstream_url: &str,
    target: &MavenGateTarget,
    published: DateTime<Utc>,
) {
    PUBLISH_TIMES
        .insert(
            (repo_id, upstream_url.to_string(), target.pom_path()),
            published,
        )
        .await;
}

/// Most POMs one listing will fetch to date its versions. A
/// `groupId:artifactId` updated inside the gate window with more undated
/// versions than this has the oldest undated ones (by Maven version order)
/// withheld from that listing until they are dated; downloads still decide
/// each version on its own POM. Already dated versions cost no probe and
/// every fetched date is remembered, so the next listing probes the next
/// undated versions and continues where this one stopped.
pub const LISTING_MAX_POM_PROBES: usize = 64;

/// How many POMs a listing fetches at once.
pub const LISTING_POM_CONCURRENCY: usize = 8;

/// How long a filtered listing that left versions undated is reused (#6284).
///
/// While a GA is still being dated, every filter pass dates the next
/// [`LISTING_MAX_POM_PROBES`] versions and so returns a longer document than
/// the one before. Without this memo the `maven-metadata.xml.sha1` request
/// (a second pass) hashed a different document than the body the client had
/// just downloaded, and two downloads in a row differed. Within this window
/// the body and every checksum sidecar are served from the same bytes; the
/// next pass after it continues dating where the memoized one stopped.
pub const LISTING_MEMO_TTL: Duration = Duration::from_secs(15);

/// What a memoized filtered listing is keyed by: the repository, its
/// upstream, the metadata path, the policy that filtered it and a digest of
/// the upstream document it was filtered from, so a changed upstream
/// document, a repointed Remote or a changed policy never reuses it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ListingMemoKey {
    repo_id: Uuid,
    upstream_url: String,
    path: String,
    min_age_days: i32,
    mode: &'static str,
    upstream_sha256: [u8; 32],
}

impl ListingMemoKey {
    pub fn new(
        repo_id: Uuid,
        upstream_url: &str,
        path: &str,
        min_age_days: i32,
        mode: &'static str,
        upstream_doc: &[u8],
    ) -> Self {
        use sha2::{Digest, Sha256};
        Self {
            repo_id,
            upstream_url: upstream_url.to_string(),
            path: path.trim_matches('/').to_string(),
            min_age_days,
            mode,
            upstream_sha256: Sha256::digest(upstream_doc).into(),
        }
    }
}

/// Total bytes of memoized listings kept at once. Weighed by document size,
/// so a few very large `maven-metadata.xml` documents cannot pin far more
/// memory than this.
const LISTING_MEMO_MAX_BYTES: u64 = 64 * 1024 * 1024;

static LISTINGS: Lazy<MokaCache<ListingMemoKey, bytes::Bytes>> = Lazy::new(|| {
    MokaCache::builder()
        .weigher(|_, v: &bytes::Bytes| v.len().min(u32::MAX as usize) as u32)
        .max_capacity(LISTING_MEMO_MAX_BYTES)
        .time_to_live(LISTING_MEMO_TTL)
        .support_invalidation_closures()
        .build()
});

/// The filtered listing a recent pass produced for `key`, if any.
pub async fn memo_listing(key: &ListingMemoKey) -> Option<bytes::Bytes> {
    LISTINGS.get(key).await
}

/// Keep a filtered listing whose pass left versions undated, so the next
/// requests for the document and its checksums within [`LISTING_MEMO_TTL`]
/// get the same bytes, and return the listing to serve. The first writer
/// wins: when concurrent passes over one document finish, each serves the
/// listing stored first, so no client in the window gets a body whose
/// checksum a later request contradicts.
pub async fn remember_listing(key: ListingMemoKey, filtered: bytes::Bytes) -> bytes::Bytes {
    LISTINGS.entry(key).or_insert(filtered).await.into_value()
}

/// The passes in flight per memo key (#6284). A pass holds its key's lock
/// from the memo check to the memo store, so a concurrent pass over the same
/// document waits and then serves what the first one stored, instead of
/// running its own pass on the dates the first one is still adding: that
/// second pass could date every version, store nothing, and serve the whole
/// upstream document next to the first pass's shorter memoized one. Entries
/// are weak, so a key with no pass in flight costs nothing.
static LISTING_PASSES: Lazy<
    std::sync::Mutex<
        std::collections::HashMap<ListingMemoKey, std::sync::Weak<tokio::sync::Mutex<()>>>,
    >,
> = Lazy::new(Default::default);

/// Wait until no other pass over `key` is in flight, and hold that until the
/// returned guard is dropped.
pub async fn serialize_listing_pass(key: &ListingMemoKey) -> tokio::sync::OwnedMutexGuard<()> {
    let lock = {
        let mut passes = LISTING_PASSES.lock().unwrap_or_else(|e| e.into_inner());
        passes.retain(|_, pass| pass.strong_count() > 0);
        match passes.get(key).and_then(std::sync::Weak::upgrade) {
            Some(lock) => lock,
            None => {
                let lock = std::sync::Arc::new(tokio::sync::Mutex::new(()));
                passes.insert(key.clone(), std::sync::Arc::downgrade(&lock));
                lock
            }
        }
    };
    lock.lock_owned().await
}

/// Drop every memoized listing of `repo_id`. Called on each age-gate policy
/// write and review decision (`invalidate_decision_memos`), so an approval,
/// rejection or reopen shows on the next request instead of after the
/// window. Process-local, like the memo.
pub fn forget_listings_for_repo(repo_id: Uuid) {
    // Only fails when the cache was built without closure support.
    let _ = LISTINGS.invalidate_entries_if(move |key, _| key.repo_id == repo_id);
}

/// Drop every memoized listing: the cache-invalidation listener's
/// conservative flush, when age-gate decisions may have been missed (#6345).
pub fn forget_all_listings() {
    LISTINGS.invalidate_all();
}

/// Drop one memoized listing (tests that step through successive passes).
/// Per key, so a test never wipes an entry another test in the same process
/// relies on.
#[cfg(test)]
pub(crate) async fn forget_listing(key: &ListingMemoKey) {
    LISTINGS.invalidate(key).await;
}

/// The non-SNAPSHOT versions of a GA-level `maven-metadata.xml` that the gate
/// evaluates, newest first (Maven version order), with the document's group
/// and artifact ids and `lastUpdated`.
pub struct MetadataVersions {
    pub group_id: String,
    pub artifact_id: String,
    pub last_updated: Option<String>,
    /// Every listed version, in document order.
    pub all: Vec<String>,
    /// The gated ones (not `-SNAPSHOT`), newest first.
    pub gated_newest_first: Vec<String>,
}

pub fn metadata_versions(xml: &str) -> Option<MetadataVersions> {
    let (group_id, artifact_id, all) = crate::formats::maven::parse_metadata_versions(xml)?;
    let mut gated: Vec<String> = all
        .iter()
        .filter(|v| !v.ends_with("-SNAPSHOT"))
        .cloned()
        .collect();
    gated = maven_version::sort_maven_versions(&gated);
    gated.reverse();
    gated.dedup();
    Some(MetadataVersions {
        group_id: group_id.trim().to_string(),
        artifact_id: artifact_id.trim().to_string(),
        last_updated: crate::formats::maven::parse_metadata_last_updated(xml),
        all,
        gated_newest_first: gated,
    })
}

/// Rewrite a GA-level `maven-metadata.xml` without the `blocked` versions, so
/// a resolver picking `LATEST`, `RELEASE` or a version range never selects a
/// withheld version. `<latest>` and `<release>` are recomputed from what
/// remains (`<release>` skips `-SNAPSHOT`); `lastUpdated` is kept. Returns
/// `None` when nothing is blocked: the upstream bytes are then served
/// unchanged, so their checksum still matches the upstream's.
pub fn filter_metadata_versions(xml: &str, blocked: &HashSet<String>) -> Option<String> {
    if blocked.is_empty() {
        return None;
    }
    let doc = metadata_versions(xml)?;
    if !doc.all.iter().any(|v| blocked.contains(v)) {
        return None;
    }
    let mut kept: Vec<String> = doc
        .all
        .iter()
        .filter(|v| !blocked.contains(*v))
        .cloned()
        .collect();
    kept.dedup();
    let sorted = maven_version::sort_maven_versions(&kept);
    let latest = sorted.last().cloned();
    let release = maven_version::latest_release(&sorted).cloned();
    let last_updated = doc
        .last_updated
        .unwrap_or_else(|| Utc::now().format("%Y%m%d%H%M%S").to_string());

    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata>\n");
    out.push_str(&format!("  <groupId>{}</groupId>\n", doc.group_id));
    out.push_str(&format!("  <artifactId>{}</artifactId>\n", doc.artifact_id));
    out.push_str("  <versioning>\n");
    if let Some(latest) = &latest {
        out.push_str(&format!("    <latest>{latest}</latest>\n"));
    }
    if let Some(release) = &release {
        out.push_str(&format!("    <release>{release}</release>\n"));
    }
    out.push_str("    <versions>\n");
    for v in &sorted {
        out.push_str(&format!("      <version>{v}</version>\n"));
    }
    out.push_str("    </versions>\n");
    out.push_str(&format!("    <lastUpdated>{last_updated}</lastUpdated>\n"));
    out.push_str("  </versioning>\n</metadata>\n");
    Some(out)
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_target_covers_version_files_and_their_sidecars() {
        let jar = gate_target("com/example/widget/2.0.0/widget-2.0.0.jar").unwrap();
        assert_eq!(jar.package, "com.example:widget");
        assert_eq!(jar.version, "2.0.0");
        assert_eq!(jar.pom_path(), "com/example/widget/2.0.0/widget-2.0.0.pom");
        assert_eq!(jar.version_dir, "com/example/widget/2.0.0");
        for p in [
            "com/example/widget/2.0.0/widget-2.0.0.pom",
            "com/example/widget/2.0.0/widget-2.0.0.jar.sha1",
            "com/example/widget/2.0.0/widget-2.0.0.pom.md5",
            "com/example/widget/2.0.0/widget-2.0.0-sources.jar",
            "com/example/widget/2.0.0/widget-2.0.0.module",
            "com/example/widget/2.0.0/widget-2.0.0.jar.asc",
            "com/example/widget/2.0.0/widget-2.0.0.jar.asc.sha256",
            "/com/example/widget/2.0.0/widget-2.0.0.jar/",
        ] {
            assert_eq!(gate_target(p), Some(jar.clone()), "{p}");
        }
    }

    #[test]
    fn gate_target_dates_by_the_pom_in_the_requested_directory() {
        // A `.` inside a group segment names a different upstream directory
        // than the dotted groupId rebuilt with `/`; the POM must come from the
        // directory the bytes come from.
        let t = gate_target("com.example/widget/2.0.0/widget-2.0.0.jar").unwrap();
        assert_eq!(t.package, "com.example:widget");
        assert_eq!(t.pom_path(), "com.example/widget/2.0.0/widget-2.0.0.pom");
    }

    #[test]
    fn gate_target_skips_metadata_snapshots_and_non_coordinates() {
        assert_eq!(gate_target("com/example/widget/maven-metadata.xml"), None);
        assert_eq!(
            gate_target("com/example/widget/maven-metadata.xml.sha1"),
            None
        );
        assert_eq!(
            gate_target("com/example/widget/1.0-SNAPSHOT/widget-1.0-20260101.120000-1.jar"),
            None
        );
        assert_eq!(gate_target("widget.jar"), None);
        assert_eq!(gate_target(".meta/prefixes.txt"), None);
    }

    #[tokio::test]
    async fn listing_memo_is_keyed_by_document_policy_and_upstream_6284() {
        let id = Uuid::new_v4();
        let doc = b"<metadata>a</metadata>";
        let key = |url: &str, path: &str, days: i32, doc: &[u8]| {
            ListingMemoKey::new(id, url, path, days, "upstream_publish_time", doc)
        };
        let base = key("http://up/", "g/a/maven-metadata.xml", 7, doc);
        remember_listing(base.clone(), bytes::Bytes::from_static(b"filtered")).await;
        // The same document under a slash-spelled path reads the memo.
        assert_eq!(
            memo_listing(&key("http://up/", "/g/a/maven-metadata.xml/", 7, doc))
                .await
                .as_deref(),
            Some(&b"filtered"[..])
        );
        // A changed upstream document, policy or upstream never does.
        for other in [
            key(
                "http://up/",
                "g/a/maven-metadata.xml",
                7,
                b"<metadata>b</metadata>",
            ),
            key("http://up/", "g/a/maven-metadata.xml", 8, doc),
            key("http://other/", "g/a/maven-metadata.xml", 7, doc),
            ListingMemoKey::new(
                id,
                "http://up/",
                "g/a/maven-metadata.xml",
                7,
                "first_seen",
                doc,
            ),
        ] {
            assert_ne!(other, base);
            assert!(memo_listing(&other).await.is_none());
        }
        forget_listing(&base).await;
        assert!(memo_listing(&base).await.is_none());
    }

    /// Two passes over one document that end with different listings: both
    /// serve, and the memo keeps, the one stored first (#6284).
    #[tokio::test]
    async fn concurrent_passes_serve_the_first_stored_listing_6284() {
        let key = ListingMemoKey::new(
            Uuid::new_v4(),
            "http://up/",
            "g/a/maven-metadata.xml",
            7,
            "upstream_publish_time",
            b"<metadata/>",
        );
        let first = bytes::Bytes::from_static(b"63 versions");
        let later = bytes::Bytes::from_static(b"127 versions");
        let (a, b) = tokio::join!(
            remember_listing(key.clone(), first.clone()),
            remember_listing(key.clone(), later.clone())
        );
        // Whichever finished first is the one both serve.
        assert_eq!(a, b, "both passes serve one document");
        assert_eq!(memo_listing(&key).await, Some(a.clone()));
        // A pass after that, with a longer listing, still serves the stored one.
        assert_eq!(
            remember_listing(key.clone(), bytes::Bytes::from_static(b"150")).await,
            a
        );
        forget_listing(&key).await;
    }

    /// A second pass over the same document waits for the first, and a pass
    /// over another document does not (#6284).
    #[tokio::test]
    async fn listing_passes_over_one_document_run_one_at_a_time_6284() {
        let key = |doc: &[u8]| {
            ListingMemoKey::new(
                Uuid::new_v4(),
                "http://up/",
                "g/a/maven-metadata.xml",
                7,
                "upstream_publish_time",
                doc,
            )
        };
        let mine = key(b"<metadata>one</metadata>");
        let other = key(b"<metadata>two</metadata>");
        let first = serialize_listing_pass(&mine).await;
        let wait = Duration::from_millis(200);
        assert!(
            tokio::time::timeout(wait, serialize_listing_pass(&mine))
                .await
                .is_err(),
            "a second pass over the same document waits"
        );
        assert!(
            tokio::time::timeout(wait, serialize_listing_pass(&other))
                .await
                .is_ok(),
            "a pass over another document does not"
        );
        drop(first);
        assert!(
            tokio::time::timeout(wait, serialize_listing_pass(&mine))
                .await
                .is_ok(),
            "it runs once the first pass is done"
        );
    }

    /// A review decision or policy write drops the memo of that repository
    /// only (#6284).
    #[tokio::test]
    async fn forget_listings_for_repo_drops_only_that_repository_6284() {
        let (mine, other) = (Uuid::new_v4(), Uuid::new_v4());
        let key = |repo| {
            ListingMemoKey::new(
                repo,
                "http://up/",
                "g/a/maven-metadata.xml",
                7,
                "upstream_publish_time",
                b"<metadata/>",
            )
        };
        let doc = bytes::Bytes::from_static(b"listing");
        remember_listing(key(mine), doc.clone()).await;
        remember_listing(key(other), doc.clone()).await;
        forget_listings_for_repo(mine);
        assert!(memo_listing(&key(mine)).await.is_none());
        assert_eq!(memo_listing(&key(other)).await, Some(doc));
        forget_listing(&key(other)).await;
    }

    #[test]
    fn last_modified_and_last_updated_parse() {
        let lm = parse_last_modified("Wed, 21 Oct 2015 07:28:00 GMT").unwrap();
        assert_eq!(lm.to_rfc3339(), "2015-10-21T07:28:00+00:00");
        assert!(parse_last_modified("yesterday").is_none());
        let lu = parse_last_updated("20260101120000").unwrap();
        assert_eq!(lu.to_rfc3339(), "2026-01-01T12:00:00+00:00");
        assert!(parse_last_updated("2026-01-01").is_none());
    }

    const DOC: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<metadata>
  <groupId>com.example</groupId>
  <artifactId>widget</artifactId>
  <versioning>
    <latest>2.0.0</latest>
    <release>2.0.0</release>
    <versions>
      <version>1.0.0</version>
      <version>1.5.0</version>
      <version>2.0.0</version>
    </versions>
    <lastUpdated>20261020101010</lastUpdated>
  </versioning>
</metadata>
"#;

    #[test]
    fn filtering_drops_blocked_versions_and_repoints_latest_and_release() {
        let blocked: HashSet<String> = ["2.0.0".to_string()].into();
        let out = filter_metadata_versions(DOC, &blocked).unwrap();
        let (_, _, versions) = crate::formats::maven::parse_metadata_versions(&out).unwrap();
        assert_eq!(versions, vec!["1.0.0", "1.5.0"]);
        assert!(out.contains("<latest>1.5.0</latest>"), "{out}");
        assert!(out.contains("<release>1.5.0</release>"), "{out}");
        assert!(out.contains("<lastUpdated>20261020101010</lastUpdated>"));
        assert!(out.contains("<groupId>com.example</groupId>"));
    }

    #[test]
    fn nothing_blocked_keeps_the_upstream_bytes() {
        assert_eq!(filter_metadata_versions(DOC, &HashSet::new()), None);
        let unrelated: HashSet<String> = ["9.9.9".to_string()].into();
        assert_eq!(filter_metadata_versions(DOC, &unrelated), None);
    }

    #[test]
    fn every_version_blocked_leaves_an_empty_list_without_latest() {
        let blocked: HashSet<String> = ["1.0.0", "1.5.0", "2.0.0"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let out = filter_metadata_versions(DOC, &blocked).unwrap();
        assert!(!out.contains("<latest>"));
        assert!(!out.contains("<release>"));
        let (_, _, versions) = crate::formats::maven::parse_metadata_versions(&out).unwrap();
        assert!(versions.is_empty());
    }

    #[test]
    fn metadata_versions_orders_gated_newest_first_and_skips_snapshots() {
        let doc = DOC.replace(
            "<version>2.0.0</version>",
            "<version>2.0.0</version>\n      <version>2.1.0-SNAPSHOT</version>",
        );
        let parsed = metadata_versions(&doc).unwrap();
        assert_eq!(parsed.gated_newest_first, vec!["2.0.0", "1.5.0", "1.0.0"]);
        assert_eq!(parsed.all.len(), 4);
        assert_eq!(parsed.last_updated.as_deref(), Some("20261020101010"));
    }
}
