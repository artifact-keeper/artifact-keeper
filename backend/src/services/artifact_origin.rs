//! Artifact origin — where an artifact's bytes came from (#4050).
//!
//! Origin is a security-relevant fact: a caching proxy re-serves content
//! under its own identity, and a lower-trust source shadowing a
//! higher-trust one is invisible unless the upstream that supplied the
//! bytes is recorded. Every `artifacts` row therefore carries an
//! immutable `origin` JSONB document (migration 226), stamped at ingest by
//! the `artifacts_origin_fill` trigger from the owning repository row —
//! hosted upload, proxied/mirrored fetch naming the upstream — or
//! supplied explicitly by an ingest path that knows better (the migration
//! worker names the source system the bytes came from). The
//! `artifacts_origin_immutable` trigger rejects any later change, so the
//! record survives proxy re-serves, re-migrations and upserts.
//!
//! This module is the Rust mirror of that document: the shape the API
//! serializes, the normalization the policy predicate compares against,
//! and the constructors ingest paths use.

use serde::{Deserialize, Serialize};

/// Schema version of the origin document (`"v"` key), so new facets can
/// be added without a migration.
pub const ORIGIN_VERSION: i32 = 1;

/// Ingest kind recorded for an artifact created by a direct upload into a
/// local (hosted) repository.
pub const KIND_HOSTED: &str = "hosted";
/// Ingest kind for an artifact fetched through a remote (proxy) repository;
/// `upstream_url` names the upstream that supplied the bytes.
pub const KIND_PROXY: &str = "proxy";
/// Ingest kind for an artifact row owned by a virtual repository.
pub const KIND_VIRTUAL: &str = "virtual";
/// Ingest kind for an artifact imported by the migration worker;
/// `upstream_url` names the source system when it can be named.
pub const KIND_MIGRATION: &str = "migration";

/// Every ingest kind the database can record. The policy predicate's
/// `allowed_kinds` list is validated against this set at write time, so a
/// misspelled kind is a 400, not a policy that silently matches nothing.
pub const ALL_KINDS: [&str; 4] = [KIND_HOSTED, KIND_PROXY, KIND_VIRTUAL, KIND_MIGRATION];

/// The immutable origin record stamped on every artifact at ingest
/// (#4050). Mirrors the JSONB document the `artifacts_origin_fill` /
/// backfill SQL derives; keep the two in lockstep.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ArtifactOrigin {
    /// Origin document schema version (currently 1).
    pub v: i32,
    /// How the artifact entered the registry: `hosted`, `proxy`,
    /// `virtual` or `migration`.
    pub kind: String,
    /// Key of the repository the artifact was uploaded to, fetched
    /// through, or imported into.
    pub repository_key: String,
    /// The upstream system that supplied the bytes, normalized
    /// (scheme/authority lowercased, trailing slashes stripped). Present
    /// for proxied/mirrored artifacts and for migrations whose source
    /// system is known; absent for hosted uploads.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_url: Option<String>,
}

impl ArtifactOrigin {
    /// Origin of a direct upload into a local repository.
    pub fn hosted(repository_key: &str) -> Self {
        Self {
            v: ORIGIN_VERSION,
            kind: KIND_HOSTED.to_string(),
            repository_key: repository_key.to_string(),
            upstream_url: None,
        }
    }

    /// Origin recorded by the migration worker for an imported artifact:
    /// the destination repo it landed in, plus the source system's base
    /// URL when the source client can name it.
    pub fn migration(repository_key: &str, source_base_url: Option<&str>) -> Self {
        Self {
            v: ORIGIN_VERSION,
            kind: KIND_MIGRATION.to_string(),
            repository_key: repository_key.to_string(),
            upstream_url: source_base_url.map(normalize_upstream_url),
        }
    }

    /// Serialize for binding into an `artifacts.origin` INSERT.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("ArtifactOrigin is always serializable")
    }

    /// Parse a stored `artifacts.origin` document. Tolerant by design —
    /// the same defence-in-depth direction as `parse_policy_predicates`:
    /// a hand-edited or future-version document degrades to `None`
    /// ("origin unknown"), which policy allowlist predicates fail closed
    /// on, rather than panicking the download path.
    pub fn from_json(value: &serde_json::Value) -> Option<Self> {
        serde_json::from_value(value.clone()).ok()
    }

    /// [`Self::from_json`] for an API response (#4452). Origins are recorded
    /// without userinfo since migration 271 (#4463), which also scrubbed the
    /// existing rows; this strip stays as defence in depth for any document
    /// written by a path that bypassed the normalizer.
    pub fn for_response(value: &serde_json::Value) -> Option<Self> {
        let mut origin = Self::from_json(value)?;
        if let Some(url) = origin.upstream_url.as_deref() {
            origin.upstream_url = Some(crate::services::proxy_service::strip_url_userinfo(url).0);
        }
        Some(origin)
    }
}

/// Normalize an upstream URL for origin comparison — the Rust mirror of
/// the SQL `ak_normalize_upstream_url` the fill trigger and backfills use
/// (migration 271): trim ASCII whitespace, drop any `userinfo@` from the
/// authority (#4463: a Remote configured as `https://user:pass@host/...`
/// must not leave its credentials in every proxied artifact's origin), then
/// lowercase the scheme://authority (case-insensitive per RFC 3986, ASCII
/// only), strip trailing slashes, and leave the path case-intact. The
/// migration worker normalizes source base URLs through here so a URL
/// recorded in Rust compares equal to one recorded by the trigger; a
/// DB-backed test pins the two implementations to each other.
pub fn normalize_upstream_url(url: &str) -> String {
    let trimmed = url.trim_matches(|c: char| c.is_ascii_whitespace());
    let (stripped, _) = crate::services::proxy_service::strip_url_userinfo_textual(trimmed);
    lowercase_scheme_authority(&stripped)
        .trim_end_matches('/')
        .to_string()
}

/// Lowercase `scheme://authority` (the authority running to the first `/`)
/// when `url` starts with a scheme followed by `://`; anything else is
/// returned unchanged. The SQL side matches
/// `^[a-zA-Z][a-zA-Z0-9+.-]*://[^/]*`.
fn lowercase_scheme_authority(url: &str) -> String {
    let Some(sep) = url.find("://") else {
        return url.to_string();
    };
    let scheme = &url[..sep];
    let scheme_ok = scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'));
    if !scheme_ok {
        return url.to_string();
    }
    let start = sep + 3;
    let end = url[start..].find('/').map_or(url.len(), |rel| start + rel);
    format!("{}{}", url[..end].to_ascii_lowercase(), &url[end..])
}

/// Read the `origin` document recorded on an existing artifact so a copy
/// path can carry it onto the copy verbatim (#4152).
///
/// Promotion and approval copies insert a NEW `artifacts` row for the
/// TARGET repository. Left to the `artifacts_origin_fill` trigger that
/// row's origin is derived from the target repo, so a proxied or migrated
/// artifact is relabelled `hosted` by the promotion hop — erasing exactly
/// the shadowing signal `origin` exists to preserve. Supplying the source
/// row's document instead is honoured by the trigger, which only derives
/// when `NEW.origin IS NULL`.
///
/// `None` means the source row no longer exists; the caller then leaves
/// the column NULL and the trigger derives, which is the pre-fix
/// behaviour. A live row cannot carry a NULL origin: migration 229
/// validated the `artifacts_origin_recorded` CHECK.
pub async fn recorded_origin(
    db: &sqlx::PgPool,
    artifact_id: uuid::Uuid,
) -> std::result::Result<Option<serde_json::Value>, sqlx::Error> {
    sqlx::query_scalar::<_, Option<serde_json::Value>>("SELECT origin FROM artifacts WHERE id = $1")
        .bind(artifact_id)
        .fetch_optional(db)
        .await
        .map(Option::flatten)
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // normalize_upstream_url (pure)
    // ------------------------------------------------------------------

    #[test]
    fn for_response_strips_upstream_userinfo_but_from_json_keeps_it() {
        // #4452: the stored origin of a proxied artifact mirrors the repo's
        // upstream_url, credentials included. The API rendering drops them;
        // the policy read (`from_json`) still sees the stored value.
        let stored = serde_json::json!({
            "v": 1,
            "kind": "proxy",
            "repository_key": "npm-remote",
            "upstream_url": "https://alice:s3cret@registry.example.com/npm"
        });
        let shown = ArtifactOrigin::for_response(&stored).expect("parses");
        assert_eq!(
            shown.upstream_url.as_deref(),
            Some("https://registry.example.com/npm")
        );
        assert_eq!(shown.kind, "proxy");
        assert_eq!(
            ArtifactOrigin::from_json(&stored)
                .unwrap()
                .upstream_url
                .as_deref(),
            Some("https://alice:s3cret@registry.example.com/npm")
        );
        // Hosted (no upstream) and unparseable documents behave as from_json.
        let hosted = ArtifactOrigin::hosted("local").to_json();
        assert_eq!(
            ArtifactOrigin::for_response(&hosted),
            Some(ArtifactOrigin::hosted("local"))
        );
        assert!(ArtifactOrigin::for_response(&serde_json::json!("junk")).is_none());
    }

    #[test]
    fn test_normalize_lowercases_scheme_and_authority_only() {
        assert_eq!(
            normalize_upstream_url("HTTPS://Repo1.Example.ORG/Maven2/"),
            "https://repo1.example.org/Maven2"
        );
    }

    #[test]
    fn test_normalize_strips_trailing_slashes() {
        assert_eq!(
            normalize_upstream_url("https://upstream.example.test///"),
            "https://upstream.example.test"
        );
        assert_eq!(
            normalize_upstream_url("https://upstream.example.test"),
            "https://upstream.example.test"
        );
    }

    #[test]
    fn test_normalize_keeps_port_and_path() {
        assert_eq!(
            normalize_upstream_url("http://Nexus.local:8081/repository/maven-public/"),
            "http://nexus.local:8081/repository/maven-public"
        );
    }

    #[test]
    fn test_normalize_non_url_passes_through_minus_slashes() {
        assert_eq!(normalize_upstream_url("not-a-url/"), "not-a-url");
    }

    // ------------------------------------------------------------------
    // serde shape
    // ------------------------------------------------------------------

    #[test]
    fn test_origin_json_shape() {
        let hosted = ArtifactOrigin::hosted("libs-release-local");
        let doc = hosted.to_json();
        assert_eq!(doc["v"], 1);
        assert_eq!(doc["kind"], "hosted");
        assert_eq!(doc["repository_key"], "libs-release-local");
        assert!(doc.get("upstream_url").is_none());

        let migration = ArtifactOrigin::migration("legacy-import", Some("HTTP://RT.LOCAL/"));
        let doc = migration.to_json();
        assert_eq!(doc["kind"], "migration");
        assert_eq!(doc["upstream_url"], "http://rt.local");
    }

    #[test]
    fn test_origin_roundtrip_and_tolerant_parse() {
        let origin = ArtifactOrigin::migration("dest", Some("http://source.local"));
        let parsed = ArtifactOrigin::from_json(&origin.to_json()).expect("parse own document");
        assert_eq!(parsed, origin);
        assert!(ArtifactOrigin::from_json(&serde_json::json!({"bogus": true})).is_none());
    }

    // ------------------------------------------------------------------
    // DB-backed: the trigger stamps origin at ingest, immutability holds,
    // and re-ingest never overwrites it.
    //
    // Gated on `try_pool` so they skip cleanly without DATABASE_URL.
    // ------------------------------------------------------------------

    /// Insert one artifact row into `repo_id` and return `(id, origin)`.
    async fn insert_and_read_origin(
        pool: &sqlx::PgPool,
        repo_id: uuid::Uuid,
        path: &str,
    ) -> (uuid::Uuid, Option<serde_json::Value>) {
        let id: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO artifacts (repository_id, path, name, size_bytes, checksum_sha256, \
             content_type, storage_key) \
             VALUES ($1, $2, $3, 1, $4, 'application/octet-stream', $5) RETURNING id",
        )
        .bind(repo_id)
        .bind(path)
        .bind(path)
        .bind(format!("{:064x}", 1))
        .bind(format!("sk/{path}"))
        .fetch_one(pool)
        .await
        .expect("insert artifact");
        let origin = sqlx::query_scalar("SELECT origin FROM artifacts WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("read origin");
        (id, origin)
    }

    #[tokio::test]
    async fn test_upload_into_local_repo_records_hosted_origin() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };

        let (_id, origin) = insert_and_read_origin(&fx.pool, fx.repo_id, "a/1.0/a-1.0.bin").await;

        let doc = origin.expect("every artifact must carry an origin");
        assert_eq!(doc["kind"], "hosted", "a local-repo insert is an upload");
        assert_eq!(
            doc["repository_key"], fx.repo_key,
            "origin names the owning repository"
        );
        assert!(
            doc.get("upstream_url").is_none(),
            "a hosted upload has no upstream: {doc}"
        );
        fx.teardown().await;
    }

    #[tokio::test]
    async fn test_proxy_fetch_records_upstream_origin() {
        use crate::api::handlers::test_db_helpers as tdh;
        // `create_repo` wires a remote fixture to https://upstream.example.test.
        let Some(fx) = tdh::Fixture::setup("remote", "generic").await else {
            return;
        };

        let (_id, origin) = insert_and_read_origin(&fx.pool, fx.repo_id, "b/2.0/b-2.0.bin").await;

        let doc = origin.expect("every artifact must carry an origin");
        assert_eq!(
            doc["kind"], "proxy",
            "a remote-repo insert is a proxied fetch"
        );
        assert_eq!(doc["repository_key"], fx.repo_key);
        assert_eq!(
            doc["upstream_url"], "https://upstream.example.test",
            "origin must name the upstream that supplied the bytes: {doc}"
        );
        fx.teardown().await;
    }

    #[tokio::test]
    async fn test_origin_update_is_rejected_once_recorded() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };

        let (id, origin) = insert_and_read_origin(&fx.pool, fx.repo_id, "c/1/c.bin").await;
        assert!(origin.is_some());

        // Any attempt to rewrite OR clear the recorded origin must fail.
        let rewrite = sqlx::query("UPDATE artifacts SET origin = $2 WHERE id = $1")
            .bind(id)
            .bind(serde_json::json!({"v":1,"kind":"proxy","repository_key":"evil"}))
            .execute(&fx.pool)
            .await;
        assert!(
            rewrite.is_err(),
            "rewriting a recorded origin must be rejected"
        );

        let cleared = sqlx::query("UPDATE artifacts SET origin = NULL WHERE id = $1")
            .bind(id)
            .execute(&fx.pool)
            .await;
        assert!(
            cleared.is_err(),
            "clearing a recorded origin must be rejected"
        );

        // And the stored document is byte-for-byte the one ingest wrote.
        let after: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT origin FROM artifacts WHERE id = $1")
                .bind(id)
                .fetch_one(&fx.pool)
                .await
                .expect("re-read origin");
        assert_eq!(
            after, origin,
            "the rejected updates must leave origin intact"
        );
        fx.teardown().await;
    }

    /// The no-overwrite invariant: a proxy re-serve or re-migration upserts
    /// the row (`ON CONFLICT DO UPDATE` refreshes size/checksum/storage
    /// pointers) but the origin stamped by the FIRST ingest stands. An
    /// upsert that TRIES to rewrite origin must fail outright.
    #[tokio::test]
    async fn test_reingest_upsert_does_not_overwrite_origin() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("remote", "generic").await else {
            return;
        };

        let (_id, origin) = insert_and_read_origin(&fx.pool, fx.repo_id, "d/1/d.bin").await;
        let recorded = origin.expect("origin recorded at first fetch");

        // The re-serve shape every upsert path uses: refresh mutable
        // columns, never origin. Must succeed and keep the origin.
        sqlx::query(
            "INSERT INTO artifacts (repository_id, path, name, size_bytes, checksum_sha256, \
             content_type, storage_key) \
             VALUES ($1, $2, $3, 2, $4, 'application/octet-stream', $5) \
             ON CONFLICT (repository_id, path) DO UPDATE SET \
               size_bytes = EXCLUDED.size_bytes, \
               checksum_sha256 = EXCLUDED.checksum_sha256, \
               updated_at = NOW()",
        )
        .bind(fx.repo_id)
        .bind("d/1/d.bin")
        .bind("d/1/d.bin")
        .bind(format!("{:064x}", 2))
        .bind("sk/d/1/d.bin-v2")
        .execute(&fx.pool)
        .await
        .expect("re-serve upsert must succeed");

        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT origin FROM artifacts WHERE repository_id = $1 AND path = $2",
        )
        .bind(fx.repo_id)
        .bind("d/1/d.bin")
        .fetch_one(&fx.pool)
        .await
        .expect("re-read origin");
        assert_eq!(
            after,
            Some(recorded.clone()),
            "re-serving must not rewrite origin"
        );

        // Mutation check (#4088 lesson): an upsert that DOES try to stamp
        // a new origin — the exact "re-serve under the proxy's own
        // identity" rewrite the issue calls out — must be rejected, not
        // silently applied.
        let hostile = sqlx::query(
            "INSERT INTO artifacts (repository_id, path, name, size_bytes, checksum_sha256, \
             content_type, storage_key, origin) \
             VALUES ($1, $2, $3, 3, $4, 'application/octet-stream', $5, $6) \
             ON CONFLICT (repository_id, path) DO UPDATE SET \
               origin = EXCLUDED.origin",
        )
        .bind(fx.repo_id)
        .bind("d/1/d.bin")
        .bind("d/1/d.bin")
        .bind(format!("{:064x}", 3))
        .bind("sk/d/1/d.bin-v3")
        .bind(serde_json::json!({"v":1,"kind":"hosted","repository_key":"attacker-controlled"}))
        .execute(&fx.pool)
        .await;
        assert!(
            hostile.is_err(),
            "an upsert rewriting origin must be rejected by the immutability trigger"
        );

        let after: Option<serde_json::Value> = sqlx::query_scalar(
            "SELECT origin FROM artifacts WHERE repository_id = $1 AND path = $2",
        )
        .bind(fx.repo_id)
        .bind("d/1/d.bin")
        .fetch_one(&fx.pool)
        .await
        .expect("re-read origin");
        assert_eq!(
            after,
            Some(recorded),
            "the rejected rewrite must leave origin intact"
        );
        fx.teardown().await;
    }

    /// The migration 227 backfill derives origin for rows that predate the
    /// column. On the migrated test database no artifact — however old —
    /// may remain without one, and a backfilled row must carry the same
    /// derivation the trigger applies (kind from repo type, upstream from
    /// the repo's current upstream_url).
    #[tokio::test]
    async fn test_backfill_left_no_originless_artifacts() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let unbackfilled: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM artifacts WHERE origin IS NULL")
                .fetch_one(&pool)
                .await
                .expect("count originless artifacts");
        assert_eq!(
            unbackfilled, 0,
            "every artifact must carry a recorded origin after migration 227"
        );

        // Shape check on whatever the shared DB holds: every origin names
        // a schema version, a known kind, and its repository key.
        let malformed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM artifacts \
             WHERE (origin ->> 'v')::int <> 1 \
                OR origin ->> 'kind' NOT IN ('hosted', 'proxy', 'virtual', 'migration') \
                OR origin ->> 'repository_key' IS NULL",
        )
        .fetch_one(&pool)
        .await
        .expect("count malformed origins");
        assert_eq!(malformed, 0, "every recorded origin must be well-formed");
    }

    // ------------------------------------------------------------------
    // #4463: userinfo never reaches a recorded origin
    // ------------------------------------------------------------------

    /// Credentialed spellings from #4462's `strip_url_userinfo` table plus
    /// the normalizer's own cases, with the expected normal form. Built at
    /// runtime so secret scanners do not flag a fixture.
    fn normalizer_cases() -> Vec<(String, String)> {
        let cred = "alice:s3cret";
        [
            (
                "https://{c}@registry.example.com/simple?x=1#f",
                "https://registry.example.com/simple?x=1#f",
            ),
            ("https://token@Host:8443", "https://host:8443"),
            ("https://u:p@ss@host/a", "https://host/a"),
            ("//{c}@host/path", "//host/path"),
            ("{c}@host/path", "host/path"),
            ("https://{c}@[::1]:8443/x/", "https://[::1]:8443/x"),
            ("https://user%40corp:p%40ss@host/", "https://host"),
            ("https://:pw@host/", "https://host"),
            ("https:{c}@host/x?q=http://z", "https:host/x?q=http://z"),
            ("https:/{c}@host", "https:/host"),
            ("https:\\\\{c}@host", "https:\\\\host"),
            ("https://{c}@HOST\\x@y/z", "https://host\\x@y/z"),
            ("https://host\\@evil/", "https://host\\@evil"),
            ("https://host/a@b?c=d@e", "https://host/a@b?c=d@e"),
            ("https://host?q=a@b", "https://host?q=a@b"),
            ("https://@host/", "https://host"),
            (
                "  HTTPS://{c}@Repo1.Example.ORG/Maven2/  ",
                "https://repo1.example.org/Maven2",
            ),
            (
                "ftp://{c}@Files.Example.TEST/pub",
                "ftp://files.example.test/pub",
            ),
            ("git+ssh://{c}@Example.TEST/r", "git+ssh://example.test/r"),
            ("https://registry.npmjs.org", "https://registry.npmjs.org"),
            ("not a url", "not a url"),
            ("", ""),
        ]
        .into_iter()
        .map(|(raw, want)| (raw.replace("{c}", cred), want.to_string()))
        .collect()
    }

    #[test]
    fn test_normalize_strips_userinfo_4463() {
        for (raw, want) in normalizer_cases() {
            let got = normalize_upstream_url(&raw);
            assert_eq!(got, want, "{raw}");
            assert!(
                !got.contains("s3cret"),
                "credential survived: {raw} -> {got}"
            );
            assert_eq!(normalize_upstream_url(&got), got, "not idempotent: {raw}");
        }
    }

    #[test]
    fn test_migration_origin_never_records_source_userinfo_4463() {
        let src = format!("https://{}@Arti.Example.TEST/artifactory/", "alice:s3cret");
        let origin = ArtifactOrigin::migration("dest", Some(&src));
        assert_eq!(
            origin.upstream_url.as_deref(),
            Some("https://arti.example.test/artifactory")
        );
    }

    /// Deterministic pseudo-random URLs assembled from the pieces the two
    /// normalizers branch on (scheme spellings, separators, userinfo,
    /// IPv6/port hosts, `@` after the authority, whitespace, case).
    fn generated_urls(n: usize) -> Vec<String> {
        const SCHEMES: [&str; 8] = ["https", "HTTP", "ftp", "git+ssh", "s3", "", "1x", "ws"];
        const SEPS: [&str; 6] = ["://", ":", ":/", ":\\\\", "//", ":///"];
        const USERS: [&str; 7] = ["", "u@", "u:p@", "a%40b:p%40w@", ":pw@", "@", "x:y@z@"];
        const HOSTS: [&str; 6] = [
            "Host.Example.TEST",
            "[::1]:8443",
            "h:80",
            "HOST\\x@y",
            "",
            "Ü.example",
        ];
        const TAILS: [&str; 8] = [
            "",
            "/",
            "/A/b/",
            "?q=a@b",
            "#f@g",
            "/p@q/",
            "///",
            "/x?y=http://z",
        ];
        const PADS: [&str; 3] = ["", " ", "\t"];
        let mut state: u64 = 0x4463_4153;
        let mut next = |m: usize| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            ((state >> 33) as usize) % m
        };
        (0..n)
            .map(|_| {
                let pad = PADS[next(PADS.len())];
                format!(
                    "{pad}{}{}{}{}{}{pad}",
                    SCHEMES[next(SCHEMES.len())],
                    SEPS[next(SEPS.len())],
                    USERS[next(USERS.len())],
                    HOSTS[next(HOSTS.len())],
                    TAILS[next(TAILS.len())],
                )
            })
            .collect()
    }

    /// #4463: the Rust normalizer and the SQL one the fill trigger runs
    /// (migration 271) must agree on every input, or a policy written
    /// against a Rust-normalized URL silently stops matching stored
    /// origins. Same for the userinfo strip on its own.
    #[tokio::test]
    async fn test_rust_and_sql_normalizers_agree_4463() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let mut inputs: Vec<String> = normalizer_cases().into_iter().map(|(raw, _)| raw).collect();
        inputs.extend(generated_urls(2000));

        let rows: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT u, ak_normalize_upstream_url(u), ak_strip_url_userinfo(u) \
               FROM unnest($1::text[]) WITH ORDINALITY AS t(u, n) ORDER BY n",
        )
        .bind(&inputs)
        .fetch_all(&pool)
        .await
        .expect("evaluate the SQL normalizer");
        assert_eq!(rows.len(), inputs.len());
        for (raw, sql_norm, sql_strip) in rows {
            assert_eq!(sql_norm, normalize_upstream_url(&raw), "normalize: {raw:?}");
            assert_eq!(
                sql_strip,
                crate::services::proxy_service::strip_url_userinfo_textual(&raw).0,
                "strip: {raw:?}"
            );
        }
    }

    /// #4463: a Remote configured with `user:password@` in its URL stamps
    /// origins without the credentials, so a credential-free allowlist
    /// entry matches what is stored.
    #[tokio::test]
    async fn test_credentialed_remote_records_origin_without_userinfo_4463() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("remote", "generic").await else {
            return;
        };
        let upstream = format!("HTTPS://{}@Upstream.Example.TEST/base/", "alice:s3cret");
        sqlx::query("UPDATE repositories SET upstream_url = $2 WHERE id = $1")
            .bind(fx.repo_id)
            .bind(&upstream)
            .execute(&fx.pool)
            .await
            .expect("set credentialed upstream");

        let (_id, origin) = insert_and_read_origin(&fx.pool, fx.repo_id, "e/1/e.bin").await;
        let doc = origin.expect("origin recorded");
        assert_eq!(
            doc["upstream_url"], "https://upstream.example.test/base",
            "{doc}"
        );
        assert!(
            !doc.to_string().contains("s3cret"),
            "credential at rest: {doc}"
        );
        fx.teardown().await;
    }

    async fn rerun_migration(pool: &sqlx::PgPool, sql: &'static str) {
        let mut conn = pool.acquire().await.expect("acquire migration connection");
        sqlx::raw_sql(sql)
            .execute(&mut *conn)
            .await
            .expect("re-running the migration must succeed");
    }

    const MIGRATION_270: &str =
        include_str!("../../migrations/270_artifacts_origin_migration_restamp.sql");
    const MIGRATION_271: &str =
        include_str!("../../migrations/271_origin_upstream_strip_userinfo.sql");

    /// Insert an artifact row with an explicit origin document (the fill
    /// trigger keeps an explicit value), created `age_hours` ago.
    async fn insert_with_origin(
        pool: &sqlx::PgPool,
        repo_id: uuid::Uuid,
        path: &str,
        checksum: &str,
        origin: serde_json::Value,
        age_hours: i32,
    ) -> uuid::Uuid {
        sqlx::query_scalar(
            "INSERT INTO artifacts (repository_id, path, name, size_bytes, checksum_sha256, \
             content_type, storage_key, origin, created_at) \
             VALUES ($1, $2, $2, 1, $3, 'application/octet-stream', $2, $4, \
                     now() - make_interval(hours => $5)) RETURNING id",
        )
        .bind(repo_id)
        .bind(path)
        .bind(checksum)
        .bind(origin)
        .bind(age_hours)
        .fetch_one(pool)
        .await
        .expect("insert artifact with explicit origin")
    }

    async fn kind_of(pool: &sqlx::PgPool, id: uuid::Uuid) -> serde_json::Value {
        sqlx::query_scalar("SELECT origin FROM artifacts WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .expect("read origin")
    }

    /// #4153: migration 270 re-stamps rows the migration worker imported
    /// before it stamped its own origin (recorded `hosted` by the 228
    /// backfill) and leaves everything it cannot attribute unambiguously.
    /// Re-running it is a no-op, and afterwards the immutability trigger
    /// still rejects every rewrite outside the sanctioned GUC window.
    #[tokio::test]
    async fn test_migration_270_restamps_migrated_rows_and_keeps_immutability_4153() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("local", "generic").await else {
            return;
        };
        let pool = &fx.pool;
        let src_key = format!("src-{}", fx.repo_id.simple());
        let conn_id: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO source_connections (name, url, auth_type, credentials_enc) \
             VALUES ($1, 'HTTPS://Arti.Example.TEST/artifactory/', 'api_token', '\\x00') \
             RETURNING id",
        )
        .bind(format!("4153-{}", fx.repo_id))
        .fetch_one(pool)
        .await
        .expect("insert source connection");
        let job = |config: serde_json::Value| {
            sqlx::query_scalar::<_, uuid::Uuid>(
                "INSERT INTO migration_jobs (source_connection_id, status, config) \
                 VALUES ($1, 'completed', $2) RETURNING id",
            )
            .bind(conn_id)
            .bind(config)
            .fetch_one(pool)
        };
        let mut mappings = serde_json::Map::new();
        mappings.insert(src_key.clone(), fx.repo_key.clone().into());
        let mapped = job(serde_json::json!({"repo_mappings": mappings.clone()}))
            .await
            .expect("mapped job");
        let dry = job(serde_json::json!({"dry_run": true, "repo_mappings": mappings}))
            .await
            .expect("dry-run job");

        let hosted = ArtifactOrigin::hosted(&fx.repo_key).to_json();
        let sum = |n: u32| format!("{n:064x}");
        let composed = insert_with_origin(
            pool,
            fx.repo_id,
            "lib/1.0/lib-1.0.tgz",
            &sum(1),
            hosted.clone(),
            24,
        )
        .await;
        let verbatim = insert_with_origin(
            pool,
            fx.repo_id,
            "com/ex/a/1/a-1.jar",
            &sum(2),
            hosted.clone(),
            24,
        )
        .await;
        let dup_a =
            insert_with_origin(pool, fx.repo_id, "x/1/dup.bin", &sum(3), hosted.clone(), 24).await;
        let dup_b =
            insert_with_origin(pool, fx.repo_id, "x/2/dup.bin", &sum(3), hosted.clone(), 24).await;
        let later =
            insert_with_origin(pool, fx.repo_id, "late.bin", &sum(4), hosted.clone(), 0).await;
        let wrong_sum =
            insert_with_origin(pool, fx.repo_id, "w.bin", &sum(5), hosted.clone(), 24).await;
        let dry_row =
            insert_with_origin(pool, fx.repo_id, "dry.bin", &sum(6), hosted.clone(), 24).await;

        for (job_id, rel, checksum) in [
            (mapped, "lib/-/lib-1.0.tgz", sum(1)),
            (mapped, "com/ex/a/1/a-1.jar", sum(2)),
            (mapped, "x/dup.bin", sum(3)),
            (mapped, "late.bin", sum(4)),
            (mapped, "w.bin", sum(9)),
            (dry, "dry.bin", sum(6)),
        ] {
            sqlx::query(
                "INSERT INTO migration_items (job_id, item_type, source_path, target_path, \
                 status, checksum_target, completed_at) \
                 VALUES ($1, 'artifact', $2, $3, 'completed', $4, now() - interval '1 hour')",
            )
            .bind(job_id)
            .bind(format!("{src_key}/{rel}"))
            .bind(format!("{}/{rel}", fx.repo_key))
            .bind(checksum)
            .execute(pool)
            .await
            .expect("insert migration item");
        }

        rerun_migration(pool, MIGRATION_270).await;

        let want = serde_json::json!({
            "v": 1,
            "kind": "migration",
            "repository_key": fx.repo_key,
            "upstream_url": "https://arti.example.test/artifactory",
        });
        assert_eq!(kind_of(pool, composed).await, want, "composed-path row");
        assert_eq!(kind_of(pool, verbatim).await, want, "verbatim-path row");
        for (id, why) in [
            (dup_a, "ambiguous: two rows share the file name"),
            (dup_b, "ambiguous: two rows share the file name"),
            (later, "created after the item completed"),
            (wrong_sum, "checksum differs"),
            (dry_row, "dry-run job"),
        ] {
            assert_eq!(kind_of(pool, id).await, hosted, "{why}");
        }

        // Idempotent: a second run changes nothing.
        rerun_migration(pool, MIGRATION_270).await;
        assert_eq!(kind_of(pool, composed).await, want);
        assert_eq!(kind_of(pool, dup_a).await, hosted);

        // The trigger is still enforced outside the GUC window...
        let rewrite = sqlx::query("UPDATE artifacts SET origin = $2 WHERE id = $1")
            .bind(dup_a)
            .bind(want.clone())
            .execute(pool)
            .await;
        assert!(
            rewrite.is_err(),
            "hosted -> migration without the GUC must be rejected"
        );
        // ...and inside it, only the sanctioned shapes pass.
        let mut tx = pool.begin().await.expect("begin");
        sqlx::query("SET LOCAL ak.origin_rewrite = 'on'")
            .execute(&mut *tx)
            .await
            .expect("set guc");
        let hostile = sqlx::query("UPDATE artifacts SET origin = $2 WHERE id = $1")
            .bind(composed)
            .bind(serde_json::json!({"v":1,"kind":"hosted","repository_key":"attacker"}))
            .execute(&mut *tx)
            .await;
        assert!(
            hostile.is_err(),
            "migration -> hosted is not a sanctioned rewrite"
        );
        drop(tx);

        sqlx::query("DELETE FROM migration_jobs WHERE source_connection_id = $1")
            .bind(conn_id)
            .execute(pool)
            .await
            .expect("delete jobs");
        sqlx::query("DELETE FROM source_connections WHERE id = $1")
            .bind(conn_id)
            .execute(pool)
            .await
            .expect("delete connection");
        fx.teardown().await;
    }

    /// #4463: migration 271 strips userinfo from origins recorded before it
    /// (and from the proxy cache catalogue), touching only the
    /// `upstream_url` facet, and a second run is a no-op.
    #[tokio::test]
    async fn test_migration_271_strips_recorded_userinfo_4463() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fx) = tdh::Fixture::setup("remote", "generic").await else {
            return;
        };
        let pool = &fx.pool;
        let credentialed = format!("https://{}@upstream.example.test/base", "alice:s3cret");
        let doc = serde_json::json!({
            "v": 1, "kind": "proxy", "repository_key": fx.repo_key, "upstream_url": credentialed,
        });
        let id = insert_with_origin(
            pool,
            fx.repo_id,
            "f/1/f.bin",
            &format!("{:064x}", 7),
            doc,
            0,
        )
        .await;
        sqlx::query(
            "INSERT INTO proxy_cache_artifacts (repository_id, path, storage_key, metadata_key, \
             size_bytes, upstream_url) VALUES ($1, 'f/1/f.bin', 'k', 'm', 1, $2)",
        )
        .bind(fx.repo_id)
        .bind(format!("{credentialed}/f/1/f.bin"))
        .execute(pool)
        .await
        .expect("insert proxy cache row");

        for _ in 0..2 {
            rerun_migration(pool, MIGRATION_271).await;
            assert_eq!(
                kind_of(pool, id).await,
                serde_json::json!({
                    "v": 1, "kind": "proxy", "repository_key": fx.repo_key,
                    "upstream_url": "https://upstream.example.test/base",
                })
            );
            let cached: String = sqlx::query_scalar(
                "SELECT upstream_url FROM proxy_cache_artifacts WHERE repository_id = $1",
            )
            .bind(fx.repo_id)
            .fetch_one(pool)
            .await
            .expect("read cache row");
            assert_eq!(cached, "https://upstream.example.test/base/f/1/f.bin");
        }

        // The upstream-only GUC window does not admit a kind change.
        let mut tx = pool.begin().await.expect("begin");
        sqlx::query("SET LOCAL ak.origin_rewrite = 'on'")
            .execute(&mut *tx)
            .await
            .expect("set guc");
        let hostile = sqlx::query(
            "UPDATE artifacts SET origin = origin || '{\"kind\":\"hosted\"}' WHERE id = $1",
        )
        .bind(id)
        .execute(&mut *tx)
        .await;
        assert!(
            hostile.is_err(),
            "proxy -> hosted is not a sanctioned rewrite"
        );
        drop(tx);

        sqlx::query("DELETE FROM proxy_cache_artifacts WHERE repository_id = $1")
            .bind(fx.repo_id)
            .execute(pool)
            .await
            .expect("delete cache rows");
        fx.teardown().await;
    }
}
