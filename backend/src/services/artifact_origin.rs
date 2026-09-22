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
}

/// Normalize an upstream URL for origin comparison — the Rust mirror of
/// the SQL `ak_normalize_upstream_url` the fill trigger and backfill use:
/// lowercase the scheme://authority (case-insensitive per RFC 3986),
/// strip trailing slashes, leave the path case-intact. The migration
/// worker normalizes source base URLs through here so a URL recorded in
/// Rust compares equal to one recorded by the trigger.
pub fn normalize_upstream_url(url: &str) -> String {
    let trimmed = url.trim();
    let after_scheme = trimmed
        .find("://")
        .filter(|&i| {
            trimmed[..i]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'))
                && !trimmed[..i].is_empty()
        })
        .map(|i| i + 3);
    let prefix_len = after_scheme.and_then(|start| {
        trimmed[start..]
            .find('/')
            .map(|rel| start + rel)
            .or(Some(trimmed.len()))
    });
    match prefix_len {
        Some(end) => {
            let prefix = trimmed[..end].to_ascii_lowercase();
            let rest = &trimmed[end..];
            format!("{prefix}{rest}").trim_end_matches('/').to_string()
        }
        None => trimmed.trim_end_matches('/').to_string(),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // normalize_upstream_url (pure)
    // ------------------------------------------------------------------

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
}
