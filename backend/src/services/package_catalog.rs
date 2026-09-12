//! One projection from a stored artifact to the package catalog (#3659).
//!
//! # Why this module exists
//!
//! `packages` / `package_versions` is a hand-maintained index that the web
//! UI's Packages page and `GET /api/v1/packages` read INSTEAD of `artifacts`.
//! Nothing derives it: a row exists only where a format handler remembered to
//! call [`PackageService::try_create_or_update_from_artifact`] after its own
//! `INSERT INTO artifacts`. That call is opt-in per handler, so the same defect
//! has been found and fixed one format at a time — NuGet (#1289), Incus
//! (#1477), Composer (#1487), Maven (#1909), OCI (#2337), Conan (#3358), Helm
//! (#3531) — while the twenty handlers nobody has reached yet still publish
//! artifacts that are pullable and invisible.
//!
//! The fix is to stop asking handlers to remember. Every publishing handler
//! already writes the two rows a catalog entry needs — the `artifacts` row
//! (name, version, size, checksum) and the `artifact_metadata` row (format +
//! the format's own parsed manifest) — so the catalog can be *projected* from
//! what is already stored, in one place, for every format at once:
//!
//! * [`project`] maps (format, metadata, artifact row) to catalog coordinates.
//! * [`register_artifact`] runs that projection on one artifact and upserts it.
//!   `proxy_helpers::record_artifact_metadata` calls it, which is the shared
//!   chokepoint every publish already passes through — the same place the
//!   upload-time quarantine hold was centralized rather than pasted into each
//!   handler.
//! * [`backfill`] runs the identical projection over artifacts already in the
//!   database. Without it a format fix only helps content published *after* the
//!   upgrade, which is the upgrade note every one of the fixes above had to
//!   carry.
//!
//! # What it deliberately does not own
//!
//! * **Remote/proxy repositories.** A cached upstream artifact is catalogued by
//!   the proxy's own path (#2218, #3441, #3599); registering it a second time
//!   here would race that write and record manifest-body sizes as image sizes.
//!   Every other repository type is projected: the rule is "the proxy owns its
//!   own catalog", not "only Local repositories hold packages" — a Staging
//!   repository, or a Virtual one that a migration wrote artifact rows onto,
//!   stores bytes here and belongs in the catalog like any other.
//! * **OCI/docker.** An OCI `artifacts` row is a manifest or a blob, not a
//!   package: the image's catalog identity is `image` + tag, which only the
//!   manifest handler knows. `handle_put_manifest` and the proxy indexer own
//!   it, and [`project`] returns `None` for the format so this module can never
//!   contradict them.
//! * **Deletion.** Catalog rows are still never removed (#3660); this module
//!   only adds what is missing.

use serde_json::Value as JsonValue;
use sqlx::PgPool;
use uuid::Uuid;

use crate::services::package_service::PackageService;

/// The catalog coordinates one artifact projects to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogEntry {
    /// `packages.name` — the identity users search by, which is NOT always the
    /// `artifacts.name` (Maven groups, Conan user/channel).
    pub name: String,
    /// `packages.version` / `package_versions.version`.
    pub version: String,
    /// `packages.description`, where the format's manifest carries one.
    pub description: Option<String>,
}

/// The stored facts a projection is allowed to read: the `artifacts` row and
/// its `artifact_metadata` sidecar, nothing else. Borrowed so the projection
/// stays a pure function over rows the caller already has.
#[derive(Debug, Clone, Copy)]
pub struct ArtifactFacts<'a> {
    pub format: &'a str,
    pub metadata: &'a JsonValue,
    pub name: &'a str,
    pub version: Option<&'a str>,
    pub path: &'a str,
}

/// Formats whose catalog identity is not derivable from an `artifacts` row.
///
/// OCI is the whole list: its rows are manifests and blobs addressed by digest,
/// and the image identity (`image` + tag) lives in the manifest handler's
/// request, not in storage. Projecting them would publish `sha256:...` as a
/// package name next to the correct rows the OCI path already writes.
fn is_exempt_format(format: &str) -> bool {
    matches!(format, "docker" | "oci")
}

/// Files that are published as artifacts but are not packages: checksums,
/// signatures, and the repository index files a format regenerates on write.
///
/// These carry a version (they sit at a versioned coordinate) so the empty-
/// version guard does not catch them, and cataloguing them would put
/// `maven-metadata.xml` and `APKINDEX.tar.gz` on the Packages page.
fn is_sidecar_path(path: &str) -> bool {
    let file = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();

    // `.prov` earns its place: a Helm chart and its provenance file publish at
    // the same name and version, so cataloguing both makes the signature's size
    // the size the Packages page reports for the chart.
    const SIDECAR_EXTENSIONS: [&str; 9] = [
        ".sha1",
        ".sha256",
        ".sha512",
        ".md5",
        ".asc",
        ".sig",
        ".sbom",
        ".metalink",
        ".prov",
    ];
    if SIDECAR_EXTENSIONS.iter().any(|ext| file.ends_with(ext)) {
        return true;
    }

    const INDEX_FILES: [&str; 11] = [
        "maven-metadata.xml",
        "index.yaml",
        "apkindex.tar.gz",
        "packages",
        "packages.gz",
        "release",
        "inrelease",
        "release.gpg",
        "repomd.xml",
        "index.json",
        "packages.json",
    ];
    if INDEX_FILES.contains(&file.as_str()) {
        return true;
    }

    path.to_ascii_lowercase().contains("/repodata/")
}

/// Read a non-empty string field out of a format's metadata object.
fn metadata_str<'a>(metadata: &'a JsonValue, key: &str) -> Option<&'a str> {
    metadata
        .get(key)
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// Maven-shaped coordinates: `groupId:artifactId`, which is what the grouped
/// listings and `packages.name` have keyed on since #2723. Detected by the
/// metadata keys rather than by a format allow-list, so Gradle, SBT and any
/// other Maven-layout format normalize the same way without being enumerated.
fn maven_shaped_name(metadata: &JsonValue) -> Option<String> {
    let group = metadata_str(metadata, "groupId")?;
    let artifact = metadata_str(metadata, "artifactId")?;
    Some(format!("{group}:{artifact}"))
}

/// Conan's reference identity `name@user/channel`, collapsing to a bare `name`
/// for the `_/_` defaults — the same shape `conan_catalog_name` produces, so a
/// projected row lands on the handler's row instead of beside it.
fn conan_name(metadata: &JsonValue, fallback: &str) -> String {
    let name = metadata_str(metadata, "name").unwrap_or(fallback);
    let user = metadata_str(metadata, "user").filter(|u| *u != "_");
    let channel = metadata_str(metadata, "channel").filter(|c| *c != "_");

    match (user, channel) {
        (Some(user), Some(channel)) => format!("{name}@{user}/{channel}"),
        _ => name.to_string(),
    }
}

/// Project one stored artifact onto its catalog coordinates, or `None` when it
/// is not a package.
///
/// Pure: every input is a row the caller already read, so the mapping is unit
/// testable per format without a database.
pub fn project(facts: &ArtifactFacts<'_>) -> Option<CatalogEntry> {
    if is_exempt_format(facts.format) || is_sidecar_path(facts.path) {
        return None;
    }

    let name = match facts.format {
        "conan" => conan_name(facts.metadata, facts.name),
        _ => maven_shaped_name(facts.metadata)
            .or_else(|| metadata_str(facts.metadata, "name").map(str::to_string))
            .unwrap_or_else(|| facts.name.to_string()),
    };
    let name = name.trim().to_string();
    if name.is_empty() {
        return None;
    }

    // The artifact row's version is the handler's own parse of the publish —
    // prefer it, and fall back to the manifest only when the row left it NULL.
    let version = facts
        .version
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
        .or_else(|| metadata_str(facts.metadata, "version").map(str::to_string))?;

    // `summary` is RPM's one-line description; `description` is everyone
    // else's. Both are optional and neither blocks the entry.
    let description = metadata_str(facts.metadata, "description")
        .or_else(|| metadata_str(facts.metadata, "summary"))
        .map(str::to_string);

    Some(CatalogEntry {
        name,
        version,
        description,
    })
}

/// One artifact's stored facts, owned, as read back from the database.
#[derive(Debug, sqlx::FromRow)]
struct StoredArtifact {
    id: Uuid,
    repository_id: Uuid,
    name: String,
    version: Option<String>,
    path: String,
    size_bytes: i64,
    checksum_sha256: String,
    format: String,
    metadata: JsonValue,
}

impl StoredArtifact {
    fn facts(&self) -> ArtifactFacts<'_> {
        ArtifactFacts {
            format: &self.format,
            metadata: &self.metadata,
            name: &self.name,
            version: self.version.as_deref(),
            path: &self.path,
        }
    }
}

/// Columns every read in this module projects, so the row shape and the
/// `local`-only / not-deleted predicates cannot drift between the live write
/// and the backfill.
const STORED_ARTIFACT_SELECT: &str = r#"
    SELECT a.id,
           a.repository_id,
           a.name,
           a.version,
           a.path,
           a.size_bytes,
           a.checksum_sha256,
           COALESCE(am.format, r.format::text) AS format,
           COALESCE(am.metadata, '{}'::jsonb)  AS metadata
    FROM artifacts a
    JOIN repositories r ON r.id = a.repository_id
    LEFT JOIN artifact_metadata am ON am.artifact_id = a.id
    WHERE a.is_deleted = false
      AND r.repo_type <> 'remote'
"#;

/// Register one artifact in the catalog, if it projects to a package.
///
/// Best-effort by contract: called after the bytes are committed, it must never
/// fail a publish, so every error is logged and swallowed — the same contract
/// the per-handler catalog calls have always had.
pub async fn register_artifact(db: &PgPool, artifact_id: Uuid) {
    let sql = format!("{STORED_ARTIFACT_SELECT} AND a.id = $1");

    let stored: Option<StoredArtifact> = match sqlx::query_as(sqlx::AssertSqlSafe(&*sql))
        .bind(artifact_id)
        .fetch_optional(db)
        .await
    {
        Ok(row) => row,
        Err(e) => {
            tracing::warn!("package catalog: reading artifact {artifact_id} failed: {e}");
            return;
        }
    };

    let Some(stored) = stored else {
        return;
    };
    let Some(entry) = project(&stored.facts()) else {
        return;
    };

    PackageService::new(db.clone())
        .try_create_or_update_from_artifact(
            stored.repository_id,
            &entry.name,
            &entry.version,
            stored.size_bytes,
            &stored.checksum_sha256,
            entry.description.as_deref(),
            Some(serde_json::json!({ "format": stored.format })),
        )
        .await;
}

/// What one [`backfill`] call did, so an operator can drive it to completion.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
pub struct BackfillReport {
    /// Artifacts examined in this call.
    pub scanned: i64,
    /// Artifacts that projected to a package and were upserted.
    pub registered: i64,
    /// Artifacts skipped as not-a-package (sidecars, OCI manifests, no version).
    pub skipped: i64,
    /// Pass back as `after` to continue; `None` when the scan is complete.
    #[schema(value_type = Option<String>)]
    pub next_cursor: Option<Uuid>,
}

/// Project every already-stored artifact onto the catalog.
///
/// This is the half of the fix that makes existing content appear: registration
/// at publish time only ever helps the next upload, so without a backfill a
/// repository that was filled before the upgrade stays empty on the Packages
/// page until every artifact in it is pushed again.
///
/// Bounded and resumable rather than one long transaction — an instance with a
/// million artifacts must not be a single statement that holds a connection for
/// minutes. Callers page with `after` until `next_cursor` is `None`.
pub async fn backfill(
    db: &PgPool,
    repository_id: Option<Uuid>,
    after: Option<Uuid>,
    limit: i64,
) -> anyhow::Result<BackfillReport> {
    let sql = format!(
        "{STORED_ARTIFACT_SELECT}
          AND ($1::uuid IS NULL OR a.repository_id = $1)
          AND ($2::uuid IS NULL OR a.id > $2)
        ORDER BY a.id
        LIMIT $3"
    );

    let rows: Vec<StoredArtifact> = sqlx::query_as(sqlx::AssertSqlSafe(&*sql))
        .bind(repository_id)
        .bind(after)
        .bind(limit)
        .fetch_all(db)
        .await?;

    let mut report = BackfillReport {
        scanned: rows.len() as i64,
        ..Default::default()
    };
    // A short page means the scan reached the end; a full page means there may
    // be more, and the last id is where the next call resumes.
    if report.scanned == limit {
        report.next_cursor = rows.last().map(|row| row.id);
    }

    let service = PackageService::new(db.clone());
    for row in &rows {
        match project(&row.facts()) {
            Some(entry) => {
                service
                    .try_create_or_update_from_artifact(
                        row.repository_id,
                        &entry.name,
                        &entry.version,
                        row.size_bytes,
                        &row.checksum_sha256,
                        entry.description.as_deref(),
                        Some(serde_json::json!({ "format": row.format })),
                    )
                    .await;
                report.registered += 1;
            }
            None => report.skipped += 1,
        }
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn facts<'a>(
        format: &'a str,
        metadata: &'a JsonValue,
        name: &'a str,
        version: Option<&'a str>,
        path: &'a str,
    ) -> ArtifactFacts<'a> {
        ArtifactFacts {
            format,
            metadata,
            name,
            version,
            path,
        }
    }

    #[test]
    fn projects_a_plain_format_from_the_artifact_row() {
        // rpm, rubygems, cargo, terraform, ... all put the package's own
        // coordinates on the artifacts row, which is why one projection can
        // serve every format that never registered itself.
        let metadata = json!({ "arch": "x86_64" });
        let entry = project(&facts(
            "rpm",
            &metadata,
            "nginx",
            Some("1.24.0-1.el9"),
            "packages/nginx-1.24.0-1.el9.x86_64.rpm",
        ))
        .expect("rpm upload is a package");

        assert_eq!(entry.name, "nginx");
        assert_eq!(entry.version, "1.24.0-1.el9");
        assert_eq!(entry.description, None);
    }

    #[test]
    fn prefers_the_manifest_name_over_the_artifact_row() {
        let metadata = json!({ "name": "@scope/pkg", "description": "a package" });
        let entry = project(&facts(
            "npm",
            &metadata,
            "pkg",
            Some("2.0.0"),
            "@scope/pkg/-/pkg-2.0.0.tgz",
        ))
        .expect("npm publish is a package");

        assert_eq!(entry.name, "@scope/pkg");
        assert_eq!(entry.description.as_deref(), Some("a package"));
    }

    #[test]
    fn normalizes_maven_shaped_coordinates_to_group_and_artifact() {
        // Matches `maven_package_name`, so a projected row lands ON the Maven
        // handler's row instead of creating a second one beside it (#2723).
        let metadata = json!({ "groupId": "com.acme", "artifactId": "widget" });
        let entry = project(&facts(
            "maven",
            &metadata,
            "widget",
            Some("1.0.0"),
            "com/acme/widget/1.0.0/widget-1.0.0.jar",
        ))
        .expect("a jar is a package");

        assert_eq!(entry.name, "com.acme:widget");
    }

    #[test]
    fn collapses_conan_default_user_and_channel() {
        let defaults = json!({ "name": "zlib", "user": "_", "channel": "_" });
        assert_eq!(
            project(&facts(
                "conan",
                &defaults,
                "zlib",
                Some("1.3"),
                "zlib/1.3/x"
            ))
            .unwrap()
            .name,
            "zlib"
        );

        let scoped = json!({ "name": "zlib", "user": "acme", "channel": "stable" });
        assert_eq!(
            project(&facts("conan", &scoped, "zlib", Some("1.3"), "zlib/1.3/x"))
                .unwrap()
                .name,
            "zlib@acme/stable"
        );
    }

    #[test]
    fn falls_back_to_the_rpm_summary_for_a_description() {
        let metadata = json!({ "summary": "HTTP server" });
        let entry = project(&facts(
            "rpm",
            &metadata,
            "nginx",
            Some("1.24.0"),
            "packages/nginx.rpm",
        ))
        .unwrap();

        assert_eq!(entry.description.as_deref(), Some("HTTP server"));
    }

    #[test]
    fn skips_oci_rows_whose_identity_only_the_manifest_handler_knows() {
        let metadata = json!({ "mediaType": "application/vnd.oci.image.manifest.v1+json" });
        assert!(project(&facts(
            "docker",
            &metadata,
            "library/alpine",
            Some("sha256:abc"),
            "manifests/sha256:abc",
        ))
        .is_none());
    }

    #[test]
    fn skips_checksums_signatures_and_repository_indexes() {
        let metadata = json!({});
        for path in [
            "com/acme/widget/1.0.0/widget-1.0.0.jar.sha1",
            "com/acme/widget/1.0.0/widget-1.0.0.jar.asc",
            "com/acme/widget/maven-metadata.xml",
            "index.yaml",
            "x86_64/APKINDEX.tar.gz",
            "repodata/repomd.xml",
            "dists/stable/main/binary-amd64/Packages.gz",
            "charts/mychart-1.0.0.tgz.prov",
        ] {
            assert!(
                project(&facts("maven", &metadata, "widget", Some("1.0.0"), path)).is_none(),
                "{path} must not be catalogued as a package"
            );
        }
    }

    #[test]
    fn skips_an_artifact_with_no_version_anywhere() {
        let metadata = json!({ "name": "thing" });
        assert!(project(&facts("generic", &metadata, "thing", None, "thing.bin")).is_none());
        assert!(project(&facts(
            "generic",
            &metadata,
            "thing",
            Some("  "),
            "thing.bin"
        ))
        .is_none());
    }

    #[test]
    fn takes_the_version_from_the_manifest_when_the_row_has_none() {
        let metadata = json!({ "name": "thing", "version": "3.1.4" });
        let entry = project(&facts(
            "conda",
            &metadata,
            "thing",
            None,
            "noarch/thing.conda",
        ))
        .unwrap();

        assert_eq!(entry.version, "3.1.4");
    }
}
