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
//!   handler. The quarantine release paths call it too (see below).
//! * [`backfill`] runs the identical projection over artifacts already in the
//!   database. Without it a format fix only helps content published *after* the
//!   upgrade, which is the upgrade note every one of the fixes above had to
//!   carry.
//!
//! # Rows it shares with format handlers
//!
//! Several formats still write their own catalog rows (npm, PyPI, NuGet, Maven,
//! Helm, Conan, ...), as does the generic finalize path in `artifact_service`,
//! so a projected entry has to land ON that row, never beside it or over its
//! contents:
//!
//! * **Identity** is the handler's: `artifacts.name`, normalized only where the
//!   catalog is keyed on something else (Maven/Gradle `groupId:artifactId`,
//!   SBT `org:module`, Conan `name@user/channel`). See [`catalog_identity`] for
//!   why the manifest's own `name` field is not used.
//! * **Metadata** is only ever filled, never replaced
//!   ([`MetadataWrite::FillMissing`]): the projection knows the format and
//!   nothing else, and a handler's row carries more.
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
//! * **Unreleased content.** An artifact is projected only when the format
//!   indexes would list it: never once rejected, and not while quarantined
//!   until a timed hold has lapsed. An upload made under a hold therefore
//!   registers when it is released — by an admin (`quarantine_service::
//!   transition`) or by the scan that clears the hold. A hold that lapses with
//!   no scan changes no row, so nothing fires for it; the reindex endpoint
//!   picks those up.
//! * **Deletion.** Catalog rows are still never removed (#3660): this module
//!   only adds what is missing, and a reindex does not prune. It never
//!   registers a soft-deleted artifact, so it cannot resurrect one either.

use serde_json::Value as JsonValue;
use sqlx::PgPool;
use uuid::Uuid;

use crate::formats::maven::MavenHandler;
use crate::services::package_service::{MetadataWrite, PackageService};

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

/// The last path segment, lowercased.
fn file_name(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase()
}

/// Files that are published as artifacts but are not packages: checksums,
/// signatures, and the repository index files a format regenerates on write.
///
/// These carry a version (they sit at a versioned coordinate) so the empty-
/// version guard does not catch them, and cataloguing them would put
/// `maven-metadata.xml` and `APKINDEX.tar.gz` on the Packages page.
fn is_sidecar_path(path: &str) -> bool {
    let file = file_name(path);

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

/// A format's descriptor or index row stored at the SAME name and version as
/// the package it describes.
///
/// Distinct from [`is_sidecar_path`] because the file names are only
/// meaningful per format. Cataloguing one of these is not merely noise: both
/// rows upsert the same `package_versions` row, whose deterministic tiebreak
/// (lowest checksum wins) then reports the descriptor's size for the package
/// about half the time — the failure `.prov` is listed for above.
///
/// * Go: `upload_mod` stores `go.mod` beside the module zip, which is what
///   `go get` actually downloads.
/// * SBT: the Ivy descriptor publishes beside the jar at the same revision.
/// * Protobuf: `_labels` is the module's label index, a zero-byte row whose
///   version is the literal `_labels`.
fn is_companion_artifact(facts: &ArtifactFacts<'_>) -> bool {
    let file = file_name(facts.path);
    match facts.format {
        "go" => file == "go.mod" || metadata_str(facts.metadata, "type") == Some("mod"),
        "sbt" => facts
            .metadata
            .get("is_ivy_descriptor")
            .and_then(JsonValue::as_bool)
            .unwrap_or(false),
        "protobuf" => file == "_labels",
        _ => false,
    }
}

/// Read a non-empty string field out of a format's metadata object.
fn metadata_str<'a>(metadata: &'a JsonValue, key: &str) -> Option<&'a str> {
    metadata
        .get(key)
        .and_then(JsonValue::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// Maven coordinates as the two Maven catalog writers key them:
/// `groupId:artifactId` (#2723) at the directory version (#3064).
///
/// The path is parsed first because it is what BOTH writers use — the Maven
/// handler and the generic finalize path in `artifact_service`, which never
/// records `groupId` in metadata. The metadata keys are the fallback for a
/// path the parser rejects.
fn maven_identity(facts: &ArtifactFacts<'_>) -> Option<(String, Option<String>)> {
    if let Ok(coords) = MavenHandler::parse_coordinates(facts.path) {
        return Some((
            format!("{}:{}", coords.group_id, coords.artifact_id),
            Some(coords.version),
        ));
    }
    let group = metadata_str(facts.metadata, "groupId")?;
    let artifact = metadata_str(facts.metadata, "artifactId")?;
    Some((format!("{group}:{artifact}"), None))
}

/// Ivy coordinates `org:module`, the SBT analogue of Maven's
/// `groupId:artifactId`.
///
/// `artifacts.name` cannot serve: the SBT handler writes the bare artifact
/// name (`mylib_2.13`) for a jar and `org/module` for its descriptor, so the
/// row name alone neither identifies the organization nor agrees across one
/// module's files.
fn ivy_name(metadata: &JsonValue) -> Option<String> {
    let org = metadata_str(metadata, "org")?;
    let module = metadata_str(metadata, "module")?;
    Some(format!("{org}:{module}"))
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

/// The catalog name an artifact registers under, plus the version when the
/// identity carries its own.
///
/// `artifacts.name` unless the format keys its catalog on something else.
/// Every handler writes the package's full identity there — Terraform's
/// `namespace/name/provider`, Swift's `scope.name`, Composer's
/// `vendor/package`, PyPI's PEP 503 normalized name — and it is exactly what
/// the self-registering handlers pass as the catalog name.
///
/// The manifest's own `name` field is not a substitute, and must not be
/// preferred. For Terraform and Swift it is the bare name, so two distinct
/// packages (`acme/vpc/aws`, `other/vpc/aws`) would collapse onto the single
/// `(repository_id, name)` row `packages` allows, each publish overwriting the
/// other's version and size. For PyPI it is the un-normalized display name
/// (`Flask`), which would put a second row beside the handler's `flask`.
fn catalog_identity(facts: &ArtifactFacts<'_>) -> (String, Option<String>) {
    let identity = match facts.format {
        "maven" | "gradle" => maven_identity(facts),
        "sbt" => ivy_name(facts.metadata).map(|name| (name, None)),
        "conan" => Some((conan_name(facts.metadata, facts.name), None)),
        _ => None,
    };
    identity.unwrap_or_else(|| (facts.name.to_string(), None))
}

/// Trim, and treat blank as absent.
fn non_blank(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string)
}

/// Project one stored artifact onto its catalog coordinates, or `None` when it
/// is not a package.
///
/// Pure: every input is a row the caller already read, so the mapping is unit
/// testable per format without a database.
pub fn project(facts: &ArtifactFacts<'_>) -> Option<CatalogEntry> {
    if is_exempt_format(facts.format) || is_sidecar_path(facts.path) || is_companion_artifact(facts)
    {
        return None;
    }

    let (name, identity_version) = catalog_identity(facts);
    let name = non_blank(Some(&name))?;

    // A version that is part of the identity wins; then the artifact row's
    // version, which is the handler's own parse of the publish; the manifest
    // only when the row left it NULL.
    let version = non_blank(identity_version.as_deref())
        .or_else(|| non_blank(facts.version))
        .or_else(|| non_blank(metadata_str(facts.metadata, "version")))?;

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
    /// [`CATALOGABLE`], evaluated by the database.
    catalogable: bool,
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

    /// Whether this artifact becomes a catalog entry, and which.
    fn entry(&self) -> Option<CatalogEntry> {
        if !self.catalogable {
            return None;
        }
        project(&self.facts())
    }

    async fn upsert(&self, service: &PackageService, entry: &CatalogEntry) {
        if let Err(e) = service
            .upsert_from_artifact(
                self.repository_id,
                &entry.name,
                &entry.version,
                self.size_bytes,
                &self.checksum_sha256,
                entry.description.as_deref(),
                Some(serde_json::json!({ "format": self.format })),
                MetadataWrite::FillMissing,
            )
            .await
        {
            tracing::warn!(
                "package catalog: registering {}@{} from artifact {} failed: {e}",
                entry.name,
                entry.version,
                self.id
            );
        }
    }
}

/// Whether a stored artifact may appear in the catalog at all, over `a`
/// (artifacts) and `r` (its repository).
///
/// The quarantine half is the listability rule the format indexes already
/// apply (Terraform's version list, the CocoaPods shard index): a rejected
/// artifact never, a quarantined one only once its timed hold has lapsed.
/// Content a client cannot see in the format's own index must not surface by
/// name on the Packages page.
const CATALOGABLE: &str = r#"(
        r.repo_type <> 'remote'
        AND (
            a.quarantine_status IS NULL
            OR a.quarantine_status NOT IN ('quarantined', 'rejected')
            OR (
                a.quarantine_status = 'quarantined'
                AND a.quarantine_until IS NOT NULL
                AND a.quarantine_until <= NOW()
            )
        )
    )"#;

/// The artifact columns [`stored_artifacts_sql`] reads from its source.
const ARTIFACT_COLUMNS: &str = "id, repository_id, name, version, path, size_bytes, \
     checksum_sha256, quarantine_status, quarantine_until";

/// Read [`StoredArtifact`]s from `source`, a subquery over `artifacts` that
/// already narrowed and ordered the rows.
///
/// Two shapes here keep a backfill page's cost independent of its cursor:
///
/// * The narrowing lives INSIDE the subquery. Joined first and limited after,
///   the planner reads `artifact_metadata` as a merge join whose inner scan
///   starts from the first artifact on every call, so page N re-reads the N-1
///   pages before it.
/// * Metadata is a `LATERAL ... LIMIT 1` lookup, not a plain join. With only a
///   page of artifacts on the outer side the planner still prefers hashing the
///   whole of `artifact_metadata` — flat per page, but a full-table read per
///   page. The `LIMIT` stops the subquery being flattened back into that join,
///   so each row is one probe of the unique `artifact_id` index; it drops
///   nothing, since there is at most one row to find.
fn stored_artifacts_sql(source: &str) -> String {
    format!(
        r#"
        SELECT a.id,
               a.repository_id,
               a.name,
               a.version,
               a.path,
               a.size_bytes,
               a.checksum_sha256,
               COALESCE(am.format, r.format::text) AS format,
               COALESCE(am.metadata, '{{}}'::jsonb) AS metadata,
               {CATALOGABLE} AS catalogable
        FROM ({source}) a
        JOIN repositories r ON r.id = a.repository_id
        LEFT JOIN LATERAL (
            SELECT m.format, m.metadata
            FROM artifact_metadata m
            WHERE m.artifact_id = a.id
            LIMIT 1
        ) am ON true
        ORDER BY a.id
        "#
    )
}

/// Register one artifact in the catalog, if it projects to a package.
///
/// Best-effort by contract: called after the bytes are committed, it must never
/// fail a publish, so every error is logged and swallowed — the same contract
/// the per-handler catalog calls have always had.
pub async fn register_artifact(db: &PgPool, artifact_id: Uuid) {
    let sql = stored_artifacts_sql(&format!(
        "SELECT {ARTIFACT_COLUMNS} FROM artifacts WHERE id = $1 AND is_deleted = false"
    ));

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
    if let Some(entry) = stored.entry() {
        stored
            .upsert(&PackageService::new(db.clone()), &entry)
            .await;
    }
}

/// What one [`backfill`] call did, so an operator can drive it to completion.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
pub struct BackfillReport {
    /// Artifacts examined in this call.
    pub scanned: i64,
    /// Artifacts that projected to a package and were upserted.
    pub registered: i64,
    /// Artifacts skipped: not a package (sidecars, descriptors, OCI manifests,
    /// no version), or not listable (remote, quarantined, rejected).
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
/// minutes. Callers page with `after` until `next_cursor` is `None`. Each page
/// is a range scan of the primary key from the cursor, so its cost does not
/// grow as the cursor advances.
pub async fn backfill(
    db: &PgPool,
    repository_id: Option<Uuid>,
    after: Option<Uuid>,
    limit: i64,
) -> anyhow::Result<BackfillReport> {
    // Both filters are spelled so the planner sees a plain range on `id`:
    // `($2 IS NULL OR id > $2)` cannot use the index as a range, and would
    // scan from the first artifact on every page. The nil UUID sorts first.
    let repository_clause = if repository_id.is_some() {
        "AND repository_id = $1"
    } else {
        "AND $1::uuid IS NULL"
    };
    let sql = stored_artifacts_sql(&format!(
        "SELECT {ARTIFACT_COLUMNS} FROM artifacts
         WHERE is_deleted = false
           AND id > $2
           {repository_clause}
         ORDER BY id
         LIMIT $3"
    ));

    let rows: Vec<StoredArtifact> = sqlx::query_as(sqlx::AssertSqlSafe(&*sql))
        .bind(repository_id)
        .bind(after.unwrap_or_else(Uuid::nil))
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
        match row.entry() {
            Some(entry) => {
                row.upsert(&service, &entry).await;
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
    fn keeps_the_row_identity_when_the_manifest_name_is_shorter() {
        // Terraform and Swift record the bare name in metadata; the row holds
        // the full identity. Preferring the manifest would collapse these two
        // modules onto one `(repository_id, name)` catalog row.
        let acme = json!({ "namespace": "acme", "name": "vpc", "provider": "aws" });
        let other = json!({ "namespace": "other", "name": "vpc", "provider": "aws" });
        let a = project(&facts(
            "terraform",
            &acme,
            "acme/vpc/aws",
            Some("1.0.0"),
            "modules/acme/vpc/aws/1.0.0.tar.gz",
        ))
        .unwrap();
        let b = project(&facts(
            "terraform",
            &other,
            "other/vpc/aws",
            Some("2.0.0"),
            "modules/other/vpc/aws/2.0.0.tar.gz",
        ))
        .unwrap();
        assert_eq!(a.name, "acme/vpc/aws");
        assert_eq!(b.name, "other/vpc/aws");

        let swift = json!({ "scope": "acme", "name": "Networking" });
        assert_eq!(
            project(&facts(
                "swift",
                &swift,
                "acme.Networking",
                Some("1.0.0"),
                "acme/Networking/1.0.0.zip",
            ))
            .unwrap()
            .name,
            "acme.Networking"
        );
    }

    #[test]
    fn keeps_the_normalized_pypi_name_the_handler_registers() {
        let metadata = json!({ "name": "Flask", "normalized_name": "flask" });
        let entry = project(&facts(
            "pypi",
            &metadata,
            "flask",
            Some("3.0.0"),
            "flask/3.0.0/Flask-3.0.0-py3-none-any.whl",
        ))
        .unwrap();
        assert_eq!(entry.name, "flask");
    }

    #[test]
    fn normalizes_maven_coordinates_from_the_path_like_both_writers() {
        // No metadata at all: the generic finalize path in artifact_service
        // records none, yet keys the catalog on `groupId:artifactId` (#2723) at
        // the directory version (#3064). The row's naive version must lose.
        let metadata = json!({});
        let entry = project(&facts(
            "gradle",
            &metadata,
            "widget-1.0.0.jar",
            Some("com"),
            "com/acme/widget/1.0.0/widget-1.0.0.jar",
        ))
        .expect("a jar is a package");

        assert_eq!(entry.name, "com.acme:widget");
        assert_eq!(entry.version, "1.0.0");
    }

    #[test]
    fn falls_back_to_maven_metadata_when_the_path_does_not_parse() {
        let metadata = json!({ "groupId": "com.acme", "artifactId": "widget" });
        let entry = project(&facts(
            "maven",
            &metadata,
            "widget",
            Some("1.0.0"),
            "widget.jar",
        ))
        .unwrap();
        assert_eq!(entry.name, "com.acme:widget");
        assert_eq!(entry.version, "1.0.0");
    }

    #[test]
    fn keys_sbt_on_organization_and_module() {
        let jar = json!({ "org": "com.acme", "module": "mylib_2.13", "is_ivy_descriptor": false });
        let entry = project(&facts(
            "sbt",
            &jar,
            "mylib_2.13",
            Some("1.0.0"),
            "com.acme/mylib_2.13/1.0.0/jars/mylib_2.13.jar",
        ))
        .unwrap();
        assert_eq!(entry.name, "com.acme:mylib_2.13");
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
    fn skips_descriptors_stored_beside_the_package_they_describe() {
        let go_mod = json!({ "module": "example.com/m", "version": "v1.0.0", "type": "mod" });
        assert!(project(&facts(
            "go",
            &go_mod,
            "example.com/m",
            Some("v1.0.0"),
            "example.com/m/v1.0.0/go.mod",
        ))
        .is_none());

        let go_zip = json!({ "module": "example.com/m", "version": "v1.0.0", "type": "zip" });
        assert!(project(&facts(
            "go",
            &go_zip,
            "example.com/m",
            Some("v1.0.0"),
            "example.com/m/v1.0.0/v1.0.0.zip",
        ))
        .is_some());

        let ivy = json!({ "org": "com.acme", "module": "mylib", "is_ivy_descriptor": true });
        assert!(project(&facts(
            "sbt",
            &ivy,
            "com.acme/mylib",
            Some("1.0.0"),
            "com.acme/mylib/1.0.0/ivys/ivy.xml",
        ))
        .is_none());

        let labels = json!({});
        assert!(project(&facts(
            "protobuf",
            &labels,
            "acme/petapis",
            Some("_labels"),
            "modules/acme/petapis/_labels",
        ))
        .is_none());
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

/// DB-backed revert-proofs: each fails if the mechanism it names is removed.
#[cfg(test)]
mod db_tests {
    use super::*;
    use crate::api::handlers::proxy_helpers;
    use crate::api::handlers::test_db_helpers as tdh;
    use serde_json::json;

    struct Seed<'a> {
        name: &'a str,
        version: &'a str,
        path: &'a str,
        size_bytes: i64,
        checksum: &'a str,
    }

    /// Insert an artifact row the way hosted handlers do, WITHOUT any catalog
    /// write, so only the code under test can produce one.
    async fn seed(pool: &PgPool, repo_id: Uuid, s: Seed<'_>) -> Uuid {
        let checksum = format!("{:0<64}", s.checksum);
        sqlx::query_scalar(
            "INSERT INTO artifacts (repository_id, path, name, version, size_bytes, \
             checksum_sha256, content_type, storage_key) \
             VALUES ($1, $2, $3, $4, $5, $6, 'application/octet-stream', $2) RETURNING id",
        )
        .bind(repo_id)
        .bind(s.path)
        .bind(s.name)
        .bind(s.version)
        .bind(s.size_bytes)
        .bind(checksum)
        .fetch_one(pool)
        .await
        .expect("seed artifact")
    }

    async fn store_metadata(pool: &PgPool, artifact_id: Uuid, format: &str, metadata: JsonValue) {
        sqlx::query(
            "INSERT INTO artifact_metadata (artifact_id, format, metadata) VALUES ($1, $2, $3)",
        )
        .bind(artifact_id)
        .bind(format)
        .bind(metadata)
        .execute(pool)
        .await
        .expect("seed metadata");
    }

    /// `(name, package version, that version's size, package metadata)`.
    async fn catalog(pool: &PgPool, repo_id: Uuid) -> Vec<(String, String, i64, JsonValue)> {
        sqlx::query_as(
            "SELECT p.name, pv.version, pv.size_bytes, COALESCE(p.metadata, 'null'::jsonb) \
             FROM packages p JOIN package_versions pv ON pv.package_id = p.id \
             WHERE p.repository_id = $1 ORDER BY p.name, pv.version",
        )
        .bind(repo_id)
        .fetch_all(pool)
        .await
        .expect("read catalog")
    }

    async fn drain_backfill(pool: &PgPool, repo_id: Uuid, page: i64) -> BackfillReport {
        let mut total = BackfillReport::default();
        let mut after = None;
        loop {
            let report = backfill(pool, Some(repo_id), after, page)
                .await
                .expect("backfill");
            total.scanned += report.scanned;
            total.registered += report.registered;
            total.skipped += report.skipped;
            match report.next_cursor {
                Some(cursor) => after = Some(cursor),
                None => return total,
            }
        }
    }

    #[tokio::test]
    async fn a_publish_through_the_metadata_chokepoint_lands_a_catalog_row() {
        let Some(f) = tdh::Fixture::setup("local", "terraform").await else {
            return;
        };

        // Two modules whose manifests share the bare name `vpc`: they must be
        // two packages, each keeping its own version and size.
        for (identity, namespace, version, size) in [
            ("acme/vpc/aws", "acme", "1.0.0", 111),
            ("other/vpc/aws", "other", "2.0.0", 222),
        ] {
            let path = format!("modules/{identity}/{version}.tar.gz");
            let id = seed(
                &f.pool,
                f.repo_id,
                Seed {
                    name: identity,
                    version,
                    path: &path,
                    size_bytes: size,
                    checksum: namespace,
                },
            )
            .await;
            proxy_helpers::record_artifact_metadata(
                &f.pool,
                id,
                f.repo_id,
                "terraform",
                &json!({ "namespace": namespace, "name": "vpc", "provider": "aws" }),
            )
            .await;
        }

        let rows = catalog(&f.pool, f.repo_id).await;
        let summary: Vec<_> = rows
            .iter()
            .map(|(n, v, s, _)| (n.as_str(), v.as_str(), *s))
            .collect();
        assert_eq!(
            summary,
            vec![
                ("acme/vpc/aws", "1.0.0", 111),
                ("other/vpc/aws", "2.0.0", 222)
            ]
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn a_backfill_registers_stored_artifacts_without_touching_handler_rows() {
        let Some(f) = tdh::Fixture::setup("local", "pypi").await else {
            return;
        };

        // `flask` already has the row the PyPI handler writes, with metadata
        // the projection does not know. `requests` has no catalog row.
        let flask = seed(
            &f.pool,
            f.repo_id,
            Seed {
                name: "flask",
                version: "3.0.0",
                path: "flask/3.0.0/Flask-3.0.0-py3-none-any.whl",
                size_bytes: 100,
                checksum: "aa",
            },
        )
        .await;
        store_metadata(
            &f.pool,
            flask,
            "pypi",
            json!({ "name": "Flask", "normalized_name": "flask" }),
        )
        .await;
        let handler_metadata = json!({ "format": "pypi", "requires_python": ">=3.8" });
        PackageService::new(f.pool.clone())
            .create_or_update_from_artifact(
                f.repo_id,
                "flask",
                "3.0.0",
                100,
                &format!("{:0<64}", "aa"),
                None,
                Some(handler_metadata.clone()),
            )
            .await
            .expect("handler row");

        for (i, version) in ["2.31.0", "2.32.0"].into_iter().enumerate() {
            let path = format!("requests/{version}/requests-{version}.tar.gz");
            let id = seed(
                &f.pool,
                f.repo_id,
                Seed {
                    name: "requests",
                    version,
                    path: &path,
                    size_bytes: 10 + i as i64,
                    checksum: "bb",
                },
            )
            .await;
            store_metadata(&f.pool, id, "pypi", json!({ "name": "Requests" })).await;
        }

        // A page of one forces the cursor through every row.
        let report = drain_backfill(&f.pool, f.repo_id, 1).await;
        assert_eq!((report.scanned, report.registered), (3, 3));

        let rows = catalog(&f.pool, f.repo_id).await;
        let names: Vec<_> = rows
            .iter()
            .map(|(n, v, _, _)| (n.as_str(), v.as_str()))
            .collect();
        assert_eq!(
            names,
            vec![
                ("flask", "3.0.0"),
                ("requests", "2.31.0"),
                ("requests", "2.32.0")
            ],
            "no display-name row beside the handler's normalized one"
        );
        assert_eq!(
            rows[0].3, handler_metadata,
            "a backfill must not rewrite a handler's metadata"
        );

        f.teardown().await;
    }

    #[tokio::test]
    async fn deleted_and_unreleased_artifacts_stay_out_until_released() {
        let Some(f) = tdh::Fixture::setup("local", "cargo").await else {
            return;
        };

        let mut ids = Vec::new();
        for (name, status_sql) in [
            ("deleted", "is_deleted = true"),
            ("rejected", "quarantine_status = 'rejected'"),
            (
                "held",
                "quarantine_status = 'quarantined', quarantine_until = NOW() + INTERVAL '1 hour'",
            ),
        ] {
            let path = format!("crates/{name}/1.0.0/{name}-1.0.0.crate");
            let id = seed(
                &f.pool,
                f.repo_id,
                Seed {
                    name,
                    version: "1.0.0",
                    path: &path,
                    size_bytes: 1,
                    checksum: "cc",
                },
            )
            .await;
            let sql = format!("UPDATE artifacts SET {status_sql} WHERE id = $1");
            sqlx::query(sqlx::AssertSqlSafe(&*sql))
                .bind(id)
                .execute(&f.pool)
                .await
                .expect("set state");
            proxy_helpers::record_artifact_metadata(&f.pool, id, f.repo_id, "cargo", &json!({}))
                .await;
            ids.push(id);
        }

        let report = drain_backfill(&f.pool, f.repo_id, 500).await;
        assert_eq!(report.registered, 0, "{report:?}");
        assert!(catalog(&f.pool, f.repo_id).await.is_empty());

        crate::services::quarantine_service::transition(
            &f.pool,
            ids[2],
            crate::services::quarantine_service::QuarantineState::Released,
            None,
        )
        .await
        .expect("release");

        let rows = catalog(&f.pool, f.repo_id).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "held", "release registers the held upload");

        f.teardown().await;
    }

    #[tokio::test]
    async fn a_go_module_reports_the_zip_size_not_the_go_mod() {
        let Some(f) = tdh::Fixture::setup("local", "go").await else {
            return;
        };

        // The go.mod's checksum sorts first, so without the descriptor rule
        // the version row's deterministic tiebreak picks the go.mod's size.
        for (file, kind, size, checksum) in [
            ("v1.0.0.zip", "zip", 4096, "ff"),
            ("go.mod", "mod", 42, "00"),
        ] {
            let path = format!("example.com/m/v1.0.0/{file}");
            let id = seed(
                &f.pool,
                f.repo_id,
                Seed {
                    name: "example.com/m",
                    version: "v1.0.0",
                    path: &path,
                    size_bytes: size,
                    checksum,
                },
            )
            .await;
            proxy_helpers::record_artifact_metadata(
                &f.pool,
                id,
                f.repo_id,
                "go",
                &json!({ "module": "example.com/m", "version": "v1.0.0", "type": kind }),
            )
            .await;
        }

        let rows = catalog(&f.pool, f.repo_id).await;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].2, 4096);

        f.teardown().await;
    }
}
