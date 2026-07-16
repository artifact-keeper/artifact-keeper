//! Curated RPM snapshot publish (#2358 — RPM curation Phase-3).
//!
//! Freezes the *approved* subset of a curation repo's synced packages into a
//! monotonic, immutable `repository_version`, then publishes it as signed,
//! AK-generated repodata that is served under `/rpm/{key}/@N/`.
//!
//! Two steps:
//!   1. [`create_version`] snapshots `curation_packages WHERE status = 'approved'`
//!      into a new `repository_versions` row (version N = MAX + 1, allocated in a
//!      single serializable transaction so the number is monotonic under
//!      concurrency) plus its `repository_version_packages` membership. It fails
//!      closed on an empty approved set and on any approved package missing its
//!      retained upstream `primary_xml_snippet` (which means it must be re-synced).
//!   2. [`publish`] re-emits an upstream-faithful `primary.xml` from the retained
//!      member snippets, generates pkgid-consistent stub `filelists.xml`/
//!      `other.xml` via the existing hosted RPM generators, builds and SIGNS a
//!      `repomd.xml`, and stores every blob (including the detached signature and
//!      the public key *as they were at publish time*) beneath the version's
//!      `storage_prefix`. Serving `@N` then reads these frozen blobs, so a later
//!      signing-key rotation never retroactively invalidates a published `@N`.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::api::handlers::rpm::{
    generate_filelists_xml, generate_other_xml, gzip_bytes, sha256_hex, RpmArtifact,
};
use crate::error::AppError;
use crate::formats::rpm::{generate_repomd, RepoMdChecksum, RepoMdData, RepoMdLocation};
use crate::services::signing_service::SigningService;
use crate::storage::StorageBackend;

/// A created (not-yet-published) or published curated snapshot.
#[derive(Debug, Clone)]
pub struct VersionSummary {
    pub id: Uuid,
    pub version_number: i64,
    pub package_count: i64,
}

/// The outcome of a successful [`publish`].
#[derive(Debug, Clone)]
pub struct PublishSummary {
    pub version_number: i64,
    pub package_count: i64,
    pub storage_prefix: String,
    pub repomd_storage_key: String,
}

/// One member of a snapshot, loaded for publication.
#[derive(Debug, Clone, sqlx::FromRow)]
struct MemberPackage {
    primary_xml_snippet: Option<String>,
    checksum_sha256: Option<String>,
    package_name: String,
    version: String,
    release: Option<String>,
    architecture: Option<String>,
}

/// Snapshot the *approved* curation set of `repo_id` into a new monotonic
/// version. Fails closed (400) when there is nothing approved to freeze, and
/// (400) when any approved package is missing its retained upstream metadata
/// snippet — those rows predate snippet retention and must be re-synced before
/// a publish can include them (never emit a package without its snippet).
pub async fn create_version(
    db: &PgPool,
    repo_id: Uuid,
    actor: Uuid,
) -> Result<VersionSummary, AppError> {
    // Serializable so the MAX(version_number)+1 read and the insert are atomic
    // with respect to a concurrent create; the UNIQUE(repository_id,
    // version_number) constraint is the hard backstop if two racers slip past.
    let mut tx = db.begin().await?;
    sqlx::query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        .execute(&mut *tx)
        .await?;

    let approved: Vec<(Uuid, Option<String>, String, String)> = sqlx::query_as(
        r#"SELECT id, primary_xml_snippet, package_name, version
           FROM curation_packages
           WHERE staging_repo_id = $1 AND status = 'approved'
           ORDER BY package_name ASC, version ASC"#,
    )
    .bind(repo_id)
    .fetch_all(&mut *tx)
    .await?;

    if approved.is_empty() {
        return Err(AppError::Validation(
            "Cannot create a version: no approved packages to freeze".to_string(),
        ));
    }

    // Fail closed on any approved package whose upstream snippet was never
    // retained (synced before snippet retention existed). List them so the
    // operator knows exactly what to re-sync.
    let needs_resync: Vec<String> = approved
        .iter()
        .filter(|(_, snippet, _, _)| snippet.as_deref().map(str::trim).unwrap_or("").is_empty())
        .map(|(_, _, name, version)| format!("{name}-{version}"))
        .collect();
    if !needs_resync.is_empty() {
        return Err(AppError::Validation(format!(
            "Cannot create a version: {} approved package(s) are missing their upstream \
             metadata snippet and must be re-synced first: {}",
            needs_resync.len(),
            needs_resync.join(", ")
        )));
    }

    let package_count = approved.len() as i64;

    // Allocate version N = MAX + 1 and insert atomically. INSERT…SELECT reads
    // the current max inside the same serializable transaction.
    let (version_id, version_number): (Uuid, i64) = sqlx::query_as(
        r#"INSERT INTO repository_versions
               (repository_id, version_number, created_by, package_count)
           SELECT $1, COALESCE(MAX(version_number), 0) + 1, $2, $3
           FROM repository_versions
           WHERE repository_id = $1
           RETURNING id, version_number"#,
    )
    .bind(repo_id)
    .bind(actor)
    .bind(package_count as i32)
    .fetch_one(&mut *tx)
    .await?;

    for (curation_package_id, _, _, _) in &approved {
        sqlx::query(
            r#"INSERT INTO repository_version_packages (version_id, curation_package_id)
               VALUES ($1, $2)"#,
        )
        .bind(version_id)
        .bind(curation_package_id)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    Ok(VersionSummary {
        id: version_id,
        version_number,
        package_count,
    })
}

/// Publish an already-created version: regenerate signed, immutable repodata and
/// store it under the version's `storage_prefix`, then mark the repository's
/// `active_publication_id`. Rejects re-publishing an already-published version
/// (its `@N` metadata is immutable) and a version with no members.
pub async fn publish(
    db: &PgPool,
    storage: &dyn StorageBackend,
    signing: &SigningService,
    repo_id: Uuid,
    version_number: i64,
) -> Result<PublishSummary, AppError> {
    // Resolve the version and guard immutability. Scope to repo_id so a version
    // number is only ever resolvable within its own repository.
    let row: Option<(Uuid, Option<DateTime<Utc>>)> = sqlx::query_as(
        r#"SELECT id, published_at
           FROM repository_versions
           WHERE repository_id = $1 AND version_number = $2"#,
    )
    .bind(repo_id)
    .bind(version_number)
    .fetch_optional(db)
    .await?;
    let (version_id, published_at) =
        row.ok_or_else(|| AppError::NotFound("Repository version not found".to_string()))?;
    if published_at.is_some() {
        return Err(AppError::Conflict(format!(
            "Version {version_number} is already published and its @N metadata is immutable"
        )));
    }

    let members: Vec<MemberPackage> = sqlx::query_as(
        r#"SELECT cp.primary_xml_snippet, cp.checksum_sha256, cp.package_name,
                  cp.version, cp.release, cp.architecture
           FROM repository_version_packages rvp
           JOIN curation_packages cp ON cp.id = rvp.curation_package_id
           WHERE rvp.version_id = $1
           ORDER BY cp.package_name ASC, cp.version ASC"#,
    )
    .bind(version_id)
    .fetch_all(db)
    .await?;

    if members.is_empty() {
        return Err(AppError::Validation(
            "Cannot publish a version with no packages".to_string(),
        ));
    }

    // Fail closed: never emit a package without its retained upstream snippet.
    for m in &members {
        if m.primary_xml_snippet
            .as_deref()
            .map(str::trim)
            .unwrap_or("")
            .is_empty()
        {
            return Err(AppError::Validation(format!(
                "Cannot publish: package {}-{} is missing its upstream metadata snippet; re-sync it first",
                m.package_name, m.version
            )));
        }
    }

    // 1. primary.xml — re-emit the upstream-faithful blocks verbatim.
    let snippets: Vec<&str> = members
        .iter()
        .map(|m| m.primary_xml_snippet.as_deref().unwrap_or_default())
        .collect();
    let primary_xml = assemble_primary_xml(&snippets);

    // 2. pkgid-consistent stub filelists.xml / other.xml via the hosted RPM
    //    generators. Each stub carries `pkgid="{checksum_sha256}"`, the SAME
    //    pkgid the primary snippet declares, so dnf accepts the metadata set.
    let stub_artifacts: Vec<RpmArtifact> = members.iter().map(member_to_stub_artifact).collect();
    let filelists_xml = generate_filelists_xml(&stub_artifacts);
    let other_xml = generate_other_xml(&stub_artifacts);

    // 3. repomd.xml over the three compressed payloads, then sign it.
    let repodata = build_repodata(&primary_xml, &filelists_xml, &other_xml)?;

    let signature = signing
        .sign_data(repo_id, repodata.repomd_xml.as_bytes())
        .await?
        .ok_or_else(|| {
            AppError::Validation(
                "Cannot publish: no signing key is configured for this repository".to_string(),
            )
        })?;
    let armored_asc = armor_pgp_signature(&signature);

    let public_key = signing.get_repo_public_key(repo_id).await?.ok_or_else(|| {
        AppError::Validation(
            "Cannot publish: repository signing key has no exportable public key".to_string(),
        )
    })?;

    // 4. Store every blob under an immutable, per-version prefix. The detached
    //    signature and the public key are stored AS THEY ARE NOW so a later key
    //    rotation cannot retroactively invalidate this published @N.
    let storage_prefix = format!("curation/{repo_id}/publications/{version_number}");
    let repomd_key = format!("{storage_prefix}/repodata/repomd.xml");
    let asc_key = format!("{storage_prefix}/repodata/repomd.xml.asc");
    let key_key = format!("{storage_prefix}/repodata/repomd.xml.key");

    put_blob(
        storage,
        &format!("{storage_prefix}/repodata/primary.xml.gz"),
        repodata.primary_gz,
    )
    .await?;
    put_blob(
        storage,
        &format!("{storage_prefix}/repodata/filelists.xml.gz"),
        repodata.filelists_gz,
    )
    .await?;
    put_blob(
        storage,
        &format!("{storage_prefix}/repodata/other.xml.gz"),
        repodata.other_gz,
    )
    .await?;
    put_blob(storage, &repomd_key, repodata.repomd_xml.into_bytes()).await?;
    put_blob(storage, &asc_key, armored_asc.into_bytes()).await?;
    put_blob(storage, &key_key, public_key.into_bytes()).await?;

    // 5. Mark the version published and make it the repo's active publication.
    let mut tx = db.begin().await?;
    sqlx::query(
        r#"UPDATE repository_versions
           SET published_at = now(), repomd_storage_key = $2,
               storage_prefix = $3, signature_storage_key = $4
           WHERE id = $1"#,
    )
    .bind(version_id)
    .bind(&repomd_key)
    .bind(&storage_prefix)
    .bind(&asc_key)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE repositories SET active_publication_id = $2 WHERE id = $1")
        .bind(repo_id)
        .bind(version_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(PublishSummary {
        version_number,
        package_count: members.len() as i64,
        storage_prefix,
        repomd_storage_key: repomd_key,
    })
}

// ---------------------------------------------------------------------------
// Pure helpers (unit-testable without a DB or storage backend)
// ---------------------------------------------------------------------------

/// The compressed repodata payloads plus the repomd.xml that indexes them.
struct Repodata {
    primary_gz: Vec<u8>,
    filelists_gz: Vec<u8>,
    other_gz: Vec<u8>,
    repomd_xml: String,
}

/// Wrap the retained per-package `<package type="rpm">…</package>` snippets in a
/// single `<metadata …>` document. The snippets are concatenated VERBATIM — the
/// signature is computed over the resulting repomd, and the snippet content is
/// never interpreted as markup by AK, so a snippet cannot break out of the
/// wrapper into repomd/signing structures.
fn assemble_primary_xml(snippets: &[&str]) -> String {
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata \
         xmlns=\"http://linux.duke.edu/metadata/common\" \
         xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\" packages=\"{}\">\n",
        snippets.len()
    );
    for snippet in snippets {
        xml.push_str(snippet.trim());
        xml.push('\n');
    }
    xml.push_str("</metadata>\n");
    xml
}

/// Build the minimal `RpmArtifact` the hosted stub generators consume. Only the
/// checksum (→ pkgid) and NEVRA metadata matter for the filelists/other stubs.
fn member_to_stub_artifact(m: &MemberPackage) -> RpmArtifact {
    RpmArtifact {
        id: Uuid::nil(),
        path: String::new(),
        name: m.package_name.clone(),
        version: Some(m.version.clone()),
        size_bytes: 0,
        checksum_sha256: m.checksum_sha256.clone().unwrap_or_default(),
        storage_key: String::new(),
        metadata: Some(serde_json::json!({
            "name": m.package_name,
            "version": m.version,
            "release": m.release.clone().unwrap_or_else(|| "1".to_string()),
            "arch": m.architecture.clone().unwrap_or_else(|| "noarch".to_string()),
        })),
    }
}

/// Compress the three payloads and index them in a signed-ready repomd.xml.
fn build_repodata(
    primary_xml: &str,
    filelists_xml: &str,
    other_xml: &str,
) -> Result<Repodata, AppError> {
    let timestamp = Utc::now().timestamp();

    let primary_gz = gzip_bytes(primary_xml.as_bytes());
    let filelists_gz = gzip_bytes(filelists_xml.as_bytes());
    let other_gz = gzip_bytes(other_xml.as_bytes());

    let data = vec![
        repomd_data(
            "primary",
            "repodata/primary.xml.gz",
            &primary_gz,
            primary_xml.as_bytes(),
            timestamp,
        ),
        repomd_data(
            "filelists",
            "repodata/filelists.xml.gz",
            &filelists_gz,
            filelists_xml.as_bytes(),
            timestamp,
        ),
        repomd_data(
            "other",
            "repodata/other.xml.gz",
            &other_gz,
            other_xml.as_bytes(),
            timestamp,
        ),
    ];

    let repomd_xml = generate_repomd(data)?;

    Ok(Repodata {
        primary_gz,
        filelists_gz,
        other_gz,
        repomd_xml,
    })
}

fn repomd_data(data_type: &str, href: &str, gz: &[u8], open: &[u8], timestamp: i64) -> RepoMdData {
    RepoMdData {
        data_type: data_type.to_string(),
        checksum: RepoMdChecksum {
            checksum_type: "sha256".to_string(),
            value: sha256_hex(gz),
        },
        open_checksum: Some(RepoMdChecksum {
            checksum_type: "sha256".to_string(),
            value: sha256_hex(open),
        }),
        location: RepoMdLocation {
            href: href.to_string(),
        },
        timestamp,
        size: gz.len() as u64,
        open_size: Some(open.len() as u64),
    }
}

/// Wrap a raw detached signature in PGP armor (76-char base64 lines), matching
/// the `repomd.xml.asc` armor the live RPM signing route emits.
fn armor_pgp_signature(signature: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(signature);
    let wrapped: Vec<&str> = b64
        .as_bytes()
        .chunks(76)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect();
    format!(
        "-----BEGIN PGP SIGNATURE-----\n\n{}\n-----END PGP SIGNATURE-----\n",
        wrapped.join("\n")
    )
}

async fn put_blob(storage: &dyn StorageBackend, key: &str, bytes: Vec<u8>) -> Result<(), AppError> {
    storage
        .put(key, bytes::Bytes::from(bytes))
        .await
        .map_err(|e| AppError::Storage(format!("Failed to store publication blob {key}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assemble_primary_xml_wraps_and_preserves_snippets() {
        let s1 = "<package type=\"rpm\">\n  <name>nginx</name>\n  <format><rpm:provides><rpm:entry name=\"webserver\"/></rpm:provides></format>\n</package>";
        let s2 = "<package type=\"rpm\"><name>curl</name></package>";
        let xml = assemble_primary_xml(&[s1, s2]);

        assert!(xml.contains("packages=\"2\""));
        assert!(xml.starts_with("<?xml version=\"1.0\""));
        assert!(xml.contains("xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\""));
        // Both verbatim blocks (incl. provides) survive inside the wrapper.
        assert!(xml.contains("<rpm:provides><rpm:entry name=\"webserver\"/>"));
        assert!(xml.contains("<name>curl</name>"));
        assert!(xml.trim_end().ends_with("</metadata>"));
        // Exactly one opening + one closing metadata tag (no breakout).
        assert_eq!(xml.matches("<metadata").count(), 1);
        assert_eq!(xml.matches("</metadata>").count(), 1);
    }

    // The stub filelists/other MUST carry the SAME pkgid the primary snippet
    // declares, or dnf rejects the metadata set. Here the member's
    // checksum_sha256 is the pkgid, and it must appear verbatim in both stubs.
    #[test]
    fn test_stub_generators_are_pkgid_consistent() {
        let member = MemberPackage {
            primary_xml_snippet: Some("<package type=\"rpm\"></package>".to_string()),
            checksum_sha256: Some("deadbeefcafef00d".to_string()),
            package_name: "bash".to_string(),
            version: "5.1.8".to_string(),
            release: Some("1.el9".to_string()),
            architecture: Some("x86_64".to_string()),
        };
        let stub = member_to_stub_artifact(&member);
        let filelists = generate_filelists_xml(std::slice::from_ref(&stub));
        let other = generate_other_xml(std::slice::from_ref(&stub));

        assert!(filelists.contains("pkgid=\"deadbeefcafef00d\""));
        assert!(filelists.contains("name=\"bash\""));
        assert!(filelists.contains("arch=\"x86_64\""));
        assert!(other.contains("pkgid=\"deadbeefcafef00d\""));
    }

    #[test]
    fn test_build_repodata_indexes_all_three_and_hashes_gz() {
        let primary = "<?xml version=\"1.0\"?><metadata packages=\"0\"></metadata>";
        let filelists = "<?xml version=\"1.0\"?><filelists packages=\"0\"></filelists>";
        let other = "<?xml version=\"1.0\"?><otherdata packages=\"0\"></otherdata>";
        let rd = build_repodata(primary, filelists, other).expect("repodata builds");

        for kind in ["primary", "filelists", "other"] {
            assert!(rd.repomd_xml.contains(kind), "repomd must index {kind}");
        }
        // The primary <checksum> in repomd is the sha256 of the gz we produced.
        let expected = sha256_hex(&rd.primary_gz);
        assert!(
            rd.repomd_xml.contains(&expected),
            "repomd must pin the sha256 of primary.xml.gz"
        );
        // gzip magic bytes are present on each payload.
        assert_eq!(&rd.primary_gz[..2], &[0x1f, 0x8b]);
        assert_eq!(&rd.filelists_gz[..2], &[0x1f, 0x8b]);
        assert_eq!(&rd.other_gz[..2], &[0x1f, 0x8b]);
    }

    #[test]
    fn test_armor_pgp_signature_shape() {
        let armored = armor_pgp_signature(b"a-raw-signature-blob");
        assert!(armored.starts_with("-----BEGIN PGP SIGNATURE-----\n\n"));
        assert!(armored.trim_end().ends_with("-----END PGP SIGNATURE-----"));
    }

    // -- create_version DB paths (skip silently when DATABASE_URL is unset) ----

    async fn seed_approved_pkg(
        pool: &PgPool,
        staging: Uuid,
        remote: Uuid,
        name: &str,
        snippet: Option<&str>,
    ) {
        sqlx::query(
            "INSERT INTO curation_packages \
             (staging_repo_id, remote_repo_id, format, package_name, version, release, \
              architecture, checksum_sha256, upstream_path, status, primary_xml_snippet) \
             VALUES ($1, $2, 'rpm', $3, '1.0', '1.el9', 'x86_64', 'abc123', $4, 'approved', $5)",
        )
        .bind(staging)
        .bind(remote)
        .bind(name)
        .bind(format!("Packages/{name}.rpm"))
        .bind(snippet)
        .execute(pool)
        .await
        .expect("seed approved package");
    }

    // Empty approved set -> Validation (400), never a 0-package version.
    #[tokio::test]
    async fn test_create_version_empty_is_rejected_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (staging, _sk, _sd) = tdh::create_repo(&pool, "local", "rpm").await;
        let (actor, _n) = tdh::create_user(&pool).await;
        let err = create_version(&pool, staging, actor).await.unwrap_err();
        assert!(
            matches!(err, AppError::Validation(_)),
            "empty approved set must be Validation(400): {err:?}"
        );
        tdh::cleanup(&pool, staging, actor).await;
    }

    // A NULL/blank snippet on an approved package fails closed (must re-sync).
    #[tokio::test]
    async fn test_create_version_null_snippet_fails_closed_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (staging, _sk, _sd) = tdh::create_repo(&pool, "local", "rpm").await;
        let (remote, _rk, _rd) = tdh::create_repo(&pool, "remote", "rpm").await;
        let (actor, _n) = tdh::create_user(&pool).await;
        seed_approved_pkg(&pool, staging, remote, "needs-resync", None).await;

        let err = create_version(&pool, staging, actor).await.unwrap_err();
        match err {
            AppError::Validation(msg) => assert!(
                msg.contains("re-synced") && msg.contains("needs-resync"),
                "message must name the package needing re-sync: {msg}"
            ),
            other => panic!("expected Validation, got {other:?}"),
        }
        tdh::cleanup(&pool, staging, actor).await;
        tdh::cleanup(&pool, remote, actor).await;
    }

    // Two creates allocate monotonic, distinct version numbers (1 then 2).
    #[tokio::test]
    async fn test_create_version_monotonic_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (staging, _sk, _sd) = tdh::create_repo(&pool, "local", "rpm").await;
        let (remote, _rk, _rd) = tdh::create_repo(&pool, "remote", "rpm").await;
        let (actor, _n) = tdh::create_user(&pool).await;
        seed_approved_pkg(
            &pool,
            staging,
            remote,
            "bash",
            Some("<package type=\"rpm\"><name>bash</name></package>"),
        )
        .await;

        let v1 = create_version(&pool, staging, actor).await.expect("v1");
        let v2 = create_version(&pool, staging, actor).await.expect("v2");
        assert_eq!(v1.version_number, 1);
        assert_eq!(v2.version_number, 2);
        assert_eq!(v1.package_count, 1);
        assert!(v2.version_number > v1.version_number, "monotonic");

        tdh::cleanup(&pool, staging, actor).await;
        tdh::cleanup(&pool, remote, actor).await;
    }

    // Full publish path: create a signing key + config, snapshot an approved
    // package, publish it, and assert the signed repodata blobs land in storage,
    // the version is marked published, and the repo's active publication is set.
    // Re-publishing the same version then fails closed (409/Conflict).
    #[tokio::test]
    async fn test_publish_stores_signed_repodata_and_sets_active_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::signing_service::{CreateKeyRequest, SigningService};
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (staging, _sk, dir) = tdh::create_repo(&pool, "staging", "rpm").await;
        let (remote, _rk, _rd) = tdh::create_repo(&pool, "remote", "rpm").await;
        let (actor, _n) = tdh::create_user(&pool).await;
        let snippet = "<package type=\"rpm\"><name>bash</name>\
            <checksum type=\"sha256\" pkgid=\"YES\">deadbeef</checksum></package>";
        seed_approved_pkg(&pool, staging, remote, "bash", Some(snippet)).await;

        // A signing key + metadata-signing config so sign_data() returns a sig.
        let signing = SigningService::new(pool.clone(), "test-encryption-key-2358");
        let key = signing
            .create_key(CreateKeyRequest {
                repository_id: Some(staging),
                name: "e2e-key".to_string(),
                key_type: "rsa".to_string(),
                algorithm: "rsa2048".to_string(),
                uid_name: None,
                uid_email: None,
                created_by: Some(actor),
            })
            .await
            .expect("create signing key");
        signing
            .update_signing_config(staging, Some(key.id), true, false, false)
            .await
            .expect("set signing config");

        let created = create_version(&pool, staging, actor)
            .await
            .expect("version");

        let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
        let backend: String =
            sqlx::query_scalar("SELECT storage_backend FROM repositories WHERE id = $1")
                .bind(staging)
                .fetch_one(&pool)
                .await
                .expect("repo storage backend");
        let storage = state
            .storage_for_repo(&crate::storage::StorageLocation {
                backend,
                path: dir.to_string_lossy().to_string(),
            })
            .expect("storage backend");

        let summary = publish(
            &pool,
            storage.as_ref(),
            &signing,
            staging,
            created.version_number,
        )
        .await
        .expect("publish");
        assert_eq!(summary.version_number, 1);
        assert_eq!(summary.package_count, 1);

        // Signed repodata blobs are stored and non-empty.
        for name in [
            "repodata/repomd.xml",
            "repodata/repomd.xml.asc",
            "repodata/repomd.xml.key",
            "repodata/primary.xml.gz",
            "repodata/filelists.xml.gz",
            "repodata/other.xml.gz",
        ] {
            let blob = storage
                .get(&format!("{}/{}", summary.storage_prefix, name))
                .await
                .unwrap_or_else(|e| panic!("missing published blob {name}: {e}"));
            assert!(!blob.is_empty(), "{name} must be non-empty");
        }
        // The stored primary.xml.gz re-emits the retained upstream snippet verbatim.
        let primary_gz = storage
            .get(&format!(
                "{}/repodata/primary.xml.gz",
                summary.storage_prefix
            ))
            .await
            .unwrap();
        let mut gz = flate2::read::GzDecoder::new(&primary_gz[..]);
        let mut primary = String::new();
        std::io::Read::read_to_string(&mut gz, &mut primary).unwrap();
        assert!(primary.contains("<name>bash</name>"), "snippet re-emitted");
        assert!(
            primary.contains("pkgid=\"YES\">deadbeef"),
            "pkgid preserved"
        );

        // The version is marked published and is the repo's active publication.
        let (published, active): (Option<chrono::DateTime<chrono::Utc>>, Option<Uuid>) =
            sqlx::query_as(
                "SELECT rv.published_at, r.active_publication_id \
                 FROM repository_versions rv JOIN repositories r ON r.id = rv.repository_id \
                 WHERE rv.id = $1",
            )
            .bind(created.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(published.is_some(), "published_at set");
        assert_eq!(active, Some(created.id), "active_publication_id set");

        // Re-publishing an already-published version is rejected (immutable @N).
        let republish = publish(
            &pool,
            storage.as_ref(),
            &signing,
            staging,
            created.version_number,
        )
        .await;
        assert!(
            matches!(republish, Err(AppError::Conflict(_))),
            "re-publish must be Conflict(409): {republish:?}"
        );

        tdh::cleanup(&pool, staging, actor).await;
        tdh::cleanup(&pool, remote, actor).await;
    }
}
