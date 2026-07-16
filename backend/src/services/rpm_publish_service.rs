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
//!      structured `primary_metadata` (which means it must be re-synced).
//!   2. [`publish`] CANONICALLY re-serializes `primary.xml` from each member's
//!      validated `primary_metadata` struct — every text node and attribute is
//!      escaped and every `<location>` is rebuilt from validated NEVRA, so
//!      attacker-influenced upstream content can never be signed verbatim. It
//!      then generates pkgid-consistent stub `filelists.xml`/`other.xml` via the
//!      existing hosted RPM generators, builds and SIGNS a
//!      `repomd.xml`, and stores every blob (including the detached signature and
//!      the public key *as they were at publish time*) beneath the version's
//!      `storage_prefix`. Serving `@N` then reads these frozen blobs, so a later
//!      signing-key rotation never retroactively invalidates a published `@N`.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::api::handlers::rpm::{
    generate_filelists_xml, generate_other_xml, gzip_bytes, sha256_hex, xml_escape, RpmArtifact,
};
use crate::error::AppError;
use crate::formats::rpm::{generate_repomd, RepoMdChecksum, RepoMdData, RepoMdLocation};
use crate::services::curation_sync::{RpmEntry, RpmPackageMetadata};
use crate::services::signing_service::SigningService;
use crate::storage::StorageBackend;

/// Hard ceiling on the number of packages a single publication may serialize
/// (#2358 A-hardened): bounds the work + output of one publish so a hostile or
/// huge approved set cannot exhaust memory.
const MAX_PUBLICATION_PACKAGES: usize = 100_000;

/// Hard ceiling on the serialized `primary.xml` buffer (#2358 A-hardened):
/// canonical serialization fails closed rather than growing an unbounded String.
const MAX_PRIMARY_XML_BYTES: usize = 512 * 1024 * 1024;

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
    /// The STRUCTURED, validated primary.xml metadata (JSONB). `NULL`/absent
    /// means the row predates structured capture (or was dropped fail-closed at
    /// sync) and must be re-synced before a publish can include it.
    primary_metadata: Option<serde_json::Value>,
    package_name: String,
    version: String,
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

    let approved: Vec<(Uuid, Option<serde_json::Value>, String, String)> = sqlx::query_as(
        r#"SELECT id, primary_metadata, package_name, version
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

    // Fail closed on any approved package whose structured metadata was never
    // captured (synced before structured capture, or dropped fail-closed at
    // sync). List them so the operator knows exactly what to re-sync.
    let needs_resync: Vec<String> = approved
        .iter()
        .filter(|(_, meta, _, _)| meta.as_ref().map(|v| v.is_null()).unwrap_or(true))
        .map(|(_, _, name, version)| format!("{name}-{version}"))
        .collect();
    if !needs_resync.is_empty() {
        return Err(AppError::Validation(format!(
            "Cannot create a version: {} approved package(s) are missing their structured \
             upstream metadata and must be re-synced first: {}",
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
        r#"SELECT cp.primary_metadata, cp.package_name, cp.version
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

    // Cap: bound the per-publication package count so a hostile/huge approved
    // set cannot exhaust memory during serialization.
    if members.len() > MAX_PUBLICATION_PACKAGES {
        return Err(AppError::Validation(format!(
            "Cannot publish: {} packages exceeds the per-publication limit of {}",
            members.len(),
            MAX_PUBLICATION_PACKAGES
        )));
    }

    // Fail closed: deserialize each member's STRUCTURED metadata. A package
    // whose metadata is missing or does not parse cleanly is never published.
    let mut metas: Vec<RpmPackageMetadata> = Vec::with_capacity(members.len());
    for m in &members {
        let raw = m
            .primary_metadata
            .as_ref()
            .filter(|v| !v.is_null())
            .ok_or_else(|| {
                AppError::Validation(format!(
                    "Cannot publish: package {}-{} is missing its structured upstream \
                     metadata; re-sync it first",
                    m.package_name, m.version
                ))
            })?;
        let meta: RpmPackageMetadata = serde_json::from_value(raw.clone()).map_err(|_| {
            AppError::Validation(format!(
                "Cannot publish: package {}-{} has unreadable structured metadata; \
                 re-sync it first",
                m.package_name, m.version
            ))
        })?;
        metas.push(meta);
    }

    // 1. primary.xml — CANONICALLY re-serialized from the validated structs.
    //    Every text node + attribute is escaped and every `<location>` is
    //    rebuilt from validated NEVRA, so attacker-influenced upstream content
    //    can never break out of the wrapper or inject markup into the signed
    //    document.
    let primary_xml = assemble_primary_xml(&metas)?;

    // 2. pkgid-consistent stub filelists.xml / other.xml via the hosted RPM
    //    generators. Each stub carries the SAME AK-derived pkgid the primary
    //    declares (from the structured, byte-verified checksum), so dnf accepts
    //    the metadata set.
    let stub_artifacts: Vec<RpmArtifact> = metas.iter().map(meta_to_stub_artifact).collect();
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

/// Build the AK `<location href>` for a member purely from validated NEVRA.
///
/// The result is always a RELATIVE `packages/{name}-{version}-{release}.{arch}.rpm`
/// path that resolves under `/rpm/{key}/@N/`. It is NEVER sourced from the
/// upstream `<location>`, so an attacker cannot smuggle an absolute URL
/// (`https://evil/…`) or a traversal (`..`) into the signed document — those are
/// impossible by construction.
fn member_location(meta: &RpmPackageMetadata) -> String {
    format!(
        "packages/{}-{}-{}.{}.rpm",
        meta.name, meta.version, meta.release, meta.arch
    )
}

/// Canonically re-serialize the validated member structs into a single
/// `<metadata …>` document (#2358 A-hardened).
///
/// Every text node and attribute value is passed through [`xml_escape`], and
/// every `<location>` is rebuilt from validated NEVRA via [`member_location`].
/// Structurally there is therefore exactly one `<metadata>`/`</metadata>` pair,
/// no attacker markup survives un-escaped, and the pkgid is AK-derived from the
/// structured (byte-verified) checksum. Fails closed if the buffer would exceed
/// [`MAX_PRIMARY_XML_BYTES`].
fn assemble_primary_xml(metas: &[RpmPackageMetadata]) -> Result<String, AppError> {
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<metadata \
         xmlns=\"http://linux.duke.edu/metadata/common\" \
         xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\" packages=\"{}\">\n",
        metas.len()
    );

    for meta in metas {
        push_package_xml(&mut xml, meta);
        if xml.len() > MAX_PRIMARY_XML_BYTES {
            return Err(AppError::Validation(
                "Cannot publish: primary.xml exceeds the maximum serialized size".to_string(),
            ));
        }
    }
    xml.push_str("</metadata>\n");
    Ok(xml)
}

/// Serialize one `<package type="rpm">` element from a validated struct, with
/// every text node and attribute value escaped.
fn push_package_xml(xml: &mut String, meta: &RpmPackageMetadata) {
    xml.push_str("  <package type=\"rpm\">\n");
    xml.push_str(&format!("    <name>{}</name>\n", xml_escape(&meta.name)));
    xml.push_str(&format!("    <arch>{}</arch>\n", xml_escape(&meta.arch)));
    xml.push_str(&format!(
        "    <version epoch=\"{}\" ver=\"{}\" rel=\"{}\"/>\n",
        xml_escape(&meta.epoch),
        xml_escape(&meta.version),
        xml_escape(&meta.release),
    ));
    // pkgid is AK-derived from the structured, byte-verified checksum.
    xml.push_str(&format!(
        "    <checksum type=\"{}\" pkgid=\"{}\">{}</checksum>\n",
        xml_escape(&meta.checksum.checksum_type),
        if meta.checksum.pkgid { "YES" } else { "NO" },
        xml_escape(&meta.checksum.value),
    ));
    xml.push_str(&format!(
        "    <summary>{}</summary>\n",
        xml_escape(&meta.summary)
    ));
    xml.push_str(&format!(
        "    <description>{}</description>\n",
        xml_escape(&meta.description)
    ));
    if let Some(v) = &meta.packager {
        xml.push_str(&format!("    <packager>{}</packager>\n", xml_escape(v)));
    }
    if let Some(v) = &meta.url {
        xml.push_str(&format!("    <url>{}</url>\n", xml_escape(v)));
    }
    xml.push_str(&format!(
        "    <time file=\"{}\" build=\"{}\"/>\n",
        meta.time.file, meta.time.build
    ));
    xml.push_str(&format!(
        "    <size package=\"{}\" installed=\"{}\" archive=\"{}\"/>\n",
        meta.size.package, meta.size.installed, meta.size.archive
    ));
    // The location is rebuilt from validated NEVRA — never from upstream.
    xml.push_str(&format!(
        "    <location href=\"{}\"/>\n",
        xml_escape(&member_location(meta))
    ));
    push_format_xml(xml, meta);
    xml.push_str("  </package>\n");
}

fn push_format_xml(xml: &mut String, meta: &RpmPackageMetadata) {
    let f = &meta.format;
    xml.push_str("    <format>\n");
    if let Some(v) = &f.license {
        xml.push_str(&format!(
            "      <rpm:license>{}</rpm:license>\n",
            xml_escape(v)
        ));
    }
    if let Some(v) = &f.vendor {
        xml.push_str(&format!(
            "      <rpm:vendor>{}</rpm:vendor>\n",
            xml_escape(v)
        ));
    }
    if let Some(v) = &f.group {
        xml.push_str(&format!("      <rpm:group>{}</rpm:group>\n", xml_escape(v)));
    }
    if let Some(v) = &f.buildhost {
        xml.push_str(&format!(
            "      <rpm:buildhost>{}</rpm:buildhost>\n",
            xml_escape(v)
        ));
    }
    if let Some(v) = &f.sourcerpm {
        xml.push_str(&format!(
            "      <rpm:sourcerpm>{}</rpm:sourcerpm>\n",
            xml_escape(v)
        ));
    }
    if let Some((start, end)) = f.header_range {
        xml.push_str(&format!(
            "      <rpm:header-range start=\"{start}\" end=\"{end}\"/>\n"
        ));
    }
    push_entry_list(xml, "rpm:provides", &f.provides);
    push_entry_list(xml, "rpm:requires", &f.requires);
    push_entry_list(xml, "rpm:conflicts", &f.conflicts);
    push_entry_list(xml, "rpm:obsoletes", &f.obsoletes);
    push_entry_list(xml, "rpm:recommends", &f.recommends);
    push_entry_list(xml, "rpm:suggests", &f.suggests);
    push_entry_list(xml, "rpm:supplements", &f.supplements);
    push_entry_list(xml, "rpm:enhances", &f.enhances);
    for file in &f.files {
        match &file.kind {
            Some(k) => xml.push_str(&format!(
                "      <file type=\"{}\">{}</file>\n",
                xml_escape(k),
                xml_escape(&file.path)
            )),
            None => xml.push_str(&format!("      <file>{}</file>\n", xml_escape(&file.path))),
        }
    }
    xml.push_str("    </format>\n");
}

fn push_entry_list(xml: &mut String, tag: &str, entries: &[RpmEntry]) {
    if entries.is_empty() {
        return;
    }
    xml.push_str(&format!("      <{tag}>\n"));
    for e in entries {
        xml.push_str(&format!(
            "        <rpm:entry name=\"{}\"",
            xml_escape(&e.name)
        ));
        if let Some(v) = &e.flags {
            xml.push_str(&format!(" flags=\"{}\"", xml_escape(v)));
        }
        if let Some(v) = &e.epoch {
            xml.push_str(&format!(" epoch=\"{}\"", xml_escape(v)));
        }
        if let Some(v) = &e.ver {
            xml.push_str(&format!(" ver=\"{}\"", xml_escape(v)));
        }
        if let Some(v) = &e.rel {
            xml.push_str(&format!(" rel=\"{}\"", xml_escape(v)));
        }
        if let Some(v) = &e.pre {
            xml.push_str(&format!(" pre=\"{}\"", xml_escape(v)));
        }
        xml.push_str("/>\n");
    }
    xml.push_str(&format!("      </{tag}>\n"));
}

/// Build the minimal `RpmArtifact` the hosted stub generators consume. The pkgid
/// is sourced from the structured, byte-verified checksum so it is consistent
/// with the primary.xml the same publish emits.
fn meta_to_stub_artifact(meta: &RpmPackageMetadata) -> RpmArtifact {
    RpmArtifact {
        id: Uuid::nil(),
        path: String::new(),
        name: meta.name.clone(),
        version: Some(meta.version.clone()),
        size_bytes: 0,
        checksum_sha256: meta.checksum.value.clone(),
        storage_key: String::new(),
        metadata: Some(serde_json::json!({
            "name": meta.name,
            "version": meta.version,
            "release": meta.release,
            "arch": meta.arch,
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
    use crate::services::curation_sync::{RpmChecksum, RpmFormat, RpmSize, RpmTime};

    fn meta(name: &str, checksum: &str) -> RpmPackageMetadata {
        RpmPackageMetadata {
            name: name.to_string(),
            arch: "x86_64".to_string(),
            epoch: "0".to_string(),
            version: "1.0".to_string(),
            release: "1.el9".to_string(),
            summary: String::new(),
            description: String::new(),
            packager: None,
            url: None,
            checksum: RpmChecksum {
                checksum_type: "sha256".to_string(),
                pkgid: true,
                value: checksum.to_string(),
            },
            size: RpmSize::default(),
            time: RpmTime::default(),
            format: RpmFormat::default(),
        }
    }

    // The canonical serializer over structs carrying attacker strings in
    // name/summary/provides must emit EXACTLY ONE metadata pair, NONE of the raw
    // attacker markup, and every `<location>` a relative AK `packages/…` path.
    #[test]
    fn test_assemble_primary_xml_is_canonical_and_escapes_attacker_markup() {
        let mut evil = meta("nginx", "abc123");
        // Attacker strings smuggled into structured fields.
        evil.name = "nginx</metadata><package type=\"rpm\">".to_string();
        evil.summary = "pwn </metadata> & <script>".to_string();
        evil.format.provides = vec![RpmEntry {
            name: "systemd".to_string(),
            flags: Some("EQ".to_string()),
            epoch: Some("99".to_string()),
            ver: Some("999\"/></rpm:provides></metadata>".to_string()),
            rel: None,
            pre: None,
        }];
        let clean = meta("curl", "def456");

        let xml = assemble_primary_xml(&[evil, clean]).expect("serialize");

        assert!(xml.contains("packages=\"2\""));
        assert!(xml.starts_with("<?xml version=\"1.0\""));
        // Structurally exactly one metadata pair — the breakout is neutralized.
        assert_eq!(xml.matches("<metadata").count(), 1);
        assert_eq!(xml.matches("</metadata>").count(), 1);
        // The RAW attacker markup never appears un-escaped.
        assert!(!xml.contains("nginx</metadata>"));
        assert!(!xml.contains("<script>"));
        assert!(!xml.contains("</rpm:provides></metadata>"));
        // It survives only as ESCAPED text.
        assert!(xml.contains("&lt;/metadata&gt;"));
        // Every location is a relative AK packages/ path built from NEVRA.
        let locations: Vec<&str> = xml.lines().filter(|l| l.contains("<location")).collect();
        assert_eq!(locations.len(), 2);
        for line in locations {
            assert!(
                line.contains("href=\"packages/"),
                "location must be a relative AK packages/ path: {line}"
            );
            assert!(!line.contains("://"), "no absolute URL in location: {line}");
        }
    }

    // The stub filelists/other MUST carry the SAME AK-derived pkgid the primary
    // declares (the structured, byte-verified checksum), or dnf rejects the set.
    #[test]
    fn test_stub_generators_are_pkgid_consistent() {
        let m = meta("bash", "deadbeefcafef00d");
        let stub = meta_to_stub_artifact(&m);
        let filelists = generate_filelists_xml(std::slice::from_ref(&stub));
        let other = generate_other_xml(std::slice::from_ref(&stub));

        assert_eq!(stub.checksum_sha256, "deadbeefcafef00d");
        assert!(filelists.contains("pkgid=\"deadbeefcafef00d\""));
        assert!(filelists.contains("name=\"bash\""));
        assert!(filelists.contains("arch=\"x86_64\""));
        assert!(other.contains("pkgid=\"deadbeefcafef00d\""));
    }

    // The location for a member is built PURELY from validated NEVRA.
    #[test]
    fn test_member_location_is_nevra_relative() {
        assert_eq!(
            member_location(&meta("nginx", "abc")),
            "packages/nginx-1.0-1.el9.x86_64.rpm"
        );
    }

    // A full realistic member round-trips provides/requires/size/format/files
    // through the canonical serializer, so dnf can still depsolve + install.
    #[test]
    fn test_assemble_primary_xml_round_trips_depsolve_fields() {
        let mut m = meta("nginx", "abc123");
        m.summary = "web server".to_string();
        m.size = RpmSize {
            package: 573440,
            installed: 1048576,
            archive: 1050624,
        };
        m.format.license = Some("BSD".to_string());
        m.format.header_range = Some((4504, 98765));
        m.format.provides = vec![RpmEntry {
            name: "webserver".to_string(),
            ..Default::default()
        }];
        m.format.requires = vec![RpmEntry {
            name: "openssl-libs".to_string(),
            flags: Some("GE".to_string()),
            epoch: Some("0".to_string()),
            ver: Some("3.0".to_string()),
            ..Default::default()
        }];
        m.format.files = vec![crate::services::curation_sync::RpmFileEntry {
            path: "/usr/sbin/nginx".to_string(),
            kind: None,
        }];

        let xml = assemble_primary_xml(std::slice::from_ref(&m)).expect("serialize");
        assert!(
            xml.contains("<size package=\"573440\" installed=\"1048576\" archive=\"1050624\"/>")
        );
        assert!(xml.contains("<rpm:license>BSD</rpm:license>"));
        assert!(xml.contains("<rpm:header-range start=\"4504\" end=\"98765\"/>"));
        assert!(xml.contains("<rpm:entry name=\"webserver\"/>"));
        assert!(
            xml.contains("<rpm:entry name=\"openssl-libs\" flags=\"GE\" epoch=\"0\" ver=\"3.0\"/>")
        );
        assert!(xml.contains("<file>/usr/sbin/nginx</file>"));
        assert!(xml.contains("<version epoch=\"0\" ver=\"1.0\" rel=\"1.el9\"/>"));
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

    /// A realistic structured metadata JSON for `name`, matching what the
    /// A-hardened sync captures.
    fn sample_meta_json(name: &str) -> serde_json::Value {
        serde_json::to_value(meta(name, "abc123")).unwrap()
    }

    async fn seed_approved_pkg(
        pool: &PgPool,
        staging: Uuid,
        remote: Uuid,
        name: &str,
        primary_metadata: Option<serde_json::Value>,
    ) {
        sqlx::query(
            "INSERT INTO curation_packages \
             (staging_repo_id, remote_repo_id, format, package_name, version, release, \
              architecture, checksum_sha256, upstream_path, status, primary_metadata) \
             VALUES ($1, $2, 'rpm', $3, '1.0', '1.el9', 'x86_64', 'abc123', $4, 'approved', $5)",
        )
        .bind(staging)
        .bind(remote)
        .bind(name)
        .bind(format!("Packages/{name}.rpm"))
        .bind(primary_metadata)
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

    // NULL structured metadata on an approved package fails closed (must re-sync).
    #[tokio::test]
    async fn test_create_version_null_metadata_fails_closed_db() {
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
            Some(sample_meta_json("bash")),
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
        seed_approved_pkg(
            &pool,
            staging,
            remote,
            "bash",
            Some(sample_meta_json("bash")),
        )
        .await;

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
        // The stored primary.xml.gz is the canonical AK re-serialization.
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
        // Canonical re-serialization: the package is emitted from the struct.
        assert!(primary.contains("<name>bash</name>"), "package re-emitted");
        // pkgid is AK-derived from the structured (byte-verified) checksum.
        assert!(
            primary.contains("pkgid=\"YES\">abc123"),
            "AK-derived pkgid present"
        );
        // The location is a relative AK packages/ path built from NEVRA.
        assert!(
            primary.contains("href=\"packages/bash-1.0-1.el9.x86_64.rpm\""),
            "canonical AK location: {primary}"
        );
        // Exactly one metadata pair.
        assert_eq!(primary.matches("</metadata>").count(), 1);

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
