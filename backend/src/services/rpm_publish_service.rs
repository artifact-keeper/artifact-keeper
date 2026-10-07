//! Curated RPM snapshot publish (#2358 — RPM curation Phase-3).
//!
//! Freezes the *approved* subset of a curation repo's synced packages into a
//! monotonic, immutable `repository_version`, then publishes it as signed,
//! AK-generated repodata that is served under `/rpm/{key}/@N/`.
//!
//! Two steps:
//!   1. [`create_version`] snapshots `curation_packages WHERE status = 'approved'`
//!      into a new `repository_versions` row (version N = MAX + 1, allocated
//!      under a per-repository advisory lock so the number is monotonic under
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
    generate_filelists_xml, generate_other_xml, gzip_bytes, push_rpm_entry_list, sha256_hex,
    xml_escape, RpmArtifact,
};
use crate::error::AppError;
use crate::formats::rpm::{generate_repomd, RepoMdChecksum, RepoMdData, RepoMdLocation};
use crate::services::cluster_lock::{lease_object_id, ClusterLease, ClusterLock, PgAdvisoryLock};
use crate::services::curation_sync::RpmPackageMetadata;
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
    /// The identity FROZEN into the snapshot at create time. The signed
    /// `primary.xml` must attest exactly these, or the publish fails closed.
    frozen_checksum_sha256: String,
    frozen_filename: String,
}

/// How many times a transient concurrency abort re-runs [`create_version`].
///
/// Concurrent creates for one repository are serialized by an advisory lock
/// (see [`create_version_once`]), so a conflict is no longer the expected
/// outcome of a race; the retry is the backstop for a deadlock or a
/// unique-violation that slips past the lock (#4307).
const CREATE_VERSION_MAX_ATTEMPTS: u32 = 5;

/// Sleep before retry number `attempt` (1-based) of [`create_version`]: the
/// original linear `20 ms * attempt` floor plus up to the same again of random
/// jitter (`jitter_fraction` in `[0, 1]`). Without the jitter two racers
/// started together sleep identical durations, wake together, and can collide
/// again on every attempt until the budget runs out (#4307).
fn create_version_retry_backoff(attempt: u32, jitter_fraction: f64) -> std::time::Duration {
    let base_ms = 20 * u64::from(attempt);
    let jitter_ms = (base_ms as f64 * jitter_fraction.clamp(0.0, 1.0)).round() as u64;
    std::time::Duration::from_millis(base_ms + jitter_ms)
}

/// Advisory-lock key text serializing [`create_version`] per repository.
/// Hashed server-side with `hashtextextended(…, 0)`; the `rpm-version:`
/// namespace keeps it apart from the other text-keyed advisory locks.
pub(crate) fn create_version_lock_key(repo_id: Uuid) -> String {
    format!("rpm-version:{repo_id}")
}

/// Whether a failed snapshot attempt is a transient concurrency abort that is
/// safe to retry: a serialization failure (`40001`), a deadlock (`40P01`), or a
/// unique-violation (`23505`) from two racers colliding on the same
/// `(repository_id, version_number)` — the constraint backstop. `create_version`
/// commits atomically, so a retry never double-inserts.
fn is_retryable_snapshot_conflict(err: &AppError) -> bool {
    let AppError::Sqlx(sqlx::Error::Database(db_err)) = err else {
        return false;
    };
    matches!(db_err.code().as_deref(), Some("40001" | "40P01" | "23505"))
}

/// Snapshot the *approved* curation set of `repo_id` into a new monotonic
/// version. Fails closed (400) when there is nothing approved to freeze, and
/// (400) when any approved package is missing its retained upstream metadata
/// snippet — those rows predate snippet retention and must be re-synced before
/// a publish can include them (never emit a package without its snippet).
///
/// Transient serialization conflicts are retried (see
/// [`CREATE_VERSION_MAX_ATTEMPTS`]); every other error propagates unchanged.
pub async fn create_version(
    db: &PgPool,
    repo_id: Uuid,
    actor: Uuid,
) -> Result<VersionSummary, AppError> {
    crate::services::rpm_layout::reject_unsupported(db, repo_id).await?;
    let mut attempt = 0;
    loop {
        attempt += 1;
        match create_version_once(db, repo_id, actor).await {
            Ok(summary) => return Ok(summary),
            Err(err)
                if attempt < CREATE_VERSION_MAX_ATTEMPTS
                    && is_retryable_snapshot_conflict(&err) =>
            {
                // Brief, growing, jittered backoff so racers do not re-collide
                // in lockstep.
                let jitter: f64 = rand::random();
                tokio::time::sleep(create_version_retry_backoff(attempt, jitter)).await;
                tracing::debug!(
                    repo_id = %repo_id,
                    attempt,
                    "curated snapshot hit a serialization conflict; retrying"
                );
            }
            Err(err) => return Err(err),
        }
    }
}

/// One snapshot attempt. See [`create_version`] for the retry contract.
async fn create_version_once(
    db: &PgPool,
    repo_id: Uuid,
    actor: Uuid,
) -> Result<VersionSummary, AppError> {
    // Concurrent creates for the same repository are serialized by a
    // transaction-scoped advisory lock taken before any read (#4307).
    //
    // The transaction runs at READ COMMITTED, deliberately not SERIALIZABLE:
    // a serializable transaction takes its snapshot at its first statement,
    // which here is the lock wait itself, so a waiter would still read the
    // pre-winner MAX(version_number) after the winner committed and abort
    // with 40001 — exactly the failure this lock exists to remove. Under READ
    // COMMITTED every statement after the lock sees the winner's commit, so
    // the MAX+1 allocation below is correct, and the UNIQUE(repository_id,
    // version_number) constraint remains the hard backstop (a 23505 is
    // retried by `create_version`). The approved-set read is one statement,
    // so it is internally consistent without a transaction-wide snapshot.
    let mut tx = db.begin().await?;
    // Explicit, so a server whose `default_transaction_isolation` is raised
    // cannot silently reintroduce the stale-snapshot conflict.
    sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(create_version_lock_key(repo_id))
        .execute(&mut *tx)
        .await?;

    let approved: Vec<(Uuid, Option<serde_json::Value>, String, String, String)> = sqlx::query_as(
        r#"SELECT id, primary_metadata, package_name, version, upstream_path
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
        .filter(|(_, meta, _, _, _)| meta.as_ref().map(|v| v.is_null()).unwrap_or(true))
        .map(|(_, _, name, version, _)| format!("{name}-{version}"))
        .collect();
    if !needs_resync.is_empty() {
        return Err(AppError::Validation(format!(
            "Cannot create a version: {} approved package(s) are missing their structured \
             upstream metadata and must be re-synced first: {}",
            needs_resync.len(),
            needs_resync.join(", ")
        )));
    }

    // FREEZE the package identity now, derived from the SAME structured metadata
    // the signed `primary.xml` is generated from. `curation_packages` is a live
    // table (a re-sync upserts the same row), so anything the `@N` serve path
    // reads back from it could be changed after publish — which would let an
    // immutable, signed snapshot serve bytes contradicting its own signed
    // metadata. The checksum frozen here is exactly the one the signed
    // `primary.xml` attests, and the filename is exactly its `<location href>`.
    let mut frozen: Vec<(Uuid, String, String, String)> = Vec::with_capacity(approved.len());
    for (id, meta_json, name, version, upstream_path) in &approved {
        let raw = meta_json.as_ref().filter(|v| !v.is_null()).ok_or_else(|| {
            AppError::Validation(format!(
                "Cannot create a version: package {name}-{version} is missing its structured \
                 upstream metadata; re-sync it first"
            ))
        })?;
        let meta: RpmPackageMetadata = serde_json::from_value(raw.clone()).map_err(|_| {
            AppError::Validation(format!(
                "Cannot create a version: package {name}-{version} has unreadable structured \
                 metadata; re-sync it first"
            ))
        })?;
        if meta.checksum.value.trim().is_empty() {
            return Err(AppError::Validation(format!(
                "Cannot create a version: package {name}-{version} has no checksum in its \
                 structured metadata; re-sync it first"
            )));
        }
        frozen.push((
            *id,
            meta.checksum.value.trim().to_string(),
            upstream_path.clone(),
            member_filename(&meta),
        ));
    }

    let package_count = approved.len() as i64;

    // Allocate version N = MAX + 1 and insert in one statement. The advisory
    // lock above guarantees no other create for this repository is between
    // its MAX read and its commit while this statement runs.
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

    for (curation_package_id, checksum, upstream_path, filename) in &frozen {
        sqlx::query(
            r#"INSERT INTO repository_version_packages
                   (version_id, curation_package_id, frozen_checksum_sha256,
                    frozen_upstream_path, frozen_filename)
               VALUES ($1, $2, $3, $4, $5)"#,
        )
        .bind(version_id)
        .bind(curation_package_id)
        .bind(checksum)
        .bind(upstream_path)
        .bind(filename)
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
    // Serialise publishes of this version (#4421). Without it, two concurrent
    // calls both pass the `published_at` check below and write the same
    // repodata keys, so repomd.xml and repomd.xml.asc can come from different
    // writers. The loser fails fast with 409 instead of overwriting the
    // winner's blobs. Held until this publish has marked the version; the
    // immutability check runs under it, so a publish that starts after the
    // winner finished sees `published_at` set. Any early return drops the
    // lease, which releases the lock.
    let publish_lock = acquire_publish_lock(db, repo_id, version_number).await?;

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
        r#"SELECT cp.primary_metadata, cp.package_name, cp.version,
                  rvp.frozen_checksum_sha256, rvp.frozen_filename
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
        // The signed document MUST attest exactly the identity frozen into the
        // snapshot. `curation_packages` is live, so a re-sync between the
        // snapshot and this publish could otherwise sign a checksum/filename the
        // frozen membership does not carry — and the `@N` serve path (which
        // trusts the FROZEN columns) would then reject every download. Fail
        // closed and tell the operator to cut a fresh version instead.
        if meta.checksum.value.trim() != m.frozen_checksum_sha256.trim()
            || member_filename(&meta) != m.frozen_filename
        {
            return Err(AppError::Conflict(format!(
                "Cannot publish: package {}-{} changed since the version was created \
                 (its upstream metadata was re-synced). Create a new version to publish \
                 the updated package.",
                m.package_name, m.version
            )));
        }
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

    // Sign repomd.xml with a REAL detached OpenPGP signature — the only form
    // `dnf` (repo_gpgcheck=1) / `rpm --import` can verify. `sign_data()` returns
    // raw PKCS#1 v1.5 bytes with no OpenPGP packet framing or CRC24 armor
    // checksum; hand-wrapping those in "BEGIN PGP SIGNATURE" markers is exactly
    // the theater #2636 removed from the live repomd path — every real client
    // rejects it. Fail closed if the repo has no active key, or its active key
    // cannot produce OpenPGP (requires `key_type='gpg'`), so a published @N
    // never carries an unverifiable signature.
    let key = signing
        .get_active_key_for_repo(repo_id)
        .await?
        .ok_or_else(|| {
            AppError::Validation(
                "Cannot publish: no signing key is configured for this repository".to_string(),
            )
        })?;
    if key.key_type != "gpg" {
        return Err(AppError::Validation(
            "Cannot publish: the repository's active signing key cannot produce an OpenPGP \
             signature (requires key_type='gpg')"
                .to_string(),
        ));
    }
    // NOTE (#1327): this signature is stored immutably below and is never
    // regenerated, so the `SigningService` handed to this function must NOT
    // have `with_signature_expiry` applied. A published `@N` has to keep
    // verifying for as long as it is served; an expiration subpacket here
    // would silently break mirror validation of an already-published snapshot
    // once the window elapsed. Expiry belongs only on the metadata the
    // registry re-signs on demand (Debian InRelease/Release.gpg, live
    // repomd.xml.asc).
    let armored_asc = signing
        .sign_openpgp_detached_with_key(&key, repodata.repomd_xml.as_bytes())
        .await?;
    let _ = signing.mark_key_used(key.id).await;

    let public_key = signing.get_repo_public_key(repo_id).await?.ok_or_else(|| {
        AppError::Validation(
            "Cannot publish: repository signing key has no exportable public key".to_string(),
        )
    })?;

    // 4. Store every blob under an immutable, per-version prefix. The detached
    //    signature and the public key are stored AS THEY ARE NOW so a later key
    //    rotation cannot retroactively invalidate this published @N.
    let storage_prefix = publication_prefix(repo_id, version_number);
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
    mark_published(
        db,
        storage,
        repo_id,
        version_id,
        version_number,
        &storage_prefix,
    )
    .await?;
    // The version is published; releasing the lock is best effort and can
    // never turn this success into an error (`release` logs its own failures,
    // and the lock dies with its detached connection regardless).
    publish_lock.release().await;

    Ok(PublishSummary {
        version_number,
        package_count: members.len() as i64,
        storage_prefix,
        repomd_storage_key: repomd_key,
    })
}

/// Advisory-lock class (`classid`) for RPM curation publishes (#4421).
const RPM_PUBLISH_LOCK_CLASS: i32 = 0x4421;

/// Take the per-version publish lock (#4421): a session advisory lock on
/// `(RPM_PUBLISH_LOCK_CLASS, hash(repo_id, version_number))`, held on a
/// DETACHED connection ([`PgAdvisoryLock`]). Detached means it is not an idle
/// open transaction (so `idle_in_transaction_session_timeout` cannot kill it
/// mid-publish) and it does not hold a pooled connection while the publish
/// itself runs its queries on `db`; the lock is released when the lease is
/// released or dropped, or when that connection dies. A second concurrent
/// publish of the same version gets 409 rather than waiting and then
/// rewriting the winner's immutable repodata. A 32-bit hash collision between
/// two versions can only cause a spurious 409, never a missed one.
///
/// [`PgAdvisoryLock`]: crate::services::cluster_lock::PgAdvisoryLock
async fn acquire_publish_lock(
    db: &PgPool,
    repo_id: Uuid,
    version_number: i64,
) -> Result<ClusterLease, AppError> {
    let object = lease_object_id(&publish_lock_key(repo_id, version_number));
    PgAdvisoryLock::new(db.clone())
        .try_acquire(RPM_PUBLISH_LOCK_CLASS, object)
        .await?
        .ok_or_else(|| publish_in_progress(version_number))
}

/// Advisory-lock key text for publishing `version_number` of `repo_id`.
fn publish_lock_key(repo_id: Uuid, version_number: i64) -> String {
    format!("rpm-publish:{repo_id}:{version_number}")
}

/// 409 for a publish that lost the race to a concurrent one (#4421).
fn publish_in_progress(version_number: i64) -> AppError {
    AppError::Conflict(format!(
        "Version {version_number} is already being published by another request"
    ))
}

/// Mark `version_id` published under `storage_prefix` and make it the
/// repository's active publication.
///
/// The UPDATE only matches an unpublished version (`published_at IS NULL`,
/// #4421), so a version is marked published exactly once. When the version
/// exists but is already published, this returns 409 WITHOUT touching
/// storage: the blobs under the prefix are the winner's.
///
/// The repository row is locked FIRST, in the same order the version retention
/// pass takes its locks (#2359), so the two cannot deadlock. If retention
/// pruned this version while its blobs were being written, the UPDATE matches
/// no row (version retention, or the repository being deleted, removed it):
/// remove the repodata just stored and fail with 409, rather than leave
/// an unreachable prefix behind or point `active_publication_id` at a deleted
/// version.
async fn mark_published(
    db: &PgPool,
    storage: &dyn StorageBackend,
    repo_id: Uuid,
    version_id: Uuid,
    version_number: i64,
    storage_prefix: &str,
) -> Result<(), AppError> {
    let repomd_key = format!("{storage_prefix}/repodata/repomd.xml");
    let asc_key = format!("{storage_prefix}/repodata/repomd.xml.asc");
    let mut tx = db.begin().await?;
    sqlx::query("SELECT 1 FROM repositories WHERE id = $1 FOR NO KEY UPDATE")
        .bind(repo_id)
        .execute(&mut *tx)
        .await?;
    let marked = sqlx::query(
        r#"UPDATE repository_versions
           SET published_at = now(), repomd_storage_key = $2,
               storage_prefix = $3, signature_storage_key = $4
           WHERE id = $1 AND published_at IS NULL"#,
    )
    .bind(version_id)
    .bind(&repomd_key)
    .bind(storage_prefix)
    .bind(&asc_key)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if marked == 0 {
        let still_exists: Option<i32> =
            sqlx::query_scalar("SELECT 1 FROM repository_versions WHERE id = $1")
                .bind(version_id)
                .fetch_optional(&mut *tx)
                .await?;
        drop(tx);
        if still_exists.is_some() {
            return Err(AppError::Conflict(format!(
                "Version {version_number} is already published and its @N metadata is immutable"
            )));
        }
        for name in PUBLICATION_REPODATA_FILES {
            let _ = storage.delete(&format!("{storage_prefix}/{name}")).await;
        }
        return Err(AppError::Conflict(format!(
            "Version {version_number} no longer exists (it was removed, for example by version \
             retention, while it was being published)"
        )));
    }
    sqlx::query("UPDATE repositories SET active_publication_id = $2 WHERE id = $1")
        .bind(repo_id)
        .bind(version_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Pure helpers (unit-testable without a DB or storage backend)
// ---------------------------------------------------------------------------

/// The storage prefix every blob of published version `version_number` of
/// `repo_id` lives under: its signed repodata (see
/// [`PUBLICATION_REPODATA_FILES`]) and the verified packages the `@N` serve
/// path caches at `packages/{frozen_filename}`.
pub(crate) fn publication_prefix(repo_id: Uuid, version_number: i64) -> String {
    format!("{}{version_number}", publications_root(repo_id))
}

/// The parent of every [`publication_prefix`] of `repo_id`, with a trailing
/// slash so `publications/1` never prefix-matches `publications/10`.
pub(crate) fn publications_root(repo_id: Uuid) -> String {
    format!("curation/{repo_id}/publications/")
}

/// The repodata blobs [`publish`] stores beneath a version's prefix.
pub(crate) const PUBLICATION_REPODATA_FILES: [&str; 6] = [
    "repodata/repomd.xml",
    "repodata/repomd.xml.asc",
    "repodata/repomd.xml.key",
    "repodata/primary.xml.gz",
    "repodata/filelists.xml.gz",
    "repodata/other.xml.gz",
];

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
    format!("packages/{}", member_filename(meta))
}

/// The canonical AK NEVRA filename for a member — the exact basename the signed
/// `<location href>` carries, and the name the `@N` serve path resolves. Frozen
/// into `repository_version_packages.frozen_filename` at snapshot time so the
/// served name and the signed name are the same string by construction.
fn member_filename(meta: &RpmPackageMetadata) -> String {
    format!(
        "{}-{}-{}.{}.rpm",
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
    push_rpm_entry_list(xml, "rpm:provides", &f.provides);
    push_rpm_entry_list(xml, "rpm:requires", &f.requires);
    push_rpm_entry_list(xml, "rpm:conflicts", &f.conflicts);
    push_rpm_entry_list(xml, "rpm:obsoletes", &f.obsoletes);
    push_rpm_entry_list(xml, "rpm:recommends", &f.recommends);
    push_rpm_entry_list(xml, "rpm:suggests", &f.suggests);
    push_rpm_entry_list(xml, "rpm:supplements", &f.supplements);
    push_rpm_entry_list(xml, "rpm:enhances", &f.enhances);
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
        // Stub artifacts feed only the pkgid-consistent filelists/other
        // generators, which never read `updated_at`; a fixed epoch keeps the
        // stub a pure function of the frozen member.
        updated_at: chrono::DateTime::UNIX_EPOCH,
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

async fn put_blob(storage: &dyn StorageBackend, key: &str, bytes: Vec<u8>) -> Result<(), AppError> {
    storage
        .put(key, bytes::Bytes::from(bytes))
        .await
        .map_err(|e| AppError::Storage(format!("Failed to store publication blob {key}: {e}")))
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::curation_sync::{RpmChecksum, RpmEntry, RpmFormat, RpmSize, RpmTime};

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

    // A snapshot FREEZES the package identity (checksum + upstream path +
    // published filename) into repository_version_packages. A later re-sync that
    // rewrites the LIVE curation_packages row must not change what the frozen
    // membership carries — that is what stops a published @N from serving bytes
    // its own signed primary.xml does not attest.
    #[tokio::test]
    async fn test_create_version_freezes_package_identity_db() {
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

        let v = create_version(&pool, staging, actor).await.expect("v1");

        let (ck, up, fname): (String, String, String) = sqlx::query_as(
            "SELECT frozen_checksum_sha256, frozen_upstream_path, frozen_filename \
             FROM repository_version_packages WHERE version_id = $1",
        )
        .bind(v.id)
        .fetch_one(&pool)
        .await
        .expect("frozen membership row");
        // Frozen from the STRUCTURED metadata the signed primary.xml is built
        // from, and the filename is exactly its <location href> basename.
        assert_eq!(ck, "abc123");
        assert_eq!(fname, "bash-1.0-1.el9.x86_64.rpm");
        assert_eq!(up, "Packages/bash.rpm");

        // Simulate the routine re-sync upserting the SAME live row with new
        // bytes/identity (curation_service uses ON CONFLICT DO UPDATE).
        sqlx::query(
            "UPDATE curation_packages SET checksum_sha256 = $2, upstream_path = $3 \
             WHERE staging_repo_id = $1",
        )
        .bind(staging)
        .bind("e".repeat(64))
        .bind("Packages/evil.rpm")
        .execute(&pool)
        .await
        .expect("simulate re-sync");

        let (ck2, up2, fname2): (String, String, String) = sqlx::query_as(
            "SELECT frozen_checksum_sha256, frozen_upstream_path, frozen_filename \
             FROM repository_version_packages WHERE version_id = $1",
        )
        .bind(v.id)
        .fetch_one(&pool)
        .await
        .expect("frozen membership row");
        assert_eq!(ck2, ck, "frozen checksum must survive a live re-sync");
        assert_eq!(up2, up, "frozen upstream path must survive a live re-sync");
        assert_eq!(fname2, fname, "frozen filename must survive a live re-sync");

        tdh::cleanup(&pool, staging, actor).await;
        tdh::cleanup(&pool, remote, actor).await;
    }

    // Publishing must fail closed if the live curation row drifted between the
    // snapshot and the publish: the signed document has to attest exactly the
    // identity the frozen membership (and hence the serve path) carries.
    #[tokio::test]
    async fn test_publish_rejects_drift_since_version_created_db() {
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

        let signing = SigningService::new(pool.clone(), "test-encryption-key-2358");
        let key = signing
            .create_key(CreateKeyRequest {
                repository_id: Some(staging),
                name: "drift-key".to_string(),
                key_type: "gpg".to_string(),
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

        // A re-sync rewrites the structured metadata (new checksum) AFTER the
        // snapshot but BEFORE the publish.
        let mut drifted = meta("bash", &"d".repeat(64));
        drifted.version = "1.0".to_string();
        sqlx::query(
            "UPDATE curation_packages SET primary_metadata = $2 WHERE staging_repo_id = $1",
        )
        .bind(staging)
        .bind(serde_json::to_value(&drifted).unwrap())
        .execute(&pool)
        .await
        .expect("simulate re-sync");

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

        let res = publish(
            &pool,
            storage.as_ref(),
            &signing,
            staging,
            created.version_number,
        )
        .await;
        assert!(
            matches!(res, Err(AppError::Conflict(_))),
            "a package that drifted since the snapshot must fail the publish closed: {res:?}"
        );

        tdh::cleanup(&pool, staging, actor).await;
        tdh::cleanup(&pool, remote, actor).await;
    }

    // A version pruned by retention while its publish was writing blobs
    // (#2359): marking it published matches no row, so the publish fails with
    // 409, removes the repodata it stored, and never points the repository's
    // active publication at the deleted version.
    #[tokio::test]
    async fn test_mark_published_after_prune_cleans_up_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo, _k, dir) = tdh::create_repo(&pool, "staging", "rpm").await;
        let (actor, _n) = tdh::create_user(&pool).await;
        let storage = crate::storage::filesystem::FilesystemStorage::new(dir.to_str().unwrap());
        // A real version, pruned after its publish started writing blobs.
        let version_id: Uuid = sqlx::query_scalar(
            "INSERT INTO repository_versions (repository_id, version_number) \
             VALUES ($1, 7) RETURNING id",
        )
        .bind(repo)
        .fetch_one(&pool)
        .await
        .unwrap();
        let prefix = publication_prefix(repo, 7);
        for name in PUBLICATION_REPODATA_FILES {
            put_blob(&storage, &format!("{prefix}/{name}"), b"x".to_vec())
                .await
                .unwrap();
        }

        sqlx::query("DELETE FROM repository_versions WHERE id = $1")
            .bind(version_id)
            .execute(&pool)
            .await
            .unwrap();

        let err = mark_published(&pool, &storage, repo, version_id, 7, &prefix)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Conflict(_)), "{err:?}");
        for name in PUBLICATION_REPODATA_FILES {
            assert!(!storage.exists(&format!("{prefix}/{name}")).await.unwrap());
        }
        let active: Option<Uuid> =
            sqlx::query_scalar("SELECT active_publication_id FROM repositories WHERE id = $1")
                .bind(repo)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(active, None);
        tdh::cleanup(&pool, repo, actor).await;
    }

    /// A staging RPM repository with one approved package, a gpg signing key
    /// bound for metadata signing, and one created (unpublished) version.
    struct PublishFixture {
        staging: Uuid,
        remote: Uuid,
        actor: Uuid,
        signing: SigningService,
        storage: std::sync::Arc<dyn StorageBackend>,
        created: VersionSummary,
    }

    impl PublishFixture {
        async fn new(pool: &PgPool, key_name: &str) -> Self {
            use crate::api::handlers::test_db_helpers as tdh;
            use crate::services::signing_service::CreateKeyRequest;
            let (staging, _sk, dir) = tdh::create_repo(pool, "staging", "rpm").await;
            let (remote, _rk, _rd) = tdh::create_repo(pool, "remote", "rpm").await;
            let (actor, _n) = tdh::create_user(pool).await;
            seed_approved_pkg(
                pool,
                staging,
                remote,
                "bash",
                Some(sample_meta_json("bash")),
            )
            .await;
            // A GPG (OpenPGP) key so publish emits a real detached signature.
            let signing = SigningService::new(pool.clone(), "test-encryption-key-2358");
            let key = signing
                .create_key(CreateKeyRequest {
                    repository_id: Some(staging),
                    name: key_name.to_string(),
                    key_type: "gpg".to_string(),
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
            let created = create_version(pool, staging, actor).await.expect("version");
            let state = tdh::build_state(pool.clone(), dir.to_string_lossy().as_ref());
            let backend: String =
                sqlx::query_scalar("SELECT storage_backend FROM repositories WHERE id = $1")
                    .bind(staging)
                    .fetch_one(pool)
                    .await
                    .expect("repo storage backend");
            let storage = state
                .storage_for_repo(&crate::storage::StorageLocation {
                    backend,
                    path: dir.to_string_lossy().to_string(),
                })
                .expect("storage backend");
            Self {
                staging,
                remote,
                actor,
                signing,
                storage,
                created,
            }
        }
    }

    // #4421: two publishers of one version. The second to mark it gets 409
    // and must leave the first publisher's repodata alone; it must not move
    // `published_at` or reuse the prune-cleanup path.
    #[tokio::test]
    async fn test_mark_published_twice_conflicts_without_cleanup_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let (repo, _k, dir) = tdh::create_repo(&pool, "staging", "rpm").await;
        let (actor, _n) = tdh::create_user(&pool).await;
        let storage = crate::storage::filesystem::FilesystemStorage::new(dir.to_str().unwrap());
        let version_id: Uuid = sqlx::query_scalar(
            "INSERT INTO repository_versions (repository_id, version_number) \
             VALUES ($1, 3) RETURNING id",
        )
        .bind(repo)
        .fetch_one(&pool)
        .await
        .unwrap();
        let prefix = publication_prefix(repo, 3);
        for name in PUBLICATION_REPODATA_FILES {
            put_blob(&storage, &format!("{prefix}/{name}"), b"winner".to_vec())
                .await
                .unwrap();
        }
        let db = &pool;
        let published_at = || async move {
            sqlx::query_scalar::<_, Option<DateTime<Utc>>>(
                "SELECT published_at FROM repository_versions WHERE id = $1",
            )
            .bind(version_id)
            .fetch_one(db)
            .await
            .unwrap()
        };

        mark_published(&pool, &storage, repo, version_id, 3, &prefix)
            .await
            .expect("first publisher marks the version");
        let first = published_at().await.expect("published");
        let err = mark_published(&pool, &storage, repo, version_id, 3, &prefix)
            .await
            .unwrap_err();
        assert!(
            matches!(&err, AppError::Conflict(m) if m.contains("already published")),
            "{err:?}"
        );
        assert_eq!(
            published_at().await,
            Some(first),
            "published_at is not moved"
        );
        for name in PUBLICATION_REPODATA_FILES {
            let blob = storage.get(&format!("{prefix}/{name}")).await.unwrap();
            assert_eq!(&blob[..], b"winner", "{name} must survive the loser");
        }
        tdh::cleanup(&pool, repo, actor).await;
    }

    // #4421: while one publish of a version holds the publish lock, a second
    // concurrent publish of the same, real, publishable version is refused
    // with 409 and writes nothing; once the lock is released the version
    // publishes normally.
    #[tokio::test]
    async fn test_concurrent_publish_of_one_version_conflicts_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let PublishFixture {
            staging,
            remote,
            actor,
            signing,
            storage,
            created,
        } = PublishFixture::new(&pool, "race-key").await;
        let n = created.version_number;

        let first = acquire_publish_lock(&pool, staging, n)
            .await
            .expect("first publisher takes the lock");
        let second = publish(&pool, storage.as_ref(), &signing, staging, n).await;
        assert!(
            matches!(&second, Err(AppError::Conflict(m)) if m.contains("being published")),
            "{second:?}"
        );
        let prefix = publication_prefix(staging, n);
        for name in PUBLICATION_REPODATA_FILES {
            assert!(
                !storage.exists(&format!("{prefix}/{name}")).await.unwrap(),
                "the refused publisher must not write {name}"
            );
        }
        let published: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT published_at FROM repository_versions WHERE id = $1")
                .bind(created.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(published, None);

        first.release().await;
        publish(&pool, storage.as_ref(), &signing, staging, n)
            .await
            .expect("the lock is released; the version publishes");
        assert_eq!(
            publish_lock_key(staging, n),
            format!("rpm-publish:{staging}:{n}")
        );
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

    // Only transient CONCURRENCY aborts are retried. A business rejection (an
    // empty approved set, a package needing re-sync) must surface immediately —
    // retrying it would just burn the attempt budget and delay a 400.
    #[test]
    fn test_only_concurrency_aborts_are_retryable() {
        for err in [
            AppError::Validation("no approved packages to freeze".to_string()),
            AppError::NotFound("Repository version not found".to_string()),
            AppError::Conflict("already published".to_string()),
            AppError::Sqlx(sqlx::Error::PoolTimedOut),
            AppError::Sqlx(sqlx::Error::RowNotFound),
        ] {
            assert!(
                !is_retryable_snapshot_conflict(&err),
                "must not retry {err:?}"
            );
        }
    }

    #[test]
    fn test_create_version_retry_backoff_is_jittered_and_growing() {
        use std::time::Duration;
        // Floor: the original linear backoff.
        assert_eq!(
            create_version_retry_backoff(1, 0.0),
            Duration::from_millis(20)
        );
        assert_eq!(
            create_version_retry_backoff(3, 0.0),
            Duration::from_millis(60)
        );
        // Ceiling: up to double the floor.
        assert_eq!(
            create_version_retry_backoff(1, 1.0),
            Duration::from_millis(40)
        );
        assert_eq!(
            create_version_retry_backoff(4, 0.5),
            Duration::from_millis(120)
        );
        // Out-of-range jitter is clamped rather than trusted.
        assert_eq!(
            create_version_retry_backoff(2, 7.0),
            Duration::from_millis(80)
        );
        assert_eq!(
            create_version_retry_backoff(2, -1.0),
            Duration::from_millis(40)
        );
        // Two racers drawing different jitter wake at different times (#4307).
        assert_ne!(
            create_version_retry_backoff(1, 0.1),
            create_version_retry_backoff(1, 0.9)
        );
    }

    #[test]
    fn test_create_version_lock_key_is_namespaced_per_repo() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        assert_eq!(create_version_lock_key(a), format!("rpm-version:{a}"));
        assert_ne!(create_version_lock_key(a), create_version_lock_key(b));
    }

    // CONCURRENT creates must both succeed with DISTINCT monotonic numbers.
    //
    // Before #4307 the snapshot ran at SERIALIZABLE with a deterministic
    // backoff, so two racers could abort each other with 40001 on every attempt
    // and exhaust the retry budget under CI load. The per-repository advisory
    // lock now serializes them; this pins that three racers allocate 1, 2 and
    // 3 instead of any of them failing.
    #[tokio::test]
    async fn test_create_version_concurrent_racers_both_succeed_db() {
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

        // Three racers: one per connection of the test pool, so every racer
        // is genuinely in flight at once.
        let (a, b, c) = tokio::join!(
            create_version(&pool, staging, actor),
            create_version(&pool, staging, actor),
            create_version(&pool, staging, actor),
        );
        let a = a.expect("racer A must not fail on a serialization conflict");
        let b = b.expect("racer B must not fail on a serialization conflict");
        let c = c.expect("racer C must not fail on a serialization conflict");

        let mut numbers = [a.version_number, b.version_number, c.version_number];
        numbers.sort_unstable();
        assert_eq!(
            numbers,
            [1, 2, 3],
            "concurrent creates must allocate distinct monotonic versions"
        );

        tdh::cleanup(&pool, staging, actor).await;
        tdh::cleanup(&pool, remote, actor).await;
    }

    // Deterministic half of #4307, independent of scheduling luck: a single
    // attempt (no retry to mask a conflict) that starts while another
    // create for the same repository holds the lock with an uncommitted
    // version 1 must WAIT for it, then allocate 2 on its first try. Without
    // the lock the attempt reads MAX = 0 and collides with the holder's row
    // (23505); with the lock inside a SERIALIZABLE transaction its snapshot
    // predates the holder's commit, so it still reads MAX = 0 and conflicts
    // (23505 or 40001). Both variants were verified to fail this test.
    #[tokio::test]
    async fn test_create_version_once_waits_for_lock_holder_then_allocates_next_db() {
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

        let mut holder = pool.begin().await.unwrap();
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(create_version_lock_key(staging))
            .execute(&mut *holder)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO repository_versions
                 (repository_id, version_number, created_by, package_count)
             VALUES ($1, 1, $2, 1)",
        )
        .bind(staging)
        .bind(actor)
        .execute(&mut *holder)
        .await
        .unwrap();

        let racer = {
            let pool = pool.clone();
            tokio::spawn(async move { create_version_once(&pool, staging, actor).await })
        };
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            !racer.is_finished(),
            "a create for the same repository must wait for the lock holder"
        );
        holder.commit().await.unwrap();

        let summary = racer
            .await
            .unwrap()
            .expect("the waiter must see the holder's commit, not conflict with it");
        assert_eq!(summary.version_number, 2);

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
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let PublishFixture {
            staging,
            remote,
            actor,
            signing,
            storage,
            created,
        } = PublishFixture::new(&pool, "e2e-key").await;

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
        for name in PUBLICATION_REPODATA_FILES {
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

    // A repo whose active key cannot produce OpenPGP (key_type='rsa', an X.509
    // key) must FAIL CLOSED at publish — never emit a raw-PKCS#1 signature
    // hand-wrapped in PGP armor that no client can verify.
    #[tokio::test]
    async fn test_publish_rejects_non_openpgp_key_db() {
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

        let signing = SigningService::new(pool.clone(), "test-encryption-key-2358");
        let key = signing
            .create_key(CreateKeyRequest {
                repository_id: Some(staging),
                name: "rsa-only".to_string(),
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

        let res = publish(
            &pool,
            storage.as_ref(),
            &signing,
            staging,
            created.version_number,
        )
        .await;
        match res {
            Err(AppError::Validation(msg)) => assert!(
                msg.contains("OpenPGP") || msg.contains("gpg"),
                "must reject a non-OpenPGP key with a clear message: {msg}"
            ),
            other => panic!("expected Validation(OpenPGP) rejection, got {other:?}"),
        }

        tdh::cleanup(&pool, staging, actor).await;
        tdh::cleanup(&pool, remote, actor).await;
    }

    // The published @N signature must be REAL, verifiable OpenPGP — not theater.
    // The detached `repomd.xml.asc` frozen at publish must verify over the frozen
    // `repomd.xml` under the frozen `repomd.xml.key`, exactly as `dnf
    // repo_gpgcheck=1` does; and a byte-tampered repomd must FAIL that check.
    #[tokio::test]
    async fn test_published_at_n_signature_verifies_and_rejects_tamper_db() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::signing_service::verify_detached;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let PublishFixture {
            staging,
            remote,
            actor,
            signing,
            storage,
            created,
        } = PublishFixture::new(&pool, "e2e-verify-key").await;

        let summary = publish(
            &pool,
            storage.as_ref(),
            &signing,
            staging,
            created.version_number,
        )
        .await
        .expect("publish");

        let prefix = &summary.storage_prefix;
        let repomd = storage
            .get(&format!("{prefix}/repodata/repomd.xml"))
            .await
            .expect("frozen repomd.xml");
        let asc = String::from_utf8(
            storage
                .get(&format!("{prefix}/repodata/repomd.xml.asc"))
                .await
                .expect("frozen repomd.xml.asc")
                .to_vec(),
        )
        .expect("asc is ASCII armor");
        let pubkey = String::from_utf8(
            storage
                .get(&format!("{prefix}/repodata/repomd.xml.key"))
                .await
                .expect("frozen repomd.xml.key")
                .to_vec(),
        )
        .expect("key is ASCII armor");

        // Real armor shape, and it VERIFIES over the frozen repomd under the
        // frozen key — the decisive "signature is not theater" assertion.
        assert!(asc.starts_with("-----BEGIN PGP SIGNATURE-----"));
        assert!(pubkey.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        verify_detached(&pubkey, &repomd, &asc)
            .expect("frozen @N signature must verify over the frozen repomd under the frozen key");

        // Tamper the signed document: verification must fail closed.
        let tampered = String::from_utf8(repomd.to_vec())
            .unwrap()
            .replace("</repomd>", "<data type=\"evil\"></data></repomd>");
        assert!(
            verify_detached(&pubkey, tampered.as_bytes(), &asc).is_err(),
            "a tampered @N repomd.xml must fail signature verification"
        );

        tdh::cleanup(&pool, staging, actor).await;
        tdh::cleanup(&pool, remote, actor).await;
    }
}
