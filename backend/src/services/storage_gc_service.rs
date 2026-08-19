//! Storage garbage collection service.
//!
//! Finds soft-deleted artifacts whose storage keys are no longer referenced
//! by any live artifact, deletes the physical storage files, and hard-deletes
//! the artifact records from the database.

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::sync::Arc;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::storage::keys::prefix_matches;
use crate::storage::{StorageBackend, StorageLocation, StorageRegistry};

const ABANDONED_OCI_UPLOAD_TTL_SQL: &str = "INTERVAL '24 hours'";
const ABANDONED_OCI_UPLOAD_SCAN_LIMIT: i64 = 1000;
const OCI_UPLOAD_CLEANUP_KEY_SCAN_LIMIT: i64 = 1000;

/// TTL for one cleanup-key sweep claim. One storage delete takes seconds;
/// 15 minutes comfortably covers a slow batch while bounding how long a
/// crashed sweeper blocks retries of its claimed keys.
const OCI_CLEANUP_KEY_CLAIM_TTL_SQL: &str = "INTERVAL '15 minutes'";

/// SQL fragment expressing the orphan-storage-key predicate.
///
/// A storage key is "orphaned" when:
/// 1. Every artifact pointing at it is soft-deleted (no live artifact shares
///    the key);
/// 2. It is not protected by an `oci_tags` row (manifests still tagged);
/// 3. It is not protected by an `oci_blobs` row (named blobs);
/// 4. It is not the per-architecture child of a still-tagged OCI image index
///    (`oci_manifest_refs` joined against `oci_tags`; see migration 092).
///
/// The fragment expects two bindings: the outer `artifacts` row aliased
/// `a` and the outer `repositories` row aliased `r`. Callers either inline
/// it in the main SELECT (where `a`/`r` come from the outer joins) or use
/// it under [`is_still_orphan`] to re-check a single (storage_key,
/// repository_id) tuple under a row-level lock.
///
/// Both the initial SELECT and the per-key re-check feed off this same
/// constant so the two checks cannot drift out of sync. Drift between the
/// two predicates is what makes a TOCTOU window real in the first place
/// (#1180); keeping them literally identical is the cheap structural
/// guarantee that they stay aligned.
///
/// The `'oci-manifests/'` literals below are the SQL embedding of
/// [`OCI_MANIFEST_STORAGE_PREFIX`](crate::storage::keys::OCI_MANIFEST_STORAGE_PREFIX) — the same prefix `manifest_storage_key()`
/// (`oci_v2.rs`) produces on writes and the lifecycle cascade
/// (`lifecycle_service.rs`, `CASCADE_OCI_TAGS_SQL`) matches on. Postgres
/// cannot read the Rust constant, so the literal is pinned to it by the
/// `const _: () = assert!(...)` after this constant (#1413).
const ORPHAN_PREDICATE_SQL: &str = r#"
a.is_deleted = true
AND NOT EXISTS (
    SELECT 1 FROM artifacts a2
    WHERE a2.storage_key = a.storage_key
      AND a2.is_deleted = false
)
AND NOT EXISTS (
    SELECT 1
    FROM oci_tags ot
    JOIN repositories otr ON otr.id = ot.repository_id
    WHERE a.storage_key LIKE 'oci-manifests/%'
      AND ot.manifest_digest = SUBSTRING(
        a.storage_key FROM LENGTH('oci-manifests/') + 1
      )
      AND otr.storage_backend = r.storage_backend
      AND (
        r.storage_backend <> 'filesystem'
        OR otr.storage_path = r.storage_path
      )
)
AND NOT EXISTS (
    SELECT 1
    FROM oci_blobs ob
    JOIN repositories obr ON obr.id = ob.repository_id
    WHERE a.storage_key LIKE 'oci-blobs/%'
      AND ob.digest = SUBSTRING(
        a.storage_key FROM LENGTH('oci-blobs/') + 1
      )
      AND obr.storage_backend = r.storage_backend
      AND (
        r.storage_backend <> 'filesystem'
        OR obr.storage_path = r.storage_path
      )
)
AND NOT EXISTS (
    SELECT 1
    FROM oci_manifest_refs omr
    JOIN oci_tags ot2 ON ot2.repository_id = omr.repository_id
                     AND ot2.manifest_digest = omr.parent_digest
    JOIN repositories omrr ON omrr.id = omr.repository_id
    WHERE a.storage_key LIKE 'oci-manifests/%'
      AND omr.child_digest = SUBSTRING(
        a.storage_key FROM LENGTH('oci-manifests/') + 1
      )
      AND omrr.storage_backend = r.storage_backend
      AND (
        r.storage_backend <> 'filesystem'
        OR omrr.storage_path = r.storage_path
      )
)
"#;

/// Compile-time guard: the `'oci-manifests/'` literals embedded in
/// [`ORPHAN_PREDICATE_SQL`] (both the `LIKE` filter and the `SUBSTRING`
/// offset) must match [`OCI_MANIFEST_STORAGE_PREFIX`](crate::storage::keys::OCI_MANIFEST_STORAGE_PREFIX). Postgres cannot
/// reference the Rust constant directly, so this keeps the SQL literal and
/// the write-path constant from drifting (#1413).
const _: () = assert!(prefix_matches("oci-manifests/"));

/// Minimum age (seconds) a blob must reach before [`StorageGcService::run_blob_gc`]
/// will consider it for deletion (#1408).
///
/// Pushes do not commit `oci_blobs` and `manifest_blob_refs` in a single
/// transaction: blobs are uploaded one by one through their own PUT
/// requests, then the manifest is pushed at the end. Between the blob
/// upload and the manifest push, the row exists with no live reference —
/// it is technically orphan but only because the client is mid-push. A
/// grace period absorbs the normal push window so blob GC can stay cheap
/// (no global advisory lock) while still being safe in practice.
/// Twenty-four hours is far above the longest realistic
/// upload-then-manifest gap and short enough that abandoned uploads do
/// not waste storage indefinitely. The bound is pinned by compile-time
/// `assert!`s in the test module to keep accidental drift out of band.
pub(crate) const MIN_BLOB_AGE_SECS: u64 = 24 * 60 * 60;

/// SQL fragment: `EXISTS (...)` — true when some `manifest_blob_refs` row
/// still protects the outer blob row aliased `ob` (joined to its
/// repository aliased `r`). Negate it to get "this blob is orphaned".
///
/// Scope mirrors the cloud/filesystem branch of [`ORPHAN_PREDICATE_SQL`],
/// because blob storage is content-addressed under `oci-blobs/<digest>`:
/// - Cloud backends (S3/Azure/GCS) share one bucket, so that key resolves
///   to the SAME physical object for every repo on the backend. A
///   reference from ANY same-backend repo must protect it; deleting on the
///   first orphan `(repo, digest)` row would destroy a blob other repos
///   still serve — the cross-repo dedup incident this table guards (57
///   blobs across 85 tags broken in prod by a per-`(repo,digest)`
///   reconciler).
/// - Filesystem repos each root their own tree at `storage_path`, so the
///   key resolves to a DISTINCT file per repo. Only a reference whose repo
///   shares this `storage_path` protects this repo's copy; another repo's
///   copy is independently reclaimable.
///
/// The outer query must expose `ob` (oci_blobs) and `r` (repositories) so
/// the initial scan and the locked re-check feed off one definition and
/// cannot drift (the #1180 lesson, applied to blob GC).
const BLOB_PROTECTED_BY_REFS_SQL: &str = r#"
    EXISTS (
        SELECT 1
        FROM manifest_blob_refs mbr
        JOIN repositories mr ON mr.id = mbr.repository_id
        WHERE mbr.blob_digest = ob.digest
          AND mr.storage_backend = r.storage_backend
          AND (
            r.storage_backend <> 'filesystem'
            OR mr.storage_path = r.storage_path
          )
    )
"#;

/// Storage-key prefix shared by every flat Maven object (artifacts, checksum
/// sidecars, `maven-metadata.xml`). Mirrors the `format!("maven/{}", path)`
/// key construction in `api/handlers/maven.rs`.
const MAVEN_FLAT_KEY_PREFIX: &str = "maven/";

/// Checksum sidecar suffixes the Maven upload handler stores as *row-less*
/// puts (no `artifacts` row; see `parse_checksum_path` in
/// `api/handlers/maven.rs`). These objects are invisible to the
/// artifacts-driven orphan sweep, which is exactly why GC used to leave
/// `.md5`/`.sha1` files behind after their base artifact was reclaimed
/// (#2668). GC derives these keys from the base key when reclaiming it.
pub(crate) const MAVEN_SIDECAR_SUFFIXES: [&str; 4] = [".md5", ".sha1", ".sha256", ".sha512"];

/// Upper bound on flat-object attribution rows examined per GC pass.
const ORPHAN_MAVEN_FLAT_SCAN_LIMIT: i64 = 1000;

/// SQL fragment expressing the orphaned row-less Maven flat-object predicate
/// over an outer `maven_flat_object_owner` row aliased `o` (#2668).
///
/// Row-less Maven objects (checksum sidecars, verbatim `maven-metadata.xml`,
/// legacy GAV-grouped companions) have no `artifacts` row, so the main
/// artifacts-driven sweep can never reclaim them. Their only durable DB
/// record is the `maven_flat_object_owner` attribution table (#2574/#2584),
/// which this sweep walks. A row is collectable only when every catalog
/// layer that could anchor (make readable) its object is gone:
///
/// 1. No `artifacts` row — live OR soft-deleted — on the same backend still
///    uses the key. Soft-deleted rows protect the object until the main
///    sweep hard-deletes them, so a resurrectable coordinate is never
///    stripped of its companions early.
/// 2. No parent artifact's metadata `files[]` (any parent, live or
///    soft-deleted) lists the key (legacy GAV-grouped companions).
/// 3. A `maven-metadata.xml` key (or a checksum sidecar of one) additionally
///    requires that NO live artifact exists under its directory prefix on
///    the same backend: the metadata document stays while any version of
///    its groupId/artifactId (or group, for group-level plugin metadata)
///    is still live. The `LIKE` prefix test can only over-match (SQL
///    wildcards in a key match a superset), i.e. only ever over-PROTECT.
/// 4. A checksum sidecar additionally requires its base key to be anchored
///    by neither an `artifacts` row (any state) nor a metadata `files[]`
///    reference on the same backend.
///
/// The one-hour age floor keeps the sweep away from in-flight first
/// publishes, whose claim row is inserted just before the object bytes are
/// written. Scan and per-row locked re-check share this constant so the two
/// predicates cannot drift (the #1180 lesson).
///
/// Guards 2 and 5 -- the `files[]` reference tests -- are built from the
/// shared [`crate::services::maven_flat_attribution::metadata_files_name_key_sql`]
/// fragment rather than an inline copy. Their inline copies matched snake_case
/// `storage_key` only, while the legacy #418-era GAV-grouped upload handler
/// wrote camelCase `storageKey`; in a `NOT EXISTS` guard a missed reference
/// means DELETE, so
/// every live GAV companion (and every checksum sidecar of one) read as
/// unreferenced and was purged by the sweep while its parent artifact was
/// still serving it (#3156).
///
/// The FIRST arm is the source allowlist
/// ([`crate::services::maven_flat_attribution::SYSTEM_WRITTEN_ATTRIBUTION_SOURCES`]).
/// Everything below it tests catalog *anchors*, which is only a proof of
/// garbage for rows the system wrote and can re-derive. An owner row is also
/// what makes a row-less legacy object READABLE (#2574/#2585), and for an
/// object whose only catalog record is its owner row every anchor arm is true
/// by construction and permanently — so before this arm existed, an
/// operator-inserted row (the documented repair for keys the catalog-only
/// backfill cannot see) nominated its own object for deletion within the hour
/// (#3431). Unknown/novel sources are protected by default: the arm is an
/// allowlist, so the failure direction is leaked storage, never lost bytes.
///
/// Guards 3, 4 and 5 likewise take their sidecar-suffix regex from
/// [`crate::services::maven_flat_attribution::GUARDED_SIDECAR_SUFFIXES`] rather
/// than an inline `(md5|sha1|sha256|sha512)` alternation. The inline copies
/// omitted `.asc`, which the READ path resolves to its base
/// (`strip_checksum_suffix`) and which migrations 163 and 170 step (3') both
/// backfill into `maven_flat_object_owner` -- so a `<base>.asc` the server was
/// still serving matched neither the verbatim guards (nothing references a
/// sidecar by name) nor the sidecar arms (the regex did not recognise it as a
/// sidecar), read as orphan, and was reclaimed while its base stayed live
/// (#3197). The rollup guard shares
/// [`crate::services::maven_flat_attribution::is_metadata_rollup_key_sql`] /
/// [`crate::services::maven_flat_attribution::metadata_rollup_dir_prefix_sql`]
/// with the repository-delete collector for the same anti-drift reason.
static ORPHAN_MAVEN_FLAT_PREDICATE_SQL: Lazy<String> = Lazy::new(|| {
    use crate::services::maven_flat_attribution as mfa;
    let sidecar_base = mfa::sidecar_base_key_sql("o.storage_key");
    format!(
        r#"
{system_source}
AND o.storage_key LIKE 'maven/%'
AND o.created_at < NOW() - INTERVAL '1 hour'
AND NOT EXISTS (
    SELECT 1 FROM artifacts a
    JOIN repositories ar ON ar.id = a.repository_id
    WHERE a.storage_key = o.storage_key
      AND ar.storage_backend = o.storage_backend
)
AND NOT EXISTS (
    SELECT 1 FROM artifact_metadata am
    JOIN artifacts pa ON pa.id = am.artifact_id
    JOIN repositories pr ON pr.id = pa.repository_id
    WHERE pr.storage_backend = o.storage_backend
      AND {files_match}
)
AND NOT EXISTS (
    SELECT 1 FROM artifacts a2
    JOIN repositories r2 ON r2.id = a2.repository_id
    WHERE {is_rollup}
      AND r2.storage_backend = o.storage_backend
      AND a2.is_deleted = false
      AND a2.storage_key LIKE {rollup_dir} || '%'
)
AND NOT EXISTS (
    SELECT 1 FROM artifacts ab
    JOIN repositories rb ON rb.id = ab.repository_id
    WHERE {is_sidecar}
      AND ab.storage_key = {sidecar_base}
      AND rb.storage_backend = o.storage_backend
)
AND NOT EXISTS (
    SELECT 1 FROM artifact_metadata am2
    JOIN artifacts pa2 ON pa2.id = am2.artifact_id
    JOIN repositories pr2 ON pr2.id = pa2.repository_id
    WHERE {is_sidecar}
      AND pr2.storage_backend = o.storage_backend
      AND {sidecar_base_files_match}
)
"#,
        system_source = mfa::system_written_source_sql("o.source"),
        files_match = mfa::metadata_files_name_key_sql("am.metadata->'files'", "o.storage_key"),
        is_rollup = mfa::is_metadata_rollup_key_sql("o.storage_key"),
        rollup_dir = mfa::metadata_rollup_dir_prefix_sql("o.storage_key"),
        is_sidecar = mfa::is_sidecar_key_sql("o.storage_key"),
        sidecar_base_files_match =
            mfa::metadata_files_name_key_sql("am2.metadata->'files'", &sidecar_base),
    )
});

/// Result of a storage GC run.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct StorageGcResult {
    pub dry_run: bool,
    pub storage_keys_deleted: i64,
    pub artifacts_removed: i64,
    pub bytes_freed: i64,
    pub errors: Vec<String>,
    /// Orphaned row-less Maven flat objects this pass identified but left in
    /// place because the sweep is not opted in (`MAVEN_FLAT_GC_ENABLED`
    /// unset, #3431). Report-only: these objects and their attribution rows
    /// were NOT deleted and are not counted in `storage_keys_deleted`. Always
    /// `0` on a dry run (a dry run deletes nothing anyway) and when the sweep
    /// is enabled.
    #[serde(default)]
    pub maven_flat_objects_gated: i64,
}

/// Default grace window (hours) used to classify "recent" OCI blobs in the
/// reclaimable report. A blob younger than this is excluded from the
/// `aged_*` figures because its parent manifest push may still be in
/// flight (the upload writes the `oci_blobs` row before the manifest that
/// references it commits). This mirrors the grace-window guard that the
/// future blob GC sweep will use, but here it only affects *reporting* —
/// nothing is ever deleted by this path.
pub const BLOB_REPORT_GRACE_HOURS_DEFAULT: i64 = 24;

/// Per-repository row in the OCI blob footprint report.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq)]
pub struct OciBlobRepoFootprint {
    /// Repository id owning these `oci_blobs` rows.
    pub repository_id: Uuid,
    /// Number of `oci_blobs` rows attributed to this repository.
    pub blob_rows: i64,
    /// Sum of `oci_blobs.size_bytes` for this repository's rows. On shared
    /// backends (anything other than `filesystem`) blobs are deduplicated
    /// across repos — one physical object per digest per backend — so the
    /// same physical bytes can be counted under more than one repository
    /// here. On `filesystem` each repository stores its own independent
    /// copy under its `storage_path`, so its rows are that repo's real
    /// bytes. See [`OciBlobFootprintReport::physical_bytes`] for the
    /// dedup-aware total.
    pub logical_bytes: i64,
}

/// Read-only OCI blob storage footprint report (issue #1408).
///
/// This is a **reporting-only** view. It performs no deletion and takes no
/// locks. It surfaces how much storage the tracked `oci_blobs` rows
/// account for so operators can see the magnitude of un-reclaimed blob
/// layers before any garbage-collection mechanism is enabled.
///
/// It deliberately does NOT attempt to classify which blobs are
/// "reclaimable orphans": that is the blob GC's job (mark-and-sweep over
/// `manifest_blob_refs`, per [`BLOB_PROTECTED_BY_REFS_SQL`]). A naive
/// per-`(repository_id, digest)` orphan heuristic would mis-handle shared
/// backends (anything other than `filesystem`), where all referencing
/// repos share ONE physical object per digest per backend, and report
/// in-use blobs as reclaimable; on `filesystem` each repository keeps an
/// independent copy under its own `storage_path`. The numbers here are
/// exact aggregates only.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq)]
pub struct OciBlobFootprintReport {
    /// Total number of `oci_blobs` rows across all repositories.
    pub total_blob_rows: i64,
    /// Number of distinct blob digests (content-addressed identities). When
    /// this is smaller than `total_blob_rows`, the difference is cross-repo
    /// sharing of a content identity (one physical object shared by all
    /// referencing repos on shared backends; an independent copy per
    /// repository on `filesystem`).
    pub distinct_digests: i64,
    /// Sum of `size_bytes` over every `oci_blobs` row. Double-counts
    /// deduplicated blobs once per referencing repository.
    pub logical_bytes: i64,
    /// Sum of `size_bytes` counting each distinct **physical storage
    /// object** exactly once, per the ownership model of
    /// [`BLOB_PROTECTED_BY_REFS_SQL`]: on shared backends (anything other
    /// than `filesystem`) a digest is one object per backend; on
    /// `filesystem` each repository stores its own copy under its
    /// `storage_path`, so the same digest in two filesystem repositories
    /// counts twice.
    pub physical_bytes: i64,
    /// Grace window (hours) applied to the `aged_*` figures below.
    pub grace_hours: i64,
    /// Distinct digests with at least one physical copy older than
    /// `grace_hours` (eligible to be *considered* by a future GC sweep once
    /// a reference table exists). Reporting only.
    pub aged_distinct_digests: i64,
    /// Physical bytes (same physical-object grouping as `physical_bytes`)
    /// older than `grace_hours`.
    pub aged_physical_bytes: i64,
    /// Per-repository logical footprint, largest `logical_bytes` first.
    pub per_repository: Vec<OciBlobRepoFootprint>,
}

/// Storage garbage collection service.
///
/// For cloud backends (S3/Azure/GCS), the shared storage instance handles all
/// deletions directly since storage keys are globally unique. For filesystem,
/// each repository has its own storage directory, so the service resolves the
/// correct backend per repo using the repository's `storage_path`.
pub struct StorageGcService {
    db: PgPool,
    storage_registry: Arc<StorageRegistry>,
    /// Opt-in gate for [`StorageGcService::cleanup_orphan_maven_flat_objects`]
    /// (#3431). `false` — the default from [`StorageGcService::new`] — makes
    /// that sweep report-only. Set from `Config::maven_flat_gc_enabled` via
    /// [`StorageGcService::with_maven_flat_gc_enabled`] at every production
    /// entry point (scheduler + admin handlers), so an entry point that
    /// forgets to wire the flag fails SAFE.
    maven_flat_gc_enabled: bool,
}

#[derive(Debug)]
struct AbandonedOciUploadSession {
    id: Uuid,
    location: StorageLocation,
    storage_keys: Vec<String>,
    bytes_received: i64,
}

#[derive(Debug)]
struct OciUploadCleanupKey {
    id: i64,
    location: StorageLocation,
    storage_key: String,
    /// Sweep-claim token (RowClaimedQueue): `Some` when the row was claimed
    /// for a real (destructive) sweep, `None` for dry-run candidate scans.
    /// The row DELETE and the failure release must present it.
    claim_token: Option<Uuid>,
}

/// Liveness clauses shared by both cleanup-journal sweeps: a storage object is
/// only reclaimable while no live upload part and no committed `oci_blobs` row
/// references it. Written against the bare table name so the fragment composes
/// into an `UPDATE`/`DELETE` on `oci_upload_cleanup_keys`.
const CLEANUP_KEY_SHARED_LIVENESS_SQL: &str = r#"
              AND NOT EXISTS (
                SELECT 1 FROM oci_upload_parts p
                WHERE p.storage_key = oci_upload_cleanup_keys.storage_key
              )
              AND NOT EXISTS (
                SELECT 1 FROM oci_blobs b
                WHERE b.storage_key = oci_upload_cleanup_keys.storage_key
              )"#;

/// Committed-key (`storage_write_completed_at IS NOT NULL`) half of the
/// liveness predicate. Deliberately NOT guarded by `s.id = upload_session_id`
/// — see the matching row `DELETE` in
/// [`StorageGcService::cleanup_unreferenced_oci_upload_keys`].
const UNREFERENCED_CLEANUP_KEY_LIVENESS_HEAD_SQL: &str = r#"
              AND storage_write_completed_at IS NOT NULL
              AND NOT EXISTS (
                SELECT 1 FROM oci_upload_sessions s
                WHERE s.storage_temp_key = oci_upload_cleanup_keys.storage_key
              )"#;

/// Pending-key (`storage_write_completed_at IS NULL`) half of the liveness
/// predicate. The owning session is re-checked by id as well as by key — see
/// the matching row `DELETE` in
/// [`StorageGcService::reap_pending_oci_upload_cleanup_keys`].
const PENDING_CLEANUP_KEY_LIVENESS_HEAD_SQL: &str = r#"
              AND storage_write_completed_at IS NULL
              AND NOT EXISTS (
                SELECT 1 FROM oci_upload_sessions s
                WHERE s.id = oci_upload_cleanup_keys.upload_session_id
                   OR s.storage_temp_key = oci_upload_cleanup_keys.storage_key
              )"#;

/// Which cleanup-journal sweep owns a claimed key, and therefore which
/// liveness predicate must still hold at the instant of its storage delete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CleanupSweepKind {
    /// [`StorageGcService::cleanup_unreferenced_oci_upload_keys`].
    Unreferenced,
    /// [`StorageGcService::reap_pending_oci_upload_cleanup_keys`].
    Pending,
}

impl CleanupSweepKind {
    /// SQL fragment (a chain of `AND` clauses) re-asserted immediately before
    /// this sweep's destructive storage delete. Mirrors the sweep's guarded
    /// row `DELETE` so the pre-delete hook and the post-delete row removal
    /// agree on exactly what "still reclaimable" means (#3085).
    fn liveness_predicate_sql(self) -> String {
        let head = match self {
            Self::Unreferenced => UNREFERENCED_CLEANUP_KEY_LIVENESS_HEAD_SQL,
            Self::Pending => PENDING_CLEANUP_KEY_LIVENESS_HEAD_SQL,
        };
        format!("{head}{CLEANUP_KEY_SHARED_LIVENESS_SQL}")
    }
}

impl StorageGcService {
    pub fn new(db: PgPool, storage_registry: Arc<StorageRegistry>) -> Self {
        Self {
            db,
            storage_registry,
            // Fail safe: the orphan Maven flat-object sweep never deletes
            // until a caller explicitly opts in (#3431).
            maven_flat_gc_enabled: false,
        }
    }

    /// Opt the orphaned row-less Maven flat-object sweep into live deletion
    /// (#3431). Mirrors `BLOB_GC_ENABLED`: without this the sweep still runs
    /// and reports what it would reclaim, but deletes nothing.
    #[must_use]
    pub fn with_maven_flat_gc_enabled(mut self, enabled: bool) -> Self {
        self.maven_flat_gc_enabled = enabled;
        self
    }

    /// Get the storage backend for a given storage location.
    pub(crate) fn storage_for_location(
        &self,
        location: &StorageLocation,
    ) -> Result<Arc<dyn StorageBackend>> {
        self.storage_registry.backend_for(location)
    }

    /// Run garbage collection on orphaned storage keys.
    ///
    /// Finds storage keys referenced only by soft-deleted artifacts (no live
    /// artifact shares the same key), deletes the physical file from the
    /// correct storage backend, then hard-deletes the database records.
    ///
    /// Each per-key deletion runs inside its own transaction. The
    /// transaction first re-verifies the orphan predicate under
    /// `FOR UPDATE` row locks so a concurrent push that lands between the
    /// outer SELECT and this point does not lose its newly-written
    /// references (#1180). The physical storage delete happens while the
    /// row lock is held but is not itself transactional; storage backends
    /// are not part of Postgres' atomic write boundary. The DB row deletes
    /// (`promotion_approvals` + `artifacts`) happen inside the same
    /// transaction so the row lock prevents any racing writer from
    /// resurrecting the rows before they are hard-deleted.
    pub async fn run_gc(&self, dry_run: bool) -> Result<StorageGcResult> {
        self.run_gc_inner(None, dry_run).await
    }

    /// Repository-scoped variant of [`Self::run_gc`] (web #708).
    ///
    /// Every candidate scan is filtered to rows owned by `repository_id`:
    /// soft-deleted artifacts in this repository (main sweep), this
    /// repository's abandoned OCI upload sessions, its orphaned upload
    /// cleanup keys, and its orphaned Maven flat-object attribution rows.
    ///
    /// The orphan *predicates* are deliberately NOT narrowed: a storage key
    /// is only ever reclaimed when no live artifact, tag, blob, or manifest
    /// reference exists for it anywhere on the instance. A dry run therefore
    /// reports "bytes reclaimable now, attributable to this repository" —
    /// honest under cross-repo dedup because a shared blob still referenced
    /// by another repository never appears in the candidate set. On a shared
    /// (cloud) backend a live (non-dry-run) run hard-deletes every
    /// repository's soft-deleted rows for a reclaimed key — exactly what the
    /// instance-wide pass would do for the same key — so per-repo scoping
    /// can never strand or prematurely delete another tenant's data.
    pub async fn run_gc_for_repository(
        &self,
        repository_id: Uuid,
        dry_run: bool,
    ) -> Result<StorageGcResult> {
        self.run_gc_inner(Some(repository_id), dry_run).await
    }

    async fn run_gc_inner(
        &self,
        repo_scope: Option<Uuid>,
        dry_run: bool,
    ) -> Result<StorageGcResult> {
        let orphans = self.select_orphans(repo_scope).await?;

        let mut result = empty_gc_result(dry_run);

        if dry_run {
            for row in &orphans {
                let bytes: i64 = row.try_get("total_bytes").unwrap_or(0);
                let count: i64 = row.try_get("artifact_count").unwrap_or(0);
                accumulate_dry_run(&mut result, bytes, count);
            }
        } else {
            for row in &orphans {
                let storage_key: String = row.try_get("storage_key").unwrap_or_default();
                let storage_backend: String = row.try_get("storage_backend").unwrap_or_default();
                let storage_path: String = row.try_get("storage_path").unwrap_or_default();
                let bytes: i64 = row.try_get("total_bytes").unwrap_or(0);
                let count: i64 = row.try_get("artifact_count").unwrap_or(0);

                // Resolve the correct storage backend for this repo
                let location = StorageLocation {
                    backend: storage_backend.clone(),
                    path: storage_path.clone(),
                };
                let storage = match self.storage_for_location(&location) {
                    Ok(s) => s,
                    Err(e) => {
                        let msg = format_gc_error("resolve storage", &storage_key, &e.to_string());
                        tracing::warn!("{}", msg);
                        result.errors.push(msg);
                        continue;
                    }
                };

                // Begin a per-key transaction. The transaction holds row locks
                // on the matching `artifacts` rows from `is_still_orphan`'s
                // FOR UPDATE clause through the storage delete and the DB row
                // deletes. Any writer trying to flip `is_deleted = false` or
                // insert a new reference is blocked behind the lock.
                let mut tx = match self.db.begin().await {
                    Ok(t) => t,
                    Err(e) => {
                        let msg = format_gc_error("begin gc tx", &storage_key, &e.to_string());
                        tracing::warn!("{}", msg);
                        result.errors.push(msg);
                        continue;
                    }
                };

                // Re-verify the orphan predicate inside the tx, taking a row
                // lock on the matching artifact rows. If a concurrent push has
                // landed a live reference (`oci_tags`, `oci_blobs`,
                // `oci_manifest_refs` parent re-tag, or a new live artifact
                // sharing the key), this returns `false` and the GC pass
                // skips the key to revisit on the next run.
                match is_still_orphan(&mut tx, &storage_key, &storage_backend, &storage_path).await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        let _ = tx.rollback().await;
                        tracing::debug!(
                            storage_key = storage_key.as_str(),
                            "GC skipped key: no longer orphan after row-lock re-check"
                        );
                        continue;
                    }
                    Err(e) => {
                        let _ = tx.rollback().await;
                        let msg = format_gc_error("re-check orphan", &storage_key, &e.to_string());
                        tracing::warn!("{}", msg);
                        result.errors.push(msg);
                        continue;
                    }
                }

                // Storage delete is not transactional, but it happens while
                // the row lock is still held by `tx`. A racing pusher cannot
                // begin re-using this storage key until we commit/rollback.
                // An already-absent object is treated as success (#1660) so a
                // retry after a crash mid-delete still reclaims the soft-deleted
                // row instead of erroring every pass — matching the cloud
                // backends' NotFound→Ok mapping.
                match storage.delete(&storage_key).await {
                    Ok(()) | Err(AppError::NotFound(_)) => {}
                    Err(e) => {
                        let _ = tx.rollback().await;
                        let msg =
                            format_gc_error("delete storage key", &storage_key, &e.to_string());
                        tracing::warn!("{}", msg);
                        result.errors.push(msg);
                        // Skip DB cleanup if storage delete fails
                        continue;
                    }
                }

                // Delete promotion_approvals (no CASCADE on this FK)
                if let Err(e) = sqlx::query(
                    r#"
                    DELETE FROM promotion_approvals
                    WHERE artifact_id IN (
                        SELECT id FROM artifacts
                        WHERE storage_key = $1 AND is_deleted = true
                    )
                    "#,
                )
                .bind(&storage_key)
                .execute(&mut *tx)
                .await
                {
                    let _ = tx.rollback().await;
                    let msg =
                        format_gc_error("delete promotion_approvals", &storage_key, &e.to_string());
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }

                // Hard-delete artifact records (cascades to child tables)
                if let Err(e) = sqlx::query(
                    "DELETE FROM artifacts WHERE storage_key = $1 AND is_deleted = true",
                )
                .bind(&storage_key)
                .execute(&mut *tx)
                .await
                {
                    let _ = tx.rollback().await;
                    let msg =
                        format_gc_error("hard-delete artifacts", &storage_key, &e.to_string());
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }

                // Row-less Maven checksum sidecars (`.md5`, `.sha1`, ...) are
                // written with no `artifacts` row of their own, so this sweep
                // never enumerates them; reclaim them together with their base
                // object or they leak on storage forever (#2668). A failure
                // here rolls the key back: the base storage delete is already
                // idempotent (NotFound => Ok), so the next pass retries the
                // whole key and the invariant stays "a reclaimed Maven key
                // takes its sidecars with it".
                if let Err(e) = reclaim_maven_sidecars(
                    &mut tx,
                    storage.as_ref(),
                    &storage_key,
                    &storage_backend,
                )
                .await
                {
                    let _ = tx.rollback().await;
                    let msg =
                        format_gc_error("delete maven sidecars", &storage_key, &e.to_string());
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }

                if let Err(e) = tx.commit().await {
                    let msg = format_gc_error("commit gc tx", &storage_key, &e.to_string());
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }

                record_gc_success(&mut result, bytes, count);
            }
        }

        // Run each OCI cleanup sweep independently so a failure in one does
        // not skip the others. Each sweep already isolates per-key errors
        // into `result.errors`; here we capture a failure of the sweep's
        // own setup query (e.g. the candidate SELECT) the same way instead
        // of `?`-propagating out of run_gc and aborting later sweeps.
        if let Err(e) = self
            .cleanup_abandoned_oci_uploads(repo_scope, dry_run, &mut result)
            .await
        {
            let msg = format_gc_error(
                "run abandoned OCI upload cleanup",
                "<sweep>",
                &e.to_string(),
            );
            tracing::warn!("{}", msg);
            result.errors.push(msg);
        }
        if let Err(e) = self
            .cleanup_unreferenced_oci_upload_keys(repo_scope, dry_run, &mut result)
            .await
        {
            let msg = format_gc_error(
                "run unreferenced OCI upload cleanup-key sweep",
                "<sweep>",
                &e.to_string(),
            );
            tracing::warn!("{}", msg);
            result.errors.push(msg);
        }
        if let Err(e) = self
            .reap_pending_oci_upload_cleanup_keys(repo_scope, dry_run, &mut result)
            .await
        {
            let msg = format_gc_error(
                "run pending OCI upload cleanup-key reaper",
                "<sweep>",
                &e.to_string(),
            );
            tracing::warn!("{}", msg);
            result.errors.push(msg);
        }
        if let Err(e) = self
            .cleanup_orphan_maven_flat_objects(repo_scope, dry_run, &mut result)
            .await
        {
            let msg = format_gc_error(
                "run orphan Maven flat-object sweep",
                "<sweep>",
                &e.to_string(),
            );
            tracing::warn!("{}", msg);
            result.errors.push(msg);
        }

        if result.storage_keys_deleted > 0 {
            tracing::info!(
                "Storage GC: deleted {} keys, removed {} artifacts, freed {} bytes",
                result.storage_keys_deleted,
                result.artifacts_removed,
                result.bytes_freed
            );
        }

        Ok(result)
    }

    /// Reclaim OCI blob layers that no live manifest references (#1408).
    ///
    /// Deletion design originated in #1409; this rebuilds it on top of the
    /// merged `manifest_blob_refs` table + backfill (#1641/#1635).
    ///
    /// Iterates `oci_blobs` rows whose digest has zero matching rows in
    /// `manifest_blob_refs` and deletes both the storage object and the DB
    /// row.
    ///
    /// The orphan predicate is **backend-aware** (see
    /// [`BLOB_PROTECTED_BY_REFS_SQL`]). Blob storage is content-addressed
    /// under `oci-blobs/<digest>`: on cloud backends (S3/Azure/GCS) that
    /// key is one shared object across every repo on the bucket, so a
    /// reference from ANY same-backend repo protects it and orphan-ness is
    /// scoped per digest cross-repo — deleting per `(repo, digest)` would
    /// destroy a blob other repos still serve (`BLOB_UNKNOWN` on pull). On
    /// filesystem each repo roots its own tree, so the key is a distinct
    /// file per repo and orphan-ness is scoped to the same `storage_path`.
    /// This mirrors the cloud/filesystem branch of `ORPHAN_PREDICATE_SQL`.
    ///
    /// Grace period (`MIN_BLOB_AGE_SECS`) shields in-flight pushes: a
    /// client first uploads blobs, then PUTs the manifest, which writes the
    /// matching `manifest_blob_refs` rows. Between those two steps the blob
    /// is "orphan" in the strict sense; skipping rows younger than the
    /// grace period covers the typical push window without serializing push
    /// throughput on a global lock.
    ///
    /// Deletion is **two-phase mark-and-sweep** (#1660): [`run_blob_gc_mark`]
    /// stamps `pending_delete_at` on aged orphan candidates under a per-row
    /// `FOR UPDATE` lock (no storage I/O), and [`run_blob_gc_sweep`] later
    /// deletes the storage object then the row (still under the lock) for
    /// blobs marked past the sweep-grace window and still orphan. The mark and
    /// the push-path resurrection (which clears the marker) serialize on the
    /// same `oci_blobs` row lock the push takes (#1610/#2190), so a blob
    /// re-adopted in the mark→sweep window is un-marked and skipped by the
    /// sweep — closing the commit-then-delete TOCTOU without moving storage
    /// deletion outside a row lock. This convenience wrapper runs both phases
    /// back-to-back with a zero sweep-grace so a single call still reclaims an
    /// aged orphan; the scheduler drives the phases on independent cadences
    /// with a real grace window.
    ///
    /// SAFETY: callers (the scheduler) must additionally gate the live pass
    /// behind
    /// [`manifest_blob_refs_backfill::any_live_manifest_missing_refs`] and
    /// an explicit operator opt-in; this method itself only enforces the
    /// grace window and the per-row locked re-check. Every deletion is
    /// audit-logged at INFO with the digest and freed byte count.
    ///
    /// [`run_blob_gc_mark`]: Self::run_blob_gc_mark
    /// [`run_blob_gc_sweep`]: Self::run_blob_gc_sweep
    pub async fn run_blob_gc(&self, dry_run: bool) -> Result<StorageGcResult> {
        if dry_run {
            // Dry-run is strictly read-only: report the candidate orphan set
            // (Phase A's would-mark set) without writing or clearing any
            // marker and without any storage I/O.
            return self.run_blob_gc_mark(true).await;
        }

        // Apply mode: mark aged orphans, then immediately sweep with a zero
        // grace so a single call reclaims a steady orphan (the mark commits
        // before the sweep selects, so its `pending_delete_at` is already in
        // the past). The two passes go through the marker so the crash-safety
        // and push-resurrection invariants hold even on this combined path.
        let mark = self.run_blob_gc_mark(false).await?;
        let mut result = self.run_blob_gc_sweep(false, 0).await?;
        // Surface any marking errors alongside the sweep's. The reclaimed
        // counters stay the sweep's (marking deletes nothing), so
        // `storage_keys_deleted` keeps meaning "objects actually removed".
        result.errors.extend(mark.errors);
        Ok(result)
    }

    /// Phase A of two-phase blob GC — **mark**. Selects aged orphan
    /// candidates ([`select_orphan_blobs`]) and, under the same per-row
    /// `FOR UPDATE` lock the push path takes (#1610/#2190), re-checks
    /// orphan-ness and stamps `pending_delete_at = NOW()`. It performs **no
    /// storage I/O**: the object stays present, so a marked-but-not-yet-swept
    /// blob is never a dangling reference, and the blob is orphan so nothing
    /// pulls it anyway.
    ///
    /// A concurrent re-push that re-adopts a marked blob clears the marker
    /// under the same lock (`persist_tag_and_refs` / finalize
    /// `ON CONFLICT DO UPDATE`, #1660 PR1), so a blob that becomes live again
    /// is resurrected and the later sweep skips it. Marking and resurrection
    /// therefore strictly serialize on the row lock, which is what lets the
    /// sweep keep storage deletion under a normal row lock without reopening
    /// the commit-then-delete TOCTOU. `pending_delete_at IS NULL` in the mark
    /// UPDATE keeps an existing (older) mark's timestamp, so the sweep grace
    /// is measured from the first mark and a re-mark is a no-op.
    ///
    /// Dry-run reports the candidate set and writes nothing.
    ///
    /// [`select_orphan_blobs`]: Self::select_orphan_blobs
    pub async fn run_blob_gc_mark(&self, dry_run: bool) -> Result<StorageGcResult> {
        // Apply mode: first prune `manifest_blob_refs` of manifests that are no
        // longer live (tag overwrite / lifecycle expiry / index or manifest
        // deletion), so their config + layer blobs become eligible in this same
        // pass (#1409 H1). Without this the protect predicate keeps a digest
        // pinned forever once any manifest referenced it, even after every
        // referencing manifest is gone. Dry-run stays strictly read-only and so
        // reports the pre-prune orphan set only.
        if !dry_run {
            match self.prune_orphan_blob_refs().await {
                Ok(pruned) if pruned > 0 => {
                    tracing::info!("Blob GC: pruned {} stale manifest_blob_refs rows", pruned);
                }
                Ok(_) => {}
                Err(e) => tracing::warn!("Blob GC: manifest_blob_refs prune failed: {}", e),
            }
        }

        let orphans = self.select_orphan_blobs().await?;

        let mut result = empty_gc_result(dry_run);

        if dry_run {
            for row in &orphans {
                let digest: String = row.try_get("digest").unwrap_or_default();
                let bytes: i64 = row.try_get("size_bytes").unwrap_or(0);
                tracing::info!(
                    digest = digest.as_str(),
                    size_bytes = bytes,
                    "Blob GC (dry-run): would mark orphan blob for deletion"
                );
                accumulate_dry_run(&mut result, bytes, 1);
            }
            return Ok(result);
        }

        for row in &orphans {
            let digest: String = row.try_get("digest").unwrap_or_default();
            let storage_key: String = row.try_get("storage_key").unwrap_or_default();
            let repository_id: Uuid = match row.try_get("repository_id") {
                Ok(v) => v,
                Err(e) => {
                    let msg = format_gc_error("read repo id", &digest, &e.to_string());
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }
            };
            let bytes: i64 = row.try_get("size_bytes").unwrap_or(0);

            let mut tx = match self.db.begin().await {
                Ok(t) => t,
                Err(e) => {
                    let msg =
                        format_gc_error("begin blob gc mark tx", &storage_key, &e.to_string());
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }
            };

            // Re-check orphan-ness under the per-row `FOR UPDATE` lock so a
            // concurrent push that just referenced this blob is observed and
            // the blob is not marked (mark phase ignores the marker itself).
            match is_blob_still_orphan(&mut tx, repository_id, &digest, false).await {
                Ok(true) => {}
                Ok(false) => {
                    let _ = tx.rollback().await;
                    tracing::debug!(
                        digest = digest.as_str(),
                        "Blob GC mark skipped digest: no longer orphan after row-lock re-check"
                    );
                    continue;
                }
                Err(e) => {
                    let _ = tx.rollback().await;
                    let msg = format_gc_error("re-check blob orphan", &storage_key, &e.to_string());
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }
            }

            // Stamp the marker while still holding the lock. No storage I/O.
            // `pending_delete_at IS NULL` keeps an existing (earlier) mark's
            // timestamp untouched, so the sweep grace is always measured from
            // the FIRST mark and a re-mark affects zero rows — we only count /
            // log a blob that was NEWLY marked this pass.
            let newly_marked = match sqlx::query(
                r#"
                UPDATE oci_blobs
                SET pending_delete_at = NOW()
                WHERE repository_id = $1
                  AND digest = $2
                  AND pending_delete_at IS NULL
                "#,
            )
            .bind(repository_id)
            .bind(&digest)
            .execute(&mut *tx)
            .await
            {
                Ok(res) => res.rows_affected() > 0,
                Err(e) => {
                    let _ = tx.rollback().await;
                    let msg =
                        format_gc_error("mark blob pending delete", &storage_key, &e.to_string());
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }
            };

            if let Err(e) = tx.commit().await {
                let msg = format_gc_error("commit blob gc mark tx", &storage_key, &e.to_string());
                tracing::warn!("{}", msg);
                result.errors.push(msg);
                continue;
            }

            if newly_marked {
                tracing::debug!(
                    digest = digest.as_str(),
                    size_bytes = bytes,
                    "Blob GC: marked orphan blob pending deletion"
                );
                record_gc_success(&mut result, bytes, 1);
            }
        }

        Ok(result)
    }

    /// Phase B of two-phase blob GC — **sweep**. Deletes blobs marked
    /// (`pending_delete_at`) at least `sweep_grace_secs` ago that are STILL
    /// orphan ([`select_pending_delete_blobs`]). For each row, under the same
    /// per-row `FOR UPDATE` lock the push path and Phase A take, it re-checks
    /// that the blob is still marked AND still orphan, deletes the storage
    /// object (idempotent — `NotFound` is treated as success, #1660 PR1), then
    /// deletes the row, then commits.
    ///
    /// Storage deletion runs UNDER the row lock, so a concurrent re-push
    /// either cleared the marker before this sweep locked the row (the
    /// re-check then skips the now-live blob) or blocks on the lock and, once
    /// the sweep commits the row delete, re-inserts a fresh row with
    /// `pending_delete_at = NULL` — not eligible for a sweep until re-marked.
    /// A crash between the storage delete and the row delete leaves the row
    /// marked and the object gone; because the blob is orphan nothing pulls
    /// it, and the next sweep re-runs the (idempotent) storage delete and
    /// removes the row — a re-collectable orphan, never a live dangling
    /// reference.
    ///
    /// Dry-run reports the sweepable set and deletes nothing.
    ///
    /// [`select_pending_delete_blobs`]: Self::select_pending_delete_blobs
    pub async fn run_blob_gc_sweep(
        &self,
        dry_run: bool,
        sweep_grace_secs: i64,
    ) -> Result<StorageGcResult> {
        let pending = self.select_pending_delete_blobs(sweep_grace_secs).await?;

        let mut result = empty_gc_result(dry_run);

        if dry_run {
            for row in &pending {
                let digest: String = row.try_get("digest").unwrap_or_default();
                let bytes: i64 = row.try_get("size_bytes").unwrap_or(0);
                tracing::info!(
                    digest = digest.as_str(),
                    size_bytes = bytes,
                    "Blob GC (dry-run): would sweep marked orphan blob"
                );
                accumulate_dry_run(&mut result, bytes, 1);
            }
            return Ok(result);
        }

        for row in &pending {
            let digest: String = row.try_get("digest").unwrap_or_default();
            let storage_key: String = row.try_get("storage_key").unwrap_or_default();
            let storage_backend: String = row.try_get("storage_backend").unwrap_or_default();
            let storage_path: String = row.try_get("storage_path").unwrap_or_default();
            let repository_id: Uuid = match row.try_get("repository_id") {
                Ok(v) => v,
                Err(e) => {
                    let msg = format_gc_error("read repo id", &digest, &e.to_string());
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }
            };
            let bytes: i64 = row.try_get("size_bytes").unwrap_or(0);

            let location = StorageLocation {
                backend: storage_backend.clone(),
                path: storage_path.clone(),
            };
            let storage = match self.storage_for_location(&location) {
                Ok(s) => s,
                Err(e) => {
                    let msg = format_gc_error("resolve storage", &storage_key, &e.to_string());
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }
            };

            let mut tx = match self.db.begin().await {
                Ok(t) => t,
                Err(e) => {
                    let msg =
                        format_gc_error("begin blob gc sweep tx", &storage_key, &e.to_string());
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }
            };

            // Re-check UNDER the lock that the blob is still marked AND still
            // orphan. `require_pending = true` makes a blob whose marker a
            // concurrent push cleared (resurrection) fail the check, so the
            // sweep skips it and the now-live blob survives.
            match is_blob_still_orphan(&mut tx, repository_id, &digest, true).await {
                Ok(true) => {}
                Ok(false) => {
                    let _ = tx.rollback().await;
                    tracing::debug!(
                        digest = digest.as_str(),
                        "Blob GC sweep skipped digest: resurrected or no longer orphan after \
                         row-lock re-check"
                    );
                    continue;
                }
                Err(e) => {
                    let _ = tx.rollback().await;
                    let msg = format_gc_error("re-check blob sweep", &storage_key, &e.to_string());
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }
            }

            // Storage delete first, still under the row lock. Deleting an
            // already-absent object is success (#1660): a retry after a crash
            // between this delete and the row delete must reclaim the marked
            // orphan, not roll back forever and leak it. The cloud backends
            // already map NotFound to Ok (s3.rs, gcs.rs, azure.rs); the
            // filesystem backend returns NotFound, so tolerate it here too.
            match storage.delete(&storage_key).await {
                Ok(()) | Err(AppError::NotFound(_)) => {}
                Err(e) => {
                    let _ = tx.rollback().await;
                    let msg = format_gc_error("delete blob storage", &storage_key, &e.to_string());
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }
            }

            // Delete only while still marked: belt-and-suspenders against ever
            // removing a resurrected (un-marked) row. We hold the lock and the
            // re-check already proved the marker is set, so this always
            // matches here; it also makes the DELETE self-documenting.
            if let Err(e) = sqlx::query(
                "DELETE FROM oci_blobs \
                 WHERE repository_id = $1 AND digest = $2 AND pending_delete_at IS NOT NULL",
            )
            .bind(repository_id)
            .bind(&digest)
            .execute(&mut *tx)
            .await
            {
                let _ = tx.rollback().await;
                let msg = format_gc_error("delete oci_blobs row", &storage_key, &e.to_string());
                tracing::warn!("{}", msg);
                result.errors.push(msg);
                continue;
            }

            if let Err(e) = tx.commit().await {
                let msg = format_gc_error("commit blob gc sweep tx", &storage_key, &e.to_string());
                tracing::warn!("{}", msg);
                result.errors.push(msg);
                continue;
            }

            // Audit log: every committed blob deletion is recorded with its
            // digest and freed bytes. Blob deletion is irreversible, so this
            // trail is the operator's record of exactly what GC reclaimed.
            tracing::info!(
                digest = digest.as_str(),
                size_bytes = bytes,
                storage_key = storage_key.as_str(),
                "Blob GC: swept marked orphan blob"
            );
            record_gc_success(&mut result, bytes, 1);
        }

        if result.storage_keys_deleted > 0 {
            tracing::info!(
                "Blob GC: swept {} blob objects, freed {} bytes",
                result.storage_keys_deleted,
                result.bytes_freed
            );
        }

        Ok(result)
    }

    /// Delete `manifest_blob_refs` rows whose manifest is no longer live, so
    /// the blobs they pinned become reclaimable (#1409 H1).
    ///
    /// A ref is stale when its `manifest_digest` is neither tagged in its repo
    /// (`oci_tags`) nor a live per-architecture child of a tagged index
    /// (`oci_manifest_refs` -> tagged `parent_digest`). Tag overwrite, lifecycle
    /// expiry and manifest/index deletion all leave such orphan refs behind;
    /// without pruning them [`BLOB_PROTECTED_BY_REFS_SQL`] would protect the
    /// digest forever. Conservative: any still-reachable manifest keeps its
    /// refs, so this can only ever over-protect (a leak), never expose a live
    /// blob.
    async fn prune_orphan_blob_refs(&self) -> Result<u64> {
        let res = sqlx::query(
            r#"
            DELETE FROM manifest_blob_refs mbr
            WHERE NOT EXISTS (
                SELECT 1 FROM oci_tags ot
                WHERE ot.repository_id = mbr.repository_id
                  AND ot.manifest_digest = mbr.manifest_digest
            )
            AND NOT EXISTS (
                SELECT 1 FROM oci_manifest_refs omr
                JOIN oci_tags ot2
                  ON ot2.repository_id = omr.repository_id
                 AND ot2.manifest_digest = omr.parent_digest
                WHERE omr.repository_id = mbr.repository_id
                  AND omr.child_digest = mbr.manifest_digest
            )
            "#,
        )
        .execute(&self.db)
        .await
        .map_err(|e| crate::error::AppError::Database(e.to_string()))?;
        Ok(res.rows_affected())
    }

    /// List `oci_blobs` rows older than the grace period whose digest is
    /// not protected by any in-scope `manifest_blob_refs` row
    /// ([`BLOB_PROTECTED_BY_REFS_SQL`]: cloud backends protect cross-repo on
    /// the shared bucket; filesystem protects only within the same
    /// `storage_path`). The grace period is the only safeguard against the
    /// push-time race described on [`Self::run_blob_gc`].
    async fn select_orphan_blobs(&self) -> Result<Vec<sqlx::postgres::PgRow>> {
        let sql = format!(
            r#"
            SELECT ob.repository_id,
                   ob.digest,
                   ob.size_bytes,
                   ob.storage_key,
                   r.storage_backend,
                   r.storage_path
            FROM oci_blobs ob
            JOIN repositories r ON r.id = ob.repository_id
            WHERE ob.created_at < NOW() - make_interval(secs => $1::BIGINT)
              AND NOT {protected}
            "#,
            protected = BLOB_PROTECTED_BY_REFS_SQL,
        );
        sqlx::query(&sql)
            .bind(MIN_BLOB_AGE_SECS as i64)
            .fetch_all(&self.db)
            .await
            .map_err(|e| crate::error::AppError::Database(e.to_string()))
    }

    /// Phase B selection: `oci_blobs` rows marked `pending_delete_at` at least
    /// `sweep_grace_secs` in the past that are STILL orphan (no in-scope
    /// `manifest_blob_refs`). Reuses [`BLOB_PROTECTED_BY_REFS_SQL`] so the
    /// sweep predicate cannot drift from the mark/scan predicate. The
    /// sweep-grace window is a second safety margin after the mark: it gives a
    /// re-push time to resurrect a blob (clear the marker) before its storage
    /// object is deleted. The per-row locked re-check ([`is_blob_still_orphan`]
    /// with the marker clause) remains the authoritative gate; this scan only
    /// narrows the candidate set, and the partial index
    /// `oci_blobs_pending_delete_idx` keeps it off the healthy, unmarked rows.
    async fn select_pending_delete_blobs(
        &self,
        sweep_grace_secs: i64,
    ) -> Result<Vec<sqlx::postgres::PgRow>> {
        let sql = format!(
            r#"
            SELECT ob.repository_id,
                   ob.digest,
                   ob.size_bytes,
                   ob.storage_key,
                   r.storage_backend,
                   r.storage_path
            FROM oci_blobs ob
            JOIN repositories r ON r.id = ob.repository_id
            WHERE ob.pending_delete_at IS NOT NULL
              AND ob.pending_delete_at < NOW() - make_interval(secs => $1::BIGINT)
              AND NOT {protected}
            "#,
            protected = BLOB_PROTECTED_BY_REFS_SQL,
        );
        sqlx::query(&sql)
            .bind(sweep_grace_secs)
            .fetch_all(&self.db)
            .await
            .map_err(|e| crate::error::AppError::Database(e.to_string()))
    }

    /// Initial scan that lists candidate orphan storage keys.
    ///
    /// This is a snapshot of the orphan set at one point in time. Each
    /// candidate is re-checked under a row-level lock by
    /// [`is_still_orphan`] before deletion so that pushes landing between
    /// this scan and the per-key delete cannot get their references
    /// silently dropped (#1180).
    ///
    /// Visibility is `pub(crate)` so that unit tests in the same crate can
    /// inspect the candidate set per-storage-key. The dry-run regression
    /// tests (#1490 / #1493) cannot assert on the global
    /// `storage_keys_deleted` counter because concurrent integration tests
    /// share the same Postgres database, and a peer test's in-flight
    /// orphan row would inflate that counter. Asserting per-key against
    /// this candidate list keeps each test isolated from its neighbors.
    /// `repo_scope` (`Some(id)`) restricts the scan to soft-deleted artifacts
    /// owned by that repository (web #708); the orphan predicate itself stays
    /// instance-wide, so a scoped scan can only ever *narrow* the candidate
    /// set, never admit a key the instance-wide scan would protect.
    pub(crate) async fn select_orphans(
        &self,
        repo_scope: Option<Uuid>,
    ) -> Result<Vec<sqlx::postgres::PgRow>> {
        let sql = format!(
            r#"
            SELECT a.storage_key, r.storage_backend, r.storage_path,
                   SUM(a.size_bytes) as total_bytes,
                   COUNT(*) as artifact_count
            FROM artifacts a
            JOIN repositories r ON r.id = a.repository_id
            WHERE {predicate}
              {scope}
            GROUP BY a.storage_key, r.storage_backend, r.storage_path
            "#,
            predicate = ORPHAN_PREDICATE_SQL,
            scope = repo_scope_clause("a.repository_id", 1, repo_scope),
        );
        let mut query = sqlx::query(&sql);
        if let Some(id) = repo_scope {
            query = query.bind(id);
        }
        query
            .fetch_all(&self.db)
            .await
            .map_err(|e| crate::error::AppError::Database(e.to_string()))
    }

    /// Build the read-only OCI blob footprint report (issue #1408).
    ///
    /// Performs only `SELECT` aggregates against `oci_blobs` (joined to
    /// `repositories` for backend/path scoping); it never deletes
    /// anything, takes no row locks, and touches no storage backend. Safe
    /// to call on a hot production database.
    ///
    /// `grace_hours` is clamped to a sane range via
    /// [`clamp_grace_hours`]; the clamped value is echoed back in the
    /// report so callers see exactly what window was applied.
    pub async fn oci_blob_footprint_report(
        &self,
        grace_hours: i64,
    ) -> Result<OciBlobFootprintReport> {
        let grace_hours = clamp_grace_hours(grace_hours);

        // Aggregate 1: global totals + dedup-aware physical bytes + aged
        // figures, all in one pass. The production report is always
        // cluster-wide (`digest_scope: None`); see
        // [`Self::fetch_blob_footprint_totals`] for the semantics and for
        // why a scoped mode exists at all.
        let totals = self.fetch_blob_footprint_totals(grace_hours, None).await?;

        // Aggregate 2: per-repository logical footprint, biggest first.
        let per_repo_sql = r#"
            SELECT repository_id,
                   COUNT(*) AS blob_rows,
                   COALESCE(SUM(size_bytes), 0)::BIGINT AS logical_bytes
            FROM oci_blobs
            GROUP BY repository_id
            ORDER BY logical_bytes DESC, repository_id ASC
        "#;
        let per_repo_rows = sqlx::query(per_repo_sql)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        let per_repository = per_repo_rows
            .into_iter()
            .map(|row| {
                let repository_id = row
                    .try_get("repository_id")
                    .map_err(|e| AppError::Database(e.to_string()))?;
                Ok(map_repo_footprint(
                    repository_id,
                    decode_report_i64(&row, "blob_rows")?,
                    decode_report_i64(&row, "logical_bytes")?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(assemble_blob_footprint_report(
            totals,
            grace_hours,
            per_repository,
        ))
    }

    /// Fetch the totals block of the OCI blob footprint report.
    ///
    /// Physical identity mirrors [`BLOB_PROTECTED_BY_REFS_SQL`] (and
    /// `StorageRegistry::backend_is_repo_isolated`): on shared backends
    /// (anything other than 'filesystem') the content-addressed key
    /// `oci-blobs/<digest>` resolves to ONE object per backend, so a
    /// digest counts once per backend; on 'filesystem' every repository
    /// roots its own tree at `storage_path`, so the same digest under
    /// two paths is two real files and must count twice. `per_object`
    /// therefore groups by (digest, backend, path-if-filesystem);
    /// `size_bytes` is MAX within a group (rows for the same digest
    /// share a size) and `first_seen` is the group's oldest row.
    /// `distinct_digests` stays digest-level (content identities),
    /// independent of how many physical copies exist; counting it over
    /// `per_object` equals counting over the scoped rows directly (the
    /// NOT NULL `repository_id` FK means the join drops no rows) and
    /// saves a fourth scan of the table.
    ///
    /// DELIBERATE: rows with `pending_delete_at IS NOT NULL` (the
    /// mark-and-sweep marker, migration 141) are INCLUDED in every
    /// figure — marked-but-not-yet-swept bytes are still physically on
    /// disk, and this is a footprint view. Do not "fix" by excluding
    /// them.
    ///
    /// `grace_hours` binds as int8, but `make_interval` only defines int4
    /// named parameters, so the SQL must cast `$1::int` or Postgres
    /// rejects the call outright (#2626). Safe: [`clamp_grace_hours`] caps
    /// the value at 8760 (callers pass the already-clamped value). The
    /// SUM(...) columns need `::BIGINT` because SUM over bigint yields
    /// NUMERIC, which the i64 decodes below reject — and a failed decode
    /// is a hard error (propagated), never a silent zero.
    ///
    /// `digest_scope`: `None` aggregates the whole cluster — the only
    /// mode the production report uses. `Some(digests)` restricts every
    /// figure to rows whose digest is in the given set. The scoped mode
    /// exists for the DB-backed regression test (#3129): the test
    /// database is shared by the entire `cargo nextest` run
    /// (process-per-test), so a before/after delta over cluster-wide
    /// totals races every concurrent suite that inserts or deletes
    /// `oci_blobs` rows. Scoping to the test's own UUID-derived
    /// (collision-free) digests makes the expected figures exact and
    /// deterministic while still exercising this very statement — the
    /// scoped and unscoped paths share ONE SQL string, so the grouping,
    /// dedup and age logic the test pins is the logic the report ships.
    async fn fetch_blob_footprint_totals(
        &self,
        grace_hours: i64,
        digest_scope: Option<&[String]>,
    ) -> Result<BlobFootprintTotals> {
        let totals_sql = r#"
            WITH scoped AS (
                SELECT digest, size_bytes, created_at, repository_id
                FROM oci_blobs
                WHERE $2::text[] IS NULL OR digest = ANY($2)
            ),
            per_object AS (
                SELECT ob.digest,
                       MAX(ob.size_bytes) AS size_bytes,
                       MIN(ob.created_at) AS first_seen
                FROM scoped ob
                JOIN repositories r ON r.id = ob.repository_id
                GROUP BY ob.digest,
                         r.storage_backend,
                         CASE WHEN r.storage_backend = 'filesystem'
                              THEN r.storage_path ELSE '' END
            )
            SELECT
                (SELECT COUNT(*) FROM scoped)                          AS total_blob_rows,
                (SELECT COALESCE(SUM(size_bytes), 0)::BIGINT
                   FROM scoped)                                        AS logical_bytes,
                COUNT(DISTINCT digest)                                 AS distinct_digests,
                COALESCE(SUM(size_bytes), 0)::BIGINT                   AS physical_bytes,
                COUNT(DISTINCT digest) FILTER (
                    WHERE first_seen < NOW() - make_interval(hours => $1::int)
                )                                                      AS aged_distinct_digests,
                COALESCE(SUM(size_bytes) FILTER (
                    WHERE first_seen < NOW() - make_interval(hours => $1::int)
                ), 0)::BIGINT                                          AS aged_physical_bytes
            FROM per_object
        "#;

        let totals = sqlx::query(totals_sql)
            .bind(grace_hours)
            .bind(digest_scope)
            .fetch_one(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(BlobFootprintTotals {
            total_blob_rows: decode_report_i64(&totals, "total_blob_rows")?,
            distinct_digests: decode_report_i64(&totals, "distinct_digests")?,
            logical_bytes: decode_report_i64(&totals, "logical_bytes")?,
            physical_bytes: decode_report_i64(&totals, "physical_bytes")?,
            aged_distinct_digests: decode_report_i64(&totals, "aged_distinct_digests")?,
            aged_physical_bytes: decode_report_i64(&totals, "aged_physical_bytes")?,
        })
    }

    async fn cleanup_abandoned_oci_uploads(
        &self,
        repo_scope: Option<Uuid>,
        dry_run: bool,
        result: &mut StorageGcResult,
    ) -> Result<()> {
        let session_ids = self
            .select_abandoned_oci_upload_session_ids(repo_scope)
            .await?;
        let mut sessions_removed = 0_i64;
        let mut upload_keys_deleted = 0_i64;

        for session_id in session_ids {
            let mut tx = match self.db.begin().await {
                Ok(t) => t,
                Err(e) => {
                    let msg = format_gc_error(
                        "begin abandoned OCI upload cleanup tx",
                        &session_id.to_string(),
                        &e.to_string(),
                    );
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }
            };

            let session = match lock_abandoned_oci_upload_session(&mut tx, session_id).await {
                Ok(Some(session)) => session,
                Ok(None) => {
                    let _ = tx.rollback().await;
                    continue;
                }
                Err(e) => {
                    let _ = tx.rollback().await;
                    let msg = format_gc_error(
                        "lock abandoned OCI upload session",
                        &session_id.to_string(),
                        &e.to_string(),
                    );
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }
            };

            if dry_run {
                let _ = tx.rollback().await;
                result.storage_keys_deleted += session.storage_keys.len() as i64;
                result.bytes_freed += session.bytes_received.max(0);
                continue;
            }

            let storage = match self.storage_for_location(&session.location) {
                Ok(s) => s,
                Err(e) => {
                    let _ = tx.rollback().await;
                    let msg = format_gc_error(
                        "resolve abandoned OCI upload storage",
                        &session.id.to_string(),
                        &e.to_string(),
                    );
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }
            };

            let mut delete_failed = false;
            for key in &session.storage_keys {
                match storage.delete(key).await {
                    Ok(()) | Err(AppError::NotFound(_)) => {}
                    Err(e) => {
                        let msg = format_gc_error(
                            "delete abandoned OCI upload storage key",
                            key,
                            &e.to_string(),
                        );
                        tracing::warn!("{}", msg);
                        result.errors.push(msg);
                        delete_failed = true;
                    }
                }
            }
            if delete_failed {
                let _ = tx.rollback().await;
                continue;
            }

            if let Err(e) = sqlx::query("DELETE FROM oci_upload_sessions WHERE id = $1")
                .bind(session.id)
                .execute(&mut *tx)
                .await
            {
                let _ = tx.rollback().await;
                let msg = format_gc_error(
                    "delete abandoned OCI upload session",
                    &session.id.to_string(),
                    &e.to_string(),
                );
                tracing::warn!("{}", msg);
                result.errors.push(msg);
                continue;
            }

            // NOTE: we intentionally do NOT delete this session's
            // oci_upload_cleanup_keys rows here. This sweep only deletes the
            // session's temp + part objects (session.storage_keys); the
            // final-part / completion-temp objects left by a failed completion
            // attempt are journaled under this session but are NOT in
            // session.storage_keys (they were never inserted into
            // oci_upload_parts), so they are reaped by the unreferenced-key
            // sweep instead. Deleting the journal rows here would remove their
            // only owner and strand those objects forever. The cost is that the
            // unreferenced sweep re-issues a now-NotFound delete for the
            // already-removed temp/part keys (a benign metrics double-count).
            if let Err(e) = tx.commit().await {
                let msg = format_gc_error(
                    "commit abandoned OCI upload cleanup tx",
                    &session.id.to_string(),
                    &e.to_string(),
                );
                tracing::warn!("{}", msg);
                result.errors.push(msg);
                continue;
            }

            sessions_removed += 1;
            upload_keys_deleted += session.storage_keys.len() as i64;
            result.storage_keys_deleted += session.storage_keys.len() as i64;
            result.bytes_freed += session.bytes_received.max(0);
        }

        if sessions_removed > 0 {
            tracing::info!(
                "Storage GC: removed {} abandoned OCI upload sessions and deleted {} upload keys",
                sessions_removed,
                upload_keys_deleted
            );
        }

        Ok(())
    }

    async fn select_abandoned_oci_upload_session_ids(
        &self,
        repo_scope: Option<Uuid>,
    ) -> Result<Vec<Uuid>> {
        let sql = format!(
            r#"
            SELECT id
            FROM oci_upload_sessions
            WHERE updated_at < NOW() - {ttl}
              {scope}
            ORDER BY updated_at ASC
            LIMIT $1
            "#,
            ttl = ABANDONED_OCI_UPLOAD_TTL_SQL,
            scope = repo_scope_clause("repository_id", 2, repo_scope),
        );
        let mut query = sqlx::query(&sql).bind(ABANDONED_OCI_UPLOAD_SCAN_LIMIT);
        if let Some(id) = repo_scope {
            query = query.bind(id);
        }
        let rows = query
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        rows.into_iter()
            .map(|row| {
                row.try_get::<Uuid, _>("id")
                    .map_err(|e| AppError::Database(e.to_string()))
            })
            .collect()
    }

    async fn cleanup_unreferenced_oci_upload_keys(
        &self,
        repo_scope: Option<Uuid>,
        dry_run: bool,
        result: &mut StorageGcResult,
    ) -> Result<()> {
        // Dry-run scans must not write claims; a real sweep claims rows
        // (RowClaimedQueue) so concurrent replicas drain disjoint keys and
        // the external storage delete only ever runs under a live claim. Both
        // paths preserve the optional repository scope.
        let cleanup_keys = if dry_run {
            self.select_unreferenced_oci_upload_cleanup_keys(repo_scope)
                .await?
        } else {
            self.claim_unreferenced_oci_upload_cleanup_keys(repo_scope)
                .await?
        };
        let mut cleanup_rows_removed = 0_i64;

        for cleanup_key in cleanup_keys {
            if dry_run {
                result.storage_keys_deleted += 1;
                continue;
            }

            let storage = match self.storage_for_location(&cleanup_key.location) {
                Ok(s) => s,
                Err(e) => {
                    let msg = format_gc_error(
                        "resolve OCI upload cleanup-key storage",
                        &cleanup_key.storage_key,
                        &e.to_string(),
                    );
                    tracing::warn!("{}", msg);
                    self.release_cleanup_key_claim(&cleanup_key, &msg).await;
                    result.errors.push(msg);
                    continue;
                }
            };

            // PHASE 1 (#3187): re-assert ownership AND liveness and publish the
            // `pending_delete_at` tombstone, atomically, before touching
            // storage. Earlier keys in this batch may have taken long enough
            // that this row's claim lapsed and another replica's sweep now owns
            // it, or that a concurrent push committed an `oci_blobs` row for
            // this key and the object is live again (#3085). The tombstone is
            // what a racing push reads to know it must not commit; a push that
            // beat us to the row lock has already deleted the row, so this
            // matches nothing and we skip the delete.
            if !self
                .tombstone_cleanup_key_for_delete(&cleanup_key, CleanupSweepKind::Unreferenced)
                .await
            {
                tracing::info!(
                    storage_key = %cleanup_key.storage_key,
                    "cleanup-key claim lost or key became live mid-batch; skipping its storage delete"
                );
                continue;
            }

            match storage.delete(&cleanup_key.storage_key).await {
                Ok(()) | Err(AppError::NotFound(_)) => {}
                Err(e) => {
                    let msg = format_gc_error(
                        "delete OCI upload cleanup-key storage",
                        &cleanup_key.storage_key,
                        &e.to_string(),
                    );
                    tracing::warn!("{}", msg);
                    // Release the claim with the error recorded so the next
                    // sweep retries the storage delete.
                    self.release_cleanup_key_claim(&cleanup_key, &msg).await;
                    result.errors.push(msg);
                    continue;
                }
            }

            // PHASE 3 (#3187): reap the journal row. `pending_delete_at IS NOT
            // NULL` ties this to the tombstone phase 1 published, so the row we
            // remove is provably the one whose object we just deleted.
            let reaped = sqlx::query(
                r#"
                DELETE FROM oci_upload_cleanup_keys
                WHERE id = $1
                  AND claim_token = $2
                  AND pending_delete_at IS NOT NULL
                  AND storage_write_completed_at IS NOT NULL
                  -- Intentionally NOT guarded by `s.id = upload_session_id`
                  -- (unlike the pending reaper): a committed cleanup key is a
                  -- part / final-part / completion-temp key, never a session's
                  -- storage_temp_key. The part check below protects live PATCH
                  -- parts; the final-part / completion-temp objects left behind
                  -- by a FAILED completion attempt are genuine orphans even
                  -- while their session survives (it was reset to `open` for
                  -- retry), so they MUST be reapable without waiting for the
                  -- session to be abandoned. Adding the session-id branch here
                  -- would strand them until the 24h sweep.
                  AND NOT EXISTS (
                    SELECT 1 FROM oci_upload_sessions s
                    WHERE s.storage_temp_key = oci_upload_cleanup_keys.storage_key
                  )
                  AND NOT EXISTS (
                    SELECT 1 FROM oci_upload_parts p
                    WHERE p.storage_key = oci_upload_cleanup_keys.storage_key
                  )
                  -- A cleanup key may be a final `oci-blobs/<digest>` object
                  -- (journaled around the blob copy/commit so a failed
                  -- `oci_blobs` INSERT does not orphan it). Once an `oci_blobs`
                  -- row references the key the blob is live: never reap it, even
                  -- if a concurrent push committed the row after this writer's
                  -- own commit failed. This is the guard that makes journaling
                  -- the blob key safe against data loss.
                  AND NOT EXISTS (
                    SELECT 1 FROM oci_blobs b
                    WHERE b.storage_key = oci_upload_cleanup_keys.storage_key
                  )
                "#,
            )
            .bind(cleanup_key.id)
            .bind(cleanup_key.claim_token)
            .execute(&self.db)
            .await;

            let reaped = match reaped {
                Ok(r) => r,
                Err(e) => {
                    let msg = format_gc_error(
                        "delete OCI upload cleanup-key row",
                        &cleanup_key.storage_key,
                        &e.to_string(),
                    );
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }
            };

            // #3187: a zero-row match used to be counted as a clean success —
            // the sweep incremented both counters unconditionally — which is
            // precisely how a lost race made itself invisible. Phase 1 proved
            // this row was ours, tombstoned, and reclaimable, and the push side
            // can no longer remove a live tombstone, so a miss here is a real
            // anomaly: report it instead of banking it.
            if reaped.rows_affected() != 1 {
                let msg = format_gc_error(
                    "reap OCI upload cleanup-key row",
                    &cleanup_key.storage_key,
                    "tombstoned row vanished or stopped matching between the storage delete \
                     and its reap; the object was deleted but its journal row was not",
                );
                tracing::warn!("{}", msg);
                result.errors.push(msg);
                continue;
            }

            cleanup_rows_removed += 1;
            result.storage_keys_deleted += 1;
        }

        if cleanup_rows_removed > 0 {
            tracing::info!(
                "Storage GC: removed {} stale OCI upload cleanup-key rows",
                cleanup_rows_removed
            );
        }

        Ok(())
    }

    async fn select_unreferenced_oci_upload_cleanup_keys(
        &self,
        repo_scope: Option<Uuid>,
    ) -> Result<Vec<OciUploadCleanupKey>> {
        let sql = format!(
            r#"
            SELECT c.id, c.storage_key, c.claim_token, r.storage_backend, r.storage_path
            FROM oci_upload_cleanup_keys c
            JOIN repositories r ON r.id = c.repository_id
            WHERE c.storage_write_completed_at IS NOT NULL
              AND c.storage_write_completed_at < NOW() - {ttl}
              {scope}
              -- See the matching DELETE: a committed key (part/final/completion
              -- temp) is intentionally reapable even while its session lives,
              -- so this is NOT guarded by `s.id = c.upload_session_id`.
              AND NOT EXISTS (
                SELECT 1 FROM oci_upload_sessions s
                WHERE s.storage_temp_key = c.storage_key
              )
              AND NOT EXISTS (
                SELECT 1 FROM oci_upload_parts p
                WHERE p.storage_key = c.storage_key
              )
              -- Never select a key that a live `oci_blobs` row references: it is
              -- a committed blob, not an orphan. This candidate guard is only
              -- point-in-time — the object is deleted before the row DELETE
              -- re-asserts predicates, so a digest that goes live AFTER the
              -- scan is caught by `hold_cleanup_key_claim_for_delete`, which
              -- re-asserts this same predicate immediately before the
              -- destructive delete (#3085).
              AND NOT EXISTS (
                SELECT 1 FROM oci_blobs b
                WHERE b.storage_key = c.storage_key
              )
            ORDER BY c.created_at ASC
            LIMIT $1
            "#,
            ttl = ABANDONED_OCI_UPLOAD_TTL_SQL,
            scope = repo_scope_clause("c.repository_id", 2, repo_scope),
        );
        let mut query = sqlx::query(&sql).bind(OCI_UPLOAD_CLEANUP_KEY_SCAN_LIMIT);
        if let Some(id) = repo_scope {
            query = query.bind(id);
        }
        let rows = query
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        rows.into_iter()
            .map(|row| decode_oci_cleanup_key_row(&row))
            .collect()
    }

    /// Claim a batch of unreferenced cleanup keys for a destructive sweep
    /// (RowClaimedQueue, see [`crate::services::cluster_work`]).
    ///
    /// Same candidate predicates as
    /// [`Self::select_unreferenced_oci_upload_cleanup_keys`], plus: rows with
    /// a live claim are skipped (another replica's sweep owns them), and
    /// selected rows are stamped with a fresh token under
    /// FOR UPDATE SKIP LOCKED so concurrent sweeps drain disjoint keys. The
    /// storage delete runs only for returned rows; the row DELETE and the
    /// failure release must present the token.
    async fn claim_unreferenced_oci_upload_cleanup_keys(
        &self,
        repo_scope: Option<Uuid>,
    ) -> Result<Vec<OciUploadCleanupKey>> {
        let sql = format!(
            r#"
            WITH candidate AS (
                SELECT c.id
                FROM oci_upload_cleanup_keys c
                WHERE c.storage_write_completed_at IS NOT NULL
                  AND c.storage_write_completed_at < NOW() - {ttl}
                  AND (c.claim_expires_at IS NULL OR c.claim_expires_at <= NOW())
                  {scope}
                  AND NOT EXISTS (
                    SELECT 1 FROM oci_upload_sessions s
                    WHERE s.storage_temp_key = c.storage_key
                  )
                  AND NOT EXISTS (
                    SELECT 1 FROM oci_upload_parts p
                    WHERE p.storage_key = c.storage_key
                  )
                  AND NOT EXISTS (
                    SELECT 1 FROM oci_blobs b
                    WHERE b.storage_key = c.storage_key
                  )
                ORDER BY c.created_at ASC
                LIMIT $1
                FOR UPDATE OF c SKIP LOCKED
            )
            UPDATE oci_upload_cleanup_keys u
            SET claimed_by = $2,
                claim_token = gen_random_uuid(),
                claim_expires_at = NOW() + {claim_ttl}
            FROM candidate, repositories r
            WHERE u.id = candidate.id
              AND r.id = u.repository_id
            RETURNING u.id, u.storage_key, u.claim_token,
                      r.storage_backend, r.storage_path
            "#,
            ttl = ABANDONED_OCI_UPLOAD_TTL_SQL,
            claim_ttl = OCI_CLEANUP_KEY_CLAIM_TTL_SQL,
            scope = repo_scope_clause("c.repository_id", 3, repo_scope),
        );
        let mut query = sqlx::query(&sql)
            .bind(OCI_UPLOAD_CLEANUP_KEY_SCAN_LIMIT)
            .bind(crate::services::cluster_work::WorkerIdentity::for_process().as_str());
        if let Some(id) = repo_scope {
            query = query.bind(id);
        }
        let rows = query
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        rows.into_iter()
            .map(|row| decode_oci_cleanup_key_row(&row))
            .collect()
    }

    /// Token-guarded claim release after a failed storage delete: records the
    /// error and lapses the claim so the next sweep (on any replica) retries.
    async fn release_cleanup_key_claim(&self, cleanup_key: &OciUploadCleanupKey, error: &str) {
        let _ = sqlx::query(
            r#"
            UPDATE oci_upload_cleanup_keys
            SET last_error = $2, claim_expires_at = NOW()
            WHERE id = $1
              AND claim_token = $3
            "#,
        )
        .bind(cleanup_key.id)
        .bind(error)
        .bind(cleanup_key.claim_token)
        .execute(&self.db)
        .await;
    }

    /// **Phase 1 of the two-phase cleanup-key sweep (#3187).** Re-assert
    /// ownership **and liveness** for one cleanup key and, in the same atomic
    /// `UPDATE`, stamp `pending_delete_at` — the durable tombstone that tells
    /// the push path this key's bytes are about to be destroyed. Returns `true`
    /// only when the key is still this sweeper's, still reclaimable, and now
    /// tombstoned; the caller must skip the destructive delete otherwise.
    ///
    /// Two independent things can change between the claim and the delete:
    ///
    /// 1. **Ownership.** A claimed batch (up to
    ///    `OCI_UPLOAD_CLEANUP_KEY_SCAN_LIMIT` rows) walks its storage deletes
    ///    sequentially, and slow object-store deletes can outlive the fixed
    ///    claim TTL — a lapsed tail claim may then be re-claimed by another
    ///    replica's sweep while this one is still walking its list, letting
    ///    both attempt the same destructive delete.
    /// 2. **Liveness (#3085).** A digest re-pushed after this row was claimed
    ///    commits an `oci_blobs` row for the very same `storage_key`, so the
    ///    object is live again. The claim-time predicate is stale by then and
    ///    the sweep's guarded row `DELETE` re-checks liveness only *after* the
    ///    bytes are already gone — it saves the journal row, not the blob.
    ///
    /// # Why the tombstone, and why this closes the window
    ///
    /// #3158 performed the re-check here but nothing else, and was explicit
    /// that this only *narrowed* the race: the `UPDATE` runs on the pool as a
    /// single autocommit statement, so its row lock — on
    /// `oci_upload_cleanup_keys`, never on `oci_blobs` — is released the
    /// instant it commits, and the caller then deletes the object holding
    /// nothing. A push committing its `oci_blobs` row inside that gap still
    /// lost its bytes.
    ///
    /// It cannot be fixed on this side alone. The blob GC one layer down gets
    /// its guarantee from [`is_blob_still_orphan`] holding `SELECT ... FOR
    /// UPDATE` on the *`oci_blobs` row* across the storage delete, which works
    /// because a re-push of a marked blob `ON CONFLICT`s onto that existing
    /// row and blocks. Here the racing push **INSERTs a new** `oci_blobs` row,
    /// so there is no row to lock and `FOR UPDATE` on `oci_blobs` would lock
    /// nothing. The only object both sides already touch is this journal row,
    /// so the push has to participate — see
    /// [`claim_cleanup_journal_row_for_blob_commit`], which is the other half
    /// of this protocol and must be read with it.
    ///
    /// The two halves meet on this row's lock, and the tombstone is what makes
    /// the meeting decisive in both orders:
    ///
    /// * **Sweep first.** This `UPDATE` commits the tombstone. The push's
    ///   `SELECT ... FOR UPDATE` then sees `pending_delete_at` set with a live
    ///   claim and refuses to commit its `oci_blobs` row at all. The storage
    ///   delete destroys bytes nothing references.
    /// * **Push first.** The push holds `FOR UPDATE` on this row and deletes
    ///   it inside the same transaction that inserts `oci_blobs`. This
    ///   `UPDATE` blocks on that lock, and when it is released the row is
    ///   gone — zero rows affected, `false`, and the caller skips the storage
    ///   delete. The bytes survive.
    ///
    /// Neither side holds a lock across the object-store call, which is the
    /// reason this shape was chosen over wrapping the storage delete in an
    /// explicit `FOR UPDATE` transaction (see migration 194 for the cost
    /// comparison).
    ///
    /// A tombstone is only binding while the claim that set it is live. A
    /// sweep that crashes between phase 1 and phase 3 leaves one behind; it
    /// lapses with `claim_expires_at` rather than dooming that digest forever,
    /// and the push side treats an expired claim as no tombstone.
    ///
    /// `kind` selects the liveness predicate matching the calling sweep's own
    /// row `DELETE`, so phase 1 and phase 3 agree on "still reclaimable".
    async fn tombstone_cleanup_key_for_delete(
        &self,
        cleanup_key: &OciUploadCleanupKey,
        kind: CleanupSweepKind,
    ) -> bool {
        let sql = format!(
            "UPDATE oci_upload_cleanup_keys \
             SET claim_expires_at = NOW() + {claim_ttl}, pending_delete_at = NOW() \
             WHERE id = $1 AND claim_token = $2{liveness}",
            claim_ttl = OCI_CLEANUP_KEY_CLAIM_TTL_SQL,
            liveness = kind.liveness_predicate_sql(),
        );
        match sqlx::query(&sql)
            .bind(cleanup_key.id)
            .bind(cleanup_key.claim_token)
            .execute(&self.db)
            .await
        {
            Ok(r) => r.rows_affected() == 1,
            Err(e) => {
                tracing::warn!(
                    storage_key = %cleanup_key.storage_key,
                    error = %e,
                    "failed to tombstone cleanup-key claim; skipping its storage delete"
                );
                false
            }
        }
    }

    /// Reconcile aged `oci_upload_cleanup_keys` rows whose storage write was
    /// never marked complete (`storage_write_completed_at IS NULL`).
    ///
    /// The normal sweep ([`cleanup_unreferenced_oci_upload_keys`]) only
    /// reaps rows whose write has been marked complete. A crash or failed
    /// storage write between the register-row INSERT and the mark leaves the
    /// row stuck at NULL forever, so the table grows without bound. This
    /// reaper closes that leak: it picks up rows that are
    ///
    /// 1. still NULL (never marked complete), and
    /// 2. older than [`ABANDONED_OCI_UPLOAD_TTL_SQL`] (so no in-flight write
    ///    can still be racing to create the object), and
    /// 3. not referenced by any live upload session or part.
    ///
    /// For each, it best-effort deletes the storage object (treating
    /// `NotFound` as success, since a crashed write may never have created
    /// it) and then deletes the row, re-asserting the NULL + unreferenced
    /// predicate in the DELETE's WHERE clause so it cannot race the writer
    /// that may be marking the row complete concurrently.
    async fn reap_pending_oci_upload_cleanup_keys(
        &self,
        repo_scope: Option<Uuid>,
        dry_run: bool,
        result: &mut StorageGcResult,
    ) -> Result<()> {
        // Dry-run scans must not write claims; a real sweep claims rows so
        // concurrent replicas drain disjoint keys and the storage delete
        // only ever runs under a live claim. Both paths preserve the optional
        // repository scope.
        let cleanup_keys = if dry_run {
            self.select_pending_oci_upload_cleanup_keys(repo_scope)
                .await?
        } else {
            self.claim_pending_oci_upload_cleanup_keys(repo_scope)
                .await?
        };
        let mut cleanup_rows_removed = 0_i64;

        for cleanup_key in cleanup_keys {
            if dry_run {
                result.storage_keys_deleted += 1;
                continue;
            }

            let storage = match self.storage_for_location(&cleanup_key.location) {
                Ok(s) => s,
                Err(e) => {
                    let msg = format_gc_error(
                        "resolve pending OCI upload cleanup-key storage",
                        &cleanup_key.storage_key,
                        &e.to_string(),
                    );
                    tracing::warn!("{}", msg);
                    self.release_cleanup_key_claim(&cleanup_key, &msg).await;
                    result.errors.push(msg);
                    continue;
                }
            };

            // PHASE 1 (#3187): same tail-expiry and same liveness window as the
            // unreferenced sweep (#3085), and the same tombstone. Re-assert
            // ownership and the pending-key liveness predicate and publish
            // `pending_delete_at` atomically, so neither a lapsed claim nor a
            // concurrent push that committed an `oci_blobs` row for this key
            // can be followed by a delete of its bytes.
            if !self
                .tombstone_cleanup_key_for_delete(&cleanup_key, CleanupSweepKind::Pending)
                .await
            {
                tracing::info!(
                    storage_key = %cleanup_key.storage_key,
                    "pending cleanup-key claim lost or key became live mid-batch; skipping its storage delete"
                );
                continue;
            }

            match storage.delete(&cleanup_key.storage_key).await {
                Ok(()) | Err(AppError::NotFound(_)) => {}
                Err(e) => {
                    let msg = format_gc_error(
                        "delete pending OCI upload cleanup-key storage",
                        &cleanup_key.storage_key,
                        &e.to_string(),
                    );
                    tracing::warn!("{}", msg);
                    // Release the claim with the error recorded so the next
                    // sweep retries the storage delete.
                    self.release_cleanup_key_claim(&cleanup_key, &msg).await;
                    result.errors.push(msg);
                    continue;
                }
            }

            // Re-assert NULL + unreferenced in the DELETE so a concurrent
            // mark (writer flipping storage_write_completed_at to a value
            // and inserting a session/part) cannot have the row reaped out
            // from under it after we observed it as pending. The owning
            // session (upload_session_id) is also re-checked so a row whose
            // upload is still live is never reaped, even when the row's
            // storage_key is a part key that does not textually match the
            // session's storage_temp_key.
            // PHASE 3 (#3187): see the unreferenced sweep. `pending_delete_at
            // IS NOT NULL` ties the reap to the tombstone phase 1 published.
            let reaped = sqlx::query(
                r#"
                DELETE FROM oci_upload_cleanup_keys
                WHERE id = $1
                  AND claim_token = $2
                  AND pending_delete_at IS NOT NULL
                  AND storage_write_completed_at IS NULL
                  AND NOT EXISTS (
                    SELECT 1 FROM oci_upload_sessions s
                    WHERE s.id = oci_upload_cleanup_keys.upload_session_id
                       OR s.storage_temp_key = oci_upload_cleanup_keys.storage_key
                  )
                  AND NOT EXISTS (
                    SELECT 1 FROM oci_upload_parts p
                    WHERE p.storage_key = oci_upload_cleanup_keys.storage_key
                  )
                  -- A pending key may be a final blob key whose copy succeeded
                  -- but whose `oci_blobs` commit failed (left NULL-marked). If a
                  -- concurrent push has since committed an `oci_blobs` row for
                  -- the same digest/key, the blob is live: never reap it.
                  AND NOT EXISTS (
                    SELECT 1 FROM oci_blobs b
                    WHERE b.storage_key = oci_upload_cleanup_keys.storage_key
                  )
                "#,
            )
            .bind(cleanup_key.id)
            .bind(cleanup_key.claim_token)
            .execute(&self.db)
            .await;

            let reaped = match reaped {
                Ok(r) => r,
                Err(e) => {
                    let msg = format_gc_error(
                        "delete pending OCI upload cleanup-key row",
                        &cleanup_key.storage_key,
                        &e.to_string(),
                    );
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }
            };

            // #3187: a zero-row match is an anomaly, not a success. See the
            // matching block in `cleanup_unreferenced_oci_upload_keys`.
            if reaped.rows_affected() != 1 {
                let msg = format_gc_error(
                    "reap pending OCI upload cleanup-key row",
                    &cleanup_key.storage_key,
                    "tombstoned row vanished or stopped matching between the storage delete \
                     and its reap; the object was deleted but its journal row was not",
                );
                tracing::warn!("{}", msg);
                result.errors.push(msg);
                continue;
            }

            cleanup_rows_removed += 1;
            result.storage_keys_deleted += 1;
        }

        if cleanup_rows_removed > 0 {
            tracing::info!(
                "Storage GC: reaped {} aged pending OCI upload cleanup-key rows",
                cleanup_rows_removed
            );
        }

        Ok(())
    }

    async fn select_pending_oci_upload_cleanup_keys(
        &self,
        repo_scope: Option<Uuid>,
    ) -> Result<Vec<OciUploadCleanupKey>> {
        let sql = format!(
            r#"
            SELECT c.id, c.storage_key, c.claim_token, r.storage_backend, r.storage_path
            FROM oci_upload_cleanup_keys c
            JOIN repositories r ON r.id = c.repository_id
            WHERE c.storage_write_completed_at IS NULL
              AND c.created_at < NOW() - {ttl}
              {scope}
              AND NOT EXISTS (
                SELECT 1 FROM oci_upload_sessions s
                WHERE s.id = c.upload_session_id
                   OR s.storage_temp_key = c.storage_key
              )
              AND NOT EXISTS (
                SELECT 1 FROM oci_upload_parts p
                WHERE p.storage_key = c.storage_key
              )
              -- Never reap a pending key that a live `oci_blobs` row references
              -- (a concurrent push committed the same digest). The storage
              -- delete runs before the row DELETE, so this guard is required on
              -- the SELECT to avoid destroying a live blob's bytes.
              AND NOT EXISTS (
                SELECT 1 FROM oci_blobs b
                WHERE b.storage_key = c.storage_key
              )
            ORDER BY c.created_at ASC
            LIMIT $1
            "#,
            ttl = ABANDONED_OCI_UPLOAD_TTL_SQL,
            scope = repo_scope_clause("c.repository_id", 2, repo_scope),
        );
        let mut query = sqlx::query(&sql).bind(OCI_UPLOAD_CLEANUP_KEY_SCAN_LIMIT);
        if let Some(id) = repo_scope {
            query = query.bind(id);
        }
        let rows = query
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        rows.into_iter()
            .map(|row| decode_oci_cleanup_key_row(&row))
            .collect()
    }

    /// Reclaim orphaned row-less Maven flat objects (#2668).
    ///
    /// Checksum sidecars, verbatim `maven-metadata.xml` documents, and legacy
    /// GAV-grouped companion files are stored with no `artifacts` row, so the
    /// artifacts-driven orphan sweep never sees them. Their durable DB record
    /// is the `maven_flat_object_owner` attribution table (#2574/#2584): this
    /// sweep walks it and deletes the storage object + attribution row for
    /// every key whose catalog anchors are all gone, per
    /// [`ORPHAN_MAVEN_FLAT_PREDICATE_SQL`]. In particular this reclaims the
    /// `maven-metadata.xml` (+ sidecars) of a groupId/artifactId whose last
    /// version has been deleted and GC'd — the exact class of files reported
    /// leaking on S3.
    ///
    /// Safety mirrors the main sweep: each candidate is re-verified under a
    /// per-row `FOR UPDATE` lock on its attribution row before its object is
    /// deleted, using the same predicate constant as the scan (#1180
    /// discipline), and the one-hour age floor in the predicate keeps the
    /// sweep away from claims inserted by an in-flight first publish. The
    /// storage delete tolerates an already-absent object (NotFound => Ok,
    /// #1660) so a crash between the object delete and the row delete leaves
    /// a re-collectable orphan, never an error loop.
    ///
    /// Attribution rows exist only for shared cloud namespaces
    /// (S3/GCS/Azure); filesystem repositories keep an isolated key space and
    /// have their sidecars reclaimed inline by the main sweep
    /// ([`reclaim_maven_sidecars`]) and their remaining metadata at
    /// repository deletion.
    async fn cleanup_orphan_maven_flat_objects(
        &self,
        repo_scope: Option<Uuid>,
        dry_run: bool,
        result: &mut StorageGcResult,
    ) -> Result<()> {
        let candidates = self.select_orphan_maven_flat_objects(repo_scope).await?;
        let mut objects_removed = 0_i64;

        // Opt-in gate (#3431), mirroring BLOB_GC_ENABLED's "bias to leaking
        // storage over losing data". This sweep's entire subject matter is
        // objects the catalog cannot see; on an instance migrated from another
        // registry that absence is the EXPECTED state of legitimate legacy
        // data — it is why the attribution table exists — so catalog absence
        // alone is not proof of garbage. Unset, the pass still reports what it
        // would reclaim and deletes nothing.
        if !dry_run && !self.maven_flat_gc_enabled {
            let gated = candidates.len() as i64;
            result.maven_flat_objects_gated += gated;
            if gated > 0 {
                tracing::info!(
                    maven_flat_objects_gated = gated,
                    "Maven flat GC (disabled): would reclaim {} orphaned row-less Maven flat \
                     objects; deleting nothing (set MAVEN_FLAT_GC_ENABLED=true to delete)",
                    gated,
                );
            }
            return Ok(());
        }

        for row in candidates {
            let storage_key: String = row
                .try_get("storage_key")
                .map_err(|e| AppError::Database(e.to_string()))?;
            let storage_backend: String = row
                .try_get("storage_backend")
                .map_err(|e| AppError::Database(e.to_string()))?;
            let storage_path: String = row
                .try_get("storage_path")
                .map_err(|e| AppError::Database(e.to_string()))?;

            if dry_run {
                result.storage_keys_deleted += 1;
                continue;
            }

            let location = StorageLocation {
                backend: storage_backend.clone(),
                path: storage_path,
            };
            let storage = match self.storage_for_location(&location) {
                Ok(s) => s,
                Err(e) => {
                    let msg =
                        format_gc_error("resolve maven flat storage", &storage_key, &e.to_string());
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }
            };

            let mut tx = match self.db.begin().await {
                Ok(t) => t,
                Err(e) => {
                    let msg =
                        format_gc_error("begin maven flat gc tx", &storage_key, &e.to_string());
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }
            };

            // Re-verify under the row lock so a claim that a concurrent
            // publish re-anchored (new artifact row / files[] reference /
            // live version under a metadata directory) is observed and
            // skipped.
            match is_maven_flat_object_still_orphan(&mut tx, &storage_backend, &storage_key).await {
                Ok(true) => {}
                Ok(false) => {
                    let _ = tx.rollback().await;
                    tracing::debug!(
                        storage_key = storage_key.as_str(),
                        "Maven flat GC skipped key: no longer orphan after row-lock re-check"
                    );
                    continue;
                }
                Err(e) => {
                    let _ = tx.rollback().await;
                    let msg =
                        format_gc_error("re-check maven flat orphan", &storage_key, &e.to_string());
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }
            }

            match storage.delete(&storage_key).await {
                Ok(()) | Err(AppError::NotFound(_)) => {}
                Err(e) => {
                    let _ = tx.rollback().await;
                    let msg =
                        format_gc_error("delete maven flat object", &storage_key, &e.to_string());
                    tracing::warn!("{}", msg);
                    result.errors.push(msg);
                    continue;
                }
            }

            if let Err(e) = sqlx::query(
                "DELETE FROM maven_flat_object_owner \
                 WHERE storage_backend = $1 AND storage_key = $2",
            )
            .bind(&storage_backend)
            .bind(&storage_key)
            .execute(&mut *tx)
            .await
            {
                let _ = tx.rollback().await;
                let msg = format_gc_error(
                    "delete maven flat attribution row",
                    &storage_key,
                    &e.to_string(),
                );
                tracing::warn!("{}", msg);
                result.errors.push(msg);
                continue;
            }

            if let Err(e) = tx.commit().await {
                let msg = format_gc_error("commit maven flat gc tx", &storage_key, &e.to_string());
                tracing::warn!("{}", msg);
                result.errors.push(msg);
                continue;
            }

            tracing::info!(
                storage_key = storage_key.as_str(),
                "Storage GC: reclaimed orphaned row-less Maven flat object"
            );
            objects_removed += 1;
            result.storage_keys_deleted += 1;
        }

        if objects_removed > 0 {
            tracing::info!(
                "Storage GC: reclaimed {} orphaned row-less Maven flat objects",
                objects_removed
            );
        }

        Ok(())
    }

    /// Candidate scan for [`Self::cleanup_orphan_maven_flat_objects`]. A
    /// snapshot only — every candidate is re-verified under a `FOR UPDATE`
    /// row lock before deletion. `pub(crate)` so unit tests can assert on
    /// per-key candidacy without racing sibling tests on shared counters
    /// (#1493 pattern).
    pub(crate) async fn select_orphan_maven_flat_objects(
        &self,
        repo_scope: Option<Uuid>,
    ) -> Result<Vec<sqlx::postgres::PgRow>> {
        let sql = format!(
            r#"
            SELECT o.storage_key, o.storage_backend, r.storage_path
            FROM maven_flat_object_owner o
            JOIN repositories r ON r.id = o.repository_id
            WHERE {predicate}
              {scope}
            ORDER BY o.storage_key
            LIMIT $1
            "#,
            predicate = ORPHAN_MAVEN_FLAT_PREDICATE_SQL.as_str(),
            scope = repo_scope_clause("o.repository_id", 2, repo_scope),
        );
        let mut query = sqlx::query(&sql).bind(ORPHAN_MAVEN_FLAT_SCAN_LIMIT);
        if let Some(id) = repo_scope {
            query = query.bind(id);
        }
        query
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))
    }

    /// Claim a batch of aged pending (never-marked-complete) cleanup keys
    /// for a destructive sweep. Same candidate predicates as
    /// [`Self::select_pending_oci_upload_cleanup_keys`], plus live-claim
    /// exclusion and FOR UPDATE SKIP LOCKED, mirroring
    /// [`Self::claim_unreferenced_oci_upload_cleanup_keys`].
    async fn claim_pending_oci_upload_cleanup_keys(
        &self,
        repo_scope: Option<Uuid>,
    ) -> Result<Vec<OciUploadCleanupKey>> {
        let sql = format!(
            r#"
            WITH candidate AS (
                SELECT c.id
                FROM oci_upload_cleanup_keys c
                WHERE c.storage_write_completed_at IS NULL
                  AND c.created_at < NOW() - {ttl}
                  AND (c.claim_expires_at IS NULL OR c.claim_expires_at <= NOW())
                  {scope}
                  AND NOT EXISTS (
                    SELECT 1 FROM oci_upload_sessions s
                    WHERE s.id = c.upload_session_id
                       OR s.storage_temp_key = c.storage_key
                  )
                  AND NOT EXISTS (
                    SELECT 1 FROM oci_upload_parts p
                    WHERE p.storage_key = c.storage_key
                  )
                  AND NOT EXISTS (
                    SELECT 1 FROM oci_blobs b
                    WHERE b.storage_key = c.storage_key
                  )
                ORDER BY c.created_at ASC
                LIMIT $1
                FOR UPDATE OF c SKIP LOCKED
            )
            UPDATE oci_upload_cleanup_keys u
            SET claimed_by = $2,
                claim_token = gen_random_uuid(),
                claim_expires_at = NOW() + {claim_ttl}
            FROM candidate, repositories r
            WHERE u.id = candidate.id
              AND r.id = u.repository_id
            RETURNING u.id, u.storage_key, u.claim_token,
                      r.storage_backend, r.storage_path
            "#,
            ttl = ABANDONED_OCI_UPLOAD_TTL_SQL,
            claim_ttl = OCI_CLEANUP_KEY_CLAIM_TTL_SQL,
            scope = repo_scope_clause("c.repository_id", 3, repo_scope),
        );
        let mut query = sqlx::query(&sql)
            .bind(OCI_UPLOAD_CLEANUP_KEY_SCAN_LIMIT)
            .bind(crate::services::cluster_work::WorkerIdentity::for_process().as_str());
        if let Some(id) = repo_scope {
            query = query.bind(id);
        }
        let rows = query
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        rows.into_iter()
            .map(|row| decode_oci_cleanup_key_row(&row))
            .collect()
    }
}

/// Delete the row-less checksum sidecars of a reclaimed Maven storage key and
/// drop the attribution rows of the key + its sidecars (#2668).
///
/// Called by the main orphan sweep inside the per-key transaction, after the
/// base object has been deleted and the `artifacts` rows hard-deleted. Maven
/// checksum sidecars (`.md5`, `.sha1`, `.sha256`, `.sha512`) are row-less
/// puts, so they are never orphan candidates themselves; deriving them from
/// the base key at reclaim time is what keeps them from leaking on storage.
///
/// Safety:
/// - No-op for non-Maven keys.
/// - A derived sidecar key that has its own `artifacts` row (any state, same
///   backend) is skipped: a row-backed object is owned by the artifacts
///   sweep, never blind-deleted here.
/// - Sidecars inherit their base object's owner by construction
///   (`maven_flat_attribution::strip_checksum_suffix` resolution + the
///   flat-key write guard), so once the base key is provably orphan — the
///   caller has just re-verified `ORPHAN_PREDICATE_SQL` under row locks — no
///   other repository can legitimately serve these sidecars.
/// - Storage deletes tolerate absent objects (NotFound => Ok); most bases
///   have fewer than four sidecars.
/// - The attribution-row cleanup keeps a hard-deleted key from staying
///   claimed forever, which would otherwise lock the coordinate against
///   every other tenant on the backend after the data is gone.
///
/// Any error propagates so the caller rolls back and retries the whole key
/// on the next pass (the base storage delete is idempotent).
async fn reclaim_maven_sidecars(
    tx: &mut Transaction<'_, Postgres>,
    storage: &dyn StorageBackend,
    storage_key: &str,
    storage_backend: &str,
) -> Result<()> {
    if !storage_key.starts_with(MAVEN_FLAT_KEY_PREFIX) {
        return Ok(());
    }

    // The base key's attribution row is dropped unconditionally: its object
    // and rows are already gone.
    let mut attribution_keys: Vec<String> = vec![storage_key.to_string()];

    for suffix in MAVEN_SIDECAR_SUFFIXES {
        let sidecar_key = format!("{storage_key}{suffix}");

        // Never touch a key that is row-backed on this backend (live or
        // soft-deleted): it belongs to the artifacts-driven sweep.
        let row_backed: bool = sqlx::query_scalar(
            "SELECT EXISTS ( \
                 SELECT 1 FROM artifacts a \
                 JOIN repositories r ON r.id = a.repository_id \
                 WHERE a.storage_key = $1 AND r.storage_backend = $2 \
             )",
        )
        .bind(&sidecar_key)
        .bind(storage_backend)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        if row_backed {
            continue;
        }

        match storage.delete(&sidecar_key).await {
            Ok(()) | Err(AppError::NotFound(_)) => {}
            Err(e) => return Err(e),
        }
        attribution_keys.push(sidecar_key);
    }

    sqlx::query(
        "DELETE FROM maven_flat_object_owner \
         WHERE storage_backend = $1 AND storage_key = ANY($2)",
    )
    .bind(storage_backend)
    .bind(&attribution_keys)
    .execute(&mut **tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(())
}

/// Re-verify the orphaned-flat-object predicate for a single
/// (storage_backend, storage_key) attribution row inside an open transaction,
/// holding a `FOR UPDATE` lock on that row (#2668).
///
/// Step 1 locks the attribution row (a vanished row returns `false`); step 2
/// re-evaluates [`ORPHAN_MAVEN_FLAT_PREDICATE_SQL`] — the same constant the
/// candidate scan uses, so the two checks cannot drift (#1180).
async fn is_maven_flat_object_still_orphan(
    tx: &mut Transaction<'_, Postgres>,
    storage_backend: &str,
    storage_key: &str,
) -> Result<bool> {
    let locked = sqlx::query(
        "SELECT storage_key FROM maven_flat_object_owner \
         WHERE storage_backend = $1 AND storage_key = $2 \
         FOR UPDATE",
    )
    .bind(storage_backend)
    .bind(storage_key)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    if locked.is_none() {
        return Ok(false);
    }

    let sql = format!(
        r#"
        SELECT EXISTS (
            SELECT 1 FROM maven_flat_object_owner o
            WHERE o.storage_backend = $1
              AND o.storage_key = $2
              AND {predicate}
        ) AS still_orphan
        "#,
        predicate = ORPHAN_MAVEN_FLAT_PREDICATE_SQL.as_str(),
    );
    let row = sqlx::query(&sql)
        .bind(storage_backend)
        .bind(storage_key)
        .fetch_one(&mut **tx)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

    Ok(row.try_get::<bool, _>("still_orphan").unwrap_or(false))
}

/// Decode an `oci_upload_cleanup_keys` JOIN `repositories` row into an
/// [`OciUploadCleanupKey`]. Shared by the unreferenced and pending cleanup-key
/// selects, which project the identical column set.
fn decode_oci_cleanup_key_row(row: &sqlx::postgres::PgRow) -> Result<OciUploadCleanupKey> {
    Ok(OciUploadCleanupKey {
        id: row
            .try_get::<i64, _>("id")
            .map_err(|e| AppError::Database(e.to_string()))?,
        storage_key: row
            .try_get::<String, _>("storage_key")
            .map_err(|e| AppError::Database(e.to_string()))?,
        location: StorageLocation {
            backend: row
                .try_get::<String, _>("storage_backend")
                .map_err(|e| AppError::Database(e.to_string()))?,
            path: row
                .try_get::<String, _>("storage_path")
                .map_err(|e| AppError::Database(e.to_string()))?,
        },
        claim_token: row
            .try_get::<Option<Uuid>, _>("claim_token")
            .map_err(|e| AppError::Database(e.to_string()))?,
    })
}

async fn lock_abandoned_oci_upload_session(
    tx: &mut Transaction<'_, Postgres>,
    session_id: Uuid,
) -> sqlx::Result<Option<AbandonedOciUploadSession>> {
    let sql = format!(
        r#"
        SELECT s.id, r.storage_backend, r.storage_path,
               s.storage_temp_key, s.bytes_received
        FROM oci_upload_sessions s
        JOIN repositories r ON r.id = s.repository_id
        WHERE s.id = $1
          AND s.updated_at < NOW() - {ttl}
        FOR UPDATE OF s
        "#,
        ttl = ABANDONED_OCI_UPLOAD_TTL_SQL,
    );
    let Some(row) = sqlx::query(&sql)
        .bind(session_id)
        .fetch_optional(&mut **tx)
        .await?
    else {
        return Ok(None);
    };

    let storage_temp_key: String = row.try_get("storage_temp_key")?;
    let part_rows = sqlx::query(
        r#"
        SELECT storage_key
        FROM oci_upload_parts
        WHERE upload_session_id = $1
        ORDER BY part_index ASC
        "#,
    )
    .bind(session_id)
    .fetch_all(&mut **tx)
    .await?;

    let mut storage_keys: Vec<String> = part_rows
        .into_iter()
        .map(|row| row.try_get::<String, _>("storage_key"))
        .collect::<sqlx::Result<Vec<_>>>()?;
    storage_keys.push(storage_temp_key);
    storage_keys.sort();
    storage_keys.dedup();

    Ok(Some(AbandonedOciUploadSession {
        id: row.try_get("id")?,
        location: StorageLocation {
            backend: row.try_get("storage_backend")?,
            path: row.try_get("storage_path")?,
        },
        storage_keys,
        bytes_received: row.try_get("bytes_received")?,
    }))
}

/// Re-verify the orphan predicate for a single (storage_key, repo
/// location) inside an open transaction with a `FOR UPDATE` lock on the
/// candidate `artifacts` rows.
///
/// Returns `Ok(true)` if every soft-deleted `artifacts` row matching the
/// key still satisfies the orphan predicate; `Ok(false)` if any racing
/// writer has landed a protecting reference.
///
/// Postgres forbids `FOR UPDATE` together with aggregate functions in
/// the same SELECT, so we split the check into two steps:
///
/// 1. Acquire row locks on every `artifacts` row matching the
///    (storage_key, backend) tuple (path-narrowed only on `filesystem`
///    because cloud backends share a global keyspace across repos on
///    the same backend type) with a separate `SELECT ... FOR UPDATE`.
///    This is the bit that blocks any racing writer from flipping
///    `is_deleted` or otherwise modifying these rows until our tx ends.
/// 2. Re-evaluate the orphan predicate (an aggregate over the locked
///    rows) in a second non-locking SELECT. Because we hold the lock
///    from step 1, no row visible in step 2 can change underneath us
///    for the rest of the transaction.
///
/// The aggregate uses `bool_and`; if there are no matching rows the
/// aggregate is NULL and `COALESCE` returns false so we skip the delete
/// (there's nothing left to delete anyway).
///
/// Lock scope rationale: `ORPHAN_PREDICATE_SQL` treats `oci_tags`,
/// `oci_blobs`, and `oci_manifest_refs` as cross-repo on cloud backends
/// because S3/GCS/Azure storage keys are globally unique within the
/// configured bucket. The lock here must match the same scope, or a
/// racing writer in a sibling cloud repo could flip `is_deleted=false`
/// on a row that shares the storage_key without being blocked, and the
/// recheck would still observe the new live row in step 2 only if it
/// committed before the snapshot. Widening the lock to all repos on
/// the same cloud backend closes that window.
async fn is_still_orphan(
    tx: &mut Transaction<'_, Postgres>,
    storage_key: &str,
    storage_backend: &str,
    storage_path: &str,
) -> sqlx::Result<bool> {
    // Step 1: acquire row locks. We do not care about the returned
    // rows; we just need them locked for the rest of the transaction.
    // `FOR UPDATE OF a` restricts the lock to the artifacts table so
    // we do not inadvertently lock the joined repositories row.
    //
    // Filesystem narrows by `storage_path` (each repo has its own
    // filesystem root); cloud backends span every repo on the same
    // backend type because they all share one bucket and the same
    // storage_key resolves to the same object.
    sqlx::query(
        r#"
        SELECT a.id
        FROM artifacts a
        JOIN repositories r ON r.id = a.repository_id
        WHERE a.storage_key = $1
          AND r.storage_backend = $2
          AND (
            r.storage_backend <> 'filesystem'
            OR r.storage_path = $3
          )
        FOR UPDATE OF a
        "#,
    )
    .bind(storage_key)
    .bind(storage_backend)
    .bind(storage_path)
    .fetch_all(&mut **tx)
    .await?;

    // Step 2: re-evaluate the orphan predicate against the locked rows.
    // Match scope used by step 1.
    let sql = format!(
        r#"
        SELECT COALESCE(bool_and({predicate}), false) AS still_orphan
        FROM artifacts a
        JOIN repositories r ON r.id = a.repository_id
        WHERE a.storage_key = $1
          AND r.storage_backend = $2
          AND (
            r.storage_backend <> 'filesystem'
            OR r.storage_path = $3
          )
        "#,
        predicate = ORPHAN_PREDICATE_SQL,
    );

    let row = sqlx::query(&sql)
        .bind(storage_key)
        .bind(storage_backend)
        .bind(storage_path)
        .fetch_one(&mut **tx)
        .await?;

    Ok(row.try_get::<bool, _>("still_orphan").unwrap_or(false))
}

/// Re-verify the blob-orphan predicate for a single (repo, digest) inside
/// an open transaction with a `FOR UPDATE` lock on the `oci_blobs` row
/// (#1408; design from #1409).
///
/// The lock is narrowed to the (repo, digest) row because
/// `oci_blobs.repository_id` is part of its primary key. The orphan
/// re-check uses the same backend-aware [`BLOB_PROTECTED_BY_REFS_SQL`]
/// fragment as [`StorageGcService::select_orphan_blobs`] (cloud =
/// cross-repo on the shared bucket, filesystem = same `storage_path`), so
/// the initial scan and the locked re-check cannot drift.
///
/// `bool_and` collapses to a single value; an empty result (row gone)
/// returns `false` so the caller skips the delete.
///
/// `require_pending_mark` selects the phase (#1660): Phase A (**mark**)
/// passes `false` and ignores the marker; Phase B (**sweep**) passes `true`
/// and additionally requires the row to still carry a `pending_delete_at`
/// marker, so a blob a concurrent push resurrected (marker cleared under this
/// same lock) fails the check and is not swept. The `FOR UPDATE` lock in
/// step 1 is taken unconditionally in both phases, so the mark/sweep/resurrect
/// operations serialize on the row regardless of the marker filter.
async fn is_blob_still_orphan(
    tx: &mut Transaction<'_, Postgres>,
    repository_id: Uuid,
    digest: &str,
    require_pending_mark: bool,
) -> sqlx::Result<bool> {
    // Step 1: lock the (repo, digest) row so a racing pusher cannot
    // re-reference this blob between the re-check and the delete.
    sqlx::query(
        r#"
        SELECT id FROM oci_blobs
        WHERE repository_id = $1 AND digest = $2
        FOR UPDATE
        "#,
    )
    .bind(repository_id)
    .bind(digest)
    .fetch_all(&mut **tx)
    .await?;

    // Step 2: join the locked row back to its repository so the shared
    // `ob`/`r`-correlated fragment can resolve the row's backend and
    // storage_path; this keeps the re-check identical in scope to the
    // initial scan. When `require_pending_mark` ($3) is true, a row whose
    // marker a racer cleared is filtered out, `bool_and` over the empty set
    // collapses to the COALESCE default `false`, and the sweep skips it.
    let sql = format!(
        r#"
        SELECT COALESCE(bool_and(NOT {protected}), false) AS still_orphan
        FROM oci_blobs ob
        JOIN repositories r ON r.id = ob.repository_id
        WHERE ob.repository_id = $1 AND ob.digest = $2
          AND (NOT $3 OR ob.pending_delete_at IS NOT NULL)
        "#,
        protected = BLOB_PROTECTED_BY_REFS_SQL,
    );
    let row = sqlx::query(&sql)
        .bind(repository_id)
        .bind(digest)
        .bind(require_pending_mark)
        .fetch_one(&mut **tx)
        .await?;

    Ok(row.try_get::<bool, _>("still_orphan").unwrap_or(false))
}

/// Outcome of the push side's commit-time guard on a blob key's
/// cleanup-journal row. See [`claim_cleanup_journal_row_for_blob_commit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CleanupJournalClaim {
    /// No sweep owns this key. The journal row (if it still existed) has been
    /// deleted inside the caller's transaction, under the row lock, so a sweep
    /// that reaches phase 1 afterwards will match zero rows and skip its
    /// storage delete. The caller may commit its `oci_blobs` row.
    Cleared,
    /// A cleanup sweep has tombstoned this key under a live claim, or has
    /// already reaped its journal row: the object either is being deleted right
    /// now or is already gone. The caller **must not** commit an `oci_blobs`
    /// row for it, and must roll back and report a retryable failure.
    Doomed,
}

/// **The push side of the two-phase cleanup-key protocol (#3187).** Read this
/// together with [`StorageGcService::tombstone_cleanup_key_for_delete`], which
/// is the sweep side; neither half is correct alone.
///
/// Call this inside the *same transaction* that commits the `oci_blobs` row
/// for `storage_key`, strictly before that INSERT commits. `journal_id` is the
/// row id returned when the push registered the key
/// (`register_oci_upload_cleanup_key`), captured then rather than looked up by
/// `storage_key` now, so that a sweep having reaped *the row this push
/// registered* is distinguishable from there never having been one.
///
/// # Why the push has to participate
///
/// The cleanup sweep destroys `oci-blobs/<digest>` objects it believes nothing
/// references. Its liveness predicate is `NOT EXISTS (SELECT 1 FROM oci_blobs
/// ...)`, and a re-push of a swept digest **INSERTs a new** `oci_blobs` row —
/// there is no existing row for the sweep to have locked, so no amount of
/// `FOR UPDATE` on `oci_blobs` (the mechanism that protects the blob GC one
/// layer down, via [`is_blob_still_orphan`]) can serialize the two. The
/// journal row is the only object both sides touch, and this function is what
/// makes the push touch it under a lock.
///
/// # The protocol
///
/// 1. `SELECT ... FOR UPDATE` the journal row. This blocks against a sweep's
///    in-flight phase-1 tombstone `UPDATE`, and makes a sweep's phase-1
///    `UPDATE` block against us. That mutual exclusion is the whole guarantee;
///    everything below is just deciding who won.
/// 2. **Row present, tombstoned, claim still live** → [`Doomed`]. The sweep
///    committed its intent before we took the lock, so its `storage.delete()`
///    is already in flight or done. Committing an `oci_blobs` row here is
///    exactly the #3085 data loss.
/// 3. **Row present, no tombstone (or a lapsed claim)** → delete it under the
///    lock and return [`Cleared`]. A sweep's phase-1 `UPDATE` now finds no row,
///    so it never deletes the object. A tombstone whose `claim_expires_at` has
///    passed belongs to a crashed sweep and is not binding — otherwise a crash
///    would doom that digest permanently.
/// 4. **Row absent** → the push registered a row and something removed it.
///    Three causes, and they must not be conflated:
///    * A **concurrent push of the same key** won and cleared the row in the
///      same transaction that committed its own `oci_blobs` row. An
///      `oci_blobs` row referencing this key proves it: the peer's journal
///      delete and its INSERT commit together, so we cannot observe one
///      without the other. The bytes are live → [`Cleared`].
///    * The **repository was deleted**, cascading the journal row away
///      (`oci_upload_cleanup_keys.repository_id ... ON DELETE CASCADE`). No
///      sweep is involved and there is nothing to protect; return [`Cleared`]
///      so the caller's own `oci_blobs` INSERT fails on its foreign key and
///      reports *that*, rather than this function inventing a concurrent-GC
///      diagnosis for an unrelated failure.
///    * Otherwise a **sweep reaped it**. Phase 3 only removes a row whose
///      object it just deleted, so the bytes are gone → [`Doomed`].
///
/// [`Doomed`]: CleanupJournalClaim::Doomed
/// [`Cleared`]: CleanupJournalClaim::Cleared
pub(crate) async fn claim_cleanup_journal_row_for_blob_commit(
    conn: &mut sqlx::PgConnection,
    journal_id: i64,
    repository_id: Uuid,
    storage_key: &str,
) -> sqlx::Result<CleanupJournalClaim> {
    // Step 1: take the row lock. `FOR UPDATE` conflicts with the sweep's
    // phase-1 `UPDATE`, so from here on exactly one of the two proceeds.
    //
    // `claim_expires_at IS NULL` is folded into "binding", not out of it, so
    // the expression is never SQL NULL and the conservative answer is the
    // default. Phase 1 always writes the tombstone and the lease together, so
    // a tombstone with no lease should not exist; if one ever does, refusing
    // the push is the safe way to be wrong.
    let row = sqlx::query(
        "SELECT pending_delete_at IS NOT NULL \
              AND (claim_expires_at IS NULL OR claim_expires_at > NOW()) AS doomed \
         FROM oci_upload_cleanup_keys WHERE id = $1 FOR UPDATE",
    )
    .bind(journal_id)
    .fetch_optional(&mut *conn)
    .await?;

    let Some(row) = row else {
        // Step 4: our journal row is gone. A peer push that cleared it
        // committed its `oci_blobs` row in the same transaction, so that row
        // is visible to us now if it exists at all.
        let live = sqlx::query("SELECT 1 AS present FROM oci_blobs WHERE storage_key = $1 LIMIT 1")
            .bind(storage_key)
            .fetch_optional(&mut *conn)
            .await?;
        if live.is_some() {
            return Ok(CleanupJournalClaim::Cleared);
        }
        // Not a peer push. Before blaming a sweep, rule out the repository
        // having been deleted underneath us, which cascades the journal row
        // away for reasons that have nothing to do with GC.
        let repo_alive = sqlx::query("SELECT 1 AS present FROM repositories WHERE id = $1")
            .bind(repository_id)
            .fetch_optional(&mut *conn)
            .await?;
        return Ok(if repo_alive.is_some() {
            CleanupJournalClaim::Doomed
        } else {
            CleanupJournalClaim::Cleared
        });
    };

    // Step 2: a live tombstone means the sweep got here first. A decode
    // failure propagates rather than defaulting — a guard against data loss
    // must not fail open on an unreadable answer.
    if row.try_get::<bool, _>("doomed")? {
        return Ok(CleanupJournalClaim::Doomed);
    }

    // Step 3: we hold the lock and the key is not doomed. Remove the journal
    // row inside the caller's transaction so it lands atomically with the
    // `oci_blobs` INSERT that follows.
    sqlx::query("DELETE FROM oci_upload_cleanup_keys WHERE id = $1")
        .bind(journal_id)
        .execute(&mut *conn)
        .await?;

    Ok(CleanupJournalClaim::Cleared)
}

/// Accumulate dry-run totals into a GC result.
pub(crate) fn accumulate_dry_run(result: &mut StorageGcResult, bytes: i64, count: i64) {
    result.storage_keys_deleted += 1;
    result.artifacts_removed += count;
    result.bytes_freed += bytes;
}

/// Record a successful GC deletion in the result.
pub(crate) fn record_gc_success(result: &mut StorageGcResult, bytes: i64, count: i64) {
    result.storage_keys_deleted += 1;
    result.artifacts_removed += count;
    result.bytes_freed += bytes;
}

/// Format a GC error message for a specific operation and storage key.
pub(crate) fn format_gc_error(operation: &str, storage_key: &str, error: &str) -> String {
    format!("Failed to {} for key {}: {}", operation, storage_key, error)
}

/// SQL clause restricting a GC candidate scan to one repository (#708).
///
/// Returns `AND <column> = $<param>` when `repo_scope` is `Some`, or an empty
/// string for the instance-wide scan. `param` is the 1-based placeholder
/// index the clause should use — one past the number of binds the unscoped
/// query already has — and the caller must bind the scoped id in that
/// position. Extracted as a pure helper so the clause shape (and its bind
/// arithmetic) is unit-testable without a database.
fn repo_scope_clause(column: &str, param: usize, repo_scope: Option<Uuid>) -> String {
    match repo_scope {
        Some(_) => format!("AND {column} = ${param}"),
        None => String::new(),
    }
}

/// Decoded global aggregate values for the OCI blob footprint report.
///
/// This is the row-free intermediate between the `totals_sql` query in
/// `StorageGcService::fetch_blob_footprint_totals` and the final
/// [`OciBlobFootprintReport`]. Splitting it out lets the report-assembly
/// logic (which is pure arithmetic/struct shuffling, not I/O) be unit
/// tested without a live database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BlobFootprintTotals {
    pub total_blob_rows: i64,
    pub distinct_digests: i64,
    pub logical_bytes: i64,
    pub physical_bytes: i64,
    pub aged_distinct_digests: i64,
    pub aged_physical_bytes: i64,
}

/// Decode an `i64` aggregate column from a footprint-report row,
/// propagating the failure as a database error.
///
/// Deliberately NOT `unwrap_or(0)`: a decode mismatch (e.g. an un-cast
/// `NUMERIC` from `SUM`) silently reporting "0 bytes" is the swallow class
/// this codebase keeps re-finding — a plausible default standing in for an
/// error — and a footprint report that reads 0 could steer a wrong
/// deletion decision downstream.
fn decode_report_i64(row: &sqlx::postgres::PgRow, column: &str) -> Result<i64> {
    row.try_get(column)
        .map_err(|e| AppError::Database(format!("decode footprint column {column}: {e}")))
}

/// Build a single per-repository footprint row from decoded column values.
///
/// Pure mapping helper shared by the per-repo aggregate decode loop and
/// the unit tests. Holds no row/DB dependency so the construction can be
/// exercised without Postgres.
pub(crate) fn map_repo_footprint(
    repository_id: Uuid,
    blob_rows: i64,
    logical_bytes: i64,
) -> OciBlobRepoFootprint {
    OciBlobRepoFootprint {
        repository_id,
        blob_rows,
        logical_bytes,
    }
}

/// Assemble the final [`OciBlobFootprintReport`] from already-decoded
/// totals, the (already clamped) grace window, and the per-repository
/// rows.
///
/// Pure: it does no I/O and takes no locks. Extracted from
/// [`StorageGcService::oci_blob_footprint_report`] so the report-assembly
/// step is covered by `--lib` unit tests even though the surrounding query
/// execution requires a database.
pub(crate) fn assemble_blob_footprint_report(
    totals: BlobFootprintTotals,
    grace_hours: i64,
    per_repository: Vec<OciBlobRepoFootprint>,
) -> OciBlobFootprintReport {
    OciBlobFootprintReport {
        total_blob_rows: totals.total_blob_rows,
        distinct_digests: totals.distinct_digests,
        logical_bytes: totals.logical_bytes,
        physical_bytes: totals.physical_bytes,
        grace_hours,
        aged_distinct_digests: totals.aged_distinct_digests,
        aged_physical_bytes: totals.aged_physical_bytes,
        per_repository,
    }
}

/// Clamp a caller-supplied grace window (hours) for the blob footprint
/// report into a defensible range.
///
/// A non-positive or absurd value is coerced rather than rejected so the
/// reporting endpoint never errors on a bad query parameter:
/// - values `<= 0` fall back to [`BLOB_REPORT_GRACE_HOURS_DEFAULT`]
///   (a zero/negative grace window would mark freshly-uploaded blobs as
///   "aged", defeating the upload-race guard the window represents);
/// - values are capped at one year (8760 h) so `make_interval` cannot be
///   handed a pathological argument.
pub(crate) fn clamp_grace_hours(grace_hours: i64) -> i64 {
    const MAX_GRACE_HOURS: i64 = 24 * 365;
    if grace_hours <= 0 {
        BLOB_REPORT_GRACE_HOURS_DEFAULT
    } else {
        grace_hours.min(MAX_GRACE_HOURS)
    }
}

/// Check whether a storage backend type uses a shared (cloud) backend.
#[cfg(test)]
pub(crate) fn is_cloud_backend(backend_type: &str) -> bool {
    matches!(backend_type, "s3" | "azure" | "gcs")
}

/// Create an empty GC result for a given dry_run mode.
pub(crate) fn empty_gc_result(dry_run: bool) -> StorageGcResult {
    StorageGcResult {
        dry_run,
        storage_keys_deleted: 0,
        artifacts_removed: 0,
        bytes_freed: 0,
        errors: Vec::new(),
        maven_flat_objects_gated: 0,
    }
}

#[cfg(test)]
static STORAGE_GC_TEST_LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> =
    std::sync::OnceLock::new();

#[cfg(test)]
pub(crate) async fn storage_gc_test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    STORAGE_GC_TEST_LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    use async_trait::async_trait;
    use bytes::Bytes;
    use std::sync::Arc;
    use uuid::Uuid;

    // -----------------------------------------------------------------------
    // Mock storage backend for unit tests
    // -----------------------------------------------------------------------

    struct MockStorage;

    #[async_trait]
    impl crate::storage::StorageBackend for MockStorage {
        async fn put(&self, _key: &str, _content: Bytes) -> crate::error::Result<()> {
            Ok(())
        }
        async fn get(&self, _key: &str) -> crate::error::Result<Bytes> {
            Ok(Bytes::new())
        }
        async fn exists(&self, _key: &str) -> crate::error::Result<bool> {
            Ok(false)
        }
        async fn delete(&self, _key: &str) -> crate::error::Result<()> {
            Ok(())
        }
        async fn put_stream(
            &self,
            key: &str,
            stream: futures::stream::BoxStream<'static, crate::error::Result<bytes::Bytes>>,
        ) -> crate::error::Result<crate::storage::PutStreamResult> {
            crate::storage::buffered_put_stream_fallback(self, key, stream).await
        }
    }

    fn make_pool() -> PgPool {
        use sqlx::postgres::PgPoolOptions;
        PgPoolOptions::new()
            .max_connections(1)
            .idle_timeout(std::time::Duration::from_secs(1))
            // Every acquire is doomed (no DB at localhost/test); fail in 1s
            // instead of sqlx's default 30s so the db-unreachable tests do
            // not serialize 30-60s sleeps through the db-serial group.
            .acquire_timeout(std::time::Duration::from_secs(1))
            .connect_lazy_with(
                sqlx::postgres::PgConnectOptions::new()
                    .host("localhost")
                    .database("test"),
            )
    }

    fn make_service(backend_type: &str) -> StorageGcService {
        let mut backends = std::collections::HashMap::new();
        if backend_type != "filesystem" {
            backends.insert(
                backend_type.to_string(),
                Arc::new(MockStorage) as Arc<dyn crate::storage::StorageBackend>,
            );
        }
        let registry = Arc::new(crate::storage::StorageRegistry::new(
            backends,
            backend_type.to_string(),
        ));
        StorageGcService::new(make_pool(), registry)
    }

    // -----------------------------------------------------------------------
    // StorageGcResult: serialization (existing tests)
    // -----------------------------------------------------------------------

    #[test]
    fn test_storage_gc_result_serialization() {
        let result = StorageGcResult {
            dry_run: false,
            storage_keys_deleted: 5,
            artifacts_removed: 12,
            bytes_freed: 1024 * 1024,
            errors: vec![],
            maven_flat_objects_gated: 0,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"storage_keys_deleted\":5"));
        assert!(json.contains("\"artifacts_removed\":12"));
    }

    #[test]
    fn test_storage_gc_result_dry_run() {
        let result = StorageGcResult {
            dry_run: true,
            storage_keys_deleted: 0,
            artifacts_removed: 0,
            bytes_freed: 0,
            errors: vec![],
            maven_flat_objects_gated: 0,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"dry_run\":true"));
    }

    #[test]
    fn test_storage_gc_result_with_errors() {
        let result = StorageGcResult {
            dry_run: false,
            storage_keys_deleted: 3,
            artifacts_removed: 3,
            bytes_freed: 512,
            errors: vec!["Failed to delete key abc".to_string()],
            maven_flat_objects_gated: 0,
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: StorageGcResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.errors.len(), 1);
        assert_eq!(deserialized.storage_keys_deleted, 3);
    }

    // -----------------------------------------------------------------------
    // StorageGcResult: additional serde and edge-case tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_storage_gc_result_serde_roundtrip() {
        let original = StorageGcResult {
            dry_run: true,
            storage_keys_deleted: 42,
            artifacts_removed: 100,
            bytes_freed: 999_999_999,
            errors: vec![
                "error one".to_string(),
                "error two".to_string(),
                "error three".to_string(),
            ],
            maven_flat_objects_gated: 0,
        };
        let json = serde_json::to_string(&original).unwrap();
        let restored: StorageGcResult = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.dry_run, original.dry_run);
        assert_eq!(restored.storage_keys_deleted, original.storage_keys_deleted);
        assert_eq!(restored.artifacts_removed, original.artifacts_removed);
        assert_eq!(restored.bytes_freed, original.bytes_freed);
        assert_eq!(restored.errors, original.errors);
    }

    #[test]
    fn test_storage_gc_result_deserialization_from_json() {
        let json = r#"{
            "dry_run": false,
            "storage_keys_deleted": 7,
            "artifacts_removed": 20,
            "bytes_freed": 4096,
            "errors": ["something went wrong"]
        }"#;
        let result: StorageGcResult = serde_json::from_str(json).unwrap();
        assert!(!result.dry_run);
        assert_eq!(result.storage_keys_deleted, 7);
        assert_eq!(result.artifacts_removed, 20);
        assert_eq!(result.bytes_freed, 4096);
        assert_eq!(result.errors, vec!["something went wrong"]);
    }

    #[test]
    fn test_storage_gc_result_large_numbers() {
        let result = StorageGcResult {
            dry_run: false,
            storage_keys_deleted: i64::MAX,
            artifacts_removed: i64::MAX,
            bytes_freed: i64::MAX,
            errors: vec![],
            maven_flat_objects_gated: 0,
        };
        let json = serde_json::to_string(&result).unwrap();
        let restored: StorageGcResult = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.storage_keys_deleted, i64::MAX);
        assert_eq!(restored.artifacts_removed, i64::MAX);
        assert_eq!(restored.bytes_freed, i64::MAX);
    }

    #[test]
    fn test_storage_gc_result_empty_errors_vec() {
        let result = StorageGcResult {
            dry_run: false,
            storage_keys_deleted: 0,
            artifacts_removed: 0,
            bytes_freed: 0,
            errors: vec![],
            maven_flat_objects_gated: 0,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"errors\":[]"));
    }

    #[test]
    fn test_storage_gc_result_debug_format() {
        let result = StorageGcResult {
            dry_run: true,
            storage_keys_deleted: 1,
            artifacts_removed: 2,
            bytes_freed: 3,
            errors: vec!["err".to_string()],
            maven_flat_objects_gated: 0,
        };
        let debug = format!("{:?}", result);
        assert!(debug.contains("StorageGcResult"));
        assert!(debug.contains("dry_run: true"));
        assert!(debug.contains("storage_keys_deleted: 1"));
        assert!(debug.contains("artifacts_removed: 2"));
        assert!(debug.contains("bytes_freed: 3"));
        assert!(debug.contains("err"));
    }

    #[test]
    fn test_storage_gc_result_multiple_errors() {
        let errors: Vec<String> = (0..50).map(|i| format!("error {}", i)).collect();
        let result = StorageGcResult {
            dry_run: false,
            storage_keys_deleted: 50,
            artifacts_removed: 50,
            bytes_freed: 50 * 1024,
            errors: errors.clone(),
            maven_flat_objects_gated: 0,
        };
        let json = serde_json::to_string(&result).unwrap();
        let restored: StorageGcResult = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.errors.len(), 50);
        assert_eq!(restored.errors[0], "error 0");
        assert_eq!(restored.errors[49], "error 49");
    }

    // -----------------------------------------------------------------------
    // empty_gc_result
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_gc_result_dry_run_true() {
        let result = empty_gc_result(true);
        assert!(result.dry_run);
        assert_eq!(result.storage_keys_deleted, 0);
        assert_eq!(result.artifacts_removed, 0);
        assert_eq!(result.bytes_freed, 0);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_empty_gc_result_dry_run_false() {
        let result = empty_gc_result(false);
        assert!(!result.dry_run);
        assert_eq!(result.storage_keys_deleted, 0);
        assert_eq!(result.artifacts_removed, 0);
        assert_eq!(result.bytes_freed, 0);
        assert!(result.errors.is_empty());
    }

    // -----------------------------------------------------------------------
    // is_cloud_backend
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_cloud_backend_s3() {
        assert!(is_cloud_backend("s3"));
    }

    #[test]
    fn test_is_cloud_backend_azure() {
        assert!(is_cloud_backend("azure"));
    }

    #[test]
    fn test_is_cloud_backend_gcs() {
        assert!(is_cloud_backend("gcs"));
    }

    #[test]
    fn test_is_cloud_backend_filesystem() {
        assert!(!is_cloud_backend("filesystem"));
    }

    #[test]
    fn test_is_cloud_backend_empty_string() {
        assert!(!is_cloud_backend(""));
    }

    #[test]
    fn test_is_cloud_backend_unknown() {
        assert!(!is_cloud_backend("unknown"));
    }

    #[test]
    fn test_is_cloud_backend_case_sensitive() {
        assert!(!is_cloud_backend("S3"));
        assert!(!is_cloud_backend("Azure"));
        assert!(!is_cloud_backend("GCS"));
    }

    // -----------------------------------------------------------------------
    // format_gc_error
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_gc_error_basic() {
        let msg = format_gc_error("delete storage key", "abc123", "file not found");
        assert_eq!(
            msg,
            "Failed to delete storage key for key abc123: file not found"
        );
    }

    #[test]
    fn test_format_gc_error_hard_delete() {
        let msg = format_gc_error(
            "hard-delete artifacts",
            "sha256:deadbeef",
            "connection reset",
        );
        assert_eq!(
            msg,
            "Failed to hard-delete artifacts for key sha256:deadbeef: connection reset"
        );
    }

    #[test]
    fn test_format_gc_error_promotion_approvals() {
        let msg = format_gc_error(
            "delete promotion_approvals",
            "key-42",
            "foreign key violation",
        );
        assert_eq!(
            msg,
            "Failed to delete promotion_approvals for key key-42: foreign key violation"
        );
    }

    #[test]
    fn test_format_gc_error_special_chars_in_key() {
        let msg = format_gc_error("delete", "path/to/key with spaces", "denied");
        assert_eq!(
            msg,
            "Failed to delete for key path/to/key with spaces: denied"
        );
    }

    #[test]
    fn test_format_gc_error_special_chars_in_error() {
        let msg = format_gc_error("delete", "key1", "error: \"quote\" & <angle>");
        assert_eq!(
            msg,
            "Failed to delete for key key1: error: \"quote\" & <angle>"
        );
    }

    #[test]
    fn test_format_gc_error_empty_strings() {
        let msg = format_gc_error("", "", "");
        assert_eq!(msg, "Failed to  for key : ");
    }

    // -----------------------------------------------------------------------
    // accumulate_dry_run
    // -----------------------------------------------------------------------

    #[test]
    fn test_accumulate_dry_run_single_call() {
        let mut result = empty_gc_result(true);
        accumulate_dry_run(&mut result, 1024, 3);

        assert_eq!(result.storage_keys_deleted, 1);
        assert_eq!(result.artifacts_removed, 3);
        assert_eq!(result.bytes_freed, 1024);
    }

    #[test]
    fn test_accumulate_dry_run_multiple_calls() {
        let mut result = empty_gc_result(true);
        accumulate_dry_run(&mut result, 100, 2);
        accumulate_dry_run(&mut result, 200, 5);
        accumulate_dry_run(&mut result, 300, 1);

        assert_eq!(result.storage_keys_deleted, 3);
        assert_eq!(result.artifacts_removed, 8);
        assert_eq!(result.bytes_freed, 600);
    }

    #[test]
    fn test_accumulate_dry_run_zero_values() {
        let mut result = empty_gc_result(true);
        accumulate_dry_run(&mut result, 0, 0);

        assert_eq!(result.storage_keys_deleted, 1);
        assert_eq!(result.artifacts_removed, 0);
        assert_eq!(result.bytes_freed, 0);
    }

    #[test]
    fn test_accumulate_dry_run_preserves_errors() {
        let mut result = empty_gc_result(true);
        result.errors.push("pre-existing error".to_string());
        accumulate_dry_run(&mut result, 512, 1);

        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0], "pre-existing error");
    }

    // -----------------------------------------------------------------------
    // record_gc_success
    // -----------------------------------------------------------------------

    #[test]
    fn test_record_gc_success_single_call() {
        let mut result = empty_gc_result(false);
        record_gc_success(&mut result, 2048, 4);

        assert_eq!(result.storage_keys_deleted, 1);
        assert_eq!(result.artifacts_removed, 4);
        assert_eq!(result.bytes_freed, 2048);
    }

    #[test]
    fn test_record_gc_success_multiple_calls() {
        let mut result = empty_gc_result(false);
        record_gc_success(&mut result, 1000, 1);
        record_gc_success(&mut result, 2000, 2);
        record_gc_success(&mut result, 3000, 3);

        assert_eq!(result.storage_keys_deleted, 3);
        assert_eq!(result.artifacts_removed, 6);
        assert_eq!(result.bytes_freed, 6000);
    }

    #[test]
    fn test_record_gc_success_zero_values() {
        let mut result = empty_gc_result(false);
        record_gc_success(&mut result, 0, 0);

        assert_eq!(result.storage_keys_deleted, 1);
        assert_eq!(result.artifacts_removed, 0);
        assert_eq!(result.bytes_freed, 0);
    }

    #[test]
    fn test_record_gc_success_preserves_errors() {
        let mut result = empty_gc_result(false);
        result.errors.push("earlier failure".to_string());
        record_gc_success(&mut result, 512, 1);

        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0], "earlier failure");
        assert_eq!(result.storage_keys_deleted, 1);
    }

    // -----------------------------------------------------------------------
    // StorageGcService::new and storage_for_location
    // -----------------------------------------------------------------------

    fn loc(backend: &str, path: &str) -> StorageLocation {
        StorageLocation {
            backend: backend.to_string(),
            path: path.to_string(),
        }
    }

    #[tokio::test]
    async fn test_storage_for_location_s3_returns_shared() {
        let service = make_service("s3");
        let storage_a = service.storage_for_location(&loc("s3", "/repo/a")).unwrap();
        let storage_b = service.storage_for_location(&loc("s3", "/repo/b")).unwrap();

        // Both should point to the same Arc allocation (the shared storage).
        assert!(Arc::ptr_eq(&storage_a, &storage_b));
    }

    #[tokio::test]
    async fn test_storage_for_location_azure_returns_shared() {
        let service = make_service("azure");
        let storage_a = service
            .storage_for_location(&loc("azure", "/data/repo1"))
            .unwrap();
        let storage_b = service
            .storage_for_location(&loc("azure", "/data/repo2"))
            .unwrap();

        assert!(Arc::ptr_eq(&storage_a, &storage_b));
    }

    #[tokio::test]
    async fn test_storage_for_location_gcs_returns_shared() {
        let service = make_service("gcs");
        let storage_a = service
            .storage_for_location(&loc("gcs", "/bucket/path1"))
            .unwrap();
        let storage_b = service
            .storage_for_location(&loc("gcs", "/bucket/path2"))
            .unwrap();

        assert!(Arc::ptr_eq(&storage_a, &storage_b));
    }

    #[tokio::test]
    async fn test_storage_for_location_filesystem_creates_new() {
        let service = make_service("filesystem");
        let storage_a = service
            .storage_for_location(&loc("filesystem", "/data/repo-a"))
            .unwrap();
        let storage_b = service
            .storage_for_location(&loc("filesystem", "/data/repo-b"))
            .unwrap();

        // Filesystem backends should be distinct allocations per path.
        assert!(!Arc::ptr_eq(&storage_a, &storage_b));
    }

    #[tokio::test]
    async fn test_storage_for_location_unknown_returns_error() {
        let service = make_service("filesystem");
        let result = service.storage_for_location(&loc("minio", "/local/path"));
        assert!(result.is_err(), "Unknown backend should return error");
    }

    #[tokio::test]
    async fn test_storage_for_location_cloud_ignores_path() {
        let service = make_service("s3");
        let storage_root = service.storage_for_location(&loc("s3", "/")).unwrap();
        let storage_deep = service
            .storage_for_location(&loc("s3", "/very/deep/nested/path/to/repo"))
            .unwrap();

        // Cloud backends always return the same shared storage regardless of path.
        assert!(Arc::ptr_eq(&storage_root, &storage_deep));
    }

    // -----------------------------------------------------------------------
    // run_gc (database error path)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_run_gc_returns_error_when_db_unreachable() {
        let service = make_service("filesystem");
        // The lazy pool has no real database behind it, so run_gc must fail
        // when it tries to execute the orphan query.
        let result = service.run_gc(false).await;
        assert!(result.is_err(), "run_gc should fail without a database");
    }

    #[tokio::test]
    async fn test_run_gc_dry_run_returns_error_when_db_unreachable() {
        let service = make_service("s3");
        let result = service.run_gc(true).await;
        assert!(
            result.is_err(),
            "run_gc dry_run should also fail without a database"
        );
    }

    // -----------------------------------------------------------------------
    // repo_scope_clause (web #708)
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_scope_clause_unscoped_is_empty() {
        assert_eq!(repo_scope_clause("a.repository_id", 1, None), "");
    }

    #[test]
    fn test_repo_scope_clause_scoped_renders_and_predicate() {
        assert_eq!(
            repo_scope_clause("a.repository_id", 1, Some(Uuid::new_v4())),
            "AND a.repository_id = $1"
        );
    }

    #[test]
    fn test_repo_scope_clause_uses_supplied_param_index() {
        // Selects that already bind a LIMIT at $1 must place the scope bind
        // at $2; the index is the caller's, not the helper's.
        assert_eq!(
            repo_scope_clause("c.repository_id", 2, Some(Uuid::new_v4())),
            "AND c.repository_id = $2"
        );
    }

    // -----------------------------------------------------------------------
    // run_gc_for_repository (web #708)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_run_gc_for_repository_returns_error_when_db_unreachable() {
        let service = make_service("filesystem");
        let result = service.run_gc_for_repository(Uuid::new_v4(), false).await;
        assert!(
            result.is_err(),
            "repo-scoped run_gc should fail without a database"
        );
    }

    #[tokio::test]
    async fn test_run_gc_for_repository_dry_run_returns_error_when_db_unreachable() {
        let service = make_service("s3");
        let result = service.run_gc_for_repository(Uuid::new_v4(), true).await;
        assert!(
            result.is_err(),
            "repo-scoped dry run should also fail without a database"
        );
    }

    /// A soft-deleted, unreferenced artifact is an orphan candidate for its
    /// OWN repository's scoped scan, but must never appear in a scan scoped
    /// to a different repository — per-key assertions keep this isolated
    /// from concurrent tests sharing the database (#1493 pattern).
    #[tokio::test]
    async fn test_select_orphans_repo_scope_filters_to_target_repository() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "maven").await else {
            return;
        };

        let uid = Uuid::new_v4().simple().to_string();
        let storage_key = format!("maven/com/acme/{uid}/gc-scope-1.0.jar");
        insert_maven_artifact_row(
            &fixture.pool,
            fixture.repo_id,
            fixture.user_id,
            &storage_key,
            true,
        )
        .await;

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let own_repo = service.select_orphans(Some(fixture.repo_id)).await;
        let other_repo = service.select_orphans(Some(Uuid::new_v4())).await;

        let storage_path_str = fixture.storage_dir.to_string_lossy().into_owned();
        fixture.teardown().await;

        let key_present = |orphans: &[sqlx::postgres::PgRow]| {
            orphans.iter().any(|row| {
                let key: String = row.try_get("storage_key").unwrap_or_default();
                let path: String = row.try_get("storage_path").unwrap_or_default();
                key == storage_key && path == storage_path_str
            })
        };

        let own_repo = own_repo.expect("own-repo scoped scan succeeds");
        assert!(
            key_present(&own_repo),
            "scan scoped to the owning repository must include its orphan key"
        );
        let other_repo = other_repo.expect("other-repo scoped scan succeeds");
        assert!(
            !key_present(&other_repo),
            "scan scoped to a different repository must not include the key"
        );
    }

    /// Reference kind for [`insert_referenced_soft_deleted_artifact`].
    enum RefKind {
        /// Insert an `oci_tags` row pointing at the digest.
        Tag {
            image: &'static str,
            tag: &'static str,
        },
        /// Insert an `oci_blobs` row pointing at the digest.
        Blob,
    }

    /// Set up the canonical "soft-deleted artifact still referenced by an
    /// OCI table" scenario for storage-GC isolation tests.
    ///
    /// Inserts an `oci_tags` or `oci_blobs` row for `digest` and a
    /// soft-deleted `artifacts` row pointing at the same `storage_key`.
    /// Returns the byte size that was written to the `artifacts` row so
    /// callers can correlate with on-disk data when needed.
    ///
    /// Centralizing this layout removes the boilerplate duplication that
    /// previously lived inline in the three GC isolation tests and makes
    /// it easy for new regression tests to follow the same pattern.
    async fn insert_referenced_soft_deleted_artifact(
        pool: &PgPool,
        repo_id: Uuid,
        user_id: Uuid,
        digest: &str,
        storage_key: &str,
        size_bytes: i64,
        kind: RefKind,
    ) {
        let (path, name, version, content_type, checksum) = match &kind {
            RefKind::Tag { image, tag } => {
                sqlx::query(
                    r#"
                    INSERT INTO oci_tags (
                        repository_id, name, tag, manifest_digest, manifest_content_type
                    )
                    VALUES ($1, $2, $3, $4, 'application/vnd.oci.image.manifest.v1+json')
                    "#,
                )
                .bind(repo_id)
                .bind(*image)
                .bind(*tag)
                .bind(digest)
                .execute(pool)
                .await
                .expect("insert oci tag");
                (
                    format!("v2/{}/manifests/{}", image, tag),
                    format!("{}:{}", image, tag),
                    (*tag).to_string(),
                    "application/vnd.oci.image.manifest.v1+json",
                    digest.trim_start_matches("sha256:").to_string(),
                )
            }
            RefKind::Blob => {
                sqlx::query(
                    r#"
                    INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key)
                    VALUES ($1, $2, $3, $4)
                    "#,
                )
                .bind(repo_id)
                .bind(digest)
                .bind(size_bytes)
                .bind(storage_key)
                .execute(pool)
                .await
                .expect("insert oci blob");
                (
                    format!("v2/gc-image/blobs/{}", digest),
                    format!("gc-image:{}", digest),
                    digest.to_string(),
                    "application/octet-stream",
                    digest.trim_start_matches("sha256:").to_string(),
                )
            }
        };

        sqlx::query(
            r#"
            INSERT INTO artifacts (
                id, repository_id, path, name, version, size_bytes,
                checksum_sha256, content_type, storage_key, uploaded_by, is_deleted
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, true)
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(repo_id)
        .bind(path)
        .bind(name)
        .bind(version)
        .bind(size_bytes)
        .bind(checksum)
        .bind(content_type)
        .bind(storage_key)
        .bind(user_id)
        .execute(pool)
        .await
        .expect("insert soft-deleted artifact");
    }

    /// Assert that `(storage_key, "filesystem", storage_path)` does NOT
    /// appear in the dry-run orphan-candidate set returned by
    /// [`StorageGcService::select_orphans`]. The per-key form is the
    /// isolation-safe alternative to asserting on the global
    /// `storage_keys_deleted` counter (see #1493).
    fn assert_key_not_orphaned(
        orphans: &[sqlx::postgres::PgRow],
        storage_key: &str,
        storage_path: &str,
        ref_kind: &str,
    ) {
        let our_key_collected = orphans.iter().any(|row| {
            let key: String = row.try_get("storage_key").unwrap_or_default();
            let backend: String = row.try_get("storage_backend").unwrap_or_default();
            let path: String = row.try_get("storage_path").unwrap_or_default();
            key == storage_key && backend == "filesystem" && path == storage_path
        });
        assert!(
            !our_key_collected,
            "GC must not flag {} as orphan while it is still referenced by {}",
            storage_key, ref_kind
        );
    }

    #[tokio::test]
    async fn test_run_gc_dry_run_keeps_oci_manifest_referenced_by_tag() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let digest = format!("sha256:{}", "a".repeat(64));
        let storage_key = format!("oci-manifests/{}", digest);

        insert_referenced_soft_deleted_artifact(
            &fixture.pool,
            fixture.repo_id,
            fixture.user_id,
            &digest,
            &storage_key,
            123,
            RefKind::Tag {
                image: "gc-image",
                tag: "latest",
            },
        )
        .await;

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let orphans = service.select_orphans(None).await;

        let storage_path_str = fixture.storage_dir.to_string_lossy().into_owned();
        fixture.teardown().await;

        let orphans = orphans.expect("dry-run candidate scan succeeds");
        assert_key_not_orphaned(&orphans, &storage_key, &storage_path_str, "oci_tags");
    }

    #[tokio::test]
    async fn test_run_gc_dry_run_keeps_oci_blob_referenced_by_blob_index() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let digest = format!("sha256:{}", "b".repeat(64));
        let storage_key = format!("oci-blobs/{}", digest);

        insert_referenced_soft_deleted_artifact(
            &fixture.pool,
            fixture.repo_id,
            fixture.user_id,
            &digest,
            &storage_key,
            456,
            RefKind::Blob,
        )
        .await;

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let orphans = service.select_orphans(None).await;

        let storage_path_str = fixture.storage_dir.to_string_lossy().into_owned();
        fixture.teardown().await;

        let orphans = orphans.expect("dry-run candidate scan succeeds");
        assert_key_not_orphaned(&orphans, &storage_key, &storage_path_str, "oci_blobs");
    }

    // -----------------------------------------------------------------------
    // #2668: row-less Maven sidecar + metadata reclamation
    // -----------------------------------------------------------------------

    /// The sidecar suffix regex embedded (three times) in
    /// [`ORPHAN_MAVEN_FLAT_PREDICATE_SQL`] must be the one the delete guards
    /// share — `GUARDED_SIDECAR_SUFFIXES`, not `MAVEN_SIDECAR_SUFFIXES`. A
    /// suffix missing from the SQL silently exempts that sidecar class from
    /// guards 3/4/5, and an exempt sidecar in a `NOT EXISTS` guard is a
    /// PURGED one.
    ///
    /// The two lists point in opposite directions and pinning the wrong one is
    /// how #3197 happened: the predicate was pinned to `MAVEN_SIDECAR_SUFFIXES`
    /// (the four suffixes GC *derives for deletion*), so `.asc` — which the read
    /// path resolves to its base and which migrations 163/170 backfill into the
    /// attribution table — was never recognised as a sidecar here at all.
    ///
    /// This is the only check on the `.asc` gap that runs WITHOUT a database;
    /// `test_orphan_maven_flat_scan_spares_asc_signature_of_live_base_3197`
    /// skips silently when `DATABASE_URL` is unset.
    #[test]
    fn test_maven_sidecar_suffixes_match_flat_predicate_sql() {
        use crate::services::maven_flat_attribution::GUARDED_SIDECAR_SUFFIXES;
        for suffix in GUARDED_SIDECAR_SUFFIXES {
            let bare = suffix.trim_start_matches('.');
            assert!(
                ORPHAN_MAVEN_FLAT_PREDICATE_SQL.contains(bare),
                "ORPHAN_MAVEN_FLAT_PREDICATE_SQL is missing guarded sidecar \
                 suffix {suffix}: keys ending in it are not recognised as \
                 sidecars, so guards 4/5 never fire and the object is purged \
                 while its base is still served (#3197)"
            );
        }
        let expected_alternation = format!(
            "({})",
            GUARDED_SIDECAR_SUFFIXES
                .map(|s| s.trim_start_matches('.'))
                .join("|")
        );
        assert!(
            ORPHAN_MAVEN_FLAT_PREDICATE_SQL.contains(&expected_alternation),
            "the SQL sidecar regex alternation must be built from \
             GUARDED_SIDECAR_SUFFIXES; expected {expected_alternation}"
        );
        // ...and every suffix GC derives for deletion must be in there too.
        // `guarded_sidecar_suffixes_are_a_superset_of_the_gc_derived_list`
        // pins the containment; this states the consequence for the SQL.
        for suffix in MAVEN_SIDECAR_SUFFIXES {
            assert!(
                GUARDED_SIDECAR_SUFFIXES.contains(&suffix),
                "{suffix} is derived for deletion but not guarded"
            );
        }
    }

    /// Guard 3 (the `maven-metadata.xml` rollup anchor) must be built from the
    /// fragments the repository-delete collector also uses, so the two delete
    /// paths cannot disagree about which keys are rollups or which directory a
    /// rollup covers — the divergence #3197 reported in the other direction.
    #[test]
    fn test_flat_predicate_rollup_guard_uses_shared_fragments() {
        use crate::services::maven_flat_attribution as mfa;
        for fragment in [
            mfa::is_metadata_rollup_key_sql("o.storage_key"),
            mfa::metadata_rollup_dir_prefix_sql("o.storage_key"),
        ] {
            assert!(
                ORPHAN_MAVEN_FLAT_PREDICATE_SQL.contains(&fragment),
                "the rollup guard must use the shared fragment `{fragment}`, \
                 not an inline copy"
            );
        }
    }

    /// #3156: a live parent artifact's metadata `files[]` must anchor its
    /// row-less companion against the flat-object sweep under BOTH spellings —
    /// primarily camelCase `storageKey`, which is what the GAV-grouped upload
    /// handler writes. The two guards this covers are `NOT EXISTS`, so a missed
    /// reference means DELETE: pre-fix, the sweep collected a live companion
    /// (guard 2) and its checksum sidecar (guard 5) for purge while the parent
    /// was still serving them.
    ///
    /// This test FAILS if either production predicate is reverted to the
    /// `jsonb_array_elements ... f->>'storage_key'` form, and its positive
    /// control (a genuinely unreferenced key) keeps the fix from passing by
    /// never collecting anything.
    ///
    /// The scan is repository-scoped, so this test does not race the
    /// cluster-wide `test_run_gc_*` tests and needs no GC lock (#1493 pattern).
    #[tokio::test]
    async fn test_orphan_maven_flat_scan_spares_camelcase_referenced_companion_3156() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fixture) = tdh::Fixture::setup("local", "maven").await else {
            return;
        };
        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let uid = Uuid::new_v4().simple().to_string();

        let camel_key = format!("maven/gav3156/{uid}/demo-1.0.0.pom");
        let camel_sidecar = format!("{camel_key}.sha1");
        let snake_key = format!("maven/gav3156/{uid}/demo-1.0.0-sources.jar");
        let orphan_key = format!("maven/gav3156/{uid}/gone-9.9.9.pom");

        seed_flat_parent_metadata(
            &fixture.pool,
            fixture.repo_id,
            fixture.user_id,
            &format!("maven/gav3156/{uid}/demo-1.0.0.jar"),
            "storageKey",
            &camel_key,
        )
        .await;
        seed_flat_parent_metadata(
            &fixture.pool,
            fixture.repo_id,
            fixture.user_id,
            &format!("maven/gav3156/{uid}/legacy-1.0.0.jar"),
            "storage_key",
            &snake_key,
        )
        .await;
        for key in [&camel_key, &camel_sidecar, &snake_key, &orphan_key] {
            insert_flat_attribution_row(&fixture.pool, fixture.repo_id, key, 2).await;
        }

        let rows = service
            .select_orphan_maven_flat_objects(Some(fixture.repo_id))
            .await;
        let collected: Vec<String> = rows
            .expect("scan succeeds")
            .iter()
            .map(|r| r.get::<String, _>("storage_key"))
            .collect();
        fixture.teardown().await;

        assert!(
            !collected.contains(&camel_key),
            "guard 2: a companion its live parent lists as camelCase \
             `storageKey` must NOT be collected for purge (#3156); \
             collected: {collected:?}"
        );
        assert!(
            !collected.contains(&camel_sidecar),
            "guard 5: the checksum sidecar of a camelCase-listed companion \
             must NOT be collected either (#3156); collected: {collected:?}"
        );
        assert!(
            !collected.contains(&snake_key),
            "the snake_case spelling must keep being honoured too; \
             collected: {collected:?}"
        );
        assert!(
            collected.contains(&orphan_key),
            "positive control: a key no parent references must still be \
             collected for purge; collected: {collected:?}"
        );
    }

    /// #3197: the flat-object sweep must not reclaim a `.asc` signature whose
    /// base object is still anchored.
    ///
    /// Guards 3/4/5 tested `\.(md5|sha1|sha256|sha512)$` — the list GC derives
    /// keys to DELETE from — while the read path resolves `.asc` to its base
    /// (`strip_checksum_suffix`) and migrations 163 / 170 step (3') backfill
    /// `.asc` rows into `maven_flat_object_owner`. So a `.asc` matched neither
    /// the verbatim guards (nothing references a sidecar by name) nor the
    /// sidecar arms (it was not recognised as a sidecar), read as orphan, and
    /// was collected while the server was still serving it.
    ///
    /// Both anchoring shapes the `.asc` gap reaches are covered: guard 4 (base
    /// with a live `artifacts` row) and guard 3 (a `maven-metadata.xml` rollup
    /// whose subtree is still live).
    ///
    /// TWO positive controls keep the fix honest — a `.asc` whose base is
    /// genuinely unreferenced, and a rollup `.asc` over an empty subtree.
    /// Without them, sparing every key ending in `.asc` would pass.
    #[tokio::test]
    async fn test_orphan_maven_flat_scan_spares_asc_signature_of_live_base_3197() {
        use crate::api::handlers::test_db_helpers as tdh;
        let Some(fixture) = tdh::Fixture::setup("local", "maven").await else {
            return;
        };
        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let uid = Uuid::new_v4().simple().to_string();

        // Guard 4: a live base object; its `.asc` and `.sha1` are row-less.
        let pom = format!("maven/gav3197/{uid}/lib/1.0/lib-1.0.pom");
        let pom_asc = format!("{pom}.asc");
        let pom_sha1 = format!("{pom}.sha1");
        // Guard 3: the rollup over that still-live subtree, signed.
        let live_rollup_asc = format!("maven/gav3197/{uid}/lib/maven-metadata.xml.asc");
        // Positive controls: nothing anchors either of these.
        let orphan_asc = format!("maven/gav3197/{uid}/lib/9.9.9/gone-9.9.9.pom.asc");
        let dead_rollup_asc = format!("maven/gav3197/{uid}/dead/maven-metadata.xml.asc");

        insert_maven_artifact_row(&fixture.pool, fixture.repo_id, fixture.user_id, &pom, false)
            .await;
        for key in [
            &pom_asc,
            &pom_sha1,
            &live_rollup_asc,
            &orphan_asc,
            &dead_rollup_asc,
        ] {
            insert_flat_attribution_row(&fixture.pool, fixture.repo_id, key, 2).await;
        }

        let rows = service
            .select_orphan_maven_flat_objects(Some(fixture.repo_id))
            .await;
        let collected: Vec<String> = rows
            .expect("scan succeeds")
            .iter()
            .map(|r| r.get::<String, _>("storage_key"))
            .collect();
        fixture.teardown().await;

        assert!(
            !collected.contains(&pom_asc),
            "guard 4: the `.asc` signature of a base with a live artifacts row \
             must NOT be collected — the read path still serves it off that \
             base (#3197); collected: {collected:?}"
        );
        assert!(
            !collected.contains(&pom_sha1),
            "the `.sha1` of the same base must keep being spared too; \
             collected: {collected:?}"
        );
        assert!(
            !collected.contains(&live_rollup_asc),
            "guard 3: the `.asc` of a maven-metadata.xml whose subtree is still \
             live must NOT be collected — losing it breaks signature \
             verification of the document that resolves version ranges \
             (#3197); collected: {collected:?}"
        );
        assert!(
            collected.contains(&orphan_asc),
            "positive control: a `.asc` whose BASE nothing anchors is a genuine \
             orphan and must still be collected — otherwise sparing every \
             `.asc` unconditionally would pass; collected: {collected:?}"
        );
        assert!(
            collected.contains(&dead_rollup_asc),
            "positive control: a rollup `.asc` over a subtree with no live \
             artifact must still be collected; collected: {collected:?}"
        );
    }

    /// Seed a parent `artifacts` row plus an `artifact_metadata` row whose
    /// `files[]` array lists a row-less companion under `json_key_name`.
    async fn seed_flat_parent_metadata(
        pool: &PgPool,
        repo_id: Uuid,
        user_id: Uuid,
        parent_key: &str,
        json_key_name: &str,
        companion_key: &str,
    ) {
        insert_maven_artifact_row(pool, repo_id, user_id, parent_key, false).await;
        crate::api::handlers::test_db_helpers::attach_maven_files_metadata(
            pool,
            parent_key,
            json_key_name,
            companion_key,
        )
        .await;
    }

    /// Insert a Maven `artifacts` row pointing at `storage_key`
    /// (`path` = key without the `maven/` prefix).
    async fn insert_maven_artifact_row(
        pool: &PgPool,
        repo_id: Uuid,
        user_id: Uuid,
        storage_key: &str,
        is_deleted: bool,
    ) {
        sqlx::query(
            r#"
            INSERT INTO artifacts (
                id, repository_id, path, name, version, size_bytes,
                checksum_sha256, content_type, storage_key, uploaded_by, is_deleted
            )
            VALUES ($1, $2, $3, 'gc2668', '1.0', 10, 'cafe', 'application/java-archive',
                    $4, $5, $6)
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(repo_id)
        .bind(storage_key.trim_start_matches("maven/"))
        .bind(storage_key)
        .bind(user_id)
        .bind(is_deleted)
        .execute(pool)
        .await
        .expect("insert maven artifact row");
    }

    /// Insert a `maven_flat_object_owner` attribution row aged `age_hours`
    /// into the past (0 = fresh).
    async fn insert_flat_attribution_row(
        pool: &PgPool,
        repo_id: Uuid,
        storage_key: &str,
        age_hours: i32,
    ) {
        insert_flat_attribution_row_with_source(
            pool,
            repo_id,
            storage_key,
            age_hours,
            "write_claim",
        )
        .await;
    }

    /// [`insert_flat_attribution_row`] with an explicit `source`, for the
    /// #3431 tests that turn on which writer produced the row. `source` is a
    /// test literal, never external input.
    async fn insert_flat_attribution_row_with_source(
        pool: &PgPool,
        repo_id: Uuid,
        storage_key: &str,
        age_hours: i32,
        source: &str,
    ) {
        sqlx::query(
            "INSERT INTO maven_flat_object_owner \
                 (storage_backend, storage_key, repository_id, source, created_at) \
             VALUES ('filesystem', $1, $2, $4, \
                     NOW() - make_interval(hours => $3))",
        )
        .bind(storage_key)
        .bind(repo_id)
        .bind(age_hours)
        .bind(source)
        .execute(pool)
        .await
        .expect("insert flat attribution row");
    }

    fn fixture_storage(
        fixture: &crate::api::handlers::test_db_helpers::Fixture,
    ) -> Arc<dyn crate::storage::StorageBackend> {
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend")
    }
    /// Shared scaffolding for the #2668 tests: maven fixture, its filesystem
    /// storage backend, a GC service, and a unique key namespace.
    async fn maven_gc_2668_setup() -> Option<(
        crate::api::handlers::test_db_helpers::Fixture,
        Arc<dyn crate::storage::StorageBackend>,
        StorageGcService,
        String,
    )> {
        let fixture =
            crate::api::handlers::test_db_helpers::Fixture::setup("local", "maven").await?;
        let storage = fixture_storage(&fixture);
        // These are the #2668 RECLAIM tests, so they opt the flat-object
        // sweep in explicitly (#3431). The default is report-only; the gate
        // itself is covered by
        // `test_run_gc_gated_flat_sweep_reports_but_deletes_nothing_3431`.
        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone())
                .with_maven_flat_gc_enabled(true);
        let uid = Uuid::new_v4().simple().to_string();
        Some((fixture, storage, service, uid))
    }

    async fn seed_objects(storage: &Arc<dyn crate::storage::StorageBackend>, keys: &[&String]) {
        for key in keys {
            storage
                .put(key, Bytes::from_static(b"gc2668"))
                .await
                .expect("seed object");
        }
    }

    /// `exists()` per key, in order. Errors fail the test (filesystem exists
    /// checks should never error here).
    async fn objects_left(
        storage: &Arc<dyn crate::storage::StorageBackend>,
        keys: &[&String],
    ) -> Vec<bool> {
        let mut left = Vec::with_capacity(keys.len());
        for key in keys {
            left.push(storage.exists(key).await.expect("exists check"));
        }
        left
    }

    async fn count_rows(pool: &PgPool, table_sql: &str, key: &str) -> i64 {
        sqlx::query_scalar(table_sql)
            .bind(key)
            .fetch_one(pool)
            .await
            .expect("count rows")
    }

    const COUNT_ARTIFACTS_SQL: &str = "SELECT COUNT(*) FROM artifacts WHERE storage_key = $1";
    const COUNT_ATTRIBUTION_SQL: &str =
        "SELECT COUNT(*) FROM maven_flat_object_owner WHERE storage_key = $1";

    /// #2668 exploit repro, fixed: deleting a Maven package left its `.md5` /
    /// `.sha1` checksum sidecars on storage forever, because those are
    /// row-less puts the artifacts-driven sweep never enumerates. Reclaiming
    /// the base key must now take its sidecars with it.
    #[tokio::test]
    async fn test_run_gc_reclaims_maven_checksum_sidecars_2668() {
        let _gc_guard = storage_gc_test_guard().await;
        let Some((fixture, storage, service, uid)) = maven_gc_2668_setup().await else {
            return;
        };

        let jar = format!("maven/gc2668/{uid}/app/1.0/app-1.0.jar");
        let sha1 = format!("{jar}.sha1");
        let md5 = format!("{jar}.md5");
        seed_objects(&storage, &[&jar, &sha1, &md5]).await;
        insert_maven_artifact_row(&fixture.pool, fixture.repo_id, fixture.user_id, &jar, true)
            .await;

        let gc = service.run_gc(false).await;

        let left = objects_left(&storage, &[&jar, &sha1, &md5]).await;
        let rows_left = count_rows(&fixture.pool, COUNT_ARTIFACTS_SQL, &jar).await;
        fixture.teardown().await;

        gc.expect("run_gc succeeds");
        assert_eq!(
            left,
            vec![false, false, false],
            "orphan Maven base object AND its row-less .sha1/.md5 sidecars \
             must all be reclaimed (#2668)"
        );
        assert_eq!(rows_left, 0, "soft-deleted artifact rows are hard-deleted");
    }

    /// Reference-safety: a live Maven artifact keeps its object AND its
    /// sidecars; and a key that merely LOOKS like a sidecar but is backed by
    /// its own live `artifacts` row is never blind-deleted when the
    /// lookalike base is reclaimed.
    #[tokio::test]
    async fn test_run_gc_never_deletes_referenced_maven_objects_2668() {
        let _gc_guard = storage_gc_test_guard().await;
        let Some((fixture, storage, service, uid)) = maven_gc_2668_setup().await else {
            return;
        };

        // Scenario 1: live artifact + sidecar -> everything survives.
        let live_jar = format!("maven/gc2668/{uid}/live/1.0/live-1.0.jar");
        let live_sha1 = format!("{live_jar}.sha1");
        // Scenario 2: orphan base whose ".sha512" key is a real, LIVE,
        // row-backed artifact -> base reclaimed, lookalike untouched.
        let orphan_jar = format!("maven/gc2668/{uid}/edge/1.0/edge-1.0.jar");
        let lookalike = format!("{orphan_jar}.sha512");
        seed_objects(&storage, &[&live_jar, &live_sha1, &orphan_jar, &lookalike]).await;
        for (key, is_deleted) in [(&live_jar, false), (&orphan_jar, true), (&lookalike, false)] {
            insert_maven_artifact_row(
                &fixture.pool,
                fixture.repo_id,
                fixture.user_id,
                key,
                is_deleted,
            )
            .await;
        }

        let gc = service.run_gc(false).await;

        let left = objects_left(&storage, &[&live_jar, &live_sha1, &orphan_jar, &lookalike]).await;
        let lookalike_rows = count_rows(&fixture.pool, COUNT_ARTIFACTS_SQL, &lookalike).await;
        fixture.teardown().await;

        gc.expect("run_gc succeeds");
        assert_eq!(
            left,
            vec![true, true, false, true],
            "live artifact + its sidecar survive; the orphan base is reclaimed; \
             a row-backed live object whose key looks like a sidecar is never \
             blind-deleted (#2668 safety)"
        );
        assert_eq!(lookalike_rows, 1, "the live lookalike row must be intact");
    }

    /// The flat-object sweep reclaims a stored `maven-metadata.xml` (and its
    /// sidecar) once no live artifact remains under its directory, and drops
    /// the attribution rows so the key is not locked forever.
    #[tokio::test]
    async fn test_run_gc_collects_orphan_maven_metadata_2668() {
        let _gc_guard = storage_gc_test_guard().await;
        let Some((fixture, storage, service, uid)) = maven_gc_2668_setup().await else {
            return;
        };

        let meta = format!("maven/gc2668/{uid}/lib/maven-metadata.xml");
        let meta_sha1 = format!("{meta}.sha1");
        seed_objects(&storage, &[&meta, &meta_sha1]).await;
        // Aged rows (past the 1h in-flight-publish grace); no live artifacts
        // exist under maven/gc2668/{uid}/lib/.
        insert_flat_attribution_row(&fixture.pool, fixture.repo_id, &meta, 2).await;
        insert_flat_attribution_row(&fixture.pool, fixture.repo_id, &meta_sha1, 2).await;

        let gc = service.run_gc(false).await;

        let left = objects_left(&storage, &[&meta, &meta_sha1]).await;
        let rows_left = count_rows(&fixture.pool, COUNT_ATTRIBUTION_SQL, &meta).await
            + count_rows(&fixture.pool, COUNT_ATTRIBUTION_SQL, &meta_sha1).await;
        fixture.teardown().await;

        gc.expect("run_gc succeeds");
        assert_eq!(
            left,
            vec![false, false],
            "orphaned maven-metadata.xml and its checksum sidecar must be \
             reclaimed once their directory has no live artifacts (#2668)"
        );
        assert_eq!(
            rows_left, 0,
            "attribution rows are dropped with the objects"
        );
    }

    /// Safety + grace: a stored `maven-metadata.xml` whose directory still
    /// holds a live version is protected, and a freshly-claimed key (younger
    /// than the in-flight-publish grace) is not touched even when orphan.
    #[tokio::test]
    async fn test_run_gc_keeps_live_and_fresh_maven_metadata_2668() {
        let _gc_guard = storage_gc_test_guard().await;
        let Some((fixture, storage, service, uid)) = maven_gc_2668_setup().await else {
            return;
        };

        // Live version under the GA directory protects its metadata.
        let jar = format!("maven/gc2668/{uid}/keep/1.0/keep-1.0.jar");
        let meta = format!("maven/gc2668/{uid}/keep/maven-metadata.xml");
        // Fresh orphan claim: inside the grace window.
        let fresh_meta = format!("maven/gc2668/{uid}/fresh/maven-metadata.xml");
        seed_objects(&storage, &[&jar, &meta, &fresh_meta]).await;
        insert_maven_artifact_row(&fixture.pool, fixture.repo_id, fixture.user_id, &jar, false)
            .await;
        insert_flat_attribution_row(&fixture.pool, fixture.repo_id, &meta, 2).await;
        insert_flat_attribution_row(&fixture.pool, fixture.repo_id, &fresh_meta, 0).await;

        let gc = service.run_gc(false).await;

        let left = objects_left(&storage, &[&meta, &fresh_meta]).await;
        let rows_left = count_rows(&fixture.pool, COUNT_ATTRIBUTION_SQL, &meta).await
            + count_rows(&fixture.pool, COUNT_ATTRIBUTION_SQL, &fresh_meta).await;
        fixture.teardown().await;

        gc.expect("run_gc succeeds");
        assert_eq!(
            left,
            vec![true, true],
            "maven-metadata.xml survives while a live version exists under its \
             directory, and a claim younger than the grace window is not swept \
             (#2668 safety)"
        );
        assert_eq!(rows_left, 2, "both attribution rows must be intact");
    }

    // -----------------------------------------------------------------------
    // #3431: the attribution table must not nominate its own keys for deletion
    // -----------------------------------------------------------------------

    /// Revert-proof, DB-free: the source allowlist must be IN the predicate,
    /// and every value in it must be one the system actually writes.
    ///
    /// `ORPHAN_MAVEN_FLAT_PREDICATE_SQL` enumerates its candidates FROM
    /// `maven_flat_object_owner` and tests catalog anchors only. Since
    /// #2574/#2585 an owner row is also what makes a row-less legacy object
    /// READABLE, so for an object whose only catalog record is its owner row
    /// every anchor arm is true by construction and permanently: without this
    /// arm the row that makes the object servable is the row that queues it
    /// for deletion (#3431).
    #[test]
    fn test_flat_predicate_restricts_reclaim_to_system_written_sources_3431() {
        use crate::services::maven_flat_attribution as mfa;

        let arm = mfa::system_written_source_sql("o.source");
        assert!(
            ORPHAN_MAVEN_FLAT_PREDICATE_SQL.contains(&arm),
            "ORPHAN_MAVEN_FLAT_PREDICATE_SQL must restrict reclaim to \
             system-written attribution sources (#3431); expected the arm \
             {arm} to appear in:\n{}",
            ORPHAN_MAVEN_FLAT_PREDICATE_SQL.as_str()
        );
        for source in mfa::SYSTEM_WRITTEN_ATTRIBUTION_SOURCES {
            assert!(
                arm.contains(&format!("'{source}'")),
                "{source} must be quoted into the SQL allowlist"
            );
        }
        // An ALLOWLIST, not a denylist: the arm must name the sources it
        // permits, never the ones it excludes, so an unknown/future value is
        // protected by default rather than reclaimed by default.
        assert!(
            arm.contains(" IN (") && !arm.contains("NOT IN"),
            "the source arm must be an allowlist (`IN`), so unknown sources \
             fail SAFE (#3431); got: {arm}"
        );
    }

    /// #3431 repro, fixed: an operator repairs a fail-closed 404 by inserting
    /// an attribution row by hand (`source='manual'`, the documented
    /// remediation for keys the catalog-only backfill of migrations 163/170
    /// cannot see). Before the fix the next hourly pass deleted the S3 object
    /// AND the row, so the key went 404 -> 200 -> permanently gone.
    ///
    /// The sweep is opted IN here, so this test isolates the source allowlist
    /// from the opt-in gate: reverting the allowlist alone must fail it.
    ///
    /// The `write_claim` positive control is load-bearing — the fix must not
    /// disable the sweep's legitimate purpose. An orphaned claim left by a
    /// crashed first publish is exactly the leftover it exists to collect,
    /// and without this assertion "spare everything" would pass.
    #[tokio::test]
    async fn test_run_gc_spares_operator_attributed_flat_object_3431() {
        let Some((fixture, storage, service, uid)) = maven_gc_2668_setup().await else {
            return;
        };

        // Hand-repaired legacy companion: no artifacts row, no files[]
        // reference, nothing under its directory. Its owner row is the ONLY
        // record of it, and the only reason a GET serves it.
        let manual = format!("maven/gc3431/{uid}/com/example/lib/1.0.0/lib-1.0.0.pom");
        // Orphaned write claim from a crashed publish: system-written, and
        // re-derivable (the next publish re-claims the key).
        let claim = format!("maven/gc3431/{uid}/com/example/crashed/1.0.0/crashed-1.0.0.jar");
        seed_objects(&storage, &[&manual, &claim]).await;
        insert_flat_attribution_row_with_source(
            &fixture.pool,
            fixture.repo_id,
            &manual,
            2,
            "manual",
        )
        .await;
        insert_flat_attribution_row(&fixture.pool, fixture.repo_id, &claim, 2).await;

        let gc = service.run_gc_for_repository(fixture.repo_id, false).await;

        let left = objects_left(&storage, &[&manual, &claim]).await;
        let manual_rows = count_rows(&fixture.pool, COUNT_ATTRIBUTION_SQL, &manual).await;
        let claim_rows = count_rows(&fixture.pool, COUNT_ATTRIBUTION_SQL, &claim).await;
        fixture.teardown().await;

        gc.expect("run_gc_for_repository succeeds");
        assert!(
            left[0],
            "an object whose owner row an OPERATOR wrote (source='manual') \
             must survive the sweep — that row is a primary record, not a \
             re-derivable cache, and deleting the object destroys the only \
             physical copy (#3431)"
        );
        assert_eq!(
            manual_rows, 1,
            "the operator's attribution row must survive too — it is the only \
             record that the key was hand-attributed, and losing it makes the \
             object unreadable even if the bytes were restored (#3431)"
        );
        assert!(
            !left[1],
            "positive control: an orphaned `write_claim` is system-written and \
             re-derivable, so it must STILL be reclaimed — the fix must not \
             disable the sweep's legitimate purpose (#3431)"
        );
        assert_eq!(
            claim_rows, 0,
            "the reclaimed claim's attribution row is dropped with its object"
        );
    }

    /// Per-source candidacy, at the scan: every system-written source stays
    /// reclaimable once its anchors are gone, and every non-system source —
    /// including a value no code in this tree has ever written — is spared.
    ///
    /// The unknown-source case (`external_repair_tool`) is the FAIL-SAFE
    /// property: the arm is an allowlist, so a value stamped by a future code
    /// path or an external repair tool is protected until someone
    /// deliberately adds it. Getting this backwards leaks storage; getting it
    /// right the other way destroys the only copy of an object.
    ///
    /// Repository-scoped, so no GC lock is needed (#1493 pattern).
    #[tokio::test]
    async fn test_orphan_maven_flat_scan_spares_non_system_sources_3431() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::maven_flat_attribution::SYSTEM_WRITTEN_ATTRIBUTION_SOURCES;

        let Some(fixture) = tdh::Fixture::setup("local", "maven").await else {
            return;
        };
        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let uid = Uuid::new_v4().simple().to_string();

        // Non-system sources: the operator repair from the report, plus a
        // value nothing in this tree writes.
        let protected_sources = ["manual", "external_repair_tool"];

        let mut expect_collected = Vec::new();
        for source in SYSTEM_WRITTEN_ATTRIBUTION_SOURCES {
            let key = format!("maven/scan3431/{uid}/{source}/1.0/gone-1.0.pom");
            insert_flat_attribution_row_with_source(
                &fixture.pool,
                fixture.repo_id,
                &key,
                2,
                source,
            )
            .await;
            expect_collected.push((source, key));
        }
        let mut expect_spared = Vec::new();
        for source in protected_sources {
            let key = format!("maven/scan3431/{uid}/{source}/1.0/kept-1.0.pom");
            insert_flat_attribution_row_with_source(
                &fixture.pool,
                fixture.repo_id,
                &key,
                2,
                source,
            )
            .await;
            expect_spared.push((source, key));
        }

        let rows = service
            .select_orphan_maven_flat_objects(Some(fixture.repo_id))
            .await;
        let collected: Vec<String> = rows
            .expect("scan succeeds")
            .iter()
            .map(|r| r.get::<String, _>("storage_key"))
            .collect();
        fixture.teardown().await;

        for (source, key) in &expect_collected {
            assert!(
                collected.contains(key),
                "source='{source}' is written by the system and is a cache \
                 over other catalog state, so it must STAY reclaimable once \
                 its anchors are gone — sparing it leaks storage forever \
                 (#3431); collected: {collected:?}"
            );
        }
        for (source, key) in &expect_spared {
            assert!(
                !collected.contains(key),
                "source='{source}' is not one the system writes, so its row is \
                 a primary record nothing can re-derive and its object must NOT \
                 be collected; unknown sources are protected by DEFAULT because \
                 the arm is an allowlist (#3431); collected: {collected:?}"
            );
        }
    }

    /// The opt-in gate (#3431), mirroring `BLOB_GC_ENABLED`: with
    /// `MAVEN_FLAT_GC_ENABLED` unset the sweep still reports what it would
    /// reclaim but deletes nothing — neither the object nor its attribution
    /// row. Flipping the flag on the same fixture data reclaims it, which
    /// keeps the gate from passing by simply never finding candidates.
    ///
    /// This runs through `run_gc_for_repository`, the per-repository admin
    /// endpoint's entry point, which shares both the predicate constant and
    /// the gate with the scheduled pass.
    #[tokio::test]
    async fn test_run_gc_gated_flat_sweep_reports_but_deletes_nothing_3431() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(fixture) = tdh::Fixture::setup("local", "maven").await else {
            return;
        };
        let storage = fixture_storage(&fixture);
        let uid = Uuid::new_v4().simple().to_string();

        // Genuinely orphaned, system-written, past the age floor: the source
        // allowlist alone would reclaim this one.
        let key = format!("maven/gate3431/{uid}/lib/maven-metadata.xml");
        seed_objects(&storage, &[&key]).await;
        insert_flat_attribution_row(&fixture.pool, fixture.repo_id, &key, 2).await;

        // Default construction == MAVEN_FLAT_GC_ENABLED unset.
        let gated =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let gated_result = gated
            .run_gc_for_repository(fixture.repo_id, false)
            .await
            .expect("gated run_gc_for_repository succeeds");
        let survived = storage.exists(&key).await.expect("exists check");
        let rows_after_gated = count_rows(&fixture.pool, COUNT_ATTRIBUTION_SQL, &key).await;

        // Same data, same code path, flag on.
        let enabled =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone())
                .with_maven_flat_gc_enabled(true);
        let enabled_result = enabled
            .run_gc_for_repository(fixture.repo_id, false)
            .await
            .expect("enabled run_gc_for_repository succeeds");
        let left_after_enabled = storage.exists(&key).await.expect("exists check");
        let rows_after_enabled = count_rows(&fixture.pool, COUNT_ATTRIBUTION_SQL, &key).await;
        fixture.teardown().await;

        assert!(
            survived,
            "with MAVEN_FLAT_GC_ENABLED unset the flat-object sweep must \
             delete nothing (#3431)"
        );
        assert_eq!(
            rows_after_gated, 1,
            "the attribution row must survive the gated pass too"
        );
        assert_eq!(
            gated_result.maven_flat_objects_gated, 1,
            "the gated pass must still REPORT what it would reclaim, so an \
             operator can size the sweep before opting in (#3431)"
        );
        assert_eq!(
            gated_result.storage_keys_deleted, 0,
            "a gated pass must not count un-deleted objects as deleted"
        );

        assert!(
            !left_after_enabled,
            "positive control: with the flag on, the very same key IS \
             reclaimed — otherwise the gate test would pass on a sweep that \
             simply never finds candidates (#3431)"
        );
        assert_eq!(
            rows_after_enabled, 0,
            "the enabled pass drops the attribution row with the object"
        );
        assert_eq!(
            enabled_result.maven_flat_objects_gated, 0,
            "nothing is gated once the sweep is opted in"
        );
    }

    /// End-to-end variant of the manifest-survival test: run GC with
    /// `dry_run = false` so the entire delete path executes (storage delete
    /// + promotion_approvals + artifacts hard-delete) and assert the
    /// physical manifest file is still on disk afterward.
    ///
    /// The dry-run tests above prove the SQL filter is correct; this proves
    /// the filter is also honored by the code path that actually deletes
    /// files. Without this, a future refactor of the delete loop could
    /// regress the fix and the dry-run tests would still pass.
    #[tokio::test]
    async fn test_run_gc_live_keeps_oci_manifest_referenced_by_tag() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let digest = format!("sha256:{}", "c".repeat(64));
        let storage_key = format!("oci-manifests/{}", digest);
        let manifest_body = Bytes::from_static(
            b"{\"schemaVersion\":2,\"mediaType\":\
              \"application/vnd.oci.image.manifest.v1+json\",\"config\":{},\"layers\":[]}",
        );

        // Materialize the manifest in the filesystem backend so the GC
        // delete path has a real file to operate on.
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");
        storage
            .put(&storage_key, manifest_body.clone())
            .await
            .expect("write manifest to storage");
        assert!(
            storage.exists(&storage_key).await.expect("exists check"),
            "manifest must exist before GC runs"
        );

        insert_referenced_soft_deleted_artifact(
            &fixture.pool,
            fixture.repo_id,
            fixture.user_id,
            &digest,
            &storage_key,
            manifest_body.len() as i64,
            RefKind::Tag {
                image: "gc-image-live",
                tag: "latest",
            },
        )
        .await;

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let _ = service.run_gc(false).await.expect("live gc succeeds");

        let file_still_exists = storage.exists(&storage_key).await.expect("exists check");
        let row_still_exists = count_soft_deleted_with_key(&fixture.pool, &storage_key).await == 1;

        fixture.teardown().await;

        // Per-key assertions: concurrent integration tests share this DB,
        // so the global `storage_keys_deleted` counter is not isolation-safe
        // here. Verifying our specific row + file survived is.
        assert!(
            row_still_exists,
            "soft-deleted artifact row for {} must survive a live GC pass while oci_tags references it",
            storage_key
        );
        assert!(
            file_still_exists,
            "manifest file must remain on disk after a live GC pass when oci_tags references it"
        );
    }

    #[tokio::test]
    async fn test_run_gc_removes_abandoned_oci_upload_session_storage() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let (storage, upload_id, temp_key, part_key) =
            seed_abandoned_oci_upload_session(&fixture).await;

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let result = service.run_gc(false).await.expect("live gc succeeds");

        let temp_exists = storage.exists(&temp_key).await.expect("temp exists check");
        let part_exists = storage.exists(&part_key).await.expect("part exists check");
        let session_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM oci_upload_sessions WHERE id = $1")
                .bind(upload_id)
                .fetch_one(&fixture.pool)
                .await
                .expect("count upload sessions");
        let part_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_upload_parts WHERE upload_session_id = $1",
        )
        .bind(upload_id)
        .fetch_one(&fixture.pool)
        .await
        .expect("count upload parts");
        let key_errors = result
            .errors
            .iter()
            .filter(|err| err.contains(&temp_key) || err.contains(&part_key))
            .cloned()
            .collect::<Vec<_>>();

        fixture.teardown().await;

        assert!(
            key_errors.is_empty(),
            "GC produced errors for abandoned upload keys: {:?}",
            key_errors
        );
        assert!(!temp_exists, "GC must delete stale upload temp objects");
        assert!(!part_exists, "GC must delete stale upload part objects");
        assert_eq!(session_count, 0, "GC must remove the stale upload session");
        assert_eq!(part_count, 0, "GC must cascade stale upload parts");
        assert!(
            result.storage_keys_deleted >= 2,
            "GC result should include the upload temp and part keys"
        );
    }

    #[tokio::test]
    async fn test_run_gc_dry_run_reports_abandoned_oci_upload_session_storage() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let (storage, upload_id, temp_key, part_key) =
            seed_abandoned_oci_upload_session(&fixture).await;

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let result = service.run_gc(true).await.expect("dry-run gc succeeds");

        let temp_exists = storage.exists(&temp_key).await.expect("temp exists check");
        let part_exists = storage.exists(&part_key).await.expect("part exists check");
        let session_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM oci_upload_sessions WHERE id = $1")
                .bind(upload_id)
                .fetch_one(&fixture.pool)
                .await
                .expect("count upload sessions");
        let part_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_upload_parts WHERE upload_session_id = $1",
        )
        .bind(upload_id)
        .fetch_one(&fixture.pool)
        .await
        .expect("count upload parts");
        let key_errors = result
            .errors
            .iter()
            .filter(|err| err.contains(&temp_key) || err.contains(&part_key))
            .cloned()
            .collect::<Vec<_>>();

        fixture.teardown().await;

        assert!(
            key_errors.is_empty(),
            "dry-run GC produced errors for abandoned upload keys: {:?}",
            key_errors
        );
        assert!(temp_exists, "dry-run must not delete upload temp objects");
        assert!(part_exists, "dry-run must not delete upload part objects");
        assert_eq!(session_count, 1, "dry-run must keep the upload session");
        assert_eq!(part_count, 1, "dry-run must keep upload parts");
        assert!(
            result.storage_keys_deleted >= 2,
            "dry-run result should count the upload temp and part keys"
        );
        assert!(
            result.bytes_freed >= 8,
            "dry-run result should count abandoned upload bytes"
        );
    }

    #[tokio::test]
    async fn test_run_gc_removes_unreferenced_oci_upload_cleanup_key_storage() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let storage_key = format!(
            "oci-uploads/{}.part.00000000.{}",
            Uuid::new_v4(),
            Uuid::new_v4()
        );
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");
        storage
            .put(&storage_key, Bytes::from_static(b"unreferenced"))
            .await
            .expect("write unreferenced cleanup key");

        sqlx::query(
            r#"
            INSERT INTO oci_upload_cleanup_keys (
                repository_id, storage_key, created_at, storage_write_completed_at
            )
            VALUES ($1, $2, NOW() - INTERVAL '25 hours', NOW() - INTERVAL '25 hours')
            "#,
        )
        .bind(fixture.repo_id)
        .bind(&storage_key)
        .execute(&fixture.pool)
        .await
        .expect("insert cleanup key row");

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let result = service.run_gc(false).await.expect("live gc succeeds");

        let key_exists = storage.exists(&storage_key).await.expect("exists check");
        let cleanup_key_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_upload_cleanup_keys WHERE storage_key = $1",
        )
        .bind(&storage_key)
        .fetch_one(&fixture.pool)
        .await
        .expect("count cleanup key rows");
        let key_errors = result
            .errors
            .iter()
            .filter(|err| err.contains(&storage_key))
            .cloned()
            .collect::<Vec<_>>();

        fixture.teardown().await;

        assert!(
            key_errors.is_empty(),
            "GC produced errors for cleanup key: {:?}",
            key_errors
        );
        assert!(
            !key_exists,
            "GC must delete unreferenced cleanup-key storage"
        );
        assert_eq!(cleanup_key_count, 0, "GC must delete cleanup-key row");
        assert!(
            result.storage_keys_deleted >= 1,
            "GC result should include the cleanup-key storage object"
        );
    }

    /// Regression for #1527: a blob key (`oci-blobs/<digest>`) journaled around
    /// the blob copy/commit must NEVER be reclaimed once an `oci_blobs` row
    /// references it, even for an aged committed cleanup row. A concurrent push
    /// of the same digest can commit the row after a different writer's commit
    /// failed; reaping then would destroy a live blob's bytes (data loss).
    #[tokio::test]
    async fn test_run_gc_keeps_cleanup_key_referenced_by_committed_oci_blob() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let digest = format!("sha256:{}", "a".repeat(64));
        let blob_key = format!("oci-blobs/{}", digest);
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");
        storage
            .put(&blob_key, Bytes::from_static(b"live blob bytes"))
            .await
            .expect("write live blob object");

        // A live `oci_blobs` row references the key (concurrent committed push).
        sqlx::query(
            "INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key) VALUES ($1, $2, $3, $4)",
        )
        .bind(fixture.repo_id)
        .bind(&digest)
        .bind(15_i64)
        .bind(&blob_key)
        .execute(&fixture.pool)
        .await
        .expect("insert referencing oci_blobs row");

        // An aged, committed cleanup-journal entry for the same key (left behind
        // when the success-path clear was lost, e.g. a transient DB blip).
        sqlx::query(
            r#"
            INSERT INTO oci_upload_cleanup_keys (
                repository_id, storage_key, created_at, storage_write_completed_at
            )
            VALUES ($1, $2, NOW() - INTERVAL '25 hours', NOW() - INTERVAL '25 hours')
            "#,
        )
        .bind(fixture.repo_id)
        .bind(&blob_key)
        .execute(&fixture.pool)
        .await
        .expect("insert committed cleanup key row");

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let result = service.run_gc(false).await.expect("live gc succeeds");

        let key_exists = storage.exists(&blob_key).await.expect("exists check");
        let cleanup_key_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_upload_cleanup_keys WHERE storage_key = $1",
        )
        .bind(&blob_key)
        .fetch_one(&fixture.pool)
        .await
        .expect("count cleanup key rows");
        let key_errors = result
            .errors
            .iter()
            .filter(|err| err.contains(&blob_key))
            .cloned()
            .collect::<Vec<_>>();

        fixture.teardown().await;

        assert!(
            key_errors.is_empty(),
            "GC produced errors for referenced blob key: {:?}",
            key_errors
        );
        assert!(
            key_exists,
            "GC must NEVER delete a blob object referenced by a live oci_blobs row"
        );
        assert_eq!(
            cleanup_key_count, 1,
            "GC must keep the cleanup row while an oci_blobs row references the key"
        );
    }

    /// Regression for #1527: when an `oci_blobs` commit fails after the blob
    /// object was copied, the orphaned `oci-blobs/<digest>` object is left
    /// journaled but NULL-marked (write never confirmed). With no referencing
    /// `oci_blobs` row, the pending reaper must reclaim it once aged.
    #[tokio::test]
    async fn test_run_gc_reaps_pending_orphaned_blob_key_without_oci_blob_row() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let digest = format!("sha256:{}", "b".repeat(64));
        let blob_key = format!("oci-blobs/{}", digest);
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");
        storage
            .put(&blob_key, Bytes::from_static(b"orphaned blob bytes"))
            .await
            .expect("write orphaned blob object");

        // NULL-marked (storage_write_completed_at IS NULL) aged journal entry,
        // no referencing oci_blobs row: the orphan left by a failed commit.
        sqlx::query(
            r#"
            INSERT INTO oci_upload_cleanup_keys (
                repository_id, storage_key, created_at
            )
            VALUES ($1, $2, NOW() - INTERVAL '25 hours')
            "#,
        )
        .bind(fixture.repo_id)
        .bind(&blob_key)
        .execute(&fixture.pool)
        .await
        .expect("insert pending cleanup key row");

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let result = service.run_gc(false).await.expect("live gc succeeds");

        let key_exists = storage.exists(&blob_key).await.expect("exists check");
        let cleanup_key_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_upload_cleanup_keys WHERE storage_key = $1",
        )
        .bind(&blob_key)
        .fetch_one(&fixture.pool)
        .await
        .expect("count cleanup key rows");
        let key_errors = result
            .errors
            .iter()
            .filter(|err| err.contains(&blob_key))
            .cloned()
            .collect::<Vec<_>>();

        fixture.teardown().await;

        assert!(
            key_errors.is_empty(),
            "GC produced errors reaping orphaned blob key: {:?}",
            key_errors
        );
        assert!(
            !key_exists,
            "GC must reclaim the orphaned blob object (no oci_blobs row references it)"
        );
        assert_eq!(
            cleanup_key_count, 0,
            "GC must delete the cleanup row for the reclaimed orphan"
        );
    }

    #[tokio::test]
    async fn test_run_gc_keeps_cleanup_key_referenced_by_active_upload_part() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let upload_id = Uuid::new_v4();
        let temp_key = format!("oci-uploads/{}", upload_id);
        let part_key = format!("{}.part.00000000.{}", temp_key, Uuid::new_v4());
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");
        storage
            .put(&part_key, Bytes::from_static(b"active"))
            .await
            .expect("write active part");

        sqlx::query(
            r#"
            INSERT INTO oci_upload_sessions (
                id, repository_id, user_id, bytes_received, storage_temp_key, updated_at
            )
            VALUES ($1, $2, $3, 6, $4, NOW())
            "#,
        )
        .bind(upload_id)
        .bind(fixture.repo_id)
        .bind(fixture.user_id)
        .bind(&temp_key)
        .execute(&fixture.pool)
        .await
        .expect("insert active upload session");
        sqlx::query(
            r#"
            INSERT INTO oci_upload_parts (
                upload_session_id, part_index, storage_key, size_bytes, digest_sha256
            )
            VALUES ($1, 0, $2, 6, 'unused-test-digest')
            "#,
        )
        .bind(upload_id)
        .bind(&part_key)
        .execute(&fixture.pool)
        .await
        .expect("insert active upload part");
        sqlx::query(
            r#"
            INSERT INTO oci_upload_cleanup_keys (
                repository_id, upload_session_id, storage_key, created_at,
                storage_write_completed_at
            )
            VALUES ($1, $2, $3, NOW() - INTERVAL '25 hours', NOW() - INTERVAL '25 hours')
            "#,
        )
        .bind(fixture.repo_id)
        .bind(upload_id)
        .bind(&part_key)
        .execute(&fixture.pool)
        .await
        .expect("insert cleanup key row");

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let result = service.run_gc(false).await.expect("live gc succeeds");

        let key_exists = storage.exists(&part_key).await.expect("exists check");
        let cleanup_key_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_upload_cleanup_keys WHERE storage_key = $1",
        )
        .bind(&part_key)
        .fetch_one(&fixture.pool)
        .await
        .expect("count cleanup key rows");
        let key_errors = result
            .errors
            .iter()
            .filter(|err| err.contains(&part_key))
            .cloned()
            .collect::<Vec<_>>();

        fixture.teardown().await;

        assert!(
            key_errors.is_empty(),
            "GC produced errors for active cleanup key: {:?}",
            key_errors
        );
        assert!(key_exists, "GC must not delete active upload part storage");
        assert_eq!(
            cleanup_key_count, 1,
            "GC must keep cleanup row while a live part references it"
        );
    }

    #[tokio::test]
    async fn test_run_gc_keeps_cleanup_key_referenced_by_active_upload_session() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let upload_id = Uuid::new_v4();
        let temp_key = format!("oci-uploads/{}", upload_id);
        let pending_part_key = format!("{}.part.00000001.{}", temp_key, Uuid::new_v4());
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");
        storage
            .put(&pending_part_key, Bytes::from_static(b"pending"))
            .await
            .expect("write pending part");

        sqlx::query(
            r#"
            INSERT INTO oci_upload_sessions (
                id, repository_id, user_id, bytes_received, storage_temp_key, updated_at
            )
            VALUES ($1, $2, $3, 7, $4, NOW())
            "#,
        )
        .bind(upload_id)
        .bind(fixture.repo_id)
        .bind(fixture.user_id)
        .bind(&temp_key)
        .execute(&fixture.pool)
        .await
        .expect("insert active upload session");
        sqlx::query(
            r#"
            INSERT INTO oci_upload_cleanup_keys (
                repository_id, upload_session_id, storage_key, created_at
            )
            VALUES ($1, $2, $3, NOW() - INTERVAL '8 days')
            "#,
        )
        .bind(fixture.repo_id)
        .bind(upload_id)
        .bind(&pending_part_key)
        .execute(&fixture.pool)
        .await
        .expect("insert cleanup key row");

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let result = service.run_gc(false).await.expect("live gc succeeds");

        let key_exists = storage
            .exists(&pending_part_key)
            .await
            .expect("exists check");
        let cleanup_key_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_upload_cleanup_keys WHERE storage_key = $1",
        )
        .bind(&pending_part_key)
        .fetch_one(&fixture.pool)
        .await
        .expect("count cleanup key rows");
        let key_errors = result
            .errors
            .iter()
            .filter(|err| err.contains(&pending_part_key))
            .cloned()
            .collect::<Vec<_>>();

        fixture.teardown().await;

        assert!(
            key_errors.is_empty(),
            "GC produced errors for active-session cleanup key: {:?}",
            key_errors
        );
        assert!(
            key_exists,
            "GC must not delete pending upload storage while its session is live"
        );
        assert_eq!(
            cleanup_key_count, 1,
            "GC must keep cleanup row while a live upload session references it"
        );
    }

    #[tokio::test]
    async fn test_run_gc_keeps_pending_cleanup_key_until_storage_write_is_marked() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let storage_key = format!(
            "oci-uploads/{}.part.00000000.{}",
            Uuid::new_v4(),
            Uuid::new_v4()
        );
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");

        // A recent (within-TTL) pending row: the writer may still be racing
        // to create the object and mark the write complete, so GC must leave
        // it alone. Only once the row ages past the TTL without being marked
        // does the pending reaper treat it as a crashed-writer leak
        // (covered by test_run_gc_reaps_aged_pending_oci_upload_cleanup_key).
        sqlx::query(
            r#"
            INSERT INTO oci_upload_cleanup_keys (repository_id, storage_key, created_at)
            VALUES ($1, $2, NOW())
            "#,
        )
        .bind(fixture.repo_id)
        .bind(&storage_key)
        .execute(&fixture.pool)
        .await
        .expect("insert pending cleanup key row");

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let result = service.run_gc(false).await.expect("live gc succeeds");

        let key_exists = storage.exists(&storage_key).await.expect("exists check");
        let cleanup_key_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_upload_cleanup_keys WHERE storage_key = $1",
        )
        .bind(&storage_key)
        .fetch_one(&fixture.pool)
        .await
        .expect("count cleanup key rows");
        let key_errors = result
            .errors
            .iter()
            .filter(|err| err.contains(&storage_key))
            .cloned()
            .collect::<Vec<_>>();

        fixture.teardown().await;

        assert!(
            key_errors.is_empty(),
            "GC produced errors for missing pending cleanup key: {:?}",
            key_errors
        );
        assert!(
            !key_exists,
            "test fixture should not create the pending key"
        );
        assert_eq!(
            cleanup_key_count, 1,
            "GC must keep a within-TTL pending cleanup row until the writer marks the storage write complete"
        );
    }

    /// An AGED, unreferenced NULL row (the writer crashed between the
    /// register INSERT and the storage-write-completed mark) must be
    /// reaped: the storage object is best-effort deleted and the row is
    /// removed. Without the reaper this row would leak forever because
    /// the committed-row sweep requires `storage_write_completed_at IS NOT
    /// NULL`.
    #[tokio::test]
    async fn test_run_gc_reaps_aged_pending_oci_upload_cleanup_key() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let storage_key = format!(
            "oci-uploads/{}.part.00000000.{}",
            Uuid::new_v4(),
            Uuid::new_v4()
        );
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");
        // The crashed write may or may not have materialized the object;
        // here we materialize it to assert the reaper deletes it.
        storage
            .put(&storage_key, Bytes::from_static(b"orphaned-pending"))
            .await
            .expect("write aged pending cleanup key");

        sqlx::query(
            r#"
            INSERT INTO oci_upload_cleanup_keys (repository_id, storage_key, created_at)
            VALUES ($1, $2, NOW() - INTERVAL '25 hours')
            "#,
        )
        .bind(fixture.repo_id)
        .bind(&storage_key)
        .execute(&fixture.pool)
        .await
        .expect("insert aged pending cleanup key row");

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let result = service.run_gc(false).await.expect("live gc succeeds");

        let key_exists = storage.exists(&storage_key).await.expect("exists check");
        let cleanup_key_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_upload_cleanup_keys WHERE storage_key = $1",
        )
        .bind(&storage_key)
        .fetch_one(&fixture.pool)
        .await
        .expect("count cleanup key rows");
        let key_errors = result
            .errors
            .iter()
            .filter(|err| err.contains(&storage_key))
            .cloned()
            .collect::<Vec<_>>();

        fixture.teardown().await;

        assert!(
            key_errors.is_empty(),
            "GC produced errors for aged pending cleanup key: {:?}",
            key_errors
        );
        assert!(
            !key_exists,
            "reaper must delete the storage object for an aged pending cleanup key"
        );
        assert_eq!(
            cleanup_key_count, 0,
            "reaper must delete the aged pending cleanup-key row"
        );
    }

    /// A RECENT NULL row (created within the TTL) must NOT be reaped: a
    /// write may still be in flight and racing to create the object, so
    /// reaping now could delete an object the writer is about to record.
    #[tokio::test]
    async fn test_run_gc_keeps_recent_pending_oci_upload_cleanup_key() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let storage_key = format!(
            "oci-uploads/{}.part.00000000.{}",
            Uuid::new_v4(),
            Uuid::new_v4()
        );
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");
        storage
            .put(&storage_key, Bytes::from_static(b"recent-pending"))
            .await
            .expect("write recent pending cleanup key");

        sqlx::query(
            r#"
            INSERT INTO oci_upload_cleanup_keys (repository_id, storage_key, created_at)
            VALUES ($1, $2, NOW())
            "#,
        )
        .bind(fixture.repo_id)
        .bind(&storage_key)
        .execute(&fixture.pool)
        .await
        .expect("insert recent pending cleanup key row");

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let result = service.run_gc(false).await.expect("live gc succeeds");

        let key_exists = storage.exists(&storage_key).await.expect("exists check");
        let cleanup_key_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_upload_cleanup_keys WHERE storage_key = $1",
        )
        .bind(&storage_key)
        .fetch_one(&fixture.pool)
        .await
        .expect("count cleanup key rows");
        let key_errors = result
            .errors
            .iter()
            .filter(|err| err.contains(&storage_key))
            .cloned()
            .collect::<Vec<_>>();

        fixture.teardown().await;

        assert!(
            key_errors.is_empty(),
            "GC produced errors for recent pending cleanup key: {:?}",
            key_errors
        );
        assert!(
            key_exists,
            "reaper must not delete the storage object for a recent pending cleanup key"
        );
        assert_eq!(
            cleanup_key_count, 1,
            "reaper must keep a recent pending cleanup-key row inside the TTL"
        );
    }

    /// An aged NULL row that is still referenced by a live upload session
    /// must NOT be reaped: the session still owns the storage object and
    /// will eventually finalize or be swept by the abandoned-session path.
    #[tokio::test]
    async fn test_run_gc_keeps_aged_pending_cleanup_key_referenced_by_live_session() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let upload_id = Uuid::new_v4();
        let temp_key = format!("oci-uploads/{}", upload_id);
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");
        storage
            .put(&temp_key, Bytes::from_static(b"live-session-temp"))
            .await
            .expect("write live session temp object");

        // A live (recently updated) session whose storage_temp_key matches
        // the cleanup row's storage_key, so the reaper's NOT EXISTS guard
        // must protect it despite the cleanup row being aged + NULL.
        sqlx::query(
            r#"
            INSERT INTO oci_upload_sessions (
                id, repository_id, user_id, bytes_received, storage_temp_key, updated_at
            )
            VALUES ($1, $2, $3, 0, $4, NOW())
            "#,
        )
        .bind(upload_id)
        .bind(fixture.repo_id)
        .bind(fixture.user_id)
        .bind(&temp_key)
        .execute(&fixture.pool)
        .await
        .expect("insert live upload session");
        sqlx::query(
            r#"
            INSERT INTO oci_upload_cleanup_keys (
                repository_id, upload_session_id, storage_key, created_at
            )
            VALUES ($1, $2, $3, NOW() - INTERVAL '25 hours')
            "#,
        )
        .bind(fixture.repo_id)
        .bind(upload_id)
        .bind(&temp_key)
        .execute(&fixture.pool)
        .await
        .expect("insert aged pending cleanup key row");

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let result = service.run_gc(false).await.expect("live gc succeeds");

        let key_exists = storage.exists(&temp_key).await.expect("exists check");
        let cleanup_key_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_upload_cleanup_keys WHERE storage_key = $1",
        )
        .bind(&temp_key)
        .fetch_one(&fixture.pool)
        .await
        .expect("count cleanup key rows");
        let key_errors = result
            .errors
            .iter()
            .filter(|err| err.contains(&temp_key))
            .cloned()
            .collect::<Vec<_>>();

        fixture.teardown().await;

        assert!(
            key_errors.is_empty(),
            "GC produced errors for referenced aged pending cleanup key: {:?}",
            key_errors
        );
        assert!(
            key_exists,
            "reaper must not delete storage referenced by a live upload session"
        );
        assert_eq!(
            cleanup_key_count, 1,
            "reaper must keep an aged pending cleanup row while a live session references it"
        );
    }

    // -----------------------------------------------------------------------
    // Regression for #1179: multi-arch index child-manifest protection
    // -----------------------------------------------------------------------

    /// Helper: count how many soft-deleted `artifacts` rows still exist
    /// for a given storage_key. Used by the #1179 / #1180 tests below to
    /// assert "the GC did/did not collect MY rows" rather than asserting
    /// global GC counts. Tests share the database with other concurrent
    /// integration tests, so global counts are unreliable for narrow
    /// regression assertions; per-key checks are not.
    async fn count_soft_deleted_with_key(pool: &PgPool, storage_key: &str) -> i64 {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM artifacts WHERE storage_key = $1 AND is_deleted = true",
        )
        .bind(storage_key)
        .fetch_one(pool)
        .await
        .expect("count soft-deleted artifacts")
    }

    async fn seed_abandoned_oci_upload_session(
        fixture: &crate::api::handlers::test_db_helpers::Fixture,
    ) -> (Arc<dyn StorageBackend>, Uuid, String, String) {
        let upload_id = Uuid::new_v4();
        let temp_key = format!("oci-uploads/{}", upload_id);
        let part_key = format!("{}.part.00000000.{}", temp_key, Uuid::new_v4());
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");

        storage
            .put(&temp_key, Bytes::new())
            .await
            .expect("write upload temp object");
        storage
            .put(&part_key, Bytes::from_static(b"orphaned"))
            .await
            .expect("write upload part object");

        sqlx::query(
            r#"
            INSERT INTO oci_upload_sessions (
                id, repository_id, user_id, bytes_received, storage_temp_key, updated_at
            )
            VALUES ($1, $2, $3, 8, $4, NOW() - INTERVAL '25 hours')
            "#,
        )
        .bind(upload_id)
        .bind(fixture.repo_id)
        .bind(fixture.user_id)
        .bind(&temp_key)
        .execute(&fixture.pool)
        .await
        .expect("insert abandoned upload session");
        sqlx::query(
            r#"
            INSERT INTO oci_upload_parts (
                upload_session_id, part_index, storage_key, size_bytes, digest_sha256
            )
            VALUES ($1, 0, $2, 8, $3)
            "#,
        )
        .bind(upload_id)
        .bind(&part_key)
        .bind("unused-test-digest")
        .execute(&fixture.pool)
        .await
        .expect("insert abandoned upload part");

        (storage, upload_id, temp_key, part_key)
    }

    /// Push a multi-arch image scenario: the index manifest is tagged
    /// (recorded in `oci_tags`) and its per-architecture child manifests
    /// are recorded in `oci_manifest_refs`. Each child manifest also has
    /// a soft-deleted `artifacts` row (a typical sequence: the index
    /// was tagged once with one child, then re-tagged with a new child,
    /// which soft-deleted the old child's `artifacts` row). Storage GC
    /// must not collect either the index or the children while the
    /// index remains tagged.
    ///
    /// Without the #1179 fix, the index itself is protected by
    /// `oci_tags` but the children are unprotected and a multi-arch
    /// `pull <repo>@<index-digest>` after GC would return
    /// MANIFEST_UNKNOWN for the platform-specific layers.
    ///
    /// Runs a live (non-dry-run) GC and asserts per-storage-key that
    /// the specific child rows survived, so concurrent integration
    /// tests against the same database cannot interfere.
    #[tokio::test]
    async fn test_run_gc_keeps_oci_index_child_manifests() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let image = "gc-multi-arch";
        let tag = "v1";
        let index_digest = format!("sha256:{}", "1".repeat(64));
        let child_amd64_digest = format!("sha256:{}", "2".repeat(64));
        let child_arm64_digest = format!("sha256:{}", "3".repeat(64));
        let child_keys = [
            format!("oci-manifests/{}", child_amd64_digest),
            format!("oci-manifests/{}", child_arm64_digest),
        ];

        // Materialize the index manifest body in storage so the live
        // GC delete path resolves real files. (The children themselves
        // do not need bodies; the GC's protection runs against the DB
        // predicates, not the filesystem.)
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");
        for child_key in &child_keys {
            storage
                .put(child_key, Bytes::from_static(b"{}"))
                .await
                .expect("write child manifest stub");
        }

        sqlx::query(
            r#"
            INSERT INTO oci_tags (
                repository_id, name, tag, manifest_digest, manifest_content_type
            )
            VALUES ($1, $2, $3, $4, 'application/vnd.oci.image.index.v1+json')
            "#,
        )
        .bind(fixture.repo_id)
        .bind(image)
        .bind(tag)
        .bind(&index_digest)
        .execute(&fixture.pool)
        .await
        .expect("insert oci tag for index");

        for child in [&child_amd64_digest, &child_arm64_digest] {
            sqlx::query(
                r#"
                INSERT INTO oci_manifest_refs (parent_digest, child_digest, repository_id)
                VALUES ($1, $2, $3)
                "#,
            )
            .bind(&index_digest)
            .bind(child)
            .bind(fixture.repo_id)
            .execute(&fixture.pool)
            .await
            .expect("insert oci_manifest_refs row");

            // A soft-deleted artifacts row makes the child a GC candidate
            // unless something else protects it. The new oci_manifest_refs
            // NOT EXISTS clause is the only thing that should protect it
            // here: the child digest is not in oci_tags or oci_blobs.
            sqlx::query(
                r#"
                INSERT INTO artifacts (
                    id, repository_id, path, name, version, size_bytes,
                    checksum_sha256, content_type, storage_key, uploaded_by, is_deleted
                )
                VALUES (
                    $1, $2, $3, $4, $5, 1024,
                    $6, 'application/vnd.oci.image.manifest.v1+json', $7, $8, true
                )
                "#,
            )
            .bind(Uuid::new_v4())
            .bind(fixture.repo_id)
            .bind(format!("v2/{}/manifests/{}", image, child))
            .bind(format!("{}:{}", image, child))
            .bind(child)
            .bind(child.trim_start_matches("sha256:"))
            .bind(format!("oci-manifests/{}", child))
            .bind(fixture.user_id)
            .execute(&fixture.pool)
            .await
            .expect("insert soft-deleted child artifact");
        }

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let _ = service.run_gc(false).await.expect("live gc succeeds");

        let mut surviving = Vec::new();
        for child_key in &child_keys {
            surviving.push((
                child_key.clone(),
                count_soft_deleted_with_key(&fixture.pool, child_key).await,
                storage.exists(child_key).await.expect("exists check"),
            ));
        }

        fixture.teardown().await;

        for (key, db_count, on_disk) in surviving {
            assert_eq!(
                db_count, 1,
                "child manifest row {} must survive GC while the parent index is tagged",
                key
            );
            assert!(
                on_disk,
                "child manifest file {} must remain on disk after GC",
                key
            );
        }
    }

    /// Counterpart: once the parent index tag is gone, the children
    /// become eligible for collection. Verifies the predicate is keyed
    /// on the parent being live in `oci_tags`, not just on the presence
    /// of any `oci_manifest_refs` row.
    ///
    /// Asserts per-storage-key (live GC) so the test does not collide
    /// with other DB-using tests running in parallel against a shared
    /// Postgres instance.
    #[tokio::test]
    async fn test_run_gc_collects_orphaned_index_children() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let image = "gc-multi-arch-orphan";
        let index_digest = format!("sha256:{}", "4".repeat(64));
        let child_digest = format!("sha256:{}", "5".repeat(64));
        let child_key = format!("oci-manifests/{}", child_digest);

        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");
        storage
            .put(&child_key, Bytes::from_static(b"{}"))
            .await
            .expect("write child manifest stub");

        // oci_manifest_refs row exists, but oci_tags does NOT point at
        // the index (e.g. the tag was overwritten or deleted).
        sqlx::query(
            r#"
            INSERT INTO oci_manifest_refs (parent_digest, child_digest, repository_id)
            VALUES ($1, $2, $3)
            "#,
        )
        .bind(&index_digest)
        .bind(&child_digest)
        .bind(fixture.repo_id)
        .execute(&fixture.pool)
        .await
        .expect("insert orphaned ref row");

        sqlx::query(
            r#"
            INSERT INTO artifacts (
                id, repository_id, path, name, version, size_bytes,
                checksum_sha256, content_type, storage_key, uploaded_by, is_deleted
            )
            VALUES (
                $1, $2, $3, $4, $5, 1024,
                $6, 'application/vnd.oci.image.manifest.v1+json', $7, $8, true
            )
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(fixture.repo_id)
        .bind(format!("v2/{}/manifests/{}", image, child_digest))
        .bind(format!("{}:{}", image, child_digest))
        .bind(&child_digest)
        .bind(child_digest.trim_start_matches("sha256:"))
        .bind(&child_key)
        .bind(fixture.user_id)
        .execute(&fixture.pool)
        .await
        .expect("insert soft-deleted child artifact");

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let _ = service.run_gc(false).await.expect("live gc succeeds");

        let remaining_rows = count_soft_deleted_with_key(&fixture.pool, &child_key).await;
        let file_still_exists = storage.exists(&child_key).await.expect("exists check");

        fixture.teardown().await;

        assert_eq!(
            remaining_rows, 0,
            "child manifest of an untagged index should be hard-deleted by GC"
        );
        assert!(
            !file_still_exists,
            "child manifest file must be removed from storage when no parent tag protects it"
        );
    }

    // -----------------------------------------------------------------------
    // Regression for #1180: TOCTOU race between SELECT and per-key delete
    // -----------------------------------------------------------------------

    /// Race a tag-insert against the per-key re-verification window.
    ///
    /// The simulation: pre-stage a soft-deleted artifact that would
    /// normally be collected, run GC, but BEFORE the re-check runs (or
    /// while it runs against an empty `oci_tags`), race in an
    /// `oci_tags` row pointing at the same manifest digest. The new
    /// FOR UPDATE re-check must observe the inserted row and skip the
    /// delete; the storage file must survive.
    ///
    /// Synchronization approach: we run GC inside one task and the
    /// racing tag-insert inside another, joined via `tokio::join!`. To
    /// make the race deterministic we drive it inside a transaction
    /// the test controls: the tag-insert task starts its tx, inserts
    /// the protecting row, sleeps briefly to let GC's outer SELECT run
    /// (which uses its own connection and will observe the empty
    /// `oci_tags` since the insert is uncommitted), then commits. The
    /// GC's per-key re-check runs after, sees the committed row, and
    /// skips the delete.
    ///
    /// On a system without the FOR UPDATE re-check (the pre-#1180
    /// code), the racing tag-insert would be observed by neither the
    /// outer SELECT nor the per-key delete, and GC would proceed to
    /// remove the storage file even though it is now referenced.
    #[tokio::test]
    async fn test_run_gc_toctou_skips_key_when_tag_inserted_during_pass() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = storage_gc_test_guard().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let image = "gc-race";
        let tag = "racy";
        let digest = format!("sha256:{}", "9".repeat(64));
        let storage_key = format!("oci-manifests/{}", digest);
        let manifest_body = Bytes::from_static(
            b"{\"schemaVersion\":2,\"mediaType\":\
              \"application/vnd.oci.image.manifest.v1+json\",\"config\":{},\"layers\":[]}",
        );

        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");
        storage
            .put(&storage_key, manifest_body.clone())
            .await
            .expect("write manifest to storage");

        sqlx::query(
            r#"
            INSERT INTO artifacts (
                id, repository_id, path, name, version, size_bytes,
                checksum_sha256, content_type, storage_key, uploaded_by, is_deleted
            )
            VALUES (
                $1, $2, $3, $4, $5, $9,
                $6, 'application/vnd.oci.image.manifest.v1+json', $7, $8, true
            )
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(fixture.repo_id)
        .bind(format!("v2/{}/manifests/{}", image, tag))
        .bind(format!("{}:{}", image, tag))
        .bind(tag)
        .bind("9".repeat(64))
        .bind(&storage_key)
        .bind(fixture.user_id)
        .bind(manifest_body.len() as i64)
        .execute(&fixture.pool)
        .await
        .expect("insert soft-deleted artifact");

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());

        // Channel to let the racer signal "I have started my tx and
        // inserted the protecting row" so we can deterministically
        // order: outer SELECT runs first (no protecting row visible),
        // then the racer commits before the per-key re-check runs.
        let (insert_started_tx, insert_started_rx) = tokio::sync::oneshot::channel::<()>();
        let (gc_outer_select_done_tx, gc_outer_select_done_rx) =
            tokio::sync::oneshot::channel::<()>();

        let pool_for_racer = fixture.pool.clone();
        let repo_id = fixture.repo_id;
        let digest_for_racer = digest.clone();
        let image_for_racer = image.to_string();
        let tag_for_racer = tag.to_string();

        let racer = tokio::spawn(async move {
            // Wait until GC has run its outer SELECT so we are racing
            // with the per-key delete window, not the initial scan.
            gc_outer_select_done_rx
                .await
                .expect("gc signals after outer select");
            // The protecting tag-insert. The pre-#1180 code path would
            // happily delete the storage file because its per-key
            // delete did not re-check, so the new live row would point
            // at a dangling key.
            sqlx::query(
                r#"
                INSERT INTO oci_tags (
                    repository_id, name, tag, manifest_digest, manifest_content_type
                )
                VALUES ($1, $2, $3, $4, 'application/vnd.oci.image.manifest.v1+json')
                "#,
            )
            .bind(repo_id)
            .bind(image_for_racer)
            .bind(tag_for_racer)
            .bind(digest_for_racer)
            .execute(&pool_for_racer)
            .await
            .expect("racing tag insert");

            // Signal the GC task to proceed into its per-key delete now
            // that the protecting row is committed.
            insert_started_tx
                .send(())
                .expect("signal gc to continue after insert");
        });

        let gc_task = async {
            // Manually replicate run_gc but expose the SELECT-vs-recheck
            // boundary so the racer can land its insert at the right
            // moment. We can't insert this hook into the production
            // run_gc method without polluting its signature, so instead
            // we drive the service through its public API and rely on
            // synchronization via two oneshot channels.

            // Step 1: call the outer SELECT directly through the same
            // service instance so we can signal afterwards.
            let orphans = service.select_orphans(None).await.expect("select orphans");
            assert!(
                orphans.iter().any(|r| {
                    let key: String = r.try_get("storage_key").unwrap_or_default();
                    key == storage_key
                }),
                "outer SELECT should still see the candidate before the racer commits"
            );

            // Signal the racer that the outer SELECT has run, then
            // wait for the racer's INSERT to commit.
            gc_outer_select_done_tx
                .send(())
                .expect("signal racer after outer select");
            insert_started_rx.await.expect("racer signals after insert");

            // Step 2: run the full GC pass. Internally this re-issues
            // the outer SELECT and then the per-key transactional
            // re-check, which is now expected to find the protecting
            // oci_tags row and skip the delete.
            service.run_gc(false).await.expect("gc run")
        };

        let (gc_result, _) = tokio::join!(gc_task, racer);

        let file_still_exists = storage.exists(&storage_key).await.expect("exists check");
        let row_still_exists = count_soft_deleted_with_key(&fixture.pool, &storage_key).await == 1;
        let any_error_for_our_key = gc_result
            .errors
            .iter()
            .any(|e| e.contains(storage_key.as_str()));

        fixture.teardown().await;

        assert!(
            !any_error_for_our_key,
            "GC produced an error for our specific key (other-test errors ignored): \
             our key {}, all errors {:?}",
            storage_key, gc_result.errors
        );
        assert!(
            file_still_exists,
            "manifest file must survive the racing tag insert"
        );
        assert!(
            row_still_exists,
            "the soft-deleted artifact row must still exist (not hard-deleted) after the racing \
             tag insert"
        );
    }

    // -----------------------------------------------------------------------
    // clamp_grace_hours (issue #1408 blob footprint report)
    // -----------------------------------------------------------------------

    #[test]
    fn test_clamp_grace_hours_zero_falls_back_to_default() {
        assert_eq!(clamp_grace_hours(0), BLOB_REPORT_GRACE_HOURS_DEFAULT);
    }

    #[test]
    fn test_clamp_grace_hours_negative_falls_back_to_default() {
        assert_eq!(clamp_grace_hours(-5), BLOB_REPORT_GRACE_HOURS_DEFAULT);
        assert_eq!(clamp_grace_hours(i64::MIN), BLOB_REPORT_GRACE_HOURS_DEFAULT);
    }

    #[test]
    fn test_clamp_grace_hours_passes_through_normal_values() {
        assert_eq!(clamp_grace_hours(1), 1);
        assert_eq!(clamp_grace_hours(24), 24);
        assert_eq!(clamp_grace_hours(168), 168);
    }

    #[test]
    fn test_clamp_grace_hours_caps_at_one_year() {
        let one_year = 24 * 365;
        assert_eq!(clamp_grace_hours(one_year), one_year);
        assert_eq!(clamp_grace_hours(one_year + 1), one_year);
        assert_eq!(clamp_grace_hours(i64::MAX), one_year);
    }

    #[test]
    fn test_clamp_grace_hours_default_is_positive() {
        // A zero input must clamp to a strictly positive window, otherwise
        // the upload-race guard the grace window represents is defeated.
        assert!(clamp_grace_hours(0) > 0);
    }

    // -----------------------------------------------------------------------
    // OciBlobFootprintReport / OciBlobRepoFootprint serde contract
    // -----------------------------------------------------------------------

    fn sample_report() -> OciBlobFootprintReport {
        OciBlobFootprintReport {
            total_blob_rows: 120,
            distinct_digests: 95,
            logical_bytes: 432_000_000_000,
            physical_bytes: 403_000_000_000,
            grace_hours: 24,
            aged_distinct_digests: 80,
            aged_physical_bytes: 344_000_000_000,
            per_repository: vec![
                OciBlobRepoFootprint {
                    repository_id: Uuid::nil(),
                    blob_rows: 70,
                    logical_bytes: 300_000_000_000,
                },
                OciBlobRepoFootprint {
                    repository_id: Uuid::from_u128(1),
                    blob_rows: 50,
                    logical_bytes: 132_000_000_000,
                },
            ],
        }
    }

    #[test]
    fn test_blob_footprint_report_serde_roundtrip() {
        let original = sample_report();
        let json = serde_json::to_string(&original).unwrap();
        let restored: OciBlobFootprintReport = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, original);
    }

    #[test]
    fn test_blob_footprint_report_field_names() {
        let json = serde_json::to_string(&sample_report()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        for field in [
            "total_blob_rows",
            "distinct_digests",
            "logical_bytes",
            "physical_bytes",
            "grace_hours",
            "aged_distinct_digests",
            "aged_physical_bytes",
            "per_repository",
        ] {
            assert!(value.get(field).is_some(), "missing field '{field}'");
        }
    }

    #[test]
    fn test_blob_footprint_report_preserves_large_byte_totals() {
        // The whole point of the report is making ~403 GB visible; ensure the
        // i64 byte fields survive a serde round trip without truncation.
        let json = serde_json::to_string(&sample_report()).unwrap();
        let restored: OciBlobFootprintReport = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.logical_bytes, 432_000_000_000);
        assert_eq!(restored.physical_bytes, 403_000_000_000);
        assert_eq!(restored.aged_physical_bytes, 344_000_000_000);
    }

    #[test]
    fn test_blob_footprint_report_physical_le_logical_in_sample() {
        // Dedup-aware physical bytes can never exceed the double-counting
        // logical sum; the sample data must respect that invariant.
        let r = sample_report();
        assert!(r.physical_bytes <= r.logical_bytes);
        assert!(r.distinct_digests <= r.total_blob_rows);
        assert!(r.aged_physical_bytes <= r.physical_bytes);
        assert!(r.aged_distinct_digests <= r.distinct_digests);
    }

    #[test]
    fn test_blob_repo_footprint_serde_roundtrip() {
        let original = OciBlobRepoFootprint {
            repository_id: Uuid::from_u128(42),
            blob_rows: 7,
            logical_bytes: 9_999,
        };
        let json = serde_json::to_string(&original).unwrap();
        let restored: OciBlobRepoFootprint = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, original);
    }

    // -----------------------------------------------------------------------
    // map_repo_footprint / assemble_blob_footprint_report (pure assembly)
    // -----------------------------------------------------------------------

    #[test]
    fn test_map_repo_footprint_copies_all_fields() {
        let id = Uuid::from_u128(7);
        let row = map_repo_footprint(id, 13, 4096);
        assert_eq!(row.repository_id, id);
        assert_eq!(row.blob_rows, 13);
        assert_eq!(row.logical_bytes, 4096);
    }

    #[test]
    fn test_map_repo_footprint_zero_values() {
        let row = map_repo_footprint(Uuid::nil(), 0, 0);
        assert_eq!(row.repository_id, Uuid::nil());
        assert_eq!(row.blob_rows, 0);
        assert_eq!(row.logical_bytes, 0);
    }

    fn sample_totals() -> BlobFootprintTotals {
        BlobFootprintTotals {
            total_blob_rows: 120,
            distinct_digests: 95,
            logical_bytes: 432_000_000_000,
            physical_bytes: 403_000_000_000,
            aged_distinct_digests: 80,
            aged_physical_bytes: 344_000_000_000,
        }
    }

    #[test]
    fn test_assemble_blob_footprint_report_maps_every_total() {
        let totals = sample_totals();
        let per_repo = vec![
            map_repo_footprint(Uuid::nil(), 70, 300_000_000_000),
            map_repo_footprint(Uuid::from_u128(1), 50, 132_000_000_000),
        ];
        let report = assemble_blob_footprint_report(totals, 24, per_repo.clone());

        assert_eq!(report.total_blob_rows, totals.total_blob_rows);
        assert_eq!(report.distinct_digests, totals.distinct_digests);
        assert_eq!(report.logical_bytes, totals.logical_bytes);
        assert_eq!(report.physical_bytes, totals.physical_bytes);
        assert_eq!(report.aged_distinct_digests, totals.aged_distinct_digests);
        assert_eq!(report.aged_physical_bytes, totals.aged_physical_bytes);
        assert_eq!(report.per_repository, per_repo);
    }

    #[test]
    fn test_assemble_blob_footprint_report_echoes_grace_hours() {
        // The clamped grace window is threaded straight through; assembly
        // must not re-clamp or otherwise mutate it.
        let report = assemble_blob_footprint_report(sample_totals(), 168, vec![]);
        assert_eq!(report.grace_hours, 168);
        assert!(report.per_repository.is_empty());
    }

    #[test]
    fn test_assemble_blob_footprint_report_matches_sample_report_shape() {
        // Building via the assembly helper must yield the same value as the
        // hand-written sample used by the serde contract tests.
        let report = assemble_blob_footprint_report(
            sample_totals(),
            24,
            vec![
                map_repo_footprint(Uuid::nil(), 70, 300_000_000_000),
                map_repo_footprint(Uuid::from_u128(1), 50, 132_000_000_000),
            ],
        );
        assert_eq!(report, sample_report());
    }

    #[test]
    fn test_assemble_blob_footprint_report_empty_repositories() {
        let report = assemble_blob_footprint_report(
            BlobFootprintTotals {
                total_blob_rows: 0,
                distinct_digests: 0,
                logical_bytes: 0,
                physical_bytes: 0,
                aged_distinct_digests: 0,
                aged_physical_bytes: 0,
            },
            BLOB_REPORT_GRACE_HOURS_DEFAULT,
            vec![],
        );
        assert_eq!(report.total_blob_rows, 0);
        assert_eq!(report.grace_hours, BLOB_REPORT_GRACE_HOURS_DEFAULT);
        assert!(report.per_repository.is_empty());
    }

    #[test]
    fn test_blob_footprint_report_empty_per_repository() {
        let report = OciBlobFootprintReport {
            total_blob_rows: 0,
            distinct_digests: 0,
            logical_bytes: 0,
            physical_bytes: 0,
            grace_hours: BLOB_REPORT_GRACE_HOURS_DEFAULT,
            aged_distinct_digests: 0,
            aged_physical_bytes: 0,
            per_repository: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"per_repository\":[]"));
        let restored: OciBlobFootprintReport = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, report);
    }

    // -----------------------------------------------------------------------
    // run_blob_gc (#1408; deletion design ported from #1409)
    //
    // The no-DB error-mapping tests run anywhere. The database-backed tests
    // exercise the blob-orphan source against a real postgres + filesystem
    // backend; they are gated on `tdh::Fixture::setup` returning Some, which
    // only happens when DATABASE_URL is set and migrations are applied (the
    // same gate the pre-existing storage GC tests above use).
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_run_blob_gc_returns_error_when_db_unreachable() {
        let service = make_service("filesystem");
        let result = service.run_blob_gc(false).await;
        assert!(
            result.is_err(),
            "run_blob_gc must fail when select_orphan_blobs cannot reach DB"
        );
    }

    #[tokio::test]
    async fn test_run_blob_gc_dry_run_returns_error_when_db_unreachable() {
        let service = make_service("s3");
        let result = service.run_blob_gc(true).await;
        assert!(
            result.is_err(),
            "run_blob_gc dry_run shares the same SELECT and must also fail without a DB"
        );
    }

    // Compile-time pins: the grace period stays inside a sane corridor.
    // 1 hour minimum gives in-flight pushes room to finish blob upload and
    // manifest PUT; 7 days maximum prevents long-lived debris from
    // accumulating after the user has long forgotten the abandoned upload.
    // Any change crossing these bounds should be a conscious policy
    // decision, not an accidental typo.
    const _BLOB_AGE_LOWER: () = assert!(MIN_BLOB_AGE_SECS >= 60 * 60);
    const _BLOB_AGE_UPPER: () = assert!(MIN_BLOB_AGE_SECS <= 7 * 24 * 60 * 60);

    /// Stash a blob row with a `created_at` far enough in the past that
    /// `MIN_BLOB_AGE_SECS` does not protect it.
    async fn insert_old_blob(
        pool: &PgPool,
        repo_id: Uuid,
        digest: &str,
        storage_key: &str,
        size: i64,
    ) {
        sqlx::query(
            r#"
            INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key, created_at)
            VALUES ($1, $2, $3, $4, NOW() - INTERVAL '30 days')
            "#,
        )
        .bind(repo_id)
        .bind(digest)
        .bind(size)
        .bind(storage_key)
        .execute(pool)
        .await
        .expect("insert old oci_blobs row");
    }

    /// Flip a test repo to a cloud backend. On cloud, blob storage is a
    /// single content-addressed object shared by every repo on the bucket,
    /// so the GC predicate protects it cross-repo; filesystem fixtures (the
    /// default) get an independent copy per `storage_path`. Exercises the
    /// cloud branch of [`BLOB_PROTECTED_BY_REFS_SQL`].
    async fn set_repo_backend(pool: &PgPool, repo_id: Uuid, backend: &str) {
        sqlx::query("UPDATE repositories SET storage_backend = $2 WHERE id = $1")
            .bind(repo_id)
            .bind(backend)
            .execute(pool)
            .await
            .expect("update repo storage_backend");
    }

    /// Set up two repos that both hold the same aged blob digest, with a
    /// `manifest_blob_refs` entry only in repo A. Returns `(fixture_a,
    /// fixture_b, shared_digest)` or `None` when no DB is configured. Shared
    /// by the cloud and filesystem scope tests so they assert the backend
    /// difference without duplicating the setup.
    async fn setup_two_repos_one_ref(
        digest_seed: char,
    ) -> Option<(
        crate::api::handlers::test_db_helpers::Fixture,
        crate::api::handlers::test_db_helpers::Fixture,
        String,
    )> {
        use crate::api::handlers::test_db_helpers as tdh;
        let fixture_a = tdh::Fixture::setup("local", "docker").await?;
        let Some(fixture_b) = tdh::Fixture::setup("local", "docker").await else {
            fixture_a.teardown().await;
            return None;
        };

        let shared_digest = format!("sha256:{}", digest_seed.to_string().repeat(64));
        let storage_key = format!("oci-blobs/{}", shared_digest);
        // Repo A has the blob and a manifest referencing it.
        insert_old_blob(
            &fixture_a.pool,
            fixture_a.repo_id,
            &shared_digest,
            &storage_key,
            555,
        )
        .await;
        sqlx::query(
            r#"
            INSERT INTO manifest_blob_refs (manifest_digest, blob_digest, repository_id, kind)
            VALUES ($1, $2, $3, 'layer')
            "#,
        )
        .bind(format!("sha256:{}", "1".repeat(64)))
        .bind(&shared_digest)
        .bind(fixture_a.repo_id)
        .execute(&fixture_a.pool)
        .await
        .expect("insert ref in repo A");
        // Repo B has the same blob digest but no manifest references it.
        insert_old_blob(
            &fixture_b.pool,
            fixture_b.repo_id,
            &shared_digest,
            &storage_key,
            555,
        )
        .await;

        Some((fixture_a, fixture_b, shared_digest))
    }

    /// Report whether the blob `(repo_id, digest)` WOULD be flagged orphan,
    /// re-evaluating the exact backend-aware predicate `select_orphan_blobs`
    /// uses ([`BLOB_PROTECTED_BY_REFS_SQL`]). Scoped to one (repo, digest)
    /// so concurrent tests' rows can't leak into the assertion, and so
    /// cloud-vs-filesystem scoping is observable from the evaluated repo's
    /// perspective.
    async fn would_gc_flag_blob(pool: &PgPool, repo_id: Uuid, digest: &str) -> bool {
        let sql = format!(
            r#"
            SELECT EXISTS(
                SELECT 1 FROM oci_blobs ob
                JOIN repositories r ON r.id = ob.repository_id
                WHERE ob.repository_id = $1
                  AND ob.digest = $2
                  AND ob.created_at < NOW() - make_interval(secs => $3::BIGINT)
                  AND NOT {protected}
            )
            "#,
            protected = BLOB_PROTECTED_BY_REFS_SQL,
        );
        sqlx::query_scalar::<_, bool>(&sql)
            .bind(repo_id)
            .bind(digest)
            .bind(MIN_BLOB_AGE_SECS as i64)
            .fetch_one(pool)
            .await
            .expect("orphan-blob predicate check")
    }

    #[tokio::test]
    async fn test_run_blob_gc_flags_orphan_blob() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = tdh::blob_gc_serial_lock().await;

        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let digest = format!("sha256:{}", "c".repeat(64));
        let storage_key = format!("oci-blobs/{}", digest);
        insert_old_blob(&fixture.pool, fixture.repo_id, &digest, &storage_key, 789).await;

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        // Dry-run must complete without errors. We don't pin a count because
        // concurrent tests may insert other orphans.
        let result = service.run_blob_gc(true).await.expect("dry-run succeeds");
        assert!(
            result.dry_run,
            "dry-run result must carry the dry_run flag for the scheduler's gate"
        );
        assert!(
            result.errors.is_empty(),
            "blob gc dry-run must not surface errors: {:?}",
            result.errors
        );
        // OUR digest must be flagged orphan by the underlying predicate.
        let flagged = would_gc_flag_blob(&fixture.pool, fixture.repo_id, &digest).await;

        fixture.teardown().await;

        assert!(
            flagged,
            "an aged oci_blobs row with no manifest_blob_refs must be flagged orphan"
        );
    }

    #[tokio::test]
    async fn test_run_blob_gc_keeps_blob_referenced_by_manifest_blob_refs() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = tdh::blob_gc_serial_lock().await;

        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let manifest_digest = format!("sha256:{}", "d".repeat(64));
        let blob_digest = format!("sha256:{}", "e".repeat(64));
        let storage_key = format!("oci-blobs/{}", blob_digest);

        insert_old_blob(
            &fixture.pool,
            fixture.repo_id,
            &blob_digest,
            &storage_key,
            321,
        )
        .await;
        sqlx::query(
            r#"
            INSERT INTO manifest_blob_refs (manifest_digest, blob_digest, repository_id, kind)
            VALUES ($1, $2, $3, 'layer')
            "#,
        )
        .bind(&manifest_digest)
        .bind(&blob_digest)
        .bind(fixture.repo_id)
        .execute(&fixture.pool)
        .await
        .expect("insert manifest_blob_refs row");

        let flagged = would_gc_flag_blob(&fixture.pool, fixture.repo_id, &blob_digest).await;

        fixture.teardown().await;

        assert!(
            !flagged,
            "blob must not be flagged orphan while manifest_blob_refs references it"
        );
    }

    /// Incident-replay (the production bug that motivated #1409): on CLOUD
    /// backends blob storage is a single content-addressed object per
    /// bucket, so an `oci_blobs` row in any same-backend repo with a live
    /// `manifest_blob_refs` entry must protect the shared object — even when
    /// the row being evaluated lives in a different repo with no references
    /// of its own. The earlier per-`(repo,digest)` reconciler deleted on the
    /// first orphan row and destroyed a shared blob (57 blobs / 85 tags).
    #[tokio::test]
    async fn test_run_blob_gc_keeps_blob_referenced_from_another_repo() {
        let _gc_guard = crate::api::handlers::test_db_helpers::blob_gc_serial_lock().await;
        let Some((fixture_a, fixture_b, shared_digest)) = setup_two_repos_one_ref('9').await else {
            return;
        };
        // Both repos live on the same cloud backend, where the digest
        // resolves to one shared object.
        set_repo_backend(&fixture_a.pool, fixture_a.repo_id, "s3").await;
        set_repo_backend(&fixture_b.pool, fixture_b.repo_id, "s3").await;

        // Evaluate from repo B (the one WITHOUT a local ref): repo A's
        // reference on the shared cloud object must still protect it.
        let flagged = would_gc_flag_blob(&fixture_b.pool, fixture_b.repo_id, &shared_digest).await;

        fixture_a.teardown().await;
        fixture_b.teardown().await;

        assert!(
            !flagged,
            "on a cloud backend a blob must not be flagged orphan while ANY same-backend repo's \
             manifest_blob_refs references the digest; otherwise blob GC would delete the shared \
             object and break the other repo"
        );
    }

    /// Apply-mode counterpart to [`test_run_blob_gc_flags_orphan_blob`]. The
    /// live pass must actually delete the file from storage and the row from
    /// `oci_blobs`. Covers the per-row loop body in
    /// [`StorageGcService::run_blob_gc`] that dry-run skips.
    #[tokio::test]
    async fn test_run_blob_gc_apply_deletes_orphan_blob() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = tdh::blob_gc_serial_lock().await;

        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let digest = format!("sha256:{}", "1".repeat(64));
        let storage_key = format!("oci-blobs/{}", digest);
        let blob_body = Bytes::from_static(b"orphan-payload");
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");
        storage
            .put(&storage_key, blob_body.clone())
            .await
            .expect("write blob to storage");

        insert_old_blob(
            &fixture.pool,
            fixture.repo_id,
            &digest,
            &storage_key,
            blob_body.len() as i64,
        )
        .await;

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let _ = service.run_blob_gc(false).await.expect("apply succeeds");

        let row_remaining: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM oci_blobs WHERE digest = $1")
                .bind(&digest)
                .fetch_one(&fixture.pool)
                .await
                .expect("count oci_blobs");
        let file_still_exists = storage.exists(&storage_key).await.expect("exists check");

        fixture.teardown().await;

        assert_eq!(
            row_remaining, 0,
            "live blob GC must hard-delete the oci_blobs row for an orphan digest"
        );
        assert!(
            !file_still_exists,
            "live blob GC must delete the storage object for an orphan digest"
        );
    }

    /// #1660: idempotent GC storage-delete. When the storage object is already
    /// absent (e.g. a retry after a crash between the storage delete and the
    /// `oci_blobs` row delete), `run_blob_gc` must treat the `NotFound` from
    /// `storage.delete` as success and still hard-delete the orphan row —
    /// otherwise the orphan leaks forever. The filesystem backend returns
    /// `NotFound` for a missing key (unlike the cloud backends' `Ok`), so this
    /// exercises the NotFound tolerance added at the blob-GC delete site.
    #[tokio::test]
    async fn test_run_blob_gc_reclaims_orphan_with_absent_object() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = tdh::blob_gc_serial_lock().await;

        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let digest = format!("sha256:{}", "4".repeat(64));
        let storage_key = format!("oci-blobs/{}", digest);

        // Insert the orphan row but DO NOT write the storage object: this is
        // the post-crash state where the object is already gone but the row
        // remains. GC's storage.delete will hit NotFound.
        insert_old_blob(&fixture.pool, fixture.repo_id, &digest, &storage_key, 42).await;

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let result = service
            .run_blob_gc(false)
            .await
            .expect("apply succeeds even when the storage object is already absent");

        let row_remaining: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_blobs WHERE repository_id = $1 AND digest = $2",
        )
        .bind(fixture.repo_id)
        .bind(&digest)
        .fetch_one(&fixture.pool)
        .await
        .expect("count oci_blobs");

        fixture.teardown().await;

        assert_eq!(
            row_remaining, 0,
            "an orphan blob whose storage object is already absent must still be reclaimed \
             (NotFound from storage.delete is treated as success, not a rollback)"
        );
        assert!(
            result.errors.is_empty(),
            "a NotFound storage delete must not be recorded as a GC error; got {:?}",
            result.errors
        );
    }

    /// Apply-mode counterpart to
    /// [`test_run_blob_gc_keeps_blob_referenced_by_manifest_blob_refs`].
    /// Ensures the per-row `is_blob_still_orphan` re-check inside the
    /// transaction sees the live `manifest_blob_refs` row and skips delete.
    #[tokio::test]
    async fn test_run_blob_gc_apply_keeps_referenced_blob() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = tdh::blob_gc_serial_lock().await;

        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let manifest_digest = format!("sha256:{}", "2".repeat(64));
        let blob_digest = format!("sha256:{}", "3".repeat(64));
        let storage_key = format!("oci-blobs/{}", blob_digest);
        let blob_body = Bytes::from_static(b"referenced-payload");
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");
        storage
            .put(&storage_key, blob_body.clone())
            .await
            .expect("write blob to storage");

        insert_old_blob(
            &fixture.pool,
            fixture.repo_id,
            &blob_digest,
            &storage_key,
            blob_body.len() as i64,
        )
        .await;
        sqlx::query(
            r#"
            INSERT INTO manifest_blob_refs (manifest_digest, blob_digest, repository_id, kind)
            VALUES ($1, $2, $3, 'layer')
            "#,
        )
        .bind(&manifest_digest)
        .bind(&blob_digest)
        .bind(fixture.repo_id)
        .execute(&fixture.pool)
        .await
        .expect("insert manifest_blob_refs row");
        // The referencing manifest must be LIVE (tagged) for the ref to be
        // legitimate: apply-mode prunes refs of manifests that are no longer
        // reachable (#1409 H1), so an untagged manifest's ref would be
        // correctly removed and its blob reclaimed. Tagging keeps this the
        // "referenced by a live manifest" case the test asserts.
        sqlx::query(
            r#"
            INSERT INTO oci_tags (
                repository_id, name, tag, manifest_digest, manifest_content_type
            )
            VALUES ($1, 'keep-img', 'latest', $2,
                    'application/vnd.oci.image.manifest.v1+json')
            "#,
        )
        .bind(fixture.repo_id)
        .bind(&manifest_digest)
        .execute(&fixture.pool)
        .await
        .expect("tag referencing manifest so its ref is live");

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let _ = service.run_blob_gc(false).await.expect("apply succeeds");

        let row_remaining: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_blobs WHERE repository_id = $1 AND digest = $2",
        )
        .bind(fixture.repo_id)
        .bind(&blob_digest)
        .fetch_one(&fixture.pool)
        .await
        .expect("count oci_blobs");
        let file_still_exists = storage.exists(&storage_key).await.expect("exists check");

        fixture.teardown().await;

        assert_eq!(
            row_remaining, 1,
            "oci_blobs row must survive when a manifest_blob_refs entry references the digest"
        );
        assert!(
            file_still_exists,
            "storage object must survive when a manifest_blob_refs entry references the digest"
        );
    }

    /// H1 (#1409): apply-mode first prunes `manifest_blob_refs` whose
    /// manifest is no longer live, so a blob pinned only by a dead manifest is
    /// reclaimed in the same pass. Here the referencing manifest is never
    /// tagged and is not an index child, so its ref is stale; after prune the
    /// blob has no protection and must be deleted. This is the headline
    /// scenario ("reclaim orphan blobs once their manifests are gone") that
    /// could not happen before H1 because the ref pinned the digest forever.
    #[tokio::test]
    async fn test_run_blob_gc_prunes_orphan_ref_and_reclaims_blob() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = tdh::blob_gc_serial_lock().await;

        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let manifest_digest = format!("sha256:{}", "4".repeat(64));
        let blob_digest = format!("sha256:{}", "5".repeat(64));
        let storage_key = format!("oci-blobs/{}", blob_digest);
        let blob_body = Bytes::from_static(b"dead-manifest-payload");
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");
        storage
            .put(&storage_key, blob_body.clone())
            .await
            .expect("write blob to storage");

        insert_old_blob(
            &fixture.pool,
            fixture.repo_id,
            &blob_digest,
            &storage_key,
            blob_body.len() as i64,
        )
        .await;
        // A ref from a manifest that is NOT tagged and NOT an index child:
        // stale, so prune must remove it.
        sqlx::query(
            r#"
            INSERT INTO manifest_blob_refs (manifest_digest, blob_digest, repository_id, kind)
            VALUES ($1, $2, $3, 'layer')
            "#,
        )
        .bind(&manifest_digest)
        .bind(&blob_digest)
        .bind(fixture.repo_id)
        .execute(&fixture.pool)
        .await
        .expect("insert stale manifest_blob_refs row");

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        let _ = service.run_blob_gc(false).await.expect("apply succeeds");

        let refs_remaining: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM manifest_blob_refs WHERE repository_id = $1 AND manifest_digest = $2",
        )
        .bind(fixture.repo_id)
        .bind(&manifest_digest)
        .fetch_one(&fixture.pool)
        .await
        .expect("count manifest_blob_refs");
        let blob_remaining: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_blobs WHERE repository_id = $1 AND digest = $2",
        )
        .bind(fixture.repo_id)
        .bind(&blob_digest)
        .fetch_one(&fixture.pool)
        .await
        .expect("count oci_blobs");
        let file_still_exists = storage.exists(&storage_key).await.expect("exists check");

        fixture.teardown().await;

        assert_eq!(
            refs_remaining, 0,
            "apply-mode must prune the manifest_blob_refs row of a manifest that is no longer live"
        );
        assert_eq!(
            blob_remaining, 0,
            "once its only (stale) ref is pruned, the orphan blob row must be reclaimed in the same pass"
        );
        assert!(
            !file_still_exists,
            "the orphan blob's storage object must be deleted after its stale ref is pruned"
        );
    }

    #[tokio::test]
    async fn test_run_blob_gc_respects_grace_period() {
        // Even with zero manifest_blob_refs rows, a blob still inside the
        // grace window represents an in-flight push and must be left alone.
        // This is the explicit safeguard against the upload-then-manifest
        // race documented on run_blob_gc.
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = tdh::blob_gc_serial_lock().await;

        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let digest = format!("sha256:{}", "f".repeat(64));
        let storage_key = format!("oci-blobs/{}", digest);
        // created_at = NOW() default; well inside MIN_BLOB_AGE_SECS.
        sqlx::query(
            r#"
            INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key)
            VALUES ($1, $2, 1024, $3)
            "#,
        )
        .bind(fixture.repo_id)
        .bind(&digest)
        .bind(&storage_key)
        .execute(&fixture.pool)
        .await
        .expect("insert fresh oci_blobs row");

        let flagged = would_gc_flag_blob(&fixture.pool, fixture.repo_id, &digest).await;

        fixture.teardown().await;

        assert!(
            !flagged,
            "blobs younger than MIN_BLOB_AGE_SECS must be skipped to protect in-flight pushes"
        );
    }

    #[tokio::test]
    async fn test_run_blob_gc_filesystem_scopes_orphan_per_storage_path() {
        // Filesystem counterpart to the cloud cross-repo test: each
        // filesystem repo roots its own tree, so the same digest is a
        // DISTINCT physical file per repo. A reference in repo A must NOT
        // protect repo B's independent copy (otherwise B's orphan file would
        // leak forever), while repo A's own copy stays protected. The
        // predicate is backend-aware, not unconditionally global.
        let _gc_guard = crate::api::handlers::test_db_helpers::blob_gc_serial_lock().await;
        let Some((fixture_a, fixture_b, shared_digest)) = setup_two_repos_one_ref('7').await else {
            return;
        };
        // Both repos keep the default `filesystem` backend, each with its
        // own storage_path.

        let flagged_b =
            would_gc_flag_blob(&fixture_b.pool, fixture_b.repo_id, &shared_digest).await;
        let flagged_a =
            would_gc_flag_blob(&fixture_a.pool, fixture_a.repo_id, &shared_digest).await;

        fixture_a.teardown().await;
        fixture_b.teardown().await;

        assert!(
            flagged_b,
            "on filesystem a blob referenced only from another repo's storage_path must still be \
             flagged orphan: the copies are physically distinct files"
        );
        assert!(
            !flagged_a,
            "repo A's own copy must remain protected by its own manifest_blob_refs entry"
        );
    }

    // -----------------------------------------------------------------------
    // Two-phase mark-and-sweep (#1660 PR2). These DB-backed tests exercise the
    // load-bearing races the mark/sweep split is designed to close: the
    // push-adopt resurrection race, the crash-after-mark and
    // crash-between-storage-and-row-delete recovery paths, the sweep-grace
    // timing, and the "referenced blob is never marked" invariant.
    // -----------------------------------------------------------------------

    /// Read a blob's `pending_delete_at` marker (NULL when unmarked).
    async fn blob_pending_delete_at(
        pool: &PgPool,
        repo_id: Uuid,
        digest: &str,
    ) -> Option<chrono::DateTime<chrono::Utc>> {
        sqlx::query_scalar(
            "SELECT pending_delete_at FROM oci_blobs WHERE repository_id = $1 AND digest = $2",
        )
        .bind(repo_id)
        .bind(digest)
        .fetch_one(pool)
        .await
        .expect("read pending_delete_at")
    }

    /// Count the `oci_blobs` rows for one (repo, digest).
    async fn blob_row_count(pool: &PgPool, repo_id: Uuid, digest: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM oci_blobs WHERE repository_id = $1 AND digest = $2",
        )
        .bind(repo_id)
        .bind(digest)
        .fetch_one(pool)
        .await
        .expect("count oci_blobs")
    }

    /// Write an orphan blob object + row and return the resolved filesystem
    /// backend so the caller can assert on the storage object. Shared by the
    /// mark/sweep tests so they do not duplicate the fixture wiring.
    async fn seed_orphan_blob_object(
        fixture: &crate::api::handlers::test_db_helpers::Fixture,
        digest: &str,
        storage_key: &str,
        body: &Bytes,
    ) -> Arc<dyn StorageBackend> {
        let location = StorageLocation {
            backend: "filesystem".to_string(),
            path: fixture.storage_dir.to_string_lossy().to_string(),
        };
        let storage = fixture
            .state
            .storage_registry
            .backend_for(&location)
            .expect("filesystem backend");
        storage
            .put(storage_key, body.clone())
            .await
            .expect("write blob to storage");
        insert_old_blob(
            &fixture.pool,
            fixture.repo_id,
            digest,
            storage_key,
            body.len() as i64,
        )
        .await;
        storage
    }

    /// (e) A still-referenced blob is NEVER marked. Phase A must leave
    /// `pending_delete_at` NULL for a blob a live (tagged) manifest still
    /// references, so it can never become sweep-eligible.
    #[tokio::test]
    async fn test_run_blob_gc_mark_skips_referenced_blob() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = tdh::blob_gc_serial_lock().await;

        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let manifest_digest = format!("sha256:{}", "a".repeat(64));
        let blob_digest = format!("sha256:{}", "b".repeat(64));
        let storage_key = format!("oci-blobs/{}", blob_digest);
        let body = Bytes::from_static(b"referenced-not-marked");
        let _storage = seed_orphan_blob_object(&fixture, &blob_digest, &storage_key, &body).await;

        sqlx::query(
            "INSERT INTO manifest_blob_refs (manifest_digest, blob_digest, repository_id, kind) \
             VALUES ($1, $2, $3, 'layer')",
        )
        .bind(&manifest_digest)
        .bind(&blob_digest)
        .bind(fixture.repo_id)
        .execute(&fixture.pool)
        .await
        .expect("insert manifest_blob_refs row");
        // Tag the manifest so its ref is LIVE (mark prunes refs of dead
        // manifests first, so an untagged manifest's ref would be removed).
        sqlx::query(
            "INSERT INTO oci_tags (repository_id, name, tag, manifest_digest, manifest_content_type) \
             VALUES ($1, 'keep-img', 'latest', $2, 'application/vnd.oci.image.manifest.v1+json')",
        )
        .bind(fixture.repo_id)
        .bind(&manifest_digest)
        .execute(&fixture.pool)
        .await
        .expect("tag referencing manifest");

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());
        service
            .run_blob_gc_mark(false)
            .await
            .expect("mark succeeds");

        let marked = blob_pending_delete_at(&fixture.pool, fixture.repo_id, &blob_digest).await;

        fixture.teardown().await;

        assert!(
            marked.is_none(),
            "a blob referenced by a live manifest must never be marked pending_delete_at"
        );
    }

    /// (a) The push-adopt race. GC marks blob `D`; before the sweep runs, a
    /// concurrent re-push resurrects `D` (clears the marker under the push-path
    /// row lock, exactly what the finalize `ON CONFLICT DO UPDATE` /
    /// `persist_tag_and_refs` un-mark do). The sweep's marker-aware re-check
    /// (`require_pending = true`) must then SKIP `D`: its row and storage
    /// object survive. This is the TOCTOU a naive commit-then-delete reorder
    /// would reopen.
    #[tokio::test]
    async fn test_run_blob_gc_sweep_skips_resurrected_blob() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = tdh::blob_gc_serial_lock().await;

        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let digest = format!("sha256:{}", "c".repeat(64));
        let storage_key = format!("oci-blobs/{}", digest);
        let body = Bytes::from_static(b"resurrected-payload");
        let storage = seed_orphan_blob_object(&fixture, &digest, &storage_key, &body).await;

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());

        // Phase A: mark the orphan.
        service
            .run_blob_gc_mark(false)
            .await
            .expect("mark succeeds");
        assert!(
            blob_pending_delete_at(&fixture.pool, fixture.repo_id, &digest)
                .await
                .is_some(),
            "mark phase must stamp pending_delete_at on the orphan"
        );

        // Concurrent re-push resurrects D: the finalize upsert clears the
        // marker under the push-path lock (#1660 PR1). We issue the same
        // marker-clearing UPDATE here.
        sqlx::query(
            "UPDATE oci_blobs SET pending_delete_at = NULL \
             WHERE repository_id = $1 AND digest = $2",
        )
        .bind(fixture.repo_id)
        .bind(&digest)
        .execute(&fixture.pool)
        .await
        .expect("resurrect (clear marker)");

        // Phase B: sweep with zero grace. The resurrected (un-marked) blob
        // must be skipped by the marker-aware re-check.
        service
            .run_blob_gc_sweep(false, 0)
            .await
            .expect("sweep succeeds");

        let row_remaining = blob_row_count(&fixture.pool, fixture.repo_id, &digest).await;
        let file_exists = storage.exists(&storage_key).await.expect("exists check");

        fixture.teardown().await;

        assert_eq!(
            row_remaining, 1,
            "a blob resurrected (marker cleared) before the sweep must survive: the sweep's \
             marker-aware re-check skips it"
        );
        assert!(
            file_exists,
            "a resurrected blob's storage object must not be deleted by the sweep"
        );
    }

    /// (d) + grace timing. A freshly-marked orphan younger than the sweep
    /// grace stays marked but is NOT swept; once past the grace it is swept
    /// (storage object + row both gone). Mirrors the mark->sweep cadence the
    /// scheduler drives.
    #[tokio::test]
    async fn test_run_blob_gc_sweep_respects_grace_then_deletes() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = tdh::blob_gc_serial_lock().await;

        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let digest = format!("sha256:{}", "d".repeat(64));
        let storage_key = format!("oci-blobs/{}", digest);
        let body = Bytes::from_static(b"grace-then-delete");
        let storage = seed_orphan_blob_object(&fixture, &digest, &storage_key, &body).await;

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());

        service
            .run_blob_gc_mark(false)
            .await
            .expect("mark succeeds");

        // Sweep with a 1h grace: the blob was just marked, so it is younger
        // than the grace and must stay marked, storage + row intact.
        service
            .run_blob_gc_sweep(false, 3600)
            .await
            .expect("in-grace sweep succeeds");
        assert_eq!(
            blob_row_count(&fixture.pool, fixture.repo_id, &digest).await,
            1,
            "a blob still inside the sweep grace must not be swept"
        );
        assert!(
            blob_pending_delete_at(&fixture.pool, fixture.repo_id, &digest)
                .await
                .is_some(),
            "an in-grace blob must remain marked for a later sweep"
        );
        assert!(
            storage.exists(&storage_key).await.expect("exists check"),
            "an in-grace blob's storage object must survive"
        );

        // Sweep with zero grace: now eligible, so the blob is swept.
        service
            .run_blob_gc_sweep(false, 0)
            .await
            .expect("post-grace sweep succeeds");

        let row_remaining = blob_row_count(&fixture.pool, fixture.repo_id, &digest).await;
        let file_exists = storage.exists(&storage_key).await.expect("exists check");

        fixture.teardown().await;

        assert_eq!(
            row_remaining, 0,
            "a genuinely-orphan blob past the sweep grace must have its row reclaimed"
        );
        assert!(
            !file_exists,
            "a genuinely-orphan blob past the sweep grace must have its storage object deleted"
        );
    }

    /// (b) Crash after mark, before sweep. A blob left marked by a mark pass
    /// that then crashed must be completed by the next sweep: it stays marked
    /// (object intact, orphan so unpullable) and a later sweep deletes both.
    #[tokio::test]
    async fn test_run_blob_gc_sweep_completes_after_crash_between_mark_and_sweep() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = tdh::blob_gc_serial_lock().await;

        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let digest = format!("sha256:{}", "e".repeat(64));
        let storage_key = format!("oci-blobs/{}", digest);
        let body = Bytes::from_static(b"crash-after-mark");
        let storage = seed_orphan_blob_object(&fixture, &digest, &storage_key, &body).await;

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());

        // Phase A commits the marker, then "crash" — no sweep runs. State:
        // row marked, object present.
        service
            .run_blob_gc_mark(false)
            .await
            .expect("mark succeeds");
        assert!(
            blob_pending_delete_at(&fixture.pool, fixture.repo_id, &digest)
                .await
                .is_some(),
            "after a mark-then-crash the row stays marked"
        );
        assert!(
            storage.exists(&storage_key).await.expect("exists check"),
            "after a mark-then-crash the storage object is intact (no dangling ref possible)"
        );

        // The next sweep completes the deletion.
        service
            .run_blob_gc_sweep(false, 0)
            .await
            .expect("recovery sweep succeeds");

        let row_remaining = blob_row_count(&fixture.pool, fixture.repo_id, &digest).await;
        let file_exists = storage.exists(&storage_key).await.expect("exists check");

        fixture.teardown().await;

        assert_eq!(
            row_remaining, 0,
            "the next sweep must complete a marked-but-unswept blob"
        );
        assert!(
            !file_exists,
            "the recovery sweep must delete the storage object"
        );
    }

    /// (c) Crash between storage-delete and row-delete. The object is already
    /// gone but the row is still marked. The next sweep must idempotently
    /// re-run `storage.delete` (NotFound -> Ok) and remove the row — a
    /// re-collectable orphan, never a leaked object or a dangling row — and
    /// must not record an error.
    #[tokio::test]
    async fn test_run_blob_gc_sweep_recollects_after_crash_mid_delete() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = tdh::blob_gc_serial_lock().await;

        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let digest = format!("sha256:{}", "f".repeat(64));
        let storage_key = format!("oci-blobs/{}", digest);
        let body = Bytes::from_static(b"crash-mid-delete");
        let storage = seed_orphan_blob_object(&fixture, &digest, &storage_key, &body).await;

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());

        service
            .run_blob_gc_mark(false)
            .await
            .expect("mark succeeds");

        // Simulate the crash: the sweep's storage.delete succeeded but the
        // row delete never committed. The object is gone; the row stays
        // marked.
        storage
            .delete(&storage_key)
            .await
            .expect("remove object (crash point)");
        assert!(
            blob_pending_delete_at(&fixture.pool, fixture.repo_id, &digest)
                .await
                .is_some(),
            "post-crash the marked row still exists"
        );

        // The re-sweep must idempotently complete: NotFound from storage.delete
        // is success, the marked row is removed, no error recorded.
        let result = service
            .run_blob_gc_sweep(false, 0)
            .await
            .expect("re-sweep succeeds even when the object is already absent");

        let row_remaining = blob_row_count(&fixture.pool, fixture.repo_id, &digest).await;
        let file_exists = storage.exists(&storage_key).await.expect("exists check");

        fixture.teardown().await;

        assert_eq!(
            row_remaining, 0,
            "a re-sweep after a crash between storage-delete and row-delete must reclaim the row"
        );
        assert!(
            !file_exists,
            "the storage object stays gone (no leaked object)"
        );
        assert!(
            result.errors.is_empty(),
            "a NotFound during the recovery sweep must not be recorded as an error; got {:?}",
            result.errors
        );
    }

    /// A re-mark of an already-marked blob is a no-op: the `pending_delete_at
    /// IS NULL` guard leaves the ORIGINAL timestamp untouched, so the sweep
    /// grace is always measured from the first mark (a blob cannot dodge the
    /// sweep by being re-marked every tick).
    #[tokio::test]
    async fn test_run_blob_gc_mark_is_idempotent_and_preserves_timestamp() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = tdh::blob_gc_serial_lock().await;

        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let digest = format!("sha256:{}", "1".repeat(64));
        let storage_key = format!("oci-blobs/{}", digest);
        let body = Bytes::from_static(b"idempotent-mark");
        let _storage = seed_orphan_blob_object(&fixture, &digest, &storage_key, &body).await;

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());

        service.run_blob_gc_mark(false).await.expect("first mark");
        let first = blob_pending_delete_at(&fixture.pool, fixture.repo_id, &digest)
            .await
            .expect("first mark must stamp the marker");

        // A second mark pass must NOT overwrite the timestamp.
        service.run_blob_gc_mark(false).await.expect("second mark");
        let second = blob_pending_delete_at(&fixture.pool, fixture.repo_id, &digest)
            .await
            .expect("blob is still marked after a second pass");

        fixture.teardown().await;

        assert_eq!(
            first, second,
            "re-marking an already-marked blob must preserve the original pending_delete_at \
             so the sweep grace is measured from the first mark"
        );
    }

    // -----------------------------------------------------------------------
    // oci_blob_footprint_report: DB-backed regression test (#2626)
    // -----------------------------------------------------------------------

    /// Seed one repository plus its `oci_blobs` rows for the footprint test.
    /// `storage_path` is derived from the unique key, so two filesystem
    /// repos never share a path and two cloud repos never share one either
    /// (proving path is IGNORED for shared backends).
    async fn seed_footprint_repo(pool: &PgPool, backend: &str, blobs: &[(&str, i64)]) -> Uuid {
        let id = Uuid::new_v4();
        let key = format!("gc-fp-{}", &id.to_string()[..8]);
        sqlx::query(
            "INSERT INTO repositories \
                 (id, key, name, format, repo_type, storage_backend, storage_path) \
             VALUES ($1, $2, $2, 'docker'::repository_format, \
                     'local'::repository_type, $3, $4)",
        )
        .bind(id)
        .bind(&key)
        .bind(backend)
        .bind(format!("/data/{key}"))
        .execute(pool)
        .await
        .expect("insert repository");
        for (digest, size) in blobs {
            sqlx::query(
                "INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key) \
                 VALUES ($1, $2, $3, 'oci-blobs/' || $2)",
            )
            .bind(id)
            .bind(digest)
            .bind(size)
            .execute(pool)
            .await
            .expect("insert oci blob");
        }
        id
    }

    /// #2626 regression + physical-bytes model + age filter, end to end
    /// against real Postgres (`--lib`, so the coverage/unit CI jobs run it):
    ///
    /// 1. The report must EXECUTE: `make_interval` only defines int4 named
    ///    parameters, so the un-cast int8 bind made every call fail with
    ///    "function make_interval(hours => bigint) does not exist".
    /// 2. Physical bytes follow [`BLOB_PROTECTED_BY_REFS_SQL`]'s ownership
    ///    model: a digest shared by two `filesystem` repos is TWO real
    ///    files (counted per `storage_path`), while a digest shared by two
    ///    repos on a shared backend is ONE object.
    /// 3. The age filter is genuinely exercised: backdating a blob past the
    ///    grace window must move the `aged_*` figures by exactly that blob.
    ///    A vacuous filter (always true or always false) fails either the
    ///    aged==0 assertion before the backdate or the aged==300 one after.
    ///
    /// The model assertions run against `fetch_blob_footprint_totals`
    /// scoped to the seeded digests — the SAME statement the unscoped
    /// production report executes — so every figure is EXACT (`==`), not a
    /// cluster-wide before/after delta. The previous delta form raced every
    /// concurrent suite that deletes `oci_blobs` rows (`cargo nextest` is
    /// process-per-test against one shared database) and was flaky in CI
    /// (#3129). The digests are locally generated UUIDs, so no concurrent
    /// test can add or remove matching rows. The unscoped report itself is
    /// still called and pinned by race-free ABSOLUTE lower bounds (our rows
    /// exist for the whole test, so cluster totals can never be below our
    /// contribution), which also proves the `None` scope arm filters
    /// nothing out. Per-repository rows are keyed by our own repo ids and
    /// asserted exactly, as before.
    #[tokio::test]
    async fn test_oci_blob_footprint_report_executes_dedups_and_ages() {
        use crate::api::handlers::test_db_helpers as tdh;

        // The backdated orphan blob below is old enough for a concurrent
        // blob-GC mark/sweep test to reap mid-assertion; serialize with
        // that cluster the same way the run_blob_gc tests do.
        let _gc_guard = tdh::blob_gc_serial_lock().await;
        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let registry = Arc::new(crate::storage::StorageRegistry::new(
            std::collections::HashMap::new(),
            "filesystem".to_string(),
        ));
        let svc = StorageGcService::new(pool.clone(), registry);

        // Fixture: a digest shared by two filesystem repos (distinct
        // storage_path => two physical files), a digest unique to repo_a,
        // and a digest shared by two repos on a shared backend ('s3': one
        // physical object regardless of path).
        let shared_fs = format!("sha256:{}", Uuid::new_v4().simple());
        let only_a = format!("sha256:{}", Uuid::new_v4().simple());
        let shared_cloud = format!("sha256:{}", Uuid::new_v4().simple());
        let repo_a =
            seed_footprint_repo(&pool, "filesystem", &[(&shared_fs, 1_000), (&only_a, 300)]).await;
        let repo_b = seed_footprint_repo(&pool, "filesystem", &[(&shared_fs, 1_000)]).await;
        let repo_c = seed_footprint_repo(&pool, "s3", &[(&shared_cloud, 700)]).await;
        let repo_d = seed_footprint_repo(&pool, "s3", &[(&shared_cloud, 700)]).await;

        let digests = [shared_fs.clone(), only_a.clone(), shared_cloud.clone()];

        // Totals scoped to exactly the seeded digests: deterministic under
        // any concurrent suite, so every figure is exact.
        let t1 = svc
            .fetch_blob_footprint_totals(24, Some(&digests))
            .await
            .expect("scoped footprint totals must execute (#2626)");
        assert_eq!(t1.total_blob_rows, 5, "five rows seeded across four repos");
        assert_eq!(t1.distinct_digests, 3, "three content identities seeded");
        assert_eq!(
            t1.logical_bytes, 3_700,
            "1000+300+1000 fs + 700+700 cloud rows seeded"
        );
        // Filesystem copies count per storage_path (1000 + 1000 + 300) and
        // the cloud digest counts once (700). Global per-digest dedup would
        // report 2000 here; per-path-everywhere counting would report
        // 3700. Both MUST fail this.
        assert_eq!(
            t1.physical_bytes, 3_000,
            "fs digest per path + cloud digest once"
        );
        // Every seeded row is seconds old: nothing crosses the 24h grace
        // window yet. An always-true age filter reports 3000 here.
        assert_eq!(t1.aged_distinct_digests, 0);
        assert_eq!(t1.aged_physical_bytes, 0);

        // The production (unscoped) report must EXECUTE (#2626) and share
        // the same statement. Our rows exist for the whole test and no
        // other suite can delete them, so cluster totals at this snapshot
        // are at least our contribution — an absolute lower bound that
        // holds regardless of concurrent inserts/deletes elsewhere (no
        // before/after delta, which is what made this test flaky, #3129).
        // A `None` digest scope that wrongly filtered rows out would
        // report 0 here and fail.
        let r1 = svc
            .oci_blob_footprint_report(24)
            .await
            .expect("footprint report must execute after seeding (#2626)");
        assert_eq!(r1.grace_hours, 24);
        assert!(
            r1.total_blob_rows >= 5,
            "cluster row count can never be below our 5 live rows, got {}",
            r1.total_blob_rows
        );
        assert!(
            r1.distinct_digests >= 3,
            "cluster digest count can never be below our 3 live digests, got {}",
            r1.distinct_digests
        );
        // Snapshot-internal invariants (computed in one statement, so
        // consistent even mid-churn).
        assert!(r1.logical_bytes >= r1.physical_bytes);
        assert!(r1.aged_physical_bytes <= r1.physical_bytes);

        // Backdate the unique digest past the 24h grace window: the aged
        // figures must move by exactly that blob (all our other rows are
        // seconds old). A filter that ignores `first_seen` in either
        // direction fails these exact assertions.
        sqlx::query(
            "UPDATE oci_blobs SET created_at = NOW() - INTERVAL '48 hours' \
             WHERE repository_id = $1 AND digest = $2",
        )
        .bind(repo_a)
        .bind(&only_a)
        .execute(&pool)
        .await
        .expect("backdate blob");

        let t2 = svc
            .fetch_blob_footprint_totals(24, Some(&digests))
            .await
            .expect("scoped footprint totals must execute after backdating");
        assert_eq!(
            t2.aged_distinct_digests, 1,
            "exactly the backdated digest crossed the grace window"
        );
        assert_eq!(
            t2.aged_physical_bytes, 300,
            "backdated 300-byte blob crossed the grace window: {} -> {}",
            t1.aged_physical_bytes, t2.aged_physical_bytes
        );
        // The backdate must not disturb the non-aged figures.
        assert_eq!(t2.total_blob_rows, 5);
        assert_eq!(t2.logical_bytes, 3_700);
        assert_eq!(t2.physical_bytes, 3_000);

        // Per-repo rows are isolated to our repos and exact.
        let by_repo: std::collections::HashMap<Uuid, (i64, i64)> = r1
            .per_repository
            .iter()
            .map(|r| (r.repository_id, (r.blob_rows, r.logical_bytes)))
            .collect();
        assert_eq!(by_repo.get(&repo_a), Some(&(2, 1_300)));
        assert_eq!(by_repo.get(&repo_b), Some(&(1, 1_000)));
        assert_eq!(by_repo.get(&repo_c), Some(&(1, 700)));
        assert_eq!(by_repo.get(&repo_d), Some(&(1, 700)));

        // Cleanup (repositories cascade-deletes oci_blobs).
        for repo in [repo_a, repo_b, repo_c, repo_d] {
            let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
                .bind(repo)
                .execute(&pool)
                .await;
        }
    }

    /// Cleanup-journal sweep claims (Tier-2: no-op without DATABASE_URL).
    ///
    /// The claim (not the row DELETE) is what stops two replicas from both
    /// attempting the external storage delete for one key: while a claim is
    /// live the key is invisible to other sweepers, and a failed storage
    /// delete releases the claim with the error recorded for retry.
    #[tokio::test]
    async fn cleanup_key_sweep_claim_is_exclusive_and_releasable() {
        use crate::api::handlers::test_db_helpers as tdh;

        // Advisory (cross-process) lock: nextest runs each test in its own
        // process, so the in-process storage_gc_test_guard cannot stop the
        // OTHER cleanup-claim test from claiming this test's aged fixture
        // rows out from under it.
        let _gc_guard = tdh::blob_gc_serial_lock().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let storage_key = format!("oci-uploads/claim-test/{}", Uuid::new_v4());
        sqlx::query(
            "INSERT INTO oci_upload_cleanup_keys \
                 (repository_id, storage_key, created_at, storage_write_completed_at) \
             VALUES ($1, $2, NOW() - INTERVAL '48 hours', NOW() - INTERVAL '48 hours')",
        )
        .bind(fixture.repo_id)
        .bind(&storage_key)
        .execute(&fixture.pool)
        .await
        .expect("insert cleanup key");

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());

        // First sweeper claims the key.
        let batch = service
            .claim_unreferenced_oci_upload_cleanup_keys(None)
            .await
            .expect("claim query ok");
        let mine = batch
            .into_iter()
            .find(|k| k.storage_key == storage_key)
            .expect("aged committed key must be claimable");
        let first_token = mine.claim_token.expect("claim must carry a token");

        // A concurrent sweeper must not see it while the claim is live.
        let contended = service
            .claim_unreferenced_oci_upload_cleanup_keys(None)
            .await
            .expect("claim query ok");
        assert!(
            contended.iter().all(|k| k.storage_key != storage_key),
            "a claimed cleanup key must not be handed to a second sweeper"
        );

        // A failed storage delete releases the claim with the error recorded;
        // the key becomes sweepable again under a fresh token.
        service
            .release_cleanup_key_claim(&mine, "storage boom")
            .await;
        let retried = service
            .claim_unreferenced_oci_upload_cleanup_keys(None)
            .await
            .expect("claim query ok");
        let mine_again = retried
            .into_iter()
            .find(|k| k.storage_key == storage_key)
            .expect("released key must be claimable again");
        assert_ne!(
            mine_again.claim_token,
            Some(first_token),
            "reclaim must mint a fresh token"
        );
        let last_error: Option<String> = sqlx::query_scalar(
            "SELECT last_error FROM oci_upload_cleanup_keys WHERE storage_key = $1",
        )
        .bind(&storage_key)
        .fetch_one(&fixture.pool)
        .await
        .expect("fetch last_error");
        assert_eq!(last_error.as_deref(), Some("storage boom"));

        let _ = sqlx::query("DELETE FROM oci_upload_cleanup_keys WHERE storage_key = $1")
            .bind(&storage_key)
            .execute(&fixture.pool)
            .await;
        fixture.teardown().await;
    }

    /// The repository-scoped live GC path must apply its scope while claiming,
    /// not only while dry-run selecting. Otherwise an admin collecting repo A
    /// could claim and delete repo B's cleanup-journal keys.
    #[tokio::test]
    async fn repository_scoped_cleanup_claims_do_not_cross_repositories() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _gc_guard = tdh::blob_gc_serial_lock().await;
        let Some(repo_a) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };
        let Some(repo_b) = tdh::Fixture::setup("local", "docker").await else {
            repo_a.teardown().await;
            return;
        };

        let committed_a = format!("oci-uploads/scoped-committed-a/{}", Uuid::new_v4());
        let committed_b = format!("oci-uploads/scoped-committed-b/{}", Uuid::new_v4());
        let pending_a = format!("oci-uploads/scoped-pending-a/{}", Uuid::new_v4());
        let pending_b = format!("oci-uploads/scoped-pending-b/{}", Uuid::new_v4());
        sqlx::query(
            "INSERT INTO oci_upload_cleanup_keys \
                 (repository_id, storage_key, created_at, storage_write_completed_at) \
             VALUES \
                 ($1, $2, NOW() - INTERVAL '48 hours', NOW() - INTERVAL '48 hours'), \
                 ($1, $3, NOW() - INTERVAL '48 hours', NULL), \
                 ($4, $5, NOW() - INTERVAL '48 hours', NOW() - INTERVAL '48 hours'), \
                 ($4, $6, NOW() - INTERVAL '48 hours', NULL)",
        )
        .bind(repo_a.repo_id)
        .bind(&committed_a)
        .bind(&pending_a)
        .bind(repo_b.repo_id)
        .bind(&committed_b)
        .bind(&pending_b)
        .execute(&repo_a.pool)
        .await
        .expect("insert repository-scoped cleanup keys");

        let service =
            StorageGcService::new(repo_a.pool.clone(), repo_a.state.storage_registry.clone());
        let committed = service
            .claim_unreferenced_oci_upload_cleanup_keys(Some(repo_a.repo_id))
            .await
            .expect("claim scoped committed keys");
        let pending = service
            .claim_pending_oci_upload_cleanup_keys(Some(repo_a.repo_id))
            .await
            .expect("claim scoped pending keys");

        assert!(committed.iter().any(|key| key.storage_key == committed_a));
        assert!(committed.iter().all(|key| key.storage_key != committed_b));
        assert!(pending.iter().any(|key| key.storage_key == pending_a));
        assert!(pending.iter().all(|key| key.storage_key != pending_b));

        let other_claims: (Option<Uuid>, Option<Uuid>) = sqlx::query_as(
            "SELECT \
                 (SELECT claim_token FROM oci_upload_cleanup_keys WHERE storage_key = $1), \
                 (SELECT claim_token FROM oci_upload_cleanup_keys WHERE storage_key = $2)",
        )
        .bind(&committed_b)
        .bind(&pending_b)
        .fetch_one(&repo_a.pool)
        .await
        .expect("read other repository claim state");
        assert_eq!(
            other_claims,
            (None, None),
            "repo B keys must remain entirely unclaimed by repo A's live sweep"
        );

        let _ = sqlx::query(
            "DELETE FROM oci_upload_cleanup_keys \
             WHERE storage_key IN ($1, $2, $3, $4)",
        )
        .bind(&committed_a)
        .bind(&pending_a)
        .bind(&committed_b)
        .bind(&pending_b)
        .execute(&repo_a.pool)
        .await;
        repo_b.teardown().await;
        repo_a.teardown().await;
    }

    /// A batch's tail claim can lapse mid-sweep (slow object-store deletes);
    /// the pre-delete renewal keeps a still-owned key held for the full
    /// batch, and fences a sweeper whose lapsed claim was already re-claimed
    /// by another replica.
    #[tokio::test]
    async fn tail_claim_renewal_keeps_ownership_and_fences_reclaimed_sweeper() {
        use crate::api::handlers::test_db_helpers as tdh;

        // Advisory (cross-process) lock — see
        // cleanup_key_sweep_claim_is_exclusive_and_releasable.
        let _gc_guard = tdh::blob_gc_serial_lock().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let storage_key = format!("oci-uploads/renew-test/{}", Uuid::new_v4());
        sqlx::query(
            "INSERT INTO oci_upload_cleanup_keys \
                 (repository_id, storage_key, created_at, storage_write_completed_at) \
             VALUES ($1, $2, NOW() - INTERVAL '48 hours', NOW() - INTERVAL '48 hours')",
        )
        .bind(fixture.repo_id)
        .bind(&storage_key)
        .execute(&fixture.pool)
        .await
        .expect("insert cleanup key");

        let service =
            StorageGcService::new(fixture.pool.clone(), fixture.state.storage_registry.clone());

        let claimed = service
            .claim_unreferenced_oci_upload_cleanup_keys(None)
            .await
            .expect("claim query ok");
        let mine = claimed
            .into_iter()
            .find(|k| k.storage_key == storage_key)
            .expect("aged committed key must be claimable");

        // A live owner renews: the deadline moves forward and the key stays
        // invisible to concurrent sweepers.
        assert!(
            service
                .tombstone_cleanup_key_for_delete(&mine, CleanupSweepKind::Unreferenced)
                .await,
            "the live owner must be able to renew its claim"
        );
        let contended = service
            .claim_unreferenced_oci_upload_cleanup_keys(None)
            .await
            .expect("claim query ok");
        assert!(
            contended.iter().all(|k| k.storage_key != storage_key),
            "a renewed claim must keep the key invisible to other sweepers"
        );

        // Tail-lapse scenario: the claim expires mid-batch and another
        // replica re-claims the key. The original sweeper's pre-delete
        // renewal must now fail, so it skips the destructive delete.
        sqlx::query(
            "UPDATE oci_upload_cleanup_keys SET claim_expires_at = NOW() - INTERVAL '1 minute' \
             WHERE storage_key = $1",
        )
        .bind(&storage_key)
        .execute(&fixture.pool)
        .await
        .expect("lapse claim");
        let reclaimed = service
            .claim_unreferenced_oci_upload_cleanup_keys(None)
            .await
            .expect("claim query ok");
        assert!(
            reclaimed.iter().any(|k| k.storage_key == storage_key),
            "a lapsed tail claim must be reclaimable by another sweeper"
        );
        assert!(
            !service
                .tombstone_cleanup_key_for_delete(&mine, CleanupSweepKind::Unreferenced)
                .await,
            "a superseded token must not renew (the delete is skipped)"
        );

        let _ = sqlx::query("DELETE FROM oci_upload_cleanup_keys WHERE storage_key = $1")
            .bind(&storage_key)
            .execute(&fixture.pool)
            .await;
        fixture.teardown().await;
    }

    // -----------------------------------------------------------------------
    // #3085: blob liveness must be re-checked immediately before the
    // destructive storage delete, not only at claim time and at the guarded
    // row DELETE that runs *after* the bytes are already gone.
    // -----------------------------------------------------------------------

    /// The pre-delete hook is only a guard if its predicate actually names
    /// the liveness tables. Runs without a database, so the shape is pinned on
    /// every CI run even when the DB-backed sweeps below skip.
    #[test]
    fn cleanup_sweep_liveness_predicates_assert_blob_and_part_liveness() {
        for kind in [CleanupSweepKind::Unreferenced, CleanupSweepKind::Pending] {
            let sql = kind.liveness_predicate_sql();
            assert!(
                sql.contains("FROM oci_blobs b"),
                "{kind:?} pre-delete re-check must refuse a key a committed oci_blobs row                  references (#3085): {sql}"
            );
            assert!(
                sql.contains("FROM oci_upload_parts p"),
                "{kind:?} pre-delete re-check must refuse a key a live upload part                  references: {sql}"
            );
            assert!(
                sql.contains("FROM oci_upload_sessions s"),
                "{kind:?} pre-delete re-check must refuse a key a live upload session                  references: {sql}"
            );
        }
    }

    /// Each sweep's pre-delete re-check must match its own guarded row
    /// `DELETE`: the committed sweep reaps only marked-complete rows, the
    /// pending reaper only never-marked rows. Swapping them would make the
    /// hook reject every key and silently disable the sweep.
    #[test]
    fn cleanup_sweep_liveness_predicates_match_their_sweep_marker() {
        let unreferenced = CleanupSweepKind::Unreferenced.liveness_predicate_sql();
        let pending = CleanupSweepKind::Pending.liveness_predicate_sql();
        assert!(
            unreferenced.contains("storage_write_completed_at IS NOT NULL"),
            "committed sweep re-check must keep its marked-complete guard: {unreferenced}"
        );
        assert!(
            pending.contains("storage_write_completed_at IS NULL"),
            "pending reaper re-check must keep its never-marked guard: {pending}"
        );
        assert!(
            pending.contains("s.id = oci_upload_cleanup_keys.upload_session_id"),
            "pending reaper re-check must also protect a key whose owning session is still              live: {pending}"
        );
        assert_ne!(unreferenced, pending);
    }

    /// Storage backend that records every `delete` and, the first time it is
    /// asked to delete `trip_key`, performs the "concurrent push" that makes
    /// `revive_key` live (commits an `oci_blobs` row for it).
    ///
    /// This reproduces the real production shape deterministically: a claimed
    /// batch walks its storage deletes sequentially, so a push that lands
    /// while an earlier key in the batch is being deleted makes a later key in
    /// the same batch live before the sweep reaches it.
    struct MidBatchPushStorage {
        db: PgPool,
        revive_key: String,
        revive_repo: Uuid,
        revive_digest: String,
        deleted: std::sync::Mutex<Vec<String>>,
        pushed: std::sync::atomic::AtomicBool,
    }

    impl MidBatchPushStorage {
        fn deleted_keys(&self) -> Vec<String> {
            self.deleted.lock().expect("deleted lock").clone()
        }

        /// Did the simulated concurrent push actually commit its `oci_blobs`
        /// row? If it never fired, the sweep reached the revive key first and
        /// the test never entered the window it exists to cover — a false red
        /// rather than a regression, so the tests assert this explicitly.
        fn pushed(&self) -> bool {
            self.pushed.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl crate::storage::StorageBackend for MidBatchPushStorage {
        async fn put(&self, _key: &str, _content: Bytes) -> crate::error::Result<()> {
            Ok(())
        }
        async fn get(&self, _key: &str) -> crate::error::Result<Bytes> {
            Ok(Bytes::new())
        }
        async fn exists(&self, _key: &str) -> crate::error::Result<bool> {
            Ok(true)
        }
        async fn delete(&self, key: &str) -> crate::error::Result<()> {
            // Fire the concurrent push on the FIRST delete that is not the
            // revive key itself, rather than on one specific "head" key.
            //
            // The claim query orders its candidate CTE by `created_at`, but it
            // returns rows from `UPDATE ... RETURNING`, which carries NO row
            // order guarantee — the CTE's ORDER BY does not survive it. The
            // observed order therefore depends on the chosen plan, and it
            // flips once `oci_upload_cleanup_keys` holds rows from other
            // tests. Keying the push off a named head made this test pass in
            // isolation and fail in the full module run.
            let tripped = {
                let mut seen = self.deleted.lock().expect("deleted lock");
                seen.push(key.to_string());
                key != self.revive_key
                    && !self.pushed.swap(true, std::sync::atomic::Ordering::SeqCst)
            };
            if tripped {
                sqlx::query(
                    "INSERT INTO oci_blobs (repository_id, digest, size_bytes, storage_key) \
                     VALUES ($1, $2, 1, $3)",
                )
                .bind(self.revive_repo)
                .bind(&self.revive_digest)
                .bind(&self.revive_key)
                .execute(&self.db)
                .await
                .expect("concurrent push commits its oci_blobs row");
            }
            Ok(())
        }
        async fn put_stream(
            &self,
            key: &str,
            stream: futures::stream::BoxStream<'static, crate::error::Result<bytes::Bytes>>,
        ) -> crate::error::Result<crate::storage::PutStreamResult> {
            crate::storage::buffered_put_stream_fallback(self, key, stream).await
        }
    }

    /// Seed three aged, committed, unreferenced cleanup keys ordered
    /// `trip` -> `revive` -> `control` by `created_at` (the sweep's claim
    /// order), wire a [`MidBatchPushStorage`] in front of them, and return the
    /// service plus the recorder.
    async fn setup_mid_batch_push_sweep(
        fixture: &crate::api::handlers::test_db_helpers::Fixture,
        tag: &str,
    ) -> (StorageGcService, Arc<MidBatchPushStorage>, [String; 3]) {
        // The sweep must resolve through an interceptable backend:
        // `StorageRegistry::backend_for` hardcodes "filesystem" to the real FS.
        set_repo_backend(&fixture.pool, fixture.repo_id, "s3").await;

        let run = Uuid::new_v4().simple().to_string();
        let trip_key = format!("oci-uploads/{tag}-trip/{run}");
        let revive_digest = format!("sha256:{run}{}", "0".repeat(32));
        let revive_key = format!("oci-blobs/{revive_digest}");
        let control_key = format!("oci-uploads/{tag}-control/{run}");

        // `revive` ($3) is seeded NEWEST so that any order-preserving plan puts
        // it last, maximising the chance another key is deleted (and so fires
        // the push) before the sweep reaches it. The tests assert the push
        // actually fired rather than trusting this.
        sqlx::query(
            "INSERT INTO oci_upload_cleanup_keys \
                 (repository_id, storage_key, created_at, storage_write_completed_at) \
             VALUES ($1, $2, NOW() - INTERVAL '72 hours', NOW() - INTERVAL '72 hours'), \
                    ($1, $3, NOW() - INTERVAL '70 hours', NOW() - INTERVAL '70 hours'), \
                    ($1, $4, NOW() - INTERVAL '71 hours', NOW() - INTERVAL '71 hours')",
        )
        .bind(fixture.repo_id)
        .bind(&trip_key)
        .bind(&revive_key)
        .bind(&control_key)
        .execute(&fixture.pool)
        .await
        .expect("seed cleanup keys");

        let storage = Arc::new(MidBatchPushStorage {
            db: fixture.pool.clone(),
            revive_key: revive_key.clone(),
            revive_repo: fixture.repo_id,
            revive_digest,
            deleted: std::sync::Mutex::new(Vec::new()),
            pushed: std::sync::atomic::AtomicBool::new(false),
        });
        let mut backends = std::collections::HashMap::new();
        backends.insert(
            "s3".to_string(),
            storage.clone() as Arc<dyn crate::storage::StorageBackend>,
        );
        let registry = Arc::new(crate::storage::StorageRegistry::new(
            backends,
            "s3".to_string(),
        ));
        let service = StorageGcService::new(fixture.pool.clone(), registry);
        (service, storage, [trip_key, revive_key, control_key])
    }

    /// Collect what the sweep actually deleted, then drop everything the
    /// fixture seeded (including the "concurrent push" `oci_blobs` row, which
    /// outlives the journal rows) and tear the repository down.
    async fn finish_mid_batch_push_sweep(
        fixture: &crate::api::handlers::test_db_helpers::Fixture,
        storage: &MidBatchPushStorage,
        keys: &[String; 3],
    ) -> Vec<String> {
        let deleted = storage.deleted_keys();
        let _ = sqlx::query("DELETE FROM oci_upload_cleanup_keys WHERE storage_key = ANY($1)")
            .bind(&keys[..])
            .execute(&fixture.pool)
            .await;
        let _ = sqlx::query("DELETE FROM oci_blobs WHERE storage_key = $1")
            .bind(&keys[1])
            .execute(&fixture.pool)
            .await;
        fixture.teardown().await;
        deleted
    }

    /// #3085 regression: a digest that is re-pushed after the sweep claimed
    /// its journal row is LIVE. The sweep re-checks liveness when it claims
    /// the key and again at the guarded row `DELETE`, but the row `DELETE`
    /// runs *after* the storage object is already gone — so without a
    /// re-check in the pre-delete hook the live blob loses its bytes.
    ///
    /// The `control` key in the same batch is never revived and MUST still be
    /// swept, so the guard cannot pass by simply refusing to delete anything.
    #[tokio::test]
    async fn unreferenced_sweep_keeps_bytes_of_blob_that_went_live_after_claim() {
        use crate::api::handlers::test_db_helpers as tdh;

        // BOTH guards are required, and they are not interchangeable.
        //
        // `storage_gc_test_guard` is an in-process mutex; `blob_gc_serial_lock`
        // is a Postgres advisory lock. This test runs an UNSCOPED
        // (`repo_scope = None`) cleanup-key sweep, exactly like the sibling
        // `test_run_gc_*` tests, which take only the in-process mutex. Holding
        // just the advisory lock does not exclude them, so under the single-
        // process `cargo test --workspace --lib` job a sibling's cluster-wide
        // sweep reaps this test's fixtures first and `deleted` comes back
        // empty. (Under nextest the `db-serial` group already serializes the
        // module, which is why that run stayed green and hid this.)
        let _sweep_guard = storage_gc_test_guard().await;
        let _gc_guard = tdh::blob_gc_serial_lock().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let (service, storage, keys) = setup_mid_batch_push_sweep(&fixture, "gc3085u").await;
        let [trip_key, revive_key, control_key] = keys.clone();

        // Scope the sweep to this fixture's repository. The sweep is otherwise
        // cluster-wide, so rows other tests left in `oci_upload_cleanup_keys`
        // join the batch and change both its size and its walk order. The
        // pre-delete hook under test is per-key and identical either way.
        let mut result = empty_gc_result(false);
        service
            .cleanup_unreferenced_oci_upload_keys(Some(fixture.repo_id), false, &mut result)
            .await
            .expect("unreferenced cleanup-key sweep runs");

        let pushed = storage.pushed();
        let deleted = finish_mid_batch_push_sweep(&fixture, &storage, &keys).await;

        assert!(
            pushed,
            "precondition: the concurrent push must fire before the sweep reaches the revive \
             key, otherwise this test never enters the window it covers: {deleted:?}"
        );
        assert!(
            deleted.contains(&trip_key),
            "a still-unreferenced key must be swept (one of these drives the concurrent \
             push): {deleted:?}"
        );
        assert!(
            deleted.contains(&control_key),
            "positive control: a still-unreferenced key must still be swept, otherwise the \
             liveness guard could pass by never deleting anything: {deleted:?}"
        );
        assert!(
            !deleted.contains(&revive_key),
            "#3085: blob liveness must be re-checked immediately before the storage delete. \
             An oci_blobs row committed after the claim makes the blob live, so its bytes \
             must survive the sweep: {deleted:?}"
        );
    }

    /// Same window on the pending (NULL-marked) reaper, which shares the
    /// pre-delete hook.
    #[tokio::test]
    async fn pending_reaper_keeps_bytes_of_blob_that_went_live_after_claim() {
        use crate::api::handlers::test_db_helpers as tdh;

        // See the note on the unreferenced-sweep test above: the in-process
        // mutex is what excludes the sibling `test_run_gc_*` cluster-wide
        // sweeps under `cargo test --workspace --lib`. The advisory lock alone
        // does not.
        let _sweep_guard = storage_gc_test_guard().await;
        let _gc_guard = tdh::blob_gc_serial_lock().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let (service, storage, keys) = setup_mid_batch_push_sweep(&fixture, "gc3085p").await;
        let [trip_key, revive_key, control_key] = keys.clone();
        // The pending reaper only sees rows whose storage write was never
        // marked complete.
        sqlx::query(
            "UPDATE oci_upload_cleanup_keys SET storage_write_completed_at = NULL \
             WHERE storage_key = ANY($1)",
        )
        .bind(&keys[..])
        .execute(&fixture.pool)
        .await
        .expect("un-mark the seeded rows");

        // Repo-scoped for the same reason as the unreferenced-sweep test above.
        let mut result = empty_gc_result(false);
        service
            .reap_pending_oci_upload_cleanup_keys(Some(fixture.repo_id), false, &mut result)
            .await
            .expect("pending cleanup-key reaper runs");

        let pushed = storage.pushed();
        let deleted = finish_mid_batch_push_sweep(&fixture, &storage, &keys).await;

        assert!(
            pushed,
            "precondition: the concurrent push must fire before the reaper reaches the revive \
             key, otherwise this test never enters the window it covers: {deleted:?}"
        );
        assert!(
            deleted.contains(&trip_key),
            "a still-unreferenced pending key must be reaped (one of these drives the \
             concurrent push): {deleted:?}"
        );
        assert!(
            deleted.contains(&control_key),
            "positive control: a still-unreferenced pending key must still be reaped: {deleted:?}"
        );
        assert!(
            !deleted.contains(&revive_key),
            "#3085: the pending reaper shares the pre-delete hook and must also refuse to \
             delete the bytes of a blob that went live after the claim: {deleted:?}"
        );
    }

    // -----------------------------------------------------------------------
    // #3187: closing the pre-delete window #3158 only narrowed.
    //
    // The tests above cover the POST-CLAIM gap: a push landing after the batch
    // was claimed but before the sweep reached that key, which the #3158
    // per-key liveness re-check already refuses. They deliberately do NOT
    // cover the residual window, which is what these tests exist for: the gap
    // between the sweep's pre-delete hook returning `true` and its
    // `storage.delete()` completing. In #3158 the hook held no lock there, so
    // a push committing an `oci_blobs` row inside that gap still lost its
    // bytes and nothing could observe it.
    //
    // Proving a TOCTOU closure needs a seam at the exact instant of the race,
    // not a sequence of calls. Two seams are used:
    //
    //   * `PreDeleteWindowStorage` runs the real push-side protocol INSIDE the
    //     sweep's own `storage.delete()` await for the very key being deleted.
    //     That is, by construction, the post-hold/pre-delete window.
    //   * `cleanup_key_tombstone_blocks_while_a_push_holds_the_journal_row`
    //     drives the opposite order with two live connections and proves the
    //     sweep's phase 1 genuinely BLOCKS on the push's row lock — the
    //     mutual exclusion #3158's autocommit `UPDATE` did not have.
    // -----------------------------------------------------------------------

    /// What the simulated push did when it ran inside the sweep's storage
    /// delete. `None` means the seam never fired.
    type PushOutcome = std::sync::Mutex<Option<CleanupJournalClaim>>;

    /// Storage backend that, while deleting `target_key`, runs the **real**
    /// push-side commit protocol
    /// ([`claim_cleanup_journal_row_for_blob_commit`]) on its own connection
    /// and, if that protocol permits it, commits the `oci_blobs` row exactly
    /// as a real push would.
    ///
    /// The push therefore executes strictly after the sweep's phase-1 hook
    /// returned `true` and strictly before the object is gone — the window
    /// #3158 left open. Committing the `oci_blobs` row for real (rather than
    /// just recording a verdict) is what makes the test revert-sensitive: with
    /// the tombstone removed from phase 1, the guard returns `Cleared`, the
    /// row lands, and the invariant assertion below fails on live bytes being
    /// deleted.
    struct PreDeleteWindowStorage {
        db: PgPool,
        target_key: String,
        target_journal_id: i64,
        target_repo: Uuid,
        target_digest: String,
        deleted: std::sync::Mutex<Vec<String>>,
        outcome: PushOutcome,
    }

    impl PreDeleteWindowStorage {
        fn deleted_keys(&self) -> Vec<String> {
            self.deleted.lock().expect("deleted lock").clone()
        }
        fn outcome(&self) -> Option<CleanupJournalClaim> {
            *self.outcome.lock().expect("outcome lock")
        }
    }

    #[async_trait]
    impl crate::storage::StorageBackend for PreDeleteWindowStorage {
        async fn put(&self, _key: &str, _content: Bytes) -> crate::error::Result<()> {
            Ok(())
        }
        async fn get(&self, _key: &str) -> crate::error::Result<Bytes> {
            Ok(Bytes::new())
        }
        async fn exists(&self, _key: &str) -> crate::error::Result<bool> {
            Ok(true)
        }
        async fn delete(&self, key: &str) -> crate::error::Result<()> {
            let fire = {
                let mut seen = self.deleted.lock().expect("deleted lock");
                seen.push(key.to_string());
                key == self.target_key
            };
            if fire {
                // The push runs on its own connection, as it does in
                // production: this is a different request, not the sweep.
                let mut tx = self.db.begin().await.expect("push begins its transaction");
                let claim = claim_cleanup_journal_row_for_blob_commit(
                    &mut tx,
                    self.target_journal_id,
                    self.target_repo,
                    &self.target_key,
                )
                .await
                .expect("push runs the cleanup-journal guard");
                match claim {
                    CleanupJournalClaim::Cleared => {
                        // The protocol said it was safe to publish the blob.
                        sqlx::query(
                            "INSERT INTO oci_blobs (repository_id, digest, size_bytes, \
                             storage_key) VALUES ($1, $2, 1, $3) \
                             ON CONFLICT (repository_id, digest) DO NOTHING",
                        )
                        .bind(self.target_repo)
                        .bind(&self.target_digest)
                        .bind(&self.target_key)
                        .execute(&mut *tx)
                        .await
                        .expect("push commits its oci_blobs row");
                        tx.commit().await.expect("push commits");
                    }
                    CleanupJournalClaim::Doomed => {
                        // The protocol refused. A real push returns a
                        // retryable 503 here and publishes nothing.
                        tx.rollback().await.expect("push rolls back");
                    }
                }
                *self.outcome.lock().expect("outcome lock") = Some(claim);
            }
            Ok(())
        }
        async fn put_stream(
            &self,
            key: &str,
            stream: futures::stream::BoxStream<'static, crate::error::Result<bytes::Bytes>>,
        ) -> crate::error::Result<crate::storage::PutStreamResult> {
            crate::storage::buffered_put_stream_fallback(self, key, stream).await
        }
    }

    /// Seed one aged, unreferenced blob-key journal row plus a control key,
    /// and wire a [`PreDeleteWindowStorage`] that races the blob key.
    async fn setup_pre_delete_window_sweep(
        fixture: &crate::api::handlers::test_db_helpers::Fixture,
        tag: &str,
        marked_complete: bool,
    ) -> (StorageGcService, Arc<PreDeleteWindowStorage>, [String; 2]) {
        set_repo_backend(&fixture.pool, fixture.repo_id, "s3").await;

        let run = Uuid::new_v4().simple().to_string();
        let digest = format!("sha256:{run}{}", "0".repeat(32));
        let blob_key = format!("oci-blobs/{digest}");
        let control_key = format!("oci-uploads/{tag}-control/{run}");
        let marker = if marked_complete {
            "NOW() - INTERVAL '72 hours'"
        } else {
            "NULL"
        };

        let journal_id: i64 = sqlx::query(&format!(
            "INSERT INTO oci_upload_cleanup_keys \
                 (repository_id, storage_key, created_at, storage_write_completed_at) \
             VALUES ($1, $2, NOW() - INTERVAL '72 hours', {marker}) RETURNING id"
        ))
        .bind(fixture.repo_id)
        .bind(&blob_key)
        .fetch_one(&fixture.pool)
        .await
        .expect("seed blob cleanup key")
        .try_get("id")
        .expect("journal id");

        sqlx::query(&format!(
            "INSERT INTO oci_upload_cleanup_keys \
                 (repository_id, storage_key, created_at, storage_write_completed_at) \
             VALUES ($1, $2, NOW() - INTERVAL '71 hours', {marker})"
        ))
        .bind(fixture.repo_id)
        .bind(&control_key)
        .execute(&fixture.pool)
        .await
        .expect("seed control cleanup key");

        let storage = Arc::new(PreDeleteWindowStorage {
            db: fixture.pool.clone(),
            target_key: blob_key.clone(),
            target_journal_id: journal_id,
            target_repo: fixture.repo_id,
            target_digest: digest,
            deleted: std::sync::Mutex::new(Vec::new()),
            outcome: std::sync::Mutex::new(None),
        });
        let mut backends = std::collections::HashMap::new();
        backends.insert(
            "s3".to_string(),
            storage.clone() as Arc<dyn crate::storage::StorageBackend>,
        );
        let registry = Arc::new(crate::storage::StorageRegistry::new(
            backends,
            "s3".to_string(),
        ));
        let service = StorageGcService::new(fixture.pool.clone(), registry);
        (service, storage, [blob_key, control_key])
    }

    /// Is there a live `oci_blobs` row for this storage key?
    async fn blob_row_exists(pool: &PgPool, storage_key: &str) -> bool {
        sqlx::query("SELECT 1 AS present FROM oci_blobs WHERE storage_key = $1")
            .bind(storage_key)
            .fetch_optional(pool)
            .await
            .expect("query oci_blobs")
            .is_some()
    }

    async fn cleanup_pre_delete_window(
        fixture: &crate::api::handlers::test_db_helpers::Fixture,
        keys: &[String; 2],
    ) {
        let _ = sqlx::query("DELETE FROM oci_upload_cleanup_keys WHERE storage_key = ANY($1)")
            .bind(&keys[..])
            .execute(&fixture.pool)
            .await;
        let _ = sqlx::query("DELETE FROM oci_blobs WHERE storage_key = $1")
            .bind(&keys[0])
            .execute(&fixture.pool)
            .await;
        fixture.teardown().await;
    }

    /// #3187, the window itself: a push that commits **inside** the sweep's
    /// `storage.delete()` await for the very key being deleted.
    ///
    /// This is the interleaving #3158 explicitly could not cover. The sweep's
    /// phase-1 hook has already returned `true`, so under #3158 nothing at all
    /// stood between the push and a live `oci_blobs` row pointing at bytes the
    /// next instruction destroys.
    ///
    /// The invariant asserted is the one that actually matters, and it is
    /// symmetric: the registry must never end up with BOTH the object deleted
    /// AND a row referencing it. Either outcome alone is fine — a refused push
    /// is a retry, a survived blob is a skipped sweep.
    #[tokio::test]
    async fn unreferenced_sweep_refuses_a_push_landing_in_the_pre_delete_window() {
        use crate::api::handlers::test_db_helpers as tdh;

        // Both guards, for the reasons documented on the #3085 tests above:
        // the in-process mutex excludes the sibling cluster-wide sweeps, the
        // advisory lock excludes other processes under nextest.
        let _sweep_guard = storage_gc_test_guard().await;
        let _gc_guard = tdh::blob_gc_serial_lock().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let (service, storage, keys) =
            setup_pre_delete_window_sweep(&fixture, "gc3187u", true).await;
        let [blob_key, control_key] = keys.clone();

        let mut result = empty_gc_result(false);
        service
            .cleanup_unreferenced_oci_upload_keys(Some(fixture.repo_id), false, &mut result)
            .await
            .expect("unreferenced cleanup-key sweep runs");

        let outcome = storage.outcome();
        let deleted = storage.deleted_keys();
        let row_live = blob_row_exists(&fixture.pool, &blob_key).await;
        cleanup_pre_delete_window(&fixture, &keys).await;

        // Precondition first: if the seam never fired, the test entered no
        // window at all and every assertion below would pass vacuously.
        assert!(
            outcome.is_some(),
            "precondition: the simulated push must run inside the sweep's storage delete for \
             this key, otherwise this test proves nothing. deleted={deleted:?}"
        );
        // THE claim. Not "the push was refused" — that is one way to satisfy
        // it. The registry must simply never end up with the object deleted
        // AND a row still pointing at it.
        assert!(
            !(deleted.contains(&blob_key) && row_live),
            "#3187 data loss: the sweep deleted {blob_key} AND an oci_blobs row references it. \
             A push landing in the post-hold, pre-storage-delete window must never produce \
             both. outcome={outcome:?} deleted={deleted:?}"
        );
        // And the mechanism that delivered it, so a future change that
        // satisfies the invariant by accident is still visible here.
        assert_eq!(
            outcome,
            Some(CleanupJournalClaim::Doomed),
            "the two-phase tombstone must be what refused the push. `Cleared` means the push \
             was allowed to publish a blob whose bytes are being destroyed. deleted={deleted:?}"
        );
        assert!(
            !row_live,
            "a push the protocol refused must not leave an oci_blobs row behind"
        );
        assert!(
            deleted.contains(&control_key),
            "positive control: a genuinely unreferenced key must still be swept, otherwise \
             the guard could pass by never deleting anything: {deleted:?}"
        );
    }

    /// Same window on the pending (NULL-marked) reaper, which shares phase 1.
    #[tokio::test]
    async fn pending_reaper_refuses_a_push_landing_in_the_pre_delete_window() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _sweep_guard = storage_gc_test_guard().await;
        let _gc_guard = tdh::blob_gc_serial_lock().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let (service, storage, keys) =
            setup_pre_delete_window_sweep(&fixture, "gc3187p", false).await;
        let [blob_key, control_key] = keys.clone();

        let mut result = empty_gc_result(false);
        service
            .reap_pending_oci_upload_cleanup_keys(Some(fixture.repo_id), false, &mut result)
            .await
            .expect("pending cleanup-key reaper runs");

        let outcome = storage.outcome();
        let deleted = storage.deleted_keys();
        let row_live = blob_row_exists(&fixture.pool, &blob_key).await;
        cleanup_pre_delete_window(&fixture, &keys).await;

        assert!(
            outcome.is_some(),
            "precondition: the simulated push must run inside the reaper's storage delete for \
             this key. deleted={deleted:?}"
        );
        assert!(
            !(deleted.contains(&blob_key) && row_live),
            "#3187 data loss via the pending reaper: {blob_key} deleted AND referenced. \
             outcome={outcome:?} deleted={deleted:?}"
        );
        assert_eq!(
            outcome,
            Some(CleanupJournalClaim::Doomed),
            "the pending reaper shares phase 1, so a push landing inside its storage delete \
             must be refused the same way. deleted={deleted:?}"
        );
        assert!(
            deleted.contains(&control_key),
            "positive control: a genuinely unreferenced pending key must still be reaped: \
             {deleted:?}"
        );
    }

    /// #3187, the other order: the **push** reaches the journal row first.
    ///
    /// This is the half a sequential test cannot fake, and the half #3158's
    /// autocommit `UPDATE` did not have. Two live connections: the push holds
    /// `SELECT ... FOR UPDATE` on the journal row inside an open transaction,
    /// and the sweep's phase-1 tombstone `UPDATE` must **block** on it rather
    /// than sail past and go on to delete the object.
    ///
    /// The blocking assertion is one-sided in the safe direction: Postgres
    /// cannot grant two conflicting row locks, so this cannot pass by timing
    /// luck. It can only fail if phase 1 stopped taking the row lock at all.
    #[tokio::test]
    async fn cleanup_key_tombstone_blocks_while_a_push_holds_the_journal_row() {
        use crate::api::handlers::test_db_helpers as tdh;
        use std::time::Duration;

        let _sweep_guard = storage_gc_test_guard().await;
        let _gc_guard = tdh::blob_gc_serial_lock().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let run = Uuid::new_v4().simple().to_string();
        let digest = format!("sha256:{run}{}", "0".repeat(32));
        let blob_key = format!("oci-blobs/{digest}");
        let claim_token = Uuid::new_v4();
        let journal_id: i64 = sqlx::query(
            "INSERT INTO oci_upload_cleanup_keys \
                 (repository_id, storage_key, created_at, storage_write_completed_at, \
                  claim_token, claim_expires_at) \
             VALUES ($1, $2, NOW() - INTERVAL '72 hours', NOW() - INTERVAL '72 hours', \
                     $3, NOW() + INTERVAL '15 minutes') RETURNING id",
        )
        .bind(fixture.repo_id)
        .bind(&blob_key)
        .bind(claim_token)
        .fetch_one(&fixture.pool)
        .await
        .expect("seed claimed blob cleanup key")
        .try_get("id")
        .expect("journal id");

        let cleanup_key = OciUploadCleanupKey {
            id: journal_id,
            location: StorageLocation {
                backend: "s3".to_string(),
                path: String::new(),
            },
            storage_key: blob_key.clone(),
            claim_token: Some(claim_token),
        };
        let service = StorageGcService::new(
            fixture.pool.clone(),
            Arc::new(crate::storage::StorageRegistry::new(
                std::collections::HashMap::new(),
                "s3".to_string(),
            )),
        );

        // The push gets there first and holds the row lock in an open
        // transaction, exactly as it does around its `oci_blobs` INSERT.
        let mut push_tx = fixture.pool.begin().await.expect("push begins");
        let claim = claim_cleanup_journal_row_for_blob_commit(
            &mut push_tx,
            journal_id,
            fixture.repo_id,
            &blob_key,
        )
        .await
        .expect("push runs the cleanup-journal guard");
        assert_eq!(
            claim,
            CleanupJournalClaim::Cleared,
            "no sweep has tombstoned this key yet, so the push must be allowed to proceed"
        );

        // Phase 1 must not be able to make progress while that transaction is
        // open. `timeout` returning Err is the proof: the future is parked on
        // the row lock.
        let tombstone =
            service.tombstone_cleanup_key_for_delete(&cleanup_key, CleanupSweepKind::Unreferenced);
        tokio::pin!(tombstone);
        let blocked = tokio::time::timeout(Duration::from_millis(750), &mut tombstone).await;
        assert!(
            blocked.is_err(),
            "#3187: the sweep's phase-1 tombstone must BLOCK on the journal row lock a \
             committing push holds. It completed instead, which means the push and the \
             sweep no longer serialize and the sweep would go on to delete live bytes."
        );

        // Release: the push commits its journal-row delete (in production, in
        // the same transaction as the `oci_blobs` INSERT).
        push_tx.commit().await.expect("push commits");

        let held = tombstone.await;
        assert!(
            !held,
            "once the push committed, the journal row is gone, so phase 1 must match zero \
             rows and report `false` — the caller then skips the storage delete and the \
             pushed bytes survive"
        );

        let _ = sqlx::query("DELETE FROM oci_upload_cleanup_keys WHERE id = $1")
            .bind(journal_id)
            .execute(&fixture.pool)
            .await;
        fixture.teardown().await;
    }

    /// A tombstone left by a sweep that crashed must not doom the digest
    /// forever: it lapses with the claim lease, and a later push proceeds.
    #[tokio::test]
    async fn expired_cleanup_key_tombstone_does_not_block_a_push() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _sweep_guard = storage_gc_test_guard().await;
        let _gc_guard = tdh::blob_gc_serial_lock().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let run = Uuid::new_v4().simple().to_string();
        let blob_key = format!("oci-blobs/sha256:{run}{}", "0".repeat(32));
        let journal_id: i64 = sqlx::query(
            "INSERT INTO oci_upload_cleanup_keys \
                 (repository_id, storage_key, storage_write_completed_at, \
                  claim_token, claim_expires_at, pending_delete_at) \
             VALUES ($1, $2, NOW(), $3, NOW() - INTERVAL '1 hour', NOW() - INTERVAL '1 hour') \
             RETURNING id",
        )
        .bind(fixture.repo_id)
        .bind(&blob_key)
        .bind(Uuid::new_v4())
        .fetch_one(&fixture.pool)
        .await
        .expect("seed stranded tombstone")
        .try_get("id")
        .expect("journal id");

        let mut tx = fixture.pool.begin().await.expect("push begins");
        let claim = claim_cleanup_journal_row_for_blob_commit(
            &mut tx,
            journal_id,
            fixture.repo_id,
            &blob_key,
        )
        .await
        .expect("push runs the cleanup-journal guard");
        tx.commit().await.expect("push commits");

        let _ = sqlx::query("DELETE FROM oci_upload_cleanup_keys WHERE id = $1")
            .bind(journal_id)
            .execute(&fixture.pool)
            .await;
        fixture.teardown().await;

        assert_eq!(
            claim,
            CleanupJournalClaim::Cleared,
            "a tombstone whose claim lease has lapsed belongs to a crashed sweep and must \
             not block the push — otherwise one crash strands that digest permanently"
        );
    }

    /// A push whose journal row a sweep already reaped must NOT be allowed to
    /// publish an `oci_blobs` row: the reap only happens after the object was
    /// deleted, so those bytes are gone.
    #[tokio::test]
    async fn push_whose_journal_row_was_reaped_is_refused() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _sweep_guard = storage_gc_test_guard().await;
        let _gc_guard = tdh::blob_gc_serial_lock().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let run = Uuid::new_v4().simple().to_string();
        let blob_key = format!("oci-blobs/sha256:{run}{}", "0".repeat(32));
        let journal_id: i64 = sqlx::query(
            "INSERT INTO oci_upload_cleanup_keys (repository_id, storage_key) \
             VALUES ($1, $2) RETURNING id",
        )
        .bind(fixture.repo_id)
        .bind(&blob_key)
        .fetch_one(&fixture.pool)
        .await
        .expect("seed journal row")
        .try_get("id")
        .expect("journal id");

        // The sweep completes: object deleted, row reaped.
        sqlx::query("DELETE FROM oci_upload_cleanup_keys WHERE id = $1")
            .bind(journal_id)
            .execute(&fixture.pool)
            .await
            .expect("sweep reaps the row");

        let mut tx = fixture.pool.begin().await.expect("push begins");
        let claim = claim_cleanup_journal_row_for_blob_commit(
            &mut tx,
            journal_id,
            fixture.repo_id,
            &blob_key,
        )
        .await
        .expect("push runs the cleanup-journal guard");
        tx.rollback().await.expect("push rolls back");
        fixture.teardown().await;

        assert_eq!(
            claim,
            CleanupJournalClaim::Doomed,
            "the journal row this push registered is gone and no oci_blobs row references \
             the key, so a sweep reaped it after deleting the object. Treating a missing \
             row as `Cleared` would publish a blob whose bytes no longer exist."
        );
    }

    /// The counterpart to the test above: a journal row that vanished because
    /// its **repository** was deleted (`ON DELETE CASCADE`) was not reaped by a
    /// sweep, and must not be reported as one.
    ///
    /// Absence of the row is not by itself evidence of GC. Conflating the two
    /// makes an unrelated failure — a push racing a repository deletion, whose
    /// `oci_blobs` INSERT is about to fail on its foreign key — surface as a
    /// misleading "storage was being reclaimed concurrently; retry" that no
    /// retry can fix.
    #[tokio::test]
    async fn push_whose_repository_was_deleted_is_not_blamed_on_gc() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _sweep_guard = storage_gc_test_guard().await;
        let _gc_guard = tdh::blob_gc_serial_lock().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        let run = Uuid::new_v4().simple().to_string();
        let blob_key = format!("oci-blobs/sha256:{run}{}", "0".repeat(32));
        let journal_id: i64 = sqlx::query(
            "INSERT INTO oci_upload_cleanup_keys (repository_id, storage_key) \
             VALUES ($1, $2) RETURNING id",
        )
        .bind(fixture.repo_id)
        .bind(&blob_key)
        .fetch_one(&fixture.pool)
        .await
        .expect("seed journal row")
        .try_get("id")
        .expect("journal id");
        let repo_id = fixture.repo_id;

        // The repository goes away mid-push; the journal row cascades with it.
        // `teardown` deletes the repository, so run it before the guard.
        fixture.teardown().await;

        let mut tx = fixture.pool.begin().await.expect("push begins");
        let claim =
            claim_cleanup_journal_row_for_blob_commit(&mut tx, journal_id, repo_id, &blob_key)
                .await
                .expect("push runs the cleanup-journal guard");
        tx.rollback().await.expect("push rolls back");

        assert_eq!(
            claim,
            CleanupJournalClaim::Cleared,
            "the repository is gone, so no sweep reaped this row and there are no bytes to \
             protect. The caller's oci_blobs INSERT will fail on its foreign key and report \
             that accurately, instead of this guard inventing a concurrent-GC diagnosis."
        );
    }

    /// The acceptance criterion the issue calls out separately: a reap that
    /// matches zero rows must be REPORTED, not banked as a success.
    ///
    /// Before #3187 the sweeps incremented `cleanup_rows_removed` and
    /// `storage_keys_deleted` unconditionally, so the exact interleaving where
    /// a push won left no journal row and no error — the data loss was
    /// invisible. Here the seam removes the journal row during the storage
    /// delete, reproducing what the old unguarded
    /// `clear_oci_upload_cleanup_key_best_effort` did.
    #[tokio::test]
    async fn sweep_reports_a_zero_row_reap_instead_of_counting_it_as_a_success() {
        use crate::api::handlers::test_db_helpers as tdh;

        let _sweep_guard = storage_gc_test_guard().await;
        let _gc_guard = tdh::blob_gc_serial_lock().await;
        let Some(fixture) = tdh::Fixture::setup("local", "docker").await else {
            return;
        };

        /// Deletes the journal row out from under the sweep, mid storage
        /// delete — the old push behaviour this fix removed.
        struct RowStealingStorage {
            db: PgPool,
            journal_id: i64,
        }

        #[async_trait]
        impl crate::storage::StorageBackend for RowStealingStorage {
            async fn put(&self, _key: &str, _content: Bytes) -> crate::error::Result<()> {
                Ok(())
            }
            async fn get(&self, _key: &str) -> crate::error::Result<Bytes> {
                Ok(Bytes::new())
            }
            async fn exists(&self, _key: &str) -> crate::error::Result<bool> {
                Ok(true)
            }
            async fn delete(&self, _key: &str) -> crate::error::Result<()> {
                sqlx::query("DELETE FROM oci_upload_cleanup_keys WHERE id = $1")
                    .bind(self.journal_id)
                    .execute(&self.db)
                    .await
                    .expect("steal the journal row");
                Ok(())
            }
            async fn put_stream(
                &self,
                key: &str,
                stream: futures::stream::BoxStream<'static, crate::error::Result<bytes::Bytes>>,
            ) -> crate::error::Result<crate::storage::PutStreamResult> {
                crate::storage::buffered_put_stream_fallback(self, key, stream).await
            }
        }

        set_repo_backend(&fixture.pool, fixture.repo_id, "s3").await;
        let run = Uuid::new_v4().simple().to_string();
        let blob_key = format!("oci-blobs/sha256:{run}{}", "0".repeat(32));
        let journal_id: i64 = sqlx::query(
            "INSERT INTO oci_upload_cleanup_keys \
                 (repository_id, storage_key, created_at, storage_write_completed_at) \
             VALUES ($1, $2, NOW() - INTERVAL '72 hours', NOW() - INTERVAL '72 hours') \
             RETURNING id",
        )
        .bind(fixture.repo_id)
        .bind(&blob_key)
        .fetch_one(&fixture.pool)
        .await
        .expect("seed journal row")
        .try_get("id")
        .expect("journal id");

        let mut backends = std::collections::HashMap::new();
        backends.insert(
            "s3".to_string(),
            Arc::new(RowStealingStorage {
                db: fixture.pool.clone(),
                journal_id,
            }) as Arc<dyn crate::storage::StorageBackend>,
        );
        let service = StorageGcService::new(
            fixture.pool.clone(),
            Arc::new(crate::storage::StorageRegistry::new(
                backends,
                "s3".to_string(),
            )),
        );

        let mut result = empty_gc_result(false);
        service
            .cleanup_unreferenced_oci_upload_keys(Some(fixture.repo_id), false, &mut result)
            .await
            .expect("unreferenced cleanup-key sweep runs");

        let _ = sqlx::query("DELETE FROM oci_upload_cleanup_keys WHERE storage_key = $1")
            .bind(&blob_key)
            .execute(&fixture.pool)
            .await;
        fixture.teardown().await;

        assert_eq!(
            result.storage_keys_deleted, 0,
            "#3187: a reap that matched zero rows must not be counted as a swept key — \
             counting it unconditionally is exactly what made a lost race invisible"
        );
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("reap OCI upload cleanup-key row")),
            "#3187: a zero-row reap must be reported as an error so the operator can see \
             the object was deleted but its journal row was not: {:?}",
            result.errors
        );
    }
}
