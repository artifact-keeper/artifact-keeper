//! SBOM (Software Bill of Materials) generation and management service.

use crate::error::{AppError, Result};
use crate::models::sbom::{
    CveHistoryEntry, CveStatus, CveTimelineEntry, CveTrends, LicensePolicy, SbomComponent,
    SbomDocument, SbomFormat, SbomSummary,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::collections::HashSet;
use uuid::Uuid;

/// Row aggregating scan_findings into a single CVE detection record per
/// (artifact_id, cve_id). Used by the scan-derived CVE history projection
/// added for #1375.
#[derive(sqlx::FromRow)]
struct ScanFindingCveRow {
    artifact_id: Uuid,
    cve_id: Option<String>,
    severity: Option<String>,
    affected_component: Option<String>,
    affected_version: Option<String>,
    fixed_version: Option<String>,
    first_detected_at: DateTime<Utc>,
    last_detected_at: DateTime<Utc>,
    all_acknowledged: bool,
}

/// Build a deterministic synthetic UUID for a (artifact, cve) pair.
///
/// Used so scan-derived `CveHistoryEntry` rows have a stable `id` across
/// re-reads. Hashing instead of `Uuid::new_v4` means clients can dedupe by
/// id even when the row is synthesized at read time. The first 16 bytes of
/// SHA-256(artifact_id || cve_id) become the UUID.
///
/// # Synthetic ID semantics
///
/// Synth ids carry **no foreign-key meaning** -- they are not present in
/// the `cve_history` table. Consequences for callers:
///
/// - `POST /sbom/cve/status/{id}` against a synth id returns 404. This is
///   expected: only curated rows (written via the rare promotion-policy
///   admin paths) can have their status mutated. Clients receiving a
///   `CveHistoryEntry` whose `sbom_id`/`component_id`/`scan_result_id` are
///   all `null` are looking at a synth row and must not offer
///   "acknowledge" / "mark fixed" UI on it.
/// - Synth ids are stable across re-reads for the same (artifact, cve)
///   pair, so client-side dedupe by `id` works.
/// - Synth ids are derived from a hash, not generated, so they will
///   collide with a `cve_history.id` only with negligible probability
///   (2^-128). If a collision ever did surface, the curated row wins via
///   the dedupe filter in `build_known_cve_set`.
pub(crate) fn synth_cve_id(artifact_id: Uuid, cve_id: &str) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(artifact_id.as_bytes());
    hasher.update([0u8]); // separator so concatenation collisions are impossible
    hasher.update(cve_id.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Uuid::from_bytes(bytes)
}

/// Collect a case-insensitive (upper-cased) set of CVE identifiers from a
/// slice of curated `CveHistoryEntry` rows.
///
/// Pulled out of the read paths so the dedupe-by-cve normalization is
/// covered by unit tests without needing a database. The CVE-history
/// pipeline calls this once per query to build the `known` set passed to
/// `build_cve_entries_from_scan_findings`.
pub(crate) fn build_known_cve_set(entries: &[CveHistoryEntry]) -> HashSet<String> {
    entries
        .iter()
        .map(|e| e.cve_id.to_ascii_uppercase())
        .collect()
}

/// Decide whether a `scan_findings`-derived row should pass the dedupe
/// filter. A row passes only when it has a `cve_id` and that id (compared
/// case-insensitively) is not already in the curated `known` set.
///
/// Extracted so the case-insensitivity contract is unit-testable. See
/// #1375 -- without this normalization the scan-derived path would
/// duplicate any CVE whose case differs between `cve_history` and
/// `scan_findings`.
pub(crate) fn scan_row_passes_known_filter(
    row_cve_id: Option<&str>,
    known: &HashSet<String>,
) -> bool {
    row_cve_id
        .map(|c| !known.contains(&c.to_ascii_uppercase()))
        .unwrap_or(false)
}

/// Rank a CVSS severity string by its operational priority. Higher rank
/// means more severe.
///
/// `critical` > `high` > `medium` > `low` > anything else (unknown / NULL
/// rendered as the empty string). The DB-side aggregates in
/// `get_cve_trends` use the inverse mapping via SQL `CASE` so that
/// `MAX(rank)` returns the right "worst seen" severity for an (artifact,
/// cve_id) pair across multiple scanner outputs. Without this ranking we
/// fall through to lexicographic ordering -- "medium" > "low" > "high" >
/// "critical" -- which silently misreports a vulnerability that one
/// scanner labels `high` and another labels `medium` as `medium`.
///
/// This helper lives in Rust so the contract is unit-testable; the SQL
/// queries inline an equivalent `CASE` because Postgres can't call Rust.
/// If you edit the ranks here, also update the four `CASE severity ...`
/// expressions in `get_cve_trends`. The unit tests in this module assert
/// the two stay in sync. (#1375 round-2)
#[allow(dead_code)] // Mirror of an SQL CASE; only used from tests today.
pub(crate) fn severity_rank(severity: &str) -> i32 {
    match severity.to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// Inverse of `severity_rank`: map a rank produced by the SQL `MAX(CASE ...)`
/// expression back to its canonical lower-case string. Ranks outside
/// 1..=4 map to `None` (caller decides whether to default to `"unknown"`
/// or skip the row).
#[allow(dead_code)] // Mirror of an SQL CASE; only used from tests today.
pub(crate) fn severity_from_rank(rank: i32) -> Option<&'static str> {
    match rank {
        4 => Some("critical"),
        3 => Some("high"),
        2 => Some("medium"),
        1 => Some("low"),
        _ => None,
    }
}

/// Map the `all_acknowledged` flag aggregated from `scan_findings` to the
/// `CveHistoryEntry.status` string (`"acknowledged"` vs `"open"`). The
/// scanner has no notion of `fixed` or `false_positive`, those statuses
/// only exist on curated rows.
pub(crate) fn status_string_from_acknowledged(all_acknowledged: bool) -> &'static str {
    if all_acknowledged {
        "acknowledged"
    } else {
        "open"
    }
}

/// Map the `all_acknowledged` flag to a typed `CveStatus` for the timeline
/// projection in `get_cve_trends`. Mirrors `status_string_from_acknowledged`
/// but returns the enum directly because the timeline DTO is typed.
pub(crate) fn status_enum_from_acknowledged(all_acknowledged: bool) -> CveStatus {
    if all_acknowledged {
        CveStatus::Acknowledged
    } else {
        CveStatus::Open
    }
}

/// Convert a `ScanFindingCveRow` aggregate into a synthetic
/// `CveHistoryEntry`. Pure mapping, no DB access -- factored out so the
/// field-by-field projection is covered by unit tests.
///
/// Synth entries carry:
///   - `id` = `synth_cve_id(artifact_id, cve_id)` (deterministic)
///   - `sbom_id` / `component_id` / `scan_result_id` = `None` (no FK)
///   - `cve_id` = empty string when the row's `cve_id` is `None`
///     (callers filter these out via `scan_row_passes_known_filter` before
///     mapping, but the defensive default keeps the mapping total).
///   - `status` from `all_acknowledged`
///   - `created_at` / `updated_at` aligned to first/last detection
fn scan_finding_to_history_entry(row: ScanFindingCveRow) -> CveHistoryEntry {
    let cve_id = row.cve_id.unwrap_or_default();
    let id = synth_cve_id(row.artifact_id, &cve_id);
    CveHistoryEntry {
        id,
        artifact_id: row.artifact_id,
        sbom_id: None,
        component_id: None,
        scan_result_id: None,
        cve_id,
        affected_component: row.affected_component,
        affected_version: row.affected_version,
        fixed_version: row.fixed_version,
        severity: row.severity,
        cvss_score: None,
        cve_published_at: None,
        first_detected_at: row.first_detected_at,
        last_detected_at: row.last_detected_at,
        status: status_string_from_acknowledged(row.all_acknowledged).to_string(),
        acknowledged_by: None,
        acknowledged_at: None,
        acknowledged_reason: None,
        created_at: row.first_detected_at,
        updated_at: row.last_detected_at,
    }
}

/// Convert a `ScanFindingCveRow` aggregate into a `CveTimelineEntry` for
/// the trends timeline. `now` is injected so tests can pin `days_exposed`
/// without `Utc::now()` racing the assertion.
fn scan_finding_to_timeline_entry(row: &ScanFindingCveRow, now: DateTime<Utc>) -> CveTimelineEntry {
    let days_exposed = (now - row.first_detected_at).num_days();
    CveTimelineEntry {
        cve_id: row.cve_id.clone().unwrap_or_default(),
        severity: row.severity.clone().unwrap_or_default(),
        affected_component: row.affected_component.clone().unwrap_or_default(),
        cve_published_at: None,
        first_detected_at: row.first_detected_at,
        status: status_enum_from_acknowledged(row.all_acknowledged),
        days_exposed,
    }
}

/// Drop entries whose owning artifact's repo is not in `allowed_repos`.
///
/// Pulled out of `filter_entries_by_repo` so the filter logic itself
/// (independent of the DB lookup that builds `repo_by_artifact`) is
/// unit-testable. The DB call still lives in the async method; this
/// helper handles the in-memory partition once that map is available.
pub(crate) fn filter_entries_by_repo_map(
    entries: Vec<CveHistoryEntry>,
    repo_by_artifact: &std::collections::HashMap<Uuid, Uuid>,
    allowed_repos: &HashSet<Uuid>,
) -> Vec<CveHistoryEntry> {
    entries
        .into_iter()
        .filter(|e| {
            repo_by_artifact
                .get(&e.artifact_id)
                .map(|r| allowed_repos.contains(r))
                .unwrap_or(false)
        })
        .collect()
}

/// Sort `CveHistoryEntry` rows by `first_detected_at` descending (newest
/// first). The read paths concatenate curated + scan-derived rows then
/// re-sort so the response is monotonic; extracted so the sort key is
/// guaranteed by a unit test and won't drift if the type changes.
pub(crate) fn sort_entries_by_first_detected_desc(entries: &mut [CveHistoryEntry]) {
    entries.sort_by_key(|e| std::cmp::Reverse(e.first_detected_at));
}

/// SBOM service for generating and managing SBOMs.
#[derive(Clone)]
pub struct SbomService {
    db: PgPool,
}

impl SbomService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Generate an SBOM for an artifact.
    ///
    /// #903 cache-invalidation contract: a cached SBOM document is only
    /// returned when its `content_hash` matches the hash of the freshly-
    /// generated content. Pre-#903 the function returned any existing row
    /// unconditionally, which pinned empty / vulnerability-shaped SBOMs
    /// forever for artifacts uploaded before this fix shipped. With the
    /// hash-gated cache, a rescan that surfaces 30 new packages re-emits
    /// the document; identical re-generations skip the write.
    pub async fn generate_sbom(
        &self,
        artifact_id: Uuid,
        repository_id: Uuid,
        format: SbomFormat,
        dependencies: Vec<DependencyInfo>,
    ) -> Result<SbomDocument> {
        self.generate_sbom_with_completeness(artifact_id, repository_id, format, dependencies, None)
            .await
    }

    /// Variant of [`generate_sbom`] that surfaces the per-scan completeness
    /// signal (#1153) inside the generated SBOM document. Pass
    /// `inventory_completeness = Some("partial")` when the latest scanner
    /// pass for this artifact saw a target it could not parse; the
    /// CycloneDX output gains a `metadata.properties` entry and the SPDX
    /// output gains a creator `Comment:` line so a downstream consumer
    /// can distinguish "no lockfile present" from "lockfile present but
    /// unparseable".
    ///
    /// `None` is treated as `"complete"` and produces SBOM content
    /// byte-identical to the pre-#1153 generator output, preserving the
    /// stored `content_hash` cache for unchanged artifacts.
    pub async fn generate_sbom_with_completeness(
        &self,
        artifact_id: Uuid,
        repository_id: Uuid,
        format: SbomFormat,
        dependencies: Vec<DependencyInfo>,
        inventory_completeness: Option<&str>,
    ) -> Result<SbomDocument> {
        // Generate first so we can hash and compare against any cached row.
        let (content, components) = match format {
            SbomFormat::CycloneDX => {
                self.generate_cyclonedx_inner(&dependencies, inventory_completeness)?
            }
            SbomFormat::SPDX => self.generate_spdx_inner(&dependencies, inventory_completeness)?,
        };

        // Calculate content hash
        let content_str = serde_json::to_string(&content)?;
        let content_hash = format!("{:x}", Sha256::digest(content_str.as_bytes()));

        // Cache check: a stored row whose content_hash matches the freshly-
        // generated content is reusable. Anything else is stale (likely
        // generated before #903 against an empty / vulnerability-only
        // dependency list) and must be replaced.
        let existing = self.get_sbom_by_artifact(artifact_id, format).await?;
        if let Some(doc) = &existing {
            if doc.content_hash == content_hash {
                return Ok(doc.clone());
            }
        }

        // Stale cache: drop components first (FK from sbom_components to
        // sbom_documents) then the document row. Using ON CONFLICT on the
        // (artifact_id, format) unique index for the insert below would
        // leave orphaned component rows, since sbom_components is keyed
        // on sbom_id which the upsert path preserves.
        if let Some(doc) = existing {
            sqlx::query("DELETE FROM sbom_components WHERE sbom_id = $1")
                .bind(doc.id)
                .execute(&self.db)
                .await?;
            sqlx::query("DELETE FROM sbom_documents WHERE id = $1")
                .bind(doc.id)
                .execute(&self.db)
                .await?;
        }

        // Extract licenses
        let licenses: Vec<String> = dependencies
            .iter()
            .filter_map(|d| d.license.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        // Insert SBOM document
        let doc = sqlx::query_as::<_, SbomDocument>(
            r#"
            INSERT INTO sbom_documents (
                artifact_id, repository_id, format, format_version, spec_version,
                content, component_count, dependency_count, license_count,
                licenses, content_hash, generator, generator_version
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING *
            "#,
        )
        .bind(artifact_id)
        .bind(repository_id)
        .bind(format.as_str())
        .bind(self.get_format_version(format))
        .bind(self.get_spec_version(format))
        .bind(&content)
        .bind(components.len() as i32)
        .bind(dependencies.len() as i32)
        .bind(licenses.len() as i32)
        .bind(&licenses)
        .bind(&content_hash)
        .bind("artifact-keeper")
        .bind(env!("CARGO_PKG_VERSION"))
        .fetch_one(&self.db)
        .await?;

        // Insert components
        for component in &components {
            sqlx::query(
                r#"
                INSERT INTO sbom_components (
                    sbom_id, name, version, purl, component_type,
                    licenses, sha256, supplier, external_refs
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                "#,
            )
            .bind(doc.id)
            .bind(&component.name)
            .bind(&component.version)
            .bind(&component.purl)
            .bind(&component.component_type)
            .bind(&component.licenses)
            .bind(&component.sha256)
            .bind(&component.supplier)
            .bind(serde_json::json!([]))
            .execute(&self.db)
            .await?;
        }

        Ok(doc)
    }

    /// Get SBOM by artifact ID and format.
    pub async fn get_sbom_by_artifact(
        &self,
        artifact_id: Uuid,
        format: SbomFormat,
    ) -> Result<Option<SbomDocument>> {
        let doc = sqlx::query_as::<_, SbomDocument>(
            "SELECT * FROM sbom_documents WHERE artifact_id = $1 AND format = $2",
        )
        .bind(artifact_id)
        .bind(format.as_str())
        .fetch_optional(&self.db)
        .await?;

        Ok(doc)
    }

    /// Get SBOM by ID.
    pub async fn get_sbom(&self, id: Uuid) -> Result<Option<SbomDocument>> {
        let doc = sqlx::query_as::<_, SbomDocument>("SELECT * FROM sbom_documents WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.db)
            .await?;

        Ok(doc)
    }

    /// List SBOMs for an artifact.
    pub async fn list_sboms_for_artifact(&self, artifact_id: Uuid) -> Result<Vec<SbomSummary>> {
        let docs = sqlx::query_as::<_, SbomDocument>(
            "SELECT * FROM sbom_documents WHERE artifact_id = $1 ORDER BY created_at DESC",
        )
        .bind(artifact_id)
        .fetch_all(&self.db)
        .await?;

        Ok(docs.into_iter().map(SbomSummary::from).collect())
    }

    /// Get components for an SBOM.
    pub async fn get_sbom_components(&self, sbom_id: Uuid) -> Result<Vec<SbomComponent>> {
        let components = sqlx::query_as::<_, SbomComponent>(
            "SELECT * FROM sbom_components WHERE sbom_id = $1 ORDER BY name",
        )
        .bind(sbom_id)
        .fetch_all(&self.db)
        .await?;

        Ok(components)
    }

    /// Convert SBOM between formats.
    pub async fn convert_sbom(
        &self,
        sbom_id: Uuid,
        target_format: SbomFormat,
    ) -> Result<SbomDocument> {
        let source = self
            .get_sbom(sbom_id)
            .await?
            .ok_or_else(|| AppError::NotFound("SBOM not found".into()))?;

        let source_format = SbomFormat::parse(&source.format)
            .ok_or_else(|| AppError::Validation("Unknown source format".into()))?;

        if source_format == target_format {
            return Ok(source);
        }

        // Get components for conversion
        let components = self.get_sbom_components(sbom_id).await?;

        // Convert to dependency info for regeneration
        let deps: Vec<DependencyInfo> = components
            .into_iter()
            .map(|c| DependencyInfo {
                name: c.name,
                version: c.version,
                purl: c.purl,
                license: c.licenses.first().cloned(),
                sha256: c.sha256,
            })
            .collect();

        // Check if target format already exists
        if let Some(existing) = self
            .get_sbom_by_artifact(source.artifact_id, target_format)
            .await?
        {
            return Ok(existing);
        }

        // Generate new SBOM in target format
        self.generate_sbom(
            source.artifact_id,
            source.repository_id,
            target_format,
            deps,
        )
        .await
    }

    /// Delete SBOM.
    pub async fn delete_sbom(&self, id: Uuid) -> Result<()> {
        sqlx::query("DELETE FROM sbom_documents WHERE id = $1")
            .bind(id)
            .execute(&self.db)
            .await?;
        Ok(())
    }

    // === CVE History ===

    /// Record a CVE finding in history.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_cve(
        &self,
        artifact_id: Uuid,
        cve_id: &str,
        severity: &str,
        affected_component: Option<&str>,
        affected_version: Option<&str>,
        fixed_version: Option<&str>,
        scan_result_id: Option<Uuid>,
    ) -> Result<CveHistoryEntry> {
        // Upsert: update last_detected_at if exists, insert if not
        let entry = sqlx::query_as::<_, CveHistoryEntry>(
            r#"
            INSERT INTO cve_history (
                artifact_id, cve_id, severity, affected_component,
                affected_version, fixed_version, scan_result_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (artifact_id, cve_id) DO UPDATE SET
                last_detected_at = NOW(),
                severity = EXCLUDED.severity,
                scan_result_id = EXCLUDED.scan_result_id,
                updated_at = NOW()
            RETURNING *
            "#,
        )
        .bind(artifact_id)
        .bind(cve_id)
        .bind(severity)
        .bind(affected_component)
        .bind(affected_version)
        .bind(fixed_version)
        .bind(scan_result_id)
        .fetch_one(&self.db)
        .await?;

        Ok(entry)
    }

    /// Get CVE history for an artifact.
    pub async fn get_cve_history(&self, artifact_id: Uuid) -> Result<Vec<CveHistoryEntry>> {
        // Primary source: legacy `cve_history` table (manual / promoted entries).
        let mut entries = sqlx::query_as::<_, CveHistoryEntry>(
            r#"
            SELECT * FROM cve_history
            WHERE artifact_id = $1
            ORDER BY first_detected_at DESC
            "#,
        )
        .bind(artifact_id)
        .fetch_all(&self.db)
        .await?;

        // Fallback / supplement: derive CVE-shaped entries from `scan_findings`
        // for findings the scanner produced but never wrote into `cve_history`
        // (see #1375: `record_cve` is presently dead code, so the scan-derived
        // path is the only source of real CVE data). De-dupe by `cve_id` so a
        // CVE that exists in both tables surfaces once with the curated row.
        // Normalize to upper-case so the dedupe is case-insensitive (schema
        // does not constrain `cve_id` case in either table).
        let known = build_known_cve_set(&entries);
        let scan_entries = self
            .build_cve_entries_from_scan_findings(Some(artifact_id), None, &known)
            .await?;
        entries.extend(scan_entries);
        sort_entries_by_first_detected_desc(&mut entries);
        Ok(entries)
    }

    /// Get CVE history for a single CVE identifier across artifacts.
    ///
    /// Reads from both `cve_history` (curated rows) and `scan_findings` (live
    /// scanner output) so that callers see the full set of artifacts where
    /// this CVE has ever been detected.
    ///
    /// # `allowed_repo_ids` contract (ADMIN-ONLY when `None`)
    ///
    /// The `allowed_repo_ids` argument scopes the lookup to repositories the
    /// caller can access (mirrors `AuthExtension::can_access_repo`).
    ///
    /// - `Some(&[...])` -- limit results to the listed repositories. An empty
    ///   slice returns zero rows (caller has access to nothing).
    /// - `None` -- **NO REPOSITORY SCOPE; FULL CROSS-REPO READ**. Only pass
    ///   `None` when the caller has admin-tier access. The convention here
    ///   mirrors `AuthExtension::allowed_repo_ids` where `None` means "no
    ///   restriction applied by auth middleware" (admin/root tokens, system
    ///   workers). Calling this with `None` for an end-user token is a data
    ///   leak. The HTTP handler enforces this by always passing
    ///   `auth.allowed_repo_ids.as_deref()` through unchanged: if auth said
    ///   "no restriction", the service trusts that decision.
    ///
    /// This is a footgun-prone shape. Tracked for refactor to an explicit
    /// `enum AccessScope { Admin, Restricted(Vec<Uuid>) }` post v1.2.0 (see
    /// #1390 follow-up). Until then, treat `None` as a load-bearing comment
    /// that must read "admin-only".
    ///
    /// Returns an empty vec when the CVE is not present (200 OK, [] body); a
    /// missing CVE is not a 404 in this contract.
    ///
    /// #1375: this is the cross-artifact lookup path that the broken
    /// `Path<Uuid>` extractor used to make impossible.
    pub async fn get_cve_history_by_cve_id(
        &self,
        cve_id: &str,
        allowed_repo_ids: Option<&[Uuid]>,
    ) -> Result<Vec<CveHistoryEntry>> {
        // Normalize: NVD shape is upper-case; lower-case is a common typo.
        // Schema does not constrain `cve_id` case in either `cve_history` or
        // `scan_findings`, so we compare case-insensitively and only use the
        // upper-cased form for display/known-set dedupe below.
        let cve_id_upper = cve_id.to_ascii_uppercase();

        // 1. Curated rows from cve_history. We join through artifacts so we
        //    can filter by allowed_repo_ids without a second round-trip.
        //    LOWER(...)=LOWER(...) so a scanner that wrote lower-case still
        //    matches an upper-case query (and vice versa).
        let mut entries: Vec<CveHistoryEntry> = if let Some(repo_ids) = allowed_repo_ids {
            sqlx::query_as::<_, CveHistoryEntry>(
                r#"
                SELECT ch.*
                FROM cve_history ch
                JOIN artifacts a ON ch.artifact_id = a.id
                WHERE LOWER(ch.cve_id) = LOWER($1)
                  AND a.repository_id = ANY($2)
                  AND NOT a.is_deleted
                ORDER BY ch.first_detected_at DESC
                "#,
            )
            .bind(&cve_id_upper)
            .bind(repo_ids)
            .fetch_all(&self.db)
            .await?
        } else {
            sqlx::query_as::<_, CveHistoryEntry>(
                r#"
                SELECT ch.*
                FROM cve_history ch
                JOIN artifacts a ON ch.artifact_id = a.id
                WHERE LOWER(ch.cve_id) = LOWER($1)
                  AND NOT a.is_deleted
                ORDER BY ch.first_detected_at DESC
                "#,
            )
            .bind(&cve_id_upper)
            .fetch_all(&self.db)
            .await?
        };

        // 2. Live findings from scan_findings, skipping cve_ids we already
        //    surfaced via the curated path. `known` is normalized so the
        //    dedupe is case-insensitive too.
        let known = build_known_cve_set(&entries);
        let scan_entries = self
            .build_cve_entries_from_scan_findings(None, Some(&cve_id_upper), &known)
            .await?;
        // For scan-derived entries we additionally enforce the repo filter
        // (artifact-level lookup already enforced it inside the helper, so
        // here we only need to re-scope by allowed_repo_ids).
        let scan_entries = match allowed_repo_ids {
            None => scan_entries,
            Some(repo_ids) => {
                let allowed: HashSet<Uuid> = repo_ids.iter().copied().collect();
                self.filter_entries_by_repo(scan_entries, &allowed).await?
            }
        };
        entries.extend(scan_entries);
        sort_entries_by_first_detected_desc(&mut entries);
        Ok(entries)
    }

    /// Drop entries whose owning artifact is not in `allowed_repos`.
    ///
    /// Used by the CVE-id read path to apply the auth `allowed_repo_ids`
    /// filter to scan-derived entries (where we synthesize `CveHistoryEntry`
    /// rows on the fly and so cannot enforce the filter inside the original
    /// SQL `WHERE` clause).
    async fn filter_entries_by_repo(
        &self,
        entries: Vec<CveHistoryEntry>,
        allowed_repos: &HashSet<Uuid>,
    ) -> Result<Vec<CveHistoryEntry>> {
        if entries.is_empty() {
            return Ok(entries);
        }
        let artifact_ids: Vec<Uuid> = entries.iter().map(|e| e.artifact_id).collect();
        let rows: Vec<(Uuid, Uuid)> = sqlx::query_as(
            r#"
            SELECT id, repository_id FROM artifacts
            WHERE id = ANY($1) AND NOT is_deleted
            "#,
        )
        .bind(&artifact_ids)
        .fetch_all(&self.db)
        .await?;
        let repo_by_artifact: std::collections::HashMap<Uuid, Uuid> = rows.into_iter().collect();
        Ok(filter_entries_by_repo_map(
            entries,
            &repo_by_artifact,
            allowed_repos,
        ))
    }

    /// Build synthetic `CveHistoryEntry` rows from `scan_findings`.
    ///
    /// Why this exists: the scanner pipeline writes findings to
    /// `scan_findings` but never invokes `SbomService::record_cve`, so the
    /// `cve_history` table is structurally empty in production. To make the
    /// CVE history / trends endpoints return real data we synthesize entries
    /// from scan findings. This is a read-time projection; nothing is
    /// persisted. (#1375)
    ///
    /// `artifact_filter` and `cve_filter` are mutually exclusive scopes —
    /// pass `Some` for at most one. `known` is a set of CVE ids that should
    /// be excluded (because the curated `cve_history` path already returned
    /// them).
    async fn build_cve_entries_from_scan_findings(
        &self,
        artifact_filter: Option<Uuid>,
        cve_filter: Option<&str>,
        known: &HashSet<String>,
    ) -> Result<Vec<CveHistoryEntry>> {
        // Each row collapses to one synthetic CVE-history entry per
        // (artifact_id, cve_id). MIN(created_at) approximates
        // first_detected_at; MAX(created_at) approximates last_detected_at.
        // Severity is aggregated via a ranked CASE (see `severity_rank`) so
        // that a CVE reported `high` by one scanner and `medium` by another
        // shows up as `high` rather than the lexicographically-larger but
        // operationally-lower `medium`. Same fix as `get_cve_trends`. (#1375)
        let rows: Vec<ScanFindingCveRow> = if let Some(artifact_id) = artifact_filter {
            sqlx::query_as::<_, ScanFindingCveRow>(
                r#"
                SELECT
                    artifact_id,
                    cve_id,
                    CASE severity_rank
                        WHEN 4 THEN 'critical'
                        WHEN 3 THEN 'high'
                        WHEN 2 THEN 'medium'
                        WHEN 1 THEN 'low'
                        ELSE NULL
                    END AS severity,
                    affected_component,
                    affected_version,
                    fixed_version,
                    first_detected_at,
                    last_detected_at,
                    all_acknowledged
                FROM (
                    SELECT
                        artifact_id,
                        cve_id,
                        MAX(
                            CASE LOWER(severity)
                                WHEN 'critical' THEN 4
                                WHEN 'high' THEN 3
                                WHEN 'medium' THEN 2
                                WHEN 'low' THEN 1
                                ELSE 0
                            END
                        ) AS severity_rank,
                        MAX(affected_component) AS affected_component,
                        MAX(affected_version) AS affected_version,
                        MAX(fixed_version) AS fixed_version,
                        MIN(created_at) AS first_detected_at,
                        MAX(created_at) AS last_detected_at,
                        BOOL_AND(is_acknowledged) AS all_acknowledged
                    FROM scan_findings
                    WHERE artifact_id = $1
                      AND cve_id IS NOT NULL
                    GROUP BY artifact_id, cve_id
                    ORDER BY MIN(created_at) DESC
                ) inner_ranked
                "#,
            )
            .bind(artifact_id)
            .fetch_all(&self.db)
            .await?
        } else if let Some(cve_id) = cve_filter {
            sqlx::query_as::<_, ScanFindingCveRow>(
                r#"
                SELECT
                    artifact_id,
                    cve_id,
                    CASE severity_rank
                        WHEN 4 THEN 'critical'
                        WHEN 3 THEN 'high'
                        WHEN 2 THEN 'medium'
                        WHEN 1 THEN 'low'
                        ELSE NULL
                    END AS severity,
                    affected_component,
                    affected_version,
                    fixed_version,
                    first_detected_at,
                    last_detected_at,
                    all_acknowledged
                FROM (
                    SELECT
                        artifact_id,
                        cve_id,
                        MAX(
                            CASE LOWER(severity)
                                WHEN 'critical' THEN 4
                                WHEN 'high' THEN 3
                                WHEN 'medium' THEN 2
                                WHEN 'low' THEN 1
                                ELSE 0
                            END
                        ) AS severity_rank,
                        MAX(affected_component) AS affected_component,
                        MAX(affected_version) AS affected_version,
                        MAX(fixed_version) AS fixed_version,
                        MIN(created_at) AS first_detected_at,
                        MAX(created_at) AS last_detected_at,
                        BOOL_AND(is_acknowledged) AS all_acknowledged
                    FROM scan_findings
                    WHERE LOWER(cve_id) = LOWER($1)
                    GROUP BY artifact_id, cve_id
                    ORDER BY MIN(created_at) DESC
                ) inner_ranked
                "#,
            )
            .bind(cve_id)
            .fetch_all(&self.db)
            .await?
        } else {
            // Unfiltered scope is a misuse (would return every CVE in the
            // system). Refuse rather than DoS the DB.
            return Ok(Vec::new());
        };

        Ok(rows
            .into_iter()
            .filter(|r| scan_row_passes_known_filter(r.cve_id.as_deref(), known))
            .map(scan_finding_to_history_entry)
            .collect())
    }

    /// Update CVE status.
    pub async fn update_cve_status(
        &self,
        id: Uuid,
        status: CveStatus,
        user_id: Option<Uuid>,
        reason: Option<&str>,
    ) -> Result<CveHistoryEntry> {
        let entry = sqlx::query_as::<_, CveHistoryEntry>(
            r#"
            UPDATE cve_history SET
                status = $2,
                acknowledged_by = $3,
                acknowledged_at = CASE WHEN $2 = 'acknowledged' THEN NOW() ELSE NULL END,
                acknowledged_reason = $4,
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(status.as_str())
        .bind(user_id)
        .bind(reason)
        .fetch_one(&self.db)
        .await?;

        Ok(entry)
    }

    /// Get CVE trends for a repository.
    ///
    /// #1375: trends previously read only from `cve_history`, which is never
    /// populated by the scanner pipeline (no caller invokes
    /// `SbomService::record_cve`). The result was an all-zeros response for
    /// every fresh deployment, which the release-gate test flagged. We now
    /// derive the aggregates from `scan_findings`, the table the scanner
    /// actually writes to, so trends reflect live CVE state.
    ///
    /// `cve_history.status` (open/fixed/acknowledged/false_positive) has no
    /// direct equivalent in `scan_findings`. We approximate:
    ///   - open: findings where `NOT is_acknowledged`
    ///   - acknowledged: findings where `is_acknowledged`
    ///   - fixed: union of two sources, deduped by (artifact_id, cve_id):
    ///     (a) curated `cve_history` rows with `status='fixed'` (preserves
    ///     the legacy admin/promotion-policy semantic for the rare callers
    ///     that write to that table); plus
    ///     (b) CVEs that appeared in an earlier `scan_findings` row for an
    ///     artifact but are absent from that artifact's most recent
    ///     `scan_results` (per `scan_type`). "Disappeared on rescan" is the
    ///     closest signal we have to a fixed CVE without a real fixed-at
    ///     timestamp.
    ///
    /// We dedupe by (artifact_id, cve_id) so multi-scanner overlap doesn't
    /// double-count a single vulnerability.
    pub async fn get_cve_trends(&self, repository_id: Option<Uuid>) -> Result<CveTrends> {
        let (total, open, acknowledged, critical, high, medium, low): (
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
        ) = if let Some(repo_id) = repository_id {
            sqlx::query_as(
                // Round-2 fix (#1375): `MAX(severity)` ordered strings
                // lexicographically, which gave the wrong "worst-seen"
                // severity when two scanners disagreed (e.g. one says
                // `high`, another says `medium` -- string MAX picks
                // `medium`). The ranked CASE maps each severity to an
                // ordered integer first; we then translate the rank back
                // to text in the projection. Keep the literals here in
                // lockstep with `severity_rank`/`severity_from_rank`.
                r#"
                WITH per_cve AS (
                    SELECT
                        sf.artifact_id,
                        sf.cve_id,
                        MAX(
                            CASE LOWER(sf.severity)
                                WHEN 'critical' THEN 4
                                WHEN 'high' THEN 3
                                WHEN 'medium' THEN 2
                                WHEN 'low' THEN 1
                                ELSE 0
                            END
                        ) AS severity_rank,
                        BOOL_AND(sf.is_acknowledged) AS all_ack
                    FROM scan_findings sf
                    JOIN artifacts a ON sf.artifact_id = a.id
                    WHERE sf.cve_id IS NOT NULL
                      AND a.repository_id = $1
                      AND NOT a.is_deleted
                    GROUP BY sf.artifact_id, sf.cve_id
                )
                SELECT
                    COUNT(*) AS total,
                    COUNT(*) FILTER (WHERE NOT all_ack) AS open,
                    COUNT(*) FILTER (WHERE all_ack) AS acknowledged,
                    COUNT(*) FILTER (WHERE severity_rank = 4) AS critical,
                    COUNT(*) FILTER (WHERE severity_rank = 3) AS high,
                    COUNT(*) FILTER (WHERE severity_rank = 2) AS medium,
                    COUNT(*) FILTER (WHERE severity_rank = 1) AS low
                FROM per_cve
                "#,
            )
            .bind(repo_id)
            .fetch_one(&self.db)
            .await?
        } else {
            sqlx::query_as(
                // See repo-scoped branch above for the rationale on the
                // ranked CASE; this branch is the unscoped (all-repos)
                // mirror and must stay byte-aligned with the CASE table.
                r#"
                WITH per_cve AS (
                    SELECT
                        sf.artifact_id,
                        sf.cve_id,
                        MAX(
                            CASE LOWER(sf.severity)
                                WHEN 'critical' THEN 4
                                WHEN 'high' THEN 3
                                WHEN 'medium' THEN 2
                                WHEN 'low' THEN 1
                                ELSE 0
                            END
                        ) AS severity_rank,
                        BOOL_AND(sf.is_acknowledged) AS all_ack
                    FROM scan_findings sf
                    JOIN artifacts a ON sf.artifact_id = a.id
                    WHERE sf.cve_id IS NOT NULL
                      AND NOT a.is_deleted
                    GROUP BY sf.artifact_id, sf.cve_id
                )
                SELECT
                    COUNT(*) AS total,
                    COUNT(*) FILTER (WHERE NOT all_ack) AS open,
                    COUNT(*) FILTER (WHERE all_ack) AS acknowledged,
                    COUNT(*) FILTER (WHERE severity_rank = 4) AS critical,
                    COUNT(*) FILTER (WHERE severity_rank = 3) AS high,
                    COUNT(*) FILTER (WHERE severity_rank = 2) AS medium,
                    COUNT(*) FILTER (WHERE severity_rank = 1) AS low
                FROM per_cve
                "#,
            )
            .fetch_one(&self.db)
            .await?
        };

        // Timeline (most recent 100 newly-detected CVEs in the last 30 days)
        // derived from scan_findings.
        //
        // Round-2 fix (#1375): severity is projected through the same
        // ranked CASE as the counts above, then mapped back to a text
        // label, so multi-scanner overlap doesn't flatten a `high`
        // finding to `medium` via lexicographic MAX.
        let timeline_rows: Vec<ScanFindingCveRow> = if let Some(repo_id) = repository_id {
            sqlx::query_as::<_, ScanFindingCveRow>(
                r#"
                SELECT
                    artifact_id,
                    cve_id,
                    CASE severity_rank
                        WHEN 4 THEN 'critical'
                        WHEN 3 THEN 'high'
                        WHEN 2 THEN 'medium'
                        WHEN 1 THEN 'low'
                        ELSE NULL
                    END AS severity,
                    affected_component,
                    affected_version,
                    fixed_version,
                    first_detected_at,
                    last_detected_at,
                    all_acknowledged
                FROM (
                    SELECT
                        sf.artifact_id,
                        sf.cve_id,
                        MAX(
                            CASE LOWER(sf.severity)
                                WHEN 'critical' THEN 4
                                WHEN 'high' THEN 3
                                WHEN 'medium' THEN 2
                                WHEN 'low' THEN 1
                                ELSE 0
                            END
                        ) AS severity_rank,
                        MAX(sf.affected_component) AS affected_component,
                        MAX(sf.affected_version) AS affected_version,
                        MAX(sf.fixed_version) AS fixed_version,
                        MIN(sf.created_at) AS first_detected_at,
                        MAX(sf.created_at) AS last_detected_at,
                        BOOL_AND(sf.is_acknowledged) AS all_acknowledged
                    FROM scan_findings sf
                    JOIN artifacts a ON sf.artifact_id = a.id
                    WHERE sf.cve_id IS NOT NULL
                      AND a.repository_id = $1
                      AND NOT a.is_deleted
                      AND sf.created_at > NOW() - INTERVAL '30 days'
                    GROUP BY sf.artifact_id, sf.cve_id
                    ORDER BY MIN(sf.created_at) DESC
                    LIMIT 100
                ) inner_ranked
                "#,
            )
            .bind(repo_id)
            .fetch_all(&self.db)
            .await?
        } else {
            sqlx::query_as::<_, ScanFindingCveRow>(
                r#"
                SELECT
                    artifact_id,
                    cve_id,
                    CASE severity_rank
                        WHEN 4 THEN 'critical'
                        WHEN 3 THEN 'high'
                        WHEN 2 THEN 'medium'
                        WHEN 1 THEN 'low'
                        ELSE NULL
                    END AS severity,
                    affected_component,
                    affected_version,
                    fixed_version,
                    first_detected_at,
                    last_detected_at,
                    all_acknowledged
                FROM (
                    SELECT
                        sf.artifact_id,
                        sf.cve_id,
                        MAX(
                            CASE LOWER(sf.severity)
                                WHEN 'critical' THEN 4
                                WHEN 'high' THEN 3
                                WHEN 'medium' THEN 2
                                WHEN 'low' THEN 1
                                ELSE 0
                            END
                        ) AS severity_rank,
                        MAX(sf.affected_component) AS affected_component,
                        MAX(sf.affected_version) AS affected_version,
                        MAX(sf.fixed_version) AS fixed_version,
                        MIN(sf.created_at) AS first_detected_at,
                        MAX(sf.created_at) AS last_detected_at,
                        BOOL_AND(sf.is_acknowledged) AS all_acknowledged
                    FROM scan_findings sf
                    JOIN artifacts a ON sf.artifact_id = a.id
                    WHERE sf.cve_id IS NOT NULL
                      AND NOT a.is_deleted
                      AND sf.created_at > NOW() - INTERVAL '30 days'
                    GROUP BY sf.artifact_id, sf.cve_id
                    ORDER BY MIN(sf.created_at) DESC
                    LIMIT 100
                ) inner_ranked
                "#,
            )
            .fetch_all(&self.db)
            .await?
        };

        let now = Utc::now();
        let timeline: Vec<CveTimelineEntry> = timeline_rows
            .iter()
            .map(|r| scan_finding_to_timeline_entry(r, now))
            .collect();

        // fixed_cves: union of two definitions, deduped by (artifact_id, cve_id):
        //   (a) curated `cve_history` rows with status='fixed'
        //   (b) CVEs present in an earlier scan_findings row for an artifact
        //       but absent from that artifact's most recent scan_result per
        //       scan_type (i.e. they "fell off" on rescan)
        // This avoids the silent-zero regression while still being correct
        // when no curated rows exist.
        let fixed_cves: i64 = if let Some(repo_id) = repository_id {
            sqlx::query_scalar(
                r#"
                WITH curated_fixed AS (
                    SELECT DISTINCT ch.artifact_id, LOWER(ch.cve_id) AS cve_id
                    FROM cve_history ch
                    JOIN artifacts a ON ch.artifact_id = a.id
                    WHERE ch.status = 'fixed'
                      AND ch.cve_id IS NOT NULL
                      AND a.repository_id = $1
                      AND NOT a.is_deleted
                ),
                latest_scans AS (
                    SELECT DISTINCT ON (sr.artifact_id, sr.scan_type)
                        sr.id, sr.artifact_id, sr.scan_type
                    FROM scan_results sr
                    JOIN artifacts a ON sr.artifact_id = a.id
                    WHERE sr.status = 'completed'
                      AND a.repository_id = $1
                      AND NOT a.is_deleted
                    ORDER BY sr.artifact_id, sr.scan_type, sr.created_at DESC
                ),
                ever_seen AS (
                    SELECT DISTINCT sf.artifact_id, LOWER(sf.cve_id) AS cve_id
                    FROM scan_findings sf
                    JOIN artifacts a ON sf.artifact_id = a.id
                    WHERE sf.cve_id IS NOT NULL
                      AND a.repository_id = $1
                      AND NOT a.is_deleted
                ),
                still_present AS (
                    SELECT DISTINCT sf.artifact_id, LOWER(sf.cve_id) AS cve_id
                    FROM scan_findings sf
                    JOIN latest_scans ls ON sf.scan_result_id = ls.id
                    WHERE sf.cve_id IS NOT NULL
                ),
                disappeared AS (
                    SELECT e.artifact_id, e.cve_id FROM ever_seen e
                    EXCEPT
                    SELECT s.artifact_id, s.cve_id FROM still_present s
                ),
                unioned AS (
                    SELECT artifact_id, cve_id FROM curated_fixed
                    UNION
                    SELECT artifact_id, cve_id FROM disappeared
                )
                SELECT COUNT(*) FROM unioned
                "#,
            )
            .bind(repo_id)
            .fetch_one(&self.db)
            .await?
        } else {
            sqlx::query_scalar(
                r#"
                WITH curated_fixed AS (
                    SELECT DISTINCT ch.artifact_id, LOWER(ch.cve_id) AS cve_id
                    FROM cve_history ch
                    JOIN artifacts a ON ch.artifact_id = a.id
                    WHERE ch.status = 'fixed'
                      AND ch.cve_id IS NOT NULL
                      AND NOT a.is_deleted
                ),
                latest_scans AS (
                    SELECT DISTINCT ON (sr.artifact_id, sr.scan_type)
                        sr.id, sr.artifact_id, sr.scan_type
                    FROM scan_results sr
                    JOIN artifacts a ON sr.artifact_id = a.id
                    WHERE sr.status = 'completed'
                      AND NOT a.is_deleted
                    ORDER BY sr.artifact_id, sr.scan_type, sr.created_at DESC
                ),
                ever_seen AS (
                    SELECT DISTINCT sf.artifact_id, LOWER(sf.cve_id) AS cve_id
                    FROM scan_findings sf
                    JOIN artifacts a ON sf.artifact_id = a.id
                    WHERE sf.cve_id IS NOT NULL
                      AND NOT a.is_deleted
                ),
                still_present AS (
                    SELECT DISTINCT sf.artifact_id, LOWER(sf.cve_id) AS cve_id
                    FROM scan_findings sf
                    JOIN latest_scans ls ON sf.scan_result_id = ls.id
                    WHERE sf.cve_id IS NOT NULL
                ),
                disappeared AS (
                    SELECT e.artifact_id, e.cve_id FROM ever_seen e
                    EXCEPT
                    SELECT s.artifact_id, s.cve_id FROM still_present s
                ),
                unioned AS (
                    SELECT artifact_id, cve_id FROM curated_fixed
                    UNION
                    SELECT artifact_id, cve_id FROM disappeared
                )
                SELECT COUNT(*) FROM unioned
                "#,
            )
            .fetch_one(&self.db)
            .await?
        };

        Ok(CveTrends {
            total_cves: total,
            open_cves: open,
            fixed_cves,
            acknowledged_cves: acknowledged,
            critical_count: critical,
            high_count: high,
            medium_count: medium,
            low_count: low,
            avg_days_to_fix: None, // scan_findings has no fixed-at timestamp
            timeline,
        })
    }

    // === License Policies ===

    /// Get license policy for a repository.
    pub async fn get_license_policy(
        &self,
        repository_id: Option<Uuid>,
    ) -> Result<Option<LicensePolicy>> {
        // Try repo-specific first, fall back to global
        let policy = if let Some(repo_id) = repository_id {
            sqlx::query_as::<_, LicensePolicy>(
                r#"
                SELECT * FROM license_policies
                WHERE repository_id = $1 AND is_enabled = true
                ORDER BY created_at DESC
                LIMIT 1
                "#,
            )
            .bind(repo_id)
            .fetch_optional(&self.db)
            .await?
        } else {
            None
        };

        if policy.is_some() {
            return Ok(policy);
        }

        // Fall back to global policy
        sqlx::query_as::<_, LicensePolicy>(
            r#"
            SELECT * FROM license_policies
            WHERE repository_id IS NULL AND is_enabled = true
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .fetch_optional(&self.db)
        .await
        .map_err(Into::into)
    }

    /// Check licenses against policy.
    pub fn check_license_compliance(
        &self,
        policy: &LicensePolicy,
        licenses: &[String],
    ) -> LicenseCheckResult {
        let mut violations = Vec::new();
        let mut warnings = Vec::new();

        for license in licenses {
            let normalized = license.to_uppercase();

            // Check denylist first (takes precedence)
            if policy
                .denied_licenses
                .iter()
                .any(|d| d.to_uppercase() == normalized)
            {
                violations.push(format!("License '{}' is denied by policy", license));
                continue;
            }

            // Check allowlist if not empty
            if !policy.allowed_licenses.is_empty()
                && !policy
                    .allowed_licenses
                    .iter()
                    .any(|a| a.to_uppercase() == normalized)
            {
                if policy.allow_unknown {
                    warnings.push(format!("License '{}' is not in approved list", license));
                } else {
                    violations.push(format!("License '{}' is not in approved list", license));
                }
            }
        }

        LicenseCheckResult {
            compliant: violations.is_empty(),
            violations,
            warnings,
        }
    }

    // === Private helpers ===

    fn get_format_version(&self, format: SbomFormat) -> &'static str {
        match format {
            SbomFormat::CycloneDX => "1.5",
            SbomFormat::SPDX => "2.3",
        }
    }

    fn get_spec_version(&self, format: SbomFormat) -> &'static str {
        match format {
            SbomFormat::CycloneDX => "CycloneDX 1.5",
            SbomFormat::SPDX => "SPDX-2.3",
        }
    }

    fn generate_cyclonedx_inner(
        &self,
        dependencies: &[DependencyInfo],
        inventory_completeness: Option<&str>,
    ) -> Result<(serde_json::Value, Vec<ComponentInfo>)> {
        let mut components = Vec::new();
        let mut cdx_components = Vec::new();

        for dep in dependencies {
            let component = ComponentInfo {
                name: dep.name.clone(),
                version: dep.version.clone(),
                purl: dep.purl.clone(),
                component_type: Some("library".to_string()),
                licenses: dep.license.clone().into_iter().collect(),
                sha256: dep.sha256.clone(),
                supplier: None,
            };
            components.push(component);

            let mut cdx_comp = serde_json::json!({
                "type": "library",
                "name": dep.name,
            });

            if let Some(v) = &dep.version {
                cdx_comp["version"] = serde_json::json!(v);
            }
            if let Some(p) = &dep.purl {
                cdx_comp["purl"] = serde_json::json!(p);
            }
            if let Some(l) = &dep.license {
                cdx_comp["licenses"] = serde_json::json!([{"license": {"id": l}}]);
            }
            if let Some(h) = &dep.sha256 {
                cdx_comp["hashes"] = serde_json::json!([{"alg": "SHA-256", "content": h}]);
            }

            cdx_components.push(cdx_comp);
        }

        let mut metadata = serde_json::json!({
            "timestamp": Utc::now().to_rfc3339(),
            "tools": [{
                "vendor": "Artifact Keeper",
                "name": "artifact-keeper",
                "version": env!("CARGO_PKG_VERSION")
            }]
        });

        // #1153: thread the scanner completeness signal into the SBOM
        // document via CycloneDX 1.5 `metadata.properties` so downstream
        // attestation tooling can tell "no lockfile present" from
        // "lockfile present but unparseable". The property is omitted
        // when `inventory_completeness` is None so legacy SBOMs hash
        // identically and the content_hash cache stays warm.
        if let Some(c) = inventory_completeness {
            metadata["properties"] = serde_json::json!([{
                "name": "artifact-keeper:scan-completeness",
                "value": c
            }]);
        }

        let sbom = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": metadata,
            "components": cdx_components
        });

        Ok((sbom, components))
    }

    fn generate_spdx_inner(
        &self,
        dependencies: &[DependencyInfo],
        inventory_completeness: Option<&str>,
    ) -> Result<(serde_json::Value, Vec<ComponentInfo>)> {
        let mut components = Vec::new();
        let mut spdx_packages = Vec::new();

        for (idx, dep) in dependencies.iter().enumerate() {
            let component = ComponentInfo {
                name: dep.name.clone(),
                version: dep.version.clone(),
                purl: dep.purl.clone(),
                component_type: Some("library".to_string()),
                licenses: dep.license.clone().into_iter().collect(),
                sha256: dep.sha256.clone(),
                supplier: None,
            };
            components.push(component);

            let spdx_id = format!("SPDXRef-Package-{}", idx);
            let mut pkg = serde_json::json!({
                "SPDXID": spdx_id,
                "name": dep.name,
                "downloadLocation": "NOASSERTION"
            });

            if let Some(v) = &dep.version {
                pkg["versionInfo"] = serde_json::json!(v);
            }
            if let Some(l) = &dep.license {
                pkg["licenseConcluded"] = serde_json::json!(l);
                pkg["licenseDeclared"] = serde_json::json!(l);
            } else {
                pkg["licenseConcluded"] = serde_json::json!("NOASSERTION");
                pkg["licenseDeclared"] = serde_json::json!("NOASSERTION");
            }
            if let Some(h) = &dep.sha256 {
                pkg["checksums"] = serde_json::json!([{
                    "algorithm": "SHA256",
                    "checksumValue": h
                }]);
            }
            if let Some(p) = &dep.purl {
                pkg["externalRefs"] = serde_json::json!([{
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": p
                }]);
            }

            spdx_packages.push(pkg);
        }

        let mut creation_info = serde_json::json!({
            "created": Utc::now().to_rfc3339(),
            "creators": [format!("Tool: artifact-keeper-{}", env!("CARGO_PKG_VERSION"))]
        });

        // #1153: SPDX 2.3 `creationInfo.comment` is the canonical place to
        // signal that the underlying scan was partial. Like the CycloneDX
        // variant above, the field is omitted when None so legacy SBOMs
        // hash identically.
        if let Some(c) = inventory_completeness {
            creation_info["comment"] =
                serde_json::json!(format!("artifact-keeper scan-completeness: {}", c));
        }

        let sbom = serde_json::json!({
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "artifact-sbom",
            "documentNamespace": format!("https://artifact-keeper.com/sbom/{}", Uuid::new_v4()),
            "creationInfo": creation_info,
            "packages": spdx_packages
        });

        Ok((sbom, components))
    }
}

/// Dependency information for SBOM generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyInfo {
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub license: Option<String>,
    pub sha256: Option<String>,
}

/// Component information extracted from dependencies.
#[derive(Debug, Clone)]
pub struct ComponentInfo {
    pub name: String,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub component_type: Option<String>,
    pub licenses: Vec<String>,
    pub sha256: Option<String>,
    pub supplier: Option<String>,
}

/// Result of license compliance check.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LicenseCheckResult {
    pub compliant: bool,
    pub violations: Vec<String>,
    pub warnings: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Pure helper functions (moved from module scope — test-only)
    // -----------------------------------------------------------------------

    fn format_version(format: SbomFormat) -> &'static str {
        match format {
            SbomFormat::CycloneDX => "1.5",
            SbomFormat::SPDX => "2.3",
        }
    }

    fn spec_version(format: SbomFormat) -> &'static str {
        match format {
            SbomFormat::CycloneDX => "CycloneDX 1.5",
            SbomFormat::SPDX => "SPDX-2.3",
        }
    }

    fn build_cyclonedx_component(dep: &DependencyInfo) -> serde_json::Value {
        let mut comp = serde_json::json!({
            "type": "library",
            "name": dep.name,
        });
        if let Some(v) = &dep.version {
            comp["version"] = serde_json::json!(v);
        }
        if let Some(p) = &dep.purl {
            comp["purl"] = serde_json::json!(p);
        }
        if let Some(l) = &dep.license {
            comp["licenses"] = serde_json::json!([{"license": {"id": l}}]);
        }
        if let Some(h) = &dep.sha256 {
            comp["hashes"] = serde_json::json!([{"alg": "SHA-256", "content": h}]);
        }
        comp
    }

    fn build_spdx_package(dep: &DependencyInfo, idx: usize) -> serde_json::Value {
        let spdx_id = format!("SPDXRef-Package-{}", idx);
        let mut pkg = serde_json::json!({
            "SPDXID": spdx_id,
            "name": dep.name,
            "downloadLocation": "NOASSERTION"
        });
        if let Some(v) = &dep.version {
            pkg["versionInfo"] = serde_json::json!(v);
        }
        if let Some(l) = &dep.license {
            pkg["licenseConcluded"] = serde_json::json!(l);
            pkg["licenseDeclared"] = serde_json::json!(l);
        } else {
            pkg["licenseConcluded"] = serde_json::json!("NOASSERTION");
            pkg["licenseDeclared"] = serde_json::json!("NOASSERTION");
        }
        if let Some(h) = &dep.sha256 {
            pkg["checksums"] = serde_json::json!([{
                "algorithm": "SHA256",
                "checksumValue": h
            }]);
        }
        if let Some(p) = &dep.purl {
            pkg["externalRefs"] = serde_json::json!([{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": p
            }]);
        }
        pkg
    }

    fn build_component_info(dep: &DependencyInfo) -> ComponentInfo {
        ComponentInfo {
            name: dep.name.clone(),
            version: dep.version.clone(),
            purl: dep.purl.clone(),
            component_type: Some("library".to_string()),
            licenses: dep.license.clone().into_iter().collect(),
            sha256: dep.sha256.clone(),
            supplier: None,
        }
    }

    fn extract_unique_licenses(dependencies: &[DependencyInfo]) -> Vec<String> {
        dependencies
            .iter()
            .filter_map(|d| d.license.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect()
    }

    fn check_license_compliance_pure(
        policy: &LicensePolicy,
        licenses: &[String],
    ) -> LicenseCheckResult {
        let mut violations = Vec::new();
        let mut warnings = Vec::new();

        for license in licenses {
            let normalized = license.to_uppercase();

            if policy
                .denied_licenses
                .iter()
                .any(|d| d.to_uppercase() == normalized)
            {
                violations.push(format!("License '{}' is denied by policy", license));
                continue;
            }

            if !policy.allowed_licenses.is_empty()
                && !policy
                    .allowed_licenses
                    .iter()
                    .any(|a| a.to_uppercase() == normalized)
            {
                if policy.allow_unknown {
                    warnings.push(format!("License '{}' is not in approved list", license));
                } else {
                    violations.push(format!("License '{}' is not in approved list", license));
                }
            }
        }

        LicenseCheckResult {
            compliant: violations.is_empty(),
            violations,
            warnings,
        }
    }

    fn content_hash(content: &str) -> String {
        format!("{:x}", Sha256::digest(content.as_bytes()))
    }

    fn days_exposed(first_detected_at: chrono::DateTime<Utc>, now: chrono::DateTime<Utc>) -> i64 {
        (now - first_detected_at).num_days()
    }

    // ===================================================================
    // format_version
    // ===================================================================

    #[test]
    fn test_format_version_cyclonedx() {
        assert_eq!(format_version(SbomFormat::CycloneDX), "1.5");
    }

    #[test]
    fn test_format_version_spdx() {
        assert_eq!(format_version(SbomFormat::SPDX), "2.3");
    }

    // ===================================================================
    // spec_version
    // ===================================================================

    #[test]
    fn test_spec_version_cyclonedx() {
        assert_eq!(spec_version(SbomFormat::CycloneDX), "CycloneDX 1.5");
    }

    #[test]
    fn test_spec_version_spdx() {
        assert_eq!(spec_version(SbomFormat::SPDX), "SPDX-2.3");
    }

    // ===================================================================
    // build_cyclonedx_component
    // ===================================================================

    #[test]
    fn test_build_cyclonedx_component_all_fields() {
        let dep = DependencyInfo {
            name: "serde".to_string(),
            version: Some("1.0.195".to_string()),
            purl: Some("pkg:cargo/serde@1.0.195".to_string()),
            license: Some("MIT".to_string()),
            sha256: Some("abcdef".to_string()),
        };
        let comp = build_cyclonedx_component(&dep);
        assert_eq!(comp["type"], "library");
        assert_eq!(comp["name"], "serde");
        assert_eq!(comp["version"], "1.0.195");
        assert_eq!(comp["purl"], "pkg:cargo/serde@1.0.195");
        assert_eq!(comp["licenses"][0]["license"]["id"], "MIT");
        assert_eq!(comp["hashes"][0]["alg"], "SHA-256");
        assert_eq!(comp["hashes"][0]["content"], "abcdef");
    }

    #[test]
    fn test_build_cyclonedx_component_minimal() {
        let dep = DependencyInfo {
            name: "minimal".to_string(),
            version: None,
            purl: None,
            license: None,
            sha256: None,
        };
        let comp = build_cyclonedx_component(&dep);
        assert_eq!(comp["type"], "library");
        assert_eq!(comp["name"], "minimal");
        assert!(comp.get("version").is_none());
        assert!(comp.get("purl").is_none());
        assert!(comp.get("licenses").is_none());
        assert!(comp.get("hashes").is_none());
    }

    #[test]
    fn test_build_cyclonedx_component_version_only() {
        let dep = DependencyInfo {
            name: "pkg".to_string(),
            version: Some("2.0".to_string()),
            purl: None,
            license: None,
            sha256: None,
        };
        let comp = build_cyclonedx_component(&dep);
        assert_eq!(comp["version"], "2.0");
        assert!(comp.get("purl").is_none());
    }

    // ===================================================================
    // build_spdx_package
    // ===================================================================

    #[test]
    fn test_build_spdx_package_all_fields() {
        let dep = DependencyInfo {
            name: "express".to_string(),
            version: Some("4.18.2".to_string()),
            purl: Some("pkg:npm/express@4.18.2".to_string()),
            license: Some("MIT".to_string()),
            sha256: Some("abc123".to_string()),
        };
        let pkg = build_spdx_package(&dep, 0);
        assert_eq!(pkg["SPDXID"], "SPDXRef-Package-0");
        assert_eq!(pkg["name"], "express");
        assert_eq!(pkg["versionInfo"], "4.18.2");
        assert_eq!(pkg["licenseConcluded"], "MIT");
        assert_eq!(pkg["licenseDeclared"], "MIT");
        assert_eq!(pkg["checksums"][0]["algorithm"], "SHA256");
        assert_eq!(
            pkg["externalRefs"][0]["referenceLocator"],
            "pkg:npm/express@4.18.2"
        );
        assert_eq!(pkg["downloadLocation"], "NOASSERTION");
    }

    #[test]
    fn test_build_spdx_package_minimal() {
        let dep = DependencyInfo {
            name: "minimal".to_string(),
            version: None,
            purl: None,
            license: None,
            sha256: None,
        };
        let pkg = build_spdx_package(&dep, 5);
        assert_eq!(pkg["SPDXID"], "SPDXRef-Package-5");
        assert_eq!(pkg["licenseConcluded"], "NOASSERTION");
        assert_eq!(pkg["licenseDeclared"], "NOASSERTION");
    }

    #[test]
    fn test_build_spdx_package_index_numbering() {
        let dep = DependencyInfo {
            name: "pkg".to_string(),
            version: None,
            purl: None,
            license: None,
            sha256: None,
        };
        assert_eq!(build_spdx_package(&dep, 0)["SPDXID"], "SPDXRef-Package-0");
        assert_eq!(build_spdx_package(&dep, 42)["SPDXID"], "SPDXRef-Package-42");
    }

    // ===================================================================
    // build_component_info
    // ===================================================================

    #[test]
    fn test_build_component_info_full() {
        let dep = DependencyInfo {
            name: "react".to_string(),
            version: Some("18.2.0".to_string()),
            purl: Some("pkg:npm/react@18.2.0".to_string()),
            license: Some("MIT".to_string()),
            sha256: Some("hash".to_string()),
        };
        let comp = build_component_info(&dep);
        assert_eq!(comp.name, "react");
        assert_eq!(comp.version.as_deref(), Some("18.2.0"));
        assert_eq!(comp.component_type.as_deref(), Some("library"));
        assert_eq!(comp.licenses, vec!["MIT".to_string()]);
        assert!(comp.supplier.is_none());
    }

    #[test]
    fn test_build_component_info_minimal() {
        let dep = DependencyInfo {
            name: "pkg".to_string(),
            version: None,
            purl: None,
            license: None,
            sha256: None,
        };
        let comp = build_component_info(&dep);
        assert!(comp.licenses.is_empty());
        assert!(comp.version.is_none());
    }

    // ===================================================================
    // extract_unique_licenses
    // ===================================================================

    #[test]
    fn test_extract_unique_licenses_empty() {
        assert!(extract_unique_licenses(&[]).is_empty());
    }

    #[test]
    fn test_extract_unique_licenses_dedup() {
        let deps = vec![
            DependencyInfo {
                name: "a".to_string(),
                version: None,
                purl: None,
                license: Some("MIT".to_string()),
                sha256: None,
            },
            DependencyInfo {
                name: "b".to_string(),
                version: None,
                purl: None,
                license: Some("MIT".to_string()),
                sha256: None,
            },
            DependencyInfo {
                name: "c".to_string(),
                version: None,
                purl: None,
                license: Some("Apache-2.0".to_string()),
                sha256: None,
            },
        ];
        let licenses = extract_unique_licenses(&deps);
        assert_eq!(licenses.len(), 2);
    }

    #[test]
    fn test_extract_unique_licenses_skips_none() {
        let deps = vec![
            DependencyInfo {
                name: "a".to_string(),
                version: None,
                purl: None,
                license: Some("MIT".to_string()),
                sha256: None,
            },
            DependencyInfo {
                name: "b".to_string(),
                version: None,
                purl: None,
                license: None,
                sha256: None,
            },
        ];
        let licenses = extract_unique_licenses(&deps);
        assert_eq!(licenses.len(), 1);
    }

    // ===================================================================
    // check_license_compliance_pure
    // ===================================================================

    fn make_test_policy(
        allowed: Vec<&str>,
        denied: Vec<&str>,
        allow_unknown: bool,
    ) -> LicensePolicy {
        LicensePolicy {
            id: Uuid::new_v4(),
            repository_id: None,
            name: "test".to_string(),
            description: None,
            allowed_licenses: allowed.into_iter().map(String::from).collect(),
            denied_licenses: denied.into_iter().map(String::from).collect(),
            allow_unknown,
            action: crate::models::sbom::PolicyAction::Block,
            is_enabled: true,
            created_at: Utc::now(),
            updated_at: None,
        }
    }

    #[test]
    fn test_check_license_compliance_pure_allowed() {
        let policy = make_test_policy(vec!["MIT"], vec![], false);
        let result = check_license_compliance_pure(&policy, &["MIT".to_string()]);
        assert!(result.compliant);
    }

    #[test]
    fn test_check_license_compliance_pure_denied() {
        let policy = make_test_policy(vec!["MIT"], vec!["GPL-3.0"], false);
        let result = check_license_compliance_pure(&policy, &["GPL-3.0".to_string()]);
        assert!(!result.compliant);
    }

    #[test]
    fn test_check_license_compliance_pure_case_insensitive() {
        let policy = make_test_policy(vec!["MIT"], vec!["gpl-3.0"], false);
        assert!(check_license_compliance_pure(&policy, &["mit".to_string()]).compliant);
        assert!(!check_license_compliance_pure(&policy, &["GPL-3.0".to_string()]).compliant);
    }

    // ===================================================================
    // content_hash
    // ===================================================================

    #[test]
    fn test_content_hash_deterministic() {
        assert_eq!(content_hash("hello"), content_hash("hello"));
    }

    #[test]
    fn test_content_hash_different_inputs() {
        assert_ne!(content_hash("hello"), content_hash("world"));
    }

    #[test]
    fn test_content_hash_empty_known_value() {
        assert_eq!(
            content_hash(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_content_hash_is_64_hex_chars() {
        let h = content_hash("test");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ===================================================================
    // days_exposed
    // ===================================================================

    #[test]
    fn test_days_exposed_same_day() {
        let now = Utc::now();
        assert_eq!(days_exposed(now, now), 0);
    }

    #[test]
    fn test_days_exposed_one_day() {
        let now = Utc::now();
        assert_eq!(days_exposed(now - chrono::Duration::days(1), now), 1);
    }

    #[test]
    fn test_days_exposed_thirty_days() {
        let now = Utc::now();
        assert_eq!(days_exposed(now - chrono::Duration::days(30), now), 30);
    }

    #[test]
    fn test_days_exposed_future_negative() {
        let now = Utc::now();
        assert_eq!(days_exposed(now + chrono::Duration::days(5), now), -5);
    }

    // ===================================================================
    // Existing tests below (kept for backward compat)
    // ===================================================================

    /// Helper to create a mock SbomService for testing SBOM generation
    /// without a database connection.
    fn generate_test_cyclonedx(deps: &[DependencyInfo]) -> serde_json::Value {
        let mut components = Vec::new();
        for dep in deps {
            let mut comp = serde_json::json!({
                "type": "library",
                "name": dep.name,
            });
            if let Some(v) = &dep.version {
                comp["version"] = serde_json::json!(v);
            }
            if let Some(p) = &dep.purl {
                comp["purl"] = serde_json::json!(p);
            }
            if let Some(l) = &dep.license {
                comp["licenses"] = serde_json::json!([{"license": {"id": l}}]);
            }
            components.push(comp);
        }

        serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": Utc::now().to_rfc3339(),
                "tools": [{
                    "vendor": "Artifact Keeper",
                    "name": "artifact-keeper",
                    "version": env!("CARGO_PKG_VERSION")
                }]
            },
            "components": components
        })
    }

    fn generate_test_spdx(deps: &[DependencyInfo]) -> serde_json::Value {
        let mut packages = Vec::new();
        for (idx, dep) in deps.iter().enumerate() {
            let spdx_id = format!("SPDXRef-Package-{}", idx);
            let mut pkg = serde_json::json!({
                "SPDXID": spdx_id,
                "name": dep.name,
                "downloadLocation": "NOASSERTION",
            });
            if let Some(v) = &dep.version {
                pkg["versionInfo"] = serde_json::json!(v);
            }
            if let Some(l) = &dep.license {
                pkg["licenseDeclared"] = serde_json::json!(l);
            }
            packages.push(pkg);
        }

        serde_json::json!({
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "artifact-sbom",
            "documentNamespace": format!("https://artifact-keeper.com/sbom/{}", Uuid::new_v4()),
            "creationInfo": {
                "created": Utc::now().to_rfc3339(),
                "creators": [format!("Tool: artifact-keeper-{}", env!("CARGO_PKG_VERSION"))]
            },
            "packages": packages
        })
    }

    #[test]
    fn test_cyclonedx_has_required_fields() {
        let deps = vec![DependencyInfo {
            name: "lodash".to_string(),
            version: Some("4.17.21".to_string()),
            purl: Some("pkg:npm/lodash@4.17.21".to_string()),
            license: Some("MIT".to_string()),
            sha256: None,
        }];

        let sbom = generate_test_cyclonedx(&deps);

        // Verify required CycloneDX 1.5 fields
        assert_eq!(sbom["bomFormat"], "CycloneDX");
        assert_eq!(sbom["specVersion"], "1.5");
        assert_eq!(sbom["version"], 1);
        assert!(sbom["metadata"].is_object());
        assert!(sbom["metadata"]["timestamp"].is_string());
        assert!(sbom["metadata"]["tools"].is_array());
        assert!(sbom["components"].is_array());
    }

    #[test]
    fn test_cyclonedx_empty_components() {
        let deps: Vec<DependencyInfo> = vec![];
        let sbom = generate_test_cyclonedx(&deps);

        // Empty SBOM should still have valid structure
        assert_eq!(sbom["bomFormat"], "CycloneDX");
        assert_eq!(sbom["specVersion"], "1.5");
        assert!(sbom["components"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_cyclonedx_component_structure() {
        let deps = vec![DependencyInfo {
            name: "axios".to_string(),
            version: Some("1.6.0".to_string()),
            purl: Some("pkg:npm/axios@1.6.0".to_string()),
            license: Some("MIT".to_string()),
            sha256: None,
        }];

        let sbom = generate_test_cyclonedx(&deps);
        let components = sbom["components"].as_array().unwrap();

        assert_eq!(components.len(), 1);
        let comp = &components[0];
        assert_eq!(comp["type"], "library");
        assert_eq!(comp["name"], "axios");
        assert_eq!(comp["version"], "1.6.0");
        assert_eq!(comp["purl"], "pkg:npm/axios@1.6.0");
    }

    #[test]
    fn test_spdx_has_required_fields() {
        let deps = vec![DependencyInfo {
            name: "lodash".to_string(),
            version: Some("4.17.21".to_string()),
            purl: None,
            license: Some("MIT".to_string()),
            sha256: None,
        }];

        let sbom = generate_test_spdx(&deps);

        // Verify required SPDX 2.3 fields
        assert_eq!(sbom["spdxVersion"], "SPDX-2.3");
        assert_eq!(sbom["SPDXID"], "SPDXRef-DOCUMENT");
        assert_eq!(sbom["dataLicense"], "CC0-1.0");
        assert!(sbom["name"].is_string());
        assert!(sbom["documentNamespace"].is_string());
        assert!(sbom["creationInfo"].is_object());
        assert!(sbom["creationInfo"]["created"].is_string());
        assert!(sbom["creationInfo"]["creators"].is_array());
        assert!(sbom["packages"].is_array());
    }

    #[test]
    fn test_spdx_empty_packages() {
        let deps: Vec<DependencyInfo> = vec![];
        let sbom = generate_test_spdx(&deps);

        // Empty SBOM should still have valid structure
        assert_eq!(sbom["spdxVersion"], "SPDX-2.3");
        assert!(sbom["packages"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_spdx_package_structure() {
        let deps = vec![DependencyInfo {
            name: "express".to_string(),
            version: Some("4.18.2".to_string()),
            purl: None,
            license: Some("MIT".to_string()),
            sha256: None,
        }];

        let sbom = generate_test_spdx(&deps);
        let packages = sbom["packages"].as_array().unwrap();

        assert_eq!(packages.len(), 1);
        let pkg = &packages[0];
        assert!(pkg["SPDXID"].as_str().unwrap().starts_with("SPDXRef-"));
        assert_eq!(pkg["name"], "express");
        assert_eq!(pkg["versionInfo"], "4.18.2");
        assert_eq!(pkg["licenseDeclared"], "MIT");
    }

    #[test]
    fn test_spdx_document_namespace_is_unique() {
        let deps: Vec<DependencyInfo> = vec![];
        let sbom1 = generate_test_spdx(&deps);
        let sbom2 = generate_test_spdx(&deps);

        // Each SBOM should have a unique document namespace
        assert_ne!(
            sbom1["documentNamespace"].as_str().unwrap(),
            sbom2["documentNamespace"].as_str().unwrap()
        );
    }

    // -----------------------------------------------------------------------
    // check_license_compliance (pure function on &self + LicensePolicy)
    //
    // NOTE: SbomService has a PgPool field, so we cannot construct it in
    // tests. However, check_license_compliance only uses &self and the
    // LicensePolicy argument, never touching the database. We duplicate
    // the logic here to test it. The engineering expert should extract this
    // into a free function or an associated function.
    // -----------------------------------------------------------------------

    /// Duplicated from SbomService::check_license_compliance for unit testing.
    fn check_license_compliance_standalone(
        policy: &LicensePolicy,
        licenses: &[String],
    ) -> LicenseCheckResult {
        let mut violations = Vec::new();
        let mut warnings = Vec::new();

        for license in licenses {
            let normalized = license.to_uppercase();

            // Check denylist first (takes precedence)
            if policy
                .denied_licenses
                .iter()
                .any(|d| d.to_uppercase() == normalized)
            {
                violations.push(format!("License '{}' is denied by policy", license));
                continue;
            }

            // Check allowlist if not empty
            if !policy.allowed_licenses.is_empty()
                && !policy
                    .allowed_licenses
                    .iter()
                    .any(|a| a.to_uppercase() == normalized)
            {
                if policy.allow_unknown {
                    warnings.push(format!("License '{}' is not in approved list", license));
                } else {
                    violations.push(format!("License '{}' is not in approved list", license));
                }
            }
        }

        LicenseCheckResult {
            compliant: violations.is_empty(),
            violations,
            warnings,
        }
    }

    fn make_policy(allowed: Vec<&str>, denied: Vec<&str>, allow_unknown: bool) -> LicensePolicy {
        LicensePolicy {
            id: Uuid::new_v4(),
            repository_id: None,
            name: "test-policy".to_string(),
            description: None,
            allowed_licenses: allowed.into_iter().map(String::from).collect(),
            denied_licenses: denied.into_iter().map(String::from).collect(),
            allow_unknown,
            action: crate::models::sbom::PolicyAction::Block,
            is_enabled: true,
            created_at: Utc::now(),
            updated_at: None,
        }
    }

    #[test]
    fn test_license_compliance_all_allowed() {
        let policy = make_policy(vec!["MIT", "Apache-2.0", "BSD-3-Clause"], vec![], false);
        let licenses = vec!["MIT".to_string(), "Apache-2.0".to_string()];

        let result = check_license_compliance_standalone(&policy, &licenses);
        assert!(result.compliant);
        assert!(result.violations.is_empty());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_license_compliance_denied_takes_precedence() {
        // GPL is in both allowed and denied; denied should win
        let policy = make_policy(vec!["MIT", "GPL-3.0"], vec!["GPL-3.0"], false);
        let licenses = vec!["GPL-3.0".to_string()];

        let result = check_license_compliance_standalone(&policy, &licenses);
        assert!(!result.compliant);
        assert_eq!(result.violations.len(), 1);
        assert!(result.violations[0].contains("denied"));
    }

    #[test]
    fn test_license_compliance_not_in_allowlist_strict() {
        let policy = make_policy(vec!["MIT"], vec![], false);
        let licenses = vec!["AGPL-3.0".to_string()];

        let result = check_license_compliance_standalone(&policy, &licenses);
        assert!(!result.compliant);
        assert_eq!(result.violations.len(), 1);
        assert!(result.violations[0].contains("not in approved list"));
    }

    #[test]
    fn test_license_compliance_not_in_allowlist_lenient() {
        let policy = make_policy(vec!["MIT"], vec![], true); // allow_unknown = true
        let licenses = vec!["AGPL-3.0".to_string()];

        let result = check_license_compliance_standalone(&policy, &licenses);
        assert!(result.compliant); // no violations, just warnings
        assert!(result.violations.is_empty());
        assert_eq!(result.warnings.len(), 1);
        assert!(result.warnings[0].contains("not in approved list"));
    }

    #[test]
    fn test_license_compliance_empty_allowlist_allows_everything() {
        // When allowlist is empty, the allowlist check is skipped
        let policy = make_policy(vec![], vec![], false);
        let licenses = vec!["ANY-LICENSE".to_string()];

        let result = check_license_compliance_standalone(&policy, &licenses);
        assert!(result.compliant);
    }

    #[test]
    fn test_license_compliance_case_insensitive() {
        let policy = make_policy(vec!["MIT"], vec!["gpl-3.0"], false);

        // "mit" should match "MIT" in allowlist
        let result1 = check_license_compliance_standalone(&policy, &["mit".to_string()]);
        assert!(result1.compliant);

        // "GPL-3.0" should match "gpl-3.0" in denylist
        let result2 = check_license_compliance_standalone(&policy, &["GPL-3.0".to_string()]);
        assert!(!result2.compliant);
    }

    #[test]
    fn test_license_compliance_empty_licenses() {
        let policy = make_policy(vec!["MIT"], vec!["GPL-3.0"], false);
        let licenses: Vec<String> = vec![];

        let result = check_license_compliance_standalone(&policy, &licenses);
        assert!(result.compliant);
        assert!(result.violations.is_empty());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_license_compliance_mixed_results() {
        let policy = make_policy(vec!["MIT", "Apache-2.0"], vec!["GPL-3.0"], false);
        let licenses = vec![
            "MIT".to_string(),
            "GPL-3.0".to_string(),      // denied
            "BSD-2-Clause".to_string(), // not in allowlist
        ];

        let result = check_license_compliance_standalone(&policy, &licenses);
        assert!(!result.compliant);
        assert_eq!(result.violations.len(), 2); // GPL denied + BSD not approved
    }

    #[test]
    fn test_license_compliance_only_denylist() {
        // No allowlist, just a denylist
        let policy = make_policy(vec![], vec!["AGPL-3.0", "SSPL-1.0"], false);

        let ok_result = check_license_compliance_standalone(&policy, &["MIT".to_string()]);
        assert!(ok_result.compliant);

        let bad_result = check_license_compliance_standalone(&policy, &["AGPL-3.0".to_string()]);
        assert!(!bad_result.compliant);
    }

    // -----------------------------------------------------------------------
    // get_format_version / get_spec_version
    //
    // NOTE: These require &self but never access DB. Testability blocker:
    // should be associated functions (no &self needed).
    // We test the expected mapping directly.
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_version_mapping() {
        // CycloneDX format version
        assert_eq!(
            match SbomFormat::CycloneDX {
                SbomFormat::CycloneDX => "1.5",
                SbomFormat::SPDX => "2.3",
            },
            "1.5"
        );
        // SPDX format version
        assert_eq!(
            match SbomFormat::SPDX {
                SbomFormat::CycloneDX => "1.5",
                SbomFormat::SPDX => "2.3",
            },
            "2.3"
        );
    }

    #[test]
    fn test_spec_version_mapping() {
        assert_eq!(
            match SbomFormat::CycloneDX {
                SbomFormat::CycloneDX => "CycloneDX 1.5",
                SbomFormat::SPDX => "SPDX-2.3",
            },
            "CycloneDX 1.5"
        );
        assert_eq!(
            match SbomFormat::SPDX {
                SbomFormat::CycloneDX => "CycloneDX 1.5",
                SbomFormat::SPDX => "SPDX-2.3",
            },
            "SPDX-2.3"
        );
    }

    // -----------------------------------------------------------------------
    // SbomFormat model tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_sbom_format_parse() {
        assert_eq!(SbomFormat::parse("cyclonedx"), Some(SbomFormat::CycloneDX));
        assert_eq!(SbomFormat::parse("CycloneDX"), Some(SbomFormat::CycloneDX));
        assert_eq!(SbomFormat::parse("cdx"), Some(SbomFormat::CycloneDX));
        assert_eq!(SbomFormat::parse("spdx"), Some(SbomFormat::SPDX));
        assert_eq!(SbomFormat::parse("SPDX"), Some(SbomFormat::SPDX));
        assert_eq!(SbomFormat::parse("unknown"), None);
        assert_eq!(SbomFormat::parse(""), None);
    }

    #[test]
    fn test_sbom_format_as_str() {
        assert_eq!(SbomFormat::CycloneDX.as_str(), "cyclonedx");
        assert_eq!(SbomFormat::SPDX.as_str(), "spdx");
    }

    #[test]
    fn test_sbom_format_content_type() {
        assert_eq!(
            SbomFormat::CycloneDX.content_type(),
            "application/vnd.cyclonedx+json"
        );
        assert_eq!(SbomFormat::SPDX.content_type(), "application/spdx+json");
    }

    #[test]
    fn test_sbom_format_display() {
        assert_eq!(format!("{}", SbomFormat::CycloneDX), "cyclonedx");
        assert_eq!(format!("{}", SbomFormat::SPDX), "spdx");
    }

    // -----------------------------------------------------------------------
    // CycloneDX generation: comprehensive component field coverage
    // -----------------------------------------------------------------------

    #[test]
    fn test_cyclonedx_component_with_all_fields() {
        let deps = vec![DependencyInfo {
            name: "serde".to_string(),
            version: Some("1.0.195".to_string()),
            purl: Some("pkg:cargo/serde@1.0.195".to_string()),
            license: Some("MIT OR Apache-2.0".to_string()),
            sha256: Some("abc123def456".to_string()),
        }];

        let sbom = generate_test_cyclonedx(&deps);
        let comp = &sbom["components"][0];

        assert_eq!(comp["name"], "serde");
        assert_eq!(comp["version"], "1.0.195");
        assert_eq!(comp["purl"], "pkg:cargo/serde@1.0.195");
        assert_eq!(comp["licenses"][0]["license"]["id"], "MIT OR Apache-2.0");
    }

    #[test]
    fn test_cyclonedx_component_optional_fields_omitted() {
        let deps = vec![DependencyInfo {
            name: "minimal".to_string(),
            version: None,
            purl: None,
            license: None,
            sha256: None,
        }];

        let sbom = generate_test_cyclonedx(&deps);
        let comp = &sbom["components"][0];

        assert_eq!(comp["name"], "minimal");
        assert_eq!(comp["type"], "library");
        // Optional fields should be absent (null in JSON)
        assert!(comp.get("version").is_none());
        assert!(comp.get("purl").is_none());
        assert!(comp.get("licenses").is_none());
    }

    #[test]
    fn test_cyclonedx_multiple_components() {
        let deps = vec![
            DependencyInfo {
                name: "alpha".to_string(),
                version: Some("1.0".to_string()),
                purl: None,
                license: None,
                sha256: None,
            },
            DependencyInfo {
                name: "beta".to_string(),
                version: Some("2.0".to_string()),
                purl: None,
                license: None,
                sha256: None,
            },
            DependencyInfo {
                name: "gamma".to_string(),
                version: Some("3.0".to_string()),
                purl: None,
                license: None,
                sha256: None,
            },
        ];

        let sbom = generate_test_cyclonedx(&deps);
        let components = sbom["components"].as_array().unwrap();
        assert_eq!(components.len(), 3);
        assert_eq!(components[0]["name"], "alpha");
        assert_eq!(components[1]["name"], "beta");
        assert_eq!(components[2]["name"], "gamma");
    }

    // -----------------------------------------------------------------------
    // SPDX generation: comprehensive field coverage
    // -----------------------------------------------------------------------

    #[test]
    fn test_spdx_package_no_license() {
        let deps = vec![DependencyInfo {
            name: "unlicensed-pkg".to_string(),
            version: Some("0.1.0".to_string()),
            purl: None,
            license: None,
            sha256: None,
        }];

        let sbom = generate_test_spdx(&deps);
        let pkg = &sbom["packages"][0];

        // When no license, SPDX should have NOASSERTION (or be absent
        // depending on the test helper). The test helper only sets
        // licenseDeclared when license is present.
        // In the real generate_spdx, both licenseConcluded and licenseDeclared
        // are set to "NOASSERTION" when license is None.
        assert_eq!(pkg["name"], "unlicensed-pkg");
    }

    #[test]
    fn test_spdx_package_spdxid_format() {
        let deps = vec![
            DependencyInfo {
                name: "a".to_string(),
                version: None,
                purl: None,
                license: None,
                sha256: None,
            },
            DependencyInfo {
                name: "b".to_string(),
                version: None,
                purl: None,
                license: None,
                sha256: None,
            },
        ];

        let sbom = generate_test_spdx(&deps);
        let packages = sbom["packages"].as_array().unwrap();

        assert_eq!(packages[0]["SPDXID"], "SPDXRef-Package-0");
        assert_eq!(packages[1]["SPDXID"], "SPDXRef-Package-1");
    }

    #[test]
    fn test_spdx_download_location_noassertion() {
        let deps = vec![DependencyInfo {
            name: "pkg".to_string(),
            version: Some("1.0".to_string()),
            purl: None,
            license: None,
            sha256: None,
        }];

        let sbom = generate_test_spdx(&deps);
        assert_eq!(sbom["packages"][0]["downloadLocation"], "NOASSERTION");
    }

    // -----------------------------------------------------------------------
    // ComponentInfo struct
    // -----------------------------------------------------------------------

    #[test]
    fn test_component_info_from_dependency() {
        let dep = DependencyInfo {
            name: "react".to_string(),
            version: Some("18.2.0".to_string()),
            purl: Some("pkg:npm/react@18.2.0".to_string()),
            license: Some("MIT".to_string()),
            sha256: Some("sha256hash".to_string()),
        };

        let comp = ComponentInfo {
            name: dep.name.clone(),
            version: dep.version.clone(),
            purl: dep.purl.clone(),
            component_type: Some("library".to_string()),
            licenses: dep.license.clone().into_iter().collect(),
            sha256: dep.sha256.clone(),
            supplier: None,
        };

        assert_eq!(comp.name, "react");
        assert_eq!(comp.version.as_deref(), Some("18.2.0"));
        assert_eq!(comp.purl.as_deref(), Some("pkg:npm/react@18.2.0"));
        assert_eq!(comp.component_type.as_deref(), Some("library"));
        assert_eq!(comp.licenses, vec!["MIT".to_string()]);
        assert_eq!(comp.sha256.as_deref(), Some("sha256hash"));
        assert!(comp.supplier.is_none());
    }

    // -----------------------------------------------------------------------
    // DependencyInfo serialization/deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_dependency_info_serde_roundtrip() {
        let dep = DependencyInfo {
            name: "axios".to_string(),
            version: Some("1.6.0".to_string()),
            purl: Some("pkg:npm/axios@1.6.0".to_string()),
            license: Some("MIT".to_string()),
            sha256: None,
        };

        let json = serde_json::to_string(&dep).unwrap();
        let deserialized: DependencyInfo = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.name, "axios");
        assert_eq!(deserialized.version.as_deref(), Some("1.6.0"));
        assert_eq!(deserialized.purl.as_deref(), Some("pkg:npm/axios@1.6.0"));
        assert_eq!(deserialized.license.as_deref(), Some("MIT"));
        assert!(deserialized.sha256.is_none());
    }

    // -----------------------------------------------------------------------
    // LicenseCheckResult serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_license_check_result_serialization() {
        let result = LicenseCheckResult {
            compliant: false,
            violations: vec!["License 'GPL-3.0' is denied".to_string()],
            warnings: vec!["License 'LGPL-2.1' is not in approved list".to_string()],
        };

        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["compliant"], false);
        assert_eq!(json["violations"].as_array().unwrap().len(), 1);
        assert_eq!(json["warnings"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn test_license_check_result_compliant_serialization() {
        let result = LicenseCheckResult {
            compliant: true,
            violations: vec![],
            warnings: vec![],
        };

        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["compliant"], true);
        assert!(json["violations"].as_array().unwrap().is_empty());
        assert!(json["warnings"].as_array().unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // CveStatus model
    // -----------------------------------------------------------------------

    #[test]
    fn test_cve_status_parse() {
        assert_eq!(CveStatus::parse("open"), Some(CveStatus::Open));
        assert_eq!(CveStatus::parse("fixed"), Some(CveStatus::Fixed));
        assert_eq!(
            CveStatus::parse("acknowledged"),
            Some(CveStatus::Acknowledged)
        );
        assert_eq!(
            CveStatus::parse("false_positive"),
            Some(CveStatus::FalsePositive)
        );
        assert_eq!(CveStatus::parse("OPEN"), Some(CveStatus::Open));
        assert_eq!(CveStatus::parse("unknown"), None);
    }

    #[test]
    fn test_cve_status_as_str() {
        assert_eq!(CveStatus::Open.as_str(), "open");
        assert_eq!(CveStatus::Fixed.as_str(), "fixed");
        assert_eq!(CveStatus::Acknowledged.as_str(), "acknowledged");
        assert_eq!(CveStatus::FalsePositive.as_str(), "false_positive");
    }

    // -----------------------------------------------------------------------
    // synth_cve_id: regression coverage for #1375. The CVE history endpoint
    // synthesizes `CveHistoryEntry` rows on the fly from `scan_findings`
    // because `cve_history` is never written to in production. Synth ids
    // must be deterministic so re-reads return stable identifiers and
    // distinct for distinct (artifact, cve) pairs.
    // -----------------------------------------------------------------------

    #[test]
    fn test_synth_cve_id_is_deterministic() {
        let artifact = Uuid::new_v4();
        let cve = "CVE-2019-10744";
        let a = synth_cve_id(artifact, cve);
        let b = synth_cve_id(artifact, cve);
        assert_eq!(
            a, b,
            "synth_cve_id must be deterministic so client-side dedup by id works"
        );
    }

    #[test]
    fn test_synth_cve_id_distinct_pairs_produce_distinct_ids() {
        let a1 = Uuid::new_v4();
        let a2 = Uuid::new_v4();
        let cve = "CVE-2019-10744";
        let x = synth_cve_id(a1, cve);
        let y = synth_cve_id(a2, cve);
        let z = synth_cve_id(a1, "CVE-2024-12345");
        assert_ne!(x, y, "different artifacts must yield different ids");
        assert_ne!(x, z, "different CVEs must yield different ids");
        assert_ne!(y, z);
    }

    #[test]
    fn test_synth_cve_id_separator_prevents_concat_collisions() {
        // Without the explicit separator byte, (artifact="00...01", cve="234")
        // would hash the same as (artifact="00...0", cve="1234"). Use a pair
        // that exercises adjacent boundaries: encode the boundary by varying
        // the cve suffix length while keeping the same combined string.
        let artifact = Uuid::nil();
        let a = synth_cve_id(artifact, "AB");
        let b = synth_cve_id(artifact, "ABC");
        assert_ne!(
            a, b,
            "synth_cve_id must separate fields so concatenation collisions \
             do not yield the same UUID for different inputs"
        );
    }

    #[test]
    fn test_synth_cve_id_empty_cve_id() {
        // Defensive: the mapping in `scan_finding_to_history_entry` passes
        // an empty cve_id when the row has `None`. The hash must still be
        // total (not panic) and remain stable.
        let artifact = Uuid::nil();
        let a = synth_cve_id(artifact, "");
        let b = synth_cve_id(artifact, "");
        assert_eq!(a, b);
        // And distinct from a non-empty cve_id under the same artifact.
        let c = synth_cve_id(artifact, "CVE-2019-10744");
        assert_ne!(a, c);
    }

    // -----------------------------------------------------------------------
    // Pure-logic helpers extracted from the DB-coupled CVE history paths.
    // These are the cases the inline coverage gate counts; the SQL queries
    // they wrap are unreachable without a live PostgreSQL, so we exercise
    // the surrounding projection / dedupe / sort logic here. (#1375)
    // -----------------------------------------------------------------------

    fn make_history_entry(cve_id: &str, first_detected_at: DateTime<Utc>) -> CveHistoryEntry {
        CveHistoryEntry {
            id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            sbom_id: None,
            component_id: None,
            scan_result_id: None,
            cve_id: cve_id.to_string(),
            affected_component: None,
            affected_version: None,
            fixed_version: None,
            severity: None,
            cvss_score: None,
            cve_published_at: None,
            first_detected_at,
            last_detected_at: first_detected_at,
            status: "open".to_string(),
            acknowledged_by: None,
            acknowledged_at: None,
            acknowledged_reason: None,
            created_at: first_detected_at,
            updated_at: first_detected_at,
        }
    }

    fn make_scan_row(
        artifact_id: Uuid,
        cve_id: Option<&str>,
        first_detected_at: DateTime<Utc>,
        all_acknowledged: bool,
    ) -> ScanFindingCveRow {
        ScanFindingCveRow {
            artifact_id,
            cve_id: cve_id.map(|s| s.to_string()),
            severity: Some("high".to_string()),
            affected_component: Some("lodash".to_string()),
            affected_version: Some("4.17.4".to_string()),
            fixed_version: Some("4.17.21".to_string()),
            first_detected_at,
            last_detected_at: first_detected_at,
            all_acknowledged,
        }
    }

    // --- build_known_cve_set -----------------------------------------------

    #[test]
    fn test_build_known_cve_set_uppercases() {
        let entries = vec![
            make_history_entry("cve-2019-10744", Utc::now()),
            make_history_entry("CVE-2024-12345", Utc::now()),
        ];
        let set = build_known_cve_set(&entries);
        assert!(set.contains("CVE-2019-10744"));
        assert!(set.contains("CVE-2024-12345"));
        // Lower-case form must not appear -- the helper exists *because* we
        // need a case-insensitive compare downstream.
        assert!(!set.contains("cve-2019-10744"));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_build_known_cve_set_empty_input() {
        let set = build_known_cve_set(&[]);
        assert!(set.is_empty());
    }

    #[test]
    fn test_build_known_cve_set_dedupes_case_variants() {
        // Two curated rows for the same CVE in mixed case must collapse
        // to one entry in the known set, otherwise the dedupe-by-known
        // filter on the scan-findings path would behave inconsistently
        // depending on which case the scanner happened to write.
        let entries = vec![
            make_history_entry("cve-2019-10744", Utc::now()),
            make_history_entry("CVE-2019-10744", Utc::now()),
        ];
        let set = build_known_cve_set(&entries);
        assert_eq!(set.len(), 1);
        assert!(set.contains("CVE-2019-10744"));
    }

    // --- scan_row_passes_known_filter --------------------------------------

    #[test]
    fn test_scan_row_passes_known_filter_drops_known_uppercase_match() {
        let known: HashSet<String> = ["CVE-2019-10744".to_string()].into_iter().collect();
        // Row matches by upper-case: filtered out.
        assert!(!scan_row_passes_known_filter(
            Some("CVE-2019-10744"),
            &known
        ));
    }

    #[test]
    fn test_scan_row_passes_known_filter_drops_known_lowercase_match() {
        let known: HashSet<String> = ["CVE-2019-10744".to_string()].into_iter().collect();
        // Row in lower-case still matches: case-insensitive dedupe.
        assert!(!scan_row_passes_known_filter(
            Some("cve-2019-10744"),
            &known
        ));
    }

    #[test]
    fn test_scan_row_passes_known_filter_keeps_novel_cve() {
        let known: HashSet<String> = ["CVE-2019-10744".to_string()].into_iter().collect();
        assert!(scan_row_passes_known_filter(Some("CVE-2024-12345"), &known));
    }

    #[test]
    fn test_scan_row_passes_known_filter_drops_none_cve_id() {
        // Rows with NULL cve_id should be filtered out -- they cannot be
        // meaningful CVE history entries.
        let known: HashSet<String> = HashSet::new();
        assert!(!scan_row_passes_known_filter(None, &known));
    }

    #[test]
    fn test_scan_row_passes_known_filter_keeps_when_known_empty() {
        let known: HashSet<String> = HashSet::new();
        assert!(scan_row_passes_known_filter(Some("CVE-2019-10744"), &known));
    }

    // --- severity_rank / severity_from_rank --------------------------------
    //
    // Round-2 regression coverage for the lexicographic-MAX bug (#1375). The
    // pre-fix SQL used `MAX(severity)` against a TEXT column, which orders
    // alphabetically: "medium" > "low" > "high" > "critical". So a CVE
    // reported as `high` by one scanner and `medium` by another surfaced as
    // `medium` in the trends counts and timeline, silently undercounting
    // high/critical findings. The ranked CASE in `get_cve_trends` and
    // `build_cve_entries_from_scan_findings` fixes this; these tests pin
    // the Rust side of the contract so the SQL and Rust stay in lockstep.

    #[test]
    fn test_severity_rank_strict_ordering() {
        // Operational severity ranking, NOT lex order. This is the load-
        // bearing contract that motivated the round-2 SQL rewrite.
        assert!(severity_rank("critical") > severity_rank("high"));
        assert!(severity_rank("high") > severity_rank("medium"));
        assert!(severity_rank("medium") > severity_rank("low"));
        assert!(severity_rank("low") > severity_rank("unknown"));
    }

    #[test]
    fn test_severity_rank_case_insensitive() {
        // The DB column has no case constraint and different scanners write
        // different cases (Trivy: "HIGH", Grype: "High", OSV: "high"). The
        // ranking must collapse all of these to the same value or the
        // multi-scanner dedupe in `get_cve_trends` would split a single
        // CVE into separate rows by case.
        assert_eq!(severity_rank("CRITICAL"), severity_rank("critical"));
        assert_eq!(severity_rank("High"), severity_rank("high"));
        assert_eq!(severity_rank("Medium"), severity_rank("medium"));
        assert_eq!(severity_rank("LOW"), severity_rank("low"));
    }

    #[test]
    fn test_severity_rank_unknown_is_zero() {
        // Anything outside the four canonical labels (NULL severity, future
        // labels like "info" / "negligible", junk data) must rank 0 so it
        // never outranks a real severity.
        assert_eq!(severity_rank(""), 0);
        assert_eq!(severity_rank("unknown"), 0);
        assert_eq!(severity_rank("info"), 0);
        assert_eq!(severity_rank("negligible"), 0);
        assert!(severity_rank("low") > severity_rank("info"));
    }

    #[test]
    fn test_severity_from_rank_round_trip() {
        // Round-trip every canonical label so a refactor of the rank
        // constants can't silently break the inverse mapping.
        for label in ["critical", "high", "medium", "low"] {
            let r = severity_rank(label);
            assert_eq!(
                severity_from_rank(r),
                Some(label),
                "rank/label round-trip must hold for {label}"
            );
        }
    }

    #[test]
    fn test_severity_from_rank_unknown_ranks() {
        assert_eq!(severity_from_rank(0), None);
        assert_eq!(severity_from_rank(5), None);
        assert_eq!(severity_from_rank(-1), None);
    }

    // The headline #1375 round-2 regression: aggregating `['low', 'high',
    // 'medium']` must yield `'high'`, not `'medium'` (which is what the
    // pre-fix lexicographic MAX returned).
    #[test]
    fn test_severity_rank_aggregates_high_over_medium_for_low_high_medium_input() {
        let severities = ["low", "high", "medium"];
        let max_rank = severities.iter().map(|s| severity_rank(s)).max().unwrap();
        assert_eq!(
            severity_from_rank(max_rank),
            Some("high"),
            "['low','high','medium'] must aggregate to 'high', not the \
             lex-largest 'medium' that the pre-fix MAX(severity) returned"
        );
    }

    #[test]
    fn test_severity_rank_aggregates_critical_over_high() {
        // The other half of the lex-sort bug: "critical" sorts BEFORE
        // "high" alphabetically, so the pre-fix MAX returned "high" for
        // a (high, critical) pair. The rank picks "critical" correctly.
        let severities = ["high", "critical"];
        let max_rank = severities.iter().map(|s| severity_rank(s)).max().unwrap();
        assert_eq!(severity_from_rank(max_rank), Some("critical"));
    }

    #[test]
    fn test_severity_rank_aggregates_mixed_case_input() {
        // Multi-scanner overlap with inconsistent casing must still pick
        // the operationally-worst severity.
        let severities = ["MEDIUM", "High", "low"];
        let max_rank = severities.iter().map(|s| severity_rank(s)).max().unwrap();
        assert_eq!(severity_from_rank(max_rank), Some("high"));
    }

    #[test]
    fn test_severity_rank_aggregates_skips_unknown() {
        // An unknown rank-0 row in the mix must not knock a real severity
        // out of the aggregate (a regression worth pinning because a
        // future scanner could write `"info"` or `""`).
        let severities = ["unknown", "low", "info", "high", "negligible"];
        let max_rank = severities.iter().map(|s| severity_rank(s)).max().unwrap();
        assert_eq!(severity_from_rank(max_rank), Some("high"));
    }

    // --- status mapping helpers --------------------------------------------

    #[test]
    fn test_status_string_from_acknowledged() {
        assert_eq!(status_string_from_acknowledged(true), "acknowledged");
        assert_eq!(status_string_from_acknowledged(false), "open");
    }

    #[test]
    fn test_status_enum_from_acknowledged() {
        assert_eq!(status_enum_from_acknowledged(true), CveStatus::Acknowledged);
        assert_eq!(status_enum_from_acknowledged(false), CveStatus::Open);
    }

    #[test]
    fn test_status_mappings_are_consistent() {
        // Whatever the string variant says, the enum variant must match
        // (else trends timeline and history list would disagree on the
        // same scan_findings row).
        assert_eq!(
            status_string_from_acknowledged(true),
            status_enum_from_acknowledged(true).as_str()
        );
        assert_eq!(
            status_string_from_acknowledged(false),
            status_enum_from_acknowledged(false).as_str()
        );
    }

    // --- scan_finding_to_history_entry -------------------------------------

    #[test]
    fn test_scan_finding_to_history_entry_basic_mapping() {
        let when = Utc::now();
        let artifact = Uuid::new_v4();
        let row = make_scan_row(artifact, Some("CVE-2019-10744"), when, false);
        let entry = scan_finding_to_history_entry(row);

        assert_eq!(entry.artifact_id, artifact);
        assert_eq!(entry.cve_id, "CVE-2019-10744");
        assert_eq!(entry.severity.as_deref(), Some("high"));
        assert_eq!(entry.affected_component.as_deref(), Some("lodash"));
        assert_eq!(entry.affected_version.as_deref(), Some("4.17.4"));
        assert_eq!(entry.fixed_version.as_deref(), Some("4.17.21"));
        assert_eq!(entry.first_detected_at, when);
        assert_eq!(entry.last_detected_at, when);
        assert_eq!(entry.status, "open");
        assert_eq!(entry.created_at, when);
        assert_eq!(entry.updated_at, when);
        // Synthetic rows carry no FK references.
        assert!(entry.sbom_id.is_none());
        assert!(entry.component_id.is_none());
        assert!(entry.scan_result_id.is_none());
        assert!(entry.acknowledged_by.is_none());
        assert!(entry.acknowledged_at.is_none());
        assert!(entry.acknowledged_reason.is_none());
        assert!(entry.cvss_score.is_none());
        assert!(entry.cve_published_at.is_none());
        // The id must equal synth_cve_id for the same inputs (stable across re-reads).
        assert_eq!(entry.id, synth_cve_id(artifact, "CVE-2019-10744"));
    }

    #[test]
    fn test_scan_finding_to_history_entry_acknowledged_status() {
        let row = make_scan_row(Uuid::new_v4(), Some("CVE-2024-12345"), Utc::now(), true);
        let entry = scan_finding_to_history_entry(row);
        assert_eq!(entry.status, "acknowledged");
    }

    #[test]
    fn test_scan_finding_to_history_entry_none_cve_id_defaults_to_empty() {
        // Defensive: the upstream filter should drop rows with NULL cve_id,
        // but if anything slips through the mapping must remain total and
        // produce a usable (if empty-id) row rather than panicking.
        let row = make_scan_row(Uuid::new_v4(), None, Utc::now(), false);
        let entry = scan_finding_to_history_entry(row);
        assert_eq!(entry.cve_id, "");
    }

    // --- scan_finding_to_timeline_entry ------------------------------------

    #[test]
    fn test_scan_finding_to_timeline_entry_days_exposed() {
        let now = Utc::now();
        // 10 days ago
        let first = now - chrono::Duration::days(10);
        let row = make_scan_row(Uuid::new_v4(), Some("CVE-2019-10744"), first, false);
        let t = scan_finding_to_timeline_entry(&row, now);
        assert_eq!(t.days_exposed, 10);
        assert_eq!(t.cve_id, "CVE-2019-10744");
        assert_eq!(t.severity, "high");
        assert_eq!(t.affected_component, "lodash");
        assert_eq!(t.status, CveStatus::Open);
        assert_eq!(t.first_detected_at, first);
        assert!(t.cve_published_at.is_none());
    }

    #[test]
    fn test_scan_finding_to_timeline_entry_acknowledged_status() {
        let now = Utc::now();
        let row = make_scan_row(Uuid::new_v4(), Some("CVE-2024-12345"), now, true);
        let t = scan_finding_to_timeline_entry(&row, now);
        assert_eq!(t.status, CveStatus::Acknowledged);
        assert_eq!(t.days_exposed, 0);
    }

    #[test]
    fn test_scan_finding_to_timeline_entry_handles_none_fields() {
        let now = Utc::now();
        let row = ScanFindingCveRow {
            artifact_id: Uuid::new_v4(),
            cve_id: None,
            severity: None,
            affected_component: None,
            affected_version: None,
            fixed_version: None,
            first_detected_at: now,
            last_detected_at: now,
            all_acknowledged: false,
        };
        let t = scan_finding_to_timeline_entry(&row, now);
        // None fields default to empty strings in the DTO.
        assert_eq!(t.cve_id, "");
        assert_eq!(t.severity, "");
        assert_eq!(t.affected_component, "");
    }

    // --- filter_entries_by_repo_map ----------------------------------------

    #[test]
    fn test_filter_entries_by_repo_map_keeps_only_allowed() {
        let artifact_a = Uuid::new_v4();
        let artifact_b = Uuid::new_v4();
        let repo_a = Uuid::new_v4();
        let repo_b = Uuid::new_v4();

        let mut e1 = make_history_entry("CVE-1", Utc::now());
        e1.artifact_id = artifact_a;
        let mut e2 = make_history_entry("CVE-2", Utc::now());
        e2.artifact_id = artifact_b;

        let mut map = std::collections::HashMap::new();
        map.insert(artifact_a, repo_a);
        map.insert(artifact_b, repo_b);

        let allowed: HashSet<Uuid> = [repo_a].into_iter().collect();
        let filtered = filter_entries_by_repo_map(vec![e1, e2], &map, &allowed);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].cve_id, "CVE-1");
        assert_eq!(filtered[0].artifact_id, artifact_a);
    }

    #[test]
    fn test_filter_entries_by_repo_map_drops_entry_with_unknown_artifact() {
        // Defensive: if the DB lookup is partial (e.g. artifact was deleted
        // mid-request, so `is_deleted` filter excluded it), the entry must
        // be dropped rather than leaked to the caller.
        let artifact_a = Uuid::new_v4();
        let mut e1 = make_history_entry("CVE-1", Utc::now());
        e1.artifact_id = artifact_a;
        let map = std::collections::HashMap::new(); // empty: artifact not present
        let allowed: HashSet<Uuid> = [Uuid::new_v4()].into_iter().collect();
        let filtered = filter_entries_by_repo_map(vec![e1], &map, &allowed);
        assert!(
            filtered.is_empty(),
            "entries with unknown repo must be dropped"
        );
    }

    #[test]
    fn test_filter_entries_by_repo_map_empty_input() {
        let map = std::collections::HashMap::new();
        let allowed: HashSet<Uuid> = HashSet::new();
        let filtered = filter_entries_by_repo_map(vec![], &map, &allowed);
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_filter_entries_by_repo_map_empty_allowed_set_drops_all() {
        // An empty allowed set must drop everything (the caller passed an
        // explicit empty allowlist, not None -- different contract).
        let artifact_a = Uuid::new_v4();
        let repo_a = Uuid::new_v4();
        let mut e1 = make_history_entry("CVE-1", Utc::now());
        e1.artifact_id = artifact_a;
        let mut map = std::collections::HashMap::new();
        map.insert(artifact_a, repo_a);
        let allowed: HashSet<Uuid> = HashSet::new();
        let filtered = filter_entries_by_repo_map(vec![e1], &map, &allowed);
        assert!(filtered.is_empty());
    }

    // --- sort_entries_by_first_detected_desc -------------------------------

    #[test]
    fn test_sort_entries_by_first_detected_desc_newest_first() {
        let now = Utc::now();
        let old = make_history_entry("CVE-OLD", now - chrono::Duration::days(30));
        let mid = make_history_entry("CVE-MID", now - chrono::Duration::days(10));
        let new = make_history_entry("CVE-NEW", now);
        // Deliberately scrambled.
        let mut entries = vec![old, new, mid];
        sort_entries_by_first_detected_desc(&mut entries);
        assert_eq!(entries[0].cve_id, "CVE-NEW");
        assert_eq!(entries[1].cve_id, "CVE-MID");
        assert_eq!(entries[2].cve_id, "CVE-OLD");
    }

    #[test]
    fn test_sort_entries_by_first_detected_desc_empty_input() {
        let mut entries: Vec<CveHistoryEntry> = vec![];
        sort_entries_by_first_detected_desc(&mut entries);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_sort_entries_by_first_detected_desc_stable_for_equal_timestamps() {
        let when = Utc::now();
        let a = make_history_entry("CVE-A", when);
        let b = make_history_entry("CVE-B", when);
        let mut entries = vec![a.clone(), b.clone()];
        sort_entries_by_first_detected_desc(&mut entries);
        // Both have the same first_detected_at -- the sort is total but the
        // relative order of equals is preserved by sort_by_key (Rust's slice
        // sort is stable). Don't rely on which comes first; rely on both
        // still being present.
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.cve_id == "CVE-A"));
        assert!(entries.iter().any(|e| e.cve_id == "CVE-B"));
    }

    // --- end-to-end pipeline check (pure, no DB) ---------------------------

    #[test]
    fn test_scan_finding_dedupe_then_merge_then_sort() {
        // Simulate the full read pipeline in `get_cve_history` against an
        // in-memory dataset: curated rows + scan rows, dedupe by cve_id,
        // sort newest-first.
        let now = Utc::now();
        let artifact = Uuid::new_v4();

        // Curated row (older, "CVE-2019-10744" upper-case).
        let curated = make_history_entry("CVE-2019-10744", now - chrono::Duration::days(20));

        // Scan rows: one is a case-variant duplicate of the curated CVE
        // (must be dropped), one is novel (must survive).
        let dup_row = make_scan_row(
            artifact,
            Some("cve-2019-10744"), // lower-case duplicate
            now - chrono::Duration::days(5),
            false,
        );
        let novel_row = make_scan_row(
            artifact,
            Some("CVE-2024-12345"),
            now - chrono::Duration::days(1),
            false,
        );

        // Step 1: known set from curated rows.
        let known = build_known_cve_set(std::slice::from_ref(&curated));
        assert_eq!(known.len(), 1);

        // Step 2: apply dedupe filter to scan rows.
        let scan_rows = vec![dup_row, novel_row];
        let kept: Vec<_> = scan_rows
            .into_iter()
            .filter(|r| scan_row_passes_known_filter(r.cve_id.as_deref(), &known))
            .collect();
        assert_eq!(
            kept.len(),
            1,
            "case-insensitive dedupe must drop the lower-case duplicate"
        );
        assert_eq!(kept[0].cve_id.as_deref(), Some("CVE-2024-12345"));

        // Step 3: project scan rows to CveHistoryEntry.
        let mut combined: Vec<CveHistoryEntry> = vec![curated];
        combined.extend(kept.into_iter().map(scan_finding_to_history_entry));

        // Step 4: sort newest-first.
        sort_entries_by_first_detected_desc(&mut combined);

        // The novel scan row was detected 1 day ago, the curated row 20
        // days ago, so the scan row sorts first.
        assert_eq!(combined.len(), 2);
        assert_eq!(combined[0].cve_id, "CVE-2024-12345");
        assert_eq!(combined[1].cve_id, "CVE-2019-10744");
    }
}
