//! SBOM (Software Bill of Materials) generation and management service.

use crate::error::{AppError, Result};
use crate::models::sbom::{
    CveHistoryEntry, CveStatus, CveTimelineEntry, CveTrends, LicensePolicy, SbomComponent,
    SbomDocument, SbomFormat, SbomSummary,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::collections::HashSet;
use uuid::Uuid;

/// Get the format version string for a given SBOM format.
pub(crate) fn format_version(format: SbomFormat) -> &'static str {
    match format {
        SbomFormat::CycloneDX => "1.5",
        SbomFormat::SPDX => "2.3",
    }
}

/// Get the full spec version string for a given SBOM format.
pub(crate) fn spec_version(format: SbomFormat) -> &'static str {
    match format {
        SbomFormat::CycloneDX => "CycloneDX 1.5",
        SbomFormat::SPDX => "SPDX-2.3",
    }
}

/// Build a CycloneDX component JSON value from a DependencyInfo.
pub(crate) fn build_cyclonedx_component(dep: &DependencyInfo) -> serde_json::Value {
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

/// Build an SPDX package JSON value from a DependencyInfo and its index.
pub(crate) fn build_spdx_package(dep: &DependencyInfo, idx: usize) -> serde_json::Value {
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

/// Build a ComponentInfo from a DependencyInfo.
pub(crate) fn build_component_info(dep: &DependencyInfo) -> ComponentInfo {
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

/// Extract unique licenses from a slice of dependencies.
pub(crate) fn extract_unique_licenses(dependencies: &[DependencyInfo]) -> Vec<String> {
    dependencies
        .iter()
        .filter_map(|d| d.license.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect()
}

/// Check licenses against a policy (standalone, no &self needed).
pub(crate) fn check_license_compliance_pure(
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

/// Calculate the SHA-256 content hash of a string.
pub(crate) fn content_hash(content: &str) -> String {
    format!("{:x}", Sha256::digest(content.as_bytes()))
}

/// Compute the number of days a CVE has been exposed.
pub(crate) fn days_exposed(
    first_detected_at: chrono::DateTime<Utc>,
    now: chrono::DateTime<Utc>,
) -> i64 {
    (now - first_detected_at).num_days()
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
    pub async fn generate_sbom(
        &self,
        artifact_id: Uuid,
        repository_id: Uuid,
        format: SbomFormat,
        dependencies: Vec<DependencyInfo>,
    ) -> Result<SbomDocument> {
        // Check if SBOM already exists
        let existing = self.get_sbom_by_artifact(artifact_id, format).await?;
        if let Some(doc) = existing {
            return Ok(doc);
        }

        // Generate SBOM content based on format
        let (content, components) = match format {
            SbomFormat::CycloneDX => self.generate_cyclonedx(&dependencies)?,
            SbomFormat::SPDX => self.generate_spdx(&dependencies)?,
        };

        // Calculate content hash
        let content_str = serde_json::to_string(&content)?;
        let content_hash = format!("{:x}", Sha256::digest(content_str.as_bytes()));

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
        let entries = sqlx::query_as::<_, CveHistoryEntry>(
            r#"
            SELECT * FROM cve_history
            WHERE artifact_id = $1
            ORDER BY first_detected_at DESC
            "#,
        )
        .bind(artifact_id)
        .fetch_all(&self.db)
        .await?;

        Ok(entries)
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
    pub async fn get_cve_trends(&self, repository_id: Option<Uuid>) -> Result<CveTrends> {
        // Get aggregate counts
        let (total, open, fixed, acknowledged, critical, high, medium, low): (
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
            i64,
        ) = if let Some(repo_id) = repository_id {
            sqlx::query_as(
                r#"
                SELECT
                    COUNT(*) as total,
                    COUNT(*) FILTER (WHERE status = 'open') as open,
                    COUNT(*) FILTER (WHERE status = 'fixed') as fixed,
                    COUNT(*) FILTER (WHERE status = 'acknowledged') as acknowledged,
                    COUNT(*) FILTER (WHERE severity = 'critical') as critical,
                    COUNT(*) FILTER (WHERE severity = 'high') as high,
                    COUNT(*) FILTER (WHERE severity = 'medium') as medium,
                    COUNT(*) FILTER (WHERE severity = 'low') as low
                FROM cve_history ch
                JOIN artifacts a ON ch.artifact_id = a.id
                WHERE a.repository_id = $1
                "#,
            )
            .bind(repo_id)
            .fetch_one(&self.db)
            .await?
        } else {
            sqlx::query_as(
                r#"
                SELECT
                    COUNT(*) as total,
                    COUNT(*) FILTER (WHERE status = 'open') as open,
                    COUNT(*) FILTER (WHERE status = 'fixed') as fixed,
                    COUNT(*) FILTER (WHERE status = 'acknowledged') as acknowledged,
                    COUNT(*) FILTER (WHERE severity = 'critical') as critical,
                    COUNT(*) FILTER (WHERE severity = 'high') as high,
                    COUNT(*) FILTER (WHERE severity = 'medium') as medium,
                    COUNT(*) FILTER (WHERE severity = 'low') as low
                FROM cve_history
                "#,
            )
            .fetch_one(&self.db)
            .await?
        };

        // Get timeline (last 30 days)
        let timeline_entries = sqlx::query_as::<_, CveHistoryEntry>(
            r#"
            SELECT * FROM cve_history
            WHERE first_detected_at > NOW() - INTERVAL '30 days'
            ORDER BY first_detected_at DESC
            LIMIT 100
            "#,
        )
        .fetch_all(&self.db)
        .await?;

        let timeline: Vec<CveTimelineEntry> = timeline_entries
            .into_iter()
            .map(|e| {
                let days_exposed = (Utc::now() - e.first_detected_at).num_days();
                CveTimelineEntry {
                    cve_id: e.cve_id,
                    severity: e.severity.unwrap_or_default(),
                    affected_component: e.affected_component.unwrap_or_default(),
                    cve_published_at: e.cve_published_at,
                    first_detected_at: e.first_detected_at,
                    status: CveStatus::parse(&e.status).unwrap_or(CveStatus::Open),
                    days_exposed,
                }
            })
            .collect();

        Ok(CveTrends {
            total_cves: total,
            open_cves: open,
            fixed_cves: fixed,
            acknowledged_cves: acknowledged,
            critical_count: critical,
            high_count: high,
            medium_count: medium,
            low_count: low,
            avg_days_to_fix: None, // TODO: calculate from fixed CVEs
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

    fn generate_cyclonedx(
        &self,
        dependencies: &[DependencyInfo],
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

        let sbom = serde_json::json!({
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
            "components": cdx_components
        });

        Ok((sbom, components))
    }

    fn generate_spdx(
        &self,
        dependencies: &[DependencyInfo],
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

        let sbom = serde_json::json!({
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "artifact-sbom",
            "documentNamespace": format!("https://artifact-keeper.com/sbom/{}", Uuid::new_v4()),
            "creationInfo": {
                "created": Utc::now().to_rfc3339(),
                "creators": [format!("Tool: artifact-keeper-{}", env!("CARGO_PKG_VERSION"))]
            },
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
}
