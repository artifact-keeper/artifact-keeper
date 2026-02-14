//! gRPC server implementations for SBOM services.

use crate::models::sbom::{CveStatus, SbomFormat};
use crate::services::sbom_service::{DependencyInfo, SbomService};
use sqlx::PgPool;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use super::generated::{
    cve_history_service_server::CveHistoryService as CveHistoryServiceTrait,
    sbom_service_server::SbomService as SbomServiceTrait,
    security_policy_service_server::SecurityPolicyService as SecurityPolicyServiceTrait, *,
};

/// gRPC server for SBOM operations.
pub struct SbomGrpcServer {
    service: Arc<SbomService>,
}

impl SbomGrpcServer {
    pub fn new(db: PgPool) -> Self {
        Self {
            service: Arc::new(SbomService::new(db)),
        }
    }
}

#[tonic::async_trait]
impl SbomServiceTrait for SbomGrpcServer {
    async fn generate_sbom(
        &self,
        request: Request<GenerateSbomRequest>,
    ) -> Result<Response<SbomDocument>, Status> {
        let req = request.into_inner();

        let artifact_id = parse_uuid(&req.artifact_id)?;
        let format = proto_to_sbom_format(req.format());

        // Get artifact to get repository_id
        // For now, we'll need the caller to provide dependencies
        // In a full implementation, we'd extract them from the artifact
        let deps: Vec<DependencyInfo> = vec![];

        let doc = self
            .service
            .generate_sbom(artifact_id, artifact_id, format, deps)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(sbom_doc_to_proto(doc)))
    }

    async fn get_sbom(
        &self,
        request: Request<GetSbomRequest>,
    ) -> Result<Response<SbomDocument>, Status> {
        let req = request.into_inner();
        let id = parse_uuid(&req.id)?;

        let doc = self
            .service
            .get_sbom(id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found("SBOM not found"))?;

        Ok(Response::new(sbom_doc_to_proto(doc)))
    }

    async fn get_sbom_by_artifact(
        &self,
        request: Request<GetSbomByArtifactRequest>,
    ) -> Result<Response<SbomDocument>, Status> {
        let req = request.into_inner();
        let artifact_id = parse_uuid(&req.artifact_id)?;
        let format = proto_to_sbom_format(req.format());

        let doc = self
            .service
            .get_sbom_by_artifact(artifact_id, format)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found("SBOM not found"))?;

        Ok(Response::new(sbom_doc_to_proto(doc)))
    }

    async fn list_sboms_for_artifact(
        &self,
        request: Request<ListSbomsRequest>,
    ) -> Result<Response<ListSbomsResponse>, Status> {
        let req = request.into_inner();
        let artifact_id = parse_uuid(&req.artifact_id)?;

        let summaries = self
            .service
            .list_sboms_for_artifact(artifact_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let sboms = summaries
            .into_iter()
            .map(|s| SbomDocument {
                id: s.id.to_string(),
                artifact_id: s.artifact_id.to_string(),
                repository_id: String::new(),
                format: sbom_format_to_proto(s.format).into(),
                format_version: s.format_version,
                spec_version: String::new(),
                content: vec![],
                component_count: s.component_count,
                dependency_count: 0,
                license_count: s.license_count,
                licenses: s.licenses,
                content_hash: String::new(),
                generator: String::new(),
                generator_version: String::new(),
                generated_at: Some(datetime_to_proto(s.generated_at)),
                created_at: Some(datetime_to_proto(s.created_at)),
            })
            .collect();

        Ok(Response::new(ListSbomsResponse { sboms }))
    }

    async fn get_sbom_components(
        &self,
        request: Request<GetSbomComponentsRequest>,
    ) -> Result<Response<GetSbomComponentsResponse>, Status> {
        let req = request.into_inner();
        let sbom_id = parse_uuid(&req.sbom_id)?;

        let components = self
            .service
            .get_sbom_components(sbom_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let proto_components: Vec<SbomComponent> = components
            .into_iter()
            .map(|c| SbomComponent {
                id: c.id.to_string(),
                sbom_id: c.sbom_id.to_string(),
                name: c.name,
                version: c.version.unwrap_or_default(),
                purl: c.purl.unwrap_or_default(),
                cpe: String::new(),
                component_type: c.component_type.unwrap_or_default(),
                licenses: c.licenses,
                sha256: c.sha256.unwrap_or_default(),
                sha1: String::new(),
                md5: String::new(),
                supplier: c.supplier.unwrap_or_default(),
                author: String::new(),
            })
            .collect();

        let total = proto_components.len() as i32;

        Ok(Response::new(GetSbomComponentsResponse {
            components: proto_components,
            next_page_token: String::new(),
            total_count: total,
        }))
    }

    async fn convert_sbom(
        &self,
        request: Request<ConvertSbomRequest>,
    ) -> Result<Response<SbomDocument>, Status> {
        let req = request.into_inner();
        let sbom_id = parse_uuid(&req.sbom_id)?;
        let target_format = proto_to_sbom_format(req.target_format());

        let doc = self
            .service
            .convert_sbom(sbom_id, target_format)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(sbom_doc_to_proto(doc)))
    }

    async fn delete_sbom(
        &self,
        request: Request<DeleteSbomRequest>,
    ) -> Result<Response<DeleteSbomResponse>, Status> {
        let req = request.into_inner();
        let id = parse_uuid(&req.id)?;

        self.service
            .delete_sbom(id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(DeleteSbomResponse { success: true }))
    }

    async fn regenerate_sbom(
        &self,
        request: Request<RegenerateSbomRequest>,
    ) -> Result<Response<SbomDocument>, Status> {
        let req = request.into_inner();
        let artifact_id = parse_uuid(&req.artifact_id)?;
        let format = proto_to_sbom_format(req.format());

        // Delete existing and regenerate
        if let Some(existing) = self
            .service
            .get_sbom_by_artifact(artifact_id, format)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
        {
            self.service
                .delete_sbom(existing.id)
                .await
                .map_err(|e| Status::internal(e.to_string()))?;
        }

        let deps: Vec<DependencyInfo> = vec![];
        let doc = self
            .service
            .generate_sbom(artifact_id, artifact_id, format, deps)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(sbom_doc_to_proto(doc)))
    }

    async fn check_license_compliance(
        &self,
        request: Request<CheckLicenseComplianceRequest>,
    ) -> Result<Response<LicenseComplianceResponse>, Status> {
        let req = request.into_inner();
        let repo_id = if req.repository_id.is_empty() {
            None
        } else {
            Some(parse_uuid(&req.repository_id)?)
        };

        let policy = self
            .service
            .get_license_policy(repo_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found("No license policy configured"))?;

        let result = self
            .service
            .check_license_compliance(&policy, &req.licenses);

        Ok(Response::new(LicenseComplianceResponse {
            compliant: result.compliant,
            violations: result.violations,
            warnings: result.warnings,
        }))
    }
}

/// gRPC server for CVE History operations.
pub struct CveHistoryGrpcServer {
    service: Arc<SbomService>,
}

impl CveHistoryGrpcServer {
    pub fn new(db: PgPool) -> Self {
        Self {
            service: Arc::new(SbomService::new(db)),
        }
    }
}

#[tonic::async_trait]
impl CveHistoryServiceTrait for CveHistoryGrpcServer {
    async fn get_cve_history(
        &self,
        request: Request<GetCveHistoryRequest>,
    ) -> Result<Response<GetCveHistoryResponse>, Status> {
        let req = request.into_inner();
        let artifact_id = parse_uuid(&req.artifact_id)?;

        let entries = self
            .service
            .get_cve_history(artifact_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let proto_entries: Vec<CveHistoryEntry> =
            entries.into_iter().map(cve_entry_to_proto).collect();

        Ok(Response::new(GetCveHistoryResponse {
            entries: proto_entries,
        }))
    }

    async fn update_cve_status(
        &self,
        request: Request<UpdateCveStatusRequest>,
    ) -> Result<Response<CveHistoryEntry>, Status> {
        let req = request.into_inner();
        let id = parse_uuid(&req.id)?;
        let status = proto_to_cve_status(req.status());

        let entry = self
            .service
            .update_cve_status(id, status, None, Some(&req.reason))
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(cve_entry_to_proto(entry)))
    }

    async fn get_cve_trends(
        &self,
        request: Request<GetCveTrendsRequest>,
    ) -> Result<Response<CveTrendsResponse>, Status> {
        let req = request.into_inner();
        let repo_id = if req.repository_id.is_empty() {
            None
        } else {
            Some(parse_uuid(&req.repository_id)?)
        };

        let trends = self
            .service
            .get_cve_trends(repo_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        let timeline: Vec<super::generated::CveTimelineEntry> = trends
            .timeline
            .into_iter()
            .map(|t| super::generated::CveTimelineEntry {
                cve_id: t.cve_id,
                severity: t.severity,
                affected_component: t.affected_component,
                cve_published_at: t.cve_published_at.map(datetime_to_proto),
                first_detected_at: Some(datetime_to_proto(t.first_detected_at)),
                status: cve_status_to_proto(t.status).into(),
                days_exposed: t.days_exposed,
            })
            .collect();

        Ok(Response::new(CveTrendsResponse {
            total_cves: trends.total_cves,
            open_cves: trends.open_cves,
            fixed_cves: trends.fixed_cves,
            acknowledged_cves: trends.acknowledged_cves,
            critical_count: trends.critical_count,
            high_count: trends.high_count,
            medium_count: trends.medium_count,
            low_count: trends.low_count,
            avg_days_to_fix: trends.avg_days_to_fix.unwrap_or(0.0),
            timeline,
        }))
    }

    async fn trigger_retroactive_scan(
        &self,
        request: Request<RetroactiveScanRequest>,
    ) -> Result<Response<RetroactiveScanResponse>, Status> {
        let _req = request.into_inner();

        // TODO: Implement retroactive scan job queuing
        Ok(Response::new(RetroactiveScanResponse {
            artifacts_queued: 0,
            job_id: Uuid::new_v4().to_string(),
        }))
    }
}

/// gRPC server for Security Policy operations.
pub struct SecurityPolicyGrpcServer {
    db: PgPool,
}

impl SecurityPolicyGrpcServer {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }
}

#[tonic::async_trait]
impl SecurityPolicyServiceTrait for SecurityPolicyGrpcServer {
    async fn get_license_policy(
        &self,
        request: Request<GetLicensePolicyRequest>,
    ) -> Result<Response<LicensePolicy>, Status> {
        let req = request.into_inner();
        let repo_id = if req.repository_id.is_empty() {
            None
        } else {
            Some(parse_uuid(&req.repository_id)?)
        };

        let service = SbomService::new(self.db.clone());
        let policy = service
            .get_license_policy(repo_id)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .ok_or_else(|| Status::not_found("No license policy found"))?;

        Ok(Response::new(license_policy_to_proto(policy)))
    }

    async fn upsert_license_policy(
        &self,
        request: Request<UpsertLicensePolicyRequest>,
    ) -> Result<Response<LicensePolicy>, Status> {
        let req = request.into_inner();
        let policy = req
            .policy
            .ok_or_else(|| Status::invalid_argument("Policy required"))?;

        let repo_id: Option<Uuid> = if policy.repository_id.is_empty() {
            None
        } else {
            Some(parse_uuid(&policy.repository_id)?)
        };

        let result = sqlx::query_as::<_, crate::models::sbom::LicensePolicy>(
            r#"
            INSERT INTO license_policies (
                repository_id, name, description, allowed_licenses,
                denied_licenses, allow_unknown, action, is_enabled
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (COALESCE(repository_id, '00000000-0000-0000-0000-000000000000'), name)
            DO UPDATE SET
                description = EXCLUDED.description,
                allowed_licenses = EXCLUDED.allowed_licenses,
                denied_licenses = EXCLUDED.denied_licenses,
                allow_unknown = EXCLUDED.allow_unknown,
                action = EXCLUDED.action,
                is_enabled = EXCLUDED.is_enabled,
                updated_at = NOW()
            RETURNING *
            "#,
        )
        .bind(repo_id)
        .bind(&policy.name)
        .bind(&policy.description)
        .bind(&policy.allowed_licenses)
        .bind(&policy.denied_licenses)
        .bind(policy.allow_unknown)
        .bind(proto_to_policy_action(policy.action()).as_str())
        .bind(policy.is_enabled)
        .fetch_one(&self.db)
        .await
        .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(license_policy_to_proto(result)))
    }

    async fn delete_license_policy(
        &self,
        request: Request<DeleteLicensePolicyRequest>,
    ) -> Result<Response<DeleteLicensePolicyResponse>, Status> {
        let req = request.into_inner();
        let id = parse_uuid(&req.id)?;

        sqlx::query("DELETE FROM license_policies WHERE id = $1")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(DeleteLicensePolicyResponse { success: true }))
    }

    async fn list_license_policies(
        &self,
        request: Request<ListLicensePoliciesRequest>,
    ) -> Result<Response<ListLicensePoliciesResponse>, Status> {
        let req = request.into_inner();

        let policies: Vec<crate::models::sbom::LicensePolicy> = if req.repository_id.is_empty() {
            sqlx::query_as("SELECT * FROM license_policies ORDER BY name")
                .fetch_all(&self.db)
                .await
                .map_err(|e| Status::internal(e.to_string()))?
        } else {
            let repo_id = parse_uuid(&req.repository_id)?;
            sqlx::query_as(
                "SELECT * FROM license_policies WHERE repository_id = $1 OR repository_id IS NULL ORDER BY name"
            )
            .bind(repo_id)
            .fetch_all(&self.db)
            .await
            .map_err(|e| Status::internal(e.to_string()))?
        };

        let proto_policies: Vec<LicensePolicy> =
            policies.into_iter().map(license_policy_to_proto).collect();

        Ok(Response::new(ListLicensePoliciesResponse {
            policies: proto_policies,
        }))
    }
}

// === Conversion helpers ===

#[allow(clippy::result_large_err)]
fn parse_uuid(s: &str) -> Result<Uuid, Status> {
    Uuid::parse_str(s).map_err(|_| Status::invalid_argument(format!("Invalid UUID: {}", s)))
}

fn proto_to_sbom_format(format: super::generated::SbomFormat) -> SbomFormat {
    match format {
        super::generated::SbomFormat::Cyclonedx => SbomFormat::CycloneDX,
        super::generated::SbomFormat::Spdx => SbomFormat::SPDX,
        _ => SbomFormat::CycloneDX,
    }
}

fn sbom_format_to_proto(format: SbomFormat) -> super::generated::SbomFormat {
    match format {
        SbomFormat::CycloneDX => super::generated::SbomFormat::Cyclonedx,
        SbomFormat::SPDX => super::generated::SbomFormat::Spdx,
    }
}

fn proto_to_cve_status(status: super::generated::CveStatus) -> CveStatus {
    match status {
        super::generated::CveStatus::Open => CveStatus::Open,
        super::generated::CveStatus::Fixed => CveStatus::Fixed,
        super::generated::CveStatus::Acknowledged => CveStatus::Acknowledged,
        super::generated::CveStatus::FalsePositive => CveStatus::FalsePositive,
        _ => CveStatus::Open,
    }
}

fn cve_status_to_proto(status: CveStatus) -> super::generated::CveStatus {
    match status {
        CveStatus::Open => super::generated::CveStatus::Open,
        CveStatus::Fixed => super::generated::CveStatus::Fixed,
        CveStatus::Acknowledged => super::generated::CveStatus::Acknowledged,
        CveStatus::FalsePositive => super::generated::CveStatus::FalsePositive,
    }
}

fn proto_to_policy_action(
    action: super::generated::PolicyAction,
) -> crate::models::sbom::PolicyAction {
    match action {
        super::generated::PolicyAction::Allow => crate::models::sbom::PolicyAction::Allow,
        super::generated::PolicyAction::Warn => crate::models::sbom::PolicyAction::Warn,
        super::generated::PolicyAction::Block => crate::models::sbom::PolicyAction::Block,
        _ => crate::models::sbom::PolicyAction::Warn,
    }
}

fn datetime_to_proto(dt: chrono::DateTime<chrono::Utc>) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    }
}

fn sbom_doc_to_proto(doc: crate::models::sbom::SbomDocument) -> SbomDocument {
    SbomDocument {
        id: doc.id.to_string(),
        artifact_id: doc.artifact_id.to_string(),
        repository_id: doc.repository_id.to_string(),
        format: sbom_format_to_proto(
            SbomFormat::parse(&doc.format).unwrap_or(SbomFormat::CycloneDX),
        )
        .into(),
        format_version: doc.format_version,
        spec_version: doc.spec_version.unwrap_or_default(),
        content: doc.content.to_string().into_bytes(),
        component_count: doc.component_count,
        dependency_count: doc.dependency_count,
        license_count: doc.license_count,
        licenses: doc.licenses,
        content_hash: doc.content_hash,
        generator: doc.generator.unwrap_or_default(),
        generator_version: doc.generator_version.unwrap_or_default(),
        generated_at: Some(datetime_to_proto(doc.generated_at)),
        created_at: Some(datetime_to_proto(doc.created_at)),
    }
}

fn cve_entry_to_proto(entry: crate::models::sbom::CveHistoryEntry) -> CveHistoryEntry {
    let status = CveStatus::parse(&entry.status).unwrap_or(CveStatus::Open);
    CveHistoryEntry {
        id: entry.id.to_string(),
        artifact_id: entry.artifact_id.to_string(),
        cve_id: entry.cve_id,
        affected_component: entry.affected_component.unwrap_or_default(),
        affected_version: entry.affected_version.unwrap_or_default(),
        fixed_version: entry.fixed_version.unwrap_or_default(),
        severity: entry.severity.unwrap_or_default(),
        cvss_score: entry.cvss_score.unwrap_or(0.0),
        cve_published_at: entry.cve_published_at.map(datetime_to_proto),
        first_detected_at: Some(datetime_to_proto(entry.first_detected_at)),
        last_detected_at: Some(datetime_to_proto(entry.last_detected_at)),
        status: cve_status_to_proto(status).into(),
        acknowledged_by: entry
            .acknowledged_by
            .map(|u| u.to_string())
            .unwrap_or_default(),
        acknowledged_at: entry.acknowledged_at.map(datetime_to_proto),
        acknowledged_reason: entry.acknowledged_reason.unwrap_or_default(),
    }
}

fn license_policy_to_proto(policy: crate::models::sbom::LicensePolicy) -> LicensePolicy {
    LicensePolicy {
        id: policy.id.to_string(),
        repository_id: policy
            .repository_id
            .map(|u| u.to_string())
            .unwrap_or_default(),
        name: policy.name,
        description: policy.description.unwrap_or_default(),
        allowed_licenses: policy.allowed_licenses,
        denied_licenses: policy.denied_licenses,
        allow_unknown: policy.allow_unknown,
        action: model_policy_action_to_proto(policy.action).into(),
        is_enabled: policy.is_enabled,
        created_at: Some(datetime_to_proto(policy.created_at)),
        updated_at: policy.updated_at.map(datetime_to_proto),
    }
}

fn model_policy_action_to_proto(
    action: crate::models::sbom::PolicyAction,
) -> super::generated::PolicyAction {
    match action {
        crate::models::sbom::PolicyAction::Allow => super::generated::PolicyAction::Allow,
        crate::models::sbom::PolicyAction::Warn => super::generated::PolicyAction::Warn,
        crate::models::sbom::PolicyAction::Block => super::generated::PolicyAction::Block,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    // -----------------------------------------------------------------------
    // parse_uuid
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_uuid_valid() {
        let uuid_str = "550e8400-e29b-41d4-a716-446655440000";
        let result = parse_uuid(uuid_str);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().to_string(), uuid_str);
    }

    #[test]
    fn test_parse_uuid_nil() {
        let result = parse_uuid("00000000-0000-0000-0000-000000000000");
        assert!(result.is_ok());
        assert!(result.unwrap().is_nil());
    }

    #[test]
    fn test_parse_uuid_invalid() {
        let result = parse_uuid("not-a-uuid");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_uuid_empty() {
        let result = parse_uuid("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_uuid_partial() {
        let result = parse_uuid("550e8400-e29b-41d4");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_uuid_v4() {
        let id = Uuid::new_v4();
        let result = parse_uuid(&id.to_string());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), id);
    }

    // -----------------------------------------------------------------------
    // datetime_to_proto
    // -----------------------------------------------------------------------

    #[test]
    fn test_datetime_to_proto_epoch() {
        let dt = Utc.timestamp_opt(0, 0).unwrap();
        let ts = datetime_to_proto(dt);
        assert_eq!(ts.seconds, 0);
        assert_eq!(ts.nanos, 0);
    }

    #[test]
    fn test_datetime_to_proto_specific_time() {
        let dt = Utc.timestamp_opt(1700000000, 500_000_000).unwrap();
        let ts = datetime_to_proto(dt);
        assert_eq!(ts.seconds, 1700000000);
        assert_eq!(ts.nanos, 500_000_000);
    }

    #[test]
    fn test_datetime_to_proto_current() {
        let now = Utc::now();
        let ts = datetime_to_proto(now);
        assert!(ts.seconds > 0);
        assert!(ts.nanos >= 0);
    }

    #[test]
    fn test_datetime_to_proto_subsec_nanos() {
        let dt = Utc.timestamp_opt(1000000, 123_456_789).unwrap();
        let ts = datetime_to_proto(dt);
        assert_eq!(ts.seconds, 1000000);
        assert_eq!(ts.nanos, 123_456_789);
    }

    // -----------------------------------------------------------------------
    // proto_to_sbom_format
    // -----------------------------------------------------------------------

    #[test]
    fn test_proto_to_sbom_format_cyclonedx() {
        let result = proto_to_sbom_format(super::super::generated::SbomFormat::Cyclonedx);
        assert_eq!(result, SbomFormat::CycloneDX);
    }

    #[test]
    fn test_proto_to_sbom_format_spdx() {
        let result = proto_to_sbom_format(super::super::generated::SbomFormat::Spdx);
        assert_eq!(result, SbomFormat::SPDX);
    }

    // -----------------------------------------------------------------------
    // sbom_format_to_proto
    // -----------------------------------------------------------------------

    #[test]
    fn test_sbom_format_to_proto_cyclonedx() {
        let result = sbom_format_to_proto(SbomFormat::CycloneDX);
        assert_eq!(result, super::super::generated::SbomFormat::Cyclonedx);
    }

    #[test]
    fn test_sbom_format_to_proto_spdx() {
        let result = sbom_format_to_proto(SbomFormat::SPDX);
        assert_eq!(result, super::super::generated::SbomFormat::Spdx);
    }

    #[test]
    fn test_sbom_format_roundtrip_cyclonedx() {
        let original = SbomFormat::CycloneDX;
        let proto = sbom_format_to_proto(original);
        let back = proto_to_sbom_format(proto);
        assert_eq!(back, original);
    }

    #[test]
    fn test_sbom_format_roundtrip_spdx() {
        let original = SbomFormat::SPDX;
        let proto = sbom_format_to_proto(original);
        let back = proto_to_sbom_format(proto);
        assert_eq!(back, original);
    }

    // -----------------------------------------------------------------------
    // proto_to_cve_status / cve_status_to_proto
    // -----------------------------------------------------------------------

    #[test]
    fn test_proto_to_cve_status_open() {
        let result = proto_to_cve_status(super::super::generated::CveStatus::Open);
        assert_eq!(result, CveStatus::Open);
    }

    #[test]
    fn test_proto_to_cve_status_fixed() {
        let result = proto_to_cve_status(super::super::generated::CveStatus::Fixed);
        assert_eq!(result, CveStatus::Fixed);
    }

    #[test]
    fn test_proto_to_cve_status_acknowledged() {
        let result = proto_to_cve_status(super::super::generated::CveStatus::Acknowledged);
        assert_eq!(result, CveStatus::Acknowledged);
    }

    #[test]
    fn test_proto_to_cve_status_false_positive() {
        let result = proto_to_cve_status(super::super::generated::CveStatus::FalsePositive);
        assert_eq!(result, CveStatus::FalsePositive);
    }

    #[test]
    fn test_cve_status_to_proto_open() {
        let result = cve_status_to_proto(CveStatus::Open);
        assert_eq!(result, super::super::generated::CveStatus::Open);
    }

    #[test]
    fn test_cve_status_to_proto_fixed() {
        let result = cve_status_to_proto(CveStatus::Fixed);
        assert_eq!(result, super::super::generated::CveStatus::Fixed);
    }

    #[test]
    fn test_cve_status_to_proto_acknowledged() {
        let result = cve_status_to_proto(CveStatus::Acknowledged);
        assert_eq!(result, super::super::generated::CveStatus::Acknowledged);
    }

    #[test]
    fn test_cve_status_to_proto_false_positive() {
        let result = cve_status_to_proto(CveStatus::FalsePositive);
        assert_eq!(result, super::super::generated::CveStatus::FalsePositive);
    }

    #[test]
    fn test_cve_status_roundtrip_all_variants() {
        for status in [
            CveStatus::Open,
            CveStatus::Fixed,
            CveStatus::Acknowledged,
            CveStatus::FalsePositive,
        ] {
            let proto = cve_status_to_proto(status);
            let back = proto_to_cve_status(proto);
            assert_eq!(back, status);
        }
    }

    // -----------------------------------------------------------------------
    // proto_to_policy_action / model_policy_action_to_proto
    // -----------------------------------------------------------------------

    #[test]
    fn test_proto_to_policy_action_allow() {
        let result = proto_to_policy_action(super::super::generated::PolicyAction::Allow);
        assert_eq!(result, crate::models::sbom::PolicyAction::Allow);
    }

    #[test]
    fn test_proto_to_policy_action_warn() {
        let result = proto_to_policy_action(super::super::generated::PolicyAction::Warn);
        assert_eq!(result, crate::models::sbom::PolicyAction::Warn);
    }

    #[test]
    fn test_proto_to_policy_action_block() {
        let result = proto_to_policy_action(super::super::generated::PolicyAction::Block);
        assert_eq!(result, crate::models::sbom::PolicyAction::Block);
    }

    #[test]
    fn test_model_policy_action_to_proto_allow() {
        let result = model_policy_action_to_proto(crate::models::sbom::PolicyAction::Allow);
        assert_eq!(result, super::super::generated::PolicyAction::Allow);
    }

    #[test]
    fn test_model_policy_action_to_proto_warn() {
        let result = model_policy_action_to_proto(crate::models::sbom::PolicyAction::Warn);
        assert_eq!(result, super::super::generated::PolicyAction::Warn);
    }

    #[test]
    fn test_model_policy_action_to_proto_block() {
        let result = model_policy_action_to_proto(crate::models::sbom::PolicyAction::Block);
        assert_eq!(result, super::super::generated::PolicyAction::Block);
    }

    #[test]
    fn test_policy_action_roundtrip_all_variants() {
        for action in [
            crate::models::sbom::PolicyAction::Allow,
            crate::models::sbom::PolicyAction::Warn,
            crate::models::sbom::PolicyAction::Block,
        ] {
            let proto = model_policy_action_to_proto(action);
            let back = proto_to_policy_action(proto);
            assert_eq!(back, action);
        }
    }

    // -----------------------------------------------------------------------
    // sbom_doc_to_proto
    // -----------------------------------------------------------------------

    #[test]
    fn test_sbom_doc_to_proto_basic() {
        let now = Utc::now();
        let doc_id = Uuid::new_v4();
        let artifact_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();

        let doc = crate::models::sbom::SbomDocument {
            id: doc_id,
            artifact_id,
            repository_id: repo_id,
            format: "cyclonedx".to_string(),
            format_version: "1.5".to_string(),
            spec_version: Some("1.5".to_string()),
            content: serde_json::json!({"test": true}),
            component_count: 42,
            dependency_count: 10,
            license_count: 3,
            licenses: vec!["MIT".to_string()],
            content_hash: "sha256:abc".to_string(),
            generator: Some("test-gen".to_string()),
            generator_version: Some("1.0".to_string()),
            generated_at: now,
            created_at: now,
            updated_at: now,
        };

        let proto = sbom_doc_to_proto(doc);
        assert_eq!(proto.id, doc_id.to_string());
        assert_eq!(proto.artifact_id, artifact_id.to_string());
        assert_eq!(proto.repository_id, repo_id.to_string());
        assert_eq!(proto.format_version, "1.5");
        assert_eq!(proto.spec_version, "1.5");
        assert_eq!(proto.component_count, 42);
        assert_eq!(proto.dependency_count, 10);
        assert_eq!(proto.license_count, 3);
        assert_eq!(proto.licenses, vec!["MIT"]);
        assert_eq!(proto.content_hash, "sha256:abc");
        assert_eq!(proto.generator, "test-gen");
        assert_eq!(proto.generator_version, "1.0");
        assert!(proto.generated_at.is_some());
        assert!(proto.created_at.is_some());
    }

    #[test]
    fn test_sbom_doc_to_proto_none_fields() {
        let now = Utc::now();
        let doc = crate::models::sbom::SbomDocument {
            id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            format: "spdx".to_string(),
            format_version: "2.3".to_string(),
            spec_version: None,
            content: serde_json::json!({}),
            component_count: 0,
            dependency_count: 0,
            license_count: 0,
            licenses: vec![],
            content_hash: "".to_string(),
            generator: None,
            generator_version: None,
            generated_at: now,
            created_at: now,
            updated_at: now,
        };

        let proto = sbom_doc_to_proto(doc);
        assert_eq!(proto.spec_version, "");
        assert_eq!(proto.generator, "");
        assert_eq!(proto.generator_version, "");
        assert!(proto.licenses.is_empty());
    }

    #[test]
    fn test_sbom_doc_to_proto_content_is_bytes() {
        let now = Utc::now();
        let content = serde_json::json!({"key": "value"});
        let doc = crate::models::sbom::SbomDocument {
            id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            format: "cyclonedx".to_string(),
            format_version: "1.5".to_string(),
            spec_version: None,
            content: content.clone(),
            component_count: 0,
            dependency_count: 0,
            license_count: 0,
            licenses: vec![],
            content_hash: "".to_string(),
            generator: None,
            generator_version: None,
            generated_at: now,
            created_at: now,
            updated_at: now,
        };

        let proto = sbom_doc_to_proto(doc);
        // Content is serialized to bytes
        let content_str = String::from_utf8(proto.content).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content_str).unwrap();
        assert_eq!(parsed["key"], "value");
    }

    // -----------------------------------------------------------------------
    // cve_entry_to_proto
    // -----------------------------------------------------------------------

    #[test]
    fn test_cve_entry_to_proto_full() {
        let now = Utc::now();
        let entry_id = Uuid::new_v4();
        let artifact_id = Uuid::new_v4();
        let ack_by = Uuid::new_v4();
        let entry = crate::models::sbom::CveHistoryEntry {
            id: entry_id,
            artifact_id,
            sbom_id: Some(Uuid::new_v4()),
            component_id: Some(Uuid::new_v4()),
            scan_result_id: Some(Uuid::new_v4()),
            cve_id: "CVE-2024-1234".to_string(),
            affected_component: Some("openssl".to_string()),
            affected_version: Some("1.1.1".to_string()),
            fixed_version: Some("1.1.1w".to_string()),
            severity: Some("high".to_string()),
            cvss_score: Some(8.5),
            cve_published_at: Some(now),
            first_detected_at: now,
            last_detected_at: now,
            status: "acknowledged".to_string(),
            acknowledged_by: Some(ack_by),
            acknowledged_at: Some(now),
            acknowledged_reason: Some("Won't fix".to_string()),
            created_at: now,
            updated_at: now,
        };

        let proto = cve_entry_to_proto(entry);
        assert_eq!(proto.id, entry_id.to_string());
        assert_eq!(proto.artifact_id, artifact_id.to_string());
        assert_eq!(proto.cve_id, "CVE-2024-1234");
        assert_eq!(proto.affected_component, "openssl");
        assert_eq!(proto.affected_version, "1.1.1");
        assert_eq!(proto.fixed_version, "1.1.1w");
        assert_eq!(proto.severity, "high");
        assert!((proto.cvss_score - 8.5).abs() < f64::EPSILON);
        assert!(proto.cve_published_at.is_some());
        assert!(proto.first_detected_at.is_some());
        assert!(proto.last_detected_at.is_some());
        assert_eq!(proto.acknowledged_by, ack_by.to_string());
        assert!(proto.acknowledged_at.is_some());
        assert_eq!(proto.acknowledged_reason, "Won't fix");
    }

    #[test]
    fn test_cve_entry_to_proto_minimal() {
        let now = Utc::now();
        let entry = crate::models::sbom::CveHistoryEntry {
            id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            sbom_id: None,
            component_id: None,
            scan_result_id: None,
            cve_id: "CVE-2024-0001".to_string(),
            affected_component: None,
            affected_version: None,
            fixed_version: None,
            severity: None,
            cvss_score: None,
            cve_published_at: None,
            first_detected_at: now,
            last_detected_at: now,
            status: "open".to_string(),
            acknowledged_by: None,
            acknowledged_at: None,
            acknowledged_reason: None,
            created_at: now,
            updated_at: now,
        };

        let proto = cve_entry_to_proto(entry);
        assert_eq!(proto.cve_id, "CVE-2024-0001");
        assert_eq!(proto.affected_component, "");
        assert_eq!(proto.affected_version, "");
        assert_eq!(proto.fixed_version, "");
        assert_eq!(proto.severity, "");
        assert!((proto.cvss_score - 0.0).abs() < f64::EPSILON);
        assert!(proto.cve_published_at.is_none());
        assert_eq!(proto.acknowledged_by, "");
        assert!(proto.acknowledged_at.is_none());
        assert_eq!(proto.acknowledged_reason, "");
    }

    // -----------------------------------------------------------------------
    // license_policy_to_proto
    // -----------------------------------------------------------------------

    #[test]
    fn test_license_policy_to_proto_full() {
        let now = Utc::now();
        let policy_id = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let policy = crate::models::sbom::LicensePolicy {
            id: policy_id,
            repository_id: Some(repo_id),
            name: "strict-policy".to_string(),
            description: Some("Block GPL".to_string()),
            allowed_licenses: vec!["MIT".to_string()],
            denied_licenses: vec!["GPL-3.0".to_string()],
            allow_unknown: false,
            action: crate::models::sbom::PolicyAction::Block,
            is_enabled: true,
            created_at: now,
            updated_at: Some(now),
        };

        let proto = license_policy_to_proto(policy);
        assert_eq!(proto.id, policy_id.to_string());
        assert_eq!(proto.repository_id, repo_id.to_string());
        assert_eq!(proto.name, "strict-policy");
        assert_eq!(proto.description, "Block GPL");
        assert_eq!(proto.allowed_licenses, vec!["MIT"]);
        assert_eq!(proto.denied_licenses, vec!["GPL-3.0"]);
        assert!(!proto.allow_unknown);
        assert!(proto.is_enabled);
        assert!(proto.created_at.is_some());
        assert!(proto.updated_at.is_some());
    }

    #[test]
    fn test_license_policy_to_proto_global() {
        let now = Utc::now();
        let policy = crate::models::sbom::LicensePolicy {
            id: Uuid::new_v4(),
            repository_id: None,
            name: "global".to_string(),
            description: None,
            allowed_licenses: vec![],
            denied_licenses: vec![],
            allow_unknown: true,
            action: crate::models::sbom::PolicyAction::Warn,
            is_enabled: true,
            created_at: now,
            updated_at: None,
        };

        let proto = license_policy_to_proto(policy);
        assert_eq!(proto.repository_id, "");
        assert_eq!(proto.description, "");
        assert!(proto.allow_unknown);
        assert!(proto.updated_at.is_none());
    }
}
