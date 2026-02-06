//! gRPC server implementations for SBOM services.

use crate::services::sbom_service::{DependencyInfo, SbomService};
use crate::models::sbom::{CveStatus, SbomFormat};
use sqlx::PgPool;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use uuid::Uuid;

use super::generated::{
    sbom_service_server::SbomService as SbomServiceTrait,
    cve_history_service_server::CveHistoryService as CveHistoryServiceTrait,
    security_policy_service_server::SecurityPolicyService as SecurityPolicyServiceTrait,
    *,
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

        let result = self.service.check_license_compliance(&policy, &req.licenses);

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

        let proto_entries: Vec<CveHistoryEntry> = entries
            .into_iter()
            .map(cve_entry_to_proto)
            .collect();

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
        let policy = req.policy.ok_or_else(|| Status::invalid_argument("Policy required"))?;

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

        let proto_policies: Vec<LicensePolicy> = policies
            .into_iter()
            .map(license_policy_to_proto)
            .collect();

        Ok(Response::new(ListLicensePoliciesResponse {
            policies: proto_policies,
        }))
    }
}

// === Conversion helpers ===

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

fn proto_to_policy_action(action: super::generated::PolicyAction) -> crate::models::sbom::PolicyAction {
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
            SbomFormat::from_str(&doc.format).unwrap_or(SbomFormat::CycloneDX)
        ).into(),
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
    let status = CveStatus::from_str(&entry.status).unwrap_or(CveStatus::Open);
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
        acknowledged_by: entry.acknowledged_by.map(|u| u.to_string()).unwrap_or_default(),
        acknowledged_at: entry.acknowledged_at.map(datetime_to_proto),
        acknowledged_reason: entry.acknowledged_reason.unwrap_or_default(),
    }
}

fn license_policy_to_proto(policy: crate::models::sbom::LicensePolicy) -> LicensePolicy {
    LicensePolicy {
        id: policy.id.to_string(),
        repository_id: policy.repository_id.map(|u| u.to_string()).unwrap_or_default(),
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

fn model_policy_action_to_proto(action: crate::models::sbom::PolicyAction) -> super::generated::PolicyAction {
    match action {
        crate::models::sbom::PolicyAction::Allow => super::generated::PolicyAction::Allow,
        crate::models::sbom::PolicyAction::Warn => super::generated::PolicyAction::Warn,
        crate::models::sbom::PolicyAction::Block => super::generated::PolicyAction::Block,
    }
}
