//! Integration tests for gRPC SBOM services.
//!
//! These tests verify the gRPC SBOM, CVE History, and Security Policy services.

mod common;

use artifact_keeper_backend::grpc::{
    generated::{
        sbom_service_client::SbomServiceClient,
        cve_history_service_client::CveHistoryServiceClient,
        security_policy_service_client::SecurityPolicyServiceClient,
        sbom_service_server::SbomServiceServer,
        cve_history_service_server::CveHistoryServiceServer,
        security_policy_service_server::SecurityPolicyServiceServer,
        CheckLicenseComplianceRequest, GenerateSbomRequest, GetCveTrendsRequest,
        ListLicensePoliciesRequest, SbomFormat,
        UpsertLicensePolicyRequest, LicensePolicy as ProtoLicensePolicy, PolicyAction,
    },
    sbom_server::{CveHistoryGrpcServer, SbomGrpcServer, SecurityPolicyGrpcServer},
};
use sqlx::PgPool;
use tokio::net::TcpListener;
use tonic::transport::{Channel, Server};

/// Start a test gRPC server and return the channel for clients.
async fn start_test_server(pool: PgPool) -> Channel {
    // Find an available port
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let sbom_server = SbomGrpcServer::new(pool.clone());
    let cve_history_server = CveHistoryGrpcServer::new(pool.clone());
    let security_policy_server = SecurityPolicyGrpcServer::new(pool);

    // Spawn the server in a background task
    tokio::spawn(async move {
        Server::builder()
            .add_service(SbomServiceServer::new(sbom_server))
            .add_service(CveHistoryServiceServer::new(cve_history_server))
            .add_service(SecurityPolicyServiceServer::new(security_policy_server))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .expect("gRPC server failed");
    });

    // Give the server a moment to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Connect to the server
    Channel::from_shared(format!("http://{}", addr))
        .unwrap()
        .connect()
        .await
        .expect("Failed to connect to test gRPC server")
}

#[tokio::test]
#[ignore] // Requires database
async fn test_sbom_service_generate_sbom_without_artifact() {
    let ctx = common::TestContext::new().await;
    let channel = start_test_server(ctx.pool.clone()).await;

    let mut client = SbomServiceClient::new(channel);

    // Try to generate SBOM for non-existent artifact
    let request = tonic::Request::new(GenerateSbomRequest {
        artifact_id: uuid::Uuid::new_v4().to_string(),
        format: SbomFormat::Cyclonedx.into(),
        force_regenerate: false,
    });

    let result = client.generate_sbom(request).await;

    // Should fail because artifact doesn't exist
    assert!(result.is_err());
}

#[tokio::test]
#[ignore] // Requires database
async fn test_cve_history_get_trends() {
    let ctx = common::TestContext::new().await;
    let channel = start_test_server(ctx.pool.clone()).await;

    let mut client = CveHistoryServiceClient::new(channel);

    // Get global CVE trends
    let request = tonic::Request::new(GetCveTrendsRequest {
        repository_id: String::new(),
        days: 30,
    });

    let response = client.get_cve_trends(request).await;

    // Should succeed even with no data
    assert!(response.is_ok());
    let trends = response.unwrap().into_inner();
    assert!(trends.total_cves >= 0);
}

#[tokio::test]
#[ignore] // Requires database
async fn test_security_policy_list_policies() {
    let ctx = common::TestContext::new().await;
    let channel = start_test_server(ctx.pool.clone()).await;

    let mut client = SecurityPolicyServiceClient::new(channel);

    // List all policies
    let request = tonic::Request::new(ListLicensePoliciesRequest {
        repository_id: String::new(),
    });

    let response = client.list_license_policies(request).await;

    // Should succeed
    assert!(response.is_ok());
    let policies = response.unwrap().into_inner();
    // We have a default policy from migration
    assert!(!policies.policies.is_empty());
}

#[tokio::test]
#[ignore] // Requires database
async fn test_security_policy_upsert_and_check_compliance() {
    let ctx = common::TestContext::new().await;
    let channel = start_test_server(ctx.pool.clone()).await;

    let mut policy_client = SecurityPolicyServiceClient::new(channel.clone());
    let mut sbom_client = SbomServiceClient::new(channel);

    // Create a test policy
    let policy = ProtoLicensePolicy {
        id: String::new(),
        repository_id: String::new(), // Global policy
        name: format!("test-policy-{}", common::test_id()),
        description: "Test license policy".to_string(),
        allowed_licenses: vec!["MIT".to_string(), "Apache-2.0".to_string()],
        denied_licenses: vec!["GPL-3.0".to_string()],
        allow_unknown: true,
        action: PolicyAction::Warn.into(),
        is_enabled: true,
        created_at: None,
        updated_at: None,
    };

    let request = tonic::Request::new(UpsertLicensePolicyRequest {
        policy: Some(policy),
    });

    let response = policy_client.upsert_license_policy(request).await;
    assert!(response.is_ok());
    let created_policy = response.unwrap().into_inner();
    assert!(!created_policy.id.is_empty());

    // Check compliance with allowed licenses
    let request = tonic::Request::new(CheckLicenseComplianceRequest {
        licenses: vec!["MIT".to_string(), "Apache-2.0".to_string()],
        repository_id: String::new(),
    });

    let response = sbom_client.check_license_compliance(request).await;
    assert!(response.is_ok());
    let compliance = response.unwrap().into_inner();
    assert!(compliance.compliant);
    assert!(compliance.violations.is_empty());

    // Clean up - delete the test policy
    let delete_request = tonic::Request::new(
        artifact_keeper_backend::grpc::generated::DeleteLicensePolicyRequest {
            id: created_policy.id,
        },
    );
    let _ = policy_client.delete_license_policy(delete_request).await;
}

#[tokio::test]
#[ignore] // Requires database
async fn test_security_policy_check_denied_license() {
    let ctx = common::TestContext::new().await;
    let channel = start_test_server(ctx.pool.clone()).await;

    let mut policy_client = SecurityPolicyServiceClient::new(channel.clone());
    let mut sbom_client = SbomServiceClient::new(channel);

    // Create a strict policy with denied licenses
    let policy = ProtoLicensePolicy {
        id: String::new(),
        repository_id: String::new(),
        name: format!("strict-policy-{}", common::test_id()),
        description: "Strict license policy for testing".to_string(),
        allowed_licenses: vec![],
        denied_licenses: vec!["GPL-3.0".to_string(), "AGPL-3.0".to_string()],
        allow_unknown: false,
        action: PolicyAction::Block.into(),
        is_enabled: true,
        created_at: None,
        updated_at: None,
    };

    let request = tonic::Request::new(UpsertLicensePolicyRequest {
        policy: Some(policy),
    });

    let response = policy_client.upsert_license_policy(request).await;
    assert!(response.is_ok());
    let created_policy = response.unwrap().into_inner();

    // Check compliance with a denied license
    let request = tonic::Request::new(CheckLicenseComplianceRequest {
        licenses: vec!["MIT".to_string(), "GPL-3.0".to_string()],
        repository_id: String::new(),
    });

    let response = sbom_client.check_license_compliance(request).await;
    assert!(response.is_ok());
    let compliance = response.unwrap().into_inner();
    assert!(!compliance.compliant);
    assert!(!compliance.violations.is_empty());
    assert!(compliance.violations.iter().any(|v| v.contains("GPL-3.0")));

    // Clean up
    let delete_request = tonic::Request::new(
        artifact_keeper_backend::grpc::generated::DeleteLicensePolicyRequest {
            id: created_policy.id,
        },
    );
    let _ = policy_client.delete_license_policy(delete_request).await;
}
