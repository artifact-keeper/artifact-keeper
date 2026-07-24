//! Integration tests for gRPC SBOM services.
//!
//! These tests verify the gRPC SBOM, CVE History, and Security Policy services
//! end to end, through the SAME authenticated interceptor contract production
//! wires in `main.rs`. Every production RPC calls `authorize_grpc_scope` as its
//! first line and fails closed (`Unauthenticated`) when no `GrpcPrincipal` was
//! stamped into the request extensions (added in #2500). The test server here
//! therefore registers each service `with_interceptor(..)` using the real
//! `AuthInterceptor`, and each client attaches a signed access-token Bearer
//! credential, so the principal is stamped exactly as it is at runtime.
//!
//! The interceptor is built with `db = None`: in that documented test mode it
//! trusts the signed token's `is_admin` / `scopes` claims instead of consulting
//! the live DB role, which lets a test mint a full-scope admin principal (or a
//! deliberately restricted one) without provisioning a `users` row.

mod common;

use artifact_keeper_backend::{
    grpc::{
        auth_interceptor::AuthInterceptor,
        generated::{
            cve_history_service_client::CveHistoryServiceClient,
            cve_history_service_server::CveHistoryServiceServer,
            sbom_service_client::SbomServiceClient, sbom_service_server::SbomServiceServer,
            security_policy_service_client::SecurityPolicyServiceClient,
            security_policy_service_server::SecurityPolicyServiceServer,
            CheckLicenseComplianceRequest, GenerateSbomRequest, GetCveTrendsRequest,
            LicensePolicy as ProtoLicensePolicy, ListLicensePoliciesRequest, PolicyAction,
            SbomFormat, UpsertLicensePolicyRequest,
        },
        sbom_server::{CveHistoryGrpcServer, SbomGrpcServer, SecurityPolicyGrpcServer},
    },
    services::auth_service::Claims,
};
use jsonwebtoken::{encode, EncodingKey, Header};
use sqlx::PgPool;
use tokio::net::TcpListener;
use tonic::transport::{Channel, Server};
use tonic::{Code, Request};

/// Shared HS256 secret for the test interceptor and every minted token. It only
/// has to be internally consistent: the interceptor is created with this secret
/// and the client tokens are signed with it.
const TEST_JWT_SECRET: &str = "grpc-sbom-integration-test-secret";

/// Mint a signed access-token JWT for the test plane.
///
/// `is_admin` sets the admin floor the interceptor enforces, and `scopes` sets
/// the per-method action-scope ceiling `authorize_grpc_scope` evaluates. Passing
/// `scopes = None` mirrors an interactive/full token (no scope restriction), so
/// `mint_admin_token()` yields a full-scope admin principal.
fn mint_token(is_admin: bool, scopes: Option<Vec<String>>) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = Claims {
        sub: uuid::Uuid::new_v4(),
        username: "grpc-test".to_string(),
        email: "grpc-test@test.local".to_string(),
        is_admin,
        allowed_repo_ids: None,
        iat: now,
        iat_ms: Some(now.saturating_mul(1000)),
        exp: now + 3600,
        token_type: "access".to_string(),
        jti: None,
        family_id: None,
        scan_pull_repo: None,
        scopes,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
    )
    .expect("failed to encode test JWT")
}

/// Full-scope admin token: passes the admin floor and every per-method scope.
fn mint_admin_token() -> String {
    mint_token(true, None)
}

/// Wrap a request message in a `tonic::Request` carrying an `authorization`
/// Bearer credential, so the interceptor authenticates it and stamps the
/// principal.
fn authed_request<T>(msg: T, token: &str) -> Request<T> {
    let mut req = Request::new(msg);
    req.metadata_mut().insert(
        "authorization",
        format!("Bearer {}", token)
            .parse()
            .expect("valid metadata value"),
    );
    req
}

/// Wrap a request message with a full-scope admin credential. Used by the
/// success-path tests.
fn admin_request<T>(msg: T) -> Request<T> {
    authed_request(msg, &mint_admin_token())
}

/// Start a test gRPC server wired with the production authentication interceptor
/// and return a channel for clients.
///
/// This mirrors the runtime wiring in `main.rs`: each service is registered via
/// `with_interceptor(server, move |req| auth.intercept(req))`, so requests carry
/// a stamped `GrpcPrincipal` and the per-method `authorize_grpc_scope` checks
/// have a principal to authorize. Registering the raw services without this
/// interceptor (as this harness did before) makes every RPC fail closed with
/// `Unauthenticated`.
async fn start_test_server(pool: PgPool) -> Channel {
    // Find an available port
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let sbom_server = SbomGrpcServer::new(pool.clone());
    let cve_history_server = CveHistoryGrpcServer::new(pool.clone());
    let security_policy_server = SecurityPolicyGrpcServer::new(pool);

    // Build the same interceptor production uses. `db = None` selects the
    // documented test mode: the interceptor trusts the signed token's
    // `is_admin` / `scopes` claims rather than consulting a live DB role.
    let auth = AuthInterceptor::new(TEST_JWT_SECRET, None);
    let sbom_auth = auth.clone();
    let cve_auth = auth.clone();
    let policy_auth = auth;

    // Spawn the server in a background task
    tokio::spawn(async move {
        // `Status` is large, so a closure returning `Result<_, Status>` trips
        // `clippy::result_large_err`; production allows it at the same spot.
        #[allow(clippy::result_large_err)]
        let sbom_interceptor = move |req| sbom_auth.intercept(req);
        #[allow(clippy::result_large_err)]
        let cve_interceptor = move |req| cve_auth.intercept(req);
        #[allow(clippy::result_large_err)]
        let policy_interceptor = move |req| policy_auth.intercept(req);

        Server::builder()
            .add_service(SbomServiceServer::with_interceptor(
                sbom_server,
                sbom_interceptor,
            ))
            .add_service(CveHistoryServiceServer::with_interceptor(
                cve_history_server,
                cve_interceptor,
            ))
            .add_service(SecurityPolicyServiceServer::with_interceptor(
                security_policy_server,
                policy_interceptor,
            ))
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

    // Try to generate an SBOM for a non-existent artifact. The caller is a
    // full-scope admin, so this passes authorization and reaches the service.
    let request = admin_request(GenerateSbomRequest {
        artifact_id: uuid::Uuid::new_v4().to_string(),
        format: SbomFormat::Cyclonedx.into(),
        force_regenerate: false,
    });

    let status = client
        .generate_sbom(request)
        .await
        .expect_err("generating an SBOM for a missing artifact must fail");

    // The insert into `sbom_documents` violates the NOT NULL foreign key
    // `artifact_id -> artifacts(id)` (migration 045), which the handler maps to
    // `Status::internal`. Asserting the exact code proves the failure is the
    // intended data error, not an auth failure (Unauthenticated /
    // PermissionDenied) masquerading as a pass, which the previous broad
    // `is_err()` assertion could not distinguish.
    assert_eq!(
        status.code(),
        Code::Internal,
        "expected an Internal (FK violation) failure, got: {status:?}"
    );
}

#[tokio::test]
#[ignore] // Requires database
async fn test_cve_history_get_trends() {
    let ctx = common::TestContext::new().await;
    let channel = start_test_server(ctx.pool.clone()).await;

    let mut client = CveHistoryServiceClient::new(channel);

    // Get global CVE trends
    let request = admin_request(GetCveTrendsRequest {
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
    let request = admin_request(ListLicensePoliciesRequest {
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

    let request = admin_request(UpsertLicensePolicyRequest {
        policy: Some(policy),
    });

    let response = policy_client.upsert_license_policy(request).await;
    assert!(response.is_ok());
    let created_policy = response.unwrap().into_inner();
    assert!(!created_policy.id.is_empty());

    // Check compliance with allowed licenses
    let request = admin_request(CheckLicenseComplianceRequest {
        licenses: vec!["MIT".to_string(), "Apache-2.0".to_string()],
        repository_id: String::new(),
    });

    let response = sbom_client.check_license_compliance(request).await;
    assert!(response.is_ok());
    let compliance = response.unwrap().into_inner();
    assert!(compliance.compliant);
    assert!(compliance.violations.is_empty());

    // Clean up - delete the test policy
    let delete_request = admin_request(
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

    let request = admin_request(UpsertLicensePolicyRequest {
        policy: Some(policy),
    });

    let response = policy_client.upsert_license_policy(request).await;
    assert!(response.is_ok());
    let created_policy = response.unwrap().into_inner();

    // Check compliance with a denied license
    let request = admin_request(CheckLicenseComplianceRequest {
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
    let delete_request = admin_request(
        artifact_keeper_backend::grpc::generated::DeleteLicensePolicyRequest {
            id: created_policy.id,
        },
    );
    let _ = policy_client.delete_license_policy(delete_request).await;
}

// ---------------------------------------------------------------------------
// Negative-path tests: prove authentication and per-method scope authorization
// are actually enforced over the wire, not just in unit tests. These use the
// same authenticated harness as the success-path tests above.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore] // Requires database
async fn test_grpc_unauthenticated_without_credential() {
    let ctx = common::TestContext::new().await;
    let channel = start_test_server(ctx.pool.clone()).await;

    let mut client = SecurityPolicyServiceClient::new(channel);

    // No `authorization` metadata at all: the interceptor rejects the request
    // before it reaches the service, so no `GrpcPrincipal` is ever stamped.
    let request = Request::new(ListLicensePoliciesRequest {
        repository_id: String::new(),
    });

    let status = client
        .list_license_policies(request)
        .await
        .expect_err("a request with no credential must be rejected");

    assert_eq!(
        status.code(),
        Code::Unauthenticated,
        "expected Unauthenticated for a missing credential, got: {status:?}"
    );
}

#[tokio::test]
#[ignore] // Requires database
async fn test_grpc_read_only_scope_denied_on_write() {
    let ctx = common::TestContext::new().await;
    let channel = start_test_server(ctx.pool.clone()).await;

    let mut client = SbomServiceClient::new(channel);

    // A read-only principal (admin floor satisfied, but scope ceiling limited to
    // `read:artifacts`) calling a write RPC (`generate_sbom` requires
    // `write:artifacts`). `authorize_grpc_scope` is the method's first line and
    // returns before any DB work, so no records are created or need cleanup.
    let read_only = mint_token(true, Some(vec!["read:artifacts".to_string()]));
    let request = authed_request(
        GenerateSbomRequest {
            artifact_id: uuid::Uuid::new_v4().to_string(),
            format: SbomFormat::Cyclonedx.into(),
            force_regenerate: false,
        },
        &read_only,
    );

    let status = client
        .generate_sbom(request)
        .await
        .expect_err("a read-only token must not perform a write RPC");

    assert_eq!(
        status.code(),
        Code::PermissionDenied,
        "expected PermissionDenied for a read-only token on a write RPC, got: {status:?}"
    );
}
