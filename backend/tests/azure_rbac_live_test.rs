//! Live integration test for Azure RBAC (service principal) auth.
//!
//! Requires env vars:
//!   AZURE_STORAGE_ACCOUNT, AZURE_STORAGE_CONTAINER,
//!   AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
//!
//! Run with:
//!   cargo test --test azure_rbac_live_test -- --ignored --nocapture

use bytes::Bytes;

#[tokio::test]
#[ignore]
async fn test_azure_rbac_put_get_exists_delete() {
    // Check that required env vars are set
    let account = std::env::var("AZURE_STORAGE_ACCOUNT").expect("AZURE_STORAGE_ACCOUNT not set");
    let container =
        std::env::var("AZURE_STORAGE_CONTAINER").expect("AZURE_STORAGE_CONTAINER not set");
    let _tenant = std::env::var("AZURE_TENANT_ID").expect("AZURE_TENANT_ID not set");
    let _client_id = std::env::var("AZURE_CLIENT_ID").expect("AZURE_CLIENT_ID not set");
    let _client_secret = std::env::var("AZURE_CLIENT_SECRET").expect("AZURE_CLIENT_SECRET not set");

    println!("Testing Azure RBAC against {}/{}", account, container);

    // Build config without access key to trigger RBAC mode
    let config = artifact_keeper_backend::storage::azure::AzureConfig {
        account_name: account,
        container_name: container,
        access_key: None,
        endpoint: None,
        redirect_downloads: false,
        sas_expiry: std::time::Duration::from_secs(3600),
        path_format: artifact_keeper_backend::storage::StoragePathFormat::Native,
    };

    use artifact_keeper_backend::storage::StorageBackend;

    let backend = artifact_keeper_backend::storage::azure::AzureBackend::new(config)
        .await
        .expect("Failed to create Azure RBAC backend");

    assert!(backend.is_rbac(), "Backend should be in RBAC mode");
    assert!(
        !backend.supports_redirect(),
        "RBAC mode should not support SAS redirects"
    );

    let test_key = format!("rbac-test/{}", uuid::Uuid::new_v4());
    let test_data = Bytes::from("Hello from Azure RBAC integration test!");

    // PUT
    println!("  PUT {}", test_key);
    backend
        .put(&test_key, test_data.clone())
        .await
        .expect("PUT failed");

    // EXISTS
    println!("  EXISTS {}", test_key);
    let exists = backend.exists(&test_key).await.expect("EXISTS failed");
    assert!(exists, "Blob should exist after PUT");

    // GET
    println!("  GET {}", test_key);
    let retrieved = backend.get(&test_key).await.expect("GET failed");
    assert_eq!(retrieved, test_data, "Retrieved data should match");

    // DELETE
    println!("  DELETE {}", test_key);
    backend.delete(&test_key).await.expect("DELETE failed");

    // EXISTS after delete
    println!("  EXISTS (after delete) {}", test_key);
    let exists_after = backend
        .exists(&test_key)
        .await
        .expect("EXISTS after delete failed");
    assert!(!exists_after, "Blob should not exist after DELETE");

    println!("  All RBAC operations passed!");
}
