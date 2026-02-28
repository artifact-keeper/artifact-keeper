//! Live integration test for Azure Shared Key auth (backwards compatibility).
//!
//! Requires env vars:
//!   AZURE_STORAGE_ACCOUNT, AZURE_STORAGE_CONTAINER, AZURE_STORAGE_ACCESS_KEY
//!
//! Run with:
//!   cargo test --test azure_shared_key_live_test -- --ignored --nocapture

use bytes::Bytes;

#[tokio::test]
#[ignore]
async fn test_azure_shared_key_put_get_exists_delete() {
    let account = std::env::var("AZURE_STORAGE_ACCOUNT").expect("AZURE_STORAGE_ACCOUNT not set");
    let container =
        std::env::var("AZURE_STORAGE_CONTAINER").expect("AZURE_STORAGE_CONTAINER not set");
    let access_key =
        std::env::var("AZURE_STORAGE_ACCESS_KEY").expect("AZURE_STORAGE_ACCESS_KEY not set");

    println!("Testing Azure Shared Key against {}/{}", account, container);

    let config = artifact_keeper_backend::storage::azure::AzureConfig {
        account_name: account,
        container_name: container,
        access_key: Some(access_key),
        endpoint: None,
        redirect_downloads: true,
        sas_expiry: std::time::Duration::from_secs(3600),
        path_format: artifact_keeper_backend::storage::StoragePathFormat::Native,
    };

    use artifact_keeper_backend::storage::StorageBackend;

    let backend = artifact_keeper_backend::storage::azure::AzureBackend::new(config)
        .await
        .expect("Failed to create Azure Shared Key backend");

    assert!(!backend.is_rbac(), "Backend should be in Shared Key mode");
    assert!(
        backend.supports_redirect(),
        "Shared Key mode should support SAS redirects"
    );

    let test_key = format!("sharedkey-test/{}", uuid::Uuid::new_v4());
    let test_data = Bytes::from("Hello from Azure Shared Key integration test!");

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

    // PRESIGNED URL
    println!("  PRESIGNED URL {}", test_key);
    let presigned = backend
        .get_presigned_url(&test_key, std::time::Duration::from_secs(300))
        .await
        .expect("PRESIGNED URL failed");
    assert!(presigned.is_some(), "Should generate SAS URL");
    let sas_url = presigned.unwrap();
    assert!(sas_url.url.contains("sig="), "SAS URL should contain sig");
    println!(
        "    SAS URL: {}...{}",
        &sas_url.url[..80],
        &sas_url.url[sas_url.url.len() - 20..]
    );

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

    println!("  All Shared Key operations passed!");
}
