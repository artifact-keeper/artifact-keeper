use super::*;
use crate::api::handlers::{rpm, test_db_helpers as tdh};
use crate::services::rpm_layout;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};

fn options() -> RestoreOptions {
    RestoreOptions {
        restore_database: true,
        restore_artifacts: true,
        target_repository_id: None,
        allow_unverified_archive: false,
        actor: None,
    }
}

async fn native(
    f: &tdh::Fixture,
    method: &str,
    path: &str,
    body: &'static str,
) -> (StatusCode, Bytes) {
    tdh::send(
        f.router_with_auth(rpm::router()),
        Request::builder()
            .method(method)
            .uri(format!("/{}/{path}", f.repo_key))
            .body(Body::from(body))
            .unwrap(),
    )
    .await
}

async fn archive(
    service: &BackupService,
    repositories: &serde_json::Value,
    artifacts: &serde_json::Value,
    contents: &[(String, Vec<u8>)],
) -> Uuid {
    let job = service
        .create(CreateBackupRequest {
            backup_type: BackupType::Full,
            repository_ids: None,
            exclude_repository_ids: None,
            since: None,
            created_by: None,
            name: None,
        })
        .await
        .unwrap();
    let repos = serde_json::to_vec(repositories).unwrap();
    let artifacts = serde_json::to_vec(artifacts).unwrap();
    let tables = [
        ("repositories", repos.as_slice()),
        ("artifacts", artifacts.as_slice()),
    ];
    let contents: Vec<_> = contents
        .iter()
        .map(|(key, bytes)| (key.as_str(), bytes.as_slice()))
        .collect();
    let (size, checksum) = payload_summary(tables.iter().copied().chain(contents.iter().copied()));
    let manifest = BackupManifest {
        version: "1.0".into(),
        backup_id: job.id,
        backup_type: BackupType::Full,
        created_at: Utc::now(),
        database_tables: vec!["repositories".into(), "artifacts".into()],
        artifact_count: contents.len() as i64,
        artifacts_unreadable: 0,
        total_size_bytes: size,
        checksum: checksum.clone(),
    };
    let tar =
        build_backup_tar(&tables, &contents, &serde_json::to_vec(&manifest).unwrap()).unwrap();
    let length = tar.len() as i64;
    service
        .archive_storage
        .put(job.storage_path.as_ref().unwrap(), Bytes::from(tar))
        .await
        .unwrap();
    sqlx::query(
        "UPDATE backups SET status='completed',size_bytes=$2,payload_checksum=$3 WHERE id=$1",
    )
    .bind(job.id)
    .bind(length)
    .bind(checksum)
    .execute(&service.db)
    .await
    .unwrap();
    job.id
}

#[tokio::test]
async fn depth_archive_roundtrip_preserves_content_and_refuses_conflicts_4216() {
    let Some(f) = tdh::Fixture::setup("local", "rpm").await else {
        return;
    };
    let storage = Arc::new(StorageService::new(Arc::new(
        crate::services::storage_service::FilesystemBackend::new(f.storage_dir.clone()),
    )));
    let service = BackupService::new(f.pool.clone(), storage);
    let mut conn = f.pool.acquire().await.unwrap();
    let plain = BackupService::export_table(&mut conn, "repositories")
        .await
        .unwrap();
    assert!(plain
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == f.repo_id.to_string())
        .unwrap()
        .get("repodata_depth")
        .is_none());
    rpm_layout::set_depth(&mut conn, f.repo_id, 1)
        .await
        .unwrap();
    sqlx::query("INSERT INTO repository_config(repository_id,key,value) VALUES($1,'not-for-backups','secret-test-value')")
        .bind(f.repo_id).execute(&mut *conn).await.unwrap();
    for (path, body) in [
        ("a/pkg-1-1.noarch.rpm", "first"),
        ("b/pkg-1-1.noarch.rpm", "second"),
    ] {
        let (status, response) = native(&f, "PUT", path, body).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "{}",
            String::from_utf8_lossy(&response)
        );
    }
    // Use production exporters and codec, scoped to this fixture so a restore
    // cannot recreate repositories belonging to concurrently running tests.
    let exported = BackupService::export_table(&mut conn, "repositories")
        .await
        .unwrap();
    let repositories = serde_json::json!([exported
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == f.repo_id.to_string())
        .unwrap()
        .clone()]);
    assert_eq!(repositories[0]["repodata_depth"], 1);
    assert!(!repositories.to_string().contains("secret-test-value"));
    let artifacts = BackupService::export_artifacts(&mut conn, Some(&[f.repo_id]), None)
        .await
        .unwrap();
    let mut contents = Vec::new();
    for row in artifacts.as_array().unwrap() {
        let key = row["storage_key"].as_str().unwrap().to_string();
        contents.push((
            key.clone(),
            service.storage.get(&key).await.unwrap().to_vec(),
        ));
    }
    drop(conn);
    let good = archive(&service, &repositories, &artifacts, &contents).await;
    let mut backups = vec![good];
    sqlx::query("DELETE FROM repositories WHERE id=$1")
        .bind(f.repo_id)
        .execute(&f.pool)
        .await
        .unwrap();
    for (key, _) in &contents {
        f.state.storage.delete(key).await.unwrap();
    }
    let restored = service.restore(good, options()).await.unwrap();
    assert!(restored.errors.is_empty(), "{:?}", restored.errors);
    assert_eq!(rpm_layout::depth(&f.pool, f.repo_id).await.unwrap(), 1);
    for (root, expected) in [("a", "first"), ("b", "second")] {
        let (status, bytes) = native(&f, "GET", &format!("{root}/pkg-1-1.noarch.rpm"), "").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(bytes, expected);
        let (status, xml) = native(&f, "GET", &format!("{root}/repodata/repomd.xml"), "").await;
        assert_eq!(status, StatusCode::OK);
        assert!(String::from_utf8_lossy(&xml).contains("repodata/primary.xml.gz"));
        let (status, primary) =
            native(&f, "GET", &format!("{root}/repodata/primary.xml.gz"), "").await;
        assert_eq!(status, StatusCode::OK);
        use std::io::Read;
        let mut primary_xml = String::new();
        flate2::read::GzDecoder::new(primary.as_ref())
            .read_to_string(&mut primary_xml)
            .unwrap();
        assert!(primary_xml.contains("href=\"pkg-1-1.noarch.rpm\""));
        assert!(primary_xml.contains(
            &crate::services::artifact_service::ArtifactService::calculate_sha256(
                expected.as_bytes()
            )
        ));
    }
    assert_eq!(
        native(&f, "GET", "repodata/repomd.xml", "").await.0,
        StatusCode::NOT_FOUND
    );
    assert!(service
        .restore(good, options())
        .await
        .unwrap()
        .errors
        .is_empty());
    for value in [
        Some(serde_json::json!(2)),
        None,
        Some(serde_json::Value::Null),
    ] {
        let mut conflicting = repositories.clone();
        if let Some(value) = value {
            conflicting[0]["repodata_depth"] = value;
        } else {
            conflicting[0]
                .as_object_mut()
                .unwrap()
                .remove("repodata_depth");
        }
        let bad = archive(&service, &conflicting, &artifacts, &contents).await;
        backups.push(bad);
        assert!(service.restore(bad, options()).await.is_err());
        assert_eq!(rpm_layout::depth(&f.pool, f.repo_id).await.unwrap(), 1);
    }
    let mut invalid_artifacts = artifacts.clone();
    invalid_artifacts[0]["path"] = "pkg.rpm".into();
    let bad = archive(&service, &repositories, &invalid_artifacts, &contents).await;
    backups.push(bad);
    sqlx::query("DELETE FROM repositories WHERE id=$1")
        .bind(f.repo_id)
        .execute(&f.pool)
        .await
        .unwrap();
    assert!(service.restore(bad, options()).await.is_err());
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM repositories WHERE id=$1)")
        .bind(f.repo_id)
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert!(
        !exists,
        "layout failure must roll back the repository and every artifact"
    );
    service.restore(good, options()).await.unwrap();
    sqlx::query("DELETE FROM backups WHERE id=ANY($1)")
        .bind(backups)
        .execute(&f.pool)
        .await
        .unwrap();
    f.teardown().await;
}

#[test]
fn archived_depth_values_are_strict_and_legacy_absence_means_zero_4216() {
    let id = Uuid::new_v4();
    let row =
        serde_json::json!({"id":id,"format":"rpm","repo_type":"local","curation_enabled":false});
    let entries = |row| {
        vec![(
            "database/repositories.json".into(),
            serde_json::to_vec(&vec![row]).unwrap(),
        )]
    };
    assert_eq!(
        archive_repository_layouts(&entries(row.clone())).unwrap()[&id],
        0
    );
    for value in [
        serde_json::json!(null),
        serde_json::json!(-1),
        serde_json::json!(1.5),
        serde_json::json!("1"),
        serde_json::json!(1024),
    ] {
        let mut invalid = row.clone();
        invalid["repodata_depth"] = value;
        assert!(archive_repository_layouts(&entries(invalid)).is_err());
    }
    let mut valid = row;
    valid["repodata_depth"] = 2.into();
    assert_eq!(
        archive_repository_layouts(&entries(valid.clone())).unwrap()[&id],
        2
    );
    valid["repo_type"] = "virtual".into();
    assert!(archive_repository_layouts(&entries(valid)).is_err());
}
