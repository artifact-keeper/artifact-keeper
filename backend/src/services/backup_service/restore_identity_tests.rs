//! A restore into a server that already has its own admin and roles (#5856).

use super::*;
use crate::api::handlers::test_db_helpers as tdh;
use crate::services::storage_service::FilesystemBackend;

fn options() -> RestoreOptions {
    RestoreOptions {
        restore_database: true,
        restore_artifacts: true,
        target_repository_id: None,
        allow_unverified_archive: false,
        actor: None,
    }
}

/// Store a completed full backup of `tables` and `contents`, with its payload
/// checksum recorded on the row the way a real backup records it.
pub(super) async fn archive_tables(
    service: &BackupService,
    tables: &[(&str, serde_json::Value)],
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
    let dumps: Vec<(&str, Vec<u8>)> = tables
        .iter()
        .map(|(table, rows)| (*table, serde_json::to_vec(rows).unwrap()))
        .collect();
    let tables: Vec<(&str, &[u8])> = dumps
        .iter()
        .map(|(table, bytes)| (*table, bytes.as_slice()))
        .collect();
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
        database_tables: tables.iter().map(|(t, _)| t.to_string()).collect(),
        artifact_count: contents.len() as i64,
        artifacts_unreadable: 0,
        total_size_bytes: size,
        checksum: checksum.clone(),
        contents: BackupContents::default(),
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

/// Rows of `table` matching `filter` (bound to `id`), as a backup dumps them.
async fn dump(pool: &PgPool, table: &str, filter: &str, id: Uuid) -> Vec<serde_json::Value> {
    let query = format!("SELECT row_to_json(t) FROM {table} t WHERE {filter}");
    sqlx::query_scalar(sqlx::AssertSqlSafe(&*query))
        .bind(id)
        .fetch_all(pool)
        .await
        .unwrap()
}

fn service_on(f: &tdh::Fixture) -> BackupService {
    let storage = Arc::new(StorageService::new(Arc::new(FilesystemBackend::new(
        f.storage_dir.clone(),
    ))));
    BackupService::new(f.pool.clone(), storage)
}

/// The source server's admin owns a repository, an artifact, a webhook, a
/// global role and a repository role. The target is a fresh server: its own
/// admin holds the same username under another id, and it seeded the same
/// role names with ids of its own. Everything must come back, owned by the
/// target's rows.
#[tokio::test]
async fn restore_into_a_fresh_server_keeps_rows_owned_by_archived_users_and_roles_5856() {
    let Some(f) = tdh::Fixture::setup("local", "generic").await else {
        return;
    };
    let pool = &f.pool;
    let service = service_on(&f);
    let source_admin = f.user_id;

    let key = format!("restore-5856/{}", Uuid::new_v4());
    let bytes = b"artifact owned by the archived admin".to_vec();
    service
        .storage
        .put(&key, Bytes::from(bytes.clone()))
        .await
        .unwrap();
    let artifact_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO artifacts (id, repository_id, path, name, size_bytes, checksum_sha256, \
         content_type, storage_key, uploaded_by) \
         VALUES ($1, $2, 'owned/a.bin', 'a.bin', $3, $4, 'application/octet-stream', $5, $6)",
    )
    .bind(artifact_id)
    .bind(f.repo_id)
    .bind(bytes.len() as i64)
    .bind(crate::services::artifact_service::ArtifactService::calculate_sha256(&bytes))
    .bind(&key)
    .bind(source_admin)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query("UPDATE repositories SET created_by = $1 WHERE id = $2")
        .bind(source_admin)
        .bind(f.repo_id)
        .execute(pool)
        .await
        .unwrap();
    let webhook_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO webhooks (id, name, url, events, repository_id, created_by) \
         VALUES ($1, $2, 'https://hooks.example.test/5856', ARRAY['artifact_uploaded'], $3, $4)",
    )
    .bind(webhook_id)
    .bind(format!("hook-5856-{webhook_id}"))
    .bind(f.repo_id)
    .bind(source_admin)
    .execute(pool)
    .await
    .unwrap();
    let developer: Uuid = sqlx::query_scalar("SELECT id FROM roles WHERE name = 'developer'")
        .fetch_one(pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)")
        .bind(source_admin)
        .bind(developer)
        .execute(pool)
        .await
        .unwrap();

    // A fine-grained grant names its principal by type and id, with no
    // foreign key to follow.
    let permission_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO permissions (id, principal_type, principal_id, target_type, target_id, actions) \
         VALUES ($1, 'user', $2, 'repository', $3, ARRAY['read'])",
    )
    .bind(permission_id)
    .bind(source_admin)
    .bind(f.repo_id)
    .execute(pool)
    .await
    .unwrap();
    let permissions = dump(pool, "permissions", "id = $1", permission_id).await;
    sqlx::query("DELETE FROM permissions WHERE id = $1")
        .bind(permission_id)
        .execute(pool)
        .await
        .unwrap();

    // The source install generated its own role ids: give every role the
    // archive mentions an id this server has never seen.
    let mut role_assignments = dump(pool, "role_assignments", "user_id = $1", source_admin).await;
    let mut user_roles = dump(pool, "user_roles", "user_id = $1", source_admin).await;
    assert!(!role_assignments.is_empty(), "fixture grants a repo role");
    let archived_repo_roles = role_assignments.len() as i64;
    let mut archived_roles: std::collections::HashMap<String, Uuid> = Default::default();
    let mut roles = Vec::new();
    for row in role_assignments.iter_mut().chain(user_roles.iter_mut()) {
        let live = row["role_id"].as_str().unwrap().to_string();
        if !archived_roles.contains_key(&live) {
            let mut role = dump(pool, "roles", "id = $1", live.parse().unwrap()).await;
            let archived = Uuid::new_v4();
            role[0]["id"] = serde_json::json!(archived);
            roles.append(&mut role);
            archived_roles.insert(live.clone(), archived);
        }
        row["role_id"] = serde_json::json!(archived_roles[&live]);
    }
    let mut conn = pool.acquire().await.unwrap();
    let repositories: Vec<serde_json::Value> =
        BackupService::export_table(&mut conn, "repositories")
            .await
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["id"] == f.repo_id.to_string())
            .cloned()
            .collect();
    let artifacts = BackupService::export_artifacts(&mut conn, Some(&[f.repo_id]), None)
        .await
        .unwrap();
    drop(conn);
    let tables = [
        (
            "users",
            dump(pool, "users", "id = $1", source_admin).await.into(),
        ),
        ("roles", roles.into()),
        ("user_roles", user_roles.into()),
        ("repositories", repositories.into()),
        ("artifacts", artifacts),
        ("role_assignments", role_assignments.into()),
        ("permissions", permissions.into()),
        (
            "webhooks",
            dump(pool, "webhooks", "id = $1", webhook_id).await.into(),
        ),
    ];
    let backup = archive_tables(&service, &tables, &[(key.clone(), bytes.clone())]).await;

    // The fresh server: none of the source's rows or bytes, and an admin of
    // its own that holds the archived admin's username.
    for sql in [
        "DELETE FROM webhooks WHERE id = $1",
        "DELETE FROM artifacts WHERE repository_id = $1",
        "DELETE FROM role_assignments WHERE repository_id = $1",
        "DELETE FROM repositories WHERE id = $1",
    ] {
        let id = if sql.contains("webhooks") {
            webhook_id
        } else {
            f.repo_id
        };
        sqlx::query(sqlx::AssertSqlSafe(sql))
            .bind(id)
            .execute(pool)
            .await
            .unwrap();
    }
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(source_admin)
        .execute(pool)
        .await
        .unwrap();
    let target_admin = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin) \
         VALUES ($1, $2, $3, 'unused', 'local', true)",
    )
    .bind(target_admin)
    .bind(&f.username)
    .bind(format!("fresh-{target_admin}@test.local"))
    .execute(pool)
    .await
    .unwrap();
    service.storage.delete(&key).await.unwrap();

    let restored = service.restore(backup, options()).await.unwrap();

    let repo_owner: Option<Uuid> =
        sqlx::query_scalar("SELECT created_by FROM repositories WHERE id = $1")
            .bind(f.repo_id)
            .fetch_optional(pool)
            .await
            .unwrap()
            .flatten();
    let uploader: Option<Uuid> =
        sqlx::query_scalar("SELECT uploaded_by FROM artifacts WHERE id = $1")
            .bind(artifact_id)
            .fetch_optional(pool)
            .await
            .unwrap()
            .flatten();
    let hook_owner: Option<Uuid> =
        sqlx::query_scalar("SELECT created_by FROM webhooks WHERE id = $1")
            .bind(webhook_id)
            .fetch_optional(pool)
            .await
            .unwrap()
            .flatten();
    let has_developer: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM user_roles WHERE user_id = $1 AND role_id = $2)",
    )
    .bind(target_admin)
    .bind(developer)
    .fetch_one(pool)
    .await
    .unwrap();
    let repo_roles: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM role_assignments ra JOIN roles r ON r.id = ra.role_id \
         WHERE ra.user_id = $1 AND ra.repository_id = $2",
    )
    .bind(target_admin)
    .bind(f.repo_id)
    .fetch_one(pool)
    .await
    .unwrap();
    let grantee: Option<Uuid> =
        sqlx::query_scalar("SELECT principal_id FROM permissions WHERE id = $1")
            .bind(permission_id)
            .fetch_optional(pool)
            .await
            .unwrap();
    let restored_bytes = service.storage.get(&key).await.ok();

    // Clean up before asserting, so a failure leaves no rows behind.
    let _ = sqlx::query("DELETE FROM webhooks WHERE id = $1")
        .bind(webhook_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM permissions WHERE id = $1")
        .bind(permission_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM user_roles WHERE user_id = $1")
        .bind(target_admin)
        .execute(pool)
        .await;
    tdh::cleanup(pool, f.repo_id, target_admin).await;
    f.teardown().await;

    assert_eq!(
        restored.status,
        RestoreStatus::Completed,
        "{:?}",
        restored.errors
    );
    assert!(restored.errors.is_empty(), "{:?}", restored.errors);
    assert_eq!(repo_owner, Some(target_admin), "repository not restored");
    assert_eq!(uploader, Some(target_admin), "artifact not restored");
    assert_eq!(hook_owner, Some(target_admin), "webhook not restored");
    assert!(has_developer, "user_roles row lost on the archived role id");
    assert_eq!(repo_roles, archived_repo_roles, "role_assignments lost");
    assert_eq!(
        grantee,
        Some(target_admin),
        "permission left on the archived id"
    );
    assert_eq!(restored_bytes.as_deref(), Some(bytes.as_slice()));
}

#[derive(Clone, Default)]
struct CapturedLogs(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLogs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogs {
    type Writer = CapturedLogs;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// A row that still cannot be restored is an error of the restore, which is
/// then `partial`, and neither the error nor the log carries the row.
#[tokio::test]
async fn a_row_that_fails_makes_the_restore_partial_and_is_named_by_its_key_5856() {
    let Some(f) = tdh::Fixture::setup("local", "generic").await else {
        return;
    };
    let service = service_on(&f);
    // Not a secret, just a value that must not leave the row.
    let marker = format!("row-body-marker-{}", Uuid::new_v4().simple());
    let (token_id, artifact_id) = (Uuid::new_v4(), Uuid::new_v4());
    let key = format!("restore-5856/{}", Uuid::new_v4());
    let bytes = b"bytes of an artifact whose repository is gone".to_vec();
    // Rows as the database writes them, then pointed at ids no server has.
    let pool = &f.pool;
    sqlx::query(
        "INSERT INTO artifacts (id, repository_id, path, name, size_bytes, checksum_sha256, \
         content_type, storage_key) VALUES ($1, $2, $3, 'orphan.bin', $4, $5, \
         'application/octet-stream', $6)",
    )
    .bind(artifact_id)
    .bind(f.repo_id)
    .bind(&marker)
    .bind(bytes.len() as i64)
    .bind(crate::services::artifact_service::ArtifactService::calculate_sha256(&bytes))
    .bind(&key)
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO api_tokens (id, user_id, name, token_hash, token_prefix, scopes) \
         VALUES ($1, $2, 'orphan-token', $3, 'ak5856xx', ARRAY['read'])",
    )
    .bind(token_id)
    .bind(f.user_id)
    .bind(&marker)
    .execute(pool)
    .await
    .unwrap();
    let mut artifacts = dump(pool, "artifacts", "id = $1", artifact_id).await;
    let mut tokens = dump(pool, "api_tokens", "id = $1", token_id).await;
    sqlx::query("DELETE FROM artifacts WHERE id = $1")
        .bind(artifact_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM api_tokens WHERE id = $1")
        .bind(token_id)
        .execute(pool)
        .await
        .unwrap();
    artifacts[0]["repository_id"] = serde_json::json!(Uuid::new_v4());
    tokens[0]["user_id"] = serde_json::json!(Uuid::new_v4());
    let tables = [
        ("artifacts", artifacts.into()),
        ("api_tokens", tokens.into()),
    ];
    let backup = archive_tables(&service, &tables, &[(key.clone(), bytes)]).await;

    let logs = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(logs.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .finish();
    let restored = {
        let _guard = tracing::subscriber::set_default(subscriber);
        service.restore(backup, options()).await.unwrap()
    };
    let logs = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    f.teardown().await;

    assert_eq!(
        restored.status,
        RestoreStatus::Partial,
        "{:?}",
        restored.errors
    );
    for (table, id) in [("artifacts", artifact_id), ("api_tokens", token_id)] {
        let error = restored
            .errors
            .iter()
            .find(|e| e.contains(&format!("into '{table}'")))
            .unwrap_or_else(|| panic!("no error for {table}: {:?}", restored.errors));
        assert!(error.contains(&format!("id={id}")), "{error}");
        assert!(error.contains("foreign key"), "{error}");
        assert!(logs.contains(&format!("id={id}")), "{logs}");
    }
    assert!(
        !restored.errors.iter().any(|e| e.contains(&marker)),
        "{:?}",
        restored.errors
    );
    assert!(!logs.contains(&marker), "row body logged: {logs}");
}
