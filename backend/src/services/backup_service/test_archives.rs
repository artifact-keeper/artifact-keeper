//! Test helpers shared by the backup test modules.
use super::*;

/// Rewrite the archive of `row` so it carries only the rows of this test
/// (#5934), and record the new payload digest on the row.
///
/// A table keeps a row when one of its top-level values is in `owned`, or
/// is the `id` of a row already kept (so an artifact brings its download
/// statistics, a webhook its signing key). Every table and every object
/// entry stays in the archive, and the manifest keeps its `contents`, so
/// the restore runs the same passes it runs on the real archive.
///
/// The backup exports the server-wide tables (users, roles, user_roles,
/// api_tokens, groups, permissions, settings, ...) whole, so in the shared
/// test database they hold the rows of every test running alongside this
/// one. (`repositories` and `download_statistics` follow the backup's
/// repository scope since #5884.) Those tests create and delete their rows
/// while the restore runs: a user still present when the `users` pass skips
/// its row and gone by the `user_roles` pass fails that row's foreign key.
/// That makes the restore fail or come back `partial` for reasons that have
/// nothing to do with this test.
pub(super) async fn keep_only_rows_of_this_test(
    service: &BackupService,
    row: &Backup,
    owned: &[String],
) {
    let path = row.storage_path.as_ref().expect("archive path");
    let bytes = service
        .archive_storage
        .get(path)
        .await
        .expect("archive readable");
    let entries = BackupService::extract_entries(&bytes).expect("extract archive");
    let mut manifest: BackupManifest = entries
        .iter()
        .find(|(p, _)| p.as_path() == std::path::Path::new("manifest.json"))
        .map(|(_, content)| serde_json::from_slice(content).expect("manifest parses"))
        .expect("archive contains a manifest");

    let mut owned: std::collections::HashSet<String> = owned.iter().cloned().collect();
    let all: Vec<(String, Vec<serde_json::Value>)> = manifest
        .database_tables
        .iter()
        .map(|table| (table.clone(), archive_table_rows(&entries, table)))
        .collect();
    let owns = |owned: &std::collections::HashSet<String>, row: &serde_json::Value| {
        row.as_object().is_some_and(|columns| {
            columns
                .values()
                .any(|v| v.as_str().is_some_and(|s| owned.contains(s)))
        })
    };
    // Grow `owned` with the ids of the rows it keeps until nothing changes.
    loop {
        let before = owned.len();
        let ids: Vec<String> = all
            .iter()
            .flat_map(|(_, rows)| rows.iter())
            .filter(|row| owns(&owned, row))
            .filter_map(|row| row.get("id")?.as_str().map(str::to_string))
            .collect();
        owned.extend(ids);
        if owned.len() == before {
            break;
        }
    }
    let tables: Vec<(String, Vec<u8>)> = all
        .iter()
        .map(|(table, rows)| {
            let kept: Vec<&serde_json::Value> =
                rows.iter().filter(|row| owns(&owned, row)).collect();
            (
                table.clone(),
                serde_json::to_vec(&kept).expect("encode rows"),
            )
        })
        .collect();
    let tables: Vec<(&str, &[u8])> = tables
        .iter()
        .map(|(table, rows)| (table.as_str(), rows.as_slice()))
        .collect();
    let objects: Vec<(String, &[u8])> = entries
        .iter()
        .filter_map(|(p, content)| artifact_storage_key(p).map(|key| (key, content.as_slice())))
        .collect();
    let objects: Vec<(&str, &[u8])> = objects
        .iter()
        .map(|(key, content)| (key.as_str(), *content))
        .collect();

    let (size, checksum) = payload_summary(tables.iter().copied().chain(objects.iter().copied()));
    manifest.total_size_bytes = size;
    manifest.checksum = checksum.clone();
    let tar = build_backup_tar(
        &tables,
        &objects,
        &serde_json::to_vec(&manifest).expect("encode manifest"),
    )
    .expect("build archive");
    let length = tar.len() as i64;
    service
        .archive_storage
        .put(path, Bytes::from(tar))
        .await
        .expect("rewrite archive");
    sqlx::query("UPDATE backups SET size_bytes = $2, payload_checksum = $3 WHERE id = $1")
        .bind(row.id)
        .bind(length)
        .bind(checksum)
        .execute(&service.db)
        .await
        .expect("record the rewritten archive's digest");
}
