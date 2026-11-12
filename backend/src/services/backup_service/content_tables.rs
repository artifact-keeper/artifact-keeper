//! The server state a backup captures beyond the core tables (#5654):
//! Docker/OCI image rows (blobs, manifests, tags and the manifest index),
//! groups and their members with the role assignments and permissions that
//! grant access, webhooks and their signing keys, admin and
//! per-repository settings with the SSO/LDAP provider configuration, and
//! security scan data.
//!
//! These live in their own module so the core archive pipeline in
//! `backup_service.rs` only calls in at a few fixed points: the export
//! ([`export_content_tables`]), the restore order ([`restore_order`]), the
//! allowlist check ([`is_content_table`]) and the blob-ownership readers used
//! for OCI blob bytes.
//!
//! OCI blob **bytes** go into the archive exactly like artifact bytes, as
//! `artifacts/<storage_key>` entries: the blob objects are added to the
//! backup's object list ([`OCI_BLOB_OBJECTS_SQL`]) and their owners are read
//! from the archived `oci_blobs` rows ([`oci_blob_owners`]), so the restore
//! writes each blob to every owning repository's storage location the same
//! way it writes artifact bytes.

use std::collections::HashMap;

use uuid::Uuid;

use crate::error::{AppError, Result};

/// How a content table is scoped to the backup's repository filter and
/// `since` cutoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    /// Server-wide configuration: always exported whole.
    Global,
    /// Rows of the repositories in scope (`repository_id`).
    Repository,
    /// Rows of the repositories in scope plus server-wide rows
    /// (`repository_id IS NULL`).
    RepositoryOrGlobal,
    /// Rows hanging off an artifact the backup exports (`artifact_id`), so a
    /// restore never inserts a row whose artifact is not in the archive.
    Artifact,
    /// Rows of an SBOM document the backup exports (`sbom_id`).
    SbomDocument,
    /// Rows of the repositories in scope, by a repository column not named
    /// `repository_id`.
    RepositoryColumn(&'static str),
    /// Rows linking two repositories that are both in scope, so a restore
    /// never links to a repository the archive does not carry.
    BothRepositories(&'static str, &'static str),
}

/// One table the backup exports in addition to the core tables.
#[derive(Debug, Clone, Copy)]
pub(super) struct ContentTable {
    pub(super) name: &'static str,
    scope: Scope,
    /// Extra predicate ANDed onto the scope filter (`t.` is the table).
    extra_where: Option<&'static str>,
    /// Row order of the export, when it matters: restore inserts in this
    /// order, so a table with a self-reference lists referenced rows first.
    order_by: Option<&'static str>,
}

const fn table(name: &'static str, scope: Scope) -> ContentTable {
    ContentTable {
        name,
        scope,
        extra_where: None,
        order_by: None,
    }
}

/// Every content table, in restore (dependency) order. Each depends only on
/// core tables or on tables earlier in this list, and the whole list is
/// restored after the core tables.
pub(super) const CONTENT_TABLES: &[ContentTable] = &[
    // Groups and memberships, and the access they and users are granted:
    // repository-scoped role assignments, user/group permissions, the
    // repositories an API token is limited to, and virtual-repository
    // membership. Each of these rows is removed with its repository, so a
    // restored repository needs them back to be reachable as before.
    table("groups", Scope::Global),
    table("user_group_members", Scope::Global),
    table("role_assignments", Scope::RepositoryOrGlobal),
    table("permissions", Scope::Global),
    table("api_token_repositories", Scope::RepositoryColumn("repo_id")),
    table(
        "virtual_repo_members",
        Scope::BothRepositories("virtual_repo_id", "member_repo_id"),
    ),
    // Admin settings and identity-provider configuration.
    table("system_settings", Scope::Global),
    table("telemetry_settings", Scope::Global),
    table("ldap_configs", Scope::Global),
    table("oidc_configs", Scope::Global),
    table("saml_configs", Scope::Global),
    // The RPM repodata depth travels on the `repositories` rows already and is
    // installed by the restore's layout step, so its config row is left out
    // here rather than fighting that guard.
    ContentTable {
        name: "repository_config",
        scope: Scope::Repository,
        extra_where: Some("t.key <> 'repodata_depth'"),
        order_by: None,
    },
    // Docker/OCI images. Blob bytes travel as `artifacts/<key>` entries.
    ContentTable {
        name: "oci_blobs",
        scope: Scope::Repository,
        // The same blobs whose bytes the backup archives
        // (OCI_BLOB_OBJECTS_SQL), so no archived row lacks its bytes.
        extra_where: Some(
            "t.pending_delete_at IS NULL AND ($2::timestamptz IS NULL OR t.created_at >= $2)",
        ),
        order_by: None,
    },
    table("oci_manifests", Scope::Repository),
    table("oci_tags", Scope::Repository),
    table("oci_manifest_refs", Scope::Repository),
    table("oci_manifest_subjects", Scope::Repository),
    table("manifest_blob_refs", Scope::Repository),
    // #5793: which image names hold which digests, and which repositories
    // are scoped to them. A blob link only travels with an archived blob,
    // so a restore never inserts a link to a blob the archive lacks.
    table("oci_image_manifests", Scope::Repository),
    ContentTable {
        name: "oci_image_blobs",
        scope: Scope::Repository,
        extra_where: Some(
            "EXISTS (SELECT 1 FROM oci_blobs b \
             WHERE b.repository_id = t.repository_id AND b.digest = t.digest \
               AND b.pending_delete_at IS NULL \
               AND ($2::timestamptz IS NULL OR b.created_at >= $2))",
        ),
        order_by: None,
    },
    table("oci_image_scope_backfill", Scope::Repository),
    // Webhooks and the keys their signatures are made with.
    table("webhook_signing_keys", Scope::Global),
    table("webhooks", Scope::RepositoryOrGlobal),
    // Security scanning: configuration, policies, results and their detail.
    table("scan_configs", Scope::Repository),
    table("scan_policies", Scope::RepositoryOrGlobal),
    ContentTable {
        name: "scan_results",
        scope: Scope::Artifact,
        extra_where: None,
        // A reused result points at its source result; sources first.
        order_by: Some("(t.source_scan_id IS NOT NULL), t.created_at, t.id"),
    },
    table("scan_findings", Scope::Artifact),
    table("scan_packages", Scope::Artifact),
    table("sbom_documents", Scope::Artifact),
    table("sbom_components", Scope::SbomDocument),
    table("finding_acknowledgements", Scope::Repository),
];

/// Whether `table` is a content table the restore may write (the restore's
/// table allowlist is the core list plus this one).
pub(super) fn is_content_table(table: &str) -> bool {
    CONTENT_TABLES.iter().any(|t| t.name == table)
}

/// Names of every content table, in restore order.
pub(super) fn restore_order() -> impl Iterator<Item = &'static str> {
    CONTENT_TABLES.iter().map(|t| t.name)
}

/// The artifacts a backup exports: the predicate the core `artifacts` export
/// uses, as a sub-select. `$1` is the repository filter, `$2` the `since`
/// cutoff.
pub(super) const ARTIFACTS_IN_SCOPE: &str = "SELECT a.id FROM artifacts a \
     WHERE ($1::uuid[] IS NULL OR a.repository_id = ANY($1)) \
       AND ($2::timestamptz IS NULL OR a.updated_at >= $2)";

/// The SQL that exports one content table as JSON rows.
fn export_sql(table: &ContentTable) -> String {
    let scope = match table.scope {
        Scope::Global => "TRUE".to_string(),
        Scope::Repository => "($1::uuid[] IS NULL OR t.repository_id = ANY($1))".to_string(),
        Scope::RepositoryOrGlobal => {
            "(t.repository_id IS NULL OR $1::uuid[] IS NULL OR t.repository_id = ANY($1))"
                .to_string()
        }
        Scope::Artifact => format!("t.artifact_id IN ({ARTIFACTS_IN_SCOPE})"),
        Scope::RepositoryColumn(column) => {
            format!("($1::uuid[] IS NULL OR t.{column} = ANY($1))")
        }
        Scope::BothRepositories(a, b) => {
            format!("($1::uuid[] IS NULL OR (t.{a} = ANY($1) AND t.{b} = ANY($1)))")
        }
        Scope::SbomDocument => format!(
            "t.sbom_id IN (SELECT d.id FROM sbom_documents d \
             WHERE d.artifact_id IN ({ARTIFACTS_IN_SCOPE}))"
        ),
    };
    let extra = table
        .extra_where
        .map(|w| format!(" AND {w}"))
        .unwrap_or_default();
    // The parameters are always bound; `TRUE` scopes keep them referenced so
    // Postgres can type them.
    format!(
        "SELECT row_to_json(t) FROM {name} t \
         WHERE {scope}{extra} AND ($1::uuid[] IS NULL OR TRUE) \
           AND ($2::timestamptz IS NULL OR TRUE){order}",
        name = table.name,
        order = table
            .order_by
            .map(|o| format!(" ORDER BY {o}"))
            .unwrap_or_default(),
    )
}

/// Export every content table that exists on the source database (#5654),
/// as `(table, json_bytes)` pairs in restore order, read in the backup's own
/// snapshot (`conn`).
pub(super) async fn export_content_tables(
    conn: &mut sqlx::PgConnection,
    repository_filter: Option<&[Uuid]>,
    since: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<Vec<(String, Vec<u8>)>> {
    let present: Vec<String> = sqlx::query_scalar(
        "SELECT table_name::text FROM information_schema.tables \
         WHERE table_schema = current_schema() AND table_name = ANY($1)",
    )
    .bind(restore_order().collect::<Vec<_>>())
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let repo_ids: Option<Vec<Uuid>> = repository_filter.map(|r| r.to_vec());
    let mut out = Vec::new();
    for table in CONTENT_TABLES {
        let name = table.name;
        if !present.iter().any(|p| p == name) {
            continue;
        }
        let sql = export_sql(table);
        let rows: Vec<serde_json::Value> = sqlx::query_scalar(sqlx::AssertSqlSafe(&*sql))
            .bind(&repo_ids)
            .bind(since)
            .fetch_all(&mut *conn)
            .await
            .map_err(|e| AppError::Database(format!("export {name}: {e}")))?;
        out.push((
            name.to_string(),
            serde_json::to_vec_pretty(&serde_json::Value::Array(rows))?,
        ));
    }
    Ok(out)
}

/// The OCI blob objects of a backup, in the shape of the artifact-object
/// query (`storage_key, storage_backend, storage_path`), so their bytes are
/// read and archived with the artifact bytes. `$1` is the repository filter,
/// `$2` the `since` cutoff.
pub(super) const OCI_BLOB_OBJECTS_SQL: &str =
    "SELECT b.storage_key, r.storage_backend, r.storage_path \
     FROM oci_blobs b JOIN repositories r ON r.id = b.repository_id \
     WHERE ($1::uuid[] IS NULL OR b.repository_id = ANY($1)) \
       AND ($2::timestamptz IS NULL OR b.created_at >= $2) \
       AND b.pending_delete_at IS NULL";

/// `(storage_key, repository_id)` of every archived `oci_blobs` row, so the
/// restore writes each blob's bytes to its owners' storage locations.
pub(super) fn oci_blob_owners(rows: &[serde_json::Value]) -> Vec<(String, Uuid)> {
    rows.iter()
        .filter_map(|row| {
            let key = row.get("storage_key")?.as_str()?;
            let repo = Uuid::parse_str(row.get("repository_id")?.as_str()?).ok()?;
            (!key.is_empty()).then(|| (key.to_string(), repo))
        })
        .collect()
}

/// Add the archived OCI blob owners to the artifact-key owner map.
pub(super) fn add_oci_blob_owners(
    rows: &[serde_json::Value],
    owners: &mut HashMap<String, Vec<Uuid>>,
) {
    for (key, repo) in oci_blob_owners(rows) {
        let repositories = owners.entry(key).or_default();
        if !repositories.contains(&repo) {
            repositories.push(repo);
        }
    }
}

/// Whether an archive carries Docker/OCI images: archives written since
/// #5654 export the blob and tag tables (and the blob bytes with them).
pub(super) fn archive_has_oci_tables(has_table: impl Fn(&str) -> bool) -> bool {
    has_table("oci_blobs") && has_table("oci_tags") && has_table("oci_manifests")
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_tables_are_listed_once_in_dependency_order_5654() {
        let names: Vec<&str> = restore_order().collect();
        let mut unique = names.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), names.len(), "a content table is listed twice");
        let at = |n: &str| names.iter().position(|t| *t == n).unwrap();
        assert!(at("groups") < at("user_group_members"));
        assert!(at("webhook_signing_keys") < at("webhooks"));
        assert!(at("scan_results") < at("scan_findings"));
        assert!(at("scan_results") < at("scan_packages"));
        assert!(at("sbom_documents") < at("sbom_components"));
        assert!(at("oci_blobs") < at("oci_tags"));
        assert!(is_content_table("oci_tags"));
        assert!(!is_content_table("users"));
    }

    #[test]
    fn export_sql_scopes_rows_to_the_backup_5654() {
        let find = |n: &str| CONTENT_TABLES.iter().find(|t| t.name == n).unwrap();
        assert!(export_sql(find("groups")).contains("WHERE TRUE"));
        assert!(export_sql(find("oci_tags")).contains("t.repository_id = ANY($1)"));
        assert!(export_sql(find("webhooks")).contains("t.repository_id IS NULL"));
        assert!(export_sql(find("scan_findings")).contains("t.artifact_id IN (SELECT a.id"));
        assert!(export_sql(find("repository_config")).contains("'repodata_depth'"));
        assert!(export_sql(find("oci_blobs")).contains("pending_delete_at IS NULL"));
        assert!(export_sql(find("oci_image_blobs")).contains("FROM oci_blobs b"));
        let at = |n: &str| CONTENT_TABLES.iter().position(|t| t.name == n).unwrap();
        assert!(at("oci_manifests") < at("oci_image_manifests"));
        assert!(at("oci_blobs") < at("oci_image_blobs"));
        assert!(export_sql(find("api_token_repositories")).contains("t.repo_id = ANY($1)"));
        assert!(export_sql(find("virtual_repo_members"))
            .contains("t.virtual_repo_id = ANY($1) AND t.member_repo_id = ANY($1)"));
        assert!(export_sql(find("scan_results")).contains("source_scan_id IS NOT NULL"));
        assert!(export_sql(find("sbom_components")).contains("FROM sbom_documents d"));
    }

    #[test]
    fn oci_blob_owners_reads_archived_rows_5654() {
        let repo = Uuid::new_v4();
        let rows = vec![
            serde_json::json!({"storage_key": "oci-blobs/sha256:aa", "repository_id": repo}),
            serde_json::json!({"storage_key": "", "repository_id": repo}),
            serde_json::json!({"storage_key": "oci-blobs/sha256:bb"}),
        ];
        assert_eq!(
            oci_blob_owners(&rows),
            vec![("oci-blobs/sha256:aa".to_string(), repo)]
        );
        let mut owners = HashMap::new();
        add_oci_blob_owners(&rows, &mut owners);
        add_oci_blob_owners(&rows, &mut owners);
        assert_eq!(owners["oci-blobs/sha256:aa"], vec![repo]);
    }

    #[test]
    fn oci_tables_mark_an_archive_that_carries_images_5654() {
        assert!(archive_has_oci_tables(|_| true));
        assert!(!archive_has_oci_tables(|t| t != "oci_blobs"));
        assert!(!archive_has_oci_tables(|_| false));
    }
}
