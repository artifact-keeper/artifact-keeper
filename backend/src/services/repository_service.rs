//! Repository service.
//!
//! Handles repository CRUD operations, virtual repository management, and quota enforcement.

use std::sync::Arc;

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
#[allow(unused_imports)] // Used by sqlx query macros
use crate::models::repository::{
    ReplicationPriority, Repository, RepositoryFormat, RepositoryType,
};
use crate::services::meili_service::{MeiliService, RepositoryDocument};

/// Request to create a new repository
#[derive(Debug)]
pub struct CreateRepositoryRequest {
    pub key: String,
    pub name: String,
    pub description: Option<String>,
    pub format: RepositoryFormat,
    pub repo_type: RepositoryType,
    pub storage_backend: String,
    pub storage_path: String,
    pub upstream_url: Option<String>,
    pub is_public: bool,
    pub quota_bytes: Option<i64>,
    /// Custom format key for WASM plugin handlers (e.g. "rpm-custom").
    pub format_key: Option<String>,
}

/// Request to update a repository
#[derive(Debug)]
pub struct UpdateRepositoryRequest {
    pub key: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub is_public: Option<bool>,
    pub quota_bytes: Option<Option<i64>>,
    pub upstream_url: Option<String>,
}

// ---------------------------------------------------------------------------
// Pure helper functions (no DB, testable in isolation)
// ---------------------------------------------------------------------------

/// Validate that a remote repository has an upstream URL.
/// Returns an error message if validation fails, None if ok.
pub(crate) fn validate_remote_upstream(
    repo_type: &RepositoryType,
    upstream_url: &Option<String>,
) -> Option<String> {
    if *repo_type == RepositoryType::Remote && upstream_url.is_none() {
        Some("Remote repository must have an upstream URL".to_string())
    } else {
        None
    }
}

/// Derive a format key string from a RepositoryFormat enum.
pub(crate) fn derive_format_key(format: &RepositoryFormat) -> String {
    format!("{:?}", format).to_lowercase()
}

/// Build a SQL LIKE search pattern from a user query string.
pub(crate) fn build_search_pattern(query: Option<&str>) -> Option<String> {
    query.map(|q| format!("%{}%", q.to_lowercase()))
}

/// Check whether a format_enabled value should cause repo creation to be rejected.
/// Returns true if the format handler is explicitly disabled.
pub(crate) fn should_reject_disabled_format(format_enabled: Option<bool>) -> bool {
    format_enabled == Some(false)
}

/// Calculate quota usage as a fraction (0.0 to 1.0+).
pub(crate) fn quota_usage_percentage(used_bytes: i64, quota_bytes: i64) -> f64 {
    if quota_bytes <= 0 {
        return 0.0;
    }
    used_bytes as f64 / quota_bytes as f64
}

/// Check whether quota usage exceeds the warning threshold (80%).
pub(crate) fn exceeds_quota_warning_threshold(used_bytes: i64, quota_bytes: i64) -> bool {
    quota_usage_percentage(used_bytes, quota_bytes) > 0.8
}

/// Repository service
pub struct RepositoryService {
    db: PgPool,
    meili_service: Option<Arc<MeiliService>>,
}

impl RepositoryService {
    /// Create a new repository service
    pub fn new(db: PgPool) -> Self {
        Self {
            db,
            meili_service: None,
        }
    }

    /// Create a new repository service with Meilisearch indexing support.
    pub fn new_with_meili(db: PgPool, meili_service: Option<Arc<MeiliService>>) -> Self {
        Self { db, meili_service }
    }

    /// Set the Meilisearch service for search indexing.
    pub fn set_meili_service(&mut self, meili_service: Arc<MeiliService>) {
        self.meili_service = Some(meili_service);
    }

    /// Get the custom format_key for a repository (if set for WASM plugins).
    pub async fn get_format_key(&self, repo_id: Uuid) -> Result<Option<String>> {
        let row: Option<(Option<String>,)> =
            sqlx::query_as("SELECT format_key FROM repositories WHERE id = $1")
                .bind(repo_id)
                .fetch_optional(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
        Ok(row.and_then(|r| r.0))
    }

    /// Create a new repository
    pub async fn create(&self, req: CreateRepositoryRequest) -> Result<Repository> {
        // Validate remote repository has upstream URL
        if let Some(msg) = validate_remote_upstream(&req.repo_type, &req.upstream_url) {
            return Err(AppError::Validation(msg));
        }

        // Check if format handler is enabled (T044)
        let format_key = derive_format_key(&req.format);
        let format_enabled: Option<bool> =
            sqlx::query_scalar("SELECT is_enabled FROM format_handlers WHERE format_key = $1")
                .bind(&format_key)
                .fetch_optional(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;

        // If format handler exists and is disabled, reject repository creation
        if should_reject_disabled_format(format_enabled) {
            return Err(AppError::Validation(format!(
                "Format handler '{}' is disabled. Enable it before creating repositories.",
                format_key
            )));
        }

        let repo = sqlx::query_as!(
            Repository,
            r#"
            INSERT INTO repositories (
                key, name, description, format, repo_type,
                storage_backend, storage_path, upstream_url,
                is_public, quota_bytes
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING
                id, key, name, description,
                format as "format: RepositoryFormat",
                repo_type as "repo_type: RepositoryType",
                storage_backend, storage_path, upstream_url,
                is_public, quota_bytes,
                replication_priority as "replication_priority: ReplicationPriority",
                promotion_target_id, promotion_policy_id,
                created_at, updated_at
            "#,
            req.key,
            req.name,
            req.description,
            req.format as RepositoryFormat,
            req.repo_type as RepositoryType,
            req.storage_backend,
            req.storage_path,
            req.upstream_url,
            req.is_public,
            req.quota_bytes,
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| {
            if e.to_string().contains("duplicate key") {
                AppError::Conflict(format!("Repository with key '{}' already exists", req.key))
            } else {
                AppError::Database(e.to_string())
            }
        })?;

        // Set custom format_key for WASM plugin handlers
        if let Some(ref fk) = req.format_key {
            sqlx::query("UPDATE repositories SET format_key = $1 WHERE id = $2")
                .bind(fk)
                .bind(repo.id)
                .execute(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
        }

        // Index repository in Meilisearch (non-blocking)
        if let Some(ref meili) = self.meili_service {
            let meili = meili.clone();
            let doc = Self::repo_to_meili_doc(&repo);
            tokio::spawn(async move {
                if let Err(e) = meili.index_repository(&doc).await {
                    tracing::warn!(
                        "Failed to index repository {} in Meilisearch: {}",
                        doc.id,
                        e
                    );
                }
            });
        }

        Ok(repo)
    }

    /// Get a repository by ID
    pub async fn get_by_id(&self, id: Uuid) -> Result<Repository> {
        let repo = sqlx::query_as!(
            Repository,
            r#"
            SELECT
                id, key, name, description,
                format as "format: RepositoryFormat",
                repo_type as "repo_type: RepositoryType",
                storage_backend, storage_path, upstream_url,
                is_public, quota_bytes,
                replication_priority as "replication_priority: ReplicationPriority",
                promotion_target_id, promotion_policy_id,
                created_at, updated_at
            FROM repositories
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Repository not found".to_string()))?;

        Ok(repo)
    }

    /// Get a repository by key
    pub async fn get_by_key(&self, key: &str) -> Result<Repository> {
        let repo = sqlx::query_as!(
            Repository,
            r#"
            SELECT
                id, key, name, description,
                format as "format: RepositoryFormat",
                repo_type as "repo_type: RepositoryType",
                storage_backend, storage_path, upstream_url,
                is_public, quota_bytes,
                replication_priority as "replication_priority: ReplicationPriority",
                promotion_target_id, promotion_policy_id,
                created_at, updated_at
            FROM repositories
            WHERE key = $1
            "#,
            key
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Repository not found".to_string()))?;

        Ok(repo)
    }

    /// List repositories with pagination
    pub async fn list(
        &self,
        offset: i64,
        limit: i64,
        format_filter: Option<RepositoryFormat>,
        type_filter: Option<RepositoryType>,
        public_only: bool,
        search_query: Option<&str>,
    ) -> Result<(Vec<Repository>, i64)> {
        let search_pattern = build_search_pattern(search_query);

        let repos = sqlx::query_as!(
            Repository,
            r#"
            SELECT
                id, key, name, description,
                format as "format: RepositoryFormat",
                repo_type as "repo_type: RepositoryType",
                storage_backend, storage_path, upstream_url,
                is_public, quota_bytes,
                replication_priority as "replication_priority: ReplicationPriority",
                promotion_target_id, promotion_policy_id,
                created_at, updated_at
            FROM repositories
            WHERE ($1::repository_format IS NULL OR format = $1)
              AND ($2::repository_type IS NULL OR repo_type = $2)
              AND ($3 = false OR is_public = true)
              AND ($6::text IS NULL OR LOWER(key) LIKE $6 OR LOWER(name) LIKE $6 OR LOWER(COALESCE(description, '')) LIKE $6)
            ORDER BY name
            OFFSET $4
            LIMIT $5
            "#,
            format_filter.clone() as Option<RepositoryFormat>,
            type_filter.clone() as Option<RepositoryType>,
            public_only,
            offset,
            limit,
            search_pattern.clone() as Option<String>,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let total = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*)
            FROM repositories
            WHERE ($1::repository_format IS NULL OR format = $1)
              AND ($2::repository_type IS NULL OR repo_type = $2)
              AND ($3 = false OR is_public = true)
              AND ($4::text IS NULL OR LOWER(key) LIKE $4 OR LOWER(name) LIKE $4 OR LOWER(COALESCE(description, '')) LIKE $4)
            "#,
            format_filter.clone() as Option<RepositoryFormat>,
            type_filter.clone() as Option<RepositoryType>,
            public_only,
            search_pattern as Option<String>,
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .unwrap_or(0);

        Ok((repos, total))
    }

    /// Update a repository
    pub async fn update(&self, id: Uuid, req: UpdateRepositoryRequest) -> Result<Repository> {
        let repo = sqlx::query_as!(
            Repository,
            r#"
            UPDATE repositories
            SET
                key = COALESCE($2, key),
                name = COALESCE($3, name),
                description = COALESCE($4, description),
                is_public = COALESCE($5, is_public),
                quota_bytes = COALESCE($6, quota_bytes),
                upstream_url = COALESCE($7, upstream_url),
                updated_at = NOW()
            WHERE id = $1
            RETURNING
                id, key, name, description,
                format as "format: RepositoryFormat",
                repo_type as "repo_type: RepositoryType",
                storage_backend, storage_path, upstream_url,
                is_public, quota_bytes,
                replication_priority as "replication_priority: ReplicationPriority",
                promotion_target_id, promotion_policy_id,
                created_at, updated_at
            "#,
            id,
            req.key,
            req.name,
            req.description,
            req.is_public,
            req.quota_bytes.flatten(),
            req.upstream_url
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| {
            if e.to_string().contains("duplicate key") {
                AppError::Conflict("Repository with that key already exists".to_string())
            } else {
                AppError::Database(e.to_string())
            }
        })?
        .ok_or_else(|| AppError::NotFound("Repository not found".to_string()))?;

        // Index updated repository in Meilisearch (non-blocking)
        if let Some(ref meili) = self.meili_service {
            let meili = meili.clone();
            let doc = Self::repo_to_meili_doc(&repo);
            tokio::spawn(async move {
                if let Err(e) = meili.index_repository(&doc).await {
                    tracing::warn!(
                        "Failed to index updated repository {} in Meilisearch: {}",
                        doc.id,
                        e
                    );
                }
            });
        }

        Ok(repo)
    }

    /// Delete a repository
    pub async fn delete(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query!("DELETE FROM repositories WHERE id = $1", id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Repository not found".to_string()));
        }

        // Remove repository from Meilisearch index (non-blocking)
        if let Some(ref meili) = self.meili_service {
            let meili = meili.clone();
            let repo_id_str = id.to_string();
            tokio::spawn(async move {
                if let Err(e) = meili.remove_repository(&repo_id_str).await {
                    tracing::warn!(
                        "Failed to remove repository {} from Meilisearch: {}",
                        repo_id_str,
                        e
                    );
                }
            });
        }

        Ok(())
    }

    /// Add a member repository to a virtual repository
    pub async fn add_virtual_member(
        &self,
        virtual_repo_id: Uuid,
        member_repo_id: Uuid,
        priority: i32,
    ) -> Result<()> {
        // Validate virtual repository exists and is virtual type
        let virtual_repo = self.get_by_id(virtual_repo_id).await?;
        if virtual_repo.repo_type != RepositoryType::Virtual {
            return Err(AppError::Validation(
                "Target repository must be a virtual repository".to_string(),
            ));
        }

        // Validate member repository exists and is not virtual
        let member_repo = self.get_by_id(member_repo_id).await?;
        if member_repo.repo_type == RepositoryType::Virtual {
            return Err(AppError::Validation(
                "Cannot add virtual repository as member".to_string(),
            ));
        }

        // Validate formats match
        if virtual_repo.format != member_repo.format {
            return Err(AppError::Validation(
                "Member repository format must match virtual repository format".to_string(),
            ));
        }

        sqlx::query!(
            r#"
            INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority)
            VALUES ($1, $2, $3)
            ON CONFLICT (virtual_repo_id, member_repo_id) DO UPDATE SET priority = $3
            "#,
            virtual_repo_id,
            member_repo_id,
            priority
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(())
    }

    /// Remove a member from a virtual repository
    pub async fn remove_virtual_member(
        &self,
        virtual_repo_id: Uuid,
        member_repo_id: Uuid,
    ) -> Result<()> {
        let result = sqlx::query!(
            "DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1 AND member_repo_id = $2",
            virtual_repo_id,
            member_repo_id
        )
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound(
                "Member not found in virtual repository".to_string(),
            ));
        }

        Ok(())
    }

    /// Get virtual repository members
    pub async fn get_virtual_members(&self, virtual_repo_id: Uuid) -> Result<Vec<Repository>> {
        let repos = sqlx::query_as!(
            Repository,
            r#"
            SELECT
                r.id, r.key, r.name, r.description,
                r.format as "format: RepositoryFormat",
                r.repo_type as "repo_type: RepositoryType",
                r.storage_backend, r.storage_path, r.upstream_url,
                r.is_public, r.quota_bytes,
                r.replication_priority as "replication_priority: ReplicationPriority",
                r.promotion_target_id, r.promotion_policy_id,
                r.created_at, r.updated_at
            FROM repositories r
            INNER JOIN virtual_repo_members vrm ON r.id = vrm.member_repo_id
            WHERE vrm.virtual_repo_id = $1
            ORDER BY vrm.priority
            "#,
            virtual_repo_id
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(repos)
    }

    /// Get repository storage usage
    pub async fn get_storage_usage(&self, repo_id: Uuid) -> Result<i64> {
        let usage = sqlx::query_scalar!(
            r#"
            SELECT COALESCE(SUM(size_bytes), 0)::BIGINT as "usage!"
            FROM artifacts
            WHERE repository_id = $1 AND is_deleted = false
            "#,
            repo_id
        )
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(usage)
    }

    /// Check if upload would exceed quota
    pub async fn check_quota(&self, repo_id: Uuid, additional_bytes: i64) -> Result<bool> {
        let repo = self.get_by_id(repo_id).await?;

        match repo.quota_bytes {
            Some(quota) => {
                let current_usage = self.get_storage_usage(repo_id).await?;
                Ok(current_usage + additional_bytes <= quota)
            }
            None => Ok(true), // No quota set
        }
    }

    /// Convert a Repository model to a Meilisearch RepositoryDocument.
    fn repo_to_meili_doc(repo: &Repository) -> RepositoryDocument {
        RepositoryDocument {
            id: repo.id.to_string(),
            name: repo.name.clone(),
            key: repo.key.clone(),
            description: repo.description.clone(),
            format: format!("{:?}", repo.format).to_lowercase(),
            repo_type: format!("{:?}", repo.repo_type).to_lowercase(),
            is_public: repo.is_public,
            created_at: repo.created_at.timestamp(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::repository::{
        ReplicationPriority, Repository, RepositoryFormat, RepositoryType,
    };

    // -----------------------------------------------------------------------
    // repo_to_meili_doc tests
    // -----------------------------------------------------------------------

    fn make_test_repo(format: RepositoryFormat, repo_type: RepositoryType) -> Repository {
        let now = chrono::Utc::now();
        Repository {
            id: Uuid::new_v4(),
            key: "test-repo".to_string(),
            name: "Test Repository".to_string(),
            description: Some("A test repository".to_string()),
            format,
            repo_type,
            storage_backend: "filesystem".to_string(),
            storage_path: "/data/repos/test-repo".to_string(),
            upstream_url: None,
            is_public: true,
            quota_bytes: Some(1024 * 1024 * 1024),
            replication_priority: ReplicationPriority::Scheduled,
            promotion_target_id: None,
            promotion_policy_id: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn test_repo_to_meili_doc_maven_local() {
        let repo = make_test_repo(RepositoryFormat::Maven, RepositoryType::Local);
        let doc = RepositoryService::repo_to_meili_doc(&repo);

        assert_eq!(doc.id, repo.id.to_string());
        assert_eq!(doc.name, "Test Repository");
        assert_eq!(doc.key, "test-repo");
        assert_eq!(doc.description, Some("A test repository".to_string()));
        assert_eq!(doc.format, "maven");
        assert_eq!(doc.repo_type, "local");
        assert!(doc.is_public);
        assert_eq!(doc.created_at, repo.created_at.timestamp());
    }

    #[test]
    fn test_repo_to_meili_doc_docker_remote() {
        let repo = make_test_repo(RepositoryFormat::Docker, RepositoryType::Remote);
        let doc = RepositoryService::repo_to_meili_doc(&repo);
        assert_eq!(doc.format, "docker");
        assert_eq!(doc.repo_type, "remote");
    }

    #[test]
    fn test_repo_to_meili_doc_npm_virtual() {
        let repo = make_test_repo(RepositoryFormat::Npm, RepositoryType::Virtual);
        let doc = RepositoryService::repo_to_meili_doc(&repo);
        assert_eq!(doc.format, "npm");
        assert_eq!(doc.repo_type, "virtual");
    }

    #[test]
    fn test_repo_to_meili_doc_pypi_staging() {
        let repo = make_test_repo(RepositoryFormat::Pypi, RepositoryType::Staging);
        let doc = RepositoryService::repo_to_meili_doc(&repo);
        assert_eq!(doc.format, "pypi");
        assert_eq!(doc.repo_type, "staging");
    }

    #[test]
    fn test_repo_to_meili_doc_no_description() {
        let now = chrono::Utc::now();
        let repo = Repository {
            id: Uuid::new_v4(),
            key: "no-desc".to_string(),
            name: "No Description".to_string(),
            description: None,
            format: RepositoryFormat::Generic,
            repo_type: RepositoryType::Local,
            storage_backend: "filesystem".to_string(),
            storage_path: "/data".to_string(),
            upstream_url: None,
            is_public: false,
            quota_bytes: None,
            replication_priority: ReplicationPriority::LocalOnly,
            promotion_target_id: None,
            promotion_policy_id: None,
            created_at: now,
            updated_at: now,
        };
        let doc = RepositoryService::repo_to_meili_doc(&repo);
        assert!(doc.description.is_none());
        assert!(!doc.is_public);
        assert_eq!(doc.format, "generic");
    }

    #[test]
    fn test_repo_to_meili_doc_various_formats() {
        let formats_and_expected: Vec<(RepositoryFormat, &str)> = vec![
            (RepositoryFormat::Cargo, "cargo"),
            (RepositoryFormat::Nuget, "nuget"),
            (RepositoryFormat::Go, "go"),
            (RepositoryFormat::Rubygems, "rubygems"),
            (RepositoryFormat::Helm, "helm"),
            (RepositoryFormat::Rpm, "rpm"),
            (RepositoryFormat::Debian, "debian"),
            (RepositoryFormat::Conan, "conan"),
            (RepositoryFormat::Terraform, "terraform"),
            (RepositoryFormat::Alpine, "alpine"),
            (RepositoryFormat::Composer, "composer"),
            (RepositoryFormat::Hex, "hex"),
            (RepositoryFormat::Swift, "swift"),
            (RepositoryFormat::Pub, "pub"),
            (RepositoryFormat::Cran, "cran"),
        ];

        for (format, expected) in formats_and_expected {
            let repo = make_test_repo(format, RepositoryType::Local);
            let doc = RepositoryService::repo_to_meili_doc(&repo);
            assert_eq!(
                doc.format, expected,
                "Format mismatch for {:?}",
                repo.format
            );
        }
    }

    // -----------------------------------------------------------------------
    // CreateRepositoryRequest construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_repository_request_construction() {
        let req = CreateRepositoryRequest {
            key: "my-repo".to_string(),
            name: "My Repository".to_string(),
            description: Some("Test repo".to_string()),
            format: RepositoryFormat::Maven,
            repo_type: RepositoryType::Local,
            storage_backend: "filesystem".to_string(),
            storage_path: "/data/my-repo".to_string(),
            upstream_url: None,
            is_public: true,
            quota_bytes: Some(1_000_000_000),
            format_key: None,
        };
        assert_eq!(req.key, "my-repo");
        assert_eq!(req.format, RepositoryFormat::Maven);
        assert_eq!(req.repo_type, RepositoryType::Local);
        assert!(req.upstream_url.is_none());
        assert_eq!(req.quota_bytes, Some(1_000_000_000));
    }

    #[test]
    fn test_create_repository_request_remote_with_upstream() {
        let req = CreateRepositoryRequest {
            key: "npm-remote".to_string(),
            name: "NPM Remote".to_string(),
            description: None,
            format: RepositoryFormat::Npm,
            repo_type: RepositoryType::Remote,
            storage_backend: "filesystem".to_string(),
            storage_path: "/data/npm-remote".to_string(),
            upstream_url: Some("https://registry.npmjs.org".to_string()),
            is_public: false,
            quota_bytes: None,
            format_key: None,
        };
        assert_eq!(
            req.upstream_url,
            Some("https://registry.npmjs.org".to_string())
        );
        assert!(!req.is_public);
    }

    // -----------------------------------------------------------------------
    // UpdateRepositoryRequest construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_update_repository_request_all_none() {
        let req = UpdateRepositoryRequest {
            key: None,
            name: None,
            description: None,
            is_public: None,
            quota_bytes: None,
            upstream_url: None,
        };
        assert!(req.key.is_none());
        assert!(req.name.is_none());
        assert!(req.description.is_none());
        assert!(req.is_public.is_none());
        assert!(req.quota_bytes.is_none());
        assert!(req.upstream_url.is_none());
    }

    #[test]
    fn test_update_repository_request_partial() {
        let req = UpdateRepositoryRequest {
            key: None,
            name: Some("Updated Name".to_string()),
            description: Some("Updated Description".to_string()),
            is_public: Some(false),
            quota_bytes: Some(Some(2_000_000_000)),
            upstream_url: None,
        };
        assert_eq!(req.name, Some("Updated Name".to_string()));
        assert_eq!(req.is_public, Some(false));
        assert_eq!(req.quota_bytes, Some(Some(2_000_000_000)));
    }

    #[test]
    fn test_update_repository_request_clear_quota() {
        // quota_bytes: Some(None) should clear the quota
        let req = UpdateRepositoryRequest {
            key: None,
            name: None,
            description: None,
            is_public: None,
            quota_bytes: Some(None),
            upstream_url: None,
        };
        assert_eq!(req.quota_bytes, Some(None));
    }

    // -----------------------------------------------------------------------
    // validate_remote_upstream (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_remote_upstream_remote_without_url_fails() {
        let result = validate_remote_upstream(&RepositoryType::Remote, &None);
        assert!(result.is_some());
        assert!(result.unwrap().contains("upstream URL"));
    }

    #[test]
    fn test_validate_remote_upstream_remote_with_url_passes() {
        let result = validate_remote_upstream(
            &RepositoryType::Remote,
            &Some("https://upstream.example.com".to_string()),
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_validate_remote_upstream_local_without_url_passes() {
        let result = validate_remote_upstream(&RepositoryType::Local, &None);
        assert!(result.is_none());
    }

    #[test]
    fn test_validate_remote_upstream_virtual_without_url_passes() {
        let result = validate_remote_upstream(&RepositoryType::Virtual, &None);
        assert!(result.is_none());
    }

    #[test]
    fn test_validate_remote_upstream_staging_without_url_passes() {
        let result = validate_remote_upstream(&RepositoryType::Staging, &None);
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // build_search_pattern (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_search_pattern_basic() {
        assert_eq!(
            build_search_pattern(Some("maven")),
            Some("%maven%".to_string())
        );
    }

    #[test]
    fn test_build_search_pattern_mixed_case() {
        assert_eq!(
            build_search_pattern(Some("MyRepo")),
            Some("%myrepo%".to_string())
        );
    }

    #[test]
    fn test_build_search_pattern_none() {
        assert!(build_search_pattern(None).is_none());
    }

    #[test]
    fn test_build_search_pattern_empty_string() {
        assert_eq!(build_search_pattern(Some("")), Some("%%".to_string()));
    }

    #[test]
    fn test_build_search_pattern_with_spaces() {
        assert_eq!(
            build_search_pattern(Some("my repo")),
            Some("%my repo%".to_string())
        );
    }

    // -----------------------------------------------------------------------
    // should_reject_disabled_format (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_should_reject_disabled_format_disabled() {
        assert!(should_reject_disabled_format(Some(false)));
    }

    #[test]
    fn test_should_reject_disabled_format_enabled() {
        assert!(!should_reject_disabled_format(Some(true)));
    }

    #[test]
    fn test_should_reject_disabled_format_not_found() {
        assert!(!should_reject_disabled_format(None));
    }

    // -----------------------------------------------------------------------
    // derive_format_key (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_derive_format_key_maven() {
        assert_eq!(derive_format_key(&RepositoryFormat::Maven), "maven");
    }

    #[test]
    fn test_derive_format_key_docker() {
        assert_eq!(derive_format_key(&RepositoryFormat::Docker), "docker");
    }

    #[test]
    fn test_derive_format_key_npm() {
        assert_eq!(derive_format_key(&RepositoryFormat::Npm), "npm");
    }

    #[test]
    fn test_derive_format_key_wasm_oci() {
        assert_eq!(derive_format_key(&RepositoryFormat::WasmOci), "wasmoci");
    }

    #[test]
    fn test_derive_format_key_helm_oci() {
        assert_eq!(derive_format_key(&RepositoryFormat::HelmOci), "helmoci");
    }

    #[test]
    fn test_derive_format_key_conda_native() {
        assert_eq!(
            derive_format_key(&RepositoryFormat::CondaNative),
            "condanative"
        );
    }

    #[test]
    fn test_derive_format_key_various_formats() {
        let cases: Vec<(RepositoryFormat, &str)> = vec![
            (RepositoryFormat::Cargo, "cargo"),
            (RepositoryFormat::Nuget, "nuget"),
            (RepositoryFormat::Go, "go"),
            (RepositoryFormat::Rubygems, "rubygems"),
            (RepositoryFormat::Helm, "helm"),
            (RepositoryFormat::Rpm, "rpm"),
            (RepositoryFormat::Debian, "debian"),
            (RepositoryFormat::Pypi, "pypi"),
            (RepositoryFormat::Generic, "generic"),
        ];
        for (format, expected) in cases {
            assert_eq!(derive_format_key(&format), expected, "Format {:?}", format);
        }
    }

    // -----------------------------------------------------------------------
    // quota_usage_percentage (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_quota_usage_percentage() {
        assert!((quota_usage_percentage(80, 100) - 0.8).abs() < f64::EPSILON);
        assert!((quota_usage_percentage(100, 100) - 1.0).abs() < f64::EPSILON);
        assert!((quota_usage_percentage(0, 100) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_quota_usage_percentage_zero_quota() {
        assert!((quota_usage_percentage(50, 0) - 0.0).abs() < f64::EPSILON);
        assert!((quota_usage_percentage(50, -1) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_quota_warning_threshold_check() {
        let threshold = 0.8;
        assert!(quota_usage_percentage(85, 100) > threshold);
        assert!(quota_usage_percentage(70, 100) <= threshold);
    }

    // -----------------------------------------------------------------------
    // exceeds_quota_warning_threshold (extracted pure function)
    // -----------------------------------------------------------------------

    #[test]
    fn test_exceeds_quota_threshold_at_90_percent() {
        assert!(exceeds_quota_warning_threshold(900, 1000));
    }

    #[test]
    fn test_exceeds_quota_threshold_at_80_percent() {
        // Exactly 0.8 is not > 0.8
        assert!(!exceeds_quota_warning_threshold(800, 1000));
    }

    #[test]
    fn test_exceeds_quota_threshold_at_81_percent() {
        assert!(exceeds_quota_warning_threshold(810, 1000));
    }

    #[test]
    fn test_exceeds_quota_threshold_at_50_percent() {
        assert!(!exceeds_quota_warning_threshold(500, 1000));
    }

    #[test]
    fn test_exceeds_quota_threshold_at_100_percent() {
        assert!(exceeds_quota_warning_threshold(1000, 1000));
    }

    #[test]
    fn test_exceeds_quota_threshold_over_quota() {
        assert!(exceeds_quota_warning_threshold(1500, 1000));
    }

    #[test]
    fn test_exceeds_quota_threshold_zero_quota() {
        // Zero quota returns 0.0 from quota_usage_percentage, which is not > 0.8
        assert!(!exceeds_quota_warning_threshold(500, 0));
    }

    #[test]
    fn test_exceeds_quota_threshold_empty() {
        assert!(!exceeds_quota_warning_threshold(0, 1000));
    }
}
