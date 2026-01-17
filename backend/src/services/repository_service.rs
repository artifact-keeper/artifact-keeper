//! Repository service.
//!
//! Handles repository CRUD operations, virtual repository management, and quota enforcement.

use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::models::repository::{Repository, RepositoryFormat, RepositoryType};

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
}

/// Request to update a repository
#[derive(Debug)]
pub struct UpdateRepositoryRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub is_public: Option<bool>,
    pub quota_bytes: Option<Option<i64>>,
    pub upstream_url: Option<String>,
}

/// Repository service
pub struct RepositoryService {
    db: PgPool,
}

impl RepositoryService {
    /// Create a new repository service
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Create a new repository
    pub async fn create(&self, req: CreateRepositoryRequest) -> Result<Repository> {
        // Validate remote repository has upstream URL
        if req.repo_type == RepositoryType::Remote && req.upstream_url.is_none() {
            return Err(AppError::Validation(
                "Remote repository must have an upstream URL".to_string(),
            ));
        }

        // Check if format handler is enabled (T044)
        let format_key = format!("{:?}", req.format).to_lowercase();
        let format_enabled: Option<bool> = sqlx::query_scalar!(
            "SELECT is_enabled FROM format_handlers WHERE format_key = $1",
            format_key
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .flatten();

        // If format handler exists and is disabled, reject repository creation
        if format_enabled == Some(false) {
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
                is_public, quota_bytes, created_at, updated_at
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
                is_public, quota_bytes, created_at, updated_at
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
                is_public, quota_bytes, created_at, updated_at
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
    ) -> Result<(Vec<Repository>, i64)> {
        let repos = sqlx::query_as!(
            Repository,
            r#"
            SELECT
                id, key, name, description,
                format as "format: RepositoryFormat",
                repo_type as "repo_type: RepositoryType",
                storage_backend, storage_path, upstream_url,
                is_public, quota_bytes, created_at, updated_at
            FROM repositories
            WHERE ($1::repository_format IS NULL OR format = $1)
              AND ($2::repository_type IS NULL OR repo_type = $2)
              AND ($3 = false OR is_public = true)
            ORDER BY name
            OFFSET $4
            LIMIT $5
            "#,
            format_filter.clone() as Option<RepositoryFormat>,
            type_filter.clone() as Option<RepositoryType>,
            public_only,
            offset,
            limit
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
            "#,
            format_filter.clone() as Option<RepositoryFormat>,
            type_filter.clone() as Option<RepositoryType>,
            public_only
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
                name = COALESCE($2, name),
                description = COALESCE($3, description),
                is_public = COALESCE($4, is_public),
                quota_bytes = COALESCE($5, quota_bytes),
                upstream_url = COALESCE($6, upstream_url),
                updated_at = NOW()
            WHERE id = $1
            RETURNING
                id, key, name, description,
                format as "format: RepositoryFormat",
                repo_type as "repo_type: RepositoryType",
                storage_backend, storage_path, upstream_url,
                is_public, quota_bytes, created_at, updated_at
            "#,
            id,
            req.name,
            req.description,
            req.is_public,
            req.quota_bytes.flatten(),
            req.upstream_url
        )
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound("Repository not found".to_string()))?;

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
            return Err(AppError::NotFound("Member not found in virtual repository".to_string()));
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
                r.is_public, r.quota_bytes, r.created_at, r.updated_at
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
}
