//! Migration service - orchestrates the migration process.
//!
//! This service coordinates the migration from Artifactory to Artifact Keeper,
//! handling repository creation, artifact transfer, user/group migration, and
//! permission mapping.

use sqlx::PgPool;
use thiserror::Error;
use tracing::{info, warn, error, debug, instrument, Span};
use uuid::Uuid;

use crate::models::migration::{MigrationJobStatus, MigrationItemType};
use crate::services::artifactory_client::{ArtifactoryClient, ArtifactoryClientConfig, ArtifactoryAuth, RepositoryListItem, RepositoryConfig};

/// Errors that can occur during migration
#[derive(Error, Debug)]
pub enum MigrationError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),

    #[error("Artifactory error: {0}")]
    ArtifactoryError(#[from] crate::services::artifactory_client::ArtifactoryError),

    #[error("Job not found: {0}")]
    JobNotFound(Uuid),

    #[error("Invalid job state: expected {expected}, got {actual}")]
    InvalidJobState { expected: String, actual: String },

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Checksum mismatch for {path}: expected {expected}, got {actual}")]
    ChecksumMismatch {
        path: String,
        expected: String,
        actual: String,
    },

    #[error("Migration error: {0}")]
    Other(String),
}

/// Package format compatibility
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatCompatibility {
    /// Fully supported, migrate as-is
    Full,
    /// Partially supported, migrate as generic
    Partial,
    /// Not supported, skip with warning
    Unsupported,
}

/// Repository type mapping from Artifactory to Artifact Keeper
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepositoryType {
    /// Local repository (hosted)
    Local,
    /// Remote repository (proxy)
    Remote,
    /// Virtual repository (group)
    Virtual,
}

impl RepositoryType {
    /// Parse from Artifactory repository type string
    pub fn from_artifactory(rclass: &str) -> Option<Self> {
        match rclass.to_lowercase().as_str() {
            "local" => Some(Self::Local),
            "remote" => Some(Self::Remote),
            "virtual" => Some(Self::Virtual),
            _ => None,
        }
    }

    /// Convert to Artifact Keeper repository type string
    pub fn to_artifact_keeper(&self) -> &'static str {
        match self {
            Self::Local => "hosted",
            Self::Remote => "proxy",
            Self::Virtual => "group",
        }
    }
}

/// Repository configuration for migration
#[derive(Debug, Clone)]
pub struct RepositoryMigrationConfig {
    pub source_key: String,
    pub target_key: String,
    pub repo_type: RepositoryType,
    pub package_type: String,
    pub description: Option<String>,
    pub format_compatibility: FormatCompatibility,
    /// For remote repos: upstream URL
    pub upstream_url: Option<String>,
    /// For virtual repos: list of member repositories
    pub members: Vec<String>,
}

/// Conflict detection result
#[derive(Debug, Clone)]
pub struct ConflictCheck {
    pub has_conflict: bool,
    pub conflict_type: Option<ConflictType>,
    pub existing_repo_key: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictType {
    /// Repository with same key exists
    SameKey,
    /// Repository with different type exists
    TypeMismatch,
    /// Repository with different format exists
    FormatMismatch,
}

/// Migration service for orchestrating the migration process
pub struct MigrationService {
    db: PgPool,
}

impl MigrationService {
    /// Create a new migration service
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Create an Artifactory client from a source connection
    pub async fn create_client(
        &self,
        connection_id: Uuid,
    ) -> Result<ArtifactoryClient, MigrationError> {
        // Fetch connection details
        let connection: (String, String, Vec<u8>) = sqlx::query_as(
            r#"
            SELECT url, auth_type, credentials_enc
            FROM source_connections
            WHERE id = $1
            "#,
        )
        .bind(connection_id)
        .fetch_optional(&self.db)
        .await?
        .ok_or_else(|| MigrationError::ConfigError("Connection not found".into()))?;

        let (url, auth_type, credentials_enc) = connection;

        // Decrypt credentials (TODO: actual decryption)
        let credentials_json = String::from_utf8(credentials_enc)
            .map_err(|e| MigrationError::ConfigError(e.to_string()))?;

        #[derive(serde::Deserialize)]
        struct Credentials {
            token: Option<String>,
            username: Option<String>,
            password: Option<String>,
        }

        let creds: Credentials = serde_json::from_str(&credentials_json)
            .map_err(|e| MigrationError::ConfigError(e.to_string()))?;

        let auth = match auth_type.as_str() {
            "api_token" => {
                let token = creds
                    .token
                    .ok_or_else(|| MigrationError::ConfigError("API token missing".into()))?;
                ArtifactoryAuth::ApiToken(token)
            }
            "basic_auth" => {
                let username = creds
                    .username
                    .ok_or_else(|| MigrationError::ConfigError("Username missing".into()))?;
                let password = creds
                    .password
                    .ok_or_else(|| MigrationError::ConfigError("Password missing".into()))?;
                ArtifactoryAuth::BasicAuth { username, password }
            }
            _ => return Err(MigrationError::ConfigError(format!("Unknown auth type: {}", auth_type))),
        };

        let config = ArtifactoryClientConfig {
            base_url: url,
            auth,
            ..Default::default()
        };

        ArtifactoryClient::new(config).map_err(Into::into)
    }

    /// Get the compatibility level for a package format
    pub fn get_format_compatibility(package_type: &str) -> FormatCompatibility {
        match package_type.to_lowercase().as_str() {
            "maven" | "npm" | "docker" | "pypi" | "helm" | "nuget" | "cargo" | "go" | "generic" => {
                FormatCompatibility::Full
            }
            "conan" | "conda" | "debian" | "rpm" => FormatCompatibility::Partial,
            _ => FormatCompatibility::Unsupported,
        }
    }

    /// Map Artifactory permission to Artifact Keeper permission
    pub fn map_permission(artifactory_permission: &str) -> Option<&'static str> {
        match artifactory_permission.to_lowercase().as_str() {
            "read" => Some("read"),
            "annotate" => Some("read"), // Metadata is read-only in AK
            "deploy" => Some("write"),
            "delete" => Some("delete"),
            "admin" => Some("admin"),
            // Unsupported Artifactory-specific permissions
            "managedxraymeta" | "distribute" => None,
            _ => None,
        }
    }

    // ============ Repository Migration Methods ============

    /// Map repository type from Artifactory to Artifact Keeper
    pub fn map_repository_type(rclass: &str) -> Option<RepositoryType> {
        RepositoryType::from_artifactory(rclass)
    }

    /// Prepare repository migration config from Artifactory repository
    pub fn prepare_repository_migration(
        repo: &RepositoryListItem,
        repo_config: Option<&RepositoryConfig>,
    ) -> Result<RepositoryMigrationConfig, MigrationError> {
        let repo_type = RepositoryType::from_artifactory(&repo.repo_type)
            .ok_or_else(|| MigrationError::ConfigError(
                format!("Unknown repository type: {}", repo.repo_type)
            ))?;

        let format_compatibility = Self::get_format_compatibility(&repo.package_type);

        Ok(RepositoryMigrationConfig {
            source_key: repo.key.clone(),
            target_key: repo.key.clone(), // Same name by default
            repo_type,
            package_type: repo.package_type.clone(),
            description: repo.description.clone(),
            format_compatibility,
            upstream_url: None, // Will be set from repo_config for remote repos
            members: vec![], // Will be set from repo_config for virtual repos
        })
    }

    /// Check for conflicts with existing repositories in Artifact Keeper
    pub async fn check_repository_conflict(
        &self,
        target_key: &str,
        repo_type: RepositoryType,
        package_type: &str,
    ) -> Result<ConflictCheck, MigrationError> {
        // Check if repository with same key exists
        let existing: Option<(String, String)> = sqlx::query_as(
            r#"
            SELECT repository_type, format
            FROM repositories
            WHERE key = $1
            "#,
        )
        .bind(target_key)
        .fetch_optional(&self.db)
        .await?;

        match existing {
            None => Ok(ConflictCheck {
                has_conflict: false,
                conflict_type: None,
                existing_repo_key: None,
                message: "No conflict".into(),
            }),
            Some((existing_type, existing_format)) => {
                let target_type = repo_type.to_artifact_keeper();

                if existing_type != target_type {
                    Ok(ConflictCheck {
                        has_conflict: true,
                        conflict_type: Some(ConflictType::TypeMismatch),
                        existing_repo_key: Some(target_key.to_string()),
                        message: format!(
                            "Repository '{}' exists with type '{}', cannot migrate as '{}'",
                            target_key, existing_type, target_type
                        ),
                    })
                } else if existing_format.to_lowercase() != package_type.to_lowercase() {
                    Ok(ConflictCheck {
                        has_conflict: true,
                        conflict_type: Some(ConflictType::FormatMismatch),
                        existing_repo_key: Some(target_key.to_string()),
                        message: format!(
                            "Repository '{}' exists with format '{}', cannot migrate as '{}'",
                            target_key, existing_format, package_type
                        ),
                    })
                } else {
                    Ok(ConflictCheck {
                        has_conflict: true,
                        conflict_type: Some(ConflictType::SameKey),
                        existing_repo_key: Some(target_key.to_string()),
                        message: format!(
                            "Repository '{}' already exists with matching type and format",
                            target_key
                        ),
                    })
                }
            }
        }
    }

    /// Create a repository in Artifact Keeper from Artifactory config
    pub async fn create_repository(
        &self,
        config: &RepositoryMigrationConfig,
    ) -> Result<Uuid, MigrationError> {
        // Check compatibility
        if config.format_compatibility == FormatCompatibility::Unsupported {
            return Err(MigrationError::ConfigError(format!(
                "Package type '{}' is not supported for migration",
                config.package_type
            )));
        }

        // Determine the format to use
        let format = if config.format_compatibility == FormatCompatibility::Partial {
            "generic".to_string() // Migrate as generic for partial support
        } else {
            config.package_type.to_lowercase()
        };

        let repo_type = config.repo_type.to_artifact_keeper();

        let repo_id: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO repositories (key, display_name, repository_type, format, description, metadata)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
            "#,
        )
        .bind(&config.target_key)
        .bind(&config.target_key) // display_name same as key
        .bind(repo_type)
        .bind(&format)
        .bind(&config.description)
        .bind(serde_json::json!({
            "migrated_from": "artifactory",
            "source_key": config.source_key,
            "original_package_type": config.package_type,
        }))
        .fetch_one(&self.db)
        .await?;

        Ok(repo_id.0)
    }

    /// Resolve virtual repository references (ensure members exist)
    pub async fn resolve_virtual_repo_members(
        &self,
        virtual_key: &str,
        members: &[String],
    ) -> Result<Vec<Uuid>, MigrationError> {
        let mut member_ids = Vec::with_capacity(members.len());

        for member_key in members {
            let member_id: Option<(Uuid,)> = sqlx::query_as(
                "SELECT id FROM repositories WHERE key = $1"
            )
            .bind(member_key)
            .fetch_optional(&self.db)
            .await?;

            match member_id {
                Some((id,)) => member_ids.push(id),
                None => {
                    tracing::warn!(
                        "Virtual repository '{}' references non-existent member '{}', skipping",
                        virtual_key, member_key
                    );
                }
            }
        }

        Ok(member_ids)
    }

    /// Get list of repositories to migrate, ordered by dependency
    /// (local repos first, then remote, then virtual)
    pub fn order_repositories_for_migration(
        repos: Vec<RepositoryMigrationConfig>,
    ) -> Vec<RepositoryMigrationConfig> {
        let mut local = Vec::new();
        let mut remote = Vec::new();
        let mut virtual_repos = Vec::new();

        for repo in repos {
            match repo.repo_type {
                RepositoryType::Local => local.push(repo),
                RepositoryType::Remote => remote.push(repo),
                RepositoryType::Virtual => virtual_repos.push(repo),
            }
        }

        // Order: local first (they host artifacts), then remote (proxies), then virtual (groups)
        let mut ordered = local;
        ordered.extend(remote);
        ordered.extend(virtual_repos);
        ordered
    }

    /// Update job status
    #[instrument(skip(self), fields(job_id = %job_id, status = ?status))]
    pub async fn update_job_status(
        &self,
        job_id: Uuid,
        status: MigrationJobStatus,
    ) -> Result<(), MigrationError> {
        info!(job_id = %job_id, status = ?status, "Updating job status");
        sqlx::query(
            r#"
            UPDATE migration_jobs
            SET status = $1
            WHERE id = $2
            "#,
        )
        .bind(status.to_string())
        .bind(job_id)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    /// Update job progress
    pub async fn update_job_progress(
        &self,
        job_id: Uuid,
        completed: i32,
        failed: i32,
        skipped: i32,
        transferred_bytes: i64,
    ) -> Result<(), MigrationError> {
        sqlx::query(
            r#"
            UPDATE migration_jobs
            SET completed_items = $1,
                failed_items = $2,
                skipped_items = $3,
                transferred_bytes = $4
            WHERE id = $5
            "#,
        )
        .bind(completed)
        .bind(failed)
        .bind(skipped)
        .bind(transferred_bytes)
        .bind(job_id)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    /// Add migration items for a job
    pub async fn add_migration_items(
        &self,
        job_id: Uuid,
        items: Vec<MigrationItemData>,
    ) -> Result<(), MigrationError> {
        for item in items {
            sqlx::query(
                r#"
                INSERT INTO migration_items (job_id, item_type, source_path, size_bytes, checksum_source, metadata)
                VALUES ($1, $2, $3, $4, $5, $6)
                "#,
            )
            .bind(job_id)
            .bind(item.item_type.to_string())
            .bind(&item.source_path)
            .bind(item.size_bytes)
            .bind(&item.checksum)
            .bind(&item.metadata)
            .execute(&self.db)
            .await?;
        }

        // Update total items count
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM migration_items WHERE job_id = $1",
        )
        .bind(job_id)
        .fetch_one(&self.db)
        .await?;

        sqlx::query("UPDATE migration_jobs SET total_items = $1 WHERE id = $2")
            .bind(count.0 as i32)
            .bind(job_id)
            .execute(&self.db)
            .await?;

        Ok(())
    }

    /// Mark an item as completed
    #[instrument(skip(self), fields(item_id = %item_id))]
    pub async fn complete_item(
        &self,
        item_id: Uuid,
        target_path: &str,
        checksum_target: &str,
    ) -> Result<(), MigrationError> {
        debug!(item_id = %item_id, target_path = %target_path, "Item completed");
        sqlx::query(
            r#"
            UPDATE migration_items
            SET status = 'completed',
                target_path = $1,
                checksum_target = $2,
                completed_at = NOW()
            WHERE id = $3
            "#,
        )
        .bind(target_path)
        .bind(checksum_target)
        .bind(item_id)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    /// Mark an item as failed
    #[instrument(skip(self), fields(item_id = %item_id))]
    pub async fn fail_item(
        &self,
        item_id: Uuid,
        error_message: &str,
    ) -> Result<(), MigrationError> {
        warn!(item_id = %item_id, error = %error_message, "Item failed");
        sqlx::query(
            r#"
            UPDATE migration_items
            SET status = 'failed',
                error_message = $1,
                retry_count = retry_count + 1,
                completed_at = NOW()
            WHERE id = $2
            "#,
        )
        .bind(error_message)
        .bind(item_id)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    /// Mark an item as skipped
    #[instrument(skip(self), fields(item_id = %item_id))]
    pub async fn skip_item(
        &self,
        item_id: Uuid,
        reason: &str,
    ) -> Result<(), MigrationError> {
        debug!(item_id = %item_id, reason = %reason, "Item skipped");
        sqlx::query(
            r#"
            UPDATE migration_items
            SET status = 'skipped',
                error_message = $1,
                completed_at = NOW()
            WHERE id = $2
            "#,
        )
        .bind(reason)
        .bind(item_id)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    /// Generate migration report
    pub async fn generate_report(&self, job_id: Uuid) -> Result<Uuid, MigrationError> {
        // Get job summary
        let job: (i32, i32, i32, i32, i64, Option<chrono::DateTime<chrono::Utc>>, Option<chrono::DateTime<chrono::Utc>>) = sqlx::query_as(
            r#"
            SELECT total_items, completed_items, failed_items, skipped_items, transferred_bytes, started_at, finished_at
            FROM migration_jobs
            WHERE id = $1
            "#,
        )
        .bind(job_id)
        .fetch_one(&self.db)
        .await?;

        let (total_items, completed, failed, skipped, transferred, started_at, finished_at) = job;

        let duration = match (started_at, finished_at) {
            (Some(start), Some(end)) => end.signed_duration_since(start).num_seconds(),
            _ => 0,
        };

        // Count items by type
        let type_counts: Vec<(String, i64, i64, i64, i64)> = sqlx::query_as(
            r#"
            SELECT item_type,
                   COUNT(*) as total,
                   COUNT(*) FILTER (WHERE status = 'completed') as completed,
                   COUNT(*) FILTER (WHERE status = 'failed') as failed,
                   COUNT(*) FILTER (WHERE status = 'skipped') as skipped
            FROM migration_items
            WHERE job_id = $1
            GROUP BY item_type
            "#,
        )
        .bind(job_id)
        .fetch_all(&self.db)
        .await?;

        // Build summary JSON
        let mut summary = serde_json::json!({
            "duration_seconds": duration,
            "total_bytes_transferred": transferred,
        });

        for (item_type, total, comp, fail, skip) in &type_counts {
            let key = match item_type.as_str() {
                "repository" => "repositories",
                "artifact" => "artifacts",
                "user" => "users",
                "group" => "groups",
                "permission" => "permissions",
                _ => continue,
            };
            summary[key] = serde_json::json!({
                "total": total,
                "migrated": comp,
                "failed": fail,
                "skipped": skip,
            });
        }

        // Get errors
        let errors: Vec<(String, String, Option<String>)> = sqlx::query_as(
            r#"
            SELECT item_type, source_path, error_message
            FROM migration_items
            WHERE job_id = $1 AND status = 'failed'
            LIMIT 100
            "#,
        )
        .bind(job_id)
        .fetch_all(&self.db)
        .await?;

        let errors_json: Vec<serde_json::Value> = errors
            .iter()
            .map(|(item_type, path, msg)| {
                serde_json::json!({
                    "code": "MIGRATION_FAILED",
                    "message": msg.clone().unwrap_or_default(),
                    "item_path": path,
                })
            })
            .collect();

        // Insert report
        let report_id: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO migration_reports (job_id, summary, warnings, errors, recommendations)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
            "#,
        )
        .bind(job_id)
        .bind(&summary)
        .bind(serde_json::json!([]))
        .bind(serde_json::Value::Array(errors_json))
        .bind(serde_json::json!([]))
        .fetch_one(&self.db)
        .await?;

        Ok(report_id.0)
    }

    /// Check if a repository pattern matches
    pub fn matches_pattern(key: &str, patterns: &[String]) -> bool {
        if patterns.is_empty() {
            return true;
        }

        for pattern in patterns {
            if pattern.contains('*') {
                // Simple glob matching
                let regex_pattern = pattern
                    .replace('.', r"\.")
                    .replace('*', ".*")
                    .replace('?', ".");
                if let Ok(re) = regex::Regex::new(&format!("^{}$", regex_pattern)) {
                    if re.is_match(key) {
                        return true;
                    }
                }
            } else if key == pattern {
                return true;
            }
        }

        false
    }

    /// Check if a path should be excluded based on patterns
    pub fn should_exclude_path(path: &str, exclude_patterns: &[String]) -> bool {
        for pattern in exclude_patterns {
            if pattern.contains('*') {
                let regex_pattern = pattern
                    .replace('.', r"\.")
                    .replace("**", ".*")
                    .replace('*', "[^/]*")
                    .replace('?', ".");
                if let Ok(re) = regex::Regex::new(&format!("^{}$", regex_pattern)) {
                    if re.is_match(path) {
                        return true;
                    }
                }
            } else if path.contains(pattern) {
                return true;
            }
        }

        false
    }

    // ============ Path Sanitization ============

    /// Sanitize artifact path by replacing or removing special characters
    /// that may cause issues in file systems or URLs
    pub fn sanitize_path(path: &str) -> String {
        // Characters that need escaping/replacement in paths
        let sanitized: String = path
            .chars()
            .map(|c| match c {
                // Replace control characters and null bytes
                '\0'..='\x1f' => '_',
                // Replace Windows forbidden characters
                '<' | '>' | ':' | '"' | '|' | '?' | '*' => '_',
                // Replace backslashes with forward slashes
                '\\' => '/',
                // Keep other characters as-is
                _ => c,
            })
            .collect();

        // Collapse multiple consecutive slashes
        let mut result = String::new();
        let mut prev_slash = false;
        for c in sanitized.chars() {
            if c == '/' {
                if !prev_slash && !result.is_empty() {
                    result.push(c);
                }
                prev_slash = true;
            } else {
                result.push(c);
                prev_slash = false;
            }
        }

        // Remove trailing slash
        result.trim_end_matches('/').to_string()
    }

    /// Sanitize repository key (stricter rules for repository names)
    pub fn sanitize_repo_key(key: &str) -> String {
        let sanitized: String = key
            .chars()
            .filter_map(|c| match c {
                // Only allow alphanumeric, dash, underscore, and dot
                'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => Some(c),
                // Replace spaces with dash
                ' ' => Some('-'),
                // Remove other characters
                _ => None,
            })
            .collect();

        // Remove leading/trailing dots and dashes
        sanitized
            .trim_start_matches(&['.', '-'][..])
            .trim_end_matches(&['.', '-'][..])
            .to_string()
    }

    /// Check if a path contains potentially dangerous patterns
    pub fn is_path_safe(path: &str) -> bool {
        // Check for path traversal attempts
        if path.contains("..") {
            return false;
        }

        // Check for absolute paths (may indicate an attempt to write outside repository)
        if path.starts_with('/') || path.starts_with('\\') {
            return false;
        }

        // Check for Windows drive letters
        if path.len() >= 2 && path.chars().nth(1) == Some(':') {
            return false;
        }

        // Check for UNC paths
        if path.starts_with("\\\\") {
            return false;
        }

        true
    }

    // ============ Incremental Migration Methods ============

    /// Get the last successful migration timestamp for a repository
    pub async fn get_last_migration_time(
        &self,
        source_connection_id: Uuid,
        repo_key: &str,
    ) -> Result<Option<chrono::DateTime<chrono::Utc>>, MigrationError> {
        let result: Option<(chrono::DateTime<chrono::Utc>,)> = sqlx::query_as(
            r#"
            SELECT MAX(mj.finished_at)
            FROM migration_jobs mj
            JOIN migration_items mi ON mi.job_id = mj.id
            WHERE mj.source_connection_id = $1
              AND mj.status = 'completed'
              AND mi.source_path LIKE $2
            "#,
        )
        .bind(source_connection_id)
        .bind(format!("{}/%", repo_key))
        .fetch_optional(&self.db)
        .await?;

        Ok(result.map(|r| r.0))
    }

    /// Record migration sync time for a repository
    pub async fn record_sync_time(
        &self,
        source_connection_id: Uuid,
        repo_key: &str,
        sync_time: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), MigrationError> {
        sqlx::query(
            r#"
            INSERT INTO migration_sync_history (source_connection_id, repository_key, synced_at)
            VALUES ($1, $2, $3)
            ON CONFLICT (source_connection_id, repository_key)
            DO UPDATE SET synced_at = $3
            "#,
        )
        .bind(source_connection_id)
        .bind(repo_key)
        .bind(sync_time)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    /// Check if an item was previously migrated (for skip duplicate)
    pub async fn is_item_migrated(
        &self,
        source_connection_id: Uuid,
        source_path: &str,
        checksum: Option<&str>,
    ) -> Result<bool, MigrationError> {
        // Check if we have a completed migration item with this path and checksum
        let result: Option<(i64,)> = sqlx::query_as(
            r#"
            SELECT COUNT(*)
            FROM migration_items mi
            JOIN migration_jobs mj ON mj.id = mi.job_id
            WHERE mj.source_connection_id = $1
              AND mi.source_path = $2
              AND mi.status = 'completed'
              AND ($3::text IS NULL OR mi.checksum_source = $3)
            "#,
        )
        .bind(source_connection_id)
        .bind(source_path)
        .bind(checksum)
        .fetch_optional(&self.db)
        .await?;

        Ok(result.map(|r| r.0 > 0).unwrap_or(false))
    }

    /// Get repositories that have been migrated for a connection
    pub async fn get_migrated_repositories(
        &self,
        source_connection_id: Uuid,
    ) -> Result<Vec<String>, MigrationError> {
        let result: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT DISTINCT SPLIT_PART(mi.source_path, '/', 1) as repo_key
            FROM migration_items mi
            JOIN migration_jobs mj ON mj.id = mi.job_id
            WHERE mj.source_connection_id = $1
              AND mj.status = 'completed'
              AND mi.item_type = 'artifact'
            ORDER BY repo_key
            "#,
        )
        .bind(source_connection_id)
        .fetch_all(&self.db)
        .await?;

        Ok(result.into_iter().map(|r| r.0).collect())
    }
}

// ============ Assessment Methods ============

/// Assessment result for a repository
#[derive(Debug, Clone, serde::Serialize)]
pub struct RepositoryAssessment {
    pub key: String,
    pub repo_type: String,
    pub package_type: String,
    pub artifact_count: i64,
    pub total_size_bytes: i64,
    pub compatibility: String,
    pub warnings: Vec<String>,
}

/// Full assessment result
#[derive(Debug, Clone, serde::Serialize)]
pub struct AssessmentResult {
    pub repositories: Vec<RepositoryAssessment>,
    pub total_artifacts: i64,
    pub total_size_bytes: i64,
    pub users_count: i64,
    pub groups_count: i64,
    pub permissions_count: i64,
    pub estimated_duration_seconds: i64,
    pub warnings: Vec<String>,
    pub blockers: Vec<String>,
}

impl MigrationService {
    /// Run a pre-migration assessment
    pub async fn run_assessment(
        &self,
        connection_id: Uuid,
        client: &ArtifactoryClient,
    ) -> Result<AssessmentResult, MigrationError> {
        let mut repositories = Vec::new();
        let mut total_artifacts = 0i64;
        let mut total_size = 0i64;
        let mut warnings = Vec::new();
        let mut blockers = Vec::new();

        // List and assess repositories
        let repos = client.list_repositories().await?;

        for repo in &repos {
            let compatibility = Self::get_format_compatibility(&repo.package_type);
            let compat_str = match compatibility {
                FormatCompatibility::Full => "full",
                FormatCompatibility::Partial => "partial",
                FormatCompatibility::Unsupported => "unsupported",
            };

            // Get artifact counts using AQL
            let artifacts = client.list_artifacts(&repo.key, 0, 1).await;
            let (artifact_count, repo_size) = match artifacts {
                Ok(aql_response) => {
                    (aql_response.range.total, 0i64) // Size would require more queries
                }
                Err(_) => (0, 0),
            };

            let mut repo_warnings = Vec::new();

            if compatibility == FormatCompatibility::Unsupported {
                repo_warnings.push(format!(
                    "Package type '{}' is not supported",
                    repo.package_type
                ));
            } else if compatibility == FormatCompatibility::Partial {
                repo_warnings.push(format!(
                    "Package type '{}' will be migrated as generic format",
                    repo.package_type
                ));
            }

            // Check for virtual repos
            if repo.repo_type.to_lowercase() == "virtual" {
                repo_warnings.push("Virtual repositories require member repos to be migrated first".into());
            }

            repositories.push(RepositoryAssessment {
                key: repo.key.clone(),
                repo_type: repo.repo_type.clone(),
                package_type: repo.package_type.clone(),
                artifact_count,
                total_size_bytes: repo_size,
                compatibility: compat_str.to_string(),
                warnings: repo_warnings,
            });

            total_artifacts += artifact_count;
            total_size += repo_size;
        }

        // Count users
        let users_count = match client.list_users().await {
            Ok(users) => users.len() as i64,
            Err(_) => {
                warnings.push("Could not fetch user list".into());
                0
            }
        };

        // Count groups
        let groups_count = match client.list_groups().await {
            Ok(groups) => groups.len() as i64,
            Err(_) => {
                warnings.push("Could not fetch group list".into());
                0
            }
        };

        // Count permissions
        let permissions_count = match client.list_permissions().await {
            Ok(perms) => perms.permissions.len() as i64,
            Err(_) => {
                warnings.push("Could not fetch permission list".into());
                0
            }
        };

        // Estimate duration (rough estimate: 1 artifact per second + overhead)
        let estimated_seconds = total_artifacts + (repositories.len() as i64 * 10);

        // Check for blockers
        if repositories.iter().all(|r| r.compatibility == "unsupported") {
            blockers.push("No repositories have supported package types".into());
        }

        Ok(AssessmentResult {
            repositories,
            total_artifacts,
            total_size_bytes: total_size,
            users_count,
            groups_count,
            permissions_count,
            estimated_duration_seconds: estimated_seconds,
            warnings,
            blockers,
        })
    }

    /// Save assessment result to database
    pub async fn save_assessment(
        &self,
        job_id: Uuid,
        result: &AssessmentResult,
    ) -> Result<(), MigrationError> {
        let summary = serde_json::to_value(result)
            .map_err(|e| MigrationError::Other(e.to_string()))?;

        // Update the job with assessment data
        sqlx::query(
            r#"
            UPDATE migration_jobs
            SET total_items = $1,
                total_bytes = $2,
                status = 'ready',
                config = config || $3
            WHERE id = $4
            "#,
        )
        .bind(result.total_artifacts as i32)
        .bind(result.total_size_bytes)
        .bind(serde_json::json!({
            "assessment": summary,
            "assessed_at": chrono::Utc::now().to_rfc3339(),
        }))
        .bind(job_id)
        .execute(&self.db)
        .await?;

        Ok(())
    }
}

/// Data for a migration item
pub struct MigrationItemData {
    pub item_type: MigrationItemType,
    pub source_path: String,
    pub size_bytes: i64,
    pub checksum: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_compatibility() {
        assert_eq!(
            MigrationService::get_format_compatibility("maven"),
            FormatCompatibility::Full
        );
        assert_eq!(
            MigrationService::get_format_compatibility("npm"),
            FormatCompatibility::Full
        );
        assert_eq!(
            MigrationService::get_format_compatibility("conan"),
            FormatCompatibility::Partial
        );
        assert_eq!(
            MigrationService::get_format_compatibility("unknown"),
            FormatCompatibility::Unsupported
        );
    }

    #[test]
    fn test_permission_mapping() {
        assert_eq!(MigrationService::map_permission("read"), Some("read"));
        assert_eq!(MigrationService::map_permission("deploy"), Some("write"));
        assert_eq!(MigrationService::map_permission("delete"), Some("delete"));
        assert_eq!(MigrationService::map_permission("admin"), Some("admin"));
        assert_eq!(MigrationService::map_permission("distribute"), None);
    }

    #[test]
    fn test_pattern_matching() {
        assert!(MigrationService::matches_pattern(
            "libs-release-local",
            &["libs-*".to_string()]
        ));
        assert!(MigrationService::matches_pattern(
            "libs-release-local",
            &["libs-release-local".to_string()]
        ));
        assert!(!MigrationService::matches_pattern(
            "plugins-local",
            &["libs-*".to_string()]
        ));
        assert!(MigrationService::matches_pattern(
            "anything",
            &[]
        ));
    }
}
