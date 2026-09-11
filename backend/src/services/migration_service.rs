//! Migration service - orchestrates the migration process.
//!
//! This service coordinates the migration from Artifactory to Artifact Keeper,
//! handling repository creation, artifact transfer, user/group migration, and
//! permission mapping.

use sqlx::PgPool;
use thiserror::Error;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

use crate::models::migration::{MigrationItemType, MigrationJobStatus};
use crate::services::artifactory_client::{
    ArtifactoryAuth, ArtifactoryClient, ArtifactoryClientConfig, RepositoryConfig,
    RepositoryListItem,
};
use crate::services::source_registry::SourceRegistry;

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

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Migration error: {0}")]
    Other(String),
}

/// How much of the source a migration run had seen when it published its
/// figures to the job row.
///
/// A run's in-memory counters restart at zero every time `process_job` is
/// entered, while the job row's do not: a resumed job still carries the
/// `completed_items` of the pass that was paused. Publishing a partial view
/// absolutely therefore *overwrites a complete record with an incomplete one*
/// — a paused-then-resumed-then-repaused job had its `completed_items` and
/// `transferred_bytes` reset to zero even though the transfers had happened
/// and the `migration_items` rows proving it were still there (#3510).
///
/// So a run may only *overwrite* the row once it has enumerated the whole
/// source; while its view is still partial it may only *advance* the row.
/// Overwriting has to stay available at the end of a run, because that is what
/// lets a stale assessment estimate be corrected downwards — the very thing
/// #3378 asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceView {
    /// The run is still enumerating: it has seen some of the source, and
    /// anything already on the row may describe more work than it has. Writes
    /// may only move the figures forward.
    Partial,
    /// The run enumerated the whole source and re-classified every item it
    /// found, so its figures supersede whatever the row carried.
    Complete,
}

impl SourceView {
    /// Whether a write in this view is allowed to overwrite the row outright.
    fn overwrites(self) -> bool {
        matches!(self, SourceView::Complete)
    }
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
    /// Parse a source-side repository type string.
    ///
    /// Accepts both the Artifactory vocabulary (`local` / `remote` /
    /// `virtual` / `federated`) and the Nexus vocabulary (`hosted` / `proxy` /
    /// `group`). These denote the same three logical kinds — the enum doc
    /// comments above have always pinned this mapping. Artifactory
    /// `federated` repos store artifacts locally (a local repo that also
    /// mirrors to peer instances), so they map to `Local`. Prior to these
    /// fixes the function only matched the Artifactory triple, so every Nexus
    /// repository was rejected by `prepare_repository_migration` with
    /// `Unknown repository type: hosted` and an entire Nexus source was
    /// effectively un-migratable (issue #1889); `federated` sources hit the
    /// same wall with `Unknown repository type: FEDERATED`.
    pub fn from_artifactory(rclass: &str) -> Option<Self> {
        match rclass.to_lowercase().as_str() {
            "local" | "hosted" | "federated" => Some(Self::Local),
            "remote" | "proxy" => Some(Self::Remote),
            "virtual" | "group" => Some(Self::Virtual),
            _ => None,
        }
    }

    /// Convert to Artifact Keeper repository type string
    pub fn to_artifact_keeper(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Remote => "remote",
            Self::Virtual => "virtual",
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

/// Outcome of correlating a source group/virtual repo's members to the
/// migrated Artifact Keeper repositories (issue #2783).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualMemberCorrelation {
    /// The AK repository id of the virtual repo whose membership was written.
    pub virtual_id: Uuid,
    /// Number of source members successfully correlated and persisted.
    pub correlated: usize,
    /// Source member names that could not be correlated (not migrated, or a
    /// self-reference) and were therefore skipped rather than written as a
    /// dangling reference.
    pub skipped: Vec<String>,
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

        // Decrypt credentials using the migration encryption key. Falls
        // back to the dev passphrase if the env var is unset so we can
        // decrypt rows written by `migration::create_connection` under
        // the same fallback (see issue #1439 / Bug A).
        let encryption_key = std::env::var("MIGRATION_ENCRYPTION_KEY")
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| {
                tracing::warn!(
                    "MIGRATION_ENCRYPTION_KEY is not set; using built-in fallback to \
                     decrypt source-connection credentials."
                );
                "artifact-keeper-default-migration-key-dev-only".to_string()
            });
        let credentials_json =
            crate::services::encryption::decrypt_credentials(&credentials_enc, &encryption_key)
                .map_err(|e| MigrationError::ConfigError(format!("Decryption failed: {}", e)))?;

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
            _ => {
                return Err(MigrationError::ConfigError(format!(
                    "Unknown auth type: {}",
                    auth_type
                )))
            }
        };

        let config = ArtifactoryClientConfig {
            base_url: url,
            auth,
            ..Default::default()
        };

        ArtifactoryClient::new(config).map_err(Into::into)
    }

    /// Normalize a source-specific package type name to the canonical
    /// Artifact Keeper format name.
    ///
    /// Different source registries use different identifiers for the same
    /// logical format. For example, Nexus 3 reports Maven repositories as
    /// `maven2`, Yum repositories as `yum`, and generic binary repositories
    /// as `raw`, while Artifact Keeper and Artifactory use `maven`, `rpm`,
    /// and `generic` respectively. This function performs that translation
    /// so downstream compatibility lookups can rely on canonical names.
    ///
    /// Unknown formats are returned unchanged (lowercased) so that the
    /// existing `Unsupported` path still triggers for truly unsupported
    /// types.
    pub fn normalize_package_type(package_type: &str) -> String {
        let lower = package_type.to_lowercase();
        match lower.as_str() {
            // Nexus uses `maven2` for Maven 2 and Maven 3 repositories
            "maven2" => "maven".to_string(),
            // Nexus uses `raw` for its unstructured binary format
            "raw" => "generic".to_string(),
            // Nexus uses `yum`, Artifact Keeper's equivalent is `rpm`
            "yum" => "rpm".to_string(),
            // Nexus uses `apt` for Debian/APT repositories; Artifact Keeper's
            // equivalent format is `debian`. Without this mapping an `apt`
            // repository normalized to the unknown name `apt`, which
            // `get_format_compatibility` classifies as `Unsupported`, so the
            // whole repository failed to migrate (#2784).
            "apt" => "debian".to_string(),
            // Some tools report Go module repositories as `golang`; Artifact
            // Keeper's canonical format is `go`.
            "golang" => "go".to_string(),
            // RubyGems is sometimes reported as `gems` or `rubygems`
            "gems" => "rubygems".to_string(),
            _ => lower,
        }
    }

    /// Get the compatibility level for a package format.
    ///
    /// Source-specific names are normalized before lookup so that Nexus
    /// formats like `maven2`, `yum`, and `raw` map to the correct Artifact
    /// Keeper compatibility level.
    pub fn get_format_compatibility(package_type: &str) -> FormatCompatibility {
        let normalized = Self::normalize_package_type(package_type);
        match normalized.as_str() {
            "maven" | "npm" | "docker" | "pypi" | "helm" | "nuget" | "cargo" | "go" | "generic"
            | "rubygems" => FormatCompatibility::Full,
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
        _repo_config: Option<&RepositoryConfig>,
    ) -> Result<RepositoryMigrationConfig, MigrationError> {
        let repo_type = RepositoryType::from_artifactory(&repo.repo_type).ok_or_else(|| {
            MigrationError::ConfigError(format!("Unknown repository type: {}", repo.repo_type))
        })?;

        let format_compatibility = Self::get_format_compatibility(&repo.package_type);
        // Canonicalize source-specific names like `maven2` or `yum` so the
        // rest of the migration pipeline sees Artifact Keeper's native names.
        let normalized_package_type = Self::normalize_package_type(&repo.package_type);

        Ok(RepositoryMigrationConfig {
            source_key: repo.key.clone(),
            target_key: repo.key.clone(), // Same name by default
            repo_type,
            package_type: normalized_package_type,
            description: repo.description.clone(),
            format_compatibility,
            // Thread the source-reported upstream URL through so remote/proxy
            // repos migrate with a non-NULL `upstream_url`. Populated by the
            // source clients (Artifactory remote-config `url` / Nexus
            // `proxy.remoteUrl`); previously hard-coded to `None`, which made
            // every remote repo fail the AK `check_upstream_url` constraint and
            // get skipped (issue #2822).
            upstream_url: repo.upstream_url.clone(),
            // Carry the source-side member keys (Nexus `group.memberNames` /
            // Artifactory virtual `repositories`) through so virtual/group repos
            // can be correlated to their migrated AK members later. Previously
            // hard-coded to `vec![]`, which is why migrated Nexus groups ended up
            // with zero members and broke the UI/backend (issue #2783).
            members: repo.members.clone(),
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
            SELECT repo_type::text, format::text
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

    /// Compute the persisted `storage_path` for an auto-provisioned repository.
    ///
    /// Filesystem-backed repos store an ABSOLUTE path under the staging/storage
    /// base so writes land on the mounted volume (#2025). Cloud backends (s3,
    /// gcs, azure) address objects by the bare repo key, matching the HTTP
    /// create-repo handler in `api::handlers::repositories`.
    fn build_storage_path(storage_backend: &str, storage_base: &str, target_key: &str) -> String {
        if storage_backend == "filesystem" {
            format!("{}/{}", storage_base, target_key)
        } else {
            target_key.to_string()
        }
    }

    /// Create a repository in Artifact Keeper from Artifactory config.
    ///
    /// `storage_backend` is the resolved backend name the migrated repo should
    /// use (typically the server's default backend). Without it every
    /// auto-provisioned repo fell back to the column default `filesystem`,
    /// silently stranding S3/GCS/Azure deployments' migrated artifacts on local
    /// disk (#2336).
    pub async fn create_repository(
        &self,
        config: &RepositoryMigrationConfig,
        storage_base: &str,
        storage_backend: &str,
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

        // A remote repo with no resolvable upstream URL cannot satisfy the
        // `check_upstream_url` constraint (repo_type='remote' requires a
        // NOT-NULL upstream_url). Surface a clear config error here instead of
        // letting the raw SQLSTATE 23514 bubble up from the INSERT (issue #2822).
        if config.repo_type == RepositoryType::Remote && config.upstream_url.is_none() {
            return Err(MigrationError::ConfigError(format!(
                "remote repo {}: source did not report an upstream URL",
                config.source_key
            )));
        }

        // The repositories table schema has no `metadata`, `display_name`, or
        // `repository_type` columns. The corresponding columns are `name` and
        // `repo_type`, and `storage_path` is NOT NULL — so the INSERT must
        // supply it. `storage_backend` must also be supplied explicitly;
        // otherwise it falls back to the column default `filesystem` (#2336).
        let storage_path =
            Self::build_storage_path(storage_backend, storage_base, &config.target_key);
        let repo_id: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO repositories (key, name, description, format, repo_type, storage_path, storage_backend, upstream_url)
            VALUES ($1, $2, $3, $4::repository_format, $5::repository_type, $6, $7, $8)
            RETURNING id
            "#,
        )
        .bind(&config.target_key)
        .bind(&config.target_key) // name same as key for auto-provisioned repos
        .bind(&config.description)
        .bind(&format)
        .bind(repo_type)
        .bind(&storage_path)
        .bind(storage_backend)
        .bind(&config.upstream_url)
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
            let member_id: Option<(Uuid,)> =
                sqlx::query_as("SELECT id FROM repositories WHERE key = $1")
                    .bind(member_key)
                    .fetch_optional(&self.db)
                    .await?;

            match member_id {
                Some((id,)) => member_ids.push(id),
                None => {
                    tracing::warn!(
                        "Virtual repository '{}' references non-existent member '{}', skipping",
                        virtual_key,
                        member_key
                    );
                }
            }
        }

        Ok(member_ids)
    }

    /// Correlate a source group/virtual repository's ordered member names to
    /// the Artifact Keeper repositories they were migrated into, then persist
    /// the membership so the resulting virtual repo is valid.
    ///
    /// This is the fix for issue #2783: a Nexus `group` (≡ AK `virtual`) repo
    /// carries a list of member *names* from the source. Those names have to be
    /// resolved to the `repositories.id` of the already-migrated members and
    /// written into `virtual_repo_members` — otherwise the migrated virtual repo
    /// has zero (or, if written blindly, dangling) members and both the API and
    /// the UI error out when they try to aggregate over it.
    ///
    /// Contract:
    /// * Source member *order* is preserved via the `priority` column
    ///   (`get_virtual_members` orders by `priority` ascending), so member
    ///   precedence survives the migration.
    /// * A member name that does not resolve to a migrated AK repo is **skipped
    ///   and reported**, never written — the `virtual_repo_members.member_repo_id`
    ///   foreign key would reject it anyway, and a dangling reference is exactly
    ///   what breaks the frontend. The returned `skipped` list lets the caller
    ///   surface a partial-migration warning.
    /// * The write is idempotent: existing rows for this virtual repo are
    ///   cleared first, so re-running a migration reconciles rather than
    ///   duplicating (the `UNIQUE(virtual_repo_id, member_repo_id)` constraint
    ///   is respected regardless).
    pub async fn correlate_virtual_repo_members(
        &self,
        virtual_key: &str,
        member_names: &[String],
    ) -> Result<VirtualMemberCorrelation, MigrationError> {
        // Resolve the virtual repository itself.
        let virtual_id: Uuid = sqlx::query_as::<_, (Uuid,)>(
            "SELECT id FROM repositories WHERE key = $1 AND repo_type = 'virtual'",
        )
        .bind(virtual_key)
        .fetch_optional(&self.db)
        .await?
        .ok_or_else(|| {
            MigrationError::ConfigError(format!(
                "Virtual repository '{}' not found while correlating members",
                virtual_key
            ))
        })?
        .0;

        // Resolve each source member name to a migrated AK repo id, preserving
        // source order and recording names that never migrated (dangling).
        let mut resolved: Vec<(Uuid, i32)> = Vec::with_capacity(member_names.len());
        let mut skipped: Vec<String> = Vec::new();
        let mut seen: std::collections::HashSet<Uuid> = std::collections::HashSet::new();

        for member_key in member_names {
            let member_id: Option<(Uuid,)> =
                sqlx::query_as("SELECT id FROM repositories WHERE key = $1")
                    .bind(member_key)
                    .fetch_optional(&self.db)
                    .await?;

            match member_id {
                Some((id,)) if id == virtual_id => {
                    // A group listing itself is a source-side cycle; drop it so
                    // aggregation can't recurse into the virtual repo itself.
                    tracing::warn!(
                        "Virtual repository '{}' lists itself as a member; skipping",
                        virtual_key
                    );
                    skipped.push(member_key.clone());
                }
                Some((id,)) if !seen.insert(id) => {
                    // Duplicate member name in the source group — keep the first
                    // occurrence's priority, ignore the rest.
                    tracing::debug!(
                        "Virtual repository '{}' lists member '{}' more than once; keeping first",
                        virtual_key,
                        member_key
                    );
                }
                Some((id,)) => {
                    // Priority is 1-based and increases with source order so
                    // `ORDER BY priority` reproduces the group's member order.
                    resolved.push((id, (resolved.len() as i32) + 1));
                }
                None => {
                    tracing::warn!(
                        "Virtual repository '{}' references member '{}' that was not \
                         migrated; skipping to avoid a dangling reference",
                        virtual_key,
                        member_key
                    );
                    skipped.push(member_key.clone());
                }
            }
        }

        // Persist atomically: clear the current membership, then insert the
        // correlated members. Done in one transaction so a concurrent reader
        // never observes a half-written membership.
        let mut tx = self.db.begin().await?;
        sqlx::query("DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1")
            .bind(virtual_id)
            .execute(&mut *tx)
            .await?;
        for (member_id, priority) in &resolved {
            sqlx::query(
                r#"
                INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority)
                VALUES ($1, $2, $3)
                ON CONFLICT (virtual_repo_id, member_repo_id)
                DO UPDATE SET priority = EXCLUDED.priority
                "#,
            )
            .bind(virtual_id)
            .bind(member_id)
            .bind(priority)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;

        Ok(VirtualMemberCorrelation {
            virtual_id,
            correlated: resolved.len(),
            skipped,
        })
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

    /// Move a job into `running` on behalf of the worker, unless the operator
    /// has already paused or cancelled it. Returns whether the job was claimed.
    ///
    /// `start_migration` flips the row to `running` and then spawns a detached
    /// task, so there is a window between the operator getting their `200 OK`
    /// and the worker actually waking up. A cancel that lands in that window
    /// used to be undone by the worker's own unguarded `update_job_status(
    /// Running)`: the row went `cancelled` -> `running`, after which
    /// `finalize_job_status`'s `WHERE status NOT IN ('paused','cancelled')`
    /// guard saw nothing to protect and stamped the job `completed` — having
    /// migrated every artifact of a migration the operator had cancelled
    /// (#3510). Claiming under the same guard closes that window: if the job
    /// was stopped first, the worker never starts.
    #[instrument(skip(self), fields(job_id = %job_id))]
    pub async fn claim_job_running(&self, job_id: Uuid) -> Result<bool, MigrationError> {
        let result = sqlx::query(
            r#"
            UPDATE migration_jobs
            SET status = 'running'
            WHERE id = $1 AND status NOT IN ('paused', 'cancelled')
            "#,
        )
        .bind(job_id)
        .execute(&self.db)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Finalize a job with a terminal status and stamp `finished_at`, unless
    /// the operator has already paused or cancelled it — the guard keeps a
    /// pause that races the worker's final write from being overwritten
    /// (issue #3380). Returns whether the job was finalized.
    #[instrument(skip(self), fields(job_id = %job_id, status = ?status))]
    pub async fn finalize_job_status(
        &self,
        job_id: Uuid,
        status: MigrationJobStatus,
    ) -> Result<bool, MigrationError> {
        info!(job_id = %job_id, status = ?status, "Finalizing job status");
        let result = sqlx::query(
            r#"
            UPDATE migration_jobs
            SET status = $1, finished_at = NOW()
            WHERE id = $2 AND status NOT IN ('paused', 'cancelled')
            "#,
        )
        .bind(status.to_string())
        .bind(job_id)
        .execute(&self.db)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Publish the numerator of a job's progress fraction.
    ///
    /// `view` decides whether the run is allowed to overwrite the row or may
    /// only advance it; see [`SourceView`]. Under `Partial` the three item
    /// counters move as a group and only when the run has accounted for at
    /// least as many items as the row already claims, and `transferred_bytes`
    /// never shrinks. That is what stops a run whose counters restarted at
    /// zero from erasing the record of work an earlier pass of the same job
    /// really did (#3510): the counters are per-run by design — `resume_job`
    /// re-lists from offset 0 and re-classifies the earlier pass's items as
    /// `skipped` — but a run that has not finished re-listing yet has not
    /// re-classified them either, so its figures are not a replacement for
    /// the row's until it has.
    ///
    /// Deliberately NOT gated on `status`, unlike [`Self::update_job_totals`]:
    /// an item that finished transferring while the operator's pause was in
    /// flight has genuinely been migrated, and counting it is honest. The
    /// monotonic rule alone is what protects the row, and this statement never
    /// touches `status`, so it cannot revive a stopped job (#3440).
    ///
    /// Returns whether the numerator was published.
    pub async fn update_job_progress(
        &self,
        job_id: Uuid,
        completed: i32,
        failed: i32,
        skipped: i32,
        transferred_bytes: i64,
        view: SourceView,
    ) -> Result<bool, MigrationError> {
        let result = sqlx::query(
            r#"
            UPDATE migration_jobs
            SET completed_items = $1,
                failed_items = $2,
                skipped_items = $3,
                transferred_bytes = CASE
                    WHEN $6 THEN $4
                    ELSE GREATEST(transferred_bytes, $4)
                END
            WHERE id = $5
              AND (
                    $6
                    OR $1 + $2 + $3
                       >= completed_items + failed_items + skipped_items
                  )
            "#,
        )
        .bind(completed)
        .bind(failed)
        .bind(skipped)
        .bind(transferred_bytes)
        .bind(job_id)
        .bind(view.overwrites())
        .execute(&self.db)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Update the totals a job is measured against
    ///
    /// The worker calls this as it enumerates the source, so `total_items`
    /// tracks what has actually been discovered instead of staying at the zero
    /// the row was created with, which left every job reporting `N/0` and 0%
    /// (#3378). The values are rebuilt rather than accumulated: a resumed or
    /// re-run job enumerates from the first page again, so adding to them
    /// would double count.
    ///
    /// A rebuild is only allowed to *replace* the denominator once the run has
    /// enumerated the whole source (`SourceView::Complete`) — which is what
    /// lets an assessment's over-estimate be corrected downwards. Mid-run the
    /// denominator may only grow, so a resumed run that is stopped partway
    /// cannot leave the row advertising one page of a source it had already
    /// measured in full, with a numerator counting the whole of it (#3510).
    ///
    /// The write is guarded the same way `finalize_job_status` is. A page
    /// listing already in flight when the operator pauses or cancels lands
    /// after the row has left `running`, and while this statement never
    /// touches `status` — so it cannot revive a stopped job — an ungated
    /// write left a dead job advertising a denominator covering work it
    /// never processed (`cancelled`, `1000/2000`, 50%). Returns whether the
    /// totals were published.
    pub async fn update_job_totals(
        &self,
        job_id: Uuid,
        total_items: i32,
        total_bytes: i64,
        view: SourceView,
    ) -> Result<bool, MigrationError> {
        let result = sqlx::query(
            r#"
            UPDATE migration_jobs
            SET total_items = CASE
                    WHEN $4 THEN $1
                    ELSE GREATEST(total_items, $1)
                END,
                total_bytes = CASE
                    WHEN $4 THEN $2
                    ELSE GREATEST(total_bytes, $2)
                END
            WHERE id = $3 AND status NOT IN ('paused', 'cancelled')
            "#,
        )
        .bind(total_items)
        .bind(total_bytes)
        .bind(job_id)
        .bind(view.overwrites())
        .execute(&self.db)
        .await?;

        Ok(result.rows_affected() > 0)
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
        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM migration_items WHERE job_id = $1")
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
    pub async fn skip_item(&self, item_id: Uuid, reason: &str) -> Result<(), MigrationError> {
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
    #[allow(clippy::type_complexity)]
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

        let (_total_items, _completed, _failed, _skipped, transferred, started_at, finished_at) =
            job;

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
            .map(|(_item_type, path, msg)| {
                serde_json::json!({
                    "code": "MIGRATION_FAILED",
                    "message": msg.clone().unwrap_or_default(),
                    "item_path": path,
                })
            })
            .collect();

        // Insert (or refresh) the report. migration_reports.job_id is UNIQUE,
        // so an ON CONFLICT upsert keeps report generation idempotent: a job
        // that reaches a terminal state more than once (e.g. a cancel after a
        // prior failed-assessment that already wrote a report) regenerates the
        // audit envelope instead of erroring on the unique constraint.
        let report_id: (Uuid,) = sqlx::query_as(
            r#"
            INSERT INTO migration_reports (job_id, summary, warnings, errors, recommendations)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (job_id) DO UPDATE
            SET generated_at = NOW(),
                summary = EXCLUDED.summary,
                warnings = EXCLUDED.warnings,
                errors = EXCLUDED.errors,
                recommendations = EXCLUDED.recommendations
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
                // Simple glob matching: escape all regex metacharacters first,
                // then convert glob wildcards to regex equivalents.
                let escaped = regex::escape(pattern);
                let regex_pattern = escaped.replace(r"\*", ".*").replace(r"\?", ".");
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
                // Escape all regex metacharacters first, then convert globs
                let escaped = regex::escape(pattern);
                let regex_pattern = escaped
                    .replace(r"\*\*", ".*")
                    .replace(r"\*", "[^/]*")
                    .replace(r"\?", ".");
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
              AND mi.source_path LIKE $2 ESCAPE '\'
            "#,
        )
        .bind(source_connection_id)
        // #3557: `repo_key` becomes a `LIKE` prefix pattern, so a `%`/`_`/`\`
        // in the key would read another repository's migration items and
        // return the wrong incremental-sync watermark.
        .bind(format!(
            "{}/%",
            crate::api::handlers::escape_like_literal(repo_key)
        ))
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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
        _connection_id: Uuid,
        client: &dyn SourceRegistry,
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

            // Get artifact counts
            let artifacts = client.list_artifacts(&repo.key, 0, 1).await;
            let (artifact_count, repo_size) = match artifacts {
                Ok(aql_response) => (aql_response.range.total, 0i64),
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
                repo_warnings
                    .push("Virtual repositories require member repos to be migrated first".into());
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

        // User/group/permission counts require source-specific APIs
        // that are not part of the common SourceRegistry trait. These will
        // be populated as 0 for now; the core repository assessment is the
        // critical piece for pre-migration validation.
        let users_count = 0i64;
        let groups_count = 0i64;
        let permissions_count = 0i64;
        warnings.push("User/group/permission counts require source-specific API access and are not included in this assessment".into());

        // Estimate duration (rough estimate: 1 artifact per second + overhead)
        let estimated_seconds = total_artifacts + (repositories.len() as i64 * 10);

        // Check for blockers
        if repositories
            .iter()
            .all(|r| r.compatibility == "unsupported")
        {
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
    ///
    /// The totals written here are the assessment's pre-run estimate and hold
    /// only until the job runs: the worker republishes what it enumerates as
    /// it goes and once more when the run ends (see `update_job_totals`), so
    /// a repository whose real content differs from the assessment does not
    /// leave a stale denominator behind. The estimate is overwritten rather
    /// than cleared up front, so the row never shows a zero denominator
    /// against a non-zero numerator while the first page is being fetched
    /// (#3378). The estimate itself survives in `config.assessment`, which is
    /// what `GET /assessment` reads.
    pub async fn save_assessment(
        &self,
        job_id: Uuid,
        result: &AssessmentResult,
    ) -> Result<(), MigrationError> {
        let summary =
            serde_json::to_value(result).map_err(|e| MigrationError::Other(e.to_string()))?;

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

    // -----------------------------------------------------------------------
    // Nexus `group` → AK `virtual` member correlation (issue #2783)
    // -----------------------------------------------------------------------

    /// DB-backed proof for #2783: a migrated Nexus `group` repo's member names
    /// are correlated to the migrated AK repositories, written in source order,
    /// with genuinely-absent members skipped (never left dangling).
    ///
    /// Fails-before: prior to the fix nothing ever populated
    /// `virtual_repo_members` during migration, so the query below returned an
    /// empty set for every migrated virtual repo. Passes-after: the members are
    /// correlated and persisted with order preserved.
    ///
    /// No-ops when `DATABASE_URL` is unset so it skips cleanly off-CI.
    #[tokio::test]
    async fn test_group_members_correlate_to_migrated_repos_2783() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        async fn insert_repo(pool: &PgPool, key: &str, repo_type: &str) -> Uuid {
            let row: (Uuid,) = sqlx::query_as(
                r#"
                INSERT INTO repositories
                    (key, name, format, repo_type, storage_path, storage_backend)
                VALUES ($1, $1, 'generic'::repository_format, $2::repository_type, $1, 'filesystem')
                RETURNING id
                "#,
            )
            .bind(key)
            .bind(repo_type)
            .fetch_one(pool)
            .await
            .expect("insert repo");
            row.0
        }

        let svc = MigrationService::new(pool.clone());
        let sfx = uuid::Uuid::new_v4().simple().to_string();
        let vkey = format!("grp-{sfx}");
        let m1 = format!("m1-{sfx}");
        let m2 = format!("m2-{sfx}");
        let m3_absent = format!("m3-{sfx}"); // referenced but never migrated

        let vid = insert_repo(&pool, &vkey, "virtual").await;
        let id1 = insert_repo(&pool, &m1, "local").await;
        let id2 = insert_repo(&pool, &m2, "local").await;

        // Source group lists members in the order [m2, m1, m3]; m3 was not
        // migrated. Ordering must be preserved and m3 must be skipped.
        let outcome = svc
            .correlate_virtual_repo_members(&vkey, &[m2.clone(), m1.clone(), m3_absent.clone()])
            .await
            .expect("correlate members");

        assert_eq!(outcome.virtual_id, vid);
        assert_eq!(outcome.correlated, 2, "two members migrated + correlated");
        assert_eq!(
            outcome.skipped,
            vec![m3_absent.clone()],
            "the un-migrated member is reported as skipped, not written"
        );

        // Persisted membership: exactly the two resolvable members, in source
        // order (m2 before m1), with no dangling references.
        let rows: Vec<(Uuid, i32)> = sqlx::query_as(
            "SELECT member_repo_id, priority FROM virtual_repo_members \
             WHERE virtual_repo_id = $1 ORDER BY priority",
        )
        .bind(vid)
        .fetch_all(&pool)
        .await
        .expect("read members");
        assert_eq!(
            rows.iter().map(|r| r.0).collect::<Vec<_>>(),
            vec![id2, id1],
            "members correlate to migrated AK repos in source order"
        );

        // Every persisted member points at a real repository (no dangling).
        let dangling: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM virtual_repo_members vrm \
             LEFT JOIN repositories r ON r.id = vrm.member_repo_id \
             WHERE vrm.virtual_repo_id = $1 AND r.id IS NULL",
        )
        .bind(vid)
        .fetch_one(&pool)
        .await
        .expect("dangling check");
        assert_eq!(dangling.0, 0, "no dangling member references");

        // Re-running reconciles (idempotent) rather than duplicating.
        let outcome2 = svc
            .correlate_virtual_repo_members(&vkey, std::slice::from_ref(&m1))
            .await
            .expect("re-correlate");
        assert_eq!(outcome2.correlated, 1);
        let rows2: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT member_repo_id FROM virtual_repo_members WHERE virtual_repo_id = $1",
        )
        .bind(vid)
        .fetch_all(&pool)
        .await
        .expect("read members after reconcile");
        assert_eq!(
            rows2,
            vec![(id1,)],
            "membership reconciled to exactly {{m1}}"
        );

        for id in [vid, id1, id2] {
            sqlx::query("DELETE FROM repositories WHERE id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .ok();
        }
    }

    // -----------------------------------------------------------------------
    // Remote/proxy upstream_url persistence on create_repository (issue #2822)
    // -----------------------------------------------------------------------

    /// DB-backed proof for #2822: `create_repository` persists a remote repo's
    /// `upstream_url` (satisfying the `check_upstream_url` constraint), rejects a
    /// remote repo with no upstream via a clear `ConfigError` (NOT a raw SQLSTATE
    /// 23514), and still accepts a Local repo with a NULL `upstream_url`.
    ///
    /// Fails-before: prior to the fix the INSERT omitted `upstream_url`, so every
    /// remote repo hit the constraint and was skipped.
    ///
    /// No-ops when `DATABASE_URL` is unset so it skips cleanly off-CI.
    #[tokio::test]
    async fn test_create_repository_persists_remote_upstream_url_2822() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let svc = MigrationService::new(pool.clone());
        let sfx = uuid::Uuid::new_v4().simple().to_string();

        // Remote repo WITH an upstream URL: created, and the row carries it.
        let rkey = format!("remote-{sfx}");
        let cfg = RepositoryMigrationConfig {
            source_key: rkey.clone(),
            target_key: rkey.clone(),
            repo_type: RepositoryType::Remote,
            package_type: "maven".to_string(),
            description: None,
            format_compatibility: FormatCompatibility::Full,
            upstream_url: Some("https://repo1.maven.org/maven2/".to_string()),
            members: vec![],
        };
        let id = svc
            .create_repository(&cfg, "/staging", "filesystem")
            .await
            .expect("remote repo with upstream_url should be created");
        let row: (Option<String>,) =
            sqlx::query_as("SELECT upstream_url FROM repositories WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("read upstream_url");
        assert_eq!(row.0, Some("https://repo1.maven.org/maven2/".to_string()));

        // Remote repo WITHOUT an upstream URL: a clear ConfigError, not a 23514.
        let rkey_bad = format!("remote-bad-{sfx}");
        let cfg_bad = RepositoryMigrationConfig {
            source_key: rkey_bad.clone(),
            target_key: rkey_bad.clone(),
            repo_type: RepositoryType::Remote,
            package_type: "maven".to_string(),
            description: None,
            format_compatibility: FormatCompatibility::Full,
            upstream_url: None,
            members: vec![],
        };
        let err = svc
            .create_repository(&cfg_bad, "/staging", "filesystem")
            .await
            .expect_err("remote repo without upstream_url must be rejected");
        match err {
            MigrationError::ConfigError(msg) => {
                assert!(msg.contains(&rkey_bad), "error names the repo: {msg}");
                assert!(
                    msg.contains("upstream URL"),
                    "error explains the cause: {msg}"
                );
            }
            other => panic!("expected ConfigError, got {other:?}"),
        }
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM repositories WHERE key = $1")
            .bind(&rkey_bad)
            .fetch_one(&pool)
            .await
            .expect("count bad repo");
        assert_eq!(count.0, 0, "rejected remote repo is not persisted");

        // A Local repo with a NULL upstream_url remains constraint-legal.
        let lkey = format!("local-{sfx}");
        let cfg_local = RepositoryMigrationConfig {
            source_key: lkey.clone(),
            target_key: lkey.clone(),
            repo_type: RepositoryType::Local,
            package_type: "maven".to_string(),
            description: None,
            format_compatibility: FormatCompatibility::Full,
            upstream_url: None,
            members: vec![],
        };
        let lid = svc
            .create_repository(&cfg_local, "/staging", "filesystem")
            .await
            .expect("local repo with NULL upstream_url should be created");

        for id in [id, lid] {
            sqlx::query("DELETE FROM repositories WHERE id = $1")
                .bind(id)
                .execute(&pool)
                .await
                .ok();
        }
    }

    // -----------------------------------------------------------------------
    // Guarded finalize: paused/cancelled must never be overwritten by a
    // terminal status (issue #3380)
    // -----------------------------------------------------------------------

    /// DB-backed proof for the #3380 finalize guard: `finalize_job_status`
    /// must skip a job the operator paused or cancelled (the pause raced the
    /// worker's final write), while a running job still finalizes with its
    /// terminal status and a `finished_at`.
    ///
    /// No-ops when `DATABASE_URL` is unset so it skips cleanly off-CI.
    #[tokio::test]
    async fn test_finalize_job_status_skips_paused_and_cancelled_3380() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        async fn seed_job(pool: &PgPool, conn_id: Uuid, status: &str) -> Uuid {
            sqlx::query_scalar(
                "INSERT INTO migration_jobs (source_connection_id, job_type, config, status) \
                 VALUES ($1, 'full', $2, $3) RETURNING id",
            )
            .bind(conn_id)
            .bind(serde_json::json!({}))
            .bind(status)
            .fetch_one(pool)
            .await
            .expect("seed migration job")
        }

        let conn_id: Uuid = sqlx::query_scalar(
            "INSERT INTO source_connections (name, url, auth_type, credentials_enc, source_type) \
             VALUES ($1, 'http://source.local', 'basic_auth', $2, 'nexus') RETURNING id",
        )
        .bind(format!("finalize-conn-{}", Uuid::new_v4()))
        .bind(vec![1u8, 2, 3])
        .fetch_one(&pool)
        .await
        .expect("seed source connection");

        let svc = MigrationService::new(pool.clone());
        let paused = seed_job(&pool, conn_id, "paused").await;
        let cancelled = seed_job(&pool, conn_id, "cancelled").await;
        let running = seed_job(&pool, conn_id, "running").await;

        for (job_id, expected) in [(paused, "paused"), (cancelled, "cancelled")] {
            let finalized = svc
                .finalize_job_status(job_id, MigrationJobStatus::Completed)
                .await
                .expect("finalize");
            assert!(!finalized, "{expected} job must not be finalized");
            let (status, finished): (String, bool) = sqlx::query_as(
                "SELECT status, finished_at IS NOT NULL FROM migration_jobs WHERE id = $1",
            )
            .bind(job_id)
            .fetch_one(&pool)
            .await
            .expect("read job row");
            assert_eq!(status, expected, "operator-set status must survive");
            assert!(!finished, "a skipped finalize must not stamp finished_at");
        }

        let finalized = svc
            .finalize_job_status(running, MigrationJobStatus::Completed)
            .await
            .expect("finalize running job");
        assert!(finalized, "a running job still finalizes");
        let (status, finished): (String, bool) = sqlx::query_as(
            "SELECT status, finished_at IS NOT NULL FROM migration_jobs WHERE id = $1",
        )
        .bind(running)
        .fetch_one(&pool)
        .await
        .expect("read finalized job row");
        assert_eq!(status, "completed");
        assert!(finished, "finalize must stamp finished_at");

        for job_id in [paused, cancelled, running] {
            sqlx::query("DELETE FROM migration_jobs WHERE id = $1")
                .bind(job_id)
                .execute(&pool)
                .await
                .ok();
        }
        sqlx::query("DELETE FROM source_connections WHERE id = $1")
            .bind(conn_id)
            .execute(&pool)
            .await
            .ok();
    }

    // -----------------------------------------------------------------------
    // A partial success must be STORABLE, not just computable (issue #3497)
    // -----------------------------------------------------------------------

    /// DB-backed proof for #3497.
    ///
    /// `determine_final_status(failed > 0, completed > 0)` returns
    /// `CompletedWithErrors`, which `Display`s as `completed_with_errors`.
    /// Migration 020's CHECK constraint on `migration_jobs.status` never listed
    /// that value and was never altered, so `finalize_job_status` came back with
    /// a check-constraint violation for every mixed-outcome job; `process_job`
    /// propagated it and the spawn wrapper in `api/handlers/migration.rs`
    /// stamped the job `failed` with the raw Postgres text in `error_summary` —
    /// a total failure reported for a run most of whose artifacts transferred.
    /// Migration 207 adds the value to the constraint.
    ///
    /// This test goes through the database on purpose. `migration_worker` has
    /// seven `determine_final_status` tests, two of which assert exactly this
    /// enum; all of them passed for as long as the write was impossible,
    /// because none of them writes. The function was never wrong — the column
    /// was. So the status under test is taken from `determine_final_status`
    /// itself rather than hand-written, and every assertion is on the row that
    /// came back out of Postgres.
    ///
    /// The loop over the whole status set is the negative control: it proves
    /// the constraint still REJECTS an unknown value, so this cannot be
    /// satisfied by simply dropping the constraint.
    ///
    /// No-ops when `DATABASE_URL` is unset so it skips cleanly off-CI.
    #[tokio::test]
    async fn test_finalize_job_status_stores_completed_with_errors_3497() {
        use crate::api::handlers::test_db_helpers as tdh;
        use crate::services::migration_worker::determine_final_status;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let conn_id: Uuid = sqlx::query_scalar(
            "INSERT INTO source_connections (name, url, auth_type, credentials_enc, source_type) \
             VALUES ($1, 'http://source.local', 'basic_auth', $2, 'nexus') RETURNING id",
        )
        .bind(format!("partial-conn-{}", Uuid::new_v4()))
        .bind(vec![1u8, 2, 3])
        .fetch_one(&pool)
        .await
        .expect("seed source connection");

        let job_id: Uuid = sqlx::query_scalar(
            "INSERT INTO migration_jobs (source_connection_id, job_type, config, status, \
             completed_items, failed_items) \
             VALUES ($1, 'full', '{}'::jsonb, 'running', 47, 3) RETURNING id",
        )
        .bind(conn_id)
        .fetch_one(&pool)
        .await
        .expect("seed migration job");

        // 47 transferred, 3 failed: the mixed outcome the worker reports.
        let final_status = determine_final_status(3, 47);
        assert_eq!(
            final_status,
            MigrationJobStatus::CompletedWithErrors,
            "a mixed outcome must resolve to CompletedWithErrors"
        );

        let svc = MigrationService::new(pool.clone());
        let finalized = svc
            .finalize_job_status(job_id, final_status)
            .await
            .expect("a partially-successful job must be storable, not a constraint violation");
        assert!(finalized, "a running job finalizes");

        let (status, finished, completed_items, failed_items): (String, bool, i32, i32) =
            sqlx::query_as(
                "SELECT status, finished_at IS NOT NULL, completed_items, failed_items \
                 FROM migration_jobs WHERE id = $1",
            )
            .bind(job_id)
            .fetch_one(&pool)
            .await
            .expect("read finalized job row");
        assert_eq!(
            status, "completed_with_errors",
            "the partial success must be recorded as itself, not collapsed into failed"
        );
        assert!(finished, "finalize must stamp finished_at");
        assert_eq!(
            (completed_items, failed_items),
            (47, 3),
            "the per-item counters that explain the partial outcome must survive"
        );

        // The constraint must still accept every status the model can produce
        // and still reject anything else — a fix that just dropped the CHECK
        // would satisfy the assertions above.
        for accepted in [
            MigrationJobStatus::Pending,
            MigrationJobStatus::Assessing,
            MigrationJobStatus::Ready,
            MigrationJobStatus::Running,
            MigrationJobStatus::Paused,
            MigrationJobStatus::Completed,
            MigrationJobStatus::CompletedWithErrors,
            MigrationJobStatus::Failed,
            MigrationJobStatus::Cancelled,
        ] {
            sqlx::query("UPDATE migration_jobs SET status = $1 WHERE id = $2")
                .bind(accepted.to_string())
                .bind(job_id)
                .execute(&pool)
                .await
                .unwrap_or_else(|e| panic!("status '{accepted}' must be storable: {e}"));
        }

        let rejected = sqlx::query("UPDATE migration_jobs SET status = $1 WHERE id = $2")
            .bind("definitely_not_a_status")
            .bind(job_id)
            .execute(&pool)
            .await;
        assert!(
            rejected.is_err(),
            "the status CHECK must still reject a value outside the model's set"
        );

        sqlx::query("DELETE FROM migration_jobs WHERE id = $1")
            .bind(job_id)
            .execute(&pool)
            .await
            .ok();
        sqlx::query("DELETE FROM source_connections WHERE id = $1")
            .bind(conn_id)
            .execute(&pool)
            .await
            .ok();
    }

    // -----------------------------------------------------------------------
    // storage_path convention for auto-provisioned repos (#2336, #2025)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_storage_path_filesystem_is_absolute() {
        // Filesystem repos must root under the staging base so writes land on
        // the mounted volume (regression for #2025).
        assert_eq!(
            MigrationService::build_storage_path("filesystem", "/data/storage", "libs-local"),
            "/data/storage/libs-local"
        );
    }

    #[test]
    fn test_build_storage_path_cloud_uses_bare_key() {
        // Cloud backends address objects by the bare repo key, matching the
        // HTTP create-repo handler. Prefixing a local staging path would be
        // wrong for object storage (#2336).
        for backend in ["s3", "gcs", "azure"] {
            assert_eq!(
                MigrationService::build_storage_path(backend, "/data/storage", "libs-local"),
                "libs-local",
                "backend {backend} should use the bare key"
            );
        }
    }

    #[test]
    fn test_build_storage_path_contract() {
        // Only "filesystem" gets the absolute staging prefix; every other
        // backend name — including unknown ones — is treated as object storage
        // and addressed by the bare repo key. This mirrors the create-repo
        // handler and guards against a newly added cloud backend silently
        // inheriting the filesystem path convention (#2336).
        let base = "/srv/ak/storage";

        // Filesystem: absolute prefix, and nested keys are preserved verbatim.
        assert_eq!(
            MigrationService::build_storage_path("filesystem", base, "libs-release"),
            "/srv/ak/storage/libs-release"
        );
        assert_eq!(
            MigrationService::build_storage_path("filesystem", base, "team/libs"),
            "/srv/ak/storage/team/libs"
        );

        // Object stores ignore the base entirely and use the bare key, even a
        // backend name the helper has never seen before.
        assert_eq!(
            MigrationService::build_storage_path("minio", base, "libs-release"),
            "libs-release"
        );

        // Backend matching is exact and case-sensitive: "Filesystem" is NOT the
        // filesystem backend, so it must not receive the staging prefix.
        assert_eq!(
            MigrationService::build_storage_path("Filesystem", base, "libs-release"),
            "libs-release"
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
        assert!(MigrationService::matches_pattern("anything", &[]));
    }

    // -----------------------------------------------------------------------
    // Format compatibility - exhaustive coverage
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_compatibility_all_full() {
        let full_formats = [
            "maven", "npm", "docker", "pypi", "helm", "nuget", "cargo", "go", "generic",
        ];
        for fmt in &full_formats {
            assert_eq!(
                MigrationService::get_format_compatibility(fmt),
                FormatCompatibility::Full,
                "Expected Full for '{}'",
                fmt
            );
        }
    }

    #[test]
    fn test_format_compatibility_all_partial() {
        let partial_formats = ["conan", "conda", "debian", "rpm"];
        for fmt in &partial_formats {
            assert_eq!(
                MigrationService::get_format_compatibility(fmt),
                FormatCompatibility::Partial,
                "Expected Partial for '{}'",
                fmt
            );
        }
    }

    #[test]
    fn test_format_compatibility_unsupported() {
        // `yum` is now normalized to `rpm` (Partial) and `raw` to `generic`
        // (Full), so those are no longer in the unsupported list. See
        // test_format_compatibility_nexus_aliases.
        let unsupported = ["bower", "gitlfs", "p2", "vagrant", ""];
        for fmt in &unsupported {
            assert_eq!(
                MigrationService::get_format_compatibility(fmt),
                FormatCompatibility::Unsupported,
                "Expected Unsupported for '{}'",
                fmt
            );
        }
    }

    // -----------------------------------------------------------------------
    // Source-specific format name normalization (issue #857)
    // -----------------------------------------------------------------------

    #[test]
    fn test_normalize_package_type_nexus_aliases() {
        // Nexus uses `maven2` for its Maven repository format.
        assert_eq!(MigrationService::normalize_package_type("maven2"), "maven");
        assert_eq!(MigrationService::normalize_package_type("MAVEN2"), "maven");

        // Nexus uses `raw` for its unstructured binary format.
        assert_eq!(MigrationService::normalize_package_type("raw"), "generic");
        assert_eq!(MigrationService::normalize_package_type("RAW"), "generic");

        // Nexus uses `yum`; Artifact Keeper's equivalent is `rpm`.
        assert_eq!(MigrationService::normalize_package_type("yum"), "rpm");
        assert_eq!(MigrationService::normalize_package_type("Yum"), "rpm");

        // Some sources report RubyGems as `gems`.
        assert_eq!(MigrationService::normalize_package_type("gems"), "rubygems");
    }

    #[test]
    fn test_normalize_package_type_passthrough() {
        // Known canonical names pass through unchanged (lowercased).
        assert_eq!(MigrationService::normalize_package_type("maven"), "maven");
        assert_eq!(MigrationService::normalize_package_type("npm"), "npm");
        assert_eq!(MigrationService::normalize_package_type("Docker"), "docker");
        // Unknown formats are also returned lowercased (but remain unsupported).
        assert_eq!(MigrationService::normalize_package_type("bower"), "bower");
    }

    #[test]
    fn test_format_compatibility_nexus_aliases() {
        // Regression test for issue #857: Nexus-specific format names used
        // to be reported as unsupported. They must now map correctly.

        // Maven 2 repositories in Nexus are fully supported.
        assert_eq!(
            MigrationService::get_format_compatibility("maven2"),
            FormatCompatibility::Full
        );

        // Raw repositories map to AK's generic format (fully supported).
        assert_eq!(
            MigrationService::get_format_compatibility("raw"),
            FormatCompatibility::Full
        );

        // Yum repositories map to AK's rpm format (partial support).
        assert_eq!(
            MigrationService::get_format_compatibility("yum"),
            FormatCompatibility::Partial
        );

        // #2784: Nexus `apt` repositories map to AK's `debian` (partial
        // support, migrated as generic). Before the mapping, `apt`
        // normalized to the unknown name `apt` and was classified
        // Unsupported, so the whole repository failed to migrate.
        assert_eq!(MigrationService::normalize_package_type("apt"), "debian");
        assert_eq!(
            MigrationService::get_format_compatibility("apt"),
            FormatCompatibility::Partial
        );

        // #2784: `golang` is an alias for AK's `go` (full support).
        assert_eq!(MigrationService::normalize_package_type("golang"), "go");
        assert_eq!(
            MigrationService::get_format_compatibility("golang"),
            FormatCompatibility::Full
        );
        // `go` itself is already the canonical, fully-supported name.
        assert_eq!(
            MigrationService::get_format_compatibility("go"),
            FormatCompatibility::Full
        );
    }

    #[test]
    fn test_prepare_repository_migration_normalizes_nexus_apt() {
        // #2784: a Nexus `apt` repository must prepare as `debian` with
        // Partial compatibility so it migrates (as generic) instead of being
        // rejected as an unsupported format.
        let repo = RepositoryListItem {
            key: "apt-hosted".to_string(),
            repo_type: "hosted".to_string(),
            package_type: "apt".to_string(),
            url: None,
            description: None,
            members: vec![],
            upstream_url: None,
        };
        let config = MigrationService::prepare_repository_migration(&repo, None).unwrap();
        assert_eq!(config.package_type, "debian");
        assert_eq!(config.format_compatibility, FormatCompatibility::Partial);
    }

    #[test]
    fn test_prepare_repository_migration_normalizes_nexus_maven2() {
        // Regression test for issue #857: when Nexus reports `maven2`, the
        // prepared config should carry the canonical `maven` name so the
        // created repository uses the correct AK format.
        //
        // `repo_type` here is the real Nexus vocabulary (`hosted`) — not the
        // Artifactory `local`. Prior fixtures used `local` and so masked
        // issue #1889, where `RepositoryType::from_artifactory` rejected
        // every Nexus repo on a live source.
        let repo = RepositoryListItem {
            key: "releases".to_string(),
            repo_type: "hosted".to_string(),
            package_type: "maven2".to_string(),
            url: None,
            description: None,
            members: vec![],
            upstream_url: None,
        };
        let config = MigrationService::prepare_repository_migration(&repo, None).unwrap();
        assert_eq!(config.package_type, "maven");
        assert_eq!(config.format_compatibility, FormatCompatibility::Full);
    }

    #[test]
    fn test_prepare_repository_migration_normalizes_nexus_yum() {
        let repo = RepositoryListItem {
            key: "yum".to_string(),
            repo_type: "hosted".to_string(),
            package_type: "yum".to_string(),
            url: None,
            description: None,
            members: vec![],
            upstream_url: None,
        };
        let config = MigrationService::prepare_repository_migration(&repo, None).unwrap();
        assert_eq!(config.package_type, "rpm");
        assert_eq!(config.format_compatibility, FormatCompatibility::Partial);
    }

    #[test]
    fn test_prepare_repository_migration_normalizes_nexus_raw() {
        let repo = RepositoryListItem {
            key: "resources".to_string(),
            repo_type: "hosted".to_string(),
            package_type: "raw".to_string(),
            url: None,
            description: None,
            members: vec![],
            upstream_url: None,
        };
        let config = MigrationService::prepare_repository_migration(&repo, None).unwrap();
        assert_eq!(config.package_type, "generic");
        assert_eq!(config.format_compatibility, FormatCompatibility::Full);
    }

    #[test]
    fn test_prepare_repository_migration_accepts_nexus_proxy() {
        // Nexus `proxy` ≡ Artifactory `remote`; both must map to
        // `RepositoryType::Remote` (issue #1889 regression).
        let repo = RepositoryListItem {
            key: "maven-central".to_string(),
            repo_type: "proxy".to_string(),
            package_type: "maven2".to_string(),
            url: Some("https://repo1.maven.org/maven2/".to_string()),
            description: None,
            members: vec![],
            upstream_url: None,
        };
        let config = MigrationService::prepare_repository_migration(&repo, None).unwrap();
        assert_eq!(config.repo_type, RepositoryType::Remote);
        assert_eq!(config.package_type, "maven");
    }

    #[test]
    fn test_prepare_repository_migration_threads_upstream_url_2822() {
        // A remote/proxy source repo's `upstream_url` must be threaded into the
        // migration config so `create_repository` can persist it and satisfy the
        // `check_upstream_url` constraint (issue #2822). Previously the field was
        // hard-coded to `None`, so every remote repo was skipped.
        let repo = RepositoryListItem {
            key: "docker-proxy".to_string(),
            repo_type: "proxy".to_string(),
            package_type: "docker".to_string(),
            url: Some("https://nexus.example.com/repository/docker-proxy/".to_string()),
            description: None,
            members: vec![],
            upstream_url: Some("https://registry-1.docker.io/".to_string()),
        };
        let config = MigrationService::prepare_repository_migration(&repo, None).unwrap();
        assert_eq!(config.repo_type, RepositoryType::Remote);
        assert_eq!(
            config.upstream_url,
            Some("https://registry-1.docker.io/".to_string()),
        );
    }

    #[test]
    fn test_prepare_repository_migration_accepts_nexus_group() {
        // Nexus `group` ≡ Artifactory `virtual`; both must map to
        // `RepositoryType::Virtual` (issue #1889 regression).
        let repo = RepositoryListItem {
            key: "maven-public".to_string(),
            repo_type: "group".to_string(),
            package_type: "maven2".to_string(),
            url: None,
            description: None,
            members: vec!["maven-releases".to_string(), "maven-central".to_string()],
            upstream_url: None,
        };
        let config = MigrationService::prepare_repository_migration(&repo, None).unwrap();
        assert_eq!(config.repo_type, RepositoryType::Virtual);
        // Nexus `group` member names must survive into the migration config so
        // they can be correlated to migrated AK repos later (issue #2783).
        assert_eq!(
            config.members,
            vec!["maven-releases".to_string(), "maven-central".to_string()],
        );
        assert_eq!(config.package_type, "maven");
    }

    #[test]
    fn test_format_compatibility_case_insensitive() {
        assert_eq!(
            MigrationService::get_format_compatibility("Maven"),
            FormatCompatibility::Full
        );
        assert_eq!(
            MigrationService::get_format_compatibility("NPM"),
            FormatCompatibility::Full
        );
        assert_eq!(
            MigrationService::get_format_compatibility("DOCKER"),
            FormatCompatibility::Full
        );
        assert_eq!(
            MigrationService::get_format_compatibility("CONAN"),
            FormatCompatibility::Partial
        );
        assert_eq!(
            MigrationService::get_format_compatibility("RPM"),
            FormatCompatibility::Partial
        );
    }

    // -----------------------------------------------------------------------
    // Permission mapping - exhaustive coverage
    // -----------------------------------------------------------------------

    #[test]
    fn test_permission_mapping_all_mapped() {
        assert_eq!(MigrationService::map_permission("read"), Some("read"));
        assert_eq!(MigrationService::map_permission("annotate"), Some("read"));
        assert_eq!(MigrationService::map_permission("deploy"), Some("write"));
        assert_eq!(MigrationService::map_permission("delete"), Some("delete"));
        assert_eq!(MigrationService::map_permission("admin"), Some("admin"));
    }

    #[test]
    fn test_permission_mapping_unsupported() {
        assert_eq!(MigrationService::map_permission("managedxraymeta"), None);
        assert_eq!(MigrationService::map_permission("distribute"), None);
    }

    #[test]
    fn test_permission_mapping_unknown() {
        assert_eq!(MigrationService::map_permission("execute"), None);
        assert_eq!(MigrationService::map_permission(""), None);
        assert_eq!(MigrationService::map_permission("superadmin"), None);
    }

    #[test]
    fn test_permission_mapping_case_insensitive() {
        assert_eq!(MigrationService::map_permission("READ"), Some("read"));
        assert_eq!(MigrationService::map_permission("Deploy"), Some("write"));
        assert_eq!(MigrationService::map_permission("ADMIN"), Some("admin"));
        assert_eq!(MigrationService::map_permission("Annotate"), Some("read"));
    }

    // -----------------------------------------------------------------------
    // RepositoryType conversions
    // -----------------------------------------------------------------------

    #[test]
    fn test_repository_type_from_artifactory() {
        assert_eq!(
            RepositoryType::from_artifactory("local"),
            Some(RepositoryType::Local)
        );
        assert_eq!(
            RepositoryType::from_artifactory("remote"),
            Some(RepositoryType::Remote)
        );
        assert_eq!(
            RepositoryType::from_artifactory("virtual"),
            Some(RepositoryType::Virtual)
        );
        assert_eq!(
            RepositoryType::from_artifactory("federated"),
            Some(RepositoryType::Local)
        );
    }

    #[test]
    fn test_repository_type_from_artifactory_case_insensitive() {
        assert_eq!(
            RepositoryType::from_artifactory("LOCAL"),
            Some(RepositoryType::Local)
        );
        assert_eq!(
            RepositoryType::from_artifactory("Remote"),
            Some(RepositoryType::Remote)
        );
        assert_eq!(
            RepositoryType::from_artifactory("VIRTUAL"),
            Some(RepositoryType::Virtual)
        );
    }

    #[test]
    fn test_repository_type_from_artifactory_unknown() {
        // `hosted` used to live here too — see #1889; it is Nexus's name
        // for `Local` and is now accepted via the alias branch. `federated`
        // maps to `Local` because federated repos store artifacts locally.
        assert_eq!(RepositoryType::from_artifactory(""), None);
        assert_eq!(RepositoryType::from_artifactory("unknown_kind"), None);
    }

    #[test]
    fn test_repository_type_from_artifactory_accepts_nexus_aliases() {
        // Nexus reports `hosted` / `proxy` / `group`; these are the same
        // three kinds as Artifactory's `local` / `remote` / `virtual` and
        // must map to the same `RepositoryType` variants. Regression
        // coverage for issue #1889.
        assert_eq!(
            RepositoryType::from_artifactory("hosted"),
            Some(RepositoryType::Local)
        );
        assert_eq!(
            RepositoryType::from_artifactory("proxy"),
            Some(RepositoryType::Remote)
        );
        assert_eq!(
            RepositoryType::from_artifactory("group"),
            Some(RepositoryType::Virtual)
        );
        // Case-insensitive across the Nexus vocabulary as well.
        assert_eq!(
            RepositoryType::from_artifactory("HOSTED"),
            Some(RepositoryType::Local)
        );
        assert_eq!(
            RepositoryType::from_artifactory("Proxy"),
            Some(RepositoryType::Remote)
        );
        assert_eq!(
            RepositoryType::from_artifactory("GROUP"),
            Some(RepositoryType::Virtual)
        );
    }

    #[test]
    fn test_repository_type_to_artifact_keeper() {
        assert_eq!(RepositoryType::Local.to_artifact_keeper(), "local");
        assert_eq!(RepositoryType::Remote.to_artifact_keeper(), "remote");
        assert_eq!(RepositoryType::Virtual.to_artifact_keeper(), "virtual");
    }

    #[test]
    fn test_repository_type_roundtrip() {
        for rclass in ["local", "remote", "virtual"] {
            let repo_type = RepositoryType::from_artifactory(rclass).unwrap();
            let ak_type = repo_type.to_artifact_keeper();
            // Verify the AK type is valid
            assert!(
                ["local", "remote", "virtual"].contains(&ak_type),
                "Unexpected AK type '{}' for '{}'",
                ak_type,
                rclass
            );
        }
    }

    // -----------------------------------------------------------------------
    // map_repository_type
    // -----------------------------------------------------------------------

    #[test]
    fn test_map_repository_type() {
        assert_eq!(
            MigrationService::map_repository_type("local"),
            Some(RepositoryType::Local)
        );
        assert_eq!(
            MigrationService::map_repository_type("remote"),
            Some(RepositoryType::Remote)
        );
        assert_eq!(
            MigrationService::map_repository_type("virtual"),
            Some(RepositoryType::Virtual)
        );
        assert_eq!(MigrationService::map_repository_type("unknown"), None);
    }

    // -----------------------------------------------------------------------
    // Pattern matching - advanced cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_pattern_matching_multiple_patterns() {
        let patterns = vec!["libs-*".to_string(), "plugins-*".to_string()];
        assert!(MigrationService::matches_pattern("libs-release", &patterns));
        assert!(MigrationService::matches_pattern(
            "plugins-local",
            &patterns
        ));
        assert!(!MigrationService::matches_pattern("ext-repo", &patterns));
    }

    #[test]
    fn test_pattern_matching_exact_match() {
        let patterns = vec!["my-repo".to_string()];
        assert!(MigrationService::matches_pattern("my-repo", &patterns));
        assert!(!MigrationService::matches_pattern("my-repo-2", &patterns));
    }

    #[test]
    fn test_pattern_matching_wildcard_at_start() {
        let patterns = vec!["*-local".to_string()];
        assert!(MigrationService::matches_pattern("libs-local", &patterns));
        assert!(MigrationService::matches_pattern("npm-local", &patterns));
        assert!(!MigrationService::matches_pattern("libs-remote", &patterns));
    }

    #[test]
    fn test_pattern_matching_question_mark_with_wildcard() {
        // Note: ? is only interpreted as regex when pattern also contains *
        let patterns = vec!["lib?-release*".to_string()];
        assert!(MigrationService::matches_pattern("libs-release", &patterns));
        assert!(MigrationService::matches_pattern(
            "libx-release-local",
            &patterns
        ));
        assert!(!MigrationService::matches_pattern(
            "library-release",
            &patterns
        ));
    }

    #[test]
    fn test_pattern_matching_question_mark_without_wildcard() {
        // Without *, the pattern is treated as an exact match
        let patterns = vec!["lib?-release".to_string()];
        // Exact match only, ? is literal
        assert!(!MigrationService::matches_pattern(
            "libs-release",
            &patterns
        ));
        assert!(MigrationService::matches_pattern("lib?-release", &patterns));
    }

    #[test]
    fn test_pattern_matching_dots_in_pattern() {
        let patterns = vec!["com.example.*".to_string()];
        assert!(MigrationService::matches_pattern(
            "com.example.mylib",
            &patterns
        ));
        // Dot should be treated as literal dot (escaped in regex)
        assert!(!MigrationService::matches_pattern(
            "comXexampleXmylib",
            &patterns
        ));
    }

    // -----------------------------------------------------------------------
    // should_exclude_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_should_exclude_path_no_patterns() {
        assert!(!MigrationService::should_exclude_path("some/path", &[]));
    }

    #[test]
    fn test_should_exclude_path_exact_substring() {
        let patterns = vec![".index".to_string()];
        assert!(MigrationService::should_exclude_path(
            "repo/.index/data",
            &patterns
        ));
        assert!(!MigrationService::should_exclude_path(
            "repo/data/file.jar",
            &patterns
        ));
    }

    #[test]
    fn test_should_exclude_path_wildcard_single() {
        let patterns = vec!["*.tmp".to_string()];
        assert!(MigrationService::should_exclude_path("file.tmp", &patterns));
        assert!(!MigrationService::should_exclude_path(
            "file.jar", &patterns
        ));
    }

    #[test]
    fn test_should_exclude_path_double_wildcard_substring_fallback() {
        // Note: ** glob pattern has a bug where .* from ** replacement gets
        // clobbered by the subsequent * -> [^/]* replacement. However,
        // the substring fallback (.git) still works for non-wildcard patterns.
        let patterns = vec![".git".to_string()];
        // Substring match works
        assert!(MigrationService::should_exclude_path(
            "repo/.git/objects/pack",
            &patterns
        ));
    }

    #[test]
    fn test_should_exclude_path_single_wildcard_in_dir() {
        // Single wildcard should NOT match across directory separators in exclude
        let patterns = vec!["*.log".to_string()];
        assert!(MigrationService::should_exclude_path(
            "debug.log",
            &patterns
        ));
        // * maps to [^/]* so it won't match across /
        assert!(!MigrationService::should_exclude_path(
            "dir/debug.log",
            &patterns
        ));
    }

    #[test]
    fn test_should_exclude_path_multiple_patterns() {
        let patterns = vec![
            ".index".to_string(),
            "*.tmp".to_string(),
            "_trash".to_string(),
        ];
        assert!(MigrationService::should_exclude_path(
            "repo/.index/data",
            &patterns
        ));
        assert!(MigrationService::should_exclude_path("temp.tmp", &patterns));
        assert!(MigrationService::should_exclude_path(
            "repo/_trash/old",
            &patterns
        ));
        assert!(!MigrationService::should_exclude_path(
            "repo/good/file.jar",
            &patterns
        ));
    }

    // -----------------------------------------------------------------------
    // sanitize_path
    // -----------------------------------------------------------------------

    #[test]
    fn test_sanitize_path_normal() {
        assert_eq!(
            MigrationService::sanitize_path("com/example/lib/1.0/lib-1.0.jar"),
            "com/example/lib/1.0/lib-1.0.jar"
        );
    }

    #[test]
    fn test_sanitize_path_control_characters() {
        assert_eq!(
            MigrationService::sanitize_path("file\x00name\x01.jar"),
            "file_name_.jar"
        );
    }

    #[test]
    fn test_sanitize_path_windows_forbidden() {
        assert_eq!(
            MigrationService::sanitize_path("file<name>:test|?.jar"),
            "file_name__test__.jar"
        );
    }

    #[test]
    fn test_sanitize_path_backslash_to_forward_slash() {
        assert_eq!(
            MigrationService::sanitize_path("com\\example\\lib.jar"),
            "com/example/lib.jar"
        );
    }

    #[test]
    fn test_sanitize_path_collapse_slashes() {
        assert_eq!(
            MigrationService::sanitize_path("com//example///lib.jar"),
            "com/example/lib.jar"
        );
    }

    #[test]
    fn test_sanitize_path_trailing_slash() {
        assert_eq!(
            MigrationService::sanitize_path("com/example/"),
            "com/example"
        );
    }

    #[test]
    fn test_sanitize_path_leading_slash_removed() {
        // Leading slash is a special case: the collapse logic skips if result is empty
        let result = MigrationService::sanitize_path("/com/example");
        assert_eq!(result, "com/example");
    }

    #[test]
    fn test_sanitize_path_star_replaced() {
        // * is a Windows-forbidden character
        assert_eq!(MigrationService::sanitize_path("file*.jar"), "file_.jar");
    }

    #[test]
    fn test_sanitize_path_empty() {
        assert_eq!(MigrationService::sanitize_path(""), "");
    }

    // -----------------------------------------------------------------------
    // sanitize_repo_key
    // -----------------------------------------------------------------------

    #[test]
    fn test_sanitize_repo_key_normal() {
        assert_eq!(
            MigrationService::sanitize_repo_key("libs-release-local"),
            "libs-release-local"
        );
    }

    #[test]
    fn test_sanitize_repo_key_spaces_to_dashes() {
        assert_eq!(
            MigrationService::sanitize_repo_key("my repo name"),
            "my-repo-name"
        );
    }

    #[test]
    fn test_sanitize_repo_key_removes_special_chars() {
        assert_eq!(
            MigrationService::sanitize_repo_key("repo@#$%!name"),
            "reponame"
        );
    }

    #[test]
    fn test_sanitize_repo_key_trims_dots_and_dashes() {
        assert_eq!(
            MigrationService::sanitize_repo_key("..repo-name--"),
            "repo-name"
        );
        assert_eq!(MigrationService::sanitize_repo_key("-.-repo-.-"), "repo");
    }

    #[test]
    fn test_sanitize_repo_key_preserves_dots_in_middle() {
        assert_eq!(
            MigrationService::sanitize_repo_key("com.example.repo"),
            "com.example.repo"
        );
    }

    #[test]
    fn test_sanitize_repo_key_allows_underscore() {
        assert_eq!(
            MigrationService::sanitize_repo_key("my_repo_name"),
            "my_repo_name"
        );
    }

    #[test]
    fn test_sanitize_repo_key_empty() {
        assert_eq!(MigrationService::sanitize_repo_key(""), "");
    }

    #[test]
    fn test_sanitize_repo_key_only_special_chars() {
        assert_eq!(MigrationService::sanitize_repo_key("@#$%"), "");
    }

    #[test]
    fn test_sanitize_repo_key_alphanumeric() {
        assert_eq!(
            MigrationService::sanitize_repo_key("MyRepo123"),
            "MyRepo123"
        );
    }

    // -----------------------------------------------------------------------
    // is_path_safe
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_path_safe_normal() {
        assert!(MigrationService::is_path_safe(
            "com/example/lib/1.0/lib.jar"
        ));
    }

    #[test]
    fn test_is_path_safe_relative_path() {
        assert!(MigrationService::is_path_safe("some/relative/path"));
    }

    #[test]
    fn test_is_path_safe_traversal() {
        assert!(!MigrationService::is_path_safe("../etc/passwd"));
        assert!(!MigrationService::is_path_safe("com/../../etc/passwd"));
        assert!(!MigrationService::is_path_safe(".."));
    }

    #[test]
    fn test_is_path_safe_absolute_forward_slash() {
        assert!(!MigrationService::is_path_safe("/etc/passwd"));
    }

    #[test]
    fn test_is_path_safe_absolute_backslash() {
        assert!(!MigrationService::is_path_safe("\\Windows\\System32"));
    }

    #[test]
    fn test_is_path_safe_windows_drive() {
        assert!(!MigrationService::is_path_safe("C:\\Users\\admin"));
        assert!(!MigrationService::is_path_safe("D:data"));
    }

    #[test]
    fn test_is_path_safe_unc_path() {
        assert!(!MigrationService::is_path_safe("\\\\server\\share"));
    }

    #[test]
    fn test_is_path_safe_empty() {
        assert!(MigrationService::is_path_safe(""));
    }

    #[test]
    fn test_is_path_safe_single_dot_ok() {
        // Single dot is not traversal
        assert!(MigrationService::is_path_safe("./file.jar"));
    }

    // -----------------------------------------------------------------------
    // order_repositories_for_migration
    // -----------------------------------------------------------------------

    #[test]
    fn test_order_repositories_local_first() {
        let repos = vec![
            RepositoryMigrationConfig {
                source_key: "virtual-repo".to_string(),
                target_key: "virtual-repo".to_string(),
                repo_type: RepositoryType::Virtual,
                package_type: "maven".to_string(),
                description: None,
                format_compatibility: FormatCompatibility::Full,
                upstream_url: None,
                members: vec![],
            },
            RepositoryMigrationConfig {
                source_key: "local-repo".to_string(),
                target_key: "local-repo".to_string(),
                repo_type: RepositoryType::Local,
                package_type: "maven".to_string(),
                description: None,
                format_compatibility: FormatCompatibility::Full,
                upstream_url: None,
                members: vec![],
            },
            RepositoryMigrationConfig {
                source_key: "remote-repo".to_string(),
                target_key: "remote-repo".to_string(),
                repo_type: RepositoryType::Remote,
                package_type: "maven".to_string(),
                description: None,
                format_compatibility: FormatCompatibility::Full,
                upstream_url: None,
                members: vec![],
            },
        ];

        let ordered = MigrationService::order_repositories_for_migration(repos);
        assert_eq!(ordered.len(), 3);
        assert_eq!(ordered[0].repo_type, RepositoryType::Local);
        assert_eq!(ordered[1].repo_type, RepositoryType::Remote);
        assert_eq!(ordered[2].repo_type, RepositoryType::Virtual);
    }

    #[test]
    fn test_order_repositories_empty() {
        let repos = vec![];
        let ordered = MigrationService::order_repositories_for_migration(repos);
        assert!(ordered.is_empty());
    }

    #[test]
    fn test_order_repositories_only_locals() {
        let repos = vec![
            RepositoryMigrationConfig {
                source_key: "a".to_string(),
                target_key: "a".to_string(),
                repo_type: RepositoryType::Local,
                package_type: "npm".to_string(),
                description: None,
                format_compatibility: FormatCompatibility::Full,
                upstream_url: None,
                members: vec![],
            },
            RepositoryMigrationConfig {
                source_key: "b".to_string(),
                target_key: "b".to_string(),
                repo_type: RepositoryType::Local,
                package_type: "npm".to_string(),
                description: None,
                format_compatibility: FormatCompatibility::Full,
                upstream_url: None,
                members: vec![],
            },
        ];

        let ordered = MigrationService::order_repositories_for_migration(repos);
        assert_eq!(ordered.len(), 2);
        assert_eq!(ordered[0].source_key, "a");
        assert_eq!(ordered[1].source_key, "b");
    }

    // -----------------------------------------------------------------------
    // prepare_repository_migration
    // -----------------------------------------------------------------------

    #[test]
    fn test_prepare_repository_migration_local() {
        use crate::services::artifactory_client::RepositoryListItem;

        let repo = RepositoryListItem {
            key: "libs-release-local".to_string(),
            repo_type: "local".to_string(),
            package_type: "maven".to_string(),
            description: Some("Maven releases".to_string()),
            url: Some("http://artifactory/libs-release-local".to_string()),
            members: vec![],
            upstream_url: None,
        };

        let config = MigrationService::prepare_repository_migration(&repo, None).unwrap();
        assert_eq!(config.source_key, "libs-release-local");
        assert_eq!(config.target_key, "libs-release-local");
        assert_eq!(config.repo_type, RepositoryType::Local);
        assert_eq!(config.package_type, "maven");
        assert_eq!(config.description, Some("Maven releases".to_string()));
        assert_eq!(config.format_compatibility, FormatCompatibility::Full);
        assert!(config.upstream_url.is_none());
        assert!(config.members.is_empty());
    }

    #[test]
    fn test_prepare_repository_migration_partial_format() {
        use crate::services::artifactory_client::RepositoryListItem;

        let repo = RepositoryListItem {
            key: "conan-local".to_string(),
            repo_type: "local".to_string(),
            package_type: "conan".to_string(),
            description: None,
            url: Some("http://artifactory/conan-local".to_string()),
            members: vec![],
            upstream_url: None,
        };

        let config = MigrationService::prepare_repository_migration(&repo, None).unwrap();
        assert_eq!(config.format_compatibility, FormatCompatibility::Partial);
    }

    #[test]
    fn test_prepare_repository_migration_unknown_type() {
        use crate::services::artifactory_client::RepositoryListItem;

        let repo = RepositoryListItem {
            key: "unknown-repo".to_string(),
            repo_type: "unknown_kind".to_string(),
            package_type: "maven".to_string(),
            description: None,
            url: Some("http://artifactory/unknown-repo".to_string()),
            members: vec![],
            upstream_url: None,
        };

        let result = MigrationService::prepare_repository_migration(&repo, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Unknown repository type"));
    }

    // -----------------------------------------------------------------------
    // MigrationError display
    // -----------------------------------------------------------------------

    #[test]
    fn test_migration_error_display() {
        let err = MigrationError::JobNotFound(Uuid::nil());
        assert!(err.to_string().contains("Job not found"));

        let err = MigrationError::InvalidJobState {
            expected: "running".to_string(),
            actual: "completed".to_string(),
        };
        assert!(err.to_string().contains("expected running"));
        assert!(err.to_string().contains("got completed"));

        let err = MigrationError::ConfigError("missing key".to_string());
        assert!(err.to_string().contains("missing key"));

        let err = MigrationError::ChecksumMismatch {
            path: "file.jar".to_string(),
            expected: "abc".to_string(),
            actual: "def".to_string(),
        };
        assert!(err.to_string().contains("file.jar"));
        assert!(err.to_string().contains("abc"));
        assert!(err.to_string().contains("def"));

        let err = MigrationError::StorageError("disk full".to_string());
        assert!(err.to_string().contains("disk full"));

        let err = MigrationError::Other("unknown".to_string());
        assert!(err.to_string().contains("unknown"));
    }

    // -----------------------------------------------------------------------
    // FormatCompatibility and RepositoryType - Debug, Clone, PartialEq
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_compatibility_debug_clone_eq() {
        let full = FormatCompatibility::Full;
        let full_clone = full;
        assert_eq!(full, full_clone);
        assert_ne!(full, FormatCompatibility::Partial);
        let _ = format!("{:?}", full);
    }

    #[test]
    fn test_repository_type_debug_clone_eq() {
        let local = RepositoryType::Local;
        let local_clone = local;
        assert_eq!(local, local_clone);
        assert_ne!(local, RepositoryType::Remote);
        let _ = format!("{:?}", local);
    }

    // -----------------------------------------------------------------------
    // ConflictType and ConflictCheck
    // -----------------------------------------------------------------------

    #[test]
    fn test_conflict_type_variants() {
        let same = ConflictType::SameKey;
        let type_mm = ConflictType::TypeMismatch;
        let format_mm = ConflictType::FormatMismatch;
        assert_ne!(same, type_mm);
        assert_ne!(same, format_mm);
        assert_ne!(type_mm, format_mm);
        let _ = format!("{:?}", same);
    }

    #[test]
    fn test_conflict_check_no_conflict() {
        let check = ConflictCheck {
            has_conflict: false,
            conflict_type: None,
            existing_repo_key: None,
            message: "No conflict".to_string(),
        };
        assert!(!check.has_conflict);
        assert!(check.conflict_type.is_none());
    }

    #[test]
    fn test_conflict_check_with_conflict() {
        let check = ConflictCheck {
            has_conflict: true,
            conflict_type: Some(ConflictType::SameKey),
            existing_repo_key: Some("my-repo".to_string()),
            message: "Repo exists".to_string(),
        };
        assert!(check.has_conflict);
        assert_eq!(check.conflict_type, Some(ConflictType::SameKey));
    }

    // -----------------------------------------------------------------------
    // MigrationItemData construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_migration_item_data_construction() {
        let item = MigrationItemData {
            item_type: MigrationItemType::Artifact,
            source_path: "libs-release/com/example/lib.jar".to_string(),
            size_bytes: 1024,
            checksum: Some("abc123".to_string()),
            metadata: Some(serde_json::json!({"key": "value"})),
        };
        assert_eq!(item.source_path, "libs-release/com/example/lib.jar");
        assert_eq!(item.size_bytes, 1024);
        assert_eq!(item.checksum, Some("abc123".to_string()));
        assert!(item.metadata.is_some());
    }

    #[test]
    fn test_migration_item_data_no_checksum() {
        let item = MigrationItemData {
            item_type: MigrationItemType::User,
            source_path: "user:admin".to_string(),
            size_bytes: 0,
            checksum: None,
            metadata: None,
        };
        assert!(item.checksum.is_none());
        assert!(item.metadata.is_none());
    }

    // -----------------------------------------------------------------------
    // RepositoryAssessment serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_repository_assessment_serialize() {
        let assessment = RepositoryAssessment {
            key: "libs-release".to_string(),
            repo_type: "local".to_string(),
            package_type: "maven".to_string(),
            artifact_count: 100,
            total_size_bytes: 1_000_000,
            compatibility: "full".to_string(),
            warnings: vec!["warning1".to_string()],
        };

        let json = serde_json::to_value(&assessment).unwrap();
        assert_eq!(json["key"], "libs-release");
        assert_eq!(json["artifact_count"], 100);
        assert_eq!(json["warnings"][0], "warning1");
    }

    #[test]
    fn test_assessment_result_serialize() {
        let result = AssessmentResult {
            repositories: vec![],
            total_artifacts: 500,
            total_size_bytes: 5_000_000,
            users_count: 10,
            groups_count: 3,
            permissions_count: 25,
            estimated_duration_seconds: 510,
            warnings: vec!["Could not fetch user list".to_string()],
            blockers: vec![],
        };

        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["total_artifacts"], 500);
        assert_eq!(json["users_count"], 10);
        assert_eq!(json["estimated_duration_seconds"], 510);
        assert!(json["blockers"].as_array().unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // RepositoryMigrationConfig construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_repository_migration_config_clone() {
        let config = RepositoryMigrationConfig {
            source_key: "src".to_string(),
            target_key: "tgt".to_string(),
            repo_type: RepositoryType::Local,
            package_type: "npm".to_string(),
            description: Some("test".to_string()),
            format_compatibility: FormatCompatibility::Full,
            upstream_url: Some("https://upstream.example.com".to_string()),
            members: vec!["member1".to_string(), "member2".to_string()],
        };
        let cloned = config.clone();
        assert_eq!(cloned.source_key, "src");
        assert_eq!(cloned.target_key, "tgt");
        assert_eq!(
            cloned.upstream_url,
            Some("https://upstream.example.com".to_string())
        );
        assert_eq!(cloned.members.len(), 2);
    }

    // -----------------------------------------------------------------------
    // AssessmentResult serialization round-trip (#654)
    // -----------------------------------------------------------------------

    #[test]
    fn test_assessment_result_serialize_deserialize() {
        let result = AssessmentResult {
            repositories: vec![RepositoryAssessment {
                key: "libs-release".to_string(),
                repo_type: "local".to_string(),
                package_type: "maven".to_string(),
                artifact_count: 42,
                total_size_bytes: 1024000,
                compatibility: "full".to_string(),
                warnings: vec![],
            }],
            total_artifacts: 42,
            total_size_bytes: 1024000,
            users_count: 5,
            groups_count: 3,
            permissions_count: 10,
            estimated_duration_seconds: 52,
            warnings: vec!["Some warning".to_string()],
            blockers: vec![],
        };

        let json = serde_json::to_value(&result).unwrap();
        let deserialized: AssessmentResult = serde_json::from_value(json.clone()).unwrap();

        assert_eq!(deserialized.total_artifacts, 42);
        assert_eq!(deserialized.users_count, 5);
        assert_eq!(deserialized.repositories.len(), 1);
        assert_eq!(deserialized.repositories[0].key, "libs-release");
        assert_eq!(deserialized.warnings, vec!["Some warning"]);

        // Verify nested under "assessment" key (as save_assessment stores it)
        let config = serde_json::json!({ "assessment": json });
        let extracted: AssessmentResult =
            serde_json::from_value(config["assessment"].clone()).unwrap();
        assert_eq!(extracted.total_artifacts, 42);
    }

    #[test]
    fn test_assessment_result_empty_repositories() {
        let result = AssessmentResult {
            repositories: vec![],
            total_artifacts: 0,
            total_size_bytes: 0,
            users_count: 0,
            groups_count: 0,
            permissions_count: 0,
            estimated_duration_seconds: 0,
            warnings: vec!["User/group/permission counts require source-specific API access and are not included in this assessment".to_string()],
            blockers: vec!["No repositories have supported package types".to_string()],
        };

        let json = serde_json::to_value(&result).unwrap();
        let deserialized: AssessmentResult = serde_json::from_value(json).unwrap();
        assert!(deserialized.repositories.is_empty());
        assert_eq!(deserialized.blockers.len(), 1);
        assert_eq!(deserialized.warnings.len(), 1);
    }

    // -----------------------------------------------------------------------
    // update_job_totals — the same terminal-state guard finalize_job_status has
    // -----------------------------------------------------------------------

    /// A page listing already in flight when the operator stops the job lands
    /// after the row has left `running`. `update_job_totals` never touches
    /// `status`, so it cannot revive a stopped job, but without a guard it
    /// leaves a dead job advertising a denominator covering work it never
    /// processed — `cancelled, 1000/2000, 50%`. `finalize_job_status` has
    /// carried this guard since #3380; the totals write needs the same one.
    ///
    /// Fails-before: the ungated `UPDATE ... WHERE id = $1` writes the totals
    /// to both stopped rows and reports success.
    ///
    /// DB-gated via `try_pool` so it skips cleanly without `DATABASE_URL`.
    #[tokio::test]
    async fn test_update_job_totals_does_not_write_to_a_stopped_job_3378() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };

        let svc = MigrationService::new(pool.clone());

        let conn_id: Uuid = sqlx::query_scalar(
            "INSERT INTO source_connections (name, url, auth_type, credentials_enc, source_type) \
             VALUES ($1, 'http://source.local', 'basic_auth', $2, 'nexus') RETURNING id",
        )
        .bind(format!("totals-guard-conn-{}", Uuid::new_v4()))
        .bind(vec![1u8, 2, 3])
        .fetch_one(&pool)
        .await
        .expect("seed source connection");

        let mut job_ids = Vec::new();
        for status in ["paused", "cancelled", "running"] {
            let job_id: Uuid = sqlx::query_scalar(
                "INSERT INTO migration_jobs (source_connection_id, job_type, config, status) \
                 VALUES ($1, 'full', '{}'::jsonb, $2) RETURNING id",
            )
            .bind(conn_id)
            .bind(status)
            .fetch_one(&pool)
            .await
            .expect("seed migration job");
            job_ids.push((status, job_id));

            let published = svc
                .update_job_totals(job_id, 2000, 20_000, SourceView::Partial)
                .await
                .expect("update_job_totals must not error");

            let (total_items, total_bytes, row_status): (i32, i64, String) = sqlx::query_as(
                "SELECT total_items, total_bytes, status FROM migration_jobs WHERE id = $1",
            )
            .bind(job_id)
            .fetch_one(&pool)
            .await
            .expect("read job row");

            if status == "running" {
                // Positive control: the guard must not block the normal path.
                assert!(published, "a running job's totals must still be published");
                assert_eq!((total_items, total_bytes), (2000, 20_000));
            } else {
                assert!(
                    !published,
                    "{status}: update_job_totals must report that it published nothing"
                );
                assert_eq!(
                    (total_items, total_bytes),
                    (0, 0),
                    "{status}: a stopped job must not be given a denominator it never processed"
                );
            }
            // The write never touches `status` either way.
            assert_eq!(row_status, status);
        }

        for (_, job_id) in job_ids {
            let _ = sqlx::query("DELETE FROM migration_jobs WHERE id = $1")
                .bind(job_id)
                .execute(&pool)
                .await;
        }
        let _ = sqlx::query("DELETE FROM source_connections WHERE id = $1")
            .bind(conn_id)
            .execute(&pool)
            .await;
    }

    // -----------------------------------------------------------------------
    // #3510: a run that has only seen part of the source may advance the job
    // row, never overwrite it
    // -----------------------------------------------------------------------

    /// The six columns both progress readers divide, in the order
    /// [`read_figures`] returns them: `(total_items, total_bytes,
    /// completed_items, failed_items, skipped_items, transferred_bytes)`.
    type Figures = (i32, i64, i32, i32, i32, i64);

    /// Seed a source connection and a `running` migration job carrying the
    /// figures an earlier pass left behind, and return `(conn_id, job_id)`.
    async fn seed_job_with_figures(
        pool: &sqlx::PgPool,
        prefix: &str,
        figures: Figures,
    ) -> (Uuid, Uuid) {
        let (total_items, total_bytes, completed, failed, skipped, transferred) = figures;
        let conn_id: Uuid = sqlx::query_scalar(
            "INSERT INTO source_connections (name, url, auth_type, credentials_enc, source_type) \
             VALUES ($1, 'http://source.local', 'basic_auth', $2, 'nexus') RETURNING id",
        )
        .bind(format!("{prefix}-conn-{}", Uuid::new_v4()))
        .bind(vec![1u8, 2, 3])
        .fetch_one(pool)
        .await
        .expect("seed source connection");

        let job_id: Uuid = sqlx::query_scalar(
            "INSERT INTO migration_jobs \
               (source_connection_id, job_type, config, status, total_items, total_bytes, \
                completed_items, failed_items, skipped_items, transferred_bytes) \
             VALUES ($1, 'full', '{}'::jsonb, 'running', $2, $3, $4, $5, $6, $7) RETURNING id",
        )
        .bind(conn_id)
        .bind(total_items)
        .bind(total_bytes)
        .bind(completed)
        .bind(failed)
        .bind(skipped)
        .bind(transferred)
        .fetch_one(pool)
        .await
        .expect("seed migration job");

        (conn_id, job_id)
    }

    async fn read_figures(pool: &sqlx::PgPool, job_id: Uuid) -> Figures {
        sqlx::query_as(
            "SELECT total_items, total_bytes, completed_items, failed_items, skipped_items, \
                    transferred_bytes FROM migration_jobs WHERE id = $1",
        )
        .bind(job_id)
        .fetch_one(pool)
        .await
        .expect("read job figures")
    }

    async fn drop_job(pool: &sqlx::PgPool, job_id: Uuid, conn_id: Uuid) {
        let _ = sqlx::query("DELETE FROM migration_jobs WHERE id = $1")
            .bind(job_id)
            .execute(pool)
            .await;
        let _ = sqlx::query("DELETE FROM source_connections WHERE id = $1")
            .bind(conn_id)
            .execute(pool)
            .await;
    }

    /// The numerator write is absolute, and the worker's counters restart at
    /// zero on every entry to `process_job`, so a resumed pass that had not
    /// re-classified anything yet published `0/0/0` over a row recording work
    /// an earlier pass really did (#3510). A run that has only seen part of
    /// the source may move the row forward; it may not walk it back.
    ///
    /// Fails-before: the ungated `UPDATE ... WHERE id = $5` writes the smaller
    /// figures and the row loses 5 completed items and 5000 transferred bytes.
    ///
    /// DB-gated via `try_pool` so it skips cleanly without `DATABASE_URL`.
    #[tokio::test]
    async fn test_update_job_progress_partial_view_never_walks_a_job_backwards_3510() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let svc = MigrationService::new(pool.clone());

        let (conn_id, job_id) =
            seed_job_with_figures(&pool, "progress-3510", (100, 10_000, 5, 1, 2, 5_000)).await;

        // A pass that has accounted for less than the row already records.
        let published = svc
            .update_job_progress(job_id, 0, 0, 0, 0, SourceView::Partial)
            .await
            .expect("update_job_progress must not error");
        assert!(
            !published,
            "a partial view describing less work must report that it published nothing"
        );
        assert_eq!(
            read_figures(&pool, job_id).await,
            (100, 10_000, 5, 1, 2, 5_000),
            "a partial view describing less work must leave the row alone"
        );

        // The same pass once it has caught up: 4 + 2 + 3 = 9 >= 5 + 1 + 2.
        let published = svc
            .update_job_progress(job_id, 4, 2, 3, 6_000, SourceView::Partial)
            .await
            .expect("update_job_progress must not error");
        assert!(published, "a partial view that has caught up must publish");
        assert_eq!(
            read_figures(&pool, job_id).await,
            (100, 10_000, 4, 2, 3, 6_000),
            "the three item counters move together once the run has caught up"
        );

        // Bytes never shrink under a partial view even when the item count grows:
        // a resumed pass re-classifies earlier transfers as skips and so carries
        // none of their bytes.
        let published = svc
            .update_job_progress(job_id, 4, 2, 4, 10, SourceView::Partial)
            .await
            .expect("update_job_progress must not error");
        assert!(published);
        assert_eq!(
            read_figures(&pool, job_id).await,
            (100, 10_000, 4, 2, 4, 6_000),
            "transferred_bytes is what `generate_report` reports as moved; a \
             partial view must not shrink it"
        );

        // A run that enumerated the whole source owns the row outright.
        let published = svc
            .update_job_progress(job_id, 1, 0, 0, 12, SourceView::Complete)
            .await
            .expect("update_job_progress must not error");
        assert!(published, "a complete view must always publish");
        assert_eq!(
            read_figures(&pool, job_id).await,
            (100, 10_000, 1, 0, 0, 12),
            "a run that re-listed the whole source replaces the numerator"
        );

        drop_job(&pool, job_id, conn_id).await;
    }

    /// The same rule on the denominator. #3445 made the run rebuild the totals
    /// absolutely, which is right at the end of a run — it is what lets an
    /// assessment's over-estimate be corrected downwards — but mid-run it left
    /// a resumed job that had been stopped after one page advertising one page
    /// of a source it had already measured in full, under a numerator counting
    /// the whole of it (#3510).
    ///
    /// Fails-before: the partial write shrinks the denominator to `(2, 12)`.
    ///
    /// DB-gated via `try_pool` so it skips cleanly without `DATABASE_URL`.
    #[tokio::test]
    async fn test_update_job_totals_partial_view_never_shrinks_the_denominator_3510() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let svc = MigrationService::new(pool.clone());

        let (conn_id, job_id) =
            seed_job_with_figures(&pool, "totals-3510", (1_500, 15_000, 73, 0, 0, 7_300)).await;

        svc.update_job_totals(job_id, 2, 12, SourceView::Partial)
            .await
            .expect("update_job_totals must not error");
        assert_eq!(
            read_figures(&pool, job_id).await,
            (1_500, 15_000, 73, 0, 0, 7_300),
            "a run one page into a source it had already measured must not \
             republish a denominator smaller than the numerator on the row"
        );

        // Still grows in the normal direction.
        svc.update_job_totals(job_id, 2_000, 20_000, SourceView::Partial)
            .await
            .expect("update_job_totals must not error");
        assert_eq!(
            read_figures(&pool, job_id).await,
            (2_000, 20_000, 73, 0, 0, 7_300),
            "a partial view must still advance the denominator"
        );

        // And a finished run still corrects an over-estimate downwards.
        svc.update_job_totals(job_id, 2, 12, SourceView::Complete)
            .await
            .expect("update_job_totals must not error");
        assert_eq!(
            read_figures(&pool, job_id).await,
            (2, 12, 73, 0, 0, 7_300),
            "a run that enumerated the whole source owns the denominator"
        );

        drop_job(&pool, job_id, conn_id).await;
    }

    /// `start_migration` flips the row to `running` and then spawns a detached
    /// task, so an operator cancel can land before the worker wakes. The
    /// worker's own `update_job_status(Running)` is unguarded and used to undo
    /// it, after which `finalize_job_status` saw a `running` row and stamped
    /// the cancelled job `completed` (#3510). Claiming the job under the same
    /// guard the finalize carries closes the window.
    ///
    /// Fails-before: `update_job_status(Running)` reports nothing and rewrites
    /// every row, including the stopped ones.
    ///
    /// DB-gated via `try_pool` so it skips cleanly without `DATABASE_URL`.
    #[tokio::test]
    async fn test_claim_job_running_refuses_a_stopped_job_3510() {
        use crate::api::handlers::test_db_helpers as tdh;

        let Some(pool) = tdh::try_pool().await else {
            return;
        };
        let svc = MigrationService::new(pool.clone());

        for (status, claimable) in [
            ("paused", false),
            ("cancelled", false),
            ("pending", true),
            ("running", true),
        ] {
            let (conn_id, job_id) =
                seed_job_with_figures(&pool, "claim-3510", (0, 0, 0, 0, 0, 0)).await;
            sqlx::query("UPDATE migration_jobs SET status = $1 WHERE id = $2")
                .bind(status)
                .bind(job_id)
                .execute(&pool)
                .await
                .expect("stage job status");

            let claimed = svc
                .claim_job_running(job_id)
                .await
                .expect("claim_job_running must not error");
            assert_eq!(
                claimed, claimable,
                "{status}: claim_job_running reported the wrong outcome"
            );

            let observed: String =
                sqlx::query_scalar("SELECT status FROM migration_jobs WHERE id = $1")
                    .bind(job_id)
                    .fetch_one(&pool)
                    .await
                    .expect("read job status");
            let expected = if claimable { "running" } else { status };
            assert_eq!(
                observed, expected,
                "{status}: the worker must not walk a stopped job back to running"
            );

            drop_job(&pool, job_id, conn_id).await;
        }
    }
}
