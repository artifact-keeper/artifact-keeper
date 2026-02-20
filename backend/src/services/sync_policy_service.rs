//! Sync policy engine service.
//!
//! Declarative policies that automatically resolve which repositories should
//! replicate to which peers. Policies use label selectors, format filters,
//! name patterns, and explicit IDs to match repositories and peers, then
//! upsert the corresponding `peer_repo_subscriptions` rows.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::repo_selector_service::RepoSelectorService;

// ---------------------------------------------------------------------------
// Models
// ---------------------------------------------------------------------------

/// A sync policy that declaratively maps repositories to peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncPolicy {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub repo_selector: serde_json::Value,
    pub peer_selector: serde_json::Value,
    pub replication_mode: String,
    pub priority: i32,
    pub artifact_filter: serde_json::Value,
    pub precedence: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Row type for sqlx::query_as — maps directly to the sync_policies table columns.
#[derive(Debug, Clone, sqlx::FromRow)]
struct SyncPolicyRow {
    id: Uuid,
    name: String,
    description: String,
    enabled: bool,
    repo_selector: serde_json::Value,
    peer_selector: serde_json::Value,
    replication_mode: String,
    priority: i32,
    artifact_filter: serde_json::Value,
    precedence: i32,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<SyncPolicyRow> for SyncPolicy {
    fn from(row: SyncPolicyRow) -> Self {
        SyncPolicy {
            id: row.id,
            name: row.name,
            description: row.description,
            enabled: row.enabled,
            repo_selector: row.repo_selector,
            peer_selector: row.peer_selector,
            replication_mode: row.replication_mode,
            priority: row.priority,
            artifact_filter: row.artifact_filter,
            precedence: row.precedence,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

// Re-export from the shared repo_selector_service for backward compatibility.
pub use crate::services::repo_selector_service::RepoSelector;

/// Peer selector: determines which peers a policy replicates to.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PeerSelector {
    /// If true, match all non-local peer instances.
    #[serde(default)]
    pub all: bool,
    /// Label key-value pairs that must all match (AND semantics).
    #[serde(default)]
    pub match_labels: HashMap<String, String>,
    /// Match peers in a specific region.
    #[serde(default)]
    pub match_region: Option<String>,
    /// Explicit peer instance UUIDs to include.
    #[serde(default)]
    pub match_peers: Vec<Uuid>,
}

/// Artifact filter: optional constraints on which artifacts get synced.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ArtifactFilter {
    /// Only sync artifacts created within the last N days.
    #[serde(default)]
    pub max_age_days: Option<i32>,
    /// Glob patterns for artifact paths to include.
    #[serde(default)]
    pub include_paths: Vec<String>,
    /// Glob patterns for artifact paths to exclude.
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    /// Maximum artifact size in bytes.
    #[serde(default)]
    pub max_size_bytes: Option<i64>,
    /// Tag selectors: all must match (AND semantics).
    /// Key is the tag key, value is the required tag value.
    /// Empty value means "key must exist with any value".
    #[serde(default)]
    pub match_tags: HashMap<String, String>,
}

impl ArtifactFilter {
    /// Check whether an artifact passes this filter.
    ///
    /// Returns `true` if the artifact should be synced (passes all constraints).
    /// An empty/default filter passes everything.
    pub fn matches(
        &self,
        artifact_path: &str,
        artifact_size_bytes: i64,
        artifact_created_at: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        if let Some(max_age) = self.max_age_days {
            let age = chrono::Utc::now() - artifact_created_at;
            if age.num_days() > max_age as i64 {
                return false;
            }
        }

        if let Some(max_size) = self.max_size_bytes {
            if artifact_size_bytes > max_size {
                return false;
            }
        }

        if !self.include_paths.is_empty() {
            let matches_any = self.include_paths.iter().any(|pattern| {
                let sql_pattern = pattern.replace('*', "%");
                sql_like_match(artifact_path, &sql_pattern)
            });
            if !matches_any {
                return false;
            }
        }

        if self.exclude_paths.iter().any(|pattern| {
            let sql_pattern = pattern.replace('*', "%");
            sql_like_match(artifact_path, &sql_pattern)
        }) {
            return false;
        }

        true
    }

    /// Check whether an artifact passes this filter, including tag constraints.
    ///
    /// `artifact_tags` is a slice of (key, value) pairs representing the artifact's labels.
    pub fn matches_with_tags(
        &self,
        artifact_path: &str,
        artifact_size_bytes: i64,
        artifact_created_at: chrono::DateTime<chrono::Utc>,
        artifact_tags: &[(String, String)],
    ) -> bool {
        if !self.matches(artifact_path, artifact_size_bytes, artifact_created_at) {
            return false;
        }

        for (required_key, required_value) in &self.match_tags {
            let tag_match = artifact_tags.iter().any(|(k, v)| {
                k == required_key && (required_value.is_empty() || v == required_value)
            });
            if !tag_match {
                return false;
            }
        }

        true
    }
}

/// Request to create a new sync policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSyncPolicyRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub repo_selector: RepoSelector,
    #[serde(default)]
    pub peer_selector: PeerSelector,
    #[serde(default = "default_replication_mode")]
    pub replication_mode: String,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub artifact_filter: ArtifactFilter,
    #[serde(default = "default_precedence")]
    pub precedence: i32,
}

/// Request to update an existing sync policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSyncPolicyRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub repo_selector: Option<RepoSelector>,
    #[serde(default)]
    pub peer_selector: Option<PeerSelector>,
    #[serde(default)]
    pub replication_mode: Option<String>,
    #[serde(default)]
    pub priority: Option<i32>,
    #[serde(default)]
    pub artifact_filter: Option<ArtifactFilter>,
    #[serde(default)]
    pub precedence: Option<i32>,
}

/// Toggle request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TogglePolicyRequest {
    pub enabled: bool,
}

/// Result of policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationResult {
    pub created: usize,
    pub updated: usize,
    pub removed: usize,
    pub policies_evaluated: usize,
    pub retroactive_tasks_queued: usize,
}

/// Preview result showing what a policy would match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewResult {
    pub matched_repositories: Vec<MatchedRepo>,
    pub matched_peers: Vec<MatchedPeer>,
    pub subscription_count: usize,
}

// Re-export from the shared repo_selector_service.
pub use crate::services::repo_selector_service::MatchedRepo;

/// A matched peer in a preview.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedPeer {
    pub id: Uuid,
    pub name: String,
    pub region: Option<String>,
}

fn default_true() -> bool {
    true
}

fn default_replication_mode() -> String {
    "push".to_string()
}

fn default_precedence() -> i32 {
    100
}

// ---------------------------------------------------------------------------
// Row helpers for query_as
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
struct PeerRow {
    id: Uuid,
    name: String,
    region: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct SubscriptionRow {
    peer_instance_id: Uuid,
    repository_id: Uuid,
    policy_id: Option<Uuid>,
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/// Service for managing sync policies and evaluating them into subscriptions.
pub struct SyncPolicyService {
    db: PgPool,
}

impl SyncPolicyService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Create a new sync policy, then evaluate it.
    pub async fn create_policy(&self, req: CreateSyncPolicyRequest) -> Result<SyncPolicy> {
        if req.name.trim().is_empty() {
            return Err(AppError::Validation(
                "Policy name cannot be empty".to_string(),
            ));
        }

        let repo_selector_json = serde_json::to_value(&req.repo_selector)
            .map_err(|e| AppError::Validation(format!("Invalid repo_selector: {e}")))?;
        let peer_selector_json = serde_json::to_value(&req.peer_selector)
            .map_err(|e| AppError::Validation(format!("Invalid peer_selector: {e}")))?;
        let artifact_filter_json = serde_json::to_value(&req.artifact_filter)
            .map_err(|e| AppError::Validation(format!("Invalid artifact_filter: {e}")))?;

        let row: SyncPolicyRow = sqlx::query_as(
            r#"
            INSERT INTO sync_policies (name, description, enabled, repo_selector, peer_selector,
                                       replication_mode, priority, artifact_filter, precedence)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id, name, description, enabled, repo_selector, peer_selector,
                      replication_mode, priority, artifact_filter, precedence, created_at, updated_at
            "#,
        )
        .bind(&req.name)
        .bind(&req.description)
        .bind(req.enabled)
        .bind(&repo_selector_json)
        .bind(&peer_selector_json)
        .bind(&req.replication_mode)
        .bind(req.priority)
        .bind(&artifact_filter_json)
        .bind(req.precedence)
        .fetch_one(&self.db)
        .await
        .map_err(|e| {
            if e.to_string().contains("duplicate key") {
                AppError::Conflict(format!("Sync policy '{}' already exists", req.name))
            } else {
                AppError::Database(e.to_string())
            }
        })?;

        let policy: SyncPolicy = row.into();

        // Evaluate after creation if enabled
        if policy.enabled {
            let _ = self.evaluate_policies().await;
        }

        Ok(policy)
    }

    /// Get a sync policy by ID.
    pub async fn get_policy(&self, id: Uuid) -> Result<SyncPolicy> {
        let row: SyncPolicyRow = sqlx::query_as(
            r#"
            SELECT id, name, description, enabled, repo_selector, peer_selector,
                   replication_mode, priority, artifact_filter, precedence, created_at, updated_at
            FROM sync_policies
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("Sync policy {id} not found")))?;

        Ok(row.into())
    }

    /// List all sync policies ordered by precedence.
    pub async fn list_policies(&self) -> Result<Vec<SyncPolicy>> {
        let rows: Vec<SyncPolicyRow> = sqlx::query_as(
            r#"
            SELECT id, name, description, enabled, repo_selector, peer_selector,
                   replication_mode, priority, artifact_filter, precedence, created_at, updated_at
            FROM sync_policies
            ORDER BY precedence ASC, created_at ASC
            "#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(rows.into_iter().map(SyncPolicy::from).collect())
    }

    /// Update an existing sync policy, then re-evaluate.
    pub async fn update_policy(
        &self,
        id: Uuid,
        req: UpdateSyncPolicyRequest,
    ) -> Result<SyncPolicy> {
        // Fetch existing policy first
        let existing = self.get_policy(id).await?;

        let name = req.name.unwrap_or(existing.name);
        let description = req.description.unwrap_or(existing.description);
        let enabled = req.enabled.unwrap_or(existing.enabled);
        let replication_mode = req.replication_mode.unwrap_or(existing.replication_mode);
        let priority = req.priority.unwrap_or(existing.priority);
        let precedence = req.precedence.unwrap_or(existing.precedence);

        let repo_selector_json = match req.repo_selector {
            Some(rs) => serde_json::to_value(&rs)
                .map_err(|e| AppError::Validation(format!("Invalid repo_selector: {e}")))?,
            None => existing.repo_selector,
        };
        let peer_selector_json = match req.peer_selector {
            Some(ps) => serde_json::to_value(&ps)
                .map_err(|e| AppError::Validation(format!("Invalid peer_selector: {e}")))?,
            None => existing.peer_selector,
        };
        let artifact_filter_json = match req.artifact_filter {
            Some(af) => serde_json::to_value(&af)
                .map_err(|e| AppError::Validation(format!("Invalid artifact_filter: {e}")))?,
            None => existing.artifact_filter,
        };

        let row: SyncPolicyRow = sqlx::query_as(
            r#"
            UPDATE sync_policies
            SET name = $2, description = $3, enabled = $4, repo_selector = $5,
                peer_selector = $6, replication_mode = $7, priority = $8,
                artifact_filter = $9, precedence = $10, updated_at = NOW()
            WHERE id = $1
            RETURNING id, name, description, enabled, repo_selector, peer_selector,
                      replication_mode, priority, artifact_filter, precedence, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(&name)
        .bind(&description)
        .bind(enabled)
        .bind(&repo_selector_json)
        .bind(&peer_selector_json)
        .bind(&replication_mode)
        .bind(priority)
        .bind(&artifact_filter_json)
        .bind(precedence)
        .fetch_one(&self.db)
        .await
        .map_err(|e| {
            if e.to_string().contains("duplicate key") {
                AppError::Conflict(format!("Sync policy '{name}' already exists"))
            } else {
                AppError::Database(e.to_string())
            }
        })?;

        let policy: SyncPolicy = row.into();

        // Re-evaluate after update
        let _ = self.evaluate_policies().await;

        Ok(policy)
    }

    /// Delete a sync policy and remove all policy-generated subscriptions.
    pub async fn delete_policy(&self, id: Uuid) -> Result<()> {
        // First remove subscriptions created by this policy
        sqlx::query("DELETE FROM peer_repo_subscriptions WHERE policy_id = $1")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        let result = sqlx::query("DELETE FROM sync_policies WHERE id = $1")
            .bind(id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound(format!("Sync policy {id} not found")));
        }

        Ok(())
    }

    /// Enable or disable a sync policy.
    pub async fn toggle_policy(&self, id: Uuid, enabled: bool) -> Result<SyncPolicy> {
        let row: SyncPolicyRow = sqlx::query_as(
            r#"
            UPDATE sync_policies
            SET enabled = $2, updated_at = NOW()
            WHERE id = $1
            RETURNING id, name, description, enabled, repo_selector, peer_selector,
                      replication_mode, priority, artifact_filter, precedence, created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(enabled)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("Sync policy {id} not found")))?;

        let policy: SyncPolicy = row.into();

        // Re-evaluate after toggle
        let _ = self.evaluate_policies().await;

        Ok(policy)
    }

    /// Core engine: evaluate all enabled policies and reconcile peer_repo_subscriptions.
    ///
    /// For each enabled policy (ordered by precedence):
    /// 1. Resolve matching repositories using repo_selector
    /// 2. Resolve matching peers using peer_selector
    /// 3. For each (repo, peer) pair: upsert into peer_repo_subscriptions with policy_id
    ///
    /// Manual subscriptions (policy_id IS NULL) are never touched.
    /// Stale policy-managed subscriptions that no longer match any policy are removed.
    pub async fn evaluate_policies(&self) -> Result<EvaluationResult> {
        let policies = self.list_enabled_policies().await?;
        let policies_evaluated = policies.len();

        // Collect all desired (peer, repo, policy) triples.
        // Later policies (higher precedence number) do not override earlier ones.
        let mut desired: HashMap<(Uuid, Uuid), Uuid> = HashMap::new();

        for policy in &policies {
            let repo_selector: RepoSelector =
                serde_json::from_value(policy.repo_selector.clone()).unwrap_or_default();
            let peer_selector: PeerSelector =
                serde_json::from_value(policy.peer_selector.clone()).unwrap_or_default();

            let repos = self.resolve_repos(&repo_selector).await?;
            let peers = self.resolve_peers(&peer_selector).await?;

            for repo in &repos {
                for peer in &peers {
                    // First policy to claim a (peer, repo) pair wins (lower precedence number)
                    desired.entry((peer.id, repo.id)).or_insert(policy.id);
                }
            }
        }

        // Get existing policy-managed subscriptions
        let existing: Vec<SubscriptionRow> = sqlx::query_as(
            r#"
            SELECT peer_instance_id, repository_id, policy_id
            FROM peer_repo_subscriptions
            WHERE policy_id IS NOT NULL
            "#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let mut created: usize = 0;
        let mut updated: usize = 0;
        let mut removed: usize = 0;

        // Remove stale policy-managed subscriptions
        for sub in &existing {
            let key = (sub.peer_instance_id, sub.repository_id);
            if !desired.contains_key(&key) {
                sqlx::query(
                    "DELETE FROM peer_repo_subscriptions WHERE peer_instance_id = $1 AND repository_id = $2 AND policy_id IS NOT NULL",
                )
                .bind(sub.peer_instance_id)
                .bind(sub.repository_id)
                .execute(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
                removed += 1;
            }
        }

        // Build a set of existing policy-managed (peer, repo) pairs for quick lookup
        let existing_set: HashMap<(Uuid, Uuid), Option<Uuid>> = existing
            .iter()
            .map(|s| ((s.peer_instance_id, s.repository_id), s.policy_id))
            .collect();

        // Upsert desired subscriptions
        let mut newly_created: Vec<(Uuid, Uuid, Uuid)> = Vec::new();

        for ((peer_id, repo_id), policy_id) in &desired {
            // Find the policy to get replication mode
            let policy = policies.iter().find(|p| p.id == *policy_id);
            let replication_mode = policy
                .map(|p| p.replication_mode.as_str())
                .unwrap_or("push");

            match existing_set.get(&(*peer_id, *repo_id)) {
                Some(Some(existing_policy_id)) if existing_policy_id == policy_id => {
                    // Already exists with the same policy -- update replication mode just in case
                    sqlx::query(
                        r#"
                        UPDATE peer_repo_subscriptions
                        SET replication_mode = $3::replication_mode, sync_enabled = true
                        WHERE peer_instance_id = $1 AND repository_id = $2 AND policy_id = $4
                        "#,
                    )
                    .bind(peer_id)
                    .bind(repo_id)
                    .bind(replication_mode)
                    .bind(policy_id)
                    .execute(&self.db)
                    .await
                    .map_err(|e| AppError::Database(e.to_string()))?;
                    updated += 1;
                }
                Some(_) => {
                    // Exists but with a different policy -- update policy_id
                    sqlx::query(
                        r#"
                        UPDATE peer_repo_subscriptions
                        SET policy_id = $3, replication_mode = $4::replication_mode, sync_enabled = true
                        WHERE peer_instance_id = $1 AND repository_id = $2 AND policy_id IS NOT NULL
                        "#,
                    )
                    .bind(peer_id)
                    .bind(repo_id)
                    .bind(policy_id)
                    .bind(replication_mode)
                    .execute(&self.db)
                    .await
                    .map_err(|e| AppError::Database(e.to_string()))?;
                    updated += 1;
                }
                None => {
                    // New subscription -- insert. Use ON CONFLICT to handle the case where
                    // a manual subscription already exists for this (peer, repo) pair.
                    // We only create a new one if there is no existing subscription at all.
                    let result = sqlx::query(
                        r#"
                        INSERT INTO peer_repo_subscriptions
                            (peer_instance_id, repository_id, sync_enabled, replication_mode, policy_id)
                        VALUES ($1, $2, true, $3::replication_mode, $4)
                        ON CONFLICT (peer_instance_id, repository_id) DO NOTHING
                        "#,
                    )
                    .bind(peer_id)
                    .bind(repo_id)
                    .bind(replication_mode)
                    .bind(policy_id)
                    .execute(&self.db)
                    .await
                    .map_err(|e| AppError::Database(e.to_string()))?;

                    if result.rows_affected() > 0 {
                        created += 1;
                        newly_created.push((*peer_id, *repo_id, *policy_id));
                    }
                }
            }
        }

        // Queue sync tasks for existing artifacts in newly created subscriptions
        let retroactive_tasks_queued = self
            .queue_retroactive_sync_tasks(&newly_created, &policies)
            .await?;

        Ok(EvaluationResult {
            created,
            updated,
            removed,
            policies_evaluated,
            retroactive_tasks_queued,
        })
    }

    /// Preview what a policy configuration would match without making changes.
    pub async fn preview_policy(&self, req: CreateSyncPolicyRequest) -> Result<PreviewResult> {
        let matched_repositories = self.resolve_repos(&req.repo_selector).await?;
        let peers = self.resolve_peers(&req.peer_selector).await?;

        let matched_peers: Vec<MatchedPeer> = peers
            .into_iter()
            .map(|p| MatchedPeer {
                id: p.id,
                name: p.name,
                region: p.region,
            })
            .collect();

        let subscription_count = matched_repositories.len() * matched_peers.len();

        Ok(PreviewResult {
            matched_repositories,
            matched_peers,
            subscription_count,
        })
    }

    /// Re-evaluate policies for a single repository (e.g., when its labels change).
    pub async fn evaluate_for_repository(&self, repo_id: Uuid) -> Result<()> {
        let policies = self.list_enabled_policies().await?;

        // Determine which policies now match this repo
        let mut matching_policies: Vec<(&SyncPolicy, Vec<PeerRow>)> = Vec::new();

        for policy in &policies {
            let repo_selector: RepoSelector =
                serde_json::from_value(policy.repo_selector.clone()).unwrap_or_default();

            let repos = self.resolve_repos(&repo_selector).await?;
            if repos.iter().any(|r| r.id == repo_id) {
                let peer_selector: PeerSelector =
                    serde_json::from_value(policy.peer_selector.clone()).unwrap_or_default();
                let peers = self.resolve_peers(&peer_selector).await?;
                matching_policies.push((policy, peers));
            }
        }

        // Collect desired (peer_id, policy_id) for this repo
        let mut desired: HashMap<Uuid, Uuid> = HashMap::new();
        for (policy, peers) in &matching_policies {
            for peer in peers {
                desired.entry(peer.id).or_insert(policy.id);
            }
        }

        // Remove stale policy-managed subscriptions for this repo
        let existing: Vec<SubscriptionRow> = sqlx::query_as(
            r#"
            SELECT peer_instance_id, repository_id, policy_id
            FROM peer_repo_subscriptions
            WHERE repository_id = $1 AND policy_id IS NOT NULL
            "#,
        )
        .bind(repo_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        for sub in &existing {
            if !desired.contains_key(&sub.peer_instance_id) {
                sqlx::query(
                    "DELETE FROM peer_repo_subscriptions WHERE peer_instance_id = $1 AND repository_id = $2 AND policy_id IS NOT NULL",
                )
                .bind(sub.peer_instance_id)
                .bind(repo_id)
                .execute(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
            }
        }

        // Upsert desired subscriptions for this repo
        let mut newly_created: Vec<(Uuid, Uuid, Uuid)> = Vec::new();
        for (peer_id, policy_id) in &desired {
            let policy = policies.iter().find(|p| p.id == *policy_id);
            let replication_mode = policy
                .map(|p| p.replication_mode.as_str())
                .unwrap_or("push");

            let result = sqlx::query(
                r#"
                INSERT INTO peer_repo_subscriptions
                    (peer_instance_id, repository_id, sync_enabled, replication_mode, policy_id)
                VALUES ($1, $2, true, $3::replication_mode, $4)
                ON CONFLICT (peer_instance_id, repository_id) DO NOTHING
                "#,
            )
            .bind(peer_id)
            .bind(repo_id)
            .bind(replication_mode)
            .bind(policy_id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

            if result.rows_affected() > 0 {
                newly_created.push((*peer_id, repo_id, *policy_id));
            }
        }

        let _ = self
            .queue_retroactive_sync_tasks(&newly_created, &policies)
            .await;

        Ok(())
    }

    /// Re-evaluate sync tasks for a single artifact (e.g., when its labels change).
    ///
    /// Determines which peers should have this artifact based on current policies
    /// and the artifact's tags, then queues push or delete tasks accordingly.
    pub async fn evaluate_for_artifact(&self, artifact_id: Uuid) -> Result<()> {
        // 1. Look up the artifact
        #[derive(sqlx::FromRow)]
        struct ArtifactRow {
            repository_id: Uuid,
            path: String,
            size_bytes: i64,
            created_at: DateTime<Utc>,
        }

        let artifact: ArtifactRow = sqlx::query_as(
            "SELECT repository_id, path, size_bytes, created_at FROM artifacts WHERE id = $1 AND is_deleted = false",
        )
        .bind(artifact_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?
        .ok_or_else(|| AppError::NotFound(format!("Artifact {artifact_id} not found")))?;

        // 2. Fetch the artifact's current labels
        let label_service =
            crate::services::artifact_label_service::ArtifactLabelService::new(self.db.clone());
        let labels = label_service.get_labels(artifact_id).await?;
        let tag_pairs: Vec<(String, String)> = labels
            .iter()
            .map(|l| (l.label_key.clone(), l.label_value.clone()))
            .collect();

        // 3. Find enabled policies that match this artifact's repo
        let policies = self.list_enabled_policies().await?;
        let mut desired_peers: Vec<Uuid> = Vec::new();

        for policy in &policies {
            let repo_selector: RepoSelector =
                serde_json::from_value(policy.repo_selector.clone()).unwrap_or_default();
            let repos = self.resolve_repos(&repo_selector).await?;

            if !repos.iter().any(|r| r.id == artifact.repository_id) {
                continue;
            }

            // 4. Check if this artifact passes the filter (including match_tags)
            let filter: ArtifactFilter =
                serde_json::from_value(policy.artifact_filter.clone()).unwrap_or_default();

            if !filter.matches_with_tags(
                &artifact.path,
                artifact.size_bytes,
                artifact.created_at,
                &tag_pairs,
            ) {
                continue;
            }

            // 5. Resolve matching peers
            let peer_selector: PeerSelector =
                serde_json::from_value(policy.peer_selector.clone()).unwrap_or_default();
            let peers = self.resolve_peers(&peer_selector).await?;

            for peer in peers {
                if !desired_peers.contains(&peer.id) {
                    desired_peers.push(peer.id);
                }
            }
        }

        // 6. Find peers that previously completed a push for this artifact
        let synced_peers: Vec<Uuid> = sqlx::query_scalar(
            r#"
            SELECT DISTINCT peer_instance_id FROM sync_tasks
            WHERE artifact_id = $1 AND task_type = 'push' AND status = 'completed'
            "#,
        )
        .bind(artifact_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // 7. Queue push tasks for peers that should have it but don't
        for peer_id in &desired_peers {
            if synced_peers.contains(peer_id) {
                continue;
            }
            // Cancel any pending delete for this peer+artifact
            let _ = sqlx::query(
                r#"
                UPDATE sync_tasks SET status = 'cancelled'
                WHERE peer_instance_id = $1 AND artifact_id = $2
                  AND task_type = 'delete' AND status = 'pending'
                "#,
            )
            .bind(peer_id)
            .bind(artifact_id)
            .execute(&self.db)
            .await;

            // Queue push
            let _ = sqlx::query(
                r#"
                INSERT INTO sync_tasks (peer_instance_id, artifact_id, priority, task_type)
                VALUES ($1, $2, 0, 'push')
                ON CONFLICT (peer_instance_id, artifact_id, task_type)
                DO UPDATE SET status = 'pending', priority = GREATEST(sync_tasks.priority, 0)
                "#,
            )
            .bind(peer_id)
            .bind(artifact_id)
            .execute(&self.db)
            .await;
        }

        // 8. Queue delete tasks for peers that shouldn't have it but do
        for peer_id in &synced_peers {
            if desired_peers.contains(peer_id) {
                continue;
            }
            // Cancel any pending push for this peer+artifact
            let _ = sqlx::query(
                r#"
                UPDATE sync_tasks SET status = 'cancelled'
                WHERE peer_instance_id = $1 AND artifact_id = $2
                  AND task_type = 'push' AND status = 'pending'
                "#,
            )
            .bind(peer_id)
            .bind(artifact_id)
            .execute(&self.db)
            .await;

            // Queue delete
            let _ = sqlx::query(
                r#"
                INSERT INTO sync_tasks (peer_instance_id, artifact_id, priority, task_type)
                VALUES ($1, $2, 0, 'delete')
                ON CONFLICT (peer_instance_id, artifact_id, task_type)
                DO UPDATE SET status = 'pending', priority = GREATEST(sync_tasks.priority, 0)
                "#,
            )
            .bind(peer_id)
            .bind(artifact_id)
            .execute(&self.db)
            .await;
        }

        Ok(())
    }

    /// Re-evaluate policies for a specific peer (e.g., when a new peer joins).
    pub async fn evaluate_for_peer(&self, peer_id: Uuid) -> Result<()> {
        let policies = self.list_enabled_policies().await?;

        // Determine which policies match this peer
        let mut matching_policies: Vec<(&SyncPolicy, Vec<MatchedRepo>)> = Vec::new();

        for policy in &policies {
            let peer_selector: PeerSelector =
                serde_json::from_value(policy.peer_selector.clone()).unwrap_or_default();

            let peers = self.resolve_peers(&peer_selector).await?;
            if peers.iter().any(|p| p.id == peer_id) {
                let repo_selector: RepoSelector =
                    serde_json::from_value(policy.repo_selector.clone()).unwrap_or_default();
                let repos = self.resolve_repos(&repo_selector).await?;
                matching_policies.push((policy, repos));
            }
        }

        // Collect desired (repo_id, policy_id) for this peer
        let mut desired: HashMap<Uuid, Uuid> = HashMap::new();
        for (policy, repos) in &matching_policies {
            for repo in repos {
                desired.entry(repo.id).or_insert(policy.id);
            }
        }

        // Remove stale policy-managed subscriptions for this peer
        let existing: Vec<SubscriptionRow> = sqlx::query_as(
            r#"
            SELECT peer_instance_id, repository_id, policy_id
            FROM peer_repo_subscriptions
            WHERE peer_instance_id = $1 AND policy_id IS NOT NULL
            "#,
        )
        .bind(peer_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        for sub in &existing {
            if !desired.contains_key(&sub.repository_id) {
                sqlx::query(
                    "DELETE FROM peer_repo_subscriptions WHERE peer_instance_id = $1 AND repository_id = $2 AND policy_id IS NOT NULL",
                )
                .bind(peer_id)
                .bind(sub.repository_id)
                .execute(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
            }
        }

        // Upsert desired subscriptions for this peer
        let mut newly_created: Vec<(Uuid, Uuid, Uuid)> = Vec::new();
        for (repo_id, policy_id) in &desired {
            let policy = policies.iter().find(|p| p.id == *policy_id);
            let replication_mode = policy
                .map(|p| p.replication_mode.as_str())
                .unwrap_or("push");

            let result = sqlx::query(
                r#"
                INSERT INTO peer_repo_subscriptions
                    (peer_instance_id, repository_id, sync_enabled, replication_mode, policy_id)
                VALUES ($1, $2, true, $3::replication_mode, $4)
                ON CONFLICT (peer_instance_id, repository_id) DO NOTHING
                "#,
            )
            .bind(peer_id)
            .bind(repo_id)
            .bind(replication_mode)
            .bind(policy_id)
            .execute(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

            if result.rows_affected() > 0 {
                newly_created.push((peer_id, *repo_id, *policy_id));
            }
        }

        let _ = self
            .queue_retroactive_sync_tasks(&newly_created, &policies)
            .await;

        Ok(())
    }

    /// Queue sync tasks for existing artifacts in newly created subscriptions.
    ///
    /// When a policy evaluation creates new (peer, repo) subscriptions, this method
    /// finds all existing artifacts in those repos, applies the policy's artifact_filter,
    /// and queues sync tasks for matching artifacts.
    async fn queue_retroactive_sync_tasks(
        &self,
        new_subscriptions: &[(Uuid, Uuid, Uuid)], // (peer_id, repo_id, policy_id)
        policies: &[SyncPolicy],
    ) -> Result<usize> {
        if new_subscriptions.is_empty() {
            return Ok(0);
        }

        #[derive(sqlx::FromRow)]
        struct ArtifactRow {
            id: Uuid,
            path: String,
            size_bytes: i64,
            created_at: DateTime<Utc>,
        }

        let mut total_queued: usize = 0;

        for (peer_id, repo_id, policy_id) in new_subscriptions {
            let filter: ArtifactFilter = policies
                .iter()
                .find(|p| p.id == *policy_id)
                .and_then(|p| serde_json::from_value(p.artifact_filter.clone()).ok())
                .unwrap_or_default();

            let artifacts: Vec<ArtifactRow> = sqlx::query_as(
                r#"
                SELECT id, path, size_bytes, created_at
                FROM artifacts
                WHERE repository_id = $1 AND is_deleted = false
                "#,
            )
            .bind(repo_id)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

            // Batch-fetch labels for all artifacts if the filter uses match_tags
            let labels_map = if !filter.match_tags.is_empty() {
                let ids: Vec<Uuid> = artifacts.iter().map(|a| a.id).collect();
                let label_svc = crate::services::artifact_label_service::ArtifactLabelService::new(
                    self.db.clone(),
                );
                label_svc.get_labels_batch(&ids).await.unwrap_or_default()
            } else {
                std::collections::HashMap::new()
            };

            for artifact in &artifacts {
                let tag_pairs: Vec<(String, String)> = labels_map
                    .get(&artifact.id)
                    .map(|labels| {
                        labels
                            .iter()
                            .map(|l| (l.label_key.clone(), l.label_value.clone()))
                            .collect()
                    })
                    .unwrap_or_default();

                if !filter.matches_with_tags(
                    &artifact.path,
                    artifact.size_bytes,
                    artifact.created_at,
                    &tag_pairs,
                ) {
                    continue;
                }
                let _ = sqlx::query(
                    r#"
                    INSERT INTO sync_tasks (peer_instance_id, artifact_id, priority)
                    VALUES ($1, $2, $3)
                    ON CONFLICT (peer_instance_id, artifact_id, task_type)
                    DO UPDATE SET priority = GREATEST(sync_tasks.priority, $3)
                    "#,
                )
                .bind(peer_id)
                .bind(artifact.id)
                .bind(0i32)
                .execute(&self.db)
                .await;
                total_queued += 1;
            }
        }

        if total_queued > 0 {
            tracing::info!(
                "Retroactively queued {} sync task(s) for {} new subscription(s)",
                total_queued,
                new_subscriptions.len()
            );
        }

        Ok(total_queued)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// List only enabled policies ordered by precedence.
    async fn list_enabled_policies(&self) -> Result<Vec<SyncPolicy>> {
        let rows: Vec<SyncPolicyRow> = sqlx::query_as(
            r#"
            SELECT id, name, description, enabled, repo_selector, peer_selector,
                   replication_mode, priority, artifact_filter, precedence, created_at, updated_at
            FROM sync_policies
            WHERE enabled = true
            ORDER BY precedence ASC, created_at ASC
            "#,
        )
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(rows.into_iter().map(SyncPolicy::from).collect())
    }

    /// Resolve repositories matching a selector (delegates to shared service).
    async fn resolve_repos(&self, selector: &RepoSelector) -> Result<Vec<MatchedRepo>> {
        let svc = RepoSelectorService::new(self.db.clone());
        svc.resolve(selector).await
    }

    /// Resolve peers matching a selector.
    async fn resolve_peers(&self, selector: &PeerSelector) -> Result<Vec<PeerRow>> {
        // Explicit peer IDs
        if !selector.match_peers.is_empty() {
            let peers: Vec<PeerRow> = sqlx::query_as(
                r#"
                SELECT id, name, region
                FROM peer_instances
                WHERE id = ANY($1) AND is_local = false
                "#,
            )
            .bind(&selector.match_peers)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
            return Ok(peers);
        }

        // Match all non-local peers
        if selector.all {
            let peers: Vec<PeerRow> = sqlx::query_as(
                "SELECT id, name, region FROM peer_instances WHERE is_local = false ORDER BY name",
            )
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
            return Ok(peers);
        }

        // Match by region
        if let Some(region) = &selector.match_region {
            let peers: Vec<PeerRow> = sqlx::query_as(
                r#"
                SELECT id, name, region
                FROM peer_instances
                WHERE is_local = false AND region = $1
                ORDER BY name
                "#,
            )
            .bind(region)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
            return Ok(peers);
        }

        // Match by peer labels (AND semantics)
        if !selector.match_labels.is_empty() {
            let label_selectors: Vec<crate::services::repository_label_service::LabelEntry> =
                selector
                    .match_labels
                    .iter()
                    .map(
                        |(k, v)| crate::services::repository_label_service::LabelEntry {
                            key: k.clone(),
                            value: v.clone(),
                        },
                    )
                    .collect();

            let label_service =
                crate::services::peer_instance_label_service::PeerInstanceLabelService::new(
                    self.db.clone(),
                );
            let peer_ids = label_service.find_peers_by_labels(&label_selectors).await?;

            if peer_ids.is_empty() {
                return Ok(vec![]);
            }

            let peers: Vec<PeerRow> = sqlx::query_as(
                r#"
                SELECT id, name, region
                FROM peer_instances
                WHERE id = ANY($1) AND is_local = false
                ORDER BY name
                "#,
            )
            .bind(&peer_ids)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

            return Ok(peers);
        }

        // Empty selector = no peers matched
        Ok(vec![])
    }
}

// Re-export sql_like_match from the shared service for backward compatibility.
pub(crate) use crate::services::repo_selector_service::sql_like_match;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Pure helper functions (moved from module scope — test-only)
    // -----------------------------------------------------------------------

    fn validate_policy_name(name: &str) -> std::result::Result<(), &'static str> {
        if name.trim().is_empty() {
            Err("Policy name cannot be empty")
        } else {
            Ok(())
        }
    }

    fn classify_policy_db_error(error_msg: &str, policy_name: &str) -> String {
        if error_msg.contains("duplicate key") {
            format!("Sync policy '{}' already exists", policy_name)
        } else {
            error_msg.to_string()
        }
    }

    fn repo_selector_has_filters(selector: &RepoSelector) -> bool {
        !selector.match_labels.is_empty()
            || !selector.match_formats.is_empty()
            || selector.match_pattern.is_some()
    }

    fn glob_to_sql_pattern(glob: &str) -> String {
        glob.replace('*', "%")
    }

    fn filter_by_formats(repo_format: &str, match_formats: &[String]) -> bool {
        if match_formats.is_empty() {
            return true;
        }
        match_formats
            .iter()
            .any(|f| f.to_lowercase() == repo_format.to_lowercase())
    }

    fn labels_match_all(
        repo_labels: &[(&str, &str)],
        required_labels: &HashMap<String, String>,
    ) -> bool {
        required_labels
            .iter()
            .all(|(k, v)| repo_labels.iter().any(|(lk, lv)| *lk == k && *lv == v))
    }

    fn compute_subscription_count(repo_count: usize, peer_count: usize) -> usize {
        repo_count * peer_count
    }

    fn validate_replication_mode(mode: &str) -> bool {
        matches!(mode, "push" | "pull" | "mirror")
    }

    // -----------------------------------------------------------------------
    // RepoSelector serialization/deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_selector_default() {
        let sel = RepoSelector::default();
        assert!(sel.match_labels.is_empty());
        assert!(sel.match_formats.is_empty());
        assert!(sel.match_pattern.is_none());
        assert!(sel.match_repos.is_empty());
    }

    #[test]
    fn test_repo_selector_serialization() {
        let mut labels = HashMap::new();
        labels.insert("env".to_string(), "prod".to_string());

        let sel = RepoSelector {
            match_labels: labels,
            match_formats: vec!["docker".to_string(), "maven".to_string()],
            match_pattern: Some("libs-*".to_string()),
            match_repos: vec![],
        };

        let json = serde_json::to_value(&sel).unwrap();
        assert_eq!(json["match_labels"]["env"], "prod");
        assert_eq!(json["match_formats"][0], "docker");
        assert_eq!(json["match_formats"][1], "maven");
        assert_eq!(json["match_pattern"], "libs-*");
    }

    #[test]
    fn test_repo_selector_deserialization() {
        let json = r#"{
            "match_labels": {"env": "prod", "tier": "1"},
            "match_formats": ["docker"],
            "match_pattern": "release-*"
        }"#;
        let sel: RepoSelector = serde_json::from_str(json).unwrap();
        assert_eq!(sel.match_labels.len(), 2);
        assert_eq!(sel.match_labels["env"], "prod");
        assert_eq!(sel.match_labels["tier"], "1");
        assert_eq!(sel.match_formats, vec!["docker"]);
        assert_eq!(sel.match_pattern, Some("release-*".to_string()));
        assert!(sel.match_repos.is_empty());
    }

    #[test]
    fn test_repo_selector_deserialization_empty_object() {
        let json = r#"{}"#;
        let sel: RepoSelector = serde_json::from_str(json).unwrap();
        assert!(sel.match_labels.is_empty());
        assert!(sel.match_formats.is_empty());
        assert!(sel.match_pattern.is_none());
        assert!(sel.match_repos.is_empty());
    }

    #[test]
    fn test_repo_selector_roundtrip() {
        let sel = RepoSelector {
            match_labels: {
                let mut m = HashMap::new();
                m.insert("team".to_string(), "platform".to_string());
                m
            },
            match_formats: vec!["npm".to_string()],
            match_pattern: None,
            match_repos: vec![Uuid::nil()],
        };
        let json = serde_json::to_string(&sel).unwrap();
        let roundtrip: RepoSelector = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.match_labels["team"], "platform");
        assert_eq!(roundtrip.match_formats, vec!["npm"]);
        assert_eq!(roundtrip.match_repos, vec![Uuid::nil()]);
    }

    #[test]
    fn test_repo_selector_with_uuids() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let sel = RepoSelector {
            match_repos: vec![id1, id2],
            ..Default::default()
        };
        let json = serde_json::to_string(&sel).unwrap();
        let roundtrip: RepoSelector = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.match_repos.len(), 2);
        assert!(roundtrip.match_repos.contains(&id1));
        assert!(roundtrip.match_repos.contains(&id2));
    }

    // -----------------------------------------------------------------------
    // PeerSelector serialization/deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_peer_selector_default() {
        let sel = PeerSelector::default();
        assert!(!sel.all);
        assert!(sel.match_labels.is_empty());
        assert!(sel.match_region.is_none());
        assert!(sel.match_peers.is_empty());
    }

    #[test]
    fn test_peer_selector_all() {
        let json = r#"{"all": true}"#;
        let sel: PeerSelector = serde_json::from_str(json).unwrap();
        assert!(sel.all);
    }

    #[test]
    fn test_peer_selector_region() {
        let sel = PeerSelector {
            match_region: Some("us-east-1".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_value(&sel).unwrap();
        assert_eq!(json["match_region"], "us-east-1");
    }

    #[test]
    fn test_peer_selector_deserialization() {
        let json = r#"{
            "match_labels": {"region": "us-east"},
            "match_region": "us-east",
            "match_peers": ["550e8400-e29b-41d4-a716-446655440000"]
        }"#;
        let sel: PeerSelector = serde_json::from_str(json).unwrap();
        assert_eq!(sel.match_labels["region"], "us-east");
        assert_eq!(sel.match_region, Some("us-east".to_string()));
        assert_eq!(sel.match_peers.len(), 1);
    }

    #[test]
    fn test_peer_selector_empty_object() {
        let json = r#"{}"#;
        let sel: PeerSelector = serde_json::from_str(json).unwrap();
        assert!(!sel.all);
        assert!(sel.match_labels.is_empty());
        assert!(sel.match_region.is_none());
        assert!(sel.match_peers.is_empty());
    }

    #[test]
    fn test_peer_selector_roundtrip() {
        let sel = PeerSelector {
            all: false,
            match_labels: {
                let mut m = HashMap::new();
                m.insert("dc".to_string(), "east".to_string());
                m
            },
            match_region: Some("eu-west-1".to_string()),
            match_peers: vec![Uuid::nil()],
        };
        let json = serde_json::to_string(&sel).unwrap();
        let roundtrip: PeerSelector = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.match_labels["dc"], "east");
        assert_eq!(roundtrip.match_region, Some("eu-west-1".to_string()));
        assert_eq!(roundtrip.match_peers.len(), 1);
    }

    // -----------------------------------------------------------------------
    // ArtifactFilter serialization/deserialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifact_filter_default() {
        let f = ArtifactFilter::default();
        assert!(f.max_age_days.is_none());
        assert!(f.include_paths.is_empty());
        assert!(f.exclude_paths.is_empty());
        assert!(f.max_size_bytes.is_none());
    }

    #[test]
    fn test_artifact_filter_serialization() {
        let f = ArtifactFilter {
            max_age_days: Some(90),
            include_paths: vec!["release/*".to_string()],
            exclude_paths: vec!["snapshot/*".to_string()],
            max_size_bytes: Some(1_073_741_824),
            match_tags: HashMap::new(),
        };
        let json = serde_json::to_value(&f).unwrap();
        assert_eq!(json["max_age_days"], 90);
        assert_eq!(json["include_paths"][0], "release/*");
        assert_eq!(json["exclude_paths"][0], "snapshot/*");
        assert_eq!(json["max_size_bytes"], 1_073_741_824i64);
    }

    #[test]
    fn test_artifact_filter_deserialization() {
        let json = r#"{
            "max_age_days": 30,
            "include_paths": ["libs/*", "core/*"],
            "exclude_paths": [],
            "max_size_bytes": 536870912
        }"#;
        let f: ArtifactFilter = serde_json::from_str(json).unwrap();
        assert_eq!(f.max_age_days, Some(30));
        assert_eq!(f.include_paths.len(), 2);
        assert!(f.exclude_paths.is_empty());
        assert_eq!(f.max_size_bytes, Some(536_870_912));
    }

    #[test]
    fn test_artifact_filter_empty_object() {
        let json = r#"{}"#;
        let f: ArtifactFilter = serde_json::from_str(json).unwrap();
        assert!(f.max_age_days.is_none());
        assert!(f.include_paths.is_empty());
        assert!(f.exclude_paths.is_empty());
        assert!(f.max_size_bytes.is_none());
    }

    #[test]
    fn test_artifact_filter_roundtrip() {
        let f = ArtifactFilter {
            max_age_days: Some(7),
            include_paths: vec!["**/*.jar".to_string()],
            exclude_paths: vec!["test/**".to_string()],
            max_size_bytes: Some(1_000_000),
            match_tags: HashMap::new(),
        };
        let json = serde_json::to_string(&f).unwrap();
        let roundtrip: ArtifactFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.max_age_days, Some(7));
        assert_eq!(roundtrip.include_paths, vec!["**/*.jar"]);
        assert_eq!(roundtrip.exclude_paths, vec!["test/**"]);
        assert_eq!(roundtrip.max_size_bytes, Some(1_000_000));
    }

    // -----------------------------------------------------------------------
    // CreateSyncPolicyRequest
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_request_deserialization_minimal() {
        let json = r#"{"name": "prod-sync"}"#;
        let req: CreateSyncPolicyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "prod-sync");
        assert_eq!(req.description, "");
        assert!(req.enabled);
        assert_eq!(req.replication_mode, "push");
        assert_eq!(req.priority, 0);
        assert_eq!(req.precedence, 100);
    }

    #[test]
    fn test_create_request_deserialization_full() {
        let json = r#"{
            "name": "full-policy",
            "description": "Sync all prod repos to US-East",
            "enabled": false,
            "repo_selector": {"match_labels": {"env": "prod"}},
            "peer_selector": {"match_region": "us-east-1"},
            "replication_mode": "mirror",
            "priority": 10,
            "artifact_filter": {"max_age_days": 30},
            "precedence": 50
        }"#;
        let req: CreateSyncPolicyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "full-policy");
        assert_eq!(req.description, "Sync all prod repos to US-East");
        assert!(!req.enabled);
        assert_eq!(req.repo_selector.match_labels["env"], "prod");
        assert_eq!(
            req.peer_selector.match_region,
            Some("us-east-1".to_string())
        );
        assert_eq!(req.replication_mode, "mirror");
        assert_eq!(req.priority, 10);
        assert_eq!(req.artifact_filter.max_age_days, Some(30));
        assert_eq!(req.precedence, 50);
    }

    #[test]
    fn test_create_request_missing_name_fails() {
        let json = r#"{"description": "no name"}"#;
        let result = serde_json::from_str::<CreateSyncPolicyRequest>(json);
        assert!(result.is_err(), "name is required");
    }

    #[test]
    fn test_create_request_defaults() {
        let json = r#"{"name": "test"}"#;
        let req: CreateSyncPolicyRequest = serde_json::from_str(json).unwrap();
        assert!(req.enabled);
        assert_eq!(req.replication_mode, "push");
        assert_eq!(req.precedence, 100);
        assert_eq!(req.priority, 0);
        assert!(req.repo_selector.match_labels.is_empty());
        assert!(req.peer_selector.match_peers.is_empty());
        assert!(req.artifact_filter.max_age_days.is_none());
    }

    // -----------------------------------------------------------------------
    // UpdateSyncPolicyRequest
    // -----------------------------------------------------------------------

    #[test]
    fn test_update_request_partial() {
        let json = r#"{"name": "renamed"}"#;
        let req: UpdateSyncPolicyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, Some("renamed".to_string()));
        assert!(req.description.is_none());
        assert!(req.enabled.is_none());
        assert!(req.repo_selector.is_none());
    }

    #[test]
    fn test_update_request_empty() {
        let json = r#"{}"#;
        let req: UpdateSyncPolicyRequest = serde_json::from_str(json).unwrap();
        assert!(req.name.is_none());
        assert!(req.description.is_none());
        assert!(req.enabled.is_none());
        assert!(req.repo_selector.is_none());
        assert!(req.peer_selector.is_none());
        assert!(req.replication_mode.is_none());
        assert!(req.priority.is_none());
        assert!(req.artifact_filter.is_none());
        assert!(req.precedence.is_none());
    }

    // -----------------------------------------------------------------------
    // Default values
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_true() {
        assert!(default_true());
    }

    #[test]
    fn test_default_replication_mode() {
        assert_eq!(default_replication_mode(), "push");
    }

    #[test]
    fn test_default_precedence() {
        assert_eq!(default_precedence(), 100);
    }

    // -----------------------------------------------------------------------
    // JSON contract tests (field names match expected)
    // -----------------------------------------------------------------------

    #[test]
    fn test_sync_policy_json_field_names() {
        let policy = SyncPolicy {
            id: Uuid::nil(),
            name: "test".to_string(),
            description: "desc".to_string(),
            enabled: true,
            repo_selector: serde_json::json!({}),
            peer_selector: serde_json::json!({}),
            replication_mode: "push".to_string(),
            priority: 0,
            artifact_filter: serde_json::json!({}),
            precedence: 100,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let json: serde_json::Value = serde_json::to_value(&policy).unwrap();

        for field in [
            "id",
            "name",
            "description",
            "enabled",
            "repo_selector",
            "peer_selector",
            "replication_mode",
            "priority",
            "artifact_filter",
            "precedence",
            "created_at",
            "updated_at",
        ] {
            assert!(
                json.get(field).is_some(),
                "Missing field '{field}' in SyncPolicy JSON"
            );
        }

        let obj = json.as_object().unwrap();
        assert_eq!(
            obj.len(),
            12,
            "SyncPolicy should have exactly 12 fields, got: {:?}",
            obj.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_repo_selector_json_field_names() {
        let sel = RepoSelector {
            match_labels: HashMap::new(),
            match_formats: vec![],
            match_pattern: None,
            match_repos: vec![],
        };
        let json: serde_json::Value = serde_json::to_value(&sel).unwrap();
        assert!(json.get("match_labels").is_some());
        assert!(json.get("match_formats").is_some());
        assert!(json.get("match_pattern").is_some());
        assert!(json.get("match_repos").is_some());
    }

    #[test]
    fn test_peer_selector_json_field_names() {
        let sel = PeerSelector {
            all: false,
            match_labels: HashMap::new(),
            match_region: None,
            match_peers: vec![],
        };
        let json: serde_json::Value = serde_json::to_value(&sel).unwrap();
        assert!(json.get("all").is_some());
        assert!(json.get("match_labels").is_some());
        assert!(json.get("match_region").is_some());
        assert!(json.get("match_peers").is_some());
    }

    #[test]
    fn test_artifact_filter_json_field_names() {
        let f = ArtifactFilter {
            max_age_days: None,
            include_paths: vec![],
            exclude_paths: vec![],
            max_size_bytes: None,
            match_tags: HashMap::new(),
        };
        let json: serde_json::Value = serde_json::to_value(&f).unwrap();
        assert!(json.get("max_age_days").is_some());
        assert!(json.get("include_paths").is_some());
        assert!(json.get("exclude_paths").is_some());
        assert!(json.get("max_size_bytes").is_some());
        assert!(json.get("match_tags").is_some());
    }

    #[test]
    fn test_evaluation_result_json_field_names() {
        let r = EvaluationResult {
            created: 5,
            updated: 3,
            removed: 1,
            policies_evaluated: 2,
            retroactive_tasks_queued: 10,
        };
        let json: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert_eq!(json["created"], 5);
        assert_eq!(json["updated"], 3);
        assert_eq!(json["removed"], 1);
        assert_eq!(json["policies_evaluated"], 2);
        assert_eq!(json["retroactive_tasks_queued"], 10);
    }

    #[test]
    fn test_preview_result_json_field_names() {
        let p = PreviewResult {
            matched_repositories: vec![],
            matched_peers: vec![],
            subscription_count: 0,
        };
        let json: serde_json::Value = serde_json::to_value(&p).unwrap();
        assert!(json.get("matched_repositories").is_some());
        assert!(json.get("matched_peers").is_some());
        assert!(json.get("subscription_count").is_some());
    }

    // -----------------------------------------------------------------------
    // Empty selectors
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_repo_selector_serializes_to_defaults() {
        let sel = RepoSelector::default();
        let json = serde_json::to_string(&sel).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["match_labels"].as_object().unwrap().is_empty());
        assert!(parsed["match_formats"].as_array().unwrap().is_empty());
        assert!(parsed["match_pattern"].is_null());
        assert!(parsed["match_repos"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_empty_peer_selector_serializes_to_defaults() {
        let sel = PeerSelector::default();
        let json = serde_json::to_string(&sel).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["all"], false);
        assert!(parsed["match_labels"].as_object().unwrap().is_empty());
        assert!(parsed["match_region"].is_null());
        assert!(parsed["match_peers"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_empty_artifact_filter_serializes_to_defaults() {
        let f = ArtifactFilter::default();
        let json = serde_json::to_string(&f).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["max_age_days"].is_null());
        assert!(parsed["include_paths"].as_array().unwrap().is_empty());
        assert!(parsed["exclude_paths"].as_array().unwrap().is_empty());
        assert!(parsed["max_size_bytes"].is_null());
    }

    // -----------------------------------------------------------------------
    // Edge cases: unicode, special characters
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_selector_unicode_labels() {
        let mut labels = HashMap::new();
        labels.insert("environnement".to_string(), "production".to_string());
        labels.insert("equipe".to_string(), "plateforme".to_string());

        let sel = RepoSelector {
            match_labels: labels,
            ..Default::default()
        };
        let json = serde_json::to_string(&sel).unwrap();
        let roundtrip: RepoSelector = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.match_labels["environnement"], "production");
        assert_eq!(roundtrip.match_labels["equipe"], "plateforme");
    }

    #[test]
    fn test_repo_selector_unicode_labels_japanese() {
        let mut labels = HashMap::new();
        labels.insert("環境".to_string(), "本番".to_string());

        let sel = RepoSelector {
            match_labels: labels,
            ..Default::default()
        };
        let json = serde_json::to_string(&sel).unwrap();
        let roundtrip: RepoSelector = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.match_labels["環境"], "本番");
    }

    #[test]
    fn test_repo_selector_special_characters_in_pattern() {
        let sel = RepoSelector {
            match_pattern: Some("libs-release-*-v2".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_string(&sel).unwrap();
        let roundtrip: RepoSelector = serde_json::from_str(&json).unwrap();
        assert_eq!(
            roundtrip.match_pattern,
            Some("libs-release-*-v2".to_string())
        );
    }

    #[test]
    fn test_artifact_filter_special_path_characters() {
        let f = ArtifactFilter {
            include_paths: vec![
                "com/example/**/*.jar".to_string(),
                "org/apache/maven-*/**".to_string(),
            ],
            exclude_paths: vec!["**/*-SNAPSHOT*".to_string()],
            ..Default::default()
        };
        let json = serde_json::to_string(&f).unwrap();
        let roundtrip: ArtifactFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.include_paths.len(), 2);
        assert_eq!(roundtrip.exclude_paths[0], "**/*-SNAPSHOT*");
    }

    #[test]
    fn test_sync_policy_description_with_special_chars() {
        let policy = SyncPolicy {
            id: Uuid::nil(),
            name: "test-policy".to_string(),
            description: "Sync repos labeled \"env=prod\" & tier=1 -> US-East peers".to_string(),
            enabled: true,
            repo_selector: serde_json::json!({}),
            peer_selector: serde_json::json!({}),
            replication_mode: "push".to_string(),
            priority: 0,
            artifact_filter: serde_json::json!({}),
            precedence: 100,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let json = serde_json::to_string(&policy).unwrap();
        let roundtrip: SyncPolicy = serde_json::from_str(&json).unwrap();
        assert!(roundtrip.description.contains("\"env=prod\""));
        assert!(roundtrip.description.contains("&"));
        assert!(roundtrip.description.contains("->"));
    }

    #[test]
    fn test_create_request_extra_fields_ignored() {
        let json = r#"{"name": "test", "unknown_field": "should be ignored"}"#;
        let req: CreateSyncPolicyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "test");
    }

    #[test]
    fn test_peer_selector_with_labels_and_region() {
        let sel = PeerSelector {
            all: false,
            match_labels: {
                let mut m = HashMap::new();
                m.insert("tier".to_string(), "edge".to_string());
                m
            },
            match_region: Some("ap-southeast-1".to_string()),
            match_peers: vec![],
        };
        let json = serde_json::to_string(&sel).unwrap();
        let roundtrip: PeerSelector = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.match_labels["tier"], "edge");
        assert_eq!(roundtrip.match_region, Some("ap-southeast-1".to_string()));
    }

    // -----------------------------------------------------------------------
    // validate_policy_name
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_policy_name_valid() {
        assert!(validate_policy_name("prod-sync").is_ok());
        assert!(validate_policy_name("a").is_ok());
        assert!(validate_policy_name("  leading-spaces").is_ok());
    }

    #[test]
    fn test_validate_policy_name_empty() {
        assert!(validate_policy_name("").is_err());
    }

    #[test]
    fn test_validate_policy_name_whitespace_only() {
        assert!(validate_policy_name("   ").is_err());
        assert!(validate_policy_name("\t\n").is_err());
    }

    // -----------------------------------------------------------------------
    // classify_policy_db_error
    // -----------------------------------------------------------------------

    #[test]
    fn test_classify_policy_db_error_duplicate() {
        let result = classify_policy_db_error("duplicate key value violates", "my-policy");
        assert_eq!(result, "Sync policy 'my-policy' already exists");
    }

    #[test]
    fn test_classify_policy_db_error_other() {
        let result = classify_policy_db_error("connection refused", "my-policy");
        assert_eq!(result, "connection refused");
    }

    // -----------------------------------------------------------------------
    // repo_selector_has_filters
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_selector_has_filters_empty() {
        let sel = RepoSelector::default();
        assert!(!repo_selector_has_filters(&sel));
    }

    #[test]
    fn test_repo_selector_has_filters_labels() {
        let sel = RepoSelector {
            match_labels: {
                let mut m = HashMap::new();
                m.insert("env".to_string(), "prod".to_string());
                m
            },
            ..Default::default()
        };
        assert!(repo_selector_has_filters(&sel));
    }

    #[test]
    fn test_repo_selector_has_filters_formats() {
        let sel = RepoSelector {
            match_formats: vec!["docker".to_string()],
            ..Default::default()
        };
        assert!(repo_selector_has_filters(&sel));
    }

    #[test]
    fn test_repo_selector_has_filters_pattern() {
        let sel = RepoSelector {
            match_pattern: Some("libs-*".to_string()),
            ..Default::default()
        };
        assert!(repo_selector_has_filters(&sel));
    }

    // -----------------------------------------------------------------------
    // glob_to_sql_pattern
    // -----------------------------------------------------------------------

    #[test]
    fn test_glob_to_sql_pattern_simple() {
        assert_eq!(glob_to_sql_pattern("libs-*"), "libs-%");
    }

    #[test]
    fn test_glob_to_sql_pattern_multiple_wildcards() {
        assert_eq!(glob_to_sql_pattern("*-release-*"), "%-release-%");
    }

    #[test]
    fn test_glob_to_sql_pattern_no_wildcard() {
        assert_eq!(glob_to_sql_pattern("exact-name"), "exact-name");
    }

    #[test]
    fn test_glob_to_sql_pattern_all_wildcard() {
        assert_eq!(glob_to_sql_pattern("*"), "%");
    }

    #[test]
    fn test_glob_to_sql_pattern_empty() {
        assert_eq!(glob_to_sql_pattern(""), "");
    }

    // -----------------------------------------------------------------------
    // filter_by_formats
    // -----------------------------------------------------------------------

    #[test]
    fn test_filter_by_formats_empty_list_passes() {
        assert!(filter_by_formats("docker", &[]));
    }

    #[test]
    fn test_filter_by_formats_matching() {
        let formats = vec!["docker".to_string(), "maven".to_string()];
        assert!(filter_by_formats("docker", &formats));
        assert!(filter_by_formats("maven", &formats));
    }

    #[test]
    fn test_filter_by_formats_case_insensitive() {
        let formats = vec!["Docker".to_string()];
        assert!(filter_by_formats("docker", &formats));
        assert!(filter_by_formats("DOCKER", &formats));
    }

    #[test]
    fn test_filter_by_formats_no_match() {
        let formats = vec!["docker".to_string()];
        assert!(!filter_by_formats("maven", &formats));
    }

    // -----------------------------------------------------------------------
    // labels_match_all
    // -----------------------------------------------------------------------

    #[test]
    fn test_labels_match_all_empty_required() {
        let repo_labels = vec![("env", "prod")];
        let required = HashMap::new();
        assert!(labels_match_all(&repo_labels, &required));
    }

    #[test]
    fn test_labels_match_all_single_match() {
        let repo_labels = vec![("env", "prod"), ("tier", "1")];
        let mut required = HashMap::new();
        required.insert("env".to_string(), "prod".to_string());
        assert!(labels_match_all(&repo_labels, &required));
    }

    #[test]
    fn test_labels_match_all_multiple_match() {
        let repo_labels = vec![("env", "prod"), ("tier", "1"), ("team", "platform")];
        let mut required = HashMap::new();
        required.insert("env".to_string(), "prod".to_string());
        required.insert("tier".to_string(), "1".to_string());
        assert!(labels_match_all(&repo_labels, &required));
    }

    #[test]
    fn test_labels_match_all_value_mismatch() {
        let repo_labels = vec![("env", "staging")];
        let mut required = HashMap::new();
        required.insert("env".to_string(), "prod".to_string());
        assert!(!labels_match_all(&repo_labels, &required));
    }

    #[test]
    fn test_labels_match_all_key_missing() {
        let repo_labels = vec![("env", "prod")];
        let mut required = HashMap::new();
        required.insert("tier".to_string(), "1".to_string());
        assert!(!labels_match_all(&repo_labels, &required));
    }

    #[test]
    fn test_labels_match_all_empty_repo_labels() {
        let repo_labels: Vec<(&str, &str)> = vec![];
        let mut required = HashMap::new();
        required.insert("env".to_string(), "prod".to_string());
        assert!(!labels_match_all(&repo_labels, &required));
    }

    // -----------------------------------------------------------------------
    // compute_subscription_count
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_subscription_count() {
        assert_eq!(compute_subscription_count(5, 3), 15);
        assert_eq!(compute_subscription_count(0, 10), 0);
        assert_eq!(compute_subscription_count(10, 0), 0);
        assert_eq!(compute_subscription_count(1, 1), 1);
    }

    // -----------------------------------------------------------------------
    // validate_replication_mode
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_replication_mode_valid() {
        assert!(validate_replication_mode("push"));
        assert!(validate_replication_mode("pull"));
        assert!(validate_replication_mode("mirror"));
    }

    #[test]
    fn test_validate_replication_mode_invalid() {
        assert!(!validate_replication_mode("sync"));
        assert!(!validate_replication_mode(""));
        assert!(!validate_replication_mode("Push"));
        assert!(!validate_replication_mode("MIRROR"));
    }

    // -----------------------------------------------------------------------
    // sql_like_match helper
    // -----------------------------------------------------------------------

    #[test]
    fn test_sql_like_match_exact() {
        assert!(sql_like_match("hello", "hello"));
        assert!(!sql_like_match("hello", "world"));
    }

    #[test]
    fn test_sql_like_match_prefix_wildcard() {
        assert!(sql_like_match("libs-release", "libs-%"));
        assert!(sql_like_match("libs-", "libs-%"));
        assert!(!sql_like_match("test-release", "libs-%"));
    }

    #[test]
    fn test_sql_like_match_suffix_wildcard() {
        assert!(sql_like_match("my-libs", "%-libs"));
        assert!(sql_like_match("-libs", "%-libs"));
        assert!(!sql_like_match("my-test", "%-libs"));
    }

    #[test]
    fn test_sql_like_match_contains() {
        assert!(sql_like_match("my-libs-release", "%-libs-%"));
        assert!(!sql_like_match("my-test-release", "%-libs-%"));
    }

    #[test]
    fn test_sql_like_match_all() {
        assert!(sql_like_match("anything", "%"));
        assert!(sql_like_match("", "%"));
    }

    #[test]
    fn test_sql_like_match_empty_pattern() {
        assert!(sql_like_match("", ""));
        assert!(!sql_like_match("hello", ""));
    }

    #[test]
    fn test_sql_like_match_multiple_wildcards() {
        assert!(sql_like_match("libs-release-v2", "libs-%-v2"));
        assert!(!sql_like_match("libs-release-v3", "libs-%-v2"));
    }

    #[test]
    fn test_sql_like_match_double_wildcard() {
        // %% is two consecutive wildcards, equivalent to %
        assert!(sql_like_match("abc", "%%"));
        assert!(sql_like_match("", "%%"));
    }

    #[test]
    fn test_sql_like_match_only_prefix() {
        assert!(sql_like_match("docker-prod", "docker%"));
        assert!(!sql_like_match("maven-prod", "docker%"));
    }

    #[test]
    fn test_sql_like_match_complex_pattern() {
        // libs-%-release-%-v2
        assert!(sql_like_match(
            "libs-core-release-stable-v2",
            "libs-%-release-%-v2"
        ));
        assert!(!sql_like_match(
            "libs-core-release-stable-v3",
            "libs-%-release-%-v2"
        ));
    }

    #[test]
    fn test_sql_like_match_single_char_value() {
        assert!(sql_like_match("a", "%"));
        assert!(sql_like_match("a", "a"));
        assert!(!sql_like_match("a", "b"));
    }

    #[test]
    fn test_sql_like_match_value_shorter_than_pattern() {
        assert!(!sql_like_match("ab", "abc"));
    }

    #[test]
    fn test_sql_like_match_value_longer_than_pattern() {
        assert!(!sql_like_match("abcdef", "abc"));
    }

    #[test]
    fn test_sql_like_match_wildcard_at_start_and_end() {
        assert!(sql_like_match("anything-release-anything", "%release%"));
        assert!(!sql_like_match("anything-snapshot-anything", "%release%"));
    }

    // -----------------------------------------------------------------------
    // TogglePolicyRequest
    // -----------------------------------------------------------------------

    #[test]
    fn test_toggle_request_deserialization() {
        let json = r#"{"enabled": true}"#;
        let req: TogglePolicyRequest = serde_json::from_str(json).unwrap();
        assert!(req.enabled);

        let json = r#"{"enabled": false}"#;
        let req: TogglePolicyRequest = serde_json::from_str(json).unwrap();
        assert!(!req.enabled);
    }

    #[test]
    fn test_toggle_request_missing_enabled_fails() {
        let json = r#"{}"#;
        let result = serde_json::from_str::<TogglePolicyRequest>(json);
        assert!(result.is_err(), "enabled is required");
    }

    // -----------------------------------------------------------------------
    // MatchedRepo / MatchedPeer
    // -----------------------------------------------------------------------

    #[test]
    fn test_matched_repo_serialization() {
        let r = MatchedRepo {
            id: Uuid::nil(),
            key: "docker-prod".to_string(),
            format: "docker".to_string(),
        };
        let json: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert!(json.get("id").is_some());
        assert_eq!(json["key"], "docker-prod");
        assert_eq!(json["format"], "docker");
    }

    #[test]
    fn test_matched_peer_serialization() {
        let p = MatchedPeer {
            id: Uuid::nil(),
            name: "edge-east".to_string(),
            region: Some("us-east-1".to_string()),
        };
        let json: serde_json::Value = serde_json::to_value(&p).unwrap();
        assert!(json.get("id").is_some());
        assert_eq!(json["name"], "edge-east");
        assert_eq!(json["region"], "us-east-1");
    }

    #[test]
    fn test_matched_peer_no_region() {
        let p = MatchedPeer {
            id: Uuid::nil(),
            name: "local-peer".to_string(),
            region: None,
        };
        let json: serde_json::Value = serde_json::to_value(&p).unwrap();
        assert!(json["region"].is_null());
    }

    // -----------------------------------------------------------------------
    // Service constructor
    // -----------------------------------------------------------------------

    #[test]
    fn test_service_constructor_compiles() {
        fn _assert_constructor_exists(_db: sqlx::PgPool) {
            let _svc = SyncPolicyService::new(_db);
        }
    }

    // -----------------------------------------------------------------------
    // ArtifactFilter::matches()
    // -----------------------------------------------------------------------

    #[test]
    fn test_filter_default_passes_everything() {
        let f = ArtifactFilter::default();
        assert!(f.matches("any/path.jar", 999_999, chrono::Utc::now()));
    }

    #[test]
    fn test_filter_max_age_rejects_old() {
        let f = ArtifactFilter {
            max_age_days: Some(7),
            ..Default::default()
        };
        let old = chrono::Utc::now() - chrono::Duration::days(10);
        let recent = chrono::Utc::now() - chrono::Duration::days(3);
        assert!(!f.matches("a.jar", 100, old));
        assert!(f.matches("a.jar", 100, recent));
    }

    #[test]
    fn test_filter_max_size_rejects_large() {
        let f = ArtifactFilter {
            max_size_bytes: Some(1000),
            ..Default::default()
        };
        assert!(!f.matches("a.jar", 2000, chrono::Utc::now()));
        assert!(f.matches("a.jar", 500, chrono::Utc::now()));
        assert!(f.matches("a.jar", 1000, chrono::Utc::now()));
    }

    #[test]
    fn test_filter_include_paths() {
        let f = ArtifactFilter {
            include_paths: vec!["release/*".to_string(), "stable/*".to_string()],
            ..Default::default()
        };
        assert!(f.matches("release/v1.0.jar", 100, chrono::Utc::now()));
        assert!(f.matches("stable/build.tar", 100, chrono::Utc::now()));
        assert!(!f.matches("snapshot/v1.0.jar", 100, chrono::Utc::now()));
    }

    #[test]
    fn test_filter_exclude_paths() {
        let f = ArtifactFilter {
            exclude_paths: vec!["*.snapshot".to_string(), "tmp/*".to_string()],
            ..Default::default()
        };
        assert!(!f.matches("build.snapshot", 100, chrono::Utc::now()));
        assert!(!f.matches("tmp/file.jar", 100, chrono::Utc::now()));
        assert!(f.matches("release/file.jar", 100, chrono::Utc::now()));
    }

    #[test]
    fn test_filter_combined_constraints() {
        let f = ArtifactFilter {
            max_age_days: Some(30),
            max_size_bytes: Some(5000),
            include_paths: vec!["release/*".to_string()],
            exclude_paths: vec!["*.tmp".to_string()],
            match_tags: HashMap::new(),
        };
        let now = chrono::Utc::now();
        // Passes all constraints
        assert!(f.matches("release/v1.jar", 1000, now));
        // Fails: wrong path
        assert!(!f.matches("snapshot/v1.jar", 1000, now));
        // Fails: too large
        assert!(!f.matches("release/v1.jar", 10_000, now));
        // Fails: excluded
        assert!(!f.matches("release/build.tmp", 1000, now));
        // Fails: too old
        let old = now - chrono::Duration::days(60);
        assert!(!f.matches("release/v1.jar", 1000, old));
    }

    #[test]
    fn test_filter_empty_include_means_all() {
        let f = ArtifactFilter {
            include_paths: vec![],
            ..Default::default()
        };
        assert!(f.matches("anything/at/all.bin", 100, chrono::Utc::now()));
    }

    // -----------------------------------------------------------------------
    // matches_with_tags tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_matches_with_tags_empty_filter_passes_all() {
        let f = ArtifactFilter::default();
        let tags = vec![("distribution".to_string(), "production".to_string())];
        assert!(f.matches_with_tags("a.jar", 100, chrono::Utc::now(), &tags));
        assert!(f.matches_with_tags("a.jar", 100, chrono::Utc::now(), &[]));
    }

    #[test]
    fn test_matches_with_tags_exact_match() {
        let f = ArtifactFilter {
            match_tags: HashMap::from([("distribution".to_string(), "production".to_string())]),
            ..Default::default()
        };
        let matching = vec![("distribution".to_string(), "production".to_string())];
        let wrong_value = vec![("distribution".to_string(), "test".to_string())];
        let missing = vec![("support".to_string(), "ltr".to_string())];

        assert!(f.matches_with_tags("a.jar", 100, chrono::Utc::now(), &matching));
        assert!(!f.matches_with_tags("a.jar", 100, chrono::Utc::now(), &wrong_value));
        assert!(!f.matches_with_tags("a.jar", 100, chrono::Utc::now(), &missing));
        assert!(!f.matches_with_tags("a.jar", 100, chrono::Utc::now(), &[]));
    }

    #[test]
    fn test_matches_with_tags_key_only() {
        let f = ArtifactFilter {
            match_tags: HashMap::from([("distribution".to_string(), String::new())]),
            ..Default::default()
        };
        // Any value for the key should pass
        let with_prod = vec![("distribution".to_string(), "production".to_string())];
        let with_test = vec![("distribution".to_string(), "test".to_string())];
        let with_empty = vec![("distribution".to_string(), String::new())];
        let missing = vec![("other".to_string(), "val".to_string())];

        assert!(f.matches_with_tags("a.jar", 100, chrono::Utc::now(), &with_prod));
        assert!(f.matches_with_tags("a.jar", 100, chrono::Utc::now(), &with_test));
        assert!(f.matches_with_tags("a.jar", 100, chrono::Utc::now(), &with_empty));
        assert!(!f.matches_with_tags("a.jar", 100, chrono::Utc::now(), &missing));
    }

    #[test]
    fn test_matches_with_tags_and_semantics() {
        let f = ArtifactFilter {
            match_tags: HashMap::from([
                ("distribution".to_string(), "production".to_string()),
                ("support".to_string(), "ltr".to_string()),
            ]),
            ..Default::default()
        };
        let both = vec![
            ("distribution".to_string(), "production".to_string()),
            ("support".to_string(), "ltr".to_string()),
        ];
        let only_one = vec![("distribution".to_string(), "production".to_string())];

        assert!(f.matches_with_tags("a.jar", 100, chrono::Utc::now(), &both));
        assert!(!f.matches_with_tags("a.jar", 100, chrono::Utc::now(), &only_one));
    }

    #[test]
    fn test_matches_with_tags_combined_with_path_filter() {
        let f = ArtifactFilter {
            include_paths: vec!["release/*".to_string()],
            match_tags: HashMap::from([("distribution".to_string(), "production".to_string())]),
            ..Default::default()
        };
        let tags = vec![("distribution".to_string(), "production".to_string())];

        // Both path and tags must match
        assert!(f.matches_with_tags("release/v1.jar", 100, chrono::Utc::now(), &tags));
        assert!(!f.matches_with_tags("snapshot/v1.jar", 100, chrono::Utc::now(), &tags));
        assert!(!f.matches_with_tags("release/v1.jar", 100, chrono::Utc::now(), &[]));
    }

    #[test]
    fn test_matches_with_tags_backward_compat() {
        // A filter deserialized from old JSON (no match_tags field) should pass all tags
        let json = r#"{"max_age_days": 30}"#;
        let f: ArtifactFilter = serde_json::from_str(json).unwrap();
        assert!(f.match_tags.is_empty());
        let tags = vec![("anything".to_string(), "here".to_string())];
        assert!(f.matches_with_tags("a.jar", 100, chrono::Utc::now(), &tags));
    }

    // -----------------------------------------------------------------------
    // SyncPolicyRow -> SyncPolicy conversion
    // -----------------------------------------------------------------------

    #[test]
    fn test_sync_policy_row_to_sync_policy_conversion() {
        let now = Utc::now();
        let id = Uuid::new_v4();
        let row = SyncPolicyRow {
            id,
            name: "row-policy".to_string(),
            description: "from row".to_string(),
            enabled: true,
            repo_selector: serde_json::json!({"match_formats": ["docker"]}),
            peer_selector: serde_json::json!({"all": true}),
            replication_mode: "mirror".to_string(),
            priority: 5,
            artifact_filter: serde_json::json!({"max_age_days": 14}),
            precedence: 42,
            created_at: now,
            updated_at: now,
        };
        let policy: SyncPolicy = row.into();
        assert_eq!(policy.id, id);
        assert_eq!(policy.name, "row-policy");
        assert_eq!(policy.description, "from row");
        assert!(policy.enabled);
        assert_eq!(policy.repo_selector["match_formats"][0], "docker");
        assert_eq!(policy.peer_selector["all"], true);
        assert_eq!(policy.replication_mode, "mirror");
        assert_eq!(policy.priority, 5);
        assert_eq!(policy.artifact_filter["max_age_days"], 14);
        assert_eq!(policy.precedence, 42);
        assert_eq!(policy.created_at, now);
        assert_eq!(policy.updated_at, now);
    }

    #[test]
    fn test_sync_policy_row_disabled() {
        let now = Utc::now();
        let row = SyncPolicyRow {
            id: Uuid::nil(),
            name: "disabled".to_string(),
            description: String::new(),
            enabled: false,
            repo_selector: serde_json::json!({}),
            peer_selector: serde_json::json!({}),
            replication_mode: "push".to_string(),
            priority: 0,
            artifact_filter: serde_json::json!({}),
            precedence: 100,
            created_at: now,
            updated_at: now,
        };
        let policy: SyncPolicy = row.into();
        assert!(!policy.enabled);
        assert_eq!(policy.name, "disabled");
    }

    #[test]
    fn test_sync_policy_row_preserves_all_fields() {
        // Ensure every field is carried over without mutation
        let created = Utc::now() - chrono::Duration::hours(24);
        let updated = Utc::now();
        let id = Uuid::new_v4();

        let row = SyncPolicyRow {
            id,
            name: "test-preserve".to_string(),
            description: "Detailed description here".to_string(),
            enabled: true,
            repo_selector: serde_json::json!({"match_labels": {"a": "b"}}),
            peer_selector: serde_json::json!({"match_region": "eu-west-1"}),
            replication_mode: "pull".to_string(),
            priority: 99,
            artifact_filter: serde_json::json!({"max_size_bytes": 5000}),
            precedence: 1,
            created_at: created,
            updated_at: updated,
        };
        let policy: SyncPolicy = row.into();

        assert_eq!(policy.id, id);
        assert_eq!(policy.name, "test-preserve");
        assert_eq!(policy.description, "Detailed description here");
        assert!(policy.enabled);
        assert_eq!(policy.replication_mode, "pull");
        assert_eq!(policy.priority, 99);
        assert_eq!(policy.precedence, 1);
        assert_eq!(policy.created_at, created);
        assert_eq!(policy.updated_at, updated);
    }

    // -----------------------------------------------------------------------
    // ArtifactFilter::matches boundary conditions
    // -----------------------------------------------------------------------

    #[test]
    fn test_filter_max_age_boundary_exact() {
        let f = ArtifactFilter {
            max_age_days: Some(7),
            ..Default::default()
        };
        // Exactly 7 days old should pass (age == limit, not strictly greater)
        let exactly_seven = chrono::Utc::now() - chrono::Duration::days(7);
        assert!(f.matches("a.jar", 100, exactly_seven));
    }

    #[test]
    fn test_filter_max_age_boundary_just_over() {
        let f = ArtifactFilter {
            max_age_days: Some(7),
            ..Default::default()
        };
        // 8 days old should fail
        let eight_days = chrono::Utc::now() - chrono::Duration::days(8);
        assert!(!f.matches("a.jar", 100, eight_days));
    }

    #[test]
    fn test_filter_max_age_zero() {
        // max_age_days = 0 means only artifacts created right now pass
        let f = ArtifactFilter {
            max_age_days: Some(0),
            ..Default::default()
        };
        assert!(f.matches("a.jar", 100, chrono::Utc::now()));
        let one_day_old = chrono::Utc::now() - chrono::Duration::days(1);
        assert!(!f.matches("a.jar", 100, one_day_old));
    }

    #[test]
    fn test_filter_max_size_boundary_exact() {
        let f = ArtifactFilter {
            max_size_bytes: Some(1000),
            ..Default::default()
        };
        // Exactly at the limit should pass (not strictly greater)
        assert!(f.matches("a.jar", 1000, chrono::Utc::now()));
    }

    #[test]
    fn test_filter_max_size_boundary_one_over() {
        let f = ArtifactFilter {
            max_size_bytes: Some(1000),
            ..Default::default()
        };
        assert!(!f.matches("a.jar", 1001, chrono::Utc::now()));
    }

    #[test]
    fn test_filter_max_size_zero() {
        let f = ArtifactFilter {
            max_size_bytes: Some(0),
            ..Default::default()
        };
        assert!(f.matches("a.jar", 0, chrono::Utc::now()));
        assert!(!f.matches("a.jar", 1, chrono::Utc::now()));
    }

    #[test]
    fn test_filter_include_paths_single_pattern() {
        let f = ArtifactFilter {
            include_paths: vec!["release/*".to_string()],
            ..Default::default()
        };
        assert!(f.matches("release/foo.jar", 100, chrono::Utc::now()));
        assert!(!f.matches("snapshot/foo.jar", 100, chrono::Utc::now()));
    }

    #[test]
    fn test_filter_include_paths_no_match_any() {
        let f = ArtifactFilter {
            include_paths: vec!["release/*".to_string(), "stable/*".to_string()],
            ..Default::default()
        };
        // Must match at least one include pattern
        assert!(!f.matches("dev/foo.jar", 100, chrono::Utc::now()));
    }

    #[test]
    fn test_filter_exclude_overrides_include() {
        let f = ArtifactFilter {
            include_paths: vec!["release/*".to_string()],
            exclude_paths: vec!["release/*.tmp".to_string()],
            ..Default::default()
        };
        // Matches include but also matches exclude
        assert!(!f.matches("release/build.tmp", 100, chrono::Utc::now()));
        // Matches include, doesn't match exclude
        assert!(f.matches("release/build.jar", 100, chrono::Utc::now()));
    }

    #[test]
    fn test_filter_exclude_only_no_include() {
        let f = ArtifactFilter {
            exclude_paths: vec!["*.log".to_string()],
            ..Default::default()
        };
        // No include filter means all paths are included, then exclude is applied
        assert!(f.matches("release/v1.jar", 100, chrono::Utc::now()));
        assert!(!f.matches("debug.log", 100, chrono::Utc::now()));
    }

    #[test]
    fn test_filter_empty_path() {
        let f = ArtifactFilter::default();
        assert!(f.matches("", 0, chrono::Utc::now()));
    }

    #[test]
    fn test_filter_wildcard_only_include() {
        let f = ArtifactFilter {
            include_paths: vec!["*".to_string()],
            ..Default::default()
        };
        assert!(f.matches("anything.jar", 100, chrono::Utc::now()));
        assert!(f.matches("deep/nested/path.tar", 100, chrono::Utc::now()));
    }

    // -----------------------------------------------------------------------
    // ArtifactFilter::matches_with_tags additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_matches_with_tags_multiple_tags_on_artifact() {
        // Artifact has more tags than the filter requires; should still pass
        let f = ArtifactFilter {
            match_tags: HashMap::from([("env".to_string(), "prod".to_string())]),
            ..Default::default()
        };
        let tags = vec![
            ("env".to_string(), "prod".to_string()),
            ("team".to_string(), "platform".to_string()),
            ("version".to_string(), "2.0".to_string()),
        ];
        assert!(f.matches_with_tags("a.jar", 100, chrono::Utc::now(), &tags));
    }

    #[test]
    fn test_matches_with_tags_duplicate_keys_in_artifact_tags() {
        // If an artifact has duplicate tag keys, at least one must match
        let f = ArtifactFilter {
            match_tags: HashMap::from([("env".to_string(), "prod".to_string())]),
            ..Default::default()
        };
        let tags = vec![
            ("env".to_string(), "staging".to_string()),
            ("env".to_string(), "prod".to_string()),
        ];
        assert!(f.matches_with_tags("a.jar", 100, chrono::Utc::now(), &tags));
    }

    #[test]
    fn test_matches_with_tags_size_filter_rejects_before_tags() {
        // If the base filter rejects, tags should not even be checked
        let f = ArtifactFilter {
            max_size_bytes: Some(100),
            match_tags: HashMap::from([("env".to_string(), "prod".to_string())]),
            ..Default::default()
        };
        let tags = vec![("env".to_string(), "prod".to_string())];
        // Tags match but size does not
        assert!(!f.matches_with_tags("a.jar", 500, chrono::Utc::now(), &tags));
    }

    #[test]
    fn test_matches_with_tags_key_only_empty_string_value() {
        // When the required value is empty, any value for the key should match
        let f = ArtifactFilter {
            match_tags: HashMap::from([("env".to_string(), String::new())]),
            ..Default::default()
        };
        // Even an empty-value tag should match
        let tags = vec![("env".to_string(), String::new())];
        assert!(f.matches_with_tags("a.jar", 100, chrono::Utc::now(), &tags));
    }

    #[test]
    fn test_matches_with_tags_three_required_all_present() {
        let f = ArtifactFilter {
            match_tags: HashMap::from([
                ("env".to_string(), "prod".to_string()),
                ("team".to_string(), "backend".to_string()),
                ("region".to_string(), "us-east".to_string()),
            ]),
            ..Default::default()
        };
        let tags = vec![
            ("env".to_string(), "prod".to_string()),
            ("team".to_string(), "backend".to_string()),
            ("region".to_string(), "us-east".to_string()),
        ];
        assert!(f.matches_with_tags("a.jar", 100, chrono::Utc::now(), &tags));
    }

    #[test]
    fn test_matches_with_tags_three_required_one_missing() {
        let f = ArtifactFilter {
            match_tags: HashMap::from([
                ("env".to_string(), "prod".to_string()),
                ("team".to_string(), "backend".to_string()),
                ("region".to_string(), "us-east".to_string()),
            ]),
            ..Default::default()
        };
        let tags = vec![
            ("env".to_string(), "prod".to_string()),
            ("team".to_string(), "backend".to_string()),
            // region is missing
        ];
        assert!(!f.matches_with_tags("a.jar", 100, chrono::Utc::now(), &tags));
    }

    // -----------------------------------------------------------------------
    // PeerSelector additional tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_peer_selector_multiple_labels() {
        let sel = PeerSelector {
            all: false,
            match_labels: HashMap::from([
                ("dc".to_string(), "east".to_string()),
                ("tier".to_string(), "edge".to_string()),
                ("env".to_string(), "prod".to_string()),
            ]),
            match_region: None,
            match_peers: vec![],
        };
        let json = serde_json::to_string(&sel).unwrap();
        let roundtrip: PeerSelector = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.match_labels.len(), 3);
        assert_eq!(roundtrip.match_labels["dc"], "east");
        assert_eq!(roundtrip.match_labels["tier"], "edge");
        assert_eq!(roundtrip.match_labels["env"], "prod");
    }

    #[test]
    fn test_peer_selector_multiple_peer_ids() {
        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let id3 = Uuid::new_v4();
        let sel = PeerSelector {
            match_peers: vec![id1, id2, id3],
            ..Default::default()
        };
        let json = serde_json::to_string(&sel).unwrap();
        let roundtrip: PeerSelector = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.match_peers.len(), 3);
        assert!(roundtrip.match_peers.contains(&id1));
        assert!(roundtrip.match_peers.contains(&id2));
        assert!(roundtrip.match_peers.contains(&id3));
    }

    #[test]
    fn test_peer_selector_all_fields_populated() {
        let id = Uuid::new_v4();
        let sel = PeerSelector {
            all: true,
            match_labels: HashMap::from([("zone".to_string(), "a".to_string())]),
            match_region: Some("eu-central-1".to_string()),
            match_peers: vec![id],
        };
        let json = serde_json::to_value(&sel).unwrap();
        assert_eq!(json["all"], true);
        assert_eq!(json["match_labels"]["zone"], "a");
        assert_eq!(json["match_region"], "eu-central-1");
        assert_eq!(json["match_peers"].as_array().unwrap().len(), 1);
    }

    // -----------------------------------------------------------------------
    // UpdateSyncPolicyRequest additional tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_update_request_full() {
        let json = r#"{
            "name": "new-name",
            "description": "new desc",
            "enabled": false,
            "repo_selector": {"match_formats": ["npm"]},
            "peer_selector": {"all": true},
            "replication_mode": "pull",
            "priority": 5,
            "artifact_filter": {"max_size_bytes": 1024},
            "precedence": 10
        }"#;
        let req: UpdateSyncPolicyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, Some("new-name".to_string()));
        assert_eq!(req.description, Some("new desc".to_string()));
        assert_eq!(req.enabled, Some(false));
        assert!(req.repo_selector.is_some());
        assert!(req.peer_selector.is_some());
        assert_eq!(req.replication_mode, Some("pull".to_string()));
        assert_eq!(req.priority, Some(5));
        assert!(req.artifact_filter.is_some());
        assert_eq!(req.precedence, Some(10));
    }

    #[test]
    fn test_update_request_only_enabled() {
        let json = r#"{"enabled": true}"#;
        let req: UpdateSyncPolicyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.enabled, Some(true));
        assert!(req.name.is_none());
        assert!(req.description.is_none());
        assert!(req.replication_mode.is_none());
    }

    #[test]
    fn test_update_request_only_precedence() {
        let json = r#"{"precedence": 999}"#;
        let req: UpdateSyncPolicyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.precedence, Some(999));
        assert!(req.name.is_none());
    }

    #[test]
    fn test_update_request_extra_fields_ignored() {
        let json = r#"{"name": "x", "foo": "bar"}"#;
        let req: UpdateSyncPolicyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, Some("x".to_string()));
    }

    // -----------------------------------------------------------------------
    // CreateSyncPolicyRequest additional tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_request_with_artifact_filter_tags() {
        let json = r#"{
            "name": "tag-policy",
            "artifact_filter": {
                "match_tags": {"env": "prod", "support": "ltr"}
            }
        }"#;
        let req: CreateSyncPolicyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.artifact_filter.match_tags.len(), 2);
        assert_eq!(req.artifact_filter.match_tags["env"], "prod");
        assert_eq!(req.artifact_filter.match_tags["support"], "ltr");
    }

    #[test]
    fn test_create_request_with_peer_selector_all() {
        let json = r#"{
            "name": "all-peers",
            "peer_selector": {"all": true}
        }"#;
        let req: CreateSyncPolicyRequest = serde_json::from_str(json).unwrap();
        assert!(req.peer_selector.all);
    }

    #[test]
    fn test_create_request_with_repo_selector_uuids() {
        let id = Uuid::new_v4();
        let json = format!(
            r#"{{"name": "uuid-policy", "repo_selector": {{"match_repos": ["{}"]}}}}"#,
            id
        );
        let req: CreateSyncPolicyRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req.repo_selector.match_repos.len(), 1);
        assert_eq!(req.repo_selector.match_repos[0], id);
    }

    #[test]
    fn test_create_request_enabled_false() {
        let json = r#"{"name": "disabled-policy", "enabled": false}"#;
        let req: CreateSyncPolicyRequest = serde_json::from_str(json).unwrap();
        assert!(!req.enabled);
    }

    // -----------------------------------------------------------------------
    // EvaluationResult construction and serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluation_result_zero_values() {
        let r = EvaluationResult {
            created: 0,
            updated: 0,
            removed: 0,
            policies_evaluated: 0,
            retroactive_tasks_queued: 0,
        };
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["created"], 0);
        assert_eq!(json["updated"], 0);
        assert_eq!(json["removed"], 0);
        assert_eq!(json["policies_evaluated"], 0);
        assert_eq!(json["retroactive_tasks_queued"], 0);
    }

    #[test]
    fn test_evaluation_result_large_values() {
        let r = EvaluationResult {
            created: 10_000,
            updated: 5_000,
            removed: 2_000,
            policies_evaluated: 50,
            retroactive_tasks_queued: 100_000,
        };
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["created"], 10_000);
        assert_eq!(json["retroactive_tasks_queued"], 100_000);
    }

    #[test]
    fn test_evaluation_result_roundtrip() {
        let r = EvaluationResult {
            created: 3,
            updated: 7,
            removed: 1,
            policies_evaluated: 4,
            retroactive_tasks_queued: 12,
        };
        let json = serde_json::to_string(&r).unwrap();
        let roundtrip: EvaluationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.created, 3);
        assert_eq!(roundtrip.updated, 7);
        assert_eq!(roundtrip.removed, 1);
        assert_eq!(roundtrip.policies_evaluated, 4);
        assert_eq!(roundtrip.retroactive_tasks_queued, 12);
    }

    // -----------------------------------------------------------------------
    // PreviewResult construction and serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_preview_result_with_data() {
        let p = PreviewResult {
            matched_repositories: vec![
                MatchedRepo {
                    id: Uuid::nil(),
                    key: "docker-prod".to_string(),
                    format: "docker".to_string(),
                },
                MatchedRepo {
                    id: Uuid::nil(),
                    key: "npm-prod".to_string(),
                    format: "npm".to_string(),
                },
            ],
            matched_peers: vec![MatchedPeer {
                id: Uuid::nil(),
                name: "peer-east".to_string(),
                region: Some("us-east-1".to_string()),
            }],
            subscription_count: 2,
        };
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["matched_repositories"].as_array().unwrap().len(), 2);
        assert_eq!(json["matched_peers"].as_array().unwrap().len(), 1);
        assert_eq!(json["subscription_count"], 2);
    }

    #[test]
    fn test_preview_result_roundtrip() {
        let p = PreviewResult {
            matched_repositories: vec![MatchedRepo {
                id: Uuid::nil(),
                key: "maven-release".to_string(),
                format: "maven".to_string(),
            }],
            matched_peers: vec![MatchedPeer {
                id: Uuid::nil(),
                name: "peer-1".to_string(),
                region: None,
            }],
            subscription_count: 1,
        };
        let json = serde_json::to_string(&p).unwrap();
        let roundtrip: PreviewResult = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.matched_repositories.len(), 1);
        assert_eq!(roundtrip.matched_repositories[0].key, "maven-release");
        assert_eq!(roundtrip.matched_peers.len(), 1);
        assert_eq!(roundtrip.matched_peers[0].name, "peer-1");
        assert!(roundtrip.matched_peers[0].region.is_none());
        assert_eq!(roundtrip.subscription_count, 1);
    }

    // -----------------------------------------------------------------------
    // MatchedPeer additional tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_matched_peer_roundtrip() {
        let p = MatchedPeer {
            id: Uuid::new_v4(),
            name: "peer-west".to_string(),
            region: Some("us-west-2".to_string()),
        };
        let json = serde_json::to_string(&p).unwrap();
        let roundtrip: MatchedPeer = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.id, p.id);
        assert_eq!(roundtrip.name, "peer-west");
        assert_eq!(roundtrip.region, Some("us-west-2".to_string()));
    }

    #[test]
    fn test_matched_peer_deserialization_from_json() {
        let json = r#"{
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "name": "edge-node",
            "region": "ap-south-1"
        }"#;
        let p: MatchedPeer = serde_json::from_str(json).unwrap();
        assert_eq!(p.name, "edge-node");
        assert_eq!(p.region, Some("ap-south-1".to_string()));
    }

    // -----------------------------------------------------------------------
    // TogglePolicyRequest additional tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_toggle_request_roundtrip() {
        let req = TogglePolicyRequest { enabled: true };
        let json = serde_json::to_string(&req).unwrap();
        let roundtrip: TogglePolicyRequest = serde_json::from_str(&json).unwrap();
        assert!(roundtrip.enabled);
    }

    #[test]
    fn test_toggle_request_extra_fields_ignored() {
        let json = r#"{"enabled": false, "extra": "value"}"#;
        let req: TogglePolicyRequest = serde_json::from_str(json).unwrap();
        assert!(!req.enabled);
    }

    // -----------------------------------------------------------------------
    // ArtifactFilter serialization with match_tags
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifact_filter_with_tags_serialization() {
        let f = ArtifactFilter {
            match_tags: HashMap::from([
                ("env".to_string(), "prod".to_string()),
                ("team".to_string(), String::new()),
            ]),
            ..Default::default()
        };
        let json = serde_json::to_value(&f).unwrap();
        let tags = json["match_tags"].as_object().unwrap();
        assert_eq!(tags.len(), 2);
        assert_eq!(tags["env"], "prod");
        assert_eq!(tags["team"], "");
    }

    #[test]
    fn test_artifact_filter_with_tags_deserialization() {
        let json = r#"{
            "match_tags": {"release": "stable", "arch": "amd64"}
        }"#;
        let f: ArtifactFilter = serde_json::from_str(json).unwrap();
        assert_eq!(f.match_tags.len(), 2);
        assert_eq!(f.match_tags["release"], "stable");
        assert_eq!(f.match_tags["arch"], "amd64");
    }

    #[test]
    fn test_artifact_filter_all_fields_deserialization() {
        let json = r#"{
            "max_age_days": 14,
            "include_paths": ["release/*"],
            "exclude_paths": ["*.tmp"],
            "max_size_bytes": 10485760,
            "match_tags": {"env": "prod"}
        }"#;
        let f: ArtifactFilter = serde_json::from_str(json).unwrap();
        assert_eq!(f.max_age_days, Some(14));
        assert_eq!(f.include_paths, vec!["release/*"]);
        assert_eq!(f.exclude_paths, vec!["*.tmp"]);
        assert_eq!(f.max_size_bytes, Some(10_485_760));
        assert_eq!(f.match_tags.len(), 1);
    }

    // -----------------------------------------------------------------------
    // sql_like_match additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_sql_like_match_pattern_with_special_chars() {
        // Dots and dashes are literal (not regex)
        assert!(sql_like_match("com.example.lib", "com.example.%"));
        assert!(!sql_like_match("com-example-lib", "com.example.%"));
    }

    #[test]
    fn test_sql_like_match_numeric_path() {
        assert!(sql_like_match("v1.2.3", "v%"));
        assert!(sql_like_match("v1.2.3", "v1.%"));
        assert!(!sql_like_match("v2.0.0", "v1.%"));
    }

    #[test]
    fn test_sql_like_match_deeply_nested_path() {
        assert!(sql_like_match(
            "com/example/libs/core/1.0/core-1.0.jar",
            "com/example/%"
        ));
        assert!(!sql_like_match(
            "org/apache/libs/core/1.0/core-1.0.jar",
            "com/example/%"
        ));
    }

    #[test]
    fn test_sql_like_match_trailing_wildcard_with_slash() {
        assert!(sql_like_match("release/v1/artifact.jar", "release/%"));
    }

    #[test]
    fn test_sql_like_match_middle_wildcard_empty_match() {
        // The wildcard can match zero characters
        assert!(sql_like_match("libs-v2", "libs-%v2"));
    }

    // -----------------------------------------------------------------------
    // validate_replication_mode additional tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_replication_mode_case_sensitivity() {
        // Only lowercase variants are valid
        assert!(!validate_replication_mode("Push"));
        assert!(!validate_replication_mode("PULL"));
        assert!(!validate_replication_mode("Mirror"));
    }

    #[test]
    fn test_validate_replication_mode_whitespace() {
        assert!(!validate_replication_mode(" push"));
        assert!(!validate_replication_mode("push "));
        assert!(!validate_replication_mode(" push "));
    }

    // -----------------------------------------------------------------------
    // labels_match_all additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_labels_match_all_both_empty() {
        let repo_labels: Vec<(&str, &str)> = vec![];
        let required = HashMap::new();
        assert!(labels_match_all(&repo_labels, &required));
    }

    #[test]
    fn test_labels_match_all_partial_key_no_match() {
        // Key "en" should not match "env"
        let repo_labels = vec![("env", "prod")];
        let mut required = HashMap::new();
        required.insert("en".to_string(), "prod".to_string());
        assert!(!labels_match_all(&repo_labels, &required));
    }

    #[test]
    fn test_labels_match_all_extra_repo_labels() {
        // Repo has labels beyond what's required; should still pass
        let repo_labels = vec![
            ("env", "prod"),
            ("tier", "1"),
            ("team", "backend"),
            ("region", "us"),
        ];
        let mut required = HashMap::new();
        required.insert("env".to_string(), "prod".to_string());
        assert!(labels_match_all(&repo_labels, &required));
    }

    // -----------------------------------------------------------------------
    // filter_by_formats additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_filter_by_formats_single_element() {
        let formats = vec!["maven".to_string()];
        assert!(filter_by_formats("maven", &formats));
        assert!(!filter_by_formats("npm", &formats));
    }

    #[test]
    fn test_filter_by_formats_many_formats() {
        let formats = vec![
            "docker".to_string(),
            "maven".to_string(),
            "npm".to_string(),
            "pypi".to_string(),
            "cargo".to_string(),
        ];
        assert!(filter_by_formats("cargo", &formats));
        assert!(filter_by_formats("PYPI", &formats));
        assert!(!filter_by_formats("rubygems", &formats));
    }

    #[test]
    fn test_filter_by_formats_mixed_case_in_list() {
        let formats = vec!["Docker".to_string(), "MAVEN".to_string(), "npm".to_string()];
        assert!(filter_by_formats("docker", &formats));
        assert!(filter_by_formats("maven", &formats));
        assert!(filter_by_formats("NPM", &formats));
    }

    // -----------------------------------------------------------------------
    // glob_to_sql_pattern additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_glob_to_sql_pattern_double_star() {
        // ** is two wildcards, becomes %%
        assert_eq!(glob_to_sql_pattern("**"), "%%");
    }

    #[test]
    fn test_glob_to_sql_pattern_complex_path() {
        assert_eq!(glob_to_sql_pattern("com/*/libs/*/v*"), "com/%/libs/%/v%");
    }

    #[test]
    fn test_glob_to_sql_pattern_no_change_for_percent() {
        // If the input already contains %, it stays as-is
        assert_eq!(glob_to_sql_pattern("already%"), "already%");
    }

    // -----------------------------------------------------------------------
    // compute_subscription_count edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_compute_subscription_count_both_zero() {
        assert_eq!(compute_subscription_count(0, 0), 0);
    }

    #[test]
    fn test_compute_subscription_count_large() {
        assert_eq!(compute_subscription_count(100, 50), 5000);
    }

    // -----------------------------------------------------------------------
    // SyncPolicy serialization roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn test_sync_policy_roundtrip() {
        let now = Utc::now();
        let policy = SyncPolicy {
            id: Uuid::new_v4(),
            name: "roundtrip-test".to_string(),
            description: "testing roundtrip".to_string(),
            enabled: true,
            repo_selector: serde_json::json!({"match_formats": ["docker"]}),
            peer_selector: serde_json::json!({"match_region": "us-east-1"}),
            replication_mode: "mirror".to_string(),
            priority: 7,
            artifact_filter: serde_json::json!({"max_age_days": 30}),
            precedence: 50,
            created_at: now,
            updated_at: now,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let roundtrip: SyncPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.id, policy.id);
        assert_eq!(roundtrip.name, "roundtrip-test");
        assert_eq!(roundtrip.replication_mode, "mirror");
        assert_eq!(roundtrip.priority, 7);
        assert_eq!(roundtrip.precedence, 50);
    }

    #[test]
    fn test_sync_policy_replication_modes_serialize() {
        for mode in ["push", "pull", "mirror"] {
            let policy = SyncPolicy {
                id: Uuid::nil(),
                name: format!("{mode}-policy"),
                description: String::new(),
                enabled: true,
                repo_selector: serde_json::json!({}),
                peer_selector: serde_json::json!({}),
                replication_mode: mode.to_string(),
                priority: 0,
                artifact_filter: serde_json::json!({}),
                precedence: 100,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };
            let json = serde_json::to_value(&policy).unwrap();
            assert_eq!(json["replication_mode"], mode);
        }
    }

    // -----------------------------------------------------------------------
    // validate_policy_name additional edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_policy_name_long_name() {
        let long_name = "a".repeat(1000);
        assert!(validate_policy_name(&long_name).is_ok());
    }

    #[test]
    fn test_validate_policy_name_special_chars() {
        assert!(validate_policy_name("prod-sync/v2").is_ok());
        assert!(validate_policy_name("policy@team").is_ok());
        assert!(validate_policy_name("policy with spaces").is_ok());
    }

    // -----------------------------------------------------------------------
    // classify_policy_db_error edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_classify_policy_db_error_partial_match() {
        // "duplicate key" anywhere in the message should trigger the conflict path
        let result = classify_policy_db_error(
            "ERROR: duplicate key value violates unique constraint \"sync_policies_name_key\"",
            "my-policy",
        );
        assert_eq!(result, "Sync policy 'my-policy' already exists");
    }

    #[test]
    fn test_classify_policy_db_error_empty_message() {
        let result = classify_policy_db_error("", "my-policy");
        assert_eq!(result, "");
    }

    #[test]
    fn test_classify_policy_db_error_preserves_original() {
        let msg = "timeout waiting for connection pool";
        let result = classify_policy_db_error(msg, "ignored");
        assert_eq!(result, msg);
    }

    // -----------------------------------------------------------------------
    // ArtifactFilter::matches with combined all-constraints
    // -----------------------------------------------------------------------

    #[test]
    fn test_filter_all_constraints_pass() {
        let f = ArtifactFilter {
            max_age_days: Some(30),
            max_size_bytes: Some(10_000),
            include_paths: vec!["release/*".to_string()],
            exclude_paths: vec!["release/*.tmp".to_string()],
            match_tags: HashMap::new(),
        };
        let recent = chrono::Utc::now() - chrono::Duration::days(5);
        assert!(f.matches("release/build.jar", 5000, recent));
    }

    #[test]
    fn test_filter_all_constraints_fail_each_independently() {
        let f = ArtifactFilter {
            max_age_days: Some(7),
            max_size_bytes: Some(1000),
            include_paths: vec!["release/*".to_string()],
            exclude_paths: vec!["release/*.tmp".to_string()],
            match_tags: HashMap::new(),
        };
        let now = chrono::Utc::now();
        let old = now - chrono::Duration::days(30);

        // Fails: too old
        assert!(!f.matches("release/build.jar", 500, old));
        // Fails: too large
        assert!(!f.matches("release/build.jar", 5000, now));
        // Fails: wrong path
        assert!(!f.matches("snapshot/build.jar", 500, now));
        // Fails: excluded
        assert!(!f.matches("release/build.tmp", 500, now));
        // Passes: all good
        assert!(f.matches("release/build.jar", 500, now));
    }

    // -----------------------------------------------------------------------
    // RepoSelector deserialization edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_repo_selector_many_formats() {
        let json = r#"{
            "match_formats": ["docker", "maven", "npm", "pypi", "cargo", "nuget", "helm"]
        }"#;
        let sel: RepoSelector = serde_json::from_str(json).unwrap();
        assert_eq!(sel.match_formats.len(), 7);
    }

    #[test]
    fn test_repo_selector_many_uuids() {
        let ids: Vec<Uuid> = (0..10).map(|_| Uuid::new_v4()).collect();
        let sel = RepoSelector {
            match_repos: ids.clone(),
            ..Default::default()
        };
        let json = serde_json::to_string(&sel).unwrap();
        let roundtrip: RepoSelector = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.match_repos.len(), 10);
        for id in &ids {
            assert!(roundtrip.match_repos.contains(id));
        }
    }

    #[test]
    fn test_repo_selector_empty_pattern() {
        let sel = RepoSelector {
            match_pattern: Some(String::new()),
            ..Default::default()
        };
        let json = serde_json::to_string(&sel).unwrap();
        let roundtrip: RepoSelector = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.match_pattern, Some(String::new()));
    }

    // -----------------------------------------------------------------------
    // CreateSyncPolicyRequest with nested selectors roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn test_create_request_roundtrip() {
        let json = r#"{
            "name": "roundtrip",
            "description": "full roundtrip test",
            "enabled": true,
            "repo_selector": {
                "match_labels": {"env": "prod"},
                "match_formats": ["docker"],
                "match_pattern": "libs-*"
            },
            "peer_selector": {
                "all": false,
                "match_region": "us-east-1"
            },
            "replication_mode": "mirror",
            "priority": 3,
            "artifact_filter": {
                "max_age_days": 14,
                "include_paths": ["release/*"],
                "max_size_bytes": 1048576,
                "match_tags": {"stable": "true"}
            },
            "precedence": 25
        }"#;
        let req: CreateSyncPolicyRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.name, "roundtrip");
        assert_eq!(req.repo_selector.match_labels["env"], "prod");
        assert_eq!(req.repo_selector.match_formats, vec!["docker"]);
        assert_eq!(req.repo_selector.match_pattern, Some("libs-*".to_string()));
        assert!(!req.peer_selector.all);
        assert_eq!(
            req.peer_selector.match_region,
            Some("us-east-1".to_string())
        );
        assert_eq!(req.replication_mode, "mirror");
        assert_eq!(req.priority, 3);
        assert_eq!(req.artifact_filter.max_age_days, Some(14));
        assert_eq!(req.artifact_filter.include_paths, vec!["release/*"]);
        assert_eq!(req.artifact_filter.max_size_bytes, Some(1_048_576));
        assert_eq!(req.artifact_filter.match_tags["stable"], "true");
        assert_eq!(req.precedence, 25);
    }
}
