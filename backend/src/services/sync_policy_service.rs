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

/// Repository selector: determines which repositories a policy applies to.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RepoSelector {
    /// Label key-value pairs that must all match (AND semantics).
    #[serde(default)]
    pub match_labels: HashMap<String, String>,
    /// Repository format types to include (e.g. "docker", "maven"). OR semantics.
    #[serde(default)]
    pub match_formats: Vec<String>,
    /// Glob-like name pattern (e.g. "libs-*"). Only `*` wildcard supported,
    /// translated to SQL `LIKE` with `%`.
    #[serde(default)]
    pub match_pattern: Option<String>,
    /// Explicit repository UUIDs to include.
    #[serde(default)]
    pub match_repos: Vec<Uuid>,
}

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
}

/// Preview result showing what a policy would match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewResult {
    pub matched_repositories: Vec<MatchedRepo>,
    pub matched_peers: Vec<MatchedPeer>,
    pub subscription_count: usize,
}

/// A matched repository in a preview.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedRepo {
    pub id: Uuid,
    pub key: String,
    pub format: String,
}

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
struct RepoRow {
    id: Uuid,
    key: String,
    format: String,
}

#[derive(Debug, sqlx::FromRow)]
struct PeerRow {
    id: Uuid,
    name: String,
    region: Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
struct LabelRow {
    repository_id: Uuid,
    label_key: String,
    label_value: String,
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
        for ((peer_id, repo_id), policy_id) in &desired {
            // Find the policy to get replication mode
            let policy = policies.iter().find(|p| p.id == *policy_id);
            let replication_mode = policy
                .map(|p| p.replication_mode.as_str())
                .unwrap_or("push");

            match existing_set.get(&(*peer_id, *repo_id)) {
                Some(Some(existing_policy_id)) if existing_policy_id == policy_id => {
                    // Already exists with the same policy — update replication mode just in case
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
                    // Exists but with a different policy — update policy_id
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
                    // New subscription — insert. Use ON CONFLICT to handle the case where
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
                    }
                }
            }
        }

        Ok(EvaluationResult {
            created,
            updated,
            removed,
            policies_evaluated,
        })
    }

    /// Preview what a policy configuration would match without making changes.
    pub async fn preview_policy(&self, req: CreateSyncPolicyRequest) -> Result<PreviewResult> {
        let repos = self.resolve_repos(&req.repo_selector).await?;
        let peers = self.resolve_peers(&req.peer_selector).await?;

        let matched_repositories: Vec<MatchedRepo> = repos
            .into_iter()
            .map(|r| MatchedRepo {
                id: r.id,
                key: r.key,
                format: r.format,
            })
            .collect();

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
        for (peer_id, policy_id) in &desired {
            let policy = policies.iter().find(|p| p.id == *policy_id);
            let replication_mode = policy
                .map(|p| p.replication_mode.as_str())
                .unwrap_or("push");

            sqlx::query(
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
        }

        Ok(())
    }

    /// Re-evaluate policies for a specific peer (e.g., when a new peer joins).
    pub async fn evaluate_for_peer(&self, peer_id: Uuid) -> Result<()> {
        let policies = self.list_enabled_policies().await?;

        // Determine which policies match this peer
        let mut matching_policies: Vec<(&SyncPolicy, Vec<RepoRow>)> = Vec::new();

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
        for (repo_id, policy_id) in &desired {
            let policy = policies.iter().find(|p| p.id == *policy_id);
            let replication_mode = policy
                .map(|p| p.replication_mode.as_str())
                .unwrap_or("push");

            sqlx::query(
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
        }

        Ok(())
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

    /// Resolve repositories matching a selector.
    async fn resolve_repos(&self, selector: &RepoSelector) -> Result<Vec<RepoRow>> {
        // If explicit repo IDs are given, use them directly
        if !selector.match_repos.is_empty() {
            let repos: Vec<RepoRow> = sqlx::query_as(
                r#"
                SELECT id, key, format::TEXT
                FROM repositories
                WHERE id = ANY($1)
                "#,
            )
            .bind(&selector.match_repos)
            .fetch_all(&self.db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
            return Ok(repos);
        }

        // Start with all repositories
        let mut all_repos: Vec<RepoRow> =
            sqlx::query_as("SELECT id, key, format::TEXT FROM repositories ORDER BY key")
                .fetch_all(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;

        let has_any_filter = !selector.match_labels.is_empty()
            || !selector.match_formats.is_empty()
            || selector.match_pattern.is_some();

        // If no filters at all, return empty (a policy with an empty selector matches nothing)
        if !has_any_filter {
            return Ok(vec![]);
        }

        // Filter by format
        if !selector.match_formats.is_empty() {
            let formats: Vec<String> = selector
                .match_formats
                .iter()
                .map(|f| f.to_lowercase())
                .collect();
            all_repos.retain(|r| formats.contains(&r.format.to_lowercase()));
        }

        // Filter by name pattern (glob: * -> %)
        if let Some(pattern) = &selector.match_pattern {
            let sql_pattern = pattern.replace('*', "%");
            all_repos.retain(|r| sql_like_match(&r.key, &sql_pattern));
        }

        // Filter by labels (AND semantics: all label pairs must match)
        if !selector.match_labels.is_empty() {
            let label_repo_ids = self.resolve_repos_by_labels(&selector.match_labels).await?;
            all_repos.retain(|r| label_repo_ids.contains(&r.id));
        }

        Ok(all_repos)
    }

    /// Find repository IDs that have all the given labels.
    async fn resolve_repos_by_labels(&self, labels: &HashMap<String, String>) -> Result<Vec<Uuid>> {
        if labels.is_empty() {
            return Ok(vec![]);
        }

        let all_labels: Vec<LabelRow> =
            sqlx::query_as("SELECT repository_id, label_key, label_value FROM repository_labels")
                .fetch_all(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;

        // Group labels by repository
        let mut repo_labels: HashMap<Uuid, Vec<(&str, &str)>> = HashMap::new();
        for row in &all_labels {
            repo_labels
                .entry(row.repository_id)
                .or_default()
                .push((&row.label_key, &row.label_value));
        }

        // Find repos that have ALL required labels
        let mut matching: Vec<Uuid> = Vec::new();
        for (repo_id, repo_label_list) in &repo_labels {
            let all_match = labels
                .iter()
                .all(|(k, v)| repo_label_list.iter().any(|(lk, lv)| lk == k && lv == v));
            if all_match {
                matching.push(*repo_id);
            }
        }

        Ok(matching)
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

/// Simple SQL LIKE pattern matching for in-memory filtering.
/// Supports `%` as wildcard (matches zero or more characters).
fn sql_like_match(value: &str, pattern: &str) -> bool {
    let parts: Vec<&str> = pattern.split('%').collect();

    if parts.len() == 1 {
        // No wildcards — exact match
        return value == pattern;
    }

    let mut pos = 0;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            // Must start with this prefix
            if !value.starts_with(part) {
                return false;
            }
            pos = part.len();
        } else if i == parts.len() - 1 {
            // Must end with this suffix
            if !value[pos..].ends_with(part) {
                return false;
            }
            pos = value.len();
        } else {
            // Must contain this part somewhere after pos
            match value[pos..].find(part) {
                Some(found) => pos += found + part.len(),
                None => return false,
            }
        }
    }

    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
        };
        let json: serde_json::Value = serde_json::to_value(&f).unwrap();
        assert!(json.get("max_age_days").is_some());
        assert!(json.get("include_paths").is_some());
        assert!(json.get("exclude_paths").is_some());
        assert!(json.get("max_size_bytes").is_some());
    }

    #[test]
    fn test_evaluation_result_json_field_names() {
        let r = EvaluationResult {
            created: 5,
            updated: 3,
            removed: 1,
            policies_evaluated: 2,
        };
        let json: serde_json::Value = serde_json::to_value(&r).unwrap();
        assert_eq!(json["created"], 5);
        assert_eq!(json["updated"], 3);
        assert_eq!(json["removed"], 1);
        assert_eq!(json["policies_evaluated"], 2);
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
}
