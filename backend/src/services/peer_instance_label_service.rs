//! Peer instance label management service.
//!
//! Provides CRUD operations for key:value labels on peer instances,
//! used for sync policy matching and organizational grouping.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::repository_label_service::LabelEntry;

/// A label attached to a peer instance.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct PeerInstanceLabel {
    pub id: Uuid,
    pub peer_instance_id: Uuid,
    pub label_key: String,
    pub label_value: String,
    pub created_at: DateTime<Utc>,
}

/// Service for managing peer instance labels.
pub struct PeerInstanceLabelService {
    db: PgPool,
}

impl PeerInstanceLabelService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Get all labels for a peer instance, ordered by key.
    pub async fn get_labels(&self, peer_instance_id: Uuid) -> Result<Vec<PeerInstanceLabel>> {
        let labels: Vec<PeerInstanceLabel> = sqlx::query_as(
            r#"
            SELECT id, peer_instance_id, label_key, label_value, created_at
            FROM peer_instance_labels
            WHERE peer_instance_id = $1
            ORDER BY label_key
            "#,
        )
        .bind(peer_instance_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(labels)
    }

    /// Replace all labels on a peer instance with the given set.
    pub async fn set_labels(
        &self,
        peer_instance_id: Uuid,
        labels: &[LabelEntry],
    ) -> Result<Vec<PeerInstanceLabel>> {
        let mut tx = self.db.begin().await?;

        sqlx::query("DELETE FROM peer_instance_labels WHERE peer_instance_id = $1")
            .bind(peer_instance_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        for label in labels {
            sqlx::query(
                r#"
                INSERT INTO peer_instance_labels (peer_instance_id, label_key, label_value)
                VALUES ($1, $2, $3)
                "#,
            )
            .bind(peer_instance_id)
            .bind(&label.key)
            .bind(&label.value)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        }

        tx.commit().await?;

        self.get_labels(peer_instance_id).await
    }

    /// Add or update a single label (upsert by key).
    pub async fn add_label(
        &self,
        peer_instance_id: Uuid,
        key: &str,
        value: &str,
    ) -> Result<PeerInstanceLabel> {
        let label: PeerInstanceLabel = sqlx::query_as(
            r#"
            INSERT INTO peer_instance_labels (peer_instance_id, label_key, label_value)
            VALUES ($1, $2, $3)
            ON CONFLICT (peer_instance_id, label_key) DO UPDATE SET label_value = $3
            RETURNING id, peer_instance_id, label_key, label_value, created_at
            "#,
        )
        .bind(peer_instance_id)
        .bind(key)
        .bind(value)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(label)
    }

    /// Remove a label by key. Returns true if a label was deleted.
    pub async fn remove_label(&self, peer_instance_id: Uuid, key: &str) -> Result<bool> {
        let result = sqlx::query(
            "DELETE FROM peer_instance_labels WHERE peer_instance_id = $1 AND label_key = $2",
        )
        .bind(peer_instance_id)
        .bind(key)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(result.rows_affected() > 0)
    }

    /// Find peer instances matching all given label selectors.
    ///
    /// Each selector specifies a key and optional value. If the value is empty,
    /// any peer with that key (regardless of value) matches. All selectors
    /// must match (AND semantics).
    pub async fn find_peers_by_labels(&self, selectors: &[LabelEntry]) -> Result<Vec<Uuid>> {
        if selectors.is_empty() {
            return Ok(vec![]);
        }

        let mut peer_ids: Option<Vec<Uuid>> = None;

        for selector in selectors {
            let ids: Vec<Uuid> = if selector.value.is_empty() {
                sqlx::query_scalar(
                    "SELECT peer_instance_id FROM peer_instance_labels WHERE label_key = $1",
                )
                .bind(&selector.key)
                .fetch_all(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?
            } else {
                sqlx::query_scalar(
                    "SELECT peer_instance_id FROM peer_instance_labels WHERE label_key = $1 AND label_value = $2",
                )
                .bind(&selector.key)
                .bind(&selector.value)
                .fetch_all(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?
            };

            peer_ids = Some(match peer_ids {
                None => ids,
                Some(existing) => existing.into_iter().filter(|id| ids.contains(id)).collect(),
            });
        }

        Ok(peer_ids.unwrap_or_default())
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_instance_label_serialization() {
        let label = PeerInstanceLabel {
            id: Uuid::nil(),
            peer_instance_id: Uuid::nil(),
            label_key: "region".to_string(),
            label_value: "us-east-1".to_string(),
            created_at: chrono::Utc::now(),
        };
        let json: serde_json::Value = serde_json::to_value(&label).unwrap();
        assert!(json.get("label_key").is_some());
        assert!(json.get("label_value").is_some());
        assert!(json.get("peer_instance_id").is_some());
    }

    #[test]
    fn test_peer_instance_label_clone() {
        let label = PeerInstanceLabel {
            id: Uuid::new_v4(),
            peer_instance_id: Uuid::new_v4(),
            label_key: "tier".to_string(),
            label_value: "critical".to_string(),
            created_at: chrono::Utc::now(),
        };
        let cloned = label.clone();
        assert_eq!(cloned.id, label.id);
        assert_eq!(cloned.label_key, "tier");
    }

    #[test]
    fn test_peer_instance_label_field_names() {
        let label = PeerInstanceLabel {
            id: Uuid::nil(),
            peer_instance_id: Uuid::nil(),
            label_key: "env".to_string(),
            label_value: "prod".to_string(),
            created_at: chrono::Utc::now(),
        };
        let json: serde_json::Value = serde_json::to_value(&label).unwrap();
        let obj = json.as_object().unwrap();
        assert_eq!(
            obj.len(),
            5,
            "PeerInstanceLabel should have exactly 5 fields"
        );
        assert!(obj.contains_key("id"));
        assert!(obj.contains_key("peer_instance_id"));
        assert!(obj.contains_key("label_key"));
        assert!(obj.contains_key("label_value"));
        assert!(obj.contains_key("created_at"));
    }

    #[test]
    fn test_service_new() {
        fn _assert_constructor_exists(_db: sqlx::PgPool) {
            let _svc = PeerInstanceLabelService::new(_db);
        }
    }
}
