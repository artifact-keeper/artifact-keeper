//! Artifact label management service.
//!
//! Provides CRUD operations for key:value labels on artifacts,
//! used for sync policy tag-based filtering.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::repository_label_service::LabelEntry;

/// A label attached to an artifact.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct ArtifactLabel {
    pub id: Uuid,
    pub artifact_id: Uuid,
    pub label_key: String,
    pub label_value: String,
    pub created_at: DateTime<Utc>,
}

/// Service for managing artifact labels.
pub struct ArtifactLabelService {
    db: PgPool,
}

impl ArtifactLabelService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Get all labels for an artifact, ordered by key.
    pub async fn get_labels(&self, artifact_id: Uuid) -> Result<Vec<ArtifactLabel>> {
        let labels: Vec<ArtifactLabel> = sqlx::query_as(
            r#"
            SELECT id, artifact_id, label_key, label_value, created_at
            FROM artifact_labels
            WHERE artifact_id = $1
            ORDER BY label_key
            "#,
        )
        .bind(artifact_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(labels)
    }

    /// Replace all labels on an artifact with the given set.
    pub async fn set_labels(
        &self,
        artifact_id: Uuid,
        labels: &[LabelEntry],
    ) -> Result<Vec<ArtifactLabel>> {
        let mut tx = self.db.begin().await?;

        sqlx::query("DELETE FROM artifact_labels WHERE artifact_id = $1")
            .bind(artifact_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        for label in labels {
            sqlx::query(
                r#"
                INSERT INTO artifact_labels (artifact_id, label_key, label_value)
                VALUES ($1, $2, $3)
                "#,
            )
            .bind(artifact_id)
            .bind(&label.key)
            .bind(&label.value)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        }

        tx.commit().await?;

        self.get_labels(artifact_id).await
    }

    /// Add or update a single label (upsert by key).
    pub async fn add_label(
        &self,
        artifact_id: Uuid,
        key: &str,
        value: &str,
    ) -> Result<ArtifactLabel> {
        let label: ArtifactLabel = sqlx::query_as(
            r#"
            INSERT INTO artifact_labels (artifact_id, label_key, label_value)
            VALUES ($1, $2, $3)
            ON CONFLICT (artifact_id, label_key) DO UPDATE SET label_value = $3
            RETURNING id, artifact_id, label_key, label_value, created_at
            "#,
        )
        .bind(artifact_id)
        .bind(key)
        .bind(value)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(label)
    }

    /// Remove a label by key. Returns true if a label was deleted.
    pub async fn remove_label(&self, artifact_id: Uuid, key: &str) -> Result<bool> {
        let result =
            sqlx::query("DELETE FROM artifact_labels WHERE artifact_id = $1 AND label_key = $2")
                .bind(artifact_id)
                .bind(key)
                .execute(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(result.rows_affected() > 0)
    }

    /// Find artifacts matching all given label selectors (AND semantics).
    pub async fn find_artifacts_by_labels(&self, selectors: &[LabelEntry]) -> Result<Vec<Uuid>> {
        if selectors.is_empty() {
            return Ok(vec![]);
        }

        let mut artifact_ids: Option<Vec<Uuid>> = None;

        for selector in selectors {
            let ids: Vec<Uuid> = if selector.value.is_empty() {
                sqlx::query_scalar("SELECT artifact_id FROM artifact_labels WHERE label_key = $1")
                    .bind(&selector.key)
                    .fetch_all(&self.db)
                    .await
                    .map_err(|e| AppError::Database(e.to_string()))?
            } else {
                sqlx::query_scalar(
                    "SELECT artifact_id FROM artifact_labels WHERE label_key = $1 AND label_value = $2",
                )
                .bind(&selector.key)
                .bind(&selector.value)
                .fetch_all(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?
            };

            artifact_ids = Some(match artifact_ids {
                None => ids,
                Some(existing) => existing.into_iter().filter(|id| ids.contains(id)).collect(),
            });
        }

        Ok(artifact_ids.unwrap_or_default())
    }

    /// Batch-fetch labels for multiple artifacts.
    pub async fn get_labels_batch(
        &self,
        artifact_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, Vec<ArtifactLabel>>> {
        if artifact_ids.is_empty() {
            return Ok(HashMap::new());
        }

        let labels: Vec<ArtifactLabel> = sqlx::query_as(
            r#"
            SELECT id, artifact_id, label_key, label_value, created_at
            FROM artifact_labels
            WHERE artifact_id = ANY($1)
            ORDER BY artifact_id, label_key
            "#,
        )
        .bind(artifact_ids)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        let mut map: HashMap<Uuid, Vec<ArtifactLabel>> = HashMap::new();
        for label in labels {
            map.entry(label.artifact_id).or_default().push(label);
        }

        Ok(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_artifact_label_serialization() {
        let label = ArtifactLabel {
            id: Uuid::nil(),
            artifact_id: Uuid::nil(),
            label_key: "distribution".to_string(),
            label_value: "production".to_string(),
            created_at: Utc::now(),
        };
        let json: serde_json::Value = serde_json::to_value(&label).unwrap();
        assert!(json.get("label_key").is_some());
        assert!(json.get("label_value").is_some());
        assert!(json.get("artifact_id").is_some());
    }

    #[test]
    fn test_artifact_label_clone() {
        let label = ArtifactLabel {
            id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            label_key: "support".to_string(),
            label_value: "ltr".to_string(),
            created_at: Utc::now(),
        };
        let cloned = label.clone();
        assert_eq!(cloned.id, label.id);
        assert_eq!(cloned.label_key, "support");
        assert_eq!(cloned.label_value, "ltr");
    }

    #[test]
    fn test_service_new_compiles() {
        fn _assert_constructor_exists(_db: sqlx::PgPool) {
            let _svc = ArtifactLabelService::new(_db);
        }
    }
}
