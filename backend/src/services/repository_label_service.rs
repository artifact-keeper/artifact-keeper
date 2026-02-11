//! Repository label management service.
//!
//! Provides CRUD operations for key:value labels on repositories,
//! used for sync policy matching and organizational grouping.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, Result};

/// A label attached to a repository.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct RepositoryLabel {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub label_key: String,
    pub label_value: String,
    pub created_at: DateTime<Utc>,
}

/// A key-value pair for setting or querying labels.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LabelEntry {
    pub key: String,
    pub value: String,
}

/// Service for managing repository labels.
pub struct RepositoryLabelService {
    db: PgPool,
}

impl RepositoryLabelService {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    /// Get all labels for a repository, ordered by key.
    pub async fn get_labels(&self, repository_id: Uuid) -> Result<Vec<RepositoryLabel>> {
        let labels: Vec<RepositoryLabel> = sqlx::query_as(
            r#"
            SELECT id, repository_id, label_key, label_value, created_at
            FROM repository_labels
            WHERE repository_id = $1
            ORDER BY label_key
            "#,
        )
        .bind(repository_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(labels)
    }

    /// Replace all labels on a repository with the given set.
    pub async fn set_labels(
        &self,
        repository_id: Uuid,
        labels: &[LabelEntry],
    ) -> Result<Vec<RepositoryLabel>> {
        let mut tx = self.db.begin().await?;

        sqlx::query("DELETE FROM repository_labels WHERE repository_id = $1")
            .bind(repository_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;

        for label in labels {
            sqlx::query(
                r#"
                INSERT INTO repository_labels (repository_id, label_key, label_value)
                VALUES ($1, $2, $3)
                "#,
            )
            .bind(repository_id)
            .bind(&label.key)
            .bind(&label.value)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        }

        tx.commit().await?;

        self.get_labels(repository_id).await
    }

    /// Add or update a single label (upsert by key).
    pub async fn add_label(
        &self,
        repository_id: Uuid,
        key: &str,
        value: &str,
    ) -> Result<RepositoryLabel> {
        let label: RepositoryLabel = sqlx::query_as(
            r#"
            INSERT INTO repository_labels (repository_id, label_key, label_value)
            VALUES ($1, $2, $3)
            ON CONFLICT (repository_id, label_key) DO UPDATE SET label_value = $3
            RETURNING id, repository_id, label_key, label_value, created_at
            "#,
        )
        .bind(repository_id)
        .bind(key)
        .bind(value)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(label)
    }

    /// Remove a label by key. Returns true if a label was deleted.
    pub async fn remove_label(&self, repository_id: Uuid, key: &str) -> Result<bool> {
        let result = sqlx::query(
            "DELETE FROM repository_labels WHERE repository_id = $1 AND label_key = $2",
        )
        .bind(repository_id)
        .bind(key)
        .execute(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(result.rows_affected() > 0)
    }

    /// Find repositories matching all given label selectors.
    ///
    /// Each selector specifies a key and optional value. If the value is empty,
    /// any repository with that key (regardless of value) matches. All selectors
    /// must match (AND semantics).
    pub async fn find_repos_by_labels(&self, selectors: &[LabelEntry]) -> Result<Vec<Uuid>> {
        if selectors.is_empty() {
            return Ok(vec![]);
        }

        let mut repo_ids: Option<Vec<Uuid>> = None;

        for selector in selectors {
            let ids: Vec<Uuid> = if selector.value.is_empty() {
                sqlx::query_scalar(
                    "SELECT repository_id FROM repository_labels WHERE label_key = $1",
                )
                .bind(&selector.key)
                .fetch_all(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?
            } else {
                sqlx::query_scalar(
                    "SELECT repository_id FROM repository_labels WHERE label_key = $1 AND label_value = $2",
                )
                .bind(&selector.key)
                .bind(&selector.value)
                .fetch_all(&self.db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?
            };

            repo_ids = Some(match repo_ids {
                None => ids,
                Some(existing) => existing.into_iter().filter(|id| ids.contains(id)).collect(),
            });
        }

        Ok(repo_ids.unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_label_entry_serialization() {
        let entry = LabelEntry {
            key: "env".to_string(),
            value: "production".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("env"));
        assert!(json.contains("production"));
    }

    #[test]
    fn test_label_entry_deserialization() {
        let json = r#"{"key": "tier", "value": "critical"}"#;
        let entry: LabelEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.key, "tier");
        assert_eq!(entry.value, "critical");
    }

    #[test]
    fn test_label_entry_empty_value() {
        let json = r#"{"key": "production", "value": ""}"#;
        let entry: LabelEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.key, "production");
        assert_eq!(entry.value, "");
    }

    #[test]
    fn test_label_entry_roundtrip() {
        let entry = LabelEntry {
            key: "region".to_string(),
            value: "us-east-1".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: LabelEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.key, "region");
        assert_eq!(deserialized.value, "us-east-1");
    }

    #[test]
    fn test_label_entry_special_characters() {
        let entry = LabelEntry {
            key: "app/version".to_string(),
            value: "v1.2.3-beta+build.42".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let deserialized: LabelEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.key, "app/version");
        assert_eq!(deserialized.value, "v1.2.3-beta+build.42");
    }

    #[test]
    fn test_label_entry_vec_serialization() {
        let entries = vec![
            LabelEntry {
                key: "env".to_string(),
                value: "prod".to_string(),
            },
            LabelEntry {
                key: "tier".to_string(),
                value: "1".to_string(),
            },
        ];
        let json = serde_json::to_string(&entries).unwrap();
        let deserialized: Vec<LabelEntry> = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.len(), 2);
        assert_eq!(deserialized[0].key, "env");
        assert_eq!(deserialized[1].key, "tier");
    }

    // -----------------------------------------------------------------------
    // JSON contract tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_label_entry_json_field_names() {
        let entry = LabelEntry {
            key: "env".to_string(),
            value: "prod".to_string(),
        };
        let json: serde_json::Value = serde_json::to_value(&entry).unwrap();
        assert!(json.get("key").is_some(), "Must have 'key' field");
        assert!(json.get("value").is_some(), "Must have 'value' field");
        let obj = json.as_object().unwrap();
        assert_eq!(obj.len(), 2, "LabelEntry should have exactly 2 fields");
    }

    #[test]
    fn test_repository_label_struct_field_names() {
        let label = RepositoryLabel {
            id: Uuid::nil(),
            repository_id: Uuid::nil(),
            label_key: "test".to_string(),
            label_value: "val".to_string(),
            created_at: chrono::Utc::now(),
        };
        let json: serde_json::Value = serde_json::to_value(&label).unwrap();

        // DB model uses label_key/label_value (matches column names)
        assert!(json.get("label_key").is_some(), "Must have 'label_key'");
        assert!(json.get("label_value").is_some(), "Must have 'label_value'");
        assert!(json.get("id").is_some());
        assert!(json.get("repository_id").is_some());
        assert!(json.get("created_at").is_some());
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_label_entry_missing_key_fails() {
        let json = r#"{"value": "test"}"#;
        let result = serde_json::from_str::<LabelEntry>(json);
        assert!(result.is_err(), "LabelEntry requires 'key' field");
    }

    #[test]
    fn test_label_entry_missing_value_fails() {
        // value is required (no #[serde(default)] on LabelEntry)
        let json = r#"{"key": "test"}"#;
        let result = serde_json::from_str::<LabelEntry>(json);
        assert!(result.is_err(), "LabelEntry requires 'value' field");
    }

    #[test]
    fn test_label_entry_extra_fields_ignored() {
        let json = r#"{"key": "env", "value": "prod", "extra": "ignored"}"#;
        let entry: LabelEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.key, "env");
        assert_eq!(entry.value, "prod");
    }

    #[test]
    fn test_label_entry_unicode_keys() {
        let entry = LabelEntry {
            key: "環境".to_string(),
            value: "本番".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let roundtrip: LabelEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.key, "環境");
        assert_eq!(roundtrip.value, "本番");
    }

    #[test]
    fn test_label_entry_with_colons_and_slashes() {
        // Common in Kubernetes-style labels: app.kubernetes.io/name
        let entry = LabelEntry {
            key: "app.kubernetes.io/name".to_string(),
            value: "artifact-keeper".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let roundtrip: LabelEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.key, "app.kubernetes.io/name");
    }

    #[test]
    fn test_label_entry_empty_key_is_allowed_by_serde() {
        // Serde allows empty strings; validation should happen at the service/handler level
        let json = r#"{"key": "", "value": "test"}"#;
        let entry: LabelEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.key, "");
    }

    #[test]
    fn test_label_entry_clone() {
        let entry = LabelEntry {
            key: "env".to_string(),
            value: "prod".to_string(),
        };
        let cloned = entry.clone();
        assert_eq!(cloned.key, "env");
        assert_eq!(cloned.value, "prod");
    }

    #[test]
    fn test_repository_label_clone() {
        let label = RepositoryLabel {
            id: Uuid::new_v4(),
            repository_id: Uuid::new_v4(),
            label_key: "tier".to_string(),
            label_value: "critical".to_string(),
            created_at: chrono::Utc::now(),
        };
        let cloned = label.clone();
        assert_eq!(cloned.id, label.id);
        assert_eq!(cloned.label_key, "tier");
    }

    #[test]
    fn test_service_new() {
        // PgPool is an Arc wrapper, so we can't construct one without a real DB.
        // This test just verifies the struct layout is correct by checking
        // that the constructor type signature compiles.
        fn _assert_constructor_exists(_db: sqlx::PgPool) {
            let _svc = RepositoryLabelService::new(_db);
        }
    }
}
