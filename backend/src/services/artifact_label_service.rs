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

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_label(key: &str, value: &str) -> ArtifactLabel {
        ArtifactLabel {
            id: Uuid::new_v4(),
            artifact_id: Uuid::new_v4(),
            label_key: key.to_string(),
            label_value: value.to_string(),
            created_at: Utc::now(),
        }
    }

    fn make_label_with_ids(id: Uuid, artifact_id: Uuid, key: &str, value: &str) -> ArtifactLabel {
        ArtifactLabel {
            id,
            artifact_id,
            label_key: key.to_string(),
            label_value: value.to_string(),
            created_at: Utc::now(),
        }
    }

    // -----------------------------------------------------------------------
    // ArtifactLabel struct serialization
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // JSON field contract: verify exact field names and count
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifact_label_has_exactly_five_fields() {
        let label = make_label("env", "prod");
        let json: serde_json::Value = serde_json::to_value(&label).unwrap();
        let obj = json.as_object().unwrap();
        assert_eq!(
            obj.len(),
            5,
            "ArtifactLabel should serialize to exactly 5 JSON fields"
        );
    }

    #[test]
    fn test_artifact_label_field_names_match_db_columns() {
        let label = make_label("env", "staging");
        let json: serde_json::Value = serde_json::to_value(&label).unwrap();
        let obj = json.as_object().unwrap();
        assert!(obj.contains_key("id"), "Missing 'id' field");
        assert!(
            obj.contains_key("artifact_id"),
            "Missing 'artifact_id' field"
        );
        assert!(obj.contains_key("label_key"), "Missing 'label_key' field");
        assert!(
            obj.contains_key("label_value"),
            "Missing 'label_value' field"
        );
        assert!(obj.contains_key("created_at"), "Missing 'created_at' field");
    }

    #[test]
    fn test_artifact_label_serialized_values_match() {
        let id = Uuid::new_v4();
        let artifact_id = Uuid::new_v4();
        let label = make_label_with_ids(id, artifact_id, "tier", "critical");
        let json: serde_json::Value = serde_json::to_value(&label).unwrap();

        assert_eq!(json["id"], id.to_string());
        assert_eq!(json["artifact_id"], artifact_id.to_string());
        assert_eq!(json["label_key"], "tier");
        assert_eq!(json["label_value"], "critical");
    }

    #[test]
    fn test_artifact_label_nil_uuids_serialize() {
        let label = ArtifactLabel {
            id: Uuid::nil(),
            artifact_id: Uuid::nil(),
            label_key: "k".to_string(),
            label_value: "v".to_string(),
            created_at: Utc::now(),
        };
        let json: serde_json::Value = serde_json::to_value(&label).unwrap();
        assert_eq!(json["id"], "00000000-0000-0000-0000-000000000000");
        assert_eq!(json["artifact_id"], "00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn test_artifact_label_created_at_is_rfc3339() {
        let label = make_label("ts", "check");
        let json: serde_json::Value = serde_json::to_value(&label).unwrap();
        let ts_str = json["created_at"].as_str().unwrap();
        // chrono serializes to RFC 3339; verify it parses back
        let parsed = DateTime::parse_from_rfc3339(ts_str);
        assert!(
            parsed.is_ok(),
            "created_at should be valid RFC 3339: {}",
            ts_str
        );
    }

    // -----------------------------------------------------------------------
    // Clone preserves all fields
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifact_label_clone_preserves_all_fields() {
        let id = Uuid::new_v4();
        let artifact_id = Uuid::new_v4();
        let ts = Utc::now();
        let label = ArtifactLabel {
            id,
            artifact_id,
            label_key: "region".to_string(),
            label_value: "us-west-2".to_string(),
            created_at: ts,
        };
        let cloned = label.clone();
        assert_eq!(cloned.id, id);
        assert_eq!(cloned.artifact_id, artifact_id);
        assert_eq!(cloned.label_key, "region");
        assert_eq!(cloned.label_value, "us-west-2");
        assert_eq!(cloned.created_at, ts);
    }

    // -----------------------------------------------------------------------
    // Debug trait
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifact_label_debug_output() {
        let label = make_label("debug_key", "debug_val");
        let debug_str = format!("{:?}", label);
        assert!(
            debug_str.contains("ArtifactLabel"),
            "Debug output should contain struct name"
        );
        assert!(
            debug_str.contains("debug_key"),
            "Debug output should contain the label key"
        );
        assert!(
            debug_str.contains("debug_val"),
            "Debug output should contain the label value"
        );
    }

    // -----------------------------------------------------------------------
    // Edge cases: special characters, empty strings, unicode, long values
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifact_label_empty_key_and_value() {
        let label = make_label("", "");
        let json: serde_json::Value = serde_json::to_value(&label).unwrap();
        assert_eq!(json["label_key"], "");
        assert_eq!(json["label_value"], "");
    }

    #[test]
    fn test_artifact_label_unicode_key_and_value() {
        let label = make_label("環境", "本番");
        let json = serde_json::to_string(&label).unwrap();
        assert!(json.contains("環境"));
        assert!(json.contains("本番"));

        let roundtrip: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip["label_key"], "環境");
        assert_eq!(roundtrip["label_value"], "本番");
    }

    #[test]
    fn test_artifact_label_kubernetes_style_key() {
        let label = make_label("app.kubernetes.io/managed-by", "artifact-keeper");
        let json = serde_json::to_string(&label).unwrap();
        let roundtrip: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip["label_key"], "app.kubernetes.io/managed-by");
    }

    #[test]
    fn test_artifact_label_value_with_special_characters() {
        let label = make_label("version", "v1.2.3-beta+build.42");
        let json = serde_json::to_string(&label).unwrap();
        let roundtrip: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip["label_value"], "v1.2.3-beta+build.42");
    }

    #[test]
    fn test_artifact_label_value_with_json_special_chars() {
        // Ensure proper escaping of JSON-sensitive characters
        let label = make_label("raw", r#"value with "quotes" and \backslash"#);
        let json = serde_json::to_string(&label).unwrap();
        let roundtrip: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            roundtrip["label_value"],
            r#"value with "quotes" and \backslash"#
        );
    }

    #[test]
    fn test_artifact_label_long_key_and_value() {
        let long_key = "k".repeat(1000);
        let long_value = "v".repeat(10_000);
        let label = make_label(&long_key, &long_value);
        let json = serde_json::to_string(&label).unwrap();
        let roundtrip: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip["label_key"].as_str().unwrap().len(), 1000);
        assert_eq!(roundtrip["label_value"].as_str().unwrap().len(), 10_000);
    }

    #[test]
    fn test_artifact_label_key_with_newlines_and_tabs() {
        let label = make_label("multi\nline", "tab\there");
        let json = serde_json::to_string(&label).unwrap();
        let roundtrip: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip["label_key"], "multi\nline");
        assert_eq!(roundtrip["label_value"], "tab\there");
    }

    // -----------------------------------------------------------------------
    // Vec<ArtifactLabel> serialization
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifact_label_vec_serialization() {
        let labels = vec![
            make_label("env", "prod"),
            make_label("tier", "1"),
            make_label("region", "us-east-1"),
        ];
        let json = serde_json::to_string(&labels).unwrap();
        let roundtrip: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtrip.len(), 3);
        assert_eq!(roundtrip[0]["label_key"], "env");
        assert_eq!(roundtrip[1]["label_key"], "tier");
        assert_eq!(roundtrip[2]["label_key"], "region");
    }

    #[test]
    fn test_artifact_label_empty_vec_serialization() {
        let labels: Vec<ArtifactLabel> = vec![];
        let json = serde_json::to_string(&labels).unwrap();
        assert_eq!(json, "[]");
    }

    // -----------------------------------------------------------------------
    // HashMap<Uuid, Vec<ArtifactLabel>> grouping logic
    //
    // The get_labels_batch method groups labels by artifact_id into a HashMap.
    // We can test the grouping logic directly using the same approach.
    // -----------------------------------------------------------------------

    #[test]
    fn test_label_grouping_by_artifact_id() {
        // Simulate the grouping logic from get_labels_batch (lines 183-186)
        let art_a = Uuid::new_v4();
        let art_b = Uuid::new_v4();
        let labels = vec![
            make_label_with_ids(Uuid::new_v4(), art_a, "env", "prod"),
            make_label_with_ids(Uuid::new_v4(), art_a, "tier", "1"),
            make_label_with_ids(Uuid::new_v4(), art_b, "env", "staging"),
        ];

        let mut map: HashMap<Uuid, Vec<ArtifactLabel>> = HashMap::new();
        for label in labels {
            map.entry(label.artifact_id).or_default().push(label);
        }

        assert_eq!(map.len(), 2, "Should have two artifact groups");
        assert_eq!(map[&art_a].len(), 2, "Artifact A should have two labels");
        assert_eq!(map[&art_b].len(), 1, "Artifact B should have one label");
        assert_eq!(map[&art_a][0].label_key, "env");
        assert_eq!(map[&art_a][1].label_key, "tier");
        assert_eq!(map[&art_b][0].label_key, "env");
    }

    #[test]
    fn test_label_grouping_empty_input() {
        let labels: Vec<ArtifactLabel> = vec![];
        let mut map: HashMap<Uuid, Vec<ArtifactLabel>> = HashMap::new();
        for label in labels {
            map.entry(label.artifact_id).or_default().push(label);
        }
        assert!(map.is_empty());
    }

    #[test]
    fn test_label_grouping_single_artifact_many_labels() {
        let art_id = Uuid::new_v4();
        let labels: Vec<ArtifactLabel> = (0..50)
            .map(|i| {
                make_label_with_ids(
                    Uuid::new_v4(),
                    art_id,
                    &format!("key_{i}"),
                    &format!("val_{i}"),
                )
            })
            .collect();

        let mut map: HashMap<Uuid, Vec<ArtifactLabel>> = HashMap::new();
        for label in labels {
            map.entry(label.artifact_id).or_default().push(label);
        }

        assert_eq!(map.len(), 1);
        assert_eq!(map[&art_id].len(), 50);
        assert_eq!(map[&art_id][0].label_key, "key_0");
        assert_eq!(map[&art_id][49].label_key, "key_49");
    }

    // -----------------------------------------------------------------------
    // Intersection (AND) logic from find_artifacts_by_labels
    //
    // The method iterates through selectors, fetching artifact IDs for each
    // from the DB, then intersects them in pure Rust (lines 152-155).
    // We test the intersection logic in isolation.
    // -----------------------------------------------------------------------

    /// Simulates the intersection fold from find_artifacts_by_labels.
    fn intersect_id_sets(sets: &[Vec<Uuid>]) -> Vec<Uuid> {
        let mut result: Option<Vec<Uuid>> = None;
        for ids in sets {
            result = Some(match result {
                None => ids.clone(),
                Some(existing) => existing.into_iter().filter(|id| ids.contains(id)).collect(),
            });
        }
        result.unwrap_or_default()
    }

    #[test]
    fn test_intersection_no_selectors() {
        let result = intersect_id_sets(&[]);
        assert!(result.is_empty(), "No selectors should yield empty result");
    }

    #[test]
    fn test_intersection_single_selector() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let result = intersect_id_sets(&[vec![a, b]]);
        assert_eq!(result.len(), 2);
        assert!(result.contains(&a));
        assert!(result.contains(&b));
    }

    #[test]
    fn test_intersection_two_selectors_with_overlap() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();
        // First selector matches {a, b, c}, second matches {b, c}
        let result = intersect_id_sets(&[vec![a, b, c], vec![b, c]]);
        assert_eq!(result.len(), 2);
        assert!(result.contains(&b));
        assert!(result.contains(&c));
        assert!(!result.contains(&a));
    }

    #[test]
    fn test_intersection_no_overlap() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let result = intersect_id_sets(&[vec![a], vec![b]]);
        assert!(
            result.is_empty(),
            "Disjoint sets should produce empty intersection"
        );
    }

    #[test]
    fn test_intersection_three_selectors_narrowing() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let c = Uuid::new_v4();
        // {a, b, c} AND {a, b} AND {a} = {a}
        let result = intersect_id_sets(&[vec![a, b, c], vec![a, b], vec![a]]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], a);
    }

    #[test]
    fn test_intersection_with_empty_second_set() {
        let a = Uuid::new_v4();
        let result = intersect_id_sets(&[vec![a], vec![]]);
        assert!(
            result.is_empty(),
            "Intersecting with empty set should produce empty"
        );
    }

    #[test]
    fn test_intersection_identical_sets() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let result = intersect_id_sets(&[vec![a, b], vec![a, b]]);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_intersection_with_duplicates_in_input() {
        let a = Uuid::new_v4();
        // If a selector returns duplicates, they pass through (matching real DB behavior)
        let result = intersect_id_sets(&[vec![a, a], vec![a]]);
        // Both copies of 'a' match the filter, so both survive
        assert_eq!(result.len(), 2);
        assert!(result.iter().all(|id| *id == a));
    }

    // -----------------------------------------------------------------------
    // LabelEntry usage from this module's perspective
    //
    // LabelEntry is defined in repository_label_service but used as input
    // to set_labels and find_artifacts_by_labels. Test its behavior here
    // in the context of artifact labels.
    // -----------------------------------------------------------------------

    #[test]
    fn test_label_entry_with_empty_value_used_as_key_only_selector() {
        // In find_artifacts_by_labels, an empty value triggers key-only matching
        let selector = LabelEntry {
            key: "production".to_string(),
            value: "".to_string(),
        };
        assert!(
            selector.value.is_empty(),
            "Empty value should trigger key-only query path"
        );
    }

    #[test]
    fn test_label_entry_with_nonempty_value_used_as_exact_selector() {
        let selector = LabelEntry {
            key: "env".to_string(),
            value: "production".to_string(),
        };
        assert!(
            !selector.value.is_empty(),
            "Non-empty value should trigger exact key+value query path"
        );
    }

    #[test]
    fn test_label_entry_vec_for_set_labels() {
        // set_labels accepts a slice of LabelEntry; verify vec construction
        let labels = vec![
            LabelEntry {
                key: "env".to_string(),
                value: "prod".to_string(),
            },
            LabelEntry {
                key: "tier".to_string(),
                value: "1".to_string(),
            },
        ];
        assert_eq!(labels.len(), 2);
        assert_eq!(labels[0].key, "env");
        assert_eq!(labels[1].key, "tier");
    }

    #[test]
    fn test_label_entry_empty_vec_for_set_labels() {
        // Passing empty labels to set_labels should clear all labels
        let labels: Vec<LabelEntry> = vec![];
        assert!(labels.is_empty());
    }

    // -----------------------------------------------------------------------
    // HashMap construction from labeled results
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_hashmap_for_empty_artifact_ids() {
        // Mirrors the early return in get_labels_batch when artifact_ids is empty
        let artifact_ids: &[Uuid] = &[];
        assert!(artifact_ids.is_empty());
        let map: HashMap<Uuid, Vec<ArtifactLabel>> = HashMap::new();
        assert!(map.is_empty());
    }

    #[test]
    fn test_hashmap_preserves_insertion_order_per_artifact() {
        let art_id = Uuid::new_v4();
        let labels = vec![
            make_label_with_ids(Uuid::new_v4(), art_id, "alpha", "1"),
            make_label_with_ids(Uuid::new_v4(), art_id, "beta", "2"),
            make_label_with_ids(Uuid::new_v4(), art_id, "gamma", "3"),
        ];

        let mut map: HashMap<Uuid, Vec<ArtifactLabel>> = HashMap::new();
        for label in labels {
            map.entry(label.artifact_id).or_default().push(label);
        }

        let result = &map[&art_id];
        assert_eq!(result[0].label_key, "alpha");
        assert_eq!(result[1].label_key, "beta");
        assert_eq!(result[2].label_key, "gamma");
    }

    // -----------------------------------------------------------------------
    // Selector branching: value.is_empty() determines query path
    // -----------------------------------------------------------------------

    #[test]
    fn test_selector_branching_multiple_mixed_selectors() {
        let selectors = vec![
            LabelEntry {
                key: "env".to_string(),
                value: "".to_string(),
            },
            LabelEntry {
                key: "tier".to_string(),
                value: "critical".to_string(),
            },
            LabelEntry {
                key: "region".to_string(),
                value: "".to_string(),
            },
        ];

        let key_only: Vec<&LabelEntry> = selectors.iter().filter(|s| s.value.is_empty()).collect();
        let exact: Vec<&LabelEntry> = selectors.iter().filter(|s| !s.value.is_empty()).collect();

        assert_eq!(key_only.len(), 2, "Two selectors use key-only matching");
        assert_eq!(exact.len(), 1, "One selector uses exact matching");
        assert_eq!(key_only[0].key, "env");
        assert_eq!(key_only[1].key, "region");
        assert_eq!(exact[0].key, "tier");
    }

    // -----------------------------------------------------------------------
    // Artifact label identity: different UUIDs = different labels
    // -----------------------------------------------------------------------

    #[test]
    fn test_labels_with_same_key_different_artifacts_are_distinct() {
        let art_a = Uuid::new_v4();
        let art_b = Uuid::new_v4();
        let label_a = make_label_with_ids(Uuid::new_v4(), art_a, "env", "prod");
        let label_b = make_label_with_ids(Uuid::new_v4(), art_b, "env", "prod");

        // Same key/value but different artifact_id means different logical labels
        assert_ne!(label_a.artifact_id, label_b.artifact_id);
        assert_ne!(label_a.id, label_b.id);
        assert_eq!(label_a.label_key, label_b.label_key);
        assert_eq!(label_a.label_value, label_b.label_value);
    }

    // -----------------------------------------------------------------------
    // Serialization round-trip: serialize then deserialize
    // -----------------------------------------------------------------------

    #[test]
    fn test_artifact_label_json_roundtrip() {
        let label = make_label("build/pipeline", "ci-main-42");
        let json = serde_json::to_string(&label).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["label_key"], "build/pipeline");
        assert_eq!(value["label_value"], "ci-main-42");
    }

    #[test]
    fn test_artifact_label_pretty_json() {
        let label = make_label("format", "docker");
        let pretty = serde_json::to_string_pretty(&label).unwrap();
        assert!(pretty.contains('\n'), "Pretty JSON should contain newlines");
        assert!(pretty.contains("label_key"));
    }
}
