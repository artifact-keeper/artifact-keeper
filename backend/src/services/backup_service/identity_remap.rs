//! Map archived user, role and group ids onto the rows this server already
//! has (#5856).
//!
//! Every install creates its own bootstrap admin and seeds its own roles, each
//! with a random id. A restore into a fresh server therefore meets an archived
//! `admin` whose username already exists under another id, and archived roles
//! whose names do. Those identity rows conflict and are skipped
//! (`ON CONFLICT DO NOTHING`), and every row that refers to them by the
//! archived id (a repository's `created_by`, an artifact's `uploaded_by`, a
//! `user_roles` row, ...) would then fail its foreign key. The remap is built
//! before any row is inserted and applied to every row that references one of
//! these tables, so those rows point at the server's own identity rows.

use std::collections::HashMap;

use sqlx::PgConnection;
use uuid::Uuid;

use crate::error::{AppError, Result};

/// The identity tables a restore matches by natural key, with that key. Every
/// key here carries a unique constraint, so a live match is the row the
/// archived one conflicts with.
const IDENTITY_KEYS: &[(&str, &str)] =
    &[("users", "username"), ("roles", "name"), ("groups", "name")];

/// `permissions` names its principal by type and id, with no foreign key.
const POLYMORPHIC_PRINCIPALS: &[(&str, &str, &str)] =
    &[("permissions", "principal_type", "principal_id")];

/// Archived identity ids that exist on this server under another id, and the
/// columns that refer to them.
#[derive(Debug, Default)]
pub(super) struct IdentityRemap {
    /// Referenced table to (archived id, live id).
    ids: HashMap<&'static str, HashMap<Uuid, Uuid>>,
    /// Referencing table to its (column, referenced table) foreign keys.
    columns: HashMap<String, Vec<(String, &'static str)>>,
}

impl IdentityRemap {
    /// Build the remap from the archive's identity rows and the live ones.
    ///
    /// `rows_of` returns the archived rows of a table, or `None` when the
    /// archive does not carry it.
    pub(super) async fn build(
        conn: &mut PgConnection,
        rows_of: impl Fn(&str) -> Result<Option<Vec<serde_json::Value>>>,
    ) -> Result<Self> {
        let mut remap = Self::default();
        for &(table, key) in IDENTITY_KEYS {
            let Some(rows) = rows_of(table)? else {
                continue;
            };
            let archived = archived_keys(&rows, key);
            if archived.is_empty() {
                continue;
            }
            let names: Vec<String> = archived.keys().cloned().collect();
            // `table` and `key` come from IDENTITY_KEYS, never from the archive.
            let query = format!("SELECT id, {key}::text FROM {table} WHERE {key} = ANY($1)");
            let live: Vec<(Uuid, String)> = sqlx::query_as(sqlx::AssertSqlSafe(&*query))
                .bind(&names)
                .fetch_all(&mut *conn)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?;
            let ids = remap_ids(&archived, live);
            if !ids.is_empty() {
                tracing::info!(
                    table,
                    remapped = ids.len(),
                    "restore maps archived ids onto existing rows by {key}"
                );
                remap.ids.insert(table, ids);
            }
        }
        if remap.ids.is_empty() {
            return Ok(remap);
        }

        let referenced: Vec<&str> = remap.ids.keys().copied().collect();
        // Single-column foreign keys only; every user, role and group
        // reference in the schema is one.
        let fks: Vec<(String, String, String)> = sqlx::query_as(
            "SELECT cl.relname::text, att.attname::text, ref.relname::text \
             FROM pg_constraint c \
             JOIN pg_class cl ON cl.oid = c.conrelid \
             JOIN pg_class ref ON ref.oid = c.confrelid \
             JOIN pg_namespace n ON n.oid = cl.relnamespace \
             JOIN pg_attribute att ON att.attrelid = c.conrelid AND att.attnum = c.conkey[1] \
             WHERE c.contype = 'f' AND array_length(c.conkey, 1) = 1 \
               AND n.nspname = current_schema() AND ref.relname = ANY($1)",
        )
        .bind(&referenced)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
        for (table, column, target) in fks {
            let Some(&target) = referenced.iter().find(|t| **t == target) else {
                continue;
            };
            remap
                .columns
                .entry(table)
                .or_default()
                .push((column, target));
        }
        Ok(remap)
    }

    /// Rewrite the identity references of one archived `table` row.
    pub(super) fn apply(&self, table: &str, row: &mut serde_json::Value) {
        let Some(fields) = row.as_object_mut() else {
            return;
        };
        for (column, target) in self.columns.get(table).into_iter().flatten() {
            self.rewrite(fields, column, target);
        }
        for &(_, type_column, id_column) in POLYMORPHIC_PRINCIPALS
            .iter()
            .filter(|(polymorphic, _, _)| *polymorphic == table)
        {
            let target = match fields.get(type_column).and_then(|t| t.as_str()) {
                Some("user") => "users",
                Some("group") => "groups",
                _ => continue,
            };
            self.rewrite(fields, id_column, target);
        }
    }

    fn rewrite(
        &self,
        fields: &mut serde_json::Map<String, serde_json::Value>,
        column: &str,
        target: &str,
    ) {
        let Some(serde_json::Value::String(value)) = fields.get_mut(column) else {
            return;
        };
        let live = Uuid::parse_str(value)
            .ok()
            .and_then(|archived| self.ids.get(target)?.get(&archived));
        if let Some(live) = live {
            *value = live.to_string();
        }
    }

    #[cfg(test)]
    pub(super) fn from_parts(
        ids: HashMap<&'static str, HashMap<Uuid, Uuid>>,
        columns: HashMap<String, Vec<(String, &'static str)>>,
    ) -> Self {
        Self { ids, columns }
    }
}

/// Natural key to archived id, for the rows that carry both.
fn archived_keys(rows: &[serde_json::Value], key: &str) -> HashMap<String, Uuid> {
    rows.iter()
        .filter_map(|row| {
            let id = Uuid::parse_str(row.get("id")?.as_str()?).ok()?;
            Some((row.get(key)?.as_str()?.to_string(), id))
        })
        .collect()
}

/// Archived id to live id, for every natural key that exists under another id.
fn remap_ids(archived: &HashMap<String, Uuid>, live: Vec<(Uuid, String)>) -> HashMap<Uuid, Uuid> {
    live.into_iter()
        .filter_map(|(live_id, name)| {
            let archived_id = *archived.get(&name)?;
            (archived_id != live_id).then_some((archived_id, live_id))
        })
        .collect()
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_keys_that_exist_under_another_id_are_remapped_5856() {
        let (same, moved, absent) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let live_moved = Uuid::new_v4();
        let rows = vec![
            json!({"id": same.to_string(), "username": "kept"}),
            json!({"id": moved.to_string(), "username": "admin"}),
            json!({"id": absent.to_string(), "username": "new"}),
            json!({"id": "not-a-uuid", "username": "broken"}),
            json!({"username": "no-id"}),
        ];
        let archived = archived_keys(&rows, "username");
        assert_eq!(archived.len(), 3);
        let ids = remap_ids(
            &archived,
            vec![(same, "kept".into()), (live_moved, "admin".into())],
        );
        assert_eq!(ids, HashMap::from([(moved, live_moved)]));
    }

    #[test]
    fn apply_rewrites_only_mapped_references_of_known_columns_5856() {
        let (old_admin, new_admin) = (Uuid::new_v4(), Uuid::new_v4());
        let (old_role, new_role) = (Uuid::new_v4(), Uuid::new_v4());
        let other = Uuid::new_v4();
        let remap = IdentityRemap::from_parts(
            HashMap::from([
                ("users", HashMap::from([(old_admin, new_admin)])),
                ("roles", HashMap::from([(old_role, new_role)])),
            ]),
            HashMap::from([(
                "user_roles".to_string(),
                vec![
                    ("user_id".to_string(), "users"),
                    ("role_id".to_string(), "roles"),
                ],
            )]),
        );
        let mut row = json!({"user_id": old_admin.to_string(), "role_id": old_role.to_string()});
        remap.apply("user_roles", &mut row);
        assert_eq!(
            row,
            json!({"user_id": new_admin.to_string(), "role_id": new_role.to_string()})
        );

        let mut unmapped = json!({"user_id": other.to_string(), "role_id": null});
        remap.apply("user_roles", &mut unmapped);
        assert_eq!(
            unmapped,
            json!({"user_id": other.to_string(), "role_id": null})
        );

        // A table with no foreign key to an identity table is left alone,
        // even when one of its values happens to equal a remapped id.
        let mut unrelated = json!({"user_id": old_admin.to_string()});
        remap.apply("system_settings", &mut unrelated);
        assert_eq!(unrelated, json!({"user_id": old_admin.to_string()}));
    }

    #[test]
    fn apply_rewrites_a_permission_by_its_principal_type_5856() {
        let (old_admin, new_admin) = (Uuid::new_v4(), Uuid::new_v4());
        let (old_group, new_group) = (Uuid::new_v4(), Uuid::new_v4());
        let remap = IdentityRemap::from_parts(
            HashMap::from([
                ("users", HashMap::from([(old_admin, new_admin)])),
                ("groups", HashMap::from([(old_group, new_group)])),
            ]),
            HashMap::new(),
        );
        for (kind, old, new) in [
            ("user", old_admin, new_admin),
            ("group", old_group, new_group),
        ] {
            let mut row = json!({"principal_type": kind, "principal_id": old.to_string()});
            remap.apply("permissions", &mut row);
            assert_eq!(row["principal_id"], json!(new.to_string()), "{kind}");
        }
        // The id of the other kind is not touched.
        let mut row = json!({"principal_type": "group", "principal_id": old_admin.to_string()});
        remap.apply("permissions", &mut row);
        assert_eq!(row["principal_id"], json!(old_admin.to_string()));
    }
}
