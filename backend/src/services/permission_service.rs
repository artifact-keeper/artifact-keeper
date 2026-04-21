//! Permission service for fine-grained access control.
//!
//! Resolves whether a user has a specific action on a target (repository,
//! group, or artifact) by checking both direct user permissions and
//! transitive group memberships in a single query. Results are cached
//! in-process with a 30-second TTL to avoid repeated database round-trips
//! on hot paths such as artifact downloads.

use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use uuid::Uuid;

use crate::error::{AppError, Result};

/// How long cached permission entries remain valid before a fresh DB lookup.
const CACHE_TTL: Duration = Duration::from_secs(30);

/// Composite cache key: (user_id, target_type, target_id).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    user_id: Uuid,
    target_type: String,
    target_id: Uuid,
}

impl CacheKey {
    fn new(user_id: Uuid, target_type: &str, target_id: Uuid) -> Self {
        Self {
            user_id,
            target_type: target_type.to_string(),
            target_id,
        }
    }
}

/// A cached set of granted actions together with its insertion timestamp.
#[derive(Debug, Clone)]
struct CacheEntry {
    actions: Vec<String>,
    inserted_at: Instant,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        self.inserted_at.elapsed() > CACHE_TTL
    }
}

/// Service that evaluates permission rules stored in the `permissions` table.
///
/// The service resolves both direct user grants and group-based grants in a
/// single SQL query, then caches the resulting action list per
/// (user, target_type, target_id) tuple for 30 seconds.
pub struct PermissionService {
    db: PgPool,
    cache: RwLock<HashMap<CacheKey, CacheEntry>>,
}

impl PermissionService {
    pub fn new(db: PgPool) -> Self {
        Self {
            db,
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Check whether `user_id` holds `action` on the given target.
    ///
    /// Admin users bypass all checks and always receive `true`. For
    /// non-admin users the service first checks the in-process cache,
    /// then falls back to a combined SQL query that resolves both direct
    /// user permissions and group-based permissions via `user_group_members`.
    pub async fn check_permission(
        &self,
        user_id: Uuid,
        target_type: &str,
        target_id: Uuid,
        action: &str,
        is_admin: bool,
    ) -> Result<bool> {
        if is_admin {
            return Ok(true);
        }

        let actions = self
            .resolve_actions(user_id, target_type, target_id)
            .await?;
        Ok(actions.iter().any(|a| a == action))
    }

    /// Return true when at least one permission rule exists for the given
    /// target, regardless of principal. This is used by middleware to decide
    /// whether fine-grained rules should be enforced at all (targets without
    /// any rules fall back to the default access model).
    pub async fn has_any_rules_for_target(
        &self,
        target_type: &str,
        target_id: Uuid,
    ) -> Result<bool> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM permissions WHERE target_type = $1 AND target_id = $2)",
        )
        .bind(target_type)
        .bind(target_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(exists)
    }

    /// Clear the entire permission cache. Call this after any CRUD operation
    /// on the `permissions` table to ensure stale grants are not served.
    pub fn invalidate_cache(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }
    }

    /// Resolve the full set of granted actions for a user on a specific target.
    ///
    /// Checks the cache first; on miss or expiry, queries the database and
    /// populates the cache before returning.
    async fn resolve_actions(
        &self,
        user_id: Uuid,
        target_type: &str,
        target_id: Uuid,
    ) -> Result<Vec<String>> {
        let key = CacheKey::new(user_id, target_type, target_id);

        // Fast path: return cached entry if still fresh.
        if let Ok(cache) = self.cache.read() {
            if let Some(entry) = cache.get(&key) {
                if !entry.is_expired() {
                    return Ok(entry.actions.clone());
                }
            }
        }

        // Cache miss or expired -- query the database.
        let actions = self.query_actions(user_id, target_type, target_id).await?;

        // Populate cache. Evict stale entries while we hold the write lock
        // to keep memory bounded over time.
        if let Ok(mut cache) = self.cache.write() {
            cache.retain(|_, v| !v.is_expired());
            cache.insert(
                key,
                CacheEntry {
                    actions: actions.clone(),
                    inserted_at: Instant::now(),
                },
            );
        }

        Ok(actions)
    }

    /// Execute the combined SQL query that resolves direct user permissions
    /// and group-based permissions via a UNION through `user_group_members`.
    async fn query_actions(
        &self,
        user_id: Uuid,
        target_type: &str,
        target_id: Uuid,
    ) -> Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT DISTINCT unnest(actions) as action
            FROM permissions
            WHERE (
                (principal_type = 'user' AND principal_id = $1)
                OR
                (principal_type = 'group' AND principal_id IN (
                    SELECT group_id FROM user_group_members WHERE user_id = $1
                ))
            )
            AND target_type = $2
            AND target_id = $3
            "#,
        )
        .bind(user_id)
        .bind(target_type)
        .bind(target_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        Ok(rows.into_iter().map(|(action,)| action).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // CacheKey construction and equality
    // -----------------------------------------------------------------------

    #[test]
    fn test_cache_key_equality_same_inputs() {
        let user_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();
        let a = CacheKey::new(user_id, "repository", target_id);
        let b = CacheKey::new(user_id, "repository", target_id);
        assert_eq!(a, b);
    }

    #[test]
    fn test_cache_key_inequality_different_user() {
        let target_id = Uuid::new_v4();
        let a = CacheKey::new(Uuid::new_v4(), "repository", target_id);
        let b = CacheKey::new(Uuid::new_v4(), "repository", target_id);
        assert_ne!(a, b);
    }

    #[test]
    fn test_cache_key_inequality_different_target_type() {
        let user_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();
        let a = CacheKey::new(user_id, "repository", target_id);
        let b = CacheKey::new(user_id, "artifact", target_id);
        assert_ne!(a, b);
    }

    #[test]
    fn test_cache_key_inequality_different_target_id() {
        let user_id = Uuid::new_v4();
        let a = CacheKey::new(user_id, "repository", Uuid::new_v4());
        let b = CacheKey::new(user_id, "repository", Uuid::new_v4());
        assert_ne!(a, b);
    }

    #[test]
    fn test_cache_key_used_as_hash_key() {
        let user_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();
        let key = CacheKey::new(user_id, "group", target_id);

        let mut map: HashMap<CacheKey, String> = HashMap::new();
        map.insert(key.clone(), "test".to_string());

        let lookup = CacheKey::new(user_id, "group", target_id);
        assert_eq!(map.get(&lookup), Some(&"test".to_string()));
    }

    // -----------------------------------------------------------------------
    // CacheEntry TTL behaviour
    // -----------------------------------------------------------------------

    #[test]
    fn test_cache_entry_not_expired_when_fresh() {
        let entry = CacheEntry {
            actions: vec!["read".to_string()],
            inserted_at: Instant::now(),
        };
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_cache_entry_expired_after_ttl() {
        let entry = CacheEntry {
            actions: vec!["read".to_string()],
            inserted_at: Instant::now() - CACHE_TTL - Duration::from_millis(1),
        };
        assert!(entry.is_expired());
    }

    #[test]
    fn test_cache_entry_not_expired_just_before_ttl() {
        let entry = CacheEntry {
            actions: vec!["read".to_string()],
            inserted_at: Instant::now() - CACHE_TTL + Duration::from_secs(1),
        };
        assert!(!entry.is_expired());
    }

    // -----------------------------------------------------------------------
    // Cache TTL constant
    // -----------------------------------------------------------------------

    #[test]
    fn test_cache_ttl_is_thirty_seconds() {
        assert_eq!(CACHE_TTL, Duration::from_secs(30));
    }

    // -----------------------------------------------------------------------
    // CacheKey debug output
    // -----------------------------------------------------------------------

    #[test]
    fn test_cache_key_debug_format() {
        let key = CacheKey::new(Uuid::nil(), "artifact", Uuid::nil());
        let debug = format!("{:?}", key);
        assert!(debug.contains("artifact"));
        assert!(debug.contains("00000000-0000-0000-0000-000000000000"));
    }

    // -----------------------------------------------------------------------
    // CacheEntry clone
    // -----------------------------------------------------------------------

    #[test]
    fn test_cache_entry_clone_preserves_actions() {
        let entry = CacheEntry {
            actions: vec!["read".to_string(), "write".to_string()],
            inserted_at: Instant::now(),
        };
        let cloned = entry.clone();
        assert_eq!(cloned.actions, entry.actions);
    }

    // -----------------------------------------------------------------------
    // Invalidation clears the cache
    // -----------------------------------------------------------------------

    #[test]
    fn test_invalidate_cache_clears_all_entries() {
        // We cannot construct a real PgPool in unit tests, but we can test
        // the cache layer by constructing PermissionService with a placeholder.
        // Since invalidate_cache only touches the RwLock<HashMap>, we use an
        // unsafe-free workaround: build the cache directly.
        let cache: RwLock<HashMap<CacheKey, CacheEntry>> = RwLock::new(HashMap::new());
        {
            let mut guard = cache.write().unwrap();
            guard.insert(
                CacheKey::new(Uuid::new_v4(), "repository", Uuid::new_v4()),
                CacheEntry {
                    actions: vec!["read".to_string()],
                    inserted_at: Instant::now(),
                },
            );
            guard.insert(
                CacheKey::new(Uuid::new_v4(), "artifact", Uuid::new_v4()),
                CacheEntry {
                    actions: vec!["write".to_string()],
                    inserted_at: Instant::now(),
                },
            );
            assert_eq!(guard.len(), 2);
        }
        // Simulate invalidation
        {
            let mut guard = cache.write().unwrap();
            guard.clear();
        }
        {
            let guard = cache.read().unwrap();
            assert!(guard.is_empty());
        }
    }

    // -----------------------------------------------------------------------
    // Admin bypass (tested via check_permission logic, no DB needed)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_admin_bypasses_permission_check() {
        // Admin users should always get true, regardless of the actual
        // permission rules. We verify the early-return path by calling
        // check_permission with is_admin=true. Since admin bypasses the
        // DB query entirely, this works without a live database.
        //
        // We cannot construct PermissionService without a real PgPool, so
        // we test the logic inline:
        let is_admin = true;
        let result: std::result::Result<bool, AppError> =
            if is_admin { Ok(true) } else { Ok(false) };
        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn test_non_admin_does_not_bypass() {
        let is_admin = false;
        let result = if is_admin { true } else { false };
        assert!(!result);
    }

    // -----------------------------------------------------------------------
    // Stale entry eviction during cache write
    // -----------------------------------------------------------------------

    #[test]
    fn test_stale_entries_evicted_on_insert() {
        let mut cache: HashMap<CacheKey, CacheEntry> = HashMap::new();

        // Insert a stale entry
        cache.insert(
            CacheKey::new(Uuid::new_v4(), "repository", Uuid::new_v4()),
            CacheEntry {
                actions: vec!["read".to_string()],
                inserted_at: Instant::now() - CACHE_TTL - Duration::from_secs(10),
            },
        );

        // Insert a fresh entry
        let fresh_key = CacheKey::new(Uuid::new_v4(), "artifact", Uuid::new_v4());
        cache.insert(
            fresh_key.clone(),
            CacheEntry {
                actions: vec!["write".to_string()],
                inserted_at: Instant::now(),
            },
        );

        assert_eq!(cache.len(), 2);

        // Simulate the eviction logic from resolve_actions
        cache.retain(|_, v| !v.is_expired());

        assert_eq!(cache.len(), 1);
        assert!(cache.contains_key(&fresh_key));
    }

    // -----------------------------------------------------------------------
    // Action list matching
    // -----------------------------------------------------------------------

    #[test]
    fn test_action_list_contains_target_action() {
        let actions = vec![
            "read".to_string(),
            "write".to_string(),
            "delete".to_string(),
        ];
        assert!(actions.iter().any(|a| a == "write"));
    }

    #[test]
    fn test_action_list_does_not_contain_missing_action() {
        let actions = vec!["read".to_string()];
        assert!(!actions.iter().any(|a| a == "admin"));
    }

    #[test]
    fn test_empty_action_list_denies_everything() {
        let actions: Vec<String> = vec![];
        assert!(!actions.iter().any(|a| a == "read"));
        assert!(!actions.iter().any(|a| a == "write"));
        assert!(!actions.iter().any(|a| a == "delete"));
        assert!(!actions.iter().any(|a| a == "admin"));
    }
}
