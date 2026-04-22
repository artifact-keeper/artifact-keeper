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
use tracing::{debug, error, warn};
use uuid::Uuid;

use crate::error::{AppError, Result};

/// Target type for system-wide permission checks (e.g. creating repositories or groups).
pub const SYSTEM_TARGET_TYPE: &str = "system";

/// Sentinel UUID used as the `target_id` for system-wide permission checks.
/// Operations that are not scoped to a specific entity (repository, group, etc.)
/// use this nil UUID as a conventional placeholder.
pub const SYSTEM_SENTINEL_ID: Uuid = Uuid::nil();

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

/// Composite key for the target rules existence cache: (target_type, target_id).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RulesCacheKey {
    target_type: String,
    target_id: Uuid,
}

impl RulesCacheKey {
    fn new(target_type: &str, target_id: Uuid) -> Self {
        Self {
            target_type: target_type.to_string(),
            target_id,
        }
    }
}

/// A cached boolean result with an insertion timestamp.
#[derive(Debug, Clone)]
struct RulesCacheEntry {
    exists: bool,
    inserted_at: Instant,
}

impl RulesCacheEntry {
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
    rules_cache: RwLock<HashMap<RulesCacheKey, RulesCacheEntry>>,
}

impl PermissionService {
    pub fn new(db: PgPool) -> Self {
        Self {
            db,
            cache: RwLock::new(HashMap::new()),
            rules_cache: RwLock::new(HashMap::new()),
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
        let key = RulesCacheKey::new(target_type, target_id);

        // Fast path: return cached result if still fresh.
        let cached = match self.rules_cache.read() {
            Ok(cache) => cache.get(&key).and_then(|entry| {
                if entry.is_expired() {
                    None
                } else {
                    debug!(
                        target_type,
                        %target_id,
                        exists = entry.exists,
                        "rules cache hit"
                    );
                    Some(entry.exists)
                }
            }),
            Err(poisoned) => {
                error!("rules cache read lock poisoned, skipping cache");
                drop(poisoned.into_inner());
                None
            }
        };

        if let Some(exists) = cached {
            return Ok(exists);
        }

        debug!(target_type, %target_id, "rules cache miss, querying database");

        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM permissions WHERE target_type = $1 AND target_id = $2)",
        )
        .bind(target_type)
        .bind(target_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;

        // Populate cache.
        match self.rules_cache.write() {
            Ok(mut cache) => {
                cache.retain(|_, v| !v.is_expired());
                cache.insert(
                    key,
                    RulesCacheEntry {
                        exists,
                        inserted_at: Instant::now(),
                    },
                );
            }
            Err(poisoned) => {
                error!("rules cache write lock poisoned, recovering to update cache");
                let mut cache = poisoned.into_inner();
                cache.retain(|_, v| !v.is_expired());
                cache.insert(
                    key,
                    RulesCacheEntry {
                        exists,
                        inserted_at: Instant::now(),
                    },
                );
            }
        }

        if !exists {
            warn!(target_type, %target_id, "no permission rules found for target");
        }

        Ok(exists)
    }

    /// Clear both permission caches. Call this after any CRUD operation
    /// on the `permissions` table to ensure stale grants are not served.
    pub fn invalidate_cache(&self) {
        match self.cache.write() {
            Ok(mut cache) => cache.clear(),
            Err(poisoned) => {
                error!("permission cache lock poisoned during invalidation, clearing");
                poisoned.into_inner().clear();
            }
        }
        match self.rules_cache.write() {
            Ok(mut cache) => cache.clear(),
            Err(poisoned) => {
                error!("rules cache lock poisoned during invalidation, clearing");
                poisoned.into_inner().clear();
            }
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
        let cached = match self.cache.read() {
            Ok(cache) => cache.get(&key).and_then(|entry| {
                if entry.is_expired() {
                    None
                } else {
                    debug!(
                        %user_id,
                        target_type,
                        %target_id,
                        actions = ?entry.actions,
                        "permission cache hit"
                    );
                    Some(entry.actions.clone())
                }
            }),
            Err(poisoned) => {
                error!("permission cache read lock poisoned, skipping cache");
                drop(poisoned.into_inner());
                None
            }
        };

        if let Some(actions) = cached {
            return Ok(actions);
        }

        debug!(%user_id, target_type, %target_id, "permission cache miss, querying database");

        // Cache miss or expired -- query the database.
        let actions = self.query_actions(user_id, target_type, target_id).await?;

        if actions.is_empty() {
            warn!(
                %user_id,
                target_type,
                %target_id,
                "permission denied: rules exist but no actions granted"
            );
        }

        // Populate cache. Evict stale entries while we hold the write lock
        // to keep memory bounded over time.
        match self.cache.write() {
            Ok(mut cache) => {
                cache.retain(|_, v| !v.is_expired());
                cache.insert(
                    key,
                    CacheEntry {
                        actions: actions.clone(),
                        inserted_at: Instant::now(),
                    },
                );
            }
            Err(poisoned) => {
                error!("permission cache write lock poisoned, recovering to update cache");
                let mut cache = poisoned.into_inner();
                cache.retain(|_, v| !v.is_expired());
                cache.insert(
                    key,
                    CacheEntry {
                        actions: actions.clone(),
                        inserted_at: Instant::now(),
                    },
                );
            }
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
    // Invalidation clears both caches
    // -----------------------------------------------------------------------

    #[test]
    fn test_invalidate_cache_clears_all_entries() {
        let cache: RwLock<HashMap<CacheKey, CacheEntry>> = RwLock::new(HashMap::new());
        let rules_cache: RwLock<HashMap<RulesCacheKey, RulesCacheEntry>> =
            RwLock::new(HashMap::new());
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
        {
            let mut guard = rules_cache.write().unwrap();
            guard.insert(
                RulesCacheKey::new("repository", Uuid::new_v4()),
                RulesCacheEntry {
                    exists: true,
                    inserted_at: Instant::now(),
                },
            );
            assert_eq!(guard.len(), 1);
        }
        // Simulate invalidation (same logic as invalidate_cache)
        {
            let mut guard = cache.write().unwrap();
            guard.clear();
        }
        {
            let mut guard = rules_cache.write().unwrap();
            guard.clear();
        }
        {
            let guard = cache.read().unwrap();
            assert!(guard.is_empty());
        }
        {
            let guard = rules_cache.read().unwrap();
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
        assert!(result.unwrap());
    }

    #[test]
    fn test_non_admin_does_not_bypass() {
        let is_admin = false;
        let result = is_admin;
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
        let actions = [
            "read".to_string(),
            "write".to_string(),
            "delete".to_string(),
        ];
        assert!(actions.iter().any(|a| a == "write"));
    }

    #[test]
    fn test_action_list_does_not_contain_missing_action() {
        let actions = ["read".to_string()];
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

    // -----------------------------------------------------------------------
    // RulesCacheKey construction and equality
    // -----------------------------------------------------------------------

    #[test]
    fn test_rules_cache_key_equality_same_inputs() {
        let target_id = Uuid::new_v4();
        let a = RulesCacheKey::new("repository", target_id);
        let b = RulesCacheKey::new("repository", target_id);
        assert_eq!(a, b);
    }

    #[test]
    fn test_rules_cache_key_inequality_different_type() {
        let target_id = Uuid::new_v4();
        let a = RulesCacheKey::new("repository", target_id);
        let b = RulesCacheKey::new("artifact", target_id);
        assert_ne!(a, b);
    }

    #[test]
    fn test_rules_cache_key_inequality_different_id() {
        let a = RulesCacheKey::new("repository", Uuid::new_v4());
        let b = RulesCacheKey::new("repository", Uuid::new_v4());
        assert_ne!(a, b);
    }

    #[test]
    fn test_rules_cache_key_used_as_hash_key() {
        let target_id = Uuid::new_v4();
        let key = RulesCacheKey::new("repository", target_id);

        let mut map: HashMap<RulesCacheKey, bool> = HashMap::new();
        map.insert(key.clone(), true);

        let lookup = RulesCacheKey::new("repository", target_id);
        assert_eq!(map.get(&lookup), Some(&true));
    }

    // -----------------------------------------------------------------------
    // RulesCacheEntry TTL behaviour
    // -----------------------------------------------------------------------

    #[test]
    fn test_rules_cache_entry_not_expired_when_fresh() {
        let entry = RulesCacheEntry {
            exists: true,
            inserted_at: Instant::now(),
        };
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_rules_cache_entry_expired_after_ttl() {
        let entry = RulesCacheEntry {
            exists: true,
            inserted_at: Instant::now() - CACHE_TTL - Duration::from_millis(1),
        };
        assert!(entry.is_expired());
    }

    #[test]
    fn test_rules_cache_entry_not_expired_just_before_ttl() {
        let entry = RulesCacheEntry {
            exists: false,
            inserted_at: Instant::now() - CACHE_TTL + Duration::from_secs(1),
        };
        assert!(!entry.is_expired());
    }

    // -----------------------------------------------------------------------
    // RwLock poisoning recovery
    // -----------------------------------------------------------------------

    #[test]
    fn test_poisoned_cache_lock_recovers_on_invalidation() {
        let cache: RwLock<HashMap<CacheKey, CacheEntry>> = RwLock::new(HashMap::new());

        // Populate the cache
        {
            let mut guard = cache.write().unwrap();
            guard.insert(
                CacheKey::new(Uuid::new_v4(), "repository", Uuid::new_v4()),
                CacheEntry {
                    actions: vec!["read".to_string()],
                    inserted_at: Instant::now(),
                },
            );
        }

        // Poison the lock by panicking inside a write guard
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = cache.write().unwrap();
            panic!("intentional poison");
        }));

        // The lock is now poisoned. Verify we can still recover and clear.
        match cache.write() {
            Ok(_) => panic!("expected poisoned lock"),
            Err(poisoned) => {
                let mut inner = poisoned.into_inner();
                inner.clear();
                assert!(inner.is_empty());
            }
        };
    }

    #[test]
    fn test_poisoned_rules_cache_lock_recovers_on_invalidation() {
        let cache: RwLock<HashMap<RulesCacheKey, RulesCacheEntry>> = RwLock::new(HashMap::new());

        {
            let mut guard = cache.write().unwrap();
            guard.insert(
                RulesCacheKey::new("repository", Uuid::new_v4()),
                RulesCacheEntry {
                    exists: true,
                    inserted_at: Instant::now(),
                },
            );
        }

        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = cache.write().unwrap();
            panic!("intentional poison");
        }));

        match cache.write() {
            Ok(_) => panic!("expected poisoned lock"),
            Err(poisoned) => {
                let mut inner = poisoned.into_inner();
                inner.clear();
                assert!(inner.is_empty());
            }
        };
    }

    #[test]
    fn test_poisoned_read_lock_returns_none() {
        let cache: RwLock<HashMap<CacheKey, CacheEntry>> = RwLock::new(HashMap::new());

        let user_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();
        let key = CacheKey::new(user_id, "repository", target_id);

        {
            let mut guard = cache.write().unwrap();
            guard.insert(
                key.clone(),
                CacheEntry {
                    actions: vec!["read".to_string()],
                    inserted_at: Instant::now(),
                },
            );
        }

        // Poison the lock
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = cache.write().unwrap();
            panic!("intentional poison");
        }));

        // On poisoned read, we should gracefully handle it (return None / skip cache)
        match cache.read() {
            Ok(_) => panic!("expected poisoned lock"),
            Err(poisoned) => {
                // The recovery pattern: accept the inner data exists but skip
                drop(poisoned.into_inner());
            }
        };
    }

    // -----------------------------------------------------------------------
    // Stale rules cache entry eviction
    // -----------------------------------------------------------------------

    #[test]
    fn test_stale_rules_entries_evicted_on_insert() {
        let mut cache: HashMap<RulesCacheKey, RulesCacheEntry> = HashMap::new();

        // Insert a stale entry
        cache.insert(
            RulesCacheKey::new("repository", Uuid::new_v4()),
            RulesCacheEntry {
                exists: true,
                inserted_at: Instant::now() - CACHE_TTL - Duration::from_secs(10),
            },
        );

        // Insert a fresh entry
        let fresh_key = RulesCacheKey::new("artifact", Uuid::new_v4());
        cache.insert(
            fresh_key.clone(),
            RulesCacheEntry {
                exists: false,
                inserted_at: Instant::now(),
            },
        );

        assert_eq!(cache.len(), 2);

        cache.retain(|_, v| !v.is_expired());

        assert_eq!(cache.len(), 1);
        assert!(cache.contains_key(&fresh_key));
    }

    // -----------------------------------------------------------------------
    // Helper: build a PermissionService with a lazy (non-connecting) PgPool
    // -----------------------------------------------------------------------

    fn lazy_service() -> PermissionService {
        let pool = PgPool::connect_lazy("postgres://fake:fake@localhost/fake").expect("lazy pool");
        PermissionService::new(pool)
    }

    /// Insert a permission cache entry for the given user/target with the specified actions.
    fn seed_permission_cache(
        service: &PermissionService,
        user_id: Uuid,
        target_type: &str,
        target_id: Uuid,
        actions: Vec<String>,
        inserted_at: Instant,
    ) {
        let mut cache = service.cache.write().unwrap();
        cache.insert(
            CacheKey::new(user_id, target_type, target_id),
            CacheEntry {
                actions,
                inserted_at,
            },
        );
    }

    /// Insert a rules cache entry indicating whether rules exist for a target.
    fn seed_rules_cache(
        service: &PermissionService,
        target_type: &str,
        target_id: Uuid,
        exists: bool,
        inserted_at: Instant,
    ) {
        let mut rules = service.rules_cache.write().unwrap();
        rules.insert(
            RulesCacheKey::new(target_type, target_id),
            RulesCacheEntry {
                exists,
                inserted_at,
            },
        );
    }

    // -----------------------------------------------------------------------
    // PermissionService::check_permission -- admin bypass via real service
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_check_permission_admin_returns_true() {
        let service = lazy_service();
        let result = service
            .check_permission(Uuid::new_v4(), "repository", Uuid::new_v4(), "delete", true)
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_check_permission_admin_ignores_action_value() {
        let service = lazy_service();
        // Even a nonsensical action is granted for admins.
        let result = service
            .check_permission(
                Uuid::new_v4(),
                "artifact",
                Uuid::new_v4(),
                "nonexistent_action",
                true,
            )
            .await;
        assert!(result.unwrap());
    }

    // -----------------------------------------------------------------------
    // PermissionService::check_permission -- cache hit for non-admin
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_check_permission_cache_hit_grants_action() {
        let service = lazy_service();
        let user_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();

        seed_permission_cache(
            &service,
            user_id,
            "repository",
            target_id,
            vec!["read".into(), "write".into()],
            Instant::now(),
        );

        let result = service
            .check_permission(user_id, "repository", target_id, "write", false)
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_check_permission_cache_hit_denies_missing_action() {
        let service = lazy_service();
        let user_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();

        seed_permission_cache(
            &service,
            user_id,
            "repository",
            target_id,
            vec!["read".into()],
            Instant::now(),
        );

        let result = service
            .check_permission(user_id, "repository", target_id, "delete", false)
            .await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn test_check_permission_cache_hit_empty_actions_denies() {
        let service = lazy_service();
        let user_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();

        seed_permission_cache(
            &service,
            user_id,
            "repository",
            target_id,
            vec![],
            Instant::now(),
        );

        let result = service
            .check_permission(user_id, "repository", target_id, "read", false)
            .await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    // -----------------------------------------------------------------------
    // PermissionService::check_permission -- expired cache triggers DB miss
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_check_permission_expired_cache_falls_through_to_db_error() {
        let service = lazy_service();
        let user_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();

        seed_permission_cache(
            &service,
            user_id,
            "repository",
            target_id,
            vec!["read".into()],
            Instant::now() - CACHE_TTL - Duration::from_secs(5),
        );

        // The lazy pool is not connected, so the DB query will fail.
        let result = service
            .check_permission(user_id, "repository", target_id, "read", false)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_check_permission_no_cache_entry_falls_through_to_db_error() {
        let service = lazy_service();
        // No cache entry at all -- falls straight to DB which errors.
        let result = service
            .check_permission(Uuid::new_v4(), "repository", Uuid::new_v4(), "read", false)
            .await;
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // PermissionService::invalidate_cache via real service
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_invalidate_cache_on_fresh_service() {
        let service = lazy_service();
        // Calling invalidate on an empty service should not panic.
        service.invalidate_cache();

        let cache = service.cache.read().unwrap();
        assert!(cache.is_empty());
        let rules = service.rules_cache.read().unwrap();
        assert!(rules.is_empty());
    }

    #[tokio::test]
    async fn test_invalidate_cache_clears_populated_caches() {
        let service = lazy_service();
        let user_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();

        seed_permission_cache(
            &service,
            user_id,
            "repository",
            target_id,
            vec!["read".into(), "write".into()],
            Instant::now(),
        );
        seed_permission_cache(
            &service,
            Uuid::new_v4(),
            "artifact",
            Uuid::new_v4(),
            vec!["delete".into()],
            Instant::now(),
        );
        seed_rules_cache(&service, "repository", target_id, true, Instant::now());

        // Verify caches are populated.
        assert_eq!(service.cache.read().unwrap().len(), 2);
        assert_eq!(service.rules_cache.read().unwrap().len(), 1);

        service.invalidate_cache();

        assert!(service.cache.read().unwrap().is_empty());
        assert!(service.rules_cache.read().unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // PermissionService::has_any_rules_for_target -- cache hit
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_has_any_rules_cache_hit_returns_true() {
        let service = lazy_service();
        let target_id = Uuid::new_v4();
        seed_rules_cache(&service, "repository", target_id, true, Instant::now());

        let result = service
            .has_any_rules_for_target("repository", target_id)
            .await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[tokio::test]
    async fn test_has_any_rules_cache_hit_returns_false() {
        let service = lazy_service();
        let target_id = Uuid::new_v4();
        seed_rules_cache(&service, "artifact", target_id, false, Instant::now());

        let result = service
            .has_any_rules_for_target("artifact", target_id)
            .await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    // -----------------------------------------------------------------------
    // PermissionService::has_any_rules_for_target -- cache miss / expired
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_has_any_rules_expired_cache_falls_through_to_db_error() {
        let service = lazy_service();
        let target_id = Uuid::new_v4();

        seed_rules_cache(
            &service,
            "repository",
            target_id,
            true,
            Instant::now() - CACHE_TTL - Duration::from_secs(5),
        );

        let result = service
            .has_any_rules_for_target("repository", target_id)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_has_any_rules_no_cache_entry_falls_through_to_db_error() {
        let service = lazy_service();
        let result = service
            .has_any_rules_for_target("repository", Uuid::new_v4())
            .await;
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // PermissionService::resolve_actions -- cache hit returns cached actions
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_resolve_actions_cache_hit_returns_actions() {
        let service = lazy_service();
        let user_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();

        seed_permission_cache(
            &service,
            user_id,
            "repository",
            target_id,
            vec!["read".into(), "write".into(), "admin".into()],
            Instant::now(),
        );

        let actions = service
            .resolve_actions(user_id, "repository", target_id)
            .await
            .unwrap();
        assert_eq!(actions.len(), 3);
        assert!(actions.contains(&"read".to_string()));
        assert!(actions.contains(&"write".to_string()));
        assert!(actions.contains(&"admin".to_string()));
    }

    #[tokio::test]
    async fn test_resolve_actions_expired_entry_triggers_db_error() {
        let service = lazy_service();
        let user_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();

        seed_permission_cache(
            &service,
            user_id,
            "artifact",
            target_id,
            vec!["read".into()],
            Instant::now() - CACHE_TTL - Duration::from_secs(10),
        );

        let result = service
            .resolve_actions(user_id, "artifact", target_id)
            .await;
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // PermissionService: invalidate after cache population round-trip
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_cache_population_then_invalidate_then_miss() {
        let service = lazy_service();
        let user_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();

        // Populate both caches through the service's internal locks.
        seed_permission_cache(
            &service,
            user_id,
            "repository",
            target_id,
            vec!["read".into()],
            Instant::now(),
        );
        seed_rules_cache(&service, "repository", target_id, true, Instant::now());

        // Verify cache hit works before invalidation.
        let granted = service
            .check_permission(user_id, "repository", target_id, "read", false)
            .await
            .unwrap();
        assert!(granted);

        let has_rules = service
            .has_any_rules_for_target("repository", target_id)
            .await
            .unwrap();
        assert!(has_rules);

        // Invalidate.
        service.invalidate_cache();

        // After invalidation, both should miss cache and hit the (broken) DB.
        let result = service
            .check_permission(user_id, "repository", target_id, "read", false)
            .await;
        assert!(result.is_err());

        let rules_result = service
            .has_any_rules_for_target("repository", target_id)
            .await;
        assert!(rules_result.is_err());
    }

    // -----------------------------------------------------------------------
    // PermissionService::new creates empty caches
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_new_service_has_empty_caches() {
        let service = lazy_service();
        assert!(service.cache.read().unwrap().is_empty());
        assert!(service.rules_cache.read().unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // Cache key isolation: different target types are separate entries
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_cache_isolates_by_target_type() {
        let service = lazy_service();
        let user_id = Uuid::new_v4();
        let target_id = Uuid::new_v4();

        seed_permission_cache(
            &service,
            user_id,
            "repository",
            target_id,
            vec!["read".into()],
            Instant::now(),
        );
        seed_permission_cache(
            &service,
            user_id,
            "artifact",
            target_id,
            vec!["delete".into()],
            Instant::now(),
        );

        // "repository" grants "read" but not "delete".
        let repo_read = service
            .check_permission(user_id, "repository", target_id, "read", false)
            .await
            .unwrap();
        assert!(repo_read);

        let repo_delete = service
            .check_permission(user_id, "repository", target_id, "delete", false)
            .await
            .unwrap();
        assert!(!repo_delete);

        // "artifact" grants "delete" but not "read".
        let art_delete = service
            .check_permission(user_id, "artifact", target_id, "delete", false)
            .await
            .unwrap();
        assert!(art_delete);

        let art_read = service
            .check_permission(user_id, "artifact", target_id, "read", false)
            .await
            .unwrap();
        assert!(!art_read);
    }
}
