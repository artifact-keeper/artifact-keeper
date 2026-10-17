//! Which members of a virtual repository a service-account token cannot
//! reach, and why (#4215).
//!
//! A virtual repository's contents belong to its members, and a member is
//! served when its owner may read it and the routed parent, and the token
//! names the member OR that parent (#4559). A parent-scoped token therefore
//! does not need member expansion. Scope and entitlement diagnostics remain
//! separate; native admission/scanning and credential lifetime are not graded.
//!
//! This is deliberately server-side. The rule exempts public members
//! through the shared scope helper, and authenticated internal visibility
//! through the shared read gate; entitlement is also an action-capability
//! question; a client that reconstructed either would be re-implementing an
//! authorization predicate and would drift from it.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::api::handlers::{proxy_helpers, repositories};
use crate::api::middleware::auth::AuthExtension;
use crate::error::{AppError, Result};
use crate::models::{access_scope::AccessScope, repository::Repository};
use crate::services::repository_service::RepositoryService;

/// Why one member is out of reach. A closed set, so a client groups on it
/// rather than parsing the prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnreachableReason {
    /// Neither member nor routed parent is in scope. Name the virtual for
    /// read-through access; direct member access remains independently scoped.
    OutOfTokenScope,
    /// The account cannot read the parent or member. Fix its read entitlement;
    /// widening token scope alone does not supply permission to read.
    NoGrant,
}

/// One member the token cannot read through its virtual parent.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UnreachableMember {
    pub repo_key: String,
    pub reason: UnreachableReason,
}

/// One virtual repository, with the members that are out of reach through it.
/// A virtual whose members are all reachable is not reported at all.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UnreachableVirtual {
    pub virtual_repo_key: String,
    pub members: Vec<UnreachableMember>,
}

/// The repository scope of one credential: `None` is unrestricted.
pub type TokenScope = Option<Vec<Uuid>>;

#[derive(Debug, sqlx::FromRow)]
struct VirtualRow {
    id: Uuid,
    key: String,
}

#[derive(Debug)]
struct MemberRow {
    virtual_repo_id: Uuid,
    repo: Repository,
}

/// Analyse one credential. See [`analyze_many`]; this is the single-subject
/// form used by the detail endpoint and the selector preview.
pub async fn analyze(
    db: &PgPool,
    owner_user_id: Option<Uuid>,
    scope: TokenScope,
) -> Result<Vec<UnreachableVirtual>> {
    let mut out = analyze_many(db, owner_user_id, vec![((), scope)]).await?;
    Ok(out.remove(&()).unwrap_or_default())
}

/// Analyse credentials of the SAME owner once per distinct virtual, not token.
/// Recursive leaf traversal and read-action checks reuse the runtime gates;
/// their results are shared across the token page. A badge per token must not
/// repeat that work for every credential naming the same virtual.
///
/// `owner_user_id` is the service account the tokens belong to. Without it the
/// entitlement half cannot be evaluated and only scope is reported — which is
/// the selector preview's case when it is asked without an account.
///
/// An UNRESTRICTED credential (`None`) is analysed against the virtual
/// repositories its owner holds a grant on: nothing is out of scope for it by
/// definition, but it can still be missing a grant, and those are the virtuals
/// the operator has expressed an interest in.
pub async fn analyze_many<K: std::hash::Hash + Eq + Clone>(
    db: &PgPool,
    owner_user_id: Option<Uuid>,
    subjects: Vec<(K, TokenScope)>,
) -> Result<HashMap<K, Vec<UnreachableVirtual>>> {
    let mut result: HashMap<K, Vec<UnreachableVirtual>> = HashMap::new();
    if subjects.is_empty() {
        return Ok(result);
    }

    let scoped_ids: Vec<Uuid> = subjects
        .iter()
        .filter_map(|(_, scope)| scope.as_ref())
        .flatten()
        .copied()
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let any_unrestricted = subjects.iter().any(|(_, scope)| scope.is_none());

    let virtuals = load_virtuals(db, &scoped_ids, any_unrestricted, owner_user_id).await?;
    if virtuals.is_empty() {
        return Ok(result);
    }
    let virtual_ids: Vec<Uuid> = virtuals.iter().map(|v| v.id).collect();
    let members = load_members(db, &virtual_ids).await?;
    if members.is_empty() {
        return Ok(result);
    }

    // The entitlement half uses the read paths' tenant AND action gates,
    // once per distinct virtual rather than once per token. Public/internal
    // baselines are evaluated by the same authorization helper.
    let owner = if let Some(user_id) = owner_user_id {
        let is_admin: bool = sqlx::query_scalar("SELECT is_admin FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?
            .ok_or_else(|| AppError::NotFound("Account not found".to_string()))?;
        Some(AuthExtension {
            user_id,
            is_admin,
            allowed_repo_ids: AccessScope::Admin,
            ..AuthExtension::default()
        })
    } else {
        None
    };
    let service = RepositoryService::new(db.clone());
    let mut readable = HashSet::new();
    let mut readable_parents = HashSet::new();
    if owner.is_some() {
        for virtual_row in &virtuals {
            let parent = service.get_by_id(virtual_row.id).await?;
            match repositories::require_visible(&parent, &owner, &service).await {
                Ok(()) => {
                    readable_parents.insert(parent.id);
                }
                Err(AppError::NotFound(_)) => continue,
                Err(error) => return Err(error),
            }
            let rows = members
                .iter()
                .filter(|m| m.virtual_repo_id == parent.id)
                .map(|m| m.repo.clone())
                .collect();
            let admitted =
                proxy_helpers::try_authorize_virtual_members(db, owner.as_ref(), parent.id, rows)
                    .await
                    .map_err(|r| proxy_helpers::member_walk_app_error(&r))?;
            readable.extend(admitted.into_iter().map(|r| r.id));
        }
    }

    let key_of: HashMap<Uuid, &str> = virtuals.iter().map(|v| (v.id, v.key.as_str())).collect();
    let mut by_virtual: HashMap<Uuid, Vec<&MemberRow>> = HashMap::new();
    for member in &members {
        by_virtual
            .entry(member.virtual_repo_id)
            .or_default()
            .push(member);
    }

    for (subject, scope) in subjects {
        let in_scope: Option<HashSet<Uuid>> =
            scope.as_ref().map(|ids| ids.iter().copied().collect());
        let principal = AuthExtension {
            allowed_repo_ids: AccessScope::from(scope),
            ..owner.clone().unwrap_or_default()
        };
        let mut unreachable = Vec::new();

        for virtual_row in &virtuals {
            // A virtual the credential is not scoped to is not its problem.
            if in_scope
                .as_ref()
                .is_some_and(|scope| !scope.contains(&virtual_row.id))
            {
                continue;
            }
            let Some(rows) = by_virtual.get(&virtual_row.id) else {
                continue;
            };

            let mut blocked = Vec::new();
            for member in rows {
                // Public members need no member grant, but the routed parent
                // must still be readable before any member can be reached.
                // Entitlement first: without it, widening the token's scope
                // would not help, so that is the remedy to report.
                let reason = if owner.is_some()
                    && (!readable_parents.contains(&virtual_row.id)
                        || !readable.contains(&member.repo.id))
                {
                    UnreachableReason::NoGrant
                } else if !repositories::member_passes_token_scope(
                    Some(&principal),
                    virtual_row.id,
                    member.repo.id,
                    member.repo.visibility,
                ) {
                    UnreachableReason::OutOfTokenScope
                } else {
                    continue;
                };
                blocked.push(UnreachableMember {
                    repo_key: member.repo.key.clone(),
                    reason,
                });
            }

            if !blocked.is_empty() {
                blocked.sort_by(|a, b| a.repo_key.cmp(&b.repo_key));
                unreachable.push(UnreachableVirtual {
                    virtual_repo_key: key_of
                        .get(&virtual_row.id)
                        .map(|k| (*k).to_string())
                        .unwrap_or_default(),
                    members: blocked,
                });
            }
        }

        unreachable.sort_by(|a, b| a.virtual_repo_key.cmp(&b.virtual_repo_key));
        result.insert(subject, unreachable);
    }

    Ok(result)
}

/// How many members are out of reach in total — the number the token list
/// shows on a row.
pub fn total_members(unreachable: &[UnreachableVirtual]) -> usize {
    unreachable.iter().map(|v| v.members.len()).sum()
}

/// Virtual repositories to analyse: those named by some scope, plus — when a
/// credential is unrestricted — those its owner holds a grant on.
async fn load_virtuals(
    db: &PgPool,
    scoped_ids: &[Uuid],
    any_unrestricted: bool,
    owner_user_id: Option<Uuid>,
) -> Result<Vec<VirtualRow>> {
    let mut rows = sqlx::query_as::<_, VirtualRow>(
        "SELECT id, key FROM repositories WHERE repo_type = 'virtual' AND (id = ANY($1) OR $2) ORDER BY key",
    )
    .bind(scoped_ids)
    .bind(any_unrestricted && owner_user_id.is_some())
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    if any_unrestricted {
        if let Some(owner) = owner_user_id {
            let admin: bool = sqlx::query_scalar("SELECT is_admin FROM users WHERE id = $1")
                .bind(owner)
                .fetch_optional(db)
                .await
                .map_err(|e| AppError::Database(e.to_string()))?
                .ok_or_else(|| AppError::NotFound("Account not found".to_string()))?;
            let visibility = if admin {
                crate::services::repository_service::RepoVisibility::All
            } else {
                crate::services::repository_service::RepoVisibility::User(owner)
            };
            let ids: Vec<_> = rows.iter().map(|r| r.id).collect();
            let visible: HashSet<_> = RepositoryService::new(db.clone())
                .filter_visible_repo_ids(&ids, &visibility)
                .await?
                .into_iter()
                .collect();
            rows.retain(|r| scoped_ids.contains(&r.id) || visible.contains(&r.id));
        }
    }
    Ok(rows)
}

async fn load_members(db: &PgPool, virtual_ids: &[Uuid]) -> Result<Vec<MemberRow>> {
    let mut rows = Vec::new();
    for virtual_repo_id in virtual_ids {
        let members = proxy_helpers::fetch_virtual_members(db, *virtual_repo_id)
            .await
            .map_err(|r| proxy_helpers::member_walk_app_error(&r))?;
        rows.extend(members.into_iter().map(|repo| MemberRow {
            virtual_repo_id: *virtual_repo_id,
            repo,
        }));
    }
    Ok(rows)
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::handlers::test_db_helpers as tdh;

    /// A virtual with three members: one public, one the account is granted,
    /// one it is not. Returns `(virtual, public, granted, ungranted)`.
    struct Fixture {
        pool: PgPool,
        user_id: Uuid,
        virtual_id: Uuid,
        public_id: Uuid,
        granted_id: Uuid,
        ungranted_id: Uuid,
        dirs: Vec<std::path::PathBuf>,
        keys: HashMap<Uuid, String>,
    }

    impl Fixture {
        async fn build() -> Option<Self> {
            let pool = tdh::try_pool().await?;
            let (user_id, _username) = tdh::create_user(&pool).await;
            let (virtual_id, vkey, vdir) = tdh::create_repo(&pool, "virtual", "nuget").await;
            let (public_id, pkey, pdir) = tdh::create_repo(&pool, "local", "nuget").await;
            let (granted_id, gkey, gdir) = tdh::create_repo(&pool, "local", "nuget").await;
            let (ungranted_id, ukey, udir) = tdh::create_repo(&pool, "local", "nuget").await;

            for (i, member) in [public_id, granted_id, ungranted_id].iter().enumerate() {
                tdh::link_virtual_member(&pool, virtual_id, *member, i as i32 + 1).await;
            }
            sqlx::query("UPDATE repositories SET is_public = true WHERE id = $1")
                .bind(public_id)
                .execute(&pool)
                .await
                .expect("make one member public");
            // The account may read the virtual itself and one member.
            tdh::grant_repo_access(&pool, virtual_id, user_id).await;
            tdh::grant_repo_access(&pool, granted_id, user_id).await;

            let keys = HashMap::from([
                (virtual_id, vkey),
                (public_id, pkey),
                (granted_id, gkey),
                (ungranted_id, ukey),
            ]);
            Some(Self {
                pool,
                user_id,
                virtual_id,
                public_id,
                granted_id,
                ungranted_id,
                dirs: vec![vdir, pdir, gdir, udir],
                keys,
            })
        }

        fn key(&self, id: Uuid) -> &str {
            self.keys.get(&id).map(String::as_str).unwrap_or("")
        }

        async fn teardown(self) {
            let _ = sqlx::query("DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1")
                .bind(self.virtual_id)
                .execute(&self.pool)
                .await;
            for id in [
                self.virtual_id,
                self.public_id,
                self.granted_id,
                self.ungranted_id,
            ] {
                let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
                    .bind(id)
                    .execute(&self.pool)
                    .await;
            }
            tdh::cleanup_user(&self.pool, self.user_id).await;
            for dir in self.dirs {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
    }

    /// Scoped to the virtual alone: #4559 admits the granted member through
    /// the parent, the ungranted member still lacks entitlement, and PUBLIC
    /// membership keeps its read baseline; only the missing grant is reported.
    #[tokio::test]
    async fn scoped_to_the_virtual_alone_reports_scope_and_grant_separately() {
        let Some(fx) = Fixture::build().await else {
            return;
        };
        let result = analyze(&fx.pool, Some(fx.user_id), Some(vec![fx.virtual_id])).await;

        let granted_key = fx.key(fx.granted_id).to_string();
        let ungranted_key = fx.key(fx.ungranted_id).to_string();
        let public_key = fx.key(fx.public_id).to_string();
        let virtual_key = fx.key(fx.virtual_id).to_string();
        fx.teardown().await;

        let report = result.expect("analysis runs");
        assert_eq!(report.len(), 1, "one virtual reported: {report:?}");
        assert_eq!(report[0].virtual_repo_key, virtual_key);

        let reasons: HashMap<&str, UnreachableReason> = report[0]
            .members
            .iter()
            .map(|m| (m.repo_key.as_str(), m.reason))
            .collect();
        assert_eq!(
            reasons.get(granted_key.as_str()),
            None,
            "a granted member is reachable through the scoped virtual: {report:?}"
        );
        assert_eq!(
            reasons.get(ungranted_key.as_str()),
            Some(&UnreachableReason::NoGrant),
            "unentitled member: {report:?}"
        );
        assert!(
            !reasons.contains_key(public_key.as_str()),
            "a public member is exempt from token scope and needs no grant: {report:?}"
        );
        assert_eq!(total_members(&report), 1);
    }

    /// Naming members as well as the virtual does not supply a missing read
    /// grant; parent read-through already satisfies the token scope term.
    #[tokio::test]
    async fn scoping_to_the_members_leaves_only_the_missing_grant() {
        let Some(fx) = Fixture::build().await else {
            return;
        };
        let scope = vec![fx.virtual_id, fx.granted_id, fx.ungranted_id];
        let result = analyze(&fx.pool, Some(fx.user_id), Some(scope)).await;

        let ungranted_key = fx.key(fx.ungranted_id).to_string();
        fx.teardown().await;

        let report = result.expect("analysis runs");
        assert_eq!(
            total_members(&report),
            1,
            "only the grant is missing: {report:?}"
        );
        assert_eq!(report[0].members[0].repo_key, ungranted_key);
        assert_eq!(report[0].members[0].reason, UnreachableReason::NoGrant);
    }

    /// Nothing to report once the account is entitled to every member and the
    /// token is scoped to them.
    #[tokio::test]
    async fn a_correctly_configured_token_reports_nothing() {
        let Some(fx) = Fixture::build().await else {
            return;
        };
        tdh::grant_repo_access(&fx.pool, fx.ungranted_id, fx.user_id).await;
        let scope = vec![fx.virtual_id, fx.granted_id, fx.ungranted_id];
        let result = analyze(&fx.pool, Some(fx.user_id), Some(scope)).await;

        fx.teardown().await;
        assert!(result.expect("analysis runs").is_empty());
    }

    /// An unrestricted token has nothing out of scope by definition, but it
    /// can still be missing a grant — and that is worth reporting, because the
    /// symptom is identical.
    #[tokio::test]
    async fn an_unrestricted_token_still_reports_a_missing_grant() {
        let Some(fx) = Fixture::build().await else {
            return;
        };
        let result = analyze(&fx.pool, Some(fx.user_id), None).await;

        let ungranted_key = fx.key(fx.ungranted_id).to_string();
        fx.teardown().await;

        let report = result.expect("analysis runs");
        assert_eq!(total_members(&report), 1, "{report:?}");
        assert_eq!(report[0].members[0].repo_key, ungranted_key);
        assert_eq!(report[0].members[0].reason, UnreachableReason::NoGrant);
    }

    #[tokio::test]
    async fn recursive_analysis_reports_leaf_entitlements_not_grouping_virtuals() {
        let Some(fx) = Fixture::build().await else {
            return;
        };
        let (nested, _, dir) = tdh::create_repo(&fx.pool, "virtual", "nuget").await;
        sqlx::query(
            "DELETE FROM virtual_repo_members WHERE virtual_repo_id = $1 AND member_repo_id = $2",
        )
        .bind(fx.virtual_id)
        .bind(fx.ungranted_id)
        .execute(&fx.pool)
        .await
        .unwrap();
        tdh::link_virtual_member(&fx.pool, fx.virtual_id, nested, 4).await;
        tdh::link_virtual_member(&fx.pool, nested, fx.ungranted_id, 1).await;
        let result = analyze(&fx.pool, Some(fx.user_id), Some(vec![fx.virtual_id]))
            .await
            .unwrap();
        assert_eq!(total_members(&result), 1);
        assert_eq!(result[0].members[0].repo_key, fx.key(fx.ungranted_id));
        assert_eq!(result[0].members[0].reason, UnreachableReason::NoGrant);
        sqlx::query("INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) VALUES ($1, $2, 2)")
            .bind(nested).bind(fx.virtual_id).execute(&fx.pool).await.unwrap();
        let cycled = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            analyze(&fx.pool, Some(fx.user_id), Some(vec![fx.virtual_id])),
        )
        .await
        .expect("cycle-safe analysis")
        .unwrap();
        assert_eq!(total_members(&cycled), 1);
        tdh::cleanup_member_repo(&fx.pool, nested, &dir).await;
        fx.teardown().await;
    }

    #[tokio::test]
    async fn internal_baseline_and_read_action_gates_match_runtime() {
        let Some(fx) = Fixture::build().await else {
            return;
        };
        sqlx::query("UPDATE repositories SET visibility = 'internal' WHERE id = $1")
            .bind(fx.ungranted_id)
            .execute(&fx.pool)
            .await
            .unwrap();
        assert!(
            analyze(&fx.pool, Some(fx.user_id), Some(vec![fx.virtual_id]))
                .await
                .unwrap()
                .is_empty()
        );
        sqlx::query("DELETE FROM role_assignments WHERE user_id = $1 AND repository_id = $2")
            .bind(fx.user_id)
            .bind(fx.granted_id)
            .execute(&fx.pool)
            .await
            .unwrap();
        tdh::grant_repo_actions(&fx.pool, fx.granted_id, fx.user_id, &["write"]).await;
        let result = analyze(&fx.pool, Some(fx.user_id), Some(vec![fx.virtual_id]))
            .await
            .unwrap();
        assert_eq!(total_members(&result), 1);
        assert_eq!(result[0].members[0].repo_key, fx.key(fx.granted_id));
        assert_eq!(result[0].members[0].reason, UnreachableReason::NoGrant);
        fx.teardown().await;
    }

    #[tokio::test]
    async fn unreadable_parent_blocks_public_and_private_members() {
        let Some(fx) = Fixture::build().await else {
            return;
        };
        sqlx::query("DELETE FROM role_assignments WHERE user_id = $1 AND repository_id = $2")
            .bind(fx.user_id)
            .bind(fx.virtual_id)
            .execute(&fx.pool)
            .await
            .unwrap();
        let result = analyze(&fx.pool, Some(fx.user_id), Some(vec![fx.virtual_id]))
            .await
            .unwrap();
        assert_eq!(total_members(&result), 3);
        assert!(result[0]
            .members
            .iter()
            .all(|m| m.reason == UnreachableReason::NoGrant));
        fx.teardown().await;
    }

    /// Without an owner entitlement is unknowable; scope names the parent,
    /// so #4559 read-through leaves no member-scope complaint to report.
    #[tokio::test]
    async fn without_an_owner_only_scope_is_judged() {
        let Some(fx) = Fixture::build().await else {
            return;
        };
        let result = analyze(&fx.pool, None, Some(vec![fx.virtual_id])).await;

        fx.teardown().await;
        assert!(
            result.expect("analysis runs").is_empty(),
            "parent scope covers member reads; no grant verdict is possible without an owner"
        );
    }
}
