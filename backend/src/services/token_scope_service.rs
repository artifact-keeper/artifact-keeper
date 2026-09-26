//! Which members of a virtual repository a service-account token cannot
//! reach, and why (#4215).
//!
//! A virtual repository's contents belong to its members, and a member is
//! served only when BOTH halves of the member predicate hold: the member is in
//! the presenting credential's repository scope, and the caller is entitled to
//! read it. Either half can fail silently — an empty listing, a 404 — and the
//! two are fixed in different places, so they are reported separately.
//!
//! This is deliberately server-side. The rule exempts public members
//! (`member_is_public || can_access_repo(..)`), `VirtualMemberResponse` does
//! not carry `is_public`, and the entitlement half is a role-assignment
//! question; a client that reconstructed either would be re-implementing an
//! authorization predicate and would drift from it.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::{AppError, Result};
use crate::services::repository_service::{RepoVisibility, RepositoryService};

/// Why one member is out of reach. A closed set, so a client groups on it
/// rather than parsing the prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnreachableReason {
    /// The member is not in the token's repository scope. Fixed by scoping the
    /// token to the member, or by a selector with `include_virtual_members`.
    OutOfTokenScope,
    /// The service account holds no read access on the member. Fixed with a
    /// grant; widening the token's scope alone would not help.
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

#[derive(Debug, sqlx::FromRow)]
struct MemberRow {
    virtual_repo_id: Uuid,
    member_repo_id: Uuid,
    member_repo_key: String,
    member_is_public: bool,
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

/// Analyse several credentials of the SAME owner in three queries, whatever
/// the number of tokens: the virtual repositories in play, their members, and
/// the owner's entitlements. The token list renders a badge per row, so the
/// per-token form would have been a query fan-out on a page load.
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

    // The entitlement half, for every member at once. `filter_visible_repo_ids`
    // with `User` is the same predicate the read paths apply, so public members
    // come back as readable here too.
    let readable: HashSet<Uuid> = match owner_user_id {
        Some(user_id) => {
            let member_ids: Vec<Uuid> = members.iter().map(|m| m.member_repo_id).collect();
            RepositoryService::new(db.clone())
                .filter_visible_repo_ids(&member_ids, &RepoVisibility::User(user_id))
                .await?
                .into_iter()
                .collect()
        }
        None => HashSet::new(),
    };

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
                // A public member is exempt from token scope and needs no
                // grant, so it is always reachable.
                if member.member_is_public {
                    continue;
                }
                // Entitlement first: without it, widening the token's scope
                // would not help, so that is the remedy to report.
                let reason =
                    if owner_user_id.is_some() && !readable.contains(&member.member_repo_id) {
                        UnreachableReason::NoGrant
                    } else if in_scope
                        .as_ref()
                        .is_some_and(|scope| !scope.contains(&member.member_repo_id))
                    {
                        UnreachableReason::OutOfTokenScope
                    } else {
                        continue;
                    };
                blocked.push(UnreachableMember {
                    repo_key: member.member_repo_key.clone(),
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
    let owner = match any_unrestricted {
        true => owner_user_id,
        false => None,
    };
    sqlx::query_as::<_, VirtualRow>(
        r#"
        SELECT DISTINCT r.id, r.key
        FROM repositories r
        WHERE r.repo_type = 'virtual'
          AND (
            r.id = ANY($1)
            OR ($2::uuid IS NOT NULL AND EXISTS (
                SELECT 1 FROM role_assignments ra
                WHERE ra.user_id = $2 AND ra.repository_id = r.id
            ))
          )
        ORDER BY r.key
        "#,
    )
    .bind(scoped_ids)
    .bind(owner)
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))
}

async fn load_members(db: &PgPool, virtual_ids: &[Uuid]) -> Result<Vec<MemberRow>> {
    sqlx::query_as::<_, MemberRow>(
        r#"
        SELECT vrm.virtual_repo_id,
               r.id   AS member_repo_id,
               r.key  AS member_repo_key,
               r.is_public AS member_is_public
        FROM virtual_repo_members vrm
        INNER JOIN repositories r ON r.id = vrm.member_repo_id
        WHERE vrm.virtual_repo_id = ANY($1)
        ORDER BY vrm.priority, r.key
        "#,
    )
    .bind(virtual_ids)
    .fetch_all(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))
}

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

    /// The reported case: scoped to the virtual alone. The granted member is
    /// out of scope, the ungranted one is missing a grant, and the PUBLIC one
    /// is reachable either way and must not be reported.
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
            Some(&UnreachableReason::OutOfTokenScope),
            "entitled but unscoped member: {report:?}"
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
        assert_eq!(total_members(&report), 2);
    }

    /// Scoping the token to the members too removes the scope complaint, and
    /// leaves the grant one — which widening the scope cannot fix.
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

    /// Without an owner the entitlement half is unknowable, so only scope is
    /// judged — the selector preview's case when no account is supplied.
    #[tokio::test]
    async fn without_an_owner_only_scope_is_judged() {
        let Some(fx) = Fixture::build().await else {
            return;
        };
        let result = analyze(&fx.pool, None, Some(vec![fx.virtual_id])).await;

        let granted_key = fx.key(fx.granted_id).to_string();
        let ungranted_key = fx.key(fx.ungranted_id).to_string();
        fx.teardown().await;

        let report = result.expect("analysis runs");
        let keys: HashSet<&str> = report[0]
            .members
            .iter()
            .map(|m| m.repo_key.as_str())
            .collect();
        assert!(keys.contains(granted_key.as_str()));
        assert!(keys.contains(ungranted_key.as_str()));
        assert!(
            report[0]
                .members
                .iter()
                .all(|m| m.reason == UnreachableReason::OutOfTokenScope),
            "no grant verdict without an owner: {report:?}"
        );
    }
}
