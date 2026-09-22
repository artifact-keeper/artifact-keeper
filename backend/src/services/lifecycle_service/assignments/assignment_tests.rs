//! Regression coverage for explicit lifecycle policy scope.

use super::*;
use serde_json::json;

fn request(policy_type: &str, config: serde_json::Value) -> CreateLifecyclePolicyRequest {
    CreateLifecyclePolicyRequest {
        name: format!("assignments-3794-{}", Uuid::new_v4()),
        policy_type: policy_type.into(),
        config,
        ..Default::default()
    }
}

fn policy_configs() -> Vec<(&'static str, serde_json::Value)> {
    vec![
        ("max_age_days", json!({"days": 1})),
        ("max_versions", json!({"keep": 1})),
        ("no_downloads_days", json!({"days": 1})),
        ("tag_pattern_keep", json!({"pattern": "^keep$"})),
        ("tag_pattern_delete", json!({"pattern": ".*"})),
        ("size_quota_bytes", json!({"quota_bytes": 100})),
    ]
}

#[test]
fn scope_normalization_3794() {
    let a = Uuid::from_u128(1);
    let b = Uuid::from_u128(2);
    assert_eq!(normalize_scope(false, vec![b, a, b]).unwrap(), vec![a, b]);
    assert!(normalize_scope(false, vec![]).unwrap().is_empty());
    assert!(normalize_scope(true, vec![]).unwrap().is_empty());
    assert!(matches!(
        normalize_scope(true, vec![a]),
        Err(AppError::UnprocessableEntity(_))
    ));
    let mut req = request("max_versions", json!({"keep": 1}));
    assert!(req.assigned_repositories().unwrap().is_empty());
    req.repository_id = Some(a);
    assert_eq!(req.assigned_repositories().unwrap(), vec![a]);
    req.repository_ids = Some(vec![]);
    assert!(req.assigned_repositories().is_err());
}

#[test]
fn scope_deserialization_is_safe_and_strict_3794() {
    let base = json!({"name":"test","policy_type":"max_age_days","config":{"days":1}});
    for legacy in [json!({}), json!({"repository_id":null})] {
        let mut value = base.clone();
        value
            .as_object_mut()
            .unwrap()
            .extend(legacy.as_object().unwrap().clone());
        let req: CreateLifecyclePolicyRequest = serde_json::from_value(value).unwrap();
        assert!(!req.applies_to_all);
        assert!(req.assigned_repositories().unwrap().is_empty());
    }
    for invalid in [
        json!({"applies_to_all":null}),
        json!({"applies_to_all":"true"}),
        json!({"repository_ids":null}),
        json!({"repository_ids":"all"}),
        json!({"repository_ids":["not-a-uuid"]}),
    ] {
        let mut value = base.clone();
        value
            .as_object_mut()
            .unwrap()
            .extend(invalid.as_object().unwrap().clone());
        assert!(serde_json::from_value::<CreateLifecyclePolicyRequest>(value).is_err());
        assert!(serde_json::from_value::<UpdateLifecyclePolicyRequest>(invalid).is_err());
    }
    let patch: UpdateLifecyclePolicyRequest = serde_json::from_value(json!({})).unwrap();
    assert!(patch.applies_to_all.is_none() && patch.repository_ids.is_none());
    let patch: UpdateLifecyclePolicyRequest =
        serde_json::from_value(json!({"applies_to_all":false,"repository_ids":[]})).unwrap();
    assert_eq!(patch.applies_to_all, Some(false));
    assert_eq!(patch.repository_ids, Some(vec![]));
}

#[tokio::test]
async fn invalid_policy_rejected_before_persistence_3794() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgresql://unused@127.0.0.1:1/unused")
        .unwrap();
    let svc = LifecycleService::new(pool);
    for (kind, config) in [
        ("invalid", json!({})),
        ("max_versions", json!({"keep":0})),
        (
            "max_age_days",
            json!({"days":1,"excludes":{"versions":["stable"]}}),
        ),
    ] {
        let error = svc.create_policy(request(kind, config)).await.unwrap_err();
        assert!(
            matches!(error, AppError::Validation(_)),
            "{kind}: {error:?}"
        );
    }
    let mut invalid = request("max_age_days", json!({"days":1}));
    invalid.cron_schedule = Some("not a cron".into());
    assert!(matches!(
        svc.create_policy(invalid).await,
        Err(AppError::Validation(_))
    ));
    let mut conflicting = request("max_age_days", json!({"days":1}));
    conflicting.applies_to_all = true;
    conflicting.repository_ids = Some(vec![Uuid::new_v4()]);
    assert!(matches!(
        svc.create_policy(conflicting).await,
        Err(AppError::UnprocessableEntity(_))
    ));
    for (kind, config) in policy_configs() {
        let mut global = request(kind, config);
        global.applies_to_all = true;
        assert!(global.assigned_repositories().unwrap().is_empty(), "{kind}");
    }
}

async fn repo(pool: &PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO repositories (id,key,name,storage_path,repo_type,format) \
         VALUES ($1,$2,$2,$2,'local','generic')",
    )
    .bind(id)
    .bind(format!("assignments-3794-{id}"))
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn artifact(pool: &PgPool, repository_id: Uuid, version: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO artifacts (id,repository_id,name,path,version,size_bytes,checksum_sha256,\
         content_type,storage_key,created_at) \
         VALUES ($1,$2,'package',$3,$4,100,$5,'application/octet-stream',$3,NOW()-INTERVAL '30 days')",
    )
    .bind(id).bind(repository_id).bind(id.to_string()).bind(version).bind("a".repeat(64))
    .execute(pool).await.unwrap();
    id
}

async fn deleted(pool: &PgPool, id: Uuid) -> bool {
    sqlx::query_scalar("SELECT is_deleted FROM artifacts WHERE id=$1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn cleanup(pool: &PgPool, policies: &[Uuid], repos: &[Uuid]) {
    sqlx::query("DELETE FROM lifecycle_policies WHERE id = ANY($1)")
        .bind(policies)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM repositories WHERE id = ANY($1)")
        .bind(repos)
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn all_types_dormant_subset_preview_execution_exclusions_3794() {
    let Some(pool) = crate::testing::try_pool_with(3).await else {
        return;
    };
    let svc = LifecycleService::new(pool.clone());
    for (kind, mut config) in policy_configs() {
        config["exclude"] = json!({"versions":["stable"]});
        let repos = [repo(&pool).await, repo(&pool).await, repo(&pool).await];
        let mut artifacts = Vec::new();
        for &r in &repos {
            artifacts.push([
                artifact(&pool, r, "old").await,
                artifact(&pool, r, "new").await,
                artifact(&pool, r, "stable").await,
            ]);
        }
        let policy = svc.create_policy(request(kind, config)).await.unwrap();
        for dry_run in [true, false] {
            let result = svc.execute_policy(policy.id, dry_run).await.unwrap();
            assert_eq!(
                (
                    result.artifacts_matched,
                    result.artifacts_removed,
                    result.bytes_matched,
                    result.bytes_freed
                ),
                (0, 0, 0, 0),
                "{kind}"
            );
        }
        assert!(svc
            .get_policy(policy.id)
            .await
            .unwrap()
            .last_run_at
            .is_none());
        assert!(!svc
            .load_enabled_policies()
            .await
            .unwrap()
            .iter()
            .any(|p| p.id == policy.id));
        for &r in &repos[..2] {
            svc.set_repository_assignment(policy.id, r, true)
                .await
                .unwrap();
        }
        let preview = svc.execute_policy(policy.id, true).await.unwrap();
        let expected = if kind == "max_versions" { 2 } else { 4 };
        assert_eq!(preview.artifacts_matched, expected, "{kind}");
        assert_eq!(preview.bytes_matched, expected * 100, "{kind}");
        assert_eq!(preview.bytes_freed, 0);
        for ids in &artifacts {
            for &id in ids {
                assert!(!deleted(&pool, id).await);
            }
        }
        let result = svc.execute_policy(policy.id, false).await.unwrap();
        assert_eq!(
            result.artifacts_matched, preview.artifacts_matched,
            "{kind}"
        );
        assert_eq!(result.artifacts_removed, expected, "{kind}");
        assert_eq!(result.bytes_freed, preview.bytes_matched, "{kind}");
        for ids in &artifacts[..2] {
            assert!(!deleted(&pool, ids[2]).await, "{kind}");
        }
        for &id in &artifacts[2] {
            assert!(!deleted(&pool, id).await, "{kind}");
        }
        cleanup(&pool, &[policy.id], &repos).await;
    }
}

#[tokio::test]
async fn assignments_crud_concurrency_and_projection_3794() {
    let Some(pool) = crate::testing::try_pool_with(4).await else {
        return;
    };
    let svc = LifecycleService::new(pool.clone());
    let repos = [repo(&pool).await, repo(&pool).await];
    let policy = svc
        .create_policy(request("max_versions", json!({"keep":1})))
        .await
        .unwrap();
    let (a, b) = tokio::join!(
        svc.set_repository_assignment(policy.id, repos[0], true),
        svc.set_repository_assignment(policy.id, repos[1], true),
    );
    a.unwrap();
    b.unwrap();
    let shared = svc.get_policy(policy.id).await.unwrap();
    assert_eq!(shared.repository_ids.len(), 2);
    assert!(shared.repository_id.is_none());
    assert!(!shared.applies_to_all);
    svc.set_repository_assignment(policy.id, repos[0], true)
        .await
        .unwrap();
    assert_eq!(
        svc.get_policy(policy.id)
            .await
            .unwrap()
            .repository_ids
            .len(),
        2
    );
    let invalid = svc
        .update_policy(
            policy.id,
            UpdateLifecyclePolicyRequest {
                repository_ids: Some(vec![repos[0], Uuid::new_v4()]),
                ..Default::default()
            },
        )
        .await;
    assert!(matches!(invalid, Err(AppError::NotFound(_))));
    assert_eq!(
        svc.get_policy(policy.id)
            .await
            .unwrap()
            .repository_ids
            .len(),
        2
    );
    assert!(svc
        .update_policy(
            policy.id,
            UpdateLifecyclePolicyRequest {
                applies_to_all: Some(true),
                ..Default::default()
            }
        )
        .await
        .is_err());

    sqlx::query("DELETE FROM repositories WHERE id=$1")
        .bind(repos[0])
        .execute(&pool)
        .await
        .unwrap();
    let remaining = svc.get_policy(policy.id).await.unwrap();
    assert_eq!(remaining.repository_ids, vec![repos[1]]);
    assert_eq!(remaining.repository_id, Some(repos[1]));
    assert!(!remaining.applies_to_all);
    for _ in 0..2 {
        let dormant = svc
            .set_repository_assignment(policy.id, repos[1], false)
            .await
            .unwrap();
        assert!(dormant.repository_ids.is_empty() && dormant.repository_id.is_none());
        assert!(!dormant.applies_to_all);
    }
    let global = svc
        .update_policy(
            policy.id,
            UpdateLifecyclePolicyRequest {
                applies_to_all: Some(true),
                repository_ids: Some(vec![]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(global.applies_to_all);
    for attach in [true, false] {
        assert!(matches!(
            svc.set_repository_assignment(policy.id, repos[1], attach)
                .await,
            Err(AppError::UnprocessableEntity(_))
        ));
    }
    let dormant = svc
        .update_policy(
            policy.id,
            UpdateLifecyclePolicyRequest {
                applies_to_all: Some(false),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(dormant.repository_ids.is_empty());
    svc.set_repository_assignment(policy.id, repos[1], true)
        .await
        .unwrap();
    svc.delete_policy(policy.id).await.unwrap();
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM lifecycle_policy_repositories WHERE policy_id=$1")
            .bind(policy.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
    assert!(matches!(
        svc.get_policy(policy.id).await,
        Err(AppError::NotFound(_))
    ));
    cleanup(&pool, &[], &repos[1..]).await;
}

#[tokio::test]
async fn migration_preserves_scope_and_repository_deletion_3794() {
    let Some(pool) = crate::testing::try_pool_with(2).await else {
        return;
    };
    let mut tx = pool.begin().await.unwrap();
    let schema = format!("scope_3794_{}", Uuid::new_v4().simple());
    sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
        "CREATE SCHEMA {schema}; SET LOCAL search_path TO {schema}; \
         CREATE TABLE repositories(id UUID PRIMARY KEY); \
         CREATE TABLE lifecycle_policies(id UUID PRIMARY KEY, \
         repository_id UUID REFERENCES repositories(id) ON DELETE CASCADE, \
         config JSONB NOT NULL, enabled BOOLEAN NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());"
    ))).execute(&mut *tx).await.unwrap();
    let repo_id = Uuid::new_v4();
    let global = Uuid::new_v4();
    let single = Uuid::new_v4();
    sqlx::query("INSERT INTO repositories VALUES ($1)")
        .bind(repo_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    let config = json!({"days":14,"exclude":{"versions":["stable"]}});
    for (id, repository_id) in [(global, None), (single, Some(repo_id))] {
        sqlx::query("INSERT INTO lifecycle_policies(id,repository_id,config,enabled) VALUES ($1,$2,$3,false)")
            .bind(id).bind(repository_id).bind(&config).execute(&mut *tx).await.unwrap();
    }
    sqlx::raw_sql(include_str!(
        "../../../../migrations/233_lifecycle_policy_assignments.sql"
    ))
    .execute(&mut *tx)
    .await
    .unwrap();
    let rows: Vec<(Uuid, bool, serde_json::Value, bool)> =
        sqlx::query_as("SELECT id,applies_to_all,config,enabled FROM lifecycle_policies")
            .fetch_all(&mut *tx)
            .await
            .unwrap();
    for (id, is_global, stored, enabled) in rows {
        assert_eq!(is_global, id == global);
        assert_eq!(stored, config);
        assert!(!enabled);
    }
    let assignments: Vec<(Uuid, Uuid)> =
        sqlx::query_as("SELECT policy_id,repository_id FROM lifecycle_policy_repositories")
            .fetch_all(&mut *tx)
            .await
            .unwrap();
    assert_eq!(assignments, vec![(single, repo_id)]);
    sqlx::query("DELETE FROM repositories WHERE id=$1")
        .bind(repo_id)
        .execute(&mut *tx)
        .await
        .unwrap();
    let retained: (bool, Option<Uuid>) =
        sqlx::query_as("SELECT applies_to_all,repository_id FROM lifecycle_policies WHERE id=$1")
            .bind(single)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(retained, (false, None));
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn global_future_repositories_and_automatic_runs_3794() {
    let Some(admin) = crate::testing::try_pool_with(2).await else {
        return;
    };
    // execute-all is deliberately cluster-wide; never run it on other tests' fixtures.
    let database = format!("lifecycle_3794_{}", Uuid::new_v4().simple());
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE {database}")))
        .execute(&admin)
        .await
        .unwrap();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(3)
        .connect_with(admin.connect_options().as_ref().clone().database(&database))
        .await
        .unwrap();
    sqlx::migrate!("./migrations").run(&pool).await.unwrap();
    let svc = LifecycleService::new(pool.clone());
    let before = repo(&pool).await;
    let dormant = svc
        .create_policy(request("tag_pattern_delete", json!({"pattern":".*"})))
        .await
        .unwrap();
    let mut global_req = request("tag_pattern_delete", json!({"pattern":".*"}));
    global_req.applies_to_all = true;
    let global = svc.create_policy(global_req).await.unwrap();
    let after = repo(&pool).await;
    let before_artifact = artifact(&pool, before, "one").await;
    let after_artifact = artifact(&pool, after, "one").await;
    assert!(svc
        .resolve_repositories(&global)
        .await
        .unwrap()
        .contains(&after));
    assert_eq!(
        svc.list_policies(Some(after))
            .await
            .unwrap()
            .iter()
            .map(|p| p.id)
            .collect::<Vec<_>>(),
        vec![global.id]
    );
    assert_eq!(svc.list_policies(None).await.unwrap().len(), 2);
    let preview = svc.execute_policy(global.id, true).await.unwrap();
    assert_eq!(preview.artifacts_matched, 2);
    let executed = svc.execute_all_enabled().await.unwrap();
    assert_eq!(executed.len(), 1);
    assert_eq!(executed[0].policy_id, global.id);
    assert_eq!(executed[0].artifacts_removed, preview.artifacts_matched);
    assert!(deleted(&pool, before_artifact).await && deleted(&pool, after_artifact).await);
    assert!(svc
        .get_policy(dormant.id)
        .await
        .unwrap()
        .last_run_at
        .is_none());

    svc.update_policy(
        global.id,
        UpdateLifecyclePolicyRequest {
            enabled: Some(false),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let assigned = svc
        .set_repository_assignment(dormant.id, after, true)
        .await
        .unwrap();
    let scoped_artifact = artifact(&pool, after, "two").await;
    let control = artifact(&pool, before, "two").await;
    let results = svc
        .execute_due_policies(&CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].policy_id, assigned.id);
    assert!(deleted(&pool, scoped_artifact).await);
    assert!(!deleted(&pool, control).await);
    svc.set_repository_assignment(dormant.id, after, false)
        .await
        .unwrap();
    assert!(svc.execute_all_enabled().await.unwrap().is_empty());
    assert!(svc
        .execute_due_policies(&CancellationToken::new())
        .await
        .unwrap()
        .is_empty());
    drop(svc);
    pool.close().await;
    sqlx::query(sqlx::AssertSqlSafe(format!("DROP DATABASE {database}")))
        .execute(&admin)
        .await
        .unwrap();
}

#[tokio::test]
async fn dormant_and_selected_oci_cascade_scope_3794() {
    let Some(pool) = crate::testing::try_pool_with(3).await else {
        return;
    };
    let svc = LifecycleService::new(pool.clone());
    let repositories = [repo(&pool).await, repo(&pool).await, repo(&pool).await];
    let digest = format!("sha256:{}", "b".repeat(64));
    for &repository in &repositories {
        let artifact_id = artifact(&pool, repository, "old").await;
        sqlx::query("UPDATE artifacts SET name='image:old',path='v2/image/manifests/old',storage_key=$2,is_deleted=true WHERE id=$1")
            .bind(artifact_id).bind(format!("oci-manifests/{digest}")).execute(&pool).await.unwrap();
        // A tag newer than the tombstone is a protected re-push, not a stale reference.
        sqlx::query("INSERT INTO oci_tags(repository_id,name,tag,manifest_digest,updated_at) VALUES ($1,'image','old',$2,NOW()-INTERVAL '1 day')")
            .bind(repository).bind(&digest).execute(&pool).await.unwrap();
    }
    let policy = svc
        .create_policy(request("tag_pattern_delete", json!({"pattern":".*"})))
        .await
        .unwrap();
    let tags = || {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM oci_tags WHERE repository_id=ANY($1)")
            .bind(repositories)
    };
    svc.execute_policy(policy.id, false).await.unwrap();
    assert_eq!(tags().fetch_one(&pool).await.unwrap(), 3);
    svc.update_policy(
        policy.id,
        UpdateLifecyclePolicyRequest {
            repository_ids: Some(repositories[..2].to_vec()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    svc.execute_policy(policy.id, true).await.unwrap();
    assert_eq!(tags().fetch_one(&pool).await.unwrap(), 3);
    svc.execute_policy(policy.id, false).await.unwrap();
    let remaining: Vec<Uuid> =
        sqlx::query_scalar("SELECT repository_id FROM oci_tags WHERE repository_id=ANY($1)")
            .bind(repositories)
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(remaining, vec![repositories[2]]);
    cleanup(&pool, &[policy.id], &repositories).await;
}

#[tokio::test]
async fn repository_deletion_and_policy_mutations_share_lock_order_3794() {
    let Some(pool) = crate::testing::try_pool_with(4).await else {
        return;
    };
    for operation in 0..3 {
        let svc = LifecycleService::new(pool.clone());
        let repository = repo(&pool).await;
        let mut req = request("max_versions", json!({"keep":1}));
        req.repository_id = Some(repository);
        let policy = svc.create_policy(req).await.unwrap();
        let mut deletion = pool.begin().await.unwrap();
        let blocker: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
            .fetch_one(&mut *deletion)
            .await
            .unwrap();
        sqlx::query("SELECT id FROM repositories WHERE id=$1 FOR UPDATE")
            .bind(repository)
            .execute(&mut *deletion)
            .await
            .unwrap();
        let worker = tokio::spawn(async move {
            match operation {
                0 => svc
                    .set_repository_assignment(policy.id, repository, true)
                    .await
                    .map(|_| ()),
                1 => svc
                    .update_policy(
                        policy.id,
                        UpdateLifecyclePolicyRequest {
                            name: Some("renamed".into()),
                            ..Default::default()
                        },
                    )
                    .await
                    .map(|_| ()),
                _ => svc.delete_policy(policy.id).await,
            }
        });
        tokio::time::timeout(std::time::Duration::from_secs(5),async {
            loop {
                let waiting:bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
                ).bind(blocker).fetch_one(&pool).await.unwrap();
                if waiting { break; }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }).await.expect("mutation should wait on repository, without holding the policy lock");
        sqlx::query("SELECT id FROM lifecycle_policies WHERE id=$1 FOR UPDATE NOWAIT")
            .bind(policy.id)
            .execute(&mut *deletion)
            .await
            .expect("repository deletion must be able to take the policy lock without a deadlock");
        sqlx::query("DELETE FROM repositories WHERE id=$1")
            .bind(repository)
            .execute(&mut *deletion)
            .await
            .unwrap();
        deletion.commit().await.unwrap();
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), worker)
            .await
            .unwrap()
            .unwrap();
        if operation == 0 {
            assert!(matches!(result, Err(AppError::NotFound(_))));
        } else {
            result.unwrap();
        }
        cleanup(&pool, &[policy.id], &[]).await;
    }
}
