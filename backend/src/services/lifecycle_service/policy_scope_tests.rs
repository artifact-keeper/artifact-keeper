//! #2024 first slice: `max_age_days.min_keep` and `config.match.path_prefix`.
//!
//! Both features ride on the same invariant as the exclusion list: the
//! dry-run preview and the live run expand the same SQL macro, so what an
//! operator approved in the preview is exactly what the sweep deletes.

use super::tests::{
    insert_max_age_test_artifact, insert_max_age_test_repository, is_deleted, make_policy,
    make_service_for_validation,
};
use super::*;
use serde_json::json;

/// Insert a 123-byte artifact at `path`, `days_ago` old, with `name` as its
/// retention-group key (the shared helper gives every row a unique name).
async fn artifact_named(
    conn: &mut sqlx::PgConnection,
    repository_id: Uuid,
    name: &str,
    path: &str,
    version: &str,
    days_ago: i32,
) -> Uuid {
    let storage_key = format!("generic/{}", Uuid::new_v4());
    let id =
        insert_max_age_test_artifact(conn, repository_id, path, version, &storage_key, days_ago)
            .await;
    sqlx::query("UPDATE artifacts SET name = $2 WHERE id = $1")
        .bind(id)
        .bind(name)
        .execute(&mut *conn)
        .await
        .expect("rename fixture artifact");
    id
}

fn policy(
    policy_type: &str,
    repository_id: Option<Uuid>,
    config: serde_json::Value,
) -> LifecyclePolicy {
    let mut policy = make_policy(Uuid::new_v4(), "scope coverage", policy_type);
    policy.repository_id = repository_id;
    policy.config = config;
    policy
}

/// Run a dry run then a live run of `policy` and assert the live run removed
/// exactly what the preview matched. Returns the preview.
async fn preview_then_run(
    conn: &mut sqlx::PgConnection,
    policy: &LifecyclePolicy,
) -> PolicyExecutionResult {
    let preview = LifecycleService::dispatch_execute(conn, policy, true)
        .await
        .expect("dry run must succeed");
    let executed = LifecycleService::dispatch_execute(conn, policy, false)
        .await
        .expect("live run must succeed");
    assert_eq!(
        (executed.artifacts_removed, executed.bytes_freed),
        (preview.artifacts_matched, preview.bytes_matched),
        "the live run must delete exactly what the dry run previewed"
    );
    preview
}

// ── validation ────────────────────────────────────────────────────────────

#[tokio::test]
async fn min_keep_validation_2024() {
    let service = make_service_for_validation();
    service
        .validate_policy_config("max_age_days", &json!({"days": 14, "min_keep": 5}))
        .expect("min_keep is a max_age_days key");
    service
        .validate_policy_config("max_age_days", &json!({"max_age_days": 14, "min_keep": 1}))
        .expect("min_keep combines with the flat alias");
    for bad in [json!(0), json!(-1), json!("5"), json!(1.5), json!(null)] {
        let err = service
            .validate_policy_config("max_age_days", &json!({"days": 14, "min_keep": bad}))
            .expect_err(&format!("min_keep {bad} must be rejected"));
        assert!(err.to_string().contains("min_keep"), "{err}");
    }
    // `max_versions` already is a keep-N policy; the key means nothing there
    // and must not be accepted as if it did.
    for policy_type in ["max_versions", "no_downloads_days", "size_quota_bytes"] {
        let mut config = json!({"min_keep": 3});
        config[allowed_config_keys(policy_type)[0]] = json!(5);
        assert!(service
            .validate_policy_config(policy_type, &config)
            .is_err());
    }
    assert_eq!(parse_min_keep(&json!({"days": 1})).unwrap(), None);
    assert_eq!(parse_min_keep(&json!({"min_keep": 7})).unwrap(), Some(7));
}

#[tokio::test]
async fn match_validation_2024() {
    let service = make_service_for_validation();
    for (policy_type, base) in [
        ("max_age_days", json!({"days": 14})),
        ("max_versions", json!({"keep": 2})),
        ("no_downloads_days", json!({"days": 14})),
        ("tag_pattern_keep", json!({"pattern": "^v"})),
        ("tag_pattern_delete", json!({"pattern": "^v"})),
        ("size_quota_bytes", json!({"quota_bytes": 10})),
    ] {
        let mut config = base.clone();
        config["match"] = json!({"path_prefix": "builds/"});
        service
            .validate_policy_config(policy_type, &config)
            .unwrap_or_else(|e| panic!("{policy_type} must accept match.path_prefix: {e}"));
    }
    // Proposed selectors that are not implemented yet must fail loudly.
    for key in ["format", "tag_pattern", "repository", "path_prefixes"] {
        let err = service
            .validate_policy_config("max_age_days", &json!({"days": 1, "match": {key: "x"}}))
            .expect_err(&format!("match.{key} must be rejected"));
        assert!(err.to_string().contains(&format!("match.{key}")), "{err}");
    }
    for bad in [
        json!("builds/"),
        json!(["builds/"]),
        json!({"path_prefix": ""}),
        json!({"path_prefix": 5}),
        json!({"path_prefix": null}),
    ] {
        assert!(
            service
                .validate_policy_config("max_age_days", &json!({"days": 1, "match": bad}))
                .is_err(),
            "match {bad} must be rejected"
        );
    }
    assert_eq!(
        parse_match_path_prefix(&json!({"match": {}})).unwrap(),
        None
    );
    assert_eq!(
        parse_policy_filters(&json!({"days": 1})).unwrap(),
        PolicyFilters::default(),
        "a config without exclude/match must produce inert filters"
    );
}

// ── SQL shape ─────────────────────────────────────────────────────────────

#[test]
fn every_statement_pair_carries_the_shared_filters_2024() {
    let mut pairs = vec![
        (NO_DOWNLOADS_SELECT_SQL, NO_DOWNLOADS_UPDATE_SQL, "$5"),
        (
            concat!(max_versions_ranked_cte!(), "SELECT"),
            concat!(max_versions_ranked_cte!(), "UPDATE"),
            "$5",
        ),
    ];
    for scoped in [true, false] {
        for min_keep in [true, false] {
            let (select, update) = max_age_sql(scoped, min_keep);
            pairs.push((select, update, if scoped { "$5" } else { "$4" }));
        }
    }
    for (select, update, prefix) in pairs {
        for sql in [select, update] {
            assert!(
                sql.contains("::TEXT IS NULL OR starts_with("),
                "missing path_prefix predicate:\n{sql}"
            );
            assert!(
                sql.contains(&format!("{prefix}::TEXT IS NULL")),
                "path_prefix must bind at {prefix}:\n{sql}"
            );
            assert!(
                sql.contains("version, '') = ANY("),
                "missing exclusion:\n{sql}"
            );
        }
    }
}

#[test]
fn min_keep_sql_ranks_like_max_versions_and_ages_like_max_age_2024() {
    for (scoped, keep_param) in [(true, "$6"), (false, "$5")] {
        let (select, update) = max_age_sql(scoped, true);
        for sql in [select, update] {
            assert!(sql.contains(retention_rank!()), "{sql}");
            assert!(sql.contains(oci_tag_join!()), "{sql}");
            assert!(
                sql.contains(&format!("expired AND rn > {keep_param}::BIGINT")),
                "{sql}"
            );
            assert!(
                sql.contains(
                    "COALESCE(ot.updated_at, a.created_at) < NOW() - make_interval(days => "
                ),
                "{sql}"
            );
            // The age test is a column of the ranked set, never a filter on
            // it, or the young newest versions would not occupy the slots
            // min_keep reserves.
            assert_eq!(
                sql.matches("COALESCE(ot.updated_at, a.created_at) < NOW()")
                    .count(),
                1
            );
            assert!(sql.contains("::INT) AS expired"), "{sql}");
        }
    }
    // Without min_keep the plain filter query runs: no window function.
    for scoped in [true, false] {
        let (select, update) = max_age_sql(scoped, false);
        assert!(!select.contains("row_number()") && !update.contains("row_number()"));
    }
    assert!(max_versions_ranked_cte!().contains(retention_rank!()));
}

// ── behaviour against Postgres ────────────────────────────────────────────

/// "Delete versions older than 30 days, but always keep the 2 newest per
/// package." The newest versions count toward the 2 whether or not they have
/// expired, an excluded tag does not take a slot, and each package is its
/// own group.
#[tokio::test]
async fn max_age_min_keep_keeps_newest_per_group_2024() {
    let Some(pool) = crate::testing::try_pool_with(1).await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin test transaction");
    let repo = insert_max_age_test_repository(&mut tx).await;
    let mut pkg = Vec::new();
    for (index, age) in [1, 100, 200, 300, 400].into_iter().enumerate() {
        let path = format!("pkg/{index}-{repo}");
        pkg.push(artifact_named(&mut tx, repo, "pkg", &path, &format!("1.{index}"), age).await);
    }
    // Newest of all, but excluded: must neither be deleted nor push `pkg`'s
    // 100-day-old version out of the two kept slots.
    let latest = artifact_named(&mut tx, repo, "pkg", &format!("pkg/l-{repo}"), "latest", 0).await;
    let lone = artifact_named(&mut tx, repo, "other", &format!("other/{repo}"), "1.0", 400).await;

    let config = json!({"days": 30, "min_keep": 2, "exclude": {"versions": ["latest"]}});
    let result = preview_then_run(&mut tx, &policy("max_age_days", Some(repo), config)).await;
    assert_eq!(
        (result.artifacts_matched, result.bytes_matched),
        (3, 369),
        "{result:?}"
    );

    for (id, gone) in [
        (pkg[0], false),
        (pkg[1], false),
        (pkg[2], true),
        (pkg[3], true),
        (pkg[4], true),
        (latest, false),
        (lone, false),
    ] {
        assert_eq!(is_deleted(&mut tx, id).await, gone, "{id}");
    }

    // Negative control: without min_keep the same policy takes every expired
    // row that is left.
    let config = json!({"days": 30, "exclude": {"versions": ["latest"]}});
    let result = preview_then_run(&mut tx, &policy("max_age_days", Some(repo), config)).await;
    assert_eq!(result.artifacts_matched, 2, "{result:?}");
    assert!(is_deleted(&mut tx, pkg[1]).await && is_deleted(&mut tx, lone).await);
    assert!(
        !is_deleted(&mut tx, pkg[0]).await,
        "1-day-old row is inside the window"
    );

    tx.rollback().await.expect("rollback test transaction");
}

/// The legacy unscoped max-age path binds one parameter fewer; the min_keep
/// variant must line up with it. A preview only: a live global run would
/// touch every repository in the shared test database.
#[tokio::test]
async fn max_age_min_keep_global_preview_binds_2024() {
    let Some(pool) = crate::testing::try_pool_with(1).await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin test transaction");
    let repo = insert_max_age_test_repository(&mut tx).await;
    let group = format!("global-{repo}");
    for (index, age) in [1, 100, 200].into_iter().enumerate() {
        artifact_named(
            &mut tx,
            repo,
            &group,
            &format!("g/{index}-{repo}"),
            "1",
            age,
        )
        .await;
    }
    let config = json!({"days": 30, "min_keep": 1, "match": {"path_prefix": "g/"}});
    let preview =
        LifecycleService::dispatch_execute(&mut tx, &policy("max_age_days", None, config), true)
            .await
            .expect("global min_keep preview must bind cleanly");
    assert!(preview.artifacts_matched >= 2, "{preview:?}");
    tx.rollback().await.expect("rollback test transaction");
}

/// `match.path_prefix` scopes every policy type, in both the preview and the
/// live run: only `builds/` artifacts go, `releases/` survives a policy whose
/// deletion condition it also matches.
#[tokio::test]
async fn match_path_prefix_scopes_every_policy_type_2024() {
    let Some(pool) = crate::testing::try_pool_with(1).await else {
        return;
    };
    let cases = [
        ("max_age_days", json!({"days": 1})),
        ("no_downloads_days", json!({"days": 1})),
        ("tag_pattern_delete", json!({"pattern": "^max-age-test-"})),
        ("max_versions", json!({"keep": 0})),
        // 3 x 123 bytes against 100: enough excess to evict all three, so
        // only the scope keeps `releases/` alive.
        ("size_quota_bytes", json!({"quota_bytes": 100})),
    ];
    for (policy_type, mut config) in cases {
        let mut tx = pool.begin().await.expect("begin test transaction");
        let repo = insert_max_age_test_repository(&mut tx).await;
        let mut ids = Vec::new();
        for path in ["builds/a", "builds/b", "releases/c"] {
            let key = format!("generic/{}", Uuid::new_v4());
            let path = format!("{path}-{repo}");
            ids.push(insert_max_age_test_artifact(&mut tx, repo, &path, "1", &key, 365).await);
        }
        config["match"] = json!({"path_prefix": "builds/"});
        let result = preview_then_run(&mut tx, &policy(policy_type, Some(repo), config)).await;
        assert_eq!(result.artifacts_matched, 2, "{policy_type}: {result:?}");
        assert!(is_deleted(&mut tx, ids[0]).await && is_deleted(&mut tx, ids[1]).await);
        assert!(
            !is_deleted(&mut tx, ids[2]).await,
            "{policy_type} left its scope"
        );
        tx.rollback().await.expect("rollback test transaction");
    }
}

/// The prefix is literal: `%` and `_` are not wildcards, as they would be if
/// the predicate were a `LIKE`.
#[tokio::test]
async fn match_path_prefix_is_literal_2024() {
    let Some(pool) = crate::testing::try_pool_with(1).await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin test transaction");
    let repo = insert_max_age_test_repository(&mut tx).await;
    let key = format!("generic/{}", Uuid::new_v4());
    let id =
        insert_max_age_test_artifact(&mut tx, repo, &format!("builds/x-{repo}"), "1", &key, 365)
            .await;
    for prefix in ["build%", "build_/", "%"] {
        let config = json!({"days": 1, "match": {"path_prefix": prefix}});
        let result = preview_then_run(&mut tx, &policy("max_age_days", Some(repo), config)).await;
        assert_eq!(
            result.artifacts_matched, 0,
            "{prefix} must not act as a wildcard"
        );
    }
    assert!(!is_deleted(&mut tx, id).await);
    tx.rollback().await.expect("rollback test transaction");
}
