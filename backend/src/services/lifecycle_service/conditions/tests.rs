//! #2024 second slice: `composite` policies (`conditions[]`, ANDed) and the
//! `match.version_pattern` scope.

use super::super::policy_scope_tests::{artifact_named, policy, preview_then_run};
use super::super::tests::{
    insert_max_age_test_artifact, insert_max_age_test_repository, is_deleted,
    make_service_for_validation,
};
use super::*;
use serde_json::json;

fn conditions(entries: serde_json::Value) -> serde_json::Value {
    json!({ "conditions": entries })
}

fn age_and_idle(age: i64, idle: i64) -> serde_json::Value {
    conditions(json!([
        {"type": "max_age_days", "value": age},
        {"type": "no_downloads_days", "value": idle},
    ]))
}

// ── parsing and validation ────────────────────────────────────────────────

#[test]
fn parse_conditions_reads_each_window_2024() {
    assert_eq!(
        parse_conditions(&age_and_idle(90, 30)).unwrap(),
        CompositeConditions {
            max_age_days: Some(90),
            no_downloads_days: Some(30),
        }
    );
    let idle_only = conditions(json!([{"type": "no_downloads_days", "value": 7}]));
    assert_eq!(
        parse_conditions(&idle_only).unwrap().windows(),
        [None, Some(7)]
    );
    let huge = conditions(json!([{"type": "max_age_days", "value": i64::from(i32::MAX) + 1}]));
    assert_eq!(
        parse_conditions(&huge).unwrap().max_age_days,
        Some(i32::MAX),
        "an out-of-range window saturates instead of wrapping negative"
    );
}

#[test]
fn parse_conditions_rejects_what_it_cannot_and_2024() {
    let age = json!({"type": "max_age_days", "value": 1});
    for (config, needle) in [
        (json!({}), "requires 'conditions'"),
        (conditions(json!([])), "requires 'conditions'"),
        (
            conditions(json!({"type": "max_age_days"})),
            "requires 'conditions'",
        ),
        (
            conditions(json!(["max_age_days"])),
            "conditions[0] must be an object",
        ),
        (
            conditions(json!([age.clone(), {"type": "max_age_days", "value": 2}])),
            "more than once",
        ),
        (
            conditions(json!([{"type": "max_age_days", "value": 1, "op": "or"}])),
            "conditions[0].op",
        ),
        (
            conditions(json!([{"type": "tag_pattern", "value": "^v"}])),
            "unknown condition type 'tag_pattern'",
        ),
        (
            conditions(json!([{"value": 1}])),
            "unknown condition type ''",
        ),
        (
            conditions(json!([{"type": "min_keep_versions", "value": 5}])),
            "top-level 'min_keep'",
        ),
    ] {
        let err = parse_conditions(&config).expect_err(&format!("{config} must be rejected"));
        assert!(err.to_string().contains(needle), "{config}: {err}");
    }
    for bad in [json!(0), json!(-1), json!("5"), json!(1.5), json!(null)] {
        let config = conditions(json!([age.clone(), {"type": "no_downloads_days", "value": bad}]));
        let err = parse_conditions(&config).expect_err("bad window");
        assert!(
            err.to_string().contains("conditions[1].value"),
            "{bad}: {err}"
        );
    }
}

#[tokio::test]
async fn composite_config_validation_2024() {
    let service = make_service_for_validation();
    let mut full = age_and_idle(90, 30);
    full["min_keep"] = json!(5);
    full["match"] = json!({"path_prefix": "v2/app/", "version_pattern": "^sha-"});
    full["exclude"] = json!({"versions": ["latest"]});
    service
        .validate_policy_config("composite", &full)
        .expect("conditions, min_keep, match and exclude are composite keys");

    for (config, needle) in [
        (json!({"days": 30}), "unknown config key 'days'"),
        (
            json!({"conditions": [{"type": "max_age_days", "value": 1}], "dry_run": true}),
            "unknown config key 'dry_run'",
        ),
        (json!({"min_keep": 1}), "requires 'conditions'"),
    ] {
        let err = service
            .validate_policy_config("composite", &config)
            .expect_err(&format!("{config} must be rejected"));
        assert!(err.to_string().contains(needle), "{err}");
    }
    let mut bad_keep = age_and_idle(1, 1);
    bad_keep["min_keep"] = json!(0);
    assert!(service
        .validate_policy_config("composite", &bad_keep)
        .is_err());
    // Single-condition types still refuse `conditions`: it must not be ignored.
    let err = service
        .validate_policy_config(
            "max_age_days",
            &json!({"days": 1, "conditions": [{"type": "no_downloads_days", "value": 1}]}),
        )
        .expect_err("conditions on max_age_days");
    assert!(err.to_string().contains("'conditions'"), "{err}");
}

#[tokio::test]
async fn match_version_pattern_validation_2024() {
    let service = make_service_for_validation();
    for (policy_type, mut config) in [
        ("max_age_days", json!({"days": 14})),
        ("max_versions", json!({"keep": 2})),
        ("no_downloads_days", json!({"days": 14})),
        ("tag_pattern_keep", json!({"pattern": "^v"})),
        ("tag_pattern_delete", json!({"pattern": "^v"})),
        ("size_quota_bytes", json!({"quota_bytes": 10})),
        ("composite", age_and_idle(1, 1)),
    ] {
        config["match"] = json!({"version_pattern": "^sha-[0-9a-f]+$"});
        service
            .validate_policy_config(policy_type, &config)
            .unwrap_or_else(|e| panic!("{policy_type} must accept match.version_pattern: {e}"));
    }
    for (bad, needle) in [
        (json!("("), "Invalid regex in match.version_pattern"),
        (
            json!(""),
            "match.version_pattern must be a non-empty string",
        ),
        (
            json!(["^v"]),
            "match.version_pattern must be a non-empty string",
        ),
    ] {
        let err = service
            .validate_policy_config(
                "max_age_days",
                &json!({"days": 1, "match": {"version_pattern": bad}}),
            )
            .expect_err("bad version_pattern");
        assert!(err.to_string().contains(needle), "{err}");
    }
    assert_eq!(
        parse_policy_filters(&json!({"match": {"path_prefix": "a/", "version_pattern": "^v"}}))
            .unwrap(),
        PolicyFilters {
            path_prefix: Some("a/".into()),
            version_pattern: Some("^v".into()),
            ..PolicyFilters::default()
        }
    );
}

// ── SQL shape ─────────────────────────────────────────────────────────────

#[test]
fn composite_sql_ands_the_single_condition_predicates_2024() {
    for min_keep in [false, true] {
        let (select, update) = composite_sql(min_keep);
        for sql in [select, update] {
            // The exact predicates the single-condition policies run.
            assert!(sql.contains(max_age_expired!("$2")), "{sql}");
            assert!(sql.contains(no_downloads_idle!("a.", "$3")), "{sql}");
            assert!(sql.contains(oci_tag_join!()), "{sql}");
            assert!(
                sql.contains("($2::INT IS NOT NULL OR $3::INT IS NOT NULL)"),
                "fail-closed guard missing:\n{sql}"
            );
            assert_eq!(sql.contains("row_number()"), min_keep, "{sql}");
            if min_keep {
                assert!(sql.contains("expired AND rn > $8::BIGINT"), "{sql}");
                assert!(sql.contains("::INT))) AS expired"), "{sql}");
            }
        }
    }
    assert!(NO_DOWNLOADS_SELECT_SQL.contains(no_downloads_idle!("a.", "$2")));
    assert!(NO_DOWNLOADS_UPDATE_SQL.contains(no_downloads_idle!("artifacts.", "$2")));
}

// ── behaviour against Postgres ────────────────────────────────────────────

async fn downloaded(conn: &mut sqlx::PgConnection, artifact_id: Uuid, days_ago: i32) {
    sqlx::query(
        "INSERT INTO download_statistics (artifact_id, downloaded_at) \
         VALUES ($1, NOW() - make_interval(days => $2::INT))",
    )
    .bind(artifact_id)
    .bind(days_ago)
    .execute(conn)
    .await
    .expect("insert download");
}

async fn artifact(conn: &mut sqlx::PgConnection, repo: Uuid, label: &str, days_ago: i32) -> Uuid {
    let key = format!("generic/{}", Uuid::new_v4());
    let path = format!("{label}-{repo}");
    insert_max_age_test_artifact(conn, repo, &path, "1", &key, days_ago).await
}

/// "Older than 60 days AND not downloaded in 30": an artifact goes only when
/// it fails both, and the live run deletes exactly what the preview counted.
#[tokio::test]
async fn composite_deletes_only_what_meets_every_condition_2024() {
    let Some(pool) = crate::testing::try_pool_with(1).await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin test transaction");
    let repo = insert_max_age_test_repository(&mut tx).await;
    let old_idle = artifact(&mut tx, repo, "old-idle", 100).await;
    let old_pulled = artifact(&mut tx, repo, "old-pulled", 100).await;
    downloaded(&mut tx, old_pulled, 5).await;
    let old_pulled_long_ago = artifact(&mut tx, repo, "old-pulled-long-ago", 100).await;
    downloaded(&mut tx, old_pulled_long_ago, 45).await;
    let young_idle = artifact(&mut tx, repo, "young-idle", 40).await;
    let fresh = artifact(&mut tx, repo, "fresh", 1).await;

    let composite = policy("composite", Some(repo), age_and_idle(60, 30));
    let result = preview_then_run(&mut tx, &composite).await;
    assert_eq!(
        (result.artifacts_matched, result.bytes_matched),
        (2, 246),
        "{result:?}"
    );
    for (id, gone, label) in [
        (old_idle, true, "past both windows"),
        (
            old_pulled_long_ago,
            true,
            "last pull outside the idle window",
        ),
        (old_pulled, false, "pulled inside the idle window"),
        (young_idle, false, "idle but inside the age window"),
        (fresh, false, "inside both windows"),
    ] {
        assert_eq!(is_deleted(&mut tx, id).await, gone, "{label}");
    }
    tx.rollback().await.expect("rollback test transaction");
}

/// A composite policy with a single condition selects exactly what the
/// single-condition policy of that name selects: both expand the same
/// predicate macro.
#[tokio::test]
async fn single_condition_composite_matches_its_plain_policy_2024() {
    let Some(pool) = crate::testing::try_pool_with(1).await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin test transaction");
    let repo = insert_max_age_test_repository(&mut tx).await;
    for (index, age) in [1, 20, 40, 90, 200].into_iter().enumerate() {
        let id = artifact(&mut tx, repo, &format!("a{index}"), age).await;
        if index % 2 == 0 {
            downloaded(&mut tx, id, 25).await;
        }
    }
    for (single_type, days) in [("max_age_days", 30), ("no_downloads_days", 30)] {
        let plain = policy(single_type, Some(repo), json!({"days": days}));
        let composite = policy(
            "composite",
            Some(repo),
            conditions(json!([{"type": single_type, "value": days}])),
        );
        let mut counts = Vec::new();
        for policy in [plain, composite] {
            let preview = LifecycleService::dispatch_execute(&mut tx, &policy, true)
                .await
                .expect("preview");
            counts.push((preview.artifacts_matched, preview.bytes_matched));
        }
        assert_eq!(counts[0], counts[1], "{single_type}");
        assert!(
            counts[0].0 > 0,
            "{single_type} fixture must match something"
        );
    }
    tx.rollback().await.expect("rollback test transaction");
}

/// The issue's use case: delete `sha-*` build images older than 14 days but
/// keep the 2 newest builds, and never touch release tags. The version scope
/// applies before ranking, so release tags neither go nor take a kept slot.
#[tokio::test]
async fn composite_min_keep_ranks_within_version_scope_2024() {
    let Some(pool) = crate::testing::try_pool_with(1).await else {
        return;
    };
    let mut tx = pool.begin().await.expect("begin test transaction");
    let repo = insert_max_age_test_repository(&mut tx).await;
    let mut builds = Vec::new();
    for (index, age) in [1, 20, 30, 40, 50].into_iter().enumerate() {
        let version = format!("sha-{index:07x}");
        let path = format!("v2/app/manifests/{version}-{repo}");
        builds.push(artifact_named(&mut tx, repo, "app", &path, &version, age).await);
    }
    let release = artifact_named(&mut tx, repo, "app", "v2/app/manifests/v1", "v1.0.0", 300).await;
    let latest = artifact_named(&mut tx, repo, "app", "v2/app/manifests/l", "latest", 0).await;

    let mut config = conditions(json!([{"type": "max_age_days", "value": 14}]));
    config["min_keep"] = json!(2);
    config["match"] = json!({"version_pattern": "^sha-"});
    let result = preview_then_run(&mut tx, &policy("composite", Some(repo), config)).await;
    assert_eq!(result.artifacts_matched, 3, "{result:?}");
    for (id, gone) in [
        (builds[0], false),
        (builds[1], false),
        (builds[2], true),
        (builds[3], true),
        (builds[4], true),
        (release, false),
        (latest, false),
    ] {
        assert_eq!(is_deleted(&mut tx, id).await, gone, "{id}");
    }
    tx.rollback().await.expect("rollback test transaction");
}

/// `match.version_pattern` scopes every policy type, in the preview and the
/// live run alike.
#[tokio::test]
async fn match_version_pattern_scopes_every_policy_type_2024() {
    let Some(pool) = crate::testing::try_pool_with(1).await else {
        return;
    };
    let cases = [
        ("max_age_days", json!({"days": 1})),
        ("no_downloads_days", json!({"days": 1})),
        ("tag_pattern_delete", json!({"pattern": "^max-age-test-"})),
        ("max_versions", json!({"keep": 0})),
        ("size_quota_bytes", json!({"quota_bytes": 100})),
        (
            "composite",
            conditions(json!([{"type": "max_age_days", "value": 1}])),
        ),
    ];
    for (policy_type, mut config) in cases {
        let mut tx = pool.begin().await.expect("begin test transaction");
        let repo = insert_max_age_test_repository(&mut tx).await;
        let mut ids = Vec::new();
        for version in ["sha-1", "sha-2", "v1.0.0"] {
            let key = format!("generic/{}", Uuid::new_v4());
            let path = format!("{version}-{repo}");
            ids.push(insert_max_age_test_artifact(&mut tx, repo, &path, version, &key, 365).await);
        }
        config["match"] = json!({"version_pattern": "^sha-"});
        let result = preview_then_run(&mut tx, &policy(policy_type, Some(repo), config)).await;
        assert_eq!(result.artifacts_matched, 2, "{policy_type}: {result:?}");
        assert!(is_deleted(&mut tx, ids[0]).await && is_deleted(&mut tx, ids[1]).await);
        assert!(
            !is_deleted(&mut tx, ids[2]).await,
            "{policy_type} left its version scope"
        );
        tx.rollback().await.expect("rollback test transaction");
    }
}

/// Composite policies run per repository only, like `max_versions`.
#[tokio::test]
async fn composite_requires_a_repository_2024() {
    let Some(pool) = crate::testing::try_pool_with(1).await else {
        return;
    };
    let mut conn = pool.acquire().await.expect("acquire");
    let err = LifecycleService::dispatch_execute(
        &mut conn,
        &policy("composite", None, age_and_idle(1, 1)),
        true,
    )
    .await
    .expect_err("no repository");
    assert!(err.to_string().contains("repository_id"), "{err}");
}
