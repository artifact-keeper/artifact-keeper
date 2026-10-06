//! #4461: every lifecycle regex (`pattern`, `exclude.version_patterns`,
//! `match.version_pattern`) is a PostgreSQL regex and is validated as one.

use super::tests::make_service_for_validation;
use super::*;
use serde_json::json;

/// Patterns the Rust `regex` crate accepts but PostgreSQL cannot compile,
/// plus two neither accepts.
const NOT_POSTGRES: [&str; 6] = [
    r"^v\d+\z",
    r"\pL",
    r"(?P<n>sha)",
    r"^sha-(?i)abc",
    "[unclosed",
    "(((",
];

fn create(policy_type: &str, config: serde_json::Value) -> CreateLifecyclePolicyRequest {
    CreateLifecyclePolicyRequest {
        name: format!("pg-regex-4461-{}", Uuid::new_v4()),
        policy_type: policy_type.into(),
        config,
        ..Default::default()
    }
}

/// Store a policy without going through validation, as one written before
/// #4461 would be.
async fn insert_unvalidated(pool: &PgPool, policy_type: &str, config: serde_json::Value) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO lifecycle_policies (name, policy_type, config) VALUES ($1, $2, $3) \
         RETURNING id",
    )
    .bind(format!("stored-regex-4461-{}", Uuid::new_v4()))
    .bind(policy_type)
    .bind(config)
    .fetch_one(pool)
    .await
    .expect("insert stored policy")
}

/// PostgreSQL-only syntax the Rust `regex` crate rejects -- including the
/// `\y` word boundary the `\b` error tells operators to use -- passes the
/// static check; PostgreSQL is the judge.
#[tokio::test]
async fn postgres_only_syntax_passes_static_validation_4461() {
    let service = make_service_for_validation();
    for pattern in [r"\ystable\y", r"^(a)\1$", r"\mrc\M"] {
        assert!(regex::Regex::new(pattern).is_err(), "{pattern}");
        for (policy_type, config) in [
            ("tag_pattern_keep", json!({"pattern": pattern})),
            (
                "max_age_days",
                json!({"days": 1, "exclude": {"version_patterns": [pattern]}}),
            ),
            (
                "max_age_days",
                json!({"days": 1, "match": {"version_pattern": pattern}}),
            ),
        ] {
            service
                .validate_policy_config(policy_type, &config)
                .unwrap_or_else(|e| panic!("{policy_type} {pattern}: {e}"));
        }
    }
}

#[test]
fn policy_regexes_collects_every_field_4461() {
    let config = json!({
        "pattern": "^tmp-",
        "exclude": {"versions": ["latest"], "version_patterns": ["^v1", 7, "stable"]},
        "match": {"version_pattern": "^sha-"},
    });
    assert_eq!(
        policy_regexes("tag_pattern_delete", &config),
        vec![
            ("pattern".to_string(), "^tmp-".to_string()),
            ("exclude.version_patterns[0]".to_string(), "^v1".to_string()),
            (
                "exclude.version_patterns[2]".to_string(),
                "stable".to_string()
            ),
            ("match.version_pattern".to_string(), "^sha-".to_string()),
        ]
    );
    // `pattern` is only a regex on the tag_pattern_* types.
    assert_eq!(
        policy_regexes("max_age_days", &json!({"days": 1, "pattern": "x"})),
        Vec::<(String, String)>::new()
    );
}

#[tokio::test]
async fn every_regex_rejects_rust_only_word_boundaries_4461() {
    let service = make_service_for_validation();
    let cases = [
        (
            "tag_pattern_keep",
            json!({"pattern": r"\bstable\b"}),
            "pattern",
        ),
        ("tag_pattern_delete", json!({"pattern": r"^x\B"}), "pattern"),
        (
            "max_age_days",
            json!({"days": 1, "exclude": {"version_patterns": ["^v1", r"\bstable\b"]}}),
            "exclude.version_patterns[1]",
        ),
    ];
    for (policy_type, config, field) in cases {
        let err = service
            .validate_policy_config(policy_type, &config)
            .expect_err(field);
        let message = err.to_string();
        assert!(
            message.contains(field) && message.contains(r"\y"),
            "{message}"
        );
    }
    // An escaped backslash followed by `b` is a literal, not a boundary.
    service
        .validate_policy_config("tag_pattern_keep", &json!({"pattern": r"^a\\b"}))
        .expect("escaped backslash");
    assert!(has_backspace_escape(r"a\Bb"));
    assert!(!has_backspace_escape(r"a\\b\y"));
    assert!(matches!(
        postgres_regex_error("pattern", Some("2201B"), "bad"),
        AppError::Validation(m) if m == "pattern is not a valid PostgreSQL regular expression: bad"
    ));
}

/// `pattern` and `exclude.version_patterns` are compiled by PostgreSQL on
/// create and update, as `match.version_pattern` is since #4459.
#[tokio::test]
async fn every_regex_is_validated_by_postgres_4461() {
    let Some(pool) = crate::testing::try_pool_with(1).await else {
        return;
    };
    let service = LifecycleService::new(pool.clone());
    for pattern in NOT_POSTGRES {
        for (policy_type, config, field) in [
            ("tag_pattern_delete", json!({"pattern": pattern}), "pattern"),
            (
                "max_versions",
                json!({"keep": 1, "exclude": {"version_patterns": [pattern]}}),
                "exclude.version_patterns[0]",
            ),
            (
                "max_age_days",
                json!({"days": 1, "match": {"version_pattern": pattern}}),
                "match.version_pattern",
            ),
        ] {
            match service.create_policy(create(policy_type, config)).await {
                Err(AppError::Validation(m)) => {
                    assert!(
                        m.contains(field) && m.contains("PostgreSQL"),
                        "{pattern}: {m}"
                    )
                }
                other => panic!("{pattern}: expected a validation error, got {other:?}"),
            }
        }
    }
    let created = service
        .create_policy(create("tag_pattern_keep", json!({"pattern": r"^v1\.0\y"})))
        .await
        .expect("a PostgreSQL word boundary is valid");
    match service
        .update_policy(
            created.id,
            UpdateLifecyclePolicyRequest {
                config: Some(json!({"pattern": r"\pL"})),
                ..Default::default()
            },
        )
        .await
    {
        Err(AppError::Validation(m)) => assert!(m.contains("PostgreSQL"), "{m}"),
        other => panic!("update: expected a validation error, got {other:?}"),
    }
    service.delete_policy(created.id).await.expect("cleanup");
}

/// A stored policy whose exclusion uses `\b` (protects nothing) or whose
/// pattern PostgreSQL cannot compile is named by the startup scan and by the
/// preview, and is left unchanged.
#[tokio::test]
async fn stored_policy_regex_problems_are_reported_4461() {
    let Some(pool) = crate::testing::try_pool_with(2).await else {
        return;
    };
    let boundary_config = json!({"days": 1, "exclude": {"version_patterns": [r"\bstable\b"]}});
    let boundary = insert_unvalidated(&pool, "max_age_days", boundary_config.clone()).await;
    let broken = insert_unvalidated(&pool, "tag_pattern_delete", json!({"pattern": r"\pL"})).await;
    let clean = insert_unvalidated(&pool, "tag_pattern_delete", json!({"pattern": "^tmp-"})).await;

    let mut conn = pool.acquire().await.expect("acquire");
    let offending = invalid_regex_policies(&mut conn).await.expect("scan");
    drop(conn);
    let problems_of = |id: Uuid| {
        offending
            .iter()
            .find(|(policy_id, _, _)| *policy_id == id)
            .map(|(_, _, problems)| problems.clone())
    };
    let found = problems_of(boundary).expect("the \\b exclusion is reported");
    assert!(
        found[0].runnable && found[0].message.contains(r"\y"),
        "{found:?}"
    );
    let found = problems_of(broken).expect("the uncompilable pattern is reported");
    assert!(
        !found[0].runnable && found[0].message.contains("PostgreSQL"),
        "{found:?}"
    );
    assert!(problems_of(clean).is_none());
    warn_invalid_lifecycle_regexes(&pool).await;

    let service = LifecycleService::new(pool.clone());
    let preview = service
        .execute_policy(boundary, true)
        .await
        .expect("preview");
    assert_eq!(preview.errors.len(), 1, "{preview:?}");
    assert!(preview.errors[0].contains("exclude.version_patterns[0]"));
    let preview = service.execute_policy(broken, true).await.expect("preview");
    assert!(preview.errors[0].contains("PostgreSQL"), "{preview:?}");
    let preview = service.execute_policy(clean, true).await.expect("preview");
    assert!(preview.errors.is_empty(), "{preview:?}");

    let stored = service.get_policy(boundary).await.expect("stored");
    assert_eq!(
        stored.config, boundary_config,
        "the stored config is not rewritten"
    );
    for id in [boundary, broken, clean] {
        service.delete_policy(id).await.expect("cleanup");
    }
}
