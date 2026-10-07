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
    for pattern in [r"\ystable\y", r"\mrc\M"] {
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
    let both = insert_unvalidated(&pool, "tag_pattern_delete", json!({"pattern": r"\bfoo("})).await;

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
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].issue, StoredRegexIssue::WordBoundary);
    assert!(found[0].message.contains(r"\y"), "{found:?}");
    assert!(found[0].fails_open("max_age_days") && !found[0].blocks_run("max_age_days"));
    let found = problems_of(broken).expect("the uncompilable pattern is reported");
    assert_eq!(found[0].issue, StoredRegexIssue::DoesNotCompile);
    assert!(found[0].message.contains("PostgreSQL"), "{found:?}");
    assert!(
        found[0].blocks_run("tag_pattern_delete") && !found[0].fails_open("tag_pattern_delete")
    );
    // `\b` AND a syntax error: compiled first, so it is classed as
    // not compiling (the preview stops rather than erroring out later).
    let found = problems_of(both).expect("the \\b + syntax error pattern is reported");
    let issues: Vec<_> = found.iter().map(|p| p.issue).collect();
    assert_eq!(
        issues,
        vec![
            StoredRegexIssue::DoesNotCompile,
            StoredRegexIssue::WordBoundary
        ]
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
    let preview = service.execute_policy(both, true).await.expect("preview");
    assert_eq!(preview.errors.len(), 2, "{preview:?}");
    assert_eq!(preview.artifacts_matched, 0);

    let stored = service.get_policy(boundary).await.expect("stored");
    assert_eq!(
        stored.config, boundary_config,
        "the stored config is not rewritten"
    );
    for id in [boundary, broken, clean, both] {
        service.delete_policy(id).await.expect("cleanup");
    }
}

#[tokio::test]
async fn static_rules_refuse_backrefs_long_patterns_and_long_lists_4461() {
    let service = make_service_for_validation();
    let long = "a".repeat(MAX_REGEX_BYTES + 1);
    let cases = [
        (
            "tag_pattern_keep",
            json!({"pattern": r"^(v)\1"}),
            "back-references",
        ),
        (
            "max_age_days",
            json!({"days": 1, "exclude": {"version_patterns": [r"(a)\2"]}}),
            "back-references",
        ),
        (
            "max_age_days",
            json!({"days": 1, "match": {"version_pattern": r"(a)\9"}}),
            "back-references",
        ),
        ("tag_pattern_delete", json!({"pattern": long}), "bytes long"),
        (
            "max_age_days",
            json!({"days": 1, "exclude": {"version_patterns": vec!["^v"; MAX_VERSION_PATTERNS + 1]}}),
            "at most 64",
        ),
    ];
    for (policy_type, config, needle) in cases {
        let err = service
            .validate_policy_config(policy_type, &config)
            .expect_err(needle);
        assert!(
            matches!(&err, AppError::Validation(m) if m.contains(needle)),
            "{err:?}"
        );
    }
    // The limits themselves are accepted, and `\\1` is an escaped backslash.
    service
        .validate_policy_config(
            "max_age_days",
            &json!({"days": 1, "exclude": {"version_patterns": vec!["^v"; MAX_VERSION_PATTERNS]}}),
        )
        .expect("64 patterns");
    service
        .validate_policy_config(
            "tag_pattern_keep",
            &json!({"pattern": format!(r"\\1{}", "a".repeat(MAX_REGEX_BYTES - 3))}),
        )
        .expect("an escaped backslash and a pattern at the length limit");
    assert!(matches!(
        postgres_regex_error("pattern", Some("57014"), "canceling statement due to statement timeout"),
        AppError::Validation(m) if m.contains("too expensive")
    ));
}

/// A pattern that takes longer than the statement timeout to compile is a
/// validation error, not a hung connection.
#[tokio::test]
async fn slow_regex_compile_is_bounded_by_the_timeout_4461() {
    let Some(pool) = crate::testing::try_pool_with(1).await else {
        return;
    };
    let mut conn = pool.acquire().await.expect("acquire");
    // ~0.5 s to compile on PostgreSQL 16; the timeout here is 1 ms.
    let expensive = "(a?)".repeat(1000);
    match compile_in_postgres(&mut conn, "pattern", &expensive, 1).await {
        Err(AppError::Validation(m)) => assert!(m.contains("too expensive"), "{m}"),
        other => panic!("expected a timeout validation error, got {other:?}"),
    }
    // The session is unaffected: no lingering timeout, no aborted transaction.
    compile_in_postgres(&mut conn, "pattern", "^v[0-9]+", 1_000)
        .await
        .expect("the connection still works");
    let timeout: String = sqlx::query_scalar("SHOW statement_timeout")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert_ne!(timeout, "1ms");
}

/// A live run refuses a stored policy whose PROTECTIVE pattern (an
/// exclusion, or the keep pattern of tag_pattern_keep) fails open, and one
/// whose selecting pattern (`match.version_pattern`, or the `pattern` of
/// tag_pattern_delete) uses `\b` (#4459, #4502). Nothing stored is changed.
#[tokio::test]
async fn live_run_refuses_fail_open_stored_patterns_4461() {
    let Some(pool) = crate::testing::try_pool_with(2).await else {
        return;
    };
    let service = LifecycleService::new(pool.clone());
    let refused = [
        (
            "max_age_days",
            json!({"days": 1, "exclude": {"version_patterns": [r"\bstable\b"]}}),
        ),
        (
            "max_age_days",
            json!({"days": 1, "exclude": {"version_patterns": [r"\pL"]}}),
        ),
        ("tag_pattern_keep", json!({"pattern": r"\bstable\b"})),
        ("tag_pattern_keep", json!({"pattern": r"(?P<n>x)"})),
        (
            "max_age_days",
            json!({"days": 1, "match": {"version_pattern": r"\bsha"}}),
        ),
        ("tag_pattern_delete", json!({"pattern": r"\btmp"})),
    ];
    for (policy_type, config) in refused {
        let id = insert_unvalidated(&pool, policy_type, config.clone()).await;
        match service.execute_policy(id, false).await {
            Err(AppError::Validation(m)) => assert!(m.contains("Refusing to run"), "{m}"),
            other => panic!("{config}: expected a refusal, got {other:?}"),
        }
        assert_eq!(service.get_policy(id).await.unwrap().config, config);
        service.delete_policy(id).await.expect("cleanup");
    }
}

/// A repository holding one 30-day-old artifact with `version`, for the
/// stored-policy run tests below. Returns `(repository, artifact)`.
async fn repository_with_artifact(conn: &mut sqlx::PgConnection, version: &str) -> (Uuid, Uuid) {
    let repository_id = super::tests::insert_max_age_test_repository(conn).await;
    let storage_key = format!("generic/{}", Uuid::new_v4());
    let path = format!("builds/{version}");
    let artifact = super::tests::insert_max_age_test_artifact(
        conn,
        repository_id,
        &path,
        version,
        &storage_key,
        30,
    )
    .await;
    (repository_id, artifact)
}

/// Assign stored policy `policy_id` to `repository_id`.
async fn assign_repository(conn: &mut sqlx::PgConnection, policy_id: Uuid, repository_id: Uuid) {
    sqlx::query(
        "INSERT INTO lifecycle_policy_repositories (policy_id, repository_id) VALUES ($1, $2)",
    )
    .bind(policy_id)
    .bind(repository_id)
    .execute(conn)
    .await
    .expect("assign repository");
}

async fn drop_repository(conn: &mut sqlx::PgConnection, repository_id: Uuid) {
    let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repository_id)
        .execute(conn)
        .await;
}

/// #4502: a stored `match.version_pattern` with `\b`, on a policy that has a
/// repository with a matching-looking artifact. The preview reports it in
/// `errors` and matches nothing (it used to be a 400 from `parse_match`), and
/// a live run refuses it up front and deletes nothing.
#[tokio::test]
async fn stored_match_word_boundary_is_previewed_and_refused_4502() {
    let Some(pool) = crate::testing::try_pool_with(2).await else {
        return;
    };
    let mut conn = pool.acquire().await.expect("acquire");
    let (repository_id, artifact) = repository_with_artifact(&mut conn, "foo-1").await;
    let config = json!({"days": 1, "match": {"version_pattern": r"\bfoo"}});
    let id = insert_unvalidated(&pool, "max_age_days", config.clone()).await;
    assign_repository(&mut conn, id, repository_id).await;

    let service = LifecycleService::new(pool.clone());
    let preview = service
        .execute_policy(id, true)
        .await
        .expect("the preview reports the pattern instead of failing");
    assert_eq!(preview.errors.len(), 1, "{preview:?}");
    assert!(
        preview.errors[0].contains("match.version_pattern") && preview.errors[0].contains(r"\y"),
        "{preview:?}"
    );
    assert_eq!(preview.artifacts_matched, 0);
    match service.execute_policy(id, false).await {
        Err(AppError::Validation(m)) => assert!(
            m.contains("Refusing to run") && m.contains("match.version_pattern"),
            "{m}"
        ),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(!super::tests::is_deleted(&mut conn, artifact).await);
    assert_eq!(service.get_policy(id).await.unwrap().config, config);

    service.delete_policy(id).await.expect("cleanup");
    drop_repository(&mut conn, repository_id).await;
}

/// Which stored-regex problems refuse a live run, and with what message.
#[test]
fn live_run_refusal_covers_protective_and_unrunnable_patterns_4502() {
    let problem = |field: &str, issue| StoredRegexProblem {
        field: field.to_string(),
        message: format!("{field}: bad"),
        issue,
    };
    let exclusion = problem(
        "exclude.version_patterns[0]",
        StoredRegexIssue::WordBoundary,
    );
    let matcher = problem("match.version_pattern", StoredRegexIssue::WordBoundary);
    let delete = problem("pattern", StoredRegexIssue::WordBoundary);

    let refusal = |policy_type: &str, problems: &[StoredRegexProblem]| {
        live_run_refusal("p", policy_type, problems).map(|e| e.to_string())
    };
    let m = refusal("max_age_days", &[exclusion]).expect("exclusion");
    assert!(m.contains("would protect nothing"), "{m}");
    assert!(matcher.blocks_run("max_age_days"));
    let m = refusal("max_age_days", &[matcher]).expect("match pattern");
    assert!(
        m.contains("match.version_pattern") && m.contains("cannot run this pattern"),
        "{m}"
    );
    // #4504: a pattern that does not compile refuses every policy type.
    let broken = problem("pattern", StoredRegexIssue::DoesNotCompile);
    let m = refusal("tag_pattern_delete", &[broken]).expect("does not compile");
    assert!(m.contains("cannot run this pattern"), "{m}");
    assert!(refusal("tag_pattern_keep", std::slice::from_ref(&delete)).is_some());
    // A `tag_pattern_delete` pattern with `\b` selects what to delete, like
    // `match.version_pattern`, so it is refused for the same reason.
    assert!(delete.blocks_run("tag_pattern_delete"));
    let m = refusal("tag_pattern_delete", &[delete]).expect("delete pattern");
    assert!(m.contains("cannot run this pattern"), "{m}");
    // `pattern` is not a selector of other policy types.
    let stray = problem("pattern", StoredRegexIssue::WordBoundary);
    assert!(!stray.blocks_run("max_age_days"));
    assert!(refusal("max_age_days", &[]).is_none());
}

/// #4504: a live run of a stored policy whose `match.version_pattern`
/// PostgreSQL cannot compile is a 400 naming the field, not a 500
/// `DATABASE_ERROR` from the delete query; the preview reports the same
/// problem. Nothing is deleted.
#[tokio::test]
async fn uncompilable_stored_match_pattern_is_a_400_on_a_live_run_4504() {
    let Some(pool) = crate::testing::try_pool_with(2).await else {
        return;
    };
    let mut conn = pool.acquire().await.expect("acquire");
    let (repository_id, artifact) = repository_with_artifact(&mut conn, "foo").await;
    let mut ids = Vec::new();
    for (policy_type, config) in [
        (
            "max_age_days",
            json!({"days": 1, "match": {"version_pattern": r"foo\z"}}),
        ),
        ("tag_pattern_delete", json!({"pattern": r"foo\z"})),
    ] {
        let id = insert_unvalidated(&pool, policy_type, config).await;
        assign_repository(&mut conn, id, repository_id).await;
        ids.push(id);
    }

    let service = LifecycleService::new(pool.clone());
    for (id, field) in ids.iter().zip(["match.version_pattern", "pattern"]) {
        // The exact field-naming text of `postgres_regex_error`: a bare
        // `contains(field)` would also match "... run this pattern ...".
        let named = format!("{field} is not a valid PostgreSQL regular expression");
        let preview = service.execute_policy(*id, true).await.expect("preview");
        assert!(
            preview.errors.iter().any(|e| e.starts_with(&named)),
            "{preview:?}"
        );
        match service.execute_policy(*id, false).await {
            Err(AppError::Validation(m)) => assert!(m.contains(&format!("': {named}")), "{m}"),
            other => panic!("{field}: expected a 400 validation error, got {other:?}"),
        }
    }
    assert!(!super::tests::is_deleted(&mut conn, artifact).await);

    for id in ids {
        service.delete_policy(id).await.expect("cleanup");
    }
    drop_repository(&mut conn, repository_id).await;
}
