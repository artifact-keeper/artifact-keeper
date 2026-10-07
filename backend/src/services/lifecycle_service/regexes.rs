//! Lifecycle policy regexes (#4459, #4461).
//!
//! Every regex a policy carries (`pattern` of the `tag_pattern_*` types, each
//! `exclude.version_patterns` entry, `match.version_pattern`) is executed by
//! PostgreSQL (`~` / `!~` / `~ ANY`), so PostgreSQL is the judge of whether it
//! is valid. It is compiled there at create/update time, on its own pooled
//! connection under a statement timeout, never inside the write transaction.
//! Static rules on top (length, `\b`/`\B`, back-references) refuse what
//! PostgreSQL would accept but a retention policy has no business running.

use super::*;
use sqlx::Connection;

/// Longest accepted lifecycle regex, in bytes. Versions and tags are short;
/// a long pattern only adds PostgreSQL compile cost.
pub(crate) const MAX_REGEX_BYTES: usize = 512;

/// Most `exclude.version_patterns` entries one policy may carry.
pub(crate) const MAX_VERSION_PATTERNS: usize = 64;

/// Statement timeout for one PostgreSQL regex compile. Compile time grows
/// steeply with pattern complexity (`repeat('(a?)', 1000)` takes ~0.5 s), so
/// every compile this module issues is bounded.
const REGEX_COMPILE_TIMEOUT_MS: u32 = 2_000;

/// SQLSTATE `invalid_regular_expression`.
const INVALID_REGULAR_EXPRESSION: &str = "2201B";

/// SQLSTATE `query_canceled` (here: the statement timeout fired).
const QUERY_CANCELED: &str = "57014";

/// Every regex a policy `config` carries, paired with the config path it came
/// from.
///
/// Deliberately lenient (non-string entries are skipped, not rejected): it
/// also reads stored configs for the startup and preview reports, where the
/// shape was validated when the policy was written.
pub(crate) fn policy_regexes(
    policy_type: &str,
    config: &serde_json::Value,
) -> Vec<(String, String)> {
    let mut found = Vec::new();
    if matches!(policy_type, "tag_pattern_keep" | "tag_pattern_delete") {
        if let Some(pattern) = config.get("pattern").and_then(|v| v.as_str()) {
            found.push(("pattern".to_string(), pattern.to_string()));
        }
    }
    let excluded = config
        .get(EXCLUDE_CONFIG_KEY)
        .and_then(|e| e.get("version_patterns"))
        .and_then(|v| v.as_array());
    for (i, pattern) in excluded.into_iter().flatten().enumerate() {
        if let Some(pattern) = pattern.as_str() {
            found.push((
                format!("exclude.version_patterns[{i}]"),
                pattern.to_string(),
            ));
        }
    }
    if let Some(pattern) = config
        .get(MATCH_CONFIG_KEY)
        .and_then(|m| m.get("version_pattern"))
        .and_then(|v| v.as_str())
    {
        found.push(("match.version_pattern".to_string(), pattern.to_string()));
    }
    found
}

/// The unescaped escape letters of `pattern`, in order: for `a\\b\yc\1` that
/// is `['y', '1']` (an escaped backslash is skipped as a pair).
fn escapes(pattern: &str) -> Vec<char> {
    let mut found = Vec::new();
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('\\') | None => {}
                Some(escaped) => found.push(escaped),
            }
        }
    }
    found
}

/// True when `pattern` contains an unescaped `\b` or `\B`.
pub(crate) fn has_backspace_escape(pattern: &str) -> bool {
    escapes(pattern).iter().any(|c| matches!(c, 'b' | 'B'))
}

/// The first static problem with a lifecycle regex, as a message, or `None`.
///
/// * longer than [`MAX_REGEX_BYTES`];
/// * `\b` / `\B`: word boundaries in the Rust `regex` crate but "backspace"
///   and "backslash" in PostgreSQL, so the pattern silently matches nothing
///   (an exclusion then protects nothing). PostgreSQL spells them `\y`/`\Y`;
/// * a back-reference `\1`..`\9`: valid in PostgreSQL but useless for
///   matching versions, and the expensive part of its regex engine.
fn static_regex_problem(field: &str, pattern: &str) -> Option<String> {
    if pattern.len() > MAX_REGEX_BYTES {
        return Some(format!(
            "{field} is {} bytes long; at most {MAX_REGEX_BYTES} are allowed",
            pattern.len()
        ));
    }
    let escapes = escapes(pattern);
    if escapes.iter().any(|c| matches!(c, 'b' | 'B')) {
        return Some(format!(
            "{field}: \\b and \\B are not word boundaries in a PostgreSQL regex; use \\y / \\Y"
        ));
    }
    if escapes.iter().any(|c| matches!(c, '1'..='9')) {
        return Some(format!(
            "{field}: back-references (\\1 to \\9) are not supported in lifecycle patterns"
        ));
    }
    None
}

/// [`static_regex_problem`] as a validation error.
pub(crate) fn reject_static_regex_problems(field: &str, pattern: &str) -> Result<()> {
    match static_regex_problem(field, pattern) {
        Some(message) => Err(AppError::Validation(message)),
        None => Ok(()),
    }
}

/// Refuse `\b` / `\B` only (the execution-time check `parse_match` keeps for
/// `match.version_pattern`, #4459).
pub(crate) fn reject_backspace_escape(field: &str, pattern: &str) -> Result<()> {
    if has_backspace_escape(pattern) {
        return Err(AppError::Validation(format!(
            "{field}: \\b and \\B are not word boundaries in a PostgreSQL regex; use \\y / \\Y"
        )));
    }
    Ok(())
}

/// Map a failed PostgreSQL regex compile to a validation error (invalid, or
/// too expensive to compile within the timeout); anything else stays a
/// database error.
pub(crate) fn postgres_regex_error(field: &str, code: Option<&str>, message: &str) -> AppError {
    match code {
        Some(INVALID_REGULAR_EXPRESSION) => AppError::Validation(format!(
            "{field} is not a valid PostgreSQL regular expression: {message}"
        )),
        Some(QUERY_CANCELED) => AppError::Validation(format!(
            "{field} is too expensive for PostgreSQL to compile; simplify the pattern"
        )),
        _ => AppError::Database(message.to_string()),
    }
}

/// Compile `pattern` with PostgreSQL (`SELECT '' ~ $1`) in a throwaway
/// transaction on `conn` whose `statement_timeout` is `timeout_ms`, so a
/// pathological pattern costs at most that long and leaves the session as it
/// found it.
pub(crate) async fn compile_in_postgres(
    conn: &mut sqlx::PgConnection,
    field: &str,
    pattern: &str,
    timeout_ms: u32,
) -> Result<()> {
    let db_error = |e: sqlx::Error| AppError::Database(e.to_string());
    let mut tx = conn.begin().await.map_err(db_error)?;
    sqlx::query("SELECT set_config('statement_timeout', $1, true)")
        .bind(timeout_ms.to_string())
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
    let compiled = sqlx::query("SELECT '' ~ $1")
        .bind(pattern)
        .execute(&mut *tx)
        .await;
    // Read-only; rolling back also drops the LOCAL timeout. A failed compile
    // aborted the transaction anyway.
    let _ = tx.rollback().await;
    compiled
        .map(|_| ())
        .map_err(|e| match e.as_database_error() {
            Some(db) => postgres_regex_error(field, db.code().as_deref(), db.message()),
            None => db_error(e),
        })
}

/// Validate every regex of a policy config for create/update: the static
/// rules, then a bounded PostgreSQL compile. Runs on its own pooled
/// connection, BEFORE the caller opens its write transaction, so no lock is
/// held while PostgreSQL compiles.
pub(crate) async fn validate_regexes_in_postgres(
    db: &PgPool,
    policy_type: &str,
    config: &serde_json::Value,
) -> Result<()> {
    let regexes = policy_regexes(policy_type, config);
    if regexes.is_empty() {
        return Ok(());
    }
    let mut conn = db
        .acquire()
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    for (field, pattern) in regexes {
        reject_static_regex_problems(&field, &pattern)?;
        compile_in_postgres(&mut conn, &field, &pattern, REGEX_COMPILE_TIMEOUT_MS).await?;
    }
    Ok(())
}

/// What is wrong with a regex stored in an existing policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoredRegexIssue {
    /// PostgreSQL cannot compile it (or not within the timeout): every run
    /// of the policy errors.
    DoesNotCompile,
    /// It uses `\b`/`\B`: it runs, but matches nothing.
    WordBoundary,
}

/// One problem with a regex stored in an existing policy (#4461).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredRegexProblem {
    pub(crate) field: String,
    pub(crate) message: String,
    pub(crate) issue: StoredRegexIssue,
}

impl StoredRegexProblem {
    /// The policy cannot run as stored, so a preview stops here: the pattern
    /// does not compile, or it is a `match.version_pattern` with `\b`/`\B`,
    /// which a run refuses (#4459, #4502). A selector that "matches nothing"
    /// is not safe in general: inside a negative lookahead such as
    /// `^(?!.*\bstable)` it makes the scope match EVERY version.
    pub(crate) fn blocks_run(&self) -> bool {
        self.issue == StoredRegexIssue::DoesNotCompile || self.is_match_word_boundary()
    }

    /// `match.version_pattern` with `\b`/`\B` (#4459).
    fn is_match_word_boundary(&self) -> bool {
        self.issue == StoredRegexIssue::WordBoundary && self.field == "match.version_pattern"
    }

    /// A live run of a policy of `policy_type` must refuse this problem.
    pub(crate) fn refuses_live_run(&self, policy_type: &str) -> bool {
        self.fails_open(policy_type) || self.is_match_word_boundary()
    }

    /// The pattern PROTECTS artifacts in a policy of `policy_type` (an
    /// exclusion, or the keep pattern of `tag_pattern_keep`), so matching
    /// nothing fails open: the policy deletes what it was written to keep.
    /// `match.version_pattern` and `tag_pattern_delete` select what to delete,
    /// so for them matching nothing deletes nothing.
    pub(crate) fn fails_open(&self, policy_type: &str) -> bool {
        self.field.starts_with("exclude.")
            || (policy_type == "tag_pattern_keep" && self.field == "pattern")
    }
}

/// Re-check the regexes of a policy that is already stored. Validation only
/// runs on create/update, so policies written before #4461 can still carry a
/// pattern PostgreSQL rejects or a `\b`; they are reported (preview errors,
/// startup WARN) and, when they fail open, refused for live runs — never
/// silently rewritten. Each compile is bounded by the same timeout as
/// create/update. A pattern can have both problems; each is reported.
pub(crate) async fn stored_regex_problems(
    conn: &mut sqlx::PgConnection,
    policy_type: &str,
    config: &serde_json::Value,
) -> Result<Vec<StoredRegexProblem>> {
    let mut problems = Vec::new();
    for (field, pattern) in policy_regexes(policy_type, config) {
        let mut report = |message: String, issue| {
            problems.push(StoredRegexProblem {
                field: field.clone(),
                message,
                issue,
            })
        };
        match compile_in_postgres(conn, &field, &pattern, REGEX_COMPILE_TIMEOUT_MS).await {
            Ok(()) => {}
            Err(AppError::Validation(message)) => report(message, StoredRegexIssue::DoesNotCompile),
            Err(other) => return Err(other),
        }
        if let Err(AppError::Validation(message)) = reject_backspace_escape(&field, &pattern) {
            report(message, StoredRegexIssue::WordBoundary);
        }
    }
    Ok(problems)
}

/// Every stored lifecycle policy with a regex problem, with its problems.
pub(crate) async fn invalid_regex_policies(
    conn: &mut sqlx::PgConnection,
) -> Result<Vec<(Uuid, String, Vec<StoredRegexProblem>)>> {
    let policies: Vec<(Uuid, String, String, serde_json::Value)> = sqlx::query_as(
        "SELECT id, name, policy_type, config FROM lifecycle_policies ORDER BY created_at",
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    let mut offending = Vec::new();
    for (id, name, policy_type, config) in policies {
        let problems = stored_regex_problems(conn, &policy_type, &config).await?;
        if !problems.is_empty() {
            offending.push((id, name, problems));
        }
    }
    Ok(offending)
}

/// Log one WARN per stored lifecycle policy with a regex problem (#4461).
/// Runs once per boot; the stored configs are left untouched. Never fails
/// startup.
pub async fn warn_invalid_lifecycle_regexes(db: &PgPool) {
    let report = async {
        let mut conn = db
            .acquire()
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
        invalid_regex_policies(&mut conn).await
    };
    match report.await {
        Ok(offending) => {
            for (id, name, problems) in offending {
                let messages: Vec<&str> = problems.iter().map(|p| p.message.as_str()).collect();
                tracing::warn!(
                    policy_id = %id,
                    policy_name = %name,
                    "lifecycle policy has a regex PostgreSQL does not run as written; a live run \
                     refuses it when the pattern protects artifacts (fix it with \
                     PATCH /api/v1/admin/lifecycle/{{id}}): {}",
                    messages.join("; ")
                );
            }
        }
        Err(e) => tracing::warn!("lifecycle regex startup check failed: {e}"),
    }
}

/// The error a live run of `policy_name` (a `policy_type` policy) returns for
/// its stored-regex `problems`, or `None` when it may run (#4461, #4502).
pub(crate) fn live_run_refusal(
    policy_name: &str,
    policy_type: &str,
    problems: &[StoredRegexProblem],
) -> Option<AppError> {
    let problem = problems.iter().find(|p| p.refuses_live_run(policy_type))?;
    let why = if problem.fails_open(policy_type) {
        "This pattern protects artifacts and would protect nothing as written"
    } else {
        "PostgreSQL cannot run this pattern as written"
    };
    Some(AppError::Validation(format!(
        "Refusing to run lifecycle policy '{policy_name}': {}. {why}; fix the policy",
        problem.message
    )))
}
