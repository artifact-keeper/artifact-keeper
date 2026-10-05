//! `composite` lifecycle policies: several deletion conditions ANDed (#2024).
//!
//! ```json
//! { "conditions": [ { "type": "max_age_days",      "value": 90 },
//!                   { "type": "no_downloads_days", "value": 30 } ],
//!   "min_keep": 5,
//!   "match":   { "path_prefix": "v2/app/", "version_pattern": "^sha-" },
//!   "exclude": { "versions": ["latest", "stable"] } }
//! ```
//!
//! An artifact is deleted only when it meets **every** condition. Each
//! condition is the exact predicate of the single-condition policy of the same
//! name ([`max_age_expired!`], [`no_downloads_idle!`]), so a composite policy
//! with one condition selects what that policy selects. `match`, `exclude` and
//! `min_keep` work as they do on `max_age_days`: the scope and exclusions
//! filter before ranking, and `min_keep` keeps the newest N of each retention
//! group whether or not they meet the conditions.
//!
//! The count and the soft-delete of a run come from one macro expansion
//! ([`retention_from_where!`] / [`retention_ranked_cte!`]) with the one
//! [`composite_condition!`], so the preview cannot disagree with the run.
//!
//! A composite policy has no proxy-cache arm: on a non-OCI Remote repository
//! it is refused at assignment (422) and skipped with a reason when global,
//! exactly like the other types `proxy_cache_arm` reports as unsupported
//! (#3734). It never evicts cache entries.

use super::*;

/// Top-level `config` key of a `composite` policy.
pub(crate) const CONDITIONS_CONFIG_KEY: &str = "conditions";

/// Condition types a `composite` policy accepts.
const CONDITION_TYPES: [&str; 2] = ["max_age_days", "no_downloads_days"];

/// The parsed `conditions[]` of a `composite` policy. Each field is the day
/// window of that condition, `None` when the policy does not use it; at least
/// one is always set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CompositeConditions {
    pub(crate) max_age_days: Option<i32>,
    pub(crate) no_downloads_days: Option<i32>,
}

impl CompositeConditions {
    /// The condition windows in `$2, $3` bind order.
    pub(crate) fn windows(&self) -> [Option<i32>; 2] {
        [self.max_age_days, self.no_downloads_days]
    }
}

fn conditions_error(detail: impl std::fmt::Display) -> AppError {
    AppError::Validation(format!("composite {detail}"))
}

/// Parse and validate `config.conditions`. Strict in the same way as
/// `exclude` and `match`: an unknown condition type, a stray key, a repeated
/// type or a non-positive window is a 422, because a condition that is
/// silently dropped widens the AND into a broader delete.
pub(crate) fn parse_conditions(config: &serde_json::Value) -> Result<CompositeConditions> {
    let entries = config
        .get(CONDITIONS_CONFIG_KEY)
        .and_then(|value| value.as_array())
        .filter(|entries| !entries.is_empty())
        .ok_or_else(|| {
            conditions_error(
                "requires 'conditions': a non-empty array of {\"type\", \"value\"} objects",
            )
        })?;
    let mut parsed = CompositeConditions::default();
    for (index, entry) in entries.iter().enumerate() {
        let object = entry.as_object().ok_or_else(|| {
            conditions_error(format_args!(
                "conditions[{index}] must be an object with 'type' and 'value'"
            ))
        })?;
        if let Some(key) = object
            .keys()
            .find(|k| !matches!(k.as_str(), "type" | "value"))
        {
            return Err(conditions_error(format_args!(
                "has unknown key 'conditions[{index}].{key}'. Allowed: type, value"
            )));
        }
        let kind = object.get("type").and_then(|t| t.as_str()).unwrap_or("");
        let slot = match kind {
            "max_age_days" => &mut parsed.max_age_days,
            "no_downloads_days" => &mut parsed.no_downloads_days,
            "min_keep_versions" => {
                return Err(conditions_error(
                    "keeps versions with the top-level 'min_keep' key, not a condition",
                ))
            }
            other => {
                return Err(conditions_error(format_args!(
                    "has unknown condition type '{other}' in conditions[{index}]. Allowed: {}",
                    CONDITION_TYPES.join(", ")
                )))
            }
        };
        let days = object
            .get("value")
            .and_then(|v| v.as_i64())
            .and_then(|days| check_window_days(days, "").ok())
            .ok_or_else(|| {
                conditions_error(format_args!(
                    "conditions[{index}].value must be a positive integer number of days, \
                     at most {MAX_WINDOW_DAYS}"
                ))
            })?;
        if slot.is_some() {
            return Err(conditions_error(format_args!(
                "lists condition '{kind}' more than once; conditions are ANDed, give each type once"
            )));
        }
        *slot = Some(days);
    }
    Ok(parsed)
}

/// The AND of a composite policy's conditions over `a` (`artifacts`) and `ot`
/// ([`oci_tag_join!`]). `$2` is the `max_age_days` window and `$3` the
/// `no_downloads_days` window; a NULL window drops its conjunct. The leading
/// conjunct fails closed: a row with neither window (only reachable by direct
/// SQL, the API rejects an empty `conditions`) selects nothing, never
/// everything.
macro_rules! composite_condition {
    () => {
        concat!(
            "($2::INT IS NOT NULL OR $3::INT IS NOT NULL)\n    AND ($2::INT IS NULL OR ",
            max_age_expired!("$2"),
            ")\n    AND ($3::INT IS NULL OR (",
            no_downloads_idle!("a.", "$3"),
            "))"
        )
    };
}

// Binds: $1 repository, $2 max_age window, $3 no_downloads window, $4..$7 the
// shared filters, [$8 min_keep].
const COMPOSITE_SELECT_SQL: &str = retention_select_sql!(
    "a.repository_id = $1\n    AND ",
    ["$4", "$5", "$6", "$7"],
    composite_condition!()
);
const COMPOSITE_UPDATE_SQL: &str = retention_update_sql!(
    "a.repository_id = $1\n    AND ",
    ["$4", "$5", "$6", "$7"],
    composite_condition!()
);
const COMPOSITE_MIN_KEEP_SELECT_SQL: &str = retention_ranked_select_sql!(
    "a.repository_id = $1\n    AND ",
    ["$4", "$5", "$6", "$7"],
    "$8",
    composite_condition!()
);
const COMPOSITE_MIN_KEEP_UPDATE_SQL: &str = retention_ranked_update_sql!(
    "a.repository_id = $1\n    AND ",
    ["$4", "$5", "$6", "$7"],
    "$8",
    composite_condition!()
);

/// The `(count, soft-delete)` statement pair of a composite run; both halves
/// from one macro family, as for [`max_age_sql`].
pub(crate) fn composite_sql(min_keep: bool) -> (&'static str, &'static str) {
    if min_keep {
        (COMPOSITE_MIN_KEEP_SELECT_SQL, COMPOSITE_MIN_KEEP_UPDATE_SQL)
    } else {
        (COMPOSITE_SELECT_SQL, COMPOSITE_UPDATE_SQL)
    }
}

impl LifecycleService {
    pub(super) async fn execute_composite(
        conn: &mut sqlx::PgConnection,
        policy: &LifecyclePolicy,
        dry_run: bool,
    ) -> Result<PolicyExecutionResult> {
        let conditions = parse_conditions(&policy.config)?;
        let filters = parse_policy_filters(&policy.config)?;
        let min_keep = parse_min_keep(&policy.config)?;
        let repository_id = policy.repository_id.ok_or_else(|| {
            AppError::Validation("composite requires a repository_id".to_string())
        })?;
        let binds = RetentionBinds {
            repository_id: Some(repository_id),
            windows: &conditions.windows(),
            filters: &filters,
            min_keep,
        };
        Self::count_then_soft_delete(
            conn,
            policy,
            dry_run,
            composite_sql(min_keep.is_some()),
            &binds,
        )
        .await
    }
}

#[cfg(ak_test_shard = "services-1")]
#[cfg(test)]
mod tests;
