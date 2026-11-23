//! Starting on a schema newer than the binary, for rolling deploys (#5920).
//!
//! During a rolling update the new pods apply their migrations as they start,
//! so for the length of the rollout the old release serves on the new
//! schema. If an old pod restarts in that window (OOM, node drain, crash),
//! sqlx finds versions in `_sqlx_migrations` that the old binary does not
//! embed and fails with `VersionMissing`, so the pod crash-loops until the
//! rollout finishes, and never comes back if the rollout is paused or rolled
//! back.
//!
//! `MIGRATIONS_IGNORE_MISSING=true` lets such a pod start: it applies its own
//! pending migrations as usual and ignores the newer ones, **unless** one of
//! them contracts schema this binary may still use. Every schema change ships
//! as expand (release N: the new object, and code that stops using the old
//! one) then contract (release N+1 or later). The expand/contract check in
//! [`crate::migration_safety`] makes every contracting migration from 418 on
//! name itself `NNN_contract_of_MMM_<what>.sql`, MMM being its expand, and
//! sqlx records the file name as the description (`contract of MMM <what>`).
//! So a binary that does not know a newer migration can still read from the
//! ledger whether it is a contract, and of which expand:
//!
//! * a newer contract whose expand MMM this binary embeds is safe: the binary
//!   is the expand release or later, so it no longer uses what the contract
//!   removes;
//! * a newer contract of an expand this binary does not embed (or one whose
//!   expand cannot be read) means the schema lost something it may use, and
//!   the binary refuses to start. Rolling back across a contract still fails.
//!
//! The ledger is classified inside the migration advisory lock
//! ([`crate::migration_repair::run_startup_migrations`]), so a newer pod
//! cannot apply a contract between the check and the run.
//!
//! Unset (the default), startup is unchanged: an unknown applied version
//! fails with `VersionMissing`, now preceded by an error naming the setting.

use sqlx::migrate::Migrator;
use sqlx::PgConnection;

use crate::error::{AppError, Result};

/// The opt-in setting.
pub const IGNORE_MISSING_ENV: &str = "MIGRATIONS_IGNORE_MISSING";

/// `MIGRATIONS_IGNORE_MISSING` as a boolean: `true`, `1`, `yes` or `on`.
pub fn ignore_missing_from_env() -> bool {
    parse_flag(std::env::var(IGNORE_MISSING_ENV).ok().as_deref())
}

fn parse_flag(value: Option<&str>) -> bool {
    value.is_some_and(|v| {
        matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "true" | "1" | "yes" | "on"
        )
    })
}

/// What a recorded description says about a migration: `None` when it is not
/// a contract, `Some(Some(MMM))` for a contract of expand MMM, `Some(None)`
/// for a contract whose expand cannot be read.
pub(crate) fn contract_of(description: &str) -> Option<Option<i64>> {
    let d = description.trim().to_ascii_lowercase();
    let mut words = d.split_whitespace();
    if words.next() != Some("contract") {
        return None;
    }
    Some(match (words.next(), words.next()) {
        (Some("of"), Some(v)) => v.parse().ok(),
        _ => None,
    })
}

/// What starting on the database's ledger means for this binary.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Every applied version is one this binary embeds.
    Known,
    /// Newer versions are applied, and none contracts anything this binary
    /// uses: expands, or contracts of an expand it embeds.
    NewerCompatible(Vec<i64>),
    /// These newer contracts are of an expand this binary does not embed:
    /// never start on them.
    NewerContract(Vec<i64>),
}

/// Classify the applied `(version, description)` rows this binary does not
/// embed (`unknown`), given the versions it does (`known`). Pure.
pub(crate) fn verdict(unknown: &[(i64, String)], known: &[i64]) -> Verdict {
    if unknown.is_empty() {
        return Verdict::Known;
    }
    let blocking: Vec<i64> = unknown
        .iter()
        .filter(|(_, d)| match contract_of(d) {
            None => false,
            Some(Some(expand)) => !known.contains(&expand),
            Some(None) => true,
        })
        .map(|(v, _)| *v)
        .collect();
    if blocking.is_empty() {
        Verdict::NewerCompatible(unknown.iter().map(|(v, _)| *v).collect())
    } else {
        Verdict::NewerContract(blocking)
    }
}

/// Applied migrations `migrator` does not embed, as `(version, description)`.
/// Empty on a database that has no ledger yet.
async fn unknown_applied(
    conn: &mut PgConnection,
    migrator: &Migrator,
) -> Result<Vec<(i64, String)>> {
    let has_ledger: bool =
        sqlx::query_scalar("SELECT to_regclass('public._sqlx_migrations') IS NOT NULL")
            .fetch_one(&mut *conn)
            .await?;
    if !has_ledger {
        return Ok(Vec::new());
    }
    let applied: Vec<(i64, String)> = sqlx::query_as(
        "SELECT version, description FROM _sqlx_migrations WHERE success ORDER BY version",
    )
    .fetch_all(&mut *conn)
    .await?;
    let known: std::collections::HashSet<i64> =
        migrator.migrations.iter().map(|m| m.version).collect();
    Ok(applied
        .into_iter()
        .filter(|(v, _)| !known.contains(v))
        .collect())
}

/// Whether startup runs `migrator` with `ignore_missing`, decided under the
/// migration lock on `conn`: [`MIGRATIONS_IGNORE_MISSING`](IGNORE_MISSING_ENV)
/// on and no newer contract this binary may trip on. Fails when the setting is
/// on and one is applied.
pub async fn ignore_missing_for(conn: &mut PgConnection, migrator: &Migrator) -> Result<bool> {
    decide(conn, migrator, ignore_missing_from_env()).await
}

async fn decide(conn: &mut PgConnection, migrator: &Migrator, enabled: bool) -> Result<bool> {
    let unknown = unknown_applied(conn, migrator).await?;
    let known: Vec<i64> = migrator.migrations.iter().map(|m| m.version).collect();
    match (verdict(&unknown, &known), enabled) {
        (Verdict::Known, _) => Ok(enabled),
        (Verdict::NewerCompatible(versions) | Verdict::NewerContract(versions), false) => {
            tracing::error!(
                ?versions,
                "the database has migrations applied that this binary does not have (a newer \
                 release migrated it). Startup fails with VersionMissing. During a rolling \
                 deploy set {IGNORE_MISSING_ENV}=true to start on a newer compatible schema; \
                 to roll back, see docs/operations/rollback.md"
            );
            Ok(false)
        }
        (Verdict::NewerContract(versions), true) => Err(AppError::Config(format!(
            "refusing to start: the database has newer contract migration(s) {versions:?} \
             applied, which remove or tighten schema this release may use (their expand \
             migration is newer than this binary). {IGNORE_MISSING_ENV}=true only covers \
             newer expands and contracts of expands this release already has; run the \
             release that applied them, or see docs/operations/rollback.md"
        ))),
        (Verdict::NewerCompatible(versions), true) => {
            tracing::warn!(
                ?versions,
                "starting on a schema newer than this binary: {IGNORE_MISSING_ENV}=true and \
                 the newer migrations are expands or contracts of expands this binary has, so \
                 they are ignored"
            );
            Ok(true)
        }
    }
}

#[cfg(ak_test_shard = "services-2")]
#[cfg(test)]
mod tests {
    use super::*;

    fn row(v: i64, d: &str) -> (i64, String) {
        (v, d.to_string())
    }

    #[test]
    fn the_flag_parses_like_the_other_booleans() {
        for on in ["true", "TRUE", " 1 ", "yes", "on"] {
            assert!(parse_flag(Some(on)), "{on}");
        }
        for off in ["", "false", "0", "no", "off", "maybe"] {
            assert!(!parse_flag(Some(off)), "{off}");
        }
        assert!(!parse_flag(None));
    }

    #[test]
    fn contract_descriptions_name_their_expand() {
        assert_eq!(
            contract_of("contract of 431 drop legacy path"),
            Some(Some(431))
        );
        assert_eq!(contract_of("Contract of 12 x"), Some(Some(12)));
        assert_eq!(
            contract_of("contract drop x"),
            Some(None),
            "no expand: unknown"
        );
        assert_eq!(contract_of("contract of soon x"), Some(None));
        assert_eq!(contract_of("contractor table"), None);
        assert_eq!(contract_of("add contract column"), None);
        assert_eq!(contract_of("scheduler job cursors"), None);
    }

    #[test]
    fn verdict_allows_only_contracts_of_known_expands() {
        let known = [416, 417];
        assert_eq!(verdict(&[], &known), Verdict::Known);
        assert_eq!(
            verdict(
                &[row(418, "add widget column"), row(419, "widget index")],
                &known
            ),
            Verdict::NewerCompatible(vec![418, 419])
        );
        // The binary has expand 417: the contract of 417 is safe for it.
        assert_eq!(
            verdict(
                &[
                    row(418, "add widget column"),
                    row(420, "contract of 417 drop gadget")
                ],
                &known
            ),
            Verdict::NewerCompatible(vec![418, 420])
        );
        // An expand it does not have, or an unreadable one: refuse.
        assert_eq!(
            verdict(
                &[row(418, "add w"), row(420, "contract of 418 drop old w")],
                &known
            ),
            Verdict::NewerContract(vec![420])
        );
        assert_eq!(
            verdict(&[row(421, "contract drop gadget")], &known),
            Verdict::NewerContract(vec![421])
        );
    }

    /// The startup decision against a real ledger: refused, allowed or
    /// disabled exactly as [`verdict`] says, and plain sqlx still fails with
    /// `VersionMissing` on a newer ledger while the allowed one runs.
    #[tokio::test]
    async fn startup_decides_on_the_ledger_under_the_lock() {
        let Some(db) = crate::testing::try_isolated_pool().await else {
            eprintln!("SKIPPED: no DATABASE_URL (set AK_TESTS_REQUIRE_DB=1 to fail instead)");
            return;
        };
        let pool = db.pool.clone();
        let mut conn = pool.acquire().await.unwrap();
        let ours = crate::MIGRATOR
            .migrations
            .iter()
            .map(|m| m.version)
            .max()
            .unwrap();
        let newer = ours + 1000;
        let record = |v: i64, d: &'static str| {
            let pool = pool.clone();
            async move {
                sqlx::query(
                    "INSERT INTO _sqlx_migrations (version, description, success, checksum, \
                     execution_time) VALUES ($1, $2, true, '\\x00'::bytea, 1)",
                )
                .bind(v)
                .bind(d)
                .execute(&pool)
                .await
                .unwrap();
            }
        };
        assert!(!decide(&mut conn, &crate::MIGRATOR, false).await.unwrap());
        assert!(
            decide(&mut conn, &crate::MIGRATOR, true).await.unwrap(),
            "nothing newer"
        );

        record(newer, "add future column").await;
        assert!(
            !decide(&mut conn, &crate::MIGRATOR, false).await.unwrap(),
            "off: sqlx decides"
        );
        assert!(decide(&mut conn, &crate::MIGRATOR, true).await.unwrap());
        // What startup then runs, without sqlx's own lock (the caller holds
        // it): plain fails, ignore_missing accepts the newer ledger.
        let with = |ignore_missing: bool| Migrator {
            migrations: crate::MIGRATOR.migrations.clone(),
            ignore_missing,
            locking: false,
            no_tx: crate::MIGRATOR.no_tx,
            table_name: crate::MIGRATOR.table_name.clone(),
            create_schemas: crate::MIGRATOR.create_schemas.clone(),
        };
        let plain = with(false).run_direct(None, &mut *conn, false).await;
        assert!(
            matches!(plain, Err(sqlx::migrate::MigrateError::VersionMissing(v)) if v == newer),
            "{plain:?}"
        );
        with(true)
            .run_direct(None, &mut *conn, false)
            .await
            .expect("a newer compatible ledger is accepted");

        // A contract of an expand this binary has: still compatible.
        let covered: &'static str =
            Box::leak(format!("contract of {ours} drop old").into_boxed_str());
        record(newer + 1, covered).await;
        assert!(decide(&mut conn, &crate::MIGRATOR, true).await.unwrap());

        // A contract of the newer expand: refused, naming it.
        record(newer + 2, "contract of 999999 drop old column").await;
        let err = decide(&mut conn, &crate::MIGRATOR, true).await.unwrap_err();
        assert!(err.to_string().contains(&(newer + 2).to_string()), "{err}");
        assert!(
            !decide(&mut conn, &crate::MIGRATOR, false).await.unwrap(),
            "off: unchanged, sqlx refuses"
        );
    }
}
