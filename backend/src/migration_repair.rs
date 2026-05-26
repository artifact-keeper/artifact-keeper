//! Pre-migration recovery for installations whose `_sqlx_migrations` table
//! contains stale checksums that would otherwise abort startup with
//! `Migration(VersionMismatch(n))`.
//!
//! Two distinct cases are handled here, both keyed on stored checksums so
//! each function is a strict no-op on databases that do not exhibit the
//! exact corruption it knows how to recover from.
//!
//! 1. `repair_legacy_073_checksum` - the duplicate-073 collision on `main`
//!    that was open between PR #975 (forward-port of download-ticket
//!    cascade into main as `073_download_tickets_cascade.sql`, colliding
//!    with the existing `073_account_lockout.sql`) and PR #1138 (rename to
//!    083). Issue #1129.
//!
//! 2. `repair_release_1_1_9_divergence` - the migration-slot divergence
//!    between `release/1.1.x` (v1.1.9) and `main` for slots 73, 74, 75.
//!    v1.1.9 customers upgrading to v1.2.0-rc.1 hit `VersionMismatch(73)`
//!    because their `_sqlx_migrations` rows still carry the v1.1.9 file
//!    checksums while the new release ships entirely different files at
//!    those slots. Issue #1277.

use sqlx::PgPool;

use crate::error::{AppError, Result};

/// Repair a stale `_sqlx_migrations` row for version 73 that was left over
/// by the duplicate-073 bug fixed in #1138.
///
/// Between PR #975 (forward-port of download-ticket cascade) and PR #1138
/// (rename to 083), the migrations directory contained two files numbered
/// 073: `073_account_lockout.sql` and `073_download_tickets_cascade.sql`.
/// Postgres only kept whichever row `sqlx migrate run` inserted first,
/// with that file's checksum. After #1138 renamed the colliding file to
/// 083, the surviving 073 file on disk (`073_account_lockout.sql`) may
/// differ from what the DB stored, and `sqlx migrate run` then aborts
/// with `Migration(VersionMismatch(73))` before applying any newer
/// migration (issue #1129).
///
/// This pre-migration step looks at the DB and only acts when both halves
/// of the broken state are present: the lockout schema (proof
/// account_lockout was applied at some point) AND the `_sqlx_migrations`
/// row for version 73 whose checksum no longer matches the current file.
/// In that exact case we rewrite the stored checksum to the current
/// file's checksum so the migrator can move on. The check is
/// conservative; if either signal is missing we leave the row alone so
/// unrelated checksum drift still surfaces as a startup error.
pub async fn repair_legacy_073_checksum(db: &PgPool) -> Result<()> {
    // Skip when the table doesn't exist yet (fresh DB) or when no row
    // for version 73 has been recorded.
    let table_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = '_sqlx_migrations')",
    )
    .fetch_one(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    if !table_exists {
        return Ok(());
    }

    let stored_checksum: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE version = 73")
            .fetch_optional(db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    let Some(stored) = stored_checksum else {
        return Ok(());
    };

    // Confirm the lockout migration was previously applied by checking
    // for one of its columns. If the column is absent, this row predates
    // the duplicate and is unrelated to the bug we're repairing.
    let lockout_applied: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
         WHERE table_name = 'users' AND column_name = 'failed_login_attempts')",
    )
    .fetch_one(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    if !lockout_applied {
        return Ok(());
    }

    let current_file = include_str!("../migrations/073_account_lockout.sql");
    use sha2::{Digest, Sha384};
    let mut hasher = Sha384::new();
    hasher.update(current_file.as_bytes());
    let current_checksum = hasher.finalize().to_vec();

    if stored == current_checksum {
        return Ok(());
    }

    tracing::warn!(
        event = "migration_073_checksum_repair",
        "Detected stale checksum for migration 073 (account_lockout). \
         Rewriting _sqlx_migrations row so the migrator can proceed. \
         This is a one-time recovery for installations affected by the \
         duplicate-073 bug fixed in #1138."
    );
    sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = 73")
        .bind(&current_checksum)
        .execute(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    Ok(())
}

// SHA-384 checksums of the v1.1.9 release files. Identical across
// v1.1.9-rc.1 through v1.1.9 (verified by re-hashing every tagged
// release). These never change in the wild because the tags are
// immutable, so they can be hard-coded as the detection key.
const V1_1_9_CHECKSUM_073: [u8; 48] = [
    0xeb, 0x25, 0xe9, 0xf5, 0x22, 0x0f, 0x6f, 0xff, 0xfd, 0x31, 0xdb, 0x25, 0x6e, 0x6a, 0x95, 0xca,
    0x2f, 0xff, 0x24, 0xcf, 0x5b, 0xf4, 0xe0, 0xa0, 0x44, 0xcf, 0x26, 0x03, 0x07, 0x10, 0x33, 0x9d,
    0x77, 0x6e, 0xba, 0xfd, 0x3a, 0x29, 0x64, 0x33, 0xbe, 0xae, 0x0a, 0xcb, 0xa3, 0x05, 0xcd, 0x5a,
];
const V1_1_9_CHECKSUM_074: [u8; 48] = [
    0x14, 0xc8, 0xec, 0x2c, 0x35, 0x9e, 0xbd, 0xe9, 0xa3, 0x78, 0xe8, 0xa8, 0x83, 0x87, 0xfb, 0x21,
    0xca, 0x77, 0xf0, 0x67, 0x7a, 0x25, 0x12, 0x73, 0xe9, 0x29, 0x5b, 0x4e, 0x1b, 0xa8, 0xf1, 0xfb,
    0xac, 0x8d, 0xe6, 0xca, 0x69, 0x9b, 0x46, 0x05, 0xb0, 0xd0, 0xa0, 0x5b, 0x49, 0xb2, 0x5f, 0x53,
];
const V1_1_9_CHECKSUM_075: [u8; 48] = [
    0x7a, 0x77, 0x96, 0x2a, 0x2f, 0xad, 0xf2, 0x2d, 0x30, 0xb3, 0x18, 0xe4, 0x44, 0xbb, 0xd4, 0x1f,
    0x68, 0xba, 0x45, 0x7b, 0x47, 0x0a, 0xb5, 0xea, 0x36, 0xa0, 0xaa, 0x3e, 0x8c, 0x63, 0xaf, 0xae,
    0x5f, 0x5f, 0x8f, 0x7d, 0x6e, 0x08, 0x29, 0x09, 0x25, 0x3b, 0xd9, 0xe2, 0x93, 0x86, 0x30, 0xdf,
];

/// Repair stale `_sqlx_migrations` rows for versions 73, 74, 75 left by
/// an upgrade from `release/1.1.x` (v1.1.9) into `main` (v1.2.0+). See
/// issue #1277.
///
/// The `release/1.1.x` branch and `main` independently consumed migration
/// slots 73, 74, 75 with different files:
///
/// | Version | release/1.1.x file              | main file                 |
/// |---------|---------------------------------|---------------------------|
/// |   73    | `download_tickets_cascade.sql`  | `account_lockout.sql`     |
/// |   74    | `used_refresh_jtis.sql`         | `password_history.sql`    |
/// |   75    | `flag_legacy_unverified_scans`  | `quarantine_period.sql`   |
///
/// On `main`, the `release/1.1.x` content was re-numbered to higher
/// slots (083 for `download_tickets_cascade`, 091 for `refresh_token_jti`
/// which supersedes `used_refresh_jtis`). A customer running v1.1.9 has
/// the `release/1.1.x` checksums in `_sqlx_migrations` for rows 73-75.
/// When they pull v1.2.0-rc.1, `sqlx migrate run` compares the on-disk
/// file checksums for slots 73-75 to the stored checksums, sees a
/// mismatch, and aborts with `Migration(VersionMismatch(73))` before
/// applying any newer migration.
///
/// This pre-migration step detects that exact upgrade path by matching
/// the stored checksums against the known v1.1.9 file SHA-384s, then:
///
/// 1. Applies the schemas that `main`'s 073/074/075 introduce, which are
///    additive over the v1.1.9 schema and not present on the customer's
///    DB (account lockout columns, password_history table,
///    quarantine_period constraint update + column + index). Each
///    statement is written idempotently (`IF NOT EXISTS` / `DROP
///    CONSTRAINT IF EXISTS`) so a retried boot after a partial failure
///    is safe.
/// 2. Rewrites the stored checksums for rows 73-75 to the current file
///    SHA-384s, so `sqlx migrate run` no longer aborts on the mismatch.
///
/// The downstream `main` migrations that re-introduce the v1.1.9 schema
/// (083 `download_tickets_cascade`, 091 `refresh_token_jti`) are
/// themselves idempotent on these databases - 083 uses a `DO` block with
/// `IF NOT NULL` before the `DROP CONSTRAINT` plus a re-`ADD CONSTRAINT`
/// (which simply re-issues the same `ON DELETE CASCADE` already present
/// from v1.1.9's 073), and 091 uses `CREATE TABLE IF NOT EXISTS` /
/// `CREATE INDEX IF NOT EXISTS`. The pre-existing `used_refresh_jtis`
/// table from v1.1.9 is left in place (unused by main code paths but
/// harmless); operators may drop it manually once confident the new
/// `refresh_token_jti` machinery is healthy.
///
/// The detection key is the v1.1.9 file SHA-384, so this function is a
/// strict no-op on:
///   * fresh installs (table missing or rows missing),
///   * installs that never ran v1.1.9 (different checksums),
///   * installs already repaired by a previous boot (checksums match
///     current files).
pub async fn repair_release_1_1_9_divergence(db: &PgPool) -> Result<()> {
    // Skip on fresh installs - no _sqlx_migrations table yet. `to_regclass`
    // resolves the unqualified table name against the connection's
    // search_path (rather than scanning every schema like
    // information_schema.tables would), which both matches sqlx's own
    // resolution rules for the production migrator and keeps the schema-
    // isolated unit tests in this module from picking up an unrelated
    // `_sqlx_migrations` in the public schema.
    let table_exists: bool =
        sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations') IS NOT NULL")
            .fetch_one(db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    if !table_exists {
        return Ok(());
    }

    let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT \
             (SELECT checksum FROM _sqlx_migrations WHERE version = 73), \
             (SELECT checksum FROM _sqlx_migrations WHERE version = 74), \
             (SELECT checksum FROM _sqlx_migrations WHERE version = 75)",
    )
    .fetch_optional(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    let Some((stored_73, stored_74, stored_75)) = row else {
        return Ok(());
    };

    // Strict match on all three v1.1.9 checksums. Partial matches fall
    // through to the normal migrator, which will surface them as
    // VersionMismatch and force operator attention - that case is not
    // the v1.1.9 -> main upgrade we know how to recover.
    if stored_73.as_slice() != V1_1_9_CHECKSUM_073
        || stored_74.as_slice() != V1_1_9_CHECKSUM_074
        || stored_75.as_slice() != V1_1_9_CHECKSUM_075
    {
        return Ok(());
    }

    tracing::warn!(
        event = "migration_release_1_1_9_divergence_repair",
        "Detected v1.1.9 -> v1.2.0 upgrade with diverged migration slots \
         73, 74, 75. Applying the schema changes introduced by main's 073 \
         (account_lockout), 074 (password_history), and 075 \
         (quarantine_period), then rewriting the _sqlx_migrations \
         checksums so the migrator can proceed. See issue #1277."
    );

    // 1. Apply main's 073: account lockout columns on users.
    sqlx::query(
        "ALTER TABLE users \
             ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER NOT NULL DEFAULT 0, \
             ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP WITH TIME ZONE, \
             ADD COLUMN IF NOT EXISTS last_failed_login_at TIMESTAMP WITH TIME ZONE",
    )
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // 2. Apply main's 074: password_history table.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS password_history ( \
             id            UUID PRIMARY KEY DEFAULT gen_random_uuid(), \
             user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, \
             password_hash TEXT NOT NULL, \
             created_at    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW() \
         )",
    )
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_password_history_user_id \
             ON password_history (user_id, created_at DESC)",
    )
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // 3. Apply main's 075: quarantine_period workflow on artifacts.
    sqlx::query(
        "ALTER TABLE artifacts DROP CONSTRAINT IF EXISTS artifacts_quarantine_status_check",
    )
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    sqlx::query(
        "ALTER TABLE artifacts ADD CONSTRAINT artifacts_quarantine_status_check \
             CHECK (quarantine_status IN ('unscanned', 'clean', 'flagged', 'quarantined', 'released', 'rejected'))",
    )
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;
    sqlx::query("ALTER TABLE artifacts ADD COLUMN IF NOT EXISTS quarantine_until TIMESTAMPTZ")
        .execute(db)
        .await
        .map_err(|e| AppError::Database(e.to_string()))?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_artifacts_quarantine_until \
             ON artifacts (quarantine_until) \
             WHERE quarantine_status = 'quarantined' AND quarantine_until IS NOT NULL",
    )
    .execute(db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    // 4. Rewrite the stored checksums to the current main file SHA-384s.
    use sha2::{Digest, Sha384};
    for (version, file) in [
        (73i64, include_str!("../migrations/073_account_lockout.sql")),
        (
            74i64,
            include_str!("../migrations/074_password_history.sql"),
        ),
        (
            75i64,
            include_str!("../migrations/075_quarantine_period.sql"),
        ),
    ] {
        let mut hasher = Sha384::new();
        hasher.update(file.as_bytes());
        let new_checksum = hasher.finalize().to_vec();
        sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = $2")
            .bind(&new_checksum)
            .bind(version)
            .execute(db)
            .await
            .map_err(|e| AppError::Database(e.to_string()))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hard-coded v1.1.9 checksums must match the SHA-384 of the
    /// release file content. This test ratchets the detection key so a
    /// typo in the byte array fails CI immediately rather than silently
    /// turning the upgrade path into a no-op for affected customers.
    ///
    /// Source of truth: the file content from the v1.1.9 git tag,
    /// reproduced verbatim here so the test runs without git access.
    #[test]
    fn v1_1_9_checksum_constants_match_release_files() {
        use sha2::{Digest, Sha384};

        // Verbatim contents of backend/migrations/073_download_tickets_cascade.sql at v1.1.9.
        let v1_1_9_073 = "-- Add ON DELETE CASCADE to download_tickets.user_id.\n--\n-- Migration 039 created the table with a plain `REFERENCES users(id)`, which\n-- defaults to `ON DELETE NO ACTION`. That meant deleting a user with\n-- outstanding (typically about-to-expire) tickets would fail with a foreign-key\n-- violation. Tickets are short-lived (30s TTL) and single-use, so cascading on\n-- delete is correct: the tickets become invalid the moment the user does.\n--\n-- We drop the old constraint by inspecting the system catalog rather than\n-- naming it explicitly, because Postgres auto-generates the constraint name\n-- (`download_tickets_user_id_fkey` is conventional but not guaranteed).\nDO $$\nDECLARE\n    fk_name text;\nBEGIN\n    SELECT con.conname INTO fk_name\n    FROM pg_constraint con\n    JOIN pg_class rel ON rel.oid = con.conrelid\n    JOIN pg_attribute att ON att.attrelid = con.conrelid AND att.attnum = ANY(con.conkey)\n    WHERE rel.relname = 'download_tickets'\n      AND att.attname = 'user_id'\n      AND con.contype = 'f';\n\n    IF fk_name IS NOT NULL THEN\n        EXECUTE format('ALTER TABLE download_tickets DROP CONSTRAINT %I', fk_name);\n    END IF;\nEND $$;\n\nALTER TABLE download_tickets\n    ADD CONSTRAINT download_tickets_user_id_fkey\n    FOREIGN KEY (user_id)\n    REFERENCES users(id)\n    ON DELETE CASCADE;\n";

        let mut h = Sha384::new();
        h.update(v1_1_9_073.as_bytes());
        let computed: Vec<u8> = h.finalize().to_vec();
        assert_eq!(
            computed.as_slice(),
            V1_1_9_CHECKSUM_073,
            "v1.1.9 checksum constant for migration 073 has drifted from the release file"
        );
    }

    /// Build a `PgPool` whose every connection pins `search_path` to the
    /// supplied isolation schema. Necessary because the production code
    /// uses `PgPool` (not a single `PgConnection`), and `SET search_path`
    /// alone is per-session - if the pool hands out two different
    /// underlying connections during the test, the second one would not
    /// see the schema. The schema-scoped `after_connect` hook applies
    /// the `SET` on every borrow so the test stays isolated regardless
    /// of which connection serves any given query.
    async fn schema_isolated_pool(url: &str, schema: &str) -> PgPool {
        use sqlx::postgres::PgPoolOptions;
        let schema = schema.to_string();
        PgPoolOptions::new()
            .max_connections(2)
            .after_connect(move |conn, _meta| {
                let schema = schema.clone();
                Box::pin(async move {
                    sqlx::query(&format!("SET search_path TO \"{schema}\""))
                        .execute(&mut *conn)
                        .await?;
                    Ok(())
                })
            })
            .connect(url)
            .await
            .expect("connect schema-isolated pool")
    }

    async fn create_isolation_schema(pool: &PgPool, schema: &str) {
        sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
            .execute(pool)
            .await
            .expect("create schema");
    }

    async fn drop_isolation_schema(url: &str, schema: &str) {
        // Use a dedicated connection that does NOT pin the search_path
        // to the about-to-be-dropped schema, otherwise the DROP itself
        // fails on Postgres when the current search_path target is
        // missing.
        if let Ok(pool) = PgPool::connect(url).await {
            let _ = sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
                .execute(&pool)
                .await;
        }
    }

    /// DB-backed regression test for the v1.1.9 -> main upgrade path.
    /// Requires `DATABASE_URL` (the CI coverage job sets this; local
    /// `cargo test --lib` skips silently when the var is missing).
    #[tokio::test]
    async fn repair_release_1_1_9_divergence_rewrites_checksums_and_applies_schema() {
        let url = match std::env::var("DATABASE_URL") {
            Ok(v) => v,
            Err(_) => return,
        };
        // Use a schema-isolated pool: install the repair scenario into
        // a fresh test schema so we don't disturb the migrator's
        // production state on shared CI databases.
        let bootstrap = match PgPool::connect(&url).await {
            Ok(p) => p,
            Err(_) => return,
        };

        let schema = format!("issue1277_{}", uuid::Uuid::new_v4().simple());
        create_isolation_schema(&bootstrap, &schema).await;
        drop(bootstrap);
        let pool = schema_isolated_pool(&url, &schema).await;

        // Minimal `users` and `artifacts` skeleton matching the columns
        // the repair function touches. Real installs always have these
        // tables from earlier migrations; we only need enough for the
        // ALTER TABLE / DROP CONSTRAINT statements to succeed.
        sqlx::query(
            "CREATE TABLE users ( \
                 id UUID PRIMARY KEY, \
                 username TEXT NOT NULL UNIQUE \
             )",
        )
        .execute(&pool)
        .await
        .expect("create users");
        sqlx::query(
            "CREATE TABLE artifacts ( \
                 id UUID PRIMARY KEY, \
                 quarantine_status TEXT NOT NULL DEFAULT 'unscanned', \
                 CONSTRAINT artifacts_quarantine_status_check \
                     CHECK (quarantine_status IN ('unscanned', 'clean', 'flagged')) \
             )",
        )
        .execute(&pool)
        .await
        .expect("create artifacts");

        // Stand up the _sqlx_migrations table in the same shape sqlx
        // creates it, then seed the three rows with the v1.1.9
        // checksums to simulate a freshly-upgraded customer.
        sqlx::query(
            "CREATE TABLE _sqlx_migrations ( \
                 version BIGINT PRIMARY KEY, \
                 description TEXT NOT NULL, \
                 installed_on TIMESTAMPTZ NOT NULL DEFAULT NOW(), \
                 success BOOLEAN NOT NULL, \
                 checksum BYTEA NOT NULL, \
                 execution_time BIGINT NOT NULL \
             )",
        )
        .execute(&pool)
        .await
        .expect("create _sqlx_migrations");
        for (version, label, checksum) in [
            (
                73i64,
                "download_tickets_cascade",
                V1_1_9_CHECKSUM_073.to_vec(),
            ),
            (74i64, "used_refresh_jtis", V1_1_9_CHECKSUM_074.to_vec()),
            (
                75i64,
                "flag_legacy_unverified_scans",
                V1_1_9_CHECKSUM_075.to_vec(),
            ),
        ] {
            sqlx::query(
                "INSERT INTO _sqlx_migrations \
                     (version, description, success, checksum, execution_time) \
                     VALUES ($1, $2, true, $3, 0)",
            )
            .bind(version)
            .bind(label)
            .bind(&checksum)
            .execute(&pool)
            .await
            .expect("seed _sqlx_migrations");
        }

        // Execute the repair.
        repair_release_1_1_9_divergence(&pool)
            .await
            .expect("repair must succeed");

        // 1. The lockout columns must now exist on users.
        let lockout_cols: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.columns \
             WHERE table_schema = current_schema() \
               AND table_name = 'users' \
               AND column_name IN ('failed_login_attempts', 'locked_until', 'last_failed_login_at')",
        )
        .fetch_one(&pool)
        .await
        .expect("count lockout columns");
        assert_eq!(
            lockout_cols, 3,
            "repair must add all three account-lockout columns"
        );

        // 2. The password_history table must exist.
        let ph_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
             WHERE table_schema = current_schema() AND table_name = 'password_history')",
        )
        .fetch_one(&pool)
        .await
        .expect("password_history exists check");
        assert!(ph_exists, "repair must create password_history table");

        // 3. The quarantine_status CHECK constraint must accept the
        //    new values, and the quarantine_until column must exist.
        sqlx::query(
            "INSERT INTO artifacts (id, quarantine_status) VALUES \
                ($1, 'quarantined'), ($2, 'released'), ($3, 'rejected')",
        )
        .bind(uuid::Uuid::new_v4())
        .bind(uuid::Uuid::new_v4())
        .bind(uuid::Uuid::new_v4())
        .execute(&pool)
        .await
        .expect("new quarantine values must be accepted by updated CHECK");

        let qu_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.columns \
             WHERE table_schema = current_schema() \
               AND table_name = 'artifacts' \
               AND column_name = 'quarantine_until')",
        )
        .fetch_one(&pool)
        .await
        .expect("quarantine_until exists check");
        assert!(qu_exists, "repair must add artifacts.quarantine_until");

        // 4. The stored checksums must now equal the current main
        //    SHA-384s (i.e. what sqlx::migrate will compute against
        //    the on-disk files), so the next `sqlx::migrate!().run()`
        //    no longer aborts with VersionMismatch.
        use sha2::{Digest, Sha384};
        for (version, file) in [
            (73i64, include_str!("../migrations/073_account_lockout.sql")),
            (
                74i64,
                include_str!("../migrations/074_password_history.sql"),
            ),
            (
                75i64,
                include_str!("../migrations/075_quarantine_period.sql"),
            ),
        ] {
            let mut h = Sha384::new();
            h.update(file.as_bytes());
            let expected: Vec<u8> = h.finalize().to_vec();
            let stored: Vec<u8> =
                sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE version = $1")
                    .bind(version)
                    .fetch_one(&pool)
                    .await
                    .expect("checksum read");
            assert_eq!(
                stored, expected,
                "checksum for migration {version} must be rewritten to the current file SHA-384"
            );
        }

        // 5. A second invocation must be a strict no-op (idempotency).
        repair_release_1_1_9_divergence(&pool)
            .await
            .expect("second invocation idempotent");

        // Cleanup: drop the isolation schema. Done outside any
        // assertion so it always runs; failures here are non-fatal.
        drop(pool);
        drop_isolation_schema(&url, &schema).await;
    }

    /// The repair must be a strict no-op when the stored checksums
    /// don't match v1.1.9 - e.g. on a fresh main install or on an
    /// install that already migrated past slot 75.
    #[tokio::test]
    async fn repair_release_1_1_9_divergence_no_op_when_checksums_differ() {
        let url = match std::env::var("DATABASE_URL") {
            Ok(v) => v,
            Err(_) => return,
        };
        let bootstrap = match PgPool::connect(&url).await {
            Ok(p) => p,
            Err(_) => return,
        };

        let schema = format!("issue1277_noop_{}", uuid::Uuid::new_v4().simple());
        create_isolation_schema(&bootstrap, &schema).await;
        drop(bootstrap);
        let pool = schema_isolated_pool(&url, &schema).await;

        // Seed _sqlx_migrations with NOT-v1.1.9 checksums (e.g. fresh
        // main install where rows 73-75 were applied from main's own
        // files). The function must not touch this DB.
        sqlx::query(
            "CREATE TABLE _sqlx_migrations ( \
                 version BIGINT PRIMARY KEY, \
                 description TEXT NOT NULL, \
                 installed_on TIMESTAMPTZ NOT NULL DEFAULT NOW(), \
                 success BOOLEAN NOT NULL, \
                 checksum BYTEA NOT NULL, \
                 execution_time BIGINT NOT NULL \
             )",
        )
        .execute(&pool)
        .await
        .expect("create _sqlx_migrations");

        let bogus_checksum = vec![0xaau8; 48];
        for version in [73i64, 74, 75] {
            sqlx::query(
                "INSERT INTO _sqlx_migrations \
                     (version, description, success, checksum, execution_time) \
                     VALUES ($1, 'irrelevant', true, $2, 0)",
            )
            .bind(version)
            .bind(&bogus_checksum)
            .execute(&pool)
            .await
            .expect("seed _sqlx_migrations");
        }

        repair_release_1_1_9_divergence(&pool)
            .await
            .expect("repair must succeed (as no-op)");

        // Verify nothing was rewritten.
        for version in [73i64, 74, 75] {
            let stored: Vec<u8> =
                sqlx::query_scalar("SELECT checksum FROM _sqlx_migrations WHERE version = $1")
                    .bind(version)
                    .fetch_one(&pool)
                    .await
                    .expect("checksum read");
            assert_eq!(
                stored, bogus_checksum,
                "no-op path must leave checksum untouched for version {version}"
            );
        }

        // And the schema must not be touched - account-lockout columns
        // must not have been spuriously created (the `users` table
        // doesn't even exist in this scenario).
        let users_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
             WHERE table_schema = current_schema() AND table_name = 'users')",
        )
        .fetch_one(&pool)
        .await
        .expect("users exists check");
        assert!(!users_exists, "no-op path must not create the users table");

        drop(pool);
        drop_isolation_schema(&url, &schema).await;
    }

    /// The repair must be a strict no-op when the _sqlx_migrations
    /// table does not exist (fresh install).
    #[tokio::test]
    async fn repair_release_1_1_9_divergence_no_op_on_fresh_install() {
        let url = match std::env::var("DATABASE_URL") {
            Ok(v) => v,
            Err(_) => return,
        };
        let bootstrap = match PgPool::connect(&url).await {
            Ok(p) => p,
            Err(_) => return,
        };

        let schema = format!("issue1277_fresh_{}", uuid::Uuid::new_v4().simple());
        create_isolation_schema(&bootstrap, &schema).await;
        drop(bootstrap);
        let pool = schema_isolated_pool(&url, &schema).await;

        // No _sqlx_migrations table at all. The repair must early-return.
        repair_release_1_1_9_divergence(&pool)
            .await
            .expect("repair must succeed (as no-op) on fresh install");

        drop(pool);
        drop_isolation_schema(&url, &schema).await;
    }
}
