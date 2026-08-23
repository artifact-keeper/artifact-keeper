//! Shared test scaffolding for DB-backed handler tests.
//!
//! Every helper here is a no-op stub when `DATABASE_URL` is unset (so the
//! tests skip cleanly in environments without Postgres). The CI coverage
//! job seeds Postgres + applies migrations before running `cargo llvm-cov
//! --lib`, so these helpers are exercised in CI and instrument the
//! handler-call paths refactored to use `proxy_helpers`.
//!
//! Tests in sibling modules call:
//!
//!     use crate::api::handlers::test_db_helpers as tdh;
//!     let Some(pool) = tdh::try_pool().await else { return; };

#![allow(dead_code)]
// streaming-invariant: test scaffolding exempt — buffering response bodies in
// DB-backed handler tests is not an artifact path (#1608).
#![allow(clippy::disallowed_methods)]

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::{Extension, Router};
use bytes::Bytes;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

use crate::api::middleware::auth::AuthExtension;
use crate::api::{AppState, SharedState};
use crate::config::Config;
use crate::models::user::User;

/// Connect to the test database.
///
/// Returns `None` only when no database is configured/reachable **and** the DB
/// is not required, so DB-free local runs no-op gracefully. When the CI
/// require-DB signal ([`crate::testing::REQUIRE_DB_ENV`]) is set, a missing
/// `DATABASE_URL` or a connect failure PANICS instead of skipping, so an
/// unreachable database can no longer silently "fiction-green" the suite
/// (#2924).
pub async fn try_pool() -> Option<PgPool> {
    crate::testing::try_pool_with(3).await
}

/// Serializes the narrowly-scoped SSRF allowlist mutation used by handler
/// tests that need a wiremock upstream. Production correctly blocks loopback,
/// so the mock listens on the host's non-loopback address and only that /32 or
/// /128 is allowlisted for the lifetime of the guard.
static SSRF_TEST_ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub struct SsrfTestAllowlistGuard {
    _lock: tokio::sync::MutexGuard<'static, ()>,
    previous: Option<String>,
}

impl Drop for SsrfTestAllowlistGuard {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => std::env::set_var("AK_SSRF_ALLOW_PRIVATE_CIDRS", value),
            None => std::env::remove_var("AK_SSRF_ALLOW_PRIVATE_CIDRS"),
        }
    }
}

/// Start wiremock on a non-loopback interface accepted by the upstream SSRF
/// policy, returning a guard that restores the process environment on drop.
pub async fn non_loopback_mock_server() -> (wiremock::MockServer, SsrfTestAllowlistGuard) {
    let lock = SSRF_TEST_ENV_LOCK.lock().await;
    let previous = std::env::var("AK_SSRF_ALLOW_PRIVATE_CIDRS").ok();
    let probe = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind route probe");
    probe.connect("8.8.8.8:80").expect("connect route probe");
    let bind_ip = probe.local_addr().expect("read route probe address").ip();
    std::env::set_var(
        "AK_SSRF_ALLOW_PRIVATE_CIDRS",
        format!("{bind_ip}/{}", if bind_ip.is_ipv4() { 32 } else { 128 }),
    );
    let listener = std::net::TcpListener::bind((bind_ip, 0)).expect("bind wiremock listener");
    let server = wiremock::MockServer::builder()
        .listener(listener)
        .start()
        .await;
    (
        server,
        SsrfTestAllowlistGuard {
            _lock: lock,
            previous,
        },
    )
}

/// Open a dedicated Postgres session and take `pg_advisory_lock(lock_key)`,
/// blocking until the lock is free. Returns `None` — which the `*_serial_lock`
/// guards below surface as an inert guard — when no database is configured or
/// the session cannot be established, mirroring [`try_pool`] so DB-free
/// environments no-op cleanly.
///
/// The connect itself is HARD-BOUNDED (#2986): unlike the pooled path in
/// [`crate::testing::try_pool_with`], whose `acquire_timeout` bounds
/// connection establishment, a raw `PgConnection::connect` has no client-side
/// timeout. A listener that accepts TCP but never completes the Postgres
/// handshake (e.g. a dead container's still-forwarded :5432) therefore parked
/// the guard — and every test queued behind the same module lock — forever.
/// The 30s bound matches the pooled path's pressure budget; an expired bound
/// routes through the same skip-or-fail decision as a connect error.
async fn serial_lock_session(lock_key: i64) -> Option<sqlx::PgConnection> {
    let url = crate::testing::require_db_url()?;
    let connect = crate::testing::bounded_connect(&url).await;
    let mut conn = crate::testing::on_connect_result(connect)?;
    if sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(lock_key)
        .execute(&mut conn)
        .await
        .is_err()
    {
        return None;
    }
    Some(conn)
}

/// Advisory-lock key for [`scan_dedup_serial_lock`] (#2000).
///
/// A single-key `pg_advisory_lock(bigint)` — a lock space distinct from the
/// two-key `pg_advisory_xact_lock(int4, int4)` used by
/// `ScanResultService::prepare_scan_placeholder` and from the scheduler locks
/// (9001-9099) documented in `scan_result_service`, so it cannot collide with
/// application locks.
const SCAN_DEDUP_TEST_LOCK_KEY: i64 = 0x5644_2000; // "SD" + issue #2000

/// Cross-process serialization guard for the DB-backed scan-dedup tests
/// (#2000). Holds a Postgres *session* advisory lock on a dedicated
/// connection; the lock is released when the guard is dropped (its connection
/// closes, ending the session), including on panic.
///
/// This exists because the `Code Coverage` CI job runs the suite under
/// `cargo nextest`, which executes **each test in its own process**. An
/// in-process `Mutex` (or the `serial_test` crate) therefore does NOT
/// serialize tests across nextest processes. A database advisory lock does:
/// every test process contends for the same key in the shared database, so
/// only one scan-dedup test mutates `scan_results` at a time. That removes the
/// cross-test interference that made
/// `scanner_service::tests::test_prepare_artifact_scan_without_bypass_reuses_existing`
/// intermittently fail under the coverage job's parallelism.
pub struct ScanDedupSerialGuard {
    _conn: Option<sqlx::PgConnection>,
}

/// Acquire the process-wide scan-dedup test lock, blocking until it is free.
///
/// Returns an inert guard (no lock held) when `DATABASE_URL` is unset or the
/// database is unreachable, mirroring [`try_pool`] so DB-free environments
/// still no-op cleanly. Call this as the first line of a scan-dedup DB test
/// and bind the result for the whole test body.
pub async fn scan_dedup_serial_lock() -> ScanDedupSerialGuard {
    ScanDedupSerialGuard {
        _conn: serial_lock_session(SCAN_DEDUP_TEST_LOCK_KEY).await,
    }
}

/// Advisory-lock key for [`blob_gc_serial_lock`] (#1660).
///
/// Distinct from [`SCAN_DEDUP_TEST_LOCK_KEY`] and from the application
/// advisory locks, so the blob-GC test cluster serializes only against
/// itself.
const BLOB_GC_TEST_LOCK_KEY: i64 = 0x424C_1660; // "BL" + issue #1660

/// Cross-process serialization guard for the DB-backed blob-GC tests (#1660).
///
/// The blob-GC service operates on the WHOLE database: `select_orphan_blobs`,
/// `select_pending_delete_blobs`, `prune_orphan_blob_refs` and the mark/sweep
/// loops are not scoped to a single repository. Under the coverage job's
/// process-per-test parallelism (`cargo nextest`), one test's apply-mode pass
/// would mark/sweep another test's freshly-seeded orphan blob, or prune a peer
/// test's still-referenced-but-untagged `manifest_blob_refs` row, before that
/// peer asserts on it. A Postgres *session* advisory lock — mirroring
/// [`scan_dedup_serial_lock`] — makes every blob-GC test contend for one key,
/// so only one runs its seed → GC → assert critical section at a time. The
/// lock releases when the guard drops (connection closes), including on panic.
pub struct BlobGcSerialGuard {
    _conn: Option<sqlx::PgConnection>,
}

/// Acquire the process-wide blob-GC test lock, blocking until it is free.
///
/// Returns an inert guard (no lock held) when `DATABASE_URL` is unset or the
/// database is unreachable, mirroring [`try_pool`] so DB-free environments
/// still no-op cleanly. Call this as the first line of a DB-backed blob-GC
/// test and bind the result for the whole test body.
pub async fn blob_gc_serial_lock() -> BlobGcSerialGuard {
    BlobGcSerialGuard {
        _conn: serial_lock_session(BLOB_GC_TEST_LOCK_KEY).await,
    }
}

/// Advisory-lock key for [`oci_reindex_serial_lock`] (#3402).
///
/// Distinct from the other test lock keys and from the application advisory
/// locks, so the OCI-reindex test cluster serializes only against itself.
const OCI_REINDEX_TEST_LOCK_KEY: i64 = 0x4F43_3402; // "OC" + issue #3402

/// Cross-process serialization guard for the DB-backed OCI migration-reindex
/// tests (#3402).
///
/// Exactly the [`blob_gc_serial_lock`] shape, for exactly the same reason:
/// `oci_migration_reindex::run_repair` scans and mutates `oci_tags` and
/// `artifacts` **instance-wide** — its queries join `repositories` rather than
/// binding a repository id, because in production it legitimately repairs the
/// whole instance. Every test in the module calls it. Run concurrently against
/// one shared database, sibling A's `run_repair` registers or reconciles the
/// rows sibling B seeded before B asserts on them, so B sees
/// `orphan_tags_reconciled: 0` for an orphan that was already cleaned up. The
/// observable tell is that `candidates_scanned` varies run to run (2, 3, …) for
/// a test that seeds a fixed number of candidates.
///
/// Serializing the module is the fix that does not change production
/// behaviour. Scoping `run_repair` to one repository would make the test pass
/// by narrowing a repair job whose whole purpose is to be instance-wide.
///
/// The lock releases when the guard drops (connection closes), including on
/// panic.
pub struct OciReindexSerialGuard {
    _conn: Option<sqlx::PgConnection>,
}

/// Acquire the process-wide OCI-reindex test lock, blocking until it is free.
///
/// Returns an inert guard (no lock held) when `DATABASE_URL` is unset or the
/// database is unreachable, mirroring [`try_pool`]. Call this as the first line
/// of a DB-backed `oci_migration_reindex` test and bind the result for the
/// whole test body.
pub async fn oci_reindex_serial_lock() -> OciReindexSerialGuard {
    OciReindexSerialGuard {
        _conn: serial_lock_session(OCI_REINDEX_TEST_LOCK_KEY).await,
    }
}

/// Advisory-lock key for [`totp_policy_serial_lock`] (#2805).
///
/// Distinct from the other test lock keys and from the application advisory
/// locks, so the 2FA-policy tests serialize only against themselves.
const TOTP_POLICY_TEST_LOCK_KEY: i64 = 0x5450_2805; // "TP" + issue #2805

/// Cross-process serialization guard for the DB-backed 2FA-policy tests
/// (#2805).
///
/// `security.totp_policy` is ONE row in `system_settings` shared by the whole
/// database, and the login/disable/admin paths all read it. Under the coverage
/// job's process-per-test parallelism (`cargo nextest`) one test's write would
/// be observed by another test's read. Mirrors [`scan_dedup_serial_lock`]:
/// every 2FA-policy test contends for one key, and the lock releases when the
/// guard drops (connection closes), including on panic.
pub struct TotpPolicySerialGuard {
    _conn: Option<sqlx::PgConnection>,
}

/// Acquire the process-wide 2FA-policy test lock, blocking until it is free.
///
/// Returns an inert guard (no lock held) when `DATABASE_URL` is unset or the
/// database is unreachable, mirroring [`try_pool`].
pub async fn totp_policy_serial_lock() -> TotpPolicySerialGuard {
    TotpPolicySerialGuard {
        _conn: serial_lock_session(TOTP_POLICY_TEST_LOCK_KEY).await,
    }
}

/// Advisory-lock key for [`usage_ledger_serial_lock`] (#2992).
///
/// Distinct from the other test lock keys and from the application advisory
/// locks, so the usage-ledger test cluster serializes only against itself.
const USAGE_LEDGER_TEST_LOCK_KEY: i64 = 0x554C_2992; // "UL" + issue #2992

/// Cross-process serialization guard for the DB-backed usage-ledger tests
/// (#2992).
///
/// `reconcile_all_usage_ledgers` operates on the WHOLE database: it reads
/// every repository's live sums and then upserts the ledger row, so a
/// concurrently mutating peer test can have its ledger row overwritten with a
/// snapshot taken before its mutation committed (read-then-write race). The
/// migration-183 trigger tests assert exact per-step ledger values, so that
/// stale overwrite makes them flaky under `cargo nextest`'s process-per-test
/// parallelism. A Postgres *session* advisory lock — mirroring
/// [`scan_dedup_serial_lock`] — makes the global-reconcile test and the
/// exact-value trigger tests contend for one key. The lock releases when the
/// guard drops (connection closes), including on panic.
pub struct UsageLedgerSerialGuard {
    _conn: Option<sqlx::PgConnection>,
}

/// Acquire the process-wide usage-ledger test lock, blocking until it is free.
///
/// Returns an inert guard (no lock held) when `DATABASE_URL` is unset or the
/// database is unreachable, mirroring [`try_pool`] so DB-free environments
/// still no-op cleanly. Call this as the first line of a DB-backed
/// usage-ledger test and bind the result for the whole test body.
pub async fn usage_ledger_serial_lock() -> UsageLedgerSerialGuard {
    UsageLedgerSerialGuard {
        _conn: serial_lock_session(USAGE_LEDGER_TEST_LOCK_KEY).await,
    }
}

/// Advisory-lock key for [`sso_provider_serial_lock`] (#2621).
///
/// Distinct from the other test lock keys and from the application advisory
/// locks, so the SSO-provider test cluster serializes only against itself.
const SSO_PROVIDER_TEST_LOCK_KEY: i64 = 0x5350_2621; // "SP" + issue #2621

/// Cross-process serialization guard for tests that seed *enabled* SSO
/// providers (#2621).
///
/// `AuthConfigService::list_enabled_providers` answers a WHOLE-database
/// question ("is any SSO provider enabled?") that both the local-login policy
/// gate and the public system-config affordance consult. Under `cargo
/// nextest`'s process-per-test parallelism, one test's freshly-seeded enabled
/// provider flips a peer test's "no SSO configured" baseline mid-assert. A
/// Postgres *session* advisory lock — mirroring [`scan_dedup_serial_lock`] —
/// makes every such test contend for one key, so only one runs its seed →
/// assert → cleanup critical section at a time. The lock releases when the
/// guard drops (connection closes), including on panic.
pub struct SsoProviderSerialGuard {
    _conn: Option<sqlx::PgConnection>,
}

/// Acquire the process-wide SSO-provider test lock, blocking until it is free.
///
/// Returns an inert guard (no lock held) when `DATABASE_URL` is unset or the
/// database is unreachable, mirroring [`try_pool`] so DB-free environments
/// still no-op cleanly. Call this as the first line of any DB-backed test
/// that seeds or asserts on enabled SSO providers and bind the result for the
/// whole test body.
pub async fn sso_provider_serial_lock() -> SsoProviderSerialGuard {
    SsoProviderSerialGuard {
        _conn: serial_lock_session(SSO_PROVIDER_TEST_LOCK_KEY).await,
    }
}

/// Advisory-lock key for [`curation_global_serial_lock`] (#2947).
///
/// Distinct from the other test lock keys and from the application advisory
/// locks, so the global-curation-rule test cluster serializes only against
/// itself.
const CURATION_GLOBAL_TEST_LOCK_KEY: i64 = 0x4355_2947; // "CU" + issue #2947

/// Cross-process serialization guard for tests that seed *global* curation
/// rules (#2947).
///
/// A `scope = 'global'` rule (`staging_repo_id IS NULL`) is instance-wide
/// policy: `fetch_applicable_rules` unions it into EVERY repository's rule
/// set. Under `cargo nextest`'s process-per-test parallelism, one test's
/// freshly-seeded global rule can decide (first-applicable-wins) a peer
/// test's evaluation mid-assert. A Postgres *session* advisory lock —
/// mirroring [`scan_dedup_serial_lock`] — makes every such test contend for
/// one key, so only one runs its seed → evaluate → cleanup critical section
/// at a time. The lock releases when the guard drops (connection closes),
/// including on panic.
pub struct CurationGlobalSerialGuard {
    _conn: Option<sqlx::PgConnection>,
}

/// Acquire the process-wide global-curation-rule test lock, blocking until it
/// is free.
///
/// Returns an inert guard (no lock held) when `DATABASE_URL` is unset or the
/// database is unreachable, mirroring [`try_pool`] so DB-free environments
/// still no-op cleanly. Call this as the first line of any DB-backed test
/// that seeds global curation rules and asserts on rule evaluation, and bind
/// the result for the whole test body.
pub async fn curation_global_serial_lock() -> CurationGlobalSerialGuard {
    CurationGlobalSerialGuard {
        _conn: serial_lock_session(CURATION_GLOBAL_TEST_LOCK_KEY).await,
    }
}

/// Advisory-lock key for [`path_stats_serial_lock`] (#2601).
///
/// Distinct from the other test lock keys and from the application advisory
/// locks (including the `hashtext('repository_path_storage_stats_rebuild')`
/// transaction lock the rebuild itself takes), so the path-stats test cluster
/// serializes only against itself.
const PATH_STATS_TEST_LOCK_KEY: i64 = 0x5053_2601; // "PS" + issue #2601

/// Cross-process serialization guard for the DB-backed path-stats tests
/// (#2601).
///
/// `StorageStatsService::recompute_path_stats` rebuilds the WHOLE
/// `repository_path_storage_stats` table (delete + reinsert in one
/// transaction), taking row locks across every repository's rows and FK
/// key-share locks on `repositories`. A peer test's `cleanup` (DELETE FROM
/// repositories, which cascades into the same stats rows) ordered against a
/// concurrent rebuild is a textbook two-table deadlock, and a repo deleted
/// between the rebuild's snapshot and its insert surfaces as an FK violation.
/// A Postgres *session* advisory lock — mirroring [`scan_dedup_serial_lock`]
/// — makes every path-stats test contend for one key, so only one runs its
/// seed → rebuild → assert → cleanup critical section at a time. The lock
/// releases when the guard drops (connection closes), including on panic.
pub struct PathStatsSerialGuard {
    _conn: Option<sqlx::PgConnection>,
}

/// Acquire the process-wide path-stats test lock, blocking until it is free.
///
/// Returns an inert guard (no lock held) when `DATABASE_URL` is unset or the
/// database is unreachable, mirroring [`try_pool`] so DB-free environments
/// still no-op cleanly. Call this as the first line of a DB-backed path-stats
/// test and bind the result for the whole test body.
pub async fn path_stats_serial_lock() -> PathStatsSerialGuard {
    PathStatsSerialGuard {
        _conn: serial_lock_session(PATH_STATS_TEST_LOCK_KEY).await,
    }
}

/// Advisory-lock key for [`format_registry_serial_lock`] (#3157).
///
/// Distinct from the other test lock keys and from the application advisory
/// locks, so the format-registry test cluster serializes only against itself.
const FORMAT_REGISTRY_TEST_LOCK_KEY: i64 = 0x4652_3157; // "FR" + issue #3157

/// Cross-process serialization guard for the DB-backed core-format-registry
/// tests (#3157).
///
/// `WasmPluginService::sync_core_format_handlers` upserts EVERY compiled-in
/// handler row, so two of these tests running concurrently would each observe
/// the other's rows: the test that deletes a handler row to reproduce the
/// pre-fix state would see it reappear under a peer's sync, and the test that
/// asserts a WASM-owned row survives a sync would race the same statement.
/// A Postgres *session* advisory lock — mirroring [`scan_dedup_serial_lock`] —
/// makes every such test contend for one key, so only one runs its
/// arrange → sync → assert → restore critical section at a time. The lock
/// releases when the guard drops (connection closes), including on panic.
pub struct FormatRegistrySerialGuard {
    _conn: Option<sqlx::PgConnection>,
}

/// Acquire the process-wide format-registry test lock, blocking until it is
/// free.
///
/// Returns an inert guard (no lock held) when `DATABASE_URL` is unset or the
/// database is unreachable, mirroring [`try_pool`] so DB-free environments
/// still no-op cleanly. Call this as the first line of a DB-backed
/// format-registry test and bind the result for the whole test body.
pub async fn format_registry_serial_lock() -> FormatRegistrySerialGuard {
    FormatRegistrySerialGuard {
        _conn: serial_lock_session(FORMAT_REGISTRY_TEST_LOCK_KEY).await,
    }
}

/// Refresh the materialized storage stats for a test, absorbing transient
/// cross-suite interference.
///
/// [`path_stats_serial_lock`] serializes the path-stats tests against each
/// other, but suites that do NOT take that lock still delete repositories
/// concurrently (their `cleanup`), which can deadlock against — or FK-abort —
/// a whole-table rebuild that has already snapshotted the deleted repo. Both
/// are transient orderings (the scheduler's answer in production is simply
/// the next tick), so the test helper retries a few times rather than letting
/// unrelated suite noise flake these assertions. `full` additionally runs the
/// repo-level persist (`recompute_all`), covering the #2601 chaining change.
pub async fn recompute_storage_stats_with_retry(pool: &PgPool, full: bool) {
    let service = crate::services::storage_stats_service::StorageStatsService::new(
        pool.clone(),
        "filesystem",
    );
    let mut last_err = None;
    for _ in 0..5 {
        let result = if full {
            service.recompute_all().await
        } else {
            service.recompute_path_stats().await
        };
        match result {
            Ok(()) => return,
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
    panic!("storage stats recompute kept failing after retries: {last_err:?}");
}

/// Build a lazily-connecting pool that never actually opens a connection
/// unless a query is issued. Useful for DB-free unit tests of code paths that
/// short-circuit before touching the database.
pub fn lazy_pool() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://invalid:invalid@127.0.0.1:1/none".to_string());
    sqlx::postgres::PgPoolOptions::new()
        .connect_lazy(&url)
        .expect("lazy pool")
}

fn cfg(storage_path: &str) -> Config {
    Config {
        database_url: std::env::var("DATABASE_URL").unwrap_or_default(),
        bind_address: "127.0.0.1:0".into(),
        log_level: "error".into(),
        environment: "development".into(),
        storage_backend: "filesystem".into(),
        storage_path: storage_path.into(),
        s3_bucket: None,
        backup_s3_bucket: None,
        gcs_bucket: None,
        s3_region: None,
        s3_endpoint: None,
        jwt_secret: "test-secret-at-least-32-bytes-long-for-testing".into(),
        signature_expiry_seconds: 604_800,
        jwt_expiration_secs: 86400,
        jwt_access_token_expiry_minutes: 30,
        jwt_refresh_token_expiry_days: 7,
        oidc_issuer: None,
        oidc_client_id: None,
        oidc_client_secret: None,
        ldap_url: None,
        ldap_base_dn: None,
        trivy_url: None,
        trivy_adapter_url: None,
        openscap_url: None,
        openscap_profile: "standard".into(),
        opensearch_url: None,
        opensearch_username: None,
        opensearch_password: None,
        opensearch_allow_invalid_certs: false,
        scan_workspace_path: "/tmp/scan".into(),
        demo_mode: false,
        guest_access_enabled: true,
        expose_detailed_health: false,
        setup_password_hint: None,
        grpc_reflection_enabled: false,
        plugins_require_signed: true,
        plugins_trusted_pubkey: None,
        peer_instance_name: "test".into(),
        peer_public_endpoint: "http://localhost:8080".into(),
        peer_api_key: "test-key".into(),
        dependency_track_url: None,
        dependency_track_enabled: false,
        otel_exporter_otlp_endpoint: None,
        otel_service_name: "test".into(),
        gc_schedule: "0 0 * * * *".into(),
        storage_stats_schedule: "0 0 */4 * * *".into(),
        blob_gc_enabled: false,
        maven_flat_gc_enabled: false,
        blob_gc_sweep_grace_secs: 3600,
        lifecycle_check_interval_secs: 60,
        stuck_scan_threshold_secs: 1800,
        stuck_scan_check_interval_secs: 600,
        stuck_scan_reap_limit: 1000,
        allow_local_admin_login: false,
        sso_disable_admin_break_glass: false,
        totp_policy: None,
        max_upload_size_bytes: 10_737_418_240,
        metrics_port: None,
        database_max_connections: 20,
        database_min_connections: 5,
        database_acquire_timeout_secs: 30,
        database_idle_timeout_secs: 600,
        database_max_lifetime_secs: 1800,
        auth_max_concurrency: crate::services::auth_service::TEST_AUTH_MAX_CONCURRENCY,
        global_max_concurrency: 512,
        global_request_timeout_secs: 120,
        rate_limit_enabled: true,
        rate_limit_auth_per_window: 120,
        rate_limit_api_per_window: 5000,
        rate_limit_search_per_window: 300,
        rate_limit_presign_per_window: 30,

        rate_limit_login_global_per_window: 8192,
        rate_limit_login_per_window: 10,
        rate_limit_login_window_secs: 900,
        rate_limit_password_change_per_window: 5,
        rate_limit_password_change_window_secs: 900,
        rate_limit_window_secs: 60,
        rate_limit_exempt_usernames: Vec::new(),
        rate_limit_exempt_service_accounts: false,
        rate_limit_trusted_cidrs: Vec::new(),
        rate_limit_trusted_proxy_cidrs: Vec::new(),
        account_lockout_threshold: 5,
        account_lockout_duration_minutes: 30,
        quarantine_enabled: false,
        quarantine_duration_minutes: 60,
        password_history_count: 0,
        password_expiry_days: 0,
        password_expiry_warning_days: vec![14, 7, 1],
        password_expiry_check_interval_secs: 3600,
        password_min_length: 8,
        password_max_length: 128,
        password_require_uppercase: false,
        password_require_lowercase: false,
        password_require_digit: false,
        password_require_special: false,
        password_min_strength: 0,
        presigned_downloads_enabled: false,
        presigned_download_expiry_secs: 300,
        proxy_singleflight_advisory_locks_enabled: false,
        proxy_singleflight_lock_poll_interval_ms: 200,
        proxy_singleflight_lock_wait_timeout_secs: 65,
        smtp_host: None,
        smtp_port: 587,
        smtp_username: None,
        smtp_password: None,
        smtp_from_address: "noreply@test.local".to_string(),
        smtp_tls_mode: "starttls".to_string(),
        npm_packument_cache_enabled: true,
        npm_packument_cache_fresh_ttl_secs: 300,
        npm_packument_cache_stale_max_secs: 86_400,
        npm_packument_cache_redis_url: None,
        npm_upstream_feed_enabled: false,
        npm_upstream_feed_url: crate::services::upstream_feed::NPM_REPLICATION_FEED_DEFAULT_URL
            .into(),
        scan_token_ttl_seconds: 300,
    }
}

pub fn build_state(pool: PgPool, storage_path: &str) -> SharedState {
    build_state_with(pool, storage_path, |_| {})
}

/// Like [`build_state`], but lets the caller adjust the test `Config` before
/// the state is built (e.g. toggling auth-policy flags such as
/// `allow_local_admin_login`).
pub fn build_state_with(
    pool: PgPool,
    storage_path: &str,
    mutate: impl FnOnce(&mut Config),
) -> SharedState {
    let storage: Arc<dyn crate::storage::StorageBackend> = Arc::new(
        crate::storage::filesystem::FilesystemStorage::new(storage_path),
    );
    // Production parity (#3368): the registry knows the global storage root,
    // so reserved bucket-root namespaces resolve there rather than under a
    // per-repository directory.
    let registry = Arc::new(
        crate::storage::StorageRegistry::new(
            std::collections::HashMap::new(),
            "filesystem".to_string(),
        )
        .with_filesystem_bucket_root(storage_path),
    );
    let mut config = cfg(storage_path);
    mutate(&mut config);
    Arc::new(AppState::new(config, pool, storage, registry))
}

/// Minimal in-memory [`crate::storage::StorageBackend`] double for tests that
/// need a registered *cloud* backend (shared flat namespace) instead of the
/// per-repo-rooted filesystem storage `build_state` provides.
///
/// A missing key returns [`crate::error::AppError::NotFound`], which is the
/// #1016 contract every real backend honours and the variant handlers match on
/// to tell "object absent" from "backend broken". This double previously
/// returned a generic storage error whose *message* contained "not found", so
/// only the string-sniffing call sites saw a miss and the `Err(NotFound(_))`
/// arms were unreachable under test (#3463).
#[derive(Default)]
pub struct MemStorage {
    pub objects: std::sync::Mutex<std::collections::HashMap<String, Bytes>>,
    /// Count of `get` calls, so a test can assert how many storage round
    /// trips a handler actually made (#3463: a repair path that cannot
    /// succeed still costs a read, and "did it stop re-reading" is not
    /// observable from the response alone).
    pub gets: std::sync::atomic::AtomicUsize,
    /// When true the double advertises presigned-redirect capability, standing
    /// in for an S3/GCS backend with `S3_REDIRECT_DOWNLOADS=true`. Defaults to
    /// false so every existing `MemStorage` user keeps the streaming path.
    pub presign: bool,
}

impl MemStorage {
    /// Number of `get` calls observed so far.
    pub fn get_count(&self) -> usize {
        self.gets.load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[async_trait::async_trait]
impl crate::storage::StorageBackend for MemStorage {
    async fn put(&self, key: &str, content: Bytes) -> crate::error::Result<()> {
        self.objects
            .lock()
            .unwrap()
            .insert(key.to_string(), content);
        Ok(())
    }

    async fn get(&self, key: &str) -> crate::error::Result<Bytes> {
        self.gets.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.objects
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .ok_or_else(|| crate::error::AppError::NotFound(format!("Key not found: {key}")))
    }

    async fn exists(&self, key: &str) -> crate::error::Result<bool> {
        Ok(self.objects.lock().unwrap().contains_key(key))
    }

    async fn delete(&self, key: &str) -> crate::error::Result<()> {
        self.objects.lock().unwrap().remove(key);
        Ok(())
    }

    async fn put_stream(
        &self,
        key: &str,
        stream: futures::stream::BoxStream<'static, crate::error::Result<Bytes>>,
    ) -> crate::error::Result<crate::storage::PutStreamResult> {
        crate::storage::buffered_put_stream_fallback(self, key, stream).await
    }

    fn supports_redirect(&self) -> bool {
        self.presign
    }

    async fn get_presigned_url(
        &self,
        key: &str,
        expires_in: std::time::Duration,
    ) -> crate::error::Result<Option<crate::storage::PresignedUrl>> {
        if !self.presign {
            return Ok(None);
        }
        // Shaped like a real SigV4 URL — in particular the signature is bound
        // to a single HTTP method, which is the whole point of #3181. Tests
        // assert on the `X-Amz-` marker rather than parsing it.
        Ok(Some(crate::storage::PresignedUrl {
            url: format!(
                "https://signed.example.com/{key}?X-Amz-Algorithm=AWS4-HMAC-SHA256\
                 &X-Amz-Expires={}&X-Amz-Signature=deadbeef",
                expires_in.as_secs()
            ),
            expires_in,
            source: crate::storage::PresignedUrlSource::S3,
        }))
    }
}

/// Like [`build_state`], but the registry carries an in-memory backend
/// registered under `backend_name` (e.g. `"s3"`), simulating a shared cloud
/// namespace. Returns the state plus the backing [`MemStorage`] so tests can
/// assert exactly which physical keys were written (#2624).
pub fn build_state_with_cloud(pool: PgPool, backend_name: &str) -> (SharedState, Arc<MemStorage>) {
    build_cloud_state(pool, backend_name, /* presign = */ false)
}

/// Like [`build_state_with_cloud`], but the in-memory backend advertises
/// presigned-redirect capability AND `presigned_downloads_enabled` is on —
/// i.e. the S3-with-`S3_REDIRECT_DOWNLOADS=true` deployment shape of #1555 /
/// #1945. Used by the #3181 HEAD regression coverage, which needs a router
/// whose GETs really do 302 so the HEAD assertion is not vacuous.
pub fn build_state_with_presigning_cloud(
    pool: PgPool,
    backend_name: &str,
) -> (SharedState, Arc<MemStorage>) {
    build_cloud_state(pool, backend_name, /* presign = */ true)
}

fn build_cloud_state(
    pool: PgPool,
    backend_name: &str,
    presign: bool,
) -> (SharedState, Arc<MemStorage>) {
    let mem = Arc::new(MemStorage {
        presign,
        ..Default::default()
    });
    let mut backends: std::collections::HashMap<String, Arc<dyn crate::storage::StorageBackend>> =
        std::collections::HashMap::new();
    backends.insert(backend_name.to_string(), mem.clone());
    let registry = Arc::new(crate::storage::StorageRegistry::new(
        backends,
        backend_name.to_string(),
    ));
    let storage: Arc<dyn crate::storage::StorageBackend> = mem.clone();
    let mut config = cfg("/tmp/ak-cloud-test-unused");
    config.presigned_downloads_enabled = presign;
    let state = Arc::new(AppState::new(config, pool, storage, registry));
    (state, mem)
}

pub async fn create_user(pool: &PgPool) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let username = format!("ph-test-u-{}", id);
    sqlx::query(
        r#"
        INSERT INTO users (id, username, email, password_hash, auth_provider, is_admin, is_active)
        VALUES ($1, $2, $3, 'unused', 'local', false, true)
        "#,
    )
    .bind(id)
    .bind(&username)
    .bind(format!("{}@test.local", username))
    .execute(pool)
    .await
    .expect("create user");
    (id, username)
}

/// Like [`create_user`], but the row is `is_service_account = true`. Shared
/// so DB-backed tests that need a service-account principal (e.g. the
/// #2826 permission-name hydration tests, and any legacy-grant test that
/// needs a `principal_type = 'user'` row naming a service account) don't
/// each hand-roll the same INSERT.
pub async fn create_service_account(pool: &PgPool) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let username = format!("ph-test-sa-{}", id);
    sqlx::query(
        r#"
        INSERT INTO users
            (id, username, email, password_hash, auth_provider,
             is_admin, is_active, is_service_account)
        VALUES ($1, $2, $3, 'unused', 'local', false, true, true)
        "#,
    )
    .bind(id)
    .bind(&username)
    .bind(format!("{}@test.local", username))
    .execute(pool)
    .await
    .expect("create service account");
    (id, username)
}

/// Insert a bare `groups` row (id + name only). Shared by DB-backed tests
/// that need a group principal but not the full `GroupService` create flow.
pub async fn create_group(pool: &PgPool) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let name = format!("ph-test-group-{}", id);
    sqlx::query("INSERT INTO groups (id, name) VALUES ($1, $2)")
        .bind(id)
        .bind(&name)
        .execute(pool)
        .await
        .expect("create group");
    (id, name)
}

/// Insert a repository row of the given type and format. `format` must be
/// a valid `repository_format` enum value (e.g. "ansible", "helm", "rpm").
pub async fn create_repo(pool: &PgPool, repo_type: &str, format: &str) -> (Uuid, String, PathBuf) {
    let id = Uuid::new_v4();
    let key = format!("ph-test-{}-{}", format, id);
    let storage_dir = std::env::temp_dir().join(format!("ph-test-{}", id));
    std::fs::create_dir_all(&storage_dir).expect("create storage dir");
    let upstream: Option<&str> = if repo_type == "remote" {
        Some("https://upstream.example.test")
    } else {
        None
    };
    let sql = format!(
        "INSERT INTO repositories (id, key, name, storage_path, repo_type, format, upstream_url) \
         VALUES ($1, $2, $3, $4, '{}'::repository_type, '{}'::repository_format, $5)",
        repo_type, format
    );
    sqlx::query(&sql)
        .bind(id)
        .bind(&key)
        .bind(&key)
        .bind(&*storage_dir.to_string_lossy())
        .bind(upstream)
        .execute(pool)
        .await
        .expect("create repo");
    (id, key, storage_dir)
}

/// Mark a repository public.
///
/// `create_repo` leaves `is_public` at its `false` default, so a repository it
/// creates is PRIVATE. Since #3323 a virtual repo resolves only the members the
/// CALLER may read directly, which means a fixture that links a `create_repo`
/// member and then probes ANONYMOUSLY resolves nothing — correctly.
///
/// Use this in fixtures whose subject is the virtual AGGREGATION rather than
/// the authorization, so the anonymous probe stays valid. When the fixture
/// probes with a caller, prefer [`grant_repo_access`] instead: it keeps the
/// member private and exercises the full read predicate rather than the
/// public-repository short-circuit.
pub async fn publish_repo(pool: &PgPool, repo_id: Uuid) {
    sqlx::query("UPDATE repositories SET is_public = true WHERE id = $1")
        .bind(repo_id)
        .execute(pool)
        .await
        .expect("publish repo");
}

pub fn make_auth(user_id: Uuid, username: &str) -> AuthExtension {
    AuthExtension {
        user_id,
        username: username.to_string(),
        email: format!("{}@test.local", username),
        is_admin: false,
        is_api_token: false,
        is_service_account: false,
        scopes: None,
        allowed_repo_ids: crate::models::access_scope::AccessScope::Admin,
        iat_ms: None,
    }
}

/// Wrap any Router<SharedState> in `with_state` + auth-injection layer.
pub fn router_with_auth(
    router: Router<SharedState>,
    state: SharedState,
    auth: AuthExtension,
) -> Router {
    router
        .with_state(state)
        .layer(Extension::<Option<AuthExtension>>(Some(auth)))
}

pub fn router_anon(router: Router<SharedState>, state: SharedState) -> Router {
    router
        .with_state(state)
        .layer(Extension::<Option<AuthExtension>>(None))
}

/// Like [`router_with_auth`] but also injects the **non-Option**
/// `Extension<AuthExtension>`, exactly as the production `auth_middleware`
/// does (it inserts both `Some(ext)` and `ext`). Handlers that extract
/// `Extension<AuthExtension>` directly (e.g. the admin-gated peer-label
/// handlers) require this raw copy to be present, otherwise the extractor
/// fails with a 500 before the in-handler authorization check ever runs.
pub fn router_with_auth_ext(
    router: Router<SharedState>,
    state: SharedState,
    auth: AuthExtension,
) -> Router {
    router
        .with_state(state)
        .layer(Extension::<AuthExtension>(auth.clone()))
        .layer(Extension::<Option<AuthExtension>>(Some(auth)))
}

/// Register a peer instance via the real `PeerInstanceService` and return its
/// id. `name_prefix` namespaces the generated peer name so concurrent suites do
/// not collide (e.g. "probe", "labels-authz", "map-err"). Centralizes the
/// `register(RegisterPeerInstanceRequest { .. })` boilerplate shared by every
/// DB-backed peer test module.
pub async fn register_test_peer(pool: &PgPool, name_prefix: &str, tag: &str) -> Uuid {
    use crate::services::peer_instance_service::{
        PeerInstanceService, RegisterPeerInstanceRequest,
    };
    let svc = PeerInstanceService::new(pool.clone());
    let id = Uuid::new_v4();
    svc.register(RegisterPeerInstanceRequest {
        name: format!("{}-{}-{}", name_prefix, tag, &id.to_string()[..8]),
        endpoint_url: "https://peer.example.test".to_string(),
        region: Some("us-east".to_string()),
        cache_size_bytes: 1024,
        sync_filter: None,
        api_key: "k".to_string(),
    })
    .await
    .expect("register peer")
    .id
}

pub async fn send(app: Router, req: Request<Body>) -> (StatusCode, Bytes) {
    let resp = app.oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let body = to_bytes(resp.into_body(), 16 * 1024 * 1024)
        .await
        .expect("body");
    (status, body)
}

/// Like [`send`], but also returns the response headers.
///
/// Body buffering is sanctioned here rather than at the call site: the
/// module-level `disallowed_methods` exemption above covers test scaffolding,
/// so a header-asserting test does not have to punch its own hole in the
/// streaming lint (#1608).
pub async fn send_with_headers(
    app: Router,
    req: Request<Body>,
) -> (StatusCode, Bytes, axum::http::HeaderMap) {
    let resp = app.oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = to_bytes(resp.into_body(), 16 * 1024 * 1024)
        .await
        .expect("body");
    (status, body, headers)
}

/// Grant `user_id` the `developer` role scoped to `repo_id`. Handler smoke
/// tests use this for an ordinary read/write repository member; owner-specific
/// tests should grant the `repository-owner` role explicitly.
pub async fn grant_repo_access(pool: &PgPool, repo_id: Uuid, user_id: Uuid) {
    sqlx::query(
        "INSERT INTO role_assignments (user_id, role_id, repository_id) \
         SELECT $1, r.id, $2 FROM roles r WHERE r.name = 'developer' \
         ON CONFLICT (user_id, role_id, repository_id) DO NOTHING",
    )
    .bind(user_id)
    .bind(repo_id)
    .execute(pool)
    .await
    .expect("grant developer role");
}

/// Like [`make_auth`] but for a GLOBAL admin (`is_admin = true`). Used by
/// handler tests that must pass an admin-only gate (#2321 G3/G4/G5) to reach
/// the downstream validation/update/not-found logic they cover.
pub fn admin_auth(user_id: Uuid, username: &str) -> AuthExtension {
    AuthExtension {
        is_admin: true,
        ..make_auth(user_id, username)
    }
}

/// Grant `user_id` the fine-grained `repository:admin` action on `repo_id`
/// (a `permissions` rule, distinct from the `role_assignments` membership row
/// `grant_repo_access` inserts). Repo-admin-gated handlers (`set_cache_ttl`,
/// `invalidate_cache`) require this for non-admins; the smoke tests that assert
/// a successful admin-tier call grant it here. Cleaned up by `cleanup`.
pub async fn grant_repo_admin(pool: &PgPool, repo_id: Uuid, user_id: Uuid) {
    grant_permission(pool, "user", user_id, "repository", repo_id, &["admin"]).await;
}

/// Insert a fine-grained `permissions` rule granting `user_id` exactly the
/// listed `actions` on `repo_id` (e.g. `["read", "write", "delete"]`).
///
/// This drives the #817/#2321 fine-grained gate (`has_any_rules_for_target` +
/// `check_permission`), which is DISTINCT from `grant_repo_access` (a
/// `role_assignments` membership row). Once any `permissions` rule exists for a
/// repository, the per-action check on the write/delete handlers stops falling
/// through, so a destructive test that expects success must grant the exact
/// action it exercises. Rows are cleaned up by `cleanup` (which deletes all
/// `permissions WHERE target_id = repo_id`).
pub async fn grant_repo_actions(pool: &PgPool, repo_id: Uuid, user_id: Uuid, actions: &[&str]) {
    grant_permission(pool, "user", user_id, "repository", repo_id, actions).await;
}

/// Insert a fine-grained `permissions` row for an arbitrary
/// `(principal_type, principal_id, target_type, target_id)` pair and return
/// its id. The general form behind [`grant_repo_admin`] and
/// [`grant_repo_actions`] (both `principal_type = "user"`,
/// `target_type = "repository"` specializations); use this directly for
/// group/service-account principals or non-repository targets (e.g. the
/// #2826 permission-name hydration tests). Rows are cleaned up by
/// [`cleanup`]'s `target_id = repo_id` delete when the target is a
/// repository; other targets need their own teardown.
pub async fn grant_permission(
    pool: &PgPool,
    principal_type: &str,
    principal_id: Uuid,
    target_type: &str,
    target_id: Uuid,
    actions: &[&str],
) -> Uuid {
    let actions: Vec<String> = actions.iter().map(|s| s.to_string()).collect();
    sqlx::query_scalar(
        "INSERT INTO permissions \
         (principal_type, principal_id, target_type, target_id, actions) \
         VALUES ($1, $2, $3, $4, $5) \
         RETURNING id",
    )
    .bind(principal_type)
    .bind(principal_id)
    .bind(target_type)
    .bind(target_id)
    .bind(&actions)
    .fetch_one(pool)
    .await
    .expect("insert permission rule")
}

/// Mint a `Bearer <jwt>` authorization header for `user_id` using the same
/// `AuthService` the handlers validate against (the state's DB + config). Shared
/// so authz tests that need a SECOND authenticated identity don't copy-paste the
/// user-row SELECT + token mint (keeps the jscpd dedup gate green).
pub async fn bearer_for(state: &SharedState, user_id: Uuid) -> String {
    let auth_service = crate::services::auth_service::AuthService::new(
        state.db.clone(),
        Arc::new(state.config.clone()),
    );
    let user = sqlx::query_as::<_, User>(
        r#"SELECT id, username, email, password_hash, display_name, auth_provider,
                  external_id, is_admin, is_active, is_service_account, must_change_password,
                  totp_secret, totp_enabled, totp_backup_codes, totp_verified_at,
                  failed_login_attempts, locked_until, last_failed_login_at,
                  password_changed_at, last_login_at, created_at, updated_at
           FROM users WHERE id = $1"#,
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await
    .expect("fetch user for bearer");
    format!(
        "Bearer {}",
        auth_service
            .generate_tokens(&user)
            .expect("mint bearer token")
            .access_token
    )
}

/// Recursively find the largest file (in bytes) under `dir`, or 0 if none.
fn dir_max_file_size(dir: &std::path::Path) -> u64 {
    let mut max = 0u64;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            max = max.max(dir_max_file_size(&path));
        } else if let Ok(meta) = std::fs::metadata(&path) {
            max = max.max(meta.len());
        }
    }
    max
}

/// Poll `dir` until a file of at least `min_size` bytes appears (the committed
/// proxy-cache blob) or a bounded timeout elapses. The streaming write-back tee
/// commits the cache asynchronously after the response body drains, so tests
/// that assert a WARM second request must wait for the commit deterministically
/// instead of racing it (#2192 / #1608 Phase 4c).
pub async fn wait_for_cached_blob(dir: &std::path::Path, min_size: u64) {
    for _ in 0..200 {
        if dir_max_file_size(dir) >= min_size {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}

/// True when `dir` holds a committed proxy-cache entry of at least
/// `min_size` bytes: a `{base}__content__` object of that size whose
/// matching `{base}__cache_meta__.json` sidecar exists.
pub fn committed_cache_entry_exists(dir: &std::path::Path, min_size: u64) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if committed_cache_entry_exists(&path, min_size) {
                return true;
            }
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some(base) = name.strip_suffix("__content__") else {
            continue;
        };
        if std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0) < min_size {
            continue;
        }
        if path
            .with_file_name(format!("{base}__cache_meta__.json"))
            .exists()
        {
            return true;
        }
    }
    false
}

/// Poll `dir` until the proxy streaming write-back has fully COMMITTED a
/// cache entry of at least `min_size` bytes, or panic after ~60s. The budget
/// must absorb worst-case parallel-run latency: the tee's ETag pin and
/// sidecar write sit behind the same runtime and DB pool as every other
/// concurrent test, and pool acquire alone is allowed 30s. A ~10s budget
/// expired spuriously at 16 coverage test threads.
///
/// The tee (`ProxyService::tee_stream`) commits in three ordered steps:
/// content object (`{base}__content__`), storage-ETag pin (a backend HEAD),
/// then the metadata sidecar (`{base}__cache_meta__.json`) — and only the
/// sidecar makes the next lookup a cache HIT. [`wait_for_cached_blob`]'s
/// size-only condition becomes true at step one, so warm-cache tests gating
/// on it race the sidecar write and observe a second upstream fetch under
/// parallel test load. This waits for the matching sidecar as well — the
/// same commit marker the production hit path requires.
pub async fn wait_for_cache_commit(dir: &std::path::Path, min_size: u64) {
    for _ in 0..2400 {
        if committed_cache_entry_exists(dir, min_size) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    panic!(
        "proxy cache never committed (content + __cache_meta__.json sidecar) under {}",
        dir.display()
    );
}

/// Attach a Maven GAV-grouped `files[]` metadata document to the artifact at
/// `parent_key`, listing one row-less companion under the JSON key spelling
/// `json_key_name` (`"storageKey"` is what the legacy #418-era upload handler
/// wrote; `"storage_key"` is the hand-repair fallback, #2706).
///
/// The entry shape mirrors the production fixture in
/// `test_expand_maven_secondary_files_emits_each_file`. Shared by the
/// repository-delete and GC flat-object guard tests (#3156) so the two do not
/// carry independent copies of the same seed.
pub async fn attach_maven_files_metadata(
    pool: &PgPool,
    parent_key: &str,
    json_key_name: &str,
    companion_key: &str,
) {
    sqlx::query(
        "INSERT INTO artifact_metadata (artifact_id, format, metadata) \
         SELECT id, 'maven', jsonb_build_object('files', $2::jsonb) \
         FROM artifacts WHERE storage_key = $1",
    )
    .bind(parent_key)
    .bind(serde_json::json!([{
        "path": "com/example/demo/1.0.0/demo-1.0.0.pom",
        "extension": "pom",
        json_key_name: companion_key,
        "sizeBytes": 200,
        "sha256": "pom-sha",
    }]))
    .execute(pool)
    .await
    .expect("attach maven files[] metadata");
}

pub async fn cleanup(pool: &PgPool, repo_id: Uuid, user_id: Uuid) {
    let _ = sqlx::query("DELETE FROM role_assignments WHERE repository_id = $1")
        .bind(repo_id)
        .execute(pool)
        .await;
    // Fine-grained rules (`grant_repo_admin` / `grant_repo_actions`) are
    // polymorphic on (target_type, target_id) with no FK cascade from
    // `repositories`, so remove them explicitly to keep the fixture self-cleaning.
    let _ =
        sqlx::query("DELETE FROM permissions WHERE target_type = 'repository' AND target_id = $1")
            .bind(repo_id)
            .execute(pool)
            .await;
    let _ = sqlx::query(
        "DELETE FROM artifact_metadata WHERE artifact_id IN \
         (SELECT id FROM artifacts WHERE repository_id = $1)",
    )
    .bind(repo_id)
    .execute(pool)
    .await;
    let _ = sqlx::query("DELETE FROM artifacts WHERE repository_id = $1")
        .bind(repo_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
        .bind(repo_id)
        .execute(pool)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await;
}

/// Link `member_id` into virtual repository `virtual_id`'s member set at
/// `priority`. Shared by the virtual-member authorization tests (#3324) so
/// each format module does not hand-roll the same INSERT.
pub async fn link_virtual_member(pool: &PgPool, virtual_id: Uuid, member_id: Uuid, priority: i32) {
    sqlx::query(
        "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
         VALUES ($1, $2, $3)",
    )
    .bind(virtual_id)
    .bind(member_id)
    .bind(priority)
    .execute(pool)
    .await
    .expect("link virtual member");
}

/// Drop a member repository created by [`create_repo`] for a virtual-repo
/// test, along with everything the test seeded under it (membership rows,
/// grants, artifacts + their metadata) and its storage directory. Shared by
/// the virtual-member authorization tests (#3324).
pub async fn cleanup_member_repo(pool: &PgPool, member_id: Uuid, dir: &std::path::Path) {
    for sql in [
        "DELETE FROM virtual_repo_members WHERE member_repo_id = $1",
        "DELETE FROM role_assignments WHERE repository_id = $1",
        "DELETE FROM artifact_metadata WHERE artifact_id IN \
         (SELECT id FROM artifacts WHERE repository_id = $1)",
        "DELETE FROM artifacts WHERE repository_id = $1",
        "DELETE FROM repositories WHERE id = $1",
    ] {
        let _ = sqlx::query(sql).bind(member_id).execute(pool).await;
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// Count `audit_log` rows for a given resource id + action string.
///
/// Shared by the auth-event audit trail tests (#386 / #1617 Phase 1) across
/// the `profile`, `totp`, and `users` handler modules so the identical
/// count-query is defined once rather than copy-pasted into each DB-backed
/// test module (keeps the jscpd duplication gate green).
pub async fn audit_count(pool: &PgPool, resource_id: Uuid, action: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM audit_log WHERE resource_id = $1 AND action = $2",
    )
    .bind(resource_id)
    .bind(action)
    .fetch_one(pool)
    .await
    .expect("audit_log count query")
}

/// Poll [`audit_count`] until it reaches `expected` (or a bounded ~2s budget is
/// exhausted), returning the last observed value.
///
/// Since #2522 the fire-and-forget audit emitters (`audit_fire_and_forget`)
/// SPAWN their INSERT instead of awaiting it, so a test that acts and then reads
/// the audit trail must tolerate the detached task's async timing. Use this for
/// the "an event was emitted" (count reaches N) assertions; a subsequent
/// "not emitted" (count stays 0) assertion can then read [`audit_count`]
/// directly, since the spawned writes for this resource have already drained.
pub async fn audit_count_eventually(
    pool: &PgPool,
    resource_id: Uuid,
    action: &str,
    expected: i64,
) -> i64 {
    let mut last = -1;
    for _ in 0..100 {
        last = audit_count(pool, resource_id, action).await;
        if last >= expected {
            return last;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    last
}

/// Count `download_statistics` rows for `artifact_id`.
pub async fn download_count(pool: &PgPool, artifact_id: Uuid) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM download_statistics WHERE artifact_id = $1")
        .bind(artifact_id)
        .fetch_one(pool)
        .await
        .expect("download_statistics count query")
}

/// Poll [`download_count`] until it reaches `expected` (or a bounded ~2s budget
/// is exhausted), returning the last observed value.
///
/// Since #2522 `record_download` SPAWNS the `download_statistics` INSERT off the
/// synchronous download hot path, so a test that serves a body and then reads
/// the count must tolerate the detached write's async timing.
pub async fn download_count_eventually(pool: &PgPool, artifact_id: Uuid, expected: i64) -> i64 {
    let mut last = -1;
    for _ in 0..100 {
        last = download_count(pool, artifact_id).await;
        if last >= expected {
            return last;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    last
}

/// Delete a test user plus the auth-related rows the audit/2FA test modules
/// create for it (audit_log, refresh/pending jti, password history). Shared
/// teardown so the identical cleanup block isn't copy-pasted across the #386
/// audit test modules (jscpd dedup).
pub async fn cleanup_user(pool: &PgPool, user_id: Uuid) {
    let _ = sqlx::query("DELETE FROM audit_log WHERE resource_id = $1")
        .bind(user_id)
        .execute(pool)
        .await;
    for table in ["refresh_token_jti", "totp_pending_jti", "password_history"] {
        let _ = sqlx::query(&format!("DELETE FROM {table} WHERE user_id = $1"))
            .bind(user_id)
            .execute(pool)
            .await;
    }
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool)
        .await;
}

/// A TOTP-enrolled test user plus everything the enable/disable/verify handler
/// tests need: the loaded [`User`] model, the raw secret bytes for generating
/// live codes, the base32 secret, and the storage-backed [`SharedState`].
pub struct TotpUserFixture {
    pub user: User,
    pub secret_bytes: Vec<u8>,
    pub secret_b32: String,
    pub state: SharedState,
    pub storage_dir: PathBuf,
}

/// Seed a fresh `totp_enabled` user with the given backup-code hashes and
/// return a [`TotpUserFixture`]. Centralizes the seed + `User` literal so the
/// TOTP handler test modules (verify-hardening #1819/#1820/#1822 and the #386
/// audit-trail tests) share one definition instead of copy-pasting it (jscpd
/// dedup). `password_hash` is seeded to the sentinel `"unused"`; tests that
/// exercise the password-verify path (e.g. `disable_totp`) overwrite it with a
/// real bcrypt hash.
pub async fn create_totp_user(pool: &PgPool, backup_hashes: &[String]) -> TotpUserFixture {
    let (user_id, username) = create_user(pool).await;
    let secret = totp_rs::Secret::generate_secret();
    let secret_b32 = secret.to_encoded().to_string();
    let secret_bytes = secret.to_bytes().expect("secret bytes");
    let backup_json = serde_json::to_string(backup_hashes).expect("serialize backup");
    sqlx::query(
        "UPDATE users SET totp_secret = $1, totp_enabled = true, totp_backup_codes = $2 \
         WHERE id = $3",
    )
    .bind(&secret_b32)
    .bind(&backup_json)
    .bind(user_id)
    .execute(pool)
    .await
    .expect("enable totp");
    let storage_dir = std::env::temp_dir().join(format!("totp-fixture-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&storage_dir).expect("create storage dir");
    let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
    let user = User {
        id: user_id,
        username,
        email: format!("{user_id}@test.local"),
        password_hash: Some("unused".to_string()),
        display_name: None,
        auth_provider: crate::models::user::AuthProvider::Local,
        external_id: None,
        is_admin: false,
        is_active: true,
        is_service_account: false,
        must_change_password: false,
        totp_secret: Some(secret_b32.clone()),
        totp_enabled: true,
        totp_backup_codes: Some(backup_json),
        totp_verified_at: None,
        failed_login_attempts: 0,
        locked_until: None,
        last_failed_login_at: None,
        password_changed_at: chrono::Utc::now(),
        last_login_at: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    TotpUserFixture {
        user,
        secret_bytes,
        secret_b32,
        state,
        storage_dir,
    }
}

/// Build a `Basic <base64(user:pass)>` header value.
pub fn basic_auth(user: &str, pass: &str) -> String {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", user, pass));
    format!("Basic {}", encoded)
}

/// Build a `RepoInfo` shaped for handler tests. `repo_type` is the
/// stringified repository_type ("local", "remote", "virtual").
pub fn make_repo_info(
    repo_id: Uuid,
    repo_key: &str,
    storage_dir: &std::path::Path,
    repo_type: &str,
    upstream_url: Option<&str>,
) -> crate::api::handlers::proxy_helpers::RepoInfo {
    crate::api::handlers::proxy_helpers::RepoInfo {
        id: repo_id,
        key: repo_key.to_string(),
        storage_path: storage_dir.to_string_lossy().into_owned(),
        storage_backend: "filesystem".to_string(),
        repo_type: repo_type.to_string(),
        format: "generic".to_string(),
        upstream_url: upstream_url.map(|s| s.to_string()),
        promotion_only: false,
        age_gate_enabled: false,
        age_gate_min_age_days: 7,
        age_gate_mode: "upstream_publish_time".to_string(),
        curation_enabled: false,
        curation_default_action: "allow".to_string(),
    }
}

/// Seed a single artifact: write `content` to `storage_key` and insert
/// an `artifacts` row at `path`. Returns the inserted artifact id.
///
/// Centralizes the put+insert pattern shared by every handler smoke test.
#[allow(clippy::too_many_arguments)]
pub async fn seed_artifact(
    state: &SharedState,
    pool: &PgPool,
    repo: &crate::api::handlers::proxy_helpers::RepoInfo,
    storage_key: &str,
    path: &str,
    name: &str,
    version: &str,
    content_type: &str,
    content: Bytes,
    uploaded_by: Uuid,
) -> Uuid {
    crate::api::handlers::proxy_helpers::put_artifact_bytes(
        state,
        repo,
        storage_key,
        content.clone(),
    )
    .await
    .expect("seed put_artifact_bytes");
    crate::api::handlers::proxy_helpers::insert_artifact(
        pool,
        crate::api::handlers::proxy_helpers::NewArtifact {
            repository_id: repo.id,
            path,
            name,
            version,
            size_bytes: content.len() as i64,
            checksum_sha256: "test-seed",
            content_type,
            storage_key,
            uploaded_by,
        },
    )
    .await
    .expect("seed insert_artifact")
}

/// Build a GET request with no body. Centralizes the
/// `Request::builder().method("GET").uri(...).body(empty)` boilerplate.
pub fn get(uri: String) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(uri)
        .body(Body::empty())
        .expect("build GET request")
}

/// Build a HEAD request.
///
/// Note that a router registering only `get(..)` still answers HEAD by running
/// the GET handler, so this exercises the same handler code the GET does — the
/// distinction lives in `DownloadContext::is_head` (#3181).
pub fn head(uri: String) -> Request<Body> {
    Request::builder()
        .method("HEAD")
        .uri(uri)
        .body(Body::empty())
        .expect("build HEAD request")
}

/// Build a POST request with the given body and content-type header.
pub fn post(uri: String, content_type: &str, body: Bytes) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", content_type)
        .body(Body::from(body))
        .expect("build POST request")
}

/// Build a PUT request with raw body bytes.
pub fn put(uri: String, body: Bytes) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(uri)
        .body(Body::from(body))
        .expect("build PUT request")
}

/// Build a PUT request carrying a JSON body (sets `content-type` so the
/// `Json` extractor accepts it; the raw [`put`] helper omits it, which yields
/// a 415 for handlers that extract `Json<_>`).
pub fn put_json(uri: String, body: Bytes) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .expect("build PUT JSON request")
}

/// Bundles all the per-test scaffolding so each handler test body is a
/// single helper call followed by assertions. Returned `None` indicates
/// the test should skip (no `DATABASE_URL`).
pub struct Fixture {
    pub pool: PgPool,
    pub user_id: Uuid,
    pub username: String,
    pub repo_id: Uuid,
    pub repo_key: String,
    pub storage_dir: PathBuf,
    pub state: SharedState,
}

impl Fixture {
    /// Spin up a pool, user, repository, and SharedState. Returns `None`
    /// when no `DATABASE_URL` is available so the test no-ops gracefully.
    /// `repo_type` is "local" / "remote" / "virtual"; `format` matches a
    /// `repository_format` enum value (e.g. "ansible", "cran").
    pub async fn setup(repo_type: &str, format: &str) -> Option<Self> {
        let pool = try_pool().await?;
        let (user_id, username) = create_user(&pool).await;
        let (repo_id, repo_key, storage_dir) = create_repo(&pool, repo_type, format).await;
        // Make the fixture user an ordinary repository member. This keeps the
        // authenticated-router smoke tests valid under per-repo authorization
        // without silently giving every fixture durable owner capability.
        grant_repo_access(&pool, repo_id, user_id).await;
        let state = build_state(pool.clone(), storage_dir.to_str().unwrap());
        Some(Self {
            pool,
            user_id,
            username,
            repo_id,
            repo_key,
            storage_dir,
            state,
        })
    }

    /// Flag the fixture repository as `promotion_only` (or clear the flag).
    /// Used by the format-native publish-gate tests to assert that a direct
    /// upload to a promotion_only repository is rejected.
    pub async fn set_promotion_only(&self, value: bool) {
        sqlx::query("UPDATE repositories SET promotion_only = $1 WHERE id = $2")
            .bind(value)
            .bind(self.repo_id)
            .execute(&self.pool)
            .await
            .expect("set promotion_only");
    }

    /// Build a `RepoInfo` matching this fixture's repository. Mirrors the
    /// shape callers need for direct `proxy_helpers` invocations.
    pub fn repo_info(
        &self,
        repo_type: &str,
        upstream_url: Option<&str>,
    ) -> crate::api::handlers::proxy_helpers::RepoInfo {
        make_repo_info(
            self.repo_id,
            &self.repo_key,
            &self.storage_dir,
            repo_type,
            upstream_url,
        )
    }

    /// Build a router with no auth injected (handler will see `None`).
    pub fn router_anon(&self, router: Router<SharedState>) -> Router {
        router_anon(router, self.state.clone())
    }

    /// Build a router with auth injected for the fixture's user.
    pub fn router_with_auth(&self, router: Router<SharedState>) -> Router {
        let auth = make_auth(self.user_id, &self.username);
        router_with_auth(router, self.state.clone(), auth)
    }

    /// Drop all rows owned by this fixture and remove the storage dir.
    pub async fn teardown(&self) {
        cleanup(&self.pool, self.repo_id, self.user_id).await;
        let _ = std::fs::remove_dir_all(&self.storage_dir);
    }
}

/// Build a [`crate::services::proxy_service::ProxyService`] backed by a
/// filesystem cache at `storage_path`.
///
/// Pass a real `PgPool` from [`try_pool`] — `ProxyService::fetch_from_upstream`
/// calls `load_upstream_auth` which queries the database before every HTTP
/// request. A lazy/fake pool will cause that query to fail and the fetch to
/// return BAD_GATEWAY.
pub fn build_proxy_service_with_fs(
    pool: PgPool,
    storage_path: &str,
) -> Arc<crate::services::proxy_service::ProxyService> {
    use crate::services::storage_service::{FilesystemBackend, StorageService};
    let backend = Arc::new(FilesystemBackend::new(std::path::PathBuf::from(
        storage_path,
    )));
    Arc::new(crate::services::proxy_service::ProxyService::new(
        pool,
        Arc::new(StorageService::new(backend)),
    ))
}

/// Build a [`SharedState`] that includes `proxy` as the proxy service.
/// Accepts any `PgPool` so callers can supply a lazy/fake pool for tests
/// that do not need a real database.
/// Construct an [`AppState`] from `config` plus a fresh filesystem storage
/// backend + empty registry rooted at `storage_path`. Shared spine of the
/// `build_state*` constructors.
fn app_state_with(config: Config, pool: PgPool, storage_path: &str) -> crate::api::AppState {
    let storage: Arc<dyn crate::storage::StorageBackend> = Arc::new(
        crate::storage::filesystem::FilesystemStorage::new(storage_path),
    );
    // Production parity (#3368): the registry knows the global storage root,
    // so reserved bucket-root namespaces resolve there rather than under a
    // per-repository directory.
    let registry = Arc::new(
        crate::storage::StorageRegistry::new(
            std::collections::HashMap::new(),
            "filesystem".to_string(),
        )
        .with_filesystem_bucket_root(storage_path),
    );
    crate::api::AppState::new(config, pool, storage, registry)
}

pub fn build_state_with_proxy(
    pool: PgPool,
    storage_path: &str,
    proxy: Arc<crate::services::proxy_service::ProxyService>,
) -> crate::api::SharedState {
    let mut state = app_state_with(cfg(storage_path), pool, storage_path);
    state.set_proxy_service(proxy);
    Arc::new(state)
}

/// Like [`build_state_with_proxy`] but also wires a
/// [`crate::services::scanner_service::ScannerService`] onto the state, so
/// handler tests can exercise the inline proxy scan + verdict-freshness wiring
/// end-to-end (#2954/#2976): the serve path only re-scans (and only consults
/// the live CVE-scanner version) when a scanner service is present.
pub fn build_state_with_proxy_and_scanner(
    pool: PgPool,
    storage_path: &str,
    proxy: Arc<crate::services::proxy_service::ProxyService>,
    scanner: Arc<crate::services::scanner_service::ScannerService>,
) -> crate::api::SharedState {
    let mut state = app_state_with(cfg(storage_path), pool, storage_path);
    state.set_proxy_service(proxy);
    state.set_scanner_service(scanner);
    Arc::new(state)
}

/// Enable scan-on-proxy for a repository with the given
/// `proxy_scan_action` (`"fail_open"` / `"fail_closed"`). Shared by the
/// inline scan-and-block handler tests (#2954 PyPI, #3003 npm).
pub async fn enable_proxy_scan(pool: &PgPool, repo_id: Uuid, action: &str) {
    sqlx::query(
        "INSERT INTO scan_configs (repository_id, scan_enabled, scan_on_upload, \
             scan_on_proxy, block_on_policy_violation, severity_threshold, \
             proxy_scan_action) \
         VALUES ($1, true, false, true, false, 'high', $2)",
    )
    .bind(repo_id)
    .bind(action)
    .execute(pool)
    .await
    .expect("enable scan-on-proxy");
}

/// Build a state whose scanner service holds exactly the given mock leaf
/// scanners, wired over the fixture's storage + a real proxy service. Shared
/// by the #2976 verdict-freshness handler tests across formats so each format
/// file does not re-assemble the ScannerService by hand.
pub fn build_scan_state_with_leaf_scanners(
    fx: &Fixture,
    storage_path: &str,
    scanners: Vec<Arc<dyn crate::services::scanner_service::Scanner>>,
) -> crate::api::SharedState {
    let proxy = build_proxy_service_with_fs(fx.pool.clone(), storage_path);
    let svc = crate::services::scanner_service::ScannerService::new_for_test_with_scanners(
        fx.pool.clone(),
        scanners,
        fx.state.storage.clone(),
        fx.state.storage_registry.clone(),
        storage_path.to_string(),
        fx.storage_dir
            .join("scan-workspace")
            .to_string_lossy()
            .into_owned(),
    );
    build_state_with_proxy_and_scanner(fx.pool.clone(), storage_path, proxy, Arc::new(svc))
}

/// Like [`build_state_with_proxy`] but also wires an [`AgeGateService`] onto the
/// state so handler tests can exercise the download age gate end-to-end
/// (`serve_file` / `serve_tarball` only enforce the gate when the service is
/// present; when it is `None` every check returns `Allow`).
pub fn build_state_with_proxy_and_age_gate(
    pool: PgPool,
    storage_path: &str,
    proxy: Arc<crate::services::proxy_service::ProxyService>,
) -> crate::api::SharedState {
    use crate::services::age_gate_service::AgeGateService;
    use crate::services::event_bus::EventBus;
    let mut state = app_state_with(cfg(storage_path), pool.clone(), storage_path);
    state.set_proxy_service(proxy);
    state.set_age_gate_service(Arc::new(AgeGateService::new(
        pool,
        Arc::new(EventBus::new(4)),
    )));
    Arc::new(state)
}

/// Like [`build_state_with_proxy`] but with `presigned_downloads_enabled = true`
/// so tests can drive the presigned-redirect gate (#1555). The filesystem
/// backend still reports `supports_redirect() == false`, so the redirect path
/// short-circuits to streaming — exactly the non-S3 fallback we want to cover.
pub fn build_state_with_proxy_presigned(
    pool: PgPool,
    storage_path: &str,
    proxy: Arc<crate::services::proxy_service::ProxyService>,
) -> crate::api::SharedState {
    let mut config = cfg(storage_path);
    config.presigned_downloads_enabled = true;
    let mut state = app_state_with(config, pool, storage_path);
    state.set_proxy_service(proxy);
    Arc::new(state)
}

/// Repoint a fixture's Remote repository at `upstream_url` and build a
/// [`SharedState`] wired with a real [`ProxyService`] whose proxy cache lives in
/// a fresh temp dir (returned so the caller keeps it alive for the request).
///
/// Shared by the format handlers' `remote download streams upstream blob`
/// regression tests (#1608 Phase 4): they mount a wiremock upstream, call this
/// to wire the proxy in, then drive the handler router end-to-end to exercise
/// the streaming pull-through branch (`proxy_fetch_streaming`).
pub async fn rewire_remote_proxy(
    fx: &Fixture,
    upstream_url: &str,
) -> (crate::api::SharedState, tempfile::TempDir) {
    sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
        .bind(upstream_url)
        .bind(fx.repo_id)
        .execute(&fx.pool)
        .await
        .expect("update upstream_url");
    let dir = tempfile::tempdir().expect("tempdir");
    let proxy = build_proxy_service_with_fs(fx.pool.clone(), dir.path().to_str().unwrap());
    let state = build_state_with_proxy(fx.pool.clone(), dir.path().to_str().unwrap(), proxy);
    (state, dir)
}

// ---------------------------------------------------------------------------
// #3149 / #3184: Content-Encoding forwarding fixtures.
// ---------------------------------------------------------------------------

/// Build a body coded with `encoding`, returning `(plain, coded)`.
///
/// Shared across the npm / PyPI / OCI / generic-repository / cargo arms so the
/// suites do not each carry their own copy of the encoder block (the jscpd
/// duplication gate scores changed files). The payload is deliberately
/// repetitive so the coding actually shrinks it: the caller asserts
/// `coded != plain`, without which a "forwarding" test could pass while
/// proving nothing.
///
/// Exists because every #3149 fixture was gzip and every assertion was
/// `== Some("gzip")`, so replacing the forwarded value with a hardcoded
/// `"gzip"` literal left all fourteen tests green -- the builders were pinned
/// to "some coding is declared", not to "the UPSTREAM's coding is declared".
/// That is not academic: `http_client.rs` documents that S3 returns a stored
/// `Content-Encoding` regardless of the request, and S3 commonly stores `br`.
/// A brotli-stored wheel labelled `gzip` makes pip raise `DecodeError`
/// mid-stream, which is strictly worse than the bug being fixed.
///
/// Use a NON-gzip coding in at least one test per builder.
pub fn coded_fixture(encoding: &str, seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let plain = seed.repeat(64);
    let coded = code_bytes(encoding, &plain);
    assert_ne!(
        coded, plain,
        "fixture must actually be coded or the test proves nothing"
    );
    (plain, coded)
}

/// Apply `encoding` to arbitrary bytes.
///
/// [`coded_fixture`] builds its own repetitive plaintext, which is right when
/// the payload is opaque. Tests whose payload has to be a *specific* artifact —
/// a real wheel zip whose METADATA the server then extracts (#3193) — need to
/// code bytes they already have, so the encoder block lives here and both entry
/// points share it rather than each suite growing a copy (the jscpd duplication
/// gate scores changed files).
pub fn code_bytes(encoding: &str, plain: &[u8]) -> Vec<u8> {
    use flate2::write::{DeflateEncoder, GzEncoder};
    use flate2::Compression;
    use std::io::Write;

    match encoding {
        "gzip" => {
            let mut e = GzEncoder::new(Vec::new(), Compression::default());
            e.write_all(plain).expect("gzip encode");
            e.finish().expect("gzip finish")
        }
        "deflate" => {
            let mut e = DeflateEncoder::new(Vec::new(), Compression::default());
            e.write_all(plain).expect("deflate encode");
            e.finish().expect("deflate finish")
        }
        other => panic!("unsupported test coding {other}"),
    }
}

/// Send `uri` through `app`, require 200, and return `(body, headers)` for
/// the #3260 forwarding assertions ([`assert_coded_forward`] /
/// [`assert_plain_forward`]). Shared so the goproxy / rubygems / hex suites
/// do not each carry a probe wrapper (the jscpd duplication gate scores
/// changed files).
pub async fn probe_ok(app: Router, uri: String) -> (Bytes, axum::http::HeaderMap) {
    let (status, body, headers) = send_with_headers(app, get(uri)).await;
    assert_eq!(status, StatusCode::OK, "probe must proxy 200");
    (body, headers)
}

/// The pair of wiremock upstreams a #3260 verbatim-forward test drives,
/// together with the coding that was actually mounted on the coded one.
///
/// The coding lives ON the fixture — and every assertion reads it from here —
/// so an assertion cannot be satisfied by a handler that emits some *other*
/// coding. That is the whole point: the first cut of these helpers compared
/// the served header against the literal `"deflate"`, which made all three
/// suites pass with the production line rewritten to
/// `builder.header(CONTENT_ENCODING, "deflate")`. See [`coded_fixture`] for
/// why that failure mode (a `br` upstream mislabelled) is worse than the bug
/// #3260 fixed.
pub struct CodedUpstreams {
    /// The coding the coded upstream declares and its body is actually coded
    /// with. Every expectation below is derived from this field rather than
    /// from a literal, so the suites can vary it per format.
    pub encoding: String,
    /// The uncoded bytes: what `encoding` must decode the served body back to.
    pub plain: Vec<u8>,
    /// The coded bytes the coded upstream serves, byte for byte.
    pub coded: Vec<u8>,
    /// Upstream that declares `encoding` on every GET.
    pub coded_mock: wiremock::MockServer,
    /// Upstream that declares no coding on every GET (the positive control).
    pub plain_mock: wiremock::MockServer,
}

/// Mount a pair of wiremock upstreams for the #3260 verbatim-forward tests:
/// the first answers every GET with `coded` and `Content-Encoding: <encoding>`
/// declared, the second answers every GET with `plain` and no coding (the
/// positive control), both under `content_type`.
///
/// Shared across the goproxy / rubygems / hex arms so each suite does not
/// carry its own copy of the mock block (the jscpd duplication gate scores
/// changed files). Uses [`coded_fixture`], so callers should pass a NON-gzip
/// coding — see its doc for why a gzip fixture proves less — and the suites
/// should not all pass the SAME coding, or a hardcoded literal of that one
/// coding satisfies every assertion in the tree.
pub async fn coded_and_plain_upstreams(
    encoding: &str,
    content_type: &str,
    seed: &[u8],
) -> CodedUpstreams {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let (plain, coded) = coded_fixture(encoding, seed);
    let coded_mock = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", content_type)
                .insert_header("content-encoding", encoding)
                .set_body_bytes(coded.clone()),
        )
        .mount(&coded_mock)
        .await;
    let plain_mock = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", content_type)
                .set_body_bytes(plain.clone()),
        )
        .mount(&plain_mock)
        .await;
    CodedUpstreams {
        encoding: encoding.to_string(),
        plain,
        coded,
        coded_mock,
        plain_mock,
    }
}

impl CodedUpstreams {
    /// Assert a #3260 verbatim forward of the coded upstream's body: the
    /// coding THIS FIXTURE mounted is the one re-declared (RFC 9110 §8.4),
    /// `Content-Length` describes the coded bytes actually sent (§8.6), the
    /// bytes pass through unchanged, and the declared coding actually decodes
    /// the body back to `plain` — not merely "some header is present".
    pub fn assert_coded_forward(&self, headers: &axum::http::HeaderMap, body: &[u8], what: &str) {
        let served = headers
            .get(axum::http::header::CONTENT_ENCODING)
            .map(|v| v.to_str().unwrap());
        assert_eq!(
            served,
            Some(self.encoding.as_str()),
            "{what}: the UPSTREAM's Content-Encoding must be re-declared, not some \
             other coding (#3260)"
        );
        assert_eq!(
            headers
                .get(axum::http::header::CONTENT_LENGTH)
                .map(|v| v.to_str().unwrap().to_string()),
            Some(self.coded.len().to_string()),
            "{what}: Content-Length must describe the coded bytes actually sent"
        );
        assert_eq!(
            body, self.coded,
            "{what}: coded bytes must pass through verbatim"
        );
        // Decode with the coding the RESPONSE declared, not with the one the
        // fixture mounted: this is what the client does, so a mislabel that
        // slipped past the header assertion still fails here.
        assert_eq!(
            decode_coded(served.expect("checked above"), body),
            self.plain,
            "{what}: the client must be able to decode the body with the declared coding"
        );
    }

    /// Positive control for [`CodedUpstreams::assert_coded_forward`], same
    /// fixture: an UNCODED upstream body must be forwarded byte-identically
    /// and must NOT grow a spurious `Content-Encoding` header.
    pub fn assert_plain_forward(&self, headers: &axum::http::HeaderMap, body: &[u8], what: &str) {
        assert_eq!(
            headers.get(axum::http::header::CONTENT_ENCODING),
            None,
            "{what}: an uncoded upstream must not grow a Content-Encoding header"
        );
        assert_eq!(
            body, self.plain,
            "{what}: uncoded body must be forwarded byte-identically"
        );
    }

    /// How many GETs the CODED upstream has served for `path` so far.
    ///
    /// The barrier for the warm-cache (`resolve_virtual_metadata` Pass 1)
    /// probes: a second request whose count is unchanged was answered from
    /// the proxy cache, so the assertions that follow are about the cache-hit
    /// arm and not a second cold fan-out. Both the fixed and the broken shape
    /// of that arm reach this barrier, so it cannot mask a regression.
    pub async fn coded_hits(&self, path: &str) -> usize {
        self.coded_mock
            .received_requests()
            .await
            .expect("wiremock request recording is enabled")
            .iter()
            .filter(|r| r.url.path() == path)
            .count()
    }
}

/// Create a Remote repository of `format` pointed at `upstream_url`, plus a
/// Virtual repository of the same format whose sole member is that remote.
/// Returns `(remote_id, remote_key, virtual_id, virtual_key)`; the caller
/// cleans both up by deleting the repository rows (members cascade).
pub async fn create_remote_and_virtual(
    pool: &PgPool,
    format: &str,
    upstream_url: &str,
) -> (Uuid, String, Uuid, String) {
    let (remote_id, remote_key, _dir) = create_repo(pool, "remote", format).await;
    sqlx::query("UPDATE repositories SET upstream_url = $1 WHERE id = $2")
        .bind(upstream_url)
        .bind(remote_id)
        .execute(pool)
        .await
        .expect("point remote upstream at mock");
    let (virtual_id, virtual_key, _vdir) = create_repo(pool, "virtual", format).await;
    sqlx::query(
        "INSERT INTO virtual_repo_members (virtual_repo_id, member_repo_id, priority) \
         VALUES ($1, $2, 0)",
    )
    .bind(virtual_id)
    .bind(remote_id)
    .execute(pool)
    .await
    .expect("link remote as virtual member");
    // Every rig built on this pair probes ANONYMOUSLY, and since #3323 a
    // virtual repo resolves only the members the caller may read directly.
    // Publish the member so those fixtures keep testing what they are about —
    // verbatim Content-Type / Content-Encoding forwarding (#3281 / #3260) —
    // rather than the authorization filter.
    publish_repo(pool, remote_id).await;
    (remote_id, remote_key, virtual_id, virtual_key)
}

/// Decode a body coded with `encoding` — the inverse of [`code_bytes`], so a
/// test can assert the client receives BYTES it can actually decode rather
/// than only that a header is present.
///
/// Takes the coding as a parameter (rather than hardcoding one decoder) so an
/// assertion can decode with the coding the RESPONSE declared. A decoder
/// pinned to a single coding cannot distinguish "forwarded the upstream's
/// coding" from "always emits that coding", which is exactly the hole the
/// #3260 suites shipped with.
pub fn decode_coded(encoding: &str, coded: &[u8]) -> Vec<u8> {
    use flate2::read::{DeflateDecoder, GzDecoder};
    use std::io::Read;

    let mut out = Vec::new();
    match encoding {
        "gzip" => GzDecoder::new(coded).read_to_end(&mut out),
        "deflate" => DeflateDecoder::new(coded).read_to_end(&mut out),
        other => panic!("unsupported test coding {other}"),
    }
    .expect("body must be decodable with the coding it declares");
    out
}

/// Decode a `deflate` body. Thin alias for [`decode_coded`] kept for the
/// #3149 / #3184 suites that only ever mount deflate.
pub fn inflate_deflate(coded: &[u8]) -> Vec<u8> {
    decode_coded("deflate", coded)
}

// ---------------------------------------------------------------------------
// #3281: Content-Type forwarding fixtures for Virtual verbatim metadata.
// ---------------------------------------------------------------------------

/// The distinctive `Content-Type` the [`Ct3281Rig`]'s typed upstream mounts.
/// Deliberately not any format's default literal, so an assertion against it
/// can only be satisfied by actually forwarding the MEMBER's type.
pub const CT_3281_TYPED: &str = "application/x-artifact-keeper-test-3281";

/// Mount an upstream that answers every GET with `body` and, when given,
/// declares `content_type`. Never declares a coding. `set_body_bytes` sets no
/// `Content-Type` of its own, so `None` yields a genuinely untyped response.
pub async fn upstream_with_optional_ct(
    content_type: Option<&str>,
    body: &[u8],
) -> wiremock::MockServer {
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mut template = ResponseTemplate::new(200).set_body_bytes(body.to_vec());
    if let Some(ct) = content_type {
        template = template.insert_header("content-type", ct);
    }
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(template)
        .mount(&server)
        .await;
    server
}

/// Rig for the #3281 Virtual verbatim `Content-Type` probes, shared across
/// the goproxy / rubygems / hex suites (the jscpd duplication gate scores
/// changed files).
///
/// Holds two (Remote member + Virtual) pairs of one format: one whose member
/// upstream declares [`CT_3281_TYPED`] on every GET, one whose member
/// declares no `Content-Type` at all. A Virtual verbatim forward must serve
/// the member's type for the first and the caller's format default for the
/// second — the same contract the Remote arms already implement.
pub struct Ct3281Rig {
    pub state: crate::api::SharedState,
    /// Virtual repo whose member declares [`CT_3281_TYPED`].
    pub typed_virtual_key: String,
    /// Virtual repo whose member declares no `Content-Type`.
    pub untyped_virtual_key: String,
    repo_ids: Vec<Uuid>,
    _typed_mock: wiremock::MockServer,
    _untyped_mock: wiremock::MockServer,
    _cache_dir: tempfile::TempDir,
}

/// Build a [`Ct3281Rig`] for `format`, serving `body` from both member
/// upstreams. `fx` supplies only the DB + proxy-carrying state.
pub async fn setup_ct_3281_rig(fx: &Fixture, format: &str, body: &[u8]) -> Ct3281Rig {
    let typed_mock = upstream_with_optional_ct(Some(CT_3281_TYPED), body).await;
    let untyped_mock = upstream_with_optional_ct(None, body).await;
    let (state, cache_dir) = rewire_remote_proxy(fx, &typed_mock.uri()).await;
    let (typed_member_id, _tk, typed_virtual_id, typed_virtual_key) =
        create_remote_and_virtual(&fx.pool, format, &typed_mock.uri()).await;
    let (untyped_member_id, _uk, untyped_virtual_id, untyped_virtual_key) =
        create_remote_and_virtual(&fx.pool, format, &untyped_mock.uri()).await;
    Ct3281Rig {
        state,
        typed_virtual_key,
        untyped_virtual_key,
        repo_ids: vec![
            typed_virtual_id,
            typed_member_id,
            untyped_virtual_id,
            untyped_member_id,
        ],
        _typed_mock: typed_mock,
        _untyped_mock: untyped_mock,
        _cache_dir: cache_dir,
    }
}

impl Ct3281Rig {
    /// Probe `uri` (a 200-serving Virtual metadata endpoint) and assert the
    /// served `Content-Type`: the member's own [`CT_3281_TYPED`] through the
    /// typed pair, and `default_ct` (the caller's format literal) through the
    /// untyped pair. `uri_for` builds the URI from a virtual repo key.
    pub async fn assert_member_ct_forwarded(
        &self,
        router: Router<SharedState>,
        uri_for: impl Fn(&str) -> String,
        default_ct: &str,
        what: &str,
    ) {
        for (key, expected, case) in [
            (&self.typed_virtual_key, CT_3281_TYPED, "member-declared"),
            (&self.untyped_virtual_key, default_ct, "fallback-to-default"),
        ] {
            let app = router_anon(router.clone(), self.state.clone());
            let (_body, headers) = probe_ok(app, uri_for(key)).await;
            let served = headers
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok());
            assert_eq!(
                served,
                Some(expected),
                "{what} ({case}): a Virtual verbatim forward must serve the member \
                 upstream's Content-Type, falling back to the format default only \
                 when the member declares none (#3281)"
            );
        }
    }

    /// Delete the rig's repositories (members cascade out of the virtual
    /// membership table via FK).
    pub async fn cleanup(self, pool: &PgPool) {
        for id in &self.repo_ids {
            let _ = sqlx::query("DELETE FROM repositories WHERE id = $1")
                .bind(id)
                .execute(pool)
                .await;
        }
    }
}

/// Build a gzip-coded body, returning `(plain, coded)`.
///
/// Retained for the arms that assert GET/HEAD header parity, where the point
/// of the test is that two builders agree with each other rather than which
/// coding is in play. Prefer [`coded_fixture`] with a NON-gzip coding for
/// anything asserting that the UPSTREAM's coding is what gets forwarded: a
/// gzip fixture cannot tell that apart from a hardcoded `"gzip"`.
pub fn gzip_fixture(seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    let plain = seed.repeat(64);
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&plain).expect("gzip encode");
    let coded = encoder.finish().expect("gzip finish");
    assert_ne!(
        coded, plain,
        "fixture must actually be coded or the test proves nothing"
    );
    (plain, coded)
}

/// Read a header off a response as a `String`, or `None` when absent.
///
/// The #3149 tests assert both presence (proxied serve forwards the upstream
/// coding) and ABSENCE (an uncoded upstream must not have a coding
/// manufactured for it), so they need the negative case to be expressible.
pub fn header_str(
    headers: &axum::http::HeaderMap,
    name: axum::http::header::HeaderName,
) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// Collect a `Response` produced by calling a handler DIRECTLY (rather than
/// through a `Router`) into `(status, body, headers)`.
///
/// [`send_with_headers`] covers the router path; several #3149 arms are
/// reached by invoking the handler function with its extractors, which yields
/// a bare `Response`. Body buffering lives here because `.clippy.toml`
/// disallows `axum::body::to_bytes` at call sites under the #1608 streaming
/// invariant, and this module carries the documented exemption.
pub async fn collect_response(
    resp: axum::response::Response,
) -> (StatusCode, Bytes, axum::http::HeaderMap) {
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = to_bytes(resp.into_body(), 16 * 1024 * 1024)
        .await
        .expect("body");
    (status, body, headers)
}

/// An admin-shaped `Extension<Option<AuthExtension>>` payload for tests that
/// invoke a download handler (or `proxy_helpers` resolver) DIRECTLY rather than
/// through a router.
///
/// Since #3178 the virtual-repo byte resolvers filter members by caller, so a
/// direct call must supply one. A global admin reproduces the pre-#3178
/// unfiltered member set exactly, which keeps those tests measuring what they
/// were written to measure (resolution order, caching, telemetry) instead of
/// silently becoming authorization tests. Authorization itself is covered by
/// `repositories::virtual_member_authz_tests`.
///
/// No `users` row is required: `RepoVisibility::All` short-circuits before any
/// query.
pub fn admin_auth_ext() -> Option<AuthExtension> {
    Some(admin_auth(Uuid::new_v4(), "tdh-resolver-admin"))
}
