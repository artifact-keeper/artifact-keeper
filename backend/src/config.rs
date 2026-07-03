//! Application configuration loaded from environment variables.

use crate::error::{AppError, Result};
use std::env;
use std::path::Path;

/// Read an environment variable and parse it, falling back to a default on missing or invalid values.
fn env_parse<T: std::str::FromStr>(key: &str, default: T) -> T {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Parse a comma-separated list of CIDR ranges from env var `key`.
///
/// Whitespace around each entry is trimmed and empty entries are dropped.
/// Individual entries that fail to parse are logged at warn level and skipped
/// (rather than aborting startup), so one typo never takes down the whole
/// list. An unset or empty var yields an empty list. Shared by the
/// rate-limit exemption (`RATE_LIMIT_TRUSTED_CIDRS`) and trusted-proxy
/// (`RATE_LIMIT_TRUSTED_PROXY_CIDRS`) lists so both honor the same syntax.
fn parse_cidr_list_env(key: &str) -> Vec<crate::api::middleware::rate_limit::CidrRange> {
    env::var(key)
        .ok()
        .map(|s| {
            s.split(',')
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .filter_map(
                    |c| match crate::api::middleware::rate_limit::CidrRange::parse(c) {
                        Ok(cidr) => Some(cidr),
                        Err(e) => {
                            tracing::warn!("Ignoring invalid CIDR in {}: {}", key, e);
                            None
                        }
                    },
                )
                .collect()
        })
        .unwrap_or_default()
}

/// Parse an opt-in boolean flag from an optional env value.
///
/// Returns `true` only for `"true"` / `"1"` (case-insensitive, trimmed);
/// every other value — including `None` (unset), empty, or garbage — is
/// `false`. Used for safety-critical opt-ins like blob GC where the
/// default MUST be off and only an explicit, recognized affirmative
/// enables it. Pure so the truth table is unit-testable without env.
fn parse_opt_in_flag(value: Option<&str>) -> bool {
    matches!(
        value.map(|v| v.trim().to_lowercase()).as_deref(),
        Some("true" | "1")
    )
}

/// Parse an opt-OUT boolean env flag: defaults to `true` (enabled) when
/// unset or unrecognized, and only an explicit, recognized negative
/// (`false`/`0`, case/whitespace-insensitive) turns it off. Used for
/// features that are ON by default and must stay on unless the operator
/// deliberately disables them — e.g. `RATE_LIMIT_ENABLED` (#1602). Pure so
/// the truth table is unit-testable without touching the environment.
fn parse_opt_out_flag(value: Option<&str>) -> bool {
    !matches!(
        value.map(|v| v.trim().to_lowercase()).as_deref(),
        Some("false" | "0")
    )
}

/// Minimum reap-threshold for the stuck-scan janitor.
///
/// `STUCK_SCAN_THRESHOLD_SECS=0` would match every `running` row on every
/// tick (the SQL becomes `started_at < NOW() - interval '0'`), reaping
/// healthy in-flight scans. A 60 s floor still lets operators configure
/// very aggressive reaping for fast-scan workloads while rejecting the
/// degenerate-zero misconfiguration.
const STUCK_SCAN_THRESHOLD_FLOOR_SECS: u64 = 60;

/// Minimum tick interval for the stuck-scan janitor.
///
/// `tokio::time::interval(Duration::from_secs(0))` panics, so a zero value
/// kills the spawned scheduler task at startup with no operator-visible
/// signal beyond a tokio panic in logs. A 30 s floor is well below the
/// 600 s default and matches the cadence of the existing lifecycle
/// scheduler.
const STUCK_SCAN_INTERVAL_FLOOR_SECS: u64 = 30;

fn clamp_stuck_scan_threshold(value: u64) -> u64 {
    if value < STUCK_SCAN_THRESHOLD_FLOOR_SECS {
        tracing::warn!(
            value,
            floor = STUCK_SCAN_THRESHOLD_FLOOR_SECS,
            "STUCK_SCAN_THRESHOLD_SECS below floor; clamping to floor"
        );
        STUCK_SCAN_THRESHOLD_FLOOR_SECS
    } else {
        value
    }
}

fn clamp_stuck_scan_interval(value: u64) -> u64 {
    if value < STUCK_SCAN_INTERVAL_FLOOR_SECS {
        tracing::warn!(
            value,
            floor = STUCK_SCAN_INTERVAL_FLOOR_SECS,
            "STUCK_SCAN_CHECK_INTERVAL_SECS below floor; clamping to floor"
        );
        STUCK_SCAN_INTERVAL_FLOOR_SECS
    } else {
        value
    }
}

/// Default cap for concurrent bcrypt-bound auth operations.
///
/// bcrypt-cost-12 is CPU-bound and takes roughly 100-300 ms per verify; once
/// in-flight verifies exceed `8 * cores`, additional requests queue behind a
/// saturated blocking-thread pool and the rest of the API starves.
///
/// The floor of 32 (raised from 8 in #1437/#1442 — see CHANGELOG) keeps
/// low-core CI runners from shedding modest concurrent basic-auth load:
/// previously a 2-core CI runner capped at 8 concurrent bcrypts, so a
/// `cargo publish` job that issued 20 parallel requests would fail 12 of
/// them with 503 (counted as "5xx" by upstream stress tests). The 8x
/// multiplier keeps large machines from being capped artificially low.
///
/// Combined with the 3 s queue tolerance in
/// [`acquire_auth_permit_for_bcrypt`](crate::services::auth_service)
/// requests now *briefly wait* for a slot instead of failing instantly,
/// so a burst of 50 concurrent verifies at cap=32 settles cleanly.
fn default_auth_max_concurrency() -> usize {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2);
    std::cmp::max(32, cores.saturating_mul(8))
}

/// Application configuration
#[derive(Clone)]
pub struct Config {
    /// Database connection URL
    pub database_url: String,

    /// Server bind address (host:port)
    pub bind_address: String,

    /// Log level
    pub log_level: String,

    /// Storage backend: "filesystem" or "s3"
    pub storage_backend: String,

    /// Filesystem storage path (when storage_backend = "filesystem")
    pub storage_path: String,

    /// S3 bucket name (when storage_backend = "s3")
    pub s3_bucket: Option<String>,

    /// GCS bucket name (when storage_backend = "gcs")
    pub gcs_bucket: Option<String>,

    /// S3 region
    pub s3_region: Option<String>,

    /// S3 endpoint URL (for MinIO or other S3-compatible services)
    pub s3_endpoint: Option<String>,

    /// JWT secret key for signing tokens
    pub jwt_secret: String,

    /// JWT token expiration in seconds (legacy, use jwt_access_token_expiry_minutes)
    pub jwt_expiration_secs: u64,

    /// JWT access token expiry in minutes
    pub jwt_access_token_expiry_minutes: i64,

    /// JWT refresh token expiry in days
    pub jwt_refresh_token_expiry_days: i64,

    /// OIDC issuer URL (optional)
    pub oidc_issuer: Option<String>,

    /// OIDC client ID (optional)
    pub oidc_client_id: Option<String>,

    /// OIDC client secret (optional)
    pub oidc_client_secret: Option<String>,

    /// LDAP server URL (optional)
    pub ldap_url: Option<String>,

    /// LDAP base DN (optional)
    pub ldap_base_dn: Option<String>,

    /// Trivy server URL for filesystem / incus (rootfs) scanning (optional).
    /// Consumed by `TrivyFsScanner` and `IncusScanner`, which drive the trivy
    /// server directly (`--server` / dir-mode). NOT used for container image
    /// scanning — see `trivy_adapter_url`.
    pub trivy_url: Option<String>,

    /// Harbor Pluggable Scanner adapter URL for container *image* scanning
    /// (optional), e.g. `http://trivy:8090` for `harbor-scanner-trivy`. When
    /// set, `ImageScanner` is registered and scans images via the Harbor
    /// scanner-adapter API (fail-closed on any adapter error). When unset, no
    /// container-image (trivy/image) scanner runs — grype still scans. This is
    /// deliberately separate from `trivy_url`: the adapter's HTTP API is
    /// incompatible with the trivy-server Twirp/`--server` protocol the
    /// fs/incus scanners use. See #2088.
    pub trivy_adapter_url: Option<String>,

    /// Lifetime, in seconds, of the short-lived per-repository pull token the
    /// scanner mints for private-image scans (#2093). Env
    /// `SCAN_TOKEN_TTL_SECONDS`, default 300. Kept intentionally short: the
    /// token only has to live long enough for the adapter / grype to complete
    /// the OCI pull, and a shorter window bounds the blast radius if one leaks
    /// (it is also single-repo-scoped via the `scan_pull_repo` claim).
    pub scan_token_ttl_seconds: u64,

    /// OpenSCAP wrapper URL for compliance scanning (optional)
    pub openscap_url: Option<String>,

    /// OpenSCAP SCAP profile to evaluate (default: standard)
    pub openscap_profile: String,

    /// OpenSearch URL for search indexing (optional)
    pub opensearch_url: Option<String>,

    /// OpenSearch username for authentication (optional)
    pub opensearch_username: Option<String>,

    /// OpenSearch password for authentication (optional)
    pub opensearch_password: Option<String>,

    /// Allow invalid TLS certificates when connecting to OpenSearch (default: false)
    pub opensearch_allow_invalid_certs: bool,

    /// Path for scan workspace shared with Trivy
    pub scan_workspace_path: String,

    /// Demo mode: blocks all write operations (POST/PUT/DELETE/PATCH) except auth
    pub demo_mode: bool,

    /// When true (default), unauthenticated requests are allowed to reach
    /// public repositories and other endpoints that explicitly opt in to
    /// optional auth. When false, every request that hits a route protected
    /// by `optional_auth_middleware` or `repo_visibility_middleware` must
    /// resolve a valid `AuthExtension`, otherwise the `guest_access_guard`
    /// returns 401. A small allowlist (login, refresh, setup status,
    /// /api/v1/system/config, health probes, OCI /v2/ challenge) is always
    /// permitted so users can authenticate and clients can negotiate.
    pub guest_access_enabled: bool,

    /// When true (the default), a WASM plugin may only be installed (via ZIP,
    /// Git, or reload) if it ships a detached Ed25519 signature
    /// (`plugin.wasm.sig`) over its raw WASM bytes that verifies against the
    /// operator-provisioned trusted public key (`plugins_trusted_pubkey`).
    /// This is a fail-closed supply-chain control: with signing required but no
    /// trusted key configured, every install is rejected. Set
    /// `PLUGINS_REQUIRE_SIGNED=false`/`0` to opt out for trusted/first-party
    /// or dev environments. Already-installed plugins loaded at startup are
    /// unaffected — only the install/reload ingress paths are gated.
    pub plugins_require_signed: bool,

    /// Base64-encoded Ed25519 public key (32 raw bytes) used to verify plugin
    /// signatures. `None` when unset. Never exposed in API responses or logs.
    pub plugins_trusted_pubkey: Option<String>,

    /// Peer instance name for mesh identification
    pub peer_instance_name: String,

    /// Public endpoint URL where this instance can be reached by peers
    pub peer_public_endpoint: String,

    /// API key for authenticating peer-to-peer requests
    pub peer_api_key: String,

    /// Dependency-Track API URL for vulnerability management (optional)
    pub dependency_track_url: Option<String>,

    /// Whether the Dependency-Track integration is enabled.
    ///
    /// This is the single source of truth for "is DT wired up?".
    /// Controlled by the `DEPENDENCY_TRACK_ENABLED` env var. When `false`
    /// (the default), no part of the backend will contact Dependency-Track:
    /// the service is not initialized, the periodic health monitor skips
    /// its probe, and the `/api/v1/system/config` endpoint reports it as
    /// disabled so the frontend can render a consistent "disabled" state
    /// instead of mixing "disabled" with "unavailable" messages
    /// (issues #1395 and #1480).
    pub dependency_track_enabled: bool,

    /// OpenTelemetry OTLP endpoint (optional, enables OTel when set).
    pub otel_exporter_otlp_endpoint: Option<String>,

    /// OpenTelemetry service name (default: "artifact-keeper").
    pub otel_service_name: String,

    /// Cron expression (6-field) for storage garbage collection (default: hourly).
    pub gc_schedule: String,

    /// Whether scheduled blob garbage collection is allowed to actually
    /// delete blobs (#1408). Defaults to `false`: blob deletion is the
    /// dangerous part of GC, so the scheduled pass runs in DRY-RUN mode
    /// (logs what it would reclaim, deletes nothing) unless an operator
    /// explicitly opts in with `BLOB_GC_ENABLED=true`. Even when enabled,
    /// the pass is still gated behind the `manifest_blob_refs` readiness
    /// check, so it never deletes while ref coverage is incomplete.
    pub blob_gc_enabled: bool,

    /// How often (in seconds) the lifecycle scheduler checks for due policies.
    pub lifecycle_check_interval_secs: u64,

    /// Threshold (in seconds) before a `scan_results` row stuck in
    /// `status='running'` is considered orphaned by the janitor and
    /// transitioned to `failed`. Default 1800 (30 minutes); raise this above
    /// the slowest expected scan (issue #1015).
    pub stuck_scan_threshold_secs: u64,

    /// How often (in seconds) the stuck-scan janitor sweeps for orphaned
    /// `running` rows. Default 600 (10 minutes).
    pub stuck_scan_check_interval_secs: u64,

    /// Maximum rows the stuck-scan janitor reaps per tick.
    ///
    /// Operators with a large post-outage backlog can tune this up so the
    /// queue drains faster; environments with a small workload can tune
    /// it down so a single tick costs less. Clamped to `[1, 10_000]` at
    /// startup (see [`crate::services::scan_result_service::clamp_stuck_scan_reap_limit`]).
    /// Env var: `STUCK_SCAN_REAP_LIMIT`. Default: 1000. PR #1212 audit M1.
    pub stuck_scan_reap_limit: i64,

    /// Maximum upload size in bytes for artifact uploads.
    /// Defaults to 10 GB (10737418240 bytes). Set to 0 to disable the limit.
    pub max_upload_size_bytes: u64,

    /// When true, the built-in admin account can log in with local credentials
    /// even when SSO providers are configured. Intended as a break-glass
    /// recovery mechanism when SSO is misconfigured.
    pub allow_local_admin_login: bool,

    /// Opt-in strict SSO enforcement (#2018). When true, the verified-admin
    /// break-glass local login (issue #443) is disabled too, so a deployment
    /// that wants "SSO-only, no exceptions" locks out *all* local logins —
    /// including admin — while any SSO provider is enabled. Defaults to
    /// `false`, preserving the historical break-glass behaviour so existing
    /// deployments are unchanged. Env var: `SSO_DISABLE_ADMIN_BREAK_GLASS`.
    pub sso_disable_admin_break_glass: bool,

    /// Port for the unauthenticated Prometheus metrics-only listener.
    ///
    /// When set, a second TCP listener is started on this port serving only
    /// `GET /metrics` with no authentication. Intended for internal Prometheus
    /// scraping in environments where the scraper cannot present credentials.
    /// When absent (default), the secondary listener is not started and metrics
    /// remain accessible only via the authenticated `GET /api/v1/admin/metrics`
    /// endpoint.
    ///
    /// **Security note:** ensure this port is not reachable from untrusted
    /// networks (e.g. restrict via firewall or Kubernetes NetworkPolicy).
    pub metrics_port: Option<u16>,

    /// Maximum number of connections in the PostgreSQL pool.
    /// Defaults to 20. Increase for higher concurrency, decrease for
    /// databases with restricted connection budgets (e.g., shared RDS).
    pub database_max_connections: u32,

    /// Minimum number of idle connections kept in the PostgreSQL pool.
    /// Defaults to 5. Set to 0 to allow the pool to scale down completely.
    pub database_min_connections: u32,

    /// Timeout in seconds for acquiring a connection from the pool before
    /// returning an error. Defaults to 5. Kept short so that callers fail fast
    /// under sustained pool exhaustion instead of piling up; raise for batch
    /// workloads where waiting is preferable to retrying.
    pub database_acquire_timeout_secs: u64,

    /// Maximum number of bcrypt-bound auth operations (login,
    /// password verification, API-token verification) allowed to run
    /// concurrently across the process. Acts as a fast-fail load shed:
    /// when saturated, additional requests receive 503 Service Unavailable
    /// with `Retry-After` instead of queueing on the blocking-task pool
    /// and starving the rest of the API.
    ///
    /// Defaults to `max(8, 4 * num_cpus)`. Set to 0 to disable the limit
    /// (legacy behaviour, not recommended in production).
    pub auth_max_concurrency: usize,

    /// Router-wide in-flight request cap applied as the outermost application
    /// layer (defense-in-depth load-shed). When more than this many requests
    /// are being processed concurrently, excess requests are shed with 503
    /// rather than queueing — this keeps the accept loop responsive even if
    /// some other code path runs an unbounded CPU-bound (e.g. bcrypt /
    /// decompression) operation on a worker thread.
    ///
    /// Must be generous: well above the tokio worker count so it never throttles
    /// legitimate parallel CI auth/upload traffic. Env var:
    /// `GLOBAL_MAX_CONCURRENCY`. Default 512. Set to 0 to disable the layer.
    pub global_max_concurrency: usize,

    /// Router-wide request timeout in seconds applied as the outermost
    /// application layer (defense-in-depth). A request that runs longer than
    /// this is aborted with 503 so a single wedged/CPU-bound request cannot
    /// hold a worker indefinitely.
    ///
    /// Must exceed the slowest legitimate request — large multi-GB artifact
    /// uploads — or they will be killed. Env var: `GLOBAL_REQUEST_TIMEOUT_SECS`.
    /// Default 120. Set to 0 to disable the layer.
    pub global_request_timeout_secs: u64,

    /// Idle timeout in seconds. Connections idle longer than this will be
    /// closed. Defaults to 600 (10 minutes).
    pub database_idle_timeout_secs: u64,

    /// Maximum lifetime in seconds for a pooled connection. Connections
    /// older than this are recycled even if still healthy. Defaults to
    /// 1800 (30 minutes). Useful when the database has a connection
    /// lifetime policy or when running behind a TCP load balancer with an
    /// idle disconnect.
    pub database_max_lifetime_secs: u64,

    /// Master on/off switch for HTTP rate limiting. When `false`, none of
    /// the per-IP / per-user rate-limit middleware layers are installed, so
    /// no request is ever limited (the limiter is bypassed entirely, not
    /// merely set very high). Intended for internal-only / VPN-gated
    /// deployments where the per-IP limiter provides little value but trips
    /// build tools that fan out many small requests (e.g. sbt/Coursier
    /// resolving plugins against the presign limiter). See #1602.
    /// Env var: `RATE_LIMIT_ENABLED` (opt-out). Default: `true` (enabled).
    pub rate_limit_enabled: bool,
    pub rate_limit_auth_per_window: u32,
    pub rate_limit_api_per_window: u32,
    pub rate_limit_search_per_window: u32,
    /// Per-IP requests-per-window cap on endpoints that mint presigned
    /// download URLs. Stricter than the API bucket because the presign
    /// path is O(1) memory per request: an attacker can issue many
    /// concurrent requests from a single host without backend memory
    /// pressure, but each minted URL becomes a separate egress out of
    /// the storage backend the attacker can drive in parallel. See
    /// #1053. Env var: `RATE_LIMIT_PRESIGN_PER_MIN`. Default: 30.
    pub rate_limit_presign_per_window: u32,
    /// Global backstop cap on unauthenticated login attempts per
    /// `rate_limit_window_secs`, shared across ALL `(username, source-IP)`
    /// keys. The login limiter partitions its budget per-`(username, ip)` so
    /// a junk flood against one identity/origin cannot lock out other
    /// accounts; this backstop bounds the total login volume (and therefore
    /// the size of the per-key map) so a username-cycling attacker cannot
    /// exhaust memory via unbounded distinct keys. Sized far above any
    /// legitimate concurrent-login volume so real users never reach it; it
    /// sheds rather than starves. Env var:
    /// `RATE_LIMIT_LOGIN_GLOBAL_PER_WINDOW`. Default: 8192.
    pub rate_limit_login_global_per_window: u32,
    /// Maximum self-password-change attempts per user per
    /// `rate_limit_password_change_window_secs`. Tighter than the global API
    /// bucket because `POST /users/:id/password` verifies the current
    /// password via bcrypt, so an attacker who already holds a victim's JWT
    /// can otherwise grind 100+ password guesses per minute against the
    /// account through this endpoint. See #1026. Env var:
    /// `RATE_LIMIT_PASSWORD_CHANGE_PER_WINDOW`. Default: 5.
    pub rate_limit_password_change_per_window: u32,
    /// Window length for the password-change limiter, in seconds. Decoupled
    /// from `rate_limit_window_secs` (which is typically 60) so the password
    /// bucket can use a longer, lockout-style window (default 15 minutes).
    /// Env var: `RATE_LIMIT_PASSWORD_CHANGE_WINDOW_SECS`. Default: 900.
    pub rate_limit_password_change_window_secs: u64,
    pub rate_limit_window_secs: u64,
    pub rate_limit_exempt_usernames: Vec<String>,
    pub rate_limit_exempt_service_accounts: bool,
    /// Comma-separated list of CIDR ranges whose source IPs bypass rate
    /// limiting. Intended for trusted internal callers (sidecar probes,
    /// service-mesh nodes, in-cluster CI runners). Applies to authed and
    /// unauthed requests alike. See #969.
    /// Env var: `RATE_LIMIT_TRUSTED_CIDRS`. Default: empty.
    /// Example: `10.0.0.0/8,fc00::/7,127.0.0.1/32`.
    pub rate_limit_trusted_cidrs: Vec<crate::api::middleware::rate_limit::CidrRange>,

    /// Comma-separated list of CIDR ranges identifying *trusted reverse
    /// proxies*. The `X-Forwarded-For` header is consulted to resolve the
    /// real client IP for rate-limit keying **only** when the immediate TCP
    /// peer (from `ConnectInfo`) falls within one of these ranges. When empty
    /// (the default), `X-Forwarded-For` is never trusted and keying always
    /// tracks the real TCP peer, so a spoofed/rotating `XFF` from an untrusted
    /// client cannot steer or multiply its rate-limit budget.
    ///
    /// This is distinct from `rate_limit_trusted_cidrs`, which exempts IPs
    /// from rate limiting entirely; this field only governs whether `XFF` is
    /// believed for client-IP resolution.
    ///
    /// Env var: `RATE_LIMIT_TRUSTED_PROXY_CIDRS`. Default: empty.
    /// Example (single reverse proxy on loopback): `127.0.0.0/8`.
    pub rate_limit_trusted_proxy_cidrs: Vec<crate::api::middleware::rate_limit::CidrRange>,

    /// Number of consecutive failed login attempts before a local account is
    /// locked. Set to 0 to disable account lockout. Default: 5.
    pub account_lockout_threshold: u32,

    /// Duration in minutes that a locked account remains locked before the
    /// user can try again. Default: 30.
    pub account_lockout_duration_minutes: i64,

    /// When true, newly uploaded artifacts are held in quarantine until
    /// security scanning completes or the hold period expires. Repositories
    /// can override this via repository_config keys. Default: false.
    pub quarantine_enabled: bool,

    /// Default quarantine hold period in minutes. Repositories can override
    /// this via repository_config keys. Default: 60.
    pub quarantine_duration_minutes: i64,

    /// Number of previous passwords to remember per user. When a user changes
    /// their password, the new password is checked against the last N hashes
    /// and rejected if it matches any of them. Set to 0 to disable password
    /// history checking. Default: 0 (disabled).
    pub password_history_count: u32,

    /// Number of days after which a local user's password expires and must
    /// be changed. Set to 0 to disable password expiration. Default: 0.
    pub password_expiry_days: u32,

    /// Comma-separated list of day thresholds at which expiry warning emails
    /// are sent to local users. Only effective when `password_expiry_days` > 0
    /// and SMTP is configured. Default: "14,7,1".
    pub password_expiry_warning_days: Vec<u32>,

    /// How often (in seconds) the password expiry notification job runs.
    /// Default: 3600 (1 hour).
    pub password_expiry_check_interval_secs: u64,

    // -- Password policy (local users) --
    /// Minimum password length (default: 8).
    pub password_min_length: usize,

    /// Maximum password length (default: 128).
    pub password_max_length: usize,

    /// Require at least one uppercase letter (default: false).
    pub password_require_uppercase: bool,

    /// Require at least one lowercase letter (default: false).
    pub password_require_lowercase: bool,

    /// Require at least one digit (default: false).
    pub password_require_digit: bool,

    /// Require at least one special character (default: false).
    pub password_require_special: bool,

    /// Minimum zxcvbn strength score (0 = disabled, 1-4 = increasingly strict).
    /// When set to a value > 0, passwords are evaluated by the zxcvbn estimator
    /// and must meet or exceed the given score.
    pub password_min_strength: u8,

    /// When true, artifact downloads served from storage backends that support
    /// presigned URLs (S3, GCS, Azure) will return a 302 redirect to a
    /// presigned URL instead of proxying the bytes through the backend. This
    /// reduces bandwidth and CPU usage on the backend server. Default: false.
    pub presigned_downloads_enabled: bool,

    /// Expiry in seconds for presigned download URLs. Only used when
    /// `presigned_downloads_enabled` is true. Default: 300 (5 minutes).
    pub presigned_download_expiry_secs: u64,

    // -- Proxy pull-through cache cross-replica single-flight (#1609) --
    /// Enable the cross-replica single-flight coordinator for pull-through cache
    /// fills: a PostgreSQL advisory lock keyed on the cache key so exactly ONE
    /// replica cold-fetches a given object cluster-wide instead of up to N (which
    /// flaps the storage ETag under readers → `Stale file handle` / truncated
    /// `.sha1`, #1606). Opt-in HA feature (like `presigned_downloads_enabled`):
    /// default `false` keeps the unchanged per-process single-flight for
    /// single-replica installs. Multi-replica deployments should set
    /// `PROXY_SINGLEFLIGHT_ADVISORY_LOCKS_ENABLED=true`.
    pub proxy_singleflight_advisory_locks_enabled: bool,

    /// Follower poll cadence (milliseconds) while the cluster leader fetches,
    /// when `proxy_singleflight_advisory_locks_enabled` is true. Default: 200.
    pub proxy_singleflight_lock_poll_interval_ms: u64,

    /// Upper bound (seconds) a follower waits for the leader's commit before
    /// falling back to its own bounded fetch, when advisory locks are enabled.
    /// Default: 65.
    pub proxy_singleflight_lock_wait_timeout_secs: u64,

    // -- SMTP (optional, notifications are disabled when smtp_host is None) --
    /// SMTP server hostname. When absent, email delivery is disabled and the
    /// SMTP service operates as a no-op.
    pub smtp_host: Option<String>,

    /// SMTP server port (default: 587).
    pub smtp_port: u16,

    /// SMTP username for authentication (optional).
    pub smtp_username: Option<String>,

    /// SMTP password for authentication (optional).
    pub smtp_password: Option<String>,

    /// Sender address used in the From header (default: "noreply@artifact-keeper.local").
    pub smtp_from_address: String,

    /// TLS mode for the SMTP connection: "starttls" (default), "tls", or "none".
    pub smtp_tls_mode: String,
}

redacted_debug!(Config {
    redact database_url,
    show bind_address,
    show log_level,
    show storage_backend,
    show storage_path,
    show s3_bucket,
    show gcs_bucket,
    show s3_region,
    show s3_endpoint,
    redact jwt_secret,
    show jwt_expiration_secs,
    show jwt_access_token_expiry_minutes,
    show jwt_refresh_token_expiry_days,
    show oidc_issuer,
    show oidc_client_id,
    redact_option oidc_client_secret,
    show ldap_url,
    show ldap_base_dn,
    show trivy_url,
    show trivy_adapter_url,
    show scan_token_ttl_seconds,
    show openscap_url,
    show openscap_profile,
    show opensearch_url,
    show opensearch_username,
    redact_option opensearch_password,
    show opensearch_allow_invalid_certs,
    show scan_workspace_path,
    show demo_mode,
    show guest_access_enabled,
    show plugins_require_signed,
    redact_option plugins_trusted_pubkey,
    show peer_instance_name,
    show peer_public_endpoint,
    redact peer_api_key,
    show dependency_track_url,
    show dependency_track_enabled,
    show otel_exporter_otlp_endpoint,
    show otel_service_name,
    show gc_schedule,
    show blob_gc_enabled,
    show lifecycle_check_interval_secs,
    show stuck_scan_threshold_secs,
    show stuck_scan_check_interval_secs,
    show stuck_scan_reap_limit,
    show max_upload_size_bytes,
    show allow_local_admin_login,
    show sso_disable_admin_break_glass,
    show metrics_port,
    show database_max_connections,
    show database_min_connections,
    show database_acquire_timeout_secs,
    show database_idle_timeout_secs,
    show database_max_lifetime_secs,
    show auth_max_concurrency,
    show global_max_concurrency,
    show global_request_timeout_secs,
    show rate_limit_enabled,
    show rate_limit_auth_per_window,
    show rate_limit_api_per_window,
    show rate_limit_search_per_window,
    show rate_limit_login_global_per_window,
    show rate_limit_password_change_per_window,
    show rate_limit_password_change_window_secs,
    show rate_limit_window_secs,
    show rate_limit_exempt_usernames,
    show rate_limit_exempt_service_accounts,
    show account_lockout_threshold,
    show account_lockout_duration_minutes,
    show quarantine_enabled,
    show quarantine_duration_minutes,
    show password_history_count,
    show password_expiry_days,
    show password_expiry_warning_days,
    show password_expiry_check_interval_secs,
    show password_min_length,
    show password_max_length,
    show password_require_uppercase,
    show password_require_lowercase,
    show password_require_digit,
    show password_require_special,
    show password_min_strength,
    show presigned_downloads_enabled,
    show presigned_download_expiry_secs,
    show proxy_singleflight_advisory_locks_enabled,
    show proxy_singleflight_lock_poll_interval_ms,
    show proxy_singleflight_lock_wait_timeout_secs,
    show smtp_host,
    show smtp_port,
    show smtp_username,
    redact_option smtp_password,
    show smtp_from_address,
    show smtp_tls_mode,
});

impl Default for Config {
    fn default() -> Self {
        Self {
            database_url: String::new(),
            bind_address: "0.0.0.0:8080".into(),
            log_level: "info".into(),
            storage_backend: "filesystem".into(),
            storage_path: "/tmp/artifact-keeper-test".into(),
            s3_bucket: None,
            gcs_bucket: None,
            s3_region: None,
            s3_endpoint: None,
            jwt_secret: "test-secret-key-that-is-at-least-32-bytes".into(),
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
            scan_token_ttl_seconds: 300,
            openscap_url: None,
            openscap_profile: "xccdf_org.ssgproject.content_profile_standard".into(),
            opensearch_url: None,
            opensearch_username: None,
            opensearch_password: None,
            opensearch_allow_invalid_certs: false,
            scan_workspace_path: "/tmp/scan-workspace".into(),
            demo_mode: false,
            guest_access_enabled: true,
            plugins_require_signed: true,
            plugins_trusted_pubkey: None,
            peer_instance_name: "test-instance".into(),
            peer_public_endpoint: "http://localhost:8080".into(),
            peer_api_key: "test-peer-api-key".into(),
            dependency_track_url: None,
            dependency_track_enabled: false,
            otel_exporter_otlp_endpoint: None,
            otel_service_name: "artifact-keeper".into(),
            gc_schedule: "0 0 * * * *".into(),
            blob_gc_enabled: false,
            lifecycle_check_interval_secs: 60,
            stuck_scan_threshold_secs: 1800,
            stuck_scan_check_interval_secs: 600,
            stuck_scan_reap_limit: 1000,
            max_upload_size_bytes: 10_737_418_240,
            allow_local_admin_login: false,
            sso_disable_admin_break_glass: false,
            metrics_port: None,
            database_max_connections: 50,
            database_min_connections: 5,
            database_acquire_timeout_secs: 5,
            database_idle_timeout_secs: 600,
            database_max_lifetime_secs: 1800,
            auth_max_concurrency: default_auth_max_concurrency(),
            global_max_concurrency: 512,
            global_request_timeout_secs: 120,
            rate_limit_enabled: true,
            rate_limit_auth_per_window: 120,
            rate_limit_api_per_window: 10000,
            rate_limit_search_per_window: 300,
            rate_limit_presign_per_window: 30,
            rate_limit_login_global_per_window: 8192,
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
            password_expiry_warning_days: vec![1, 7, 14],
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
            smtp_from_address: "noreply@artifact-keeper.local".into(),
            smtp_tls_mode: "starttls".into(),
        }
    }
}

impl Config {
    /// Return a `Config` with sensible defaults for unit tests. Equivalent to
    /// `Config::default()` today, but kept as a named constructor so tests read
    /// clearly and any future test-specific tweaks live in one place.
    #[cfg(test)]
    pub fn test_config() -> Self {
        Self::default()
    }

    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self> {
        let config = Self {
            database_url: env::var("DATABASE_URL")
                .map_err(|_| AppError::Config("DATABASE_URL not set".into()))?,
            bind_address: env::var("BIND_ADDRESS").unwrap_or_else(|_| "0.0.0.0:8080".into()),
            log_level: env::var("LOG_LEVEL").unwrap_or_else(|_| "info".into()),
            storage_backend: env::var("STORAGE_BACKEND").unwrap_or_else(|_| "filesystem".into()),
            storage_path: env::var("STORAGE_PATH").unwrap_or_else(|_| {
                if cfg!(windows) {
                    r"C:\ProgramData\ArtifactKeeper\artifacts".into()
                } else {
                    "/var/lib/artifact-keeper/artifacts".into()
                }
            }),
            s3_bucket: env::var("S3_BUCKET").ok(),
            gcs_bucket: env::var("GCS_BUCKET").ok(),
            s3_region: env::var("S3_REGION").ok(),
            s3_endpoint: env::var("S3_ENDPOINT").ok(),
            jwt_secret: env::var("JWT_SECRET")
                .map_err(|_| AppError::Config("JWT_SECRET not set".into()))?,
            jwt_expiration_secs: env_parse("JWT_EXPIRATION_SECS", 86400),
            jwt_access_token_expiry_minutes: env_parse("JWT_ACCESS_TOKEN_EXPIRY_MINUTES", 30),
            jwt_refresh_token_expiry_days: env_parse("JWT_REFRESH_TOKEN_EXPIRY_DAYS", 7),
            oidc_issuer: env::var("OIDC_ISSUER").ok(),
            oidc_client_id: env::var("OIDC_CLIENT_ID").ok(),
            oidc_client_secret: env::var("OIDC_CLIENT_SECRET").ok(),
            ldap_url: env::var("LDAP_URL").ok(),
            ldap_base_dn: env::var("LDAP_BASE_DN").ok(),
            trivy_url: env::var("TRIVY_URL").ok(),
            // Treat an empty value as unset: deployment templates commonly
            // render `TRIVY_ADAPTER_URL=` (present-but-empty) when the feature
            // is off, and registering the image scanner with an empty URL would
            // make every image scan fail closed instead of not running at all.
            trivy_adapter_url: env::var("TRIVY_ADAPTER_URL").ok().filter(|s| !s.is_empty()),
            scan_token_ttl_seconds: env_parse("SCAN_TOKEN_TTL_SECONDS", 300),
            openscap_url: env::var("OPENSCAP_URL").ok(),
            openscap_profile: env::var("OPENSCAP_PROFILE")
                .unwrap_or_else(|_| "xccdf_org.ssgproject.content_profile_standard".into()),
            opensearch_url: env::var("OPENSEARCH_URL").ok(),
            opensearch_username: env::var("OPENSEARCH_USERNAME").ok(),
            opensearch_password: env::var("OPENSEARCH_PASSWORD").ok(),
            opensearch_allow_invalid_certs: matches!(
                env::var("OPENSEARCH_ALLOW_INVALID_CERTS").as_deref(),
                Ok("true" | "1")
            ),
            scan_workspace_path: env::var("SCAN_WORKSPACE_PATH").unwrap_or_else(|_| {
                if cfg!(windows) {
                    r"C:\ProgramData\ArtifactKeeper\scan-workspace".into()
                } else {
                    "/scan-workspace".into()
                }
            }),
            demo_mode: matches!(env::var("DEMO_MODE").as_deref(), Ok("true" | "1")),
            // Default to true for zero-impact upgrades; only "false"/"0" disables guests.
            // Any other value (including unset, garbage, or empty) keeps guests enabled.
            guest_access_enabled: !matches!(
                env::var("AK_GUEST_ACCESS_ENABLED").as_deref(),
                Ok("false" | "0")
            ),
            // Fail-closed supply-chain control: defaults to true so an
            // unsigned WASM plugin cannot be installed out of the box. Only an
            // explicit, recognized negative ("false"/"0", case/whitespace-
            // insensitive) opts out; unset/empty/garbage keeps it required.
            plugins_require_signed: parse_opt_out_flag(
                env::var("PLUGINS_REQUIRE_SIGNED").ok().as_deref(),
            ),
            plugins_trusted_pubkey: env::var("PLUGINS_TRUSTED_PUBKEY")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
            peer_instance_name: env::var("PEER_INSTANCE_NAME")
                .unwrap_or_else(|_| "artifact-keeper-local".into()),
            peer_public_endpoint: env::var("PEER_PUBLIC_ENDPOINT")
                .unwrap_or_else(|_| "http://localhost:8080".into()),
            peer_api_key: env::var("PEER_API_KEY").unwrap_or_else(|_| {
                let key = format!("{:032x}", rand::random::<u128>());
                tracing::warn!(
                    "PEER_API_KEY not set, generated random key. \
                     Set PEER_API_KEY in your environment for stable peer authentication."
                );
                key
            }),
            dependency_track_url: env::var("DEPENDENCY_TRACK_URL").ok(),
            // Single source of truth for "DT is wired in". Defaults to false
            // when unset, so DT integration must be explicitly opted into.
            // Accepts "true" / "1" (case-insensitive); anything else (empty,
            // garbage, unset) keeps DT disabled.
            dependency_track_enabled: env::var("DEPENDENCY_TRACK_ENABLED")
                .map(|v| {
                    let v = v.trim().to_lowercase();
                    v == "true" || v == "1"
                })
                .unwrap_or(false),
            otel_exporter_otlp_endpoint: env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok(),
            otel_service_name: env::var("OTEL_SERVICE_NAME")
                .unwrap_or_else(|_| "artifact-keeper".into()),
            gc_schedule: env::var("GC_SCHEDULE").unwrap_or_else(|_| "0 0 * * * *".into()),
            // Blob deletion is the dangerous half of GC. Defaults to false
            // so the scheduled pass dry-runs unless an operator opts in.
            // Accepts "true" / "1" (case-insensitive); anything else
            // (empty, garbage, unset) keeps live blob deletion disabled.
            blob_gc_enabled: parse_opt_in_flag(env::var("BLOB_GC_ENABLED").ok().as_deref()),
            lifecycle_check_interval_secs: env_parse("LIFECYCLE_CHECK_INTERVAL_SECS", 60),
            stuck_scan_threshold_secs: clamp_stuck_scan_threshold(env_parse(
                "STUCK_SCAN_THRESHOLD_SECS",
                1800,
            )),
            stuck_scan_check_interval_secs: clamp_stuck_scan_interval(env_parse(
                "STUCK_SCAN_CHECK_INTERVAL_SECS",
                600,
            )),
            stuck_scan_reap_limit:
                crate::services::scan_result_service::clamp_stuck_scan_reap_limit(env_parse(
                    "STUCK_SCAN_REAP_LIMIT",
                    1000,
                )),
            max_upload_size_bytes: env_parse("MAX_UPLOAD_SIZE", 10_737_418_240_u64),
            allow_local_admin_login: matches!(
                env::var("ALLOW_LOCAL_ADMIN_LOGIN").as_deref(),
                Ok("true" | "1")
            ),
            sso_disable_admin_break_glass: matches!(
                env::var("SSO_DISABLE_ADMIN_BREAK_GLASS").as_deref(),
                Ok("true" | "1")
            ),
            metrics_port: match env::var("METRICS_PORT") {
                Ok(val) => match val.parse::<u16>() {
                    Ok(port) => Some(port),
                    Err(_) => {
                        tracing::warn!(
                            value = %val,
                            "METRICS_PORT is set but could not be parsed as a valid port \
                             number; unauthenticated metrics listener is disabled"
                        );
                        None
                    }
                },
                Err(_) => None,
            },
            database_max_connections: env_parse("DATABASE_MAX_CONNECTIONS", 50),
            database_min_connections: env_parse("DATABASE_MIN_CONNECTIONS", 5),
            database_acquire_timeout_secs: env_parse("DATABASE_ACQUIRE_TIMEOUT_SECS", 5),
            database_idle_timeout_secs: env_parse("DATABASE_IDLE_TIMEOUT_SECS", 600),
            database_max_lifetime_secs: env_parse("DATABASE_MAX_LIFETIME_SECS", 1800),
            auth_max_concurrency: env_parse("AUTH_MAX_CONCURRENCY", default_auth_max_concurrency()),
            global_max_concurrency: env_parse("GLOBAL_MAX_CONCURRENCY", 512_usize),
            global_request_timeout_secs: env_parse("GLOBAL_REQUEST_TIMEOUT_SECS", 120_u64),
            rate_limit_enabled: parse_opt_out_flag(env::var("RATE_LIMIT_ENABLED").ok().as_deref()),
            rate_limit_auth_per_window: env_parse("RATE_LIMIT_AUTH_PER_MIN", 120),
            rate_limit_api_per_window: env_parse("RATE_LIMIT_API_PER_MIN", 10000),
            rate_limit_search_per_window: env_parse("RATE_LIMIT_SEARCH_PER_MIN", 300),
            rate_limit_presign_per_window: env_parse("RATE_LIMIT_PRESIGN_PER_MIN", 30),
            rate_limit_login_global_per_window: env_parse(
                "RATE_LIMIT_LOGIN_GLOBAL_PER_WINDOW",
                8192,
            ),
            rate_limit_password_change_per_window: env_parse(
                "RATE_LIMIT_PASSWORD_CHANGE_PER_WINDOW",
                5,
            ),
            rate_limit_password_change_window_secs: env_parse(
                "RATE_LIMIT_PASSWORD_CHANGE_WINDOW_SECS",
                900,
            ),
            rate_limit_window_secs: env_parse("RATE_LIMIT_WINDOW_SECS", 60),
            rate_limit_exempt_usernames: env::var("RATE_LIMIT_EXEMPT_USERNAMES")
                .ok()
                .map(|s| {
                    s.split(',')
                        .map(|u| u.trim().to_string())
                        .filter(|u| !u.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            rate_limit_exempt_service_accounts: matches!(
                env::var("RATE_LIMIT_EXEMPT_SERVICE_ACCOUNTS").as_deref(),
                Ok("true" | "1")
            ),
            rate_limit_trusted_cidrs: parse_cidr_list_env("RATE_LIMIT_TRUSTED_CIDRS"),
            rate_limit_trusted_proxy_cidrs: parse_cidr_list_env("RATE_LIMIT_TRUSTED_PROXY_CIDRS"),
            account_lockout_threshold: env_parse("ACCOUNT_LOCKOUT_THRESHOLD", 5),
            account_lockout_duration_minutes: env_parse("ACCOUNT_LOCKOUT_DURATION_MINUTES", 30),
            quarantine_enabled: matches!(
                env::var("QUARANTINE_ENABLED").as_deref(),
                Ok("true" | "1")
            ),
            quarantine_duration_minutes: env_parse("QUARANTINE_DURATION_MINUTES", 60).max(1),
            password_history_count: env_parse::<u32>("PASSWORD_HISTORY_COUNT", 0).min(24),
            password_expiry_days: env_parse("PASSWORD_EXPIRY_DAYS", 0).min(3650),
            password_expiry_warning_days: {
                let raw =
                    env::var("PASSWORD_EXPIRY_WARNING_DAYS").unwrap_or_else(|_| "14,7,1".into());
                let mut days: Vec<u32> = raw
                    .split(',')
                    .filter_map(|s| s.trim().parse::<u32>().ok())
                    .filter(|&d| d > 0)
                    .collect();
                days.sort_unstable();
                days.dedup();
                days
            },
            password_expiry_check_interval_secs: env_parse(
                "PASSWORD_EXPIRY_CHECK_INTERVAL_SECS",
                3600,
            ),
            password_min_length: env_parse("PASSWORD_MIN_LENGTH", 8),
            password_max_length: env_parse("PASSWORD_MAX_LENGTH", 128),
            password_require_uppercase: matches!(
                env::var("PASSWORD_REQUIRE_UPPERCASE").as_deref(),
                Ok("true" | "1")
            ),
            password_require_lowercase: matches!(
                env::var("PASSWORD_REQUIRE_LOWERCASE").as_deref(),
                Ok("true" | "1")
            ),
            password_require_digit: matches!(
                env::var("PASSWORD_REQUIRE_DIGIT").as_deref(),
                Ok("true" | "1")
            ),
            password_require_special: matches!(
                env::var("PASSWORD_REQUIRE_SPECIAL").as_deref(),
                Ok("true" | "1")
            ),
            password_min_strength: {
                let raw = env_parse::<u8>("PASSWORD_MIN_STRENGTH", 0);
                raw.min(4)
            },
            presigned_downloads_enabled: matches!(
                env::var("PRESIGNED_DOWNLOADS_ENABLED").as_deref(),
                Ok("true" | "1")
            ),
            presigned_download_expiry_secs: env_parse("PRESIGNED_DOWNLOAD_EXPIRY_SECS", 300),
            proxy_singleflight_advisory_locks_enabled: matches!(
                env::var("PROXY_SINGLEFLIGHT_ADVISORY_LOCKS_ENABLED").as_deref(),
                Ok("true" | "1")
            ),
            proxy_singleflight_lock_poll_interval_ms: env_parse(
                "PROXY_SINGLEFLIGHT_LOCK_POLL_INTERVAL_MS",
                200,
            ),
            proxy_singleflight_lock_wait_timeout_secs: env_parse(
                "PROXY_SINGLEFLIGHT_LOCK_WAIT_TIMEOUT_SECS",
                65,
            ),
            smtp_host: env::var("SMTP_HOST").ok().filter(|s| !s.is_empty()),
            smtp_port: env_parse("SMTP_PORT", 587),
            smtp_username: env::var("SMTP_USERNAME").ok().filter(|s| !s.is_empty()),
            smtp_password: env::var("SMTP_PASSWORD").ok().filter(|s| !s.is_empty()),
            smtp_from_address: env::var("SMTP_FROM_ADDRESS")
                .unwrap_or_else(|_| "noreply@artifact-keeper.local".into()),
            smtp_tls_mode: {
                let mode = env::var("SMTP_TLS_MODE")
                    .unwrap_or_else(|_| "starttls".into())
                    .to_lowercase();
                match mode.as_str() {
                    "starttls" | "tls" | "none" => mode,
                    _ => {
                        tracing::warn!(
                            value = %mode,
                            "SMTP_TLS_MODE has an unrecognized value, falling back to \"starttls\""
                        );
                        "starttls".into()
                    }
                }
            },
        };

        config.validate_jwt_secret()?;
        config.validate_storage_paths()?;

        Ok(config)
    }

    /// Validate that JWT_SECRET meets minimum security requirements.
    ///
    /// A weak, low-entropy, or placeholder signing secret makes every issued
    /// token forgeable, so it is rejected as a hard error in *every* environment
    /// — the process refuses to start rather than serve with a guessable key.
    /// There is intentionally no `ENVIRONMENT`-gated relaxation: dev and test
    /// must use a strong secret too (or construct `Config` directly, which skips
    /// this `from_env`-only check). Detection lives in the pure, unit-testable
    /// [`jwt_secret_strength_error`] helper.
    fn validate_jwt_secret(&self) -> Result<()> {
        if let Some(reason) = jwt_secret_strength_error(&self.jwt_secret) {
            return Err(AppError::Config(format!(
                "JWT_SECRET is unsuitable: {reason} \
                 Generate a secure random secret (e.g. `openssl rand -base64 48`)."
            )));
        }
        Ok(())
    }

    /// Validate that the filesystem storage paths are absolute.
    ///
    /// The `filesystem` backend uses `storage_path` (and the scanner uses
    /// `scan_workspace_path`) as a base directory that every blob/key is joined
    /// onto. A relative value resolves against the process working directory at
    /// runtime, so artifacts and scan workspaces silently land somewhere other
    /// than the intended location depending on where the process was launched.
    /// Reject such an operator misconfiguration at startup rather than serve
    /// from an unintended directory. Object stores (`s3`/`gcs`) treat
    /// `storage_path` as an object-key prefix that may be empty or relative, so
    /// the check applies only to the `filesystem` backend. This is a
    /// `from_env`-only check (like [`validate_jwt_secret`]); constructing
    /// `Config` directly skips it. Detection lives in the pure, unit-testable
    /// [`storage_path_error`] helper.
    fn validate_storage_paths(&self) -> Result<()> {
        if let Some(message) = storage_path_error(
            &self.storage_backend,
            &self.storage_path,
            &self.scan_workspace_path,
        ) {
            return Err(AppError::Config(message));
        }
        Ok(())
    }
}

/// Known throwaway / placeholder JWT secrets that must never reach production.
/// Kept lowercase; comparison is case-insensitive in `jwt_secret_warnings`.
const KNOWN_PLACEHOLDERS: &[&str] = &[
    "change-me-in-production-please",
    "change-this-in-production-use-at-least-32-bytes",
    "change-me",
    "changeme",
    "secret",
    "jwt-secret",
    "jwt_secret",
    "my-secret",
    "mysecret",
    // NB: well-known doc-example secrets (e.g. the jwt.io sample) are
    // intentionally NOT listed here as literals — the low-entropy heuristic
    // below already flags them, and listing them trips secret scanners.
    "supersecret",
    "super-secret",
    "test-secret",
    "testsecret",
    "dev-secret",
    "development",
    "password",
    "insecure",
    "todo",
    "placeholder",
];

/// Weak/guessable fragments that must never appear *anywhere inside* a signing
/// secret. Unlike [`KNOWN_PLACEHOLDERS`] (which match the whole value) these are
/// tested as case-insensitive substrings, so a long-enough secret that merely
/// embeds one of them — e.g. a CI/test value built from these words — is still
/// rejected. Kept lowercase; the caller lowercases the secret before matching.
const WEAK_SUBSTRINGS: &[&str] = &[
    "change-me",
    "change-this",
    "placeholder",
    "redteam",
    "test-secret",
    "secret-key",
    "your-secret",
    "your_jwt",
    "example",
    "insecure",
    "default",
];

/// A specific weakness detected in a JWT secret. Pure data so the detection
/// logic is unit-testable without touching the environment or a logger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JwtSecretWarning {
    /// Fewer than 32 characters.
    TooShort,
    /// Matches a well-known placeholder/throwaway value.
    KnownPlaceholder,
    /// Low entropy: too few distinct characters or an obvious repeat/sequence.
    LowEntropy,
}

impl JwtSecretWarning {
    fn message(self) -> &'static str {
        match self {
            JwtSecretWarning::TooShort => "it is shorter than 32 characters.",
            JwtSecretWarning::KnownPlaceholder => "it is a known placeholder/default value.",
            JwtSecretWarning::LowEntropy => {
                "it has low entropy (too few distinct characters or an obvious pattern)."
            }
        }
    }
}

/// Pure secret-strength check. Returns the list of weaknesses found, in a
/// stable order, or an empty vec for a strong secret. Shared by production
/// (hard-fail) and non-production (warn-only) paths so behavior matches.
pub(crate) fn jwt_secret_warnings(secret: &str) -> Vec<JwtSecretWarning> {
    let mut warnings = Vec::new();

    if secret.len() < 32 {
        warnings.push(JwtSecretWarning::TooShort);
    }

    let lower = secret.to_lowercase();
    if KNOWN_PLACEHOLDERS.contains(&lower.as_str())
        || WEAK_SUBSTRINGS.iter().any(|frag| lower.contains(frag))
    {
        warnings.push(JwtSecretWarning::KnownPlaceholder);
    }

    if is_low_entropy(secret) {
        warnings.push(JwtSecretWarning::LowEntropy);
    }

    warnings
}

/// Pure secret-strength gate. Returns `Some(reason)` describing the first
/// weakness found in `secret`, or `None` if the secret is strong enough to
/// sign tokens with. Thin wrapper over [`jwt_secret_warnings`] used by the
/// startup `from_env` check so callers get a single, ready-to-surface message.
pub(crate) fn jwt_secret_strength_error(secret: &str) -> Option<&'static str> {
    jwt_secret_warnings(secret).first().map(|w| w.message())
}

/// Pure filesystem-storage path gate. Returns `Some(message)` describing the
/// first offending path (naming the env var and value), or `None` if the paths
/// are acceptable for the selected backend.
///
/// Only the `filesystem` backend uses `storage_path`/`scan_workspace_path` as
/// local base directories that keys are joined onto, so a relative value there
/// resolves against the process working directory at runtime. Object stores
/// (`s3`/`gcs`) treat `storage_path` as an object-key prefix that may be empty
/// or relative, so the check is skipped for them — gating only when the backend
/// is `filesystem`. Used by the startup `from_env` check so the caller gets a
/// single, ready-to-surface message; `Path::is_absolute` keeps the rule correct
/// on the running platform.
pub(crate) fn storage_path_error(
    storage_backend: &str,
    storage_path: &str,
    scan_workspace_path: &str,
) -> Option<String> {
    // Only the filesystem backend treats these as local base directories; this
    // mirrors the exact backend-selection match in StorageService.
    if storage_backend != "filesystem" {
        return None;
    }

    for (var, value) in [
        ("STORAGE_PATH", storage_path),
        ("SCAN_WORKSPACE_PATH", scan_workspace_path),
    ] {
        if !Path::new(value).is_absolute() {
            return Some(format!(
                "{var} must be an absolute path when STORAGE_BACKEND=filesystem, \
                 but got `{value}`. A relative path resolves against the process \
                 working directory at runtime, so artifacts would be stored in an \
                 unintended location; set it to an absolute path \
                 (e.g. /var/lib/artifact-keeper/artifacts)."
            ));
        }
    }

    None
}

/// Heuristic low-entropy detector for JWT secrets.
///
/// Flags secrets that are clearly low-entropy regardless of length: fewer than
/// 16 distinct characters, a single repeated character, or an obvious
/// monotonic character sequence (e.g. "abcdefgh...", "12345678..."). It is
/// intentionally conservative — a genuinely random secret of reasonable length
/// will comfortably clear these bars and produce no warning.
fn is_low_entropy(secret: &str) -> bool {
    if secret.is_empty() {
        return true;
    }

    let chars: Vec<char> = secret.chars().collect();

    // Distinct-character count: a strong random secret of 32+ bytes will have
    // many distinct characters; fewer than 16 is suspiciously low.
    let distinct = chars.iter().collect::<std::collections::HashSet<_>>().len();
    if distinct < 16 {
        return true;
    }

    // Obvious monotonic run over the whole string (ascending or descending by 1),
    // e.g. the lowercase alphabet immediately followed by the ten digits.
    let is_run = |step: i32| {
        chars
            .windows(2)
            .all(|w| (w[1] as i32 - w[0] as i32) == step)
    };
    if chars.len() >= 2 && (is_run(1) || is_run(-1)) {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Environment variable tests must be serialized because env is global state.
    // We use a mutex to prevent parallel test interference.
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    /// Restore an env var to a previously captured value (or remove it if it
    /// was unset), so env-mutating tests do not leak state to other tests.
    fn restore_env(key: &str, saved: Option<String>) {
        match saved {
            Some(v) => env::set_var(key, v),
            None => env::remove_var(key),
        }
    }

    // -----------------------------------------------------------------------
    // parse_opt_in_flag (pure; blob GC opt-in, #1408)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_opt_in_flag_truth_table() {
        // Affirmatives (case-insensitive, trimmed) enable.
        assert!(parse_opt_in_flag(Some("true")));
        assert!(parse_opt_in_flag(Some("TRUE")));
        assert!(parse_opt_in_flag(Some("  True  ")));
        assert!(parse_opt_in_flag(Some("1")));
        // Everything else — including unset — stays off. Safety-critical:
        // blob deletion must never enable by accident.
        assert!(!parse_opt_in_flag(None));
        assert!(!parse_opt_in_flag(Some("")));
        assert!(!parse_opt_in_flag(Some("false")));
        assert!(!parse_opt_in_flag(Some("0")));
        assert!(!parse_opt_in_flag(Some("yes")));
        assert!(!parse_opt_in_flag(Some("on")));
        assert!(!parse_opt_in_flag(Some("2")));
        assert!(!parse_opt_in_flag(Some("garbage")));
    }

    // -----------------------------------------------------------------------
    // parse_opt_out_flag (pure; RATE_LIMIT_ENABLED opt-out, #1602)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_opt_out_flag_truth_table() {
        // Default ON: unset, empty, or any unrecognized value stays enabled.
        assert!(parse_opt_out_flag(None));
        assert!(parse_opt_out_flag(Some("")));
        assert!(parse_opt_out_flag(Some("true")));
        assert!(parse_opt_out_flag(Some("1")));
        assert!(parse_opt_out_flag(Some("yes")));
        assert!(parse_opt_out_flag(Some("garbage")));
        // Only explicit, recognized negatives (case/whitespace-insensitive)
        // turn it off.
        assert!(!parse_opt_out_flag(Some("false")));
        assert!(!parse_opt_out_flag(Some("FALSE")));
        assert!(!parse_opt_out_flag(Some("  False  ")));
        assert!(!parse_opt_out_flag(Some("0")));
    }

    #[test]
    fn test_config_rate_limit_enabled_by_default() {
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::remove_var("RATE_LIMIT_ENABLED");
        let config = Config::from_env().expect("config should load");
        assert!(
            config.rate_limit_enabled,
            "rate limiting must be ON by default (#1602)"
        );
    }

    #[test]
    fn test_config_rate_limit_disabled_via_env() {
        let _guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::set_var("RATE_LIMIT_ENABLED", "false");
        let config = Config::from_env().expect("config should load");
        env::remove_var("RATE_LIMIT_ENABLED");
        assert!(
            !config.rate_limit_enabled,
            "RATE_LIMIT_ENABLED=false must disable rate limiting"
        );
    }

    #[test]
    fn test_config_blob_gc_disabled_by_default() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_flag = env::var("BLOB_GC_ENABLED").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::remove_var("BLOB_GC_ENABLED");

        let config = Config::from_env().unwrap();
        assert!(
            !config.blob_gc_enabled,
            "blob GC must default to disabled (dry-run) when BLOB_GC_ENABLED is unset"
        );

        env::set_var("BLOB_GC_ENABLED", "true");
        let config = Config::from_env().unwrap();
        assert!(
            config.blob_gc_enabled,
            "BLOB_GC_ENABLED=true must opt into live blob deletion"
        );

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        if let Some(v) = saved_flag {
            env::set_var("BLOB_GC_ENABLED", v);
        } else {
            env::remove_var("BLOB_GC_ENABLED");
        }
    }

    // -----------------------------------------------------------------------
    // Default / test_config
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_produces_valid_config() {
        let config = Config::default();
        assert_eq!(config.bind_address, "0.0.0.0:8080");
        assert_eq!(config.storage_backend, "filesystem");
        assert_eq!(config.jwt_expiration_secs, 86400);
        assert_eq!(config.jwt_access_token_expiry_minutes, 30);
        assert_eq!(config.jwt_refresh_token_expiry_days, 7);
        assert!(!config.demo_mode);
        assert_eq!(config.database_max_connections, 50);
        assert_eq!(config.database_min_connections, 5);
        assert!(config.auth_max_concurrency >= 8);
        assert_eq!(config.rate_limit_api_per_window, 10000);
        assert_eq!(config.rate_limit_search_per_window, 300);
        // #1026: password-change limiter defaults must be strictly tighter
        // than the global API bucket so a victim-JWT bearer cannot grind
        // 100+ password guesses per minute through the bcrypt verifier.
        assert_eq!(config.rate_limit_password_change_per_window, 5);
        assert_eq!(config.rate_limit_password_change_window_secs, 900);
        assert!(
            (config.rate_limit_password_change_per_window as u64) * config.rate_limit_window_secs
                < (config.rate_limit_api_per_window as u64)
                    * config.rate_limit_password_change_window_secs,
            "password-change effective rate must be tighter than the API bucket"
        );
        assert_eq!(config.max_upload_size_bytes, 10_737_418_240);
        assert_eq!(config.smtp_port, 587);
        assert_eq!(config.smtp_tls_mode, "starttls");
    }

    // -----------------------------------------------------------------------
    // Global defense-in-depth backstop (concurrency limit + request timeout)
    // -----------------------------------------------------------------------

    #[test]
    fn test_global_backstop_defaults_are_generous() {
        let config = Config::default();
        // The concurrency cap must be well above the worker pool so it never
        // throttles legitimate parallel CI traffic, and the timeout must be
        // generous enough not to kill large uploads.
        assert_eq!(config.global_max_concurrency, 512);
        assert_eq!(config.global_request_timeout_secs, 120);
    }

    #[test]
    fn test_global_backstop_zero_disables_each_layer() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_conc = env::var("GLOBAL_MAX_CONCURRENCY").ok();
        let saved_to = env::var("GLOBAL_REQUEST_TIMEOUT_SECS").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::set_var("GLOBAL_MAX_CONCURRENCY", "0");
        env::set_var("GLOBAL_REQUEST_TIMEOUT_SECS", "0");

        let config = Config::from_env().expect("config should load");
        // 0 is the documented "disable this layer" sentinel for both.
        assert_eq!(config.global_max_concurrency, 0);
        assert_eq!(config.global_request_timeout_secs, 0);

        // Restore
        env::remove_var("GLOBAL_MAX_CONCURRENCY");
        env::remove_var("GLOBAL_REQUEST_TIMEOUT_SECS");
        if let Some(v) = saved_conc {
            env::set_var("GLOBAL_MAX_CONCURRENCY", v);
        }
        if let Some(v) = saved_to {
            env::set_var("GLOBAL_REQUEST_TIMEOUT_SECS", v);
        }
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        }
    }

    #[test]
    fn test_global_backstop_parses_custom_values() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_conc = env::var("GLOBAL_MAX_CONCURRENCY").ok();
        let saved_to = env::var("GLOBAL_REQUEST_TIMEOUT_SECS").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::set_var("GLOBAL_MAX_CONCURRENCY", "1024");
        env::set_var("GLOBAL_REQUEST_TIMEOUT_SECS", "300");

        let config = Config::from_env().expect("config should load");
        assert_eq!(config.global_max_concurrency, 1024);
        assert_eq!(config.global_request_timeout_secs, 300);

        env::remove_var("GLOBAL_MAX_CONCURRENCY");
        env::remove_var("GLOBAL_REQUEST_TIMEOUT_SECS");
        if let Some(v) = saved_conc {
            env::set_var("GLOBAL_MAX_CONCURRENCY", v);
        }
        if let Some(v) = saved_to {
            env::set_var("GLOBAL_REQUEST_TIMEOUT_SECS", v);
        }
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        }
    }

    #[test]
    fn test_test_config_returns_default() {
        let from_default = Config::default();
        let from_helper = Config::test_config();
        // Spot-check a few fields to confirm they are the same.
        assert_eq!(from_default.bind_address, from_helper.bind_address);
        assert_eq!(from_default.jwt_secret, from_helper.jwt_secret);
        assert_eq!(from_default.storage_backend, from_helper.storage_backend);
        assert_eq!(
            from_default.max_upload_size_bytes,
            from_helper.max_upload_size_bytes
        );
    }

    // -----------------------------------------------------------------------
    // env_parse
    // -----------------------------------------------------------------------

    #[test]
    fn test_env_parse_returns_default_when_var_not_set() {
        let _lock = ENV_MUTEX.lock().unwrap();
        // Use a unique key unlikely to be set
        env::remove_var("__TEST_ENV_PARSE_MISSING_12345__");
        let result: u64 = env_parse("__TEST_ENV_PARSE_MISSING_12345__", 42);
        assert_eq!(result, 42);
    }

    #[test]
    fn test_env_parse_parses_valid_value() {
        let _lock = ENV_MUTEX.lock().unwrap();
        env::set_var("__TEST_ENV_PARSE_VALID__", "100");
        let result: u64 = env_parse("__TEST_ENV_PARSE_VALID__", 42);
        assert_eq!(result, 100);
        env::remove_var("__TEST_ENV_PARSE_VALID__");
    }

    #[test]
    fn test_env_parse_returns_default_on_invalid_value() {
        let _lock = ENV_MUTEX.lock().unwrap();
        env::set_var("__TEST_ENV_PARSE_INVALID__", "not-a-number");
        let result: u64 = env_parse("__TEST_ENV_PARSE_INVALID__", 42);
        assert_eq!(result, 42);
        env::remove_var("__TEST_ENV_PARSE_INVALID__");
    }

    #[test]
    fn test_env_parse_bool() {
        let _lock = ENV_MUTEX.lock().unwrap();
        env::set_var("__TEST_ENV_PARSE_BOOL__", "true");
        let result: bool = env_parse("__TEST_ENV_PARSE_BOOL__", false);
        assert!(result);
        env::remove_var("__TEST_ENV_PARSE_BOOL__");
    }

    #[test]
    fn test_env_parse_i64() {
        let _lock = ENV_MUTEX.lock().unwrap();
        env::set_var("__TEST_ENV_PARSE_I64__", "-30");
        let result: i64 = env_parse("__TEST_ENV_PARSE_I64__", 7);
        assert_eq!(result, -30);
        env::remove_var("__TEST_ENV_PARSE_I64__");
    }

    #[test]
    fn test_env_parse_empty_string_falls_back_to_default() {
        let _lock = ENV_MUTEX.lock().unwrap();
        env::set_var("__TEST_ENV_PARSE_EMPTY__", "");
        // Empty string is not parseable as u64, so default is used
        let result: u64 = env_parse("__TEST_ENV_PARSE_EMPTY__", 99);
        assert_eq!(result, 99);
        env::remove_var("__TEST_ENV_PARSE_EMPTY__");
    }

    // -----------------------------------------------------------------------
    // Stuck-scan clamps (#1015 hardening)
    // -----------------------------------------------------------------------

    #[test]
    fn test_clamp_stuck_scan_threshold_below_floor_clamps_to_floor() {
        assert_eq!(
            clamp_stuck_scan_threshold(0),
            STUCK_SCAN_THRESHOLD_FLOOR_SECS
        );
        assert_eq!(
            clamp_stuck_scan_threshold(STUCK_SCAN_THRESHOLD_FLOOR_SECS - 1),
            STUCK_SCAN_THRESHOLD_FLOOR_SECS
        );
    }

    #[test]
    fn test_clamp_stuck_scan_threshold_at_or_above_floor_passes_through() {
        assert_eq!(
            clamp_stuck_scan_threshold(STUCK_SCAN_THRESHOLD_FLOOR_SECS),
            STUCK_SCAN_THRESHOLD_FLOOR_SECS
        );
        assert_eq!(clamp_stuck_scan_threshold(1800), 1800);
        assert_eq!(clamp_stuck_scan_threshold(86400), 86400);
    }

    #[test]
    fn test_clamp_stuck_scan_interval_below_floor_clamps_to_floor() {
        // The headline reason for the floor: tokio::time::interval(Duration::ZERO)
        // panics, which would silently kill the spawned scheduler task.
        assert_eq!(clamp_stuck_scan_interval(0), STUCK_SCAN_INTERVAL_FLOOR_SECS);
        assert_eq!(
            clamp_stuck_scan_interval(STUCK_SCAN_INTERVAL_FLOOR_SECS - 1),
            STUCK_SCAN_INTERVAL_FLOOR_SECS
        );
    }

    #[test]
    fn test_clamp_stuck_scan_interval_at_or_above_floor_passes_through() {
        assert_eq!(
            clamp_stuck_scan_interval(STUCK_SCAN_INTERVAL_FLOOR_SECS),
            STUCK_SCAN_INTERVAL_FLOOR_SECS
        );
        assert_eq!(clamp_stuck_scan_interval(600), 600);
    }

    // -----------------------------------------------------------------------
    // Config::from_env
    // -----------------------------------------------------------------------

    #[test]
    fn test_config_from_env_missing_database_url_errors() {
        let _lock = ENV_MUTEX.lock().unwrap();
        // Save and remove required vars
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        env::remove_var("DATABASE_URL");
        env::set_var("JWT_SECRET", STRONG_SECRET);

        let result = Config::from_env();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("DATABASE_URL"));

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
    }

    #[test]
    fn test_config_from_env_missing_jwt_secret_errors() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        env::set_var("DATABASE_URL", "postgresql://localhost/test");
        env::remove_var("JWT_SECRET");

        let result = Config::from_env();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("JWT_SECRET"));

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        }
    }

    #[test]
    fn test_config_from_env_defaults() {
        let _lock = ENV_MUTEX.lock().unwrap();
        // Save existing env vars
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_bind = env::var("BIND_ADDRESS").ok();
        let saved_log = env::var("LOG_LEVEL").ok();
        let saved_storage = env::var("STORAGE_BACKEND").ok();
        let saved_demo = env::var("DEMO_MODE").ok();

        // Set only required vars
        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);

        // Remove optional vars to test defaults
        env::remove_var("BIND_ADDRESS");
        env::remove_var("LOG_LEVEL");
        env::remove_var("STORAGE_BACKEND");
        env::remove_var("DEMO_MODE");
        env::remove_var("RATE_LIMIT_AUTH_PER_MIN");
        env::remove_var("RATE_LIMIT_API_PER_MIN");
        env::remove_var("RATE_LIMIT_SEARCH_PER_MIN");
        env::remove_var("RATE_LIMIT_WINDOW_SECS");
        env::remove_var("PASSWORD_EXPIRY_WARNING_DAYS");
        env::remove_var("PASSWORD_EXPIRY_CHECK_INTERVAL_SECS");

        let config = Config::from_env().expect("Config should load with required vars");

        assert_eq!(config.database_url, "postgresql://localhost/testdb");
        assert_eq!(config.jwt_secret, STRONG_SECRET);
        assert_eq!(config.bind_address, "0.0.0.0:8080");
        assert_eq!(config.log_level, "info");
        assert_eq!(config.storage_backend, "filesystem");
        assert_eq!(config.jwt_expiration_secs, 86400);
        assert_eq!(config.jwt_access_token_expiry_minutes, 30);
        assert_eq!(config.jwt_refresh_token_expiry_days, 7);
        assert!(!config.demo_mode);
        if cfg!(windows) {
            assert_eq!(
                config.scan_workspace_path,
                r"C:\ProgramData\ArtifactKeeper\scan-workspace"
            );
        } else {
            assert_eq!(config.scan_workspace_path, "/scan-workspace");
        }
        assert_eq!(config.peer_instance_name, "artifact-keeper-local");
        assert_eq!(config.peer_public_endpoint, "http://localhost:8080");
        assert_eq!(config.max_upload_size_bytes, 10_737_418_240);

        // Database pool defaults (#678, raised for perf bundle #991/#1088)
        assert_eq!(config.database_max_connections, 50);
        assert_eq!(config.database_min_connections, 5);
        assert_eq!(config.database_acquire_timeout_secs, 5);
        assert_eq!(config.database_idle_timeout_secs, 600);
        assert_eq!(config.database_max_lifetime_secs, 1800);
        assert!(config.auth_max_concurrency >= 8);

        // Password expiration defaults (#679)
        assert_eq!(config.password_expiry_days, 0);
        assert_eq!(config.password_expiry_warning_days, vec![1, 7, 14]);
        assert_eq!(config.password_expiry_check_interval_secs, 3600);

        // Rate limit defaults (#692)
        assert_eq!(config.rate_limit_auth_per_window, 120);
        assert_eq!(config.rate_limit_api_per_window, 10000);
        assert_eq!(config.rate_limit_search_per_window, 300);
        assert_eq!(config.rate_limit_window_secs, 60);

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        if let Some(v) = saved_bind {
            env::set_var("BIND_ADDRESS", v);
        }
        if let Some(v) = saved_log {
            env::set_var("LOG_LEVEL", v);
        }
        if let Some(v) = saved_storage {
            env::set_var("STORAGE_BACKEND", v);
        }
        if let Some(v) = saved_demo {
            env::set_var("DEMO_MODE", v);
        }
    }

    // -----------------------------------------------------------------------
    // Database pool configuration (#678)
    // -----------------------------------------------------------------------

    #[test]
    fn test_config_database_pool_env_overrides() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_max = env::var("DATABASE_MAX_CONNECTIONS").ok();
        let saved_min = env::var("DATABASE_MIN_CONNECTIONS").ok();
        let saved_acq = env::var("DATABASE_ACQUIRE_TIMEOUT_SECS").ok();
        let saved_idle = env::var("DATABASE_IDLE_TIMEOUT_SECS").ok();
        let saved_life = env::var("DATABASE_MAX_LIFETIME_SECS").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::set_var("DATABASE_MAX_CONNECTIONS", "50");
        env::set_var("DATABASE_MIN_CONNECTIONS", "10");
        env::set_var("DATABASE_ACQUIRE_TIMEOUT_SECS", "15");
        env::set_var("DATABASE_IDLE_TIMEOUT_SECS", "300");
        env::set_var("DATABASE_MAX_LIFETIME_SECS", "900");

        let config = Config::from_env().expect("Config should load");

        assert_eq!(config.database_max_connections, 50);
        assert_eq!(config.database_min_connections, 10);
        assert_eq!(config.database_acquire_timeout_secs, 15);
        assert_eq!(config.database_idle_timeout_secs, 300);
        assert_eq!(config.database_max_lifetime_secs, 900);

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        for (k, v) in [
            ("DATABASE_MAX_CONNECTIONS", saved_max),
            ("DATABASE_MIN_CONNECTIONS", saved_min),
            ("DATABASE_ACQUIRE_TIMEOUT_SECS", saved_acq),
            ("DATABASE_IDLE_TIMEOUT_SECS", saved_idle),
            ("DATABASE_MAX_LIFETIME_SECS", saved_life),
        ] {
            match v {
                Some(val) => env::set_var(k, val),
                None => env::remove_var(k),
            }
        }
    }

    #[test]
    fn test_config_database_pool_invalid_value_falls_back_to_default() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_max = env::var("DATABASE_MAX_CONNECTIONS").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::set_var("DATABASE_MAX_CONNECTIONS", "not-a-number");

        let config = Config::from_env().expect("Config should load even with invalid pool setting");

        // env_parse falls back to the default when the value cannot be parsed
        assert_eq!(config.database_max_connections, 50);

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        if let Some(v) = saved_max {
            env::set_var("DATABASE_MAX_CONNECTIONS", v);
        } else {
            env::remove_var("DATABASE_MAX_CONNECTIONS");
        }
    }

    #[test]
    fn test_config_demo_mode_true() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_demo = env::var("DEMO_MODE").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::set_var("DEMO_MODE", "true");

        let config = Config::from_env().unwrap();
        assert!(config.demo_mode);

        // Also test "1"
        env::set_var("DEMO_MODE", "1");
        let config = Config::from_env().unwrap();
        assert!(config.demo_mode);

        // Test "false" is not demo mode
        env::set_var("DEMO_MODE", "false");
        let config = Config::from_env().unwrap();
        assert!(!config.demo_mode);

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        if let Some(v) = saved_demo {
            env::set_var("DEMO_MODE", v);
        } else {
            env::remove_var("DEMO_MODE");
        }
    }

    #[test]
    fn test_config_guest_access_enabled_default_true() {
        // Issue #850: zero-impact upgrades. When the env var is unset the
        // server must keep behaving exactly as it did before, which means
        // anonymous (guest) access stays enabled.
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_flag = env::var("AK_GUEST_ACCESS_ENABLED").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::remove_var("AK_GUEST_ACCESS_ENABLED");

        let config = Config::from_env().unwrap();
        assert!(config.guest_access_enabled);

        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        if let Some(v) = saved_flag {
            env::set_var("AK_GUEST_ACCESS_ENABLED", v);
        } else {
            env::remove_var("AK_GUEST_ACCESS_ENABLED");
        }
    }

    #[test]
    fn test_config_guest_access_enabled_explicit_values() {
        // Verify that "false" and "0" disable guest access, while anything
        // else (including "true", "1", garbage, and empty string) keeps it
        // enabled. The "fail open" behaviour on garbage values is intentional
        // so a typo in deployment does not lock administrators out without
        // warning.
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_flag = env::var("AK_GUEST_ACCESS_ENABLED").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);

        env::set_var("AK_GUEST_ACCESS_ENABLED", "false");
        assert!(!Config::from_env().unwrap().guest_access_enabled);

        env::set_var("AK_GUEST_ACCESS_ENABLED", "0");
        assert!(!Config::from_env().unwrap().guest_access_enabled);

        env::set_var("AK_GUEST_ACCESS_ENABLED", "true");
        assert!(Config::from_env().unwrap().guest_access_enabled);

        env::set_var("AK_GUEST_ACCESS_ENABLED", "1");
        assert!(Config::from_env().unwrap().guest_access_enabled);

        env::set_var("AK_GUEST_ACCESS_ENABLED", "yes");
        assert!(Config::from_env().unwrap().guest_access_enabled);

        env::set_var("AK_GUEST_ACCESS_ENABLED", "");
        assert!(Config::from_env().unwrap().guest_access_enabled);

        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        if let Some(v) = saved_flag {
            env::set_var("AK_GUEST_ACCESS_ENABLED", v);
        } else {
            env::remove_var("AK_GUEST_ACCESS_ENABLED");
        }
    }

    #[test]
    fn test_config_default_guest_access_enabled() {
        // The Config::default() helper returns guest_access_enabled = true,
        // which is what test_config() relies on.
        let config = Config::default();
        assert!(config.guest_access_enabled);
    }

    #[test]
    fn test_config_plugins_require_signed_default_true() {
        // Fail-closed: when PLUGINS_REQUIRE_SIGNED is unset, plugin signature
        // verification is required so an unsigned WASM cannot be installed.
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_flag = env::var("PLUGINS_REQUIRE_SIGNED").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::remove_var("PLUGINS_REQUIRE_SIGNED");

        assert!(Config::from_env().unwrap().plugins_require_signed);

        restore_env("DATABASE_URL", saved_db);
        restore_env("JWT_SECRET", saved_jwt);
        restore_env("PLUGINS_REQUIRE_SIGNED", saved_flag);
    }

    #[test]
    fn test_config_plugins_require_signed_explicit_values() {
        // Only an explicit, recognized negative disables the requirement;
        // garbage/empty/affirmative all keep it required (fail-closed).
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_flag = env::var("PLUGINS_REQUIRE_SIGNED").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);

        env::set_var("PLUGINS_REQUIRE_SIGNED", "false");
        assert!(!Config::from_env().unwrap().plugins_require_signed);

        env::set_var("PLUGINS_REQUIRE_SIGNED", "0");
        assert!(!Config::from_env().unwrap().plugins_require_signed);

        env::set_var("PLUGINS_REQUIRE_SIGNED", "true");
        assert!(Config::from_env().unwrap().plugins_require_signed);

        env::set_var("PLUGINS_REQUIRE_SIGNED", "1");
        assert!(Config::from_env().unwrap().plugins_require_signed);

        env::set_var("PLUGINS_REQUIRE_SIGNED", "garbage");
        assert!(Config::from_env().unwrap().plugins_require_signed);

        env::set_var("PLUGINS_REQUIRE_SIGNED", "");
        assert!(Config::from_env().unwrap().plugins_require_signed);

        restore_env("DATABASE_URL", saved_db);
        restore_env("JWT_SECRET", saved_jwt);
        restore_env("PLUGINS_REQUIRE_SIGNED", saved_flag);
    }

    #[test]
    fn test_config_plugins_trusted_pubkey() {
        // Unset -> None; set non-empty -> Some(trimmed); empty/whitespace -> None.
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_key = env::var("PLUGINS_TRUSTED_PUBKEY").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);

        env::remove_var("PLUGINS_TRUSTED_PUBKEY");
        assert_eq!(Config::from_env().unwrap().plugins_trusted_pubkey, None);

        env::set_var("PLUGINS_TRUSTED_PUBKEY", "  abc123==  ");
        assert_eq!(
            Config::from_env()
                .unwrap()
                .plugins_trusted_pubkey
                .as_deref(),
            Some("abc123==")
        );

        env::set_var("PLUGINS_TRUSTED_PUBKEY", "   ");
        assert_eq!(Config::from_env().unwrap().plugins_trusted_pubkey, None);

        restore_env("DATABASE_URL", saved_db);
        restore_env("JWT_SECRET", saved_jwt);
        restore_env("PLUGINS_TRUSTED_PUBKEY", saved_key);
    }

    #[test]
    fn test_config_allow_local_admin_login() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_flag = env::var("ALLOW_LOCAL_ADMIN_LOGIN").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);

        // Default is false
        env::remove_var("ALLOW_LOCAL_ADMIN_LOGIN");
        let config = Config::from_env().unwrap();
        assert!(!config.allow_local_admin_login);

        // "true" enables it
        env::set_var("ALLOW_LOCAL_ADMIN_LOGIN", "true");
        let config = Config::from_env().unwrap();
        assert!(config.allow_local_admin_login);

        // "1" also enables it
        env::set_var("ALLOW_LOCAL_ADMIN_LOGIN", "1");
        let config = Config::from_env().unwrap();
        assert!(config.allow_local_admin_login);

        // "false" does not enable it
        env::set_var("ALLOW_LOCAL_ADMIN_LOGIN", "false");
        let config = Config::from_env().unwrap();
        assert!(!config.allow_local_admin_login);

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        if let Some(v) = saved_flag {
            env::set_var("ALLOW_LOCAL_ADMIN_LOGIN", v);
        } else {
            env::remove_var("ALLOW_LOCAL_ADMIN_LOGIN");
        }
    }

    #[test]
    fn test_config_sso_disable_admin_break_glass() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_flag = env::var("SSO_DISABLE_ADMIN_BREAK_GLASS").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);

        // Default is false: the admin break-glass stays enabled (#2018).
        env::remove_var("SSO_DISABLE_ADMIN_BREAK_GLASS");
        let config = Config::from_env().unwrap();
        assert!(!config.sso_disable_admin_break_glass);

        // "true" opts into strict SSO-only enforcement.
        env::set_var("SSO_DISABLE_ADMIN_BREAK_GLASS", "true");
        let config = Config::from_env().unwrap();
        assert!(config.sso_disable_admin_break_glass);

        // "1" also opts in.
        env::set_var("SSO_DISABLE_ADMIN_BREAK_GLASS", "1");
        let config = Config::from_env().unwrap();
        assert!(config.sso_disable_admin_break_glass);

        // Any other value leaves the break-glass enabled.
        env::set_var("SSO_DISABLE_ADMIN_BREAK_GLASS", "false");
        let config = Config::from_env().unwrap();
        assert!(!config.sso_disable_admin_break_glass);

        restore_env("DATABASE_URL", saved_db);
        restore_env("JWT_SECRET", saved_jwt);
        restore_env("SSO_DISABLE_ADMIN_BREAK_GLASS", saved_flag);
    }

    #[test]
    fn test_config_custom_jwt_expiry() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_exp = env::var("JWT_EXPIRATION_SECS").ok();
        let saved_access = env::var("JWT_ACCESS_TOKEN_EXPIRY_MINUTES").ok();
        let saved_refresh = env::var("JWT_REFRESH_TOKEN_EXPIRY_DAYS").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::set_var("JWT_EXPIRATION_SECS", "3600");
        env::set_var("JWT_ACCESS_TOKEN_EXPIRY_MINUTES", "15");
        env::set_var("JWT_REFRESH_TOKEN_EXPIRY_DAYS", "14");

        let config = Config::from_env().unwrap();
        assert_eq!(config.jwt_expiration_secs, 3600);
        assert_eq!(config.jwt_access_token_expiry_minutes, 15);
        assert_eq!(config.jwt_refresh_token_expiry_days, 14);

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        if let Some(v) = saved_exp {
            env::set_var("JWT_EXPIRATION_SECS", v);
        } else {
            env::remove_var("JWT_EXPIRATION_SECS");
        }
        if let Some(v) = saved_access {
            env::set_var("JWT_ACCESS_TOKEN_EXPIRY_MINUTES", v);
        } else {
            env::remove_var("JWT_ACCESS_TOKEN_EXPIRY_MINUTES");
        }
        if let Some(v) = saved_refresh {
            env::set_var("JWT_REFRESH_TOKEN_EXPIRY_DAYS", v);
        } else {
            env::remove_var("JWT_REFRESH_TOKEN_EXPIRY_DAYS");
        }
    }

    #[test]
    fn test_config_gc_schedule_default() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_gc = env::var("GC_SCHEDULE").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::remove_var("GC_SCHEDULE");

        let config = Config::from_env().unwrap();
        assert_eq!(config.gc_schedule, "0 0 * * * *");

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        if let Some(v) = saved_gc {
            env::set_var("GC_SCHEDULE", v);
        }
    }

    #[test]
    fn test_config_gc_schedule_custom() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_gc = env::var("GC_SCHEDULE").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::set_var("GC_SCHEDULE", "0 30 2 * * *");

        let config = Config::from_env().unwrap();
        assert_eq!(config.gc_schedule, "0 30 2 * * *");

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        if let Some(v) = saved_gc {
            env::set_var("GC_SCHEDULE", v);
        } else {
            env::remove_var("GC_SCHEDULE");
        }
    }

    #[test]
    fn test_config_lifecycle_check_interval_default() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_lc = env::var("LIFECYCLE_CHECK_INTERVAL_SECS").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::remove_var("LIFECYCLE_CHECK_INTERVAL_SECS");

        let config = Config::from_env().unwrap();
        assert_eq!(config.lifecycle_check_interval_secs, 60);

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        if let Some(v) = saved_lc {
            env::set_var("LIFECYCLE_CHECK_INTERVAL_SECS", v);
        }
    }

    #[test]
    fn test_config_lifecycle_check_interval_custom() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_lc = env::var("LIFECYCLE_CHECK_INTERVAL_SECS").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::set_var("LIFECYCLE_CHECK_INTERVAL_SECS", "300");

        let config = Config::from_env().unwrap();
        assert_eq!(config.lifecycle_check_interval_secs, 300);

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        if let Some(v) = saved_lc {
            env::set_var("LIFECYCLE_CHECK_INTERVAL_SECS", v);
        } else {
            env::remove_var("LIFECYCLE_CHECK_INTERVAL_SECS");
        }
    }

    #[test]
    fn test_config_optional_s3_fields() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_bucket = env::var("S3_BUCKET").ok();
        let saved_region = env::var("S3_REGION").ok();
        let saved_endpoint = env::var("S3_ENDPOINT").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::set_var("S3_BUCKET", "my-bucket");
        env::set_var("S3_REGION", "us-east-1");
        env::set_var("S3_ENDPOINT", "http://minio:9000");

        let config = Config::from_env().unwrap();
        assert_eq!(config.s3_bucket.as_deref(), Some("my-bucket"));
        assert_eq!(config.s3_region.as_deref(), Some("us-east-1"));
        assert_eq!(config.s3_endpoint.as_deref(), Some("http://minio:9000"));

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        if let Some(v) = saved_bucket {
            env::set_var("S3_BUCKET", v);
        } else {
            env::remove_var("S3_BUCKET");
        }
        if let Some(v) = saved_region {
            env::set_var("S3_REGION", v);
        } else {
            env::remove_var("S3_REGION");
        }
        if let Some(v) = saved_endpoint {
            env::set_var("S3_ENDPOINT", v);
        } else {
            env::remove_var("S3_ENDPOINT");
        }
    }

    #[test]
    fn test_config_max_upload_size_default() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_max = env::var("MAX_UPLOAD_SIZE").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::remove_var("MAX_UPLOAD_SIZE");

        let config = Config::from_env().unwrap();
        assert_eq!(config.max_upload_size_bytes, 10_737_418_240); // 10 GB

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        if let Some(v) = saved_max {
            env::set_var("MAX_UPLOAD_SIZE", v);
        }
    }

    #[test]
    fn test_config_max_upload_size_custom() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_max = env::var("MAX_UPLOAD_SIZE").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::set_var("MAX_UPLOAD_SIZE", "1073741824"); // 1 GB

        let config = Config::from_env().unwrap();
        assert_eq!(config.max_upload_size_bytes, 1_073_741_824);

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        if let Some(v) = saved_max {
            env::set_var("MAX_UPLOAD_SIZE", v);
        } else {
            env::remove_var("MAX_UPLOAD_SIZE");
        }
    }

    #[test]
    fn test_config_metrics_port_unset_is_none() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_port = env::var("METRICS_PORT").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::remove_var("METRICS_PORT");

        let config = Config::from_env().unwrap();
        assert!(config.metrics_port.is_none());

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        if let Some(v) = saved_port {
            env::set_var("METRICS_PORT", v);
        }
    }

    #[test]
    fn test_config_metrics_port_set() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_port = env::var("METRICS_PORT").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::set_var("METRICS_PORT", "9091");

        let config = Config::from_env().unwrap();
        assert_eq!(config.metrics_port, Some(9091));

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        if let Some(v) = saved_port {
            env::set_var("METRICS_PORT", v);
        } else {
            env::remove_var("METRICS_PORT");
        }
    }

    #[test]
    fn test_config_metrics_port_invalid_is_none() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_port = env::var("METRICS_PORT").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::set_var("METRICS_PORT", "not-a-port");

        let config = Config::from_env().unwrap();
        assert!(config.metrics_port.is_none());

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        if let Some(v) = saved_port {
            env::set_var("METRICS_PORT", v);
        } else {
            env::remove_var("METRICS_PORT");
        }
    }

    #[test]
    fn test_config_max_upload_size_zero_disables() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_max = env::var("MAX_UPLOAD_SIZE").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::set_var("MAX_UPLOAD_SIZE", "0");

        let config = Config::from_env().unwrap();
        assert_eq!(config.max_upload_size_bytes, 0);

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        if let Some(v) = saved_max {
            env::set_var("MAX_UPLOAD_SIZE", v);
        } else {
            env::remove_var("MAX_UPLOAD_SIZE");
        }
    }

    // -----------------------------------------------------------------------
    // PASSWORD_HISTORY_COUNT
    // -----------------------------------------------------------------------

    #[test]
    fn test_password_history_count_default_zero() {
        let _lock = ENV_MUTEX.lock().unwrap();
        env::remove_var("PASSWORD_HISTORY_COUNT");
        let result: u32 = env_parse("PASSWORD_HISTORY_COUNT", 0);
        assert_eq!(result, 0);
    }

    #[test]
    fn test_password_history_count_parsed() {
        let _lock = ENV_MUTEX.lock().unwrap();
        env::set_var("PASSWORD_HISTORY_COUNT", "12");
        let result: u32 = env_parse("PASSWORD_HISTORY_COUNT", 0);
        assert_eq!(result, 12);
        env::remove_var("PASSWORD_HISTORY_COUNT");
    }

    #[test]
    fn test_password_history_count_invalid_falls_back() {
        let _lock = ENV_MUTEX.lock().unwrap();
        env::set_var("PASSWORD_HISTORY_COUNT", "not-a-number");
        let result: u32 = env_parse("PASSWORD_HISTORY_COUNT", 0);
        assert_eq!(result, 0);
        env::remove_var("PASSWORD_HISTORY_COUNT");
    }

    #[test]
    fn test_password_history_count_clamped_to_max_24() {
        let _lock = ENV_MUTEX.lock().unwrap();
        env::set_var("PASSWORD_HISTORY_COUNT", "100");
        let result: u32 = env_parse::<u32>("PASSWORD_HISTORY_COUNT", 0).min(24);
        assert_eq!(result, 24);
        env::remove_var("PASSWORD_HISTORY_COUNT");
    }

    #[test]
    fn test_password_history_count_at_max_not_clamped() {
        let _lock = ENV_MUTEX.lock().unwrap();
        env::set_var("PASSWORD_HISTORY_COUNT", "24");
        let result: u32 = env_parse::<u32>("PASSWORD_HISTORY_COUNT", 0).min(24);
        assert_eq!(result, 24);
        env::remove_var("PASSWORD_HISTORY_COUNT");
    }

    #[test]
    fn test_password_history_count_below_max_not_clamped() {
        let _lock = ENV_MUTEX.lock().unwrap();
        env::set_var("PASSWORD_HISTORY_COUNT", "10");
        let result: u32 = env_parse::<u32>("PASSWORD_HISTORY_COUNT", 0).min(24);
        assert_eq!(result, 10);
        env::remove_var("PASSWORD_HISTORY_COUNT");
    }

    // ── presigned downloads config tests ──────────────────────────────

    #[test]
    fn test_presigned_downloads_disabled_by_default() {
        let _lock = ENV_MUTEX.lock().unwrap();
        env::remove_var("PRESIGNED_DOWNLOADS_ENABLED");
        let enabled = matches!(
            env::var("PRESIGNED_DOWNLOADS_ENABLED").as_deref(),
            Ok("true" | "1")
        );
        assert!(!enabled);
    }

    #[test]
    fn test_presigned_downloads_enabled_true() {
        let _lock = ENV_MUTEX.lock().unwrap();
        env::set_var("PRESIGNED_DOWNLOADS_ENABLED", "true");
        let enabled = matches!(
            env::var("PRESIGNED_DOWNLOADS_ENABLED").as_deref(),
            Ok("true" | "1")
        );
        assert!(enabled);
        env::remove_var("PRESIGNED_DOWNLOADS_ENABLED");
    }

    #[test]
    fn test_presigned_downloads_enabled_one() {
        let _lock = ENV_MUTEX.lock().unwrap();
        env::set_var("PRESIGNED_DOWNLOADS_ENABLED", "1");
        let enabled = matches!(
            env::var("PRESIGNED_DOWNLOADS_ENABLED").as_deref(),
            Ok("true" | "1")
        );
        assert!(enabled);
        env::remove_var("PRESIGNED_DOWNLOADS_ENABLED");
    }

    #[test]
    fn test_presigned_download_expiry_default() {
        let _lock = ENV_MUTEX.lock().unwrap();
        env::remove_var("PRESIGNED_DOWNLOAD_EXPIRY_SECS");
        let expiry: u64 = env_parse("PRESIGNED_DOWNLOAD_EXPIRY_SECS", 300);
        assert_eq!(expiry, 300);
    }

    // ── proxy cross-replica single-flight config tests (#1609) ────────────

    #[test]
    fn test_proxy_singleflight_advisory_locks_disabled_by_default() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::remove_var("PROXY_SINGLEFLIGHT_ADVISORY_LOCKS_ENABLED");
        env::remove_var("PROXY_SINGLEFLIGHT_LOCK_POLL_INTERVAL_MS");
        env::remove_var("PROXY_SINGLEFLIGHT_LOCK_WAIT_TIMEOUT_SECS");
        let config = Config::from_env().expect("config should load");
        assert!(!config.proxy_singleflight_advisory_locks_enabled);
        assert_eq!(config.proxy_singleflight_lock_poll_interval_ms, 200);
        assert_eq!(config.proxy_singleflight_lock_wait_timeout_secs, 65);
    }

    #[test]
    fn test_proxy_singleflight_advisory_locks_opt_in() {
        let _lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::set_var("PROXY_SINGLEFLIGHT_ADVISORY_LOCKS_ENABLED", "true");
        env::set_var("PROXY_SINGLEFLIGHT_LOCK_POLL_INTERVAL_MS", "125");
        env::set_var("PROXY_SINGLEFLIGHT_LOCK_WAIT_TIMEOUT_SECS", "42");
        let config = Config::from_env().expect("config should load");
        assert!(config.proxy_singleflight_advisory_locks_enabled);
        assert_eq!(config.proxy_singleflight_lock_poll_interval_ms, 125);
        assert_eq!(config.proxy_singleflight_lock_wait_timeout_secs, 42);
        env::remove_var("PROXY_SINGLEFLIGHT_ADVISORY_LOCKS_ENABLED");
        env::remove_var("PROXY_SINGLEFLIGHT_LOCK_POLL_INTERVAL_MS");
        env::remove_var("PROXY_SINGLEFLIGHT_LOCK_WAIT_TIMEOUT_SECS");
    }

    #[test]
    fn test_presigned_download_expiry_custom() {
        let _lock = ENV_MUTEX.lock().unwrap();
        env::set_var("PRESIGNED_DOWNLOAD_EXPIRY_SECS", "600");
        let expiry: u64 = env_parse("PRESIGNED_DOWNLOAD_EXPIRY_SECS", 300);
        assert_eq!(expiry, 600);
        env::remove_var("PRESIGNED_DOWNLOAD_EXPIRY_SECS");
    }

    // -----------------------------------------------------------------------
    // Rate limit defaults (#692)
    // -----------------------------------------------------------------------

    #[test]
    fn test_config_rate_limit_api_default_is_10000() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_rate = env::var("RATE_LIMIT_API_PER_MIN").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::remove_var("RATE_LIMIT_API_PER_MIN");

        let config = Config::from_env().expect("Config should load");
        assert_eq!(
            config.rate_limit_api_per_window, 10000,
            "Default API rate limit should be 10000 after #692 fix"
        );

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        match saved_rate {
            Some(v) => env::set_var("RATE_LIMIT_API_PER_MIN", v),
            None => env::remove_var("RATE_LIMIT_API_PER_MIN"),
        }
    }

    #[test]
    fn test_config_rate_limit_api_env_override() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_rate = env::var("RATE_LIMIT_API_PER_MIN").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::set_var("RATE_LIMIT_API_PER_MIN", "25000");

        let config = Config::from_env().expect("Config should load");
        assert_eq!(config.rate_limit_api_per_window, 25000);

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        match saved_rate {
            Some(v) => env::set_var("RATE_LIMIT_API_PER_MIN", v),
            None => env::remove_var("RATE_LIMIT_API_PER_MIN"),
        }
    }

    // -----------------------------------------------------------------------
    // Password expiry notification config (#679)
    // -----------------------------------------------------------------------

    #[test]
    fn test_config_password_expiry_warning_days_custom() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_warn = env::var("PASSWORD_EXPIRY_WARNING_DAYS").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::set_var("PASSWORD_EXPIRY_WARNING_DAYS", "30,14,7,3,1");

        let config = Config::from_env().unwrap();
        // Should be sorted and deduped
        assert_eq!(config.password_expiry_warning_days, vec![1, 3, 7, 14, 30]);

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        match saved_warn {
            Some(v) => env::set_var("PASSWORD_EXPIRY_WARNING_DAYS", v),
            None => env::remove_var("PASSWORD_EXPIRY_WARNING_DAYS"),
        }
    }

    #[test]
    fn test_config_password_expiry_warning_days_dedup_and_sort() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_warn = env::var("PASSWORD_EXPIRY_WARNING_DAYS").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::set_var("PASSWORD_EXPIRY_WARNING_DAYS", "7,7,3,14,3");

        let config = Config::from_env().unwrap();
        // Duplicates removed and sorted
        assert_eq!(config.password_expiry_warning_days, vec![3, 7, 14]);

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        match saved_warn {
            Some(v) => env::set_var("PASSWORD_EXPIRY_WARNING_DAYS", v),
            None => env::remove_var("PASSWORD_EXPIRY_WARNING_DAYS"),
        }
    }

    #[test]
    fn test_config_password_expiry_warning_days_filters_zero() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_warn = env::var("PASSWORD_EXPIRY_WARNING_DAYS").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::set_var("PASSWORD_EXPIRY_WARNING_DAYS", "0,7,0,1");

        let config = Config::from_env().unwrap();
        // Zeros filtered out
        assert_eq!(config.password_expiry_warning_days, vec![1, 7]);

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        match saved_warn {
            Some(v) => env::set_var("PASSWORD_EXPIRY_WARNING_DAYS", v),
            None => env::remove_var("PASSWORD_EXPIRY_WARNING_DAYS"),
        }
    }

    #[test]
    fn test_config_password_expiry_warning_days_ignores_invalid() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_warn = env::var("PASSWORD_EXPIRY_WARNING_DAYS").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::set_var("PASSWORD_EXPIRY_WARNING_DAYS", "abc,7,,1,xyz");

        let config = Config::from_env().unwrap();
        // Non-numeric values filtered by parse, empty strings ignored
        assert_eq!(config.password_expiry_warning_days, vec![1, 7]);

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        match saved_warn {
            Some(v) => env::set_var("PASSWORD_EXPIRY_WARNING_DAYS", v),
            None => env::remove_var("PASSWORD_EXPIRY_WARNING_DAYS"),
        }
    }

    #[test]
    fn test_config_password_expiry_check_interval_custom() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_interval = env::var("PASSWORD_EXPIRY_CHECK_INTERVAL_SECS").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::set_var("PASSWORD_EXPIRY_CHECK_INTERVAL_SECS", "1800");

        let config = Config::from_env().unwrap();
        assert_eq!(config.password_expiry_check_interval_secs, 1800);

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        match saved_interval {
            Some(v) => env::set_var("PASSWORD_EXPIRY_CHECK_INTERVAL_SECS", v),
            None => env::remove_var("PASSWORD_EXPIRY_CHECK_INTERVAL_SECS"),
        }
    }

    // -----------------------------------------------------------------------
    // rate_limit_search_per_window env var override (#829)
    // -----------------------------------------------------------------------

    #[test]
    fn test_config_rate_limit_search_per_window_env_override() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_search = env::var("RATE_LIMIT_SEARCH_PER_MIN").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::set_var("RATE_LIMIT_SEARCH_PER_MIN", "500");

        let config = Config::from_env().unwrap();
        assert_eq!(config.rate_limit_search_per_window, 500);

        // Restore
        if let Some(v) = saved_db {
            env::set_var("DATABASE_URL", v);
        } else {
            env::remove_var("DATABASE_URL");
        }
        if let Some(v) = saved_jwt {
            env::set_var("JWT_SECRET", v);
        } else {
            env::remove_var("JWT_SECRET");
        }
        match saved_search {
            Some(v) => env::set_var("RATE_LIMIT_SEARCH_PER_MIN", v),
            None => env::remove_var("RATE_LIMIT_SEARCH_PER_MIN"),
        }
    }

    // -----------------------------------------------------------------------
    // dependency_track_enabled (issues #1395, #1480)
    //
    // Disabling Dependency-Track must be a single, authoritative kill
    // switch read from `DEPENDENCY_TRACK_ENABLED`. These tests pin the
    // parse behaviour: any value other than `true`/`1` (case-insensitive,
    // whitespace trimmed) keeps the integration off, regardless of
    // whether a stale `DEPENDENCY_TRACK_URL` is configured.
    // -----------------------------------------------------------------------

    /// Helper to set env, run a closure, and restore prior state. Keeps
    /// the env-mutated tests below from leaking state into other tests.
    fn with_dt_env<F: FnOnce()>(value: Option<&str>, f: F) {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_dt = env::var("DEPENDENCY_TRACK_ENABLED").ok();
        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        match value {
            Some(v) => env::set_var("DEPENDENCY_TRACK_ENABLED", v),
            None => env::remove_var("DEPENDENCY_TRACK_ENABLED"),
        }
        f();
        match saved_db {
            Some(v) => env::set_var("DATABASE_URL", v),
            None => env::remove_var("DATABASE_URL"),
        }
        match saved_jwt {
            Some(v) => env::set_var("JWT_SECRET", v),
            None => env::remove_var("JWT_SECRET"),
        }
        match saved_dt {
            Some(v) => env::set_var("DEPENDENCY_TRACK_ENABLED", v),
            None => env::remove_var("DEPENDENCY_TRACK_ENABLED"),
        }
    }

    #[test]
    fn test_dt_enabled_defaults_false_when_unset() {
        with_dt_env(None, || {
            let cfg = Config::from_env().unwrap();
            assert!(!cfg.dependency_track_enabled);
        });
    }

    #[test]
    fn test_dt_enabled_default_in_struct_default_is_false() {
        let cfg = Config::default();
        assert!(!cfg.dependency_track_enabled);
    }

    #[test]
    fn test_dt_enabled_explicit_true() {
        with_dt_env(Some("true"), || {
            let cfg = Config::from_env().unwrap();
            assert!(cfg.dependency_track_enabled);
        });
    }

    #[test]
    fn test_dt_enabled_explicit_one() {
        with_dt_env(Some("1"), || {
            let cfg = Config::from_env().unwrap();
            assert!(cfg.dependency_track_enabled);
        });
    }

    #[test]
    fn test_dt_enabled_case_insensitive_true() {
        with_dt_env(Some("TRUE"), || {
            let cfg = Config::from_env().unwrap();
            assert!(cfg.dependency_track_enabled);
        });
    }

    #[test]
    fn test_dt_enabled_with_whitespace() {
        with_dt_env(Some("  true  "), || {
            let cfg = Config::from_env().unwrap();
            assert!(cfg.dependency_track_enabled);
        });
    }

    #[test]
    fn test_dt_enabled_explicit_false() {
        with_dt_env(Some("false"), || {
            let cfg = Config::from_env().unwrap();
            assert!(!cfg.dependency_track_enabled);
        });
    }

    #[test]
    fn test_dt_enabled_empty_string_is_disabled() {
        with_dt_env(Some(""), || {
            let cfg = Config::from_env().unwrap();
            assert!(!cfg.dependency_track_enabled);
        });
    }

    #[test]
    fn test_dt_enabled_garbage_is_disabled() {
        with_dt_env(Some("yes"), || {
            let cfg = Config::from_env().unwrap();
            assert!(!cfg.dependency_track_enabled);
        });
        with_dt_env(Some("on"), || {
            let cfg = Config::from_env().unwrap();
            assert!(!cfg.dependency_track_enabled);
        });
    }

    /// Regression for #1395: a stale `DEPENDENCY_TRACK_URL` must not flip
    /// the enabled flag on its own. The flag is independent of URL
    /// presence.
    #[test]
    fn test_dt_enabled_independent_of_url() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_db = env::var("DATABASE_URL").ok();
        let saved_jwt = env::var("JWT_SECRET").ok();
        let saved_dt = env::var("DEPENDENCY_TRACK_ENABLED").ok();
        let saved_url = env::var("DEPENDENCY_TRACK_URL").ok();

        env::set_var("DATABASE_URL", "postgresql://localhost/testdb");
        env::set_var("JWT_SECRET", STRONG_SECRET);
        env::set_var("DEPENDENCY_TRACK_URL", "http://dt.example.com:8081");
        env::remove_var("DEPENDENCY_TRACK_ENABLED");

        let cfg = Config::from_env().unwrap();
        assert_eq!(
            cfg.dependency_track_url.as_deref(),
            Some("http://dt.example.com:8081")
        );
        assert!(
            !cfg.dependency_track_enabled,
            "URL set without ENABLED=true must leave integration disabled (issue #1395)"
        );

        // Restore
        match saved_db {
            Some(v) => env::set_var("DATABASE_URL", v),
            None => env::remove_var("DATABASE_URL"),
        }
        match saved_jwt {
            Some(v) => env::set_var("JWT_SECRET", v),
            None => env::remove_var("JWT_SECRET"),
        }
        match saved_dt {
            Some(v) => env::set_var("DEPENDENCY_TRACK_ENABLED", v),
            None => env::remove_var("DEPENDENCY_TRACK_ENABLED"),
        }
        match saved_url {
            Some(v) => env::set_var("DEPENDENCY_TRACK_URL", v),
            None => env::remove_var("DEPENDENCY_TRACK_URL"),
        }
    }

    // -----------------------------------------------------------------------
    // jwt_secret_warnings / jwt_secret_strength_error (pure; secret-strength
    // detection used by the unconditional startup hard-fail in every environment)
    // -----------------------------------------------------------------------

    /// A long, varied, non-sequential secret is strong and yields no warnings.
    /// Deliberately a readable passphrase (not a credential-shaped literal) so
    /// secret scanners do not flag this test fixture. It contains none of the
    /// denied weak substrings and has well over 16 distinct characters.
    const STRONG_SECRET: &str = "robust-passphrase-with-many-varied-glyphs-2468";

    #[test]
    fn jwt_warnings_strong_secret_is_clean() {
        assert!(
            jwt_secret_warnings(STRONG_SECRET).is_empty(),
            "a strong random secret must produce no warnings"
        );
    }

    #[test]
    fn jwt_warnings_too_short() {
        // A short (<32) value flags TooShort. Use a readable, non-credential-
        // shaped literal so secret scanners do not flag this test fixture.
        let secret = "short-passphrase-not-secret"; // 27 chars
        let w = jwt_secret_warnings(secret);
        assert!(w.contains(&JwtSecretWarning::TooShort));
        assert!(!w.contains(&JwtSecretWarning::KnownPlaceholder));
    }

    #[test]
    fn jwt_warnings_known_placeholder_case_insensitive() {
        assert!(jwt_secret_warnings("change-me-in-production-please")
            .contains(&JwtSecretWarning::KnownPlaceholder));
        assert!(
            jwt_secret_warnings("ChangeMe").contains(&JwtSecretWarning::KnownPlaceholder),
            "placeholder match must be case-insensitive"
        );
        assert!(
            jwt_secret_warnings("SECRET").contains(&JwtSecretWarning::KnownPlaceholder),
            "extended placeholder list must include common throwaways"
        );
    }

    #[test]
    fn jwt_warnings_low_entropy_repeated_char() {
        // 40 identical chars: long enough, but 1 distinct char -> low entropy.
        let secret = "a".repeat(40);
        let w = jwt_secret_warnings(&secret);
        assert!(w.contains(&JwtSecretWarning::LowEntropy));
        assert!(
            !w.contains(&JwtSecretWarning::TooShort),
            "40 chars is not too short"
        );
    }

    #[test]
    fn jwt_warnings_low_entropy_sequential() {
        // A single ascending run of 40 ASCII chars: 40 distinct characters and
        // long enough, but every step is +1 -> an obvious pattern -> low entropy.
        let secret: String = (b' '..=b'G').map(|b| b as char).collect();
        assert_eq!(secret.len(), 40);
        assert!(jwt_secret_warnings(&secret).contains(&JwtSecretWarning::LowEntropy));
    }

    #[test]
    fn jwt_warnings_short_placeholder_stacks() {
        // "secret" is short, a known placeholder, AND low entropy: all three.
        let w = jwt_secret_warnings("secret");
        assert!(w.contains(&JwtSecretWarning::TooShort));
        assert!(w.contains(&JwtSecretWarning::KnownPlaceholder));
        assert!(w.contains(&JwtSecretWarning::LowEntropy));
    }

    #[test]
    fn validate_jwt_secret_production_rejects_weak() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_env = env::var("ENVIRONMENT").ok();
        env::set_var("ENVIRONMENT", "production");

        let mut config = Config::test_config();
        config.jwt_secret = "secret".into();
        let result = config.validate_jwt_secret();
        assert!(result.is_err(), "production must reject a weak secret");
        assert!(result.unwrap_err().to_string().contains("JWT_SECRET"));

        match saved_env {
            Some(v) => env::set_var("ENVIRONMENT", v),
            None => env::remove_var("ENVIRONMENT"),
        }
    }

    #[test]
    fn validate_jwt_secret_production_accepts_strong() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_env = env::var("ENVIRONMENT").ok();
        env::set_var("ENVIRONMENT", "production");

        let mut config = Config::test_config();
        config.jwt_secret = STRONG_SECRET.into();
        assert!(
            config.validate_jwt_secret().is_ok(),
            "production must accept a strong secret"
        );

        match saved_env {
            Some(v) => env::set_var("ENVIRONMENT", v),
            None => env::remove_var("ENVIRONMENT"),
        }
    }

    #[test]
    fn validate_jwt_secret_rejects_weak_regardless_of_environment() {
        // A weak secret must be a hard error even outside production: there is
        // no ENVIRONMENT-gated relaxation anymore, so dev/test startup via
        // from_env refuses a guessable signing key just like production.
        let _lock = ENV_MUTEX.lock().unwrap();
        let saved_env = env::var("ENVIRONMENT").ok();
        env::set_var("ENVIRONMENT", "development");

        let mut config = Config::test_config();
        config.jwt_secret = "secret".into();
        let result = config.validate_jwt_secret();
        assert!(
            result.is_err(),
            "a weak secret must be rejected even in development"
        );
        assert!(result.unwrap_err().to_string().contains("JWT_SECRET"));

        match saved_env {
            Some(v) => env::set_var("ENVIRONMENT", v),
            None => env::remove_var("ENVIRONMENT"),
        }
    }

    // -----------------------------------------------------------------------
    // jwt_secret_strength_error (pure first-weakness gate used at startup)
    // -----------------------------------------------------------------------

    #[test]
    fn strength_error_rejects_exploit_secret() {
        // The low-entropy, human-readable rig secret embeds "redteam",
        // "test-secret" and "secret-key" — it must be rejected on the weak
        // substring rule, not merely warned about.
        assert!(jwt_secret_strength_error("redteam-test-secret-key-32-bytes-long").is_some());
    }

    #[test]
    fn strength_error_rejects_short_secret() {
        assert!(jwt_secret_strength_error("short-passphrase-not-here").is_some());
    }

    #[test]
    fn strength_error_rejects_low_distinct_secret() {
        // 36 identical chars: long enough, but a single distinct character.
        assert!(jwt_secret_strength_error(&"a".repeat(36)).is_some());
    }

    #[test]
    fn strength_error_rejects_placeholders_and_substrings() {
        for weak in [
            "change-me-in-production-please",
            "change-this-in-production-use-at-least-32-bytes",
            "please-change-me-before-any-real-deployment-now",
            "my-app-default-signing-passphrase-for-tokens",
            "an-example-passphrase-with-plenty-of-distinct",
        ] {
            assert!(
                jwt_secret_strength_error(weak).is_some(),
                "expected `{weak}` to be rejected"
            );
        }
    }

    #[test]
    fn strength_error_accepts_strong_secret() {
        // High-entropy, 32+ chars, >=16 distinct, and NO denied substring.
        assert!(jwt_secret_strength_error(STRONG_SECRET).is_none());
    }

    // -----------------------------------------------------------------------
    // storage_path_error (pure; filesystem absolute-path gate, #2025)
    // -----------------------------------------------------------------------

    #[test]
    fn storage_path_error_rejects_relative_storage_path() {
        // A relative STORAGE_PATH on the filesystem backend resolves against the
        // process CWD at runtime — must be rejected, naming the var and value.
        for value in ["data/artifacts", "./data"] {
            let err = storage_path_error("filesystem", value, "/scan-workspace")
                .expect("relative storage_path must be rejected");
            assert!(err.contains("STORAGE_PATH"), "message names the var: {err}");
            assert!(err.contains(value), "message names the value: {err}");
        }
    }

    #[test]
    fn storage_path_error_accepts_absolute_paths() {
        assert!(storage_path_error(
            "filesystem",
            "/var/lib/artifact-keeper/artifacts",
            "/scan-workspace",
        )
        .is_none());
    }

    #[test]
    fn storage_path_error_rejects_relative_scan_workspace_path() {
        // storage_path is fine; the scanner workspace path is relative.
        let err = storage_path_error(
            "filesystem",
            "/var/lib/artifact-keeper/artifacts",
            "scan-workspace",
        )
        .expect("relative scan_workspace_path must be rejected");
        assert!(
            err.contains("SCAN_WORKSPACE_PATH"),
            "message names the var: {err}"
        );
        assert!(
            err.contains("scan-workspace"),
            "message names the value: {err}"
        );
    }

    #[test]
    fn storage_path_error_skips_object_store_backends() {
        // Object stores treat storage_path as an object-key prefix that may be
        // empty or relative; the local absolute-path rule must not apply.
        assert!(storage_path_error("s3", "artifact-keeper", "").is_none());
        assert!(storage_path_error("s3", "", "").is_none());
        assert!(storage_path_error("gcs", "some/prefix", "").is_none());
    }

    /// Extract the text of a top-level `services.<name>` block (a 2-space
    /// indented key) from a compose file, up to the next sibling service or
    /// 2-space-indented line. Comment lines are stripped so assertions match
    /// live configuration, not documentation. Test-only, minimal parser.
    fn compose_service_block(compose: &str, name: &str) -> String {
        let mut out = String::new();
        let mut in_block = false;
        let key = format!("{name}:");
        for line in compose.lines() {
            let is_service_key = line.starts_with("  ")
                && !line.starts_with("   ")
                && line.trim_start().starts_with(&key);
            if is_service_key {
                in_block = true;
                continue;
            }
            if in_block {
                let boundary =
                    line.starts_with("  ") && !line.starts_with("   ") && !line.trim().is_empty();
                if boundary {
                    break;
                }
                if line.trim_start().starts_with('#') {
                    continue;
                }
                out.push_str(line);
                out.push('\n');
            }
        }
        out
    }

    /// Regression guard for #2084: the hardened runtime image (#2059) ships no
    /// `/bin/sh`, so no compose service that runs that image may be launched
    /// through a shell. On `main` the `backend` service used
    /// `entrypoint: ["/bin/sh","-c", <wait-for-DT-key>]` and `dtrack-init` ran
    /// the backend image via `/bin/sh`; both broke `docker compose up` with
    /// `exec: "/bin/sh": no such file or directory`.
    #[test]
    fn shipped_compose_does_not_run_hardened_image_through_a_shell() {
        let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("backend crate has a parent directory (repo root)");
        let compose_path = repo_root.join("docker-compose.yml");
        let compose = std::fs::read_to_string(&compose_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", compose_path.display()));

        let backend = compose_service_block(&compose, "backend");
        assert!(
            !backend.is_empty(),
            "backend service not found in docker-compose.yml"
        );
        assert!(
            !backend.contains("/bin/sh") && !backend.contains("/bin/bash"),
            "backend service must not use a shell entrypoint; the runtime image \
             has no shell (#2059/#2084). Offending block:\n{backend}"
        );

        // dtrack-init may legitimately use a shell, but not on the shell-less
        // backend image — it must run a shell-bearing image instead.
        let dtrack_init = compose_service_block(&compose, "dtrack-init");
        assert!(
            !dtrack_init.is_empty(),
            "dtrack-init service not found in docker-compose.yml"
        );
        assert!(
            !dtrack_init.contains("artifact-keeper-backend"),
            "dtrack-init must not run the shell-less backend image (#2084). \
             Offending block:\n{dtrack_init}"
        );
    }
}
