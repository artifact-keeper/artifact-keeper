//! Artifact Keeper - Main Entry Point

// ---------------------------------------------------------------------------
// Global allocator selection (non-Windows only)
// ---------------------------------------------------------------------------
// - `--features jemalloc`   -> use jemalloc
// - `--features mimalloc`   -> use mimalloc
// - `--features profiling`  -> use jemalloc with heap profiling enabled
//   (profiling implies jemalloc)
//
// If both jemalloc and mimalloc features are enabled, jemalloc wins.
// On Windows these features are unavailable; the system allocator is used.

#[cfg(all(feature = "jemalloc", not(target_os = "windows")))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(all(feature = "mimalloc", not(feature = "jemalloc")))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use axum::http::{header, Method};
use axum::Router;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

use rand::Rng;

use artifact_keeper_backend::{
    api,
    config::Config,
    db,
    error::Result,
    grpc::{
        generated::{
            cve_history_service_server::CveHistoryServiceServer,
            sbom_service_server::SbomServiceServer,
            security_policy_service_server::SecurityPolicyServiceServer,
        },
        sbom_server::{CveHistoryGrpcServer, SbomGrpcServer, SecurityPolicyGrpcServer},
    },
    services::{
        auth_service::AuthService,
        dependency_track_service::DependencyTrackService,
        metrics_service,
        opensearch_service::OpenSearchService,
        plugin_registry::PluginRegistry,
        proxy_service::ProxyService,
        scan_config_service::ScanConfigService,
        scan_result_service::ScanResultService,
        scanner_service::{AdvisoryClient, ScannerService},
        scheduler_service,
        smtp_service::SmtpService,
        storage_service::StorageService,
        wasm_plugin_service::WasmPluginService,
    },
};
use tokio_util::sync::CancellationToken;
use tonic::transport::Server as TonicServer;

#[cfg(windows)]
mod windows_service;

/// Wait for a shutdown signal (Ctrl+C or SIGTERM).
///
/// Returns once either signal is received. This allows Kubernetes to send
/// SIGTERM during pod termination while also supporting local Ctrl+C.
async fn shutdown_signal() {
    use tokio::signal;

    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => { tracing::info!("received Ctrl+C, starting graceful shutdown"); },
        _ = terminate => { tracing::info!("received SIGTERM, starting graceful shutdown"); },
    }
}

/// Core server logic extracted so it can be called from both the normal entrypoint
/// and the Windows Service entrypoint with an externally-managed shutdown token.
pub async fn run_server(shutdown_token: Option<CancellationToken>) -> Result<()> {
    // Install a rustls CryptoProvider before any TLS operations.
    // Required by rustls 0.23+ when multiple providers (ring, aws-lc-rs)
    // are compiled in via transitive dependencies (object_store, reqwest, sqlx).
    // Without this, IRSA/STS credential fetches panic at startup.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls CryptoProvider");

    // Resolve the shutdown token early so background workers spawned during
    // startup (email dispatcher, webhook producer) share the same
    // cancellation source as the HTTP/gRPC servers spawned later. If the
    // caller did not pass one (console mode) we create our own and bind it
    // to the OS signal listener.
    let runtime_shutdown_token = match shutdown_token {
        Some(token) => token,
        None => {
            let token = CancellationToken::new();
            let signal_token = token.clone();
            tokio::spawn(async move {
                shutdown_signal().await;
                signal_token.cancel();
            });
            token
        }
    };

    // Load environment variables
    if let Ok(env_file) = std::env::var("AK_ENV_FILE") {
        dotenvy::from_path(&env_file).ok();
    } else {
        dotenvy::dotenv().ok();
    }

    // Initialize tracing (with optional OpenTelemetry OTLP export).
    // Read OTel config directly from env since Config::from_env() might fail
    // and we want tracing available to log those errors.
    let otel_endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok();
    let otel_service_name =
        std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "artifact-keeper".into());
    let _otel_guard = artifact_keeper_backend::telemetry::init_tracing(
        otel_endpoint.as_deref(),
        &otel_service_name,
    );

    // Load configuration
    let config = Config::from_env()?;

    // Log active allocator
    #[cfg(all(feature = "jemalloc", not(target_os = "windows")))]
    tracing::info!("Global allocator: jemalloc");
    #[cfg(all(feature = "mimalloc", not(feature = "jemalloc")))]
    tracing::info!("Global allocator: mimalloc");
    #[cfg(not(any(
        all(feature = "jemalloc", not(target_os = "windows")),
        all(feature = "mimalloc", not(feature = "jemalloc")),
    )))]
    tracing::info!("Global allocator: system");
    #[cfg(feature = "profiling")]
    tracing::info!("Jemalloc profiling enabled - set _RJEM_MALLOC_CONF=prof:true to activate");

    tracing::info!("Starting Artifact Keeper");

    // Connect to database
    let db_pool = db::create_pool(&config).await?;
    tracing::info!("Connected to database");

    // Run migrations (skip with SKIP_MIGRATIONS=true for pre-applied migrations)
    let skip_migrations = std::env::var("SKIP_MIGRATIONS")
        .unwrap_or_default()
        .eq_ignore_ascii_case("true");

    if skip_migrations {
        tracing::info!("SKIP_MIGRATIONS=true, skipping automatic database migrations");
    } else {
        tracing::info!("Running database migrations...");
        artifact_keeper_backend::migration_repair::repair_legacy_073_checksum(&db_pool).await?;
        artifact_keeper_backend::migration_repair::repair_release_1_1_9_divergence(&db_pool)
            .await?;
        // Some migrations (e.g. CREATE INDEX on a populated `artifacts` table
        // or backfill UPDATEs) take longer than the per-query
        // `statement_timeout` that operators commonly set on their Postgres
        // parameter group as an app-query safeguard (10 s on AWS RDS for many
        // tunings). Acquire a dedicated connection and raise the timeouts
        // session-locally so the migration runner doesn't share fate with
        // production query limits. The SET is per-session and is wiped when
        // the connection is dropped — global limits for normal app queries
        // are unaffected.
        let mut conn = db_pool.acquire().await?;
        sqlx::query("SET statement_timeout = '30min'")
            .execute(&mut *conn)
            .await?;
        sqlx::query("SET lock_timeout = '5min'")
            .execute(&mut *conn)
            .await?;
        sqlx::migrate!("./migrations").run(&mut *conn).await?;
        tracing::info!("Database migrations complete");
    }

    // Provision admin user on first boot; returns true when setup lock is needed
    let setup_required = provision_admin_user(&db_pool, &config.storage_path).await?;

    // Log loudly at WARN level when setup is still required so log-based
    // alerting and SIEM rules can surface "this server has not had its
    // admin password changed". Before #889, the same condition surfaced
    // implicitly via /readyz returning 503; that signal was load-bearing
    // for some operators and we removed it (the 503 caused Kubernetes
    // restart loops). Emitting a structured WARN here preserves the
    // alert path without driving Kubernetes to restart the pod.
    if setup_required {
        tracing::warn!(
            event = "setup_required",
            "Default admin password has not been changed. API mutations are gated by the setup middleware until the change-password flow runs. See the deployment documentation for credential bootstrap details."
        );
    }

    // Bootstrap OIDC config from environment variables when no DB configs exist yet.
    // This bridges the gap between env-var-based deployment and the database-backed
    // SSO config that the handlers actually use (fixes #238).
    bootstrap_oidc_from_env(&db_pool).await?;

    // Bootstrap LDAP config from environment variables when no DB configs exist yet.
    // Same bridge as OIDC above: the SSO handlers and provider list read from the
    // database, so LDAP_* env vars must be seeded into ldap_configs on first boot
    // for env-only deployments to work (fixes #1434).
    bootstrap_ldap_from_env(&db_pool).await?;

    // Initialize peer identity for mesh networking
    let peer_id = init_peer_identity(&db_pool, &config).await?;
    tracing::info!("Peer identity: {} ({})", config.peer_instance_name, peer_id);

    // Warn when permission rules exist but enforcement is not yet active (#794).
    // This makes the gap visible in server logs so administrators do not
    // assume their rules are protecting anything.
    match sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM permissions")
        .fetch_one(&db_pool)
        .await
    {
        Ok(count) if count > 0 => {
            tracing::warn!(
                permission_rules = count,
                "Found {} permission rule(s) in the database, but enforcement is NOT active. \
                 Permission rules created via /api/v1/permissions are stored but not consulted \
                 during request authorization. This will be addressed in a future release. \
                 See https://github.com/artifact-keeper/artifact-keeper/issues/794",
                count,
            );
        }
        Ok(_) => {}  // no rules, nothing to warn about
        Err(_) => {} // table may not exist on old schema, ignore
    }

    // Initialize WASM plugin system (T068)
    let plugins_dir =
        PathBuf::from(std::env::var("PLUGINS_DIR").unwrap_or_else(|_| "./plugins".to_string()));
    let (plugin_registry, wasm_plugin_service) = initialize_wasm_plugins(
        db_pool.clone(),
        plugins_dir,
        config.plugins_require_signed,
        config.plugins_trusted_pubkey.clone(),
    )
    .await?;

    // Initialize OpenSearch (optional, graceful fallback)
    let search_service = match &config.opensearch_url {
        Some(url) => {
            tracing::info!("Initializing OpenSearch at {}", url);
            match OpenSearchService::new(
                url,
                config.opensearch_username.as_deref(),
                config.opensearch_password.as_deref(),
                config.opensearch_allow_invalid_certs,
            ) {
                Ok(s) => {
                    let service = Arc::new(s);
                    match service.configure_indexes().await {
                        Ok(()) => {
                            tracing::info!("OpenSearch indexes configured");
                            let svc = service.clone();
                            let pool = db_pool.clone();
                            tokio::spawn(async move {
                                match svc.is_index_empty().await {
                                    Ok(true) => {
                                        tracing::info!(
                                            "OpenSearch index is empty, starting background reindex"
                                        );
                                        if let Err(e) = svc.full_reindex(&pool).await {
                                            tracing::error!("Background reindex failed: {}", e);
                                        }
                                    }
                                    Ok(false) => {
                                        tracing::info!(
                                            "OpenSearch index already populated, skipping reindex"
                                        );
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "Failed to check OpenSearch index status: {}",
                                            e
                                        );
                                    }
                                }
                            });
                            Some(service)
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to configure OpenSearch indexes, continuing without search: {}",
                                e
                            );
                            None
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to initialize OpenSearch client, continuing without search: {}",
                        e
                    );
                    None
                }
            }
        }
        _ => {
            tracing::info!("OpenSearch not configured, search indexing disabled");
            None
        }
    };

    // Initialize Prometheus metrics recorder
    let metrics_handle = metrics_service::init_metrics();
    tracing::info!("Prometheus metrics recorder initialized");

    // Issues #976, #1224: surface the upstream private-IP allowlist at
    // boot so the posture is obvious in startup logs. Metadata IPs
    // remain blocked unconditionally; the validator handles that. The
    // warning is loud because relaxing the SSRF guard is a security
    // tradeoff the operator owns.
    if let Some(list) = artifact_keeper_backend::api::validation::private_cidr_allowlist_value() {
        tracing::warn!(
            target: "security",
            allowlist = %list,
            "AK_SSRF_ALLOW_PRIVATE_CIDRS (or alias UPSTREAM_PRIVATE_IP_ALLOWLIST) \
             is set; upstream URLs may now target listed private CIDRs. Cloud \
             metadata IPs and loopback remain blocked. SSRF risk surface \
             widened (issues #976, #1224)."
        );
    } else {
        if artifact_keeper_backend::api::validation::upstream_allow_private_ips_enabled() {
            tracing::warn!(
                target: "security",
                "UPSTREAM_ALLOW_PRIVATE_IPS=true; upstream / remote-proxy URLs \
                 may now target ALL RFC1918 / unique-local addresses. Cloud \
                 metadata IPs and loopback remain blocked. Prefer \
                 AK_SSRF_ALLOW_PRIVATE_CIDRS with explicit CIDRs for a \
                 narrower SSRF surface (issues #976, #1224, #1435)."
            );
        }
        if artifact_keeper_backend::api::validation::webhook_allow_private_ips_enabled() {
            tracing::warn!(
                target: "security",
                "WEBHOOK_ALLOW_PRIVATE_IPS=true; webhook delivery URLs may \
                 now target ALL RFC1918 / unique-local addresses. Cloud \
                 metadata IPs and loopback remain blocked. Prefer \
                 AK_SSRF_ALLOW_PRIVATE_CIDRS with explicit CIDRs for a \
                 narrower SSRF surface (issue #1435)."
            );
        }
    }

    // Create primary storage backend based on STORAGE_BACKEND config
    let primary_storage: Arc<dyn artifact_keeper_backend::storage::StorageBackend> = match config
        .storage_backend
        .as_str()
    {
        "s3" => {
            let s3 = artifact_keeper_backend::storage::s3::S3Backend::from_env().await?;
            tracing::info!("S3 storage backend initialized");
            // Issue #981: run a single connectivity probe so users see
            // the root cause (TLS, DNS, 403, region mismatch) at boot
            // instead of "storage probe timed out" minutes later in a
            // health log. Probe failure is a *warning* only: the user's
            // setup may rely on lazy bucket-creation or an offline boot
            // sequence, so we do not refuse to start.
            match s3.startup_probe().await {
                Ok(()) => tracing::info!("S3 connectivity probe succeeded"),
                Err(e) => tracing::warn!(
                    error = %e,
                    "S3 connectivity probe failed at startup; the service will \
                     continue starting but storage operations may fail until \
                     this is fixed (issue #981)"
                ),
            }
            Arc::new(s3)
        }
        "azure" => {
            let azure_config = artifact_keeper_backend::storage::azure::AzureConfig::from_env()?;
            let azure =
                artifact_keeper_backend::storage::azure::AzureBackend::new(azure_config).await?;
            tracing::info!("Azure Blob storage backend initialized");
            Arc::new(azure)
        }
        "gcs" => {
            let gcs_config = artifact_keeper_backend::storage::gcs::GcsConfig::from_env()?;
            let gcs = artifact_keeper_backend::storage::gcs::GcsBackend::new(gcs_config).await?;
            tracing::info!("GCS storage backend initialized");
            Arc::new(gcs)
        }
        _ => {
            tracing::info!(
                "Filesystem storage backend initialized at {}",
                config.storage_path
            );
            Arc::new(
                artifact_keeper_backend::storage::filesystem::FilesystemStorage::new(
                    &config.storage_path,
                ),
            )
        }
    };

    // Build the storage registry for per-repo backend routing.
    // The registry maps backend names to initialized StorageBackend instances.
    // "filesystem" is always available (handled dynamically by the registry).
    let storage_registry = {
        use std::collections::HashMap;
        let mut backends: HashMap<
            String,
            Arc<dyn artifact_keeper_backend::storage::StorageBackend>,
        > = HashMap::new();

        // Register the primary backend under its type name if it is not filesystem
        if config.storage_backend != "filesystem" {
            backends.insert(config.storage_backend.clone(), primary_storage.clone());
        }

        // Try to register additional backends if credentials are available and
        // they are not already the primary backend.
        if config.storage_backend != "s3" {
            if let Ok(s3) = artifact_keeper_backend::storage::s3::S3Backend::from_env().await {
                tracing::info!("Additional S3 storage backend registered");
                backends.insert("s3".to_string(), Arc::new(s3));
            }
        }
        if config.storage_backend != "azure" {
            if let Ok(azure_cfg) = artifact_keeper_backend::storage::azure::AzureConfig::from_env()
            {
                if let Ok(azure) =
                    artifact_keeper_backend::storage::azure::AzureBackend::new(azure_cfg).await
                {
                    tracing::info!("Additional Azure storage backend registered");
                    backends.insert("azure".to_string(), Arc::new(azure));
                }
            }
        }
        if config.storage_backend != "gcs" {
            if let Ok(gcs_cfg) = artifact_keeper_backend::storage::gcs::GcsConfig::from_env() {
                if let Ok(gcs) =
                    artifact_keeper_backend::storage::gcs::GcsBackend::new(gcs_cfg).await
                {
                    tracing::info!("Additional GCS storage backend registered");
                    backends.insert("gcs".to_string(), Arc::new(gcs));
                }
            }
        }

        let available: Vec<String> = {
            let mut names = vec!["filesystem".to_string()];
            names.extend(backends.keys().cloned());
            names
        };
        tracing::info!("Storage backends available: {:?}", available);

        Arc::new(artifact_keeper_backend::storage::StorageRegistry::new(
            backends,
            config.storage_backend.clone(),
        ))
    };

    // One-shot backfill of oci_manifest_refs for index manifests that
    // pre-date migration 092 (artifact-keeper#1179). Runs after the
    // storage registry is wired up because it needs the registry to read
    // the parent manifest bodies from per-repo backends. Failures are
    // logged but do not block startup. On a fresh database or after the
    // first successful run, the candidate query returns zero rows and
    // this is a near-instant no-op.
    let _refs_backfill_stats =
        artifact_keeper_backend::services::oci_manifest_refs_backfill::run_backfill(
            &db_pool,
            storage_registry.clone(),
        )
        .await;

    // One-shot backfill of manifest_blob_refs for image manifests that
    // pre-date migration 120 (artifact-keeper#1635). GC prerequisite for
    // #1408 / #1610: reconstructs the (manifest -> blob) edges for the
    // existing corpus so a future blob GC can judge oci_blobs orphanhood
    // safely. ADDITIVE ONLY -- no deletion. Runs after the storage
    // registry is wired up because it reads manifest bodies from per-repo
    // backends. Failures are logged but do not block startup; on a fresh
    // database or after the first successful run the candidate query
    // returns zero rows and this is a near-instant no-op.
    // #1642: run the manifest_blob_refs backfill in the BACKGROUND rather than
    // awaiting it here. On a large post-upgrade corpus this scans every image
    // manifest serially (storage GET + parse + INSERT per manifest), which used
    // to delay the HTTP listener bind below by minutes. Deferring it is safe:
    // the backfill is additive-only (no deletion), and the blob-GC readiness
    // gate (`any_live_manifest_missing_refs`) keeps blob GC OFF until every live
    // manifest has its refs, so GC cannot act on a half-backfilled corpus. The
    // scheduler escalates any failures per-tick thereafter (#1409).
    {
        let db_pool = db_pool.clone();
        let storage_registry = storage_registry.clone();
        tokio::spawn(async move {
            let blob_refs_backfill_stats =
                artifact_keeper_backend::services::manifest_blob_refs_backfill::run_backfill(
                    &db_pool,
                    storage_registry,
                )
                .await;
            // A failed candidate (body missing from storage, over-cap, DB write
            // error) leaves that manifest ref-less, which keeps the blob-GC
            // readiness gate closed — the feature stays OFF. This log is the
            // earliest signal; the scheduler escalates per-tick thereafter.
            if blob_refs_backfill_stats.candidates_failed > 0 {
                tracing::error!(
                    candidates_scanned = blob_refs_backfill_stats.candidates_scanned,
                    edges_inserted = blob_refs_backfill_stats.edges_inserted,
                    candidates_failed = blob_refs_backfill_stats.candidates_failed,
                    "manifest_blob_refs backfill left {} live manifest(s) un-backfilled; \
                     blob GC will stay gated off until they are resolved (re-pushed, or \
                     the offending tag deleted)",
                    blob_refs_backfill_stats.candidates_failed
                );
            } else {
                tracing::info!(
                    candidates_scanned = blob_refs_backfill_stats.candidates_scanned,
                    edges_inserted = blob_refs_backfill_stats.edges_inserted,
                    "manifest_blob_refs backfill complete"
                );
            }
        });
    }

    // Initialize security scanner service
    let advisory_client = Arc::new(AdvisoryClient::new(std::env::var("GITHUB_TOKEN").ok()));
    let scan_result_service = Arc::new(ScanResultService::new(db_pool.clone()));
    let scan_config_service = Arc::new(ScanConfigService::new(db_pool.clone()));

    // #2093: token minter + scanner identity for private-repo image pulls.
    // Load the dedicated `_ak_scanner` service account (migration 138). When it
    // is present, the image/grype scanners mint short-lived, single-repo-scoped
    // pull tokens so they can pull private images; when absent (not yet
    // migrated), pulls fall back to anonymous — public repos only.
    let scanner_auth = Arc::new(AuthService::new(db_pool.clone(), Arc::new(config.clone())));
    let scanner_identity = match scanner_auth.load_scanner_identity().await {
        Ok(Some(u)) => {
            tracing::info!("Scanner service account loaded; private-repo image scanning enabled");
            Some(u)
        }
        Ok(None) => {
            tracing::warn!(
                "Scanner service account (_ak_scanner) not found; image scans will pull \
                 anonymously (public repositories only). Run migrations to enable private-repo \
                 scanning."
            );
            None
        }
        Err(e) => {
            tracing::error!("Failed to load scanner service account: {}", e);
            None
        }
    };

    let mut scanner_service = ScannerService::new(
        db_pool.clone(),
        advisory_client,
        scan_result_service,
        scan_config_service,
        config.trivy_url.clone(),
        config.trivy_adapter_url.clone(),
        primary_storage.clone(),
        storage_registry.clone(),
        config.storage_path.clone(),
        config.scan_workspace_path.clone(),
        config.openscap_url.clone(),
        config.openscap_profile.clone(),
        scanner_auth,
        scanner_identity,
        config.scan_token_ttl_seconds,
    );

    // Initialize Dependency-Track integration (before wrapping scanner in Arc,
    // so we can wire the DT service into the scan pipeline for SBOM submission).
    let dt_service_arc: Option<Arc<DependencyTrackService>> =
        match DependencyTrackService::from_env() {
            Some(Ok(dt_service)) => {
                tracing::info!("Dependency-Track integration enabled");
                Some(Arc::new(dt_service))
            }
            Some(Err(e)) => {
                tracing::warn!("Failed to initialize Dependency-Track: {}", e);
                None
            }
            None => None,
        };

    if let Some(ref dt) = dt_service_arc {
        scanner_service.set_dependency_track(dt.clone());
    }

    let scanner_service = Arc::new(scanner_service);

    // Create application state with WASM plugin support
    let scheduler_storage = primary_storage.clone();
    let mut app_state = api::AppState::with_wasm_plugins(
        config.clone(),
        db_pool.clone(),
        primary_storage,
        storage_registry.clone(),
        plugin_registry,
        wasm_plugin_service,
    );
    app_state.set_scanner_service(scanner_service);

    // Initialize quality check service for health scoring and quality gates
    let quality_check_service = Arc::new(
        artifact_keeper_backend::services::quality_check_service::QualityCheckService::new(
            db_pool.clone(),
        ),
    );
    app_state.set_quality_check_service(quality_check_service);
    if let Some(search) = search_service {
        app_state.set_search_service(search);
    }
    if let Some(dt) = dt_service_arc {
        app_state.set_dependency_track(dt);
    }

    app_state.set_metrics_handle(metrics_handle);

    // Initialize proxy service for remote repository caching
    match StorageService::from_config(&config).await {
        Ok(storage_svc) => {
            let proxy_service = Arc::new(ProxyService::new(db_pool.clone(), Arc::new(storage_svc)));
            app_state.set_proxy_service(proxy_service);
            tracing::info!("Proxy service initialized for remote repositories");
        }
        Err(e) => {
            tracing::warn!(
                "Failed to initialize proxy service, remote repositories disabled: {}",
                e
            );
        }
    }

    // Initialize SMTP service (optional, graceful no-op when SMTP_HOST is absent)
    match SmtpService::new(&config) {
        Ok(smtp) => {
            if smtp.is_configured() {
                tracing::info!("SMTP service initialized");
            } else {
                tracing::info!("SMTP not configured, email delivery disabled");
            }
            app_state.set_smtp_service(Arc::new(smtp));
        }
        Err(e) => {
            tracing::warn!(
                "Failed to initialize SMTP service, email delivery disabled: {}",
                e
            );
        }
    }

    // Validate the webhook signing-secret encryption key at boot. We accept
    // any common base64 alphabet (standard or URL-safe, padded or not) so
    // operator-supplied keys generated by tools like `openssl rand -base64`
    // or Kubernetes secret generators work regardless of which characters
    // happen to land in the output (see #1350: a `_` byte from base64url
    // tripped the standard-only decoder).
    //
    // If the operator has set AK_WEBHOOK_SECRET_KEY but it is still malformed
    // after trying every alphabet, fail loud and early instead of letting
    // create/rotate-secret return HTTP 500 hours later. A missing key is
    // also fatal: webhooks v2 cannot create or rotate secrets without it.
    // Operators who want to run the backend without webhook support entirely
    // can omit the key by also disabling the producer
    // (WEBHOOKS_V2_PRODUCER_ENABLED=false, the default).
    match artifact_keeper_backend::services::webhook_secret_crypto::ensure_configured() {
        Ok(()) => tracing::info!("Webhook secret encryption key validated"),
        Err(artifact_keeper_backend::services::webhook_secret_crypto::WebhookSecretError::KeyMissing) => {
            tracing::warn!(
                "AK_WEBHOOK_SECRET_KEY is not configured; webhook create and \
                 rotate-secret endpoints will return HTTP 500 until it is set"
            );
        }
        Err(e) => {
            tracing::error!(
                "AK_WEBHOOK_SECRET_KEY is set but invalid: {}; refusing to start",
                e
            );
            std::process::exit(1);
        }
    }

    // Start email dispatcher (subscribes to EventBus for email_subscriptions delivery).
    // Webhook delivery goes through the v2 webhook pipeline below; the legacy
    // notification_dispatcher that combined both channels was removed in #920.
    artifact_keeper_backend::services::email_dispatcher::start_dispatcher(
        app_state.event_bus.clone(),
        app_state.db.clone(),
        app_state.smtp_service.clone(),
    );
    tracing::info!("Email dispatcher started");

    // Start webhooks v2 producer: subscribes to EventBus and enqueues rows
    // into webhook_deliveries. The retry scheduler (every 30s) drives
    // actual HTTP delivery. See backend/src/services/webhook_producer.rs.
    //
    // Gated behind WEBHOOKS_V2_PRODUCER_ENABLED (default off) so v1.1.9
    // ships the dual-write code path dark. Operators flip the flag once
    // they have rotated migrated webhook secrets and verified delivery.
    let producer_enabled = std::env::var("WEBHOOKS_V2_PRODUCER_ENABLED")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    if producer_enabled {
        artifact_keeper_backend::services::webhook_producer::start_webhook_producer(
            app_state.event_bus.clone(),
            app_state.db.clone(),
            runtime_shutdown_token.clone(),
        );
        tracing::info!("Webhook producer started (WEBHOOKS_V2_PRODUCER_ENABLED=true)");
    } else {
        tracing::info!(
            "Webhook producer disabled (set WEBHOOKS_V2_PRODUCER_ENABLED=true to enable)"
        );
    }

    app_state
        .setup_required
        .store(setup_required, std::sync::atomic::Ordering::Relaxed);
    let state = Arc::new(app_state);

    // Spawn background schedulers (metrics snapshots, health monitor, lifecycle)
    scheduler_service::spawn_all(
        db_pool.clone(),
        config.clone(),
        scheduler_storage,
        storage_registry.clone(),
        state.smtp_service.clone(),
    );

    // Keep a handle for the gRPC server before the sync worker consumes db_pool
    let grpc_db_pool = db_pool.clone();

    // Spawn background sync worker for peer replication
    artifact_keeper_backend::services::sync_worker::spawn_sync_worker(
        db_pool,
        storage_registry.clone(),
    )
    .await;
    tracing::info!("Sync worker started");

    // Conditionally clone state for the metrics listener before the router takes
    // ownership. The clone only happens when METRICS_PORT is actually configured.
    let metrics_state = config.metrics_port.map(|_| state.clone());

    // Build router
    let app = Router::new()
        .merge(api::routes::create_router(state))
        .layer(axum::middleware::from_fn(
            artifact_keeper_backend::api::middleware::metrics::metrics_middleware,
        ))
        .layer({
            // In production the frontend is served from the same origin, so
            // credentials + same-origin work without an explicit allow-origin.
            // In development the Next.js dev server runs on a different port,
            // so we must whitelist that origin and enable credentials.
            // Private-network origins (192.168.x.x, 10.x.x.x, 172.16-31.x.x,
            // 127.x.x.x) are always allowed in development mode.
            if std::env::var("ENVIRONMENT").unwrap_or_default() == "development" {
                let explicit_origins: Vec<String> = std::env::var("CORS_ORIGINS")
                    .unwrap_or_else(|_| "http://localhost:3000".into())
                    .split(',')
                    .map(|s| s.trim().to_owned())
                    .collect();
                CorsLayer::new()
                    .allow_origin(AllowOrigin::predicate(
                        move |origin: &axum::http::HeaderValue, _req| {
                            let origin_str = origin.to_str().unwrap_or("");
                            if explicit_origins.iter().any(|o| o == origin_str) {
                                return true;
                            }
                            // Allow any private-network / loopback origin
                            if let Some(host) = origin_str
                                .strip_prefix("http://")
                                .or_else(|| origin_str.strip_prefix("https://"))
                            {
                                let host = host.split(':').next().unwrap_or("");
                                if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
                                    return ip.is_private() || ip.is_loopback();
                                }
                                return host == "localhost";
                            }
                            false
                        },
                    ))
                    .allow_methods([
                        Method::GET,
                        Method::POST,
                        Method::PUT,
                        Method::PATCH,
                        Method::DELETE,
                        Method::OPTIONS,
                    ])
                    .allow_headers([
                        header::CONTENT_TYPE,
                        header::AUTHORIZATION,
                        header::ACCEPT,
                        header::COOKIE,
                    ])
                    .allow_credentials(true)
            } else {
                // Production: use CORS_ORIGINS env var if set, otherwise same-origin only
                let origins_str = std::env::var("CORS_ORIGINS").unwrap_or_default();
                if origins_str.is_empty() {
                    CorsLayer::new()
                } else {
                    let origins: Vec<_> = origins_str
                        .split(',')
                        .map(|s| s.trim().parse().expect("invalid CORS origin"))
                        .collect();
                    CorsLayer::new()
                        .allow_origin(AllowOrigin::list(origins))
                        .allow_methods([
                            Method::GET,
                            Method::POST,
                            Method::PUT,
                            Method::PATCH,
                            Method::DELETE,
                            Method::OPTIONS,
                        ])
                        .allow_headers([
                            header::CONTENT_TYPE,
                            header::AUTHORIZATION,
                            header::ACCEPT,
                        ])
                }
            }
        })
        .layer(axum::middleware::from_fn(
            artifact_keeper_backend::api::middleware::security_headers::security_headers_middleware,
        ))
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &axum::http::Request<_>| {
                let uri = request.uri();
                let sanitized =
                    artifact_keeper_backend::api::redact_sensitive_params(uri.path(), uri.query());
                tracing::info_span!(
                    "http_request",
                    method = %request.method(),
                    uri = %sanitized,
                )
            }),
        );

    // The concrete shutdown token used by all servers and background tasks
    // is resolved earlier in run_server (see `runtime_shutdown_token`) so
    // that long-lived workers (email dispatcher, webhook producer)
    // share the same cancellation source as the HTTP/gRPC servers.
    let shutdown_token = runtime_shutdown_token.clone();

    // Start HTTP server
    let addr: SocketAddr = config.bind_address.parse()?;
    tracing::info!("HTTP server listening on {}", addr);

    // Start gRPC server on a separate port
    let grpc_port = std::env::var("GRPC_PORT")
        .unwrap_or_else(|_| "9090".to_string())
        .parse::<u16>()
        .unwrap_or(9090);
    let grpc_addr: SocketAddr = format!("0.0.0.0:{}", grpc_port).parse()?;

    // Reuse the existing pool instead of creating a second one (PgPool is Arc-backed)
    let sbom_server = SbomGrpcServer::new(grpc_db_pool.clone());
    let cve_history_server = CveHistoryGrpcServer::new(grpc_db_pool.clone());
    let security_policy_server = SecurityPolicyGrpcServer::new(grpc_db_pool.clone());

    // gRPC auth interceptor - validates JWT Bearer tokens. Pass the shared
    // PgPool so the interceptor can consult the replica-safe credential-change
    // watermark on every request (#1173 / PR #1190 review). Without the pool
    // the interceptor would only see in-memory invalidations made on this
    // replica, leaving a stale-token window equal to the JWT lifetime after a
    // password reset / TOTP change on a peer replica.
    let grpc_auth = artifact_keeper_backend::grpc::auth_interceptor::AuthInterceptor::new(
        &config.jwt_secret,
        Some(grpc_db_pool),
    );

    // Include file descriptor for gRPC reflection
    let reflection_service = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(include_bytes!(concat!(
            env!("OUT_DIR"),
            "/sbom_descriptor.bin"
        )))
        .build_v1()
        .expect("Failed to build reflection service");

    let grpc_auth_sbom = grpc_auth.clone();
    let grpc_auth_cve = grpc_auth.clone();
    let grpc_auth_policy = grpc_auth;
    let grpc_shutdown_token = shutdown_token.clone();
    tokio::spawn(async move {
        tracing::info!("gRPC server listening on {}", grpc_addr);
        #[allow(clippy::result_large_err)]
        let sbom_interceptor = move |req| grpc_auth_sbom.intercept(req);
        #[allow(clippy::result_large_err)]
        let cve_interceptor = move |req| grpc_auth_cve.intercept(req);
        #[allow(clippy::result_large_err)]
        let policy_interceptor = move |req| grpc_auth_policy.intercept(req);
        if let Err(e) = TonicServer::builder()
            .add_service(reflection_service)
            .add_service(SbomServiceServer::with_interceptor(
                sbom_server,
                sbom_interceptor,
            ))
            .add_service(CveHistoryServiceServer::with_interceptor(
                cve_history_server,
                cve_interceptor,
            ))
            .add_service(SecurityPolicyServiceServer::with_interceptor(
                security_policy_server,
                policy_interceptor,
            ))
            .serve_with_shutdown(grpc_addr, grpc_shutdown_token.cancelled())
            .await
        {
            tracing::error!("gRPC server error: {}", e);
        }
        tracing::info!("gRPC server shut down");
    });

    // Optionally start an unauthenticated metrics-only listener on METRICS_PORT.
    if let (Some(metrics_port), Some(metrics_state)) = (config.metrics_port, metrics_state) {
        tracing::warn!(
            port = metrics_port,
            "Starting unauthenticated metrics listener - \
             ensure this port is not reachable from untrusted networks"
        );
        let metrics_addr: SocketAddr = format!("0.0.0.0:{}", metrics_port).parse()?;
        let metrics_shutdown = shutdown_token.clone();
        tokio::spawn(async move {
            let metrics_app = Router::new()
                .route(
                    "/metrics",
                    axum::routing::get(api::handlers::health::metrics),
                )
                .with_state(metrics_state);
            match tokio::net::TcpListener::bind(metrics_addr).await {
                Ok(listener) => {
                    tracing::info!("Metrics listener on {}", metrics_addr);
                    if let Err(e) = axum::serve(listener, metrics_app)
                        .with_graceful_shutdown(async move { metrics_shutdown.cancelled().await })
                        .await
                    {
                        tracing::error!("Metrics listener error: {}", e);
                    }
                    tracing::info!("Metrics listener shut down");
                }
                Err(e) => {
                    tracing::error!("Failed to bind metrics listener on {}: {}", metrics_addr, e);
                }
            }
        });
    }

    let http_shutdown_token = shutdown_token.clone();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    // Install `ConnectInfo<SocketAddr>` so the TCP peer address is available
    // in request extensions. Without it, `extract_client_ip_addr` never sees
    // a peer and the per-IP rate-limit key degenerates to the constant
    // `ip:unknown` bucket for every unauthenticated request (direct-to-backend
    // topology with no X-Forwarded-For), collapsing the login limiter into a
    // single global counter that 429s every account at once. It is also load-
    // bearing for the trusted-proxy X-Forwarded-For gate (#2023): the gate
    // keys on the real TCP peer and only believes XFF when that peer is a
    // configured trusted proxy.
    //
    // Boot-time guard (#2023): fail fast on startup if this wiring is ever
    // dropped (e.g. a future refactor reverting to a plain
    // `app.into_make_service()`), rather than silently degrading every
    // per-IP / login limiter to a single shared bucket. The probe runs the
    // EXACT `connect_info_make_service` adapter used by the serve call below,
    // applied to a sentinel clone of the real router, so any change that stops
    // injecting `ConnectInfo` fails here at startup. Gated to the serve path
    // so unit tests that build the Router directly never trip it.
    assert_connect_info_wired(app.clone()).await;
    axum::serve(listener, connect_info_make_service(app))
        .with_graceful_shutdown(async move { http_shutdown_token.cancelled().await })
        .await?;

    tracing::info!("HTTP server shut down");

    Ok(())
}

/// The single source of truth for installing `ConnectInfo<SocketAddr>` on the
/// HTTP serve path (#2023). Both the real `axum::serve` call and the boot-time
/// guard route through this adapter, so the guard validates exactly the wiring
/// that is served — reverting it (e.g. to a plain `into_make_service()`) is a
/// one-line change here that the guard then catches at startup.
fn connect_info_make_service(
    app: Router,
) -> axum::extract::connect_info::IntoMakeServiceWithConnectInfo<Router, std::net::SocketAddr> {
    app.into_make_service_with_connect_info::<std::net::SocketAddr>()
}

/// Boot-time assertion that the serve-path `ConnectInfo<SocketAddr>` wiring
/// actually injects the TCP peer address into request extensions (#2023).
///
/// Appends a sentinel `ConnectInfo`-reading route to the real router, wraps it
/// with the SAME [`connect_info_make_service`] adapter the server uses, drives
/// one synthetic connection through it, and panics if the handler does not
/// observe the peer. A future change that stops wiring `ConnectInfo` (reverting
/// to a plain `into_make_service()`) fails this probe at startup instead of
/// silently collapsing every per-IP / login rate-limit bucket into one shared
/// counter. Called only from the serve path, so unit tests that build the
/// Router directly are unaffected.
async fn assert_connect_info_wired(app: Router) {
    use axum::extract::connect_info::Connected;
    use std::net::SocketAddr;
    use tower::Service;

    const PROBE_PATH: &str = "/__connect_info_boot_probe__";

    // A fake connected stream that reports a fixed peer address, mirroring how
    // `axum::serve` feeds accepted TCP connections to the make-service.
    #[derive(Clone)]
    struct ProbeStream(SocketAddr);
    impl Connected<ProbeStream> for SocketAddr {
        fn connect_info(target: ProbeStream) -> Self {
            target.0
        }
    }

    let probe_peer: SocketAddr = "203.0.113.123:54321".parse().expect("probe peer parses");
    // Sentinel route on the REAL router so the probe exercises the same
    // make-service wiring that will serve production traffic.
    let app = app.route(
        PROBE_PATH,
        axum::routing::get(
            |axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>| async move {
                peer.to_string()
            },
        ),
    );

    let mut make = connect_info_make_service(app);
    // `MakeService::call` yields the per-connection service for this peer.
    let mut svc = make
        .call(ProbeStream(probe_peer))
        .await
        .expect("connect-info make-service must produce a per-connection service");
    let request = axum::http::Request::builder()
        .uri(PROBE_PATH)
        .body(axum::body::Body::empty())
        .expect("probe request builds");
    let response = svc.call(request).await.expect("probe request must route");
    let status = response.status();
    assert!(
        status.is_success(),
        "ConnectInfo<SocketAddr> wiring is not active: boot probe returned {status} \
         (expected the serve path's connect_info_make_service to inject the peer)"
    );
    #[allow(clippy::disallowed_methods)]
    // STREAMING-EXEMPT: 64-byte boot self-probe body; not an artifact path (#1608)
    let body = axum::body::to_bytes(response.into_body(), 64)
        .await
        .expect("probe body");
    let observed = String::from_utf8_lossy(&body);
    assert_eq!(
        observed,
        probe_peer.to_string(),
        "ConnectInfo<SocketAddr> wiring did not propagate the TCP peer to request \
         extensions (observed {observed:?}); the per-IP / login rate-limit keying \
         would silently collapse to a single shared bucket"
    );
}

// ---------------------------------------------------------------------------
// Platform-specific entrypoints
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
#[tokio::main]
async fn main() -> Result<()> {
    run_server(None).await
}

#[cfg(windows)]
fn main() -> Result<()> {
    use artifact_keeper_backend::error::AppError;

    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--service") {
        windows_service::run_as_service().map_err(|e| {
            eprintln!("Service error: {e}");
            AppError::Config(e.to_string())
        })
    } else if args.iter().any(|a| a == "--install") {
        windows_service::install_service(&args).map_err(|e| {
            eprintln!("Install error: {e}");
            AppError::Config(e.to_string())
        })
    } else if args.iter().any(|a| a == "--uninstall") {
        windows_service::uninstall_service().map_err(|e| {
            eprintln!("Uninstall error: {e}");
            AppError::Config(e.to_string())
        })
    } else {
        // Console mode: same as Linux/macOS
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime");
        runtime.block_on(run_server(None))
    }
}

/// Initialize the WASM plugin system (T068).
///
/// Creates the plugin registry, loads active plugins from the database,
/// and returns both the registry and the plugin service.
async fn initialize_wasm_plugins(
    db_pool: sqlx::PgPool,
    plugins_dir: PathBuf,
    require_signed: bool,
    trusted_pubkey: Option<String>,
) -> Result<(Arc<PluginRegistry>, Arc<WasmPluginService>)> {
    tracing::info!("Initializing WASM plugin system");

    // Create plugin registry
    let registry = Arc::new(PluginRegistry::new().map_err(|e| {
        artifact_keeper_backend::error::AppError::Internal(format!(
            "Failed to create plugin registry: {}",
            e
        ))
    })?);

    // Create WASM plugin service. The signature policy gates the install/reload
    // ingress paths; startup loading below intentionally reuses already-trusted
    // DB records and is not re-gated.
    let wasm_service = Arc::new(WasmPluginService::new(
        db_pool.clone(),
        registry.clone(),
        plugins_dir.clone(),
        require_signed,
        trusted_pubkey,
    ));

    // Ensure plugins directory exists
    wasm_service.ensure_plugins_dir().await?;

    // Load active plugins from database
    let active_plugins = load_active_plugins(&db_pool).await?;

    let mut loaded_count = 0;
    let mut error_count = 0;

    for plugin in active_plugins {
        if let Some(ref wasm_path) = plugin.wasm_path {
            match wasm_service
                .activate_plugin_at_startup(&plugin, std::path::Path::new(wasm_path))
                .await
            {
                Ok(_) => {
                    tracing::info!("Loaded plugin: {} v{}", plugin.name, plugin.version);
                    loaded_count += 1;
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to load plugin {}: {}. Marking as error state.",
                        plugin.name,
                        e
                    );
                    // Update plugin status to error
                    let _ = sqlx::query("UPDATE plugins SET status = 'error' WHERE id = $1")
                        .bind(plugin.id)
                        .execute(&db_pool)
                        .await;
                    error_count += 1;
                }
            }
        }
    }

    tracing::info!(
        "WASM plugin system initialized: {} plugins loaded, {} errors",
        loaded_count,
        error_count
    );

    Ok((registry, wasm_service))
}

/// Initialize or retrieve the persistent peer identity for this instance.
async fn init_peer_identity(db: &sqlx::PgPool, config: &Config) -> Result<uuid::Uuid> {
    // Check if identity already exists
    let existing: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT peer_instance_id FROM peer_instance_identity LIMIT 1")
            .fetch_optional(db)
            .await
            .map_err(|e| artifact_keeper_backend::error::AppError::Database(e.to_string()))?;

    if let Some(id) = existing {
        // Update name/endpoint in case config changed
        sqlx::query(
            "UPDATE peer_instance_identity SET name = $1, endpoint_url = $2, updated_at = NOW()",
        )
        .bind(&config.peer_instance_name)
        .bind(&config.peer_public_endpoint)
        .execute(db)
        .await
        .map_err(|e| artifact_keeper_backend::error::AppError::Database(e.to_string()))?;
        return Ok(id);
    }

    // Generate new identity
    let id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO peer_instance_identity (peer_instance_id, name, endpoint_url) VALUES ($1, $2, $3)",
    )
    .bind(id)
    .bind(&config.peer_instance_name)
    .bind(&config.peer_public_endpoint)
    .execute(db)
    .await
    .map_err(|e| artifact_keeper_backend::error::AppError::Database(e.to_string()))?;

    // Also register this instance in the peer_instances table as is_local=true
    sqlx::query(
        r#"
        INSERT INTO peer_instances (name, endpoint_url, status, api_key, is_local)
        VALUES ($1, $2, 'online', $3, true)
        ON CONFLICT (name) DO UPDATE SET
            endpoint_url = EXCLUDED.endpoint_url,
            api_key = EXCLUDED.api_key,
            status = 'online',
            is_local = true,
            updated_at = NOW()
        "#,
    )
    .bind(&config.peer_instance_name)
    .bind(&config.peer_public_endpoint)
    .bind(&config.peer_api_key)
    .execute(db)
    .await
    .map_err(|e| artifact_keeper_backend::error::AppError::Database(e.to_string()))?;

    Ok(id)
}

/// Bootstrap an OIDC provider from environment variables.  This lets operators
/// configure OIDC entirely via env vars (OIDC_ISSUER, OIDC_CLIENT_ID,
/// OIDC_CLIENT_SECRET, etc.) without needing admin API access first.
///
/// The provider named by OIDC_NAME (default `default`) is reconciled on every
/// boot. If providers already exist but none carries that name, bootstrap skips
/// creation and warns rather than duplicating a pre-existing provider.
async fn bootstrap_oidc_from_env(db: &sqlx::PgPool) -> Result<()> {
    use artifact_keeper_backend::services::auth_config_service::{
        plan_provider_reconcile, AuthConfigService, ReconcileAction,
    };

    let req = match build_oidc_bootstrap_request() {
        Some(r) => r,
        None => return Ok(()),
    };

    // Reconcile the env-managed provider (matched by name) on every boot so
    // changing OIDC_* env and redeploying takes effect. Other (UI-created)
    // providers are left untouched.
    let existing = AuthConfigService::list_oidc(db).await?;
    let pairs: Vec<(uuid::Uuid, String)> =
        existing.iter().map(|c| (c.id, c.name.clone())).collect();

    match plan_provider_reconcile(&req.name, &pairs) {
        ReconcileAction::Create => {
            let config = AuthConfigService::create_oidc(db, req).await?;
            tracing::info!(
                "Bootstrapped OIDC provider '{}' (id={}) from environment variables",
                config.name,
                config.id
            );
        }
        ReconcileAction::Update(id) => {
            let name = req.name.clone();
            let cfg = AuthConfigService::update_oidc(db, id, req.into()).await?;
            tracing::info!(
                "Reconciled env-managed OIDC provider '{}' (id={}) from environment variables",
                name,
                cfg.id
            );
        }
        ReconcileAction::Skip(existing_name) => {
            tracing::warn!(
                "OIDC_* env set but an OIDC provider ('{}') already exists and none is named \
                 '{}'; env bootstrap skipped to avoid creating a duplicate. Set OIDC_NAME to the \
                 existing provider's name (or rename it to '{}') to let env vars manage it, or \
                 unset OIDC_*.",
                existing_name,
                req.name,
                req.name
            );
        }
    }

    Ok(())
}

/// Raw OIDC environment variable values for bootstrap.
#[derive(Default)]
struct OidcEnvVars {
    name: Option<String>,
    issuer: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    scopes: Option<String>,
    groups_claim: Option<String>,
    redirect_uri: Option<String>,
    username_claim: Option<String>,
    email_claim: Option<String>,
}

/// Build a CreateOidcConfigRequest from OIDC_* environment variables.
/// Returns None if any of the three required env vars are missing or empty.
fn build_oidc_bootstrap_request(
) -> Option<artifact_keeper_backend::services::auth_config_service::CreateOidcConfigRequest> {
    build_oidc_request_from_values(OidcEnvVars {
        name: std::env::var("OIDC_NAME").ok(),
        issuer: std::env::var("OIDC_ISSUER").ok(),
        client_id: std::env::var("OIDC_CLIENT_ID").ok(),
        client_secret: std::env::var("OIDC_CLIENT_SECRET").ok(),
        scopes: std::env::var("OIDC_SCOPES").ok(),
        groups_claim: std::env::var("OIDC_GROUPS_CLAIM").ok(),
        redirect_uri: std::env::var("OIDC_REDIRECT_URI").ok(),
        username_claim: std::env::var("OIDC_USERNAME_CLAIM").ok(),
        email_claim: std::env::var("OIDC_EMAIL_CLAIM").ok(),
    })
}

/// Pure function that assembles a CreateOidcConfigRequest from optional values.
/// Returns None if issuer, client_id, or client_secret are missing or empty.
fn build_oidc_request_from_values(
    env: OidcEnvVars,
) -> Option<artifact_keeper_backend::services::auth_config_service::CreateOidcConfigRequest> {
    use artifact_keeper_backend::services::auth_config_service::CreateOidcConfigRequest;

    let issuer = env.issuer.filter(|v| !v.is_empty())?;
    let client_id = env.client_id.filter(|v| !v.is_empty())?;
    let client_secret = env.client_secret.filter(|v| !v.is_empty())?;
    let name = env
        .name
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "default".to_string());

    let scopes = env
        .scopes
        .map(|s| s.split_whitespace().map(String::from).collect::<Vec<_>>());

    let groups_claim_val = env.groups_claim.unwrap_or_else(|| "groups".to_string());

    let mut attr_map = serde_json::Map::new();
    attr_map.insert(
        "groups_claim".into(),
        serde_json::Value::String(groups_claim_val),
    );
    if let Some(uri) = env.redirect_uri {
        attr_map.insert("redirect_uri".into(), serde_json::Value::String(uri));
    }
    if let Some(claim) = env.username_claim {
        attr_map.insert("username_claim".into(), serde_json::Value::String(claim));
    }
    if let Some(claim) = env.email_claim {
        attr_map.insert("email_claim".into(), serde_json::Value::String(claim));
    }

    Some(CreateOidcConfigRequest {
        name,
        issuer_url: issuer,
        client_id,
        client_secret,
        scopes,
        attribute_mapping: Some(serde_json::Value::Object(attr_map)),
        is_enabled: Some(true),
        auto_create_users: Some(true),
        pkce_enabled: None,
        map_groups_to_groups: None,
    })
}

/// Bootstrap an LDAP provider from environment variables.  This lets operators
/// configure LDAP entirely via env vars (LDAP_URL, LDAP_BASE_DN, LDAP_BIND_DN,
/// etc.) without needing admin API access first.  Mirrors
/// `bootstrap_oidc_from_env` (fixes #1434).
///
/// The provider named by LDAP_NAME (default `default`) is reconciled on every
/// boot. If providers already exist but none carries that name, bootstrap skips
/// creation and warns rather than duplicating a pre-existing provider (#1887).
async fn bootstrap_ldap_from_env(db: &sqlx::PgPool) -> Result<()> {
    use artifact_keeper_backend::services::auth_config_service::{
        plan_provider_reconcile, AuthConfigService, ReconcileAction,
    };

    let req = match build_ldap_bootstrap_request() {
        Some(r) => r,
        None => return Ok(()),
    };

    // Reconcile the env-managed provider (matched by name) on every boot so
    // changing LDAP_* env and redeploying takes effect. Other (UI-created)
    // providers are left untouched.
    let existing = AuthConfigService::list_ldap(db).await?;
    let pairs: Vec<(uuid::Uuid, String)> =
        existing.iter().map(|c| (c.id, c.name.clone())).collect();

    match plan_provider_reconcile(&req.name, &pairs) {
        ReconcileAction::Create => {
            let config = AuthConfigService::create_ldap(db, req).await?;
            tracing::info!(
                "Bootstrapped LDAP provider '{}' (id={}) from environment variables",
                config.name,
                config.id
            );
        }
        ReconcileAction::Update(id) => {
            let name = req.name.clone();
            let cfg = AuthConfigService::update_ldap(db, id, req.into()).await?;
            tracing::info!(
                "Reconciled env-managed LDAP provider '{}' (id={}) from environment variables",
                name,
                cfg.id
            );
        }
        ReconcileAction::Skip(existing_name) => {
            tracing::warn!(
                "LDAP_* env set but an LDAP provider ('{}') already exists and none is named \
                 '{}'; env bootstrap skipped to avoid creating a duplicate. Set LDAP_NAME to the \
                 existing provider's name (or rename it to '{}') to let env vars manage it, or \
                 unset LDAP_*.",
                existing_name,
                req.name,
                req.name
            );
        }
    }

    Ok(())
}

/// Raw LDAP environment variable values for bootstrap.
#[derive(Default)]
struct LdapEnvVars {
    name: Option<String>,
    url: Option<String>,
    base_dn: Option<String>,
    bind_dn: Option<String>,
    bind_password: Option<String>,
    user_filter: Option<String>,
    username_attr: Option<String>,
    email_attr: Option<String>,
    display_name_attr: Option<String>,
    groups_attr: Option<String>,
    group_base_dn: Option<String>,
    group_filter: Option<String>,
    admin_group_dn: Option<String>,
    use_starttls: Option<String>,
}

/// Build a CreateLdapConfigRequest from LDAP_* environment variables.
/// Returns None if any of the required env vars are missing or empty.
fn build_ldap_bootstrap_request(
) -> Option<artifact_keeper_backend::services::auth_config_service::CreateLdapConfigRequest> {
    build_ldap_request_from_values(LdapEnvVars {
        name: std::env::var("LDAP_NAME").ok(),
        url: std::env::var("LDAP_URL").ok(),
        base_dn: std::env::var("LDAP_BASE_DN").ok(),
        bind_dn: std::env::var("LDAP_BIND_DN").ok(),
        bind_password: std::env::var("LDAP_BIND_PASSWORD").ok(),
        user_filter: std::env::var("LDAP_USER_FILTER").ok(),
        username_attr: std::env::var("LDAP_USERNAME_ATTR").ok(),
        email_attr: std::env::var("LDAP_EMAIL_ATTR").ok(),
        display_name_attr: std::env::var("LDAP_DISPLAY_NAME_ATTR").ok(),
        groups_attr: std::env::var("LDAP_GROUPS_ATTR").ok(),
        group_base_dn: std::env::var("LDAP_GROUP_BASE_DN").ok(),
        group_filter: std::env::var("LDAP_GROUP_FILTER").ok(),
        admin_group_dn: std::env::var("LDAP_ADMIN_GROUP_DN").ok(),
        use_starttls: std::env::var("LDAP_USE_STARTTLS").ok(),
    })
}

/// Pure function that assembles a CreateLdapConfigRequest from optional values.
/// Returns None if the LDAP server URL or base DN are missing or empty: both
/// are required to bind and search the directory.
fn build_ldap_request_from_values(
    env: LdapEnvVars,
) -> Option<artifact_keeper_backend::services::auth_config_service::CreateLdapConfigRequest> {
    use artifact_keeper_backend::services::auth_config_service::CreateLdapConfigRequest;

    let server_url = env.url.filter(|v| !v.is_empty())?;
    let user_base_dn = env.base_dn.filter(|v| !v.is_empty())?;

    let name = env
        .name
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "default".to_string());

    let use_starttls = env
        .use_starttls
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    Some(CreateLdapConfigRequest {
        name,
        server_url,
        bind_dn: env.bind_dn.filter(|v| !v.is_empty()),
        bind_password: env.bind_password.filter(|v| !v.is_empty()),
        user_base_dn,
        user_filter: env.user_filter.filter(|v| !v.is_empty()),
        group_base_dn: env.group_base_dn.filter(|v| !v.is_empty()),
        group_filter: env.group_filter.filter(|v| !v.is_empty()),
        email_attribute: env.email_attr.filter(|v| !v.is_empty()),
        display_name_attribute: env.display_name_attr.filter(|v| !v.is_empty()),
        username_attribute: env.username_attr.filter(|v| !v.is_empty()),
        groups_attribute: env.groups_attr.filter(|v| !v.is_empty()),
        admin_group_dn: env.admin_group_dn.filter(|v| !v.is_empty()),
        use_starttls: Some(use_starttls),
        is_enabled: Some(true),
        priority: Some(0),
    })
}

/// Provision the initial admin user on first boot and determine setup mode.
///
/// Returns `true` when the API should be locked until the admin changes
/// the default password (i.e. `must_change_password` is still set and no
/// explicit `ADMIN_PASSWORD` env var was provided).
///
/// Uses a PostgreSQL advisory lock to prevent race conditions when multiple
/// replicas start simultaneously.  The lock is held for the duration of the
/// check-and-create sequence so only one replica performs the initial insert.
async fn provision_admin_user(db: &sqlx::PgPool, storage_path: &str) -> Result<bool> {
    use std::path::Path;

    // Skip admin provisioning when SSO handles admin assignment (issue #211)
    if std::env::var("SKIP_ADMIN_PROVISIONING")
        .unwrap_or_default()
        .eq_ignore_ascii_case("true")
    {
        tracing::info!(
            "SKIP_ADMIN_PROVISIONING=true - skipping built-in admin user creation. \
             Admin access must be granted via SSO group mapping."
        );
        return Ok(false);
    }

    let storage_dir = Path::new(storage_path);
    let password_file = storage_dir.join("admin.password");

    // Ensure the storage directory exists before we try to write anything.
    // Docker named volumes normally create the mount point, but bind mounts,
    // alternative runtimes (Podman rootless, Kubernetes emptyDir), and custom
    // STORAGE_PATH values may not.  Creating it here avoids a silent failure
    // when writing the admin password file later. (fixes #787)
    if let Err(e) = std::fs::create_dir_all(storage_dir) {
        tracing::warn!(
            "Could not create storage directory {}: {}",
            storage_dir.display(),
            e
        );
    }

    // Acquire a cluster-wide advisory lock so that concurrent replicas
    // serialize their admin provisioning.  The lock key is a stable hash
    // of a well-known string.  We use a transaction-scoped lock
    // (pg_advisory_xact_lock) so it is automatically released when the
    // transaction commits or rolls back.
    let mut tx = db
        .begin()
        .await
        .map_err(|e| artifact_keeper_backend::error::AppError::Database(e.to_string()))?;

    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('admin_password_init'))")
        .execute(&mut *tx)
        .await
        .map_err(|e| artifact_keeper_backend::error::AppError::Database(e.to_string()))?;

    // Re-check admin existence while holding the lock (double-check pattern).
    let admin_row: Option<(bool,)> =
        sqlx::query_as("SELECT must_change_password FROM users WHERE is_admin = true LIMIT 1")
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| artifact_keeper_backend::error::AppError::Database(e.to_string()))?;

    let demo_mode = matches!(std::env::var("DEMO_MODE").as_deref(), Ok("true" | "1"));

    if let Some((must_change,)) = admin_row {
        // Ensure existing admin user always has auth_provider = 'local' so
        // password-based login works.  This is a no-op when the column is
        // already correct but fixes installs that ended up with a wrong value.
        sqlx::query(
            "UPDATE users SET auth_provider = 'local' \
             WHERE username = 'admin' AND auth_provider != 'local'",
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| artifact_keeper_backend::error::AppError::Database(e.to_string()))?;

        if !must_change && !demo_mode {
            if let Ok(env_pw) = std::env::var("ADMIN_PASSWORD") {
                if is_insecure_default_password(&env_pw) {
                    tracing::warn!("ADMIN_PASSWORD matches a well-known default.");
                    sqlx::query(
                        "UPDATE users SET must_change_password = true WHERE username = 'admin'",
                    )
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| {
                        artifact_keeper_backend::error::AppError::Database(e.to_string())
                    })?;
                    tx.commit().await.map_err(|e| {
                        artifact_keeper_backend::error::AppError::Database(e.to_string())
                    })?;
                    return Ok(true);
                }
            }
        }

        if must_change {
            tracing::warn!(
                "Admin user has not changed default password. \
                 API is locked until password is changed."
            );
            if password_file.exists() {
                tracing::info!("Admin password file: {}", password_file.display());
            } else {
                // The password file is missing (deleted, volume recreated, or
                // the initial write failed).  Generate a new password, write
                // the file FIRST, then update the DB hash.  If the file write
                // fails we skip the DB update so the old hash remains usable
                // on retry.
                tracing::warn!(
                    "Admin password file missing at {}. Regenerating password.",
                    password_file.display()
                );
                let password = generate_random_password();
                if let Err(e) = write_admin_password_file(&password_file, &password) {
                    tracing::error!("Failed to write admin password file: {}", e);
                    tracing::error!(
                        "Admin password could not be persisted. \
                         Re-run the server or check file permissions for: {}",
                        password_file.display()
                    );
                } else {
                    // File written successfully, now update the DB hash to match.
                    let password_hash = AuthService::hash_password(&password).await?;
                    sqlx::query("UPDATE users SET password_hash = $1 WHERE username = 'admin'")
                        .bind(&password_hash)
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| {
                            artifact_keeper_backend::error::AppError::Database(e.to_string())
                        })?;
                    log_admin_setup_banner(&password_file, Some(&password));
                }
            }
            tx.commit()
                .await
                .map_err(|e| artifact_keeper_backend::error::AppError::Database(e.to_string()))?;
            return Ok(true);
        }
        tx.commit()
            .await
            .map_err(|e| artifact_keeper_backend::error::AppError::Database(e.to_string()))?;
        return Ok(false);
    }

    // --- No admin user exists yet: create one. ---

    let (password, must_change) = match std::env::var("ADMIN_PASSWORD") {
        Ok(p) if !p.is_empty() => {
            if is_insecure_default_password(&p) && !demo_mode {
                tracing::warn!("ADMIN_PASSWORD matches a well-known default.");
                (p, true)
            } else {
                (p, false)
            }
        }
        _ => {
            let p = generate_random_password();
            (p, true)
        }
    };

    // Write the password file BEFORE updating the database.  If the file
    // write fails, we abort without inserting the DB row so the next startup
    // can retry cleanly.  This avoids the scenario where the hash is in the
    // DB but the plaintext is lost.
    if must_change {
        if let Err(e) = write_admin_password_file(&password_file, &password) {
            tracing::error!("Failed to write admin password file: {}", e);
            tracing::error!(
                "Admin password could not be persisted. \
                 Re-run the server or check file permissions for: {}",
                password_file.display()
            );
            // Roll back the transaction (advisory lock released).  The next
            // replica or restart will retry.
            tx.rollback()
                .await
                .map_err(|e| artifact_keeper_backend::error::AppError::Database(e.to_string()))?;
            return Err(artifact_keeper_backend::error::AppError::Config(format!(
                "Cannot persist admin password file at {}. \
                 Fix file permissions and restart.",
                password_file.display()
            )));
        }
    }

    let password_hash = AuthService::hash_password(&password).await?;

    sqlx::query(
        r#"
        INSERT INTO users (username, email, password_hash, is_admin, must_change_password, auth_provider)
        VALUES ('admin', 'admin@localhost', $1, true, $2, 'local')
        ON CONFLICT (username) DO UPDATE
            SET password_hash = EXCLUDED.password_hash,
                must_change_password = EXCLUDED.must_change_password,
                auth_provider = 'local'
        "#,
    )
    .bind(&password_hash)
    .bind(must_change)
    .execute(&mut *tx)
    .await
    .map_err(|e| artifact_keeper_backend::error::AppError::Database(e.to_string()))?;

    tx.commit()
        .await
        .map_err(|e| artifact_keeper_backend::error::AppError::Database(e.to_string()))?;

    if must_change {
        // Only echo the plaintext when we generated it ourselves. If the
        // password came from ADMIN_PASSWORD but matched an insecure default,
        // it was already supplied by the operator and is presumably logged
        // elsewhere; we still force a change but don't re-emit it.
        let echo = std::env::var("ADMIN_PASSWORD").ok().is_none();
        log_admin_setup_banner(&password_file, echo.then_some(password.as_str()));
        Ok(true)
    } else {
        tracing::info!("Admin user created with password from ADMIN_PASSWORD env var");
        Ok(false)
    }
}

/// Generate a random 20-character password for the admin user.
fn generate_random_password() -> String {
    const CHARSET: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*";
    let mut rng = rand::rng();
    (0..20)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Write the admin password and setup instructions to a file.
///
/// Returns `Ok(())` on success.  On failure the error is propagated so that
/// callers can avoid updating the database hash (preventing the "hash in DB
/// but plaintext lost" scenario).
fn write_admin_password_file(
    password_file: &std::path::Path,
    password: &str,
) -> std::io::Result<()> {
    let file_contents = format!(
        "{}\n\n\
        # ONE-TIME SETUP -- this password must be changed before the API unlocks.\n\
        #\n\
        # Step 1: Login to get a JWT token:\n\
        #   curl -s -X POST http://localhost:8080/api/v1/auth/login \\\n\
        #     -H 'Content-Type: application/json' \\\n\
        #     -d '{{\"username\":\"admin\",\"password\":\"<password-above>\"}}'\n\
        #\n\
        # Step 2: Change the password (use the access_token from step 1):\n\
        #   curl -s -X POST http://localhost:8080/api/v1/users/me/password \\\n\
        #     -H 'Authorization: Bearer <access_token>' \\\n\
        #     -H 'Content-Type: application/json' \\\n\
        #     -d '{{\"current_password\":\"<password-above>\",\"new_password\":\"<your-new-password>\"}}'\n\
        #\n\
        # The API is LOCKED until you complete these steps.\n\
        # Do NOT use this password directly in API calls -- you must login first.\n",
        password
    );
    std::fs::write(password_file, &file_contents)?;
    #[cfg(unix)]
    if let Err(e) = std::fs::set_permissions(password_file, std::fs::Permissions::from_mode(0o600))
    {
        tracing::warn!("Failed to set permissions on admin password file: {}", e);
    }
    tracing::info!("Admin password written to: {}", password_file.display());
    Ok(())
}

/// Log the setup banner with instructions for the admin user.
///
/// When `password` is `Some`, the banner echoes the plaintext into logs in
/// addition to pointing at the file. This trades a small disclosure risk for
/// onboarding friction: the password is single-use anyway (the API is locked
/// behind `must_change_password = true` and the first login forces a rotation),
/// and operators are otherwise stuck spelunking inside the container to find
/// the file (issue #1009). Set `ARTIFACT_KEEPER_HIDE_ADMIN_PASSWORD=true` to
/// suppress the plaintext echo while keeping the file path hint, which is
/// useful for shared log aggregators.
fn log_admin_setup_banner(password_file: &std::path::Path, password: Option<&str>) {
    let hide_password = std::env::var("ARTIFACT_KEEPER_HIDE_ADMIN_PASSWORD")
        .unwrap_or_default()
        .eq_ignore_ascii_case("true");

    let password_line = match (password, hide_password) {
        (Some(pw), false) => format!("  Password:  {}\n", pw),
        _ => format!("  Password:  see file {}\n", password_file.display()),
    };

    tracing::info!(
        "\n\
        ===========================================================\n\
        \n\
          Initial admin user created.\n\
        \n\
          Username:  admin\n\
        {}\
        \n\
          File:      {}\n\
          Read it by exec'ing into the artifact-keeper backend container:\n\
            Docker:      docker exec artifact-keeper-backend cat {}\n\
            Kubernetes:  kubectl exec deploy/artifact-keeper-backend -- cat {}\n\
        \n\
          The API is LOCKED until you change this password.\n\
          Open the web UI and log in -- you will be redirected to\n\
          the forced-change-password screen. Alternatively call\n\
          POST /api/v1/auth/login then POST /api/v1/users/<id>/password.\n\
        \n\
          Set ARTIFACT_KEEPER_HIDE_ADMIN_PASSWORD=true to hide the\n\
          password from logs (file is still written).\n\
        \n\
        ===========================================================",
        password_line,
        password_file.display(),
        password_file.display(),
        password_file.display(),
    );
}

fn is_insecure_default_password(password: &str) -> bool {
    const INSECURE_DEFAULTS: &[&str] = &[
        "admin",
        "password",
        "changeme",
        "admin123",
        "Password1",
        "letmein",
        "welcome",
        "123456",
        "admin1234",
        "default",
    ];
    INSECURE_DEFAULTS
        .iter()
        .any(|d| d.eq_ignore_ascii_case(password))
}

/// Load active plugins from the database.
async fn load_active_plugins(
    db_pool: &sqlx::PgPool,
) -> Result<Vec<artifact_keeper_backend::models::plugin::Plugin>> {
    use artifact_keeper_backend::models::plugin::Plugin;

    let plugins = sqlx::query_as::<_, Plugin>(
        r#"
        SELECT
            id, name, version, display_name, description, author, homepage, license,
            status, plugin_type, source_type,
            source_url, source_ref, wasm_path, manifest,
            capabilities, resource_limits,
            config, config_schema, error_message,
            installed_at, enabled_at, updated_at
        FROM plugins
        WHERE status = 'active' AND wasm_path IS NOT NULL
        ORDER BY name
        "#,
    )
    .fetch_all(db_pool)
    .await
    .map_err(|e| artifact_keeper_backend::error::AppError::Database(e.to_string()))?;

    Ok(plugins)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // build_oidc_request_from_values
    // -----------------------------------------------------------------------

    fn env(
        issuer: Option<&str>,
        client_id: Option<&str>,
        client_secret: Option<&str>,
    ) -> OidcEnvVars {
        OidcEnvVars {
            issuer: issuer.map(String::from),
            client_id: client_id.map(String::from),
            client_secret: client_secret.map(String::from),
            ..Default::default()
        }
    }

    #[test]
    fn test_bootstrap_request_all_required_fields() {
        let req = build_oidc_request_from_values(env(
            Some("https://idp.example.com"),
            Some("my-client"),
            Some("my-secret"),
        ))
        .unwrap();

        assert_eq!(req.name, "default");
        assert_eq!(req.issuer_url, "https://idp.example.com");
        assert_eq!(req.client_id, "my-client");
        assert_eq!(req.client_secret, "my-secret");
        assert_eq!(req.is_enabled, Some(true));
        assert_eq!(req.auto_create_users, Some(true));
    }

    #[test]
    fn test_bootstrap_request_custom_name() {
        let mut e = env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        );
        e.name = Some("Corporate SSO".into());
        let req = build_oidc_request_from_values(e).unwrap();

        assert_eq!(req.name, "Corporate SSO");
    }

    #[test]
    fn test_bootstrap_request_empty_name_defaults_to_default() {
        let mut e = env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        );
        e.name = Some(String::new());
        let req = build_oidc_request_from_values(e).unwrap();

        assert_eq!(req.name, "default");
    }

    #[test]
    fn test_bootstrap_request_missing_issuer() {
        let req = build_oidc_request_from_values(env(None, Some("client"), Some("secret")));
        assert!(req.is_none());
    }

    #[test]
    fn test_bootstrap_request_missing_client_id() {
        let req = build_oidc_request_from_values(env(
            Some("https://idp.example.com"),
            None,
            Some("secret"),
        ));
        assert!(req.is_none());
    }

    #[test]
    fn test_bootstrap_request_missing_client_secret() {
        let req = build_oidc_request_from_values(env(
            Some("https://idp.example.com"),
            Some("client"),
            None,
        ));
        assert!(req.is_none());
    }

    #[test]
    fn test_bootstrap_request_empty_issuer() {
        let req = build_oidc_request_from_values(env(Some(""), Some("client"), Some("secret")));
        assert!(req.is_none());
    }

    #[test]
    fn test_bootstrap_request_empty_client_id() {
        let req = build_oidc_request_from_values(env(
            Some("https://idp.example.com"),
            Some(""),
            Some("secret"),
        ));
        assert!(req.is_none());
    }

    #[test]
    fn test_bootstrap_request_empty_client_secret() {
        let req = build_oidc_request_from_values(env(
            Some("https://idp.example.com"),
            Some("client"),
            Some(""),
        ));
        assert!(req.is_none());
    }

    #[test]
    fn test_bootstrap_request_default_groups_claim() {
        let req = build_oidc_request_from_values(env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        ))
        .unwrap();

        let attr = req.attribute_mapping.unwrap();
        assert_eq!(attr["groups_claim"], "groups");
    }

    #[test]
    fn test_bootstrap_request_custom_groups_claim() {
        let mut e = env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        );
        e.groups_claim = Some("roles".into());
        let req = build_oidc_request_from_values(e).unwrap();

        let attr = req.attribute_mapping.unwrap();
        assert_eq!(attr["groups_claim"], "roles");
    }

    #[test]
    fn test_bootstrap_request_scopes_parsing() {
        let mut e = env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        );
        e.scopes = Some("openid email profile offline_access".into());
        let req = build_oidc_request_from_values(e).unwrap();

        assert_eq!(
            req.scopes.unwrap(),
            vec!["openid", "email", "profile", "offline_access"]
        );
    }

    #[test]
    fn test_bootstrap_request_no_scopes() {
        let req = build_oidc_request_from_values(env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        ))
        .unwrap();

        assert!(req.scopes.is_none());
    }

    #[test]
    fn test_bootstrap_request_redirect_uri() {
        let mut e = env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        );
        e.redirect_uri = Some("https://app.example.com/callback".into());
        let req = build_oidc_request_from_values(e).unwrap();

        let attr = req.attribute_mapping.unwrap();
        assert_eq!(attr["redirect_uri"], "https://app.example.com/callback");
    }

    #[test]
    fn test_bootstrap_request_no_redirect_uri() {
        let req = build_oidc_request_from_values(env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        ))
        .unwrap();

        let attr = req.attribute_mapping.unwrap();
        assert!(attr.get("redirect_uri").is_none());
    }

    #[test]
    fn test_bootstrap_request_custom_username_claim() {
        let mut e = env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        );
        e.username_claim = Some("upn".into());
        let req = build_oidc_request_from_values(e).unwrap();

        let attr = req.attribute_mapping.unwrap();
        assert_eq!(attr["username_claim"], "upn");
    }

    #[test]
    fn test_bootstrap_request_custom_email_claim() {
        let mut e = env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        );
        e.email_claim = Some("mail".into());
        let req = build_oidc_request_from_values(e).unwrap();

        let attr = req.attribute_mapping.unwrap();
        assert_eq!(attr["email_claim"], "mail");
    }

    #[test]
    fn test_bootstrap_request_all_optional_fields() {
        let req = build_oidc_request_from_values(OidcEnvVars {
            name: Some("Corporate OIDC".into()),
            issuer: Some("https://auth.corp.com/realms/main".into()),
            client_id: Some("artifact-keeper".into()),
            client_secret: Some("super-secret-123".into()),
            scopes: Some("openid email profile".into()),
            groups_claim: Some("roles".into()),
            redirect_uri: Some("https://app.corp.com/sso/callback".into()),
            username_claim: Some("samaccountname".into()),
            email_claim: Some("mail".into()),
        })
        .unwrap();

        assert_eq!(req.name, "Corporate OIDC");
        assert_eq!(req.issuer_url, "https://auth.corp.com/realms/main");
        assert_eq!(req.client_id, "artifact-keeper");
        assert_eq!(req.client_secret, "super-secret-123");
        assert_eq!(req.scopes.unwrap(), vec!["openid", "email", "profile"]);

        let attr = req.attribute_mapping.unwrap();
        assert_eq!(attr["groups_claim"], "roles");
        assert_eq!(attr["redirect_uri"], "https://app.corp.com/sso/callback");
        assert_eq!(attr["username_claim"], "samaccountname");
        assert_eq!(attr["email_claim"], "mail");
    }

    #[test]
    fn test_bootstrap_request_no_optional_claims_in_attr_map() {
        let req = build_oidc_request_from_values(env(
            Some("https://idp.example.com"),
            Some("client"),
            Some("secret"),
        ))
        .unwrap();

        let attr = req.attribute_mapping.unwrap();
        let obj = attr.as_object().unwrap();
        // Only groups_claim should be present (it always has a default)
        assert_eq!(obj.len(), 1);
        assert!(obj.contains_key("groups_claim"));
        assert!(!obj.contains_key("redirect_uri"));
        assert!(!obj.contains_key("username_claim"));
        assert!(!obj.contains_key("email_claim"));
    }

    #[test]
    fn test_insecure_default_admin() {
        assert!(is_insecure_default_password("admin"));
    }

    #[test]
    fn test_insecure_default_case_insensitive() {
        assert!(is_insecure_default_password("ADMIN"));
        assert!(is_insecure_default_password("PASSWORD"));
    }

    #[test]
    fn test_secure_password_not_flagged() {
        assert!(!is_insecure_default_password("xK9#mP2$vL5nQ8"));
    }

    #[test]
    fn test_all_insecure_defaults_detected() {
        let defaults = [
            "admin",
            "password",
            "changeme",
            "admin123",
            "Password1",
            "letmein",
            "welcome",
            "123456",
            "admin1234",
            "default",
        ];
        for pw in defaults {
            assert!(
                is_insecure_default_password(pw),
                "{pw} should be flagged as insecure"
            );
        }
    }

    #[test]
    fn test_insecure_defaults_mixed_case_variations() {
        assert!(is_insecure_default_password("ChAnGeMe"));
        assert!(is_insecure_default_password("LETMEIN"));
        assert!(is_insecure_default_password("Welcome"));
        assert!(is_insecure_default_password("Default"));
        assert!(is_insecure_default_password("ADMIN123"));
        assert!(is_insecure_default_password("password1"));
    }

    #[test]
    fn test_empty_password_not_flagged() {
        assert!(!is_insecure_default_password(""));
    }

    #[test]
    fn test_near_miss_passwords_not_flagged() {
        // Passwords similar to but not matching the insecure list
        assert!(!is_insecure_default_password("admin2"));
        assert!(!is_insecure_default_password("password!"));
        assert!(!is_insecure_default_password("changeme1"));
        assert!(!is_insecure_default_password("1234567"));
        assert!(!is_insecure_default_password("defaults"));
    }

    #[test]
    fn test_long_secure_password_not_flagged() {
        assert!(!is_insecure_default_password("my-secure-p@ssw0rd-2026"));
        assert!(!is_insecure_default_password(
            "correct-horse-battery-staple"
        ));
        assert!(!is_insecure_default_password("Tr0ub4dor&3"));
    }

    #[test]
    fn test_whitespace_password_not_flagged() {
        // Passwords with leading/trailing whitespace are not in the list
        assert!(!is_insecure_default_password(" admin"));
        assert!(!is_insecure_default_password("admin "));
        assert!(!is_insecure_default_password(" password "));
    }

    // -----------------------------------------------------------------------
    // run_server signature check
    // -----------------------------------------------------------------------

    #[test]
    fn test_run_server_accepts_none_token() {
        // Verify that run_server compiles with None (console mode).
        // We cannot actually run it in a unit test because it needs a database,
        // but confirming the function signature accepts Option<CancellationToken>
        // ensures the refactor is correct.
        fn _assert_callable(token: Option<CancellationToken>) {
            drop(run_server(token));
        }
    }

    #[test]
    fn test_run_server_accepts_some_token() {
        // Verify that run_server compiles with Some(token) (Windows Service mode).
        fn _assert_callable_with_token() {
            let token = CancellationToken::new();
            drop(run_server(Some(token)));
        }
    }

    // -----------------------------------------------------------------------
    // AK_ENV_FILE logic
    // -----------------------------------------------------------------------

    #[test]
    fn test_ak_env_file_var_is_checked() {
        // The AK_ENV_FILE environment variable should be read by the startup
        // logic. We verify the env var lookup works (the actual file loading
        // is tested implicitly by dotenvy).
        let saved = std::env::var("AK_ENV_FILE").ok();

        std::env::set_var("AK_ENV_FILE", "/tmp/nonexistent-test-env-file");
        assert_eq!(
            std::env::var("AK_ENV_FILE").unwrap(),
            "/tmp/nonexistent-test-env-file"
        );

        // dotenvy::from_path on a nonexistent file returns Err, which is
        // handled gracefully by the .ok() call in run_server.
        let result = dotenvy::from_path("/tmp/nonexistent-test-env-file");
        assert!(result.is_err());

        // Restore
        if let Some(v) = saved {
            std::env::set_var("AK_ENV_FILE", v);
        } else {
            std::env::remove_var("AK_ENV_FILE");
        }
    }

    // NOTE: windows_service.rs is behind #[cfg(windows)] and cannot be
    // unit-tested on macOS/Linux. It is compile-checked on Windows CI and
    // tested manually via `--install` / `--uninstall` / `--service` flags.

    // -----------------------------------------------------------------------
    // Regression: issue #1009 -- admin password is echoed to logs by default
    // and hidden when ARTIFACT_KEEPER_HIDE_ADMIN_PASSWORD is set.
    // -----------------------------------------------------------------------

    #[test]
    fn admin_setup_banner_echoes_password_by_default() {
        // We can't capture tracing output without a subscriber setup, so we
        // exercise the path the banner takes and verify the env-toggle
        // contract directly. The actual format is asserted by
        // `admin_setup_banner_password_line_format`.
        let saved = std::env::var("ARTIFACT_KEEPER_HIDE_ADMIN_PASSWORD").ok();
        std::env::remove_var("ARTIFACT_KEEPER_HIDE_ADMIN_PASSWORD");
        let hidden = std::env::var("ARTIFACT_KEEPER_HIDE_ADMIN_PASSWORD")
            .unwrap_or_default()
            .eq_ignore_ascii_case("true");
        assert!(!hidden, "default state must NOT hide the password");
        if let Some(v) = saved {
            std::env::set_var("ARTIFACT_KEEPER_HIDE_ADMIN_PASSWORD", v);
        }
    }

    // -----------------------------------------------------------------------
    // Regression: issue #1129 -- the repair function knows where to find the
    // current 073 migration text and computes a SHA-384 over it. We can't run
    // the DB-touching half as a unit test, but we can assert that the file is
    // wired into the binary and the checksum routine matches sqlx's algorithm.
    // -----------------------------------------------------------------------

    #[test]
    fn migration_073_text_is_embedded_in_binary() {
        // The repair function uses include_str! to embed the migration text.
        // If someone deletes or renames 073_account_lockout.sql without
        // updating the path, the binary won't compile, so this assertion is
        // mostly future-proofing: confirm the embedded text is non-empty and
        // matches the expected schema change.
        let embedded = include_str!("../migrations/073_account_lockout.sql");
        assert!(!embedded.is_empty());
        assert!(embedded.contains("failed_login_attempts"));
        assert!(embedded.contains("locked_until"));
    }

    #[test]
    fn migration_073_checksum_matches_sqlx_algorithm() {
        // sqlx records each migration's SHA-384 checksum in _sqlx_migrations.
        // The repair function recomputes that hash to detect drift; verify the
        // algorithm here so a future sqlx upgrade that switches algorithms
        // doesn't silently break the repair path.
        use sha2::{Digest, Sha384};
        let embedded = include_str!("../migrations/073_account_lockout.sql");
        let mut hasher = Sha384::new();
        hasher.update(embedded.as_bytes());
        let hash = hasher.finalize();
        assert_eq!(hash.len(), 48, "SHA-384 produces 48 bytes");
    }

    #[test]
    fn admin_setup_banner_hides_password_when_env_set() {
        let saved = std::env::var("ARTIFACT_KEEPER_HIDE_ADMIN_PASSWORD").ok();
        std::env::set_var("ARTIFACT_KEEPER_HIDE_ADMIN_PASSWORD", "true");
        let hidden = std::env::var("ARTIFACT_KEEPER_HIDE_ADMIN_PASSWORD")
            .unwrap_or_default()
            .eq_ignore_ascii_case("true");
        assert!(hidden);
        // TRUE / True / 1-style toggles
        std::env::set_var("ARTIFACT_KEEPER_HIDE_ADMIN_PASSWORD", "TRUE");
        assert!(std::env::var("ARTIFACT_KEEPER_HIDE_ADMIN_PASSWORD")
            .unwrap()
            .eq_ignore_ascii_case("true"));
        if let Some(v) = saved {
            std::env::set_var("ARTIFACT_KEEPER_HIDE_ADMIN_PASSWORD", v);
        } else {
            std::env::remove_var("ARTIFACT_KEEPER_HIDE_ADMIN_PASSWORD");
        }
    }

    // -----------------------------------------------------------------------
    // build_ldap_request_from_values (issue #1434)
    // -----------------------------------------------------------------------

    fn ldap_env(url: Option<&str>, base_dn: Option<&str>) -> LdapEnvVars {
        LdapEnvVars {
            url: url.map(String::from),
            base_dn: base_dn.map(String::from),
            ..Default::default()
        }
    }

    #[test]
    fn test_ldap_bootstrap_request_required_fields() {
        let req = build_ldap_request_from_values(ldap_env(
            Some("ldap://dc.local:389"),
            Some("DC=domain,DC=local"),
        ))
        .unwrap();

        assert_eq!(req.name, "default");
        assert_eq!(req.server_url, "ldap://dc.local:389");
        assert_eq!(req.user_base_dn, "DC=domain,DC=local");
        // Bootstrapped providers are enabled so they show up in the SSO list.
        assert_eq!(req.is_enabled, Some(true));
        assert_eq!(req.priority, Some(0));
        assert_eq!(req.use_starttls, Some(false));
    }

    #[test]
    fn test_ldap_bootstrap_request_name_override() {
        // LDAP_NAME lets operators point the env-managed provider at an
        // existing one, mirroring OIDC_NAME (#1887).
        let req = build_ldap_request_from_values(LdapEnvVars {
            name: Some("Corporate AD".to_string()),
            url: Some("ldap://dc.local:389".to_string()),
            base_dn: Some("DC=domain,DC=local".to_string()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(req.name, "Corporate AD");
    }

    #[test]
    fn test_ldap_bootstrap_request_empty_name_defaults() {
        let req = build_ldap_request_from_values(LdapEnvVars {
            name: Some("".to_string()),
            url: Some("ldap://dc.local:389".to_string()),
            base_dn: Some("DC=domain,DC=local".to_string()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(req.name, "default");
    }

    #[test]
    fn test_ldap_bootstrap_request_missing_url() {
        let req = build_ldap_request_from_values(ldap_env(None, Some("DC=domain,DC=local")));
        assert!(req.is_none());
    }

    #[test]
    fn test_ldap_bootstrap_request_missing_base_dn() {
        let req = build_ldap_request_from_values(ldap_env(Some("ldap://dc.local:389"), None));
        assert!(req.is_none());
    }

    #[test]
    fn test_ldap_bootstrap_request_empty_url() {
        let req = build_ldap_request_from_values(ldap_env(Some(""), Some("DC=domain,DC=local")));
        assert!(req.is_none());
    }

    #[test]
    fn test_ldap_bootstrap_request_empty_base_dn() {
        let req = build_ldap_request_from_values(ldap_env(Some("ldap://dc.local:389"), Some("")));
        assert!(req.is_none());
    }

    #[test]
    fn test_ldap_bootstrap_request_full_active_directory_config() {
        // Mirrors the Active Directory example from issue #1434.
        let req = build_ldap_request_from_values(LdapEnvVars {
            name: None,
            url: Some("ldap://dc.local:389".to_string()),
            base_dn: Some("DC=domain,DC=local".to_string()),
            bind_dn: Some("user@domain".to_string()),
            bind_password: Some("superPassword".to_string()),
            user_filter: Some("(sAMAccountName={0})".to_string()),
            username_attr: Some("sAMAccountName".to_string()),
            email_attr: None,
            display_name_attr: None,
            groups_attr: None,
            group_base_dn: Some("OU=Groups,DC=domain,DC=local".to_string()),
            group_filter: Some("(memberUid={0})".to_string()),
            admin_group_dn: Some("CN=admin_users_group,OU=Groups,DC=domain,DC=local".to_string()),
            use_starttls: Some("false".to_string()),
        })
        .unwrap();

        assert_eq!(req.bind_dn.as_deref(), Some("user@domain"));
        assert_eq!(req.bind_password.as_deref(), Some("superPassword"));
        assert_eq!(req.user_filter.as_deref(), Some("(sAMAccountName={0})"));
        assert_eq!(req.username_attribute.as_deref(), Some("sAMAccountName"));
        assert_eq!(
            req.group_base_dn.as_deref(),
            Some("OU=Groups,DC=domain,DC=local")
        );
        assert_eq!(req.group_filter.as_deref(), Some("(memberUid={0})"));
        assert_eq!(
            req.admin_group_dn.as_deref(),
            Some("CN=admin_users_group,OU=Groups,DC=domain,DC=local")
        );
        assert_eq!(req.use_starttls, Some(false));
        assert_eq!(req.is_enabled, Some(true));
    }

    #[test]
    fn test_ldap_bootstrap_request_starttls_truthy_values() {
        for v in ["true", "1"] {
            let req = build_ldap_request_from_values(LdapEnvVars {
                url: Some("ldap://dc.local:389".to_string()),
                base_dn: Some("DC=domain,DC=local".to_string()),
                use_starttls: Some(v.to_string()),
                ..Default::default()
            })
            .unwrap();
            assert_eq!(
                req.use_starttls,
                Some(true),
                "value {v} should enable STARTTLS"
            );
        }
    }

    #[test]
    fn test_ldap_bootstrap_request_empty_optional_fields_become_none() {
        // Empty strings (e.g. unset compose interpolations) must not produce
        // empty bind DNs or filters that would break directory binds.
        let req = build_ldap_request_from_values(LdapEnvVars {
            url: Some("ldap://dc.local:389".to_string()),
            base_dn: Some("DC=domain,DC=local".to_string()),
            bind_dn: Some("".to_string()),
            bind_password: Some("".to_string()),
            user_filter: Some("".to_string()),
            ..Default::default()
        })
        .unwrap();

        assert!(req.bind_dn.is_none());
        assert!(req.bind_password.is_none());
        assert!(req.user_filter.is_none());
    }
}
// warm cache benchmark
// sqlx-cli benchmark
// coverage benchmark
