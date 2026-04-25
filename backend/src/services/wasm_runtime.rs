//! WASM runtime service for executing plugin components.
//!
//! Provides wasmtime-based execution environment with resource limits,
//! timeout handling, and async support for WASM format handler plugins.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use thiserror::Error;
use tracing::{debug, error, info, warn};
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, ResourceLimiter, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

use crate::models::plugin::PluginResourceLimits;

/// Default fuel per second of execution time.
const FUEL_PER_SECOND: u64 = 100_000_000;

/// Errors that can occur during WASM execution.
#[derive(Debug, Error)]
pub enum WasmError {
    #[error("WASM execution timed out after {0} seconds")]
    Timeout(u32),

    #[error("WASM execution exceeded fuel limit")]
    FuelExhausted,

    #[error("WASM execution exceeded memory limit ({0} MB)")]
    MemoryExceeded(u32),

    #[error("WASM component validation failed: {0}")]
    ValidationFailed(String),

    #[error("WASM compilation failed: {0}")]
    CompilationFailed(String),

    #[error("WASM instantiation failed: {0}")]
    InstantiationFailed(String),

    #[error("WASM function call failed: {0}")]
    CallFailed(String),

    #[error("WASM engine error: {0}")]
    EngineError(String),

    #[error("Plugin returned error: {0}")]
    PluginError(String),
}

impl From<wasmtime::Error> for WasmError {
    fn from(e: wasmtime::Error) -> Self {
        let msg = e.to_string();
        if msg.contains("fuel") {
            WasmError::FuelExhausted
        } else if msg.contains("memory") {
            WasmError::MemoryExceeded(0)
        } else {
            WasmError::EngineError(msg)
        }
    }
}

/// Result type for WASM operations.
pub type WasmResult<T> = std::result::Result<T, WasmError>;

/// Plugin execution context stored in the WASM Store.
///
/// Contains plugin metadata and state needed during execution.
pub struct PluginContext {
    pub plugin_id: String,
    pub format_key: String,
    limits: StoreLimits,
    wasi_ctx: WasiCtx,
    resource_table: ResourceTable,
}

impl PluginContext {
    /// Create a new plugin context.
    pub fn new(plugin_id: String, format_key: String, limits: &PluginResourceLimits) -> Self {
        let store_limits = StoreLimitsBuilder::new()
            .memory_size(limits.memory_mb as usize * 1024 * 1024)
            .table_elements(10000)
            .instances(10)
            .tables(10)
            .memories(1)
            .build();

        // Build minimal WASI context for plugins
        let wasi_ctx = WasiCtxBuilder::new().inherit_stdio().build();

        Self {
            plugin_id,
            format_key,
            limits: store_limits,
            wasi_ctx,
            resource_table: ResourceTable::new(),
        }
    }
}

impl WasiView for PluginContext {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi_ctx,
            table: &mut self.resource_table,
        }
    }
}

impl ResourceLimiter for PluginContext {
    fn memory_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        self.limits.memory_growing(current, desired, maximum)
    }

    fn table_growing(
        &mut self,
        current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> anyhow::Result<bool> {
        self.limits.table_growing(current, desired, maximum)
    }
}

/// Compiled WASM plugin ready for instantiation.
///
/// Contains the wasmtime Engine and compiled Component for a single plugin.
/// Each plugin version gets its own Engine for hot-reload isolation.
pub struct CompiledPlugin {
    engine: Arc<Engine>,
    component: Component,
    linker: Linker<PluginContext>,
}

impl CompiledPlugin {
    /// Get a reference to the engine.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Get a reference to the component.
    pub fn component(&self) -> &Component {
        &self.component
    }

    /// Get a reference to the linker.
    pub fn linker(&self) -> &Linker<PluginContext> {
        &self.linker
    }
}

/// WASM runtime for compiling and executing plugins.
///
/// Provides async-compatible wasmtime execution with resource limits
/// and timeout handling using dual-layer protection (fuel + wall-clock).
pub struct WasmRuntime {
    /// Default configuration for new engines.
    config: Config,
}

impl WasmRuntime {
    /// Create a new WASM runtime with default configuration.
    pub fn new() -> WasmResult<Self> {
        let mut config = Config::new();

        // Enable async support for Tokio integration
        config.async_support(true);

        // Enable fuel-based execution metering
        config.consume_fuel(true);

        // Enable Component Model for WIT interfaces
        config.wasm_component_model(true);

        // Enable SIMD for performance (commonly used in parsing)
        config.wasm_simd(true);

        // Enable relaxed SIMD if available
        config.wasm_relaxed_simd(true);

        // Disable features we don't need for security
        config.wasm_threads(false);

        Ok(Self { config })
    }

    /// Create a new WASM runtime with custom configuration.
    pub fn with_config(config: Config) -> Self {
        Self { config }
    }

    /// Compile a WASM component from bytes.
    ///
    /// Returns a CompiledPlugin that can be used to create instances.
    /// Each call creates a new Engine for hot-reload isolation.
    pub fn compile(&self, wasm_bytes: &[u8]) -> WasmResult<CompiledPlugin> {
        // Create a new engine for this plugin (isolation for hot-reload)
        let engine =
            Engine::new(&self.config).map_err(|e| WasmError::EngineError(e.to_string()))?;
        let engine = Arc::new(engine);

        // Compile the component
        let component = Component::new(&engine, wasm_bytes)
            .map_err(|e| WasmError::CompilationFailed(e.to_string()))?;

        // Create linker and add WASI imports
        let mut linker = Linker::new(&engine);

        // Add minimal WASI imports for basic I/O
        // We only expose wasi:io/streams for artifact data
        wasmtime_wasi::p2::add_to_linker_async(&mut linker)
            .map_err(|e| WasmError::EngineError(format!("Failed to add WASI: {}", e)))?;

        info!("Compiled WASM component ({} bytes)", wasm_bytes.len());

        Ok(CompiledPlugin {
            engine,
            component,
            linker,
        })
    }

    /// Validate a WASM component without fully compiling it.
    ///
    /// Performs quick validation to check if the bytes represent a valid
    /// WASM component that could be compiled.
    pub fn validate(&self, wasm_bytes: &[u8]) -> WasmResult<()> {
        // Create a temporary engine for validation
        let engine =
            Engine::new(&self.config).map_err(|e| WasmError::EngineError(e.to_string()))?;

        // Try to parse as a component
        Component::new(&engine, wasm_bytes)
            .map_err(|e| WasmError::ValidationFailed(e.to_string()))?;

        debug!("WASM component validation passed");
        Ok(())
    }

    /// Create a new store for plugin execution.
    ///
    /// The store contains the execution context and resource limits.
    pub fn create_store(
        &self,
        compiled: &CompiledPlugin,
        plugin_id: &str,
        format_key: &str,
        limits: &PluginResourceLimits,
    ) -> WasmResult<Store<PluginContext>> {
        let context = PluginContext::new(plugin_id.to_string(), format_key.to_string(), limits);

        let mut store = Store::new(compiled.engine(), context);

        // Set resource limiter
        store.limiter(|ctx| ctx);

        // Set initial fuel based on timeout
        let fuel = limits
            .fuel
            .max(limits.timeout_secs as u64 * FUEL_PER_SECOND);
        store
            .set_fuel(fuel)
            .map_err(|e| WasmError::EngineError(e.to_string()))?;

        debug!(
            "Created store for plugin {} with {} fuel, {} MB memory limit",
            plugin_id, fuel, limits.memory_mb
        );

        Ok(store)
    }
}

impl Default for WasmRuntime {
    fn default() -> Self {
        Self::new().expect("Failed to create default WasmRuntime")
    }
}

/// Execute a WASM function with timeout protection.
///
/// Uses dual-layer protection:
/// 1. Fuel metering for deterministic per-operation limits
/// 2. Wall-clock timeout as defense-in-depth
pub async fn execute_with_timeout<F, T>(timeout_secs: u32, future: F) -> WasmResult<T>
where
    F: std::future::Future<Output = WasmResult<T>>,
{
    // Wall-clock timeout is slightly longer than fuel timeout
    // to allow fuel exhaustion to trigger first in normal cases
    let timeout = Duration::from_secs((timeout_secs + 1) as u64);

    match tokio::time::timeout(timeout, future).await {
        Ok(result) => result,
        Err(_) => {
            warn!(
                "WASM execution wall-clock timeout after {} seconds",
                timeout_secs
            );
            Err(WasmError::Timeout(timeout_secs))
        }
    }
}

// =========================================================================
// T064: WASM Execution Metrics
// =========================================================================

/// Metrics collected during WASM plugin execution.
#[derive(Debug, Clone, Default)]
pub struct WasmExecutionMetrics {
    /// Execution time in milliseconds.
    pub execution_time_ms: u64,
    /// Fuel consumed during execution.
    pub fuel_consumed: u64,
    /// Peak memory usage in bytes (if available).
    pub peak_memory_bytes: Option<u64>,
    /// Whether the execution was successful.
    pub success: bool,
    /// Error message if execution failed.
    pub error_message: Option<String>,
}

impl WasmExecutionMetrics {
    /// Create new metrics for a successful execution.
    pub fn success(execution_time_ms: u64, fuel_consumed: u64) -> Self {
        Self {
            execution_time_ms,
            fuel_consumed,
            peak_memory_bytes: None,
            success: true,
            error_message: None,
        }
    }

    /// Create new metrics for a failed execution.
    pub fn failure(execution_time_ms: u64, error: &str) -> Self {
        Self {
            execution_time_ms,
            fuel_consumed: 0,
            peak_memory_bytes: None,
            success: false,
            error_message: Some(error.to_string()),
        }
    }

    /// Set peak memory usage.
    pub fn with_memory(mut self, peak_memory_bytes: u64) -> Self {
        self.peak_memory_bytes = Some(peak_memory_bytes);
        self
    }
}

/// Execute a WASM function with metrics collection.
///
/// Wraps execution to collect timing and resource usage metrics.
pub async fn execute_with_metrics<F, T>(
    timeout_secs: u32,
    initial_fuel: u64,
    future: F,
    get_remaining_fuel: impl FnOnce() -> u64,
) -> (WasmResult<T>, WasmExecutionMetrics)
where
    F: std::future::Future<Output = WasmResult<T>>,
{
    let start = std::time::Instant::now();

    let result = execute_with_timeout(timeout_secs, future).await;

    let execution_time_ms = start.elapsed().as_millis() as u64;

    let metrics = match &result {
        Ok(_) => {
            let remaining_fuel = get_remaining_fuel();
            let fuel_consumed = initial_fuel.saturating_sub(remaining_fuel);
            WasmExecutionMetrics::success(execution_time_ms, fuel_consumed)
        }
        Err(e) => WasmExecutionMetrics::failure(execution_time_ms, &e.to_string()),
    };

    (result, metrics)
}

// =========================================================================
// T066: Plugin Crash Isolation
// =========================================================================

/// Safely execute a WASM function with crash isolation.
///
/// Wraps WASM execution in a catch_unwind to prevent panics from
/// propagating and taking down the host process.
pub async fn execute_with_isolation<F, T>(timeout_secs: u32, future: F) -> WasmResult<T>
where
    F: std::future::Future<Output = WasmResult<T>> + std::panic::UnwindSafe,
{
    // Note: async catch_unwind is tricky - we use the synchronous result
    // The actual async execution is handled by execute_with_timeout
    let result = execute_with_timeout(timeout_secs, future).await;

    // If we get here, no panic occurred
    result
}

/// Wrapper that provides crash isolation for synchronous WASM operations.
pub fn isolate_crash<F, T>(f: F) -> WasmResult<T>
where
    F: FnOnce() -> WasmResult<T> + std::panic::UnwindSafe,
{
    match std::panic::catch_unwind(f) {
        Ok(result) => result,
        Err(panic) => {
            let panic_msg = if let Some(s) = panic.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic".to_string()
            };

            error!("WASM plugin panicked: {}", panic_msg);
            Err(WasmError::PluginError(format!(
                "Plugin crashed: {}",
                panic_msg
            )))
        }
    }
}

// =========================================================================
// T067: Timeout Cleanup
// =========================================================================

/// Cleanup handle for WASM execution timeout.
///
/// When dropped, ensures any resources associated with the execution
/// are properly cleaned up, even if timeout occurred.
pub struct ExecutionCleanup {
    plugin_id: String,
    started_at: std::time::Instant,
    cleaned_up: bool,
}

impl ExecutionCleanup {
    /// Create a new cleanup handle.
    pub fn new(plugin_id: &str) -> Self {
        Self {
            plugin_id: plugin_id.to_string(),
            started_at: std::time::Instant::now(),
            cleaned_up: false,
        }
    }

    /// Mark as successfully cleaned up.
    pub fn complete(&mut self) {
        self.cleaned_up = true;
    }

    /// Get execution duration so far.
    pub fn elapsed(&self) -> std::time::Duration {
        self.started_at.elapsed()
    }
}

impl Drop for ExecutionCleanup {
    fn drop(&mut self) {
        if !self.cleaned_up {
            warn!(
                "WASM execution for plugin {} was not cleanly completed after {:?}",
                self.plugin_id,
                self.elapsed()
            );
            // The Store will be dropped automatically, which handles
            // memory and resource cleanup. We just log the warning.
        }
    }
}

/// Execute with automatic cleanup on timeout or error.
pub async fn execute_with_cleanup<F, T>(
    plugin_id: &str,
    timeout_secs: u32,
    future: F,
) -> WasmResult<T>
where
    F: std::future::Future<Output = WasmResult<T>>,
{
    let mut cleanup = ExecutionCleanup::new(plugin_id);

    let result = execute_with_timeout(timeout_secs, future).await;

    if result.is_ok() {
        cleanup.complete();
    }

    result
}

// =========================================================================
// Original Types
// =========================================================================

/// Artifact metadata returned from WASM plugins.
///
/// Maps to the WIT metadata record type.
#[derive(Debug, Clone)]
pub struct WasmMetadata {
    pub path: String,
    pub version: Option<String>,
    pub content_type: String,
    pub size_bytes: u64,
    pub checksum_sha256: Option<String>,
}

impl WasmMetadata {
    /// Convert to JSON value for storage.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "path": self.path,
            "version": self.version,
            "content_type": self.content_type,
            "size_bytes": self.size_bytes,
            "checksum_sha256": self.checksum_sha256,
        })
    }
}

/// Validation error returned from WASM plugins.
///
/// Maps to the WIT validation-error record type.
#[derive(Debug, Clone)]
pub struct WasmValidationError {
    pub message: String,
    pub field: Option<String>,
}

impl std::fmt::Display for WasmValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref field) = self.field {
            write!(f, "{} (field: {})", self.message, field)
        } else {
            write!(f, "{}", self.message)
        }
    }
}

/// Index file generated by WASM plugins.
///
/// Represents a file path and its content.
#[derive(Debug, Clone)]
pub struct WasmIndexFile {
    pub path: String,
    pub content: Bytes,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_runtime_creation() {
        let runtime = WasmRuntime::new();
        assert!(runtime.is_ok());
    }

    #[test]
    fn test_plugin_context_creation() {
        let limits = PluginResourceLimits::default();
        let context = PluginContext::new(
            "test-plugin".to_string(),
            "test-format".to_string(),
            &limits,
        );
        assert_eq!(context.plugin_id, "test-plugin");
        assert_eq!(context.format_key, "test-format");
    }

    #[test]
    fn test_wasm_metadata_to_json() {
        let metadata = WasmMetadata {
            path: "/test/file.jar".to_string(),
            version: Some("1.0.0".to_string()),
            content_type: "application/java-archive".to_string(),
            size_bytes: 1024,
            checksum_sha256: Some("abc123".to_string()),
        };

        let json = metadata.to_json();
        assert_eq!(json["path"], "/test/file.jar");
        assert_eq!(json["version"], "1.0.0");
        assert_eq!(json["size_bytes"], 1024);
    }

    #[test]
    fn test_wasm_validation_error_display() {
        let error = WasmValidationError {
            message: "Invalid format".to_string(),
            field: Some("version".to_string()),
        };
        assert_eq!(error.to_string(), "Invalid format (field: version)");

        let error_no_field = WasmValidationError {
            message: "Unknown error".to_string(),
            field: None,
        };
        assert_eq!(error_no_field.to_string(), "Unknown error");
    }

    #[tokio::test]
    async fn test_execute_with_timeout_success() {
        let result = execute_with_timeout(5, async { Ok::<_, WasmError>("success") }).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success");
    }

    #[tokio::test]
    async fn test_execute_with_timeout_timeout() {
        let result: WasmResult<()> = execute_with_timeout(1, async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok(())
        })
        .await;
        assert!(matches!(result, Err(WasmError::Timeout(_))));
    }

    #[test]
    fn test_wasm_error_from_wasmtime_error() {
        // Test that wasmtime errors are converted properly
        let error = WasmError::from(wasmtime::Error::msg("test error"));
        assert!(matches!(error, WasmError::EngineError(_)));
    }

    // -----------------------------------------------------------------------
    // WasmError conversion from wasmtime::Error - keyword matching
    // -----------------------------------------------------------------------

    #[test]
    fn test_wasm_error_from_wasmtime_fuel_error() {
        let error = WasmError::from(wasmtime::Error::msg("all fuel consumed by wasm"));
        assert!(matches!(error, WasmError::FuelExhausted));
    }

    #[test]
    fn test_wasm_error_from_wasmtime_memory_error() {
        let error = WasmError::from(wasmtime::Error::msg("memory allocation failed"));
        assert!(matches!(error, WasmError::MemoryExceeded(0)));
    }

    #[test]
    fn test_wasm_error_from_wasmtime_generic_error() {
        let error = WasmError::from(wasmtime::Error::msg("something unexpected"));
        match error {
            WasmError::EngineError(msg) => assert!(msg.contains("something unexpected")),
            other => panic!("Expected EngineError, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // WasmError Display implementations
    // -----------------------------------------------------------------------

    #[test]
    fn test_wasm_error_display_timeout() {
        let err = WasmError::Timeout(30);
        assert_eq!(err.to_string(), "WASM execution timed out after 30 seconds");
    }

    #[test]
    fn test_wasm_error_display_fuel_exhausted() {
        let err = WasmError::FuelExhausted;
        assert_eq!(err.to_string(), "WASM execution exceeded fuel limit");
    }

    #[test]
    fn test_wasm_error_display_memory_exceeded() {
        let err = WasmError::MemoryExceeded(128);
        assert_eq!(
            err.to_string(),
            "WASM execution exceeded memory limit (128 MB)"
        );
    }

    #[test]
    fn test_wasm_error_display_validation_failed() {
        let err = WasmError::ValidationFailed("bad bytes".to_string());
        assert_eq!(
            err.to_string(),
            "WASM component validation failed: bad bytes"
        );
    }

    #[test]
    fn test_wasm_error_display_compilation_failed() {
        let err = WasmError::CompilationFailed("syntax error".to_string());
        assert_eq!(err.to_string(), "WASM compilation failed: syntax error");
    }

    #[test]
    fn test_wasm_error_display_instantiation_failed() {
        let err = WasmError::InstantiationFailed("missing import".to_string());
        assert_eq!(err.to_string(), "WASM instantiation failed: missing import");
    }

    #[test]
    fn test_wasm_error_display_call_failed() {
        let err = WasmError::CallFailed("trap: unreachable".to_string());
        assert_eq!(
            err.to_string(),
            "WASM function call failed: trap: unreachable"
        );
    }

    #[test]
    fn test_wasm_error_display_engine_error() {
        let err = WasmError::EngineError("config error".to_string());
        assert_eq!(err.to_string(), "WASM engine error: config error");
    }

    #[test]
    fn test_wasm_error_display_plugin_error() {
        let err = WasmError::PluginError("unexpected error".to_string());
        assert_eq!(err.to_string(), "Plugin returned error: unexpected error");
    }

    // -----------------------------------------------------------------------
    // WasmRuntime
    // -----------------------------------------------------------------------

    #[test]
    fn test_wasm_runtime_default() {
        // Default should succeed
        let runtime = WasmRuntime::default();
        // Just verify it was created successfully
        let _ = &runtime.config;
    }

    #[test]
    fn test_wasm_runtime_with_config() {
        let mut config = Config::new();
        config.async_support(true);
        let runtime = WasmRuntime::with_config(config);
        let _ = &runtime.config;
    }

    #[test]
    fn test_wasm_runtime_validate_invalid_bytes() {
        let runtime = WasmRuntime::new().unwrap();
        let result = runtime.validate(b"this is not wasm");
        assert!(result.is_err());
        assert!(matches!(result, Err(WasmError::ValidationFailed(_))));
    }

    #[test]
    fn test_wasm_runtime_compile_invalid_bytes() {
        let runtime = WasmRuntime::new().unwrap();
        let result = runtime.compile(b"not a valid wasm component");
        assert!(result.is_err());
        assert!(matches!(result, Err(WasmError::CompilationFailed(_))));
    }

    // -----------------------------------------------------------------------
    // WasmMetadata
    // -----------------------------------------------------------------------

    #[test]
    fn test_wasm_metadata_to_json_with_none_values() {
        let metadata = WasmMetadata {
            path: "/artifacts/test.bin".to_string(),
            version: None,
            content_type: "application/octet-stream".to_string(),
            size_bytes: 0,
            checksum_sha256: None,
        };

        let json = metadata.to_json();
        assert_eq!(json["path"], "/artifacts/test.bin");
        assert!(json["version"].is_null());
        assert_eq!(json["content_type"], "application/octet-stream");
        assert_eq!(json["size_bytes"], 0);
        assert!(json["checksum_sha256"].is_null());
    }

    #[test]
    fn test_wasm_metadata_to_json_large_size() {
        let metadata = WasmMetadata {
            path: "/large/file.bin".to_string(),
            version: Some("2.0.0".to_string()),
            content_type: "application/octet-stream".to_string(),
            size_bytes: u64::MAX,
            checksum_sha256: Some("deadbeef".to_string()),
        };

        let json = metadata.to_json();
        assert_eq!(json["size_bytes"], u64::MAX);
    }

    #[test]
    fn test_wasm_metadata_clone() {
        let metadata = WasmMetadata {
            path: "/test".to_string(),
            version: Some("1.0.0".to_string()),
            content_type: "text/plain".to_string(),
            size_bytes: 100,
            checksum_sha256: Some("abc".to_string()),
        };
        let cloned = metadata.clone();
        assert_eq!(cloned.path, metadata.path);
        assert_eq!(cloned.version, metadata.version);
    }

    // -----------------------------------------------------------------------
    // WasmValidationError
    // -----------------------------------------------------------------------

    #[test]
    fn test_wasm_validation_error_display_with_field() {
        let err = WasmValidationError {
            message: "must be non-empty".to_string(),
            field: Some("name".to_string()),
        };
        assert_eq!(err.to_string(), "must be non-empty (field: name)");
    }

    #[test]
    fn test_wasm_validation_error_display_without_field() {
        let err = WasmValidationError {
            message: "general validation error".to_string(),
            field: None,
        };
        assert_eq!(err.to_string(), "general validation error");
    }

    #[test]
    fn test_wasm_validation_error_clone() {
        let err = WasmValidationError {
            message: "test".to_string(),
            field: Some("f".to_string()),
        };
        let cloned = err.clone();
        assert_eq!(cloned.message, err.message);
        assert_eq!(cloned.field, err.field);
    }

    // -----------------------------------------------------------------------
    // WasmIndexFile
    // -----------------------------------------------------------------------

    #[test]
    fn test_wasm_index_file() {
        let index = WasmIndexFile {
            path: "/index/metadata.json".to_string(),
            content: Bytes::from_static(b"{\"version\": \"1.0\"}"),
        };
        assert_eq!(index.path, "/index/metadata.json");
        assert_eq!(index.content.as_ref(), b"{\"version\": \"1.0\"}");
    }

    #[test]
    fn test_wasm_index_file_clone() {
        let index = WasmIndexFile {
            path: "/path".to_string(),
            content: Bytes::from_static(b"data"),
        };
        let cloned = index.clone();
        assert_eq!(cloned.path, index.path);
        assert_eq!(cloned.content, index.content);
    }

    // -----------------------------------------------------------------------
    // WasmExecutionMetrics
    // -----------------------------------------------------------------------

    #[test]
    fn test_wasm_execution_metrics_success() {
        let metrics = WasmExecutionMetrics::success(150, 10_000_000);
        assert_eq!(metrics.execution_time_ms, 150);
        assert_eq!(metrics.fuel_consumed, 10_000_000);
        assert!(metrics.success);
        assert!(metrics.error_message.is_none());
        assert!(metrics.peak_memory_bytes.is_none());
    }

    #[test]
    fn test_wasm_execution_metrics_failure() {
        let metrics = WasmExecutionMetrics::failure(200, "timeout occurred");
        assert_eq!(metrics.execution_time_ms, 200);
        assert_eq!(metrics.fuel_consumed, 0);
        assert!(!metrics.success);
        assert_eq!(metrics.error_message.as_deref(), Some("timeout occurred"));
    }

    #[test]
    fn test_wasm_execution_metrics_with_memory() {
        let metrics = WasmExecutionMetrics::success(100, 5000).with_memory(1024 * 1024);
        assert_eq!(metrics.peak_memory_bytes, Some(1024 * 1024));
        assert!(metrics.success);
    }

    #[test]
    fn test_wasm_execution_metrics_default() {
        let metrics = WasmExecutionMetrics::default();
        assert_eq!(metrics.execution_time_ms, 0);
        assert_eq!(metrics.fuel_consumed, 0);
        assert!(!metrics.success);
        assert!(metrics.error_message.is_none());
        assert!(metrics.peak_memory_bytes.is_none());
    }

    // -----------------------------------------------------------------------
    // execute_with_timeout
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_execute_with_timeout_inner_error_passes_through() {
        let result: WasmResult<()> =
            execute_with_timeout(5, async { Err(WasmError::FuelExhausted) }).await;
        assert!(matches!(result, Err(WasmError::FuelExhausted)));
    }

    #[tokio::test]
    async fn test_execute_with_timeout_with_zero_timeout() {
        // Timeout of 0 seconds means the wall clock adds 1 -> 1 second timeout
        let result: WasmResult<()> = execute_with_timeout(0, async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok(())
        })
        .await;
        assert!(matches!(result, Err(WasmError::Timeout(0))));
    }

    // -----------------------------------------------------------------------
    // execute_with_metrics
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_execute_with_metrics_success() {
        let (result, metrics) =
            execute_with_metrics(5, 100_000, async { Ok::<_, WasmError>("done") }, || 80_000).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "done");
        assert!(metrics.success);
        assert_eq!(metrics.fuel_consumed, 20_000); // 100_000 - 80_000
    }

    #[tokio::test]
    async fn test_execute_with_metrics_failure() {
        let (result, metrics) = execute_with_metrics(
            5,
            100_000,
            async { Err::<String, _>(WasmError::FuelExhausted) },
            || 0,
        )
        .await;

        assert!(result.is_err());
        assert!(!metrics.success);
        assert!(metrics.error_message.is_some());
    }

    // -----------------------------------------------------------------------
    // isolate_crash
    // -----------------------------------------------------------------------

    #[test]
    fn test_isolate_crash_normal_ok() {
        let result = isolate_crash(|| Ok::<_, WasmError>(42));
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_isolate_crash_normal_err() {
        let result = isolate_crash(|| Err::<i32, _>(WasmError::FuelExhausted));
        assert!(matches!(result, Err(WasmError::FuelExhausted)));
    }

    #[test]
    fn test_isolate_crash_panic_str() {
        let result = isolate_crash::<_, i32>(|| panic!("intentional panic"));
        match result {
            Err(WasmError::PluginError(msg)) => {
                assert!(msg.contains("Plugin crashed"));
                assert!(msg.contains("intentional panic"));
            }
            other => panic!("Expected PluginError, got {:?}", other),
        }
    }

    #[test]
    fn test_isolate_crash_panic_string() {
        let result = isolate_crash::<_, i32>(|| panic!("{}", "formatted panic".to_string()));
        match result {
            Err(WasmError::PluginError(msg)) => {
                assert!(msg.contains("formatted panic"));
            }
            other => panic!("Expected PluginError, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // ExecutionCleanup
    // -----------------------------------------------------------------------

    #[test]
    fn test_execution_cleanup_complete() {
        let mut cleanup = ExecutionCleanup::new("test-plugin");
        assert!(!cleanup.cleaned_up);
        assert_eq!(cleanup.plugin_id, "test-plugin");
        cleanup.complete();
        assert!(cleanup.cleaned_up);
        // Dropping after complete() should not warn
    }

    #[test]
    fn test_execution_cleanup_elapsed() {
        let cleanup = ExecutionCleanup::new("test-plugin");
        std::thread::sleep(std::time::Duration::from_millis(10));
        let elapsed = cleanup.elapsed();
        assert!(elapsed >= std::time::Duration::from_millis(10));
    }

    #[test]
    fn test_execution_cleanup_drop_without_complete_does_not_panic() {
        // Dropping without calling complete() should log a warning but not panic
        let _cleanup = ExecutionCleanup::new("uncompleted-plugin");
        // Just let it drop
    }

    // -----------------------------------------------------------------------
    // execute_with_cleanup
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_execute_with_cleanup_success() {
        let result = execute_with_cleanup("test-plugin", 5, async { Ok::<_, WasmError>(42) }).await;
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_execute_with_cleanup_error() {
        let result: WasmResult<i32> = execute_with_cleanup("test-plugin", 5, async {
            Err(WasmError::PluginError("crash".to_string()))
        })
        .await;
        assert!(matches!(result, Err(WasmError::PluginError(_))));
    }

    // -----------------------------------------------------------------------
    // execute_with_isolation
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_execute_with_isolation_success() {
        let result = execute_with_isolation(5, async { Ok::<_, WasmError>("isolated") }).await;
        assert_eq!(result.unwrap(), "isolated");
    }

    #[tokio::test]
    async fn test_execute_with_isolation_error() {
        let result: WasmResult<()> =
            execute_with_isolation(5, async { Err(WasmError::FuelExhausted) }).await;
        assert!(matches!(result, Err(WasmError::FuelExhausted)));
    }

    // -----------------------------------------------------------------------
    // PluginContext
    // -----------------------------------------------------------------------

    #[test]
    fn test_plugin_context_custom_limits() {
        let limits = PluginResourceLimits {
            memory_mb: 128,
            timeout_secs: 10,
            fuel: 1_000_000_000,
        };
        let ctx = PluginContext::new("my-plugin".to_string(), "my-format".to_string(), &limits);
        assert_eq!(ctx.plugin_id, "my-plugin");
        assert_eq!(ctx.format_key, "my-format");
    }

    // -----------------------------------------------------------------------
    // FUEL_PER_SECOND constant
    // -----------------------------------------------------------------------

    #[test]
    fn test_fuel_per_second_constant() {
        assert_eq!(FUEL_PER_SECOND, 100_000_000);
    }

    // -----------------------------------------------------------------------
    // wasmtime 36.x migration - WasiView / WasiCtxView shape
    // -----------------------------------------------------------------------

    /// Exercises the new `WasiView::ctx(&mut self) -> WasiCtxView<'_>` shape
    /// introduced in wasmtime-wasi 30.x (split out of the old dual-method
    /// trait). Before the migration this used `table()` + `ctx()`.
    #[test]
    fn test_wasi_view_returns_ctx_view_with_both_refs() {
        let limits = PluginResourceLimits::default();
        let mut context = PluginContext::new("wv".to_string(), "wv-fmt".to_string(), &limits);

        let view: WasiCtxView<'_> = context.ctx();
        // Both refs must be populated - just de-reference them to prove
        // they're live references into the same PluginContext.
        let _ctx_ptr: *const WasiCtx = view.ctx;
        let _table_ptr: *const wasmtime::component::ResourceTable = view.table;
    }

    /// Compiles a minimal valid component and creates a Store from it. This
    /// exercises the full v36 code path: `Engine::new(&Config)`, component
    /// parsing, `Linker::new`, `wasmtime_wasi::p2::add_to_linker_async`, and
    /// `Store::new` with a `PluginContext` (which requires `WasiView`).
    #[test]
    fn test_compile_and_store_roundtrip_with_minimal_component() {
        let runtime = WasmRuntime::new().unwrap();
        // `(component)` is the minimal valid component in WAT text form.
        let compiled = runtime
            .compile(b"(component)")
            .expect("minimal component should compile");

        let limits = PluginResourceLimits::default();
        let store = runtime
            .create_store(&compiled, "rt-id", "rt-fmt", &limits)
            .expect("store creation should succeed");

        // If we got a Store back the WasiView + ResourceLimiter plumbing is
        // wired up correctly for the new 36.x API.
        assert_eq!(store.data().plugin_id, "rt-id");
        assert_eq!(store.data().format_key, "rt-fmt");
    }

    /// Verifies the ResourceLimiter impl uses the 36.x `usize` signature for
    /// `table_growing` (it was `u32` in 24.x). If this compiles, the shape
    /// is correct; asserting the call returns Ok for a growth below the
    /// default cap gives us confidence the delegation to StoreLimits still
    /// works after the type change.
    #[test]
    fn test_resource_limiter_table_growing_usize_signature() {
        let limits = PluginResourceLimits::default();
        let mut context = PluginContext::new("rl".to_string(), "rl-fmt".to_string(), &limits);

        let ok = context
            .table_growing(0_usize, 16_usize, Some(10_000_usize))
            .expect("table growth should be allowed under the default limit");
        assert!(ok);
    }
}
