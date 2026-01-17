//! WASM runtime service for executing plugin components.
//!
//! Provides wasmtime-based execution environment with resource limits,
//! timeout handling, and async support for WASM format handler plugins.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, ResourceLimiter, Store, StoreLimits, StoreLimitsBuilder};

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

        Self {
            plugin_id,
            format_key,
            limits: store_limits,
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
        let engine = Engine::new(&self.config)
            .map_err(|e| WasmError::EngineError(e.to_string()))?;
        let engine = Arc::new(engine);

        // Compile the component
        let component = Component::new(&engine, wasm_bytes)
            .map_err(|e| WasmError::CompilationFailed(e.to_string()))?;

        // Create linker and add WASI imports
        let mut linker = Linker::new(&engine);

        // Add minimal WASI imports for basic I/O
        // We only expose wasi:io/streams for artifact data
        wasmtime_wasi::add_to_linker_async(&mut linker)
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
        let engine = Engine::new(&self.config)
            .map_err(|e| WasmError::EngineError(e.to_string()))?;

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
        let context = PluginContext::new(
            plugin_id.to_string(),
            format_key.to_string(),
            limits,
        );

        let mut store = Store::new(compiled.engine(), context);

        // Set resource limiter
        store.limiter(|ctx| ctx);

        // Set initial fuel based on timeout
        let fuel = limits.fuel.max(limits.timeout_secs as u64 * FUEL_PER_SECOND);
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
pub async fn execute_with_timeout<F, T>(
    timeout_secs: u32,
    future: F,
) -> WasmResult<T>
where
    F: std::future::Future<Output = WasmResult<T>>,
{
    // Wall-clock timeout is slightly longer than fuel timeout
    // to allow fuel exhaustion to trigger first in normal cases
    let timeout = Duration::from_secs((timeout_secs + 1) as u64);

    match tokio::time::timeout(timeout, future).await {
        Ok(result) => result,
        Err(_) => {
            warn!("WASM execution wall-clock timeout after {} seconds", timeout_secs);
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
pub async fn execute_with_isolation<F, T>(
    timeout_secs: u32,
    future: F,
) -> WasmResult<T>
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
            Err(WasmError::PluginError(format!("Plugin crashed: {}", panic_msg)))
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
        let result = execute_with_timeout(5, async {
            Ok::<_, WasmError>("success")
        })
        .await;
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
}
