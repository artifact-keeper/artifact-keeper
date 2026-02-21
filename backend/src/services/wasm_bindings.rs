//! Host-side bindings generated from the format-plugin WIT interface.
//!
//! Uses wasmtime's component::bindgen! macro to generate Rust types and
//! function stubs for calling into WASM plugin components.
//!
//! Two worlds are supported:
//! - `format-plugin` (v1): parse_metadata, validate, generate_index
//! - `format-plugin-v2`: adds handle_request for native protocol serving

use bytes::Bytes;

use super::wasm_runtime::{WasmIndexFile, WasmMetadata};

/// V1 bindings for the original format-plugin world.
pub mod v1 {
    wasmtime::component::bindgen!({
        world: "format-plugin",
        path: "src/wit/format-plugin.wit",
        async: true,
    });
}

/// V2 bindings for plugins that serve native client protocols.
pub mod v2 {
    wasmtime::component::bindgen!({
        world: "format-plugin-v2",
        path: "src/wit/format-plugin.wit",
        async: true,
    });
}

// Re-export the main types for convenience
pub use v1::FormatPlugin;

/// Type alias for the WIT-generated Metadata record (v1).
pub type WitMetadata = v1::exports::artifact_keeper::format::handler::Metadata;

impl From<WitMetadata> for WasmMetadata {
    fn from(m: WitMetadata) -> Self {
        Self {
            path: m.path,
            version: m.version,
            content_type: m.content_type,
            size_bytes: m.size_bytes,
            checksum_sha256: m.checksum_sha256,
        }
    }
}

impl From<&WasmMetadata> for WitMetadata {
    fn from(m: &WasmMetadata) -> Self {
        Self {
            path: m.path.clone(),
            version: m.version.clone(),
            content_type: m.content_type.clone(),
            size_bytes: m.size_bytes,
            checksum_sha256: m.checksum_sha256.clone(),
        }
    }
}

/// Convert WIT index file tuples to domain types.
pub fn index_files_from_wit(files: Vec<(String, Vec<u8>)>) -> Vec<WasmIndexFile> {
    files
        .into_iter()
        .map(|(path, content)| WasmIndexFile {
            path,
            content: Bytes::from(content),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// V2 types for handle-request
// ---------------------------------------------------------------------------

/// Type alias for the V2 Metadata (same shape, different module path).
pub type WitMetadataV2 = v2::exports::artifact_keeper::format::handler::Metadata;

/// Type alias for V2 request-handler types.
pub type WitHttpRequest = v2::exports::artifact_keeper::format::request_handler::HttpRequest;
pub type WitRepoContext = v2::exports::artifact_keeper::format::request_handler::RepoContext;
pub type WitHttpResponse = v2::exports::artifact_keeper::format::request_handler::HttpResponse;

/// Domain-level HTTP request for WASM plugins.
#[derive(Debug, Clone)]
pub struct WasmHttpRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Domain-level repository context for WASM plugins.
#[derive(Debug, Clone)]
pub struct WasmRepoContext {
    pub repo_key: String,
    pub base_url: String,
    pub download_base_url: String,
}

/// Domain-level HTTP response from WASM plugins.
#[derive(Debug, Clone)]
pub struct WasmHttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl From<WitHttpResponse> for WasmHttpResponse {
    fn from(r: WitHttpResponse) -> Self {
        Self {
            status: r.status,
            headers: r.headers,
            body: r.body,
        }
    }
}

impl From<&WasmHttpRequest> for WitHttpRequest {
    fn from(r: &WasmHttpRequest) -> Self {
        Self {
            method: r.method.clone(),
            path: r.path.clone(),
            query: r.query.clone(),
            headers: r.headers.clone(),
            body: r.body.clone(),
        }
    }
}

impl From<&WasmRepoContext> for WitRepoContext {
    fn from(c: &WasmRepoContext) -> Self {
        Self {
            repo_key: c.repo_key.clone(),
            base_url: c.base_url.clone(),
            download_base_url: c.download_base_url.clone(),
        }
    }
}

impl From<&WasmMetadata> for WitMetadataV2 {
    fn from(m: &WasmMetadata) -> Self {
        Self {
            path: m.path.clone(),
            version: m.version.clone(),
            content_type: m.content_type.clone(),
            size_bytes: m.size_bytes,
            checksum_sha256: m.checksum_sha256.clone(),
        }
    }
}

impl From<WitMetadataV2> for WasmMetadata {
    fn from(m: WitMetadataV2) -> Self {
        Self {
            path: m.path,
            version: m.version,
            content_type: m.content_type,
            size_bytes: m.size_bytes,
            checksum_sha256: m.checksum_sha256,
        }
    }
}
