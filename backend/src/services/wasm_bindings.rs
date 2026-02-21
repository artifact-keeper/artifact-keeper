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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_wasm_metadata() -> WasmMetadata {
        WasmMetadata {
            path: "pkg/my-lib-1.0.0.whl".to_string(),
            version: Some("1.0.0".to_string()),
            content_type: "application/zip".to_string(),
            size_bytes: 4096,
            checksum_sha256: Some("abc123".to_string()),
        }
    }

    fn sample_wasm_metadata_no_optionals() -> WasmMetadata {
        WasmMetadata {
            path: "data.bin".to_string(),
            version: None,
            content_type: "application/octet-stream".to_string(),
            size_bytes: 0,
            checksum_sha256: None,
        }
    }

    // -----------------------------------------------------------------------
    // WasmMetadata <-> WitMetadata (v1) round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn test_wasm_to_wit_metadata_v1() {
        let wasm = sample_wasm_metadata();
        let wit: WitMetadata = (&wasm).into();
        assert_eq!(wit.path, "pkg/my-lib-1.0.0.whl");
        assert_eq!(wit.version, Some("1.0.0".to_string()));
        assert_eq!(wit.content_type, "application/zip");
        assert_eq!(wit.size_bytes, 4096);
        assert_eq!(wit.checksum_sha256, Some("abc123".to_string()));
    }

    #[test]
    fn test_wit_to_wasm_metadata_v1() {
        let wit = WitMetadata {
            path: "artifact.tar.gz".to_string(),
            version: Some("2.0.0".to_string()),
            content_type: "application/gzip".to_string(),
            size_bytes: 8192,
            checksum_sha256: Some("def456".to_string()),
        };
        let wasm: WasmMetadata = wit.into();
        assert_eq!(wasm.path, "artifact.tar.gz");
        assert_eq!(wasm.version, Some("2.0.0".to_string()));
        assert_eq!(wasm.content_type, "application/gzip");
        assert_eq!(wasm.size_bytes, 8192);
        assert_eq!(wasm.checksum_sha256, Some("def456".to_string()));
    }

    #[test]
    fn test_metadata_v1_round_trip_with_none_fields() {
        let wasm = sample_wasm_metadata_no_optionals();
        let wit: WitMetadata = (&wasm).into();
        let back: WasmMetadata = wit.into();
        assert_eq!(back.path, wasm.path);
        assert_eq!(back.version, None);
        assert_eq!(back.checksum_sha256, None);
        assert_eq!(back.size_bytes, 0);
    }

    // -----------------------------------------------------------------------
    // WasmMetadata <-> WitMetadataV2 round-trip
    // -----------------------------------------------------------------------

    #[test]
    fn test_wasm_to_wit_metadata_v2() {
        let wasm = sample_wasm_metadata();
        let wit: WitMetadataV2 = (&wasm).into();
        assert_eq!(wit.path, wasm.path);
        assert_eq!(wit.version, wasm.version);
        assert_eq!(wit.content_type, wasm.content_type);
        assert_eq!(wit.size_bytes, wasm.size_bytes);
        assert_eq!(wit.checksum_sha256, wasm.checksum_sha256);
    }

    #[test]
    fn test_wit_v2_to_wasm_metadata() {
        let wit = WitMetadataV2 {
            path: "rpm/pkg-1.0.x86_64.rpm".to_string(),
            version: Some("1.0".to_string()),
            content_type: "application/x-rpm".to_string(),
            size_bytes: 16384,
            checksum_sha256: None,
        };
        let wasm: WasmMetadata = wit.into();
        assert_eq!(wasm.path, "rpm/pkg-1.0.x86_64.rpm");
        assert_eq!(wasm.version, Some("1.0".to_string()));
        assert_eq!(wasm.checksum_sha256, None);
    }

    // -----------------------------------------------------------------------
    // WasmHttpRequest -> WitHttpRequest
    // -----------------------------------------------------------------------

    #[test]
    fn test_wasm_to_wit_http_request() {
        let req = WasmHttpRequest {
            method: "GET".to_string(),
            path: "/simple/".to_string(),
            query: "format=json".to_string(),
            headers: vec![("accept".to_string(), "text/html".to_string())],
            body: vec![],
        };
        let wit: WitHttpRequest = (&req).into();
        assert_eq!(wit.method, "GET");
        assert_eq!(wit.path, "/simple/");
        assert_eq!(wit.query, "format=json");
        assert_eq!(wit.headers.len(), 1);
        assert_eq!(wit.headers[0].0, "accept");
        assert!(wit.body.is_empty());
    }

    #[test]
    fn test_wasm_to_wit_http_request_with_body() {
        let req = WasmHttpRequest {
            method: "POST".to_string(),
            path: "/upload".to_string(),
            query: String::new(),
            headers: vec![],
            body: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let wit: WitHttpRequest = (&req).into();
        assert_eq!(wit.method, "POST");
        assert_eq!(wit.body, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    // -----------------------------------------------------------------------
    // WasmRepoContext -> WitRepoContext
    // -----------------------------------------------------------------------

    #[test]
    fn test_wasm_to_wit_repo_context() {
        let ctx = WasmRepoContext {
            repo_key: "my-pypi".to_string(),
            base_url: "https://example.com/ext/pypi-custom/my-pypi".to_string(),
            download_base_url: "https://example.com/api/v1/repositories/my-pypi/download"
                .to_string(),
        };
        let wit: WitRepoContext = (&ctx).into();
        assert_eq!(wit.repo_key, "my-pypi");
        assert_eq!(wit.base_url, "https://example.com/ext/pypi-custom/my-pypi");
        assert_eq!(
            wit.download_base_url,
            "https://example.com/api/v1/repositories/my-pypi/download"
        );
    }

    // -----------------------------------------------------------------------
    // WitHttpResponse -> WasmHttpResponse
    // -----------------------------------------------------------------------

    #[test]
    fn test_wit_to_wasm_http_response() {
        let wit = WitHttpResponse {
            status: 200,
            headers: vec![("content-type".to_string(), "text/html".to_string())],
            body: b"<html>OK</html>".to_vec(),
        };
        let wasm: WasmHttpResponse = wit.into();
        assert_eq!(wasm.status, 200);
        assert_eq!(wasm.headers.len(), 1);
        assert_eq!(wasm.headers[0].0, "content-type");
        assert_eq!(wasm.body, b"<html>OK</html>");
    }

    #[test]
    fn test_wit_to_wasm_http_response_empty() {
        let wit = WitHttpResponse {
            status: 404,
            headers: vec![],
            body: vec![],
        };
        let wasm: WasmHttpResponse = wit.into();
        assert_eq!(wasm.status, 404);
        assert!(wasm.headers.is_empty());
        assert!(wasm.body.is_empty());
    }

    // -----------------------------------------------------------------------
    // index_files_from_wit
    // -----------------------------------------------------------------------

    #[test]
    fn test_index_files_from_wit_empty() {
        let result = index_files_from_wit(vec![]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_index_files_from_wit_single() {
        let files = vec![("index.html".to_string(), b"<html>".to_vec())];
        let result = index_files_from_wit(files);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].path, "index.html");
        assert_eq!(result[0].content, Bytes::from("<html>"));
    }

    #[test]
    fn test_index_files_from_wit_multiple() {
        let files = vec![
            ("repodata/repomd.xml".to_string(), b"<xml/>".to_vec()),
            ("repodata/primary.xml.gz".to_string(), vec![0x1f, 0x8b]),
        ];
        let result = index_files_from_wit(files);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].path, "repodata/repomd.xml");
        assert_eq!(result[1].path, "repodata/primary.xml.gz");
        assert_eq!(result[1].content, Bytes::from(vec![0x1f, 0x8b]));
    }

    // -----------------------------------------------------------------------
    // Domain type Debug + Clone
    // -----------------------------------------------------------------------

    #[test]
    fn test_wasm_http_request_debug_clone() {
        let req = WasmHttpRequest {
            method: "GET".to_string(),
            path: "/".to_string(),
            query: String::new(),
            headers: vec![],
            body: vec![],
        };
        let cloned = req.clone();
        assert_eq!(cloned.method, req.method);
        assert_eq!(cloned.path, req.path);
        let debug = format!("{:?}", req);
        assert!(debug.contains("WasmHttpRequest"));
    }

    #[test]
    fn test_wasm_repo_context_debug_clone() {
        let ctx = WasmRepoContext {
            repo_key: "test".to_string(),
            base_url: "http://localhost".to_string(),
            download_base_url: "http://localhost/dl".to_string(),
        };
        let cloned = ctx.clone();
        assert_eq!(cloned.repo_key, "test");
        let debug = format!("{:?}", ctx);
        assert!(debug.contains("WasmRepoContext"));
    }

    #[test]
    fn test_wasm_http_response_debug_clone() {
        let resp = WasmHttpResponse {
            status: 200,
            headers: vec![("x-test".to_string(), "value".to_string())],
            body: vec![1, 2, 3],
        };
        let cloned = resp.clone();
        assert_eq!(cloned.status, 200);
        assert_eq!(cloned.headers, resp.headers);
        assert_eq!(cloned.body, resp.body);
    }
}
