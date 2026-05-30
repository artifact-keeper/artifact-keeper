//! Generic binary format handler.

use async_trait::async_trait;
use bytes::Bytes;

use super::FormatHandler;
use crate::error::Result;
use crate::models::repository::RepositoryFormat;

pub struct GenericHandler;

impl GenericHandler {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GenericHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// A single candidate member when resolving a generic artifact through a
/// virtual repository, in priority order.
#[derive(Debug, Clone)]
pub struct GenericVirtualMember {
    /// True when the member is a Remote (proxy) repo. Remote members are
    /// suppressed by the shadowing guard when a non-Remote member owns the
    /// requested path.
    pub is_remote: bool,
    /// The bytes this member would serve for the requested path, or `None`
    /// when the member does not have the artifact.
    pub bytes: Option<Vec<u8>>,
}

/// Pure model of the generic-format virtual download resolution (B9).
///
/// Mirrors the runtime behaviour of `download_artifact`'s Virtual arm:
/// members are tried in priority order and the first one that produces
/// bytes wins. The `local_owns_path` flag is the exact-path shadowing
/// guard (`virtual_non_remote_owns_path`): when a non-Remote member owns
/// the requested path, every Remote member is suppressed so it cannot
/// shadow the local artifact with empty or unrelated bytes.
///
/// Without the guard, a Remote member earlier in priority order that
/// returns bytes (including an empty body from a catch-all upstream) would
/// win the first-match race and the local member's real bytes would never
/// be served. This pure helper captures that contract so it has unit
/// coverage without a database or storage backend.
pub fn resolve_generic_virtual_bytes(
    members: &[GenericVirtualMember],
    local_owns_path: bool,
) -> Option<Vec<u8>> {
    for member in members {
        if member.is_remote && local_owns_path {
            // Shadowing guard: skip Remote members entirely.
            continue;
        }
        if let Some(bytes) = &member.bytes {
            return Some(bytes.clone());
        }
    }
    None
}

#[async_trait]
impl FormatHandler for GenericHandler {
    fn format(&self) -> RepositoryFormat {
        RepositoryFormat::Generic
    }

    async fn parse_metadata(&self, path: &str, _content: &Bytes) -> Result<serde_json::Value> {
        // Generic format has minimal metadata
        Ok(serde_json::json!({
            "path": path,
        }))
    }

    async fn validate(&self, _path: &str, _content: &Bytes) -> Result<()> {
        // Generic format accepts any content
        Ok(())
    }

    async fn generate_index(&self) -> Result<Option<Vec<(String, Bytes)>>> {
        // No index for generic format
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generic_handler_new() {
        let handler = GenericHandler::new();
        assert_eq!(handler.format(), RepositoryFormat::Generic);
    }

    #[test]
    fn test_generic_handler_default() {
        let handler = GenericHandler;
        assert_eq!(handler.format(), RepositoryFormat::Generic);
    }

    #[test]
    fn test_generic_handler_format_key() {
        let handler = GenericHandler::new();
        assert_eq!(handler.format_key(), "generic");
    }

    #[test]
    fn test_generic_handler_is_not_wasm_plugin() {
        let handler = GenericHandler::new();
        assert!(!handler.is_wasm_plugin());
    }

    #[tokio::test]
    async fn test_parse_metadata_returns_path() {
        let handler = GenericHandler::new();
        let content = Bytes::from_static(b"some binary data");
        let metadata = handler
            .parse_metadata("/path/to/file.bin", &content)
            .await
            .unwrap();
        assert_eq!(metadata["path"], "/path/to/file.bin");
    }

    #[tokio::test]
    async fn test_parse_metadata_different_paths() {
        let handler = GenericHandler::new();
        let content = Bytes::from_static(b"data");

        let m1 = handler.parse_metadata("file.txt", &content).await.unwrap();
        assert_eq!(m1["path"], "file.txt");

        let m2 = handler
            .parse_metadata("/a/b/c/d.tar.gz", &content)
            .await
            .unwrap();
        assert_eq!(m2["path"], "/a/b/c/d.tar.gz");
    }

    #[tokio::test]
    async fn test_parse_metadata_empty_path() {
        let handler = GenericHandler::new();
        let content = Bytes::from_static(b"data");
        let metadata = handler.parse_metadata("", &content).await.unwrap();
        assert_eq!(metadata["path"], "");
    }

    #[tokio::test]
    async fn test_parse_metadata_ignores_content() {
        let handler = GenericHandler::new();
        let content1 = Bytes::from_static(b"content A");
        let content2 = Bytes::from_static(b"content B");
        let m1 = handler.parse_metadata("file.bin", &content1).await.unwrap();
        let m2 = handler.parse_metadata("file.bin", &content2).await.unwrap();
        // Metadata should be the same regardless of content
        assert_eq!(m1, m2);
    }

    #[tokio::test]
    async fn test_validate_accepts_anything() {
        let handler = GenericHandler::new();
        // Generic format should accept any content
        assert!(handler
            .validate("file.bin", &Bytes::from_static(b""))
            .await
            .is_ok());
        assert!(handler
            .validate("file.bin", &Bytes::from_static(b"data"))
            .await
            .is_ok());
        assert!(handler.validate("", &Bytes::new()).await.is_ok());
    }

    #[tokio::test]
    async fn test_validate_binary_content() {
        let handler = GenericHandler::new();
        let binary = Bytes::from(vec![0u8, 1, 2, 255, 254, 253]);
        assert!(handler.validate("binary.bin", &binary).await.is_ok());
    }

    #[tokio::test]
    async fn test_generate_index_returns_none() {
        let handler = GenericHandler::new();
        let result = handler.generate_index().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_parse_metadata_with_unicode_path() {
        let handler = GenericHandler::new();
        let content = Bytes::from_static(b"data");
        let metadata = handler
            .parse_metadata("/path/to/file-\u{00e9}\u{00e8}.bin", &content)
            .await
            .unwrap();
        assert_eq!(metadata["path"], "/path/to/file-\u{00e9}\u{00e8}.bin");
    }

    #[tokio::test]
    async fn test_parse_metadata_with_large_content() {
        let handler = GenericHandler::new();
        let large_content = Bytes::from(vec![0u8; 10_000]);
        let metadata = handler
            .parse_metadata("large.bin", &large_content)
            .await
            .unwrap();
        assert_eq!(metadata["path"], "large.bin");
    }

    // ========================================================================
    // resolve_generic_virtual_bytes tests (B9): a generic virtual repo MUST
    // serve a present local member's artifact bytes, even when a Remote
    // member earlier in priority order also responds.
    // ========================================================================

    fn remote(bytes: Option<&[u8]>) -> GenericVirtualMember {
        GenericVirtualMember {
            is_remote: true,
            bytes: bytes.map(|b| b.to_vec()),
        }
    }

    fn local(bytes: Option<&[u8]>) -> GenericVirtualMember {
        GenericVirtualMember {
            is_remote: false,
            bytes: bytes.map(|b| b.to_vec()),
        }
    }

    #[test]
    fn test_generic_virtual_serves_local_member_bytes() {
        // The member that actually has the artifact is local; the guard is
        // off (no shadowing), so it is served.
        let members = vec![remote(None), local(Some(b"PAYLOAD"))];
        let served = resolve_generic_virtual_bytes(&members, /* local_owns_path = */ true);
        assert_eq!(served.as_deref(), Some(&b"PAYLOAD"[..]));
    }

    #[test]
    fn test_generic_virtual_guard_skips_remote_that_would_shadow_local() {
        // Regression for B9: a Remote member earlier in priority order returns
        // an EMPTY body for the same path. Without the shadowing guard the
        // remote wins the first-match race and the download serves zero bytes,
        // hiding the local member's real artifact. With the guard active
        // (local owns the path) the remote is skipped and the local bytes win.
        let members = vec![remote(Some(b"")), local(Some(b"REAL-BYTES"))];

        // Guard ON (a non-Remote member owns the path): local bytes served.
        let with_guard = resolve_generic_virtual_bytes(&members, true);
        assert_eq!(
            with_guard.as_deref(),
            Some(&b"REAL-BYTES"[..]),
            "with the shadowing guard the local member's bytes must be served"
        );

        // Guard OFF demonstrates the pre-fix bug: the empty remote shadows.
        let without_guard = resolve_generic_virtual_bytes(&members, false);
        assert_eq!(
            without_guard.as_deref(),
            Some(&b""[..]),
            "without the guard the remote's empty body shadows the local artifact (the B9 bug)"
        );
    }

    #[test]
    fn test_generic_virtual_remote_serves_when_no_local_owner() {
        // No local member owns the path: the remote proxy is allowed to serve.
        let members = vec![remote(Some(b"UPSTREAM")), local(None)];
        let served = resolve_generic_virtual_bytes(&members, false);
        assert_eq!(served.as_deref(), Some(&b"UPSTREAM"[..]));
    }

    #[test]
    fn test_generic_virtual_none_when_no_member_has_artifact() {
        let members = vec![remote(None), local(None)];
        assert!(resolve_generic_virtual_bytes(&members, false).is_none());
        assert!(resolve_generic_virtual_bytes(&members, true).is_none());
    }
}
