//! Shared storage-key prefixes.
//!
//! OCI objects are stored under fixed key prefixes that are referenced from
//! several independent sites: the write path that produces the keys, the
//! lifecycle cascade SQL, and the storage GC orphan predicate. The Rust
//! sites build keys with these constants; the SQL sites still have to embed
//! the literal (Postgres cannot read Rust constants) but pin themselves to
//! the constant with compile-time assertions so the two can never drift.

/// Storage-key prefix for OCI image manifest objects: `oci-manifests/`.
///
/// Single source of truth for the manifest key shape. Consumed by:
/// - `crate::api::handlers::oci_v2::manifest_storage_key` (the write path)
/// - `crate::services::lifecycle_service::CASCADE_OCI_TAGS_SQL`
/// - `crate::services::storage_gc_service::ORPHAN_PREDICATE_SQL`
///
/// The SQL sites embed the literal `'oci-manifests/'`; they assert at
/// compile time (via [`prefix_matches`]) that the literal matches this
/// constant. If you change this value, those assertions force you to update
/// the SQL too.
pub const OCI_MANIFEST_STORAGE_PREFIX: &str = "oci-manifests/";

/// Const-evaluable equality check between [`OCI_MANIFEST_STORAGE_PREFIX`] and
/// the bare prefix a SQL literal embeds (e.g. `"oci-manifests/"` extracted
/// from `'oci-manifests/'`).
///
/// `&str` equality is not usable in `const` context on the supported
/// toolchain, so the SQL-pinning `const _: () = assert!(...)` guards call
/// this instead. It exists purely so those guards stay one-liners.
pub const fn prefix_matches(literal: &str) -> bool {
    let a = OCI_MANIFEST_STORAGE_PREFIX.as_bytes();
    let b = literal.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_matches_is_exact() {
        assert!(prefix_matches("oci-manifests/"));
        assert!(!prefix_matches("oci-manifests"));
        assert!(!prefix_matches("oci-blobs/"));
        assert!(!prefix_matches("oci-manifests/x"));
    }

    #[test]
    fn prefix_constant_is_stable() {
        // The SQL literals in the lifecycle cascade and storage GC orphan
        // predicate hard-code this exact value; keep them in sync.
        assert_eq!(OCI_MANIFEST_STORAGE_PREFIX, "oci-manifests/");
    }
}
