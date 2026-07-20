//! Shared storage-key prefixes and the repository-scoped key scheme.
//!
//! OCI objects are stored under fixed key prefixes that are referenced from
//! several independent sites: the write path that produces the keys, the
//! lifecycle cascade SQL, and the storage GC orphan predicate. The Rust
//! sites build keys with these constants; the SQL sites still have to embed
//! the literal (Postgres cannot read Rust constants) but pin themselves to
//! the constant with compile-time assertions so the two can never drift.
//!
//! [`StorageKeyScheme`] (#2624) governs whether path-addressed format objects
//! on shared cloud namespaces embed the owning repository's id in their
//! storage key (`{format}/{repository_id}/{path}`, the same shape the
//! rpm/alpine/incus handlers already use) or keep the legacy flat
//! `{format}/{path}` namespace.

use uuid::Uuid;

/// How path-addressed format objects are keyed on shared cloud namespaces
/// (S3/GCS/Azure).
///
/// Selected by the `STORAGE_KEY_SCHEME` environment variable:
/// `repo-scoped` (default) or `flat` (the pre-#2624 layout).
///
/// Filesystem backends are exempt either way: [`super::registry`] roots a
/// fresh `FilesystemStorage` at each repository's `storage_path`, so their
/// key space is already physically per-repository and scoping the key again
/// would only churn the on-disk layout.
///
/// Rollout/back-compat contract (#2624):
/// - Row-anchored reads always use the `artifacts.storage_key` recorded at
///   write time, so objects written under either scheme stay readable
///   without any migration.
/// - Derived (row-less) reads try the scoped candidate first and then fall
///   back to the legacy flat key, gated by the same #2504/#2574 attribution
///   rules as before.
/// - The scoped segment is the repository **UUID** (never reused, unlike the
///   repository key), so a scoped key is physically attributable to exactly
///   one repository for all time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StorageKeyScheme {
    /// `{format}/{repository_id}/{path}` on shared cloud namespaces (default).
    #[default]
    RepoScoped,
    /// Legacy flat `{format}/{path}` shared namespace.
    Flat,
}

impl StorageKeyScheme {
    /// Load from the `STORAGE_KEY_SCHEME` environment variable.
    pub fn from_env() -> Self {
        match std::env::var("STORAGE_KEY_SCHEME")
            .unwrap_or_default()
            .to_lowercase()
            .as_str()
        {
            "flat" | "legacy" => Self::Flat,
            _ => Self::RepoScoped,
        }
    }

    /// The storage key new `{format_prefix}` objects are written to for
    /// `repository_id` on `storage_backend`.
    ///
    /// Repo-isolated (filesystem) backends and the [`Flat`](Self::Flat)
    /// scheme keep the legacy `{format}/{path}` key; shared cloud namespaces
    /// under [`RepoScoped`](Self::RepoScoped) embed the repository id.
    pub fn write_key(
        self,
        storage_backend: &str,
        format_prefix: &str,
        repository_id: Uuid,
        path: &str,
    ) -> String {
        self.scoped_read_key(storage_backend, format_prefix, repository_id, path)
            .unwrap_or_else(|| format!("{format_prefix}/{path}"))
    }

    /// The repo-scoped candidate a derived (row-less) read should try BEFORE
    /// the legacy flat key, or `None` when writes for this backend/scheme go
    /// to the flat key anyway.
    ///
    /// The returned key embeds `repository_id`, so serving it back to that
    /// same repository needs no catalog attribution check — the key cannot
    /// name another repository's object.
    pub fn scoped_read_key(
        self,
        storage_backend: &str,
        format_prefix: &str,
        repository_id: Uuid,
        path: &str,
    ) -> Option<String> {
        if self == Self::RepoScoped && !super::registry::backend_is_repo_isolated(storage_backend) {
            Some(format!("{format_prefix}/{repository_id}/{path}"))
        } else {
            None
        }
    }
}

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

    // -- StorageKeyScheme (#2624) -------------------------------------------

    const REPO_A: Uuid = Uuid::from_u128(0x1111_2222_3333_4444_5555_6666_7777_8888);
    const REPO_B: Uuid = Uuid::from_u128(0x9999_aaaa_bbbb_cccc_dddd_eeee_ffff_0000);

    #[test]
    fn repo_scoped_write_key_embeds_repository_id_on_cloud() {
        let key = StorageKeyScheme::RepoScoped.write_key(
            "s3",
            "maven",
            REPO_A,
            "com/example/lib/1.0/lib-1.0.jar",
        );
        assert_eq!(
            key,
            format!("maven/{REPO_A}/com/example/lib/1.0/lib-1.0.jar")
        );
    }

    #[test]
    fn repo_scoped_write_key_keeps_flat_key_on_filesystem() {
        // Filesystem backends are already rooted per-repository; the key
        // stays in the legacy shape so existing directory trees are reused.
        let key = StorageKeyScheme::RepoScoped.write_key(
            "filesystem",
            "maven",
            REPO_A,
            "com/example/lib/1.0/lib-1.0.jar",
        );
        assert_eq!(key, "maven/com/example/lib/1.0/lib-1.0.jar");
    }

    #[test]
    fn flat_scheme_write_key_is_legacy_shape_everywhere() {
        for backend in ["s3", "gcs", "azure", "filesystem"] {
            let key = StorageKeyScheme::Flat.write_key(
                backend,
                "maven",
                REPO_A,
                "com/example/lib/1.0/lib-1.0.jar",
            );
            assert_eq!(key, "maven/com/example/lib/1.0/lib-1.0.jar");
        }
    }

    #[test]
    fn scoped_keys_of_two_repositories_can_never_collide() {
        // The scheme's whole point (#2624/#2586): the same coordinate in two
        // repositories resolves to two distinct physical objects.
        let path = "com/example/lib/1.0/lib-1.0.jar";
        let a = StorageKeyScheme::RepoScoped.write_key("s3", "maven", REPO_A, path);
        let b = StorageKeyScheme::RepoScoped.write_key("s3", "maven", REPO_B, path);
        assert_ne!(a, b);
        assert!(a.contains(&REPO_A.to_string()));
        assert!(b.contains(&REPO_B.to_string()));
    }

    #[test]
    fn scoped_read_key_matches_write_key_on_cloud() {
        let path = "com/example/lib/maven-metadata.xml";
        let scoped = StorageKeyScheme::RepoScoped
            .scoped_read_key("gcs", "maven", REPO_A, path)
            .expect("cloud backend under repo-scoped scheme yields a candidate");
        assert_eq!(
            scoped,
            StorageKeyScheme::RepoScoped.write_key("gcs", "maven", REPO_A, path)
        );
    }

    #[test]
    fn scoped_read_key_is_none_when_writes_are_flat() {
        let path = "com/example/lib/maven-metadata.xml";
        assert!(StorageKeyScheme::RepoScoped
            .scoped_read_key("filesystem", "maven", REPO_A, path)
            .is_none());
        assert!(StorageKeyScheme::Flat
            .scoped_read_key("s3", "maven", REPO_A, path)
            .is_none());
    }

    #[test]
    fn default_scheme_is_repo_scoped() {
        assert_eq!(StorageKeyScheme::default(), StorageKeyScheme::RepoScoped);
    }
}
