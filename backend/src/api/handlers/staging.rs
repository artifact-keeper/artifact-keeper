//! Shared local staging for large upload bodies.
//!
//! Format handlers that receive a multi-GiB body and must land it on local
//! disk before handing it to the [`StorageBackend`](crate::storage) — incus
//! (monolithic + chunked) and OCI blob uploads today — stage here rather than
//! each rolling their own `std::env::temp_dir()` path.
//!
//! Staging lives under `<STORAGE_PATH>/.incoming`: the data volume, sized by
//! the deployment's storage provisioning, **not** `/tmp`. On Kubernetes `/tmp`
//! is typically a small `emptyDir` (256Mi in the reference chart); a multi-GiB
//! upload streamed there overruns it and kubelet evicts the pod mid-receive
//! (`Usage of EmptyDir volume "tmp" exceeds the limit`), so the artifact never
//! lands. Co-locating staging with the data volume makes it inherit the same
//! sizing as the artifacts it's staging.
//!
//! A single env var, `AK_UPLOAD_STAGING_DIR`, relocates the staging root for
//! operators who want a dedicated scratch volume (it replaces the former
//! per-format `AK_INCUS_UPLOAD_TMP_DIR` / `AK_OCI_UPLOAD_TMP_DIR`).
//!
//! Handlers remove their own temp file on the success and error paths. A file
//! only leaks when the receive is killed (OOM / eviction / restart) before
//! that cleanup runs; [`sweep_stale`] reaps such orphans on the same schedule
//! and max-age as the chunked-session reaper
//! ([`crate::api::handlers::incus::cleanup_stale_sessions`]).

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use uuid::Uuid;

/// Reserved staging directory under `STORAGE_PATH`. Dot-prefixed so it cannot
/// collide with a repository key prefix in the filesystem backend's
/// `<base>/<prefix>/<key>` layout.
const STAGING_SUBDIR: &str = ".incoming";

/// Age after which a staged temp file is treated as orphaned and reaped.
/// Shared by [`sweep_stale`] and the chunked-session reaper so both expire
/// staging on the identical threshold.
pub const UPLOAD_STAGING_MAX_AGE_HOURS: u64 = 24;

/// Root staging directory: `$AK_UPLOAD_STAGING_DIR` if set and non-empty,
/// otherwise `<storage_path>/.incoming`. Never `/tmp`.
pub fn staging_root(storage_path: &str) -> PathBuf {
    match std::env::var("AK_UPLOAD_STAGING_DIR") {
        Ok(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => Path::new(storage_path).join(STAGING_SUBDIR),
    }
}

/// Deterministic per-upload staging path. `kind` namespaces by format
/// (`"incus"`, `"oci"`, …) for operator visibility; `id` is a per-upload UUID
/// so concurrent uploads of the same artifact never collide. Pure path
/// construction — call [`ensure_staging_root`] (or `create_dir_all` on the
/// parent) before writing.
pub fn staging_temp_path(storage_path: &str, kind: &str, id: &Uuid) -> PathBuf {
    staging_root(storage_path).join(format!("ak-{kind}-upload-{id}"))
}

/// Create the staging root if it doesn't exist. Idempotent; cheap to call
/// before each staged write.
pub async fn ensure_staging_root(storage_path: &str) -> std::io::Result<()> {
    tokio::fs::create_dir_all(staging_root(storage_path)).await
}

/// Reap staged entries older than `max_age_hours`. Best-effort: an entry that
/// can't be removed is logged and skipped (not fatal), and a missing staging
/// root is a no-op. Returns the number of entries removed.
pub async fn sweep_stale(storage_path: &str, max_age_hours: u64) -> std::io::Result<u64> {
    let root = staging_root(storage_path);
    let mut entries = match tokio::fs::read_dir(&root).await {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };

    let cutoff = SystemTime::now()
        .checked_sub(Duration::from_secs(max_age_hours.saturating_mul(3600)))
        .unwrap_or(SystemTime::UNIX_EPOCH);

    let mut removed = 0u64;
    while let Some(entry) = entries.next_entry().await? {
        let meta = match entry.metadata().await {
            Ok(m) => m,
            Err(_) => continue,
        };
        // Reap by last-modified: an in-flight upload bumps mtime as it writes,
        // so only genuinely abandoned staging crosses the cutoff.
        let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        if modified > cutoff {
            continue;
        }
        let path = entry.path();
        let result = if meta.is_dir() {
            tokio::fs::remove_dir_all(&path).await
        } else {
            tokio::fs::remove_file(&path).await
        };
        match result {
            Ok(()) => removed += 1,
            Err(e) => tracing::warn!("Failed to reap stale staging entry {:?}: {}", path, e),
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staging_root_defaults_under_storage_path() {
        // SAFETY: env-mutating test — snapshot + restore so it can't leak into
        // sibling tests sharing the process env.
        let prev = std::env::var("AK_UPLOAD_STAGING_DIR").ok();
        std::env::remove_var("AK_UPLOAD_STAGING_DIR");
        assert_eq!(
            staging_root("/data/storage"),
            PathBuf::from("/data/storage/.incoming")
        );
        if let Some(v) = prev {
            std::env::set_var("AK_UPLOAD_STAGING_DIR", v);
        }
    }

    #[test]
    fn staging_root_honors_env_override() {
        let prev = std::env::var("AK_UPLOAD_STAGING_DIR").ok();
        std::env::set_var("AK_UPLOAD_STAGING_DIR", "/mnt/scratch/ak");
        assert_eq!(staging_root("/data/storage"), PathBuf::from("/mnt/scratch/ak"));
        match prev {
            Some(v) => std::env::set_var("AK_UPLOAD_STAGING_DIR", v),
            None => std::env::remove_var("AK_UPLOAD_STAGING_DIR"),
        }
    }

    #[test]
    fn staging_temp_path_is_per_uuid_and_kind_namespaced() {
        let prev = std::env::var("AK_UPLOAD_STAGING_DIR").ok();
        std::env::remove_var("AK_UPLOAD_STAGING_DIR");
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let pa = staging_temp_path("/data/storage", "incus", &a);
        assert_eq!(pa, staging_temp_path("/data/storage", "incus", &a), "stable per uuid");
        assert_ne!(pa, staging_temp_path("/data/storage", "incus", &b), "distinct uuids differ");
        assert_ne!(
            staging_temp_path("/data/storage", "incus", &a),
            staging_temp_path("/data/storage", "oci", &a),
            "kind namespaces the filename"
        );
        assert_eq!(
            pa.file_name().and_then(|s| s.to_str()),
            Some(format!("ak-incus-upload-{a}").as_str())
        );
        if let Some(v) = prev {
            std::env::set_var("AK_UPLOAD_STAGING_DIR", v);
        }
    }

    #[tokio::test]
    async fn sweep_stale_tolerates_missing_root_keeps_fresh_reaps_aged() {
        // SAFETY: env-mutating test — snapshot + restore around the assertions.
        let prev = std::env::var("AK_UPLOAD_STAGING_DIR").ok();
        let base = std::env::temp_dir().join(format!("ak-staging-test-{}", Uuid::new_v4()));
        std::env::set_var("AK_UPLOAD_STAGING_DIR", &base);

        // Missing root is a no-op.
        assert_eq!(sweep_stale("/unused", UPLOAD_STAGING_MAX_AGE_HOURS).await.unwrap(), 0);

        ensure_staging_root("/unused").await.unwrap();
        let file = base.join("ak-incus-upload-staged");
        let dir = base.join("ak-oci-upload-tree");
        tokio::fs::write(&file, b"x").await.unwrap();
        tokio::fs::create_dir_all(&dir).await.unwrap();

        // A 24h cutoff keeps just-written staging (mtime ~now is newer than now-24h).
        assert_eq!(sweep_stale("/unused", UPLOAD_STAGING_MAX_AGE_HOURS).await.unwrap(), 0);
        assert!(file.exists() && dir.exists(), "fresh staging is kept");

        // A 0h cutoff (now) treats anything already on disk as aged — reaps both
        // the file and the directory tree.
        let removed = sweep_stale("/unused", 0).await.unwrap();
        assert_eq!(removed, 2, "aged file + directory both reaped");
        assert!(!file.exists() && !dir.exists(), "aged staging is removed");

        let _ = tokio::fs::remove_dir_all(&base).await;
        match prev {
            Some(v) => std::env::set_var("AK_UPLOAD_STAGING_DIR", v),
            None => std::env::remove_var("AK_UPLOAD_STAGING_DIR"),
        }
    }
}
