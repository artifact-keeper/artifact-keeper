//! Storage path format configuration for Artifactory compatibility.
//!
//! Artifactory uses a different content-addressable storage path format:
//! - Artifactory: `{checksum[0:2]}/{checksum}` (1-level sharding)
//! - Native: `{checksum[0:2]}/{checksum[2:4]}/{checksum}` (2-level sharding)
//!
//! Configuration via environment variable:
//! - STORAGE_PATH_FORMAT: "native" (default), "artifactory", or "migration"
//!
//! Migration mode reads from both formats for zero-downtime Artifactory migration.

use std::fmt;

/// Storage path format for content-addressable storage
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StoragePathFormat {
    /// Native 2-level sharding: {checksum[0:2]}/{checksum[2:4]}/{checksum}
    /// Example: 91/6f/916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9
    #[default]
    Native,

    /// Artifactory 1-level sharding: {checksum[0:2]}/{checksum}
    /// Example: 91/916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9
    Artifactory,

    /// Migration mode: write in native format, read from both
    /// Attempts native path first, falls back to Artifactory path if not found.
    /// Use this when migrating from Artifactory with existing S3 data.
    Migration,
}

impl StoragePathFormat {
    /// Load from environment variable STORAGE_PATH_FORMAT
    pub fn from_env() -> Self {
        match std::env::var("STORAGE_PATH_FORMAT")
            .unwrap_or_default()
            .to_lowercase()
            .as_str()
        {
            "artifactory" | "jfrog" => Self::Artifactory,
            "migration" | "migrate" | "fallback" => Self::Migration,
            _ => Self::Native,
        }
    }

    /// Generate storage key from checksum in this format
    ///
    /// # Arguments
    /// * `checksum` - SHA-256 checksum (64 hex characters)
    ///
    /// # Panics
    /// Panics if checksum is less than 4 characters (invalid checksum)
    pub fn storage_key(&self, checksum: &str) -> String {
        match self {
            Self::Native | Self::Migration => {
                // 2-level sharding: ab/cd/abcd...
                format!("{}/{}/{}", &checksum[..2], &checksum[2..4], checksum)
            }
            Self::Artifactory => {
                // 1-level sharding: ab/abcd...
                format!("{}/{}", &checksum[..2], checksum)
            }
        }
    }

    /// Get alternative path for fallback reads (Migration mode only)
    ///
    /// Returns the Artifactory-format path when in Migration mode,
    /// None otherwise.
    pub fn fallback_key(&self, checksum: &str) -> Option<String> {
        match self {
            Self::Migration => {
                // Return Artifactory format as fallback
                Some(format!("{}/{}", &checksum[..2], checksum))
            }
            _ => None,
        }
    }

    /// Check if this format supports fallback paths
    pub fn has_fallback(&self) -> bool {
        matches!(self, Self::Migration)
    }

    /// Get all possible paths for a checksum (for migration/lookup)
    pub fn all_paths(&self, checksum: &str) -> Vec<String> {
        match self {
            Self::Native => vec![format!(
                "{}/{}/{}",
                &checksum[..2],
                &checksum[2..4],
                checksum
            )],
            Self::Artifactory => vec![format!("{}/{}", &checksum[..2], checksum)],
            Self::Migration => vec![
                // Native first, then Artifactory
                format!("{}/{}/{}", &checksum[..2], &checksum[2..4], checksum),
                format!("{}/{}", &checksum[..2], checksum),
            ],
        }
    }
}

impl fmt::Display for StoragePathFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native => write!(f, "native"),
            Self::Artifactory => write!(f, "artifactory"),
            Self::Migration => write!(f, "migration"),
        }
    }
}

impl std::str::FromStr for StoragePathFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "native" | "default" => Ok(Self::Native),
            "artifactory" | "jfrog" => Ok(Self::Artifactory),
            "migration" | "migrate" | "fallback" => Ok(Self::Migration),
            _ => Err(format!(
                "Unknown storage path format: {}. Use 'native', 'artifactory', or 'migration'",
                s
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CHECKSUM: &str = "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9";

    #[test]
    fn test_native_format() {
        let format = StoragePathFormat::Native;
        assert_eq!(
            format.storage_key(TEST_CHECKSUM),
            "91/6f/916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
        );
        assert!(!format.has_fallback());
        assert!(format.fallback_key(TEST_CHECKSUM).is_none());
    }

    #[test]
    fn test_artifactory_format() {
        let format = StoragePathFormat::Artifactory;
        assert_eq!(
            format.storage_key(TEST_CHECKSUM),
            "91/916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
        );
        assert!(!format.has_fallback());
        assert!(format.fallback_key(TEST_CHECKSUM).is_none());
    }

    #[test]
    fn test_migration_format() {
        let format = StoragePathFormat::Migration;
        // Writes in native format
        assert_eq!(
            format.storage_key(TEST_CHECKSUM),
            "91/6f/916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
        );
        // Has fallback to Artifactory format
        assert!(format.has_fallback());
        assert_eq!(
            format.fallback_key(TEST_CHECKSUM),
            Some("91/916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9".to_string())
        );
    }

    #[test]
    fn test_all_paths() {
        let checksum = TEST_CHECKSUM;

        assert_eq!(StoragePathFormat::Native.all_paths(checksum).len(), 1);
        assert_eq!(StoragePathFormat::Artifactory.all_paths(checksum).len(), 1);
        assert_eq!(StoragePathFormat::Migration.all_paths(checksum).len(), 2);

        let migration_paths = StoragePathFormat::Migration.all_paths(checksum);
        assert!(migration_paths[0].contains("/6f/")); // Native first
        assert!(!migration_paths[1].contains("/6f/")); // Artifactory second
    }

    #[test]
    fn test_from_str() {
        assert_eq!(
            "native".parse::<StoragePathFormat>().unwrap(),
            StoragePathFormat::Native
        );
        assert_eq!(
            "artifactory".parse::<StoragePathFormat>().unwrap(),
            StoragePathFormat::Artifactory
        );
        assert_eq!(
            "jfrog".parse::<StoragePathFormat>().unwrap(),
            StoragePathFormat::Artifactory
        );
        assert_eq!(
            "migration".parse::<StoragePathFormat>().unwrap(),
            StoragePathFormat::Migration
        );
        assert!("invalid".parse::<StoragePathFormat>().is_err());
    }

    #[test]
    fn test_display() {
        assert_eq!(StoragePathFormat::Native.to_string(), "native");
        assert_eq!(StoragePathFormat::Artifactory.to_string(), "artifactory");
        assert_eq!(StoragePathFormat::Migration.to_string(), "migration");
    }

    #[test]
    fn test_default() {
        assert_eq!(StoragePathFormat::default(), StoragePathFormat::Native);
    }
}
