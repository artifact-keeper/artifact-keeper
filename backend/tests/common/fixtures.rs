//! Test fixtures and data factories for backend tests
//!
//! Provides reusable test data for:
//! - Users and authentication
//! - Repositories
//! - Artifacts
//! - Package metadata

#![allow(dead_code)]

use std::collections::HashMap;

/// Test user credentials
pub struct TestUser {
    pub username: String,
    pub email: String,
    pub password: String,
}

impl TestUser {
    pub fn admin() -> Self {
        Self {
            username: "admin".to_string(),
            email: "admin@test.local".to_string(),
            password: "admin123".to_string(),
        }
    }

    pub fn regular() -> Self {
        Self {
            username: "testuser".to_string(),
            email: "testuser@test.local".to_string(),
            password: "password123".to_string(),
        }
    }

    pub fn with_name(name: &str) -> Self {
        Self {
            username: name.to_string(),
            email: format!("{}@test.local", name),
            password: "password123".to_string(),
        }
    }
}

/// Test repository configuration
pub struct TestRepository {
    pub name: String,
    pub format: String,
    pub repo_type: String,
}

impl TestRepository {
    pub fn pypi() -> Self {
        Self {
            name: "test-pypi".to_string(),
            format: "pypi".to_string(),
            repo_type: "hosted".to_string(),
        }
    }

    pub fn npm() -> Self {
        Self {
            name: "test-npm".to_string(),
            format: "npm".to_string(),
            repo_type: "hosted".to_string(),
        }
    }

    pub fn maven() -> Self {
        Self {
            name: "test-maven".to_string(),
            format: "maven".to_string(),
            repo_type: "hosted".to_string(),
        }
    }

    pub fn cargo() -> Self {
        Self {
            name: "test-cargo".to_string(),
            format: "cargo".to_string(),
            repo_type: "hosted".to_string(),
        }
    }

    pub fn go() -> Self {
        Self {
            name: "test-go".to_string(),
            format: "go".to_string(),
            repo_type: "hosted".to_string(),
        }
    }

    pub fn rpm() -> Self {
        Self {
            name: "test-rpm".to_string(),
            format: "rpm".to_string(),
            repo_type: "hosted".to_string(),
        }
    }

    pub fn deb() -> Self {
        Self {
            name: "test-deb".to_string(),
            format: "deb".to_string(),
            repo_type: "hosted".to_string(),
        }
    }

    pub fn helm() -> Self {
        Self {
            name: "test-helm".to_string(),
            format: "helm".to_string(),
            repo_type: "hosted".to_string(),
        }
    }

    pub fn conda() -> Self {
        Self {
            name: "test-conda".to_string(),
            format: "conda".to_string(),
            repo_type: "hosted".to_string(),
        }
    }

    pub fn docker() -> Self {
        Self {
            name: "test-docker".to_string(),
            format: "docker".to_string(),
            repo_type: "hosted".to_string(),
        }
    }
}

/// Test artifact metadata
pub struct TestArtifact {
    pub name: String,
    pub version: String,
    pub format: String,
    pub metadata: HashMap<String, String>,
}

impl TestArtifact {
    pub fn pypi_package() -> Self {
        let mut metadata = HashMap::new();
        metadata.insert("author".to_string(), "Test Author".to_string());
        metadata.insert("license".to_string(), "MIT".to_string());

        Self {
            name: "test-package".to_string(),
            version: "1.0.0".to_string(),
            format: "pypi".to_string(),
            metadata,
        }
    }

    pub fn npm_package() -> Self {
        let mut metadata = HashMap::new();
        metadata.insert("author".to_string(), "Test Author".to_string());
        metadata.insert("license".to_string(), "MIT".to_string());

        Self {
            name: "@test/package".to_string(),
            version: "1.0.0".to_string(),
            format: "npm".to_string(),
            metadata,
        }
    }

    pub fn cargo_crate() -> Self {
        let mut metadata = HashMap::new();
        metadata.insert("authors".to_string(), "Test Author <test@test.local>".to_string());
        metadata.insert("license".to_string(), "MIT".to_string());

        Self {
            name: "test-crate".to_string(),
            version: "1.0.0".to_string(),
            format: "cargo".to_string(),
            metadata,
        }
    }

    pub fn with_name_version(name: &str, version: &str, format: &str) -> Self {
        Self {
            name: name.to_string(),
            version: version.to_string(),
            format: format.to_string(),
            metadata: HashMap::new(),
        }
    }
}

/// Generate random binary data for testing artifact uploads
pub fn random_binary_data(size: usize) -> Vec<u8> {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let mut data = Vec::with_capacity(size);
    let state = RandomState::new();
    let mut hasher = state.build_hasher();

    for i in 0..size {
        hasher.write_usize(i);
        data.push((hasher.finish() & 0xFF) as u8);
    }

    data
}

/// Generate a minimal wheel file content for PyPI testing
pub fn minimal_wheel_content() -> Vec<u8> {
    // A minimal valid wheel is just a zip with WHEEL and METADATA files
    vec![
        0x50, 0x4b, 0x03, 0x04, // PK header
        0x14, 0x00, 0x00, 0x00, // version, flags
        0x00, 0x00, 0x00, 0x00, // compression, time
        0x00, 0x00, 0x00, 0x00, // date, crc
        0x00, 0x00, 0x00, 0x00, // compressed size
        0x00, 0x00, 0x00, 0x00, // uncompressed size
        0x00, 0x00, 0x00, 0x00, // filename len, extra len
    ]
}

/// Generate a minimal npm tarball content
pub fn minimal_npm_tarball() -> Vec<u8> {
    // Minimal gzipped tar
    vec![
        0x1f, 0x8b, 0x08, 0x00, // gzip header
        0x00, 0x00, 0x00, 0x00, // timestamp
        0x00, 0x03, // compression flags
    ]
}
