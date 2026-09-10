//! Artifact Keeper - Backend Library
//!
//! Open-source artifact registry supporting 13+ package formats.

#[macro_use]
mod macros;

/// CI test-surface contract (#3494): every backend/tests/ target must be
/// wired into a workflow or carry a justified exemption. Lives in the lib so
/// `--lib` (which every CI Rust-test job runs) always executes the gate.
mod ci_test_surface;

pub mod api;
pub mod build_info;
pub mod cli;
pub mod config;
pub mod db;
pub mod error;
pub mod formats;
pub mod grpc;
pub mod migration_repair;
pub mod models;
pub mod services;
pub mod storage;
pub mod telemetry;
// Test-harness plumbing (DB skip-vs-fail decision, #2924). Always compiled so
// both the crate's `#[cfg(test)]` unit tests and the out-of-crate integration
// tests under `backend/tests/` (which see the library without `cfg(test)`) can
// share one place; `#[doc(hidden)]` because it carries no production behavior.
#[doc(hidden)]
pub mod testing;
pub mod util;

pub use config::Config;
pub use error::{AppError, Result};

// CHANGELOG-only PR trigger (#1525 follow-up: path-filter + branch-protection gap)
